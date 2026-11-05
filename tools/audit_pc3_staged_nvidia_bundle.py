#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recheck a staged PC3 NVIDIA package bundle without changing it or the host.

This audit reads pinned manifests, staged .deb files, and a captured host
inventory. It never installs packages, runs maintainer scripts, changes file
permissions, loads modules, or contacts PC3.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.stage_nvidia_canary_packages import (  # noqa: E402
    CACHE_ROOT,
    MANIFEST_PATH,
    MANIFEST_SHA256,
    unique_json_object,
    verify_deb_metadata,
)

STAGE_REPORT = ROOT / "evidence/pc3-nvidia-canary-stage-v1-20261023T094921Z.json"
HOST_SNAPSHOT = ROOT / "evidence/pc3-canary-host-state-independent-staged-preflight-v2-20261028T1515Z.json"


def _hash_file(path: Path) -> tuple[int, str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            sha256.update(block)
            md5.update(block)
    return size, md5.hexdigest(), sha256.hexdigest()


def _safe_staged_path(root: Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise ValueError("staged archive path is malformed")
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("staged archive path escapes the repository")
    root = Path(root).resolve(strict=True)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise ValueError("staged archive path is missing") from error
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("staged archive path has a symlink component")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("staged archive path component is not a directory")
        if index == len(relative.parts) - 1 and not stat.S_ISREG(info.st_mode):
            raise ValueError("staged archive is not a regular file")
    return current


def verify_staged_package(root: Path, entry: dict, staged: dict, *, deb_runner=subprocess.run) -> dict:
    """Verify one stage claim, archive bytes, and .deb identity without writes."""
    identity = {
        "transaction": entry["transaction"],
        "package": entry["package"],
        "version": entry["version"],
        "architecture": entry["architecture"],
        "filename": entry["filename"],
    }
    if any(staged.get(key) != value for key, value in identity.items()):
        raise ValueError("stage identity differs from the pinned manifest")
    if staged.get("bytes") != entry["size"] or staged.get("md5") != entry["md5_from_apt_uri"] or staged.get("sha256") != entry["sha256"]:
        raise ValueError("stage hash or size claim differs from the pinned manifest")

    path = _safe_staged_path(root, staged.get("path"))
    size, md5, sha256 = _hash_file(path)
    if (size, md5, sha256) != (entry["size"], entry["md5_from_apt_uri"], entry["sha256"]):
        raise ValueError("archive hash or size differs from the pinned manifest")
    control = verify_deb_metadata(path, entry, runner=deb_runner)
    return {
        **identity,
        "path": staged["path"],
        "bytes": size,
        "md5": md5,
        "sha256": sha256,
        "deb_control": control,
    }


def index_installed_packages(packages: list[dict]) -> dict[str, list[str]]:
    """Index only installed dpkg records, normalizing :architecture suffixes."""
    if not isinstance(packages, list):
        raise ValueError("host package inventory must be a list")
    index: dict[str, list[str]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("host package inventory contains a malformed entry")
        name, status, version = package.get("name"), package.get("status"), package.get("version")
        if not isinstance(name, str) or not isinstance(status, str) or not isinstance(version, str):
            raise ValueError("host package inventory entry lacks name, status, or version")
        if status != "ii":
            continue
        normalized_name = name.partition(":")[0]
        index.setdefault(normalized_name, []).append(version)
    return index


def installed_package_matches(entry: dict, installed_index: dict[str, list[str]]) -> bool:
    versions = installed_index.get(entry.get("package"), [])
    return len(versions) == 1 and versions[0] == entry.get("version")


def _read_json(path: Path) -> tuple[dict, str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("evidence input must be a regular non-symlink file")
    raw = path.read_bytes()
    return json.loads(raw, object_pairs_hook=unique_json_object), hashlib.sha256(raw).hexdigest()


def _safe_project_input(root: Path, path: Path, label: str) -> Path:
    """Resolve an absolute or project-relative input without following symlinks."""
    root = Path(root).resolve(strict=True)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(label + " escapes the canonical project") from error
    if not relative.parts:
        raise ValueError(label + " must identify a file")
    current = root
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise ValueError(label + " is missing") from error
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(label + " has a symlink component")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError(label + " parent is not a directory")
        if index == len(relative.parts) - 1 and not stat.S_ISREG(info.st_mode):
            raise ValueError(label + " must be a regular file")
    return candidate


def audit_bundle(
    *, manifest_path: Path = MANIFEST_PATH,
    stage_path: Path = STAGE_REPORT,
    host_snapshot_path: Path = HOST_SNAPSHOT,
    root: Path = ROOT,
    deb_runner=subprocess.run,
) -> dict:
    from tools.stage_nvidia_canary_packages import load_manifest

    root = Path(root).resolve(strict=True)
    manifest_path = _safe_project_input(root, manifest_path, "manifest")
    stage_path = _safe_project_input(root, stage_path, "stage report")
    host_snapshot_path = _safe_project_input(root, host_snapshot_path, "host snapshot")
    manifest, manifest_sha256 = load_manifest(manifest_path, expected_sha256=MANIFEST_SHA256)
    stage, stage_sha256 = _read_json(stage_path)
    host, host_sha256 = _read_json(host_snapshot_path)

    if stage.get("schema") != "pc3-nvidia-canary-package-stage-v1" or stage.get("status") != "staged-and-verified":
        raise ValueError("unsupported or unsuccessful package stage report")
    if stage.get("manifest_sha256") != manifest_sha256:
        raise ValueError("stage report does not reference the pinned manifest")
    if stage.get("target_kernel") != host.get("kernel_release"):
        raise ValueError("staged rollback kernel does not match the host snapshot kernel")
    if host.get("host") != "pc3" or host.get("driver_recovery_inventory", {}).get("package_query_complete") is not True:
        raise ValueError("host snapshot is incomplete or does not identify PC3")

    staged_rows = stage.get("packages")
    if not isinstance(staged_rows, list) or len(staged_rows) != manifest["package_count"]:
        raise ValueError("stage package count differs from pinned manifest")
    stage_index = {}
    for row in staged_rows:
        if not isinstance(row, dict):
            raise ValueError("stage report contains a malformed package record")
        key = (row.get("transaction"), row.get("package"))
        if key in stage_index:
            raise ValueError("stage report contains a duplicate transaction/package")
        stage_index[key] = row

    package_results = []
    for entry in manifest["packages"]:
        row = stage_index.get((entry["transaction"], entry["package"]))
        if row is None:
            raise ValueError("stage report is missing a pinned package")
        expected_path = (CACHE_ROOT.relative_to(ROOT) / entry["transaction"] / entry["filename"]).as_posix()
        if row.get("path") != expected_path:
            raise ValueError("stage path differs from the pinned private cache layout")
        package_results.append(verify_staged_package(root, entry, row, deb_runner=deb_runner))

    inventory = host["driver_recovery_inventory"]["packages"]
    installed_index = index_installed_packages(inventory)
    rollback_entries = [entry for entry in manifest["packages"] if entry["transaction"] == "rollback"]
    rollback_matches = [
        {"package": entry["package"], "version": entry["version"],
         "installed_exactly": installed_package_matches(entry, installed_index)}
        for entry in rollback_entries
    ]
    rollback_match_count = sum(item["installed_exactly"] for item in rollback_matches)
    rollback_unmatched = [item["package"] for item in rollback_matches if not item["installed_exactly"]]
    transaction_results = {
        transaction: {
            "package_count": sum(entry["transaction"] == transaction for entry in manifest["packages"]),
            "bytes": sum(entry["size"] for entry in manifest["packages"] if entry["transaction"] == transaction),
        }
        for transaction in ("target", "rollback")
    }
    auditor_path = Path(__file__)
    test_path = Path(root) / "tests/test_audit_pc3_staged_nvidia_bundle.py"
    return {
        "schema": "pc3-staged-nvidia-package-bundle-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "all-staged-archives-reverified",
        "scope": "offline local archive and captured-inventory audit; no PC3 connection or host mutation",
        "auditor": {
            "path": str(auditor_path.relative_to(root)),
            "sha256": _hash_file(auditor_path)[2],
            "focused_test_path": str(test_path.relative_to(root)),
            "focused_test_sha256": _hash_file(test_path)[2],
        },
        "manifest": {"path": str(Path(manifest_path).relative_to(root)), "sha256": manifest_sha256,
                     "package_count": manifest["package_count"]},
        "stage_report": {"path": str(Path(stage_path).relative_to(root)), "sha256": stage_sha256,
                         "status": stage["status"], "target_kernel": stage["target_kernel"]},
        "host_snapshot": {"path": str(Path(host_snapshot_path).relative_to(root)), "sha256": host_sha256,
                          "observed_at_utc": host.get("observed_at_utc"),
                          "kernel_release": host.get("kernel_release"),
                          "loaded_nvidia_module_version": host.get("loaded_nvidia_module_version")},
        "transactions": transaction_results,
        "verified_archive_count": len(package_results),
        "package_archives": package_results,
        "rollback_snapshot_comparison": {
            "status": "exact-match" if rollback_match_count == len(rollback_entries) else "partial-match",
            "exact_package_version_matches": rollback_match_count,
            "expected_package_count": len(rollback_entries),
            "all_packages_match_snapshot": rollback_match_count == len(rollback_entries),
            "unmatched_packages": rollback_unmatched,
            "packages": rollback_matches,
            "operational_recovery_proven": False,
            "limitations": [
                "Archive availability and package-version agreement do not prove installation, boot, driver operation, or rollback recovery.",
                "The snapshot is a captured PC3 observation and is not a live query performed by this audit.",
                "No module-signature trust, PCI ownership change, or same-process mixed-GPU CUDA test is covered.",
            ],
        },
        "historical_stage_safety_flags": {
            key: stage.get(key) for key in (
                "all_package_hashes_verified", "all_deb_control_identities_verified",
                "apt_or_dpkg_install_invoked", "package_scripts_executed", "kernel_modules_loaded",
                "gpu_accessed", "driver_or_pci_modified",
            )
        },
    }


def _write_private_exclusive(path: Path, data: dict) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite existing evidence: " + str(path))
    encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-snapshot", type=Path, default=HOST_SNAPSHOT,
                        help="captured PC3 inventory to compare with the staged rollback set")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    output = args.output or ROOT / (
        "evidence/pc3-staged-package-bundle-audit-v1-%s.json"
        % datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    try:
        report = audit_bundle(host_snapshot_path=args.host_snapshot)
        _write_private_exclusive(output, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print("audit failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "verified_archive_count": report["verified_archive_count"],
        "rollback_exact_package_version_matches": report["rollback_snapshot_comparison"]["exact_package_version_matches"],
        "rollback_expected_package_count": report["rollback_snapshot_comparison"]["expected_package_count"],
        "operational_recovery_proven": report["rollback_snapshot_comparison"]["operational_recovery_proven"],
        "output": str(output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
