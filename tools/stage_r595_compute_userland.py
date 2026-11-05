#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the pinned R595.99.02 compute libraries without installing them.

The package and the archived Ubuntu signature/index audit are pinned by
SHA-256. Extraction is confined to a new private directory below
``build/staging``. No package scripts, CUDA calls, driver changes, or GPU
access occur.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.stage_nvidia_canary_packages import verify_deb_metadata  # noqa: E402

RECOVERY_ROOT = ROOT / ".cache/canary/pc3-r595-recovery-20261028T1629Z"
RECOVERY_MANIFEST = RECOVERY_ROOT / "manifest.json"
RECOVERY_MANIFEST_SHA256 = "eedb4723859f6c737ee8d0dbf975a8d77ea9076bc84824b0e16d2fb89bcccad2"
ARCHIVE_AUDIT = ROOT / "evidence/pc3-r595-recovery-archive-audit-v5-20261029T0205Z.json"
ARCHIVE_AUDIT_SHA256 = "2f70be2ee82521b5822a0b960cffc29d3cbfd907825c10550708040bf7be1f23"
EXPECTED_PACKAGE = {
    "package": "libnvidia-compute-595",
    "version": "595.99.02-0ubuntu0.26.04.1",
    "architecture": "amd64",
    "archive": "packages/libnvidia-compute-595_595.99.02-0ubuntu0.26.04.1_amd64.deb",
    "apt_filename": "pool/restricted/n/nvidia-graphics-drivers-595/libnvidia-compute-595_595.99.02-0ubuntu0.26.04.1_amd64.deb",
    "bytes": 85770234,
    "sha256": "a8f3ed02c0a89502b24a4fdf6a8dd88ffd646c254896cb3e12e8f74bebb06136",
    "signed_source": "resolute-updates/restricted",
    "packages_index_sha256": "58754027a2f17d9ab09eb4dcf4c22f14ad6221695b8de57fecc5160a5e1414f5",
    "signed_release_sha256": "ebbcd81b1c46264144baa563be8d74971303ef8008ef291b8a01ec44f786f829",
}
LIBDIR = PurePosixPath("usr/lib/x86_64-linux-gnu")
REQUIRED_LIBRARIES = {
    "libcuda": "libcuda.so.595.99.02",
    "cuda_debugger": "libcudadebugger.so.595.99.02",
    "nvml": "libnvidia-ml.so.595.99.02",
    "nvvm": "libnvidia-nvvm.so.595.99.02",
    "nvvm70": "libnvidia-nvvm70.so.4",
    "opencl": "libnvidia-opencl.so.595.99.02",
    "ptx_jit_compiler": "libnvidia-ptxjitcompiler.so.595.99.02",
}
LOADER_LINKS = {
    "libcuda.so": "libcuda.so.1",
    "libcuda.so.1": REQUIRED_LIBRARIES["libcuda"],
    "libcudadebugger.so.1": REQUIRED_LIBRARIES["cuda_debugger"],
    "libnvidia-ml.so": "libnvidia-ml.so.1",
    "libnvidia-ml.so.1": REQUIRED_LIBRARIES["nvml"],
    "libnvidia-nvvm.so": "libnvidia-nvvm.so.4",
    "libnvidia-nvvm.so.4": REQUIRED_LIBRARIES["nvvm"],
    "libnvidia-nvvm70.so": "libnvidia-nvvm70.so.4",
    "libnvidia-opencl.so.1": REQUIRED_LIBRARIES["opencl"],
    "libnvidia-ptxjitcompiler.so": "libnvidia-ptxjitcompiler.so.1",
    "libnvidia-ptxjitcompiler.so.1": REQUIRED_LIBRARIES["ptx_jit_compiler"],
}
STAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
DEFAULT_OUTPUT = ROOT / "build/staging/r595.99.02-compute-userland-v1-20261031"
DEFAULT_REPORT = ROOT / "evidence/r595.99.02-compute-userland-stage-v1-20261031.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_pinned_json(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"pinned {label} is missing or unsafe")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"pinned {label} hash differs")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError(f"pinned {label} is malformed") from None
    if not isinstance(data, dict):
        raise ValueError(f"pinned {label} root must be an object")
    return data


def validate_provenance() -> dict[str, Any]:
    manifest = _read_pinned_json(RECOVERY_MANIFEST, RECOVERY_MANIFEST_SHA256,
                                 "R595 recovery manifest")
    if (manifest.get("schema") != "pc3-r595-recovery-package-stage-v1" or
            manifest.get("status") != "archive-set-staged-and-signed-index-verified"):
        raise ValueError("R595 recovery manifest does not describe the pinned signed archive stage")
    package_matches = [row for row in manifest.get("packages", [])
                       if isinstance(row, dict) and row.get("package") == EXPECTED_PACKAGE["package"]]
    if len(package_matches) != 1:
        raise ValueError("R595 recovery manifest does not contain exactly one compute package")
    package = package_matches[0]
    if any(package.get(key) != value for key, value in EXPECTED_PACKAGE.items()):
        raise ValueError("R595 package identity or signed-index provenance differs from the pin")

    audit = _read_pinned_json(ARCHIVE_AUDIT, ARCHIVE_AUDIT_SHA256, "R595 archive audit")
    if (audit.get("schema") != "pc3-r595-recovery-archive-audit-v1" or
            audit.get("status") != "all-archives-match-signed-ubuntu-indexes" or
            audit.get("qualification") != "offline-archive-provenance-and-identity-only" or
            audit.get("manifest", {}).get("sha256") != RECOVERY_MANIFEST_SHA256 or
            audit.get("operational_recovery_proven") is not False):
        raise ValueError("R595 archive audit does not prove the pinned offline archive identity")
    state = audit.get("state_changes", {})
    if any(state.get(key) is not False for key in (
            "driver_or_pci_modified", "maintainer_scripts_run", "modules_loaded",
            "packages_installed", "pc3_contacted")):
        raise ValueError("R595 archive audit reports an unexpected state change")
    audit_matches = [row for row in audit.get("archives", [])
                     if isinstance(row, dict) and row.get("package") == EXPECTED_PACKAGE["package"]]
    if len(audit_matches) != 1:
        raise ValueError("R595 archive audit does not contain exactly one compute archive")
    observed = audit_matches[0]
    expected_audit_identity = {
        "architecture": EXPECTED_PACKAGE["architecture"],
        "archive": EXPECTED_PACKAGE["archive"],
        "bytes": EXPECTED_PACKAGE["bytes"],
        "dpkg_control_identity_verified": True,
        "package": EXPECTED_PACKAGE["package"],
        "sha256": EXPECTED_PACKAGE["sha256"],
        "signed_source": EXPECTED_PACKAGE["signed_source"],
        "version": EXPECTED_PACKAGE["version"],
    }
    if any(observed.get(key) != value for key, value in expected_audit_identity.items()):
        raise ValueError("R595 archive audit package identity differs from the pin")
    ubuntu = audit.get("ubuntu_archive", {})
    if (ubuntu.get("verified_inrelease_count") != 3 or
            ubuntu.get("verified_package_index_count") != 3 or
            ubuntu.get("signing_fingerprint") != "F6ECB3762474EDA9D21B7022871920D1991BC93C"):
        raise ValueError("R595 archive audit does not retain the expected Ubuntu signature chain")
    return {
        "manifest": {"path": str(RECOVERY_MANIFEST.relative_to(ROOT)),
                     "sha256": RECOVERY_MANIFEST_SHA256},
        "archive_audit": {"path": str(ARCHIVE_AUDIT.relative_to(ROOT)),
                          "sha256": ARCHIVE_AUDIT_SHA256,
                          "schema": audit["schema"], "status": audit["status"]},
        "package_signed_source": EXPECTED_PACKAGE["signed_source"],
        "packages_index_sha256": EXPECTED_PACKAGE["packages_index_sha256"],
        "signed_release_sha256": EXPECTED_PACKAGE["signed_release_sha256"],
        "signing_fingerprint": ubuntu["signing_fingerprint"],
    }


def inventory_tree(root: Path) -> list[dict[str, Any]]:
    """Hash regular files and record only non-dangling in-tree symlinks."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("staged package root must be a real directory")
    root = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []

    def record(path: Path) -> dict[str, Any]:
        rel = PurePosixPath(path.relative_to(root).as_posix())
        if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
            raise ValueError("package member path is unsafe")
        info = path.lstat()
        item: dict[str, Any] = {"path": rel.as_posix()}
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError):
                raise ValueError("package symlink escapes stage root or is dangling") from None
            item.update({"type": "symlink", "target": target})
        elif stat.S_ISREG(info.st_mode):
            item.update({"type": "file", "bytes": info.st_size, "sha256": sha256_file(path)})
        else:
            raise ValueError("package contains a non-regular, non-symlink member")
        return item

    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        descend = []
        for name in sorted(dirnames):
            path = current / name
            if path.is_symlink():
                entries.append(record(path))
            else:
                descend.append(name)
        dirnames[:] = descend
        for name in sorted(filenames):
            entries.append(record(current / name))
    entries.sort(key=lambda item: item["path"])
    if not entries:
        raise ValueError("staged package tree is empty")
    paths = [entry["path"] for entry in entries]
    if len(paths) != len(set(paths)):
        raise ValueError("staged package tree has duplicate paths")
    return entries


def validate_compute_userland(root: Path, entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Require the R595 compute libraries and exact loader alias chains."""
    by_path = {entry["path"]: entry for entry in entries}
    result: dict[str, dict[str, Any]] = {}
    for role, basename in REQUIRED_LIBRARIES.items():
        rel = (LIBDIR / basename).as_posix()
        item = by_path.get(rel)
        if not item or item.get("type") != "file":
            raise ValueError(f"required R595 compute library is missing: {basename}")
        result[role] = {key: value for key, value in item.items() if key != "type"}

    for link_name, target in LOADER_LINKS.items():
        rel = (LIBDIR / link_name).as_posix()
        item = by_path.get(rel)
        if not item or item.get("type") != "symlink" or item.get("target") != target:
            raise ValueError(f"R595 loader symlink is missing or differs: {link_name}")
        resolved = (Path(root).resolve(strict=True) / Path(*LIBDIR.parts) / link_name)
        try:
            resolved.resolve(strict=True).relative_to(Path(root).resolve(strict=True))
        except (OSError, ValueError):
            raise ValueError("R595 loader symlink escapes the stage or is dangling") from None
    return result


def _validate_destinations(output_dir: Path, report_path: Path) -> tuple[Path, Path]:
    allowed_stage = (ROOT / "build/staging").resolve(strict=True)
    allowed_evidence = (ROOT / "evidence").resolve(strict=True)
    resolved = []
    for path, parent, label in ((Path(output_dir), allowed_stage, "stage"),
                                (Path(report_path), allowed_evidence, "report")):
        if not STAGE_NAME.fullmatch(path.name):
            raise ValueError(f"{label} destination has an unsafe basename")
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"{label} destination already exists")
        try:
            parent_actual = path.parent.resolve(strict=True)
            parent_actual.relative_to(parent)
        except (OSError, ValueError):
            raise ValueError(f"{label} destination must remain under the project {label} directory") from None
        if parent_actual != parent:
            raise ValueError(f"{label} destination must be a direct child of the project directory")
        resolved.append(parent / path.name)
    return resolved[0], resolved[1]


def _safe_archive_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    if path.is_symlink():
        raise ValueError("R595 package archive must not be a symlink")
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        raise ValueError("R595 package archive must remain inside the canonical project") from None
    current = ROOT
    for index, part in enumerate(relative.parts):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("R595 package archive path contains a symlink")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("R595 package archive parent is not a directory")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ValueError("R595 package archive must be a regular file")
    return current


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def stage_compute_userland(output_dir: Path = DEFAULT_OUTPUT,
                           report_path: Path = DEFAULT_REPORT, *, runner=subprocess.run) -> dict[str, Any]:
    output_dir, report_path = _validate_destinations(output_dir, report_path)
    provenance = validate_provenance()
    archive = _safe_archive_path(RECOVERY_ROOT / EXPECTED_PACKAGE["archive"])
    archive_identity = {"bytes": archive.stat().st_size, "sha256": sha256_file(archive)}
    if archive_identity != {"bytes": EXPECTED_PACKAGE["bytes"],
                            "sha256": EXPECTED_PACKAGE["sha256"]}:
        raise ValueError("R595 package archive differs from the signed, pinned package")
    deb_identity = verify_deb_metadata(archive, EXPECTED_PACKAGE, runner=runner)

    output_dir.mkdir(mode=0o700)
    report_created = False
    try:
        extraction = runner(["dpkg-deb", "--extract", str(archive), str(output_dir)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=False)
        if extraction.returncode != 0:
            raise RuntimeError("dpkg-deb data extraction failed")
        os.chmod(output_dir, 0o700)
        entries = inventory_tree(output_dir)
        libraries = validate_compute_userland(output_dir, entries)
        report: dict[str, Any] = {
            "schema": "r595.99.02-compute-userland-stage-v1",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "qualification": "pinned-r595-compute-userland-staged; no runtime test",
            "package": {
                "path": str(archive.relative_to(ROOT)),
                **EXPECTED_PACKAGE,
                **archive_identity,
                "deb_identity": deb_identity,
            },
            "provenance": provenance,
            "stage": {
                "path": str(output_dir), "mode": "0700", "file_count": len(entries),
                "libraries": libraries, "files": entries,
            },
            "tool_sha256": sha256_file(Path(__file__).resolve(strict=True)),
            "actions": {
                "package_scripts_run": False, "package_installed": False,
                "system_library_paths_changed": False, "module_loaded_or_installed": False,
                "cuda_api_called": False, "gpu_accessed": False,
            },
        }
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        _write_exclusive(report_path, payload, 0o600)
        report_created = True
    except Exception:
        shutil.rmtree(output_dir)
        if report_created:
            report_path.unlink()
        raise
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    try:
        result = stage_compute_userland(args.output_dir, args.report)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"R595 compute userland stage failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "schema": result["schema"], "stage": result["stage"]["path"],
        "file_count": result["stage"]["file_count"],
        "libcuda_sha256": result["stage"]["libraries"]["libcuda"]["sha256"],
        "report": str(args.report),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
