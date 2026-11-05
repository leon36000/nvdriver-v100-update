#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline verification of the staged PC3 R595 recovery archives.

Checks the pinned stage manifest, signed Ubuntu Release/index chain, package
records, .deb control identities, and captured PC3 inventory. It never contacts
PC3, installs packages, runs maintainer scripts, or changes system state.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".cache/canary/pc3-r595-recovery-20261028T1629Z"
MANIFEST = STAGE / "manifest.json"
MANIFEST_SHA256 = "eedb4723859f6c737ee8d0dbf975a8d77ea9076bc84824b0e16d2fb89bcccad2"
HOST_SNAPSHOT = ROOT / "evidence/pc3-canary-host-state-package-audit-v1-20261028T1540Z.json"
HOST_SNAPSHOT_SHA256 = "e85b41d72e08411af72d77415517c805511a8f72d72787ddc8dbbba3d182a3fd"
HOST_SNAPSHOT_SCHEMA = "nvidia-hybrid-canary-host-state-v2"
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
EXPECTED_SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024

sys.path.insert(0, str(ROOT))
from tools.audit_r58017804_v100_compute_package import parse_release_sha256  # noqa: E402


def parse_control_paragraph(paragraph: str) -> dict[str, str]:
    if not isinstance(paragraph, str):
        raise ValueError("Debian control paragraph must be text")
    fields: dict[str, str] = {}
    current = None
    for line in paragraph.splitlines():
        if not line:
            continue
        if line[0].isspace():
            if current is None:
                raise ValueError("orphan Debian control continuation")
            fields[current] += " " + line.strip()
            continue
        key, separator, value = line.partition(":")
        if not separator or not key or key in fields:
            raise ValueError("malformed or duplicate Debian control field")
        current = key
        fields[key] = value.strip()
    return fields


def parse_packages_index(index_bytes: bytes) -> list[dict[str, str]]:
    if not isinstance(index_bytes, bytes) or not index_bytes or len(index_bytes) > MAX_INDEX_BYTES:
        raise ValueError("APT package index size is invalid")
    try:
        text = index_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ValueError("APT package index is not UTF-8") from error
    rows = []
    for paragraph in re.split(r"\n[ \t]*\n", text):
        if paragraph.strip():
            fields = parse_control_paragraph(paragraph)
            if not all(fields.get(key) for key in ("Package", "Version", "Architecture")):
                raise ValueError("APT package paragraph lacks its identity")
            rows.append(fields)
    if not rows:
        raise ValueError("APT package index contains no package records")
    return rows


def find_package_record(rows: list[dict[str, str]], package: str,
                        version: str, architecture: str) -> dict[str, str]:
    matches = [row for row in rows if (row.get("Package"), row.get("Version"),
                                       row.get("Architecture")) ==
               (package, version, architecture)]
    if len(matches) != 1:
        raise ValueError("signed APT index must contain exactly one package identity")
    return matches[0]


def safe_bundle_file(root: Path, relative_path: str) -> Path:
    if (not isinstance(relative_path, str) or not relative_path or "\\" in relative_path):
        raise ValueError("bundle path is malformed")
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("bundle path escapes its root")
    root = Path(root).resolve(strict=True)
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise ValueError("bundle path is missing") from error
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("bundle path contains a symlink")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("bundle path component is not a directory")
        if index == len(relative.parts) - 1 and not stat.S_ISREG(info.st_mode):
            raise ValueError("bundle path is not a regular file")
    return current


def _hash(path: Path, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > limit:
                raise ValueError("bundle input exceeds its size limit")
            digest.update(chunk)
    return size, digest.hexdigest()


def _read_json(path: Path, limit: int) -> tuple[dict, str]:
    size, digest = _hash(path, limit)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("bundle JSON root must be an object")
    return value, digest


def _verify_release(path: Path, expected_hash: str, keyring: Path) -> tuple[str, str]:
    size, digest = _hash(path, 4 * 1024 * 1024)
    if digest != expected_hash:
        raise ValueError("Ubuntu InRelease bytes differ from the pinned manifest")
    with tempfile.TemporaryDirectory(prefix="pc3-r595-release-audit-") as temporary:
        release_path = Path(temporary) / "Release"
        result = subprocess.run(
            ["gpgv", "--keyring", str(keyring), "--status-fd", "1", "--output",
             str(release_path), str(path)], capture_output=True, text=True,
            check=False, timeout=30)
        if result.returncode != 0:
            raise ValueError("Ubuntu InRelease signature verification failed")
        valid = [line.split() for line in result.stdout.splitlines()
                 if line.startswith("[GNUPG:] VALIDSIG ")]
        if len(valid) != 1 or valid[0][2] != EXPECTED_SIGNER:
            raise ValueError("Ubuntu InRelease signer differs from the pinned archive key")
        return release_path.read_text(encoding="utf-8", errors="strict"), digest


def _installed_index(packages: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for row in packages:
        if not isinstance(row, dict):
            raise ValueError("captured package inventory contains a malformed row")
        if row.get("status") == "ii":
            name, version = row.get("name"), row.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError("captured installed package lacks identity")
            result.setdefault(name.partition(":")[0], []).append(version)
    return result


def classify_snapshot_package(package: str, version: str,
                              package_index: dict[str, list[str]]) -> tuple[bool, str]:
    versions = package_index.get(package, [])
    installed_exact = len(versions) == 1 and versions[0] == version
    state = ("installed-exact-in-snapshot" if installed_exact else
             "not-in-snapshot-included-for-metapackage-dependency")
    return installed_exact, state


def load_stage_creation_snapshot(root: Path, metadata: dict) -> tuple[dict, dict]:
    """Verify the historical inventory that the stage manifest annotated."""
    if (not isinstance(metadata, dict) or
            not isinstance(metadata.get("path"), str) or
            not isinstance(metadata.get("sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]) is None):
        raise ValueError("stage-creation snapshot metadata is malformed")
    path = safe_bundle_file(root, metadata["path"])
    snapshot, digest = _read_json(path, 16 * 1024 * 1024)
    validate_host_snapshot_identity(snapshot, digest, metadata["sha256"])
    if (snapshot.get("kernel_release") != metadata.get("kernel_release") or
            snapshot.get("loaded_nvidia_module_version") !=
            metadata.get("loaded_nvidia_module_version")):
        raise ValueError("stage-creation snapshot metadata differs from its pinned inventory")
    return snapshot, {"path": str(path.relative_to(Path(root).resolve(strict=True))),
                      "sha256": digest,
                      "observed_at_utc": snapshot.get("observed_at_utc"),
                      "kernel_release": snapshot["kernel_release"],
                      "loaded_nvidia_module_version": snapshot["loaded_nvidia_module_version"]}


def resolve_host_snapshot_inputs(snapshot_path: Path | None,
                                 snapshot_sha256: str | None) -> tuple[Path, str]:
    """Use the pinned historical default or require an exact caller pin."""
    if snapshot_path is None and snapshot_sha256 is None:
        return HOST_SNAPSHOT, HOST_SNAPSHOT_SHA256
    if snapshot_path is None or snapshot_sha256 is None:
        raise ValueError("host snapshot path and SHA-256 must be supplied together")
    if not isinstance(snapshot_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256) is None:
        raise ValueError("host snapshot SHA-256 must be 64 lowercase SHA-256 hex characters")
    return Path(snapshot_path), snapshot_sha256


def validate_host_snapshot_identity(host: dict, actual_sha256: str,
                                    expected_sha256: str) -> None:
    """Fail closed unless this is the exact pinned, complete PC3 inventory."""
    if (not isinstance(expected_sha256, str) or
            re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None or
            actual_sha256 != expected_sha256):
        raise ValueError("captured PC3 host snapshot SHA-256 differs from the exact pin")
    if (not isinstance(host, dict) or host.get("schema") != HOST_SNAPSHOT_SCHEMA or
            host.get("host") != "pc3"):
        raise ValueError("host snapshot must identify the supported PC3 inventory schema")
    inventory = host.get("driver_recovery_inventory")
    if (not isinstance(inventory, dict) or
            inventory.get("package_query_complete") is not True or
            not isinstance(inventory.get("packages"), list)):
        raise ValueError("captured PC3 package inventory is incomplete")


def audit(stage_root: Path = STAGE, manifest_path: Path = MANIFEST,
          host_snapshot_path: Path = HOST_SNAPSHOT, *,
          host_snapshot_sha256: str = HOST_SNAPSHOT_SHA256,
          runner=subprocess.run) -> dict:
    root = Path(ROOT).resolve(strict=True)
    stage_root = Path(stage_root)
    try:
        stage_relative = stage_root.absolute().relative_to(root)
    except ValueError as error:
        raise ValueError("stage root escapes the canonical project") from error
    stage_root = root / stage_relative
    manifest_rel = Path(manifest_path).absolute().relative_to(root)
    host_rel = Path(host_snapshot_path).absolute().relative_to(root)
    manifest_file = safe_bundle_file(root, manifest_rel.as_posix())
    host_file = safe_bundle_file(root, host_rel.as_posix())
    manifest, manifest_hash = _read_json(manifest_file, MAX_MANIFEST_BYTES)
    if manifest_hash != MANIFEST_SHA256:
        raise ValueError("recovery manifest differs from the pinned stage")
    if (manifest.get("schema") != "pc3-r595-recovery-package-stage-v1" or
            manifest.get("status") != "archive-set-staged-and-signed-index-verified"):
        raise ValueError("unsupported or unsuccessful R595 recovery stage")
    if Path(manifest.get("stage_root", "")).resolve(strict=True) != stage_root.resolve(strict=True):
        raise ValueError("manifest stage root does not match the selected bundle")
    stage_snapshot, stage_snapshot_identity = load_stage_creation_snapshot(
        root, manifest.get("pc3_snapshot"))
    stage_snapshot_package_index = _installed_index(
        stage_snapshot["driver_recovery_inventory"].get("packages"))
    host, host_hash = _read_json(host_file, 16 * 1024 * 1024)
    validate_host_snapshot_identity(host, host_hash, host_snapshot_sha256)
    current_snapshot_package_index = _installed_index(host["driver_recovery_inventory"].get("packages"))

    if KEYRING.is_symlink() or not KEYRING.is_file():
        raise ValueError("Ubuntu archive keyring is unavailable or unsafe")
    keyring_sha = _hash(KEYRING, 16 * 1024 * 1024)[1]
    signed_releases = {}
    for entry in manifest.get("provenance", {}).get("inrelease_signatures", []):
        release_path = safe_bundle_file(stage_root, entry.get("inrelease"))
        release_text, release_hash = _verify_release(release_path, entry.get("sha256"), KEYRING)
        if entry.get("signing_fingerprint") != EXPECTED_SIGNER:
            raise ValueError("manifest signer differs from the pinned Ubuntu archive key")
        signed_releases[entry["inrelease"]] = release_text

    package_indexes = {}
    index_results = []
    for entry in manifest.get("provenance", {}).get("packages_indexes", []):
        path = safe_bundle_file(stage_root, entry.get("packages_index"))
        size, digest = _hash(path, MAX_INDEX_BYTES)
        if size != entry.get("bytes") or digest != entry.get("sha256"):
            raise ValueError("APT package index bytes differ from the pinned manifest")
        release_text = signed_releases.get(entry.get("signed_release"))
        if release_text is None or parse_release_sha256(release_text, entry.get("release_path")) != (size, digest):
            raise ValueError("APT package index is not pinned by its signed Ubuntu Release")
        package_indexes[entry.get("source")] = parse_packages_index(path.read_bytes())
        index_results.append({"source": entry["source"], "bytes": size,
                              "sha256": digest, "signed_release": entry["signed_release"],
                              "release_path": entry["release_path"]})
    if len(signed_releases) != 3 or len(package_indexes) != 3:
        raise ValueError("stage must contain the three expected signed archive indexes")

    archive_results = []
    installed_matches = []
    total_bytes = 0
    seen = set()
    for entry in manifest.get("packages", []):
        identity = (entry.get("package"), entry.get("version"), entry.get("architecture"))
        if identity in seen:
            raise ValueError("stage repeats a package identity")
        seen.add(identity)
        rows = package_indexes.get(entry.get("signed_source"))
        if rows is None:
            raise ValueError("package names an unknown signed APT index")
        record = find_package_record(rows, *identity)
        expected_archive = (entry.get("apt_filename"), str(entry.get("bytes")), entry.get("sha256"))
        observed_archive = (record.get("Filename"), record.get("Size"), record.get("SHA256", "").lower())
        if expected_archive != observed_archive:
            raise ValueError("signed APT package identity/hash differs from the stage manifest")
        if record.get("Depends", "") != entry.get("depends", ""):
            raise ValueError("signed APT dependency metadata differs from the stage manifest")
        archive = safe_bundle_file(stage_root, entry.get("archive"))
        size, digest = _hash(archive, MAX_ARCHIVE_BYTES)
        if size != entry.get("bytes") or digest != entry.get("sha256"):
            raise ValueError("staged .deb bytes differ from the signed APT package record")
        control = runner(["dpkg-deb", "--field", str(archive)], capture_output=True,
                         text=True, check=False, timeout=30)
        if control.returncode != 0:
            raise ValueError("dpkg-deb could not read a staged package control record")
        fields = parse_control_paragraph(control.stdout)
        if (fields.get("Package"), fields.get("Version"), fields.get("Architecture"),
                fields.get("Depends", "")) != (*identity, entry.get("depends", "")):
            raise ValueError("staged .deb control identity differs from signed APT metadata")
        _, expected_stage_state = classify_snapshot_package(
            identity[0], identity[1], stage_snapshot_package_index)
        if entry.get("snapshot_state") != expected_stage_state:
            raise ValueError("stage annotation differs from its pinned stage-creation snapshot")
        current_installed_exact, current_snapshot_state = classify_snapshot_package(
            identity[0], identity[1], current_snapshot_package_index)
        installed_matches.append({"package": identity[0], "version": identity[1],
                                  "installed_exactly": current_installed_exact})
        archive_results.append({"package": identity[0], "version": identity[1],
                                "architecture": identity[2], "bytes": size,
                                "sha256": digest, "signed_source": entry["signed_source"],
                                "archive": entry["archive"],
                                "dpkg_control_identity_verified": True,
                                "snapshot_state": expected_stage_state,
                                "current_snapshot_state": current_snapshot_state})
        total_bytes += size
    if (len(archive_results) != 20 or total_bytes != manifest.get("total_archive_bytes") or
            len(installed_matches) != 20):
        raise ValueError("archive count or aggregate size differs from the pinned stage")
    match_count = sum(row["installed_exactly"] for row in installed_matches)
    return {
        "schema": "pc3-r595-recovery-archive-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "all-archives-match-signed-ubuntu-indexes",
        "qualification": "offline-archive-provenance-and-identity-only",
        "manifest": {"path": str(manifest_file.relative_to(root)), "sha256": manifest_hash},
        "stage_creation_snapshot": stage_snapshot_identity,
        "host_snapshot": {"path": str(host_file.relative_to(root)), "sha256": host_hash,
                          "host": host["host"], "kernel_release": host["kernel_release"],
                          "observed_at_utc": host.get("observed_at_utc"),
                          "loaded_nvidia_module_version": host["loaded_nvidia_module_version"]},
        "ubuntu_archive": {"keyring": str(KEYRING), "keyring_sha256": keyring_sha,
                            "signing_fingerprint": EXPECTED_SIGNER,
                            "verified_inrelease_count": len(signed_releases),
                            "verified_package_index_count": len(index_results),
                            "package_indexes": index_results},
        "archives": archive_results,
        "archive_count": len(archive_results),
        "total_archive_bytes": total_bytes,
        "captured_snapshot_exact_version_matches": match_count,
        "captured_snapshot_expected_packages": len(archive_results),
        "operational_recovery_proven": False,
        "state_changes": {"pc3_contacted": False, "packages_installed": False,
                          "maintainer_scripts_run": False, "modules_loaded": False,
                          "driver_or_pci_modified": False},
        "limitations": [
            "Stage snapshot annotations describe the stage-time inventory only; packages omitted by its collection scope were not thereby proven absent from the host.",
            "The current host snapshot is a captured PC3 observation, not a live query performed by this offline audit.",
            "Archive identity and signed-index provenance do not prove full dependency closure, installation, boot, driver operation, or rollback recovery.",
            "No package installation, module operation, boot, or hardware test was performed.",
        ],
    }


def write_private_exclusive(path: Path, report: dict) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite existing evidence: " + str(path))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp",
                                          dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--host-snapshot", type=Path,
                        help="captured PC3 host inventory; requires --host-snapshot-sha256")
    parser.add_argument("--host-snapshot-sha256",
                        help="exact lowercase SHA-256 pin for --host-snapshot")
    args = parser.parse_args(argv)
    output = args.output or ROOT / ("evidence/pc3-r595-recovery-archive-audit-v1-%s.json" %
                                   datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    try:
        host_snapshot_path, host_snapshot_sha256 = resolve_host_snapshot_inputs(
            args.host_snapshot, args.host_snapshot_sha256)
        report = audit(host_snapshot_path=host_snapshot_path,
                       host_snapshot_sha256=host_snapshot_sha256)
        write_private_exclusive(output, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError) as error:
        print("recovery archive audit failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "archives": report["archive_count"],
                      "bytes": report["total_archive_bytes"],
                      "exact_snapshot_matches": report["captured_snapshot_exact_version_matches"],
                      "operational_recovery_proven": report["operational_recovery_proven"],
                      "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
