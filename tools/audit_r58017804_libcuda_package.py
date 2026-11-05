#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the exact R580.178.04 libcuda package against the PC3 V100 capture.

The audit reads a locally staged .deb, APT package metadata, and a saved
read-only V100 guest observation. It runs ``dpkg-deb --field`` and extracts
only the package data files into a temporary directory; it never runs package
scripts or installs packages.
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
from tools.stage_nvidia_canary_packages import verify_deb_metadata  # noqa: E402

PACKAGE_VERSION = "580.178.04-0ubuntu0.26.04.1"
EXPECTED_PACKAGE = {
    "package": "libnvidia-compute-580",
    "version": PACKAGE_VERSION,
    "architecture": "amd64",
    "filename": "libnvidia-compute-580_580.178.04-0ubuntu0.26.04.1_amd64.deb",
    "apt_filename": "pool/restricted/n/nvidia-graphics-drivers-580/libnvidia-compute-580_580.178.04-0ubuntu0.26.04.1_amd64.deb",
    "size": 59208394,
    "md5": "1d3a5984447960fb5a0a765274ba9bd0",
    "sha256": "bad67da0389624dfa17cd33b8c6f419a4b962391f3fc7dffc5781bea274f1990",
}
EXPECTED_GUEST_LIBRARY = {
    "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
    "bytes": 96284520,
    "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
}
ARCHIVE_PATH = ROOT / ".cache/canary/pc3-r580-58017804/target" / EXPECTED_PACKAGE["filename"]
GUEST_REPORT_PATH = ROOT / "evidence/pc3-v100-libcuda-instruction-window-v45-20261028T120352Z.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _parse_fields(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        if not line or line[:1].isspace():
            continue
        key, separator, value = line.partition(":")
        if not separator or key in fields:
            raise ValueError("malformed or duplicate APT metadata field")
        fields[key] = value.strip()
    return fields


def validate_apt_record(fields: dict[str, str]) -> dict:
    expected = {
        "Package": EXPECTED_PACKAGE["package"],
        "Version": EXPECTED_PACKAGE["version"],
        "Architecture": EXPECTED_PACKAGE["architecture"],
        "Filename": EXPECTED_PACKAGE["apt_filename"],
        "Size": str(EXPECTED_PACKAGE["size"]),
        "MD5sum": EXPECTED_PACKAGE["md5"],
        "SHA256": EXPECTED_PACKAGE["sha256"],
    }
    if any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError("APT package identity or digest differs from the pin")
    return {
        "package": EXPECTED_PACKAGE["package"],
        "version": EXPECTED_PACKAGE["version"],
        "architecture": EXPECTED_PACKAGE["architecture"],
        "filename": EXPECTED_PACKAGE["filename"],
        "apt_filename": EXPECTED_PACKAGE["apt_filename"],
        "size": EXPECTED_PACKAGE["size"],
        "md5": EXPECTED_PACKAGE["md5"],
        "sha256": EXPECTED_PACKAGE["sha256"],
    }


def validate_guest_observation(report: dict) -> dict:
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-pc3-v100-libcuda-bounded-window-v1":
        raise ValueError("unsupported V100 guest library observation")
    guest = report.get("guest")
    if not isinstance(guest, dict) or guest.get("name") != "pc3-v100":
        raise ValueError("guest identity differs from the pin")
    gpu = guest.get("gpu")
    library = guest.get("libcuda")
    if not isinstance(gpu, dict) or gpu.get("driver_version") != "580.178.04":
        raise ValueError("guest identity differs from the pin")
    if library != EXPECTED_GUEST_LIBRARY:
        raise ValueError("library identity differs from the pin")
    return dict(library)


def verify_archive_file(path: Path, record: dict) -> dict:
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("pinned package archive is missing") from error
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("package archive must be a regular non-symlink file")
    digest = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
            md5.update(block)
    result = {"bytes": size, "md5": md5.hexdigest(), "sha256": digest.hexdigest()}
    if result != {"bytes": record["size"], "md5": record["md5"], "sha256": record["sha256"]}:
        raise ValueError("archive bytes differ from the pinned APT record")
    return result


def compare_library_file(path: Path, expected: dict) -> dict:
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("extracted libcuda file is missing") from error
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("extracted libcuda must be a regular non-symlink file")
    actual = {"bytes": info.st_size, "sha256": _sha256(path)}
    if actual != {"bytes": expected["bytes"], "sha256": expected["sha256"]}:
        raise ValueError("extracted libcuda differs from the captured V100 guest binary")
    return actual


def _read_json(path: Path) -> tuple[dict, str]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("guest observation must be a regular non-symlink file")
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def _safe_archive_path(root: Path, archive: Path) -> Path:
    root = Path(root).resolve(strict=True)
    archive = Path(archive)
    if not archive.is_absolute():
        archive = root / archive
    if archive.is_symlink():
        raise ValueError("package archive path must not be a symlink")
    try:
        relative = archive.relative_to(root)
    except ValueError as error:
        raise ValueError("package archive path escapes the canonical project") from error
    if not relative.parts or any(part in {".", ".."} for part in relative.parts):
        raise ValueError("package archive path escapes the canonical project")
    current = root
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise ValueError("package archive path is missing") from error
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("package archive path has a symlink component")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("package archive parent is not a directory")
    return archive


def audit(*, root: Path = ROOT, archive_path: Path = ARCHIVE_PATH,
          guest_report_path: Path = GUEST_REPORT_PATH, runner=subprocess.run,
          extractor=None) -> dict:
    root = Path(root).resolve(strict=True)
    archive = _safe_archive_path(root, archive_path)
    guest_report, guest_report_sha256 = _read_json(guest_report_path)
    guest_library = validate_guest_observation(guest_report)

    apt_result = runner(["apt-cache", "show", EXPECTED_PACKAGE["package"] + "=" + EXPECTED_PACKAGE["version"]],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if apt_result.returncode != 0:
        raise ValueError("apt-cache package metadata query failed")
    apt_record = validate_apt_record(_parse_fields(apt_result.stdout))
    archive_result = verify_archive_file(archive, apt_record)
    deb_entry = {
        "package": EXPECTED_PACKAGE["package"], "version": EXPECTED_PACKAGE["version"],
        "architecture": EXPECTED_PACKAGE["architecture"],
    }
    deb_control = verify_deb_metadata(archive, deb_entry, runner=runner)

    with tempfile.TemporaryDirectory(prefix="r58017804-libcuda-audit-") as temporary:
        extractor_fn = extractor or runner
        extract_result = extractor_fn(["dpkg-deb", "--extract", str(archive), temporary],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if extract_result.returncode != 0:
            raise ValueError("dpkg-deb data-only extraction failed")
        relative_library = Path("usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04")
        extracted_library = Path(temporary) / relative_library
        library_result = compare_library_file(extracted_library, guest_library)

    auditor_path = Path(__file__)
    test_path = root / "tests/test_audit_r58017804_libcuda_package.py"
    return {
        "schema": "pc3-r58017804-libcuda-package-binary-match-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "archive-library-matches-v100-guest-capture",
        "qualification": "package-and-binary-provenance-validated; no installation or runtime test",
        "auditor": {
            "path": str(auditor_path.relative_to(root)), "sha256": _sha256(auditor_path),
            "focused_test_path": str(test_path.relative_to(root)), "focused_test_sha256": _sha256(test_path),
        },
        "apt_package_record": apt_record,
        "source_url": "http://ca.archive.ubuntu.com/ubuntu/" + apt_record["apt_filename"],
        "archive": {
            "path": str(archive.relative_to(root)), **archive_result,
            "dpkg_control": deb_control["fields"],
        },
        "v100_guest_observation": {
            "path": str(Path(guest_report_path).relative_to(root)),
            "report_sha256": guest_report_sha256,
            "guest": "pc3-v100", "driver_version": "580.178.04",
            "kernel_release": guest_report.get("guest", {}).get("kernel_release"),
            "library": guest_library,
        },
        "binary_comparison": {
            "same_size": library_result["bytes"] == guest_library["bytes"],
            "same_sha256": library_result["sha256"] == guest_library["sha256"],
            "extracted_path": "usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
            "extracted_library": library_result,
        },
        "actions": {
            "package_installed": False, "maintainer_scripts_run": False,
            "module_loaded": False, "pc3_contacted": False,
            "gpu_accessed": False, "host_state_changed": False,
        },
        "limitations": [
            "This proves the origin and bytes of the libcuda binary captured on the separate stock V100 guest.",
            "It does not verify the full user-space package closure or this library against the hybrid kernel modules.",
            "No candidate module, CUDA process, same-Linux dual-GPU execution, UVM, or P2P path was tested.",
        ],
    }


def _write_exclusive(path: Path, report: dict) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite evidence: " + str(path))
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
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
    args = parser.parse_args(argv)
    output = args.output or ROOT / "evidence" / (
        "r58017804-libcuda-package-binary-match-v1-" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    try:
        report = audit()
        _write_exclusive(output, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "archive_sha256": report["archive"]["sha256"],
                      "guest_libcuda_sha256": report["v100_guest_observation"]["library"]["sha256"],
                      "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
