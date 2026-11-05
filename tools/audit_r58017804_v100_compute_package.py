#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the V100 guest's R580.178.04 compute libraries to Ubuntu's signed package.

This read-only audit verifies Ubuntu's InRelease signature and the package index
digest, downloads the exact amd64 .deb into a private temporary directory,
checks its signed-index size and SHA-256, and extracts package data only. It
does not run package scripts or install anything.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
import urllib.request
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SUITE = "noble-security"
PACKAGE = "libnvidia-compute-580-server"
VERSION = "580.178.04-0ubuntu0.24.04.1"
ARCHITECTURE = "amd64"
PACKAGE_DIRECTORY = "pool/restricted/n/nvidia-graphics-drivers-580-server/"
INDEX_RELATIVE = "restricted/binary-amd64/Packages.xz"
ARCHIVE_BASE = "https://archive.ubuntu.com/ubuntu/"
INRELEASE_URL = ARCHIVE_BASE + "dists/" + SUITE + "/InRelease"
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
GUEST_CAPTURE_SCHEMA = "nvidia-hybrid-pc3-v100-package-inventory-capture-v1"
EXPECTED_GUEST_REPORT = ROOT / "evidence/pc3-v100-package-inventory-v2-20261028T1605Z.json"
EXPECTED_GUEST_REPORT_SHA256 = "31356b8ce32ac18d8278050e46f5c3bc536f81c6fd525897f5f168e33c1875a4"
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_KEYRING_BYTES = 64 * 1024 * 1024


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid)


def _snapshot_keyring(destination: Path) -> tuple[int, str]:
    """Copy the exact no-follow keyring inode to a private, stable snapshot."""
    destination = Path(destination)
    source_fd = None
    snapshot_fd = None
    complete = False
    digest = hashlib.sha256()
    size = 0
    try:
        source_fd = os.open(KEYRING, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                            getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_KEYRING_BYTES:
            raise ValueError("Ubuntu archive keyring is not a bounded regular file")
        snapshot_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_KEYRING_BYTES:
                raise ValueError("Ubuntu archive keyring exceeded its size bound")
            digest.update(block)
            remaining = memoryview(block)
            while remaining:
                written = os.write(snapshot_fd, remaining)
                if written <= 0:
                    raise OSError("short keyring snapshot write")
                remaining = remaining[written:]
        after = os.fstat(source_fd)
        path_after = os.stat(KEYRING, follow_symlinks=False)
        snapshot = os.fstat(snapshot_fd)
        if (_file_identity(before) != _file_identity(after) or
                _file_identity(before) != _file_identity(path_after) or
                size != before.st_size or snapshot.st_size != size):
            raise ValueError("keyring changed during snapshot")
        os.fchmod(snapshot_fd, 0o600)
        os.fsync(snapshot_fd)
        if stat.S_IMODE(os.fstat(snapshot_fd).st_mode) != 0o600:
            raise ValueError("keyring snapshot permissions are not private")
        complete = True
        return size, digest.hexdigest()
    except OSError as error:
        raise ValueError("keyring changed during snapshot") from error
    finally:
        if snapshot_fd is not None:
            os.close(snapshot_fd)
        if source_fd is not None:
            os.close(source_fd)
        if not complete:
            try:
                destination.unlink()
            except OSError:
                pass


def parse_release_sha256(release_text: str, relative_path: str) -> tuple[int, str]:
    """Return the signed Release size/digest for one exact relative path."""
    if not isinstance(release_text, str) or not isinstance(relative_path, str):
        raise ValueError("signed Release input is invalid")
    active = False
    records: dict[str, tuple[int, str]] = {}
    for line in release_text.splitlines():
        if line == "SHA256:":
            if active:
                raise ValueError("signed Release repeats its SHA256 section")
            active = True
            continue
        if active and line and not line[0].isspace():
            break
        if active and line.strip():
            fields = line.split()
            if (len(fields) != 3 or re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]) is None or
                    not fields[1].isdigit() or fields[2] in records):
                raise ValueError("signed Release SHA256 record is malformed")
            records[fields[2]] = (int(fields[1]), fields[0].lower())
    if not active or relative_path not in records:
        raise ValueError("signed Release does not pin the requested package index")
    return records[relative_path]


def _parse_control_paragraph(paragraph: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in paragraph.splitlines():
        if not line or line[0].isspace():
            continue
        key, separator, value = line.partition(":")
        if not separator or key in fields:
            raise ValueError("APT package control paragraph is malformed")
        fields[key] = value.strip()
    return fields


def parse_packages_index(index_bytes: bytes, package: str, version: str,
                         architecture: str) -> dict[str, str]:
    """Find one exact package record in a compressed apt Packages index."""
    if not isinstance(index_bytes, bytes) or not index_bytes or len(index_bytes) > MAX_INDEX_BYTES:
        raise ValueError("APT package index size is invalid")
    try:
        text = lzma.decompress(index_bytes).decode("utf-8", "strict")
    except (lzma.LZMAError, UnicodeDecodeError):
        raise ValueError("APT package index is not a valid xz UTF-8 stream") from None
    matches = []
    for paragraph in re.split(r"\n\s*\n", text):
        if not paragraph.strip():
            continue
        fields = _parse_control_paragraph(paragraph)
        if (fields.get("Package"), fields.get("Version"), fields.get("Architecture")) == (
                package, version, architecture):
            matches.append(fields)
    if len(matches) != 1:
        raise ValueError("APT index does not contain exactly one exact package pin")
    fields = matches[0]
    if (not fields.get("Filename", "").startswith(PACKAGE_DIRECTORY) or
            PurePosixPath(fields["Filename"]).is_absolute() or
            ".." in PurePosixPath(fields["Filename"]).parts or
            not fields.get("Size", "").isdigit() or
            not 0 < int(fields["Size"]) <= MAX_PACKAGE_BYTES or
            re.fullmatch(r"[0-9a-fA-F]{64}", fields.get("SHA256", "")) is None):
        raise ValueError("exact package record has unsafe or incomplete archive metadata")
    return fields


def compare_package_libraries(guest_inventory: dict[str, Any], extracted_root: Path,
                              package_name: str = PACKAGE) -> dict[str, Any]:
    """Compare all recorded library paths owned by one guest package."""
    if not isinstance(guest_inventory, dict) or not isinstance(guest_inventory.get("packages"), list) or \
            not isinstance(guest_inventory.get("libraries"), list):
        raise ValueError("guest package inventory is invalid")
    package_records = [item for item in guest_inventory["packages"]
                       if isinstance(item, dict) and item.get("name", "").split(":", 1)[0] == package_name]
    if len(package_records) != 1 or package_records[0].get("version") != VERSION:
        raise ValueError("guest compute package identity differs from the pinned R580 build")
    libraries = [item for item in guest_inventory["libraries"]
                 if isinstance(item, dict) and item.get("package", "").split(":", 1)[0] == package_name]
    if not libraries or len(libraries) > 512:
        raise ValueError("guest compute package library set is empty or over its bound")
    root = Path(extracted_root).resolve(strict=True)
    rows = []
    seen: set[str] = set()
    for library in sorted(libraries, key=lambda item: item.get("path", "")):
        path_text = library.get("path")
        if (not isinstance(path_text, str) or not path_text.startswith("/") or
                ".." in PurePosixPath(path_text).parts or path_text in seen):
            raise ValueError("guest compute package contains an invalid or duplicate library path")
        seen.add(path_text)
        relative = PurePosixPath(path_text).relative_to("/")
        candidate = root.joinpath(*relative.parts)
        try:
            candidate_resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            rows.append({"path": path_text, "status": "missing"})
            continue
        try:
            candidate_resolved.relative_to(root)
        except ValueError:
            raise ValueError("extracted package library symlink escapes the extraction directory") from None
        info = candidate.stat()
        if not stat.S_ISREG(info.st_mode):
            rows.append({"path": path_text, "status": "different", "reason": "not a regular file"})
            continue
        digest = hashlib.sha256()
        with candidate.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        guest_resolved = library.get("resolved_path")
        archive_resolved = "/" + candidate_resolved.relative_to(root).as_posix()
        link_matches = archive_resolved == guest_resolved and candidate.is_symlink() is library.get("is_symlink")
        bytes_match = info.st_size == library.get("bytes")
        hash_matches = digest.hexdigest() == library.get("sha256")
        matched = link_matches and bytes_match and hash_matches
        rows.append({
            "path": path_text,
            "status": "match" if matched else "different",
            "bytes_match": bytes_match,
            "sha256_match": hash_matches,
            "symlink_target_match": link_matches,
            "guest_bytes": library.get("bytes"),
            "archive_bytes": info.st_size,
            "guest_sha256": library.get("sha256"),
            "archive_sha256": digest.hexdigest(),
            "guest_resolved_path": guest_resolved,
            "archive_resolved_path": archive_resolved,
            "guest_is_symlink": library.get("is_symlink"),
            "archive_is_symlink": candidate.is_symlink(),
        })
    matched = sum(row["status"] == "match" for row in rows)
    different = sum(row["status"] == "different" for row in rows)
    missing = sum(row["status"] == "missing" for row in rows)
    return {"paths": len(rows), "matched": matched, "different": different,
            "missing": missing, "comparisons": rows}


def load_pinned_legacy_guest_inventory(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load only the exact historical v1 capture this offline audit was built for.

    The current collector's v6 validator intentionally rejects v1. This adapter
    keeps the dated package-provenance audit reproducible without weakening that
    validator or accepting arbitrary legacy inventories.
    """
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INDEX_BYTES:
        raise ValueError("pinned historical guest capture has an invalid size")
    if hashlib.sha256(raw).hexdigest() != EXPECTED_GUEST_REPORT_SHA256:
        raise ValueError("guest report is not the pinned historical guest capture")
    capture = json.loads(raw)
    capture_fields = {
        "collection_scope", "driver_or_gpu_execution_tested", "guest_hostkey_fingerprint",
        "guest_inventory", "guest_script_sha256", "guest_stderr_sha256", "host_or_guest_mutation_performed",
        "observed_at_utc", "pinned_libcuda_comparison", "read_only_guest_query", "schema", "status",
        "target", "transport_script_sha256",
    }
    if (not isinstance(capture, dict) or set(capture) != capture_fields or
            capture.get("schema") != GUEST_CAPTURE_SCHEMA or capture.get("status") != "collected" or
            capture.get("guest_hostkey_fingerprint") !=
            "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"):
        raise ValueError("pinned historical guest capture identity or status is invalid")
    inventory = capture.get("guest_inventory")
    inventory_fields = {"hostname", "kernel_release", "libraries", "observed_at_utc",
                        "packages", "pinned_libcuda_path", "schema"}
    if (not isinstance(inventory, dict) or set(inventory) != inventory_fields or
            inventory.get("schema") != "nvidia-hybrid-pc3-v100-package-inventory-v1" or
            inventory.get("hostname") != "pc3-v100" or
            inventory.get("kernel_release") != "6.8.0-147-generic" or
            not isinstance(inventory.get("packages"), list) or len(inventory["packages"]) != 75 or
            not isinstance(inventory.get("libraries"), list) or len(inventory["libraries"]) != 54):
        raise ValueError("pinned historical guest inventory schema is invalid")
    package_fields = {"architecture", "name", "status", "version"}
    if any(not isinstance(item, dict) or set(item) != package_fields or
           not all(isinstance(item.get(key), str) for key in package_fields)
           for item in inventory["packages"]):
        raise ValueError("pinned historical guest package records are invalid")
    library_fields = {"bytes", "is_symlink", "package", "path", "resolved_path", "sha256"}
    for item in inventory["libraries"]:
        if (not isinstance(item, dict) or set(item) != library_fields or
                not isinstance(item.get("package"), str) or
                not isinstance(item.get("path"), str) or
                not isinstance(item.get("resolved_path"), str) or
                not item["path"].startswith("/") or not item["resolved_path"].startswith("/") or
                ".." in PurePosixPath(item["path"]).parts or
                ".." in PurePosixPath(item["resolved_path"]).parts or
                type(item.get("is_symlink")) is not bool or
                type(item.get("bytes")) is not int or not 0 < item["bytes"] <= 512 * 1024 * 1024 or
                re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) is None):
            raise ValueError("pinned historical guest library records are invalid")
    package_records = [item for item in inventory["packages"]
                       if item["name"].split(":", 1)[0] == PACKAGE]
    if (len(package_records) != 1 or package_records[0] != {
            "architecture": ARCHITECTURE, "name": PACKAGE + ":amd64",
            "status": "install ok installed", "version": VERSION}):
        raise ValueError("pinned historical guest compute package differs from the exact R580 pin")
    if inventory.get("pinned_libcuda_path") != "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04":
        raise ValueError("pinned historical guest libcuda path differs from the R580 pin")
    return capture, inventory


def _safe_project_file(value: str | Path, *, default: Path | None = None) -> Path:
    raw = Path(value) if value is not None else default
    if raw is None:
        raise ValueError("a project file path is required")
    candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = Path(os.path.abspath(candidate))
    try:
        relative = candidate.relative_to(ROOT)
    except ValueError:
        raise ValueError("audit file path escapes the canonical project") from None
    current = ROOT
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("audit file path has a symlink component")
    return candidate


def _download(url: str, destination: Path, maximum: int) -> tuple[int, str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "nvidia-hybrid-package-audit/1"})
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "archive.ubuntu.com":
                raise ValueError("Ubuntu download redirected outside the pinned HTTPS archive")
            with destination.open("xb") as stream:
                os.chmod(destination, 0o600)
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > maximum:
                        raise ValueError("Ubuntu download exceeded its size bound")
                    digest.update(block)
                    stream.write(block)
    except Exception:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return size, digest.hexdigest(), response.geturl()


def audit(guest_report_path: Path = EXPECTED_GUEST_REPORT) -> dict[str, Any]:
    guest_path = _safe_project_file(guest_report_path)
    if not guest_path.is_file():
        raise ValueError("V100 guest package inventory is missing")
    guest_raw = guest_path.read_bytes()
    if len(guest_raw) > MAX_INDEX_BYTES:
        raise ValueError("V100 guest inventory exceeds its size bound")
    guest_capture, inventory = load_pinned_legacy_guest_inventory(guest_raw)
    guest_package = next((item for item in inventory["packages"]
                          if item["name"].split(":", 1)[0] == PACKAGE), None)
    if guest_package is None or guest_package["version"] != VERSION or guest_package["architecture"] != ARCHITECTURE:
        raise ValueError("installed V100 guest compute package differs from the exact R580 pin")
    if guest_capture.get("pinned_libcuda_comparison", {}).get("matches_prior_capture") is not True:
        raise ValueError("V100 guest libcuda no longer matches the previously pinned capture")

    if not KEYRING.is_file() or KEYRING.is_symlink():
        raise ValueError("Ubuntu archive keyring is unavailable or unsafe")
    with tempfile.TemporaryDirectory(prefix="r580-v100-compute-audit-") as temporary:
        work = Path(temporary)
        keyring_snapshot = work / "ubuntu-archive-keyring.gpg"
        keyring_bytes, keyring_sha256 = _snapshot_keyring(keyring_snapshot)
        inrelease = work / "InRelease"
        release = work / "Release"
        inrelease_size, inrelease_sha256, inrelease_final = _download(
            INRELEASE_URL, inrelease, 4 * 1024 * 1024)
        signature = subprocess.run(["gpgv", "--keyring", str(keyring_snapshot), "--output", str(release),
                                    str(inrelease)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False, timeout=30)
        if signature.returncode != 0:
            raise ValueError("Ubuntu InRelease signature verification failed")
        release_text = release.read_text(encoding="utf-8", errors="strict")
        index_size, index_sha256 = parse_release_sha256(release_text, INDEX_RELATIVE)
        if index_size > MAX_INDEX_BYTES:
            raise ValueError("signed Ubuntu package index exceeds its size bound")
        package_index = work / "Packages.xz"
        fetched_index_size, fetched_index_sha256, index_final = _download(
            ARCHIVE_BASE + "dists/" + SUITE + "/" + INDEX_RELATIVE,
            package_index, MAX_INDEX_BYTES)
        if (fetched_index_size, fetched_index_sha256) != (index_size, index_sha256):
            raise ValueError("Ubuntu package index differs from the signed Release metadata")
        fields = parse_packages_index(package_index.read_bytes(), PACKAGE, VERSION, ARCHITECTURE)
        archive_rel = fields["Filename"]
        archive = work / "package.deb"
        archive_size, archive_sha256, archive_final = _download(
            ARCHIVE_BASE + archive_rel, archive, MAX_PACKAGE_BYTES)
        if (archive_size, archive_sha256) != (int(fields["Size"]), fields["SHA256"].lower()):
            raise ValueError("downloaded package archive differs from the signed package index")
        control = subprocess.run(["dpkg-deb", "--field", str(archive)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 check=False, timeout=30)
        if control.returncode != 0:
            raise ValueError("dpkg-deb control metadata query failed")
        control_fields = _parse_control_paragraph(control.stdout.decode("utf-8", "strict"))
        if (control_fields.get("Package"), control_fields.get("Version"),
                control_fields.get("Architecture")) != (PACKAGE, VERSION, ARCHITECTURE):
            raise ValueError("downloaded .deb control identity differs from the pin")
        extracted = work / "extracted"
        extracted.mkdir(mode=0o700)
        unpack = subprocess.run(["dpkg-deb", "--extract", str(archive), str(extracted)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=90)
        if unpack.returncode != 0:
            raise ValueError("data-only package extraction failed")
        comparison = compare_package_libraries(inventory, extracted)

    matched = comparison["matched"]
    report = {
        "schema": "pc3-v100-r58017804-compute-package-library-match-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "all-package-library-paths-match" if matched == comparison["paths"] else "package-library-mismatch",
        "qualification": "ubuntu-signed-package-provenance-and-library-bytes-compared; no installation or CUDA execution",
        "guest_inventory": {"path": str(guest_path.relative_to(ROOT)),
                            "sha256": hashlib.sha256(guest_raw).hexdigest(),
                            "guest": inventory["hostname"], "kernel_release": inventory["kernel_release"],
                            "package": guest_package},
        "ubuntu_source": {"archive_base": ARCHIVE_BASE, "suite": SUITE,
                          "inrelease_url": INRELEASE_URL, "inrelease_final_url": inrelease_final,
                          "inrelease_bytes": inrelease_size, "inrelease_sha256": inrelease_sha256,
                          "inrelease_gpgv_verified": True,
                          "keyring": str(KEYRING), "keyring_bytes": keyring_bytes,
                          "keyring_sha256": keyring_sha256,
                          "signed_package_index_path": INDEX_RELATIVE,
                          "signed_package_index_url": index_final,
                          "signed_package_index_bytes": index_size,
                          "signed_package_index_sha256": index_sha256},
        "archive": {"package": PACKAGE, "version": VERSION, "architecture": ARCHITECTURE,
                    "filename": archive_rel, "url": archive_final, "bytes": archive_size,
                    "sha256": archive_sha256, "control_identity_verified": True,
                    "retained_after_audit": False},
        "library_comparison": comparison,
        "installed_or_loaded": False,
        "guest_or_host_state_changed": False,
        "cuda_or_gpu_execution_tested": False,
    }
    auditor_path = Path(__file__)
    test_path = ROOT / "tests/test_audit_r58017804_v100_compute_package.py"
    report["auditor"] = {"path": str(auditor_path.relative_to(ROOT)),
                         "sha256": hashlib.sha256(auditor_path.read_bytes()).hexdigest(),
                         "focused_test_path": str(test_path.relative_to(ROOT)),
                         "focused_test_sha256": hashlib.sha256(test_path.read_bytes()).hexdigest()}
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-report", type=Path, default=EXPECTED_GUEST_REPORT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = audit(args.guest_report)
        if args.output is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output = ROOT / "evidence" / f"r58017804-v100-compute-library-match-{stamp}.json"
        else:
            output = _safe_project_file(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        print(str(error)[:300], file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "report": str(output),
                      "sha256": hashlib.sha256(payload).hexdigest(),
                      "matched": result["library_comparison"]["matched"],
                      "paths": result["library_comparison"]["paths"]}, sort_keys=True))
    return 0 if result["status"] == "all-package-library-paths-match" else 3


if __name__ == "__main__":
    raise SystemExit(main())
