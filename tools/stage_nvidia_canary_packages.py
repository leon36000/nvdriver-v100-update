#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage and verify a pinned PC3 R580 canary package set without installation.

The manifest is anchored to a locally recorded digest. Downloads are confined to
approved NVIDIA/Ubuntu package hosts, written atomically with private permissions,
and checked against size, APT MD5, and pinned SHA-256. ``dpkg-deb --field`` reads
identity metadata only; package scripts are never run. This tool never invokes
APT, dpkg installation, modprobe, SSH, or GPU/PCI operations.
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
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evidence/pc3-nvidia-canary-package-manifest-v1-20261023.json"
MANIFEST_SHA256 = "8aa76d874bf9ebbf9fe0c5528b4fdeb9f932b17115232b0cdbb14f5470f6e764"
SOURCE_REPORT = "evidence/pc3-nvidia-canary-uri-v2-20261023.json"
SOURCE_REPORT_SHA256 = "cb6bdf0b82aae1e846a9c1c10cecd003b2a54515f85dd123f2b3b83bc8a9a77e"
SCHEMA = "pc3-nvidia-driver-canary-package-manifest-v1"
CACHE_ROOT = ROOT / ".cache/canary/pc3-r580-58019607"
ALLOWED_HOSTS = {"developer.download.nvidia.com", "ca.archive.ubuntu.com"}
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
PACKAGE_FIELDS = {
    "transaction", "package", "version", "architecture", "filename", "url",
    "size", "md5_from_apt_uri", "sha256",
}
OPTIONAL_PACKAGE_FIELDS = {"apt_label", "apt_origin", "apt_suite"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _safe_filename(value) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 200
        and value.endswith(".deb")
        and str(PurePosixPath(value)) == value
        and not value.startswith("/")
        and re.fullmatch(r"[A-Za-z0-9_.+~-]+", value) is not None
        and value not in {".", ".."}
    )


def _validate_url(url: str, filename: str) -> urllib.parse.SplitResult:
    if not isinstance(url, str) or len(url) > 2048 or any(ord(char) < 0x20 for char in url):
        raise ValueError("malformed package URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as error:
        raise ValueError("malformed package URL") from error
    if hostname not in ALLOWED_HOSTS:
        raise ValueError("unapproved package host")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("package URL must not contain credentials, query, or fragment")
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        raise ValueError("non-standard package URL port")
    if parsed.scheme != "https" and not (hostname == "ca.archive.ubuntu.com" and parsed.scheme == "http"):
        raise ValueError("unapproved package URL scheme")
    if not parsed.path.startswith("/") or "%2f" in parsed.path.lower() or "%5c" in parsed.path.lower():
        raise ValueError("unsafe package URL path")
    try:
        decoded_name = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1], errors="strict")
    except UnicodeError as error:
        raise ValueError("invalid encoded package filename") from error
    if decoded_name != filename:
        raise ValueError("URL basename differs from pinned package filename")
    return parsed


def validate_package_entries(entries):
    if not isinstance(entries, list) or not entries or len(entries) > 64:
        raise ValueError("package entries must be a non-empty bounded list")
    seen_names = set()
    seen_packages = set()
    total_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("package entry must be an object")
        keys = set(entry)
        if not PACKAGE_FIELDS <= keys or keys - PACKAGE_FIELDS - OPTIONAL_PACKAGE_FIELDS:
            raise ValueError("package entry has missing or unexpected fields")
        if not _safe_filename(entry["filename"]):
            raise ValueError("package filename must be a safe basename ending in .deb")
        if entry["transaction"] not in {"target", "rollback"}:
            raise ValueError("unknown package transaction")
        if not isinstance(entry["package"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", entry["package"]):
            raise ValueError("invalid Debian package name")
        if not isinstance(entry["version"], str) or not re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,160}", entry["version"]):
            raise ValueError("invalid Debian package version")
        if not isinstance(entry["architecture"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", entry["architecture"]):
            raise ValueError("invalid Debian architecture")
        if type(entry["size"]) is not int or not 0 < entry["size"] <= MAX_PACKAGE_BYTES:
            raise ValueError("package size must be a positive integer within the safety limit")
        if not isinstance(entry["md5_from_apt_uri"], str) or not re.fullmatch(r"[0-9a-f]{32}", entry["md5_from_apt_uri"]):
            raise ValueError("invalid pinned APT MD5")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError("invalid pinned SHA-256")
        for optional in OPTIONAL_PACKAGE_FIELDS & keys:
            if entry[optional] is not None and not isinstance(entry[optional], str):
                raise ValueError("invalid optional APT provenance field")
        _validate_url(entry["url"], entry["filename"])
        unique_name = (entry["transaction"], entry["filename"])
        unique_package = (entry["transaction"], entry["package"])
        if unique_name in seen_names or unique_package in seen_packages:
            raise ValueError("duplicate package name or filename in transaction")
        seen_names.add(unique_name)
        seen_packages.add(unique_package)
        total_bytes += entry["size"]
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("package set exceeds the staging byte limit")
    return entries


def load_manifest(path: Path = MANIFEST_PATH, *, expected_sha256: str = MANIFEST_SHA256):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ValueError("expected manifest SHA-256 must be lowercase hexadecimal")
    path = Path(path)
    if path.is_symlink():
        raise ValueError("refusing a symlink manifest")
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds the size limit")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_sha256:
        raise ValueError("manifest SHA-256 mismatch")
    try:
        manifest = json.loads(raw, object_pairs_hook=unique_json_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("invalid manifest JSON") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported canary package manifest schema")
    if manifest.get("host_key_alias") != "pc3" or manifest.get("target") != "pc3@pc3":
        raise ValueError("manifest does not identify the pinned PC3 target")
    if manifest.get("source_preflight_report") != SOURCE_REPORT or manifest.get("source_preflight_report_sha256") != SOURCE_REPORT_SHA256:
        raise ValueError("manifest source preflight report is not the pinned PC3 evidence")
    if manifest.get("driver_or_pci_modified") is not False or manifest.get("install_or_download_performed") is not False:
        raise ValueError("manifest claims the canary host was already modified")
    entries = validate_package_entries(manifest.get("packages"))
    if type(manifest.get("package_count")) is not int or manifest["package_count"] != len(entries) or len(entries) != 36:
        raise ValueError("manifest package count differs from the pinned transaction")
    expected = {"target": {"package_count": 18, "bytes": 312428150},
                "rollback": {"package_count": 18, "bytes": 247417522}}
    if manifest.get("transactions") != expected:
        raise ValueError("manifest transaction summary differs from the pinned package plan")
    actual = {}
    for name in ("target", "rollback"):
        group = [item for item in entries if item["transaction"] == name]
        actual[name] = {"package_count": len(group), "bytes": sum(item["size"] for item in group)}
    if actual != expected:
        raise ValueError("package entries do not match transaction package counts and byte totals")
    return manifest, actual_hash


class _PinnedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        try:
            original = _validate_url(request.full_url, urllib.parse.unquote(
                urllib.parse.urlsplit(request.full_url).path.rsplit("/", 1)[-1]))
            redirected = _validate_url(newurl, urllib.parse.unquote(
                urllib.parse.urlsplit(newurl).path.rsplit("/", 1)[-1]))
        except (ValueError, TypeError) as error:
            raise urllib.error.HTTPError(newurl, code, "unapproved redirect target: " + str(error), headers, fp) from error
        if original.hostname != redirected.hostname or (original.scheme == "https" and redirected.scheme != "https"):
            raise urllib.error.HTTPError(newurl, code, "unapproved redirect target", headers, fp)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def _safe_open(url: str, timeout: int):
    opener = urllib.request.build_opener(_PinnedRedirectHandler())
    return opener.open(url, timeout=timeout)


def _hashes(path: Path):
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            sha.update(block)
            md5.update(block)
    return size, md5.hexdigest(), sha.hexdigest()


def _verify_existing(path: Path, entry):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not path.is_file() or path.is_symlink():
        raise ValueError("existing package path is not a regular non-symlink file")
    size, md5, sha = _hashes(path)
    if size != entry["size"] or md5 != entry["md5_from_apt_uri"] or sha != entry["sha256"]:
        raise ValueError("existing file hash mismatch")
    os.chmod(path, 0o600, follow_symlinks=False)
    return {"verified": True, "already_present": True, "bytes": size, "md5": md5, "sha256": sha}


def _ensure_private_directory(directory: Path):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("staging directory must be a real directory")
    os.chmod(directory, 0o700)
    return directory


def download_package(entry, destination: Path, *, opener=None, timeout: int = 90):
    """Download one pinned archive to destination; never clobber an existing file."""
    validate_package_entries([entry])
    destination = _ensure_private_directory(destination)
    final_path = destination / entry["filename"]
    existing = _verify_existing(final_path, entry)
    if existing is not None:
        return existing
    url = entry["url"]
    parsed_url = _validate_url(url, entry["filename"])
    open_url = opener if opener is not None else _safe_open
    fd, temporary_name = tempfile.mkstemp(prefix="." + entry["filename"] + ".", suffix=".part", dir=destination)
    temporary = Path(temporary_name)
    digest_sha = hashlib.sha256()
    digest_md5 = hashlib.md5()
    total = 0
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as output:
            with open_url(url, timeout=timeout) as response:
                final_url = response.geturl() if hasattr(response, "geturl") else None
                if final_url:
                    try:
                        redirected = _validate_url(final_url, entry["filename"])
                    except ValueError as error:
                        raise ValueError("unapproved redirect target: " + str(error)) from error
                    if redirected.hostname != parsed_url.hostname or (parsed_url.scheme == "https" and redirected.scheme != "https"):
                        raise ValueError("unapproved redirect target")
                while True:
                    block = response.read(min(1024 * 1024, entry["size"] - total + 1))
                    if not block:
                        break
                    total += len(block)
                    if total > entry["size"]:
                        raise ValueError("package size mismatch: response exceeds pinned size")
                    digest_sha.update(block)
                    digest_md5.update(block)
                    output.write(block)
            output.flush()
            os.fsync(output.fileno())
        if total != entry["size"]:
            raise ValueError("package size mismatch: received %d, expected %d" % (total, entry["size"]))
        md5 = digest_md5.hexdigest()
        sha = digest_sha.hexdigest()
        if md5 != entry["md5_from_apt_uri"]:
            raise ValueError("APT MD5 mismatch")
        if sha != entry["sha256"]:
            raise ValueError("SHA-256 mismatch")
        try:
            os.link(temporary, final_path, follow_symlinks=False)
        except FileExistsError:
            existing = _verify_existing(final_path, entry)
            if existing is None:
                raise ValueError("package path changed during atomic publication")
            return existing
        os.chmod(final_path, 0o600, follow_symlinks=False)
        directory_fd = os.open(destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return {"verified": True, "already_present": False, "bytes": total, "md5": md5, "sha256": sha}
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _parse_control_fields(text):
    fields = {}
    for line in text.splitlines():
        if not line or line[:1].isspace():
            continue
        key, separator, value = line.partition(":")
        if not separator or key in fields:
            raise ValueError("malformed or duplicate dpkg-deb control field")
        fields[key] = value.strip()
    return fields


def verify_deb_metadata(path: Path, entry, *, runner=subprocess.run):
    """Read .deb identity only. This never extracts files or runs package scripts."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("package metadata check requires a regular staged archive")
    result = runner(["dpkg-deb", "--field", str(path), "Package", "Version", "Architecture"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        raise ValueError("dpkg-deb metadata read failed: " + (result.stderr or "unknown error").strip())
    fields = _parse_control_fields(result.stdout)
    expected = {"Package": entry["package"], "Version": entry["version"], "Architecture": entry["architecture"]}
    if any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError(".deb control identity differs from pinned manifest")
    return {"verified": True, "fields": expected, "method": "dpkg-deb --field; no extraction or maintainer scripts"}


def stage_packages(manifest, cache_root: Path = CACHE_ROOT, *, opener=None, deb_runner=subprocess.run, progress=print):
    """Stage both full transactions and return an install-free verification record."""
    entries = validate_package_entries(manifest["packages"])
    cache_root = _ensure_private_directory(cache_root)
    total_bytes = sum(entry["size"] for entry in entries)
    free_bytes = shutil.disk_usage(cache_root).free
    reserve = max(64 * 1024 * 1024, total_bytes // 10)
    if free_bytes < total_bytes + reserve:
        raise OSError("insufficient free space for target, rollback, and safety reserve")
    staged = []
    for index, entry in enumerate(entries, start=1):
        transaction_dir = _ensure_private_directory(cache_root / entry["transaction"])
        package_result = download_package(entry, transaction_dir, opener=opener)
        package_path = transaction_dir / entry["filename"]
        control = verify_deb_metadata(package_path, entry, runner=deb_runner)
        staged.append({
            "transaction": entry["transaction"], "package": entry["package"],
            "version": entry["version"], "architecture": entry["architecture"],
            "filename": entry["filename"], "path": str(package_path.relative_to(ROOT)) if package_path.is_relative_to(ROOT) else str(package_path),
            "bytes": package_result["bytes"], "md5": package_result["md5"], "sha256": package_result["sha256"],
            "already_present": package_result["already_present"], "deb_control_verified": control["verified"],
        })
        if progress:
            progress("verified %d/%d %s %s" % (index, len(entries), entry["transaction"], entry["package"]))
    return {
        "schema": "pc3-nvidia-canary-package-stage-v1",
        "status": "staged-and-verified",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_sha256": MANIFEST_SHA256,
        "source_preflight_report": SOURCE_REPORT,
        "source_preflight_report_sha256": SOURCE_REPORT_SHA256,
        "target_kernel": "7.0.0-38-generic",
        "transactions": {
            name: {"package_count": sum(x["transaction"] == name for x in staged),
                  "bytes": sum(x["bytes"] for x in staged if x["transaction"] == name)}
            for name in ("target", "rollback")
        },
        "packages": staged,
        "all_package_hashes_verified": True,
        "all_deb_control_identities_verified": True,
        "package_scripts_executed": False,
        "apt_or_dpkg_install_invoked": False,
        "driver_or_pci_modified": False,
        "kernel_modules_loaded": False,
        "gpu_accessed": False,
    }


def _write_new_private_report(path: Path, report):
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError("refusing a symlink stage report path")
    path = candidate.resolve(strict=False)
    evidence_root = (ROOT / "evidence").resolve(strict=True)
    if not path.is_relative_to(evidence_root):
        raise ValueError("stage report must be written under the canonical evidence directory")
    if path.parent != evidence_root or not evidence_root.is_dir():
        raise ValueError("stage report must be a direct child of the evidence directory")
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite stage report: " + str(path))
    if path.parent.is_symlink():
        raise ValueError("refusing a symlink evidence directory")
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    fd, temporary_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".part", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
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
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path, default=CACHE_ROOT,
                        help="local cache directory (default: canonical PC3 R580 canary cache)")
    parser.add_argument("--report", type=Path,
                        help="new report under evidence/ (defaults to a UTC timestamped path)")
    args = parser.parse_args(argv)
    try:
        manifest, manifest_hash = load_manifest()
        if args.cache_root.absolute() != CACHE_ROOT.absolute():
            raise ValueError("cache root is pinned to the canonical PC3 R580 staging directory")
        for component in (ROOT / ".cache", ROOT / ".cache/canary", CACHE_ROOT):
            if component.is_symlink():
                raise ValueError("refusing a symlink in the canonical package cache path")
        stage = stage_packages(manifest, args.cache_root)
        stage["manifest_sha256"] = manifest_hash
        report_path = args.report or ROOT / "evidence" / (
            "pc3-nvidia-canary-stage-v1-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
        report_path = _write_new_private_report(report_path, stage)
    except (OSError, ValueError, urllib.error.URLError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error), "installed": False,
                          "driver_or_pci_modified": False}, sort_keys=True))
        return 2
    print(json.dumps({"status": stage["status"], "packages": len(stage["packages"]),
                      "report": str(report_path.relative_to(ROOT)),
                      "report_sha256": sha256_file(report_path), "installed": False,
                      "driver_or_pci_modified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
