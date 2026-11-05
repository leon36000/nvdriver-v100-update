#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify that an extracted source directory exactly matches a pinned tar subtree.

This reads archive members without extracting them. It rejects unsafe archive
paths, links and special files, and records path-sensitive SHA-256 manifests
for the archived and extracted files. A successful result proves source
provenance only; it does not validate a build or runtime behavior.
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
import sys
import tarfile


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_archive_path(name: str) -> str:
    if "\\" in name:
        raise ValueError(f"unsafe archive path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive path: {name!r}")
    normalized = "/".join(part for part in path.parts if part not in ("", "."))
    return normalized


def _normalize_prefix(prefix: str) -> str:
    normalized = _normalize_archive_path(prefix)
    if not normalized:
        raise ValueError("archive subtree prefix must not be empty")
    return normalized.rstrip("/")


def source_manifest_sha256(files: dict[str, bytes]) -> str:
    """Hash sorted relative paths and content hashes, independent of input order."""
    digest = hashlib.sha256()
    for name in sorted(files):
        normalized = _normalize_archive_path(name)
        if not normalized or normalized != name:
            raise ValueError(f"manifest path must be normalized and relative: {name!r}")
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(files[name]).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _read_archive_subtree(archive_path: Path, prefix: str) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    seen_names: set[str] = set()
    selected_prefix = prefix + "/"
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            normalized = _normalize_archive_path(member.name)
            if normalized == prefix:
                if not member.isdir():
                    raise ValueError("archive subtree root is not a directory")
                continue
            if not normalized.startswith(selected_prefix):
                continue
            relative = normalized[len(selected_prefix):]
            if not relative:
                continue
            if relative in seen_names:
                raise ValueError(f"duplicate archive path: {relative}")
            seen_names.add(relative)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"non-regular archive member in subtree: {relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read archive member: {relative}")
            with stream:
                files[relative] = stream.read()
    if not files:
        raise ValueError(f"archive subtree contains no regular files: {prefix}")
    return files


def _read_extracted_tree(directory: Path) -> dict[str, bytes]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("extracted source root must be a real directory")
    files: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise ValueError(f"symlink in extracted tree: {relative}")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"non-regular file in extracted tree: {relative}")
        files[relative] = path.read_bytes()
    return files


def compare_archive_subtree(
    archive_path: Path,
    subtree_prefix: str,
    extracted_directory: Path,
    *,
    expected_archive_sha256: str | None = None,
) -> dict:
    """Compare exact file paths and bytes for one archive subtree."""
    archive_path = Path(archive_path)
    extracted_directory = Path(extracted_directory)
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ValueError("archive input must be a regular file")
    prefix = _normalize_prefix(subtree_prefix)
    archive_hash = sha256_file(archive_path)
    expected_hash = None
    if expected_archive_sha256 is not None:
        expected_hash = expected_archive_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ValueError("expected archive SHA-256 must contain 64 hexadecimal characters")
        if archive_hash != expected_hash:
            raise ValueError(
                f"archive SHA-256 mismatch: got {archive_hash}, expected {expected_hash}"
            )

    archive_files = _read_archive_subtree(archive_path, prefix)
    extracted_files = _read_extracted_tree(extracted_directory)
    archive_names = set(archive_files)
    extracted_names = set(extracted_files)
    missing = sorted(archive_names - extracted_names)
    extra = sorted(extracted_names - archive_names)
    changed = sorted(
        name for name in archive_names & extracted_names
        if archive_files[name] != extracted_files[name]
    )
    byte_for_byte_match = not (missing or extra or changed)

    return {
        "schema_version": 1,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "archive_path": str(archive_path.resolve()),
        "archive_sha256": archive_hash,
        "expected_archive_sha256": expected_hash,
        "archive_sha256_matches_expected": (
            archive_hash == expected_hash if expected_hash is not None else None
        ),
        "archive_subtree_prefix": prefix,
        "extracted_directory": str(extracted_directory.resolve()),
        "archive_file_count": len(archive_files),
        "extracted_file_count": len(extracted_files),
        "archive_manifest_sha256": source_manifest_sha256(archive_files),
        "extracted_manifest_sha256": source_manifest_sha256(extracted_files),
        "missing_from_extracted": missing,
        "extra_in_extracted": extra,
        "changed_files": changed,
        "byte_for_byte_match": byte_for_byte_match,
        "provenance_valid": byte_for_byte_match and (
            expected_hash is None or archive_hash == expected_hash
        ),
        "scope": "source-provenance-only; compares regular-file relative paths and bytes; excludes filesystem metadata; no build, module-load, CUDA, or hardware validation",
        "filesystem_metadata_compared": False,
    }


def _write_private_report(path: Path, report: dict) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence report output")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--subtree", required=True, help="POSIX path prefix inside the tar archive")
    parser.add_argument("--directory", type=Path, required=True, help="already-extracted subtree root")
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = compare_archive_subtree(
            args.archive,
            args.subtree,
            args.directory,
            expected_archive_sha256=args.expected_archive_sha256,
        )
    except (OSError, tarfile.TarError, ValueError) as exc:
        print(json.dumps({"provenance_valid": False, "error": str(exc)}, sort_keys=True))
        return 2
    if args.report is not None:
        _write_private_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["provenance_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
