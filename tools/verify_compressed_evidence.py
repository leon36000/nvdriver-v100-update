#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify lossless gzip storage for large evidence excluded by GitLab's blob limit."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys


SCHEMA = "nvidia-hybrid-compressed-evidence-manifest-v1"


def _safe_relative_path(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a repository-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"{field} must be a safe repository-relative path")
    if path.as_posix() != value:
        raise ValueError(f"{field} must use normalized POSIX separators")
    return value


def _sha256_path(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def verify_compressed_evidence(root: Path, manifest_path: str) -> dict[str, object]:
    relative_manifest = _safe_relative_path(manifest_path, "manifest path")
    with (root / relative_manifest).open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ValueError("unsupported compressed evidence manifest schema")
    if document.get("manifest_path") != relative_manifest:
        raise ValueError("compressed evidence manifest path does not match its location")
    records = document.get("files")
    if not isinstance(records, list) or document.get("file_count") != len(records):
        raise ValueError("compressed evidence manifest file count is invalid")

    seen_originals: set[str] = set()
    seen_stored: set[str] = set()
    total_original_bytes = 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("compressed evidence manifest contains a malformed record")
        original = _safe_relative_path(record.get("original_path"), "original path")
        stored = _safe_relative_path(record.get("stored_path"), "stored path")
        if stored != original + ".gz":
            raise ValueError(f"stored evidence must be the original path plus .gz: {stored}")
        if original in seen_originals or stored in seen_stored:
            raise ValueError("compressed evidence manifest contains duplicate paths")
        seen_originals.add(original)
        seen_stored.add(stored)

        original_size = record.get("original_size_bytes")
        stored_size = record.get("stored_size_bytes")
        if (type(original_size) is not int or original_size < 0 or
                type(stored_size) is not int or stored_size < 0):
            raise ValueError(f"compressed evidence size is invalid: {stored}")
        original_digest = record.get("original_sha256")
        stored_digest = record.get("stored_sha256")
        for digest in (original_digest, stored_digest):
            if not isinstance(digest, str) or len(digest) != 64 or any(
                    character not in "0123456789abcdef" for character in digest):
                raise ValueError(f"compressed evidence SHA-256 is invalid: {stored}")

        source_path = root / original
        if source_path.exists() or source_path.is_symlink():
            raise ValueError(f"uncompressed evidence path is still present: {original}")
        stored_path = root / stored
        metadata = stored_path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"compressed evidence is not a regular file: {stored}")
        actual_stored_digest, actual_stored_size = _sha256_path(stored_path)
        if actual_stored_size != stored_size:
            raise ValueError(f"compressed evidence size differs from manifest: {stored}")
        if actual_stored_digest != stored_digest:
            raise ValueError(f"compressed evidence SHA-256 differs from manifest: {stored}")

        digest = hashlib.sha256()
        decompressed_size = 0
        with gzip.open(stored_path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                decompressed_size += len(chunk)
        if decompressed_size != original_size:
            raise ValueError(f"decompressed evidence size differs from manifest: {stored}")
        if digest.hexdigest() != original_digest:
            raise ValueError(f"decompressed evidence SHA-256 differs from manifest: {stored}")
        total_original_bytes += decompressed_size

    return {"schema": SCHEMA, "status": "pass", "files_verified": len(records),
            "original_bytes_verified": total_original_bytes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", required=True,
                        help="repository-relative compressed evidence manifest")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    print(json.dumps(verify_compressed_evidence(root, args.manifest), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"compressed evidence verification failed: {error}", file=sys.stderr)
        raise SystemExit(2)
