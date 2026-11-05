#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create or verify a content-and-mode manifest for a Git-index snapshot."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys


SCHEMA = "nvidia-hybrid-git-transfer-manifest-v1"


def _relative_manifest_path(path: str) -> str:
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise ValueError("manifest path must be a safe repository-relative path")
    if candidate.as_posix() != path:
        raise ValueError("manifest path must use normalized POSIX separators")
    return path


def _index_entries(root: Path) -> dict[str, str]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--stage", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise ValueError("cannot read Git index: " + completed.stderr.decode(
            "utf-8", errors="replace").strip())
    entries: dict[str, str] = {}
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            header, encoded_path = record.split(b"\t", 1)
            mode, _object_id, stage = header.decode("ascii").split()
            path = encoded_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("unexpected Git index record") from error
        _relative_manifest_path(path)
        if stage != "0" or mode not in {"100644", "100755"}:
            raise ValueError(f"unsupported index entry for {path}")
        if path in entries:
            raise ValueError(f"duplicate index entry: {path}")
        entries[path] = mode
    return entries


def _file_record(root: Path, relative_path: str, mode: str) -> dict[str, object]:
    path = root / relative_path
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"indexed path is not a regular file: {relative_path}")
    executable = bool(metadata.st_mode & 0o111)
    if executable != (mode == "100755"):
        raise ValueError(f"worktree mode differs from index: {relative_path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": relative_path, "mode": mode, "size_bytes": size,
            "sha256": digest.hexdigest()}


def create_manifest(root: Path, manifest_path: str) -> dict[str, object]:
    relative_manifest = _relative_manifest_path(manifest_path)
    entries = _index_entries(root)
    if relative_manifest in entries:
        raise ValueError("manifest must be generated before it is added to the index")
    files = [_file_record(root, path, mode)
             for path, mode in sorted(entries.items())]
    return {
        "schema": SCHEMA,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_path_excluded_from_file_set": relative_manifest,
        "file_count": len(files),
        "files": files,
    }


def write_manifest(root: Path, manifest_path: str) -> dict[str, object]:
    relative_manifest = _relative_manifest_path(manifest_path)
    target = root / relative_manifest
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ValueError("refusing to overwrite an existing transfer manifest")
    result = create_manifest(root, relative_manifest)
    opener = gzip.open if target.name.endswith(".gz") else open
    with opener(target, "xt", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return result


def _working_tree_entries(root: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        names[:] = [name for name in names if name != ".git"]
        for name in names:
            path = base / name
            if path.is_symlink():
                raise ValueError(f"working tree contains a directory symlink: {path.relative_to(root)}")
        for name in filenames:
            path = base / name
            relative = path.relative_to(root).as_posix()
            _relative_manifest_path(relative)
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"working tree path is not a regular file: {relative}")
            entries[relative] = "100755" if metadata.st_mode & 0o111 else "100644"
    return entries


def verify_manifest(root: Path, manifest_path: str, *,
                    working_tree: bool = False) -> dict[str, object]:
    relative_manifest = _relative_manifest_path(manifest_path)
    target = root / relative_manifest
    opener = gzip.open if target.name.endswith(".gz") else open
    with opener(target, "rt", encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ValueError("unsupported transfer manifest schema")
    if document.get("manifest_path_excluded_from_file_set") != relative_manifest:
        raise ValueError("manifest does not identify its own exclusion path")
    files = document.get("files")
    if not isinstance(files, list) or document.get("file_count") != len(files):
        raise ValueError("manifest file count is invalid")

    expected: dict[str, dict[str, object]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("manifest contains a malformed file record")
        raw_path = item.get("path")
        if not isinstance(raw_path, str):
            raise ValueError("manifest path is not text")
        path = _relative_manifest_path(raw_path)
        if path == relative_manifest or path in expected:
            raise ValueError(f"manifest contains an invalid or duplicate path: {path}")
        if item.get("mode") not in {"100644", "100755"}:
            raise ValueError(f"manifest mode is invalid: {path}")
        if type(item.get("size_bytes")) is not int or item["size_bytes"] < 0:
            raise ValueError(f"manifest size is invalid: {path}")
        digest = item.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest):
            raise ValueError(f"manifest SHA-256 is invalid: {path}")
        expected[path] = item

    actual = _working_tree_entries(root) if working_tree else _index_entries(root)
    actual.pop(relative_manifest, None)
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        raise ValueError(
            f"Git index path set differs from manifest (missing={len(missing)}, "
            f"unexpected={len(unexpected)})")

    total_bytes = 0
    for path in sorted(expected):
        item = expected[path]
        if actual[path] != item["mode"]:
            raise ValueError(f"Git index mode differs from manifest: {path}")
        observed = _file_record(root, path, actual[path])
        if observed["size_bytes"] != item["size_bytes"]:
            raise ValueError(f"file size differs from manifest: {path}")
        if observed["sha256"] != item["sha256"]:
            raise ValueError(f"file SHA-256 differs from manifest: {path}")
        total_bytes += observed["size_bytes"]
    return {"schema": SCHEMA, "status": "pass", "files_verified": len(expected),
            "bytes_verified": total_bytes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", required=True,
                        help="repository-relative manifest path")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true",
                      help="create a new manifest from the staged Git index")
    mode.add_argument("--verify", action="store_true",
                      help="compare indexed paths, modes, sizes, and SHA-256 hashes")
    mode.add_argument("--verify-tree", action="store_true",
                      help="verify a clean checkout without requiring Git in the image")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    result = (write_manifest(root, args.manifest) if args.write
              else verify_manifest(root, args.manifest,
                                   working_tree=args.verify_tree))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"transfer manifest verification failed: {error}", file=sys.stderr)
        raise SystemExit(2)
