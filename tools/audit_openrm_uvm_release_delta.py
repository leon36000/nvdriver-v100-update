#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the pinned R615.71.10 and R615.78.08 Open UVM source trees.

This is a bounded source-delta check. It does not infer runtime compatibility,
GV100 dispatch, or hardware behavior from byte equality.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile


ROOT = Path(__file__).resolve().parents[1]
ARCHIVES = (
    {
        "version": "615.71.10",
        "path": ROOT / ".cache/upstream/open-gpu-kernel-modules-615.71.10-6f3be8c9.tar.gz",
        "sha256": "c01605048cab3d988b1b3028fbee0646ba0937407949dc43514b3e4694f40f6c",
    },
    {
        "version": "615.78.08",
        "path": ROOT / ".cache/upstream/open-gpu-kernel-modules-1a82fbfda8f321b056eb3568850f9316c5e465c5.tar.gz",
        "sha256": "590ee6a5a780f946322edd17f9d235c6664eb7e6839073ac0d68c0f263e7184f",
    },
)
SCOPE = "kernel-open/nvidia-uvm/"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_manifest_sha256(files: dict[str, str]) -> str:
    """Hash sorted path-NUL-content-SHA256-LF rows."""
    digest = hashlib.sha256()
    for relative_path, content_hash in sorted(files.items()):
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _archive_uvm(archive_spec: dict) -> tuple[dict[str, str], str]:
    path = archive_spec["path"]
    raw_hash = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            raw_hash.update(chunk)
    if raw_hash.hexdigest() != archive_spec["sha256"]:
        raise ValueError(f"archive hash mismatch: {path.name}")

    files: dict[str, str] = {}
    release_version = None
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"unsafe archive member path: {member.name!r}")
            parts = member_path.parts
            if len(parts) >= 2 and parts[1] == "README.md" and member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("could not read root README")
                readme = source.read().decode("utf-8", errors="strict")
                needle = "version " + archive_spec["version"] + "."
                if needle in readme:
                    release_version = archive_spec["version"]
            if len(parts) < 3 or "/".join(parts[1:3]) != "kernel-open/nvidia-uvm":
                continue
            if not member.isfile():
                if member.isdir():
                    continue
                raise ValueError(f"non-regular UVM archive member: {member.name!r}")
            relative = "/".join(parts[3:])
            if not relative or not relative.endswith((".c", ".h")):
                continue
            if relative in files:
                raise ValueError(f"duplicate UVM source path: {relative}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"could not read UVM source: {relative}")
            files[relative] = _sha256(source.read())

    if release_version != archive_spec["version"]:
        raise ValueError(f"archive README does not identify {archive_spec['version']}")
    if not files:
        raise ValueError(f"no C/H files found in {SCOPE} in {path.name}")
    return files, raw_hash.hexdigest()


def compare() -> dict:
    left, right = ARCHIVES
    baseline, baseline_hash = _archive_uvm(left)
    candidate, candidate_hash = _archive_uvm(right)
    baseline_paths, candidate_paths = set(baseline), set(candidate)
    changed = sorted(
        path for path in baseline_paths & candidate_paths
        if baseline[path] != candidate[path]
    )
    added = sorted(candidate_paths - baseline_paths)
    removed = sorted(baseline_paths - candidate_paths)
    return {
        "schema": "openrm-uvm-release-delta-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": SCOPE + "**/*.[ch]",
        "archives": [
            {
                "version": left["version"],
                "path": str(left["path"].resolve(strict=True)),
                "sha256": baseline_hash,
                "source_files": len(baseline),
                "source_manifest_sha256": _source_manifest_sha256(baseline),
            },
            {
                "version": right["version"],
                "path": str(right["path"].resolve(strict=True)),
                "sha256": candidate_hash,
                "source_files": len(candidate),
                "source_manifest_sha256": _source_manifest_sha256(candidate),
            },
        ],
        "changed_common_source_count": len(changed),
        "added_source_count": len(added),
        "removed_source_count": len(removed),
        "changed_paths": changed,
        "added_paths": added,
        "removed_paths": removed,
        "byte_identical": not changed and not added and not removed,
        "qualification": "hash-pinned-source-comparison",
        "runtime_or_hardware_validated": False,
        "limitations": [
            "The comparison is restricted to C and H files under kernel-open/nvidia-uvm.",
            "Byte equality does not prove that either release supports GV100 or works at runtime.",
            "Generated RM HAL admission is covered by a separate exact-release CPU source harness.",
        ],
    }


def _write_report(path: Path, report: dict) -> None:
    root = (ROOT / "evidence").resolve(strict=True)
    candidate = Path(os.path.abspath(path))
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("report must be written beneath repository evidence") from error
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(candidate, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("report destination is not a regular file")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report", type=Path,
        default=ROOT / "evidence/openrm-uvm-release-delta-6157110-vs-6157808-v1-20261031.json",
    )
    args = parser.parse_args()
    try:
        report = compare()
        _write_report(args.report, report)
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
