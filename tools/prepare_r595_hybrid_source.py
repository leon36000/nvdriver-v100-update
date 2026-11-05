#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Clone a pinned R595 source tree and apply an exact hybrid patch series.

The tool never edits the input source tree and never overwrites a destination
or report. It keeps failed clones for diagnosis and emits a mode-0600 manifest.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_volta_uvm_port import ignore_r595_kernel_build_outputs  # noqa: E402


class PatchSeriesError(RuntimeError):
    def __init__(self, message: str, results: list[dict]):
        super().__init__(message)
        self.results = results


def tree_fingerprint(root: Path) -> dict:
    """Hash the regular source files retained by the NVIDIA build-output filter."""
    root = Path(root).resolve(strict=True)
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        ignored = ignore_r595_kernel_build_outputs(directory, dirnames + filenames)
        dirnames[:] = sorted(name for name in dirnames if name not in ignored)
        for filename in sorted(filenames):
            if filename in ignored:
                continue
            path = current / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"source tree contains a non-regular input: {path}")
            relative = path.relative_to(root).as_posix()
            mode = stat.S_IMODE(path.stat().st_mode)
            file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            digest.update(relative.encode("utf-8") + b"\0")
            digest.update(f"{mode:o}\0{file_hash}\n".encode("ascii"))
            file_count += 1
            total_bytes += path.stat().st_size
    return {
        "algorithm": "sha256(path NUL mode-octal NUL file-sha256 LF), sorted by relative path",
        "sha256": digest.hexdigest(),
        "regular_file_count": file_count,
        "total_bytes": total_bytes,
    }


def apply_exact_patch_series(source: Path, patches: list[Path]) -> list[dict]:
    results = []
    for patch_path in patches:
        patch_path = Path(patch_path).resolve(strict=True)
        if not patch_path.is_file() or patch_path.is_symlink():
            raise ValueError(f"patch input is not a regular file: {patch_path}")
        patch_hash = hashlib.sha256(patch_path.read_bytes()).hexdigest()
        command = [
            "patch", "--batch", "--forward", "--fuzz=0",
            "--no-backup-if-mismatch", "-p1", "--input", str(patch_path),
        ]
        result = subprocess.run(
            command, cwd=source, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        output = result.stdout
        offset_or_fuzz = re.search(
            r"\boffset\s+-?\d+\s+lines?\b|\bfuzz\b", output, re.IGNORECASE
        ) is not None
        item = {
            "path": str(patch_path),
            "sha256": patch_hash,
            "command": command,
            "exit_code": result.returncode,
            "output": output,
            "zero_offset_zero_fuzz": result.returncode == 0 and not offset_or_fuzz,
        }
        results.append(item)
        if result.returncode != 0 or offset_or_fuzz:
            raise PatchSeriesError(
                f"patch did not apply exactly: {patch_path.name}: {output.strip()}",
                results,
            )
    return results


def prepare(source: Path, destination: Path, report: Path,
            patches: list[Path]) -> dict:
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()
    report = Path(report).resolve()
    if not source.is_dir():
        raise ValueError("R595 source input must be a directory")
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite source destination: {destination}")
    if report.exists():
        raise FileExistsError(f"refusing to overwrite source report: {report}")

    before = tree_fingerprint(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, ignore=ignore_r595_kernel_build_outputs)
    applied = []
    error = None
    try:
        applied = apply_exact_patch_series(destination, patches)
        after = tree_fingerprint(destination)
        status = "prepared"
    except Exception as exc:
        applied = getattr(exc, "results", applied)
        after = tree_fingerprint(destination)
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"

    document = {
        "schema": "r595-hybrid-source-preparation-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "source_tree": str(source),
        "source_fingerprint": before,
        "destination_tree": str(destination),
        "destination_fingerprint": after,
        "patches": applied,
        "error": error,
        "source_tree_modified": False,
        "destination_overwritten": False,
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.chmod(report, 0o600)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--patch", type=Path, action="append", required=True,
                        help="patch to apply, repeated in exact application order")
    args = parser.parse_args()
    try:
        result = prepare(args.source, args.destination, args.report, args.patch)
    except Exception as error:
        print(f"source preparation failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"],
        "report": str(args.report.resolve()),
        "source_fingerprint": result["source_fingerprint"]["sha256"],
        "destination_fingerprint": result["destination_fingerprint"]["sha256"],
        "patch_count": len(result["patches"]),
        "error": result["error"],
    }, indent=2))
    return 0 if result["status"] == "prepared" else 2


if __name__ == "__main__":
    raise SystemExit(main())
