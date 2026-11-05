#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Classify Linux objtool RETHUNK warnings by symbol-table provenance.

The receipt contains counts and input hashes only. It deliberately omits symbol
names, disassembly, pseudocode, and source or binary contents.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Iterable


WARNING = re.compile(
    r"^.+?: warning: objtool: (?P<symbol>.+?)\+0x[0-9a-fA-F]+: "
    r"'naked' return found in MITIGATION_RETHUNK build$"
)


class AuditError(RuntimeError):
    """Raised when the input evidence cannot be classified safely."""


def parse_warnings(text: str) -> list[str]:
    """Extract only symbol identifiers from exact RETHUNK warning lines."""
    return [match.group("symbol") for line in text.splitlines()
            if (match := WARNING.fullmatch(line))]


def parse_nm_symbols(text: str) -> set[str]:
    """Parse names from GNU nm --defined-only output without retaining rows."""
    symbols = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] not in {"U", "u"}:
            symbols.add(fields[-1])
    return symbols


def classify_warnings(
    warning_symbols: Iterable[str], opaque_symbols: set[str], source_symbols: set[str]
) -> dict[str, int | str]:
    """Count warning rows by matching defined symbol names in supplied objects."""
    rows = list(warning_symbols)
    counts: Counter[str] = Counter()
    for symbol in rows:
        in_opaque = symbol in opaque_symbols
        in_source = symbol in source_symbols
        if in_opaque and in_source:
            counts["opaque_and_source"] += 1
        elif in_opaque:
            counts["opaque_only"] += 1
        elif in_source:
            counts["source_only"] += 1
        else:
            counts["unmatched"] += 1
    unique = set(rows)
    return {
        "warning_rows": len(rows),
        "unique_warning_symbols": len(unique),
        "opaque_only_rows": counts["opaque_only"],
        "source_only_rows": counts["source_only"],
        "opaque_and_source_rows": counts["opaque_and_source"],
        "unmatched_rows": counts["unmatched"],
        "match_basis": "defined-symbol-name-only",
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _nm(path: Path, nm_command: str) -> set[str]:
    result = subprocess.run(
        [nm_command, "-A", "--defined-only", str(path)],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise AuditError("symbol-table extraction failed")
    return parse_nm_symbols(result.stdout)


def _source_objects(root: Path, opaque_object: Path) -> list[Path]:
    if not root.is_dir():
        raise AuditError("source-object directory is unavailable")
    opaque_resolved = opaque_object.resolve(strict=True)
    objects = []
    for path in sorted(root.rglob("*.o")):
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError as error:
            raise AuditError("object disappeared during enumeration") from error
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            continue
        if path.resolve(strict=True) == opaque_resolved:
            continue
        objects.append(path)
    if not objects:
        raise AuditError("no regular source objects were found")
    return objects


def audit(log_path: Path, opaque_object: Path, source_object_root: Path,
          *, nm_command: str = "nm") -> dict:
    log_path = log_path.resolve(strict=True)
    opaque_object = opaque_object.resolve(strict=True)
    source_object_root = source_object_root.resolve(strict=True)
    try:
        log = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise AuditError("objtool log is unreadable") from error
    warnings = parse_warnings(log)
    if not warnings:
        raise AuditError("no exact MITIGATION_RETHUNK warnings were found")

    source_objects = _source_objects(source_object_root, opaque_object)
    opaque_symbols = _nm(opaque_object, nm_command)
    source_symbols: set[str] = set()
    for path in source_objects:
        source_symbols.update(_nm(path, nm_command))

    classification = classify_warnings(warnings, opaque_symbols, source_symbols)
    return {
        "schema": "nvidia-hybrid.rethunk-warning-provenance.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ANALYZED_STATICALLY",
        "inputs": {
            "objtool_log_sha256": _sha256(log_path),
            "opaque_object_sha256": _sha256(opaque_object),
            "source_object_count": len(source_objects),
        },
        "classification": classification,
        "limits": [
            "Classification compares warning symbol names with defined symbol tables only.",
            "It does not inspect instruction bytes, disassemble, decompile, or prove control flow.",
            "A name match does not establish which duplicate definition objtool analyzed.",
            "It does not establish module safety or justify loading the module.",
        ],
    }


def write_receipt(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise AuditError("refusing to overwrite an existing receipt") from None
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--opaque-object", type=Path, required=True)
    parser.add_argument("--source-object-root", type=Path, required=True)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        document = audit(args.log, args.opaque_object, args.source_object_root,
                         nm_command=args.nm)
        if args.output:
            write_receipt(args.output, document)
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (AuditError, OSError, subprocess.SubprocessError) as error:
        print(f"RETHUNK provenance audit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
