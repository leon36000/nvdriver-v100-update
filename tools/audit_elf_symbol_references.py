#!/usr/bin/env python3
"""Audit direct static references to one symbol in an ELF relocatable object.

The report contains hashes, reference addresses and relocation metadata only; it
does not retain disassembly or bytes from the input artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_symbol(output: str, name: str) -> dict[str, int | str]:
    """Return the unique exact ELF symbol row, rejecting ambiguity."""
    matches: list[dict[str, int | str]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[0].rstrip(":").isdigit() is False:
            continue
        if fields[7] != name:
            continue
        try:
            matches.append({
                "index": int(fields[0].rstrip(":"), 10),
                "value": int(fields[1], 16),
                "size": int(fields[2], 10),
                "type": fields[3],
                "binding": fields[4],
                "section_index": int(fields[6], 10),
            })
        except ValueError as exc:
            raise ValueError(f"malformed exact symbol row for {name}") from exc
    if len(matches) != 1:
        raise ValueError(f"expected one exact symbol row for {name}; found {len(matches)}")
    return matches[0]


def parse_relocation_references(
    output: str, *, symbol_index: int, target_value: int
) -> list[dict[str, int | str]]:
    """Find direct relocations by symbol-table index or .text section addend."""
    section = "unknown"
    matches: list[dict[str, int | str]] = []
    for line in output.splitlines():
        header = re.match(r"Relocation section '([^']+)'", line)
        if header:
            section = header.group(1)
            continue
        fields = line.split()
        if len(fields) < 5 or not fields[2].startswith("R_X86_64_"):
            continue
        try:
            relocation_offset = int(fields[0], 16)
            info = int(fields[1], 16)
            relocation_symbol_index = info >> 32
        except ValueError:
            continue

        addend = 0
        if len(fields) >= 7 and fields[-2] in ("+", "-"):
            try:
                addend = int(fields[-1], 16)
            except ValueError:
                continue
            if fields[-2] == "-":
                addend = -addend

        match_kind = None
        if relocation_symbol_index == symbol_index:
            match_kind = "symbol-index"
        elif fields[4] == ".text" and addend == target_value:
            match_kind = "section-addend"
        if match_kind is not None:
            matches.append({
                "section": section,
                "offset": relocation_offset,
                "relocation_type": fields[2],
                "symbol_index": relocation_symbol_index,
                "symbol_name": fields[4],
                "addend": addend,
                "match_kind": match_kind,
            })
    return matches


def _run(argv: list[str]) -> str:
    completed = subprocess.run(
        argv,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    return completed.stdout


def audit(path: Path, symbol_name: str) -> dict[str, object]:
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    header = _run(["readelf", "-hW", str(path)])
    if "REL (Relocatable file)" not in header:
        raise ValueError("input must be an ELF relocatable object")
    symbols = parse_symbol(_run(["readelf", "-sW", str(path)]), symbol_name)
    relocations = parse_relocation_references(
        _run(["readelf", "-rW", str(path)]),
        symbol_index=int(symbols["index"]),
        target_value=int(symbols["value"]),
    )

    references: list[dict[str, str | int]] = []
    definition_count = 0
    symbol_expr = re.compile(rf"<{re.escape(symbol_name)}(?:\+[^>]*)?>")
    definition_expr = re.compile(rf"^\s*[0-9a-fA-F]+\s+<{re.escape(symbol_name)}>:\s*$")
    instruction_expr = re.compile(r"^\s*([0-9a-fA-F]+):\s*(\S+)")
    disassembly = subprocess.Popen(
        ["objdump", "-d", "--no-show-raw-insn", "--section=.text", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    assert disassembly.stdout is not None
    for line in disassembly.stdout:
        if not symbol_expr.search(line):
            continue
        if definition_expr.match(line):
            definition_count += 1
            continue
        instruction = instruction_expr.match(line)
        if instruction:
            references.append({
                "source_address": int(instruction.group(1), 16),
                "mnemonic": instruction.group(2),
            })
    stderr = disassembly.stderr.read() if disassembly.stderr is not None else ""
    if disassembly.stdout is not None:
        disassembly.stdout.close()
    if disassembly.stderr is not None:
        disassembly.stderr.close()
    status = disassembly.wait()
    if status != 0:
        raise RuntimeError(f"objdump failed ({status}): {stderr[-2000:]}")
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    if before != after:
        raise RuntimeError("input changed during audit")

    return {
        "schema": "local-elf-symbol-reference-audit-v1",
        "subject": {
            "name": path.name,
            "sha256": before,
            "bytes": path.stat().st_size,
            "format": "ELF64 x86-64 ET_REL",
            "private_artifact_content_retained": False,
        },
        "symbol": {"name": symbol_name, **symbols},
        "method": {
            "relocation_scan": "all readelf -rW rows; exact symbol-table index plus .text section-symbol addend",
            "disassembly_annotation_scan": "objdump -d .text symbol annotations; definitions excluded; relocation-backed operands are scanned separately",
            "input_unchanged": before == after,
        },
        "results": {
            "symbol_definitions_seen": definition_count,
            "annotated_disassembly_reference_count": len(references),
            "annotated_disassembly_references": references,
            "direct_relocation_reference_count": len(relocations),
            "direct_relocation_references": relocations,
        },
        "limitations": [
            "objdump -d annotations alone do not expose relocation-backed immediates; use the separate relocation results",
            "does not resolve computed function pointers or runtime dispatch",
            "zero static references does not prove the symbol is unreachable",
            "Ghidra xrefs in non-alloc sections require separate address-space classification",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("symbol")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.elf, args.symbol)
        encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=f".{args.output.name}.", dir=args.output.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, args.output)
            except Exception:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                raise
        else:
            sys.stdout.write(encoded)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ELF symbol audit failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
