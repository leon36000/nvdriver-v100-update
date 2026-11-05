#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce a narrow relocation-aware audit of the pinned R580 lookup callsite."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

EXPECTED_BINARY_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
EXPECTED_FUNCTION = "_nv031364rm"
EXPECTED_CALL_OFFSET = 0x92
EXPECTED_TARGET = "_nv031399rm"
DEFAULT_BINARY = (
    "build/experiments/proprietary580-wrapper-baseline-v1/"
    "nvidia-580.178.04/nvidia/nv-kernel.o_binary"
)
DEFAULT_REPORT = "evidence/rea-r580-lookup-callsite-v1-20261022.json"
DEFAULT_LOG = "evidence/logs/rea-r580-lookup-callsite-v1-20261022.log"

_SYMBOL_RE = re.compile(
    rf"^\s*([0-9a-fA-F]+)\s+<{re.escape(EXPECTED_FUNCTION)}>:\s*$"
)
_INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)([^\s]+)\s*(.*)$"
)
_RELOCATION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*(R_X86_64_[A-Z0-9_]+)\s+"
    r"([A-Za-z0-9_.$]+?)(?:([+-])0x([0-9a-fA-F]+))?\s*$"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_disassembly(text: str) -> dict[str, object]:
    """Validate the exact call instruction and its following ELF relocation."""
    symbols = [
        (index, int(match.group(1), 16))
        for index, line in enumerate(text.splitlines())
        if (match := _SYMBOL_RE.match(line))
    ]
    if len(symbols) != 1:
        raise ValueError(f"expected one {EXPECTED_FUNCTION} symbol header")
    symbol_line, symbol_address = symbols[0]

    instructions: list[tuple[int, str, str]] = []
    relocations: list[tuple[int, str, str, int]] = []
    for line in text.splitlines()[symbol_line + 1:]:
        match = _SYMBOL_RE.match(line)
        if match:
            break
        instruction = _INSTRUCTION_RE.match(line)
        if instruction:
            address = int(instruction.group(1), 16)
            encoded = " ".join(instruction.group(2).split()).lower()
            mnemonic = instruction.group(3).lower()
            instructions.append((address, encoded, mnemonic))
            continue
        relocation = _RELOCATION_RE.match(line)
        if relocation:
            sign, magnitude = relocation.group(4), relocation.group(5)
            addend = int(magnitude, 16) if magnitude else 0
            if sign == "-":
                addend = -addend
            relocations.append((
                int(relocation.group(1), 16), relocation.group(2),
                relocation.group(3), addend,
            ))

    expected_address = symbol_address + EXPECTED_CALL_OFFSET
    pinned = [item for item in instructions if item[0] == expected_address]
    if len(pinned) != 1:
        raise ValueError(
            f"expected call instruction at {expected_address:#x} "
            f"(function +{EXPECTED_CALL_OFFSET:#x})"
        )
    call_address, encoded, mnemonic = pinned[0]
    if mnemonic != "call":
        raise ValueError("pinned instruction is not a call opcode")
    opcode = encoded.split()
    if len(opcode) != 5 or opcode[0] != "e8":
        raise ValueError("pinned call opcode is not a five-byte x86-64 rel32 call")

    call_relocations = [item for item in relocations if item[0] == call_address + 1]
    if len(call_relocations) != 1:
        raise ValueError("expected exactly one relocation at the rel32 call operand")
    relocation_address, relocation_type, target_symbol, addend = call_relocations[0]
    if relocation_type != "R_X86_64_PC32":
        raise ValueError("call relocation type is not R_X86_64_PC32")
    if target_symbol != EXPECTED_TARGET:
        raise ValueError("call relocation target is not _nv031399rm")
    if addend != -4:
        raise ValueError("call relocation addend is not -4")

    return {
        "symbol": EXPECTED_FUNCTION,
        "symbol_address": symbol_address,
        "call_offset": call_address - symbol_address,
        "call_address": call_address,
        "instruction_bytes": encoded,
        "instruction_mnemonic": mnemonic,
        "relocation_address": relocation_address,
        "relocation_type": relocation_type,
        "target_symbol": target_symbol,
        "addend": addend,
        "claim_scope": (
            "The pinned relocatable object contains this call and relocation. "
            "This does not establish runtime branch selection, selector meaning, "
            "cache hit or miss, CUDA behavior, or the identity of a loaded module."
        ),
    }


def _write_private(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    path.chmod(0o600)


def run(binary: Path, report_path: Path, log_path: Path) -> dict[str, object]:
    binary = binary.resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"pinned R580 binary not found: {binary}")
    binary_hash = sha256_file(binary)
    if binary_hash != EXPECTED_BINARY_SHA256:
        raise ValueError("R580 input does not match the pinned binary SHA-256")
    objdump = shutil.which("objdump")
    if not objdump:
        raise RuntimeError("objdump is unavailable")
    version = subprocess.run(
        [objdump, "--version"], capture_output=True, text=True, check=False, timeout=15
    )
    if version.returncode:
        raise RuntimeError("objdump --version failed")
    command = [objdump, "-dr", "-M", "intel", f"--disassemble={EXPECTED_FUNCTION}", str(binary)]
    result = subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=30
    )
    _write_private(log_path, result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"objdump failed with status {result.returncode}")
    parsed = parse_disassembly(result.stdout)
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-r580-lookup-callsite-audit-v1",
        "status": "static_audit_passed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "path": str(binary),
            "sha256": binary_hash,
            "expected_sha256": EXPECTED_BINARY_SHA256,
        },
        "tool": {
            "path": objdump,
            "version": version.stdout.splitlines()[0] if version.stdout else "unknown",
            "arguments": command[1:-1],
            "log_path": str(log_path),
            "log_sha256": sha256_file(log_path),
        },
        "finding": parsed,
    }
    _write_private(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(DEFAULT_BINARY))
    parser.add_argument("--report", type=Path, default=Path(DEFAULT_REPORT))
    parser.add_argument("--log", type=Path, default=Path(DEFAULT_LOG))
    args = parser.parse_args(argv)
    try:
        result = run(args.binary, args.report, args.log)
    except (FileNotFoundError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": result["status"],
        "binary_sha256": result["input"]["sha256"],
        "call_offset": result["finding"]["call_offset"],
        "target_symbol": result["finding"]["target_symbol"],
        "report": str(args.report),
        "log": str(args.log),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
