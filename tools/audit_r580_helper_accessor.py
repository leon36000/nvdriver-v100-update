#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Statically audit the pinned R580 helper and its lookup caller."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


EXPECTED_OBJECT_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
BASE = Path(__file__).resolve().parents[1]
DEFAULT_OBJECT = BASE / (
    "build/experiments/proprietary580-wrapper-baseline-v1/"
    "nvidia-580.178.04/nvidia/nv-kernel.o_binary"
)
DEFAULT_REPORT = BASE / "evidence/rea-r580-helper-accessor-v1-20261022.json"
DEFAULT_LOG = BASE / "evidence/logs/rea-r580-helper-accessor-v1-20261022.log"

HELPER_BASE = 0xD61270
CALLER_BASE = 0x3C100
_INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)([a-z][a-z0-9]*)\s*(.*?)\s*$"
)
_RELOCATION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*(R_X86_64_[A-Z0-9_]+)\s+"
    r"([A-Za-z0-9_.$]+?)(?:([+-])0x([0-9a-fA-F]+))?\s*$"
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_disassembly(text: str) -> tuple[dict[int, tuple[str, str]], list[tuple[int, str, str, int]]]:
    instructions: dict[int, tuple[str, str]] = {}
    relocations: list[tuple[int, str, str, int]] = []
    for line in text.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            address = int(match.group(1), 16)
            if address in instructions:
                raise ValueError(f"duplicate disassembly address {address:#x}")
            instructions[address] = (match.group(3).lower(), " ".join(match.group(4).split()).lower())
            continue
        relocation = _RELOCATION.match(line)
        if relocation:
            sign, magnitude = relocation.group(4), relocation.group(5)
            addend = int(magnitude, 16) if magnitude else 0
            if sign == "-":
                addend = -addend
            relocations.append((int(relocation.group(1), 16), relocation.group(2),
                                relocation.group(3), addend))
    return instructions, relocations


def _expect(
    instructions: dict[int, tuple[str, str]], base: int, offset: int,
    mnemonic: str, operands_prefix: str
) -> None:
    actual = instructions.get(base + offset)
    if actual is None or actual[0] != mnemonic or not actual[1].startswith(operands_prefix.lower()):
        raise ValueError(
            f"unexpected helper instruction at {base + offset:#x}: {actual!r}; "
            f"expected {mnemonic} {operands_prefix}"
        )


def validate_helper_disassembly(text: str) -> dict[str, object]:
    """Map the helper's conditional return paths from exact disassembly."""
    instructions, relocations = _parse_disassembly(text)
    anchors = (
        (0x10, "mov", "ebx,edx"),
        (0x12, "mov", "esi,ebx"),
        (0x14, "lea", "rdx,[rbp+0xf]"),
        (0x18, "mov", "byte ptr [rbp+0xf],0x0"),
        (0x1C, "call", "d61291"),
        (0x21, "cmp", "byte ptr [rbp+0xf],0x0"),
        (0x25, "mov", "r12d,eax"),
        (0x28, "jne", "d612ab"),
        (0x2A, "cmp", "dword ptr [r13+0x10],ebx"),
        (0x2E, "jbe", "d612c0"),
        (0x30, "mov", "rax,qword ptr [r13+0x0]"),
        (0x34, "shr", "ebx,0x2"),
        (0x37, "mov", "r12d,dword ptr [rax+rbx*4]"),
        (0x3B, "pop", "rbx"),
        (0x3C, "mov", "eax,r12d"),
        (0x50, "mov", "esi,0x7f00000"),
        (0x55, "mov", "edi,0xed2ad0a"),
        (0x5A, "xor", "eax,eax"),
        (0x5C, "call", "d612d1"),
        (0x61, "mov", "edi,0x7f0"),
        (0x66, "call", "d612db"),
        (0x6C, "mov", "eax,r12d"),
        (0x77, "ret", ""),
    )
    for offset, mnemonic, operands in anchors:
        _expect(instructions, HELPER_BASE, offset, mnemonic, operands)

    expected_relocations = [
        (HELPER_BASE + 0x1D, "R_X86_64_PC32", "_nv060447rm", -4),
        (HELPER_BASE + 0x5D, "R_X86_64_PC32", "_nv047869rm", -4),
        (HELPER_BASE + 0x67, "R_X86_64_PC32", "_nv046745rm", -4),
    ]
    actual_relocations = [item for item in relocations if item[0] in {entry[0] for entry in expected_relocations}]
    if actual_relocations != expected_relocations:
        raise ValueError("helper relocation targets do not match the pinned R580 object")

    return {
        "symbol": "_nv049612rm",
        "symbol_offset": HELPER_BASE,
        "buffer_offset_input": "edx -> ebx",
        "primary_helper": "_nv060447rm",
        "bounds_check": "dword [r13+0x10] > ebx",
        "word_load": "dword [rax + ((ebx >> 2) * 4)], where rax = qword [r13+0x0]",
        "bounds_error_log_helpers": ["_nv047869rm", "_nv046745rm"],
        "return_modes": [
            "saved_nv060447rm_eax_when_local_byte_nonzero",
            "loaded_32_bit_word_when_local_byte_zero_and_in_bounds",
            "saved_nv060447rm_eax_after_bounds_error_logging",
        ],
    }


def validate_caller_disassembly(text: str) -> dict[str, object]:
    """Verify the fixed caller supplies offset 0xa00 and forwards EAX in R14D."""
    instructions, relocations = _parse_disassembly(text)
    anchors = (
        (0x9FC, "xor", "edi,edi"),
        (0x9FE, "mov", "edx,0xa00"),
        (0xA03, "lea", "rsi,[rbp+0x50]"),
        (0xA0A, "call", "3cb0f"),
        (0xA1A, "mov", "r14d,eax"),
        (0x08F, "mov", "edi,r14d"),
        (0x092, "call", "3c197"),
    )
    for offset, mnemonic, operands in anchors:
        actual = instructions.get(CALLER_BASE + offset)
        if actual is None or actual[0] != mnemonic or not actual[1].startswith(operands.lower()):
            raise ValueError(f"unexpected caller instruction at +{offset:#x}: {actual!r}")
    expected = sorted([
        (CALLER_BASE + 0xA0B, "R_X86_64_PC32", "_nv049612rm", -4),
        (CALLER_BASE + 0x093, "R_X86_64_PC32", "_nv031399rm", -4),
    ])
    actual = [item for item in relocations if item[0] in {entry[0] for entry in expected}]
    if sorted(actual) != expected:
        raise ValueError("expected caller relocation to _nv049612rm and _nv031399rm")
    return {
        "caller_symbol": "_nv031364rm",
        "caller_offset": 0xA0A,
        "argument_sources": {"edi": "zero", "rsi": "address_of_rbp_plus_0x50", "edx": "0xa00"},
        "return_capture": "eax -> r14d",
        "first_lookup_argument": "r14d",
        "lookup_call_offset": 0x92,
    }


def build_static_helper_report(
    object_sha256: str, helper_disassembly: str, caller_disassembly: str
) -> dict[str, object]:
    if object_sha256 != EXPECTED_OBJECT_SHA256:
        raise ValueError("helper report requires the pinned R580 object")
    return {
        "schema": "rea-r580-helper-accessor-v1",
        "status": "static_helper_accessor_mapped",
        "qualification": "analyzed_statically",
        "inputs": {
            "rm_object_sha256": object_sha256,
            "runtime_capture_used": False,
            "loaded_module_identity_checked": False,
        },
        "helper": validate_helper_disassembly(helper_disassembly),
        "caller_context": validate_caller_disassembly(caller_disassembly),
        "interpretation": (
            "The pinned object shows _nv049612rm calling _nv060447rm, then taking "
            "one of three register-level return paths: a saved helper EAX value, "
            "a bounded 32-bit word load, or the saved value after logging. The "
            "fixed _nv031364rm call at +0xa0a supplies zero, a stack address, and "
            "offset 0xa00; its EAX result is captured in R14D and later placed in "
            "EDI for _nv031399rm. This does not identify the buffer's semantic "
            "type, the helper result's meaning, or any runtime value."
        ),
        "limitations": [
            "Private buffer and structure meanings are unknown.",
            "No runtime data, GPU, driver module, or VM was inspected or changed.",
            "This static mapping does not establish CUDA or hybrid-driver behavior.",
        ],
    }


def _write_new_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def run_static_helper_audit(object_path: Path, report_path: Path, log_path: Path) -> dict[str, object]:
    object_path = object_path.resolve()
    report_path = report_path.resolve()
    log_path = log_path.resolve()
    object_sha = sha256_file(object_path)
    if object_sha != EXPECTED_OBJECT_SHA256:
        raise ValueError("helper audit requires the pinned R580 object")
    objdump = shutil.which("objdump")
    if objdump is None:
        raise RuntimeError("objdump is required")
    commands = [
        [objdump, "-dr", "-M", "intel", "--disassemble=_nv049612rm", str(object_path)],
        [objdump, "-dr", "-M", "intel", "--disassemble=_nv031364rm", str(object_path)],
    ]
    outputs = []
    for command in commands:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"objdump failed: {command}")
        outputs.append(result.stdout)
    helper_text, caller_text = outputs
    report = build_static_helper_report(object_sha, helper_text, caller_text)
    log_bytes = ("\n".join(
        f"$ {' '.join(command)}\n{output.rstrip()}" for command, output in zip(commands, outputs)
    ) + "\n").encode()
    report["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["verification"] = {
        "objdump_path": objdump,
        "commands": [command[1:-1] for command in commands],
        "auditor_sha256": sha256_file(Path(__file__)),
        "log_path": str(log_path.relative_to(BASE)),
        "log_sha256": sha256_bytes(log_bytes),
    }
    _write_new_private(log_path, log_bytes)
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    _write_new_private(report_path, report_bytes)
    return {
        "status": report["status"],
        "qualification": report["qualification"],
        "report_path": str(report_path.relative_to(BASE)),
        "report_sha256": sha256_bytes(report_bytes),
        "log_path": str(log_path.relative_to(BASE)),
        "log_sha256": sha256_bytes(log_bytes),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, default=DEFAULT_OBJECT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--static-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.static_only:
        parser.error("this audit is static-only; pass --static-only explicitly")
    try:
        print(json.dumps(run_static_helper_audit(args.object, args.report, args.log), sort_keys=True))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
