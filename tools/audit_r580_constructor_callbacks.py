#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit one pinned R580 callback-constructor path from disassembly.

This is a narrow, hash-pinned static audit of proprietary R580.178.04.
It resolves the constructor-miss path used by _nv000794rm when flags bit 4
is set. It does not observe runtime state, cache contents, or GPU behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone


PINNED_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
DEFAULT_OBJECT = (
    Path(__file__).resolve().parents[1]
    / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-kernel.o_binary"
)
FUNCTIONS = (
    "_nv000794rm",
    "_nv031399rm",
    "_nv006506rm",
    "_nv052705rm",
    "_nv005685rm",
    "_nv006052rm",
    "_nv005882rm",
    "_nv031304rm",
    "_nv031301rm",
    "_nv031308rm",
    "_nv031310rm",
)


class AuditError(RuntimeError):
    pass


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AuditError(f"could not run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        raise AuditError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr.strip()}")
    return result.stdout


def require(text: str, fragment: str, where: str) -> None:
    if fragment not in text:
        raise AuditError(f"expected disassembly fact missing in {where}: {fragment}")


def parse_symbols(output: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in output.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+\w\s+(\S+)$", line)
        if match:
            symbols[match.group(2)] = int(match.group(1), 16)
    return symbols


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def private_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        try:
            os.chmod(path, 0o600)
        except FileNotFoundError:
            pass


def audit(rm_object: Path) -> tuple[dict[str, object], str]:
    try:
        digest = sha256_file(rm_object)
    except OSError as exc:
        raise AuditError(f"cannot read RM object {rm_object}: {exc}") from exc
    if digest != PINNED_SHA256:
        raise AuditError(f"pinned input hash mismatch: got {digest}, expected {PINNED_SHA256}")

    file_description = run(["file", "--brief", str(rm_object)]).strip()
    if file_description != "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped":
        raise AuditError(f"unexpected input format: {file_description}")

    symbols = parse_symbols(run(["nm", "-nS", "--defined-only", str(rm_object)]))
    disassembly = {
        name: run(["objdump", "-dr", "-M", "intel", f"--disassemble={name}", str(rm_object)])
        for name in FUNCTIONS
    }
    # The wrapper reads +0x274 only on the flags&0x10 path and passes it as
    # the second _nv031399rm argument. That branch starts with the first key
    # word forced to zero and the third argument zero.
    require(disassembly["_nv000794rm"], "DWORD PTR [rdi+0x274]", "_nv000794rm")
    require(disassembly["_nv000794rm"], "test   BYTE PTR [rdi+0x10],0x10", "_nv000794rm selector gate")
    require(disassembly["_nv000794rm"], "je     d6d4e0", "_nv000794rm selector gate")
    require(disassembly["_nv000794rm"], "xor    r12d,r12d", "_nv000794rm")
    require(disassembly["_nv000794rm"], "mov    esi,r13d", "_nv000794rm")
    require(disassembly["_nv000794rm"], "mov    edi,r12d", "_nv000794rm")
    require(disassembly["_nv000794rm"], "xor    edx,edx", "_nv000794rm")
    require(disassembly["_nv000794rm"], "_nv031399rm-0x4", "_nv000794rm")
    require(disassembly["_nv000794rm"], "test   BYTE PTR [rbx+0x10],0x10", "_nv000794rm")
    require(disassembly["_nv000794rm"], "jne    d6d470", "_nv000794rm extended callback gate")

    # On descriptor lookup miss, _nv031399rm calls the allocator/constructor.
    require(disassembly["_nv031399rm"], "_nv006506rm-0x4", "_nv031399rm")
    require(disassembly["_nv031399rm"], "mov    ecx,r12d", "_nv031399rm miss arguments")
    require(disassembly["_nv031399rm"], "mov    r8d,ebx", "_nv031399rm miss arguments")
    require(disassembly["_nv031399rm"], "xor    edx,edx", "_nv031399rm miss arguments")

    # The constructor's PC32 relocation is against the section symbol. For
    # this x86-64 relocation, the call destination is S + A + 4.
    ctor = disassembly["_nv006506rm"]
    require(ctor, "mov    esi,0x98", "_nv006506rm allocation")
    require(ctor, "_nv005685rm-0x4", "_nv006506rm object initializer")
    require(ctor, "xor    esi,esi", "_nv006506rm object zero-fill")
    require(ctor, "mov    edx,0x98", "_nv006506rm object zero-fill")
    require(ctor, "_nv052705rm-0x4", "_nv006506rm object zero-fill")
    require(disassembly["_nv052705rm"], "os_mem_set-0x4", "_nv052705rm zero-fill helper")
    require(ctor, "bfe80a: R_X86_64_PC32\t.text+0xbfe4ac", "_nv006506rm initializer relocation")
    relocation_offset = 0xBFE80A
    relocation_addend = 0xBFE4AC
    resolved_target = relocation_addend + 4
    initializer_symbol = symbols.get("_nv005882rm")
    if initializer_symbol != resolved_target:
        raise AuditError(
            f"PC32 initializer resolved to 0x{resolved_target:x}, but _nv005882rm is {initializer_symbol!r}"
        )

    # Constructor class words reach _nv006052rm as (0, 0) on this miss.
    # _nv005685rm points that helper at root+0x48; no case writes a value for
    # (0, 0), so the prior zeroed selector stays zero.
    init = disassembly["_nv005685rm"]
    require(init, "_nv006052rm-0x4", "_nv005685rm")
    require(init, "lea    rdi,[rdi+0x10]", "_nv005685rm selector destination")
    require(ctor, "lea    r11,[r10+0x38]", "_nv006506rm embedded selector")
    require(ctor, "[r10+0x58],r11", "_nv006506rm embedded selector")
    selector = disassembly["_nv006052rm"]
    require(selector, "cmp    esi,0x11", "_nv006052rm selector dispatch")
    require(selector, "cmp    esi,0x12", "_nv006052rm selector dispatch")
    if "cmp    esi,0x0\n" in selector:
        raise AuditError("unexpected zero first-word case in _nv006052rm")

    # Resolve code-zero callback stores using relocations and the symbol table.
    callback_targets = {
        "0x68": "_nv031304rm",
        "0x70": "_nv031301rm",
        "0x78": "_nv031308rm",
        "0x80": "_nv031310rm",
    }
    callback_relocations = {
        "0x68": "_nv031304rm",
        "0x70": ".text+0xbfe470",
        "0x78": ".text+0xbfe490",
        "0x80": ".text+0xbfe670",
    }
    for relocation in callback_relocations.values():
        require(disassembly["_nv005882rm"], relocation, "_nv005882rm callback stores")
    selector_init = disassembly["_nv005882rm"]
    for fragment in (
        "mov    rax,QWORD PTR [rdi+0x58]",
        "movzx  eax,WORD PTR [rax+0x10]",
        "shr    rax,0x5",
        "jb     bfe600",
        "jae    bfe586",
        "bfe586:",
        "QWORD PTR [rdi+0x68]",
        "jne    bfe598",
        "bfe598:",
        "QWORD PTR [rdi+0x70]",
        "QWORD PTR [rdi+0x78]",
        "QWORD PTR [rdi+0x80]",
    ):
        require(selector_init, fragment, "_nv005882rm selector-zero branch")
    expected_addresses = {
        "_nv031304rm": 0x612350,
        "_nv031301rm": 0xBFE470,
        "_nv031308rm": 0xBFE490,
        "_nv031310rm": 0xBFE670,
    }
    for name, expected in expected_addresses.items():
        if symbols.get(name) != expected:
            raise AuditError(f"unexpected address for {name}: {symbols.get(name)!r}")

    # Confirm the return values from the exact selected targets.
    require(disassembly["_nv031304rm"], "mov    eax,0x34", "_nv031304rm")
    for name in ("_nv031301rm", "_nv031308rm", "_nv031310rm"):
        require(disassembly[name], "xor    eax,eax", name)
        require(disassembly[name], "ret", name)

    # _nv000794rm invokes +0x70 first, then +0x68 when the result is zero;
    # that second return is passed in ESI to nv_set_dma_address_size.
    require(disassembly["_nv000794rm"], "QWORD PTR [rax+0x70]", "_nv000794rm address-size callback")
    require(disassembly["_nv000794rm"], "QWORD PTR [r14+0x68]", "_nv000794rm address-size fallback")
    require(disassembly["_nv000794rm"], "jne    d6d3fd", "_nv000794rm address-size callback gate")
    require(disassembly["_nv000794rm"], "mov    esi,eax", "_nv000794rm address-size argument")
    require(disassembly["_nv000794rm"], "nv_set_dma_address_size-0x4", "_nv000794rm address-size setter")

    report: dict[str, object] = {
        "schema": "rea-r580-constructor-callback-closure-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input": {
            "path": str(rm_object.resolve()),
            "sha256": digest,
            "format": file_description,
            "analysis_scope": "pinned R580.178.04 nv-kernel.o_binary, selected disassembly only",
        },
        "constructor_miss": {
            "entry": "_nv000794rm",
            "condition": "flags & 0x10 set; descriptor cache miss; constructor allocation succeeds",
            "_nv031399rm_arguments": {"rdi": "0", "rsi": "nv_state+0x274", "rdx": "0"},
            "initializer": {
                "symbol": "_nv005882rm",
                "pc32_relocation_offset": f"0x{relocation_offset:x}",
                "pc32_addend": f"0x{relocation_addend:x}",
                "resolved_section_offset": f"0x{resolved_target:x}",
                "selector_storage_offset": "0x48",
                "selector_input_words": ["0", "0"],
                "selector_remains_zero_on_this_branch": True,
            },
            "class_code_zero": {
                "callback_targets": callback_targets,
                "callback_returns": {"0x68": "0x34", "0x70": "0", "0x78": "0", "0x80": "0"},
                "nv_set_dma_address_size_argument": "0x34",
                "slots_0x78_0x80_invoked_on_flags_0x10_branch": False,
            },
        },
        "cache_hit_callback_targets": "unknown",
        "runtime_field_value_observed": False,
        "limits": [
            "The report resolves one statically visible constructor-miss path only.",
            "It does not prove that this cache-miss path ran on a GPU or establish live callback slot values.",
            "The actual nv_state+0x274 value at runtime remains unknown.",
            "A cache-hit object can have been initialized through a different path; its callback targets remain unknown.",
            "The callback value 0x34 is passed to nv_set_dma_address_size; this report does not assign it a hardware semantic.",
        ],
        "verification": {
            "commands": [
                "sha256sum <pinned nv-kernel.o_binary>",
                "nm -nS --defined-only <pinned nv-kernel.o_binary>",
                "objdump -dr -M intel --disassemble=<listed symbol> <pinned nv-kernel.o_binary>",
            ],
            "symbols_disassembled": list(FUNCTIONS),
        },
    }
    raw_log = "\n".join(f"===== {name} =====\n{disassembly[name]}" for name in FUNCTIONS)
    return report, raw_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rm-object", type=Path, default=DEFAULT_OBJECT)
    parser.add_argument("--output", type=Path, help="write a private JSON report instead of stdout")
    parser.add_argument("--raw-log", type=Path, help="also save the selected disassembly as a private log")
    args = parser.parse_args(argv)
    try:
        report, raw_log = audit(args.rm_object)
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.raw_log:
            private_write(args.raw_log, raw_log)
            report["verification"]["raw_disassembly_log"] = {
                "path": str(args.raw_log.resolve()),
                "sha256": hashlib.sha256(raw_log.encode("utf-8")).hexdigest(),
            }
            encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            private_write(args.output, encoded)
        else:
            sys.stdout.write(encoded)
    except (AuditError, OSError) as exc:
        parser.exit(2, f"audit failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
