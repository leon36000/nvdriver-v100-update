#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory the pinned R580 descriptor lookup's direct call graph.

This bounded audit checks relocation references and disassembly in the pinned
R580.178.04 kernel object. It cannot observe live cache contents or ordering.
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
    "rm_init_private_state",
    "rm_init_adapter",
    "_nv000794rm",
    "_nv000790rm",
    "_nv031364rm",
    "_nv031399rm",
)
SYMBOLS = (*FUNCTIONS, "_nv000815rm")


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


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_symbols(output: str) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for line in output.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\w\s+(\S+)$", line)
        if match:
            result.append({"address": int(match.group(1), 16), "size": int(match.group(2), 16), "name": match.group(3)})
    return result


def parse_relocations(path: Path, wanted_symbols: set[str]) -> list[dict[str, str]]:
    try:
        process = subprocess.Popen(
            ["readelf", "-rW", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise AuditError(f"could not run readelf: {exc}") from exc
    if process.stdout is None:
        process.kill()
        raise AuditError("readelf stdout pipe was not created")

    section = ""
    references: list[dict[str, str]] = []
    for line in process.stdout:
        section_match = re.match(r"Relocation section '([^']+)'", line)
        if section_match:
            section = section_match.group(1)
            continue
        fields = line.split()
        if len(fields) < 7 or fields[4] not in wanted_symbols:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            continue
        sign = -1 if fields[5] == "-" else 1
        try:
            addend = sign * int(fields[6], 0)
        except ValueError:
            try:
                addend = sign * int(fields[6], 16)
            except ValueError as exc:
                process.kill()
                raise AuditError(f"unrecognized relocation addend: {line.rstrip()}") from exc
        references.append(
            {
                "section": section,
                "offset": f"0x{int(fields[0], 16):x}",
                "type": fields[2],
                "symbol": fields[4],
                "addend": addend,
            }
        )
    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if return_code != 0:
        raise AuditError(f"readelf failed ({return_code}): {stderr.strip()}")
    return references


def owner_of(address: int, symbols: list[dict[str, object]]) -> str:
    matches = [
        symbol
        for symbol in symbols
        if int(symbol["address"]) <= address < int(symbol["address"]) + int(symbol["size"])
    ]
    if len(matches) != 1:
        raise AuditError(f"expected one owning symbol for relocation 0x{address:x}, got {matches!r}")
    return str(matches[0]["name"])


def private_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def require(text: str, fragment: str, where: str) -> None:
    if fragment not in text:
        raise AuditError(f"expected disassembly fact missing in {where}: {fragment}")


def audit(path: Path) -> tuple[dict[str, object], str]:
    digest = file_sha256(path)
    if digest != PINNED_SHA256:
        raise AuditError(f"pinned input hash mismatch: got {digest}, expected {PINNED_SHA256}")
    file_description = run(["file", "--brief", str(path)]).strip()
    if file_description != "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped":
        raise AuditError(f"unexpected input format: {file_description}")

    symbols = parse_symbols(run(["nm", "-nS", "--defined-only", str(path)]))
    disassembly = {
        name: run(["objdump", "-dr", "-M", "intel", f"--disassemble={name}", str(path)])
        for name in FUNCTIONS
    }
    references = parse_relocations(path, {"_nv031399rm", "_nv031364rm", "_nv000794rm", "_nv000790rm"})
    relevant = [reference for reference in references if reference["section"] == ".rela.text"]

    by_target = {
        symbol: [reference for reference in relevant if reference["symbol"] == symbol]
        for symbol in ("_nv031399rm", "_nv031364rm", "_nv000794rm", "_nv000790rm")
    }
    if [(item["offset"], item["type"]) for item in by_target["_nv031399rm"]] != [
        ("0x3c193", "R_X86_64_PC32"),
        ("0xd6d3cd", "R_X86_64_PC32"),
    ]:
        raise AuditError(f"unexpected direct relocation census for _nv031399rm: {by_target['_nv031399rm']!r}")
    if [(item["offset"], item["type"]) for item in by_target["_nv031364rm"]] != [
        ("0xd6e46f", "R_X86_64_PC32")
    ]:
        raise AuditError(f"unexpected direct relocation census for _nv031364rm: {by_target['_nv031364rm']!r}")
    if [(item["offset"], item["type"]) for item in by_target["_nv000794rm"]] != [
        ("0xd6493a", "R_X86_64_PC32")
    ]:
        raise AuditError(f"unexpected direct relocation census for _nv000794rm: {by_target['_nv000794rm']!r}")
    if [(item["offset"], item["type"]) for item in by_target["_nv000790rm"]] != [
        ("0xd64aa9", "R_X86_64_PC32")
    ]:
        raise AuditError(f"unexpected direct relocation census for _nv000790rm: {by_target['_nv000790rm']!r}")

    routes: dict[str, str] = {}
    expected_owners = {
        "_nv031399rm": {"0x3c193": "_nv031364rm", "0xd6d3cd": "_nv000794rm"},
        "_nv031364rm": {"0xd6e46f": "_nv000790rm"},
        "_nv000794rm": {"0xd6493a": "rm_init_private_state"},
        "_nv000790rm": {"0xd64aa9": "rm_init_adapter"},
    }
    for target, entries in by_target.items():
        for entry in entries:
            owner = owner_of(int(entry["offset"], 16), symbols)
            expected = expected_owners[target].get(entry["offset"])
            if owner != expected:
                raise AuditError(f"relocation {entry['offset']} to {target} belongs to {owner}, expected {expected}")
            routes[target] = owner

    # Verify the two _nv031399rm callers both pass class-key words 0 and 0.
    wrapper = disassembly["_nv000794rm"]
    for fragment in ("xor    r12d,r12d", "mov    edi,r12d", "xor    edx,edx", "mov    esi,r13d"):
        require(wrapper, fragment, "_nv000794rm -> _nv031399rm")
    enumerate_path = disassembly["_nv031364rm"]
    for fragment in (
        "mov    eax,DWORD PTR [rbx+0x12c8]",
        "xor    r14d,r14d",
        "xor    edx,edx",
        "mov    esi,r15d",
        "mov    edi,r14d",
        "_nv031399rm-0x4",
    ):
        require(enumerate_path, fragment, "_nv031364rm -> _nv031399rm")
    require(disassembly["_nv000790rm"], "_nv031364rm-0x4", "_nv000790rm -> _nv031364rm")

    private_state = disassembly["rm_init_private_state"]
    require(private_state, "mov    rdi,rsi", "rm_init_private_state argument forwarding")
    require(private_state, "_nv000794rm-0x4", "rm_init_private_state route")
    adapter = disassembly["rm_init_adapter"]
    require(adapter, "mov    r12,rsi", "rm_init_adapter argument forwarding")
    require(adapter, "test   BYTE PTR [r12+0x11],0x8", "rm_init_adapter backend branch")
    require(adapter, "_nv000815rm-0x4", "rm_init_adapter alternate branch")
    require(adapter, "_nv000790rm-0x4", "rm_init_adapter normal branch")

    caller_records = [
        {
            "relocation_offset": "0x3c193",
            "caller": "_nv031364rm",
            "first_key_argument": "0",
            "selector_argument": "record+0x12c8",
            "third_key_argument": "0",
        },
        {
            "relocation_offset": "0xd6d3cd",
            "caller": "_nv000794rm",
            "first_key_argument": "0",
            "selector_argument": "nv_state+0x274",
            "third_key_argument": "0",
        },
    ]
    report: dict[str, object] = {
        "schema": "rea-r580-descriptor-cache-callers-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input": {"path": str(path.resolve()), "sha256": digest, "format": file_description},
        "direct_references_to_nv031399rm": caller_records,
        "caller_routes": {
            "_nv031364rm": "_nv000790rm",
            "_nv000794rm": "rm_init_private_state",
            "_nv000790rm": "rm_init_adapter (when flags bit 3 is clear)",
        },
        "all_direct_symbol_relocations": references,
        "first_and_third_key_arguments_zero_at_both_direct_call_sites": True,
        "cache_hit_before_private_state_cannot_be_excluded": True,
        "runtime_cache_contents": "unknown",
        "limits": [
            "The relocation census covers references to these local symbols in this pinned relocatable object; it is not dynamic call tracing.",
            "The binary call graph does not establish per-device cache ownership, global lifetime, inter-device ordering, or cache contents at runtime.",
            "Both visible direct callers pass zero first and third key arguments; this does not rule out aliasing or later mutation of cached object fields.",
            "No GPU, driver module, or VM was exercised.",
        ],
        "verification": {"commands": ["readelf -rW", "nm -nS --defined-only", "objdump -dr -M intel"]},
    }
    raw_log = "\n".join(f"===== {name} =====\n{disassembly[name]}" for name in FUNCTIONS)
    return report, raw_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rm-object", type=Path, default=DEFAULT_OBJECT)
    parser.add_argument("--output", type=Path, help="write a private JSON report instead of stdout")
    parser.add_argument("--raw-log", type=Path, help="also save selected disassembly as a private log")
    args = parser.parse_args(argv)
    try:
        report, raw_log = audit(args.rm_object)
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
