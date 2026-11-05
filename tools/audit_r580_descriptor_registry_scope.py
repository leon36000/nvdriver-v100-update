#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the lifetime and scope of the pinned R580 descriptor registry.

The tool binds static disassembly to the exact R580.178.04 proprietary object
and wrapper sources. It does not observe live cache contents or GPU behavior.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PINNED_RM_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
PINNED_NV_C_SHA256 = "359a50f7dc840c0d7adc40388313391cfcaa55598982a4745622887e9423e005"
PINNED_NV_PCI_C_SHA256 = "7ac1926cb26ee6495c7af5b50c073ec6dfc351e2a7654268bebc9bde61862681"
BASE = Path("build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia")
DEFAULT_RM_OBJECT = ROOT / BASE / "nv-kernel.o_binary"
DEFAULT_NV_SOURCE = ROOT / BASE / "nv.c"
DEFAULT_NV_PCI_SOURCE = ROOT / BASE / "nv-pci.c"

DISASSEMBLE = (
    "rm_init_rm",
    "rm_shutdown_rm",
    "_nv000796rm",
    "_nv000843rm",
    "_nv021662rm",
    "_nv000755rm",
    "_nv006694rm",
    "_nv003385rm",
    "_nv005103rm",
    "_nv058760rm",
    "_nv058761rm",
    "_nv031399rm",
    "_nv049087rm",
    "_nv049090rm",
    "_nv052721rm",
    "_nv052725rm",
    "_nv006506rm",
    "_nv006815rm",
)
WANTED_RELOCATIONS = {
    "_nv029075rm",
    "_nv000796rm",
    "_nv021662rm",
    "_nv006694rm",
    "_nv003385rm",
    "_nv058760rm",
    "_nv000843rm",
    "_nv000754rm",
    "_nv000755rm",
    "_nv006815rm",
    "_nv005103rm",
    "_nv058761rm",
    "_nv031399rm",
    "_nv052721rm",
    "_nv052725rm",
    "_nv049087rm",
    "_nv049090rm",
    "_nv006506rm",
}
EXPECTED_EDGES = {
    ("_nv000796rm", "0xd65417", -4, ".rela.text"),
    ("_nv021662rm", "0xacb9", -4, ".rela.text"),
    ("_nv006694rm", "0xac7a", -4, ".rela.text"),
    ("_nv003385rm", "0xb05000", -4, ".rela.text"),
    ("_nv003385rm", "0xb0508c", -4, ".rela.text"),
    ("_nv058760rm", "0xb04f12", -4, ".rela.text"),
    ("_nv000754rm", "0xd6ce4b", -4, ".rela.text"),
    ("_nv000755rm", "0xd6ce54", -4, ".rela.text"),
    ("_nv006815rm", "0xace0", -4, ".rela.text"),
    ("_nv058761rm", "0xb04e69", -4, ".rela.text"),
    ("_nv005103rm", "0x4d863e8", 0, ".rela.rodata"),
    ("_nv029075rm", "0xa665", -4, ".rela.text"),
    ("_nv029075rm", "0xa7c1", -8, ".rela.text"),
    ("_nv029075rm", "0xab02", -8, ".rela.text"),
    ("_nv029075rm", "0x38c67", -4, ".rela.text"),
    ("_nv052721rm", "0x38c90", -4, ".rela.text"),
    ("_nv052725rm", "0x38d3d", -4, ".rela.text"),
    ("_nv049087rm", "0x38cca", -4, ".rela.text"),
    ("_nv049090rm", "0x38cec", -4, ".rela.text"),
    ("_nv006506rm", "0x38d80", -4, ".rela.text"),
    ("_nv005103rm", "0x4d863e8", 0, ".rela.rodata"),
}


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
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_symbols(output: str) -> dict[str, dict[str, object]]:
    parsed: dict[str, dict[str, object]] = {}
    for line in output.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\w)\s+(\S+)$", line)
        if match:
            parsed[match.group(4)] = {
                "address": int(match.group(1), 16),
                "size": int(match.group(2), 16),
                "type": match.group(3),
            }
    return parsed


def parse_relocations(path: Path) -> list[dict[str, object]]:
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
    references: list[dict[str, object]] = []
    for line in process.stdout:
        heading = re.match(r"Relocation section '([^']+)'", line)
        if heading:
            section = heading.group(1)
            continue
        fields = line.split()
        if len(fields) < 7 or fields[4] not in WANTED_RELOCATIONS:
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


def owner_of(address: int, symbols: dict[str, dict[str, object]]) -> str:
    matches = [
        name
        for name, symbol in symbols.items()
        if int(symbol["address"]) <= address < int(symbol["address"]) + int(symbol["size"])
    ]
    if len(matches) != 1:
        raise AuditError(f"expected one owning symbol for relocation 0x{address:x}, got {matches!r}")
    return matches[0]


def source_anchor(source: str, path: Path, fragment: str, expected_count: int = 1) -> dict[str, object]:
    lines = source.splitlines()
    matches = [(index, line) for index, line in enumerate(lines, 1) if fragment in line]
    if len(matches) != expected_count:
        raise AuditError(f"expected {expected_count} source occurrence(s) of {fragment!r} in {path}, got {len(matches)}")
    return {
        "path": str(path.resolve()),
        "line": matches[0][0],
        "text": matches[0][1].strip(),
        "occurrences": expected_count,
    }


def classify_global_writes(path: Path, references: list[dict[str, object]], symbols: dict[str, dict[str, object]]) -> tuple[list[dict[str, object]], str]:
    target_refs = {
        str(item["offset"]): item
        for item in references
        if item["section"] == ".rela.text" and item["symbol"] == "_nv029075rm"
    }
    try:
        process = subprocess.Popen(
            ["objdump", "-dr", "-M", "intel", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise AuditError(f"could not run objdump: {exc}") from exc
    if process.stdout is None:
        process.kill()
        raise AuditError("objdump stdout pipe was not created")

    section = ""
    instruction: tuple[int, str] | None = None
    matched: dict[str, str] = {}
    writes: list[dict[str, object]] = []
    write_ops = {"mov", "xchg", "add", "sub", "and", "or", "xor", "inc", "dec", "xadd", "cmpxchg", "bts", "btr", "btc", "neg", "not"}
    relocation_re = re.compile(r"^\s*([0-9a-fA-F]+):\s+R_X86_64_\S+\s+_nv029075rm(?:[+-]0x[0-9a-fA-F]+)?\s*$")
    for line in process.stdout:
        heading = re.match(r"Disassembly of section (\S+):", line)
        if heading:
            section = heading.group(1)
            instruction = None
            continue
        if section != ".text":
            continue
        relocation = relocation_re.match(line)
        if relocation:
            offset = f"0x{int(relocation.group(1), 16):x}"
            if offset not in target_refs:
                process.kill()
                raise AuditError(f"objdump/readelf global-reference mismatch at {offset}")
            if instruction is None:
                process.kill()
                raise AuditError(f"could not bind global relocation {offset} to an instruction")
            matched[offset] = instruction[1]
            text = instruction[1]
            parts = text.split(None, 1)
            if len(parts) != 2:
                continue
            mnemonic = parts[0].lower().removeprefix("lock")
            operands = parts[1].strip()
            destination = operands.split(",", 1)[0].strip()
            if mnemonic in write_ops and "PTR [rip" in destination:
                address = int(offset, 16)
                writes.append(
                    {
                        "offset": offset,
                        "owner": owner_of(address, symbols),
                        "instruction": text,
                        "addend": target_refs[offset]["addend"],
                    }
                )
            continue

        if "\t" not in line or "R_X86_64_" in line:
            continue
        columns = line.split("\t")
        address_match = re.match(r"^\s*([0-9a-fA-F]+):", columns[0])
        if len(columns) >= 3 and address_match:
            encoded = columns[1].strip()
            text = columns[-1].strip()
            if re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", encoded) and text:
                instruction = (int(address_match.group(1), 16), text)

    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if return_code != 0:
        raise AuditError(f"objdump failed ({return_code}): {stderr.strip()}")
    if set(matched) != set(target_refs):
        missing = sorted(set(target_refs) - set(matched))
        extra = sorted(set(matched) - set(target_refs))
        raise AuditError(f"objdump/readelf global-reference census mismatch; missing={missing}, extra={extra}")
    writes.sort(key=lambda item: int(str(item["offset"]), 16))
    return writes, "\n".join(f"{offset} {text}" for offset, text in sorted(matched.items(), key=lambda item: int(item[0], 16)))


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
        raise AuditError(f"expected static signature missing in {where}: {fragment}")


def audit(rm_object: Path, nv_source_path: Path, pci_source_path: Path) -> tuple[dict[str, object], str]:
    hashes = {
        "rm_object": (file_sha256(rm_object), PINNED_RM_SHA256),
        "nv_source": (file_sha256(nv_source_path), PINNED_NV_C_SHA256),
        "nv_pci_source": (file_sha256(pci_source_path), PINNED_NV_PCI_C_SHA256),
    }
    for label, (actual, expected) in hashes.items():
        if actual != expected:
            raise AuditError(f"pinned input hash mismatch for {label}: got {actual}, expected {expected}")

    file_description = run(["file", "--brief", str(rm_object)]).strip()
    expected_description = "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped"
    if file_description != expected_description:
        raise AuditError(f"unexpected input format: {file_description}")

    symbols = parse_symbols(run(["nm", "-nS", "--defined-only", str(rm_object)]))
    global_pointer = symbols.get("_nv029075rm")
    if global_pointer != {"address": 0x5ED2188, "size": 8, "type": "b"}:
        raise AuditError(f"unexpected _nv029075rm symbol: {global_pointer!r}")

    references = parse_relocations(rm_object)
    references_by_edge: set[tuple[str, str, int, str]] = {
        (str(item["symbol"]), str(item["offset"]), int(item["addend"]), str(item["section"]))
        for item in references
    }
    if not EXPECTED_EDGES <= references_by_edge:
        raise AuditError(f"missing expected constructor/registry relocations: {sorted(EXPECTED_EDGES - references_by_edge)!r}")

    global_references = [
        item for item in references if item["section"] == ".rela.text" and item["symbol"] == "_nv029075rm"
    ]
    if len(global_references) != 878:
        raise AuditError(f"unexpected _nv029075rm text-reference count: {len(global_references)}")
    write_sites, global_instruction_census = classify_global_writes(rm_object, references, symbols)
    expected_write_sites = [
        ("0xa665", "_nv058760rm", -4),
        ("0xa7c1", "_nv058760rm", -8),
        ("0xab02", "_nv058761rm", -8),
    ]
    actual_write_sites = [(str(item["offset"]), str(item["owner"]), int(item["addend"])) for item in write_sites]
    if actual_write_sites != expected_write_sites:
        raise AuditError(f"unexpected _nv029075rm write-site census: {actual_write_sites!r}")
    if not ("QWORD PTR [rip+0x0],rdi" in write_sites[0]["instruction"]):
        raise AuditError("manager pointer setter no longer stores the constructor argument")
    if not all("QWORD PTR [rip+0x0],0x0" in item["instruction"] for item in write_sites[1:]):
        raise AuditError("expected null-pointer cleanup stores were not found")

    disassembly = {
        name: run(["objdump", "-dr", "-M", "intel", f"--disassemble={name}", str(rm_object)])
        for name in DISASSEMBLE
    }
    require(disassembly["rm_init_rm"], "_nv000796rm-0x4", "module RM initialization")
    require(disassembly["_nv000796rm"], "_nv021662rm-0x4", "RM-manager initialization")
    require(disassembly["_nv021662rm"], "_nv006694rm-0x4", "RM-manager object construction")
    require(disassembly["_nv006694rm"], "_nv003385rm-0x4", "manager object class constructor")
    require(disassembly["_nv003385rm"], "_nv058760rm-0x4", "manager constructor")
    require(disassembly["rm_shutdown_rm"], "_nv000843rm-0x4", "module RM shutdown")
    require(disassembly["_nv000843rm"], "_nv000754rm-0x4", "RM-manager shutdown")
    require(disassembly["_nv000843rm"], "_nv000755rm-0x4", "RM-manager object release")
    require(disassembly["_nv000755rm"], "_nv006815rm-0x4", "RM-manager destructor dispatch")
    require(disassembly["_nv006694rm"], ".rodata+0x4d863e0", "manager class descriptor pointer")
    require(disassembly["_nv006815rm"], "QWORD PTR [rax+0x8]", "indirect manager destructor slot")
    require(disassembly["_nv005103rm"], "_nv058761rm-0x4", "manager destructor")
    require(disassembly["_nv058760rm"], "_nv029075rm-0x4", "global manager pointer setter")
    require(disassembly["_nv058760rm"], "_nv029075rm-0x8", "global manager initialization-failure cleanup")
    require(disassembly["_nv058761rm"], "_nv029075rm-0x8", "global manager shutdown cleanup")

    lookup = disassembly["_nv031399rm"]
    for fragment in (
        "_nv029075rm-0x4",
        "mov    r14,QWORD PTR [rax+0x1e0]",
        "mov    rdi,QWORD PTR [r14+0x950]",
        "_nv052721rm-0x4",
        "mov    rdi,QWORD PTR [r14+0x38]",
        "_nv049087rm-0x4",
        "_nv049090rm-0x4",
        "_nv052725rm-0x4",
        "cmp    DWORD PTR [rax+0x88],r12d",
        "cmp    DWORD PTR [rax+0x8c],ebx",
        "cmp    DWORD PTR [rax+0x90],r13d",
        "cmp    DWORD PTR [rax+0x94],ecx",
        "_nv006506rm-0x4",
    ):
        require(lookup, fragment, "shared descriptor registry lookup")
    require(disassembly["_nv049087rm"], "QWORD PTR [rbx+0x18]", "registry traversal helper one")
    require(disassembly["_nv049090rm"], "QWORD PTR [rbx+0x20]", "registry traversal helper two")

    nv_source = nv_source_path.read_text(encoding="utf-8")
    pci_source = pci_source_path.read_text(encoding="utf-8")
    anchors = {
        "rm_init_inside_module_init": source_anchor(nv_source, nv_source_path, "if (!rm_init_rm(*sp))"),
        "module_initializer_calls_nv_module_init": source_anchor(nv_source, nv_source_path, "rc = nv_module_init(&sp);"),
        "rm_shutdown_inside_module_exit": source_anchor(nv_source, nv_source_path, "rm_shutdown_rm(sp);"),
        "per_device_rm_init_adapter": source_anchor(nv_source, nv_source_path, "if (!rm_init_adapter(sp, nv))"),
        "per_pci_probe_private_state": source_anchor(pci_source, pci_source_path, "if (!rm_init_private_state(sp, nv))"),
    }
    if anchors["rm_init_inside_module_init"]["line"] >= anchors["per_device_rm_init_adapter"]["line"]:
        raise AuditError("unexpected source ordering for module and per-adapter RM initialization")

    owner_counts: dict[str, int] = {}
    for item in global_references:
        owner = owner_of(int(str(item["offset"]), 16), symbols)
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
    top_owners = sorted(owner_counts.items(), key=lambda pair: (-pair[1], pair[0]))[:20]
    relocation_edges = [
        {"from": source, "to": target, "offset": offset, "addend": addend}
        for source, target, offset, addend in (
            ("rm_init_rm", "_nv000796rm", "0xd65417", -4),
            ("_nv000796rm", "_nv021662rm", "0xacb9", -4),
            ("_nv021662rm", "_nv006694rm", "0xac7a", -4),
            ("_nv006694rm", "_nv003385rm", "0xb05000", -4),
            ("_nv003385rm", "_nv058760rm", "0xb04f12", -4),
            ("rm_shutdown_rm", "_nv000843rm", "0xd65479", -4),
            ("_nv000843rm", "_nv000755rm", "0xd6ce54", -4),
            ("_nv000755rm", "_nv006815rm", "0xace0", -4),
            ("_nv005103rm", "_nv058761rm", "0xb04e69", -4),
        )
    ]
    direct_reference_counts = {
        target: sum(item["symbol"] == target and item["section"] == ".rela.text" for item in references)
        for target in ("_nv000796rm", "_nv021662rm", "_nv058760rm", "_nv058761rm")
    }
    if direct_reference_counts != {"_nv000796rm": 1, "_nv021662rm": 1, "_nv058760rm": 1, "_nv058761rm": 1}:
        raise AuditError(f"unexpected manager-constructor/destructor reference counts: {direct_reference_counts!r}")
    report: dict[str, object] = {
        "schema": "rea-r580-descriptor-registry-scope-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inputs": {
            "rm_object": {"path": str(rm_object.resolve()), "sha256": hashes["rm_object"][0], "format": file_description},
            "nv_c": {"path": str(nv_source_path.resolve()), "sha256": hashes["nv_source"][0]},
            "nv_pci_c": {"path": str(pci_source_path.resolve()), "sha256": hashes["nv_pci_source"][0]},
        },
        "module_lifecycle_source_anchors": anchors,
        "binary_initialization_call_chain": relocation_edges[:5],
        "binary_shutdown_call_chain": relocation_edges[5:],
        "binary_shutdown_dispatch": {
            "manager_release": "_nv000755rm calls _nv006815rm on the _nv029075rm object",
            "indirect_destructor_slot": {
                "owner": "_nv006815rm",
                "vtable_slot_offset": "0x8",
                "vtable_base": "object[0], initialized from .rodata+0x4d863e0",
                "relocation_section": ".rela.rodata",
                "relocation_offset": "0x4d863e8",
                "target": "_nv005103rm",
                "next_call": "_nv005103rm -> _nv058761rm",
            },
        },
        "constructor_destructor_direct_reference_counts": direct_reference_counts,
        "root_pointer": {
            "symbol": "_nv029075rm",
            "address": f"0x{int(global_pointer['address']):x}",
            "storage_section": ".bss",
            "size_bytes": int(global_pointer["size"]),
            "text_reference_count": len(global_references),
            "owners_with_direct_references": len(owner_counts),
            "top_reference_owners": [{"owner": owner, "references": count} for owner, count in top_owners],
            "write_sites": [
                {
                    "offset": str(item["offset"]),
                    "owner": str(item["owner"]),
                    "instruction": str(item["instruction"]),
                    "operation": operation,
                }
                for item, operation in zip(
                    write_sites,
                    ("store_object_pointer", "clear_on_initialization_failure", "clear_on_manager_teardown"),
                    strict=True,
                )
            ],
        },
        "cache_registry": {
            "lookup_function": "_nv031399rm",
            "manager_pointer_field_offset": "0x1e0",
            "lock_offset_from_registry": "0x950",
            "list_head_offset_from_registry": "0x38",
            "lock_helpers": {"acquire": "_nv052721rm", "release": "_nv052725rm"},
            "link_helpers": {"list_head_link": "_nv049087rm returns [node+0x18]", "next_link": "_nv049090rm returns [node+0x20]"},
            "descriptor_key_offsets": ["0x88", "0x8c", "0x90", "0x94"],
            "miss_constructor": "_nv006506rm",
            "per_adapter_lookup_routes": ["rm_init_private_state -> _nv000794rm -> _nv031399rm", "rm_init_adapter -> _nv000790rm -> _nv031364rm -> _nv031399rm"],
        },
        "scope_assessment": {
            "status": "static_inference",
            "conclusion": "The descriptor list is reached through the module-lifetime RM manager pointer, not through an adapter pointer at the lookup call. Both per-device initialization paths use this same global manager registry and lock; matching four-word keys can therefore reuse a descriptor across adapters while the manager is live.",
            "basis": "Pinned R580 binary global-pointer setter/cleanup, module init/shutdown source anchors, per-device source anchors, and the exact lookup/list/lock disassembly signatures.",
            "not_established": [
                "Live selector values, cache hit/miss outcomes, and callback targets on V100 or other hardware.",
                "Whether any pair of installed adapters supplies identical four-word keys during a real probe.",
                "The semantic meaning of descriptor callbacks or whether any are hardware-specific.",
                "Concurrent multi-adapter behavior, hot-unplug order, failure recovery, or long-duration stability.",
            ],
        },
        "global_reference_instruction_census_sha256": hashlib.sha256(global_instruction_census.encode("utf-8")).hexdigest(),
        "hardware_validation_performed": False,
        "limits": [
            "This is static evidence from one exact R580.178.04 relocatable object and its pinned wrapper sources; no dynamic call trace was collected.",
            "The 8-byte BSS symbol and lookup dataflow identify a module-manager-owned registry shape, but do not certify runtime cache contents or callback semantics.",
            "No driver module, PCI binding, VM, firmware, reboot, or GPU state was changed.",
        ],
        "verification": {"commands": ["sha256sum", "file", "nm -nS --defined-only", "readelf -rW", "objdump -dr -M intel"]},
    }
    report["tool_sha256"] = file_sha256(Path(__file__))

    raw = [
        f"rm_object={rm_object.resolve()} sha256={hashes['rm_object'][0]}",
        f"nv.c={nv_source_path.resolve()} sha256={hashes['nv_source'][0]}",
        f"nv-pci.c={pci_source_path.resolve()} sha256={hashes['nv_pci_source'][0]}",
        f"_nv029075rm direct .text references={len(global_references)}; unique owners={len(owner_counts)}",
        "Global pointer write sites:",
        *[f"{item['offset']} {item['owner']}: {item['instruction']}" for item in write_sites],
        "Module/per-device source anchors:",
        *[f"{name}: {value['path']}:{value['line']}: {value['text']}" for name, value in anchors.items()],
        "Global pointer reference instruction census (offset instruction):",
        global_instruction_census,
        *[f"\n===== {name} =====\n{body}" for name, body in disassembly.items()],
    ]
    return report, "\n".join(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rm-object", type=Path, default=DEFAULT_RM_OBJECT)
    parser.add_argument("--nv-source", type=Path, default=DEFAULT_NV_SOURCE)
    parser.add_argument("--pci-source", type=Path, default=DEFAULT_NV_PCI_SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-log", type=Path)
    args = parser.parse_args(argv)
    try:
        report, raw_log = audit(args.rm_object, args.nv_source, args.pci_source)
        private_write(args.output, json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.raw_log is not None:
            private_write(args.raw_log, raw_log)
    except (AuditError, OSError, UnicodeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(args.output.resolve()), "schema": report["schema"], "status": report["scope_assessment"]["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
