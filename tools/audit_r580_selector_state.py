#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve the R580 selector's wrapper field and PCI initialization path.

This audit correlates a pinned R580 proprietary RM object with the DWARF
layout in its wrapper module and checks the source-level PCI and platform
paths. It is static evidence; it does not observe a live GPU's field value.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04"
PINNED_HASHES = {
    "module": "6687ca7503c4fef5b44186fba1209d579631ba4a96998625001299dda0eecff4",
    "rm_object": "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b",
    "common/inc/nv.h": "bc5802ef5a0e47be045cac9b74e61a0092f0bb96fc1ede05e2361d164e3b7787",
    "common/inc/nv-linux.h": "16b7612d2a0f70708b1400e569a1b5d4b726c0218657d13de34e10c710f9169c",
    "nvidia/nv.c": "359a50f7dc840c0d7adc40388313391cfcaa55598982a4745622887e9423e005",
    "nvidia/nv-pci.c": "7ac1926cb26ee6495c7af5b50c073ec6dfc351e2a7654268bebc9bde61862681",
    "nvidia/nv-platform.c": "9fcce137af66b1ca7e304fc18a62b5654c7bf4fc4814ba10dcc541b1db5d6c96",
}
SELECTOR_OFFSET = 0x274
SELECTOR_FIELD = "disp_sw_soc_chip_id"


class AuditError(ValueError):
    """Raised when pinned source or binary evidence is incomplete or conflicts."""


def _dwarf_dies(text: str) -> list[dict[str, Any]]:
    header = re.compile(
        r"^\s*<(?P<depth>\d+)><[0-9a-fA-F]+>:\s+Abbrev Number:\s+\d+"
        r"(?:\s+\((?P<tag>DW_TAG_[^)]+)\))?"
    )
    dies: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = header.match(line)
        if match:
            if current is not None:
                dies.append(current)
            current = {
                "depth": int(match.group("depth")),
                "tag": match.group("tag"),
                "attributes": [],
            }
        elif current is not None:
            current["attributes"].append(line)
    if current is not None:
        dies.append(current)
    return dies


def _attribute(die: Mapping[str, Any], name: str) -> str | None:
    pattern = re.compile(rf"\b{re.escape(name)}\s*:\s*(.*)$")
    for line in die["attributes"]:
        match = pattern.search(line)
        if match:
            return match.group(1).strip()
    return None


def _name_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.rsplit(":", 1)[-1].strip()


def _integer_attribute(value: str | None, label: str) -> int:
    if value is None or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
        raise AuditError(f"{label} must be a direct constant in DWARF")
    return int(value, 0) if value.lower().startswith("0x") else int(value, 10)


def parse_nv_state_layouts(dwarf_text: str) -> list[dict[str, Any]]:
    """Return every complete DWARF nv_state_t layout and its direct members."""
    dies = _dwarf_dies(dwarf_text)
    layouts: list[dict[str, Any]] = []
    for index, die in enumerate(dies):
        if die["tag"] != "DW_TAG_structure_type" or _name_value(_attribute(die, "DW_AT_name")) != "nv_state_t":
            continue
        byte_size = _integer_attribute(_attribute(die, "DW_AT_byte_size"), "nv_state_t byte size")
        members: dict[str, int] = {}
        child_depth = die["depth"] + 1
        for child in dies[index + 1 :]:
            if child["depth"] <= die["depth"]:
                break
            if child["depth"] != child_depth or child["tag"] != "DW_TAG_member":
                continue
            member_name = _name_value(_attribute(child, "DW_AT_name"))
            location = _attribute(child, "DW_AT_data_member_location")
            if member_name and location is not None:
                offset = _integer_attribute(location, f"nv_state_t.{member_name} offset")
                if member_name in members:
                    raise AuditError(f"duplicate direct member {member_name} in nv_state_t")
                members[member_name] = offset
        if not members:
            raise AuditError("nv_state_t DWARF record has no direct member offsets")
        layouts.append({"byte_size": byte_size, "member_offsets": members})
    return layouts


def resolve_nv_state_layout(layouts: list[dict[str, Any]], field: str) -> dict[str, Any]:
    """Require all DWARF copies to agree on the complete structure layout."""
    if not layouts:
        raise AuditError("no complete nv_state_t structure was found in DWARF")
    normalized = {(item["byte_size"], tuple(sorted(item["member_offsets"].items()))) for item in layouts}
    if len(normalized) != 1:
        raise AuditError("conflicting nv_state_t layouts found across compilation units")
    byte_size, members = next(iter(normalized))
    member_offsets = dict(members)
    if field not in member_offsets:
        raise AuditError(f"nv_state_t.{field} has no direct constant DWARF offset")
    return {
        "byte_size": byte_size,
        "member_offsets": member_offsets,
        "copies": len(layouts),
    }


def _line_of(pattern: str, text: str, label: str) -> int:
    compiled = re.compile(pattern, re.MULTILINE | re.DOTALL)
    match = compiled.search(text)
    if not match:
        raise AuditError(f"required source relationship not found: {label}")
    return text.count("\n", 0, match.start()) + 1


def inspect_source_flow(sources: Mapping[str, str]) -> dict[str, Any]:
    """Check the wrapper handoff, PCI zero-allocation path, and SoC setter."""
    required = {"nv.c", "nv-pci.c", "nv-linux.h", "nv-platform.c", "nv.h"}
    missing = required - set(sources)
    if missing:
        raise AuditError(f"missing source text: {', '.join(sorted(missing))}")
    nv_c = sources["nv.c"]
    nv_pci = sources["nv-pci.c"]
    nv_linux = sources["nv-linux.h"]
    nv_platform = sources["nv-platform.c"]
    nv_h = sources["nv.h"]

    parameter_line = _line_of(r"nv_start_device\s*\(\s*nv_state_t\s*\*\s*nv", nv_c, "nv_start_device nv_state_t parameter")
    call_line = _line_of(r"rm_init_adapter\s*\(\s*sp\s*,\s*nv\s*\)", nv_c, "rm_init_adapter(sp, nv)")
    alloc_line = _line_of(r"NV_KZALLOC\s*\(\s*nvl\s*,\s*sizeof\s*\(\s*nv_linux_state_t\s*\)\s*\)", nv_pci, "PCI nv_linux_state_t zero allocation")
    kzalloc_macro_line = _line_of(r"#define\s+NV_KZALLOC[\s\S]{0,240}\bkzalloc\s*\(", nv_linux, "NV_KZALLOC wraps kzalloc")
    state_ptr_line = _line_of(r"nv\s*=\s*NV_STATE_PTR\s*\(\s*nvl\s*\)", nv_pci, "PCI nv_state_t pointer")
    embedding_line = _line_of(r"typedef\s+struct\s+nv_linux_state_s\s*\{\s*nv_state_t\s+nv_state\s*;", nv_linux, "nv_state_t first member")
    macro_line = _line_of(r"#define\s+NV_STATE_PTR\(nvl\)\s*&\(\(\(nv_linux_state_t\s*\*\)\(nvl\)\)->nv_state\)", nv_linux, "NV_STATE_PTR definition")
    field_line = _line_of(r"NvU32\s+disp_sw_soc_chip_id\s*;", nv_h, "nv_state_t selector field declaration")
    setter_line = _line_of(
        r"of_property_read_u32\s*\([^;]*nvidia,disp-sw-soc-chip-id[^;]*&\s*nv->disp_sw_soc_chip_id",
        nv_platform,
        "device-tree SoC selector setter",
    )
    return {
        "rm_init_adapter": {
            "function_parameter_type": "nv_state_t *",
            "parameter_line": parameter_line,
            "call": "rm_init_adapter(sp, nv)",
            "call_line": call_line,
        },
        "pci_state": {
            "allocation": "NV_KZALLOC(nvl, sizeof(nv_linux_state_t))",
            "allocation_line": alloc_line,
            "kzalloc_wrapper_line": kzalloc_macro_line,
            "state_pointer_line": state_ptr_line,
            "first_member_line": embedding_line,
            "NV_STATE_PTR_line": macro_line,
            "initial_value_zero_from_kzalloc": True,
        },
        "selector_field": {
            "type": "NvU32",
            "name": SELECTOR_FIELD,
            "header_line": field_line,
            "platform_setter": "of_property_read_u32(nvidia,disp-sw-soc-chip-id, &nv->disp_sw_soc_chip_id)",
            "platform_setter_line": setter_line,
        },
        "scope": "Source-based inference only: PCI allocation starts zeroed and the named source setter is in the device-tree platform path. Earlier opaque RM calls before this callsite could still mutate the field; no live value was observed.",
    }


def scan_field_references(source_root: Path) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for path in sorted(source_root.rglob("*")):
        if path.suffix not in {".c", ".h"} or path.name.endswith(".orig") or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if SELECTOR_FIELD in line:
                refs.append({"path": str(path.relative_to(source_root)), "line": line_no, "text": line.strip()})
    return refs


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise AuditError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr[-2000:]}")
    return result.stdout


def build_report(module: Path, rm_object: Path, source_root: Path, readelf: str = "readelf", objdump: str = "objdump") -> dict[str, Any]:
    paths = {
        "module": module,
        "rm_object": rm_object,
        "common/inc/nv.h": source_root / "common/inc/nv.h",
        "common/inc/nv-linux.h": source_root / "common/inc/nv-linux.h",
        "nvidia/nv.c": source_root / "nvidia/nv.c",
        "nvidia/nv-pci.c": source_root / "nvidia/nv-pci.c",
        "nvidia/nv-platform.c": source_root / "nvidia/nv-platform.c",
    }
    hashes: dict[str, str] = {}
    for label, path in paths.items():
        if not path.is_file():
            raise AuditError(f"required input is missing: {path}")
        hashes[label] = _sha256(path)
        if hashes[label] != PINNED_HASHES[label]:
            raise AuditError(f"pinned {label} SHA-256 mismatch: {hashes[label]}")

    layout = resolve_nv_state_layout(
        parse_nv_state_layouts(_run([readelf, "--debug-dump=info", str(module)])), SELECTOR_FIELD
    )
    if layout["member_offsets"][SELECTOR_FIELD] != SELECTOR_OFFSET:
        raise AuditError("pinned DWARF field offset does not match proprietary RM +0x274 load")

    disassembly = _run([objdump, "-dr", "--disassemble=rm_init_adapter", str(rm_object)])
    handoff = re.search(r"mov\s+%rsi,%r12", disassembly) and re.search(r"mov\s+%r12,%rdi", disassembly)
    call = re.search(r"R_X86_64_PC32\s+_nv000790rm-0x4", disassembly)
    if not handoff or not call:
        raise AuditError("rm_init_adapter does not contain the pinned RSI→R12→RDI call handoff")
    call_position = call.start()
    if disassembly.find("mov    %r12,%rdi") > call_position:
        raise AuditError("R12-to-RDI handoff appears after _nv000790rm call relocation")
    selector_disassembly = _run([objdump, "-dr", "--disassemble=_nv000790rm", str(rm_object)])
    if not re.search(r"0x274\(%r12\)", selector_disassembly):
        raise AuditError("pinned _nv000790rm does not read input +0x274 from R12")

    source_texts = {
        "nv.c": paths["nvidia/nv.c"].read_text(encoding="utf-8"),
        "nv-pci.c": paths["nvidia/nv-pci.c"].read_text(encoding="utf-8"),
        "nv-linux.h": paths["common/inc/nv-linux.h"].read_text(encoding="utf-8"),
        "nv-platform.c": paths["nvidia/nv-platform.c"].read_text(encoding="utf-8"),
        "nv.h": paths["common/inc/nv.h"].read_text(encoding="utf-8"),
    }
    source_flow = inspect_source_flow(source_texts)
    refs = scan_field_references(source_root)
    setter_refs = [ref for ref in refs if "&nv->disp_sw_soc_chip_id" in ref["text"]]
    if len(setter_refs) != 1 or setter_refs[0]["path"] != "nvidia/nv-platform.c":
        raise AuditError("named selector field writes are not the expected single platform property setter")

    return {
        "schema_version": 1,
        "qualification": "analyzed-statically",
        "branch": "NVIDIA proprietary R580.178.04",
        "selector": {
            "input_offset": "nv_state_t+0x274",
            "source_field": f"nv_state_t.{SELECTOR_FIELD}",
            "source_field_type": "NvU32",
            "dwarf_field_offset": f"0x{layout['member_offsets'][SELECTOR_FIELD]:x}",
            "nv_state_t_size": layout["byte_size"],
            "identical_dwarf_layout_copies": layout["copies"],
            "binary_handoff": "rm_init_adapter RSI -> R12; R12 -> RDI -> _nv000790rm",
            "binary_input_load": "_nv000790rm reads dword R12+0x274",
            "normalized_key_decoder": "tools/r580_descriptor_key.py",
            "architectural_interpretation": "The field name identifies a display SoC software chip ID, not a GPU architecture ID. The normalized descriptor key does not establish a GV100-specific branch.",
        },
        "pci_initialization": {
            "source_flow": source_flow,
            "direct_field_references": refs,
            "direct_named_setter_count": len(setter_refs),
            "pci_allocation_value": 0,
            "rm_callsite_value": None,
            "callsite_value_status": "unknown; source initializes zero but earlier opaque RM calls may write it; not observed on hardware",
        },
        "inputs": {
            label: {"path": str(path), "sha256": hashes[label]}
            for label, path in paths.items()
        },
        "limits": [
            "No live nv_state_t memory was read; the PCI value of the field remains a source-based prediction.",
            "A named source-reference scan does not exclude writes through aliases or opaque binary helpers.",
            "This resolves the wrapper field, not the runtime descriptor callback branch or interrupt semantics.",
        ],
        "next_experiment": "Trace every RM helper called before _nv000790rm for writes to nv_state_t+0x274; if no producer is found, observe the bounded callsite value on the stock V100 guest, then inspect descriptor consumers without treating this field as a GPU-architecture discriminator.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=BASE / "nvidia.ko")
    parser.add_argument("--rm-object", type=Path, default=BASE / "nvidia/nv-kernel.o_binary")
    parser.add_argument("--source-root", type=Path, default=BASE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.module, args.rm_object, args.source_root, args.readelf, args.objdump)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (AuditError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps({"report": str(args.output), "qualification": report["qualification"], "field": report["selector"]["source_field"], "offset": report["selector"]["input_offset"]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
