#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile exact pinned Volta C369 replayable-fault parsing code for CPU vectors.

This extracts only the selected UVM parsing functions into temporary host C
programs. It exercises synthetic packets with NVIDIA's generated field headers;
it does not load a module or prove GPU fault behavior.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_R580_UVM = ROOT / (
    "build/experiments/private-open580-native-default-regression-v1-20261024/"
    "baseline/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
DEFAULT_R595_UVM = ROOT / (
    "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v15-20261028T004147Z/"
    "nvidia-uvm"
)

PINNED_FAULT_SOURCE_SHA256 = "d0b8cfcf715246b49741314e0009b78c798719b634269ee44a75ee12f9874e77"
PINNED_C369_SHA256 = "755c9258db3cbce8f0cc4b1fb76c7ddda8a65c7f184470282edc1b88ed53aa77"
PINNED_VOLTA_FAULT_HEADER_SHA256 = "acef4b2abb4feb8f1935b659f7cbf52e3d02e4786ce176cda4d76dd70f54bc13"
PINNED_R580_PASCAL_FAULT_SOURCE_SHA256 = "a4cafceee01aac86cb2a4a0527729f28ec6cbc17ff34ec7150d5a5fa0dd7df52"
PINNED_R595_PASCAL_FAULT_SOURCE_SHA256 = "ba3cd6e3bfb4972f6e970b307e7b6343e2b4f265842803a1947993331f306050"
PASCAL_FUNCTIONS = (
    "get_fault_buffer_entry",
    "get_fault_buffer_entry_metadata",
    "uvm_hal_pascal_fault_buffer_entry_is_valid",
    "uvm_hal_pascal_fault_buffer_entry_clear_valid",
)
PASCAL_FUNCTION_SIGNATURES = (
    ("get_fault_buffer_entry",
     "static NvU32 *get_fault_buffer_entry(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
    ("get_fault_buffer_entry_metadata",
     "static UvmFaultMetadataPacket *get_fault_buffer_entry_metadata(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
    ("uvm_hal_pascal_fault_buffer_entry_is_valid",
     "bool uvm_hal_pascal_fault_buffer_entry_is_valid(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
    ("uvm_hal_pascal_fault_buffer_entry_clear_valid",
     "void uvm_hal_pascal_fault_buffer_entry_clear_valid(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
)
GV100_FAULT_BUFFER_CALLBACKS = {
    "entry_is_valid": "uvm_hal_pascal_fault_buffer_entry_is_valid",
    "entry_clear_valid": "uvm_hal_pascal_fault_buffer_entry_clear_valid",
    "read_put": "uvm_hal_volta_fault_buffer_read_put",
    "read_get": "uvm_hal_volta_fault_buffer_read_get",
    "write_get": "uvm_hal_volta_fault_buffer_write_get",
    "parse_replayable_entry": "uvm_hal_volta_fault_buffer_parse_replayable_entry",
    "parse_non_replayable_entry": "uvm_hal_volta_fault_buffer_parse_non_replayable_entry",
    "get_fault_type": "uvm_hal_volta_fault_buffer_get_fault_type",
}

UVM_ENUMS = (
    "uvm_aperture_t",
    "uvm_fault_access_type_t",
    "uvm_fault_type_t",
    "uvm_fault_client_type_t",
    "uvm_mmu_engine_type_t",
)

FUNCTIONS = (
    ("get_fault_access_type", "static uvm_fault_access_type_t get_fault_access_type(const NvU32 *fault_entry)"),
    ("is_fault_address_virtual", "static bool is_fault_address_virtual(const NvU32 *fault_entry)"),
    ("uvm_hal_volta_fault_buffer_get_fault_type",
     "uvm_fault_type_t uvm_hal_volta_fault_buffer_get_fault_type(const NvU32 *fault_entry)"),
    ("get_fault_client_type", "static uvm_fault_client_type_t get_fault_client_type(const NvU32 *fault_entry)"),
    ("get_fault_inst_aperture", "static uvm_aperture_t get_fault_inst_aperture(const NvU32 *fault_entry)"),
    ("get_fault_buffer_entry",
     "static NvU32 *get_fault_buffer_entry(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
    ("get_fault_buffer_entry_metadata",
     "static UvmFaultMetadataPacket *get_fault_buffer_entry_metadata(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
    ("client_id_ce", "static bool client_id_ce(NvU16 client_id)"),
    ("client_id_host", "static bool client_id_host(NvU16 client_id)"),
    ("uvm_hal_volta_fault_buffer_get_mmu_engine_type",
     "uvm_mmu_engine_type_t uvm_hal_volta_fault_buffer_get_mmu_engine_type(NvU16 mmu_engine_id, uvm_fault_client_type_t client_type, NvU16 client_id)"),
    ("uvm_hal_volta_fault_buffer_get_ve_id",
     "NvU8 uvm_hal_volta_fault_buffer_get_ve_id(NvU16 mmu_engine_id, uvm_mmu_engine_type_t mmu_engine_type)"),
    ("parse_fault_entry_common",
     "static void parse_fault_entry_common(uvm_parent_gpu_t *parent_gpu, NvU32 *fault_entry, uvm_fault_buffer_entry_t *buffer_entry)"),
    ("uvm_hal_volta_fault_buffer_parse_replayable_entry",
     "NV_STATUS uvm_hal_volta_fault_buffer_parse_replayable_entry(uvm_parent_gpu_t *parent_gpu, NvU32 index, uvm_fault_buffer_entry_t *buffer_entry)"),
    ("uvm_hal_volta_fault_buffer_parse_non_replayable_entry",
     "void uvm_hal_volta_fault_buffer_parse_non_replayable_entry(uvm_parent_gpu_t *parent_gpu, void *fault_packet, uvm_fault_buffer_entry_t *buffer_entry)"),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _mask_comments(source: str) -> str:
    """Blank C comments without moving offsets needed for source extraction."""
    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return re.sub(r"/\*.*?\*/|//[^\n]*", blank, source, flags=re.DOTALL)


def _typedef_enum(source: str, name: str) -> str:
    masked = _mask_comments(source)
    for match in re.finditer(r"typedef\s+enum\s*\{", masked):
        opening = match.end() - 1
        depth = 0
        for offset in range(opening, len(masked)):
            if masked[offset] == "{":
                depth += 1
            elif masked[offset] == "}":
                depth -= 1
                if depth == 0:
                    end = offset + 1
                    trailer = re.match(r"\s*" + re.escape(name) + r"\s*;", masked[end:end + 100])
                    if trailer is not None:
                        return source[match.start():end + trailer.end()]
                    break
    raise ValueError(f"pinned enum missing: {name}")


def _enum_contract(source: str, name: str) -> str:
    declaration = _mask_comments(_typedef_enum(source, name))
    match = re.search(r"\{(.*?)\}\s*" + re.escape(name) + r"\s*;", declaration, re.DOTALL)
    if match is None:
        raise ValueError(f"malformed enum declaration: {name}")
    return ",".join("".join(row.split()) for row in match.group(1).split(",") if row.strip())


def _typedef_struct_body(source: str, name: str) -> str:
    masked = _mask_comments(source)
    for match in re.finditer(r"typedef\s+struct\s*\{", masked):
        opening = match.end() - 1
        depth = 0
        for offset in range(opening, len(masked)):
            if masked[offset] == "{":
                depth += 1
            elif masked[offset] == "}":
                depth -= 1
                if depth == 0:
                    trailer = masked[offset + 1:offset + 180]
                    if re.match(r"\s*" + re.escape(name) + r"\s*;", trailer):
                        return source[opening + 1:offset]
                    break
    raise ValueError(f"pinned typedef struct missing: {name}")


def _tagged_union(source: str, tag: str, alias: str) -> str:
    masked = _mask_comments(source)
    match = re.search(r"typedef\s+union\s+" + re.escape(tag) + r"\s*\{", masked)
    if match is None:
        raise ValueError(f"pinned union missing: {tag}")
    opening = match.end() - 1
    depth = 0
    for offset in range(opening, len(masked)):
        if masked[offset] == "{":
            depth += 1
        elif masked[offset] == "}":
            depth -= 1
            if depth == 0:
                end = offset + 1
                trailer = masked[end:end + 120]
                if re.match(r"\s*" + re.escape(alias) + r"\s*;", trailer):
                    return source[match.start():end] + f" {alias};"
                break
    raise ValueError(f"malformed pinned union: {tag}")


def _extract_function(source: str, name: str) -> str:
    masked = _mask_comments(source)
    definition = (r"^[ \t]*(?:static[ \t]+)?[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*"
                  r"[ \t]+\*?[ \t]*" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{")
    matches = list(re.finditer(definition, masked, re.MULTILINE | re.DOTALL))
    if len(matches) != 1:
        raise ValueError(f"expected one source definition for {name}, found {len(matches)}")
    opening = matches[0].end() - 1
    depth = 0
    for offset in range(opening, len(masked)):
        if masked[offset] == "{":
            depth += 1
        elif masked[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:offset]
    raise ValueError(f"unterminated function: {name}")


def _required_define(source: str, name: str, expected_value: str) -> str:
    rows = re.findall(r"^[ \t]*#[ \t]*define[ \t]+" + re.escape(name) + r"[ \t]+([^\n]+)",
                      _mask_comments(source), re.MULTILINE)
    values = [" ".join(row.split()) for row in rows]
    if values != [expected_value]:
        raise ValueError(f"pinned macro changed: {name}: {values!r}")
    return f"#define {name} {expected_value}"


def _define_value(source: str, name: str) -> str:
    rows = re.findall(r"^[ \t]*#[ \t]*define[ \t]+" + re.escape(name) + r"[ \t]+([^\n]+)",
                      _mask_comments(source), re.MULTILINE)
    values = [" ".join(row.split()) for row in rows]
    if len(values) != 1:
        raise ValueError(f"expected one generated-header definition for {name}, found {len(values)}")
    return values[0]


def _required_source(root: Path, relative: str) -> Path:
    path = (root / relative).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"not a source file: {path}")
    return path


def _normalized_function_hash(source: str, name: str) -> str:
    body = _extract_function(source, name)
    normalized = "".join(_mask_comments(body).split()).encode("utf-8")
    return sha256_bytes(normalized)


def _fault_buffer_table_rows(source: str) -> dict[str, dict[str, object]]:
    masked = _mask_comments(source)
    declaration = re.search(
        r"static\s+uvm_hal_class_ops_t\s+fault_buffer_table\s*\[\]\s*=\s*",
        masked,
    )
    if declaration is None:
        raise ValueError("pinned HAL fault_buffer_table declaration missing")
    array_open = masked.find("{", declaration.end())
    if array_open < 0:
        raise ValueError("pinned HAL fault_buffer_table initializer missing")

    rows: dict[str, dict[str, object]] = {}
    cursor = array_open + 1
    while cursor < len(masked):
        while cursor < len(masked) and (masked[cursor].isspace() or masked[cursor] == ","):
            cursor += 1
        if cursor >= len(masked) or masked[cursor] == "}":
            break
        if masked[cursor] != "{":
            raise ValueError("unexpected token in fault_buffer_table initializer")
        row_open = cursor
        depth = 0
        while cursor < len(masked):
            if masked[cursor] == "{":
                depth += 1
            elif masked[cursor] == "}":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        if depth != 0:
            raise ValueError("unterminated fault_buffer_table row")
        row = masked[row_open:cursor]
        id_match = re.search(r"\.id\s*=\s*([^,\n]+)", row)
        if id_match is None:
            continue
        id_arch = re.search(r"ARCHITECTURE_([A-Z0-9]+)", id_match.group(1))
        if id_arch is None:
            continue
        arch = id_arch.group(1)
        parent_match = re.search(r"\.parent_id\s*=\s*([^,\n]+)", row)
        parent_arch = None
        if parent_match is not None:
            parent_arch_match = re.search(r"ARCHITECTURE_([A-Z0-9]+)", parent_match.group(1))
            if parent_arch_match is not None:
                parent_arch = parent_arch_match.group(1)
        callback_block = re.search(r"\.u\.fault_buffer_ops\s*=\s*\{(.*?)\n\s*\}", row, re.DOTALL)
        callbacks: dict[str, str] = {}
        if callback_block is not None:
            callbacks = {
                field: function
                for field, function in re.findall(
                    r"\.(entry_is_valid|entry_clear_valid|read_put|read_get|write_get|parse_replayable_entry|"
                    r"parse_non_replayable_entry|get_fault_type)\s*=\s*([A-Za-z_]\w*)",
                    callback_block.group(1),
                )
            }
        rows[arch] = {"parent": parent_arch, "callbacks": callbacks}
    if not rows:
        raise ValueError("no rows found in pinned HAL fault_buffer_table")
    return rows


def _resolve_gv100_fault_buffer_callbacks(source: str) -> tuple[dict[str, str], dict[str, str]]:
    rows = _fault_buffer_table_rows(source)
    if "GV100" not in rows:
        raise ValueError("GV100 fault-buffer HAL row missing")

    selected: dict[str, str] = {}
    origins: dict[str, str] = {}
    for field in GV100_FAULT_BUFFER_CALLBACKS:
        arch = "GV100"
        visited: set[str] = set()
        while arch is not None:
            if arch in visited:
                raise ValueError(f"cycle in fault-buffer HAL inheritance for {field}")
            visited.add(arch)
            row = rows.get(arch)
            if row is None:
                break
            callback = row["callbacks"].get(field)
            if callback is not None:
                selected[field] = callback
                origins[field] = arch
                break
            arch = row["parent"]
        if field not in selected:
            raise ValueError(f"GV100 fault-buffer HAL callback unresolved: {field}")
        if selected[field] != GV100_FAULT_BUFFER_CALLBACKS[field]:
            raise ValueError(
                f"unexpected GV100 {field} callback: {selected[field]}"
            )
    return selected, origins


def _validate_source_pair(r580_uvm: Path, r595_uvm: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    hal_text: dict[str, str] = {}
    expected_pascal_hashes = {
        "r580": PINNED_R580_PASCAL_FAULT_SOURCE_SHA256,
        "r595": PINNED_R595_PASCAL_FAULT_SOURCE_SHA256,
    }
    for label, root in (("r580", r580_uvm), ("r595", r595_uvm)):
        files = {
            "fault_source": _required_source(root, "uvm_volta_fault_buffer.c"),
            "pascal_fault_source": _required_source(root, "uvm_pascal_fault_buffer.c"),
            "hal_types": _required_source(root, "uvm_hal_types.h"),
            "hal_source": _required_source(root, "uvm_hal.c"),
            "common_inc_nvtypes": _required_source(root.parent / "common/inc", "nvtypes.h"),
            "common_inc_nvstatus": _required_source(root.parent / "common/inc", "nvstatus.h"),
            "common_inc_nvmisc": _required_source(root.parent / "common/inc", "nvmisc.h"),
            "common_inc_nv_uvm_types": _required_source(root.parent / "common/inc", "nv_uvm_types.h"),
            "c369_header": _required_source(root, "clc369.h"),
            "clb069_header": _required_source(root, "clb069.h"),
            "volta_fault_header": _required_source(root, "hwref/volta/gv100/dev_fault.h"),
        }
        hashes = {key: sha256_file(path) for key, path in files.items()}
        if hashes["fault_source"] != PINNED_FAULT_SOURCE_SHA256:
            raise ValueError(f"{label} fault-parser source differs from pinned R580 snapshot")
        if hashes["c369_header"] != PINNED_C369_SHA256:
            raise ValueError(f"{label} C369 packet header differs from pinned source")
        if hashes["volta_fault_header"] != PINNED_VOLTA_FAULT_HEADER_SHA256:
            raise ValueError(f"{label} GV100 fault header differs from pinned source")
        if hashes["pascal_fault_source"] != expected_pascal_hashes[label]:
            raise ValueError(f"{label} Pascal fault-buffer source differs from pinned snapshot")
        pascal_source = files["pascal_fault_source"].read_text(encoding="utf-8")
        hal_source = files["hal_source"].read_text(encoding="utf-8")
        c369_header = files["c369_header"].read_text(encoding="utf-8")
        clb069_header = files["clb069_header"].read_text(encoding="utf-8")
        packet_contract = {
            "c369_packet_size_bytes": _define_value(c369_header, "NVC369_BUF_SIZE"),
            "b069_packet_size_bytes": _define_value(clb069_header, "NVB069_FAULT_BUF_SIZE"),
            "c369_valid_field": _define_value(c369_header, "NVC369_BUF_ENTRY_VALID"),
            "b069_valid_field": _define_value(clb069_header, "NVB069_FAULT_BUF_ENTRY_VALID"),
        }
        if packet_contract["c369_packet_size_bytes"] != packet_contract["b069_packet_size_bytes"]:
            raise ValueError(f"{label} B069/C369 packet sizes differ")
        if packet_contract["c369_valid_field"] != packet_contract["b069_valid_field"]:
            raise ValueError(f"{label} B069/C369 VALID field encodings differ")
        callbacks, origins = _resolve_gv100_fault_buffer_callbacks(hal_source)
        accessor_hashes = {
            name: _normalized_function_hash(pascal_source, name)
            for name in PASCAL_FUNCTIONS[:2]
        }
        callback_hashes = {
            name: _normalized_function_hash(pascal_source, name)
            for name in PASCAL_FUNCTIONS[2:]
        }
        records[label] = {
            "root": str(root),
            **hashes,
            "gv100_fault_buffer_callbacks": callbacks,
            "gv100_fault_buffer_callback_origins": origins,
            "pascal_callback_body_sha256": callback_hashes,
            "pascal_entry_accessor_body_sha256": accessor_hashes,
            "pascal_c369_packet_contract": packet_contract,
        }
        hal_text[label] = files["hal_types"].read_text(encoding="utf-8")

    if records["r580"]["fault_source"] != records["r595"]["fault_source"]:
        raise ValueError("R580 and R595 fault parser source bytes differ")
    if records["r580"]["pascal_callback_body_sha256"] != records["r595"]["pascal_callback_body_sha256"]:
        raise ValueError("R580/R595 selected Pascal callback bodies differ")
    if records["r580"]["pascal_entry_accessor_body_sha256"] != records["r595"]["pascal_entry_accessor_body_sha256"]:
        raise ValueError("R580/R595 selected Pascal entry-accessor bodies differ")
    if records["r580"]["clb069_header"] != records["r595"]["clb069_header"]:
        raise ValueError("R580/R595 Pascal C369-compatible field header differs")
    if records["r580"]["pascal_c369_packet_contract"] != records["r595"]["pascal_c369_packet_contract"]:
        raise ValueError("R580/R595 Pascal/C369 packet contract differs")
    for label in ("r580", "r595"):
        if records[label]["gv100_fault_buffer_callbacks"] != GV100_FAULT_BUFFER_CALLBACKS:
            raise ValueError(f"{label} GV100 HAL callback selection changed")
    for enum_name in UVM_ENUMS:
        if _enum_contract(hal_text["r580"], enum_name) != _enum_contract(hal_text["r595"], enum_name):
            raise ValueError(f"R580/R595 UVM enum contract differs: {enum_name}")
    for struct_name in ("uvm_gpu_phys_address_t", "uvm_fault_source_t"):
        r580_body = "".join(_typedef_struct_body(hal_text["r580"], struct_name).split())
        r595_body = "".join(_typedef_struct_body(hal_text["r595"], struct_name).split())
        if r580_body != r595_body:
            raise ValueError(f"R580/R595 UVM field contract differs: {struct_name}")
    return records


def _c_prefix(uvm_root: Path) -> str:
    common = (uvm_root.parent / "common/inc").resolve(strict=True)
    hal = (uvm_root / "uvm_hal_types.h").read_text(encoding="utf-8")
    common_types = (common / "nv_uvm_types.h").read_text(encoding="utf-8")
    pascal = (uvm_root / "uvm_pascal_fault_buffer.c").read_text(encoding="utf-8")
    enums = "\n".join(_typedef_enum(hal, name) for name in UVM_ENUMS)
    phys_address = _typedef_struct_body(hal, "uvm_gpu_phys_address_t")
    fault_source = _typedef_struct_body(hal, "uvm_fault_source_t")
    pascal_fault_entry = _typedef_struct_body(pascal, "fault_buffer_entry_b069_t")
    metadata_union = _tagged_union(common_types, "UvmFaultMetadataPacket_tag", "UvmFaultMetadataPacket")
    crypt_tag = _required_define(common_types, "UVM_CSL_CRYPT_AUTH_TAG_SIZE_BYTES", "16")
    packet_size = _required_define(hal, "UVM_GPU_MMU_MAX_FAULT_PACKET_SIZE", "32")

    return r'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nvtypes.h"
#include "nvstatus.h"
#include "nvmisc.h"
#include "hwref/volta/gv100/dev_fault.h"
#include "clc369.h"
#include "clb069.h"

#define READ_HWVALUE_MW(v, d, r, f) DRF_VAL_MW(d, _##r, _##f, (v))
#define WRITE_HWCONST_MW(v, d, r, f, c) FLD_ASSIGN_MW(NV##d##_##r##_##f, DRF_DEF_MW(d,_##r,_##f,_##c), v)
#define HWSIZE_MW(d, r, f) DRF_SIZE_MW(NV##d##_##r##_##f)
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "pinned UVM compile-time assertion")
#define UVM_ASSERT(condition) assert(condition)
#define UVM_ASSERT_MSG(condition, ...) assert(condition)
#define order_base_2(value) ((value) <= 1 ? 0 : (32 - __builtin_clz((unsigned)(value) - 1)))
#define MAX_SUBCONTEXTS 64
''' + crypt_tag + "\n" + packet_size + "\n" + enums + "\n" + f'''typedef struct {{
{phys_address}
}} uvm_gpu_phys_address_t;

typedef struct {{
{fault_source}
}} uvm_fault_source_t;

typedef struct {{
{pascal_fault_entry}
}} fault_buffer_entry_b069_t;

_Static_assert(NVB069_FAULT_BUF_SIZE == NVC369_BUF_SIZE, "Pascal/Volta fault-buffer size mismatch");
_Static_assert(sizeof(fault_buffer_entry_b069_t) == NVC369_BUF_SIZE, "Pascal fault-entry layout mismatch");
_Static_assert(DRF_WORD_MW(NVB069_FAULT_BUF_ENTRY_VALID) == DRF_WORD_MW(NVC369_BUF_ENTRY_VALID), "valid-bit word mismatch");
_Static_assert(DRF_SHIFT_MW(NVB069_FAULT_BUF_ENTRY_VALID) == DRF_SHIFT_MW(NVC369_BUF_ENTRY_VALID), "valid-bit shift mismatch");
_Static_assert(DRF_SIZE_MW(NVB069_FAULT_BUF_ENTRY_VALID) == DRF_SIZE_MW(NVC369_BUF_ENTRY_VALID), "valid-bit width mismatch");

typedef struct {{
    NvU64 fault_address;
    NvU64 timestamp;
    uvm_gpu_phys_address_t instance_ptr;
    uvm_fault_source_t fault_source;
    uvm_fault_type_t fault_type : order_base_2(UVM_FAULT_TYPE_COUNT) + 1;
    uvm_fault_access_type_t fault_access_type : order_base_2(UVM_FAULT_ACCESS_TYPE_COUNT) + 1;
    bool is_replayable : 1;
    bool is_virtual : 1;
    bool in_protected_mode : 1;
}} uvm_fault_buffer_entry_t;

{metadata_union}

typedef struct {{
{_typedef_struct_body((uvm_root / 'uvm_volta_fault_buffer.c').read_text(encoding='utf-8'), 'fault_buffer_entry_c369_t')}
}} fault_buffer_entry_c369_t;

typedef struct uvm_parent_gpu_struct uvm_parent_gpu_t;

typedef struct {{
    bool (*entry_is_valid)(uvm_parent_gpu_t *, NvU32);
    void (*entry_clear_valid)(uvm_parent_gpu_t *, NvU32);
    uvm_fault_type_t (*get_fault_type)(const NvU32 *);
    uvm_mmu_engine_type_t (*get_mmu_engine_type)(NvU16, uvm_fault_client_type_t, NvU16);
    NvU8 (*get_ve_id)(NvU16, uvm_mmu_engine_type_t);
}} uvm_fault_buffer_hal_t;

typedef struct {{
    NvU16 (*mmu_client_id_to_utlb_id)(NvU16);
}} uvm_arch_hal_t;

typedef struct {{
    NvU32 max_faults;
    NvU32 utlb_count;
}} uvm_fault_buffer_replayable_t;

typedef struct {{
    void *bufferAddress;
    UvmFaultMetadataPacket *bufferMetadata;
}} uvm_fault_buffer_rm_replayable_t;

typedef struct {{
    uvm_fault_buffer_replayable_t replayable;
    struct {{ uvm_fault_buffer_rm_replayable_t replayable; }} rm_info;
}} uvm_fault_buffer_t;

struct uvm_parent_gpu_struct {{
    uvm_fault_buffer_hal_t *fault_buffer_hal;
    uvm_arch_hal_t *arch_hal;
    uvm_fault_buffer_t fault_buffer;
    NvU32 utlb_per_gpc_count;
}};

static struct {{ bool conf_computing_enabled; }} g_uvm_global;
static NvU32 test_valid_calls;
static NvU32 test_clear_calls;
static NvU32 test_client_map_calls;
static NvU32 test_decrypt_calls;
static NvU32 test_fatal_calls;
static NvU32 test_assertion_count;
static NvU32 test_failures;

static NvU64 uvm_parent_gpu_canonical_address(uvm_parent_gpu_t *parent_gpu, NvU64 address)
{{
    (void)parent_gpu;
    return address;
}}

static NV_STATUS uvm_conf_computing_fault_decrypt(uvm_parent_gpu_t *parent_gpu,
                                                  void *destination,
                                                  NvU32 *source,
                                                  NvU8 *auth_tag,
                                                  NvBool valid)
{{
    (void)parent_gpu; (void)destination; (void)source; (void)auth_tag; (void)valid;
    ++test_decrypt_calls;
    abort();
}}

static void uvm_global_set_fatal_error(NV_STATUS status)
{{
    (void)status;
    ++test_fatal_calls;
}}
'''


def build_harness(uvm_root: Path) -> str:
    source = (uvm_root / "uvm_volta_fault_buffer.c").read_text(encoding="utf-8")
    pascal_source = (uvm_root / "uvm_pascal_fault_buffer.c").read_text(encoding="utf-8")
    chunks = [_c_prefix(uvm_root)]
    for name, signature in FUNCTIONS:
        chunks.append(signature + "\n{\n" + _extract_function(source, name) + "\n}\n")
    chunks.append("#define get_fault_buffer_entry get_pascal_fault_buffer_entry\n"
                  "#define get_fault_buffer_entry_metadata get_pascal_fault_buffer_entry_metadata\n")
    for name, signature in PASCAL_FUNCTION_SIGNATURES:
        chunks.append(signature + "\n{\n" + _extract_function(pascal_source, name) + "\n}\n")
    chunks.append("#undef get_fault_buffer_entry\n#undef get_fault_buffer_entry_metadata\n")
    chunks.append(_C_VECTOR_SUFFIX)
    return "\n".join(chunks)


_C_VECTOR_SUFFIX = r''' 
static NvU16 test_mmu_client_id_to_utlb_id(NvU16 client_id)
{
    ++test_client_map_calls;
    return client_id % 4;
}

static bool test_entry_is_valid(uvm_parent_gpu_t *parent_gpu, NvU32 index)
{
    ++test_valid_calls;
    return uvm_hal_pascal_fault_buffer_entry_is_valid(parent_gpu, index);
}

static void test_entry_clear_valid(uvm_parent_gpu_t *parent_gpu, NvU32 index)
{
    ++test_clear_calls;
    uvm_hal_pascal_fault_buffer_entry_clear_valid(parent_gpu, index);
}

typedef struct {
    const char *name;
    NvU64 instance_page;
    NvU64 fault_page;
    NvU64 timestamp;
    NvU32 fault_type;
    NvU32 access_type;
    NvU32 inst_aperture;
    NvU32 client_type;
    NvU16 client_id;
    NvU16 engine_id;
    NvU8 gpc_id;
    bool protected_mode;
    bool replayable;
    bool replayable_enabled;
    bool valid;
    uvm_fault_type_t expected_fault_type;
    uvm_fault_access_type_t expected_access_type;
    uvm_aperture_t expected_aperture;
    bool expected_virtual;
} packet_case_t;

typedef struct { NvU32 value; uvm_fault_access_type_t access; bool is_virtual; const char *name; } access_case_t;
typedef struct { NvU32 value; uvm_fault_type_t type; const char *name; } fault_case_t;

static void make_packet(NvU32 packet[8], const packet_case_t *test_case)
{
    memset(packet, 0, 8 * sizeof(*packet));
    packet[0] = DRF_NUM_MW(C369, _BUF_ENTRY, _INST_APERTURE, test_case->inst_aperture) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _INST_LO, test_case->instance_page & 0xFFFFF);
    packet[1] = DRF_NUM_MW(C369, _BUF_ENTRY, _INST_HI, test_case->instance_page >> 20);
    packet[2] = DRF_NUM_MW(C369, _BUF_ENTRY, _ADDR_LO, test_case->fault_page & 0xFFFFF);
    packet[3] = DRF_NUM_MW(C369, _BUF_ENTRY, _ADDR_HI, test_case->fault_page >> 20);
    packet[4] = DRF_NUM_MW(C369, _BUF_ENTRY, _TIMESTAMP_LO, test_case->timestamp & 0xFFFFFFFFULL);
    packet[5] = DRF_NUM_MW(C369, _BUF_ENTRY, _TIMESTAMP_HI, test_case->timestamp >> 32);
    packet[6] = DRF_NUM_MW(C369, _BUF_ENTRY, _ENGINE_ID, test_case->engine_id);
    packet[7] = DRF_NUM_MW(C369, _BUF_ENTRY, _FAULT_TYPE, test_case->fault_type) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _REPLAYABLE_FAULT, test_case->replayable) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _CLIENT, test_case->client_id) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _ACCESS_TYPE, test_case->access_type) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _MMU_CLIENT_TYPE, test_case->client_type) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _GPC_ID, test_case->gpc_id) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _PROTECTED_MODE, test_case->protected_mode) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _REPLAYABLE_FAULT_EN, test_case->replayable_enabled) |
                DRF_NUM_MW(C369, _BUF_ENTRY, _VALID, test_case->valid);
}

static void check_u64(const char *name, NvU64 actual, NvU64 expected)
{
    ++test_assertion_count;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s actual=0x%llx expected=0x%llx\n", name,
                (unsigned long long)actual, (unsigned long long)expected);
        ++test_failures;
    }
}

static void run_confidential_callback_cases(void)
{
    NvU32 packet[8] = {0};
    UvmFaultMetadataPacket metadata = {0};
    uvm_parent_gpu_t parent_gpu = {
        .fault_buffer = {
            .replayable = { .max_faults = 1 },
            .rm_info = { .replayable = {
                .bufferAddress = packet,
                .bufferMetadata = &metadata,
            }},
        },
    };

    g_uvm_global.conf_computing_enabled = true;
    test_valid_calls = test_clear_calls = 0;

    /* Metadata-valid must be authoritative even when the packet bit is clear. */
    metadata.valid = NV_TRUE;
    check_u64("cc-metadata-valid-read", test_entry_is_valid(&parent_gpu, 0), NV_TRUE);
    check_u64("cc-packet-valid-stays-clear", READ_HWVALUE_MW(packet, C369, BUF_ENTRY, VALID), 0);
    test_entry_clear_valid(&parent_gpu, 0);
    check_u64("cc-metadata-valid-cleared", metadata.valid, NV_FALSE);
    check_u64("cc-packet-valid-remains-clear", READ_HWVALUE_MW(packet, C369, BUF_ENTRY, VALID), 0);
    check_u64("cc-valid-callback-count", test_valid_calls, 1);
    check_u64("cc-clear-callback-count", test_clear_calls, 1);

    /* Conversely, a set packet bit cannot override invalid CC metadata. */
    test_valid_calls = test_clear_calls = 0;
    metadata.valid = NV_FALSE;
    packet[7] = DRF_DEF_MW(C369, _BUF_ENTRY, _VALID, _TRUE);
    check_u64("cc-invalid-metadata-read", test_entry_is_valid(&parent_gpu, 0), NV_FALSE);
    check_u64("cc-encrypted-packet-bit-preserved", READ_HWVALUE_MW(packet, C369, BUF_ENTRY, VALID), 1);
    test_entry_clear_valid(&parent_gpu, 0);
    check_u64("cc-invalid-metadata-stays-clear", metadata.valid, NV_FALSE);
    check_u64("cc-packet-bit-not-cleared-by-metadata-path",
              READ_HWVALUE_MW(packet, C369, BUF_ENTRY, VALID), 1);
    check_u64("cc-invalid-valid-callback-count", test_valid_calls, 1);
    check_u64("cc-invalid-clear-callback-count", test_clear_calls, 1);

    g_uvm_global.conf_computing_enabled = false;
    printf("callback_case=confidential-metadata-valid cases=2 checks=12\n");
}

static int run_packet_case(const packet_case_t *test_case, NvU32 fault_index,
                           bool non_replayable_packet)
{
    NvU32 packet[8];
    uvm_fault_buffer_entry_t parsed = {0};
    uvm_fault_buffer_hal_t fault_hal = {
        .entry_is_valid = test_entry_is_valid,
        .entry_clear_valid = test_entry_clear_valid,
        .get_fault_type = uvm_hal_volta_fault_buffer_get_fault_type,
        .get_mmu_engine_type = uvm_hal_volta_fault_buffer_get_mmu_engine_type,
        .get_ve_id = uvm_hal_volta_fault_buffer_get_ve_id,
    };
    uvm_arch_hal_t arch_hal = { .mmu_client_id_to_utlb_id = test_mmu_client_id_to_utlb_id };
    uvm_parent_gpu_t parent_gpu = {
        .fault_buffer_hal = &fault_hal,
        .arch_hal = &arch_hal,
        .fault_buffer = {
            .replayable = { .max_faults = 1, .utlb_count = 32 },
            .rm_info = { .replayable = { .bufferAddress = packet, .bufferMetadata = NULL } },
        },
        .utlb_per_gpc_count = 4,
    };
    NV_STATUS status;
    NvU64 expected_instance = test_case->instance_page << 12;
    NvU64 expected_fault = test_case->fault_page << 12;
    NvU64 expected_utlb = 0;
    NvU64 expected_ve = 0;
    bool is_gpc = test_case->client_type == NV_PFAULT_MMU_CLIENT_TYPE_GPC;

    test_valid_calls = test_clear_calls = test_client_map_calls = 0;
    test_decrypt_calls = test_fatal_calls = 0;
    make_packet(packet, test_case);
    if (non_replayable_packet) {
        uvm_hal_volta_fault_buffer_parse_non_replayable_entry(&parent_gpu, packet, &parsed);
        status = NV_OK;
    }
    else {
        status = uvm_hal_volta_fault_buffer_parse_replayable_entry(&parent_gpu, fault_index, &parsed);
    }

    if (is_gpc) {
        expected_utlb = (NvU64)test_case->gpc_id * parent_gpu.utlb_per_gpc_count +
                        (test_case->client_id % 4);
        expected_ve = test_case->engine_id - NV_PFAULT_MMU_ENG_ID_GRAPHICS;
    }
    check_u64("status", (NvU64)status, NV_OK);
    check_u64("instance-address", parsed.instance_ptr.address, expected_instance);
    check_u64("fault-address", parsed.fault_address, expected_fault);
    check_u64("timestamp", parsed.timestamp, test_case->timestamp);
    check_u64("instance-aperture", parsed.instance_ptr.aperture, test_case->expected_aperture);
    check_u64("fault-type", parsed.fault_type, test_case->expected_fault_type);
    check_u64("access-type", parsed.fault_access_type, test_case->expected_access_type);
    check_u64("client-type", parsed.fault_source.client_type, test_case->client_type);
    check_u64("client-id", parsed.fault_source.client_id, test_case->client_id);
    check_u64("engine-id", parsed.fault_source.mmu_engine_id, test_case->engine_id);
    check_u64("engine-type", parsed.fault_source.mmu_engine_type,
              is_gpc ? UVM_MMU_ENGINE_TYPE_GRAPHICS : UVM_MMU_ENGINE_TYPE_HOST);
    check_u64("utlb-id", parsed.fault_source.utlb_id, expected_utlb);
    check_u64("ve-id", parsed.fault_source.ve_id, expected_ve);
    check_u64("replayable", parsed.is_replayable, test_case->replayable);
    check_u64("virtual", parsed.is_virtual, test_case->expected_virtual);
    check_u64("protected", parsed.in_protected_mode, test_case->protected_mode);
    check_u64("valid-after-parse", READ_HWVALUE_MW(packet, C369, BUF_ENTRY, VALID),
              non_replayable_packet ? test_case->valid : 0);
    check_u64("entry-valid-calls", test_valid_calls, non_replayable_packet ? 0 : 1);
    check_u64("entry-clear-calls", test_clear_calls, non_replayable_packet ? 0 : 1);
    check_u64("client-map-calls", test_client_map_calls, is_gpc ? 1 : 0);
    check_u64("unexpected-decrypt-calls", test_decrypt_calls, 0);
    check_u64("unexpected-fatal-calls", test_fatal_calls, 0);

    printf("vector=%s addr=0x%llx inst=0x%llx ts=0x%llx fault=%u access=%u aperture=%u client=%u engine=%u utlb=%llu ve=%llu checks=22\n",
           test_case->name,
           (unsigned long long)parsed.fault_address,
           (unsigned long long)parsed.instance_ptr.address,
           (unsigned long long)parsed.timestamp,
           (unsigned)parsed.fault_type,
           (unsigned)parsed.fault_access_type,
           (unsigned)parsed.instance_ptr.aperture,
           (unsigned)parsed.fault_source.client_type,
           (unsigned)parsed.fault_source.mmu_engine_type,
           (unsigned long long)parsed.fault_source.utlb_id,
           (unsigned long long)parsed.fault_source.ve_id);
    return test_failures == 0 ? 0 : 1;
}

static const access_case_t access_cases[] = {
    { NV_PFAULT_ACCESS_TYPE_VIRT_READ, UVM_FAULT_ACCESS_TYPE_READ, true, "virt-read" },
    { NV_PFAULT_ACCESS_TYPE_VIRT_WRITE, UVM_FAULT_ACCESS_TYPE_WRITE, true, "virt-write" },
    { NV_PFAULT_ACCESS_TYPE_VIRT_ATOMIC_STRONG, UVM_FAULT_ACCESS_TYPE_ATOMIC_STRONG, true, "virt-atomic-strong" },
    { NV_PFAULT_ACCESS_TYPE_VIRT_PREFETCH, UVM_FAULT_ACCESS_TYPE_PREFETCH, true, "virt-prefetch" },
    { NV_PFAULT_ACCESS_TYPE_VIRT_ATOMIC_WEAK, UVM_FAULT_ACCESS_TYPE_ATOMIC_WEAK, true, "virt-atomic-weak" },
    { NV_PFAULT_ACCESS_TYPE_PHYS_READ, UVM_FAULT_ACCESS_TYPE_READ, false, "phys-read" },
    { NV_PFAULT_ACCESS_TYPE_PHYS_WRITE, UVM_FAULT_ACCESS_TYPE_WRITE, false, "phys-write" },
    { NV_PFAULT_ACCESS_TYPE_PHYS_ATOMIC, UVM_FAULT_ACCESS_TYPE_ATOMIC_STRONG, false, "phys-atomic" },
    { NV_PFAULT_ACCESS_TYPE_PHYS_PREFETCH, UVM_FAULT_ACCESS_TYPE_PREFETCH, false, "phys-prefetch" },
};

static const fault_case_t fault_cases[] = {
    { NV_PFAULT_FAULT_TYPE_PDE, UVM_FAULT_TYPE_INVALID_PDE, "pde" },
    { NV_PFAULT_FAULT_TYPE_PDE_SIZE, UVM_FAULT_TYPE_PDE_SIZE, "pde-size" },
    { NV_PFAULT_FAULT_TYPE_PTE, UVM_FAULT_TYPE_INVALID_PTE, "pte" },
    { NV_PFAULT_FAULT_TYPE_VA_LIMIT_VIOLATION, UVM_FAULT_TYPE_VA_LIMIT_VIOLATION, "va-limit" },
    { NV_PFAULT_FAULT_TYPE_UNBOUND_INST_BLOCK, UVM_FAULT_TYPE_UNBOUND_INST_BLOCK, "unbound-instance" },
    { NV_PFAULT_FAULT_TYPE_PRIV_VIOLATION, UVM_FAULT_TYPE_PRIV_VIOLATION, "privilege" },
    { NV_PFAULT_FAULT_TYPE_RO_VIOLATION, UVM_FAULT_TYPE_WRITE, "read-only-write" },
    { NV_PFAULT_FAULT_TYPE_WO_VIOLATION, UVM_FAULT_TYPE_READ, "write-only-read" },
    { NV_PFAULT_FAULT_TYPE_PITCH_MASK_VIOLATION, UVM_FAULT_TYPE_PITCH_MASK_VIOLATION, "pitch-mask" },
    { NV_PFAULT_FAULT_TYPE_WORK_CREATION, UVM_FAULT_TYPE_WORK_CREATION, "work-creation" },
    { NV_PFAULT_FAULT_TYPE_UNSUPPORTED_APERTURE, UVM_FAULT_TYPE_UNSUPPORTED_APERTURE, "unsupported-aperture" },
    { NV_PFAULT_FAULT_TYPE_COMPRESSION_FAILURE, UVM_FAULT_TYPE_COMPRESSION_FAILURE, "compression" },
    { NV_PFAULT_FAULT_TYPE_UNSUPPORTED_KIND, UVM_FAULT_TYPE_UNSUPPORTED_KIND, "unsupported-kind" },
    { NV_PFAULT_FAULT_TYPE_REGION_VIOLATION, UVM_FAULT_TYPE_REGION_VIOLATION, "region" },
    { NV_PFAULT_FAULT_TYPE_POISONED, UVM_FAULT_TYPE_POISONED, "poisoned" },
    { NV_PFAULT_FAULT_TYPE_ATOMIC_VIOLATION, UVM_FAULT_TYPE_ATOMIC, "atomic-violation" },
};

static const NvU32 aperture_values[] = {
    NVC369_BUF_ENTRY_INST_APERTURE_VID_MEM,
    NVC369_BUF_ENTRY_INST_APERTURE_SYS_MEM_COHERENT,
    NVC369_BUF_ENTRY_INST_APERTURE_SYS_MEM_NONCOHERENT,
};

static packet_case_t make_gpc_case(const fault_case_t *fault, const access_case_t *access,
                                   unsigned vector_index, unsigned aperture_index)
{
    packet_case_t result = {
        .name = "",
        .instance_page = 0xABCDE12345ULL + vector_index,
        .fault_page = 0x123456789ULL + (vector_index & 0x3FF),
        .timestamp = 0x12345678ABCDEF01ULL + vector_index,
        .fault_type = fault->value,
        .access_type = access->value,
        .inst_aperture = aperture_values[aperture_index],
        .client_type = NV_PFAULT_MMU_CLIENT_TYPE_GPC,
        .client_id = (NvU16)(vector_index % 40),
        .engine_id = (NvU16)(NV_PFAULT_MMU_ENG_ID_GRAPHICS + (vector_index % 64)),
        .gpc_id = (NvU8)(vector_index % 8),
        .protected_mode = (vector_index & 1) != 0,
        .replayable = true,
        .replayable_enabled = true,
        .valid = true,
        .expected_fault_type = fault->type,
        .expected_access_type = access->access,
        .expected_aperture = aperture_index == 0 ? UVM_APERTURE_VID : UVM_APERTURE_SYS,
        .expected_virtual = access->is_virtual,
    };
    return result;
}

static int probe_guard(const char *mode)
{
    NvU32 fault_index = 0;
    packet_case_t test_case = {
        .name = "assertion-guard",
        .instance_page = 0x1234,
        .fault_page = 0x5678,
        .timestamp = 9,
        .fault_type = NV_PFAULT_FAULT_TYPE_PTE,
        .access_type = NV_PFAULT_ACCESS_TYPE_VIRT_READ,
        .inst_aperture = NVC369_BUF_ENTRY_INST_APERTURE_SYS_MEM_COHERENT,
        .client_type = NV_PFAULT_MMU_CLIENT_TYPE_GPC,
        .client_id = 1,
        .engine_id = NV_PFAULT_MMU_ENG_ID_GRAPHICS,
        .gpc_id = 0,
        .replayable = true,
        .replayable_enabled = true,
        .valid = true,
        .expected_fault_type = UVM_FAULT_TYPE_INVALID_PTE,
        .expected_access_type = UVM_FAULT_ACCESS_TYPE_READ,
        .expected_aperture = UVM_APERTURE_SYS,
        .expected_virtual = true,
    };
    if (strcmp(mode, "--probe-invalid-valid") == 0)
        test_case.valid = false;
    else if (strcmp(mode, "--probe-replayable-disabled") == 0)
        test_case.replayable_enabled = false;
    else if (strcmp(mode, "--probe-invalid-access") == 0)
        test_case.access_type = 12;
    else if (strcmp(mode, "--probe-out-of-range-index") == 0)
        fault_index = 1;
    else
        return 2;
    return run_packet_case(&test_case, fault_index, false);
}

int main(int argc, char **argv)
{
    unsigned vector_index = 0;
    unsigned checks_before = test_assertion_count;
    unsigned i, j;
    int failures = 0;
    if (argc == 2)
        return probe_guard(argv[1]);

    for (i = 0; i < sizeof(fault_cases) / sizeof(fault_cases[0]); ++i) {
        for (j = 0; j < sizeof(access_cases) / sizeof(access_cases[0]); ++j) {
            packet_case_t test_case = make_gpc_case(&fault_cases[i], &access_cases[j],
                                                     vector_index, vector_index % 3);
            char label[96];
            snprintf(label, sizeof(label), "%s-%s-%u",
                     fault_cases[i].name, access_cases[j].name, vector_index);
            test_case.name = label;
            failures += run_packet_case(&test_case, 0, false);
            ++vector_index;
        }
    }

    {
        packet_case_t hub = {
            .name = "hub-host-physical-read",
            .instance_page = 0xFEDCBA9876ULL,
            .fault_page = 0x102030405ULL,
            .timestamp = 0xFEDCBA9876543210ULL,
            .fault_type = NV_PFAULT_FAULT_TYPE_PTE,
            .access_type = NV_PFAULT_ACCESS_TYPE_PHYS_READ,
            .inst_aperture = NVC369_BUF_ENTRY_INST_APERTURE_VID_MEM,
            .client_type = NV_PFAULT_MMU_CLIENT_TYPE_HUB,
            .client_id = NV_PFAULT_CLIENT_HUB_HOST,
            .engine_id = NV_PFAULT_MMU_ENG_ID_HOST13,
            .gpc_id = 0,
            .replayable = true,
            .replayable_enabled = true,
            .valid = true,
            .expected_fault_type = UVM_FAULT_TYPE_INVALID_PTE,
            .expected_access_type = UVM_FAULT_ACCESS_TYPE_READ,
            .expected_aperture = UVM_APERTURE_VID,
            .expected_virtual = false,
        };
        failures += run_packet_case(&hub, 0, false);
    }

    {
        packet_case_t non_replayable = {
            .name = "non-replayable-gpc-virtual-write-only-read",
            .instance_page = 0x13579BDF02ULL,
            .fault_page = 0x23456789AULL,
            .timestamp = 0x1029384756ABCDEFULL,
            .fault_type = NV_PFAULT_FAULT_TYPE_WO_VIOLATION,
            .access_type = NV_PFAULT_ACCESS_TYPE_VIRT_WRITE,
            .inst_aperture = NVC369_BUF_ENTRY_INST_APERTURE_SYS_MEM_NONCOHERENT,
            .client_type = NV_PFAULT_MMU_CLIENT_TYPE_GPC,
            .client_id = 19,
            .engine_id = NV_PFAULT_MMU_ENG_ID_GRAPHICS + 6,
            .gpc_id = 3,
            .protected_mode = true,
            .replayable = false,
            .replayable_enabled = true,
            .valid = true,
            .expected_fault_type = UVM_FAULT_TYPE_READ,
            .expected_access_type = UVM_FAULT_ACCESS_TYPE_WRITE,
            .expected_aperture = UVM_APERTURE_SYS,
            .expected_virtual = true,
        };
        failures += run_packet_case(&non_replayable, 0, true);
    }
    run_confidential_callback_cases();
    printf("summary vectors=%u callback_cases=2 checks=%u failures=%u\n",
           vector_index + 2, test_assertion_count - checks_before, test_failures);
    return failures || test_failures ? 1 : 0;
}
'''


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite evidence: {path}")
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence output")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(descriptor)


def run(r580_uvm: Path, r595_uvm: Path, report_path: Path, log_path: Path,
        compiler: str = "cc") -> dict:
    r580_uvm = r580_uvm.resolve(strict=True)
    r595_uvm = r595_uvm.resolve(strict=True)
    if report_path.exists() or log_path.exists():
        raise FileExistsError("refusing to overwrite host-harness evidence")
    source_records = _validate_source_pair(r580_uvm, r595_uvm)
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise ValueError(f"compiler not found: {compiler}")
    compiler_version = subprocess.run([compiler_path, "--version"], capture_output=True,
                                      text=True, check=True).stdout.splitlines()[0]
    logs: list[str] = []
    outputs: dict[str, str] = {}
    guard_names = ("--probe-invalid-valid", "--probe-replayable-disabled",
                   "--probe-invalid-access", "--probe-out-of-range-index")
    with tempfile.TemporaryDirectory(prefix="volta-fault-decode-host-") as directory:
        scratch = Path(directory)
        for label, root in (("r580", r580_uvm), ("r595", r595_uvm)):
            common_inc = (root.parent / "common/inc").resolve(strict=True)
            c_source = scratch / f"{label}_fault_decode.c"
            binary = scratch / f"{label}_fault_decode"
            c_source.write_text(build_harness(root), encoding="utf-8")
            command = [compiler_path, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-I", str(common_inc), "-I", str(root), str(c_source), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            logs.append("$ " + shlex.join(command) + "\n" + compiled.stdout + compiled.stderr)
            if compiled.returncode != 0:
                raise RuntimeError(f"{label} host parser compilation failed (see captured log)")
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            logs.append("$ " + shlex.quote(str(binary)) + "\n" + executed.stdout + executed.stderr)
            if executed.returncode != 0:
                raise RuntimeError(f"{label} host parser vectors failed (see captured log)")
            outputs[label] = executed.stdout
            if "summary vectors=146 callback_cases=2 checks=3224 failures=0" not in executed.stdout:
                raise RuntimeError(f"{label} host parser vector/check count changed")

            for guard in guard_names:
                probe = subprocess.run([str(binary), guard], capture_output=True, text=True,
                                       preexec_fn=_disable_core_dumps)
                logs.append("$ " + shlex.quote(str(binary)) + " " + guard +
                            "\nexpected assertion rejection; returncode=" + str(probe.returncode) +
                            "\n" + probe.stdout + probe.stderr)
                if probe.returncode != -signal.SIGABRT:
                    raise RuntimeError(f"expected bounded assertion guard failed: {label} {guard}")
        if outputs["r580"] != outputs["r595"]:
            raise RuntimeError("R580 and candidate R595 host parser outputs differ")

    log_bytes = "".join(logs).encode("utf-8")
    log_hash = sha256_bytes(log_bytes)
    report = {
        "schema": "codex.volta-c369-fault-decode-host-harness.v1",
        "status": "passed",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "host-cpu-execution-of-extracted-pinned-C369-fault-buffer-parsers",
        "implementations_executed": 2,
        "vectors_per_implementation": 148,
        "parser_vectors_per_implementation": 146,
        "confidential_callback_cases_per_implementation": 2,
        "checks_passed": 6448,
        "assertion_guards_per_implementation": list(guard_names),
        "hardware_validated": False,
        "same_process_cuda_validated": False,
        "source_pair": source_records,
        "compiler": {"path": compiler_path, "version": compiler_version},
        "compile_flags": ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "result_stdout_sha256": {key: sha256_bytes(value.encode("utf-8")) for key, value in outputs.items()},
        "log": {"path": str(log_path.resolve()), "sha256": log_hash, "mode": "0600"},
        "limits": [
            "The replayable and non-replayable Volta parser paths plus the selected Pascal entry accessors and valid/clear callbacks are extracted into temporary host C programs.",
            "Packets are synthetic little-endian dword arrays built with the pinned C369 field definitions.",
            "The exact Pascal callback reads and clears the B069 VALID bit; compile-time assertions verify its packet size and VALID field word, shift, and width match the C369 packet.",
            "GPU canonical-address translation and GPC client-to-uTLB mapping use explicit identity/deterministic CPU shims.",
            "The HAL callback wrappers only count invocations and delegate to the extracted Pascal functions. Two additional direct callback cases exercise confidential-computing metadata-valid reads and clears; no decrypt or GPU operation is attempted.",
            "The non-replayable parser receives a copied packet and is checked to leave its VALID bit unchanged without valid/clear callbacks.",
            "No UVM module, GPU, CUDA context, hardware fault generation, or VM behavior is exercised.",
        ],
    }
    report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_exclusive(log_path.resolve(), log_bytes)
    _write_exclusive(report_path.resolve(), report_bytes)
    return {
        "status": "passed",
        "report": str(report_path.resolve()),
        "report_sha256": sha256_bytes(report_bytes),
        "log": str(log_path.resolve()),
        "log_sha256": log_hash,
        "implementations_executed": 2,
        "vectors_per_implementation": 148,
        "checks_passed": 6448,
        "hardware_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-uvm", type=Path, default=DEFAULT_R580_UVM)
    parser.add_argument("--r595-uvm", type=Path, default=DEFAULT_R595_UVM)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    print(json.dumps(run(args.r580_uvm, args.r595_uvm,
                         args.report, args.log, args.compiler), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"host fault-decode harness failed: {error}", file=sys.stderr)
        raise SystemExit(2)
