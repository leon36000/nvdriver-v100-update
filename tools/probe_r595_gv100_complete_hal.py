#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an isolated R595 UVM overlay with the complete R580 GV100 HAL rows.

The probe copies only source-derived callback bodies and never installs or
loads its module. A successful result proves compile/link closure for these HAL
tables, not that the candidate is safe or selectable on hardware.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
    compare_hal_tables,
    extract_r580_uvm_c_sources,
    map_callback_definitions,
    parse_gpu_hal_selector_contract,
    parse_hal_class_tables,
)
from tools.probe_r595_gv100_fault_hal import (  # noqa: E402
    FAULT_CALLBACKS,
    extract_archived_r580_uvm,
    stage_fault_hal_candidate,
)
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    DEFAULT_R595_SOURCE,
    R580_SOURCE_ROOT,
    VOLTA_OBJECT_SOURCES,
    build_overlay,
    prepare_overlay,
    read_member,
    resolve_frontend_module_symvers,
    source_archive_root,
)

DEFAULT_R580_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
R580_HAL_MEMBER = "kernel-open/nvidia-uvm/uvm_hal.c"
R580_HAL_HEADER_MEMBER = "kernel-open/nvidia-uvm/uvm_hal.h"
SOURCE_LIST_ANCHOR = "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n"
CLASS_HEADERS = ("clc36f.h", "clc3b5.h")
VOLTA_MMU_R595_ADAPTER = "uvm_hal_mmu_mode_volta_r595"
ALREADY_STAGED_SOURCES = set(VOLTA_OBJECT_SOURCES) | {
    "uvm_hal.c", "uvm_pascal_mmu.c", "uvm_pascal_fault_buffer.c",
}

# R595's selected GV100 rows do not reference these legacy R580 helpers. The
# v12 object/source audit found each name exactly once (its definition only),
# with no EXPORT_SYMBOL use or cross-object relocation. Keep that audit scoped
# to these exact functions so source drift fails closed instead of silently
# changing the linkage of additional callbacks.
R580_ORPHAN_HAL_HELPERS = {
    "uvm_hal_pascal_host_tlb_invalidate_va",
    "uvm_hal_pascal_replay_faults",
    "uvm_hal_pascal_ce_semaphore_release",
    "uvm_hal_pascal_ce_semaphore_reduction_inc",
    "uvm_hal_pascal_ce_semaphore_timestamp",
    "uvm_hal_maxwell_ce_offset_out",
    "uvm_hal_maxwell_ce_offset_in_out",
    "uvm_hal_maxwell_host_membar_sys",
    "uvm_hal_maxwell_host_tlb_invalidate_all_a16f",
    "uvm_hal_maxwell_ce_semaphore_release",
    "uvm_hal_maxwell_host_tlb_invalidate_all_b06f",
    "uvm_hal_maxwell_host_tlb_invalidate_va",
    "uvm_hal_maxwell_host_tlb_invalidate_test",
    "uvm_hal_maxwell_ce_semaphore_reduction_inc",
    "uvm_hal_maxwell_ce_semaphore_timestamp",
    "uvm_hal_maxwell_host_semaphore_timestamp",
    "uvm_hal_maxwell_ce_memcopy",
    "uvm_hal_maxwell_host_write_gpu_put",
    "uvm_hal_maxwell_host_init_noop",
    "uvm_hal_maxwell_replay_faults_unsupported",
    "uvm_hal_maxwell_cancel_faults_global_unsupported",
    "uvm_hal_maxwell_cancel_faults_targeted_unsupported",
    "uvm_hal_maxwell_cancel_faults_va_unsupported",
    "uvm_hal_maxwell_host_clear_faulted_channel_method_unsupported",
    "uvm_hal_maxwell_ce_memset_1",
    "uvm_hal_maxwell_ce_memset_4",
    "uvm_hal_maxwell_ce_memset_8",
    "uvm_hal_pascal_fault_buffer_read_put",
    "uvm_hal_pascal_fault_buffer_read_get",
    "uvm_hal_pascal_fault_buffer_write_get",
    "uvm_hal_pascal_fault_buffer_get_fault_type",
    "uvm_hal_pascal_fault_buffer_parse_replayable_entry",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mask_comments(source: str) -> str:
    """Mask C comments while preserving offsets and line breaks."""
    output = list(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                state = "block"
                index += 2
                continue
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                state = "line"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
        elif state == "block":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                output[index] = " "
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state in ("string", "char"):
            if char == "\\":
                if index + 1 < len(source):
                    index += 2
                    continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        index += 1
    return "".join(output)


def extract_callback_prototype(header: str, symbol: str) -> str:
    """Extract one prototype, including a return type wrapped to its own line."""
    clean = _mask_comments(header)
    name_re = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
    declarations = []
    for match in name_re.finditer(clean):
        opening = clean.find("(", match.start(), match.end())
        depth = 0
        closing = None
        for index in range(opening, len(clean)):
            if clean[index] == "(":
                depth += 1
            elif clean[index] == ")":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None:
            continue
        end = closing + 1
        while end < len(clean) and clean[end].isspace():
            end += 1
        if end >= len(clean) or clean[end] != ";":
            continue
        start = clean.rfind("\n", 0, match.start()) + 1
        if not clean[start:match.start()].strip():
            previous_end = start - 1
            while previous_end >= 0:
                previous_start = clean.rfind("\n", 0, previous_end) + 1
                if clean[previous_start:previous_end].strip():
                    start = previous_start
                    break
                previous_end = previous_start - 1
        declaration = re.sub(r"\s+", " ", clean[start:end + 1]).strip()
        declarations.append(declaration)
    if len(declarations) != 1:
        raise ValueError(f"expected one prototype for {symbol}; found {len(declarations)}")
    return declarations[0]


def merge_callback_prototypes(r580_header: str, r595_header: str,
                              callback_symbols: set[str]) -> tuple[str, dict]:
    """Add missing pinned declarations and reject signature drift or collisions."""
    missing = []
    already_equal = []
    for symbol in sorted(callback_symbols):
        legacy = extract_callback_prototype(r580_header, symbol)
        occurrences = list(re.finditer(r"\b" + re.escape(symbol) + r"\s*\(",
                                       _mask_comments(r595_header)))
        if not occurrences:
            missing.append(legacy)
            continue
        modern = extract_callback_prototype(r595_header, symbol)
        if modern != legacy:
            raise ValueError(
                f"R595 prototype differs for {symbol}: R580={legacy!r}; R595={modern!r}"
            )
        already_equal.append(symbol)
    if not missing:
        return r595_header, {"added": [], "already_identical": already_equal}
    endif = list(re.finditer(r"(?m)^\s*#\s*endif\b[^\n]*", r595_header))
    if not endif:
        raise ValueError("R595 UVM HAL header has no final include-guard #endif")
    insertion = endif[-1].start()
    inserted = "\n/* Source-derived R580 GV100 HAL callback prototypes. */\n"
    inserted += "\n".join(missing) + "\n\n"
    merged = r595_header[:insertion] + inserted + r595_header[insertion:]
    return merged, {
        "added": sorted(symbol for symbol in callback_symbols
                         if any(symbol in declaration for declaration in missing)),
        "already_identical": already_equal,
    }


def format_complete_hal_row(target_id: str, union_name: str,
                            callbacks: dict[str, str]) -> str:
    if not callbacks:
        raise ValueError(f"refusing empty HAL row for {target_id}")
    if any(re.fullmatch(r"[A-Za-z_]\w*", name) is None
           for name in callbacks.values()):
        raise ValueError(f"HAL row {target_id} contains a non-symbol callback")
    assignments = "\n".join(
        f"            .{operation} = {symbol},"
        for operation, symbol in callbacks.items()
    )
    return (
        "    {\n"
        f"        .id = {target_id},\n"
        f"        .u.{union_name} = {{\n{assignments}\n        }}\n"
        "    },\n"
    )


def insert_complete_hal_row(source: str, table_name: str,
                            target_id: str, row_text: str) -> str:
    """Insert one explicit no-parent class row before the table's first entry."""
    tables = parse_hal_class_tables(source)
    if table_name not in tables:
        raise ValueError(f"HAL table not found: {table_name}")
    if any(row["id"] == target_id for row in tables[table_name]):
        raise ValueError(f"HAL table {table_name} already contains target id {target_id}")
    declaration = re.search(
        r"static\s+uvm_hal_class_ops_t\s+" + re.escape(table_name) +
        r"\s*\[\s*\]\s*=\s*\{", _mask_comments(source))
    if declaration is None:
        raise ValueError(f"HAL table declaration not found: {table_name}")
    table_open = declaration.end() - 1
    table_close = _matching_brace(_mask_comments(source), table_open)
    table_source = source[table_open + 1:table_close]
    first_row = re.search(r"(?m)^[ \t]*\{\s*\.id\s*=", table_source)
    if first_row is None:
        raise ValueError(f"HAL table has no row insertion point: {table_name}")
    insertion = table_open + 1 + first_row.start()
    return source[:insertion] + row_text + source[insertion:]


def _source_hashes(source_tree: Path, source_names: set[str]) -> dict:
    result = {}
    for name in sorted(source_names):
        path = source_tree / name
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _function_definition_declaration_start(source: str, symbol: str) -> int:
    """Find the declaration start for one unreferenced top-level definition."""
    clean = _mask_comments(source)
    matches = list(re.finditer(r"\b" + re.escape(symbol) + r"\s*\(", clean))
    if len(matches) != 1:
        raise ValueError(f"expected one definition of {symbol}; found {len(matches)}")
    match = matches[0]
    opening = clean.find("(", match.start(), match.end())
    depth = 0
    closing = None
    for index in range(opening, len(clean)):
        if clean[index] == "(":
            depth += 1
        elif clean[index] == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        raise ValueError(f"unterminated parameter list for {symbol}")
    body_open = closing + 1
    while body_open < len(clean) and clean[body_open].isspace():
        body_open += 1
    if body_open >= len(clean) or clean[body_open] != "{":
        raise ValueError(f"expected one definition of {symbol}; occurrence is not a definition")

    barrier = max(clean.rfind(";", 0, match.start()),
                  clean.rfind("}", 0, match.start()),
                  clean.rfind("{", 0, match.start()))
    prelude_start = barrier + 1
    prelude = clean[prelude_start:match.start()]
    offset = prelude_start
    declaration_start = None
    for line in prelude.splitlines(keepends=True):
        line_without_ending = line.rstrip("\r\n")
        stripped = line_without_ending.lstrip()
        if stripped and not stripped.startswith("#"):
            declaration_start = offset + len(line_without_ending) - len(stripped)
            break
        offset += len(line)
    if declaration_start is None:
        # Most signatures keep the return type on the function-name line. In
        # that case, the preceding top-level barrier can be followed only by
        # whitespace and the declaration begins on this line.
        line_start = clean.rfind("\n", 0, match.start()) + 1
        line_prefix = clean[line_start:match.start()]
        if not line_prefix.strip():
            raise ValueError(f"could not locate declaration start for {symbol}")
        declaration_start = line_start + len(line_prefix) - len(line_prefix.lstrip())
    return declaration_start


def localize_unreferenced_hal_helpers(uvm_root: Path, source_names: set[str],
                                      symbols: set[str], *,
                                      referenced_symbols: set[str]) -> dict:
    """Give audited orphan R580 helpers internal linkage in the R595 overlay.

    The function bodies remain byte-for-byte intact. Each name must occur
    exactly once across the candidate C/header tree, be absent from the actual
    GV100 callback set, and have a definition in one of the pinned legacy
    callback sources. Any source/export/reference drift aborts before edits.
    """
    uvm_root = Path(uvm_root)
    if not symbols:
        raise ValueError("refusing an empty orphan-helper set")
    overlap = symbols & referenced_symbols
    if overlap:
        raise ValueError(f"orphan helper is selected by a HAL row: {sorted(overlap)}")

    code_sources = {}
    for path in sorted(uvm_root.rglob("*")):
        if path.is_file() and path.suffix in {".c", ".h"}:
            code_sources[path.relative_to(uvm_root).as_posix()] = path.read_text(errors="strict")

    occurrences = {}
    insertion_by_source = {}
    for symbol in sorted(symbols):
        pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
        matches = [
            relative for relative, source in code_sources.items()
            for _ in pattern.finditer(_mask_comments(source))
        ]
        if len(matches) != 1:
            if not matches:
                raise ValueError(f"expected one definition of {symbol}; found none")
            raise ValueError(
                f"source references prevent localizing {symbol}: {matches}")
        relative = matches[0]
        if relative not in source_names:
            raise ValueError(f"orphan helper {symbol} is outside the pinned legacy source set")
        source = code_sources[relative]
        declaration_start = _function_definition_declaration_start(source, symbol)
        insertion_by_source.setdefault(relative, []).append(declaration_start)
        occurrences[symbol] = 1

    source_hashes_before = {}
    source_hashes_after = {}
    for relative, insertions in insertion_by_source.items():
        path = uvm_root / relative
        original = code_sources[relative]
        updated = original
        source_hashes_before[relative] = _sha256(original.encode())
        for insertion in sorted(insertions, reverse=True):
            updated = updated[:insertion] + "static " + updated[insertion:]
        path.write_text(updated)
        source_hashes_after[relative] = _sha256(updated.encode())

    return {
        "symbols": sorted(symbols),
        "localized_symbols": sorted(symbols),
        "source_occurrences_before": occurrences,
        "source_files": sorted(insertion_by_source),
        "source_sha256_before": source_hashes_before,
        "source_sha256_after": source_hashes_after,
        "bodies_unchanged": True,
        "change": "insert static storage class at each audited function definition",
        "scope": "R595 scratch UVM overlay only; installed NVIDIA sources untouched",
    }


def audit_private_hal_helper_linkage(module_path: Path, object_paths: list[Path],
                                     symbols: set[str]) -> dict:
    """Confirm localized dead helpers disappear and create no cross-object U refs."""
    module_path = Path(module_path)
    all_symbols = subprocess.run(
        ["nm", "--defined-only", str(module_path)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    global_symbols = subprocess.run(
        ["nm", "-g", "--defined-only", str(module_path)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if all_symbols.returncode or global_symbols.returncode:
        raise ValueError("nm could not inspect the linked UVM module")

    def symbol_types(output: str) -> dict[str, str]:
        result = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 2:
                result[fields[-1]] = fields[-2]
        return result

    defined = symbol_types(all_symbols.stdout)
    global_defined = symbol_types(global_symbols.stdout)
    unresolved = {symbol: [] for symbol in symbols}
    for object_path in object_paths:
        nm = subprocess.run(
            ["nm", "-u", str(object_path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if nm.returncode:
            raise ValueError(f"nm could not inspect object {object_path}")
        for line in nm.stdout.splitlines():
            fields = line.split()
            if fields and fields[-1] in unresolved:
                unresolved[fields[-1]].append(str(object_path))

    object_definitions = {symbol: [] for symbol in symbols}
    no_cross_object_references = all(not paths for paths in unresolved.values())
    for object_path in object_paths:
        nm = subprocess.run(
            ["nm", "--defined-only", str(object_path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if nm.returncode:
            raise ValueError(f"nm could not inspect object {object_path}")
        for line in nm.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 2:
                name = fields[-1]
                for symbol in symbols:
                    if name == symbol or name.startswith(symbol + "."):
                        object_definitions[symbol].append(str(object_path))
    symbols_absent_from_objects = all(not paths for paths in object_definitions.values())
    symbols_absent_from_module = all(symbol not in defined for symbol in symbols)
    symbols_absent_globally = all(symbol not in global_defined for symbol in symbols)
    return {
        "all_symbols_absent_from_compiled_objects": symbols_absent_from_objects,
        "all_symbols_absent_from_linked_module": symbols_absent_from_module,
        "all_symbols_absent_from_global_module_symbols": symbols_absent_globally,
        "object_definitions": object_definitions,
        "cross_object_undefined_references": unresolved,
        "no_cross_object_undefined_references": no_cross_object_references,
        "passed": (symbols_absent_from_objects and symbols_absent_from_module
                   and symbols_absent_globally and no_cross_object_references),
        "module_sha256": _sha256(module_path.read_bytes()),
    }


def _stage_extra_sources(source_tree: Path, r595_uvm: Path,
                         extra_sources: set[str]) -> dict:
    source_list_path = r595_uvm / "nvidia-uvm-sources.Kbuild"
    source_list = source_list_path.read_text()
    if source_list.count(SOURCE_LIST_ANCHOR) != 1:
        raise ValueError("R595 Kbuild source-list anchor is not unique")
    copy_plan = []
    copied_hashes = {}
    for relative in sorted(extra_sources):
        data = (source_tree / relative).read_bytes()
        destination = r595_uvm / relative
        if destination.exists():
            if destination.read_bytes() != data:
                raise FileExistsError(
                    f"refusing to overwrite non-identical R595 source: {destination}")
        else:
            copy_plan.append((relative, destination, data))
        source_entry = f"NVIDIA_UVM_SOURCES += nvidia-uvm/{relative}\n"
        if source_entry not in source_list:
            source_list = source_list.replace(
                SOURCE_LIST_ANCHOR, SOURCE_LIST_ANCHOR + source_entry, 1)
        copied_hashes[relative] = _sha256(data)
    # All source conflicts and source-list anchors are checked before mutation.
    for _, destination, data in copy_plan:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    source_list_path.write_text(source_list)
    return {
        "added_source_names": sorted(extra_sources),
        "copied_source_hashes": copied_hashes,
    }


def stage_missing_archive_headers(archive_path: Path, source_tree: Path,
                                 candidate_root: Path, candidate_uvm: Path,
                                 source_names: set[str],
                                 expected_root: str = R580_SOURCE_ROOT) -> dict:
    """Stage only unavailable quoted headers included by selected R580 C files."""
    candidate_root = Path(candidate_root)
    candidate_uvm = Path(candidate_uvm)
    if not candidate_root.is_dir() or not candidate_uvm.is_dir():
        raise ValueError("candidate source roots must already exist")
    candidate_headers = [path for path in candidate_root.rglob("*.h") if path.is_file()]
    available_paths = {
        PurePosixPath(path.relative_to(candidate_root).as_posix())
        for path in candidate_headers
    }
    available_basenames = {path.name for path in candidate_headers}
    required = set()
    for source_name in sorted(source_names):
        source = (Path(source_tree) / source_name).read_text(errors="strict")
        clean = _mask_comments(source)
        for include in re.findall(r'(?m)^\s*#\s*include\s*"([^"\n]+)"', clean):
            relative = PurePosixPath(include)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe quoted include in R580 source: {include}")
            if relative in available_paths or relative.name in available_basenames:
                continue
            required.add(relative)

    staged = {}
    copy_plan = []
    with tarfile.open(archive_path, "r:*") as archive:
        root = source_archive_root(archive, expected_root)
        for relative in sorted(required, key=lambda value: value.as_posix()):
            member_name = (root + "/kernel-open/nvidia-uvm/" + relative.as_posix())
            data = read_member(archive, member_name)
            destination = candidate_uvm.joinpath(*relative.parts)
            if destination.exists():
                if destination.read_bytes() != data:
                    raise FileExistsError(
                        f"refusing to overwrite non-identical R595 header: {destination}")
            else:
                copy_plan.append((destination, data))
            staged[relative.as_posix()] = _sha256(data)

    # Validate all missing dependencies and collisions before mutating the overlay.
    for destination, _ in copy_plan:
        destination.parent.mkdir(parents=True, exist_ok=True)
    for destination, data in copy_plan:
        destination.write_bytes(data)
    return {
        "added_headers": sorted(staged),
        "header_sha256": staged,
        "source_names_scanned": sorted(source_names),
    }


def stage_complete_hal_rows(r580_tables: dict, resolved_callbacks: dict,
                            r595_uvm: Path) -> dict:
    hal_path = Path(r595_uvm) / "uvm_hal.c"
    source = hal_path.read_text()
    inserted = []
    for table_name, target_id in REQUIRED_GV100_TABLE_TARGETS.items():
        if table_name == "fault_buffer_table":
            # The isolated fault candidate was already staged through its
            # dedicated source/type-checked path, with no parent or stubs.
            continue
        matching = [row for row in r580_tables[table_name] if row["id"] == target_id]
        if len(matching) != 1:
            raise ValueError(f"R580 source does not resolve one target row: {table_name}")
        union = matching[0]["union"]
        callbacks = resolved_callbacks[table_name]
        source = insert_complete_hal_row(
            source, table_name, target_id,
            format_complete_hal_row(target_id, union, callbacks),
        )
        inserted.append(table_name)
    include_lines = []
    for header in CLASS_HEADERS:
        include = f'#include "{header}"'
        if include not in source:
            include_lines.append(include)
    if include_lines:
        source = "\n".join(include_lines) + "\n" + source
    hal_path.write_text(source)
    candidate_tables = parse_hal_class_tables(source)
    for table_name, target_id in REQUIRED_GV100_TABLE_TARGETS.items():
        rows = [row for row in candidate_tables[table_name] if row["id"] == target_id]
        if len(rows) != 1:
            raise ValueError(f"staged table did not retain one {target_id} row in {table_name}")
        if rows[0]["parent_id"] is not None:
            raise ValueError(f"staged {table_name} row unexpectedly depends on a parent")
        if rows[0]["assignments"] != resolved_callbacks[table_name]:
            raise ValueError(f"staged {table_name} callbacks differ from resolved R580 source")
    return {
        "inserted_tables": inserted,
        "fault_buffer_table_inserted_by_typed_fault_probe": True,
        "all_six_rows_explicit_and_parentless": True,
        "class_header_includes_added": include_lines,
    }


def audit_staged_gv100_dispatch(hal_source: str) -> dict:
    """Prove the six staged GV100 rows reach R595's real class selectors.

    Compiling callbacks is insufficient when uvm_hal_init_gpu cannot select
    their architecture/class IDs. Keep this source-level gate adjacent to the
    overlay builder so future table edits fail before Kbuild if a row or a
    selector route is missing.
    """
    tables = parse_hal_class_tables(hal_source)
    selectors = parse_gpu_hal_selector_contract(hal_source)
    rows = {}
    errors = {}
    for table_name, target_id in REQUIRED_GV100_TABLE_TARGETS.items():
        matches = [row for row in tables.get(table_name, [])
                   if row["id"] == target_id]
        if len(matches) != 1:
            errors[table_name] = f"expected one {target_id} row; found {len(matches)}"
            continue
        row = matches[0]
        assignments = row["assignments"]
        rows[table_name] = {
            "id": target_id,
            "parent_id": row["parent_id"],
            "callback_count": len(assignments),
            "callbacks_complete": bool(assignments) and all(assignments.values()),
        }
        if row["parent_id"] is not None:
            errors[table_name] = "GV100 row unexpectedly depends on a parent row"
        elif not rows[table_name]["callbacks_complete"]:
            errors[table_name] = "GV100 row has no callbacks or a NULL callback"

    missing_selectors = sorted(set(REQUIRED_GV100_TABLE_TARGETS) - set(selectors))
    if missing_selectors:
        errors["selectors"] = f"missing selector routes: {missing_selectors}"
    return {
        "hal_source_sha256": _sha256(hal_source.encode()),
        "required_table_count": len(REQUIRED_GV100_TABLE_TARGETS),
        "required_targets": dict(REQUIRED_GV100_TABLE_TARGETS),
        "selected_rows": rows,
        "selector_contract": selectors,
        "missing_selectors": missing_selectors,
        "errors": errors,
        "static_dispatch_candidate": not errors and
                                     len(rows) == len(REQUIRED_GV100_TABLE_TARGETS) and
                                     len(selectors) == len(REQUIRED_GV100_TABLE_TARGETS),
        "runtime_or_hardware_validated": False,
    }


def add_volta_mmu_mode_adapter(volta_source: str, pascal_source: str,
                               r595_header: str) -> tuple[str, str, dict]:
    """Bridge R580's page-size-argument factory to R595's lookup callback.

    R580 rejects 128K at the Volta factory and its Pascal-derived HAL advertises
    only 2M/64K/4K. R595 moved supported sizes into the returned HAL's
    page_sizes() callback, so the class-table adapter selects the sole valid
    legacy factory argument (64K) while preserving that complete page mask.
    """
    old_symbol = "uvm_hal_mmu_mode_volta"
    old_definition = re.compile(
        r"uvm_mmu_mode_hal_t\s*\*\s*" + re.escape(old_symbol) +
        r"\s*\(\s*NvU64\s+big_page_size\s*\)\s*\{"
    )

    def function_body(source: str, pattern: re.Pattern, description: str) -> tuple[re.Match, str]:
        clean = _mask_comments(source)
        matches = list(pattern.finditer(clean))
        if len(matches) != 1:
            raise ValueError(f"expected one {description} definition; found {len(matches)}")
        match = matches[0]
        opening = clean.find("{", match.start(), match.end())
        closing = _matching_brace(clean, opening)
        return match, clean[opening + 1:closing]

    volta_match, volta_body = function_body(
        volta_source, old_definition, "R580 Volta mode factory")
    required_volta_contract = (
        re.search(
            r"UVM_ASSERT\s*\(\s*big_page_size\s*==\s*UVM_PAGE_SIZE_64K\s*\|\|"
            r"\s*big_page_size\s*==\s*UVM_PAGE_SIZE_128K\s*\)\s*;",
            volta_body,
        ),
        re.search(
            r"if\s*\(\s*big_page_size\s*==\s*UVM_PAGE_SIZE_128K\s*\)\s*"
            r"return\s+NULL\s*;",
            volta_body,
        ),
        re.search(
            r"uvm_hal_mmu_mode_pascal\s*\(\s*big_page_size\s*\)",
            volta_body,
        ),
    )
    if not all(required_volta_contract):
        raise ValueError("unrecognized legacy Volta page-size contract")

    pascal_mode_pattern = re.compile(
        r"uvm_mmu_mode_hal_t\s*\*\s*uvm_hal_mmu_mode_pascal\s*"
        r"\(\s*NvU64\s+big_page_size\s*\)\s*\{"
    )
    _, pascal_mode_body = function_body(
        pascal_source, pascal_mode_pattern, "R580 Pascal mode factory")
    if not re.search(
            r"if\s*\(\s*big_page_size\s*==\s*UVM_PAGE_SIZE_128K\s*\)\s*"
            r"return\s+NULL\s*;", pascal_mode_body):
        raise ValueError("R580 Pascal factory no longer rejects 128K")

    _, page_sizes_body = function_body(
        pascal_source,
        re.compile(r"static\s+NvU64\s+page_sizes_pascal\s*\(\s*void\s*\)\s*\{"),
        "R580 Pascal page-size mask",
    )
    advertised_sizes = set(re.findall(r"UVM_PAGE_SIZE_\w+", page_sizes_body))
    expected_sizes = {"UVM_PAGE_SIZE_2M", "UVM_PAGE_SIZE_64K", "UVM_PAGE_SIZE_4K"}
    if advertised_sizes != expected_sizes:
        raise ValueError(
            "legacy Volta page-size contract changed: Pascal mask is "
            f"{sorted(advertised_sizes)!r}"
        )

    if VOLTA_MMU_R595_ADAPTER in _mask_comments(volta_source):
        raise ValueError(f"adapter already exists: {VOLTA_MMU_R595_ADAPTER}")
    closing = _matching_brace(_mask_comments(volta_source),
                              _mask_comments(volta_source).find("{", volta_match.start(), volta_match.end()))
    adapter = (
        "\n\n/* R595 moved supported page sizes into the returned HAL's page_sizes() mask. "
        "The R580 Volta factory accepts 64K, rejects 128K, and its inherited Pascal "
        "mask advertises 2M/64K/4K. Keep the historical implementation intact and "
        "adapt the no-argument R595 table callback through its valid 64K entry. */\n"
        f"uvm_mmu_mode_hal_t *{VOLTA_MMU_R595_ADAPTER}(void)\n"
        "{\n"
        f"    return {old_symbol}(UVM_PAGE_SIZE_64K);\n"
        "}\n"
    )
    adapted_source = volta_source[:closing + 1] + adapter + volta_source[closing + 1:]

    header_clean = _mask_comments(r595_header)
    if re.search(r"\b" + re.escape(VOLTA_MMU_R595_ADAPTER) + r"\s*\(", header_clean):
        raise ValueError(f"R595 header already declares {VOLTA_MMU_R595_ADAPTER}")
    guards = list(re.finditer(r"(?m)^\s*#\s*endif\b[^\n]*", r595_header))
    if not guards:
        raise ValueError("R595 UVM HAL header has no final include-guard #endif")
    prototype = f"uvm_mmu_mode_hal_t *{VOLTA_MMU_R595_ADAPTER}(void);\n\n"
    insertion = guards[-1].start()
    adapted_header = r595_header[:insertion] + prototype + r595_header[insertion:]
    return adapted_source, adapted_header, {
        "legacy_symbol": old_symbol,
        "adapter_symbol": VOLTA_MMU_R595_ADAPTER,
        "adapter_argument": "UVM_PAGE_SIZE_64K",
        "legacy_128k_rejected": True,
        "128k_excluded_by_pascal_page_size_mask": True,
        "pascal_page_sizes_advertised": sorted(advertised_sizes),
        "legacy_factory_preserved": True,
        "r595_callback_contract": "no arguments; valid page sizes returned by page_sizes()",
    }


def adapt_volta_noncoherent_mmu_pte(volta_source: str, volta_dev_mmu_header: str,
                                    r595_hal_types: str) -> tuple[str, dict]:
    """Encode R595 SYS_NON_COHERENT BAR1 PTEs using GV100's system address field.

    R595 can select this aperture for peer BAR1 mappings when PCIe atomics are
    disabled. The pinned Volta PTE callback predates that aperture and asserts
    on it. GV100's generated VER2 PTE header provides aperture value 3; the
    address remains a system physical address, not a VID/peer address.
    """
    aperture_token = "UVM_APERTURE_SYS_NON_COHERENT"
    type_clean = _mask_comments(r595_hal_types)
    if not re.search(r"\b" + re.escape(aperture_token) + r"\b", type_clean):
        raise ValueError("R595 UVM types lack SYS_NON_COHERENT aperture")

    macro = "NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY"
    header_clean = _mask_comments(volta_dev_mmu_header)
    definitions = list(re.finditer(
        r"(?m)^\s*#\s*define\s+" + re.escape(macro) + r"\s+(0[xX][0-9A-Fa-f]+)\b",
        header_clean,
    ))
    if len(definitions) != 1 or int(definitions[0].group(1), 16) != 3:
        raise ValueError("GV100 PTE aperture value must be defined once as 3")

    clean = _mask_comments(volta_source)
    functions = list(re.finditer(r"\bstatic\s+NvU64\s+make_pte_volta\s*\(", clean))
    if len(functions) != 1:
        raise ValueError(f"expected one make_pte_volta definition; found {len(functions)}")
    opening = clean.find("{", functions[0].start())
    closing = _matching_brace(clean, opening)
    body = volta_source[opening + 1:closing]

    def replace_one(source: str, pattern: str, replacement, description: str) -> str:
        matches = list(re.finditer(pattern, _mask_comments(source), re.MULTILINE))
        if len(matches) != 1:
            raise ValueError(
                f"unrecognized make_pte_volta {description} source pattern; found {len(matches)}"
            )
        match = matches[0]
        replacement_text = replacement(match) if callable(replacement) else replacement
        return source[:match.start()] + replacement_text + source[match.end():]

    aperture_pattern = (
        r"^(?P<indent>[ \t]*)if\s*\(\s*aperture\s*==\s*UVM_APERTURE_SYS\s*\)\s*\n"
        r"[ \t]*aperture_bits\s*=\s*NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY\s*;\s*\n"
        r"[ \t]*else\s+if\s*\(\s*aperture\s*==\s*UVM_APERTURE_VID\s*\)"
    )
    def aperture_replacement(match: re.Match) -> str:
        indent = match.group("indent")
        inner = indent + "    "
        return (
            f"{indent}if (aperture == UVM_APERTURE_SYS)\n"
            f"{inner}aperture_bits = NV_MMU_VER2_PTE_APERTURE_SYSTEM_COHERENT_MEMORY;\n"
            f"{indent}else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)\n"
            f"{inner}aperture_bits = {macro};\n"
            f"{indent}else if (aperture == UVM_APERTURE_VID)"
        )
    body = replace_one(body, aperture_pattern, aperture_replacement, "aperture-selection")

    address_pattern = (
        r"^(?P<indent>[ \t]*)if\s*\(\s*aperture\s*==\s*UVM_APERTURE_SYS\s*\)\s*\{"
    )
    def address_replacement(match: re.Match) -> str:
        indent = match.group("indent")
        return (f"{indent}if (aperture == UVM_APERTURE_SYS || "
                "aperture == UVM_APERTURE_SYS_NON_COHERENT) {")
    body = replace_one(body, address_pattern, address_replacement, "system-address")
    adapted = volta_source[:opening + 1] + body + volta_source[closing:]
    if adapted == volta_source:
        raise ValueError("SYS_NON_COHERENT PTE adapter made no source change")

    return adapted, {
        "aperture": aperture_token,
        "gv100_pte_aperture_macro": macro,
        "gv100_pte_aperture_value": 3,
        "noncoherent_aperture_is_gv100_pte_value_3": True,
        "uses_system_physical_address_field": True,
        "pde_or_page_table_allocation_behavior_changed": False,
        "input_source_sha256": _sha256(volta_source.encode()),
        "adapted_source_sha256": _sha256(adapted.encode()),
    }


def adapt_volta_noncoherent_ce_aperture(volta_ce_source: str,
                                        r580_c3b5_header: str,
                                        r595_c3b5_header: str,
                                        r595_hal_types: str) -> tuple[str, dict]:
    """Route Volta C3B5 copies to the noncoherent system target when requested.

    The exact C3B5 source headers in R580 and R595 both define target value 2
    for NONCOHERENT_SYSMEM. The R580 Volta CE helper predates the R595 UVM
    aperture and rejects it. Add only this physical-memory target to the
    existing Volta helper; preserve its SYS/VID encodings and fail closed on
    source/header drift.
    """
    token = "UVM_APERTURE_SYS_NON_COHERENT"
    if not re.search(r"\b" + re.escape(token) + r"\b", _mask_comments(r595_hal_types)):
        raise ValueError("R595 UVM types lack SYS_NON_COHERENT aperture")

    def c3b5_contract(header: str, label: str) -> dict[str, str]:
        clean = _mask_comments(header)
        values = {}
        for side in ("SRC", "DST"):
            field = f"NVC3B5_SET_{side}_PHYS_MODE_TARGET"
            aperture = f"NVC3B5_SET_{side}_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM"
            field_matches = list(re.finditer(
                r"(?m)^\s*#\s*define\s+" + re.escape(field) + r"\s+([0-9]+:[0-9]+)\b",
                clean,
            ))
            value_matches = list(re.finditer(
                r"(?m)^\s*#\s*define\s+" + re.escape(aperture) +
                r"\s+\(?\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)?\s*$",
                clean,
            ))
            if (len(field_matches) != 1 or field_matches[0].group(1) != "1:0" or
                    len(value_matches) != 1 or int(value_matches[0].group(1), 0) != 2):
                raise ValueError(f"{label} GV100 C3B5 field width/value contract changed")
            values[f"{side.lower()}_target_field"] = field_matches[0].group(1)
            values[f"{side.lower()}_noncoherent_target"] = value_matches[0].group(1)
        return values

    legacy_fields = c3b5_contract(r580_c3b5_header, "R580")
    modern_fields = c3b5_contract(r595_c3b5_header, "R595")
    if legacy_fields != modern_fields:
        raise ValueError("R580 and R595 C3B5 headers disagree on the noncoherent target")

    clean = _mask_comments(volta_ce_source)
    functions = list(re.finditer(r"\bstatic\s+NvU32\s+ce_aperture\s*\(", clean))
    if len(functions) != 1:
        raise ValueError(f"expected one legacy ce_aperture definition; found {len(functions)}")
    opening = clean.find("{", functions[0].start())
    closing = _matching_brace(clean, opening)
    body = volta_ce_source[opening + 1:closing]
    if token in _mask_comments(body):
        raise ValueError("legacy ce_aperture already handles SYS_NON_COHERENT")

    coherent_check = re.compile(
        r"(?m)^(?P<indent>[ \t]*)BUILD_BUG_ON\(HWCONST\(C3B5, SET_SRC_PHYS_MODE, "
        r"TARGET, COHERENT_SYSMEM\) !=\n[ \t]*HWCONST\(C3B5, SET_DST_PHYS_MODE, "
        r"TARGET, COHERENT_SYSMEM\)\);"
    )
    check_matches = list(coherent_check.finditer(_mask_comments(body)))
    if len(check_matches) != 1:
        raise ValueError("legacy ce_aperture contract lacks one C3B5 coherent source/destination check")
    check = check_matches[0]
    indent = check.group("indent")
    noncoherent_check = (
        "\n" + indent + "BUILD_BUG_ON(HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, "
        "NONCOHERENT_SYSMEM) !=\n" + indent + "             "
        "HWCONST(C3B5, SET_DST_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM));"
    )
    body = body[:check.end()] + noncoherent_check + body[check.end():]

    routes = re.compile(
        r"(?m)^(?P<indent>[ \t]*)UVM_ASSERT_MSG\(aperture == UVM_APERTURE_VID "
        r"\|\| aperture == UVM_APERTURE_SYS,\s*\"aperture 0x%x\\n\", aperture\);\n\s*\n"
        r"(?P=indent)if \(aperture == UVM_APERTURE_SYS\)\n[ \t]*return "
        r"HWCONST\(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM\);\n"
        r"[ \t]*else\n[ \t]*return HWCONST\(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB\);"
    )
    route_matches = list(routes.finditer(_mask_comments(body)))
    if len(route_matches) != 1:
        raise ValueError("legacy ce_aperture contract differs from the expected SYS/VID routes")
    route = route_matches[0]
    indent = route.group("indent")
    inner = indent + "    "
    replacement = (
        f"{indent}UVM_ASSERT_MSG(aperture == UVM_APERTURE_VID ||\n"
        f"{inner}               aperture == UVM_APERTURE_SYS ||\n"
        f"{inner}               aperture == UVM_APERTURE_SYS_NON_COHERENT,\n"
        f"{inner}               \"aperture 0x%x\\n\", aperture);\n\n"
        f"{indent}if (aperture == UVM_APERTURE_SYS)\n"
        f"{inner}return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);\n"
        f"{indent}else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)\n"
        f"{inner}return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM);\n"
        f"{indent}else\n"
        f"{inner}return HWCONST(C3B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);"
    )
    body = body[:route.start()] + replacement + body[route.end():]
    adapted = volta_ce_source[:opening + 1] + body + volta_ce_source[closing:]
    if adapted == volta_ce_source:
        raise ValueError("SYS_NON_COHERENT CE adapter made no source change")

    return adapted, {
        "aperture": token,
        "class": "C3B5",
        "r580_c3b5_fields": legacy_fields,
        "r595_c3b5_fields": modern_fields,
        "gv100_c3b5_noncoherent_target_is_2": True,
        "src_dst_target_encodings_match": True,
        "coherent_and_vid_routes_preserved": True,
        "r580_c3b5_header_sha256": _sha256(r580_c3b5_header.encode()),
        "r595_c3b5_header_sha256": _sha256(r595_c3b5_header.encode()),
        "input_source_sha256": _sha256(volta_ce_source.encode()),
        "adapted_source_sha256": _sha256(adapted.encode()),
        "hardware_runtime_validated": False,
    }


def adapt_volta_shared_maxwell_ce_phys_mode(maxwell_ce_source: str,
                                            r580_b0b5_header: str,
                                            r595_b0b5_header: str,
                                            r580_c3b5_header: str,
                                            r595_c3b5_header: str,
                                            r595_hal_types: str,
                                            volta_phys_mode_callback: str) -> tuple[str, dict]:
    """Adapt the B0B5 helper R595 dispatches for Volta physical memcopies.

    R595's staged VOLTA_DMA_COPY_A row resolves phys_mode to the legacy
    Maxwell helper. Its B0B5 method IDs and aperture encodings must therefore
    match C3B5 before accepting SYS_NON_COHERENT addresses from the newer UVM
    path. This adds the NC branch only after validating both source releases
    and both class headers.
    """
    if volta_phys_mode_callback != "uvm_hal_maxwell_ce_phys_mode":
        raise ValueError("Volta CE phys_mode dispatch no longer uses the expected shared callback")
    if not re.search(r"\bUVM_APERTURE_SYS_NON_COHERENT\b",
                     _mask_comments(r595_hal_types)):
        raise ValueError("R595 UVM types lack SYS_NON_COHERENT aperture")

    def class_contract(header: str, class_name: str, label: str) -> dict[str, str]:
        clean = _mask_comments(header)
        prefix = "NV" + class_name
        contract = {}
        for side, expected_method in (("SRC", "0x00000260"), ("DST", "0x00000264")):
            rows = (
                ("method", f"{prefix}_SET_{side}_PHYS_MODE", r"\(?\s*(0[xX][0-9A-Fa-f]+)\s*\)?"),
                ("field", f"{prefix}_SET_{side}_PHYS_MODE_TARGET", r"([0-9]+:[0-9]+)"),
                ("local", f"{prefix}_SET_{side}_PHYS_MODE_TARGET_LOCAL_FB",
                 r"\(?\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)?"),
                ("coherent", f"{prefix}_SET_{side}_PHYS_MODE_TARGET_COHERENT_SYSMEM",
                 r"\(?\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)?"),
                ("noncoherent", f"{prefix}_SET_{side}_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM",
                 r"\(?\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)?"),
            )
            values = {}
            for key, macro, value_pattern in rows:
                matches = list(re.finditer(
                    r"(?m)^\s*#\s*define\s+" + re.escape(macro) +
                    r"\s+" + value_pattern + r"\s*$", clean))
                if len(matches) != 1:
                    raise ValueError(f"{label} {class_name} physical-mode field missing/duplicated: {macro}")
                values[key] = matches[0].group(1)
            numeric = {key: int(value, 0) for key, value in values.items()
                       if key != "field"}
            if (values["field"] != "1:0" or
                    numeric != {"method": int(expected_method, 16),
                                "local": 0, "coherent": 1, "noncoherent": 2}):
                raise ValueError(f"{label} {class_name} physical-mode method contract changed")
            contract[side.lower()] = values
        return contract

    legacy_b0b5 = class_contract(r580_b0b5_header, "B0B5", "R580")
    modern_b0b5 = class_contract(r595_b0b5_header, "B0B5", "R595")
    legacy_c3b5 = class_contract(r580_c3b5_header, "C3B5", "R580")
    modern_c3b5 = class_contract(r595_c3b5_header, "C3B5", "R595")
    if legacy_b0b5 != modern_b0b5 or legacy_c3b5 != modern_c3b5:
        raise ValueError("R580 and R595 B0B5/C3B5 physical-mode method contracts differ")
    if legacy_b0b5 != legacy_c3b5 or modern_b0b5 != modern_c3b5:
        raise ValueError("B0B5/C3B5 physical-mode method contract differs")

    clean = _mask_comments(maxwell_ce_source)
    aperture_functions = list(re.finditer(r"\bstatic\s+NvU32\s+ce_aperture\s*\(", clean))
    callback_functions = list(re.finditer(
        r"\bNvU32\s+uvm_hal_maxwell_ce_phys_mode\s*\(", clean))
    if len(aperture_functions) != 1 or len(callback_functions) != 1:
        raise ValueError("expected one legacy Maxwell ce_aperture and phys_mode callback")
    callback_open = clean.find("{", callback_functions[0].start())
    callback_close = _matching_brace(clean, callback_open)
    callback_body = re.sub(r"\s+", "", clean[callback_open + 1:callback_close])
    if ("ce_aperture(src.aperture)" not in callback_body or
            "ce_aperture(dst.aperture)" not in callback_body):
        raise ValueError("legacy Maxwell phys_mode callback no longer routes both operands through ce_aperture")

    opening = clean.find("{", aperture_functions[0].start())
    closing = _matching_brace(clean, opening)
    body = maxwell_ce_source[opening + 1:closing]
    if "UVM_APERTURE_SYS_NON_COHERENT" in _mask_comments(body):
        raise ValueError("legacy Maxwell ce_aperture already handles SYS_NON_COHERENT")

    coherent_check = re.compile(
        r"(?m)^(?P<indent>[ \t]*)BUILD_BUG_ON\(HWCONST\(B0B5, SET_SRC_PHYS_MODE, "
        r"TARGET, COHERENT_SYSMEM\) !=\n[ \t]*HWCONST\(B0B5, SET_DST_PHYS_MODE, "
        r"TARGET, COHERENT_SYSMEM\)\);"
    )
    checks = list(coherent_check.finditer(_mask_comments(body)))
    if len(checks) != 1:
        raise ValueError("legacy Maxwell ce_aperture contract lacks one B0B5 coherent src/dst check")
    check = checks[0]
    indent = check.group("indent")
    insertion = (
        "\n" + indent + "BUILD_BUG_ON(HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, "
        "NONCOHERENT_SYSMEM) !=\n" + indent + "             "
        "HWCONST(B0B5, SET_DST_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM));"
    )
    body = body[:check.end()] + insertion + body[check.end():]

    routes = re.compile(
        r"(?m)^(?P<indent>[ \t]*)UVM_ASSERT_MSG\(aperture == UVM_APERTURE_VID "
        r"\|\| aperture == UVM_APERTURE_SYS,\s*\"aperture 0x%x\\n\", aperture\);\n\s*\n"
        r"(?P=indent)if \(aperture == UVM_APERTURE_SYS\)\n[ \t]*return "
        r"HWCONST\(B0B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM\);\n"
        r"[ \t]*else\n[ \t]*return HWCONST\(B0B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB\);"
    )
    matches = list(routes.finditer(_mask_comments(body)))
    if len(matches) != 1:
        raise ValueError("legacy Maxwell ce_aperture contract differs from expected SYS/VID routes")
    route = matches[0]
    indent = route.group("indent")
    inner = indent + "    "
    replacement = (
        f"{indent}UVM_ASSERT_MSG(aperture == UVM_APERTURE_VID ||\n"
        f"{inner}               aperture == UVM_APERTURE_SYS ||\n"
        f"{inner}               aperture == UVM_APERTURE_SYS_NON_COHERENT,\n"
        f"{inner}               \"aperture 0x%x\\n\", aperture);\n\n"
        f"{indent}if (aperture == UVM_APERTURE_SYS)\n"
        f"{inner}return HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, COHERENT_SYSMEM);\n"
        f"{indent}else if (aperture == UVM_APERTURE_SYS_NON_COHERENT)\n"
        f"{inner}return HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, NONCOHERENT_SYSMEM);\n"
        f"{indent}else\n"
        f"{inner}return HWCONST(B0B5, SET_SRC_PHYS_MODE, TARGET, LOCAL_FB);"
    )
    body = body[:route.start()] + replacement + body[route.end():]
    adapted = maxwell_ce_source[:opening + 1] + body + maxwell_ce_source[closing:]
    if adapted == maxwell_ce_source:
        raise ValueError("shared Maxwell SYS_NON_COHERENT CE adapter made no source change")

    return adapted, {
        "volta_phys_mode_callback": volta_phys_mode_callback,
        "class_used_by_callback": "B0B5",
        "volta_copy_class": "C3B5",
        "b0b5_and_c3b5_method_contracts_match": True,
        "src_dst_target_encodings_match": True,
        "route_values": {"LOCAL_FB": 0, "COHERENT_SYSMEM": 1,
                         "NONCOHERENT_SYSMEM": 2},
        "r580_b0b5_header_sha256": _sha256(r580_b0b5_header.encode()),
        "r595_b0b5_header_sha256": _sha256(r595_b0b5_header.encode()),
        "r580_c3b5_header_sha256": _sha256(r580_c3b5_header.encode()),
        "r595_c3b5_header_sha256": _sha256(r595_c3b5_header.encode()),
        "input_source_sha256": _sha256(maxwell_ce_source.encode()),
        "adapted_source_sha256": _sha256(adapted.encode()),
        "hardware_runtime_validated": False,
    }


def adapt_gv100_plc_external_map_guard(modern_source: str,
                                       legacy_map_source: str,
                                       legacy_volta_source: str,
                                       modern_gpu_header: str,
                                       modern_uvm_types: str,
                                       modern_user_types: str,
                                       modern_arch_header: str) -> tuple[str, dict]:
    """Restore R580's pre-map PLC rejection for GV100 on the R595 path.

    The modern source has removed the per-GPU ``plc_supported`` property. Use
    the RM-reported GPU architecture already present in UvmGpuInfo, and reject
    only GV100 before VA validation, unmapping, allocation or RM PTE queries.
    """
    def function_body(source: str, name: str) -> str:
        clean = _mask_comments(source)
        functions = list(re.finditer(
            r"\b(?:static\s+)?NV_STATUS\s+" + re.escape(name) + r"\s*\(", clean))
        if len(functions) != 1:
            raise ValueError(f"expected one {name} definition; found {len(functions)}")
        opening = clean.find("{", functions[0].start())
        closing = _matching_brace(clean, opening)
        return source[opening + 1:closing]

    function_name = "uvm_map_external_allocation_on_gpu"
    legacy_body = _mask_comments(function_body(legacy_map_source, function_name))
    legacy_compact = re.sub(r"\s+", "", legacy_body)
    legacy_contract = (
        "if((map_rm_params->compression_type==UvmGpuCompressionTypeEnabledNoPlc)&&"
        "!mapping_gpu->parent->plc_supported)returnNV_ERR_INVALID_DEVICE;"
    )
    if ("parent_gpu->plc_supported=false;" not in
            re.sub(r"\s+", "", _mask_comments(legacy_volta_source)) or
            legacy_contract not in legacy_compact or
            legacy_compact.find(legacy_contract) >
            legacy_compact.find("uvm_gpu_can_address(")):
        raise ValueError("R580 PLC rejection contract or pre-map ordering changed")

    gpu_clean = _mask_comments(modern_gpu_header)
    gpu_struct = re.search(
        r"struct\s+uvm_parent_gpu_struct\s*\{([^}]*)\}", gpu_clean, re.DOTALL)
    info_type = re.search(
        r"typedef\s+struct\s+UvmGpuInfo_tag\s*\{([^}]*)\}\s*UvmGpuInfo\s*;",
        _mask_comments(modern_uvm_types), re.DOTALL)
    if (gpu_struct is None or
            not re.search(r"\bUvmGpuInfo\s+rm_info\s*;", gpu_struct.group(1)) or
            info_type is None or not re.search(r"\bNvU32\s+gpuArch\s*;", info_type.group(1))):
        raise ValueError("R595 parent GPU does not expose the RM architecture field")

    arch_macro = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100"
    arch_definitions = list(re.finditer(
        r"(?m)^\s*#\s*define\s+" + re.escape(arch_macro) +
        r"\s+\(?\s*(0[xX][0-9A-Fa-f]+)\s*\)?\b",
        _mask_comments(modern_arch_header),
    ))
    if len(arch_definitions) != 1 or int(arch_definitions[0].group(1), 16) != 0x140:
        raise ValueError("GV100 architecture value must be defined once as 0x140")

    clean = _mask_comments(modern_source)
    matches = list(re.finditer(
        r"\b(?:static\s+)?NV_STATUS\s+" + re.escape(function_name) + r"\s*\(", clean))
    if len(matches) != 1:
        raise ValueError(f"expected one modern {function_name} definition; found {len(matches)}")
    opening = clean.find("{", matches[0].start())
    closing = _matching_brace(clean, opening)
    signature = clean[matches[0].start():opening]
    body = modern_source[opening + 1:closing]
    body_clean = _mask_comments(body)
    if "plc_supported" in body_clean or re.search(
            r"UvmGpuCompressionTypeEnabledNoPlc[^;]*NV_ERR_INVALID_DEVICE", body_clean, re.DOTALL):
        raise ValueError("modern mapping function already has PLC guard")
    user_type_clean = _mask_comments(modern_user_types)
    compression_enum = re.search(
        r"typedef\s+enum\s*\{([^}]*)\}\s*UvmGpuCompressionType\s*;",
        user_type_clean, re.DOTALL)
    if (not re.search(
                r"const\s+uvm_map_rm_params_t\s*\*\s*map_rm_params\b", signature) or
            compression_enum is None or not re.search(
                r"\bUvmGpuCompressionTypeEnabledNoPlc\s*=\s*1\b",
                compression_enum.group(1))):
        raise ValueError("R595 mapping function lacks the NoPLC compression contract")

    anchor = list(re.finditer(
        r"(?m)^(?P<indent>[ \t]*)uvm_assert_rwsem_locked_read\s*\(\s*&va_space->lock\s*\)\s*;",
        body_clean,
    ))
    if len(anchor) != 1:
        raise ValueError("expected one mapping lock assertion anchor")
    mapping_side_effects = (
        "uvm_gpu_can_address(",
        "uvm_unmap_external_in_range(",
        "uvm_kvmalloc_zero(",
        "uvm_rm_locked_call(",
        "uvm_va_range_map_rm_allocation(",
    )
    if any(token not in body_clean for token in mapping_side_effects):
        raise ValueError("modern mapping side-effect order changed")

    indent = anchor[0].group("indent")
    inner = indent + "    "
    guard_statement = (
        f"{indent}if ((map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc) &&\n"
        f"{inner}(mapping_gpu->parent->rm_info.gpuArch == {arch_macro}))\n"
        f"{inner}return NV_ERR_INVALID_DEVICE;"
    )
    insertion = anchor[0].end()
    body = body[:insertion] + "\n\n" + guard_statement + body[insertion:]
    adapted = modern_source[:opening + 1] + body + modern_source[closing:]
    adapted_body = _mask_comments(function_body(adapted, function_name))
    adapted_guard_index = adapted_body.find(guard_statement)
    if adapted_guard_index < 0 or any(
            adapted_body.find(token) < adapted_guard_index for token in mapping_side_effects):
        raise ValueError("adapted GV100 PLC guard is not before every mapping side effect")

    return adapted, {
        "scope": "GV100 only",
        "legacy_volta_plc_supported": False,
        "legacy_status": "NV_ERR_INVALID_DEVICE",
        "architecture_macro": arch_macro,
        "architecture_value": 0x140,
        "guard_statement": guard_statement,
        "gv100_no_plc_rejected_before_mapping_side_effects": True,
        "r580_volta_plc_disabled": True,
        "other_gpu_architectures_unchanged": True,
        "input_source_sha256": _sha256(modern_source.encode()),
        "adapted_source_sha256": _sha256(adapted.encode()),
        "legacy_map_source_sha256": _sha256(legacy_map_source.encode()),
        "legacy_volta_source_sha256": _sha256(legacy_volta_source.encode()),
    }


def stage_legacy_subchannel_aliases(r580_macros: str, r595_macros: str,
                                    source_texts: dict[str, str]) -> tuple[str, dict]:
    """Map only used legacy class names through their exact R580 channel aliases."""
    def definitions(source: str) -> dict[str, str]:
        clean = _mask_comments(source)
        found = {}
        for match in re.finditer(
                r"(?m)^\s*#\s*define\s+UVM_SUBCHANNEL_([A-Za-z0-9_]+)\s+([^\n]+)",
                clean):
            name, value = match.group(1), match.group(2).strip()
            if name in found:
                raise ValueError(f"duplicate UVM subchannel definition: {name}")
            found[name] = value
        return found

    legacy_defs = definitions(r580_macros)
    modern_defs = definitions(r595_macros)
    used_classes = set()
    for source in source_texts.values():
        used_classes.update(re.findall(
            r"\bNV_PUSH_[A-Za-z0-9_]+\s*\(\s*([A-Za-z0-9_]+)\s*,",
            _mask_comments(source),
        ))
    added = {}
    already_compatible = []
    for class_name in sorted(used_classes):
        old_value = legacy_defs.get(class_name)
        if old_value is None:
            raise ValueError(f"R580 has no subchannel mapping for used class {class_name}")
        new_value = modern_defs.get(class_name)
        if new_value == old_value:
            already_compatible.append(class_name)
            continue
        if new_value is not None:
            raise ValueError(
                f"R595 subchannel mapping differs for {class_name}: "
                f"R580={old_value!r}; R595={new_value!r}"
            )
        if old_value not in {"UVM_SUBCHANNEL_HOST", "UVM_SUBCHANNEL_CE",
                             "UVM_SUBCHANNEL_SW", "UVM_SUBCHANNEL_SEC2"}:
            raise ValueError(
                f"refusing unsupported R580 subchannel target for {class_name}: {old_value}"
            )
        generic_class = old_value.removeprefix("UVM_SUBCHANNEL_")
        if generic_class not in modern_defs:
            raise ValueError(f"R595 does not define required generic subchannel {old_value}")
        added[class_name] = old_value

    if not added:
        return r595_macros, {
            "used_classes": sorted(used_classes),
            "added_aliases": {},
            "already_compatible": already_compatible,
        }
    modern_clean = _mask_comments(r595_macros)
    if re.search(r"(?m)^\s*#\s*endif\b[^\n]*", modern_clean) is None:
        raise ValueError("R595 push macro header has no include-guard #endif")
    insertion_match = list(re.finditer(r"(?m)^\s*#\s*endif\b[^\n]*", r595_macros))[-1]
    aliases = "\n/* Source-derived R580 class-to-subchannel aliases required by GV100 HAL callbacks. */\n"
    aliases += "".join(
        f"#define UVM_SUBCHANNEL_{name} {value}\n"
        for name, value in sorted(added.items())
    ) + "\n"
    updated = r595_macros[:insertion_match.start()] + aliases + r595_macros[insertion_match.start():]
    return updated, {
        "used_classes": sorted(used_classes),
        "added_aliases": added,
        "already_compatible": already_compatible,
    }


def _enum_numeric_value(header: str, enum_name: str, symbol: str) -> int:
    clean = _mask_comments(header)
    enum = re.search(
        r"typedef\s+enum\s*\{(?P<body>[^{}]*?)\}\s*" + re.escape(enum_name) + r"\s*;",
        clean,
    )
    if enum is None:
        raise ValueError(f"missing enum definition: {enum_name}")
    current = -1
    for item in enum.group("body").split(","):
        match = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*(?:=\s*(\d+))?\s*", item)
        if match is None:
            if item.strip():
                raise ValueError(f"unrecognized {enum_name} enumerator: {item.strip()!r}")
            continue
        current = int(match.group(2)) if match.group(2) is not None else current + 1
        if match.group(1) == symbol:
            return current
    raise ValueError(f"missing enum value {symbol} in {enum_name}")


def adapt_unsupported_access_counter_return(source: str,
                                            r580_hal_types: str,
                                            r595_hal_types: str) -> tuple[str, dict]:
    """Preserve the unreachable Maxwell unsupported callback's numeric fallback."""
    enum_name = "uvm_access_counter_clear_op_t"
    legacy_none = _enum_numeric_value(
        r580_hal_types, enum_name, "UVM_ACCESS_COUNTER_CLEAR_OP_NONE")
    modern_targeted = _enum_numeric_value(
        r595_hal_types, enum_name, "UVM_ACCESS_COUNTER_CLEAR_OP_TARGETED")
    if legacy_none != modern_targeted:
        raise ValueError(
            "access-counter enum numeric contract differs: "
            f"legacy NONE={legacy_none}; modern TARGETED={modern_targeted}"
        )
    symbol = "uvm_hal_maxwell_access_counter_query_clear_op_unsupported"
    pattern = re.compile(
        r"uvm_access_counter_clear_op_t\s+" + re.escape(symbol) +
        r"\s*\([^)]*\)\s*\{"
    )
    clean = _mask_comments(source)
    matches = list(pattern.finditer(clean))
    if len(matches) != 1:
        raise ValueError(f"expected one unsupported Maxwell callback; found {len(matches)}")
    opening = clean.find("{", matches[0].start(), matches[0].end())
    closing = _matching_brace(clean, opening)
    body = source[opening + 1:closing]
    body_clean = clean[opening + 1:closing]
    if not re.search(r"UVM_ASSERT_MSG\s*\(\s*false\s*,", body_clean):
        raise ValueError("unsupported Maxwell callback lost its fail-fast assertion")
    old_return = "return UVM_ACCESS_COUNTER_CLEAR_OP_NONE;"
    if body.count(old_return) != 1:
        raise ValueError("unsupported Maxwell callback has unexpected NONE return")
    adapted_body = body.replace(
        old_return, "return UVM_ACCESS_COUNTER_CLEAR_OP_TARGETED;", 1)
    adapted = source[:opening + 1] + adapted_body + source[closing:]
    return adapted, {
        "callback": symbol,
        "legacy_none_numeric_value": legacy_none,
        "modern_targeted_numeric_value": modern_targeted,
        "same_numeric_value": True,
        "fail_fast_assertion_preserved": True,
        "adaptation_scope": "return after unconditional unsupported-callback assertion only",
    }



def _extract_function_body(source: str, symbol: str, return_type: str,
                           *, is_static: bool = False) -> str:
    """Return one C function body, ignoring comments but retaining code text."""
    storage = r"static\s+" if is_static else r"(?:static\s+)?"
    pattern = re.compile(
        r"\b" + storage + re.escape(return_type) + r"\s+" + re.escape(symbol) +
        r"\s*\([^)]*\)\s*\{"
    )
    clean = _mask_comments(source)
    matches = list(pattern.finditer(clean))
    if len(matches) != 1:
        raise ValueError(
            f"expected one {symbol} function definition; found {len(matches)}")
    opening = clean.find("{", matches[0].start(), matches[0].end())
    closing = _matching_brace(clean, opening)
    return clean[opening + 1:closing]


def _has_parent_gpu_prefetch_capability(gpu_header: str) -> bool:
    """Return whether a parent-GPU struct contains the retired capability bit."""
    clean = _mask_comments(gpu_header)
    matches = list(re.finditer(r"\bstruct\s+uvm_parent_gpu_struct\s*\{", clean))
    if len(matches) != 1:
        raise ValueError("expected one R595 parent-GPU struct")
    opening = clean.find("{", matches[0].start(), matches[0].end())
    closing = _matching_brace(clean, opening)
    body = clean[opening + 1:closing]
    return bool(re.search(r"\bprefetch_fault_supported\b", body))


def _release_uvm_assert_is_elided(common_header: str) -> bool:
    """Recognize the pinned release UVM_ASSERT macro branch without preprocessing."""
    lines = common_header.splitlines()
    condition = "#if UVM_IS_DEBUG() || defined __COVERITY__"
    starts = [index for index, line in enumerate(lines)
              if line.strip() == condition]
    if len(starts) != 1:
        return False
    else_lines = [index for index in range(starts[0] + 1, len(lines))
                  if lines[index].strip() == "#else"]
    if len(else_lines) != 1:
        return False
    endif_lines = [index for index in range(else_lines[0] + 1, len(lines))
                   if lines[index].strip() == "#endif"]
    if len(endif_lines) != 1:
        return False
    release_branch = "\n".join(lines[else_lines[0] + 1:endif_lines[0]])
    return re.search(
        r'^\s*#define\s+UVM_ASSERT\s*\(\s*expr\s*\)\s+'
        r'UVM_ASSERT_MSG_IGNORE\s*\(\s*expr\s*,\s*"\\n"\s*\)',
        release_branch,
        re.MULTILINE,
    ) is not None


def audit_volta_prefetch_capability_contract(r580_volta_source: str,
                                             r580_common_header: str,
                                             r595_gpu_header: str,
                                             r595_volta_source: str,
                                             r595_hal_header: str,
                                             r595_common_header: str,
                                             r595_fault_source: str) -> dict:
    """Prove the smallest R595 Volta prefetch adaptation from pinned source.

    R580 marks GV100 as capable and asserts that invariant with UVM_ASSERT.
    In release builds that macro is explicitly elided; R595 instead initializes
    its runtime prefetch-enabled state before invoking its architecture HAL.
    The register actions are compared separately before selecting R595's
    existing Turing callbacks directly for the GV100 row.
    """
    if _has_parent_gpu_prefetch_capability(r595_gpu_header):
        raise ValueError("stock R595 unexpectedly contains the retired Volta capability bit")

    legacy_body = _extract_function_body(
        r580_volta_source, "uvm_hal_volta_arch_init_properties", "void")
    legacy_assert = re.compile(
        r"UVM_ASSERT\s*\(\s*parent_gpu\s*->\s*rm_info\s*\.\s*gpuArch\s*==\s*"
        r"NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100\s*\)\s*;"
    )
    if len(legacy_assert.findall(legacy_body)) != 1:
        raise ValueError("R580 GV100 property assertion changed")
    if len(re.findall(
            r"parent_gpu\s*->\s*prefetch_fault_supported\s*=\s*true\s*;",
            legacy_body)) != 1:
        raise ValueError("R580 no longer marks GV100 prefetch capability true")

    if not _release_uvm_assert_is_elided(r580_common_header):
        raise ValueError("R580 release UVM_ASSERT elision contract changed")
    if not _release_uvm_assert_is_elided(r595_common_header):
        raise ValueError("R595 release UVM_ASSERT elision contract changed")
    if re.search(r"\bprefetch_fault_supported\b", _mask_comments(r595_volta_source)):
        raise ValueError("stock R595 Volta source unexpectedly uses the retired capability bit")

    fault_init_pattern = re.compile(
        r"//\s*Re-enable fault prefetching just in case it was disabled in a previous run"
        r"\s*parent_gpu\s*->\s*fault_buffer\.prefetch_faults_enabled\s*=\s*true\s*;"
    )
    if len(fault_init_pattern.findall(r595_fault_source)) != 1:
        raise ValueError("R595 replayable-fault prefetch initialization changed")

    clean_hal = _mask_comments(r595_hal_header)
    turing_symbols = (
        "uvm_hal_turing_mmu_enable_prefetch_faults",
        "uvm_hal_turing_mmu_disable_prefetch_faults",
    )
    for symbol in turing_symbols:
        prototype = re.compile(
            r"\bvoid\s+" + re.escape(symbol) +
            r"\s*\(\s*uvm_parent_gpu_t\s*\*\s*parent_gpu\s*\)\s*;"
        )
        if len(prototype.findall(clean_hal)) != 1:
            raise ValueError(f"R595 Turing prefetch prototype changed: {symbol}")
    if re.search(r"uvm_hal_volta_mmu_(?:enable|disable)_prefetch_faults", clean_hal):
        raise ValueError("R595 unexpectedly declares a Volta prefetch wrapper")

    return {
        "r580_gv100_capability_true": True,
        "r580_enable_assert_is_debug_only_in_release": True,
        "r595_assert_is_debug_only_in_release": True,
        "r595_replayable_fault_init_enables_prefetch": True,
        "private_parent_gpu_capability_added": False,
        "volta_prefetch_wrapper_added": False,
        "runtime_or_hardware_validated": False,
        "source_sha256": {
        "r580_volta_source": _sha256(r580_volta_source.encode()),
        "r580_common_header": _sha256(r580_common_header.encode()),
            "r595_gpu_header": _sha256(r595_gpu_header.encode()),
            "r595_volta_source": _sha256(r595_volta_source.encode()),
            "r595_hal_header": _sha256(r595_hal_header.encode()),
            "r595_common_header": _sha256(r595_common_header.encode()),
            "r595_fault_source": _sha256(r595_fault_source.encode()),
        },
    }


def adapt_volta_prefetch_callbacks(callbacks_by_table: dict,
                                   r580_pascal_mmu_source: str,
                                   r595_turing_mmu_source: str,
                                   r595_hal_header: str,
                                   r595_gpu_header: str) -> tuple[dict, dict]:
    """Route GV100 to R595 callbacks after proving the register actions match.

    R580's Volta capability assertion is a debug invariant, not a release guard.
    R580 sets that capability true for GV100, while R595 initializes the active
    fault-buffer prefetch state true. Reuse the existing R595 callbacks directly.
    """
    table = callbacks_by_table.get("arch_table")
    if not isinstance(table, dict):
        raise ValueError("callback map has no arch_table")
    old_symbols = {
        "enable_prefetch_faults": "uvm_hal_pascal_mmu_enable_prefetch_faults",
        "disable_prefetch_faults": "uvm_hal_pascal_mmu_disable_prefetch_faults",
    }
    if any(table.get(operation) != symbol for operation, symbol in old_symbols.items()):
        raise ValueError("R580 arch_table prefetch callback mapping changed")
    if _has_parent_gpu_prefetch_capability(r595_gpu_header):
        raise ValueError("R595 overlay must not add the retired capability field")

    helper = "mmu_set_prefetch_faults"
    legacy_helper = _extract_function_body(
        r580_pascal_mmu_source, helper, "void", is_static=True)
    modern_helper = _extract_function_body(
        r595_turing_mmu_source, helper, "void", is_static=True)
    normalized = lambda body: re.sub(r"\s+", "", body)
    if normalized(legacy_helper) != normalized(modern_helper):
        raise ValueError("R580/R595 prefetch register helper differs")

    legacy_enable = _extract_function_body(
        r580_pascal_mmu_source, old_symbols["enable_prefetch_faults"], "void")
    modern_enable_symbol = "uvm_hal_turing_mmu_enable_prefetch_faults"
    modern_disable_symbol = "uvm_hal_turing_mmu_disable_prefetch_faults"
    modern_enable = _extract_function_body(
        r595_turing_mmu_source, modern_enable_symbol, "void")
    legacy_disable = _extract_function_body(
        r580_pascal_mmu_source, old_symbols["disable_prefetch_faults"], "void")
    modern_disable = _extract_function_body(
        r595_turing_mmu_source, modern_disable_symbol, "void")

    capability_assertion = re.compile(
        r"UVM_ASSERT\s*\(\s*parent_gpu\s*->\s*prefetch_fault_supported\s*\)\s*;"
    )
    if len(capability_assertion.findall(legacy_enable)) != 1:
        raise ValueError("R580 enable callback capability assertion changed")
    if re.search(r"\bprefetch_fault_supported\b", legacy_disable):
        raise ValueError("R580 disable callback unexpectedly gained a capability assertion")
    if re.search(r"\bprefetch_fault_supported\b",
                 r595_turing_mmu_source + r595_hal_header):
        raise ValueError("R595 shared Turing action unexpectedly owns retired capability state")
    legacy_enable_action = capability_assertion.sub("", legacy_enable)
    if normalized(legacy_enable_action) != normalized(modern_enable):
        raise ValueError("R580/R595 prefetch enable action differs")
    if normalized(legacy_disable) != normalized(modern_disable):
        raise ValueError("R580/R595 prefetch disable action differs")

    replacements = {
        "enable_prefetch_faults": modern_enable_symbol,
        "disable_prefetch_faults": modern_disable_symbol,
    }
    for symbol in replacements.values():
        declaration = extract_callback_prototype(r595_hal_header, symbol)
        expected = "void" + symbol + "(uvm_parent_gpu_t*parent_gpu);"
        if re.sub(r"\s+", "", declaration) != expected:
            raise ValueError(f"R595 callback prototype differs for {symbol}")

    adapted = {name: dict(operations)
               for name, operations in callbacks_by_table.items()}
    adapted["arch_table"].update(replacements)
    return adapted, {
        "legacy_callbacks": old_symbols,
        "selected_callbacks": replacements,
        "shared_register_helper_identical": True,
        "shared_register_helper_sha256": _sha256(
            normalized(legacy_helper).encode()),
        "enable_action_identical_after_assertion_removal": True,
        "disable_action_identical": True,
        "direct_r595_turing_callbacks_selected": True,
        "modern_callback_prototypes_verified": True,
        "runtime_support_proven": False,
        "source_sha256": {
            "r580_pascal_mmu": _sha256(r580_pascal_mmu_source.encode()),
            "r595_turing_mmu": _sha256(r595_turing_mmu_source.encode()),
            "r595_hal_header": _sha256(r595_hal_header.encode()),
            "r595_gpu_header": _sha256(r595_gpu_header.encode()),
        },
    }


def candidate_limitations() -> list[str]:
    """Return current limits without carrying claims from retired prototypes."""
    return [
        "This candidate is built only from pinned open-source R580/R595 UVM inputs and explicit rows; it is never installed or loaded.",
        "A complete HAL table set and successful link do not prove RM registration, runtime class IDs, callback semantics, fault recovery, memory coherency, UVM operation, or CUDA execution.",
        "The R595 no-argument MMU lookup is adapted through the R580 factory's valid 64K selector; the inherited page-size mask includes 2M/64K/4K and runtime behavior remains unvalidated.",
        "The reused compile adapter prunes R580 capability assignments and adapts two Pascal MMU signatures; resulting runtime semantics are unvalidated.",
        "Legacy host/CE class aliases and the unreachable Maxwell NONE enum fallback are adapted from the pinned R580 definitions; runtime command routing is unvalidated.",
        "The v12 GV100 row directly selects R595's existing Turing prefetch callbacks after pinned source comparison; no private capability field or Volta wrapper is added. The comparison establishes register-action equivalence only, not runtime behavior on Volta.",
        "Some inherited R580 callbacks are deliberately named unsupported or stub; they preserve the source-defined fallback and do not imply those features are supported.",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--r595-source", type=Path, default=DEFAULT_R595_SOURCE)
    parser.add_argument("--scratch", type=Path, required=True,
                        help="new isolated build tree; must not exist")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--kernel-uname",
                        help="explicit target Linux release (paired with --kernel-source)")
    parser.add_argument("--kernel-source", type=Path,
                        help="explicit Linux kernel source/output tree")
    parser.add_argument("--kernel-compiler", type=Path,
                        help="explicit compiler executable for the target kernel")
    parser.add_argument("--frontend-module-symvers", type=Path,
                        help="pin a hybrid frontend Module.symvers and build only nvidia-uvm")
    parser.add_argument("--expected-frontend-module-symvers-sha256",
                        help="required SHA-256 for --frontend-module-symvers")
    parser.add_argument("--expected-r580-sha256",
                        default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256)
    parser.add_argument(
        "--r580-source-root",
        choices=(R580_SOURCE_ROOT, "NVIDIA-kernel-module-source-580.196.07"),
        default=R580_SOURCE_ROOT,
        help="exact source root inside the hash-pinned R580 archive",
    )
    args = parser.parse_args()
    if (args.kernel_uname is None) != (args.kernel_source is None):
        parser.error("--kernel-uname and --kernel-source must be supplied together")
    try:
        frontend_symvers, expected_frontend_symvers_sha256, _ = (
            resolve_frontend_module_symvers(
                args.frontend_module_symvers,
                args.expected_frontend_module_symvers_sha256))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    archive = args.r580_archive.resolve(strict=True)
    r595 = args.r595_source.resolve(strict=True)
    scratch = args.scratch.resolve()
    report_path = args.report.resolve()
    log_path = args.log.resolve()
    if report_path.exists() or log_path.exists():
        parser.error("refusing to overwrite existing report or log")

    archive_hash = _sha256(archive.read_bytes())
    if archive_hash != args.expected_r580_sha256:
        parser.error("R580 archive does not match the pinned SHA-256")

    preparation = None
    fault_stage = None
    source_stage = None
    header_stage = None
    subchannel_stage = None
    counter_enum_stage = None
    row_stage = None
    prototype_stage = None
    mmu_adapter_stage = None
    shared_maxwell_ce_stage = None
    plc_guard_stage = None
    prefetch_capability_stage = None
    prefetch_adapter_stage = None
    dispatch_stage = None
    build_result = None
    module_audit = None
    legacy_linkage_stage = None
    legacy_linkage_audit = None
    error = None
    callback_source_map = {}
    added_sources = set()
    required_objects = set()
    callbacks_by_table = {}
    callbacks_for_module_audit = {}
    callback_symbols = set()
    with tempfile.TemporaryDirectory(prefix="r580-gv100-hal-input-") as temporary:
        temporary = Path(temporary)
        try:
            r580_fault_root = extract_archived_r580_uvm(
                archive, temporary / "r580-fault", args.r580_source_root)
            r580_all_c_root = extract_r580_uvm_c_sources(
                archive, temporary / "r580-all-c", args.r580_source_root)
            r580_hal = read_member_from_archive(
                archive, R580_HAL_MEMBER, args.r580_source_root)
            r580_header = read_member_from_archive(
                archive, R580_HAL_HEADER_MEMBER, args.r580_source_root)
            r595_hal = (r595 / "nvidia-uvm/uvm_hal.c").read_text()
            r595_table_source = compare_hal_tables(r580_hal, r595_hal)
            r580_tables = parse_hal_class_tables(r580_hal)
            callbacks_by_table = r595_table_source["r580_resolved_callbacks"]
            callback_symbols = {
                symbol for operations in callbacks_by_table.values()
                for symbol in operations.values()
            }
            callback_source_map = map_callback_definitions(r580_all_c_root, callback_symbols)
            if any(len(paths) != 1 for paths in callback_source_map.values()):
                raise ValueError("callback source census found missing or duplicate C definitions")
            all_sources = {paths[0] for paths in callback_source_map.values()}
            added_sources = all_sources - ALREADY_STAGED_SOURCES
            missing_source_names = sorted(name for name in added_sources
                                          if not (r580_all_c_root / name).is_file())
            if missing_source_names:
                raise ValueError(f"callback source files are missing: {missing_source_names}")

            preparation = prepare_overlay(
                archive, r595, scratch,
                expected_archive_sha256=args.expected_r580_sha256,
                expected_source_root=args.r580_source_root,
                compile_probe_adapter=True,
            )
            volta_source_path = scratch / "nvidia-uvm/uvm_volta_mmu.c"
            pascal_source_path = scratch / "nvidia-uvm/uvm_pascal_mmu.c"
            header_path = scratch / "nvidia-uvm/uvm_hal.h"
            volta_source_before = volta_source_path.read_text()
            pascal_source_for_contract = pascal_source_path.read_text()
            modern_header_before = header_path.read_text()
            adapted_volta, adapted_header, mmu_adapter_stage = add_volta_mmu_mode_adapter(
                volta_source_before, pascal_source_for_contract, modern_header_before)
            volta_dev_mmu_path = scratch / "nvidia-uvm/hwref/volta/gv100/dev_mmu.h"
            modern_hal_types_path = scratch / "nvidia-uvm/uvm_hal_types.h"
            adapted_volta, noncoherent_pte_stage = adapt_volta_noncoherent_mmu_pte(
                adapted_volta, volta_dev_mmu_path.read_text(),
                modern_hal_types_path.read_text())
            volta_source_path.write_text(adapted_volta)
            volta_ce_path = scratch / "nvidia-uvm/uvm_volta_ce.c"
            adapted_volta_ce, noncoherent_ce_stage = adapt_volta_noncoherent_ce_aperture(
                volta_ce_path.read_text(),
                read_member_from_archive(
                    archive, "kernel-open/nvidia-uvm/clc3b5.h",
                    args.r580_source_root),
                (scratch / "nvidia-uvm/clc3b5.h").read_text(),
                modern_hal_types_path.read_text(),
            )
            volta_ce_path.write_text(adapted_volta_ce)
            header_path.write_text(adapted_header)
            mmu_adapter_stage["input_volta_source_sha256"] = _sha256(
                volta_source_before.encode())
            mmu_adapter_stage["adapted_volta_source_sha256"] = _sha256(
                adapted_volta.encode())
            mmu_adapter_stage["input_r595_header_sha256"] = _sha256(
                modern_header_before.encode())
            mmu_adapter_stage["adapted_r595_header_sha256"] = _sha256(
                adapted_header.encode())
            mmu_adapter_stage["system_noncoherent_pte_adapter"] = noncoherent_pte_stage
            mmu_adapter_stage["system_noncoherent_ce_adapter"] = noncoherent_ce_stage
            gpu_header_path = scratch / "nvidia-uvm/uvm_gpu.h"
            volta_arch_source_path = scratch / "nvidia-uvm/uvm_volta.c"
            gpu_header_before_prefetch = gpu_header_path.read_text()
            volta_arch_source_before_prefetch = volta_arch_source_path.read_text()
            hal_header_before_prefetch = header_path.read_text()
            prefetch_capability_stage = audit_volta_prefetch_capability_contract(
                (r580_all_c_root / "uvm_volta.c").read_text(),
                read_member_from_archive(
                    archive, "kernel-open/nvidia-uvm/uvm_common.h",
                    args.r580_source_root),
                gpu_header_before_prefetch,
                volta_arch_source_before_prefetch,
                hal_header_before_prefetch,
                (scratch / "nvidia-uvm/uvm_common.h").read_text(),
                (scratch / "nvidia-uvm/uvm_gpu_replayable_faults.c").read_text(),
            )
            map_external_path = scratch / "nvidia-uvm/uvm_map_external.c"
            adapted_map_external, plc_guard_stage = adapt_gv100_plc_external_map_guard(
                map_external_path.read_text(),
                read_member_from_archive(
                    archive, "kernel-open/nvidia-uvm/uvm_map_external.c",
                    args.r580_source_root),
                read_member_from_archive(
                    archive, "kernel-open/nvidia-uvm/uvm_volta.c",
                    args.r580_source_root),
                (scratch / "nvidia-uvm/uvm_gpu.h").read_text(),
                (scratch / "common/inc/nv_uvm_types.h").read_text(),
                (scratch / "common/inc/nv_uvm_user_types.h").read_text(),
                (scratch / "nvidia-uvm/ctrl2080mc.h").read_text(),
            )
            map_external_path.write_text(adapted_map_external)
            fault_stage = stage_fault_hal_candidate(
                r580_fault_root, scratch / "nvidia-uvm", FAULT_CALLBACKS)
            source_stage = _stage_extra_sources(
                r580_all_c_root, scratch / "nvidia-uvm", added_sources)
            source_stage["source_sha256"] = _source_hashes(r580_all_c_root, added_sources)
            header_stage = stage_missing_archive_headers(
                archive, r580_all_c_root, scratch, scratch / "nvidia-uvm",
                added_sources, args.r580_source_root,
            )
            maxwell_ce_path = scratch / "nvidia-uvm/uvm_maxwell_ce.c"
            adapted_maxwell_ce, shared_maxwell_ce_stage = (
                adapt_volta_shared_maxwell_ce_phys_mode(
                    maxwell_ce_path.read_text(),
                    read_member_from_archive(
                        archive, "kernel-open/nvidia-uvm/clb0b5.h",
                        args.r580_source_root),
                    (scratch / "nvidia-uvm/clb0b5.h").read_text(),
                    read_member_from_archive(
                        archive, "kernel-open/nvidia-uvm/clc3b5.h",
                        args.r580_source_root),
                    (scratch / "nvidia-uvm/clc3b5.h").read_text(),
                    modern_hal_types_path.read_text(),
                    callbacks_by_table.get("ce_table", {}).get("phys_mode", ""),
                ))
            maxwell_ce_path.write_text(adapted_maxwell_ce)
            mmu_adapter_stage["shared_maxwell_phys_mode_ce_adapter"] = shared_maxwell_ce_stage
            push_macros_path = scratch / "nvidia-uvm/uvm_push_macros.h"
            modern_push_macros = push_macros_path.read_text()
            legacy_push_macros = read_member_from_archive(
                archive, "kernel-open/nvidia-uvm/uvm_push_macros.h",
                args.r580_source_root)
            added_source_texts = {
                name: (scratch / "nvidia-uvm" / name).read_text()
                for name in sorted(added_sources)
            }
            adapted_push_macros, subchannel_stage = stage_legacy_subchannel_aliases(
                legacy_push_macros, modern_push_macros, added_source_texts)
            push_macros_path.write_text(adapted_push_macros)
            subchannel_stage["input_header_sha256"] = _sha256(
                modern_push_macros.encode())
            subchannel_stage["adapted_header_sha256"] = _sha256(
                adapted_push_macros.encode())

            maxwell_host_path = scratch / "nvidia-uvm/uvm_maxwell_host.c"
            maxwell_host_source = maxwell_host_path.read_text()
            legacy_hal_types = read_member_from_archive(
                archive, "kernel-open/nvidia-uvm/uvm_hal_types.h",
                args.r580_source_root)
            modern_hal_types = (scratch / "nvidia-uvm/uvm_hal_types.h").read_text()
            adapted_maxwell_host, counter_enum_stage = adapt_unsupported_access_counter_return(
                maxwell_host_source, legacy_hal_types, modern_hal_types)
            maxwell_host_path.write_text(adapted_maxwell_host)
            counter_enum_stage["input_source_sha256"] = _sha256(
                maxwell_host_source.encode())
            counter_enum_stage["adapted_source_sha256"] = _sha256(
                adapted_maxwell_host.encode())
            row_callbacks_by_table = {
                table: dict(operations)
                for table, operations in callbacks_by_table.items()
            }
            row_callbacks_by_table["arch_table"]["mmu_mode_hal"] = VOLTA_MMU_R595_ADAPTER
            row_callbacks_by_table, prefetch_adapter_stage = adapt_volta_prefetch_callbacks(
                row_callbacks_by_table,
                (r580_all_c_root / "uvm_pascal_mmu.c").read_text(),
                (scratch / "nvidia-uvm/uvm_turing_mmu.c").read_text(),
                header_path.read_text(),
                gpu_header_path.read_text(),
            )
            callbacks_for_module_audit = row_callbacks_by_table
            row_stage = stage_complete_hal_rows(
                r580_tables, row_callbacks_by_table, scratch / "nvidia-uvm")
            dispatch_stage = audit_staged_gv100_dispatch(
                (scratch / "nvidia-uvm/uvm_hal.c").read_text())
            if not dispatch_stage["static_dispatch_candidate"]:
                raise ValueError(
                    "staged GV100 UVM rows are not selectable through all six "
                    f"R595 HAL routes: {dispatch_stage['errors']}"
                )
            merged_header, prototype_stage = merge_callback_prototypes(
                r580_header, header_path.read_text(), callback_symbols)
            header_path.write_text(merged_header)
            legacy_linkage_stage = localize_unreferenced_hal_helpers(
                scratch / "nvidia-uvm", all_sources,
                R580_ORPHAN_HAL_HELPERS,
                referenced_symbols=callback_symbols,
            )
            build_result = build_overlay(
                scratch, args.jobs, compile_probe_adapter=True,
                frontend_module_symvers=frontend_symvers,
                expected_frontend_symvers_sha256=(
                    expected_frontend_symvers_sha256
                ),
                kernel_uname=args.kernel_uname,
                kernel_source=args.kernel_source,
                kernel_compiler=args.kernel_compiler,
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

    candidate_linked = bool(build_result and build_result.get("module_linked_this_run"))
    compiled_objects = []
    if build_result and Path(build_result["build_log"]).is_file():
        build_text = Path(build_result["build_log"]).read_text(errors="replace")
        compiled_objects = re.findall(
            r"^\s*CC \[M\]\s+(?:\S*/)?(nvidia-uvm/[^\s]+\.o)",
            build_text, re.M)
        required_objects = {
            "nvidia-uvm/uvm_hal.o",
            "nvidia-uvm/uvm_volta_fault_buffer.o",
            "nvidia-uvm/uvm_pascal_fault_buffer.o",
            *(f"nvidia-uvm/{Path(name).stem}.o" for name in VOLTA_OBJECT_SOURCES),
            "nvidia-uvm/uvm_pascal_mmu.o",
            *(f"nvidia-uvm/{Path(name).stem}.o" for name in added_sources),
        }
        if candidate_linked:
            module_path = scratch / "nvidia-uvm.ko"
            nm = subprocess.run(
                ["nm", "--defined-only", str(module_path)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False,
            )
            if nm.returncode == 0:
                module_audit = audit_module_symbols(callbacks_for_module_audit, nm.stdout)
                defined_symbols = {
                    fields[-1] for line in nm.stdout.splitlines()
                    if len(fields := line.split()) >= 2
                    and fields[-2] not in {"U", "u", "w", "v"}
                }
                module_audit["r595_api_adapters"] = {
                    VOLTA_MMU_R595_ADAPTER: VOLTA_MMU_R595_ADAPTER in defined_symbols,
                }
                object_paths = sorted(scratch.rglob("*.o"))
                legacy_linkage_audit = audit_private_hal_helper_linkage(
                    module_path, object_paths, R580_ORPHAN_HAL_HELPERS)
            else:
                error = f"nm failed: {nm.stdout[-2000:]}"
                candidate_linked = False

    if build_result and not (required_objects <= set(compiled_objects)):
        candidate_linked = False
    if module_audit and not module_audit["all_callbacks_defined"]:
        candidate_linked = False
    if module_audit and not all(module_audit["r595_api_adapters"].values()):
        candidate_linked = False
    if legacy_linkage_audit and not legacy_linkage_audit["passed"]:
        candidate_linked = False
    success = candidate_linked and error is None

    if build_result and Path(build_result["build_log"]).is_file():
        log_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build_result["build_log"], log_path)
    else:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text((error or "Candidate staging did not produce a build log") + "\n")
    os.chmod(log_path, 0o600)
    log_hash = _sha256(log_path.read_bytes())
    report = {
        "schema": "r595-gv100-complete-hal-probe-v12",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if success else "failed",
        "classification": "isolated-complete-gv100-uvm-hal-compile-link-probe-only",
        "r580_archive": str(archive),
        "r580_archive_sha256": archive_hash,
        "r580_source_root": args.r580_source_root,
        "expected_r580_archive_sha256": args.expected_r580_sha256,
        "r595_source": str(r595),
        "scratch": str(scratch),
        "preparation": preparation,
        "r580_resolved_callback_count": len(callback_symbols),
        "r580_resolved_callbacks_by_table": callbacks_by_table if preparation else None,
        "callback_source_map": callback_source_map,
        "additional_source_files": sorted(added_sources),
        "additional_source_hashes": source_stage.get("source_sha256") if source_stage else None,
        "source_staging": source_stage,
        "legacy_header_dependency_staging": header_stage,
        "legacy_subchannel_alias_adaptation": subchannel_stage,
        "unsupported_access_counter_enum_adaptation": counter_enum_stage,
        "fault_buffer_row_staging": fault_stage,
        "complete_hal_row_staging": row_stage,
        "static_gv100_dispatch_audit": dispatch_stage,
        "modern_mmu_callback_adapter": mmu_adapter_stage,
        "volta_plc_external_map_guard": plc_guard_stage,
        "volta_prefetch_capability_contract": prefetch_capability_stage,
        "modern_prefetch_callback_adaptation": prefetch_adapter_stage,
        "staged_row_callbacks_by_table": callbacks_for_module_audit if preparation else None,
        "prototype_staging": prototype_stage,
        "unreferenced_legacy_hal_linkage_localization": legacy_linkage_stage,
        "unreferenced_legacy_hal_linkage_audit": legacy_linkage_audit,
        "build": build_result,
        "compiled_candidate_objects": sorted(required_objects & set(compiled_objects)),
        "required_candidate_objects": sorted(required_objects),
        "candidate_module": {
            "path": str(scratch / "nvidia-uvm.ko"),
            "linked_this_run": candidate_linked,
            "sha256": (build_result.get("module_sha256") if build_result else None),
            "symbol_audit": module_audit,
        },
        "module_loaded": False,
        "module_installed": False,
        "hardware_validated": False,
        "error": error,
        "build_log_copy": str(log_path),
        "build_log_sha256": log_hash,
        "limitations": candidate_limitations(),
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({
        "status": report["status"],
        "report": str(report_path),
        "report_sha256": _sha256(report_path.read_bytes()),
        "log": str(log_path),
        "log_sha256": log_hash,
        "source_dispatch_rows_staged": row_stage,
        "static_gv100_dispatch_candidate": (
            dispatch_stage["static_dispatch_candidate"] if dispatch_stage else None),
        "modern_mmu_callback_adapter": mmu_adapter_stage,
        "additional_source_files": sorted(added_sources),
        "additional_header_files": header_stage["added_headers"] if header_stage else None,
        "module_linked": candidate_linked,
        "all_callbacks_defined": (module_audit["all_callbacks_defined"]
                                   if module_audit else None),
        "orphan_hal_helpers_localized": (
            len(legacy_linkage_stage["localized_symbols"])
            if legacy_linkage_stage else None),
        "orphan_hal_linkage_audit_passed": (
            legacy_linkage_audit["passed"] if legacy_linkage_audit else None),
        "error": error,
    }, indent=2))
    return 0 if success else 2


def read_member_from_archive(archive_path: Path, relative: str,
                             expected_root: str = R580_SOURCE_ROOT) -> str:
    with tarfile.open(archive_path, "r:*") as archive:
        root = source_archive_root(archive, expected_root)
        return read_member(archive, root + "/" + relative).decode("utf-8", errors="strict")


def _matching_brace(source: str, opening: int) -> int:
    masked = _mask_comments(source)
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unbalanced HAL table initializer")


def audit_module_symbols(callbacks_by_table: dict, nm_output: str) -> dict:
    defined = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] not in {"U", "u", "w", "v"}:
            defined.add(fields[-1])
    tables = {}
    for table, callback_map in callbacks_by_table.items():
        expected = set(callback_map.values())
        missing = expected - defined
        tables[table] = {
            "expected_count": len(expected),
            "defined_count": len(expected & defined),
            "missing_symbols": sorted(missing),
            "complete": not missing,
        }
    return {
        "defined_symbol_count": len(defined),
        "all_callbacks_defined": all(value["complete"] for value in tables.values()),
        "tables": tables,
    }


if __name__ == "__main__":
    raise SystemExit(main())
