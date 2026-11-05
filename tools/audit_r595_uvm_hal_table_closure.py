#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare pinned R580 and installed R595 UVM architecture HAL tables."""
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
import tarfile
import tempfile
from pathlib import PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    DEFAULT_R595_SOURCE,
    read_member,
    R580_SOURCE_ROOT,
)
from tools.audit_hybrid_uvm_abi import c_function_definition  # noqa: E402

R580_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
R580_HAL_MEMBER = "kernel-open/nvidia-uvm/uvm_hal.c"
R580_GPU_OPS_MEMBER = "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c"
R595_HAL_RELATIVE = Path("nvidia-uvm/uvm_hal.c")

# These are the architecture-class tables selected for each GV100 UVM HAL.
# chip_table is intentionally omitted: its rows are implementation overrides,
# such as GB10B, rather than a required Volta class row.
REQUIRED_GV100_TABLE_TARGETS = {
    "ce_table": "VOLTA_DMA_COPY_A",
    "host_table": "VOLTA_CHANNEL_GPFIFO_A",
    "arch_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    "fault_buffer_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    "access_counter_buffer_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    "sec2_table": "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
}
SELECTOR_EXPECTATIONS = {
    "ce_table": ("gpu_info->ceClass", "ce_hal", "ce_ops"),
    "host_table": ("gpu_info->hostClass", "host_hal", "host_ops"),
    "arch_table": ("gpu_info->gpuArch", "arch_hal", "arch_ops"),
    "fault_buffer_table": ("gpu_info->gpuArch", "fault_buffer_hal", "fault_buffer_ops"),
    "access_counter_buffer_table": (
        "gpu_info->gpuArch", "access_counter_buffer_hal", "access_counter_buffer_ops"),
    "sec2_table": ("gpu_info->gpuArch", "sec2_hal", "sec2_ops"),
}


def _strip_comments(source: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unbalanced HAL table initializer")


def parse_hal_class_tables(source: str) -> dict[str, list[dict]]:
    """Parse every static uvm_hal_class_ops_t table and its initializer rows."""
    source = _strip_comments(source)
    declaration = re.compile(
        r"static\s+uvm_hal_class_ops_t\s+(\w+_table)\s*\[\s*\]\s*=\s*\{"
    )
    tables = {}
    for match in declaration.finditer(source):
        name = match.group(1)
        if name in tables:
            raise ValueError(f"duplicate HAL table declaration: {name}")
        outer_open = match.end() - 1
        outer_close = _matching_brace(source, outer_open)
        rows = []
        depth = 0
        row_start = None
        for index in range(outer_open, outer_close + 1):
            char = source[index]
            if char == "{":
                depth += 1
                if depth == 2:
                    row_start = index
            elif char == "}":
                if depth == 2 and row_start is not None:
                    row = source[row_start:index + 1]
                    row_id = re.search(r"\.id\s*=\s*([^,]+)", row)
                    if row_id is None:
                        raise ValueError(f"HAL table {name} contains a row without .id")
                    parent = re.search(r"\.parent_id\s*=\s*([^,]+)", row)
                    union = re.search(r"\.u\.(\w+)\s*=", row)
                    union_assignments = {}
                    if union:
                        union_open = row.find("{", union.start())
                        if union_open >= 0:
                            union_close = _matching_brace(row, union_open)
                            union_assignments = dict(re.findall(
                                r"\.(\w+)\s*=\s*([A-Za-z_]\w*)\s*,",
                                row[union_open + 1:union_close],
                            ))
                    rows.append({
                        "id": row_id.group(1).strip(),
                        "parent_id": parent.group(1).strip() if parent else None,
                        "union": union.group(1) if union else None,
                        "assignments": union_assignments,
                    })
                    row_start = None
                depth -= 1
        ids = [row["id"] for row in rows]
        if len(ids) != len(set(ids)):
            raise ValueError(f"HAL table {name} has duplicate row id")
        if not rows:
            raise ValueError(f"HAL table {name} has no initializer rows")
        tables[name] = rows
    if not tables:
        raise ValueError("no static uvm_hal_class_ops_t tables found")
    return tables


def _resolve_table_row_callbacks(rows: list[dict], target_id: str) -> dict[str, str]:
    row_by_id = {row["id"]: row for row in rows}
    if target_id not in row_by_id:
        raise ValueError(f"HAL table does not contain requested target row: {target_id}")
    resolved = {}
    visiting = set()

    def resolve(row_id: str) -> dict[str, str]:
        if row_id in resolved:
            return resolved[row_id]
        if row_id in visiting:
            raise ValueError(f"HAL table inheritance cycle at {row_id}")
        if row_id not in row_by_id:
            raise ValueError(f"HAL table inheritance parent is missing: {row_id}")
        visiting.add(row_id)
        row = row_by_id[row_id]
        callbacks = resolve(row["parent_id"]).copy() if row["parent_id"] else {}
        callbacks.update({name: symbol for name, symbol in row["assignments"].items()
                          if symbol != "NULL"})
        visiting.remove(row_id)
        resolved[row_id] = callbacks
        return callbacks

    return resolve(target_id)


def audit_candidate_module_symbols(callbacks_by_table: dict[str, dict[str, str]],
                                   nm_output: str) -> dict:
    """Compare resolved source callbacks with defined symbols in an ELF module."""
    defined = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol_type, symbol_name = fields[-2], fields[-1]
        if symbol_type not in {"U", "u", "w", "v"}:
            defined.add(symbol_name)
    tables = {}
    for table, operation_map in sorted(callbacks_by_table.items()):
        expected = set(operation_map.values()) - {"NULL"}
        present = expected & defined
        missing = expected - defined
        tables[table] = {
            "callback_count": len(expected),
            "defined_symbols": sorted(present),
            "missing_symbols": sorted(missing),
            "all_callbacks_defined": not missing,
        }
    return {
        "module_defined_symbol_count": len(defined),
        "all_callbacks_defined": bool(tables) and all(
            item["all_callbacks_defined"] for item in tables.values()),
        "tables": tables,
    }


def map_callback_definitions(source_root: Path,
                              callback_symbols: set[str]) -> dict[str, list[str]]:
    """Find actual function bodies in extracted source files, not prototypes/calls."""
    source_root = Path(source_root).resolve(strict=True)
    found = {symbol: [] for symbol in callback_symbols}
    for source_path in sorted(source_root.rglob("*.c")):
        source_text = source_path.read_text(encoding="utf-8", errors="strict")
        for symbol in callback_symbols:
            if symbol in source_text:
                try:
                    c_function_definition(source_path, symbol)
                except RuntimeError:
                    continue
                found[symbol].append(source_path.relative_to(source_root).as_posix())
    return found


def checked_source_archive_root(archive: tarfile.TarFile,
                                expected_root: str = R580_SOURCE_ROOT) -> str:
    """Accept only one source root matching the caller's hash-pinned version."""
    suffix = "/kernel-open/nvidia-uvm/uvm_volta.c"
    matches = [member.name[:-len(suffix)] for member in archive.getmembers()
               if member.name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(
            "archive must contain exactly one R580 kernel-open Volta UVM tree")
    if matches[0] != expected_root:
        raise ValueError(
            f"unexpected source root {matches[0]!r}; expected {expected_root!r}")
    return matches[0]


def extract_r580_uvm_c_sources(archive_path: Path, destination: Path,
                               expected_root: str = R580_SOURCE_ROOT) -> Path:
    """Extract pinned UVM C files with a path traversal check."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:*") as archive:
        root = checked_source_archive_root(archive, expected_root)
        prefix = root + "/kernel-open/nvidia-uvm/"
        for member in archive.getmembers():
            if not member.isfile() or not member.name.startswith(prefix) or not member.name.endswith(".c"):
                continue
            relative = PurePosixPath(member.name[len(prefix):])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe UVM C source archive path: {member.name}")
            output = destination.joinpath(*relative.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(read_member(archive, member.name))
    return destination


def parse_gpu_hal_selector_contract(source: str) -> dict[str, dict]:
    """Verify each required table lookup rejects a missing class before use."""
    source = _strip_comments(source)
    function = re.search(r"NV_STATUS\s+uvm_hal_init_gpu\s*\([^)]*\)\s*\{", source)
    if function is None:
        raise ValueError("uvm_hal_init_gpu function is missing")
    opening = source.find("{", function.start(), function.end())
    closing = _matching_brace(source, opening)
    body = source[opening + 1:closing]
    result = {}
    for table, (class_field, hal_member, union_member) in SELECTOR_EXPECTATIONS.items():
        lookup_re = re.compile(
            r"class_ops\s*=\s*ops_find_by_id\s*\(\s*" +
            re.escape(table) + r"\s*,(?P<args>.*?)\);", re.DOTALL)
        matches = list(lookup_re.finditer(body))
        if len(matches) != 1:
            raise ValueError(f"expected one {table} lookup in uvm_hal_init_gpu")
        lookup = matches[0]
        if class_field not in lookup.group("args"):
            raise ValueError(f"{table} lookup does not use {class_field}")
        tail = body[lookup.end():]
        assignment = re.search(
            r"parent_gpu\s*->\s*" + re.escape(hal_member) +
            r"\s*=\s*&class_ops\s*->\s*u\." +
            re.escape(union_member) + r"\s*;", tail)
        if assignment is None:
            raise ValueError(f"{table} lookup does not install its HAL pointer")
        check = re.search(r"if\s*\(\s*class_ops\s*==\s*NULL\s*\)\s*\{", tail[:assignment.start()])
        if check is None:
            raise ValueError(f"{table} lookup uses a possibly null HAL pointer")
        check_open = tail.find("{", check.start(), check.end())
        check_close = _matching_brace(tail, check_open)
        failure_block = tail[check_open + 1:check_close]
        status = re.search(r"return\s+(NV_ERR_[A-Z0-9_]+)\s*;", failure_block)
        if status is None or status.group(1) != "NV_ERR_INVALID_CLASS":
            raise ValueError(f"{table} does not fail on an absent class with NV_ERR_INVALID_CLASS")
        result[table] = {
            "class_id_field": class_field,
            "missing_class_status": status.group(1),
            "null_checked_before_install": True,
            "installed_pointer": f"parent_gpu->{hal_member} -> u.{union_member}",
            "installs_hal_pointer": True,
        }
    return result


def parse_r580_gpu_info_producer_contract(source: str) -> dict:
    """Check the pinned RM source path that supplies UVM's HAL selector keys.

    This is a source-shape contract only. In particular, the class-list query
    does not prove which values a live RM instance returns for a GV100.
    """
    with tempfile.TemporaryDirectory(prefix="r580-gpu-info-source-") as temporary:
        source_path = Path(temporary) / "nv_gpu_ops.c"
        source_path.write_text(source, encoding="utf-8")
        functions = {
            name: c_function_definition(source_path, name)
            for name in ("nvGpuOpsGetGpuInfo", "findDeviceClasses",
                         "isClassHost", "isClassCE", "isClassCompute")
        }

    producer = _strip_comments(functions["nvGpuOpsGetGpuInfo"])
    classes = _strip_comments(functions["findDeviceClasses"])
    host = _strip_comments(functions["isClassHost"])
    ce = _strip_comments(functions["isClassCE"])
    compute = _strip_comments(functions["isClassCompute"])

    arch_query = re.search(
        r"pRmApi\s*->\s*Control\s*\([^;]*"
        r"NV2080_CTRL_CMD_MC_GET_ARCH_INFO[^;]*\)", producer, re.DOTALL)
    arch_assignment = re.search(
        r"pGpuInfo\s*->\s*gpuArch\s*=\s*archInfoParams\.architecture\s*;",
        producer)
    if arch_query is None or arch_assignment is None or arch_query.start() >= arch_assignment.start():
        raise ValueError("R580 GPU-info producer does not source gpuArch from MC_GET_ARCH_INFO")
    if "subDeviceHandle" not in arch_query.group(0) or "&archInfoParams" not in arch_query.group(0):
        raise ValueError("R580 MC_GET_ARCH_INFO query does not use the subdevice architecture payload")
    checked_status = re.search(
        r"if\s*\(\s*NV_OK\s*!=\s*status\s*\)\s*goto\s+cleanup\s*;",
        producer[arch_query.end():arch_assignment.start()])
    if checked_status is None:
        raise ValueError("R580 GPU-info producer does not check MC_GET_ARCH_INFO status")

    class_call = re.search(r"\bfindDeviceClasses\s*\((?P<args>[^;]*?)\)\s*;",
                           producer, re.DOTALL)
    if class_call is None:
        raise ValueError("R580 GPU-info producer does not query RM device classes")
    class_args = class_call.group("args")
    for field in ("hostClass", "ceClass", "computeClass"):
        if not re.search(r"&\s*pGpuInfo\s*->\s*" + re.escape(field) + r"\b",
                         class_args):
            raise ValueError(f"R580 GPU-info producer does not populate {field}")
    if class_call.start() < arch_assignment.end():
        raise ValueError("R580 GPU-info producer queries classes before assigning gpuArch")

    class_list_queries = list(re.finditer(
        r"pRmApi\s*->\s*Control\s*\([^;]*"
        r"NV0080_CTRL_CMD_GPU_GET_CLASSLIST[^;]*\)\s*;",
        classes, re.DOTALL))
    if len(class_list_queries) != 2 or "classParams.classList" not in classes:
        raise ValueError("R580 findDeviceClasses must size then read the RM class list")
    allocation = re.search(r"classList\s*=\s*portMemAllocNonPaged\s*\(", classes)
    scan = re.search(r"for\s*\(\s*i\s*=\s*0\s*;", classes)
    if allocation is None or scan is None:
        raise ValueError("R580 class-list query is missing its allocation or scan")
    first_query_guard = re.search(
        r"if\s*\(\s*(?:status\s*!=\s*NV_OK|NV_OK\s*!=\s*status)\s*\)\s*"
        r"return\s+status\s*;",
        classes[class_list_queries[0].end():allocation.start()])
    if first_query_guard is None:
        raise ValueError("R580 class-list sizing query does not propagate RM errors")
    class_pointer = re.search(r"classParams\.classList\s*=\s*", classes)
    if class_pointer is None or not (
            allocation.start() < class_pointer.start() < class_list_queries[1].start()):
        raise ValueError("R580 class-list read does not install its allocated output buffer")
    allocation_guard = re.search(
        r"if\s*\(\s*classList\s*==\s*NULL\s*\)\s*"
        r"(?:\{\s*return\s+NV_ERR_INSUFFICIENT_RESOURCES\s*;\s*\}|"
        r"return\s+NV_ERR_INSUFFICIENT_RESOURCES\s*;)",
        classes[allocation.end():class_pointer.start()])
    if allocation_guard is None:
        raise ValueError("R580 class-list allocation is not checked before use")
    second_query_guard = re.search(
        r"if\s*\(\s*(?:status\s*!=\s*NV_OK|NV_OK\s*!=\s*status)\s*\)\s*"
        r"goto\s+Cleanup_classlist\s*;",
        classes[class_list_queries[1].end():scan.start()])
    if second_query_guard is None:
        raise ValueError("R580 class-list read does not fail closed before scanning results")
    cleanup_label = re.search(r"\bCleanup_classlist\s*:\s*(?P<body>.*)",
                              classes, re.DOTALL)
    if cleanup_label is None:
        raise ValueError("R580 class-list error path has no shared cleanup label")
    cleanup_body = cleanup_label.group("body")
    cleanup_free = re.search(r"portMemFree\s*\(\s*classList\s*\)\s*;",
                             cleanup_body)
    cleanup_return = re.search(r"return\s+status\s*;", cleanup_body)
    if (cleanup_free is None or cleanup_return is None or
            cleanup_free.start() >= cleanup_return.start()):
        raise ValueError("R580 class-list cleanup does not free its buffer before returning")
    producer_next_query = re.search(
        r"pRmApi\s*->\s*Control\s*\(", producer[class_call.end():])
    producer_guard_region = producer[
        class_call.end():class_call.end() + producer_next_query.start()
        if producer_next_query else len(producer)]
    producer_class_guard = re.search(
        r"if\s*\(\s*(?:status\s*!=\s*NV_OK|NV_OK\s*!=\s*status)\s*\)\s*"
        r"goto\s+cleanup\s*;", producer_guard_region)
    if producer_class_guard is None:
        raise ValueError("R580 GPU-info producer does not stop and clean up on class-query failure")
    for field, predicate in (("hostClass", "isClassHost"),
                             ("ceClass", "isClassCE"),
                             ("computeClass", "isClassCompute")):
        classification = re.search(
            r"\b" + predicate + r"\s*\(\s*classList\s*\[\s*i\s*\]\s*\)"
            r"[^;]*\*\s*" + field + r"\s*=\s*NV_MAX\s*\(", classes)
        if classification is None:
            raise ValueError(f"R580 class-list scan does not select {field} via {predicate}")
    if not re.search(r"CliGetChannelClassInfo\s*\(\s*class\s*,\s*&\s*classInfo\s*\)", host):
        raise ValueError("R580 host-class predicate does not query channel class metadata")
    if not re.search(
            r"classInfo\.classType\s*==\s*CHANNEL_CLASS_TYPE_GPFIFO", host):
        raise ValueError("R580 host-class predicate does not select GPFIFO classes")
    if not re.search(r"\bcase\s+VOLTA_DMA_COPY_A\s*:", ce):
        raise ValueError("R580 CE-class predicate omits VOLTA_DMA_COPY_A")
    if not re.search(r"\bcase\s+VOLTA_COMPUTE_A\s*:", compute):
        raise ValueError("R580 compute-class predicate omits VOLTA_COMPUTE_A")

    return {
        "architecture": {
            "query": "NV2080_CTRL_CMD_MC_GET_ARCH_INFO",
            "assigned_field": "gpuArch",
            "source_field": "archInfoParams.architecture",
            "status_checked_before_assignment": True,
        },
        "class_list": {
            "query": "NV0080_CTRL_CMD_GPU_GET_CLASSLIST",
            "query_count": len(class_list_queries),
            "selected_fields": ["hostClass", "ceClass", "computeClass"],
            "selection_policy": "maximum class ID matching each RM class predicate",
            "sizing_query_error_checked": True,
            "allocation_error_checked": True,
            "class_read_error_checked_before_scan": True,
            "class_read_error_path": "Cleanup_classlist",
            "class_list_freed_before_status_return": True,
            "producer_stops_on_class_query_error": True,
        },
        "predicates": {
            "hostClass": "RM channel class type is GPFIFO",
            "ceClass": "switch includes VOLTA_DMA_COPY_A",
            "computeClass": "switch includes VOLTA_COMPUTE_A",
        },
        "live_rm_values_observed": False,
    }


def compare_hal_tables(r580_source: str, r595_source: str) -> dict:
    r580 = parse_hal_class_tables(r580_source)
    r595 = parse_hal_class_tables(r595_source)
    for branch, tables in (("R580", r580), ("R595", r595)):
        absent = sorted(set(REQUIRED_GV100_TABLE_TARGETS) - set(tables))
        if absent:
            raise ValueError(f"required HAL table missing from {branch}: {', '.join(absent)}")

    missing_r580 = {}
    missing_r595 = {}
    present_r580 = {}
    present_r595 = {}
    resolved_r580_callbacks = {}
    resolved_r595_callbacks = {}
    for table, target in REQUIRED_GV100_TABLE_TARGETS.items():
        ids580 = {row["id"] for row in r580[table]}
        ids595 = {row["id"] for row in r595[table]}
        if target not in ids580:
            missing_r580[table] = target
        if target not in ids595:
            missing_r595[table] = target
        else:
            present_r595[table] = target
            resolved_r595_callbacks[table] = _resolve_table_row_callbacks(
                r595[table], target)
        if target in ids580:
            present_r580[table] = target
            resolved_r580_callbacks[table] = _resolve_table_row_callbacks(r580[table], target)
    if missing_r580:
        raise ValueError(f"pinned R580 reference lacks required GV100 rows: {missing_r580}")

    callback_differences = {}
    for table in REQUIRED_GV100_TABLE_TARGETS:
        callbacks580 = resolved_r580_callbacks.get(table, {})
        callbacks595 = resolved_r595_callbacks.get(table, {})
        difference = {
            name: {"r580": callbacks580.get(name), "r595": callbacks595.get(name)}
            for name in sorted(set(callbacks580) | set(callbacks595))
            if callbacks580.get(name) != callbacks595.get(name)
        }
        if difference:
            callback_differences[table] = difference

    return {
        "required_table_count": len(REQUIRED_GV100_TABLE_TARGETS),
        "required_targets": dict(REQUIRED_GV100_TABLE_TARGETS),
        "r580_all_required_targets_present": not missing_r580,
        "r595_all_required_targets_present": not missing_r595,
        "r580_present_targets": present_r580,
        "r595_present_targets": present_r595,
        "r595_missing_targets": missing_r595,
        "r580_resolved_callbacks": resolved_r580_callbacks,
        "r595_resolved_callbacks": resolved_r595_callbacks,
        "r580_to_r595_callback_differences": callback_differences,
        "architecture_table_has_gv100": (
            "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100"
            in {row["id"] for row in r595["arch_table"]}
        ),
        "table_inventory": {
            "R580": r580,
            "R595": r595,
        },
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=R580_ARCHIVE)
    parser.add_argument("--r595-source", type=Path, default=DEFAULT_R595_SOURCE)
    parser.add_argument("--candidate-module", type=Path,
                        help="optional compile-only candidate .ko for symbol-closure audit")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-r580-sha256",
                        default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256)
    parser.add_argument("--expected-r580-source-root",
                        default=R580_SOURCE_ROOT,
                        help="expected top-level root of the hash-pinned source archive")
    args = parser.parse_args()
    archive_path = args.r580_archive.resolve(strict=True)
    r595_hal = args.r595_source.resolve(strict=True) / R595_HAL_RELATIVE
    if not r595_hal.is_file():
        parser.error(f"R595 UVM HAL source is missing: {r595_hal}")
    report_path = args.report.resolve()
    if report_path.exists():
        parser.error(f"refusing to overwrite existing report: {report_path}")
    archive_hash = _sha256(archive_path.read_bytes())
    if archive_hash != args.expected_r580_sha256:
        parser.error("R580 archive hash does not match the pinned expected SHA-256")
    with tarfile.open(archive_path, "r:*") as archive:
        root = checked_source_archive_root(archive, args.expected_r580_source_root)
        r580_bytes = read_member(archive, root + "/" + R580_HAL_MEMBER)
        r580_gpu_ops_bytes = read_member(archive, root + "/" + R580_GPU_OPS_MEMBER)
    r595_bytes = r595_hal.read_bytes()
    r580_text = r580_bytes.decode("utf-8", errors="strict")
    r580_gpu_ops_text = r580_gpu_ops_bytes.decode("utf-8", errors="strict")
    r595_text = r595_bytes.decode("utf-8", errors="strict")
    comparison = compare_hal_tables(r580_text, r595_text)
    selector_contract = parse_gpu_hal_selector_contract(r595_text)
    gpu_info_producer_contract = parse_r580_gpu_info_producer_contract(
        r580_gpu_ops_text)
    module_audit = None
    module_info = None
    if args.candidate_module is not None:
        module_path = args.candidate_module.resolve(strict=True)
        nm_result = subprocess.run(
            ["nm", "--defined-only", str(module_path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if nm_result.returncode != 0:
            parser.error(f"nm failed for candidate module: {nm_result.stdout[-2000:]}")
        module_audit = audit_candidate_module_symbols(
            comparison["r595_resolved_callbacks"], nm_result.stdout)
        module_audit["all_required_tables_present"] = (
            comparison["r595_all_required_targets_present"])
        module_audit["all_callbacks_defined"] = (
            module_audit["all_required_tables_present"] and
            module_audit["all_callbacks_defined"])
        callback_symbols = {
            symbol for operation_map in comparison["r595_resolved_callbacks"].values()
            for symbol in operation_map.values() if symbol != "NULL"
        }
        source_tree = args.r595_source.resolve(strict=True) / "nvidia-uvm"
        source_definitions = map_callback_definitions(source_tree, callback_symbols)
        source_missing = sorted(symbol for symbol, paths in source_definitions.items() if not paths)
        source_duplicates = {
            symbol: paths for symbol, paths in source_definitions.items() if len(paths) > 1
        }
        callback_files_for_missing_module_symbols = {}
        for table, item in module_audit["tables"].items():
            for symbol in item["missing_symbols"]:
                callback_files_for_missing_module_symbols[symbol] = source_definitions.get(symbol, [])
        module_info = {
            "path": str(module_path),
            "sha256": _sha256(module_path.read_bytes()),
            "nm_command": ["nm", "--defined-only", str(module_path)],
            "symbol_audit": module_audit,
            "candidate_callback_source_root": str(source_tree),
            "candidate_callback_source_definitions": source_definitions,
            "candidate_callback_source_missing": source_missing,
            "candidate_callback_duplicate_definitions": source_duplicates,
            "source_files_needed_for_undefined_callbacks": callback_files_for_missing_module_symbols,
        }
    source_dispatch_complete = (
        gpu_info_producer_contract is not None and
        comparison["r595_all_required_targets_present"] and
        len(selector_contract) == len(REQUIRED_GV100_TABLE_TARGETS))
    report = {
        "schema": "r595-uvm-hal-table-closure-v7",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "pinned-source-static-gpu-info-to-hal-selector-contract",
        "r580_archive": str(archive_path),
        "r580_archive_sha256": archive_hash,
        "r580_source_root": root,
        "r580_hal_source_sha256": _sha256(r580_bytes),
        "r580_gpu_ops_member": R580_GPU_OPS_MEMBER,
        "r580_gpu_ops_source_sha256": _sha256(r580_gpu_ops_bytes),
        "r580_gpu_info_producer_contract": gpu_info_producer_contract,
        "r595_source": str(args.r595_source.resolve(strict=True)),
        "r595_hal_source": str(r595_hal),
        "r595_hal_source_sha256": _sha256(r595_bytes),
        "comparison": comparison,
        "r595_gpu_selector_contract": selector_contract,
        "candidate_module": module_info,
        "source_dispatch_complete_for_gv100": source_dispatch_complete,
        "candidate_module_all_resolved_gv100_callbacks_defined": (
            module_audit["all_callbacks_defined"] if module_audit else None),
        "hardware_validated": False,
        "limitations": [
            "The census inventories source initializers and row identifiers; it does not execute UVM table initialization or prove the runtime RM class identifiers.",
            "GV100 rows absent from R595 indicate missing source dispatch entries; this report does not assess whether every listed table is reached in every workload.",
            "No module was installed or loaded and no GPU was exercised.",
        ],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({
        "report": str(report_path),
        "report_sha256": _sha256(report_path.read_bytes()),
        "r580_all_required_targets_present": comparison["r580_all_required_targets_present"],
        "r595_missing_targets": comparison["r595_missing_targets"],
        "r580_gpu_info_producer_contract_valid": True,
        "source_dispatch_complete_for_gv100": source_dispatch_complete,
        "candidate_module_all_resolved_gv100_callbacks_defined": (
            module_audit["all_callbacks_defined"] if module_audit else None),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
