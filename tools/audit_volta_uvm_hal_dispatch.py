#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit static GV100 UVM HAL dispatch rows across pinned driver sources.

This reports source-table presence and inheritance only. It does not claim
that RM returns these class IDs or that any UVM module works on hardware.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
    audit_candidate_module_symbols,
    extract_r580_uvm_c_sources,
    map_callback_definitions,
    _resolve_table_row_callbacks,
    checked_source_archive_root,
    parse_gpu_hal_selector_contract,
    parse_hal_class_tables,
)
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    R580_SOURCE_ROOT,
    read_member,
)

DEFAULT_R580_ARCHIVE = (
    ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
)


def audit_volta_uvm_dispatch(r580_source: str,
                             modern_source: str,
                             *,
                             modern_branch: str) -> dict:
    """Compare the six Volta-selected UVM tables and modern selector contract."""
    r580_tables = parse_hal_class_tables(r580_source)
    modern_tables = parse_hal_class_tables(modern_source)
    for branch, tables in (("R580 reference", r580_tables),
                           (modern_branch, modern_tables)):
        absent = sorted(set(REQUIRED_GV100_TABLE_TARGETS) - set(tables))
        if absent:
            raise ValueError(
                f"required HAL table missing from {branch}: {', '.join(absent)}"
            )

    r580_present = {}
    r580_missing = {}
    modern_present = {}
    modern_missing = {}
    modern_initial_rows = {
        table: rows[0]["id"] for table, rows in modern_tables.items()
    }
    r580_lineage = {}
    r580_callbacks = {}
    modern_callbacks = {}
    resolved_counts = {}
    inheritance_errors = {}
    for table, target in REQUIRED_GV100_TABLE_TARGETS.items():
        r580_ids = {row["id"] for row in r580_tables[table]}
        modern_ids = {row["id"] for row in modern_tables[table]}
        if target in r580_ids:
            r580_present[table] = target
            r580_lineage[table] = _resolve_table_row_lineage(
                r580_tables[table], target
            )
            r580_callbacks[table] = _resolve_table_row_callbacks(
                r580_tables[table], target
            )
        else:
            r580_missing[table] = target
        if target not in modern_ids:
            modern_missing[table] = target
            inheritance_errors[table] = f"target row is absent: {target}"
            continue

        modern_present[table] = target
        try:
            callbacks = _resolve_table_row_callbacks(modern_tables[table], target)
        except ValueError as error:
            inheritance_errors[table] = str(error)
        else:
            modern_callbacks[table] = callbacks
            resolved_counts[table] = len(callbacks)

    if r580_missing:
        raise ValueError(
            "pinned R580 reference lacks required GV100 rows: "
            + ", ".join(sorted(r580_missing))
        )

    selector_contract = parse_gpu_hal_selector_contract(modern_source)
    inheritance_closure_valid = not inheritance_errors
    all_targets_present = not modern_missing
    callback_changes = []
    for table in sorted(set(r580_callbacks) & set(modern_callbacks)):
        for operation in sorted(
            set(r580_callbacks[table]) | set(modern_callbacks[table])
        ):
            r580_callback = r580_callbacks[table].get(operation)
            modern_callback = modern_callbacks[table].get(operation)
            if r580_callback == modern_callback:
                continue
            callback_changes.append({
                "table": table,
                "operation": operation,
                "r580_callback": r580_callback,
                "modern_callback": modern_callback,
                "change": (
                    "modern-only" if r580_callback is None else
                    "removed" if modern_callback is None else
                    "replaced"
                ),
            })
    return {
        "schema": "volta-uvm-hal-dispatch-audit-v4",
        "modern_branch": modern_branch,
        "required_targets": dict(REQUIRED_GV100_TABLE_TARGETS),
        "required_table_count": len(REQUIRED_GV100_TABLE_TARGETS),
        "r580_all_required_targets_present": not r580_missing,
        "r580_present_targets": r580_present,
        "r580_target_lineage": r580_lineage,
        "r580_resolved_callbacks": r580_callbacks,
        "modern_resolved_callbacks": modern_callbacks,
        "r580_to_modern_callback_changes": callback_changes,
        "r580_to_modern_callback_change_count": len(callback_changes),
        "modern_all_required_targets_present": all_targets_present,
        "modern_present_targets": modern_present,
        "modern_missing_targets": modern_missing,
        "modern_initial_row_ids": modern_initial_rows,
        "modern_inheritance_closure_valid": inheritance_closure_valid,
        "modern_inheritance_errors": inheritance_errors,
        "modern_resolved_callback_counts": resolved_counts,
        "modern_selector_contract": selector_contract,
        "modern_static_dispatch_candidate": (
            all_targets_present and inheritance_closure_valid
            and len(selector_contract) == len(REQUIRED_GV100_TABLE_TARGETS)
        ),
        "runtime_or_hardware_validated": False,
        "limitations": [
            "Static source-table inspection does not establish which class IDs the RM returns.",
            "Resolved callback names do not validate callback semantics or hardware compatibility.",
            "No module was installed or loaded and no GPU was exercised.",
        ],
    }


def _resolve_table_row_lineage(rows: list[dict], target_id: str) -> list[str]:
    """Return selected HAL row ancestry ordered from root to target."""
    row_by_id = {row["id"]: row for row in rows}
    if target_id not in row_by_id:
        raise ValueError(f"HAL table does not contain requested target row: {target_id}")

    lineage = []
    visiting = set()
    row_id = target_id
    while row_id is not None:
        if row_id in visiting:
            raise ValueError(f"HAL table inheritance cycle at {row_id}")
        row = row_by_id.get(row_id)
        if row is None:
            raise ValueError(f"HAL table inheritance parent is missing: {row_id}")
        visiting.add(row_id)
        lineage.append(row_id)
        row_id = row["parent_id"]
    lineage.reverse()
    return lineage


def audit_candidate_callback_closure(callbacks_by_table: dict[str, dict[str, str]],
                                    nm_output: str,
                                    source_definitions: dict[str, list[str]]) -> dict:
    """Report callback source locations and symbol closure for selected HAL rows."""
    module_audit = audit_candidate_module_symbols(callbacks_by_table, nm_output)
    callback_symbols = {
        symbol for operations in callbacks_by_table.values()
        for symbol in operations.values() if symbol != "NULL"
    }
    missing_sources = sorted(
        symbol for symbol in callback_symbols
        if not source_definitions.get(symbol)
    )
    duplicates = {
        symbol: source_definitions[symbol]
        for symbol in sorted(callback_symbols)
        if len(source_definitions.get(symbol, [])) > 1
    }
    source_files_for_undefined = {}
    for table_result in module_audit["tables"].values():
        for symbol in table_result["missing_symbols"]:
            source_files_for_undefined[symbol] = source_definitions.get(symbol, [])
    missing_module_symbols = sorted(source_files_for_undefined)
    return {
        "callback_symbol_count": len(callback_symbols),
        "callback_symbols_defined": sorted(callback_symbols - set(missing_module_symbols)),
        "callback_symbols_missing": missing_module_symbols,
        "callback_symbols_missing_count": len(missing_module_symbols),
        "callback_source_definitions": {
            symbol: source_definitions.get(symbol, [])
            for symbol in sorted(callback_symbols)
        },
        "callback_source_missing": missing_sources,
        "callback_duplicate_definitions": duplicates,
        "module_symbol_audit": module_audit,
        "source_files_for_undefined_callbacks": source_files_for_undefined,
    }


def audit_r580_callback_closure(callbacks_by_table: dict[str, dict[str, str]],
                                nm_output: str,
                                source_definitions: dict[str, list[str]]) -> dict:
    """Compatibility wrapper for older R580 callback-closure callers."""
    return audit_candidate_callback_closure(
        callbacks_by_table, nm_output, source_definitions
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--expected-r580-sha256",
                        default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256)
    parser.add_argument("--expected-r580-source-root", default=R580_SOURCE_ROOT)
    parser.add_argument("--modern-source-root", type=Path, required=True,
                        help="root containing nvidia-uvm/uvm_hal.c")
    parser.add_argument("--modern-branch", required=True,
                        help="exact label for the candidate source version")
    parser.add_argument("--candidate-module", type=Path,
                        help="optional linked candidate nvidia-uvm.ko for symbol closure audit")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    archive_path = args.r580_archive.resolve(strict=True)
    archive_bytes = archive_path.read_bytes()
    archive_hash = _sha256(archive_bytes)
    if archive_hash != args.expected_r580_sha256:
        parser.error("R580 archive SHA-256 does not match the pinned value")

    modern_root = args.modern_source_root.resolve(strict=True)
    modern_hal = modern_root / "nvidia-uvm/uvm_hal.c"
    if not modern_hal.is_file():
        parser.error(f"modern UVM HAL source is missing: {modern_hal}")
    modern_bytes = modern_hal.read_bytes()

    with tarfile.open(archive_path, "r:*") as archive:
        source_root = checked_source_archive_root(
            archive, args.expected_r580_source_root
        )
        r580_bytes = read_member(
            archive, source_root + "/kernel-open/nvidia-uvm/uvm_hal.c"
        )

    result = audit_volta_uvm_dispatch(
        r580_bytes.decode("utf-8", errors="strict"),
        modern_bytes.decode("utf-8", errors="strict"),
        modern_branch=args.modern_branch,
    )
    candidate_module = None
    if args.candidate_module is not None:
        module_path = args.candidate_module.resolve(strict=True)
        nm_command = ["nm", "--defined-only", str(module_path)]
        nm_result = subprocess.run(
            nm_command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if nm_result.returncode != 0:
            parser.error(f"nm failed for candidate module: {nm_result.stdout[-2000:]}")
        # The candidate module must be checked against callbacks selected by its
        # own modern HAL rows. The R580 reference callbacks are useful for
        # comparison, but modern rows can intentionally replace them.
        callbacks = result["modern_resolved_callbacks"]
        callback_symbols = {
            symbol for operations in callbacks.values()
            for symbol in operations.values() if symbol != "NULL"
        }
        source_definitions = map_callback_definitions(modern_hal.parent, callback_symbols)
        closure = audit_candidate_callback_closure(
            callbacks, nm_result.stdout, source_definitions,
        )
        candidate_module = {
            "path": str(module_path),
            "sha256": _sha256(module_path.read_bytes()),
            "nm_command": nm_command,
            "static_dispatch_candidate": result[
                "modern_static_dispatch_candidate"
            ],
            "all_required_volta_targets_present": result[
                "modern_all_required_targets_present"
            ],
            **closure,
        }
        candidate_module[
            "all_volta_dispatch_targets_and_callbacks_defined"
        ] = bool(
            candidate_module["static_dispatch_candidate"] and
            candidate_module["module_symbol_audit"]["all_callbacks_defined"]
        )
    report = {
        **result,
        "candidate_module": candidate_module,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "r580_archive": str(archive_path),
        "r580_archive_sha256": archive_hash,
        "r580_source_root": source_root,
        "r580_hal_sha256": _sha256(r580_bytes),
        "modern_source_root": str(modern_root),
        "modern_hal_source": str(modern_hal),
        "modern_hal_sha256": _sha256(modern_bytes),
    }

    report_path = args.report.resolve()
    if report_path.exists():
        parser.error(f"refusing to overwrite existing report: {report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({
        "report": str(report_path),
        "report_sha256": _sha256(report_path.read_bytes()),
        "modern_branch": result["modern_branch"],
        "modern_missing_targets": result["modern_missing_targets"],
        "modern_static_dispatch_candidate": result["modern_static_dispatch_candidate"],
        "candidate_module_callbacks_defined_for_present_rows": (
            candidate_module["module_symbol_audit"]["all_callbacks_defined"]
            if candidate_module else None
        ),
        "candidate_module_all_volta_dispatch_targets_and_callbacks_defined": (
            candidate_module["all_volta_dispatch_targets_and_callbacks_defined"]
            if candidate_module else None
        ),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
