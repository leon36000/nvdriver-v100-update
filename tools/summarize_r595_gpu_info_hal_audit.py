#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a path-free receipt from the R580 GPU-info/R595 UVM HAL audit."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402


EXPECTED_SCHEMA = "r595-uvm-hal-table-closure-v7"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_summary(raw: dict, raw_sha256: str) -> dict:
    if raw.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("unexpected R595 UVM HAL audit schema")
    comparison = raw.get("comparison")
    selectors = raw.get("r595_gpu_selector_contract")
    producer = raw.get("r580_gpu_info_producer_contract")
    module = raw.get("candidate_module")
    if not all(isinstance(value, dict) for value in
               (comparison, selectors, producer, module)):
        raise ValueError("audit is missing producer, selector, comparison, or module data")
    symbol_audit = module.get("symbol_audit")
    if not isinstance(symbol_audit, dict):
        raise ValueError("audit is missing candidate module symbol closure")
    tables = symbol_audit.get("tables")
    if not isinstance(tables, dict) or not tables:
        raise ValueError("audit is missing per-table module symbol results")
    class_list = producer.get("class_list")
    required_status_facts = (
        "sizing_query_error_checked",
        "allocation_error_checked",
        "class_read_error_checked_before_scan",
        "class_list_freed_before_status_return",
        "producer_stops_on_class_query_error",
    )
    if (not isinstance(class_list, dict) or any(
            class_list.get(field) is not True for field in required_status_facts)):
        raise ValueError("audit is missing the R580 class-list fail-closed status contract")

    callback_differences = []
    for table, callbacks in sorted(
            comparison.get("r580_to_r595_callback_differences", {}).items()):
        for callback, values in sorted(callbacks.items()):
            callback_differences.append({
                "table": table,
                "callback": callback,
                "r580_symbol": values.get("r580"),
                "r595_symbol": values.get("r595"),
            })

    missing_symbols = sum(len(item.get("missing_symbols", []))
                          for item in tables.values())
    return {
        "schema": "r595-gv100-gpu-info-hal-static-audit-sanitized-v2",
        "created_utc": raw.get("created_utc"),
        "sanitized_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "pinned-source-and-compiled-module-symbol-closure",
        "raw_report_sha256": raw_sha256,
        "source_inputs": {
            "r580_archive_sha256": raw.get("r580_archive_sha256"),
            "r580_gpu_ops_source_sha256": raw.get("r580_gpu_ops_source_sha256"),
            "r580_uvm_hal_source_sha256": raw.get("r580_hal_source_sha256"),
            "r595_uvm_hal_source_sha256": raw.get("r595_hal_source_sha256"),
            "candidate_module_sha256": module.get("sha256"),
        },
        "r580_gpu_info_producer": {
            "architecture_query": producer.get("architecture", {}).get("query"),
            "architecture_field": producer.get("architecture", {}).get("assigned_field"),
            "architecture_source": producer.get("architecture", {}).get("source_field"),
            "architecture_status_checked": producer.get("architecture", {}).get(
                "status_checked_before_assignment"),
            "class_list_query": producer.get("class_list", {}).get("query"),
            "class_list_query_count": producer.get("class_list", {}).get("query_count"),
            "selected_fields": producer.get("class_list", {}).get("selected_fields"),
            "sizing_query_error_checked": class_list.get(
                "sizing_query_error_checked"),
            "allocation_error_checked": class_list.get("allocation_error_checked"),
            "class_read_error_checked_before_scan": class_list.get(
                "class_read_error_checked_before_scan"),
            "class_read_error_path": class_list.get("class_read_error_path"),
            "class_list_freed_before_status_return": class_list.get(
                "class_list_freed_before_status_return"),
            "producer_stops_on_class_query_error": class_list.get(
                "producer_stops_on_class_query_error"),
            "predicates": producer.get("predicates"),
            "live_rm_values_observed": producer.get("live_rm_values_observed"),
        },
        "gv100_hal_dispatch": {
            "required_tables": comparison.get("required_table_count"),
            "r580_targets_present": comparison.get("r580_all_required_targets_present"),
            "r595_candidate_targets_present": comparison.get(
                "r595_all_required_targets_present"),
            "candidate_selector_count": len(selectors),
            "selectors_fail_closed": bool(selectors) and all(
                item.get("missing_class_status") == "NV_ERR_INVALID_CLASS"
                and item.get("null_checked_before_install") is True
                and item.get("installs_hal_pointer") is True
                for item in selectors.values()),
            "source_dispatch_complete": raw.get("source_dispatch_complete_for_gv100"),
        },
        "callback_port_differences": callback_differences,
        "candidate_module_symbol_closure": {
            "module_sha256": module.get("sha256"),
            "table_count": len(tables),
            "callback_symbol_references": sum(
                item.get("callback_count", 0) for item in tables.values()),
            "all_selected_callbacks_defined": symbol_audit.get("all_callbacks_defined"),
            "missing_callback_symbols": missing_symbols,
            "callback_source_definitions_missing": len(
                module.get("candidate_callback_source_missing", [])),
            "duplicate_callback_source_definitions": len(
                module.get("candidate_callback_duplicate_definitions", {})),
        },
        "module_loaded": False,
        "hardware_validated": False,
        "cuda_validated": False,
        "limitations": [
            "The RM source audit does not observe live GPU architecture or class-list values.",
            "The fail-closed class-list and cleanup contract is source-derived; live RM error handling was not exercised.",
            "The compiled module was not installed or loaded; no GPU or CUDA runtime was exercised.",
            "Callback-name substitutions identify source differences but do not prove semantic equivalence or hardware stability.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw_path = args.input.resolve(strict=True)
    output_candidate = Path(args.output)
    if not output_candidate.is_absolute():
        output_candidate = ROOT / output_candidate
    output_path = Path(os.path.abspath(output_candidate))
    raw_bytes = raw_path.read_bytes()
    try:
        raw = json.loads(raw_bytes)
        summary = build_summary(raw, _sha256(raw_bytes))
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    try:
        write_private_evidence_report(
            output_path, summary, repository_root=ROOT)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "schema": summary["schema"],
        "receipt_sha256": _sha256(output_path.read_bytes()),
        "source_dispatch_complete": summary["gv100_hal_dispatch"][
            "source_dispatch_complete"],
        "all_selected_callbacks_defined": summary[
            "candidate_module_symbol_closure"]["all_selected_callbacks_defined"],
        "hardware_validated": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
