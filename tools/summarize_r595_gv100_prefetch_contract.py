#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a path-free receipt for the isolated R595 GV100 prefetch audit/build."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402


EXPECTED_SCHEMA = "r595-gv100-complete-hal-probe-v12"
EXPECTED_CLASSIFICATION = "isolated-complete-gv100-uvm-hal-compile-link-probe-only"
TABLES = {
    "access_counter_buffer_table",
    "arch_table",
    "ce_table",
    "fault_buffer_table",
    "host_table",
    "sec2_table",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} is missing or is not a SHA-256 digest")
    return value


def _require_true(value: object, label: str) -> None:
    if value is not True:
        raise ValueError(f"{label} is not proven true by the raw report")


def _require_false(value: object, label: str) -> None:
    if value is not False:
        raise ValueError(f"{label} must remain false for this compile-only receipt")


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} is missing")
    return value


def build_summary(raw: dict, raw_sha256: str) -> dict:
    """Validate raw build evidence and return only portable, non-path data."""
    if raw.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("unexpected R595 GV100 HAL report schema")
    if raw.get("status") != "passed":
        raise ValueError("raw R595 build report did not pass")
    if raw.get("classification") != EXPECTED_CLASSIFICATION:
        raise ValueError("raw R595 report has an unexpected evidence classification")
    _require_sha256(raw_sha256, "raw report digest")

    preparation = _mapping(raw.get("preparation"), "source preparation")
    build = _mapping(raw.get("build"), "module build")
    candidate = _mapping(raw.get("candidate_module"), "candidate module")
    dispatch = _mapping(raw.get("static_gv100_dispatch_audit"), "GV100 dispatch audit")
    prefetch = _mapping(raw.get("volta_prefetch_capability_contract"),
                        "Volta prefetch capability contract")
    callbacks = _mapping(raw.get("modern_prefetch_callback_adaptation"),
                         "prefetch callback adaptation")

    _require_true(preparation.get("archive_sha256_matches_expected"),
                  "pinned R580 source archive")
    _require_false(preparation.get("loaded_or_installed"),
                   "source preparation load/install status")
    _require_false(preparation.get("runtime_semantics_validated"),
                   "source preparation runtime status")
    _require_false(raw.get("module_installed"), "module installation status")
    _require_false(raw.get("module_loaded"), "module load status")
    _require_false(raw.get("hardware_validated"), "hardware validation status")

    for field in ("build_command_succeeded", "module_exists", "module_elf_valid",
                  "module_linked", "module_linked_this_run",
                  "expected_port_sources_compiled_this_run",
                  "expected_volta_sources_compiled_this_run"):
        _require_true(build.get(field), f"build.{field}")
    if build.get("build_exit_code") != 0:
        raise ValueError("module build did not exit successfully")
    _require_false(build.get("loaded_or_installed"), "build load/install status")
    if build.get("unexpected_module_actions") != []:
        raise ValueError("build report records unexpected module actions")

    module_sha256 = _require_sha256(candidate.get("sha256"), "candidate module digest")
    if module_sha256 != _require_sha256(build.get("module_sha256"),
                                        "built module digest"):
        raise ValueError("candidate module digest does not match the build result")
    _require_sha256(build.get("build_log_sha256"), "build log digest")
    r580_archive_sha256 = _require_sha256(
        raw.get("r580_archive_sha256"), "R580 source archive digest")
    _require_sha256(dispatch.get("hal_source_sha256"), "adapted HAL source digest")

    required_objects = raw.get("required_candidate_objects")
    compiled_objects = raw.get("compiled_candidate_objects")
    if (not isinstance(required_objects, list) or not required_objects
            or not isinstance(compiled_objects, list)
            or set(required_objects) != set(compiled_objects)
            or len(compiled_objects) != len(set(compiled_objects))):
        raise ValueError("compiled candidate objects do not close the required object set")

    symbol_audit = _mapping(candidate.get("symbol_audit"), "candidate module symbol audit")
    _require_true(symbol_audit.get("all_callbacks_defined"),
                  "candidate callback symbol closure")
    symbol_tables = _mapping(symbol_audit.get("tables"), "candidate HAL table symbols")
    if set(symbol_tables) != TABLES:
        raise ValueError("candidate module symbol audit has incomplete table coverage")
    callback_count = 0
    for table in sorted(TABLES):
        item = _mapping(symbol_tables[table], f"candidate symbols for {table}")
        _require_true(item.get("complete"), f"candidate symbol closure for {table}")
        expected = item.get("expected_count")
        defined = item.get("defined_count")
        if not isinstance(expected, int) or expected <= 0 or defined != expected:
            raise ValueError(f"candidate symbol count is incomplete for {table}")
        if item.get("missing_symbols") != []:
            raise ValueError(f"candidate module symbol closure has missing callbacks for {table}")
        callback_count += defined

    if dispatch.get("required_table_count") != len(TABLES):
        raise ValueError("GV100 dispatch table count is incomplete")
    _require_false(dispatch.get("runtime_or_hardware_validated"),
                   "dispatch runtime/hardware status")
    if dispatch.get("missing_selectors") != [] or dispatch.get("errors") != {}:
        raise ValueError("GV100 dispatch audit contains missing selectors or errors")
    selected_rows = _mapping(dispatch.get("selected_rows"), "GV100 selected HAL rows")
    selectors = _mapping(dispatch.get("selector_contract"), "GV100 selector contract")
    if set(selected_rows) != TABLES or set(selectors) != TABLES:
        raise ValueError("GV100 dispatch does not cover all six required tables")
    for table in sorted(TABLES):
        row = _mapping(selected_rows[table], f"selected GV100 row {table}")
        _require_true(row.get("callbacks_complete"), f"selected row {table}")
        if row.get("parent_id") is not None:
            raise ValueError(f"selected GV100 row {table} is not explicit and parentless")
        selector = _mapping(selectors[table], f"selector contract for {table}")
        if selector.get("missing_class_status") != "NV_ERR_INVALID_CLASS":
            raise ValueError(f"selector for {table} does not fail closed")
        _require_true(selector.get("null_checked_before_install"),
                      f"selector null check for {table}")
        _require_true(selector.get("installs_hal_pointer"),
                      f"selector HAL installation for {table}")

    for field in ("r580_gv100_capability_true",
                  "r580_enable_assert_is_debug_only_in_release",
                  "r595_assert_is_debug_only_in_release",
                  "r595_replayable_fault_init_enables_prefetch"):
        _require_true(prefetch.get(field), f"prefetch semantics.{field}")
    for field in ("private_parent_gpu_capability_added",
                  "volta_prefetch_wrapper_added"):
        _require_false(prefetch.get(field), f"prefetch semantics.{field}")
    _require_false(prefetch.get("runtime_or_hardware_validated"),
                   "prefetch runtime/hardware status")
    prefetch_hashes = _mapping(prefetch.get("source_sha256"),
                               "prefetch semantic source hashes")
    if set(prefetch_hashes) != {
            "r580_volta_source", "r580_common_header", "r595_gpu_header", "r595_volta_source",
            "r595_hal_header", "r595_common_header", "r595_fault_source"}:
        raise ValueError("prefetch semantic source hash set is incomplete")
    for name, digest in prefetch_hashes.items():
        _require_sha256(digest, f"prefetch source {name}")

    for field in ("enable_action_identical_after_assertion_removal",
                  "disable_action_identical",
                  "direct_r595_turing_callbacks_selected",
                  "modern_callback_prototypes_verified",
                  "shared_register_helper_identical"):
        _require_true(callbacks.get(field), f"prefetch callback adaptation.{field}")
    _require_false(callbacks.get("runtime_support_proven"),
                   "prefetch runtime support")
    callback_hashes = _mapping(callbacks.get("source_sha256"),
                               "callback comparison source hashes")
    if set(callback_hashes) != {
            "r580_pascal_mmu", "r595_hal_header", "r595_turing_mmu",
            "r595_gpu_header"}:
        raise ValueError("prefetch callback comparison source hash set is incomplete")
    for name, digest in callback_hashes.items():
        _require_sha256(digest, f"callback comparison source {name}")

    kernel_target = _mapping(build.get("kernel_target"), "kernel target")
    kernel_release = kernel_target.get("release")
    if not isinstance(kernel_release, str) or not kernel_release:
        raise ValueError("build kernel release is missing")
    warning_count = build.get("build_warning_count")
    if not isinstance(warning_count, int) or warning_count < 0:
        raise ValueError("build warning count is invalid")

    return {
        "schema": "r595-gv100-prefetch-semantics-build-sanitized-v1",
        "created_utc": raw.get("created_utc"),
        "sanitized_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "isolated-source-and-module-compile-link-only",
        "status": "passed",
        "raw_report_sha256": raw_sha256,
        "source_inputs": {
            "r580_archive_sha256": r580_archive_sha256,
            "r595_adapted_hal_sha256": dispatch["hal_source_sha256"],
            "prefetch_callback_sources_sha256": callback_hashes,
            "prefetch_semantic_sources_sha256": prefetch_hashes,
        },
        "build": {
            "kernel_release": kernel_release,
            "module_sha256": module_sha256,
            "build_log_sha256": build["build_log_sha256"],
            "candidate_object_count": len(compiled_objects),
            "candidate_callback_count": callback_count,
            "warning_count": warning_count,
            "installed_or_loaded": False,
        },
        "gv100_dispatch": {
            "complete_table_count": len(TABLES),
            "all_rows_explicit_and_parentless": True,
            "all_selectors_fail_closed": True,
            "all_module_callbacks_defined": True,
            "runtime_or_hardware_validated": False,
        },
        "prefetch_semantics": {
            "r580_gv100_capability_true": True,
            "r580_assert_is_debug_only_in_release": True,
            "r595_assert_is_debug_only_in_release": True,
            "r595_fault_buffer_prefetch_state_initialized_true": True,
            "private_capability_field_added": False,
            "volta_wrapper_added": False,
            "low_level_actions_identical_to_r595_turing_helpers": True,
            "direct_r595_turing_callbacks_selected": True,
            "runtime_support_proven": False,
        },
        "module_loaded": False,
        "hardware_validated": False,
        "cuda_validated": False,
        "limitations": [
            "The result proves isolated source compilation and module link closure only.",
            "The candidate module was not installed or loaded; no GPU or CUDA runtime was exercised.",
            "R580's capability assertion is debug-only in release builds; static source equivalence does not prove runtime behavior or hardware stability.",
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
        write_private_evidence_report(output_path, summary, repository_root=ROOT)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "schema": summary["schema"],
        "receipt_sha256": _sha256(output_path.read_bytes()),
        "module_sha256": summary["build"]["module_sha256"],
        "complete_table_count": summary["gv100_dispatch"]["complete_table_count"],
        "hardware_validated": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
