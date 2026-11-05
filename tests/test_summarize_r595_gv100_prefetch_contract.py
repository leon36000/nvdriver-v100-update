# SPDX-License-Identifier: MIT
"""Tests for the isolated R595 GV100 prefetch-contract receipt."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.summarize_r595_gv100_prefetch_contract import (  # noqa: E402
    build_summary,
)


TABLES = (
    "access_counter_buffer_table",
    "arch_table",
    "ce_table",
    "fault_buffer_table",
    "host_table",
    "sec2_table",
)


class SummarizeR595Gv100PrefetchContractTests(unittest.TestCase):
    def _raw_report(self):
        module_sha = "a" * 64
        return {
            "schema": "r595-gv100-complete-hal-probe-v12",
            "created_utc": "2026-11-03T12:00:00+00:00",
            "status": "passed",
            "classification": "isolated-complete-gv100-uvm-hal-compile-link-probe-only",
            "r580_archive_sha256": "b" * 64,
            "module_installed": False,
            "module_loaded": False,
            "hardware_validated": False,
            "required_candidate_objects": ["object_a.o", "object_b.o"],
            "compiled_candidate_objects": ["object_a.o", "object_b.o"],
            "preparation": {
                "archive_sha256_matches_expected": True,
                "loaded_or_installed": False,
                "runtime_semantics_validated": False,
            },
            "build": {
                "build_command_succeeded": True,
                "build_exit_code": 0,
                "build_log_sha256": "c" * 64,
                "build_warning_count": 1,
                "module_linked": True,
                "module_linked_this_run": True,
                "module_sha256": module_sha,
                "module_exists": True,
                "module_elf_valid": True,
                "expected_port_sources_compiled_this_run": True,
                "expected_volta_sources_compiled_this_run": True,
                "loaded_or_installed": False,
                "unexpected_module_actions": [],
                "kernel_target": {"release": "7.0.0-38-generic"},
            },
            "candidate_module": {
                "linked_this_run": True,
                "sha256": module_sha,
                "symbol_audit": {
                    "all_callbacks_defined": True,
                    "tables": {
                        name: {
                            "complete": True,
                            "expected_count": 1,
                            "defined_count": 1,
                            "missing_symbols": [],
                        }
                        for name in TABLES
                    },
                },
            },
            "static_gv100_dispatch_audit": {
                "hal_source_sha256": "9" * 64,
                "required_table_count": 6,
                "missing_selectors": [],
                "errors": {},
                "runtime_or_hardware_validated": False,
                "selected_rows": {
                    name: {
                        "callbacks_complete": True,
                        "callback_count": 1,
                        "parent_id": None,
                    }
                    for name in TABLES
                },
                "selector_contract": {
                    name: {
                        "missing_class_status": "NV_ERR_INVALID_CLASS",
                        "null_checked_before_install": True,
                        "installs_hal_pointer": True,
                    }
                    for name in TABLES
                },
            },
            "volta_prefetch_capability_contract": {
                "r580_gv100_capability_true": True,
                "r580_enable_assert_is_debug_only_in_release": True,
                "r595_assert_is_debug_only_in_release": True,
                "r595_replayable_fault_init_enables_prefetch": True,
                "private_parent_gpu_capability_added": False,
                "volta_prefetch_wrapper_added": False,
                "runtime_or_hardware_validated": False,
                "source_sha256": {
                    "r580_volta_source": "d" * 64,
                    "r580_common_header": "e" * 64,
                    "r595_gpu_header": "f" * 64,
                    "r595_volta_source": "1" * 64,
                    "r595_hal_header": "2" * 64,
                    "r595_common_header": "3" * 64,
                    "r595_fault_source": "8" * 64,
                },
            },
            "modern_prefetch_callback_adaptation": {
                "direct_r595_turing_callbacks_selected": True,
                "enable_action_identical_after_assertion_removal": True,
                "disable_action_identical": True,
                "shared_register_helper_identical": True,
                "modern_callback_prototypes_verified": True,
                "runtime_support_proven": False,
                "source_sha256": {
                    "r580_pascal_mmu": "4" * 64,
                    "r595_hal_header": "5" * 64,
                    "r595_turing_mmu": "6" * 64,
                    "r595_gpu_header": "7" * 64,
                },
            },
        }

    def test_receipt_is_path_free_and_states_the_compile_link_boundary(self):
        summary = build_summary(self._raw_report(), "7" * 64)
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn("/private", serialized)
        self.assertNotIn(str(ROOT), serialized)
        self.assertEqual(summary["raw_report_sha256"], "7" * 64)
        self.assertEqual(summary["status"], "passed")
        self.assertFalse(summary["prefetch_semantics"]["private_capability_field_added"])
        self.assertTrue(summary["prefetch_semantics"]["direct_r595_turing_callbacks_selected"])
        self.assertEqual(summary["gv100_dispatch"]["complete_table_count"], 6)
        self.assertTrue(summary["gv100_dispatch"]["all_module_callbacks_defined"])
        self.assertFalse(summary["module_loaded"])
        self.assertFalse(summary["hardware_validated"])
        self.assertFalse(summary["cuda_validated"])

    def test_rejects_unknown_schema_and_unpassed_build(self):
        raw = self._raw_report()
        raw["schema"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "schema"):
            build_summary(raw, "7" * 64)
        raw = self._raw_report()
        raw["build"]["build_exit_code"] = 1
        with self.assertRaisesRegex(ValueError, "build"):
            build_summary(raw, "7" * 64)

    def test_rejects_missing_guard_or_mismatched_module_hash(self):
        raw = self._raw_report()
        raw["volta_prefetch_capability_contract"][
            "r580_gv100_capability_true"] = False
        with self.assertRaisesRegex(ValueError, "prefetch"):
            build_summary(raw, "7" * 64)
        raw = self._raw_report()
        raw["build"]["module_sha256"] = "8" * 64
        with self.assertRaisesRegex(ValueError, "module"):
            build_summary(raw, "7" * 64)

    def test_rejects_incomplete_or_vacuous_dispatch_and_symbol_closure(self):
        raw = self._raw_report()
        del raw["static_gv100_dispatch_audit"]["selected_rows"]["host_table"]
        with self.assertRaisesRegex(ValueError, "dispatch"):
            build_summary(raw, "7" * 64)
        raw = self._raw_report()
        raw["candidate_module"]["symbol_audit"]["tables"]["arch_table"][
            "missing_symbols"] = ["callback"]
        with self.assertRaisesRegex(ValueError, "symbol"):
            build_summary(raw, "7" * 64)

    def test_cli_writes_private_receipt_only_under_evidence(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "evidence") as temporary:
            raw_path = Path(temporary) / "raw.json"
            output_path = Path(temporary) / "receipt.json"
            raw_path.write_text(json.dumps(self._raw_report()), encoding="utf-8")
            run = subprocess.run(
                [sys.executable,
                 str(ROOT / "tools/summarize_r595_gv100_prefetch_contract.py"),
                 "--input", str(raw_path), "--output", str(output_path)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            body = output_path.read_text(encoding="utf-8")
            self.assertNotIn(str(ROOT), body)
            self.assertEqual(os.stat(output_path).st_mode & 0o777, 0o600)

    def test_cli_rejects_output_outside_evidence(self):
        with tempfile.TemporaryDirectory(prefix="prefetch-receipt-") as temporary:
            raw_path = Path(temporary) / "raw.json"
            output_path = Path(temporary) / "receipt.json"
            raw_path.write_text(json.dumps(self._raw_report()), encoding="utf-8")
            run = subprocess.run(
                [sys.executable,
                 str(ROOT / "tools/summarize_r595_gv100_prefetch_contract.py"),
                 "--input", str(raw_path), "--output", str(output_path)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("inside repository evidence", run.stderr)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
