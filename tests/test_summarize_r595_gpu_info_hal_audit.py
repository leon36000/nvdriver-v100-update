# SPDX-License-Identifier: MIT
"""Tests for the path-free R580 RM to R595 GV100 HAL receipt."""
import json
import os
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.summarize_r595_gpu_info_hal_audit import (  # noqa: E402
    build_summary,
)


class SummarizeR595GpuInfoHalAuditTests(unittest.TestCase):
    def _raw_report(self):
        return {
            "schema": "r595-uvm-hal-table-closure-v7",
            "created_utc": "2026-11-03T12:00:00+00:00",
            "r580_archive_sha256": "a" * 64,
            "r580_gpu_ops_source_sha256": "b" * 64,
            "r580_hal_source_sha256": "c" * 64,
            "r595_hal_source_sha256": "d" * 64,
            "r580_gpu_info_producer_contract": {
                "architecture": {
                    "query": "NV2080_CTRL_CMD_MC_GET_ARCH_INFO",
                    "assigned_field": "gpuArch",
                    "source_field": "archInfoParams.architecture",
                    "status_checked_before_assignment": True,
                },
                "class_list": {
                    "query": "NV0080_CTRL_CMD_GPU_GET_CLASSLIST",
                    "query_count": 2,
                    "selected_fields": ["hostClass", "ceClass", "computeClass"],
                    "sizing_query_error_checked": True,
                    "allocation_error_checked": True,
                    "class_read_error_checked_before_scan": True,
                    "class_read_error_path": "Cleanup_classlist",
                    "class_list_freed_before_status_return": True,
                    "producer_stops_on_class_query_error": True,
                },
                "predicates": {
                    "hostClass": "GPFIFO",
                    "ceClass": "VOLTA_DMA_COPY_A",
                    "computeClass": "VOLTA_COMPUTE_A",
                },
                "live_rm_values_observed": False,
            },
            "comparison": {
                "required_table_count": 6,
                "r580_all_required_targets_present": True,
                "r595_all_required_targets_present": True,
                "r580_to_r595_callback_differences": {
                    "arch_table": {
                        "enable_prefetch_faults": {
                            "r580": "uvm_hal_pascal_mmu_enable_prefetch_faults",
                            "r595": "uvm_hal_turing_mmu_enable_prefetch_faults",
                        },
                    },
                },
            },
            "r595_gpu_selector_contract": {
                "arch_table": {
                    "missing_class_status": "NV_ERR_INVALID_CLASS",
                    "null_checked_before_install": True,
                    "installs_hal_pointer": True,
                },
            },
            "candidate_module": {
                "path": "/private/local/build/nvidia-uvm.ko",
                "sha256": "e" * 64,
                "symbol_audit": {
                    "all_callbacks_defined": True,
                    "tables": {
                        "arch_table": {
                            "callback_count": 5,
                            "missing_symbols": [],
                        },
                    },
                },
                "candidate_callback_source_root": "/private/local/source/nvidia-uvm",
                "candidate_callback_source_missing": [],
                "candidate_callback_duplicate_definitions": {},
            },
            "source_dispatch_complete_for_gv100": True,
            "r595_source": "/private/local/source",
        }

    def test_receipt_is_path_free_and_keeps_the_static_only_boundary(self):
        summary = build_summary(self._raw_report(), "f" * 64)
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn("/private/local", serialized)
        self.assertEqual(summary["raw_report_sha256"], "f" * 64)
        self.assertTrue(summary["gv100_hal_dispatch"]["selectors_fail_closed"])
        producer = summary["r580_gpu_info_producer"]
        self.assertEqual(summary["schema"],
                         "r595-gv100-gpu-info-hal-static-audit-sanitized-v2")
        self.assertTrue(producer["sizing_query_error_checked"])
        self.assertTrue(producer["allocation_error_checked"])
        self.assertTrue(producer["class_read_error_checked_before_scan"])
        self.assertTrue(producer["class_list_freed_before_status_return"])
        self.assertTrue(producer["producer_stops_on_class_query_error"])
        self.assertEqual(
            summary["callback_port_differences"][0]["r595_symbol"],
            "uvm_hal_turing_mmu_enable_prefetch_faults")
        self.assertTrue(summary["candidate_module_symbol_closure"][
            "all_selected_callbacks_defined"])
        self.assertFalse(summary["module_loaded"])
        self.assertFalse(summary["hardware_validated"])
        self.assertFalse(summary["cuda_validated"])

    def test_rejects_unknown_source_audit_schema(self):
        raw = self._raw_report()
        raw["schema"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            build_summary(raw, "f" * 64)

    def test_empty_selector_map_does_not_pass_closed_selector_summary_vacuously(self):
        raw = self._raw_report()
        raw["r595_gpu_selector_contract"] = {}
        summary = build_summary(raw, "f" * 64)
        self.assertFalse(summary["gv100_hal_dispatch"]["selectors_fail_closed"])

    def test_rejects_incomplete_class_list_error_contract(self):
        raw = self._raw_report()
        del raw["r580_gpu_info_producer_contract"]["class_list"][
            "allocation_error_checked"]
        with self.assertRaisesRegex(ValueError, "fail-closed status contract"):
            build_summary(raw, "f" * 64)

    def test_cli_writes_only_under_evidence_and_does_not_leak_paths(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "evidence") as temporary:
            raw_path = Path(temporary) / "raw.json"
            output_path = Path(temporary) / "receipt.json"
            raw_path.write_text(json.dumps(self._raw_report()), encoding="utf-8")
            run = subprocess.run(
                [sys.executable, str(ROOT / "tools/summarize_r595_gpu_info_hal_audit.py"),
                 "--input", str(raw_path), "--output", str(output_path)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            output = output_path.read_text(encoding="utf-8")
            self.assertNotIn(str(ROOT), output)
            self.assertNotIn("/private/local", output)
            self.assertEqual(os.stat(output_path).st_mode & 0o777, 0o600)

    def test_cli_rejects_output_outside_repository_evidence(self):
        with tempfile.TemporaryDirectory(prefix="gpu-info-hal-summary-") as temporary:
            raw_path = Path(temporary) / "raw.json"
            output_path = Path(temporary) / "receipt.json"
            raw_path.write_text(json.dumps(self._raw_report()), encoding="utf-8")
            run = subprocess.run(
                [sys.executable, str(ROOT / "tools/summarize_r595_gpu_info_hal_audit.py"),
                 "--input", str(raw_path), "--output", str(output_path)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("inside repository evidence", run.stderr)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
