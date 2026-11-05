#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression contract for cross-provider managed-memory staging in R580 UVM."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_uvm_staged_migration.py"
SPEC = importlib.util.spec_from_file_location("r580_uvm_staged_migration", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


class R580UvmStagedMigrationTests(unittest.TestCase):
    def test_pinned_source_reports_conditional_cross_provider_rejection(self):
        report = AUDIT.audit_sources()
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertEqual(
            report["result"]["migration_behavior"],
            "cross_provider_gpu_staging_can_be_rejected_when_source_tracker_is_pending",
        )
        self.assertTrue(all(report["result"]["checks"].values()))

    def test_removing_the_tracker_merge_breaks_the_staged_ordering_proof(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-stage-audit-") as temp:
            root = Path(temp)
            shutil.copytree(AUDIT.SOURCE_ROOT, root / "nvidia-uvm")
            block = root / "nvidia-uvm/uvm_va_block.c"
            source = block.read_text()
            source = source.replace(
                "status = uvm_tracker_add_tracker_safe(&block->tracker, &local_tracker);",
                "status = NV_OK;",
                1,
            )
            block.write_text(source)
            result = AUDIT.analyze_sources(root / "nvidia-uvm", AUDIT.BRIDGE_PATH)
            self.assertFalse(result["checks"]["source_stage_tracker_is_merged_before_destination_stage"])

    def test_removing_the_isolated_cross_gpu_rejection_breaks_the_contract(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-stage-audit-") as temp:
            root = Path(temp)
            shutil.copytree(AUDIT.SOURCE_ROOT, root / "nvidia-uvm")
            push = root / "nvidia-uvm/uvm_push.c"
            source = push.read_text()
            source = source.replace(
                "if (uvm_tracker_has_other_gpus(tracker, gpu))\n            return NV_ERR_NOT_SUPPORTED;",
                "if (false)\n            return NV_ERR_NOT_SUPPORTED;",
                1,
            )
            push.write_text(source)
            result = AUDIT.analyze_sources(root / "nvidia-uvm", AUDIT.BRIDGE_PATH)
            self.assertFalse(result["checks"]["isolated_mode_rejects_pending_other_gpu_tracker"])


if __name__ == "__main__":
    unittest.main()
