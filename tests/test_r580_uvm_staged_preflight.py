#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression checks for fail-closed R580 isolated UVM staging."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_uvm_staged_preflight.py"
SPEC = importlib.util.spec_from_file_location("r580_uvm_staged_preflight", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


class R580UvmStagedPreflightTests(unittest.TestCase):
    def test_requested_unsupported_gpu_pages_are_rejected_before_copy_dispatch(self):
        result = AUDIT.analyze_source(AUDIT.SOURCE_ROOT)
        self.assertTrue(result["checks"]["isolated_gpu_destination_is_gated"])
        self.assertTrue(result["checks"]["only_requested_region_pages_trigger_rejection"])
        self.assertTrue(result["checks"]["unsupported_sources_are_intersected_with_copy_access"])
        self.assertTrue(result["checks"]["accessible_duplicate_suppresses_unneeded_staging"])
        self.assertTrue(result["checks"]["late_reject_precedes_all_copy_dispatch"])
        self.assertTrue(result["checks"]["early_reject_precedes_mapping_invalidation_and_population"])

    def test_removing_late_guard_rejects_the_static_contract(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-preflight-late-") as temp:
            root = Path(temp)
            shutil.copytree(AUDIT.SOURCE_ROOT, root / "nvidia-uvm")
            path = root / "nvidia-uvm/uvm_va_block.c"
            source = path.read_text()
            call = source.index("block_get_isolated_staged_pages(block,")
            start = source.rfind("    // The isolated hybrid path cannot order", 0, call)
            end = source.index("    if (UVM_ID_IS_GPU(dst_id)) {\n        // If the destination is a GPU", call)
            path.write_text(source[:start] + source[end:])
            result = AUDIT.analyze_source(root / "nvidia-uvm")
            self.assertFalse(result["checks"]["isolated_gpu_destination_is_gated"])
            self.assertFalse(result["checks"]["late_reject_precedes_all_copy_dispatch"])

    def test_removing_accessible_residency_subtraction_detects_false_rejection_risk(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-preflight-accessible-") as temp:
            root = Path(temp)
            shutil.copytree(AUDIT.SOURCE_ROOT, root / "nvidia-uvm")
            path = root / "nvidia-uvm/uvm_va_block.c"
            source = path.read_text()
            pattern = (
                r"    // An accessible read-duplicate means those pages do not need staging\.\n"
                r"    if \(uvm_processor_mask_and\(processors, can_copy_from, &block->resident\)\) \{\n"
                r".*?\n    \}\n\n"
            )
            updated, count = re.subn(pattern, "", source, count=1, flags=re.DOTALL)
            self.assertEqual(count, 1)
            path.write_text(updated)
            result = AUDIT.analyze_source(root / "nvidia-uvm")
            self.assertFalse(result["checks"]["accessible_duplicate_suppresses_unneeded_staging"])

    def test_removing_early_preflight_detects_side_effect_order_regression(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-preflight-early-") as temp:
            root = Path(temp)
            shutil.copytree(AUDIT.SOURCE_ROOT, root / "nvidia-uvm")
            path = root / "nvidia-uvm/uvm_va_block.c"
            source = path.read_text()
            start = source.index("    // Fail closed before invalidating mappings or allocating destination GPU")
            end = source.index("    // Unmap all mapped processors except for UVM-Lite GPUs", start)
            path.write_text(source[:start] + source[end:])
            result = AUDIT.analyze_source(root / "nvidia-uvm")
            self.assertFalse(result["checks"]["early_reject_precedes_mapping_invalidation_and_population"])


if __name__ == "__main__":
    unittest.main()
