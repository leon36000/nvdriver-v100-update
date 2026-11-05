# SPDX-License-Identifier: MIT
"""Static regression checks for isolated R580 UVM owner transitions."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_uvm_isolated_service_phases.py"
SPEC = importlib.util.spec_from_file_location("r580_uvm_isolated_service_phases", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


class R580UvmIsolatedServicePhaseTests(unittest.TestCase):
    def test_current_source_exposes_conditional_tracker_owner_risk(self):
        result = AUDIT.analyze_source(AUDIT.SOURCE_ROOT)
        self.assertEqual(result["status"], "conditional-risk")
        self.assertEqual(result["failed_checks"], [])
        self.assertTrue(result["checks"]["isolated_push_refuses_pending_foreign_gpu_tracker"])
        self.assertTrue(result["checks"]["two_unmap_batches_precede_destination_population_and_copy"])
        self.assertTrue(result["checks"]["no_tracker_wait_boundary_after_mapping_invalidation"])
        self.assertTrue(result["checks"]["service_copy_flows_into_finish_without_tracker_wait"])
        self.assertTrue(result["checks"]["service_revoke_and_map_subphases_have_no_wait_retry_boundary"])

    def test_removing_the_isolated_rejection_invalidates_source_recognition(self):
        with tempfile.TemporaryDirectory(prefix="r580-owner-phase-guard-") as temp:
            root = Path(temp)
            shutil.copytree(AUDIT.SOURCE_ROOT, root / "nvidia-uvm")
            path = root / "nvidia-uvm/uvm_push.c"
            source = path.read_text()
            start = source.index("static NV_STATUS reject_other_gpus_if_isolated(")
            end = source.index("\n}", start) + 2
            source = source[:start] + (
                "static NV_STATUS reject_other_gpus_if_isolated(uvm_tracker_t *tracker, uvm_gpu_t *gpu)\n"
                "{\n    return NV_OK;\n}"
            ) + source[end:]
            path.write_text(source)
            result = AUDIT.analyze_source(root / "nvidia-uvm")
            self.assertFalse(result["checks"]["isolated_push_refuses_pending_foreign_gpu_tracker"])
            self.assertIn("isolated_push_refuses_pending_foreign_gpu_tracker", result["failed_checks"])


if __name__ == "__main__":
    unittest.main()
