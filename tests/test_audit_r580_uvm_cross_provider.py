# SPDX-License-Identifier: MIT
"""Regression checks for the pinned R580 mixed-provider UVM admission audit."""
from pathlib import Path
import importlib
import importlib.util
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROUTE = ROOT / "src/hybrid580_uvm_address_space_route.h"
MODULE_NAME = "tools.audit_r580_uvm_cross_provider"


class R580UvmCrossProviderAuditTests(unittest.TestCase):
    def test_pinned_non_cc_registration_path_exposes_the_cross_provider_blocker(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.fail("the source-backed R580 UVM cross-provider audit is not implemented")
        audit = importlib.import_module(MODULE_NAME)
        report = audit.audit_sources(audit.SOURCE_ROOT, ROUTE)

        self.assertEqual(report["result"]["cross_provider_admission"], "blocked")
        self.assertEqual(report["result"]["blocker"], "cross_provider_dup_allocation")
        self.assertTrue(report["result"]["existing_gpu_pool_page_precedes_second_gpu"])
        self.assertTrue(report["result"]["initialization_failure_propagates"])
        self.assertFalse(report["qualification"]["runtime_validated"])
        self.assertFalse(report["qualification"]["hardware_validated"])
        self.assertEqual(
            {name: item["sha256"] for name, item in report["source_files"].items()},
            audit.EXPECTED_SOURCE_SHA256,
        )

    def test_route_classifier_fails_closed_when_mapping_semantics_are_unknown(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.skipTest("audit implementation is not present yet")
        audit = importlib.import_module(MODULE_NAME)
        with self.assertRaisesRegex(ValueError, "unrecognized DupAllocation route"):
            audit.classify_dup_allocation_route(
                "if (src_provider != dst_provider) { return try_other_rm(); }"
            )

    def test_modified_route_cannot_reuse_the_pinned_blocker_report(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.skipTest("audit implementation is not present yet")
        audit = importlib.import_module(MODULE_NAME)
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            changed_route = temporary / "hybrid580_uvm_address_space_route.h"
            shutil.copyfile(ROOT / "src/hybrid580_uvm_callback_bridge.c",
                            temporary / "hybrid580_uvm_callback_bridge.c")
            shutil.copyfile(ROUTE, changed_route)
            changed_route.write_text(
                changed_route.read_text().replace(
                    "if (src_provider != dst_provider)",
                    "if (src_provider == dst_provider)",
                    1,
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "pinned source SHA-256 mismatch"):
                audit.audit_sources(audit.SOURCE_ROOT, changed_route)

    def test_report_writer_never_truncates_an_existing_evidence_file(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.skipTest("audit implementation is not present yet")
        audit = importlib.import_module(MODULE_NAME)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "existing.json"
            target.write_bytes(b"keep-existing-evidence\n")

            with self.assertRaises(FileExistsError):
                audit.write_json(target, {"status": "new"})

            self.assertEqual(target.read_bytes(), b"keep-existing-evidence\n")


if __name__ == "__main__":
    unittest.main()
