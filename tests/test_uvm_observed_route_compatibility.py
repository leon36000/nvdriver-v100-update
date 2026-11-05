#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise trace-to-branch UVM route compatibility reporting."""

import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import compare_uvm_ioctl_routes as route_tool


ROOT = Path(__file__).resolve().parents[1]
TRACE_SUMMARY = ROOT / "evidence/pc3-v100-context-uvm-sequence-v1-20261028.json"
TOOL = ROOT / "tools/compare_uvm_ioctl_routes.py"


class ObservedUvmRouteCompatibilityTests(unittest.TestCase):
    def test_unpinned_current_format_trace_cannot_claim_static_route_coverage(self):
        raw = json.dumps({
            "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
            "qualification": "v100-cuda-phase-report-contract-valid",
            "phase": "context",
        }).encode("utf-8")
        capture = {
            "capture": "caller-generated.json",
            "capture_sha256": hashlib.sha256(raw).hexdigest(),
        }
        with mock.patch.object(route_tool, "_read_regular", return_value=raw):
            with self.assertRaisesRegex(ValueError, "fixed SHA-256 allowlist"):
                route_tool._load_hash_pinned_raw_trace(capture)

    def test_real_v100_range_group_calls_are_routed_by_r595_and_missing_in_r615(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "route-compatibility.json"
            completed = subprocess.run(
                [
                    sys.executable, "-B", str(TOOL),
                    "--observed-summary", str(TRACE_SUMMARY),
                    "--report", str(report_path),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        comparison = report["observed_trace_compatibility"]
        self.assertEqual(comparison["capture_count"], 2)
        self.assertFalse(comparison["uvm_payloads_observed"])
        self.assertFalse(comparison["runtime_compatibility_proven"])
        self.assertFalse(comparison["cuda_execution_validated"])
        self.assertIn("node-open-traces", comparison["qualification"])
        for capture in comparison["captures"]:
            self.assertFalse(capture["cuda_execution_validated"])
            self.assertIn("not-established", capture["source_qualification"])
            row = next(
                row for row in capture["requests"]
                if row["name"] == "UVM_CREATE_RANGE_GROUP"
            )
            self.assertEqual((row["request"], row["count"]), ("0x17", 8))
            self.assertEqual(row["baseline"]["status"], "routed")
            self.assertEqual(row["baseline"]["handler"], "uvm_api_create_range_group")
            self.assertEqual(row["candidate"]["status"], "missing_dispatch")
            self.assertIsNone(row["candidate"]["handler"])

    def test_same_name_with_a_different_request_number_is_not_reported_as_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate_root = Path(tmp) / "candidate"
            candidate_root.mkdir()
            (candidate_root / "uvm.c").write_text(
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_CREATE_RANGE_GROUP, "
                "uvm_api_create_range_group_new);\n"
            )
            (candidate_root / "uvm_ioctl.h").write_text(
                "#define UVM_CREATE_RANGE_GROUP UVM_IOCTL_BASE(24)\n"
            )
            completed = subprocess.run(
                [
                    sys.executable, "-B", str(TOOL),
                    "--candidate-root", str(candidate_root),
                    "--observed-summary", str(TRACE_SUMMARY),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        row = next(
            row for row in report["observed_trace_compatibility"]["captures"][0]["requests"]
            if row["name"] == "UVM_CREATE_RANGE_GROUP"
        )
        self.assertEqual(row["candidate"]["status"], "request_value_mismatch")
        self.assertEqual(row["candidate"]["handler"], "uvm_api_create_range_group_new")

    def test_summary_count_must_match_the_hash_pinned_raw_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = json.loads(TRACE_SUMMARY.read_text())
            range_group = next(
                row for row in summary["captures"][0]["requests"]
                if row["name"] == "UVM_CREATE_RANGE_GROUP"
            )
            range_group["count"] = 9
            altered_summary = Path(tmp) / "altered-summary.json"
            altered_summary.write_text(json.dumps(summary))
            completed = subprocess.run(
                [
                    sys.executable, "-B", str(TOOL),
                    "--observed-summary", str(altered_summary),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("does not match the hash-pinned raw trace", completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
