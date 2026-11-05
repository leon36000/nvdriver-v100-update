#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the exact-source R595 BAR1 peer host harness."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_noncoherent_bar1_consumers import DEFAULT_CANDIDATE, DEFAULT_R595  # noqa: E402
from tools.run_r595_bar1_peer_host_harness import run_harness  # noqa: E402


class R595Bar1PeerHostHarnessTests(unittest.TestCase):
    def test_executes_eighteen_exact_source_aperture_address_and_range_vectors(self):
        report = run_harness(DEFAULT_R595, DEFAULT_CANDIDATE)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["checks_passed"], 18)
        self.assertEqual(len(report["functions_extracted"]), 4)
        self.assertTrue(report["source_identity"]["matches"])
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_rejects_candidate_source_drift_before_compilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            source_path = candidate / "uvm_gpu.c"
            shutil.copy2(DEFAULT_CANDIDATE / "uvm_gpu.c", source_path)
            source = source_path.read_text(encoding="utf-8")
            source_path.write_text(source.replace("UVM_GPU_LINK_PCIE_BAR1", "UVM_GPU_LINK_INVALID", 1), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "differs from pinned R595"):
                run_harness(DEFAULT_R595, candidate)


if __name__ == "__main__":
    unittest.main()
