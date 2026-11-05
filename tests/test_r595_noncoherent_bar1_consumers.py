#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression tests for the R595 noncoherent BAR1 consumer audit."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_noncoherent_bar1_consumers import (  # noqa: E402
    DEFAULT_CANDIDATE,
    DEFAULT_R580,
    DEFAULT_R595,
    audit,
)


class R595NoncoherentBar1ConsumerTests(unittest.TestCase):
    def test_v11_candidate_closes_static_bar1_consumer_contract(self):
        report = audit(DEFAULT_R595, DEFAULT_R580, DEFAULT_CANDIDATE)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["checks"]), 23)
        self.assertTrue(all(row["status"] == "passed" for row in report["checks"].values()))
        self.assertFalse(report["runtime_or_hardware_validated"])
        self.assertFalse(report["module_loaded_or_installed"])
        self.assertEqual(report["p2p_rm_boundary"]["open_implementation_found"], False)
        self.assertGreater(report["p2p_rm_boundary"]["open_c_files_scanned"], 0)
        self.assertEqual(
            report["source_hashes"]["R595.99.02/nvidia/nv_uvm_interface.c"],
            report["source_hashes"]["candidate/nvidia/nv_uvm_interface.c"],
        )
        self.assertEqual(
            report["source_hashes"]["R595.99.02/common/inc/rm-gpu-ops.h"],
            report["source_hashes"]["candidate/common/inc/rm-gpu-ops.h"],
        )

    def _copy_minimal_sources(self, base: Path):
        r595_open = base / "r595" / "kernel-open"
        r595 = r595_open / "nvidia-uvm"
        r580 = base / "r580"
        candidate_open = base / "candidate"
        candidate = candidate_open / "nvidia-uvm"
        for root in (r595, r580, candidate):
            root.mkdir(parents=True)

        r595_files = (
            "uvm_gpu.c",
            "uvm_mmu.c",
            "uvm_pte_batch.c",
            "uvm_hal_types.h",
            "uvm_get_rm_ptes_test.c",
        )
        candidate_files = r595_files + (
            "uvm_hal.c",
            "uvm_volta_fault_buffer.c",
            "uvm_volta_mmu.c",
            "uvm_volta_ce.c",
            "uvm_maxwell_ce.c",
        )
        for name in r595_files:
            shutil.copy2(DEFAULT_R595 / name, r595 / name)
        for name in candidate_files:
            shutil.copy2(DEFAULT_CANDIDATE / name, candidate / name)
        shutil.copy2(DEFAULT_R580 / "uvm_volta_fault_buffer.c", r580 / "uvm_volta_fault_buffer.c")

        for root, source_root in ((r595_open, DEFAULT_R595.parent),
                                  (candidate_open, DEFAULT_CANDIDATE.parent)):
            for relative in (Path("nvidia/nv_uvm_interface.c"),
                             Path("common/inc/rm-gpu-ops.h")):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_root / relative, destination)
        return r595, r580, candidate

    def test_audit_rejects_bar1_atomic_selection_contract_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            r595, r580, candidate = self._copy_minimal_sources(Path(temporary))
            for root in (r595, candidate):
                path = root / "uvm_gpu.c"
                source = path.read_text(encoding="utf-8")
                source = source.replace(
                    "return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT;",
                    "return UVM_APERTURE_SYS;",
                    1,
                )
                path.write_text(source, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "parent_gpu_peer_aperture"):
                audit(r595, r580, candidate)

    def test_audit_rejects_p2p_rm_wrapper_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            r595, r580, candidate = self._copy_minimal_sources(Path(temporary))
            source = candidate.parent / "nvidia/nv_uvm_interface.c"
            text = source.read_text(encoding="utf-8")
            source.write_text(text.replace("rm_gpu_ops_get_p2p_caps(",
                                           "rm_gpu_ops_get_p2p_caps_drift(", 1),
                              encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "candidate P2P interface differs"):
                audit(r595, r580, candidate)


if __name__ == "__main__":
    unittest.main()
