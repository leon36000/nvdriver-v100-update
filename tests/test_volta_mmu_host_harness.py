#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the host MMU callback harness against pinned R580/R595 sources."""
import hashlib
import json
from pathlib import Path
import shutil
import signal
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    prepare_overlay,
)
from tools.run_volta_mmu_host_harness import (  # noqa: E402
    build_harness,
    extract_test_vectors,
    run,
    verify_pde_type_contract,
    verify_volta_mmu_header_identity,
)
from tools.probe_r595_gv100_complete_hal import (  # noqa: E402
    adapt_volta_noncoherent_mmu_pte,
)


R580_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
R580_UVM = (
    ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04/nvidia-uvm"
)
R595_SOURCE = (
    ROOT / "build/experiments/r595-r580-patch-replay-fabric-status-v9-20261024/source/kernel-open"
)
R595_V5_UVM = (
    ROOT / "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v5-20261027T222520Z/nvidia-uvm"
)


class VoltaMmuHostHarnessTests(unittest.TestCase):
    def test_unadapted_r595_volta_mmu_asserts_on_bar1_noncoherent_aperture(self):
        """Pin the exact v5 failure that motivated the adapter."""
        harness, _ = build_harness(R580_UVM, R595_V5_UVM)
        marker = "    return failures ? 1 : 0;"
        probe = """    failures += check("candidate-bar1-sys-noncoherent",
        candidate_make_pte_volta(UVM_APERTURE_SYS_NON_COHERENT,
                                 0x399999999999000ULL,
                                 UVM_PROT_READ_ONLY,
                                 UVM_MMU_PTE_FLAGS_CACHED),
        0x399999999999C7ULL);
"""
        self.assertEqual(harness.count(marker), 1)
        harness = harness.replace(marker, probe + marker, 1)

        with tempfile.TemporaryDirectory(prefix="volta-noncoherent-red-") as temporary:
            temporary_root = Path(temporary)
            c_source = temporary_root / "probe.c"
            binary = temporary_root / "probe"
            c_source.write_text(harness)
            common_inc = R580_UVM.parent / "common/inc"
            compiled = subprocess.run(
                ["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-I", str(common_inc), "-I", str(R595_V5_UVM),
                 str(c_source), "-o", str(binary)],
                capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)

        self.assertEqual(executed.returncode, -signal.SIGABRT, executed.stderr)
        self.assertIn("candidate_make_pte_volta: Assertion `0' failed", executed.stderr)

    def test_candidate_gv100_field_header_must_match_pinned_r580(self):
        pinned_header = b"#define NV_MMU_VER2_PDE_ADDRESS_SYS 53:8\n"
        verify_volta_mmu_header_identity(pinned_header, pinned_header)
        with self.assertRaisesRegex(ValueError, "differs from pinned R580"):
            verify_volta_mmu_header_identity(
                pinned_header, b"#define NV_MMU_VER2_PDE_ADDRESS_SYS 52:8\n")

    def test_page_tree_vector_audit_rejects_changed_47bit_expected_value(self):
        valid = """
            hal->make_pte(UVM_APERTURE_PEER_0, 0x5BBBBBBBB000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x2DD1BBBBBBC3
            hal->unmapped_pte(page_size) == 0x20
            hal->unmapped_pte(page_size) == 0
            hal->make_pte(UVM_APERTURE_SYS, 0x399999999999000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x399999999999C5
            hal->make_pte(UVM_APERTURE_VID, 0x1BBBBBB000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x1BBBBBBC1
            hal->make_pte(UVM_APERTURE_PEER_0, 0x1BBBBBB000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x1BBBBBBC3
            alloc_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x399999999999000LL);
            alloc_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBB000LL);
            alloc_big_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x399999999999900LL);
            alloc_big_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBBB00LL);
            TEST_CHECK_RET(pde_bits[0] == 0x3999999999990C);
            TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB0A);
            TEST_CHECK_RET(pde_bits[0] == 0x3999999999999C && pde_bits[1] == 0x1BBBBBB0A);
            TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBBBA && pde_bits[1] == 0x3999999999990C);
            if (g_uvm_global.ats.enabled)
                TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB2A);
            else
                TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB0A);
        """
        extract_test_vectors(valid)
        with self.assertRaisesRegex(ValueError, "page-tree vectors changed"):
            extract_test_vectors(valid.replace("0x2DD1BBBBBBC3", "0x2DD1BBBBBBC2"))

    def test_page_tree_vector_audit_requires_volta_pde_vectors(self):
        valid = """
            hal->unmapped_pte(page_size) == 0x20;
            hal->unmapped_pte(page_size) == 0;
            hal->make_pte(UVM_APERTURE_SYS, 0x399999999999000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x399999999999C5;
            hal->make_pte(UVM_APERTURE_VID, 0x1BBBBBB000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x1BBBBBBC1;
            hal->make_pte(UVM_APERTURE_PEER_0, 0x1BBBBBB000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x1BBBBBBC3;
            hal->make_pte(UVM_APERTURE_PEER_0, 0x5BBBBBBBB000LL,
                          UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED) == 0x2DD1BBBBBBC3;
            alloc_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x399999999999000LL);
            alloc_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBB000LL);
            alloc_big_sys = fake_table_alloc(UVM_APERTURE_SYS, 0x399999999999900LL);
            alloc_big_vid = fake_table_alloc(UVM_APERTURE_VID, 0x1BBBBBBB00LL);
            hal->make_pde(pde_bits, phys_allocs, &dir, 0);
            TEST_CHECK_RET(pde_bits[0] == 0x3999999999990C);
            TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB0A);
            TEST_CHECK_RET(pde_bits[0] == 0x3999999999999C && pde_bits[1] == 0x1BBBBBB0A);
            TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBBBA && pde_bits[1] == 0x3999999999990C);
            if (g_uvm_global.ats.enabled)
                TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB2A);
            else
            TEST_CHECK_RET(pde_bits[0] == 0x1BBBBBB0A);
        """
        extract_test_vectors(valid)
        with self.assertRaisesRegex(ValueError, "PDE"):
            extract_test_vectors(valid.replace("0x1BBBBBB2A", "0x1BBBBBB2B"))

    def test_selected_pinned_callback_bodies_compile_and_match_source_vectors(self):
        for path in (R580_ARCHIVE, R580_UVM, R595_SOURCE):
            self.assertTrue(path.exists(), f"pinned input is missing: {path}")

        with tempfile.TemporaryDirectory(prefix="volta-mmu-harness-test-") as temporary:
            temporary_root = Path(temporary)
            overlay = temporary_root / "overlay"
            prepare_overlay(
                R580_ARCHIVE,
                R595_SOURCE,
                overlay,
                expected_archive_sha256=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
                compile_probe_adapter=True,
            )
            r580_volta = (R580_UVM / "uvm_volta_mmu.c").read_text()
            candidate_volta = (overlay / "nvidia-uvm/uvm_volta_mmu.c").read_text()
            volta_header = (overlay / "nvidia-uvm/hwref/volta/gv100/dev_mmu.h").read_text()
            r595_types = (overlay / "nvidia-uvm/uvm_hal_types.h").read_text()
            candidate_volta, adapter_evidence = adapt_volta_noncoherent_mmu_pte(
                candidate_volta, volta_header, r595_types)
            (overlay / "nvidia-uvm/uvm_volta_mmu.c").write_text(candidate_volta)
            verify_pde_type_contract(
                (R580_UVM / "uvm_hal_types.h").read_text(),
                (R580_UVM / "uvm_mmu.h").read_text(),
                (R580_UVM / "uvm_global.h").read_text(),
                r580_volta,
                candidate_volta,
            )
            with self.assertRaisesRegex(ValueError, "MMU_BIG/MMU_SMALL"):
                verify_pde_type_contract(
                    (R580_UVM / "uvm_hal_types.h").read_text(),
                    (R580_UVM / "uvm_mmu.h").read_text(),
                    (R580_UVM / "uvm_global.h").read_text(),
                    r580_volta,
                    candidate_volta.replace("#define MMU_BIG 0", "#define MMU_BIG 1", 1),
                )
            result = run(
                R580_UVM,
                overlay / "nvidia-uvm",
                temporary_root / "report.json",
                temporary_root / "harness.log",
            )
            report = json.loads((temporary_root / "report.json").read_text())

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["checks_passed"], 32)
        self.assertFalse(report["hardware_validated"])
        self.assertFalse(report["module_loaded"])
        self.assertFalse(report["module_installed"])
        self.assertEqual(report["assertion_guard_checks_passed"], 2)
        self.assertEqual(
            [guard["name"] for guard in report["assertion_guard_results"]],
            ["hwvalue64-field-overflow", "peer-id-out-of-range"],
        )
        self.assertEqual(len(report["results"]), 32)
        self.assertTrue(any("candidate-sys-noncoherent-bar1 actual=0x399999999999c7"
                            in line for line in report["results"]))
        self.assertEqual(report["sources"]["candidate_volta_mmu"]["sha256"],
                         adapter_evidence["adapted_source_sha256"])
        self.assertEqual(report["runner_sha256"],
                         hashlib.sha256((ROOT / "tools/run_volta_mmu_host_harness.py").read_bytes()).hexdigest())
        self.assertTrue(any("peer0-47bit-cached-readonly" in line for line in report["results"]))
        self.assertTrue(any("candidate-poisoned-volta actual=0x1bad000e9" in line
                            for line in report["results"]))
        self.assertTrue(any("candidate-dual-pde-big-sys-small-vid-low actual=0x3999999999999c"
                            in line for line in report["results"]))
        self.assertTrue(any("candidate-no-ats-depth2-enabled actual=0x1bbbbbb2a"
                            in line for line in report["results"]))
        self.assertTrue(any("r580-no-ats-depth2-disabled actual=0x1bbbbbb0a"
                            in line for line in report["results"]))
        self.assertEqual(
            report["sources"]["r580_volta_dev_mmu"]["sha256"],
            report["sources"]["volta_dev_mmu"]["sha256"],
        )

    def test_exact_r595_v5_candidate_fails_noncoherent_aperture_vector(self):
        self.assertTrue(R595_V5_UVM.is_dir(), f"exact v5 candidate is missing: {R595_V5_UVM}")
        with tempfile.TemporaryDirectory(prefix="volta-mmu-v5-harness-test-") as temporary:
            temporary_root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "host harness vector check failed") as raised:
                run(R580_UVM, R595_V5_UVM,
                    temporary_root / "report.json", temporary_root / "harness.log")

        self.assertIn("candidate_make_pte_volta", str(raised.exception))
        self.assertIn("Assertion `0' failed", str(raised.exception))

    def test_adapted_r595_candidate_passes_host_callback_harness(self):
        self.assertTrue(R595_V5_UVM.is_dir(), f"exact v5 candidate is missing: {R595_V5_UVM}")
        with tempfile.TemporaryDirectory(prefix="volta-mmu-adapted-harness-test-") as temporary:
            temporary_root = Path(temporary)
            candidate = temporary_root / "candidate"
            (candidate / "hwref/volta/gv100").mkdir(parents=True)
            shutil.copy2(R595_V5_UVM / "uvm_pascal_mmu.c", candidate / "uvm_pascal_mmu.c")
            shutil.copy2(R595_V5_UVM / "hwref/volta/gv100/dev_mmu.h",
                         candidate / "hwref/volta/gv100/dev_mmu.h")
            adapted_source, adapter_evidence = adapt_volta_noncoherent_mmu_pte(
                (R595_V5_UVM / "uvm_volta_mmu.c").read_text(),
                (R595_V5_UVM / "hwref/volta/gv100/dev_mmu.h").read_text(),
                (R595_V5_UVM / "uvm_hal_types.h").read_text(),
            )
            (candidate / "uvm_volta_mmu.c").write_text(adapted_source)
            result = run(R580_UVM, candidate,
                         temporary_root / "report.json", temporary_root / "harness.log")
            report = json.loads((temporary_root / "report.json").read_text())

        self.assertEqual(result["status"], "passed")
        self.assertEqual(report["schema"], "volta-mmu-host-harness-v6")
        self.assertEqual(report["checks_passed"], 32)
        self.assertEqual(report["differential_pte"]["vectors_passed"], 8448)
        self.assertEqual(report["differential_pte"]["seed_hex"], "0x4d595df4d0f33173")
        self.assertEqual(report["sources"]["candidate_volta_mmu"]["sha256"],
                         adapter_evidence["adapted_source_sha256"])
        self.assertTrue(any("candidate-sys-noncoherent-bar1 actual=0x399999999999c7"
                            in line for line in report["results"]))
        self.assertEqual(report["assertion_guard_checks_passed"], 2)
        self.assertFalse(report["hardware_validated"])
        self.assertFalse(report["module_loaded"])
        self.assertFalse(report["module_installed"])

    def test_deterministic_pte_differential_rejects_high_system_address_mutant(self):
        self.assertTrue(R595_V5_UVM.is_dir(), f"exact v5 candidate is missing: {R595_V5_UVM}")
        with tempfile.TemporaryDirectory(prefix="volta-mmu-high-address-mutant-") as temporary:
            temporary_root = Path(temporary)
            candidate = temporary_root / "candidate"
            (candidate / "hwref/volta/gv100").mkdir(parents=True)
            shutil.copy2(R595_V5_UVM / "uvm_pascal_mmu.c", candidate / "uvm_pascal_mmu.c")
            shutil.copy2(R595_V5_UVM / "hwref/volta/gv100/dev_mmu.h",
                         candidate / "hwref/volta/gv100/dev_mmu.h")
            adapted_source, _ = adapt_volta_noncoherent_mmu_pte(
                (R595_V5_UVM / "uvm_volta_mmu.c").read_text(),
                (R595_V5_UVM / "hwref/volta/gv100/dev_mmu.h").read_text(),
                (R595_V5_UVM / "uvm_hal_types.h").read_text(),
            )
            marker = "    address >>= NV_MMU_VER2_PTE_ADDRESS_SHIFT;"
            self.assertEqual(adapted_source.count(marker), 1)
            mutant_source = adapted_source.replace(
                marker,
                "    if (address & (1ULL << 56))\n"
                "        pte_bits ^= 1ULL << 6;\n\n" + marker,
                1,
            )
            (candidate / "uvm_volta_mmu.c").write_text(mutant_source)
            with self.assertRaisesRegex(RuntimeError, "pte-differential-mismatch") as raised:
                run(R580_UVM, candidate,
                    temporary_root / "report.json", temporary_root / "harness.log")

        self.assertIn("address=0x", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
