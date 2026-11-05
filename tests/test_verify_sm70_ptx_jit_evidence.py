#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for linking a PTX-only build to a stock V100 run."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/verify_sm70_ptx_jit_evidence.py"


def load_tool():
    if not TOOL_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("verify_sm70_ptx_jit_evidence", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ToolAvailability(unittest.TestCase):
    def test_ptx_jit_evidence_verifier_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "SM70 PTX-JIT evidence verifier is missing")


@unittest.skipUnless(TOOL_PATH.is_file(), "SM70 PTX-JIT evidence verifier is missing")
class EvidenceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def setUp(self):
        self.artifact = b"ptx-only fatbin fixture"
        self.artifact_sha = hashlib.sha256(self.artifact).hexdigest()
        self.tool_sha = "a" * 64
        self.build = {
            "schema": "nvidia-hybrid-sm70-ptx-jit-image-build-v1",
            "status": "ptx-only-sm70-fatbin-built-and-statically-inspected",
            "artifact": {"bytes": len(self.artifact), "sha256": self.artifact_sha},
            "source_ptx": {"ptx_version": "8.8", "target": "sm_70",
                           "entrypoints": ["hybrid_arch", "hybrid_empty", "hybrid_add"]},
            "builder": {"cuobjdump_sha256": self.tool_sha},
            "cuda_or_gpu_execution_tested": False,
            "module_loaded_or_installed": False,
        }
        self.runtime = {
            "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
            "qualification": "v100-reference-report-contract-valid",
            "exit_code": 0,
            "module": {"bytes": len(self.artifact), "sha256": self.artifact_sha},
            "module_after": {"bytes": len(self.artifact), "sha256": self.artifact_sha},
            "payload_cleanup_passed": True,
            "probe": {"sha256": "b" * 64},
            "probe_contract": {"probe_sha256": "b" * 64},
            "execution_scope": {"guest_driver_changed": False, "module_loaded": False,
                                "pci_binding_changed": False, "vm_management_issued": False},
            "remote": {
                "qualification": "v100-reference-report-contract-valid",
                "host": "pc3",
                "host_kernel_release": "7.0.0-38-generic",
                "execution_scope": {"guest_driver_changed": False, "module_loaded": False,
                                    "pci_binding_changed": False, "vm_management_issued": False},
                "guest": {"hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
                          "driver_version": "580.178.04", "name": "Tesla V100-SXM2-16GB",
                          "pci": "0000:00:05.0", "compute_process_count_before": 0,
                          "memory_used_mib_before": "0"},
                "driver_library": {"path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
                                    "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"},
                "probe": {"driver_api": 13000,
                          "execution_mode": "resident-contexts-sequential-kernels",
                          "concurrent_kernel_execution_validated": False,
                          "hybrid_validated": False, "context_coexistence_passed": False,
                          "devices": [{"compute_capability": "7.0", "sm": 70,
                                       "architecture_kernel_passed": True,
                                       "synchronous_passed": True,
                                       "synchronous_sizes": [1, 31, 256, 4096, 65537],
                                       "asynchronous_passed": True,
                                       "asynchronous_sizes": [1, 31, 256, 4096, 65537],
                                       "cleanup_passed": True, "cleanup_errors": [],
                                       "concurrent_kernel_execution_validated": False,
                                       "tested": True, "targeted": True}]},
                "guest_after": {"compute_process_count": 0, "memory_used_mib": "0"},
                "compute_process_count_prelaunch": 0,
                "compute_process_count_after_probe": 0,
                "compute_process_count_after": 0,
                "compute_process_query_after_valid": True,
                "guest_cleanup_passed": True,
                "payload_file_cleanup_passed": True,
            },
        }
        self.inspection = {
            "list_elf": "cuobjdump info : No ELF file found",
            "list_ptx": "PTX file    1: hybrid_probe.sm70-ptx.1.sm_70.ptx",
            "dump_ptx": (".version 8.8\n.target sm_70\n"
                         ".entry hybrid_arch() {}\n.entry hybrid_empty() {}\n"
                         ".entry hybrid_add() {}\n"),
        }

    def verify(self):
        return self.tool.validate_ptx_jit_evidence(
            self.build, self.runtime, self.artifact, self.tool_sha, self.inspection)

    def test_accepts_ptx_only_sm70_kernel_execution_with_cleanup(self):
        result = self.verify()
        self.assertEqual(result["status"], "ptx-only-sm70-kernel-executed-on-v100")
        self.assertTrue(result["ptx_only_image"])
        self.assertFalse(result["same_linux_hybrid_validated"])

    def test_rejects_any_cubin_elf_inside_the_ptx_image(self):
        self.inspection["list_elf"] = "ELF file 1: sm_70.cubin"
        with self.assertRaisesRegex(ValueError, "contains an ELF image"):
            self.verify()

    def test_rejects_missing_or_duplicate_ptx_images(self):
        self.inspection["list_ptx"] += "\nPTX file 2: sm_120.ptx"
        with self.assertRaisesRegex(ValueError, "exactly one SM70 PTX image"):
            self.verify()

    def test_rejects_an_embedded_ptx_target_or_entrypoint_mismatch(self):
        self.inspection["dump_ptx"] = ".version 8.8\n.target sm_80\n.entry hybrid_arch() {}"
        with self.assertRaisesRegex(ValueError, "PTX target or entrypoints"):
            self.verify()

    def test_rejects_runtime_module_hash_mismatch(self):
        self.runtime["module"]["sha256"] = "d" * 64
        self.runtime["module_after"]["sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "runtime did not load the audited artifact"):
            self.verify()

    def test_rejects_wrong_guest_gpu_or_driver(self):
        self.runtime["remote"]["guest"]["driver_version"] = "595.99.02"
        with self.assertRaisesRegex(ValueError, "pinned stock V100 R580 guest"):
            self.verify()

    def test_rejects_partial_kernel_sizes_or_wrong_numeric_arch_kernel(self):
        device = self.runtime["remote"]["probe"]["devices"][0]
        device["asynchronous_sizes"].pop()
        with self.assertRaisesRegex(ValueError, "synchronous/asynchronous SM70 kernel"):
            self.verify()

    def test_rejects_cleanup_leak_or_hybrid_claim(self):
        self.runtime["remote"]["guest_after"]["memory_used_mib"] = "256"
        with self.assertRaisesRegex(ValueError, "cleanup or process-count gate"):
            self.verify()
        self.runtime["remote"]["guest_after"]["memory_used_mib"] = "0"
        self.runtime["remote"]["probe"]["hybrid_validated"] = True
        with self.assertRaisesRegex(ValueError, "single-GPU reference must remain"):
            self.verify()

    def test_rejects_driver_or_pci_side_effects(self):
        self.runtime["execution_scope"]["pci_binding_changed"] = True
        with self.assertRaisesRegex(ValueError, "scope was not read-only"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
