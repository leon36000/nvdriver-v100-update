# SPDX-License-Identifier: MIT
"""Acceptance tests for the guarded stock-V100 P2P A/B injection mode."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_pc3_v100_guest_reference.py"
SPEC = importlib.util.spec_from_file_location("pc3_v100_reference", TOOL)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class Pc3V100P2PFaultContractTests(unittest.TestCase):
    def test_fault_diagnostic_must_match_selected_mode(self):
        for mode in ("alloc", "register-va", "register-vidmem", "unregister-vidmem"):
            with self.subTest(mode=mode):
                self.assertEqual(
                    RUNNER.validate_p2p_fault_diagnostics(
                        f"HYBRID_RM_P2P_FAULT denied={mode} errno=EIO\n", mode), 1)

    def test_fault_diagnostic_counts_every_matching_request_in_the_selected_family(self):
        self.assertEqual(
            RUNNER.validate_p2p_fault_diagnostics(
                "HYBRID_RM_P2P_FAULT denied=register-va errno=EIO\n"
                "HYBRID_RM_P2P_FAULT denied=register-va errno=EIO\n",
                "register-va"), 2)

    def test_fault_diagnostic_rejects_missing_wrong_or_unrecognized_denial(self):
        with self.assertRaises(ValueError):
            RUNNER.validate_p2p_fault_diagnostics("probe stopped before P2P\n", "alloc")
        with self.assertRaises(ValueError):
            RUNNER.validate_p2p_fault_diagnostics(
                "HYBRID_RM_P2P_FAULT denied=register-va errno=EIO\n", "alloc")
        with self.assertRaises(ValueError):
            RUNNER.validate_p2p_fault_diagnostics(
                "HYBRID_RM_P2P_FAULT denied=unknown errno=EIO\n", "alloc")

    def test_fault_diagnostic_rejects_tracking_overflow_even_with_denial(self):
        with self.assertRaises(ValueError):
            RUNNER.validate_p2p_fault_diagnostics(
                "HYBRID_RM_P2P_FAULT denied=register-va errno=EIO\n"
                "HYBRID_RM_P2P_FAULT tracking-overflow\n", "register-va")

    def test_applied_fault_is_valid_evidence_even_if_cuda_probe_exits_on_it(self):
        expected = {}
        before = {}
        after = {}
        for name in ("probe", "module", "p2p-fault-shim"):
            digest = ("a" if name == "probe" else "b" if name == "module" else "c") * 64
            path = "/tmp/codex-v100-ref-" + name
            expected[name] = {"bytes": 100, "sha256": digest}
            before[name] = {**expected[name], "guest_path": path}
            after[path] = expected[name]
        remote = {
            "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
            "host": "pc3", "host_kernel_release": "6.8.0-147-generic",
            "qualification": "probe-executed", "memory_mode": "device",
            "managed_prefetch_requested": False, "cuda_graphs_requested": False,
            "performance_benchmark_requested": False,
            "phase_capture_requested": False, "phase": None,
            "libcuda_override_requested": False,
            "p2p_fault_requested": True, "p2p_fault_mode": "alloc",
            "p2p_fault_denial_count": 1,
            "guest": {"hostname": "pc3-v100", "name": "Tesla V100-SXM2-16GB",
                      "uuid": "GPU-12345678-1234-1234-1234-123456789abc",
                      "pci": "0000:81:00.0", "kernel_release": "6.8.0-147-generic",
                      "driver_version": "580.178.04"},
            "guest_after": {"hostname": "pc3-v100", "uuid": "GPU-12345678-1234-1234-1234-123456789abc",
                            "pci": "0000:81:00.0", "compute_process_count": 0},
            "guest_cleanup_passed": True, "payload_file_cleanup_passed": True,
            "execution_scope": {"guest_driver_changed": False, "module_loaded": False,
                                "vm_management_issued": False, "pci_binding_changed": False},
            "probe_exit_code": 1,
            "probe": {"schema": "nvidia-hybrid-probe-v2", "status": "fault-injected"},
            "probe_stderr": "HYBRID_RM_P2P_FAULT denied=alloc errno=EIO\n",
            "artifacts_before": before, "artifacts_after": after,
        }
        qualification = RUNNER.validate_remote_acceptance(
            remote, expected, p2p_fault_mode="alloc")
        self.assertEqual(qualification,
                         "p2p-fault-injection-report-contract-valid")

    def test_fault_injection_stays_in_child_probe_environment(self):
        cleaned = RUNNER.clean_cuda_environment({
            "PATH": "/usr/bin", "LD_PRELOAD": "/tmp/untrusted.so",
            "CUDA_VISIBLE_DEVICES": "bad", "NVIDIA_DRIVER_CAPABILITIES": "compute",
        }, "GPU-test")
        self.assertNotIn("LD_PRELOAD", cleaned)
        self.assertEqual(cleaned["CUDA_VISIBLE_DEVICES"], "GPU-test")
        self.assertIn('"LD_PRELOAD":str(fault_library)', RUNNER.REMOTE_ROOT_SCRIPT)

    def test_cli_requires_fault_mode_and_shim_together_and_isolates_full_probe(self):
        with tempfile.TemporaryDirectory(prefix="p2p-fault-cli-") as directory:
            shim = Path(directory) / "p2p-fault.so"
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            header[16:18] = (3).to_bytes(2, "little")
            header[18:20] = (62).to_bytes(2, "little")
            shim.write_bytes(header)
            report = str(Path(directory) / "result.json")
            args = RUNNER.parse_args([
                "--p2p-fault", "alloc", "--p2p-fault-shim", str(shim),
                "--evidence", report,
            ])
            self.assertEqual(args.p2p_fault, "alloc")
            self.assertEqual(args.p2p_fault_shim, shim)
            with self.assertRaises(SystemExit):
                RUNNER.parse_args(["--p2p-fault", "alloc", "--evidence", report])
            with self.assertRaises(SystemExit):
                RUNNER.parse_args(["--p2p-fault-shim", str(shim), "--evidence", report])
            with self.assertRaises(SystemExit):
                RUNNER.parse_args([
                    "--p2p-fault", "alloc", "--p2p-fault-shim", str(shim),
                    "--phase", "context", "--evidence", report,
                ])


if __name__ == "__main__":
    unittest.main()
