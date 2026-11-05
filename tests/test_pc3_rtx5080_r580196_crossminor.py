from __future__ import annotations

import ast
import copy
import tempfile
import unittest
from pathlib import Path

from tools import run_pc3_rtx5080_r580196_crossminor as tool


def valid_remote() -> dict:
    gpu = {"name": "NVIDIA GeForce RTX 5080", "uuid": tool.EXPECTED_UUID,
           "pci": tool.EXPECTED_PCI, "driver_version": tool.EXPECTED_DRIVER,
           "binding": "nvidia"}
    module = {"loaded_version": tool.EXPECTED_DRIVER, "path": "/lib/modules/nvidia.ko",
              "sha256": "a" * 64, "bytes": 15_000_000}
    system_libcuda = {"path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
                      "sha256": "b" * 64, "bytes": 96_000_000}
    return {
        "schema": "nvidia-hybrid-pc3-rtx5080-r58019607-crossminor-remote-v1",
        "status": "complete", "hostname": "pc3", "kernel_release": tool.EXPECTED_KERNEL,
        "gpu_before": gpu, "gpu_after": copy.deepcopy(gpu),
        "module_before": module, "module_after": copy.deepcopy(module),
        "system_libcuda_before": system_libcuda,
        "system_libcuda_after": copy.deepcopy(system_libcuda),
        "compute_pids_before": [], "compute_pids_prelaunch": [], "compute_pids_after": [],
        "staged_artifacts": {
            "probe": {"bytes": 182_184, "sha256": tool.reference.EXPECTED_ARTIFACTS["probe"][1]},
            "fatbin": {"bytes": 19_016, "sha256": tool.reference.EXPECTED_ARTIFACTS["fatbin"][1]},
            "libcuda": {"bytes": tool.LIBCUDA_BYTES, "sha256": tool.LIBCUDA_SHA256},
        },
        "staged_libcuda_path": "/tmp/codex-rtx5080-r580196-abc/lib/libcuda.so.1",
        "phase": {
            "status": "phase-passed", "phase": "kernel",
            "driver_library_path": "/tmp/codex-rtx5080-r580196-abc/lib/libcuda.so.1",
            "driver_api": tool.EXPECTED_API, "result_value": 1200,
            "expected_result": 1200, "numeric_result_passed": True,
            "selected_device": {"name": "NVIDIA GeForce RTX 5080",
                                "pci_bus_id": tool.EXPECTED_PCI, "sm": 120,
                                "compute_capability": "12.0"},
            "completed_operations": ["cuInit", "cuDriverGetVersion", "cuDeviceGetCount",
                "cuCtxCreate_v2", "cuModuleLoad", "cuMemAlloc_v2",
                "cuLaunchKernel(hybrid_arch)", "cuCtxSynchronize", "cuMemcpyDtoH_v2"],
        },
        "probe_exit_code": 0,
        "cleanup_passed": True, "workspace_removed": True,
        "execution_scope": {"driver_or_module_changed": False, "pci_binding_changed": False,
                            "vm_management_issued": False, "gpu_reset_requested": False},
    }


class CrossMinorRunnerTests(unittest.TestCase):
    def test_remote_worker_is_valid_python_and_has_no_system_mutation_commands(self):
        ast.parse(tool.REMOTE_SCRIPT)
        for forbidden in ("modprobe", "rmmod", "virsh", "reboot", "setpci", "nvidia-smi --gpu-reset"):
            self.assertNotIn(forbidden, tool.REMOTE_SCRIPT)
        self.assertIn('"LD_LIBRARY_PATH":str(libdir)', tool.REMOTE_SCRIPT)
        self.assertIn('"CUDA_VISIBLE_DEVICES":EXPECTED_UUID', tool.REMOTE_SCRIPT)
        self.assertIn("StrictHostKeyChecking=yes", tool.SSH_OPTIONS)

    def test_report_accepts_exact_sm120_kernel_with_r580_user_library(self):
        result = tool.validate_remote(valid_remote())
        self.assertEqual(result["qualification"],
                         "r58019607-libcuda-on-stock-r595-rtx5080-kernel-validated")
        self.assertFalse(result["hybrid_validated"])
        self.assertEqual(result["kernel_result"], 1200)

    def test_report_classifies_exact_cuda_system_driver_mismatch_as_completed_negative_result(self):
        report = valid_remote()
        report["status"] = "failed"
        report["probe_exit_code"] = 2
        report["phase"] = {
            "status": "phase-failed", "phase": "kernel",
            "driver_library_path": report["staged_libcuda_path"],
            "driver_api": None, "completed_operations": [],
            "error": "cuInit failed with CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH): system has unsupported display driver / cuda driver combination",
        }
        result = tool.validate_remote(report)
        self.assertEqual(result["qualification"],
                         "r58019607-libcuda-rejected-by-stock-r595-system-driver-mismatch")
        self.assertFalse(result["kernel_passed"])
        self.assertEqual(result["cuda_result"], 803)

    def test_report_rejects_wrong_host_gpu_and_kernel_stack(self):
        mutations = (
            (lambda value: value.update(hostname="other"), "PC3 host"),
            (lambda value: value["gpu_before"].update(pci="0000:03:00.0"), "RTX 5080 identity"),
            (lambda value: value["gpu_after"].update(binding="vfio-pci"), "RTX 5080 identity"),
            (lambda value: value["module_after"].update(loaded_version="580.196.07"), "module identity"),
            (lambda value: value["system_libcuda_after"].update(sha256="c" * 64), "system libcuda"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                report = valid_remote()
                mutate(report)
                with self.assertRaisesRegex(ValueError, message):
                    tool.validate_remote(report)

    def test_report_requires_exact_crossminor_kernel_and_cleanup_contract(self):
        mutations = (
            (lambda value: value["phase"].update(driver_api=13020), "kernel result"),
            (lambda value: value["phase"].update(result_value=1201), "kernel result"),
            (lambda value: value["phase"].update(driver_library_path="/usr/lib/libcuda.so.595"), "staged R580.196.07"),
            (lambda value: value["phase"].update(status="phase-failed"), "kernel result"),
            (lambda value: value["phase"]["selected_device"].update(sm=70), "SM120 RTX 5080"),
            (lambda value: value["phase"].update(completed_operations=[]), "omitted required CUDA operations"),
            (lambda value: value.update(compute_pids_prelaunch=[42]), "compute-process"),
            (lambda value: value.update(workspace_removed=False), "cleanup"),
            (lambda value: value["execution_scope"].update(vm_management_issued=True), "cleanup"),
            (lambda value: value["staged_artifacts"]["libcuda"].update(sha256="d" * 64), "staged artifacts"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                report = valid_remote()
                mutate(report)
                with self.assertRaisesRegex(ValueError, message):
                    tool.validate_remote(report)

    def test_libcuda_pin_rejects_symlink_wrong_name_size_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong_name = root / "libcuda.so"
            wrong_name.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "exact R580.196.07"):
                tool.pinned_libcuda(wrong_name)
            exact_name = root / "libcuda.so.580.196.07"
            exact_name.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "exact R580.196.07"):
                tool.pinned_libcuda(exact_name)
            link_dir = root / "links"
            link_dir.mkdir()
            link = link_dir / "libcuda.so.580.196.07"
            link.symlink_to(exact_name)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                tool.pinned_libcuda(link)


if __name__ == "__main__":
    unittest.main()
