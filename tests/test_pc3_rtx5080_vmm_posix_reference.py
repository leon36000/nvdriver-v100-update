from __future__ import annotations

import base64
import ast
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_pc3_rtx5080_vmm_posix_reference.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("rtx5080_vmm_posix_reference", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("RTX 5080 VMM POSIX reference runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_probe_result():
    child = {
        "status": "phase-passed",
        "phase": "vmm-posix_fd-importer",
        "numerical_phase_passed": True,
        "initial_values_match": True,
        "posix_shareable_fd_opened": True,
        "posix_shareable_fd_closed": True,
        "cleanup_passed": True,
        "cleanup_errors": [],
        "device": {"pci_bus_id": "0000:02:00.0", "sm": 120},
    }
    return {
        "schema": "nvidia-hybrid-driver-api-vmm-share-v1",
        "phase": "vmm-posix_fd-share",
        "shareable_handle_kind": "posix_fd",
        "shareable_handle_type": 1,
        "shareable_handle_bytes": 4,
        "status": "phase-passed",
        "expected_pci": "0000:02:00.0",
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
        "driver_api": 13020,
        "device": {
            "name": "NVIDIA GeForce RTX 5080",
            "pci_bus_id": "0000:02:00.0",
            "sm": 120,
            "compute_capability": "12.0",
            "unified_addressing": 1,
            "fabric_handle_support": {"status": 0, "value": 1},
            "posix_fd_handle_support": {"status": 0, "value": 1},
        },
        "attribute_support": {"status": 0, "value": 1},
        "allocation_bytes": 65536,
        "observation_valid": True,
        "allocation_created": True,
        "export_attempted": True,
        "export_succeeded": True,
        "import_attempted": True,
        "import_succeeded": True,
        "initial_values_match": True,
        "child_writeback_match": True,
        "numerical_phase_passed": True,
        "child": child,
        "posix_shareable_fd_opened": True,
        "posix_shareable_fd_closed": True,
        "cleanup_passed": True,
        "cleanup_errors": [],
        "completed_operations": [
            "cuInit", "cuCtxCreate_v2", "cuMemGetAllocationGranularity", "cuMemCreate",
            "cuMemAddressReserve", "cuMemMap", "cuMemSetAccess", "cuMemcpyHtoD_v2",
            "cuCtxSynchronize", "cuMemExportToShareableHandle", "cuMemImportFromShareableHandle",
            "cuMemcpyDtoH_v2", "close_posix_shareable_fd", "cuMemUnmap",
            "cuMemAddressFree", "cuMemRelease", "cuCtxDestroy_v2",
        ],
    }


class Pc3Rtx5080VmmPosixReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_valid_rtx5080_posix_fd_exchange_is_accepted_as_reference_only(self):
        validated = self.tool.validate_probe_result(valid_probe_result(), 0)
        self.assertEqual(validated["qualification"], "rtx5080-vmm-posix-reference-validated")
        self.assertTrue(validated["numeric_exchange_passed"])
        self.assertFalse(validated["hybrid_validated"])

    def test_wrong_gpu_identity_is_rejected(self):
        report = valid_probe_result()
        report["device"]["pci_bus_id"] = "0000:03:00.0"
        with self.assertRaisesRegex(ValueError, "PCI identity"):
            self.tool.validate_probe_result(report, 0)

    def test_vmm_success_requires_both_numeric_directions(self):
        report = valid_probe_result()
        report["child_writeback_match"] = False
        with self.assertRaisesRegex(ValueError, "numeric exchange"):
            self.tool.validate_probe_result(report, 0)

    def test_posix_handle_must_be_closed_and_cuda_cleanup_must_pass(self):
        report = valid_probe_result()
        report["posix_shareable_fd_closed"] = False
        with self.assertRaisesRegex(ValueError, "descriptor cleanup"):
            self.tool.validate_probe_result(report, 0)
        report = valid_probe_result()
        report["cleanup_passed"] = False
        with self.assertRaisesRegex(ValueError, "CUDA cleanup"):
            self.tool.validate_probe_result(report, 0)

    def test_valid_api_negative_is_preserved_without_claiming_numeric_success(self):
        report = valid_probe_result()
        report.update({
            "status": "phase-failed", "posix_shareable_fd_opened": False,
            "initial_values_match": None, "child_writeback_match": None,
            "numerical_phase_passed": None, "child": None,
            "failure_operation": "cuMemCreate", "failure_code": 800,
            "failure_name": "CUDA_ERROR_NOT_PERMITTED",
        })
        report["device"]["posix_fd_handle_support"]["value"] = 0
        report["attribute_support"]["value"] = 0
        validated = self.tool.validate_probe_result(report, 0)
        self.assertEqual(validated["qualification"],
                         "rtx5080-vmm-posix-negative-observation-validated")
        self.assertFalse(validated["numeric_exchange_passed"])

    def test_remote_scope_requires_unchanged_module_library_and_gpu(self):
        gpu = {"name": "NVIDIA GeForce RTX 5080", "uuid": "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77",
               "pci": "0000:02:00.0", "driver_version": "595.99.02", "binding": "nvidia"}
        module = {"loaded_version": "595.99.02", "path": "/lib/modules/nvidia.ko",
                  "sha256": "a" * 64}
        library = {"path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
                   "sha256": "b" * 64, "bytes": 96_000_000}
        remote = {
            "schema": "nvidia-hybrid-pc3-rtx5080-vmm-posix-reference-v1",
            "status": "complete", "hostname": "pc3", "kernel_release": "7.0.0-38-generic",
            "gpu": gpu, "gpu_after": gpu, "module_before": module, "module_after": module,
            "libcuda": library, "gpu_compute_processes_before": [],
            "gpu_compute_processes_after": [], "cleanup_passed": True,
            "remote_workspace_removed": True, "probe_source_sha256": self.tool.PROBE_SOURCE_SHA256,
            "probe_source_bytes": 100, "cuda_visible_devices": gpu["uuid"],
            "execution_scope": {key: False for key in (
                "driver_or_module_changed", "pci_binding_changed", "vm_management_issued",
                "gpu_reset_requested", "imex_configuration_changed")},
            "probe": valid_probe_result(), "probe_exit_code": 0,
        }
        remote["probe"]["driver_library_path"] = library["path"]
        validated = self.tool.validate_remote_report(remote)
        self.assertTrue(validated["numeric_exchange_passed"])
        remote["module_after"] = {**module, "sha256": "c" * 64}
        with self.assertRaisesRegex(ValueError, "module identity changed"):
            self.tool.validate_remote_report(remote)

    def test_probe_artifact_payload_is_hash_pinned_and_bounded(self):
        data = b"hash-pinned-probe"
        payload = self.tool.probe_artifact_payload(data, hashlib.sha256(data).hexdigest())
        self.assertEqual(base64.b64decode(payload["base64"], validate=True), data)
        self.assertEqual(payload["sha256"], hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(ValueError, "hash"):
            self.tool.probe_artifact_payload(data, "0" * 64)

    def test_remote_worker_has_strictly_scoped_cuda_and_no_system_mutations(self):
        script = self.tool.REMOTE_SCRIPT
        compile(script, "<remote-vmm-worker>", "exec")
        worker_ast = ast.parse(script)
        canonical = next(node for node in worker_ast.body
                         if isinstance(node, ast.FunctionDef) and node.name == "canonical_pci")
        namespace = {}
        exec(compile(ast.Module(body=[canonical], type_ignores=[]),
                     "<remote-pci-parser>", "exec"), namespace)
        self.assertEqual(namespace["canonical_pci"]("0000:02:00.0"), "0000:02:00.0")
        with self.assertRaises(RuntimeError):
            namespace["canonical_pci"]("0000:02:00.0; reboot")
        for forbidden in ("modprobe", "rmmod", "reboot", "virsh", "nvidia-smi --gpu-reset"):
            self.assertNotIn(forbidden, script)
        self.assertIn("StrictHostKeyChecking=yes", self.tool.SSH_OPTIONS)
        self.assertIn("CUDA_VISIBLE_DEVICES", script)


if __name__ == "__main__":
    unittest.main()
