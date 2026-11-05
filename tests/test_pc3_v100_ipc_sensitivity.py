#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU contract tests for the guarded V100 CUDA IPC sensitivity run."""
from __future__ import annotations

import ast
import importlib.util
import copy
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_pc3_v100_system_features_sensitivity.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("v100_ipc_sensitivity_runner", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("V100 IPC sensitivity runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ipc_phase_result(success: bool = True):
    memory_sharing_support = {
        "virtual_memory_management": {"status": 0, "value": 1},
        "posix_file_descriptor": {"status": 0, "value": 1},
        "fabric_handle": {"status": 0, "value": 0},
    }
    device = {
        "name": "Tesla V100-SXM2-16GB", "pci_bus_id": "0000:00:05.0",
        "sm": 70, "compute_capability": "7.0", "unified_addressing": 1,
        "memory_sharing_support": copy.deepcopy(memory_sharing_support),
    }
    operations = [
        "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
        "cuCtxCreate_v2", "cuMemAlloc_v2", "cuMemcpyHtoD_v2",
        "cuIpcGetMemHandle", "child:cuCtxCreate_v2",
        "child:cuIpcOpenMemHandle_v2",
        "child:cuMemcpyDtoH_v2", "child:cuMemcpyHtoD_v2",
        "child:cuCtxSynchronize", "child:cuIpcCloseMemHandle",
        "cuCtxSynchronize", "cuMemcpyDtoH_v2", "cuMemFree_v2",
        "cuCtxDestroy_v2", "child:cuCtxDestroy_v2",
    ]
    if not success:
        operations.remove("child:cuIpcOpenMemHandle_v2")
        operations.remove("child:cuMemcpyDtoH_v2")
        operations.remove("child:cuMemcpyHtoD_v2")
        operations.remove("child:cuCtxSynchronize")
        operations.remove("child:cuIpcCloseMemHandle")
        operations.remove("cuCtxSynchronize")
        operations.remove("cuMemcpyDtoH_v2")
    return {
        "schema": "nvidia-hybrid-v100-driver-api-ipc-memory-v1",
        "status": "phase-passed" if success else "phase-failed",
        "phase": "ipc-memory-share",
        "expected_pci": "0000:00:05.0",
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
        "driver_api": 13000,
        "device": device,
        "importer_device": {
            **{key: value for key, value in device.items() if key != "memory_sharing_support"},
            "memory_sharing_support": copy.deepcopy(memory_sharing_support),
        },
        "allocation_bytes": 64,
        "ipc_handle_bytes": 64,
        "export_attempted": True,
        "open_attempted": True,
        "open_succeeded": success,
        "ipc_succeeded": success,
        "initial_values_match": True if success else None,
        "child_writeback_match": True if success else None,
        "failure_operation": None if success else "child:cuIpcOpenMemHandle_v2",
        "failure_code": None if success else 801,
        "failure_name": None if success else "CUDA_ERROR_NOT_SUPPORTED",
        "observation_valid": True,
        "completed_operations": operations,
        "cleanup_passed": True,
        "cleanup_errors": [],
        "error": "",
    }


def ipc_guest_report(tool, success_by_mask=None):
    success_by_mask = success_by_mask or {9: True, 8: True, 1: True, 0: True}
    common = {
        "schema": "nvidia-hybrid-v100-system-features-ipc-sensitivity-guest-v1",
        "workload": "ipc-memory-share",
        "status": "observed",
        "hostname": "pc3-v100",
        "kernel_release": "6.8.0-147-generic",
        "gpu": {
            "name": "Tesla V100-SXM2-16GB",
            "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e",
            "pci": "0000:00:05.0",
            "driver_version": "580.178.04",
        },
        "libcuda": {
            "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
            "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
            "driver_api": 13000,
        },
        "gpu_compute_processes_before": [],
        "gpu_compute_processes_after": [],
        "cleanup_passed": True,
        "driver_or_module_changed": False,
        "gpu_reset_requested": False,
        "temporary_payload_remaining": False,
        "execution_scope": {
            "read_only": True,
            "experimental_module_loaded": False,
            "stock_driver_changed": False,
            "pci_binding_changed": False,
            "vm_management_issued": False,
            "gpu_reset_requested": False,
        },
        "ipc_artifacts": {
            "probe_source_sha256": getattr(tool, "IPC_PROBE_SOURCE_SHA256", "0" * 64)
        },
    }
    phase_by_mask = {}
    for mask in (9, 8, 1, 0):
        phase = ipc_phase_result(success_by_mask[mask])
        fabric_support = 1 if mask in (9, 8) else 0
        for endpoint in ("device", "importer_device"):
            phase[endpoint]["memory_sharing_support"]["fabric_handle"]["value"] = fabric_support
        phase_by_mask[mask] = phase
    records_by_mask = {
        mask: [
            {"transport": "direct", "kernel_mask": 9, "exposed_mask": mask,
             "caller_image": "libcuda.so.580.178.04", "caller_offset": "0x1a2b"},
            {"transport": "direct", "kernel_mask": 9, "exposed_mask": mask,
             "caller_image": "libcuda.so.580.178.04", "caller_offset": "0x2b3c"},
        ]
        for mask in (9, 8, 1, 0)
    }
    common["controls"] = [
        {"mode": mode, "probe_exit_code": 0, "cuda": ipc_phase_result()}
        for mode in ("stock", "preload_passthrough")
    ]
    common["runs"] = [
        {"requested_mask": mask, "ioctl_records": records_by_mask[mask],
         "cuda": phase_by_mask[mask], "probe_exit_code": 0}
        for mask in (9, 8, 1, 0)
    ]
    return common


class Pc3V100IpcSensitivityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def ipc_validator(self):
        validator = getattr(self.tool, "validate_guest_ipc_sensitivity", None)
        self.assertTrue(callable(validator), "V100 IPC report validator is missing")
        return validator

    def test_numeric_two_process_ipc_is_accepted_and_bit3_contrast_is_reported(self):
        result = self.ipc_validator()(ipc_guest_report(self.tool))
        self.assertTrue(result["complete"])
        self.assertEqual([run["requested_mask"] for run in result["runs"]], [9, 8, 1, 0])
        self.assertTrue(result["ipc_succeeded_for_all_masks"])
        self.assertTrue(result["mask_9_vs_1_outcomes_equal"])
        self.assertTrue(result["ipc_transfer_outcomes_equal"])
        self.assertFalse(result["device_capability_outcomes_equal"])
        self.assertFalse(result["mask_9_vs_1_fabric_capability_equal"])
        self.assertTrue(result["all_process_capability_pairs_equal"])
        self.assertEqual(result.get("api_outcomes_equal"), result["ipc_transfer_outcomes_equal"])
        self.assertFalse(result["caller_chain_capture_requested"])

    def test_cuda_ipc_rejection_is_a_valid_observation_when_cleanup_passes(self):
        report = ipc_guest_report(self.tool, {9: True, 8: True, 1: False, 0: False})
        result = self.ipc_validator()(report)
        self.assertTrue(result["complete"])
        self.assertFalse(result["ipc_succeeded_for_all_masks"])
        self.assertFalse(result["mask_9_vs_1_outcomes_equal"])
        self.assertEqual(result["runs"][2]["cuda"]["failure_operation"],
                         "child:cuIpcOpenMemHandle_v2")

    def test_ipc_success_requires_both_importer_read_and_exporter_writeback(self):
        report = ipc_guest_report(self.tool)
        report["runs"][0]["cuda"]["child_writeback_match"] = False
        with self.assertRaisesRegex(ValueError, "IPC numeric exchange"):
            self.ipc_validator()(report)

    def test_report_cannot_claim_numeric_success_without_a_successful_open(self):
        report = ipc_guest_report(self.tool)
        report["runs"][0]["cuda"]["open_succeeded"] = False
        with self.assertRaisesRegex(ValueError, "numeric exchange"):
            self.ipc_validator()(report)

    def test_vmm_and_shareable_handle_capabilities_are_required_for_followup_routing(self):
        report = ipc_guest_report(self.tool)
        del report["runs"][0]["cuda"]["device"]["memory_sharing_support"]
        result = self.ipc_validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["capability_queries_complete"])
        self.assertFalse(result["all_process_capability_pairs_equal"])

    def test_one_missing_capability_query_makes_report_incomplete(self):
        report = ipc_guest_report(self.tool)
        del report["runs"][0]["cuda"]["device"]["memory_sharing_support"]["fabric_handle"]
        result = self.ipc_validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["capability_queries_complete"])
        self.assertFalse(result["all_process_capability_pairs_equal"])

    def test_mask_dependent_fabric_capability_change_is_preserved(self):
        report = ipc_guest_report(self.tool)
        for endpoint in ("device", "importer_device"):
            report["runs"][2]["cuda"][endpoint]["memory_sharing_support"][
                "fabric_handle"]["value"] = 1
        result = self.ipc_validator()(report)
        self.assertTrue(result["complete"])
        self.assertTrue(result["ipc_succeeded_for_all_masks"])
        self.assertTrue(result["mask_9_vs_1_outcomes_equal"])
        self.assertTrue(result["mask_9_vs_1_fabric_capability_equal"])

    def test_capability_query_error_is_unknown_and_makes_report_incomplete(self):
        report = ipc_guest_report(self.tool)
        for endpoint in ("device", "importer_device"):
            support = report["runs"][0]["cuda"][endpoint]["memory_sharing_support"]
            support["fabric_handle"] = {"status": 999, "value": None}
        result = self.ipc_validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["capability_queries_complete"])
        self.assertNotEqual(result["runs"][0]["cuda"]["device"][
            "memory_sharing_support"]["fabric_handle"]["value"], 0)

    def test_exporter_importer_capability_mismatch_makes_report_incomplete(self):
        report = ipc_guest_report(self.tool)
        report["runs"][0]["cuda"]["importer_device"][
            "memory_sharing_support"]["fabric_handle"]["value"] = 0
        result = self.ipc_validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["all_process_capability_pairs_equal"])

    def test_exporter_importer_capability_records_must_be_independent(self):
        report = ipc_guest_report(self.tool)
        phase = report["runs"][0]["cuda"]
        phase["importer_device"]["memory_sharing_support"] = \
            phase["device"]["memory_sharing_support"]
        result = self.ipc_validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["all_process_capability_pairs_equal"])

    def test_ipc_failure_is_not_complete_when_cleanup_failed(self):
        report = ipc_guest_report(self.tool, {9: False, 8: True, 1: True, 0: True})
        report["runs"][0]["cuda"]["cleanup_passed"] = False
        with self.assertRaisesRegex(ValueError, "cleanup"):
            self.ipc_validator()(report)

    def test_guarded_guest_generator_accepts_pinned_ipc_probe(self):
        self.assertTrue(hasattr(self.tool, "IPC_PROBE_SOURCE_SHA256"),
                        "pinned V100 IPC probe artifact is missing")
        with tempfile.TemporaryDirectory(prefix="v100-ipc-guest-code-") as directory:
            shim = Path(directory) / "shim.so"
            shim.write_bytes(b"test interposer")
            code = self.tool.make_guest_code(shim, workload="ipc-memory-share")
        ast.parse(code)
        self.assertIn("nvidia-hybrid-v100-system-features-ipc-sensitivity-guest-v1", code)
        self.assertIn(self.tool.IPC_PROBE_SOURCE_SHA256, code)


if __name__ == "__main__":
    unittest.main()
