# SPDX-License-Identifier: MIT
"""Tests for paired, fixed-field NV20_SUBDEVICE_0 comparisons."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "compare_nv2080_subdevice_alloc", ROOT / "tools/compare_nv2080_subdevice_alloc.py")
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def capture(subdevice_id: int = 0, outer_params_size: int = 0) -> dict:
    packet = {
        "layout": "NVOS64", "hClass": 0x2080, "paramsSize": outer_params_size, "flags": 0,
        "status": 0, "hRootPresent": True, "hObjectParentPresent": True,
        "hObjectNewPresent": True, "pAllocParmsPresent": True,
        "pRightsRequestedPresent": False,
        "subdeviceAlloc": {"classPayloadBytes": 4, "subDeviceId": subdevice_id},
    }
    return {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v20", "trace_complete": True,
        "child_exit_code": 0, "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
        "architecture": "x86_64", "pointer_bits": 64, "nested_pointers_read": True,
        "nested_pointer_scope": (
            "NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; handles omitted"),
        "payload_scope": "NV20_SUBDEVICE_0 fixed class parameters only; handles omitted",
        "subdevice_alloc_payload_snapshots_read": 2,
        "records": [{"tid": 71, "fd": 9, "fd_role": "control", "request": 0xC030462B,
                     "packet_size": 48, "operation": "subdevice_alloc", "entry": packet,
                     "exit": json.loads(json.dumps(packet)), "syscall_return": 0}],
        "errors": [],
    }


def phase(name: str, sm: int, pci: str) -> dict:
    return {"schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
            "phase": "context", "cleanup_passed": True, "cleanup_errors": [],
            "selected_device": {"name": name, "sm": sm, "pci_bus_id": pci}}


def reports(v100_capture: dict | None = None, rtx_capture: dict | None = None) -> tuple[dict, dict]:
    observer_artifact = {"sha256": "a" * 64, "bytes": 220480}
    v100_name = "Tesla V100-SXM2-16GB"
    v100 = {
        "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
        "qualification": "v100-cuda-phase-report-contract-valid", "target": "pc3@pc3",
        "payload_cleanup_passed": True, "ioctl_observer": observer_artifact,
        "remote": {
            "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
            "qualification": "v100-cuda-phase-report-contract-valid", "phase": "context",
            "phase_capture_requested": True, "subdevice_alloc_capture_requested": True,
            "subdevice_alloc_records_seen": True, "subdevice_alloc_payload_snapshots_read": 2,
            "probe_exit_code": 0, "observer_exit_code": 0,
            "guest_cleanup_passed": True, "payload_file_cleanup_passed": True,
            "guest": {"name": v100_name, "driver_version": "580.178.04",
                      "kernel_release": "6.8.0-147-generic", "pci": "0000:00:05.0",
                      "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e"},
            "probe": phase(v100_name, 70, "0000:00:05.0"),
            "ioctl_observation": v100_capture or capture(),
        },
    }
    rtx_name = "NVIDIA GeForce RTX 5080"
    rtx = {
        "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
        "target": "pc3@pc3", "host_key_alias": "pc3", "exit_code": 0, "ssh_exit_code": 0,
        "local_artifacts": {"observer": observer_artifact},
        "remote": {
            "schema": "nvidia-hybrid-remote-selected-gpu-v1",
            "qualification": "rtx5080-cuda-phase-report-contract-valid", "exit_code": 0,
            "phase": "context", "phase_capture_requested": True,
            "subdevice_alloc_capture_requested": True, "subdevice_alloc_records_seen": True,
            "subdevice_alloc_payload_snapshots_read": 2,
            "kernel_release": "7.0.0-38-generic",
            "selected_nvidia_smi": {"name": rtx_name, "driver": "595.99.02",
                                    "pci": "00000000:02:00.0",
                                    "uuid": "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"},
            "phase_report": phase(rtx_name, 120, "0000:02:00.0"),
            "hardware_acceptance": {"ioctl_observation": {"report": rtx_capture or capture()}},
        },
    }
    return v100, rtx


class CompareNV2080SubdeviceAllocTests(unittest.TestCase):
    def test_paired_captures_compare_only_fixed_class_fields(self):
        v100, rtx = reports()
        result = TOOL.compare_reports(v100, rtx)
        self.assertEqual(result["schema"], "nvidia-hybrid-nv2080-subdevice-allocation-comparison-v2")
        self.assertTrue(result["allocation_fields_match"])
        self.assertTrue(result["observer_binary_match"])
        self.assertEqual(result["references"]["v100"]["observation"]["outer_params_size"], 0)
        self.assertFalse(result["same_kernel_hybrid_validated"])
        self.assertEqual(result["references"]["v100"]["driver"], "580.178.04")
        self.assertEqual(result["references"]["rtx5080"]["driver"], "595.99.02")

    def test_differences_are_reported_without_becoming_a_compatibility_claim(self):
        v100, rtx = reports(rtx_capture=capture(1))
        result = TOOL.compare_reports(v100, rtx)
        self.assertFalse(result["allocation_fields_match"])
        self.assertEqual(result["allocation_field_differences"], [
            {"field": "subDeviceId", "v100": 0, "rtx5080": 1}])
        self.assertFalse(result["same_kernel_hybrid_validated"])

    def test_outer_size_difference_is_reported_without_claiming_compatibility(self):
        v100, rtx = reports(rtx_capture=capture(outer_params_size=4))
        result = TOOL.compare_reports(v100, rtx)
        self.assertFalse(result["allocation_fields_match"])
        self.assertEqual(result["allocation_field_differences"], [
            {"field": "outerParamsSize", "v100": 0, "rtx5080": 4}])
        self.assertFalse(result["same_kernel_hybrid_validated"])

    def test_unredacted_failed_or_unstable_observations_are_rejected(self):
        v100, rtx = reports()
        bad = capture()
        bad["records"][0]["entry"]["hRoot"] = 0x1234
        v100["remote"]["ioctl_observation"] = bad
        with self.assertRaises(ValueError):
            TOOL.compare_reports(v100, rtx)

        v100, rtx = reports()
        v100["remote"]["ioctl_observation"]["records"][0]["exit"]["status"] = 0x56
        with self.assertRaises(ValueError):
            TOOL.compare_reports(v100, rtx)

        v100, rtx = reports()
        rtx["remote"]["hardware_acceptance"]["ioctl_observation"]["report"][
            "records"][0]["exit"]["subdeviceAlloc"]["subDeviceId"] = 1
        with self.assertRaisesRegex(ValueError, "changed"):
            TOOL.compare_reports(v100, rtx)

    def test_wrong_gpu_identity_is_rejected(self):
        v100, rtx = reports()
        v100["remote"]["guest"]["pci"] = "0000:00:06.0"
        with self.assertRaisesRegex(ValueError, "does not match"):
            TOOL.compare_reports(v100, rtx)


if __name__ == "__main__":
    unittest.main(verbosity=2)
