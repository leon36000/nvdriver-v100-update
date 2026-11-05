# SPDX-License-Identifier: MIT
"""Tests for paired, redacted NV2081_BINAPI allocation comparisons."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPARE_PATH = ROOT / "tools/compare_nv2081_binapi_alloc.py"
SPEC = importlib.util.spec_from_file_location("hybrid_compare_nv2081_binapi_alloc", COMPARE_PATH)
COMPARE = None
if COMPARE_PATH.is_file() and SPEC is not None and SPEC.loader is not None:
    COMPARE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(COMPARE)


OBSERVER_SHA = "a" * 64
CAPTURE_SHA = "b" * 64


def observation(reserved_zero: bool = True, optional_absent: bool = False,
                outer_params_size: int = 0) -> dict:
    payload = None if optional_absent else {
        "classPayloadBytes": 4, "reservedZero": reserved_zero,
    }
    packet = {
        "layout": "NVOS64", "hClass": 0x2081, "paramsSize": outer_params_size, "flags": 0,
        "status": 0, "hRootPresent": True, "hObjectParentPresent": True,
        "hObjectNewPresent": True, "pAllocParmsPresent": not optional_absent,
        "pRightsRequestedPresent": False, "binapiAlloc": payload,
    }
    return {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v21", "trace_complete": True,
        "child_exit_code": 0, "control_path": "/dev/nvidiactl",
        "gpu_path": "/dev/nvidia0", "architecture": "x86_64", "pointer_bits": 64,
        "nested_pointers_read": not optional_absent,
        "nested_pointer_scope": (
            "NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; handles omitted"),
        "payload_scope": "NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted",
        "binapi_alloc_payload_snapshots_read": 0 if optional_absent else 2,
        "records": [{
            "tid": 123, "fd": 7, "fd_role": "control", "request": 0xC030462B,
            "packet_size": 48, "operation": "binapi_alloc", "entry": packet,
            "exit": dict(packet), "syscall_return": 0,
        }],
        "errors": [],
    }


def phase(name: str, sm: int, pci: str) -> dict:
    return {
        "schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
        "phase": "context", "cleanup_passed": True, "cleanup_errors": [],
        "selected_device": {
            "name": name, "sm": sm, "pci_bus_id": pci,
        },
    }


def reports(v100_observer: dict | None = None, rtx_observer: dict | None = None) -> tuple[dict, dict]:
    v100_observer = v100_observer or observation()
    rtx_observer = rtx_observer or observation()
    artifact = {"bytes": 1000, "sha256": OBSERVER_SHA}
    v100 = {
        "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
        "target": "pc3@pc3", "phase": "context", "exit_code": 0,
        "qualification": "v100-cuda-phase-report-contract-valid", "payload_cleanup_passed": True,
        "ioctl_observer": dict(artifact),
        "remote": {
            "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
            "qualification": "v100-cuda-phase-report-contract-valid", "phase": "context",
            "phase_capture_requested": True, "binapi_alloc_capture_requested": True,
            "binapi_alloc_records_seen": True,
            "binapi_alloc_payload_snapshots_read": v100_observer[
                "binapi_alloc_payload_snapshots_read"],
            "probe_exit_code": 0, "observer_exit_code": 0,
            "guest_cleanup_passed": True, "payload_file_cleanup_passed": True,
            "guest": {
                "name": "Tesla V100-SXM2-16GB", "driver_version": "580.178.04",
                "kernel_release": "6.8.0-147-generic",
            },
            "probe": phase("Tesla V100-SXM2-16GB", 70, "0000:00:05.0"),
            "ioctl_observation": v100_observer,
        },
    }
    rtx = {
        "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
        "target": "pc3@pc3", "host_key_alias": "pc3", "phase": "context",
        "exit_code": 0, "ssh_exit_code": 0,
        "local_artifacts": {"observer": dict(artifact)},
        "remote": {
            "schema": "nvidia-hybrid-remote-selected-gpu-v1",
            "qualification": "rtx5080-cuda-phase-report-contract-valid", "phase": "context",
            "kernel_release": "7.0.0-38-generic",
            "exit_code": 0, "phase_capture_requested": True,
            "binapi_alloc_capture_requested": True, "binapi_alloc_records_seen": True,
            "binapi_alloc_payload_snapshots_read": rtx_observer[
                "binapi_alloc_payload_snapshots_read"],
            "selected_nvidia_smi": {
                "name": "NVIDIA GeForce RTX 5080", "driver": "595.99.02",
                "pci": "00000000:02:00.0", "uuid": "GPU-01234567-89ab-cdef-0123-456789abcdef",
            },
            "hardware_acceptance": {
                "exit_code": 0, "phase": "context",
                "qualification": "phase-report-contract-pass",
                "probe": phase("NVIDIA GeForce RTX 5080", 120, "0000:02:00.0"),
                "ioctl_observation": {
                    "artifact": {"bytes": 1284, "sha256": CAPTURE_SHA},
                    "report": rtx_observer,
                },
            },
        },
    }
    return v100, rtx


class NV2081BinapiComparisonTests(unittest.TestCase):
    def test_comparator_api_is_present(self):
        self.assertIsNotNone(COMPARE, "paired NV2081 allocation comparator is not implemented")

    @unittest.skipUnless(COMPARE, "comparator implementation is required")
    def test_compares_only_fixed_redacted_payload_and_preserves_limits(self):
        v100, rtx = reports()
        result = COMPARE.compare_reports(v100, rtx)
        self.assertEqual(result["schema"], "nvidia-hybrid-nv2081-binapi-allocation-comparison-v2")
        self.assertTrue(result["observer_binary_match"])
        self.assertEqual(result["references"]["rtx5080"]["capture_report_sha256"], CAPTURE_SHA)
        self.assertTrue(result["allocation_fields_match"])
        self.assertFalse(result["same_kernel_hybrid_validated"])
        self.assertEqual(result["references"]["v100"]["observation"]["typed_payload"], {
            "classPayloadBytes": 4, "reservedZero": True,
        })
        self.assertEqual(result["references"]["v100"]["observation"]["outer_params_size"], 0)

    @unittest.skipUnless(COMPARE, "comparator implementation is required")
    def test_compares_outer_params_size_even_when_class_payload_is_present(self):
        v100, rtx = reports(observation(outer_params_size=0),
                            observation(outer_params_size=4))
        result = COMPARE.compare_reports(v100, rtx)
        self.assertFalse(result["allocation_fields_match"])
        self.assertEqual(result["allocation_field_differences"], [{
            "field": "outerParamsSize", "v100": 0, "rtx5080": 4,
        }])
        self.assertFalse(result["same_kernel_hybrid_validated"])

    @unittest.skipUnless(COMPARE, "comparator implementation is required")
    def test_preserves_optional_parameter_absence_without_inventing_payload(self):
        v100, rtx = reports(observation(optional_absent=True), observation(optional_absent=True))
        result = COMPARE.compare_reports(v100, rtx)
        self.assertTrue(result["allocation_fields_match"])
        self.assertIsNone(result["references"]["v100"]["observation"]["typed_payload"])

    @unittest.skipUnless(COMPARE, "comparator implementation is required")
    def test_reports_a_real_typed_difference_without_claiming_compatibility(self):
        v100, rtx = reports(observation(), observation(reserved_zero=False))
        result = COMPARE.compare_reports(v100, rtx)
        self.assertFalse(result["allocation_fields_match"])
        self.assertEqual(result["allocation_field_differences"], [{
            "field": "reservedZero", "v100": True, "rtx5080": False,
        }])
        self.assertFalse(result["same_kernel_hybrid_validated"])

    @unittest.skipUnless(COMPARE, "comparator implementation is required")
    def test_rejects_failed_or_mismatched_capture_provenance(self):
        for mutate, message in (
                (lambda v, r: v.update(exit_code=1), "qualified"),
                (lambda v, r: v["remote"].update(guest_cleanup_passed=False), "cleanup"),
                (lambda v, r: r["remote"]["hardware_acceptance"]["probe"].update(
                    selected_device={"name": "Tesla V100-SXM2-16GB", "sm": 70,
                                     "pci_bus_id": "0000:00:05.0"}), "physical GPU"),
                (lambda v, r: r["remote"]["hardware_acceptance"]["ioctl_observation"][
                    "artifact"].update(sha256="invalid"), "capture report artifact")):
            v100, rtx = reports()
            mutate(v100, rtx)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                COMPARE.compare_reports(v100, rtx)

    @unittest.skipUnless(COMPARE, "comparator implementation is required")
    def test_cli_writes_private_evidence_and_refuses_overwrite(self):
        v100, rtx = reports()
        with tempfile.TemporaryDirectory(prefix="nv2081-binapi-compare-") as directory:
            root = Path(directory)
            v100_path, rtx_path = root / "v100.json", root / "rtx.json"
            output = root / "comparison.json"
            v100_path.write_text(json.dumps(v100), encoding="utf-8")
            rtx_path.write_text(json.dumps(rtx), encoding="utf-8")
            result = COMPARE.run(v100_path, rtx_path, output)
            self.assertTrue(result["allocation_fields_match"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text())["schema"], result["schema"])
            with self.assertRaisesRegex(ValueError, "overwrite"):
                COMPARE.run(v100_path, rtx_path, output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
