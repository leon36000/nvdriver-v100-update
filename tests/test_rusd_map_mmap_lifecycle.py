# SPDX-License-Identifier: MIT
"""Behavioral tests for the privacy-preserving RUSD map/mmap summarizer."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/summarize_rusd_map_mmap_lifecycle.py"


def fixture_report() -> dict:
    selected_identity = "opaque-selected-file-identity"
    unrelated_identity = "opaque-unrelated-file-identity"
    control_identity = "opaque-control-file-identity"
    rusd = {
        "classPayloadBytes": 8,
        "polledDataMask": 0,
    }
    records = [
                {
                    "operation": "rusd_alloc",
                    "fd_file_id": control_identity,
                    "fd_role": "control",
                    "syscall_return": 0,
                    "entry": {"hClass": 0xDE, "rusd": rusd},
                    "exit": {"status": 0, "hClass": 0xDE, "rusd": rusd},
                },
                {
                    "operation": "map_memory",
                    "fd_file_id": control_identity,
                    "fd_role": "control",
                    "syscall_return": 0,
                    "entry": {
                        "memoryObjectClass": {"classId": 0xDE},
                        "backendFileId": selected_identity,
                        "backendFdRole": "gpu",
                        "status": 0,
                    },
                    "exit": {
                        "memoryObjectClass": {"classId": 0xDE},
                        "backendFileId": selected_identity,
                        "backendFdRole": "gpu",
                        "status": 0,
                    },
                },
                {
                    "operation": "map_memory",
                    "fd_file_id": control_identity,
                    "fd_role": "control",
                    "syscall_return": 0,
                    "entry": {
                        "memoryObjectClass": {"classId": 0x3E},
                        "backendFileId": unrelated_identity,
                        "backendFdRole": "gpu",
                        "status": 0,
                    },
                    "exit": {
                        "memoryObjectClass": {"classId": 0x3E},
                        "backendFileId": unrelated_identity,
                        "backendFdRole": "gpu",
                        "status": 0,
                    },
                },
                {
                    "operation": "mmap",
                    "fd_file_id": selected_identity,
                    "fd_role": "gpu",
                    "mmap_succeeded": True,
                },
                {
                    "operation": "mmap",
                    "fd_file_id": unrelated_identity,
                    "fd_role": "gpu",
                    "mmap_succeeded": True,
                },
                {
                    "operation": "mmap",
                    "fd_file_id": selected_identity,
                    "fd_role": "gpu",
                    "mmap_succeeded": False,
                },
    ]
    observer = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v22",
        "trace_complete": True,
        "child_exit_code": 77,
        "errors": [],
        "fd_identity_capture_complete": True,
        "rusd_payload_snapshots_read": 2,
        "records": records,
    }
    probe = {
        "schema": "nvidia-hybrid-probe-v2",
        "status": "incomplete",
        "required_sm": [70, 120],
        "missing_sm": [70],
        "hybrid_validated": False,
        "devices": [{
            "sm": 120,
            "tested": True,
            "architecture_kernel_passed": True,
            "synchronous_passed": True,
            "asynchronous_passed": True,
            "cleanup_passed": True,
            "cleanup_errors": [],
        }],
    }
    hardware_acceptance = {
        "schema": "nvidia-hybrid-hardware-acceptance-v2",
        "qualification": "incomplete-hardware-missing",
        "exit_code": 77,
        "validation_errors": [],
        "rusd_alloc_capture_requested": True,
        "map_memory_capture_requested": True,
        "probe": probe,
        "ioctl_observation": {"report": observer},
    }
    remote = {
        "schema": "nvidia-hybrid-remote-selected-gpu-v1",
        "exit_code": 77,
        "qualification": "rtx5080-report-contract-valid-hybrid-incomplete",
        "rusd_alloc_capture_requested": True,
        "rusd_alloc_records_seen": True,
        "map_memory_capture_requested": True,
        "map_memory_records_seen": True,
        "hardware_acceptance": hardware_acceptance,
    }
    return {
        "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
        "target": "pc3@pc3",
        "host_key_alias": "pc3",
        "exit_code": 77,
        "ssh_exit_code": 77,
        "ssh_stderr": "",
        "ssh_stdout": json.dumps(remote),
        "remote": remote,
    }


def rtx5080_expected_sm70_absence_report() -> dict:
    return fixture_report()


def load_tool():
    if not TOOL_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        "summarize_rusd_map_mmap_lifecycle", TOOL_PATH)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RUSDMapMmapLifecycleTests(unittest.TestCase):
    def test_correlates_only_successful_class_resolved_map_and_mmap(self):
        tool = load_tool()
        self.assertIsNotNone(tool, "the lifecycle summarizer must be implemented")
        summary = tool.summarize_report(fixture_report(), "a" * 64)
        self.assertEqual(summary["counts"]["rusd_alloc_records"], 1)
        self.assertEqual(summary["counts"]["successful_rusd_alloc_records"], 1)
        self.assertEqual(summary["counts"]["successful_map_memory_records"], 2)
        self.assertEqual(summary["counts"]["rusd_class_map_records"], 1)
        self.assertEqual(summary["counts"]["successful_rusd_class_map_records"], 1)
        self.assertEqual(summary["counts"]["successful_mmap_records"], 2)
        self.assertEqual(summary["counts"]["correlated_rusd_map_mmap_pairs"], 1)
        self.assertEqual(summary["counts"]["correlated_pairs_with_matching_role"], 1)
        self.assertEqual(summary["qualification"], "stock-driver-rusd-map-mmap-correlated")
        self.assertFalse(summary["same_kernel_hybrid_validated"])
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn("opaque-selected-file-identity", serialized)
        self.assertNotIn("opaque-control-file-identity", serialized)
        self.assertNotIn("fd_file_id", serialized)

    def test_ambiguous_file_reuse_does_not_qualify_as_one_lifecycle_pair(self):
        tool = load_tool()
        self.assertIsNotNone(tool, "the lifecycle summarizer must be implemented")
        report = fixture_report()
        records = report["remote"]["hardware_acceptance"][
            "ioctl_observation"]["report"]["records"]
        records.append(copy.deepcopy(records[3]))
        report["ssh_stdout"] = json.dumps(report["remote"])
        summary = tool.summarize_report(report, "b" * 64)
        self.assertEqual(summary["counts"]["correlated_rusd_map_mmap_pairs"], 2)
        self.assertEqual(summary["qualification"], "stock-driver-observation-incomplete")

    def test_rejects_incomplete_transport_or_unrequested_observer_scope(self):
        tool = load_tool()
        self.assertIsNotNone(tool, "the lifecycle summarizer must be implemented")
        report = fixture_report()
        report["ssh_exit_code"] = 1
        with self.assertRaisesRegex(ValueError, "transport"):
            tool.summarize_report(report, "c" * 64)
        report = fixture_report()
        report["remote"]["rusd_alloc_capture_requested"] = False
        with self.assertRaisesRegex(ValueError, "capture scope"):
            tool.summarize_report(report, "c" * 64)

    def test_accepts_only_the_recorded_exit_77_for_missing_sm70(self):
        tool = load_tool()
        self.assertIsNotNone(tool, "the lifecycle summarizer must be implemented")
        summary = tool.summarize_report(
            rtx5080_expected_sm70_absence_report(), "d" * 64)
        self.assertEqual(summary["qualification"],
                         "stock-driver-rusd-map-mmap-correlated")
        self.assertEqual(summary["probe_limit"]["missing_sm"], [70])
        self.assertEqual(summary["probe_limit"]["tested_sm"], [120])
        self.assertFalse(summary["same_kernel_hybrid_validated"])

        bad = rtx5080_expected_sm70_absence_report()
        bad["remote"]["hardware_acceptance"]["probe"]["missing_sm"] = [70, 80]
        bad["ssh_stdout"] = json.dumps(bad["remote"])
        with self.assertRaisesRegex(ValueError, "exit 77"):
            tool.summarize_report(bad, "e" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
