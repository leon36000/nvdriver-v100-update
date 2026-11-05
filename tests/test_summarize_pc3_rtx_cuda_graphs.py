# SPDX-License-Identifier: MIT
"""Mutation tests for the redacted PC3 full-acceptance CUDA Graph receipt."""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import summarize_pc3_rtx_cuda_graphs as summarizer
from tools.summarize_pc3_rtx_cuda_graphs import (
    PINNED_ARTIFACTS,
    SummaryError,
    summarize_report,
    write_new_json,
)

TEST_PINS = {
    name: hashlib.sha256(f"fixture {name}".encode()).hexdigest()
    for name in PINNED_ARTIFACTS
}


def make_capture(root: Path) -> Path:
    artifact_dir = root / "artifacts"
    logs_dir = root / "evidence" / "logs"
    artifact_dir.mkdir(parents=True)
    logs_dir.mkdir(parents=True)
    local = {}
    remote_before = {}
    remote_after = {}
    for name, digest in PINNED_ARTIFACTS.items():
        content = f"fixture {name}".encode()
        path = artifact_dir / name.replace("/", "_")
        path.write_bytes(content)
        row = {"bytes": len(content), "path": str(path),
               "sha256": hashlib.sha256(content).hexdigest()}
        local[name] = row
        remote_before[name] = {**row, "path": f"/tmp/probe/{name}"}
        remote_after[name] = {**remote_before[name]}
    trust = {
        "status": "trusted-pinned-build",
        "provenance": "pinned-probe-and-fatbin-sha256",
        "probe_sha256": PINNED_ARTIFACTS["probe"],
        "module_sha256": PINNED_ARTIFACTS["module"],
    }
    device = {
        "name": "NVIDIA GeForce RTX 5080", "pci_bus_id": "0000:02:00.0",
        "compute_capability": "12.0", "sm": 120, "tested": True, "targeted": True,
        "synchronous_passed": True, "asynchronous_passed": True,
        "synchronous_sizes": [1, 31, 256, 4096, 65537],
        "asynchronous_sizes": [1, 31, 256, 4096, 65537],
        "architecture_kernel_passed": True, "cuda_graphs_passed": True,
        "cuda_graph_launches": 2, "cleanup_passed": True,
        "cleanup_errors": [], "error": "",
    }
    probe = {
        "schema": "nvidia-hybrid-probe-v2", "status": "incomplete",
        "hybrid_validated": False, "required_sm": [70, 120], "missing_sm": [70],
        "cuda_graphs_requested": True, "cuda_graph_api": "cuGraphInstantiateWithFlags",
        "required_set_passed": False,
        "performance_benchmark_requested": False, "peer_transfer_requested": False,
        "devices": [device], "driver_api": 13020,
    }
    acceptance = {
        "exit_code": 77, "qualification": "incomplete-hardware-missing",
        "validation_errors": [], "probe": probe,
        "probe_build_trust": {"status": "trusted-pinned-build",
                               "before_run": trust, "after_run": copy.deepcopy(trust)},
    }
    remote = {
        "exit_code": 77, "report_contract_validated": True,
        "qualification": "rtx5080-report-contract-valid-hybrid-incomplete",
        "cuda_execution_validated": False, "cuda_graphs_requested": True,
        "cuda_graphs_report_contract_passed": True, "cuda_graphs_validated": False,
        "hardware_acceptance": acceptance,
        "device_selection": {"pci": "0000:02:00.0", "uuid": "GPU-test"},
        "selected_nvidia_smi": {"name": "NVIDIA GeForce RTX 5080",
                                "pci": "00000000:02:00.0", "driver": "595.99.02",
                                "uuid": "GPU-test"},
        "system_libcuda_before": {"sha256": "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d"},
        "system_libcuda_after": {"sha256": "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d"},
        "remote_work_cleanup": {"attempted": True, "passed": True,
                                "removed": True, "retained_for_inspection": False},
        "artifacts_before": remote_before, "artifacts_after": remote_after,
        "kernel_release": "7.0.0-test",
    }
    capture = {
        "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
        "target": "pc3@pc3", "host_key_alias": "pc3",
        "observed_at_utc": "2026-11-03T00:00:00Z", "phase": None,
        "phase_capture_requested": False, "cuda_graphs_requested": True,
        "expected_libcuda_sha256": "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d",
        "exit_code": 77, "ssh_exit_code": 77,
        "report_contract_validated": True,
        "qualification": "rtx5080-report-contract-valid-hybrid-incomplete",
        "cuda_execution_validated": False, "local_artifacts": local,
        "local_artifacts_after": copy.deepcopy(local), "remote": remote,
    }
    raw = logs_dir / "capture.json"
    raw.write_text(json.dumps(capture), encoding="utf-8")
    raw.chmod(0o600)
    return raw


class RTXStockCudaGraphsSummaryTests(unittest.TestCase):
    def test_summarizes_graph_report_without_promoting_execution_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(summarizer.PINNED_ARTIFACTS, TEST_PINS):
                raw = make_capture(root)
                result = summarize_report(raw, root)
        self.assertEqual(result["cuda_graph_replays_reported_passed"], 2)
        self.assertEqual(result["missing_sm"], [70])
        self.assertFalse(result["hybrid_validated"])
        self.assertFalse(result["independent_hardware_attestation"])
        self.assertFalse(result["cuda_execution_validated"])
        self.assertNotIn("target", result)
        self.assertNotIn("host", result)

    def test_rejects_graph_launch_count_mismatch(self):
        self._mutate_and_reject(lambda capture: capture["remote"]["hardware_acceptance"]
                                ["probe"]["devices"][0].__setitem__("cuda_graph_launches", 1))

    def test_rejects_report_that_omits_sm70_from_missing_set(self):
        self._mutate_and_reject(lambda capture: capture["remote"]["hardware_acceptance"]
                                ["probe"].__setitem__("missing_sm", []))

    def test_rejects_false_numeric_or_cleanup_result(self):
        self._mutate_and_reject(lambda capture: capture["remote"]["hardware_acceptance"]
                                ["probe"]["devices"][0].__setitem__("asynchronous_passed", False))
        self._mutate_and_reject(lambda capture: capture["remote"]["hardware_acceptance"]
                                ["probe"]["devices"][0].__setitem__("cleanup_passed", False))

    def test_rejects_changed_pinned_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(summarizer.PINNED_ARTIFACTS, TEST_PINS):
                raw = make_capture(root)
                artifact = root / "artifacts" / "module"
                artifact.write_text("tampered", encoding="utf-8")
                with self.assertRaises(SummaryError):
                    summarize_report(raw, root)

    def test_rejects_raw_report_readable_by_group_or_other(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(summarizer.PINNED_ARTIFACTS, TEST_PINS):
                raw = make_capture(root)
                raw.chmod(0o644)
                with self.assertRaisesRegex(SummaryError, "permissions"):
                    summarize_report(raw, root)

    def test_atomic_receipt_writer_refuses_replace_and_outside_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "evidence").mkdir()
            output = root / "evidence" / "receipt.json"
            write_new_json(output, {"safe": True}, root)
            with self.assertRaises(SummaryError):
                write_new_json(output, {"safe": False}, root)
            with self.assertRaises(SummaryError):
                write_new_json(root / "elsewhere.json", {"safe": False}, root)

    def _mutate_and_reject(self, mutate):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(summarizer.PINNED_ARTIFACTS, TEST_PINS):
                raw = make_capture(root)
                capture = json.loads(raw.read_text())
                mutate(capture)
                raw.write_text(json.dumps(capture), encoding="utf-8")
                with self.assertRaises(SummaryError):
                    summarize_report(raw, root)


if __name__ == "__main__":
    unittest.main()
