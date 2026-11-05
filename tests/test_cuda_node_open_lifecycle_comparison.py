#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU contracts for paired installed-driver CUDA node-lifecycle evidence."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/compare_cuda_node_open_lifecycle.py"


class ToolAvailability(unittest.TestCase):
    def test_comparator_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "paired CUDA node-lifecycle comparator is missing")


if TOOL_PATH.is_file():
    spec = importlib.util.spec_from_file_location("cuda_node_open_lifecycle_comparison", TOOL_PATH)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)

    class ComparisonContracts(unittest.TestCase):
        def make_capture(self, root: Path, role: str, *, sm: int, api: int,
                         incomplete: bool = False,
                         request_outcomes: bool = False):
            evidence = root / (role + ".json")
            trace = (
                '100 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n'
                '100 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc020462a, 0x7fff1234) = 0\n'
                '100 openat(AT_FDCWD, "/dev/nvidia0", O_RDWR) = 4</dev/nvidia0<char 195:0>>\n'
                '100 ioctl(4</dev/nvidia0<char 195:0>>, 0xc00446c9, 0x7fff1234) = 0\n'
            )
            if incomplete:
                trace += '100 openat(4</dev>, "nvidia-uvm", O_RDWR) = 5</dev/nvidia-uvm<char 508:0>>\n'
            if request_outcomes:
                trace += ('100 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc028465e, 0x7fff1234) = 0\n'
                          '100 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc028465e, 0x7fff5678) = -1 ENOTTY (Inappropriate ioctl for device)\n')
            trace += ('100 close(4</dev/nvidia0<char 195:0>>) = 0\n'
                      '100 close(3</dev/nvidiactl<char 195:255>>) = 0\n')
            raw = trace.encode()
            compressed = gzip.compress(raw, mtime=0)
            trace_path = evidence.with_suffix(evidence.suffix + ".strace.gz")
            trace_path.write_bytes(compressed)
            trace_path.chmod(0o600)
            summary = tool.TRACE.summarize_node_open_trace(raw)
            artifact = {
                "mode": "0600",
                "compressed_bytes": len(compressed),
                "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
                "raw_bytes": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "summary": summary,
            }
            device = {"name": "Tesla V100-SXM2-16GB" if sm == 70 else "NVIDIA GeForce RTX 5080",
                      "pci_bus_id": "0000:00:05.0" if sm == 70 else "0000:02:00.0",
                      "sm": sm, "compute_capability": f"{sm // 10}.{sm % 10}"}
            phase = {"schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
                     "phase": "enumerate", "driver_api": api, "selected_device": device,
                     "cleanup_passed": True, "cleanup_errors": [], "error": ""}
            probe_sha = "a" * 64
            if role == "rtx5080":
                report = {
                    "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
                    "phase": "enumerate", "exit_code": 0,
                    "local_artifacts": {
                        "probe": {"bytes": 10, "sha256": probe_sha},
                        "module": {"bytes": 20, "sha256": "b" * 64},
                    },
                    "remote": {"phase": "enumerate", "exit_code": 0,
                               "qualification": "rtx5080-cuda-phase-report-contract-valid",
                               "phase_report": phase,
                               "remote_work_cleanup": {
                                   "attempted": True, "passed": True, "removed": True,
                                   "retained_for_inspection": False,
                               },
                               "selected_nvidia_smi": {"driver": "595.99.02"},
                               "ioctl_trace_artifact": artifact,
                               "kernel_release": "7.0.0-test"},
                }
            else:
                report = {
                    "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
                    "phase": "enumerate", "qualification": "v100-cuda-phase-report-contract-valid",
                    "probe": {"bytes": 10, "sha256": probe_sha},
                    "module": {"bytes": 20, "sha256": "b" * 64},
                    "ioctl_trace_artifact": artifact,
                    "remote": {"phase": "enumerate", "phase_capture_requested": True,
                               "qualification": "v100-cuda-phase-report-contract-valid",
                               "probe_exit_code": 0, "probe": phase,
                               "guest_cleanup_passed": True,
                               "payload_file_cleanup_passed": True,
                               "guest": {"driver_version": "580.178.04",
                                         "kernel_release": "6.8.0-test"}},
                }
            evidence.write_text(json.dumps(report))
            evidence.chmod(0o600)
            return evidence, trace_path

        def test_cli_recomputes_and_compares_redacted_node_lifecycle(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, _ = self.make_capture(root, "rtx5080", sm=120, api=13020)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                output = root / "comparison.json"
                result = tool.main(["--rtx-report", str(rtx), "--v100-report", str(v100),
                                    "--report", str(output)])
                self.assertEqual(result, 0)
                report = json.loads(output.read_text())
                self.assertEqual(report["schema"], "nvidia-hybrid-cuda-node-open-lifecycle-comparison-v3")
                self.assertFalse(report["comparison"]["hybrid_runtime_validated"])
                self.assertFalse(report["comparison"]["raw_syscall_results_in_report"])
                self.assertEqual(report["devices"]["rtx5080"]["trace"]["ioctl_counts_by_node"],
                                 {"nvidia0": 1, "nvidiactl": 1})
                self.assertEqual(report["devices"]["v100"]["trace"]["open_count_by_node"],
                                 {"nvidia0": 1, "nvidiactl": 1})
                self.assertEqual(report["devices"]["rtx5080"]["trace"][
                    "ioctl_requests_by_node"], {
                        "nvidia0": {"0xc00446c9": 1},
                        "nvidiactl": {"0xc020462a": 1},
                    })
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertNotIn("events", report["devices"]["rtx5080"]["trace"])
                self.assertNotIn("events", report["devices"]["v100"]["trace"])
                self.assertFalse(report["comparison"]["raw_syscall_arguments_in_report"])

        def test_comparison_aggregates_ioctl_returns_without_arguments_or_events(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, _ = self.make_capture(root, "rtx5080", sm=120, api=13020,
                                           request_outcomes=True)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                output = root / "comparison.json"
                result = tool.main(["--rtx-report", str(rtx), "--v100-report", str(v100),
                                    "--report", str(output)])
                self.assertEqual(result, 0)
                report = json.loads(output.read_text())
                returns = report["devices"]["rtx5080"]["trace"][
                    "ioctl_return_counts_by_node"]["nvidiactl"]["0xc028465e"]
                self.assertEqual(returns, {"negative": 1, "nonnegative": 1})
                serialized = json.dumps(report)
                self.assertNotIn("0x7fff1234", serialized)
                self.assertNotIn("0x7fff5678", serialized)
                self.assertNotIn('"syscall_return":', serialized)
                self.assertNotIn("events", report["devices"]["rtx5080"]["trace"])

        def test_rejects_corrupt_trace_sidecar(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, rtx_sidecar = self.make_capture(root, "rtx5080", sm=120, api=13020)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                rtx_sidecar.write_bytes(b"corrupt")
                with self.assertRaisesRegex(ValueError, "compressed|gzip|hash"):
                    tool.compare(rtx, v100)

        def test_rejects_incomplete_relative_path_lifecycle(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, _ = self.make_capture(root, "rtx5080", sm=120, api=13020,
                                           incomplete=True)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                with self.assertRaisesRegex(ValueError, "incomplete|relative|node-open"):
                    tool.compare(rtx, v100)

        def test_rejects_non_private_reports(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, _ = self.make_capture(root, "rtx5080", sm=120, api=13020)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                rtx.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "private|mode"):
                    tool.compare(rtx, v100)

        def test_rejects_non_private_trace_sidecar(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, rtx_sidecar = self.make_capture(root, "rtx5080", sm=120, api=13020)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                rtx_sidecar.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "private|mode"):
                    tool.compare(rtx, v100)

        def test_rejects_different_cuda_fatbins(self):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                rtx, _ = self.make_capture(root, "rtx5080", sm=120, api=13020)
                v100, _ = self.make_capture(root, "v100", sm=70, api=13000)
                report = json.loads(v100.read_text())
                report["module"]["sha256"] = "c" * 64
                v100.write_text(json.dumps(report))
                v100.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "same CUDA fatbin"):
                    tool.compare(rtx, v100)
