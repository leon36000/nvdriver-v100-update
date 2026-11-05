# SPDX-License-Identifier: MIT
"""Integrity and comparison contracts for installed-driver ioctl traces."""
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import compare_ioctl_trace_evidence as compare
from tools import summarize_rm_ioctl_trace as trace_summary


class InstalledIoctlTraceComparisonTests(unittest.TestCase):
    def make_input(self, root, name, raw):
        report_path = root / f"{name}.json"
        sidecar = report_path.with_suffix(report_path.suffix + ".strace.gz")
        compressed = gzip.compress(raw, mtime=0)
        sidecar.write_bytes(compressed)
        sidecar.chmod(0o600)
        summary = trace_summary.summarize(raw)
        artifact = {
            "path": str(sidecar.resolve()), "compressed_bytes": len(compressed),
            "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "mode": "0600", "summary": summary,
        }
        trace = {"strace_version": "strace -- version fixture",
                 "trace": {"trace_complete": True, "size_limit_exceeded": False,
                           "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                           "summary": summary}}
        if name == "rtx":
            report = {
                "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
                "remote": {
                    "schema": "nvidia-hybrid-remote-selected-gpu-v1",
                    "qualification": "rtx5080-report-contract-valid-hybrid-incomplete",
                    "selected_nvidia_smi": {"name": "NVIDIA GeForce RTX 5080",
                        "uuid": "GPU-12345678-1234-1234-1234-123456789abc",
                        "pci": "00000000:02:00.0", "driver": "595.99.02"},
                    "kernel_release": "7.0.0-test",
                    "hardware_acceptance": {"qualification": "incomplete-hardware-missing",
                        "probe": {"driver_api": 13020, "missing_sm": [70],
                                  "hybrid_validated": False}, "ioctl_trace": trace},
                    "ioctl_trace_artifact": artifact,
                },
            }
        else:
            report = {
                "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
                "qualification": "v100-reference-report-contract-valid",
                "ioctl_trace_artifact": artifact,
                "remote": {
                    "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
                    "qualification": "v100-reference-report-contract-valid",
                    "guest": {"name": "Tesla V100-SXM2-16GB",
                        "uuid": "GPU-abcdefab-1234-1234-1234-123456789abc",
                        "pci": "0000:00:05.0", "driver_version": "580.178.04",
                        "kernel_release": "6.8.0-test"},
                    "probe": {"driver_api": 13000, "hybrid_validated": False},
                    "ioctl_trace": trace,
                },
            }
        report_path.write_text(json.dumps(report))
        return report_path, sidecar

    def test_compares_verified_metadata_and_keeps_pointer_values_out(self):
        rtx_raw = (
            b"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0xfeedface) = 0\n"
            b"7 ioctl(9</dev/nvidia-uvm<char 511:0>>, 0x30000001, 0xcafebabe) = 0\n")
        v100_raw = (
            b"3 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x1111) = 0\n"
            b"3 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x2222) = 0\n"
            b"3 ioctl(9</dev/nvidia-uvm<char 511:0>>, 0x30000001, 0x3333) = 0\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rtx, _ = self.make_input(root, "rtx", rtx_raw)
            v100, _ = self.make_input(root, "v100", v100_raw)
            result = compare.build_comparison(rtx, v100)
            self.assertEqual(result["schema"], "nvidia-hybrid-installed-driver-ioctl-comparison-v1")
            self.assertEqual(result["comparison"]["sequence"]["common_prefix_calls"], 1)
            self.assertEqual(result["comparison"]["request_count_deltas"], [{
                "node": "/dev/nvidiactl", "request": "0xc030462b",
                "rtx_count": 1, "v100_count": 2, "v100_minus_rtx": 1,
            }])
            self.assertEqual(result["inputs"]["rtx5080"]["call_count"], 2)
            self.assertEqual(result["inputs"]["v100"]["call_count"], 3)
            encoded = json.dumps(result)
            for pointer in ("0xfeedface", "0xcafebabe", "0xbad0", "0x1111"):
                self.assertNotIn(pointer, encoded)
            self.assertIn("metadata only", result["scope"])

    def test_rejects_trace_sidecar_or_summary_tampering(self):
        raw = b"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0xfeed) = 0\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rtx, sidecar = self.make_input(root, "rtx", raw)
            v100, _ = self.make_input(root, "v100", raw)
            sidecar.write_bytes(sidecar.read_bytes() + b"tamper")
            with self.assertRaises(ValueError):
                compare.build_comparison(rtx, v100)
            sidecar.write_bytes(gzip.compress(raw, mtime=0))
            report = json.loads(rtx.read_text())
            report["remote"]["hardware_acceptance"]["ioctl_trace"]["trace"]["summary"]["parsed_calls"] = 7
            rtx.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                compare.build_comparison(rtx, v100)

    def test_register_fd_alignment_is_pointer_free_and_has_one_based_context(self):
        rtx_raw = (
            b"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc020462a, 0xfeedface) = 0\n"
            b"7 ioctl(9</dev/nvidia0<char 195:0>>, 0xc00446c9, 0xcafebabe) = 0\n"
            b"7 ioctl(9</dev/nvidia0<char 195:0>>, 0xc01046ce, 0xdeadbeef) = 0\n")
        v100_raw = (
            b"3 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc020462a, 0x1111) = 0\n"
            b"3 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc020462a, 0x2222) = 0\n"
            b"3 ioctl(9</dev/nvidia0<char 195:0>>, 0xc00446c9, 0x3333) = 0\n"
            b"3 ioctl(9</dev/nvidia0<char 195:0>>, 0xc01046ce, 0x4444) = 0\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rtx, _ = self.make_input(root, "rtx", rtx_raw)
            v100, _ = self.make_input(root, "v100", v100_raw)
            result = compare.build_comparison(rtx, v100)
        sequence = result["comparison"]["sequence"]
        self.assertEqual(sequence["first_divergence"]["zero_based_index"], 1)
        self.assertEqual(sequence["first_divergence_context"]["radius"], 2)
        self.assertEqual(sequence["first_divergence_context"]["rtx5080"][0]["call_index"], 1)
        occurrences = sequence["register_fd_occurrences"]
        self.assertFalse(occurrences["arguments_or_file_identity_compared"])
        self.assertEqual(occurrences["rtx5080"][0]["call_index"], 2)
        self.assertEqual(occurrences["v100"][0]["call_index"], 3)
        self.assertEqual(occurrences["v100"][0]["previous"]["request"], "0xc020462a")
        self.assertEqual(occurrences["v100"][0]["next"]["request"], "0xc01046ce")
        encoded = json.dumps(result)
        for pointer in ("0xfeedface", "0xcafebabe", "0xdeadbeef", "0x1111", "0x3333"):
            self.assertNotIn(pointer, encoded)

    def test_output_is_exclusive_and_private(self):
        raw = b"7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0xfeed) = 0\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rtx, _ = self.make_input(root, "rtx", raw)
            v100, _ = self.make_input(root, "v100", raw)
            output = root / "comparison.json"
            compare.write_comparison(rtx, v100, output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                compare.write_comparison(rtx, v100, output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
