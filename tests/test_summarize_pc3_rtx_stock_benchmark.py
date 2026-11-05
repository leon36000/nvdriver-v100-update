import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.summarize_pc3_rtx_stock_benchmark import (
    SUMMARY_SCHEMA,
    SummaryError,
    summarize_report,
    write_new_json,
)


LIBCUDA_SHA256 = "a" * 64


def _summary(samples, median, p95):
    return {"samples": samples, "median": median, "p95": p95,
            "values": [median] * samples}


def _benchmark():
    samples = 9
    transfer_samples = 7
    transfers = []
    for size in (4096, 65536, 1048576, 16777216, 67108864):
        direction = {
            "data_integrity_passed": True,
            "gb_per_second_median": 20.0,
            "gb_per_second_p95": 21.0,
            "gb_per_second_samples": [20.0] * transfer_samples,
        }
        transfers.append({
            "bytes": size,
            "data_integrity_passed": True,
            "samples": transfer_samples,
            "h_to_d": copy.deepcopy(direction),
            "d_to_h": copy.deepcopy(direction),
        })
    return {
        "schema": "nvidia-cuda-performance-benchmark-v2",
        "status": "completed",
        "samples": samples,
        "transfer_samples": transfer_samples,
        "launches_per_sample": 256,
        "warmup_launches": 64,
        "kernel_launch": {
            "samples": samples,
            "device_elapsed_us_median": 1.2,
            "device_elapsed_us_p95": 1.3,
            "device_elapsed_us_samples": [1.2] * samples,
            "host_api_us_median": 1.1,
            "host_api_us_p95": 1.2,
            "host_api_us_samples": [1.1] * samples,
        },
        "cuda_graph_launch": {
            "device_elapsed_us": _summary(samples, 1.9, 2.0),
            "host_api_us": _summary(samples, 1.2, 1.3),
        },
        "transfers": transfers,
    }


def _report():
    acceptance = {
        "schema": "nvidia-hybrid-hardware-acceptance-v2",
        "exit_code": 77,
        "qualification": "incomplete-hardware-missing",
        "kernel_release": "7.0.0-38-generic",
        "performance_benchmark_requested": True,
        "validation_errors": [],
        "probe": {
            "schema": "nvidia-hybrid-probe-v2",
            "status": "incomplete",
            "hybrid_validated": False,
            "required_set_passed": False,
            "missing_sm": [70],
            "driver_api": 13020,
            "devices": [{
                "name": "NVIDIA GeForce RTX 5080",
                "pci_bus_id": "0000:02:00.0",
                "sm": 120,
                "compute_capability": "12.0",
                "performance_benchmark_passed": True,
                "performance_benchmark": _benchmark(),
            }],
        },
    }
    return {
        "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
        "report_contract_validated": True,
        "qualification": "rtx5080-report-contract-valid-hybrid-incomplete",
        "exit_code": 77,
        "observed_at_utc": "2026-11-03T17:17:08.596694+00:00",
        "performance_benchmark_requested": True,
        "benchmark_samples": 9,
        "benchmark_transfer_samples": 7,
        "expected_libcuda_sha256": LIBCUDA_SHA256,
        "remote": {
            "performance_benchmark_report_contract_passed": True,
            "performance_benchmark_validated": False,
            "cuda_execution_validated": False,
            "selected_nvidia_smi": {
                "name": "NVIDIA GeForce RTX 5080",
                "uuid": "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77",
                "pci": "00000000:02:00.0",
                "driver": "595.99.02",
            },
            "system_libcuda_before": {"sha256": LIBCUDA_SHA256},
            "system_libcuda_after": {"sha256": LIBCUDA_SHA256},
            "remote_work_cleanup": {"passed": True, "removed": True},
            "preflight": {
                "status": "inventory",
                "driver_api": 13020,
                "devices": [{"pci_bus_id": "0000:02:00.0", "sm": 120}],
            },
            "commands": [{"stdout": json.dumps(acceptance)}],
        },
    }


class Pc3RtxStockBenchmarkSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "evidence" / "logs").mkdir(parents=True)
        (self.root / "evidence").mkdir(exist_ok=True)

    def tearDown(self):
        self.temp.cleanup()

    def write_capture(self, report=None):
        path = self.root / "evidence" / "logs" / "capture.json"
        path.write_text(json.dumps(report or _report()), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_summarizes_stock_rtx_benchmark_without_claiming_hybrid_validation(self):
        summary = summarize_report(self.write_capture(), self.root)
        self.assertEqual(summary["schema"], SUMMARY_SCHEMA)
        self.assertEqual(summary["qualification"],
                         "stock-rtx-benchmark-report-pass-hybrid-gate-incomplete")
        self.assertEqual(summary["host_hardware"]["compute_capability"], "12.0")
        self.assertEqual(summary["stock_rtx_benchmark"]["kernel_launch"]["device_elapsed_us"],
                         {"median": 1.2, "p95": 1.3, "samples": 9})
        self.assertEqual(len(summary["stock_rtx_benchmark"]["pinned_transfers"]), 5)
        self.assertTrue(summary["hybrid_acceptance"]["report_contract_validated"])
        self.assertFalse(summary["hybrid_acceptance"]["same_host_v100_blackwell_validated"])
        self.assertFalse(summary["hybrid_acceptance"]["cuda_execution_independently_attested"])
        serialized = json.dumps(summary)
        self.assertNotIn("GPU-819a4547", serialized)
        self.assertNotIn("/home/", serialized)
        self.assertNotIn("/run/media/", serialized)
        self.assertNotIn("pc3@", serialized.lower())

    def test_rejects_missing_sm70_or_wrong_adapter(self):
        report = _report()
        acceptance = json.loads(report["remote"]["commands"][0]["stdout"])
        acceptance["probe"]["missing_sm"] = []
        report["remote"]["commands"][0]["stdout"] = json.dumps(acceptance)
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(report), self.root)

        report = _report()
        report["remote"]["selected_nvidia_smi"]["driver"] = "590.00.00"
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(report), self.root)

        report = _report()
        acceptance = json.loads(report["remote"]["commands"][0]["stdout"])
        acceptance["probe"]["devices"] = [None]
        report["remote"]["commands"][0]["stdout"] = json.dumps(acceptance)
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(report), self.root)

    def test_rejects_failed_transfer_integrity_and_unattested_override(self):
        report = _report()
        acceptance = json.loads(report["remote"]["commands"][0]["stdout"])
        acceptance["probe"]["devices"][0]["performance_benchmark"]["transfers"][0][
            "h_to_d"]["data_integrity_passed"] = False
        report["remote"]["commands"][0]["stdout"] = json.dumps(acceptance)
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(report), self.root)

        report = _report()
        acceptance = json.loads(report["remote"]["commands"][0]["stdout"])
        acceptance["probe"]["devices"][0]["performance_benchmark"]["transfers"][0][
            "h_to_d"]["gb_per_second_samples"] = 7
        report["remote"]["commands"][0]["stdout"] = json.dumps(acceptance)
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(report), self.root)

        report = _report()
        report["remote"]["cuda_execution_validated"] = True
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(report), self.root)

    def test_requires_private_raw_input(self):
        path = self.write_capture()
        path.chmod(0o644)
        with self.assertRaises(SummaryError):
            summarize_report(path, self.root)

    def test_rejects_symlinked_raw_report_and_evidence_directory(self):
        outside = self.root / "outside.json"
        outside.write_text(json.dumps(_report()), encoding="utf-8")
        outside.chmod(0o600)
        link = self.root / "evidence" / "logs" / "linked.json"
        link.symlink_to(outside)
        with self.assertRaises(SummaryError):
            summarize_report(link, self.root)
        link.unlink()
        logs = self.root / "evidence" / "logs"
        moved = self.root / "logs-moved"
        logs.rename(moved)
        logs.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(SummaryError):
            summarize_report(outside, self.root)

    def test_writer_never_overwrites_or_escapes_evidence(self):
        summary = summarize_report(self.write_capture(), self.root)
        output = self.root / "evidence" / "summary.json"
        write_new_json(output, summary, self.root)
        previous = output.read_bytes()
        with self.assertRaises(SummaryError):
            write_new_json(output, summary, self.root)
        self.assertEqual(output.read_bytes(), previous)
        with self.assertRaises(SummaryError):
            write_new_json(self.root / "outside.json", summary, self.root)


if __name__ == "__main__":
    unittest.main()
