import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.summarize_pc3_rtx_stock_phase import (
    SummaryError,
    summarize_report,
    write_new_json,
)


class RtxStockPhaseSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "evidence" / "logs").mkdir(parents=True)
        (self.root / "build").mkdir()
        self.manifest = {}
        for name in sorted({"cuda_probe_contract.py", "module", "observer", "probe", "runner"}):
            path = self.root / "build" / name
            content = ("fixture-" + name).encode()
            path.write_bytes(content)
            self.manifest[name] = {
                "bytes": len(content),
                "path": str(path),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        self.report = {
            "schema": "nvidia-hybrid-remote-selected-gpu-transport-v1",
            "observed_at_utc": "2026-11-02T17:33:51Z",
            "phase": "kernel",
            "exit_code": 0,
            "ssh_exit_code": 0,
            "qualification": "rtx5080-cuda-phase-report-contract-valid",
            "report_contract_validated": True,
            "cuda_execution_validated": False,
            "target": "private-host-account",
            "ssh_argv": ["ssh", "-i", "/private/key"],
            "ssh_stdout": "HOST_SENTINEL_PRIVATE_OUTPUT",
            "local_artifacts": copy.deepcopy(self.manifest),
            "local_artifacts_after": copy.deepcopy(self.manifest),
            "remote": {
                "schema": "nvidia-hybrid-remote-selected-gpu-v1",
                "phase": "kernel",
                "exit_code": 0,
                "qualification": "rtx5080-cuda-phase-report-contract-valid",
                "report_contract_validated": True,
                "cuda_execution_validated": False,
                "kernel_release": "7.0.0-38-generic",
                "device_alloc_records_seen": True,
                "device_alloc_payload_snapshots_read": 2,
                "remote_work_cleanup": {"passed": True},
                "system_libcuda_before": {"sha256": "a" * 64, "path": "/private/path"},
                "system_libcuda_after": {"sha256": "a" * 64, "path": "/private/path"},
                "artifacts_before": copy.deepcopy(self.manifest),
                "artifacts_after": copy.deepcopy(self.manifest),
                "phase_report": {
                    "schema": "nvidia-cuda-driver-phase-v1",
                    "phase": "kernel",
                    "status": "phase-passed",
                    "driver_api": 13020,
                    "expected_result": 1200,
                    "result_value": 1200,
                    "numeric_result_passed": True,
                    "cleanup_passed": True,
                    "cleanup_errors": [],
                    "selected_device": {
                        "name": "NVIDIA GeForce RTX 5080",
                        "pci_bus_id": "0000:02:00.0",
                        "compute_capability": "12.0",
                        "sm": 120,
                    },
                },
            },
        }

    def tearDown(self):
        self.temp.cleanup()

    def write_capture(self, report=None):
        path = self.root / "evidence" / "logs" / "capture.json"
        path.write_text(json.dumps(self.report if report is None else report), encoding="utf-8")
        return path

    def test_valid_capture_is_whitelisted_and_unattested(self):
        summary = summarize_report(self.write_capture(), self.root)
        self.assertEqual(summary["qualification"], "report-contract-valid-no-independent-hardware-attestation")
        self.assertEqual(summary["numeric_result"]["reported"], 1200)
        self.assertFalse(summary["cuda_execution_validated"])
        encoded = json.dumps(summary)
        for forbidden in ("private-host-account", "HOST_SENTINEL", "/private/key", "system_libcuda_before"):
            self.assertNotIn(forbidden, encoded)

    def test_rejects_claim_of_independent_cuda_validation(self):
        bad = copy.deepcopy(self.report)
        bad["remote"]["cuda_execution_validated"] = True
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(bad), self.root)

    def test_rejects_wrong_gpu_or_numeric_result(self):
        bad_gpu = copy.deepcopy(self.report)
        bad_gpu["remote"]["phase_report"]["selected_device"]["sm"] = 70
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(bad_gpu), self.root)
        bad_number = copy.deepcopy(self.report)
        bad_number["remote"]["phase_report"]["result_value"] = 1199
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(bad_number), self.root)

    def test_rejects_non_utc_capture_timestamp(self):
        bad = copy.deepcopy(self.report)
        bad["observed_at_utc"] = "2026-11-02T12:33:51-05:00"
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(bad), self.root)

    def test_missing_library_hash_stays_unknown_and_mismatch_fails(self):
        without_hash = copy.deepcopy(self.report)
        without_hash["remote"]["system_libcuda_before"] = None
        without_hash["remote"]["system_libcuda_after"] = None
        summary = summarize_report(self.write_capture(without_hash), self.root)
        self.assertIsNone(summary["system_libcuda_sha256_before_and_after"])
        self.assertIsNone(summary["system_libcuda_hash_stable"])

        mismatch = copy.deepcopy(self.report)
        mismatch["remote"]["system_libcuda_after"]["sha256"] = "b" * 64
        with self.assertRaises(SummaryError):
            summarize_report(self.write_capture(mismatch), self.root)

    def test_rejects_artifact_tampering_and_path_escape(self):
        capture = self.write_capture()
        (self.root / "build" / "probe").write_text("changed", encoding="utf-8")
        with self.assertRaises(SummaryError):
            summarize_report(capture, self.root)

        outside = self.root.parent / "outside-artifact"
        outside.write_text("outside", encoding="utf-8")
        bad = copy.deepcopy(self.report)
        bad["local_artifacts"]["probe"]["path"] = str(outside)
        bad["local_artifacts_after"]["probe"]["path"] = str(outside)
        bad["remote"]["artifacts_before"]["probe"]["path"] = str(outside)
        bad["remote"]["artifacts_after"]["probe"]["path"] = str(outside)
        path = self.write_capture(bad)
        with self.assertRaises(SummaryError):
            summarize_report(path, self.root)
        outside.unlink()

    def test_receipt_writer_never_overwrites(self):
        output = self.root / "evidence" / "receipt.json"
        report = summarize_report(self.write_capture(), self.root)
        write_new_json(output, report, self.root)
        original = output.read_bytes()
        with self.assertRaises(SummaryError):
            write_new_json(output, report, self.root)
        self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
