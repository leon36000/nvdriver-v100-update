import contextlib
import copy
import hashlib
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


summarizer = importlib.import_module("tools.summarize_volta_fault_init_host_harness")


def _source_profile(name):
    source = dict(summarizer.SOURCE_HASHES[name])
    for field in (
        "init_body_without_prefetch_expression_sha256",
        "deinit_body_without_prefetch_expression_sha256",
        "fault_buffer_reinit_body_sha256",
        "non_replayable_deinit_body_sha256",
    ):
        source[field] = hashlib.sha256(field.encode("ascii")).hexdigest()
    source["prefetch_capability_read_present"] = name == "r580"
    source["deinit_prefetch_capability_read_present"] = name == "r580"
    source["volta_capability_initialization"] = {
        "prefetch_fault_supported_true": name == "r580",
    }
    return source


def _valid_report():
    return {
        "schema": summarizer.EXPECTED_SCHEMA,
        "status": "passed",
        "classification": summarizer.EXPECTED_CLASSIFICATION,
        "created_utc": "2026-11-03T12:00:00+00:00",
        "checks_passed": 420,
        "checks_per_implementation": 210,
        "implementations_executed": 2,
        "vectors_per_implementation": 15,
        "expected_guard_count": 6,
        "assertion_guards": [
            "--probe-zero-utlb",
            "--probe-non-divisible-buffer-size",
            "--probe-tracker-nonempty",
        ],
        "hardware_validated": False,
        "module_loaded": False,
        "source_pair": {
            "r580": _source_profile("r580"),
            "r595": _source_profile("r595"),
        },
        "prefetch_false_counterfactual": {
            "r580": "enabled=false; callback=disable_prefetch_faults",
            "r595": "enabled=true; callback=enable_prefetch_faults",
            "scope": (
                "synthetic field value; GV100 source initializes R580 capability true, "
                "and R595 has no such field"
            ),
        },
        "compile_flags": ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        # These intentionally untrusted fields must never enter the receipt.
        "report": "/private/build/path/report.json",
        "log": "/private/build/path/build.log",
    }


class VoltaFaultInitReceiptTest(unittest.TestCase):
    def test_summary_is_path_free_and_keeps_hardware_claims_false(self):
        summary = summarizer.build_summary(_valid_report(), "a" * 64, "b" * 64)
        rendered = json.dumps(summary, sort_keys=True)
        self.assertNotIn("/private/", rendered)
        self.assertEqual("2026-11-03T12:00:00+00:00", summary["created_utc"])
        self.assertEqual(420, summary["host_execution"]["checks_passed"])
        self.assertFalse(summary["hardware_validated"])
        self.assertFalse(summary["module_loaded"])
        self.assertFalse(summary["cuda_validated"])
        self.assertTrue(summary["prefetch_capability_delta"]["false_state_vector_is_synthetic_counterfactual"])

    def test_rejects_changed_release_source_hash(self):
        report = _valid_report()
        report["source_pair"]["r595"]["gpu_header_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned release"):
            summarizer.build_summary(report, "a" * 64, "b" * 64)

    def test_rejects_divergent_normalized_lifecycle(self):
        report = _valid_report()
        report["source_pair"]["r595"]["fault_buffer_reinit_body_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "normalized lifecycle contract differs"):
            summarizer.build_summary(report, "a" * 64, "b" * 64)

    def test_rejects_runtime_claims(self):
        for field in ("hardware_validated", "module_loaded"):
            with self.subTest(field=field):
                report = _valid_report()
                report[field] = True
                with self.assertRaisesRegex(ValueError, "must remain false"):
                    summarizer.build_summary(report, "a" * 64, "b" * 64)

    def test_rejects_check_count_drift(self):
        report = _valid_report()
        report["checks_passed"] = 419
        with self.assertRaisesRegex(ValueError, "check count changed"):
            summarizer.build_summary(report, "a" * 64, "b" * 64)

    def test_rejects_timestamp_without_timezone_or_with_path_data(self):
        for timestamp in ("2026-11-03T12:00:00", "/private/build/report.json"):
            with self.subTest(timestamp=timestamp):
                report = _valid_report()
                report["created_utc"] = timestamp
                with self.assertRaisesRegex(ValueError, "timestamp"):
                    summarizer.build_summary(report, "a" * 64, "b" * 64)

    def test_cli_writes_private_receipt_bound_to_raw_inputs(self):
        report = _valid_report()
        raw_bytes = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
        log_bytes = b"pinned host harness log\n"
        with tempfile.TemporaryDirectory(prefix="volta-summary-input-") as input_dir:
            root = Path(input_dir)
            raw_path = root / "raw.json"
            log_path = root / "raw.log"
            raw_path.write_bytes(raw_bytes)
            log_path.write_bytes(log_bytes)
            evidence_root = Path(summarizer.ROOT) / "evidence"
            with tempfile.TemporaryDirectory(prefix="volta-summary-output-", dir=evidence_root) as output_dir:
                output_path = Path(output_dir) / "receipt.json"
                stdout = io.StringIO()
                argv = [
                    "summarize_volta_fault_init_host_harness.py",
                    "--input", str(raw_path),
                    "--log", str(log_path),
                    "--output", str(output_path),
                ]
                with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
                    self.assertEqual(0, summarizer.main())
                mode = os.stat(output_path).st_mode & 0o777
                self.assertEqual(0o600, mode)
                output = json.loads(output_path.read_text(encoding="utf-8"))
                status = json.loads(stdout.getvalue())
                self.assertEqual(hashlib.sha256(raw_bytes).hexdigest(), output["raw_report_sha256"])
                self.assertEqual(hashlib.sha256(log_bytes).hexdigest(), output["raw_log_sha256"])
                self.assertEqual(hashlib.sha256(output_path.read_bytes()).hexdigest(), status["receipt_sha256"])
                self.assertEqual(420, output["host_execution"]["checks_passed"])
                self.assertFalse(output["hardware_validated"])


if __name__ == "__main__":
    unittest.main()
