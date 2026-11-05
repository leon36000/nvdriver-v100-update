# SPDX-License-Identifier: MIT
"""CPU-only tests for aggregation of selected stock-driver reference evidence."""

import math
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.aggregate_cuda_performance_references import (
    EXCLUDED_DIAGNOSTICS, RTX_QUALIFICATION, V100_QUALIFICATION,
    load_rtx_reference, load_v100_reference, summarize_samples,
)


class SampleSummaryTests(unittest.TestCase):
    def test_uses_median_and_nearest_rank_p95(self):
        odd = summarize_samples([5.0, 1.0, 3.0])
        self.assertEqual(odd["median"], 3.0)
        self.assertEqual(odd["p95_nearest_rank"], 5.0)
        self.assertEqual(odd["values"], [1.0, 3.0, 5.0])

        even = summarize_samples([4.0, 1.0, 3.0, 2.0])
        self.assertEqual(even["median"], 2.5)
        self.assertEqual(even["p95_nearest_rank"], 4.0)

    def test_rejects_empty_nonpositive_boolean_and_nonfinite_samples(self):
        invalid = ([], [0.0], [-1.0], [True], [math.inf], [math.nan])
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                summarize_samples(values)


class DiagnosticCaptureManifestTests(unittest.TestCase):
    def test_all_four_unqualified_capture_artifacts_remain_accounted_for(self):
        diagnostics = {item["path"]: item["reason"]
                       for item in EXCLUDED_DIAGNOSTICS}
        self.assertEqual(set(diagnostics), {
            "evidence/pc3-rtx5080-performance-reference-v1-20261023T2345Z.json",
            "evidence/pc3-rtx5080-performance-reference-v2-20261023T2347Z.json",
            "evidence/pc3-rtx5080-performance-reference-v3-20261023T2350Z.json",
            "evidence/pc3-v100-performance-reference-v2-20261023T2356Z.json",
        })
        self.assertIn("staging", diagnostics[
            "evidence/pc3-rtx5080-performance-reference-v1-20261023T2345Z.json"])
        self.assertIn("bandwidth", diagnostics[
            "evidence/pc3-rtx5080-performance-reference-v3-20261023T2350Z.json"])
        self.assertIn("graph", diagnostics[
            "evidence/pc3-v100-performance-reference-v2-20261023T2356Z.json"])

    def test_caller_authored_execution_flags_cannot_enable_benchmark_aggregation(self):
        cases = (
            (load_rtx_reference, {
                "performance_benchmark_requested": True,
                "remote": {
                    "qualification": RTX_QUALIFICATION,
                    "performance_benchmark_validated": True,
                    "cuda_execution_validated": False,
                    "cuda_execution_validation_state":
                        "not-established; probe build identity is not trusted",
                    "execution_attestation": {
                        "schema": "fake-signature-v1",
                        "signature": "caller-authored",
                    },
                },
            }),
            (load_v100_reference, {
                "qualification": V100_QUALIFICATION,
                "performance_benchmark_requested": True,
                "exit_code": 0,
                "cuda_execution_validated": False,
                "cuda_execution_validation_state":
                    "not-established; probe build identity is not trusted",
                "execution_attestation": {
                    "schema": "fake-signature-v1",
                    "signature": "caller-authored",
                },
                "remote": {
                    "qualification": V100_QUALIFICATION,
                    "performance_benchmark_requested": True,
                    "probe_exit_code": 0,
                    "cuda_execution_validated": False,
                    "cuda_execution_validation_state":
                        "not-established; probe build identity is not trusted",
                },
            }),
        )
        import json
        import tempfile
        for loader, report in cases:
            with self.subTest(loader=loader.__name__), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                path.write_text(json.dumps(report), encoding="utf-8")
                report["cuda_execution_validated"] = True
                report["cuda_execution_validation_state"] = "trusted-pinned-probe-attested"
                if isinstance(report.get("remote"), dict):
                    report["remote"]["cuda_execution_validated"] = True
                    report["remote"]["cuda_execution_validation_state"] = (
                        "trusted-pinned-probe-attested")
                path.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "no independently verifiable execution attestation"):
                    loader(path)


if __name__ == "__main__":
    unittest.main()
