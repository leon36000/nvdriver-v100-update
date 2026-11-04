# SPDX-License-Identifier: MIT
"""CPU-only contract tests for locally built CUDA probe artifacts."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.cuda_probe_contract import validate_probe_contract


CONTRACT = {
    "schema": "nvidia-hybrid-probe-contract-v1",
    "contract_version": 2,
    "probe_report_schema": "nvidia-hybrid-probe-v2",
    "probe_report_fields": [
        "memory_mode",
        "managed_prefetch_requested",
        "managed_prefetch_api",
        "devices",
        "cuda_graphs_requested",
        "cuda_graph_api",
    ],
    "device_report_fields": [
        "managed_memory_passed",
        "managed_prefetch_passed",
        "cuda_graphs_passed",
        "cuda_graph_launches",
    ],
}


class ProbeContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.probe = Path(self.tmp.name) / "probe"
        self.probe.write_bytes(b"synthetic executable")
        self.probe.chmod(0o700)
        self.digest = hashlib.sha256(self.probe.read_bytes()).hexdigest()

    def test_accepts_compatible_contract_and_pins_probe_digest(self):
        calls = []

        def invoke(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, json.dumps(CONTRACT), "")

        result = validate_probe_contract(
            self.probe, expected_sha256=self.digest, invoke=invoke)

        self.assertEqual(result["probe_sha256"], self.digest)
        self.assertEqual(result["schema"], CONTRACT["schema"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], [str(self.probe.resolve()), "--contract"])
        self.assertEqual(calls[0][1]["stdin"], subprocess.DEVNULL)
        self.assertEqual(calls[0][1]["timeout"], 5)

    def test_rejects_legacy_binary_before_invocation_on_hash_mismatch(self):
        calls = []
        with self.assertRaisesRegex(ValueError, "changed before contract check"):
            validate_probe_contract(
                self.probe, expected_sha256="0" * 64,
                invoke=lambda *args, **kwargs: calls.append(args))
        self.assertEqual(calls, [])

    def test_rejects_incompatible_report_fields(self):
        legacy = dict(CONTRACT)
        legacy["probe_report_fields"] = ["devices"]
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps(legacy), ""))

    def test_detects_artifact_replacement_during_contract_check(self):
        def replace_then_report(argv, **kwargs):
            self.probe.write_bytes(b"replacement executable")
            return subprocess.CompletedProcess(argv, 0, json.dumps(CONTRACT), "")

        with self.assertRaisesRegex(ValueError, "changed during contract check"):
            validate_probe_contract(self.probe, invoke=replace_then_report)

    def test_rejects_binary_without_contract(self):
        with self.assertRaisesRegex(ValueError, "contract is missing"):
            validate_probe_contract(
                self.probe,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 64, "", "unknown option"))


if __name__ == "__main__":
    unittest.main()
