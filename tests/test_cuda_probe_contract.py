# SPDX-License-Identifier: MIT
"""CPU-only contract tests for locally built CUDA probe artifacts."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.cuda_probe_contract import (
    validate_graph_api_claim, validate_probe_contract)


CONTRACT = {
    "schema": "nvidia-hybrid-probe-contract-v1",
    "contract_version": 10,
    "probe_report_schema": "nvidia-hybrid-probe-v2",
    "probe_report_fields": [
        "expected_device_pci_by_sm",
        "memory_mode",
        "managed_prefetch_requested",
        "managed_prefetch_api",
        "devices",
        "cuda_graphs_requested",
        "cuda_graph_api",
        "performance_benchmark_requested",
        "concurrent_kernel_test_requested",
        "concurrent_kernel_dispatch_passed",
        "concurrent_kernel_dispatch",
        "peer_transfer_requested",
        "peer_transfer",
    ],
    "peer_transfer_report_schema": "nvidia-hybrid-peer-transfer-v3",
    "peer_transfer_fields": [
        "host_staged_fallback_passed",
        "host_staged_fallback_status",
    ],
    "peer_transfer_direction_fields": [
        "host_staged_sync_copy_passed",
        "host_staged_async_copy_passed",
        "host_staged_data_integrity_passed",
    ],
    "device_report_fields": [
        "concurrent_managed_access",
        "pageable_memory_access",
        "pageable_memory_access_uses_host_page_tables",
        "managed_memory_passed",
        "managed_prefetch_passed",
        "cuda_graphs_passed",
        "cuda_graph_launches",
        "performance_benchmark_passed",
        "performance_benchmark",
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

    def test_accepts_legacy_per_device_contract_without_hybrid_pci_mapping(self):
        legacy = dict(CONTRACT)
        legacy["contract_version"] = 4
        legacy["probe_report_fields"] = [
            field for field in CONTRACT["probe_report_fields"]
            if field not in ("expected_device_pci_by_sm", "performance_benchmark_requested")]
        legacy["device_report_fields"] = [
            field for field in CONTRACT["device_report_fields"]
            if field not in ("performance_benchmark_passed", "performance_benchmark")]
        result = validate_probe_contract(
            self.probe,
            invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, json.dumps(legacy), ""))
        self.assertEqual(result["contract_version"], 4)

    def test_exact_device_map_mode_requires_v6_mapping_field(self):
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe, require_exact_device_map=True,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps({**CONTRACT, "contract_version": 5,
                                        "probe_report_fields": [
                                            field for field in CONTRACT["probe_report_fields"]
                                            if field != "expected_device_pci_by_sm"]}), ""))

    def test_concurrent_dispatch_requires_v7_report_fields(self):
        result = validate_probe_contract(
            self.probe, require_concurrent_dispatch=True,
            invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, json.dumps(CONTRACT), ""))
        self.assertGreaterEqual(result["contract_version"], 7)

        legacy = dict(CONTRACT)
        legacy["contract_version"] = 6
        legacy["probe_report_fields"] = [
            field for field in CONTRACT["probe_report_fields"]
            if field not in {"concurrent_kernel_test_requested",
                             "concurrent_kernel_dispatch_passed",
                             "concurrent_kernel_dispatch"}]
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe, require_concurrent_dispatch=True,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps(legacy), ""))

    def test_peer_transfer_requires_v10_host_staging_report_contract(self):
        result = validate_probe_contract(
            self.probe, require_peer_transfer=True,
            invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, json.dumps(CONTRACT), ""))
        self.assertEqual(result["contract_version"], 10)

        legacy = dict(CONTRACT)
        legacy["contract_version"] = 9
        legacy["peer_transfer_report_schema"] = "nvidia-hybrid-peer-transfer-v2"
        legacy.pop("peer_transfer_direction_fields")
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe, require_peer_transfer=True,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps(legacy), ""))

        legacy = dict(CONTRACT)
        legacy["contract_version"] = 8
        legacy["probe_report_fields"] = [
            field for field in CONTRACT["probe_report_fields"]
            if field not in {"peer_transfer_requested", "peer_transfer"}]
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe, require_peer_transfer=True,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps(legacy), ""))

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

    def test_rejects_contract_missing_pageable_memory_capability(self):
        legacy = dict(CONTRACT)
        legacy["device_report_fields"] = [
            field for field in CONTRACT["device_report_fields"]
            if field != "pageable_memory_access"
        ]
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps(legacy), ""))

    def test_rejects_contract_missing_concurrent_managed_access(self):
        legacy = dict(CONTRACT)
        legacy["device_report_fields"] = [
            field for field in CONTRACT["device_report_fields"]
            if field != "concurrent_managed_access"
        ]
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

    def test_performance_mode_requires_contract_v5_fields(self):
        legacy = dict(CONTRACT)
        legacy["contract_version"] = 4
        legacy["probe_report_fields"] = [
            field for field in CONTRACT["probe_report_fields"]
            if field != "performance_benchmark_requested"]
        legacy["device_report_fields"] = [
            field for field in CONTRACT["device_report_fields"]
            if field not in ("performance_benchmark_passed", "performance_benchmark")]
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_probe_contract(
                self.probe, require_performance_benchmark=True,
                invoke=lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv, 0, json.dumps(legacy), ""))

    def test_graph_api_claim_separates_functional_replay_from_timing_graph(self):
        validate_graph_api_claim("not-requested", False, False)
        validate_graph_api_claim("cuGraphInstantiateWithFlags", False, True)
        validate_graph_api_claim("cuGraphInstantiateWithFlags", True, False)
        validate_graph_api_claim("cuGraphInstantiateWithFlags", True, True)
        validate_graph_api_claim("unavailable", True, False)
        for api, graphs, benchmark in (
                ("not-requested", False, True),
                ("unavailable", False, True),
                ("unknown", True, False),
                ("cuGraphInstantiateWithFlags", False, False)):
            with self.subTest(api=api, graphs=graphs, benchmark=benchmark), \
                    self.assertRaises(ValueError):
                validate_graph_api_claim(api, graphs, benchmark)


if __name__ == "__main__":
    unittest.main()
