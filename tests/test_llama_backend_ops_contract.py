from __future__ import annotations

import unittest
from datetime import datetime, timezone
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.llama_backend_ops_contract import (
    canonical_pci, target_cuda_ordinals, validate_backend_ops_output,
    validate_acceptance_freshness, validate_backend_source_mapping,
    validate_runtime_library_identities,
)


def accepted_probe() -> dict:
    devices = []
    for ordinal, sm, pci in (
            (0, 120, "0000:02:00.0"), (1, 70, "0000:81:00.0")):
        devices.append({
            "ordinal": ordinal,
            "sm": sm,
            "pci_bus_id": pci,
            "targeted": True,
            "tested": True,
            "architecture_kernel_passed": True,
            "synchronous_passed": True,
            "asynchronous_passed": True,
            "cleanup_passed": True,
            "error": "",
        })
    return {
        "schema": "nvidia-hybrid-probe-v2",
        "status": "hybrid-validated",
        "hybrid_validated": True,
        "required_set_passed": True,
        "context_coexistence_passed": True,
        "devices": devices,
    }


def successful_output(backend: str = "CUDA1", *, tests: str = "24/24",
                      description: str = "NVIDIA Tesla V100") -> str:
    return f"""Testing 3 devices

Backend 1/3: CUDA0
  Skipping CUDA0
Backend 2/3: CUDA1
  Device description: {description}
{tests} tests passed
Backend CUDA1: OK
Backend 3/3: CPU
  Skipping CPU backend
2/3 backends passed
OK
"""


class LlamaBackendOpsContractTests(unittest.TestCase):
    def test_pci_normalization_pads_domain_and_rejects_invalid_slot(self):
        self.assertEqual(canonical_pci("0002:02:00.0"), "00000002:02:00.0")
        with self.assertRaisesRegex(ValueError, "invalid PCI slot"):
            canonical_pci("0000:02:20.0")

    def test_exact_device_mapping_resolves_backend_ordinals_from_pci_not_row_order(self):
        actual = target_cuda_ordinals(
            accepted_probe(), {70: "0000:81:00.0", 120: "0000:02:00.0"})
        self.assertEqual(actual, {120: 0, 70: 1})

    def test_incomplete_or_unpinned_hybrid_probe_cannot_select_backends(self):
        report = accepted_probe()
        report["status"] = "incomplete"
        with self.assertRaisesRegex(ValueError, "acceptance has not passed"):
            target_cuda_ordinals(report, {70: "0000:81:00.0", 120: "0000:02:00.0"})

        report = accepted_probe()
        with self.assertRaisesRegex(ValueError, "does not match"):
            target_cuda_ordinals(report, {70: "0000:82:00.0", 120: "0000:02:00.0"})

    def test_actual_cuda_backend_output_passes_without_metal_only_fa_vec_summary(self):
        result = validate_backend_ops_output(successful_output(), 0, "CUDA1", "Tesla V100")
        self.assertEqual(result["tests_passed"], 24)
        self.assertEqual(result["tests_total"], 24)
        self.assertIsNone(result["fa_vec_cases_run"])

    def test_numerical_summary_from_another_backend_cannot_validate_cuda_target(self):
        output = """Testing 2 devices
Backend 1/2: CPU
  24/24 tests passed
  fa_vec (Q,NE) slice: 8 cases run, 0 failed
  Backend CPU: OK
Backend 2/2: CUDA1
  Device description: NVIDIA Tesla V100
  Backend CUDA1: OK
2/2 backends passed
OK
"""
        with self.assertRaisesRegex(ValueError, "exactly one operation-test summary"):
            validate_backend_ops_output(output, 0, "CUDA1", "Tesla V100")

    def test_upstream_zero_exit_after_skipping_missing_cuda_backend_is_rejected(self):
        output = """Testing 1 devices
Backend 1/1: CPU
  Skipping CPU backend
1/1 backends passed
OK
"""
        with self.assertRaisesRegex(ValueError, "not enumerated"):
            validate_backend_ops_output(output, 0, "CUDA0", "Tesla V100")

    def test_selected_cuda_backend_that_was_skipped_is_rejected(self):
        output = """Testing 1 devices
Backend 1/1: CUDA0
  Skipping missing CUDA backend
1/1 backends passed
OK
"""
        with self.assertRaisesRegex(ValueError, "was enumerated but skipped"):
            validate_backend_ops_output(output, 0, "CUDA0", "Tesla V100")

    def test_zero_or_failed_operation_counts_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "empty or at least one"):
            validate_backend_ops_output(successful_output(tests="0/0"), 0, "CUDA1", "Tesla V100")
        with self.assertRaisesRegex(ValueError, "empty or at least one"):
            validate_backend_ops_output(successful_output(tests="23/24"), 0, "CUDA1", "Tesla V100")

    def test_failed_backend_status_and_reported_fa_vec_failure_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "did not report one successful"):
            validate_backend_ops_output(successful_output().replace(
                "Backend CUDA1: OK", "Backend CUDA1: FAIL"), 0, "CUDA1", "Tesla V100")
        reported_fa_vec = successful_output().replace(
            "24/24 tests passed",
            "24/24 tests passed\nfa_vec (Q,NE) slice: 8 cases run, 1 failed")
        with self.assertRaisesRegex(ValueError, "FA vector slice"):
            validate_backend_ops_output(reported_fa_vec, 0, "CUDA1", "Tesla V100")

    def test_reported_fa_vec_summary_must_contain_cases(self):
        empty_fa_vec = successful_output().replace(
            "24/24 tests passed",
            "24/24 tests passed\nfa_vec (Q,NE) slice: 0 cases run, 0 failed")
        with self.assertRaisesRegex(ValueError, "FA vector slice"):
            validate_backend_ops_output(empty_fa_vec, 0, "CUDA1", "Tesla V100")

    def test_console_color_codes_do_not_hide_success(self):
        output = successful_output().replace("Backend CUDA1: OK", "Backend CUDA1: \x1b[1;32mOK\x1b[0m")
        result = validate_backend_ops_output(output, 0, "CUDA1", "Tesla V100")
        self.assertEqual(result["backend_name"], "CUDA1")

    def test_backend_ordinal_must_report_the_pinned_gpu_model(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_backend_ops_output(
                successful_output(description="NVIDIA GeForce RTX 5080"),
                0, "CUDA1", "Tesla V100")

    def test_runtime_libraries_must_match_exactly_one_hash_locked_mapping(self):
        expected = {
            "libcudart.so.12": {
            "path": "/opt/cuda/lib/libcudart.so.12.9.79",
            "bytes": 100,
            "sha256": "a" * 64,
            "device_major": 259,
            "device_minor": 2,
            "inode": 12345,
            },
        }
        validate_runtime_library_identities(
            {"libcudart.so.12": [expected["libcudart.so.12"]]}, expected)
        with self.assertRaisesRegex(ValueError, "identity differs"):
            validate_runtime_library_identities(
                {"libcudart.so.12": [{**expected["libcudart.so.12"], "sha256": "b" * 64}]},
                expected)
        with self.assertRaisesRegex(ValueError, "exactly one mapped instance"):
            validate_runtime_library_identities({"libcudart.so.12": []}, expected)
        with self.assertRaisesRegex(ValueError, "dependency set"):
            validate_runtime_library_identities({}, expected)

    def test_backend_source_must_preserve_cuda_ordinal_to_pci_mapping(self):
        source = "\n".join((
            "info.devices[id].physical_device = id % info.physical_device_count;",
            "dev_ctx->name = GGML_CUDA_NAME + std::to_string(i);",
            "const int physical_id = info.devices[i].physical_device;",
            "CUDA_CHECK(cudaDeviceGetPCIBusId(pci_bus_id, sizeof(pci_bus_id), physical_id));",
        ))
        validate_backend_source_mapping(source)
        with self.assertRaisesRegex(ValueError, "no longer proves"):
            validate_backend_source_mapping("dev_ctx->name = GGML_CUDA_NAME;")

    def test_hybrid_acceptance_must_be_timezone_aware_and_fresh(self):
        now = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
        self.assertEqual(validate_acceptance_freshness("2026-11-02T09:55:00+00:00", now), 300)
        with self.assertRaisesRegex(ValueError, "no timezone"):
            validate_acceptance_freshness("2026-11-02T09:55:00", now)
        with self.assertRaisesRegex(ValueError, "older than 15 minutes"):
            validate_acceptance_freshness("2026-11-02T09:40:00Z", now)
        with self.assertRaisesRegex(ValueError, "future-dated"):
            validate_acceptance_freshness("2026-11-02T10:02:00Z", now)


if __name__ == "__main__":
    unittest.main()
