# SPDX-License-Identifier: MIT
"""CPU-only validation tests for bounded CUDA peer-copy reports."""

import unittest

from tools.cuda_probe_contract import validate_peer_transfer_report


def peer_report(status="peer-memory-verified", passed=True,
                direct_access=True, capabilities=(True, True)):
    return {
        "schema": "nvidia-hybrid-peer-transfer-v3",
        "status": status,
        "requested": True,
        "passed": passed,
        "sm70_can_access_sm120": capabilities[0],
        "sm120_can_access_sm70": capabilities[1],
        "direct_peer_access_enabled": direct_access,
        "direct_dma_attested": False,
        "host_staged_fallback_passed": True,
        "host_staged_fallback_status": "host-staged-verified",
        "sm70_pci_bus_id": "0000:01:00.0",
        "sm120_pci_bus_id": "0000:02:00.0",
        "bytes_per_direction": 4096,
        "directions": [
            {"source_sm": 70, "destination_sm": 120,
             "direct_access_enabled": direct_access,
             "direct_kernel_attempted": direct_access,
             "direct_kernel_passed": direct_access,
             "sync_copy_passed": True, "async_copy_passed": True,
             "data_integrity_passed": True,
             "host_staged_sync_copy_passed": True,
             "host_staged_async_copy_passed": True,
             "host_staged_data_integrity_passed": True},
            {"source_sm": 120, "destination_sm": 70,
             "direct_access_enabled": direct_access,
             "direct_kernel_attempted": direct_access,
             "direct_kernel_passed": direct_access,
             "sync_copy_passed": True, "async_copy_passed": True,
             "data_integrity_passed": True,
             "host_staged_sync_copy_passed": True,
             "host_staged_async_copy_passed": True,
             "host_staged_data_integrity_passed": True},
        ],
        "cleanup_passed": True,
        "error": "",
    }


class CudaPeerTransferContractTests(unittest.TestCase):
    def test_unrequested_peer_transfer_is_explicitly_null(self):
        validate_peer_transfer_report(
            {"peer_transfer_requested": False, "peer_transfer": None}, False)

    def test_accepts_bidirectional_peer_memory_kernel_reads_without_dma_attestation(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        validate_peer_transfer_report(
            report, True,
            {70: "00000000:01:00.0", 120: "00000000:02:00.0"})

    def test_accepts_cross_context_copy_without_peer_memory_access(self):
        peer = peer_report(
            "copy-only-verified", True, False,
            capabilities=(False, False))
        validate_peer_transfer_report(
            {"peer_transfer_requested": True, "peer_transfer": peer}, True,
            {70: "0000:01:00.0", 120: "0000:02:00.0"})

    def test_accepts_one_way_peer_kernel_read(self):
        peer = peer_report("one-way-peer-memory-verified", True, False,
                           capabilities=(True, False))
        peer["directions"][0].update(
            direct_access_enabled=False, direct_kernel_attempted=False,
            direct_kernel_passed=False)
        peer["directions"][1].update(
            direct_access_enabled=True, direct_kernel_attempted=True,
            direct_kernel_passed=True)
        validate_peer_transfer_report(
            {"peer_transfer_requested": True, "peer_transfer": peer}, True)

    def test_rejects_copy_success_without_both_numeric_directions(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["directions"].pop()
        with self.assertRaisesRegex(ValueError, "host-staged fallback flag|bidirectional"):
            validate_peer_transfer_report(report, True)

    def test_rejects_copy_success_claimed_as_direct_dma_attestation(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["direct_dma_attested"] = True
        with self.assertRaisesRegex(ValueError, "qualification flags"):
            validate_peer_transfer_report(report, True)

    def test_accepts_host_staged_fallback_when_peer_api_is_unavailable(self):
        peer = peer_report("api-unavailable", False, False, (None, None))
        for direction in peer["directions"]:
            direction.update(
                direct_access_enabled=False,
                direct_kernel_attempted=False,
                direct_kernel_passed=False,
                sync_copy_passed=False,
                async_copy_passed=False,
                data_integrity_passed=False)
        validate_peer_transfer_report(
            {"peer_transfer_requested": True, "peer_transfer": peer}, True)

    def test_rejects_result_for_unpinned_or_swapped_devices(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        with self.assertRaisesRegex(ValueError, "identities differ"):
            validate_peer_transfer_report(
                report, True,
                {70: "0000:09:00.0", 120: "0000:02:00.0"})

    def test_rejects_unrequested_peer_data(self):
        report = {"peer_transfer_requested": False,
                  "peer_transfer": peer_report()}
        with self.assertRaisesRegex(ValueError, "unrequested"):
            validate_peer_transfer_report(report, False)

    def test_rejects_contradictory_per_direction_integrity_flag(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["directions"][0]["async_copy_passed"] = False
        with self.assertRaisesRegex(ValueError, "integrity flag contradicts"):
            validate_peer_transfer_report(report, True)

    def test_rejects_host_staged_integrity_flag_that_disagrees_with_copies(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["directions"][0][
            "host_staged_async_copy_passed"] = False
        with self.assertRaisesRegex(ValueError, "host-staged integrity"):
            validate_peer_transfer_report(report, True)

    def test_rejects_kernel_success_without_attempt(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["directions"][0]["direct_kernel_attempted"] = False
        with self.assertRaisesRegex(ValueError, "kernel success requires"):
            validate_peer_transfer_report(report, True)

    def test_rejects_peer_kernel_attempt_without_enabled_access(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["directions"][0]["direct_access_enabled"] = False
        with self.assertRaisesRegex(ValueError, "requires enabled direct access"):
            validate_peer_transfer_report(report, True)

    def test_rejects_directional_access_without_matching_capability(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report(capabilities=(True, False))}
        with self.assertRaisesRegex(ValueError, "contradicts queried capability"):
            validate_peer_transfer_report(report, True)

    def test_rejects_overall_access_flag_that_disagrees_with_directions(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report()}
        report["peer_transfer"]["direct_peer_access_enabled"] = False
        with self.assertRaisesRegex(ValueError, "overall peer-access flag"):
            validate_peer_transfer_report(report, True)

    def test_rejects_peer_kernel_failure_without_failed_kernel_evidence(self):
        report = {"peer_transfer_requested": True,
                  "peer_transfer": peer_report(
                      "peer-kernel-failed", False, True)}
        with self.assertRaisesRegex(ValueError, "peer-kernel-failed"):
            validate_peer_transfer_report(report, True)

    def test_rejects_copy_failure_without_two_direction_results(self):
        peer = peer_report("copy-failed", False, False, (False, False))
        peer["directions"] = []
        with self.assertRaisesRegex(ValueError, "host-staged fallback flag|copy-failed requires both directions"):
            validate_peer_transfer_report(
                {"peer_transfer_requested": True, "peer_transfer": peer}, True)


if __name__ == "__main__":
    unittest.main()
