# SPDX-License-Identifier: MIT
"""CPU-only contract tests for the opt-in VMM peer-read probe."""

import copy
import unittest

from tools.vmm_peer_probe_contract import validate_vmm_peer_report


def direction(source=70, destination=120, passed=True):
    return {
        "source_sm": source,
        "destination_sm": destination,
        "source_pci_bus_id": "0000:01:00.0" if source == 70 else "0000:02:00.0",
        "destination_pci_bus_id": "0000:02:00.0" if destination == 120 else "0000:01:00.0",
        "peer_capability": False,
        "allocation_granularity_bytes": 65536,
        "allocation_bytes": 65536,
        "allocation_created": True,
        "mapping_created": True,
        "access_configured": True,
        "source_access_verified": True,
        "destination_readonly_access_verified": True,
        "kernel_attempted": True,
        "kernel_passed": passed,
        "cleanup_passed": True,
        "cleanup_errors": [],
        "error": "" if passed else "injected numerical failure",
    }


def report(status="vmm-peer-memory-verified", passed=True, directions=None):
    if directions is None:
        directions = [direction(70, 120), direction(120, 70)]
    return {
        "schema": "nvidia-hybrid-vmm-peer-probe-v1",
        "status": status,
        "passed": passed,
        "driver_version": 13010,
        "cuda_vmm_mode": "explicit-vmm-access-no-cuCtxEnablePeerAccess",
        "direct_dma_attested": False,
        "requested_count": 1024,
        "libcuda_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
        "module_path": "/tmp/hybrid_probe.fatbin",
        "sm70_name": "NVIDIA Tesla V100",
        "sm120_name": "NVIDIA RTX 5080",
        "sm70_pci_bus_id": "0000:01:00.0",
        "sm120_pci_bus_id": "0000:02:00.0",
        "cleanup_passed": all(item["cleanup_passed"] for item in directions),
        "directions": directions,
        "error": "",
    }


class VmmPeerProbeContractTests(unittest.TestCase):
    def test_accepts_bidirectional_numeric_vmm_peer_reads_without_route_claim(self):
        validate_vmm_peer_report(report(), {70: "0000:01:00.0", 120: "0000:02:00.0"})

    def test_classic_peer_capability_is_reported_but_not_required(self):
        value = report()
        for item in value["directions"]:
            item["peer_capability"] = False
        validate_vmm_peer_report(value)

    def test_accepts_one_way_vmm_read(self):
        value = report("one-way-vmm-peer-memory-verified", False,
                       [direction(70, 120), direction(120, 70, False)])
        validate_vmm_peer_report(value)

    def test_accepts_clean_preflight_failure(self):
        value = {"schema": "nvidia-hybrid-vmm-peer-probe-v1",
                 "status": "preflight-failed", "passed": False,
                 "direct_dma_attested": False, "directions": [],
                 "error": "expected devices absent"}
        validate_vmm_peer_report(value)

    def test_rejects_claimed_dma_route(self):
        value = report()
        value["direct_dma_attested"] = True
        with self.assertRaisesRegex(ValueError, "cannot attest"):
            validate_vmm_peer_report(value)

    def test_rejects_success_without_both_directions(self):
        value = report()
        value["directions"].pop()
        with self.assertRaisesRegex(ValueError, "both verified directions"):
            validate_vmm_peer_report(value)

    def test_rejects_kernel_success_without_destination_permission(self):
        value = report()
        value["directions"][0]["destination_readonly_access_verified"] = False
        with self.assertRaisesRegex(ValueError, "lacks allocation or permission"):
            validate_vmm_peer_report(value)

    def test_rejects_attempt_before_permission_verification(self):
        value = report()
        value["directions"][0]["kernel_passed"] = False
        value["directions"][0]["source_access_verified"] = False
        value["status"] = "vmm-peer-memory-failed"
        value["passed"] = False
        with self.assertRaisesRegex(ValueError, "attempt lacks verified"):
            validate_vmm_peer_report(value)

    def test_rejects_cleanup_claim_with_error(self):
        value = report()
        value["directions"][0]["cleanup_errors"] = ["cuMemUnmap failed"]
        with self.assertRaisesRegex(ValueError, "cleanup claims success"):
            validate_vmm_peer_report(value)

    def test_rejects_cleanup_failure_without_evidence(self):
        value = report()
        value["directions"][0]["kernel_passed"] = False
        value["directions"][0]["cleanup_passed"] = False
        value["cleanup_passed"] = False
        value["status"] = "vmm-peer-memory-failed"
        value["passed"] = False
        with self.assertRaisesRegex(ValueError, "lacks cleanup error evidence"):
            validate_vmm_peer_report(value)

    def test_preserves_kernel_success_when_cleanup_fails_but_fails_overall(self):
        value = report("vmm-peer-memory-failed", False)
        value["cleanup_passed"] = False
        for item in value["directions"]:
            item["cleanup_passed"] = False
            item["cleanup_errors"] = ["cuMemUnmap failed"]
        validate_vmm_peer_report(value)

    def test_rejects_duplicate_or_reversed_wrong_architecture_pair(self):
        value = report()
        value["directions"][1] = copy.deepcopy(value["directions"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_vmm_peer_report(value)

    def test_rejects_unpinned_pci_identity(self):
        value = report()
        with self.assertRaisesRegex(ValueError, "differ from pinned"):
            validate_vmm_peer_report(value, {70: "0000:09:00.0", 120: "0000:02:00.0"})

    def test_rejects_wrong_gpu_model_for_expected_compute_capability(self):
        value = report()
        value["sm120_name"] = "NVIDIA RTX 5090"
        with self.assertRaisesRegex(ValueError, "not identified as the expected RTX 5080"):
            validate_vmm_peer_report(value)

    def test_rejects_unknown_direction_field(self):
        value = report()
        value["directions"][0]["copy_passed"] = True
        with self.assertRaisesRegex(ValueError, "unexpected or missing"):
            validate_vmm_peer_report(value)


if __name__ == "__main__":
    unittest.main()
