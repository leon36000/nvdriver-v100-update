# SPDX-License-Identifier: MIT
"""Contract tests for fixed, redacted NV20_SUBDEVICE_0 payload observations."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hybrid_acceptance_subdevice_contract", ROOT / "tests/run_hybrid_acceptance.py")
assert SPEC is not None and SPEC.loader is not None
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCEPTANCE)


def observation(case: str = "valid") -> dict:
    payload = {"classPayloadBytes": 4, "subDeviceId": 0}
    packet = {
        "layout": "NVOS64", "hClass": 0x2080, "paramsSize": 0, "flags": 0,
        "status": 0, "hRootPresent": True, "hObjectParentPresent": True,
        "hObjectNewPresent": True, "pAllocParmsPresent": True,
        "pRightsRequestedPresent": False, "subdeviceAlloc": payload,
    }
    exit_packet = dict(packet)
    if case == "failed-status":
        exit_packet["status"] = 0x56
    row = {
        "tid": 123, "fd": 7, "fd_role": "control", "request": 0xC030462B,
        "packet_size": 48, "operation": "subdevice_alloc", "entry": packet,
        "exit": exit_packet, "syscall_return": 0,
    }
    result = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v20", "trace_complete": True,
        "child_exit_code": 0, "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
        "architecture": "x86_64", "pointer_bits": 64, "nested_pointers_read": True,
        "nested_pointer_scope": (
            "NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; handles omitted"),
        "payload_scope": "NV20_SUBDEVICE_0 fixed class parameters only; handles omitted",
        "subdevice_alloc_payload_snapshots_read": 2, "records": [row], "errors": [],
    }
    if case == "unredacted":
        packet["hRoot"] = 0xAABBCCDD
    elif case == "wrong-class":
        packet["hClass"] = 0x80
    elif case == "wrong-request":
        row["request"] = 0xC030462A
    elif case == "wrong-packet-size":
        row["packet_size"] = 64
    elif case == "bad-snapshot-count":
        result["subdevice_alloc_payload_snapshots_read"] = 1
    elif case == "failed-syscall":
        row["syscall_return"] = -1
    elif case == "failed-status":
        row["exit"]["status"] = 0x56
    elif case == "changed-payload":
        row["exit"]["subdeviceAlloc"] = {"classPayloadBytes": 4, "subDeviceId": 1}
    return result


class SubdeviceAllocContractTests(unittest.TestCase):
    def test_accepts_a_single_redacted_successful_fixed_payload(self):
        validate = getattr(ACCEPTANCE, "validate_subdevice_alloc_observation", None)
        self.assertTrue(callable(validate), "shared NV2080 observer contract is not implemented")
        self.assertEqual(validate(observation()), (True, 2))

    def test_rejects_unredacted_or_malformed_payloads_and_packets(self):
        validate = getattr(ACCEPTANCE, "validate_subdevice_alloc_observation", None)
        self.assertTrue(callable(validate), "shared NV2080 observer contract is not implemented")
        for case in ("unredacted", "wrong-class", "wrong-request", "wrong-packet-size",
                     "bad-snapshot-count", "failed-syscall", "failed-status", "changed-payload"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate(observation(case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
