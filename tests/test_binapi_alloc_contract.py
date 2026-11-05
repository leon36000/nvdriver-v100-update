# SPDX-License-Identifier: MIT
"""Contract tests for fixed, redacted NV2081_BINAPI allocation payloads."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hybrid_acceptance_binapi_alloc_contract", ROOT / "tests/run_hybrid_acceptance.py")
assert SPEC is not None and SPEC.loader is not None
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCEPTANCE)


def observation(case: str = "valid") -> dict:
    payload = {"classPayloadBytes": 4, "reservedZero": True}
    packet = {
        "layout": "NVOS64", "hClass": 0x2081, "paramsSize": 0, "flags": 0,
        "status": 0, "hRootPresent": True, "hObjectParentPresent": True,
        "hObjectNewPresent": True, "pAllocParmsPresent": True,
        "pRightsRequestedPresent": False, "binapiAlloc": payload,
    }
    exit_packet = dict(packet)
    if case == "changed-payload":
        exit_packet["binapiAlloc"] = {"classPayloadBytes": 4, "reservedZero": False}
    row = {
        "tid": 123, "fd": 7, "fd_role": "control", "request": 0xC030462B,
        "packet_size": 48, "operation": "binapi_alloc", "entry": packet,
        "exit": exit_packet, "syscall_return": 0,
    }
    result = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v21", "trace_complete": True,
        "child_exit_code": 0, "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
        "architecture": "x86_64", "pointer_bits": 64, "nested_pointers_read": True,
        "nested_pointer_scope": (
            "NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; handles omitted"),
        "payload_scope": "NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted",
        "binapi_alloc_payload_snapshots_read": 2, "records": [row], "errors": [],
    }
    if case == "optional-absent":
        packet["pAllocParmsPresent"] = False
        packet["binapiAlloc"] = None
        exit_packet["pAllocParmsPresent"] = False
        exit_packet["binapiAlloc"] = None
        result["binapi_alloc_payload_snapshots_read"] = 0
        result["nested_pointers_read"] = False
    elif case == "nonzero-reserved":
        packet["binapiAlloc"]["reservedZero"] = False
        exit_packet["binapiAlloc"]["reservedZero"] = False
    elif case == "failed-status":
        exit_packet["status"] = 0x56
    elif case == "unredacted":
        packet["hRoot"] = 0xAABBCCDD
    elif case == "wrong-class":
        packet["hClass"] = 0x2080
    elif case == "wrong-request":
        row["request"] = 0xC030462A
    elif case == "bad-snapshot-count":
        result["binapi_alloc_payload_snapshots_read"] = 1
    elif case == "failed-syscall":
        row["syscall_return"] = -1
    elif case == "raw-reserved":
        packet["binapiAlloc"]["reserved"] = 0
    return result


class BinapiAllocContractTests(unittest.TestCase):
    def test_accepts_fixed_redacted_payload_and_optional_absence(self):
        validate = getattr(ACCEPTANCE, "validate_binapi_alloc_observation", None)
        self.assertTrue(callable(validate), "shared NV2081 observer contract is not implemented")
        self.assertEqual(validate(observation()), (True, 2))
        self.assertEqual(validate(observation("optional-absent")), (True, 0))

    def test_reserved_value_is_only_a_zero_predicate(self):
        validate = getattr(ACCEPTANCE, "validate_binapi_alloc_observation", None)
        self.assertTrue(callable(validate), "shared NV2081 observer contract is not implemented")
        self.assertEqual(validate(observation("nonzero-reserved")), (True, 2))
        with self.assertRaises(ValueError):
            validate(observation("raw-reserved"))

    def test_rejects_malformed_or_unsuccessful_allocations(self):
        validate = getattr(ACCEPTANCE, "validate_binapi_alloc_observation", None)
        self.assertTrue(callable(validate), "shared NV2081 observer contract is not implemented")
        for case in ("unredacted", "wrong-class", "wrong-request", "bad-snapshot-count",
                     "failed-syscall", "failed-status", "changed-payload"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate(observation(case))


if __name__ == "__main__":
    unittest.main(verbosity=2)
