# SPDX-License-Identifier: MIT
"""Contract tests for the fixed, redacted GT200_DEBUGGER allocation observer."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hybrid_acceptance_gt200_debugger_contract", ROOT / "tests/run_hybrid_acceptance.py")
assert SPEC is not None and SPEC.loader is not None
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCEPTANCE)


def observation(case: str = "valid") -> dict:
    payload = {
        "classPayloadBytes": 12,
        "obsoleteClientZero": True,
        "appClientPresent": True,
        "appClientMatchesRoot": True,
        "appClientMatchesParent": False,
        "appClientEqualsDebuggee": False,
        "debuggee3dHandlePresent": True,
        "appClientClassWithinRoot": {"resolution": "not-observed-live-object", "classId": None},
        "debuggee3dClassWithinRoot": {"resolution": "resolved", "classId": 0xCEC0},
        "debuggee3dParentClassWithinRoot": {"resolution": "resolved", "classId": 0xC96F},
        "parentClassWithinRoot": {"resolution": "resolved", "classId": 0x80},
    }
    packet = {
        "layout": "NVOS64", "hClass": 0x83DE, "paramsSize": 0, "flags": 0,
        "status": 0, "hRootPresent": True, "hObjectParentPresent": True,
        "hObjectNewPresent": True, "pAllocParmsPresent": True,
        "pRightsRequestedPresent": False, "debuggerAlloc": payload,
    }
    row = {
        "tid": 123, "fd": 7, "fd_role": "control", "request": 0xC030462B,
        "packet_size": 48, "operation": "gt200_debugger_alloc",
        "entry": copy.deepcopy(packet), "exit": copy.deepcopy(packet), "syscall_return": 0,
    }
    result = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v34", "trace_complete": True,
        "child_exit_code": 0, "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
        "architecture": "x86_64", "pointer_bits": 64, "nested_pointers_read": True,
        "nested_pointer_scope": (
            "exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; emits handle "
            "presence and within-root class relations including the debuggee direct-parent class; "
            "raw handles and addresses omitted"),
        "payload_scope": (
            "NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; "
            "raw handles, pointers, and payload bytes omitted"),
        "object_class_resolution_scope": (
            "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; "
            "lookup is keyed by NVOS64 root and handle and emits only object and direct-parent "
            "class IDs/presence; "
            "unresolved means no unique live object was observed"),
        "debugger_alloc_payload_snapshots_read": 2, "records": [row], "errors": [],
    }
    if case == "unredacted":
        row["entry"]["hObjectNew"] = 0xAABBCCDD
    elif case == "wrong-class":
        row["exit"]["hClass"] = 0x83DD
    elif case == "wrong-request":
        row["request"] = 0xC030462A
    elif case == "bad-snapshot-count":
        result["debugger_alloc_payload_snapshots_read"] = 1
    elif case == "failed-syscall":
        row["syscall_return"] = -5
    elif case == "failed-status":
        row["exit"]["status"] = 0x56
    elif case == "changed-payload":
        row["exit"]["debuggerAlloc"]["debuggee3dHandlePresent"] = False
    elif case == "invalid-class-ref":
        row["exit"]["debuggerAlloc"]["appClientClassWithinRoot"]["classId"] = 0x41
        row["exit"]["debuggerAlloc"]["appClientClassWithinRoot"]["resolution"] = "ambiguous"
    elif case == "invalid-parent-class-ref":
        row["entry"]["debuggerAlloc"]["debuggee3dParentClassWithinRoot"]["resolution"] = "resolved"
        row["entry"]["debuggerAlloc"]["debuggee3dParentClassWithinRoot"]["classId"] = None
    return result


def context_phase_report() -> dict:
    operations = ["cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                  "cuDeviceGetName", "cuDeviceGetPCIBusId",
                  "cuDeviceGetAttribute.major", "cuDeviceGetAttribute.minor",
                  "cuDeviceGetAttribute.concurrent_managed_access",
                  "cuDeviceGetAttribute.pageable_memory_access",
                  "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables",
                  "cuCtxCreate_v2", "cuCtxSetCurrent", "cuCtxGetDevice"]
    return {
        "schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
        "phase": "context", "expected_pci": "00000000:02:00.0",
        "driver_library_path": str(Path(sys.executable).resolve()), "driver_api": 13020,
        "selected_device": {
            "name": "fixture-SM120", "pci_bus_id": "0000:02:00.0", "sm": 120,
            "compute_capability": "12.0", "concurrent_managed_access": True,
            "pageable_memory_access": True,
            "pageable_memory_access_uses_host_page_tables": False,
        },
        "completed_operations": operations, "numeric_result_passed": False,
        "result_value": None, "expected_result": None, "cleanup_passed": True,
        "cleanup_errors": [], "error": "",
    }


class GT200DebuggerAllocContractTests(unittest.TestCase):
    def test_accepts_redacted_success_and_resolved_class_relations(self):
        validate = getattr(ACCEPTANCE, "validate_gt200_debugger_alloc_observation", None)
        self.assertTrue(callable(validate), "shared GT200_DEBUGGER observer contract is missing")
        self.assertEqual(validate(observation()), (True, 2))

    def test_rejects_unredacted_or_inconsistent_observations(self):
        validate = ACCEPTANCE.validate_gt200_debugger_alloc_observation
        for case in ("unredacted", "wrong-class", "wrong-request", "bad-snapshot-count",
                     "failed-syscall", "failed-status", "changed-payload", "invalid-class-ref",
                     "invalid-parent-class-ref"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate(observation(case))

    def test_direct_acceptance_runner_forwards_isolated_capture_and_archives_contract(self):
        runner = ROOT / "tests/run_hybrid_acceptance_fixture_cli.py"
        probe_report = context_phase_report()
        observed = observation()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" +
                             repr(json.dumps(probe_report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only fixture")
            observer.write_text(
                "#!" + sys.executable + "\nimport json,subprocess,sys\n"
                "from pathlib import Path\nargs=sys.argv[1:]\n"
                "assert '--gt200-debugger-alloc' in args\n"
                "assert '--device-alloc' not in args and '--ioctl-trace' not in args\n"
                "assert args[args.index('--gpu-path')+1] == '/dev/nvidia0'\n"
                "Path(args[args.index('--output')+1]).write_text(" +
                repr(json.dumps(observed)) + ")\n"
                "raise SystemExit(subprocess.run(args[args.index('--')+1:], check=False).returncode)\n")
            observer.chmod(0o700)
            evidence_dir = root / "evidence"
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--ioctl-observer", str(observer), "--gt200-debugger-alloc",
                "--phase", "context", "--expected-pci", "0000:02:00.0",
                "--gpu-path", "/dev/nvidia0", "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            report = json.loads(next(evidence_dir.glob("hardware-probe-*.json")).read_text())
            self.assertEqual(report["report_contract_qualification"], "phase-report-contract-pass")
            self.assertEqual(report["qualification"], "untrusted-probe-artifact")
            self.assertTrue(report["gt200_debugger_alloc_capture_requested"])
            self.assertTrue(report["gt200_debugger_alloc_records_seen"])
            self.assertEqual(report["gt200_debugger_alloc_payload_snapshots_read"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
