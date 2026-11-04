#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only acceptance contracts for the guarded PC3 V100 guest runner."""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/run_pc3_v100_guest_reference.py"


def phase_report(phase="kernel", pci="0000:81:00.0", sm=70):
    operations = ["cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                  "cuDeviceGetName", "cuDeviceGetPCIBusId",
                  "cuDeviceGetAttribute.major", "cuDeviceGetAttribute.minor"]
    selected = None
    if phase != "initialize":
        selected = {"name": "Tesla V100-SXM2-16GB", "pci_bus_id": pci, "sm": sm,
                    "compute_capability": "7.0"}
    if phase == "initialize":
        operations = ["cuInit"]
    elif phase != "enumerate":
        operations += ["cuCtxCreate_v2", "cuCtxSetCurrent", "cuCtxGetDevice"]
        if phase == "allocation":
            operations += ["cuMemAlloc_v2"]
        elif phase in ("module", "kernel"):
            operations += ["cuModuleLoad", "cuModuleGetFunction(hybrid_arch)"]
            if phase == "kernel":
                operations += ["cuMemAlloc_v2", "cuLaunchKernel(hybrid_arch)",
                               "cuCtxSynchronize", "cuMemcpyDtoH_v2"]
    is_kernel = phase == "kernel"
    return {"schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
            "phase": phase, "expected_pci": "00000000:" + pci.split(":", 1)[1],
            "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
            "driver_api": None if phase == "initialize" else 13000,
            "selected_device": selected, "completed_operations": operations,
            "numeric_result_passed": is_kernel,
            "result_value": 700 if is_kernel else None,
            "expected_result": 700 if is_kernel else None,
            "cleanup_passed": True, "cleanup_errors": [], "error": ""}


class RunnerAvailability(unittest.TestCase):
    def test_v100_guest_runner_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "guarded PC3 V100 guest runner is missing")


if TOOL_PATH.is_file():
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference", TOOL_PATH)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)

    class CredentialParsing(unittest.TestCase):
        def test_reads_only_pc3_sudo_value(self):
            value = tool.parse_pc3_sudo_secret("[pc2]\npassword_sudo=other\n[pc3]\npassword_sudo=pc3-secret\n")
            self.assertEqual(value, "pc3-secret")

        def test_missing_pc3_secret_is_rejected_without_echo(self):
            with self.assertRaises(ValueError) as error:
                tool.parse_pc3_sudo_secret("[pc4]\npassword_sudo=hidden\n")
            self.assertNotIn("hidden", str(error.exception))

        def test_newline_in_secret_is_rejected_without_echo(self):
            with self.assertRaises(ValueError) as error:
                tool.validate_sudo_secret("secret\nextra")
            self.assertNotIn("secret", str(error.exception))

        def test_secret_is_redacted_recursively_from_evidence(self):
            value = tool.redact_nested({"stdout": ["credential=abc123"]}, "abc123")
            self.assertEqual(value, {"stdout": ["credential=[REDACTED]"]})

    class V100ProbeGate(unittest.TestCase):
        def make_report(self):
            return {
                "schema": "nvidia-hybrid-probe-v2",
                "status": "control-passed",
                "memory_mode": "device",
                "managed_prefetch_requested": False,
                "managed_prefetch_api": "not-requested",
                "cuda_graphs_requested": False,
                "cuda_graph_api": "not-requested",
                "cuda_graph_api": "not-requested",
                "hybrid_validated": False,
                "required_set_passed": True,
                "context_coexistence_passed": False,
                "execution_mode": "resident-contexts-sequential-kernels",
                "concurrent_kernel_execution_validated": False,
                "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
                "driver_api": 13000,
                "required_sm": [70],
                "missing_sm": [],
                "devices": [{
                    "ordinal": 0,
                    "name": "Tesla V100-SXM2-16GB",
                    "pci_bus_id": "0000:81:00.0",
                    "compute_capability": "7.0",
                    "sm": 70,
                    "targeted": True,
                    "tested": True,
                    "architecture_kernel_passed": True,
                    "synchronous_passed": True,
                    "synchronous_sizes": [1, 31, 256, 4096, 65537],
                    "asynchronous_passed": True,
                    "asynchronous_sizes": [1, 31, 256, 4096, 65537],
                    "managed_memory_passed": False,
                    "managed_prefetch_passed": False,
                    "cuda_graphs_passed": False,
                    "cuda_graph_launches": 0,
                    "cuda_graph_launches": 0,
                    "cleanup_passed": True,
                    "cleanup_errors": [],
                    "error": "",
                }],
            }

        def test_accepts_sm70_reference_without_claiming_hybrid(self):
            result = tool.validate_v100_reference(self.make_report(), 0, "0000:81:00.0")
            self.assertEqual(result, "v100-reference-validated")

        def test_phase_gate_uses_the_shared_phase_contract(self):
            result = tool.validate_cuda_phase_report(
                phase_report("kernel"), 0, "0000:81:00.0", "kernel")
            self.assertEqual(result, "phase-observed-on-hardware")
            wrong_sm = phase_report("kernel", sm=120)
            with self.assertRaises(ValueError):
                tool.validate_cuda_phase_report(wrong_sm, 0, "0000:81:00.0", "kernel")

        def test_remote_phase_acceptance_is_distinct_from_the_sm70_reference(self):
            remote, expected = self.binapi_control_remote(present=False)
            remote["phase_capture_requested"] = True
            remote["phase"] = "kernel"
            remote["probe"] = phase_report("kernel")
            remote["probe_exit_code"] = 0
            remote["driver_library"] = {"path": remote["probe"]["driver_library_path"],
                                         "bytes": 12, "sha256": "b" * 64}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rm_control_requested=True,
                binapi_control_requested=True, phase="kernel"),
                "v100-cuda-phase-validated")
            remote["probe"]["selected_device"]["sm"] = 120
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(remote, expected,
                    rm_control_requested=True, binapi_control_requested=True,
                    phase="kernel")

        def test_remote_phase_accepts_validated_nv0080_capture(self):
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote.update({"observer_exit_code": 0, "phase_capture_requested": True,
                           "phase": "context", "probe_exit_code": 0,
                           "device_alloc_capture_requested": True,
                           "device_alloc_records_seen": True,
                           "device_alloc_payload_snapshots_read": 2,
                           "gpu_id_info_records_seen": False,
                           "attached_ids_records_seen": False,
                           "probed_ids_records_seen": False,
                           "channel_alloc_records_seen": False,
                           "map_memory_records_seen": False,
                           "rusd_alloc_records_seen": False,
                           "p2p_alloc_records_seen": False,
                           "p2p_control_records_seen": False,
                           "binapi_control_records_seen": False,
                           "rm_control_records_seen": None})
            remote["probe"] = phase_report("context")
            remote["driver_library"] = {"path": remote["probe"]["driver_library_path"],
                                         "bytes": 12, "sha256": "b" * 64}
            payload = {"classPayloadBytes": 56, "deviceId": 0,
                       "hClientShare": "same-as-root", "targetClientZero": True,
                       "targetDeviceZero": True, "flags": 0x403,
                       "vaSpaceSize": 0x123000, "vaStartInternalZero": False,
                       "vaLimitInternalZero": False, "vaMode": 2}
            packet = {"layout": "NVOS64", "hClass": 128, "paramsSize": 56,
                      "flags": 0, "status": 0, "hRootPresent": True,
                      "hObjectParentPresent": True, "hObjectNewPresent": True,
                      "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                      "deviceAlloc": payload}
            scope = ("NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; "
                     "client handles are relational booleans; internal VA addresses are omitted")
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v19", "trace_complete": True,
                "child_exit_code": 0, "control_path": "/dev/nvidiactl",
                "gpu_path": "/dev/nvidia0", "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": True, "nested_pointer_scope": scope,
                "payload_scope": ("NV01_DEVICE_0 fixed class parameters only; handles are redacted "
                                  "and internal VA addresses are omitted"),
                "fd_identity_tracking": False, "device_alloc_payload_snapshots_read": 2,
                "errors": [], "records": [{"tid": 1234, "fd": 7, "fd_role": "control",
                    "request": 0xc020462a, "packet_size": 64, "operation": "device_alloc",
                    "entry": packet, "exit": packet, "syscall_return": 0}],
            }
            expected = {"probe": {"bytes": 3, "sha256": "a" * 64},
                        "module": {"bytes": 3, "sha256": "a" * 64},
                        "observer": {"bytes": 4, "sha256": "c" * 64}}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, device_alloc_requested=True, phase="context"),
                "v100-cuda-phase-validated")

            remote["ioctl_observation"]["records"][0]["entry"]["deviceAlloc"]["rawHandle"] = 7
            with self.assertRaisesRegex(ValueError, "unredacted"):
                tool.validate_remote_acceptance(
                    remote, expected, device_alloc_requested=True, phase="context")

        def test_remote_phase_accepts_validated_nv2080_capture(self):
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote.update({"observer_exit_code": 0, "phase_capture_requested": True,
                           "phase": "context", "probe_exit_code": 0,
                           "subdevice_alloc_capture_requested": True,
                           "subdevice_alloc_records_seen": True,
                           "subdevice_alloc_payload_snapshots_read": 2,
                           "gpu_id_info_records_seen": False,
                           "attached_ids_records_seen": False,
                           "probed_ids_records_seen": False,
                           "channel_alloc_records_seen": False,
                           "map_memory_records_seen": False,
                           "rusd_alloc_records_seen": False,
                           "p2p_alloc_records_seen": False,
                           "p2p_control_records_seen": False,
                           "binapi_control_records_seen": False,
                           "rm_control_records_seen": None})
            remote["probe"] = phase_report("context")
            remote["driver_library"] = {"path": remote["probe"]["driver_library_path"],
                                         "bytes": 12, "sha256": "b" * 64}
            payload = {"classPayloadBytes": 4, "subDeviceId": 0}
            packet = {"layout": "NVOS64", "hClass": 0x2080, "paramsSize": 0,
                      "flags": 0, "status": 0, "hRootPresent": True,
                      "hObjectParentPresent": True, "hObjectNewPresent": True,
                      "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                      "subdeviceAlloc": payload}
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v20", "trace_complete": True,
                "child_exit_code": 0, "control_path": "/dev/nvidiactl",
                "gpu_path": "/dev/nvidia0", "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": True,
                "nested_pointer_scope": ("NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed "
                                         "4-byte subDeviceId only; handles omitted"),
                "payload_scope": "NV20_SUBDEVICE_0 fixed class parameters only; handles omitted",
                "fd_identity_tracking": False, "subdevice_alloc_payload_snapshots_read": 2,
                "errors": [], "records": [{"tid": 1234, "fd": 7, "fd_role": "control",
                    "request": 0xc030462b, "packet_size": 48,
                    "operation": "subdevice_alloc", "entry": packet,
                    "exit": packet, "syscall_return": 0}],
            }
            expected = {"probe": {"bytes": 3, "sha256": "a" * 64},
                        "module": {"bytes": 3, "sha256": "a" * 64},
                        "observer": {"bytes": 4, "sha256": "c" * 64}}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, subdevice_alloc_requested=True, phase="context"),
                "v100-cuda-phase-validated")

        def test_remote_phase_accepts_redacted_nv2081_allocation(self):
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote.update({"observer_exit_code": 0, "phase_capture_requested": True,
                           "phase": "context", "probe_exit_code": 0,
                           "binapi_alloc_capture_requested": True,
                           "binapi_alloc_records_seen": True,
                           "binapi_alloc_payload_snapshots_read": 2,
                           "gpu_id_info_records_seen": False,
                           "attached_ids_records_seen": False,
                           "probed_ids_records_seen": False,
                           "channel_alloc_records_seen": False,
                           "map_memory_records_seen": False,
                           "rusd_alloc_records_seen": False,
                           "p2p_alloc_records_seen": False,
                           "p2p_control_records_seen": False,
                           "binapi_control_records_seen": False,
                           "rm_control_records_seen": None})
            remote["probe"] = phase_report("context")
            remote["driver_library"] = {"path": remote["probe"]["driver_library_path"],
                                         "bytes": 12, "sha256": "b" * 64}
            packet = {"layout": "NVOS64", "hClass": 0x2081, "paramsSize": 0,
                      "flags": 0, "status": 0, "hRootPresent": True,
                      "hObjectParentPresent": True, "hObjectNewPresent": True,
                      "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                      "binapiAlloc": {"classPayloadBytes": 4, "reservedZero": True}}
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v21", "trace_complete": True,
                "child_exit_code": 0, "control_path": "/dev/nvidiactl",
                "gpu_path": "/dev/nvidia0", "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": True,
                "nested_pointer_scope": ("NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed "
                                         "4-byte reserved zero predicate only; handles omitted"),
                "payload_scope": ("NV2081_BINAPI fixed class parameters only; raw reserved value, "
                                 "handles omitted"),
                "fd_identity_tracking": False, "binapi_alloc_payload_snapshots_read": 2,
                "errors": [], "records": [{"tid": 1234, "fd": 7, "fd_role": "control",
                    "request": 0xc030462b, "packet_size": 48,
                    "operation": "binapi_alloc", "entry": packet,
                    "exit": packet, "syscall_return": 0}],
            }
            expected = {"probe": {"bytes": 3, "sha256": "a" * 64},
                        "module": {"bytes": 3, "sha256": "a" * 64},
                        "observer": {"bytes": 4, "sha256": "c" * 64}}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, binapi_alloc_requested=True, phase="context"),
                "v100-cuda-phase-validated")

        def test_phase_cli_accepts_exactly_one_isolated_observer(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-phase-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                with self.assertRaises(SystemExit) as missing:
                    tool.parse_args(["--phase", "kernel", "--evidence",
                                     str(root / "missing.json")])
                self.assertEqual(missing.exception.code, 2)
                args = tool.parse_args(["--phase", "kernel", "--probe", str(probe),
                                        "--module", str(module), "--ioctl-observer", str(observer),
                                        "--rm-control", "--binapi-control", "--evidence",
                                        str(root / "phase.json")])
                report = tool.report_path(args)
                self.assertTrue(report["phase_capture_requested"])
                self.assertEqual(report["phase"], "kernel")
                device_args = tool.parse_args(["--phase", "context", "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--device-alloc", "--evidence", str(root / "device-alloc.json")])
                self.assertTrue(tool.report_path(device_args)["phase_capture_requested"])
                subdevice_args = tool.parse_args(["--phase", "context", "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--subdevice-alloc", "--evidence", str(root / "subdevice-alloc.json")])
                self.assertTrue(tool.report_path(subdevice_args)["subdevice_alloc_capture_requested"])
                binapi_alloc_args = tool.parse_args(["--phase", "context", "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--binapi-alloc", "--evidence", str(root / "binapi-alloc.json")])
                self.assertTrue(tool.report_path(binapi_alloc_args)["binapi_alloc_capture_requested"])
                with self.assertRaises(SystemExit) as both:
                    tool.parse_args(["--phase", "context", "--probe", str(probe),
                        "--module", str(module), "--ioctl-observer", str(observer),
                        "--rm-control", "--binapi-control", "--device-alloc",
                        "--evidence", str(root / "both.json")])
                self.assertEqual(both.exception.code, 2)
                with self.assertRaises(SystemExit) as mixed_allocation_classes:
                    tool.parse_args(["--phase", "context", "--probe", str(probe),
                        "--module", str(module), "--ioctl-observer", str(observer),
                        "--subdevice-alloc", "--device-alloc",
                        "--evidence", str(root / "mixed-alloc.json")])
                self.assertEqual(mixed_allocation_classes.exception.code, 2)
                with self.assertRaises(SystemExit) as mixed:
                    tool.parse_args(["--phase", "kernel", "--probe", str(probe),
                                     "--module", str(module), "--ioctl-observer", str(observer),
                                     "--rm-control", "--binapi-control", "--gpu-id-info",
                                     "--evidence", str(root / "mixed.json")])
                self.assertEqual(mixed.exception.code, 2)
                with self.assertRaises(SystemExit) as graphs_mixed:
                    tool.parse_args(["--phase", "kernel", "--probe", str(probe),
                                     "--module", str(module), "--ioctl-observer", str(observer),
                                     "--device-alloc", "--cuda-graphs",
                                     "--evidence", str(root / "graphs-mixed.json")])
                self.assertEqual(graphs_mixed.exception.code, 2)

        def test_managed_memory_reference_requires_a_real_managed_memory_pass(self):
            report = self.make_report()
            report["memory_mode"] = "managed"
            report["devices"][0]["managed_memory_passed"] = True
            result = tool.validate_v100_reference(report, 0, "0000:81:00.0", managed_memory=True)
            self.assertEqual(result, "v100-reference-validated")
            report["devices"][0]["managed_memory_passed"] = False
            with self.assertRaises(ValueError):
                tool.validate_v100_reference(report, 0, "0000:81:00.0", managed_memory=True)

        def test_managed_prefetch_reference_requires_a_real_prefetch_pass(self):
            report = self.make_report()
            report["memory_mode"] = "managed"
            report["managed_prefetch_requested"] = True
            report["managed_prefetch_api"] = "cuMemPrefetchAsync_v2"
            report["devices"][0]["managed_memory_passed"] = True
            report["devices"][0]["managed_prefetch_passed"] = True
            result = tool.validate_v100_reference(
                report, 0, "0000:81:00.0", managed_memory=True, managed_prefetch=True)
            self.assertEqual(result, "v100-reference-validated")
            report["devices"][0]["managed_prefetch_passed"] = False
            with self.assertRaisesRegex(ValueError, "prefetch"):
                tool.validate_v100_reference(
                    report, 0, "0000:81:00.0", managed_memory=True, managed_prefetch=True)

        def test_cuda_graph_reference_requires_two_completed_numeric_replays(self):
            report = self.make_report()
            report["cuda_graphs_requested"] = True
            report["cuda_graph_api"] = "cuGraphInstantiateWithFlags"
            report["devices"][0]["cuda_graphs_passed"] = True
            report["devices"][0]["cuda_graph_launches"] = 2
            self.assertEqual(tool.validate_v100_reference(
                report, 0, "0000:81:00.0", cuda_graphs=True),
                "v100-reference-validated")
            report["devices"][0]["cuda_graph_launches"] = 1
            with self.assertRaisesRegex(ValueError, "replay count"):
                tool.validate_v100_reference(
                    report, 0, "0000:81:00.0", cuda_graphs=True)

        def test_rejects_a_hybrid_claim_from_single_gpu_reference(self):
            report = self.make_report()
            report["hybrid_validated"] = True
            with self.assertRaises(ValueError):
                tool.validate_v100_reference(report, 0, "0000:81:00.0")

        def test_rejects_incomplete_async_sizes(self):
            report = self.make_report()
            report["devices"][0]["asynchronous_sizes"] = [1, 31, 256]
            with self.assertRaises(ValueError):
                tool.validate_v100_reference(report, 0, "0000:81:00.0")

        def test_rejects_mismatched_pci_identity(self):
            with self.assertRaises(ValueError):
                tool.validate_v100_reference(self.make_report(), 0, "0000:82:00.0")

        def make_remote(self):
            probe = self.make_report()
            artifact = {"bytes": 3, "sha256": "a" * 64}
            return {
                "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
                "host": "pc3", "host_kernel_release": "7.0.0-38-generic",
                "memory_mode": "device",
                "managed_prefetch_requested": False,
                "cuda_graphs_requested": False,
                "qualification": "probe-executed", "guest_cleanup_passed": True,
                "payload_file_cleanup_passed": True,
                "execution_scope": {"guest_driver_changed": False, "module_loaded": False,
                                    "vm_management_issued": False, "pci_binding_changed": False},
                "guest": {"hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
                          "name": "Tesla V100-SXM2-16GB", "uuid": "GPU-12345678-1234-1234-1234-123456789abc",
                          "pci": "0000:81:00.0", "driver_version": "580.178.04"},
                "guest_after": {"memory_used_mib": "0"}, "probe_exit_code": 0, "probe": probe,
                "driver_library": {"path": probe["driver_library_path"], "bytes": 1234, "sha256": "b" * 64},
                "artifacts_before": {name: {**artifact, "guest_path": f"/tmp/codex-v100-ref-{name}"}
                                     for name in ("probe", "module")},
                "artifacts_after": {f"/tmp/codex-v100-ref-{name}": artifact
                                    for name in ("probe", "module")},
            }

        def test_accepts_complete_cross_checked_remote_reference(self):
            expected = {name: {"bytes": 3, "sha256": "a" * 64} for name in ("probe", "module")}
            self.assertEqual(tool.validate_remote_acceptance(self.make_remote(), expected),
                             "v100-reference-validated")

        def test_rejects_remote_runner_failure_even_when_probe_json_passes(self):
            remote = self.make_remote()
            remote["failure_stage"] = "post_probe_inventory"
            expected = {name: {"bytes": 3, "sha256": "a" * 64} for name in ("probe", "module")}
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(remote, expected)

        def test_rejects_observer_trace_that_reads_nested_pointers(self):
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v1",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "fd_identity_tracking": False, "errors": [], "records": [{"operation": "alloc"}],
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(remote, expected)

        def test_accepts_hash_cross_checked_ioctl_observer_trace(self):
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            remote["gpu_id_info_records_seen"] = False
            remote["attached_ids_records_seen"] = False
            remote["probed_ids_records_seen"] = False
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v1",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": False,
                "fd_identity_tracking": False, "errors": [],
                "records": [{
                    "operation": "alloc", "packet_size": 48,
                    "entry": {"layout": "NVOS64", "hClass": 0,
                              "pAllocParms": 0, "pRightsRequested": 0,
                              "paramsSize": 0, "flags": 0},
                    "exit": {"hClass": 65}, "syscall_return": 0,
                }],
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            self.assertEqual(tool.validate_remote_acceptance(remote, expected),
                             "v100-reference-validated")

        def attached_ids_remote(self, gpu_id_info=False):
            remote = self.make_remote()
            remote["gpu_id_info_capture_requested"] = gpu_id_info
            remote["gpu_id_info_records_seen"] = gpu_id_info
            remote["attached_ids_capture_requested"] = True
            remote["probed_ids_capture_requested"] = False
            remote["probed_ids_records_seen"] = False
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            remote["attached_ids_records_seen"] = True
            if gpu_id_info:
                scope = ("exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 and "
                         "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payloads only; addresses omitted")
                records = [
                    {"operation": "gpu_id_info_v2", "command": 0x205,
                     "gpuId": 5, "status": 0},
                    {"operation": "gpu_attached_ids", "command": 0x201,
                     "gpu_ids": [5], "params_size": 128},
                ]
            else:
                scope = "exact NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payload only; addresses omitted"
                records = [{"operation": "gpu_attached_ids", "command": 0x201,
                            "gpu_ids": [5], "params_size": 128}]
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v4",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "nested_pointer_scope": scope,
                "fd_identity_tracking": False, "errors": [],
                "records": records,
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_accepts_hash_cross_checked_attached_ids_capture(self):
            remote, expected = self.attached_ids_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, attached_ids_requested=True), "v100-reference-validated")

        def test_accepts_cross_checked_gpu_id_info_and_attached_ids(self):
            remote, expected = self.attached_ids_remote(gpu_id_info=True)
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, gpu_id_info_requested=True,
                attached_ids_requested=True), "v100-reference-validated")

        def test_attached_ids_capture_requires_exact_scope_and_trace_summary(self):
            remote, expected = self.attached_ids_remote()
            remote["ioctl_observation"]["nested_pointer_scope"] = "all nested pointers"
            with self.assertRaisesRegex(ValueError, "outside the requested metadata payloads"):
                tool.validate_remote_acceptance(remote, expected, attached_ids_requested=True)
            remote, expected = self.attached_ids_remote()
            remote["attached_ids_records_seen"] = False
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(remote, expected, attached_ids_requested=True)

        def probed_ids_remote(self):
            remote, expected = self.rm_control_remote()
            remote["gpu_id_info_capture_requested"] = True
            remote["gpu_id_info_records_seen"] = True
            remote["attached_ids_capture_requested"] = True
            remote["attached_ids_records_seen"] = True
            remote["probed_ids_capture_requested"] = True
            remote["probed_ids_records_seen"] = True
            observed = remote["ioctl_observation"]
            observed["schema"] = "nvidia-hybrid-rm-ioctl-observer-v6"
            observed["nested_pointers_read"] = True
            observed["nested_pointer_scope"] = (
                "exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2, "
                "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS, and "
                "NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payloads only; addresses omitted")
            observed["payload_scope"] = (
                "RM_CONTROL headers plus explicitly selected fixed metadata payloads; "
                "other nested parameters omitted")
            observed["records"].extend([
                {"operation": "gpu_id_info_v2"},
                {"operation": "gpu_attached_ids"},
                {"operation": "gpu_probed_ids", "command": 0x214,
                 "params_size": 384, "gpuIds": [5],
                 "excludedGpuIds": [0xffffffff], "gpuFlags": [1]},
            ])
            return remote, expected

        def test_accepts_probed_ids_in_combined_metadata_capture(self):
            remote, expected = self.probed_ids_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, gpu_id_info_requested=True,
                attached_ids_requested=True, probed_ids_requested=True,
                rm_control_requested=True), "v100-reference-validated")

            remote, expected = self.probed_ids_remote()
            remote["ioctl_observation"]["nested_pointer_scope"] = "all nested pointers"
            with self.assertRaisesRegex(ValueError, "outside the requested metadata payloads"):
                tool.validate_remote_acceptance(
                    remote, expected, gpu_id_info_requested=True,
                    attached_ids_requested=True, probed_ids_requested=True,
                    rm_control_requested=True)

            remote, expected = self.probed_ids_remote()
            remote["ioctl_observation"]["records"] = [
                row for row in remote["ioctl_observation"]["records"]
                if row.get("operation") != "gpu_probed_ids"]
            remote["probed_ids_records_seen"] = False
            with self.assertRaisesRegex(ValueError, "contains no GPU_GET_PROBED_IDS"):
                tool.validate_remote_acceptance(
                    remote, expected, gpu_id_info_requested=True,
                    attached_ids_requested=True, probed_ids_requested=True,
                    rm_control_requested=True)

        def rm_control_remote(self, attached_ids=False):
            remote = self.make_remote()
            remote["rm_control_capture_requested"] = True
            remote["rm_control_records_seen"] = True
            remote["gpu_id_info_capture_requested"] = False
            remote["gpu_id_info_records_seen"] = False
            remote["attached_ids_capture_requested"] = attached_ids
            remote["attached_ids_records_seen"] = attached_ids
            remote["probed_ids_capture_requested"] = False
            remote["probed_ids_records_seen"] = False
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            records = [{"operation": "rm_control_header", "entry": {"command": 0x205},
                        "exit": {"command": 0x205, "status": 0}}]
            observation = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v5",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": attached_ids,
                "fd_identity_tracking": False, "errors": [],
            }
            if attached_ids:
                scope = "exact NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payload only; addresses omitted"
                observation["nested_pointer_scope"] = scope
                observation["payload_scope"] = (
                    "RM_CONTROL headers plus explicitly selected fixed metadata payloads; "
                    "other nested parameters omitted")
                records.append({"operation": "gpu_attached_ids", "exit": {"status": 0}})
            else:
                observation["payload_scope"] = (
                    "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted")
            observation["records"] = records
            remote["ioctl_observation"] = observation
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def p2p_control_remote(self):
            remote, expected = self.rm_control_remote()
            remote["p2p_control_capture_requested"] = True
            remote["p2p_control_records_seen"] = True
            scope = ("exact NV503C register/unregister VA-space, register/unregister vidmem, and "
                     "register-PID fixed parameter structures; raw addresses, handles, and VA-space tokens omitted")
            header = {
                "command": 0x503c0102, "flags": 0, "params_size": 16, "status": 0,
                "hClientPresent": True, "hObjectPresent": True,
                "client_object_equal": False,
                "client_matches_prior_root_allocation": False,
                "object_matches_prior_root_allocation": False,
                "objectClass": {"resolution": "resolved", "classId": 0x503c},
                "p2pControl": {"command": 0x503c0102, "payloadBytes": 16,
                               "payloadValid": True, "inputHandlePresent": True,
                               "vaSpaceTokenNonzeroAtSnapshot": False},
            }
            header_exit = copy.deepcopy(header)
            header_exit["p2pControl"]["vaSpaceTokenNonzeroAtSnapshot"] = True
            vidmem = {
                "command": 0x503c0104, "flags": 0, "params_size": 32, "status": 0,
                "hClientPresent": True, "hObjectPresent": True,
                "client_object_equal": False,
                "client_matches_prior_root_allocation": False,
                "object_matches_prior_root_allocation": False,
                "objectClass": {"resolution": "resolved", "classId": 0x503c},
                "p2pControl": {"command": 0x503c0104, "payloadBytes": 32,
                               "payloadValid": True, "inputHandlePresent": True,
                               "addressAligned64K": True, "sizeNonzero": True,
                               "sizeAligned64K": True, "offsetAligned64K": True,
                               "offsetAndSizeDoNotOverflow": True,
                               "addressAndSizeDoNotOverflow": True},
            }
            records = [
                {"tid": 1234, "fd": 7, "fd_role": "control", "request": 0xc020462a,
                 "packet_size": 32, "operation": "rm_control_header",
                 "entry": header, "exit": header_exit, "syscall_return": 0},
                {"tid": 1234, "fd": 7, "fd_role": "control", "request": 0xc01046d3,
                 "packet_size": 16, "operation": "rm_control_header",
                 "entry": vidmem, "exit": copy.deepcopy(vidmem), "syscall_return": 0},
            ]
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v17",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "nested_pointer_scope": scope,
                "payload_scope": (
                    "RM_CONTROL headers plus exact NV503C P2P control payloads; raw addresses, handles, "
                    "and VA-space tokens omitted; other nested parameter payloads omitted"),
                "p2p_control_payload_snapshots_read": 4,
                "fd_identity_tracking": False, "errors": [], "records": records,
            }
            return remote, expected

        def binapi_control_remote(self, *, present=True):
            remote, expected = self.rm_control_remote()
            remote["binapi_control_capture_requested"] = True
            remote["p2p_control_capture_requested"] = False
            remote["p2p_control_records_seen"] = False
            remote["binapi_control_records_seen"] = present
            remote["binapi_payload_snapshots_read"] = 2 if present else 0
            zero_changed = "00" * 124
            changed = "01" + ("00" * 123)
            nonzero = "01" + ("00" * 30)
            common_payload = {"payloadBytes": 992, "payloadValid": True,
                              "nonzeroU32Count": 1,
                              "nonzeroU32MaskLsbFirst": nonzero}
            entry = {"command": 0x20810108, "flags": 0, "params_size": 992,
                     "status": 0, "hClientPresent": True, "hObjectPresent": True,
                     "client_object_equal": False,
                     "client_matches_prior_root_allocation": False,
                     "object_matches_prior_root_allocation": False,
                     "objectClass": {"resolution": "resolved", "classId": 0x2081},
                     "binapiPayload": {**common_payload, "changedByteCount": 0,
                                       "changedByteMaskLsbFirst": zero_changed,
                                       "entryExitPayloadEqual": None}}
            exit_phase = copy.deepcopy(entry)
            exit_phase["binapiPayload"]["changedByteCount"] = 1
            exit_phase["binapiPayload"]["changedByteMaskLsbFirst"] = changed
            exit_phase["binapiPayload"]["entryExitPayloadEqual"] = False
            rows = ([{"tid": 1234, "fd": 7, "fd_role": "control",
                      "request": 0xc020462a, "packet_size": 32,
                      "operation": "binapi_control", "entry": entry,
                      "exit": exit_phase, "syscall_return": 0}] if present else [])
            observed = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v18",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
                "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": present,
                "fd_identity_tracking": False,
                "object_class_resolution_scope": (
                    "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly "
                    "selected control and GPU paths; keyed by root and handle; unresolved means "
                    "no unique live object was observed"),
                "binapi_payload_snapshots_read": 2 if present else 0,
                "payload_scope": (
                    "RM_CONTROL headers plus exact 992-byte NV2081_BINAPI payload-shape metadata; "
                    "contained pointers are never followed; raw bytes, addresses, and handles omitted"),
                "errors": [], "records": rows,
            }
            if present:
                observed["nested_pointer_scope"] = (
                    "exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; "
                    "no contained pointer is followed; raw bytes, addresses, and handles omitted")
            remote["rm_control_records_seen"] = present
            remote["ioctl_observation"] = observed
            return remote, expected

        def test_accepts_exact_redacted_nv2081_binapi_payload_shape_capture(self):
            remote, expected = self.binapi_control_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rm_control_requested=True,
                binapi_control_requested=True), "v100-reference-validated")

        def test_binapi_capture_rejects_bad_class_or_mask_count(self):
            remote, expected = self.binapi_control_remote()
            remote["ioctl_observation"]["records"][0]["entry"]["objectClass"]["classId"] = 0x80
            with self.assertRaisesRegex(ValueError, "live NV2081_BINAPI"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_requested=True,
                    binapi_control_requested=True)

            remote, expected = self.binapi_control_remote()
            remote["ioctl_observation"]["records"][0]["exit"]["binapiPayload"][
                "changedByteCount"] = 3
            with self.assertRaisesRegex(ValueError, "mask counts"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_requested=True,
                    binapi_control_requested=True)

        def test_accepts_complete_binapi_capture_with_no_observed_command(self):
            remote, expected = self.binapi_control_remote(present=False)
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rm_control_requested=True,
                binapi_control_requested=True), "v100-reference-validated")

        def test_binapi_capture_cli_requires_rm_control_and_observer(self):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                observer = root / "observer"
                observer.write_bytes(b"CPU observer fixture")
                evidence = root / "new.json"
                base = ["--binapi-control", "--evidence", str(evidence)]
                with self.assertRaises(SystemExit) as missing_observer:
                    tool.parse_args(base)
                self.assertEqual(missing_observer.exception.code, 2)
                with self.assertRaises(SystemExit) as missing_rm:
                    tool.parse_args([*base, "--ioctl-observer", str(observer)])
                self.assertEqual(missing_rm.exception.code, 2)
                args = tool.parse_args(["--rm-control", "--binapi-control",
                                        "--ioctl-observer", str(observer),
                                        "--evidence", str(evidence)])
                self.assertTrue(args.binapi_control)

        def test_accepts_exact_redacted_nv503c_control_payload_capture(self):
            remote, expected = self.p2p_control_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rm_control_requested=True,
                p2p_control_requested=True), "v100-reference-validated")

        def test_nv503c_control_capture_rejects_unredacted_or_invalid_payloads(self):
            remote, expected = self.p2p_control_remote()
            remote["ioctl_observation"]["records"][0]["entry"]["hClient"] = 17
            with self.assertRaisesRegex(ValueError, "malformed or unredacted"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_requested=True,
                    p2p_control_requested=True)

            remote, expected = self.p2p_control_remote()
            remote["ioctl_observation"]["records"][1]["exit"]["p2pControl"][
                "addressAligned64K"] = False
            with self.assertRaisesRegex(ValueError, "range violates"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_requested=True,
                    p2p_control_requested=True)

            remote, expected = self.p2p_control_remote()
            remote["ioctl_observation"]["records"][0]["entry"]["objectClass"][
                "classId"] = 0x80
            with self.assertRaisesRegex(ValueError, "malformed or unredacted"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_requested=True,
                    p2p_control_requested=True)

            remote, expected = self.p2p_control_remote()
            remote["ioctl_observation"]["records"][0]["exit"]["status"] = 8
            with self.assertRaisesRegex(ValueError, "embedded RM status"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_requested=True,
                    p2p_control_requested=True)

        def test_p2p_control_capture_requires_rm_control_and_observer(self):
            with tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / "new.json"
                result = subprocess.run([sys.executable, str(TOOL_PATH), "--p2p-control",
                                         "--ioctl-observer", "/dev/null",
                                         "--evidence", str(evidence)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--p2p-control requires --rm-control", result.stderr)

        def channel_alloc_remote(self):
            remote = self.make_remote()
            remote["channel_alloc_capture_requested"] = True
            remote["channel_alloc_records_seen"] = True
            remote["gpu_id_info_capture_requested"] = False
            remote["gpu_id_info_records_seen"] = False
            remote["attached_ids_capture_requested"] = False
            remote["attached_ids_records_seen"] = False
            remote["probed_ids_capture_requested"] = False
            remote["probed_ids_records_seen"] = False
            remote["rm_control_capture_requested"] = False
            remote["rm_control_records_seen"] = None
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            channel = {"classPayloadBytes": 368}
            records = [{"operation": "channel_alloc", "fd_role": "control",
                        "request": 0xc030462b,
                        "packet_size": 48, "syscall_return": 0,
                        "entry": {"hClass": 0xc36f,
                                  "channelPayloadState": "r580-r595-class-layout-parsed",
                                  "pAllocParmsPresent": True, "channel": channel},
                        "exit": {"hClass": 0xc36f,
                                 "channelPayloadState": "r580-r595-class-layout-parsed",
                                 "pAllocParmsPresent": True, "channel": channel}}]
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v9",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "nested_pointer_scope": (
                    "VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads "
                    "parsed using the byte-identical pinned R580.178.04/R595.99.02 "
                    "NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted"),
                "channel_payload_snapshots_read": 2,
                "gpu_path": "/dev/nvidia0",
                "object_class_resolution_scope":
                    "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed",
                "fd_identity_tracking": False, "errors": [], "records": records,
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_accepts_hash_cross_checked_r580_channel_payload_capture(self):
            remote, expected = self.channel_alloc_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, channel_alloc_requested=True),
                "v100-reference-validated")

        def rusd_alloc_remote(self):
            remote = self.make_remote()
            remote["rusd_alloc_capture_requested"] = True
            remote["rusd_alloc_records_seen"] = True
            remote["gpu_id_info_records_seen"] = False
            remote["attached_ids_records_seen"] = False
            remote["probed_ids_records_seen"] = False
            remote["map_memory_records_seen"] = False
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            scope = ("RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned "
                     "8-byte polledDataMask; raw addresses and handles omitted")
            def row(role, mask):
                packet = {"layout": "NVOS64", "hClass": 0xde, "paramsSize": 0,
                          "flags": 0, "status": 0, "hRootPresent": True,
                          "hObjectParentPresent": True, "hObjectNewPresent": True,
                          "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                          "rusdPayloadState": "r580-r595-class-layout-parsed",
                          "rusd": {"classPayloadBytes": 8, "polledDataMask": mask}}
                return {"tid": 1234, "fd": 7 if role == "control" else 9,
                        "fd_role": role, "request": 0xc030462b, "packet_size": 48,
                        "operation": "rusd_alloc", "entry": packet.copy(),
                        "exit": packet.copy(), "syscall_return": 0}
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v14",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
                "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": True, "nested_pointer_scope": scope,
                "rusd_payload_snapshots_read": 4, "fd_identity_tracking": False,
                "errors": [], "records": [row("control", 0), row("gpu", 4)],
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def p2p_alloc_remote(self):
            remote = self.make_remote()
            remote["p2p_alloc_capture_requested"] = True
            remote["p2p_alloc_records_seen"] = True
            remote["gpu_id_info_records_seen"] = False
            remote["attached_ids_records_seen"] = False
            remote["probed_ids_records_seen"] = False
            remote["map_memory_records_seen"] = False
            remote["rusd_alloc_records_seen"] = False
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            scope = ("NV50_THIRD_PARTY_P2P NV503C_ALLOC_PARAMETERS only, parsed as the pinned "
                     "4-byte flags word; raw addresses and handles omitted")
            payload = {"classPayloadBytes": 4, "flags": 0, "type": 0,
                       "typeName": "proprietary", "unknownFlagBits": 0}
            packet = {"layout": "NVOS64", "hClass": 0x503c, "paramsSize": 0,
                      "flags": 0, "status": 0, "hRootPresent": True,
                      "hObjectParentPresent": True, "hObjectNewPresent": True,
                      "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                      "p2pPayloadState": "r580-r595-class-layout-parsed",
                      "p2p": payload}
            row = {"tid": 1234, "fd": 7, "fd_role": "control",
                   "request": 0xc030462b, "packet_size": 48,
                   "operation": "p2p_alloc", "entry": copy.deepcopy(packet),
                   "exit": copy.deepcopy(packet), "syscall_return": 0}
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v16",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
                "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": True, "nested_pointer_scope": scope,
                "p2p_payload_snapshots_read": 2, "fd_identity_tracking": False,
                "errors": [], "records": [row],
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_accepts_exact_v100_p2p_allocation_flags(self):
            remote, expected = self.p2p_alloc_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, p2p_alloc_requested=True),
                "v100-reference-validated")
            self.assertEqual(remote["p2p_allocation_types"], ["proprietary"])

        def test_p2p_capture_rejects_wrong_class_payload_and_incomplete_snapshot(self):
            remote, expected = self.p2p_alloc_remote()
            exit_payload = remote["ioctl_observation"]["records"][0]["exit"]["p2p"]
            exit_payload.update({"flags": 1, "type": 1, "typeName": "bar1"})
            with self.assertRaisesRegex(ValueError, "flags changed"):
                tool.validate_remote_acceptance(remote, expected,
                                                p2p_alloc_requested=True)
            remote, expected = self.p2p_alloc_remote()
            remote["ioctl_observation"]["p2p_payload_snapshots_read"] = 1
            with self.assertRaisesRegex(ValueError, "snapshot count"):
                tool.validate_remote_acceptance(remote, expected,
                                                p2p_alloc_requested=True)

        def test_p2p_capture_requires_observer_and_isolated_mode(self):
            with tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / "new.json"
                result = subprocess.run([sys.executable, str(TOOL_PATH), "--p2p-alloc",
                                         "--evidence", str(evidence)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--p2p-alloc requires --ioctl-observer", result.stderr)

        def test_p2p_capture_rejects_nonzero_embedded_rm_status(self):
            remote, expected = self.p2p_alloc_remote()
            remote["ioctl_observation"]["records"][0]["exit"]["status"] = 0x56
            with self.assertRaisesRegex(ValueError, "embedded RM status"):
                tool.validate_remote_acceptance(remote, expected,
                                                p2p_alloc_requested=True)

        def test_accepts_exact_rusd_mask_capture_without_handle_or_address_disclosure(self):
            remote, expected = self.rusd_alloc_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rusd_alloc_requested=True),
                "v100-reference-validated")

        def test_rusd_capture_rejects_wrong_scope_and_bad_layout(self):
            remote, expected = self.rusd_alloc_remote()
            remote["ioctl_observation"]["nested_pointer_scope"] = "all allocations"
            with self.assertRaisesRegex(ValueError, "outside the requested"):
                tool.validate_remote_acceptance(remote, expected,
                                                rusd_alloc_requested=True)

            remote, expected = self.rusd_alloc_remote()
            remote["ioctl_observation"]["records"][0]["entry"]["rusd"][
                "classPayloadBytes"] = 16
            with self.assertRaisesRegex(ValueError, "RUSD class payload"):
                tool.validate_remote_acceptance(remote, expected,
                                                rusd_alloc_requested=True)

            remote, expected = self.rusd_alloc_remote()
            remote["ioctl_observation"]["records"] = [{"operation": "alloc"}]
            remote["rusd_alloc_records_seen"] = False
            remote["ioctl_observation"]["rusd_payload_snapshots_read"] = 0
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rusd_alloc_requested=True),
                "v100-reference-validated")

        def test_rusd_capture_rejects_absent_record_with_inconsistent_summary(self):
            remote, expected = self.rusd_alloc_remote()
            remote["ioctl_observation"]["records"] = [{"operation": "alloc"}]
            remote["ioctl_observation"]["rusd_payload_snapshots_read"] = 0
            remote["rusd_alloc_records_seen"] = True
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(remote, expected,
                                                rusd_alloc_requested=True)

        def test_rusd_capture_accepts_complete_empty_filtered_trace_as_absence(self):
            remote, expected = self.rusd_alloc_remote()
            observed = remote["ioctl_observation"]
            observed["records"] = []
            observed["rusd_payload_snapshots_read"] = 0
            remote["rusd_alloc_records_seen"] = False
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rusd_alloc_requested=True),
                "v100-reference-validated")

        def test_channel_capture_rejects_incomplete_or_wrong_class_payloads(self):
            remote, expected = self.channel_alloc_remote()
            remote["ioctl_observation"]["channel_payload_snapshots_read"] = 1
            with self.assertRaisesRegex(ValueError, "snapshot count"):
                tool.validate_remote_acceptance(
                    remote, expected, channel_alloc_requested=True)

            remote, expected = self.channel_alloc_remote()
            remote["ioctl_observation"]["records"][0]["entry"]["channel"][
                "classPayloadBytes"] = 360
            with self.assertRaisesRegex(ValueError, "class payload"):
                tool.validate_remote_acceptance(
                    remote, expected, channel_alloc_requested=True)

            remote, expected = self.channel_alloc_remote()
            remote["ioctl_observation"]["records"][0]["exit"]["hClass"] = 0xc96f
            with self.assertRaisesRegex(ValueError, "Volta channel class"):
                tool.validate_remote_acceptance(
                    remote, expected, channel_alloc_requested=True)

        def test_channel_capture_requires_observer_and_exact_scope(self):
            remote, expected = self.channel_alloc_remote()
            expected.pop("observer")
            remote["artifacts_before"].pop("observer")
            remote["artifacts_after"].pop("/tmp/codex-v100-ref-observer")
            with self.assertRaisesRegex(ValueError, "observer"):
                tool.validate_remote_acceptance(
                    remote, expected, channel_alloc_requested=True)

            remote, expected = self.channel_alloc_remote()
            remote["ioctl_observation"]["nested_pointer_scope"] = "all nested pointers"
            with self.assertRaisesRegex(ValueError, "outside the requested"):
                tool.validate_remote_acceptance(
                    remote, expected, channel_alloc_requested=True)

        def map_memory_remote(self):
            remote = self.make_remote()
            remote["map_memory_capture_requested"] = True
            remote["map_memory_records_seen"] = True
            remote["gpu_id_info_records_seen"] = False
            remote["attached_ids_records_seen"] = False
            remote["probed_ids_records_seen"] = False
            remote["channel_alloc_records_seen"] = False
            remote["rm_control_records_seen"] = None
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["observer_exit_code"] = 0
            lifecycle = "opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; exec invalidates inherited IDs; io_uring and external fd injection are not tracked; VMA file references remain kernel-owned"
            payload_scope = "exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; no allocation payloads emitted; addresses, paths, and handles omitted"
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v15",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
                "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": False, "fd_identity_tracking": False,
                "fd_identity_capture_complete": True,
                "fd_lifecycle_scope": lifecycle, "payload_scope": payload_scope,
                "object_class_resolution_scope": "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed",
                "errors": [],
                "records": [
                    {"operation": "fd_open", "request": 257, "packet_size": 0,
                     "fd": 8, "fd_file_id": 2, "fd_role": "control",
                     "entry": None, "exit": None, "syscall_return": 8,
                     "tid": 1234},
                    {"operation": "fd_open", "request": 257, "packet_size": 0,
                     "fd": 15, "fd_file_id": 7, "fd_role": "gpu",
                     "entry": None, "exit": None, "syscall_return": 15,
                     "tid": 1234},
                    {"operation": "map_memory", "request": 3224913486,
                     "packet_size": 56, "fd": 8, "fd_file_id": 2,
                     "fd_role": "control", "syscall_return": 0,
                     "tid": 1234,
                     "entry": {"backendFd": 15, "backendFdRole": "gpu",
                               "backendFileId": 7, "length": 65536,
                               "flags": 524290, "hClientPresent": True,
                               "hDevicePresent": True, "hMemoryPresent": True,
                               "linearAddressPresent": False, "offsetNonzero": False,
                               "memoryObjectClass": {"resolution": "resolved", "classId": 0xc361},
                               "status": 0},
                     "exit": {"backendFd": 15, "backendFdRole": "gpu",
                              "backendFileId": 7, "length": 65536,
                              "flags": 50855938, "hClientPresent": True,
                              "hDevicePresent": True, "hMemoryPresent": True,
                              "linearAddressPresent": True, "offsetNonzero": False,
                              "memoryObjectClass": {"resolution": "resolved", "classId": 0xc361},
                              "status": 0}},
                    {"operation": "mmap", "request": 9, "packet_size": 0,
                     "fd": 15, "fd_file_id": 7, "fd_role": "gpu",
                     "syscall_return": None, "exit": None,
                     "mmap_succeeded": True,
                     "entry": {"length": 65536, "prot": 2,
                               "flags": 1, "offsetZero": True}, "tid": 1234},
                    {"operation": "unmap_memory", "request": 3223340623,
                     "packet_size": 32, "fd": 8, "fd_file_id": 2,
                     "fd_role": "control", "syscall_return": 0,
                     "entry": {"flags": 0, "hClientPresent": True,
                               "hDevicePresent": True, "hMemoryPresent": True,
                               "linearAddressPresent": True, "status": 0},
                     "exit": {"flags": 0, "hClientPresent": True,
                              "hDevicePresent": True, "hMemoryPresent": True,
                              "linearAddressPresent": True, "status": 0}, "tid": 1234},
                ],
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_accepts_r580_map_to_mmap_on_same_gpu_file_identity(self):
            remote, expected = self.map_memory_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, map_memory_requested=True),
                "v100-reference-validated")
            self.assertEqual(remote["map_memory_class_resolution_counts"], {"resolved": 1})
            self.assertEqual(remote["map_memory_class_ids"], [0xc361])

        def test_r580_map_capture_rejects_incomplete_or_mismatched_identity(self):
            remote, expected = self.map_memory_remote()
            remote["ioctl_observation"]["fd_identity_capture_complete"] = False
            with self.assertRaisesRegex(ValueError, "identity"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

            remote, expected = self.map_memory_remote()
            remote["ioctl_observation"]["records"][3]["fd_file_id"] = 99
            with self.assertRaisesRegex(ValueError, "file identity lifecycle"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

        def test_r580_map_capture_requires_exact_scope_and_successful_pair(self):
            remote, expected = self.map_memory_remote()
            remote["ioctl_observation"]["payload_scope"] = "all RM payloads"
            with self.assertRaisesRegex(ValueError, "scope"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

            remote, expected = self.map_memory_remote()
            remote["ioctl_observation"]["records"][3]["mmap_succeeded"] = False
            with self.assertRaisesRegex(ValueError, "successful mmap"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

            remote, expected = self.map_memory_remote()
            remote["ioctl_observation"]["records"][2]["request"] = 0
            with self.assertRaisesRegex(ValueError, "RM map packet"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

            remote, expected = self.map_memory_remote()
            remote["ioctl_observation"]["records"][2]["entry"]["memoryObjectClass"] = {
                "resolution": "resolved", "classId": None}
            with self.assertRaisesRegex(ValueError, "memory-object class"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

            remote, expected = self.map_memory_remote()
            remote["map_memory_records_seen"] = False
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(
                    remote, expected, map_memory_requested=True)

        def test_accepts_fixed_rm_control_headers_without_nested_reads(self):
            remote, expected = self.rm_control_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rm_control_requested=True), "v100-reference-validated")
            remote["ioctl_observation"]["payload_scope"] = "all RM payloads"
            with self.assertRaisesRegex(ValueError, "scope"):
                tool.validate_remote_acceptance(remote, expected, rm_control_requested=True)

        def test_accepts_rm_control_with_only_explicit_metadata_payload(self):
            remote, expected = self.rm_control_remote(attached_ids=True)
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, attached_ids_requested=True,
                rm_control_requested=True), "v100-reference-validated")
            remote["ioctl_observation"]["payload_scope"] = (
                "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted")
            with self.assertRaisesRegex(ValueError, "scope"):
                tool.validate_remote_acceptance(remote, expected, attached_ids_requested=True,
                                                rm_control_requested=True)

        def test_rejects_rm_control_record_summary_mismatch(self):
            remote, expected = self.rm_control_remote()
            remote["rm_control_records_seen"] = False
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(remote, expected, rm_control_requested=True)

        def test_trace_mode_requires_complete_trace_and_hashed_helper(self):
            remote = self.make_remote()
            helper = {"bytes": 8, "sha256": "d" * 64}
            remote["artifacts_before"]["trace-helper"] = {
                **helper, "guest_path": "/tmp/codex-v100-ref-helper.py"}
            remote["artifacts_after"]["/tmp/codex-v100-ref-helper.py"] = helper
            remote["ioctl_trace"] = {
                "trace_complete": True, "timed_out": False,
                "strace_version": "strace -- version 6.8",
                "strace_sha256": "e" * 64,
                "trace": {"trace_complete": True, "size_limit_exceeded": False,
                          "summary": {"trace_complete": True, "parsed_calls": 1}},
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["trace-helper"] = helper
            self.assertEqual(tool.validate_remote_acceptance(remote, expected, trace_requested=True),
                             "v100-reference-validated")
            remote["ioctl_trace"]["trace"]["trace_complete"] = False
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(remote, expected, trace_requested=True)

    class TransportContracts(unittest.TestCase):
        def test_v100_runner_defaults_to_current_probe_bundle(self):
            self.assertEqual(tool.DEFAULT_PROBE,
                             ROOT / "build/probe-managed-prefetch-v2/hybrid_cuda_probe")
            self.assertEqual(tool.DEFAULT_MODULE,
                             ROOT / "build/probe-managed-prefetch-v2/hybrid_probe.sm70-sm120.fatbin")

        def test_cli_records_optional_ioctl_observer_identity(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-observer-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                try:
                    args = tool.parse_args([
                        "--probe", str(probe), "--module", str(module),
                        "--ioctl-observer", str(observer), "--evidence", str(root / "report.json"),
                    ])
                except SystemExit as error:
                    self.fail(f"CLI rejected the optional observer: exit {error.code}")
                report = tool.report_path(args)
                self.assertEqual(report.get("ioctl_observer"), tool.identity(observer))
                self.assertEqual(report.get("runner_source"), tool.identity(Path(tool.__file__)))

        def test_channel_alloc_capture_requires_observer_and_records_opt_in(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-channel-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--channel-alloc", "--evidence", str(root / "missing.json")])
                self.assertEqual(error.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--channel-alloc",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.channel_alloc)
                self.assertTrue(tool.report_path(args)["channel_alloc_capture_requested"])
                with self.assertRaises(SystemExit) as conflict:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--ioctl-observer", str(observer), "--channel-alloc",
                                     "--gpu-id-info", "--evidence", str(root / "conflict.json")])
                self.assertEqual(conflict.exception.code, 2)

        def test_attached_ids_capture_requires_observer_and_records_opt_in(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-attached-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--attached-ids", "--evidence", str(root / "missing-observer.json")])
                self.assertEqual(error.exception.code, 2)

        def test_rm_control_capture_requires_observer_and_records_opt_in(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-rm-control-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--rm-control", "--evidence", str(root / "missing-observer.json")])
                self.assertEqual(error.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--rm-control",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(tool.report_path(args)["rm_control_capture_requested"])
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--attached-ids",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.attached_ids)
                self.assertTrue(tool.report_path(args)["attached_ids_capture_requested"])

        def test_probed_ids_capture_requires_observer_and_records_opt_in(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-probed-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--probed-ids", "--evidence", str(root / "missing-observer.json")])
                self.assertEqual(error.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--probed-ids",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.probed_ids)
                self.assertTrue(tool.report_path(args)["probed_ids_capture_requested"])

        def test_gpu_id_info_capture_requires_observer_and_records_opt_in(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-id-info-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--gpu-id-info", "--evidence", str(root / "missing-observer.json")])
                self.assertEqual(error.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--gpu-id-info",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.gpu_id_info)
                self.assertTrue(tool.report_path(args)["gpu_id_info_capture_requested"])

        def test_map_memory_capture_requires_observer_and_isolated_default_mode(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-map-memory-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--map-memory", "--evidence", str(root / "missing.json")])
                self.assertEqual(error.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--map-memory",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.map_memory)
                self.assertTrue(tool.report_path(args)["map_memory_capture_requested"])
                with self.assertRaises(SystemExit) as conflict:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--ioctl-observer", str(observer), "--map-memory",
                                     "--rm-control", "--evidence", str(root / "conflict.json")])
                self.assertEqual(conflict.exception.code, 2)
                with self.assertRaises(SystemExit) as managed:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--ioctl-observer", str(observer), "--map-memory",
                                     "--managed-memory", "--evidence", str(root / "managed.json")])
                self.assertEqual(managed.exception.code, 2)

        def test_rusd_capture_requires_observer_and_isolated_default_probe(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-rusd-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                with self.assertRaises(SystemExit) as missing_observer:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--rusd-alloc", "--evidence", str(root / "missing.json")])
                self.assertEqual(missing_observer.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--rusd-alloc",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.rusd_alloc)
                self.assertTrue(tool.report_path(args)["rusd_alloc_capture_requested"])
                for conflicts in (("--gpu-id-info",), ("--managed-memory",),
                                  ("--map-memory",), ("--channel-alloc",)):
                    with self.subTest(conflicts=conflicts):
                        with self.assertRaises(SystemExit) as rejected:
                            tool.parse_args(["--probe", str(probe), "--module", str(module),
                                             "--ioctl-observer", str(observer), "--rusd-alloc",
                                             *conflicts, "--evidence",
                                             str(root / ("conflict-" + conflicts[0][2:] + ".json"))])
                        self.assertEqual(rejected.exception.code, 2)

        def test_cli_records_managed_memory_mode(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-managed-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module = root / "probe", root / "module"
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--managed-memory", "--managed-prefetch",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.managed_memory)
                self.assertTrue(args.managed_prefetch)
                self.assertEqual(tool.report_path(args)["memory_mode"], "managed")
                self.assertTrue(tool.report_path(args)["managed_prefetch_requested"])

        def test_cli_records_opt_in_strace_helper_and_rejects_existing_sidecar(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-strace-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module = root / "probe", root / "module"
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                evidence = root / "report.json"
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-trace", "--evidence", str(evidence)])
                report = tool.report_path(args)
                self.assertEqual(report["ioctl_trace_helper"],
                                 tool.identity(ROOT / "tools/summarize_rm_ioctl_trace.py"))
                evidence.with_suffix(".json.strace.gz").write_bytes(b"existing")
                with self.assertRaises(SystemExit) as error:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--ioctl-trace", "--evidence", str(evidence)])
                self.assertEqual(error.exception.code, 2)

        def test_guest_ssh_uses_strict_pinned_host_key_and_no_agent_config(self):
            argv = tool.guest_ssh_base("/var/lib/pc3-v100-vm/id_ed25519",
                                       "/tmp/codex-pc3-vm-known_hosts")
            joined = " ".join(argv)
            self.assertIn("-F /dev/null", joined)
            self.assertIn("StrictHostKeyChecking=yes", joined)
            self.assertIn("-i /var/lib/pc3-v100-vm/id_ed25519", joined)
            self.assertIn("-p 22223", joined)

        def test_embedded_guest_pin_is_scoped_to_the_forwarded_host_entry(self):
            script = tool.REMOTE_ROOT_SCRIPT
            self.assertIn("known_stat = known.lstat()", script)
            self.assertIn("not stat.S_ISREG(known_stat.st_mode)", script)
            self.assertIn("known_stat.st_uid != expected_uid", script)
            self.assertIn("known_stat.st_mode & 0o022", script)
            self.assertIn('"ssh-keygen", "-F", "[127.0.0.1]:22223"', script)
            self.assertIn('"ssh-keygen", "-lf", matched_file', script)
            self.assertIn("fingerprints != {expected_fingerprint}", script)
            self.assertNotIn('["ssh-keygen", "-lf", str(known)]', script)

        def test_decoy_host_fingerprint_does_not_satisfy_guest_pin(self):
            if shutil.which("ssh-keygen") is None:
                self.skipTest("OpenSSH key tools are unavailable")
            with tempfile.TemporaryDirectory(prefix="pc3-v100-hostkey-test-") as temp_dir:
                root = Path(temp_dir)
                keys = {}
                fingerprints = {}
                for name in ("decoy", "guest"):
                    key = root / name
                    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    fields = key.with_suffix(".pub").read_text().strip().split()
                    keys[name] = " ".join(fields[:2])
                    output = subprocess.run(["ssh-keygen", "-lf", str(key.with_suffix(".pub"))],
                                            check=True, text=True, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE).stdout
                    fingerprints[name] = output.split()[1]
                known = root / "known_hosts"
                known.write_text("decoy.example " + keys["decoy"] + "\n" +
                                 "[127.0.0.1]:22223 " + keys["guest"] + "\n")
                known.chmod(0o600)
                def run(argv, timeout):
                    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          timeout=timeout, check=False)
                self.assertIsNone(tool.verify_guest_host_key(known, fingerprints["guest"],
                                                            os.getuid(), run))
                with self.assertRaises(RuntimeError):
                    tool.verify_guest_host_key(known, fingerprints["decoy"], os.getuid(), run)

        def test_embedded_remote_helpers_are_valid_python(self):
            compile(tool.REMOTE_ROOT_SCRIPT, "<remote-root-helper>", "exec")
            compile(tool._credential_remote_script(), "<credential-reader>", "exec")
            import ast
            outer = ast.parse(tool.REMOTE_ROOT_SCRIPT)
            run_code = next(node.value.value for node in ast.walk(outer)
                            if isinstance(node, ast.Assign) and
                            any(isinstance(target, ast.Name) and target.id == "run_code"
                                for target in node.targets) and isinstance(node.value, ast.Constant))
            self.assertIn("importlib.machinery.SourceFileLoader", run_code)
            compile(run_code, "<guest-cuda-runner>", "exec")
            self.assertIn('"--map-memory","--gpu-path","/dev/nvidia0"', run_code)
            self.assertIn("map_memory_capture_requested", tool.REMOTE_ROOT_SCRIPT)
            self.assertIn('"--rusd-alloc","--gpu-path","/dev/nvidia0"', run_code)
            self.assertIn("rusd_alloc_capture_requested", tool.REMOTE_ROOT_SCRIPT)

        def test_cuda_environment_drops_injection_and_selects_only_requested_uuid(self):
            env = tool.clean_cuda_environment({"PATH": "/attacker", "LD_PRELOAD": "/bad.so",
                                              "CUDA_VISIBLE_DEVICES": "0,1", "NVIDIA_VISIBLE_DEVICES": "all",
                                              "PYTHONPATH": "/bad"}, "GPU-12345678-1234-1234-1234-123456789abc")
            self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                   "CUDA_VISIBLE_DEVICES": "GPU-12345678-1234-1234-1234-123456789abc"})

        def test_payload_staging_path_is_randomized_and_confined_to_tmp(self):
            self.assertTrue(hasattr(tool, "payload_staging_path"), "randomized payload staging is not implemented")
            self.assertEqual(tool.payload_staging_path("a" * 32),
                             "/tmp/codex-v100-payload-" + "a" * 32 + ".json")
            with self.assertRaises(ValueError):
                tool.payload_staging_path("../../etc/passwd")

        def test_sudo_authentication_stdin_does_not_include_the_payload(self):
            self.assertTrue(hasattr(tool, "sudo_auth_stdin"), "sudo input boundary is not implemented")
            self.assertEqual(tool.sudo_auth_stdin("only-this-line"), b"only-this-line\n")

        def test_payload_helpers_are_valid_python(self):
            self.assertTrue(hasattr(tool, "payload_writer_code"), "payload writer is not implemented")
            compile(tool.payload_writer_code(), "<payload-writer>", "exec")
            compile(tool.payload_cleanup_code(), "<payload-cleanup>", "exec")


if __name__ == "__main__":
    unittest.main()
