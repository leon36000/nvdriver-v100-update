#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only acceptance contracts for the guarded PC3 V100 guest runner."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/run_pc3_v100_guest_reference.py"
BUILD_TOOL_PATH = ROOT / "tools/build_probe_cuda129.py"


def phase_report(phase="kernel", pci="0000:81:00.0", sm=70):
    operations = ["cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                  "cuDeviceGetName", "cuDeviceGetPCIBusId",
                  "cuDeviceGetAttribute.major", "cuDeviceGetAttribute.minor",
                  "cuDeviceGetAttribute.concurrent_managed_access",
                  "cuDeviceGetAttribute.pageable_memory_access",
                  "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables"]
    selected = None
    if phase != "initialize":
        selected = {"name": "Tesla V100-SXM2-16GB", "pci_bus_id": pci, "sm": sm,
                    "compute_capability": "7.0", "pageable_memory_access": True,
                    "concurrent_managed_access": True,
                    "pageable_memory_access_uses_host_page_tables": False}
    if phase == "initialize":
        operations = ["cuInit"]
    elif phase != "enumerate":
        operations += ["cuCtxCreate_v2", "cuCtxSetCurrent", "cuCtxGetDevice"]
        if phase == "allocation":
            operations += ["cuMemAlloc_v2"]
        elif phase == "managed-accessed-by":
            operations += ["cuMemAllocManaged", "cuMemAdvise(SET_ACCESSED_BY)",
                           "cuMemAdvise(UNSET_ACCESSED_BY)"]
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


def system_pageable_report(status="unsupported", pageable=False, pci="0000:81:00.0", sm=70):
    return {
        "schema": "nvidia-cuda-system-pageable-memory-v1", "status": status,
        "phase": "system-pageable-memory", "expected_pci": "00000000:" + pci.split(":", 1)[1],
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
        "driver_api": 13000,
        "selected_device": {
            "name": "Tesla V100-SXM2-16GB", "pci_bus_id": pci, "sm": sm,
            "compute_capability": f"{sm // 10}.{sm % 10}",
            "concurrent_managed_access": True, "pageable_memory_access": pageable,
            "pageable_memory_access_uses_host_page_tables": False,
            "unified_addressing": True,
        },
        "allocators": ({"malloc": None, "mmap": None} if status == "unsupported" else {
            "malloc": {"tested": True, "passed": True,
                       "execution_mode": "context-synchronized", "sizes": [1, 31, 256, 4096, 65537]},
            "mmap": {"tested": True, "passed": True,
                     "execution_mode": "stream-synchronized", "sizes": [1, 31, 256, 4096, 65537]},
        }),
        "cleanup_passed": True, "cleanup_errors": [],
        "error": "device does not report pageable memory access" if status == "unsupported" else "",
    }


def performance_benchmark_fixture():
    launch = [float(value) for value in range(1, 10)]
    copies = [float(value) for value in range(1, 8)]

    def middle_and_p95(values):
        ordered = sorted(values)
        return ordered[len(ordered) // 2], ordered[-1]

    launch_median, launch_p95 = middle_and_p95(launch)
    transfers = []
    for size, iterations in zip((4096, 65536, 1048576, 16777216, 67108864),
                                (2048, 128, 8, 1, 1)):
        directions = {}
        elapsed = [size / (value * 1000.0) for value in copies]
        elapsed_median, elapsed_p95 = middle_and_p95(elapsed)
        for direction in ("h_to_d", "d_to_h"):
            directions[direction] = {
                "data_integrity_passed": True,
                "host_api_us_per_copy_samples": copies.copy(),
                "host_api_us_per_copy_median": 4.0,
                "host_api_us_per_copy_p95": 7.0,
                "device_elapsed_us_per_copy_samples": elapsed.copy(),
                "device_elapsed_us_per_copy_median": elapsed_median,
                "device_elapsed_us_per_copy_p95": elapsed_p95,
                "gb_per_second_samples": copies.copy(),
                "gb_per_second_median": 4.0,
                "gb_per_second_p95": 7.0,
            }
        transfers.append({"bytes": size, "samples": 7,
                          "iterations_per_sample": iterations,
                          "data_integrity_passed": True, **directions})
    return {
        "schema": "nvidia-cuda-performance-benchmark-v2", "status": "completed",
        "timing_sources": {"host": "std::chrono::steady_clock",
                           "device": "CUDA events (cuEventElapsedTime)"},
        "samples": 9, "warmup_launches": 64, "launches_per_sample": 256,
        "kernel_launch": {
            "kernel": "hybrid_empty", "samples": 9,
            "host_api_us_samples": launch.copy(),
            "host_api_us_median": launch_median,
            "host_api_us_p95": launch_p95,
            "device_elapsed_us_samples": launch.copy(),
            "device_elapsed_us_median": launch_median,
            "device_elapsed_us_p95": launch_p95},
        "cuda_graph_launch": {
            "host_api_us": {"values": launch.copy(), "median": launch_median,
                             "p95": launch_p95, "samples": 9},
            "device_elapsed_us": {"values": launch.copy(), "median": launch_median,
                                   "p95": launch_p95, "samples": 9}},
        "transfers": transfers,
    }


class RunnerAvailability(unittest.TestCase):
    def test_v100_guest_runner_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "guarded PC3 V100 guest runner is missing")


if TOOL_PATH.is_file():
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference", TOOL_PATH)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    build_spec = importlib.util.spec_from_file_location("build_probe", BUILD_TOOL_PATH)
    build_tool = importlib.util.module_from_spec(build_spec)
    build_spec.loader.exec_module(build_tool)

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
                    "concurrent_managed_access": True,
                    "pageable_memory_access": True,
                    "pageable_memory_access_uses_host_page_tables": False,
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
            self.assertEqual(result, "v100-reference-report-contract-valid")

        def test_performance_graph_timing_is_allowed_without_functional_graph_replay(self):
            report = self.make_report()
            report["performance_benchmark_requested"] = True
            report["cuda_graph_api"] = "cuGraphInstantiateWithFlags"
            report["devices"][0]["performance_benchmark_passed"] = True
            report["devices"][0]["performance_benchmark"] = performance_benchmark_fixture()
            self.assertEqual(tool.validate_v100_reference(
                report, 0, "0000:81:00.0", performance_benchmark=True),
                "v100-reference-report-contract-valid")
            report["cuda_graph_api"] = "not-requested"
            with self.assertRaisesRegex(ValueError, "requires its CUDA Graph launch API"):
                tool.validate_v100_reference(
                    report, 0, "0000:81:00.0", performance_benchmark=True)

        def test_sm70_reference_requires_unified_memory_attributes(self):
            for field in ("concurrent_managed_access", "pageable_memory_access",
                          "pageable_memory_access_uses_host_page_tables"):
                with self.subTest(field=field):
                    report = self.make_report()
                    del report["devices"][0][field]
                    with self.assertRaisesRegex(ValueError, field):
                        tool.validate_v100_reference(report, 0, "0000:81:00.0")

        def test_phase_gate_uses_the_shared_phase_contract(self):
            result = tool.validate_cuda_phase_report(
                phase_report("kernel"), 0, "0000:81:00.0", "kernel")
            self.assertEqual(result, "phase-report-contract-pass")
            wrong_sm = phase_report("kernel", sm=120)
            with self.assertRaises(ValueError):
                tool.validate_cuda_phase_report(wrong_sm, 0, "0000:81:00.0", "kernel")

        def test_system_pageable_phase_accepts_explicit_v100_unsupported_before_context(self):
            report = system_pageable_report()
            self.assertEqual(tool.validate_cuda_phase_report(
                report, 77, "0000:81:00.0", "system-pageable-memory"),
                "system-pageable-memory-unsupported-report-contract-valid")
            for mutate in (
                lambda r: r["selected_device"].update(pageable_memory_access=True),
                lambda r: r.update(status="validated", error=""),
                lambda r: r.update(expected_pci="00000000:82:00.0"),
                lambda r: r["selected_device"].update(sm=120, compute_capability="12.0"),
            ):
                candidate = copy.deepcopy(report)
                mutate(candidate)
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    tool.validate_cuda_phase_report(
                        candidate, 77, "0000:81:00.0", "system-pageable-memory")

        def test_system_pageable_phase_cli_isolated_without_an_ioctl_observer(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-pageable-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module = root / "probe", root / "module"
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                args = tool.parse_args(["--phase", "system-pageable-memory",
                                        "--probe", str(probe), "--module", str(module),
                                        "--evidence", str(root / "pageable.json")])
                self.assertEqual(args.phase, "system-pageable-memory")
                self.assertTrue(tool.report_path(args)["phase_capture_requested"])
                with self.assertRaises(SystemExit) as mixed_trace:
                    tool.parse_args(["--phase", "system-pageable-memory",
                                     "--probe", str(probe), "--module", str(module),
                                     "--ioctl-trace", "--evidence", str(root / "mixed.json")])
                self.assertEqual(mixed_trace.exception.code, 2)

        def test_remote_system_pageable_phase_records_expected_unsupported_result(self):
            remote = self.make_remote()
            remote.update({"phase_capture_requested": True,
                           "phase": "system-pageable-memory",
                           "probe": system_pageable_report(),
                           "probe_exit_code": 77,
                           "driver_library": {"path": system_pageable_report()["driver_library_path"],
                                              "bytes": 1234, "sha256": "b" * 64}})
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, phase="system-pageable-memory"),
                "v100-system-pageable-memory-unsupported-report-contract-valid")
            remote["probe"]["selected_device"]["pageable_memory_access"] = True
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(
                    remote, expected, phase="system-pageable-memory")

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
                "v100-cuda-phase-report-contract-valid")
            remote["probe"]["selected_device"]["sm"] = 120
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(remote, expected,
                    rm_control_requested=True, binapi_control_requested=True,
                    phase="kernel")

        def test_remote_enumeration_phase_accepts_complete_ioctl_node_trace(self):
            remote = self.make_remote()
            remote["phase_capture_requested"] = True
            remote["phase"] = "enumerate"
            remote["probe"] = phase_report("enumerate")
            remote["probe_exit_code"] = 0
            helper = {"bytes": 8, "sha256": "d" * 64,
                      "guest_path": "/tmp/codex-v100-ref-trace-helper.py"}
            remote["artifacts_before"]["trace-helper"] = helper
            remote["artifacts_after"][helper["guest_path"]] = {
                "bytes": helper["bytes"], "sha256": helper["sha256"]}
            remote["ioctl_trace"] = {
                "trace_complete": True, "timed_out": False,
                "strace_version": "strace -- version 6.8",
                "strace_sha256": "e" * 64,
                "trace": {"trace_complete": True, "size_limit_exceeded": False,
                          "summary": {
                              "schema": "nvidia-hybrid-node-open-trace-v1",
                              "qualification": "complete-node-open-trace",
                              "trace_complete": True,
                              "selected_node_open_count": 1,
                              "successful_selected_node_open_count": 1,
                              "unparsed_lines": [],
                          }},
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["trace-helper"] = {"bytes": helper["bytes"],
                                        "sha256": helper["sha256"]}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, trace_requested=True, phase="enumerate"),
                "v100-cuda-phase-report-contract-valid")

            remote["ioctl_trace"]["trace"]["summary"]["unparsed_lines"] = [
                {"line": 1, "bytes": 5, "sha256": "f" * 64,
                 "target_hint": "descriptor"}]
            with self.assertRaisesRegex(ValueError, "node-open"):
                tool.validate_remote_acceptance(
                    remote, expected, trace_requested=True, phase="enumerate")

        def test_remote_context_phase_accepts_complete_generic_ioctl_trace(self):
            remote = self.make_remote()
            remote["phase_capture_requested"] = True
            remote["phase"] = "context"
            remote["probe"] = phase_report("context")
            remote["probe_exit_code"] = 0
            helper = {"bytes": 8, "sha256": "d" * 64,
                      "guest_path": "/tmp/codex-v100-ref-trace-helper.py"}
            remote["artifacts_before"]["trace-helper"] = helper
            remote["artifacts_after"][helper["guest_path"]] = {
                "bytes": helper["bytes"], "sha256": helper["sha256"]}
            remote["ioctl_trace"] = {
                "trace_complete": True, "timed_out": False,
                "strace_version": "strace -- version 6.8",
                "strace_sha256": "e" * 64,
                "trace": {"trace_complete": True, "size_limit_exceeded": False,
                          "summary": {
                              "schema": "nvidia-hybrid-node-open-trace-v1",
                              "qualification": "complete-node-open-trace",
                              "trace_complete": True,
                              "selected_node_open_count": 2,
                              "successful_selected_node_open_count": 2,
                              "unparsed_lines": [],
                          }},
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["trace-helper"] = {"bytes": helper["bytes"],
                                        "sha256": helper["sha256"]}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, trace_requested=True, phase="context"),
                "v100-cuda-phase-report-contract-valid")

        def test_managed_accessed_by_phase_requires_successful_set_and_unset_ioctl(self):
            remote = self.make_remote()
            remote["phase_capture_requested"] = True
            remote["phase"] = "managed-accessed-by"
            remote["probe"] = phase_report("managed-accessed-by")
            helper = {"bytes": 8, "sha256": "d" * 64,
                      "guest_path": "/tmp/codex-v100-ref-trace-helper.py"}
            remote["artifacts_before"]["trace-helper"] = helper
            remote["artifacts_after"][helper["guest_path"]] = {
                "bytes": helper["bytes"], "sha256": helper["sha256"]}
            calls = [
                {"line": 20, "pid": 1234, "node": "/dev/nvidia-uvm",
                 "request": "0x2e", "syscall_return": 0},
                {"line": 21, "pid": 1234, "node": "/dev/nvidia-uvm",
                 "request": "0x2f", "syscall_return": 0},
                {"line": 22, "pid": 1234, "node": "/dev/nvidia-uvm",
                 "request": "0x2f", "syscall_return": 0},
            ]
            remote["ioctl_trace"] = {
                "trace_complete": True, "timed_out": False,
                "strace_version": "strace -- version 6.8",
                "strace_sha256": "e" * 64,
                "trace": {"trace_complete": True, "size_limit_exceeded": False,
                          "summary": {"schema": "nvidia-hybrid-ioctl-metadata-summary-v2",
                                      "trace_complete": True, "parsed_calls": 2,
                                      "negative_syscall_returns": 0,
                                      "unparsed_lines": [], "calls": copy.deepcopy(calls)}},
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["trace-helper"] = {"bytes": helper["bytes"],
                                        "sha256": helper["sha256"]}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, trace_requested=True, phase="managed-accessed-by"),
                "v100-cuda-phase-report-contract-valid")

            remote["ioctl_trace"]["trace"]["summary"]["calls"].pop()
            remote["ioctl_trace"]["trace"]["summary"]["calls"].pop()
            with self.assertRaisesRegex(ValueError, "SET_ACCESSED_BY.*UNSET_ACCESSED_BY"):
                tool.validate_remote_acceptance(
                    remote, expected, trace_requested=True, phase="managed-accessed-by")

            remote["ioctl_trace"]["trace"]["summary"]["calls"] = copy.deepcopy(calls)
            remote["ioctl_trace"]["trace"]["summary"]["calls"][1]["syscall_return"] = -1
            with self.assertRaisesRegex(ValueError, "SET_ACCESSED_BY.*UNSET_ACCESSED_BY"):
                tool.validate_remote_acceptance(
                    remote, expected, trace_requested=True, phase="managed-accessed-by")

            remote["ioctl_trace"]["trace"]["summary"]["calls"] = copy.deepcopy(calls)
            remote["ioctl_trace"]["trace"]["summary"]["calls"][1]["pid"] = 9999
            with self.assertRaisesRegex(ValueError, "SET_ACCESSED_BY.*UNSET_ACCESSED_BY"):
                tool.validate_remote_acceptance(
                    remote, expected, trace_requested=True, phase="managed-accessed-by")

        def test_remote_context_phase_accepts_redacted_uvm_vaspace_fd_capture(self):
            remote = self.make_remote()
            remote.update({"phase_capture_requested": True, "phase": "context",
                           "probe": phase_report("context"), "probe_exit_code": 0,
                           "uvm_vaspace_fd_capture_requested": True,
                           "uvm_vaspace_records_seen": True,
                           "uvm_map_external_records_seen": True,
                           "observer_exit_code": 0,
                           "gpu_id_info_records_seen": False,
                           "attached_ids_records_seen": False,
                           "probed_ids_records_seen": False})
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote["ioctl_observation"] = {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v31",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "uvm_path": "/dev/nvidia-uvm",
                "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": False, "fd_identity_tracking": True,
                "fd_identity_capture_complete": True,
                "payload_scope": ("reads only pinned 4-byte rmCtrlFd fields in "
                                  "UVM_REGISTER_GPU_VASPACE (offset 16) and "
                                  "UVM_MAP_EXTERNAL_ALLOCATION (offset 9248) at syscall entry and return; checks "
                                  "selected-node, transient in-memory file identity and pending "
                                  "close/dup/range mutation; emits only "
                                  "booleans; raw descriptor, payload, TID, file identity and ioctl "
                                  "argument address omitted"),
                "fd_lifecycle_scope": ("selected control-node open, dup, fcntl-dup, close and "
                                       "close_range metadata across traced shared descriptor tables; "
                                       "io_uring and external descriptor injection are not tracked"),
                "uvm_vaspace_records_seen": 1, "uvm_map_external_records_seen": 1,
                "errors": [],
                "records": [{
                    "operation": "uvm_register_gpu_vaspace", "request": 25,
                    "field_read_at_entry": True,
                    "rm_ctrl_fd_identity_tracked_at_entry": True,
                    "rm_ctrl_fd_same_file_identity_at_exit": True,
                    "rm_ctrl_fd_field_unchanged_at_exit": True,
                    "rm_ctrl_fd_no_mutation_pending_at_entry": True,
                    "rm_ctrl_fd_no_mutation_pending_at_exit": True,
                    "uvm_fd_matches_selected_node_at_entry": True,
                    "rm_ctrl_fd_matches_control_node_at_entry": True,
                    "rm_ctrl_fd_matches_control_node_at_exit": True,
                    "rm_ctrl_fd_is_negative": False, "exit_observed": True,
                    "syscall_return": 0,
                }, {
                    "operation": "uvm_map_external_allocation", "request": 33,
                    "field_read_at_entry": True,
                    "rm_ctrl_fd_identity_tracked_at_entry": True,
                    "rm_ctrl_fd_same_file_identity_at_exit": True,
                    "rm_ctrl_fd_field_unchanged_at_exit": True,
                    "rm_ctrl_fd_no_mutation_pending_at_entry": True,
                    "rm_ctrl_fd_no_mutation_pending_at_exit": True,
                    "uvm_fd_matches_selected_node_at_entry": True,
                    "rm_ctrl_fd_matches_control_node_at_entry": True,
                    "rm_ctrl_fd_matches_control_node_at_exit": True,
                    "rm_ctrl_fd_is_negative": False, "exit_observed": True,
                    "syscall_return": 0,
                }],
            }
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, uvm_vaspace_fd_requested=True, phase="context"),
                "v100-cuda-phase-report-contract-valid")
            kernel_remote = copy.deepcopy(remote)
            kernel_remote.update({"phase": "kernel", "probe": phase_report("kernel")})
            self.assertEqual(tool.validate_remote_acceptance(
                kernel_remote, expected, uvm_vaspace_fd_requested=True, phase="kernel"),
                "v100-cuda-phase-report-contract-valid")
            vaspace_only = copy.deepcopy(remote)
            vaspace_only["ioctl_observation"]["records"] = [
                record for record in vaspace_only["ioctl_observation"]["records"]
                if record.get("operation") != "uvm_map_external_allocation"]
            vaspace_only["ioctl_observation"]["uvm_map_external_records_seen"] = 0
            vaspace_only["uvm_map_external_records_seen"] = False
            self.assertEqual(tool.validate_remote_acceptance(
                vaspace_only, expected, uvm_vaspace_fd_requested=True, phase="context"),
                "v100-cuda-phase-report-contract-valid")
            for mutate in (
                    lambda value: value["ioctl_observation"]["records"][0].update(raw_fd=8),
                    lambda value: value["ioctl_observation"]["records"][1].update(request=25),
                    lambda value: value.update(uvm_map_external_records_seen=False)):
                corrupted = copy.deepcopy(remote)
                mutate(corrupted)
                with self.assertRaisesRegex(ValueError, "UVM VA-space/map"):
                    tool.validate_remote_acceptance(
                        corrupted, expected, uvm_vaspace_fd_requested=True, phase="context")

        def test_uvm_vaspace_fd_capture_cli_allows_context_or_kernel_observer_only(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-uvm-vaspace-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                args = tool.parse_args([
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--phase", "context",
                    "--uvm-vaspace-fd", "--evidence", str(root / "report.json")])
                self.assertTrue(args.uvm_vaspace_fd)
                self.assertTrue(tool.report_path(args)["uvm_vaspace_fd_capture_requested"])
                kernel_args = tool.parse_args([
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--phase", "kernel",
                    "--uvm-vaspace-fd", "--evidence", str(root / "kernel-report.json")])
                self.assertTrue(kernel_args.uvm_vaspace_fd)
                invalid = [
                    ["--phase", "context", "--uvm-vaspace-fd"],
                    ["--ioctl-observer", str(observer), "--phase", "enumerate",
                     "--uvm-vaspace-fd"],
                    ["--ioctl-observer", str(observer), "--phase", "kernel",
                     "--uvm-vaspace-fd", "--ioctl-trace"],
                ]
                for index, extra in enumerate(invalid):
                    with self.subTest(extra=extra), self.assertRaises(SystemExit) as error:
                        tool.parse_args(["--probe", str(probe), "--module", str(module),
                                         *extra, "--evidence", str(root / f"invalid-{index}.json")])
                    self.assertEqual(error.exception.code, 2)

        def test_remote_enumeration_accepts_only_redacted_rm_control_headers(self):
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote.update({"observer_exit_code": 0, "phase_capture_requested": True,
                           "phase": "enumerate", "probe_exit_code": 0,
                           "rm_control_capture_requested": False,
                           "rm_control_records_seen": None,
                           "gpu_id_info_records_seen": False,
                           "attached_ids_records_seen": False,
                           "probed_ids_records_seen": False,
                           "rm_control_headers_capture_requested": True,
                           "rm_control_headers_records_seen": True,
                           "rm_control_headers_record_count": 1,
                           "probe": phase_report("enumerate"),
                           "ioctl_observation": {
                               "schema": "nvidia-hybrid-rm-ioctl-observer-v23",
                               "trace_complete": True, "child_exit_code": 0,
                               "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                               "pointer_bits": 64, "nested_pointers_read": False,
                               "fd_identity_tracking": False,
                               "payload_scope": ("fixed NVOS54 RM_CONTROL headers only; handles redacted; "
                                                 "nested parameter payloads omitted"),
                               "errors": [], "records": [{"tid": 1234, "fd": 7,
                                   "fd_role": "control", "request": 0xC020462A,
                                   "packet_size": 32, "operation": "rm_control_header",
                                   "syscall_return": 0,
                                   "entry": {"command": 0x205, "flags": 0, "params_size": 0,
                                             "status": 0, "hClientPresent": True,
                                             "hObjectPresent": True,
                                             "client_object_equal": False,
                                             "client_matches_prior_root_allocation": False,
                                             "object_matches_prior_root_allocation": False},
                                   "exit": {"command": 0x205, "flags": 0, "params_size": 0,
                                            "status": 0, "hClientPresent": True,
                                            "hObjectPresent": True,
                                            "client_object_equal": False,
                                            "client_matches_prior_root_allocation": False,
                                            "object_matches_prior_root_allocation": False}}]}})
            remote["driver_library"] = {
                "path": remote["probe"]["driver_library_path"],
                "bytes": 12, "sha256": "b" * 64}
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, rm_control_headers_requested=True,
                phase="enumerate"), "v100-cuda-phase-report-contract-valid")

            valid_remote = copy.deepcopy(remote)
            remote["ioctl_observation"]["records"][0]["entry"]["hClient"] = 0x1234
            with self.assertRaisesRegex(ValueError, "redact|handle"):
                tool.validate_remote_acceptance(
                    remote, expected, rm_control_headers_requested=True,
                    phase="enumerate")

            allocation = {"layout": "NVOS21", "hRoot": 7, "hObjectParent": 17,
                          "hObjectNew": 18, "pAllocParms": 0x123456789abcdef0}
            unexpected_remote = copy.deepcopy(valid_remote)
            unexpected_remote["ioctl_observation"]["records"].append({
                "tid": 1234, "fd": 7, "fd_role": "control",
                "request": 0xC030462B, "packet_size": 48, "operation": "alloc",
                "entry": allocation, "exit": allocation, "syscall_return": 0})
            with self.assertRaisesRegex(ValueError, "invalid ioctl envelope"):
                tool.validate_remote_acceptance(
                    unexpected_remote, expected, rm_control_headers_requested=True,
                    phase="enumerate")

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
                "v100-cuda-phase-report-contract-valid")

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
                "v100-cuda-phase-report-contract-valid")

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
                "v100-cuda-phase-report-contract-valid")

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
                self.assertFalse(report["report_contract_validated"])
                self.assertFalse(report["device_inventory_observed"])
                self.assertFalse(report["cuda_execution_validated"])
                self.assertIn("probe build identity is not trusted",
                              report["cuda_execution_validation_state"])
                self.assertEqual(report["phase"], "kernel")
                enumerate_headers = tool.parse_args(["--phase", "enumerate",
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--rm-control-headers",
                    "--evidence", str(root / "enumerate-headers.json")])
                self.assertTrue(tool.report_path(enumerate_headers)[
                    "rm_control_headers_capture_requested"])
                enumerate_trace = tool.parse_args(["--phase", "enumerate",
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-trace", "--evidence", str(root / "enumerate-trace.json")])
                self.assertTrue(tool.report_path(enumerate_trace)["phase_capture_requested"])
                self.assertEqual(tool.report_path(enumerate_trace)["phase"], "enumerate")
                self.assertIn("ioctl_trace_helper", tool.report_path(enumerate_trace))
                context_trace = tool.parse_args(["--phase", "context",
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-trace", "--evidence", str(root / "context-trace.json")])
                self.assertEqual(tool.report_path(context_trace)["phase"], "context")
                self.assertIn("ioctl_trace_helper", tool.report_path(context_trace))
                accessed_by_trace = tool.parse_args(["--phase", "managed-accessed-by",
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-trace", "--evidence", str(root / "accessed-by-trace.json")])
                self.assertEqual(tool.report_path(accessed_by_trace)["phase"],
                                 "managed-accessed-by")
                self.assertIn("ioctl_trace_helper", tool.report_path(accessed_by_trace))
                with self.assertRaises(SystemExit) as trace_wrong_phase:
                    tool.parse_args(["--phase", "kernel", "--probe", str(probe),
                        "--module", str(module), "--ioctl-trace", "--evidence",
                        str(root / "kernel-trace.json")])
                self.assertEqual(trace_wrong_phase.exception.code, 2)
                with self.assertRaises(SystemExit) as headers_wrong_phase:
                    tool.parse_args(["--phase", "context", "--probe", str(probe),
                        "--module", str(module), "--ioctl-observer", str(observer),
                        "--rm-control-headers", "--evidence",
                        str(root / "headers-wrong-phase.json")])
                self.assertEqual(headers_wrong_phase.exception.code, 2)
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
            self.assertEqual(result, "v100-reference-report-contract-valid")
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
            self.assertEqual(result, "v100-reference-report-contract-valid")
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
                "v100-reference-report-contract-valid")
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
                "rm_control_capture_requested": False,
                "rm_control_records_seen": None,
                "rm_control_headers_capture_requested": False,
                "rm_control_headers_records_seen": None,
                "rm_control_headers_record_count": None,
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
                             "v100-reference-report-contract-valid")

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
                             "v100-reference-report-contract-valid")

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
                remote, expected, attached_ids_requested=True), "v100-reference-report-contract-valid")

        def test_accepts_cross_checked_gpu_id_info_and_attached_ids(self):
            remote, expected = self.attached_ids_remote(gpu_id_info=True)
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, gpu_id_info_requested=True,
                attached_ids_requested=True), "v100-reference-report-contract-valid")

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
                rm_control_requested=True), "v100-reference-report-contract-valid")

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

        def fabric_status_observation(self):
            common = {
                "command": 0x136, "flags": 0, "params_size": 4, "status": 0,
                "hClientPresent": True, "hObjectPresent": True,
                "client_object_equal": True,
                "client_matches_prior_root_allocation": False,
                "object_matches_prior_root_allocation": False,
            }
            rows = []
            for request, packet_size, value in (
                    (0xC020462A, 32, 4), (0xC01046D3, 16, 3)):
                entry = {**common, "fabricStatus": value}
                exit_phase = {**common, "fabricStatus": value}
                rows.append({
                    "tid": 1234, "fd": 7, "fd_role": "control",
                    "request": request, "packet_size": packet_size,
                    "operation": "rm_control_fabric_status",
                    "entry": entry, "exit": exit_phase, "syscall_return": 0,
                })
            return {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v24",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "nested_pointer_scope": (
                    "exact NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS 4-byte enum only; "
                    "raw addresses and handles omitted"),
                "payload_scope": (
                    "exact root-global Fabric Manager status enum plus fixed RM_CONTROL "
                    "headers; raw addresses and handles omitted"),
                "fabric_status_payload_snapshots_read": 4,
                "fd_identity_tracking": False, "errors": [], "records": rows,
            }

        def fabric_status_remote(self):
            remote = self.make_remote()
            remote.update({
                "phase_capture_requested": True, "phase": "enumerate",
                "probe": phase_report("enumerate"),
                "fabric_status_capture_requested": True,
                "fabric_status_records_seen": True,
                "fabric_status_record_count": 2,
                "fabric_status_values": [4, 3],
                "gpu_id_info_capture_requested": False,
                "gpu_id_info_records_seen": False,
                "attached_ids_capture_requested": False,
                "attached_ids_records_seen": False,
                "probed_ids_capture_requested": False,
                "probed_ids_records_seen": False,
                "channel_alloc_records_seen": False,
                "map_memory_records_seen": False,
                "rusd_alloc_records_seen": False,
                "p2p_alloc_records_seen": False,
                "p2p_control_records_seen": False,
                "binapi_control_records_seen": False,
                "device_alloc_records_seen": False,
                "subdevice_alloc_records_seen": False,
                "binapi_alloc_records_seen": False,
                "observer_exit_code": 0,
                "ioctl_observation": self.fabric_status_observation(),
            })
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_fabric_status_observation_requires_exact_redacted_status_values(self):
            observed = self.fabric_status_observation()
            self.assertEqual(tool.validate_fabric_status_capture(observed), (2, [4, 3]))
            for mutate in (
                lambda candidate: candidate["records"][0]["exit"].update(fabricStatus=5),
                lambda candidate: candidate["records"][0]["entry"].update(params_address=123),
                lambda candidate: candidate.update(fabric_status_payload_snapshots_read=3),
            ):
                candidate = copy.deepcopy(observed)
                mutate(candidate)
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    tool.validate_fabric_status_capture(candidate)

        def test_remote_fabric_status_isolated_enumeration_capture_is_cross_checked(self):
            remote, expected = self.fabric_status_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, fabric_status_requested=True, phase="enumerate"),
                "v100-cuda-phase-report-contract-valid")
            remote["fabric_status_values"] = [4, 4]
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(
                    remote, expected, fabric_status_requested=True, phase="enumerate")

        def system_features_observation(self):
            common = {
                "command": 0x1f0, "flags": 0, "params_size": 4, "status": 0,
                "hClientPresent": True, "hObjectPresent": True,
                "client_object_equal": True,
                "client_matches_prior_root_allocation": False,
                "object_matches_prior_root_allocation": False,
            }
            rows = []
            for request, packet_size, value in (
                    (0xC020462A, 32, 0xA5A55A5A), (0xC01046D3, 16, 0x13579BDF)):
                entry = {**common, "featuresMask": 0}
                exit_phase = {**common, "featuresMask": value}
                rows.append({
                    "tid": 1234, "fd": 7, "fd_role": "control",
                    "request": request, "packet_size": packet_size,
                    "operation": "rm_control_system_features",
                    "entry": entry, "exit": exit_phase, "syscall_return": 0,
                })
            return {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v25",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "nested_pointer_scope": (
                    "exact NV0000_CTRL_CMD_SYSTEM_GET_FEATURES 4-byte featuresMask only; "
                    "raw addresses and handles omitted"),
                "payload_scope": (
                    "exact root-global SYSTEM_GET_FEATURES 4-byte mask plus fixed RM_CONTROL "
                    "headers; raw addresses and handles omitted"),
                "system_features_payload_snapshots_read": 4,
                "fd_identity_tracking": False, "errors": [], "records": rows,
            }

        def sync_boost_groups_observation(self):
            common = {
                "command": 0xA04, "flags": 0, "params_size": 2244, "status": 0,
                "hClientPresent": True, "hObjectPresent": True,
                "client_object_equal": True,
                "client_matches_prior_root_allocation": False,
                "object_matches_prior_root_allocation": False,
            }
            rows = []
            for request, packet_size, count in (
                    (0xC020462A, 32, 3), (0xC01046D3, 16, 0)):
                entry = dict(common)
                exit_phase = {**common, "syncBoostGroupCount": count}
                rows.append({
                    "tid": 1234, "fd": 7, "fd_role": "control",
                    "request": request, "packet_size": packet_size,
                    "operation": "rm_control_sync_boost_groups",
                    "entry": entry, "exit": exit_phase, "syscall_return": 0,
                })
            return {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v32",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "architecture": "x86_64",
                "pointer_bits": 64, "nested_pointers_read": True,
                "nested_pointer_scope": (
                    "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; "
                    "inline GPU IDs and group payloads omitted"),
                "payload_scope": (
                    "exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; "
                    "inline GPU IDs and group payloads omitted; raw addresses and handles omitted"),
                "sync_boost_group_payload_snapshots_read": 2,
                "fd_identity_tracking": False, "errors": [], "records": rows,
            }

        def ioctl_shape_observation(self, requests=(
                (0xC038464E, 56, "control"),
                (0xC028465E, 40, "control"),
                (0xC01046CE, 16, "gpu"),
                (0xC01046CF, 16, "gpu"))):
            rows = []
            for index, (request, size, role) in enumerate(requests):
                rows.append({
                    "tid": 1234, "fd": 7 if role == "control" else 9, "fd_role": role,
                    "request": request, "packet_size": size,
                    "operation": "selected_ioctl_payload_shape",
                    "entry_nonzero_offsets": [0, min(4, size - 1)],
                    "exit_nonzero_offsets": [0, min(8, size - 1)],
                    "changed_offsets": [min(4, size - 1), min(8, size - 1)],
                    "entry_snapshot_passed": True, "exit_snapshot_passed": True,
                    "entry": None, "exit": None, "syscall_return": 0,
                })
            return {
                "schema": "nvidia-hybrid-rm-ioctl-observer-v26",
                "trace_complete": True, "child_exit_code": 0,
                "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
                "architecture": "x86_64", "pointer_bits": 64,
                "nested_pointers_read": False,
                "snapshot_consistency": "per-task syscall stop; other threads may mutate shared packet memory",
                "fd_identity_tracking": False,
                "payload_scope": (
                    "exact requests 0xc038464e (56 bytes) and 0xc028465e (40 bytes) "
                    "on the selected control path, and 0xc01046ce/0xc01046cf (16 bytes each) "
                    "on the selected GPU path; emits only nonzero and changed byte offsets; "
                    "raw values and pointers omitted"),
                "errors": [], "records": rows,
            }

        def ioctl_shape_remote(self, requests=(
                (0xC038464E, 56, "control"),
                (0xC028465E, 40, "control"),
                (0xC01046CE, 16, "gpu"),
                (0xC01046CF, 16, "gpu"))):
            request_counts = {
                "0xc038464e": sum(request == 0xC038464E for request, _, _ in requests),
                "0xc028465e": sum(request == 0xC028465E for request, _, _ in requests),
                "0xc01046ce": sum(request == 0xC01046CE for request, _, _ in requests),
                "0xc01046cf": sum(request == 0xC01046CF for request, _, _ in requests),
            }
            remote = self.make_remote()
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            remote.update({
                "observer_exit_code": 0,
                "ioctl_shapes_capture_requested": True,
                "ioctl_shape_records_seen": bool(requests),
                "ioctl_shape_record_count": len(requests),
                "ioctl_shape_request_counts": request_counts,
                "gpu_id_info_records_seen": False,
                "attached_ids_records_seen": False,
                "probed_ids_records_seen": False,
                "channel_alloc_records_seen": False,
                "map_memory_records_seen": False,
                "rusd_alloc_records_seen": False,
                "p2p_alloc_records_seen": False,
                "p2p_control_records_seen": False,
                "binapi_control_records_seen": False,
                "device_alloc_records_seen": False,
                "subdevice_alloc_records_seen": False,
                "binapi_alloc_records_seen": False,
                "ioctl_observation": self.ioctl_shape_observation(requests),
            })
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_ioctl_shape_observation_accepts_allowlisted_redacted_payloads(self):
            observed = self.ioctl_shape_observation()
            self.assertEqual(tool.validate_ioctl_shape_capture(observed),
                             (4, {"0xc038464e": 1, "0xc028465e": 1,
                                  "0xc01046ce": 1, "0xc01046cf": 1}))
            remote, expected = self.ioctl_shape_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, ioctl_shapes_requested=True),
                "v100-reference-report-contract-valid")

        def test_ioctl_shape_evidence_summary_redacts_transient_task_and_fd_ids(self):
            observed = self.ioctl_shape_observation()
            summary = tool.summarize_ioctl_shape_capture(observed)
            self.assertEqual(summary["coverage"], "complete")
            self.assertEqual(summary["record_count"], 4)
            self.assertEqual(summary["event_lifecycle"], {
                "allocation_count": 1, "free_count": 1,
                "balanced": True, "matched_groups": 1,
                "unmatched_allocations": 0, "unmatched_frees": 0,
            })
            serialized = str(summary).lower()
            self.assertNotIn("'tid'", serialized)
            self.assertNotIn("'fd'", serialized)
            self.assertNotIn("1234", serialized)

        def test_ioctl_shape_evidence_summary_marks_partial_and_unbalanced_capture(self):
            observed = self.ioctl_shape_observation(requests=(
                (0xC01046CE, 16, "gpu"),))
            summary = tool.summarize_ioctl_shape_capture(observed)
            self.assertEqual(summary["coverage"], "partial")
            self.assertEqual(summary["event_lifecycle"]["balanced"], False)
            self.assertEqual(summary["event_lifecycle"]["unmatched_allocations"], 1)
            empty = self.ioctl_shape_observation(requests=())
            self.assertEqual(tool.summarize_ioctl_shape_capture(empty)["coverage"],
                             "inconclusive")

        def test_ioctl_shape_report_sanitizer_drops_raw_rows_even_on_rejection(self):
            observed = self.ioctl_shape_observation()
            report = {"remote": {"ioctl_observation": copy.deepcopy(observed)}}
            tool.sanitize_ioctl_shape_evidence(report, requested=True)
            persisted = str(report).lower()
            self.assertNotIn("'tid'", persisted)
            self.assertNotIn("'fd'", persisted)
            self.assertNotIn("1234", persisted)

            malformed_observation = copy.deepcopy(observed)
            malformed_observation["records"][0]["raw_payload"] = "private"
            malformed = {"remote": {"ioctl_observation": malformed_observation}}
            tool.sanitize_ioctl_shape_evidence(malformed, requested=True)
            self.assertEqual(malformed["remote"]["ioctl_observation"], {
                "schema": "nvidia-hybrid-rm-ioctl-shape-summary-v1",
                "status": "rejected",
            })

        def test_ioctl_shape_observation_can_wrap_the_isolated_kernel_phase(self):
            remote, expected = self.ioctl_shape_remote()
            remote.update({
                "phase_capture_requested": True, "phase": "kernel",
                "probe": phase_report("kernel"), "probe_exit_code": 0,
                "driver_library": {"path": phase_report("kernel")["driver_library_path"],
                                    "bytes": 1234, "sha256": "b" * 64},
            })
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, ioctl_shapes_requested=True, phase="kernel"),
                "v100-cuda-phase-report-contract-valid")
            remote["phase"] = "enumerate"
            with self.assertRaisesRegex(ValueError, "isolated"):
                tool.validate_remote_acceptance(
                    remote, expected, ioctl_shapes_requested=True, phase="enumerate")

        def test_ioctl_shapes_phase_selection_is_kernel_only_and_exclusive(self):
            tool.validate_ioctl_shapes_selection(None, ())
            tool.validate_ioctl_shapes_selection("kernel", ())
            for phase, modes in (("enumerate", ()), ("kernel", ("managed_memory",)),
                                 ("context", ())):
                with self.subTest(phase=phase, modes=modes), self.assertRaisesRegex(ValueError, "isolated"):
                    tool.validate_ioctl_shapes_selection(phase, modes)

        def test_ioctl_shape_observation_rejects_unexpected_requests_roles_and_data(self):
            remote, expected = self.ioctl_shape_remote()
            for mutate in (
                    lambda candidate: candidate["records"][0].update(request=0xC01046CE),
                    lambda candidate: candidate["records"][0].update(fd_role="gpu"),
                    lambda candidate: candidate["records"][0].update(
                        exit_nonzero_offsets=[56]),
                    lambda candidate: candidate["records"][0].update(raw_payload="secret"),
                    lambda candidate: candidate["records"][0].update(
                        entry_snapshot_passed=False)):
                observed = copy.deepcopy(remote["ioctl_observation"])
                mutate(observed)
                with self.subTest(observed=observed), self.assertRaises(ValueError):
                    tool.validate_ioctl_shape_capture(observed)

            remote["ioctl_shape_record_count"] = 2
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(
                    remote, expected, ioctl_shapes_requested=True)

        def test_ioctl_shape_capture_accepts_complete_trace_with_no_selected_calls(self):
            remote, expected = self.ioctl_shape_remote(requests=())
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, ioctl_shapes_requested=True),
                "v100-reference-report-contract-valid")

        def test_ioctl_shape_cli_requires_observer_and_isolated_default_probe(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-ioctl-shapes-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer")):
                    path.write_bytes(content)
                with self.assertRaises(SystemExit) as missing_observer:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--ioctl-shapes", "--evidence", str(root / "missing.json")])
                self.assertEqual(missing_observer.exception.code, 2)
                args = tool.parse_args(["--probe", str(probe), "--module", str(module),
                                        "--ioctl-observer", str(observer), "--ioctl-shapes",
                                        "--evidence", str(root / "report.json")])
                self.assertTrue(args.ioctl_shapes)
                self.assertTrue(tool.report_path(args)["ioctl_shapes_capture_requested"])
                for extra in ("--ioctl-trace", "--managed-memory", "--system-features"):
                    argv = ["--probe", str(probe), "--module", str(module),
                            "--ioctl-observer", str(observer), "--ioctl-shapes", extra]
                    argv += ["--evidence", str(root / (extra[2:] + ".json"))]
                    with self.subTest(extra=extra), self.assertRaises(SystemExit) as conflict:
                        tool.parse_args(argv)
                    self.assertEqual(conflict.exception.code, 2)
                phase_args = tool.parse_args([
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--ioctl-shapes",
                    "--phase", "kernel", "--evidence", str(root / "kernel-shapes.json")])
                self.assertTrue(phase_args.ioctl_shapes)
                self.assertEqual(phase_args.phase, "kernel")
                with self.assertRaises(SystemExit) as wrong_phase:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                    "--ioctl-observer", str(observer), "--ioctl-shapes",
                                    "--phase", "enumerate", "--evidence",
                                    str(root / "enumerate-shapes.json")])
                self.assertEqual(wrong_phase.exception.code, 2)

        def system_features_remote(self):
            remote = self.make_remote()
            remote.update({
                "phase_capture_requested": True, "phase": "enumerate",
                "probe": phase_report("enumerate"),
                "system_features_capture_requested": True,
                "system_features_records_seen": True,
                "system_features_record_count": 2,
                "system_features_masks": [0xA5A55A5A, 0x13579BDF],
                "fabric_status_capture_requested": False,
                "fabric_status_records_seen": False,
                "fabric_status_values": None,
                "gpu_id_info_capture_requested": False,
                "gpu_id_info_records_seen": False,
                "attached_ids_capture_requested": False,
                "attached_ids_records_seen": False,
                "probed_ids_capture_requested": False,
                "probed_ids_records_seen": False,
                "channel_alloc_records_seen": False,
                "map_memory_records_seen": False,
                "rusd_alloc_records_seen": False,
                "p2p_alloc_records_seen": False,
                "p2p_control_records_seen": False,
                "binapi_control_records_seen": False,
                "device_alloc_records_seen": False,
                "subdevice_alloc_records_seen": False,
                "binapi_alloc_records_seen": False,
                "observer_exit_code": 0,
                "ioctl_observation": self.system_features_observation(),
            })
            observer = {"bytes": 4, "sha256": "c" * 64,
                        "guest_path": "/tmp/codex-v100-ref-observer"}
            remote["artifacts_before"]["observer"] = observer
            remote["artifacts_after"][observer["guest_path"]] = {
                "bytes": observer["bytes"], "sha256": observer["sha256"]}
            expected = {name: {"bytes": 3, "sha256": "a" * 64}
                        for name in ("probe", "module")}
            expected["observer"] = {"bytes": 4, "sha256": "c" * 64}
            return remote, expected

        def test_system_features_observation_requires_exact_redacted_mask(self):
            observed = self.system_features_observation()
            self.assertEqual(tool.validate_system_features_capture(
                observed), (2, [0xA5A55A5A, 0x13579BDF]))
            for mutate in (
                lambda candidate: candidate["records"][0]["exit"].update(featuresMask=-1),
                lambda candidate: candidate["records"][0]["entry"].update(params_address=123),
                lambda candidate: candidate.update(system_features_payload_snapshots_read=3),
            ):
                candidate = copy.deepcopy(observed)
                mutate(candidate)
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    tool.validate_system_features_capture(candidate)

        def test_sync_boost_groups_observation_reads_only_bounded_count(self):
            observed = self.sync_boost_groups_observation()
            self.assertEqual(tool.validate_sync_boost_groups_capture(observed), (2, [3, 0]))
            for mutate in (
                lambda candidate: candidate["records"][0]["exit"].update(syncBoostGroupCount=17),
                lambda candidate: candidate["records"][0]["exit"].update(params_address=123),
                lambda candidate: candidate.update(sync_boost_group_payload_snapshots_read=3),
                lambda candidate: candidate["records"][0]["exit"].update(syncBoostGroupIds=[1]),
            ):
                candidate = copy.deepcopy(observed)
                mutate(candidate)
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    tool.validate_sync_boost_groups_capture(candidate)

        def test_remote_sync_boost_groups_capture_isolated_and_cross_checked(self):
            remote, expected = self.system_features_remote()
            observed = self.sync_boost_groups_observation()
            remote.update({
                "system_features_capture_requested": False,
                "system_features_records_seen": False,
                "system_features_masks": None,
                "sync_boost_groups_capture_requested": True,
                "sync_boost_groups_records_seen": True,
                "sync_boost_groups_record_count": 2,
                "sync_boost_group_counts": [3, 0],
                "sync_boost_group_payload_snapshots_read": 2,
                "ioctl_observation": observed,
            })
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, sync_boost_groups_requested=True, phase="enumerate"),
                "v100-cuda-phase-report-contract-valid")
            remote["sync_boost_group_counts"] = [3, 1]
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(
                    remote, expected, sync_boost_groups_requested=True, phase="enumerate")

        def test_remote_system_features_capture_isolated_and_cross_checked(self):
            remote, expected = self.system_features_remote()
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, system_features_requested=True, phase="enumerate"),
                "v100-cuda-phase-report-contract-valid")
            remote["system_features_masks"] = [1, 2]
            with self.assertRaisesRegex(ValueError, "summary differs"):
                tool.validate_remote_acceptance(
                    remote, expected, system_features_requested=True, phase="enumerate")

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
                binapi_control_requested=True), "v100-reference-report-contract-valid")

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
                binapi_control_requested=True), "v100-reference-report-contract-valid")

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
                p2p_control_requested=True), "v100-reference-report-contract-valid")

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
                "v100-reference-report-contract-valid")

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
                "v100-reference-report-contract-valid")
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
                "v100-reference-report-contract-valid")

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
                "v100-reference-report-contract-valid")

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
                "v100-reference-report-contract-valid")

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
                "nested_pointers_read": False, "fd_identity_tracking": True,
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
                "v100-reference-report-contract-valid")
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
                remote, expected, rm_control_requested=True), "v100-reference-report-contract-valid")
            remote["ioctl_observation"]["payload_scope"] = "all RM payloads"
            with self.assertRaisesRegex(ValueError, "scope"):
                tool.validate_remote_acceptance(remote, expected, rm_control_requested=True)

        def test_accepts_rm_control_with_only_explicit_metadata_payload(self):
            remote, expected = self.rm_control_remote(attached_ids=True)
            self.assertEqual(tool.validate_remote_acceptance(
                remote, expected, attached_ids_requested=True,
                rm_control_requested=True), "v100-reference-report-contract-valid")
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
                             "v100-reference-report-contract-valid")
            remote["ioctl_trace"]["trace"]["trace_complete"] = False
            with self.assertRaises(ValueError):
                tool.validate_remote_acceptance(remote, expected, trace_requested=True)

    class TransportContracts(unittest.TestCase):
        def test_embedded_v100_phase_checks_compute_process_counts_at_all_boundaries(self):
            script = tool.REMOTE_ROOT_SCRIPT
            compile(script, "<embedded-v100-guest-runner>", "exec")
            self.assertIn("--query-compute-apps=pid", script)
            self.assertIn("compute_process_count_before", script)
            self.assertIn("compute_process_count_prelaunch", script)
            self.assertIn("compute_process_count_after", script)

        def test_default_probe_passes_the_runner_contract_preflight(self):
            contract = tool.validate_probe_contract(tool.DEFAULT_PROBE)
            self.assertEqual(contract["schema"], "nvidia-hybrid-probe-contract-v1")
            self.assertEqual(contract["probe_report_schema"], "nvidia-hybrid-probe-v2")

        def test_v100_runner_defaults_to_current_probe_bundle(self):
            self.assertEqual(tool.DEFAULT_PROBE,
                             ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe")
            self.assertEqual(tool.DEFAULT_MODULE,
                             ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin")

        def test_v100_probe_pins_match_the_shared_acceptance_and_software_suite(self):
            acceptance_spec = importlib.util.spec_from_file_location(
                "shared_hybrid_acceptance", ROOT / "tests/run_hybrid_acceptance.py")
            acceptance = importlib.util.module_from_spec(acceptance_spec)
            acceptance_spec.loader.exec_module(acceptance)
            suite_spec = importlib.util.spec_from_file_location(
                "shared_software_suite", ROOT / "tools/run_software_test_suite.py")
            suite = importlib.util.module_from_spec(suite_spec)
            suite_spec.loader.exec_module(suite)
            self.assertEqual(tool.PINNED_PROBE_SHA256, acceptance.PINNED_PROBE_SHA256)
            self.assertEqual(tool.PINNED_MODULE_SHA256, acceptance.PINNED_MODULE_SHA256)
            self.assertEqual(tool.PINNED_PROBE_SHA256, suite.PINNED_PROBE_SHA256)
            trust = tool.verify_pinned_probe_build(
                tool.identity(tool.DEFAULT_PROBE), tool.identity(tool.DEFAULT_MODULE))
            self.assertEqual(trust["status"], "trusted-pinned-build")

        def test_v100_probe_build_gate_rejects_a_substituted_fatbin(self):
            with self.assertRaisesRegex(ValueError, "fatbin hash differs from the pinned probe build"):
                tool.verify_pinned_probe_build(
                    {"sha256": tool.PINNED_PROBE_SHA256}, {"sha256": "0" * 64})

        def test_v100_probe_preflight_rejects_unpinned_bundle(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-unpinned-probe-") as temp_dir:
                root = Path(temp_dir)
                probe, module, evidence = root / "probe", root / "module", root / "evidence.json"
                probe.write_bytes(b"synthetic probe")
                module.write_bytes(b"synthetic fatbin")
                with (patch.object(tool, "fetch_pc3_sudo_secret",
                                   side_effect=AssertionError("credential access must not occur")) as fetch,
                      patch.object(tool, "validate_probe_contract",
                                   side_effect=AssertionError("probe execution must not occur")) as contract):
                    result = tool.main(["--probe", str(probe), "--module", str(module),
                                        "--evidence", str(evidence)])
                fetch.assert_not_called()
                contract.assert_not_called()
                self.assertEqual(result, 2)
                report = __import__("json").loads(evidence.read_text())
                self.assertEqual(report.get("failure_stage"), "local_preflight")
                self.assertIn("probe hash differs from the pinned probe build",
                              report.get("error", ""))
                self.assertNotIn("payload_staging", report)

        def test_current_probe_builder_and_historical_guest_reference_are_independently_pinned(self):
            self.assertEqual(build_tool.DEFAULT_OUTPUT,
                             ROOT / "build/probe-cuda129-sm70v-sm120a-v2")
            self.assertEqual(tool.DEFAULT_PROBE.parent,
                             ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged")

        def test_incompatible_probe_contract_fails_before_credential_or_remote_access(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-contract-preflight-") as temp_dir:
                root = Path(temp_dir)
                probe, module, evidence = root / "probe", root / "module", root / "evidence.json"
                probe.write_text(
                    f"#!{sys.executable}\n"
                    "import json\n"
                    "print(json.dumps({'schema':'nvidia-hybrid-probe-contract-v1',"
                    "'contract_version':1,'probe_report_schema':'nvidia-hybrid-probe-v2',"
                    "'probe_report_fields':['devices'],'device_report_fields':[]}))\n"
                )
                probe.chmod(0o700)
                module.write_bytes(b"test fatbin")
                with (patch.object(tool, "PINNED_PROBE_SHA256",
                                   hashlib.sha256(probe.read_bytes()).hexdigest()),
                      patch.object(tool, "PINNED_MODULE_SHA256",
                                   hashlib.sha256(module.read_bytes()).hexdigest()),
                      patch.object(tool, "fetch_pc3_sudo_secret",
                                   side_effect=AssertionError("credential access must not occur")) as fetch):
                    result = tool.main(["--probe", str(probe), "--module", str(module),
                                        "--evidence", str(evidence)])
                fetch.assert_not_called()
                self.assertEqual(result, 2)
                report = __import__("json").loads(evidence.read_text())
                self.assertEqual(report.get("failure_stage"), "local_preflight")
                self.assertIn("CUDA probe report contract is incompatible", report.get("error", ""))
                self.assertEqual(report["probe_build_trust"]["status"], "trusted-pinned-build")
                self.assertIn("not independently attested",
                              report["cuda_execution_validation_state"])
                self.assertNotIn("payload_staging", report)
                self.assertNotIn("pc3_ssh_exit_code", report)

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

        def test_fabric_status_capture_requires_isolated_enumeration_observer(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-fabric-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as missing_observer:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--phase", "enumerate", "--fabric-status",
                                     "--evidence", str(root / "missing.json")])
                self.assertEqual(missing_observer.exception.code, 2)
                args = tool.parse_args([
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--phase", "enumerate",
                    "--fabric-status", "--evidence", str(root / "report.json")])
                self.assertTrue(args.fabric_status)
                self.assertTrue(tool.report_path(args)["fabric_status_capture_requested"])
                for extra in ("--rm-control", "--ioctl-trace", "--gpu-id-info"):
                    with self.subTest(extra=extra), self.assertRaises(SystemExit) as conflict:
                        tool.parse_args([
                            "--probe", str(probe), "--module", str(module),
                            "--ioctl-observer", str(observer), "--phase", "enumerate",
                            "--fabric-status", extra,
                            "--evidence", str(root / ("conflict-" + extra[2:] + ".json"))])
                    self.assertEqual(conflict.exception.code, 2)

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

        def test_system_features_capture_requires_isolated_enumeration_observer(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-system-features-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as missing_observer:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--phase", "enumerate", "--system-features",
                                     "--evidence", str(root / "missing.json")])
                self.assertEqual(missing_observer.exception.code, 2)
                args = tool.parse_args([
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--phase", "enumerate",
                    "--system-features", "--evidence", str(root / "report.json")])
                self.assertTrue(args.system_features)
                self.assertTrue(tool.report_path(args)["system_features_capture_requested"])
                for extra in ("--rm-control", "--ioctl-trace", "--fabric-status"):
                    with self.subTest(extra=extra), self.assertRaises(SystemExit) as conflict:
                        tool.parse_args([
                            "--probe", str(probe), "--module", str(module),
                            "--ioctl-observer", str(observer), "--phase", "enumerate",
                            "--system-features", extra,
                            "--evidence", str(root / ("conflict-" + extra[2:] + ".json"))])
                    self.assertEqual(conflict.exception.code, 2)

        def test_sync_boost_groups_capture_requires_isolated_enumeration_observer(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-sync-boost-cli-") as temp_dir:
                root = Path(temp_dir)
                probe, module, observer = (root / "probe", root / "module", root / "observer")
                probe.write_bytes(b"probe")
                module.write_bytes(b"fatbin")
                observer.write_bytes(b"observer")
                with self.assertRaises(SystemExit) as missing_observer:
                    tool.parse_args(["--probe", str(probe), "--module", str(module),
                                     "--phase", "enumerate", "--sync-boost-groups",
                                     "--evidence", str(root / "missing.json")])
                self.assertEqual(missing_observer.exception.code, 2)
                args = tool.parse_args([
                    "--probe", str(probe), "--module", str(module),
                    "--ioctl-observer", str(observer), "--phase", "enumerate",
                    "--sync-boost-groups", "--evidence", str(root / "report.json")])
                self.assertTrue(args.sync_boost_groups)
                self.assertTrue(tool.report_path(args)["sync_boost_groups_capture_requested"])
                for extra in ("--rm-control", "--ioctl-trace", "--system-features"):
                    with self.subTest(extra=extra), self.assertRaises(SystemExit) as conflict:
                        tool.parse_args([
                            "--probe", str(probe), "--module", str(module),
                            "--ioctl-observer", str(observer), "--phase", "enumerate",
                            "--sync-boost-groups", extra,
                            "--evidence", str(root / ("conflict-" + extra[2:] + ".json"))])
                    self.assertEqual(conflict.exception.code, 2)

        def test_guest_ssh_uses_strict_pinned_host_key_and_no_agent_config(self):
            argv = tool.guest_ssh_base("/var/lib/pc3-v100-vm/id_ed25519",
                                       "/tmp/codex-pc3-vm-known_hosts")
            joined = " ".join(argv)
            self.assertIn("-F /dev/null", joined)
            self.assertIn("StrictHostKeyChecking=yes", joined)
            self.assertIn("-i /var/lib/pc3-v100-vm/id_ed25519", joined)
            self.assertIn("-p 22223", joined)

        def test_pc3_host_ssh_enables_password_auth_only_for_forced_executable_askpass(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-askpass-contract-") as temp_dir:
                askpass = Path(temp_dir) / "askpass"
                askpass.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                askpass.chmod(0o700)
                with patch.dict(os.environ, {"SSH_ASKPASS": str(askpass),
                                             "SSH_ASKPASS_REQUIRE": "force",
                                             "DISPLAY": ":0"}):
                    argv = tool.pc3_ssh_base("pc3@192.168.1.126", "pc3")
            self.assertIn("-oBatchMode=no", argv)
            self.assertIn("-oPubkeyAuthentication=no", argv)
            self.assertIn("-oPreferredAuthentications=password", argv)
            self.assertIn("-oStrictHostKeyChecking=yes", argv)

        def test_pc3_host_ssh_keeps_batch_mode_without_forced_executable_askpass(self):
            with patch.dict(os.environ, {"SSH_ASKPASS": "/missing/askpass",
                                         "SSH_ASKPASS_REQUIRE": "prefer",
                                         "DISPLAY": ":0"}):
                argv = tool.pc3_ssh_base("pc3@192.168.1.126", "pc3")
            self.assertIn("-oBatchMode=yes", argv)
            self.assertNotIn("-oBatchMode=no", argv)

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
            self.assertIn("def validate_ioctl_shapes_selection(phase, other_modes):",
                          tool.REMOTE_ROOT_SCRIPT)
            import ast
            outer = ast.parse(tool.REMOTE_ROOT_SCRIPT)
            run_code = next(node.value.value for node in ast.walk(outer)
                            if isinstance(node, ast.Assign) and
                            any(isinstance(target, ast.Name) and target.id == "run_code"
                                for target in node.targets) and isinstance(node.value, ast.Constant))
            inventory_code = next(node.value.value for node in ast.walk(outer)
                                  if isinstance(node, ast.Assign) and
                                  any(isinstance(target, ast.Name) and target.id == "inventory_code"
                                      for target in node.targets) and
                                  isinstance(node.value, ast.Constant))
            compile(inventory_code, "<guest-inventory>", "exec")
            self.assertIn("importlib.machinery.SourceFileLoader", run_code)
            compile(run_code, "<guest-cuda-runner>", "exec")
            self.assertIn("--query-compute-apps=pid", inventory_code)
            self.assertIn("--query-compute-apps=pid", run_code)
            self.assertIn('"--map-memory","--gpu-path","/dev/nvidia0"', run_code)
            self.assertIn("map_memory_capture_requested", tool.REMOTE_ROOT_SCRIPT)
            self.assertIn('"--rusd-alloc","--gpu-path","/dev/nvidia0"', run_code)
            self.assertIn("rusd_alloc_capture_requested", tool.REMOTE_ROOT_SCRIPT)
            self.assertIn('"--rm-control-headers"', run_code)
            self.assertIn("rm_control_headers_records_seen", tool.REMOTE_ROOT_SCRIPT)
            self.assertIn('"--system-features"', run_code)
            self.assertIn("system_features_masks", tool.REMOTE_ROOT_SCRIPT)
            self.assertIn('"--sync-boost-groups"', run_code)
            self.assertIn("sync_boost_group_counts", tool.REMOTE_ROOT_SCRIPT)
            unpack = next(node.targets[0] for node in ast.walk(ast.parse(run_code))
                          if isinstance(node, ast.Assign) and
                          isinstance(node.targets[0], (ast.Tuple, ast.List)) and
                          isinstance(node.value, ast.Subscript))
            nested_arg_count = len(unpack.elts)
            outer_call = next(node for node in ast.walk(outer)
                              if isinstance(node, ast.Call) and
                              isinstance(node.func, ast.Name) and node.func.id == "guest_json" and
                              node.args and isinstance(node.args[0], ast.Name) and
                              node.args[0].id == "run_code")
            args_keyword = next(item.value for item in outer_call.keywords if item.arg == "args")
            self.assertEqual(nested_arg_count, len(args_keyword.elts))

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

        def test_r58019607_override_is_hash_pinned_and_only_allows_feature_enumeration(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-r580-libcuda-") as temporary:
                root = Path(temporary)
                probe, module, observer = root / "probe", root / "module", root / "observer"
                libcuda = root / "libcuda.so.580.196.07"
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer"), (libcuda, b"pinned-test-image")):
                    path.write_bytes(content)
                digest = hashlib.sha256(libcuda.read_bytes()).hexdigest()
                with patch.object(tool, "R580_19607_LIBCUDA_BYTES", libcuda.stat().st_size), \
                     patch.object(tool, "R580_19607_LIBCUDA_SHA256", digest):
                    options = ["--phase", "enumerate", "--probe", str(probe),
                               "--module", str(module), "--ioctl-observer", str(observer),
                               "--system-features", "--libcuda-override", str(libcuda),
                               "--evidence", str(root / "accepted.json")]
                    args = tool.parse_args(options)
                    identity = tool.report_path(args)["libcuda_override"]
                    self.assertEqual(identity["sha256"], digest)
                    self.assertEqual(identity["bytes"], len(b"pinned-test-image"))
                    with self.assertRaises(SystemExit):
                        tool.parse_args([item for item in options if item != "--system-features"])
                    wrong = options.copy()
                    wrong[wrong.index("enumerate")] = "context"
                    with self.assertRaises(SystemExit):
                        tool.parse_args(wrong)

        def test_r58019607_override_allows_only_pinned_context_device_alloc_observation(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-r580-context-") as temporary:
                root = Path(temporary)
                probe, module, observer = root / "probe", root / "module", root / "observer"
                libcuda = root / "libcuda.so.580.196.07"
                for path, content in ((probe, b"probe"), (module, b"fatbin"),
                                      (observer, b"observer"), (libcuda, b"pinned-context-image")):
                    path.write_bytes(content)
                digest = hashlib.sha256(libcuda.read_bytes()).hexdigest()
                with patch.object(tool, "R580_19607_LIBCUDA_BYTES", libcuda.stat().st_size), \
                     patch.object(tool, "R580_19607_LIBCUDA_SHA256", digest):
                    options = ["--phase", "context", "--probe", str(probe),
                               "--module", str(module), "--ioctl-observer", str(observer),
                               "--device-alloc", "--libcuda-override", str(libcuda),
                               "--evidence", str(root / "accepted.json")]
                    args = tool.parse_args(options)
                    self.assertEqual(args.phase, "context")
                    self.assertTrue(args.device_alloc)
                    self.assertFalse(args.system_features)
                    missing_capture = [item for item in options if item != "--device-alloc"]
                    with self.assertRaises(SystemExit):
                        tool.parse_args(missing_capture)
                    wrong_capture = options.copy()
                    wrong_capture[wrong_capture.index("--device-alloc")] = "--system-features"
                    with self.assertRaises(SystemExit):
                        tool.parse_args(wrong_capture)
                    kernel_options = options.copy()
                    kernel_options[kernel_options.index("context")] = "kernel"
                    kernel_args = tool.parse_args(kernel_options)
                    self.assertEqual(kernel_args.phase, "kernel")
                    self.assertTrue(kernel_args.device_alloc)
                    missing_kernel_capture = [item for item in kernel_options
                                              if item != "--device-alloc"]
                    with self.assertRaises(SystemExit):
                        tool.parse_args(missing_kernel_capture)

        def test_r58019607_override_rejects_symlink_and_wrong_hash(self):
            with tempfile.TemporaryDirectory(prefix="pc3-v100-r580-libcuda-identity-") as temporary:
                root = Path(temporary)
                actual = root / "actual"
                actual.write_bytes(b"not-the-pinned-library")
                link = root / "libcuda.so.580.196.07"
                link.symlink_to(actual)
                with self.assertRaisesRegex(ValueError, "unavailable"):
                    tool.r58019607_libcuda_identity(link)
                link.unlink()
                link.write_bytes(b"not-the-pinned-library")
                with patch.object(tool, "R580_19607_LIBCUDA_BYTES", link.stat().st_size), \
                     patch.object(tool, "R580_19607_LIBCUDA_SHA256", "0" * 64):
                    with self.assertRaisesRegex(ValueError, "pinned R580.196.07 image"):
                        tool.r58019607_libcuda_identity(link)

        def test_r58019607_guest_load_uses_only_private_ld_library_path(self):
            worker = tool.REMOTE_ROOT_SCRIPT
            self.assertIn('expected_override_artifacts = {"probe", "module", "observer", "libcuda"}', worker)
            self.assertIn('"LD_LIBRARY_PATH":libcuda_temp.name', worker)
            self.assertIn('env=probe_env,timeout=100,check=False', worker)
            self.assertIn('env=env,timeout=15', worker)
            self.assertIn('library_digest.hexdigest()!=libcuda_sha256', worker)
            self.assertIn('libcuda_temp.cleanup()', worker)
            self.assertIn('"libcuda_override_temp_cleanup_passed":None', worker)

        def test_r58019607_exact_system_driver_mismatch_is_a_valid_negative_observation(self):
            artifact_specs = {
                "probe": {"bytes": 5, "sha256": "a" * 64},
                "module": {"bytes": 6, "sha256": "b" * 64},
                "observer": {"bytes": 8, "sha256": "c" * 64},
                "libcuda": {"bytes": tool.R580_19607_LIBCUDA_BYTES,
                            "sha256": tool.R580_19607_LIBCUDA_SHA256},
            }
            before = {}
            after = {}
            for name, item in artifact_specs.items():
                path = f"/tmp/codex-v100-ref-{name}.libcuda" if name == "libcuda" else f"/tmp/codex-v100-ref-{name}"
                before[name] = {**item, "guest_path": path}
                after[path] = {"bytes": item["bytes"], "sha256": item["sha256"]}
            probe = {"schema": "nvidia-cuda-driver-phase-v1", "status": "phase-failed",
                     "phase": "enumerate", "driver_library_path": before["libcuda"]["guest_path"],
                     "error": "cuInit failed with CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH)",
                     "selected_device": None}
            remote = {
                "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1", "host": "pc3",
                "qualification": "probe-executed", "libcuda_override_requested": True,
                "libcuda_override_temp_cleanup_passed": True,
                "phase": "enumerate", "system_features_capture_requested": True,
                "execution_scope": {key: False for key in
                                    ("guest_driver_changed", "module_loaded", "vm_management_issued", "pci_binding_changed")},
                "guest": {"hostname": "pc3-v100", "name": "Tesla V100-SXM2-16GB",
                          "driver_version": "580.178.04", "pci": "0000:00:05.0",
                          "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e"},
                "guest_after": {"hostname": "pc3-v100", "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e",
                                "pci": "0000:00:05.0", "driver_version": "580.178.04",
                                "compute_process_count": 0},
                "compute_process_count_prelaunch": 0,
                "compute_process_query_after_valid": True,
                "compute_process_count_after_probe": 0,
                "guest_cleanup_passed": True, "payload_file_cleanup_passed": True,
                "probe": probe, "probe_exit_code": 2,
                "driver_library": {"path": probe["driver_library_path"],
                                   "bytes": tool.R580_19607_LIBCUDA_BYTES,
                                   "sha256": tool.R580_19607_LIBCUDA_SHA256},
                "artifacts_before": before, "artifacts_after": after,
                "ioctl_observation": {"schema": "nvidia-hybrid-rm-ioctl-observer-v25",
                                      "errors": [], "child_exit_code": 2},
            }
            self.assertEqual(
                tool.validate_r58019607_stock_v100_rejection(remote, artifact_specs),
                "r58019607-rejection-report-contract-valid")
            remote["guest"]["pci"] = "0000:81:00.0"
            with self.assertRaisesRegex(ValueError, "pinned stock V100 guest"):
                tool.validate_r58019607_stock_v100_rejection(remote, artifact_specs)
            remote["guest"]["pci"] = "0000:00:05.0"
            remote["guest"]["uuid"] = "GPU-12345678-1234-1234-1234-123456789abc"
            with self.assertRaisesRegex(ValueError, "pinned stock V100 guest"):
                tool.validate_r58019607_stock_v100_rejection(remote, artifact_specs)
            remote["guest"]["uuid"] = "GPU-42d06a85-027a-75ea-7857-a8de27ad465e"
            remote["probe"]["error"] = "cuInit failed with CUresult=999 (CUDA_ERROR_UNKNOWN)"
            with self.assertRaisesRegex(ValueError, "exact pre-enumeration"):
                tool.validate_r58019607_stock_v100_rejection(remote, artifact_specs)


class DirectPc3TransportTests(unittest.TestCase):
    def test_transport_failure_classification_is_fixed_and_does_not_retain_stderr(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_failure_class", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw = b"sudo: interactive authentication is required; token=private-value"
        result = module.classify_pc3_transport_failure(raw)
        self.assertEqual(result, "sudo_interactive_auth_required")
        self.assertNotIn("private-value", result)
        self.assertEqual(module.classify_pc3_transport_failure(
            "ssh: Permission denied (publickey)."), "ssh_public_key_auth_denied")
        self.assertEqual(module.classify_pc3_transport_failure(
            "ssh: Permission denied (publickey,password)."), "ssh_public_key_auth_denied")
        self.assertEqual(module.classify_pc3_transport_failure(
            "unrecognized secret payload"), "unclassified_transport_failure")
        self.assertIsNone(module.classify_pc3_transport_failure(b""))

    def test_payload_upload_failure_record_keeps_only_class_exit_and_stderr_digest(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_upload_failure", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        secret = b"private-marker-never-retain"
        stderr = b"ssh: Permission denied (publickey). " + secret
        result = module.payload_upload_failure_fields(255, stderr)
        self.assertEqual(result["failure_stage"], "pc3_payload_upload")
        self.assertEqual(result["pc3_upload_ssh_exit_code"], 255)
        self.assertEqual(result["pc3_upload_failure_class"], "ssh_public_key_auth_denied")
        self.assertEqual(result["pc3_upload_stderr_sha256"], hashlib.sha256(stderr).hexdigest())
        self.assertNotIn(secret.decode(), repr(result))
        self.assertEqual(module.payload_upload_failure_fields(
            None, process_failure="timeout")["pc3_upload_failure_class"],
            "ssh_process_timed_out")
        self.assertEqual(module.payload_upload_failure_fields(
            None, process_failure="start")["pc3_upload_failure_class"],
            "ssh_process_start_failed")
        self.assertEqual(module.payload_upload_failure_fields(
            2, b"")["pc3_upload_failure_class"],
            "ssh_failed_without_classifiable_stderr")

    def test_direct_pc3_preflight_checks_ssh_then_sudo_without_retaining_stderr(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_preflight", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        secret_marker = b"private-sudo-diagnostic-marker"
        outcomes = [
            subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"sudo: a password is required; " + secret_marker),
        ]
        with patch.object(module.subprocess, "run", side_effect=outcomes) as remote:
            result = module.direct_pc3_preflight(["ssh", "--", "pc3@pc3"])
        self.assertEqual([call.args[0][-1] for call in remote.call_args_list],
                         ["true", "sudo -n true"])
        self.assertEqual(result["failure_stage"], "pc3_sudo_preflight")
        self.assertIs(result["pc3_ssh_preflight_passed"], True)
        self.assertIs(result["pc3_sudo_preflight_passed"], False)
        self.assertEqual(result["pc3_sudo_preflight_exit_code"], 1)
        self.assertEqual(result["pc3_sudo_preflight_failure_class"],
                         "sudo_interactive_auth_required")
        self.assertEqual(result["pc3_sudo_preflight_stderr_sha256"],
                         hashlib.sha256(b"sudo: a password is required; " + secret_marker).hexdigest())
        self.assertNotIn(secret_marker.decode(), repr(result))
        self.assertEqual(remote.call_args_list[0].kwargs["stdin"], module.subprocess.DEVNULL)

    def test_direct_pc3_preflight_reports_ssh_auth_failure_without_running_sudo(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_preflight_auth", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        denied = b"Permission denied (publickey); private-marker"
        with patch.object(module.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 255, stdout=b"", stderr=denied)) as remote:
            result = module.direct_pc3_preflight(["ssh", "--", "pc3@pc3"])
        remote.assert_called_once()
        self.assertEqual(result["failure_stage"], "pc3_ssh_preflight")
        self.assertIs(result["pc3_ssh_preflight_passed"], False)
        self.assertEqual(result["pc3_ssh_preflight_failure_class"], "ssh_public_key_auth_denied")
        self.assertEqual(result["pc3_ssh_preflight_stderr_sha256"], hashlib.sha256(denied).hexdigest())
        self.assertNotIn("private-marker", repr(result))

    def test_main_stops_before_payload_when_direct_sudo_preflight_fails(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_main_preflight", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="pc3-v100-sudo-preflight-") as temp_dir:
            root = Path(temp_dir)
            probe, fatbin, evidence = root / "probe", root / "module", root / "report.json"
            probe.write_bytes(b"synthetic pinned probe")
            fatbin.write_bytes(b"synthetic pinned fatbin")
            identity = root / "fake-pc3-key"
            failure = {
                "failure_stage": "pc3_sudo_preflight",
                "pc3_sudo_preflight_exit_code": 1,
                "pc3_sudo_preflight_failure_class": "sudo_interactive_auth_required",
                "pc3_sudo_preflight_stderr_sha256": "a" * 64,
            }
            with (patch.object(module, "verify_pinned_probe_build",
                               return_value={"status": "trusted-pinned-build"}),
                  patch.object(module, "validate_probe_contract", return_value={"schema": "test"}),
                  patch.object(module, "validate_direct_identity_file", return_value=identity),
                  patch.object(module, "direct_pc3_preflight", return_value=failure) as preflight,
                  patch.object(module.subprocess, "run",
                               side_effect=AssertionError("payload transfer must not run")) as remote):
                result = module.main([
                    "--direct-pc3", "--identity-file", str(identity),
                    "--probe", str(probe), "--module", str(fatbin),
                    "--evidence", str(evidence),
                ])
            self.assertEqual(result, 2)
            preflight.assert_called_once()
            remote.assert_not_called()
            report = __import__("json").loads(evidence.read_text())
            self.assertEqual(report["failure_stage"], "pc3_sudo_preflight")
            self.assertEqual(report["pc3_sudo_preflight_failure_class"],
                             "sudo_interactive_auth_required")
            self.assertNotIn("payload_staging", report)

    def test_direct_route_is_key_only_and_pinned_to_pc3(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_direct", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        argv = module.pc3_direct_ssh_base()
        encoded = " ".join(argv)
        self.assertEqual(argv[-1], "pc3@pc3")
        self.assertIn("-oPreferredAuthentications=publickey", encoded)
        self.assertIn("-oPasswordAuthentication=no", encoded)
        self.assertIn("-oStrictHostKeyChecking=yes", encoded)
        self.assertIn("-oHostKeyAlias=pc3", encoded)
        with self.assertRaisesRegex(ValueError, "pinned PC3 SSH route"):
            module.pc3_direct_ssh_base("pc1@pc1", "pc1")

    def test_direct_identity_is_private_and_binds_only_the_pinned_route(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_identity", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            identity = ssh_dir / "pc3-key"
            identity.write_text("test-key-material", encoding="utf-8")
            identity.chmod(0o600)
            with patch.object(module.Path, "home", return_value=home):
                argv = module.pc3_direct_ssh_base(identity_file=identity)
                self.assertIn("-i", argv)
                self.assertIn(str(identity), argv)
                self.assertIn("-oIdentitiesOnly=yes", argv)
                self.assertEqual(argv[-1], "pc3@pc3")
                with self.assertRaisesRegex(ValueError, "pinned PC3 SSH route"):
                    module.pc3_direct_ssh_base("pc1@pc1", "pc1", identity)
                outside = home / "outside-key"
                outside.write_text("test-key-material", encoding="utf-8")
                outside.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "in ~/.ssh"):
                    module.pc3_direct_ssh_base(identity_file=outside)

    def test_direct_mode_never_accepts_legacy_credential_source_options(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_direct_args", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=ROOT / "evidence") as temporary:
            evidence = Path(temporary) / "result.json"
            args = module.parse_args(["--direct-pc3", "--evidence", str(evidence)])
            self.assertTrue(args.direct_pc3)
            self.assertIsNone(args.credential_host)
            self.assertIsNone(args.credential_file)
            report = module.report_path(args)
            self.assertEqual(report["transport_mode"], "pc3-direct-key-sudo-n")
            self.assertIsNone(report["credential_host"])
            with self.assertRaises(SystemExit):
                module.parse_args(["--identity-file", "/tmp/not-a-pc3-key",
                                  "--evidence", str(evidence)])
            with self.assertRaises(SystemExit):
                module.parse_args(["--direct-pc3", "--credential-host", "gx10-e526",
                                  "--evidence", str(evidence)])

    def test_direct_cleanup_uses_direct_route_only(self):
        spec = importlib.util.spec_from_file_location("pc3_guest_runner_direct_cleanup", TOOL_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=b'{"cleanup_passed":true,"remaining":false}', stderr=b"")
        with (patch.object(module, "pc3_direct_ssh_base", return_value=["ssh", "--", "pc3@pc3"]) as direct,
              patch.object(module, "pc3_ssh_base") as legacy,
              patch.object(module.subprocess, "run", return_value=completed) as remote):
            passed = module.cleanup_pc3_payload("pc3@pc3", "pc3",
                                                "/tmp/codex-v100-payload-" + "a" * 32 + ".json",
                                                "b" * 64, direct_pc3=True)
        self.assertTrue(passed)
        direct.assert_called_once_with("pc3@pc3", "pc3", None)
        legacy.assert_not_called()
        self.assertEqual(remote.call_args.args[0][:3], ["ssh", "--", "pc3@pc3"])


if __name__ == "__main__":
    unittest.main()
