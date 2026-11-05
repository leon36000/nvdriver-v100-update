from __future__ import annotations

import ast
import contextlib
import io
import importlib.util
import json
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_pc3_rtx5080_ioctl_shape_reference.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_rtx5080_ioctl_shape_reference", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("RTX 5080 ioctl-shape reference runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(request: int, role: str, size: int, tid: int = 91, fd: int = 7):
    return {
        "tid": tid, "fd": fd, "fd_role": role, "request": request,
        "packet_size": size, "operation": "selected_ioctl_payload_shape",
        "entry_nonzero_offsets": [], "exit_nonzero_offsets": [],
        "changed_offsets": [], "entry_snapshot_passed": True,
        "exit_snapshot_passed": True, "entry": None, "exit": None,
        "syscall_return": 0,
    }


def valid_observation(gpu_path: str = "/dev/nvidia2"):
    expected_scope = (
        "exact requests 0xc038464e (56 bytes) and 0xc028465e (40 bytes) on the selected "
        "control path, and 0xc01046ce/0xc01046cf (16 bytes each) on the selected GPU path; "
        "emits only nonzero and changed byte offsets; raw values and pointers omitted")
    records = [record(0xc038464e, "control", 56),
               record(0xc028465e, "control", 40),
               record(0xc01046ce, "gpu", 16),
               record(0xc01046cf, "gpu", 16)]
    return {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v26",
        "trace_complete": True, "child_exit_code": 0,
        "control_path": "/dev/nvidiactl", "gpu_path": gpu_path,
        "architecture": "x86_64", "pointer_bits": 64,
        "nested_pointers_read": False,
        "snapshot_consistency": "per-task syscall stop; other threads may mutate shared packet memory",
        "fd_identity_tracking": False, "payload_scope": expected_scope,
        "records": records, "errors": [],
    }


def event_cleanup_row(operation: str, role: str, request: int, tid: int = 91,
                      fd: int = 7, **extra):
    row = {
        "tid": tid, "fd": fd, "fd_role": role, "request": request,
        "packet_size": 0, "operation": operation,
        "entry": None, "exit": None, "syscall_return": 0,
    }
    row.update(extra)
    return row


def valid_event_cleanup_observation(gpu_path: str = "/dev/nvidia2"):
    observed = valid_observation(gpu_path)
    observed.update({
        "schema": "nvidia-hybrid-rm-ioctl-observer-v27",
        "fd_identity_tracking": True,
        "payload_scope": (
            "selected event ioctls plus a fixed 16-byte root-free equality predicate "
            "and selected descriptor lifecycle; raw payload bytes and handle values "
            "omitted; temporary TID/FD/file-identity fields require summarization before evidence persistence"),
        "fd_lifecycle_scope": (
            "selected control/GPU open, dup, fcntl-dup, close, and close_range metadata; "
            "clone tasks are accepted only when kcmp confirms a shared descriptor table; "
            "paths, descriptor values, and opaque file-identity tokens are transient; "
            "io_uring and external fd injection are not tracked"),
        "fd_identity_capture_complete": True,
    })
    shapes = observed["records"]
    shapes.append(record(0xc01046ce, "gpu", 16, tid=91, fd=7))
    root_free = event_cleanup_row(
        "root_free_predicate", "control", 0xc0104629, fd=3,
        packet_size=16, entry_nonzero_offsets=[0, 8], exit_nonzero_offsets=[0, 8],
        changed_offsets=[], entry_snapshot_passed=True, exit_snapshot_passed=True,
        root_free_candidate=True, root_free_succeeded=True)
    rows = [
        event_cleanup_row("fd_open", "control", 257, fd=3, syscall_return=3),
        event_cleanup_row("fd_open", "gpu", 257, fd=7, syscall_return=7),
        *shapes[:4], shapes[4], root_free,
        event_cleanup_row("close", "gpu", 3, fd=7, close_succeeded=True),
        event_cleanup_row("close", "control", 3, fd=3, close_succeeded=True),
    ]
    for row in rows:
        row["fd_file_id"] = {"control": 11, "gpu": 22}.get(row["fd_role"])
        if row["operation"] == "selected_ioctl_payload_shape":
            row["fd"] = 3 if row["fd_role"] == "control" else 7
    observed["records"] = rows
    return observed


def valid_phase(tool):
    operations = [
        "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
        "cuDeviceGetName", "cuDeviceGetPCIBusId", "cuDeviceGetAttribute.major",
        "cuDeviceGetAttribute.minor", "cuDeviceGetAttribute.concurrent_managed_access",
        "cuDeviceGetAttribute.pageable_memory_access",
        "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables",
        "cuCtxCreate_v2", "cuCtxSetCurrent", "cuCtxGetDevice", "cuModuleLoad",
        "cuModuleGetFunction(hybrid_arch)", "cuMemAlloc_v2",
        "cuLaunchKernel(hybrid_arch)", "cuCtxSynchronize", "cuMemcpyDtoH_v2",
    ]
    return {
        "schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
        "phase": "kernel", "expected_pci": tool.EXPECTED_PCI,
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
        "driver_api": tool.EXPECTED_DRIVER_API,
        "selected_device": {
            "name": "NVIDIA GeForce RTX 5080", "pci_bus_id": tool.EXPECTED_PCI,
            "sm": 120, "compute_capability": "12.0",
            "concurrent_managed_access": True, "pageable_memory_access": True,
            "pageable_memory_access_uses_host_page_tables": True,
        },
        "completed_operations": operations, "numeric_result_passed": True,
        "result_value": 1200, "expected_result": 1200,
        "cleanup_passed": True, "cleanup_errors": [], "error": "",
    }


def valid_remote(tool):
    gpu = {
        "name": "NVIDIA GeForce RTX 5080", "uuid": tool.EXPECTED_GPU_UUID,
        "pci": tool.EXPECTED_PCI, "driver_version": tool.EXPECTED_DRIVER,
        "binding": "nvidia", "minor": 0, "node": "/dev/nvidia0",
        "gpu_node": {"path": "/dev/nvidia0", "major": 195, "minor": 0,
                     "sysfs_pci": tool.EXPECTED_PCI,
                     "identity_source": "proc-driver-gpu-information+sysfs-pci-binding"},
        "control_node": {"path": "/dev/nvidiactl", "major": 195, "minor": 255},
    }
    module = {"loaded_version": tool.EXPECTED_DRIVER, "path": "/lib/modules/nvidia.ko",
              "sha256": "a" * 64, "bytes": 15_000_000}
    libcuda = {"path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
               "sha256": "b" * 64, "bytes": 96_000_000}
    artifacts = {name: {"sha256": digest, "bytes": 1024}
                 for name, (_path, digest, _executable) in tool.EXPECTED_ARTIFACTS.items()}
    return {
        "schema": tool.REMOTE_SCHEMA, "capture_mode": "ioctl_shapes",
        "status": "complete", "hostname": "pc3",
        "kernel_release": tool.EXPECTED_KERNEL,
        "gpu": gpu, "gpu_after": dict(gpu),
        "module_before": module, "module_after": dict(module),
        "libcuda_before": libcuda, "libcuda_after": dict(libcuda),
        "gpu_compute_process_count_before": 0, "gpu_compute_process_count_prelaunch": 0,
        "gpu_compute_process_count_after": 0,
        "artifacts_before": artifacts, "artifacts_after": artifacts,
        "cuda_visible_devices": tool.EXPECTED_GPU_UUID,
        "probe_exit_code": 0, "phase": valid_phase(tool),
        "observer_exit_code": 0,
        "ioctl_observation": tool.summarize_ioctl_observation(
            valid_observation(gpu["node"]), gpu["node"], 0),
        "cleanup_passed": True, "remote_workspace_removed": True,
        "execution_scope": {key: False for key in (
            "driver_or_module_changed", "pci_binding_changed", "vm_management_issued",
            "gpu_reset_requested", "imex_configuration_changed")},
    }


def raw_event_cleanup_remote(tool):
    report = valid_remote(tool)
    report["capture_mode"] = "event_cleanup"
    report["ioctl_observation"] = valid_event_cleanup_observation(
        report["gpu"]["node"])
    return report


def valid_enumeration_phase(tool):
    operations = [
        "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
        "cuDeviceGetName", "cuDeviceGetPCIBusId", "cuDeviceGetAttribute.major",
        "cuDeviceGetAttribute.minor", "cuDeviceGetAttribute.concurrent_managed_access",
        "cuDeviceGetAttribute.pageable_memory_access",
        "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables",
    ]
    return {
        "schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
        "phase": "enumerate", "expected_pci": tool.EXPECTED_PCI,
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
        "driver_api": tool.EXPECTED_DRIVER_API,
        "selected_device": {
            "name": "NVIDIA GeForce RTX 5080", "pci_bus_id": tool.EXPECTED_PCI,
            "sm": 120, "compute_capability": "12.0",
            "concurrent_managed_access": True, "pageable_memory_access": True,
            "pageable_memory_access_uses_host_page_tables": True,
        },
        "completed_operations": operations, "numeric_result_passed": False,
        "result_value": None, "expected_result": None,
        "cleanup_passed": True, "cleanup_errors": [], "error": "",
    }


def raw_sync_boost_observation(count=0, request=0xc020462a, syscall_return=0,
                               rm_status=0):
    scope = (
        "exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; "
        "inline GPU IDs and group payloads omitted; raw addresses and handles omitted")
    packet_size = 32 if request == 0xc020462a else 16
    fields = {
        "command": 0xa04, "flags": 0, "params_size": 2244, "status": rm_status,
        "hClientPresent": True, "hObjectPresent": True, "client_object_equal": True,
        "client_matches_prior_root_allocation": True,
        "object_matches_prior_root_allocation": True,
    }
    entry = dict(fields)
    exited = dict(fields)
    if syscall_return == 0 and rm_status == 0:
        exited["syncBoostGroupCount"] = count
    observation = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v32",
        "trace_complete": True, "child_exit_code": 0,
        "control_path": "/dev/nvidiactl",
        "architecture": "x86_64", "pointer_bits": 64,
        "nested_pointers_read": syscall_return == 0 and rm_status == 0,
        "snapshot_consistency": "per-task syscall stop; other threads may mutate shared packet memory",
        "fd_identity_tracking": False, "payload_scope": scope,
        "sync_boost_group_payload_snapshots_read": int(syscall_return == 0 and rm_status == 0),
        "records": [{
            "tid": 91, "fd": 3, "fd_role": "control", "request": request,
            "packet_size": packet_size, "operation": "rm_control_sync_boost_groups",
            "entry": entry, "exit": exited, "syscall_return": syscall_return,
        }],
        "errors": [],
    }
    if syscall_return == 0 and rm_status == 0:
        observation["nested_pointer_scope"] = (
            "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; "
            "inline GPU IDs and group payloads omitted")
    return observation


def valid_sync_boost_remote(tool):
    report = valid_remote(tool)
    report["capture_mode"] = "sync_boost_groups"
    report["artifacts_before"]["observer"] = {
        "sha256": tool.SYNC_BOOST_OBSERVER_SHA256, "bytes": 269360}
    report["artifacts_after"] = report["artifacts_before"]
    report["phase"] = valid_enumeration_phase(tool)
    report["ioctl_observation"] = tool.summarize_sync_boost_observation(
        raw_sync_boost_observation(), 0)
    return report


class Pc3Rtx5080IoctlShapeReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool() if TOOL.is_file() else None

    def setUp(self):
        if self.tool is None and self._testMethodName != "test_runner_module_is_present":
            self.skipTest("the production runner is the feature under test")

    def test_runner_module_is_present(self):
        self.assertTrue(TOOL.is_file(), "strict RTX 5080 ioctl runner has not been implemented")

    def test_kernel_phase_requires_numeric_sm120_kernel_and_cleanup(self):
        outcome = self.tool.validate_phase_result(
            valid_phase(self.tool), 0, "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02")
        self.assertEqual(outcome["qualification"], "rtx5080-r595-kernel-phase-validated")
        self.assertFalse(outcome["hybrid_validated"])
        expanded = valid_phase(self.tool)
        expanded["expected_pci"] = "00000000:02:00.0"
        self.tool.validate_phase_result(
            expanded, 0, "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02")

    def test_sync_boost_mode_requires_clean_r595_cuda_enumeration(self):
        phase = valid_enumeration_phase(self.tool)
        outcome = self.tool.validate_enumeration_phase_result(
            phase, 0, phase["driver_library_path"])
        self.assertEqual(outcome["qualification"],
                         "rtx5080-r595-enumeration-phase-validated")
        self.assertFalse(outcome["hybrid_validated"])
        for mutate, message in (
                (lambda p: p.update(status="phase-failed"), "enumeration phase"),
                (lambda p: p["selected_device"].update(sm=70), "SM120"),
                (lambda p: p["completed_operations"].remove("cuInit"), "cuInit"),
                (lambda p: p["completed_operations"].append("cuLaunchKernel(hybrid_arch)"),
                 "unexpected CUDA operation"),
                (lambda p: p["selected_device"].update(concurrent_managed_access=1),
                 "identity"),
                (lambda p: p.update(cleanup_passed=False), "cleanup"),
                (lambda p: p.update(numeric_result_passed=True), "enumeration-only")):
            changed = valid_enumeration_phase(self.tool)
            mutate(changed)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.tool.validate_enumeration_phase_result(
                    changed, 0, changed["driver_library_path"])

    def test_sync_boost_summary_keeps_only_exact_root_output_and_redacts_identifiers(self):
        raw = raw_sync_boost_observation()
        summary = self.tool.summarize_sync_boost_observation(raw, 0)
        self.assertEqual(summary["record_count"], 1)
        self.assertEqual(summary["sync_boost_group_payload_snapshots_read"], 1)
        self.assertEqual(summary["records"][0]["exit"]["syncBoostGroupCount"], 0)
        encoded = json.dumps(summary)
        for forbidden in ('"tid"', '"fd"', '"hClient"', '"hObject"',
                          '"params_address"', '"gpuIds"', '"boostGroupId"'):
            self.assertNotIn(forbidden, encoded)

    def test_sync_boost_summary_treats_rm_failure_as_failed_despite_successful_ioctl(self):
        failed_rm = raw_sync_boost_observation(
            count=3, syscall_return=0, rm_status=0x00000005)
        summary = self.tool.summarize_sync_boost_observation(failed_rm, 0)

        self.assertEqual(summary["successful_record_count"], 0)
        self.assertEqual(summary["failed_record_count"], 1)
        self.assertEqual(summary["group_counts"], [])
        self.assertEqual(summary["sync_boost_group_payload_snapshots_read"], 0)
        self.assertEqual(summary["records"][0]["syscall_return"], 0)
        self.assertEqual(summary["records"][0]["exit"]["status"], 0x00000005)
        self.assertNotIn("syncBoostGroupCount", summary["records"][0]["exit"])

        stale_output = raw_sync_boost_observation(
            count=3, syscall_return=0, rm_status=0x00000005)
        stale_output["records"][0]["exit"]["syncBoostGroupCount"] = 0
        stale_output["sync_boost_group_payload_snapshots_read"] = 1
        stale_output["nested_pointers_read"] = True
        stale_output["nested_pointer_scope"] = (
            "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; "
            "inline GPU IDs and group payloads omitted")
        with self.assertRaisesRegex(ValueError, "failed ioctl cannot carry an output count"):
            self.tool.summarize_sync_boost_observation(stale_output, 0)

    def test_sync_boost_summary_rejects_stale_output_and_malformed_counts(self):
        cases = []
        stale = raw_sync_boost_observation(syscall_return=-25)
        stale["records"][0]["exit"]["syncBoostGroupCount"] = 0
        cases.append((stale, "failed ioctl"))
        bad_count = raw_sync_boost_observation(count=17)
        cases.append((bad_count, "fixed output capacity"))
        bad_request = raw_sync_boost_observation(request=0xc038464e)
        cases.append((bad_request, "selected root sync-boost command"))
        for raw, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.tool.summarize_sync_boost_observation(raw, 0)

    def test_sync_boost_mode_reports_unobserved_query_without_claiming_failure(self):
        report = valid_sync_boost_remote(self.tool)
        empty = {**raw_sync_boost_observation(), "records": [],
                 "sync_boost_group_payload_snapshots_read": 0,
                 "nested_pointers_read": False}
        empty.pop("nested_pointer_scope", None)
        report["ioctl_observation"] = self.tool.summarize_sync_boost_observation(
            empty, 0)
        outcome = self.tool.validate_remote_report(report, capture_mode="sync_boost_groups")
        self.assertEqual(outcome["qualification"],
                         "rtx5080-r595-enumeration-no-sync-boost-query-observed")
        self.assertFalse(outcome["sync_boost_groups_observed"])

    def test_sync_boost_mode_distinguishes_observed_failed_ioctl_from_no_query(self):
        report = valid_sync_boost_remote(self.tool)
        failed = raw_sync_boost_observation(syscall_return=-25, rm_status=0xabcdef01)
        report["ioctl_observation"] = self.tool.summarize_sync_boost_observation(failed, 0)
        outcome = self.tool.validate_remote_report(report, capture_mode="sync_boost_groups")
        self.assertEqual(outcome["qualification"],
                         "rtx5080-r595-enumeration-sync-boost-query-failed")
        self.assertEqual(outcome["sync_boost_group_failure_count"], 1)
        self.assertEqual(outcome["sync_boost_group_counts"], [])

    def test_sync_boost_mode_selects_its_pinned_observer_and_sanitizes_evidence(self):
        report = valid_sync_boost_remote(self.tool)
        report["ioctl_observation"] = raw_sync_boost_observation()
        output = json.dumps(report)
        with tempfile.TemporaryDirectory(prefix="rtx5080-sync-boost-test-") as directory:
            evidence = Path(directory) / "sync-boost.json"
            payloads = []

            def invoke(_argv, **kwargs):
                payloads.append(json.loads(kwargs["input"]))
                return SimpleNamespace(returncode=0, stdout=output, stderr="")

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = self.tool.run(
                    ["--sync-boost-groups", "--evidence", str(evidence)], invoke=invoke)
            self.assertEqual(exit_code, 0)
            self.assertEqual(payloads[0]["capture_mode"], "sync_boost_groups")
            self.assertEqual(payloads[0]["artifacts"]["observer"]["sha256"],
                             self.tool.SYNC_BOOST_OBSERVER_SHA256)
            saved = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(saved["remote"]["capture_mode"], "sync_boost_groups")
            self.assertEqual(saved["remote"]["ioctl_observation"]["record_count"], 1)
            encoded = json.dumps(saved)
            self.assertNotIn('"tid":', encoded)
            self.assertNotIn('"fd":', encoded)

    def test_probe_manifest_pins_historical_sources_and_both_architecture_images(self):
        result = self.tool.validate_probe_build(self.tool.EXPECTED_ARTIFACTS["probe"][0])
        self.assertEqual(result["source_inputs_sha256"], {
            str((ROOT / relative).resolve()): digest
            for relative, digest in self.tool.EXPECTED_BUILD_SOURCES.items()})
        self.assertEqual(result["fatbin_sha256"],
                         self.tool.EXPECTED_ARTIFACTS["fatbin"][1])
        self.assertEqual(len(result["build_manifest_sha256"]), 64)

    def test_kernel_phase_fails_closed_on_wrong_gpu_result_scope_or_cleanup(self):
        cases = (
            (lambda p: p.update(status="phase-failed"), "phase"),
            (lambda p: p.update(expected_pci="0000:03:00.0"), "PCI"),
            (lambda p: p["selected_device"].update(sm=70), "SM120"),
            (lambda p: p.update(result_value=1190), "numeric"),
            (lambda p: p["completed_operations"].remove("cuLaunchKernel(hybrid_arch)"), "kernel operation"),
            (lambda p: p.update(cleanup_passed=False), "cleanup"),
            (lambda p: p.update(cleanup_errors=["resource leak"]), "cleanup"),
        )
        for mutate, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                probe = valid_phase(self.tool)
                mutate(probe)
                self.tool.validate_phase_result(probe, 0, probe["driver_library_path"])
        with self.assertRaisesRegex(ValueError, "libcuda"):
            self.tool.validate_phase_result(valid_phase(self.tool), 0, "/tmp/other-libcuda.so")
        with self.assertRaisesRegex(ValueError, "exit successfully"):
            self.tool.validate_phase_result(valid_phase(self.tool), 2,
                                            valid_phase(self.tool)["driver_library_path"])

    def test_complete_event_trace_is_summarized_without_fd_or_thread_values(self):
        observation = valid_observation()
        summary = self.tool.summarize_ioctl_observation(observation, "/dev/nvidia2", 0)
        self.assertEqual(summary["request_counts"]["0xc01046ce"], 1)
        self.assertEqual(summary["request_counts"]["0xc01046cf"], 1)
        self.assertEqual(summary["coverage_status"], "complete")
        encoded = json.dumps(summary)
        self.assertNotIn('"fd":', encoded)
        self.assertNotIn('"tid":', encoded)
        self.assertNotIn("records", summary)

    def test_event_cleanup_trace_summarizes_root_and_close_candidates_without_identifiers(self):
        observation = valid_event_cleanup_observation()
        summary = self.tool.summarize_event_cleanup_observation(
            observation, "/dev/nvidia2", 0)
        self.assertEqual(summary["event_lifecycle"]["allocation_count"], 2)
        self.assertEqual(summary["event_lifecycle"]["free_count"], 1)
        self.assertEqual(summary["event_cleanup"]["root_free_candidate_count"], 1)
        self.assertEqual(summary["event_cleanup"]["root_free_success_count"], 1)
        self.assertEqual(summary["event_cleanup"]["root_free_success_after_event_alloc_count"], 1)
        self.assertEqual(summary["event_cleanup"]["pending_event_allocations_at_gpu_close"], 1)
        self.assertEqual(summary["event_cleanup"]["gpu_close_count"], 1)
        self.assertEqual(summary["event_cleanup"]["successful_gpu_close_count"], 1)
        self.assertTrue(summary["event_cleanup"]["fd_identity_capture_complete"])
        self.assertFalse(summary["hybrid_validated"])
        encoded = json.dumps(summary)
        for forbidden in ('"tid"', '"fd"', '"source_fd"', 'records', '0x11223344'):
            self.assertNotIn(forbidden, encoded)

    def test_event_cleanup_correlates_lifecycle_across_threads_by_open_file_identity(self):
        observation = valid_event_cleanup_observation()
        rows = observation["records"]
        ioctls = [row for row in rows if row["operation"] == "selected_ioctl_payload_shape"]
        event_allocs = [row for row in ioctls if row["request"] == 0xc01046ce]
        event_free = next(row for row in ioctls if row["request"] == 0xc01046cf)
        event_free["tid"] = 92
        event_allocs[-1]["fd"] = 8
        event_allocs[-1]["fd_file_id"] = 23
        rows.insert(2, event_cleanup_row("fd_open", "gpu", 257, fd=8,
                                        syscall_return=8, fd_file_id=23))
        gpu_close = next(row for row in rows if row["operation"] == "close" and
                         row["fd_role"] == "gpu")
        gpu_close.update(tid=92, fd=8, fd_file_id=23)

        summary = self.tool.summarize_event_cleanup_observation(
            observation, "/dev/nvidia2", 0)

        self.assertEqual(summary["event_cleanup"]["pending_event_allocations_at_gpu_close"], 1)
        self.assertTrue(summary["event_cleanup"]["cleanup_route_candidate_observed"])
        self.assertEqual(summary["event_lifecycle"]["matched_file_identity_groups"], 1)
        self.assertFalse(summary["event_lifecycle"]["balanced_by_file_identity"])

    def test_event_cleanup_waits_for_last_alias_before_counting_gpu_file_close(self):
        observation = valid_event_cleanup_observation()
        rows = observation["records"]
        root_free = next(row for row in rows if row["operation"] == "root_free_predicate")
        root_free["root_free_succeeded"] = False
        gpu_close = next(row for row in rows if row["operation"] == "close" and
                         row["fd_role"] == "gpu")
        gpu_close.update(tid=92, fd=7, fd_file_id=22)
        rows.insert(2, event_cleanup_row(
            "fd_dup", "gpu", 32, tid=93, fd=8, syscall_return=8,
            source_fd=7, fd_file_id=22, replaced_fd_file_id=None))

        before_last_close = self.tool.summarize_event_cleanup_observation(
            observation, "/dev/nvidia2", 0)
        self.assertEqual(before_last_close["event_cleanup"][
            "pending_event_allocations_at_gpu_close"], 0)
        self.assertFalse(before_last_close["event_cleanup"][
            "cleanup_route_candidate_observed"])

        rows.append(event_cleanup_row(
            "close", "gpu", 3, tid=93, fd=8, close_succeeded=True,
            fd_file_id=22))
        after_last_close = self.tool.summarize_event_cleanup_observation(
            observation, "/dev/nvidia2", 0)
        self.assertEqual(after_last_close["event_cleanup"][
            "pending_event_allocations_at_gpu_close"], 1)
        self.assertTrue(after_last_close["event_cleanup"][
            "cleanup_route_candidate_observed"])
        self.assertEqual(after_last_close["event_cleanup"][
            "gpu_aliases_without_observed_close_at_process_exit"], 0)

    def test_event_cleanup_reports_pending_objects_when_gpu_alias_survives_process_trace(self):
        observation = valid_event_cleanup_observation()
        rows = observation["records"]
        root_free = next(row for row in rows if row["operation"] == "root_free_predicate")
        root_free["root_free_succeeded"] = False
        rows[:] = [row for row in rows if not (
            row["operation"] == "close" and row["fd_role"] == "gpu")]

        summary = self.tool.summarize_event_cleanup_observation(
            observation, "/dev/nvidia2", 0)

        event_cleanup = summary["event_cleanup"]
        self.assertEqual(event_cleanup[
            "gpu_aliases_without_observed_close_at_process_exit"], 1)
        self.assertEqual(event_cleanup[
            "gpu_file_identities_without_observed_close_at_process_exit"], 1)
        self.assertEqual(event_cleanup[
            "pending_event_allocations_on_open_gpu_files_at_process_exit"], 1)
        self.assertFalse(event_cleanup["cleanup_route_candidate_observed"])

    def test_event_cleanup_close_range_uses_transient_file_identities(self):
        observation = valid_event_cleanup_observation()
        rows = observation["records"]
        rows[:] = [row for row in rows if not (
            row["operation"] == "close" and row["fd_role"] == "gpu")]
        rows.insert(2, event_cleanup_row(
            "fd_dup", "gpu", 32, tid=93, fd=8, syscall_return=8,
            source_fd=7, fd_file_id=22, replaced_fd_file_id=None))
        rows.append({
            "tid": 93, "fd": -1, "fd_role": "other", "fd_file_id": None,
            "request": 436, "packet_size": 0, "operation": "fd_close_range",
            "entry": {"first_fd": 7, "last_fd": 8, "flags": 0},
            "exit": None, "syscall_return": 0,
            "fd_descriptors": [{"fd": 7, "file_id": 22},
                                {"fd": 8, "file_id": 22}],
        })

        summary = self.tool.summarize_event_cleanup_observation(
            observation, "/dev/nvidia2", 0)

        self.assertEqual(summary["event_cleanup"]["close_range_count"], 1)
        self.assertEqual(summary["event_cleanup"]["pending_event_allocations_at_close_range"], 1)
        self.assertTrue(summary["event_cleanup"]["cleanup_route_candidate_observed"])

    def test_event_cleanup_trace_rejects_unredacted_or_inconsistent_lifecycle(self):
        observation = valid_event_cleanup_observation()
        observation["records"][8]["close_succeeded"] = False
        with self.assertRaisesRegex(ValueError, "close"):
            self.tool.summarize_event_cleanup_observation(
                observation, "/dev/nvidia2", 0)
        observation = valid_event_cleanup_observation()
        observation["records"][7]["root_free_succeeded"] = 1
        with self.assertRaisesRegex(ValueError, "root-free"):
            self.tool.summarize_event_cleanup_observation(
                observation, "/dev/nvidia2", 0)

    def test_observer_trace_and_redaction_contract_are_enforced(self):
        mutations = (
            (lambda o: o.update(trace_complete=False), "trace"),
            (lambda o: o.update(child_exit_code=2), "child"),
            (lambda o: o.update(schema="old-schema"), "schema"),
            (lambda o: o.update(nested_pointers_read=True), "boundary"),
            (lambda o: o.update(gpu_path="/dev/nvidia0"), "path"),
            (lambda o: o["records"][0].update(syscall_return=-1), "return success"),
            (lambda o: o["records"][0].update(entry={"raw": "forbidden"}), "redacted"),
            (lambda o: o["records"][0].update(changed_offsets=[56]), "offset"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                observation = valid_observation()
                mutate(observation)
                self.tool.summarize_ioctl_observation(observation, "/dev/nvidia2", 0)

    def test_empty_or_partial_trace_is_inconclusive_not_an_abi_failure(self):
        observation = valid_observation()
        observation["records"] = []
        summary = self.tool.summarize_ioctl_observation(observation, "/dev/nvidia2", 0)
        self.assertEqual(summary["coverage_status"], "inconclusive")
        observation = valid_observation()
        observation["records"] = observation["records"][:1]
        summary = self.tool.summarize_ioctl_observation(observation, "/dev/nvidia2", 0)
        self.assertEqual(summary["coverage_status"], "partial")
        observation = valid_observation()
        observation["records"].append(record(0xc01046ce, "gpu", 16, tid=92, fd=8))
        summary = self.tool.summarize_ioctl_observation(observation, "/dev/nvidia2", 0)
        self.assertEqual(summary["coverage_status"], "partial")
        self.assertFalse(summary["event_lifecycle"]["balanced_by_thread_gpu_descriptor"])

    def test_gpu_minor_character_device_and_sysfs_bdf_must_agree(self):
        gpu = valid_remote(self.tool)["gpu"]
        self.assertTrue(self.tool.validate_gpu_node_identity(gpu))
        for mutate in (
            lambda item: item["gpu_node"].update(minor=1),
            lambda item: item["gpu_node"].update(major=194),
            lambda item: item["gpu_node"].update(sysfs_pci="0000:03:00.0"),
            lambda item: item["control_node"].update(major=194),
        ):
            changed = json.loads(json.dumps(gpu))
            mutate(changed)
            with self.assertRaisesRegex(ValueError, "character-node|sysfs|minor|major"):
                self.tool.validate_gpu_node_identity(changed)

    def test_remote_report_requires_pinned_host_stack_idle_gpu_and_cleanup(self):
        report = valid_remote(self.tool)
        result = self.tool.validate_remote_report(report)
        self.assertFalse(result["hybrid_validated"])
        self.assertEqual(result["qualification"], "rtx5080-r595-ioctl-kernel-phase-validated")
        mutations = (
            (lambda r: r.update(hostname="other"), "host"),
            (lambda r: r["gpu"].update(driver_version="580.178.04"), "GPU identity"),
            (lambda r: r["module_after"].update(sha256="c" * 64), "module identity"),
            (lambda r: r.update(gpu_compute_process_count_before=1), "busy"),
            (lambda r: r.update(remote_workspace_removed=False), "cleanup"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                changed = valid_remote(self.tool)
                mutate(changed)
                with self.assertRaisesRegex(ValueError, message):
                    self.tool.validate_remote_report(changed)

    def test_event_cleanup_mode_scrubs_transient_ids_before_evidence_persistence(self):
        remote = raw_event_cleanup_remote(self.tool)
        expected_raw = remote["ioctl_observation"]
        expected_summary = self.tool.summarize_event_cleanup_observation(
            expected_raw, remote["gpu"]["node"], 0)
        output = json.dumps(remote)

        with tempfile.TemporaryDirectory(prefix="rtx5080-event-cleanup-test-") as directory:
            evidence = Path(directory) / "event-cleanup.json"
            payloads = []

            def invoke(_argv, **kwargs):
                payloads.append(json.loads(kwargs["input"]))
                return SimpleNamespace(returncode=0, stdout=output, stderr="")

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = self.tool.run(
                    ["--event-cleanup", "--evidence", str(evidence)], invoke=invoke)
            self.assertEqual(exit_code, 0)
            self.assertEqual(payloads[0]["capture_mode"], "event_cleanup")
            saved = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(saved["remote"]["capture_mode"], "event_cleanup")
            self.assertEqual(saved["remote"]["ioctl_observation"], expected_summary)
            encoded = json.dumps(saved)
            self.assertNotIn('"records"', encoded)
            self.assertNotIn('"tid":', encoded)
            self.assertNotIn('"fd":', encoded)
            self.assertNotIn('"fd_file_id"', encoded)
            self.assertNotIn('"fd_file_ids"', encoded)
            self.assertNotIn('"fd_descriptors"', encoded)

    def test_event_cleanup_report_validation_requires_capture_mode_and_redacted_summary(self):
        report = raw_event_cleanup_remote(self.tool)
        report["ioctl_observation"] = self.tool.summarize_event_cleanup_observation(
            report["ioctl_observation"], report["gpu"]["node"], 0)
        result = self.tool.validate_remote_report(report, capture_mode="event_cleanup")
        self.assertFalse(result["hybrid_validated"])
        self.assertEqual(result["event_cleanup"]["causal_attribution"], "not-proven")
        self.assertEqual(result["qualification"],
                         "rtx5080-r595-kernel-phase-validated-event-cleanup-partial")

        changed = json.loads(json.dumps(report))
        changed["ioctl_observation"]["records"] = [{"tid": 91, "fd": 7}]
        with self.assertRaisesRegex(ValueError, "raw|redact|record"):
            self.tool.validate_remote_report(changed, capture_mode="event_cleanup")

        changed = json.loads(json.dumps(report))
        changed["capture_mode"] = "ioctl_shapes"
        with self.assertRaisesRegex(ValueError, "capture mode"):
            self.tool.validate_remote_report(changed, capture_mode="event_cleanup")

    def test_remote_worker_uses_phase_probe_strict_node_identity_and_temporary_files(self):
        compile(self.tool.REMOTE_SCRIPT, "<pc3-rtx5080-ioctl-worker>", "exec")
        ast.parse(self.tool.REMOTE_SCRIPT)
        for forbidden in ("modprobe", "rmmod", "reboot", "virsh", "nvidia-smi --gpu-reset"):
            self.assertNotIn(forbidden, self.tool.REMOTE_SCRIPT)
        self.assertIn("StrictHostKeyChecking=yes", self.tool.SSH_OPTIONS)
        self.assertIn("Device Minor", self.tool.REMOTE_SCRIPT)
        self.assertIn("/sys/bus/pci/devices", self.tool.REMOTE_SCRIPT)
        self.assertIn("/proc/devices", self.tool.REMOTE_SCRIPT)
        self.assertIn("CUDA_VISIBLE_DEVICES", self.tool.REMOTE_SCRIPT)
        self.assertIn('phase_name = "enumerate" if capture_mode == "sync_boost_groups" else "kernel"',
                      self.tool.REMOTE_SCRIPT)
        self.assertNotIn('"--require-sm"', self.tool.REMOTE_SCRIPT)
        self.assertIn('REMOTE_SCHEMA = "' + self.tool.REMOTE_SCHEMA + '"',
                      self.tool.REMOTE_SCRIPT)
        self.assertIn('REQUEST_SCHEMA = "' + self.tool.REQUEST_SCHEMA + '"',
                      self.tool.REMOTE_SCRIPT)
        self.assertIn('"--event-cleanup"', self.tool.REMOTE_SCRIPT)
        self.assertIn('probe_argv.append("--close-fds-on-exit")',
                      self.tool.REMOTE_SCRIPT)
        self.assertIn('observer_argv.append("--sync-boost-groups")', self.tool.REMOTE_SCRIPT)


if __name__ == "__main__":
    unittest.main()
