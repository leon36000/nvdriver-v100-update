# SPDX-License-Identifier: MIT
"""Negative certification tests; these fixtures are not hardware evidence."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_hybrid_acceptance import (DEFAULT_MODULE, DEFAULT_PROBE,
                                   trusted_probe_build_identity,
                                   validate_device_alloc_observation,
                                   validate_system_pageable_memory_report,
                                   validate_phase_probe_report, validate_probe_report,
                                   record_cuda_selection_environment)


def complete_report():
    return {
        "schema": "nvidia-hybrid-probe-v2", "status": "hybrid-validated",
        "memory_mode": "device",
        "managed_prefetch_requested": False,
        "managed_prefetch_api": "not-requested",
        "cuda_graphs_requested": False,
        "cuda_graph_api": "not-requested",
        "hybrid_validated": True, "required_set_passed": True,
        "required_sm": [70, 120], "missing_sm": [], "driver_api": 13020,
        "driver_library_path": str(Path(sys.executable).resolve()),
        "expected_device_pci_by_sm": {"70": "0000:01:00.0", "120": "0000:02:00.0"},
        "execution_mode": "resident-contexts-sequential-kernels",
        "context_coexistence_passed": True,
        "concurrent_kernel_execution_validated": False,
        "concurrent_kernel_test_requested": False,
        "concurrent_kernel_dispatch_passed": False,
        "concurrent_kernel_dispatch": None,
        "devices": [
            {
                "sm": sm, "ordinal": index, "pci_bus_id": f"0000:0{index+1}:00.0",
                "compute_capability": f"{sm//10}.{sm%10}", "name": f"fixture-SM{sm}",
                "concurrent_managed_access": True,
                "pageable_memory_access": True,
                "pageable_memory_access_uses_host_page_tables": index == 1,
                "targeted": True, "tested": True, "architecture_kernel_passed": True,
                "synchronous_passed": True, "asynchronous_passed": True,
                "synchronous_sizes": [1, 31, 256, 4096, 65537],
                "asynchronous_sizes": [1, 31, 256, 4096, 65537],
                "managed_memory_passed": False,
                "managed_prefetch_passed": False,
                "cuda_graphs_passed": False,
                "cuda_graph_launches": 0,
                "cleanup_passed": True, "cleanup_errors": [], "error": "",
            } for index, sm in enumerate((70, 120))
        ],
    }


def phase_report(phase="kernel", pci="0000:02:00.0", sm=120):
    operations = ["cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                  "cuDeviceGetName", "cuDeviceGetPCIBusId",
                  "cuDeviceGetAttribute.major", "cuDeviceGetAttribute.minor",
                  "cuDeviceGetAttribute.concurrent_managed_access",
                  "cuDeviceGetAttribute.pageable_memory_access",
                  "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables"]
    selected = None
    if phase != "initialize":
        selected = {"name": f"fixture-SM{sm}", "pci_bus_id": pci, "sm": sm,
                    "compute_capability": f"{sm // 10}.{sm % 10}",
                    "concurrent_managed_access": True,
                    "pageable_memory_access": True,
                    "pageable_memory_access_uses_host_page_tables": sm == 120}
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
    kernel = phase == "kernel"
    return {"schema": "nvidia-cuda-driver-phase-v1", "status": "phase-passed",
            "phase": phase, "expected_pci": "00000000:" + pci.split(":", 1)[1],
            "driver_library_path": str(Path(sys.executable).resolve()),
            "driver_api": None if phase == "initialize" else 13020,
            "selected_device": selected, "completed_operations": operations,
            "numeric_result_passed": kernel,
            "result_value": 1200 if kernel else None,
            "expected_result": 1200 if kernel else None,
            "cleanup_passed": True, "cleanup_errors": [], "error": ""}


def system_pageable_report():
    return {
        "schema": "nvidia-cuda-system-pageable-memory-v1", "status": "validated",
        "phase": "system-pageable-memory", "expected_pci": "00000000:02:00.0",
        "driver_library_path": str(Path(sys.executable).resolve()), "driver_api": 13020,
        "selected_device": {
            "name": "NVIDIA GeForce RTX 5080", "pci_bus_id": "0000:02:00.0",
            "sm": 120, "compute_capability": "12.0", "concurrent_managed_access": True,
            "pageable_memory_access": True,
            "pageable_memory_access_uses_host_page_tables": False,
            "unified_addressing": True,
        },
        "allocators": {
            "malloc": {"tested": True, "passed": True,
                       "execution_mode": "context-synchronized",
                       "sizes": [1, 31, 256, 4096, 65537]},
            "mmap": {"tested": True, "passed": True,
                     "execution_mode": "stream-synchronized",
                     "sizes": [1, 31, 256, 4096, 65537]},
        },
        "cleanup_passed": True, "cleanup_errors": [], "error": "",
    }


def binapi_observation(case="valid"):
    mask = "00" * 31
    changed_mask = "00" * 124
    entry_payload = {
        "payloadBytes": 992, "payloadValid": True, "nonzeroU32Count": 0,
        "nonzeroU32MaskLsbFirst": mask, "changedByteCount": 0,
        "changedByteMaskLsbFirst": changed_mask, "entryExitPayloadEqual": None,
    }
    exit_payload = {**entry_payload, "entryExitPayloadEqual": True}
    entry = {
        "command": 0x20810108, "flags": 0, "params_size": 992, "status": 0,
        "hClientPresent": True, "hObjectPresent": True,
        "client_object_equal": True, "client_matches_prior_root_allocation": True,
        "object_matches_prior_root_allocation": True,
        "objectClass": {"resolution": "resolved", "classId": 0x2081},
        "binapiPayload": entry_payload,
    }
    exit_packet = {**entry, "binapiPayload": exit_payload}
    row = {
        "tid": 81, "fd": 3, "fd_role": "control", "request": 0xc020462a,
        "packet_size": 32, "operation": "binapi_control", "entry": entry,
        "exit": exit_packet, "syscall_return": 0,
    }
    pointer_scope = (
        "exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; "
        "no contained pointer is followed; raw bytes, addresses, and handles omitted")
    observed = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v18", "trace_complete": True,
        "child_exit_code": 77, "control_path": "/dev/nvidiactl",
        "gpu_path": "/dev/nvidia0", "nested_pointers_read": True,
        "nested_pointer_scope": pointer_scope,
        "payload_scope": (
            "RM_CONTROL headers plus exact 992-byte NV2081_BINAPI payload-shape metadata; "
            "contained pointers are never followed; raw bytes, addresses, and handles omitted"),
        "object_class_resolution_scope": (
            "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected "
            "control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed"),
        "binapi_payload_snapshots_read": 2, "records": [row], "errors": [],
    }
    if case == "empty":
        observed["binapi_payload_snapshots_read"] = 0
        observed["nested_pointers_read"] = False
        observed.pop("nested_pointer_scope")
        observed["records"] = []
    elif case == "bad-mask-count":
        observed["records"][0]["exit"]["binapiPayload"]["changedByteCount"] = 1
    return observed


def device_alloc_observation(case="valid"):
    allocation = {
        "classPayloadBytes": 56, "deviceId": 0, "hClientShare": "same-as-root",
        "targetClientZero": True, "targetDeviceZero": True, "flags": 0x403,
        "vaSpaceSize": 0x123000, "vaStartInternalZero": False,
        "vaLimitInternalZero": False, "vaMode": 2,
    }
    packet = {
        "layout": "NVOS64", "hClass": 128, "paramsSize": 56, "flags": 0,
        "status": 0, "hRootPresent": True, "hObjectParentPresent": True,
        "hObjectNewPresent": True, "pAllocParmsPresent": True,
        "pRightsRequestedPresent": False, "deviceAlloc": allocation,
    }
    row = {"tid": 81, "fd": 3, "fd_role": "control", "request": 0xc020462a,
           "packet_size": 64, "operation": "device_alloc", "entry": packet,
           "exit": packet, "syscall_return": 0}
    observed = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v19", "trace_complete": True,
        "child_exit_code": 0, "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
        "architecture": "x86_64", "pointer_bits": 64, "nested_pointers_read": True,
        "nested_pointer_scope": (
            "NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; "
            "client handles are relational booleans; internal VA addresses are omitted"),
        "payload_scope": (
            "NV01_DEVICE_0 fixed class parameters only; handles are redacted and internal VA addresses are omitted"),
        "device_alloc_payload_snapshots_read": 2, "records": [row], "errors": [],
    }
    if case == "unredacted":
        observed["records"][0]["entry"]["deviceAlloc"]["rawHandle"] = 0x13579bdf
    elif case == "snapshot-count":
        observed["device_alloc_payload_snapshots_read"] = 1
    elif case == "no-success":
        observed["records"][0]["exit"]["status"] = 1
    return observed


class AcceptanceContractTests(unittest.TestCase):
    def test_hybrid_receipts_capture_cuda_visibility_and_device_order(self):
        with patch.dict(os.environ, {"CUDA_VISIBLE_DEVICES": "GPU-a,GPU-b",
                                     "CUDA_DEVICE_ORDER": "PCI_BUS_ID"}, clear=True):
            self.assertEqual(record_cuda_selection_environment(), {
                "cuda_visible_devices": "GPU-a,GPU-b",
                "cuda_device_order": "PCI_BUS_ID",
            })

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(record_cuda_selection_environment(), {
                "cuda_visible_devices": None,
                "cuda_device_order": None,
            })

    def test_concurrent_dispatch_requires_both_exact_devices_numeric_results_and_overlap(self):
        report = complete_report()
        report["concurrent_kernel_test_requested"] = True
        report["concurrent_kernel_dispatch_passed"] = True
        report["concurrent_kernel_dispatch"] = {
            "schema": "nvidia-hybrid-concurrent-dispatch-v1",
            "qualification": "host-dispatch-window-overlap-profiler-timeline-required",
            "requested": True,
            "passed": True,
            "gpu_timeline_overlap_validated": False,
            "rounds": 2_000_000,
            "devices": [
                {"sm": 70, "pci_bus_id": "0000:01:00.0",
                 "kernel_name": "hybrid_concurrent_work", "rounds": 2_000_000,
                 "numeric_result_passed": True,
                 "host_window_start_ns": 100, "host_window_end_ns": 10_000},
                {"sm": 120, "pci_bus_id": "0000:02:00.0",
                 "kernel_name": "hybrid_concurrent_work", "rounds": 2_000_000,
                 "numeric_result_passed": True,
                 "host_window_start_ns": 200, "host_window_end_ns": 9_000},
            ],
        }
        expected = {70: "0000:01:00.0", 120: "0000:02:00.0"}
        self.assertEqual(validate_probe_report(
            report, 0, expected_device_pci_by_sm=expected,
            expected_concurrent_dispatch=True), "report-contract-valid")

        invalid_reports = []
        no_overlap = copy.deepcopy(report)
        no_overlap["concurrent_kernel_dispatch"]["devices"][1].update(
            host_window_start_ns=10_001, host_window_end_ns=12_000)
        invalid_reports.append(no_overlap)
        wrong_gpu = copy.deepcopy(report)
        wrong_gpu["concurrent_kernel_dispatch"]["devices"][1]["pci_bus_id"] = "0000:03:00.0"
        invalid_reports.append(wrong_gpu)
        bad_numeric = copy.deepcopy(report)
        bad_numeric["concurrent_kernel_dispatch"]["devices"][0]["numeric_result_passed"] = False
        invalid_reports.append(bad_numeric)
        fake_gpu_timeline = copy.deepcopy(report)
        fake_gpu_timeline["concurrent_kernel_dispatch"]["gpu_timeline_overlap_validated"] = True
        fake_gpu_timeline["concurrent_kernel_execution_validated"] = True
        invalid_reports.append(fake_gpu_timeline)
        for invalid in invalid_reports:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_probe_report(
                    invalid, 0, expected_device_pci_by_sm=expected,
                    expected_concurrent_dispatch=True)

    def test_concurrent_dispatch_claim_is_rejected_when_not_requested(self):
        report = complete_report()
        report["concurrent_kernel_dispatch_passed"] = True
        with self.assertRaisesRegex(ValueError, "unrequested concurrent dispatch"):
            validate_probe_report(report, 0)

    def test_legacy_v6_probe_without_optional_concurrent_fields_remains_valid(self):
        report = complete_report()
        for key in ("concurrent_kernel_test_requested",
                    "concurrent_kernel_dispatch_passed", "concurrent_kernel_dispatch"):
            report.pop(key)
        self.assertEqual(validate_probe_report(
            report, 0, expected_device_pci_by_sm={
                70: "0000:01:00.0", 120: "0000:02:00.0"}),
            "report-contract-valid")

    def test_device_alloc_observer_requires_fixed_redacted_nv0080_payload(self):
        self.assertEqual(validate_device_alloc_observation(device_alloc_observation()), (True, 2))
        for case in ("unredacted", "snapshot-count", "no-success"):
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate_device_alloc_observation(device_alloc_observation(case))

    def test_acceptance_runner_defaults_to_current_probe_bundle(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(DEFAULT_PROBE, root / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe")
        self.assertEqual(DEFAULT_MODULE, root / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin")
        builder_source = (root / "tools/build_probe_cuda129.py").read_text(encoding="utf-8")
        self.assertEqual(DEFAULT_PROBE.parent,
                         root / "build/probe-cuda129-sm70v-sm120a-v3-host-staged")
        self.assertIn('parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)',
                      builder_source)
        manifest_path = DEFAULT_PROBE.parent / "build-manifest.json"
        self.assertTrue(DEFAULT_PROBE.is_file())
        self.assertTrue(DEFAULT_MODULE.is_file())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "built-static-images")
        self.assertEqual(manifest["fatbin_images"], ["sm_70", "sm_120a"])
        self.assertFalse(manifest["probe_directly_links_libcuda"])
        self.assertEqual(manifest["probe"], {
            "path": str(DEFAULT_PROBE.resolve()),
            "sha256": hashlib.sha256(DEFAULT_PROBE.read_bytes()).hexdigest(),
        })
        self.assertEqual(manifest["fatbin"]["path"], str(DEFAULT_MODULE.resolve()))
        self.assertEqual(manifest["fatbin"]["sha256"],
                         hashlib.sha256(DEFAULT_MODULE.read_bytes()).hexdigest())
        self.assertEqual(manifest["source_inputs_sha256"], {
            str((root / "kernels/hybrid_probe.cu").resolve()):
                hashlib.sha256((root / "kernels/hybrid_probe.cu").read_bytes()).hexdigest(),
            str((root / "src/hybrid_cuda_probe.cpp").resolve()):
                hashlib.sha256((root / "src/hybrid_cuda_probe.cpp").read_bytes()).hexdigest(),
        })

    def test_software_suite_evidence_pins_the_concurrent_dispatch_implementation(self):
        root = Path(__file__).resolve().parents[1]
        runner = (root / "tools/run_software_test_suite.py").read_text()
        for source in ("tests/run_hybrid_acceptance.py", "tools/cuda_probe_contract.py",
                       "tools/run_remote_selected_gpu.py",
                       "tools/run_pc3_v100_guest_reference.py",
                       "tools/compare_rm_control_headers.py",
                       "tools/aggregate_cuda_performance_references.py",
                       "tools/inspect_pc3_v100_trace_capabilities.py",
                       "tools/run_pc3_v100_system_features_sensitivity.py",
                       "tools/compare_uvm_ioctl_routes.py",
                       "tools/audit_nsys_concurrent_overlap.py", "tools/build_probe.py",
                       "src/hybrid_cuda_probe.cpp", "kernels/hybrid_probe.cu",
                       "src/experiments/concurrent_dispatch_v1/hybrid_cuda_probe.cpp",
                       "kernels/experiments/concurrent_dispatch_v1/hybrid_probe.cu"):
            with self.subTest(source=source):
                self.assertIn(f'"{source}"', runner)

    def test_phase_contract_is_separate_from_hybrid_acceptance(self):
        for phase in ("initialize", "enumerate", "context", "allocation", "module", "kernel",
                      "managed-accessed-by"):
            with self.subTest(phase=phase):
                report = phase_report(phase)
                self.assertEqual(validate_phase_probe_report(
                    report, 0, "0000:02:00.0", phase), "phase-report-contract-pass")
        for mutate in (
            lambda r: r.update(phase="allocation"),
            lambda r: r.update(hybrid_validated=True),
            lambda r: r.update(cleanup_passed=False),
            lambda r: r.update(selected_device={"name": "wrong", "pci_bus_id": "0000:09:00.0",
                                                 "sm": 120, "compute_capability": "12.0"}),
            lambda r: r.update(result_value=1190),
        ):
            report = phase_report()
            mutate(report)
            with self.assertRaises(ValueError):
                validate_phase_probe_report(report, 0, "0000:02:00.0", "kernel")

    def test_system_pageable_memory_contract_requires_both_direct_pointer_allocators(self):
        report = system_pageable_report()
        self.assertEqual(validate_system_pageable_memory_report(
            report, 0, "0000:02:00.0"), "system-pageable-memory-report-contract-pass")
        mutations = (
            lambda r: r.update(expected_pci="0000:09:00.0"),
            lambda r: r["selected_device"].update(unified_addressing=False),
            lambda r: r["selected_device"].update(pageable_memory_access=False),
            lambda r: r["allocators"]["malloc"].update(passed=False),
            lambda r: r["allocators"]["mmap"].update(sizes=[1, 31]),
            lambda r: r["allocators"]["malloc"].update(sizes=[True, 31, 256, 4096, 65537]),
            lambda r: r.update(cleanup_passed=False),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(report)
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_system_pageable_memory_report(candidate, 0, "0000:02:00.0")

    def test_system_pageable_memory_unsupported_is_explicit_and_has_no_allocator_results(self):
        report = system_pageable_report()
        report.update(status="unsupported", error="device does not report pageable memory access",
                      allocators={"malloc": None, "mmap": None})
        report["selected_device"]["pageable_memory_access"] = False
        self.assertEqual(validate_system_pageable_memory_report(
            report, 77, "0000:02:00.0"), "system-pageable-memory-unsupported-report-contract-valid")
        with self.assertRaises(ValueError):
            validate_system_pageable_memory_report(report, 0, "0000:02:00.0")
        inconsistent = copy.deepcopy(report)
        inconsistent["selected_device"]["pageable_memory_access"] = True
        with self.assertRaisesRegex(ValueError, "unsupported pageable-memory result"):
            validate_system_pageable_memory_report(inconsistent, 77, "0000:02:00.0")

    def test_system_pageable_memory_runner_isolated_without_ioctl_observer(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, evidence = root / "probe", root / "module", root / "evidence"
            report = system_pageable_report()
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"synthetic module path")
            result = subprocess.run([
                sys.executable, str(runner), "--phase", "system-pageable-memory",
                "--probe", str(probe), "--module", str(module),
                "--expected-pci", "0000:02:00.0", "--evidence-dir", str(evidence),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            saved = json.loads(next(evidence.glob("*.json")).read_text())
            self.assertEqual(saved["report_contract_qualification"], "system-pageable-memory-report-contract-pass")
            self.assertEqual(saved["qualification"], "untrusted-probe-artifact")
            self.assertIn("--module", saved["command"])
            self.assertIsNone(saved["ioctl_observation"])

    def test_phase_capture_requires_exactly_one_supported_observer_mode(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module = root / "probe", root / "module"
            probe.write_text("#!/bin/sh\nexit 0\n")
            probe.chmod(0o700)
            module.write_bytes(b"unused phase fixture")
            missing = subprocess.run([sys.executable, str(runner), "--phase", "context",
                "--probe", str(probe), "--module", str(module), "--expected-pci", "0000:02:00.0",
                "--evidence-dir", str(root / "evidence")], text=True, capture_output=True, check=False)
            self.assertEqual(missing.returncode, 2)
            self.assertIn("phase requires exactly one isolated BINAPI, NV01_DEVICE_0, NV20_SUBDEVICE_0, or NV2081_BINAPI allocation capture",
                          missing.stderr)

    def test_selected_gpu_runner_records_guard_and_rejects_other_devices(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70],
                      context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module = root / "fixture-probe", root / "fixture.fatbin"
            module.write_bytes(b"CPU fixture only")
            for index, pci in enumerate(("0000:02:00.0", "0000:09:00.0")):
                probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                                 ")\nraise SystemExit(77)\n")
                probe.chmod(0o700)
                destination = root / ("evidence-" + str(index))
                result = subprocess.run(
                    [sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                     "--evidence-dir", str(destination), "--expected-pci", pci],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 77 if index == 0 else 2, result.stderr)
                evidence = json.loads(next(destination.glob("*.json")).read_text())
                self.assertIn("--expected-pci", evidence["command"])
                self.assertEqual(evidence["device_selection"]["expected_pci_bus_id"], "0000" + pci)
                self.assertEqual(evidence["qualification"], "incomplete-hardware-missing" if index == 0
                                 else "invalid-probe-report")

    def test_rtx_only_inventory_accepts_unpinned_map_and_reports_missing_volta(self):
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70],
                      context_coexistence_passed=False,
                      expected_device_pci_by_sm={})
        report["devices"] = report["devices"][1:]
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "fixture-probe"
            probe.write_text("#!" + sys.executable + "\nprint(" +
                             repr(json.dumps(report)) + ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module = root / "fixture.fatbin"
            module.write_bytes(b"CPU fixture only")
            evidence_dir = root / "evidence"
            result = subprocess.run(
                [sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                 "--evidence-dir", str(evidence_dir), "--expected-pci", "0000:02:00.0"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 77, result.stderr)
            evidence = json.loads(next(evidence_dir.glob("*.json")).read_text())
            self.assertEqual(evidence["qualification"], "incomplete-hardware-missing")
            self.assertEqual(evidence["validation_errors"], [])
            self.assertIn("--require-sm", evidence["command"])

    def test_observer_requires_pci_guard_before_spawning(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "spawned"
            observer = root / "observer"
            observer.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
            observer.chmod(0o700)
            probe = root / "probe"
            probe.write_text("#!/bin/sh\nexit 77\n")
            probe.chmod(0o700)
            module = root / "module"
            module.write_bytes(b"CPU fixture")
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                                     "--module", str(module), "--ioctl-observer", str(observer),
                                     "--evidence-dir", str(root / "evidence")],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires --expected-pci", result.stderr)
            self.assertFalse(marker.exists())

    def test_strace_requires_pci_guard_before_spawning(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "spawned"
            tracer = root / "strace"
            tracer.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
            tracer.chmod(0o700)
            probe = root / "probe"
            probe.write_text("#!/bin/sh\nexit 77\n")
            probe.chmod(0o700)
            module = root / "module"
            module.write_bytes(b"CPU fixture")
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                                     "--module", str(module), "--strace-binary", str(tracer),
                                     "--ioctl-trace", "--evidence-dir", str(root / "evidence")],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires --expected-pci", result.stderr)
            self.assertFalse(marker.exists())

    def test_strace_trace_is_bounded_summarized_and_persisted_without_payloads(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, tracer, trace, helper = (root / "probe", root / "module", root / "strace",
                                                     root / "cuda-ioctl.strace", root / "trace-helper")
            probe.write_text("#!" + sys.executable + "\nimport json\nprint(" +
                             repr(json.dumps(report)) + ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            tracer.write_text(
                "#!/usr/bin/env python3\nimport subprocess,sys\n"
                "if sys.argv[1:] == ['--version']:\n print('strace -- version fixture'); raise SystemExit(0)\n"
                "args=sys.argv[1:]\nout=args[args.index('-o')+1]\ncmd=args[args.index('--')+1:]\n"
                "open(out,'w').write('7 ioctl(8</dev/nvidiactl<char 195:255>>, 0xc030462b, 0x1234) = 0\\n')\n"
                "raise SystemExit(subprocess.run(cmd,check=False).returncode)\n")
            tracer.chmod(0o700)
            helper.write_bytes((Path(__file__).resolve().parents[1] /
                                "tools/summarize_rm_ioctl_trace.py").read_bytes())
            destination = root / "evidence"
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--evidence-dir", str(destination),
                "--expected-pci", "0000:02:00.0", "--ioctl-trace",
                "--trace-helper", str(helper), "--ioctl-trace-output", str(trace),
                "--strace-binary", str(tracer)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            observed = evidence["ioctl_trace"]
            self.assertTrue(observed["trace"]["trace_complete"])
            self.assertEqual(observed["strace_version"], "strace -- version fixture")
            self.assertEqual(observed["trace"]["summary"]["parsed_calls"], 1)
            self.assertNotIn("0x1234", json.dumps(evidence))
            self.assertTrue(trace.is_file())
            self.assertEqual(trace.stat().st_mode & 0o777, 0o600)

    def test_enumerate_phase_can_capture_node_open_and_descriptor_lifecycle(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        helper_source = Path(__file__).resolve().parents[1] / "tools/summarize_rm_ioctl_trace.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = phase_report("enumerate")
            probe, module, tracer, trace, helper = (
                root / "probe", root / "module", root / "strace", root / "cuda-enumerate.strace",
                root / "trace-helper")
            probe.write_text("#!" + sys.executable + "\nimport json\nprint(" +
                             repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            tracer.write_text(r'''#!/usr/bin/env python3
import subprocess,sys
if sys.argv[1:] == ["--version"]:
 print("strace -- version fixture"); raise SystemExit(0)
args=sys.argv[1:]
out=args[args.index("-o")+1]
cmd=args[args.index("--")+1:]
open(out,"w").write('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 3</dev/nvidiactl<char 195:255>>\n123 ioctl(3</dev/nvidiactl<char 195:255>>, 0xc01046d3, 0x7ffe1234) = 0\n')
raise SystemExit(subprocess.run(cmd,check=False).returncode)
''')
            tracer.chmod(0o700)
            helper.write_bytes(helper_source.read_bytes())
            destination = root / "evidence"
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--evidence-dir", str(destination),
                "--expected-pci", "0000:02:00.0", "--phase", "enumerate", "--ioctl-trace",
                "--trace-helper", str(helper), "--ioctl-trace-output", str(trace),
                "--strace-binary", str(tracer)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            observed = evidence["ioctl_trace"]["trace"]["summary"]
            self.assertEqual(observed["schema"], "nvidia-hybrid-node-open-trace-v1")
            self.assertTrue(observed["trace_complete"])
            self.assertEqual(observed["successful_selected_node_open_count"], 1)
            self.assertEqual(observed["ioctl_counts_by_node"], {"nvidiactl": 1})
            self.assertNotIn("0x7ffe1234", json.dumps(evidence))
            self.assertEqual(trace.stat().st_mode & 0o777, 0o600)
            self.assertEqual(evidence["qualification"], "untrusted-probe-artifact")
            self.assertEqual(evidence["report_contract_qualification"], "phase-report-contract-pass")

    def test_context_phase_can_capture_generic_ioctl_calls(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        helper_source = Path(__file__).resolve().parents[1] / "tools/summarize_rm_ioctl_trace.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = phase_report("context", pci="0000:81:00.0", sm=70)
            probe, module, tracer, trace, helper = (
                root / "probe", root / "module", root / "strace", root / "cuda-context.strace",
                root / "trace-helper")
            probe.write_text("#!" + sys.executable + "\nimport json\nprint(" +
                             repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            tracer.write_text(r'''#!/usr/bin/env python3
import subprocess,sys
if sys.argv[1:] == ["--version"]:
 print("strace -- version fixture"); raise SystemExit(0)
args=sys.argv[1:]
out=args[args.index("-o")+1]
cmd=args[args.index("--")+1:]
open(out,"w").write('123 openat(AT_FDCWD, "/dev/nvidiactl", O_RDWR) = 8</dev/nvidiactl<char 195:255>>\n'
                      '123 openat(AT_FDCWD, "/dev/nvidia-uvm", O_RDWR) = 9</dev/nvidia-uvm<char 237:0>>\n'
                      '123 ioctl(9</dev/nvidia-uvm<char 237:0>>, 0x19, 0x7ffe1234) = 0\n'
                      '123 close(9</dev/nvidia-uvm<char 237:0>>) = 0\n'
                      '123 close(8</dev/nvidiactl<char 195:255>>) = 0\n')
raise SystemExit(subprocess.run(cmd,check=False).returncode)
''')
            tracer.chmod(0o700)
            helper.write_bytes(helper_source.read_bytes())
            destination = root / "evidence"
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--evidence-dir", str(destination),
                "--expected-pci", "0000:81:00.0", "--phase", "context", "--ioctl-trace",
                "--trace-helper", str(helper), "--ioctl-trace-output", str(trace),
                "--strace-binary", str(tracer)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            summary = evidence["ioctl_trace"]["trace"]["summary"]
            self.assertEqual(summary["schema"], "nvidia-hybrid-node-open-trace-v1")
            self.assertEqual(summary["ioctl_counts_by_node"], {"nvidia-uvm": 1})
            self.assertEqual(summary["selected_node_descriptors_open_at_trace_end"], 0)
            self.assertNotIn("0x7ffe1234", json.dumps(evidence))
            self.assertEqual(trace.stat().st_mode & 0o777, 0o600)
            self.assertEqual(evidence["qualification"], "untrusted-probe-artifact")
            self.assertEqual(evidence["report_contract_qualification"], "phase-report-contract-pass")

    def test_enumerate_phase_can_capture_redacted_rm_control_headers(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer, destination = (root / "probe", root / "module",
                                                     root / "observer", root / "evidence")
            probe_report = phase_report("enumerate")
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(probe_report)) +
                             ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            packet = {"command": 0x205, "flags": 3, "params_size": 0, "status": 0,
                      "hClientPresent": True, "hObjectPresent": True,
                      "client_object_equal": False,
                      "client_matches_prior_root_allocation": False,
                      "object_matches_prior_root_allocation": False}
            observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v23",
                        "trace_complete": True, "child_exit_code": 0,
                        "control_path": "/dev/nvidiactl", "nested_pointers_read": False,
                        "payload_scope": ("fixed NVOS54 RM_CONTROL headers only; handles redacted; "
                                          "nested parameter payloads omitted"),
                        "records": [{"tid": 1234, "fd": 7, "fd_role": "control",
                                     "request": 0xC020462A, "packet_size": 32,
                                     "operation": "rm_control_header", "entry": packet,
                                     "exit": packet, "syscall_return": 0}], "errors": []}
            observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                "from pathlib import Path\n"
                "assert '--rm-control-headers' in sys.argv and '--rm-control' not in sys.argv\n"
                "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
            observer.chmod(0o700)
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--ioctl-observer", str(observer),
                "--expected-pci", "0000:02:00.0", "--phase", "enumerate",
                "--rm-control-headers", "--evidence-dir", str(destination)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            self.assertTrue(evidence["rm_control_headers_capture_requested"])
            self.assertTrue(evidence["rm_control_headers_records_seen"])
            self.assertEqual(evidence["rm_control_headers_record_count"], 1)
            self.assertEqual(evidence["ioctl_observation"]["report"], observed)
            self.assertNotIn('"hClient":', json.dumps(evidence))
            self.assertEqual(evidence["qualification"], "untrusted-probe-artifact")
            self.assertEqual(evidence["report_contract_qualification"], "phase-report-contract-pass")

            bad_observed = copy.deepcopy(observed)
            bad_observed["records"][0]["entry"] = None
            observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                "from pathlib import Path\n"
                "assert '--rm-control-headers' in sys.argv and '--rm-control' not in sys.argv\n"
                "Path(sys.argv[2]).write_text(" + repr(json.dumps(bad_observed)) + ")\n"
                "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
            destination_bad = root / "evidence-bad"
            rejected = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--ioctl-observer", str(observer),
                "--expected-pci", "0000:02:00.0", "--phase", "enumerate",
                "--rm-control-headers", "--evidence-dir", str(destination_bad)],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(rejected.returncode, 0)

            allocation = {"layout": "NVOS21", "hRoot": 7, "hObjectParent": 17,
                          "hObjectNew": 18, "pAllocParms": 0x123456789abcdef0}
            bad_observed = copy.deepcopy(observed)
            bad_observed["records"].append({
                "tid": 1234, "fd": 7, "fd_role": "control",
                "request": 0xC030462B, "packet_size": 48, "operation": "alloc",
                "entry": allocation, "exit": allocation, "syscall_return": 0})
            observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                "from pathlib import Path\n"
                "assert '--rm-control-headers' in sys.argv and '--rm-control' not in sys.argv\n"
                "Path(sys.argv[2]).write_text(" + repr(json.dumps(bad_observed)) + ")\n"
                "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
            destination_bad_records = root / "evidence-bad-records"
            rejected_records = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--ioctl-observer", str(observer),
                "--expected-pci", "0000:02:00.0", "--phase", "enumerate",
                "--rm-control-headers", "--evidence-dir", str(destination_bad_records)],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(rejected_records.returncode, 0)
            evidence_bad_records = json.loads(next(destination_bad_records.glob(
                "hardware-probe-*.json")).read_text())
            self.assertTrue(any("unexpected records" in error
                                for error in evidence_bad_records["validation_errors"]))

    def test_observer_report_is_archived_and_failures_cannot_pass(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            for index, change in enumerate(({}, {"trace_complete": False},
                    {"child_exit_code": 0}, {"control_path": "/dev/null"},
                    {"errors": ["partial read"]})):
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v1", "trace_complete": True,
                            "child_exit_code": 77, "control_path": "/dev/nvidiactl",
                            "nested_pointers_read": False,
                            "records": [], "errors": []}
                observed.update(change)
                observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--expected-pci", "0000:02:00.0", "--evidence-dir", str(destination)],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 77 if index == 0 else 2, result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertEqual(evidence["ioctl_observation"]["report"], observed)
                self.assertEqual(len(evidence["ioctl_observation"]["artifact"]["sha256"]), 64)
                self.assertEqual(len(evidence["artifacts"]["ioctl_observer"]["sha256"]), 64)
                self.assertEqual(evidence["qualification"], "incomplete-hardware-missing" if index == 0
                                 else "invalid-probe-report")

    def test_gpu_id_info_observer_requires_explicit_scope_and_version(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        result = subprocess.run([sys.executable, str(runner), "--gpu-id-info"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--gpu-id-info requires --ioctl-observer", result.stderr)

        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            for index, scope in enumerate((
                    "exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 payload only; addresses omitted",
                    "all RM control payloads")):
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v3", "trace_complete": True,
                            "child_exit_code": 77, "control_path": "/dev/nvidiactl",
                            "nested_pointers_read": True, "nested_pointer_scope": scope,
                            "records": [], "errors": []}
                observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("gpu-info-evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--gpu-id-info", "--expected-pci", "0000:02:00.0",
                    "--evidence-dir", str(destination)], capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, 77 if index == 0 else 2,
                                 result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["gpu_id_info_capture_requested"])
                self.assertEqual(evidence["ioctl_observation"]["report"], observed)

    def test_attached_ids_observer_requires_explicit_exact_scope_and_version(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        result = subprocess.run([sys.executable, str(runner), "--attached-ids"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--attached-ids requires --ioctl-observer", result.stderr)

        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            cases = (
                (False, "exact NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payload only; addresses omitted"),
                (True, "exact NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 and "
                       "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS payloads only; addresses omitted"),
            )
            for index, (id_info, scope) in enumerate(cases):
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v4", "trace_complete": True,
                            "child_exit_code": 77, "control_path": "/dev/nvidiactl",
                            "nested_pointers_read": True, "nested_pointer_scope": scope,
                            "records": [{"operation": "gpu_attached_ids"}], "errors": []}
                observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("attached-evidence-" + str(index))
                flags = ["--attached-ids"] + (["--gpu-id-info"] if id_info else [])
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer), *flags,
                    "--expected-pci", "0000:02:00.0", "--evidence-dir", str(destination)],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["attached_ids_capture_requested"])
                self.assertEqual(evidence["gpu_id_info_capture_requested"], id_info)
                self.assertEqual(evidence["ioctl_observation"]["report"], observed)

            observed["nested_pointer_scope"] = "all RM payloads"
            observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                "from pathlib import Path\n"
                "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
            observer.chmod(0o700)
            destination = root / "attached-evidence-wrong-scope"
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--ioctl-observer", str(observer), "--attached-ids",
                "--gpu-id-info", "--expected-pci", "0000:02:00.0", "--evidence-dir", str(destination)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            self.assertEqual(evidence["qualification"], "invalid-probe-report")

    def test_rm_control_observer_requires_fixed_header_scope_and_version(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        result = subprocess.run([sys.executable, str(runner), "--rm-control"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--rm-control requires --ioctl-observer", result.stderr)

        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            scopes = (
                "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted",
                "unbounded RM payload capture",
            )
            for index, scope in enumerate(scopes):
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v5",
                            "trace_complete": True, "child_exit_code": 77,
                            "control_path": "/dev/nvidiactl", "nested_pointers_read": False,
                            "payload_scope": scope, "records": [
                                {"operation": "rm_control_header", "entry": {"command": 1},
                                 "exit": {"command": 1, "status": 0}}], "errors": []}
                observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("rm-control-evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer), "--rm-control",
                    "--expected-pci", "0000:02:00.0", "--evidence-dir", str(destination)],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 77 if index == 0 else 2,
                                 result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["rm_control_capture_requested"])
                self.assertEqual(evidence["ioctl_observation"]["report"], observed)

    def test_p2p_control_observer_accepts_complete_empty_nested_scope(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        missing = subprocess.run([sys.executable, str(runner), "--p2p-control"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(missing.returncode, 2)
        self.assertIn("--p2p-control requires --ioctl-observer", missing.stderr)
        missing_rm = subprocess.run([sys.executable, str(runner), "--p2p-control",
                                     "--ioctl-observer", "/does-not-need-to-exist",
                                     "--expected-pci", "0000:02:00.0"],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(missing_rm.returncode, 2)
        self.assertIn("--p2p-control requires --rm-control", missing_rm.stderr)

        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        scope = ("RM_CONTROL headers plus exact NV503C P2P control payloads; raw addresses, "
                 "handles, and VA-space tokens omitted; other nested parameter payloads omitted")
        observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v17", "trace_complete": True,
                    "child_exit_code": 77, "control_path": "/dev/nvidiactl",
                    "nested_pointers_read": False, "payload_scope": scope,
                    "p2p_control_payload_snapshots_read": 0,
                    "records": [{"operation": "rm_control_header"}], "errors": []}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                "from pathlib import Path\n"
                "assert '--rm-control' in sys.argv and '--p2p-control' in sys.argv\n"
                "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
            observer.chmod(0o700)
            destination = root / "p2p-control-evidence"
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--ioctl-observer", str(observer), "--rm-control",
                "--p2p-control", "--expected-pci", "0000:02:00.0", "--evidence-dir",
                str(destination)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            self.assertTrue(evidence["p2p_control_capture_requested"])
            self.assertFalse(evidence["p2p_control_records_seen"])
            self.assertEqual(evidence["p2p_control_payload_snapshots_read"], 0)

    def test_probed_ids_observer_requires_exact_v6_fixed_payload_and_record(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        result = subprocess.run([sys.executable, str(runner), "--probed-ids"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--probed-ids requires --ioctl-observer", result.stderr)

        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            arrays = {
                "gpuIds": [7] + [0xffffffff] * 31,
                "excludedGpuIds": [0xffffffff] * 32,
                "gpuFlags": [1] + [0] * 31,
            }
            payload = {"command": 0x214, "flags": 0, "params_size": 384,
                       "status": 0, "client_handle_present": True,
                       "object_handle_present": True, "client_matches_prior_root_allocation": False,
                       "object_matches_prior_root_allocation": False, "client_object_equal": True,
                       **arrays}
            cases = (
                ("exact NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payload only; addresses omitted", True, True),
                ("all nested pointers", True, False),
                ("exact NV0000_CTRL_CMD_GPU_GET_PROBED_IDS payload only; addresses omitted", False, False),
            )
            for index, (scope, include_record, valid) in enumerate(cases):
                records = ([{"operation": "gpu_probed_ids", "request": 0xc020462a,
                             "packet_size": 32, "entry": payload, "exit": payload,
                             "syscall_return": 0}] if include_record else [])
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v6", "trace_complete": True,
                            "child_exit_code": 77, "control_path": "/dev/nvidiactl",
                            "nested_pointers_read": True, "nested_pointer_scope": scope,
                            "records": records, "errors": []}
                observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("probed-evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--probed-ids", "--expected-pci", "0000:02:00.0",
                    "--evidence-dir", str(destination)], capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, 77 if valid else 2,
                                 result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["probed_ids_capture_requested"])
                self.assertEqual(evidence["probed_ids_records_seen"], include_record)
                self.assertEqual(evidence["ioctl_observation"]["report"], observed)

    def test_channel_alloc_observer_requires_redacted_class_payload_and_success(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        result = subprocess.run([sys.executable, str(runner), "--channel-alloc"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--channel-alloc requires --ioctl-observer", result.stderr)

        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70], context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        descriptor = {"basePresent": True, "size": 4096, "addressSpace": 2, "cacheAttrib": 3}
        channel = {
            "classPayloadBytes": 368, "hObjectErrorPresent": False,
            "hObjectBufferPresent": False, "gpFifoOffsetNonzero": True,
            "gpFifoEntries": 64, "flags": 0, "hContextSharePresent": True,
            "hVASpacePresent": False, "hUserdMemoryPresentCount": 1,
            "userdOffsetNonzeroCount": 1, "engineType": 0x31,
            "subDeviceId": 1, "cidPresent": False,
            "hObjectEccErrorPresent": False,
            "memoryDescriptors": {"instanceMem": descriptor, "userdMem": descriptor,
                                  "ramfcMem": descriptor, "mthdbufMem": descriptor},
            "reservedFields": {"hPhysChannelGroupPresent": False,
                               "internalFlagsZero": True, "errorNotifierMemZero": True,
                               "eccErrorNotifierMemZero": True, "processIdZero": True,
                               "subProcessIdZero": True, "encryptIvZero": True,
                               "decryptIvZero": True, "hmacNonceZero": True,
                               "tpcConfigIdZero": True},
        }
        packet = {"layout": "NVOS64", "hClass": 0xc36f, "paramsSize": 0,
                  "flags": 0, "status": 0, "hRootPresent": True,
                  "hObjectParentPresent": True, "hObjectNewPresent": True,
                  "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                  "channelPayloadState": "r580-r595-class-layout-parsed", "channel": channel}
        volta_row = {"request": 0xc030462b, "packet_size": 48,
               "entry": packet, "exit": packet, "syscall_return": 0,
               "operation": "channel_alloc", "fd_role": "control"}
        blackwell_packet = {**packet, "hClass": 0xc96f}
        blackwell_row = {**volta_row, "entry": blackwell_packet, "exit": blackwell_packet}
        scope = ("VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed "
                 "using the byte-identical pinned R580.178.04/R595.99.02 "
                 "NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            leaked_packet = {**packet, "gpFifoOffset": 123456789}
            leaked_row = {**volta_row, "entry": leaked_packet}
            cases = (
                (scope, [blackwell_row, volta_row], True, 4, 77),
                (scope, [volta_row], True, 2, 77),
                ("all RM payloads", [blackwell_row], True, 2, 2),
                (scope, [], False, 0, 2),
                (scope, [leaked_row], True, 2, 2),
            )
            for index, (observed_scope, rows, nested, snapshots, expected_code) in enumerate(cases):
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v9", "trace_complete": True,
                            "child_exit_code": 77, "control_path": "/dev/nvidiactl",
                            "nested_pointers_read": nested,
                            "channel_payload_snapshots_read": snapshots,
                            "nested_pointer_scope": observed_scope,
                            "gpu_path": "/dev/nvidia0",
                            "object_class_resolution_scope":
                                "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed",
                            "records": rows, "errors": []}
                observer.write_text("#!" + sys.executable + "\nimport subprocess,sys,json\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[2]).write_text(" + repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("channel-evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--channel-alloc", "--expected-pci", "0000:02:00.0",
                    "--evidence-dir", str(destination)], capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["channel_alloc_capture_requested"])
                self.assertEqual(evidence["channel_alloc_records_seen"], bool(rows))

    def test_binapi_observer_requires_its_capture_contract(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as tmp:
            observer = Path(tmp) / "observer"
            missing_observer = subprocess.run(
                [sys.executable, str(runner), "--binapi-control"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(missing_observer.returncode, 2)
            self.assertIn("--binapi-control requires --ioctl-observer",
                          missing_observer.stderr)
            missing_rm = subprocess.run(
                [sys.executable, str(runner), "--binapi-control", "--ioctl-observer",
                 str(observer), "--expected-pci", "0000:02:00.0"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(missing_rm.returncode, 2)
            self.assertIn("--binapi-control requires --rm-control", missing_rm.stderr)

    def test_binapi_observer_validates_redacted_shape_and_archives_capture(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        probe_report = complete_report()
        probe_report.update(status="incomplete", hybrid_validated=False,
                            required_set_passed=False, missing_sm=[70],
                            context_coexistence_passed=False)
        probe_report["devices"] = probe_report["devices"][1:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(probe_report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            cases = (("valid", 77, True, 2), ("empty", 77, False, 0),
                     ("bad-mask-count", 2, None, None))
            for case, expected_code, records_seen, snapshots in cases:
                observed = binapi_observation(case)
                observer.write_text("#!" + sys.executable + "\nimport json,subprocess,sys\n"
                    "from pathlib import Path\n"
                    "args=sys.argv[1:]\n"
                    "assert '--rm-control' in args and '--binapi-control' in args\n"
                    "assert args[args.index('--gpu-path')+1] == '/dev/nvidia0'\n"
                    "Path(args[args.index('--output')+1]).write_text(" +
                    repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(args[args.index('--')+1:], check=False).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("binapi-evidence-" + case)
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--rm-control", "--binapi-control", "--expected-pci", "0000:02:00.0",
                    "--gpu-path", "/dev/nvidia0", "--evidence-dir", str(destination)], capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, expected_code,
                                 result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["binapi_control_capture_requested"])
                self.assertEqual(evidence["binapi_control_records_seen"], records_seen,
                                 f"{case}: {evidence['validation_errors']}")
                self.assertEqual(evidence["binapi_payload_snapshots_read"], snapshots,
                                 f"{case}: {evidence['validation_errors']}")
                if expected_code == 77:
                    self.assertEqual(evidence["qualification"], "incomplete-hardware-missing")
                else:
                    self.assertEqual(evidence["qualification"], "invalid-probe-report")

    def test_device_alloc_phase_capture_isolated_and_archived(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        probe_report = phase_report("context", pci="0000:02:00.0", sm=120)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(probe_report)) +
                             ")\nraise SystemExit(0)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            observed = device_alloc_observation()
            observer.write_text("#!" + sys.executable + "\nimport json,subprocess,sys\n"
                "from pathlib import Path\nargs=sys.argv[1:]\n"
                "assert '--device-alloc' in args and '--binapi-control' not in args\n"
                "assert args[args.index('--gpu-path')+1] == '/dev/nvidia0'\n"
                "Path(args[args.index('--output')+1]).write_text(" +
                repr(json.dumps(observed)) + ")\n"
                "raise SystemExit(subprocess.run(args[args.index('--')+1:], check=False).returncode)\n")
            observer.chmod(0o700)
            destination = root / "device-alloc-evidence"
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                "--module", str(module), "--ioctl-observer", str(observer), "--device-alloc",
                "--phase", "context", "--expected-pci", "0000:02:00.0",
                "--gpu-path", "/dev/nvidia0", "--evidence-dir", str(destination)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
            self.assertEqual(evidence["qualification"], "untrusted-probe-artifact")
            self.assertEqual(evidence["report_contract_qualification"], "phase-report-contract-pass")
            self.assertEqual(evidence["device_alloc_payload_snapshots_read"], 2)
            self.assertTrue(evidence["device_alloc_records_seen"])

    def test_rusd_observer_validates_only_the_pinned_poll_mask(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        missing = subprocess.run([sys.executable, str(runner), "--rusd-alloc"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(missing.returncode, 2)
        self.assertIn("--rusd-alloc requires --ioctl-observer", missing.stderr)

        probe_report = complete_report()
        probe_report.update(status="incomplete", hybrid_validated=False,
                            required_set_passed=False, missing_sm=[70],
                            context_coexistence_passed=False)
        probe_report["devices"] = probe_report["devices"][1:]
        packet = {"layout": "NVOS64", "hClass": 0xde, "paramsSize": 0,
                  "flags": 0, "status": 0, "hRootPresent": True,
                  "hObjectParentPresent": True, "hObjectNewPresent": True,
                  "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                  "rusdPayloadState": "r580-r595-class-layout-parsed",
                  "rusd": {"classPayloadBytes": 8, "polledDataMask": 5}}
        record = {"tid": 81, "fd": 7, "fd_role": "gpu", "request": 0xc030462b,
                  "packet_size": 48, "operation": "rusd_alloc", "entry": packet,
                  "exit": dict(packet), "syscall_return": 0}
        scope = ("RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned "
                 "8-byte polledDataMask; raw addresses and handles omitted")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(probe_report)) +
                             ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            cases = (([record], 2, 77), ([], 0, 77), ([], 1, 2),
                     ([{**record, "entry": {**packet, "rusd":
                        {"classPayloadBytes": 8, "polledDataMask": 5, "raw": 123}}}], 2, 2))
            for index, (records, snapshots, expected_code) in enumerate(cases):
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v14",
                            "trace_complete": True, "child_exit_code": 77,
                            "control_path": "/dev/nvidiactl", "gpu_path": "/dev/nvidia0",
                            "nested_pointers_read": True, "nested_pointer_scope": scope,
                            "rusd_payload_snapshots_read": snapshots,
                            "records": records, "errors": []}
                observer.write_text("#!" + sys.executable + "\nimport json,subprocess,sys\n"
                    "from pathlib import Path\n"
                    "args=sys.argv[1:]\n"
                    "assert '--rusd-alloc' in args\n"
                    "assert args[args.index('--gpu-path')+1] == '/dev/nvidia0'\n"
                    "Path(args[args.index('--output')+1]).write_text(" +
                    repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(args[args.index('--')+1:], check=False).returncode)\n")
                observer.chmod(0o700)
                destination = root / ("rusd-evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--rusd-alloc", "--expected-pci", "0000:02:00.0",
                    "--evidence-dir", str(destination)], capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
                evidence = json.loads(next(destination.glob("hardware-probe-*.json")).read_text())
                self.assertTrue(evidence["rusd_alloc_capture_requested"])
                self.assertEqual(evidence["rusd_alloc_records_seen"], bool(records))
                if expected_code == 77:
                    self.assertEqual(evidence["rusd_polled_data_masks"], [5] if records else [])

    def test_rusd_capture_cannot_be_combined_with_other_capture_or_memory_modes(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        for extra in (("--gpu-id-info",), ("--map-memory",), ("--managed-memory",),
                      ("--ioctl-trace",)):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                observer, probe, module = root / "observer", root / "probe", root / "module"
                observer.write_text("#!/bin/sh\nexit 0\n")
                observer.chmod(0o700)
                probe.write_text("#!/bin/sh\nexit 77\n")
                probe.chmod(0o700)
                module.write_bytes(b"CPU fixture")
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--rusd-alloc", "--expected-pci", "0000:02:00.0", *extra,
                    "--evidence-dir", str(root / "evidence")], capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, 2)

    def test_complete_device_evidence_is_required(self):
        self.assertEqual(validate_probe_report(
            complete_report(), 0,
            expected_device_pci_by_sm={70: "0000:01:00.0", 120: "0000:02:00.0"}),
            "report-contract-valid")
        with self.assertRaises(ValueError):
            validate_probe_report({"hybrid_validated": True,
                                   "required_set_passed": True, "missing_sm": []}, 0)

    def test_untrusted_executable_is_rejected_before_probe_execution(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module = root / "fake-probe", root / "fake.fatbin"
            evidence_dir, invoked = root / "evidence", root / "probe-invoked"
            probe.write_text(
                "#!" + sys.executable + "\nimport json, sys\nfrom pathlib import Path\n"
                "Path(" + repr(str(invoked)) + ").write_text('ran:' + ' '.join(sys.argv[1:]))\n"
                "print(" + repr(json.dumps(complete_report())) + ")\n"
            )
            probe.chmod(0o700)
            module.write_bytes(b"not a CUDA fatbin")
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0",
                "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10, check=False)

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertFalse(invoked.exists(), "an untrusted probe must not be executed")
            saved = json.loads(next(evidence_dir.glob(
                "hardware-probe-preflight-*.json")).read_text())
            self.assertEqual(saved["schema"],
                             "nvidia-hybrid-hardware-acceptance-preflight-v1")
            self.assertEqual(saved["report_contract_qualification"],
                             "not-run-untrusted-probe")
            self.assertEqual(saved["qualification"], "untrusted-probe-artifact")
            self.assertEqual(saved["probe_build_trust"]["status"], "untrusted")
            self.assertFalse(saved["process_started"])
            self.assertEqual(next(evidence_dir.glob(
                "hardware-probe-preflight-*.json")).stat().st_mode & 0o777, 0o600)
            self.assertIn("pinned executable", " ".join(saved["validation_errors"]))

    def test_untrusted_concurrent_and_peer_probe_contract_handlers_never_run(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance.py")
        contract = {"schema": "nvidia-hybrid-probe-contract-v1", "contract_version": 7}
        for option in ("--concurrent-kernels", "--peer-transfer"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                probe, module = root / "fake-probe", root / "fake.fatbin"
                invoked, evidence_dir = root / "probe-invoked", root / "evidence"
                probe.write_text(
                    "#!" + sys.executable + "\nimport json, sys\nfrom pathlib import Path\n"
                    "Path(" + repr(str(invoked)) + ").write_text('ran:' + ' '.join(sys.argv[1:]))\n"
                    "print(" + repr(json.dumps(contract)) + " if sys.argv[1:] == ['--contract'] else '{}')\n"
                )
                probe.chmod(0o700)
                module.write_bytes(b"not a CUDA fatbin")
                result = subprocess.run([
                    sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                    "--expected-device", "70=0000:01:00.0",
                    "--expected-device", "120=0000:02:00.0", option,
                    "--evidence-dir", str(evidence_dir),
                ], capture_output=True, text=True, timeout=10, check=False)

                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(invoked.exists(), "an untrusted --contract handler must not run")
                saved = json.loads(next(evidence_dir.glob(
                    "hardware-probe-preflight-*.json")).read_text())
                self.assertFalse(saved["process_started"])
                self.assertEqual(saved["report_contract_qualification"],
                                 "not-run-untrusted-probe")

    def test_pinned_probe_and_fatbin_are_trusted_after_remote_style_copy(self):
        if not DEFAULT_PROBE.is_file() or not DEFAULT_MODULE.is_file():
            self.skipTest("pinned local CUDA artifacts are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module = root / "probe", root / "module"
            shutil.copyfile(DEFAULT_PROBE, probe)
            shutil.copyfile(DEFAULT_MODULE, module)
            identity = trusted_probe_build_identity(probe, module)
            self.assertEqual(identity["status"], "trusted-pinned-build")
            self.assertEqual(identity["provenance"], "pinned-probe-and-fatbin-sha256")

            module.write_bytes(b"substituted module")
            with self.assertRaisesRegex(ValueError, "pinned fatbin"):
                trusted_probe_build_identity(probe, module)

    def test_libcuda_override_requires_matching_hash_before_running_probe(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module = root / "probe", root / "module"
            override, invoked = root / "libcuda.so.1", root / "probe-invoked"
            probe.write_text("#!" + sys.executable + "\nfrom pathlib import Path\n"
                             "Path(" + repr(str(invoked)) + ").write_text('ran')\n"
                             "print(" + repr(json.dumps(complete_report())) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            override.write_bytes(b"pinned fake libcuda")
            base = [sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--libcuda-override", str(override),
                    "--evidence-dir", str(root / "evidence")]
            missing_hash = subprocess.run(base, capture_output=True, text=True, timeout=10)
            self.assertEqual(missing_hash.returncode, 2)
            self.assertIn("--libcuda-override requires --libcuda-sha256", missing_hash.stderr)
            self.assertFalse(invoked.exists())

            wrong_hash = subprocess.run(base + ["--libcuda-sha256", "0" * 64],
                                        capture_output=True, text=True, timeout=10)
            self.assertEqual(wrong_hash.returncode, 2)
            self.assertIn("SHA-256", wrong_hash.stderr)
            self.assertFalse(invoked.exists())

    def test_cli_forwards_and_archives_hash_pinned_libcuda_override(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, override = root / "probe", root / "module", root / "libcuda.so.1"
            evidence_dir = root / "evidence"
            report = complete_report()
            override.write_bytes(b"CPU-only pinned libcuda fixture")
            report["driver_library_path"] = str(override.resolve())
            probe.write_text("#!" + sys.executable + "\nimport json, sys\n"
                             "expected = " + repr(str(override.resolve())) + "\n"
                             "assert sys.argv[sys.argv.index('--libcuda') + 1] == expected\n"
                             "print(" + repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only module fixture")
            digest = hashlib.sha256(override.read_bytes()).hexdigest()
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--libcuda-override", str(override), "--libcuda-sha256", digest,
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0",
                "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            saved = json.loads(next(evidence_dir.glob("hardware-probe-*.json")).read_text())
            before = saved["artifacts"]["libcuda_override_before_run"]
            after = saved["artifacts"]["libcuda_override_after_run"]
            self.assertEqual(before, after)
            self.assertEqual(before["sha256"], digest)
            self.assertEqual(saved["artifacts"]["driver_library_observed_after_run"], before)
            self.assertEqual(saved["qualification"], "untrusted-probe-artifact")

    def test_cli_rejects_libcuda_override_changed_during_probe(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, override = root / "probe", root / "module", root / "libcuda.so.1"
            evidence_dir = root / "evidence"
            override.write_bytes(b"before")
            report = complete_report()
            report["driver_library_path"] = str(override.resolve())
            probe.write_text("#!" + sys.executable + "\nimport json\n"
                             "from pathlib import Path\n"
                             "Path(" + repr(str(override.resolve())) + ").write_bytes(b'after')\n"
                             "print(" + repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only module fixture")
            digest = hashlib.sha256(override.read_bytes()).hexdigest()
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--libcuda-override", str(override), "--libcuda-sha256", digest,
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0",
                "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            saved = json.loads(next(evidence_dir.glob("hardware-probe-*.json")).read_text())
            self.assertEqual(saved["qualification"], "invalid-probe-report")
            self.assertTrue(any("identity changed" in error
                                for error in saved["validation_errors"]),
                            saved["validation_errors"])

    def test_cli_rejects_probe_report_for_a_different_libcuda_path(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, override = root / "probe", root / "module", root / "libcuda.so.1"
            evidence_dir = root / "evidence"
            override.write_bytes(b"pinned fake libcuda")
            report = complete_report()
            report["driver_library_path"] = str(Path(sys.executable).resolve())
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only module fixture")
            digest = hashlib.sha256(override.read_bytes()).hexdigest()
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--libcuda-override", str(override), "--libcuda-sha256", digest,
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0",
                "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            saved = json.loads(next(evidence_dir.glob("hardware-probe-*.json")).read_text())
            self.assertEqual(saved["qualification"], "invalid-probe-report")
            self.assertTrue(any("other than the pinned override" in error
                                for error in saved["validation_errors"]))

    def test_cli_forwards_and_validates_exact_device_pair(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        report = complete_report()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, evidence_dir = root / "probe", root / "module", root / "evidence"
            probe.write_text("#!" + sys.executable + "\nprint(" + repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only acceptance fixture")
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0",
                "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            saved = json.loads(next(evidence_dir.glob("*.json")).read_text())
            self.assertEqual(saved["report_contract_qualification"], "report-contract-valid")
            self.assertEqual(saved["qualification"], "untrusted-probe-artifact")
            self.assertIn("70=00000000:01:00.0", saved["command"])
            self.assertIn("120=00000000:02:00.0", saved["command"])
            self.assertEqual(saved["probe"]["expected_device_pci_by_sm"],
                             {"70": "0000:01:00.0", "120": "0000:02:00.0"})

    def test_cli_forwards_concurrent_dispatch_request_to_exact_pair(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        report = complete_report()
        report.update(concurrent_kernel_test_requested=True,
                      concurrent_kernel_dispatch_passed=True,
                      concurrent_kernel_dispatch={
                          "schema": "nvidia-hybrid-concurrent-dispatch-v1",
                          "qualification": "host-dispatch-window-overlap-profiler-timeline-required",
                          "requested": True, "passed": True,
                          "gpu_timeline_overlap_validated": False,
                          "rounds": 2048,
                          "devices": [
                              {"sm": 70, "pci_bus_id": "0000:01:00.0",
                               "kernel_name": "hybrid_concurrent_work", "rounds": 2048,
                               "numeric_result_passed": True,
                               "host_window_start_ns": 100, "host_window_end_ns": 2000},
                              {"sm": 120, "pci_bus_id": "0000:02:00.0",
                               "kernel_name": "hybrid_concurrent_work", "rounds": 2048,
                               "numeric_result_passed": True,
                               "host_window_start_ns": 150, "host_window_end_ns": 1800},
                          ]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, evidence_dir = root / "probe", root / "module", root / "evidence"
            contract = {
                "schema": "nvidia-hybrid-probe-contract-v1", "contract_version": 7,
                "probe_report_schema": "nvidia-hybrid-probe-v2",
                "probe_report_fields": ["expected_device_pci_by_sm", "memory_mode",
                    "managed_prefetch_requested", "managed_prefetch_api", "devices",
                    "cuda_graphs_requested", "cuda_graph_api", "performance_benchmark_requested",
                    "concurrent_kernel_test_requested", "concurrent_kernel_dispatch_passed",
                    "concurrent_kernel_dispatch"],
                "device_report_fields": ["concurrent_managed_access", "pageable_memory_access",
                    "pageable_memory_access_uses_host_page_tables", "managed_memory_passed",
                    "managed_prefetch_passed", "cuda_graphs_passed", "cuda_graph_launches"],
            }
            probe.write_text("#!" + sys.executable + "\nimport json, sys\n"
                "print(" + repr(json.dumps(contract)) + " if sys.argv[1:] == ['--contract'] else "
                + repr(json.dumps(report)) + ")\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only concurrent dispatch fixture")
            result = subprocess.run([
                sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0", "--concurrent-kernels",
                "--evidence-dir", str(evidence_dir),
            ], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            saved = json.loads(next(evidence_dir.glob("*.json")).read_text())
            self.assertEqual(saved["report_contract_qualification"], "report-contract-valid")
            self.assertEqual(saved["qualification"], "untrusted-probe-artifact")
            self.assertIn("--concurrent-kernels", saved["command"])

    def test_concurrent_dispatch_cli_requires_the_exact_hybrid_pair(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module = root / "probe", root / "module"
            probe.write_text("#!/bin/sh\nexit 77\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU-only fixture")
            base = [sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--concurrent-kernels",
                    "--evidence-dir", str(root / "evidence")]
            missing_pair = subprocess.run(base, capture_output=True, text=True, timeout=10)
            self.assertEqual(missing_pair.returncode, 2)
            mixed_phase = subprocess.run(base + ["--phase", "kernel", "--expected-pci",
                "0000:02:00.0"], capture_output=True, text=True, timeout=10)
            self.assertEqual(mixed_phase.returncode, 2)
            stale_probe = subprocess.run(base + [
                "--expected-device", "70=0000:01:00.0",
                "--expected-device", "120=0000:02:00.0"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(stale_probe.returncode, 2)
            self.assertIn("probe contract is incompatible", stale_probe.stderr)

    def test_unified_memory_capabilities_are_required_booleans(self):
        for field in ("concurrent_managed_access", "pageable_memory_access",
                      "pageable_memory_access_uses_host_page_tables"):
            with self.subTest(field=field):
                missing = complete_report()
                del missing["devices"][0][field]
                with self.assertRaisesRegex(ValueError, field):
                    validate_probe_report(missing, 0)

                malformed = complete_report()
                malformed["devices"][0][field] = 1
                with self.assertRaisesRegex(ValueError, field):
                    validate_probe_report(malformed, 0)

    def test_managed_memory_mode_requires_a_per_device_managed_memory_pass(self):
        report = complete_report()
        report["memory_mode"] = "managed"
        for device in report["devices"]:
            device["managed_memory_passed"] = True
        self.assertEqual(validate_probe_report(
            report, 0, expected_memory_mode="managed",
            expected_device_pci_by_sm={70: "0000:01:00.0", 120: "0000:02:00.0"}),
                         "report-contract-valid")
        report["devices"][1]["managed_memory_passed"] = False
        with self.assertRaises(ValueError):
            validate_probe_report(report, 0, expected_memory_mode="managed")

    def test_managed_prefetch_requires_a_per_device_prefetch_pass(self):
        report = complete_report()
        report["memory_mode"] = "managed"
        report["managed_prefetch_requested"] = True
        report["managed_prefetch_api"] = "cuMemPrefetchAsync_v2"
        for device in report["devices"]:
            device["managed_memory_passed"] = True
            device["managed_prefetch_passed"] = True
        self.assertEqual(validate_probe_report(
            report, 0, expected_memory_mode="managed", expected_managed_prefetch=True,
            expected_device_pci_by_sm={70: "0000:01:00.0", 120: "0000:02:00.0"}),
            "report-contract-valid")
        report["devices"][1]["managed_prefetch_passed"] = False
        with self.assertRaises(ValueError):
            validate_probe_report(report, 0, expected_memory_mode="managed",
                                  expected_managed_prefetch=True)

    def test_cuda_graphs_requires_two_numeric_replays_per_targeted_device(self):
        report = complete_report()
        report["cuda_graphs_requested"] = True
        report["cuda_graph_api"] = "cuGraphInstantiateWithFlags"
        for device in report["devices"]:
            device["cuda_graphs_passed"] = True
            device["cuda_graph_launches"] = 2
        self.assertEqual(validate_probe_report(
            report, 0, expected_cuda_graphs=True,
            expected_device_pci_by_sm={70: "0000:01:00.0", 120: "0000:02:00.0"}),
                         "report-contract-valid")

        report["devices"][1]["cuda_graph_launches"] = 1
        with self.assertRaises(ValueError):
            validate_probe_report(report, 0, expected_cuda_graphs=True)

        report = complete_report()
        report["cuda_graphs_requested"] = True
        report["cuda_graph_api"] = "cuGraphInstantiateWithFlags"
        report["devices"][0]["cuda_graphs_passed"] = True
        report["devices"][0]["cuda_graph_launches"] = 2
        report["devices"][1]["cuda_graphs_passed"] = False
        report["devices"][1]["cuda_graph_launches"] = 0
        report["devices"][1]["error"] = "cuGraphLaunch failed"
        report["status"] = "failed"
        report["hybrid_validated"] = False
        report["required_set_passed"] = False
        self.assertEqual(validate_probe_report(report, 2, expected_cuda_graphs=True), "failed")

    def test_performance_graph_microbenchmark_does_not_claim_functional_graph_replay(self):
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70],
                      context_coexistence_passed=False,
                      performance_benchmark_requested=True,
                      cuda_graph_api="cuGraphInstantiateWithFlags")
        report["devices"] = [report["devices"][1]]
        device = report["devices"][0]
        device.update(ordinal=0, pci_bus_id="0000:02:00.0",
                      performance_benchmark_passed=True)
        launch = [float(value) for value in range(1, 10)]
        copies = [float(value) for value in range(1, 10)]

        def metric(values):
            ordered = sorted(values)
            return values, ordered[len(ordered) // 2], ordered[-1]

        host, host_median, host_p95 = metric(launch)
        launch_elapsed, launch_elapsed_median, launch_elapsed_p95 = metric(launch)
        transfer_rows = []
        for size, iterations in zip((4096, 65536, 1048576, 16777216, 67108864),
                                    (2048, 128, 8, 1, 1)):
            directions = {}
            for direction in ("h_to_d", "d_to_h"):
                transfer_elapsed = [size / (value * 1000.0) for value in copies]
                _, elapsed_median, elapsed_p95 = metric(transfer_elapsed)
                directions[direction] = {
                    "data_integrity_passed": True,
                    "host_api_us_per_copy_samples": copies.copy(),
                    "host_api_us_per_copy_median": 5.0,
                    "host_api_us_per_copy_p95": 9.0,
                    "device_elapsed_us_per_copy_samples": transfer_elapsed,
                    "device_elapsed_us_per_copy_median": elapsed_median,
                    "device_elapsed_us_per_copy_p95": elapsed_p95,
                    "gb_per_second_samples": copies.copy(),
                    "gb_per_second_median": 5.0,
                    "gb_per_second_p95": 9.0,
                }
            transfer_rows.append({"bytes": size, "samples": 9,
                                  "iterations_per_sample": iterations,
                                  "data_integrity_passed": True, **directions})
        device["performance_benchmark"] = {
            "schema": "nvidia-cuda-performance-benchmark-v2",
            "status": "completed",
            "timing_sources": {
                "host": "std::chrono::steady_clock",
                "device": "CUDA events (cuEventElapsedTime)"},
            "samples": 9, "warmup_launches": 64, "launches_per_sample": 256,
            "kernel_launch": {
                "kernel": "hybrid_empty", "samples": 9,
                "host_api_us_samples": host,
                "host_api_us_median": host_median, "host_api_us_p95": host_p95,
                "device_elapsed_us_samples": launch_elapsed,
                "device_elapsed_us_median": launch_elapsed_median,
                "device_elapsed_us_p95": launch_elapsed_p95},
            "cuda_graph_launch": {
                "host_api_us": {"values": launch, "median": 5.0,
                                 "p95": 9.0, "samples": 9},
                "device_elapsed_us": {"values": launch, "median": 5.0,
                                       "p95": 9.0, "samples": 9}},
            "transfers": transfer_rows,
        }

        self.assertEqual(validate_probe_report(
            report, 77, expected_performance_benchmark=True),
            "incomplete-hardware-missing")
        with self.assertRaisesRegex(ValueError, "sample count"):
            validate_probe_report(report, 77, expected_performance_benchmark=True,
                                  expected_benchmark_samples=21)
        for invalid_api in ("not-requested", "unavailable"):
            candidate = copy.deepcopy(report)
            candidate["cuda_graph_api"] = invalid_api
            with self.subTest(invalid_api=invalid_api), self.assertRaises(ValueError):
                validate_probe_report(candidate, 77,
                                      expected_performance_benchmark=True)
        bad_bandwidth = copy.deepcopy(report)
        bad_metric = bad_bandwidth["devices"][0]["performance_benchmark"][
            "transfers"][0]["h_to_d"]
        bad_metric["gb_per_second_samples"][0] *= 2048
        bad_metric["gb_per_second_median"] = 6.0
        bad_metric["gb_per_second_p95"] = 2048.0
        with self.assertRaisesRegex(ValueError, "does not match per-copy device time"):
            validate_probe_report(bad_bandwidth, 77,
                                  expected_performance_benchmark=True)

    def test_each_material_contradiction_is_rejected(self):
        variants = []
        for mutate in (
            lambda r: r.update(schema="nvidia-hybrid-probe-v1"),
            lambda r: r.update(context_coexistence_passed=False),
            lambda r: r["devices"][1].update(pci_bus_id="0000:01:00.0"),
            lambda r: r["devices"][1].update(synchronous_sizes=[1, 31]),
            lambda r: r["devices"][1].update(asynchronous_passed=False),
            lambda r: r["devices"][1].update(cleanup_passed=False, cleanup_errors=["free failed"]),
            lambda r: r["devices"][1].update(error="silent failure"),
            lambda r: r["devices"][1].update(sm=70),
            lambda r: r.update(devices=[]),
            lambda r: r.update(required_sm=[120]),
            lambda r: r.update(missing_sm=[70]),
        ):
            report = copy.deepcopy(complete_report())
            mutate(report)
            variants.append(report)
        for report in variants:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_probe_report(report, 0)

    def test_hybrid_success_is_pinned_to_exact_pci_devices(self):
        expected = {70: "0000:01:00.0", 120: "0000:02:00.0"}
        report = complete_report()
        self.assertEqual(validate_probe_report(
            report, 0, expected_device_pci_by_sm=expected), "report-contract-valid")

        wrong_cli_target = {70: "0000:03:00.0", 120: "0000:02:00.0"}
        with self.assertRaisesRegex(ValueError, "expected device mapping"):
            validate_probe_report(report, 0,
                                  expected_device_pci_by_sm=wrong_cli_target)

        wrong_report_target = copy.deepcopy(report)
        wrong_report_target["devices"][0]["pci_bus_id"] = "0000:03:00.0"
        with self.assertRaisesRegex(ValueError, "targeting contradicts the expected PCI device map"):
            validate_probe_report(wrong_report_target, 0,
                                  expected_device_pci_by_sm=expected)

    def test_duplicate_architecture_devices_are_not_all_selected(self):
        report = complete_report()
        extra = copy.deepcopy(report["devices"][0])
        extra.update(ordinal=2, pci_bus_id="0000:03:00.0", targeted=False,
                     tested=False, architecture_kernel_passed=False,
                     synchronous_passed=False, asynchronous_passed=False,
                     synchronous_sizes=[], asynchronous_sizes=[])
        report["devices"].append(extra)
        self.assertEqual(validate_probe_report(
            report, 0,
            expected_device_pci_by_sm={70: "0000:01:00.0", 120: "0000:02:00.0"}),
            "report-contract-valid")
        report["devices"][2]["targeted"] = True
        with self.assertRaises(ValueError):
            validate_probe_report(
                report, 0,
                expected_device_pci_by_sm={70: "0000:01:00.0", 120: "0000:02:00.0"})

    def test_missing_hardware_must_match_the_inventory(self):
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70],
                      context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        self.assertEqual(validate_probe_report(report, 77), "incomplete-hardware-missing")
        report["context_coexistence_passed"] = True
        with self.assertRaises(ValueError):
            validate_probe_report(report, 77)
        report["context_coexistence_passed"] = False
        report["missing_sm"] = [120]
        with self.assertRaises(ValueError):
            validate_probe_report(report, 77)

    def test_cli_archives_rejected_claim_with_binary_hashes(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "claim"
            probe.write_text('#!/bin/sh\nprintf \'{"hybrid_validated":true,"required_set_passed":true,"missing_sm":[]}\\n\'\n')
            probe.chmod(0o700)
            module = root / "fixture.fatbin"
            module.write_bytes(b"fixture-not-a-cubin")
            result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                                     "--module", str(module), "--evidence-dir", str(root / "evidence")],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            evidence = json.loads(next((root / "evidence").glob("*.json")).read_text())
            self.assertEqual(evidence["qualification"], "invalid-probe-report")
            self.assertEqual(len(evidence["artifacts"]["probe"]["sha256"]), 64)
            self.assertEqual(len(evidence["artifacts"]["module"]["sha256"]), 64)

    def test_cli_missing_hardware_is_nonzero_unless_explicitly_allowed(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        report = complete_report()
        report.update(status="incomplete", hybrid_validated=False,
                      required_set_passed=False, missing_sm=[70],
                      context_coexistence_passed=False)
        report["devices"] = report["devices"][1:]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "fixture-probe"
            # This is a report-contract fixture, never archived as GPU evidence.
            probe.write_text("#!" + sys.executable + "\nimport json\nprint(" +
                             repr(json.dumps(report)) + ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module = root / "fixture.fatbin"
            module.write_bytes(b"fixture-not-a-cubin")
            for flags, expected in (([], 77), (["--strict"], 77),
                                    (["--allow-incomplete"], 0)):
                with self.subTest(flags=flags):
                    destination = root / ("evidence-" + str(expected) + "-" + str(len(flags)))
                    result = subprocess.run(
                        [sys.executable, str(runner), "--probe", str(probe),
                         "--module", str(module), "--evidence-dir", str(destination), *flags],
                        capture_output=True, text=True, check=False, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    evidence = json.loads(next(destination.glob("*.json")).read_text())
                    self.assertEqual(evidence["qualification"], "incomplete-hardware-missing")
                    self.assertEqual(evidence["exit_code"], 77)
                    self.assertFalse(evidence["probe"]["hybrid_validated"])

    def test_map_memory_observer_requires_pinned_status_and_a_gpu_mapping_pair(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        missing = subprocess.run([sys.executable, str(runner), "--map-memory"],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(missing.returncode, 2)
        self.assertIn("--map-memory requires --ioctl-observer", missing.stderr)

        probe_report = complete_report()
        probe_report.update(status="incomplete", hybrid_validated=False,
                            required_set_passed=False, missing_sm=[70],
                            context_coexistence_passed=False)
        probe_report["devices"] = probe_report["devices"][1:]
        map_payload = {"length": 4096, "status": 0, "flags": 1,
                       "hClientPresent": True, "hDevicePresent": True,
                       "hMemoryPresent": True, "offsetNonzero": False,
                       "linearAddressPresent": True, "backendFd": 19,
                       "backendFdRole": "gpu", "backendFileId": 2,
                       "memoryObjectClass": {"resolution": "resolved", "classId": 0xc661}}
        unmap_payload = {"status": 0, "flags": 1, "hClientPresent": True,
                         "hDevicePresent": True, "hMemoryPresent": True,
                         "linearAddressPresent": True}
        scope = ("exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device "
                 "open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; "
                 "no allocation payloads emitted; addresses, paths, and handles omitted")
        fd_lifecycle_scope = ("opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/"
                              "fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; "
                              "exec invalidates inherited IDs; io_uring and external fd injection are not tracked; "
                              "VMA file references remain kernel-owned")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nimport json\nprint(" +
                             repr(json.dumps(probe_report)) + ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            for index, (status, include_mmap, close_between) in enumerate(
                    ((0, True, False), (0, False, False), (5, True, False), (0, True, True))):
                records = [
                    {"operation": "fd_open", "request": 257, "packet_size": 0,
                     "tid": 77, "fd": 8, "fd_role": "control", "fd_file_id": 1,
                     "entry": None, "exit": None, "syscall_return": 8},
                    {"operation": "fd_open", "request": 257, "packet_size": 0,
                     "tid": 77, "fd": 19, "fd_role": "gpu", "fd_file_id": 2,
                     "entry": None, "exit": None, "syscall_return": 19},
                    {"operation": "map_memory", "request": 0xc038464e,
                     "packet_size": 56, "fd": 8, "fd_file_id": 1,
                     "fd_role": "control", "syscall_return": 0,
                     "entry": dict(map_payload, linearAddressPresent=False),
                     "exit": dict(map_payload, status=status)},
                ]
                if close_between:
                    records.append({"operation": "close", "request": 3, "packet_size": 0,
                        "fd": 19, "fd_file_id": 2, "fd_role": "gpu", "entry": None, "exit": None,
                        "syscall_return": 0, "close_succeeded": True})
                if include_mmap:
                    records.append({"operation": "mmap", "request": 9,
                        "packet_size": 0, "fd": 19, "fd_file_id": 2, "fd_role": "gpu",
                        "syscall_return": None,
                        "entry": {"length": 4096, "prot": 1, "flags": 1,
                                  "offsetZero": True},
                        "exit": None, "mmap_succeeded": True})
                records.append({"operation": "unmap_memory", "request": 0xc020464f,
                    "packet_size": 32, "fd": 8, "fd_file_id": 1,
                    "fd_role": "control", "syscall_return": 0,
                    "entry": unmap_payload, "exit": unmap_payload})
                if not close_between:
                    records.append({"operation": "close", "request": 3, "packet_size": 0,
                        "fd": 19, "fd_file_id": 2, "fd_role": "gpu", "entry": None, "exit": None,
                        "syscall_return": 0, "close_succeeded": True})
                observed = {"schema": "nvidia-hybrid-rm-ioctl-observer-v15",
                            "trace_complete": True, "nested_pointers_read": False,
                            "payload_scope": scope, "fd_lifecycle_scope": fd_lifecycle_scope,
                            "object_class_resolution_scope": ("successful prior RM_ALLOC and RM_FREE packets observed on "
                                "the explicitly selected control and GPU paths; keyed by root and handle; unresolved "
                                "means no unique live object was observed"),
                            "fd_identity_capture_complete": True,
                            "gpu_path": "/dev/nvidia0",
                            "errors": [], "child_exit_code": 77,
                            "control_path": "/dev/nvidiactl", "records": records}
                observer.write_text("#!" + sys.executable + "\nimport json,subprocess,sys\n"
                    "from pathlib import Path\n"
                    "Path(sys.argv[sys.argv.index('--output')+1]).write_text(" +
                    repr(json.dumps(observed)) + ")\n"
                    "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
                observer.chmod(0o700)
                evidence_dir = root / ("evidence-" + str(index))
                result = subprocess.run([sys.executable, str(runner), "--probe", str(probe),
                    "--module", str(module), "--ioctl-observer", str(observer),
                    "--map-memory", "--expected-pci", "0000:02:00.0",
                    "--evidence-dir", str(evidence_dir)], capture_output=True,
                    text=True, timeout=10)
                qualifies = status == 0 and include_mmap and not close_between
                self.assertEqual(result.returncode, 77 if qualifies else 2,
                                 result.stdout + result.stderr)
                evidence = json.loads(next(evidence_dir.glob("hardware-probe-*.json")).read_text())
                self.assertEqual(evidence["map_memory_capture_requested"], True)
                self.assertEqual(evidence["map_memory_success_count"], 1 if status == 0 else 0)
                self.assertEqual(evidence["map_memory_mmap_success_count"], 1 if qualifies else 0)
                self.assertEqual(evidence["map_memory_gpu_fd_close_count"], 1)
                self.assertEqual(evidence["validation_errors"] == [], qualifies)

    def test_map_memory_and_rusd_observer_modes_can_be_combined(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(runner), "--probe", str(Path(directory) / "missing-probe"),
                 "--module", str(Path(directory) / "missing-module"),
                 "--evidence-dir", directory, "--ioctl-observer", "/dev/null",
                 "--expected-pci", "0000:02:00.0", "--map-memory", "--rusd-alloc"],
                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("build the probe first", result.stderr)
        self.assertNotIn("--map-memory must run separately", result.stderr)
        self.assertNotIn("--rusd-alloc is an isolated", result.stderr)

    def test_combined_rusd_map_observation_validates_lifecycle_and_resolved_class(self):
        runner = Path(__file__).with_name("run_hybrid_acceptance_fixture_cli.py")
        probe_report = complete_report()
        probe_report.update(status="incomplete", hybrid_validated=False,
                            required_set_passed=False, missing_sm=[70],
                            context_coexistence_passed=False)
        probe_report["devices"] = probe_report["devices"][1:]
        class_ref = {"resolution": "resolved", "classId": 0xde}
        map_common = {"length": 4096, "status": 0, "flags": 1,
                      "hClientPresent": True, "hDevicePresent": True,
                      "hMemoryPresent": True, "offsetNonzero": False,
                      "backendFd": 19, "backendFdRole": "gpu", "backendFileId": 2,
                      "memoryObjectClass": class_ref}
        map_entry = dict(map_common, linearAddressPresent=False)
        map_exit = dict(map_common, linearAddressPresent=True)
        unmap = {"status": 0, "flags": 1, "hClientPresent": True,
                 "hDevicePresent": True, "hMemoryPresent": True,
                 "linearAddressPresent": True}
        rusd_packet = {"layout": "NVOS64", "hClass": 0xde, "paramsSize": 0,
                       "flags": 0, "status": 0, "hRootPresent": True,
                       "hObjectParentPresent": True, "hObjectNewPresent": True,
                       "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                       "rusdPayloadState": "r580-r595-class-layout-parsed",
                       "rusd": {"classPayloadBytes": 8, "polledDataMask": 0}}
        fd_fields = {"tid": 77, "fd": 8, "fd_file_id": 1,
                     "fd_role": "control", "request": 257, "packet_size": 0,
                     "entry": None, "exit": None, "syscall_return": 8}
        gpu_open = dict(fd_fields, fd=19, fd_file_id=2, fd_role="gpu", syscall_return=19)
        records = [
            dict(fd_fields, operation="fd_open"),
            dict(gpu_open, operation="fd_open"),
            {"tid": 77, "fd": 19, "fd_file_id": 2, "fd_role": "gpu",
             "request": 0xc030462b, "packet_size": 48, "operation": "rusd_alloc",
             "entry": rusd_packet, "exit": rusd_packet, "syscall_return": 0},
            {"tid": 77, "fd": 8, "fd_file_id": 1, "fd_role": "control",
             "request": 0xc038464e, "packet_size": 56, "operation": "map_memory",
             "entry": map_entry, "exit": map_exit, "syscall_return": 0},
            {"tid": 77, "fd": 19, "fd_file_id": 2, "fd_role": "gpu",
             "request": 9, "packet_size": 0, "operation": "mmap",
             "entry": {"length": 4096, "prot": 1, "flags": 1, "offsetZero": True},
             "exit": None, "syscall_return": None, "mmap_succeeded": True},
            {"tid": 77, "fd": 8, "fd_file_id": 1, "fd_role": "control",
             "request": 0xc020464f, "packet_size": 32, "operation": "unmap_memory",
             "entry": unmap, "exit": unmap, "syscall_return": 0},
            {"tid": 77, "fd": 8, "fd_file_id": 1, "fd_role": "control",
             "request": 3, "packet_size": 0, "operation": "close",
             "entry": None, "exit": None, "syscall_return": 0, "close_succeeded": True},
            {"tid": 77, "fd": 19, "fd_file_id": 2, "fd_role": "gpu",
             "request": 3, "packet_size": 0, "operation": "close",
             "entry": None, "exit": None, "syscall_return": 0, "close_succeeded": True},
        ]
        fd_lifecycle_scope = (
            "opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/"
            "fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; "
            "exec invalidates inherited IDs; io_uring and external fd injection are not tracked; "
            "VMA file references remain kernel-owned")
        observed = {
            "schema": "nvidia-hybrid-rm-ioctl-observer-v22", "trace_complete": True,
            "nested_pointers_read": True,
            "nested_pointer_scope": (
                "RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS fixed 8-byte polledDataMask only, "
                "plus exact pinned R580 NVOS33/NVOS34 map packets and selected-file lifecycle "
                "metadata; other allocation payloads and raw addresses/handles omitted"),
            "rusd_payload_snapshots_read": 2,
            "payload_scope": (
                "exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device "
                "open/dup/close/mmap metadata, transient RM_ALLOC/RM_FREE class resolution, and "
                "fixed RM_USER_SHARED_DATA 8-byte polling-mask snapshots only; addresses, paths, "
                "and handles omitted"),
            "object_class_resolution_scope": (
                "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected "
                "control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed"),
            "fd_lifecycle_scope": fd_lifecycle_scope, "fd_identity_capture_complete": True,
            "gpu_path": "/dev/nvidia0", "errors": [], "child_exit_code": 77,
            "control_path": "/dev/nvidiactl", "records": records,
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, module, observer = root / "probe", root / "module", root / "observer"
            probe.write_text("#!" + sys.executable + "\nimport json\nprint(" +
                             repr(json.dumps(probe_report)) + ")\nraise SystemExit(77)\n")
            probe.chmod(0o700)
            module.write_bytes(b"CPU fixture")
            observer.write_text("#!" + sys.executable + "\nimport json,subprocess,sys\n"
                "from pathlib import Path\n"
                "Path(sys.argv[sys.argv.index('--output')+1]).write_text(" +
                repr(json.dumps(observed)) + ")\n"
                "raise SystemExit(subprocess.run(sys.argv[sys.argv.index('--')+1:]).returncode)\n")
            observer.chmod(0o700)
            evidence_dir = root / "evidence"
            result = subprocess.run(
                [sys.executable, str(runner), "--probe", str(probe), "--module", str(module),
                 "--ioctl-observer", str(observer), "--expected-pci", "0000:02:00.0",
                 "--map-memory", "--rusd-alloc", "--evidence-dir", str(evidence_dir)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            evidence = json.loads(next(evidence_dir.glob("hardware-probe-*.json")).read_text())
            self.assertEqual(evidence["map_memory_class_ids"], [0xde])
            self.assertEqual(evidence["map_memory_success_count"], 1)
            self.assertEqual(evidence["map_memory_mmap_success_count"], 1)
            self.assertTrue(evidence["rusd_alloc_records_seen"])
            self.assertEqual(evidence["rusd_polled_data_masks"], [0])
            self.assertEqual(evidence["validation_errors"], [])


class ReadmeAcceptancePinTests(unittest.TestCase):
    def test_acceptance_example_uses_the_runner_pinned_probe_and_fatbin(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text()
        start = readme.index("### Opt-in peer-transfer diagnostic")
        end = readme.index("### Opt-in CUDA VMM peer-memory diagnostic", start)
        section = readme[start:end]

        self.assertIn(f"--probe {DEFAULT_PROBE.relative_to(root)}", section)
        self.assertIn(f"--module {DEFAULT_MODULE.relative_to(root)}", section)
        self.assertNotIn("probe-libcuda-override-v12-20261101", section)


if __name__ == "__main__":
    unittest.main()
