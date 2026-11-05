#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run and archive the same-process SM70 + SM120 Driver API acceptance probe."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from tools.cuda_probe_contract import (
        validate_graph_api_claim, validate_peer_transfer_report,
        validate_performance_benchmark_report,
        validate_probe_contract)
except ModuleNotFoundError as error:
    if error.name != "tools":
        raise
    from cuda_probe_contract import (
        validate_graph_api_claim, validate_peer_transfer_report,
        validate_performance_benchmark_report,
        validate_probe_contract)


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SM = [70, 120]
REQUIRED_SIZES = [1, 31, 256, 4096, 65537]
DEFAULT_PROBE = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe"
DEFAULT_MODULE = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin"
PINNED_PROBE_SHA256 = "c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422"
PINNED_MODULE_SHA256 = "8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70"
RELEASE_PINNED_PROBE_SHA256 = PINNED_PROBE_SHA256
RELEASE_PINNED_MODULE_SHA256 = PINNED_MODULE_SHA256
SUCCESSFUL_REPORT_QUALIFICATIONS = {
    "report-contract-valid",
    "phase-report-contract-pass",
    "system-pageable-memory-report-contract-pass",
    "system-pageable-memory-unsupported-report-contract-valid",
}


def canonical_pci(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value):
        raise ValueError("invalid expected PCI ID")
    domain, bus, slot_function = value.lower().split(":")
    if int(slot_function[:2], 16) > 31:
        raise ValueError("invalid expected PCI slot")
    return domain.zfill(8) + ":" + bus + ":" + slot_function


def validate_probe_report(report: object, exit_code: int,
                          expected_memory_mode: str = "device",
                          expected_managed_prefetch: bool = False,
                          expected_cuda_graphs: bool = False,
                          expected_performance_benchmark: bool = False,
                          expected_device_pci_by_sm: dict[int, str] | None = None,
                          expected_concurrent_dispatch: bool = False,
                          expected_peer_transfer: bool = False,
                          expected_benchmark_samples: int | None = None,
                          expected_benchmark_transfer_samples: int | None = None) -> str:
    """Check per-device evidence and contradictions before assigning a qualification.

    This is a report contract, not hardware attestation. The invoked probe and
    driver remain trusted measurement instruments; their identities are archived.
    """
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict), "probe report must be an object")
    require(report.get("schema") == "nvidia-hybrid-probe-v2", "unsupported probe schema")
    require(expected_memory_mode in ("device", "managed"), "unsupported expected memory mode")
    require(type(expected_managed_prefetch) is bool, "unsupported expected managed-prefetch mode")
    require(type(expected_cuda_graphs) is bool, "unsupported expected CUDA Graph mode")
    require(type(expected_performance_benchmark) is bool,
            "unsupported expected performance benchmark mode")
    require(type(expected_concurrent_dispatch) is bool,
            "unsupported expected concurrent dispatch mode")
    require(type(expected_peer_transfer) is bool,
            "unsupported expected peer-transfer mode")
    require(expected_benchmark_samples is None or
            (type(expected_benchmark_samples) is int and
             9 <= expected_benchmark_samples <= 1001),
            "expected benchmark samples must be 9 through 1001")
    require(expected_benchmark_transfer_samples is None or
            (type(expected_benchmark_transfer_samples) is int and
             7 <= expected_benchmark_transfer_samples <= 1001),
            "expected transfer samples must be 7 through 1001")
    require(expected_performance_benchmark or
            (expected_benchmark_samples is None and
             expected_benchmark_transfer_samples is None),
            "expected benchmark samples require a benchmark")
    require(report.get("memory_mode") == expected_memory_mode, "memory mode differs from the command")
    require(report.get("managed_prefetch_requested") is expected_managed_prefetch,
            "managed-prefetch mode differs from the command")
    prefetch_api = report.get("managed_prefetch_api")
    require(isinstance(prefetch_api, str), "missing managed-prefetch API identity")
    if expected_managed_prefetch:
        require(prefetch_api in ("cuMemPrefetchAsync_v2", "cuMemPrefetchAsync", "unavailable"),
                "unknown managed-prefetch API identity")
    else:
        require(prefetch_api == "not-requested", "unrequested managed-prefetch API claim")
    require(report.get("cuda_graphs_requested") is expected_cuda_graphs,
            "CUDA Graph mode differs from the command")
    validate_performance_benchmark_report(
        report, expected_performance_benchmark,
        expected_samples=expected_benchmark_samples,
        expected_transfer_samples=expected_benchmark_transfer_samples)
    if expected_peer_transfer or "peer_transfer_requested" in report or "peer_transfer" in report:
        validate_peer_transfer_report(report, expected_peer_transfer,
                                      expected_device_pci_by_sm)
    graph_api = report.get("cuda_graph_api")
    validate_graph_api_claim(graph_api, expected_cuda_graphs,
                             expected_performance_benchmark)
    require(report.get("required_sm") == REQUIRED_SM, "required architecture set differs from the command")
    reported_device_map = report.get("expected_device_pci_by_sm")
    require(isinstance(reported_device_map, dict), "missing expected device PCI map")
    require(set(reported_device_map) in (set(), {str(sm) for sm in REQUIRED_SM}),
            "expected device PCI map must be empty or pin every required architecture")
    normalized_device_map = {}
    for sm in REQUIRED_SM:
        if str(sm) not in reported_device_map:
            continue
        pci = reported_device_map[str(sm)]
        require(isinstance(pci, str), "expected device PCI map contains a non-string ID")
        try:
            normalized_device_map[sm] = canonical_pci(pci)
        except ValueError as error:
            raise ValueError("expected device PCI map contains an invalid PCI ID") from error
    require(len(set(normalized_device_map.values())) == len(normalized_device_map),
            "expected device PCI map reuses a PCI ID")
    if expected_device_pci_by_sm is not None:
        cli_device_map = {}
        require(isinstance(expected_device_pci_by_sm, dict),
                "expected device mapping must be a mapping")
        for sm, pci in expected_device_pci_by_sm.items():
            require(type(sm) is int and sm in REQUIRED_SM and isinstance(pci, str),
                    "expected device mapping contains an invalid architecture or PCI ID")
            try:
                cli_device_map[sm] = canonical_pci(pci)
            except ValueError as error:
                raise ValueError("expected device mapping contains an invalid PCI ID") from error
        require(cli_device_map == normalized_device_map,
                "report expected device mapping differs from the expected device mapping")
    require(type(report.get("driver_api")) is int and report["driver_api"] > 0, "invalid Driver API version")
    require(isinstance(report.get("driver_library_path"), str) and
            Path(report["driver_library_path"]).is_absolute(), "missing resolved driver library path")
    require(report.get("execution_mode") == "resident-contexts-sequential-kernels", "unexpected execution scope")
    require(report.get("concurrent_kernel_execution_validated") is False, "concurrency is outside this probe's scope")
    concurrent_fields = ("concurrent_kernel_test_requested",
                         "concurrent_kernel_dispatch_passed",
                         "concurrent_kernel_dispatch")
    has_concurrent_fields = any(key in report for key in concurrent_fields)
    dispatch_passed = report.get("concurrent_kernel_dispatch_passed", False)
    dispatch = report.get("concurrent_kernel_dispatch")
    if not expected_concurrent_dispatch:
        if has_concurrent_fields:
            require(report.get("concurrent_kernel_test_requested") is False and
                    type(dispatch_passed) is bool and not dispatch_passed and dispatch is None,
                    "unrequested concurrent dispatch claim")
    else:
        require(report.get("concurrent_kernel_test_requested") is True and
                type(dispatch_passed) is bool,
                "concurrent-dispatch mode differs from the command")
    if expected_concurrent_dispatch and dispatch_passed:
        require(isinstance(dispatch, dict), "passing concurrent dispatch requires evidence")
        require(set(dispatch) == {"schema", "qualification", "requested", "passed",
                                  "gpu_timeline_overlap_validated", "rounds", "devices"},
                "concurrent dispatch report has unexpected or missing fields")
        require(dispatch.get("schema") == "nvidia-hybrid-concurrent-dispatch-v1",
                "unsupported concurrent dispatch schema")
        require(dispatch.get("qualification") ==
                "host-dispatch-window-overlap-profiler-timeline-required",
                "concurrent dispatch qualification overstates its evidence")
        require(dispatch.get("requested") is True and dispatch.get("passed") is True and
                dispatch.get("gpu_timeline_overlap_validated") is False,
                "concurrent dispatch status contradicts its evidence scope")
        rounds = dispatch.get("rounds")
        require(type(rounds) is int and 0 < rounds <= 10_000_000,
                "invalid concurrent dispatch work bound")
        rows = dispatch.get("devices")
        require(isinstance(rows, list) and len(rows) == len(REQUIRED_SM),
                "concurrent dispatch requires exactly two device rows")
        by_sm = {}
        for row in rows:
            require(isinstance(row, dict) and set(row) == {
                "sm", "pci_bus_id", "kernel_name", "rounds", "numeric_result_passed",
                "host_window_start_ns", "host_window_end_ns"},
                "concurrent dispatch device row has unexpected or missing fields")
            sm = row.get("sm")
            require(type(sm) is int and sm in REQUIRED_SM and sm not in by_sm,
                    "concurrent dispatch has a duplicate or unsupported SM")
            pci = row.get("pci_bus_id")
            require(isinstance(pci, str), "concurrent dispatch PCI ID must be a string")
            try:
                canonical = canonical_pci(pci)
            except ValueError as error:
                raise ValueError("concurrent dispatch has an invalid PCI ID") from error
            expected_pci = normalized_device_map.get(sm)
            require(expected_pci is not None and canonical == expected_pci,
                    "concurrent dispatch device differs from the pinned PCI ID")
            require(row.get("kernel_name") == "hybrid_concurrent_work" and
                    row.get("rounds") == rounds and type(row.get("rounds")) is int,
                    "concurrent dispatch kernel/workload differs between devices")
            require(row.get("numeric_result_passed") is True,
                    "concurrent dispatch has no passing numeric result")
            start, end = row.get("host_window_start_ns"), row.get("host_window_end_ns")
            require(type(start) is int and type(end) is int and 0 <= start < end,
                    "concurrent dispatch has an invalid host timing window")
            by_sm[sm] = (start, end)
        require(set(by_sm) == set(REQUIRED_SM),
                "concurrent dispatch does not include both required architectures")
        require(max(by_sm[70][0], by_sm[120][0]) < min(by_sm[70][1], by_sm[120][1]),
                "concurrent dispatch host windows do not overlap")
    elif expected_concurrent_dispatch:
        require(dispatch is None, "failed concurrent dispatch must not contain partial success evidence")
    for key in ("hybrid_validated", "required_set_passed", "context_coexistence_passed"):
        require(type(report.get(key)) is bool, f"{key} must be boolean")
    devices = report.get("devices")
    require(isinstance(devices, list), "devices must be a list")
    ordinals, pci_ids, present = set(), set(), set()
    successful, failed = set(), False
    for device in devices:
        require(isinstance(device, dict), "device result must be an object")
        sm, ordinal, pci = device.get("sm"), device.get("ordinal"), device.get("pci_bus_id")
        require(type(sm) is int and sm > 0, "invalid SM value")
        require(type(ordinal) is int and ordinal >= 0 and ordinal not in ordinals, "duplicate/invalid device ordinal")
        require(isinstance(pci, str) and re.fullmatch(r"[0-9a-fA-F]{4,8}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", pci)
                and pci.lower() not in pci_ids, "duplicate/invalid PCI identity")
        ordinals.add(ordinal)
        pci_ids.add(pci.lower())
        expected_pci = normalized_device_map.get(sm)
        exact_mapping = len(normalized_device_map) == len(REQUIRED_SM)
        expected_target = ((expected_pci is not None and canonical_pci(pci) == expected_pci)
                           if exact_mapping else sm in REQUIRED_SM)
        if pci.lower() in {value.lower() for value in normalized_device_map.values()}:
            require(expected_target,
                    "device at a pinned PCI ID reports a different compute capability")
        if expected_target:
            present.add(sm)
        require(device.get("compute_capability") == f"{sm//10}.{sm%10}", "SM/compute capability mismatch")
        require(isinstance(device.get("name"), str) and bool(device["name"]), "missing GPU name")
        for key in ("targeted", "tested", "architecture_kernel_passed", "synchronous_passed",
                    "asynchronous_passed", "managed_memory_passed", "managed_prefetch_passed",
                    "cuda_graphs_passed", "cleanup_passed", "concurrent_managed_access",
                    "pageable_memory_access",
                    "pageable_memory_access_uses_host_page_tables"):
            require(type(device.get(key)) is bool, f"device {key} must be boolean")
        graph_launches = device.get("cuda_graph_launches")
        require(type(graph_launches) is int and 0 <= graph_launches <= 2,
                "invalid CUDA Graph launch count")
        if not expected_cuda_graphs or not device["targeted"]:
            require(not device["cuda_graphs_passed"] and graph_launches == 0,
                    "unrequested/untargeted CUDA Graph claim")
        if device["cuda_graphs_passed"]:
            require(expected_cuda_graphs and graph_launches == 2,
                    "CUDA Graph success requires two requested launches")
        if expected_cuda_graphs and graph_api == "unavailable":
            require(not device["cuda_graphs_passed"],
                    "unavailable CUDA Graph API cannot pass")
        if expected_memory_mode == "device" or not device["targeted"]:
            require(not device["managed_memory_passed"], "unrequested/untargeted managed-memory claim")
        if not expected_managed_prefetch or not device["targeted"]:
            require(not device["managed_prefetch_passed"], "unrequested/untargeted managed-prefetch claim")
        require(device["targeted"] is expected_target,
                "targeting contradicts the expected PCI device map")
        require(isinstance(device.get("error"), str), "device error must be a string")
        require(isinstance(device.get("cleanup_errors"), list) and
                all(isinstance(e, str) and e for e in device["cleanup_errors"]), "invalid cleanup errors")
        require(device["cleanup_passed"] == (not device["cleanup_errors"]), "cleanup status contradicts errors")
        for phase in ("synchronous", "asynchronous"):
            sizes = device.get(phase + "_sizes")
            require(isinstance(sizes, list) and all(type(n) is int for n in sizes) and
                    sizes == REQUIRED_SIZES[:len(sizes)], f"invalid {phase} sizes")
            if device[phase + "_passed"]:
                require(sizes == REQUIRED_SIZES, f"{phase} claims success without all sizes")
        passed = (device["tested"] and device["architecture_kernel_passed"] and
                  device["synchronous_passed"] and device["asynchronous_passed"] and
                  (expected_memory_mode == "device" or device["managed_memory_passed"]) and
                  (not expected_managed_prefetch or device["managed_prefetch_passed"]) and
                  (not expected_cuda_graphs or device["cuda_graphs_passed"]) and
                  (not expected_performance_benchmark or
                   device["performance_benchmark_passed"]) and
                  device["cleanup_passed"] and not device["error"])
        if device["targeted"]:
            if passed:
                successful.add(sm)
            else:
                failed = True
        else:
            require(not device["tested"] and not device["architecture_kernel_passed"] and
                    not device["synchronous_passed"] and not device["asynchronous_passed"] and
                    not device["managed_memory_passed"] and
                    not device["managed_prefetch_passed"] and
                    not device["cuda_graphs_passed"] and graph_launches == 0 and
                    not device["synchronous_sizes"] and not device["asynchronous_sizes"] and
                    device["cleanup_passed"] and not device["error"], "untargeted device claims execution")
    missing = sorted(set(REQUIRED_SM) - present)
    require(report.get("missing_sm") == missing, "missing architectures contradict inventory")
    require(not missing or not report["context_coexistence_passed"],
            "mixed-generation context coexistence requires both architectures")
    status = report.get("status")
    if status == "hybrid-validated":
        require(len(normalized_device_map) == len(REQUIRED_SM) and
                expected_device_pci_by_sm is not None,
                "hybrid success requires caller-pinned PCI IDs for every required architecture")
        require(exit_code == 0 and not failed and not missing and successful == set(REQUIRED_SM)
                and report["hybrid_validated"] and report["required_set_passed"] and
                report["context_coexistence_passed"], "invalid hybrid success claim")
        require(not expected_concurrent_dispatch or dispatch_passed,
                "hybrid success omitted the requested concurrent dispatch")
        return "report-contract-valid"
    require(not report["hybrid_validated"] and not report["required_set_passed"], "failure/incomplete report claims success")
    if status == "incomplete":
        require(exit_code == 77 and bool(missing) and not failed, "invalid missing-hardware result")
        return "incomplete-hardware-missing"
    concurrent_failed = (expected_concurrent_dispatch and not dispatch_passed and not missing)
    peer = report.get("peer_transfer")
    peer_failed = (expected_peer_transfer and isinstance(peer, dict) and
                   (peer.get("status") in ("query-failed", "peer-kernel-failed",
                                           "cleanup-failed", "copy-failed") or
                    peer.get("host_staged_fallback_status") in
                    ("copy-failed", "cleanup-failed")))
    require(status == "failed" and exit_code == 2 and
            (failed or concurrent_failed or peer_failed),
            "invalid failure status or exit code")
    return "failed"


def validate_phase_probe_report(report: object, exit_code: int, expected_pci: str,
                                expected_phase: str) -> str:
    """Validate one selected-device Driver API phase without hybrid qualification."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(expected_phase in ("initialize", "enumerate", "context", "allocation", "module", "kernel",
                               "managed-accessed-by"),
            "unsupported expected phase")
    expected_operations = ["cuInit"]
    if expected_phase != "initialize":
        expected_operations = ["cuInit", "cuDriverGetVersion", "cuDeviceGetCount",
                               "cuDeviceGet", "cuDeviceGetName", "cuDeviceGetPCIBusId",
                               "cuDeviceGetAttribute.major", "cuDeviceGetAttribute.minor",
                               "cuDeviceGetAttribute.concurrent_managed_access",
                               "cuDeviceGetAttribute.pageable_memory_access",
                               "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables"]
        if expected_phase != "enumerate":
            expected_operations += ["cuCtxCreate_v2", "cuCtxSetCurrent", "cuCtxGetDevice"]
            if expected_phase == "allocation":
                expected_operations += ["cuMemAlloc_v2"]
            elif expected_phase == "managed-accessed-by":
                expected_operations += ["cuMemAllocManaged",
                                        "cuMemAdvise(SET_ACCESSED_BY)",
                                        "cuMemAdvise(UNSET_ACCESSED_BY)"]
            elif expected_phase in ("module", "kernel"):
                expected_operations += ["cuModuleLoad", "cuModuleGetFunction(hybrid_arch)"]
                if expected_phase == "kernel":
                    expected_operations += ["cuMemAlloc_v2", "cuLaunchKernel(hybrid_arch)",
                                            "cuCtxSynchronize", "cuMemcpyDtoH_v2"]

    require(isinstance(report, dict), "phase probe report must be an object")
    required_keys = {"schema", "status", "phase", "expected_pci", "driver_library_path",
                     "driver_api", "selected_device", "completed_operations",
                     "numeric_result_passed", "result_value", "expected_result",
                     "cleanup_passed", "cleanup_errors", "error"}
    require(set(report) == required_keys, "phase report contains missing or unexpected fields")
    require(exit_code == 0 and report.get("schema") == "nvidia-cuda-driver-phase-v1" and
            report.get("status") == "phase-passed", "phase probe did not pass")
    require(report.get("phase") == expected_phase, "phase name differs from the command")
    pci = canonical_pci(expected_pci)
    require(report.get("expected_pci") == pci, "phase expected PCI differs from the command")
    library = report.get("driver_library_path")
    require(isinstance(library, str) and Path(library).is_absolute(),
            "phase report lacks a resolved CUDA library path")
    selected = None
    if expected_phase == "initialize":
        require(report.get("driver_api") is None and report.get("selected_device") is None,
                "initialize-only phase must not report enumeration or a Driver API version")
    else:
        require(type(report.get("driver_api")) is int and report["driver_api"] > 0,
                "phase report has an invalid Driver API version")
        device = report.get("selected_device")
        require(isinstance(device, dict) and set(device) ==
                {"name", "pci_bus_id", "sm", "compute_capability",
                 "concurrent_managed_access",
                 "pageable_memory_access", "pageable_memory_access_uses_host_page_tables"},
                "phase report lacks the exact selected-device identity")
        require(isinstance(device.get("name"), str) and bool(device["name"]) and
                canonical_pci(device.get("pci_bus_id", "")) == pci,
                "phase device identity differs from the selected PCI device")
        sm = device.get("sm")
        require(type(sm) is int and sm > 0 and
                device.get("compute_capability") == f"{sm // 10}.{sm % 10}",
                "phase device architecture metadata is inconsistent")
        require(type(device["concurrent_managed_access"]) is bool and
                type(device["pageable_memory_access"]) is bool and
                type(device["pageable_memory_access_uses_host_page_tables"]) is bool,
                "phase device Unified Memory capabilities are invalid")
        selected = device
    require(report.get("completed_operations") == expected_operations,
            "completed Driver API operations differ from the requested phase")
    is_kernel = expected_phase == "kernel"
    require(report.get("numeric_result_passed") is is_kernel,
            "numeric kernel result is outside or missing from the requested phase")
    if is_kernel:
        expected_value = selected["sm"] * 10
        require(report.get("result_value") == expected_value and
                report.get("expected_result") == expected_value,
                "architecture kernel result differs from the selected GPU")
    else:
        require(report.get("result_value") is None and report.get("expected_result") is None,
                "non-kernel phase reports an unrequested numeric result")
    require(report.get("cleanup_passed") is True and report.get("cleanup_errors") == [] and
            report.get("error") == "", "phase cleanup or error status is not clean")
    return "phase-report-contract-pass"


def validate_system_pageable_memory_report(report: object, exit_code: int,
                                           expected_pci: str,
                                           expected_name_fragment: str = "RTX 5080",
                                           expected_sm: int = 120,
                                           expected_compute_capability: str = "12.0") -> str:
    """Validate ordinary system-memory kernel access on one explicitly selected GPU."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict), "pageable-memory report must be an object")
    expected_keys = {"schema", "status", "phase", "expected_pci", "driver_library_path",
                     "driver_api", "selected_device", "allocators", "cleanup_passed",
                     "cleanup_errors", "error"}
    require(set(report) == expected_keys, "pageable-memory report has missing or unexpected fields")
    require(report.get("schema") == "nvidia-cuda-system-pageable-memory-v1" and
            report.get("phase") == "system-pageable-memory",
            "pageable-memory report schema or phase differs from the request")
    pci = canonical_pci(expected_pci)
    require(report.get("expected_pci") == pci, "pageable-memory expected PCI differs from request")
    library = report.get("driver_library_path")
    require(isinstance(library, str) and Path(library).is_absolute(),
            "pageable-memory report lacks a resolved CUDA library path")
    require(type(report.get("driver_api")) is int and report["driver_api"] > 0,
            "pageable-memory report has an invalid Driver API version")
    device = report.get("selected_device")
    require(isinstance(device, dict) and set(device) == {
        "name", "pci_bus_id", "sm", "compute_capability", "concurrent_managed_access",
        "pageable_memory_access", "pageable_memory_access_uses_host_page_tables",
        "unified_addressing"}, "pageable-memory report lacks exact selected-device capabilities")
    require(isinstance(expected_name_fragment, str) and expected_name_fragment and
            isinstance(device.get("name"), str) and expected_name_fragment in device["name"] and
            canonical_pci(device.get("pci_bus_id", "")) == pci and
            type(device.get("sm")) is int and device.get("sm") == expected_sm and
            device.get("compute_capability") == expected_compute_capability,
            "pageable-memory device identity differs from the selected GPU")
    require(all(type(device.get(key)) is bool for key in (
        "concurrent_managed_access", "pageable_memory_access",
        "pageable_memory_access_uses_host_page_tables", "unified_addressing")),
        "pageable-memory device capabilities are not boolean")
    require(report.get("cleanup_passed") is True and report.get("cleanup_errors") == [],
            "pageable-memory cleanup did not pass")
    status = report.get("status")
    if status == "unsupported":
        unsupported_reason = report.get("error")
        capability_absent = (
            unsupported_reason == "device does not report pageable memory access" and
            device["pageable_memory_access"] is False) or (
            unsupported_reason == "device does not report unified addressing" and
            device["unified_addressing"] is False)
        require(exit_code == 77 and report.get("allocators") == {"malloc": None, "mmap": None} and
                capability_absent,
                "unsupported pageable-memory result is inconsistent")
        return "system-pageable-memory-unsupported-report-contract-valid"
    require(exit_code == 0 and status == "validated" and report.get("error") == "",
            "pageable-memory kernel test did not validate")
    require(device["pageable_memory_access"] and device["unified_addressing"],
            "validated pageable-memory test lacks its capability gates")
    allocators = report.get("allocators")
    require(isinstance(allocators, dict) and set(allocators) == {"malloc", "mmap"},
            "pageable-memory allocator results are incomplete")
    expected_sizes = [1, 31, 256, 4096, 65537]
    for name, mode in (("malloc", "context-synchronized"), ("mmap", "stream-synchronized")):
        result = allocators[name]
        sizes = result.get("sizes") if isinstance(result, dict) else None
        require(isinstance(result, dict) and set(result) == {
            "tested", "passed", "execution_mode", "sizes"} and
            result.get("tested") is True and result.get("passed") is True and
            result.get("execution_mode") == mode and sizes == expected_sizes and
            all(type(size) is int for size in sizes),
            f"{name} pageable-memory kernel checks did not pass all sizes")
    return "system-pageable-memory-report-contract-pass"


def correlated_gpu_mmap_count(records: list[object]) -> int:
    """Count ordered map-to-mmap pairs bound to one observed file object."""
    count = 0
    for map_index, mapped in enumerate(records):
        if not isinstance(mapped, dict) or mapped.get("operation") != "map_memory":
            continue
        entry, exit_payload = mapped.get("entry"), mapped.get("exit")
        if (mapped.get("syscall_return") != 0 or not isinstance(entry, dict) or
            not isinstance(exit_payload, dict) or exit_payload.get("status") != 0 or
            exit_payload.get("backendFdRole") != "gpu" or
            exit_payload.get("linearAddressPresent") is not True or
            type(entry.get("backendFd")) is not int or
            entry.get("backendFd") != exit_payload.get("backendFd") or
            type(entry.get("backendFileId")) is not int or
            entry.get("backendFileId") <= 0 or
            entry.get("backendFileId") != exit_payload.get("backendFileId")):
            continue
        fd = exit_payload["backendFd"]
        file_id = exit_payload["backendFileId"]
        if not any(isinstance(row, dict) and row.get("operation") in ("fd_open", "fd_dup") and
                   row.get("fd") == fd and row.get("fd_role") == "gpu" and
                   row.get("fd_file_id") == file_id for row in records[:map_index]):
            continue
        for index in range(map_index + 1, len(records)):
            row = records[index]
            if not isinstance(row, dict):
                continue
            if (row.get("operation") == "close" and row.get("fd") == fd and
                row.get("fd_role") == "gpu" and row.get("fd_file_id") == file_id and
                row.get("close_succeeded") is True):
                break
            if (row.get("operation") == "map_memory" and
                isinstance(row.get("entry"), dict) and
                row["entry"].get("backendFd") == fd and
                row["entry"].get("backendFileId") == file_id):
                break
            payload = row.get("entry")
            if (row.get("operation") == "mmap" and row.get("fd") == fd and
                row.get("fd_role") == "gpu" and row.get("fd_file_id") == file_id and
                row.get("mmap_succeeded") is True and
                isinstance(payload, dict) and payload.get("offsetZero") is True and
                payload.get("length") == exit_payload.get("length")):
                count += 1
                break
    return count


def validate_map_fd_lifecycle(records: list[object]) -> None:
    """Check selected numeric-FD reuse against observed open/dup/close events."""
    active: dict[int, tuple[int, str]] = {}
    known_file_ids: set[int] = set()
    for row in records:
        if not isinstance(row, dict):
            continue
        operation = row.get("operation")
        fd = row.get("fd")
        file_id = row.get("fd_file_id")
        role = row.get("fd_role")
        if operation == "fd_open":
            if (set(row) != {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                             "fd_file_id", "entry", "exit", "syscall_return"} or
                row.get("request") not in (2, 257, 437) or type(fd) is not int or fd < 0 or
                role not in ("control", "gpu") or type(file_id) is not int or file_id <= 0 or
                row.get("entry") is not None or row.get("exit") is not None or
                row.get("syscall_return") != fd or fd in active or file_id in known_file_ids):
                raise ValueError("selected open event has invalid file identity metadata")
            active[fd] = (file_id, role)
            known_file_ids.add(file_id)
        elif operation == "fd_dup":
            source_fd = row.get("source_fd")
            if (set(row) != {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                             "fd_file_id", "source_fd", "entry", "exit", "syscall_return"} or
                row.get("request") not in (32, 33, 72, 292) or type(fd) is not int or fd < 0 or
                type(source_fd) is not int or source_fd < 0 or role not in ("control", "gpu") or
                type(file_id) is not int or file_id <= 0 or
                active.get(source_fd) != (file_id, role) or row.get("entry") is not None or
                row.get("exit") is not None or row.get("syscall_return") != fd):
                raise ValueError("selected dup event does not preserve its source file identity")
            active[fd] = (file_id, role)
        elif operation == "close":
            if (type(fd) is not int or fd < 0 or type(file_id) is not int or file_id <= 0 or
                role not in ("control", "gpu") or active.get(fd) != (file_id, role) or
                row.get("entry") is not None or row.get("exit") is not None or
                type(row.get("close_succeeded")) is not bool or
                row.get("close_succeeded") != (row.get("syscall_return") == 0)):
                raise ValueError("close event does not match the selected open file identity")
            active.pop(fd, None)
        elif operation == "rusd_alloc":
            if (type(fd) is not int or fd < 0 or type(file_id) is not int or file_id <= 0 or
                role not in ("control", "gpu") or active.get(fd) != (file_id, role)):
                raise ValueError("RUSD allocation does not match an observed selected-file identity")
        elif operation == "fd_close_range":
            interval = row.get("entry")
            if (row.get("request") != 436 or fd != -1 or role != "other" or
                not isinstance(interval, dict) or set(interval) != {"first_fd", "last_fd", "flags"} or
                type(interval.get("first_fd")) is not int or type(interval.get("last_fd")) is not int or
                type(interval.get("flags")) is not int or row.get("exit") is not None or
                type(row.get("syscall_return")) is not int):
                raise ValueError("close_range event has invalid descriptor-lifecycle metadata")
            if row["syscall_return"] == 0:
                for selected_fd in list(active):
                    if interval["first_fd"] <= selected_fd <= interval["last_fd"]:
                        active.pop(selected_fd, None)
        elif operation == "map_memory":
            payload = row.get("entry")
            if not isinstance(payload, dict):
                continue
            memory_class = payload.get("memoryObjectClass")
            if (not isinstance(memory_class, dict) or
                set(memory_class) != {"resolution", "classId"} or
                memory_class.get("resolution") not in
                ("absent", "resolved", "not-observed-live-object", "invalid-root", "ambiguous") or
                (memory_class.get("resolution") == "resolved" and
                 (type(memory_class.get("classId")) is not int or
                  not 0 < memory_class["classId"] <= 0xffffffff)) or
                (memory_class.get("resolution") != "resolved" and
                 memory_class.get("classId") is not None)):
                raise ValueError("RM map packet has invalid memory-object class metadata")
            exit_payload = row.get("exit")
            if (isinstance(exit_payload, dict) and
                exit_payload.get("memoryObjectClass") != memory_class):
                raise ValueError("RM map packet memory-object class changed during ioctl")
            backend_fd, backend_id = payload.get("backendFd"), payload.get("backendFileId")
            if (active.get(fd) != (file_id, "control") or type(backend_fd) is not int or
                type(backend_id) is not int or active.get(backend_fd) != (backend_id,
                                                                          payload.get("backendFdRole"))):
                raise ValueError("RM map packet references an untracked or mismatched backend file")
        elif operation == "mmap":
            if (type(fd) is not int or type(file_id) is not int or
                active.get(fd) != (file_id, role)):
                raise ValueError("mmap descriptor does not match the observed open file identity")
        elif operation == "unmap_memory":
            if active.get(fd) != (file_id, "control"):
                raise ValueError("RM unmap packet uses an untracked control file")


def validate_binapi_control_observation(observed: dict) -> tuple[bool, int]:
    """Validate fixed BINAPI payload-shape metadata, never raw bytes or pointers."""
    pointer_scope = (
        "exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; "
        "no contained pointer is followed; raw bytes, addresses, and handles omitted")
    class_scope = (
        "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected "
        "control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed")
    snapshots = observed.get("binapi_payload_snapshots_read")
    rows = observed.get("records")
    if type(snapshots) is not int or snapshots < 0:
        raise ValueError("BINAPI observation has no valid payload-snapshot count")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("BINAPI observation records are malformed")
    if (observed.get("gpu_path") != "/dev/nvidia0" or
        observed.get("object_class_resolution_scope") != class_scope):
        raise ValueError("BINAPI observer did not resolve live classes on both selected RM paths")
    if snapshots == 0:
        if (rows or observed.get("nested_pointers_read") is not False or
            "nested_pointer_scope" in observed):
            raise ValueError("empty BINAPI capture unexpectedly included records or nested reads")
        return False, 0
    if snapshots < 2 or snapshots % 2 or snapshots != 2 * len(rows):
        raise ValueError("BINAPI payload snapshots do not form complete entry/exit pairs")
    if (observed.get("nested_pointers_read") is not True or
        observed.get("nested_pointer_scope") != pointer_scope):
        raise ValueError("BINAPI observer exceeded or misstated its fixed pointer scope")

    record_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                     "entry", "exit", "syscall_return"}
    outer_fields = {"command", "flags", "params_size", "status", "hClientPresent",
                    "hObjectPresent", "client_object_equal",
                    "client_matches_prior_root_allocation",
                    "object_matches_prior_root_allocation", "objectClass", "binapiPayload"}
    payload_fields = {"payloadBytes", "payloadValid", "nonzeroU32Count",
                      "nonzeroU32MaskLsbFirst", "changedByteCount",
                      "changedByteMaskLsbFirst", "entryExitPayloadEqual"}
    for row in rows:
        if (set(row) != record_fields or type(row.get("tid")) is not int or row["tid"] <= 0 or
            type(row.get("fd")) is not int or row["fd"] < 0 or
            row.get("fd_role") != "control" or row.get("operation") != "binapi_control" or
            (row.get("request"), row.get("packet_size")) not in
            ((0xc020462a, 32), (0xc01046d3, 16)) or row.get("syscall_return") != 0):
            raise ValueError("BINAPI RM_CONTROL transport is malformed or unsuccessful")
        phases = [row.get("entry"), row.get("exit")]
        if not all(isinstance(phase, dict) and set(phase) == outer_fields for phase in phases):
            raise ValueError("BINAPI RM_CONTROL header is malformed or unredacted")
        command = phases[0].get("command")
        if command != 0x20810108:
            raise ValueError("BINAPI RM_CONTROL command differs from the fixed observed command")
        for phase_index, phase in enumerate(phases):
            if (phase.get("command") != command or phase.get("params_size") != 992 or
                type(phase.get("flags")) is not int or type(phase.get("status")) is not int or
                (phase_index == 1 and phase.get("status") != 0) or
                any(type(phase.get(key)) is not bool for key in (
                    "hClientPresent", "hObjectPresent", "client_object_equal",
                    "client_matches_prior_root_allocation",
                    "object_matches_prior_root_allocation")) or
                phase.get("hClientPresent") is not True or phase.get("hObjectPresent") is not True):
                raise ValueError("BINAPI RM_CONTROL header fields are invalid")
            object_class = phase.get("objectClass")
            if (not isinstance(object_class, dict) or
                set(object_class) != {"resolution", "classId"} or
                object_class.get("resolution") != "resolved" or
                object_class.get("classId") != 0x2081):
                raise ValueError("BINAPI object class is not a resolved live NV2081_BINAPI")
            payload = phase.get("binapiPayload")
            if not isinstance(payload, dict) or set(payload) != payload_fields:
                raise ValueError("BINAPI payload-shape metadata is malformed")
            nonzero_mask = payload.get("nonzeroU32MaskLsbFirst")
            changed_mask = payload.get("changedByteMaskLsbFirst")
            if (payload.get("payloadBytes") != 992 or payload.get("payloadValid") is not True or
                type(payload.get("nonzeroU32Count")) is not int or
                type(payload.get("changedByteCount")) is not int or
                not isinstance(nonzero_mask, str) or not re.fullmatch(r"[0-9a-f]{62}", nonzero_mask) or
                not isinstance(changed_mask, str) or not re.fullmatch(r"[0-9a-f]{248}", changed_mask)):
                raise ValueError("BINAPI payload-shape metadata is malformed or contains raw values")
            nonzero_bits = sum(byte.bit_count() for byte in bytes.fromhex(nonzero_mask))
            changed_bits = sum(byte.bit_count() for byte in bytes.fromhex(changed_mask))
            equal = payload.get("entryExitPayloadEqual")
            if (not 0 <= payload["nonzeroU32Count"] <= 248 or
                payload["nonzeroU32Count"] != nonzero_bits or
                not 0 <= payload["changedByteCount"] <= 992 or
                payload["changedByteCount"] != changed_bits):
                raise ValueError("BINAPI mask counts disagree with their fixed-size masks")
            if phase_index == 0:
                if (equal is not None or payload["changedByteCount"] != 0 or
                    any(bytes.fromhex(changed_mask))):
                    raise ValueError("BINAPI entry metadata contains an exit-only comparison")
            elif type(equal) is not bool or equal != (payload["changedByteCount"] == 0):
                raise ValueError("BINAPI entry/exit equality disagrees with the byte-change mask")
    return True, snapshots


def validate_device_alloc_observation(observed: dict) -> tuple[bool, int]:
    """Validate the fixed, redacted NV0080 class payload observer contract."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict), "device-allocation observation must be an object")
    require(observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v19" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "device-allocation observer report is incomplete")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("gpu_path") == "/dev/nvidia0" and
            observed.get("architecture") == "x86_64" and observed.get("pointer_bits") == 64,
            "device-allocation observer selected an unexpected descriptor or ABI")
    require(observed.get("payload_scope") ==
            "NV01_DEVICE_0 fixed class parameters only; handles are redacted and internal VA addresses are omitted",
            "device-allocation observer payload scope differs from the fixed safe boundary")
    scope = ("NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; "
             "client handles are relational booleans; internal VA addresses are omitted")
    require(observed.get("nested_pointer_scope") == scope,
            "device-allocation observer nested-payload scope differs from the pinned layout")
    snapshots = observed.get("device_alloc_payload_snapshots_read")
    require(type(snapshots) is int and snapshots >= 0,
            "device-allocation observer has no valid payload snapshot count")
    records = observed.get("records")
    require(isinstance(records, list), "device-allocation observer records are missing")
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry", "exit", "syscall_return"}
    packet_fields = {"layout", "hClass", "paramsSize", "flags", "status",
                     "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                     "pAllocParmsPresent", "pRightsRequestedPresent", "deviceAlloc"}
    payload_fields = {"classPayloadBytes", "deviceId", "hClientShare", "targetClientZero",
                      "targetDeviceZero", "flags", "vaSpaceSize", "vaStartInternalZero",
                      "vaLimitInternalZero", "vaMode"}
    present_payloads = 0
    successful = False
    for row in records:
        require(isinstance(row, dict) and set(row) == row_fields,
                "device-allocation record has unexpected or unredacted fields")
        require(row.get("operation") == "device_alloc" and row.get("fd_role") in ("control", "gpu") and
                type(row.get("tid")) is int and type(row.get("fd")) is int and row["fd"] >= 0 and
                type(row.get("request")) is int and row["request"] > 0 and
                type(row.get("packet_size")) is int and row["packet_size"] > 0,
                "device-allocation record identity is malformed")
        require(type(row.get("syscall_return")) is int,
                "device-allocation record has no syscall result")
        for endpoint in ("entry", "exit"):
            packet = row.get(endpoint)
            require(isinstance(packet, dict) and set(packet) == packet_fields and
                    packet.get("layout") == "NVOS64" and packet.get("hClass") == 128 and
                    type(packet.get("paramsSize")) is int and 0 <= packet["paramsSize"] <= 4096 and
                    type(packet.get("flags")) is int and type(packet.get("status")) is int and
                    all(type(packet.get(key)) is bool for key in
                        ("hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                         "pAllocParmsPresent", "pRightsRequestedPresent")),
                    "device-allocation packet header is malformed")
            payload = packet.get("deviceAlloc")
            if payload is None:
                continue
            require(isinstance(payload, dict) and set(payload) == payload_fields and
                    payload.get("classPayloadBytes") == 56 and
                    type(payload.get("deviceId")) is int and payload["deviceId"] >= 0 and
                    payload.get("hClientShare") in ("zero", "same-as-root", "other-nonzero") and
                    all(type(payload.get(key)) is bool for key in
                        ("targetClientZero", "targetDeviceZero", "vaStartInternalZero",
                         "vaLimitInternalZero")) and
                    type(payload.get("flags")) is int and
                    type(payload.get("vaSpaceSize")) is int and payload["vaSpaceSize"] >= 0 and
                    type(payload.get("vaMode")) is int,
                    "device-allocation payload is malformed or contains unredacted data")
            present_payloads += 1
            if endpoint == "exit" and row["syscall_return"] == 0 and packet["status"] == 0:
                successful = True
    require(present_payloads == snapshots,
            "device-allocation snapshot count differs from the redacted records")
    require(len(records) > 0 and successful,
            "device-allocation capture has no successful NV01_DEVICE_0 construction")
    require(snapshots > 0,
            "device-allocation capture observed no NV0080 class payload")
    return True, snapshots


def validate_subdevice_alloc_observation(observed: dict) -> tuple[bool, int]:
    """Validate redacted entry/exit snapshots of NV2080_ALLOC_PARAMETERS."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v20" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "subdevice-allocation observer report is incomplete")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("gpu_path") == "/dev/nvidia0" and
            observed.get("architecture") == "x86_64" and observed.get("pointer_bits") == 64,
            "subdevice-allocation observer selected an unexpected descriptor or ABI")
    require(observed.get("payload_scope") ==
            "NV20_SUBDEVICE_0 fixed class parameters only; handles omitted" and
            observed.get("nested_pointer_scope") ==
            "NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; handles omitted",
            "subdevice-allocation observer scope differs from the fixed safe boundary")
    snapshots = observed.get("subdevice_alloc_payload_snapshots_read")
    require(type(snapshots) is int and snapshots >= 0,
            "subdevice-allocation observer has no valid snapshot count")
    records = observed.get("records")
    require(isinstance(records, list) and len(records) > 0,
            "subdevice-allocation observer records are missing")
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry", "exit", "syscall_return"}
    packet_fields = {"layout", "hClass", "paramsSize", "flags", "status",
                     "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                     "pAllocParmsPresent", "pRightsRequestedPresent", "subdeviceAlloc"}
    payload_fields = {"classPayloadBytes", "subDeviceId"}
    snapshot_count = 0
    success = False
    for row in records:
        require(isinstance(row, dict) and set(row) == row_fields and
                row.get("operation") == "subdevice_alloc" and
                row.get("fd_role") in ("control", "gpu") and
                type(row.get("tid")) is int and type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("request") == 0xC030462B and row.get("packet_size") == 48 and
                type(row.get("syscall_return")) is int,
                "subdevice-allocation record envelope is malformed")
        snapshots_by_phase = []
        for endpoint in ("entry", "exit"):
            packet = row.get(endpoint)
            require(isinstance(packet, dict) and set(packet) == packet_fields and
                    packet.get("layout") == "NVOS64" and packet.get("hClass") == 0x2080 and
                    type(packet.get("paramsSize")) is int and packet["paramsSize"] in (0, 4) and
                    type(packet.get("flags")) is int and type(packet.get("status")) is int and
                    all(type(packet.get(key)) is bool for key in
                        ("hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                         "pAllocParmsPresent", "pRightsRequestedPresent")),
                    "subdevice-allocation packet is malformed or unredacted")
            payload = packet.get("subdeviceAlloc")
            if payload is not None:
                require(isinstance(payload, dict) and set(payload) == payload_fields and
                        payload.get("classPayloadBytes") == 4 and
                        type(payload.get("subDeviceId")) is int and
                        0 <= payload["subDeviceId"] <= 0xFFFFFFFF,
                        "subdevice-allocation class payload is malformed")
                snapshot_count += 1
            snapshots_by_phase.append(payload)
        require(snapshots_by_phase[0] == snapshots_by_phase[1],
                "subdevice-allocation payload changed between syscall entry and exit")
        if (row["syscall_return"] == 0 and row["exit"]["status"] == 0 and
                snapshots_by_phase[1] is not None):
            success = True
    require(snapshot_count == snapshots and snapshots > 0,
            "subdevice-allocation snapshot count differs from the records")
    require(success, "subdevice-allocation capture has no successful NV20_SUBDEVICE_0 construction")
    return True, snapshots


def validate_binapi_alloc_observation(observed: dict) -> tuple[bool, int]:
    """Validate the optional, fixed and redacted NV2081 allocation payload."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v21" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "BINAPI-allocation observer report is incomplete")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("gpu_path") == "/dev/nvidia0" and
            observed.get("architecture") == "x86_64" and observed.get("pointer_bits") == 64,
            "BINAPI-allocation observer selected an unexpected descriptor or ABI")
    require(observed.get("payload_scope") ==
            "NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted" and
            observed.get("nested_pointer_scope") ==
            "NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; handles omitted",
            "BINAPI-allocation observer scope differs from the fixed safe boundary")
    snapshots = observed.get("binapi_alloc_payload_snapshots_read")
    require(type(snapshots) is int and snapshots >= 0 and
            observed.get("nested_pointers_read") is (snapshots > 0),
            "BINAPI-allocation observer has an invalid payload-read count")
    records = observed.get("records")
    require(isinstance(records, list) and len(records) > 0,
            "BINAPI-allocation observer records are missing")
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry", "exit", "syscall_return"}
    packet_fields = {"layout", "hClass", "paramsSize", "flags", "status",
                     "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                     "pAllocParmsPresent", "pRightsRequestedPresent", "binapiAlloc"}
    payload_fields = {"classPayloadBytes", "reservedZero"}
    snapshot_count = 0
    successful = False
    for row in records:
        require(isinstance(row, dict) and set(row) == row_fields and
                row.get("operation") == "binapi_alloc" and
                row.get("fd_role") in ("control", "gpu") and
                type(row.get("tid")) is int and type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("request") == 0xC030462B and row.get("packet_size") == 48 and
                type(row.get("syscall_return")) is int,
                "BINAPI-allocation record envelope is malformed")
        payloads = []
        for endpoint in ("entry", "exit"):
            packet = row.get(endpoint)
            require(isinstance(packet, dict) and set(packet) == packet_fields and
                    packet.get("layout") == "NVOS64" and packet.get("hClass") == 0x2081 and
                    type(packet.get("paramsSize")) is int and packet["paramsSize"] in (0, 4) and
                    type(packet.get("flags")) is int and type(packet.get("status")) is int and
                    all(type(packet.get(key)) is bool for key in
                        ("hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                         "pAllocParmsPresent", "pRightsRequestedPresent")),
                    "BINAPI-allocation packet is malformed or unredacted")
            payload = packet.get("binapiAlloc")
            if payload is None:
                require(not packet["pAllocParmsPresent"] and packet["paramsSize"] == 0,
                        "absent optional BINAPI payload has inconsistent packet fields")
            else:
                require(packet["pAllocParmsPresent"] and
                        isinstance(payload, dict) and set(payload) == payload_fields and
                        payload.get("classPayloadBytes") == 4 and
                        type(payload.get("reservedZero")) is bool,
                        "BINAPI-allocation class payload is malformed or unredacted")
                snapshot_count += 1
            payloads.append(payload)
        require(payloads[0] == payloads[1],
                "BINAPI-allocation payload changed between syscall entry and exit")
        if row["syscall_return"] == 0 and row["exit"]["status"] == 0:
            successful = True
    require(snapshot_count == snapshots,
            "BINAPI-allocation snapshot count differs from the redacted records")
    require(successful,
            "BINAPI-allocation capture has no successful NV2081_BINAPI construction")
    return True, snapshots


def validate_gt200_debugger_alloc_observation(observed: dict) -> tuple[bool, int]:
    """Validate only the fixed GT200_DEBUGGER payload and redacted handle relations."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v34" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "GT200_DEBUGGER observer report is incomplete")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("gpu_path") == "/dev/nvidia0" and
            observed.get("architecture") == "x86_64" and observed.get("pointer_bits") == 64,
            "GT200_DEBUGGER observer selected an unexpected descriptor or ABI")
    require(observed.get("payload_scope") ==
            "NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; "
            "raw handles, pointers, and payload bytes omitted" and
            observed.get("nested_pointer_scope") ==
            "exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; emits handle presence "
            "and within-root class relations including the debuggee direct-parent class; raw handles and addresses omitted" and
            observed.get("object_class_resolution_scope") ==
            "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; "
            "lookup is keyed by NVOS64 root and handle and emits only object and direct-parent class IDs/presence; "
            "unresolved means no unique live object was observed",
            "GT200_DEBUGGER observer scope differs from the fixed redacted boundary")
    require(observed.get("nested_pointers_read") is True,
            "GT200_DEBUGGER capture did not read its required fixed payload")
    snapshots = observed.get("debugger_alloc_payload_snapshots_read")
    require(type(snapshots) is int and snapshots > 0,
            "GT200_DEBUGGER observer has no valid payload snapshot count")
    records = observed.get("records")
    require(isinstance(records, list) and len(records) > 0,
            "GT200_DEBUGGER observer records are missing")
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry", "exit", "syscall_return"}
    packet_fields = {"layout", "hClass", "paramsSize", "flags", "status",
                     "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                     "pAllocParmsPresent", "pRightsRequestedPresent", "debuggerAlloc"}
    payload_fields = {"classPayloadBytes", "obsoleteClientZero", "appClientPresent",
                      "appClientMatchesRoot", "appClientMatchesParent", "appClientEqualsDebuggee",
                      "debuggee3dHandlePresent", "appClientClassWithinRoot",
                      "debuggee3dClassWithinRoot", "debuggee3dParentClassWithinRoot",
                      "parentClassWithinRoot"}
    relation_fields = {"resolution", "classId"}
    resolutions = {"resolved", "not-observed-live-object", "invalid-root", "ambiguous", "absent"}
    present_payloads = 0
    success = False
    for row in records:
        require(isinstance(row, dict) and set(row) == row_fields and
                row.get("operation") == "gt200_debugger_alloc" and
                row.get("fd_role") in ("control", "gpu") and
                type(row.get("tid")) is int and row["tid"] > 0 and
                type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("request") == 0xC030462B and row.get("packet_size") == 48 and
                type(row.get("syscall_return")) is int,
                "GT200_DEBUGGER allocation record envelope is malformed or unredacted")
        endpoint_payloads = []
        for endpoint in ("entry", "exit"):
            packet = row.get(endpoint)
            require(isinstance(packet, dict) and set(packet) == packet_fields and
                    packet.get("layout") == "NVOS64" and packet.get("hClass") == 0x83DE and
                    type(packet.get("paramsSize")) is int and packet["paramsSize"] in (0, 12) and
                    type(packet.get("flags")) is int and type(packet.get("status")) is int and
                    all(type(packet.get(key)) is bool for key in
                        ("hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                         "pAllocParmsPresent", "pRightsRequestedPresent")),
                    "GT200_DEBUGGER allocation packet is malformed or unredacted")
            payload = packet.get("debuggerAlloc")
            if payload is None:
                require(packet["pAllocParmsPresent"] is False,
                        "GT200_DEBUGGER allocation omitted a required payload")
            else:
                require(isinstance(payload, dict) and set(payload) == payload_fields and
                        payload.get("classPayloadBytes") == 12 and
                        all(type(payload.get(key)) is bool for key in
                            ("obsoleteClientZero", "appClientPresent", "appClientMatchesRoot",
                             "appClientMatchesParent", "appClientEqualsDebuggee",
                             "debuggee3dHandlePresent")),
                        "GT200_DEBUGGER nested payload is malformed or unredacted")
                for key in ("appClientClassWithinRoot", "debuggee3dClassWithinRoot",
                            "debuggee3dParentClassWithinRoot", "parentClassWithinRoot"):
                    relation = payload.get(key)
                    require(isinstance(relation, dict) and set(relation) == relation_fields and
                            relation.get("resolution") in resolutions and
                            ((relation["resolution"] == "resolved" and
                              type(relation.get("classId")) is int and
                              0 <= relation["classId"] <= 0xFFFFFFFF) or
                             (relation["resolution"] != "resolved" and
                              relation.get("classId") is None)),
                            "GT200_DEBUGGER handle-to-class relation is malformed")
                present_payloads += 1
            endpoint_payloads.append(payload)
        require(endpoint_payloads[0] == endpoint_payloads[1],
                "GT200_DEBUGGER nested payload changed between syscall entry and exit")
        if (row["syscall_return"] == 0 and row["exit"]["status"] == 0 and
                endpoint_payloads[1] is not None):
            success = True
    require(present_payloads == snapshots and snapshots > 0,
            "GT200_DEBUGGER snapshot count differs from the redacted records")
    require(success, "GT200_DEBUGGER capture has no successful class construction")
    return True, snapshots


GT200_DEBUGGER_LIFECYCLE_PAYLOAD_SCOPE = (
    "GT200_DEBUGGER allocations, class-resolved GT200_DEBUGGER frees, fixed NVOS54 headers plus a redacted hObject-to-prior-debugger-allocation equality, and exact 4-byte exceptionMask snapshots for resolved 0x83de0309 controls only; null pointers, size mismatch, and undocumented bits fail closed; unresolved command candidates are never dereferenced; raw handles and addresses omitted")


def gt200_debugger_lifecycle_payload_scope_matches(observed: dict) -> bool:
    """Share the lifecycle payload-scope gate with the full observation validator."""
    return (isinstance(observed, dict) and
            observed.get("payload_scope") == GT200_DEBUGGER_LIFECYCLE_PAYLOAD_SCOPE)


def validate_gt200_debugger_lifecycle_observation(
        observed: dict) -> dict[str, int | list[int]]:
    """Validate redacted GT200_DEBUGGER alloc/free/control lifecycle records."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v39" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "GT200_DEBUGGER lifecycle observer report is incomplete")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("gpu_path") == "/dev/nvidia0" and
            observed.get("architecture") == "x86_64" and observed.get("pointer_bits") == 64,
            "GT200_DEBUGGER lifecycle observer selected an unexpected descriptor or ABI")
    require(gt200_debugger_lifecycle_payload_scope_matches(observed) and
            observed.get("nested_pointer_scope") ==
            "exact NV83DE allocation parameters plus fixed NVOS54 headers for resolved GT200_DEBUGGER controls and unresolved 0x83de command candidates; only exact 4-byte exceptionMask for resolved 0x83de0309 controls is followed after fixed-size, non-null-pointer, and documented-bit checks; RM_FREE class resolution is root-scoped; a redacted hObject-to-prior-GT200_DEBUGGER-allocation equality is emitted; raw handles and addresses omitted" and
            observed.get("object_class_resolution_scope") ==
            "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU "
            "paths; debugger control hClient is resolved to one observed root before resolving hObject; "
            "a redacted hObject equality against prior successful GT200_DEBUGGER allocations is recorded; unresolved free classes and debugger-command candidates emit redacted fixed headers; raw handles are omitted",
            "GT200_DEBUGGER lifecycle scope differs from the fixed redacted boundary")

    snapshots = observed.get("debugger_alloc_payload_snapshots_read")
    mask_snapshots = observed.get("debugger_exception_mask_payload_snapshots_read")
    free_unresolved = observed.get("debugger_free_unresolved_class_count")
    control_unresolved = observed.get("debugger_control_unresolved_candidate_count")
    records = observed.get("records")
    require(type(snapshots) is int and 0 <= snapshots <= 0xFFFFFFFF and
            type(mask_snapshots) is int and 0 <= mask_snapshots <= 0xFFFFFFFF and
            type(free_unresolved) is int and 0 <= free_unresolved <= 0xFFFFFFFF and
            type(control_unresolved) is int and 0 <= control_unresolved <= 0xFFFFFFFF and
            isinstance(records, list),
            "GT200_DEBUGGER lifecycle counts or records are malformed")
    require(observed.get("nested_pointers_read") is (snapshots > 0 or mask_snapshots > 0),
            "GT200_DEBUGGER lifecycle nested-read flag does not match its fixed payload snapshots")

    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry", "exit", "syscall_return"}
    alloc_fields = {"layout", "hClass", "paramsSize", "flags", "status", "hRootPresent",
                    "hObjectParentPresent", "hObjectNewPresent", "pAllocParmsPresent",
                    "pRightsRequestedPresent", "debuggerAlloc"}
    alloc_payload_fields = {"classPayloadBytes", "obsoleteClientZero", "appClientPresent",
                            "appClientMatchesRoot", "appClientMatchesParent", "appClientEqualsDebuggee",
                            "debuggee3dHandlePresent", "appClientClassWithinRoot",
                            "debuggee3dClassWithinRoot", "debuggee3dParentClassWithinRoot",
                            "parentClassWithinRoot"}
    relation_fields = {"resolution", "classId"}
    resolutions = {"resolved", "not-observed-live-object", "invalid-root", "ambiguous", "absent"}
    free_fields = {"layout", "status", "hRootPresent", "hObjectParentPresent",
                   "hObjectOldPresent", "objectClassWithinRoot"}
    control_fields = {"command", "flags", "params_size", "status", "hClientPresent",
                      "hObjectPresent", "client_object_equal", "client_matches_prior_root_allocation",
                      "object_matches_prior_root_allocation",
                      "object_handle_matches_prior_debugger_allocation"}
    alloc_count = free_count = control_count = control_candidate_count = alloc_snapshots = 0
    mask_control_count = 0
    unresolved_mask_statuses = []
    for row in records:
        require(isinstance(row, dict) and
                set(row) in (row_fields, row_fields | {"debuggerTargetObjectClassWithinRoot"}) and
                row.get("fd_role") in ("control", "gpu") and
                type(row.get("tid")) is int and 0 < row["tid"] <= 0x7FFFFFFF and
                type(row.get("fd")) is int and 0 <= row["fd"] <= 0x7FFFFFFF and
                type(row.get("request")) is int and
                type(row.get("packet_size")) is int and
                type(row.get("syscall_return")) is int and
                -(1 << 63) <= row["syscall_return"] < (1 << 63),
                "GT200_DEBUGGER lifecycle record envelope is malformed or unredacted")
        operation = row["operation"]
        if operation == "gt200_debugger_alloc":
            alloc_count += 1
            require(set(row) == row_fields and row["request"] == 0xC030462B and
                    row["packet_size"] == 48,
                    "GT200_DEBUGGER allocation request is unexpected")
            payloads = []
            packets = []
            for endpoint in ("entry", "exit"):
                packet = row[endpoint]
                require(isinstance(packet, dict) and set(packet) == alloc_fields and
                        packet.get("layout") == "NVOS64" and packet.get("hClass") == 0x83DE and
                        type(packet.get("paramsSize")) is int and packet["paramsSize"] in (0, 12) and
                        type(packet.get("flags")) is int and 0 <= packet["flags"] <= 0xFFFFFFFF and
                        type(packet.get("status")) is int and 0 <= packet["status"] <= 0xFFFFFFFF and
                        all(type(packet.get(key)) is bool for key in (
                            "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                            "pAllocParmsPresent", "pRightsRequestedPresent")),
                        "GT200_DEBUGGER allocation packet is malformed or unredacted")
                payload = packet.get("debuggerAlloc")
                # The observer reads a fixed 12-byte NV83DE payload for each
                # recorded allocation, even when outer paramsSize is zero.
                require(packet["pAllocParmsPresent"] is True and
                        isinstance(payload, dict) and set(payload) == alloc_payload_fields and
                        payload.get("classPayloadBytes") == 12 and
                        all(type(payload.get(key)) is bool for key in (
                            "obsoleteClientZero", "appClientPresent", "appClientMatchesRoot",
                            "appClientMatchesParent", "appClientEqualsDebuggee",
                            "debuggee3dHandlePresent")),
                        "GT200_DEBUGGER fixed allocation payload is missing, malformed, or unredacted")
                for key in ("appClientClassWithinRoot", "debuggee3dClassWithinRoot",
                            "debuggee3dParentClassWithinRoot", "parentClassWithinRoot"):
                    relation = payload.get(key)
                    require(isinstance(relation, dict) and set(relation) == relation_fields and
                            relation.get("resolution") in resolutions and
                            ((relation["resolution"] == "resolved" and
                              type(relation.get("classId")) is int and
                              0 <= relation["classId"] <= 0xFFFFFFFF) or
                             (relation["resolution"] != "resolved" and
                              relation.get("classId") is None)),
                            "GT200_DEBUGGER allocation relation is malformed")
                alloc_snapshots += 1
                payloads.append(payload)
                packets.append(packet)
            require(payloads[0] == payloads[1],
                    "GT200_DEBUGGER allocation payload changed during the syscall")
            require({key: value for key, value in packets[0].items()
                     if key not in ("status", "hObjectNewPresent")} ==
                    {key: value for key, value in packets[1].items()
                     if key not in ("status", "hObjectNewPresent")},
                    "GT200_DEBUGGER allocation identity changed during the syscall")
        elif operation == "gt200_debugger_free":
            free_count += 1
            require(set(row) == row_fields and row["request"] == 0xC0104629 and
                    row["packet_size"] == 16,
                    "GT200_DEBUGGER free request is unexpected")
            packets = []
            for endpoint in ("entry", "exit"):
                packet = row[endpoint]
                require(isinstance(packet, dict) and set(packet) == free_fields and
                        packet.get("layout") == "NVOS00" and
                        type(packet.get("status")) is int and 0 <= packet["status"] <= 0xFFFFFFFF and
                        all(type(packet.get(key)) is bool for key in (
                            "hRootPresent", "hObjectParentPresent", "hObjectOldPresent")) and
                        packet.get("hRootPresent") is True and packet.get("hObjectOldPresent") is True and
                        packet.get("objectClassWithinRoot") == 0x83DE,
                        "GT200_DEBUGGER free packet is malformed or unresolved")
                packets.append(packet)
            require({key: value for key, value in packets[0].items() if key != "status"} ==
                    {key: value for key, value in packets[1].items() if key != "status"},
                    "GT200_DEBUGGER free packet identity changed during the syscall")
        elif operation == "gt200_debugger_control":
            control_count += 1
            entry_control = row.get("entry")
            mask_command = (isinstance(entry_control, dict) and
                            entry_control.get("command") == 0x83DE0309)
            if mask_command:
                mask_control_count += 1
            relation = row.get("debuggerTargetObjectClassWithinRoot")
            require(set(row) == row_fields | {"debuggerTargetObjectClassWithinRoot"} and
                    row["request"] in (0xC020462A, 0xC01046D3) and
                    row["packet_size"] == (32 if row["request"] == 0xC020462A else 16) and
                    isinstance(relation, dict) and set(relation) == relation_fields and
                    relation.get("resolution") == "resolved" and relation.get("classId") == 0x83DE,
                    "GT200_DEBUGGER control target is malformed or unresolved")
            packets = []
            for endpoint in ("entry", "exit"):
                packet = row[endpoint]
                expected_control_fields = control_fields | ({"exceptionMask"} if mask_command else set())
                if mask_command and endpoint == "exit":
                    expected_control_fields = expected_control_fields | {"exceptionMaskUserBufferEntryExitEqual"}
                require(isinstance(packet, dict) and set(packet) == expected_control_fields and
                        type(packet.get("command")) is int and
                        0 <= packet["command"] <= 0xFFFFFFFF and
                        packet["command"] & 0xFFFF0000 == 0x83DE0000 and
                        all(type(packet.get(key)) is int and 0 <= packet[key] <= 0xFFFFFFFF
                            for key in ("flags", "params_size", "status")) and
                        all(type(packet.get(key)) is bool for key in (
                            "hClientPresent", "hObjectPresent", "client_object_equal",
                            "client_matches_prior_root_allocation", "object_matches_prior_root_allocation",
                            "object_handle_matches_prior_debugger_allocation")),
                        "GT200_DEBUGGER control header is malformed or contains unredacted handles")
                if mask_command:
                    mask = packet.get("exceptionMask")
                    require(type(mask) is int and 0 <= mask <= 0xFFFFFFFF and
                            (mask == 0xFFFF or mask & ~0x3F == 0),
                            "GT200_DEBUGGER exception mask contains undocumented values")
                    if endpoint == "exit":
                        require(type(packet.get("exceptionMaskUserBufferEntryExitEqual")) is bool and
                                packet["exceptionMaskUserBufferEntryExitEqual"] is
                                (mask == row["entry"].get("exceptionMask")),
                                "GT200_DEBUGGER exception-mask entry/exit comparison is inconsistent")
                require(packet["hClientPresent"] is True and packet["hObjectPresent"] is True,
                        "GT200_DEBUGGER control is missing handles required for class resolution")
                require(packet["object_handle_matches_prior_debugger_allocation"] is True,
                        "resolved GT200_DEBUGGER control does not match its tracked debugger allocation")
                packets.append(packet)
            require({key: value for key, value in packets[0].items()
                     if key not in ("status", "exceptionMaskUserBufferEntryExitEqual")} ==
                    {key: value for key, value in packets[1].items()
                     if key not in ("status", "exceptionMaskUserBufferEntryExitEqual")},
                    "GT200_DEBUGGER control identity changed during the syscall")
        elif operation == "gt200_debugger_control_candidate":
            control_candidate_count += 1
            relation = row.get("debuggerTargetObjectClassWithinRoot")
            require(set(row) == row_fields | {"debuggerTargetObjectClassWithinRoot"} and
                    row["request"] in (0xC020462A, 0xC01046D3) and
                    row["packet_size"] == (32 if row["request"] == 0xC020462A else 16) and
                    isinstance(relation, dict) and set(relation) == relation_fields and
                    relation.get("resolution") in ("not-observed-live-object", "invalid-root", "ambiguous", "absent") and
                    relation.get("classId") is None,
                    "unresolved GT200_DEBUGGER command candidate relation is malformed")
            packets = []
            for endpoint in ("entry", "exit"):
                packet = row[endpoint]
                require(isinstance(packet, dict) and set(packet) == control_fields and
                        type(packet.get("command")) is int and
                        0 <= packet["command"] <= 0xFFFFFFFF and
                        packet["command"] & 0xFFFF0000 == 0x83DE0000 and
                        all(type(packet.get(key)) is int and 0 <= packet[key] <= 0xFFFFFFFF
                            for key in ("flags", "params_size", "status")) and
                        all(type(packet.get(key)) is bool for key in (
                            "hClientPresent", "hObjectPresent", "client_object_equal",
                            "client_matches_prior_root_allocation", "object_matches_prior_root_allocation",
                            "object_handle_matches_prior_debugger_allocation")),
                        "unresolved debugger candidate header is malformed or unredacted")
                require(packet["hClientPresent"] is True,
                        "unresolved debugger candidate omitted its root client handle")
                packets.append(packet)
            require({key: value for key, value in packets[0].items() if key != "status"} ==
                    {key: value for key, value in packets[1].items() if key != "status"},
                    "unresolved debugger candidate identity changed during the syscall")
            if packets[0]["command"] == 0x83DE0309:
                # Keep only the fixed command's RM result; do not retain handles
                # or follow its nested parameter pointer for unresolved targets.
                unresolved_mask_statuses.append(packets[1]["status"])
        else:
            raise ValueError("GT200_DEBUGGER lifecycle contains an unselected operation")

    require(alloc_snapshots == snapshots and snapshots == alloc_count * 2 and
            mask_snapshots == mask_control_count * 2,
            "GT200_DEBUGGER allocation snapshot count differs from the records")
    require(observed.get("nested_pointers_read") is (alloc_snapshots > 0 or mask_snapshots > 0),
            "GT200_DEBUGGER lifecycle observer read unexpected nested data")
    require(control_candidate_count == control_unresolved,
            "unresolved debugger command count differs from its redacted candidate records")
    return {"records": len(records), "allocations": alloc_count, "frees": free_count,
            "controls": control_count, "allocation_payload_snapshots": snapshots,
            "exception_mask_payload_snapshots": mask_snapshots,
            "resolved_exception_mask_controls": mask_control_count,
            "unresolved_exception_mask_candidates": len(unresolved_mask_statuses),
            "unresolved_exception_mask_rm_statuses": unresolved_mask_statuses,
            "unresolved_free_classes": free_unresolved,
            "unresolved_control_candidates": control_unresolved}


def file_identity(path: Path) -> dict:
    path = path.resolve(strict=True)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def trusted_probe_build_identity(probe: Path, module: Path) -> dict[str, str]:
    """Verify the exact pinned probe and matching fatbin, including remote copies.

    A syntactically valid JSON report is not evidence that the CUDA probe ran.
    Hash pins make the check portable to the selected-GPU runner's temporary
    directory. For the canonical local build, also validate its source/build
    manifest through the software-suite verifier.
    """
    probe_sha256 = file_identity(probe)["sha256"]
    if probe_sha256 != PINNED_PROBE_SHA256:
        raise ValueError("probe hash differs from the pinned executable")
    module_sha256 = file_identity(module)["sha256"]
    if module_sha256 != PINNED_MODULE_SHA256:
        raise ValueError("module hash differs from the pinned fatbin")
    identity = {
        "status": "trusted-pinned-build",
        "probe_sha256": probe_sha256,
        "module_sha256": module_sha256,
        "provenance": "pinned-probe-and-fatbin-sha256",
    }
    if (DEFAULT_PROBE.is_file() and DEFAULT_MODULE.is_file() and
            probe.resolve(strict=True) == DEFAULT_PROBE.resolve(strict=True) and
            module.resolve(strict=True) == DEFAULT_MODULE.resolve(strict=True)):
        from tools.run_software_test_suite import _verify_probe_build
        _, manifest_sha256, pinned_probe, manifest_path = (
            _verify_probe_build(probe.parent)
        )
        if (pinned_probe.resolve(strict=True) != probe.resolve(strict=True) or
                manifest_path.resolve(strict=True) != (probe.parent / "build-manifest.json").resolve(strict=True)):
            raise ValueError("canonical probe build manifest path is inconsistent")
        identity["provenance"] = "source-verified-manifest-and-pinned-artifacts"
        identity["manifest_path"] = str(manifest_path.resolve(strict=True))
        identity["manifest_sha256"] = manifest_sha256
    return identity


def write_probe_trust_preflight_rejection(
        args: argparse.Namespace, probe: Path, module: Path,
        trust: dict[str, str]) -> int:
    """Archive a trust failure without executing any supplied child process."""
    reason = trust.get("reason", "probe and fatbin are not a trusted pinned build")
    observed_at = datetime.now(timezone.utc)
    evidence = {
        "schema": "nvidia-hybrid-hardware-acceptance-preflight-v1",
        "evidence_kind": "local-preflight-only-no-hardware-claim",
        "observed_at_utc": observed_at.isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "kernel_release": os.uname().release,
        "requested_probe": file_identity(probe),
        "requested_module": file_identity(module),
        "probe_build_trust": trust,
        "process_started": False,
        "report_contract_qualification": "not-run-untrusted-probe",
        "qualification": "untrusted-probe-artifact",
        "validation_errors": [reason],
        "cuda_execution_validated": False,
        "cuda_execution_validation_state": "not-run; probe trust preflight rejected the artifacts",
        "exit_code": 2,
    }
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = args.evidence_dir / (
        f"hardware-probe-preflight-{socket.gethostname()}-"
        f"{observed_at.strftime('%Y%m%dT%H%M%S%fZ')}.json"
    )
    descriptor = os.open(
        evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, sort_keys=True))
    return 2


def record_cuda_selection_environment() -> dict[str, str | None]:
    """Capture variables that determine CUDA device visibility and order."""
    return {
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "cuda_device_order": os.environ.get("CUDA_DEVICE_ORDER"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="retained for compatibility; strict exit codes are the default")
    parser.add_argument("--allow-incomplete", action="store_true",
                        help="explicitly return zero for a truthful missing-hardware result")
    parser.add_argument("--timeout", type=float, default=60.0, help="probe timeout in seconds (default: 60)")
    parser.add_argument("--probe", type=Path, default=DEFAULT_PROBE)
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--libcuda-override", type=Path,
                        help="load this exact libcuda file instead of the system loader choice")
    parser.add_argument("--libcuda-sha256",
                        help="required SHA-256 pin for --libcuda-override")
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "evidence")
    parser.add_argument("--expected-pci", help="require one visible GPU at this PCI ID before creating a CUDA context")
    parser.add_argument("--expected-device", action="append", default=[], metavar="SM=PCI",
                        help="pin one hybrid target by compute capability and PCI ID; repeat for each required SM")
    parser.add_argument("--phase", choices=("initialize", "enumerate", "context", "allocation", "module", "kernel", "system-pageable-memory", "managed-accessed-by"),
                        help="run one isolated CUDA Driver API phase; system-pageable-memory tests direct malloc/mmap pointers")
    parser.add_argument("--managed-memory", action="store_true",
                        help="test cuMemAllocManaged on the selected GPU(s)")
    parser.add_argument("--managed-prefetch", action="store_true",
                        help="with --managed-memory, prefetch ranges to each GPU and back to the CPU")
    parser.add_argument("--cuda-graphs", action="store_true",
                        help="run two opt-in CUDA Graph replays of the numeric kernel per targeted GPU")
    parser.add_argument("--concurrent-kernels", action="store_true",
                        help="dispatch a bounded numeric workload from two host threads to the exact SM70/SM120 pair; this does not prove GPU timeline overlap")
    parser.add_argument("--peer-transfer", action="store_true",
                        help="query directional SM70/SM120 direct-access capability and verify bounded sync/async peer copies; this does not attest physical DMA routing")
    parser.add_argument("--benchmark", action="store_true",
                        help="run a bounded launch and pinned-copy reference; requires isolated --expected-pci")
    parser.add_argument("--benchmark-samples", type=int,
                        help="set both launch and transfer samples to N (9..1001); defaults are 9 and 7")
    parser.add_argument("--ioctl-observer", type=Path, help="own-child read-only syscall observer; requires a selected PCI guard")
    parser.add_argument("--gpu-id-info", action="store_true",
                        help="with --ioctl-observer, capture only the fixed GPU_GET_ID_INFO_V2 payload")
    parser.add_argument("--attached-ids", action="store_true",
                        help="with --ioctl-observer, capture only the fixed GPU_GET_ATTACHED_IDS payload")
    parser.add_argument("--probed-ids", action="store_true",
                        help="with --ioctl-observer, capture only the fixed GPU_GET_PROBED_IDS payload")
    parser.add_argument("--rm-control", action="store_true",
                        help="with --ioctl-observer, capture fixed RM_CONTROL headers without nested payloads")
    parser.add_argument("--rm-control-headers", action="store_true",
                        help="with --phase enumerate, capture all RM_CONTROL headers with handles redacted")
    parser.add_argument("--p2p-control", action="store_true",
                        help="with --rm-control, capture redacted fixed NV503C P2P control payloads")
    parser.add_argument("--binapi-control", action="store_true",
                        help="with --rm-control, capture redacted fixed NV2081_BINAPI payload-shape metadata")
    parser.add_argument("--device-alloc", action="store_true",
                        help="capture only fixed, redacted NV0080_ALLOC_PARAMETERS on NV01_DEVICE_0")
    parser.add_argument("--subdevice-alloc", action="store_true",
                        help="capture only the fixed, redacted NV2080_ALLOC_PARAMETERS subDeviceId")
    parser.add_argument("--binapi-alloc", action="store_true",
                        help="capture only the optional, redacted NV2081_ALLOC_PARAMETERS reserved-zero predicate")
    parser.add_argument("--gt200-debugger-alloc", action="store_true",
                        help="capture only the fixed, redacted NV83DE_ALLOC_PARAMETERS handle relations")
    parser.add_argument("--gt200-debugger-lifecycle", action="store_true",
                        help="capture redacted GT200_DEBUGGER allocations, frees, and fixed control headers")
    parser.add_argument("--gpu-path",
                        help="selected GPU descriptor for allocation captures (must be /dev/nvidia0)")
    parser.add_argument("--channel-alloc", action="store_true",
                        help="with --ioctl-observer, capture only redacted GPFIFO allocation parameters")
    parser.add_argument("--map-memory", action="store_true",
                        help="with --ioctl-observer, capture redacted fixed R580 MAP/UNMAP packets")
    parser.add_argument("--rusd-alloc", action="store_true",
                        help="with --ioctl-observer, capture only the redacted RM_USER_SHARED_DATA polling mask")
    parser.add_argument("--ioctl-trace", action="store_true",
                        help="trace ioctl metadata; with --phase enumerate/context, also trace NVIDIA node opens and descriptor lifecycle")
    parser.add_argument("--ioctl-trace-output", type=Path,
                        help="private raw strace output path; requires --ioctl-trace")
    parser.add_argument("--strace-binary", type=Path, default=Path("/usr/bin/strace"),
                        help="strace executable used only with --ioctl-trace")
    parser.add_argument("--trace-helper", type=Path, default=ROOT / "tools/summarize_rm_ioctl_trace.py",
                        help="capture and metadata parser helper")
    args = parser.parse_args()
    if args.benchmark_samples is not None and not 9 <= args.benchmark_samples <= 1001:
        parser.error("--benchmark-samples must be from 9 through 1001")
    if args.benchmark_samples is not None and not args.benchmark:
        parser.error("--benchmark-samples requires --benchmark")
    if (args.libcuda_override is None) != (args.libcuda_sha256 is None):
        parser.error("--libcuda-override requires --libcuda-sha256, and vice versa")
    libcuda_override = None
    libcuda_identity_before = None
    if args.libcuda_override is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", args.libcuda_sha256):
            parser.error("--libcuda-sha256 must be exactly 64 hexadecimal characters")
        try:
            libcuda_override = args.libcuda_override.resolve(strict=True)
            if not libcuda_override.is_file():
                raise ValueError("override is not a regular file")
            libcuda_identity_before = file_identity(libcuda_override)
        except (OSError, ValueError) as error:
            parser.error(f"cannot inspect --libcuda-override: {error}")
        if libcuda_identity_before["sha256"] != args.libcuda_sha256.lower():
            parser.error("--libcuda-override SHA-256 does not match --libcuda-sha256")
    expected_device_pci_by_sm = {}
    for value in args.expected_device:
        sm_text, separator, pci_text = value.partition("=")
        if not separator or not sm_text.isdigit():
            parser.error("--expected-device must use SM=PCI, for example 70=0000:03:00.0")
        sm = int(sm_text)
        try:
            pci = canonical_pci(pci_text)
        except ValueError:
            parser.error("--expected-device contains an invalid PCI ID")
        if (sm not in REQUIRED_SM or sm in expected_device_pci_by_sm or
                pci in expected_device_pci_by_sm.values()):
            parser.error("--expected-device must uniquely pin each required SM to a valid PCI ID")
        expected_device_pci_by_sm[sm] = pci
    if expected_device_pci_by_sm and set(expected_device_pci_by_sm) != set(REQUIRED_SM):
        parser.error("--expected-device must be supplied once for each required SM: 70 and 120")
    if args.concurrent_kernels and (
            set(expected_device_pci_by_sm) != set(REQUIRED_SM) or args.phase or
            args.expected_pci or args.managed_memory or args.managed_prefetch or
            args.cuda_graphs or args.benchmark or args.ioctl_observer or
            args.ioctl_trace):
        parser.error("--concurrent-kernels requires only the exact --expected-device pair 70 and 120")
    if args.peer_transfer and (
            set(expected_device_pci_by_sm) != set(REQUIRED_SM) or args.phase or
            args.expected_pci or args.benchmark):
        parser.error("--peer-transfer requires only the exact --expected-device pair 70 and 120")
    if args.expected_device and (args.phase or args.benchmark or args.expected_pci):
        parser.error("--expected-device is only for the full multi-device acceptance run")
    if args.benchmark and (
            args.expected_pci is None or args.phase or args.managed_memory or
            args.managed_prefetch or args.cuda_graphs or args.ioctl_observer is not None or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.rm_control_headers or args.p2p_control or args.binapi_control or
            args.device_alloc or args.subdevice_alloc or args.binapi_alloc or
            args.channel_alloc or args.map_memory or args.rusd_alloc or args.ioctl_trace):
        parser.error("--benchmark requires an isolated device-memory run with --expected-pci")
    enumerate_node_trace = args.phase == "enumerate" and args.ioctl_trace
    phase_ioctl_trace = args.phase in ("enumerate", "context", "managed-accessed-by") and args.ioctl_trace
    enumerate_rm_control_headers = args.phase == "enumerate" and args.rm_control_headers
    system_pageable_phase = args.phase == "system-pageable-memory"
    managed_accessed_by_phase = args.phase == "managed-accessed-by"
    phase_capture_mode = phase_ioctl_trace or enumerate_rm_control_headers or system_pageable_phase
    if (args.gt200_debugger_alloc or args.gt200_debugger_lifecycle) and (
            args.ioctl_observer is None or args.phase != "context"):
        parser.error("debugger capture requires --ioctl-observer with --phase context")
    if args.gt200_debugger_alloc and any((args.gpu_id_info, args.attached_ids, args.probed_ids,
            args.rm_control, args.rm_control_headers, args.p2p_control, args.binapi_control,
            args.device_alloc, args.subdevice_alloc, args.binapi_alloc, args.channel_alloc,
            args.map_memory, args.rusd_alloc, args.ioctl_trace, args.managed_memory,
            args.managed_prefetch, args.cuda_graphs)):
        parser.error("--gt200-debugger-alloc must be an isolated context observer capture")
    if args.gt200_debugger_lifecycle and any((args.gt200_debugger_alloc, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.rm_control, args.rm_control_headers,
            args.p2p_control, args.binapi_control, args.device_alloc, args.subdevice_alloc,
            args.binapi_alloc, args.channel_alloc, args.map_memory, args.rusd_alloc,
            args.ioctl_trace, args.managed_memory, args.managed_prefetch, args.cuda_graphs)):
        parser.error("--gt200-debugger-lifecycle must be an isolated context observer capture")
    if args.rm_control_headers and args.phase != "enumerate":
        parser.error("--rm-control-headers requires --phase enumerate")
    if args.rm_control_headers and args.ioctl_observer is None:
        parser.error("--rm-control-headers requires --ioctl-observer")
    if system_pageable_phase and (args.expected_pci is None or args.ioctl_observer is not None or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.rm_control_headers or args.p2p_control or args.binapi_control or args.device_alloc or
            args.subdevice_alloc or args.binapi_alloc or args.gt200_debugger_alloc or args.gt200_debugger_lifecycle or args.channel_alloc or args.map_memory or
            args.rusd_alloc or args.ioctl_trace or args.managed_memory or args.managed_prefetch or
            args.cuda_graphs):
        parser.error("--phase system-pageable-memory requires only --expected-pci and its numeric kernel")
    if managed_accessed_by_phase and (args.expected_pci is None or args.ioctl_observer is not None or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.rm_control_headers or args.p2p_control or args.binapi_control or args.device_alloc or
            args.subdevice_alloc or args.binapi_alloc or args.gt200_debugger_alloc or args.gt200_debugger_lifecycle or args.channel_alloc or args.map_memory or
            args.rusd_alloc or not args.ioctl_trace or args.managed_memory or args.managed_prefetch or
            args.cuda_graphs):
        parser.error("--phase managed-accessed-by requires only --expected-pci and its bounded ioctl trace")
    if args.phase and not phase_capture_mode and (args.expected_pci is None or args.ioctl_observer is None or
                       sum((args.binapi_control, args.device_alloc, args.subdevice_alloc,
                            args.binapi_alloc, args.gt200_debugger_alloc,
                            args.gt200_debugger_lifecycle)) != 1 or
                       (args.binapi_control and not args.rm_control)):
        parser.error("phase requires exactly one isolated BINAPI, NV01_DEVICE_0, NV20_SUBDEVICE_0, or NV2081_BINAPI allocation capture with --expected-pci and --ioctl-observer")
    if phase_ioctl_trace and (args.expected_pci is None or args.ioctl_observer is not None or
                                 args.gpu_id_info or args.attached_ids or args.probed_ids or
                                 args.rm_control or args.rm_control_headers or args.p2p_control or args.binapi_control or
                                 args.device_alloc or args.subdevice_alloc or args.binapi_alloc or args.gt200_debugger_alloc or args.gt200_debugger_lifecycle or
                                 args.channel_alloc or args.map_memory or args.rusd_alloc or
                                 args.managed_memory or args.managed_prefetch or args.cuda_graphs):
        parser.error("--phase enumerate/context/managed-accessed-by --ioctl-trace requires only --expected-pci and the bounded trace")
    if enumerate_rm_control_headers and (args.expected_pci is None or args.ioctl_observer is None or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.p2p_control or args.binapi_control or args.device_alloc or args.subdevice_alloc or
            args.binapi_alloc or args.gt200_debugger_alloc or args.gt200_debugger_lifecycle or args.channel_alloc or args.map_memory or args.rusd_alloc or
            args.ioctl_trace or args.managed_memory or args.managed_prefetch or args.cuda_graphs):
        parser.error("--phase enumerate --rm-control-headers requires only --expected-pci and the isolated observer")
    if args.phase and not phase_capture_mode and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                       args.p2p_control or args.channel_alloc or args.map_memory or
                       args.rusd_alloc or args.ioctl_trace or args.managed_memory or
                       args.managed_prefetch or args.cuda_graphs):
        parser.error("phase capture must be isolated with its selected observer")
    if args.gpu_path is not None and not (args.binapi_control or args.device_alloc or args.subdevice_alloc or args.binapi_alloc or args.gt200_debugger_alloc or args.gt200_debugger_lifecycle):
        parser.error("--gpu-path requires an allocation observer capture")
    if args.binapi_control or args.device_alloc or args.subdevice_alloc or args.binapi_alloc or args.gt200_debugger_alloc or args.gt200_debugger_lifecycle:
        args.gpu_path = args.gpu_path or "/dev/nvidia0"
        if args.gpu_path != "/dev/nvidia0":
            parser.error("selected allocation capture requires the /dev/nvidia0 descriptor")
    if args.ioctl_observer is not None and args.expected_pci is None:
        parser.error("--ioctl-observer requires --expected-pci")
    if args.gpu_id_info and args.ioctl_observer is None:
        parser.error("--gpu-id-info requires --ioctl-observer")
    if args.attached_ids and args.ioctl_observer is None:
        parser.error("--attached-ids requires --ioctl-observer")
    if args.probed_ids and args.ioctl_observer is None:
        parser.error("--probed-ids requires --ioctl-observer")
    if args.rm_control and args.ioctl_observer is None:
        parser.error("--rm-control requires --ioctl-observer")
    if args.p2p_control and args.ioctl_observer is None:
        parser.error("--p2p-control requires --ioctl-observer")
    if args.p2p_control and not args.rm_control:
        parser.error("--p2p-control requires --rm-control")
    if args.binapi_control and args.ioctl_observer is None:
        parser.error("--binapi-control requires --ioctl-observer")
    if args.binapi_control and not args.rm_control:
        parser.error("--binapi-control requires --rm-control")
    if args.device_alloc and args.ioctl_observer is None:
        parser.error("--device-alloc requires --ioctl-observer")
    if args.subdevice_alloc and args.ioctl_observer is None:
        parser.error("--subdevice-alloc requires --ioctl-observer")
    if args.binapi_alloc and args.ioctl_observer is None:
        parser.error("--binapi-alloc requires --ioctl-observer")
    if args.gt200_debugger_alloc and args.ioctl_observer is None:
        parser.error("--gt200-debugger-alloc requires --ioctl-observer")
    if args.gt200_debugger_lifecycle and args.ioctl_observer is None:
        parser.error("--gt200-debugger-lifecycle requires --ioctl-observer")
    if args.device_alloc and (args.binapi_control or args.subdevice_alloc or args.rm_control or args.p2p_control or
                              args.channel_alloc or args.map_memory or args.rusd_alloc or
                              args.gpu_id_info or args.attached_ids or args.probed_ids or
                              args.ioctl_trace or args.managed_memory or args.managed_prefetch):
        parser.error("--device-alloc must be an isolated observer capture mode")
    if args.subdevice_alloc and (args.binapi_control or args.device_alloc or args.rm_control or
                                 args.p2p_control or args.channel_alloc or args.map_memory or
                                 args.rusd_alloc or args.gpu_id_info or args.attached_ids or
                                 args.probed_ids or args.ioctl_trace or args.managed_memory or
                                 args.managed_prefetch):
        parser.error("--subdevice-alloc must be an isolated observer capture mode")
    if args.binapi_alloc and (args.binapi_control or args.device_alloc or args.subdevice_alloc or
                              args.rm_control or args.p2p_control or args.channel_alloc or
                              args.map_memory or args.rusd_alloc or args.gpu_id_info or
                              args.attached_ids or args.probed_ids or args.ioctl_trace or
                              args.managed_memory or args.managed_prefetch):
        parser.error("--binapi-alloc must be an isolated observer capture mode")
    if args.channel_alloc and args.ioctl_observer is None:
        parser.error("--channel-alloc requires --ioctl-observer")
    if args.map_memory and args.ioctl_observer is None:
        parser.error("--map-memory requires --ioctl-observer")
    if args.rusd_alloc and args.ioctl_observer is None:
        parser.error("--rusd-alloc requires --ioctl-observer")
    if args.channel_alloc and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                               args.rm_control or args.rusd_alloc):
        parser.error("--channel-alloc must run separately from other captures")
    if args.map_memory and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                            args.rm_control or args.channel_alloc):
        parser.error("--map-memory must run separately from other captures")
    if args.rusd_alloc and (args.gpu_id_info or args.attached_ids or args.probed_ids or
                            args.rm_control or args.channel_alloc or
                            args.ioctl_trace or args.managed_memory or args.managed_prefetch):
        parser.error("--rusd-alloc must be isolated from other captures except --map-memory")
    if args.p2p_control and (args.ioctl_trace or args.gpu_id_info or args.attached_ids or
                             args.probed_ids or args.channel_alloc or args.map_memory or
                             args.rusd_alloc or args.binapi_control or args.managed_memory or
                             args.managed_prefetch):
        parser.error("--p2p-control must be isolated with --rm-control")
        if args.binapi_control and (args.ioctl_trace or args.gpu_id_info or args.attached_ids or
                                args.probed_ids or args.p2p_control or args.channel_alloc or
                                args.map_memory or args.rusd_alloc or args.managed_memory or
                                args.managed_prefetch):
            parser.error("--binapi-control must be isolated with --rm-control")
    if args.ioctl_trace and args.expected_pci is None:
        parser.error("--ioctl-trace requires --expected-pci")
    if args.managed_prefetch and not args.managed_memory:
        parser.error("--managed-prefetch requires --managed-memory")
    if args.ioctl_trace_output is not None and not args.ioctl_trace:
        parser.error("--ioctl-trace-output requires --ioctl-trace")
    if args.trace_helper != ROOT / "tools/summarize_rm_ioctl_trace.py" and not args.ioctl_trace:
        parser.error("--trace-helper requires --ioctl-trace")
    if args.timeout <= 0 or (args.strict and args.allow_incomplete):
        parser.error("timeout must be positive; --strict cannot accompany --allow-incomplete")
    expected_pci = None
    if args.expected_pci is not None:
        try:
            expected_pci = canonical_pci(args.expected_pci)
        except ValueError as error:
            parser.error(str(error))
    probe = args.probe.resolve()
    module = args.module.resolve()
    if not probe.is_file() or not module.is_file():
        print("build the probe first with: python3 tools/build_probe.py", file=sys.stderr)
        return 64
    try:
        probe_build_trust_before = trusted_probe_build_identity(probe, module)
    except Exception as error:
        probe_build_trust_before = {
            "status": "untrusted",
            "reason": str(error)[:500],
        }
    if probe_build_trust_before.get("status") != "trusted-pinned-build":
        return write_probe_trust_preflight_rejection(
            args, probe, module, probe_build_trust_before)
    if args.concurrent_kernels:
        try:
            validate_probe_contract(
                probe, expected_sha256=file_identity(probe)["sha256"],
                require_exact_device_map=True, require_concurrent_dispatch=True)
        except ValueError as error:
            parser.error(f"concurrent-dispatch probe contract is incompatible: {error}")
    if args.peer_transfer:
        try:
            validate_probe_contract(
                probe, expected_sha256=file_identity(probe)["sha256"],
                require_exact_device_map=True, require_peer_transfer=True)
        except ValueError as error:
            parser.error(f"peer-transfer probe contract is incompatible: {error}")

    if args.phase:
        command = [str(probe), "--phase", args.phase, "--expected-pci", expected_pci]
        if args.phase in ("module", "kernel", "system-pageable-memory"):
            command += ["--module", str(module)]
    else:
        command = [str(probe), "--module", str(module), "--require-sm", "70,120"]
        for sm in REQUIRED_SM:
            if sm in expected_device_pci_by_sm:
                command += ["--expected-device", f"{sm}={expected_device_pci_by_sm[sm]}"]
        if args.managed_memory:
            command.append("--managed-memory")
        if args.managed_prefetch:
            command.append("--managed-prefetch")
        if args.cuda_graphs:
            command.append("--cuda-graphs")
        if args.concurrent_kernels:
            command.append("--concurrent-kernels")
        if args.peer_transfer:
            command.append("--peer-transfer")
        if args.benchmark:
            command.append("--benchmark")
            if args.benchmark_samples is not None:
                command += ["--benchmark-samples", str(args.benchmark_samples)]
        if expected_pci is not None:
            command += ["--expected-pci", expected_pci]
    if libcuda_override is not None:
        command += ["--libcuda", str(libcuda_override)]
    artifacts = {"probe": file_identity(probe), "module": file_identity(module),
                 "probe_build_trust_before": probe_build_trust_before}
    if libcuda_identity_before is not None:
        artifacts["libcuda_override_before_run"] = libcuda_identity_before
    observation = None
    observer = args.ioctl_observer.resolve(strict=True) if args.ioctl_observer is not None else None
    observation_path = None
    if observer is not None:
        args.evidence_dir.mkdir(parents=True, exist_ok=True)
        # A private directory reserves a new path without pre-creating the file:
        # the observer itself opens its report O_EXCL and owns its lifecycle.
        observation_path = Path(tempfile.mkdtemp(prefix="rm-observer-", dir=args.evidence_dir)) / "ioctl.json"
        artifacts["ioctl_observer"] = file_identity(observer)
        observer_command = [str(observer), "--output", str(observation_path)]
        if args.gpu_id_info:
            observer_command.append("--gpu-id-info")
        if args.attached_ids:
            observer_command.append("--attached-ids")
        if args.probed_ids:
            observer_command.append("--probed-ids")
        if args.rm_control:
            observer_command.append("--rm-control")
        if args.rm_control_headers:
            observer_command.append("--rm-control-headers")
        if args.p2p_control:
            observer_command.append("--p2p-control")
        if args.binapi_control:
            observer_command += ["--binapi-control", "--gpu-path", args.gpu_path]
        if args.device_alloc:
            observer_command += ["--device-alloc", "--gpu-path", args.gpu_path]
        if args.subdevice_alloc:
            observer_command += ["--subdevice-alloc", "--gpu-path", args.gpu_path]
        if args.binapi_alloc:
            observer_command += ["--binapi-alloc", "--gpu-path", args.gpu_path]
        if args.gt200_debugger_alloc:
            observer_command += ["--gt200-debugger-alloc", "--gpu-path", args.gpu_path]
        if args.gt200_debugger_lifecycle:
            observer_command += ["--gt200-debugger-lifecycle", "--gpu-path", args.gpu_path]
        if args.channel_alloc:
            observer_command += ["--channel-alloc", "--gpu-path", "/dev/nvidia0"]
        if args.map_memory:
            observer_command += ["--map-memory", "--gpu-path", "/dev/nvidia0"]
        if args.rusd_alloc:
            observer_command += ["--rusd-alloc", "--gpu-path", "/dev/nvidia0"]
        command = [*observer_command, "--", *command]
    timed_out = False
    trace_observation = None
    trace_helper = None
    trace_output_path = args.ioctl_trace_output
    if args.ioctl_trace:
        try:
            helper_path = args.trace_helper.resolve(strict=True)
            helper_loader = importlib.machinery.SourceFileLoader(
                "cuda_ioctl_trace_helper", str(helper_path))
            helper_spec = importlib.util.spec_from_loader(helper_loader.name, helper_loader)
            if helper_spec is None or helper_spec.loader is None:
                raise ImportError("unable to load ioctl trace helper")
            trace_helper = importlib.util.module_from_spec(helper_spec)
            helper_loader.exec_module(trace_helper)
            if trace_output_path is None:
                args.evidence_dir.mkdir(parents=True, exist_ok=True)
                trace_parent = Path(tempfile.mkdtemp(prefix="cuda-ioctl-trace-", dir=args.evidence_dir))
                trace_output_path = trace_parent / "ioctl.strace"
            trace_observation = {"helper": file_identity(helper_path),
                                 "requested_output_path": str(trace_output_path.resolve())}
            artifacts["ioctl_trace_helper"] = trace_observation["helper"]
        except (OSError, ImportError, ValueError) as error:
            trace_observation = {"trace_complete": False, "error": str(error)[:300]}
    try:
        if args.ioctl_trace:
            if trace_helper is None:
                raise RuntimeError("ioctl trace helper is unavailable; refusing an untraced CUDA run")
            node_trace = args.phase in ("enumerate", "context")
            capture_options = ({"syscalls": trace_helper.NODE_TRACE_SYSCALLS,
                                "summary_fn": trace_helper.summarize_node_open_trace}
                               if node_trace else {})
            captured = trace_helper.capture(str(args.strace_binary), str(trace_output_path), command,
                                           timeout=args.timeout, env=dict(os.environ),
                                           **capture_options)
            completed = subprocess.CompletedProcess(command, captured["exit_code"],
                                                    captured["stdout"], captured["stderr"])
            trace_observation.update({key: value for key, value in captured.items()
                                      if key != "raw_trace"})
            if (file_identity(args.strace_binary) !=
                    {"path": captured["strace_path"],
                     "bytes": args.strace_binary.resolve(strict=True).stat().st_size,
                     "sha256": captured["strace_sha256"]}):
                raise ValueError("strace binary changed during capture")
            if file_identity(args.trace_helper) != artifacts["ioctl_trace_helper"]:
                raise ValueError("ioctl trace helper changed during capture")
        else:
            completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, check=False, timeout=args.timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        decode = lambda value: value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
        completed = subprocess.CompletedProcess(command, 124, decode(error.stdout), decode(error.stderr))
    except OSError as error:
        completed = subprocess.CompletedProcess(command, 2, "", str(error))
    except (RuntimeError, ValueError, ImportError, PermissionError) as error:
        completed = subprocess.CompletedProcess(command, 2, "", str(error)[:1000])
        if args.ioctl_trace:
            trace_observation = trace_observation or {}
            trace_observation.update({"trace_complete": False, "error": str(error)[:300]})
    probe_report, validation_errors = None, []
    qualification = "invalid-probe-report"
    binapi_control_records_seen = None
    rm_control_headers_records_seen = None
    rm_control_headers_record_count = None
    binapi_payload_snapshots_read = None
    device_alloc_records_seen = None
    device_alloc_payload_snapshots_read = None
    subdevice_alloc_records_seen = None
    subdevice_alloc_payload_snapshots_read = None
    binapi_alloc_records_seen = None
    binapi_alloc_payload_snapshots_read = None
    gt200_debugger_alloc_records_seen = None
    gt200_debugger_alloc_payload_snapshots_read = None
    gt200_debugger_lifecycle_summary = None
    try:
        if observer is not None:
            observed = json.loads(observation_path.read_text())
            if not isinstance(observed, dict):
                raise ValueError("ioctl observer report must be a JSON object")
            observation = {"report": observed, "artifact": file_identity(observation_path)}
            p2p_snapshots = None
            if args.p2p_control:
                p2p_snapshots = observed.get("p2p_control_payload_snapshots_read")
                if type(p2p_snapshots) is not int or p2p_snapshots < 0:
                    raise ValueError("P2P control observation has no valid snapshot count")
            if args.binapi_control:
                (binapi_control_records_seen,
                 binapi_payload_snapshots_read) = validate_binapi_control_observation(observed)
            if args.device_alloc:
                (device_alloc_records_seen,
                 device_alloc_payload_snapshots_read) = validate_device_alloc_observation(observed)
            if args.subdevice_alloc:
                (subdevice_alloc_records_seen,
                 subdevice_alloc_payload_snapshots_read) = validate_subdevice_alloc_observation(observed)
            if args.binapi_alloc:
                (binapi_alloc_records_seen,
                 binapi_alloc_payload_snapshots_read) = validate_binapi_alloc_observation(observed)
            if args.gt200_debugger_alloc:
                (gt200_debugger_alloc_records_seen,
                 gt200_debugger_alloc_payload_snapshots_read) = validate_gt200_debugger_alloc_observation(observed)
            if args.gt200_debugger_lifecycle:
                gt200_debugger_lifecycle_summary = validate_gt200_debugger_lifecycle_observation(observed)
            expected_schema = ("nvidia-hybrid-rm-ioctl-observer-v39" if args.gt200_debugger_lifecycle else
                               "nvidia-hybrid-rm-ioctl-observer-v34" if args.gt200_debugger_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v23" if args.rm_control_headers else
                               "nvidia-hybrid-rm-ioctl-observer-v22" if args.map_memory and args.rusd_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v21" if args.binapi_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v20" if args.subdevice_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v19" if args.device_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v18" if args.binapi_control else
                               "nvidia-hybrid-rm-ioctl-observer-v17" if args.p2p_control else
                               "nvidia-hybrid-rm-ioctl-observer-v15" if args.map_memory else
                               "nvidia-hybrid-rm-ioctl-observer-v14" if args.rusd_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v9" if args.channel_alloc else
                               "nvidia-hybrid-rm-ioctl-observer-v6" if args.probed_ids else
                               "nvidia-hybrid-rm-ioctl-observer-v5" if args.rm_control else
                               "nvidia-hybrid-rm-ioctl-observer-v4" if args.attached_ids else
                               "nvidia-hybrid-rm-ioctl-observer-v3" if args.gpu_id_info else
                               "nvidia-hybrid-rm-ioctl-observer-v1")
            selected_scopes = []
            if args.gpu_id_info:
                selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2")
            if args.attached_ids:
                selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS")
            if args.probed_ids:
                selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_PROBED_IDS")
            if args.channel_alloc:
                expected_scope = ("VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed "
                                  "using the byte-identical pinned R580.178.04/R595.99.02 "
                                  "NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted")
            elif args.map_memory and args.rusd_alloc:
                expected_scope = (
                    "RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS fixed 8-byte polledDataMask only, "
                    "plus exact pinned R580 NVOS33/NVOS34 map packets and selected-file lifecycle "
                    "metadata; other allocation payloads and raw addresses/handles omitted")
            elif args.rusd_alloc:
                expected_scope = ("RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned "
                                  "8-byte polledDataMask; raw addresses and handles omitted")
            elif args.binapi_control and binapi_payload_snapshots_read:
                expected_scope = ("exact 992-byte top-level NV2081_BINAPI control payload for command "
                                  "0x20810108; no contained pointer is followed; raw bytes, addresses, "
                                  "and handles omitted")
            elif args.device_alloc:
                expected_scope = ("NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; "
                                  "client handles are relational booleans; internal VA addresses are omitted")
            elif args.subdevice_alloc:
                expected_scope = ("NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; "
                                  "handles omitted")
            elif args.binapi_alloc:
                expected_scope = ("NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; "
                                  "handles omitted")
            elif args.gt200_debugger_alloc:
                expected_scope = ("exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; "
                                  "emits handle presence and within-root class relations including the debuggee direct-parent class; "
                                  "raw handles and addresses omitted")
            elif args.gt200_debugger_lifecycle:
                expected_scope = ("exact NV83DE allocation parameters plus fixed NVOS54 headers for resolved GT200_DEBUGGER controls and unresolved 0x83de command candidates; only exact 4-byte exceptionMask for resolved 0x83de0309 controls is followed after fixed-size, non-null-pointer, and documented-bit checks; RM_FREE class resolution is root-scoped; a redacted hObject-to-prior-GT200_DEBUGGER-allocation equality is emitted; raw handles and addresses omitted")
            elif args.p2p_control and p2p_snapshots:
                expected_scope = ("exact NV503C register/unregister VA-space, register/unregister vidmem, and "
                                  "register-PID fixed parameter structures; raw addresses, handles, and "
                                  "VA-space tokens omitted")
            elif len(selected_scopes) == 1:
                expected_scope = "exact " + selected_scopes[0] + " payload only; addresses omitted"
            elif len(selected_scopes) == 2:
                expected_scope = "exact " + " and ".join(selected_scopes) + " payloads only; addresses omitted"
            elif len(selected_scopes) == 3:
                expected_scope = ("exact " + ", ".join(selected_scopes[:-1]) + ", and " +
                                  selected_scopes[-1] + " payloads only; addresses omitted")
            else:
                expected_scope = None
            scope_ok = observed.get("nested_pointer_scope") == expected_scope
            nested_requested = (args.gpu_id_info or args.attached_ids or args.probed_ids or
                                args.rusd_alloc or
                                args.device_alloc or
                                args.subdevice_alloc or
                                args.gt200_debugger_alloc or
                                (args.gt200_debugger_lifecycle and
                                 (gt200_debugger_lifecycle_summary["allocation_payload_snapshots"] > 0 or
                                  gt200_debugger_lifecycle_summary["exception_mask_payload_snapshots"] > 0)) or
                                (args.binapi_alloc and binapi_alloc_payload_snapshots_read > 0) or
                                (args.binapi_control and binapi_payload_snapshots_read > 0) or
                                (args.p2p_control and p2p_snapshots > 0))
            if args.channel_alloc:
                if (observed.get("gpu_path") != "/dev/nvidia0" or
                    observed.get("object_class_resolution_scope") !=
                    "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed"):
                    raise ValueError("channel observer did not capture both selected RM descriptor paths")
                snapshots = observed.get("channel_payload_snapshots_read")
                if type(snapshots) is not int or snapshots < 0:
                    raise ValueError("channel allocation observation has no nested-read count")
                nested_requested = nested_requested or snapshots > 0
            if args.map_memory and observed.get("gpu_path") != "/dev/nvidia0":
                raise ValueError("map-memory observer did not select the backend GPU descriptor")
            if args.map_memory and observed.get("object_class_resolution_scope") != (
                    "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed"):
                raise ValueError("map-memory observer omitted transient RM object-class tracking scope")
            if args.rusd_alloc and observed.get("gpu_path") != "/dev/nvidia0":
                raise ValueError("RUSD observer did not select the backend GPU descriptor")
            if args.binapi_control:
                payload_scope_ok = observed.get("payload_scope") == (
                    "RM_CONTROL headers plus exact 992-byte NV2081_BINAPI payload-shape metadata; "
                    "contained pointers are never followed; raw bytes, addresses, and handles omitted")
            elif args.device_alloc:
                payload_scope_ok = observed.get("payload_scope") == (
                    "NV01_DEVICE_0 fixed class parameters only; handles are redacted and internal VA addresses are omitted")
            elif args.subdevice_alloc:
                payload_scope_ok = observed.get("payload_scope") == (
                    "NV20_SUBDEVICE_0 fixed class parameters only; handles omitted")
            elif args.binapi_alloc:
                payload_scope_ok = observed.get("payload_scope") == (
                    "NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted")
            elif args.gt200_debugger_alloc:
                payload_scope_ok = observed.get("payload_scope") == (
                    "NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; "
                    "raw handles, pointers, and payload bytes omitted")
            elif args.gt200_debugger_lifecycle:
                payload_scope_ok = gt200_debugger_lifecycle_payload_scope_matches(observed)
            elif args.p2p_control:
                payload_scope_ok = observed.get("payload_scope") == (
                    "RM_CONTROL headers plus exact NV503C P2P control payloads; raw addresses, "
                    "handles, and VA-space tokens omitted; other nested parameter payloads omitted")
            elif args.rm_control_headers:
                payload_scope_ok = observed.get("payload_scope") == (
                    "fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted")
            elif args.rm_control and not nested_requested:
                payload_scope_ok = observed.get("payload_scope") == (
                    "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted")
            elif args.rm_control:
                payload_scope_ok = observed.get("payload_scope") == (
                    "RM_CONTROL headers plus explicitly selected fixed metadata payloads; other nested parameters omitted")
            elif args.map_memory and args.rusd_alloc:
                payload_scope_ok = observed.get("payload_scope") == (
                    "exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device "
                    "open/dup/close/mmap metadata, transient RM_ALLOC/RM_FREE class resolution, and "
                    "fixed RM_USER_SHARED_DATA 8-byte polling-mask snapshots only; addresses, paths, "
                    "and handles omitted")
            elif args.map_memory:
                payload_scope_ok = observed.get("payload_scope") == (
                    "exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device "
                    "open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; "
                    "no allocation payloads emitted; addresses, paths, and handles omitted")
            else:
                payload_scope_ok = "payload_scope" not in observed
            fd_lifecycle_scope_ok = (
                observed.get("fd_lifecycle_scope") ==
                "opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/"
                "fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; "
                "exec invalidates inherited IDs; io_uring and external fd injection are not tracked; "
                "VMA file references remain kernel-owned"
                if args.map_memory else "fd_lifecycle_scope" not in observed)
            if (observed.get("schema") != expected_schema or
                observed.get("trace_complete") is not True or observed.get("errors") != [] or
                observed.get("child_exit_code") != completed.returncode or
                observed.get("control_path") != "/dev/nvidiactl" or
                observed.get("nested_pointers_read") is not nested_requested or
                ((nested_requested or args.channel_alloc) and not scope_ok) or
                not payload_scope_ok or not fd_lifecycle_scope_ok or
                not isinstance(observed.get("records"), list)):
                raise ValueError("incomplete or inconsistent ioctl observation")
            if args.p2p_control:
                snapshots_seen = sum(
                    isinstance(row, dict) and isinstance(row.get(phase), dict) and
                    isinstance(row[phase].get("p2pControl"), dict)
                    for row in observed["records"] for phase in ("entry", "exit"))
                if snapshots_seen != p2p_snapshots or (p2p_snapshots and p2p_snapshots % 2):
                    raise ValueError("P2P control snapshot count does not match entry/exit records")
                if not p2p_snapshots and (nested_requested or "nested_pointer_scope" in observed):
                    raise ValueError("empty P2P control observation unexpectedly read nested payloads")
            if args.map_memory and observed.get("fd_identity_capture_complete") is not True:
                raise ValueError("map observation has incomplete selected-file identity tracking")
            if args.map_memory:
                validate_map_fd_lifecycle(observed["records"])
            if args.probed_ids:
                probed_rows = [row for row in observed["records"]
                               if isinstance(row, dict) and row.get("operation") == "gpu_probed_ids"]
                if not probed_rows:
                    raise ValueError("probed-ID observation contains no GPU_GET_PROBED_IDS record")
                direct_request, xfer_request = 0xc020462a, 0xc01046d3
                uint32_max = (1 << 32) - 1
                for row in probed_rows:
                    request = row.get("request")
                    expected_packet_size = 32 if request == direct_request else 16 if request == xfer_request else None
                    if (expected_packet_size is None or row.get("packet_size") != expected_packet_size or
                        type(row.get("syscall_return")) is not int):
                        raise ValueError("probed-ID observation has an invalid ioctl envelope")
                    for phase in ("entry", "exit"):
                        payload = row.get(phase)
                        if not isinstance(payload, dict):
                            raise ValueError("probed-ID observation is missing a fixed payload snapshot")
                        if (payload.get("command") != 0x214 or payload.get("params_size") != 384 or
                            type(payload.get("status")) is not int or
                            any(key in payload for key in ("params", "params_address", "xfer_payload_address"))):
                            raise ValueError("probed-ID observation differs from the pinned fixed ABI")
                        for key in ("gpuIds", "excludedGpuIds", "gpuFlags"):
                            values = payload.get(key)
                        if (not isinstance(values, list) or len(values) != 32 or
                            any(type(value) is not int or value < 0 or value > uint32_max
                                    for value in values)):
                                raise ValueError("probed-ID observation has an invalid 32-entry table")
            if args.rm_control_headers:
                uint32_max = (1 << 32) - 1
                records = observed.get("records")
                if not isinstance(records, list) or not records:
                    raise ValueError("RM_CONTROL header observation contains no header records")
                header_rows = [row for row in records
                               if isinstance(row, dict) and row.get("operation") == "rm_control_header"]
                if len(header_rows) != len(records):
                    raise ValueError("redacted RM_CONTROL header observation contains unexpected records")
                row_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                              "operation", "entry", "exit", "syscall_return"}
                header_fields = {"command", "flags", "params_size", "status",
                                 "hClientPresent", "hObjectPresent", "client_object_equal",
                                 "client_matches_prior_root_allocation",
                                 "object_matches_prior_root_allocation"}
                for row in header_rows:
                    if (set(row) != row_fields or type(row.get("tid")) is not int or
                            row["tid"] <= 0 or type(row.get("fd")) is not int or row["fd"] < 0 or
                            row.get("fd_role") != "control" or
                            (row.get("request"), row.get("packet_size")) not in
                            ((0xc020462a, 32), (0xc01046d3, 16)) or
                            type(row.get("syscall_return")) is not int):
                        raise ValueError("RM_CONTROL header has an invalid ioctl envelope")
                    for phase in ("entry", "exit"):
                        packet = row.get(phase)
                        if (not isinstance(packet, dict) or set(packet) != header_fields or
                                any(type(packet.get(key)) is not int or
                                    not 0 <= packet[key] <= uint32_max
                                    for key in ("command", "flags", "params_size", "status")) or
                                any(type(packet.get(key)) is not bool for key in (
                                    "hClientPresent", "hObjectPresent", "client_object_equal",
                                    "client_matches_prior_root_allocation",
                                    "object_matches_prior_root_allocation"))):
                            raise ValueError("RM_CONTROL header contains raw handles or nested payload data")
                rm_control_headers_records_seen = True
                rm_control_headers_record_count = len(header_rows)
            if args.channel_alloc:
                channel_rows = [row for row in observed["records"]
                                if isinstance(row, dict) and row.get("operation") == "channel_alloc"]
                if not channel_rows:
                    raise ValueError("channel allocation observation contains no GPFIFO allocation record")
                successful_channels = 0
                expected_snapshots = 0
                forbidden_payload_keys = {
                    "pAllocParms", "params_address", "xfer_payload_address", "hRoot",
                    "hObjectParent", "hObjectNew", "gpFifoOffset", "userdOffset",
                    "hContextShare", "hVASpace", "hUserdMemory", "hObjectError",
                    "hObjectBuffer", "hObjectEccError", "base", "cid",
                }
                for row in channel_rows:
                    if (row.get("request") != 0xc030462b or row.get("packet_size") != 48 or
                        type(row.get("syscall_return")) is not int):
                        raise ValueError("channel allocation observation has an invalid ioctl envelope")
                    for phase in ("entry", "exit"):
                        payload = row.get(phase)
                        if not isinstance(payload, dict) or forbidden_payload_keys.intersection(payload):
                            raise ValueError("channel allocation observation contains raw handles or addresses")
                        klass = payload.get("hClass")
                        channel = payload.get("channel")
                        size = payload.get("paramsSize")
                        state = payload.get("channelPayloadState")
                        if klass not in (0xc36f, 0xc96f) or payload.get("layout") != "NVOS64":
                            raise ValueError("channel allocation observation differs from the pinned R580 payload contract")
                        if (type(size) is not int or size < 0 or size > 0xffffffff or
                            payload.get("pAllocParmsPresent") is not True or
                            state != "r580-r595-class-layout-parsed" or
                            not isinstance(channel, dict) or
                            channel.get("classPayloadBytes") != 368 or
                            any(key in channel for key in forbidden_payload_keys)):
                            raise ValueError("channel payload differs from the pinned R580/R595 class layout")
                        expected_snapshots += 1
                    if row.get("syscall_return") == 0 and row["exit"].get("status") == 0:
                        successful_channels += 1
                if observed.get("channel_payload_snapshots_read") != expected_snapshots:
                    raise ValueError("channel payload snapshot count does not match entry/exit records")
                if successful_channels == 0:
                    raise ValueError("channel allocation observation contains no successful RM allocation")
            if args.rusd_alloc:
                records = observed["records"]
                if any(not isinstance(row, dict) for row in records):
                    raise ValueError("RUSD observer returned a non-object record")
                rusd_rows = [row for row in records if row.get("operation") == "rusd_alloc"]
                snapshots = observed.get("rusd_payload_snapshots_read")
                allowed_operations = {"rusd_alloc"}
                if args.map_memory:
                    allowed_operations.update({"fd_open", "fd_dup", "fd_close_range", "close",
                                               "mmap", "map_memory", "unmap_memory"})
                if (type(snapshots) is not int or snapshots != 2 * len(rusd_rows) or
                    any(row.get("operation") not in allowed_operations for row in records) or
                    (not args.map_memory and len(rusd_rows) != len(records))):
                    raise ValueError("RUSD payload snapshot count or selected class scope is invalid")
                record_keys = {"tid", "fd", "fd_role", "request", "packet_size",
                               "operation", "entry", "exit", "syscall_return"}
                if args.map_memory:
                    record_keys.add("fd_file_id")
                packet_keys = {"layout", "hClass", "paramsSize", "flags", "status",
                               "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                               "pAllocParmsPresent", "pRightsRequestedPresent",
                               "rusdPayloadState", "rusd"}
                masks = []
                for row in rusd_rows:
                    if (set(row) != record_keys or type(row.get("tid")) is not int or
                        row["tid"] <= 0 or type(row.get("fd")) is not int or row["fd"] < 0 or
                        row.get("fd_role") not in ("control", "gpu") or
                        row.get("request") != 0xc030462b or row.get("packet_size") != 48 or
                        row.get("syscall_return") != 0):
                        raise ValueError("RUSD allocation transport failed or contains unexpected fields")
                    phase_masks = []
                    for phase in ("entry", "exit"):
                        packet = row.get(phase)
                        if (not isinstance(packet, dict) or set(packet) != packet_keys or
                            packet.get("layout") != "NVOS64" or packet.get("hClass") != 0xde or
                            type(packet.get("paramsSize")) is not int or packet["paramsSize"] != 0 or
                            type(packet.get("flags")) is not int or
                            type(packet.get("status")) is not int or packet["status"] != 0 or
                            any(type(packet.get(key)) is not bool for key in
                                ("hRootPresent", "hObjectParentPresent", "hObjectNewPresent")) or
                            packet.get("pAllocParmsPresent") is not True or
                            packet.get("pRightsRequestedPresent") is not False or
                            packet.get("rusdPayloadState") != "r580-r595-class-layout-parsed"):
                            raise ValueError("RUSD allocation payload does not match the pinned class layout")
                        payload = packet.get("rusd")
                        if (not isinstance(payload, dict) or set(payload) !=
                            {"classPayloadBytes", "polledDataMask"} or
                            payload.get("classPayloadBytes") != 8 or
                            type(payload.get("polledDataMask")) is not int or
                            not 0 <= payload["polledDataMask"] <= 0xffffffffffffffff):
                            raise ValueError("RUSD payload is malformed or exposes unapproved data")
                        phase_masks.append(payload["polledDataMask"])
                    if phase_masks[0] != phase_masks[1]:
                        raise ValueError("RUSD polling mask changed between entry and exit snapshots")
                    masks.append(phase_masks[0])
            if args.map_memory:
                map_rows = [row for row in observed["records"]
                            if isinstance(row, dict) and row.get("operation") == "map_memory"]
                unmap_rows = [row for row in observed["records"]
                              if isinstance(row, dict) and row.get("operation") == "unmap_memory"]
                mmap_rows = [row for row in observed["records"]
                             if isinstance(row, dict) and row.get("operation") == "mmap"]
                close_rows = [row for row in observed["records"]
                              if isinstance(row, dict) and row.get("operation") == "close"]
                forbidden_map_keys = {
                    "params_address", "xfer_payload_address", "linear_address",
                    "pLinearAddress", "hClient", "hDevice", "hMemory", "offset",
                }
                map_payload_keys = {"length", "status", "flags", "hClientPresent",
                    "hDevicePresent", "hMemoryPresent", "offsetNonzero",
                    "linearAddressPresent", "memoryObjectClass", "backendFd",
                    "backendFdRole", "backendFileId"}
                class_resolution_counts: dict[str, int] = {}
                class_ids: set[int] = set()
                successful_maps = 0
                successful_unmaps = 0
                for row in map_rows:
                    if (row.get("request") != 0xc038464e or row.get("packet_size") != 56 or
                        row.get("fd_role") != "control" or
                        type(row.get("syscall_return")) is not int):
                        raise ValueError("map observation has an invalid NVOS33 ioctl envelope")
                    for phase in ("entry", "exit"):
                        payload = row.get(phase)
                        if (not isinstance(payload, dict) or forbidden_map_keys.intersection(payload) or
                            set(payload) != map_payload_keys):
                            raise ValueError("map observation contains raw handles or addresses")
                        class_ref = payload.get("memoryObjectClass")
                        if (not isinstance(class_ref, dict) or
                            set(class_ref) != {"resolution", "classId"} or
                            class_ref.get("resolution") not in
                            ("absent", "resolved", "not-observed-live-object", "invalid-root", "ambiguous") or
                            (class_ref.get("resolution") == "resolved" and
                             (type(class_ref.get("classId")) is not int or
                              not 0 < class_ref["classId"] <= 0xffffffff)) or
                            (class_ref.get("resolution") != "resolved" and
                             class_ref.get("classId") is not None)):
                            raise ValueError("map observation has invalid memory-object class metadata")
                        if (type(payload.get("length")) is not int or payload["length"] < 0 or
                            type(payload.get("status")) is not int or
                            type(payload.get("flags")) is not int or
                            type(payload.get("backendFd")) is not int or payload["backendFd"] < 0 or
                            any(type(payload.get(key)) is not bool for key in (
                                "hClientPresent", "hDevicePresent", "hMemoryPresent",
                                "offsetNonzero", "linearAddressPresent")) or
                            payload.get("backendFdRole") not in ("control", "gpu", "other", "unknown")):
                            raise ValueError("map observation differs from the pinned NVOS33 payload contract")
                    entry_class = row["entry"]["memoryObjectClass"]
                    if entry_class != row["exit"]["memoryObjectClass"]:
                        raise ValueError("map observation changed memory-object class during ioctl")
                    resolution = entry_class["resolution"]
                    class_resolution_counts[resolution] = class_resolution_counts.get(resolution, 0) + 1
                    if resolution == "resolved":
                        class_ids.add(entry_class["classId"])
                    if (row["syscall_return"] == 0 and row["exit"].get("status") == 0 and
                        row["exit"].get("backendFdRole") == "gpu" and
                        row["exit"].get("linearAddressPresent") is True and
                        type(row["entry"].get("backendFd")) is int and
                        row["entry"].get("backendFd") == row["exit"].get("backendFd")):
                        successful_maps += 1
                for row in unmap_rows:
                    if (row.get("request") != 0xc020464f or row.get("packet_size") != 32 or
                        row.get("fd_role") != "control" or
                        type(row.get("syscall_return")) is not int):
                        raise ValueError("unmap observation has an invalid NVOS34 ioctl envelope")
                    for phase in ("entry", "exit"):
                        payload = row.get(phase)
                        if not isinstance(payload, dict) or forbidden_map_keys.intersection(payload):
                            raise ValueError("unmap observation contains raw handles or addresses")
                        if (type(payload.get("status")) is not int or
                            type(payload.get("flags")) is not int or
                            any(type(payload.get(key)) is not bool for key in (
                                "hClientPresent", "hDevicePresent", "hMemoryPresent",
                                "linearAddressPresent"))):
                            raise ValueError("unmap observation differs from the pinned NVOS34 payload contract")
                    if row["syscall_return"] == 0 and row["exit"].get("status") == 0:
                        successful_unmaps += 1
                if not map_rows or not unmap_rows or not successful_maps or not successful_unmaps:
                    raise ValueError("map observation contains no successful control-to-GPU map/unmap pair")
                for row in mmap_rows:
                    entry = row.get("entry")
                    if (row.get("request") != 9 or row.get("packet_size") != 0 or
                        row.get("fd_role") not in ("control", "gpu") or
                        row.get("syscall_return") is not None or row.get("exit") is not None or
                        type(row.get("mmap_succeeded")) is not bool or
                        not isinstance(entry, dict) or set(entry) != {"length", "prot", "flags", "offsetZero"} or
                        type(entry.get("length")) is not int or entry["length"] <= 0 or
                        type(entry.get("prot")) is not int or type(entry.get("flags")) is not int or
                        type(entry.get("offsetZero")) is not bool):
                        raise ValueError("mmap observation contains invalid or unredacted syscall metadata")
                for row in close_rows:
                    if (row.get("request") != 3 or row.get("packet_size") != 0 or
                        row.get("fd_role") not in ("control", "gpu") or
                        row.get("entry") is not None or row.get("exit") is not None or
                        type(row.get("syscall_return")) is not int or
                        type(row.get("close_succeeded")) is not bool or
                        row.get("close_succeeded") != (row.get("syscall_return") == 0)):
                        raise ValueError("close observation contains invalid descriptor-lifecycle metadata")
                successful_mmaps = correlated_gpu_mmap_count(observed["records"])
                if successful_mmaps == 0:
                    raise ValueError("map observation contains no successful mmap on the mapped GPU descriptor")
                map_memory_class_resolution_counts = dict(sorted(class_resolution_counts.items()))
                map_memory_class_ids = sorted(class_ids)
            else:
                map_memory_class_resolution_counts = None
                map_memory_class_ids = None
            if file_identity(observer) != artifacts["ioctl_observer"]:
                raise ValueError("ioctl observer changed during execution")
        probe_report = json.loads(completed.stdout)
        if args.phase:
            if args.phase == "system-pageable-memory":
                qualification = validate_system_pageable_memory_report(
                    probe_report, completed.returncode, expected_pci)
            else:
                qualification = validate_phase_probe_report(
                    probe_report, completed.returncode, expected_pci, args.phase)
        else:
            qualification = validate_probe_report(
                probe_report, completed.returncode,
                expected_memory_mode="managed" if args.managed_memory else "device",
                expected_managed_prefetch=args.managed_prefetch,
                expected_cuda_graphs=args.cuda_graphs,
                expected_performance_benchmark=args.benchmark,
                expected_device_pci_by_sm=expected_device_pci_by_sm or None,
                expected_concurrent_dispatch=args.concurrent_kernels,
                expected_peer_transfer=args.peer_transfer,
                expected_benchmark_samples=(
                    (args.benchmark_samples or 9) if args.benchmark else None),
                expected_benchmark_transfer_samples=(
                    (args.benchmark_samples or 7) if args.benchmark else None))
        if expected_pci is not None and not args.phase:
            devices = probe_report["devices"]
            if len(devices) != 1 or canonical_pci(devices[0]["pci_bus_id"]) != expected_pci:
                raise ValueError("selected GPU report does not match expected PCI identity/cardinality")
        driver_library = Path(probe_report["driver_library_path"])
        if libcuda_override is not None:
            if driver_library.resolve(strict=True) != libcuda_override:
                raise ValueError("probe loaded a CUDA driver library other than the pinned override")
            libcuda_identity_after = file_identity(libcuda_override)
            artifacts["libcuda_override_after_run"] = libcuda_identity_after
            if libcuda_identity_after != libcuda_identity_before:
                raise ValueError("pinned CUDA driver library identity changed during execution")
            artifacts["driver_library_observed_after_run"] = libcuda_identity_after
        else:
            artifacts["driver_library_observed_after_run"] = file_identity(driver_library)
        for label, path in (("probe", probe), ("module", module)):
            if file_identity(path) != artifacts[label]:
                raise ValueError(f"{label} changed during execution")
        try:
            probe_build_trust_after = trusted_probe_build_identity(probe, module)
        except Exception as error:
            probe_build_trust_after = {
                "status": "untrusted",
                "reason": str(error)[:500],
            }
        if probe_build_trust_before.get("status") == "trusted-pinned-build" and (
                probe_build_trust_after != probe_build_trust_before):
            raise ValueError("pinned probe build identity changed during execution")
    except (ValueError, OSError) as error:
        validation_errors.append(str(error))
        qualification = "invalid-probe-report"
        probe_build_trust_after = {
            "status": "untrusted",
            "reason": str(error)[:500],
        }
    report_contract_qualification = qualification
    if timed_out:
        qualification = "timeout"
    if args.ioctl_trace and (not isinstance(trace_observation, dict) or
                             trace_observation.get("trace", {}).get("trace_complete") is not True):
        validation_errors.append("ioctl trace is missing, incomplete, or over its limit")
        qualification = "invalid-ioctl-trace"
    probe_build_trusted = (
        probe_build_trust_before.get("status") == "trusted-pinned-build" and
        probe_build_trust_after == probe_build_trust_before and
        probe_build_trust_before.get("probe_sha256") == RELEASE_PINNED_PROBE_SHA256 and
        probe_build_trust_before.get("module_sha256") == RELEASE_PINNED_MODULE_SHA256
    )
    if qualification in SUCCESSFUL_REPORT_QUALIFICATIONS and not probe_build_trusted:
        validation_errors.append(
            "successful report requires the source-verified, hash-pinned probe and matching fatbin"
        )
        qualification = "untrusted-probe-artifact"

    probed_ids_records_seen = None
    p2p_control_records_seen = None
    p2p_control_payload_snapshots_read = None
    channel_alloc_records_seen = None
    rusd_alloc_records_seen = None
    rusd_polled_data_masks = None
    map_memory_records_seen = None
    map_memory_success_count = None
    unmap_memory_success_count = None
    map_memory_mmap_success_count = None
    map_memory_gpu_fd_close_count = None
    map_memory_class_resolution_counts = None
    map_memory_class_ids = None
    if isinstance(observation, dict) and isinstance(observation.get("report"), dict):
        rows = observation["report"].get("records", [])
        if isinstance(rows, list):
            p2p_control_records_seen = any(
                isinstance(row, dict) and isinstance(row.get("entry"), dict) and
                isinstance(row["entry"].get("p2pControl"), dict)
                for row in rows)
            if args.p2p_control and isinstance(observation.get("report"), dict):
                p2p_control_payload_snapshots_read = observation["report"].get(
                    "p2p_control_payload_snapshots_read")
            probed_ids_records_seen = any(
                isinstance(row, dict) and row.get("operation") == "gpu_probed_ids"
                for row in rows)
            channel_alloc_records_seen = any(
                isinstance(row, dict) and row.get("operation") == "channel_alloc"
                for row in rows)
            if args.rusd_alloc:
                rusd_rows = [row for row in rows if isinstance(row, dict) and
                             row.get("operation") == "rusd_alloc"]
                rusd_alloc_records_seen = bool(rusd_rows)
                rusd_polled_data_masks = [row["entry"]["rusd"]["polledDataMask"]
                                          for row in rusd_rows]
            map_memory_records_seen = any(
                isinstance(row, dict) and row.get("operation") in
                ("map_memory", "unmap_memory") for row in rows)
            map_memory_success_count = sum(
                row.get("operation") == "map_memory" and row.get("syscall_return") == 0 and
                isinstance(row.get("exit"), dict) and row["exit"].get("status") == 0 and
                row["exit"].get("backendFdRole") == "gpu" and
                row["exit"].get("linearAddressPresent") is True
                for row in rows if isinstance(row, dict))
            unmap_memory_success_count = sum(
                row.get("operation") == "unmap_memory" and row.get("syscall_return") == 0 and
                isinstance(row.get("exit"), dict) and row["exit"].get("status") == 0
                for row in rows if isinstance(row, dict))
            map_memory_mmap_success_count = correlated_gpu_mmap_count(rows)
            map_memory_gpu_fd_close_count = sum(
                row.get("operation") == "close" and row.get("fd_role") == "gpu" and
                row.get("close_succeeded") is True for row in rows if isinstance(row, dict))
            if args.map_memory:
                class_counts: dict[str, int] = {}
                class_ids: set[int] = set()
                for row in rows:
                    if not isinstance(row, dict) or row.get("operation") != "map_memory":
                        continue
                    payload = row.get("entry")
                    if not isinstance(payload, dict):
                        continue
                    class_ref = payload.get("memoryObjectClass")
                    if not isinstance(class_ref, dict):
                        continue
                    resolution = class_ref["resolution"]
                    class_counts[resolution] = class_counts.get(resolution, 0) + 1
                    if resolution == "resolved":
                        class_ids.add(class_ref["classId"])
                map_memory_class_resolution_counts = dict(sorted(class_counts.items()))
                map_memory_class_ids = sorted(class_ids)

    timestamp = datetime.now(timezone.utc)
    evidence = {
        "schema": "nvidia-hybrid-hardware-acceptance-v2",
        "observed_at_utc": timestamp.isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "kernel_release": os.uname().release,
        "command": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "probe": probe_report,
        "artifacts": artifacts,
        "probe_build_trust": {
            "status": "trusted-pinned-build" if probe_build_trusted else "untrusted",
            "before_run": probe_build_trust_before,
            "after_run": probe_build_trust_after,
        },
        "ioctl_observation": observation,
        "ioctl_trace": trace_observation,
        "gpu_id_info_capture_requested": args.gpu_id_info,
        "attached_ids_capture_requested": args.attached_ids,
        "probed_ids_capture_requested": args.probed_ids,
        "probed_ids_records_seen": probed_ids_records_seen,
        "p2p_control_capture_requested": args.p2p_control,
        "p2p_control_records_seen": p2p_control_records_seen,
        "p2p_control_payload_snapshots_read": p2p_control_payload_snapshots_read,
        "channel_alloc_capture_requested": args.channel_alloc,
        "channel_alloc_records_seen": channel_alloc_records_seen,
        "rusd_alloc_capture_requested": args.rusd_alloc,
        "rusd_alloc_records_seen": rusd_alloc_records_seen,
        "rusd_polled_data_masks": rusd_polled_data_masks,
        "map_memory_capture_requested": args.map_memory,
        "map_memory_records_seen": map_memory_records_seen,
        "map_memory_success_count": map_memory_success_count,
        "map_memory_mmap_success_count": map_memory_mmap_success_count,
        "map_memory_gpu_fd_close_count": map_memory_gpu_fd_close_count,
        "map_memory_class_resolution_counts": map_memory_class_resolution_counts,
        "map_memory_class_ids": map_memory_class_ids,
        "unmap_memory_success_count": unmap_memory_success_count,
        "rm_control_capture_requested": args.rm_control,
        "rm_control_headers_capture_requested": args.rm_control_headers,
        "rm_control_headers_records_seen": rm_control_headers_records_seen,
        "rm_control_headers_record_count": rm_control_headers_record_count,
        "binapi_control_capture_requested": args.binapi_control,
        "device_alloc_capture_requested": args.device_alloc,
        "phase_capture_requested": args.phase is not None,
        "phase": args.phase,
        "binapi_control_records_seen": binapi_control_records_seen,
        "binapi_payload_snapshots_read": binapi_payload_snapshots_read,
        "device_alloc_records_seen": device_alloc_records_seen,
        "device_alloc_payload_snapshots_read": device_alloc_payload_snapshots_read,
        "subdevice_alloc_capture_requested": args.subdevice_alloc,
        "subdevice_alloc_records_seen": subdevice_alloc_records_seen,
        "subdevice_alloc_payload_snapshots_read": subdevice_alloc_payload_snapshots_read,
        "binapi_alloc_capture_requested": args.binapi_alloc,
        "binapi_alloc_records_seen": binapi_alloc_records_seen,
        "binapi_alloc_payload_snapshots_read": binapi_alloc_payload_snapshots_read,
        "gt200_debugger_alloc_capture_requested": args.gt200_debugger_alloc,
        "gt200_debugger_alloc_records_seen": gt200_debugger_alloc_records_seen,
        "gt200_debugger_alloc_payload_snapshots_read": gt200_debugger_alloc_payload_snapshots_read,
        "gt200_debugger_lifecycle_capture_requested": args.gt200_debugger_lifecycle,
        "gt200_debugger_lifecycle": gt200_debugger_lifecycle_summary,
        "validation_errors": validation_errors,
        "report_contract_qualification": report_contract_qualification,
        "qualification": qualification,
        "device_selection": {"expected_pci_bus_id": expected_pci,
                             **record_cuda_selection_environment()},
        "memory_mode": "managed" if args.managed_memory else "device",
        "managed_prefetch_requested": args.managed_prefetch,
        "cuda_graphs_requested": args.cuda_graphs,
        "performance_benchmark_requested": args.benchmark,
        "peer_transfer_requested": args.peer_transfer,
    }
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = args.evidence_dir / (
        f"hardware-probe-{socket.gethostname()}-"
        f"{timestamp.strftime('%Y%m%dT%H%M%S%fZ')}.json"
    )
    with evidence_path.open("x") as stream:
        stream.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, sort_keys=True))
    if timed_out:
        return 124
    if qualification == "invalid-ioctl-trace":
        return 2
    if qualification == "invalid-probe-report":
        return 2
    if qualification == "untrusted-probe-artifact":
        return 2
    if args.allow_incomplete and qualification == "incomplete-hardware-missing":
        return 0
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
