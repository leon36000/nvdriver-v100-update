#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run process-local SYSTEM_GET_FEATURES sensitivity probes on PC3's V100 guest.

The experimental LD_PRELOAD shim changes only successful fixed four-byte
answers in short-lived CUDA processes. Workloads are CUDA enumeration or one
bounded SM70 context/kernel test. No module, firmware, PCI binding, VM, or
persistent driver state is changed.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SOURCE = ROOT / "src/system_features_mask_override.c"
UPSTREAM = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
INCLUDE_PARTS = (
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    "src/nvidia/arch/nvalloc/unix/include",
    "kernel-open/common/inc",
)
MASKS = (9, 8, 1, 0)
EXPECTED_HOST = "pc3-v100"
EXPECTED_KERNEL = "6.8.0-147-generic"
EXPECTED_GPU_UUID = "GPU-42d06a85-027a-75ea-7857-a8de27ad465e"
EXPECTED_PCI = "0000:00:05.0"
EXPECTED_DRIVER = "580.178.04"
EXPECTED_LIBCUDA = "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04"
EXPECTED_LIBCUDA_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
EXPECTED_LIBCUDA_SIZE = 96_284_520
KERNEL_PROBE_SOURCE = ROOT / "src/system_features_sm70_kernel_probe.py"
KERNEL_PROBE_SOURCE_SHA256 = "d90f6cce9f46031d4f1c42c23cb6e21c57689633b1a88bc63edfd220d066b596"
KERNEL_SM70_CUBIN = ROOT / "build/probe-mask-kernel-current-v1-20261027/hybrid_probe.sm70.cubin"
KERNEL_SM70_CUBIN_SHA256 = "8e175174646caaabd3590d13f6bc0d3269708a9c07246c409e62e5d7c967ad50"
IPC_PROBE_SOURCE = ROOT / "src/system_features_ipc_memory_probe.py"
IPC_PROBE_SOURCE_SHA256 = "c24666e1bbfacce48520f4b81ccfd6bbd249d1fbde7194dab1a3650f4c5e5439"
VMM_FABRIC_PROBE_SOURCE = ROOT / "src/system_features_vmm_fabric_probe.py"
VMM_FABRIC_PROBE_SOURCE_SHA256 = "b7a903bf0dcad5f925ddc04fa1108b22b980a2a023c2998678ceb30e38be58a3"
TRACE_AUDIT_TOOL = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
TRACE_AUDIT_TOOL_SHA256 = "d26e632dd8c61d9fa187927b73290bd32ce6b567357549cb6f32b6c582931fe0"
REFERENCE_TOOL = ROOT / "tools/run_pc3_v100_guest_reference.py"
REFERENCE_TOOL_SHA256 = "d0028ad31c74cf43198ffbecd10be0df8d2dd04e890202d07386a2f946da7574"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_pci(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    import re
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match or int(match.group(3), 16) > 31:
        return None
    return (f"{int(match.group(1), 16) & 0xffff:04x}:"
            f"{int(match.group(2), 16):02x}:{int(match.group(3), 16):02x}."
            f"{int(match.group(4))}")


def validate_guest_sensitivity(report: object) -> dict[str, object]:
    """Validate identity, scope, exact mask delivery, and preserve CUDA outcomes."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-hybrid-v100-system-features-sensitivity-guest-v1",
            "unsupported V100 sensitivity report")
    if report.get("status") is not None:
        require(report.get("status") == "observed", "guest did not complete the bounded observation")
    if report.get("temporary_payload_remaining") is not None:
        require(report.get("temporary_payload_remaining") is False,
                "temporary experiment payload was not cleaned up")
    require(report.get("hostname") == EXPECTED_HOST and
            report.get("kernel_release") == EXPECTED_KERNEL,
            "V100 guest identity differs from the pinned test target")
    capture_caller_chain = report.get("caller_chain_capture_requested", False)
    require(type(capture_caller_chain) is bool,
            "caller chain capture request must be a boolean")
    capture_gpu_name_callers = report.get("gpu_name_caller_trace_requested", False)
    require(type(capture_gpu_name_callers) is bool,
            "GPU name caller trace request must be a boolean")
    gpu = report.get("gpu")
    require(isinstance(gpu, dict) and isinstance(gpu.get("name"), str) and
            gpu["name"].startswith("Tesla V100") and
            gpu.get("uuid") == EXPECTED_GPU_UUID and
            canonical_pci(gpu.get("pci")) == EXPECTED_PCI and
            gpu.get("driver_version") == EXPECTED_DRIVER,
            "guest GPU identity is not the pinned R580 Tesla V100")
    libcuda = report.get("libcuda")
    require(isinstance(libcuda, dict) and libcuda.get("path") == EXPECTED_LIBCUDA and
            libcuda.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
            type(libcuda.get("driver_api")) is int and libcuda["driver_api"] == 13000,
            "libcuda identity differs from the pinned R580 reference")
    require(report.get("gpu_compute_processes_before") == [] and
            report.get("gpu_compute_processes_after") == [] and
            report.get("cleanup_passed") is True and
            report.get("driver_or_module_changed") is False and
            report.get("gpu_reset_requested") is False,
            "execution scope or cleanup invariant failed")
    scope = report.get("execution_scope")
    if scope is not None:
        require(isinstance(scope, dict) and scope.get("read_only") is True and
                all(scope.get(key) is False for key in (
                    "experimental_module_loaded", "stock_driver_changed",
                    "pci_binding_changed", "vm_management_issued",
                    "gpu_reset_requested")),
                "execution scope contains a prohibited system change")

    complete = True
    gpu_name_signatures = []
    gpu_name_stage_signatures = []

    def validate_gpu_name_stage_counts(cuda: object, record_count: int) -> list[tuple[str, int]]:
        stages = ("before_libcuda_load", "after_libcuda_load", "after_cu_init",
                  "after_cu_driver_get_version", "after_cu_device_get_count",
                  "after_cu_device_get", "after_cu_device_get_name")
        require(isinstance(cuda, dict) and
                isinstance(cuda.get("gpu_name_trace_stage_counts"), list),
                "GPU name API-stage trace is missing")
        rows = cuda["gpu_name_trace_stage_counts"]
        require(len(rows) == len(stages), "GPU name API-stage trace is incomplete")
        counts = []
        for expected_stage, row in zip(stages, rows):
            require(isinstance(row, dict) and set(row) == {"stage", "records"} and
                    row.get("stage") == expected_stage and
                    type(row.get("records")) is int and row["records"] >= 0,
                    "GPU name API-stage trace is malformed")
            counts.append(row["records"])
        require(counts[0] == 0 and counts == sorted(counts) and counts[-1] == record_count,
                "GPU name API-stage counts do not match the caller records")
        return list(zip(stages[1:], [current - previous
                                     for previous, current in zip(counts, counts[1:])]))

    def validate_gpu_name_records(records: object) -> tuple[list[tuple[object, ...]], bool]:
        require(isinstance(records, list) and bool(records),
                "GPU name caller trace is missing")
        signatures = []
        resolved = True
        for record in records:
            require(isinstance(record, dict) and set(record) == {
                "command", "transport", "flags", "params_size", "ioctl_result",
                "embedded_status", "caller_image", "caller_offset",
                "caller_chain_offsets", "caller_chain_anchor_found",
                "caller_chain_truncated"},
                "GPU name caller trace is malformed or unredacted")
            require(record.get("command") == "0x20800110" and
                    record.get("transport") in ("direct", "xfer") and
                    type(record.get("flags")) is int and record["flags"] == 0 and
                    type(record.get("params_size")) is int and record["params_size"] == 132 and
                    type(record.get("ioctl_result")) is int and record["ioctl_result"] == 0 and
                    type(record.get("embedded_status")) is int and record["embedded_status"] == 0,
                    "GPU name trace does not match a successful R580 RM control")
            image = record.get("caller_image")
            offset = record.get("caller_offset")
            require(isinstance(image, str) and
                    re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", image) is not None and
                    ((image == "unresolved" and offset is None) or
                     (image != "unresolved" and isinstance(offset, str) and
                      re.fullmatch(r"0x[0-9a-f]+", offset) is not None and
                      0 < int(offset, 16) < EXPECTED_LIBCUDA_SIZE)),
                    "GPU name caller location is missing or unredacted")
            chain = record.get("caller_chain_offsets")
            anchor = record.get("caller_chain_anchor_found")
            truncated = record.get("caller_chain_truncated")
            require(isinstance(chain, list) and len(chain) <= 24 and
                    all(isinstance(value, str) and
                        re.fullmatch(r"0x[0-9a-f]+", value) is not None and
                        0 < int(value, 16) < EXPECTED_LIBCUDA_SIZE for value in chain) and
                    type(anchor) is bool and type(truncated) is bool and
                    (anchor or not chain),
                    "GPU name caller chain is malformed or unredacted")
            if image != "libcuda.so.580.178.04" or not offset or not anchor:
                resolved = False
            signatures.append((record["transport"], image, offset, tuple(chain)))
        return signatures, resolved

    controls = report.get("controls")
    controls_equal: bool | None = None
    passthrough_name_signatures = None
    if controls is not None:
        require(isinstance(controls, list) and len(controls) == 2 and
                [item.get("mode") for item in controls if isinstance(item, dict)] ==
                ["stock", "preload_passthrough"],
                "CUDA control runs are missing or reordered")
        control_cuda = [item.get("cuda") for item in controls]
        if capture_gpu_name_callers:
            control_cuda_comparable = [
                ({key: value for key, value in outcome.items()
                  if key != "gpu_name_trace_stage_counts"}
                 if isinstance(outcome, dict) else outcome)
                for outcome in control_cuda]
        else:
            control_cuda_comparable = control_cuda
        controls_equal = control_cuda_comparable[0] == control_cuda_comparable[1]
        if not controls_equal:
            complete = False
        for item in controls:
            if item.get("probe_exit_code") != 0 or not isinstance(item.get("cuda"), dict) or item["cuda"].get("cu_init") != 0:
                complete = False
            if capture_gpu_name_callers and item.get("mode") == "preload_passthrough":
                signatures, resolved = validate_gpu_name_records(
                    item.get("gpu_name_string_records"))
                passthrough_name_signatures = signatures
                complete = complete and resolved
                gpu_name_stage_signatures.append(validate_gpu_name_stage_counts(
                    item.get("cuda"), len(signatures)))

    runs = report.get("runs")
    require(isinstance(runs, list) and len(runs) == len(MASKS),
            "sensitivity report must contain exactly four mask runs")
    normalized_runs: list[dict[str, object]] = []
    cuda_outcomes: list[object] = []
    for expected_mask, run in zip(MASKS, runs):
        require(isinstance(run, dict) and type(run.get("requested_mask")) is int and
                run["requested_mask"] == expected_mask,
                "sensitivity mask sequence is incomplete or reordered")
        records = run.get("ioctl_records")
        require(isinstance(records, list), "override mask trace is malformed")
        if not records:
            complete = False
        for record in records:
            require(isinstance(record, dict) and
                    record.get("transport") in ("direct", "xfer") and
                    type(record.get("kernel_mask")) is int and record["kernel_mask"] == 9 and
                    type(record.get("exposed_mask")) is int and
                    record["exposed_mask"] == expected_mask,
                    "override mask trace does not prove the requested userland value")
            caller_image = record.get("caller_image")
            caller_offset = record.get("caller_offset")
            require(isinstance(caller_image, str) and
                    re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", caller_image) is not None and
                    ((caller_image == "unresolved" and caller_offset is None) or
                     (caller_image != "unresolved" and isinstance(caller_offset, str) and
                      re.fullmatch(r"0x[0-9a-f]+", caller_offset) is not None)),
                    "SYSTEM_GET_FEATURES caller location is missing or unredacted")
            if caller_image == "unresolved":
                complete = False
            if capture_caller_chain:
                caller_chain = record.get("caller_chain_offsets")
                anchor_found = record.get("caller_chain_anchor_found")
                caller_chain_truncated = record.get("caller_chain_truncated")
                require(isinstance(caller_chain, list) and
                        0 <= len(caller_chain) <= 24 and
                        all(isinstance(offset, str) and
                            re.fullmatch(r"0x[0-9a-f]+", offset) is not None and
                            0 < int(offset, 16) < EXPECTED_LIBCUDA_SIZE
                            for offset in caller_chain) and
                        type(anchor_found) is bool and
                        type(caller_chain_truncated) is bool,
                        "caller chain is missing, malformed, or not redacted")
                require(anchor_found or not caller_chain,
                        "caller chain contains frames without its callsite anchor")
                if not anchor_found or not caller_chain or caller_chain_truncated:
                    complete = False
        cuda = run.get("cuda")
        require(isinstance(cuda, dict), "CUDA enumeration outcome is missing")
        for field in ("cu_init", "device_count_status", "device_count", "driver_api"):
            value = cuda.get(field)
            require(value is None or type(value) is int,
                    "CUDA enumeration outcome contains an invalid status")
        if run.get("probe_exit_code", 0) != 0 or cuda.get("cu_init") != 0:
            complete = False
        if cuda.get("cu_init") == 0:
            if cuda.get("driver_api") is not None and cuda.get("driver_api") != 13000:
                raise ValueError("CUDA Driver API version differs from the pinned libcuda")
            if cuda.get("driver_api") != 13000 or cuda.get("device_count_status") != 0:
                complete = False
            if cuda.get("device_count") != 1:
                complete = False
            device = cuda.get("device")
            if isinstance(device, dict):
                attributes = device.get("attributes")
                if isinstance(attributes, dict):
                    for key in ("concurrent_managed_access", "pageable_memory_access",
                                "pageable_memory_access_uses_host_page_tables"):
                        value = attributes.get(key)
                        if type(value) is not int:
                            complete = False
                else:
                    complete = False
                for status_key, value_key, expected in (
                    ("name_status", "name", "Tesla V100"),
                    ("pci_status", "pci", EXPECTED_PCI),
                    ("compute_capability_status", "compute_capability", [7, 0]),
                ):
                    status = device.get(status_key, 0)
                    value = device.get(value_key)
                    if status == 0:
                        matches = (isinstance(value, str) and value.startswith(expected)
                                   if value_key == "name" else
                                   canonical_pci(value) == expected if value_key == "pci" else
                                   value == expected)
                        require(matches, "CUDA enumerated a device other than the pinned V100")
                    else:
                        complete = False
            else:
                complete = False
        cuda_outcomes.append(cuda)
        name_signatures = None
        if capture_gpu_name_callers:
            name_signatures, resolved = validate_gpu_name_records(
                run.get("gpu_name_string_records"))
            gpu_name_signatures.append(name_signatures)
            complete = complete and resolved
            gpu_name_stage_signatures.append(validate_gpu_name_stage_counts(
                cuda, len(name_signatures)))
        normalized_runs.append({
            "requested_mask": expected_mask,
            "override_observed": bool(records),
            "ioctl_records": records,
            "probe_exit_code": run.get("probe_exit_code", 0),
            "cuda": cuda,
            **({"gpu_name_string_records": run["gpu_name_string_records"]}
               if capture_gpu_name_callers else {}),
        })
    if capture_gpu_name_callers:
        reference_signatures = gpu_name_signatures[0] if gpu_name_signatures else None
        if (passthrough_name_signatures is None or
                passthrough_name_signatures != reference_signatures or
                any(signatures != reference_signatures
                    for signatures in gpu_name_signatures[1:])):
            complete = False
        if (not gpu_name_stage_signatures or
                any(signature != gpu_name_stage_signatures[0]
                    for signature in gpu_name_stage_signatures[1:])):
            complete = False
    return {
        "runs": normalized_runs,
        "complete": complete,
        "api_outcomes_equal": all(value == cuda_outcomes[0] for value in cuda_outcomes[1:]),
        "control_outcomes_equal": controls_equal,
        "caller_chain_capture_requested": capture_caller_chain,
        "gpu_name_caller_trace_requested": capture_gpu_name_callers,
        "gpu_name_caller_trace_complete": (
            capture_gpu_name_callers and complete and bool(gpu_name_signatures)),
        "gpu_name_trace_stage_deltas": (
            [{"after_stage": stage, "new_records": delta}
             for stage, delta in (gpu_name_stage_signatures[0]
                                  if gpu_name_stage_signatures else [])]
            if capture_gpu_name_callers else None),
    }


def validate_guest_kernel_sensitivity(report: object) -> dict[str, object]:
    """Validate four process-local masks around a pinned, numerical SM70 kernel phase."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-hybrid-v100-system-features-kernel-sensitivity-guest-v1" and
            report.get("workload") == "sm70-kernel" and report.get("status") == "observed",
            "unsupported V100 kernel-sensitivity report")
    require(report.get("hostname") == EXPECTED_HOST and
            report.get("kernel_release") == EXPECTED_KERNEL,
            "V100 guest identity differs from the pinned kernel-test target")
    gpu = report.get("gpu")
    require(isinstance(gpu, dict) and isinstance(gpu.get("name"), str) and
            gpu["name"].startswith("Tesla V100") and gpu.get("uuid") == EXPECTED_GPU_UUID and
            canonical_pci(gpu.get("pci")) == EXPECTED_PCI and
            gpu.get("driver_version") == EXPECTED_DRIVER,
            "kernel-sensitivity GPU identity is not the pinned R580 Tesla V100")
    libcuda = report.get("libcuda")
    require(isinstance(libcuda, dict) and libcuda.get("path") == EXPECTED_LIBCUDA and
            libcuda.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
            type(libcuda.get("driver_api")) is int and libcuda["driver_api"] == 13000,
            "kernel-sensitivity libcuda identity differs from the pinned R580 image")
    require(report.get("gpu_compute_processes_before") == [] and
            report.get("gpu_compute_processes_after") == [] and
            report.get("cleanup_passed") is True and
            report.get("driver_or_module_changed") is False and
            report.get("gpu_reset_requested") is False and
            report.get("temporary_payload_remaining") is False,
            "kernel-sensitivity scope or host-side cleanup invariant failed")
    scope = report.get("execution_scope")
    require(isinstance(scope, dict) and scope.get("read_only") is True and
            all(scope.get(key) is False for key in (
                "experimental_module_loaded", "stock_driver_changed", "pci_binding_changed",
                "vm_management_issued", "gpu_reset_requested")),
            "kernel-sensitivity scope contains a prohibited system change")
    artifacts = report.get("kernel_artifacts")
    require(isinstance(artifacts, dict) and
            artifacts.get("probe_source_sha256") == KERNEL_PROBE_SOURCE_SHA256 and
            artifacts.get("sm70_cubin_sha256") == KERNEL_SM70_CUBIN_SHA256,
            "kernel-sensitivity report does not pin its probe source and SM70 cubin")

    def phase_passed(outcome: object, exit_code: object) -> bool:
        require(isinstance(outcome, dict), "kernel phase result is malformed")
        if isinstance(outcome.get("probe_error_class"), str):
            return False
        require(outcome.get("schema") == "nvidia-hybrid-v100-sm70-driver-api-kernel-v1" and
                outcome.get("cubin_sha256") == KERNEL_SM70_CUBIN_SHA256 and
                outcome.get("cubin_digest_passed") is True and
                outcome.get("status") in ("phase-passed", "phase-failed") and
                outcome.get("phase") == "kernel" and
                outcome.get("expected_pci") == EXPECTED_PCI and
                outcome.get("driver_library_path") == EXPECTED_LIBCUDA,
                "kernel phase identity does not match the pinned guest and artifacts")
        require(type(outcome.get("cleanup_passed")) is bool and
                isinstance(outcome.get("cleanup_errors"), list) and
                isinstance(outcome.get("completed_operations"), list) and
                all(isinstance(item, str) for item in outcome["completed_operations"]) and
                isinstance(outcome.get("error"), str),
                "kernel phase cleanup or operation metadata is malformed")
        device = outcome.get("device")
        if device is not None:
            require(isinstance(device, dict) and
                    isinstance(device.get("name"), str) and
                    device["name"].startswith("Tesla V100") and
                    canonical_pci(device.get("pci_bus_id")) == EXPECTED_PCI and
                    device.get("sm") == 70 and device.get("compute_capability") == "7.0",
                    "kernel phase identity selected a different GPU")
        if (exit_code == 0 and outcome.get("status") == "phase-passed" and
                outcome.get("driver_api") == 13000 and isinstance(device, dict) and
                outcome.get("numeric_result_passed") is True and
                outcome.get("result_value") == 700 and outcome.get("expected_result") == 700 and
                outcome.get("cleanup_passed") is True and outcome.get("cleanup_errors") == [] and
                outcome.get("error") == ""):
            operations = set(outcome["completed_operations"])
            required = {"cuCtxCreate_v2", "cuModuleLoadData", "cuMemAlloc_v2",
                        "cuLaunchKernel", "cuCtxSynchronize", "cuMemcpyDtoH_v2"}
            return required.issubset(operations)
        return False

    complete = True
    controls = report.get("controls")
    require(isinstance(controls, list) and len(controls) == 2 and
            [item.get("mode") for item in controls if isinstance(item, dict)] ==
            ["stock", "preload_passthrough"],
            "stock and pass-through kernel controls are missing or reordered")
    controls_equal = controls[0].get("cuda") == controls[1].get("cuda")
    if not controls_equal:
        complete = False
    for control in controls:
        if not phase_passed(control.get("cuda"), control.get("probe_exit_code")):
            complete = False

    runs = report.get("runs")
    require(isinstance(runs, list) and len(runs) == len(MASKS),
            "kernel-sensitivity report must contain exactly four ordered masks")
    normalized_runs: list[dict[str, object]] = []
    cuda_outcomes: list[object] = []
    for expected_mask, run in zip(MASKS, runs):
        require(isinstance(run, dict) and type(run.get("requested_mask")) is int and
                run["requested_mask"] == expected_mask,
                "kernel-sensitivity masks are incomplete or reordered")
        records = run.get("ioctl_records")
        require(isinstance(records, list), "kernel-sensitivity ioctl trace is malformed")
        if not records:
            complete = False
        for record in records:
            require(isinstance(record, dict) and
                    record.get("transport") in ("direct", "xfer") and
                    type(record.get("kernel_mask")) is int and record["kernel_mask"] == 9 and
                    type(record.get("exposed_mask")) is int and
                    record["exposed_mask"] == expected_mask and
                    isinstance(record.get("caller_image"), str) and
                    re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", record["caller_image"]) is not None and
                    record["caller_image"] != "unresolved" and
                    isinstance(record.get("caller_offset"), str) and
                    re.fullmatch(r"0x[0-9a-f]+", record["caller_offset"]) is not None and
                    0 < int(record["caller_offset"], 16) < EXPECTED_LIBCUDA_SIZE,
                    "kernel-sensitivity trace does not prove the requested redacted mask")
        phase_ok = phase_passed(run.get("cuda"), run.get("probe_exit_code"))
        if not phase_ok:
            complete = False
        cuda_outcomes.append(run.get("cuda"))
        normalized_runs.append({
            "requested_mask": expected_mask,
            "override_observed": bool(records),
            "ioctl_records": records,
            "probe_exit_code": run.get("probe_exit_code"),
            "kernel_phase_passed": phase_ok,
            "cuda": run.get("cuda"),
        })
    return {
        "runs": normalized_runs,
        "complete": complete,
        "api_outcomes_equal": all(value == cuda_outcomes[0] for value in cuda_outcomes[1:]),
        "control_outcomes_equal": controls_equal,
        "caller_chain_capture_requested": False,
        "kernel_phase_passed_for_all_masks": all(run["kernel_phase_passed"]
                                                  for run in normalized_runs),
    }


def validate_guest_ipc_sensitivity(report: object) -> dict[str, object]:
    """Validate process-to-process CUDA memory IPC outcomes without assuming success."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-hybrid-v100-system-features-ipc-sensitivity-guest-v1" and
            report.get("workload") == "ipc-memory-share" and report.get("status") == "observed",
            "unsupported V100 IPC-sensitivity report")
    require(report.get("hostname") == EXPECTED_HOST and
            report.get("kernel_release") == EXPECTED_KERNEL,
            "V100 IPC guest identity differs from the pinned target")
    gpu = report.get("gpu")
    require(isinstance(gpu, dict) and isinstance(gpu.get("name"), str) and
            gpu["name"].startswith("Tesla V100") and gpu.get("uuid") == EXPECTED_GPU_UUID and
            canonical_pci(gpu.get("pci")) == EXPECTED_PCI and
            gpu.get("driver_version") == EXPECTED_DRIVER,
            "IPC-sensitivity GPU identity is not the pinned R580 Tesla V100")
    libcuda = report.get("libcuda")
    require(isinstance(libcuda, dict) and libcuda.get("path") == EXPECTED_LIBCUDA and
            libcuda.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
            type(libcuda.get("driver_api")) is int and libcuda["driver_api"] == 13000,
            "IPC-sensitivity libcuda identity differs from the pinned R580 image")
    require(report.get("gpu_compute_processes_before") == [] and
            report.get("gpu_compute_processes_after") == [] and
            report.get("cleanup_passed") is True and
            report.get("driver_or_module_changed") is False and
            report.get("gpu_reset_requested") is False and
            report.get("temporary_payload_remaining") is False,
            "IPC-sensitivity scope or cleanup invariant failed")
    scope = report.get("execution_scope")
    require(isinstance(scope, dict) and scope.get("read_only") is True and
            all(scope.get(key) is False for key in (
                "experimental_module_loaded", "stock_driver_changed", "pci_binding_changed",
                "vm_management_issued", "gpu_reset_requested")),
            "IPC-sensitivity scope contains a prohibited system change")
    artifacts = report.get("ipc_artifacts")
    require(isinstance(artifacts, dict) and
            artifacts.get("probe_source_sha256") == IPC_PROBE_SOURCE_SHA256,
            "IPC-sensitivity report does not pin its probe source")

    required_success_operations = {
        "cuCtxCreate_v2", "cuMemAlloc_v2", "cuMemcpyHtoD_v2", "cuIpcGetMemHandle",
        "child:cuCtxCreate_v2", "child:cuIpcOpenMemHandle_v2",
        "child:cuMemcpyDtoH_v2", "child:cuMemcpyHtoD_v2",
        "child:cuIpcCloseMemHandle", "cuCtxSynchronize", "cuMemcpyDtoH_v2",
        "cuMemFree_v2", "cuCtxDestroy_v2", "child:cuCtxDestroy_v2",
    }
    valid_failure_operations = {
        "cuIpcGetMemHandle", "child:cuIpcOpenMemHandle_v2",
        "child:numeric-validation-initial", "parent:numeric-validation",
        "child:cuMemcpyDtoH_v2", "child:cuMemcpyHtoD_v2",
        "child:cuCtxSynchronize", "parent:cuCtxSynchronize", "parent:cuMemcpyDtoH_v2",
    }

    def validate_phase(outcome: object, exit_code: object) -> tuple[
            bool, bool, tuple[object, ...], tuple[object, ...], bool, bool]:
        require(isinstance(outcome, dict) and
                outcome.get("schema") == "nvidia-hybrid-v100-driver-api-ipc-memory-v1" and
                outcome.get("phase") == "ipc-memory-share" and
                outcome.get("status") in ("phase-passed", "phase-failed") and
                outcome.get("expected_pci") == EXPECTED_PCI and
                outcome.get("driver_library_path") == EXPECTED_LIBCUDA and
                outcome.get("driver_api") == 13000,
                "IPC phase identity does not match the pinned V100 guest")
        device = outcome.get("device")
        require(isinstance(device, dict) and isinstance(device.get("name"), str) and
                device["name"].startswith("Tesla V100") and
                canonical_pci(device.get("pci_bus_id")) == EXPECTED_PCI and
                device.get("sm") == 70 and device.get("compute_capability") == "7.0" and
                device.get("unified_addressing") == 1,
                "IPC phase selected a different device or lacks the IPC UVA prerequisite")

        capability_queries_complete = True

        def memory_sharing_signature(candidate: object) -> tuple[
                tuple[str, int | None, int | None], ...]:
            nonlocal capability_queries_complete
            require(isinstance(candidate, dict),
                    "IPC memory-sharing capability device metadata is missing")
            support = candidate.get("memory_sharing_support")
            expected_support = ("virtual_memory_management", "posix_file_descriptor",
                                "fabric_handle")
            if not isinstance(support, dict):
                capability_queries_complete = False
                return tuple((key, None, None) for key in expected_support)
            require(set(support).issubset(set(expected_support)),
                    "IPC memory-sharing capability query set is malformed")
            signature: list[tuple[str, int | None, int | None]] = []
            for key in expected_support:
                entry = support.get(key)
                if not isinstance(entry, dict) or type(entry.get("status")) is not int:
                    capability_queries_complete = False
                    signature.append((key, None, None))
                    continue
                require(entry["status"] >= 0,
                        "IPC memory-sharing capability result is malformed")
                value = entry.get("value")
                if entry["status"] == 0:
                    require(type(value) is int and value in (0, 1),
                            "IPC memory-sharing capability is not boolean")
                else:
                    require(value is None,
                            "unsupported IPC memory-sharing attribute has a value")
                    capability_queries_complete = False
                signature.append((key, entry["status"], value))
            return tuple(signature)

        exporter_support = memory_sharing_signature(device)
        importer_device = outcome.get("importer_device")
        require(isinstance(importer_device, dict) and
                isinstance(importer_device.get("name"), str) and
                importer_device["name"].startswith("Tesla V100") and
                canonical_pci(importer_device.get("pci_bus_id")) == EXPECTED_PCI and
                importer_device.get("sm") == 70 and
                importer_device.get("compute_capability") == "7.0" and
                importer_device.get("unified_addressing") == 1,
                "IPC importer device identity is missing or different")
        importer_support = memory_sharing_signature(importer_device)
        exporter_records = device.get("memory_sharing_support")
        importer_records = importer_device.get("memory_sharing_support")
        capability_records_independent = (
            device is not importer_device and exporter_records is not importer_records)
        if isinstance(exporter_records, dict) and isinstance(importer_records, dict):
            capability_records_independent = capability_records_independent and all(
                key not in exporter_records or key not in importer_records or
                exporter_records[key] is not importer_records[key]
                for key in exporter_records
            )
        process_capabilities_equal = (
            exporter_support == importer_support and capability_records_independent and
            capability_queries_complete)
        require(outcome.get("allocation_bytes") == 64 and
                outcome.get("ipc_handle_bytes") == 64 and
                type(outcome.get("export_attempted")) is bool and
                type(outcome.get("open_attempted")) is bool and
                type(outcome.get("open_succeeded")) is bool and
                type(outcome.get("ipc_succeeded")) is bool and
                type(outcome.get("observation_valid")) is bool,
                "IPC phase dimensions or observation flags are malformed")
        operations = outcome.get("completed_operations")
        cleanup_errors = outcome.get("cleanup_errors")
        require(isinstance(operations, list) and all(isinstance(item, str) for item in operations) and
                type(outcome.get("cleanup_passed")) is bool and isinstance(cleanup_errors, list) and
                isinstance(outcome.get("error"), str),
                "IPC phase cleanup or operation metadata is malformed")
        if not outcome["cleanup_passed"] or cleanup_errors:
            raise ValueError("IPC phase cleanup did not pass")
        if exit_code != 0:
            return (False, False, ("probe-exit", exit_code),
                    (exporter_support, importer_support), process_capabilities_equal,
                    capability_queries_complete)
        if outcome["status"] == "phase-passed":
            require(outcome.get("ipc_succeeded") is True and
                    outcome.get("export_attempted") is True and
                    outcome.get("open_attempted") is True and
                    outcome.get("open_succeeded") is True and
                    outcome.get("observation_valid") is True and
                    outcome.get("initial_values_match") is True and
                    outcome.get("child_writeback_match") is True and
                    outcome.get("failure_operation") is None and
                    outcome.get("failure_code") is None and
                    outcome.get("failure_name") is None and
                    outcome.get("error") == "" and
                    required_success_operations.issubset(set(operations)),
                    "IPC numeric exchange did not pass in both processes")
            return (True, True, ("passed", outcome.get("initial_values_match"),
                                 outcome.get("child_writeback_match")),
                    (exporter_support, importer_support), process_capabilities_equal,
                    capability_queries_complete)
        require(outcome.get("ipc_succeeded") is False and
                outcome.get("observation_valid") is True and
                outcome.get("export_attempted") is True,
                "failed IPC phase did not capture an observable export/open result")
        failure_operation = outcome.get("failure_operation")
        failure_code = outcome.get("failure_code")
        failure_name = outcome.get("failure_name")
        require(failure_operation in valid_failure_operations and
                ((type(failure_code) is int and failure_code > 0 and
                  isinstance(failure_name, str) and
                  re.fullmatch(r"CUDA_ERROR_[A-Z0-9_]{1,80}", failure_name) is not None) or
                 (failure_code is None and failure_name == "IPC_NUMERIC_MISMATCH")),
                "IPC failure is not a captured Driver API or numeric-check outcome")
        if failure_operation == "cuIpcGetMemHandle":
            require(outcome.get("open_attempted") is False and
                    outcome.get("open_succeeded") is False,
                    "IPC open cannot be reported after export failed")
        if failure_operation == "child:cuIpcOpenMemHandle_v2":
            require(outcome.get("open_attempted") is True and
                    outcome.get("open_succeeded") is False,
                    "IPC importer open failure was not attempted")
        if failure_operation not in ("cuIpcGetMemHandle", "child:cuIpcOpenMemHandle_v2"):
            require(outcome.get("open_succeeded") is True,
                    "post-open IPC failure lacks a successful importer mapping")
        return (True, False, (failure_operation, failure_code, failure_name,
                              outcome.get("open_attempted"), outcome.get("open_succeeded")),
                (exporter_support, importer_support), process_capabilities_equal,
                capability_queries_complete)

    controls = report.get("controls")
    require(isinstance(controls, list) and len(controls) == 2 and
            [item.get("mode") for item in controls if isinstance(item, dict)] ==
            ["stock", "preload_passthrough"],
            "stock and pass-through IPC controls are missing or reordered")
    complete = True
    control_transfer_signatures: list[tuple[object, ...]] = []
    control_capability_pairs: list[tuple[object, ...]] = []
    capability_queries_complete = True
    all_process_capability_pairs_equal = True
    for control in controls:
        observed, _passed, transfer_signature, capability_pair, process_equal, caps_complete = validate_phase(
            control.get("cuda"), control.get("probe_exit_code"))
        control_transfer_signatures.append(transfer_signature)
        control_capability_pairs.append(capability_pair)
        capability_queries_complete = capability_queries_complete and caps_complete
        all_process_capability_pairs_equal = all_process_capability_pairs_equal and process_equal
        if not process_equal or not caps_complete:
            complete = False
        if not observed:
            complete = False
    controls_equal = control_transfer_signatures[0] == control_transfer_signatures[1]
    control_capability_outcomes_equal = control_capability_pairs[0] == control_capability_pairs[1]
    if not controls_equal or not control_capability_outcomes_equal:
        complete = False

    runs = report.get("runs")
    require(isinstance(runs, list) and len(runs) == len(MASKS),
            "IPC-sensitivity report must contain exactly four ordered masks")
    normalized_runs: list[dict[str, object]] = []
    transfer_signatures: dict[int, tuple[object, ...]] = {}
    capability_signatures: dict[int, tuple[object, ...]] = {}
    passed_by_mask: dict[int, bool] = {}
    for expected_mask, run in zip(MASKS, runs):
        require(isinstance(run, dict) and type(run.get("requested_mask")) is int and
                run["requested_mask"] == expected_mask,
                "IPC-sensitivity masks are incomplete or reordered")
        records = run.get("ioctl_records")
        require(isinstance(records, list), "IPC-sensitivity ioctl trace is malformed")
        if not records:
            complete = False
        for record in records:
            require(isinstance(record, dict) and
                    record.get("transport") in ("direct", "xfer") and
                    record.get("kernel_mask") == 9 and
                    record.get("exposed_mask") == expected_mask and
                    isinstance(record.get("caller_image"), str) and
                    re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", record["caller_image"]) is not None and
                    record["caller_image"] != "unresolved" and
                    isinstance(record.get("caller_offset"), str) and
                    re.fullmatch(r"0x[0-9a-f]+", record["caller_offset"]) is not None and
                    0 < int(record["caller_offset"], 16) < EXPECTED_LIBCUDA_SIZE,
                    "IPC trace does not prove the requested redacted mask")
        observed, passed, transfer_signature, capability_pair, process_equal, caps_complete = \
            validate_phase(run.get("cuda"), run.get("probe_exit_code"))
        if not observed:
            complete = False
        if not process_equal or not caps_complete:
            complete = False
        capability_queries_complete = capability_queries_complete and caps_complete
        all_process_capability_pairs_equal = all_process_capability_pairs_equal and process_equal
        transfer_signatures[expected_mask] = transfer_signature
        capability_signatures[expected_mask] = capability_pair
        passed_by_mask[expected_mask] = passed
        normalized_runs.append({
            "requested_mask": expected_mask,
            "override_observed": bool(records),
            "ioctl_records": records,
            "probe_exit_code": run.get("probe_exit_code"),
            "ipc_observation_valid": observed,
            "ipc_succeeded": passed,
            "cuda": run.get("cuda"),
        })
    return {
        "runs": normalized_runs,
        "complete": complete,
        "ipc_succeeded_for_all_masks": all(passed_by_mask.values()),
        "ipc_outcomes_equal": all(value == transfer_signatures[9]
                                   for value in transfer_signatures.values()),
        "ipc_transfer_outcomes_equal": all(value == transfer_signatures[9]
                                            for value in transfer_signatures.values()),
        "mask_9_vs_1_outcomes_equal": transfer_signatures.get(9) == transfer_signatures.get(1),
        "device_capability_outcomes_equal": all(value == capability_signatures[9]
                                                 for value in capability_signatures.values()),
        "mask_9_vs_1_fabric_capability_equal": (
            capability_signatures.get(9, ((None,), (None,)))[0][-1] ==
            capability_signatures.get(1, ((None,), (None,)))[0][-1] and
            capability_signatures.get(9, ((None,), (None,)))[1][-1] ==
            capability_signatures.get(1, ((None,), (None,)))[1][-1]),
        "capability_queries_complete": capability_queries_complete,
        "all_process_capability_pairs_equal": all_process_capability_pairs_equal,
        "control_outcomes_equal": controls_equal,
        "control_capability_outcomes_equal": control_capability_outcomes_equal,
        "api_outcomes_equal": all(value == transfer_signatures[9]
                                   for value in transfer_signatures.values()),
        "caller_chain_capture_requested": False,
    }


def validate_guest_vmm_fabric_sensitivity(report: object) -> dict[str, object]:
    """Validate bounded VMM shareable-handle observations and endpoint agreement."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict) and report.get("workload") in
            ("vmm-fabric-share", "vmm-posix-share") and report.get("status") == "observed",
            "unsupported V100 VMM shareable-handle sensitivity report")
    kind = "fabric" if report["workload"] == "vmm-fabric-share" else "posix_fd"
    expected_handle_type = 8 if kind == "fabric" else 1
    expected_handle_bytes = 64 if kind == "fabric" else 4
    exporter_phase = f"vmm-{kind}-share"
    importer_phase = f"vmm-{kind}-importer"
    expected_schema = ("nvidia-hybrid-v100-system-features-vmm-fabric-sensitivity-guest-v1"
                       if kind == "fabric" else
                       "nvidia-hybrid-v100-system-features-vmm-posix-sensitivity-guest-v1")
    require(report.get("schema") == expected_schema,
            "V100 VMM report schema does not match its shareable-handle kind")
    require(report.get("hostname") == EXPECTED_HOST and
            report.get("kernel_release") == EXPECTED_KERNEL,
            "VMM/FABRIC guest identity differs from the pinned target")
    gpu = report.get("gpu")
    require(isinstance(gpu, dict) and isinstance(gpu.get("name"), str) and
            gpu["name"].startswith("Tesla V100") and gpu.get("uuid") == EXPECTED_GPU_UUID and
            canonical_pci(gpu.get("pci")) == EXPECTED_PCI and
            gpu.get("driver_version") == EXPECTED_DRIVER,
            "VMM/FABRIC GPU identity is not the pinned R580 Tesla V100")
    libcuda = report.get("libcuda")
    require(isinstance(libcuda, dict) and libcuda.get("path") == EXPECTED_LIBCUDA and
            libcuda.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
            type(libcuda.get("driver_api")) is int and libcuda["driver_api"] == 13000,
            "VMM/FABRIC libcuda identity differs from the pinned R580 image")
    require(report.get("gpu_compute_processes_before") == [] and
            report.get("gpu_compute_processes_after") == [] and
            report.get("cleanup_passed") is True and
            report.get("driver_or_module_changed") is False and
            report.get("gpu_reset_requested") is False and
            report.get("temporary_payload_remaining") is False,
            "VMM/FABRIC execution scope or cleanup invariant failed")
    scope = report.get("execution_scope")
    require(isinstance(scope, dict) and scope.get("read_only") is True and
            all(scope.get(key) is False for key in (
                "experimental_module_loaded", "stock_driver_changed", "pci_binding_changed",
                "vm_management_issued", "gpu_reset_requested")),
            "VMM/FABRIC scope contains a prohibited system change")
    artifacts = report.get("vmm_fabric_artifacts" if kind == "fabric" else "vmm_posix_artifacts")
    require(isinstance(artifacts, dict) and
            artifacts.get("probe_source_sha256") == VMM_FABRIC_PROBE_SOURCE_SHA256,
            "VMM shareable-handle report does not pin its probe source")

    def validate_imex(value: object) -> tuple[object, ...]:
        require(isinstance(value, dict) and
                type(value.get("driver_registered")) is bool and
                type(value.get("directory_present")) is bool and
                type(value.get("channel_nodes_seen")) is int and value["channel_nodes_seen"] >= 0 and
                type(value.get("character_nodes_seen")) is int and
                0 <= value["character_nodes_seen"] <= value["channel_nodes_seen"] and
                type(value.get("read_write_accessible_nodes")) is int and
                0 <= value["read_write_accessible_nodes"] <= value["character_nodes_seen"] and
                type(value.get("effective_uid")) is int and value["effective_uid"] == 0,
                "IMEX preflight metadata is missing or malformed")
        return (value["driver_registered"], value["directory_present"],
                value["channel_nodes_seen"], value["character_nodes_seen"],
                value["read_write_accessible_nodes"], value["effective_uid"])

    def validate_endpoint(value: object, phase: str) -> tuple[
            bool, tuple[object, ...], tuple[object, ...], bool, bool]:
        require(isinstance(value, dict) and
                value.get("schema") == "nvidia-hybrid-driver-api-vmm-share-v1" and
                value.get("phase") == phase and
                value.get("shareable_handle_kind") == kind and
                value.get("shareable_handle_type") == expected_handle_type and
                value.get("shareable_handle_bytes") == expected_handle_bytes and
                value.get("status") in ("phase-passed", "phase-failed") and
                value.get("expected_pci") == EXPECTED_PCI and
                value.get("driver_library_path") == EXPECTED_LIBCUDA and
                value.get("driver_api") == 13000 and
                type(value.get("observation_valid")) is bool and
                type(value.get("cleanup_passed")) is bool and
                isinstance(value.get("cleanup_errors"), list) and
                isinstance(value.get("completed_operations"), list) and
                all(isinstance(item, str) for item in value["completed_operations"]),
                "VMM endpoint identity or operation metadata is malformed")
        if value["cleanup_passed"] is not True or value["cleanup_errors"]:
            raise ValueError("VMM endpoint cleanup did not pass")
        device = value.get("device")
        require(isinstance(device, dict) and isinstance(device.get("name"), str) and
                device["name"].startswith("Tesla V100") and
                canonical_pci(device.get("pci_bus_id")) == EXPECTED_PCI and
                device.get("sm") == 70 and device.get("compute_capability") == "7.0" and
                device.get("unified_addressing") == 1,
                "VMM endpoint did not select the pinned UVA-capable V100")
        support_key = "fabric_handle_support" if kind == "fabric" else "posix_fd_handle_support"
        support = device.get(support_key)
        require(isinstance(support, dict) and type(support.get("status")) is int and
                support["status"] >= 0,
                "VMM shareable-handle support-attribute result is malformed")
        capability_complete = support["status"] == 0
        if capability_complete:
            require(type(support.get("value")) is int and support["value"] in (0, 1),
                    "VMM shareable-handle support attribute is not boolean")
        else:
            require(support.get("value") is None,
                    "failed VMM shareable-handle support query must remain unknown")
        require(value.get("attribute_support") == support,
                "VMM support-attribute copies disagree")
        if kind == "posix_fd":
            require(type(value.get("posix_shareable_fd_opened")) is bool and
                    type(value.get("posix_shareable_fd_closed")) is bool and
                    value.get("posix_shareable_fd_closed") is True and
                    (value.get("status") != "phase-passed" or
                     value.get("posix_shareable_fd_opened") is True),
                    "POSIX shareable-descriptor lifecycle metadata is malformed")
        imex = validate_imex(value.get("imex_preflight"))
        endpoint_capability_signature = (support["status"], support.get("value"), imex)
        operations = set(value["completed_operations"])
        observation_valid = value["observation_valid"]
        process_capabilities_equal = True
        transfer: tuple[object, ...]
        if phase == exporter_phase:
            require(type(value.get("allocation_created")) is bool and
                    type(value.get("export_attempted")) is bool and
                    type(value.get("export_succeeded")) is bool and
                    type(value.get("import_attempted")) is bool and
                    type(value.get("import_succeeded")) is bool,
                    "VMM/FABRIC exporter attempt metadata is malformed")
            allocation_bytes = value.get("allocation_bytes")
            require(allocation_bytes is None or
                    (type(allocation_bytes) is int and 0 < allocation_bytes <= 1024 * 1024 * 1024),
                    "VMM/FABRIC exporter allocation size is malformed")
            require(allocation_bytes is not None or value["allocation_created"] is False,
                    "allocation size is missing after a VMM allocation was created")
            if value["allocation_created"]:
                require(allocation_bytes <= 4 * 1024 * 1024,
                        "VMM allocation exceeded the probe memory bound")
            child = value.get("child")
            if value["export_succeeded"]:
                require(value["export_attempted"] is True and isinstance(child, dict),
                        "successful FABRIC export lacks importer process evidence")
                child_observed, child_transfer, child_capability, child_caps_complete, child_pair_equal = \
                    validate_endpoint(child, importer_phase)
                if child_observed is not observation_valid:
                    observation_valid = False
                capability_complete = capability_complete and child_caps_complete
                process_capabilities_equal = (
                    child_pair_equal and endpoint_capability_signature == child_capability)
                if child.get("device", {}).get(support_key) is not None:
                    child_attribute = child["device"][support_key]
                    require(child_attribute == value["child"]["attribute_support"],
                            "VMM importer attribute copies disagree")
                elif child.get("attribute_support") is not None:
                    require(child.get("attribute_support") == child["device"][support_key],
                            "VMM importer attribute copies disagree")
                if child.get("status") == "phase-passed":
                    require(child.get("import_attempted") is True and
                            child.get("import_succeeded") is True and
                            child.get("initial_values_match") is True and
                            child.get("numerical_phase_passed") is True and
                            {"cuMemImportFromShareableHandle", "cuMemMap", "cuMemSetAccess",
                             "cuMemcpyDtoH_v2", "cuMemcpyHtoD_v2", "cuMemUnmap",
                             "cuMemAddressFree", "cuMemRelease", "cuCtxDestroy_v2"}.issubset(operations | set(child.get("completed_operations", []))),
                            "successful FABRIC import lacks mapping/numeric/cleanup evidence")
            elif child is not None:
                require(isinstance(child, dict), "FABRIC child outcome is malformed")
            transfer = (value.get("status"), value.get("failure_operation"),
                        value.get("failure_code"), value.get("failure_name"),
                        value.get("numerical_phase_passed"), value.get("child_writeback_match"))
            if value.get("status") == "phase-passed":
                require(value.get("export_attempted") is True and
                        value.get("export_succeeded") is True and
                        value.get("import_attempted") is True and
                        value.get("import_succeeded") is True and
                        value.get("numerical_phase_passed") is True and
                        value.get("child_writeback_match") is True and
                        isinstance(child, dict) and child.get("status") == "phase-passed" and
                        value.get("failure_operation") is None and
                        value.get("failure_code") is None and value.get("failure_name") is None,
                        "VMM/FABRIC phase claims success without two-process numeric writeback")
            elif observation_valid:
                failure_op = value.get("failure_operation")
                failure_code, failure_name = value.get("failure_code"), value.get("failure_name")
                allowed_cuda_operations = {
                    "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                    "cuDeviceGetName", "cuDeviceGetPCIBusId", "cuDeviceComputeCapability",
                    "cuCtxCreate_v2", "cuMemGetAllocationGranularity", "cuMemCreate",
                    "cuMemAddressReserve", "cuMemMap", "cuMemSetAccess", "cuMemcpyHtoD_v2",
                    "cuCtxSynchronize", "cuMemExportToShareableHandle", "cuMemcpyDtoH_v2",
                }
                require((failure_op is None and isinstance(value.get("error_class"), str)) or
                        (isinstance(failure_op, str) and
                         (failure_op in allowed_cuda_operations or
                          failure_op == "parent:numeric-validation" or
                          (failure_op.startswith("child:") and
                           failure_op[len("child:"):] in allowed_cuda_operations) or
                          failure_op == "load_cuda") and
                         ((type(failure_code) is int and failure_code > 0 and
                           isinstance(failure_name, str) and
                           re.fullmatch(r"CUDA_ERROR_[A-Z0-9_]{1,80}", failure_name) is not None) or
                          (failure_code is None and isinstance(failure_name, str)))),
                        "failed VMM/FABRIC phase lacks a typed failure observation")
            expected_success = {"cuMemGetAllocationGranularity", "cuMemCreate", "cuMemAddressReserve",
                                "cuMemMap", "cuMemSetAccess", "cuMemcpyHtoD_v2",
                                "cuMemExportToShareableHandle", "cuMemUnmap", "cuMemAddressFree",
                                "cuMemRelease", "cuCtxDestroy_v2", "cuCtxSynchronize"}
            if value.get("status") == "phase-passed":
                require(expected_success.issubset(operations),
                        "successful VMM/FABRIC exporter lacks required operations")
        else:
            require(type(value.get("allocation_bytes")) is int and
                    0 < value["allocation_bytes"] <= 4 * 1024 * 1024 and
                    type(value.get("import_attempted")) is bool and
                    type(value.get("import_succeeded")) is bool,
                    "VMM/FABRIC importer attempt metadata is malformed")
            transfer = (value.get("status"), value.get("failure_operation"),
                        value.get("failure_code"), value.get("failure_name"),
                        value.get("numerical_phase_passed"), value.get("initial_values_match"))
            if value.get("status") == "phase-passed":
                required = {"cuMemImportFromShareableHandle", "cuMemAddressReserve", "cuMemMap",
                            "cuMemSetAccess", "cuMemcpyDtoH_v2", "cuMemcpyHtoD_v2",
                            "cuCtxSynchronize", "cuMemUnmap", "cuMemAddressFree",
                            "cuMemRelease", "cuCtxDestroy_v2"}
                if kind == "posix_fd":
                    required.add("close_posix_shareable_fd")
                require(value.get("import_attempted") is True and value.get("import_succeeded") is True and
                        value.get("initial_values_match") is True and
                        value.get("numerical_phase_passed") is True and required.issubset(operations),
                        "successful VMM/FABRIC importer lacks numeric mapping/cleanup evidence")
            elif observation_valid:
                failure_op = value.get("failure_operation")
                failure_code, failure_name = value.get("failure_code"), value.get("failure_name")
                allowed_cuda_operations = {
                    "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
                    "cuDeviceGetName", "cuDeviceGetPCIBusId", "cuDeviceComputeCapability",
                    "cuCtxCreate_v2", "cuMemImportFromShareableHandle", "cuMemAddressReserve",
                    "cuMemMap", "cuMemSetAccess", "cuMemcpyDtoH_v2", "cuMemcpyHtoD_v2",
                    "cuCtxSynchronize",
                }
                require((failure_op is None and isinstance(value.get("error_class"), str)) or
                        (failure_op in allowed_cuda_operations and
                         ((type(failure_code) is int and failure_code > 0 and
                           isinstance(failure_name, str) and
                           re.fullmatch(r"CUDA_ERROR_[A-Z0-9_]{1,80}", failure_name) is not None) or
                          (failure_code is None and isinstance(failure_name, str)))),
                        "failed VMM/FABRIC importer lacks a typed failure observation")
        return (observation_valid, transfer, endpoint_capability_signature,
                capability_complete, process_capabilities_equal)

    controls = report.get("controls")
    require(isinstance(controls, list) and len(controls) == 2 and
            [item.get("mode") for item in controls if isinstance(item, dict)] ==
            ["stock", "preload_passthrough"],
            "stock and pass-through VMM/FABRIC controls are missing or reordered")
    complete = True
    control_transfers: list[tuple[object, ...]] = []
    control_capabilities: list[tuple[object, ...]] = []
    all_process_capability_pairs_equal = True
    capability_queries_complete = True
    for control in controls:
        require(control.get("probe_exit_code") == 0,
                "VMM/FABRIC control process did not exit cleanly")
        endpoint = control.get("cuda")
        observed, transfer, capability, caps_complete, process_equal = \
            validate_endpoint(endpoint, exporter_phase)
        child = endpoint.get("child") if isinstance(endpoint, dict) else None
        child_transfer_signature = None
        child_capability_signature = None
        if isinstance(child, dict):
            child_observed, child_transfer, child_capability, child_caps_complete, child_pair_equal = \
                validate_endpoint(child, importer_phase)
            observed = observed and child_observed
            caps_complete = caps_complete and child_caps_complete
            child_transfer_signature = child_transfer
            child_capability_signature = child_capability
            process_equal = process_equal and child_pair_equal and capability == child_capability
        control_transfers.append((transfer, child_transfer_signature))
        control_capabilities.append((capability, child_capability_signature))
        if not observed or not caps_complete or not process_equal:
            complete = False
        capability_queries_complete = capability_queries_complete and caps_complete
        all_process_capability_pairs_equal = all_process_capability_pairs_equal and process_equal
    control_outcomes_equal = control_transfers[0] == control_transfers[1]
    if not control_outcomes_equal or control_capabilities[0] != control_capabilities[1]:
        complete = False

    runs = report.get("runs")
    require(isinstance(runs, list) and len(runs) == len(MASKS),
            "VMM/FABRIC-sensitivity report must contain exactly four masks")
    normalized_runs: list[dict[str, object]] = []
    transfer_signatures: dict[int, tuple[object, ...]] = {}
    capability_signatures: dict[int, tuple[object, ...]] = {}
    passed_by_mask: dict[int, bool] = {}
    for expected_mask, run in zip(MASKS, runs):
        require(isinstance(run, dict) and type(run.get("requested_mask")) is int and
                run["requested_mask"] == expected_mask,
                "VMM/FABRIC masks are incomplete or reordered")
        records = run.get("ioctl_records")
        require(isinstance(records, list), "VMM/FABRIC ioctl trace is malformed")
        if not records:
            complete = False
        for record in records:
            require(isinstance(record, dict) and record.get("transport") in ("direct", "xfer") and
                    record.get("kernel_mask") == 9 and record.get("exposed_mask") == expected_mask and
                    isinstance(record.get("caller_image"), str) and
                    re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}", record["caller_image"]) is not None and
                    record["caller_image"] != "unresolved" and
                    isinstance(record.get("caller_offset"), str) and
                    re.fullmatch(r"0x[0-9a-f]+", record["caller_offset"]) is not None and
                    0 < int(record["caller_offset"], 16) < EXPECTED_LIBCUDA_SIZE,
                    "VMM/FABRIC trace does not prove the requested redacted mask")
        endpoint = run.get("cuda")
        observed, transfer, capability, caps_complete, process_equal = \
            validate_endpoint(endpoint, exporter_phase)
        child = endpoint.get("child") if isinstance(endpoint, dict) else None
        child_transfer_signature = None
        child_capability_signature = None
        child_passed = False
        if isinstance(child, dict):
            child_observed, child_transfer, child_capability, child_caps_complete, child_pair_equal = \
                validate_endpoint(child, importer_phase)
            observed = observed and child_observed
            caps_complete = caps_complete and child_caps_complete
            child_transfer_signature = child_transfer
            child_capability_signature = child_capability
            process_equal = process_equal and child_pair_equal and capability == child_capability
            child_passed = child.get("status") == "phase-passed"
        if not observed or not caps_complete or not process_equal or run.get("probe_exit_code") != 0:
            complete = False
        capability_queries_complete = capability_queries_complete and caps_complete
        all_process_capability_pairs_equal = all_process_capability_pairs_equal and process_equal
        passed = endpoint.get("status") == "phase-passed" and child_passed if isinstance(endpoint, dict) else False
        transfer_signatures[expected_mask] = (transfer, child_transfer_signature)
        capability_signatures[expected_mask] = (capability, child_capability_signature)
        passed_by_mask[expected_mask] = passed
        normalized_runs.append({"requested_mask": expected_mask,
                                "ioctl_records": records,
                                "probe_exit_code": run.get("probe_exit_code"),
                                "vmm_share_observation_valid": observed,
                                "vmm_share_succeeded": passed,
                                "cuda": endpoint})
    transfer_equal = all(value == transfer_signatures[9]
                         for value in transfer_signatures.values())
    capability_equal = all(value == capability_signatures[9]
                           for value in capability_signatures.values())
    result: dict[str, object] = {
        "runs": normalized_runs,
        "complete": complete,
        "api_outcomes_equal": transfer_equal,
        "vmm_share_kind": kind,
        "vmm_share_succeeded_for_all_masks": all(passed_by_mask.values()),
        "vmm_share_transfer_outcomes_equal": transfer_equal,
        "vmm_share_capability_outcomes_equal": capability_equal,
        "capability_queries_complete": capability_queries_complete,
        "all_process_capability_pairs_equal": all_process_capability_pairs_equal,
        "mask_9_vs_1_vmm_share_transfer_equal": transfer_signatures.get(9) == transfer_signatures.get(1),
        "mask_9_vs_1_handle_capability_equal": capability_signatures.get(9) == capability_signatures.get(1),
        "control_outcomes_equal": control_outcomes_equal,
        "caller_chain_capture_requested": False,
    }
    if kind == "fabric":
        result.update({
            "vmm_fabric_succeeded_for_all_masks": result["vmm_share_succeeded_for_all_masks"],
            "vmm_fabric_transfer_outcomes_equal": transfer_equal,
            "vmm_fabric_capability_outcomes_equal": capability_equal,
            "mask_9_vs_1_vmm_fabric_transfer_equal": result["mask_9_vs_1_vmm_share_transfer_equal"],
            "mask_9_vs_1_fabric_capability_equal": result["mask_9_vs_1_handle_capability_equal"],
        })
    return result


CUDA_PROBE = r'''import ctypes,json,os
LIBCUDA_PATH = "__LIBCUDA_PATH__"
result = {"cu_init": None, "driver_get_version_status": None,
          "device_count_status": None, "device_count": None,
          "driver_api": None, "device": None}
trace_path = os.environ.get("HYBRID_GPU_NAME_CALLER_TRACE_PATH")
if trace_path:
    result["gpu_name_trace_stage_counts"] = []
def sample_name_trace(stage):
    if not trace_path:
        return
    try:
        with open(trace_path,"r",encoding="utf-8") as stream:
            count = sum(1 for line in stream if line.strip())
    except Exception:
        count = -1
    result["gpu_name_trace_stage_counts"].append({"stage":stage,"records":count})
sample_name_trace("before_libcuda_load")
try:
    lib = ctypes.CDLL(LIBCUDA_PATH)
    sample_name_trace("after_libcuda_load")
    i32 = ctypes.c_int
    u32 = ctypes.c_uint
    lib.cuInit.argtypes = [u32]; lib.cuInit.restype = i32
    lib.cuDriverGetVersion.argtypes = [ctypes.POINTER(i32)]; lib.cuDriverGetVersion.restype = i32
    lib.cuDeviceGetCount.argtypes = [ctypes.POINTER(i32)]; lib.cuDeviceGetCount.restype = i32
    lib.cuDeviceGet.argtypes = [ctypes.POINTER(i32), i32]; lib.cuDeviceGet.restype = i32
    lib.cuDeviceGetName.argtypes = [ctypes.c_char_p, i32, i32]; lib.cuDeviceGetName.restype = i32
    lib.cuDeviceGetPCIBusId.argtypes = [ctypes.c_char_p, i32, i32]; lib.cuDeviceGetPCIBusId.restype = i32
    lib.cuDeviceComputeCapability.argtypes = [ctypes.POINTER(i32), ctypes.POINTER(i32), i32]
    lib.cuDeviceComputeCapability.restype = i32
    lib.cuDeviceGetAttribute.argtypes = [ctypes.POINTER(i32), i32, i32]
    lib.cuDeviceGetAttribute.restype = i32
    result["cu_init"] = int(lib.cuInit(0))
    sample_name_trace("after_cu_init")
    version = i32()
    result["driver_get_version_status"] = int(lib.cuDriverGetVersion(ctypes.byref(version)))
    sample_name_trace("after_cu_driver_get_version")
    if result["driver_get_version_status"] == 0:
        result["driver_api"] = int(version.value)
    count = i32()
    result["device_count_status"] = int(lib.cuDeviceGetCount(ctypes.byref(count)))
    sample_name_trace("after_cu_device_get_count")
    if result["device_count_status"] == 0:
        result["device_count"] = int(count.value)
        if count.value > 0:
            dev = i32(); dev_get = int(lib.cuDeviceGet(ctypes.byref(dev), 0))
            sample_name_trace("after_cu_device_get")
            name = ctypes.create_string_buffer(256); pci = ctypes.create_string_buffer(32)
            major = i32(); minor = i32()
            name_status = int(lib.cuDeviceGetName(name, len(name), dev)) if dev_get == 0 else dev_get
            sample_name_trace("after_cu_device_get_name")
            pci_status = int(lib.cuDeviceGetPCIBusId(pci, len(pci), dev)) if dev_get == 0 else dev_get
            cc_status = int(lib.cuDeviceComputeCapability(ctypes.byref(major), ctypes.byref(minor), dev)) if dev_get == 0 else dev_get
            attrs = {}
            for key, number in (("concurrent_managed_access", 89),
                                ("pageable_memory_access", 88),
                                ("pageable_memory_access_uses_host_page_tables", 100)):
                value = i32()
                status = int(lib.cuDeviceGetAttribute(ctypes.byref(value), number, dev)) if dev_get == 0 else dev_get
                attrs[key] = int(value.value) if status == 0 else None
                attrs[key + "_status"] = status
            result["device"] = {
                "device_get_status": dev_get,
                "name_status": name_status, "name": name.value.decode("utf-8", "replace") if name_status == 0 else "",
                "pci_status": pci_status, "pci": pci.value.decode("ascii", "replace") if pci_status == 0 else "",
                "compute_capability_status": cc_status,
                "compute_capability": [int(major.value), int(minor.value)] if cc_status == 0 else None,
                "attributes": attrs,
            }
except Exception as exc:
    result["probe_error_class"] = type(exc).__name__
print(json.dumps(result, sort_keys=True))
'''


GUEST_TEMPLATE = r'''import base64,csv,hashlib,json,os,re,shutil,stat,subprocess,sys,tempfile
from pathlib import Path
MASKS = (9, 8, 1, 0)
LIBCUDA = "__LIBCUDA_PATH__"
VMM_EXPECTED_PCI = "__VMM_EXPECTED_PCI__"
SHIM_B64 = "__SHIM_B64__"
SHIM_SHA256 = "__SHIM_SHA256__"
PROBE_B64 = "__PROBE_B64__"
CAPTURE_CALLER_CHAIN = __CAPTURE_CALLER_CHAIN__
CAPTURE_GPU_NAME_CALLERS = __CAPTURE_GPU_NAME_CALLERS__
WORKLOAD = "__WORKLOAD__"
PROBE_TIMEOUT = __PROBE_TIMEOUT__
KERNEL_PROBE_SOURCE_SHA256 = "__KERNEL_PROBE_SOURCE_SHA256__"
KERNEL_SM70_CUBIN_SHA256 = "__KERNEL_SM70_CUBIN_SHA256__"
IPC_PROBE_SOURCE_SHA256 = "__IPC_PROBE_SOURCE_SHA256__"
VMM_FABRIC_PROBE_SOURCE_SHA256 = "__VMM_FABRIC_PROBE_SOURCE_SHA256__"
def command(argv, timeout=20):
    env = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"}
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
def digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
def pci(value):
    import re
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match or int(match.group(3), 16) > 31: return None
    return f"{int(match.group(1),16)&0xffff:04x}:{int(match.group(2),16):02x}:{int(match.group(3),16):02x}.{int(match.group(4))}"
def gpus():
    result = command(["nvidia-smi", "--query-gpu=name,uuid,pci.bus_id,driver_version", "--format=csv,noheader"])
    if result is None or result.returncode != 0: raise RuntimeError("gpu_inventory_unavailable")
    rows = []
    for row in csv.reader(result.stdout.decode("utf-8", "replace").splitlines()):
        if len(row) == 4:
            rows.append({"name":row[0].strip(), "uuid":row[1].strip(),
                         "pci":pci(row[2].strip()), "driver_version":row[3].strip()})
    return rows
def compute_pids():
    result = command(["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader,nounits"])
    if result is None or result.returncode != 0: raise RuntimeError("compute_process_inventory_unavailable")
    pids = []
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        value = line.strip()
        if value.isdigit(): pids.append(int(value))
    return sorted(set(pids))
def module_identity():
    version_path = Path("/sys/module/nvidia/version")
    version = version_path.read_text().strip() if version_path.is_file() else None
    info = command(["modinfo", "-n", "nvidia"])
    module_path = info.stdout.decode("utf-8", "replace").strip() if info and info.returncode == 0 else None
    digest = digest_file(module_path) if module_path and os.path.isfile(module_path) else None
    return {"loaded":version is not None, "version":version, "path":module_path, "sha256":digest}
def write_private(path, data):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0), 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0: raise OSError("short_write")
            view = view[written:]
        os.fsync(fd)
    finally: os.close(fd)
def execute_probe(probe_code, env, trace_path=None, capture_caller_chain=False,
                  gpu_name_trace_path=None):
    completed = None
    try:
        probe_env = dict(env)
        if WORKLOAD in ("vmm-fabric-share", "vmm-posix-share"):
            probe_bytes = probe_code.encode("utf-8")
            probe_env["NVIDIA_HYBRID_VMM_CHILD_SOURCE_B64"] = base64.b64encode(probe_bytes).decode("ascii")
            probe_env["NVIDIA_HYBRID_VMM_CHILD_SOURCE_B64_SHA256"] = hashlib.sha256(probe_bytes).hexdigest()
            probe_env["NVIDIA_HYBRID_VMM_SHARE_KIND"] = (
                "fabric" if WORKLOAD == "vmm-fabric-share" else "posix_fd")
            probe_env["NVIDIA_HYBRID_VMM_EXPECTED_PCI"] = VMM_EXPECTED_PCI
            probe_env["NVIDIA_HYBRID_VMM_EXPECTED_DEVICE_NAME_PREFIX"] = "Tesla V100"
            probe_env["NVIDIA_HYBRID_VMM_EXPECTED_SM"] = "70"
            probe_env["NVIDIA_HYBRID_VMM_EXPECTED_DRIVER_API"] = "13000"
            probe_env["NVIDIA_HYBRID_VMM_LIBCUDA_PATH"] = LIBCUDA
        completed = subprocess.run([sys.executable,"-c",probe_code],stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=PROBE_TIMEOUT,check=False,env=probe_env)
        try:
            cuda = json.loads(completed.stdout.decode("utf-8", "strict").strip())
        except Exception as exc:
            cuda = {"probe_error_class":type(exc).__name__}
        exit_code = completed.returncode
    except Exception as exc:
        cuda = {"probe_error_class":type(exc).__name__,"cu_init":None,
                "device_count_status":None,"device_count":None,"driver_api":None}
        exit_code = 124 if isinstance(exc, subprocess.TimeoutExpired) else 125
    records = []
    if trace_path is not None:
        with open(trace_path,"r",encoding="utf-8") as stream:
            for line in stream:
                value = json.loads(line)
                expected_keys = {"transport","kernel_mask","exposed_mask",
                                 "caller_image","caller_offset"}
                if capture_caller_chain:
                    expected_keys.update({"caller_chain_offsets",
                                          "caller_chain_anchor_found",
                                          "caller_chain_truncated"})
                if (set(value) != expected_keys or
                    value.get("transport") not in ("direct","xfer")):
                    raise RuntimeError("override_trace_contract_failed")
                if capture_caller_chain:
                    offsets = value.get("caller_chain_offsets")
                    if (not isinstance(offsets, list) or not 0 <= len(offsets) <= 8 or
                        any(not isinstance(offset, str) or
                            re.fullmatch(r"0x[0-9a-f]+", offset) is None or
                            not 0 < int(offset, 16) < 96284520
                            for offset in offsets) or
                        type(value.get("caller_chain_anchor_found")) is not bool or
                        type(value.get("caller_chain_truncated")) is not bool):
                        raise RuntimeError("caller_chain_contract_failed")
                    if not value["caller_chain_anchor_found"] and offsets:
                        raise RuntimeError("caller_chain_contract_failed")
                records.append(value)
    gpu_name_records = []
    if gpu_name_trace_path is not None:
        with open(gpu_name_trace_path,"r",encoding="utf-8") as stream:
            for line in stream:
                value = json.loads(line)
                expected_keys = {"command","transport","flags","params_size",
                                 "ioctl_result","embedded_status","caller_image",
                                 "caller_offset","caller_chain_offsets",
                                 "caller_chain_anchor_found","caller_chain_truncated"}
                if set(value) != expected_keys:
                    raise RuntimeError("gpu_name_caller_trace_contract_failed")
                gpu_name_records.append(value)
    return {"cuda":cuda,"probe_exit_code":exit_code,"ioctl_records":records,
            "gpu_name_string_records":gpu_name_records,
            "stdout_bytes":len(completed.stdout) if completed is not None else None,
            "stdout_sha256":hashlib.sha256(completed.stdout).hexdigest() if completed is not None else None,
            "stderr_bytes":len(completed.stderr) if completed is not None else None,
            "stderr_sha256":hashlib.sha256(completed.stderr).hexdigest() if completed is not None else None}
def main():
    schema = ("nvidia-hybrid-v100-system-features-kernel-sensitivity-guest-v1"
              if WORKLOAD == "sm70-kernel" else
              "nvidia-hybrid-v100-system-features-ipc-sensitivity-guest-v1"
              if WORKLOAD == "ipc-memory-share" else
              "nvidia-hybrid-v100-system-features-vmm-fabric-sensitivity-guest-v1"
              if WORKLOAD == "vmm-fabric-share" else
              "nvidia-hybrid-v100-system-features-vmm-posix-sensitivity-guest-v1"
              if WORKLOAD == "vmm-posix-share" else
              "nvidia-hybrid-v100-system-features-sensitivity-guest-v1")
    report = {"schema":schema, "workload":WORKLOAD,
              "hostname":os.uname().nodename, "kernel_release":os.uname().release,
              "caller_chain_capture_requested":CAPTURE_CALLER_CHAIN,
              "gpu_name_caller_trace_requested":CAPTURE_GPU_NAME_CALLERS,
              "gpu_compute_processes_before":[], "gpu_compute_processes_after":[],
              "controls":[], "runs":[], "cleanup_passed":False, "driver_or_module_changed":False,
              "gpu_reset_requested":False,
              "execution_scope":{"read_only":True,"experimental_module_loaded":False,
                  "stock_driver_changed":False,"pci_binding_changed":False,
                  "vm_management_issued":False,"gpu_reset_requested":False}}
    if WORKLOAD == "sm70-kernel":
        report["kernel_artifacts"] = {
            "probe_source_sha256":KERNEL_PROBE_SOURCE_SHA256,
            "sm70_cubin_sha256":KERNEL_SM70_CUBIN_SHA256,
        }
    elif WORKLOAD == "ipc-memory-share":
        report["ipc_artifacts"] = {"probe_source_sha256":IPC_PROBE_SOURCE_SHA256}
    elif WORKLOAD == "vmm-fabric-share":
        report["vmm_fabric_artifacts"] = {"probe_source_sha256":VMM_FABRIC_PROBE_SOURCE_SHA256}
    elif WORKLOAD == "vmm-posix-share":
        report["vmm_posix_artifacts"] = {"probe_source_sha256":VMM_FABRIC_PROBE_SOURCE_SHA256}
    temp_dir = None
    failure_stage = "preflight"
    try:
        if os.geteuid() != 0: raise RuntimeError("root_identity_required")
        if os.uname().machine != "x86_64": raise RuntimeError("x86_64_abi_required")
        if report["hostname"].split(".")[0] != "pc3-v100": raise RuntimeError("unexpected_guest_identity")
        gpu_rows = gpus()
        if len(gpu_rows) != 1: raise RuntimeError("unexpected_gpu_count")
        report["gpu"] = gpu_rows[0]
        if (gpu_rows[0]["name"].startswith("Tesla V100") is False or
            gpu_rows[0]["uuid"] != "GPU-42d06a85-027a-75ea-7857-a8de27ad465e" or
            gpu_rows[0]["pci"] != "0000:00:05.0" or gpu_rows[0]["driver_version"] != "580.178.04"):
            raise RuntimeError("unexpected_v100_identity")
        report["gpu_compute_processes_before"] = compute_pids()
        if report["gpu_compute_processes_before"]: raise RuntimeError("gpu_compute_process_active")
        module_before = module_identity()
        if not module_before["loaded"] or module_before["version"] != "580.178.04":
            raise RuntimeError("unexpected_loaded_driver_module")
        libcuda_path = Path(LIBCUDA)
        if not libcuda_path.is_file(): raise RuntimeError("pinned_libcuda_missing")
        resolved_libcuda = libcuda_path.resolve(strict=True)
        libcuda_hash = digest_file(resolved_libcuda)
        if libcuda_hash != "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9":
            raise RuntimeError("pinned_libcuda_hash_mismatch")
        report["libcuda"] = {"path":str(resolved_libcuda),"sha256":libcuda_hash,"driver_api":13000}
        temp_dir = tempfile.mkdtemp(prefix="codex-v100-feature-mask-")
        os.chmod(temp_dir, 0o700)
        shim = base64.b64decode(SHIM_B64, validate=True)
        if hashlib.sha256(shim).hexdigest() != SHIM_SHA256: raise RuntimeError("shim_hash_mismatch")
        shim_path = os.path.join(temp_dir, "feature-mask-override.so")
        write_private(shim_path, shim)
        probe_code = base64.b64decode(PROBE_B64, validate=True).decode("utf-8", "strict")
        failure_stage = "control_runs"
        stock_env = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"}
        passthrough_env = dict(stock_env, LD_PRELOAD=shim_path)
        passthrough_name_trace = None
        if CAPTURE_GPU_NAME_CALLERS:
            passthrough_name_trace = os.path.join(temp_dir,"preload-passthrough-gpu-name.jsonl")
            write_private(passthrough_name_trace,b"")
            passthrough_env["HYBRID_GPU_NAME_CALLER_TRACE_PATH"] = passthrough_name_trace
        for mode, env in (("stock",stock_env),("preload_passthrough",passthrough_env)):
            outcome = execute_probe(
                probe_code,env,
                gpu_name_trace_path=(passthrough_name_trace
                                     if mode == "preload_passthrough" else None))
            report["controls"].append({"mode":mode,"probe_exit_code":outcome["probe_exit_code"],
                                       "cuda":outcome["cuda"],
                                       **({"gpu_name_string_records":outcome["gpu_name_string_records"]}
                                          if CAPTURE_GPU_NAME_CALLERS else {}),
                                       "stdout_bytes":outcome["stdout_bytes"],
                                       "stdout_sha256":outcome["stdout_sha256"],
                                       "stderr_bytes":outcome["stderr_bytes"],
                                       "stderr_sha256":outcome["stderr_sha256"]})
        failure_stage = "mask_runs"
        for mask in MASKS:
            trace = os.path.join(temp_dir, "mask-%x.jsonl" % mask)
            write_private(trace, b"")
            gpu_name_trace = None
            env = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C",
                   "LD_PRELOAD":shim_path,"HYBRID_FEATURES_MASK_OVERRIDE":hex(mask),
                   "HYBRID_FEATURES_TRACE_PATH":trace}
            if CAPTURE_GPU_NAME_CALLERS:
                gpu_name_trace = os.path.join(temp_dir,"mask-%x-gpu-name.jsonl" % mask)
                write_private(gpu_name_trace,b"")
                env["HYBRID_GPU_NAME_CALLER_TRACE_PATH"] = gpu_name_trace
            if CAPTURE_CALLER_CHAIN:
                env["HYBRID_FEATURES_CAPTURE_CALL_CHAIN"] = "1"
            outcome = execute_probe(probe_code,env,trace,CAPTURE_CALLER_CHAIN,
                                    gpu_name_trace)
            report["runs"].append({"requested_mask":mask,
                                    "ioctl_records":outcome["ioctl_records"],
                                    **({"gpu_name_string_records":outcome["gpu_name_string_records"]}
                                       if CAPTURE_GPU_NAME_CALLERS else {}),
                                    "cuda":outcome["cuda"],
                                    "probe_exit_code":outcome["probe_exit_code"],
                                    "stdout_bytes":outcome["stdout_bytes"],
                                    "stdout_sha256":outcome["stdout_sha256"],
                                    "stderr_bytes":outcome["stderr_bytes"],
                                    "stderr_sha256":outcome["stderr_sha256"]})
        failure_stage = "postflight"
        report["gpu_compute_processes_after"] = compute_pids()
        if report["gpu_compute_processes_after"]: raise RuntimeError("gpu_compute_process_started")
        report["driver_or_module_changed"] = (module_identity() != module_before or
                                              gpus() != gpu_rows)
        report["cleanup_passed"] = True
        report["module_identity_before"] = module_before
        report["module_identity_after"] = module_identity()
        report["status"] = "observed"
    except Exception as exc:
        report["status"] = "failed"
        report["failure_stage"] = failure_stage
        report["error_class"] = type(exc).__name__
    finally:
        if temp_dir is not None:
            try: shutil.rmtree(temp_dir)
            except OSError: report["cleanup_passed"] = False
            report["temporary_payload_remaining"] = os.path.exists(temp_dir)
            if report["temporary_payload_remaining"]: report["cleanup_passed"] = False
        else:
            report["temporary_payload_remaining"] = False
    print(json.dumps(report, sort_keys=True))
main()
'''


def load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load helper {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_pinned_script(name: str, path: Path, expected_sha256: str):
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError(f"pinned helper hash mismatch for {path.name}: {actual}")
    return load_script(name, path)


def compile_shim(directory: Path) -> Path:
    if not SOURCE.is_file() or not UPSTREAM.is_dir():
        raise FileNotFoundError("pinned R580 source or interposer source is missing")
    output = directory / "system-features-mask-override.so"
    includes = ["-I" + str(UPSTREAM / item) for item in INCLUDE_PARTS]
    command = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
               "-fPIC", "-shared", "-Wl,-z,relro,-z,now", *includes,
               str(SOURCE), "-ldl", "-o", str(output)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=45, check=False)
    if result.returncode:
        raise RuntimeError("strict local interposer build failed")
    return output


def make_kernel_probe_code() -> str:
    """Embed the exact probe source and current SM70 cubin into the bounded guest job."""
    assets: list[tuple[Path, str, int]] = [
        (KERNEL_PROBE_SOURCE, KERNEL_PROBE_SOURCE_SHA256, 32 * 1024),
        (KERNEL_SM70_CUBIN, KERNEL_SM70_CUBIN_SHA256, 32 * 1024),
    ]
    data_values: list[bytes] = []
    for path, expected_sha256, max_bytes in assets:
        if path.is_symlink() or not path.is_file():
            raise ValueError("pinned V100 kernel-probe artifact is missing or redirected")
        data = path.read_bytes()
        if not 1 <= len(data) <= max_bytes or sha256_bytes(data) != expected_sha256:
            raise ValueError("pinned V100 kernel-probe artifact failed its hash/size check")
        data_values.append(data)
    source = data_values[0].decode("utf-8", "strict")
    replacements = {
        "__LIBCUDA_PATH__": EXPECTED_LIBCUDA,
        "__CUBIN_B64__": base64.b64encode(data_values[1]).decode("ascii"),
        "__CUBIN_SHA256__": KERNEL_SM70_CUBIN_SHA256,
    }
    code = source
    for key, value in replacements.items():
        code = code.replace(key, value)
    if any(token in code for token in replacements):
        raise ValueError("unexpanded kernel probe payload token")
    return code


def make_ipc_probe_code() -> str:
    """Embed the exact, hash-pinned two-process Driver API IPC probe."""
    if IPC_PROBE_SOURCE.is_symlink() or not IPC_PROBE_SOURCE.is_file():
        raise ValueError("pinned V100 IPC-probe source is missing or redirected")
    data = IPC_PROBE_SOURCE.read_bytes()
    if not 1 <= len(data) <= 64 * 1024 or sha256_bytes(data) != IPC_PROBE_SOURCE_SHA256:
        raise ValueError("pinned V100 IPC-probe source failed its hash/size check")
    source = data.decode("utf-8", "strict")
    code = source.replace("__LIBCUDA_PATH__", EXPECTED_LIBCUDA)
    if "__LIBCUDA_PATH__" in code:
        raise ValueError("unexpanded IPC-probe library token")
    return code


def make_vmm_fabric_probe_code() -> str:
    """Embed the hash-pinned two-process CUDA VMM shareable-handle probe."""
    if VMM_FABRIC_PROBE_SOURCE.is_symlink() or not VMM_FABRIC_PROBE_SOURCE.is_file():
        raise ValueError("pinned V100 VMM/FABRIC probe source is missing or redirected")
    data = VMM_FABRIC_PROBE_SOURCE.read_bytes()
    if (not 1 <= len(data) <= 64 * 1024 or
            sha256_bytes(data) != VMM_FABRIC_PROBE_SOURCE_SHA256):
        raise ValueError("pinned V100 VMM/FABRIC probe source failed its hash/size check")
    code = data.decode("utf-8", "strict").replace("__LIBCUDA_PATH__", EXPECTED_LIBCUDA)
    if "__LIBCUDA_PATH__" in code:
        raise ValueError("unexpanded VMM/FABRIC-probe library token")
    return code


def make_guest_code(shim: Path, capture_caller_chain: bool = False,
                    workload: str = "enumeration",
                    capture_gpu_name_callers: bool = False) -> str:
    if workload not in ("enumeration", "sm70-kernel", "ipc-memory-share",
                        "vmm-fabric-share", "vmm-posix-share"):
        raise ValueError("unsupported V100 sensitivity workload")
    if workload != "enumeration" and capture_caller_chain:
        raise ValueError("caller-chain capture is a separate experiment")
    if workload != "enumeration" and capture_gpu_name_callers:
        raise ValueError("GPU name caller capture applies only to enumeration")
    if workload == "enumeration":
        probe = CUDA_PROBE.replace("__LIBCUDA_PATH__", EXPECTED_LIBCUDA)
    elif workload == "sm70-kernel":
        probe = make_kernel_probe_code()
    elif workload == "ipc-memory-share":
        probe = make_ipc_probe_code()
    else:
        probe = make_vmm_fabric_probe_code()
    shim_bytes = shim.read_bytes()
    replacements = {
        "__LIBCUDA_PATH__": EXPECTED_LIBCUDA,
        "__VMM_EXPECTED_PCI__": EXPECTED_PCI,
        "__SHIM_B64__": base64.b64encode(shim_bytes).decode("ascii"),
        "__SHIM_SHA256__": sha256_bytes(shim_bytes),
        "__PROBE_B64__": base64.b64encode(probe.encode("utf-8")).decode("ascii"),
        "__CAPTURE_CALLER_CHAIN__": "True" if capture_caller_chain else "False",
        "__CAPTURE_GPU_NAME_CALLERS__": "True" if capture_gpu_name_callers else "False",
        "__WORKLOAD__": workload,
        "__PROBE_TIMEOUT__": ("25" if workload == "enumeration" else
                              "100" if workload in ("ipc-memory-share", "vmm-fabric-share",
                                                     "vmm-posix-share") else "75"),
        "__KERNEL_PROBE_SOURCE_SHA256__": (KERNEL_PROBE_SOURCE_SHA256
                                            if workload == "sm70-kernel" else "not-applicable"),
        "__KERNEL_SM70_CUBIN_SHA256__": (KERNEL_SM70_CUBIN_SHA256
                                         if workload == "sm70-kernel" else "not-applicable"),
        "__IPC_PROBE_SOURCE_SHA256__": (IPC_PROBE_SOURCE_SHA256
                                        if workload == "ipc-memory-share" else "not-applicable"),
        "__VMM_FABRIC_PROBE_SOURCE_SHA256__": (
            VMM_FABRIC_PROBE_SOURCE_SHA256 if workload in ("vmm-fabric-share", "vmm-posix-share")
            else "not-applicable"),
    }
    code = GUEST_TEMPLATE
    for key, value in replacements.items():
        code = code.replace(key, value)
    if any(token in code for token in replacements):
        raise ValueError("unexpanded guest-code template token")
    if len(code.encode("utf-8")) > 120_000:
        raise ValueError("guest execution payload exceeds the bounded SSH argument budget")
    return code


def validate_remote_report(report: object) -> dict[str, object]:
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-pc3-v100-trace-capability-v3":
        raise ValueError("PC3-to-guest transport report is missing")
    host = report.get("host")
    if (report.get("status") != "observed" or not isinstance(host, dict) or
            host.get("hostname", "").split(".")[0] != "pc3" or
            host.get("sudo_identity_verified") is not True or
            host.get("guest_host_key_verified") is not True):
        raise ValueError("PC3 identity or strict V100 guest host-key verification failed")
    if report.get("read_only") is not True or any(report.get(key) is not False for key in (
        "experimental_module_loaded", "stock_driver_changed", "pci_binding_changed",
        "vm_management_issued", "kprobe_attached")):
        raise ValueError("PC3 guest transport left the authorized read-only scope")
    guest = report.get("guest")
    if isinstance(guest, dict) and guest.get("schema") == \
            "nvidia-hybrid-v100-system-features-kernel-sensitivity-guest-v1":
        validated = validate_guest_kernel_sensitivity(guest)
    elif isinstance(guest, dict) and guest.get("schema") == \
            "nvidia-hybrid-v100-system-features-ipc-sensitivity-guest-v1":
        validated = validate_guest_ipc_sensitivity(guest)
    elif isinstance(guest, dict) and guest.get("schema") == \
            "nvidia-hybrid-v100-system-features-vmm-fabric-sensitivity-guest-v1":
        validated = validate_guest_vmm_fabric_sensitivity(guest)
    elif isinstance(guest, dict) and guest.get("schema") == \
            "nvidia-hybrid-v100-system-features-vmm-posix-sensitivity-guest-v1":
        validated = validate_guest_vmm_fabric_sensitivity(guest)
    else:
        validated = validate_guest_sensitivity(guest)
    return {"transport": {"host": host, "read_only": True,
                           "experimental_module_loaded": False,
                           "stock_driver_changed": False,
                           "pci_binding_changed": False,
                           "vm_management_issued": False,
                           "kprobe_attached": False},
            "guest": guest, **validated}


def write_private_new(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def run(args: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_prefix = ("pc3-v100-system-features-kernel-sensitivity-v1" if
                       args.workload == "sm70-kernel" else
                       "pc3-v100-cuda-ipc-sensitivity-v1" if
                       args.workload == "ipc-memory-share" else
                       "pc3-v100-cuda-vmm-posix-sensitivity-v1" if
                       args.workload == "vmm-posix-share" else
                       "pc3-v100-cuda-vmm-fabric-sensitivity-v1" if
                       args.workload == "vmm-fabric-share" else
                       "pc3-v100-system-features-sensitivity-v1")
    evidence = args.evidence or ROOT / "evidence" / f"{evidence_prefix}-{now}.json"
    report: dict[str, object] = {
        "schema": ("nvidia-hybrid-v100-system-features-kernel-sensitivity-v1" if
                    args.workload == "sm70-kernel" else
                    "nvidia-hybrid-pc3-v100-cuda-ipc-sensitivity-v1" if
                    args.workload == "ipc-memory-share" else
                    "nvidia-hybrid-pc3-v100-cuda-vmm-posix-sensitivity-v1" if
                    args.workload == "vmm-posix-share" else
                    "nvidia-hybrid-pc3-v100-cuda-vmm-fabric-sensitivity-v1" if
                    args.workload == "vmm-fabric-share" else
                    "nvidia-hybrid-v100-system-features-sensitivity-v1"),
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": args.target, "workload": args.workload,
        "masks": list(MASKS), "status": "failed",
        "execution_scope": {"system_module_loaded_or_changed": False,
                            "pci_binding_changed": False, "firmware_changed": False,
                            "gpu_reset_requested": False},
        "credential_value_logged": False, "credential_value_persisted": False,
        "runner_sha256": sha256_file(Path(__file__)),
        "caller_chain_capture_requested": args.capture_caller_chain,
        "gpu_name_caller_trace_requested": args.capture_gpu_name_callers,
        "interposer_source_sha256": sha256_file(SOURCE),
        "transport_helpers": {
            "trace_audit_sha256": TRACE_AUDIT_TOOL_SHA256,
            "reference_runner_sha256": REFERENCE_TOOL_SHA256,
        },
    }
    try:
        audit = load_pinned_script("pc3_v100_trace_capability_helper",
                                   TRACE_AUDIT_TOOL, TRACE_AUDIT_TOOL_SHA256)
        reference = load_pinned_script("pc3_v100_reference_transport",
                                       REFERENCE_TOOL, REFERENCE_TOOL_SHA256)
        with tempfile.TemporaryDirectory(prefix="v100-features-shim-") as temp:
            shim = compile_shim(Path(temp))
            shim_hash = sha256_file(shim)
            guest_code = make_guest_code(shim, args.capture_caller_chain, args.workload,
                                         args.capture_gpu_name_callers)
            remote_script = audit.remote_root_script(
                guest_code, reference.EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
                reference.DEFAULT_GUEST_KEY, reference.DEFAULT_GUEST_KNOWN_HOSTS,
                read_only=True, trace_event_definition_write_attempted=False)
            report["interposer"] = {"sha256": shim_hash, "bytes": shim.stat().st_size,
                                    "compiled_with": "cc -std=gnu11 -Wall -Wextra -Werror -DNVRM=1 -fPIC -shared"}
            report["remote_guest_code_sha256"] = sha256_bytes(guest_code.encode())
            report["remote_script_sha256"] = sha256_bytes(remote_script.encode())
            secret = reference.fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
            remote_command = "sudo -S -p '' python3 -c " + shlex.quote(remote_script)
            try:
                completed = subprocess.run(
                    reference.pc3_ssh_base(args.target, args.host_key_alias) + [remote_command],
                    input=reference.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=240, check=False,
                    env=audit.pc3_ssh_environment(os.environ))
            finally:
                secret = None
            report["transport_io"] = {
                "returncode": completed.returncode,
                "stdout_bytes": len(completed.stdout),
                "stdout_sha256": sha256_bytes(completed.stdout),
                "stderr_bytes": len(completed.stderr),
                "stderr_sha256": sha256_bytes(completed.stderr),
            }
            if completed.returncode != 0:
                raise RuntimeError("PC3 guarded guest execution failed")
            remote_report = json.loads(completed.stdout.decode("utf-8", "strict"))
            report["remote_report"] = remote_report
            validated = validate_remote_report(remote_report)
            report["transport"] = validated["transport"]
            report["guest"] = validated["guest"]
            report["runs"] = validated["runs"]
            report["complete"] = validated["complete"]
            report["api_outcomes_equal"] = validated["api_outcomes_equal"]
            report["control_outcomes_equal"] = validated["control_outcomes_equal"]
            report["caller_chain_capture_requested"] = validated["caller_chain_capture_requested"]
            report["gpu_name_caller_trace_requested"] = validated[
                "gpu_name_caller_trace_requested"]
            report["gpu_name_caller_trace_complete"] = validated[
                "gpu_name_caller_trace_complete"]
            report["gpu_name_trace_stage_deltas"] = validated[
                "gpu_name_trace_stage_deltas"]
            if args.workload == "sm70-kernel":
                report["kernel_phase_passed_for_all_masks"] = \
                    validated["kernel_phase_passed_for_all_masks"]
            elif args.workload == "ipc-memory-share":
                report["ipc_succeeded_for_all_masks"] = validated["ipc_succeeded_for_all_masks"]
                report["ipc_outcomes_equal"] = validated["ipc_outcomes_equal"]
                report["mask_9_vs_1_outcomes_equal"] = validated["mask_9_vs_1_outcomes_equal"]
                report["ipc_transfer_outcomes_equal"] = validated["ipc_transfer_outcomes_equal"]
                report["device_capability_outcomes_equal"] = validated["device_capability_outcomes_equal"]
                report["mask_9_vs_1_fabric_capability_equal"] = \
                    validated["mask_9_vs_1_fabric_capability_equal"]
                report["capability_queries_complete"] = validated["capability_queries_complete"]
                report["all_process_capability_pairs_equal"] = \
                    validated["all_process_capability_pairs_equal"]
            elif args.workload in ("vmm-fabric-share", "vmm-posix-share"):
                for key in ("vmm_share_kind", "vmm_share_succeeded_for_all_masks",
                            "vmm_share_transfer_outcomes_equal", "vmm_share_capability_outcomes_equal",
                            "mask_9_vs_1_vmm_share_transfer_equal", "mask_9_vs_1_handle_capability_equal",
                            "capability_queries_complete", "all_process_capability_pairs_equal"):
                    report[key] = validated[key]
                if args.workload == "vmm-fabric-share":
                    for key in ("vmm_fabric_succeeded_for_all_masks",
                                "vmm_fabric_transfer_outcomes_equal",
                                "vmm_fabric_capability_outcomes_equal",
                                "mask_9_vs_1_vmm_fabric_transfer_equal",
                                "mask_9_vs_1_fabric_capability_equal"):
                        report[key] = validated[key]
            report["status"] = "complete" if validated["complete"] else "incomplete"
        write_private_new(evidence, report)
        print(json.dumps({"evidence": str(evidence), "status": report["status"],
                          "complete": report.get("complete"),
                          "api_outcomes_equal": report.get("api_outcomes_equal"),
                          "report_sha256": sha256_file(evidence)}, indent=2))
        return 0 if report["status"] == "complete" else 1
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        report["error"] = str(exc)[:300]
        try:
            write_private_new(evidence, report)
            print(json.dumps({"evidence": str(evidence), "status": "failed",
                              "error_class": report["error_class"],
                              "report_sha256": sha256_file(evidence)}, indent=2), file=sys.stderr)
        except FileExistsError:
            print("evidence destination already exists; refusing to overwrite", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    parser.add_argument("--credential-host", default="gx10-e526")
    parser.add_argument("--credential-file", default="/home/pc6/Desktop/ACCES-BANC-GPU.env")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--workload", choices=("enumeration", "sm70-kernel", "ipc-memory-share",
                                                 "vmm-fabric-share", "vmm-posix-share"),
                        default="enumeration",
                        help="test enumeration, SM70 kernels, legacy IPC, or VMM FABRIC/POSIX-FD sharing")
    parser.add_argument("--capture-caller-chain", action="store_true",
                        help="record at most eight same-image return offsets for each overridden ioctl")
    parser.add_argument("--capture-gpu-name-callers", action="store_true",
                        help="trace only redacted R580 GPU_GET_NAME_STRING caller locations")
    args = parser.parse_args(argv)
    if args.workload != "enumeration" and args.capture_caller_chain:
        parser.error("--capture-caller-chain applies only to enumeration workload")
    if args.workload != "enumeration" and args.capture_gpu_name_callers:
        parser.error("--capture-gpu-name-callers applies only to enumeration workload")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
