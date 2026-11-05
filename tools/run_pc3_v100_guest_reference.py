#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the SM70 numerical reference inside PC3's existing V100 guest.

The default transport gets sudo auth from the historical PC6 credential path.
Use --direct-pc3 to require the local SSH key plus PC3 sudo -n; it never
contacts PC6. The runner may stage and remove a temporary test payload; it does
not install a driver or change VM, PCI-binding, firmware, or boot state.
"""
from __future__ import annotations

import argparse
import base64
import configparser
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
_probe_contract_spec = importlib.util.spec_from_file_location(
    "nvidia_hybrid_probe_contract", ROOT / "tools/cuda_probe_contract.py")
if _probe_contract_spec is None or _probe_contract_spec.loader is None:
    raise RuntimeError("CUDA probe contract helper is unavailable")
_probe_contract_module = importlib.util.module_from_spec(_probe_contract_spec)
_probe_contract_spec.loader.exec_module(_probe_contract_module)
validate_probe_contract = _probe_contract_module.validate_probe_contract
validate_performance_benchmark_report = _probe_contract_module.validate_performance_benchmark_report
validate_graph_api_claim = _probe_contract_module.validate_graph_api_claim
SIZES = [1, 31, 256, 4096, 65537]
DEFAULT_PROBE = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe"
DEFAULT_MODULE = ROOT / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin"
PINNED_PROBE_SHA256 = "c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422"
PINNED_MODULE_SHA256 = "8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70"
DEFAULT_CREDENTIAL_HOST = "gx10-e526"
DEFAULT_CREDENTIAL_FILE = "/home/pc6/Desktop/ACCES-BANC-GPU.env"
DEFAULT_PC3_TARGET = "pc3@pc3"
DEFAULT_HOST_KEY_ALIAS = "pc3"
DEFAULT_GUEST_KEY = "/var/lib/pc3-v100-vm/id_ed25519"
DEFAULT_GUEST_KNOWN_HOSTS = "/tmp/codex-pc3-vm-known_hosts"
EXPECTED_GUEST_HOSTKEY_FINGERPRINT = "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
R580_19607_LIBCUDA_BYTES = 96300904
R580_19607_LIBCUDA_SHA256 = "a5c77bf2de83c0ec06ecd368d224c3e0d653d658d6f99319921e976f21867b14"
P2P_FAULT_MODES = ("alloc", "register-va", "register-vidmem", "unregister-vidmem")


def canonical_pci(value: str) -> str:
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match:
        raise ValueError("invalid PCI identity")
    domain, bus, slot, function = match.groups()
    if int(slot, 16) > 31:
        raise ValueError("invalid PCI identity")
    return f"{int(domain, 16) & 0xffff:04x}:{int(bus, 16):02x}:{int(slot, 16):02x}.{int(function, 16)}"


def validate_sudo_secret(value: str) -> str:
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value or "\0" in value:
        raise ValueError("PC3 sudo credential is missing or malformed")
    return value


def redact_secret(text: str, secret: str | None) -> str:
    if not secret or len(secret) < 4:
        return "[omitted]"
    return text.replace(secret, "[REDACTED]")[:2000]


def classify_pc3_transport_failure(stderr: bytes | str) -> str | None:
    """Return a fixed, non-sensitive transport failure category, never raw output."""
    if isinstance(stderr, bytes):
        text = stderr.decode("utf-8", "replace").lower()
    elif isinstance(stderr, str):
        text = stderr.lower()
    else:
        return None
    if not text.strip():
        return None
    if re.search(r"sudo:.*(?:interactive authentication is required|a password is required)", text):
        return "sudo_interactive_auth_required"
    if re.search(r"permission denied\s*\([^)]*publickey[^)]*\)", text):
        return "ssh_public_key_auth_denied"
    if "connection timed out" in text or "operation timed out" in text:
        return "ssh_connection_timed_out"
    if "no route to host" in text or "network is unreachable" in text:
        return "ssh_network_unreachable"
    if "could not resolve hostname" in text or "temporary failure in name resolution" in text:
        return "ssh_hostname_unresolved"
    if "connection refused" in text:
        return "ssh_connection_refused"
    return "unclassified_transport_failure"


def payload_upload_failure_fields(returncode: int | None, stderr: bytes | str = b"",
                                  process_failure: str | None = None) -> dict[str, object]:
    """Describe a failed SSH upload without retaining its output or credentials."""
    if isinstance(stderr, bytes):
        raw_stderr = stderr
    elif isinstance(stderr, str):
        raw_stderr = stderr.encode("utf-8", "replace")
    else:
        raw_stderr = b""
    if process_failure == "timeout":
        failure_class = "ssh_process_timed_out"
    elif process_failure == "start":
        failure_class = "ssh_process_start_failed"
    else:
        failure_class = (classify_pc3_transport_failure(raw_stderr) or
                         "ssh_failed_without_classifiable_stderr")
    return {
        "failure_stage": "pc3_payload_upload",
        "pc3_upload_ssh_exit_code": returncode,
        "pc3_upload_failure_class": failure_class,
        "pc3_upload_stderr_sha256": hashlib.sha256(raw_stderr).hexdigest(),
    }


def direct_pc3_preflight(ssh_base: list[str]) -> dict[str, object]:
    """Verify the pinned PC3 route and noninteractive sudo before staging payloads."""
    checks = (
        ("ssh", "true"),
        ("sudo", "sudo -n true"),
    )
    passed: dict[str, object] = {}
    for name, remote_command in checks:
        try:
            result = subprocess.run(
                ssh_base + [remote_command], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False)
        except subprocess.TimeoutExpired as error:
            stderr = error.stderr or b""
            process_failure = "timeout"
            returncode = None
        except OSError:
            stderr = b""
            process_failure = "start"
            returncode = None
        else:
            stderr = result.stderr
            process_failure = None
            returncode = result.returncode
        if returncode != 0:
            if isinstance(stderr, str):
                raw_stderr = stderr.encode("utf-8", "replace")
            elif isinstance(stderr, bytes):
                raw_stderr = stderr
            else:
                raw_stderr = b""
            if process_failure == "timeout":
                failure_class = "ssh_process_timed_out"
            elif process_failure == "start":
                failure_class = "ssh_process_start_failed"
            else:
                failure_class = (classify_pc3_transport_failure(raw_stderr) or
                                 "ssh_failed_without_classifiable_stderr")
            return {
                **passed,
                f"pc3_{name}_preflight_passed": False,
                "failure_stage": f"pc3_{name}_preflight",
                f"pc3_{name}_preflight_exit_code": returncode,
                f"pc3_{name}_preflight_failure_class": failure_class,
                f"pc3_{name}_preflight_stderr_sha256": hashlib.sha256(raw_stderr).hexdigest(),
            }
        passed[f"pc3_{name}_preflight_passed"] = True
    return passed


def redact_nested(value: object, secret: str | None) -> object:
    if not secret:
        return value
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]")
    if isinstance(value, list):
        return [redact_nested(item, secret) for item in value]
    if isinstance(value, dict):
        return {redact_nested(key, secret): redact_nested(item, secret) for key, item in value.items()}
    return value


def parse_pc3_sudo_secret(contents: str) -> str:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(contents)
        value = parser.get("pc3", "password_sudo", raw=True).strip()
    except (configparser.Error, KeyError, ValueError):
        raise ValueError("PC3 sudo credential is unavailable in its authorized file") from None
    return validate_sudo_secret(value)


def validate_v100_reference(report: object, exit_code: int, expected_pci: str,
                            managed_memory: bool = False,
                            managed_prefetch: bool = False,
                            cuda_graphs: bool = False,
                            performance_benchmark: bool = False) -> str:
    """Accept only a complete single-device SM70 reference, never a hybrid claim."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    pci = canonical_pci(expected_pci)
    require(isinstance(report, dict), "probe report must be an object")
    require(exit_code == 0, "SM70 probe did not exit successfully")
    require(report.get("schema") == "nvidia-hybrid-probe-v2", "unsupported probe schema")
    expected_memory_mode = "managed" if managed_memory else "device"
    require(not managed_prefetch or managed_memory,
            "managed-prefetch requires managed-memory mode")
    require(report.get("memory_mode") == expected_memory_mode,
            "memory mode differs from the requested reference")
    require(report.get("managed_prefetch_requested") is managed_prefetch,
            "managed-prefetch mode differs from the requested reference")
    prefetch_api = report.get("managed_prefetch_api")
    if managed_prefetch:
        require(prefetch_api in ("cuMemPrefetchAsync_v2", "cuMemPrefetchAsync"),
                "V100 managed-prefetch API was unavailable or unidentified")
    else:
        require(prefetch_api == "not-requested",
                "unrequested V100 managed-prefetch API claim")
    require(report.get("cuda_graphs_requested") is cuda_graphs,
            "CUDA Graph mode differs from the requested reference")
    validate_performance_benchmark_report(report, performance_benchmark)
    graph_api = report.get("cuda_graph_api")
    validate_graph_api_claim(graph_api, cuda_graphs, performance_benchmark)
    require(report.get("status") == "control-passed", "single-device SM70 reference was not classified as control-passed")
    require(report.get("required_sm") == [70] and report.get("missing_sm") == [], "probe did not test only present SM70")
    require(report.get("hybrid_validated") is False, "single-device reference must not claim hybrid validation")
    require(report.get("required_set_passed") is True, "SM70 required set did not pass")
    require(report.get("context_coexistence_passed") is False, "single-device reference cannot establish coexistence")
    require(report.get("execution_mode") == "resident-contexts-sequential-kernels", "unexpected execution mode")
    require(report.get("concurrent_kernel_execution_validated") is False, "sequential probe cannot establish concurrent kernels")
    require(type(report.get("driver_api")) is int and report["driver_api"] > 0, "invalid CUDA Driver API version")
    library = report.get("driver_library_path")
    require(isinstance(library, str) and Path(library).is_absolute(), "missing resolved libcuda path")
    devices = report.get("devices")
    require(isinstance(devices, list) and len(devices) == 1, "expected exactly one visible GPU")
    device = devices[0]
    require(device.get("name", "").startswith("Tesla V100"), "selected device is not a Tesla V100")
    require(device.get("sm") == 70 and device.get("compute_capability") == "7.0", "selected GPU is not SM70")
    require(canonical_pci(device.get("pci_bus_id", "")) == pci, "probe PCI identity differs from guest inventory")
    for capability in ("concurrent_managed_access", "pageable_memory_access",
                       "pageable_memory_access_uses_host_page_tables"):
        require(type(device.get(capability)) is bool,
                f"V100 reference is missing boolean {capability}")
    require(device.get("targeted") is True and device.get("tested") is True, "SM70 device was not targeted")
    require(device.get("architecture_kernel_passed") is True, "SM70 kernel failed")
    for phase in ("synchronous", "asynchronous"):
        require(device.get(phase + "_passed") is True, phase + " CUDA path failed")
        require(device.get(phase + "_sizes") == SIZES, phase + " path did not test all required sizes")
    require(device.get("cleanup_passed") is True and device.get("cleanup_errors") == [], "CUDA resource cleanup failed")
    require(device.get("managed_memory_passed") is managed_memory,
            "managed-memory result differs from the requested reference")
    require(device.get("managed_prefetch_passed") is managed_prefetch,
            "managed-prefetch result differs from the requested reference")
    require(device.get("cuda_graphs_passed") is cuda_graphs,
            "CUDA Graph result differs from the requested reference")
    require(device.get("cuda_graph_launches") == (2 if cuda_graphs else 0),
            "V100 CUDA Graph replay count differs from the requested reference")
    require(device.get("error") == "", "probe reported a device error")
    return "v100-reference-report-contract-valid"


def validate_p2p_fault_diagnostics(stderr: object, expected_mode: str) -> int:
    """Require only denials from the requested P2P operation family."""
    if expected_mode not in P2P_FAULT_MODES:
        raise ValueError("unsupported P2P fault mode")
    if not isinstance(stderr, str):
        raise ValueError("P2P fault run has no probe stderr text")
    prefix = "HYBRID_RM_P2P_FAULT "
    diagnostic_lines = [line for line in stderr.splitlines() if line.startswith(prefix)]
    denied_prefix = prefix + "denied="
    expected = denied_prefix + expected_mode + " errno=EIO"
    if not diagnostic_lines or any(line != expected for line in diagnostic_lines):
        raise ValueError("probe did not report only the selected P2P fault")
    return len(diagnostic_lines)


def validate_cuda_phase_report(report: object, exit_code: int, expected_pci: str,
                               expected_phase: str) -> str:
    """Reuse the shared exact phase contract, then bind it to the V100 guest."""
    validator_path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_phase_validator", validator_path)
    if spec is None or spec.loader is None:
        raise ValueError("shared CUDA phase validator is unavailable")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    if expected_phase == "system-pageable-memory":
        return validator.validate_system_pageable_memory_report(
            report, exit_code, expected_pci, expected_name_fragment="Tesla V100",
            expected_sm=70, expected_compute_capability="7.0")
    qualification = validator.validate_phase_probe_report(
        report, exit_code, expected_pci, expected_phase)
    if expected_phase != "initialize":
        selected = report.get("selected_device")
        if (not isinstance(selected, dict) or selected.get("sm") != 70 or
                not selected.get("name", "").startswith("Tesla V100")):
            raise ValueError("CUDA phase did not target the Tesla V100 SM70 device")
    return qualification


def validate_device_alloc_capture(observed: dict) -> tuple[bool, int]:
    """Use the local acceptance runner's single redacted NV0080 contract."""
    validator_path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_device_alloc_validator",
                                                  validator_path)
    if spec is None or spec.loader is None:
        raise ValueError("shared NV01_DEVICE_0 allocation validator is unavailable")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    return validator.validate_device_alloc_observation(observed)


def validate_subdevice_alloc_capture(observed: dict) -> tuple[bool, int]:
    """Use the shared fixed, redacted NV2080 allocation contract."""
    validator_path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_subdevice_alloc_validator",
                                                  validator_path)
    if spec is None or spec.loader is None:
        raise ValueError("shared NV20_SUBDEVICE_0 allocation validator is unavailable")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    return validator.validate_subdevice_alloc_observation(observed)


def validate_binapi_alloc_capture(observed: dict) -> tuple[bool, int]:
    """Use the shared fixed, redacted NV2081 allocation contract."""
    validator_path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_binapi_alloc_validator",
                                                  validator_path)
    if spec is None or spec.loader is None:
        raise ValueError("shared NV2081_BINAPI allocation validator is unavailable")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    return validator.validate_binapi_alloc_observation(observed)


def validate_rm_control_headers_capture(observed: object) -> int:
    """Validate the fixed-header-only observer contract, including redaction."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict), "RM_CONTROL header observation is missing")
    require(observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v23",
            "RM_CONTROL header observation has the wrong schema")
    require(observed.get("trace_complete") is True and observed.get("errors") == [],
            "RM_CONTROL header observation is incomplete")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("architecture") == "x86_64" and
            observed.get("pointer_bits") == 64 and
            observed.get("nested_pointers_read") is False and
            observed.get("fd_identity_tracking") is False,
            "RM_CONTROL header observer exceeded its fixed read-only scope")
    require(observed.get("payload_scope") ==
            "fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted",
            "RM_CONTROL header observer has an unexpected payload scope")

    rows = observed.get("records")
    require(isinstance(rows, list) and bool(rows),
            "RM_CONTROL header observer returned no records")
    required_row_keys = {"tid", "fd", "fd_role", "request", "packet_size",
                         "operation", "entry", "exit", "syscall_return"}
    required_header_keys = {"command", "flags", "params_size", "status",
                            "hClientPresent", "hObjectPresent", "client_object_equal",
                            "client_matches_prior_root_allocation",
                            "object_matches_prior_root_allocation"}
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == required_row_keys,
                f"RM_CONTROL header record {index} contains unexpected fields")
        require(row.get("operation") == "rm_control_header" and
                row.get("request") == 0xC020462A and row.get("packet_size") == 32 and
                type(row.get("syscall_return")) is int and
                type(row.get("fd")) is int and row["fd"] >= 0 and
                type(row.get("tid")) is int and row["tid"] >= 0 and
                row.get("fd_role") == "control",
                f"RM_CONTROL header record {index} has an invalid ioctl envelope")
        for part in ("entry", "exit"):
            header = row.get(part)
            require(isinstance(header, dict) and set(header) == required_header_keys,
                    f"RM_CONTROL header record {index} does not redact handles")
            require(all(type(header.get(name)) is int and 0 <= header[name] <= 0xFFFFFFFF
                        for name in ("command", "flags", "params_size", "status")) and
                    all(type(header.get(name)) is bool for name in (
                        "hClientPresent", "hObjectPresent", "client_object_equal",
                        "client_matches_prior_root_allocation",
                        "object_matches_prior_root_allocation")),
                    f"RM_CONTROL header record {index} has invalid fixed fields")
    return len(rows)


def validate_fabric_status_capture(observed: object) -> tuple[int, list[int]]:
    """Validate the exact, redacted root-global Fabric Manager status capture."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict), "Fabric Status observation is missing")
    require(observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v24" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "Fabric Status observation is incomplete or has the wrong schema")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("architecture") == "x86_64" and
            observed.get("pointer_bits") == 64 and
            observed.get("nested_pointers_read") is True and
            observed.get("fd_identity_tracking") is False,
            "Fabric Status observer exceeded its read-only ABI boundary")
    require(observed.get("nested_pointer_scope") ==
            "exact NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS 4-byte enum only; raw addresses and handles omitted" and
            observed.get("payload_scope") ==
            "exact root-global Fabric Manager status enum plus fixed RM_CONTROL headers; raw addresses and handles omitted",
            "Fabric Status observer exceeded its exact payload scope")
    rows = observed.get("records")
    require(isinstance(rows, list) and bool(rows),
            "Fabric Status capture contains no successful root-global status ioctl")
    record_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                     "operation", "entry", "exit", "syscall_return"}
    header_fields = {"command", "flags", "params_size", "status", "hClientPresent",
                     "hObjectPresent", "client_object_equal",
                     "client_matches_prior_root_allocation",
                     "object_matches_prior_root_allocation", "fabricStatus"}
    known_statuses = {1, 2, 3, 4}
    exit_values = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == record_fields and
                row.get("operation") == "rm_control_fabric_status" and
                row.get("fd_role") == "control" and
                ((row.get("request") == 0xC020462A and row.get("packet_size") == 32) or
                 (row.get("request") == 0xC01046D3 and row.get("packet_size") == 16)) and
                type(row.get("tid")) is int and row["tid"] >= 0 and
                type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("syscall_return") == 0,
                f"Fabric Status record {index} has an invalid or failed ioctl envelope")
        for phase in ("entry", "exit"):
            header = row.get(phase)
            require(isinstance(header, dict) and set(header) == header_fields and
                    header.get("command") == 0x136 and header.get("flags") == 0 and
                    header.get("params_size") == 4 and
                    type(header.get("status")) is int and
                    0 <= header["status"] <= 0xFFFFFFFF and
                    (phase != "exit" or header.get("status") == 0) and
                    all(type(header.get(key)) is bool for key in (
                        "hClientPresent", "hObjectPresent", "client_object_equal",
                        "client_matches_prior_root_allocation",
                        "object_matches_prior_root_allocation")) and
                    type(header.get("fabricStatus")) is int and
                    header["fabricStatus"] in known_statuses and
                    "hClient" not in header and "hObject" not in header and
                    "params" not in header and "params_address" not in header,
                    f"Fabric Status record {index} has a malformed or unredacted payload")
        exit_values.append(row["exit"]["fabricStatus"])
    require(observed.get("fabric_status_payload_snapshots_read") == 2 * len(rows),
            "Fabric Status payload snapshot count differs from the ioctl records")
    return len(rows), exit_values


def validate_system_features_capture(observed: object) -> tuple[int, list[int]]:
    """Validate the exact, redacted root-global SYSTEM_GET_FEATURES mask capture."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict), "SYSTEM_GET_FEATURES observation is missing")
    require(observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v25" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "SYSTEM_GET_FEATURES observation is incomplete or has the wrong schema")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("architecture") == "x86_64" and
            observed.get("pointer_bits") == 64 and
            observed.get("nested_pointers_read") is True and
            observed.get("fd_identity_tracking") is False,
            "SYSTEM_GET_FEATURES observer exceeded its read-only ABI boundary")
    require(observed.get("nested_pointer_scope") ==
            "exact NV0000_CTRL_CMD_SYSTEM_GET_FEATURES 4-byte featuresMask only; raw addresses and handles omitted" and
            observed.get("payload_scope") ==
            "exact root-global SYSTEM_GET_FEATURES 4-byte mask plus fixed RM_CONTROL headers; raw addresses and handles omitted",
            "SYSTEM_GET_FEATURES observer exceeded its exact payload scope")
    rows = observed.get("records")
    require(isinstance(rows, list) and bool(rows),
            "SYSTEM_GET_FEATURES capture contains no root-global features ioctl")
    record_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                     "operation", "entry", "exit", "syscall_return"}
    header_fields = {"command", "flags", "params_size", "status", "hClientPresent",
                     "hObjectPresent", "client_object_equal",
                     "client_matches_prior_root_allocation",
                     "object_matches_prior_root_allocation", "featuresMask"}
    masks = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == record_fields and
                row.get("operation") == "rm_control_system_features" and
                row.get("fd_role") == "control" and
                ((row.get("request") == 0xC020462A and row.get("packet_size") == 32) or
                 (row.get("request") == 0xC01046D3 and row.get("packet_size") == 16)) and
                type(row.get("tid")) is int and row["tid"] >= 0 and
                type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("syscall_return") == 0,
                f"SYSTEM_GET_FEATURES record {index} has an invalid or failed ioctl envelope")
        for phase in ("entry", "exit"):
            header = row.get(phase)
            require(isinstance(header, dict) and set(header) == header_fields and
                    header.get("command") == 0x1F0 and header.get("flags") == 0 and
                    header.get("params_size") == 4 and
                    type(header.get("status")) is int and
                    0 <= header["status"] <= 0xFFFFFFFF and
                    (phase != "exit" or header.get("status") == 0) and
                    all(type(header.get(key)) is bool for key in (
                        "hClientPresent", "hObjectPresent", "client_object_equal",
                        "client_matches_prior_root_allocation",
                        "object_matches_prior_root_allocation")) and
                    type(header.get("featuresMask")) is int and
                    0 <= header["featuresMask"] <= 0xFFFFFFFF and
                    "hClient" not in header and "hObject" not in header and
                    "params" not in header and "params_address" not in header,
                    f"SYSTEM_GET_FEATURES record {index} has a malformed or unredacted payload")
        masks.append(row["exit"]["featuresMask"])
    require(observed.get("system_features_payload_snapshots_read") == 2 * len(rows),
            "SYSTEM_GET_FEATURES payload snapshot count differs from the ioctl records")
    return len(rows), masks


def validate_sync_boost_groups_capture(observed: object) -> tuple[int, list[int]]:
    """Validate the exact, bounded root-global SYNC_GPU_BOOST_GROUP_INFO count."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v32" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "SYNC_GPU_BOOST_GROUP_INFO observation is incomplete or has the wrong schema")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("architecture") == "x86_64" and
            observed.get("pointer_bits") == 64 and
            observed.get("nested_pointers_read") is True and
            observed.get("fd_identity_tracking") is False,
            "SYNC_GPU_BOOST_GROUP_INFO observer exceeded its read-only ABI boundary")
    require(observed.get("nested_pointer_scope") ==
            "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; "
            "inline GPU IDs and group payloads omitted" and
            observed.get("payload_scope") ==
            "exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; "
            "inline GPU IDs and group payloads omitted; raw addresses and handles omitted",
            "SYNC_GPU_BOOST_GROUP_INFO observer exceeded its exact payload scope")
    rows = observed.get("records")
    require(isinstance(rows, list) and bool(rows),
            "SYNC_GPU_BOOST_GROUP_INFO capture contains no successful root-global ioctl")
    record_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                     "operation", "entry", "exit", "syscall_return"}
    header_fields = {"command", "flags", "params_size", "status", "hClientPresent",
                     "hObjectPresent", "client_object_equal",
                     "client_matches_prior_root_allocation",
                     "object_matches_prior_root_allocation", "syncBoostGroupCount"}
    counts = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == record_fields and
                row.get("operation") == "rm_control_sync_boost_groups" and
                row.get("fd_role") == "control" and
                ((row.get("request") == 0xC020462A and row.get("packet_size") == 32) or
                 (row.get("request") == 0xC01046D3 and row.get("packet_size") == 16)) and
                type(row.get("tid")) is int and row["tid"] >= 0 and
                type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("syscall_return") == 0,
                f"SYNC_GPU_BOOST_GROUP_INFO record {index} has an invalid or failed ioctl envelope")
        for phase in ("entry", "exit"):
            header = row.get(phase)
            expected_header_fields = (header_fields if phase == "exit" else
                                      header_fields - {"syncBoostGroupCount"})
            require(isinstance(header, dict) and set(header) == expected_header_fields and
                    header.get("command") == 0xA04 and header.get("flags") == 0 and
                    header.get("params_size") == 2244 and
                    type(header.get("status")) is int and
                    0 <= header["status"] <= 0xFFFFFFFF and
                    (phase != "exit" or header.get("status") == 0) and
                    all(type(header.get(key)) is bool for key in (
                        "hClientPresent", "hObjectPresent", "client_object_equal",
                        "client_matches_prior_root_allocation",
                        "object_matches_prior_root_allocation")) and
                    (phase != "exit" or
                     (type(header.get("syncBoostGroupCount")) is int and
                      0 <= header["syncBoostGroupCount"] <= 16)) and
                    "hClient" not in header and "hObject" not in header and
                    "params" not in header and "params_address" not in header and
                    "syncBoostGroupIds" not in header,
                    f"SYNC_GPU_BOOST_GROUP_INFO record {index} has a malformed or unredacted payload")
        counts.append(row["exit"]["syncBoostGroupCount"])
    require(observed.get("sync_boost_group_payload_snapshots_read") == len(rows),
            "SYNC_GPU_BOOST_GROUP_INFO payload snapshot count differs from the ioctl records")
    return len(rows), counts


def validate_ioctl_shape_capture(observed: object) -> tuple[int, dict[str, int]]:
    """Validate bounded byte-position metadata for four allowlisted ioctl payloads."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v26" and
            observed.get("trace_complete") is True and observed.get("errors") == [],
            "ioctl payload-shape observation is incomplete or has the wrong schema")
    require(observed.get("control_path") == "/dev/nvidiactl" and
            observed.get("gpu_path") == "/dev/nvidia0" and
            observed.get("architecture") == "x86_64" and
            observed.get("pointer_bits") == 64 and
            observed.get("nested_pointers_read") is False and
            observed.get("snapshot_consistency") ==
            "per-task syscall stop; other threads may mutate shared packet memory" and
            observed.get("fd_identity_tracking") is False,
            "ioctl payload-shape observer exceeded its fixed device or ABI boundary")
    require(observed.get("child_exit_code") == 0,
            "ioctl payload-shape child did not exit successfully")
    expected_scope = (
        "exact requests 0xc038464e (56 bytes) and 0xc028465e (40 bytes) on the selected "
        "control path, and 0xc01046ce/0xc01046cf (16 bytes each) on the selected GPU path; "
        "emits only nonzero and changed byte offsets; raw values and pointers omitted")
    require(observed.get("payload_scope") == expected_scope and
            "nested_pointer_scope" not in observed,
            "ioctl payload-shape observer exceeded its redacted metadata scope")
    rows = observed.get("records")
    require(isinstance(rows, list), "ioctl payload-shape records are missing")
    allowlist = {
        0xC038464E: (56, "control"),
        0xC028465E: (40, "control"),
        0xC01046CE: (16, "gpu"),
        0xC01046CF: (16, "gpu"),
    }
    counts = {f"0x{request:08x}": 0 for request in allowlist}
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets",
                  "entry_snapshot_passed", "exit_snapshot_passed", "entry", "exit",
                  "syscall_return"}
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == row_fields,
                f"ioctl payload-shape record {index} contains raw or unexpected fields")
        request = row.get("request")
        require(type(request) is int and request in allowlist,
                f"ioctl payload-shape record {index} uses an unapproved request")
        packet_size, fd_role = allowlist[request]
        require(row.get("operation") == "selected_ioctl_payload_shape" and
                row.get("packet_size") == packet_size and row.get("fd_role") == fd_role and
                type(row.get("tid")) is int and row["tid"] > 0 and
                type(row.get("fd")) is int and row["fd"] >= 0 and
                row.get("syscall_return") == 0 and
                row.get("entry_snapshot_passed") is True and
                row.get("exit_snapshot_passed") is True and
                row.get("entry") is None and row.get("exit") is None,
                f"ioctl payload-shape record {index} has an invalid envelope or snapshot")
        position_sets = {}
        for field in ("entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets"):
            offsets = row.get(field)
            require(isinstance(offsets, list) and
                    all(type(offset) is int and 0 <= offset < packet_size for offset in offsets) and
                    offsets == sorted(set(offsets)),
                    f"ioctl payload-shape record {index} has invalid {field}")
            position_sets[field] = set(offsets)
        require(position_sets["changed_offsets"] <=
                (position_sets["entry_nonzero_offsets"] | position_sets["exit_nonzero_offsets"]),
                f"ioctl payload-shape record {index} has an impossible changed-byte position")
        counts[f"0x{request:08x}"] += 1
    return len(rows), counts


def summarize_ioctl_shape_capture(observed: object) -> dict[str, object]:
    """Return coverage and lifecycle counts without retaining transient TIDs or FDs."""
    record_count, request_counts = validate_ioctl_shape_capture(observed)
    rows = observed["records"]
    allocations = 0
    frees = 0
    outstanding: dict[tuple[int, int], int] = {}
    allocations_by_group: dict[tuple[int, int], int] = {}
    frees_by_group: dict[tuple[int, int], int] = {}
    unmatched_frees_by_group: dict[tuple[int, int], int] = {}
    for row in rows:
        key = (row["tid"], row["fd"])
        if row["request"] == 0xC01046CE:
            allocations += 1
            allocations_by_group[key] = allocations_by_group.get(key, 0) + 1
            outstanding[key] = outstanding.get(key, 0) + 1
        elif row["request"] == 0xC01046CF:
            frees += 1
            frees_by_group[key] = frees_by_group.get(key, 0) + 1
            if outstanding.get(key, 0) > 0:
                outstanding[key] -= 1
            else:
                unmatched_frees_by_group[key] = unmatched_frees_by_group.get(key, 0) + 1
    unmatched_allocations = sum(outstanding.values())
    unmatched_frees = sum(unmatched_frees_by_group.values())
    groups = set(allocations_by_group) | set(frees_by_group)
    matched_groups = sum(
        allocations_by_group.get(key, 0) > 0 and
        allocations_by_group.get(key, 0) == frees_by_group.get(key, 0) and
        outstanding.get(key, 0) == 0 and
        unmatched_frees_by_group.get(key, 0) == 0
        for key in groups
    )
    lifecycle_balanced = unmatched_allocations == 0 and unmatched_frees == 0
    all_requests_seen = all(request_counts.values())
    coverage = ("inconclusive" if record_count == 0 else
                "complete" if all_requests_seen and lifecycle_balanced else "partial")
    return {
        "schema": "nvidia-hybrid-rm-ioctl-shape-summary-v1",
        "trace_complete": True,
        "record_count": record_count,
        "request_counts": request_counts,
        "event_lifecycle": {
            "allocation_count": allocations,
            "free_count": frees,
            "balanced": lifecycle_balanced,
            "matched_groups": matched_groups,
            "unmatched_allocations": unmatched_allocations,
            "unmatched_frees": unmatched_frees,
        },
        "coverage": coverage,
    }


def sanitize_ioctl_shape_evidence(report: dict[str, object], requested: bool) -> None:
    """Replace raw shape-observer rows before serializing evidence, including failures."""
    if not requested:
        return
    remote = report.get("remote")
    if not isinstance(remote, dict) or "ioctl_observation" not in remote:
        return
    try:
        remote["ioctl_observation"] = summarize_ioctl_shape_capture(
            remote["ioctl_observation"])
    except (TypeError, ValueError, KeyError):
        remote["ioctl_observation"] = {
            "schema": "nvidia-hybrid-rm-ioctl-shape-summary-v1",
            "status": "rejected",
        }


def validate_ioctl_shapes_selection(phase: str | None, other_modes: tuple[object, ...]) -> None:
    """Allow shape-only capture alone or around the single-process kernel phase."""
    if phase not in (None, "kernel") or any(other_modes):
        raise ValueError("ioctl payload-shape capture requires an isolated kernel-phase observer")


def validate_remote_acceptance(remote: object, expected_artifacts: dict[str, dict[str, object]],
                               trace_requested: bool = False,
                               managed_memory: bool = False,
                               managed_prefetch: bool = False,
                               cuda_graphs: bool = False,
                               performance_benchmark: bool = False,
                               gpu_id_info_requested: bool = False,
                               attached_ids_requested: bool = False,
                               probed_ids_requested: bool = False,
                               rm_control_requested: bool = False,
                               channel_alloc_requested: bool = False,
                               map_memory_requested: bool = False,
                               rusd_alloc_requested: bool = False,
                               p2p_alloc_requested: bool = False,
                               p2p_control_requested: bool = False,
                               binapi_control_requested: bool = False,
                               rm_control_headers_requested: bool = False,
                               fabric_status_requested: bool = False,
                               system_features_requested: bool = False,
                               sync_boost_groups_requested: bool = False,
                               device_alloc_requested: bool = False,
                               subdevice_alloc_requested: bool = False,
                               binapi_alloc_requested: bool = False,
                               ioctl_shapes_requested: bool = False,
                               phase: str | None = None,
                               uvm_vaspace_fd_requested: bool = False,
                               libcuda_override_requested: bool = False,
                               p2p_fault_mode: str | None = None) -> str:
    requested_phase = phase
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(remote, dict), "remote result must be an object")
    require(remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1", "unsupported remote result schema")
    require(remote.get("host") == "pc3" and isinstance(remote.get("host_kernel_release"), str), "wrong PC3 host identity")
    require(not remote.get("failure_stage"), "remote execution failed before qualification")
    require(remote.get("qualification") == "probe-executed", "remote probe lifecycle did not complete")
    require(remote.get("memory_mode") == ("managed" if managed_memory else "device"),
            "remote memory mode differs from the request")
    require(remote.get("managed_prefetch_requested") is managed_prefetch,
            "remote managed-prefetch mode differs from the request")
    require(remote.get("cuda_graphs_requested") is cuda_graphs,
            "remote CUDA Graph mode differs from the request")
    require(remote.get("performance_benchmark_requested", False) is performance_benchmark,
            "remote performance benchmark mode differs from the request")
    require(remote.get("gpu_id_info_capture_requested", False) is gpu_id_info_requested,
            "remote GPU-ID-info capture mode differs from the request")
    require(remote.get("attached_ids_capture_requested", False) is attached_ids_requested,
            "remote attached-ID capture mode differs from the request")
    require(remote.get("probed_ids_capture_requested", False) is probed_ids_requested,
            "remote probed-ID capture mode differs from the request")
    require(remote.get("rm_control_capture_requested", False) is rm_control_requested,
            "remote RM_CONTROL capture mode differs from the request")
    require(remote.get("rm_control_headers_capture_requested", False) is
            rm_control_headers_requested,
            "remote redacted RM_CONTROL header mode differs from the request")
    require(remote.get("fabric_status_capture_requested", False) is
            fabric_status_requested,
            "remote Fabric Status capture mode differs from the request")
    require(remote.get("system_features_capture_requested", False) is
            system_features_requested,
            "remote SYSTEM_GET_FEATURES capture mode differs from the request")
    require(remote.get("sync_boost_groups_capture_requested", False) is
            sync_boost_groups_requested,
            "remote SYNC_GPU_BOOST_GROUP_INFO capture mode differs from the request")
    require(remote.get("ioctl_shapes_capture_requested", False) is ioctl_shapes_requested,
            "remote ioctl payload-shape capture mode differs from the request")
    require(remote.get("uvm_vaspace_fd_capture_requested", False) is
            uvm_vaspace_fd_requested,
            "remote UVM VA-space descriptor capture mode differs from the request")
    require(remote.get("channel_alloc_capture_requested", False) is channel_alloc_requested,
            "remote channel-allocation capture mode differs from the request")
    require(remote.get("map_memory_capture_requested", False) is map_memory_requested,
            "remote map-memory capture mode differs from the request")
    require(remote.get("rusd_alloc_capture_requested", False) is rusd_alloc_requested,
            "remote RUSD allocation capture mode differs from the request")
    require(remote.get("p2p_alloc_capture_requested", False) is p2p_alloc_requested,
            "remote P2P allocation capture mode differs from the request")
    require(remote.get("p2p_control_capture_requested", False) is p2p_control_requested,
            "remote P2P control capture mode differs from the request")
    require(remote.get("binapi_control_capture_requested", False) is binapi_control_requested,
            "remote BINAPI control capture mode differs from the request")
    require(remote.get("device_alloc_capture_requested", False) is device_alloc_requested,
            "remote NV01_DEVICE_0 allocation capture mode differs from the request")
    require(remote.get("subdevice_alloc_capture_requested", False) is subdevice_alloc_requested,
            "remote NV20_SUBDEVICE_0 allocation capture mode differs from the request")
    require(remote.get("binapi_alloc_capture_requested", False) is binapi_alloc_requested,
            "remote NV2081_BINAPI allocation capture mode differs from the request")
    require(remote.get("phase_capture_requested", False) is (requested_phase is not None) and
            remote.get("phase") == requested_phase,
            "remote CUDA phase selection differs from the request")
    require(remote.get("libcuda_override_requested", False) is libcuda_override_requested,
            "remote libcuda override mode differs from the request")
    require(remote.get("p2p_fault_requested", False) is (p2p_fault_mode is not None) and
            remote.get("p2p_fault_mode") == p2p_fault_mode,
            "remote P2P fault mode differs from the request")
    require(p2p_fault_mode is None or
            (p2p_fault_mode in P2P_FAULT_MODES and
             "p2p-fault-shim" in expected_artifacts and requested_phase is None and
             not any((trace_requested, managed_memory, managed_prefetch, cuda_graphs,
                      performance_benchmark, gpu_id_info_requested, attached_ids_requested,
                      probed_ids_requested, rm_control_requested, channel_alloc_requested,
                      map_memory_requested, rusd_alloc_requested, p2p_alloc_requested,
                      p2p_control_requested, binapi_control_requested,
                      rm_control_headers_requested, fabric_status_requested,
                      system_features_requested, sync_boost_groups_requested,
                      device_alloc_requested, subdevice_alloc_requested,
                      binapi_alloc_requested, ioctl_shapes_requested,
                      uvm_vaspace_fd_requested, libcuda_override_requested)) and
             "observer" not in expected_artifacts and "trace-helper" not in expected_artifacts),
            "P2P fault injection requires one isolated full SM70 reference run")
    require(not uvm_vaspace_fd_requested or
            (requested_phase in ("context", "kernel") and not trace_requested and
             "observer" in expected_artifacts and not any((
                 managed_memory, managed_prefetch, cuda_graphs, performance_benchmark,
                 gpu_id_info_requested, attached_ids_requested, probed_ids_requested,
                 rm_control_requested, channel_alloc_requested, map_memory_requested,
                 rusd_alloc_requested, p2p_alloc_requested, p2p_control_requested,
                 binapi_control_requested, rm_control_headers_requested,
                  fabric_status_requested, system_features_requested,
                  sync_boost_groups_requested,
                 device_alloc_requested, subdevice_alloc_requested,
                 binapi_alloc_requested, ioctl_shapes_requested))),
            "UVM descriptor capture requires an isolated context or kernel observer")
    shape_other_captures = (trace_requested, managed_memory, managed_prefetch, cuda_graphs,
                            performance_benchmark, gpu_id_info_requested, attached_ids_requested,
                            probed_ids_requested, rm_control_requested,
                            rm_control_headers_requested, fabric_status_requested,
                             system_features_requested, sync_boost_groups_requested,
                             channel_alloc_requested,
                            map_memory_requested, rusd_alloc_requested, p2p_alloc_requested,
                            p2p_control_requested, binapi_control_requested,
                            device_alloc_requested, subdevice_alloc_requested,
                            binapi_alloc_requested, uvm_vaspace_fd_requested)
    require(not ioctl_shapes_requested or
            (requested_phase in (None, "kernel") and "observer" in expected_artifacts and
             not any(shape_other_captures)),
            "ioctl payload-shape capture requires an isolated default or kernel-phase observer run")
    if requested_phase is not None:
        phase_observer_count = sum((binapi_control_requested, device_alloc_requested,
                                    subdevice_alloc_requested, binapi_alloc_requested,
                                    rm_control_headers_requested, fabric_status_requested,
                                     system_features_requested, sync_boost_groups_requested,
                                     ioctl_shapes_requested,
                                    uvm_vaspace_fd_requested))
        phase_trace = (requested_phase in ("enumerate", "context", "managed-accessed-by") and trace_requested and
                       "trace-helper" in expected_artifacts and
                       "observer" not in expected_artifacts and phase_observer_count == 0)
        phase_observer = ("observer" in expected_artifacts and phase_observer_count == 1 and
                          not trace_requested)
        phase_pageable = (requested_phase == "system-pageable-memory" and
                          not trace_requested and "trace-helper" not in expected_artifacts and
                          "observer" not in expected_artifacts and phase_observer_count == 0 and
                          not any((cuda_graphs, managed_memory, managed_prefetch,
                                   gpu_id_info_requested, attached_ids_requested,
                                   probed_ids_requested, rm_control_requested,
                                   channel_alloc_requested, map_memory_requested,
                                   rusd_alloc_requested, p2p_alloc_requested,
                                   p2p_control_requested, binapi_control_requested,
                                   rm_control_headers_requested, device_alloc_requested,
                                   subdevice_alloc_requested, binapi_alloc_requested,
                                   system_features_requested)))
        require(requested_phase in ("initialize", "enumerate", "context", "allocation", "module", "kernel",
                                    "managed-accessed-by",
                                    "system-pageable-memory") and
                (phase_trace or phase_observer or phase_pageable) and
                (not binapi_control_requested or rm_control_requested) and
                (not (rm_control_headers_requested or fabric_status_requested or
                      system_features_requested or sync_boost_groups_requested) or
                 requested_phase == "enumerate") and
                not any((cuda_graphs, managed_memory, managed_prefetch, gpu_id_info_requested,
                attached_ids_requested,
                probed_ids_requested, channel_alloc_requested, map_memory_requested,
                rusd_alloc_requested, p2p_alloc_requested, p2p_control_requested,
                rm_control_requested if phase_pageable else False,
                binapi_control_requested if phase_pageable else False)),
                "CUDA phase requires one isolated observer, an enumeration/context ioctl trace, or the standalone pageable-memory phase")
    require(not system_features_requested or
            (requested_phase == "enumerate" and "observer" in expected_artifacts and
             not any((trace_requested, managed_memory, managed_prefetch, cuda_graphs,
                      gpu_id_info_requested, attached_ids_requested, probed_ids_requested,
                       rm_control_requested, rm_control_headers_requested, fabric_status_requested,
                       sync_boost_groups_requested,
                      channel_alloc_requested, map_memory_requested, rusd_alloc_requested,
                      p2p_alloc_requested, p2p_control_requested, binapi_control_requested,
                      device_alloc_requested, subdevice_alloc_requested, binapi_alloc_requested))),
            "SYSTEM_GET_FEATURES capture must be isolated to one enumeration observer")
    require(not fabric_status_requested or
            (requested_phase == "enumerate" and not any((
                trace_requested, managed_memory, managed_prefetch, cuda_graphs,
                gpu_id_info_requested, attached_ids_requested, probed_ids_requested,
                rm_control_requested, rm_control_headers_requested,
                channel_alloc_requested, map_memory_requested, rusd_alloc_requested,
                p2p_alloc_requested, p2p_control_requested, binapi_control_requested,
                device_alloc_requested, subdevice_alloc_requested,
                binapi_alloc_requested))),
            "Fabric Status capture must be isolated to one enumeration observer")
    require(not rm_control_headers_requested or
            (requested_phase == "enumerate" and not any((
                rm_control_requested, gpu_id_info_requested, attached_ids_requested,
                probed_ids_requested, channel_alloc_requested, map_memory_requested,
                rusd_alloc_requested, p2p_alloc_requested, p2p_control_requested,
                binapi_control_requested, device_alloc_requested,
                subdevice_alloc_requested, binapi_alloc_requested, trace_requested,
                managed_memory, managed_prefetch, cuda_graphs))),
            "redacted RM_CONTROL header capture must be isolated to enumeration")
    require(not channel_alloc_requested or "observer" in expected_artifacts,
            "requested channel capture requires the RM ioctl observer")
    require(not map_memory_requested or "observer" in expected_artifacts,
            "requested map-memory capture requires the RM ioctl observer")
    require(not rusd_alloc_requested or "observer" in expected_artifacts,
            "requested RUSD capture requires the RM ioctl observer")
    require(not p2p_alloc_requested or "observer" in expected_artifacts,
            "requested P2P capture requires the RM ioctl observer")
    require(not p2p_control_requested or "observer" in expected_artifacts,
            "requested P2P control capture requires the RM ioctl observer")
    require(not binapi_control_requested or "observer" in expected_artifacts,
            "requested BINAPI control capture requires the RM ioctl observer")
    require(not device_alloc_requested or "observer" in expected_artifacts,
            "requested NV01_DEVICE_0 capture requires the RM ioctl observer")
    require(not subdevice_alloc_requested or "observer" in expected_artifacts,
            "requested NV20_SUBDEVICE_0 capture requires the RM ioctl observer")
    require(not binapi_alloc_requested or "observer" in expected_artifacts,
            "requested NV2081_BINAPI capture requires the RM ioctl observer")
    require(not fabric_status_requested or "observer" in expected_artifacts,
            "requested Fabric Status capture requires the RM ioctl observer")
    require(not p2p_control_requested or rm_control_requested,
            "P2P control capture requires the RM_CONTROL header capture")
    require(not binapi_control_requested or rm_control_requested,
            "BINAPI control capture requires the RM_CONTROL header capture")
    require(not device_alloc_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            channel_alloc_requested, map_memory_requested, rusd_alloc_requested,
            p2p_alloc_requested, p2p_control_requested, binapi_control_requested,
            managed_memory, managed_prefetch)),
            "NV01_DEVICE_0 capture must be isolated")
    require(not subdevice_alloc_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            channel_alloc_requested, map_memory_requested, rusd_alloc_requested,
            p2p_alloc_requested, p2p_control_requested, binapi_control_requested,
            device_alloc_requested, managed_memory, managed_prefetch)),
            "NV20_SUBDEVICE_0 capture must be isolated")
    require(not binapi_alloc_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            channel_alloc_requested, map_memory_requested, rusd_alloc_requested,
            p2p_alloc_requested, p2p_control_requested, binapi_control_requested,
            device_alloc_requested, subdevice_alloc_requested, managed_memory, managed_prefetch)),
            "NV2081_BINAPI allocation capture must be isolated")
    require(not channel_alloc_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            map_memory_requested, rusd_alloc_requested, p2p_alloc_requested)),
            "channel-allocation capture must be an isolated observer mode")
    require(not map_memory_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            channel_alloc_requested, rusd_alloc_requested, p2p_alloc_requested)),
            "map-memory capture must be an isolated observer mode")
    require(not rusd_alloc_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            channel_alloc_requested, map_memory_requested, p2p_alloc_requested)),
            "RUSD allocation capture must be an isolated observer mode")
    require(not p2p_alloc_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, rm_control_requested,
            channel_alloc_requested, map_memory_requested, rusd_alloc_requested)),
            "P2P allocation capture must be an isolated observer mode")
    require(not p2p_control_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, channel_alloc_requested,
            map_memory_requested, rusd_alloc_requested, p2p_alloc_requested,
            binapi_control_requested)),
            "P2P control capture must be isolated with RM_CONTROL headers")
    require(not binapi_control_requested or not any((trace_requested, gpu_id_info_requested,
            attached_ids_requested, probed_ids_requested, channel_alloc_requested,
            map_memory_requested, rusd_alloc_requested, p2p_alloc_requested,
            p2p_control_requested, managed_memory, managed_prefetch)),
            "BINAPI control capture must be isolated with RM_CONTROL headers")
    require(remote.get("payload_file_cleanup_passed") is True, "root runner did not remove its PC3 payload file")
    scope = remote.get("execution_scope")
    require(isinstance(scope, dict) and all(scope.get(key) is False for key in
            ("guest_driver_changed", "module_loaded", "vm_management_issued", "pci_binding_changed")),
            "remote execution scope differs from the read-only GPU-test contract")
    guest = remote.get("guest")
    require(isinstance(guest, dict) and guest.get("hostname") == "pc3-v100", "wrong V100 guest identity")
    require(guest.get("name", "").startswith("Tesla V100"), "guest inventory is not Tesla V100")
    require(re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", guest.get("uuid", "")) is not None,
            "invalid guest GPU UUID")
    require(isinstance(guest.get("driver_version"), str) and bool(guest["driver_version"]), "missing guest driver version")
    if libcuda_override_requested:
        override_enumeration = (requested_phase == "enumerate" and
                                system_features_requested and not device_alloc_requested)
        override_context_or_kernel = (requested_phase in ("context", "kernel") and
                           device_alloc_requested and not system_features_requested)
        require((override_enumeration or override_context_or_kernel) and
                guest.get("driver_version") == "580.178.04",
                "R580.196.07 libcuda requires the pinned stock R580.178.04 guest driver")
        require(remote.get("libcuda_override_temp_cleanup_passed") is True,
                "temporary R580 loader directory was not removed")
    pci = canonical_pci(guest.get("pci", ""))
    require(isinstance(guest.get("kernel_release"), str) and bool(guest["kernel_release"]), "missing guest kernel release")
    require(isinstance(remote.get("guest_after"), dict), "missing post-probe guest inventory")
    require(remote.get("guest_cleanup_passed") is True, "temporary guest artifacts were not removed")
    probe = remote.get("probe")
    if p2p_fault_mode is not None:
        require(type(remote.get("probe_exit_code")) is int and
                remote.get("probe_exit_code") != 124,
                "P2P fault probe did not complete")
        require(isinstance(probe, dict), "P2P fault probe returned no parsed report")
        denial_count = validate_p2p_fault_diagnostics(remote.get("probe_stderr"),
                                                       p2p_fault_mode)
        require(remote.get("p2p_fault_denial_count") == denial_count,
                "P2P fault count differs from the probe diagnostic")
        qualification = "p2p-fault-injection-report-contract-valid"
    elif requested_phase is not None:
        phase_qualification = validate_cuda_phase_report(
            probe, remote.get("probe_exit_code"), pci, requested_phase)
        if requested_phase == "system-pageable-memory":
            require(phase_qualification in ("system-pageable-memory-unsupported-report-contract-valid",
                                            "system-pageable-memory-report-contract-pass"),
                    "V100 pageable-memory capability result is invalid")
        else:
            require(phase_qualification == "phase-report-contract-pass",
                    "V100 CUDA phase gate failed")
    else:
        require(validate_v100_reference(probe, remote.get("probe_exit_code"), pci,
                                        managed_memory=managed_memory,
                                        managed_prefetch=managed_prefetch,
                                        cuda_graphs=cuda_graphs,
                                        performance_benchmark=performance_benchmark) == "v100-reference-report-contract-valid",
                "SM70 reference gate failed")

    library = remote.get("driver_library")
    if p2p_fault_mode is None:
        require(isinstance(library, dict) and library.get("path") == probe.get("driver_library_path"),
                "installed libcuda identity is missing")
        require(type(library.get("bytes")) is int and library["bytes"] > 0 and
                re.fullmatch(r"[0-9a-f]{64}", library.get("sha256", "")) is not None,
                "installed libcuda hash is invalid")
    elif library is not None:
        require(isinstance(library, dict) and isinstance(probe, dict) and
                library.get("path") == probe.get("driver_library_path") and
                type(library.get("bytes")) is int and library["bytes"] > 0 and
                re.fullmatch(r"[0-9a-f]{64}", library.get("sha256", "")) is not None,
                "optional libcuda identity in the P2P fault result is invalid")

    before = remote.get("artifacts_before")
    after = remote.get("artifacts_after")
    require(isinstance(before, dict) and set(before) == set(expected_artifacts), "remote input artifact set differs")
    require(isinstance(after, dict), "missing remote post-run hashes")
    for name, expected in expected_artifacts.items():
        item = before.get(name)
        require(isinstance(item, dict) and item.get("bytes") == expected.get("bytes") and
                item.get("sha256") == expected.get("sha256"), f"{name} hash differs from local input")
        guest_path = item.get("guest_path")
        require(isinstance(guest_path, str) and guest_path.startswith("/tmp/codex-v100-ref-"),
                f"{name} was not staged in its isolated guest temp path")
        require(after.get(guest_path) == {"bytes": item["bytes"], "sha256": item["sha256"]},
                f"{name} changed during the probe")
    if libcuda_override_requested:
        staged = before.get("libcuda")
        guest_after = remote.get("guest_after")
        require(isinstance(staged, dict) and isinstance(guest_after, dict) and
                guest_after.get("driver_version") == guest.get("driver_version"),
                "stock V100 driver identity changed during the isolated user-library probe")
        require(library.get("path") == staged.get("guest_path") and
                library.get("bytes") == R580_19607_LIBCUDA_BYTES and
                library.get("sha256") == R580_19607_LIBCUDA_SHA256,
                "probe did not use the exact staged R580.196.07 libcuda image")

    if "observer" in expected_artifacts:
        observed = remote.get("ioctl_observation")
        require(isinstance(observed, dict), "requested RM ioctl observation is missing")
        expected_observer_schema = ("nvidia-hybrid-rm-ioctl-observer-v31"
                                    if uvm_vaspace_fd_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v26"
                                    if ioctl_shapes_requested else
                                   "nvidia-hybrid-rm-ioctl-observer-v25"
                                    if system_features_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v32"
                                    if sync_boost_groups_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v24"
                                    if fabric_status_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v23"
                                    if rm_control_headers_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v21"
                                    if binapi_alloc_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v20"
                                    if subdevice_alloc_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v18"
                                    if binapi_control_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v19"
                                    if device_alloc_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v17"
                                    if p2p_control_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v16"
                                    if p2p_alloc_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v15"
                                    if map_memory_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v14"
                                    if rusd_alloc_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v9"
                                    if channel_alloc_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v6"
                                    if probed_ids_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v5"
                                    if rm_control_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v4"
                                    if attached_ids_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v3"
                                    if gpu_id_info_requested else
                                    "nvidia-hybrid-rm-ioctl-observer-v1")
        require(observed.get("schema") == expected_observer_schema and
                observed.get("trace_complete") is True and observed.get("errors") == [],
                "RM ioctl observation is incomplete")
        require(observed.get("child_exit_code") == remote.get("probe_exit_code") and
                remote.get("observer_exit_code") == remote.get("probe_exit_code"),
                "observer and CUDA probe exit codes differ")
        require(observed.get("control_path") == "/dev/nvidiactl" and
                observed.get("architecture") == "x86_64" and observed.get("pointer_bits") == 64,
                "RM ioctl observation has an unexpected device or ABI")
        ioctl_shape_count = None
        ioctl_shape_counts = None
        if ioctl_shapes_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0",
                    "ioctl payload-shape observation does not use the selected V100 descriptor")
            ioctl_shape_count, ioctl_shape_counts = validate_ioctl_shape_capture(observed)
            require(remote.get("ioctl_shape_records_seen") is bool(ioctl_shape_count) and
                    remote.get("ioctl_shape_record_count") == ioctl_shape_count and
                    remote.get("ioctl_shape_request_counts") == ioctl_shape_counts,
                    "V100 ioctl payload-shape summary differs from the redacted observer trace")
        else:
            require(remote.get("ioctl_shape_records_seen") is None and
                    remote.get("ioctl_shape_record_count") is None and
                    remote.get("ioctl_shape_request_counts") is None,
                    "ioctl payload-shape results were reported without requesting capture")
        binapi_snapshots = None
        if binapi_control_requested:
            binapi_snapshots = observed.get("binapi_payload_snapshots_read")
            require(type(binapi_snapshots) is int and binapi_snapshots >= 0,
                    "BINAPI observation has no valid payload-snapshot count")
        device_alloc_snapshots = None
        if device_alloc_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0",
                    "NV01_DEVICE_0 observation does not use the selected guest GPU descriptor")
            _, device_alloc_snapshots = validate_device_alloc_capture(observed)
            require(remote.get("device_alloc_records_seen") is True and
                    remote.get("device_alloc_payload_snapshots_read") == device_alloc_snapshots,
                    "V100 device-allocation summary differs from the redacted observer trace")
        subdevice_alloc_snapshots = None
        if subdevice_alloc_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0",
                    "NV20_SUBDEVICE_0 observation does not use the selected guest GPU descriptor")
            _, subdevice_alloc_snapshots = validate_subdevice_alloc_capture(observed)
            require(remote.get("subdevice_alloc_records_seen") is True and
                    remote.get("subdevice_alloc_payload_snapshots_read") == subdevice_alloc_snapshots,
                    "V100 subdevice-allocation summary differs from the redacted observer trace")
        binapi_alloc_snapshots = None
        if binapi_alloc_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0",
                    "NV2081_BINAPI allocation observation does not use the selected guest GPU descriptor")
            _, binapi_alloc_snapshots = validate_binapi_alloc_capture(observed)
            require(remote.get("binapi_alloc_records_seen") is True and
                    remote.get("binapi_alloc_payload_snapshots_read") == binapi_alloc_snapshots,
                    "V100 BINAPI allocation summary differs from the redacted observer trace")
        nested_requested = (gpu_id_info_requested or attached_ids_requested or
                            probed_ids_requested or channel_alloc_requested or
                            rusd_alloc_requested or p2p_alloc_requested or
                            (fabric_status_requested and
                             observed.get("fabric_status_payload_snapshots_read", 0) > 0) or
                            (system_features_requested and
                             observed.get("system_features_payload_snapshots_read", 0) > 0) or
                            (sync_boost_groups_requested and
                             observed.get("sync_boost_group_payload_snapshots_read", 0) > 0) or
                            device_alloc_requested or subdevice_alloc_requested or
                            (binapi_alloc_requested and binapi_alloc_snapshots > 0) or
                            (p2p_control_requested and
                             observed.get("p2p_control_payload_snapshots_read", 0) > 0) or
                            (binapi_control_requested and binapi_snapshots > 0))
        if map_memory_requested:
            nested_requested = False
        require(observed.get("nested_pointers_read") is nested_requested and
                observed.get("fd_identity_tracking") is
                (map_memory_requested or uvm_vaspace_fd_requested),
                "RM ioctl observer exceeded its read-only packet boundary")
        if rm_control_headers_requested:
            header_count = validate_rm_control_headers_capture(observed)
            require(remote.get("rm_control_headers_records_seen") is True and
                    remote.get("rm_control_headers_record_count") == header_count,
                    "V100 redacted RM_CONTROL header summary differs from the observer trace")
        if fabric_status_requested:
            fabric_count, fabric_values = validate_fabric_status_capture(observed)
            require(remote.get("fabric_status_records_seen") is True and
                    remote.get("fabric_status_record_count") == fabric_count and
                    remote.get("fabric_status_values") == fabric_values,
                    "V100 Fabric Status summary differs from the exact observer trace")
        else:
            require(remote.get("fabric_status_records_seen") is not True and
                    remote.get("fabric_status_values") is None,
                    "Fabric Status values were reported without requesting capture")
        if system_features_requested:
            feature_count, feature_masks = validate_system_features_capture(observed)
            require(remote.get("system_features_records_seen") is True and
                    remote.get("system_features_record_count") == feature_count and
                    remote.get("system_features_masks") == feature_masks,
                    "V100 SYSTEM_GET_FEATURES summary differs from the exact observer trace")
        else:
            require(remote.get("system_features_records_seen") is not True and
                    remote.get("system_features_masks") is None,
                    "SYSTEM_GET_FEATURES values were reported without requesting capture")
        if sync_boost_groups_requested:
            sync_count, sync_values = validate_sync_boost_groups_capture(observed)
            require(remote.get("sync_boost_groups_records_seen") is True and
                    remote.get("sync_boost_groups_record_count") == sync_count and
                    remote.get("sync_boost_group_counts") == sync_values and
                    remote.get("sync_boost_group_payload_snapshots_read") ==
                    observed.get("sync_boost_group_payload_snapshots_read"),
                    "V100 SYNC_GPU_BOOST_GROUP_INFO summary differs from the exact observer trace")
        else:
            require(remote.get("sync_boost_groups_records_seen") is not True and
                    remote.get("sync_boost_group_counts") is None and
                    remote.get("sync_boost_group_payload_snapshots_read") is None,
                    "SYNC_GPU_BOOST_GROUP_INFO values were reported without requesting capture")
        selected_scopes = []
        if gpu_id_info_requested:
            selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2")
        if attached_ids_requested:
            selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS")
        if probed_ids_requested:
            selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_PROBED_IDS")
        if sync_boost_groups_requested:
            expected_scope = (
                "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; "
                "inline GPU IDs and group payloads omitted")
        elif system_features_requested:
            expected_scope = (
                "exact NV0000_CTRL_CMD_SYSTEM_GET_FEATURES 4-byte featuresMask only; "
                "raw addresses and handles omitted")
        elif fabric_status_requested:
            expected_scope = (
                "exact NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS 4-byte enum only; "
                "raw addresses and handles omitted")
        elif channel_alloc_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0" and
                    observed.get("object_class_resolution_scope") ==
                    "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed",
                    "channel observer did not capture both selected RM descriptor paths")
            expected_scope = (
                "VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads "
                "parsed using the byte-identical pinned R580.178.04/R595.99.02 "
                "NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted")
        elif rusd_alloc_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0",
                    "RUSD observer did not include the selected GPU descriptor")
            expected_scope = (
                "RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned "
                "8-byte polledDataMask; raw addresses and handles omitted")
        elif p2p_alloc_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0",
                    "P2P observer did not include the selected GPU descriptor")
            expected_scope = (
                "NV50_THIRD_PARTY_P2P NV503C_ALLOC_PARAMETERS only, parsed as the pinned "
                "4-byte flags word; raw addresses and handles omitted")
        elif p2p_control_requested:
            expected_scope = (
                "exact NV503C register/unregister VA-space, register/unregister vidmem, and "
                "register-PID fixed parameter structures; raw addresses, handles, and VA-space tokens omitted")
        elif binapi_control_requested and binapi_snapshots:
            expected_scope = (
                "exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; "
                "no contained pointer is followed; raw bytes, addresses, and handles omitted")
        elif device_alloc_requested:
            expected_scope = (
                "NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; "
                "client handles are relational booleans; internal VA addresses are omitted")
        elif subdevice_alloc_requested:
            expected_scope = (
                "NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; handles omitted")
        elif binapi_alloc_requested:
            expected_scope = (
                "NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; handles omitted")
        elif len(selected_scopes) == 1:
            expected_scope = "exact " + selected_scopes[0] + " payload only; addresses omitted"
        elif len(selected_scopes) == 2:
            expected_scope = "exact " + " and ".join(selected_scopes) + " payloads only; addresses omitted"
        elif len(selected_scopes) == 3:
            expected_scope = ("exact " + ", ".join(selected_scopes[:-1]) + ", and " +
                              selected_scopes[-1] + " payloads only; addresses omitted")
        else:
            expected_scope = None
        if map_memory_requested:
            require(observed.get("gpu_path") == "/dev/nvidia0" and
                    observed.get("object_class_resolution_scope") ==
                    "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed" and
                    observed.get("payload_scope") == (
                        "exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device "
                        "open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; "
                        "no allocation payloads emitted; addresses, paths, and handles omitted") and
                    observed.get("fd_lifecycle_scope") == (
                        "opaque file IDs assigned at observed open/openat/openat2 and "
                        "dup/dup2/dup3/fcntl(F_DUPFD*) calls; close() removes an ID; "
                        "close_range invalidates affected IDs; exec invalidates inherited IDs; "
                        "io_uring and external fd injection are not tracked; VMA file references "
                        "remain kernel-owned"),
                    "map observer exceeded its fixed payload or file-lifecycle scope")
            require(observed.get("fd_identity_capture_complete") is True,
                    "map observer has incomplete selected-file identity capture")
        elif not uvm_vaspace_fd_requested:
            require("fd_lifecycle_scope" not in observed and
                    "fd_identity_capture_complete" not in observed,
                    "unrequested map-memory scope was returned")
            if (not uvm_vaspace_fd_requested and not rm_control_requested and not rm_control_headers_requested and
                    not fabric_status_requested and not system_features_requested and
                    not sync_boost_groups_requested and
                    not ioctl_shapes_requested and
                    not device_alloc_requested and
                    not subdevice_alloc_requested and not binapi_alloc_requested):
                require("payload_scope" not in observed,
                        "unrequested RM_CONTROL payload scope was returned")
        if nested_requested:
            require(observed.get("nested_pointer_scope") == expected_scope,
                    "RM ioctl observer read outside the requested metadata payloads")
        if rm_control_requested:
            expected_payload_scope = (
                "RM_CONTROL headers plus exact NV503C P2P control payloads; raw addresses, handles, "
                "and VA-space tokens omitted; other nested parameter payloads omitted"
                if p2p_control_requested else
                "RM_CONTROL headers plus exact 992-byte NV2081_BINAPI payload-shape metadata; "
                "contained pointers are never followed; raw bytes, addresses, and handles omitted"
                if binapi_control_requested else
                "RM_CONTROL headers plus explicitly selected fixed metadata payloads; "
                "other nested parameters omitted" if nested_requested else
                "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted")
            require(observed.get("payload_scope") == expected_payload_scope,
                    "RM ioctl observer exceeded the requested RM_CONTROL payload scope")
        elif sync_boost_groups_requested:
            require(observed.get("payload_scope") ==
                    "exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; "
                    "inline GPU IDs and group payloads omitted; raw addresses and handles omitted",
                    "SYNC_GPU_BOOST_GROUP_INFO observer exceeded its exact fixed payload scope")
        elif system_features_requested:
            require(observed.get("payload_scope") ==
                    "exact root-global SYSTEM_GET_FEATURES 4-byte mask plus fixed RM_CONTROL headers; raw addresses and handles omitted",
                    "SYSTEM_GET_FEATURES observer exceeded its exact fixed payload scope")
        elif fabric_status_requested:
            require(observed.get("payload_scope") ==
                    "exact root-global Fabric Manager status enum plus fixed RM_CONTROL headers; raw addresses and handles omitted",
                    "Fabric Status observer exceeded its exact fixed payload scope")
        elif device_alloc_requested:
            require(observed.get("payload_scope") ==
                    "NV01_DEVICE_0 fixed class parameters only; handles are redacted and internal VA addresses are omitted",
                    "device-allocation observer exceeded its fixed redacted payload scope")
        elif subdevice_alloc_requested:
            require(observed.get("payload_scope") ==
                    "NV20_SUBDEVICE_0 fixed class parameters only; handles omitted",
                    "subdevice-allocation observer exceeded its fixed redacted payload scope")
        elif binapi_alloc_requested:
            require(observed.get("payload_scope") ==
                    "NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted",
                    "BINAPI-allocation observer exceeded its fixed redacted payload scope")
        elif (not uvm_vaspace_fd_requested and not map_memory_requested and not rm_control_headers_requested and
              not fabric_status_requested and not system_features_requested and
              not sync_boost_groups_requested and
              not ioctl_shapes_requested):
            require("payload_scope" not in observed,
                    "unrequested RM_CONTROL payload scope was returned")
        records = observed.get("records")
        empty_rusd_absence = (rusd_alloc_requested and
                              observed.get("rusd_payload_snapshots_read") == 0)
        empty_binapi_absence = binapi_control_requested and binapi_snapshots == 0
        empty_shape_absence = ioctl_shapes_requested and ioctl_shape_count == 0
        require(isinstance(records, list) and all(isinstance(record, dict) for record in records) and
                (bool(records) or empty_rusd_absence or empty_binapi_absence or empty_shape_absence),
                "RM ioctl observation contains no valid records")
        if uvm_vaspace_fd_requested:
            records = [record for record in records if record.get("operation") in (
                "uvm_register_gpu_vaspace", "uvm_map_external_allocation")]
            vaspace_records = [record for record in records
                               if record.get("operation") == "uvm_register_gpu_vaspace"]
            map_external_records = [record for record in records
                                    if record.get("operation") == "uvm_map_external_allocation"]
            uvm_fields = {"operation", "request", "field_read_at_entry",
                          "rm_ctrl_fd_identity_tracked_at_entry",
                          "rm_ctrl_fd_same_file_identity_at_exit",
                          "rm_ctrl_fd_field_unchanged_at_exit",
                          "rm_ctrl_fd_no_mutation_pending_at_entry",
                          "rm_ctrl_fd_no_mutation_pending_at_exit",
                          "uvm_fd_matches_selected_node_at_entry",
                          "rm_ctrl_fd_matches_control_node_at_entry",
                          "rm_ctrl_fd_matches_control_node_at_exit",
                          "rm_ctrl_fd_is_negative", "exit_observed", "syscall_return"}
            require(observed.get("uvm_path") == "/dev/nvidia-uvm" and
                    observed.get("fd_identity_tracking") is True and
                    observed.get("fd_identity_capture_complete") is True and
                    observed.get("fd_lifecycle_scope") == (
                        "selected control-node open, dup, fcntl-dup, close and close_range metadata "
                        "across traced shared descriptor tables; io_uring and external descriptor "
                        "injection are not tracked") and
                    observed.get("payload_scope") == (
                        "reads only pinned 4-byte rmCtrlFd fields in "
                        "UVM_REGISTER_GPU_VASPACE (offset 16) and "
                        "UVM_MAP_EXTERNAL_ALLOCATION (offset 9248) at syscall entry and return; checks "
                        "selected-node, transient in-memory file identity and pending "
                        "close/dup/range mutation; emits only "
                        "booleans; raw descriptor, payload, TID, file identity and ioctl "
                        "argument address omitted") and
                    observed.get("uvm_vaspace_records_seen") == len(vaspace_records) and
                    observed.get("uvm_map_external_records_seen") == len(map_external_records) and
                    remote.get("uvm_vaspace_records_seen") is True and
                    remote.get("uvm_map_external_records_seen") is (len(map_external_records) > 0) and
                    len(vaspace_records) > 0,
                    "UVM VA-space/map observer summary is incomplete")
            require(all(set(record) == uvm_fields and
                        ((record.get("operation") == "uvm_register_gpu_vaspace" and
                          record.get("request") == 25) or
                         (record.get("operation") == "uvm_map_external_allocation" and
                          record.get("request") == 33)) and
                        record.get("field_read_at_entry") is True and
                        record.get("rm_ctrl_fd_identity_tracked_at_entry") is True and
                        record.get("rm_ctrl_fd_same_file_identity_at_exit") is True and
                        record.get("rm_ctrl_fd_field_unchanged_at_exit") is True and
                        record.get("rm_ctrl_fd_no_mutation_pending_at_entry") is True and
                        record.get("rm_ctrl_fd_no_mutation_pending_at_exit") is True and
                        record.get("uvm_fd_matches_selected_node_at_entry") is True and
                        record.get("rm_ctrl_fd_matches_control_node_at_entry") is True and
                        record.get("rm_ctrl_fd_matches_control_node_at_exit") is True and
                        record.get("rm_ctrl_fd_is_negative") is False and
                        record.get("exit_observed") is True and
                        record.get("syscall_return") == 0 for record in records),
                    "UVM VA-space/map observer record is incomplete, unredacted, or unsuccessful")
        else:
            require(remote.get("uvm_vaspace_records_seen") is None and
                    remote.get("uvm_map_external_records_seen") is None and
                    "uvm_path" not in observed and
                    all(record.get("operation") not in (
                            "uvm_register_gpu_vaspace", "uvm_map_external_allocation")
                        for record in records),
                    "UVM descriptor results were returned without requesting capture")
        map_records_seen = any(record.get("operation") == "map_memory"
                               for record in records)
        require(remote.get("map_memory_records_seen", False) is map_records_seen,
                "remote map-memory record summary differs from the observer trace")
        require(not map_memory_requested or map_records_seen,
                "map-memory capture contains no RM map request")
        if map_memory_requested:
            class_counts = {}
            class_ids = set()
            for record in records:
                if record.get("operation") != "map_memory":
                    continue
                for phase in ("entry", "exit"):
                    payload = record.get(phase)
                    require(isinstance(payload, dict),
                            "map-memory record is missing its fixed packet snapshot")
                    ref = payload.get("memoryObjectClass")
                    require(isinstance(ref, dict) and set(ref) == {"resolution", "classId"} and
                            ref.get("resolution") in ("absent", "resolved", "not-observed-live-object",
                                                       "invalid-root", "ambiguous") and
                            ((ref.get("resolution") == "resolved" and
                              type(ref.get("classId")) is int and 0 < ref["classId"] <= 0xffffffff) or
                             (ref.get("resolution") != "resolved" and ref.get("classId") is None)),
                            "map-memory record has invalid memory-object class metadata")
                require(record["entry"]["memoryObjectClass"] ==
                        record["exit"]["memoryObjectClass"],
                        "map-memory object class changed during ioctl")
                ref = record["entry"]["memoryObjectClass"]
                resolution = ref["resolution"]
                class_counts[resolution] = class_counts.get(resolution, 0) + 1
                if resolution == "resolved":
                    class_ids.add(ref["classId"])
            remote["map_memory_class_resolution_counts"] = dict(sorted(class_counts.items()))
            remote["map_memory_class_ids"] = sorted(class_ids)
        id_info_seen = any(record.get("operation") == "gpu_id_info_v2" for record in records)
        require(remote.get("gpu_id_info_records_seen") is id_info_seen,
                "remote GPU-ID-info record summary differs from the observer trace")
        attached_ids_seen = any(record.get("operation") == "gpu_attached_ids" for record in records)
        require(remote.get("attached_ids_records_seen") is attached_ids_seen,
                "remote attached-ID record summary differs from the observer trace")
        probed_ids_seen = any(record.get("operation") == "gpu_probed_ids" for record in records)
        require(remote.get("probed_ids_records_seen") is probed_ids_seen,
                "remote probed-ID record summary differs from the observer trace")
        require(not probed_ids_requested or probed_ids_seen,
                "probed-ID capture contains no GPU_GET_PROBED_IDS record")
        if channel_alloc_requested:
            channel_records = [record for record in records
                               if record.get("operation") == "channel_alloc"]
            require(remote.get("channel_alloc_records_seen") is bool(channel_records),
                    "remote channel-allocation record summary differs from the observer trace")
            require(bool(channel_records), "channel capture contains no Volta channel allocation")
            require(all(record.get("fd_role") in ("control", "gpu")
                        for record in channel_records),
                    "channel allocation lacks a selected descriptor role")
            require(observed.get("channel_payload_snapshots_read") == 2 * len(channel_records),
                    "channel payload snapshot count differs from the observer trace")
            for record in channel_records:
                require(record.get("request") == 0xc030462b and
                        record.get("packet_size") == 48 and
                        record.get("syscall_return") == 0,
                        "channel allocation transport did not succeed")
                for phase in ("entry", "exit"):
                    packet = record.get(phase)
                    require(isinstance(packet, dict) and packet.get("hClass") == 0xc36f,
                            "channel capture contains a non-Volta channel class")
                    require(packet.get("pAllocParmsPresent") is True and
                            packet.get("channelPayloadState") == "r580-r595-class-layout-parsed",
                            "Volta channel class payload was not parsed")
                    channel = packet.get("channel")
                    require(isinstance(channel, dict) and
                            channel.get("classPayloadBytes") == 368,
                            "Volta channel class payload has an unexpected size")
        else:
            require(remote.get("channel_alloc_records_seen") is not True,
                    "channel-allocation records were reported without requesting capture")
        rusd_seen = any(record.get("operation") == "rusd_alloc" for record in records)
        require(remote.get("rusd_alloc_records_seen", False) is rusd_seen,
                "remote RUSD record summary differs from the observer trace")
        if rusd_alloc_requested:
            rusd_records = [record for record in records
                            if record.get("operation") == "rusd_alloc"]
            require(observed.get("rusd_payload_snapshots_read") == 2 * len(rusd_records),
                    "RUSD class payload snapshot count differs from the observer trace")
            record_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                             "operation", "entry", "exit", "syscall_return"}
            packet_fields = {"layout", "hClass", "paramsSize", "flags", "status",
                             "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                             "pAllocParmsPresent", "pRightsRequestedPresent",
                             "rusdPayloadState", "rusd"}
            for row in rusd_records:
                require(set(row) == record_fields and row.get("fd_role") in ("control", "gpu") and
                        row.get("request") == 0xc030462b and row.get("packet_size") == 48 and
                        row.get("syscall_return") == 0,
                        "RUSD RM allocation transport has unexpected fields or failed")
                masks = []
                for phase in ("entry", "exit"):
                    packet = row.get(phase)
                    require(isinstance(packet, dict) and set(packet) == packet_fields and
                            packet.get("layout") == "NVOS64" and
                            packet.get("hClass") == 0xde and
                            packet.get("paramsSize") == 0 and packet.get("status") == 0 and
                            packet.get("pAllocParmsPresent") is True and
                            packet.get("pRightsRequestedPresent") is False and
                            packet.get("rusdPayloadState") == "r580-r595-class-layout-parsed",
                            "RUSD class payload packet layout is malformed")
                    rusd = packet.get("rusd")
                    require(isinstance(rusd, dict) and set(rusd) ==
                            {"classPayloadBytes", "polledDataMask"} and
                            rusd.get("classPayloadBytes") == 8 and
                            type(rusd.get("polledDataMask")) is int and
                            0 <= rusd["polledDataMask"] <= 0xffffffffffffffff,
                            "RUSD class payload is malformed or unredacted")
                    masks.append(rusd["polledDataMask"])
                require(masks[0] == masks[1],
                        "RUSD polling mask changed during the observed allocation")
        else:
            require(remote.get("rusd_alloc_records_seen") is not True,
                    "RUSD allocation records were reported without requesting capture")
        p2p_seen = any(record.get("operation") == "p2p_alloc" for record in records)
        require(remote.get("p2p_alloc_records_seen", False) is p2p_seen,
                "remote P2P record summary differs from the observer trace")
        if p2p_alloc_requested:
            p2p_records = [record for record in records
                           if record.get("operation") == "p2p_alloc"]
            require(bool(p2p_records),
                    "P2P capture contains no NV50_THIRD_PARTY_P2P allocation")
            expected_snapshots = 0
            record_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                             "operation", "entry", "exit", "syscall_return"}
            packet_fields = {"layout", "hClass", "paramsSize", "flags", "status",
                             "hRootPresent", "hObjectParentPresent", "hObjectNewPresent",
                             "pAllocParmsPresent", "pRightsRequestedPresent",
                             "p2pPayloadState", "p2p"}
            type_names = {0: "proprietary", 1: "bar1", 2: "nvlink"}
            observed_types = []
            for row in p2p_records:
                require(set(row) == record_fields and row.get("fd_role") in ("control", "gpu") and
                        row.get("request") == 0xc030462b and row.get("packet_size") == 48 and
                        row.get("syscall_return") == 0,
                        "P2P allocation transport has unexpected fields or failed")
                snapshots_for_row = 0
                payloads = []
                for phase in ("entry", "exit"):
                    packet = row.get(phase)
                    require(isinstance(packet, dict) and set(packet) == packet_fields and
                            packet.get("layout") == "NVOS64" and
                            packet.get("hClass") == 0x503c and
                            packet.get("paramsSize") in (0, 4) and
                            type(packet.get("status")) is int and
                            0 <= packet["status"] <= 0xffffffff and
                            packet.get("pRightsRequestedPresent") is False,
                            "P2P class allocation packet layout is malformed")
                    if packet.get("pAllocParmsPresent") is False:
                        require(packet.get("p2pPayloadState") == "optional-payload-omitted" and
                                packet.get("p2p") is None,
                                "optional P2P payload is represented incorrectly")
                        payloads.append(None)
                        continue
                    require(packet.get("pAllocParmsPresent") is True and
                            packet.get("p2pPayloadState") == "r580-r595-class-layout-parsed",
                            "P2P class payload was not parsed")
                    p2p = packet.get("p2p")
                    require(isinstance(p2p, dict) and set(p2p) == {
                            "classPayloadBytes", "flags", "type", "typeName", "unknownFlagBits"} and
                            p2p.get("classPayloadBytes") == 4 and
                            type(p2p.get("flags")) is int and
                            0 <= p2p["flags"] <= 0xffffffff and
                            p2p.get("type") == (p2p["flags"] & 3) and
                            p2p.get("typeName") == type_names.get(p2p["type"], "unknown") and
                            p2p.get("unknownFlagBits") == (p2p["flags"] & ~3),
                            "P2P class payload is malformed or unredacted")
                    snapshots_for_row += 1
                    payloads.append(p2p)
                    observed_types.append(p2p["typeName"])
                expected_snapshots += snapshots_for_row
                require(payloads[0] == payloads[1],
                        "P2P flags changed during the observed allocation")
                require(row["exit"].get("status") == 0,
                        "P2P allocation embedded RM status failed")
            require(observed.get("p2p_payload_snapshots_read") == expected_snapshots,
                    "P2P class payload snapshot count differs from the observer trace")
            remote["p2p_allocation_types"] = sorted(set(observed_types))
        else:
            require(remote.get("p2p_alloc_records_seen") is not True,
                    "P2P allocation records were reported without requesting capture")
        if p2p_control_requested:
            commands = {0x503c0102: 16, 0x503c0103: 4, 0x503c0104: 32,
                        0x503c0105: 4, 0x503c0106: 4}
            expected_fields = {
                0x503c0102: {"command", "payloadBytes", "payloadValid",
                             "inputHandlePresent", "vaSpaceTokenNonzeroAtSnapshot"},
                0x503c0103: {"command", "payloadBytes", "payloadValid",
                             "inputHandlePresent"},
                0x503c0104: {"command", "payloadBytes", "payloadValid",
                             "inputHandlePresent", "addressAligned64K", "sizeNonzero",
                             "sizeAligned64K", "offsetAligned64K",
                             "offsetAndSizeDoNotOverflow", "addressAndSizeDoNotOverflow"},
                0x503c0105: {"command", "payloadBytes", "payloadValid",
                             "inputHandlePresent"},
                0x503c0106: {"command", "payloadBytes", "payloadValid",
                             "inputHandlePresent"},
            }
            outer_fields = {"command", "flags", "params_size", "status",
                            "hClientPresent", "hObjectPresent", "client_object_equal",
                            "client_matches_prior_root_allocation",
                            "object_matches_prior_root_allocation", "p2pControl",
                            "objectClass"}
            rows = [row for row in records
                    if isinstance(row.get("entry"), dict) and
                    isinstance(row["entry"].get("p2pControl"), dict)]
            require(bool(rows) and remote.get("p2p_control_records_seen") is True,
                    "P2P control capture contains no recognized NV503C controls")
            snapshots = 0
            for row in rows:
                require(row.get("operation") == "rm_control_header" and
                        row.get("fd_role") == "control" and
                        ((row.get("request") == 0xc020462a and row.get("packet_size") == 32) or
                         (row.get("request") == 0xc01046d3 and row.get("packet_size") == 16)) and
                        row.get("syscall_return") == 0,
                        "P2P RM_CONTROL transport is unexpected or failed")
                for phase in ("entry", "exit"):
                    outer = row.get(phase)
                    require(isinstance(outer, dict) and set(outer) == outer_fields and
                            outer.get("command") in commands and
                            outer.get("params_size") == commands[outer.get("command")] and
                            type(outer.get("status")) is int and
                            type(outer.get("hClientPresent")) is bool and
                            type(outer.get("hObjectPresent")) is bool and
                            outer.get("hClientPresent") is True and
                            outer.get("hObjectPresent") is True and
                            isinstance(outer.get("objectClass"), dict) and
                            set(outer["objectClass"]) == {"resolution", "classId"} and
                            outer["objectClass"].get("resolution") == "resolved" and
                            outer["objectClass"].get("classId") == 0x503c and
                            "hClient" not in outer and "hObject" not in outer and
                            "params_address" not in outer and "params" not in outer,
                            "P2P RM_CONTROL header is malformed or unredacted")
                    control = outer.get("p2pControl")
                    if control is None:
                        continue
                    command = outer["command"]
                    require(command in commands and set(control) == expected_fields[command] and
                            control.get("command") == command and
                            control.get("payloadBytes") == commands[command] and
                            control.get("payloadValid") is True and
                            control.get("inputHandlePresent") is True,
                            "NV503C fixed control payload is malformed or unredacted")
                    require(all(type(value) is bool for key, value in control.items()
                                if key not in ("command", "payloadBytes")),
                            "NV503C control payload contains a non-boolean private value")
                    if command == 0x503c0104:
                        require(all(control.get(key) is True for key in (
                            "addressAligned64K", "sizeNonzero", "sizeAligned64K",
                            "offsetAligned64K", "offsetAndSizeDoNotOverflow",
                            "addressAndSizeDoNotOverflow")),
                            "registered vidmem range violates the captured R580 constraints")
                    if phase == "exit":
                        require(outer.get("status") == 0,
                                "NV503C control returned a nonzero embedded RM status")
                    snapshots += 1
            require(observed.get("p2p_control_payload_snapshots_read") == snapshots and
                    snapshots >= 2,
                    "P2P control payload snapshot count differs from the trace")
        else:
            require(remote.get("p2p_control_records_seen") is not True,
                    "P2P control records were reported without requesting capture")
        if binapi_control_requested:
            helper_path = ROOT / "tools/run_remote_selected_gpu.py"
            helper_spec = importlib.util.spec_from_file_location(
                "pc3_v100_binapi_capture_contract", helper_path)
            if helper_spec is None or helper_spec.loader is None:
                raise ValueError("shared BINAPI capture contract could not be loaded")
            helper = importlib.util.module_from_spec(helper_spec)
            helper_spec.loader.exec_module(helper)
            try:
                records_seen, snapshots = helper.validate_binapi_control_observation(observed)
            except ValueError as error:
                raise ValueError(f"V100 BINAPI payload-shape capture is invalid: {error}") from error
            require(snapshots == binapi_snapshots and
                    remote.get("binapi_control_records_seen") is records_seen and
                    remote.get("binapi_payload_snapshots_read") == snapshots,
                    "V100 BINAPI capture summary differs from the observer trace")
        else:
            require(remote.get("binapi_control_records_seen") is not True,
                    "BINAPI control records were reported without requesting capture")
        if map_memory_requested:
            # Reuse the exact fd-lifecycle and map->mmap correlator used by the
            # RTX5080 acceptance runner; the report contains no raw addresses.
            helper_path = ROOT / "tools/run_remote_selected_gpu.py"
            helper_spec = importlib.util.spec_from_file_location(
                "pc3_v100_map_trace_contract", helper_path)
            if helper_spec is None or helper_spec.loader is None:
                raise ValueError("shared map-trace contract could not be loaded")
            helper = importlib.util.module_from_spec(helper_spec)
            helper_spec.loader.exec_module(helper)
            try:
                helper.validate_map_fd_lifecycle(records)
            except ValueError as error:
                raise ValueError("V100 map file identity lifecycle is invalid") from error
            maps = [record for record in records
                    if record.get("operation") == "map_memory"]
            unmaps = [record for record in records
                      if record.get("operation") == "unmap_memory"]
            map_fields = {"tid", "fd", "fd_file_id", "fd_role", "request",
                          "packet_size", "operation", "entry", "exit", "syscall_return"}
            map_payload_fields = {"backendFd", "backendFdRole", "backendFileId",
                                  "flags", "hClientPresent", "hDevicePresent",
                                  "hMemoryPresent", "length", "linearAddressPresent",
                                  "memoryObjectClass", "offsetNonzero", "status"}
            for row in maps:
                require(set(row) == map_fields and row.get("request") == 0xc038464e and
                        row.get("packet_size") == 56 and row.get("fd_role") == "control" and
                        isinstance(row.get("entry"), dict) and
                        isinstance(row.get("exit"), dict) and
                        set(row["entry"]) == map_payload_fields and
                        set(row["exit"]) == map_payload_fields and
                        type(row["entry"].get("length")) is int and
                        row["entry"]["length"] > 0 and
                        type(row["entry"].get("flags")) is int and
                        type(row["entry"].get("offsetNonzero")) is bool and
                        type(row["entry"].get("linearAddressPresent")) is bool and
                        type(row["entry"].get("status")) is int and
                        row["entry"].get("backendFdRole") in ("control", "gpu"),
                        "RM map packet has unexpected layout or unredacted fields")
                for phase in ("entry", "exit"):
                    ref = row[phase]["memoryObjectClass"]
                    require(isinstance(ref, dict) and set(ref) == {"resolution", "classId"} and
                            ref.get("resolution") in ("absent", "resolved", "not-observed-live-object",
                                                       "invalid-root", "ambiguous") and
                            ((ref.get("resolution") == "resolved" and
                              type(ref.get("classId")) is int and 0 < ref["classId"] <= 0xffffffff) or
                             (ref.get("resolution") != "resolved" and ref.get("classId") is None)),
                            "RM map packet has invalid memory-object class metadata")
                require(row["entry"]["memoryObjectClass"] ==
                        row["exit"]["memoryObjectClass"],
                        "RM map packet memory-object class changed during ioctl")
            unmap_fields = {"tid", "fd", "fd_file_id", "fd_role", "request",
                            "packet_size", "operation", "entry", "exit", "syscall_return"}
            unmap_payload_fields = {"flags", "hClientPresent", "hDevicePresent",
                                    "hMemoryPresent", "linearAddressPresent", "status"}
            for row in unmaps:
                require(set(row) == unmap_fields and row.get("request") == 0xc020464f and
                        row.get("packet_size") == 32 and row.get("fd_role") == "control" and
                        isinstance(row.get("entry"), dict) and
                        isinstance(row.get("exit"), dict) and
                        set(row["entry"]) == unmap_payload_fields and
                        set(row["exit"]) == unmap_payload_fields,
                        "RM unmap packet has unexpected layout or unredacted fields")
            mmap_rows = [record for record in records
                         if record.get("operation") == "mmap"]
            for row in mmap_rows:
                require(set(row) == {"tid", "fd", "fd_file_id", "fd_role", "request",
                                     "packet_size", "operation", "mmap_succeeded", "entry",
                                     "exit", "syscall_return"} and row.get("request") == 9 and
                        row.get("packet_size") == 0 and row.get("syscall_return") is None and
                        row.get("exit") is None and type(row.get("mmap_succeeded")) is bool and
                        isinstance(row.get("entry"), dict) and
                        set(row["entry"]) == {"length", "prot", "flags", "offsetZero"} and
                        type(row["entry"].get("length")) is int and
                        row["entry"]["length"] > 0 and
                        type(row["entry"].get("prot")) is int and
                        type(row["entry"].get("flags")) is int and
                        type(row["entry"].get("offsetZero")) is bool,
                        "mmap record has unexpected layout or unredacted metadata")
            close_rows = [record for record in records
                          if record.get("operation") == "close"]
            for row in close_rows:
                require(set(row) == {"tid", "fd", "fd_file_id", "fd_role", "request",
                                     "packet_size", "operation", "close_succeeded", "entry",
                                     "exit", "syscall_return"} and row.get("request") == 3 and
                        row.get("packet_size") == 0 and row.get("entry") is None and
                        row.get("exit") is None and type(row.get("syscall_return")) is int and
                        type(row.get("close_succeeded")) is bool and
                        row.get("close_succeeded") == (row.get("syscall_return") == 0),
                        "close record has unexpected descriptor metadata")
            successful_maps = [record for record in maps
                               if record.get("syscall_return") == 0 and
                               isinstance(record.get("exit"), dict) and
                               record["exit"].get("status") == 0 and
                               record["exit"].get("backendFdRole") == "gpu"]
            successful_unmaps = [record for record in unmaps
                                 if record.get("syscall_return") == 0 and
                                 isinstance(record.get("exit"), dict) and
                                 record["exit"].get("status") == 0]
            try:
                correlated_mmaps = helper.correlated_gpu_mmap_count(records)
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("V100 map-to-mmap correlation is malformed") from error
            require(bool(successful_maps) and bool(successful_unmaps),
                    "map capture contains no successful RM map and unmap")
            require(correlated_mmaps > 0,
                    "map capture contains no successful mmap on the mapped GPU file identity")
            class_counts = {}
            class_ids = set()
            for row in maps:
                ref = row["entry"]["memoryObjectClass"]
                resolution = ref["resolution"]
                class_counts[resolution] = class_counts.get(resolution, 0) + 1
                if resolution == "resolved":
                    class_ids.add(ref["classId"])
            remote["map_memory_class_resolution_counts"] = dict(sorted(class_counts.items()))
            remote["map_memory_class_ids"] = sorted(class_ids)
        rm_control_seen = any(record.get("operation") in
                              ("rm_control_header", "gpu_id_info_v2", "gpu_attached_ids",
                               "gpu_probed_ids", "binapi_control")
                              for record in records)
        if rm_control_requested:
            require(remote.get("rm_control_records_seen") is rm_control_seen and
                    (rm_control_seen or binapi_control_requested),
                    "remote RM_CONTROL record summary differs from the observer trace")
        else:
            require(remote.get("rm_control_records_seen") is None,
                    "RM_CONTROL records were reported without an RM_CONTROL capture request")
    else:
        require("ioctl_observation" not in remote and "observer_exit_code" not in remote,
                "unrequested RM ioctl observation was returned")
        require(remote.get("gpu_id_info_records_seen") is None,
                "GPU-ID-info records were reported without an ioctl observer")
        require(remote.get("attached_ids_records_seen") is None,
                "attached-ID records were reported without an ioctl observer")
        require(remote.get("probed_ids_records_seen") is None,
                "probed-ID records were reported without an ioctl observer")
        require(remote.get("rm_control_records_seen") is None,
                "RM_CONTROL records were reported without an ioctl observer")
        require(remote.get("channel_alloc_records_seen") is None,
                "channel-allocation records were reported without an ioctl observer")
        require(remote.get("map_memory_records_seen") is None,
                "map-memory records were reported without an ioctl observer")
    if trace_requested:
        trace = remote.get("ioctl_trace")
        require(isinstance(trace, dict) and trace.get("trace_complete") is True and
                trace.get("timed_out") is False,
                "requested ioctl strace capture is incomplete")
        capture = trace.get("trace")
        require(isinstance(capture, dict) and capture.get("trace_complete") is True and
                capture.get("size_limit_exceeded") is False,
                "requested ioctl trace is missing, truncated, or incomplete")
        summary = capture.get("summary")
        if requested_phase in ("enumerate", "context"):
            require(isinstance(summary, dict) and
                    summary.get("schema") == "nvidia-hybrid-node-open-trace-v1" and
                    summary.get("qualification") == "complete-node-open-trace" and
                    summary.get("trace_complete") is True and
                    summary.get("selected_node_open_count", 0) > 0 and
                    summary.get("successful_selected_node_open_count", 0) > 0 and
                    summary.get("unparsed_lines") == [],
                    "enumeration ioctl trace has an incomplete NVIDIA node-open lifecycle")
        else:
            require(isinstance(summary, dict) and summary.get("trace_complete") is True and
                    summary.get("parsed_calls", 0) > 0,
                    "ioctl trace contains no complete parsed calls")
            if requested_phase == "managed-accessed-by":
                calls = summary.get("calls")
                advice_calls = [call for call in calls if isinstance(call, dict) and
                                call.get("request") in ("0x2e", "0x2f") and
                                call.get("node") == "/dev/nvidia-uvm"] if isinstance(calls, list) else []
                set_call = next((call for call in advice_calls
                                 if call.get("request") == "0x2e"), None)
                unset_call = next((call for call in advice_calls
                                   if set_call is not None and
                                   call.get("request") == "0x2f" and
                                   type(call.get("line")) is int and
                                   type(set_call.get("line")) is int and
                                   call["line"] > set_call["line"]), None)
                require(summary.get("schema") == "nvidia-hybrid-ioctl-metadata-summary-v2" and
                        summary.get("negative_syscall_returns") == 0 and
                        summary.get("unparsed_lines") == [] and
                        set_call is not None and set_call.get("syscall_return") == 0 and
                        unset_call is not None and unset_call.get("syscall_return") == 0 and
                        type(set_call.get("pid")) is int and
                        unset_call.get("pid") == set_call.get("pid"),
                        "managed-accessed-by trace must show successful SET_ACCESSED_BY (0x2e) then UNSET_ACCESSED_BY (0x2f) UVM ioctls from the probe process")
        require(isinstance(trace.get("strace_version"), str) and
                trace["strace_version"].startswith("strace -- version ") and
                re.fullmatch(r"[0-9a-f]{64}", trace.get("strace_sha256", "")) is not None,
                "strace identity is missing or invalid")
    else:
        require("ioctl_trace" not in remote and "ioctl_trace_transport" not in remote,
                "unrequested ioctl strace data was returned")
    if requested_phase == "system-pageable-memory":
        return "v100-" + phase_qualification
    if p2p_fault_mode is not None:
        return "p2p-fault-injection-report-contract-valid"
    return "v100-cuda-phase-report-contract-valid" if requested_phase is not None else "v100-reference-report-contract-valid"


def validate_r58019607_stock_v100_rejection(
        remote: object, expected_artifacts: dict[str, dict[str, object]]) -> str:
    """Accept only the exact, non-disruptive 803 rejection as negative evidence."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(remote, dict) and
            remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1" and
            remote.get("host") == "pc3" and
            remote.get("qualification") == "probe-executed",
            "R580 compatibility rejection lacks a completed PC3 guest run")
    require(remote.get("libcuda_override_requested") is True and
            remote.get("phase") == "enumerate" and
            remote.get("system_features_capture_requested") is True,
            "R580 compatibility rejection used an unexpected test mode")
    scope = remote.get("execution_scope")
    require(isinstance(scope, dict) and all(scope.get(key) is False for key in
            ("guest_driver_changed", "module_loaded", "vm_management_issued", "pci_binding_changed")),
            "R580 compatibility rejection changed protected execution state")
    guest = remote.get("guest")
    guest_after = remote.get("guest_after")
    require(isinstance(guest, dict) and guest.get("hostname") == "pc3-v100" and
            str(guest.get("name", "")).startswith("Tesla V100") and
            guest.get("driver_version") == "580.178.04" and
            guest.get("uuid") == "GPU-42d06a85-027a-75ea-7857-a8de27ad465e" and
            canonical_pci(str(guest.get("pci", ""))) == "0000:00:05.0",
            "negative R580 result is not bound to the pinned stock V100 guest")
    require(isinstance(guest_after, dict) and
            guest_after.get("uuid") == guest.get("uuid") and
            canonical_pci(str(guest_after.get("pci", ""))) == canonical_pci(str(guest.get("pci", ""))) and
            guest_after.get("driver_version") == guest.get("driver_version") and
            remote.get("compute_process_count_prelaunch") == 0 and
            remote.get("compute_process_query_after_valid") is True and
            remote.get("compute_process_count_after_probe") == 0 and
            guest_after.get("compute_process_count") == 0,
            "V100 guest or compute-process state changed during the rejection test")
    require(remote.get("guest_cleanup_passed") is True and
            remote.get("payload_file_cleanup_passed") is True and
            remote.get("libcuda_override_temp_cleanup_passed") is True,
            "R580 compatibility rejection left temporary guest artifacts")

    probe = remote.get("probe")
    require(isinstance(probe, dict) and probe.get("schema") == "nvidia-cuda-driver-phase-v1" and
            probe.get("phase") == "enumerate" and probe.get("status") == "phase-failed" and
            remote.get("probe_exit_code") == 2 and
            "CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH)" in str(probe.get("error", "")) and
            probe.get("selected_device") is None,
            "R580 negative result is not the exact pre-enumeration CUDA driver mismatch")
    library = remote.get("driver_library")
    require(isinstance(library, dict) and
            library.get("path") == probe.get("driver_library_path") and
            library.get("bytes") == R580_19607_LIBCUDA_BYTES and
            library.get("sha256") == R580_19607_LIBCUDA_SHA256,
            "rejected probe did not load the pinned R580.196.07 libcuda")
    before = remote.get("artifacts_before")
    after = remote.get("artifacts_after")
    require(isinstance(before, dict) and set(before) == set(expected_artifacts) and
            isinstance(after, dict), "R580 rejection artifact inventory is incomplete")
    for name, expected in expected_artifacts.items():
        item = before.get(name)
        require(isinstance(item, dict) and item.get("bytes") == expected.get("bytes") and
                item.get("sha256") == expected.get("sha256") and
                isinstance(item.get("guest_path"), str) and
                item["guest_path"].startswith("/tmp/codex-v100-ref-") and
                after.get(item["guest_path"]) ==
                {"bytes": expected.get("bytes"), "sha256": expected.get("sha256")},
                f"R580 rejection artifact failed identity or cleanup verification: {name}")
    require(library.get("path") == before["libcuda"].get("guest_path"),
            "R580 rejection did not use the exact staged user library")
    observed = remote.get("ioctl_observation")
    require(isinstance(observed, dict) and
            observed.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v25" and
            observed.get("errors") == [] and
            observed.get("child_exit_code") == 2,
            "R580 rejection lacks a clean, read-only feature-query observer record")
    return "r58019607-rejection-report-contract-valid"


def guest_ssh_base(private_key: str, known_hosts: str) -> list[str]:
    return ["ssh", "-F", "/dev/null", "-T", "-oBatchMode=yes", "-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + known_hosts,
            "-oConnectTimeout=8", "-oConnectionAttempts=1", "-i", private_key,
            "-p", "22223", "ubuntu@127.0.0.1"]


def payload_staging_path(nonce: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("invalid temporary payload identifier")
    return "/tmp/codex-v100-payload-" + nonce + ".json"


def sudo_auth_stdin(secret: str) -> bytes:
    return (validate_sudo_secret(secret) + "\n").encode("utf-8")


def payload_writer_code() -> str:
    return r'''import hashlib,json,os,re,sys
from pathlib import Path
path,digest=sys.argv[1:]
if not re.fullmatch(r"/tmp/codex-v100-payload-[0-9a-f]{32}\.json",path):raise SystemExit(2)
data=sys.stdin.buffer.read()
if hashlib.sha256(data).hexdigest()!=digest:raise SystemExit(3)
p=Path(path)
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"wb") as f:f.write(data)
p.chmod(0o600)
print(json.dumps({"bytes":len(data),"sha256":digest}))
'''


def payload_cleanup_code() -> str:
    return r'''import hashlib,json,os,re,stat,sys
from pathlib import Path
path,digest=sys.argv[1:]
if not re.fullmatch(r"/tmp/codex-v100-payload-[0-9a-f]{32}\.json",path):raise SystemExit(2)
p=Path(path); passed=False
try:
 st=p.lstat()
 if stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600 and hashlib.sha256(p.read_bytes()).hexdigest()==digest:
  p.unlink(); passed=True
except FileNotFoundError:passed=True
print(json.dumps({"cleanup_passed":passed,"remaining":p.exists()}))
'''


def verify_guest_host_key(known: Path, expected_fingerprint: str, expected_uid: int, run) -> None:
    """Verify one root-controlled known_hosts file and the exact forwarded guest endpoint."""
    known_stat = known.lstat()
    if (not stat.S_ISREG(known_stat.st_mode) or known_stat.st_uid != expected_uid or
            known_stat.st_mode & 0o022):
        raise RuntimeError("guest known-hosts ownership or mode is unsafe")

    selected = run(["ssh-keygen", "-F", "[127.0.0.1]:22223", "-f", str(known)], timeout=10)
    selected_lines = [line for line in selected.stdout.decode("utf-8", "replace").splitlines()
                      if line and not line.startswith("#")]
    if (selected.returncode or not selected_lines or
            any(line.split()[0].startswith("@") or len(line.split()) < 3 for line in selected_lines)):
        raise RuntimeError("guest host key entry for the forwarded endpoint is invalid")

    matched_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="codex-v100-known-hosts-",
                                         dir="/tmp", delete=False) as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write("\n".join(selected_lines) + "\n")
            matched_file = stream.name
        fingerprints_result = run(["ssh-keygen", "-lf", matched_file], timeout=10)
    finally:
        if matched_file is not None:
            os.unlink(matched_file)
    fingerprints = {line.split()[1] for line in fingerprints_result.stdout.decode("utf-8", "replace").splitlines()
                    if len(line.split()) > 1}
    if fingerprints_result.returncode or fingerprints != {expected_fingerprint}:
        raise RuntimeError("guest endpoint does not contain exactly the pinned host key")


def clean_cuda_environment(source: dict[str, str], gpu_uuid: str | None = None) -> dict[str, str]:
    env = {key: value for key, value in source.items()
           if not key.startswith(("LD_", "CUDA_", "NVIDIA_", "PYTHON"))}
    env["PATH"] = "/usr/bin:/bin"
    env["LC_ALL"] = "C"
    if gpu_uuid:
        env["CUDA_VISIBLE_DEVICES"] = gpu_uuid
    return env


def identity(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    data = resolved.read_bytes()
    return {"path": str(resolved), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def verify_pinned_probe_build(probe_identity: object,
                              module_identity: object) -> dict[str, str]:
    """Reject synthetic or stale executables before the V100 reference can run."""
    if (not isinstance(probe_identity, dict) or
            probe_identity.get("sha256") != PINNED_PROBE_SHA256):
        raise ValueError("CUDA probe hash differs from the pinned probe build")
    if (not isinstance(module_identity, dict) or
            module_identity.get("sha256") != PINNED_MODULE_SHA256):
        raise ValueError("CUDA fatbin hash differs from the pinned probe build")
    return {"status": "trusted-pinned-build",
            "probe_sha256": PINNED_PROBE_SHA256,
            "module_sha256": PINNED_MODULE_SHA256,
            "provenance": "pinned-probe-and-fatbin-sha256"}


def p2p_fault_shim_identity(path: Path) -> dict[str, object]:
    """Accept only a regular x86_64 ELF shared object, pinned through one fd."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("P2P fault injector is unavailable or is a symlink") from error
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        header = stream.read(64)
        if (not stat.S_ISREG(info.st_mode) or len(header) != 64 or
                header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1 or
                int.from_bytes(header[16:18], "little") != 3 or
                int.from_bytes(header[18:20], "little") != 62):
            raise ValueError("P2P fault injector must be an x86_64 ELF64 shared object")
        digest = hashlib.sha256(header)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path.resolve(strict=True)), "bytes": info.st_size,
            "sha256": digest.hexdigest()}


def r58019607_libcuda_identity(path: Path) -> dict[str, object]:
    """Pin the only user-library override this guarded V100 experiment accepts."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("R580.196.07 libcuda override is unavailable") from error
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or path.name != "libcuda.so.580.196.07" or
                info.st_size != R580_19607_LIBCUDA_BYTES):
            raise ValueError("libcuda override must be the exact regular R580.196.07 image")
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        if digest.hexdigest() != R580_19607_LIBCUDA_SHA256:
            raise ValueError("libcuda override does not match the pinned R580.196.07 image")
    return {"path": str(path.resolve(strict=True)), "bytes": info.st_size,
            "sha256": R580_19607_LIBCUDA_SHA256}


def _credential_remote_script() -> str:
    return r'''import configparser, os, stat, sys
from pathlib import Path
p = Path(sys.argv[1])
st = p.stat()
if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_uid != os.getuid():
    raise SystemExit(3)
c = configparser.ConfigParser(interpolation=None, strict=True)
try:
    c.read(p, encoding="utf-8")
    v = c.get("pc3", "password_sudo", raw=True).strip()
except (configparser.Error, KeyError, ValueError):
    raise SystemExit(4)
if not v or "\n" in v or "\r" in v or "\0" in v:
    raise SystemExit(5)
sys.stdout.write(v)
'''


REMOTE_ROOT_SCRIPT = r'''import base64, csv, hashlib, json, os, re, shlex, stat, subprocess, sys, tempfile, uuid
from pathlib import Path

GUEST_KEY = "/var/lib/pc3-v100-vm/id_ed25519"
GUEST_KNOWN_HOSTS = "/tmp/codex-pc3-vm-known_hosts"
EXPECTED_FINGERPRINT = "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
SIZES = [1, 31, 256, 4096, 65537]
stage = "preflight"
report = {"schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
          "host": os.uname().nodename, "host_kernel_release": os.uname().release,
          "guest": None, "artifacts_before": {}, "artifacts_after": {},
          "probe_exit_code": None, "probe": None, "driver_library": None,
          "p2p_fault_requested": False, "p2p_fault_mode": None,
          "p2p_fault_denial_count": 0,
          "gpu_id_info_capture_requested": False, "gpu_id_info_records_seen": None,
          "attached_ids_capture_requested": False, "attached_ids_records_seen": None,
          "probed_ids_capture_requested": False, "probed_ids_records_seen": None,
          "rm_control_capture_requested": False, "rm_control_records_seen": None,
          "rm_control_headers_capture_requested": False,
          "rm_control_headers_records_seen": None,
          "rm_control_headers_record_count": None,
          "fabric_status_capture_requested": False,
          "fabric_status_records_seen": None,
          "fabric_status_record_count": None,
          "fabric_status_values": None,
          "system_features_capture_requested": False,
          "system_features_records_seen": None,
          "system_features_record_count": None,
          "system_features_masks": None,
          "sync_boost_groups_capture_requested": False,
          "sync_boost_groups_records_seen": None,
          "sync_boost_groups_record_count": None,
          "sync_boost_group_counts": None,
          "sync_boost_group_payload_snapshots_read": None,
          "ioctl_shapes_capture_requested": False,
          "ioctl_shape_records_seen": None,
          "ioctl_shape_record_count": None,
          "ioctl_shape_request_counts": None,
          "uvm_vaspace_fd_capture_requested": False,
          "uvm_vaspace_records_seen": None,
          "uvm_map_external_records_seen": None,
          "channel_alloc_capture_requested": False, "channel_alloc_records_seen": None,
          "map_memory_capture_requested": False, "map_memory_records_seen": None,
          "rusd_alloc_capture_requested": False, "rusd_alloc_records_seen": None,
          "p2p_alloc_capture_requested": False, "p2p_alloc_records_seen": None,
          "p2p_control_capture_requested": False, "p2p_control_records_seen": None,
          "binapi_control_capture_requested": False, "binapi_control_records_seen": None,
          "binapi_payload_snapshots_read": None,
          "device_alloc_capture_requested": False, "device_alloc_records_seen": None,
          "device_alloc_payload_snapshots_read": None,
          "subdevice_alloc_capture_requested": False, "subdevice_alloc_records_seen": None,
          "subdevice_alloc_payload_snapshots_read": None,
          "binapi_alloc_capture_requested": False, "binapi_alloc_records_seen": None,
          "binapi_alloc_payload_snapshots_read": None,
          "phase_capture_requested": False, "phase": None,
          "libcuda_override_requested": False,
          "libcuda_override_temp_cleanup_passed": None,
          "cuda_graphs_requested": False,
          "guest_cleanup_passed": False, "qualification": "failed",
          "execution_scope": {"guest_driver_changed": False, "module_loaded": False,
                              "vm_management_issued": False, "pci_binding_changed": False}}

def canonical_pci(value):
    m = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not m or int(m.group(3), 16) > 31:
        raise ValueError("invalid PCI identity")
    return f"{int(m.group(1),16)&0xffff:04x}:{int(m.group(2),16):02x}:{int(m.group(3),16):02x}.{int(m.group(4),16)}"

def call(argv, input_data=None, timeout=30):
    return subprocess.run(argv, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False,
                          env={k:v for k,v in os.environ.items() if not k.startswith(("LD_","CUDA_","NVIDIA_","PYTHON"))} |
                              {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})

def guest_base():
    return ["ssh", "-F", "/dev/null", "-T", "-oBatchMode=yes", "-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + GUEST_KNOWN_HOSTS,
            "-oConnectTimeout=8", "-oConnectionAttempts=1", "-i", GUEST_KEY,
            "-p", "22223", "ubuntu@127.0.0.1"]

def remote_command(argv):
    return " ".join(shlex.quote(str(v)) for v in argv)

def guest_json(code, args=(), input_data=None, timeout=35):
    command = remote_command(["python3", "-c", code, *args])
    result = call(guest_base() + [command], input_data=input_data, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError("guest SSH command failed")
    return json.loads(result.stdout.decode("utf-8"))

###GUEST_HOSTKEY_HELPER###

def validate_ioctl_shapes_selection(phase, other_modes):
    if phase not in (None, "kernel") or any(other_modes):
        raise ValueError("ioctl payload-shape capture requires an isolated kernel-phase observer")

def main(payload):
    global stage
    phase = payload.get("phase")
    if phase is not None and phase not in (
            "initialize", "enumerate", "context", "allocation", "module", "kernel",
            "managed-accessed-by", "system-pageable-memory"):
        raise ValueError("unsupported CUDA Driver API phase")
    libcuda_override = payload.get("libcuda_override", False)
    if type(libcuda_override) is not bool:
        raise ValueError("libcuda override selection must be boolean")
    report["libcuda_override_requested"] = libcuda_override
    report["phase_capture_requested"] = phase is not None
    report["phase"] = phase
    p2p_fault_mode = payload.get("p2p_fault_mode")
    p2p_fault_requested = p2p_fault_mode is not None
    if p2p_fault_requested and p2p_fault_mode not in (
            "alloc", "register-va", "register-vidmem", "unregister-vidmem"):
        raise ValueError("unsupported P2P fault mode")
    if p2p_fault_requested != ("p2p-fault-shim" in payload.get("artifacts", {})):
        raise ValueError("P2P fault mode and shim artifact must be supplied together")
    if p2p_fault_requested and (phase is not None or payload.get("libcuda_override") or
            payload.get("ioctl_trace") or payload.get("managed_memory") or
            payload.get("managed_prefetch") or payload.get("cuda_graphs") or
            payload.get("performance_benchmark") or
            any(payload.get(key, False) for key in (
                "gpu_id_info_capture", "attached_ids_capture", "probed_ids_capture",
                "rm_control_capture", "rm_control_headers_capture",
                "fabric_status_capture", "system_features_capture",
                "sync_boost_groups_capture", "channel_alloc_capture",
                "map_memory_capture", "rusd_alloc_capture", "p2p_alloc_capture",
                "p2p_control_capture", "binapi_control_capture", "device_alloc_capture",
                "subdevice_alloc_capture", "binapi_alloc_capture", "ioctl_shapes_capture",
                "uvm_vaspace_fd_capture")) or "observer" in payload.get("artifacts", {}) or
            "trace-helper" in payload.get("artifacts", {})):
        raise ValueError("P2P fault injection requires an isolated full CUDA reference")
    report["p2p_fault_requested"] = p2p_fault_requested
    report["p2p_fault_mode"] = p2p_fault_mode
    managed_memory = payload.get("managed_memory", False)
    if type(managed_memory) is not bool:
        raise ValueError("managed-memory selection must be boolean")
    report["memory_mode"] = "managed" if managed_memory else "device"
    managed_prefetch = payload.get("managed_prefetch", False)
    if type(managed_prefetch) is not bool:
        raise ValueError("managed-prefetch selection must be boolean")
    if managed_prefetch and not managed_memory:
        raise ValueError("managed-prefetch requires managed-memory mode")
    report["managed_prefetch_requested"] = managed_prefetch
    cuda_graphs = payload.get("cuda_graphs", False)
    if type(cuda_graphs) is not bool:
        raise ValueError("CUDA Graph selection must be boolean")
    if cuda_graphs and phase is not None:
        raise ValueError("CUDA Graph testing cannot be combined with a phase-only probe")
    report["cuda_graphs_requested"] = cuda_graphs
    performance_benchmark = payload.get("performance_benchmark", False)
    if type(performance_benchmark) is not bool:
        raise ValueError("performance benchmark selection must be boolean")
    if performance_benchmark and (phase is not None or managed_memory or managed_prefetch or
                                  cuda_graphs or payload.get("ioctl_trace") or
                                  any(payload.get(key, False) for key in (
                                      "gpu_id_info_capture", "attached_ids_capture",
                                      "probed_ids_capture", "rm_control_capture",
                                      "rm_control_headers_capture", "fabric_status_capture",
                                      "system_features_capture", "sync_boost_groups_capture",
                                      "channel_alloc_capture",
                                      "map_memory_capture", "rusd_alloc_capture",
                                      "p2p_alloc_capture", "p2p_control_capture",
                                      "binapi_control_capture", "device_alloc_capture",
                                      "subdevice_alloc_capture", "binapi_alloc_capture"))):
        raise ValueError("performance benchmark requires an isolated device-memory reference")
    report["performance_benchmark_requested"] = performance_benchmark
    gpu_id_info_capture = payload.get("gpu_id_info_capture", False)
    if type(gpu_id_info_capture) is not bool:
        raise ValueError("GPU-ID-info capture selection must be boolean")
    if gpu_id_info_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("GPU-ID-info capture requires the RM ioctl observer")
    report["gpu_id_info_capture_requested"] = gpu_id_info_capture
    attached_ids_capture = payload.get("attached_ids_capture", False)
    if type(attached_ids_capture) is not bool:
        raise ValueError("attached-ID capture selection must be boolean")
    if (gpu_id_info_capture or attached_ids_capture) and "observer" not in payload.get("artifacts", {}):
        raise ValueError("GPU metadata capture requires the RM ioctl observer")
    report["attached_ids_capture_requested"] = attached_ids_capture
    probed_ids_capture = payload.get("probed_ids_capture", False)
    if type(probed_ids_capture) is not bool:
        raise ValueError("probed-ID capture selection must be boolean")
    if probed_ids_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("probed-ID capture requires the RM ioctl observer")
    report["probed_ids_capture_requested"] = probed_ids_capture
    rm_control_capture = payload.get("rm_control_capture", False)
    if type(rm_control_capture) is not bool:
        raise ValueError("RM_CONTROL capture selection must be boolean")
    if rm_control_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("RM_CONTROL capture requires the RM ioctl observer")
    report["rm_control_capture_requested"] = rm_control_capture
    rm_control_headers_capture = payload.get("rm_control_headers_capture", False)
    if type(rm_control_headers_capture) is not bool:
        raise ValueError("redacted RM_CONTROL header capture selection must be boolean")
    if rm_control_headers_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("redacted RM_CONTROL header capture requires the RM ioctl observer")
    if rm_control_headers_capture and (phase != "enumerate" or any((
            rm_control_capture, gpu_id_info_capture, attached_ids_capture,
            probed_ids_capture, payload.get("channel_alloc_capture"),
            payload.get("map_memory_capture"), payload.get("rusd_alloc_capture"),
            payload.get("p2p_alloc_capture"), payload.get("p2p_control_capture"),
            payload.get("binapi_control_capture"), payload.get("device_alloc_capture"),
            payload.get("subdevice_alloc_capture"), payload.get("binapi_alloc_capture"),
            payload.get("ioctl_trace"), managed_memory, managed_prefetch, cuda_graphs))):
        raise ValueError("redacted RM_CONTROL headers require an isolated enumeration phase")
    report["rm_control_headers_capture_requested"] = rm_control_headers_capture
    fabric_status_capture = payload.get("fabric_status_capture", False)
    if type(fabric_status_capture) is not bool:
        raise ValueError("Fabric Status capture selection must be boolean")
    if fabric_status_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("Fabric Status capture requires the RM ioctl observer")
    if fabric_status_capture and (phase != "enumerate" or any((
            payload.get("ioctl_trace"), managed_memory, managed_prefetch, cuda_graphs,
            gpu_id_info_capture, attached_ids_capture, probed_ids_capture,
            rm_control_capture, rm_control_headers_capture,
            payload.get("channel_alloc_capture"), payload.get("map_memory_capture"),
            payload.get("rusd_alloc_capture"), payload.get("p2p_alloc_capture"),
            payload.get("p2p_control_capture"), payload.get("binapi_control_capture"),
            payload.get("device_alloc_capture"), payload.get("subdevice_alloc_capture"),
            payload.get("binapi_alloc_capture")))):
        raise ValueError("Fabric Status capture requires an isolated enumeration observer")
    report["fabric_status_capture_requested"] = fabric_status_capture
    system_features_capture = payload.get("system_features_capture", False)
    if type(system_features_capture) is not bool:
        raise ValueError("SYSTEM_GET_FEATURES capture selection must be boolean")
    if system_features_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("SYSTEM_GET_FEATURES capture requires the RM ioctl observer")
    if system_features_capture and (phase != "enumerate" or any((
            payload.get("ioctl_trace"), managed_memory, managed_prefetch, cuda_graphs,
            gpu_id_info_capture, attached_ids_capture, probed_ids_capture,
            rm_control_capture, rm_control_headers_capture, fabric_status_capture,
            payload.get("channel_alloc_capture"), payload.get("map_memory_capture"),
            payload.get("rusd_alloc_capture"), payload.get("p2p_alloc_capture"),
            payload.get("p2p_control_capture"), payload.get("binapi_control_capture"),
            payload.get("device_alloc_capture"), payload.get("subdevice_alloc_capture"),
            payload.get("binapi_alloc_capture")))):
        raise ValueError("SYSTEM_GET_FEATURES capture requires an isolated enumeration observer")
    report["system_features_capture_requested"] = system_features_capture
    sync_boost_groups_capture = payload.get("sync_boost_groups_capture", False)
    if type(sync_boost_groups_capture) is not bool:
        raise ValueError("SYNC_GPU_BOOST_GROUP_INFO capture selection must be boolean")
    if sync_boost_groups_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("SYNC_GPU_BOOST_GROUP_INFO capture requires the RM ioctl observer")
    if sync_boost_groups_capture and (phase != "enumerate" or any((
            payload.get("ioctl_trace"), managed_memory, managed_prefetch, cuda_graphs,
            gpu_id_info_capture, attached_ids_capture, probed_ids_capture,
            rm_control_capture, rm_control_headers_capture, fabric_status_capture,
            system_features_capture, payload.get("channel_alloc_capture"),
            payload.get("map_memory_capture"), payload.get("rusd_alloc_capture"),
            payload.get("p2p_alloc_capture"), payload.get("p2p_control_capture"),
            payload.get("binapi_control_capture"), payload.get("device_alloc_capture"),
            payload.get("subdevice_alloc_capture"), payload.get("binapi_alloc_capture"),
            payload.get("ioctl_shapes_capture"), payload.get("uvm_vaspace_fd_capture")))):
        raise ValueError("SYNC_GPU_BOOST_GROUP_INFO capture requires an isolated enumeration observer")
    report["sync_boost_groups_capture_requested"] = sync_boost_groups_capture
    channel_alloc_capture = payload.get("channel_alloc_capture", False)
    if type(channel_alloc_capture) is not bool:
        raise ValueError("channel-allocation capture selection must be boolean")
    if channel_alloc_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("channel-allocation capture requires the RM ioctl observer")
    if channel_alloc_capture and any((gpu_id_info_capture, attached_ids_capture,
                                     probed_ids_capture, rm_control_capture)):
        raise ValueError("channel-allocation capture must be an isolated observer mode")
    report["channel_alloc_capture_requested"] = channel_alloc_capture
    map_memory_capture = payload.get("map_memory_capture", False)
    if type(map_memory_capture) is not bool:
        raise ValueError("map-memory capture selection must be boolean")
    if map_memory_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("map-memory capture requires the RM ioctl observer")
    if map_memory_capture and any((gpu_id_info_capture, attached_ids_capture,
                                   probed_ids_capture, rm_control_capture,
                                   channel_alloc_capture)):
        raise ValueError("map-memory capture must be an isolated observer mode")
    if map_memory_capture and (payload.get("ioctl_trace") or managed_memory or managed_prefetch):
        raise ValueError("map-memory capture requires an isolated device-memory probe")
    report["map_memory_capture_requested"] = map_memory_capture
    rusd_alloc_capture = payload.get("rusd_alloc_capture", False)
    if type(rusd_alloc_capture) is not bool:
        raise ValueError("RUSD allocation capture selection must be boolean")
    if rusd_alloc_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("RUSD allocation capture requires the RM ioctl observer")
    if rusd_alloc_capture and any((payload.get("ioctl_trace"), managed_memory,
                                   managed_prefetch, gpu_id_info_capture,
                                   attached_ids_capture, probed_ids_capture,
                                   rm_control_capture, channel_alloc_capture,
                                   map_memory_capture)):
        raise ValueError("RUSD allocation capture must be an isolated device-memory observer mode")
    report["rusd_alloc_capture_requested"] = rusd_alloc_capture
    p2p_alloc_capture = payload.get("p2p_alloc_capture", False)
    if type(p2p_alloc_capture) is not bool:
        raise ValueError("P2P allocation capture selection must be boolean")
    if p2p_alloc_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("P2P allocation capture requires the RM ioctl observer")
    if p2p_alloc_capture and any((payload.get("ioctl_trace"), managed_memory,
                                  managed_prefetch, gpu_id_info_capture,
                                  attached_ids_capture, probed_ids_capture,
                                  rm_control_capture, channel_alloc_capture,
                                  map_memory_capture, rusd_alloc_capture)):
        raise ValueError("P2P allocation capture must be an isolated device-memory observer mode")
    report["p2p_alloc_capture_requested"] = p2p_alloc_capture
    p2p_control_capture = payload.get("p2p_control_capture", False)
    if type(p2p_control_capture) is not bool:
        raise ValueError("P2P control capture selection must be boolean")
    if p2p_control_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("P2P control capture requires the RM ioctl observer")
    if p2p_control_capture and not rm_control_capture:
        raise ValueError("P2P control capture requires RM_CONTROL capture")
    if p2p_control_capture and any((payload.get("ioctl_trace"), managed_memory,
                                    managed_prefetch, gpu_id_info_capture,
                                    attached_ids_capture, probed_ids_capture,
                                    channel_alloc_capture, map_memory_capture,
                                    rusd_alloc_capture, p2p_alloc_capture)):
        raise ValueError("P2P control capture must be isolated with RM_CONTROL headers")
    report["p2p_control_capture_requested"] = p2p_control_capture
    binapi_control_capture = payload.get("binapi_control_capture", False)
    if type(binapi_control_capture) is not bool:
        raise ValueError("BINAPI control capture selection must be boolean")
    if binapi_control_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("BINAPI control capture requires the RM ioctl observer")
    if binapi_control_capture and not rm_control_capture:
        raise ValueError("BINAPI control capture requires RM_CONTROL capture")
    if binapi_control_capture and any((payload.get("ioctl_trace"), managed_memory,
                                       managed_prefetch, gpu_id_info_capture,
                                       attached_ids_capture, probed_ids_capture,
                                       channel_alloc_capture, map_memory_capture,
                                       rusd_alloc_capture, p2p_alloc_capture,
                                       p2p_control_capture)):
        raise ValueError("BINAPI control capture must be isolated with RM_CONTROL headers")
    report["binapi_control_capture_requested"] = binapi_control_capture
    device_alloc_capture = payload.get("device_alloc_capture", False)
    if type(device_alloc_capture) is not bool:
        raise ValueError("NV01_DEVICE_0 allocation capture selection must be boolean")
    if device_alloc_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("NV01_DEVICE_0 allocation capture requires the RM ioctl observer")
    if device_alloc_capture and any((payload.get("ioctl_trace"), managed_memory,
                                     managed_prefetch, gpu_id_info_capture,
                                     attached_ids_capture, probed_ids_capture,
                                     rm_control_capture, channel_alloc_capture,
                                     map_memory_capture, rusd_alloc_capture,
                                     p2p_alloc_capture, p2p_control_capture,
                                     binapi_control_capture)):
        raise ValueError("NV01_DEVICE_0 allocation capture must be isolated")
    report["device_alloc_capture_requested"] = device_alloc_capture
    subdevice_alloc_capture = payload.get("subdevice_alloc_capture", False)
    if type(subdevice_alloc_capture) is not bool:
        raise ValueError("NV20_SUBDEVICE_0 allocation capture selection must be boolean")
    if subdevice_alloc_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("NV20_SUBDEVICE_0 allocation capture requires the RM ioctl observer")
    if subdevice_alloc_capture and any((payload.get("ioctl_trace"), managed_memory,
                                        managed_prefetch, gpu_id_info_capture,
                                        attached_ids_capture, probed_ids_capture,
                                        rm_control_capture, channel_alloc_capture,
                                        map_memory_capture, rusd_alloc_capture,
                                        p2p_alloc_capture, p2p_control_capture,
                                        binapi_control_capture, device_alloc_capture)):
        raise ValueError("NV20_SUBDEVICE_0 allocation capture must be isolated")
    report["subdevice_alloc_capture_requested"] = subdevice_alloc_capture
    binapi_alloc_capture = payload.get("binapi_alloc_capture", False)
    if type(binapi_alloc_capture) is not bool:
        raise ValueError("NV2081_BINAPI allocation capture selection must be boolean")
    if binapi_alloc_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("NV2081_BINAPI allocation capture requires the RM ioctl observer")
    if binapi_alloc_capture and any((payload.get("ioctl_trace"), managed_memory,
                                     managed_prefetch, gpu_id_info_capture,
                                     attached_ids_capture, probed_ids_capture,
                                     rm_control_capture, channel_alloc_capture,
                                     map_memory_capture, rusd_alloc_capture,
                                     p2p_alloc_capture, p2p_control_capture,
                                     binapi_control_capture, device_alloc_capture,
                                     subdevice_alloc_capture)):
        raise ValueError("NV2081_BINAPI allocation capture must be isolated")
    report["binapi_alloc_capture_requested"] = binapi_alloc_capture
    ioctl_shapes_capture = payload.get("ioctl_shapes_capture", False)
    if type(ioctl_shapes_capture) is not bool:
        raise ValueError("ioctl payload-shape capture selection must be boolean")
    if ioctl_shapes_capture and "observer" not in payload.get("artifacts", {}):
        raise ValueError("ioctl payload-shape capture requires the RM ioctl observer")
    if ioctl_shapes_capture:
        validate_ioctl_shapes_selection(phase, (
            payload.get("ioctl_trace"), managed_memory, managed_prefetch,
            cuda_graphs, performance_benchmark, gpu_id_info_capture,
            attached_ids_capture, probed_ids_capture, rm_control_capture,
            rm_control_headers_capture, fabric_status_capture, system_features_capture,
            sync_boost_groups_capture,
            channel_alloc_capture, map_memory_capture, rusd_alloc_capture,
            p2p_alloc_capture, p2p_control_capture, binapi_control_capture,
            device_alloc_capture, subdevice_alloc_capture, binapi_alloc_capture))
    report["ioctl_shapes_capture_requested"] = ioctl_shapes_capture
    uvm_vaspace_fd_capture = payload.get("uvm_vaspace_fd_capture", False)
    if type(uvm_vaspace_fd_capture) is not bool:
        raise ValueError("UVM VA-space descriptor capture selection must be boolean")
    if uvm_vaspace_fd_capture and (phase not in ("context", "kernel") or
            "observer" not in payload.get("artifacts", {}) or any((
                payload.get("ioctl_trace"), managed_memory, managed_prefetch, cuda_graphs,
                performance_benchmark, gpu_id_info_capture, attached_ids_capture,
                probed_ids_capture, rm_control_capture, rm_control_headers_capture,
                fabric_status_capture, system_features_capture, channel_alloc_capture,
                sync_boost_groups_capture,
                map_memory_capture, rusd_alloc_capture, p2p_alloc_capture,
                p2p_control_capture, binapi_control_capture, device_alloc_capture,
                subdevice_alloc_capture, binapi_alloc_capture, ioctl_shapes_capture))):
        raise ValueError("UVM descriptor capture requires an isolated context or kernel observer")
    report["uvm_vaspace_fd_capture_requested"] = uvm_vaspace_fd_capture
    if phase is not None:
        phase_observer_count = sum((binapi_control_capture, device_alloc_capture,
                                    subdevice_alloc_capture, binapi_alloc_capture,
                                    rm_control_headers_capture, fabric_status_capture,
                                    system_features_capture, sync_boost_groups_capture,
                                    ioctl_shapes_capture,
                                    uvm_vaspace_fd_capture))
        phase_trace = (phase in ("enumerate", "context", "managed-accessed-by") and
                       payload.get("ioctl_trace") is True and
                       "trace-helper" in payload.get("artifacts", {}) and
                       "observer" not in payload.get("artifacts", {}) and
                       phase_observer_count == 0)
        phase_observer = ("observer" in payload.get("artifacts", {}) and
                          phase_observer_count == 1 and
                          payload.get("ioctl_trace") is not True)
        phase_pageable = (phase == "system-pageable-memory" and
                          payload.get("ioctl_trace") is not True and
                          "trace-helper" not in payload.get("artifacts", {}) and
                          "observer" not in payload.get("artifacts", {}) and
                          phase_observer_count == 0)
        if (not (phase_trace or phase_observer or phase_pageable) or
                (binapi_control_capture and not rm_control_capture) or
                (rm_control_headers_capture and phase != "enumerate") or
                any((managed_memory, managed_prefetch,
                     gpu_id_info_capture, attached_ids_capture, probed_ids_capture,
                     channel_alloc_capture, map_memory_capture, rusd_alloc_capture,
                     p2p_alloc_capture, p2p_control_capture))):
            raise ValueError("CUDA phase requires one isolated observer, an enumeration/context ioctl trace, or the standalone pageable-memory phase")
    if libcuda_override:
        expected_override_artifacts = {"probe", "module", "observer", "libcuda"}
        other_capture_modes = (
            payload.get("ioctl_trace"), managed_memory, managed_prefetch, cuda_graphs,
            performance_benchmark, gpu_id_info_capture, attached_ids_capture,
            probed_ids_capture, rm_control_capture, rm_control_headers_capture,
            fabric_status_capture, sync_boost_groups_capture, channel_alloc_capture,
            map_memory_capture, rusd_alloc_capture, p2p_alloc_capture,
            p2p_control_capture, binapi_control_capture,
            subdevice_alloc_capture, binapi_alloc_capture, ioctl_shapes_capture,
            uvm_vaspace_fd_capture)
        override_enumeration = (phase == "enumerate" and system_features_capture and
                                not device_alloc_capture)
        override_context_or_kernel = (phase in ("context", "kernel") and
                                      device_alloc_capture and not system_features_capture)
        if (not (override_enumeration or override_context_or_kernel) or
                set(payload.get("artifacts", {})) != expected_override_artifacts or
                any(other_capture_modes)):
            raise ValueError("R580.196.07 override requires isolated feature enumeration or context/kernel plus NV01_DEVICE_0 capture")
    temp = None
    guest_paths = []
    guest_hashes = []
    try:
        stage = "host_key_and_guest_key"
        key = Path(GUEST_KEY)
        known = Path(GUEST_KNOWN_HOSTS)
        if not key.is_file():
            raise RuntimeError("pinned guest SSH material is unavailable")
        key_stat = key.lstat()
        if not stat.S_ISREG(key_stat.st_mode) or key_stat.st_uid != 0 or stat.S_IMODE(key_stat.st_mode) != 0o600:
            raise RuntimeError("guest SSH key ownership or mode is unsafe")
        verify_guest_host_key(known, EXPECTED_FINGERPRINT, 0, call)
        report["guest_hostkey_fingerprint"] = EXPECTED_FINGERPRINT

        stage = "guest_inventory"
        inventory_code = r"""import csv,json,os,platform,socket,subprocess,sys
env={k:v for k,v in os.environ.items() if not k.startswith(("LD_","CUDA_","NVIDIA_","PYTHON"))}
env.update({"PATH":"/usr/bin:/bin","LC_ALL":"C"})
r=subprocess.run(["nvidia-smi","--query-gpu=name,uuid,pci.bus_id,driver_version,memory.total,memory.used,utilization.gpu,temperature.gpu","--format=csv,noheader,nounits"],text=True,capture_output=True,env=env,timeout=15)
rows=[row for row in csv.reader(r.stdout.splitlines()) if row]
q=None
if len(rows)==1 and len(rows[0])==8:
 q=subprocess.run(["nvidia-smi","-i",rows[0][1].strip(),"--query-compute-apps=pid","--format=csv,noheader,nounits"],text=True,capture_output=True,env=env,timeout=15)
pids=[]; valid=q is not None and q.returncode==0
if valid:
 for line in q.stdout.splitlines():
  value=line.strip()
  if not value or value.lower().startswith("no running processes"):continue
  if not value.isdigit():valid=False
  else:pids.append(int(value))
print(json.dumps({"hostname":socket.gethostname(),"kernel_release":platform.release(),"nvidia_smi_exit":r.returncode,
"nvidia_smi_stderr":r.stderr[:1000],"devices":[[v.strip() for v in row] for row in rows],
"compute_process_query_exit":None if q is None else q.returncode,
"compute_process_query_valid":valid,"compute_process_count":len(pids)}))
"""
        guest = guest_json(inventory_code)
        rows = guest.get("devices")
        if (guest.get("hostname") != "pc3-v100" or guest.get("nvidia_smi_exit") != 0 or
            not isinstance(rows, list) or len(rows) != 1 or len(rows[0]) != 8 or
            not rows[0][0].startswith("Tesla V100") or
            not re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", rows[0][1]) or
            guest.get("compute_process_query_exit") != 0 or
            guest.get("compute_process_query_valid") is not True or
            type(guest.get("compute_process_count")) is not int):
            raise RuntimeError("guest inventory is not exactly one Tesla V100")
        if guest["compute_process_count"] != 0:
            raise RuntimeError("guest V100 has active compute processes before the reference")
        if libcuda_override and rows[0][3] != "580.178.04":
            raise RuntimeError("R580.196.07 user-library experiment requires the pinned stock R580.178.04 guest driver")
        guest_pci = canonical_pci(rows[0][2])
        gpu_uuid = rows[0][1]
        report["guest"] = {"hostname": guest["hostname"], "kernel_release": guest["kernel_release"],
                           "name": rows[0][0], "uuid": gpu_uuid, "pci": guest_pci,
                           "driver_version": rows[0][3], "memory_total_mib": rows[0][4],
                           "memory_used_mib_before": rows[0][5], "utilization_percent_before": rows[0][6],
                           "temperature_c_before": rows[0][7],
                           "compute_process_count_before": guest["compute_process_count"]}

        stage = "artifact_verification"
        artifact_names = ["probe", "module"]
        if libcuda_override:
            artifact_names.append("libcuda")
        if p2p_fault_requested:
            artifact_names.append("p2p-fault-shim")
        if "observer" in payload["artifacts"]:
            artifact_names.append("observer")
        if payload.get("ioctl_trace"):
            if "observer" in artifact_names:
                raise RuntimeError("strace and packet observer are separate capture modes")
            artifact_names.append("trace-helper")
        if set(payload["artifacts"]) != set(artifact_names):
            raise RuntimeError("unexpected remote artifact set")
        artifact_data = {}
        for name in artifact_names:
            item = payload["artifacts"][name]
            data = base64.b64decode(item["base64"], validate=True)
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != item["bytes"] or digest != item["sha256"]:
                raise RuntimeError("uploaded artifact identity mismatch")
            artifact_data[name] = data
            report["artifacts_before"][name] = {"bytes": len(data), "sha256": digest}

        nonce = uuid.uuid4().hex
        temp = tempfile.TemporaryDirectory(prefix="codex-v100-ref-")
        host_files = {name: Path(temp.name) / name for name in artifact_names}
        extensions = {"probe": "probe", "module": "fatbin", "observer": "observer",
                      "trace-helper": "py", "libcuda": "libcuda",
                      "p2p-fault-shim": "p2p-fault.so"}
        guest_paths_by_name = {
            name: "/tmp/codex-v100-ref-" + nonce + "." + extensions[name]
            for name in artifact_names
        }
        guest_paths = [guest_paths_by_name[name] for name in artifact_names]
        guest_hashes = [report["artifacts_before"][name]["sha256"] for name in artifact_names]
        for name, path in host_files.items():
            path.write_bytes(artifact_data[name])
            path.chmod(0o700 if name in ("probe", "observer") else 0o600)

        stage = "guest_transfer"
        write_code = r"""import hashlib,json,os,sys
from pathlib import Path
p=Path(sys.argv[1])
data=sys.stdin.buffer.read()
with p.open("xb") as f:f.write(data)
p.chmod(0o700 if p.suffix in (".probe",".observer") else 0o600)
print(json.dumps({"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}))
"""
        for name in artifact_names:
            dest = guest_paths_by_name[name]
            written = guest_json(write_code, args=(dest,), input_data=artifact_data[name],
                                 timeout=180 if name == "libcuda" else 35)
            if written != report["artifacts_before"][name]:
                raise RuntimeError("guest artifact hash differs after transfer")
            report["artifacts_before"][name]["guest_path"] = dest

        stage = "sm70_cuda_probe"
        run_code = r"""import base64,gzip,hashlib,importlib.machinery,importlib.util,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
probe,module,pci,gpu_uuid,observer,trace_helper,trace_enabled,managed_enabled,prefetch_enabled,graphs_enabled,benchmark_enabled,id_info_enabled,attached_enabled,probed_enabled,rm_control_enabled,rm_control_headers_enabled,fabric_status_enabled,system_features_enabled,sync_boost_enabled,channel_alloc_enabled,map_memory_enabled,rusd_alloc_enabled,p2p_alloc_enabled,p2p_control_enabled,binapi_control_enabled,device_alloc_enabled,subdevice_alloc_enabled,binapi_alloc_enabled,ioctl_shapes_enabled,uvm_vaspace_fd_enabled,phase_enabled,libcuda_path,libcuda_sha256,libcuda_bytes,p2p_fault_path,p2p_fault_mode,p2p_fault_sha256,p2p_fault_bytes=sys.argv[1:]
env={"PATH":"/usr/bin:/bin","LC_ALL":"C","CUDA_VISIBLE_DEVICES":gpu_uuid}
process_query=subprocess.run(["nvidia-smi","-i",gpu_uuid,"--query-compute-apps=pid","--format=csv,noheader,nounits"],text=True,capture_output=True,env=env,timeout=15)
process_ids=[]; process_query_valid=process_query.returncode==0
if process_query_valid:
 for line in process_query.stdout.splitlines():
  value=line.strip()
  if not value or value.lower().startswith("no running processes"):continue
  if not value.isdigit():process_query_valid=False
  else:process_ids.append(int(value))
if not process_query_valid:raise RuntimeError("V100 compute-process query failed before probe launch")
if process_ids:raise RuntimeError("V100 guest became busy before probe launch")
process_count_prelaunch=len(process_ids)
libcuda_temp=None
libcuda_temp_path=None
probe_env=env
if libcuda_path:
 library_path=Path(libcuda_path)
 library_stat=library_path.lstat()
 if (not stat.S_ISREG(library_stat.st_mode) or
     not library_path.name.startswith("codex-v100-ref-") or not library_path.name.endswith(".libcuda") or
     library_stat.st_size!=int(libcuda_bytes)):
  raise RuntimeError("temporary R580 libcuda artifact identity is invalid")
 library_digest=hashlib.sha256()
 with library_path.open("rb") as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b""):library_digest.update(chunk)
 if library_digest.hexdigest()!=libcuda_sha256:raise RuntimeError("temporary R580 libcuda hash changed before load")
 libcuda_temp=tempfile.TemporaryDirectory(prefix="codex-v100-r580-libcuda-")
 libcuda_temp_path=libcuda_temp.name
 (Path(libcuda_temp.name)/"libcuda.so.1").symlink_to(library_path)
 probe_env={**env,"LD_LIBRARY_PATH":libcuda_temp.name}
if p2p_fault_mode:
 fault_library=Path(p2p_fault_path)
 fault_stat=fault_library.lstat()
 if (not stat.S_ISREG(fault_stat.st_mode) or
     not fault_library.name.startswith("codex-v100-ref-") or
     not fault_library.name.endswith(".p2p-fault.so") or
     fault_stat.st_size!=int(p2p_fault_bytes)):
  raise RuntimeError("temporary P2P fault injector identity is invalid")
 fault_digest=hashlib.sha256()
 with fault_library.open("rb") as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b""):fault_digest.update(chunk)
 if fault_digest.hexdigest()!=p2p_fault_sha256:
  raise RuntimeError("temporary P2P fault injector hash changed before load")
 probe_env={**probe_env,"LD_PRELOAD":str(fault_library),
            "HYBRID_RM_P2P_FAULT":p2p_fault_mode}
if phase_enabled:
 probe_argv=[probe,"--module",module,"--phase",phase_enabled,"--expected-pci",pci]
else:
 probe_argv=[probe,"--module",module,"--require-sm","70","--expected-pci",pci]
if managed_enabled == "1":probe_argv.append("--managed-memory")
if prefetch_enabled == "1":probe_argv.append("--managed-prefetch")
if graphs_enabled == "1":probe_argv.append("--cuda-graphs")
if benchmark_enabled == "1":probe_argv.append("--benchmark")
observer_exit=None
observation=None
trace_report=None
trace_transport=None
try:
 if trace_enabled == "1":
  loader=importlib.machinery.SourceFileLoader("cuda_ioctl_trace_helper",trace_helper)
  spec=importlib.util.spec_from_loader(loader.name,loader)
  if spec is None or spec.loader is None:raise RuntimeError("ioctl trace helper cannot be loaded")
  helper=importlib.util.module_from_spec(spec);loader.exec_module(helper)
  node_lifecycle=(phase_enabled in ("enumerate","context"))
  with tempfile.TemporaryDirectory(prefix="codex-v100-strace-") as directory:
   trace_path=str(Path(directory)/"ioctl.strace")
   captured=helper.capture("/usr/bin/strace",trace_path,probe_argv,timeout=100,env=probe_env,
    syscalls=(helper.NODE_TRACE_SYSCALLS if node_lifecycle else ("ioctl",)),
    summary_fn=(helper.summarize_node_open_trace if node_lifecycle else None))
   r=subprocess.CompletedProcess(probe_argv,captured["exit_code"],captured["stdout"],captured["stderr"])
   raw=captured.pop("raw_trace")
   trace_report={k:v for k,v in captured.items() if k not in ("stdout","stderr","argv")}
   trace_report["trace_complete"]=trace_report["trace"].get("trace_complete") is True and not trace_report["timed_out"]
   compressed=gzip.compress(raw,mtime=0)
   if len(compressed)>1024*1024:raise RuntimeError("compressed trace exceeds transport limit")
   trace_transport={"gzip_base64":base64.b64encode(compressed).decode("ascii"),
    "gzip_bytes":len(compressed),"gzip_sha256":hashlib.sha256(compressed).hexdigest(),
    "raw_bytes":len(raw),"raw_sha256":hashlib.sha256(raw).hexdigest()}
 elif observer:
  with tempfile.TemporaryDirectory(prefix="codex-v100-observer-") as directory:
   observation_path=str(Path(directory)/"ioctl.json")
   argv=[observer,"--output",observation_path,"--control-path","/dev/nvidiactl",
         "--timeout-seconds","65"]
   if id_info_enabled == "1": argv.append("--gpu-id-info")
   if attached_enabled == "1": argv.append("--attached-ids")
   if probed_enabled == "1": argv.append("--probed-ids")
   if rm_control_enabled == "1": argv.append("--rm-control")
   if rm_control_headers_enabled == "1": argv.append("--rm-control-headers")
   if fabric_status_enabled == "1": argv.append("--fabric-status")
   if system_features_enabled == "1": argv.append("--system-features")
   if sync_boost_enabled == "1": argv.append("--sync-boost-groups")
   if p2p_control_enabled == "1": argv.append("--p2p-control")
   if binapi_control_enabled == "1": argv += ["--binapi-control","--gpu-path","/dev/nvidia0"]
   if device_alloc_enabled == "1": argv += ["--device-alloc","--gpu-path","/dev/nvidia0"]
   if subdevice_alloc_enabled == "1": argv += ["--subdevice-alloc","--gpu-path","/dev/nvidia0"]
   if binapi_alloc_enabled == "1": argv += ["--binapi-alloc","--gpu-path","/dev/nvidia0"]
   if ioctl_shapes_enabled == "1": argv += ["--ioctl-shapes","--gpu-path","/dev/nvidia0"]
   if uvm_vaspace_fd_enabled == "1": argv += ["--uvm-vaspace-fd","--uvm-path","/dev/nvidia-uvm"]
   if channel_alloc_enabled == "1": argv += ["--channel-alloc","--gpu-path","/dev/nvidia0"]
   if map_memory_enabled == "1": argv += ["--map-memory","--gpu-path","/dev/nvidia0"]
   if rusd_alloc_enabled == "1": argv += ["--rusd-alloc","--gpu-path","/dev/nvidia0"]
   if p2p_alloc_enabled == "1": argv += ["--p2p-alloc","--gpu-path","/dev/nvidia0"]
   argv += ["--",*probe_argv]
   r=subprocess.run(argv,text=True,capture_output=True,env=probe_env,timeout=100,check=False)
   observer_exit=r.returncode
   try: observation=json.loads(Path(observation_path).read_text())
   except (OSError,ValueError,TypeError): observation=None
 else:
  r=subprocess.run(probe_argv,text=True,capture_output=True,env=probe_env,timeout=100,check=False)
 report=None
 try: report=json.loads(r.stdout)
 except (ValueError,TypeError): pass
 lib=None
 if isinstance(report,dict) and isinstance(report.get("driver_library_path"),str):
  p=Path(report["driver_library_path"]).resolve(strict=True); b=p.read_bytes()
  lib={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
 if libcuda_path and (not isinstance(lib,dict) or lib.get("path")!=str(Path(libcuda_path).resolve(strict=True)) or
                      lib.get("bytes")!=int(libcuda_bytes) or lib.get("sha256")!=libcuda_sha256):
  raise RuntimeError("CUDA probe did not resolve the exact staged R580.196.07 libcuda")
 after_query=subprocess.run(["nvidia-smi","-i",gpu_uuid,"--query-compute-apps=pid","--format=csv,noheader,nounits"],text=True,capture_output=True,env=env,timeout=15)
 after_ids=[]; after_valid=after_query.returncode==0
 if after_valid:
  for line in after_query.stdout.splitlines():
   value=line.strip()
   if not value or value.lower().startswith("no running processes"):continue
   if not value.isdigit():after_valid=False
   else:after_ids.append(int(value))
 result={"exit_code":observation.get("child_exit_code") if observer and isinstance(observation,dict) else r.returncode,
         "stdout":r.stdout,"stderr":r.stderr,"probe":report,"driver_library":lib,
         "compute_process_count_prelaunch":process_count_prelaunch,
         "compute_process_query_after_valid":after_valid,
         "compute_process_count_after_probe":len(after_ids),
         "libcuda_override_temp_cleanup_passed":None}
 if observer:
  result["observer_exit_code"]=observer_exit
  result["ioctl_observation"]=observation
 if trace_enabled == "1":
  result["ioctl_trace"]=trace_report
  result["ioctl_trace_transport"]=trace_transport
except subprocess.TimeoutExpired:
 result={"exit_code":124,"stdout":"","stderr":"probe or observer timed out","probe":None,"driver_library":None}
 if observer:
  result["observer_exit_code"]=124
  result["ioctl_observation"]=observation
 if trace_enabled == "1":
  result["ioctl_trace"]={"timed_out":True,"trace_complete":False}
 result["libcuda_override_temp_cleanup_passed"]=None
if libcuda_temp is not None:
 libcuda_temp.cleanup()
 result["libcuda_override_temp_cleanup_passed"]=not Path(libcuda_temp_path).exists()
print(json.dumps(result))
"""
        observer_path = guest_paths_by_name.get("observer", "")
        trace_helper_path = guest_paths_by_name.get("trace-helper", "")
        run_result = guest_json(run_code, args=(guest_paths_by_name["probe"],
                                                guest_paths_by_name["module"],
                                                guest_pci, gpu_uuid, observer_path, trace_helper_path,
                                                "1" if payload.get("ioctl_trace") else "0",
                                                "1" if managed_memory else "0",
                                                "1" if managed_prefetch else "0",
                                                "1" if payload.get("cuda_graphs") else "0",
                                                "1" if payload.get("performance_benchmark") else "0",
                                                "1" if payload.get("gpu_id_info_capture") else "0",
                                                "1" if payload.get("attached_ids_capture") else "0",
                                                "1" if payload.get("probed_ids_capture") else "0",
                                                "1" if payload.get("rm_control_capture") else "0",
                                                "1" if payload.get("rm_control_headers_capture") else "0",
                                                "1" if payload.get("fabric_status_capture") else "0",
                                                "1" if payload.get("system_features_capture") else "0",
                                                "1" if payload.get("sync_boost_groups_capture") else "0",
                                                "1" if payload.get("channel_alloc_capture") else "0",
                                                "1" if payload.get("map_memory_capture") else "0",
                                                "1" if payload.get("rusd_alloc_capture") else "0",
                                                "1" if payload.get("p2p_alloc_capture") else "0",
                                                "1" if payload.get("p2p_control_capture") else "0",
                                                "1" if payload.get("binapi_control_capture") else "0",
                                                "1" if payload.get("device_alloc_capture") else "0",
                                                "1" if payload.get("subdevice_alloc_capture") else "0",
                                                "1" if payload.get("binapi_alloc_capture") else "0",
                                                "1" if payload.get("ioctl_shapes_capture") else "0",
                                                "1" if payload.get("uvm_vaspace_fd_capture") else "0",
                                                phase or "",
                                                guest_paths_by_name.get("libcuda", ""),
                                                report["artifacts_before"].get("libcuda", {}).get("sha256", ""),
                                                str(report["artifacts_before"].get("libcuda", {}).get("bytes", "")),
                                                guest_paths_by_name.get("p2p-fault-shim", ""),
                                                payload.get("p2p_fault_mode") or "",
                                                report["artifacts_before"].get("p2p-fault-shim", {}).get("sha256", ""),
                                                str(report["artifacts_before"].get("p2p-fault-shim", {}).get("bytes", ""))),
                                timeout=240 if libcuda_override else (150 if payload.get("ioctl_trace") else 125))
        report["compute_process_count_prelaunch"] = run_result.get(
            "compute_process_count_prelaunch")
        report["compute_process_query_after_valid"] = run_result.get(
            "compute_process_query_after_valid")
        report["compute_process_count_after_probe"] = run_result.get(
            "compute_process_count_after_probe")
        report["libcuda_override_temp_cleanup_passed"] = run_result.get(
            "libcuda_override_temp_cleanup_passed")
        if libcuda_override and report["libcuda_override_temp_cleanup_passed"] is not True:
            raise RuntimeError("temporary R580 libcuda loader directory cleanup was not verified")
        if (type(report["compute_process_count_prelaunch"]) is not int or
                report["compute_process_count_prelaunch"] != 0 or
                report["compute_process_query_after_valid"] is not True or
                type(report["compute_process_count_after_probe"]) is not int or
                report["compute_process_count_after_probe"] != 0):
            raise RuntimeError("V100 guest compute-process guard did not remain idle")
        report["probe_exit_code"] = run_result.get("exit_code")
        report["probe"] = run_result.get("probe")
        report["probe_stdout"] = run_result.get("stdout", "")
        report["probe_stderr"] = run_result.get("stderr", "")
        if p2p_fault_requested:
            report["p2p_fault_denial_count"] = sum(
                line.startswith("HYBRID_RM_P2P_FAULT denied=")
                for line in report["probe_stderr"].splitlines())
        report["driver_library"] = run_result.get("driver_library")
        if "observer_exit_code" in run_result:
            report["observer_exit_code"] = run_result["observer_exit_code"]
            report["ioctl_observation"] = run_result.get("ioctl_observation")
            observed_rows = (run_result.get("ioctl_observation") or {}).get("records", [])
            report["gpu_id_info_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "gpu_id_info_v2"
                for row in observed_rows)
            report["attached_ids_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "gpu_attached_ids"
                for row in observed_rows)
            report["probed_ids_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "gpu_probed_ids"
                for row in observed_rows)
            report["channel_alloc_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "channel_alloc"
                for row in observed_rows)
            report["map_memory_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "map_memory"
                for row in observed_rows)
            report["rusd_alloc_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "rusd_alloc"
                for row in observed_rows)
            report["p2p_alloc_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "p2p_alloc"
                for row in observed_rows)
            report["p2p_control_records_seen"] = any(
                isinstance(row, dict) and isinstance(row.get("entry"), dict) and
                isinstance(row["entry"].get("p2pControl"), dict)
                for row in observed_rows)
            report["binapi_control_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "binapi_control"
                for row in observed_rows)
            report["device_alloc_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "device_alloc"
                for row in observed_rows)
            report["subdevice_alloc_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "subdevice_alloc"
                for row in observed_rows)
            report["binapi_alloc_records_seen"] = any(
                isinstance(row, dict) and row.get("operation") == "binapi_alloc"
                for row in observed_rows)
            report["uvm_vaspace_records_seen"] = (
                any(isinstance(row, dict) and
                    row.get("operation") == "uvm_register_gpu_vaspace"
                    for row in observed_rows)
                if payload.get("uvm_vaspace_fd_capture") else None)
            report["uvm_map_external_records_seen"] = (
                any(isinstance(row, dict) and
                    row.get("operation") == "uvm_map_external_allocation"
                    for row in observed_rows)
                if payload.get("uvm_vaspace_fd_capture") else None)
            if payload.get("ioctl_shapes_capture"):
                shape_rows = [row for row in observed_rows
                              if isinstance(row, dict) and
                              row.get("operation") == "selected_ioctl_payload_shape"]
                report["ioctl_shape_records_seen"] = bool(shape_rows)
                report["ioctl_shape_record_count"] = len(shape_rows)
                report["ioctl_shape_request_counts"] = {
                    "0xc038464e": sum(row.get("request") == 0xc038464e for row in shape_rows),
                    "0xc028465e": sum(row.get("request") == 0xc028465e for row in shape_rows),
                    "0xc01046ce": sum(row.get("request") == 0xc01046ce for row in shape_rows),
                    "0xc01046cf": sum(row.get("request") == 0xc01046cf for row in shape_rows),
                }
            if isinstance(run_result.get("ioctl_observation"), dict):
                report["binapi_payload_snapshots_read"] = (
                    run_result["ioctl_observation"].get("binapi_payload_snapshots_read")
                    if payload.get("binapi_control_capture") else None)
                report["device_alloc_payload_snapshots_read"] = (
                    run_result["ioctl_observation"].get("device_alloc_payload_snapshots_read")
                    if payload.get("device_alloc_capture") else None)
                report["subdevice_alloc_payload_snapshots_read"] = (
                    run_result["ioctl_observation"].get("subdevice_alloc_payload_snapshots_read")
                    if payload.get("subdevice_alloc_capture") else None)
                report["binapi_alloc_payload_snapshots_read"] = (
                    run_result["ioctl_observation"].get("binapi_alloc_payload_snapshots_read")
                    if payload.get("binapi_alloc_capture") else None)
            if payload.get("rm_control_capture"):
                report["rm_control_records_seen"] = any(
                    isinstance(row, dict) and row.get("operation") in
                    ("rm_control_header", "gpu_id_info_v2", "gpu_attached_ids",
                     "gpu_probed_ids", "binapi_control")
                    for row in observed_rows)
            if payload.get("rm_control_headers_capture"):
                header_count = sum(1 for row in observed_rows
                                   if isinstance(row, dict) and
                                   row.get("operation") == "rm_control_header")
                report["rm_control_headers_record_count"] = header_count
                report["rm_control_headers_records_seen"] = header_count > 0
            if payload.get("fabric_status_capture"):
                fabric_rows = [row for row in observed_rows
                               if isinstance(row, dict) and
                               row.get("operation") == "rm_control_fabric_status"]
                report["fabric_status_record_count"] = len(fabric_rows)
                report["fabric_status_records_seen"] = bool(fabric_rows)
                report["fabric_status_values"] = [
                    row.get("exit", {}).get("fabricStatus")
                    if isinstance(row.get("exit"), dict) else None
                    for row in fabric_rows]
            if payload.get("system_features_capture"):
                feature_rows = [row for row in observed_rows
                                if isinstance(row, dict) and
                                row.get("operation") == "rm_control_system_features"]
                report["system_features_record_count"] = len(feature_rows)
                report["system_features_records_seen"] = bool(feature_rows)
                report["system_features_masks"] = [
                    row.get("exit", {}).get("featuresMask")
                    if isinstance(row.get("exit"), dict) else None
                    for row in feature_rows]
            if payload.get("sync_boost_groups_capture"):
                sync_rows = [row for row in observed_rows
                             if isinstance(row, dict) and
                             row.get("operation") == "rm_control_sync_boost_groups"]
                report["sync_boost_groups_record_count"] = len(sync_rows)
                report["sync_boost_groups_records_seen"] = bool(sync_rows)
                report["sync_boost_group_counts"] = [
                    row.get("exit", {}).get("syncBoostGroupCount")
                    if isinstance(row.get("exit"), dict) else None
                    for row in sync_rows]
                report["sync_boost_group_payload_snapshots_read"] = (
                    run_result["ioctl_observation"].get(
                        "sync_boost_group_payload_snapshots_read"))
        if payload.get("ioctl_trace"):
            report["ioctl_trace"] = run_result.get("ioctl_trace")
            report["ioctl_trace_transport"] = run_result.get("ioctl_trace_transport")

        stage = "post_probe_inventory"
        guest_after = guest_json(inventory_code)
        after_rows = guest_after.get("devices")
        if (guest_after.get("hostname") != guest.get("hostname") or
            guest_after.get("nvidia_smi_exit") != 0 or not isinstance(after_rows, list) or
            len(after_rows) != 1 or len(after_rows[0]) != 8 or after_rows[0][1] != gpu_uuid or
            canonical_pci(after_rows[0][2]) != guest_pci or
            (libcuda_override and after_rows[0][3] != rows[0][3]) or
            guest_after.get("compute_process_query_exit") != 0 or
            guest_after.get("compute_process_query_valid") is not True or
            type(guest_after.get("compute_process_count")) is not int or
            guest_after.get("compute_process_count") != 0):
            raise RuntimeError("guest GPU identity changed during the SM70 reference")
        report["guest_after"] = {"hostname": guest_after["hostname"],
                                 "uuid": after_rows[0][1],
                                 "pci": canonical_pci(after_rows[0][2]),
                                 "memory_used_mib": after_rows[0][5],
                                 "utilization_percent": after_rows[0][6],
                                 "temperature_c": after_rows[0][7],
                                 "driver_version": after_rows[0][3],
                                 "compute_process_count": guest_after["compute_process_count"]}
        report["compute_process_count_after"] = guest_after["compute_process_count"]

        stage = "artifact_integrity_after_run"
        hash_code = r"""import hashlib,json,sys
from pathlib import Path
out={}
for raw in sys.argv[1:]:
 p=Path(raw); b=p.read_bytes(); out[raw]={"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
print(json.dumps(out,sort_keys=True))
"""
        after = guest_json(hash_code, args=guest_paths)
        report["artifacts_after"] = after
        for name, path in zip(artifact_names, guest_paths):
            before = report["artifacts_before"][name]
            if after.get(path) != {"bytes": before["bytes"], "sha256": before["sha256"]}:
                raise RuntimeError("guest test artifacts changed during execution")
        stage = "guest_cleanup"
        report["qualification"] = "probe-executed"
    except Exception as error:
        report["failure_stage"] = stage
        report["error_type"] = type(error).__name__
        report["error"] = str(error)[:500]
    finally:
        if guest_paths:
            cleanup_code = r"""import hashlib,json,stat,sys
from pathlib import Path
ok=True
args=sys.argv[1:]
if len(args)%2:ok=False
for raw,digest in zip(args[::2],args[1::2]):
 p=Path(raw)
 try:
  st=p.lstat()
  if not stat.S_ISREG(st.st_mode) or not p.name.startswith("codex-v100-ref-"):ok=False
  elif hashlib.sha256(p.read_bytes()).hexdigest()==digest:p.unlink()
  else:ok=False
 except FileNotFoundError:pass
print(json.dumps({"cleanup_passed":ok,"remaining":[p for p in args[::2] if Path(p).exists()]}))
"""
            try:
                if len(guest_hashes) != len(guest_paths):
                    raise RuntimeError("guest cleanup identities are incomplete")
                cleanup_args = tuple(value for pair in zip(guest_paths, guest_hashes) for value in pair)
                cleanup = guest_json(cleanup_code, args=cleanup_args)
                report["guest_cleanup_passed"] = cleanup.get("cleanup_passed") is True and not cleanup.get("remaining")
            except Exception:
                report["guest_cleanup_passed"] = False
            if not report["guest_cleanup_passed"]:
                report["qualification"] = "failed"
                report.setdefault("error", "temporary guest probe files were not cleaned")
        if temp is not None:
            temp.cleanup()
    return report

payload_path=None
payload_digest=""
payload_cleanup_passed=False
try:
    if len(sys.argv)!=3:raise ValueError("payload arguments missing")
    candidate=Path(sys.argv[1]); payload_digest=sys.argv[2]
    if (not re.fullmatch(r"/tmp/codex-v100-payload-[0-9a-f]{32}\.json",str(candidate)) or
        not re.fullmatch(r"[0-9a-f]{64}",payload_digest)):
        raise ValueError("payload identity invalid")
    payload_path=candidate
    st=payload_path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid==0 or stat.S_IMODE(st.st_mode)!=0o600:
        raise ValueError("payload file type or mode invalid")
    data=payload_path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=payload_digest:raise ValueError("payload hash mismatch")
    payload=json.loads(data.decode("utf-8"))
    payload_path.unlink()
    payload_cleanup_passed=not payload_path.exists()
    result=main(payload)
except Exception as error:
    result={"schema":"nvidia-hybrid-pc3-v100-guest-reference-v1","host":os.uname().nodename,
            "qualification":"failed","failure_stage":"input","error_type":type(error).__name__,
            "error":str(error)[:500],"execution_scope":{"guest_driver_changed":False,"module_loaded":False,
            "vm_management_issued":False,"pci_binding_changed":False}}
finally:
    if payload_path is not None and payload_path.exists():
        try:
            st=payload_path.lstat()
            if (stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and
                hashlib.sha256(payload_path.read_bytes()).hexdigest()==payload_digest):
                payload_path.unlink()
                payload_cleanup_passed=not payload_path.exists()
        except OSError:pass
    result["payload_file_cleanup_passed"]=payload_cleanup_passed
print(json.dumps(result,sort_keys=True))
'''
REMOTE_ROOT_SCRIPT = REMOTE_ROOT_SCRIPT.replace(
    "###GUEST_HOSTKEY_HELPER###", inspect.getsource(verify_guest_host_key)
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=DEFAULT_PC3_TARGET)
    parser.add_argument("--host-key-alias", default=DEFAULT_HOST_KEY_ALIAS)
    parser.add_argument("--credential-host")
    parser.add_argument("--credential-file")
    parser.add_argument("--direct-pc3", action="store_true",
                        help="use only the configured local SSH key and PC3 sudo -n; never contact PC6")
    parser.add_argument("--identity-file", type=Path,
                        help="optional private key directly inside ~/.ssh for PC3-only authentication")
    parser.add_argument("--probe", type=Path, default=DEFAULT_PROBE)
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--ioctl-observer", type=Path,
                        help="optionally capture read-only /dev/nvidiactl ROOT allocation/free packets")
    parser.add_argument("--libcuda-override", type=Path,
                        help="test only the hash-pinned R580.196.07 libcuda on stock R580.178.04 V100; requires --phase enumerate --system-features and an ioctl observer")
    parser.add_argument("--gpu-id-info", action="store_true",
                        help="with --ioctl-observer, capture the fixed GPU_GET_ID_INFO_V2 payload")
    parser.add_argument("--attached-ids", action="store_true",
                        help="with --ioctl-observer, capture the fixed GPU_GET_ATTACHED_IDS payload")
    parser.add_argument("--probed-ids", action="store_true",
                        help="with --ioctl-observer, capture the fixed GPU_GET_PROBED_IDS payload")
    parser.add_argument("--rm-control", action="store_true",
                        help="with --ioctl-observer, capture fixed NVOS54 RM_CONTROL headers only")
    parser.add_argument("--rm-control-headers", action="store_true",
                        help="with --phase enumerate, capture only redacted fixed RM_CONTROL headers")
    parser.add_argument("--fabric-status", action="store_true",
                        help="with --phase enumerate, capture only the fixed root-global Fabric Manager status enum")
    parser.add_argument("--system-features", action="store_true",
                        help="with --phase enumerate, capture only the fixed root-global SYSTEM_GET_FEATURES mask")
    parser.add_argument("--sync-boost-groups", action="store_true",
                        help="with --phase enumerate, capture only the bounded root-global SYNC_GPU_BOOST_GROUP_INFO groupCount")
    parser.add_argument("--channel-alloc", action="store_true",
                        help="with --ioctl-observer, capture sanitized Volta/Blackwell channel allocation payloads")
    parser.add_argument("--map-memory", action="store_true",
                        help="with --ioctl-observer, capture selected R580 map/unmap and mapped-GPU mmap metadata")
    parser.add_argument("--rusd-alloc", action="store_true",
                        help="with --ioctl-observer, capture the typed RM_USER_SHARED_DATA allocation mask")
    parser.add_argument("--p2p-alloc", action="store_true",
                        help="with --ioctl-observer, capture only the fixed NV50_THIRD_PARTY_P2P allocation flags")
    parser.add_argument("--p2p-control", action="store_true",
                        help="with --rm-control, capture exact NV503C P2P control payload metadata")
    parser.add_argument("--binapi-control", action="store_true",
                        help="with --rm-control, capture redacted shape metadata for the fixed 992-byte NV2081_BINAPI payload")
    parser.add_argument("--device-alloc", action="store_true",
                        help="capture fixed, redacted NV0080_ALLOC_PARAMETERS for NV01_DEVICE_0")
    parser.add_argument("--subdevice-alloc", action="store_true",
                        help="capture only fixed, redacted NV2080_ALLOC_PARAMETERS subDeviceId")
    parser.add_argument("--binapi-alloc", action="store_true",
                        help="capture only optional, redacted NV2081_ALLOC_PARAMETERS reserved-zero predicate")
    parser.add_argument("--ioctl-shapes", action="store_true",
                        help="capture only byte-position metadata for three fixed ioctl payloads on the selected V100 paths")
    parser.add_argument("--uvm-vaspace-fd", action="store_true",
                        help="with --phase context or kernel, observe redacted rmCtrlFd fields in UVM VA-space registration and external-allocation mapping")
    parser.add_argument("--ioctl-trace", action="store_true",
                        help="capture all ioctl metadata from the selected V100 CUDA probe")
    parser.add_argument("--managed-memory", action="store_true",
                        help="run CUDA kernels using cuMemAllocManaged on the V100")
    parser.add_argument("--managed-prefetch", action="store_true",
                        help="with --managed-memory, prefetch test ranges to the V100 and CPU")
    parser.add_argument("--cuda-graphs", action="store_true",
                        help="run two opt-in CUDA Graph replays of the numeric kernel on the V100")
    parser.add_argument("--benchmark", action="store_true",
                        help="run a bounded launch and pinned-copy performance reference on the V100")
    parser.add_argument("--phase", choices=("initialize", "enumerate", "context", "allocation", "module", "kernel",
                                               "managed-accessed-by", "system-pageable-memory"),
                        help="run one isolated CUDA Driver API phase; pageable-memory is a standalone no-observer test")
    parser.add_argument("--p2p-fault", choices=P2P_FAULT_MODES,
                        help="deny every exact match in the selected NV503C BAR1 allocation/control family in the child probe")
    parser.add_argument("--p2p-fault-shim", type=Path,
                        help="process-local LD_PRELOAD shim built by build_rm_p2p_fault_injector.py")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.benchmark and (
            args.phase or args.managed_memory or args.managed_prefetch or args.cuda_graphs or
            args.ioctl_trace or args.ioctl_observer is not None or args.gpu_id_info or
            args.attached_ids or args.probed_ids or args.rm_control or args.rm_control_headers or
            args.fabric_status or args.system_features or args.sync_boost_groups or
            args.channel_alloc or args.map_memory or args.rusd_alloc or args.p2p_alloc or
            args.p2p_control or args.binapi_control or args.device_alloc or
            args.subdevice_alloc or args.binapi_alloc or args.ioctl_shapes or
            args.uvm_vaspace_fd):
        parser.error("--benchmark requires an isolated device-memory reference run")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", args.target):
        parser.error("target must be a literal user@host")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.host_key_alias):
        parser.error("invalid PC3 host-key alias")
    if args.direct_pc3:
        if args.target != DEFAULT_PC3_TARGET or args.host_key_alias != DEFAULT_HOST_KEY_ALIAS:
            parser.error("--direct-pc3 requires the pinned pc3@pc3 target and pc3 host-key alias")
        if args.credential_host is not None or args.credential_file is not None:
            parser.error("--direct-pc3 cannot be combined with legacy credential-host options")
        args.credential_host = None
        args.credential_file = None
        if args.identity_file is not None:
            try:
                args.identity_file = validate_direct_identity_file(args.identity_file)
            except ValueError as error:
                parser.error(str(error))
    else:
        if args.identity_file is not None:
            parser.error("--identity-file requires --direct-pc3")
        args.credential_host = args.credential_host or DEFAULT_CREDENTIAL_HOST
        args.credential_file = args.credential_file or DEFAULT_CREDENTIAL_FILE
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.credential_host):
            parser.error("credential host must be a configured SSH alias")
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    if (args.p2p_fault is None) != (args.p2p_fault_shim is None):
        parser.error("--p2p-fault and --p2p-fault-shim must be supplied together")
    if args.p2p_fault is not None and (args.phase is not None or args.libcuda_override is not None or
            args.managed_memory or args.managed_prefetch or args.cuda_graphs or args.benchmark or
            args.ioctl_trace or args.ioctl_observer is not None or args.gpu_id_info or
            args.attached_ids or args.probed_ids or args.rm_control or
            args.rm_control_headers or args.fabric_status or args.system_features or
            args.sync_boost_groups or args.channel_alloc or args.map_memory or
            args.rusd_alloc or args.p2p_alloc or args.p2p_control or
            args.binapi_control or args.device_alloc or args.subdevice_alloc or
            args.binapi_alloc or args.ioctl_shapes or args.uvm_vaspace_fd):
        parser.error("--p2p-fault requires an isolated full SM70 reference run")
    if args.p2p_fault_shim is not None:
        try:
            p2p_fault_shim_identity(args.p2p_fault_shim)
        except (OSError, ValueError) as error:
            parser.error(str(error))
    if args.ioctl_trace and args.ioctl_observer is not None:
        parser.error("--ioctl-trace and --ioctl-observer are separate capture modes")
    if args.attached_ids and args.ioctl_observer is None:
        parser.error("--attached-ids requires --ioctl-observer")
    if args.gpu_id_info and args.ioctl_observer is None:
        parser.error("--gpu-id-info requires --ioctl-observer")
    if args.probed_ids and args.ioctl_observer is None:
        parser.error("--probed-ids requires --ioctl-observer")
    if args.rm_control and args.ioctl_observer is None:
        parser.error("--rm-control requires --ioctl-observer")
    if args.rm_control_headers and args.ioctl_observer is None:
        parser.error("--rm-control-headers requires --ioctl-observer")
    if args.fabric_status and args.ioctl_observer is None:
        parser.error("--fabric-status requires --ioctl-observer")
    if args.system_features and args.ioctl_observer is None:
        parser.error("--system-features requires --ioctl-observer")
    if args.sync_boost_groups and args.ioctl_observer is None:
        parser.error("--sync-boost-groups requires --ioctl-observer")
    if args.channel_alloc and args.ioctl_observer is None:
        parser.error("--channel-alloc requires --ioctl-observer")
    if args.map_memory and args.ioctl_observer is None:
        parser.error("--map-memory requires --ioctl-observer")
    if args.rusd_alloc and args.ioctl_observer is None:
        parser.error("--rusd-alloc requires --ioctl-observer")
    if args.p2p_alloc and args.ioctl_observer is None:
        parser.error("--p2p-alloc requires --ioctl-observer")
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
    if args.ioctl_shapes and args.ioctl_observer is None:
        parser.error("--ioctl-shapes requires --ioctl-observer")
    if args.uvm_vaspace_fd and args.ioctl_observer is None:
        parser.error("--uvm-vaspace-fd requires --ioctl-observer")
    if args.uvm_vaspace_fd and (args.phase not in ("context", "kernel") or any((
            args.ioctl_trace, args.managed_memory, args.managed_prefetch, args.cuda_graphs,
            args.benchmark, args.gpu_id_info, args.attached_ids, args.probed_ids,
            args.rm_control, args.rm_control_headers, args.fabric_status,
            args.system_features, args.sync_boost_groups,
            args.channel_alloc, args.map_memory, args.rusd_alloc,
            args.p2p_alloc, args.p2p_control, args.binapi_control, args.device_alloc,
            args.subdevice_alloc, args.binapi_alloc, args.ioctl_shapes))):
        parser.error("--uvm-vaspace-fd requires an isolated --phase context or kernel observer")
    if args.ioctl_shapes and (args.phase not in (None, "kernel") or args.ioctl_trace or
            args.managed_memory or args.managed_prefetch or args.cuda_graphs or args.benchmark or
            args.gpu_id_info or args.attached_ids or args.probed_ids or args.rm_control or
            args.rm_control_headers or args.fabric_status or args.system_features or
            args.sync_boost_groups or
            args.channel_alloc or args.map_memory or args.rusd_alloc or args.p2p_alloc or
            args.p2p_control or args.binapi_control or args.device_alloc or
            args.subdevice_alloc or args.binapi_alloc):
        parser.error("--ioctl-shapes requires an isolated default or kernel-phase observer run")
    if args.device_alloc and (args.subdevice_alloc or any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
            args.probed_ids, args.rm_control, args.channel_alloc, args.map_memory,
            args.rusd_alloc, args.p2p_alloc, args.p2p_control, args.binapi_control,
            args.managed_memory, args.managed_prefetch))):
        parser.error("--device-alloc must be an isolated observer mode")
    if args.subdevice_alloc and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
            args.probed_ids, args.rm_control, args.channel_alloc, args.map_memory,
            args.rusd_alloc, args.p2p_alloc, args.p2p_control, args.binapi_control,
            args.device_alloc, args.managed_memory, args.managed_prefetch)):
        parser.error("--subdevice-alloc must be an isolated observer mode")
    if args.binapi_alloc and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                                  args.probed_ids, args.rm_control, args.channel_alloc,
                                  args.map_memory, args.rusd_alloc, args.p2p_alloc,
                                  args.p2p_control, args.binapi_control, args.device_alloc,
                                  args.subdevice_alloc, args.managed_memory,
                                  args.managed_prefetch)):
        parser.error("--binapi-alloc must be an isolated observer mode")
    if args.channel_alloc and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                                   args.probed_ids, args.rm_control, args.map_memory,
                                   args.rusd_alloc, args.p2p_alloc)):
        parser.error("--channel-alloc is an isolated observer capture mode")
    if args.map_memory and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                                args.probed_ids, args.rm_control, args.channel_alloc,
                                args.rusd_alloc, args.p2p_alloc)):
        parser.error("--map-memory is an isolated observer capture mode")
    if args.map_memory and (args.managed_memory or args.managed_prefetch):
        parser.error("--map-memory capture uses the default device-memory probe only")
    if args.rusd_alloc and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                                args.probed_ids, args.rm_control, args.channel_alloc,
                                args.map_memory, args.managed_memory, args.managed_prefetch,
                                args.p2p_alloc)):
        parser.error("--rusd-alloc is an isolated default device-memory observer capture mode")
    if args.p2p_alloc and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                               args.probed_ids, args.rm_control, args.channel_alloc,
                               args.map_memory, args.rusd_alloc, args.managed_memory,
                               args.managed_prefetch)):
        parser.error("--p2p-alloc is an isolated default device-memory observer capture mode")
    if args.p2p_control and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                                 args.probed_ids, args.channel_alloc, args.map_memory,
                                 args.rusd_alloc, args.p2p_alloc, args.managed_memory,
                                 args.managed_prefetch, args.binapi_control)):
        parser.error("--p2p-control must be isolated with --rm-control")
    if args.binapi_control and any((args.ioctl_trace, args.gpu_id_info, args.attached_ids,
                                    args.probed_ids, args.channel_alloc, args.map_memory,
                                    args.rusd_alloc, args.p2p_alloc, args.p2p_control,
                                    args.managed_memory, args.managed_prefetch)):
        parser.error("--binapi-control must be isolated with --rm-control")
    if args.managed_prefetch and not args.managed_memory:
        parser.error("--managed-prefetch requires --managed-memory")
    if args.rm_control_headers and (args.phase != "enumerate" or any((
            args.rm_control, args.ioctl_trace, args.gpu_id_info, args.attached_ids,
            args.probed_ids, args.channel_alloc, args.map_memory, args.rusd_alloc,
            args.p2p_alloc, args.p2p_control, args.binapi_control, args.device_alloc,
            args.subdevice_alloc, args.binapi_alloc, args.fabric_status, args.system_features,
            args.sync_boost_groups,
            args.managed_memory,
            args.managed_prefetch, args.cuda_graphs))):
        parser.error("--rm-control-headers requires an isolated --phase enumerate capture")
    if args.fabric_status and (args.phase != "enumerate" or any((
            args.rm_control, args.rm_control_headers, args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.channel_alloc, args.map_memory,
            args.rusd_alloc, args.p2p_alloc, args.p2p_control, args.binapi_control,
            args.device_alloc, args.subdevice_alloc, args.binapi_alloc,
            args.managed_memory, args.managed_prefetch, args.cuda_graphs,
            args.system_features, args.sync_boost_groups))):
        parser.error("--fabric-status requires an isolated --phase enumerate observer")
    if args.system_features and (args.phase != "enumerate" or any((
            args.rm_control, args.rm_control_headers, args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.channel_alloc, args.map_memory,
            args.rusd_alloc, args.p2p_alloc, args.p2p_control, args.binapi_control,
            args.device_alloc, args.subdevice_alloc, args.binapi_alloc, args.fabric_status,
            args.managed_memory, args.managed_prefetch, args.cuda_graphs))):
        parser.error("--system-features requires an isolated --phase enumerate observer")
    if args.sync_boost_groups and (args.phase != "enumerate" or any((
            args.rm_control, args.rm_control_headers, args.ioctl_trace, args.gpu_id_info,
            args.attached_ids, args.probed_ids, args.channel_alloc, args.map_memory,
            args.rusd_alloc, args.p2p_alloc, args.p2p_control, args.binapi_control,
            args.device_alloc, args.subdevice_alloc, args.binapi_alloc,
            args.fabric_status, args.system_features, args.ioctl_shapes,
            args.uvm_vaspace_fd, args.managed_memory, args.managed_prefetch,
            args.cuda_graphs, args.benchmark))):
        parser.error("--sync-boost-groups requires an isolated --phase enumerate observer")
    if args.phase:
        phase_observer_count = sum((args.binapi_control, args.device_alloc,
                                    args.subdevice_alloc, args.binapi_alloc,
                                    args.rm_control_headers, args.fabric_status,
                                    args.system_features, args.sync_boost_groups,
                                    args.ioctl_shapes,
                                    args.uvm_vaspace_fd))
        phase_trace = (args.phase in ("enumerate", "context", "managed-accessed-by") and args.ioctl_trace and
                       args.ioctl_observer is None and phase_observer_count == 0)
        phase_observer = (args.ioctl_observer is not None and phase_observer_count == 1 and
                          not args.ioctl_trace)
        phase_pageable = (args.phase == "system-pageable-memory" and
                          args.ioctl_observer is None and not args.ioctl_trace and
                          phase_observer_count == 0)
        if (not (phase_trace or phase_observer or phase_pageable) or
                (args.binapi_control and not args.rm_control) or
                (args.rm_control_headers and args.phase != "enumerate") or
                args.gpu_id_info or args.attached_ids or args.probed_ids or
                args.channel_alloc or args.map_memory or args.rusd_alloc or
                args.p2p_alloc or args.p2p_control or args.managed_memory or
                args.managed_prefetch or args.cuda_graphs):
            parser.error("--phase requires one isolated observer, enumerate/context/managed-accessed-by with --ioctl-trace, or standalone system-pageable-memory")
    if args.libcuda_override is not None:
        try:
            r58019607_libcuda_identity(args.libcuda_override)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        override_enumeration = (args.phase == "enumerate" and args.system_features and
                                not args.device_alloc and args.ioctl_observer is not None and
                                not args.ioctl_trace)
        override_context_or_kernel = (args.phase in ("context", "kernel") and args.device_alloc and
                           not args.system_features and args.ioctl_observer is not None and
                           not args.ioctl_trace)
        if not (override_enumeration or override_context_or_kernel):
            parser.error("--libcuda-override allows only enumerate plus SYSTEM_GET_FEATURES or context/kernel plus NV01_DEVICE_0 capture, each with one ioctl observer")
    sidecar = args.evidence.with_suffix(args.evidence.suffix + ".strace.gz")
    if args.ioctl_trace and sidecar.exists():
        parser.error("trace sidecar destination already exists")
    return args


def fetch_pc3_sudo_secret(host: str, credential_file: str) -> str:
    command = ["python3", "-c", _credential_remote_script(), credential_file]
    remote = " ".join(shlex.quote(part) for part in command)
    ssh = ["ssh", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
           "-oConnectTimeout=10", "-oConnectionAttempts=1", "--", host, remote]
    try:
        result = subprocess.run(ssh, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("authorized credential host could not be reached") from None
    if result.returncode != 0:
        raise RuntimeError("authorized PC3 credential could not be read")
    try:
        value = result.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise RuntimeError("authorized PC3 credential is not valid UTF-8") from None
    return validate_sudo_secret(value)


def pc3_ssh_base(target: str, host_key_alias: str) -> list[str]:
    askpass = os.environ.get("SSH_ASKPASS", "")
    askpass_enabled = (os.environ.get("SSH_ASKPASS_REQUIRE") == "force" and
                       bool(os.environ.get("DISPLAY")) and bool(askpass) and
                       Path(askpass).is_file() and os.access(askpass, os.X_OK))
    auth_options = (["-oBatchMode=no", "-oPubkeyAuthentication=no",
                     "-oPreferredAuthentications=password", "-oPasswordAuthentication=yes",
                     "-oKbdInteractiveAuthentication=no"] if askpass_enabled else ["-oBatchMode=yes"])
    return ["ssh", "-F", "/dev/null", "-T", *auth_options, "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=" + str(Path.home() / ".ssh/known_hosts"),
            "-oHostKeyAlias=" + host_key_alias, "-oConnectTimeout=10", "-oConnectionAttempts=1",
            "--", target]


def validate_direct_identity_file(identity_file: Path | str) -> Path:
    """Accept only a private regular key directly inside this user's ~/.ssh."""
    candidate = Path(identity_file)
    if not candidate.is_absolute():
        raise ValueError("PC3 SSH identity path must be absolute")
    ssh_dir = Path.home() / ".ssh"
    try:
        ssh_dir_info = ssh_dir.lstat()
        info = candidate.lstat()
        resolved_ssh_dir = ssh_dir.resolve(strict=True)
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except OSError:
        raise ValueError("PC3 SSH identity file or .ssh directory is unavailable") from None
    if (stat.S_ISLNK(ssh_dir_info.st_mode) or not stat.S_ISDIR(ssh_dir_info.st_mode) or
            resolved_parent != resolved_ssh_dir or
            stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or
            info.st_uid != os.geteuid() or (stat.S_IMODE(info.st_mode) & 0o077) != 0 or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", resolved_candidate.name)):
        raise ValueError("PC3 SSH identity must be a private regular file owned by this user in ~/.ssh")
    return resolved_candidate


def pc3_direct_ssh_base(target: str = DEFAULT_PC3_TARGET,
                        host_key_alias: str = DEFAULT_HOST_KEY_ALIAS,
                        identity_file: Path | str | None = None) -> list[str]:
    """Build key-only SSH arguments that can address PC3 and no other host."""
    if target != DEFAULT_PC3_TARGET or host_key_alias != DEFAULT_HOST_KEY_ALIAS:
        raise ValueError("direct collection is restricted to the pinned PC3 SSH route")
    argv = ["ssh", "-F", "/dev/null"]
    if identity_file is not None:
        identity = validate_direct_identity_file(identity_file)
        argv += ["-i", str(identity)]
    return argv + ["-T", "-oBatchMode=yes",
            "-oIdentitiesOnly=yes", "-oPreferredAuthentications=publickey",
            "-oPubkeyAuthentication=yes", "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no", "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=" + str(Path.home() / ".ssh/known_hosts"),
            "-oHostKeyAlias=" + host_key_alias, "-oConnectTimeout=10",
            "-oConnectionAttempts=1", "--", target]


def cleanup_pc3_payload(target: str, host_key_alias: str, path: str, digest: str,
                        direct_pc3: bool = False,
                        identity_file: Path | str | None = None) -> bool:
    remote = " ".join(shlex.quote(part) for part in
                      ["python3", "-c", payload_cleanup_code(), path, digest])
    try:
        ssh_base = (pc3_direct_ssh_base(target, host_key_alias, identity_file)
                    if direct_pc3 else pc3_ssh_base(target, host_key_alias))
        result = subprocess.run(ssh_base + [remote], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        report = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        return False
    return report.get("cleanup_passed") is True and report.get("remaining") is False


def report_path(args: argparse.Namespace) -> dict[str, object]:
    report = {"schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
              "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "report_contract_validated": False,
              "device_inventory_observed": False,
              "cuda_execution_validated": False,
              "cuda_execution_validation_state": "not-established; probe build identity is not trusted",
              "target": args.target,
              "transport_mode": "pc3-direct-key-sudo-n" if args.direct_pc3 else "pc6-sourced-sudo-auth",
              "ssh_identity_file_basename": (args.identity_file.name
                                             if args.identity_file is not None else None),
              "credential_host": args.credential_host,
              "credential_file": args.credential_file,
              "memory_mode": "managed" if args.managed_memory else "device",
              "managed_prefetch_requested": args.managed_prefetch,
              "cuda_graphs_requested": args.cuda_graphs,
              "performance_benchmark_requested": args.benchmark,
              "gpu_id_info_capture_requested": args.gpu_id_info,
              "attached_ids_capture_requested": args.attached_ids,
              "probed_ids_capture_requested": args.probed_ids,
              "rm_control_capture_requested": args.rm_control,
              "rm_control_headers_capture_requested": args.rm_control_headers,
              "fabric_status_capture_requested": args.fabric_status,
              "system_features_capture_requested": args.system_features,
              "sync_boost_groups_capture_requested": args.sync_boost_groups,
              "ioctl_shapes_capture_requested": args.ioctl_shapes,
              "uvm_vaspace_fd_capture_requested": args.uvm_vaspace_fd,
              "channel_alloc_capture_requested": args.channel_alloc,
              "map_memory_capture_requested": args.map_memory,
              "rusd_alloc_capture_requested": args.rusd_alloc,
              "p2p_alloc_capture_requested": args.p2p_alloc,
              "p2p_control_capture_requested": args.p2p_control,
              "binapi_control_capture_requested": args.binapi_control,
              "device_alloc_capture_requested": args.device_alloc,
              "subdevice_alloc_capture_requested": args.subdevice_alloc,
              "binapi_alloc_capture_requested": args.binapi_alloc,
              "libcuda_override_requested": args.libcuda_override is not None,
              "p2p_fault_requested": args.p2p_fault is not None,
              "p2p_fault_mode": args.p2p_fault,
              "phase_capture_requested": args.phase is not None,
              "phase": args.phase,
              "credential_value_logged": False, "credential_value_persisted": False,
              "probe": identity(args.probe), "module": identity(args.module),
              "runner_source": identity(Path(__file__)),
              "remote_script_sha256": hashlib.sha256(REMOTE_ROOT_SCRIPT.encode()).hexdigest()}
    if args.libcuda_override is not None:
        report["libcuda_override"] = r58019607_libcuda_identity(args.libcuda_override)
    if args.p2p_fault_shim is not None:
        report["p2p_fault_shim"] = p2p_fault_shim_identity(args.p2p_fault_shim)
    if args.ioctl_observer is not None:
        report["ioctl_observer"] = identity(args.ioctl_observer)
    if args.ioctl_trace:
        report["ioctl_trace_helper"] = identity(ROOT / "tools/summarize_rm_ioctl_trace.py")
    return report


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = report_path(args)
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    secret = None
    payload_path = None
    payload_digest = None
    payload_cleanup_done = False
    try:
        try:
            report["probe_build_trust"] = verify_pinned_probe_build(
                report["probe"], report["module"])
            report["cuda_execution_validation_state"] = (
                "probe/fatbin identity is pinned; guest CUDA execution is not independently attested")
            report["probe_contract"] = validate_probe_contract(
                args.probe, expected_sha256=report["probe"]["sha256"],
                require_performance_benchmark=args.benchmark)
            if args.direct_pc3:
                ssh_base = pc3_direct_ssh_base(args.target, args.host_key_alias,
                                               args.identity_file)
                preflight = direct_pc3_preflight(ssh_base)
                report.update(preflight)
                if preflight.get("pc3_ssh_preflight_passed") is not True:
                    raise RuntimeError("PC3 SSH preflight failed")
                if preflight.get("pc3_sudo_preflight_passed") is not True:
                    raise RuntimeError("PC3 noninteractive sudo preflight failed")
            else:
                ssh_base = pc3_ssh_base(args.target, args.host_key_alias)
                secret = fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
            payload = {"artifacts": {}}
            artifact_paths = {"probe": args.probe, "module": args.module}
            if args.libcuda_override is not None:
                artifact_paths["libcuda"] = args.libcuda_override
            if args.p2p_fault_shim is not None:
                artifact_paths["p2p-fault-shim"] = args.p2p_fault_shim
            if args.ioctl_observer is not None:
                artifact_paths["observer"] = args.ioctl_observer
            if args.ioctl_trace:
                artifact_paths["trace-helper"] = ROOT / "tools/summarize_rm_ioctl_trace.py"
                payload["ioctl_trace"] = True
            report_keys = {"probe": "probe", "module": "module", "observer": "ioctl_observer",
                           "trace-helper": "ioctl_trace_helper",
                           "libcuda": "libcuda_override",
                           "p2p-fault-shim": "p2p_fault_shim"}
            for name, path in artifact_paths.items():
                data = path.resolve(strict=True).read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                expected = report[report_keys[name]]
                if len(data) != expected["bytes"] or digest != expected["sha256"]:
                    raise RuntimeError("local test artifact changed after evidence reservation")
                payload["artifacts"][name] = {"bytes": len(data), "sha256": digest,
                                               "base64": base64.b64encode(data).decode("ascii")}
            payload["managed_memory"] = args.managed_memory
            payload["managed_prefetch"] = args.managed_prefetch
            payload["cuda_graphs"] = args.cuda_graphs
            payload["performance_benchmark"] = args.benchmark
            payload["gpu_id_info_capture"] = args.gpu_id_info
            payload["attached_ids_capture"] = args.attached_ids
            payload["probed_ids_capture"] = args.probed_ids
            payload["rm_control_capture"] = args.rm_control
            payload["rm_control_headers_capture"] = args.rm_control_headers
            payload["fabric_status_capture"] = args.fabric_status
            payload["system_features_capture"] = args.system_features
            payload["sync_boost_groups_capture"] = args.sync_boost_groups
            payload["ioctl_shapes_capture"] = args.ioctl_shapes
            payload["uvm_vaspace_fd_capture"] = args.uvm_vaspace_fd
            payload["channel_alloc_capture"] = args.channel_alloc
            payload["map_memory_capture"] = args.map_memory
            payload["rusd_alloc_capture"] = args.rusd_alloc
            payload["p2p_alloc_capture"] = args.p2p_alloc
            payload["p2p_control_capture"] = args.p2p_control
            payload["binapi_control_capture"] = args.binapi_control
            payload["device_alloc_capture"] = args.device_alloc
            payload["subdevice_alloc_capture"] = args.subdevice_alloc
            payload["binapi_alloc_capture"] = args.binapi_alloc
            payload["phase"] = args.phase
            payload["libcuda_override"] = args.libcuda_override is not None
            payload["p2p_fault_mode"] = args.p2p_fault
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            payload_digest = hashlib.sha256(payload_bytes).hexdigest()
            payload_path = payload_staging_path(uuid.uuid4().hex)
            report["payload_staging"] = {"path": payload_path, "bytes": len(payload_bytes),
                                         "sha256": payload_digest, "uploaded": False}
            upload_remote = " ".join(shlex.quote(part) for part in
                                     ["python3", "-c", payload_writer_code(), payload_path, payload_digest])
            try:
                uploaded = subprocess.run(ssh_base + [upload_remote],
                                          input=payload_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          timeout=300 if args.libcuda_override is not None else 30,
                                          check=False)
            except subprocess.TimeoutExpired as error:
                report.update(payload_upload_failure_fields(
                    None, error.stderr or b"", process_failure="timeout"))
                raise RuntimeError("PC3 payload staging failed") from None
            except OSError:
                report.update(payload_upload_failure_fields(
                    None, process_failure="start"))
                raise RuntimeError("PC3 payload staging failed") from None
            if uploaded.returncode != 0:
                report.update(payload_upload_failure_fields(
                    uploaded.returncode, uploaded.stderr))
                raise RuntimeError("PC3 payload staging failed")
            try:
                upload_receipt = json.loads(uploaded.stdout.decode("utf-8", "strict"))
            except (UnicodeDecodeError, ValueError):
                report["failure_stage"] = "pc3_payload_receipt_invalid"
                report["pc3_payload_receipt_stdout_sha256"] = hashlib.sha256(
                    uploaded.stdout).hexdigest()
                raise RuntimeError("PC3 payload staging receipt is invalid") from None
            if upload_receipt != {"bytes": len(payload_bytes), "sha256": payload_digest}:
                report["failure_stage"] = "pc3_payload_receipt_mismatch"
                report["pc3_payload_receipt_stdout_sha256"] = hashlib.sha256(
                    uploaded.stdout).hexdigest()
                raise RuntimeError("PC3 payload staging receipt differs from the local payload")
            report["payload_staging"]["uploaded"] = True

            sudo_prefix = "sudo -n python3 -c " if args.direct_pc3 else "sudo -S -p '' python3 -c "
            remote_command = (sudo_prefix + shlex.quote(REMOTE_ROOT_SCRIPT) + " " +
                              shlex.quote(payload_path) + " " + shlex.quote(payload_digest))
            if args.direct_pc3:
                remote_options = {"stdin": subprocess.DEVNULL}
            else:
                remote_options = {"input": sudo_auth_stdin(secret)}
            try:
                result = subprocess.run(ssh_base + [remote_command],
                                        **remote_options, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=520 if args.libcuda_override is not None else 260,
                                        check=False)
            except (OSError, subprocess.TimeoutExpired):
                report["failure_stage"] = "pc3_sudo_transport"
                report["error"] = "PC3 root test session failed or timed out"
            else:
                report["pc3_ssh_exit_code"] = result.returncode
                try:
                    remote = json.loads(result.stdout.decode("utf-8", "strict"))
                except (UnicodeDecodeError, ValueError):
                    remote = None
                if isinstance(remote, dict) and remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1":
                    report["remote"] = remote
                else:
                    report["failure_stage"] = "pc3_sudo_transport"
                    report["error"] = "PC3 did not return a valid redacted result record"
                    report["pc3_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
                    report["pc3_transport_failure_class"] = classify_pc3_transport_failure(
                        result.stderr)
                    report["pc3_stderr"] = redact_secret(result.stderr.decode("utf-8", "replace"), secret)
            report["payload_cleanup_passed"] = cleanup_pc3_payload(
                args.target, args.host_key_alias, payload_path, payload_digest,
                direct_pc3=args.direct_pc3, identity_file=args.identity_file)
            payload_cleanup_done = report["payload_cleanup_passed"] is True
            remote = report.get("remote")
            if isinstance(remote, dict) and isinstance(remote.get("probe"), dict):
                try:
                    artifact_paths = {"probe": args.probe, "module": args.module}
                    if args.libcuda_override is not None:
                        artifact_paths["libcuda"] = args.libcuda_override
                    if args.p2p_fault_shim is not None:
                        artifact_paths["p2p-fault-shim"] = args.p2p_fault_shim
                    if args.ioctl_observer is not None:
                        artifact_paths["observer"] = args.ioctl_observer
                    if args.ioctl_trace:
                        artifact_paths["trace-helper"] = ROOT / "tools/summarize_rm_ioctl_trace.py"
                        trace_transport = remote.pop("ioctl_trace_transport", None)
                        trace_meta = remote.get("ioctl_trace") or {}
                        trace_capture = trace_meta.get("trace") or {}
                        if not isinstance(trace_transport, dict) or not isinstance(trace_capture, dict):
                            raise ValueError("requested ioctl trace transport is missing")
                        compressed = base64.b64decode(trace_transport["gzip_base64"], validate=True)
                        summary_spec = importlib.util.spec_from_file_location(
                            "trace_summary_local", ROOT / "tools/summarize_rm_ioctl_trace.py")
                        if summary_spec is None or summary_spec.loader is None:
                            raise ValueError("local ioctl trace helper cannot be loaded")
                        summary_module = importlib.util.module_from_spec(summary_spec)
                        summary_spec.loader.exec_module(summary_module)
                        sidecar = args.evidence.with_suffix(args.evidence.suffix + ".strace.gz")
                        local_summary_fn = (summary_module.summarize_node_open_trace
                                            if args.phase in ("enumerate", "context") else None)
                        report["ioctl_trace_artifact"] = summary_module.write_trace_sidecar(
                            sidecar, compressed, trace_transport, trace_capture["summary"],
                            require_complete=False, summary_fn=local_summary_fn)
                    report_keys = {"probe": "probe", "module": "module", "observer": "ioctl_observer",
                                   "trace-helper": "ioctl_trace_helper",
                                   "libcuda": "libcuda_override",
                                   "p2p-fault-shim": "p2p_fault_shim"}
                    expected_artifacts = {name: report[report_keys[name]] for name in artifact_paths}
                    for name, path in artifact_paths.items():
                        current = identity(path)
                        report[report_keys[name] + "_after"] = current
                        if current != expected_artifacts[name]:
                            raise ValueError("local test artifact changed during execution")
                    try:
                        qualification = validate_remote_acceptance(
                            remote, expected_artifacts, trace_requested=args.ioctl_trace,
                            managed_memory=args.managed_memory,
                            managed_prefetch=args.managed_prefetch,
                            cuda_graphs=args.cuda_graphs,
                            performance_benchmark=args.benchmark,
                            gpu_id_info_requested=args.gpu_id_info,
                            attached_ids_requested=args.attached_ids,
                            probed_ids_requested=args.probed_ids,
                            rm_control_requested=args.rm_control,
                            rm_control_headers_requested=args.rm_control_headers,
                            fabric_status_requested=args.fabric_status,
                            system_features_requested=args.system_features,
                            sync_boost_groups_requested=args.sync_boost_groups,
                            channel_alloc_requested=args.channel_alloc,
                            map_memory_requested=args.map_memory,
                            rusd_alloc_requested=args.rusd_alloc,
                            p2p_alloc_requested=args.p2p_alloc,
                            p2p_control_requested=args.p2p_control,
                            binapi_control_requested=args.binapi_control,
                            device_alloc_requested=args.device_alloc,
                            subdevice_alloc_requested=args.subdevice_alloc,
                            binapi_alloc_requested=args.binapi_alloc,
                            ioctl_shapes_requested=args.ioctl_shapes,
                            phase=args.phase,
                            uvm_vaspace_fd_requested=args.uvm_vaspace_fd,
                            libcuda_override_requested=args.libcuda_override is not None,
                            p2p_fault_mode=args.p2p_fault)
                    except (KeyError, TypeError, ValueError) as success_validation_error:
                        if args.libcuda_override is None:
                            raise
                        qualification = validate_r58019607_stock_v100_rejection(
                            remote, expected_artifacts)
                        remote["compatibility_outcome"] = (
                            "CUDA_ERROR_SYSTEM_DRIVER_MISMATCH-803-report-contract-valid")
                        report["success_validation_error"] = str(success_validation_error)
                    else:
                        if args.libcuda_override is not None:
                            remote["compatibility_outcome"] = (
                                "phase-report-contract-valid"
                                if args.phase in ("context", "kernel") else
                                "enumeration-report-contract-valid")
                    if not report.get("payload_cleanup_passed"):
                        raise ValueError("PC3 payload cleanup could not be verified")
                    remote["report_contract_validated"] = True
                    remote["device_inventory_observed"] = True
                    remote["cuda_execution_validated"] = False
                    remote["cuda_execution_validation_state"] = report[
                        "cuda_execution_validation_state"]
                    report["report_contract_validated"] = True
                    report["device_inventory_observed"] = True
                    report["cuda_execution_validated"] = False
                    remote["qualification"] = qualification
                    report["qualification"] = qualification
                    return_code = 0
                except (KeyError, TypeError, ValueError) as error:
                    remote["qualification"] = "failed"
                    report["qualification"] = "failed"
                    report["validation_error"] = str(error)
                    return_code = 2
            else:
                report["qualification"] = "failed"
                if isinstance(remote, dict):
                    report["failure_stage"] = remote.get("failure_stage", "probe_validation")
                    report["error"] = remote.get("error", "SM70 reference did not pass")
                return_code = 2
            report["exit_code"] = return_code
        except (OSError, RuntimeError, ValueError) as error:
            report["qualification"] = "failed"
            report["failure_stage"] = report.get("failure_stage", "local_preflight")
            report["error"] = str(error)[:300]
            report["exit_code"] = 2
            return_code = 2
        finally:
            if payload_path and payload_digest and not payload_cleanup_done:
                report["payload_cleanup_passed"] = cleanup_pc3_payload(args.target, args.host_key_alias,
                                                                        payload_path, payload_digest,
                                                                        direct_pc3=args.direct_pc3,
                                                                        identity_file=args.identity_file)
                payload_cleanup_done = report["payload_cleanup_passed"] is True
            stdin = b""
            sanitize_ioctl_shape_evidence(report, requested=args.ioctl_shapes)
            report = redact_nested(report, secret)
            secret = None
            if "exit_code" not in report:
                report["exit_code"] = 2
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
        print(json.dumps({"evidence": str(args.evidence), "qualification": report["qualification"],
                          "exit_code": report["exit_code"]}, sort_keys=True))
        return int(report["exit_code"])
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    raise SystemExit(main())
