#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the SM70 numerical reference inside PC3's existing V100 guest.

The sudo credential is fetched from the authorized PC6 credential file over
strict SSH and exists only in this process' memory/stdin. No driver, VM, PCI
binding, firmware, or boot state is changed.
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
SIZES = [1, 31, 256, 4096, 65537]
DEFAULT_PROBE = ROOT / "build/probe-managed-prefetch-v2/hybrid_cuda_probe"
DEFAULT_MODULE = ROOT / "build/probe-managed-prefetch-v2/hybrid_probe.sm70-sm120.fatbin"
DEFAULT_CREDENTIAL_HOST = "gx10-e526"
DEFAULT_CREDENTIAL_FILE = "/home/pc6/Desktop/ACCES-BANC-GPU.env"
DEFAULT_PC3_TARGET = "pc3@pc3"
DEFAULT_HOST_KEY_ALIAS = "pc3"
DEFAULT_GUEST_KEY = "/var/lib/pc3-v100-vm/id_ed25519"
DEFAULT_GUEST_KNOWN_HOSTS = "/tmp/codex-pc3-vm-known_hosts"
EXPECTED_GUEST_HOSTKEY_FINGERPRINT = "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"


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
                            cuda_graphs: bool = False) -> str:
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
    graph_api = report.get("cuda_graph_api")
    if cuda_graphs:
        require(graph_api == "cuGraphInstantiateWithFlags",
                "V100 CUDA Graph API was unavailable or unidentified")
    else:
        require(graph_api == "not-requested", "unrequested V100 CUDA Graph API claim")
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
    return "v100-reference-validated"


def validate_cuda_phase_report(report: object, exit_code: int, expected_pci: str,
                               expected_phase: str) -> str:
    """Reuse the shared exact phase contract, then bind it to the V100 guest."""
    validator_path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_phase_validator", validator_path)
    if spec is None or spec.loader is None:
        raise ValueError("shared CUDA phase validator is unavailable")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
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


def validate_remote_acceptance(remote: object, expected_artifacts: dict[str, dict[str, object]],
                               trace_requested: bool = False,
                               managed_memory: bool = False,
                               managed_prefetch: bool = False,
                               cuda_graphs: bool = False,
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
                               device_alloc_requested: bool = False,
                               subdevice_alloc_requested: bool = False,
                               binapi_alloc_requested: bool = False,
                               phase: str | None = None) -> str:
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
    require(remote.get("gpu_id_info_capture_requested", False) is gpu_id_info_requested,
            "remote GPU-ID-info capture mode differs from the request")
    require(remote.get("attached_ids_capture_requested", False) is attached_ids_requested,
            "remote attached-ID capture mode differs from the request")
    require(remote.get("probed_ids_capture_requested", False) is probed_ids_requested,
            "remote probed-ID capture mode differs from the request")
    require(remote.get("rm_control_capture_requested", False) is rm_control_requested,
            "remote RM_CONTROL capture mode differs from the request")
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
    if requested_phase is not None:
        require(requested_phase in ("initialize", "enumerate", "context", "allocation", "module", "kernel") and
                "observer" in expected_artifacts and
                sum((binapi_control_requested, device_alloc_requested,
                     subdevice_alloc_requested, binapi_alloc_requested)) == 1 and
                (not binapi_control_requested or rm_control_requested) and
                not any((trace_requested, managed_memory,
                managed_prefetch, gpu_id_info_requested, attached_ids_requested,
                probed_ids_requested, channel_alloc_requested, map_memory_requested,
                rusd_alloc_requested, p2p_alloc_requested, p2p_control_requested)),
                "CUDA phase requires exactly one isolated BINAPI, NV01_DEVICE_0, NV20_SUBDEVICE_0, or NV2081_BINAPI allocation observer mode")
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
    pci = canonical_pci(guest.get("pci", ""))
    require(isinstance(guest.get("kernel_release"), str) and bool(guest["kernel_release"]), "missing guest kernel release")
    require(isinstance(remote.get("guest_after"), dict), "missing post-probe guest inventory")
    require(remote.get("guest_cleanup_passed") is True, "temporary guest artifacts were not removed")
    probe = remote.get("probe")
    if requested_phase is not None:
        require(validate_cuda_phase_report(probe, remote.get("probe_exit_code"), pci,
                                           requested_phase) == "phase-observed-on-hardware",
                "V100 CUDA phase gate failed")
    else:
        require(validate_v100_reference(probe, remote.get("probe_exit_code"), pci,
                                        managed_memory=managed_memory,
                                        managed_prefetch=managed_prefetch,
                                        cuda_graphs=cuda_graphs) == "v100-reference-validated",
                "SM70 reference gate failed")

    library = remote.get("driver_library")
    require(isinstance(library, dict) and library.get("path") == probe.get("driver_library_path"),
            "installed libcuda identity is missing")
    require(type(library.get("bytes")) is int and library["bytes"] > 0 and
            re.fullmatch(r"[0-9a-f]{64}", library.get("sha256", "")) is not None,
            "installed libcuda hash is invalid")

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

    if "observer" in expected_artifacts:
        observed = remote.get("ioctl_observation")
        require(isinstance(observed, dict), "requested RM ioctl observation is missing")
        expected_observer_schema = ("nvidia-hybrid-rm-ioctl-observer-v21"
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
                            device_alloc_requested or subdevice_alloc_requested or
                            (binapi_alloc_requested and binapi_alloc_snapshots > 0) or
                            (p2p_control_requested and
                             observed.get("p2p_control_payload_snapshots_read", 0) > 0) or
                            (binapi_control_requested and binapi_snapshots > 0))
        if map_memory_requested:
            nested_requested = False
        require(observed.get("nested_pointers_read") is nested_requested and
                observed.get("fd_identity_tracking") is False,
                "RM ioctl observer exceeded its read-only packet boundary")
        selected_scopes = []
        if gpu_id_info_requested:
            selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2")
        if attached_ids_requested:
            selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS")
        if probed_ids_requested:
            selected_scopes.append("NV0000_CTRL_CMD_GPU_GET_PROBED_IDS")
        if channel_alloc_requested:
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
        else:
            require("fd_lifecycle_scope" not in observed and
                    "fd_identity_capture_complete" not in observed,
                    "unrequested map-memory scope was returned")
            if (not rm_control_requested and not device_alloc_requested and
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
        elif not map_memory_requested:
            require("payload_scope" not in observed,
                    "unrequested RM_CONTROL payload scope was returned")
        records = observed.get("records")
        empty_rusd_absence = (rusd_alloc_requested and
                              observed.get("rusd_payload_snapshots_read") == 0)
        empty_binapi_absence = binapi_control_requested and binapi_snapshots == 0
        require(isinstance(records, list) and all(isinstance(record, dict) for record in records) and
                (bool(records) or empty_rusd_absence or empty_binapi_absence),
                "RM ioctl observation contains no valid records")
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
        require(isinstance(summary, dict) and summary.get("trace_complete") is True and
                summary.get("parsed_calls", 0) > 0,
                "ioctl trace contains no complete parsed calls")
        require(isinstance(trace.get("strace_version"), str) and
                trace["strace_version"].startswith("strace -- version ") and
                re.fullmatch(r"[0-9a-f]{64}", trace.get("strace_sha256", "")) is not None,
                "strace identity is missing or invalid")
    else:
        require("ioctl_trace" not in remote and "ioctl_trace_transport" not in remote,
                "unrequested ioctl strace data was returned")
    return "v100-cuda-phase-validated" if requested_phase is not None else "v100-reference-validated"


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
          "gpu_id_info_capture_requested": False, "gpu_id_info_records_seen": None,
          "attached_ids_capture_requested": False, "attached_ids_records_seen": None,
          "probed_ids_capture_requested": False, "probed_ids_records_seen": None,
          "rm_control_capture_requested": False, "rm_control_records_seen": None,
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

def main(payload):
    global stage
    phase = payload.get("phase")
    if phase is not None and phase not in (
            "initialize", "enumerate", "context", "allocation", "module", "kernel"):
        raise ValueError("unsupported CUDA Driver API phase")
    report["phase_capture_requested"] = phase is not None
    report["phase"] = phase
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
    if phase is not None and (
            "observer" not in payload.get("artifacts", {}) or
            sum((binapi_control_capture, device_alloc_capture,
                 subdevice_alloc_capture, binapi_alloc_capture)) != 1 or
            (binapi_control_capture and not rm_control_capture) or
            any((payload.get("ioctl_trace"), managed_memory, managed_prefetch,
                 gpu_id_info_capture, attached_ids_capture, probed_ids_capture,
                 channel_alloc_capture, map_memory_capture, rusd_alloc_capture,
                 p2p_alloc_capture, p2p_control_capture))):
        raise ValueError("CUDA phase requires exactly one isolated BINAPI, NV01_DEVICE_0, NV20_SUBDEVICE_0, or NV2081_BINAPI allocation observer mode")
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
print(json.dumps({"hostname":socket.gethostname(),"kernel_release":platform.release(),"nvidia_smi_exit":r.returncode,
"nvidia_smi_stderr":r.stderr[:1000],"devices":[[v.strip() for v in row] for row in rows]}))
"""
        guest = guest_json(inventory_code)
        rows = guest.get("devices")
        if (guest.get("hostname") != "pc3-v100" or guest.get("nvidia_smi_exit") != 0 or
            not isinstance(rows, list) or len(rows) != 1 or len(rows[0]) != 8 or
            not rows[0][0].startswith("Tesla V100") or
            not re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", rows[0][1])):
            raise RuntimeError("guest inventory is not exactly one Tesla V100")
        guest_pci = canonical_pci(rows[0][2])
        gpu_uuid = rows[0][1]
        report["guest"] = {"hostname": guest["hostname"], "kernel_release": guest["kernel_release"],
                           "name": rows[0][0], "uuid": gpu_uuid, "pci": guest_pci,
                           "driver_version": rows[0][3], "memory_total_mib": rows[0][4],
                           "memory_used_mib_before": rows[0][5], "utilization_percent_before": rows[0][6],
                           "temperature_c_before": rows[0][7]}

        stage = "artifact_verification"
        artifact_names = ["probe", "module"]
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
                      "trace-helper": "py"}
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
            written = guest_json(write_code, args=(dest,), input_data=artifact_data[name])
            if written != report["artifacts_before"][name]:
                raise RuntimeError("guest artifact hash differs after transfer")
            report["artifacts_before"][name]["guest_path"] = dest

        stage = "sm70_cuda_probe"
        run_code = r"""import base64,gzip,hashlib,importlib.machinery,importlib.util,json,os,subprocess,sys,tempfile
from pathlib import Path
probe,module,pci,gpu_uuid,observer,trace_helper,trace_enabled,managed_enabled,prefetch_enabled,graphs_enabled,id_info_enabled,attached_enabled,probed_enabled,rm_control_enabled,channel_alloc_enabled,map_memory_enabled,rusd_alloc_enabled,p2p_alloc_enabled,p2p_control_enabled,binapi_control_enabled,device_alloc_enabled,subdevice_alloc_enabled,binapi_alloc_enabled,phase_enabled=sys.argv[1:]
env={"PATH":"/usr/bin:/bin","LC_ALL":"C","CUDA_VISIBLE_DEVICES":gpu_uuid}
if phase_enabled:
 probe_argv=[probe,"--module",module,"--phase",phase_enabled,"--expected-pci",pci]
else:
 probe_argv=[probe,"--module",module,"--require-sm","70","--expected-pci",pci]
if managed_enabled == "1":probe_argv.append("--managed-memory")
if prefetch_enabled == "1":probe_argv.append("--managed-prefetch")
if graphs_enabled == "1":probe_argv.append("--cuda-graphs")
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
  with tempfile.TemporaryDirectory(prefix="codex-v100-strace-") as directory:
   trace_path=str(Path(directory)/"ioctl.strace")
   captured=helper.capture("/usr/bin/strace",trace_path,probe_argv,timeout=100,env=env)
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
   if p2p_control_enabled == "1": argv.append("--p2p-control")
   if binapi_control_enabled == "1": argv += ["--binapi-control","--gpu-path","/dev/nvidia0"]
   if device_alloc_enabled == "1": argv += ["--device-alloc","--gpu-path","/dev/nvidia0"]
   if subdevice_alloc_enabled == "1": argv += ["--subdevice-alloc","--gpu-path","/dev/nvidia0"]
   if binapi_alloc_enabled == "1": argv += ["--binapi-alloc","--gpu-path","/dev/nvidia0"]
   if channel_alloc_enabled == "1": argv += ["--channel-alloc","--gpu-path","/dev/nvidia0"]
   if map_memory_enabled == "1": argv += ["--map-memory","--gpu-path","/dev/nvidia0"]
   if rusd_alloc_enabled == "1": argv += ["--rusd-alloc","--gpu-path","/dev/nvidia0"]
   if p2p_alloc_enabled == "1": argv += ["--p2p-alloc","--gpu-path","/dev/nvidia0"]
   argv += ["--",*probe_argv]
   r=subprocess.run(argv,text=True,capture_output=True,env=env,timeout=100,check=False)
   observer_exit=r.returncode
   try: observation=json.loads(Path(observation_path).read_text())
   except (OSError,ValueError,TypeError): observation=None
 else:
  r=subprocess.run(probe_argv,text=True,capture_output=True,env=env,timeout=100,check=False)
 report=None
 try: report=json.loads(r.stdout)
 except (ValueError,TypeError): pass
 lib=None
 if isinstance(report,dict) and isinstance(report.get("driver_library_path"),str):
  p=Path(report["driver_library_path"]).resolve(strict=True); b=p.read_bytes()
  lib={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
 result={"exit_code":observation.get("child_exit_code") if observer and isinstance(observation,dict) else r.returncode,
         "stdout":r.stdout,"stderr":r.stderr,"probe":report,"driver_library":lib}
 if observer:
  result["observer_exit_code"]=observer_exit
  result["ioctl_observation"]=observation
 if trace_enabled == "1":
  result["ioctl_trace"]=trace_report
  result["ioctl_trace_transport"]=trace_transport
 print(json.dumps(result))
except subprocess.TimeoutExpired:
 result={"exit_code":124,"stdout":"","stderr":"probe or observer timed out","probe":None,"driver_library":None}
 if observer:
  result["observer_exit_code"]=124
  result["ioctl_observation"]=observation
 if trace_enabled == "1":
  result["ioctl_trace"]={"timed_out":True,"trace_complete":False}
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
                                                "1" if payload.get("gpu_id_info_capture") else "0",
                                                "1" if payload.get("attached_ids_capture") else "0",
                                                "1" if payload.get("probed_ids_capture") else "0",
                                                "1" if payload.get("rm_control_capture") else "0",
                                                "1" if payload.get("channel_alloc_capture") else "0",
                                                "1" if payload.get("map_memory_capture") else "0",
                                                "1" if payload.get("rusd_alloc_capture") else "0",
                                                "1" if payload.get("p2p_alloc_capture") else "0",
                                                "1" if payload.get("p2p_control_capture") else "0",
                                                "1" if payload.get("binapi_control_capture") else "0",
                                                "1" if payload.get("device_alloc_capture") else "0",
                                                "1" if payload.get("subdevice_alloc_capture") else "0",
                                                "1" if payload.get("binapi_alloc_capture") else "0",
                                                phase or ""),
                                timeout=150 if payload.get("ioctl_trace") else 125)
        report["probe_exit_code"] = run_result.get("exit_code")
        report["probe"] = run_result.get("probe")
        report["probe_stdout"] = run_result.get("stdout", "")
        report["probe_stderr"] = run_result.get("stderr", "")
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
        if payload.get("ioctl_trace"):
            report["ioctl_trace"] = run_result.get("ioctl_trace")
            report["ioctl_trace_transport"] = run_result.get("ioctl_trace_transport")

        stage = "post_probe_inventory"
        guest_after = guest_json(inventory_code)
        after_rows = guest_after.get("devices")
        if (guest_after.get("hostname") != guest.get("hostname") or
            guest_after.get("nvidia_smi_exit") != 0 or not isinstance(after_rows, list) or
            len(after_rows) != 1 or len(after_rows[0]) != 8 or after_rows[0][1] != gpu_uuid or
            canonical_pci(after_rows[0][2]) != guest_pci):
            raise RuntimeError("guest GPU identity changed during the SM70 reference")
        report["guest_after"] = {"memory_used_mib": after_rows[0][5],
                                 "utilization_percent": after_rows[0][6],
                                 "temperature_c": after_rows[0][7]}

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
    parser.add_argument("--credential-host", default=DEFAULT_CREDENTIAL_HOST)
    parser.add_argument("--credential-file", default=DEFAULT_CREDENTIAL_FILE)
    parser.add_argument("--probe", type=Path, default=DEFAULT_PROBE)
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--ioctl-observer", type=Path,
                        help="optionally capture read-only /dev/nvidiactl ROOT allocation/free packets")
    parser.add_argument("--gpu-id-info", action="store_true",
                        help="with --ioctl-observer, capture the fixed GPU_GET_ID_INFO_V2 payload")
    parser.add_argument("--attached-ids", action="store_true",
                        help="with --ioctl-observer, capture the fixed GPU_GET_ATTACHED_IDS payload")
    parser.add_argument("--probed-ids", action="store_true",
                        help="with --ioctl-observer, capture the fixed GPU_GET_PROBED_IDS payload")
    parser.add_argument("--rm-control", action="store_true",
                        help="with --ioctl-observer, capture fixed NVOS54 RM_CONTROL headers only")
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
    parser.add_argument("--ioctl-trace", action="store_true",
                        help="capture all ioctl metadata from the selected V100 CUDA probe")
    parser.add_argument("--managed-memory", action="store_true",
                        help="run CUDA kernels using cuMemAllocManaged on the V100")
    parser.add_argument("--managed-prefetch", action="store_true",
                        help="with --managed-memory, prefetch test ranges to the V100 and CPU")
    parser.add_argument("--cuda-graphs", action="store_true",
                        help="run two opt-in CUDA Graph replays of the numeric kernel on the V100")
    parser.add_argument("--phase", choices=("initialize", "enumerate", "context", "allocation", "module", "kernel"),
                        help="run one isolated CUDA Driver API phase with one selected redacted observer")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", args.target):
        parser.error("target must be a literal user@host")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.host_key_alias):
        parser.error("invalid PC3 host-key alias")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.credential_host):
        parser.error("credential host must be a configured SSH alias")
    if args.evidence.exists():
        parser.error("evidence destination already exists")
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
    if args.phase and (args.ioctl_observer is None or
                       sum((args.binapi_control, args.device_alloc, args.subdevice_alloc,
                            args.binapi_alloc)) != 1 or
                       (args.binapi_control and not args.rm_control) or
                       args.ioctl_trace or args.gpu_id_info or
                       args.attached_ids or args.probed_ids or args.channel_alloc or
                       args.map_memory or args.rusd_alloc or args.p2p_alloc or
                       args.p2p_control or args.managed_memory or args.managed_prefetch or
                       args.cuda_graphs):
        parser.error("--phase requires exactly one isolated BINAPI, NV01_DEVICE_0, NV20_SUBDEVICE_0, or NV2081_BINAPI allocation observer capture")
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
    return ["ssh", "-F", "/dev/null", "-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=" + str(Path.home() / ".ssh/known_hosts"),
            "-oHostKeyAlias=" + host_key_alias, "-oConnectTimeout=10", "-oConnectionAttempts=1",
            "--", target]


def cleanup_pc3_payload(target: str, host_key_alias: str, path: str, digest: str) -> bool:
    remote = " ".join(shlex.quote(part) for part in
                      ["python3", "-c", payload_cleanup_code(), path, digest])
    try:
        result = subprocess.run(pc3_ssh_base(target, host_key_alias) + [remote], stdin=subprocess.DEVNULL,
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
              "target": args.target, "credential_host": args.credential_host,
              "credential_file": args.credential_file,
              "memory_mode": "managed" if args.managed_memory else "device",
              "managed_prefetch_requested": args.managed_prefetch,
              "cuda_graphs_requested": args.cuda_graphs,
              "gpu_id_info_capture_requested": args.gpu_id_info,
              "attached_ids_capture_requested": args.attached_ids,
              "probed_ids_capture_requested": args.probed_ids,
              "rm_control_capture_requested": args.rm_control,
              "channel_alloc_capture_requested": args.channel_alloc,
              "map_memory_capture_requested": args.map_memory,
              "rusd_alloc_capture_requested": args.rusd_alloc,
              "p2p_alloc_capture_requested": args.p2p_alloc,
              "p2p_control_capture_requested": args.p2p_control,
              "binapi_control_capture_requested": args.binapi_control,
              "device_alloc_capture_requested": args.device_alloc,
              "subdevice_alloc_capture_requested": args.subdevice_alloc,
              "binapi_alloc_capture_requested": args.binapi_alloc,
              "phase_capture_requested": args.phase is not None,
              "phase": args.phase,
              "credential_value_logged": False, "credential_value_persisted": False,
              "probe": identity(args.probe), "module": identity(args.module),
              "runner_source": identity(Path(__file__)),
              "remote_script_sha256": hashlib.sha256(REMOTE_ROOT_SCRIPT.encode()).hexdigest()}
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
            secret = fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
            payload = {"artifacts": {}}
            artifact_paths = {"probe": args.probe, "module": args.module}
            if args.ioctl_observer is not None:
                artifact_paths["observer"] = args.ioctl_observer
            if args.ioctl_trace:
                artifact_paths["trace-helper"] = ROOT / "tools/summarize_rm_ioctl_trace.py"
                payload["ioctl_trace"] = True
            report_keys = {"probe": "probe", "module": "module", "observer": "ioctl_observer",
                           "trace-helper": "ioctl_trace_helper"}
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
            payload["gpu_id_info_capture"] = args.gpu_id_info
            payload["attached_ids_capture"] = args.attached_ids
            payload["probed_ids_capture"] = args.probed_ids
            payload["rm_control_capture"] = args.rm_control
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
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            payload_digest = hashlib.sha256(payload_bytes).hexdigest()
            payload_path = payload_staging_path(uuid.uuid4().hex)
            report["payload_staging"] = {"path": payload_path, "bytes": len(payload_bytes),
                                         "sha256": payload_digest, "uploaded": False}
            upload_remote = " ".join(shlex.quote(part) for part in
                                     ["python3", "-c", payload_writer_code(), payload_path, payload_digest])
            try:
                uploaded = subprocess.run(pc3_ssh_base(args.target, args.host_key_alias) + [upload_remote],
                                          input=payload_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise RuntimeError("PC3 payload staging failed") from None
            if uploaded.returncode != 0:
                raise RuntimeError("PC3 payload staging failed")
            try:
                upload_receipt = json.loads(uploaded.stdout.decode("utf-8", "strict"))
            except (UnicodeDecodeError, ValueError):
                raise RuntimeError("PC3 payload staging receipt is invalid") from None
            if upload_receipt != {"bytes": len(payload_bytes), "sha256": payload_digest}:
                raise RuntimeError("PC3 payload staging receipt differs from the local payload")
            report["payload_staging"]["uploaded"] = True

            remote_command = ("sudo -S -p '' python3 -c " + shlex.quote(REMOTE_ROOT_SCRIPT) + " " +
                              shlex.quote(payload_path) + " " + shlex.quote(payload_digest))
            stdin = sudo_auth_stdin(secret)
            try:
                result = subprocess.run(pc3_ssh_base(args.target, args.host_key_alias) + [remote_command],
                                        input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=260, check=False)
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
                    report["pc3_stderr"] = redact_secret(result.stderr.decode("utf-8", "replace"), secret)
            report["payload_cleanup_passed"] = cleanup_pc3_payload(args.target, args.host_key_alias,
                                                                    payload_path, payload_digest)
            payload_cleanup_done = report["payload_cleanup_passed"] is True
            remote = report.get("remote")
            if isinstance(remote, dict) and isinstance(remote.get("probe"), dict):
                try:
                    artifact_paths = {"probe": args.probe, "module": args.module}
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
                        report["ioctl_trace_artifact"] = summary_module.write_trace_sidecar(
                            sidecar, compressed, trace_transport, trace_capture["summary"],
                            require_complete=False)
                    report_keys = {"probe": "probe", "module": "module", "observer": "ioctl_observer",
                                   "trace-helper": "ioctl_trace_helper"}
                    expected_artifacts = {name: report[report_keys[name]] for name in artifact_paths}
                    for name, path in artifact_paths.items():
                        current = identity(path)
                        report[report_keys[name] + "_after"] = current
                        if current != expected_artifacts[name]:
                            raise ValueError("local test artifact changed during execution")
                    qualification = validate_remote_acceptance(
                        remote, expected_artifacts, trace_requested=args.ioctl_trace,
                        managed_memory=args.managed_memory,
                        managed_prefetch=args.managed_prefetch,
                        cuda_graphs=args.cuda_graphs,
                        gpu_id_info_requested=args.gpu_id_info,
                        attached_ids_requested=args.attached_ids,
                        probed_ids_requested=args.probed_ids,
                        rm_control_requested=args.rm_control,
                        channel_alloc_requested=args.channel_alloc,
                        map_memory_requested=args.map_memory,
                        rusd_alloc_requested=args.rusd_alloc,
                        p2p_alloc_requested=args.p2p_alloc,
                        p2p_control_requested=args.p2p_control,
                        binapi_control_requested=args.binapi_control,
                        device_alloc_requested=args.device_alloc,
                        subdevice_alloc_requested=args.subdevice_alloc,
                        binapi_alloc_requested=args.binapi_alloc,
                        phase=args.phase)
                    if not report.get("payload_cleanup_passed"):
                        raise ValueError("PC3 payload cleanup could not be verified")
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
                                                                        payload_path, payload_digest)
                payload_cleanup_done = report["payload_cleanup_passed"] is True
            stdin = b""
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
