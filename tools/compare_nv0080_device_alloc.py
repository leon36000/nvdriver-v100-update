#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare paired, redacted NV01_DEVICE_0 allocations from the PC3 references."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_FIELDS = (
    "classPayloadBytes", "deviceId", "hClientShare", "targetClientZero",
    "targetDeviceZero", "flags", "vaSpaceSize", "vaStartInternalZero",
    "vaLimitInternalZero", "vaMode",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_shared_validator():
    path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_nv0080_validator", path)
    require(spec is not None and spec.loader is not None,
            "shared device-allocation validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_device_alloc_observation


def _canonical_pci(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(
        r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value),
        "capture has a malformed PCI address")
    parts = value.split(":")
    domain = parts[0][-4:]
    return f"{domain}:{parts[1].lower()}:{parts[2].lower()}"


def _extract(report: object, branch: str) -> dict[str, object]:
    require(isinstance(report, dict) and isinstance(report.get("remote"), dict),
            f"{branch} transport report is malformed")
    remote = report["remote"]
    if branch == "v100":
        require(report.get("schema") == "nvidia-hybrid-pc3-v100-reference-transport-v1" and
                report.get("target") == "pc3@pc3" and
                report.get("qualification") == "v100-cuda-phase-report-contract-valid" and
                remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1" and
                remote.get("qualification") == "v100-cuda-phase-report-contract-valid",
                "V100 report is not a qualified isolated guest phase")
        identity = remote.get("guest")
        observer = remote.get("ioctl_observation")
        phase = remote.get("probe")
        observer_artifact = report.get("ioctl_observer")
        kernel = identity.get("kernel_release") if isinstance(identity, dict) else None
        driver = identity.get("driver_version") if isinstance(identity, dict) else None
        expected_name = "Tesla V100-SXM2-16GB"
        expected_sm = 70
        expected_pci = "0000:00:05.0"
        require(remote.get("phase") == "context" and
                remote.get("phase_capture_requested") is True and
                remote.get("device_alloc_capture_requested") is True and
                remote.get("device_alloc_records_seen") is True and
                remote.get("device_alloc_payload_snapshots_read") == 2 and
                remote.get("probe_exit_code") == 0 and remote.get("observer_exit_code") == 0 and
                remote.get("guest_cleanup_passed") is True and
                remote.get("payload_file_cleanup_passed") is True and
                report.get("payload_cleanup_passed") is True,
                "V100 phase, observer, or cleanup gates did not pass")
        require(isinstance(identity, dict) and identity.get("name") == expected_name and
                driver == "580.178.04" and isinstance(kernel, str) and kernel,
                "capture does not identify the installed V100/R580 guest")
    else:
        require(report.get("schema") == "nvidia-hybrid-remote-selected-gpu-transport-v1" and
                report.get("exit_code") == 0 and report.get("ssh_exit_code") == 0 and
                report.get("target") == "pc3@pc3" and report.get("host_key_alias") == "pc3" and
                remote.get("schema") == "nvidia-hybrid-remote-selected-gpu-v1" and
                remote.get("qualification") == "rtx5080-cuda-phase-report-contract-valid" and
                remote.get("exit_code") == 0,
                "RTX5080 report is not a qualified isolated PC3 phase")
        identity = remote.get("selected_nvidia_smi")
        hardware = remote.get("hardware_acceptance")
        observer_envelope = (hardware.get("ioctl_observation")
                             if isinstance(hardware, dict) else None)
        observer = (observer_envelope.get("report")
                    if isinstance(observer_envelope, dict) else None)
        phase = remote.get("phase_report")
        observer_artifact = report.get("local_artifacts", {}).get("observer")
        kernel = remote.get("kernel_release")
        driver = identity.get("driver") if isinstance(identity, dict) else None
        expected_name = "NVIDIA GeForce RTX 5080"
        expected_sm = 120
        expected_pci = "0000:02:00.0"
        require(remote.get("phase") == "context" and
                remote.get("phase_capture_requested") is True and
                remote.get("device_alloc_capture_requested") is True and
                remote.get("device_alloc_records_seen") is True and
                remote.get("device_alloc_payload_snapshots_read") == 2,
                "RTX5080 phase or observer gates did not pass")
        require(isinstance(identity, dict) and identity.get("name") == expected_name and
                driver == "595.99.02" and isinstance(kernel, str) and kernel,
                "capture does not identify the installed RTX5080/R595 host")

    require(isinstance(observer, dict), f"{branch} redacted observer report is missing")
    require(isinstance(phase, dict) and phase.get("schema") == "nvidia-cuda-driver-phase-v1" and
            phase.get("status") == "phase-passed" and phase.get("phase") == "context" and
            phase.get("cleanup_passed") is True and phase.get("cleanup_errors") == [] and
            isinstance(phase.get("selected_device"), dict),
            f"{branch} CUDA context phase did not pass with cleanup")
    selected = phase["selected_device"]
    require(selected.get("name") == expected_name and selected.get("sm") == expected_sm and
            _canonical_pci(selected.get("pci_bus_id")) == expected_pci and
            _canonical_pci(identity.get("pci")) == expected_pci,
            f"{branch} context phase does not match the selected physical GPU")
    require(isinstance(observer_artifact, dict) and
            re.fullmatch(r"[0-9a-f]{64}", str(observer_artifact.get("sha256", ""))) is not None,
            f"{branch} report does not pin the observer binary")

    validator = _load_shared_validator()
    records_seen, snapshots = validator(observer)
    records = observer["records"]
    require(records_seen is True and snapshots == 2 and len(records) == 1,
            f"{branch} context must contain exactly one successful device allocation")
    row = records[0]
    require(row.get("request") == 0xC030462B and row.get("packet_size") == 48 and
            row.get("syscall_return") == 0 and
            row["entry"].get("status") == 0 and row["exit"].get("status") == 0 and
            row["entry"] == row["exit"],
            f"{branch} device allocation was not a stable successful NVOS64 request")
    payload = row["exit"].get("deviceAlloc")
    require(isinstance(payload, dict) and set(payload) == set(PAYLOAD_FIELDS),
            f"{branch} typed payload has unexpected fields")
    return {
        "branch": branch,
        "gpu": identity["name"],
        "sm": expected_sm,
        "driver": driver,
        "kernel_release": kernel,
        "pci": expected_pci,
        "uuid": identity.get("uuid"),
        "observer_sha256": observer_artifact["sha256"],
        "observation": {
            "request": f"0x{row['request']:08x}",
            "packet_size": row["packet_size"],
            "operation": row["operation"],
            "records": len(records),
            "successful_status": row["exit"]["status"],
            "snapshots": snapshots,
            "outer_params_size": row["entry"]["paramsSize"],
            "entry_exit_stable": row["entry"] == row["exit"],
            "typed_payload": {name: payload[name] for name in PAYLOAD_FIELDS},
        },
    }


def compare_reports(v100_report: object, rtx_report: object) -> dict[str, object]:
    v100 = _extract(v100_report, "v100")
    rtx = _extract(rtx_report, "rtx5080")
    left = v100["observation"]["typed_payload"]
    right = rtx["observation"]["typed_payload"]
    left_fields = [("outerParamsSize", v100["observation"]["outer_params_size"])] + [
        (name, left[name]) for name in PAYLOAD_FIELDS]
    right_fields = [("outerParamsSize", rtx["observation"]["outer_params_size"])] + [
        (name, right[name]) for name in PAYLOAD_FIELDS]
    differences = [
        {"field": name_left, "v100": value_left, "rtx5080": value_right}
        for (name_left, value_left), (name_right, value_right)
        in zip(left_fields, right_fields, strict=True)
        if name_left != name_right or value_left != value_right
    ]
    return {
        "schema": "nvidia-hybrid-nv0080-device-allocation-comparison-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "paired-sanitized-installed-driver-observations-compared",
        "references": {
            "v100": dict(v100),
            "rtx5080": dict(rtx),
        },
        "observer_binary_match": v100["observer_sha256"] == rtx["observer_sha256"],
        "allocation_fields_match": not differences,
        "allocation_field_differences": differences,
        "same_kernel_hybrid_validated": False,
        "conclusion": (
            "The two isolated stock-driver context phases emitted the same observed fixed "
            "NV01_DEVICE_0 allocation fields." if not differences else
            "The isolated stock-driver context phases emitted differing typed allocation fields."
        ),
        "limits": [
            "The references ran on separate Linux kernels and separate installed NVIDIA driver branches.",
            "This compares one ordinary CUDA context-creation allocation per GPU, not the complete RM object graph.",
            "Matching request shape and fields do not establish that either experimental backend executes the allocation.",
            "This report does not validate a shared libcuda, same-process dual-GPU enumeration, kernel execution, UVM, P2P, or hybrid operation.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v100", type=Path, required=True)
    parser.add_argument("--rtx5080", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output already exists")
    v100_path = args.v100.resolve(strict=True)
    rtx_path = args.rtx5080.resolve(strict=True)
    output = args.output.resolve()
    if v100_path == rtx_path or output in (v100_path, rtx_path):
        parser.error("input and output paths must be distinct")
    try:
        v100_report = json.loads(v100_path.read_text(encoding="utf-8"))
        rtx_report = json.loads(rtx_path.read_text(encoding="utf-8"))
        result = compare_reports(v100_report, rtx_report)
        result["references"]["v100"]["report_sha256"] = sha256_file(v100_path)
        result["references"]["v100"]["report_path"] = str(v100_path)
        result["references"]["rtx5080"]["report_sha256"] = sha256_file(rtx_path)
        result["references"]["rtx5080"]["report_path"] = str(rtx_path)
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps({"output": str(output), "sha256": hashlib.sha256(encoded).hexdigest(),
        "allocation_fields_match": result["allocation_fields_match"],
                      "observer_binary_match": result["observer_binary_match"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
