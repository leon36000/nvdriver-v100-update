#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare paired, redacted NV20_SUBDEVICE_0 allocations from PC3 references."""
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
PAYLOAD_FIELDS = ("classPayloadBytes", "subDeviceId")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_validator():
    path = ROOT / "tests/run_hybrid_acceptance.py"
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_nv2080_validator", path)
    require(spec is not None and spec.loader is not None,
            "shared subdevice-allocation validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_subdevice_alloc_observation


def canonical_pci(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(
        r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value),
        "capture has a malformed PCI address")
    parts = value.split(":")
    return f"{parts[0][-4:].lower()}:{parts[1].lower()}:{parts[2].lower()}"


def extract(report: object, branch: str) -> dict[str, object]:
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
        artifact = report.get("ioctl_observer")
        kernel = identity.get("kernel_release") if isinstance(identity, dict) else None
        driver = identity.get("driver_version") if isinstance(identity, dict) else None
        gpu_name, sm, pci = "Tesla V100-SXM2-16GB", 70, "0000:00:05.0"
        require(remote.get("phase") == "context" and
                remote.get("phase_capture_requested") is True and
                remote.get("subdevice_alloc_capture_requested") is True and
                remote.get("subdevice_alloc_records_seen") is True and
                remote.get("subdevice_alloc_payload_snapshots_read") == 2 and
                remote.get("probe_exit_code") == 0 and remote.get("observer_exit_code") == 0 and
                remote.get("guest_cleanup_passed") is True and
                remote.get("payload_file_cleanup_passed") is True and
                report.get("payload_cleanup_passed") is True,
                "V100 context, observer, or cleanup gates did not pass")
        require(isinstance(identity, dict) and identity.get("name") == gpu_name and
                driver == "580.178.04" and kernel == "6.8.0-147-generic",
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
        acceptance = remote.get("hardware_acceptance")
        envelope = acceptance.get("ioctl_observation") if isinstance(acceptance, dict) else None
        observer = envelope.get("report") if isinstance(envelope, dict) else None
        phase = remote.get("phase_report")
        artifact = report.get("local_artifacts", {}).get("observer")
        kernel = remote.get("kernel_release")
        driver = identity.get("driver") if isinstance(identity, dict) else None
        gpu_name, sm, pci = "NVIDIA GeForce RTX 5080", 120, "0000:02:00.0"
        require(remote.get("phase") == "context" and
                remote.get("phase_capture_requested") is True and
                remote.get("subdevice_alloc_capture_requested") is True and
                remote.get("subdevice_alloc_records_seen") is True and
                remote.get("subdevice_alloc_payload_snapshots_read") == 2,
                "RTX5080 context or observer gates did not pass")
        require(isinstance(identity, dict) and identity.get("name") == gpu_name and
                driver == "595.99.02" and isinstance(kernel, str) and kernel,
                "capture does not identify the installed RTX5080/R595 host")

    require(isinstance(observer, dict), f"{branch} redacted observer report is missing")
    require(isinstance(phase, dict) and phase.get("schema") == "nvidia-cuda-driver-phase-v1" and
            phase.get("status") == "phase-passed" and phase.get("phase") == "context" and
            phase.get("cleanup_passed") is True and phase.get("cleanup_errors") == [] and
            isinstance(phase.get("selected_device"), dict),
            f"{branch} CUDA context phase did not pass with cleanup")
    selected = phase["selected_device"]
    require(selected.get("name") == gpu_name and selected.get("sm") == sm and
            canonical_pci(selected.get("pci_bus_id")) == pci and
            canonical_pci(identity.get("pci")) == pci,
            f"{branch} context phase does not match the selected physical GPU")
    require(isinstance(artifact, dict) and re.fullmatch(
        r"[0-9a-f]{64}", str(artifact.get("sha256", ""))) is not None,
        f"{branch} report does not pin the observer binary")
    records_seen, snapshots = load_validator()(observer)
    rows = observer["records"]
    require(records_seen is True and snapshots == 2 and len(rows) == 1,
            f"{branch} context must contain exactly one successful subdevice allocation")
    row = rows[0]
    require(row.get("request") == 0xC030462B and row.get("packet_size") == 48 and
            row.get("syscall_return") == 0 and row["entry"].get("status") == 0 and
            row["exit"].get("status") == 0 and row["entry"] == row["exit"],
            f"{branch} subdevice allocation was not a stable successful NVOS64 request")
    payload = row["exit"].get("subdeviceAlloc")
    require(isinstance(payload, dict) and set(payload) == set(PAYLOAD_FIELDS),
            f"{branch} typed class payload has unexpected fields")
    return {
        "branch": branch, "gpu": gpu_name, "sm": sm, "driver": driver,
        "kernel_release": kernel, "pci": pci, "uuid": identity.get("uuid"),
        "observer_sha256": artifact["sha256"],
        "observation": {
            "request": f"0x{row['request']:08x}", "packet_size": row["packet_size"],
            "operation": row["operation"], "records": len(rows),
            "successful_status": row["exit"]["status"], "snapshots": snapshots,
            "outer_params_size": row["entry"]["paramsSize"],
            "entry_exit_stable": row["entry"] == row["exit"],
            "typed_payload": {name: payload[name] for name in PAYLOAD_FIELDS},
        },
    }


def compare_reports(v100_report: object, rtx_report: object) -> dict[str, object]:
    v100, rtx = extract(v100_report, "v100"), extract(rtx_report, "rtx5080")
    left, right = v100["observation"]["typed_payload"], rtx["observation"]["typed_payload"]
    fields = [("outerParamsSize", v100["observation"]["outer_params_size"],
               rtx["observation"]["outer_params_size"])]
    fields.extend((name, left[name], right[name]) for name in PAYLOAD_FIELDS)
    differences = [{"field": name, "v100": value_left, "rtx5080": value_right}
                   for name, value_left, value_right in fields if value_left != value_right]
    return {
        "schema": "nvidia-hybrid-nv2080-subdevice-allocation-comparison-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "paired-sanitized-installed-driver-observations-compared",
        "references": {"v100": v100, "rtx5080": rtx},
        "observer_binary_match": v100["observer_sha256"] == rtx["observer_sha256"],
        "allocation_fields_match": not differences,
        "allocation_field_differences": differences,
        "same_kernel_hybrid_validated": False,
        "conclusion": ("Both isolated stock-driver phases emitted the same NV2080 subDeviceId fields."
                       if not differences else
                       "The isolated stock-driver phases emitted differing NV2080 class fields."),
        "limits": [
            "The references ran on separate Linux kernels and separate installed NVIDIA driver branches.",
            "The capture observes one NV20_SUBDEVICE_0 construction, not the complete RM object graph.",
            "Matching request shape does not validate either experimental backend or class dispatch.",
            "This does not validate one libcuda, same-process dual-GPU enumeration, kernel execution, UVM, P2P, or hybrid operation.",
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
    v100_path, rtx_path = args.v100.resolve(strict=True), args.rtx5080.resolve(strict=True)
    output = args.output.resolve()
    if v100_path == rtx_path or output in (v100_path, rtx_path):
        parser.error("input and output paths must be distinct")
    try:
        result = compare_reports(json.loads(v100_path.read_text(encoding="utf-8")),
                                 json.loads(rtx_path.read_text(encoding="utf-8")))
        result["references"]["v100"].update(
            {"report_sha256": sha256_file(v100_path), "report_path": str(v100_path)})
        result["references"]["rtx5080"].update(
            {"report_sha256": sha256_file(rtx_path), "report_path": str(rtx_path)})
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
                      "observer_binary_match": result["observer_binary_match"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
