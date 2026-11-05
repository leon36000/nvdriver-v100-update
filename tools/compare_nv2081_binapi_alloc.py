#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare paired, redacted NV2081_BINAPI allocations from PC3 references."""
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
    spec = importlib.util.spec_from_file_location("hybrid_acceptance_binapi_validator", path)
    require(spec is not None and spec.loader is not None,
            "shared BINAPI allocation validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_binapi_alloc_observation


def canonical_pci(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(
        r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value),
        "capture has a malformed PCI address")
    parts = value.split(":")
    return f"{parts[0][-4:].lower()}:{parts[1].lower()}:{parts[2].lower()}"


def observer_hash(artifact: object, branch: str) -> str:
    require(isinstance(artifact, dict) and re.fullmatch(
        r"[0-9a-f]{64}", str(artifact.get("sha256", ""))) is not None,
        f"{branch} report does not pin the observer binary hash")
    size = artifact.get("bytes")
    require(isinstance(size, int) and not isinstance(size, bool) and size > 0,
            f"{branch} report does not pin the observer binary size")
    return artifact["sha256"]


def capture_report_hash(artifact: object, branch: str) -> str:
    require(isinstance(artifact, dict) and re.fullmatch(
        r"[0-9a-f]{64}", str(artifact.get("sha256", ""))) is not None and
        isinstance(artifact.get("bytes"), int) and not isinstance(artifact.get("bytes"), bool) and
        artifact["bytes"] > 0,
        f"{branch} observer capture report artifact is malformed")
    return artifact["sha256"]


def extract(report: object, branch: str) -> dict[str, object]:
    require(isinstance(report, dict) and isinstance(report.get("remote"), dict),
            f"{branch} transport report is malformed")
    remote = report["remote"]

    if branch == "v100":
        require(report.get("schema") == "nvidia-hybrid-pc3-v100-reference-transport-v1" and
                report.get("target") == "pc3@pc3" and report.get("phase") == "context" and
                report.get("exit_code") == 0 and
                report.get("qualification") == "v100-cuda-phase-report-contract-valid" and
                report.get("payload_cleanup_passed") is True and
                remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1" and
                remote.get("qualification") == "v100-cuda-phase-report-contract-valid",
                "V100 report is not a qualified isolated guest context phase")
        identity = remote.get("guest")
        observer = remote.get("ioctl_observation")
        phase = remote.get("probe")
        artifact = report.get("ioctl_observer")
        driver = identity.get("driver_version") if isinstance(identity, dict) else None
        kernel = identity.get("kernel_release") if isinstance(identity, dict) else None
        gpu_name, sm, pci = "Tesla V100-SXM2-16GB", 70, "0000:00:05.0"
        require(remote.get("phase") == "context" and
                remote.get("phase_capture_requested") is True and
                remote.get("binapi_alloc_capture_requested") is True and
                remote.get("binapi_alloc_records_seen") is True and
                remote.get("probe_exit_code") == 0 and remote.get("observer_exit_code") == 0 and
                remote.get("guest_cleanup_passed") is True and
                remote.get("payload_file_cleanup_passed") is True,
                "V100 context, observer, or cleanup gates did not pass")
        require(isinstance(identity, dict) and identity.get("name") == gpu_name and
                driver == "580.178.04" and kernel == "6.8.0-147-generic",
                "capture does not identify the installed V100/R580 guest")
        records_seen = remote.get("binapi_alloc_records_seen")
        reported_snapshots = remote.get("binapi_alloc_payload_snapshots_read")
        artifact_envelope = None
    elif branch == "rtx5080":
        require(report.get("schema") == "nvidia-hybrid-remote-selected-gpu-transport-v1" and
                report.get("exit_code") == 0 and report.get("ssh_exit_code") == 0 and
                report.get("target") == "pc3@pc3" and report.get("host_key_alias") == "pc3" and
                remote.get("schema") == "nvidia-hybrid-remote-selected-gpu-v1" and
                remote.get("qualification") == "rtx5080-cuda-phase-report-contract-valid" and
                remote.get("exit_code") == 0,
                "RTX5080 report is not a qualified isolated PC3 context phase")
        identity = remote.get("selected_nvidia_smi")
        acceptance = remote.get("hardware_acceptance")
        envelope = acceptance.get("ioctl_observation") if isinstance(acceptance, dict) else None
        observer = envelope.get("report") if isinstance(envelope, dict) else None
        phase = acceptance.get("probe") if isinstance(acceptance, dict) else None
        local_artifact = report.get("local_artifacts", {}).get("observer")
        artifact_envelope = envelope.get("artifact") if isinstance(envelope, dict) else None
        driver = identity.get("driver") if isinstance(identity, dict) else None
        kernel = remote.get("kernel_release")
        gpu_name, sm, pci = "NVIDIA GeForce RTX 5080", 120, "0000:02:00.0"
        require(remote.get("phase") == "context" and
                remote.get("phase_capture_requested") is True and
                remote.get("binapi_alloc_capture_requested") is True and
                remote.get("binapi_alloc_records_seen") is True and
                isinstance(acceptance, dict) and acceptance.get("phase") == "context" and
                acceptance.get("exit_code") == 0,
                "RTX5080 context or observer gates did not pass")
        require(isinstance(identity, dict) and identity.get("name") == gpu_name and
                driver == "595.99.02" and isinstance(kernel, str) and kernel,
                "capture does not identify the installed RTX5080/R595 host")
        observer_hash(local_artifact, branch)
        trace_artifact_sha = capture_report_hash(artifact_envelope, branch)
        records_seen = remote.get("binapi_alloc_records_seen")
        reported_snapshots = remote.get("binapi_alloc_payload_snapshots_read")
        artifact = local_artifact
    else:
        raise ValueError("branch must be v100 or rtx5080")

    require(isinstance(observer, dict), f"{branch} redacted observer report is missing")
    require(isinstance(phase, dict) and phase.get("schema") == "nvidia-cuda-driver-phase-v1" and
            phase.get("status") == "phase-passed" and phase.get("phase") == "context" and
            phase.get("cleanup_passed") is True and phase.get("cleanup_errors") == [] and
            isinstance(phase.get("selected_device"), dict),
            f"{branch} CUDA context phase did not pass with cleanup")
    selected = phase["selected_device"]
    require(selected.get("name") == gpu_name and selected.get("sm") == sm and
            canonical_pci(selected.get("pci_bus_id")) == pci and
            canonical_pci(identity.get("pci") if branch == "rtx5080" else selected.get("pci_bus_id")) == pci,
            f"{branch} context phase does not match the selected physical GPU")
    artifact_sha = observer_hash(artifact, branch)
    require(observer.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v21" and
            observer.get("trace_complete") is True and observer.get("child_exit_code") == 0 and
            observer.get("errors") == [],
            f"{branch} observer trace is incomplete or has errors")
    require(reported_snapshots in (0, 2) and observer.get(
        "binapi_alloc_payload_snapshots_read") == reported_snapshots,
        f"{branch} observer snapshot counters disagree")
    records_seen_by_validator, snapshots = load_validator()(observer)
    records = [row for row in observer["records"] if row.get("operation") == "binapi_alloc"]
    require(records_seen is True and records_seen_by_validator is True and
            snapshots == reported_snapshots and len(records) == 1 and
            len(observer["records"]) == 1,
            f"{branch} context must contain exactly one validated BINAPI allocation")
    row = records[0]
    require(row.get("request") == 0xC030462B and row.get("packet_size") == 48 and
            row.get("syscall_return") == 0 and row["entry"].get("status") == 0 and
            row["exit"].get("status") == 0 and row["entry"] == row["exit"],
            f"{branch} BINAPI allocation was not a stable successful NVOS64 request")
    payload_present = row["exit"].get("pAllocParmsPresent") is True
    outer_params_size = row["entry"].get("paramsSize")
    payload = row["exit"].get("binapiAlloc")
    require((payload_present and isinstance(payload, dict)) or
            (not payload_present and payload is None),
            f"{branch} optional BINAPI allocation payload has inconsistent presence")
    typed_payload = None if payload is None else {
        "classPayloadBytes": payload["classPayloadBytes"],
        "reservedZero": payload["reservedZero"],
    }
    return {
        "branch": branch, "gpu": gpu_name, "sm": sm, "driver": driver,
        "kernel_release": kernel, "pci": pci,
        "observer_sha256": artifact_sha,
        "capture_report_sha256": trace_artifact_sha if branch == "rtx5080" else None,
        "observation": {
            "operation": "binapi_alloc", "records": 1,
            "successful_status": row["exit"]["status"],
            "payload_snapshots": snapshots, "entry_exit_stable": True,
            "outer_params_size": outer_params_size,
            "allocation_parameters_present": payload_present,
            "typed_payload": typed_payload,
        },
    }


def compare_reports(v100_report: object, rtx_report: object) -> dict[str, object]:
    v100, rtx = extract(v100_report, "v100"), extract(rtx_report, "rtx5080")
    left = v100["observation"]
    right = rtx["observation"]
    fields: list[tuple[str, object, object]] = [
        ("allocation_parameters_present", left["allocation_parameters_present"],
         right["allocation_parameters_present"]),
        ("outerParamsSize", left["outer_params_size"], right["outer_params_size"]),
    ]
    if left["typed_payload"] is not None and right["typed_payload"] is not None:
        fields.extend((name, left["typed_payload"][name], right["typed_payload"][name])
                      for name in ("classPayloadBytes", "reservedZero"))
    differences = [{"field": name, "v100": value_left, "rtx5080": value_right}
                   for name, value_left, value_right in fields if value_left != value_right]
    return {
        "schema": "nvidia-hybrid-nv2081-binapi-allocation-comparison-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "paired-sanitized-installed-driver-observations-compared",
        "references": {"v100": v100, "rtx5080": rtx},
        "observer_binary_match": v100["observer_sha256"] == rtx["observer_sha256"],
        "allocation_fields_match": not differences,
        "allocation_field_differences": differences,
        "same_kernel_hybrid_validated": False,
        "conclusion": (
            "The isolated stock-driver context phases emitted the same redacted NV2081 allocation fields."
            if not differences else
            "The isolated stock-driver context phases emitted different redacted NV2081 allocation fields."),
        "limits": [
            "The V100 guest and RTX5080 host ran on separate Linux kernels with separate installed driver branches.",
            "The observer saw one NV2081_BINAPI allocation per context phase; it did not validate the full RM object graph.",
            "Matching allocation fields do not establish Resource Manager ABI or backend compatibility.",
            "This does not validate same-process dual-GPU enumeration, an experimental module, UVM, P2P, or hybrid operation.",
        ],
    }


def run(v100_path: Path, rtx_path: Path, output: Path) -> dict[str, object]:
    require(not output.exists(), "refusing to overwrite comparison output")
    v100_resolved, rtx_resolved, output_resolved = (
        v100_path.resolve(strict=True), rtx_path.resolve(strict=True), output.resolve())
    require(v100_resolved != rtx_resolved and output_resolved not in (v100_resolved, rtx_resolved),
            "input and output paths must be distinct")
    result = compare_reports(json.loads(v100_resolved.read_text(encoding="utf-8")),
                             json.loads(rtx_resolved.read_text(encoding="utf-8")))
    result["inputs"] = {
        "v100": {"sha256": sha256_file(v100_resolved), "path": str(v100_resolved)},
        "rtx5080": {"sha256": sha256_file(rtx_resolved), "path": str(rtx_resolved)},
    }
    result["tool"] = {"sha256": sha256_file(Path(__file__).resolve())}
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(output_resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v100", type=Path, required=True)
    parser.add_argument("--rtx5080", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = run(args.v100, args.rtx5080, args.output)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({
        "schema": result["schema"], "qualification": result["qualification"],
        "observer_binary_match": result["observer_binary_match"],
        "allocation_fields_match": result["allocation_fields_match"],
        "same_kernel_hybrid_validated": result["same_kernel_hybrid_validated"],
        "output": str(args.output.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
