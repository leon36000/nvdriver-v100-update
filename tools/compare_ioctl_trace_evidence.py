#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify and compare metadata-only PC3 RTX 5080 and V100 ioctl captures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

if __package__:
    from . import summarize_rm_ioctl_trace as trace_tool
else:
    import summarize_rm_ioctl_trace as trace_tool


RTX_REPORT_SCHEMA = "nvidia-hybrid-remote-selected-gpu-transport-v1"
V100_REPORT_SCHEMA = "nvidia-hybrid-pc3-v100-reference-transport-v1"
SCOPE = ("ioctl request metadata only; syscall arguments, pointed memory, RM payload status, "
         "file-object identity, UVM migration, and hybrid compatibility are not established")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _call_sequence(summary: dict[str, Any]) -> list[tuple[str, str, int]]:
    return [(call["node"], call["request"], call["syscall_return"])
            for call in summary["calls"]]


def _public_call(call: tuple[str, str, int]) -> dict[str, Any]:
    """Expose only the fields already admitted by the pointer-free comparison."""
    return {"node": call[0], "request": call[1], "syscall_return": call[2]}


def _request_occurrences(sequence: list[tuple[str, str, int]],
                         request: str) -> list[dict[str, Any]]:
    """Return one-based positions and adjacent ioctl metadata, never arguments."""
    occurrences = []
    for index, call in enumerate(sequence):
        if call[1] != request:
            continue
        occurrences.append({
            "call_index": index + 1,
            "call": _public_call(call),
            "previous": _public_call(sequence[index - 1]) if index else None,
            "next": _public_call(sequence[index + 1])
                    if index + 1 < len(sequence) else None,
        })
    return occurrences


def _sequence_window(sequence: list[tuple[str, str, int]], center: int,
                     radius: int = 2) -> list[dict[str, Any]]:
    """Return a bounded, pointer-free context around a zero-based index."""
    start = max(0, center - radius)
    end = min(len(sequence), center + radius + 1)
    return [{"call_index": index + 1, **_public_call(sequence[index])}
            for index in range(start, end)]


def _trace_fields(report: dict[str, Any], role: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    remote = report.get("remote")
    if not isinstance(remote, dict):
        raise ValueError(f"{role}: remote report object is missing")
    if role == "rtx5080":
        if report.get("schema") != RTX_REPORT_SCHEMA:
            raise ValueError("RTX input has an unsupported report schema")
        acceptance = remote.get("hardware_acceptance")
        if not isinstance(acceptance, dict):
            raise ValueError("RTX hardware-acceptance record is missing")
        if remote.get("qualification") != "rtx5080-report-contract-valid-hybrid-incomplete":
            raise ValueError("RTX installed-driver reference did not validate")
        probe = acceptance.get("probe")
        device = remote.get("selected_nvidia_smi")
        trace = acceptance.get("ioctl_trace")
        artifact = remote.get("ioctl_trace_artifact")
        if (acceptance.get("qualification") != "incomplete-hardware-missing" or
                not isinstance(probe, dict) or probe.get("missing_sm") != [70] or
                probe.get("hybrid_validated") is not False or
                not isinstance(device, dict) or device.get("name") != "NVIDIA GeForce RTX 5080"):
            raise ValueError("RTX record is not the expected single-generation reference")
        identity = {
            "gpu": device["name"], "uuid": device.get("uuid"), "pci": device.get("pci"),
            "driver": device.get("driver"), "kernel": acceptance.get("kernel_release"),
            "driver_api": probe.get("driver_api"),
            "qualification": remote["qualification"],
        }
    elif role == "v100":
        if report.get("schema") != V100_REPORT_SCHEMA or report.get("qualification") != "v100-reference-report-contract-valid":
            raise ValueError("V100 input is not a validated installed-driver reference")
        probe = remote.get("probe")
        device = remote.get("guest")
        trace = remote.get("ioctl_trace")
        artifact = report.get("ioctl_trace_artifact")
        if (remote.get("qualification") != "v100-reference-report-contract-valid" or
                not isinstance(probe, dict) or probe.get("hybrid_validated") is not False or
                not isinstance(device, dict) or not str(device.get("name", "")).startswith("Tesla V100")):
            raise ValueError("V100 record is not the expected V100-only reference")
        identity = {
            "gpu": device["name"], "uuid": device.get("uuid"), "pci": device.get("pci"),
            "driver": device.get("driver_version"), "kernel": device.get("kernel_release"),
            "driver_api": probe.get("driver_api"),
            "qualification": remote["qualification"],
        }
    else:
        raise ValueError("unsupported trace role")

    if not isinstance(trace, dict) or not isinstance(trace.get("trace"), dict):
        raise ValueError(f"{role}: trace metadata is missing")
    if not isinstance(artifact, dict):
        raise ValueError(f"{role}: verified local sidecar metadata is missing")
    return trace, artifact, identity


def _load_verified(path: Path, role: str) -> dict[str, Any]:
    report_path = path.resolve(strict=True)
    raw_report = report_path.read_bytes()
    report = json.loads(raw_report)
    if not isinstance(report, dict):
        raise ValueError(f"{role}: report root must be an object")
    trace, artifact, identity = _trace_fields(report, role)
    capture = trace["trace"]
    summary = capture.get("summary")
    if (capture.get("trace_complete") is not True or capture.get("size_limit_exceeded") is not False or
            not isinstance(summary, dict) or summary.get("trace_complete") is not True or
            summary.get("schema") != "nvidia-hybrid-ioctl-metadata-summary-v2"):
        raise ValueError(f"{role}: trace is incomplete or has an unsupported summary")

    sidecar = report_path.with_suffix(report_path.suffix + ".strace.gz")
    if artifact.get("path") != str(sidecar):
        raise ValueError(f"{role}: sidecar path does not match the evidence report")
    sidecar_stat = sidecar.lstat()
    if (not stat.S_ISREG(sidecar_stat.st_mode) or sidecar_stat.st_uid != os.geteuid() or
            stat.S_IMODE(sidecar_stat.st_mode) != 0o600):
        raise ValueError(f"{role}: sidecar must be a caller-owned regular file with mode 0600")
    compressed = sidecar.read_bytes()
    if (artifact.get("compressed_bytes") != len(compressed) or
            artifact.get("compressed_sha256") != _sha256(compressed)):
        raise ValueError(f"{role}: compressed sidecar identity mismatch")
    raw = trace_tool.inflate_gzip_trace(compressed)
    if (artifact.get("raw_bytes") != len(raw) or artifact.get("raw_sha256") != _sha256(raw) or
            capture.get("bytes") != len(raw) or capture.get("sha256") != _sha256(raw)):
        raise ValueError(f"{role}: raw trace identity mismatch")
    recomputed = trace_tool.summarize(raw)
    if recomputed != summary or artifact.get("summary") != recomputed:
        raise ValueError(f"{role}: local trace summary differs from captured metadata")
    identity.update({
        "report_path": str(report_path), "report_sha256": _sha256(raw_report),
        "sidecar_path": str(sidecar), "sidecar_sha256": _sha256(compressed),
        "trace_sha256": _sha256(raw), "trace_bytes": len(raw),
        "strace_version": str(trace.get("strace_version", "")).splitlines()[0],
        "call_count": recomputed["parsed_calls"],
        "node_call_counts": {
            node: sum(1 for call in recomputed["calls"] if call["node"] == node)
            for node in sorted({call["node"] for call in recomputed["calls"]})
        },
        "request_counts": recomputed["requests"],
        "negative_syscall_returns": recomputed["negative_syscall_returns"],
        "unparsed_line_count": len(recomputed["unparsed_lines"]),
        "uvm_ioctl_call_count": sum(1 for call in recomputed["calls"]
                                     if call["node"] == "/dev/nvidia-uvm"),
        "rm_alloc_request_count": sum(1 for call in recomputed["calls"]
                                       if call["request"] == "0xc030462b"),
        "rm_alloc_packet_sizes": recomputed["rm_alloc_packet_sizes"],
        "uvm_workload_validated": False,
    })
    return {"identity": identity, "summary": recomputed,
            "sequence": _call_sequence(recomputed)}


def build_comparison(rtx_report: str | Path, v100_report: str | Path) -> dict[str, Any]:
    """Verify both reports/sidecars and return aggregate, pointer-free comparison data."""
    rtx = _load_verified(Path(rtx_report), "rtx5080")
    v100 = _load_verified(Path(v100_report), "v100")
    left, right = rtx["sequence"], v100["sequence"]
    common = 0
    for left_call, right_call in zip(left, right):
        if left_call != right_call:
            break
        common += 1
    first = None
    if common < max(len(left), len(right)):
        first = {
            "zero_based_index": common,
            "rtx5080_call": list(left[common]) if common < len(left) else None,
            "v100_call": list(right[common]) if common < len(right) else None,
        }
    divergence_context = None
    if first is not None:
        divergence_context = {
            "radius": 2,
            "rtx5080": _sequence_window(left, common),
            "v100": _sequence_window(right, common),
        }
    rtx_counts = {(item["node"], item["request"]): item["count"]
                  for item in rtx["summary"]["requests"]}
    v100_counts = {(item["node"], item["request"]): item["count"]
                   for item in v100["summary"]["requests"]}
    deltas = []
    for node, request in sorted(set(rtx_counts) | set(v100_counts)):
        a, b = rtx_counts.get((node, request), 0), v100_counts.get((node, request), 0)
        if a != b:
            deltas.append({"node": node, "request": request,
                           "rtx_count": a, "v100_count": b, "v100_minus_rtx": b - a})
    return {
        "schema": "nvidia-hybrid-installed-driver-ioctl-comparison-v1",
        "qualification": "verified-metadata-comparison-only",
        "scope": SCOPE,
        "inputs": {"rtx5080": rtx["identity"], "v100": v100["identity"]},
        "comparison": {
            "call_counts_equal": len(left) == len(right),
            "rtx5080_call_count": len(left), "v100_call_count": len(right),
            "sequence": {"common_prefix_calls": common,
                         "first_divergence": first,
                         "first_divergence_context": divergence_context,
                         "register_fd_occurrences": {
                             "request": "0xc00446c9",
                             "arguments_or_file_identity_compared": False,
                             "rtx5080": _request_occurrences(left, "0xc00446c9"),
                             "v100": _request_occurrences(right, "0xc00446c9"),
                         },
                         "pid_file_descriptor_and_pointer_values_compared": False},
            "request_count_deltas": deltas,
            "rm_alloc_ioctl": {"request": "0xc030462b",
                               "rtx5080_count": rtx["identity"]["rm_alloc_request_count"],
                               "v100_count": v100["identity"]["rm_alloc_request_count"]},
            "uvm_ioctl_calls": {"rtx5080": rtx["identity"]["uvm_ioctl_call_count"],
                                "v100": v100["identity"]["uvm_ioctl_call_count"]},
            "payload_status_observed": False,
            "uvm_workload_validated": False,
            "same_linux_or_cross_backend_compatibility_validated": False,
        },
        "tool": {"path": str(Path(__file__).resolve()),
                 "sha256": _sha256(Path(__file__).read_bytes())},
    }


def write_comparison(rtx_report: str | Path, v100_report: str | Path,
                     output: str | Path) -> dict[str, Any]:
    report = build_comparison(rtx_report, v100_report)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtx-report", type=Path, required=True)
    parser.add_argument("--v100-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("comparison output already exists")
    try:
        report = write_comparison(args.rtx_report, args.v100_report, args.output)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({"output": str(args.output),
                      "qualification": report["qualification"],
                      "rtx5080_calls": report["comparison"]["rtx5080_call_count"],
                      "v100_calls": report["comparison"]["v100_call_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
