#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify and compare redacted CUDA enumeration node-lifecycle captures."""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRACE_PATH = ROOT / "tools/summarize_rm_ioctl_trace.py"
_trace_spec = importlib.util.spec_from_file_location("cuda_node_trace_helper", TRACE_PATH)
if _trace_spec is None or _trace_spec.loader is None:
    raise RuntimeError("CUDA node trace helper is unavailable")
TRACE = importlib.util.module_from_spec(_trace_spec)
_trace_spec.loader.exec_module(TRACE)

RTX_SCHEMA = "nvidia-hybrid-remote-selected-gpu-transport-v1"
V100_SCHEMA = "nvidia-hybrid-pc3-v100-reference-transport-v1"
PHASE_SCHEMA = "nvidia-cuda-driver-phase-v1"
MAX_REPORT_BYTES = 16 * 1024 * 1024


def _read_private_regular(path: Path, max_bytes: int) -> bytes:
    """Read a private regular file through a no-follow descriptor, with a hard bound."""
    absolute = Path(os.path.abspath(path))
    current = absolute
    while current != current.parent:
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValueError("source path contains a symlink")
        except FileNotFoundError:
            raise ValueError("source file or parent is missing") from None
        current = current.parent
    before = absolute.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("source report and trace sidecar must be regular private mode-0600 files")
    if before.st_size < 1 or before.st_size > max_bytes:
        raise ValueError("source file is empty or exceeds its size limit")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ValueError("cannot open private evidence file safely") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev or
                opened.st_ino != before.st_ino or stat.S_IMODE(opened.st_mode) != 0o600):
            raise ValueError("evidence file changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise ValueError("evidence file exceeds its size limit")
            chunks.append(block)
        after = os.fstat(descriptor)
        if (after.st_dev != opened.st_dev or after.st_ino != opened.st_ino or
                after.st_size != opened.st_size or after.st_mtime_ns != opened.st_mtime_ns):
            raise ValueError("evidence file changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _json_report(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_private_regular(path, MAX_REPORT_BYTES)
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("evidence report is not one UTF-8 JSON object") from None
    if not isinstance(value, dict):
        raise ValueError("evidence report root must be a JSON object")
    return value, raw


def _artifact(report: dict[str, Any], role: str) -> tuple[dict[str, Any], dict[str, Any]]:
    remote = report.get("remote")
    if not isinstance(remote, dict):
        raise ValueError(f"{role}: remote result is missing")
    artifact = (remote.get("ioctl_trace_artifact") if role == "rtx5080"
                else report.get("ioctl_trace_artifact"))
    if not isinstance(artifact, dict):
        raise ValueError(f"{role}: persisted trace-sidecar metadata is missing")
    return remote, artifact


def _source_identity(report: dict[str, Any], role: str) -> dict[str, Any]:
    remote, artifact = _artifact(report, role)
    if role == "rtx5080":
        phase = remote.get("phase_report")
        if (report.get("schema") != RTX_SCHEMA or report.get("phase") != "enumerate" or
                report.get("exit_code") != 0 or remote.get("phase") != "enumerate" or
                remote.get("exit_code") != 0 or
                remote.get("qualification") != "rtx5080-cuda-phase-report-contract-valid" or
                remote.get("remote_work_cleanup") != {
                    "attempted": True, "passed": True, "removed": True,
                    "retained_for_inspection": False}):
            raise ValueError("RTX5080 report is not a cleaned successful enumeration reference")
        local = report.get("local_artifacts")
        gpu_summary = remote.get("selected_nvidia_smi")
        driver_version = gpu_summary.get("driver") if isinstance(gpu_summary, dict) else None
        kernel = remote.get("kernel_release")
    elif role == "v100":
        phase = remote.get("probe")
        if (report.get("schema") != V100_SCHEMA or report.get("phase") != "enumerate" or
                report.get("qualification") != "v100-cuda-phase-report-contract-valid" or
                remote.get("phase") != "enumerate" or
                remote.get("phase_capture_requested") is not True or
                remote.get("qualification") != "v100-cuda-phase-report-contract-valid" or
                remote.get("probe_exit_code") != 0 or
                remote.get("guest_cleanup_passed") is not True or
                remote.get("payload_file_cleanup_passed") is not True):
            raise ValueError("V100 report is not a cleaned successful enumeration reference")
        local = {"probe": report.get("probe"), "module": report.get("module")}
        guest = remote.get("guest")
        driver_version = guest.get("driver_version") if isinstance(guest, dict) else None
        kernel = guest.get("kernel_release") if isinstance(guest, dict) else None
    else:
        raise ValueError("unsupported capture role")

    expected_sm = 120 if role == "rtx5080" else 70
    pci = "0000:02:00.0" if role == "rtx5080" else "0000:00:05.0"
    if (not isinstance(phase, dict) or phase.get("schema") != PHASE_SCHEMA or
            phase.get("phase") != "enumerate" or phase.get("status") != "phase-passed" or
            phase.get("driver_api") not in (13000, 13020) or
            phase.get("cleanup_passed") is not True or phase.get("cleanup_errors") != [] or
            phase.get("error") != ""):
        raise ValueError(f"{role}: CUDA phase did not pass its cleanup contract")
    device = phase.get("selected_device")
    if (not isinstance(device, dict) or device.get("sm") != expected_sm or
            device.get("pci_bus_id") != pci or not isinstance(device.get("name"), str) or
            not device["name"]):
        raise ValueError(f"{role}: selected GPU identity differs from its expected PC3 device")
    if not isinstance(driver_version, str) or not driver_version or not isinstance(kernel, str) or not kernel:
        raise ValueError(f"{role}: installed driver or kernel identity is missing")
    if not isinstance(local, dict):
        raise ValueError(f"{role}: local probe artifacts are missing")
    probe, module = local.get("probe"), local.get("module")
    for label, identity in (("probe", probe), ("CUDA fatbin", module)):
        if (not isinstance(identity, dict) or type(identity.get("bytes")) is not int or
                identity["bytes"] <= 0 or
                re.fullmatch(r"[0-9a-f]{64}", str(identity.get("sha256", ""))) is None):
            raise ValueError(f"{role}: {label} identity is malformed")

    return {
        "role": role,
        "gpu": {"name": device["name"], "sm": expected_sm,
                "pci_bus_id": pci, "compute_capability": device.get("compute_capability")},
        "driver": {"version": driver_version, "driver_api": phase["driver_api"],
                   "kernel_release": kernel},
        "probe_sha256": probe["sha256"],
        "cuda_fatbin_sha256": module["sha256"],
        "trace_artifact": artifact,
    }


def _summarize_capture(report_path: Path, role: str) -> tuple[dict[str, Any], dict[str, Any]]:
    report, report_bytes = _json_report(report_path)
    identity = _source_identity(report, role)
    artifact = identity.pop("trace_artifact")
    sidecar = report_path.with_suffix(report_path.suffix + ".strace.gz")
    compressed = _read_private_regular(sidecar, TRACE.MAX_TRACE_GZIP_BYTES)
    if (artifact.get("mode") != "0600" or
            artifact.get("compressed_bytes") != len(compressed) or
            artifact.get("compressed_sha256") != hashlib.sha256(compressed).hexdigest() or
            artifact.get("raw_bytes") not in range(1, TRACE.MAX_TRACE_BYTES + 1) or
            re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("raw_sha256", ""))) is None):
        raise ValueError(f"{role}: compressed trace sidecar does not match its private report metadata")
    if artifact.get("path") and Path(str(artifact["path"])).resolve(strict=False) != sidecar.resolve(strict=True):
        raise ValueError(f"{role}: trace sidecar path differs from the evidence report")
    raw = TRACE.inflate_gzip_trace(compressed)
    if (len(raw) != artifact["raw_bytes"] or
            hashlib.sha256(raw).hexdigest() != artifact["raw_sha256"]):
        raise ValueError(f"{role}: inflated trace does not match its recorded hash")
    summary = TRACE.summarize_node_open_trace(raw)
    if (summary.get("schema") != "nvidia-hybrid-node-open-trace-v1" or
            summary.get("qualification") != "complete-node-open-trace" or
            summary.get("trace_complete") is not True or
            summary.get("unparsed_lines") != [] or
            summary.get("selected_node_open_count", 0) <= 0 or
            summary.get("successful_selected_node_open_count", 0) <= 0):
        raise ValueError(f"{role}: node-open lifecycle trace is incomplete")
    if artifact.get("summary") != summary:
        raise ValueError(f"{role}: local trace reparse differs from the archived redacted summary")

    events = summary["events"]
    opens = Counter(row["node"] for row in events
                    if row.get("operation") == "open" and row.get("succeeded") is True)
    closes = Counter(row["node"] for row in events
                     if row.get("operation") == "close" and row.get("succeeded") is True)
    ioctls_by_node: dict[str, Counter[str]] = {}
    ioctl_returns_by_node: dict[str, dict[str, Counter[str]]] = {}
    for row in events:
        if row.get("operation") != "ioctl":
            continue
        node, request = row.get("node"), row.get("request")
        if (not isinstance(node, str) or not node or
                not isinstance(request, str) or
                re.fullmatch(r"0x[0-9a-f]+", request) is None):
            raise ValueError(f"{role}: reparsed ioctl event has an invalid node/request identity")
        ioctls_by_node.setdefault(node, Counter())[request] += 1
        syscall_return = row.get("syscall_return")
        if type(syscall_return) is not int:
            raise ValueError(f"{role}: reparsed ioctl event has an invalid syscall result")
        result_class = "negative" if syscall_return < 0 else "nonnegative"
        ioctl_returns_by_node.setdefault(node, {}).setdefault(
            request, Counter())[result_class] += 1
    ioctl_requests_by_node = {
        node: dict(sorted(requests.items()))
        for node, requests in sorted(ioctls_by_node.items())
    }
    ioctl_return_counts_by_node = {
        node: {
            request: {result_class: counts[result_class]
                      for result_class in ("negative", "nonnegative") if counts[result_class]}
            for request, counts in sorted(requests.items())
        }
        for node, requests in sorted(ioctl_returns_by_node.items())
    }
    if {node: sum(requests.values()) for node, requests in ioctl_requests_by_node.items()} != \
            summary["ioctl_counts_by_node"]:
        raise ValueError(f"{role}: ioctl request histogram differs from the parsed node totals")
    report_digest = hashlib.sha256(report_bytes).hexdigest()
    compact_summary = {
        "trace_sha256": summary["trace_sha256"],
        "trace_bytes": summary["trace_bytes"],
        "selected_node_open_count": summary["selected_node_open_count"],
        "successful_selected_node_open_count": summary["successful_selected_node_open_count"],
        "open_count_by_node": dict(sorted(opens.items())),
        "close_count_by_node": dict(sorted(closes.items())),
        "ioctl_counts_by_node": summary["ioctl_counts_by_node"],
        "ioctl_requests_by_node": ioctl_requests_by_node,
        "ioctl_return_counts_by_node": ioctl_return_counts_by_node,
        "descriptors_open_at_trace_end_by_node":
            summary["selected_node_descriptors_open_at_trace_end_by_node"],
        "negative_syscall_returns": summary["negative_syscall_returns"],
        "other_open_count": summary["other_open_count"],
        "relative_path_open_count": summary["relative_path_open_count"],
        "descriptor_lifecycle_scope": summary["descriptor_lifecycle_scope"],
    }
    return {
        **identity,
        "source_report": {"name": report_path.name, "sha256": report_digest},
        "compressed_trace_sha256": artifact["compressed_sha256"],
        "trace": compact_summary,
    }, summary


def compare(rtx_path: Path, v100_path: Path) -> dict[str, Any]:
    rtx, _ = _summarize_capture(rtx_path, "rtx5080")
    v100, _ = _summarize_capture(v100_path, "v100")
    if rtx["probe_sha256"] != v100["probe_sha256"]:
        raise ValueError("paired enumeration traces must use the same CUDA probe binary")
    if rtx["cuda_fatbin_sha256"] != v100["cuda_fatbin_sha256"]:
        raise ValueError("paired enumeration traces must use the same CUDA fatbin")
    return {
        "schema": "nvidia-hybrid-cuda-node-open-lifecycle-comparison-v3",
        "qualification": "paired-stock-driver-enumeration-reference",
        "observed_at_utc": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
        "comparison": {
            "same_probe_binary": True,
            "same_cuda_fatbin": True,
            "hybrid_runtime_validated": False,
            "raw_syscall_arguments_in_report": False,
            "raw_syscall_results_in_report": False,
            "raw_trace_sidecars_retained_privately": True,
            "scope": "one isolated cuInit/device-enumeration process per stock-driver environment",
        },
        "devices": {"rtx5080": rtx, "v100": v100},
        "not_proven": [
            "same-Linux or same-process operation of both devices",
            "compatibility of cross-version RM command payloads",
            "kernel struct-file identity beyond the observed process-local descriptor lifecycle",
            "CUDA context creation, kernel execution, UVM, P2P, concurrency, or performance",
            "meaning of negative syscalls outside the selected NVIDIA-node lifecycle",
        ],
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "trace_helper_sha256": hashlib.sha256(TRACE_PATH.read_bytes()).hexdigest(),
    }


def _write_private_exclusive(path: Path, value: dict[str, Any]) -> None:
    parent = path.parent
    if not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise ValueError("comparison output directory must exist and be private")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtx-report", type=Path, required=True)
    parser.add_argument("--v100-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report.exists() or args.report.is_symlink():
        parser.error("comparison report already exists")
    try:
        result = compare(args.rtx_report, args.v100_report)
        _write_private_exclusive(args.report, result)
    except (OSError, ValueError, gzip.BadGzipFile) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"report": str(args.report), "schema": result["schema"],
                      "hybrid_runtime_validated": False,
                      "rtx5080_opens": result["devices"]["rtx5080"]["trace"]["selected_node_open_count"],
                      "v100_opens": result["devices"]["v100"]["trace"]["selected_node_open_count"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
