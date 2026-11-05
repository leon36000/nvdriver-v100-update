#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare NVIDIA UVM ioctl definitions and dispatch routes in two source trees."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
R595_UVM_ROOT = ROOT / (
    "build/research/open-gpu-kernel-modules-595.99.02/source/"
    "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm"
)
R615_UVM_ROOT = ROOT / (
    "build/research/open-gpu-kernel-modules-615.78.08/partial/"
    "kernel-open/nvidia-uvm"
)
R580_UVM_ROOT = ROOT / (
    "build/experiments/private-open580-native-v4-softdep-v1-20261023/private/"
    "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
MAX_REPORT_BYTES = 8 * 1024 * 1024
ROUTE_RE = re.compile(
    r"\bUVM_ROUTE_CMD_STACK_INIT_CHECK\s*\(\s*"
    r"(UVM_[A-Z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.S,
)
ALL_ROUTE_RE = re.compile(
    r"\b(UVM_ROUTE_CMD_[A-Z0-9_]+)\s*\(\s*"
    r"(UVM_[A-Z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.S,
)
IOCTL_RE = re.compile(
    r"^\s*#define\s+(UVM_[A-Z0-9_]+)\s+UVM_IOCTL_BASE\s*\(\s*([^)]*?)\s*\)",
    re.M,
)
BASE_REQUEST_RE = re.compile(
    r"^\s*#\s*define\s+(?P<name>UVM_[A-Z0-9_]+)\s+"
    r"UVM_IOCTL_BASE\(\s*(?P<value>\d+)\s*\)", re.M
)
DIRECT_REQUEST_RE = re.compile(
    r"^\s*#\s*define\s+(?P<name>UVM_[A-Z0-9_]+)\s+"
    r"(?P<value>0x[0-9a-fA-F]+|\d+)\b", re.M
)
REQUEST_VALUE_RE = re.compile(r"(?:0x[0-9a-fA-F]+|\d+)\Z")
REQUEST_NAME_RE = re.compile(r"UVM_[A-Z0-9_]+\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
# These captures predate report-contract-only qualifications. Their content
# hashes are pinned here so the historical label is accepted only for these
# exact immutable files, never as a general proof of CUDA execution.
LEGACY_CONTEXT_CAPTURE_HASHES = {
    "pc3-v100-context-ioctl-sequence-v1-20261028.json":
        "8c7c9c2cb9369afcb7f0139ae03f82054103b35de485324022ddd566d1427588",
    "pc3-v100-context-ioctl-sequence-v2-20261028.json":
        "b7857cabab5f2b121c79a7134a76f856462af7355f29a5b1ac60673a3694244a",
}
CURRENT_CONTEXT_CAPTURE_HASHES: dict[str, str] = {}


def _read_regular(path: Path, label: str) -> bytes:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for source verification")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{label} must be a regular file: {path}")
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_uvm_source(root: Path, label: str) -> dict[str, Any]:
    root = Path(root)
    source_path = root / "uvm.c"
    header_path = root / "uvm_ioctl.h"
    linux_header_path = root / "uvm_linux_ioctl.h"
    source_bytes = _read_regular(source_path, f"{label} dispatch source")
    header_bytes = _read_regular(header_path, f"{label} ioctl header")
    try:
        linux_header_bytes = _read_regular(linux_header_path, f"{label} Linux ioctl header")
        linux_header_available = True
    except FileNotFoundError:
        # Some retained branch snapshots are partial and omit the Linux-only UAPI header.
        linux_header_bytes = b""
        linux_header_available = False
    source = source_bytes.decode("utf-8")
    header = header_bytes.decode("utf-8")
    linux_header = linux_header_bytes.decode("utf-8")

    all_route_rows = ALL_ROUTE_RE.findall(source)
    routes = [(name, handler) for name, handler in ROUTE_RE.findall(source)]
    route_names = [name for name, _ in routes]
    all_route_names = [name for _, name, _ in all_route_rows]
    seen_routes: set[str] = set()
    duplicate_routes: set[str] = set()
    for name in all_route_names:
        if name in seen_routes:
            duplicate_routes.add(name)
        seen_routes.add(name)
    if duplicate_routes:
        raise ValueError(
            f"{label} has duplicate UVM dispatch routes: {sorted(duplicate_routes)}")
    if not all_route_rows:
        raise ValueError(f"{label} has no UVM_ROUTE_CMD_STACK_INIT_CHECK routes")

    ioctl_rows = [(name, value.strip()) for name, value in IOCTL_RE.findall(header)]
    linux_ioctl_rows = [
        (match.group("name"), match.group("value"))
        for match in DIRECT_REQUEST_RE.finditer(linux_header)
    ]
    all_ioctl_rows = [*ioctl_rows, *linux_ioctl_rows]
    ioctl_names = [name for name, _ in all_ioctl_rows]
    seen_definitions: set[str] = set()
    duplicate_definitions: set[str] = set()
    for name in ioctl_names:
        if name in seen_definitions:
            duplicate_definitions.add(name)
        seen_definitions.add(name)
    if duplicate_definitions:
        raise ValueError(
            f"{label} has duplicate UVM ioctl definitions: {sorted(duplicate_definitions)}")
    if not all_ioctl_rows:
        raise ValueError(f"{label} has no UVM_IOCTL_BASE definitions")

    defined = set(ioctl_names)
    missing_definitions = sorted(set(all_route_names) - defined)
    if missing_definitions and linux_header_available:
        raise ValueError(f"{label} dispatch routes lack ioctl definitions: {missing_definitions}")

    return {
        "label": label,
        "source": {
            "uvm.c": {"path": str(source_path), "sha256": hashlib.sha256(source_bytes).hexdigest()},
            "uvm_ioctl.h": {"path": str(header_path), "sha256": hashlib.sha256(header_bytes).hexdigest()},
            "uvm_linux_ioctl.h": {
                "path": str(linux_header_path),
                "available": linux_header_available,
                "sha256": hashlib.sha256(linux_header_bytes).hexdigest()
                if linux_header_available else None,
            },
        },
        "route_count": len(routes),
        "routes": {name: handler for name, handler in routes},
        "all_route_count": len(all_route_rows),
        "all_routes": {name: handler for _, name, handler in all_route_rows},
        "route_kinds": {name: kind for kind, name, _ in all_route_rows},
        "ioctl_definition_count": len(ioctl_rows),
        "ioctl_definitions": {name: value for name, value in ioctl_rows},
        "linux_ioctl_definitions": {name: value for name, value in linux_ioctl_rows},
        "all_ioctl_definition_count": len(all_ioctl_rows),
        "all_ioctl_definitions": {name: value for name, value in all_ioctl_rows},
        "unrouted_ioctl_definitions": sorted(defined - set(all_route_names)),
        "route_definition_closure": "closed" if not missing_definitions else "partial",
        "missing_route_definitions": missing_definitions,
    }


def compare_uvm_sources(baseline_root: Path, candidate_root: Path,
                        baseline_label: str, candidate_label: str) -> dict[str, Any]:
    baseline = parse_uvm_source(baseline_root, baseline_label)
    candidate = parse_uvm_source(candidate_root, candidate_label)
    baseline_routes = set(baseline["routes"])
    candidate_routes = set(candidate["routes"])
    baseline_ioctls = set(baseline["ioctl_definitions"])
    candidate_ioctls = set(candidate["ioctl_definitions"])
    return {
        "schema": "nvidia-uvm-ioctl-route-compare-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "analyzed-statically",
        "runtime_compatibility_proven": False,
        "hardware_tested": False,
        "baseline": baseline,
        "candidate": candidate,
        "removed_dispatch_routes": sorted(baseline_routes - candidate_routes),
        "added_dispatch_routes": sorted(candidate_routes - baseline_routes),
        "common_dispatch_routes": sorted(baseline_routes & candidate_routes),
        "removed_ioctl_definitions": sorted(baseline_ioctls - candidate_ioctls),
        "added_ioctl_definitions": sorted(candidate_ioctls - baseline_ioctls),
        "common_ioctl_definitions": sorted(baseline_ioctls & candidate_ioctls),
    }


def _load_r580_request_values() -> tuple[dict[str, int], dict[str, str]]:
    ioctl_path = R580_UVM_ROOT / "uvm_ioctl.h"
    linux_ioctl_path = R580_UVM_ROOT / "uvm_linux_ioctl.h"
    ioctl_bytes = _read_regular(ioctl_path, "R580 UVM ioctl header")
    linux_ioctl_bytes = _read_regular(linux_ioctl_path, "R580 Linux UVM ioctl header")
    ioctl_text = ioctl_bytes.decode("utf-8")
    linux_ioctl_text = linux_ioctl_bytes.decode("utf-8")
    values: dict[str, int] = {}
    by_value: dict[int, str] = {}

    def add(name: str, value: int) -> None:
        if name in values or value in by_value:
            raise ValueError(f"duplicate R580 UVM ioctl definition: {name} / 0x{value:x}")
        values[name] = value
        by_value[value] = name

    for match in BASE_REQUEST_RE.finditer(ioctl_text):
        add(match.group("name"), int(match.group("value"), 10))
    for match in DIRECT_REQUEST_RE.finditer(linux_ioctl_text):
        value_text = match.group("value")
        add(match.group("name"), int(value_text, 0 if value_text.lower().startswith("0x") else 10))
    return values, {
        "uvm_ioctl_h_sha256": hashlib.sha256(ioctl_bytes).hexdigest(),
        "uvm_linux_ioctl_h_sha256": hashlib.sha256(linux_ioctl_bytes).hexdigest(),
    }


def _load_hash_pinned_raw_trace(
    capture: dict[str, Any]
) -> tuple[dict[int, int], str, str]:
    capture_name = capture.get("capture")
    expected_hash = capture.get("capture_sha256")
    if (not isinstance(capture_name, str) or Path(capture_name).name != capture_name
            or not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash)):
        raise ValueError("observed UVM capture name or hash is invalid")
    path = ROOT / "evidence" / capture_name
    raw = _read_regular(path, "hash-pinned raw V100 UVM trace capture")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("hash-pinned raw V100 UVM trace capture exceeds the size limit")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(f"capture {capture_name} does not match its recorded SHA-256")
    try:
        report = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"hash-pinned raw capture {capture_name} is invalid JSON: {error}") from None
    if (not isinstance(report, dict)
            or report.get("schema") != "nvidia-hybrid-pc3-v100-reference-transport-v1"
            or report.get("phase") != "context"):
        raise ValueError(f"capture {capture_name} is not a recorded V100 context trace")
    qualification = report.get("qualification")
    if qualification == "v100-cuda-phase-report-contract-valid":
        if CURRENT_CONTEXT_CAPTURE_HASHES.get(capture_name) != actual_hash:
            raise ValueError(
                f"capture {capture_name} is not in the fixed SHA-256 allowlist for "
                "current report-contract traces"
            )
        source_qualification = (
            "current-v100-phase-report-contract-label; exact-capture-hash-pinned; "
            "CUDA-execution-not-established-by-this-analysis"
        )
    elif (qualification == "v100-cuda-phase-validated"
          and LEGACY_CONTEXT_CAPTURE_HASHES.get(capture_name) == actual_hash):
        source_qualification = (
            "historical-v100-cuda-phase-validated-label; exact-capture-hash-pinned; "
            "CUDA-execution-not-established-by-this-analysis"
        )
    else:
        raise ValueError(
            f"capture {capture_name} has an unsupported qualification or is not the "
            "exact hash-pinned historical capture"
        )
    remote = report.get("remote")
    trace_envelope = remote.get("ioctl_trace") if isinstance(remote, dict) else None
    trace = trace_envelope.get("trace") if isinstance(trace_envelope, dict) else None
    summary = trace.get("summary") if isinstance(trace, dict) else None
    if (not isinstance(summary, dict) or summary.get("trace_complete") is not True
            or summary.get("qualification") != "complete-node-open-trace"
            or summary.get("descriptor_lifecycle_scope") !=
            "selected node descriptors only; ioctl payloads and syscall arguments omitted"):
        raise ValueError(f"capture {capture_name} lacks a complete redacted node trace")
    events = summary.get("events")
    if not isinstance(events, list):
        raise ValueError(f"capture {capture_name} has no raw trace event list")

    request_counts: dict[int, int] = {}
    for event in events:
        if not isinstance(event, dict):
            raise ValueError(f"capture {capture_name} has a malformed raw trace event")
        if event.get("node") != "nvidia-uvm" or event.get("operation") != "ioctl":
            continue
        request_text = event.get("request")
        syscall_return = event.get("syscall_return")
        if (not isinstance(request_text, str)
                or not re.fullmatch(r"0x[0-9a-fA-F]+", request_text)
                or type(syscall_return) is not int):
            raise ValueError(f"capture {capture_name} has malformed raw UVM ioctl metadata")
        request = int(request_text, 16)
        request_counts[request] = request_counts.get(request, 0) + 1
    if summary.get("ioctl_counts_by_node", {}).get("nvidia-uvm") != sum(request_counts.values()):
        raise ValueError(f"capture {capture_name} UVM trace count is internally inconsistent")
    return request_counts, actual_hash, source_qualification


def _assess_observed_request(parsed: dict[str, Any], name: str, request: int,
                             *, baseline_route_exists: bool) -> dict[str, Any]:
    if not baseline_route_exists:
        definitions = parsed.get("all_ioctl_definitions", parsed["ioctl_definitions"])
        return {
            "status": "outside_compared_dispatch_inventory",
            "handler": None,
            "ioctl_definition_present": name in definitions,
            "dispatch_present": name in parsed["routes"],
        }

    expressions = parsed.get("all_ioctl_definitions", parsed["ioctl_definitions"])
    expression = expressions.get(name)
    routes = parsed.get("all_routes", parsed["routes"])
    handler = routes.get(name)
    route_kind = parsed.get("route_kinds", {}).get(name)
    linux_header = parsed.get("source", {}).get("uvm_linux_ioctl.h", {})
    if (handler is not None and not expression and
            linux_header.get("available") is False):
        return {
            "status": "route_present_definition_unavailable",
            "handler": handler,
            "route_kind": route_kind,
            "ioctl_definition_present": False,
            "dispatch_present": True,
        }
    match = REQUEST_VALUE_RE.fullmatch(expression or "")
    if not expression or handler is None:
        return {
            "status": "missing_dispatch",
            "handler": handler,
            "route_kind": route_kind,
            "ioctl_definition_present": bool(expression),
            "dispatch_present": handler is not None,
        }
    if not match:
        return {
            "status": "unparseable_ioctl_definition",
            "handler": handler,
            "ioctl_definition_present": True,
            "dispatch_present": True,
        }
    value = int(expression, 0 if expression.lower().startswith("0x") else 10)
    if value != request:
        return {
            "status": "request_value_mismatch",
            "handler": handler,
            "ioctl_definition_present": True,
            "dispatch_present": True,
        }
    return {
        "status": "routed",
        "handler": handler,
        "route_kind": route_kind,
        "ioctl_definition_present": True,
        "dispatch_present": True,
    }


def compare_observed_summary(baseline: dict[str, Any], candidate: dict[str, Any],
                             summary_path: Path) -> dict[str, Any]:
    summary_path = Path(summary_path)
    raw = _read_regular(summary_path, "observed UVM trace summary")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("observed UVM trace summary exceeds the size limit")
    try:
        summary = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"observed UVM trace summary is invalid JSON: {error}") from None
    if not isinstance(summary, dict) or summary.get("schema") != "nvidia-hybrid-pc3-v100-context-uvm-sequence-v1":
        raise ValueError("observed UVM trace summary has an unexpected schema")
    if summary.get("qualification") != "repeated-stock-driver-context-ioctl-metadata-only":
        raise ValueError("observed UVM trace summary is not a repeated stock capture")
    if summary.get("uvm_payloads_observed") is not False or summary.get("hybrid_validated") is not False:
        raise ValueError("observed UVM trace summary has an invalid proof scope")
    comparison = summary.get("comparison")
    captures = summary.get("captures")
    if (not isinstance(comparison, dict) or comparison.get("request_counts_identical") is not True
            or comparison.get("first_seen_order_identical") is not True
            or not isinstance(captures, list) or len(captures) < 2):
        raise ValueError("observed UVM trace summary lacks repeated matching captures")

    r580_values, r580_hashes = _load_r580_request_values()
    if summary.get("pinned_linux_uapi_headers") != r580_hashes:
        raise ValueError("observed UVM trace summary was not derived from the pinned R580 UAPI headers")

    output_captures = []
    identity = None
    for capture in captures:
        if not isinstance(capture, dict):
            raise ValueError("observed UVM trace summary contains a malformed capture")
        report_hash = capture.get("capture_sha256")
        guest_name = capture.get("guest_name")
        driver_version = capture.get("driver_version")
        kernel_release = capture.get("kernel_release")
        requests = capture.get("requests")
        current_identity = (guest_name, driver_version, kernel_release)
        if (not isinstance(report_hash, str) or not SHA256_RE.fullmatch(report_hash)
                or not isinstance(guest_name, str) or "Tesla V100" not in guest_name
                or driver_version != "580.178.04" or not isinstance(kernel_release, str)
                or not isinstance(requests, list)):
            raise ValueError("observed UVM capture identity or request list is invalid")
        if identity is not None and current_identity != identity:
            raise ValueError("observed UVM captures do not identify the same stock V100 environment")
        identity = current_identity

        raw_request_counts, raw_capture_hash, source_qualification = (
            _load_hash_pinned_raw_trace(capture)
        )

        output_requests = []
        seen_names: set[str] = set()
        reported_request_counts: dict[int, int] = {}
        for row in requests:
            if not isinstance(row, dict):
                raise ValueError("observed UVM capture contains a malformed request")
            name, request_text, count = row.get("name"), row.get("request"), row.get("count")
            if (not isinstance(name, str) or not REQUEST_NAME_RE.fullmatch(name)
                    or name in seen_names or not isinstance(request_text, str)
                    or not re.fullmatch(r"0x[0-9a-fA-F]+", request_text)
                    or type(count) is not int or count < 1):
                raise ValueError("observed UVM request fields are invalid")
            seen_names.add(name)
            request = int(request_text, 16)
            if r580_values.get(name) != request:
                raise ValueError(f"observed request {name} does not match pinned R580 UAPI")
            reported_request_counts[request] = count
            if raw_request_counts.get(request) != count:
                raise ValueError(
                    f"observed request {name} count does not match the hash-pinned raw trace"
                )

            baseline_route_exists = name in baseline.get("all_routes", baseline["routes"])
            baseline_result = _assess_observed_request(
                baseline, name, request, baseline_route_exists=baseline_route_exists)
            candidate_result = _assess_observed_request(
                candidate, name, request, baseline_route_exists=baseline_route_exists)
            output_requests.append({
                "name": name,
                "request": f"0x{request:x}",
                "count": count,
                "baseline": baseline_result,
                "candidate": candidate_result,
            })
        if reported_request_counts != raw_request_counts:
            raise ValueError("observed UVM request list does not match the hash-pinned raw trace")
        output_captures.append({
            "capture": capture.get("capture"),
            "capture_sha256": raw_capture_hash,
            "driver_version": driver_version,
            "guest_name": guest_name,
            "kernel_release": kernel_release,
            "source_qualification": source_qualification,
            "cuda_execution_validated": False,
            "requests": output_requests,
        })

    return {
        "schema": "nvidia-hybrid-observed-uvm-route-coverage-v1",
        "qualification": "static-route-coverage-of-repeated-stock-V100-node-open-traces",
        "observed_summary": {
            "path": str(summary_path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "pinned_r580_uapi_headers": r580_hashes,
        },
        "capture_count": len(output_captures),
        "captures": output_captures,
        "uvm_payloads_observed": False,
        "cuda_execution_validated": False,
        "runtime_compatibility_proven": False,
        "hardware_tested_with_candidate": False,
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise ValueError(f"refusing to overwrite report: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, default=R595_UVM_ROOT)
    parser.add_argument("--candidate-root", type=Path, default=R615_UVM_ROOT)
    parser.add_argument("--baseline-label", default="R595.99.02")
    parser.add_argument("--candidate-label", default="R615.78.08")
    parser.add_argument("--observed-summary", type=Path,
                        help="redacted repeated stock V100 UVM context summary")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)

    report = compare_uvm_sources(
        args.baseline_root, args.candidate_root,
        args.baseline_label, args.candidate_label,
    )
    if args.observed_summary:
        report["schema"] = "nvidia-uvm-ioctl-route-compare-v2"
        report["observed_trace_compatibility"] = compare_observed_summary(
            report["baseline"], report["candidate"], args.observed_summary)
    if args.report:
        _write_report(args.report, report)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
