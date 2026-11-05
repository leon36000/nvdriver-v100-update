#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare redacted-metadata summaries of repeated stock V100 context traces."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_UVM_HEADER_DIR = (
    ROOT / "build/experiments/private-open580-native-v4-softdep-v1-20261023"
    / "private/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
MAX_REPORT_BYTES = 8 * 1024 * 1024
BASE_REQUEST = re.compile(
    r"^\s*#\s*define\s+(?P<name>UVM_[A-Z0-9_]+)\s+UVM_IOCTL_BASE\(\s*(?P<value>\d+)\s*\)",
    re.MULTILINE,
)
DIRECT_REQUEST = re.compile(
    r"^\s*#\s*define\s+(?P<name>UVM_[A-Z0-9_]+)\s+(?P<value>0x[0-9a-fA-F]+|\d+)\b",
    re.MULTILINE,
)
NODE_NAME = re.compile(r"nvidia(?:ctl|-uvm|[0-9]+)\Z")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_header(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", "strict")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read pinned UVM header {path.name}: {error}") from None
    return text, _sha256(raw)


def load_request_names(uvm_ioctl_header: Path, uvm_linux_ioctl_header: Path) -> tuple[dict[int, str], dict[str, str]]:
    """Read Linux UVM command values from the exact source headers, rejecting aliases."""
    ioctl_text, ioctl_hash = _read_header(Path(uvm_ioctl_header))
    linux_text, linux_hash = _read_header(Path(uvm_linux_ioctl_header))
    names: dict[int, str] = {}
    seen_names: set[str] = set()

    def add(name: str, value: int) -> None:
        require(name not in seen_names, f"duplicate UVM request name: {name}")
        require(value not in names,
                f"duplicate UVM request value 0x{value:x}: {names.get(value)} and {name}")
        names[value] = name
        seen_names.add(name)

    for match in BASE_REQUEST.finditer(ioctl_text):
        add(match.group("name"), int(match.group("value"), 10))
    for match in DIRECT_REQUEST.finditer(linux_text):
        value_text = match.group("value")
        add(match.group("name"), int(value_text, 0 if value_text.lower().startswith("0x") else 10))
    require(names, "pinned UVM headers contain no Linux ioctl definitions")
    return names, {
        "uvm_ioctl_h_sha256": ioctl_hash,
        "uvm_linux_ioctl_h_sha256": linux_hash,
    }


def _read_capture(path: Path) -> tuple[dict, str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read capture {path.name}: {error}") from None
    require(len(raw) <= MAX_REPORT_BYTES, f"capture {path.name} exceeds the size limit")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"capture {path.name} is not valid JSON: {error}") from None
    require(isinstance(value, dict), f"capture {path.name} root must be an object")
    return value, _sha256(raw)


def _capture_summary(path: Path, request_names: dict[int, str]) -> dict:
    report, report_hash = _read_capture(path)
    require(report.get("schema") == "nvidia-hybrid-pc3-v100-reference-transport-v1",
            f"{path.name} is not a PC3 V100 transport report")
    require(report.get("qualification") == "v100-cuda-phase-report-contract-valid" and
            report.get("phase") == "context",
            f"{path.name} is not a passed context-phase capture")
    remote = report.get("remote")
    require(isinstance(remote, dict) and
            remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1" and
            remote.get("qualification") == "v100-cuda-phase-report-contract-valid" and
            remote.get("phase") == "context",
            f"{path.name} lacks a passed V100 guest context result")
    require(remote.get("guest_cleanup_passed") is True and
            remote.get("payload_file_cleanup_passed") is True and
            remote.get("compute_process_count_prelaunch") == 0 and
            remote.get("compute_process_count_after") == 0,
            f"{path.name} did not pass the bounded cleanup/idle checks")
    guest = remote.get("guest")
    probe = remote.get("probe")
    require(isinstance(guest, dict) and isinstance(probe, dict),
            f"{path.name} lacks guest or probe identity")
    require(isinstance(guest.get("uuid"), str) and guest.get("uuid") and
            isinstance(guest.get("name"), str) and guest["name"].startswith("Tesla V100") and
            isinstance(guest.get("driver_version"), str) and
            isinstance(guest.get("kernel_release"), str) and
            isinstance(guest.get("pci"), str),
            f"{path.name} does not identify one V100 guest")
    require(probe.get("phase") == "context" and probe.get("status") == "phase-passed",
            f"{path.name} did not pass cuCtxCreate context setup")

    trace = remote.get("ioctl_trace")
    trace = trace.get("trace") if isinstance(trace, dict) else None
    summary = trace.get("summary") if isinstance(trace, dict) else None
    require(isinstance(trace, dict) and isinstance(summary, dict),
            f"{path.name} has no structured ioctl trace summary")
    require(trace.get("trace_complete") is True and trace.get("size_limit_exceeded") is False and
            summary.get("trace_complete") is True and
            summary.get("qualification") == "complete-node-open-trace" and
            summary.get("unparsed_lines") == [] and
            summary.get("relative_path_open_count") == 0,
            f"{path.name} trace is not complete")
    require(summary.get("descriptor_lifecycle_scope") ==
            "selected node descriptors only; ioctl payloads and syscall arguments omitted",
            f"{path.name} trace scope differs from the expected redacted metadata mode")
    events = summary.get("events")
    require(isinstance(events, list), f"{path.name} trace events must be a list")

    request_counts: dict[int, int] = {}
    first_seen: list[int] = []
    negative_returns = 0
    uvm_event_count = 0
    for event in events:
        require(isinstance(event, dict), f"{path.name} contains a malformed trace event")
        if event.get("node") != "nvidia-uvm" or event.get("operation") != "ioctl":
            continue
        request_text, result = event.get("request"), event.get("syscall_return")
        require(isinstance(request_text, str) and re.fullmatch(r"0x[0-9a-fA-F]+", request_text),
                f"{path.name} contains a malformed UVM request code")
        require(type(result) is int, f"{path.name} contains a malformed UVM syscall result")
        code = int(request_text, 16)
        require(code in request_names,
                f"UVM request {request_text.lower()} is not present in pinned headers")
        if code not in request_counts:
            first_seen.append(code)
        request_counts[code] = request_counts.get(code, 0) + 1
        negative_returns += int(result < 0)
        uvm_event_count += 1

    node_counts = summary.get("ioctl_counts_by_node")
    require(isinstance(node_counts, dict) and
            all(isinstance(node, str) and NODE_NAME.fullmatch(node) and
                type(count) is int and count >= 0 for node, count in node_counts.items()),
            f"{path.name} has malformed per-node ioctl counts")
    require(node_counts.get("nvidia-uvm") == uvm_event_count,
            f"{path.name} UVM event count disagrees with trace summary event count")

    request_rows = [{
        "request": f"0x{code:x}",
        "name": request_names[code],
        "count": request_counts[code],
    } for code in first_seen]
    return {
        "capture": path.name,
        "capture_sha256": report_hash,
        "observed_at_utc": report.get("observed_at_utc"),
        "guest_name": guest["name"],
        "driver_version": guest["driver_version"],
        "kernel_release": guest["kernel_release"],
        "gpu_pci": guest["pci"],
        "trace_sha256": trace.get("sha256"),
        "trace_event_count": len(events),
        "node_ioctl_counts": dict(sorted(node_counts.items())),
        "uvm_ioctl_count": uvm_event_count,
        "uvm_ioctl_negative_returns": negative_returns,
        "first_seen_request_order": [request_names[code] for code in first_seen],
        "requests": request_rows,
        "_guest_uuid_for_comparison": guest["uuid"],
        "_request_counts_for_comparison": request_counts,
    }


def analyze_reports(capture_paths: list[Path],
                    uvm_ioctl_header: Path,
                    uvm_linux_ioctl_header: Path) -> dict:
    require(isinstance(capture_paths, list) and len(capture_paths) >= 2,
            "at least two context captures are required for comparison")
    request_names, header_hashes = load_request_names(uvm_ioctl_header, uvm_linux_ioctl_header)
    captures = [_capture_summary(Path(path), request_names) for path in capture_paths]
    identity_keys = ("_guest_uuid_for_comparison", "guest_name", "driver_version",
                     "kernel_release", "gpu_pci")
    first_identity = tuple(captures[0][key] for key in identity_keys)
    require(all(tuple(capture[key] for key in identity_keys) == first_identity
                 for capture in captures[1:]),
            "captures must identify the same V100 guest and stock driver")
    first_counts = captures[0]["_request_counts_for_comparison"]
    first_order = captures[0]["first_seen_request_order"]
    counts_identical = all(capture["_request_counts_for_comparison"] == first_counts
                           for capture in captures[1:])
    order_identical = all(capture["first_seen_request_order"] == first_order
                          for capture in captures[1:])
    for capture in captures:
        del capture["_guest_uuid_for_comparison"]
        del capture["_request_counts_for_comparison"]
    identical = counts_identical and order_identical
    return {
        "schema": "nvidia-hybrid-pc3-v100-context-uvm-sequence-v1",
        "qualification": ("repeated-stock-driver-context-ioctl-metadata-only"
                          if identical else "repeated-context-captures-differ"),
        "scope": "UVM ioctl request metadata only; no ioctl payload, pointer, FD, task, or file identity retained",
        "gpu_kernel_execution_validated": False,
        "hybrid_validated": False,
        "uvm_payloads_observed": False,
        "pinned_linux_uapi_headers": header_hashes,
        "comparison": {
            "capture_count": len(captures),
            "request_counts_identical": counts_identical,
            "first_seen_order_identical": order_identical,
            "first_seen_order": first_order,
        },
        "captures": captures,
    }


def write_report(path: Path, report: dict) -> None:
    """Create a new mode-0600 JSON report without replacing an existing artifact."""
    path = Path(path)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    path.chmod(0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="append", required=True, type=Path,
                        help="mode-0600 PC3 V100 context trace report; pass at least two")
    parser.add_argument("--uvm-header", type=Path,
                        default=DEFAULT_UVM_HEADER_DIR / "uvm_ioctl.h")
    parser.add_argument("--uvm-linux-header", type=Path,
                        default=DEFAULT_UVM_HEADER_DIR / "uvm_linux_ioctl.h")
    parser.add_argument("--output", required=True, type=Path,
                        help="new output path; existing files are never replaced")
    args = parser.parse_args(argv)
    try:
        result = analyze_reports(args.capture, args.uvm_header, args.uvm_linux_header)
        write_report(args.output, result)
    except (OSError, ValueError) as error:
        print(f"analysis failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output),
                      "qualification": result["qualification"],
                      "captures": result["comparison"]["capture_count"],
                      "uvm_ioctl_count_per_capture": [capture["uvm_ioctl_count"]
                                                       for capture in result["captures"]]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
