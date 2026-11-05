#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Map observed UVM ioctl numbers to pinned source definitions and routes.

This tool reads source headers and privacy-filtered comparison summaries. It
does not inspect raw ioctl arguments, payloads, pointers, or strace sidecars.
The result is a static ABI inventory, not a UVM workload or compatibility test.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_R580_PROPRIETARY = ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04/nvidia-uvm"
DEFAULT_R580_OPEN = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
DEFAULT_R595_OPEN = ROOT / ".cache/upstream/open-gpu-kernel-modules-ac24e02fc090c3e05c1fc03384b317ac2cc301b5/kernel-open/nvidia-uvm"
DEFAULT_TRACES = (
    ROOT / "evidence/pc3-volta-blackwell-full-ioctl-comparison-v1-20261020.json",
    ROOT / "evidence/pc3-volta-blackwell-managed-memory-ioctl-comparison-v1-20261020.json",
    ROOT / "evidence/pc3-volta-blackwell-managed-prefetch-ioctl-comparison-v1-20261020.json",
)
SOURCE_FILES = ("uvm_ioctl.h", "uvm_linux_ioctl.h", "uvm.c")

IOCTL_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+(UVM_[A-Z0-9_]+)\s+UVM_IOCTL_BASE\(\s*(0[xX][0-9a-fA-F]+|[0-9]+)\s*\)",
    re.MULTILINE,
)
LINUX_IOCTL_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+(UVM_[A-Z0-9_]+)\s+(0[xX][0-9a-fA-F]+|[0-9]+)\s*(?://.*)?$",
    re.MULTILINE,
)
ROUTE_RE = re.compile(
    r"(UVM_ROUTE_CMD_[A-Z0-9_]+)\s*\(\s*(UVM_[A-Z0-9_]+)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)",
    re.DOTALL,
)
CASE_RE = re.compile(r"\bcase\s+(UVM_[A-Z0-9_]+)\s*:")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def read_profile(root: Path, label: str, release: str) -> dict[str, Any]:
    root = root.resolve()
    source_bytes: dict[str, bytes] = {}
    source_text: dict[str, str] = {}
    for name in SOURCE_FILES:
        path = root / name
        try:
            raw = path.read_bytes()
            source_text[name] = raw.decode("utf-8", "strict")
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"{label}: cannot read source file {path}: {exc}") from None
        source_bytes[name] = raw

    commands: dict[str, int] = {}
    for name, value in IOCTL_DEFINE_RE.findall(source_text["uvm_ioctl.h"]):
        number = int(value, 0)
        if name in commands and commands[name] != number:
            raise ValueError(f"{label}: conflicting ioctl values for {name}")
        commands[name] = number
    for name, value in LINUX_IOCTL_DEFINE_RE.findall(source_text["uvm_linux_ioctl.h"]):
        number = int(value, 0)
        if name in commands and commands[name] != number:
            raise ValueError(f"{label}: conflicting ioctl values for {name}")
        commands[name] = number
    if not commands:
        raise ValueError(f"{label}: no UVM ioctl definitions found")

    dispatch: dict[str, dict[str, str | None]] = {}
    for macro, name, handler in ROUTE_RE.findall(source_text["uvm.c"]):
        value = {"route": macro, "handler": handler}
        if name in dispatch and dispatch[name] != value:
            raise ValueError(f"{label}: conflicting dispatch routes for {name}")
        dispatch[name] = value
    for name in CASE_RE.findall(source_text["uvm.c"]):
        dispatch.setdefault(name, {"route": "switch-case", "handler": None})

    entries = []
    for name, number in sorted(commands.items(), key=lambda item: (item[1], item[0])):
        entries.append({
            "name": name,
            "value": number,
            "value_hex": f"0x{number:x}",
            "dispatch": dispatch.get(name),
        })
    return {
        "label": label,
        "release": release,
        "source_root": _source_path(root),
        "files": {
            name: {"bytes": len(source_bytes[name]), "sha256": sha256(source_bytes[name])}
            for name in SOURCE_FILES
        },
        "command_count": len(entries),
        "routed_command_count": sum(item["dispatch"] is not None for item in entries),
        "commands": entries,
    }


def _by_value(profile: dict[str, Any]) -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for command in profile["commands"]:
        result.setdefault(command["value"], []).append(command["name"])
    return {value: sorted(names) for value, names in result.items()}


def _by_name(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {command["name"]: command for command in profile["commands"]}


def compare_profiles(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_values = _by_value(left)
    right_values = _by_value(right)
    left_names = _by_name(left)
    right_names = _by_name(right)
    all_names = set(left_names) | set(right_names)
    return {
        "command_ids_equal": left_values == right_values,
        "dispatch_equal": {
            name: left_names[name].get("dispatch") if name in left_names else None
            for name in all_names
        } == {
            name: right_names[name].get("dispatch") if name in right_names else None
            for name in all_names
        },
        "left_only_names": sorted(set(left_names) - set(right_names)),
        "right_only_names": sorted(set(right_names) - set(left_names)),
        "value_name_deltas": [
            {"value_hex": f"0x{value:x}", "left_names": left_values.get(value, []),
             "right_names": right_values.get(value, [])}
            for value in sorted(set(left_values) | set(right_values))
            if left_values.get(value, []) != right_values.get(value, [])
        ],
        "dispatch_deltas": [
            {"name": name, "left": left_names.get(name, {}).get("dispatch"),
             "right": right_names.get(name, {}).get("dispatch")}
            for name in sorted(all_names)
            if left_names.get(name, {}).get("dispatch") !=
               right_names.get(name, {}).get("dispatch")
        ],
    }


def _parse_request(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
        raise ValueError("trace has a malformed UVM request value")
    return int(value, 0)


def _node_lifecycle_inputs(data: dict[str, Any], path: Path) -> dict[str, dict[str, Any]]:
    comparison = data.get("comparison")
    devices = data.get("devices")
    if (data.get("schema") != "nvidia-hybrid-cuda-node-open-lifecycle-comparison-v3" or
            not isinstance(comparison, dict) or
            comparison.get("hybrid_runtime_validated") is not False or
            comparison.get("scope") !=
            "one isolated cuInit/device-enumeration process per stock-driver environment" or
            not isinstance(devices, dict)):
        raise ValueError(f"unsupported or insufficient node-lifecycle summary: {path}")

    normalized: dict[str, dict[str, Any]] = {}
    for gpu in ("rtx5080", "v100"):
        device = devices.get(gpu)
        driver = device.get("driver") if isinstance(device, dict) else None
        trace = device.get("trace") if isinstance(device, dict) else None
        requests_by_node = trace.get("ioctl_requests_by_node") if isinstance(trace, dict) else None
        version = driver.get("version") if isinstance(driver, dict) else None
        driver_api = driver.get("driver_api") if isinstance(driver, dict) else None
        if (not isinstance(version, str) or not version or type(driver_api) is not int or
                not isinstance(requests_by_node, dict) or len(requests_by_node) > 16):
            raise ValueError(f"node-lifecycle summary is missing bounded {gpu} ioctl metadata: {path}")

        request_counts = []
        for node, commands in requests_by_node.items():
            if not isinstance(node, str) or node not in ("nvidia-uvm", "nvidiactl", "nvidia0"):
                raise ValueError(f"node-lifecycle summary has an unexpected device node: {path}")
            if not isinstance(commands, dict) or len(commands) > 4096:
                raise ValueError(f"node-lifecycle summary has unbounded ioctl metadata: {path}")
            for request, count in commands.items():
                _parse_request(request)
                if type(count) is not int or count < 0:
                    raise ValueError(f"node-lifecycle summary has a malformed ioctl count: {path}")
                request_counts.append({
                    "node": "/dev/" + node,
                    "request": request,
                    "count": count,
                })
        normalized[gpu] = {
            "driver": version,
            "driver_api": driver_api,
            "uvm_workload_validated": False,
            "request_counts": request_counts,
        }
    return normalized


def _read_trace(path: Path, profiles: dict[str, dict[str, Any]]) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read trace summary {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"trace summary root must be an object: {path}")
    trace_schema = data.get("schema")
    if trace_schema == "nvidia-hybrid-cuda-node-open-lifecycle-comparison-v3":
        inputs = _node_lifecycle_inputs(data, path)
    else:
        inputs = data.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError(f"trace summary has no supported inputs map: {path}")

    observations: dict[str, Any] = {}
    for gpu in ("rtx5080", "v100"):
        item = inputs.get(gpu)
        if not isinstance(item, dict) or not isinstance(item.get("request_counts"), list):
            raise ValueError(f"trace summary is missing {gpu} request counts: {path}")
        counts: dict[int, int] = {}
        for entry in item["request_counts"]:
            if not isinstance(entry, dict):
                raise ValueError(f"trace summary has a malformed request entry: {path}")
            if entry.get("node") != "/dev/nvidia-uvm":
                continue
            request = _parse_request(entry.get("request"))
            count = entry.get("count")
            if type(count) is not int or count < 0:
                raise ValueError(f"trace summary has a malformed request count: {path}")
            counts[request] = counts.get(request, 0) + count

        observed = []
        unmapped = []
        for value, count in sorted(counts.items()):
            names_by_source: dict[str, list[str]] = {}
            dispatch_by_source: dict[str, dict[str, Any]] = {}
            for label, profile in profiles.items():
                matches = [command for command in profile["commands"] if command["value"] == value]
                names_by_source[label] = sorted(command["name"] for command in matches)
                dispatch_by_source[label] = {
                    command["name"]: command["dispatch"] for command in matches
                }
            record = {"value_hex": f"0x{value:x}", "count": count,
                      "names_by_source": names_by_source,
                      "dispatch_by_source": dispatch_by_source}
            observed.append(record)
            if not any(names_by_source.values()):
                unmapped.append({"value_hex": record["value_hex"], "count": count})
        claim = item.get("uvm_workload_validated")
        observations[gpu] = {
            "driver": item.get("driver"),
            "driver_api": item.get("driver_api"),
            "trace_input_schema": trace_schema,
            "source_family_hint": ("R580" if str(item.get("driver", "")).startswith("580.")
                                   else "R595" if str(item.get("driver", "")).startswith("595.")
                                   else "unknown"),
            "source_version_match_claimed": False,
            "uvm_workload_validated": claim if type(claim) is bool else None,
            "input_claims_uvm_workload_validated": claim is True,
            "distinct_request_count": len(counts),
            "observed_call_count": sum(counts.values()),
            "commands": observed,
            "unmapped_requests": unmapped,
        }
    return {
        "report": _source_path(path.resolve()),
        "sha256": sha256(raw),
        "schema": data.get("schema"),
        "inputs": observations,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    profiles = {
        "r580_proprietary": read_profile(Path(args.r580_proprietary), "r580_proprietary", "580.178.04"),
        "r580_open": read_profile(Path(args.r580_open), "r580_open", "580.178.04"),
        "r595_open": read_profile(Path(args.r595_open), "r595_open", "595.104.02"),
    }
    trace_paths = args.trace if args.trace else list(DEFAULT_TRACES)
    observations = [_read_trace(Path(path), profiles) for path in trace_paths]
    return {
        "schema": "nvidia-hybrid-uvm-ioctl-surface-v1",
        "qualification": "source-and-command-number-audit-only",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "raw_ioctl_arguments_read": False,
            "ioctl_arguments_read": False,
            "payloads_read": False,
            "pointers_read": False,
            "strace_sidecars_read": False,
            "uvm_workload_executed": False,
            "hardware_compatibility_established": False,
        },
        "sources": profiles,
        "comparisons": {
            "r580_flavors": compare_profiles(profiles["r580_proprietary"], profiles["r580_open"]),
            "r580_to_r595_open": compare_profiles(profiles["r580_proprietary"], profiles["r595_open"]),
        },
        "observations": observations,
    }


def write_exclusive(path: Path, report: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-proprietary", type=Path, default=DEFAULT_R580_PROPRIETARY)
    parser.add_argument("--r580-open", type=Path, default=DEFAULT_R580_OPEN)
    parser.add_argument("--r595-open", type=Path, default=DEFAULT_R595_OPEN)
    parser.add_argument("--trace", type=Path, action="append", default=[])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report.exists():
        print("report already exists", file=sys.stderr)
        return 2
    if not args.report.parent.is_dir():
        print("report parent directory does not exist", file=sys.stderr)
        return 2
    try:
        report = build_report(args)
        write_exclusive(args.report, report)
    except FileExistsError:
        print("report already exists", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"report": str(args.report), "qualification": report["qualification"],
                      "trace_count": len(report["observations"]),
                      "r580_flavors_command_ids_equal": report["comparisons"]["r580_flavors"]["command_ids_equal"],
                      "r580_to_r595_command_ids_equal": report["comparisons"]["r580_to_r595_open"]["command_ids_equal"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
