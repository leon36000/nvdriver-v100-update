#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit counts-only evidence for a class-resolved RUSD map/mmap pair."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterator


MAX_INPUT_BYTES = 16 * 1024 * 1024
EVENT_OPERATIONS = frozenset({"rusd_alloc", "map_memory", "mmap"})
EXPECTED_OUTER_SCHEMA = "nvidia-hybrid-remote-selected-gpu-transport-v1"
EXPECTED_REMOTE_SCHEMA = "nvidia-hybrid-remote-selected-gpu-v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _event_records(value: Any) -> Iterator[dict[str, Any]]:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        require(visited <= 1_000_000, "observer report has too many nested values")
        if isinstance(current, dict):
            operation = current.get("operation")
            if isinstance(operation, str) and operation in EVENT_OPERATIONS:
                yield current
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def _successful_ioctl(record: dict[str, Any]) -> bool:
    exit_packet = record.get("exit")
    return (
        record.get("syscall_return") == 0
        and isinstance(exit_packet, dict)
        and exit_packet.get("status") == 0
    )


def _class_id(packet: Any) -> int | None:
    if not isinstance(packet, dict):
        return None
    value = packet.get("memoryObjectClass")
    if not isinstance(value, dict):
        return None
    class_id = value.get("classId")
    return class_id if type(class_id) is int else None


def _valid_opaque_identity(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value)
    return type(value) is int and value != 0


def _successful_rusd_payload(record: dict[str, Any]) -> bool:
    entry = record.get("entry")
    exit_packet = record.get("exit")
    if not isinstance(entry, dict) or not isinstance(exit_packet, dict):
        return False
    before = entry.get("rusd")
    after = exit_packet.get("rusd")
    if not isinstance(before, dict) or before != after:
        return False
    mask = before.get("polledDataMask")
    return (
        _successful_ioctl(record)
        and entry.get("hClass") == 0xDE
        and exit_packet.get("hClass") == 0xDE
        and before.get("classPayloadBytes") == 8
        and type(mask) is int
        and 0 <= mask <= 0xFFFFFFFFFFFFFFFF
    )


def _successful_rusd_map(record: dict[str, Any]) -> tuple[Any, str] | None:
    entry = record.get("entry")
    exit_packet = record.get("exit")
    if not isinstance(entry, dict) or not isinstance(exit_packet, dict):
        return None
    if (
        not _successful_ioctl(record)
        or _class_id(entry) != 0xDE
        or _class_id(exit_packet) != 0xDE
    ):
        return None
    file_id = entry.get("backendFileId")
    role = entry.get("backendFdRole")
    if (
        not _valid_opaque_identity(file_id)
        or exit_packet.get("backendFileId") != file_id
        or exit_packet.get("backendFdRole") != role
        or not isinstance(role, str)
        or not role
    ):
        return None
    return file_id, role


def _successful_mmap(record: dict[str, Any]) -> tuple[Any, str] | None:
    if record.get("mmap_succeeded") is not True:
        return None
    file_id = record.get("fd_file_id")
    role = record.get("fd_role")
    if (
        not _valid_opaque_identity(file_id)
        or not isinstance(role, str)
        or not role
    ):
        return None
    return file_id, role


def _validate_probe_exit(report: dict[str, Any], remote: dict[str, Any]) -> dict[str, Any]:
    exit_codes = (
        report.get("exit_code"),
        report.get("ssh_exit_code"),
        remote.get("exit_code"),
    )
    if exit_codes == (0, 0, 0):
        return {"missing_sm": [], "tested_sm": []}
    require(exit_codes == (77, 77, 77), "transport report has an unsupported exit code")
    require(
        remote.get("qualification")
        == "rtx5080-report-contract-valid-hybrid-incomplete",
        "exit 77 is not the documented RTX5080 partial-reference result",
    )
    hardware = remote.get("hardware_acceptance")
    require(
        isinstance(hardware, dict)
        and hardware.get("schema") == "nvidia-hybrid-hardware-acceptance-v2"
        and hardware.get("qualification") == "incomplete-hardware-missing"
        and hardware.get("exit_code") == 77
        and hardware.get("validation_errors") == [],
        "exit 77 lacks a clean hardware-acceptance report",
    )
    probe = hardware.get("probe")
    require(
        isinstance(probe, dict)
        and probe.get("schema") == "nvidia-hybrid-probe-v2"
        and probe.get("status") == "incomplete"
        and probe.get("required_sm") == [70, 120]
        and probe.get("missing_sm") == [70]
        and probe.get("hybrid_validated") is False,
        "exit 77 is not exactly the expected missing-SM70 probe result",
    )
    devices = probe.get("devices")
    require(
        isinstance(devices, list)
        and len(devices) == 1
        and isinstance(devices[0], dict)
        and devices[0].get("sm") == 120
        and devices[0].get("tested") is True
        and devices[0].get("architecture_kernel_passed") is True
        and devices[0].get("synchronous_passed") is True
        and devices[0].get("asynchronous_passed") is True
        and devices[0].get("cleanup_passed") is True
        and devices[0].get("cleanup_errors") == [],
        "exit 77 lacks a clean RTX5080 SM120 reference result",
    )
    return {"missing_sm": [70], "tested_sm": [120]}


def summarize_report(report: dict[str, Any], input_sha256: str) -> dict[str, Any]:
    require(
        isinstance(report, dict)
        and report.get("schema") == EXPECTED_OUTER_SCHEMA
        and report.get("target") == "pc3@pc3"
        and report.get("host_key_alias") == "pc3"
        and report.get("ssh_stderr") == "",
        "transport report identity or stderr is invalid",
    )
    remote = report.get("remote")
    require(
        isinstance(remote, dict)
        and remote.get("schema") == EXPECTED_REMOTE_SCHEMA,
        "remote report schema is invalid",
    )
    probe_limit = _validate_probe_exit(report, remote)
    require(
        remote.get("rusd_alloc_capture_requested") is True
        and remote.get("map_memory_capture_requested") is True
        and remote.get("rusd_alloc_records_seen") is True
        and remote.get("map_memory_records_seen") is True,
        "requested RUSD and MAP_MEMORY capture scope is missing",
    )
    stdout = report.get("ssh_stdout")
    require(isinstance(stdout, str) and stdout, "observer output is missing")
    try:
        stdout_report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("remote stdout is not valid JSON") from exc
    require(stdout_report == remote, "remote stdout does not match the report object")
    hardware = remote.get("hardware_acceptance")
    require(
        isinstance(hardware, dict)
        and hardware.get("schema") == "nvidia-hybrid-hardware-acceptance-v2"
        and hardware.get("rusd_alloc_capture_requested") is True
        and hardware.get("map_memory_capture_requested") is True
        and hardware.get("validation_errors") == [],
        "hardware acceptance does not contain a clean RUSD/map capture scope",
    )
    observation = hardware.get("ioctl_observation")
    observer_report = observation.get("report") if isinstance(observation, dict) else None
    require(
        isinstance(observer_report, dict)
        and observer_report.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v22"
        and observer_report.get("trace_complete") is True
        and observer_report.get("child_exit_code") == remote.get("exit_code")
        and observer_report.get("errors") == []
        and observer_report.get("fd_identity_capture_complete") is True,
        "observer trace is incomplete or inconsistent with the probe result",
    )
    require(
        isinstance(input_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", input_sha256) is not None,
        "input report SHA-256 is malformed",
    )
    records = list(_event_records(observer_report.get("records")))
    rusd_records = [r for r in records if r.get("operation") == "rusd_alloc"]
    map_records = [r for r in records if r.get("operation") == "map_memory"]
    mmap_records = [r for r in records if r.get("operation") == "mmap"]
    successful_allocs = [r for r in rusd_records if _successful_rusd_payload(r)]
    stable_zero_masks = [
        r for r in successful_allocs
        if r["entry"]["rusd"]["polledDataMask"] == 0
    ]
    successful_maps = [r for r in map_records if _successful_ioctl(r)]
    rusd_class_maps = [
        r for r in map_records
        if _class_id(r.get("entry")) == 0xDE
        and _class_id(r.get("exit")) == 0xDE
    ]
    successful_rusd_maps = [
        (r, identity)
        for r in rusd_class_maps
        if (identity := _successful_rusd_map(r)) is not None
    ]
    successful_mmaps = [
        (r, identity)
        for r in mmap_records
        if (identity := _successful_mmap(r)) is not None
    ]
    pairs = [
        (map_identity, mmap_identity)
        for _, map_identity in successful_rusd_maps
        for _, mmap_identity in successful_mmaps
        if map_identity[0] == mmap_identity[0]
    ]
    matching_roles = sum(1 for left, right in pairs if left[1] == right[1])
    qualify = (
        len(rusd_records) == 1
        and len(successful_allocs) == 1
        and len(stable_zero_masks) == 1
        and len(rusd_class_maps) == 1
        and len(successful_rusd_maps) == 1
        and len(pairs) == 1
        and matching_roles == 1
    )
    return {
        "schema": "nvidia-hybrid-rusd-map-mmap-correlation-v1",
        "input_report_sha256": input_sha256,
        "qualification": (
            "stock-driver-rusd-map-mmap-correlated"
            if qualify
            else "stock-driver-observation-incomplete"
        ),
        "evidence_level": "installed-driver-observation-only",
        "same_kernel_hybrid_validated": False,
        "probe_limit": probe_limit,
        "opaque_identifiers_emitted": False,
        "counts": {
            "rusd_alloc_records": len(rusd_records),
            "successful_rusd_alloc_records": len(successful_allocs),
            "stable_zero_mask_rusd_alloc_records": len(stable_zero_masks),
            "map_memory_records": len(map_records),
            "successful_map_memory_records": len(successful_maps),
            "rusd_class_map_records": len(rusd_class_maps),
            "successful_rusd_class_map_records": len(successful_rusd_maps),
            "successful_mmap_records": len(successful_mmaps),
            "correlated_rusd_map_mmap_pairs": len(pairs),
            "correlated_pairs_with_matching_role": matching_roles,
        },
    }


def _write_new_private_file(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        size = args.input.stat().st_size
        require(size <= MAX_INPUT_BYTES, "input report exceeds the 16 MiB limit")
        raw = args.input.read_bytes()
        require(len(raw) == size, "input report changed while it was read")
        report = json.loads(raw.decode("utf-8"))
        summary = summarize_report(report, hashlib.sha256(raw).hexdigest())
        encoded = (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _write_new_private_file(args.output, encoded)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"RUSD lifecycle summary failed: {exc}", file=sys.stderr)
        return 2
    print(f"Redacted RUSD lifecycle summary written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
