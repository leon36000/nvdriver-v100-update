#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile pinned UVM ioctl headers and compare observed payload layouts.

This checks host-compiled public UAPI structure sizes/offsets and command
numbers only. It does not execute an ioctl, read captured payloads, or prove
kernel/user-space runtime compatibility.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROBE_SCHEMA = "nvidia-hybrid-uvm-payload-layout-probe-v2"
REPORT_SCHEMA = "nvidia-hybrid-uvm-payload-abi-compare-v3"
SEQUENCE_SCHEMA = "nvidia-hybrid-pc3-v100-context-uvm-sequence-v1"
SEQUENCE_QUALIFICATION = "repeated-stock-driver-context-ioctl-metadata-only"
UVM_HEADERS = ("uvm_ioctl.h", "uvm_linux_ioctl.h", "uvm_types.h")
COMMON_HEADERS = (
    "nvlimits.h", "nvtypes.h", "nvstatus.h", "nvCpuUuid.h", "nv_uvm_user_types.h",
)
EXPECTED_COMMANDS = {
    "UVM_CREATE_RANGE_GROUP": 0x17,
    "UVM_REGISTER_GPU_VASPACE": 0x19,
    "UVM_REGISTER_GPU": 0x25,
    "UVM_PAGEABLE_MEM_ACCESS": 0x27,
    "UVM_PAGEABLE_MEM_ACCESS_ON_GPU": 0x46,
    "UVM_MAP_EXTERNAL_ALLOCATION": 0x21,
    "UVM_MM_INITIALIZE": 0x4B,
    "UVM_INITIALIZE": 0x30000001,
    "UVM_EVENT_CTRL": 0x11,
    "UVM_CREATE_EXTERNAL_RANGE": 0x49,
    "UVM_REGISTER_CHANNEL": 0x1B,
    "UVM_UNREGISTER_CHANNEL": 0x1C,
    "UVM_ALLOC_SEMAPHORE_POOL": 0x44,
    "UVM_VALIDATE_VA_RANGE": 0x48,
    "UVM_MAP_DYNAMIC_PARALLELISM_REGION": 0x41,
    "UVM_FREE": 0x22,
    "UVM_DESTROY_RANGE_GROUP": 0x18,
    "UVM_UNREGISTER_GPU_VASPACE": 0x1A,
}
EXPECTED_LAYOUT_FIELDS = {
    "UVM_INITIALIZE_PARAMS": ("flags", "rmStatus"),
    "UVM_CREATE_RANGE_GROUP_PARAMS": ("rangeGroupId", "rmStatus"),
    "UVM_REGISTER_GPU_PARAMS": (
        "gpu_uuid", "numaEnabled", "numaNodeId", "rmCtrlFd", "hClient", "hSmcPartRef", "rmStatus",
    ),
    "UVM_REGISTER_GPU_VASPACE_PARAMS": (
        "gpuUuid", "rmCtrlFd", "hClient", "hVaSpace", "rmStatus",
    ),
    "UVM_PAGEABLE_MEM_ACCESS_PARAMS": ("pageableMemAccess", "rmStatus"),
    "UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS": ("gpu_uuid", "pageableMemAccess", "rmStatus"),
    "UVM_MM_INITIALIZE_PARAMS": ("uvmFd", "rmStatus"),
    "UVM_CREATE_EXTERNAL_RANGE_PARAMS": ("base", "length", "rmStatus"),
    "UVM_REGISTER_CHANNEL_PARAMS": (
        "gpuUuid", "rmCtrlFd", "hClient", "hChannel", "base", "length", "rmStatus",
    ),
    "UVM_ALLOC_SEMAPHORE_POOL_PARAMS": (
        "base", "length", "perGpuAttributes", "gpuAttributesCount", "rmStatus",
    ),
    "UVM_VALIDATE_VA_RANGE_PARAMS": ("base", "length", "rmStatus"),
    "UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS": ("base", "length", "gpuUuid", "rmStatus"),
    "UVM_DESTROY_RANGE_GROUP_PARAMS": ("rangeGroupId", "rmStatus"),
    "UVM_UNREGISTER_GPU_VASPACE_PARAMS": ("gpuUuid", "rmStatus"),
    "UVM_MAP_EXTERNAL_ALLOCATION_PARAMS": (
        "base", "length", "offset", "perGpuAttributes", "gpuAttributesCount",
        "rmCtrlFd", "hClient", "hMemory", "rmStatus",
    ),
}
BRANCH_LAYOUT_FIELDS = {
    "UVM_EVENT_CTRL_PARAMS": {
        True: ("sessionIndex", "eventQueueIndex", "eventType", "enable", "rmStatus"),
        False: ("eventQueueIndex", "eventType", "enable", "rmStatus"),
    },
    "UVM_FREE_PARAMS": {
        True: ("base", "length", "rmStatus"),
        False: ("base", "rmStatus"),
    },
    "UVM_UNREGISTER_CHANNEL_PARAMS": {
        True: ("gpuUuid", "hClient", "hChannel", "rmStatus"),
        False: ("hClient", "hChannel", "rmStatus"),
    },
}

C_PROBE = r'''#include <stddef.h>
#include <stdio.h>
#include "uvm_linux_ioctl.h"

#define FIELD(type, field, suffix) \
    printf("{\"name\":\"" #field "\",\"offset\":%zu,\"size\":%zu}%s", \
           offsetof(type, field), sizeof(((type *)0)->field), suffix)
#define LAYOUT_BEGIN(type) \
    printf("\"" #type "\":{\"size\":%zu,\"fields\":[", sizeof(type))
#define LAYOUT_END() printf("]}")

int main(void)
{
    printf("{\"schema\":\"nvidia-hybrid-uvm-payload-layout-probe-v2\",\"pointer_bytes\":%zu,"
           "\"r580_abi_profile\":%s,\"event_ctrl_has_session_index\":%s,\"commands\":{",
           sizeof(void *), UVM_R580_ABI_PROFILE ? "true" : "false",
           UVM_R580_ABI_PROFILE ? "true" : "false");
    printf("\"UVM_CREATE_RANGE_GROUP\":%u,", (unsigned int)UVM_CREATE_RANGE_GROUP);
    printf("\"UVM_REGISTER_GPU_VASPACE\":%u,", (unsigned int)UVM_REGISTER_GPU_VASPACE);
    printf("\"UVM_REGISTER_GPU\":%u,", (unsigned int)UVM_REGISTER_GPU);
    printf("\"UVM_PAGEABLE_MEM_ACCESS\":%u,", (unsigned int)UVM_PAGEABLE_MEM_ACCESS);
    printf("\"UVM_PAGEABLE_MEM_ACCESS_ON_GPU\":%u,", (unsigned int)UVM_PAGEABLE_MEM_ACCESS_ON_GPU);
    printf("\"UVM_MAP_EXTERNAL_ALLOCATION\":%u,", (unsigned int)UVM_MAP_EXTERNAL_ALLOCATION);
    printf("\"UVM_MM_INITIALIZE\":%u,", (unsigned int)UVM_MM_INITIALIZE);
    printf("\"UVM_EVENT_CTRL\":%u,", (unsigned int)UVM_EVENT_CTRL);
    printf("\"UVM_CREATE_EXTERNAL_RANGE\":%u,", (unsigned int)UVM_CREATE_EXTERNAL_RANGE);
    printf("\"UVM_REGISTER_CHANNEL\":%u,", (unsigned int)UVM_REGISTER_CHANNEL);
    printf("\"UVM_UNREGISTER_CHANNEL\":%u,", (unsigned int)UVM_UNREGISTER_CHANNEL);
    printf("\"UVM_ALLOC_SEMAPHORE_POOL\":%u,", (unsigned int)UVM_ALLOC_SEMAPHORE_POOL);
    printf("\"UVM_VALIDATE_VA_RANGE\":%u,", (unsigned int)UVM_VALIDATE_VA_RANGE);
    printf("\"UVM_MAP_DYNAMIC_PARALLELISM_REGION\":%u,",
           (unsigned int)UVM_MAP_DYNAMIC_PARALLELISM_REGION);
    printf("\"UVM_FREE\":%u,", (unsigned int)UVM_FREE);
    printf("\"UVM_DESTROY_RANGE_GROUP\":%u,", (unsigned int)UVM_DESTROY_RANGE_GROUP);
    printf("\"UVM_UNREGISTER_GPU_VASPACE\":%u,", (unsigned int)UVM_UNREGISTER_GPU_VASPACE);
    printf("\"UVM_INITIALIZE\":%u},\"layouts\":{", (unsigned int)UVM_INITIALIZE);

    LAYOUT_BEGIN(UVM_INITIALIZE_PARAMS);
    FIELD(UVM_INITIALIZE_PARAMS, flags, ","); FIELD(UVM_INITIALIZE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_CREATE_RANGE_GROUP_PARAMS);
    FIELD(UVM_CREATE_RANGE_GROUP_PARAMS, rangeGroupId, ",");
    FIELD(UVM_CREATE_RANGE_GROUP_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_REGISTER_GPU_PARAMS);
    FIELD(UVM_REGISTER_GPU_PARAMS, gpu_uuid, ",");
    FIELD(UVM_REGISTER_GPU_PARAMS, numaEnabled, ",");
    FIELD(UVM_REGISTER_GPU_PARAMS, numaNodeId, ",");
    FIELD(UVM_REGISTER_GPU_PARAMS, rmCtrlFd, ",");
    FIELD(UVM_REGISTER_GPU_PARAMS, hClient, ",");
    FIELD(UVM_REGISTER_GPU_PARAMS, hSmcPartRef, ",");
    FIELD(UVM_REGISTER_GPU_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_REGISTER_GPU_VASPACE_PARAMS);
    FIELD(UVM_REGISTER_GPU_VASPACE_PARAMS, gpuUuid, ",");
    FIELD(UVM_REGISTER_GPU_VASPACE_PARAMS, rmCtrlFd, ",");
    FIELD(UVM_REGISTER_GPU_VASPACE_PARAMS, hClient, ",");
    FIELD(UVM_REGISTER_GPU_VASPACE_PARAMS, hVaSpace, ",");
    FIELD(UVM_REGISTER_GPU_VASPACE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_PAGEABLE_MEM_ACCESS_PARAMS);
    FIELD(UVM_PAGEABLE_MEM_ACCESS_PARAMS, pageableMemAccess, ",");
    FIELD(UVM_PAGEABLE_MEM_ACCESS_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS);
    FIELD(UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS, gpu_uuid, ",");
    FIELD(UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS, pageableMemAccess, ",");
    FIELD(UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_MM_INITIALIZE_PARAMS);
    FIELD(UVM_MM_INITIALIZE_PARAMS, uvmFd, ",");
    FIELD(UVM_MM_INITIALIZE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_CREATE_EXTERNAL_RANGE_PARAMS);
    FIELD(UVM_CREATE_EXTERNAL_RANGE_PARAMS, base, ",");
    FIELD(UVM_CREATE_EXTERNAL_RANGE_PARAMS, length, ",");
    FIELD(UVM_CREATE_EXTERNAL_RANGE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_REGISTER_CHANNEL_PARAMS);
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, gpuUuid, ",");
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, rmCtrlFd, ",");
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, hClient, ",");
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, hChannel, ",");
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, base, ",");
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, length, ",");
    FIELD(UVM_REGISTER_CHANNEL_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_UNREGISTER_CHANNEL_PARAMS);
#if UVM_R580_ABI_PROFILE
    FIELD(UVM_UNREGISTER_CHANNEL_PARAMS, gpuUuid, ",");
#endif
    FIELD(UVM_UNREGISTER_CHANNEL_PARAMS, hClient, ",");
    FIELD(UVM_UNREGISTER_CHANNEL_PARAMS, hChannel, ",");
    FIELD(UVM_UNREGISTER_CHANNEL_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_ALLOC_SEMAPHORE_POOL_PARAMS);
    FIELD(UVM_ALLOC_SEMAPHORE_POOL_PARAMS, base, ",");
    FIELD(UVM_ALLOC_SEMAPHORE_POOL_PARAMS, length, ",");
    FIELD(UVM_ALLOC_SEMAPHORE_POOL_PARAMS, perGpuAttributes, ",");
    FIELD(UVM_ALLOC_SEMAPHORE_POOL_PARAMS, gpuAttributesCount, ",");
    FIELD(UVM_ALLOC_SEMAPHORE_POOL_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_VALIDATE_VA_RANGE_PARAMS);
    FIELD(UVM_VALIDATE_VA_RANGE_PARAMS, base, ",");
    FIELD(UVM_VALIDATE_VA_RANGE_PARAMS, length, ",");
    FIELD(UVM_VALIDATE_VA_RANGE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS);
    FIELD(UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS, base, ",");
    FIELD(UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS, length, ",");
    FIELD(UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS, gpuUuid, ",");
    FIELD(UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_FREE_PARAMS);
    FIELD(UVM_FREE_PARAMS, base, ",");
#if UVM_R580_ABI_PROFILE
    FIELD(UVM_FREE_PARAMS, length, ",");
#endif
    FIELD(UVM_FREE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_DESTROY_RANGE_GROUP_PARAMS);
    FIELD(UVM_DESTROY_RANGE_GROUP_PARAMS, rangeGroupId, ",");
    FIELD(UVM_DESTROY_RANGE_GROUP_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_UNREGISTER_GPU_VASPACE_PARAMS);
    FIELD(UVM_UNREGISTER_GPU_VASPACE_PARAMS, gpuUuid, ",");
    FIELD(UVM_UNREGISTER_GPU_VASPACE_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_EVENT_CTRL_PARAMS);
#if UVM_R580_ABI_PROFILE
    FIELD(UVM_EVENT_CTRL_PARAMS, sessionIndex, ",");
#endif
    FIELD(UVM_EVENT_CTRL_PARAMS, eventQueueIndex, ",");
    FIELD(UVM_EVENT_CTRL_PARAMS, eventType, ",");
    FIELD(UVM_EVENT_CTRL_PARAMS, enable, ",");
    FIELD(UVM_EVENT_CTRL_PARAMS, rmStatus, "");
    LAYOUT_END(); printf(",");
    LAYOUT_BEGIN(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS);
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, base, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, length, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, offset, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, perGpuAttributes, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, gpuAttributesCount, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, rmCtrlFd, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, hClient, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, hMemory, ",");
    FIELD(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, rmStatus, "");
    LAYOUT_END();
    printf("}}\n");
    return 0;
}
'''


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def validate_branch_profile_header_text(header_text: str, *, r580_abi_profile: bool) -> None:
    """Cross-check branch-conditional C probe fields against exact typedef bodies."""
    branch_members = {
        "UVM_EVENT_CTRL_PARAMS": "sessionIndex",
        "UVM_FREE_PARAMS": "length",
        "UVM_UNREGISTER_CHANNEL_PARAMS": "gpuUuid",
    }
    bodies = {}
    for match in re.finditer(
        r"typedef\s+struct\s*\{(?P<body>.*?)\}\s*(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*;",
        header_text,
        re.DOTALL,
    ):
        name = match.group("name")
        if name in branch_members:
            if name in bodies:
                raise ValueError(f"exact UVM header has duplicate typedef body for {name}")
            bodies[name] = match.group("body")
    for struct_name, member in branch_members.items():
        if struct_name not in bodies:
            raise ValueError(f"exact UVM header lacks typedef body for {struct_name}")
        body = re.sub(r"/\*.*?\*/|//[^\n]*", "", bodies[struct_name], flags=re.DOTALL)
        present = re.search(rf"\b{re.escape(member)}\b", body) is not None
        if present != r580_abi_profile:
            expected = "present" if r580_abi_profile else "absent"
            raise ValueError(
                f"{struct_name}: branch-specific member {member} is not {expected}"
            )


def load_sequence_report(path: Path) -> dict[str, Any]:
    """Validate and summarize the retained repeated V100 request metadata."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("sequence report must be a regular non-symlink file")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("sequence report is unreadable or invalid JSON") from None
    if (not isinstance(raw, dict) or raw.get("schema") != SEQUENCE_SCHEMA or
            raw.get("qualification") != SEQUENCE_QUALIFICATION or
            raw.get("uvm_payloads_observed") is not False):
        raise ValueError("sequence report schema, qualification, or payload boundary is invalid")
    captures = raw.get("captures")
    if not isinstance(captures, list) or len(captures) < 2:
        raise ValueError("sequence report must contain at least two repeated captures")

    normalized_captures = []
    reference_order = None
    reference_requests = None
    seen_capture_names = set()
    for capture in captures:
        if not isinstance(capture, dict):
            raise ValueError("sequence capture entry is malformed")
        capture_name = capture.get("capture")
        capture_hash = capture.get("capture_sha256")
        trace_hash = capture.get("trace_sha256")
        driver_version = capture.get("driver_version")
        order = capture.get("first_seen_request_order")
        requests = capture.get("requests")
        ioctl_count = capture.get("uvm_ioctl_count")
        if (not isinstance(capture_name, str) or not capture_name or
                Path(capture_name).name != capture_name or capture_name in {".", ".."} or
                not isinstance(capture_hash, str) or len(capture_hash) != 64 or
                any(ch not in "0123456789abcdef" for ch in capture_hash) or
                not isinstance(trace_hash, str) or len(trace_hash) != 64 or
                any(ch not in "0123456789abcdef" for ch in trace_hash) or
                not isinstance(driver_version, str) or not driver_version.startswith("580.") or
                not isinstance(capture.get("guest_name"), str) or
                "Tesla V100" not in capture["guest_name"] or
                not isinstance(capture.get("gpu_pci"), str) or not capture["gpu_pci"] or
                not isinstance(capture.get("kernel_release"), str) or
                not capture["kernel_release"] or
                not isinstance(order, list) or not order or
                any(not isinstance(name, str) for name in order) or
                not isinstance(requests, list) or len(requests) != len(order) or
                not _positive_int(ioctl_count)):
            raise ValueError("sequence capture metadata is incomplete or malformed")
        if capture_name in seen_capture_names:
            raise ValueError("sequence capture names are not unique")
        seen_capture_names.add(capture_name)
        request_numbers = {}
        request_counts = 0
        request_order = []
        for request in requests:
            if not isinstance(request, dict):
                raise ValueError("sequence request entry is malformed")
            name = request.get("name")
            number = request.get("request")
            count = request.get("count")
            if (not isinstance(name, str) or name not in EXPECTED_COMMANDS or
                    name in request_numbers or not isinstance(number, str) or
                    not _positive_int(count)):
                raise ValueError("sequence request name, number, or count is invalid")
            try:
                parsed_number = int(number, 0)
            except ValueError:
                raise ValueError("sequence request number is not a base-prefixed integer") from None
            if parsed_number != EXPECTED_COMMANDS[name]:
                raise ValueError("sequence request number differs from the pinned UAPI contract")
            request_numbers[name] = parsed_number
            request_counts += count
            request_order.append(name)
        if request_order != order or request_counts != ioctl_count:
            raise ValueError("sequence request order or aggregate count is inconsistent")
        if reference_order is None:
            reference_order = list(order)
            reference_requests = dict(request_numbers)
        elif order != reference_order or request_numbers != reference_requests:
            raise ValueError("repeated captures disagree on the observed UVM request sequence")
        normalized_captures.append({
            "capture": capture_name,
            "capture_sha256": capture_hash,
            "trace_sha256": trace_hash,
            "driver_version": driver_version,
            "kernel_release": capture.get("kernel_release"),
            "guest_name": capture.get("guest_name"),
            "gpu_pci": capture.get("gpu_pci"),
            "uvm_ioctl_count": ioctl_count,
        })

    if reference_order is None or reference_requests is None:
        raise ValueError("sequence report contains no validated capture requests")
    additional = sorted(set(EXPECTED_COMMANDS) - set(reference_requests))
    return {
        "path": display_path(path),
        "sha256": sha256_file(path),
        "schema": SEQUENCE_SCHEMA,
        "qualification": SEQUENCE_QUALIFICATION,
        "uvm_payloads_observed": False,
        "capture_count": len(normalized_captures),
        "captures": normalized_captures,
        "first_seen_request_order": reference_order,
        "request_numbers": reference_requests,
        "additional_probe_requests_not_in_trace": additional,
        "repeated_order_consistent": True,
    }


def parse_probe_output(stdout: str) -> dict[str, Any]:
    try:
        raw = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        raise ValueError("compiler probe did not return one JSON object") from None
    if not isinstance(raw, dict) or raw.get("schema") != PROBE_SCHEMA:
        raise ValueError("compiler probe schema is invalid")
    if type(raw.get("pointer_bytes")) is not int or raw["pointer_bytes"] != 8:
        raise ValueError("UVM payload probe requires a 64-bit host ABI")
    r580_abi_profile = raw.get("r580_abi_profile")
    has_session_index = raw.get("event_ctrl_has_session_index")
    if (type(r580_abi_profile) is not bool or type(has_session_index) is not bool or
            has_session_index != r580_abi_profile):
        raise ValueError("R580 ABI profile and event-control field profile must agree")
    commands = raw.get("commands")
    if not isinstance(commands, dict) or commands != EXPECTED_COMMANDS:
        raise ValueError("observed UVM command numbers differ from the pinned contract")

    layouts = raw.get("layouts")
    expected_layout_names = set(EXPECTED_LAYOUT_FIELDS) | set(BRANCH_LAYOUT_FIELDS)
    if not isinstance(layouts, dict) or set(layouts) != expected_layout_names:
        raise ValueError("UVM payload layout set is incomplete or unexpected")
    normalized_layouts: dict[str, dict[str, Any]] = {}
    expected_layout_fields = {
        **EXPECTED_LAYOUT_FIELDS,
        **{
            name: variants[r580_abi_profile]
            for name, variants in BRANCH_LAYOUT_FIELDS.items()
        },
    }
    for name, expected_fields in expected_layout_fields.items():
        layout = layouts.get(name)
        if not isinstance(layout, dict) or set(layout) != {"size", "fields"}:
            raise ValueError(f"{name}: malformed structure layout")
        size = layout.get("size")
        fields = layout.get("fields")
        if not _positive_int(size) or size > 65536 or not isinstance(fields, list):
            raise ValueError(f"{name}: malformed structure size or fields")
        if len(fields) != len(expected_fields):
            raise ValueError(f"{name}: field layout is incomplete")
        normalized_fields = []
        previous_end = 0
        for expected, field in zip(expected_fields, fields):
            if (not isinstance(field, dict) or set(field) != {"name", "offset", "size"} or
                    field.get("name") != expected or
                    type(field.get("offset")) is not int or field["offset"] < 0 or
                    not _positive_int(field.get("size")) or
                    field["offset"] + field["size"] > size or
                    field["offset"] < previous_end):
                raise ValueError(f"{name}: malformed field layout")
            previous_end = field["offset"] + field["size"]
            normalized_fields.append({
                "name": expected,
                "offset": field["offset"],
                "size": field["size"],
            })
        normalized_layouts[name] = {"size": size, "fields": normalized_fields}
    return {
        "pointer_bytes": 8,
        "r580_abi_profile": r580_abi_profile,
        "event_ctrl_has_session_index": has_session_index,
        "commands": dict(commands),
        "layouts": normalized_layouts,
    }


def compare_layouts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_layouts = left["layouts"]
    right_layouts = right["layouts"]
    layout_deltas = {
        name: {"left": left_layouts[name], "right": right_layouts[name]}
        for name in (*EXPECTED_LAYOUT_FIELDS, *BRANCH_LAYOUT_FIELDS)
        if left_layouts[name] != right_layouts[name]
    }
    command_deltas = {
        name: {"left": left["commands"].get(name), "right": right["commands"].get(name)}
        for name in EXPECTED_COMMANDS
        if left["commands"].get(name) != right["commands"].get(name)
    }
    return {
        "identical": not layout_deltas and not command_deltas,
        "command_deltas": command_deltas,
        "layout_deltas": layout_deltas,
    }


def _source_files(uvm_root: Path, common_include: Path) -> dict[str, dict[str, Any]]:
    files = {}
    for name in UVM_HEADERS:
        path = uvm_root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required UVM header is missing or is a symlink: {path}")
        files[f"uvm/{name}"] = {
            "path": display_path(path), "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    for name in COMMON_HEADERS:
        path = common_include / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required common header is missing or is a symlink: {path}")
        files[f"common/{name}"] = {
            "path": display_path(path), "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    return files


def _compile_profile(
    label: str, uvm_root: Path, common_include: Path, compiler: Path,
    r580_abi_profile: bool,
) -> dict[str, Any]:
    uvm_root = uvm_root.resolve(strict=True)
    common_include = common_include.resolve(strict=True)
    files = _source_files(uvm_root, common_include)
    try:
        header_text = (uvm_root / "uvm_ioctl.h").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{label}: exact UVM header cannot be read: {exc}") from None
    validate_branch_profile_header_text(header_text, r580_abi_profile=r580_abi_profile)
    with tempfile.TemporaryDirectory(prefix="uvm-payload-abi-") as scratch_name:
        scratch = Path(scratch_name)
        source = scratch / "probe.c"
        binary = scratch / "probe"
        source.write_text(C_PROBE, encoding="utf-8")
        command = [
            str(compiler), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            f"-DUVM_R580_ABI_PROFILE={int(r580_abi_profile)}",
            "-I", str(uvm_root), "-I", str(common_include),
            str(source), "-o", str(binary),
        ]
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        try:
            compiled = subprocess.run(command, text=True, capture_output=True,
                                      check=False, timeout=60, env=environment)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"{label}: compiler failed to execute: {exc}") from None
        if compiled.returncode != 0:
            raise ValueError(f"{label}: UVM header probe did not compile: {compiled.stderr[-4000:]}")
        try:
            executed = subprocess.run([str(binary)], text=True, capture_output=True,
                                       check=False, timeout=10, env=environment)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"{label}: compiled layout probe failed to execute: {exc}") from None
        if executed.returncode != 0:
            raise ValueError(f"{label}: compiled layout probe returned {executed.returncode}")
        layout = parse_probe_output(executed.stdout)
    return {
        "label": label,
        "source_root": display_path(uvm_root),
        "common_include": display_path(common_include),
        "files": files,
        "branch_profile_source_validation": {
            "passed": True,
            "r580_abi_profile": r580_abi_profile,
            "struct_members_checked": {
                "UVM_EVENT_CTRL_PARAMS": "sessionIndex",
                "UVM_FREE_PARAMS": "length",
                "UVM_UNREGISTER_CHANNEL_PARAMS": "gpuUuid",
            },
        },
        "layout": layout,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    observed_sequence = load_sequence_report(args.sequence_report)
    compiler_name = shutil.which(str(args.compiler))
    if compiler_name is None:
        raise ValueError("C compiler was not found")
    compiler = Path(compiler_name).resolve(strict=True)
    version = subprocess.run([str(compiler), "--version"], text=True,
                             capture_output=True, check=False, timeout=10)
    if version.returncode != 0:
        raise ValueError("C compiler version query failed")
    version_line = version.stdout.splitlines()[0] if version.stdout.splitlines() else "unknown"
    target = subprocess.run([str(compiler), "-dumpmachine"], text=True,
                            capture_output=True, check=False, timeout=10)
    if target.returncode != 0 or not target.stdout.strip():
        raise ValueError("C compiler target query failed")

    profiles = {
        "r580_proprietary": _compile_profile(
            "R580 proprietary UVM", args.r580_proprietary, args.r580_proprietary_common,
            compiler, r580_abi_profile=True),
        "r580_open_candidate": _compile_profile(
            "R580 open candidate UVM", args.r580_open, args.r580_open_common,
            compiler, r580_abi_profile=True),
        "r595_open": _compile_profile(
            "R595 v15 UVM", args.r595_open, args.r595_open_common,
            compiler, r580_abi_profile=False),
    }
    comparisons = {
        "r580_proprietary_vs_open_candidate": compare_layouts(
            profiles["r580_proprietary"]["layout"], profiles["r580_open_candidate"]["layout"]),
        "r580_candidate_vs_r595": compare_layouts(
            profiles["r580_open_candidate"]["layout"], profiles["r595_open"]["layout"]),
    }
    return {
        "schema": REPORT_SCHEMA,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "compiled-exact-uapi-header-layout-only",
        "runtime_or_hardware_validated": False,
        "scope": {
            "ioctl_executed": False,
            "trace_payloads_read": False,
            "kernel_vfs_executed": False,
            "runtime_abi_validated": False,
            "only_64_bit_host_layout_compiled": True,
        },
        "compiler": {
            "path": display_path(compiler),
            "sha256": sha256_file(compiler),
            "version": version_line,
            "target": target.stdout.strip(),
            "flags": ["-std=gnu11", "-Wall", "-Wextra", "-Werror"],
        },
        "probe_source_sha256": hashlib.sha256(C_PROBE.encode("utf-8")).hexdigest(),
        "comparator_source_sha256": sha256_file(Path(__file__).resolve()),
        "observed_sequence": observed_sequence,
        "profiles": profiles,
        "comparisons": comparisons,
        "status": "pass" if all(item["identical"] for item in comparisons.values()) else "differences",
        "interpretation": (
            "The sequence report is hash-pinned and validated as repeated R580 stock V100 ioctl request "
            "metadata. All request names in that trace are included in the compiled exact-header probe; "
            "UVM_EVENT_CTRL and UVM_PAGEABLE_MEM_ACCESS_ON_GPU are separately probed requests not seen "
            "in the retained trace. Matching command numbers and host-compiled field layouts are "
            "necessary UAPI evidence, not proof that proprietary userspace sends identical payload values "
            "or that either kernel accepts the other branch's runtime calls. R580 and R595 keep the same "
            "request numbers for the probed commands, but UVM_EVENT_CTRL, UVM_FREE, and "
            "UVM_UNREGISTER_CHANNEL have branch-specific payload layouts."
        ),
    }


def write_exclusive(path: Path, report: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-proprietary", type=Path, required=True)
    parser.add_argument("--r580-proprietary-common", type=Path, required=True)
    parser.add_argument("--r580-open", type=Path, required=True)
    parser.add_argument("--r580-open-common", type=Path, required=True)
    parser.add_argument("--r595-open", type=Path, required=True)
    parser.add_argument("--r595-open-common", type=Path, required=True)
    parser.add_argument("--sequence-report", type=Path, required=True,
                        help="hash-pinned repeated stock V100 UVM request metadata JSON")
    parser.add_argument("--compiler", default="cc")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report.exists() or not args.report.parent.is_dir():
        print("report exists or parent directory is missing", file=sys.stderr)
        return 2
    try:
        report = build_report(args)
        write_exclusive(args.report, report)
    except FileExistsError:
        print("report already exists", file=sys.stderr)
        return 2
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({
        "report": str(args.report),
        "status": report["status"],
        "qualification": report["qualification"],
        "comparisons_identical": {
            name: item["identical"] for name, item in report["comparisons"].items()
        },
    }, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
