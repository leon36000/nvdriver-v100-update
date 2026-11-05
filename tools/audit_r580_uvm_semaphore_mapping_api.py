#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the public R580 UVM/RM APIs used to allocate and map semaphore memory.

The result is a hash-pinned static source finding about the declared UVM/RM
interface. It cannot rule out private RM entry points or establish DMA
coherence, runtime behavior, CUDA operation, or cross-provider hardware access.
"""
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
SOURCE_PACKAGE = (
    ROOT / "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open"
)
SOURCE_ROOT = SOURCE_PACKAGE / "nvidia-uvm"
HEADER_PATH = SOURCE_PACKAGE / "common/inc/nv_uvm_interface.h"
RM_SOURCE_PATH = SOURCE_ROOT / "uvm_rm_mem.c"
RM_INTERFACE_PATH = SOURCE_PACKAGE / "nvidia/nv_uvm_interface.c"
RM_GPU_OPS_PATH = SOURCE_PACKAGE / "common/inc/rm-gpu-ops.h"
SOURCE_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
PATCH = ROOT / "patches/r580.178.04/uvm/0002-hybrid-isolated-gpu-execution.patch"
HYBRID_DUP_MEMORY_ROUTE_PATH = ROOT / "src/hybrid580_uvm_dup_memory_route.h"
HYBRID_EXTERNAL_MAPPING_ROUTE_PATH = ROOT / "src/hybrid580_uvm_external_mapping_route.h"
HYBRID_CALLBACK_BRIDGE_PATH = ROOT / "src/hybrid580_uvm_callback_bridge.c"
HYBRID_FRONTEND_PATH = ROOT / "src/hybrid_frontend.c"
HYBRID_MEMORY_OWNER_PATH = ROOT / "src/hybrid580_frontend_uvm_memory_owner.h"
UVM_CONTROL_FD_PATCH = ROOT / "patches/r580.178.04/uvm/0003-pass-control-fd-to-dup-memory.patch"
SOURCE_TAG = "580.178.04"
EXPECTED_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
EXPECTED_PATCH_SHA256 = "23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0"
SOURCE_FILES = ("uvm_rm_mem.c", "uvm_rm_mem.h", "uvm_ioctl.h", "uvm_map_external.c")
EXPECTED_SOURCE_SHA256 = {
    "common/inc/nv_uvm_interface.h": "68b6cae62ad0bdf6940d48a34084d789cd1f87a06b84310195cd2adc4b9e50f8",
    "nvidia-uvm/uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
    "nvidia-uvm/uvm_rm_mem.h": "ced992530152a8fc0e0c9b099cad16a857bcf09b0a1bc4407c0598c53d239c7e",
    "nvidia-uvm/uvm_ioctl.h": "937a3fe1c0b2f4d8cfc18443d41ad10ee85c4445f954cc5c67b460ded2dd4916",
    "nvidia-uvm/uvm_map_external.c": "4115e9f2de1fc9ad460a61168e78e68ede19c57ac6216740dc57475b29d07511",
    "nvidia-uvm/uvm_va_range_device_p2p.c": "64090e24a6cd722769bf2023d3299485ce516eb03334adfbc459ebc0738c19b5",
    "common/inc/rm-gpu-ops.h": "9afee2aa39eb2380c32a9c53a528f3e61d0fe6f972f0e29f88c549742ecb6da0",
    "nvidia/nv_uvm_interface.c": "b41c704d29363dd52dd0ea669ee253a37185f5826c7db56a07dec21c3d24eddc",
}
EXPECTED_HYBRID_SOURCE_SHA256 = {
    "src/hybrid580_uvm_dup_memory_route.h": "77d7c8f5f44a5ecd36be1d631e3fa8bf01843f52880febc8c1ab81e4d03bede7",
    "src/hybrid580_uvm_external_mapping_route.h": "4698cfc5336288b49f2a27f2e7c1767040a4f176f2a06ebe8bd7d4e9c7f639c7",
    "src/hybrid580_uvm_callback_bridge.c": "c581cda76752f4dd4b903442309b5944dd2ff6eb9dd702c6dc4d91345aca86c5",
    "src/hybrid_frontend.c": "fbd58920739764d0be486185b701ba3828f88f92cf7b3444cbe2e310001d92c0",
    "src/hybrid580_frontend_uvm_memory_owner.h": "ce3afb6ade48c0b7fe895e2897199b6b285ec501dec2312cafcdb36d23efa2d7",
}
EXPECTED_UVM_CONTROL_FD_PATCH_SHA256 = "1ea8a83f9af76d1d8189aa04647591d92e02ce7ad3a55db8c55cb13e280c1be6"

RELEVANT_APIS = (
    "nvUvmInterfaceMemoryAllocSys",
    "nvUvmInterfaceMemoryCpuMap",
    "nvUvmInterfaceDupAllocation",
    "nvUvmInterfaceDupMemory",
    "nvUvmInterfaceDupMemoryWithControlFd",
)
RAW_DESCRIPTOR_TYPES = re.compile(
    r"\bstruct\s+page\b|\bdma_addr_t\b|"
    r"\bstruct\s+sg_table\b|\bsg_table\b|"
    r"\bstruct\s+dma_buf\b|\b(?:struct\s+)?scatterlist\b",
    re.IGNORECASE,
)


def read_regular_file_snapshot(path: Path) -> bytes:
    """Read one no-follow regular-file snapshot and reject concurrent changes."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(Path(path), flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"input is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        signature_before = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        )
        signature_after = (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        )
        snapshot = b"".join(chunks)
        if signature_before != signature_after or len(snapshot) != before.st_size:
            raise ValueError(f"input changed while being read: {path}")
        return snapshot
    finally:
        os.close(descriptor)


def sha256_bytes(snapshot: bytes) -> str:
    return hashlib.sha256(snapshot).hexdigest()


def project_path(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _mask_comments_and_literals(source: str) -> str:
    """Replace comments and C literals with spaces while retaining offsets."""
    result = list(source)
    state = "code"
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "*":
                result[index] = result[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == "/" and following == "/":
                result[index] = result[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == '"':
                result[index] = " "
                state = "string"
                escaped = False
            elif char == "'":
                result[index] = " "
                state = "character"
                escaped = False
        elif state in ("block_comment", "line_comment", "string", "character"):
            if char != "\n":
                result[index] = " "
            if state == "block_comment" and char == "*" and following == "/":
                result[index + 1] = " "
                state = "code"
                index += 2
                continue
            if state == "line_comment" and char == "\n":
                state = "code"
            elif state in ("string", "character"):
                quote = '"' if state == "string" else "'"
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    state = "code"
        index += 1
    return "".join(result)


def _interface_prototypes(header_text: str) -> dict[str, str]:
    """Extract complete public UVM interface prototypes from the header."""
    code = _mask_comments_and_literals(header_text)
    prototypes: dict[str, str] = {}
    for match in re.finditer(r"\b(nvUvmInterface[A-Za-z0-9_]*)\s*\(", code):
        name = match.group(1)
        open_paren = code.find("(", match.start(), match.end())
        depth = 0
        close_paren = None
        for index in range(open_paren, len(code)):
            if code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren is None:
            continue
        end = close_paren + 1
        while end < len(code) and code[end].isspace():
            end += 1
        if end >= len(code) or code[end] != ";":
            continue
        signature = re.sub(r"\s+", " ", code[match.start():end + 1]).strip()
        if name in prototypes:
            raise ValueError(f"duplicate public interface prototype: {name}")
        prototypes[name] = signature
    return prototypes


def _doc_comment_before(header_text: str, api_name: str) -> str:
    code = _mask_comments_and_literals(header_text)
    match = re.search(r"\b" + re.escape(api_name) + r"\s*\(", code)
    if match is None:
        return ""
    comment_end = header_text.rfind("*/", 0, match.start())
    if comment_end < 0:
        return ""
    comment_start = header_text.rfind("/*", 0, comment_end)
    if comment_start < 0:
        return ""
    gap = code[comment_end + 2:match.start()]
    if not re.fullmatch(r"\s*(?:NV_STATUS|void)\s*", gap):
        return ""
    return header_text[comment_start:comment_end + 2]


def _function_definition(source_text: str, function_name: str) -> str:
    """Extract one function body using balanced C delimiters after masking literals."""
    code = _mask_comments_and_literals(source_text)
    pattern = re.compile(
        r"\b(?:static\s+)?(?:NV_STATUS|NvU32|void)\s+" + re.escape(function_name) + r"\s*\("
    )
    for match in pattern.finditer(code):
        open_paren = code.find("(", match.start(), match.end())
        depth = 0
        close_paren = None
        for index in range(open_paren, len(code)):
            if code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren is None:
            continue
        cursor = close_paren + 1
        while cursor < len(code) and code[cursor].isspace():
            cursor += 1
        if cursor >= len(code) or code[cursor] != "{":
            continue
        brace_depth = 0
        for end in range(cursor, len(code)):
            if code[end] == "{":
                brace_depth += 1
            elif code[end] == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    return source_text[match.start():end + 1]
    raise ValueError(f"could not extract function definition: {function_name}")


def analyze_interface(
    header_text: str,
    rm_source_text: str,
    ioctl_text: str,
    external_map_text: str,
    rm_interface_text: str | None = None,
    rm_gpu_ops_text: str | None = None,
    hybrid_dup_route_text: str | None = None,
    hybrid_external_route_text: str | None = None,
    hybrid_bridge_text: str | None = None,
    hybrid_frontend_text: str | None = None,
    hybrid_memory_owner_text: str | None = None,
    uvm_control_fd_patch_text: str | None = None,
) -> dict[str, Any]:
    """Analyze supplied source text; public for mutation tests and audit reuse."""
    if rm_interface_text is None:
        rm_interface_text = read_regular_file_snapshot(RM_INTERFACE_PATH).decode("utf-8")
    if rm_gpu_ops_text is None:
        rm_gpu_ops_text = read_regular_file_snapshot(RM_GPU_OPS_PATH).decode("utf-8")
    if hybrid_dup_route_text is None:
        hybrid_dup_route_text = read_regular_file_snapshot(HYBRID_DUP_MEMORY_ROUTE_PATH).decode("utf-8")
    if hybrid_external_route_text is None:
        hybrid_external_route_text = read_regular_file_snapshot(HYBRID_EXTERNAL_MAPPING_ROUTE_PATH).decode("utf-8")
    if hybrid_bridge_text is None:
        hybrid_bridge_text = read_regular_file_snapshot(HYBRID_CALLBACK_BRIDGE_PATH).decode("utf-8")
    if hybrid_frontend_text is None:
        hybrid_frontend_text = read_regular_file_snapshot(HYBRID_FRONTEND_PATH).decode("utf-8")
    if hybrid_memory_owner_text is None:
        hybrid_memory_owner_text = read_regular_file_snapshot(HYBRID_MEMORY_OWNER_PATH).decode("utf-8")
    if uvm_control_fd_patch_text is None:
        uvm_control_fd_patch_text = read_regular_file_snapshot(UVM_CONTROL_FD_PATCH).decode("utf-8")
    prototypes = _interface_prototypes(header_text)
    api_signatures = {name: prototypes.get(name, "") for name in RELEVANT_APIS}
    added_header = uvm_control_fd_patch_text.split("--- /dev/null", maxsplit=1)
    added_header_text = added_header[1] if len(added_header) == 2 else ""
    control_fd_prototype = re.search(
        r"^\+NV_STATUS\s+nvUvmInterfaceDupMemoryWithControlFd\s*\((?P<args>.*?)\);",
        added_header_text,
        re.MULTILINE | re.DOTALL,
    )
    if control_fd_prototype is not None:
        args = re.sub(r"^\+", "", control_fd_prototype.group("args"), flags=re.MULTILINE)
        api_signatures["nvUvmInterfaceDupMemoryWithControlFd"] = re.sub(
            r"\s+", " ",
            "NV_STATUS nvUvmInterfaceDupMemoryWithControlFd(" + args + ");",
        ).strip()
    alloc_sys = api_signatures["nvUvmInterfaceMemoryAllocSys"]
    cpu_map = api_signatures["nvUvmInterfaceMemoryCpuMap"]
    dup_alloc = api_signatures["nvUvmInterfaceDupAllocation"]
    dup_memory = api_signatures["nvUvmInterfaceDupMemory"]
    dup_memory_with_fd = api_signatures["nvUvmInterfaceDupMemoryWithControlFd"]
    dup_doc = _doc_comment_before(header_text, "nvUvmInterfaceDupAllocation")
    dup_doc_code = re.sub(r"/\*|\*/", " ", dup_doc)

    try:
        alloc_body = _function_definition(rm_source_text, "uvm_rm_mem_alloc")
        cpu_map_body = _function_definition(rm_source_text, "uvm_rm_mem_map_cpu")
        gpu_map_body = _function_definition(rm_source_text, "uvm_rm_mem_map_gpu")
        ext_entry = _function_definition(external_map_text, "uvm_map_external_allocation")
        ext_map = _function_definition(external_map_text, "uvm_map_external_allocation_on_gpu")
        ext_pte = _function_definition(external_map_text, "uvm_pte_buffer_get")
        rm_dup_memory = _function_definition(rm_interface_text, "nvUvmInterfaceDupMemory")
        hybrid_dup_memory = _function_definition(hybrid_bridge_text, "nvUvmInterfaceDupMemory")
        hybrid_dup_memory_with_fd = _function_definition(
            hybrid_bridge_text, "nvUvmInterfaceDupMemoryWithControlFd"
        )
        hybrid_owner_pin = _function_definition(
            hybrid_frontend_text, "hybrid580_frontend_uvm_memory_owner_pin_v1"
        )
        hybrid_owner_unpin = _function_definition(
            hybrid_frontend_text, "hybrid580_frontend_uvm_memory_owner_unpin_v1"
        )
        hybrid_owner_quarantine = _function_definition(
            hybrid_frontend_text, "hybrid580_frontend_uvm_memory_owner_quarantine_v1"
        )
    except ValueError:
        alloc_body = cpu_map_body = gpu_map_body = ext_entry = ext_map = ext_pte = ""
        rm_dup_memory = hybrid_dup_memory = hybrid_dup_memory_with_fd = hybrid_owner_pin = ""
        hybrid_owner_unpin = hybrid_owner_quarantine = ""
    ioctl_code = _mask_comments_and_literals(ioctl_text)
    ioctl_struct = re.search(
        r"typedef\s+struct\s*\{(?P<body>[^}]+)\}\s*UVM_MAP_EXTERNAL_ALLOCATION_PARAMS\s*;",
        ioctl_code,
        re.DOTALL,
    )
    ioctl_fields = ioctl_struct.group("body") if ioctl_struct else ""

    checks = {
        "system_memory_allocated_in_rm_va_space": bool(
            re.search(r"\buvmGpuAddressSpaceHandle\s+vaSpace\b", alloc_sys)
            and re.search(r"\bUvmGpuPointer\s*\*\s*gpuPointer\b", alloc_sys)
            and re.search(
                r"if\s*\(\s*type\s*==\s*UVM_RM_MEM_TYPE_SYS\s*\)\s*\{.*?"
                r"nvUvmInterfaceMemoryAllocSys\s*\(\s*gpu->rm_address_space\s*,",
                _mask_comments_and_literals(alloc_body), re.DOTALL,
            )
        ),
        "cpu_mapping_uses_rm_allocation": bool(
            re.search(r"\buvmGpuAddressSpaceHandle\s+vaSpace\b", cpu_map)
            and re.search(r"\bUvmGpuPointer\s+gpuPointer\b", cpu_map)
            and re.search(
                r"nvUvmInterfaceMemoryCpuMap\s*\(\s*gpu->rm_address_space\s*,\s*"
                r"gpu_va\s*,\s*rm_mem->size\s*,",
                _mask_comments_and_literals(cpu_map_body), re.DOTALL,
            )
        ),
        "cross_va_mapping_uses_rm_duplication": bool(
            re.search(
                r"\buvmGpuAddressSpaceHandle\s+srcVaSpace\b.*?\bNvU64\s+srcAddress\b.*?"
                r"\buvmGpuAddressSpaceHandle\s+dstVaSpace\b.*?\bNvU64\s*\*\s*dstAddress\b",
                dup_alloc,
            )
            and re.search(
                r"srcAddress.*?previously returned by.*?nvUvmInterfaceMemoryAllocFB.*?"
                r"nvUvmInterfaceMemoryAllocSys",
                dup_doc_code, re.DOTALL,
            )
            and re.search(
                r"nvUvmInterfaceDupAllocation\s*\(\s*gpu_owner->rm_address_space\s*,\s*"
                r"gpu_owner_va\s*,\s*gpu->rm_address_space\s*,",
                _mask_comments_and_literals(gpu_map_body), re.DOTALL,
            )
        ),
        "physical_duplication_requires_rm_handles": bool(
            re.search(r"\buvmGpuDeviceHandle\s+device\b", dup_memory)
            and re.search(r"\bNvHandle\s+hClient\b", dup_memory)
            and re.search(r"\bNvHandle\s+hPhysMemory\b", dup_memory)
        ),
        "external_mapping_uses_rm_client_and_object_handles": bool(
            re.search(r"\bNvS32\s+rmCtrlFd\s*;", ioctl_fields)
            and re.search(r"\bNvU32\s+hClient\s*;", ioctl_fields)
            and re.search(r"\bNvU32\s+hMemory\s*;", ioctl_fields)
            and re.search(
                r"\.rm_control_fd\s*=\s*params->rmCtrlFd.*?"
                r"\.user_client\s*=\s*params->hClient.*?"
                r"\.user_object\s*=\s*params->hMemory",
                _mask_comments_and_literals(ext_entry), re.DOTALL,
            )
            and re.search(
                r"nvUvmInterfaceDupMemory\s*\(\s*uvm_gpu_device_handle\s*\(\s*mapping_gpu\s*\)\s*,\s*"
                r"user_rm_mem->user_client\s*,\s*user_rm_mem->user_object\s*,\s*"
                r"&ext_gpu_map->mem_handle->rm_handle\s*,",
                _mask_comments_and_literals(ext_map), re.DOTALL,
            )
            and re.search(
                r"nvUvmInterfaceGetExternalAllocPtes\s*\(\s*gpu_va_space->duped_gpu_va_space\s*,\s*"
                r"mem_handle\s*,",
                _mask_comments_and_literals(ext_pte), re.DOTALL,
            )
        ),
    }

    raw_descriptor_api_names = sorted(
        name for name, signature in prototypes.items()
        if RAW_DESCRIPTOR_TYPES.search(signature)
    )
    checks["public_interface_has_no_raw_os_page_import"] = not raw_descriptor_api_names
    failed = sorted(name for name, passed in checks.items() if not passed)
    if raw_descriptor_api_names:
        status = "raw-descriptor-api-found"
    elif failed:
        status = "unresolved"
    else:
        status = "gap-supported"
    handle_path_status = (
        "source-path-present-cross-provider-unresolved"
        if checks["external_mapping_uses_rm_client_and_object_handles"]
        else "unresolved"
    )
    masked_ext_entry = _mask_comments_and_literals(ext_entry)
    masked_ext_map = _mask_comments_and_literals(ext_map)
    masked_rm_dup_memory = _mask_comments_and_literals(rm_dup_memory)
    masked_hybrid_dup_memory = _mask_comments_and_literals(hybrid_dup_memory)
    masked_dup_route = _mask_comments_and_literals(hybrid_dup_route_text)
    masked_external_route = _mask_comments_and_literals(hybrid_external_route_text)
    masked_hybrid_dup_memory_with_fd = _mask_comments_and_literals(hybrid_dup_memory_with_fd)
    masked_hybrid_owner_pin = _mask_comments_and_literals(hybrid_owner_pin)
    masked_control_fd_patch = _mask_comments_and_literals(uvm_control_fd_patch_text)
    cross_provider_checks = {
        "uvm_patch_passes_the_exact_rm_control_fd": bool(
            "nvUvmInterfaceDupMemoryWithControlFd" in uvm_control_fd_patch_text
            and re.search(
                r"nvUvmInterfaceDupMemoryWithControlFd\s*\(\s*\n\+\s*"
                r"user_rm_mem->rm_control_fd\s*,\s*\n\+\s*"
                r"uvm_gpu_device_handle\s*\(\s*mapping_gpu\s*\)",
                masked_control_fd_patch, re.DOTALL,
            )
        ),
        "hybrid_dispatch_resolves_owner_from_control_fd_and_public_handles": bool(
            re.search(r"\bint\s+rmControlFd\b", dup_memory_with_fd)
            and re.search(
                r"hybrid580_frontend_uvm_memory_owner_pin_v1\s*\(\s*rmControlFd\s*,\s*"
                r"\(uint32_t\)hClient\s*,\s*\(uint32_t\)hPhysMemory\s*,\s*&owner\s*\)",
                masked_hybrid_dup_memory_with_fd, re.DOTALL,
            )
            and re.search(r"owner\.backend\s*==\s*HYBRID580_BACKEND_OPEN", masked_hybrid_dup_memory_with_fd)
            and re.search(r"owner\.backend\s*==\s*HYBRID580_BACKEND_LEGACY", masked_hybrid_dup_memory_with_fd)
        ),
        "owner_pin_validates_frontend_fd_root_object_and_pins_memory": bool(
            re.search(r"fget\s*\(\s*\(unsigned int\)rm_control_fd\s*\)", masked_hybrid_owner_pin)
            and "front_file->f_op != &hybrid_front_fops" in masked_hybrid_owner_pin
            and "base->kind != HYBRID_FRONT_CONTROL_FILE" in masked_hybrid_owner_pin
            and re.search(r"hybrid_front_find_root\s*\(\s*state\s*,\s*public_client\s*\)", masked_hybrid_owner_pin)
            and re.search(r"hybrid_front_find_object\s*\(\s*root\s*,\s*public_memory\s*\)", masked_hybrid_owner_pin)
            and re.search(r"owner->backend_memory\s*=\s*memory->backend_handle", masked_hybrid_owner_pin)
            and re.search(r"atomic_inc\s*\(\s*&memory->uvm_memory_pins\s*\)", masked_hybrid_owner_pin)
            and re.search(r"pin->front_file\s*=\s*front_file", masked_hybrid_owner_pin)
            and re.search(r"pin->memory\s*=\s*memory", masked_hybrid_owner_pin)
            and re.search(r"owner->pin\s*=\s*pin", masked_hybrid_owner_pin)
        ),
        "owner_pin_lifecycle_unpins_or_quarantines_the_reference": bool(
            re.search(r"atomic_dec_if_positive\s*\(\s*&pin->memory->uvm_memory_pins\s*\)",
                      _mask_comments_and_literals(hybrid_owner_unpin))
            and re.search(r"fput\s*\(\s*front_file\s*\)",
                          _mask_comments_and_literals(hybrid_owner_unpin))
            and re.search(r"list_add\s*\(\s*&pin->quarantine_link",
                          _mask_comments_and_literals(hybrid_owner_quarantine))
            and re.search(
                r"if\s*\(\s*quarantine\s*\).*?"
                r"hybrid580_frontend_uvm_memory_owner_quarantine_v1\s*\(\s*&owner\s*\)\s*;"
                r"\s*else\s*"
                r"hybrid580_frontend_uvm_memory_owner_unpin_v1\s*\(\s*&owner\s*\)",
                masked_hybrid_dup_memory_with_fd, re.DOTALL,
            )
        ),
        "duplicate_is_rejected_before_call_when_source_and_target_providers_differ": bool(
            re.search(
                r"hybrid580_uvm_device_registry_lookup\s*\(\s*devices\s*,\s*public_device\s*,\s*&provider\s*,\s*&native_device\s*\)",
                masked_dup_route, re.DOTALL,
            )
            and re.search(
                r"if\s*\(\s*provider\s*!=\s*source_provider\s*\)\s*"
                r"return\s+not_supported_status\s*;",
                masked_dup_route, re.DOTALL,
            )
            and re.search(
                r"selected->duplicate\s*\(\s*selected->context\s*,\s*native_device\s*,\s*"
                r"client\s*,\s*physical_handle\s*,",
                masked_dup_route, re.DOTALL,
            )
        ),
        "legacy_dup_memory_abi_fails_closed_without_source_identity": bool(
            re.search(
                r"return\s+NV_ERR_NOT_SUPPORTED\s*;\s*}\s*$",
                _mask_comments_and_literals(hybrid_dup_memory), re.DOTALL,
            )
            and not re.search(
                r"\b(?:hybrid580_uvm_dup_memory_route_duplicate|"
                r"hybrid580_open_dup_memory_ops|hybrid580_legacy_dup_memory_ops)\b",
                _mask_comments_and_literals(hybrid_dup_memory),
            )
        ),
        "mapping_requires_va_space_and_duplicated_memory_to_share_provider": bool(
            re.search(
                r"if\s*\(\s*space_provider\s*!=\s*memory_provider\s*\)\s*"
                r"return\s+HYBRID580_UVM_EXTERNAL_MAPPING_PROVIDER_MISMATCH\s*;",
                masked_external_route, re.DOTALL,
            )
        ),
    }
    cross_provider_status = (
        "source-owner-resolved-same-provider-only"
        if all(cross_provider_checks.values())
        else "unresolved"
    )
    return {
        "status": status,
        "checks": checks,
        "failed_checks": failed,
        "relevant_api_signatures": {
            name.removeprefix("nvUvmInterface"): signature
            for name, signature in api_signatures.items()
        },
        "raw_descriptor_api_names": raw_descriptor_api_names,
        "public_api_prototype_count": len(prototypes),
        "external_handle_path": {
            "status": (
                "source-owner-resolved-same-provider-only"
                if all(cross_provider_checks.values())
                else handle_path_status
            ),
            "ioctl": "UVM_MAP_EXTERNAL_ALLOCATION",
            "handle_fields": ["rmCtrlFd", "hClient", "hMemory"],
            "mapping_path": [
                "uvm_map_external_allocation",
                "nvUvmInterfaceDupMemoryWithControlFd",
                "nvUvmInterfaceGetExternalAllocPtes",
            ],
            "cross_provider_compatibility": "explicitly-rejected-before-rm-duplication",
        },
        "cross_provider_import": {
            "status": cross_provider_status,
            "checks": cross_provider_checks,
            "classification_scope": "pinned R580 UVM external-allocation path plus current hybrid UVM callback bridge",
            "interpretation": (
                "The pinned UVM control-FD patch passes the exact rm_control_fd and public client/memory handles to the bridge. The bridge resolves that descriptor against tracked frontend state, pins the source memory, and obtains its backend provider and native RM handles. The duplicate route checks the target device provider before invoking RM and rejects a mismatch; the legacy ABI without source identity fails closed. This establishes a same-provider source-owner route in the inspected path, not cross-provider memory import, DMA-BUF support, P2P, DMA visibility, ordering, coherence, runtime behavior, or CUDA operation."
            ),
        },
    }


def audit_sources(source_root: Path = SOURCE_ROOT, header_path: Path = HEADER_PATH) -> dict[str, Any]:
    source_root = Path(source_root)
    header_path = Path(header_path)
    if source_root.is_symlink() or header_path.is_symlink():
        raise ValueError("R580 UVM source root and interface header must not be symlinks")
    source_root = source_root.resolve(strict=True)
    header_path = header_path.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be the R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source tree is not NVIDIA R580.178.04")
    if header_path != (source_root.parent / "common/inc/nv_uvm_interface.h").resolve(strict=True):
        raise ValueError("interface header must belong to the same pinned R580 source tree")

    archive = SOURCE_ARCHIVE.resolve(strict=True)
    patch = PATCH.resolve(strict=True)
    control_fd_patch = UVM_CONTROL_FD_PATCH.resolve(strict=True)
    archive_snapshot = read_regular_file_snapshot(archive)
    patch_snapshot = read_regular_file_snapshot(patch)
    control_fd_patch_snapshot = read_regular_file_snapshot(control_fd_patch)
    archive_sha = sha256_bytes(archive_snapshot)
    patch_sha = sha256_bytes(patch_snapshot)
    control_fd_patch_sha = sha256_bytes(control_fd_patch_snapshot)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 archive SHA-256 mismatch")
    if patch_sha != EXPECTED_PATCH_SHA256:
        raise ValueError("isolated-UVM patch SHA-256 mismatch")
    if control_fd_patch_sha != EXPECTED_UVM_CONTROL_FD_PATCH_SHA256:
        raise ValueError("control-FD UVM patch SHA-256 mismatch")

    input_files: dict[str, dict[str, Any]] = {}
    source_snapshots: dict[str, bytes] = {}
    for relative, expected in EXPECTED_SOURCE_SHA256.items():
        path = source_root.parent / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source must be a regular non-symlink file: {relative}")
        snapshot = read_regular_file_snapshot(path)
        actual = sha256_bytes(snapshot)
        if actual != expected:
            raise ValueError(f"pinned source SHA-256 mismatch for {relative}: {actual}")
        source_snapshots[relative] = snapshot
        input_files[relative] = {
            "path": project_path(path),
            "sha256": actual,
            "bytes": len(snapshot),
        }
    input_files["uvm_control_fd_dispatch_patch"] = {
        "path": project_path(control_fd_patch),
        "sha256": control_fd_patch_sha,
        "bytes": len(control_fd_patch_snapshot),
    }

    hybrid_snapshots: dict[str, bytes] = {}
    hybrid_input_files: dict[str, dict[str, Any]] = {}
    for relative, expected in EXPECTED_HYBRID_SOURCE_SHA256.items():
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"hybrid source must be a regular non-symlink file: {relative}")
        snapshot = read_regular_file_snapshot(path)
        actual = sha256_bytes(snapshot)
        if actual != expected:
            raise ValueError(f"pinned hybrid source SHA-256 mismatch for {relative}: {actual}")
        hybrid_snapshots[relative] = snapshot
        hybrid_input_files[relative] = {
            "path": project_path(path),
            "sha256": actual,
            "bytes": len(snapshot),
        }

    result = analyze_interface(
        source_snapshots["common/inc/nv_uvm_interface.h"].decode("utf-8"),
        source_snapshots["nvidia-uvm/uvm_rm_mem.c"].decode("utf-8"),
        source_snapshots["nvidia-uvm/uvm_ioctl.h"].decode("utf-8"),
        source_snapshots["nvidia-uvm/uvm_map_external.c"].decode("utf-8"),
        source_snapshots["nvidia/nv_uvm_interface.c"].decode("utf-8"),
        source_snapshots["common/inc/rm-gpu-ops.h"].decode("utf-8"),
        hybrid_snapshots["src/hybrid580_uvm_dup_memory_route.h"].decode("utf-8"),
        hybrid_snapshots["src/hybrid580_uvm_external_mapping_route.h"].decode("utf-8"),
        hybrid_snapshots["src/hybrid580_uvm_callback_bridge.c"].decode("utf-8"),
        hybrid_snapshots["src/hybrid_frontend.c"].decode("utf-8"),
        hybrid_snapshots["src/hybrid580_frontend_uvm_memory_owner.h"].decode("utf-8"),
        control_fd_patch_snapshot.decode("utf-8"),
    )
    p2p_source = source_snapshots["nvidia-uvm/uvm_va_range_device_p2p.c"].decode("utf-8")
    legacy_p2p_dup_calls = len(re.findall(
        r"\bnvUvmInterfaceDupMemory\s*\(", _mask_comments_and_literals(p2p_source)
    ))
    result["remaining_legacy_dup_memory_call_sites"] = {
        "file": "nvidia-uvm/uvm_va_range_device_p2p.c",
        "count": legacy_p2p_dup_calls,
        "status": (
            "three-direct-calls-hit-fail-closed-legacy-abi"
            if legacy_p2p_dup_calls == 3
            and "uvm_va_range_device_p2p.c" not in control_fd_patch_snapshot.decode("utf-8")
            else "source-or-patch-changed"
        ),
    }
    return {
        "schema": "nvidia-r580-uvm-semaphore-mapping-api-v3",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {
            "source_archive": {"path": project_path(archive), "sha256": archive_sha},
            "patch": {"path": project_path(patch), "sha256": patch_sha},
            "control_fd_dispatch_patch": {
                "path": project_path(control_fd_patch),
                "sha256": control_fd_patch_sha,
                "bytes": len(control_fd_patch_snapshot),
            },
            "source_files": input_files,
            "hybrid_source_files": hybrid_input_files,
        },
        "result": result,
        "interpretation": (
            "The pinned public nvUvmInterface declarations allocate system memory in an RM VA space, "
            "map CPU access to that RM allocation, and duplicate it between RM VA spaces using an "
            "RM allocation address. The physical-memory duplicate API requires RM client and memory "
            "handles. No declared public interface prototype accepts Linux struct page, dma_addr_t, "
            "scatterlist, sg_table, or dma_buf descriptors. The pinned control-FD patch passes "
            "rm_control_fd to the hybrid dispatcher, which resolves tracked source RM ownership and "
            "allows duplication only when the target GPU belongs to that same provider. Cross-provider "
            "duplication remains unsupported; three direct R580 P2P call sites still use the old ABI "
            "and fail closed. The raw-descriptor result is only an API-surface finding, not proof of "
            "DMA visibility, ordering, coherence, P2P, runtime behavior, or hardware operation."
        ),
        "next_experiment": (
            "Determine whether each of the three direct P2P call sites can carry the exact source "
            "control fd and public handles through the same owner resolver. Keep them fail closed if "
            "not. Investigate a separate explicit cross-provider import primitive with per-device "
            "DMA/IOMMU ownership, cache/order guarantees, unwind rules, and fault-progress tests "
            "before claiming cross-provider P2P or attempting any module load."
        ),
    }


def write_json(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources()
        if args.output:
            write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    return 0 if report["result"]["status"] == "gap-supported" else 1


if __name__ == "__main__":
    raise SystemExit(main())
