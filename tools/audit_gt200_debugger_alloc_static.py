#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce a narrow static audit of CUDA's GT200_DEBUGGER allocation path.

This pins two user libraries, open RM headers/dispatch, and an existing
hardware-observed NVOS64 summary. It runs bounded objdump and source-contract
checks; it does not attach a debugger, read process memory, contact a GPU, or
claim runtime behavior.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402

TRACE_SUMMARY = ROOT / "evidence/pc3-volta-blackwell-rm-alloc-header-summary-v1-20261021.json"
TRACE_SUMMARY_SHA256 = "ea06aaf20ee7b6fe8833a047b20e6152e12bfa2cb4ac05b16e525be9e70617db"

LIBRARIES = {
    "580.178.04": {
        "path": ROOT / "build/staging/r58017804-compute-userland-v1/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
        "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
        "start": 0x47A9B0,
        "stop": 0x47AA80,
        "instructions": {
            0x47A9B1: "movd xmm1,r8d",
            0x47A9B6: "movd xmm0,ecx",
            0x47A9BA: "punpckldq xmm0,xmm1",
            0x47A9D0: "mov DWORD PTR [rbp-0x38],edx",
            0x47A9D3: "mov edx,0x83de",
            0x47A9D8: "movq QWORD PTR [rbp-0x4c],xmm0",
            0x47A9E1: "mov DWORD PTR [rbp-0x50],0x0",
            0x47A9EF: "mov DWORD PTR [rbp-0x40],edi",
            0x47A9F2: "mov DWORD PTR [rbp-0x3c],esi",
            0x47A9F5: "mov DWORD PTR [rbp-0x34],0x83de",
            0x47A9FC: "mov QWORD PTR [rbp-0x30],rcx",
            0x47AA00: "mov QWORD PTR [rbp-0x28],0x0",
            0x47AA08: "movups XMMWORD PTR [rbp-0x20],xmm0",
            0x47AA26: "mov ecx,0xc030462b",
            0x47AA2E: "mov edx,0x30",
            0x47AA33: "mov esi,0x2b",
        },
    },
    "595.99.02": {
        "path": ROOT / "build/staging/r595.99.02-compute-userland-v1-20261031/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
        "sha256": "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d",
        "start": 0x430730,
        "stop": 0x430810,
        "instructions": {
            0x430731: "movd xmm1,r8d",
            0x430736: "movd xmm0,ecx",
            0x43073A: "punpckldq xmm0,xmm1",
            0x430750: "mov DWORD PTR [rbp-0x38],edx",
            0x430753: "mov edx,0x83de",
            0x430758: "movq QWORD PTR [rbp-0x4c],xmm0",
            0x430761: "mov DWORD PTR [rbp-0x50],0x0",
            0x43076F: "mov DWORD PTR [rbp-0x40],edi",
            0x430772: "mov DWORD PTR [rbp-0x3c],esi",
            0x430775: "mov DWORD PTR [rbp-0x34],0x83de",
            0x43077C: "mov QWORD PTR [rbp-0x30],rcx",
            0x430780: "mov QWORD PTR [rbp-0x28],0x0",
            0x430788: "movups XMMWORD PTR [rbp-0x20],xmm0",
            0x4307A6: "mov ecx,0xc030462b",
            0x4307AE: "mov edx,0x30",
            0x4307B3: "mov esi,0x2b",
        },
    },
}

SOURCE_ROOTS = {
    "580.178.04": ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04/src",
    "580.196.07": ROOT / "build/experiments/r58019607-uvm-consumer-v10-20261029/NVIDIA-kernel-module-source-580.196.07/src",
    "595.99.02": ROOT / "build/experiments/r595-syncboost-replay-v3/source/src",
    "615.71.10": ROOT / ".cache/upstream/extracted-r615-71-10-20261023/open-gpu-kernel-modules-6f3be8c9c3fb4ed6ffc607a0d32d31ce4db7fba5/src",
}
CLASS_HEADER_SHA256 = "44835665d85dd315f6cb398e6f4a016eea4756acf6088f0c7e800c22c159d21a"
R580_RMAPI_SHA256 = "cef3ea5e0510cf4296d7f5654f9e4eb77c6b3e9e0e8f19442ecbf814b6f6004f"
MODERN_RMAPI_SHA256 = "2622372217127a4ba2f5ff5ca40308b8fb5a7afd0457928e781ce68bb465a892"
SECOND_CLIENT_BODY_SHA256 = "0066c8396db3fa1d1dcee37a1bfa66418c19f55f2e754669e07f27e792639d94"
GT200_RESOURCE_ENTRY_SHA256 = "59c50239f2437ae512846c8a03ebbcfde7f7d3dfdf9b7cd3a2b0810b50aac537"
CONSTRUCTOR_TARGET = "nvidia/src/kernel/gpu/gr/kernel_sm_debugger_session.c"
DEBUGGER_FORWARD_HASHES = {
    "ksmdbgssnInternalControlForward_IMPL": "98be00e114c07f2f1872331564e9dcb8cd59e13c272e6ea5b517ca14493bf228",
    "ksmdbgssnGetInternalObjectHandle_IMPL": "ced5ec8fb843d253c502090c8da43825bd2fda6f85890761429ba88355b419eb",
    "gpuresInternalControlForward_IMPL": "dd371977d23e5b2cbafeea68ecd5648a20dda1b6e3b48453cd39c6913baef292",
    "gpuresGetInternalObjectHandle_IMPL": "1fd1b0a034625a5b9decf102f6883f51e6b6aa372920fc97bb96347ee83a5976",
    "_gpuRmApiControl": "49a309c73d7aea5f919e9d0a8f62c8383457c913325b823ae67ea76b63f07b35",
    "clientGetResourceRef_IMPL": "1ee87ac22f472d73df4f40bd029ab2d8562c71fd84f26d0ced20f4e70386ea36",
    "clientValidateNewResourceHandle_IMPL": "797ee7f741a4c2bb29f7aba6b829db526d9f5065463f5133b6b550c004b9bc28",
}


def _matching_c_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    """Return the position after a balanced C delimiter, ignoring comments and literals."""
    depth = 0
    state = "code"
    escaped = False
    i = start
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "line-comment":
            if ch == "\n":
                state = "code"
            i += 1
            continue
        if state == "block-comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                i += 1
            continue
        if state in {"string", "char"}:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                state = "code"
            i += 1
            continue
        if ch == "/" and nxt == "/":
            state = "line-comment"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            state = "block-comment"
            i += 2
            continue
        if ch == '"':
            state = "string"
        elif ch == "'":
            state = "char"
        elif ch == opening:
            depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError(f"unbalanced C delimiter {opening!r} in source")


def extract_c_function(text: str, name: str) -> str:
    """Extract one function definition, ignoring same-named calls and declarations."""
    for match in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text):
        opening_paren = text.find("(", match.start())
        signature_end = _matching_c_delimiter(text, opening_paren, "(", ")")
        body_start = signature_end
        while body_start < len(text) and text[body_start].isspace():
            body_start += 1
        if body_start >= len(text) or text[body_start] != "{":
            continue
        body_end = _matching_c_delimiter(text, body_start, "{", "}")
        return text[body_start:body_end]
    raise ValueError(f"function definition {name} is missing")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def disassemble(path: Path, start: int, stop: int) -> dict[int, str]:
    output = subprocess.check_output(
        ["objdump", "-D", "-Mintel", "-j", ".text",
         f"--start-address={start:#x}", f"--stop-address={stop:#x}", str(path)],
        text=True,
    )
    instructions = {}
    for line in output.splitlines():
        fields = line.strip().split("\t")
        if len(fields) < 3 or not re.fullmatch(r"[0-9a-f]+:", fields[0]):
            continue
        instructions[int(fields[0][:-1], 16)] = re.sub(r"\s+", " ", fields[-1].strip().lower())
    return instructions


def validate_instruction_map(instructions: dict[int, str], expected: dict[int, str]) -> None:
    for address, fragment in expected.items():
        actual = instructions.get(address)
        if actual != fragment.lower():
            raise ValueError(
                f"disassembly mismatch at {address:#x}: expected {fragment!r}, got {actual!r}"
            )


def constructor_evidence(source: Path, version: str) -> dict:
    """Extract the open RM's target-object, security, and unwind invariants."""
    path = source / CONSTRUCTOR_TARGET
    text = path.read_text()
    name_offset = text.index("ksmdbgssnConstruct_IMPL")
    start = text.rfind("NV_STATUS", 0, name_offset)
    end = text.index("\n/**", name_offset)
    body = text[start:end]
    required = (
        "hAppClient = pNv83deAllocParams->hAppClient;",
        "hClass3dObject = pNv83deAllocParams->hClass3dObject;",
        "serverGetClientUnderLock(&g_resServ, hAppClient, &pAppClient)",
        "clientGetResourceRef(pAppClient, hClass3dObject, &pGrResourceRef)",
        "dynamicCast(pGrResourceRef->pResource, KernelGraphicsObject)",
        "VALIDATE_MATCHING_SEC_TOKENS",
        "RS_ACCESS_DEBUG",
        "pGpu == GPU_RES_GET_GPU(pKernelSMDebuggerSession->pObject)",
        "pParentRef  = pGrResourceRef->pParentRef;",
        "subdeviceGetByInstance(pAppClient,",
        "kgrctxRegisterKernelSMDebuggerSession",
        "_ShareDebugger(pKernelSMDebuggerSession, pCallContext->pResourceRef, pGrResourceRef)",
    )
    missing = [item for item in required if item not in body]
    if missing:
        raise ValueError(f"GT200_DEBUGGER constructor invariants missing in R{version}: {missing}")

    init_at = body.index("_ksmdbgssnInitClient(pGpu, pKernelSMDebuggerSession)")
    register_at = body.index("kgrctxRegisterKernelSMDebuggerSession")
    unwind = ("NvBool                    bRegistered = NV_FALSE;" in body and
              "_ksmdbgssnCleanup(pKernelSMDebuggerSession, pGpu, bRegistered);" in body and
              "failed:" in body)
    return {
        "path": str(path.relative_to(ROOT)),
        "source_sha256": sha256(path),
        "constructor_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "app_client_zero_falls_back_to_caller": (
            "if (hAppClient == NV01_NULL_OBJECT)" in body and
            "hAppClient = pParams->hClient;" in body),
        "debuggee_object_resolved_within_app_client": True,
        "debuggee_must_be_kernel_graphics_object": True,
        "permission_paths": ["matching-security-token", "RS_ACCESS_DEBUG"],
        "debugger_and_debuggee_gpu_equality_checked": True,
        "app_channel_derived_from_debuggee_parent": "pParentRef->hResource" in body,
        "subdevice_selected_from_debuggee_device_and_gpu_instance": True,
        "debugger_session_registered_to_debuggee_graphics_context": True,
        "init_client_precedes_context_registration": init_at < register_at,
        "constructor_failure_cleanup": unwind,
        "cleanup_helper_declared_in_file": "_ksmdbgssnCleanup" in text,
    }


def class_macro_value(header: Path, name: str) -> int:
    text = header.read_text()
    match = re.search(r"^#define\s+" + re.escape(name) +
                      r"\s+\(?\s*(0x[0-9a-fA-F]+)\s*\)?\s*$",
                      text, re.MULTILINE)
    if match is None:
        raise ValueError(f"class macro {name} is missing in {header}")
    return int(match.group(1), 16)


def resource_class_entry(resource_list: Path, class_name: str) -> tuple[str, str]:
    text = resource_list.read_text()
    marker = "/* External Class         */ " + class_name + ","
    if text.count(marker) != 1:
        raise ValueError(f"{class_name} resource entry is missing or ambiguous in {resource_list}")
    marker_offset = text.index(marker)
    start = text.rfind("RS_ENTRY(", 0, marker_offset)
    end = text.find("\nRS_ENTRY(", marker_offset)
    if end < 0:
        end = text.find("\n)", marker_offset)
        if end < 0:
            raise ValueError(f"{class_name} resource entry is unterminated")
        end += 2
    entry = text[start:end]
    internal = re.search(r"/\* Internal Class\s*\*/\s*(\w+)\s*,", entry)
    parents = re.search(r"/\* Parents\s*\*/\s*(.*?)\n\s*/\* Alloc Param Info",
                        entry, re.S)
    if internal is None or parents is None:
        raise ValueError(f"{class_name} resource entry lacks class or parent metadata")
    return entry, (internal.group(1), tuple(
        re.findall(r"classId\((\w+)\)", parents.group(1))))


def channel_ancestry_evidence() -> dict:
    """Pin generation-specific channel classes and Blackwell compute ancestry."""
    result = {}
    for version, source in SOURCE_ROOTS.items():
        inc = source / "common/sdk/nvidia/inc/class"
        resource_list = source / "nvidia/src/kernel/rmapi/resource_list.h"
        entries = {}
        contracts = (
            ("VOLTA_CHANNEL_GPFIFO_A", "clc36f.h", 0xC36F,
             "KernelChannel", ("Device", "KernelChannelGroupApi"), True),
            ("BLACKWELL_CHANNEL_GPFIFO_A", "clc96f.h", 0xC96F,
             "KernelChannel", ("Device", "KernelChannelGroupApi"), True),
            ("BLACKWELL_COMPUTE_B", "clcec0.h", 0xCEC0,
             "KernelGraphicsObject", ("KernelChannel",), False),
        )
        for name, header_name, expected_id, expected_internal, expected_parents, required in contracts:
            header = inc / header_name
            value = class_macro_value(header, name)
            entry, (internal, parents) = resource_class_entry(resource_list, name)
            required_params = "RS_REQUIRED(NV_CHANNEL_ALLOC_PARAMS)" in entry
            if (value != expected_id or internal != expected_internal or
                    parents != expected_parents or required_params != required or
                    "/* Multi-Instance         */ NV_TRUE," not in entry):
                raise ValueError(f"{name} class contract changed in R{version}")
            if name == "BLACKWELL_COMPUTE_B" and "RS_OPTIONAL(NV_GR_ALLOCATION_PARAMETERS)" not in entry:
                raise ValueError(f"{name} allocation-parameter contract changed in R{version}")
            entries[name] = {
                "class_id": f"0x{value:04x}",
                "header": str(header.relative_to(ROOT)),
                "header_sha256": sha256(header),
                "resource_list_sha256": sha256(resource_list),
                "resource_entry_sha256": hashlib.sha256(entry.encode()).hexdigest(),
                "internal_class": internal,
                "parents": list(parents),
                "multi_instance": True,
                "required_channel_alloc_params": required_params,
            }
        result[version] = entries
    return result


def build_gate_evidence() -> dict:
    """Record compile-time Volta/Blackwell gates in each pinned OpenRM tree."""
    expected = {
        "RMCFG_CHIP_GV100": 0,
        "RMCFG_CLASS_VOLTA_CHANNEL_GPFIFO_A": 1,
        "RMCFG_CLASS_VOLTA_USERMODE_A": 1,
        "RMCFG_CLASS_VOLTA_COMPUTE_A": 0,
        "RMCFG_CLASS_BLACKWELL_COMPUTE_B": 1,
    }
    result = {}
    for version, source in SOURCE_ROOTS.items():
        config = source / "nvidia/generated/rmconfig.h"
        text = config.read_text()
        values = {}
        for name, wanted in expected.items():
            match = re.search(r"^#define\s+" + re.escape(name) + r"\s+(\d+)\b",
                              text, re.MULTILINE)
            if match is None:
                raise ValueError(f"{name} missing from generated rmconfig for R{version}")
            value = int(match.group(1))
            if value != wanted:
                raise ValueError(f"{name} changed from audited value in R{version}")
            values[name] = value
        result[version] = {
            "path": str(config.relative_to(ROOT)),
            "sha256": sha256(config),
            "macros": values,
            "implication": "GV100 and Volta compute class are disabled in this OpenRM configuration; Volta channel and usermode classes remain enabled",
        }
    return result


def source_evidence() -> dict:
    result = {}
    body_hashes = set()
    for version, source in SOURCE_ROOTS.items():
        class_header = source / "common/sdk/nvidia/inc/class/cl83de.h"
        rmapi = source / "nvidia/src/kernel/rmapi/rmapi_specific.c"
        resource_list = source / "nvidia/src/kernel/rmapi/resource_list.h"
        if sha256(class_header) != CLASS_HEADER_SHA256:
            raise ValueError(f"cl83de.h pin mismatch for R{version}")
        expected_rmapi = R580_RMAPI_SHA256 if version.startswith("580.") else MODERN_RMAPI_SHA256
        if sha256(rmapi) != expected_rmapi:
            raise ValueError(f"rmapi_specific.c pin mismatch for R{version}")
        text = class_header.read_text()
        struct = re.search(
            r"typedef struct NV83DE_ALLOC_PARAMETERS\s*\{(?P<body>.*?)\}\s*NV83DE_ALLOC_PARAMETERS;",
            text, re.S,
        )
        if struct is None:
            raise ValueError(f"NV83DE_ALLOC_PARAMETERS missing in R{version}")
        body = struct.group("body")
        fields = re.findall(r"NvHandle\s+(\w+)\s*;", body)
        if fields != ["hDebuggerClient_Obsolete", "hAppClient", "hClass3dObject"]:
            raise ValueError(f"unexpected NV83DE allocation fields in R{version}: {fields}")
        if "hDebuggerClient_Obsolete" not in body or "must be zero" not in text:
            raise ValueError(f"obsolete debugger-client field contract missing in R{version}")
        rmapi_text = rmapi.read_text()
        start = rmapi_text.index("serverAllocLookupSecondClient")
        start = rmapi_text.rfind("NV_STATUS", 0, start)
        end = rmapi_text.index("\nNV_STATUS", start + 10)
        body_hash = hashlib.sha256(rmapi_text[start:end].encode()).hexdigest()
        if "case GT200_DEBUGGER:" not in rmapi_text[start:end] or \
                "((NV83DE_ALLOC_PARAMETERS *) pAllocParams)->hAppClient" not in rmapi_text[start:end]:
            raise ValueError(f"dual-client lookup does not use hAppClient in R{version}")
        body_hashes.add(body_hash)
        resource_text = resource_list.read_text()
        marker = "/* External Class         */ GT200_DEBUGGER,"
        if resource_text.count(marker) != 1:
            raise ValueError(f"GT200_DEBUGGER resource entry is missing or ambiguous in R{version}")
        marker_offset = resource_text.index(marker)
        entry_start = resource_text.rfind("RS_ENTRY(", 0, marker_offset)
        entry_end = resource_text.index("\n)", marker_offset) + 2
        entry = resource_text[entry_start:entry_end]
        entry_hash = hashlib.sha256(entry.encode()).hexdigest()
        if entry_hash != GT200_RESOURCE_ENTRY_SHA256:
            raise ValueError(f"GT200_DEBUGGER resource registration differs in R{version}")
        registration_requirements = (
            "/* Internal Class         */ KernelSMDebuggerSession,",
            "/* Multi-Instance         */ NV_TRUE,",
            "/* Parents                */ RS_LIST(classId(Device)),",
            "/* Alloc Param Info       */ RS_REQUIRED(NV83DE_ALLOC_PARAMETERS),",
            "RS_FLAGS_DUAL_CLIENT_LOCK",
        )
        if not all(required in entry for required in registration_requirements):
            raise ValueError(f"GT200_DEBUGGER class registration contract differs in R{version}")
        result[version] = {
            "class_header_sha256": sha256(class_header),
            "rmapi_source_sha256": sha256(rmapi),
            "second_client_lookup_body_sha256": body_hash,
            "resource_list_sha256": sha256(resource_list),
            "gt200_debugger_resource_entry_sha256": entry_hash,
            "class_registration": {
                "internal_class": "KernelSMDebuggerSession",
                "multi_instance": True,
                "parent_external_class": "NV01_DEVICE_0",
                "allocation_parameters": "NV83DE_ALLOC_PARAMETERS",
                "dual_client_lock": True,
            },
            "allocation_fields": fields,
            "second_client_from_payload": "hAppClient",
            "debugger_constructor": constructor_evidence(source, version),
        }
    if body_hashes != {SECOND_CLIENT_BODY_SHA256}:
        raise ValueError("GT200_DEBUGGER second-client lookup body differs across pinned branches")
    return result


def debugger_control_route_evidence() -> dict:
    """Pin the internal-control forwarding and Resource Server object lookup chain."""
    paths = {
        "debugger": "nvidia/src/kernel/gpu/gr/kernel_sm_debugger_session.c",
        "gpu_resource": "nvidia/src/kernel/gpu/gpu_resource.c",
        "gpu": "nvidia/src/kernel/gpu/gpu.c",
        "client": "nvidia/src/libraries/resserv/src/rs_client.c",
        "server": "nvidia/src/libraries/resserv/src/rs_server.c",
    }
    functions = {
        "debugger_forward": ("debugger", "ksmdbgssnInternalControlForward_IMPL"),
        "debugger_object_handle": ("debugger", "ksmdbgssnGetInternalObjectHandle_IMPL"),
        "gpu_resource_forward": ("gpu_resource", "gpuresInternalControlForward_IMPL"),
        "gpu_resource_object_handle": ("gpu_resource", "gpuresGetInternalObjectHandle_IMPL"),
        "gpu_rm_api_control": ("gpu", "_gpuRmApiControl"),
        "client_resource_lookup": ("client", "clientGetResourceRef_IMPL"),
        "client_handle_validation": ("client", "clientValidateNewResourceHandle_IMPL"),
        "resource_server_control": ("server", "serverControl"),
    }
    reports = {}
    hashes_by_function: dict[str, set[str]] = {name: set() for name in functions}
    for version, source in SOURCE_ROOTS.items():
        loaded = {}
        for key, relpath in paths.items():
            path = source / relpath
            if not path.is_file():
                raise ValueError(f"control-route source missing for R{version}: {relpath}")
            loaded[key] = {"path": str(path.relative_to(ROOT)),
                           "sha256": sha256(path), "text": path.read_text()}

        bodies = {}
        for key, (file_key, function_name) in functions.items():
            body = extract_c_function(loaded[file_key]["text"], function_name)
            body_hash = hashlib.sha256(body.encode()).hexdigest()
            bodies[key] = body
            hashes_by_function[key].add(body_hash)
            if function_name in DEBUGGER_FORWARD_HASHES and \
                    body_hash != DEBUGGER_FORWARD_HASHES[function_name]:
                raise ValueError(f"{function_name} body changed in R{version}")

        required = {
            "debugger_forward": (
                "gpuresInternalControlForward_IMPL(staticCast(pKernelSMDebuggerSession, GpuResource), command, pParams, size)",
            ),
            "debugger_object_handle": ("return NV01_NULL_OBJECT;",),
            "gpu_resource_forward": (
                "GPU_GET_PHYSICAL_RMAPI(GPU_RES_GET_GPU(pGpuResource))",
                "RES_GET_CLIENT_HANDLE(pGpuResource)",
                "gpuresGetInternalObjectHandle(pGpuResource)",
                "pRmApi->Control(pRmApi,",
            ),
            "gpu_resource_object_handle": ("return RES_GET_HANDLE(pGpuResource);",),
            "gpu_rm_api_control": (
                "hClient == pGpu->hInternalClient && hObject == pGpu->hInternalSubdevice",
                "pInternalRmApi->Control(pInternalRmApi, hClient, hObject, cmd, pParams, paramsSize)",
            ),
            "client_resource_lookup": (
                "mapFind(&pClient->resourceMap, hResource)",
                "return NV_ERR_OBJECT_NOT_FOUND;",
            ),
            "client_handle_validation": (
                "pClient->hClient == hResource || hResource == 0",
                "return NV_ERR_INVALID_OBJECT_HANDLE;",
            ),
            "resource_server_control": (
                "clientGetResourceRef(pClient, pParams->hObject, &pResourceRef)",
            ),
        }
        for key, fragments in required.items():
            missing = [fragment for fragment in fragments if fragment not in bodies[key]]
            if missing:
                raise ValueError(f"control-route contract {key} changed in R{version}: {missing}")

        reports[version] = {
            "source_files": {key: {"path": value["path"], "sha256": value["sha256"]}
                             for key, value in loaded.items()},
            "function_sha256": {
                key: hashlib.sha256(body.encode()).hexdigest()
                for key, body in bodies.items()
            },
            "debugger_forward_uses_null_object_handle": True,
            "gpu_fast_path_requires_internal_client_and_subdevice_pair": True,
            "fallback_preserves_requested_client_and_object_handles": True,
            "resource_server_looks_up_hObject_in_client_map": True,
            "zero_handle_rejected_for_standard_resource_allocation": True,
        }

    for name, expected in DEBUGGER_FORWARD_HASHES.items():
        key = next(key for key, (_, function_name) in functions.items()
                   if function_name == name)
        if hashes_by_function[key] != {expected}:
            raise ValueError(f"{name} differs across pinned branches")
    if hashes_by_function["resource_server_control"] != {
            "8ac3a0934ce0271589886ed589a599d373b473e5b84a31b5388311f3776dd4d3",
            "0dafd4d91b5066a686b1caa56b6cd04c208c9df30bd90c20e7c0a3d418958be3"}:
        raise ValueError("Resource Server control implementation changed outside pinned R580/R595/R615 bodies")

    return {
        "qualification": "static-open-source-control-flow-only",
        "branches": reports,
        "interpretation": {
            "conditional_route": (
                "If ksmdbgssnInternalControlForward_IMPL reaches the ordinary physical RM control path, "
                "its object handle is NV01_NULL_OBJECT (zero); the GPU cached-subdevice fast path "
                "requires a nonmatching internal-subdevice handle, then Resource Server looks up "
                "hObject in the client resource map. Standard allocation rejects handle zero, so this "
                "route predicts OBJECT_NOT_FOUND unless a separate special mapping or wrapper applies."
            ),
            "not_established": (
                "Static source does not show that an observed GT200_DEBUGGER operation invokes this "
                "virtual forwarding method, nor does it rule out a separate runtime wrapper."
            ),
            "portability": (
                "The debugger forwarding, object-handle, GPU dispatch, and resource-map lookup bodies "
                "are byte-identical across R580.178.04, R580.196.07, R595.99.02, and R615.71.10; "
                "this is not a R580-only implementation that can simply be copied into R595."
            ),
        },
        "runtime_or_hardware_validated": False,
        "gpu_accessed_by_this_audit": False,
    }


def trace_evidence() -> dict:
    if sha256(TRACE_SUMMARY) != TRACE_SUMMARY_SHA256:
        raise ValueError("hardware-observed RM allocation summary hash mismatch")
    summary = json.loads(TRACE_SUMMARY.read_text())
    if summary.get("comparison", {}).get("allocation_payloads_read") is not False:
        raise ValueError("allocation payload boundary changed in the pinned summary")
    result = {}
    for report in summary.get("reports", []):
        role = report.get("role")
        record = next((item for item in report.get("classes", [])
                       if item.get("class_id") == "0x000083de"), None)
        edges = [item for item in report.get("parent_class_edges", [])
                 if item.get("child_class") == "0x000083de"]
        if role not in {"v100", "rtx5080"} or record is None or len(edges) != 1:
            raise ValueError("pinned allocation summary lacks a unique 0x83de record/edge")
        if (record.get("alloc_records") != 1 or
                record.get("non_null_alloc_parameter_pointer_count") != 1 or
                record.get("parameter_size_counts") != [{"bytes": 0, "count": 1}] or
                record.get("embedded_statuses") != [{"count": 1, "status": "0x00000000"}] or
                edges[0].get("parent_class") != "0x00000080" or
                report.get("nested_alloc_parameters_read") is not False):
            raise ValueError(f"pinned 0x83de record boundary changed for {role}")
        result[role] = {
            "allocation_count": 1,
            "class_id": "0x83de",
            "parent_class_id": "0x80",
            "outer_params_size": 0,
            "p_alloc_parms_non_null": True,
            "allocation_status": "NV_OK",
            "nested_payload_observed": False,
            "object_handles_recorded": report.get("object_handles_recorded"),
        }
    if set(result) != {"v100", "rtx5080"}:
        raise ValueError("both V100 and RTX 5080 trace summaries are required")
    return result


def audit() -> dict:
    library_evidence = {}
    for version, config in LIBRARIES.items():
        path = config["path"]
        if sha256(path) != config["sha256"]:
            raise ValueError(f"libcuda hash mismatch for R{version}")
        instructions = disassemble(path, config["start"], config["stop"])
        validate_instruction_map(instructions, config["instructions"])
        library_evidence[version] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": config["sha256"],
            "candidate_function_range": [f"{config['start']:#x}", f"{config['stop']:#x}"],
            "instruction_count_checked": len(config["instructions"]),
            "nvos64_hclass": "0x83de",
            "nvos64_packet_layout": {
                "packet_size": 48,
                "fields": {
                    "hRoot": {"offset": 0, "source": "incoming EDI"},
                    "hObjectParent": {"offset": 4, "source": "incoming ESI"},
                    "hObjectNew": {"offset": 8, "source": "incoming EDX"},
                    "hClass": {"offset": 12, "value": "0x83de"},
                    "pAllocParms": {"offset": 16, "value": "non-null local payload pointer"},
                    "pRightsRequested": {"offset": 24, "value": "NULL"},
                    "paramsSize": {"offset": 32, "value": 0},
                    "flags": {"offset": 36, "value": 0},
                    "status": {"offset": 40, "initial_value": 0},
                },
            },
            "alloc_params_first_handle": "literal zero",
            "alloc_params_second_handle_source": "incoming ECX",
            "alloc_params_third_handle_source": "incoming R8D",
            "ioctl_request": "NV_ESC_RM_ALLOC (0xc030462b)",
            "ioctl_payload_bytes": 48,
            "p_alloc_parms_non_null": True,
            "nvOS64_paramsSize": 0,
        }
    sources = source_evidence()
    debugger_control_route = debugger_control_route_evidence()
    channel_ancestry = channel_ancestry_evidence()
    build_gates = build_gate_evidence()
    trace = trace_evidence()
    return {
        "schema": "gt200-debugger-allocation-static-audit-v7",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "static-binary-and-open-source-correlation-only",
        "tool": {"name": "GNU objdump", "version": subprocess.check_output(
            ["objdump", "--version"], text=True).splitlines()[0]},
        "libraries": library_evidence,
        "source_branches": sources,
        "debugger_control_route": debugger_control_route,
        "channel_ancestry": channel_ancestry,
        "build_gates": build_gates,
        "trace_summary_sha256": TRACE_SUMMARY_SHA256,
        "trace_observations": trace,
        "interpretation": {
            "payload_layout_static": {
                "NV83DE_ALLOC_PARAMETERS": {
                    "size_bytes": 12,
                    "fields": {
                        "hDebuggerClient_Obsolete": {"offset": 0, "value": 0},
                        "hAppClient": {"offset": 4, "source": "incoming ECX"},
                        "hClass3dObject": {"offset": 8, "source": "incoming R8D"},
                    },
                },
                "caveat": "Static register-to-stack assignments only; runtime values and handle ownership were not observed.",
            },
            "cross_client_locking": "RM lookup takes hAppClient as the second client",
            "parent_note": "NVOS64 hObjectParent is a separate incoming argument; the captures classify it as NV01_DEVICE_0 while the debuggee 3D handle is nested in pAllocParms",
            "remaining_unknowns": [
                "runtime values and frontend/backend ownership of hAppClient and hClass3dObject",
                "whether the observed allocation is required for ordinary CUDA initialization",
                "successful allocation under the hybrid frontend",
            ],
        },
        "runtime_or_hardware_validated": False,
        "driver_installed_or_loaded": False,
        "gpu_accessed_by_this_audit": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path,
                        default=ROOT / "evidence/gt200-debugger-alloc-static-v7-20261101.json")
    args = parser.parse_args(argv)
    try:
        report = audit()
        report_path = write_private_evidence_report(args.report, report)
        print(json.dumps({"status": "static-audit-passed", "report": str(report_path),
                          "qualification": report["qualification"]}, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"static audit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
