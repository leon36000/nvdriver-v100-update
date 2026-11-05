#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the R580 UVM/RM interface for provider-routing obligations.

The report is a static source inventory. It does not assert that a bridge,
provider isolation, GPU initialization, or UVM runtime behavior works.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone


API_PREFIX = "nvUvmInterface"
HANDLE_TYPES = (
    "UvmGpuPagingChannelHandle",
    "uvmGpuCopyEngineHandle",
    "uvmGpuAddressSpaceHandle",
    "uvmGpuChannelHandle",
    "uvmGpuSessionHandle",
    "uvmGpuDeviceHandle",
    "uvmGpuTsgHandle",
)
DEVICE_HANDLE = "uvmGpuDeviceHandle"
SESSION_HANDLE = "uvmGpuSessionHandle"


def strip_c_comments(source: str) -> str:
    """Remove C comments while preserving newlines and quoted literals."""
    out = []
    i = 0
    state = "code"
    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == "/" and nxt == "*":
                out.extend("  ")
                i += 2
                state = "block"
                continue
            if char == "/" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "line"
                continue
            out.append(char)
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            i += 1
            continue
        if state == "block":
            if char == "*" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "code"
            else:
                out.append("\n" if char == "\n" else " ")
                i += 1
            continue
        if state == "line":
            if char == "\n":
                out.append(char)
                state = "code"
            else:
                out.append(" ")
            i += 1
            continue
        out.append(char)
        if char == "\\" and i + 1 < len(source):
            out.append(source[i + 1])
            i += 2
            continue
        if (state == "string" and char == '"') or (state == "char" and char == "'"):
            state = "code"
        i += 1
    return "".join(out)


def split_parameters(parameters: str) -> list[str]:
    """Split a C parameter list at top-level commas."""
    if not parameters.strip() or parameters.strip() == "void":
        return []
    result = []
    start = 0
    paren = bracket = brace = 0
    for i, char in enumerate(parameters):
        if char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
        elif char == "," and paren == bracket == brace == 0:
            result.append(parameters[start:i].strip())
            start = i + 1
    result.append(parameters[start:].strip())
    if min(paren, bracket, brace) < 0 or paren or bracket or brace:
        raise ValueError("unbalanced C declarator in parameter list")
    return result


def _matching_paren(source: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unterminated UVM interface prototype")


def _parameter_facts(raw_parameter: str) -> dict:
    handles = []
    for handle_type in HANDLE_TYPES:
        match = re.search(rf"\b{re.escape(handle_type)}\b", raw_parameter)
        if match:
            explicit_pointer_depth = raw_parameter[match.end():].count("*")
            handles.append({
                "type": handle_type,
                "explicit_pointer_depth": explicit_pointer_depth,
                "candidate_direction": "output_or_inout" if explicit_pointer_depth else "input",
            })
    uuid_match = re.search(r"\bNvProcessorUuid\b", raw_parameter)
    return {
        "declaration": " ".join(raw_parameter.split()),
        "handle_parameters": handles,
        "uuid_parameter": bool(uuid_match),
        "callback_parameter": bool(re.search(
            r"\b(?:UvmOps|uvmPmaEvict)[A-Za-z0-9_]*\b", raw_parameter)),
        "void_pointer_parameter": bool(re.search(r"\bvoid\s*\*", raw_parameter)),
    }


def route_class(name: str, parameters: list[dict]) -> tuple[str, str]:
    input_handles = [
        handle["type"]
        for parameter in parameters
        for handle in parameter["handle_parameters"]
        if handle["explicit_pointer_depth"] == 0
    ]
    output_handles = [
        handle["type"]
        for parameter in parameters
        for handle in parameter["handle_parameters"]
        if handle["explicit_pointer_depth"] > 0
    ]
    has_uuid = any(parameter["uuid_parameter"] for parameter in parameters)
    has_callback = any(parameter["callback_parameter"] for parameter in parameters)
    has_fault_state = any(re.search(r"\bUvmGpuFaultInfo\b", p["declaration"])
                          for p in parameters)
    has_csl_context = any(re.search(r"\bUvmCslContext\b", p["declaration"])
                          for p in parameters)
    has_void_pointer = any(p["void_pointer_parameter"] for p in parameters)

    if SESSION_HANDLE in input_handles and has_uuid:
        return "session_plus_uuid", "select GPU provider by UUID and use its child session"
    if has_uuid:
        return "uuid", "resolve the registered physical GPU to one backend"
    if has_fault_state:
        return "embedded_gpu_state", "resolve provider from RM-owned GPU state embedded in UvmGpuFaultInfo"
    if has_csl_context and input_handles:
        return "context_plus_handle", "validate context and typed handle share one provider, then bind context ownership"
    if has_csl_context:
        return "provider_context", "resolve the backend from the CSL context association; do not forward RM-private context pointers across providers"
    if has_void_pointer and input_handles:
        return "handle_plus_opaque_pointer", "route by the typed handle and register/translate provider-owned pointer results"
    if has_void_pointer:
        suffix = "; use provider-aware callback trampolines" if has_callback else ""
        return "provider_opaque_pointer", "resolve provider through an explicit opaque-token map; never forward a foreign backend pointer" + suffix
    device_inputs = input_handles.count(DEVICE_HANDLE)
    if device_inputs >= 2 and name in {
        "nvUvmInterfaceGetP2PCaps", "nvUvmInterfaceP2pObjectCreate"
    }:
        return "paired_device_handles", "require a same-provider pair or an explicit cross-provider policy"
    if len(input_handles) >= 2:
        return "multiple_object_handles", "resolve every handle and reject mixed providers unless this API is explicitly bridged"
    if any(handle != SESSION_HANDLE for handle in input_handles):
        return "single_opaque_handle", "resolve the opaque object token to its provider and native handle"
    if SESSION_HANDLE in input_handles:
        return "session_scope", "resolve the logical session and any child object before dispatch"
    if has_callback or "Callbacks" in name or "UvmOps" in name:
        return "global_callback", "coordinate callback registration, teardown, and exactly-once event delivery"
    if output_handles:
        if SESSION_HANDLE in output_handles:
            return "global_factory", "create one logical session backed by one child session per provider"
        return "global_object_factory", "create a logical token and retain provider ownership for its native object"
    return "global", "define explicit fanout, aggregation, or provider-neutral semantics"


def parse_prototypes(header_text: str) -> list[dict]:
    source = strip_c_comments(header_text)
    pattern = re.compile(r"\b(NV_STATUS|void)\s+(nvUvmInterface[A-Za-z0-9_]+)\s*\(")
    prototypes = []
    for match in pattern.finditer(source):
        open_index = source.find("(", match.start())
        close_index = _matching_paren(source, open_index)
        tail = source[close_index + 1:]
        semicolon = re.match(r"\s*;", tail)
        if semicolon is None:
            continue
        raw_parameters = split_parameters(source[open_index + 1:close_index])
        parameters = [_parameter_facts(item) for item in raw_parameters]
        name = match.group(2)
        classification, obligation = route_class(name, parameters)
        prototypes.append({
            "name": name,
            "return_type": match.group(1),
            "line": source.count("\n", 0, match.start()) + 1,
            "parameters": parameters,
            "route_class": classification,
            "routing_obligation": obligation,
        })
    names = [item["name"] for item in prototypes]
    if len(names) != len(set(names)):
        raise ValueError("duplicate UVM interface declarations")
    return prototypes


def parse_exports(provider_text: str) -> list[str]:
    source = strip_c_comments(provider_text)
    return re.findall(r"\bEXPORT_SYMBOL(?:_GPL)?\s*\(\s*(nvUvmInterface[A-Za-z0-9_]+)\s*\)\s*;", source)


def callsites(api_names: list[str], caller_sources: list[tuple[str, str]]) -> dict[str, list[dict]]:
    found = {name: [] for name in api_names}
    if not api_names:
        return found
    pattern = re.compile(r"\b(" + "|".join(map(re.escape, sorted(api_names, key=len, reverse=True))) + r")\s*\(")
    for relative_path, contents in caller_sources:
        source = strip_c_comments(contents)
        for match in pattern.finditer(source):
            found[match.group(1)].append({
                "path": relative_path,
                "line": source.count("\n", 0, match.start()) + 1,
            })
    return found


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _typedef_struct_body(source: str, tag: str, alias: str) -> str | None:
    clean = strip_c_comments(source)
    match = re.search(rf"typedef\s+struct\s+{re.escape(tag)}\s*\{{", clean)
    if not match:
        return None
    open_brace = clean.find("{", match.start())
    depth = 0
    close_brace = None
    for index in range(open_brace, len(clean)):
        if clean[index] == "{":
            depth += 1
        elif clean[index] == "}":
            depth -= 1
            if depth == 0:
                close_brace = index
                break
    if close_brace is None:
        raise ValueError(f"unterminated typedef struct {tag}")
    if not re.match(rf"\s*{re.escape(alias)}\s*(?:,|;)", clean[close_brace + 1:]):
        raise ValueError(f"typedef struct {tag} does not end as {alias}")
    return clean[open_brace + 1:close_brace]


def type_observations(types_text: str | None) -> dict:
    if types_text is None:
        return {"available": False, "items": {}}
    declarations = {
        "UvmGpuFaultInfo": ("UvmGpuFaultInfo_tag", "UvmGpuFaultInfo"),
        "UvmCslContext": ("UvmCslContext_tag", "UvmCslContext"),
        "UvmGpuPagingChannel": ("UvmGpuPagingChannel_tag", "UvmGpuPagingChannel"),
    }
    items = {}
    for alias, (tag, typedef_name) in declarations.items():
        body = _typedef_struct_body(types_text, tag, typedef_name)
        if body is None:
            raise ValueError(f"missing source typedef {typedef_name}")
        if alias == "UvmGpuFaultInfo":
            items[alias] = {
                "contains_device_pointer": bool(re.search(r"\bstruct\s+Device\s*\*\s*pDevice\s*;", body)),
                "contains_backend_register_mappings": bool(re.search(r"\bvolatile\s+NvU32\s*\*", body)),
            }
        elif alias == "UvmCslContext":
            items[alias] = {
                "contains_rm_context_pointer": bool(re.search(r"\bstruct\s+ccslContext_t\s*\*\s*ctx\s*;", body)),
                "contains_backend_stack_pointer": bool(re.search(r"\bvoid\s*\*\s*nvidia_stack\s*;", body)),
            }
        else:
            items[alias] = {
                "contains_gpu_device_pointer": bool(re.search(r"\bstruct\s+gpuDevice\s*\*\s*device\s*;", body)),
            }
    return {"available": True, "items": items}


def audit_texts(header_text: str, provider_text: str, callers: list[tuple[str, str]],
                expected_count: int, source_version: str = "unspecified",
                source_hashes: dict[str, str] | None = None,
                types_text: str | None = None) -> dict:
    prototypes = parse_prototypes(header_text)
    exports = parse_exports(provider_text)
    duplicates = sorted(name for name in set(exports) if exports.count(name) > 1)
    declared = {item["name"] for item in prototypes}
    exported = set(exports)
    missing_exports = sorted(declared - exported)
    undeclared_exports = sorted(exported - declared)
    if len(prototypes) != expected_count:
        raise ValueError(f"expected {expected_count} declarations, found {len(prototypes)}")
    if duplicates or missing_exports or undeclared_exports:
        raise ValueError(
            "declaration/export set mismatch: "
            f"missing_exports={missing_exports}, undeclared_exports={undeclared_exports}, "
            f"duplicate_exports={duplicates}"
        )

    xrefs = callsites([item["name"] for item in prototypes], callers)
    for item in prototypes:
        item["uvm_callsites"] = xrefs[item["name"]]
        item["uvm_callsite_count"] = len(xrefs[item["name"]])
    route_counts: dict[str, int] = {}
    for item in prototypes:
        route_counts[item["route_class"]] = route_counts.get(item["route_class"], 0) + 1
    return {
        "schema": "nvidia-r580-uvm-interface-ownership-audit-v1",
        "source_version": source_version,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "static-source-contract",
        "scope": {
            "hardware_execution": False,
            "module_load_or_install": False,
            "dual_backend_runtime": False,
            "uvm_workload_validated": False,
            "routing_policy_is_implementation": False,
        },
        "source_inputs": source_hashes or {},
        "opaque_owner_type_evidence": type_observations(types_text),
        "interface": {
            "declared_exported_count": len(prototypes),
            "provider_export_count": len(exports),
            "declaration_export_sets_match": True,
            "duplicate_exports": duplicates,
        },
        "routing_inventory": {
            "by_route_class": dict(sorted(route_counts.items())),
            "apis_with_opaque_handle_inputs": sum(
                any(h["explicit_pointer_depth"] == 0
                    for p in item["parameters"] for h in p["handle_parameters"])
                for item in prototypes
            ),
            "apis_with_multiple_object_handles": sum(
                sum(h["explicit_pointer_depth"] == 0 and h["type"] != SESSION_HANDLE
                    for p in item["parameters"] for h in p["handle_parameters"]) >= 2
                for item in prototypes
            ),
            "apis_with_uuid_parameters": sum(
                any(p["uuid_parameter"] for p in item["parameters"]) for item in prototypes
            ),
            "apis_with_untyped_void_pointer_parameters": sum(
                any(p["void_pointer_parameter"] for p in item["parameters"])
                for item in prototypes
            ),
            "apis_without_observed_uvm_callsite": [
                item["name"] for item in prototypes if not item["uvm_callsite_count"]
            ],
        },
        "apis": prototypes,
    }


def audit_sources(header_path: Path, provider_path: Path, caller_paths: list[Path],
                  source_root: Path, expected_count: int, source_version: str) -> dict:
    header_bytes = header_path.read_bytes()
    provider_bytes = provider_path.read_bytes()
    types_path = source_root / "common/inc/nv_uvm_types.h"
    types_bytes = types_path.read_bytes() if types_path.is_file() else None
    callers = []
    hashes = {
        header_path.relative_to(source_root).as_posix(): sha256_bytes(header_bytes),
        provider_path.relative_to(source_root).as_posix(): sha256_bytes(provider_bytes),
    }
    if types_bytes is not None:
        hashes[types_path.relative_to(source_root).as_posix()] = sha256_bytes(types_bytes)
    for path in caller_paths:
        contents = path.read_bytes()
        relative = path.relative_to(source_root).as_posix()
        callers.append((relative, contents.decode("utf-8", errors="strict")))
        hashes[relative] = sha256_bytes(contents)
    return audit_texts(header_bytes.decode("utf-8", errors="strict"),
                       provider_bytes.decode("utf-8", errors="strict"), callers,
                       expected_count=expected_count,
                       source_version=source_version,
                       source_hashes=dict(sorted(hashes.items())),
                       types_text=(types_bytes.decode("utf-8", errors="strict")
                                   if types_bytes is not None else None))


def write_report(path: Path, report: dict) -> None:
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
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
    parser.add_argument("--source-root", type=Path, required=True,
                        help="extracted NVIDIA R580 kernel-open source root")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-version", default="580.178.04")
    parser.add_argument("--expected-count", type=int, default=76)
    args = parser.parse_args(argv)

    root = args.source_root.resolve(strict=True)
    header = root / "common/inc/nv_uvm_interface.h"
    provider = root / "nvidia/nv_uvm_interface.c"
    uvm_root = root / "nvidia-uvm"
    if not header.is_file() or not provider.is_file() or not uvm_root.is_dir():
        parser.error("source root must contain common/inc/nv_uvm_interface.h, nvidia/nv_uvm_interface.c, and nvidia-uvm/")
    callers = sorted(uvm_root.rglob("*.c"))
    try:
        report = audit_sources(header, provider, callers, root, args.expected_count,
                               args.source_version)
        write_report(args.output, report)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"UVM ownership audit failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "output": str(args.output),
        "declarations_and_exports": report["interface"]["declared_exported_count"],
        "route_classes": report["routing_inventory"]["by_route_class"],
        "qualification": report["qualification"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
