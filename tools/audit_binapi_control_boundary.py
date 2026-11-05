#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the fixed NV2081 header boundary without decoding the opaque payload."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
R580 = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
R595 = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02"
INCLUDE_PARTS = (
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    "src/nvidia/arch/nvalloc/unix/include",
    "kernel-open/common/inc",
)
ABI_FILES = (
    "src/common/sdk/nvidia/inc/class/cl2081.h",
    "src/common/sdk/nvidia/inc/g_finn_rm_api.h",
    "src/common/sdk/nvidia/inc/nvos.h",
    "src/nvidia/src/kernel/rmapi/resource_list.h",
    "src/nvidia/src/kernel/rmapi/rmapi_finn.c",
    "src/nvidia/src/kernel/rmapi/binary_api.c",
    "src/nvidia/interface/rmapi/src/g_finn_rm_api.c",
)
MAX_CORRELATION_BYTES = 1024 * 1024
EXPECTED_CORRELATION_SCHEMA = "nvidia-hybrid-rm-object-correlation-v1"

PROBE_SOURCE = r'''#include <stddef.h>
#include <stdio.h>
#include <class/cl2081.h>
#include <g_finn_rm_api.h>
#include <nvos.h>
_Static_assert(NV2081_BINAPI == 0x2081U, "NV2081 class ID");
_Static_assert(FINN_NV2081_BINAPI_INTERFACE_ID == 0x208101U, "BINAPI interface ID");
_Static_assert(sizeof(NV2081_ALLOC_PARAMETERS) == 4, "NV2081 alloc payload size");
_Static_assert(offsetof(NV2081_ALLOC_PARAMETERS, reserved) == 0, "NV2081 alloc offset");
_Static_assert(sizeof(FINN_RM_API) == 32, "FINN fixed header size");
_Static_assert(offsetof(FINN_RM_API, version) == 0, "FINN version offset");
_Static_assert(offsetof(FINN_RM_API, payloadSize) == 8, "FINN payload offset");
_Static_assert(offsetof(FINN_RM_API, interface) == 16, "FINN interface offset");
_Static_assert(offsetof(FINN_RM_API, message) == 24, "FINN message offset");
_Static_assert(NVOS54_FLAGS_FINN_SERIALIZED == 4, "NVOS54 FINN serialized flag");
int main(void) {
    printf("%zu %zu %zu %zu %zu %zu %zu %u %u %u\n",
           sizeof(NV2081_ALLOC_PARAMETERS),
           offsetof(NV2081_ALLOC_PARAMETERS, reserved),
           sizeof(FINN_RM_API), offsetof(FINN_RM_API, version),
           offsetof(FINN_RM_API, payloadSize), offsetof(FINN_RM_API, interface),
           offsetof(FINN_RM_API, message), NV2081_BINAPI,
           FINN_NV2081_BINAPI_INTERFACE_ID, NVOS54_FLAGS_FINN_SERIALIZED);
    return 0;
}
'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_version(source_root: Path) -> str | None:
    path = source_root / "version.mk"
    if not path.is_file():
        return None
    match = re.search(r"^NVIDIA_VERSION\s*=\s*(\S+)\s*$",
                      path.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match else None


def _class_optional(source_root: Path) -> bool:
    text = (source_root / ABI_FILES[3]).read_text(encoding="utf-8")
    marker = "/* External Class         */ NV2081_BINAPI"
    start = text.find(marker)
    end = text.find("RS_ENTRY(", start + len(marker)) if start >= 0 else -1
    return start >= 0 and end >= 0 and "RS_OPTIONAL(NV2081_ALLOC_PARAMETERS)" in text[start:end]


def _resource_registration_facts(source_root: Path) -> dict[str, Any]:
    path = source_root / "src/nvidia/src/kernel/rmapi/resource_list.h"
    text = path.read_text(encoding="utf-8")
    marker = "/* External Class         */ NV2081_BINAPI"
    position = text.find(marker)
    start = text.rfind("RS_ENTRY(", 0, position) if position >= 0 else -1
    end = text.find("RS_ENTRY(", position + len(marker)) if position >= 0 else -1
    block = text[start:end] if start >= 0 and end >= 0 else ""
    internal = re.search(r"/\* Internal Class\s+\*/\s*(\w+)", block)
    parent = re.search(r"/\* Parents\s+\*/\s*RS_LIST\(classId\((\w+)\)\)", block)
    alloc = re.search(r"/\* Alloc Param Info\s+\*/\s*RS_OPTIONAL\((\w+)\)", block)
    flags_start = block.find("/* Flags")
    flags_end = block.find("/* Required Access Rights", flags_start + 1) if flags_start >= 0 else -1
    flags_text = block[flags_start:flags_end] if flags_start >= 0 and flags_end >= 0 else ""
    flags = sorted(set(re.findall(r"RS_FLAGS_[A-Z0-9_]+", flags_text)))
    return {
        "class_registration_present": bool(block),
        "internal_class": internal.group(1) if internal else None,
        "parent_class": parent.group(1) if parent else None,
        "optional_alloc_parameters": bool(alloc and alloc.group(1) == "NV2081_ALLOC_PARAMETERS"),
        "allocation_flags": flags,
        "alloc_rpc_to_physical_rm": "RS_FLAGS_ALLOC_RPC_TO_PHYS_RM" in flags,
        "alloc_rpc_to_vgpu_host": "RS_FLAGS_ALLOC_RPC_TO_VGPU_HOST" in flags,
        "alloc_gsp_plugin_for_vgpu_gsp": "RS_FLAGS_ALLOC_GSP_PLUGIN_FOR_VGPU_GSP" in flags,
    }


def _dispatch_facts(source_root: Path) -> dict[str, bool]:
    path = source_root / "src/nvidia/src/kernel/rmapi/binary_api.c"
    text = path.read_text(encoding="utf-8")
    start = text.find("binapiControl_IMPL\n(")
    end = text.find("NV_STATUS\nbinapiprivControl_IMPL", start + 1) if start >= 0 else -1
    body = text[start:end] if start >= 0 and end >= 0 else ""
    return {
        "null_command_returns_ok": (
            "NV_STATUS status = NV_OK;" in body and
            "if (RMCTRL_IS_NULL_CMD(pParams->cmd))\n        return NV_OK;" in body),
        "virtual_gpu_routes_to_rpc": (
            "if (IS_VIRTUAL(pGpu))" in body and "NV_RM_RPC_API_CONTROL" in body),
        "firmware_client_routes_to_physical_rm": (
            "else if (IS_FW_CLIENT(pGpu))" in body and
            "pRmApi = GPU_GET_PHYSICAL_RMAPI(pGpu);" in body and
            "status = pRmApi->Control" in body),
        "ordinary_physical_default_is_ok_without_rm_call": (
            "NV_STATUS status = NV_OK;" in body and
            "else if (IS_FW_CLIENT(pGpu))" in body and
            body.count("pRmApi->Control") == 1 and
            body.rstrip().endswith("return status;\n}")),
    }


def _finn_serialization_facts(source_root: Path) -> dict[str, bool]:
    generated_path = source_root / ABI_FILES[-1]
    generated = generated_path.read_text(encoding="utf-8")
    marker = "// Serialize this API to the bit pump."
    start = generated.find(marker)
    end_marker = "} // end finnSerializeRoot_FINN_RM_API"
    end = generated.find(end_marker, start + len(marker)) if start >= 0 else -1
    serializer = generated[start:end + len(end_marker)] if start >= 0 and end >= 0 else ""
    get_size_start = generated.find("NvU64 FinnRmApiGetSerializedSize(")
    get_size_end_marker = "// Size of the unserialized format"
    get_size_end = generated.find(get_size_end_marker,
                                  get_size_start + 1) if get_size_start >= 0 else -1
    get_size = (generated[get_size_start:get_size_end]
                if get_size_start >= 0 and get_size_end >= 0 else "")

    rmapi_finn = (source_root / "src/nvidia/src/kernel/rmapi/rmapi_finn.c").read_text(
        encoding="utf-8")
    ctrl_start = rmapi_finn.find("serverSerializeCtrlDown\n(")
    ctrl_end_marker = "NV_STATUS\nserverSerializeCtrlUp"
    ctrl_end = rmapi_finn.find(ctrl_end_marker, ctrl_start + 1) if ctrl_start >= 0 else -1
    ctrl = rmapi_finn[ctrl_start:ctrl_end] if ctrl_start >= 0 and ctrl_end >= 0 else ""
    listed = "FINN_INTERFACE_ID(FINN_NV2081_BINAPI)" in serializer
    rejects_unknown = ("// Everything else is unsupported." in serializer and
                       "return NV_ERR_NOT_SUPPORTED;" in serializer)
    return {
        "nv2081_interface_is_listed_in_generated_serializer": listed,
        "generated_serializer_rejects_unlisted_interface": rejects_unknown,
        "serialized_size_returns_zero_on_serializer_error": (
            "finnSerializeRoot_FINN_RM_API(interface, message" in get_size and
            "!= NV_OK)\n        return 0;" in get_size),
        "unserialized_control_keeps_original_params_when_size_is_zero": (
            "if (serializedSize == 0)\n            return NV_OK;" in ctrl),
        "finn_serialized_flag_set_only_after_successful_serialization": (
            "*flags |= NVOS54_FLAGS_FINN_SERIALIZED;" in ctrl and
            ctrl.find("*flags |= NVOS54_FLAGS_FINN_SERIALIZED;") >
            ctrl.find("status = FinnRmApiSerializeDown(")),
    }


def _binapi_schema_facts(source_root: Path) -> dict[str, Any]:
    sdk = source_root / "src/common/sdk/nvidia/inc"
    class_header = sdk / "class/cl2081.h"
    finn_header = sdk / "g_finn_rm_api.h"
    class_text = class_header.read_text(encoding="utf-8")
    finn_text = finn_header.read_text(encoding="utf-8")
    class_dir = sdk / "class"
    source_files = sorted([*class_dir.glob("*.h"), *class_dir.glob("*.finn")])
    source_texts = {path: path.read_text(encoding="utf-8") for path in source_files}
    source_texts[finn_header] = finn_text
    message_defs = sorted({name for text in source_texts.values()
                           for name in re.findall(
                               r"^\s*#define\s+(FINN_NV2081_BINAPI\S*_MESSAGE_ID)\b",
                               text, re.MULTILINE)})
    class_structs = sorted(set(re.findall(
        r"typedef\s+struct\s+(NV2081_[A-Z0-9_]+)\s*\{", class_text)))
    command_literal = any(re.search(r"\b0x20810108\b", text, re.IGNORECASE)
                          for text in source_texts.values())
    return {
        "interface_declared": (
            "#define FINN_NV2081_BINAPI_INTERFACE_ID (0x208101U)" in finn_text),
        "interface_aliases_generic_finn_header": (
            "typedef FINN_RM_API FINN_NV2081_BINAPI;" in finn_text),
        "cl2081_finn_input_source_present": (
            (class_dir / "cl2081.finn").is_file()),
        "class_structs_in_cl2081_header": class_structs,
        "message_id_definitions_in_binapi_sdk_headers": message_defs,
        "observed_command_literal_in_binapi_sdk_headers": command_literal,
        "resource_registration": _resource_registration_facts(source_root),
    }


def _probe_release(source_root: Path, compiler: str) -> dict[str, Any]:
    include_dirs = [source_root / part for part in INCLUDE_PARTS]
    if not all(path.is_dir() for path in include_dirs):
        raise ValueError(f"{source_version(source_root)} pinned include tree is incomplete")
    with tempfile.TemporaryDirectory(prefix="nv2081-abi-") as temporary:
        root = Path(temporary)
        source = root / "probe.c"
        binary = root / "probe"
        source.write_text(PROBE_SOURCE, encoding="utf-8")
        command = [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
                   *["-I" + str(path) for path in include_dirs], str(source), "-o", str(binary)]
        built = subprocess.run(command, capture_output=True, text=True,
                               timeout=30, check=False)
        if built.returncode:
            raise ValueError("pinned ABI probe failed to compile")
        ran = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=5, check=False)
        if ran.returncode:
            raise ValueError("pinned ABI probe failed to execute")
        try:
            values = [int(value) for value in ran.stdout.split()]
        except ValueError as exc:
            raise ValueError("pinned ABI probe returned malformed measurements") from exc
        if len(values) != 10:
            raise ValueError("pinned ABI probe returned an unexpected field count")
        alloc_size, alloc_offset, finn_size, version, payload, interface, message, klass, api, flag = values
        return {
            "nv2081_alloc_params_size_bytes": alloc_size,
            "nv2081_alloc_reserved_offset": alloc_offset,
            "finn_rm_api_size_bytes": finn_size,
            "finn_rm_api_offsets": {"version": version, "payloadSize": payload,
                                    "interface": interface, "message": message},
            "nv2081_class_id": klass,
            "nv2081_binapi_interface_id": api,
            "nvos54_finn_serialized_flag": flag,
            "compiler": compiler,
            "compile_flags": ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1"],
        }


def audit_sources(cc: str = "cc") -> dict[str, Any]:
    compiler = shutil.which(cc)
    if compiler is None:
        raise ValueError("C compiler not found")
    roots = {"R580": R580, "R595": R595}
    versions = {label: source_version(tree) for label, tree in roots.items()}
    if versions != {"R580": "580.178.04", "R595": "595.99.02"}:
        raise ValueError("the exact pinned R580/R595 source trees are required")

    files: dict[str, dict[str, str]] = {}
    dispatch: dict[str, dict[str, bool]] = {}
    optional: dict[str, bool] = {}
    probes: dict[str, dict[str, Any]] = {}
    interface_mentions: dict[str, bool] = {}
    finn_serialization: dict[str, dict[str, bool]] = {}
    binapi_schema: dict[str, dict[str, Any]] = {}
    for label, tree in roots.items():
        if not all((tree / rel).is_file() for rel in ABI_FILES):
            raise ValueError(f"{label} pinned ABI source set is incomplete")
        files[label] = {rel: sha256_file(tree / rel) for rel in ABI_FILES}
        dispatch[label] = _dispatch_facts(tree)
        optional[label] = _class_optional(tree)
        probes[label] = _probe_release(tree, compiler)
        generated = (tree / ABI_FILES[-1]).read_text(encoding="utf-8")
        interface_mentions[label] = "FINN_NV2081_BINAPI_INTERFACE_ID" in generated
        finn_serialization[label] = _finn_serialization_facts(tree)
        binapi_schema[label] = _binapi_schema_facts(tree)

    command = 0x20810108
    api_ids = {label: probes[label]["nv2081_binapi_interface_id"] for label in roots}
    return {
        "schema": "nvidia-hybrid-nv2081-control-boundary-v1",
        "qualification": "opaque-control-payload-unresolved",
        "source_comparison": {
            "releases": versions,
            "source_sha256": files,
            "binary_api_c_byte_identical": (
                files["R580"]["src/nvidia/src/kernel/rmapi/binary_api.c"] ==
                files["R595"]["src/nvidia/src/kernel/rmapi/binary_api.c"]),
            "dispatch_facts": dispatch,
            "nv2081_alloc_class_optional": optional,
            "generated_finn_serializer_mentions_nv2081_interface": interface_mentions,
            "finn_serialization_facts": finn_serialization,
            "binapi_schema_facts": binapi_schema,
            "interpretation": (
                "Open source identifies the BinaryApi resource class, Subdevice parent, "
                "allocation RPC/GSP flags and control dispatch branches, but does not expose "
                "the observed proprietary command's 992-byte parameter structure or message-08 schema."),
        },
        "fixed_header_abi": probes,
        "observed_command_decode": {
            "command": command,
            "interface_id": command >> 8,
            "message_id": command & 0xff,
            "matches_r580_binapi_interface": (command >> 8) == api_ids["R580"],
            "matches_r595_binapi_interface": (command >> 8) == api_ids["R595"],
        },
        "payload_boundary": {
            "observed_outer_params_size_bytes": 992,
            "observed_outer_flags": 0,
            "finn_serialized_flag_mask": probes["R580"]["nvos54_finn_serialized_flag"],
            "outer_finn_serialized_flag_set": False,
            "generated_serializer_lists_observed_interface": False,
            "open_source_serializer_rejects_unlisted_interface": True,
            "open_source_unserialized_control_keeps_original_params": True,
            "nested_payload_read": False,
            "finn_rm_api_header_is_the_992_byte_payload": False,
            "payload_pointer_fields_and_message_08_type": "unresolved",
            "routing_policy": "keep generic NV2081_BINAPI RM_CONTROL denied until a typed payload contract is established",
        },
    }


def load_correlation(path: Path) -> tuple[dict[str, Any], str]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CORRELATION_BYTES:
        raise ValueError("correlation input must be a bounded regular file")
    raw = path.read_bytes()
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("correlation input is not valid JSON") from exc
    if not isinstance(report, dict):
        raise ValueError("correlation input must be an object")
    return report, sha256_bytes(raw)


def validate_correlations(inputs: list[tuple[dict[str, Any], str]]) -> list[dict[str, Any]]:
    observations = []
    seen_cases: set[str] = set()
    for report, digest in inputs:
        if (report.get("schema") != EXPECTED_CORRELATION_SCHEMA or
                report.get("qualification") != "nv2081-control-object-correlated" or
                report.get("trace_complete") is not True or
                report.get("nested_pointers_read") is not False or
                report.get("control_count") != 1 or
                not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise ValueError("hardware input is not a complete sanitized class correlation")
        case = report.get("case")
        if case not in ("v100", "rtx5080") or case in seen_cases:
            raise ValueError("hardware inputs must contain one V100 and one RTX5080 report")
        seen_cases.add(case)
        control = report["controls"][0]
        if (control.get("command") != 0x20810108 or control.get("params_size") != 992 or
                control.get("flags") != 0 or
                control.get("outer_finn_serialized_flag_set") is not False or
                control.get("transport_success") is not True or
                control.get("entry_status") != 0 or control.get("exit_status") != 0 or
                control.get("client_root_is_nv01_root_client") is not True or
                control.get("object_is_nv2081_binapi") is not True or
                control.get("header_stable") is not True):
            raise ValueError("hardware observation does not meet the fixed-header correlation contract")
        observations.append({
            "case": case,
            "sanitized_correlation_sha256": digest,
            "trace_source_sha256": report.get("source_sha256"),
            "record_index": control.get("record_index"),
            "command": control["command"],
            "params_size": control["params_size"],
            "flags": control["flags"],
            "outer_finn_serialized_flag_set": False,
            "transport_success": True,
            "entry_status": 0,
            "exit_status": 0,
            "client_root_class_id": control["client_root_class_id"],
            "object_class_id": control["object_class_id"],
            "client_root_is_nv01_root_client": True,
            "object_is_nv2081_binapi": True,
            "nested_payload_read": False,
        })
    if seen_cases != {"v100", "rtx5080"}:
        raise ValueError("both V100 and RTX5080 observations are required")
    observations.sort(key=lambda row: (0 if row["case"] == "v100" else 1))
    return observations


def write_private_exclusive(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise FileNotFoundError("output directory does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
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
    parser.add_argument("--output", required=True, type=Path,
                        help="new mode-0600 audit report")
    parser.add_argument("--correlation", action="append", required=True, type=Path,
                        help="sanitized V100/RTX5080 object-correlation report; pass twice")
    parser.add_argument("--cc", default="cc", help="C compiler used for pinned SDK assertions")
    args = parser.parse_args(argv)
    try:
        source = audit_sources(args.cc)
        hardware = validate_correlations([load_correlation(path)
                                          for path in args.correlation])
        report = {**source, "hardware_observations": hardware,
                  "nested_payload_read": False}
        encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_private_exclusive(args.output, encoded)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"BINAPI boundary audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"qualification": report["qualification"],
                      "hardware_observations": len(hardware),
                      "outer_payload_size": 992,
                      "payload_contract": "unresolved"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
