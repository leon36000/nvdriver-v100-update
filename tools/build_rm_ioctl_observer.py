#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproducibly build the read-only RM ioctl observer against pinned R580 SDK headers."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/rm_ioctl_observer.c"
UPSTREAM = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
R595_UPSTREAM = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02"
CHANNEL_HEADER = Path("src/common/sdk/nvidia/inc/alloc/alloc_channel.h")
CHANNEL_HEADER_SHA256 = "f0211fbc8bf3f80841f699bf4ccb776d32517308782dfb3c8e99c7652986b5ab"
RUSD_HEADER = Path("src/common/sdk/nvidia/inc/class/cl00de.h")
P2P_HEADER = Path("src/common/sdk/nvidia/inc/class/cl503c.h")
P2P_CONTROL_HEADER = Path("src/common/sdk/nvidia/inc/ctrl/ctrl503c.h")
INCLUDE_PARTS = (
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    "src/nvidia/arch/nvalloc/unix/include",
    "kernel-open/common/inc",
    "kernel-open/nvidia-uvm",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dependencies(depfile: Path) -> list[Path]:
    text = depfile.read_text(encoding="utf-8").replace("\\\n", " ")
    if ":" not in text:
        raise ValueError("compiler dependency file has no target separator")
    paths = {Path(value).resolve() for value in shlex.split(text.split(":", 1)[1])}
    missing = sorted(str(path) for path in paths if not path.is_file())
    if missing:
        raise ValueError("compiler dependency closure contains missing files")
    return sorted(paths)


def persist(report_path: Path, report: dict[str, object]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def release_version(source_root: Path) -> str | None:
    version_file = source_root / "version.mk"
    if not version_file.is_file():
        return None
    match = re.search(r"^NVIDIA_VERSION\s*=\s*(\S+)\s*$",
                      version_file.read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1) if match else None


def channel_payload_abi_evidence() -> dict[str, object]:
    r580_header = UPSTREAM / CHANNEL_HEADER
    r595_header = R595_UPSTREAM / CHANNEL_HEADER
    r580_resource_list = UPSTREAM / "src/nvidia/src/kernel/rmapi/resource_list.h"
    r595_resource_list = R595_UPSTREAM / "src/nvidia/src/kernel/rmapi/resource_list.h"
    result: dict[str, object] = {
        "r580_version": release_version(UPSTREAM),
        "r595_version": release_version(R595_UPSTREAM),
        "r580_version_mk_sha256": sha256(UPSTREAM / "version.mk") if (UPSTREAM / "version.mk").is_file() else None,
        "r595_version_mk_sha256": sha256(R595_UPSTREAM / "version.mk") if (R595_UPSTREAM / "version.mk").is_file() else None,
        "r580_header": str(r580_header),
        "r595_header": str(r595_header),
        "r580_header_sha256": sha256(r580_header) if r580_header.is_file() else None,
        "r595_header_sha256": sha256(r595_header) if r595_header.is_file() else None,
        "r580_resource_list_sha256": sha256(r580_resource_list) if r580_resource_list.is_file() else None,
        "r595_resource_list_sha256": sha256(r595_resource_list) if r595_resource_list.is_file() else None,
        "expected_identical_header_sha256": CHANNEL_HEADER_SHA256,
        "class_payload_size_bytes": 368,
        "byte_identical": False,
        "required_classes": {},
    }
    for source, resource_list in (("R580", r580_resource_list),
                                  ("R595", r595_resource_list)):
        text = resource_list.read_text(encoding="utf-8") if resource_list.is_file() else ""
        for klass in ("VOLTA_CHANNEL_GPFIFO_A", "BLACKWELL_CHANNEL_GPFIFO_A"):
            marker = "/* External Class         */ " + klass
            position = text.find(marker)
            next_entry = text.find("RS_ENTRY(", position + len(marker)) if position >= 0 else -1
            block = text[position:next_entry] if position >= 0 and next_entry >= 0 else ""
            result["required_classes"][f"{source}:{klass}"] = (
                "RS_REQUIRED(NV_CHANNEL_ALLOC_PARAMS)" in block)
    result["byte_identical"] = (
        result["r580_version"] == "580.178.04" and
        result["r595_version"] == "595.99.02" and
        result["r580_header_sha256"] == CHANNEL_HEADER_SHA256 and
        result["r595_header_sha256"] == CHANNEL_HEADER_SHA256 and
        all(result["required_classes"].values()) and
        len(result["required_classes"]) == 4)
    return result


def rusd_payload_abi_evidence(cc: str = "cc") -> dict[str, object]:
    """Compile the required RUSD class payload against both pinned SDKs."""
    import tempfile

    compiler = shutil.which(cc)
    result: dict[str, object] = {
        "r580_version": release_version(UPSTREAM),
        "r595_version": release_version(R595_UPSTREAM),
        "r580_header": str(UPSTREAM / RUSD_HEADER),
        "r595_header": str(R595_UPSTREAM / RUSD_HEADER),
        "r580_header_sha256": sha256(UPSTREAM / RUSD_HEADER),
        "r595_header_sha256": sha256(R595_UPSTREAM / RUSD_HEADER),
        "r580_resource_list_sha256": sha256(UPSTREAM / "src/nvidia/src/kernel/rmapi/resource_list.h"),
        "r595_resource_list_sha256": sha256(R595_UPSTREAM / "src/nvidia/src/kernel/rmapi/resource_list.h"),
        "measurements": {},
        "required_classes": {},
        "poll_mask_constants": {},
        "compiler": compiler,
        "byte_identical": False,
    }
    if compiler is None:
        result["error"] = "C compiler not found"
        return result

    measurements: dict[str, dict[str, int] | None] = {}
    for label, tree in (("R580", UPSTREAM), ("R595", R595_UPSTREAM)):
        header = tree / RUSD_HEADER
        source = tree / "src/nvidia/src/kernel/rmapi/resource_list.h"
        if not header.is_file() or not source.is_file():
            result["error"] = label + " RUSD source is missing"
            return result
        text = source.read_text(encoding="utf-8")
        marker = "/* External Class         */ RM_USER_SHARED_DATA"
        start = text.find(marker)
        end = text.find("RS_ENTRY(", start + len(marker)) if start >= 0 else -1
        block = text[start:end] if start >= 0 and end >= 0 else ""
        result["required_classes"][label] = (
            "RS_REQUIRED(NV00DE_ALLOC_PARAMETERS)" in block)
        header_text = header.read_text(encoding="utf-8")
        constants = {}
        for name in ("CLOCK", "PERF", "MEMORY", "POWER", "THERMAL", "PCI", "FAN"):
            match = re.search(r"^#define NV00DE_RUSD_POLL_" + name + r"\s+(0x[0-9a-fA-F]+)\s*$",
                              header_text, re.MULTILINE)
            if match:
                constants[name] = int(match.group(1), 16)
        result["poll_mask_constants"][label] = constants

        include_dirs = [tree / part for part in INCLUDE_PARTS]
        if not all(path.is_dir() for path in include_dirs):
            result["error"] = label + " pinned include tree is incomplete"
            return result
        probe_source = (
            "#include <stddef.h>\n#include <stdio.h>\n"
            "#include <class/cl00de.h>\n"
            "_Static_assert(RM_USER_SHARED_DATA == 0xde, \"RUSD class\");\n"
            "_Static_assert(sizeof(NV00DE_ALLOC_PARAMETERS) == 8, \"RUSD size\");\n"
            "_Static_assert(offsetof(NV00DE_ALLOC_PARAMETERS, polledDataMask) == 0, \"RUSD offset\");\n"
            "int main(void) { printf(\"%zu %zu\\n\", sizeof(NV00DE_ALLOC_PARAMETERS), "
            "offsetof(NV00DE_ALLOC_PARAMETERS, polledDataMask)); return 0; }\n")
        with tempfile.TemporaryDirectory(prefix="rusd-abi-probe-") as temporary:
            root = Path(temporary)
            source_path = root / "probe.c"
            binary_path = root / "probe"
            source_path.write_text(probe_source, encoding="utf-8")
            command = [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
                       *["-I" + str(path) for path in include_dirs], str(source_path),
                       "-o", str(binary_path)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=30, check=False)
            if built.returncode:
                result["error"] = (label + " RUSD ABI compile failed: " +
                                   (built.stderr or built.stdout)[-3000:])
                return result
            measured = subprocess.run([str(binary_path)], capture_output=True, text=True,
                                      timeout=5, check=False)
            if measured.returncode:
                result["error"] = label + " RUSD ABI probe failed"
                return result
            try:
                size, offset = (int(value) for value in measured.stdout.split())
            except (ValueError, TypeError):
                result["error"] = label + " RUSD ABI probe output is invalid"
                return result
            measurements[label] = {"size_bytes": size, "polled_data_mask_offset": offset}

    result["measurements"] = measurements
    expected_constants = {"CLOCK": 1, "PERF": 2, "MEMORY": 4, "POWER": 8,
                          "THERMAL": 16, "PCI": 32, "FAN": 64}
    result["byte_identical"] = (
        result["r580_version"] == "580.178.04" and
        result["r595_version"] == "595.99.02" and
        measurements.get("R580") == measurements.get("R595") ==
        {"size_bytes": 8, "polled_data_mask_offset": 0} and
        result["required_classes"] == {"R580": True, "R595": True} and
        result["poll_mask_constants"] == {"R580": expected_constants,
                                          "R595": expected_constants})
    return result


def p2p_payload_abi_evidence(cc: str = "cc") -> dict[str, object]:
    """Compile the fixed P2P allocation payload against both pinned SDKs."""
    import tempfile

    compiler = shutil.which(cc)
    result: dict[str, object] = {
        "r580_version": release_version(UPSTREAM),
        "r595_version": release_version(R595_UPSTREAM),
        "r580_header": str(UPSTREAM / P2P_HEADER),
        "r595_header": str(R595_UPSTREAM / P2P_HEADER),
        "r580_header_sha256": sha256(UPSTREAM / P2P_HEADER),
        "r595_header_sha256": sha256(R595_UPSTREAM / P2P_HEADER),
        "r580_resource_list_sha256": sha256(UPSTREAM / "src/nvidia/src/kernel/rmapi/resource_list.h"),
        "r595_resource_list_sha256": sha256(R595_UPSTREAM / "src/nvidia/src/kernel/rmapi/resource_list.h"),
        "measurements": {},
        "optional_classes": {},
        "type_constants": {},
        "compiler": compiler,
        "byte_identical": False,
    }
    if compiler is None:
        result["error"] = "C compiler not found"
        return result

    measurements: dict[str, dict[str, int] | None] = {}
    constants_by_release: dict[str, dict[str, int]] = {}
    for label, tree in (("R580", UPSTREAM), ("R595", R595_UPSTREAM)):
        header = tree / P2P_HEADER
        source = tree / "src/nvidia/src/kernel/rmapi/resource_list.h"
        if not header.is_file() or not source.is_file():
            result["error"] = label + " P2P source is missing"
            return result
        text = source.read_text(encoding="utf-8")
        marker = "/* External Class         */ NV50_THIRD_PARTY_P2P"
        start = text.find(marker)
        end = text.find("RS_ENTRY(", start + len(marker)) if start >= 0 else -1
        block = text[start:end] if start >= 0 and end >= 0 else ""
        result["optional_classes"][label] = (
            "RS_OPTIONAL(NV503C_ALLOC_PARAMETERS)" in block)
        header_text = header.read_text(encoding="utf-8")
        constants: dict[str, int] = {}
        for name in ("PROPRIETARY", "BAR1", "NVLINK"):
            match = re.search(
                r"^#define NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_" + name +
                r"\s+\((0x[0-9a-fA-F]+)\)\s*$", header_text, re.MULTILINE)
            if match:
                constants[name] = int(match.group(1), 16)
        constants_by_release[label] = constants

        include_dirs = [tree / part for part in INCLUDE_PARTS]
        if not all(path.is_dir() for path in include_dirs):
            result["error"] = label + " pinned include tree is incomplete"
            return result
        probe_source = (
            "#include <stddef.h>\n#include <stdio.h>\n"
            "#include <class/cl503c.h>\n"
            "_Static_assert(NV50_THIRD_PARTY_P2P == 0x503c, \"P2P class\");\n"
            "_Static_assert(sizeof(NV503C_ALLOC_PARAMETERS) == 4, \"P2P size\");\n"
            "_Static_assert(offsetof(NV503C_ALLOC_PARAMETERS, flags) == 0, \"P2P flags offset\");\n"
            "int main(void) { printf(\"%zu %zu\\n\", sizeof(NV503C_ALLOC_PARAMETERS), "
            "offsetof(NV503C_ALLOC_PARAMETERS, flags)); return 0; }\n")
        with tempfile.TemporaryDirectory(prefix="p2p-abi-probe-") as temporary:
            root = Path(temporary)
            source_path = root / "probe.c"
            binary_path = root / "probe"
            source_path.write_text(probe_source, encoding="utf-8")
            command = [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
                       *["-I" + str(path) for path in include_dirs], str(source_path),
                       "-o", str(binary_path)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=30, check=False)
            if built.returncode:
                result["error"] = (label + " P2P ABI compile failed: " +
                                   (built.stderr or built.stdout)[-3000:])
                return result
            measured = subprocess.run([str(binary_path)], capture_output=True, text=True,
                                      timeout=5, check=False)
            if measured.returncode:
                result["error"] = label + " P2P ABI probe failed"
                return result
            try:
                size, offset = (int(value) for value in measured.stdout.split())
            except (ValueError, TypeError):
                result["error"] = label + " P2P ABI probe output is invalid"
                return result
            measurements[label] = {"size_bytes": size, "flags_offset": offset}

    result["measurements"] = measurements
    result["type_constants"] = constants_by_release
    result["byte_identical"] = (
        result["r580_version"] == "580.178.04" and
        result["r595_version"] == "595.99.02" and
        measurements.get("R580") == measurements.get("R595") ==
        {"size_bytes": 4, "flags_offset": 0} and
        result["optional_classes"] == {"R580": True, "R595": True} and
        constants_by_release == {
            "R580": {"PROPRIETARY": 0, "BAR1": 1, "NVLINK": 2},
            "R595": {"PROPRIETARY": 0, "BAR1": 1, "NVLINK": 2}})
    return result


def p2p_control_payload_abi_evidence(cc: str = "cc") -> dict[str, object]:
    """Compile all five fixed third-party P2P control layouts against R580/R595."""
    compiler = shutil.which(cc)
    result: dict[str, object] = {
        "r580_version": release_version(UPSTREAM),
        "r595_version": release_version(R595_UPSTREAM),
        "r580_header": str(UPSTREAM / P2P_CONTROL_HEADER),
        "r595_header": str(R595_UPSTREAM / P2P_CONTROL_HEADER),
        "r580_header_sha256": sha256(UPSTREAM / P2P_CONTROL_HEADER),
        "r595_header_sha256": sha256(R595_UPSTREAM / P2P_CONTROL_HEADER),
        "measurements": {}, "compiler": compiler, "byte_identical": False,
    }
    if compiler is None:
        result["error"] = "C compiler not found"
        return result
    probe_source = r"""#include <stddef.h>
#include <stdio.h>
#include <ctrl/ctrl503c.h>
_Static_assert(NV503C_CTRL_CMD_REGISTER_VA_SPACE == 0x503c0102, "register VA command");
_Static_assert(NV503C_CTRL_CMD_UNREGISTER_VA_SPACE == 0x503c0103, "unregister VA command");
_Static_assert(NV503C_CTRL_CMD_REGISTER_VIDMEM == 0x503c0104, "register vidmem command");
_Static_assert(NV503C_CTRL_CMD_UNREGISTER_VIDMEM == 0x503c0105, "unregister vidmem command");
_Static_assert(NV503C_CTRL_CMD_REGISTER_PID == 0x503c0106, "register PID command");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) == 16, "register VA size");
_Static_assert(offsetof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS, hVASpace) == 0, "register VA handle");
_Static_assert(offsetof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS, vaSpaceToken) == 8, "register VA token");
_Static_assert(sizeof(NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS) == 4, "unregister VA size");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS) == 32, "register vidmem size");
_Static_assert(offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, hMemory) == 0, "vidmem handle");
_Static_assert(offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, address) == 8, "vidmem address");
_Static_assert(offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, size) == 16, "vidmem size");
_Static_assert(offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, offset) == 24, "vidmem offset");
_Static_assert(sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS) == 4, "unregister vidmem size");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_PID_PARAMS) == 4, "register PID size");
int main(void) {
    printf("%u %u %u %u %u %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
        NV503C_CTRL_CMD_REGISTER_VA_SPACE, NV503C_CTRL_CMD_UNREGISTER_VA_SPACE,
        NV503C_CTRL_CMD_REGISTER_VIDMEM, NV503C_CTRL_CMD_UNREGISTER_VIDMEM,
        NV503C_CTRL_CMD_REGISTER_PID,
        sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS),
        offsetof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS, hVASpace),
        offsetof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS, vaSpaceToken),
        sizeof(NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS),
        sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS),
        offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, hMemory),
        offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, address),
        offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, size),
        offsetof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS, offset),
        sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS) +
        sizeof(NV503C_CTRL_REGISTER_PID_PARAMS));
    return 0;
}
"""
    measurements: dict[str, dict[str, object] | None] = {}
    for label, tree in (("R580", UPSTREAM), ("R595", R595_UPSTREAM)):
        include_dirs = [tree / part for part in INCLUDE_PARTS]
        if not (tree / P2P_CONTROL_HEADER).is_file() or not all(p.is_dir() for p in include_dirs):
            result["error"] = label + " pinned P2P control header or include directory is missing"
            return result
        with tempfile.TemporaryDirectory(prefix="p2p-control-abi-probe-") as temporary:
            root = Path(temporary)
            source_path = root / "probe.c"
            binary_path = root / "probe"
            source_path.write_text(probe_source, encoding="utf-8")
            command = [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
                       *["-I" + str(path) for path in include_dirs], str(source_path),
                       "-o", str(binary_path)]
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=30, check=False)
            if built.returncode:
                result["error"] = (label + " P2P control ABI compile failed: " +
                                   (built.stderr or built.stdout)[-3000:])
                return result
            measured = subprocess.run([str(binary_path)], capture_output=True, text=True,
                                      timeout=5, check=False)
            if measured.returncode:
                result["error"] = label + " P2P control ABI probe failed"
                return result
            try:
                values = [int(value) for value in measured.stdout.split()]
            except (ValueError, TypeError):
                result["error"] = label + " P2P control ABI probe output is invalid"
                return result
            if len(values) != 15:
                result["error"] = label + " P2P control ABI probe output is incomplete"
                return result
            measurements[label] = {
                "commands": {"register_va_space": values[0], "unregister_va_space": values[1],
                             "register_vidmem": values[2], "unregister_vidmem": values[3],
                             "register_pid": values[4]},
                "register_va_space": {"size_bytes": values[5], "hVASpace_offset": values[6],
                                      "vaSpaceToken_offset": values[7]},
                "unregister_va_space_bytes": values[8],
                "register_vidmem": {"size_bytes": values[9], "hMemory_offset": values[10],
                                    "address_offset": values[11], "size_offset": values[12],
                                    "offset_offset": values[13]},
                "unregister_vidmem_and_register_pid_bytes": values[14],
            }
    result["measurements"] = measurements
    result["byte_identical"] = (
        result["r580_version"] == "580.178.04" and
        result["r595_version"] == "595.99.02" and
        measurements.get("R580") == measurements.get("R595") and
        measurements.get("R580") == {
            "commands": {"register_va_space": 0x503c0102, "unregister_va_space": 0x503c0103,
                         "register_vidmem": 0x503c0104, "unregister_vidmem": 0x503c0105,
                         "register_pid": 0x503c0106},
            "register_va_space": {"size_bytes": 16, "hVASpace_offset": 0,
                                  "vaSpaceToken_offset": 8},
            "unregister_va_space_bytes": 4,
            "register_vidmem": {"size_bytes": 32, "hMemory_offset": 0,
                                "address_offset": 8, "size_offset": 16,
                                "offset_offset": 24},
            "unregister_vidmem_and_register_pid_bytes": 8,
        })
    return result


def build(output: Path, report_path: Path, cc: str = "cc") -> dict[str, object]:
    output = output.resolve()
    report_path = report_path.resolve()
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-rm-ioctl-observer-build-v3",
        "qualification": "failed",
        "source": str(SOURCE),
        "source_sha256": sha256(SOURCE),
        "header_root": str(UPSTREAM),
        "binary": str(output),
        "report": str(report_path),
        "target": "x86_64-linux-gnu",
        "compiler": None,
        "compiler_version": None,
        "command": [],
        "inputs": [],
        "channel_payload_abi": channel_payload_abi_evidence(),
        "rusd_payload_abi": rusd_payload_abi_evidence(cc),
        "p2p_payload_abi": p2p_payload_abi_evidence(cc),
        "p2p_control_payload_abi": p2p_control_payload_abi_evidence(cc),
        "repeat_build_sha256": [],
        "binary_bytes": None,
        "binary_sha256": None,
        "loaded_or_installed": False,
        "diagnostics": "",
    }
    if output.exists() or report_path.exists():
        report["diagnostics"] = "refusing to overwrite an existing output or report"
        return report
    if report["channel_payload_abi"].get("byte_identical") is not True:
        report["diagnostics"] = "pinned R580/R595 NV_CHANNEL_ALLOC_PARAMS headers or class metadata differ"
        return report
    if report["rusd_payload_abi"].get("byte_identical") is not True:
        report["diagnostics"] = "pinned R580/R595 NV00DE_ALLOC_PARAMETERS layout or class metadata differ"
        return report
    if report["p2p_payload_abi"].get("byte_identical") is not True:
        report["diagnostics"] = "pinned R580/R595 NV503C_ALLOC_PARAMETERS layout or class metadata differ"
        return report
    if report["p2p_control_payload_abi"].get("byte_identical") is not True:
        report["diagnostics"] = "pinned R580/R595 NV503C control command IDs or payload layouts differ"
        return report
    include_dirs = [UPSTREAM / part for part in INCLUDE_PARTS]
    if not SOURCE.is_file() or not all(path.is_dir() for path in include_dirs):
        report["diagnostics"] = "observer source or pinned R580 include directory is missing"
        return report
    compiler = shutil.which(cc)
    if not compiler:
        report["diagnostics"] = "C compiler not found"
        return report
    compiler = str(Path(compiler).resolve())
    version = subprocess.run([compiler, "--version"], capture_output=True, text=True,
                             timeout=10, check=False)
    if version.returncode:
        report["diagnostics"] = "compiler version query failed"
        return report
    report["compiler"] = compiler
    report["compiler_version"] = (version.stdout or version.stderr).splitlines()[0]
    output.parent.mkdir(parents=True, exist_ok=True)
    report["command"] = ["cc", "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra",
                         "-Werror", "-DNVRM=1", "-ffile-prefix-map=" + str(ROOT) + "=.",
                         "-MD", "-MF", "<temporary>/rm_ioctl_observer.d", "-Isrc",
                         *["-I" + str(path.relative_to(ROOT)) for path in include_dirs],
                         str(SOURCE.relative_to(ROOT)), "-o", "<temporary>/rm_ioctl_observer"]
    hashes: list[str] = []
    first_binary: Path | None = None
    first_dependencies: list[Path] = []
    for attempt in range(2):
        with tempfile.TemporaryDirectory(prefix=".rm-ioctl-observer-build-",
                                         dir=output.parent) as temp_name:
            temp_dir = Path(temp_name)
            binary = temp_dir / "rm_ioctl_observer"
            depfile = temp_dir / "rm_ioctl_observer.d"
            actual_command = [compiler, "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra",
                              "-Werror", "-DNVRM=1", "-ffile-prefix-map=" + str(ROOT) + "=.",
                              "-MD", "-MF", str(depfile), "-Isrc",
                              *["-I" + str(path) for path in include_dirs], str(SOURCE),
                              "-o", str(binary)]
            env = dict(os.environ)
            env.update({"LC_ALL": "C", "SOURCE_DATE_EPOCH": "0", "TZ": "UTC"})
            result = subprocess.run(actual_command, cwd=ROOT, env=env, capture_output=True,
                                    text=True, timeout=90, check=False)
            if result.returncode or not binary.is_file() or not depfile.is_file():
                report["diagnostics"] = (result.stderr or result.stdout)[-12000:]
                return report
            try:
                current_dependencies = dependencies(depfile)
            except (OSError, ValueError) as error:
                report["diagnostics"] = str(error)
                return report
            digest = sha256(binary)
            hashes.append(digest)
            if attempt == 0:
                first_binary = binary
                first_dependencies = current_dependencies
                # Keep the first candidate alive until both independent builds finish.
                retained = tempfile.TemporaryDirectory(prefix=".rm-ioctl-observer-repro-",
                                                       dir=output.parent)
                retained_path = Path(retained.name) / "rm_ioctl_observer"
                shutil.copyfile(binary, retained_path)
                retained_path.chmod(0o755)
            elif current_dependencies != first_dependencies:
                report["diagnostics"] = "repeat builds used different dependency closures"
                retained.cleanup()
                return report
            report["diagnostics"] = (result.stderr or result.stdout)[-12000:]
    report["repeat_build_sha256"] = hashes
    report["inputs"] = [{"path": str(path), "sha256": sha256(path)}
                        for path in first_dependencies]
    if hashes[0] != hashes[1]:
        report["diagnostics"] = "independent builds produced different binaries"
        retained.cleanup()
        return report
    try:
        os.link(retained_path, output)
    except FileExistsError:
        report["diagnostics"] = "output appeared during build; refusing to overwrite it"
        retained.cleanup()
        return report
    finally:
        retained.cleanup()
    report["binary_bytes"] = output.stat().st_size
    report["binary_sha256"] = sha256(output)
    report["qualification"] = "repeatable-build-only-no-driver-execution"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args(argv)
    try:
        report = build(args.output, args.report, args.cc)
        if not args.report.exists():
            persist(args.report.resolve(), report)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        report = {"schema": "nvidia-hybrid-rm-ioctl-observer-build-v3",
                  "qualification": "failed", "diagnostics": str(error)[:1000],
                  "loaded_or_installed": False}
        if not args.report.exists():
            persist(args.report.resolve(), report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("qualification") == "repeatable-build-only-no-driver-execution" else 2


if __name__ == "__main__":
    raise SystemExit(main())
