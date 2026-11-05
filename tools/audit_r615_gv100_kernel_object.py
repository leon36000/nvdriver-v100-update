#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the bounded GV100 symbol surface in pinned R615/R580 Open RM objects.

This reads ELF symbol/relocation tables and strings only. Symbol presence does
not establish device-catalog registration, dispatch reachability, or runtime
initialization on a GV100.
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
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import (  # noqa: E402
    validate_report_path,
    write_private_evidence_report,
)

R615_ARCHIVE_SHA256 = (
    "41e16cfbb3ba475c55b6ce5b2595e1a87a76948873a1a83f1b261f6b7ba0bf5b"
)
R615_MEMBER = (
    "nvidia_driver-linux-x86_64-615.71.10-archive/"
    "kernel-open/nvidia/nv-kernel.o_binary"
)
R580_ARCHIVE_SHA256 = (
    "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
)
R580_OPEN_OBJECT_SHA256 = (
    "c5f7a58442286f02f9caebf3279320dd8a846883d7514c183981efa754d11248"
)
DEFAULT_R615_ARCHIVE = (
    ROOT / ".cache/upstream/nvidia_driver-linux-x86_64-615.71.10-archive.tar.xz"
)
DEFAULT_R615_OBJECT = (
    ROOT / ".cache/upstream/extracted-r615-71-10-package/kernel-open/"
    "nvidia/nv-kernel.o_binary"
)
DEFAULT_R580_ARCHIVE = (
    ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
)
DEFAULT_R580_OBJECT = (
    ROOT / "build/experiments/r580-uvm-clean-v3-20261021/source/"
    "kernel-open/nvidia/nv-kernel.o_binary"
)
DEFAULT_REPORT = ROOT / "evidence/r615-r580-gv100-kernel-object-symbol-audit-v3-20261023.json"
GENERIC_RM_ANCHORS = (
    "gpuBuildClassDB_IMPL",
    "gpuIsClassSupported_IMPL",
    "gpuGetClassList_IMPL",
    "gpuarchConstruct_IMPL",
    "gpumgrGetGpuArch_IMPL",
    "__nvoc_ctor_GpuArch",
    "__nvoc_objCreate_GpuArch",
)
VOLTA_CLASS_METADATA = (
    "VOLTA_USERMODE_AParentList",
    "VOLTA_USERMODE_A_RightsRequiredArray",
    "VOLTA_CHANNEL_GPFIFO_AParentList",
    "VOLTA_CHANNEL_GPFIFO_A_RightsRequiredArray",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def implementation_fingerprints() -> dict[str, str]:
    paths = (
        Path(__file__).resolve(strict=True),
        ROOT / "tools/probe_r615_gv100_dispatch.py",
        ROOT / "tests/test_audit_r615_gv100_kernel_object.py",
    )
    return {
        path.relative_to(ROOT).as_posix(): sha256_file(path)
        for path in paths
    }


def _run(*arguments: str) -> str:
    result = subprocess.run(
        arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{Path(arguments[0]).name} failed ({result.returncode}): "
            f"{result.stderr[-1200:]}"
        )
    return result.stdout


def parse_gv100_functions(nm_output: str) -> set[str]:
    """Return defined nm names ending in the GV100 architecture suffix."""
    functions = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol_type, name = fields[-2], fields[-1]
        if symbol_type.upper() == "U":
            continue
        if re.search(r"_GV100(?:\.cold)?$", name):
            functions.add(name)
    return functions


def compare_gv100_functions(r615: set[str], r580: set[str]) -> dict:
    shared = r615 & r580
    return {
        "counts": {
            "r615": len(r615), "r580": len(r580), "shared": len(shared),
        },
        "shared": sorted(shared),
        "r615_only": sorted(r615 - r580),
        "r580_only": sorted(r580 - r615),
    }


def parse_readelf_symbols(readelf_output: str) -> dict:
    names: set[str] = set()
    types: dict[str, str] = {}
    file_markers = set()
    for line in readelf_output.splitlines():
        fields = line.strip().split(maxsplit=7)
        if len(fields) != 8 or not fields[0].endswith(":"):
            continue
        symbol_type, name = fields[3], fields[7]
        if name in ("", "0"):
            continue
        names.add(name)
        types[name] = symbol_type
        if symbol_type == "FILE" and "gv100" in name.lower():
            file_markers.add(name)
    return {
        "symbol_names": names,
        "symbol_types": types,
        "gv100_file_markers": sorted(file_markers),
    }


def _tool_version(command: str) -> str:
    executable = shutil.which(command)
    if not executable:
        raise FileNotFoundError(f"required ELF inspection tool is unavailable: {command}")
    output = _run(executable, "--version")
    return output.splitlines()[0] if output.splitlines() else executable


def _inspect_object(path: Path) -> dict:
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"ELF input is not a regular file: {path}")
    nm_tool = shutil.which("nm")
    readelf_tool = shutil.which("readelf")
    strings_tool = shutil.which("strings")
    if not all((nm_tool, readelf_tool, strings_tool)):
        raise FileNotFoundError("nm, readelf and strings are required")

    nm_output = _run(nm_tool, "-an", "--defined-only", str(path))
    all_defined = {
        line.split()[-1] for line in nm_output.splitlines() if line.split()
    }
    elf_header = _run(readelf_tool, "-h", str(path))
    symbols = parse_readelf_symbols(_run(readelf_tool, "-sW", str(path)))
    relocations = _run(readelf_tool, "-rW", str(path))
    printable_strings = _run(strings_tool, "-a", "-n", "5", str(path))
    header_fields = {}
    for key in ("Class", "Data", "Type", "Machine"):
        match = re.search(rf"^\s*{key}:\s*(.+)$", elf_header, re.MULTILINE)
        if match:
            header_fields[key.lower()] = match.group(1).strip()
    relocation_references = [
        line.strip() for line in relocations.splitlines() if "GV100" in line
    ]
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "elf_header": header_fields,
        "defined_symbol_count": len(all_defined),
        "gv100_function_symbols": sorted(parse_gv100_functions(nm_output)),
        "gv100_file_markers": symbols["gv100_file_markers"],
        "gv100_relocation_reference_count": len(relocation_references),
        "generic_rm_anchor_presence": {
            name: name in all_defined for name in GENERIC_RM_ANCHORS
        },
        "volta_class_metadata_presence": {
            name: name in all_defined for name in VOLTA_CLASS_METADATA
        },
        "volta_classic_predicate_present": (
            "rmcfg_IsVOLTA_CLASSIC_GPUSorBetter" in all_defined
        ),
        "is_device_volta_plus_present": "isDeviceVoltaPlus" in all_defined,
        "explicit_gv100_class_list_getters": sorted(
            name for name in all_defined
            if re.search(r"gpuGet.*ClassList.*GV100", name)
        ),
        "product_strings": {
            "Tesla V100": sum("Tesla V100" in line for line in printable_strings.splitlines()),
            "Quadro GV100": sum("Quadro GV100" in line for line in printable_strings.splitlines()),
        },
    }


def audit_objects(r615_archive: Path,
                  r615_object: Path,
                  r580_archive: Path,
                  r580_object: Path) -> dict:
    r615_archive = Path(r615_archive).resolve(strict=True)
    r615_object = Path(r615_object).resolve(strict=True)
    r580_archive = Path(r580_archive).resolve(strict=True)
    r580_object = Path(r580_object).resolve(strict=True)
    r615_archive_hash = sha256_file(r615_archive)
    if r615_archive_hash != R615_ARCHIVE_SHA256:
        raise ValueError("R615 archive differs from the pinned R615.71.10 package")
    r580_archive_hash = sha256_file(r580_archive)
    if r580_archive_hash != R580_ARCHIVE_SHA256:
        raise ValueError("R580 source archive differs from pinned R580.178.04")
    with tarfile.open(r615_archive, "r:*") as archive:
        member = archive.getmember(R615_MEMBER)
        if not member.isfile():
            raise ValueError("R615 nv-kernel.o_binary archive member is not regular")
        member_data = archive.extractfile(member).read()
    r615_object_data = r615_object.read_bytes()
    if member_data != r615_object_data:
        raise ValueError("extracted R615 RM object differs from its exact archive member")

    r615 = _inspect_object(r615_object)
    r580 = _inspect_object(r580_object)
    if r615["sha256"] != sha256_bytes(member_data):
        raise ValueError("R615 RM object identity changed while collecting ELF evidence")
    if r580["sha256"] != R580_OPEN_OBJECT_SHA256:
        raise ValueError("R580 Open RM comparator differs from its pinned local build artifact")
    with tarfile.open(r580_archive, "r:*") as archive:
        r580_archive_has_binary = any(
            member.name.endswith("/kernel-open/nvidia/nv-kernel.o_binary")
            and member.isfile()
            for member in archive.getmembers()
        )

    return {
        "schema": "r615-r580-gv100-kernel-object-symbol-audit-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "implementation_sha256": implementation_fingerprints(),
        "tools": {
            name: _tool_version(name) for name in ("readelf", "nm", "strings")
        },
        "inputs": {
            "r615_archive": {
                "path": str(r615_archive),
                "sha256": r615_archive_hash,
                "archive_member": R615_MEMBER,
                "member_sha256": sha256_bytes(member_data),
                "member_bytes": len(member_data),
                "extracted_object_matches_member": True,
                "object": r615,
            },
            "r580_source_archive": {
                "path": str(r580_archive),
                "sha256": r580_archive_hash,
                "contains_nv_kernel_o_binary_member": r580_archive_has_binary,
            },
            "r580_open_local_build_artifact": {
                **r580,
                "provenance_note": (
                    "Pinned local Open R580 build artifact; the R580 source archive "
                    "does not contain this proprietary RM object as an archive member."
                ),
            },
        },
        "gv100_function_comparison": compare_gv100_functions(
            set(r615["gv100_function_symbols"]), set(r580["gv100_function_symbols"])
        ),
        "qualification": "analyzed-statically",
        "symbol_presence_proves_dispatch_or_initialization": False,
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "limitations": [
            "The R580 comparator is a pinned local Open build artifact, not a binary member of the pinned source archive.",
            "Symbols, relocations, file markers and strings do not prove RM catalog membership, GV100 dispatch reachability or initialization semantics.",
            "This audit inspects proprietary machine-code metadata only; it does not decompile or redistribute implementation code.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r615-archive", type=Path, default=DEFAULT_R615_ARCHIVE)
    parser.add_argument("--r615-object", type=Path, default=DEFAULT_R615_OBJECT)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--r580-object", type=Path, default=DEFAULT_R580_OBJECT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    try:
        validate_report_path(args.report)
        report = audit_objects(
            args.r615_archive, args.r615_object, args.r580_archive, args.r580_object
        )
        write_private_evidence_report(args.report, report)
    except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError) as error:
        print(f"R615/R580 GV100 object audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
