#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit a fresh R580 nvidia/nvidia-uvm module pair without loading it.

The audit checks the pinned source inputs, output ELF/module metadata, Kbuild
log, and the complete nvUvmInterface import/export set. It does not install,
load, or execute either module and does not claim GPU/UVM runtime behavior.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_TAG = "580.178.04"
SOURCE_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
FATAL_BUILD_RE = re.compile(
    r"(?i)(?:\berror:\s|\bfatal error\b|undefined reference|undefined symbol|"
    r"multiple definition|no rule to make target|make(?:\[\d+\])?:\s*\*\*\*|"
    r"\bError\s+[1-9][0-9]*\b)"
)
LINK_MODULE_RE = re.compile(r"^\s*LD\s+\[M\]\s+(nvidia(?:-uvm)?\.ko)\s*$")
OBJTOOL_NAKED_RETURN_RE = re.compile(
    r"warning:\s+objtool:.*'naked' return found"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def normalize_sha256(value: str) -> str:
    normalized = value.lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        raise ValueError("expected SHA-256 must be exactly 64 hexadecimal digits")
    return normalized


def parse_module_symvers(text: str, *, provider: str) -> dict[str, dict[str, str]]:
    """Return R580 UVM interface exports owned by exactly one module."""
    found: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        crc, name, module, export_type = fields[:4]
        if module != provider or not name.startswith("nvUvmInterface"):
            continue
        if not export_type.startswith("EXPORT_SYMBOL"):
            continue
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", crc) is None:
            raise ValueError(f"malformed CRC on Module.symvers line {line_number}")
        value = {"crc": crc.lower(), "export": export_type}
        previous = found.get(name)
        if previous is not None and previous != value:
            raise ValueError(f"conflicting provider rows for {name}")
        found[name] = value
    if not found:
        raise ValueError(f"no nvUvmInterface exports found for provider {provider}")
    return found


def parse_nm_undefined(text: str) -> set[str]:
    """Parse GNU nm -u output; omit weak and version decoration."""
    names: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] == "U":
            name = fields[-1].split("@", 1)[0]
            if name:
                names.add(name)
    return names


def compare_uvm_interface(imports: set[str],
                          exports: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Compare the UVM module's imports with the selected RM provider."""
    provided = set(exports)
    missing = sorted(imports - provided)
    provider_only = sorted(provided - imports)
    return {
        "import_count": len(imports),
        "export_count": len(provided),
        "all_imports_resolved": not missing,
        "exact_interface_match": imports == provided,
        "unmatched_imports": missing,
        "provider_only_exports": provider_only,
    }


def parse_modinfo(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if key in result and result[key] != value:
            raise ValueError(f"conflicting modinfo values for {key}")
        result[key] = value
    return result


def summarize_build_log(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    links = {match.group(1) for line in lines if (match := LINK_MODULE_RE.match(line))}
    errors = [line.strip() for line in lines if FATAL_BUILD_RE.search(line)]
    if errors:
        raise ValueError("build log contains errors: " + " | ".join(errors[:4]))
    return {
        "has_both_module_link_steps": {"nvidia.ko", "nvidia-uvm.ko"}.issubset(links),
        "module_link_steps": sorted(links),
        "modpost_count": sum("MODPOST Module.symvers" in line for line in lines),
        "warning_line_count": sum("warning:" in line.lower() for line in lines),
        "objtool_naked_return_warning_count": sum(
            bool(OBJTOOL_NAKED_RETURN_RE.search(line)) for line in lines
        ),
        "pahole_missing": any("pahole: not found" in line for line in lines),
        "error_lines": [],
    }


def run_text(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cannot run {argv[0]}: {exc}") from None
    if result.returncode != 0:
        raise ValueError(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()[:500]}")
    return result.stdout


def modinfo(path: Path) -> dict[str, str]:
    values = {}
    for key in ("version", "depends", "license", "vermagic"):
        values[key] = run_text(["modinfo", "-F", key, str(path)]).strip()
    return values


def elf_header(path: Path) -> dict[str, str]:
    text = run_text(["readelf", "-h", str(path)])
    type_match = re.search(r"^\s*Type:\s*(.+)$", text, re.MULTILINE)
    machine_match = re.search(r"^\s*Machine:\s*(.+)$", text, re.MULTILINE)
    if type_match is None or machine_match is None:
        raise ValueError(f"cannot parse ELF header for {path.name}")
    header = {"type": type_match.group(1).strip(), "machine": machine_match.group(1).strip()}
    if not header["type"].startswith("REL "):
        raise ValueError(f"{path.name} is not an ELF relocatable module")
    return header


def module_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"module artifact is absent or not a regular file: {path}")
    return {
        "path": project_path(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "elf": elf_header(path),
        "modinfo": modinfo(path),
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    archive = args.source_archive.resolve(strict=True)
    core = args.rm_core_object.resolve(strict=True)
    tree = args.build_tree.resolve(strict=True)
    log = args.build_log.resolve(strict=True)
    expected_archive = SOURCE_ARCHIVE_SHA256
    expected_core = normalize_sha256(args.expected_rm_core_sha256)
    archive_hash = sha256_file(archive)
    core_hash = sha256_file(core)
    if archive_hash != expected_archive:
        raise ValueError("R580 source archive SHA-256 does not match pinned 580.178.04 source")
    if core_hash != expected_core:
        raise ValueError("Open R580 RM core SHA-256 does not match the explicit expected value")

    kernel_module = tree / "nvidia.ko"
    uvm_module = tree / "nvidia-uvm.ko"
    copied_core = tree / "nvidia/nv-kernel.o_binary"
    symvers = tree / "Module.symvers"
    for path in (kernel_module, uvm_module, copied_core, symvers):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required build output is absent or not a regular file: {path}")
    if sha256_file(copied_core) != core_hash:
        raise ValueError("the RM core copied into the build tree differs from the pinned input")

    build_log_text = log.read_text(encoding="utf-8", errors="strict")
    build_summary = summarize_build_log(build_log_text)
    if not build_summary["has_both_module_link_steps"]:
        raise ValueError("build log does not show both nvidia.ko and nvidia-uvm.ko link steps")
    if build_summary["modpost_count"] == 0:
        raise ValueError("build log has no MODPOST step")

    kernel_info = module_record(kernel_module)
    uvm_info = module_record(uvm_module)
    if kernel_info["modinfo"]["version"] != SOURCE_TAG or uvm_info["modinfo"]["version"] != SOURCE_TAG:
        raise ValueError("module versions do not match the pinned R580 source tag")
    vermagic = uvm_info["modinfo"]["vermagic"].split()
    if not vermagic or vermagic[0] != args.kernel_release:
        raise ValueError("nvidia-uvm vermagic does not match the requested kernel release")
    dependencies = {item for item in uvm_info["modinfo"]["depends"].split(",") if item}
    if "nvidia" not in dependencies:
        raise ValueError("nvidia-uvm metadata does not depend on the nvidia provider")

    exports = parse_module_symvers(symvers.read_text(encoding="utf-8", errors="strict"),
                                   provider="nvidia")
    undefined = parse_nm_undefined(run_text(["nm", "-u", str(uvm_module)]))
    imports = {name for name in undefined if name.startswith("nvUvmInterface")}
    interface = compare_uvm_interface(imports, exports)
    if not interface["all_imports_resolved"]:
        raise ValueError("nvidia-uvm has nvUvmInterface imports missing from nvidia.ko")
    if not interface["exact_interface_match"]:
        raise ValueError("nvidia and nvidia-uvm nvUvmInterface sets differ")

    return {
        "schema": "nvidia-r580-uvm-module-pair-audit-v1",
        "qualification": "compiled-and-static-import-export-closure",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "tag": SOURCE_TAG,
            "archive": project_path(archive),
            "archive_sha256": archive_hash,
            "rm_core_object": project_path(core),
            "rm_core_sha256": core_hash,
            "build_tree": project_path(tree),
        },
        "target_kernel_release": args.kernel_release,
        "build_log": {
            "path": project_path(log),
            "sha256": sha256_file(log),
            "summary": build_summary,
        },
        "modules": {"nvidia": kernel_info, "nvidia_uvm": uvm_info},
        "uvm_interface": {
            **interface,
            "symbols": sorted(imports),
            "provider_export_records": exports,
        },
        "scope": {
            "install_attempted": False,
            "load_attempted": False,
            "hardware_execution": False,
            "uvm_runtime_validation": False,
            "same_process_dual_gpu_cuda": False,
            "license_metadata_changed": False,
        },
        "interpretation": (
            "R580 nvidia and nvidia-uvm compile as a same-version module pair for the target "
            "headers and their static nvUvmInterface import/export names match exactly. "
            "This establishes no module-load, initialization, UVM workload, or GPU behavior."
        ),
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
    parser.add_argument("--build-tree", type=Path, required=True,
                        help="kernel-open output directory containing both .ko files")
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--rm-core-object", type=Path, required=True)
    parser.add_argument("--expected-rm-core-sha256", required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--kernel-release", required=True)
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
    print(json.dumps({
        "report": project_path(args.report),
        "qualification": report["qualification"],
        "nvidia_uvm_version": report["modules"]["nvidia_uvm"]["modinfo"]["version"],
        "uvm_interface_import_export_count": report["uvm_interface"]["import_count"],
        "hardware_execution": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
