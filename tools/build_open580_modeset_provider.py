#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build, but never install/load, R580 NVKMS against the private Open core."""
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

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "build/experiments/private-open-pm-channel-restart-v2-20261021/"
          "NVIDIA-kernel-module-source-580.178.04/kernel-open")
PROVIDER_MODULE = SOURCE / "hybrid580_open.ko"
PROVIDER_MODULE_SHA256 = "6108bb0221ac17fb435e918c4d0402406eb80f2f5739ebf81279d39f6bd2e2b1"
PROVIDER_SYMVERS_SHA256 = "87246357b0b97080fd62f5dd4b64a9994368876514c6f4c00d5047b0c2c82546"
MODESET_BINARY = (ROOT / "build/experiments/private-proprietary-pm-channel-restart-v2-20261021/"
                  "nvidia-580.178.04/nvidia-modeset/nv-modeset-kernel.o_binary")
MODESET_BINARY_SHA256 = "9a8640a8f49c88cfcc0773d728d6b2a28b877794c95ec63a5e950b2d8385a83d"
PROVIDER_SYMBOL = "hybrid580_open_nvidia_get_rm_ops"
STOCK_SYMBOL = "nvidia_get_rm_ops"
NAMESPACE_DEFINE = "-Dnvidia_get_rm_ops=hybrid580_open_nvidia_get_rm_ops"
KBUILD_ANCHOR = "NVIDIA_MODESET_CFLAGS += -I$(src)/nvidia-modeset -I$(src)/common/inc"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_symvers(text: str) -> dict[str, dict[str, str]]:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        crc, symbol, module, export = fields[:4]
        if symbol in result:
            raise ValueError(f"duplicate Module.symvers symbol: {symbol}")
        result[symbol] = {"crc": crc.lower(), "module": module,
                          "export": export}
    return result


def parse_modversions(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[0].startswith("0x"):
            continue
        if fields[1] in result:
            raise ValueError(f"duplicate module version entry: {fields[1]}")
        result[fields[1]] = fields[0].lower()
    return result


def verify_provider_import(undefined_symbols: list[str],
                           module_versions: dict[str, str],
                           provider_symvers: dict[str, dict[str, str]]) -> dict:
    if STOCK_SYMBOL in undefined_symbols or STOCK_SYMBOL in module_versions:
        raise ValueError("stock symbol remains in modeset imports")
    if PROVIDER_SYMBOL not in undefined_symbols:
        raise ValueError("namespaced provider import is absent")
    if PROVIDER_SYMBOL not in module_versions:
        raise ValueError("namespaced provider import has no module CRC")
    provider = provider_symvers.get(PROVIDER_SYMBOL)
    if provider is None:
        raise ValueError("provider export is absent from Module.symvers")
    if module_versions[PROVIDER_SYMBOL] != provider["crc"]:
        raise ValueError("namespaced provider import CRC mismatch")
    return {"symbol": PROVIDER_SYMBOL,
            "crc": provider["crc"],
            "provider_module": provider["module"],
            "export": provider["export"]}


def add_provider_namespace(kbuild_path: Path) -> tuple[str, str]:
    kbuild_path = Path(kbuild_path)
    before = kbuild_path.read_text()
    if before.count(NAMESPACE_DEFINE):
        if before.count(NAMESPACE_DEFINE) != 1:
            raise ValueError("duplicate NVKMS provider namespace define")
        return before, before
    if before.count(KBUILD_ANCHOR) != 1:
        raise ValueError("expected one NVKMS CFLAGS anchor")
    after = before.replace(KBUILD_ANCHOR,
                           KBUILD_ANCHOR + "\nNVIDIA_MODESET_CFLAGS += " +
                           NAMESPACE_DEFINE)
    kbuild_path.write_text(after)
    return before, after


def prepare_scratch(source: Path, scratch: Path) -> Path:
    source = Path(source).resolve()
    scratch = Path(scratch).resolve()
    if scratch.exists():
        raise FileExistsError(f"refusing to overwrite existing scratch tree: {scratch}")
    if not (source / "Module.symvers").is_file() or not (
            source / "nvidia-modeset/nvidia-modeset.Kbuild").is_file():
        raise ValueError("source tree lacks R580 NVKMS inputs")
    if source == scratch or source in scratch.parents:
        raise ValueError("scratch tree must not be inside the source tree")
    scratch.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, scratch)
    return scratch


def stage_hash_pinned_file(source: Path, destination: Path,
                           expected_sha256: str, label: str) -> dict[str, str | int]:
    source = Path(source)
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing modeset object: {destination}")
    if not source.is_file():
        raise FileNotFoundError(source)
    if len(expected_sha256) != 64 or sha256_file(source) != expected_sha256:
        raise ValueError(f"{label} hash changed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)
    digest = sha256_file(destination)
    if digest != expected_sha256:
        raise RuntimeError(f"staged {label} hash changed during copy")
    return {"source": str(source.resolve()), "path": str(destination.resolve()),
            "bytes": destination.stat().st_size, "sha256": digest}


def stage_modeset_binary(source: Path, destination: Path,
                         expected_sha256: str) -> dict[str, str | int]:
    return stage_hash_pinned_file(source, destination, expected_sha256,
                                  "modeset core")


def stage_provider_symvers(source: Path, destination: Path,
                           expected_sha256: str) -> dict[str, str | int]:
    return stage_hash_pinned_file(source, destination, expected_sha256,
                                  "provider Module.symvers")


def make_build_command(scratch_source: Path, kernel_release: str, jobs: int,
                       provider_symvers: Path) -> list[str]:
    return ["make", "-C", str(Path(scratch_source).resolve()),
            "KERNEL_UNAME=" + kernel_release,
            "NV_KERNEL_MODULES=nvidia-modeset",
            "KBUILD_EXTRA_SYMBOLS=" + str(Path(provider_symvers).resolve()),
            "-j" + str(jobs), "modules"]


def verify_fixed_char_device(source_root: Path) -> dict[str, int | bool]:
    source_root = Path(source_root)
    constants = (source_root / "common/inc/nv-chardev-numbers.h").read_text()
    modeset = (source_root / "nvidia-modeset/nvidia-modeset-linux.c").read_text()
    modeset = re.sub(r"\\\r?\n", " ", modeset)
    major = re.search(r"#\s*define\s+NV_MAJOR_DEVICE_NUMBER\s+(\d+)", constants)
    minor = re.search(
        r"#\s*define\s+NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE\s+(\d+)", constants)
    uses_mkdev = re.search(
        r"#\s*define\s+NVKMS_RDEV\b\s*\(?\s*MKDEV\s*\(\s*"
        r"NV_MAJOR_DEVICE_NUMBER\s*,\s*NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE",
        modeset)
    reserves = re.search(
        r"register_chrdev_region\s*\(\s*NVKMS_RDEV\s*,\s*1\s*,\s*"
        r"[\"']nvidia-modeset[\"']\s*\)", modeset)
    if (major is None or minor is None or major.group(1) != "195" or
            minor.group(1) != "254" or uses_mkdev is None or reserves is None):
        raise ValueError("fixed NVKMS char-device reservation is not 195:254")
    return {"major": int(major.group(1)), "minor": int(minor.group(1)),
            "source_reservation_verified": True}


def run_capture(command: list[str], *, cwd: Path | None = None,
                timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          check=False, timeout=timeout)


def run_build(scratch_root: Path, kernel_release: str, jobs: int) -> dict:
    scratch_root = Path(scratch_root).resolve()
    scratch_source = scratch_root / "kernel-open"
    if scratch_root != ROOT and ROOT not in scratch_root.parents:
        raise ValueError("scratch root must remain under driver-hybrid/build/experiments")
    if scratch_source.exists():
        raise FileExistsError(f"refusing to overwrite existing scratch tree: {scratch_source}")
    if not PROVIDER_MODULE.is_file() or sha256_file(PROVIDER_MODULE) != PROVIDER_MODULE_SHA256:
        raise ValueError("pinned private Open provider module hash changed")
    if not SOURCE.is_dir():
        raise FileNotFoundError(SOURCE)
    source_symvers = SOURCE / "Module.symvers"
    source_kbuild = SOURCE / "nvidia-modeset/nvidia-modeset.Kbuild"
    source_hashes = {"provider_module": sha256_file(PROVIDER_MODULE),
                     "Module.symvers": sha256_file(source_symvers),
                     "nvidia-modeset.Kbuild": sha256_file(source_kbuild)}
    if source_hashes["Module.symvers"] != PROVIDER_SYMVERS_SHA256:
        raise ValueError("pinned private Open Module.symvers hash changed")
    if not MODESET_BINARY.is_file() or sha256_file(MODESET_BINARY) != MODESET_BINARY_SHA256:
        raise ValueError("pinned R580 NVKMS core binary is absent or changed")
    source_hashes["nv-modeset-kernel.o_binary"] = sha256_file(MODESET_BINARY)
    source_exports = parse_symvers(source_symvers.read_text())
    if PROVIDER_SYMBOL not in source_exports:
        raise ValueError("private Open provider export is absent")
    if source_exports[PROVIDER_SYMBOL]["module"] != "hybrid580_open":
        raise ValueError("private Open provider module name changed")

    prepare_scratch(SOURCE, scratch_source)
    provider_symvers = stage_provider_symvers(
        source_symvers, scratch_root / "provider-Module.symvers",
        PROVIDER_SYMVERS_SHA256)
    staged_modeset_binary = stage_modeset_binary(
        MODESET_BINARY,
        scratch_source / "nvidia-modeset/nv-modeset-kernel.o_binary",
        MODESET_BINARY_SHA256)
    _, patched_kbuild = add_provider_namespace(
        scratch_source / "nvidia-modeset/nvidia-modeset.Kbuild")
    kernel_build = Path("/lib/modules") / kernel_release / "build"
    if not kernel_build.exists():
        raise FileNotFoundError(f"kernel build tree is absent: {kernel_build}")
    build_log = scratch_root / "nvidia-modeset-build.log"
    command = make_build_command(scratch_source, kernel_release, jobs,
                                 Path(provider_symvers["path"]))
    started = datetime.now(timezone.utc).isoformat()
    result = run_capture(command)
    build_log.parent.mkdir(parents=True, exist_ok=True)
    build_log.write_text(result.stdout)
    os.chmod(build_log, 0o600)
    report = {
        "schema": "hybrid-open580-modeset-provider-build-v1",
        "created_utc": started,
        "qualification": "build-only-private-source-prototype",
        "kernel_release": kernel_release,
        "kernel_build_tree": str(kernel_build.resolve()),
        "source": str(SOURCE),
        "scratch_source": str(scratch_source),
        "inputs": source_hashes,
        "external_provider_symvers": provider_symvers,
        "staged_modeset_core": staged_modeset_binary,
        "binary_license_boundary": (
            "Private R580 release object included for local build validation only; "
            "the combined module is not cleared for redistribution."),
        "namespace_define": NAMESPACE_DEFINE,
        "provider_symbol": PROVIDER_SYMBOL,
        "scratch_kbuild_sha256": sha256_file(
            scratch_source / "nvidia-modeset/nvidia-modeset.Kbuild"),
        "scratch_namespace_applied": NAMESPACE_DEFINE in patched_kbuild,
        "build_command": command,
        "build_exit_code": result.returncode,
        "build_log": str(build_log),
        "build_log_sha256": sha256_file(build_log),
        "loaded": False,
        "installed": False,
        "hardware_validated": False,
        "runtime_callback_validated": False,
    }
    if result.returncode != 0:
        report["qualification"] = "build-failed"
        report["build_error_tail"] = result.stdout.splitlines()[-80:]
        return report

    try:
        module_candidates = sorted(scratch_source.rglob("nvidia-modeset.ko"))
        if len(module_candidates) != 1:
            raise FileNotFoundError(
                "Kbuild did not produce exactly one nvidia-modeset.ko: " +
                repr([str(path) for path in module_candidates]))
        module_path = module_candidates[0]
        undefined = run_capture(["nm", "-u", str(module_path)])
        if undefined.returncode:
            raise RuntimeError("nm could not inspect the built NVKMS module")
        undefined_symbols = [line.split()[-1] for line in undefined.stdout.splitlines()
                             if line.split()]
        versions = run_capture(["modprobe", "--show-modversions", str(module_path)])
        if versions.returncode:
            raise RuntimeError("modprobe could not inspect module CRC imports")
        module_versions = parse_modversions(versions.stdout)
        provider_import = verify_provider_import(undefined_symbols,
                                                 module_versions, source_exports)
        vermagic = run_capture(["modinfo", "-F", "vermagic", str(module_path)])
        if vermagic.returncode or not vermagic.stdout.split() or \
                vermagic.stdout.split()[0] != kernel_release:
            raise ValueError("NVKMS vermagic does not match the requested kernel")
        fixed_char_device = verify_fixed_char_device(scratch_source)
        if {"provider_module": sha256_file(PROVIDER_MODULE),
            "Module.symvers": sha256_file(source_symvers),
            "nvidia-modeset.Kbuild": sha256_file(source_kbuild),
            "nv-modeset-kernel.o_binary": sha256_file(MODESET_BINARY)} != source_hashes:
            raise RuntimeError("recorded provider input changed during isolated build")
        if sha256_file(Path(provider_symvers["path"])) != PROVIDER_SYMVERS_SHA256:
            raise RuntimeError("external provider Module.symvers changed during modpost")
        report.update({
            "qualification": "compiled-import-crc-closed-static-chardev-contract",
            "module": {"path": str(module_path), "bytes": module_path.stat().st_size,
                       "sha256": sha256_file(module_path)},
            "module_license": run_capture(["modinfo", "-F", "license",
                                           str(module_path)]).stdout.strip(),
            "vermagic": vermagic.stdout.strip(),
            "provider_import": provider_import,
            "undefined_symbol_count": len(undefined_symbols),
            "undefined_stock_provider_symbol": STOCK_SYMBOL in undefined_symbols,
            "fixed_char_device": fixed_char_device,
        })
    except (FileNotFoundError, RuntimeError, ValueError, OSError) as error:
        report["qualification"] = "compiled-post-build-validation-failed"
        report["validation_error"] = f"{type(error).__name__}: {error}"
    return report


def write_report(path: Path, report: dict) -> None:
    path = Path(path).resolve()
    if ROOT / "evidence" not in path.parents:
        raise ValueError("report must remain under driver-hybrid/evidence")
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing report: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", required=True, type=Path,
                        help="new build/experiments directory; it must not exist")
    parser.add_argument("--report", required=True, type=Path,
                        help="new evidence JSON path; it must not exist")
    parser.add_argument("--kernel-release", default="7.0.0-38-generic")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    scratch = args.scratch if args.scratch.is_absolute() else ROOT / args.scratch
    report_path = args.report if args.report.is_absolute() else ROOT / args.report
    if not scratch.resolve().is_relative_to((ROOT / "build/experiments").resolve()):
        parser.error("scratch must remain under build/experiments")
    if args.kernel_release != "7.0.0-38-generic":
        parser.error("only the audited kernel 7.0.0-38-generic is pinned")
    try:
        report = run_build(scratch, args.kernel_release, args.jobs)
        write_report(report_path, report)
    except Exception as error:
        print(f"build evidence incomplete: {type(error).__name__}: {error}",
              file=sys.stderr)
        return 1
    print(json.dumps({k: report[k] for k in (
        "qualification", "kernel_release", "module", "provider_import",
        "fixed_char_device", "build_exit_code", "build_log_sha256")
        if k in report}, indent=2, sort_keys=True))
    return 0 if report["qualification"] == \
        "compiled-import-crc-closed-static-chardev-contract" else 2


if __name__ == "__main__":
    raise SystemExit(main())
