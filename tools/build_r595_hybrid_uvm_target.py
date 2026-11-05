#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the R595 hybrid UVM consumer against an explicit frontend/kernel ABI.

This is a compile-only tool. It copies a prepared R595/R580 UVM source tree to
a fresh experiment directory, regenerates Kbuild conftests for the requested
kernel, and verifies the resulting public ``nvUvmInterface`` CRC bindings.
It never installs or loads a module and never accesses a GPU.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import build_hybrid_frontend as frontend  # noqa: E402

ADDRESS_SPACE_DISPATCH = "nvUvmInterfaceDupAddressSpaceWithControlFd"
ADDRESS_SPACE_PUBLIC_API = "nvUvmInterfaceDupAddressSpace"
DEFAULT_DEBUG_SOURCE_PREFIX = "/usr/src/nvidia-hybrid-driver"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_manifest(root: Path) -> tuple[str, int]:
    """Fingerprint regular source files without following links."""
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("source tree is not a directory")
    records: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("source tree contains a symlink: " + str(path.relative_to(root)))
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        mode = path.stat(follow_symlinks=False).st_mode & 0o777
        records.append(f"{relative}\0{mode:o}\0{sha256_file(path)}\n")
    if not records:
        raise ValueError("source tree is empty")
    return hashlib.sha256("".join(records).encode()).hexdigest(), len(records)


def validate_kernel(release: str, build_root: Path) -> Path:
    if not release or "/" in release or release in (".", ".."):
        raise ValueError("invalid kernel release")
    kernel = Path(build_root).resolve(strict=True)
    if not kernel.is_dir():
        raise ValueError("kernel build root is not a directory")
    required = (".config", "Module.symvers", "Makefile", "include/config/kernel.release",
                "include/generated/autoconf.h")
    for name in required:
        if not (kernel / name).is_file():
            raise ValueError("kernel build tree lacks " + name)
    actual = (kernel / "include/config/kernel.release").read_text().strip()
    if actual != release:
        raise ValueError(f"kernel release mismatch: requested {release}, headers say {actual}")
    return kernel


def debug_prefix_map_flags(source_root: Path, canonical_prefix: str) -> list[str]:
    """Map ephemeral source-copy paths to a stable debug-info prefix."""
    source = str(Path(source_root).resolve(strict=True))
    prefix = str(canonical_prefix)
    if not Path(prefix).is_absolute():
        raise ValueError("canonical debug source prefix must be absolute")
    if any(character.isspace() for character in source + prefix) or "=" in source + prefix:
        raise ValueError("source paths and canonical debug prefix cannot contain whitespace or '='")
    return [
        f"-ffile-prefix-map={source}={prefix}",
        f"-fdebug-prefix-map={source}={prefix}",
    ]


def wire_supplemental_conftests(source: Path, supplemental: Path) -> dict[str, str | bool]:
    """Include hybrid frontend API probes in this private source copy."""
    source = Path(source)
    supplemental = Path(supplemental).resolve(strict=True)
    if supplemental.is_symlink() or not supplemental.is_file():
        raise ValueError("supplemental conftest fragment must be a regular file")
    kbuild = source / "Kbuild"
    if kbuild.is_symlink() or not kbuild.is_file():
        raise ValueError("private source copy lacks a regular root Kbuild")
    before = kbuild.read_bytes()
    anchor = (
        b"$(foreach _module, $(NV_KERNEL_MODULES), \\\n"
        b" $(eval include $(src)/$(_module)/$(_module).Kbuild))\n"
    )
    overlay = (
        b"ifneq ($(strip $(NV_KERNEL_EXTRA_CONFTEST_KBUILD)),)\n"
        b"include $(NV_KERNEL_EXTRA_CONFTEST_KBUILD)\n"
        b"endif\n"
    )
    if overlay in before:
        if before.count(overlay) != 1:
            raise ValueError("root Kbuild repeats the supplemental conftest include")
        return {"applied": False, "kbuild_before_sha256": hashlib.sha256(before).hexdigest(),
                "kbuild_after_sha256": hashlib.sha256(before).hexdigest(),
                "fragment_sha256": sha256_file(supplemental)}
    if b"NV_KERNEL_EXTRA_CONFTEST_KBUILD" in before:
        raise ValueError("root Kbuild has an unexpected supplemental conftest include")
    if before.count(anchor) != 1:
        raise ValueError("root Kbuild does not have one exact module-include anchor")
    after = before.replace(anchor, anchor + b"\n" + overlay, 1)
    kbuild.write_bytes(after)
    return {"applied": True, "kbuild_before_sha256": hashlib.sha256(before).hexdigest(),
            "kbuild_after_sha256": hashlib.sha256(after).hexdigest(),
            "fragment_sha256": sha256_file(supplemental)}


def audit_uvm_import_bindings(frontend_symbols: dict[str, dict[str, str]],
                              consumer_symbols: dict[str, str],
                              public_api_names: list[str]) -> dict[str, Any]:
    """Verify direct R595 imports plus the deliberate control-fd address-space route."""
    public = set(public_api_names)
    actual_public = public.intersection(consumer_symbols)
    missing_public = sorted(public - actual_public)
    if missing_public != [ADDRESS_SPACE_PUBLIC_API]:
        return {"verified": False, "declared_public_api_count": len(public),
                "direct_public_import_count": len(actual_public),
                "missing_public_imports": missing_public,
                "unexpected_public_imports": sorted(actual_public - public),
                "direct_binding": None, "address_space_dispatch": None}
    direct_names = sorted(public - {ADDRESS_SPACE_PUBLIC_API})
    direct = frontend.check_public_uvm_consumer_bindings(
        frontend_symbols, consumer_symbols, direct_names)
    export = frontend_symbols.get(ADDRESS_SPACE_DISPATCH)
    import_crc = consumer_symbols.get(ADDRESS_SPACE_DISPATCH)
    dispatcher = {
        "symbol": ADDRESS_SPACE_DISPATCH,
        "frontend_crc": export.get("crc") if export else None,
        "consumer_crc": import_crc,
        "frontend_owner": export.get("module") if export else None,
        "frontend_export": export.get("export") if export else None,
        "matches": bool(export and export.get("module") == "nvidia" and
                         export.get("export") == "EXPORT_SYMBOL" and import_crc and
                         export.get("crc", "").lower() == import_crc.lower()),
        "replaces_public_call": ADDRESS_SPACE_PUBLIC_API,
    }
    return {
        "verified": bool(direct["verified"] and dispatcher["matches"]),
        "declared_public_api_count": len(public),
        "direct_public_import_count": len(actual_public),
        "missing_public_imports": missing_public,
        "unexpected_public_imports": [],
        "direct_binding": direct,
        "address_space_dispatch": dispatcher,
    }


def safe_new_path(path: Path, allowed_root: Path, label: str) -> Path:
    allowed = Path(allowed_root).resolve(strict=True)
    raw = path if path.is_absolute() else ROOT / path
    result = Path(os.path.abspath(raw))
    try:
        relative = result.relative_to(allowed)
    except ValueError:
        raise ValueError(f"{label} must be below {allowed}") from None
    cursor = allowed
    if cursor.is_symlink():
        raise ValueError(f"{label} root is a symlink")
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} path contains a symlink")
    if result.exists():
        raise ValueError(f"refusing to overwrite {label}: {result}")
    return result


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _modinfo(module: Path, field: str) -> str:
    result = subprocess.run(["modinfo", "-F", field, str(module)],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"modinfo failed for {field}: {result.stderr.strip()}")
    return result.stdout.strip()


def build(args: argparse.Namespace) -> dict[str, Any]:
    kernel = validate_kernel(args.kernel_release, args.kernel_build)
    source = Path(args.source_tree).resolve(strict=True)
    frontend_symvers = Path(args.frontend_module_symvers).resolve(strict=True)
    supplemental = Path(args.extra_conftest_kbuild).resolve(strict=True)
    compiler = Path(args.compiler).resolve(strict=True)
    if not compiler.is_file() or not os.access(compiler, os.X_OK):
        raise ValueError("compiler must be an executable regular file")
    if not (source / "Kbuild").is_file() or not (source / "nvidia-uvm").is_dir():
        raise ValueError("source tree lacks the R595 UVM Kbuild inputs")
    api_header = source / "common/inc/nv_uvm_interface.h"
    if not api_header.is_file():
        raise ValueError("source tree lacks the R595 public UVM interface header")
    source_sha, source_files = tree_manifest(source)
    symvers = frontend.symbols(frontend_symvers)
    if not any(item.get("module") == "nvidia" for item in symvers.values()):
        raise ValueError("frontend Module.symvers does not identify the nvidia owner")
    api_names = frontend.standard_uvm_symbols_from_header(api_header)
    if len(api_names) < 70:
        raise ValueError("R595 public UVM API inventory is unexpectedly incomplete")

    work = safe_new_path(args.work, ROOT / "build/experiments", "work directory")
    report_path = safe_new_path(args.report, ROOT / "evidence", "build report")
    log_path = safe_new_path(args.log, ROOT / "evidence/logs", "build log")
    work.parent.mkdir(parents=True, exist_ok=True)
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    source_copy = work / "source"
    shutil.copytree(source, source_copy, symlinks=True)
    copied_sha, copied_files = tree_manifest(source_copy)
    if (copied_sha, copied_files) != (source_sha, source_files):
        raise ValueError("private UVM source copy does not match the pinned input tree")
    conftest_overlay = wire_supplemental_conftests(source_copy, supplemental)
    prefix_flags = debug_prefix_map_flags(source_copy, args.debug_source_prefix)

    argv = ["make", "-C", str(source_copy),
            "KERNEL_UNAME=" + args.kernel_release,
            "SYSSRC=" + str(kernel),
            "CC=" + str(compiler),
            "NV_KERNEL_MODULES=nvidia-uvm",
            "KBUILD_EXTRA_SYMBOLS=" + str(frontend_symvers),
            "NV_KERNEL_EXTRA_CONFTEST_KBUILD=" + str(supplemental),
            "modules", "-j" + str(args.jobs)]
    env = os.environ.copy()
    cleared = []
    for name in ("CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "EXTRA_CFLAGS",
                 "KCFLAGS", "MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "CC", "CXX", "LD",
                 "OBJCOPY", "TARGET_ARCH", "NV_VERBOSE", "NV_SPECTRE_V2"):
        if name in env:
            cleared.append(name)
            env.pop(name)
    env["LC_ALL"] = "C"
    env["KCFLAGS"] = " ".join(prefix_flags)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log_path.open("x", encoding="utf-8") as stream:
        os.chmod(log_path, 0o600)
        stream.write("$ " + shlex.join(argv) + "\n")
        stream.write("cwd: " + str(ROOT) + "\n")
        stream.write("KCFLAGS: " + shlex.join(prefix_flags) + "\n")
        stream.flush()
        try:
            process = subprocess.run(argv, cwd=ROOT, env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, timeout=args.timeout,
                                     check=False)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
            stream.write("\nTIMEOUT after " + str(args.timeout) + " seconds\n")
    module = source_copy / "nvidia-uvm.ko"
    report: dict[str, Any] = {
        "schema": "nvidia-r595-hybrid-uvm-target-build-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "failed",
        "qualification": "failed",
        "kernel_release": args.kernel_release,
        "source": {"path": str(source), "tree_sha256": source_sha,
                   "regular_file_count": source_files},
        "source_overlays": {"supplemental_frontend_conftests": conftest_overlay},
        "inputs_sha256": {
            "kernel_config": sha256_file(kernel / ".config"),
            "kernel_release_file": sha256_file(kernel / "include/config/kernel.release"),
            "kernel_module_symvers": sha256_file(kernel / "Module.symvers"),
            "frontend_module_symvers": sha256_file(frontend_symvers),
            "extra_conftest_kbuild": sha256_file(supplemental),
            "compiler": sha256_file(compiler),
            "build_implementation": sha256_file(Path(__file__).resolve()),
        },
        "build": {"argv": argv, "exit_code": exit_code,
                  "duration_seconds": round(time.monotonic() - started, 3),
                  "environment_names_cleared": cleared,
                  "reproducible_debug_prefix_map": {
                      "source": str(source_copy),
                      "canonical_prefix": args.debug_source_prefix,
                      "flags": prefix_flags,
                  },
                  "log_path": str(log_path), "log_sha256": sha256_file(log_path),
                  "log_mode": "0600"},
        "frontend_public_uvm_api_count": len(api_names),
        "module_loaded": False,
        "module_installed": False,
        "gpu_accessed": False,
        "cuda_execution_validated": False,
    }
    try:
        if exit_code:
            raise RuntimeError("target-kernel R595 hybrid UVM Kbuild failed")
        if not module.is_file() or module.is_symlink():
            raise ValueError("Kbuild did not produce a regular nvidia-uvm.ko")
        identity = {field: _modinfo(module, field)
                    for field in ("name", "version", "vermagic", "depends", "license")}
        if identity["name"] != "nvidia_uvm" or identity["version"] != args.expected_version:
            raise ValueError("UVM module identity differs from the selected R595 release")
        if identity["vermagic"].split(maxsplit=1)[:1] != [args.kernel_release]:
            raise ValueError("UVM module vermagic differs from the requested kernel")
        if "nvidia" not in identity["depends"].split(","):
            raise ValueError("UVM module does not declare the hybrid frontend dependency")
        report["module"] = {"path": str(module), "bytes": module.stat().st_size,
                             "sha256": sha256_file(module), "identity": identity}
        consumer_work = work / ".consumer-modversions"
        consumer_work.mkdir(mode=0o700)
        consumer = frontend.extract_kernel_modversions_section(
            module, consumer_work)
        if "CONFIG_EXTENDED_MODVERSIONS=y" in (kernel / ".config").read_text():
            extended_work = work / ".consumer-extended-modversions"
            extended_work.mkdir(mode=0o700)
            consumer = frontend.merge_module_modversions(
                consumer, frontend.extract_extended_modversions(
                    module, extended_work))
        binding = audit_uvm_import_bindings(symvers, consumer, api_names)
        report["frontend_public_uvm_binding"] = binding
        if not binding["verified"]:
            raise ValueError("R595 UVM public import CRCs do not match the hybrid frontend")
        report.update({
            "status": "passed",
            "qualification": "compiled-hybrid-r595-uvm-target-kernel-module-and-public-abi",
            "source_copy_matches_input": True,
        })
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    write_report(report_path, report)
    report["report_path"] = str(report_path.resolve(strict=True))
    report["report_sha256"] = sha256_file(report_path)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-tree", type=Path, required=True)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--kernel-build", type=Path, required=True)
    parser.add_argument("--frontend-module-symvers", type=Path, required=True)
    parser.add_argument("--extra-conftest-kbuild", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, default=Path(shutil.which("gcc") or "gcc"))
    parser.add_argument("--expected-version", default="595.99.02")
    parser.add_argument("--debug-source-prefix", default=DEFAULT_DEBUG_SOURCE_PREFIX,
                        help="stable absolute path recorded in debug information")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.timeout < 1:
        parser.error("--jobs and --timeout must be positive")
    try:
        result = build(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"build_r595_hybrid_uvm_target: error: {error}", file=sys.stderr)
        return 1
    print(json.dumps({key: result.get(key) for key in
                      ("status", "qualification", "kernel_release", "module",
                       "frontend_public_uvm_binding", "report_path", "report_sha256",
                       "error")}, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
