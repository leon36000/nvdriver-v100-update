#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the locally patched R580.196.07 proprietary backend in isolation.

Inputs are pinned to the verified R580.196.07 runfile, source-port report, and
matching SDK archive. The tool writes only beneath build/experiments and
evidence; it never signs, installs, loads, or accesses a GPU.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.probe_r580_proprietary_source_port import tree_fingerprint  # noqa: E402

RUNFILE = ROOT / ".cache/upstream/NVIDIA-Linux-x86_64-580.196.07.run"
RUNFILE_SHA256 = "0aab0518db53cf73c412dc7f32bbc850ca95e839d8923d0de4bff42c1c9169ce"
SDK_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.196.07.tar.xz"
SDK_ARCHIVE_SHA256 = "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"
PATCH_REPORT = ROOT / "evidence/r58019607-debugger-bridge-source-port-v2-20261101.json"
PATCH_REPORT_SHA256 = "16537c39e8853931aa1bce8216378b01e9b1134aa90edfc6f26e73415ca25d24"
PATCH_TOOL = ROOT / "tools/probe_r580_proprietary_source_port.py"
PATCH_BASE_SOURCE_SHA256 = "8abd0e8289b0bcf2403212d0a32d66931977d66f07777d47b5099a2c67b04972"
PATCHED_SOURCE_SHA256 = "39a267ccc6baf43d5faa05644c079a808569ece4a7174432bf6bcb258972c3b3"
PATCHED_SOURCE = ROOT / "build/experiments/r58019607-debugger-bridge-source-port-v2-20261101/source"
CORE_SHA256 = "24c741bc9b378d66d128de985ae016a662f721bb10faa04511310bace4910f2c"
KERNEL68_GCC13 = Path(
    "/tmp/nvidia-hybrid-linux68-headers-20261029/gcc13-root/usr/bin/"
    "x86_64-linux-gnu-gcc-13"
)
KERNEL68_GCC13_SHA256 = "1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26"
SDK_PREFIX = "NVIDIA-kernel-module-source-580.196.07/src/"
SDK_INCLUDE_DIRS = (
    "common/sdk/nvidia/inc/",
    "common/inc/",
    "nvidia/arch/nvalloc/unix/include/",
)
PROJECT_HEADERS = {
    "src/rm_session_endpoint.h": "nvidia/rm_session_endpoint.h",
    "src/hybrid580-gpu-catalog.h": "nvidia/hybrid580-gpu-catalog.h",
    "src/hybrid580_pm_provider_recovery.h": "nvidia/hybrid580-pm-provider-recovery.h",
    "src/hybrid580_pm_provider_kernel.h": "nvidia/hybrid580-pm-provider-kernel.h",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_patch_port_report(report: dict) -> bool:
    if not isinstance(report, dict) or report.get("schema") != "r580-proprietary-source-port-probe-v1":
        raise ValueError("source-port report schema is not the pinned R580 probe")
    if (report.get("version_under_test") != "580.196.07" or
            report.get("patch_version") != "580.178.04" or
            report.get("source_patch_probe_only") is not True):
        raise ValueError("source-port report does not describe the expected source-only R580 port")
    probe = report.get("patch_probe")
    if not isinstance(probe, dict):
        raise ValueError("source-port report has no patch probe result")
    if (probe.get("patch_count") != 48 or probe.get("patches_applied_count") != 48 or
            probe.get("all_patches_applied") is not True or probe.get("fuzz_notices") != [] or
            probe.get("source_tree_unchanged") is not True or
            probe.get("proprietary_core_unchanged") is not True or
            probe.get("build_performed") is not False or
            probe.get("install_or_load_performed") is not False or
            probe.get("hardware_accessed") is not False or
            probe.get("vendor_binary_reverse_engineered") is not False or
            probe.get("vendor_binary_modified") is not False or
            probe.get("source_tree_sha256_after") != PATCH_BASE_SOURCE_SHA256 or
            not isinstance(probe.get("scratch_root"), str) or
            not probe.get("scratch_root")):
        raise ValueError("source-port result is incomplete, fuzzed, or differs from the pinned source")
    boundary = report.get("license_boundary")
    if not isinstance(boundary, dict) or any(boundary.get(key) is not expected for key, expected in (
            ("proprietary_binary_reverse_engineered", False),
            ("proprietary_binary_modified", False),
            ("redistribution_authorized", False))):
        raise ValueError("source-port report violates the proprietary binary/license boundary")
    return True


def sdk_member_relative_path(member_name: str, member_kind: str) -> str | None:
    if not isinstance(member_name, str) or not member_name or "\\" in member_name:
        raise ValueError("SDK archive contains an invalid member path")
    raw = member_name.rstrip("/")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in raw.split("/")):
        raise ValueError("SDK archive contains an unsafe member path")
    if not raw.startswith(SDK_PREFIX):
        return None
    suffix = raw[len(SDK_PREFIX):]
    if not any(suffix.startswith(prefix) for prefix in SDK_INCLUDE_DIRS):
        return None
    if member_kind == "directory":
        return None
    if member_kind != "file":
        raise ValueError("SDK include tree contains a non-regular archive member")
    return suffix


def classify_build_warnings(lines) -> dict:
    result = {"objtool_naked_return": 0, "objtool_frame_pointer": 0,
              "other_warning": 0, "total_warning_lines": 0}
    for line in lines:
        if "warning:" not in line.lower():
            continue
        result["total_warning_lines"] += 1
        lowered = line.lower()
        if "warning: objtool:" in lowered and "naked' return found in mitigation_rethunk build" in lowered:
            result["objtool_naked_return"] += 1
        elif "warning: objtool:" in lowered and "call without frame pointer save/setup" in lowered:
            result["objtool_frame_pointer"] += 1
        else:
            result["other_warning"] += 1
    return result


def validate_module_metadata(metadata: dict, kernel_release: str) -> bool:
    expected = {"name": "hybrid580_legacy", "version": "580.196.07", "license": "NVIDIA"}
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError("compiled module has unexpected " + key)
    if not metadata.get("vermagic", "").startswith(kernel_release + " "):
        raise ValueError("compiled module vermagic does not match the selected kernel")
    if metadata.get("alias") or metadata.get("depends"):
        raise ValueError("private backend unexpectedly exposes PCI aliases or module dependencies")
    return True


def resolve_kernel_build_tree(kernel_release: str, kernel_build_dir: Path | None = None) -> Path:
    requested = (Path(kernel_build_dir) if kernel_build_dir is not None else
                 Path("/lib/modules", kernel_release, "build"))
    kernel = requested.resolve(strict=True)
    if not kernel.is_dir():
        raise ValueError("target kernel build path is not a directory")
    for name in ("Makefile", ".config", "Module.symvers"):
        path = kernel / name
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise ValueError("target kernel build tree is missing " + name) from error
        if not stat.S_ISREG(mode):
            raise ValueError("target kernel build tree requires a regular " + name)
    return kernel


def resolve_compiler(compiler: Path | None) -> Path | None:
    if compiler is None:
        return None
    resolved = Path(compiler).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("selected compiler must be an executable regular file")
    return resolved


def build_command(source: Path, kernel_release: str, kernel: Path,
                  jobs: int, compiler: Path | None = None) -> list[str]:
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    command = ["make", "-C", str(source), "KERNEL_UNAME=" + kernel_release,
               "SYSSRC=" + str(kernel), "NV_KERNEL_MODULES=nvidia",
               "-j" + str(jobs), "modules"]
    if compiler is not None:
        command.insert(-2, "CC=" + str(compiler))
    return command


def open_evidence_output_directories(evidence_dir: Path) -> tuple[int, int]:
    """Open evidence and logs directories without following their final components."""
    required = ("O_NOFOLLOW", "O_DIRECTORY")
    if any(not hasattr(os, flag) for flag in required):
        raise OSError("O_NOFOLLOW and O_DIRECTORY are required for evidence output")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    evidence_fd = os.open(evidence_dir, flags)
    try:
        logs_fd = os.open("logs", flags, dir_fd=evidence_fd)
    except Exception:
        os.close(evidence_fd)
        raise
    return evidence_fd, logs_fd


def validate_direct_report_path(report_path: Path, evidence_dir: Path) -> Path:
    if evidence_dir.is_symlink():
        raise ValueError("evidence output directory must not be a symlink")
    evidence_root = evidence_dir.resolve(strict=True)
    if not evidence_root.is_dir() or report_path.parent != evidence_root:
        raise ValueError("report must be a direct child of the evidence directory")
    return report_path


def _validate_output_name(name: str) -> None:
    if not name or name in (".", "..") or Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError("evidence output must be a single safe filename")


def write_private_file_at(directory_fd: int, name: str, data: bytes) -> None:
    _validate_output_name(name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence output")
    descriptor = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def create_private_log_at(directory_fd: int, name: str) -> int:
    _validate_output_name(name)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence output")
    flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
             getattr(os, "O_CLOEXEC", 0))
    return os.open(name, flags, 0o600, dir_fd=directory_fd)


def write_private_report_at(directory_fd: int, name: str, report: dict) -> None:
    write_private_file_at(directory_fd, name,
                          (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())


def read_open_file_bytes(descriptor: int) -> bytes:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError("build log descriptor is not a regular file")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def extract_sdk_headers(archive_path: Path, source: Path) -> int:
    sdk_root = source / "hybrid-sdk"
    sdk_root.mkdir()
    extracted = 0
    with tarfile.open(archive_path, "r:xz") as archive:
        for member in archive.getmembers():
            kind = "file" if member.isfile() else "directory" if member.isdir() else "other"
            suffix = sdk_member_relative_path(member.name, kind)
            if suffix is None:
                continue
            target = sdk_root.joinpath(*PurePosixPath(suffix).parts)
            if not target.resolve().is_relative_to(sdk_root.resolve()):
                raise ValueError("SDK path escaped the private scratch directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("SDK archive file could not be read")
            with stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output)
            extracted += 1
    if extracted == 0:
        raise ValueError("pinned SDK archive yielded no approved header files")
    return extracted


def stage_project_headers(source: Path) -> dict:
    hashes = {}
    for source_relative, target_relative in PROJECT_HEADERS.items():
        source_header = ROOT / source_relative
        target = source / target_relative
        shutil.copy2(source_header, target)
        hashes[source_relative] = sha256(source_header)
    control_source = ROOT / "src/hybrid580-control-session.h"
    control_target = source / "nvidia/hybrid580-control-session.h"
    control = control_source.read_bytes().replace(b"hybrid580_open", b"hybrid580_legacy")
    control_target.write_bytes(control)
    hashes["src/hybrid580-control-session.h"] = sha256(control_source)
    gpu_source = ROOT / "src/hybrid580-gpu-session.h"
    gpu_target = source / "nvidia/hybrid580-gpu-session.h"
    expected_gpu = gpu_source.read_bytes().replace(b"hybrid580_open", b"hybrid580_legacy")
    if not gpu_target.is_file() or gpu_target.is_symlink() or gpu_target.read_bytes() != expected_gpu:
        raise ValueError("patched GPU session header differs from the project API")
    hashes["src/hybrid580-gpu-session.h"] = sha256(gpu_source)
    sdk_nvos = source / "hybrid-sdk/common/sdk/nvidia/inc/nvos.h"
    if not sdk_nvos.is_file():
        raise ValueError("matching R580.196.07 SDK nvos.h was not staged")
    overlay = source / "common/inc/nvos.h"
    shutil.copy2(sdk_nvos, overlay)
    hashes["matching_sdk_nvos.h"] = sha256(sdk_nvos)
    return hashes


def _modinfo(module: Path) -> dict:
    result = {}
    for key in ("name", "version", "license", "vermagic", "alias", "depends"):
        value = subprocess.check_output(["modinfo", "-F", key, str(module)], text=True).strip()
        result[key] = value
    return result


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path,
                        default=ROOT / "build/experiments" / ("r58019607-proprietary-module-build-" + stamp))
    parser.add_argument("--report", type=Path,
                        default=ROOT / "evidence" / ("r58019607-proprietary-module-build-" + stamp + ".json"))
    parser.add_argument("--kernel-release", default="7.0.0-38-generic")
    parser.add_argument("--kernel-build-dir", type=Path,
                        help="explicit external kernel build tree (defaults to /lib/modules/<release>/build)")
    parser.add_argument("--compiler", type=Path,
                        help="optional explicit C compiler; its resolved path and SHA-256 are recorded")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    work, report_path = args.work_dir.resolve(), args.report.resolve()
    try:
        report_path = validate_direct_report_path(report_path, ROOT / "evidence")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    log_path = ROOT / "evidence/logs" / (report_path.stem + ".log")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if work.exists() or report_path.exists() or log_path.exists():
        parser.error("work, report, and log paths must all be unused")
    if not work.is_relative_to(ROOT / "build/experiments"):
        parser.error("work directory must remain under build/experiments")
    if (not report_path.is_relative_to(ROOT / "evidence") or
            not log_path.is_relative_to(ROOT / "evidence/logs")):
        parser.error("report and log must remain under evidence")
    try:
        evidence_fd, logs_fd = open_evidence_output_directories(ROOT / "evidence")
    except OSError as error:
        parser.error("evidence and logs must be real directories without symlink redirection: " + str(error))

    report = {
        "schema": "r58019607-proprietary-port-build-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "not-started",
        "qualification": "not-started",
        "loaded_or_installed": False,
        "runtime_or_hardware_validated": False,
        "core_modified": False,
        "redistribution_authorized": False,
        "work_dir": str(work),
        "log": str(log_path),
        "steps": [],
    }
    result_code = 2
    try:
        for path, expected in ((RUNFILE, RUNFILE_SHA256), (SDK_ARCHIVE, SDK_ARCHIVE_SHA256),
                               (PATCH_REPORT, PATCH_REPORT_SHA256)):
            if sha256(path) != expected:
                raise ValueError("pinned input hash mismatch: " + str(path))
        source_report = json.loads(PATCH_REPORT.read_text())
        validate_patch_port_report(source_report)
        source = PATCHED_SOURCE.resolve(strict=True)
        if not source.is_relative_to(ROOT / "build/experiments"):
            raise ValueError("pinned local patch-port source is outside the experiment area")
        source_before = tree_fingerprint(source)
        if source_before != PATCHED_SOURCE_SHA256:
            raise ValueError("patch-port source differs from its pinned tree fingerprint")
        if source_report["patch_probe"]["source_tree_sha256_after"] != PATCH_BASE_SOURCE_SHA256:
            raise ValueError("patch-port report does not identify the pinned pre-overlay source tree")
        core = source / "nvidia/nv-kernel.o_binary"
        if sha256(core) != CORE_SHA256:
            raise ValueError("R580.196.07 proprietary core hash differs from the pinned vendor object")

        kernel = resolve_kernel_build_tree(args.kernel_release, args.kernel_build_dir)
        compiler = resolve_compiler(args.compiler)
        config = kernel / ".config"
        symvers = kernel / "Module.symvers"
        report["inputs"] = {
            "runfile": {"path": str(RUNFILE), "sha256": sha256(RUNFILE)},
            "sdk_archive": {"path": str(SDK_ARCHIVE), "sha256": sha256(SDK_ARCHIVE)},
            "patch_port_report": {"path": str(PATCH_REPORT), "sha256": sha256(PATCH_REPORT)},
            "patch_port_tool": {"path": str(PATCH_TOOL), "sha256": sha256(PATCH_TOOL)},
            "build_tool": {"path": str(Path(__file__).resolve()), "sha256": sha256(Path(__file__))},
            "patch_source_tree_sha256": source_before,
            "proprietary_core_sha256": sha256(core),
            "kernel_release": args.kernel_release,
            "kernel_build_tree": str(kernel),
            "kernel_config": {"path": str(config), "sha256": sha256(config)},
            "kernel_module_symvers": {"path": str(symvers), "sha256": sha256(symvers)},
            "compiler": ({"path": str(compiler), "sha256": sha256(compiler)}
                         if compiler is not None else None),
            "pinned_source_tree": {"path": str(source), "sha256": source_before},
        }
        work.mkdir(parents=True)
        scratch = work / "source"
        shutil.copytree(source, scratch, symlinks=False)
        copied_tree = tree_fingerprint(scratch)
        if copied_tree != source_before:
            raise ValueError("isolated source copy differs from the hash-pinned patch tree")
        extracted_headers = extract_sdk_headers(SDK_ARCHIVE, scratch)
        staged_headers = stage_project_headers(scratch)
        report["staging"] = {"sdk_regular_files_extracted": extracted_headers,
                             "project_header_sha256": staged_headers,
                             "source_patch_offsets_retained": len(source_report["patch_probe"].get("offset_notices", [])),
                             "source_patch_fuzz_count": 0}
        core_copy = scratch / "nvidia/nv-kernel.o_binary"
        if sha256(core_copy) != CORE_SHA256:
            raise ValueError("proprietary core changed during source staging")

        command = build_command(scratch, args.kernel_release, kernel, args.jobs, compiler)
        descriptor = create_private_log_at(logs_fd, log_path.name)
        with os.fdopen(descriptor, "r+b") as log_stream:
            completed = subprocess.run(command, cwd=ROOT, stdout=log_stream,
                                       stderr=subprocess.STDOUT, timeout=1200, check=False)
            log_stream.flush()
            os.fsync(log_stream.fileno())
            log_bytes = read_open_file_bytes(log_stream.fileno())
        log_sha256 = hashlib.sha256(log_bytes).hexdigest()
        build_log = log_bytes.decode(errors="replace").splitlines()
        report["steps"].append({"name": "module-build", "command": command,
                                "exit_code": completed.returncode,
                                "log_sha256": log_sha256, "log_bytes": len(log_bytes)})
        report["build_warnings"] = classify_build_warnings(build_log)
        if completed.returncode:
            raise RuntimeError("R580.196.07 private backend build failed; inspect the pinned log")
        module = scratch / "hybrid580_legacy.ko"
        if not module.is_file() or module.is_symlink():
            raise ValueError("successful Kbuild did not produce a regular private module")
        metadata = _modinfo(module)
        validate_module_metadata(metadata, args.kernel_release)
        if sha256(core_copy) != CORE_SHA256 or sha256(core) != CORE_SHA256:
            raise ValueError("vendor core bytes changed during the compile")
        if tree_fingerprint(source) != source_before:
            raise ValueError("patch-port source input changed during the compile")
        report["module"] = {"path": str(module), "sha256": sha256(module),
                            "bytes": module.stat().st_size, "metadata": metadata}
        report["status"] = "compiled-private-proprietary-backend"
        report["qualification"] = (
            "compiled-module-with-retained-build-warnings"
            if report["build_warnings"]["total_warning_lines"] else "compiled-module-only")
        report["source_patch_tree_unchanged"] = True
        report["proprietary_core_unchanged"] = True
        result_code = 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError, tarfile.TarError) as error:
        report["status"] = "failed"
        report["qualification"] = "compile-or-provenance-failed"
        report["error"] = str(error)
    try:
        write_private_report_at(evidence_fd, report_path.name, report)
    finally:
        os.close(logs_fd)
        os.close(evidence_fd)
    print(json.dumps({"status": report["status"], "qualification": report["qualification"],
                      "report": str(report_path), "log": str(log_path),
                      "module": report.get("module")}, indent=2))
    return result_code


if __name__ == "__main__":
    raise SystemExit(main())
