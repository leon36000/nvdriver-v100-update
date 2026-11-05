#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Link a PTX-only SM70 image to its guarded stock-V100 CUDA execution report.

This is an offline evidence consistency check. It independently re-inspects the
fatbin with a caller-selected, hash-pinned cuobjdump and checks the recorded
guest execution and cleanup gates. It does not execute CUDA or certify a hybrid
driver.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent.resolve()
SHARED_TOOLS_ROOT = (WORKSPACE_ROOT / "tools").resolve(strict=True)
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
EXPECTED_SIZES = [1, 31, 256, 4096, 65537]
EXPECTED_ENTRIES = {"hybrid_arch", "hybrid_empty", "hybrid_add"}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PTX_ROW = re.compile(r"^PTX file\s+\d+:\s*(\S+)\s*$", re.MULTILINE)
ENTRY = re.compile(r"\.entry\s+([A-Za-z_][A-Za-z_0-9]*)\b")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
        raise ValueError(f"evidence report is not a bounded regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(f"evidence report is not valid UTF-8 JSON: {path}") from None
    if not isinstance(value, dict):
        raise ValueError(f"evidence report root is not an object: {path}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _recorded_sha(record: Any, label: str) -> str:
    _require(isinstance(record, dict), f"{label} record is missing")
    value = record.get("sha256")
    _require(isinstance(value, str) and HEX_SHA256.fullmatch(value) is not None,
             f"{label} SHA-256 is invalid")
    return value


def _one_device(runtime: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any],
                                                dict[str, Any], dict[str, Any]]:
    remote = runtime.get("remote")
    _require(isinstance(remote, dict), "runtime report has no remote guest result")
    guest = remote.get("guest")
    probe = remote.get("probe")
    _require(isinstance(guest, dict) and isinstance(probe, dict),
             "runtime guest or CUDA probe record is malformed")
    devices = probe.get("devices")
    _require(isinstance(devices, list) and len(devices) == 1 and
             isinstance(devices[0], dict),
             "runtime result must describe exactly one tested V100")
    return remote, guest, probe, devices[0]


def validate_ptx_jit_evidence(build: dict[str, Any], runtime: dict[str, Any],
                              artifact: bytes, cuobjdump_sha256: str,
                              inspection: dict[str, str]) -> dict[str, Any]:
    """Validate the build/runtime/inspection contract without executing CUDA."""
    _require(build.get("schema") == "nvidia-hybrid-sm70-ptx-jit-image-build-v1" and
             build.get("status") == "ptx-only-sm70-fatbin-built-and-statically-inspected",
             "build evidence is not the pinned SM70 PTX-only image report")
    _require(build.get("cuda_or_gpu_execution_tested") is False and
             build.get("module_loaded_or_installed") is False,
             "build report has an invalid static-only scope")
    artifact_record = build.get("artifact")
    artifact_sha = _recorded_sha(artifact_record, "build artifact")
    _require(len(artifact) == artifact_record.get("bytes") and
             sha256_bytes(artifact) == artifact_sha,
             "artifact bytes or SHA-256 differ from the build report")
    builder = build.get("builder")
    _require(isinstance(builder, dict), "build cuobjdump record is missing")
    expected_tool_sha = builder.get("cuobjdump_sha256")
    _require(isinstance(expected_tool_sha, str) and
             HEX_SHA256.fullmatch(expected_tool_sha) is not None,
             "cuobjdump SHA-256 is invalid")
    _require(cuobjdump_sha256 == expected_tool_sha,
             "cuobjdump bytes do not match the build report")

    source = build.get("source_ptx")
    _require(isinstance(source, dict) and source.get("target") == "sm_70" and
             source.get("ptx_version") == "8.8" and
             set(source.get("entrypoints", [])) == EXPECTED_ENTRIES,
             "build source PTX target, version, or entrypoints differ")
    _require(set(inspection) == {"list_elf", "list_ptx", "dump_ptx"} and
             all(isinstance(value, str) for value in inspection.values()),
             "cuobjdump inspection output is malformed")
    _require("no elf file found" in inspection["list_elf"].lower() and
             not re.search(r"^\s*ELF file\s+\d+\s*:", inspection["list_elf"], re.MULTILINE | re.IGNORECASE),
             "fatbin contains an ELF image")
    ptx_rows = PTX_ROW.findall(inspection["list_ptx"])
    _require(len(ptx_rows) == 1 and "sm_70" in ptx_rows[0],
             "fatbin must contain exactly one SM70 PTX image")
    dump = inspection["dump_ptx"]
    entries = set(ENTRY.findall(dump))
    _require(re.search(r"^\.version\s+8\.8\s*$", dump, re.MULTILINE) is not None and
             re.search(r"^\.target\s+sm_70\s*$", dump, re.MULTILINE) is not None and
             entries == EXPECTED_ENTRIES,
             "embedded PTX target or entrypoints differ from the audited kernel")

    _require(runtime.get("schema") == "nvidia-hybrid-pc3-v100-reference-transport-v1" and
             runtime.get("qualification") == "v100-reference-report-contract-valid" and
             runtime.get("exit_code") == 0 and
             runtime.get("module_after") == runtime.get("module"),
             "runtime capture did not complete with stable module bytes")
    runtime_module = runtime.get("module")
    _require(isinstance(runtime_module, dict) and
             runtime_module.get("bytes") == len(artifact) and
             _recorded_sha(runtime_module, "runtime module") == artifact_sha,
             "runtime did not load the audited artifact")
    remote, guest, probe, device = _one_device(runtime)
    _require(remote.get("qualification") == "v100-reference-report-contract-valid" and
             remote.get("host") == "pc3" and
             remote.get("host_kernel_release") == "7.0.0-38-generic" and
             guest.get("hostname") == "pc3-v100" and
             guest.get("driver_version") == "580.178.04" and
             guest.get("kernel_release") == "6.8.0-147-generic" and
             guest.get("name") == "Tesla V100-SXM2-16GB" and
             guest.get("pci") == "0000:00:05.0",
             "runtime did not use the pinned stock V100 R580 guest")
    _require(guest.get("compute_process_count_before") == 0 and
             guest.get("memory_used_mib_before") == "0" and
             isinstance(remote.get("driver_library"), dict) and
             remote["driver_library"].get("path") ==
             "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04" and
             remote["driver_library"].get("sha256") ==
             "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
             "runtime did not use the pinned idle guest and R580 libcuda")
    _require(probe.get("driver_api") == 13000 and
             probe.get("execution_mode") == "resident-contexts-sequential-kernels" and
             probe.get("concurrent_kernel_execution_validated") is False,
             "runtime did not use the pinned single-GPU probe mode")
    _require(device.get("tested") is True and device.get("targeted") is True and
             device.get("compute_capability") == "7.0" and device.get("sm") == 70 and
             device.get("architecture_kernel_passed") is True and
             device.get("synchronous_passed") is True and
             device.get("synchronous_sizes") == EXPECTED_SIZES and
             device.get("asynchronous_passed") is True and
             device.get("asynchronous_sizes") == EXPECTED_SIZES,
             "runtime did not pass the synchronous/asynchronous SM70 kernel contract")
    _require(device.get("cleanup_passed") is True and device.get("cleanup_errors") == [] and
             remote.get("guest_cleanup_passed") is True and
             remote.get("payload_file_cleanup_passed") is True and
             runtime.get("payload_cleanup_passed") is True and
             remote.get("compute_process_count_prelaunch") == 0 and
             remote.get("compute_process_count_after_probe") == 0 and
             remote.get("compute_process_count_after") == 0 and
             remote.get("compute_process_query_after_valid") is True and
             isinstance(remote.get("guest_after"), dict) and
             remote["guest_after"].get("compute_process_count") == 0 and
             remote["guest_after"].get("memory_used_mib") == "0",
             "runtime cleanup or process-count gate failed")
    scope = runtime.get("execution_scope")
    remote_scope = remote.get("execution_scope")
    expected_no_side_effects = {"guest_driver_changed": False, "module_loaded": False,
                                "pci_binding_changed": False, "vm_management_issued": False}
    _require((scope is None or scope == expected_no_side_effects) and
             remote_scope == expected_no_side_effects,
             "runtime scope was not read-only")
    probe_sha = _recorded_sha(runtime.get("probe"), "runtime probe")
    probe_contract = runtime.get("probe_contract")
    _require(isinstance(probe_contract, dict) and
             probe_sha == probe_contract.get("probe_sha256"),
             "runtime probe and its pinned contract disagree")
    probe_report = remote.get("probe")
    _require(isinstance(probe_report, dict) and
             probe_report.get("hybrid_validated") is False and
             probe_report.get("context_coexistence_passed") is False,
             "single-GPU reference must remain a stock non-hybrid result")

    return {
        "schema": "nvidia-hybrid-sm70-ptx-jit-runtime-verification-v1",
        "status": "ptx-only-sm70-kernel-executed-on-v100",
        "qualification": "stock-v100-ptx-jit-kernel-validated",
        "ptx_only_image": True,
        "elf_image_count": 0,
        "ptx_image_count": 1,
        "ptx_target": "sm_70",
        "ptx_version": "8.8",
        "entrypoints": sorted(entries),
        "artifact": {"bytes": len(artifact), "sha256": artifact_sha},
        "cuobjdump_sha256": cuobjdump_sha256,
        "gpu": {"host": "pc3", "guest": guest["hostname"], "name": guest["name"],
                "pci": guest["pci"], "driver_version": guest["driver_version"],
                "kernel_release": guest["kernel_release"]},
        "kernel_sizes": EXPECTED_SIZES,
        "cleanup_passed": True,
        "same_linux_hybrid_validated": False,
        "candidate_module_loaded_or_installed": False,
        "scope": "offline verification of prior stock-guest CUDA execution; not hybrid certification",
    }


def _load_repo_path(text: str, label: str) -> Path:
    if not isinstance(text, str) or not text or "\x00" in text:
        raise ValueError(f"{label} path is invalid")
    candidate = Path(text)
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=True)
    else:
        if ".." in PurePosixPath(text).parts:
            raise ValueError(f"{label} path escapes the project")
        resolved = (ROOT / candidate).resolve(strict=True)
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        raise ValueError(f"{label} path escapes the project") from None
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file")
    return resolved


def _load_workspace_path(text: str, label: str) -> Path:
    if not isinstance(text, str) or not text or "\x00" in text:
        raise ValueError(f"{label} path is invalid")
    candidate = Path(text)
    resolved = candidate.resolve(strict=True) if candidate.is_absolute() else \
        (ROOT / candidate).resolve(strict=True)
    if not (resolved.is_relative_to(WORKSPACE_ROOT) or
            resolved.is_relative_to(SHARED_TOOLS_ROOT)):
        raise ValueError(f"{label} path escapes the configured workspace and shared tools")
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file")
    return resolved


def _hash_file(path: Path, limit: int) -> tuple[int, str, bytes]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError(f"file is not a bounded regular file: {path}")
    data = path.read_bytes()
    if len(data) != info.st_size:
        raise ValueError(f"file changed while being read: {path}")
    return len(data), sha256_bytes(data), data


def _cuobjdump(cuobjdump: Path, artifact: Path) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, option in (("list_elf", "--list-elf"),
                        ("list_ptx", "--list-ptx"),
                        ("dump_ptx", "--dump-ptx")):
        try:
            result = subprocess.run([str(cuobjdump), option, str(artifact)],
                                    check=False, capture_output=True, text=True,
                                    timeout=45)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError(f"cuobjdump failed during {option}") from None
        combined = result.stdout + ("\n" if result.stdout and result.stderr else "") + result.stderr
        if result.returncode != 0 or len(combined) > 2 * 1024 * 1024:
            raise ValueError(f"cuobjdump returned an invalid result for {option}")
        output[key] = combined
    return output


def verify(build_path: Path, runtime_path: Path, artifact_path: Path,
           cuobjdump_path: Path) -> dict[str, Any]:
    build = read_json(build_path)
    runtime = read_json(runtime_path)
    artifact_path = _load_repo_path(str(artifact_path), "command-line artifact")
    cuobjdump_path = _load_workspace_path(str(cuobjdump_path), "command-line cuobjdump")
    artifact_size, artifact_sha, artifact = _hash_file(artifact_path, MAX_ARTIFACT_BYTES)
    tool_size, tool_sha, _ = _hash_file(cuobjdump_path, MAX_ARTIFACT_BYTES)
    if not os.access(cuobjdump_path, os.X_OK):
        raise ValueError("cuobjdump is not executable")
    artifact_record = build.get("artifact")
    _require(isinstance(artifact_record, dict), "build artifact record is missing")
    expected_artifact_path = _load_repo_path(artifact_record.get("path"), "build artifact")
    _require(artifact_path == expected_artifact_path,
             "command-line artifact differs from the build-report path")
    runtime_module = runtime.get("module")
    _require(isinstance(runtime_module, dict), "runtime module record is missing")
    module_path = _load_repo_path(runtime_module.get("path"), "runtime module")
    _require(artifact_path == module_path,
             "runtime module path differs from the audited artifact")
    builder = build.get("builder")
    _require(isinstance(builder, dict), "build cuobjdump record is missing")
    build_tool_path = _load_workspace_path(builder.get("cuobjdump_path"),
                                           "build cuobjdump")
    _require(build_tool_path == cuobjdump_path,
             "command-line cuobjdump differs from the build-report path")
    manifest_ref = build.get("base_probe_manifest")
    _require(isinstance(manifest_ref, dict), "base probe build manifest reference is missing")
    manifest_path = _load_repo_path(manifest_ref.get("path"), "base probe build manifest")
    manifest_size, manifest_sha, manifest_bytes = _hash_file(manifest_path, MAX_REPORT_BYTES)
    _require(_recorded_sha(manifest_ref, "base probe manifest") == manifest_sha,
             "base probe build manifest hash differs")
    try:
        base_manifest = json.loads(manifest_bytes.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("base probe manifest is not valid UTF-8 JSON") from None
    _require(isinstance(base_manifest, dict) and
             base_manifest.get("schema") == "nvidia-hybrid-probe-build-v2" and
             base_manifest.get("status") == "built-static-images",
             "base probe build manifest has an unexpected identity")
    base_probe_sha = _recorded_sha(base_manifest.get("probe"), "base probe")
    runtime_probe = runtime.get("probe")
    _require(isinstance(runtime_probe, dict), "runtime probe record is missing")
    _require(_recorded_sha(runtime_probe, "runtime probe") == base_probe_sha and
             manifest_ref.get("base_probe_sha256") == base_probe_sha,
             "V100 runtime probe differs from the pinned build manifest")
    probe_path = _load_repo_path(runtime_probe.get("path"), "runtime probe executable")
    probe_size, probe_sha, _ = _hash_file(probe_path, MAX_ARTIFACT_BYTES)
    _require(probe_size == runtime_probe.get("bytes") and probe_sha == base_probe_sha,
             "runtime probe executable bytes differ from the captured report")
    source_inputs = base_manifest.get("source_inputs_sha256")
    _require(isinstance(source_inputs, dict) and source_inputs,
             "base probe source-input hashes are missing")
    for source_name, source_sha in source_inputs.items():
        source_path = _load_repo_path(source_name, "base probe source input")
        _, actual_sha, _ = _hash_file(source_path, MAX_ARTIFACT_BYTES)
        _require(actual_sha == source_sha,
                 f"base probe source input changed since build: {source_path.name}")
    source_record = build.get("source_ptx")
    _require(isinstance(source_record, dict), "SM70 PTX source record is missing")
    source_path = _load_repo_path(source_record.get("path"), "SM70 PTX source")
    source_size, source_sha, source_bytes = _hash_file(source_path, MAX_ARTIFACT_BYTES)
    _require(source_size == source_record.get("bytes") and
             source_sha == source_record.get("sha256"),
             "SM70 source PTX bytes differ from the build report")
    source_text = source_bytes.decode("utf-8", "strict")
    source_entries = set(ENTRY.findall(source_text))
    _require(re.search(r"^\.version\s+8\.8\s*$", source_text, re.MULTILINE) is not None and
             re.search(r"^\.target\s+sm_70\s*$", source_text, re.MULTILINE) is not None and
             source_entries == EXPECTED_ENTRIES,
             "SM70 PTX source file does not match its recorded target and entrypoints")
    inspection = _cuobjdump(cuobjdump_path, artifact_path)
    result = validate_ptx_jit_evidence(build, runtime, artifact, tool_sha, inspection)
    result.update({
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "build_report": {"path": str(build_path), "sha256": sha256_bytes(build_path.read_bytes())},
        "runtime_report": {"path": str(runtime_path), "sha256": sha256_bytes(runtime_path.read_bytes())},
        "base_probe_manifest": {"path": str(manifest_path), "bytes": manifest_size,
                                "sha256": manifest_sha},
        "runtime_probe": {"path": str(probe_path), "bytes": probe_size,
                          "sha256": probe_sha},
        "artifact": {"path": str(artifact_path), "bytes": artifact_size, "sha256": artifact_sha},
        "cuobjdump": {"path": str(cuobjdump_path), "bytes": tool_size, "sha256": tool_sha},
    })
    return result


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-report", type=Path, required=True)
    parser.add_argument("--runtime-report", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--cuobjdump", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.build_report, args.runtime_report, args.artifact,
                        args.cuobjdump)
        write_private_json(args.output, result)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps({"status": "rejected", "error": str(error)}, sort_keys=True),
              file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "output": str(args.output),
                      "qualification": result["qualification"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
