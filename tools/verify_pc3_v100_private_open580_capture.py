#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently verify the retained PC3 R580 private-provider build artifacts."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
KERNEL_RELEASE = "6.8.0-147-generic"
SOURCE_VERSION = "580.178.04"
PRIVATE_EXPORT_PREFIX = "hybrid580_open_"
EXPECTED_INPUTS = (
    "Makefile", "Module.symvers", "include/config/auto.conf",
    "include/generated/autoconf.h", "include/generated/utsrelease.h",
    "scripts/Makefile.build", "scripts/Makefile.modpost", "scripts/mod/modpost",
    "scripts/basic/fixdep",
)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_symvers(text: str) -> dict[str, str]:
    exports: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 4 or fields[1] in exports or fields[3] not in {"EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL"}:
            raise ValueError("private Module.symvers contains an invalid or duplicate record")
        exports[fields[1]] = fields[3]
    if not exports:
        raise ValueError("private Module.symvers is empty")
    return exports


def readelf_section_strings(path: Path, section: str) -> set[str]:
    result = subprocess.run(["readelf", "-p", section, str(path)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    if result.returncode != 0:
        raise ValueError("readelf could not inspect section " + section)
    strings = set()
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        if "]" in line:
            value = line.split("]", 1)[1].strip()
            if value:
                strings.add(value)
    return strings


def parse_readelf_modinfo(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*\[\s*[0-9a-fA-F]+\]\s*(.*?)\s*$", line)
        if not match or "=" not in match.group(1):
            continue
        key, value = match.group(1).split("=", 1)
        if key and value:
            fields.setdefault(key, []).append(value)
    return fields


def module_symbols(path: Path) -> tuple[set[str], set[str]]:
    result = subprocess.run(["nm", "-g", str(path)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode != 0:
        raise ValueError("nm could not inspect the private module")
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) > 1:
            (undefined if fields[-2] in {"U", "w", "v"} else defined).add(fields[-1])
    return defined, undefined


def safe_artifact_path(relative: object) -> Path:
    if not isinstance(relative, str):
        raise ValueError("artifact path is not text")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or ".." in parsed.parts or not parsed.parts or not relative.startswith(("build/", "evidence/")):
        raise ValueError("artifact path escapes the canonical project")
    candidate = ROOT.joinpath(*parsed.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("captured artifact is missing or is a symlink")
    if not candidate.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True)):
        raise ValueError("captured artifact resolves outside the canonical project")
    return candidate


def verify_capture(capture_path: Path) -> dict:
    if capture_path.is_symlink():
        raise ValueError("capture report must not be a symlink")
    capture_path = capture_path.resolve(strict=True)
    if not capture_path.is_relative_to((ROOT / "evidence").resolve(strict=True)):
        raise ValueError("capture report must be a regular evidence file in the canonical project")
    raw = capture_path.read_bytes()
    capture = json.loads(raw.decode("utf-8", "strict"))
    checks: dict[str, bool] = {}
    errors: list[str] = []

    def check(name: str, condition: bool, message: str) -> None:
        checks[name] = bool(condition)
        if not condition:
            errors.append(message)

    check("capture_identity", capture.get("schema") == "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1" and
          capture.get("target") == "pc3@pc3" and capture.get("guest_hostname") == "pc3-v100" and
          capture.get("guest_kernel_release") == KERNEL_RELEASE,
          "capture identity differs from the pinned PC3 V100 target")
    check("compile_only_boundary", all(capture.get(key) is False for key in
          ("module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested")),
          "capture crossed the compile-only boundary")
    check("remote_cleanup", all(capture.get(key) is True for key in
          ("remote_scratch_removed", "remote_bundle_removed", "pc3_stage_bundle_removed")),
          "remote build cleanup is not verified")

    builder = capture.get("builder_report")
    check("builder_report_present", isinstance(builder, dict), "builder report is absent")
    if not isinstance(builder, dict):
        builder = {}
    check("builder_qualification", capture.get("status") == "collected" and
          capture.get("builder_qualification") == "compiled-native-private-open580-provider-only" and
          builder.get("qualification") == "compiled-native-private-open580-provider-only" and
          builder.get("source_version") == SOURCE_VERSION and builder.get("kernel_release") == KERNEL_RELEASE,
          "builder report does not prove the pinned native compile")
    check("builder_side_effect_flags", all(builder.get(key) is False for key in
          ("loaded_or_installed", "device_registered", "real_rm_executed", "gpu_accessed", "runtime_or_binary_abi_validated")) and
          builder.get("signed") is False,
          "builder report contains an unexpected runtime or signing claim")

    artifacts = capture.get("retrieved_artifacts")
    verified_artifacts: dict[str, dict] = {}
    if not isinstance(artifacts, list):
        artifacts = []
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            errors.append("captured artifact manifest record is malformed")
            continue
        try:
            path = safe_artifact_path(record["path"])
            size = path.stat().st_size
            sha = digest_file(path)
            good = type(record["bytes"]) is int and record["bytes"] == size and record["sha256"] == sha
            checks["artifact:" + record["path"]] = good
            if not good:
                errors.append("captured artifact size or hash mismatch: " + record["path"])
            verified_artifacts[record["path"]] = {"bytes": size, "sha256": sha}
        except (OSError, ValueError) as error:
            checks["artifact:" + str(record.get("path"))] = False
            errors.append(str(error))
    check("artifact_manifest_nonempty", bool(artifacts), "capture contains no artifacts")

    report_rel = next((name for name in verified_artifacts
                       if name.startswith("evidence/private-open580-guestkernel-") and name.endswith(".json")), None)
    report_artifact = None
    if report_rel is not None:
        report_artifact_path = safe_artifact_path(report_rel)
        report_artifact_raw = report_artifact_path.read_bytes()
        report_artifact = json.loads(report_artifact_raw.decode("utf-8", "strict"))
    check("builder_report_artifact_binding", report_artifact is not None and report_artifact == builder and
          report_artifact_raw is not None and digest_bytes(report_artifact_raw) == capture.get("builder_report_sha256"),
          "captured builder report does not match its bound artifact hash")

    module_records = [name for name in verified_artifacts if name.endswith("/hybrid580_open.ko")]
    module_record = next((record for record in artifacts if isinstance(record, dict) and record.get("path") in module_records), None)
    module_path = safe_artifact_path(module_records[0]) if len(module_records) == 1 else None
    module = builder.get("module") if isinstance(builder.get("module"), dict) else {}
    check("private_module_artifact", module_path is not None and module_record is not None and
          module.get("sha256") == verified_artifacts[module_records[0]]["sha256"] and
          module.get("bytes") == verified_artifacts[module_records[0]]["bytes"],
          "private .ko is missing or differs from the builder's module identity")

    metadata: dict[str, list[str]] = {}
    exported_strings: set[str] = set()
    module_exports: dict[str, str] = {}
    undefined: set[str] = set()
    machine = None
    if module_path is not None:
        header = subprocess.run(["readelf", "-h", str(module_path)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        header_text = header.stdout.decode("utf-8", "replace")
        match = re.search(r"^\s*Machine:\s*(.+)$", header_text, re.MULTILINE)
        machine = match.group(1).strip() if match else None
        modinfo_result = subprocess.run(["readelf", "-p", ".modinfo", str(module_path)], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        if modinfo_result.returncode == 0:
            metadata = parse_readelf_modinfo(modinfo_result.stdout.decode("utf-8", "replace"))
        exported_strings = readelf_section_strings(module_path, "__ksymtab_strings")
        _, undefined = module_symbols(module_path)

    metadata_claim = builder.get("metadata") if isinstance(builder.get("metadata"), dict) else {}
    check("elf_architecture", machine == "Advanced Micro Devices X86-64",
          "private module ELF machine is not x86-64")
    check("module_metadata", metadata.get("name") == ["hybrid580_open"] and
          metadata.get("license") == ["Dual MIT/GPL"] and
          metadata.get("version") == [SOURCE_VERSION] and
          bool(metadata.get("vermagic")) and metadata["vermagic"][0].startswith(KERNEL_RELEASE + " ") and
          not metadata.get("alias"),
          "private module name, license, version, vermagic, or alias metadata is incorrect")
    check("metadata_matches_builder", all(metadata.get(key) == metadata_claim.get(key)
          for key in ("name", "license", "version", "vermagic")),
          "readelf metadata differs from the builder report")

    symvers_paths = [name for name in verified_artifacts if "/private/" in name and name.endswith("/Module.symvers")]
    exports_report = builder.get("exports") if isinstance(builder.get("exports"), dict) else {}
    if len(symvers_paths) == 1:
        symvers_text = safe_artifact_path(symvers_paths[0]).read_text(encoding="utf-8", errors="strict")
        module_exports = parse_symvers(symvers_text)
    check("private_export_manifest", len(symvers_paths) == 1 and module_exports == exports_report and
          len(module_exports) == builder.get("export_count") and
          all(name.startswith(PRIVATE_EXPORT_PREFIX) for name in module_exports),
          "private Module.symvers differs from the builder export manifest")
    check("elf_exports_match_symvers", bool(module_exports) and exported_strings == set(module_exports),
          "ELF export strings differ from the private Module.symvers")
    imports_report = builder.get("imports") if isinstance(builder.get("imports"), dict) else {}
    check("module_imports_match_builder", undefined == set(imports_report) and
          len(imports_report) == builder.get("import_count") and
          builder.get("gpl_only_import_count") == sum(value == "EXPORT_SYMBOL_GPL" for value in imports_report.values()),
          "private module undefined symbols differ from the builder import manifest")
    dispatch = builder.get("control_fd_dispatch_export")
    check("private_control_fd_dispatch", isinstance(dispatch, dict) and
          dispatch.get("private_symbol") == "hybrid580_open_nvUvmInterfaceDupMemoryWithControlFd" and
          dispatch.get("private_export_flavor") == "EXPORT_SYMBOL" and
          dispatch.get("public_symbol_absent") is True,
          "private control-fd UVM dispatch export is incorrect")

    before = builder.get("target_kernel_inputs_before")
    after = builder.get("target_kernel_inputs_after")
    fingerprints = isinstance(before, dict) and isinstance(after, dict) and before == after
    fingerprints = fingerprints and isinstance(before.get("files"), dict) and set(before["files"]) == set(EXPECTED_INPUTS)
    check("target_kbuild_inputs_unchanged", fingerprints and
          builder.get("target_kernel_inputs_unchanged_after_build") is True and
          builder.get("target_kernel_symvers", {}).get("unchanged_after_build") is True,
          "target Kbuild fingerprints changed or are incomplete")
    steps = builder.get("steps")
    required_steps = {"baseline-build", "private-build", "elf-export-strings"}
    check("all_build_steps_passed", isinstance(steps, list) and bool(steps) and
          all(isinstance(item, dict) and type(item.get("exit_code")) is int and item["exit_code"] == 0 for item in steps) and
          required_steps.issubset({item.get("name") for item in steps if isinstance(item, dict)}),
          "one or more native build or validation steps did not pass")

    return {
        "schema": "nvidia-hybrid-pc3-v100-private-open580-artifact-verification-v1",
        "status": "pass" if not errors else "failed",
        "qualification": "compile-artifact-cross-checked" if not errors else "failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "capture_path": str(capture_path.relative_to(ROOT)),
        "capture_sha256": digest_bytes(raw),
        "target": capture.get("target"),
        "guest_kernel_release": capture.get("guest_kernel_release"),
        "private_module": {"path": module_records[0] if len(module_records) == 1 else None,
                           "sha256": module.get("sha256"), "bytes": module.get("bytes"),
                           "machine": machine, "metadata": metadata,
                           "export_count": len(module_exports), "import_count": len(undefined)},
        "verified_artifact_count": len(verified_artifacts),
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
        "checks": checks,
        "errors": errors,
    }


def output_path(value: str | None) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw = Path(value) if value else Path("evidence") / f"pc3-v100-private-open580-artifact-verification-{stamp}.json"
    candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = Path(os.path.abspath(candidate))
    if candidate.parent != ROOT / "evidence" or candidate.exists() or candidate.is_symlink():
        raise ValueError("verification report destination must be a new evidence file in the canonical project")
    if not candidate.parent.is_dir() or candidate.parent.is_symlink():
        raise ValueError("verification report directory must not be a symlink")
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, help="local PC3 private R580 build capture JSON")
    parser.add_argument("--output", help="new evidence JSON destination inside the canonical project")
    args = parser.parse_args(argv)
    try:
        capture = Path(args.capture)
        capture = capture if capture.is_absolute() else ROOT / capture
        result = verify_capture(capture)
        destination = output_path(args.output)
        payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"status": result["status"], "report": str(destination),
                          "sha256": digest_bytes(payload)}, sort_keys=True))
        return 0 if result["status"] == "pass" else 1
    except Exception as error:
        print(type(error).__name__ + ": " + str(error)[:240], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
