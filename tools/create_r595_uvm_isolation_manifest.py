#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the R595 isolated-UVM option to one exact module and evidence chain.

This creates private evidence only. It never signs, installs, stages into the
host module tree, inserts, or executes a kernel module.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG_RELATIVE_PATH = Path("packaging/modprobe.d/hybrid595-standard-uvm.conf")
EXPECTED_CONFIG_LINE = "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1"
PARAMETER_NAME = "uvm_hybrid_isolated_gpu_execution"
EXPECTED_R595_UVM_SCHEMA = "r595-gv100-complete-hal-probe-v10"
EXPECTED_AUDIT_SCHEMA = "hybrid-module-bundle-static-audit-v1"
EXPECTED_DEPMOD_SCHEMA = "hybrid-module-bundle-depmod-static-v1"
EXPECTED_LOAD_ORDER = [
    "hybrid580_open.ko",
    "hybrid580_legacy.ko",
    "nvidia.ko",
    "nvidia_uvm.ko",
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _project_file(value: str | Path, root: Path) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise ValueError("evidence contains an invalid path")
    root = root.resolve(strict=True)
    supplied = Path(value)
    candidate = supplied if supplied.is_absolute() else root / supplied
    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(root)
    except ValueError:
        raise ValueError("evidence path escapes the project root") from None
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink evidence path is refused")
    info = cursor.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("evidence artifact must be a regular file")
    return cursor


def _read_json(path_value: str | Path, root: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    path = _project_file(path_value, root)
    raw = path.read_bytes()

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    try:
        report = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid evidence JSON {path.name}: {exc}") from None
    if not isinstance(report, dict):
        raise ValueError(f"evidence report is not a JSON object: {path.name}")
    reference = {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256(raw),
        "bytes": len(raw),
        "schema": report.get("schema"),
        "qualification": report.get("qualification"),
    }
    return report, reference, path


def _verified_record_path(value: str, expected_hash: str, root: Path, label: str) -> tuple[Path, dict[str, Any]]:
    path = _project_file(value, root)
    raw = path.read_bytes()
    digest = _sha256(raw)
    if digest != expected_hash:
        raise ValueError(f"{label} hash differs from its build evidence")
    return path, {"path": path.relative_to(root).as_posix(), "sha256": digest, "bytes": len(raw)}


def build_manifest(inputs: dict[str, str | Path], *, project_root: Path = ROOT) -> dict[str, Any]:
    required = {
        "build_report",
        "bundle_audit",
        "depmod_report",
        "preflight_report",
        "software_suite_report",
        "uvm_module",
        "modprobe_config",
    }
    if set(inputs) != required:
        raise ValueError("exactly six R595 UVM manifest inputs are required")
    root = Path(project_root).resolve(strict=True)

    build, build_ref, build_path = _read_json(inputs["build_report"], root)
    audit, audit_ref, audit_path = _read_json(inputs["bundle_audit"], root)
    depmod, depmod_ref, depmod_path = _read_json(inputs["depmod_report"], root)
    preflight, preflight_ref, _ = _read_json(inputs["preflight_report"], root)
    software, software_ref, _ = _read_json(inputs["software_suite_report"], root)

    if (software.get("schema") != "software-verification-openrm-hal-matrix-v1" or
            software.get("status") != "pass" or software.get("process_exit_code") != 0 or
            not isinstance(software.get("tests_run"), int) or software["tests_run"] <= 0 or
            software.get("qualification") != "software-suite-only" or
            software.get("runtime_or_hardware_validated") is not False or
            software.get("loaded_or_installed") is not False):
        raise ValueError("a passed software-suite-only report is required for the manifest")
    generator_path = _project_file("tools/create_r595_uvm_isolation_manifest.py", root)
    generator_hash = _sha256(generator_path.read_bytes())
    auditor_path = _project_file("tools/audit_hybrid_candidate_bundle.py", root)
    auditor_hash = _sha256(auditor_path.read_bytes())
    test_path = _project_file("tests/test_create_r595_uvm_isolation_manifest.py", root)
    test_hash = _sha256(test_path.read_bytes())
    if (software.get("implementation_sha256", {}).get(
            "tools/create_r595_uvm_isolation_manifest.py") != generator_hash or
            software.get("implementation_sha256", {}).get(
                "tools/audit_hybrid_candidate_bundle.py") != auditor_hash or
            software.get("test_source_sha256", {}).get(
                "tests/test_create_r595_uvm_isolation_manifest.py") != test_hash):
        raise ValueError("suite report does not pin the current manifest, auditor, and test sources")

    if (build.get("schema") != EXPECTED_R595_UVM_SCHEMA or build.get("status") != "passed" or
            build.get("module_loaded") is not False or build.get("module_installed") is not False or
            build.get("hardware_validated") is not False):
        raise ValueError("UVM build report must be a passed compile-only R595 HAL build")
    candidate = build.get("candidate_module", {})
    if candidate.get("linked_this_run") is not True:
        raise ValueError("build report does not identify a freshly linked UVM candidate")
    module_path, module_ref = _verified_record_path(
        candidate.get("path"), candidate.get("sha256"), root, "UVM module"
    )
    requested_module = _project_file(inputs["uvm_module"], root)
    if requested_module != module_path:
        raise ValueError("requested UVM module path differs from build report")

    archive = build.get("r580_archive")
    archive_hash = build.get("r580_archive_sha256")
    expected_archive_hash = build.get("expected_r580_archive_sha256")
    archive_path, archive_ref = _verified_record_path(archive, archive_hash, root, "R580.196.07 source archive")
    if archive_hash != expected_archive_hash:
        raise ValueError("UVM build report does not pin its exact R580.196.07 archive")

    if (audit.get("schema") != EXPECTED_AUDIT_SCHEMA or audit.get("status") != "passed" or
            audit.get("qualification") != "static-module-bundle-closure" or
            audit.get("issues") != [] or audit.get("module_loaded") is not False or
            audit.get("module_installed") is not False or
            audit.get("runtime_or_hardware_validated") is not False):
        raise ValueError("bundle audit must be a clean static-only pass")
    if (audit.get("implementation_sha256", {}).get(
            "tools/audit_hybrid_candidate_bundle.py") != auditor_hash):
        raise ValueError("bundle audit auditor source hash differs from the current checked implementation")
    audit_build_ref = audit.get("reports", {}).get("uvm", {})
    if (audit_build_ref.get("sha256") != build_ref["sha256"] or
            _project_file(audit_build_ref.get("path", ""), root) != build_path):
        raise ValueError("bundle audit does not pin this exact UVM build report")

    uvm = audit.get("modules", {}).get("uvm", {})
    parameters = uvm.get("parameters", {})
    if uvm.get("name") != "nvidia_uvm" or uvm.get("sha256") != module_ref["sha256"]:
        raise ValueError("bundle audit identifies a different UVM module")
    if _project_file(uvm.get("path", ""), root) != module_path:
        raise ValueError("bundle audit path differs from the exact UVM module")
    if parameters.get(PARAMETER_NAME, {}).get("type") != "bool":
        raise ValueError("bundle audit does not expose the bool isolation parameter")
    expected_kernel = str(audit.get("kernel_release", ""))
    if (uvm.get("depends") != ["nvidia"] or not expected_kernel or
            not str(uvm.get("vermagic", "")).startswith(expected_kernel)):
        raise ValueError("UVM module identity or kernel dependency differs from the bundle")

    if (depmod.get("schema") != EXPECTED_DEPMOD_SCHEMA or depmod.get("status") != "passed" or
            depmod.get("qualification") != "isolated-dependency-map-only" or
            depmod.get("loaded_or_installed") is not False or
            depmod.get("runtime_or_hardware_validated") is not False):
        raise ValueError("depmod report must be a passed isolated dependency-only result")
    if (_project_file(depmod.get("audit_report", ""), root) != audit_path or
            depmod.get("audit_report_sha256") != audit_ref["sha256"]):
        raise ValueError("depmod report does not pin the exact bundle audit")
    depmod_uvm = depmod.get("modules", {}).get("uvm", {})
    if depmod_uvm.get("name") != "nvidia_uvm" or depmod_uvm.get("sha256") != module_ref["sha256"]:
        raise ValueError("depmod report identifies a different UVM module")
    if depmod.get("resolution", {}).get("nvidia_uvm", {}).get("ordered_modules") != EXPECTED_LOAD_ORDER:
        raise ValueError("depmod report has an unexpected four-module load order")

    if (preflight.get("host", "").lower() != "pc3" or
            preflight.get("runtime_validated") is not False or
            preflight.get("tool_loaded_modules") is not False or
            preflight.get("tool_installed_modules") is not False):
        raise ValueError("PC3 preflight must remain read-only and compile-only")
    preflight_uvm = preflight.get("candidate_modules", {}).get("uvm", {})
    preflight_inputs = preflight.get("preflight_inputs", {})
    preflight_audit = preflight_inputs.get("candidate_bundle_audit", {})
    preflight_depmod = preflight_inputs.get("candidate_depmod_report", {})
    if preflight_uvm.get("sha256") != module_ref["sha256"]:
        raise ValueError("PC3 preflight is for a different UVM module")
    if (_project_file(preflight_audit.get("path", ""), root) != audit_path or
            preflight_audit.get("sha256") != audit_ref["sha256"]):
        raise ValueError("PC3 preflight does not pin the exact bundle audit")
    if (_project_file(preflight_depmod.get("path", ""), root) != depmod_path or
            preflight_depmod.get("sha256") != depmod_ref["sha256"]):
        raise ValueError("PC3 preflight does not pin the exact depmod report")

    config_path = _project_file(inputs["modprobe_config"], root)
    if config_path.relative_to(root) != CONFIG_RELATIVE_PATH:
        raise ValueError("modprobe configuration must be the candidate-only R595 config")
    active_lines = [
        line.strip() for line in config_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if active_lines != [EXPECTED_CONFIG_LINE]:
        raise ValueError("config must contain only the exact candidate UVM option")
    config_data = config_path.read_bytes()
    config_ref = {
        "path": config_path.relative_to(root).as_posix(),
        "sha256": _sha256(config_data),
        "bytes": len(config_data),
    }

    return {
        "schema": "nvidia-hybrid-r595-uvm-isolation-manifest-v2",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "static-build-and-config-closure",
        "kernel_release": audit["kernel_release"],
        "module": {
            "name": "nvidia_uvm",
            "version": uvm.get("version", ""),
            "vermagic": uvm["vermagic"],
            "depends": uvm["depends"],
            **module_ref,
        },
        "configuration": {
            **config_ref,
            "module": "nvidia_uvm",
            "options": [PARAMETER_NAME + "=1"],
            "default_without_option": "disabled",
            "isolated_execution_required": True,
            "bound_module_sha256": module_ref["sha256"],
            "activation_performed": False,
        },
        "source_hal": {
            "release": "580.196.07",
            **archive_ref,
        },
        "dependency_load_order": EXPECTED_LOAD_ORDER,
        "pc3_preflight": {
            "status": preflight.get("status"),
            "canary_ready": preflight.get("canary_ready"),
            "blocker_codes": [item.get("code") for item in preflight.get("blockers", [])],
            "observed_at_utc": preflight.get("observed_at_utc"),
        },
        "evidence": {
            "uvm_build": build_ref,
            "bundle_audit": audit_ref,
            "bundle_audit_implementation": {
                "path": auditor_path.relative_to(root).as_posix(),
                "sha256": auditor_hash,
                "bytes": auditor_path.stat().st_size,
            },
            "depmod": depmod_ref,
            "pc3_preflight": preflight_ref,
            "software_suite": software_ref,
            "manifest_generator": {
                "path": generator_path.relative_to(root).as_posix(),
                "sha256": generator_hash,
                "bytes": generator_path.stat().st_size,
            },
            "manifest_test": {
                "path": test_path.relative_to(root).as_posix(),
                "sha256": test_hash,
                "bytes": test_path.stat().st_size,
            },
        },
        "module_loaded_or_installed": False,
        "runtime_or_hardware_validated": False,
        "activation_performed": False,
    }


def write_report(path: Path, report: dict[str, Any], *, project_root: Path = ROOT) -> None:
    root = Path(project_root).resolve(strict=True)
    output = Path(path)
    output = output if output.is_absolute() else root / output
    output = Path(os.path.abspath(output))
    try:
        relative = output.relative_to(root)
    except ValueError:
        raise ValueError("output path escapes project root") from None
    cursor = root
    for part in relative.parts[:-1]:
        cursor = cursor / part
        cursor.mkdir(exist_ok=True)
        if stat.S_ISLNK(cursor.lstat().st_mode) or not cursor.is_dir():
            raise ValueError("unsafe output directory")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite manifest: {output}")
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".r595-uvm-manifest-", dir=output.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, output)
    finally:
        temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("build-report", "bundle-audit", "depmod-report", "preflight-report",
                "software-suite-report",
                "uvm-module", "modprobe-config"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = {
        "build_report": args.build_report,
        "bundle_audit": args.bundle_audit,
        "depmod_report": args.depmod_report,
        "preflight_report": args.preflight_report,
        "software_suite_report": args.software_suite_report,
        "uvm_module": args.uvm_module,
        "modprobe_config": args.modprobe_config,
    }
    try:
        manifest = build_manifest(inputs)
        write_report(args.output, manifest)
        print(json.dumps({
            "manifest": str(args.output),
            "qualification": manifest["qualification"],
            "module_sha256": manifest["module"]["sha256"],
            "canary_ready": manifest["pc3_preflight"]["canary_ready"],
            "activation_performed": False,
        }, sort_keys=True))
    except (FileExistsError, OSError, TypeError, ValueError, KeyError) as exc:
        print(f"R595 UVM manifest creation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
