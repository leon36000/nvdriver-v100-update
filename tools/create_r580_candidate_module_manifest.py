#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a hash-checked manifest for the standard-identity R580 module set.

The manifest joins existing build, ABI, resolver, and PC3 preflight evidence.
It never installs, signs, inserts, or otherwise activates a kernel module.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULES = {
    "open": "hybrid580_open",
    "legacy": "hybrid580_legacy",
    "frontend": "nvidia",
    "uvm": "nvidia_uvm",
}
MODULE_DEPENDENCIES = {
    "hybrid580_open": [],
    "hybrid580_legacy": [],
    "nvidia": ["hybrid580_legacy", "hybrid580_open"],
    "nvidia_uvm": ["nvidia"],
}
ISOLATED_UVM_CONFIG = "packaging/modprobe.d/hybrid580-standard-uvm.conf"
ISOLATED_UVM_PATCH = (
    "patches/r580.178.04/uvm/0007-reject-cross-gpu-tracker-dependencies.patch")
ISOLATED_UVM_OPTION = "uvm_hybrid_isolated_gpu_execution=1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _project_file(path_value: str, root: Path) -> Path:
    if not isinstance(path_value, str) or not path_value or "\x00" in path_value:
        raise ValueError("evidence contains an invalid artifact path")
    path = Path(path_value)
    path = path if path.is_absolute() else root / path
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("artifact path escapes the project root") from None
    info = resolved.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError("artifact must be a regular non-symlink file")
    return resolved


def _read_json(path: Path, root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    path = _project_file(str(path), root)
    raw = path.read_bytes()

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid evidence JSON {path.name}: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError(f"evidence report is not a JSON object: {path.name}")
    return value, {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "schema": value.get("schema"),
        "qualification": value.get("qualification"),
    }


def _artifact_record(record: dict[str, Any], root: Path, expected_name: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError(f"missing module record for {expected_name}")
    path = _project_file(record.get("path"), root)
    digest = sha256_bytes(path.read_bytes())
    if digest != record.get("sha256"):
        raise ValueError(f"on-disk hash differs from evidence for {expected_name}")
    if record.get("bytes", path.stat().st_size) != path.stat().st_size:
        raise ValueError(f"on-disk size differs from evidence for {expected_name}")
    return {
        "module_name": expected_name,
        "filename": path.name,
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": digest,
        "version": record.get("version", ""),
        "vermagic": record.get("vermagic", ""),
        "depends": sorted(record.get("depends", []))
        if isinstance(record.get("depends"), list)
        else sorted(item for item in record.get("depends", "").split(",") if item),
    }


def _checked_evidence_path(path_value: str, expected_sha256: str, root: Path,
                           expected_name: str) -> str:
    path = _project_file(path_value, root)
    if sha256_bytes(path.read_bytes()) != expected_sha256:
        raise ValueError(f"build-evidence artifact hash differs for {expected_name}")
    return path.relative_to(root).as_posix()


def _runtime_uvm_configuration(uvm_build: dict[str, Any], root: Path) -> dict[str, Any]:
    config = _project_file(ISOLATED_UVM_CONFIG, root)
    active_lines = [line.strip() for line in config.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    expected_line = f"options nvidia_uvm {ISOLATED_UVM_OPTION}"
    if active_lines != [expected_line]:
        raise ValueError("isolated UVM module option is missing or ambiguous")

    patch = _project_file(ISOLATED_UVM_PATCH, root)
    patch_bytes = patch.read_bytes()
    patch_text = patch_bytes.decode("utf-8", errors="strict")
    if ("static bool uvm_hybrid_isolated_gpu_execution = false;" not in patch_text or
            "module_param(uvm_hybrid_isolated_gpu_execution, bool, 0444);" not in patch_text):
        raise ValueError("isolated-mode patch does not declare the opt-in UVM parameter")

    patch_inputs = uvm_build.get("inputs", {}).get("patches", [])
    matching_patches = ([item for item in patch_inputs
                         if isinstance(item, dict) and item.get("path") == ISOLATED_UVM_PATCH]
                        if isinstance(patch_inputs, list) else [])
    if (len(matching_patches) != 1 or
            matching_patches[0].get("sha256") != sha256_bytes(patch_bytes)):
        raise ValueError("UVM candidate build did not consume the exact isolated-mode patch")

    return {
        "qualification": "candidate-only-source-and-modprobe-configuration",
        "module": MODULES["uvm"],
        "options": [ISOLATED_UVM_OPTION],
        "isolated_mode_required": True,
        "default_without_option": "disabled",
        "modprobe_config": {
            "path": config.relative_to(root).as_posix(),
            "sha256": sha256_bytes(config.read_bytes()),
            "bytes": config.stat().st_size,
        },
        "source_patch": {
            "path": patch.relative_to(root).as_posix(),
            "sha256": sha256_bytes(patch_bytes),
            "bytes": len(patch_bytes),
        },
        "activation_performed": False,
    }


def build_manifest(report_paths: dict[str, Path], *, project_root: Path = ROOT) -> dict[str, Any]:
    root = Path(project_root).resolve(strict=True)
    required = {"backend_pair", "frontend_build", "uvm_build", "uvm_abi",
                "dependency_graph", "pc3_preflight"}
    if set(report_paths) not in (required, required | {"software_suite"}):
        raise ValueError("manifest requires the six pinned evidence reports and optional software suite")
    reports: dict[str, dict[str, Any]] = {}
    refs: dict[str, dict[str, Any]] = {}
    for role, path in report_paths.items():
        reports[role], refs[role] = _read_json(Path(path), root)

    pair = reports["backend_pair"]
    if pair.get("schema") != "nvidia-hybrid-r580-backend-pair-audit-v2" or pair.get("status") != "passed":
        raise ValueError("backend pair report is not the passed R580 pair audit")
    frontend = reports["frontend_build"]
    if (frontend.get("qualification") != "compiled-bdf-selected-gpu-file-frontend-kernel-module" or
            frontend.get("built_module_identity", {}).get("matches") is not True or
            frontend.get("built_module_identity", {}).get("observed") != "nvidia" or
            frontend.get("inputs_unchanged") is not True or
            frontend.get("unresolved_imports") != [] or
            frontend.get("duplicate_import_providers") != {}):
        raise ValueError("frontend report does not prove the standard nvidia identity")
    backend_crc = frontend.get("backend_import_crc_validation", {})
    if backend_crc.get("verified") is not True or backend_crc.get("mismatches") != []:
        raise ValueError("frontend backend-import CRC validation is not clean")
    uvm_build = reports["uvm_build"]
    if (uvm_build.get("qualification", {}).get("level") != "compiled-frontend-bound-uvm" or
            uvm_build.get("qualification", {}).get("module_loaded_or_installed") is not False or
            uvm_build.get("qualification", {}).get("runtime_or_hardware_validated") is not False):
        raise ValueError("UVM report does not establish a compile-only frontend-bound build")
    consumer_binding = uvm_build.get("build", {}).get("frontend_consumer_binding", {})
    if (consumer_binding.get("passed") is not True or
            consumer_binding.get("frontend_module_name") != "nvidia" or
            consumer_binding.get("uvm_interface_import_count") != 77 or
            consumer_binding.get("matching_frontend_crc_count") != 77 or
            consumer_binding.get("symvers_unchanged_after_build") is not True):
        raise ValueError("UVM build report does not close the standard frontend binding")
    runtime_uvm_configuration = _runtime_uvm_configuration(uvm_build, root)
    uvm_abi = reports["uvm_abi"]
    interface = uvm_abi.get("uvm_interface", {})
    if (uvm_abi.get("qualification") != "compiled-and-consumer-modversion-crcs-validated" or
            uvm_abi.get("frontend_symvers", {}).get("provider") != "nvidia" or
            uvm_abi.get("module", {}).get("depends") != "nvidia" or
            interface.get("all_crcs_match") is not True or
            interface.get("consumer_import_count") != 77):
        raise ValueError("UVM consumer ABI report does not prove all 77 standard imports")
    graph = reports["dependency_graph"]
    if (graph.get("schema") != "nvidia-r580-hybrid-module-dependency-graph-v5" or
            graph.get("qualification") != "isolated-depmod-and-modprobe-resolution" or
            graph.get("frontend_module_name") != "nvidia" or
            graph.get("uvm_module_name") != "nvidia_uvm" or
            graph.get("module_load_attempted") is not False or
            graph.get("runtime_or_hardware_validated") is not False or
            graph.get("depmod", {}).get("warning_lines") != []):
        raise ValueError("dependency graph report is not a warning-free isolated standard-name resolution")
    expected_order = ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy", "nvidia", "nvidia_uvm"]
    if graph.get("modprobe_show_depends", {}).get("insert_order") != expected_order:
        raise ValueError("resolved standard-name module insertion plan differs")
    preflight = reports["pc3_preflight"]
    if (preflight.get("schema") not in {
                "nvidia-hybrid-canary-preflight-v4", "nvidia-hybrid-canary-preflight-v5"} or
            preflight.get("host", "").lower() != "pc3" or
            preflight.get("expected_module_names") != MODULES or
            preflight.get("tool_loaded_modules") is not False or
            preflight.get("tool_installed_modules") is not False or
            preflight.get("runtime_validated") is not False):
        raise ValueError("PC3 preflight does not describe this exact compile-only module set")
    if preflight.get("schema") == "nvidia-hybrid-canary-preflight-v5":
        staged = preflight.get("staged_stack_validation", {})
        staged_input = preflight.get("preflight_inputs", {}).get("staged_stack", {})
        staged_config = staged.get("configuration", {})
        preflight_uvm = preflight.get("candidate_modules", {}).get("uvm", {})
        if (staged.get("qualification") != "staged-manifest-config-module-hash-verified" or
                staged.get("activation_performed") is not False or
                staged.get("module_count") != 4 or
                not re.fullmatch(r"[0-9a-f]{64}", str(staged.get("staging_report_sha256", ""))) or
                not re.fullmatch(r"[0-9a-f]{64}", str(staged.get("candidate_manifest_sha256", ""))) or
                staged_input.get("staging_report_sha256") != staged.get("staging_report_sha256") or
                staged_input.get("candidate_manifest_sha256") != staged.get("candidate_manifest_sha256") or
                staged_config.get("module") != "nvidia_uvm" or
                staged_config.get("options") != [ISOLATED_UVM_OPTION] or
                staged_config.get("bound_module_sha256") != preflight_uvm.get("sha256")):
            raise ValueError("preflight v5 does not close the staged UVM option/module hash pair")

    graph_modules = graph.get("modules", {})
    pair_modules = pair.get("modules", {})
    records: dict[str, dict[str, Any]] = {}
    for role in ("open", "legacy"):
        name = MODULES[role]
        item = graph_modules.get(name)
        audit_item = pair_modules.get(role)
        if not isinstance(audit_item, dict) or item.get("sha256") != audit_item.get("sha256"):
            raise ValueError(f"dependency graph and pair audit disagree for {name}")
        pair_path = _checked_evidence_path(
            audit_item.get("path"), audit_item.get("sha256"), root, name
        )
        records[role] = _artifact_record(item, root, name)
        records[role]["build_path"] = pair_path
    frontend_module = frontend.get("module", {})
    uvm_module = uvm_abi.get("module", {})
    build_uvm_module = uvm_build.get("build", {}).get("modules", {}).get("nvidia-uvm.ko", {})
    for role, name, evidence_record in (
        ("frontend", "nvidia", frontend_module),
        ("uvm", "nvidia_uvm", uvm_module),
    ):
        item = graph_modules.get(name)
        if not isinstance(item, dict) or item.get("sha256") != evidence_record.get("sha256"):
            raise ValueError(f"dependency graph and build evidence disagree for {name}")
        if role == "uvm" and build_uvm_module.get("sha256") != item.get("sha256"):
            raise ValueError("UVM build report and consumer ABI report identify different modules")
        artifact = _artifact_record(item, root, name)
        evidence_path = _checked_evidence_path(
            evidence_record.get("path"), evidence_record.get("sha256"), root, name
        )
        if role == "uvm":
            build_path = _checked_evidence_path(
                build_uvm_module.get("path"), item.get("sha256"), root, name
            )
            if build_path != evidence_path:
                raise ValueError("UVM compile and ABI reports point at different artifacts")
        records[role] = artifact
        records[role]["build_path"] = evidence_path

    runtime_uvm_configuration["candidate_module"] = {
        "module_name": MODULES["uvm"],
        "path": records["uvm"]["path"],
        "sha256": records["uvm"]["sha256"],
    }

    symvers_record = uvm_abi.get("frontend_symvers", {})
    symvers_path = _checked_evidence_path(
        symvers_record.get("path"), symvers_record.get("sha256"), root,
        "frontend Module.symvers",
    )
    symvers_resolved = str((root / symvers_path).resolve(strict=True))
    generated_symvers = frontend.get("generated_outputs_sha256", {}).get(symvers_resolved)
    if generated_symvers != symvers_record.get("sha256"):
        raise ValueError("UVM ABI audit does not use the exact frontend build Module.symvers")

    preflight_modules = preflight.get("candidate_modules", {})
    for role, name in MODULES.items():
        record = records[role]
        candidate = preflight_modules.get(role)
        if not isinstance(candidate, dict) or candidate.get("sha256") != record["sha256"]:
            raise ValueError(f"PC3 preflight hashes differ for {name}")
        record["signer"] = candidate.get("signer", "")
        record["sig_key"] = candidate.get("sig_key", "")
        record["signature_status"] = "signed" if record["signer"] else "unsigned"

    software = reports.get("software_suite")
    if software is not None and (
            software.get("status") != "pass" or software.get("qualification") != "software-suite-only" or
            software.get("loaded_or_installed") is not False or
            software.get("runtime_or_hardware_validated") is not False):
        raise ValueError("software-suite evidence must be a clean software-only pass")

    return {
        "schema": "nvidia-r580-hybrid-candidate-module-manifest-v2",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate": {
            "driver_branch": "R580",
            "source_version": "580.178.04",
            "kernel_release": graph.get("kernel_release"),
            "frontend_module_name": "nvidia",
            "uvm_module_name": "nvidia_uvm",
            "architecture_strategy": "one R580 frontend with isolated Open and proprietary backends",
        },
        "qualification": "compiled-abi-closed-and-isolated-dependency-resolved",
        "modules": records,
        "runtime_configuration": runtime_uvm_configuration,
        "abi_closure": {
            "frontend_backend_imports": "verified",
            "uvm_import_count": interface["consumer_import_count"],
            "uvm_import_crcs_match": True,
            "unused_provider_exports": interface.get("provider_only_symbols", []),
            "frontend_module_symvers": {
                "path": symvers_path,
                "sha256": symvers_record.get("sha256"),
            },
            "dependency_load_order": expected_order,
        },
        "pc3_preflight": {
            "status": preflight.get("status"),
            "canary_ready": preflight.get("canary_ready"),
            "blocker_codes": [item.get("code") for item in preflight.get("blockers", [])],
            "host_state_observed_at_utc": preflight.get("observed_at_utc"),
        },
        "evidence": refs,
        "runtime_or_hardware_validated": False,
        "module_loaded_or_installed": False,
        "activation_authorized": False,
        "scope": (
            "Artifact, module-version CRC, and isolated depmod/modprobe-resolution evidence only. "
            "This is an exclusive standard-name R580 candidate; it is blocked against PC3's active R595 stack. "
            "No signature enrollment, installation, module insertion, GPU initialization, CUDA, UVM runtime, or performance was validated."
        ),
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite manifest report: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("backend-pair", "frontend-build", "uvm-build", "uvm-abi",
                 "dependency-graph", "pc3-preflight", "software-suite"):
        parser.add_argument("--" + name, type=Path, required=name != "software-suite")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    reports = {
        "backend_pair": args.backend_pair,
        "frontend_build": args.frontend_build,
        "uvm_build": args.uvm_build,
        "uvm_abi": args.uvm_abi,
        "dependency_graph": args.dependency_graph,
        "pc3_preflight": args.pc3_preflight,
    }
    if args.software_suite is not None:
        reports["software_suite"] = args.software_suite
    try:
        manifest = build_manifest(reports)
        write_report(args.output, manifest)
        print(json.dumps({
            "manifest": str(args.output),
            "qualification": manifest["qualification"],
            "module_count": len(manifest["modules"]),
            "pc3_preflight_status": manifest["pc3_preflight"]["status"],
            "module_loaded_or_installed": manifest["module_loaded_or_installed"],
        }, sort_keys=True))
    except (FileExistsError, OSError, TypeError, ValueError, KeyError) as exc:
        print(f"module manifest creation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
