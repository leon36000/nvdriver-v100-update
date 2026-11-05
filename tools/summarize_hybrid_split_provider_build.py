#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a path-free receipt for a hash-pinned split-provider module build."""
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
sys.path.insert(0, str(ROOT))
REPORT_ROLES = ("frontend", "open", "legacy", "uvm", "bundle", "depmod")
EXPECTED = {
    "frontend": (
        "nvidia-hybrid-gpu-file-frontend-v1",
        "compiled-bdf-selected-gpu-file-frontend-kernel-module",
    ),
    "open": (
        "replayed-r595-private-open-debugger-bridge-build-v1",
        "compiled-replayed-r595-private-open-debugger-provider",
    ),
    "legacy": (
        "r58019607-proprietary-port-build-v1",
        "compiled-module-with-retained-build-warnings",
    ),
    "uvm": (
        "nvidia-r595-hybrid-uvm-target-build-v1",
        "compiled-hybrid-r595-uvm-target-kernel-module-and-public-abi",
    ),
    "bundle": (
        "hybrid-module-bundle-static-audit-v1",
        "static-module-bundle-closure",
    ),
    "depmod": (
        "hybrid-module-bundle-depmod-static-v1",
        "isolated-dependency-map-only",
    ),
}
MODULE_ROLES = ("frontend", "legacy", "open", "uvm")
EXPECTED_MODULE_NAMES = {
    "frontend": "nvidia",
    "legacy": "hybrid580_legacy",
    "open": "hybrid580_open",
    "uvm": "nvidia_uvm",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError("invalid split-provider build evidence: " + label)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in build evidence")
        result[key] = value
    return result


def _read_regular_json(path: Path, root: Path) -> tuple[dict[str, Any], str]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("build evidence must not be a symlink")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("build evidence is outside the project") from None
    fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("build evidence must be a regular file")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid build evidence JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("build evidence root must be an object")
    return value, _sha256(raw)


def _project_artifact(path_value: Any, expected_sha256: Any,
                      root: Path) -> tuple[Path, int]:
    if not isinstance(path_value, str) or not path_value or "\x00" in path_value:
        raise ValueError("invalid module artifact path in build evidence")
    path = Path(path_value)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        raise ValueError("module artifact must not be a symlink")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("module artifact is outside the project") from None
    fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("module artifact must be a regular file")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    if digest.hexdigest() != expected_sha256:
        raise ValueError("module artifact hash differs from build evidence")
    return resolved, info.st_size


def _warning_category(line: str) -> str:
    """Return a stable warning class without retaining source paths or text."""
    if re.search(r"pahole version differs", line, re.IGNORECASE):
        return "pahole_version_mismatch"
    if re.search(r"objtool:.*'naked' return found", line):
        return "objtool_naked_return"
    if re.search(r"objtool:.*frame pointer", line, re.IGNORECASE):
        return "objtool_frame_pointer"
    match = re.search(r"warning:.*?\[(-W[^\]]+)\]", line)
    if match:
        return "compiler:" + match.group(1)
    return "unclassified"


def _warning_categories(lines: list[str]) -> dict[str, int]:
    categories: dict[str, int] = {}
    for line in lines:
        if not re.search(r"\bwarning\b", line, re.IGNORECASE):
            continue
        category = _warning_category(line)
        categories[category] = categories.get(category, 0) + 1
    return dict(sorted(categories.items()))


def _project_log(path_value: Any, expected_sha256: Any,
                 root: Path) -> tuple[str, dict[str, int]]:
    """Read a build log under the project and return its hash and warning classes."""
    if not isinstance(path_value, str) or not path_value or "\x00" in path_value:
        raise ValueError("invalid build log path in build evidence")
    path = Path(path_value)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink():
        raise ValueError("build log must not be a symlink")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("build log is outside the project") from None
    fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("build log must be a regular file")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    digest = _sha256(raw)
    if expected_sha256 is not None and (
            not isinstance(expected_sha256, str) or digest != expected_sha256):
        raise ValueError("build log hash differs from build evidence")
    lines = raw.decode("utf-8", errors="replace").splitlines()
    return digest, _warning_categories(lines)


def _nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _build_warning_inventory(reports: dict[str, dict[str, Any]],
                             root: Path) -> dict[str, Any]:
    frontend_warnings = reports["frontend"].get("build_warnings")
    _require(isinstance(frontend_warnings, list) and
             all(isinstance(item, str) for item in frontend_warnings),
             "frontend warning inventory")

    legacy = reports["legacy"]
    legacy_counts = legacy.get("build_warnings")
    _require(isinstance(legacy_counts, dict) and
             "total_warning_lines" in legacy_counts and
             all(isinstance(key, str) and _nonnegative_integer(value)
                 for key, value in legacy_counts.items()),
             "R580 warning inventory")
    legacy_total = legacy_counts["total_warning_lines"]
    legacy_categories = {key: value for key, value in legacy_counts.items()
                         if key != "total_warning_lines"}
    _require(legacy_total == sum(legacy_categories.values()),
             "R580 warning totals")
    legacy_log_sha, legacy_warning_categories = _project_log(
        legacy.get("log"), None, root)
    legacy_log_warnings = sum(legacy_warning_categories.values())
    _require(legacy_log_warnings == legacy_total,
             "R580 build log warning count")
    for category in ("objtool_frame_pointer", "objtool_naked_return"):
        _require(legacy_warning_categories.get(category, 0) ==
                 legacy_categories.get(category, 0),
                 "R580 " + category + " log count")
    reported_other = legacy_total - sum(
        legacy_categories.get(category, 0) for category in
        ("objtool_frame_pointer", "objtool_naked_return"))
    observed_other = legacy_log_warnings - sum(
        legacy_warning_categories.get(category, 0) for category in
        ("objtool_frame_pointer", "objtool_naked_return"))
    _require(observed_other == reported_other,
             "R580 other warning log count")

    open_build_log = reports["open"].get("build", {}).get("log", {})
    _require(isinstance(open_build_log, dict), "open-provider build log record")
    open_log_sha, open_warning_categories = _project_log(
        open_build_log.get("path"), open_build_log.get("sha256"), root)
    open_warnings = sum(open_warning_categories.values())

    uvm_build = reports["uvm"].get("build", {})
    uvm_log_sha, uvm_warning_categories = _project_log(
        uvm_build.get("log_path"), uvm_build.get("log_sha256"), root)
    uvm_log_warnings = sum(uvm_warning_categories.values())

    frontend_warning_categories = _warning_categories(frontend_warnings)
    frontend_unclassified = frontend_warning_categories.get("unclassified", 0)
    legacy_unclassified = legacy_warning_categories.get("unclassified", 0)
    open_unclassified = open_warning_categories.get("unclassified", 0)
    uvm_unclassified = uvm_warning_categories.get("unclassified", 0)
    component_total = (len(frontend_warnings) + legacy_total + open_warnings +
                       uvm_log_warnings)
    return {
        "reported_total_lines": component_total,
        "counting_complete": True,
        "message_classification_complete": all(value == 0 for value in (
            frontend_unclassified, legacy_unclassified, open_unclassified,
            uvm_unclassified)),
        "components": {
            "frontend": {
                "reported_warning_lines": len(frontend_warnings),
                "categories": frontend_warning_categories,
                "unclassified_warning_lines": frontend_unclassified,
                "warning_log_in_report": False,
            },
            "open_provider": {
                "reported_warning_lines": open_warnings,
                "categories": open_warning_categories,
                "unclassified_warning_lines": open_unclassified,
                "build_log_sha256": open_log_sha,
                "build_log_hash_verified": True,
            },
            "legacy_provider": {
                "reported_warning_lines": legacy_total,
                "categories": legacy_warning_categories,
                "source_report_categories": legacy_categories,
                "unclassified_warning_lines": legacy_unclassified,
                "build_log_sha256": legacy_log_sha,
                "build_log_hash_verified": True,
            },
            "uvm": {
                "reported_warning_lines": uvm_log_warnings,
                "categories": uvm_warning_categories,
                "unclassified_warning_lines": uvm_unclassified,
                "build_log_sha256": uvm_log_sha,
                "build_log_hash_verified": True,
            },
        },
        "unclassified_warning_lines": (frontend_unclassified +
                                       legacy_unclassified + open_unclassified +
                                       uvm_unclassified),
        "limitations": [
            "Warning totals are bound to the build reports and available raw logs.",
            "The R580 source report retains aggregate objtool categories; this inventory classifies available warning lines by message type.",
            "Recognized warning categories do not establish warning impact, kernel safety, or runtime behavior.",
            "Some warning lines may remain unclassified when their message does not match a recognized compiler or objtool form.",
        ],
    }


def _dependencies(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item for item in value.split(",") if item]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ValueError("invalid module dependency list in build evidence")


def _module_from_build(report: dict[str, Any], role: str) -> dict[str, Any]:
    module = report.get("module")
    if not isinstance(module, dict):
        raise ValueError("missing module record in build report")
    if role == "legacy":
        identity = module.get("metadata")
        if not isinstance(identity, dict):
            raise ValueError("missing legacy module metadata")
        return {
            "path": module.get("path"), "sha256": module.get("sha256"),
            "bytes": module.get("bytes"), "name": identity.get("name"),
            "version": identity.get("version"), "vermagic": identity.get("vermagic"),
            "license": identity.get("license"),
            "depends": _dependencies(identity.get("depends", "")),
        }
    if role == "frontend":
        return {
            "path": module.get("path"), "sha256": module.get("sha256"),
            "bytes": module.get("bytes"), "name": report.get("module_name"),
            "depends": None,
        }
    if role == "open":
        return {
            "path": module.get("path"), "sha256": module.get("sha256"),
            "bytes": module.get("bytes"), "name": module.get("name"),
            "version": report.get("source_version"),
            "license": module.get("license"),
            "depends": [],
        }
    identity = module.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("missing UVM module identity")
    return {
        "path": module.get("path"), "sha256": module.get("sha256"),
        "bytes": module.get("bytes"), "name": identity.get("name"),
        "version": identity.get("version"), "vermagic": identity.get("vermagic"),
        "license": identity.get("license"),
        "depends": _dependencies(identity.get("depends", "")),
    }


def build_summary(reports: dict[str, dict[str, Any]],
                  report_hashes: dict[str, str], *, root: Path = ROOT) -> dict[str, Any]:
    """Validate cross-report provenance and return a path-free build receipt."""
    root = Path(root).resolve(strict=True)
    if set(reports) != set(REPORT_ROLES) or set(report_hashes) != set(REPORT_ROLES):
        raise ValueError("six named build reports are required")
    for role, (schema, qualification) in EXPECTED.items():
        report = reports[role]
        _require(report.get("schema") == schema, role + " schema")
        _require(report.get("qualification") == qualification, role + " qualification")
        _require(report_hashes[role] and len(report_hashes[role]) == 64,
                 role + " report hash")

    kernel = reports["frontend"].get("kernel_release")
    _require(isinstance(kernel, str) and bool(kernel), "kernel release")
    for role in ("open", "legacy", "uvm", "bundle", "depmod"):
        report_kernel = reports[role].get("kernel_release")
        if role == "legacy" and report_kernel is None:
            report_kernel = reports[role].get("inputs", {}).get("kernel_release")
        _require(report_kernel == kernel, role + " kernel release")

    frontend = reports["frontend"]
    public_binding = frontend.get("public_uvm_consumer_binding", {})
    _require(public_binding.get("enabled") is True and
             public_binding.get("verified") is True and
             public_binding.get("api_count") == 79 and
             public_binding.get("matched_count") == 79 and
             public_binding.get("missing") == [] and
             public_binding.get("mismatches") == [], "stock R595 UVM binding")
    _require(frontend.get("objtool_active") is True and
             frontend.get("inputs_unchanged") is True and
             frontend.get("unresolved_imports") == [] and
             frontend.get("duplicate_import_providers") in ([], {}) and
             frontend.get("hybrid_uvm_api_contract_failures") == [],
             "frontend compile/import checks")
    _require(frontend.get("loaded_or_installed") is False and
             frontend.get("real_rm_executed") is False and
             frontend.get("gpu_accessed") is False and
             frontend.get("cuda_compatibility_established") is False,
             "frontend runtime boundary")
    backend_crc = frontend.get("backend_import_crc_validation", {})
    _require(backend_crc.get("verified") is True and
             backend_crc.get("mismatches") == [], "backend import CRCs")
    _require(frontend.get("build_warnings") == [
        "warning: pahole version differs from the one used to build the kernel",
    ], "frontend build-warning inventory")
    warning_inventory = _build_warning_inventory(reports, root)

    uvm = reports["uvm"]
    _require(uvm.get("status") == "passed" and
             uvm.get("frontend_public_uvm_binding", {}).get("verified") is True,
             "hybrid UVM build and binding")
    uvm_binding = uvm["frontend_public_uvm_binding"]
    _require(uvm_binding.get("declared_public_api_count") == 79 and
             uvm_binding.get("direct_public_import_count") == 78 and
             uvm_binding.get("missing_public_imports") ==
             ["nvUvmInterfaceDupAddressSpace"], "UVM control-fd replacement contract")
    dispatch = uvm_binding.get("address_space_dispatch", {})
    _require(dispatch.get("matches") is True and
             dispatch.get("replaces_public_call") == "nvUvmInterfaceDupAddressSpace" and
             dispatch.get("symbol") == "nvUvmInterfaceDupAddressSpaceWithControlFd",
             "UVM control-fd dispatch CRC")
    _require(uvm.get("source_copy_matches_input") is True,
             "UVM source-copy identity")
    symvers_outputs = [
        (path, digest) for path, digest in
        frontend.get("generated_outputs_sha256", {}).items()
        if Path(path).name == "Module.symvers"
    ]
    _require(len(symvers_outputs) == 1, "frontend Module.symvers output")
    symvers_path, symvers_hash = symvers_outputs[0]
    _project_artifact(symvers_path, symvers_hash, root)
    argv = uvm.get("build", {}).get("argv", [])
    _require(f"KBUILD_EXTRA_SYMBOLS={symvers_path}" in argv,
             "UVM build consumes the exact frontend Module.symvers")

    audit = reports["bundle"]
    _require(audit.get("status") == "passed" and audit.get("issues") == [],
             "four-module closure status")
    _require(audit.get("module_loaded") is False and
             audit.get("module_installed") is False and
             audit.get("runtime_or_hardware_validated") is False,
             "bundle activation boundary")
    for role in ("frontend", "open", "legacy", "uvm"):
        referenced = audit.get("reports", {}).get(role, {})
        _require(referenced.get("sha256") == report_hashes[role],
                 "bundle input report hash for " + role)

    audited_modules = audit.get("modules", {})
    _require(set(audited_modules) == set(MODULE_ROLES), "bundle module set")
    normalized_modules = {}
    for role in MODULE_ROLES:
        built = _module_from_build(reports[role], role)
        audited = audited_modules[role]
        expected_name = EXPECTED_MODULE_NAMES[role]
        _require(built.get("name") == expected_name and
                 audited.get("name") == expected_name, role + " module name")
        _require(built.get("sha256") == audited.get("sha256"),
                 role + " cross-report module hash")
        artifact, actual_size = _project_artifact(
            built.get("path"), built.get("sha256"), root)
        _require(actual_size == built.get("bytes"), role + " build module size")
        if audited.get("bytes") is not None:
            _require(actual_size == audited.get("bytes"), role + " audit module size")
        _require(Path(audited.get("path", "")).resolve(strict=True) == artifact,
                 role + " audit artifact identity")
        _require(audited.get("vermagic", "").split()[0] == kernel,
                 role + " module vermagic")
        if built.get("depends") is not None:
            _require(sorted(built["depends"]) == sorted(audited.get("depends", [])),
                     role + " module dependencies")
        version = built.get("version") or audited.get("version") or ""
        normalized_modules[role] = {
            "module_name": expected_name,
            "version": version,
            "license": built.get("license") or audited.get("license") or "",
            "bytes": actual_size,
            "sha256": built["sha256"],
            "depends": sorted(audited.get("depends", [])),
            "vermagic": audited["vermagic"],
        }

    symbols = audit.get("symbol_closure", {})
    front_imports = symbols.get("frontend_imports", {})
    provider_imports = symbols.get("provider_imports", {})
    uvm_imports = symbols.get("uvm_imports", {})
    standard_closure = symbols.get("standard_uvm_interface_closure", {})
    for name, check in (("frontend", front_imports),
                        ("R580 provider", provider_imports.get("legacy", {})),
                        ("open provider", provider_imports.get("open", {})),
                        ("UVM", uvm_imports)):
        _require(check.get("crc_mismatches") == [] and
                 check.get("ambiguous_matches") == [], name + " symbol closure")
    _require(standard_closure.get("crc_mismatches") == [] and
             standard_closure.get("missing_exports") == [] and
             standard_closure.get("unexpected_exports") == [],
             "standard UVM export closure")

    depmod = reports["depmod"]
    _require(depmod.get("status") == "passed" and
             depmod.get("audit_report_sha256") == report_hashes["bundle"],
             "depmod report-to-audit binding")
    _require(depmod.get("loaded_or_installed") is False and
             depmod.get("runtime_or_hardware_validated") is False,
             "depmod activation boundary")
    for role in MODULE_ROLES:
        _require(depmod.get("modules", {}).get(role, {}).get("sha256") ==
                 normalized_modules[role]["sha256"], role + " depmod artifact hash")
    resolution = depmod.get("resolution", {})
    expected_nvidia = ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"]
    expected_uvm = expected_nvidia + ["nvidia_uvm.ko"]
    with_pre_softdep_nvidia = ["ecdsa_generic.ko.zst"] + expected_nvidia
    with_pre_softdep_uvm = ["ecdsa_generic.ko.zst"] + expected_uvm
    for target, hard_order, optional_order in (
        ("nvidia", expected_nvidia, with_pre_softdep_nvidia),
        ("nvidia_uvm", expected_uvm, with_pre_softdep_uvm),
    ):
        record = resolution.get(target, {})
        _require(record.get("ordered_modules") in (hard_order, optional_order),
                 "kmod dependency order")
        _require(record.get("builtin_modules") in ([], ["ecdh_generic"]),
                 "kmod builtin softdep output")

    softdep_resolution = depmod.get("soft_dependency_resolution", {})
    owners = softdep_resolution.get("owners", {})
    _require(owners == {
        "hybrid580_open": {"pre": ["ecdh_generic", "ecdsa_generic"], "post": []}
    }, "module softdep declaration")
    resolved_targets = softdep_resolution.get("resolved_targets", {})
    builtin_target = resolved_targets.get("ecdh_generic", {})
    _require(builtin_target.get("kind") == "kernel-builtin" and
             builtin_target.get("resolved") is True and
             builtin_target.get("relative_path") == "kernel/crypto/ecdh_generic.ko",
             "kernel builtin softdep resolution")
    module_target = resolved_targets.get("ecdsa_generic", {})
    support_module = softdep_resolution.get("support_modules", {}).get(
        "ecdsa_generic", {})
    _require(module_target.get("kind") == "loadable-module" and
             module_target.get("relative_path") ==
             "kernel/crypto/ecdsa_generic.ko.zst" and
             module_target.get("ordered_modules") == ["ecdsa_generic.ko.zst"] and
             re.fullmatch(r"[0-9a-f]{64}", module_target.get("sha256", "")) and
             module_target.get("sha256") == support_module.get("sha256"),
             "loadable softdep resolution")

    return {
        "schema": "hybrid-r580-r595-split-provider-build-sanitized-v4",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "four-module-static-build-and-dependency-closure",
        "kernel_release": kernel,
        "report_sha256": report_hashes,
        "modules": normalized_modules,
        "abi": {
            "stock_r595_uvm_public_apis_matched": 79,
            "hybrid_uvm_direct_public_imports_matched": 78,
            "control_fd_replacement": {
                "replaces": "nvUvmInterfaceDupAddressSpace",
                "dispatch": "nvUvmInterfaceDupAddressSpaceWithControlFd",
                "crc_matches": True,
            },
            "provider_import_crcs_verified": True,
            "unresolved_imports": 0,
            "ambiguous_imports": 0,
        },
        "symbol_closure": {
            "frontend_imports": front_imports["import_count"],
            "legacy_provider_imports": provider_imports["legacy"]["import_count"],
            "open_provider_imports": provider_imports["open"]["import_count"],
            "uvm_imports": uvm_imports["import_count"],
            "uvm_imports_from_frontend": uvm_imports["matched_by_provider"]["frontend"],
            "uvm_imports_from_kernel": uvm_imports["matched_by_provider"]["kernel"],
        },
        "dependency_resolution": {
            "nvidia": expected_nvidia,
            "nvidia_uvm": expected_uvm,
            "softdep_builtin": ["ecdh_generic"],
            "softdep_module": ["ecdsa_generic.ko.zst"],
        },
        "build_warning_inventory": warning_inventory,
        "module_loaded": False,
        "module_installed": False,
        "gpu_accessed": False,
        "cuda_execution_validated": False,
        "runtime_or_hardware_validated": False,
        "limitations": [
            "This receipt verifies compile, symbol CRC, static bundle, and isolated kmod dependency closure only.",
            "No module was installed or loaded; no RM, GPU, CUDA, UVM runtime, P2P, or performance test ran.",
            "The R580 proprietary module is identified by hash; this receipt does not grant redistribution rights.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("frontend_report", type=Path)
    parser.add_argument("open_report", type=Path)
    parser.add_argument("legacy_report", type=Path)
    parser.add_argument("uvm_report", type=Path)
    parser.add_argument("bundle_report", type=Path)
    parser.add_argument("depmod_report", type=Path)
    parser.add_argument("sanitized_output", type=Path)
    args = parser.parse_args()

    paths = dict(zip(REPORT_ROLES, (
        args.frontend_report, args.open_report, args.legacy_report,
        args.uvm_report, args.bundle_report, args.depmod_report,
    )))
    try:
        root = ROOT.resolve(strict=True)
        loaded = {role: _read_regular_json(path, root) for role, path in paths.items()}
        reports = {role: value[0] for role, value in loaded.items()}
        hashes = {role: value[1] for role, value in loaded.items()}
        summary = build_summary(reports, hashes, root=root)
        from tools.probe_r615_gv100_dispatch import write_private_evidence_report
        output = args.sanitized_output
        if not output.is_absolute():
            output = root / output
        write_private_evidence_report(output, summary, repository_root=root)
        print(json.dumps({
            "path": output.relative_to(root).as_posix(),
            "qualification": summary["qualification"],
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "modules": {key: value["sha256"]
                        for key, value in summary["modules"].items()},
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("split-provider build receipt rejected: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
