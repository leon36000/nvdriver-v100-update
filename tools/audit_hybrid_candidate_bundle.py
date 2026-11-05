#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit static module identity, dependencies, and symbol CRC closure."""

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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_uvm_symbol_closure import (  # noqa: E402
    dump_modversions,
    parse_modversions,
    parse_symvers,
)


EXPECTED_MODULES = {
    "frontend": {"name": "nvidia", "depends": {"hybrid580_legacy", "hybrid580_open"}},
    "open": {"name": "hybrid580_open", "depends": set()},
    "legacy": {"name": "hybrid580_legacy", "depends": set()},
    "uvm": {"name": "nvidia_uvm", "depends": {"nvidia"}},
}
IMPLEMENTATION_FILES = (
    "tools/audit_hybrid_candidate_bundle.py",
    "tools/audit_r595_uvm_symbol_closure.py",
    "tools/build_hybrid_frontend.py",
    "tools/probe_r595_gv100_complete_hal.py",
    "tools/probe_volta_uvm_port.py",
)
REPLACED_UVM_APIS = {
    # The control-fd-aware frontend entrypoint replaces the stock UVM call.
    # The frontend keeps exporting the old API for compatibility with other
    # consumers, so it must not be mistaken for a missing UVM import.
    "nvUvmInterfaceDupAddressSpace": "nvUvmInterfaceDupAddressSpaceWithControlFd",
}
REQUIRED_UVM_ISOLATION_PARAMETER = "uvm_hybrid_isolated_gpu_execution"
R595_HYBRID_UVM_SCHEMA = "nvidia-r595-hybrid-uvm-target-build-v1"


def audit_import_closure(imports, providers):
    """Require every import CRC to match exactly one supplied export."""
    matched_by_provider = {}
    crc_mismatches = []
    ambiguous_matches = []
    for symbol, imported_crc in sorted(imports.items()):
        candidates = [
            (provider, symvers[symbol])
            for provider, symvers in providers.items()
            if symbol in symvers
        ]
        matches = [
            provider for provider, entry in candidates
            if str(imported_crc).lower() == entry["crc"].lower()
        ]
        if not matches:
            crc_mismatches.append({
                "symbol": symbol,
                "import_crc": str(imported_crc).lower(),
                "candidate_exports": [
                    {"provider": provider, "crc": entry["crc"],
                     "module": entry["module"]}
                    for provider, entry in candidates
                ],
            })
        elif len(matches) > 1:
            ambiguous_matches.append({
                "symbol": symbol,
                "providers": sorted(matches),
            })
        else:
            provider = matches[0]
            matched_by_provider[provider] = matched_by_provider.get(provider, 0) + 1
    return {
        "import_count": len(imports),
        "matched_by_provider": dict(sorted(matched_by_provider.items())),
        "crc_mismatches": crc_mismatches,
        "ambiguous_matches": ambiguous_matches,
    }


def audit_provider_import_closures(open_imports, legacy_imports, kernel_symvers):
    """Require both private R580 providers to resolve all imports to Linux."""
    kernel = {"kernel": kernel_symvers}
    return {
        "open": audit_import_closure(open_imports, kernel),
        "legacy": audit_import_closure(legacy_imports, kernel),
    }


def symvers_owner_matches(entry, module_name):
    """Match Module.symvers owners written as names or build-output paths."""
    owner = Path(str(entry.get("module", ""))).name
    if owner.endswith(".ko"):
        owner = owner[:-3]
    return owner == module_name


def audit_export_closure(exports, symvers, module_name):
    """Compare a module's ELF exports with its owning Module.symvers rows."""
    expected = {
        symbol: entry["crc"] for symbol, entry in symvers.items()
        if symvers_owner_matches(entry, module_name)
    }
    actual = {symbol: crc.lower() for symbol, crc in exports.items()}
    common = set(actual) & set(expected)
    return {
        "actual_export_count": len(actual),
        "expected_export_count": len(expected),
        "missing_exports": sorted(set(expected) - set(actual)),
        "unexpected_exports": sorted(set(actual) - set(expected)),
        "crc_mismatches": sorted(
            symbol for symbol in common
            if actual[symbol] != expected[symbol].lower()),
    }


def audit_standard_uvm_api(imports, exports, frontend_only_extensions):
    """Match stock UVM imports while accounting for declared hybrid exports."""
    normalized_imports = {name: crc.lower() for name, crc in imports.items()}
    normalized_exports = {name: crc.lower() for name, crc in exports.items()}
    extensions = set(frontend_only_extensions)
    for old_name, replacement_name in REPLACED_UVM_APIS.items():
        if replacement_name in normalized_imports and old_name in normalized_exports:
            normalized_exports.pop(old_name)
    common = set(normalized_imports) & set(normalized_exports)
    return {
        "missing_exports": sorted(set(normalized_imports) - set(normalized_exports)),
        "unexpected_exports": sorted(
            set(normalized_exports) - set(normalized_imports) - extensions),
        "missing_frontend_extensions": sorted(extensions - set(normalized_exports)),
        "frontend_only_extensions": sorted(
            (set(normalized_exports) - set(normalized_imports)) & extensions),
        "crc_mismatches": sorted(
            name for name in common
            if normalized_imports[name] != normalized_exports[name]),
    }


def validate_module_topology(modules, kernel_release):
    """Check standard module identities, dependency edges, and vermagic."""
    issues = []
    for role, expected in EXPECTED_MODULES.items():
        metadata = modules.get(role, {})
        if metadata.get("name") != expected["name"]:
            issues.append({
                "check": "module-name", "role": role,
                "expected": expected["name"], "actual": metadata.get("name"),
            })
        expected_dependencies = expected["depends"]
        if role == "open" and kernel_release == "6.8.0-147-generic":
            # This kernel's crypto/ecc exports are emitted as module dependency
            # ``ecc``; the exact target Module.symvers still must close them.
            expected_dependencies = {"ecc"}
        actual_dependencies = set(metadata.get("depends", []))
        if actual_dependencies != expected_dependencies:
            issues.append({
                "check": "module-dependencies", "role": role,
                "expected": sorted(expected_dependencies),
                "actual": sorted(actual_dependencies),
            })
        vermagic = metadata.get("vermagic", "")
        if vermagic.split(maxsplit=1)[:1] != [kernel_release]:
            issues.append({
                "check": "module-kernel-release", "role": role,
                "expected": kernel_release, "actual": vermagic,
            })
    return issues


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def implementation_sha256():
    """Hash the auditor and its direct build/ELF inspection dependencies."""
    return {relative: sha256_file(ROOT / relative)
            for relative in IMPLEMENTATION_FILES}


def _load_json(path, label):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object: {path}")
    return value


def _module_artifact(report, key, label):
    record = report.get(key)
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise ValueError(f"{label} report does not identify a module path")
    expected = record.get("sha256")
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
        raise ValueError(f"{label} report does not contain a valid module SHA-256")
    path = Path(record["path"])
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} module must be a regular non-symlink file: {path}")
    actual = sha256_file(path)
    if actual != expected.lower():
        raise ValueError(f"{label} module SHA-256 mismatch: got {actual}, expected {expected}")
    return path.resolve(strict=True), actual


def _provider_symvers_reference(report, role, module_path, frontend_report):
    """Return the provider Module.symvers path and its evidence-backed hash."""
    if role not in {"open", "legacy"}:
        raise ValueError(f"unsupported provider role: {role}")
    path = Path(module_path).parent / "Module.symvers"
    expected = report.get("symvers_sha256")
    if role == "legacy":
        compatibility = report.get("compatibility_with_v2", {})
        compatibility_path = compatibility.get("symvers")
        compatibility_hash = compatibility.get("symvers_sha256")
        if compatibility_path is not None:
            if Path(compatibility_path).resolve() != path.resolve():
                raise ValueError("legacy provider report pins a different Module.symvers path")
            if not isinstance(compatibility_hash, str):
                raise ValueError("legacy provider report does not pin its Module.symvers hash")
            if expected is not None and expected != compatibility_hash:
                raise ValueError("legacy provider report has conflicting Module.symvers hashes")
            expected = compatibility_hash
    if expected is None:
        if role == "legacy":
            # The R580 target builder emits a fresh sibling Module.symvers but
            # does not yet include its digest in its receipt. Accept it only
            # when its complete owner/CRC/export ABI matches exactly one
            # hash-pinned R580 provider input consumed by the frontend.
            equivalent = _frontend_provider_symvers_equivalent(
                frontend_report, path, "hybrid580_legacy")
            return Path(equivalent["path"]), equivalent["sha256"]
        if (role == "open"
                and report.get("schema")
                    != "nvidia-hybrid.r595112-open-provider-source-core-build.v1"
                and report.get("inputs_unchanged") is not True):
            raise ValueError("Open provider report does not prove its build inputs unchanged")
        expected = _report_symvers_hash(frontend_report, path)
    return path, expected


def _pinned_symvers(path, expected, label):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} Module.symvers must be a regular non-symlink file: {path}")
    actual = sha256_file(path)
    if not isinstance(expected, str) or actual != expected.lower():
        raise ValueError(
            f"{label} Module.symvers SHA-256 mismatch: got {actual}, expected {expected}")
    return path.resolve(strict=True), actual


def _report_symvers_hash(report, path):
    for field in ("inputs_sha256", "generated_outputs_sha256"):
        entries = report.get(field, {})
        for input_path, input_hash in entries.items():
            if Path(input_path).resolve() == Path(path).resolve():
                return input_hash
    raise ValueError(f"frontend build report does not pin Module.symvers: {path}")


def _require_frontend_generated_symvers(frontend_report, expected_sha256):
    """Require a consumer build's symvers bytes to equal the frontend output."""
    outputs = frontend_report.get("generated_outputs_sha256", {})
    matches = [
        (path, digest) for path, digest in outputs.items()
        if Path(path).name == "Module.symvers"
    ]
    if len(matches) != 1:
        raise ValueError(
            "frontend build report must identify exactly one generated Module.symvers")
    path, digest = matches[0]
    _, actual = _pinned_symvers(path, digest, "frontend generated")
    if actual != str(expected_sha256).lower():
        raise ValueError(
            "frontend generated Module.symvers digest differs from consumer build input")
    return path, actual


def _symvers_semantic_rows(path):
    """Compare Module.symvers ABI rows without treating build roots as ABI."""
    rows = {}
    for line_number, line in enumerate(Path(path).read_text().splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 4:
            raise ValueError(f"malformed Module.symvers row at {path}:{line_number}")
        crc, symbol, module_path, *export_metadata = fields
        owner = Path(module_path).name
        if owner.endswith(".ko"):
            owner = owner[:-3]
        normalized = (crc.lower(), owner, tuple(export_metadata))
        if symbol in rows and rows[symbol] != normalized:
            raise ValueError(f"conflicting Module.symvers entry for {symbol} at {path}")
        rows[symbol] = normalized
    if not rows:
        raise ValueError(f"Module.symvers is empty: {path}")
    return rows


def _frontend_provider_symvers_equivalent(frontend_report, provider_symvers,
                                          expected_owner):
    """Find the exact symvers file consumed by frontend and prove ABI identity."""
    inputs = frontend_report.get("inputs_sha256", {})
    if not isinstance(inputs, dict):
        raise ValueError("frontend report does not contain pinned Module.symvers inputs")
    provider_rows = _symvers_semantic_rows(provider_symvers)
    if any(row[1] != expected_owner for row in provider_rows.values()):
        raise ValueError(f"provider Module.symvers contains a non-{expected_owner} export")

    matches = []
    for raw_path, expected_hash in inputs.items():
        candidate = Path(raw_path)
        if candidate.name != "Module.symvers":
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"frontend Module.symvers input is missing or unsafe: {candidate}")
        if not isinstance(expected_hash, str) or sha256_file(candidate) != expected_hash.lower():
            raise ValueError(f"frontend Module.symvers input hash changed: {candidate}")
        if _symvers_semantic_rows(candidate) == provider_rows:
            canonical = "\n".join(
                " ".join([crc, symbol, owner, *metadata])
                for symbol, (crc, owner, metadata) in sorted(provider_rows.items())
            ) + "\n"
            matches.append({
                "path": str(candidate.resolve(strict=True)),
                "sha256": expected_hash.lower(),
                "semantic_abi_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                "export_count": len(provider_rows),
            })
    if len(matches) != 1:
        raise ValueError(
            "frontend report must contain exactly one pinned Module.symvers with "
            f"the same {expected_owner} export ABI; matches={len(matches)}")
    return matches[0]


def _modinfo(module_path, executable=None):
    executable = executable or "modinfo"
    result = {}
    for field in ("name", "version", "vermagic", "depends", "license", "softdep"):
        command = subprocess.run(
            [executable, "-F", field, str(module_path)],
            capture_output=True, text=True, check=False,
        )
        if command.returncode:
            raise ValueError(
                f"modinfo could not read {field} from {module_path}: "
                f"{command.stderr.strip()}")
        result[field] = command.stdout.strip()
    result["depends"] = sorted(item for item in result["depends"].split(",") if item)
    return result


def parse_modinfo_parameters(text):
    """Parse `modinfo -p` lines without treating descriptions as parameter names."""
    parameters = {}
    for line in text.splitlines():
        name, separator, description = line.partition(":")
        name = name.strip()
        if not separator or not name:
            continue
        if name in parameters:
            raise ValueError(f"duplicate module parameter in modinfo output: {name}")
        type_match = re.search(r"\((bool|byte|charp|int|long|short|uint|ulong|ushort)\)\s*$",
                               description.strip())
        parameters[name] = {
            "description": description.strip(),
            "type": type_match.group(1) if type_match else None,
        }
    return parameters


def uvm_hybrid_isolation_parameter_issue(parameters):
    """Return a fail-closed issue unless the isolated UVM bool exists."""
    parameter = parameters.get(REQUIRED_UVM_ISOLATION_PARAMETER)
    if parameter is not None and parameter.get("type") == "bool":
        return None
    return {
        "check": "uvm-hybrid-isolation-parameter",
        "required_parameter": REQUIRED_UVM_ISOLATION_PARAMETER,
        "observed": parameter,
    }


def _modinfo_parameters(module_path, executable=None):
    executable = executable or "modinfo"
    command = subprocess.run(
        [executable, "-p", str(module_path)],
        capture_output=True, text=True, check=False,
    )
    if command.returncode:
        raise ValueError(
            f"modinfo could not read parameters from {module_path}: "
            f"{command.stderr.strip()}")
    return parse_modinfo_parameters(command.stdout)


def _modprobe_exports(module_path, executable=None):
    executable = executable or "modprobe"
    command = subprocess.run(
        [executable, "--show-exports", str(module_path)],
        capture_output=True, text=True, check=False,
    )
    if command.returncode:
        raise ValueError(
            f"modprobe --show-exports failed for {module_path}: "
            f"{command.stderr.strip()}")
    return parse_modversions(command.stdout)


def _require_not_loaded(report, fields, label):
    present_values = [report[field] for field in fields if field in report]
    if any(value is not False for value in present_values):
        raise ValueError(f"{label} report does not prove unloaded state; status fields conflict")
    if len(present_values) == len(fields):
        return
    qualification = report.get("qualification")
    combined = report.get("loaded_or_installed")
    if combined is None and isinstance(qualification, dict):
        combined = qualification.get("module_loaded_or_installed")
    if combined is False:
        return
    for field in fields:
        if report.get(field) is not False:
            raise ValueError(f"{label} report does not prove {field}=false")


def _normalize_uvm_report(report):
    """Normalize supported UVM build receipts to the bundle audit shape."""
    if isinstance(report.get("candidate_module"), dict):
        return report
    if report.get("schema") == R595_HYBRID_UVM_SCHEMA:
        build = report.get("build", {})
        module = report.get("module", {})
        identity = module.get("identity", {})
        inputs = report.get("inputs_sha256", {})
        binding = report.get("frontend_public_uvm_binding", {})
        direct = binding.get("direct_binding", {})
        checks = direct.get("checks", {})
        dispatch = binding.get("address_space_dispatch", {})
        symvers_hash = inputs.get("frontend_module_symvers")
        symvers_args = [
            argument.split("=", 1)[1]
            for argument in build.get("argv", [])
            if isinstance(argument, str)
            and argument.startswith("KBUILD_EXTRA_SYMBOLS=")
        ]
        valid_direct_checks = (
            type(direct.get("api_count")) is int
            and direct.get("api_count") == 78
            and len(checks) == 78
            and all(
                isinstance(entry, dict)
                and entry.get("matches") is True
                and isinstance(entry.get("consumer_import_crc"), str)
                and entry["consumer_import_crc"].lower()
                    == str(entry.get("frontend_export_crc", "")).lower()
                for entry in checks.values()
            )
        )
        valid_dispatch = (
            dispatch.get("matches") is True
            and dispatch.get("symbol") == "nvUvmInterfaceDupAddressSpaceWithControlFd"
            and dispatch.get("replaces_public_call") == "nvUvmInterfaceDupAddressSpace"
            and dispatch.get("frontend_owner") == "nvidia"
            and dispatch.get("frontend_export") == "EXPORT_SYMBOL"
            and isinstance(dispatch.get("consumer_crc"), str)
            and dispatch["consumer_crc"].lower()
                == str(dispatch.get("frontend_crc", "")).lower()
        )
        if (report.get("status") != "passed"
                or report.get("qualification")
                    != "compiled-hybrid-r595-uvm-target-kernel-module-and-public-abi"
                or report.get("module_loaded") is not False
                or report.get("module_installed") is not False
                or report.get("gpu_accessed") is not False
                or report.get("cuda_execution_validated") is not False
                or report.get("source_copy_matches_input") is not True
                or report.get("kernel_release") is None
                or build.get("exit_code") != 0
                or identity.get("name") != "nvidia_uvm"
                or identity.get("depends") != "nvidia"
                or not isinstance(module.get("path"), str)
                or not isinstance(module.get("sha256"), str)
                or not isinstance(symvers_hash, str)
                or re.fullmatch(r"[0-9a-fA-F]{64}", symvers_hash) is None
                or len(symvers_args) != 1
                or binding.get("verified") is not True
                or binding.get("declared_public_api_count") != 79
                or binding.get("direct_public_import_count") != 78
                or binding.get("missing_public_imports")
                    != ["nvUvmInterfaceDupAddressSpace"]
                or binding.get("unexpected_public_imports") != []
                or not valid_direct_checks
                or not valid_dispatch):
            raise ValueError(
                "R595 hybrid UVM report does not prove the pinned compile-only "
                "frontend ABI binding")

        normalized = dict(report)
        normalized["candidate_module"] = {
            "path": module["path"], "sha256": module["sha256"],
            "name": "nvidia_uvm", "linked_this_run": True,
        }
        normalized_build = dict(build)
        normalized_build["build_command_succeeded"] = True
        normalized_build["frontend_module_symvers"] = {
            "path": symvers_args[0], "expected_sha256": symvers_hash,
            "sha256_before": symvers_hash, "sha256_after": symvers_hash,
            "unchanged": True,
        }
        normalized["build"] = normalized_build
        return normalized
    if report.get("schema") != "r580-uvm-isolated-gpu-execution-build-v5":
        raise ValueError("unsupported UVM build report schema")

    build = report.get("build", {})
    inputs = report.get("inputs", {})
    qualification = report.get("qualification", {})
    binding = build.get("frontend_consumer_binding", {})
    frontend_symvers = inputs.get("frontend_module_symvers", {})
    expected_symvers_hash = inputs.get("expected_frontend_module_symvers_sha256")
    module_identity = build.get("module_identity", {})
    module = build.get("modules", {}).get("nvidia-uvm.ko", {})
    uvm_import_count = binding.get("uvm_interface_import_count")
    matching_import_count = binding.get("matching_frontend_crc_count")
    counts_valid = (type(uvm_import_count) is int and uvm_import_count > 0
                    and type(matching_import_count) is int
                    and matching_import_count == uvm_import_count)

    if (build.get("exit_code") != 0
            or build.get("kernel_release") is None
            or qualification.get("level") != "compiled-frontend-bound-uvm"
            or qualification.get("module_loaded_or_installed") is not False
            or qualification.get("runtime_or_hardware_validated") is not False
            or module_identity.get("module_name_matches") is not True
            or module_identity.get("actual_module_name") != "nvidia_uvm"
            or module_identity.get("expected_module_name") != "nvidia_uvm"
            or not isinstance(module.get("path"), str)
            or not isinstance(module.get("sha256"), str)):
        raise ValueError("R580 UVM report does not prove a compile-only nvidia_uvm build")
    if (inputs.get("frontend_module_name") != "nvidia"
            or not isinstance(frontend_symvers.get("path"), str)
            or not isinstance(frontend_symvers.get("sha256"), str)
            or frontend_symvers.get("sha256") != expected_symvers_hash
            or binding.get("passed") is not True
            or binding.get("frontend_module_name") != "nvidia"
            or binding.get("frontend_is_only_provider_dependency") is not True
            or binding.get("module_dependencies") != ["nvidia"]
            or binding.get("symvers_unchanged_after_build") is not True
            or build.get("frontend_symvers_unchanged_after_build") is not True
            or not counts_valid
            or binding.get("mismatched_symbols") != {}):
        raise ValueError("R580 UVM frontend UVM binding is incomplete or mismatched")

    normalized = dict(report)
    normalized["candidate_module"] = {
        "path": module["path"],
        "sha256": module["sha256"],
        "name": "nvidia_uvm",
        "linked_this_run": True,
    }
    normalized_build = dict(build)
    normalized_build["build_command_succeeded"] = True
    normalized_build["frontend_module_symvers"] = {
        "path": frontend_symvers["path"],
        "expected_sha256": expected_symvers_hash,
        "sha256_before": frontend_symvers["sha256"],
        "sha256_after": frontend_symvers["sha256"],
        "unchanged": True,
    }
    normalized["build"] = normalized_build
    return normalized


def _normalize_open_report(report):
    """Normalize the R595.112 source-core build receipt for bundle auditing."""
    if report.get("schema") != "nvidia-hybrid.r595112-open-provider-source-core-build.v1":
        return report

    qualification = report.get("qualification", {})
    build = report.get("build", {})
    module_path = build.get("module_path")
    module_sha256 = build.get("module_sha256")
    if (report.get("status") != "BUILD_PASS"
            or qualification.get("compiled") is not True
            or qualification.get("installed_or_loaded") is not False
            or qualification.get("hardware_tested") is not False
            or qualification.get("cuda_runtime_validated") is not False
            or build.get("commands_exit_codes") != [0, 0]
            or build.get("error_lines") != 0
            or build.get("kernel_release") is None
            or not isinstance(module_path, str)
            or not isinstance(module_sha256, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", module_sha256) is None
            or build.get("module_selection") != ["nvidia"]):
        raise ValueError(
            "R595.112 source-core Open report does not prove a compile-only "
            "hybrid580_open build")

    normalized = dict(report)
    normalized["kernel_release"] = build["kernel_release"]
    normalized["module_loaded"] = False
    normalized["module_installed"] = False
    normalized["module"] = {
        "name": "hybrid580_open",
        "path": str(ROOT / module_path) if not Path(module_path).is_absolute()
            else module_path,
        "sha256": module_sha256.lower(),
    }
    return normalized


def _kernel_symvers_input(frontend_report, frontend_symvers, open_symvers, legacy_symvers):
    inputs = frontend_report.get("inputs_sha256", {})
    paths = {Path(item).resolve() for item in inputs}
    for path in (open_symvers, legacy_symvers):
        if Path(path).resolve() not in paths:
            raise ValueError(f"frontend report does not include backend symvers input: {path}")
    other = [
        (Path(path), digest) for path, digest in inputs.items()
        if Path(path).name == "Module.symvers"
        and Path(path).resolve() not in {
            Path(frontend_symvers).resolve(),
            Path(open_symvers).resolve(),
            Path(legacy_symvers).resolve(),
        }
    ]
    if len(other) != 1:
        raise ValueError(
            "frontend report must identify exactly one kernel Module.symvers input")
    return other[0]


def _report_name(report, role):
    if role == "frontend":
        return report.get("module_name")
    if role == "open":
        names = report.get("metadata", {}).get("name", [])
        return report.get("module", {}).get("name") or (names[0] if names else None)
    if role == "legacy":
        names = report.get("module_metadata", {}).get("name", [])
        if isinstance(names, list):
            names = names[0] if names else None
        if isinstance(names, str):
            return names or None
        return report.get("module", {}).get("metadata", {}).get("name")
    return None


def _legacy_report_vermagic(report):
    """Read the legacy module vermagic from supported report generations."""
    value = report.get("module_metadata", {}).get("vermagic")
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str) or not value.strip():
        value = report.get("module", {}).get("metadata", {}).get("vermagic")
    return value.strip() if isinstance(value, str) else ""


def audit_bundle(frontend_report_path, open_report_path, legacy_report_path,
                 uvm_report_path, modinfo=None, modprobe=None):
    paths = {
        "frontend": Path(frontend_report_path),
        "open": Path(open_report_path),
        "legacy": Path(legacy_report_path),
        "uvm": Path(uvm_report_path),
    }
    reports = {role: _load_json(path, f"{role} build report")
               for role, path in paths.items()}
    reports["open"] = _normalize_open_report(reports["open"])
    reports["uvm"] = _normalize_uvm_report(reports["uvm"])
    _require_not_loaded(reports["frontend"], ("loaded_or_installed",), "frontend")
    _require_not_loaded(reports["open"], ("module_loaded", "module_installed"), "Open backend")
    _require_not_loaded(reports["legacy"], ("loaded_or_installed",), "legacy backend")
    _require_not_loaded(reports["uvm"], ("module_loaded", "module_installed"), "UVM")

    module_records = {}
    artifact_keys = {
        "frontend": "module", "open": "module",
        "legacy": "module", "uvm": "candidate_module",
    }
    module_paths = {}
    for role, key in artifact_keys.items():
        module_path, digest = _module_artifact(reports[role], key, role)
        module_paths[role] = module_path
        metadata = _modinfo(module_path, modinfo)
        metadata.update({"path": str(module_path), "sha256": digest})
        module_records[role] = metadata
        claimed_name = reports[role][key].get("name") or _report_name(reports[role], role)
        if claimed_name and claimed_name != metadata["name"]:
            raise ValueError(
                f"{role} module identity mismatch: report says {claimed_name}, "
                f"modinfo says {metadata['name']}")

    uvm_parameters = _modinfo_parameters(module_paths["uvm"], modinfo)
    module_records["uvm"]["parameters"] = uvm_parameters

    kernel_release = reports["frontend"].get("kernel_release")
    if not isinstance(kernel_release, str) or not kernel_release:
        raise ValueError("frontend report does not identify the target kernel release")
    issues = validate_module_topology(module_records, kernel_release)
    isolation_issue = uvm_hybrid_isolation_parameter_issue(uvm_parameters)
    if isolation_issue:
        issues.append(isolation_issue)
    open_report_kernel = reports["open"].get("kernel_release")
    if open_report_kernel is None:
        open_vermagic = reports["open"].get("metadata", {}).get("vermagic", [""])
        open_report_kernel = open_vermagic[0].split()[0] if open_vermagic else ""
    if open_report_kernel != kernel_release:
        issues.append({"check": "open-provider-report-kernel-release"})
    legacy_vermagic = _legacy_report_vermagic(reports["legacy"])
    if legacy_vermagic.split(maxsplit=1)[:1] != [kernel_release]:
        issues.append({"check": "legacy-provider-report-kernel-release"})
    if reports["uvm"].get("build", {}).get("build_command_succeeded") is not True:
        issues.append({"check": "uvm-build-command"})
    if reports["uvm"].get("candidate_module", {}).get("linked_this_run") is not True:
        issues.append({"check": "uvm-linked-this-run"})

    build_symvers = reports["uvm"].get("build", {}).get("frontend_module_symvers")
    if not isinstance(build_symvers, dict) or build_symvers.get("unchanged") is not True:
        raise ValueError("UVM build report lacks an unchanged frontend Module.symvers pin")
    frontend_symvers, frontend_hash = _pinned_symvers(
        build_symvers.get("path", ""), build_symvers.get("expected_sha256"),
        "hybrid frontend")
    if build_symvers.get("sha256_before") != frontend_hash \
            or build_symvers.get("sha256_after") != frontend_hash:
        raise ValueError("UVM build report frontend Module.symvers before/after hashes disagree")
    _require_frontend_generated_symvers(reports["frontend"], frontend_hash)

    open_symvers_path, open_expected_hash = _provider_symvers_reference(
        reports["open"], "open", module_paths["open"], reports["frontend"])
    open_symvers, open_hash = _pinned_symvers(
        open_symvers_path, open_expected_hash, "Open backend")
    open_frontend_input = _frontend_provider_symvers_equivalent(
        reports["frontend"], open_symvers, "hybrid580_open")
    legacy_symvers_path, legacy_expected = _provider_symvers_reference(
        reports["legacy"], "legacy", module_paths["legacy"], reports["frontend"])
    legacy_symvers, legacy_hash = _pinned_symvers(
        legacy_symvers_path, legacy_expected, "R580 proprietary backend")
    kernel_symvers_path, kernel_expected = _kernel_symvers_input(
        reports["frontend"], frontend_symvers,
        Path(open_frontend_input["path"]), legacy_symvers)
    kernel_symvers, kernel_hash = _pinned_symvers(
        kernel_symvers_path, kernel_expected, "kernel")

    symvers = {
        "kernel": parse_symvers(kernel_symvers),
        "frontend": parse_symvers(frontend_symvers),
        "open": parse_symvers(open_symvers),
        "legacy": parse_symvers(legacy_symvers),
    }
    frontend_exports = _modprobe_exports(module_paths["frontend"], modprobe)
    open_exports = _modprobe_exports(module_paths["open"], modprobe)
    legacy_exports = _modprobe_exports(module_paths["legacy"], modprobe)
    export_closures = {
        "frontend": audit_export_closure(
            frontend_exports, symvers["frontend"], "nvidia"),
        "open": audit_export_closure(
            open_exports, symvers["open"], "hybrid580_open"),
        "legacy": audit_export_closure(
            legacy_exports, symvers["legacy"], "hybrid580_legacy"),
    }
    for role, result in export_closures.items():
        if result["missing_exports"] or result["unexpected_exports"] or result["crc_mismatches"]:
            issues.append({"check": f"{role}-export-table-closure"})

    open_imports = dump_modversions(
        module_paths["open"], modprobe=modprobe, include_extended=True)
    legacy_imports = dump_modversions(
        module_paths["legacy"], modprobe=modprobe, include_extended=True)
    frontend_imports = dump_modversions(
        module_paths["frontend"], modprobe=modprobe, include_extended=True)
    uvm_imports = dump_modversions(
        module_paths["uvm"], modprobe=modprobe, include_extended=True)
    provider_import_closures = audit_provider_import_closures(
        open_imports, legacy_imports, symvers["kernel"])
    for role, closure in provider_import_closures.items():
        if closure["crc_mismatches"] or closure["ambiguous_matches"]:
            issues.append({"check": f"{role}-provider-kernel-import-closure"})
    frontend_closure = audit_import_closure(
        frontend_imports,
        {key: symvers[key] for key in ("kernel", "open", "legacy")},
    )
    uvm_closure = audit_import_closure(
        uvm_imports,
        {key: symvers[key] for key in ("kernel", "frontend")},
    )
    if frontend_closure["crc_mismatches"] or frontend_closure["ambiguous_matches"]:
        issues.append({"check": "frontend-import-crc-closure"})
    if uvm_closure["crc_mismatches"] or uvm_closure["ambiguous_matches"]:
        issues.append({"check": "uvm-import-crc-closure"})

    private_actual = {
        name: crc.lower() for name, crc in frontend_imports.items()
        if name.startswith(("hybrid580_open_", "hybrid580_legacy_"))
    }
    private_expected = reports["frontend"].get("backend_imports", {})
    private_expected = {
        name: value.get("crc", "").lower()
        for name, value in private_expected.items()
    }
    if private_actual != private_expected:
        issues.append({
            "check": "frontend-private-import-set",
            "expected_count": len(private_expected),
            "actual_count": len(private_actual),
        })

    uvm_api_imports = {
        name: crc.lower() for name, crc in uvm_imports.items()
        if name.startswith("nvUvmInterface")
    }
    uvm_api_exports = {
        name: entry["crc"].lower()
        for name, entry in symvers["frontend"].items()
        if name.startswith("nvUvmInterface")
        and symvers_owner_matches(entry, "nvidia")
    }
    hybrid_only_ownership = reports["frontend"].get(
        "hybrid_only_dispatch_ownership", {})
    hybrid_only_extensions = set(hybrid_only_ownership)
    if any(value.get("frontend_owner") != "nvidia"
           or value.get("private_provider_exports") != []
           for value in hybrid_only_ownership.values()):
        issues.append({"check": "hybrid-only-uvm-extension-ownership"})
    uvm_api_closure = audit_standard_uvm_api(
        uvm_api_imports, uvm_api_exports, hybrid_only_extensions)
    if any(uvm_api_closure[key] for key in (
            "missing_exports", "unexpected_exports", "missing_frontend_extensions",
            "crc_mismatches")):
        issues.append({
            "check": "standard-uvm-api-import-export-set",
            "import_count": len(uvm_api_imports),
            "export_count": len(uvm_api_exports),
            **uvm_api_closure,
        })

    symvers_records = {
        "kernel": {"path": str(kernel_symvers), "sha256": kernel_hash},
        "frontend": {"path": str(frontend_symvers), "sha256": frontend_hash},
        "open": {"path": str(open_symvers), "sha256": open_hash},
        "open_frontend_build_input": open_frontend_input,
        "legacy": {"path": str(legacy_symvers), "sha256": legacy_hash},
    }
    return {
        "schema": "hybrid-module-bundle-static-audit-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if not issues else "failed",
        "qualification": "static-module-bundle-closure" if not issues else "failed",
        "kernel_release": kernel_release,
        "modules": module_records,
        "symvers": symvers_records,
        "symbol_closure": {
            "module_exports": export_closures,
            "provider_imports": provider_import_closures,
            "frontend_imports": frontend_closure,
            "uvm_imports": uvm_closure,
            "standard_uvm_interface_import_count": len(uvm_api_imports),
            "standard_uvm_interface_export_count": len(uvm_api_exports),
            "standard_uvm_interface_closure": uvm_api_closure,
            "frontend_private_import_count": len(private_actual),
        },
        "reports": {
            role: {"path": str(path.resolve()), "sha256": sha256_file(path)}
            for role, path in paths.items()
        },
        "implementation_sha256": implementation_sha256(),
        "issues": issues,
        "module_loaded": False,
        "module_installed": False,
        "runtime_or_hardware_validated": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-report", type=Path, required=True)
    parser.add_argument("--open-report", type=Path, required=True)
    parser.add_argument("--legacy-report", type=Path, required=True)
    parser.add_argument("--uvm-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    report_path = args.report
    if report_path.is_symlink() or report_path.exists():
        parser.error("refusing to overwrite an existing or symlink audit report")
    try:
        report = audit_bundle(
            args.frontend_report, args.open_report, args.legacy_report,
            args.uvm_report,
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os.chmod(report_path, 0o600)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({
        "status": report["status"],
        "qualification": report["qualification"],
        "kernel_release": report["kernel_release"],
        "frontend_imports": report["symbol_closure"]["frontend_imports"]["import_count"],
        "uvm_imports": report["symbol_closure"]["uvm_imports"]["import_count"],
        "uvm_interface_imports": report["symbol_closure"]["standard_uvm_interface_import_count"],
        "issues": report["issues"],
        "report": str(report_path.resolve()),
        "report_sha256": sha256_file(report_path),
    }, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
