#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare an R580 UVM module's imports with a hybrid frontend and its RMs.

This is a static symbol/CRC closure audit. It does not load modules, call RM,
initialize GPUs, or establish that an exported wrapper is semantically correct.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

API_PREFIX = "nvUvmInterface"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_symvers(path: Path) -> dict[str, dict[str, str]]:
    symbols: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        fields = line.split()
        if len(fields) < 4:
            continue
        name = fields[1]
        item = {"crc": fields[0], "module": fields[2], "export": fields[3]}
        previous = symbols.get(name)
        if previous is not None and previous != item:
            raise ValueError(f"conflicting Module.symvers entry for {name} at line {line_number}")
        symbols[name] = item
    return symbols


def parse_module_versions(source: str) -> dict[str, str]:
    match = re.search(
        r"static\s+const\s+struct\s+modversion_info\s+____versions\[\].*?=\s*\{(.*?)^\s*\};",
        source, re.DOTALL | re.MULTILINE)
    if match is None:
        raise ValueError("modpost __versions array not found")
    versions: dict[str, str] = {}
    for crc, name in re.findall(r"\{\s*(0x[0-9a-fA-F]+)\s*,\s*\"([^\"]+)\"\s*\}", match.group(1)):
        previous = versions.get(name)
        if previous is not None and previous.lower() != crc.lower():
            raise ValueError(f"conflicting imported CRCs for {name}")
        versions[name] = crc.lower()
    return versions


def module_imports(module: Path) -> set[str]:
    result = subprocess.run(["nm", "-u", str(module)], capture_output=True,
                            text=True, check=True, timeout=20)
    return {line.split()[-1] for line in result.stdout.splitlines() if line.split()}


def audit_global_symbol_precedence(
        imports: dict[str, str], intended: dict[str, dict[str, str]],
        resident: dict[str, dict[str, str]]) -> dict:
    """Flag imports that can resolve to a competing resident export by name.

    Module.symvers records ABI CRCs, not a per-import provider binding. Linux's
    module loader resolves an exported name before checking that export's CRC;
    therefore matching CRCs can still select the wrong implementation, while
    a mismatching earlier provider can reject the import. This is a static
    risk classification: actual module-list order and symbol owners are not
    observable from these inputs.
    """
    intended_missing = sorted(set(imports) - set(intended))
    intended_crc_mismatches = [
        {"symbol": name, "consumer_crc": crc,
         "intended_crc": intended[name]["crc"].lower()}
        for name, crc in sorted(imports.items())
        if name in intended and intended[name]["crc"].lower() != crc.lower()
    ]
    overlaps = sorted(set(imports) & set(resident))
    matching_crc_overlaps = [
        name for name in overlaps
        if imports[name].lower() == resident[name]["crc"].lower()
    ]
    resident_crc_mismatches = [
        {"symbol": name, "consumer_crc": imports[name].lower(),
         "resident_crc": resident[name]["crc"].lower()}
        for name in overlaps
        if imports[name].lower() != resident[name]["crc"].lower()
    ]
    if intended_missing or intended_crc_mismatches:
        classification = "intended-provider-closure-gap"
    elif overlaps:
        classification = "order-sensitive-global-symbol-resolution"
    else:
        classification = "no-resident-export-overlap"
    return {
        "classification": classification,
        "import_count": len(imports),
        "intended_provider_missing": intended_missing,
        "intended_provider_crc_mismatches": intended_crc_mismatches,
        "resident_overlap_count": len(overlaps),
        "matching_crc_overlaps": matching_crc_overlaps,
        "resident_crc_mismatches": resident_crc_mismatches,
        "runtime_or_load_order_observed": False,
    }


def audit_coverage(uvm_versions: dict[str, str], actual_imports: set[str],
                   reference: dict[str, dict[str, str]],
                   frontend: dict[str, dict[str, str]],
                   open_backend: dict[str, dict[str, str]],
                   legacy_backend: dict[str, dict[str, str]]) -> dict:
    imported_apis = {name: crc for name, crc in uvm_versions.items()
                     if name.startswith(API_PREFIX)}
    actual_apis = {name for name in actual_imports if name.startswith(API_PREFIX)}
    if set(imported_apis) != actual_apis:
        raise ValueError("UVM module undefined-symbol set differs from its modpost version table")

    reference_missing = sorted(set(imported_apis) - set(reference))
    reference_crc_mismatches = sorted(
        name for name, crc in imported_apis.items()
        if name in reference and reference[name]["crc"].lower() != crc.lower())

    frontend_api_exports = {
        name: item for name, item in frontend.items()
        if name.startswith(API_PREFIX) and item["export"] in ("EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL")
    }
    missing_frontend_exports = sorted(set(imported_apis) - set(frontend_api_exports))
    frontend_crc_mismatches = sorted(
        name for name, item in frontend_api_exports.items()
        if name in imported_apis and item["crc"].lower() != imported_apis[name].lower())

    expected_open = {API_PREFIX + name[len(API_PREFIX):]: name for name in imported_apis}
    # Backend export namespaces are mechanically prefixed, preserving the API suffix.
    open_missing = sorted(private for private in
                         ("hybrid580_open_" + name for name in expected_open)
                         if private not in open_backend)
    legacy_missing = sorted(private for private in
                           ("hybrid580_legacy_" + name for name in expected_open)
                           if private not in legacy_backend)
    open_crc_mismatches = sorted(
        "hybrid580_open_" + name for name, crc in imported_apis.items()
        if "hybrid580_open_" + name in open_backend and
        open_backend["hybrid580_open_" + name]["crc"].lower() != crc.lower())
    legacy_crc_mismatches = sorted(
        "hybrid580_legacy_" + name for name, crc in imported_apis.items()
        if "hybrid580_legacy_" + name in legacy_backend and
        legacy_backend["hybrid580_legacy_" + name]["crc"].lower() != crc.lower())

    complete = not any((reference_missing, reference_crc_mismatches,
                        missing_frontend_exports, frontend_crc_mismatches,
                        open_missing, legacy_missing, open_crc_mismatches,
                        legacy_crc_mismatches))
    return {
        "qualification": "static-uvm-symbol-closure-only" if complete else
                         "static-uvm-symbol-coverage-gap",
        "uvm_interface_import_count": len(imported_apis),
        "frontend_standard_export_count": len(frontend_api_exports),
        "missing_frontend_standard_exports": missing_frontend_exports,
        "frontend_crc_mismatches": frontend_crc_mismatches,
        "missing_from_reference_provider": reference_missing,
        "reference_crc_mismatches": reference_crc_mismatches,
        "missing_open_private_exports": open_missing,
        "open_private_crc_mismatches": open_crc_mismatches,
        "missing_legacy_private_exports": legacy_missing,
        "legacy_private_crc_mismatches": legacy_crc_mismatches,
        "unresolved_after_frontend": missing_frontend_exports,
        "global_symbol_precedence": audit_global_symbol_precedence(
            imported_apis, frontend_api_exports, reference),
        "runtime_or_semantic_validation": False,
    }


def build_report(uvm_module: Path, uvm_mod_c: Path, reference_symvers: Path,
                 frontend_symvers: Path, open_symvers: Path,
                 legacy_symvers: Path) -> dict:
    paths = {
        "uvm_module": uvm_module.resolve(strict=True),
        "uvm_modpost_source": uvm_mod_c.resolve(strict=True),
        "reference_symvers": reference_symvers.resolve(strict=True),
        "frontend_symvers": frontend_symvers.resolve(strict=True),
        "open_backend_symvers": open_symvers.resolve(strict=True),
        "legacy_backend_symvers": legacy_symvers.resolve(strict=True),
    }
    versions = parse_module_versions(paths["uvm_modpost_source"].read_text())
    imports = module_imports(paths["uvm_module"])
    report = {
        "schema": "hybrid-uvm-symbol-coverage-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "inputs_sha256": {key: sha256(path) for key, path in paths.items()},
        "module_import_count": len(imports),
        **audit_coverage(versions, imports,
                         parse_symvers(paths["reference_symvers"]),
                         parse_symvers(paths["frontend_symvers"]),
                         parse_symvers(paths["open_backend_symvers"]),
                         parse_symvers(paths["legacy_backend_symvers"])),
        "loaded_or_installed": False,
        "real_rm_executed": False,
        "gpu_accessed": False,
        "same_linux_cuda_established": False,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uvm-module", required=True, type=Path)
    parser.add_argument("--uvm-mod-c", required=True, type=Path)
    parser.add_argument("--reference-symvers", required=True, type=Path)
    parser.add_argument("--frontend-symvers", required=True, type=Path)
    parser.add_argument("--open-symvers", required=True, type=Path)
    parser.add_argument("--legacy-symvers", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("report already exists")
    report = build_report(args.uvm_module, args.uvm_mod_c, args.reference_symvers,
                          args.frontend_symvers, args.open_symvers,
                          args.legacy_symvers)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in (
        "qualification", "uvm_interface_import_count", "frontend_standard_export_count",
        "unresolved_after_frontend", "missing_open_private_exports",
        "missing_legacy_private_exports", "global_symbol_precedence")}, sort_keys=True))
    return 0 if report["qualification"] == "static-uvm-symbol-closure-only" else 2


if __name__ == "__main__":
    raise SystemExit(main())
