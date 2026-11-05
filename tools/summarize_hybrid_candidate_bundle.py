#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate and sanitize a static four-module hybrid-bundle audit."""

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

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-f]{64}")
MODULES = {
    "frontend": ("nvidia", {"hybrid580_legacy", "hybrid580_open"}),
    "legacy": ("hybrid580_legacy", set()),
    "open": ("hybrid580_open", set()),
    "uvm": ("nvidia_uvm", {"nvidia"}),
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("invalid static hybrid-bundle evidence: " + message)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _implementation_hashes() -> dict[str, str]:
    result = {}
    for relative in ("tools/audit_hybrid_candidate_bundle.py",
                     "tools/summarize_hybrid_candidate_bundle.py"):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("receipt implementation is not a regular file")
        result[relative] = _sha256(path.read_bytes())
    return result


def _clean_closure(record: dict, label: str) -> None:
    _require(isinstance(record, dict), label + " record")
    for field in ("crc_mismatches", "ambiguous_matches", "missing_exports",
                  "unexpected_exports", "missing_frontend_extensions"):
        if field in record:
            _require(record[field] == [], label + " " + field)


def _matched_total(record: dict, label: str) -> int:
    matched = record.get("matched_by_provider")
    _require(isinstance(matched, dict), label + " provider map")
    for provider, count in matched.items():
        _require(isinstance(provider, str) and type(count) is int and count >= 0,
                 label + " provider count")
    return sum(matched.values())


def build_receipt(report: dict, raw_report_sha256: str) -> dict:
    """Return a path-free receipt only for a clean, unloaded bundle audit."""
    _require(isinstance(raw_report_sha256, str) and
             SHA256.fullmatch(raw_report_sha256) is not None,
             "raw report digest")
    _require(report.get("schema") == "hybrid-module-bundle-static-audit-v1" and
             report.get("status") == "passed" and
             report.get("qualification") == "static-module-bundle-closure",
             "report status/schema/qualification")
    _require(report.get("module_loaded") is False and
             report.get("module_installed") is False and
             report.get("runtime_or_hardware_validated") is False,
             "no-load qualification")
    _require(report.get("issues") == [], "audit issues")

    kernel = report.get("kernel_release")
    _require(isinstance(kernel, str) and kernel, "kernel release")
    raw_modules = report.get("modules")
    _require(isinstance(raw_modules, dict) and set(raw_modules) == set(MODULES),
             "module role set")
    modules = {}
    for role, (expected_name, expected_dependencies) in MODULES.items():
        source = raw_modules[role]
        _require(isinstance(source, dict), role + " module record")
        digest = source.get("sha256")
        _require(source.get("name") == expected_name, role + " module name")
        _require(isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
                 role + " module digest")
        dependencies = source.get("depends")
        _require(isinstance(dependencies, list) and
                 all(isinstance(item, str) for item in dependencies) and
                 set(dependencies) == expected_dependencies,
                 role + " dependency set")
        vermagic = source.get("vermagic", "")
        _require(isinstance(vermagic, str) and
                 vermagic.split(maxsplit=1)[:1] == [kernel],
                 role + " vermagic")
        version = source.get("version", "")
        license_name = source.get("license")
        _require(isinstance(version, str) and isinstance(license_name, str),
                 role + " metadata")
        modules[role] = {
            "name": expected_name,
            "version": version,
            "sha256": digest.lower(),
            "depends": sorted(expected_dependencies),
            "vermagic": vermagic,
            "license": license_name,
        }

    closure = report.get("symbol_closure")
    _require(isinstance(closure, dict), "symbol closure")
    frontend = closure.get("frontend_imports")
    uvm = closure.get("uvm_imports")
    _clean_closure(frontend, "frontend imports")
    _clean_closure(uvm, "UVM imports")
    frontend_count = frontend.get("import_count")
    uvm_count = uvm.get("import_count")
    _require(type(frontend_count) is int and frontend_count > 0 and
             _matched_total(frontend, "frontend imports") == frontend_count,
             "frontend import resolution")
    _require(type(uvm_count) is int and uvm_count > 0 and
             _matched_total(uvm, "UVM imports") == uvm_count,
             "UVM import resolution")

    provider_imports = closure.get("provider_imports")
    _require(isinstance(provider_imports, dict) and
             set(provider_imports) == {"open", "legacy"}, "provider imports")
    provider_counts = {}
    for role, record in provider_imports.items():
        _clean_closure(record, role + " provider imports")
        count = record.get("import_count")
        _require(type(count) is int and count >= 0 and
                 _matched_total(record, role + " provider imports") == count,
                 role + " provider resolution")
        provider_counts[role] = count

    exports = closure.get("module_exports")
    _require(isinstance(exports, dict) and set(exports) == {
        "frontend", "open", "legacy"}, "module exports")
    export_counts = {}
    for role, record in exports.items():
        _clean_closure(record, role + " exports")
        actual = record.get("actual_export_count")
        expected = record.get("expected_export_count")
        _require(type(actual) is int and actual >= 0 and
                 type(expected) is int and actual == expected,
                 role + " export closure")
        export_counts[role] = actual

    interface = closure.get("standard_uvm_interface_closure")
    _clean_closure(interface, "public UVM interface")
    interface_imports = closure.get("standard_uvm_interface_import_count")
    interface_exports = closure.get("standard_uvm_interface_export_count")
    _require(type(interface_imports) is int and interface_imports >= 0 and
             type(interface_exports) is int and interface_exports >= interface_imports,
             "public UVM interface count")
    extensions = interface.get("frontend_only_extensions", [])
    _require(isinstance(extensions, list), "public UVM frontend extensions")

    return {
        "schema": "hybrid-module-bundle-static-sanitized-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "raw_report_sha256": raw_report_sha256.lower(),
        "implementation_sha256": _implementation_hashes(),
        "status": "passed",
        "qualification": "static-module-bundle-closure-only",
        "kernel_release": kernel,
        "modules": modules,
        "symbol_closure": {
            "frontend_import_count": frontend_count,
            "uvm_import_count": uvm_count,
            "public_uvm_interface_import_count": interface_imports,
            "public_uvm_interface_export_count": interface_exports,
            "provider_import_counts": provider_counts,
            "module_export_counts": export_counts,
            "issue_count": 0,
        },
        "runtime": {
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "runtime_or_hardware_validated": False,
        },
        "limitations": [
            "Static ELF, module metadata, and symbol CRC closure only.",
            "Does not establish module loading, GPU initialization, CUDA or UVM execution.",
            "Does not establish P2P, performance, rollback, or stability.",
        ],
    }


def _read_private_report(path: Path, expected_sha256: str) -> tuple[dict, str]:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("raw report must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("raw report must have mode 0600")
        data = stream.read()
        if len(data) != metadata.st_size:
            raise ValueError("raw report changed while being read")
    digest = _sha256(data)
    if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
        raise ValueError("expected raw report digest is invalid")
    if digest != expected_sha256.lower():
        raise ValueError("raw report digest mismatch")
    report = json.loads(data)
    if not isinstance(report, dict):
        raise ValueError("raw report must contain a JSON object")
    return report, digest


def _write_receipt(path: Path, receipt: dict) -> None:
    path = Path(path)
    evidence_root = ROOT / "evidence"
    resolved_parent = path.parent.resolve(strict=True)
    if evidence_root.resolve(strict=True) not in (resolved_parent, *resolved_parent.parents):
        raise ValueError("receipt must be written under project evidence")
    if path.exists() or path.is_symlink():
        raise FileExistsError(str(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write((json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-report", type=Path, required=True)
    parser.add_argument("--expected-raw-report-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report, digest = _read_private_report(
            args.raw_report, args.expected_raw_report_sha256)
        receipt = build_receipt(report, digest)
        _write_receipt(args.output, receipt)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("summarize_hybrid_candidate_bundle: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": receipt["status"],
        "qualification": receipt["qualification"],
        "output": str(args.output),
        "sha256": _sha256(args.output.read_bytes()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
