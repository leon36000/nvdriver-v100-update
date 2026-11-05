#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize one private REA/Ghidra result for the open R595 UVM module."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULE_SHA256 = "7284d09d2f3ddafc24805ce9702d3bc596a3f2919468f79c5d9a9ac586f3cd48"
EXPECTED_PROCEDURE = "uvm_hal_init_gpu"
EXPECTED_MODULE_VERSION = "595.112.07"
EXPECTED_MODULE_LICENSE = "Dual MIT/GPL"
EXPECTED_VERMAGIC = "7.0.0-38-generic SMP preempt mod_unload modversions"
EXPECTED_REA_VERSION = "6.8.0"
EXPECTED_GHIDRA_VERSION = "12.1.4"
EXPECTED_JAVA_VERSION = "21.0.13"
SELECTOR_FIELDS = ("gpuArch", "hostClass", "ceClass")

sys.path.insert(0, str(ROOT))
from tools.nouveau_gv100_rea_audit import (  # noqa: E402
    extract_procedure_body,
    mask_c_comments_and_literals,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def receipt_from_report(raw: bytes, module_sha256: str, module_metadata: dict) -> dict:
    """Validate a closed-schema REA result and return path-free metadata only."""
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"input is not UTF-8 JSON: {error}") from error
    _require(isinstance(report, dict), "REA report must be a JSON object")
    _require(module_sha256 == EXPECTED_MODULE_SHA256,
             "module bytes do not match the pinned open UVM candidate")
    _require(module_metadata == {
        "version": EXPECTED_MODULE_VERSION,
        "license": EXPECTED_MODULE_LICENSE,
        "vermagic": EXPECTED_VERMAGIC,
    }, "module metadata does not match the pinned open UVM build")
    _require(report.get("operation") == "procedure_pseudo_code",
             "REA did not return procedure pseudocode")
    provider = report.get("provider")
    parameters = report.get("parameters")
    subject = report.get("subject")
    _require(isinstance(provider, dict), "REA report has no provider metadata")
    _require(isinstance(parameters, dict), "REA report has no procedure metadata")
    _require(isinstance(subject, dict) and isinstance(subject.get("digest"), dict),
             "REA report has no subject digest")
    _require(provider.get("id") == "ghidra",
             "REA did not use Ghidra")
    _require(provider.get("version") == EXPECTED_GHIDRA_VERSION,
             "REA did not identify the pinned Ghidra version")
    _require(parameters.get("procedure") == EXPECTED_PROCEDURE,
             "REA analyzed a different procedure")
    _require(subject["digest"].get("sha256") == EXPECTED_MODULE_SHA256,
             "REA report is not bound to the exact candidate module")
    _require(isinstance(report.get("normalized_result"), str),
             "REA report contains no normalized Ghidra result")
    body = extract_procedure_body(report["normalized_result"], EXPECTED_PROCEDURE)
    masked_body = mask_c_comments_and_literals(body)
    field_counts = {field: masked_body.count(field) for field in SELECTOR_FIELDS}
    _require(all(count > 0 for count in field_counts.values()),
             "compiled function does not expose all three UVM selector fields")
    _require(report.get("confidence") == "observed"
             and report.get("authority") == "shipped-artifact",
             "REA evidence is not an observed shipped-artifact procedure result")
    return {
        "schema": "r595112-open-uvm-ghidra-sanitized-v1",
        "classification": "static-decompilation-of-project-built-open-module",
        "qualification": "ANALYZED_STATICALLY",
        "rea_version": EXPECTED_REA_VERSION,
        "ghidra_version": EXPECTED_GHIDRA_VERSION,
        "java_version": EXPECTED_JAVA_VERSION,
        "module": {
            "sha256": EXPECTED_MODULE_SHA256,
            **module_metadata,
        },
        "procedure": EXPECTED_PROCEDURE,
        "selector_field_occurrences_in_bounded_body": field_counts,
        "rea_report_sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_pseudocode_sha256": hashlib.sha256(
            report["normalized_result"].encode("utf-8")).hexdigest(),
        "normalized_pseudocode_bytes": len(report["normalized_result"].encode("utf-8")),
        "pseudocode_retained": False,
        "runtime_or_hardware_validated": False,
        "limitations": [
            "Ghidra pseudocode is static analysis output and is not original NVIDIA source.",
            "The module was compiled but never installed or loaded; no UVM or GPU behavior was exercised.",
            "Field occurrence confirms that the compiled procedure refers to these selectors, not successful RM lookup or callback dispatch.",
        ],
    }


def read_module_metadata(module: Path) -> tuple[str, dict[str, str]]:
    if module.is_symlink() or not module.is_file():
        raise ValueError("module must be a regular non-symlink file")
    digest = hashlib.sha256(module.read_bytes()).hexdigest()
    metadata = {}
    for name in ("version", "license", "vermagic"):
        try:
            result = subprocess.run(
                ["modinfo", "-F", name, str(module)],
                check=False, capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("modinfo could not read the candidate module") from error
        if result.returncode != 0:
            raise ValueError("modinfo rejected the candidate module")
        metadata[name] = result.stdout.strip()
    return digest, metadata


def write_new_receipt(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise ValueError("output must not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rea_report", type=Path)
    parser.add_argument("module", type=Path)
    parser.add_argument("sanitized_output", type=Path)
    args = parser.parse_args(argv)
    if args.rea_report.is_symlink() or not args.rea_report.is_file():
        parser.error("rea_report must be a regular non-symlink file")
    if stat.S_IMODE(args.rea_report.stat().st_mode) != 0o600:
        parser.error("rea_report must have mode 0600")
    try:
        module_digest, metadata = read_module_metadata(args.module)
        receipt = receipt_from_report(args.rea_report.read_bytes(), module_digest, metadata)
        parent = args.sanitized_output.parent.resolve(strict=True)
        if not parent.is_relative_to(ROOT):
            raise ValueError("sanitized output must stay inside the project")
        encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_new_receipt(parent / args.sanitized_output.name, encoded)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({
        "path": args.sanitized_output.as_posix(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "procedure": EXPECTED_PROCEDURE,
        "pseudocode_retained": False,
        "runtime_or_hardware_validated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
