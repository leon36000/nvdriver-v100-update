#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a path-free receipt for R595 UVM global and per-GPU call edges."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULE_SHA256 = "7284d09d2f3ddafc24805ce9702d3bc596a3f2919468f79c5d9a9ac586f3cd48"
EXPECTED_MODULE_VERSION = "595.112.07"
EXPECTED_MODULE_LICENSE = "Dual MIT/GPL"
EXPECTED_VERMAGIC = "7.0.0-38-generic SMP preempt mod_unload modversions"
EXPECTED_REA_VERSION = "6.8.0"
EXPECTED_GHIDRA_VERSION = "12.1.4"
EXPECTED_JAVA_VERSION = "21.0.13"

PROCEDURE_EXPECTATIONS = {
    "global_init": {
        "procedure": "uvm_gpu_init",
        "required_callee": "uvm_hal_init_table",
        "required_caller": "uvm_global_init",
        "scope": "global UVM HAL table initialization",
    },
    "per_gpu_add": {
        "procedure": "add_gpu",
        "required_callee": "uvm_hal_init_gpu",
        "required_caller": "uvm_gpu_retain_by_uuid",
        "scope": "per-GPU registration and HAL dispatch path",
    },
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _read_private_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to read REA output")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), "REA report must be a regular file")
        _require(stat.S_IMODE(before.st_mode) == 0o600,
                 "REA report must have mode 0600")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(descriptor)
        _require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 "REA report changed while being read")
        _require(len(raw) == before.st_size, "short read of REA report")
        return raw
    finally:
        os.close(descriptor)


def _record_summary(raw: bytes, module_sha256: str, expectation: dict) -> dict:
    try:
        bundle = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"REA evidence is not UTF-8 JSON: {error}") from error
    _require(isinstance(bundle, dict), "REA evidence bundle must be an object")
    records = bundle.get("records")
    _require(isinstance(records, list) and len(records) == 1,
             "REA evidence must contain exactly one function record")
    record = records[0]
    _require(isinstance(record, dict), "REA function record must be an object")
    _require(record.get("operation") == "analyze_function",
             "REA operation is not analyze_function")
    _require(record.get("confidence") == "observed" and
             record.get("authority") == "shipped-artifact",
             "REA result is not an observed artifact analysis")

    provider = record.get("provider")
    _require(isinstance(provider, dict) and provider.get("id") == "ghidra" and
             provider.get("version") == EXPECTED_GHIDRA_VERSION,
             "REA did not use the pinned Ghidra provider")
    subject = record.get("subject")
    _require(isinstance(subject, dict) and isinstance(subject.get("digest"), dict),
             "REA record has no artifact digest")
    _require(subject["digest"].get("sha256") == module_sha256 == EXPECTED_MODULE_SHA256,
             "REA record is not bound to the pinned open UVM module")

    result = record.get("normalized_result")
    _require(isinstance(result, dict), "REA record has no normalized function result")
    procedure = result.get("procedure")
    _require(isinstance(procedure, dict) and
             procedure.get("name") == expectation["procedure"],
             "REA analyzed a different procedure")
    address = procedure.get("address")
    _require(isinstance(address, str) and address.startswith("0x"),
             "REA procedure address is missing")

    def names(field: str) -> list[str]:
        values = result.get(field)
        _require(isinstance(values, list), f"REA {field} inventory is missing")
        output = []
        for value in values:
            _require(isinstance(value, dict), f"REA {field} entry is malformed")
            name = value.get("name")
            if isinstance(name, str):
                output.append(name)
        return output

    callees = names("callees")
    callers = names("callers")
    _require(callees.count(expectation["required_callee"]) == 1,
             "required direct callee is absent or ambiguous")
    _require(callers.count(expectation["required_caller"]) == 1,
             "required direct caller is absent or ambiguous")
    coverage = record.get("relationship_coverage")
    _require(isinstance(coverage, dict) and coverage.get("status") in
             {"complete", "complete-within-view"},
             "REA relationship coverage is incomplete")

    return {
        "procedure": expectation["procedure"],
        "address": address,
        "scope": expectation["scope"],
        "direct_callee_count": len(callees),
        "required_direct_callee": expectation["required_callee"],
        "required_direct_callee_observed": True,
        "direct_caller_count": len(callers),
        "required_direct_caller": expectation["required_caller"],
        "required_direct_caller_observed": True,
        "relationship_coverage": coverage["status"],
        "rea_evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "pseudocode_retained": False,
    }


def receipt_from_reports(global_raw: bytes, per_gpu_raw: bytes,
                         module_sha256: str, module_metadata: dict) -> dict:
    _require(module_sha256 == EXPECTED_MODULE_SHA256,
             "module bytes do not match the pinned open UVM candidate")
    _require(module_metadata == {
        "version": EXPECTED_MODULE_VERSION,
        "license": EXPECTED_MODULE_LICENSE,
        "vermagic": EXPECTED_VERMAGIC,
    }, "module metadata does not match the pinned open UVM candidate")
    procedures = {
        key: _record_summary(global_raw if key == "global_init" else per_gpu_raw,
                             module_sha256, expectation)
        for key, expectation in PROCEDURE_EXPECTATIONS.items()
    }
    return {
        "schema": "r595112-open-uvm-add-gpu-ghidra-sanitized-v1",
        "classification": "static-decompilation-of-project-built-open-module",
        "qualification": "ANALYZED_STATICALLY",
        "rea_version": EXPECTED_REA_VERSION,
        "ghidra_version": EXPECTED_GHIDRA_VERSION,
        "java_version": EXPECTED_JAVA_VERSION,
        "module": {
            "sha256": EXPECTED_MODULE_SHA256,
            **module_metadata,
        },
        "procedures": procedures,
        "pseudocode_retained": False,
        "runtime_or_hardware_validated": False,
        "limitations": [
            "Ghidra relationships confirm only resolved static references in this exact compiled open module.",
            "uvm_gpu_init is a global table initializer; add_gpu is the per-GPU path that references uvm_hal_init_gpu.",
            "The result does not prove returned RM architecture/classes, successful table lookup, module load, UVM behavior, CUDA execution, or GPU initialization.",
            "The full Ghidra dossier, pseudocode, assembly, and workstation paths are excluded from this receipt.",
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
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("global_init_report", type=Path)
    parser.add_argument("per_gpu_report", type=Path)
    parser.add_argument("module", type=Path)
    parser.add_argument("sanitized_output", type=Path)
    args = parser.parse_args(argv)
    try:
        global_raw = _read_private_regular(args.global_init_report)
        per_gpu_raw = _read_private_regular(args.per_gpu_report)
        module_sha256, module_metadata = read_module_metadata(args.module)
        receipt = receipt_from_reports(global_raw, per_gpu_raw,
                                       module_sha256, module_metadata)
        output_parent = args.sanitized_output.parent.resolve(strict=True)
        if not output_parent.is_relative_to(ROOT):
            raise ValueError("sanitized output must stay inside the project")
        output_path = output_parent / args.sanitized_output.name
        encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_new_receipt(output_path, encoded)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({
        "path": args.sanitized_output.as_posix(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "module_sha256": EXPECTED_MODULE_SHA256,
        "pseudocode_retained": False,
        "runtime_or_hardware_validated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
