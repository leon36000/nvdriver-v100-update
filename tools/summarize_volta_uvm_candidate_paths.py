#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a path-free receipt from a private R580/R595 UVM source audit."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REPORT_SCHEMA = "volta-uvm-r580-r595-candidate-path-audit-v9"
EXPECTED_BRANCH = "R595.112.07+R580.196.07-GV100-HAL-dispatch-gate-v1"
EXPECTED_CANDIDATE_HAL_SHA256 = "3a7c5f6f892102663af00fdcb9e638a3a96a2b8cddd00af25d9054169106c248"
EXPECTED_R580_ARCHIVE_SHA256 = "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"
EXPECTED_R580_INITIALIZER_SHA256 = "2f6bb4ea1fd81e3a495802b0181573ff339e317c22dfb745ee3b2f4207343653"
EXPECTED_CAPABILITY_FIELDS = {
    "va_invalidate_supported",
    "va_range_invalidate_supported",
    "can_map_sysmem_with_large_pages",
    "prefetch_fault_supported",
    "gpfifo_in_vidmem_supported",
    "replayable_faults_supported",
    "non_replayable_faults_supported",
    "fault_cancel_va_supported",
    "scoped_atomics_supported",
    "sparse_mappings_supported",
    "plc_supported",
}
ABSOLUTE_PATH = re.compile(
    r"(?:^|[\s=:\"'])/(?:home|run|tmp|mnt|media|root|usr|var|opt|etc)/"
    r"|(?:^|[\s=:\"'])[A-Za-z]:[\\/]"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _text(value: object, label: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{label} must be non-empty text")
    return value


def _sha256(value: object, label: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _path_free(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _require(not any(token in key.lower() for token in ("path", "root", "directory")),
                     f"path-bearing field is forbidden in sanitized output: {key}")
            _path_free(child)
    elif isinstance(value, list):
        for child in value:
            _path_free(child)
    elif isinstance(value, str):
        _require(ABSOLUTE_PATH.search(value) is None,
                 "absolute local path detected in sanitized output")


def receipt_from_report(raw: bytes) -> dict:
    """Validate the exact pinned audit and retain only portable evidence."""
    source_digest = hashlib.sha256(raw).hexdigest()
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"input is not a UTF-8 JSON report: {error}") from error
    _require(isinstance(report, dict), "input report must be a JSON object")
    _require(report.get("schema") == EXPECTED_REPORT_SCHEMA,
             "unexpected candidate-path audit schema")
    _require(report.get("classification") == "pinned-static-source-callpath-audit",
             "input report is not the expected static source audit")
    _require(report.get("candidate_branch") == EXPECTED_BRANCH,
             "input candidate branch does not match the pinned build")
    _require(report.get("candidate_tree_is_experimental") is True,
             "candidate tree must be marked experimental")
    _require(report.get("candidate_legacy_identifiers_absent_count") == 11,
             "candidate audit must cover all eleven old identifiers")

    candidate = report.get("candidate_source")
    legacy = report.get("r580_source")
    _require(isinstance(candidate, dict) and isinstance(legacy, dict),
             "source identity objects are missing")
    _require(_sha256(candidate.get("hal_source_sha256"), "candidate HAL source")
             == EXPECTED_CANDIDATE_HAL_SHA256,
             "candidate HAL source is not the pinned overlay")
    _require(_sha256(legacy.get("archive_sha256"), "R580 archive")
             == EXPECTED_R580_ARCHIVE_SHA256,
             "R580 source archive is not the pinned package")
    _require(_sha256(legacy.get("volta_initializer_sha256"), "R580 Volta initializer")
             == EXPECTED_R580_INITIALIZER_SHA256,
             "R580 Volta initializer is not the pinned source")
    _require(isinstance(candidate.get("uvm_source_file_count"), int)
             and candidate["uvm_source_file_count"] > 0,
             "candidate UVM source count is invalid")

    capabilities = report.get("capabilities")
    _require(isinstance(capabilities, list) and len(capabilities) == 11,
             "audit must include exactly eleven capability paths")
    fields = [item.get("field") for item in capabilities if isinstance(item, dict)]
    _require(len(fields) == 11 and set(fields) == EXPECTED_CAPABILITY_FIELDS,
             "capability field set is incomplete or contains duplicates")
    safe_capabilities = []
    for item in capabilities:
        _require(item.get("runtime_or_hardware_validated") is False,
                 f"runtime validation cannot be inferred for {item['field']}")
        safe_capabilities.append({
            "field": _text(item.get("field"), "capability field"),
            "candidate_disposition": _text(item.get("candidate_disposition"), "disposition"),
            "candidate_interpretation": _text(item.get("candidate_interpretation"), "interpretation"),
            "validation_needed": _text(item.get("validation_needed"), "validation requirement"),
            "runtime_or_hardware_validated": False,
        })

    p2p = report.get("p2p_direction_mapping")
    _require(isinstance(p2p, dict)
             and p2p.get("classification") == "static-r595-uvm-p2p-direction-consumer-audit"
             and p2p.get("rm_capability_values_observed") is False
             and p2p.get("runtime_or_hardware_validated") is False,
             "P2P evidence does not meet the pinned static-only contract")
    p2p_scan = p2p.get("source_scan")
    p2p_contract = p2p.get("consumer_direction_contract")
    _require(isinstance(p2p_scan, dict) and isinstance(p2p_contract, dict),
             "P2P source-scan or consumer contract is missing")
    _require(p2p_scan.get("rm_gpu_ops_get_p2p_caps_definition_count") == 0,
             "unexpected RM P2P producer definition in scanned source")

    prefetch = report.get("prefetch_callback_comparison")
    _require(isinstance(prefetch, dict)
             and prefetch.get("runtime_or_hardware_validated") is False,
             "prefetch comparison is missing or claims runtime validation")
    control = prefetch.get("control_helper")
    guard = prefetch.get("enable_wrapper_guard")
    _require(isinstance(control, dict)
             and control.get("identical_after_comments_literals_and_whitespace_masked") is True
             and isinstance(guard, dict),
             "prefetch helper equivalence/guard evidence is incomplete")

    aperture = report.get("noncoherent_aperture_comparison")
    _require(isinstance(aperture, dict)
             and aperture.get("runtime_or_hardware_validated") is False,
             "noncoherent aperture comparison is missing or claims runtime validation")
    candidate_aperture = aperture.get("candidate")
    _require(isinstance(candidate_aperture, dict)
             and isinstance(candidate_aperture.get("checks"), dict)
             and all(value is True for value in candidate_aperture["checks"].values())
             and len(candidate_aperture["checks"]) == 4,
             "all four static noncoherent-aperture checks must pass")

    created_utc = _text(report.get("created_utc"), "audit timestamp")
    limitations = report.get("limitations")
    _require(isinstance(limitations, list) and limitations
             and all(isinstance(item, str) and item for item in limitations),
             "source-audit limitations are missing")
    receipt = {
        "schema": "r595-volta-capability-paths-sanitized-v1",
        "created_utc": created_utc,
        "classification": "pinned-static-source-callpath-audit",
        "qualification": "ANALYZED_STATICALLY",
        "source_report_sha256": source_digest,
        "source_identity": {
            "candidate_branch": EXPECTED_BRANCH,
            "candidate_hal_source_sha256": EXPECTED_CANDIDATE_HAL_SHA256,
            "candidate_uvm_source_file_count": candidate["uvm_source_file_count"],
            "candidate_uvm_source_manifest_sha256": _sha256(
                candidate.get("uvm_source_manifest_sha256"), "candidate source manifest"),
            "r580_source_archive_sha256": EXPECTED_R580_ARCHIVE_SHA256,
            "r580_volta_initializer_sha256": EXPECTED_R580_INITIALIZER_SHA256,
        },
        "capability_count": len(safe_capabilities),
        "capabilities": safe_capabilities,
        "p2p_consumer": {
            "consumer_direction_contract": p2p_contract,
            "rm_capability_values_observed": False,
            "scanned_candidate_c_header_file_count": p2p_scan.get("c_header_file_count"),
            "rm_p2p_capability_definition_count": 0,
            "source_scan_qualification": _text(p2p_scan.get("qualification"), "P2P scan qualification"),
            "validation_needed": _text(p2p.get("validation_needed"), "P2P validation requirement"),
            "runtime_or_hardware_validated": False,
        },
        "prefetch_control": {
            "candidate_callback_selection": _text(prefetch.get("candidate_callback_selection"), "prefetch callback"),
            "candidate_and_R580_control_helper_normalized_equal": True,
            "candidate_prefetch_fault_supported_assertion": guard.get("candidate_prefetch_fault_supported_assertion"),
            "r580_prefetch_fault_supported_assertion": guard.get("r580_prefetch_fault_supported_assertion"),
            "interpretation": _text(guard.get("interpretation"), "prefetch guard interpretation"),
            "validation_needed": _text(prefetch.get("validation_needed"), "prefetch validation requirement"),
            "runtime_or_hardware_validated": False,
        },
        "noncoherent_aperture": {
            "candidate_checks": candidate_aperture["checks"],
            "interpretation": _text(aperture.get("interpretation"), "aperture interpretation"),
            "validation_needed": _text(aperture.get("validation_needed"), "aperture validation requirement"),
            "runtime_or_hardware_validated": False,
        },
        "runtime_or_hardware_validated": False,
        "limitations": limitations,
    }
    _path_free(receipt)
    return receipt


def write_sanitized_receipt(path: Path, data: bytes) -> None:
    """Create a new mode-0644 receipt without following or replacing a file."""
    if path.is_symlink():
        raise ValueError("output must not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_report", type=Path)
    parser.add_argument("sanitized_output", type=Path)
    args = parser.parse_args(argv)
    private_path = args.private_report
    if private_path.is_symlink() or not private_path.is_file():
        parser.error("private_report must be a regular non-symlink file")
    if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
        parser.error("private_report must have mode 0600")
    output_path = args.sanitized_output
    try:
        parent = output_path.parent.resolve(strict=True)
        if not parent.is_relative_to(ROOT):
            raise ValueError("sanitized output must stay inside the project")
        receipt = receipt_from_report(private_path.read_bytes())
        encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_sanitized_receipt(parent / output_path.name, encoded)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({
        "path": output_path.as_posix(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "capability_count": receipt["capability_count"],
        "runtime_or_hardware_validated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
