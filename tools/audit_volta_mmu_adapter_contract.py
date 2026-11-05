#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the narrow R580-to-R595 Volta MMU callback adaptation.

This is a source-contract audit. It does not validate a loaded module or GPU.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_volta_uvm_port import (  # noqa: E402
    _mask_c_comments,
    _matching_c_brace,
    _verify_r580_volta_mmu_64k_contract,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_function(source: str, symbol: str) -> str:
    """Return one C function body; refuse missing or ambiguous definitions."""
    masked = _mask_c_comments(source)
    pattern = re.compile(rf"\b{re.escape(symbol)}\s*\([^;{{}}]*\)\s*\{{")
    matches = list(pattern.finditer(masked))
    if len(matches) != 1:
        raise ValueError(f"expected one definition of {symbol}, found {len(matches)}")
    match = matches[0]
    opening = match.end() - 1
    closing = _matching_c_brace(source, opening)
    return source[opening + 1:closing]


def normalize_c(source: str) -> str:
    """Remove comments and whitespace for a narrow token-equivalence check."""
    return re.sub(r"\s+", "", _mask_c_comments(source))


def call_sites(source: str, symbol: str) -> list[dict]:
    masked = _mask_c_comments(source)
    pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(([^()]*)\)")
    rows = []
    for match in pattern.finditer(masked):
        suffix = masked[match.end():].lstrip()
        if suffix.startswith("{"):
            continue
        expression = source[match.start(1):match.end(1)].strip()
        rows.append({
            "line": masked.count("\n", 0, match.start()) + 1,
            "argument": re.sub(r"\s+", "", expression),
        })
    return rows


def pte_flag_layout(header: Path) -> dict:
    """Read the three generated fields used by the invalid big-PTE value."""
    source = header.read_text(encoding="utf-8")

    def macro_value(name: str) -> str:
        rows = re.findall(
            rf"^\s*#define\s+{re.escape(name)}\s+([^\s/]+)",
            source,
            flags=re.MULTILINE,
        )
        if len(rows) != 1:
            raise ValueError(f"expected one {name} macro in {header}, found {len(rows)}")
        return rows[0]

    layout = {}
    for field in ("VALID", "VOL", "PRIVILEGE"):
        bounds = re.fullmatch(r"(\d+):(\d+)", macro_value(f"NV_MMU_VER2_PTE_{field}"))
        if bounds is None:
            raise ValueError(f"unsupported PTE field range for {field} in {header}")
        high, low = map(int, bounds.groups())
        true_value = int(macro_value(f"NV_MMU_VER2_PTE_{field}_TRUE"), 0)
        false_value = int(macro_value(f"NV_MMU_VER2_PTE_{field}_FALSE"), 0)
        if high < low or true_value >= (1 << (high - low + 1)) or false_value >= (1 << (high - low + 1)):
            raise ValueError(f"PTE field value does not fit {field} in {header}")
        layout[field] = {"high": high, "low": low, "true": true_value, "false": false_value}
    ranges = [(row["high"], row["low"]) for row in layout.values()]
    for index, (high, low) in enumerate(ranges):
        for other_high, other_low in ranges[index + 1:]:
            if max(low, other_low) <= min(high, other_high):
                raise ValueError(f"overlapping PTE validity fields in {header}")
    encoded = sum(row["false"] << row["low"] for row in layout.values())
    privilege = layout["PRIVILEGE"]
    encoded |= privilege["true"] << privilege["low"]
    return {"fields": layout, "unmapped_64k_value": encoded}


def volta_pte_encoder_profile(r580_function: str, candidate_function: str) -> str | None:
    """Accept either exact R580 PTE logic or its two-site R595 aperture extension.

    The R595 GV100 candidate adds the Volta-defined system-noncoherent aperture
    in the aperture selector and system-address branch. Canonicalizing exactly
    those two audited changes must yield the pinned R580 function body byte for
    byte after comment/whitespace normalization. Other deltas fail closed.
    """
    r580 = normalize_c(r580_function)
    candidate = normalize_c(candidate_function)
    if candidate == r580:
        return "r580-source-exact"

    aperture_extension = (
        "elseif(aperture==UVM_APERTURE_SYS_NON_COHERENT)"
        "aperture_bits=NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY;"
    )
    system_address_extension = (
        "if(aperture==UVM_APERTURE_SYS||"
        "aperture==UVM_APERTURE_SYS_NON_COHERENT){"
    )
    if candidate.count(aperture_extension) != 1:
        return None
    if candidate.count(system_address_extension) != 1:
        return None

    canonicalized = candidate.replace(aperture_extension, "", 1).replace(
        system_address_extension, "if(aperture==UVM_APERTURE_SYS){", 1
    )
    if canonicalized == r580:
        return "r595-volta-system-noncoherent-aperture-extension"
    return None


def _required_file(root: Path, relative: str) -> Path:
    path = (root / relative).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"expected source file: {path}")
    return path


def audit(r580_root: Path, r595_root: Path, candidate_root: Path) -> dict:
    r580_pascal = _required_file(r580_root, "uvm_pascal_mmu.c")
    r580_volta = _required_file(r580_root, "uvm_volta_mmu.c")
    r580_va_block = _required_file(r580_root, "uvm_va_block.c")
    r595_turing = _required_file(r595_root, "uvm_turing_mmu.c")
    r595_va_block = _required_file(r595_root, "uvm_va_block.c")
    candidate_pascal = _required_file(candidate_root, "uvm_pascal_mmu.c")
    candidate_volta = _required_file(candidate_root, "uvm_volta_mmu.c")
    r580_pascal_fields = _required_file(r580_root, "hwref/pascal/gp100/dev_mmu.h")
    r580_volta_fields = _required_file(r580_root, "hwref/volta/gv100/dev_mmu.h")
    r595_turing_fields = _required_file(r595_root, "hwref/turing/tu102/dev_mmu.h")
    candidate_volta_fields = _required_file(candidate_root, "hwref/volta/gv100/dev_mmu.h")

    source_text = {
        "r580_pascal_mmu": r580_pascal.read_text(encoding="utf-8"),
        "r580_volta_mmu": r580_volta.read_text(encoding="utf-8"),
        "r580_va_block": r580_va_block.read_text(encoding="utf-8"),
        "r595_turing_mmu": r595_turing.read_text(encoding="utf-8"),
        "r595_va_block": r595_va_block.read_text(encoding="utf-8"),
        "candidate_pascal_mmu": candidate_pascal.read_text(encoding="utf-8"),
        "candidate_volta_mmu": candidate_volta.read_text(encoding="utf-8"),
    }

    _verify_r580_volta_mmu_64k_contract(source_text["r580_volta_mmu"])
    r580_unmapped = extract_function(source_text["r580_pascal_mmu"], "unmapped_pte_pascal")
    r580_factory = extract_function(source_text["r580_volta_mmu"], "uvm_hal_mmu_mode_volta")
    r595_unmapped = extract_function(source_text["r595_turing_mmu"], "unmapped_pte_turing")
    r595_poisoned = extract_function(source_text["r595_turing_mmu"], "poisoned_pte_turing")
    candidate_unmapped = extract_function(source_text["candidate_pascal_mmu"], "unmapped_pte_pascal")
    candidate_poisoned = extract_function(source_text["candidate_pascal_mmu"], "poisoned_pte_pascal")
    candidate_volta_factory = extract_function(source_text["candidate_volta_mmu"], "uvm_hal_mmu_mode_volta")
    candidate_r595_volta_wrapper = extract_function(source_text["candidate_volta_mmu"], "uvm_hal_mmu_mode_volta_r595")
    r580_make_pte_volta = extract_function(source_text["r580_volta_mmu"], "make_pte_volta")
    candidate_make_pte_volta = extract_function(source_text["candidate_volta_mmu"], "make_pte_volta")
    pte_encoder_profile = volta_pte_encoder_profile(r580_make_pte_volta,
                                                   candidate_make_pte_volta)

    legacy_calls = call_sites(source_text["r580_va_block"], "unmapped_pte")
    modern_calls = call_sites(source_text["r595_va_block"], "unmapped_pte")
    accepted_legacy_args = {"big_page_size", "tree->big_page_size", "UVM_PAGE_SIZE_64K"}
    legacy_args_valid = len(legacy_calls) == 7 and all(
        row["argument"] in accepted_legacy_args for row in legacy_calls
    )
    modern_args_valid = len(modern_calls) == 7 and all(row["argument"] == "" for row in modern_calls)

    pte_layouts = {
        "r580_pascal": pte_flag_layout(r580_pascal_fields),
        "r580_volta": pte_flag_layout(r580_volta_fields),
        "r595_turing": pte_flag_layout(r595_turing_fields),
    }
    common_layout = pte_layouts["r580_pascal"]["fields"]
    pte_layout_matches = all(row["fields"] == common_layout for row in pte_layouts.values())
    pte_value_matches = all(row["unmapped_64k_value"] == 0x20 for row in pte_layouts.values())

    checks = {
        "r580_volta_factory_asserts_64k_or_128k_then_rejects_128k": True,
        "r580_volta_factory_derives_from_pascal": (
            "uvm_hal_mmu_mode_pascal(big_page_size)" in re.sub(r"\s+", "", r580_factory)
        ),
        "r580_production_unmapped_calls_use_big_page_or_explicit_64k": legacy_args_valid,
        "r595_production_unmapped_calls_use_no_argument_contract": modern_args_valid,
        "pinned_pascal_volta_turing_pte_field_layouts_match": pte_layout_matches,
        "pinned_invalid_64k_pte_encoding_is_0x20": pte_value_matches,
        "candidate_volta_factory_matches_r580_factory_body": (
            normalize_c(candidate_volta_factory) == normalize_c(r580_factory)
        ),
        "candidate_r595_volta_wrapper_fixes_64k_mode": (
            "uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K)"
            in re.sub(r"\s+", "", candidate_r595_volta_wrapper)
        ),
        "candidate_unmapped_callback_matches_r595_turing": (
            normalize_c(candidate_unmapped) == normalize_c(r595_unmapped)
        ),
        "candidate_poisoned_callback_matches_r595_turing": (
            normalize_c(candidate_poisoned) == normalize_c(r595_poisoned)
        ),
        "candidate_volta_field_header_matches_pinned_r580": (
            candidate_volta_fields.read_bytes() == r580_volta_fields.read_bytes()
        ),
        "candidate_volta_pte_encoder_matches_pinned_or_approved_profile": (
            pte_encoder_profile is not None
        ),
    }
    if not all(checks.values()):
        failed = ", ".join(key for key, passed in checks.items() if not passed)
        raise ValueError(f"Volta MMU callback source contract failed: {failed}")

    return {
        "schema": "volta-r580-r595-mmu-adapter-audit-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "static-source-contracts-pass-runtime-unvalidated",
        "checks": checks,
        "legacy_unmapped_call_sites": legacy_calls,
        "modern_unmapped_call_sites": modern_calls,
        "legacy_unmapped_behavior": {
            "64k": "VALID=0, VOL=0, PRIVILEGE=1 (0x20 computed from pinned generated field definitions)",
            "other_page_sizes": "0",
        },
        "pte_field_layouts": pte_layouts,
        "candidate_volta_pte_encoder_profile": pte_encoder_profile,
        "candidate_adaptation": {
            "Volta factory": "R580 implementation retained; no 128 KiB mode",
            "unmapped PTE": "R595 no-argument Turing encoding after fixed 64 KiB Volta mode selection",
            "poisoned PTE": "R595 tree-aware callback over the retained Volta make_pte function",
            "Volta PTE encoder": (
                "token-equivalent to pinned R580 source"
                if pte_encoder_profile == "r580-source-exact"
                else "pinned R580 PTE logic with only the verified GV100 SYS_NON_COHERENT aperture extension"
            ),
        },
        "sources": {
            key: {"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                  "sha256": sha256_file(path)}
            for key, path in {
                "r580_pascal_mmu": r580_pascal,
                "r580_volta_mmu": r580_volta,
                "r580_va_block": r580_va_block,
                "r595_turing_mmu": r595_turing,
                "r595_va_block": r595_va_block,
                "candidate_pascal_mmu": candidate_pascal,
                "candidate_volta_mmu": candidate_volta,
                "r580_pascal_mmu_fields": r580_pascal_fields,
                "r580_volta_mmu_fields": r580_volta_fields,
                "r595_turing_mmu_fields": r595_turing_fields,
                "candidate_volta_mmu_fields": candidate_volta_fields,
            }.items()
        },
        "runtime_or_hardware_validated": False,
        "limitations": [
            "Static source equivalence does not execute the MMU HAL or prove GPU PTE behavior.",
            "Other UVM callbacks and compatibility adaptations remain compile-probe-only.",
            "No module was installed or loaded and no GPU state was changed.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-uvm", type=Path, required=True,
                        help="pinned R580 nvidia-uvm source directory")
    parser.add_argument("--r595-uvm", type=Path, required=True,
                        help="pinned R595 nvidia-uvm source directory")
    parser.add_argument("--candidate-uvm", type=Path, required=True,
                        help="staged Volta candidate nvidia-uvm source directory")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.r580_uvm, args.r595_uvm, args.candidate_uvm)
    report_path = args.report.resolve()
    if report_path.exists():
        parser.error(f"refusing to overwrite report: {report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    report_path.write_bytes(encoded)
    report_path.chmod(0o600)
    print(json.dumps({
        "status": "passed",
        "report": str(report_path),
        "report_sha256": hashlib.sha256(encoded).hexdigest(),
        "runtime_or_hardware_validated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        raise SystemExit(2)
