#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the R580 isolated-mode preflight for GPU-staged UVM migrations."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_hybrid_uvm_abi import c_function_definition  # noqa: E402

SOURCE_ROOT = (
    ROOT / "build/experiments/r580-uvm-early-preflight-v3-20261028T1921Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
PATCH_PATHS = (
    ROOT / "patches/r580.178.04/uvm/0010-reject-unsupported-isolated-staged-migrations.patch",
    ROOT / "patches/r580.178.04/uvm/0011-preflight-unsupported-staging-before-unmap.patch",
    ROOT / "patches/r580.178.04/uvm/0012-exact-isolated-staged-page-mask.patch",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _matches(source: str, pattern: str) -> bool:
    return re.search(pattern, source, re.MULTILINE | re.DOTALL) is not None


def analyze_source(source_root: Path) -> dict[str, Any]:
    va_block_source = Path(source_root) / "uvm_va_block.c"
    block_copy = c_function_definition(va_block_source, "block_copy_resident_pages")
    make_resident_copy = c_function_definition(va_block_source, "uvm_va_block_make_resident_copy")
    source_preflight = c_function_definition(va_block_source, "block_get_isolated_staged_pages")

    gate = re.search(
        r"if\s*\(\s*UVM_ID_IS_GPU\(dst_id\)\s*&&\s*"
        r"uvm_push_isolated_gpu_execution_enabled\(\s*\)\s*\)",
        block_copy,
    )
    dispatch = block_copy.find("block_copy_resident_pages_mask(")
    gate_start = gate.start() if gate else -1
    late_preflight = block_copy[gate.start():dispatch] if gate and dispatch > gate.start() else ""
    early_call = make_resident_copy.find("block_get_isolated_staged_pages(")
    first_unmap = make_resident_copy.find("uvm_va_block_unmap_mask(")
    population = make_resident_copy.find("block_populate_pages(")
    early_reject = make_resident_copy.find("status = NV_ERR_NOT_SUPPORTED;", early_call)
    early_prefix = make_resident_copy[:early_call] if early_call >= 0 else ""

    checks = {
        "isolated_gpu_destination_is_gated": gate is not None,
        "only_requested_region_pages_trigger_rejection": (
            _matches(source_preflight, r"uvm_page_mask_and\s*\(\s*source_pages_mask\s*,\s*copy_page_mask")
            and _matches(source_preflight, r"uvm_page_mask_region_clear_outside\s*\(\s*staged_pages\s*,\s*region\s*\)")
            and _matches(source_preflight, r"uvm_page_mask_andnot\s*\(\s*staged_pages\s*,\s*staged_pages\s*,\s*&block->discarded_pages\s*\)")
        ),
        "unsupported_sources_are_intersected_with_copy_access": (
            _matches(source_preflight, r"uvm_processor_mask_andnot\s*\(\s*processors\s*,\s*&block->resident\s*,\s*can_copy_from\s*\)")
            and _matches(source_preflight, r"for_each_id_in_mask\s*\(\s*src_id\s*,\s*processors\s*\)")
            and _matches(source_preflight, r"block_get_can_copy_from_mask\s*\(\s*block\s*,\s*dst_id\s*\)")
        ),
        "accessible_duplicate_suppresses_unneeded_staging": (
            _matches(source_preflight, r"uvm_processor_mask_and\s*\(\s*processors\s*,\s*can_copy_from\s*,\s*&block->resident\s*\)")
            and _matches(source_preflight, r"uvm_page_mask_andnot\s*\(\s*staged_pages\s*,\s*staged_pages\s*,\s*uvm_va_block_resident_mask_get\s*\(")
        ),
        "late_reject_precedes_all_copy_dispatch": (
            gate is not None and dispatch > gate_start and
            _matches(late_preflight, r"block_get_isolated_staged_pages\s*\(")
            and _matches(late_preflight, r"!uvm_page_mask_empty\s*\(\s*&block_context->make_resident.copy_resident_pages_mask\s*\)")
            and _matches(late_preflight, r"status\s*=\s*NV_ERR_NOT_SUPPORTED\s*;\s*goto out\s*;")
        ),
        "early_reject_precedes_mapping_invalidation_and_population": (
            early_call >= 0 and first_unmap > early_call and population > early_call and
            early_reject > early_call and early_reject < first_unmap and
            _matches(early_prefix, r"uvm_page_mask_andnot\s*\(\s*preflight_pages\s*,\s*preflight_pages\s*,\s*&va_block->discarded_pages\s*\)")
        ),
    }
    return {
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "source": {"path": str(va_block_source), "sha256": sha256_file(va_block_source)},
        "interpretation": (
            "The isolated UVM path computes the exact subset requiring CPU staging by "
            "subtracting pages available from any directly accessible resident processor. "
            "It checks requested, non-discarded pages before mapping invalidation/population "
            "and repeats the check immediately before migration-copy dispatch. Unsupported "
            "staging returns NV_ERR_NOT_SUPPORTED; managed-memory migration remains disabled."
        ),
    }


def audit_sources(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    result = analyze_source(source_root)
    return {
        "schema": "nvidia-r580-uvm-staged-preflight-v3",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {
            "source_release": "580.178.04",
            "patches": [
                {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path)}
                for path in PATCH_PATHS
            ],
        },
        "result": result,
        "status": "pass" if not result["failed_checks"] else "fail",
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root)
        write_report(args.output, report)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"staged migration preflight audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
