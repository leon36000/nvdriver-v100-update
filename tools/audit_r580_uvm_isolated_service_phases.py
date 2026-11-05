#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit cross-GPU tracker ownership across R580 isolated UVM service phases.

This audit identifies source-level refusal boundaries. It does not prove that a
particular asynchronous dependency is pending on hardware or that a migration
fails at runtime.
"""
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
SOURCE_FILES = ("uvm_va_block.c", "uvm_push.c", "uvm_tracker.c")
EXPECTED_SOURCE_SHA256 = {
    "uvm_va_block.c": "a07749889e648b2487934d4d867a96855fcfe25eca704d792387d7f5965f4758",
    "uvm_push.c": "9ace70a23fb4316d7169446d8002a5ec1f293cf067bec24a7b6399c8a8b97e41",
    "uvm_tracker.c": "af78f7843aefe9682ddc3bf5a44a0fcaec0d59043e50d9fb1a0da51d058ed608",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has(source: str, pattern: str) -> bool:
    return re.search(pattern, source, re.MULTILINE | re.DOTALL) is not None


def _function(source_root: Path, file_name: str, name: str) -> str:
    try:
        return c_function_definition(Path(source_root) / file_name, name)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract {file_name}:{name}: {exc}") from None


def analyze_source(source_root: Path) -> dict[str, Any]:
    source_root = Path(source_root)
    make_resident = _function(source_root, "uvm_va_block.c", "uvm_va_block_make_resident_copy")
    unmap_mask = _function(source_root, "uvm_va_block.c", "uvm_va_block_unmap_mask")
    unmap_gpu = _function(source_root, "uvm_va_block.c", "block_unmap_gpu")
    copy_push = _function(source_root, "uvm_va_block.c", "block_copy_begin_push")
    service_locked = _function(source_root, "uvm_va_block.c", "uvm_va_block_service_locked")
    service_finish = _function(source_root, "uvm_va_block.c", "uvm_va_block_service_finish")
    revoke_finish = _function(source_root, "uvm_va_block.c", "block_service_finish_revoke_prot")
    map_finish = _function(source_root, "uvm_va_block.c", "block_service_finish_map")
    accessed_by_finish = _function(source_root, "uvm_va_block.c", "block_service_finish_map_accessed_by")
    map_gpu = _function(source_root, "uvm_va_block.c", "block_map_gpu_to")
    reject = _function(source_root, "uvm_push.c", "reject_other_gpus_if_isolated")
    tracker_owner = _function(source_root, "uvm_tracker.c", "uvm_tracker_has_other_gpus")

    unmaps = [m.start() for m in re.finditer(r"uvm_va_block_unmap_mask\s*\(", make_resident)]
    population = make_resident.find("block_populate_pages(")
    copy = make_resident.find("block_copy_resident_pages(")
    no_unmap_phase_wait = (
        len(unmaps) == 2
        and population > unmaps[1]
        and copy > population
        and not _has(make_resident, r"uvm_tracker_wait(?:_for_other_gpus)?\s*\(")
        and not _has(make_resident, r"wait_for_other_gpus_if_needed\s*\(")
    )

    copy_call = service_locked.find("uvm_va_block_service_copy(")
    finish_call = service_locked.find("uvm_va_block_service_finish(")
    no_copy_to_map_wait = (
        copy_call >= 0
        and finish_call > copy_call
        and not _has(service_locked[copy_call:finish_call], r"uvm_tracker_wait(?:_for_other_gpus)?\s*\(")
    )

    checks = {
        "isolated_push_refuses_pending_foreign_gpu_tracker": (
            _has(reject, r"uvm_push_isolated_gpu_execution_enabled\s*\(\)")
            and _has(reject, r"uvm_tracker_has_other_gpus\s*\(\s*tracker\s*,\s*gpu\s*\)")
            and _has(reject, r"return\s+NV_ERR_NOT_SUPPORTED\s*;")
            and _has(tracker_owner, r"uvm_tracker_is_completed\s*\(")
        ),
        "unmap_mask_batches_async_gpu_pushes_into_local_tracker": (
            _has(unmap_mask, r"uvm_tracker_t\s+local_tracker\s*=\s*UVM_TRACKER_INIT")
            and _has(unmap_mask, r"uvm_va_block_unmap\s*\(.*?&local_tracker\s*\)")
            and _has(unmap_mask, r"uvm_tracker_add_tracker_safe\s*\(\s*&va_block->tracker\s*,\s*&local_tracker\s*\)")
            and _has(unmap_gpu, r"uvm_push_begin_acquire\s*\(.*?&block->tracker\s*,")
            and _has(unmap_gpu, r"uvm_tracker_add_push_safe\s*\(\s*out_tracker\s*,\s*&push\s*\)")
        ),
        "two_unmap_batches_precede_destination_population_and_copy": (
            len(unmaps) == 2 and population > unmaps[1] and copy > population
        ),
        "no_tracker_wait_boundary_after_mapping_invalidation": no_unmap_phase_wait,
        "copy_push_acquires_the_va_block_tracker": _has(
            copy_push,
            r"uvm_push_begin_acquire(?:_gpu_to_gpu)?\s*\(.*?tracker_ptr",
        ) and _has(copy_push, r"tracker_ptr\s*=\s*&va_block->tracker"),
        "service_copy_flows_into_finish_without_tracker_wait": no_copy_to_map_wait,
        "post_migration_gpu_map_acquires_the_va_block_tracker": _has(
            map_gpu,
            r"uvm_push_begin_acquire\s*\(.*?&va_block->tracker\s*,",
        ),
        "service_finish_runs_revoke_then_map_then_accessed_by": _has(
            service_finish,
            r"block_service_finish_revoke_prot\s*\(.*?block_service_finish_map\s*\(.*?"
            r"block_service_finish_map_accessed_by\s*\(",
        ),
        "service_revoke_and_map_subphases_have_no_wait_retry_boundary": all(
            not _has(function, r"uvm_tracker_wait(?:_for_other_gpus)?\s*\(")
            and not _has(function, r"wait_for_other_gpus_if_needed\s*\(")
            for function in (revoke_finish, map_finish, accessed_by_finish)
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "conditional-risk" if not failed else "unrecognized-source",
        "checks": checks,
        "failed_checks": failed,
        "source_files": {
            name: {"path": str(source_root / name), "sha256": sha256_file(source_root / name)}
            for name in SOURCE_FILES
        },
        "finding": (
            "The isolated push guard rejects a push with NV_ERR_NOT_SUPPORTED when its tracker "
            "contains pending work owned by another GPU. The resident-copy path submits two "
            "mapping-invalidation batches, then populates/copies; service then proceeds into "
            "revoke and map phases. These source paths have no tracker-wait/retry boundary between "
            "those phases. Therefore an owner transition can be refused while foreign-GPU work is "
            "still pending. This is conditional on runtime tracker completion and does not prove "
            "that every direct migration fails."
        ),
        "next_design_constraint": (
            "Any enabling change must preserve VA-block state across lock drops, resume only "
            "idempotent phases, and avoid waiting while holding the block lock. A retry that "
            "replays source-to-CPU staging is not acceptable."
        ),
    }


def audit_sources(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise ValueError("UVM source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be the pinned R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != "NVIDIA-kernel-module-source-580.178.04":
        raise ValueError("source tree is not NVIDIA R580.178.04")

    for name, expected_hash in EXPECTED_SOURCE_SHA256.items():
        path = source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected a regular pinned source file: {name}")
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            raise ValueError(f"pinned R580 source SHA-256 mismatch for {name}: {actual_hash}")

    result = analyze_source(source_root)
    return {
        "schema": "nvidia-r580-uvm-isolated-service-phases-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": "580.178.04",
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "result": result,
        "status": "risk" if result["status"] == "conditional-risk" else "fail",
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
        print(f"isolated service-phase audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "risk" else 1


if __name__ == "__main__":
    raise SystemExit(main())
