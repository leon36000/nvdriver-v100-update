#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the R595 PMM tracker-allocation fallback and its lock context.

This is a source audit. It identifies a conditional wait reachable after
tracker allocation failure; it does not establish a deadlock or a runtime
failure on a GPU.
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
    ROOT
    / "build/experiments/r595-provider-id-validation-v1-20261029/"
    "candidate/nvidia-uvm"
)
SOURCE_TAG = "R595.99.02 / provider-id-validation-v1"
SOURCE_FILES = (
    "uvm_pmm_gpu.c",
    "uvm_tracker.c",
    "uvm_va_block.c",
    "uvm_mmu.c",
    "uvm_kvmalloc.c",
    "uvm_lock.h",
    "uvm_linux.h",
)
EXPECTED_SHA256 = {
    "uvm_pmm_gpu.c": "753fe5ac7220b7035ae9e641fb6595769166bf556e1aadc3cdfa9ae5c6d5cb31",
    "uvm_tracker.c": "1b7fd32a785b78af5492c30a297e148f421af3e04108a587a641932d4ca7499a",
    "uvm_va_block.c": "faf15872daf79ea83894ce24f7f8c4034809c03114a99da1fd0817288785c931",
    "uvm_mmu.c": "4b1b2234c78b24881c8b8854961f00d575e8b70df4e2be08d881833308b03297",
    "uvm_kvmalloc.c": "c076016dc5fcad9619eb935af1e187070653b1a97b34d392c66e0b320356d9db",
    "uvm_lock.h": "09a9f44192b270ce7f08217306a38f1a2d08b5cf1f0b713d0f12d352bacca20d",
    "uvm_linux.h": "9fed68595b1d9fe2a63ef1ed90625b3cd0fe58c69c88bb7d0801ac7244a968e7",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _function(source_root: Path, file_name: str, name: str) -> str:
    return c_function_definition(Path(source_root) / file_name, name)


def _check_safe_wait(tracker_source: str) -> bool:
    try:
        safe = c_function_definition_from_text(tracker_source, "uvm_tracker_add_tracker_safe")
    except ValueError:
        return False
    return bool(re.search(
        r"uvm_tracker_add_tracker\s*\(\s*dst\s*,\s*src\s*\).*?"
        r"if\s*\(\s*status\s*==\s*NV_ERR_NO_MEMORY\s*\).*?"
        r"status\s*=\s*uvm_tracker_wait\s*\(\s*src\s*\)",
        safe,
        re.DOTALL,
    ))


def c_function_definition_from_text(source: str, function_name: str) -> str:
    """Extract a C function from text using the repository's brace parser."""
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".c") as stream:
        stream.write(source)
        stream.flush()
        return c_function_definition(Path(stream.name), function_name)


def analyze_sources(source_root: Path) -> dict[str, Any]:
    source_root = Path(source_root)
    pmm_source = (source_root / "uvm_pmm_gpu.c").read_text(encoding="utf-8")
    tracker_source = (source_root / "uvm_tracker.c").read_text(encoding="utf-8")
    va_block_source = (source_root / "uvm_va_block.c").read_text(encoding="utf-8")
    mmu_source = (source_root / "uvm_mmu.c").read_text(encoding="utf-8")
    kvmalloc_source = (source_root / "uvm_kvmalloc.c").read_text(encoding="utf-8")
    lock_header = (source_root / "uvm_lock.h").read_text(encoding="utf-8")
    linux_header = (source_root / "uvm_linux.h").read_text(encoding="utf-8")

    pmm_free = _function(source_root, "uvm_pmm_gpu.c", "uvm_pmm_gpu_free")
    pmm_alloc = _function(source_root, "uvm_pmm_gpu.c", "pmm_gpu_alloc")
    evict = _function(source_root, "uvm_pmm_gpu.c", "evict_root_chunk_from_va_block")
    free_root = _function(source_root, "uvm_pmm_gpu.c", "free_root_chunk")
    tracker_add = _function(source_root, "uvm_tracker.c", "uvm_tracker_add_tracker")
    reserve = _function(source_root, "uvm_tracker.c", "uvm_tracker_reserve")
    tracker_safe = _function(source_root, "uvm_tracker.c", "uvm_tracker_add_tracker_safe")
    block_populate = _function(source_root, "uvm_va_block.c", "block_populate_gpu_chunk")
    block_destroy = _function(source_root, "uvm_va_block.c", "block_destroy_gpu_state")
    phys_deallocate = _function(source_root, "uvm_mmu.c", "phys_mem_deallocate_vidmem")
    root_lock = _function(source_root, "uvm_pmm_gpu.c", "root_chunk_lock")
    root_unlock = _function(source_root, "uvm_pmm_gpu.c", "root_chunk_unlock")
    bit_lock = _function(source_root, "uvm_lock.h", "__uvm_bit_lock")

    free_lock = pmm_free.find("root_chunk_lock(pmm, root_chunk);")
    free_merge = pmm_free.find("uvm_tracker_add_tracker_safe(&root_chunk->tracker, tracker);")
    free_unlock = pmm_free.find("root_chunk_unlock(pmm, root_chunk);")
    alloc_lock = pmm_alloc.find("root_chunk_lock(pmm, root_chunk);")
    alloc_merge = pmm_alloc.find("uvm_tracker_add_tracker_safe(&local_tracker, &root_chunk->tracker);")
    alloc_unlock = pmm_alloc.find("root_chunk_unlock(pmm, root_chunk);", alloc_merge)

    checks = {
        "safe_merge_waits_on_source_only_after_no_memory": _check_safe_wait(tracker_source),
        "merge_retries_after_pruning_completed_entries": bool(re.search(
            r"uvm_tracker_reserve\s*\(\s*dst\s*,\s*src->size\s*\).*?"
            r"if\s*\(\s*status\s*==\s*NV_ERR_NO_MEMORY\s*\)\s*\{.*?"
            r"uvm_tracker_remove_completed\s*\(\s*dst\s*\).*?"
            r"uvm_tracker_remove_completed\s*\(\s*src\s*\).*?"
            r"reserve_for_entries_from_tracker\s*\(\s*dst\s*,\s*src\s*\)",
            tracker_add,
            re.DOTALL,
        )),
        "tracker_reserve_uses_kernel_allocation_flags": (
            "uvm_kvmalloc(sizeof(*new_entries) * new_max_size)" in reserve
            and "uvm_kvrealloc(tracker->dynamic_entries" in reserve
            and "#define NV_UVM_GFP_FLAGS (GFP_KERNEL | __GFP_NOMEMALLOC)" in linux_header
            and "kmalloc(size, NV_UVM_GFP_FLAGS)" in kvmalloc_source
        ),
        "root_chunk_lock_uses_sleepable_bitlock": (
            "uvm_bit_lock(&pmm->root_chunks.bitlocks" in root_lock
            and "uvm_bit_unlock(&pmm->root_chunks.bitlocks" in root_unlock
            and "wait_on_bit_lock(bit_locks->bits, bit, TASK_UNINTERRUPTIBLE)" in bit_lock
        ),
        "pmm_comment_warns_synchronization_may_be_long": (
            "synchronizing any pending operations might take a long" in pmm_source
            and "undesirable for that to block other operations of PMM" in pmm_source
        ),
        "pmm_free_merges_under_root_lock": (
            0 <= free_lock < free_merge < free_unlock
            and "uvm_tracker_remove_completed(tracker);" in pmm_free[:free_lock]
            and "uvm_tracker_remove_completed(&root_chunk->tracker);" in pmm_free[free_lock:free_merge]
            and "uvm_tracker_has_other_gpus" not in pmm_free[free_lock:free_merge]
            and "uvm_tracker_has_other_providers" not in pmm_free[free_lock:free_merge]
        ),
        "pmm_alloc_merges_under_root_lock_after_isolated_other_gpu_guard": (
            0 <= alloc_lock < alloc_merge < alloc_unlock
            and bool(re.search(
                r"uvm_push_isolated_gpu_execution_enabled\(\)\s*&&\s*"
                r"uvm_tracker_has_other_gpus\(&root_chunk->tracker, gpu\)",
                pmm_alloc[alloc_lock:alloc_merge],
            ))
        ),
        "block_population_cleanup_calls_pmm_free_under_block_lock": (
            "uvm_assert_mutex_locked(&block->lock);" in block_populate
            and "uvm_pmm_gpu_free(&gpu->pmm, chunk, &block->tracker);" in block_populate
        ),
        "gpu_state_teardown_calls_pmm_free_under_block_lock": (
            "uvm_assert_mutex_locked(&block->lock);" in block_destroy
            and "uvm_pmm_gpu_free(&gpu->pmm, chunk, &block->tracker);" in block_destroy
        ),
        "mmu_page_table_free_calls_pmm_free_under_tree_lock": (
            "uvm_assert_mutex_locked(&tree->lock);" in phys_deallocate
            and "uvm_pmm_gpu_free(&tree->gpu->pmm, ptr->handle.chunk, &tree->tracker);" in phys_deallocate
        ),
        "eviction_merges_after_va_block_unlock": bool(re.search(
            r"uvm_mutex_unlock\(&va_block->lock\);.*?"
            r"if\s*\(\s*status\s*==\s*NV_OK\s*\)\s*\{\s*"
            r"root_chunk_lock\(pmm, root_chunk\);\s*"
            r"status\s*=\s*uvm_tracker_add_tracker_safe\(&root_chunk->tracker, &tracker\);",
            evict,
            re.DOTALL,
        )),
        "root_chunk_return_to_pma_waits_under_root_lock": bool(re.search(
            r"root_chunk_lock\(pmm, root_chunk\);.*?"
            r"uvm_tracker_wait_deinit\(&root_chunk->tracker\);.*?"
            r"root_chunk_unlock\(pmm, root_chunk\);",
            free_root,
            re.DOTALL,
        )),
    }

    failed = sorted(key for key, value in checks.items() if not value)
    risk = checks["safe_merge_waits_on_source_only_after_no_memory"] and checks[
        "pmm_free_merges_under_root_lock"
    ] and checks["block_population_cleanup_calls_pmm_free_under_block_lock"]
    return {
        "status": "conditional-lock-held-wait-risk" if risk and not failed else "unresolved",
        "checks": checks,
        "failed_checks": failed,
        "source_sites": {
            "pmm_gpu_free_safe_merge_line": pmm_source[:pmm_source.index(
                "uvm_tracker_add_tracker_safe(&root_chunk->tracker, tracker);")].count("\n") + 1,
            "pmm_alloc_safe_merge_line": pmm_source[:pmm_source.index(
                "uvm_tracker_add_tracker_safe(&local_tracker, &root_chunk->tracker);")].count("\n") + 1,
            "root_chunk_free_wait_line": pmm_source[:pmm_source.index(
                "uvm_tracker_wait_deinit(&root_chunk->tracker);")].count("\n") + 1,
            "block_population_free_line": va_block_source[:va_block_source.index(
                "uvm_pmm_gpu_free(&gpu->pmm, chunk, &block->tracker);")].count("\n") + 1,
            "block_teardown_free_line": va_block_source[:va_block_source.rindex(
                "uvm_pmm_gpu_free(&gpu->pmm, chunk, &block->tracker);")].count("\n") + 1,
            "mmu_page_table_free_line": mmu_source[:mmu_source.index(
                "uvm_pmm_gpu_free(&tree->gpu->pmm, ptr->handle.chunk, &tree->tracker);")].count("\n") + 1,
        },
        "interpretation": (
            "When uvm_tracker_add_tracker_safe() sees NV_ERR_NO_MEMORY after the merge's "
            "reserve/prune/retry sequence, it waits for the source tracker. uvm_pmm_gpu_free() "
            "calls that helper while holding the root-chunk bitlock; source callsites include "
            "GPU-chunk cleanup under the VA-block mutex. This is a conditional latency and "
            "progress risk under allocation pressure, not a demonstrated deadlock or an observed "
            "runtime failure. The bitlock is sleepable (wait_on_bit_lock), so this audit does not "
            "classify it as a spinlock/atomic-context violation. The isolated provider guard in "
            "pmm_gpu_alloc() does not guard pmm_gpu_free(); the free path does not revalidate "
            "tracker GPU/provider identity, and same-GPU fallback waits remain possible."
        ),
        "next_falsifier": (
            "On a disposable candidate canary, inject tracker-vector allocation failure while "
            "the source tracker has a pending entry whose GPU completion needs UVM service for "
            "the same VA block. Capture lockdep and bounded completion/recovery. The pinned source "
            "has no dedicated tracker-reserve fault-injection hook; candidate activation remains "
            "blocked by the separate PC3 module/signature/device-node preflight."
        ),
    }


def audit_sources(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise ValueError("source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "candidate":
        raise ValueError("source root must be the pinned candidate/nvidia-uvm tree")

    sources = {}
    for name in SOURCE_FILES:
        path = source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source must be a regular non-symlink file: {name}")
        actual = sha256_file(path)
        if actual != EXPECTED_SHA256[name]:
            raise ValueError(f"pinned source SHA-256 mismatch for {name}: {actual}")
        sources[name] = {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": actual,
            "bytes": path.stat().st_size,
        }

    return {
        "schema": "nvidia-r595-pmm-tracker-wait-context-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {"source_root": source_root.relative_to(ROOT).as_posix(), "files": sources},
        "result": analyze_sources(source_root),
    }


def write_json(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root)
        if args.output:
            write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    return 0 if report["result"]["status"] == "conditional-lock-held-wait-risk" else 1


if __name__ == "__main__":
    raise SystemExit(main())
