#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit R580 isolated-UVM semaphore ownership, CPU visibility, waits and teardown.

This is hash-pinned source analysis. It does not establish DMA/cache coherence,
module runtime behavior, CUDA execution, or cross-provider hardware operation.
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

SOURCE_TAG = "580.178.04"
SOURCE_ROOT = (
    ROOT / "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
SOURCE_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
PATCH = ROOT / "patches/r580.178.04/uvm/0002-hybrid-isolated-gpu-execution.patch"
EXPECTED_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
EXPECTED_PATCH_SHA256 = "23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0"
SOURCE_FILES = (
    "uvm_gpu.c",
    "uvm_gpu_semaphore.c",
    "uvm_rm_mem.c",
    "uvm_tracker.c",
    "uvm_channel.c",
)
EXPECTED_SOURCE_SHA256 = {
    "uvm_gpu.c": "23bb5a514a99b1c747e683ddd3612511647cc3e95745ccdc1b1e22db3d584197",
    "uvm_gpu_semaphore.c": "4224b4f808c9f86279cb97bfa9645e6b592ace4b2f4213e81848d1ebba4258a3",
    "uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
    "uvm_tracker.c": "756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41",
    "uvm_channel.c": "64fcdb55ecba388c8ed6c656ca72b60f2b6f4b8bc0ebaffd794ed1e78068a248",
}
EXPECTED_CHECKS = (
    "system_aperture",
    "isolated_page_cpu_and_owner_mapping",
    "owner_mapping_recorded_in_rm_state",
    "cross_gpu_mapping_skipped_and_teardown_guarded",
    "cpu_wait_observes_owner_tracking_semaphore",
    "free_unmaps_cpu_and_owner_gpu",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _function(root: Path, file_name: str, function_name: str) -> str:
    path = Path(root) / file_name
    try:
        return c_function_definition(path, function_name)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract {file_name}:{function_name}: {exc}") from None


def _has(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None


def analyze_sources(source_root: Path) -> dict[str, Any]:
    """Check the local source-shape invariants; tests use this for mutations."""
    source_root = Path(source_root)
    checks: dict[str, bool] = {}

    pool_create = _function(source_root, "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_pool_create")
    checks["system_aperture"] = _has(pool_create, r"pool->aperture\s*=\s*UVM_APERTURE_SYS\s*;")

    page_alloc = _function(source_root, "uvm_gpu_semaphore.c", "pool_page_alloc_buffers")
    checks["isolated_page_cpu_and_owner_mapping"] = all(
        (
            _has(
                page_alloc,
                r"memory_type\s*=\s*\(pool->aperture\s*==\s*UVM_APERTURE_SYS\)\s*\?\s*"
                r"UVM_RM_MEM_TYPE_SYS\s*:\s*UVM_RM_MEM_TYPE_GPU",
            ),
            _has(
                page_alloc,
                r"if\s*\(\s*!g_uvm_global\.conf_computing_enabled\s*&&\s*"
                r"!uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\)\s*"
                r"return\s+uvm_rm_mem_alloc_and_map_cpu\s*\(\s*gpu\s*,\s*memory_type\s*,",
            ),
            _has(page_alloc, r"return\s+uvm_rm_mem_alloc_and_map_all\s*\("),
        )
    )

    rm_alloc = _function(source_root, "uvm_rm_mem.c", "uvm_rm_mem_alloc")
    set_gpu_va = _function(source_root, "uvm_rm_mem.c", "rm_mem_set_gpu_va")
    alloc_cpu = _function(source_root, "uvm_rm_mem.c", "uvm_rm_mem_alloc_and_map_cpu")
    map_cpu = _function(source_root, "uvm_rm_mem.c", "uvm_rm_mem_map_cpu")
    checks["owner_mapping_recorded_in_rm_state"] = all(
        (
            _has(
                rm_alloc,
                r"rm_mem->gpu_owner\s*=\s*gpu\s*;.*?rm_mem_set_gpu_va\s*\(\s*rm_mem\s*,\s*gpu\s*,\s*gpu_va\s*\)",
            ),
            _has(set_gpu_va, r"rm_mem->vas\s*\[.*?\]\s*=\s*va\s*;.*?uvm_processor_mask_set\s*\(\s*&rm_mem->mapped_on\s*,\s*gpu->id\s*\)"),
            _has(
                alloc_cpu,
                r"uvm_rm_mem_alloc\s*\(\s*gpu\s*,\s*type\s*,\s*size\s*,\s*gpu_alignment\s*,\s*&rm_mem\s*\).*?"
                r"uvm_rm_mem_map_cpu\s*\(\s*rm_mem\s*\)",
            ),
            _has(
                map_cpu,
                r"gpu\s*=\s*rm_mem->gpu_owner\s*;.*?nvUvmInterfaceMemoryCpuMap\s*\(.*?"
                r"rm_mem_set_cpu_va\s*\(\s*rm_mem\s*,\s*cpu_va\s*\)",
            ),
        )
    )

    init_pools = _function(source_root, "uvm_gpu.c", "init_semaphore_pools")
    deinit_pools = _function(source_root, "uvm_gpu.c", "deinit_semaphore_pools")
    checks["cross_gpu_mapping_skipped_and_teardown_guarded"] = all(
        (
            _has(
                init_pools,
                r"if\s*\(\s*!uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\)\s*"
                r"return\s+NV_OK\s*;.*?for_each_gpu\s*\(\s*other_gpu\s*\).*?"
                r"uvm_gpu_semaphore_pool_map_gpu\s*\(\s*other_gpu->semaphore_pool\s*,\s*gpu\s*\)",
            ),
            _has(
                deinit_pools,
                r"if\s*\(\s*g_uvm_global\.conf_computing_enabled\s*\|\|\s*"
                r"uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\)\s*\{.*?"
                r"uvm_gpu_semaphore_pool_unmap_gpu\s*\(\s*other_gpu->semaphore_pool\s*,\s*gpu\s*\)",
            ),
        )
    )

    tracker = _function(source_root, "uvm_tracker.c", "uvm_tracker_wait_for_other_gpus")
    wait_entry = _function(source_root, "uvm_tracker.c", "wait_for_entry_with_spin")
    entry_completed = _function(source_root, "uvm_tracker.c", "uvm_tracker_is_entry_completed")
    channel_completed = _function(source_root, "uvm_channel.c", "uvm_channel_is_value_completed")
    sem_completed = _function(source_root, "uvm_gpu_semaphore.c", "uvm_gpu_tracking_semaphore_is_value_completed")
    sem_update = _function(source_root, "uvm_gpu_semaphore.c", "update_completed_value_locked")
    sem_get_payload = _function(source_root, "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_get_payload")
    sem_get_cpu_va = _function(source_root, "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_get_cpu_va")
    checks["cpu_wait_observes_owner_tracking_semaphore"] = all(
        (
            _has(
                tracker,
                r"uvm_tracker_entry_gpu\s*\(\s*entry\s*\)\s*==\s*gpu.*?"
                r"wait_for_entry_with_spin\s*\(\s*entry\s*,\s*&spin\s*\)",
            ),
            _has(wait_entry, r"uvm_tracker_is_entry_completed\s*\(\s*tracker_entry\s*\).*?uvm_channel_check_errors\s*\(\s*tracker_entry->channel\s*\).*?uvm_global_get_status\s*\(\s*\)"),
            _has(entry_completed, r"uvm_channel_is_value_completed\s*\(\s*tracker_entry->channel\s*,\s*tracker_entry->value\s*\)"),
            _has(channel_completed, r"uvm_gpu_tracking_semaphore_is_value_completed\s*\(\s*&channel->tracking_sem\s*,\s*value\s*\)"),
            _has(sem_completed, r"uvm_gpu_tracking_semaphore_update_completed_value\s*\(\s*tracking_sem\s*\)\s*>=\s*value"),
            _has(sem_update, r"uvm_gpu_semaphore_get_payload\s*\(\s*&tracking_semaphore->semaphore\s*\)"),
            _has(sem_get_payload, r"UVM_GPU_READ_ONCE\s*\(\s*\*uvm_gpu_semaphore_get_cpu_va\s*\(\s*semaphore\s*\)\s*\)"),
            _has(sem_get_cpu_va, r"uvm_rm_mem_get_cpu_va\s*\(\s*semaphore->page->memory\s*\)"),
        )
    )

    page_free = _function(source_root, "uvm_gpu_semaphore.c", "pool_page_free_buffers")
    pool_free = _function(source_root, "uvm_gpu_semaphore.c", "pool_free_page")
    rm_free = _function(source_root, "uvm_rm_mem.c", "uvm_rm_mem_free")
    checks["free_unmaps_cpu_and_owner_gpu"] = all(
        (
            _has(page_free, r"uvm_rm_mem_free\s*\(\s*page->memory\s*\)"),
            _has(pool_free, r"pool_page_free_buffers\s*\(\s*page\s*\)"),
            _has(
                rm_free,
                r"uvm_rm_mem_unmap_cpu\s*\(\s*rm_mem\s*\).*?"
                r"if\s*\(!uvm_id_equal\s*\(\s*gpu_id\s*,\s*gpu_owner->id\s*\)\).*?"
                r"rm_mem_unmap_gpu\s*\(\s*rm_mem\s*,\s*gpu_owner\s*\).*?"
                r"uvm_processor_mask_empty\s*\(\s*&rm_mem->mapped_on\s*\)",
            ),
        )
    )

    failed = sorted(name for name, passed in checks.items() if not passed)
    return {"status": "pass" if not failed else "fail", "checks": checks, "failed_checks": failed}


def audit_sources(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise ValueError("UVM source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be the R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source tree is not NVIDIA R580.178.04")

    archive = SOURCE_ARCHIVE.resolve(strict=True)
    patch = PATCH.resolve(strict=True)
    archive_sha = sha256_file(archive)
    patch_sha = sha256_file(patch)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 archive SHA-256 mismatch")
    if patch_sha != EXPECTED_PATCH_SHA256:
        raise ValueError("isolated-UVM patch SHA-256 mismatch")

    files = {}
    for name, expected in EXPECTED_SOURCE_SHA256.items():
        path = source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source must be a regular non-symlink file: {name}")
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"pinned source SHA-256 mismatch for {name}: {actual}")
        files[name] = {"path": project_path(path), "sha256": actual, "bytes": path.stat().st_size}

    result = analyze_sources(source_root)
    return {
        "schema": "nvidia-r580-uvm-semaphore-owner-contract-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {
            "source_archive": {"path": project_path(archive), "sha256": archive_sha},
            "patch": {"path": project_path(patch), "sha256": patch_sha},
            "source_files": files,
        },
        "result": result,
        "interpretation": (
            "The pinned R580 source allocates each normal semaphore page in system aperture, "
            "records the owner GPU mapping, maps the page for CPU observation, and in isolated "
            "mode skips cross-GPU mappings while tracker waits poll the owner semaphore. Source "
            "also frees the CPU and owner mappings. This does not prove PCIe visibility/cache "
            "coherence on a given topology or any runtime/hardware behavior."
        ),
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
    return 0 if report["result"]["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
