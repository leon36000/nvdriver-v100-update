#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trace the pinned R595 UVM system-semaphore path across RM providers.

This is a fail-closed source audit. It identifies a conditional initialization
blocker; it does not run a kernel module, RM operation, or GPU test.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_volta_uvm_port import (  # noqa: E402
    _mask_c_comments,
    _matching_c_brace,
)

DEFAULT_R595_UVM = ROOT / "build/experiments/r595-gv100-hal-rmfd-v1-20261028T180300Z/nvidia-uvm"
DEFAULT_FRONTEND_ROUTE = ROOT / "src/hybrid580_uvm_address_space_route.h"

PINNED_HASHES = {
    "uvm_gpu.c": "66881c4ae46461314d41342b2a27df9119d68d68f90d181e3a32670dcc19f590",
    "uvm_gpu_semaphore.c": "1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f",
    "uvm_channel.c": "34a6816a77e55515179607558c4ddae65a8ae2bb591bc6e481a918370d1bc675",
    "uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
}
FRONTEND_ROUTE_SHA256 = "741ef4746d8a9b3d80e7d7eaf1fcc0c801728b001849b90d9ecab36ce2552882"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_function(source: str, name: str) -> tuple[str, int]:
    masked = _mask_c_comments(source)
    pattern = re.compile(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{")
    matches = list(pattern.finditer(masked))
    if len(matches) != 1:
        raise ValueError(f"expected one definition of {name}, found {len(matches)}")
    match = matches[0]
    opening = match.end() - 1
    closing = _matching_c_brace(source, opening)
    return source[opening + 1:closing], masked.count("\n", 0, match.start()) + 1


def _require(body: str, function: str, *tokens: str) -> None:
    missing = [token for token in tokens if token not in body]
    if missing:
        raise ValueError(f"source contract failed in {function}: missing {missing}")


def _require_before(body: str, function: str, first: str, second: str) -> None:
    first_at = body.find(first)
    second_at = body.find(second)
    if first_at < 0 or second_at < 0 or first_at >= second_at:
        raise ValueError(f"source contract failed in {function}: expected {first!r} before {second!r}")


def audit_sources(r595_uvm_root: Path, frontend_route: Path) -> dict:
    r595_uvm_root = r595_uvm_root.resolve(strict=True)
    frontend_route = frontend_route.resolve(strict=True)
    sources: dict[str, str] = {}
    rows: dict[str, dict] = {}
    for name, expected_hash in PINNED_HASHES.items():
        path = r595_uvm_root / name
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            raise ValueError(f"source hash mismatch for {path}: expected {expected_hash}, got {actual_hash}")
        sources[name] = path.read_text(encoding="utf-8")
        rows[name] = {"path": str(path), "sha256": actual_hash}

    frontend_hash = sha256_file(frontend_route)
    if frontend_hash != FRONTEND_ROUTE_SHA256:
        raise ValueError(
            f"source hash mismatch for {frontend_route}: expected {FRONTEND_ROUTE_SHA256}, got {frontend_hash}"
        )
    rows["hybrid_frontend_route"] = {"path": str(frontend_route), "sha256": frontend_hash}

    functions: dict[str, tuple[str, int, str]] = {}
    for name, function_names in {
        "uvm_gpu.c": ("init_gpu", "init_semaphore_pools"),
        "uvm_gpu_semaphore.c": (
            "uvm_gpu_semaphore_pool_create", "pool_page_alloc_buffers", "pool_alloc_page",
            "uvm_gpu_semaphore_pool_map_gpu", "uvm_gpu_semaphore_alloc",
            "uvm_gpu_tracking_semaphore_alloc",
        ),
        "uvm_channel.c": (
            "channel_manager_num_channels", "channel_pool_add", "channel_create",
            "channel_manager_create_ce_pools", "channel_manager_create_pools",
            "uvm_channel_manager_create",
        ),
        "uvm_rm_mem.c": (
            "uvm_rm_mem_alloc_and_map_all", "uvm_rm_mem_map_all_gpus", "uvm_rm_mem_map_gpu",
        ),
    }.items():
        for function_name in function_names:
            body, line = extract_function(sources[name], function_name)
            functions[function_name] = (body, line, name)

    route_body, route_line = extract_function(
        frontend_route.read_text(encoding="utf-8"),
        "hybrid580_uvm_address_space_route_dup_allocation",
    )
    functions["hybrid580_uvm_address_space_route_dup_allocation"] = (
        route_body, route_line, "hybrid_frontend_route"
    )

    body, _, _ = functions["init_gpu"]
    _require(body, "init_gpu", "init_semaphore_pools(gpu)", "uvm_channel_manager_create(gpu, &gpu->channel_manager)")
    _require_before(body, "init_gpu", "init_semaphore_pools(gpu)", "uvm_channel_manager_create(gpu, &gpu->channel_manager)")
    _require(body, "init_gpu", "if (status != NV_OK)", "return status;")

    body, _, _ = functions["init_semaphore_pools"]
    _require(body, "init_semaphore_pools", "uvm_gpu_semaphore_pool_create(gpu", "for_each_gpu(other_gpu)",
             "uvm_gpu_semaphore_pool_map_gpu(other_gpu->semaphore_pool, gpu)", "if (status != NV_OK)", "return status;")
    body, _, _ = functions["uvm_gpu_semaphore_pool_create"]
    _require(body, "uvm_gpu_semaphore_pool_create", "pool->aperture = UVM_APERTURE_SYS;")
    body, _, _ = functions["pool_page_alloc_buffers"]
    _require(body, "pool_page_alloc_buffers", "uvm_rm_mem_alloc_and_map_all(gpu, memory_type")
    body, _, _ = functions["pool_alloc_page"]
    _require(body, "pool_alloc_page", "pool_page_alloc_buffers(pool_page)")
    body, _, _ = functions["uvm_gpu_semaphore_pool_map_gpu"]
    _require(body, "uvm_gpu_semaphore_pool_map_gpu", "uvm_rm_mem_map_gpu(page->memory, gpu, 0)")
    body, _, _ = functions["uvm_gpu_semaphore_alloc"]
    _require(body, "uvm_gpu_semaphore_alloc", "pool->free_semaphores_count == 0", "pool_alloc_page(pool)")
    _require_before(body, "uvm_gpu_semaphore_alloc", "pool->free_semaphores_count == 0", "pool_alloc_page(pool)")
    body, _, _ = functions["uvm_gpu_tracking_semaphore_alloc"]
    _require(body, "uvm_gpu_tracking_semaphore_alloc", "uvm_gpu_semaphore_alloc(pool, &tracking_sem->semaphore)")

    body, _, _ = functions["uvm_channel_manager_create"]
    _require(body, "uvm_channel_manager_create", "channel_manager_create_pools(channel_manager)")
    body, _, _ = functions["channel_manager_create_pools"]
    _require(body, "channel_manager_create_pools", "channel_manager_create_ce_pools(manager, preferred_ce)")
    body, _, _ = functions["channel_manager_create_ce_pools"]
    _require(body, "channel_manager_create_ce_pools", "for_each_set_bit(ce, manager->ce_mask", "channel_pool_add(manager")
    body, _, _ = functions["channel_manager_num_channels"]
    _require(body, "channel_manager_num_channels", "channel_pool_type_ce_num_channels = 2", "num_channels = channel_pool_type_ce_num_channels")
    body, _, _ = functions["channel_pool_add"]
    _require(body, "channel_pool_add", "for (i = 0; i < num_channels; i++)", "channel_create(pool, channel)", "channel_init(channel)")
    body, _, _ = functions["channel_create"]
    _require(body, "channel_create", "uvm_gpu_tracking_semaphore_alloc(semaphore_pool, &channel->tracking_sem)")

    body, _, _ = functions["uvm_rm_mem_alloc_and_map_all"]
    _require(body, "uvm_rm_mem_alloc_and_map_all", "uvm_rm_mem_alloc_and_map_cpu", "uvm_rm_mem_map_all_gpus(rm_mem, gpu_alignment)")
    body, _, _ = functions["uvm_rm_mem_map_all_gpus"]
    _require(body, "uvm_rm_mem_map_all_gpus", "for_each_gpu(gpu)", "uvm_rm_mem_map_gpu(rm_mem, gpu, gpu_alignment)")
    body, _, _ = functions["uvm_rm_mem_map_gpu"]
    _require(body, "uvm_rm_mem_map_gpu", "gpu_owner = rm_mem->gpu_owner", "gpu_owner->rm_address_space",
             "gpu->rm_address_space", "nvUvmInterfaceDupAllocation(", "if (status != NV_OK)", "return status;")
    body, _, _ = functions["hybrid580_uvm_address_space_route_dup_allocation"]
    _require(body, "hybrid580_uvm_address_space_route_dup_allocation", "if (src_provider != dst_provider)",
             "return not_supported_status;", "selected->duplicate(")
    _require_before(body, "hybrid580_uvm_address_space_route_dup_allocation",
                    "if (src_provider != dst_provider)", "selected->duplicate(")

    evidence = []
    for function_name, (_, line, source_name) in functions.items():
        evidence.append({"source": source_name, "function": function_name, "line": line})

    return {
        "schema": "r595-cross-provider-semaphore-init-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "analyzed-statically",
        "result": "conditional_cross_provider_gpu_registration_blocker",
        "candidate": {
            "branch": "R595.99.02 Open UVM with the pinned RM-control-FD patch source",
            "source_root": str(r595_uvm_root),
            "frontend_route": str(frontend_route),
            "source_hashes": rows,
        },
        "claims": {
            "first_gpu_eagerly_allocates_sysmem_semaphore_pages": True,
            "second_gpu_maps_existing_pool_before_channel_manager": True,
            "mapping_requires_dup_allocation_between_owner_and_target_address_spaces": True,
            "provider_mismatch_stops_before_backend_dispatch": True,
        },
        "failure_path": [
            "A GPU with at least one usable copy engine creates two channels in each common CE pool during UVM GPU initialization.",
            "Each channel eagerly allocates a tracking semaphore; the initially empty system-memory pool therefore allocates a page and maps it to currently registered GPUs.",
            "When a GPU from another backend registers, init_semaphore_pools maps the existing GPU's semaphore pages before creating the new channel manager.",
            "That map calls DupAllocation with the owning and target GPUs' RM address spaces; the hybrid route returns NOT_SUPPORTED for different providers without an RM call.",
            "init_gpu propagates the map error, so static source predicts rejection of the second provider GPU at this point, conditional on the cited channel/page path being exercised.",
        ],
        "evidence": evidence,
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "not_proven": [
            "No candidate module was loaded or installed.",
            "No mixed-provider UVM registration was attempted on a live kernel.",
            "The audit does not establish behavior for every GPU capability or configuration.",
            "CUDA contexts, kernels, UVM migration, P2P, and same-process hybrid execution remain unvalidated.",
        ],
        "next_experiment": "Design provider-aware UVM system-memory semaphore allocation/mapping semantics, then compile and test that policy in isolation before any canary activation.",
    }


def _write_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r595-uvm-root", type=Path, default=DEFAULT_R595_UVM)
    parser.add_argument("--frontend-route", type=Path, default=DEFAULT_FRONTEND_ROUTE)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = audit_sources(args.r595_uvm_root, args.frontend_route)
    except (OSError, ValueError) as exc:
        print(f"audit rejected input: {exc}", file=sys.stderr)
        return 2
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    if args.report is not None:
        report_path = args.report if args.report.is_absolute() else ROOT / args.report
        _write_private(report_path, encoded)
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
