#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the R580 UVM source path that blocks the current mixed-provider bridge.

This is a narrow static source audit. It does not load a module, initialize a
GPU, prove DMA/coherence behavior, or qualify the hybrid driver on hardware.
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
    ROOT / "build/experiments/private-open580-native-v4-softdep-v1-20261023"
    / "private/NVIDIA-kernel-module-source-580.178.04/kernel-open"
)
SOURCE_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
EXPECTED_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
ROUTE_PATH = ROOT / "src/hybrid580_uvm_address_space_route.h"
BRIDGE_PATH = ROOT / "src/hybrid580_uvm_callback_bridge.c"
EXPECTED_SOURCE_SHA256 = {
    "uvm_gpu.c": "b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700",
    "uvm_gpu_semaphore.c": "1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f",
    "uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
    "uvm_channel.c": "64fcdb55ecba388c8ed6c656ca72b60f2b6f4b8bc0ebaffd794ed1e78068a248",
    "hybrid580_uvm_address_space_route.h": "741ef4746d8a9b3d80e7d7eaf1fcc0c801728b001849b90d9ecab36ce2552882",
    "hybrid580_uvm_callback_bridge.c": "c581cda76752f4dd4b903442309b5944dd2ff6eb9dd702c6dc4d91345aca86c5",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _source_file(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"{label}: expected a regular non-symlink source file")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"{label}: expected a regular non-symlink source file")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ValueError(
            f"pinned source SHA-256 mismatch for {label}: {actual}"
        )
    return {"path": project_path(path), "sha256": actual, "bytes": path.stat().st_size}


def _function(path: Path, symbol: str) -> str:
    try:
        return c_function_definition(path, symbol)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract pinned function {symbol} from {path}: {exc}") from None


def _require(text: str, pattern: str, description: str, *, flags: int = 0) -> None:
    if re.search(pattern, text, flags) is None:
        raise ValueError("pinned source contract changed: " + description)


def _ordered(text: str, patterns: list[str], description: str) -> None:
    cursor = 0
    for pattern in patterns:
        match = re.search(pattern, text[cursor:])
        if match is None:
            raise ValueError("pinned source order changed: " + description)
        cursor += match.end()


def classify_dup_allocation_route(function_source: str) -> str:
    """Recognize only the known cross-provider fail-closed route."""
    if re.search(
        r"if\s*\(\s*src_provider\s*!=\s*dst_provider\s*\)\s*"
        r"return\s+not_supported_status\s*;",
        function_source,
    ) is None:
        raise ValueError("unrecognized DupAllocation route; do not infer compatibility")

    reject = function_source.index("src_provider != dst_provider")
    dispatch = function_source.find("selected->duplicate", reject)
    if dispatch < 0 or dispatch < reject:
        raise ValueError("cross-provider rejection is not proven to precede RM dispatch")
    return "cross_provider_rejected_before_backend_call"


def audit_sources(source_root: Path, route_path: Path) -> dict[str, Any]:
    source_root = Path(source_root)
    route_path = Path(route_path)
    if source_root.is_symlink() or route_path.is_symlink():
        raise ValueError("source root and route header must not be symlinks")
    source_root = source_root.resolve(strict=True)
    route_path = route_path.resolve(strict=True)
    bridge_path = route_path.with_name("hybrid580_uvm_callback_bridge.c").resolve(strict=True)
    archive = SOURCE_ARCHIVE.resolve(strict=True)

    if source_root.name != "kernel-open":
        raise ValueError("source root must be the pinned R580 kernel-open tree")
    if source_root.parent.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source root is not NVIDIA R580.178.04")
    archive_hash = sha256_file(archive)
    if archive_hash != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 source archive SHA-256 mismatch")

    paths = {
        "uvm_gpu.c": source_root / "nvidia-uvm/uvm_gpu.c",
        "uvm_gpu_semaphore.c": source_root / "nvidia-uvm/uvm_gpu_semaphore.c",
        "uvm_rm_mem.c": source_root / "nvidia-uvm/uvm_rm_mem.c",
        "uvm_channel.c": source_root / "nvidia-uvm/uvm_channel.c",
        "hybrid580_uvm_address_space_route.h": route_path,
        "hybrid580_uvm_callback_bridge.c": bridge_path,
    }
    files = {
        label: _source_file(path, EXPECTED_SOURCE_SHA256[label], label)
        for label, path in paths.items()
    }

    functions = {
        "gpu": {
            name: _function(paths["uvm_gpu.c"], name)
            for name in ("init_semaphore_pools", "init_gpu", "add_gpu")
        },
        "semaphore": {
            name: _function(paths["uvm_gpu_semaphore.c"], name)
            for name in (
                "uvm_gpu_semaphore_pool_create",
                "pool_page_alloc_buffers",
                "uvm_gpu_semaphore_pool_map_gpu",
                "uvm_gpu_semaphore_alloc",
                "pool_alloc_page",
                "uvm_gpu_tracking_semaphore_alloc",
            )
        },
        "rm_memory": {
            "uvm_rm_mem_map_gpu": _function(paths["uvm_rm_mem.c"], "uvm_rm_mem_map_gpu"),
        },
        "channel": {
            name: _function(paths["uvm_channel.c"], name)
            for name in (
                "uvm_channel_manager_create",
                "channel_manager_create_pools",
                "channel_manager_pick_ces",
                "pick_ces",
                "pick_ces_for_channel_types",
                "channel_manager_num_channels",
                "channel_manager_create_ce_pools",
                "channel_pool_add",
                "channel_create",
            )
        },
        "route": {
            "hybrid580_uvm_address_space_route_dup_allocation": _function(
                route_path, "hybrid580_uvm_address_space_route_dup_allocation"
            ),
            "nvUvmInterfaceDupAllocation": _function(
                bridge_path, "nvUvmInterfaceDupAllocation"
            ),
        },
    }

    sem_init = functions["gpu"]["init_semaphore_pools"]
    _ordered(
        sem_init,
        [
            r"uvm_gpu_semaphore_pool_create\s*\(",
            r"if\s*\(\s*g_uvm_global\.conf_computing_enabled\s*\)",
            r"for_each_gpu\s*\(\s*other_gpu\s*\)",
            r"if\s*\(\s*other_gpu\s*==\s*gpu\s*\)",
            r"uvm_gpu_semaphore_pool_map_gpu\s*\(\s*other_gpu->semaphore_pool\s*,\s*gpu\s*\)",
            r"if\s*\(\s*status\s*!=\s*NV_OK\s*\)\s*return\s+status\s*;",
        ],
        "non-CC semaphore-pool mapping/failure path",
    )

    gpu_init = functions["gpu"]["init_gpu"]
    _ordered(
        gpu_init,
        [
            r"status\s*=\s*init_semaphore_pools\s*\(\s*gpu\s*\)",
            r"if\s*\(\s*status\s*!=\s*NV_OK\s*\)",
            r"return\s+status\s*;",
            r"uvm_channel_manager_create\s*\(",
        ],
        "GPU init must abort on semaphore-pool mapping failure before channel setup",
    )

    _ordered(
        functions["gpu"]["add_gpu"],
        [
            r"status\s*=\s*init_gpu\s*\(\s*gpu\s*,\s*gpu_info\s*\)",
            r"if\s*\(\s*status\s*!=\s*NV_OK\s*\)\s*goto\s+error\s*;",
            r"__set_bit\s*\(\s*uvm_id_sub_processor_index\(gpu->id\)\s*,\s*parent_gpu->valid_gpus\s*\)",
            r"peers_discover_nvlink\s*\(\s*gpu\s*\)",
        ],
        "GPU registration must reject failed init before publishing the GPU or discovering peers",
    )

    _require(
        functions["semaphore"]["uvm_gpu_semaphore_pool_create"],
        r"pool->aperture\s*=\s*UVM_APERTURE_SYS",
        "ordinary semaphore pools use system-memory aperture",
    )
    _ordered(
        functions["semaphore"]["pool_page_alloc_buffers"],
        [
            r"pool->aperture\s*==\s*UVM_APERTURE_SYS",
            r"UVM_RM_MEM_TYPE_SYS",
            r"uvm_rm_mem_alloc_and_map_all\s*\(\s*gpu\s*,\s*memory_type\s*,",
        ],
        "ordinary semaphore pages are system memory mapped on their owner GPU",
    )

    pool_map = functions["semaphore"]["uvm_gpu_semaphore_pool_map_gpu"]
    _ordered(
        pool_map,
        [
            r"list_for_each_entry\s*\(\s*page\s*,\s*&pool->pages\s*,\s*all_pages_node\s*\)",
            r"uvm_rm_mem_map_gpu\s*\(\s*page->memory\s*,\s*gpu\s*,\s*0\s*\)",
            r"if\s*\(\s*status\s*!=\s*NV_OK\s*\)\s*goto\s+done\s*;",
            r"return\s+status\s*;",
        ],
        "all existing semaphore pages must be mapped and errors propagated",
    )

    rm_map = functions["rm_memory"]["uvm_rm_mem_map_gpu"]
    _ordered(
        rm_map,
        [
            r"gpu_owner\s*=\s*rm_mem->gpu_owner\s*;",
            r"nvUvmInterfaceDupAllocation\s*\(\s*gpu_owner->rm_address_space\s*,",
            r"gpu->rm_address_space\s*,",
            r"if\s*\(\s*status\s*!=\s*NV_OK\s*\)",
            r"return\s+status\s*;",
        ],
        "sysmem map must duplicate from owner RM VA space into target RM VA space",
    )

    channel = functions["channel"]
    _require(channel["uvm_channel_manager_create"], r"channel_manager_create_pools\s*\(",
             "GPU initialization creates its channel pools")
    _ordered(channel["channel_manager_create_pools"],
             [r"channel_manager_pick_ces\s*\(", r"channel_manager_create_ce_pools\s*\("],
             "ordinary mode creates copy-engine channel pools")
    _require(channel["channel_manager_pick_ces"],
             r"nvUvmInterfaceQueryCopyEnginesCaps\s*\(",
             "copy-engine capabilities are queried during initialization")
    _require(channel["channel_manager_pick_ces"], r"pick_ces\s*\(",
             "ordinary mode selects copy engines")
    _require(channel["pick_ces"], r"pick_ces_for_channel_types\s*\(",
             "copy-engine selection populates the usable engine mask")
    _ordered(channel["pick_ces_for_channel_types"],
             [r"UVM_ASSERT\s*\(\s*best_ce\s*!=\s*UVM_COPY_ENGINE_COUNT_MAX\s*\)",
              r"__set_bit\s*\(\s*best_ce\s*,\s*manager->ce_mask\s*\)"],
             "selected copy engines enter the channel-pool mask")
    _require(channel["channel_manager_create_ce_pools"], r"for_each_set_bit\s*\(",
             "usable copy engines produce channel pools")
    _require(channel["channel_manager_create_ce_pools"], r"channel_pool_add\s*\(",
             "copy-engine pools are allocated during GPU initialization")
    _ordered(channel["channel_manager_num_channels"],
             [r"channel_pool_type_ce_num_channels\s*=\s*2",
              r"num_channels\s*=\s*channel_pool_type_ce_num_channels"],
             "each usable copy-engine pool receives two channels")
    _ordered(channel["channel_pool_add"],
             [r"channel_manager_num_channels\s*\(", r"i\s*<\s*num_channels",
              r"channel_create\s*\(\s*pool\s*,\s*channel\s*\)"],
             "each initialized channel allocates its tracking semaphore")
    _require(channel["channel_create"], r"uvm_gpu_tracking_semaphore_alloc\s*\(",
             "channel creation allocates a tracking semaphore")
    _require(functions["semaphore"]["uvm_gpu_tracking_semaphore_alloc"],
             r"uvm_gpu_semaphore_alloc\s*\(",
             "tracking semaphore allocation reaches the pool allocator")
    _require(functions["semaphore"]["uvm_gpu_semaphore_alloc"],
             r"pool->free_semaphores_count\s*==\s*0", "empty semaphore pools allocate a page")
    _require(functions["semaphore"]["uvm_gpu_semaphore_alloc"],
             r"pool_alloc_page\s*\(\s*pool\s*\)", "empty semaphore pools allocate a page")
    _require(functions["semaphore"]["pool_alloc_page"],
             r"list_add\s*\(\s*&pool_page->all_pages_node\s*,\s*&pool->pages\s*\)",
             "allocated semaphore page becomes visible to the next GPU")

    route = functions["route"]["hybrid580_uvm_address_space_route_dup_allocation"]
    route_result = classify_dup_allocation_route(route)
    _require(functions["route"]["nvUvmInterfaceDupAllocation"],
             r"hybrid580_uvm_address_space_route_dup_allocation\s*\(",
             "public UVM callback uses the audited route")
    _require(functions["route"]["nvUvmInterfaceDupAllocation"],
             r"NV_ERR_NOT_SUPPORTED", "cross-provider rejection maps to NV_ERR_NOT_SUPPORTED")

    function_hashes = {
        group: {
            name: hashlib.sha256(body.encode("utf-8")).hexdigest()
            for name, body in entries.items()
        }
        for group, entries in functions.items()
    }
    return {
        "schema": "nvidia-r580-uvm-cross-provider-static-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "runtime_validated": False,
            "hardware_validated": False,
            "module_loaded_or_installed": False,
        },
        "source_archive": {
            "path": project_path(archive),
            "sha256": archive_hash,
        },
        "source_files": files,
        "function_sha256": function_hashes,
        "result": {
            "cross_provider_admission": "blocked",
            "blocker": "cross_provider_dup_allocation",
            "path": route_result,
            "condition": (
                "non-Confidential-Computing UVM mode, with a previously initialized GPU "
                "that reports at least one usable copy engine"
            ),
            "existing_gpu_pool_page_precedes_second_gpu": True,
            "initialization_failure_propagates": True,
            "p2p_none_cannot_bypass_gpu_admission": True,
            "required_missing_contract": (
                "map the same system-memory semaphore allocation from one RM provider's "
                "VA space into the other provider's VA space with coherent cross-GPU use"
            ),
        },
        "interpretation": (
            "For the pinned source and current bridge, a second GPU owned by the other "
            "RM provider cannot complete UVM GPU initialization in this mode. This is "
            "a static control-flow result; it does not establish a runtime failure or "
            "prove that a cross-provider mapping implementation is impossible."
        ),
    }


def write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--route-header", type=Path, default=ROUTE_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root, args.route_header)
        if args.output:
            write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
