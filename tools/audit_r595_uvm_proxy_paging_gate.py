#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove the pinned R595 UVM paging-channel callbacks are SR-IOV-heavy-only.

This is a source-contract audit, not a runtime or GPU test. It pins the UVM
files from both R595 source drops used in the branch comparison and the current
hybrid callback bridge, then checks the call path from pool creation through
allocate, use, and destroy.
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


BRANCHES = {
    "595.99.02": {
        "commit": "e394a404108a9ce5bba988c1dddf694dabbd4a43",
        "source_root": ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm",
        "files": {
            "uvm_channel.c": "34a6816a77e55515179607558c4ddae65a8ae2bb591bc6e481a918370d1bc675",
            "uvm_gpu.h": "76c578d204b32499e0004d1f1f43f9a1ce6718be13faa1394a5a63d0d1c7f9b5",
            "uvm_channel.h": "1e2c72f5c00fd632f99b2d51aa7f88513f4a00c2dab3cf2a03e703487a5df4ac",
            "uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
        },
    },
    "595.112.07": {
        "commit": "d8257d95ae5fed364163e4df51db66df8b1ee0d2",
        "source_root": ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/kernel-open/nvidia-uvm",
        "files": {
            "uvm_channel.c": "34a6816a77e55515179607558c4ddae65a8ae2bb591bc6e481a918370d1bc675",
            "uvm_gpu.h": "76c578d204b32499e0004d1f1f43f9a1ce6718be13faa1394a5a63d0d1c7f9b5",
            "uvm_channel.h": "1e2c72f5c00fd632f99b2d51aa7f88513f4a00c2dab3cf2a03e703487a5df4ac",
            "uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
        },
    },
}
BRIDGE = ROOT / "src/hybrid580_uvm_callback_bridge.c"
BRIDGE_SHA256 = "c581cda76752f4dd4b903442309b5944dd2ff6eb9dd702c6dc4d91345aca86c5"

FUNCTIONS = {
    "proxy_pool_predicate": ("uvm_gpu.h", "uvm_parent_gpu_needs_proxy_channel_pool"),
    "pool_is_proxy": ("uvm_channel.h", "uvm_channel_pool_is_proxy"),
    "channel_is_proxy": ("uvm_channel.h", "uvm_channel_is_proxy"),
    "max_pools": ("uvm_channel.c", "channel_manager_get_max_pools"),
    "create_pools": ("uvm_channel.c", "channel_manager_create_pools"),
    "proxy_create": ("uvm_channel.c", "proxy_channel_create"),
    "channel_create": ("uvm_channel.c", "channel_create"),
    "channel_destroy": ("uvm_channel.c", "channel_destroy"),
    "proxy_submit": ("uvm_channel.c", "proxy_channel_submit_work"),
    "map_proxy": ("uvm_rm_mem.c", "rm_mem_map_gpu_proxy"),
    "unmap_proxy": ("uvm_rm_mem.c", "rm_mem_unmap_gpu_proxy"),
    "unmap_memory": ("uvm_rm_mem.c", "rm_mem_unmap_gpu"),
}
BRIDGE_FUNCTIONS = {
    "paging_allocate": "nvUvmInterfacePagingChannelAllocate",
    "paging_destroy": "nvUvmInterfacePagingChannelDestroy",
    "paging_map": "nvUvmInterfacePagingChannelsMap",
    "paging_unmap": "nvUvmInterfacePagingChannelsUnmap",
    "paging_push": "nvUvmInterfacePagingChannelPushStream",
}
PAGING_CALLS = {
    "allocate": "nvUvmInterfacePagingChannelAllocate",
    "destroy": "nvUvmInterfacePagingChannelDestroy",
    "map": "nvUvmInterfacePagingChannelsMap",
    "unmap": "nvUvmInterfacePagingChannelsUnmap",
    "push": "nvUvmInterfacePagingChannelPushStream",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strip_c_comments_and_literals(source: str) -> str:
    pattern = r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, " ", source, flags=re.DOTALL)


def load_functions(source_root: Path) -> tuple[dict[str, str], dict[str, int]]:
    source_root = Path(source_root)
    if source_root.is_symlink() or source_root.name != "nvidia-uvm":
        raise ValueError("R595 UVM source root must be a regular nvidia-uvm directory")
    source_text = []
    for path in sorted(source_root.rglob("*.c")):
        if path.is_symlink():
            raise ValueError("R595 UVM C source files must not be symlinks")
        source_text.append(path.read_text(encoding="utf-8"))
    if not source_text:
        raise ValueError("R595 UVM source tree contains no C files")
    source_code = strip_c_comments_and_literals("\n".join(source_text))
    functions = {
        key: c_function_definition(source_root / filename, name)
        for key, (filename, name) in FUNCTIONS.items()
    }
    call_counts = {
        name: len(re.findall(r"\b" + re.escape(name) + r"\s*\(", source_code))
        for name in PAGING_CALLS.values()
    }
    return functions, call_counts


def load_bridge_functions(bridge_path: Path = BRIDGE) -> dict[str, str]:
    bridge_path = Path(bridge_path)
    if bridge_path.is_symlink():
        raise ValueError("hybrid callback bridge must not be a symlink")
    return {
        key: c_function_definition(bridge_path, name)
        for key, name in BRIDGE_FUNCTIONS.items()
    }


def load_default_functions() -> tuple[dict[str, str], dict[str, str]]:
    functions, call_counts = load_functions(BRANCHES["595.99.02"]["source_root"])
    functions["_paging_call_counts"] = json.dumps(call_counts, sort_keys=True)
    return functions, load_bridge_functions()


def _call_counts(functions: dict[str, str]) -> dict[str, int]:
    try:
        value = json.loads(functions["_paging_call_counts"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("paging callback call-site counts are missing or malformed") from exc
    if not isinstance(value, dict) or any(type(count) is not int or count < 0
                                          for count in value.values()):
        raise ValueError("paging callback call-site counts are malformed")
    return value


def analyze_functions(functions: dict[str, str],
                      bridge: dict[str, str]) -> dict[str, Any]:
    counts = _call_counts(functions)
    predicate = functions["proxy_pool_predicate"]
    max_pools = functions["max_pools"]
    create_pools = functions["create_pools"]
    proxy_create = functions["proxy_create"]
    channel_create = functions["channel_create"]
    channel_destroy = functions["channel_destroy"]
    proxy_submit = functions["proxy_submit"]
    map_proxy = functions["map_proxy"]
    unmap_proxy = functions["unmap_proxy"]
    unmap_memory = functions["unmap_memory"]
    checks = {
        "proxy_pool_requires_sriov_heavy": (
            predicate ==
            "uvm_parent_gpu_needs_proxy_channel_pool(const uvm_parent_gpu_t *parent_gpu) "
            "{ return uvm_parent_gpu_is_virt_mode_sriov_heavy(parent_gpu); }"
        ),
        "proxy_pool_capacity_is_heavy_mode_gated": bool(re.search(
            r"if\s*\(uvm_parent_gpu_needs_proxy_channel_pool\(manager->gpu->parent\)\)\s*"
            r"num_channel_pools\+\+;", max_pools)),
        "proxy_pool_creation_is_heavy_mode_gated": bool(re.search(
            r"if\s*\(uvm_parent_gpu_needs_proxy_channel_pool\(manager->gpu->parent\)\)\s*"
            r"\{[^{}]*channel_pool_add\(manager,\s*UVM_CHANNEL_POOL_TYPE_CE_PROXY,",
            create_pools)),
        "proxy_pool_type_is_the_proxy_channel_discriminator": (
            "return pool->pool_type == UVM_CHANNEL_POOL_TYPE_CE_PROXY;" in
            functions["pool_is_proxy"] and
            "return uvm_channel_pool_is_proxy(channel->pool);" in
            functions["channel_is_proxy"]
        ),
        "proxy_allocator_is_selected_only_for_proxy_channels": (
            "UVM_ASSERT(uvm_channel_is_proxy(channel));" in proxy_create and
            bool(re.search(
                r"if\s*\(uvm_channel_is_proxy\(channel\)\)\s*"
                r"status\s*=\s*proxy_channel_create\(channel,\s*pool->engine_index\);\s*"
                r"else\s*status\s*=\s*internal_channel_create\(channel\);",
                channel_create
            ))
        ),
        "paging_callback_call_sites_are_single_and_proxy_scoped": (
            counts == {
                PAGING_CALLS["allocate"]: 1,
                PAGING_CALLS["destroy"]: 1,
                PAGING_CALLS["map"]: 1,
                PAGING_CALLS["unmap"]: 1,
                PAGING_CALLS["push"]: 1,
            } and
            "nvUvmInterfacePagingChannelAllocate(" in proxy_create and
            "if (uvm_channel_is_proxy(channel)) uvm_rm_locked_call_void(nvUvmInterfacePagingChannelDestroy(" in channel_destroy and
            "UVM_ASSERT(uvm_channel_is_proxy(channel));" in proxy_submit and
            "nvUvmInterfacePagingChannelPushStream(" in proxy_submit and
            "nvUvmInterfacePagingChannelsMap(" in map_proxy and
            "nvUvmInterfacePagingChannelsUnmap(" in unmap_proxy
        ),
        "proxy_va_mapping_is_heavy_mode_gated": (
            "if (!uvm_parent_gpu_needs_proxy_channel_pool(gpu->parent)) return NV_OK;" in map_proxy and
            map_proxy.index("if (!uvm_parent_gpu_needs_proxy_channel_pool(gpu->parent)) return NV_OK;") <
            map_proxy.index("nvUvmInterfacePagingChannelsMap(") and
            map_proxy.index("if (status != NV_OK)") >
            map_proxy.index("nvUvmInterfacePagingChannelsMap(") and
            map_proxy.index("return status;") < map_proxy.index("rm_mem_set_gpu_proxy_va(") and
            map_proxy.index("rm_mem_set_gpu_proxy_va(") >
            map_proxy.index("nvUvmInterfacePagingChannelsMap(")
        ),
        "proxy_va_unmap_requires_prior_proxy_mapping": (
            "if (!uvm_rm_mem_mapped_on_gpu_proxy(rm_mem, gpu)) return;" in unmap_proxy and
            unmap_proxy.index("if (!uvm_rm_mem_mapped_on_gpu_proxy(rm_mem, gpu)) return;") <
            unmap_proxy.index("nvUvmInterfacePagingChannelsUnmap(") and
            "rm_mem_unmap_gpu_proxy(rm_mem, gpu);" in unmap_memory
        ),
        "paging_allocate_remains_fail_closed": (
            "*channel = NULL;" in bridge["paging_allocate"] and
            "memset(channelInfo, 0, sizeof(*channelInfo));" in bridge["paging_allocate"] and
            "return NV_ERR_NOT_SUPPORTED;" in bridge["paging_allocate"]
        ),
        "paging_map_remains_fail_closed_and_zeroes_output": (
            "*dstAddress = 0;" in bridge["paging_map"] and
            "return NV_ERR_NOT_SUPPORTED;" in bridge["paging_map"]
        ),
        "paging_destroy_and_unmap_do_not_forward_foreign_handles": (
            "(void)channel;" in bridge["paging_destroy"] and
            "hybrid580_" not in bridge["paging_destroy"] and
            "(void)srcVaSpace;" in bridge["paging_unmap"] and
            "hybrid580_" not in bridge["paging_unmap"]
        ),
        "paging_push_remains_fail_closed": (
            "return NV_ERR_NOT_SUPPORTED;" in bridge["paging_push"]
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "source_contracts_passed" if not failed else "unresolved",
        "checks": checks,
        "failed_checks": failed,
        "callback_call_site_counts": counts,
        "interpretation": (
            "The pinned R595 UVM creates its CE proxy pool only when the parent GPU is "
            "SR-IOV Heavy. Paging-channel allocate, destroy, and push are used only for "
            "those proxy channels. PagingChannelsMap/Unmap are separate: the pinned "
            "uvm_rm_mem.c calls them only for proxy-VA mappings, with Map returning before "
            "the callback unless the same SR-IOV-heavy predicate is true, and Unmap requiring "
            "a previously recorded proxy mapping. The hybrid bridge's fail-closed paging "
            "callbacks therefore do not block the ordinary non-SR-IOV-heavy path. This is "
            "a source-level conclusion for the pinned trees. It does not establish the "
            "virtualization mode reported by the PC3 V100 guest or validate UVM on a GPU."
        ),
    }


def audit_sources() -> dict[str, Any]:
    bridge_hash = sha256_file(BRIDGE)
    if bridge_hash != BRIDGE_SHA256:
        raise ValueError("hybrid callback bridge source hash differs from the reviewed pin")
    bridge = load_bridge_functions()
    branch_reports: dict[str, Any] = {}
    for release, config in BRANCHES.items():
        source_root = Path(config["source_root"])
        if source_root.is_symlink():
            raise ValueError(f"{release} UVM source root must not be a symlink")
        actual_hashes = {
            filename: sha256_file(source_root / filename)
            for filename in config["files"]
        }
        if actual_hashes != config["files"]:
            raise ValueError(f"{release} UVM source files differ from the pinned upstream snapshot")
        functions, call_counts = load_functions(source_root)
        functions["_paging_call_counts"] = json.dumps(call_counts, sort_keys=True)
        result = analyze_functions(functions, bridge)
        branch_reports[release] = {
            "upstream_commit": config["commit"],
            "files": actual_hashes,
            "result": result,
        }
    branch_file_parity = (
        branch_reports["595.99.02"]["files"] ==
        branch_reports["595.112.07"]["files"]
    )
    all_checks = {
        "reviewed_bridge_hash_matches": bridge_hash == BRIDGE_SHA256,
        "r595_99_and_112_gate_sources_are_identical": branch_file_parity,
        **{
            f"{release}:{name}": passed
            for release, report in branch_reports.items()
            for name, passed in report["result"]["checks"].items()
        },
    }
    failed = sorted(name for name, passed in all_checks.items() if not passed)
    return {
        "schema": "r595-uvm-paging-callback-routes-audit-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "supersedes": {
            "report": "evidence/r595-uvm-proxy-paging-gate-v1-20261101T062250Z.json",
            "reason": (
                "v1 counted callback references only in uvm_channel.c and missed the "
                "proxy-VA Map/Unmap route in uvm_rm_mem.c; v2 scans the full pinned UVM "
                "C tree and verifies that memory route's SR-IOV-heavy guard."
            ),
        },
        "scope": {
            "upstream_sources": "R595.99.02 and R595.112.07 UVM C trees",
            "scanned_call_sites": "all *.c files under each pinned nvidia-uvm source root",
            "bridge": "current hybrid R580 callback bridge source",
        },
        "source_branches": branch_reports,
        "bridge": {"path": str(BRIDGE.relative_to(ROOT)), "sha256": bridge_hash},
        "result": {
            "status": "source_contracts_passed" if not failed else "unresolved",
            "checks": all_checks,
            "failed_checks": failed,
        },
        "qualification": {
            "source_analysis": True,
            "compiled": False,
            "runtime_or_hardware_validated": False,
            "guest_virtualization_mode_verified": False,
            "module_loaded_or_installed": False,
        },
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    evidence_root = (ROOT / "evidence").resolve(strict=True)
    path = Path(path)
    if path.is_symlink():
        raise ValueError("report output must not be a symlink")
    if not path.is_absolute():
        path = ROOT / path
    parent = path.parent.resolve(strict=True)
    if parent != evidence_root and evidence_root not in parent.parents:
        raise ValueError("report output must be within the project evidence directory")
    path = parent / path.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        help="write a new mode-0600 JSON report under evidence/")
    args = parser.parse_args(argv)
    try:
        report = audit_sources()
        if args.output:
            write_report(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["result"]["status"] == "source_contracts_passed" else 1
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"source audit failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
