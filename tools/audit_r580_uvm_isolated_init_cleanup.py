#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit isolated R580 UVM semaphore initialization and partial-init cleanup.

This audit checks the exact compiled R580 patch chain and extracted source
functions. It establishes source ordering only; it does not execute UVM, test
RM cross-provider behavior, or validate a GPU runtime.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_hybrid_uvm_abi import c_function_definition  # noqa: E402

BUILD_REPORT = ROOT / "evidence/r580-uvm-pmm-retry-pair-v4-20261028T1337Z.json"
EXPECTED_BUILD_REPORT_SHA256 = "a09dc0d0915ce42115cbaa93bbbbc85586cc912cd081f97260cec2de642a6d9d"
SOURCE_ROOT = (
    ROOT / "build/experiments/r580-uvm-pmm-retry-pair-v4-20261028T1337Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
SOURCE_RELEASE = "580.178.04"
SOURCE_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
PATCH_HASHES = {
    "0007-reject-cross-gpu-tracker-dependencies.patch":
        "b8ce083d3f380e63e5d1028a1c14c8481983b8a2365f1451320101cbed16424d",
    "0008-pmm-allocation-outside-va-block-lock.patch":
        "b532998cbca0a7ca566690a448f6984dff50f22219c60ccd9fa08578c7c40baa",
    "0009-reject-hmm-gpu-migration-in-isolated-mode.patch":
        "e5970b1c9d5ef68d3b5dc1c4a7a64bd2f256204d694b5c9f4518dc4c1b17f273",
}
SOURCE_FILES = (
    "uvm_gpu.c",
    "uvm_gpu.h",
    "uvm_push.c",
    "uvm_gpu_semaphore.c",
    "uvm_rm_mem.c",
    "uvm_channel.c",
    "uvm_mmu.c",
)
BRIDGE_PATH = ROOT / "src/hybrid580_uvm_callback_bridge.c"
ROUTE_HEADERS = (
    ROOT / "src/hybrid580_uvm_device_route.h",
    ROOT / "src/hybrid580_uvm_address_space_route.h",
    ROOT / "src/hybrid580_uvm_typed_child_route.h",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_functions(source_root: Path,
                      bridge_path: Path = BRIDGE_PATH) -> dict[str, str]:
    source_root = Path(source_root)
    bridge_path = Path(bridge_path)
    return {
        "allow_cross_gpu": c_function_definition(source_root / "uvm_push.c", "uvm_push_allow_dependencies_across_gpus"),
        "isolated_enabled": c_function_definition(source_root / "uvm_push.c", "uvm_push_isolated_gpu_execution_enabled"),
        "init_semaphore_pools": c_function_definition(source_root / "uvm_gpu.c", "init_semaphore_pools"),
        "init_gpu": c_function_definition(source_root / "uvm_gpu.c", "init_gpu"),
        "configure_address_space": c_function_definition(source_root / "uvm_gpu.c", "configure_address_space"),
        "add_gpu": c_function_definition(source_root / "uvm_gpu.c", "add_gpu"),
        "remove_gpu": c_function_definition(source_root / "uvm_gpu.c", "remove_gpu"),
        "deinit_gpu": c_function_definition(source_root / "uvm_gpu.c", "deinit_gpu"),
        "deinit_semaphore_pools": c_function_definition(source_root / "uvm_gpu.c", "deinit_semaphore_pools"),
        "channel_manager_destroy": c_function_definition(source_root / "uvm_channel.c", "uvm_channel_manager_destroy"),
        "channel_manager_pick_ces": c_function_definition(source_root / "uvm_channel.c", "channel_manager_pick_ces"),
        "channel_manager_create_pools": c_function_definition(source_root / "uvm_channel.c", "channel_manager_create_pools"),
        "tsg_create": c_function_definition(source_root / "uvm_channel.c", "tsg_create"),
        "internal_channel_create": c_function_definition(source_root / "uvm_channel.c", "internal_channel_create"),
        "channel_create": c_function_definition(source_root / "uvm_channel.c", "channel_create"),
        "proxy_channel_create": c_function_definition(source_root / "uvm_channel.c", "proxy_channel_create"),
        "proxy_pool_predicate": c_function_definition(source_root / "uvm_gpu.h", "uvm_parent_gpu_needs_proxy_channel_pool"),
        "create_identity_mapping": c_function_definition(source_root / "uvm_mmu.c", "create_identity_mapping"),
        "uvm_mmu_create_flat_mappings": c_function_definition(source_root / "uvm_mmu.c", "uvm_mmu_create_flat_mappings"),
        "semaphore_pool_unmap_gpu": c_function_definition(source_root / "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_pool_unmap_gpu"),
        "semaphore_pool_destroy": c_function_definition(source_root / "uvm_gpu_semaphore.c", "uvm_gpu_semaphore_pool_destroy"),
        "rm_mem_unmap_gpu": c_function_definition(source_root / "uvm_rm_mem.c", "rm_mem_unmap_gpu"),
        "rm_mem_unmap_gpu_public": c_function_definition(source_root / "uvm_rm_mem.c", "uvm_rm_mem_unmap_gpu"),
        "bridge_device_call": c_function_definition(bridge_path, "hybrid580_uvm_device_call"),
        "bridge_address_space_call": c_function_definition(bridge_path, "hybrid580_uvm_address_space_call"),
        "bridge_query_copy_engines": c_function_definition(bridge_path, "nvUvmInterfaceQueryCopyEnginesCaps"),
        "bridge_tsg_allocate": c_function_definition(bridge_path, "nvUvmInterfaceTsgAllocate"),
        "bridge_channel_allocate": c_function_definition(bridge_path, "nvUvmInterfaceChannelAllocate"),
        "bridge_set_page_directory": c_function_definition(bridge_path, "nvUvmInterfaceSetPageDirectory"),
        "bridge_paging_channel_allocate": c_function_definition(bridge_path, "nvUvmInterfacePagingChannelAllocate"),
    }


def _ordered(text: str, tokens: tuple[str, ...]) -> bool:
    cursor = 0
    for token in tokens:
        index = text.find(token, cursor)
        if index < 0:
            return False
        cursor = index + len(token)
    return True


def analyze_functions(functions: dict[str, str]) -> dict[str, Any]:
    allow = functions["allow_cross_gpu"]
    isolated = functions["isolated_enabled"]
    init_semaphores = functions["init_semaphore_pools"]
    init_gpu = functions["init_gpu"]
    add_gpu = functions["add_gpu"]
    remove_gpu = functions["remove_gpu"]
    deinit_gpu = functions["deinit_gpu"]
    deinit_semaphores = functions["deinit_semaphore_pools"]
    manager_destroy = functions["channel_manager_destroy"]
    pool_unmap = functions["semaphore_pool_unmap_gpu"]
    pool_destroy = functions["semaphore_pool_destroy"]
    rm_unmap = functions["rm_mem_unmap_gpu"]
    rm_unmap_public = functions["rm_mem_unmap_gpu_public"]

    map_loop = init_semaphores.find("for_each_gpu(other_gpu)")
    map_call = init_semaphores.find("uvm_gpu_semaphore_pool_map_gpu(other_gpu->semaphore_pool, gpu)")
    isolate_gate = init_semaphores.find("if (!uvm_push_allow_dependencies_across_gpus())")
    isolate_return = init_semaphores.find("return NV_OK;", isolate_gate)

    init_call = add_gpu.find("status = init_gpu(gpu, gpu_info)")
    init_failure = add_gpu.find("if (status != NV_OK) goto error;", init_call)
    gpu_publish = min(
        (index for index in (
            add_gpu.find("uvm_global_add_parent_gpu(parent_gpu)"),
            add_gpu.find("__set_bit(uvm_id_sub_processor_index(gpu->id)"),
        ) if index >= 0),
        default=-1,
    )
    error_label = add_gpu.find("error:", init_failure)
    error_remove = add_gpu.find("remove_gpu(gpu);", error_label)
    remove_deinit = remove_gpu.find("deinit_gpu(gpu)")
    remove_free = remove_gpu.find("uvm_kvfree(gpu)", remove_deinit)

    cleanup_unmap = deinit_semaphores.find("uvm_gpu_semaphore_pool_unmap_gpu(other_gpu->semaphore_pool, gpu)")
    cleanup_local_destroy = deinit_semaphores.find("uvm_gpu_semaphore_pool_destroy(gpu->semaphore_pool)")
    checks = {
        "isolated_mode_disables_foreign_gpu_dependencies": (
            "return !g_uvm_global.conf_computing_enabled && !uvm_hybrid_isolated_gpu_execution;" in allow
            and "return uvm_hybrid_isolated_gpu_execution;" in isolated
        ),
        "isolated_registration_returns_before_foreign_semaphore_mapping": (
            "uvm_gpu_semaphore_pool_create(gpu, &gpu->semaphore_pool)" in init_semaphores
            and isolate_gate >= 0
            and isolate_return > isolate_gate
            and map_loop > isolate_return
            and map_call > map_loop
        ),
        "isolated_semaphore_pages_use_owner_local_cpu_mapping": (
            "!uvm_push_allow_dependencies_across_gpus()" in functions.get("semaphore_page_alloc", "")
            and "uvm_rm_mem_alloc_and_map_cpu(gpu, memory_type, memory_size, 0, &page->memory)" in functions.get("semaphore_page_alloc", "")
        ),
        "init_gpu_propagates_semaphore_failure_before_channel_creation": _ordered(
            init_gpu,
            ("status = init_semaphore_pools(gpu)",
             "if (status != NV_OK)",
             "return status;",
             "uvm_channel_manager_create(gpu, &gpu->channel_manager)"),
        ),
        "failed_gpu_init_enters_remove_before_publication": (
            init_call >= 0
            and init_failure > init_call
            and error_label > init_failure
            and error_remove > error_label
            and gpu_publish > init_failure
        ),
        "remove_gpu_deinitializes_before_freeing_gpu": (
            remove_deinit >= 0 and remove_free > remove_deinit
        ),
        "partial_init_channel_manager_cleanup_is_null_safe": (
            "uvm_channel_manager_destroy(gpu->channel_manager)" in deinit_gpu
            and "if (channel_manager == NULL) return;" in manager_destroy
        ),
        "semaphore_rollback_unmaps_existing_pool_pages_before_local_destroy": (
            cleanup_unmap >= 0
            and cleanup_local_destroy > cleanup_unmap
            and "uvm_rm_mem_unmap_gpu(page->memory, gpu)" in pool_unmap
            and "if (!uvm_rm_mem_mapped_on_gpu(rm_mem, gpu)) return;" in rm_unmap
            and "rm_mem_unmap_gpu(rm_mem, gpu);" in rm_unmap_public
        ),
        "partial_init_rollback_keeps_rm_space_until_semaphore_unmap": _ordered(
            deinit_gpu,
            ("deconfigure_address_space(gpu)",
             "deinit_semaphore_pools(gpu)",
             "uvm_pmm_gpu_deinit(&gpu->pmm)",
             "nvUvmInterfaceAddressSpaceDestroy(gpu->rm_address_space)"),
        ),
        "semaphore_pool_destroy_accepts_absent_local_pool": (
            "if (!pool) return;" in pool_destroy
        ),
        "post_semaphore_gpu_init_order_reaches_address_space_and_flat_maps": _ordered(
            init_gpu,
            ("status = init_semaphore_pools(gpu)",
             "status = uvm_channel_manager_create(gpu, &gpu->channel_manager)",
             "status = configure_address_space(gpu)",
             "status = uvm_mmu_create_flat_mappings(gpu)"),
        ),
        "copy_engine_caps_query_routes_by_registered_gpu_owner": (
            "nvUvmInterfaceQueryCopyEnginesCaps(uvm_gpu_device_handle(manager->gpu), ces_caps)" in functions["channel_manager_pick_ces"]
            and "hybrid580_uvm_device_call(device, caps" in functions["bridge_query_copy_engines"]
            and "hybrid580_uvm_device_route_call(" in functions["bridge_device_call"]
        ),
        "tsg_create_routes_by_gpu_address_space_owner": (
            "nvUvmInterfaceTsgAllocate(gpu->rm_address_space" in functions["tsg_create"]
            and "hybrid580_uvm_address_space_route_call(" in functions["bridge_tsg_allocate"]
            and "HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE" in functions["bridge_tsg_allocate"]
        ),
        "channel_create_routes_by_tsg_owner_and_same_provider": (
            "nvUvmInterfaceChannelAllocate(channel_get_tsg(channel)" in functions["internal_channel_create"]
            and "hybrid580_uvm_typed_child_route_call(" in functions["bridge_channel_allocate"]
            and "HYBRID580_UVM_TYPED_CHILD_TSG" in functions["bridge_channel_allocate"]
            and "params.provider" in functions["bridge_channel_allocate"]
        ),
        "page_directory_programming_routes_by_gpu_address_space_owner": (
            "nvUvmInterfaceSetPageDirectory(gpu->rm_address_space" in functions["configure_address_space"]
            and "hybrid580_uvm_address_space_call(" in functions["bridge_set_page_directory"]
        ),
        "unsupported_proxy_channel_api_is_limited_to_sriov_heavy_mode": (
            _ordered(functions["channel_manager_create_pools"],
                     ("if (uvm_parent_gpu_needs_proxy_channel_pool(manager->gpu->parent))",
                      "channel_pool_add(manager, UVM_CHANNEL_POOL_TYPE_CE_PROXY"))
            and "return uvm_parent_gpu_is_virt_mode_sriov_heavy(parent_gpu);" in functions["proxy_pool_predicate"]
            and _ordered(functions["channel_create"],
                         ("if (uvm_channel_is_proxy(channel))",
                          "proxy_channel_create(channel, pool->engine_index)",
                          "internal_channel_create(channel)"))
            and "nvUvmInterfacePagingChannelAllocate(uvm_gpu_device_handle(gpu)" in functions["proxy_channel_create"]
            and "return NV_ERR_NOT_SUPPORTED;" in functions["bridge_paging_channel_allocate"]
        ),
        "flat_mapping_setup_uses_the_gpu_local_page_tree_path": (
            _ordered(functions["uvm_mmu_create_flat_mappings"],
                     ("create_static_vidmem_mapping(gpu)",
                      "create_dynamic_sysmem_mapping(gpu)",
                      "create_dynamic_vidmem_mapping(gpu)"))
            and "uvm_page_table_range_vec_create(&gpu->address_space_tree" in functions["create_identity_mapping"]
            and "uvm_page_table_range_vec_write_ptes(mapping->range_vec" in functions["create_identity_mapping"]
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "source_contracts_passed" if not failed else "unresolved",
        "checks": checks,
        "failed_checks": failed,
        "interpretation": (
            "The compiled isolated-mode source disables cross-GPU tracker dependencies and "
            "returns from semaphore-pool initialization before mapping another provider's "
            "existing semaphore pages. New semaphore backing is CPU-mapped and remains local "
            "to its owner GPU. If GPU initialization fails before publication, add_gpu routes "
            "through remove_gpu/deinit_gpu; null channel-manager and semaphore-pool cleanup is "
            "guarded, while any partially installed foreign pool mappings are removed before "
            "the RM address space is destroyed. After the semaphore step, the ordinary channel "
            "path queries copy-engine caps by device owner, allocates TSGs by address-space "
            "owner, allocates channels by TSG owner, and programs the page directory by "
            "address-space owner. The paging-channel callback remains unsupported, but R580 "
            "calls it only for SR-IOV Heavy proxy pools. These are static route and source-order "
            "findings only. They do not prove runtime GPU initialization, RM acceptance, or "
            "cross-GPU UVM/P2P behavior."
        ),
    }


def audit_sources(source_root: Path = SOURCE_ROOT,
                  build_report_path: Path = BUILD_REPORT) -> dict[str, Any]:
    source_root = Path(source_root)
    build_report_path = Path(build_report_path)
    if source_root.is_symlink() or build_report_path.is_symlink():
        raise ValueError("source root and build report must not be symlinks")
    source_root = source_root.resolve(strict=True)
    build_report_path = build_report_path.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be an R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != f"NVIDIA-kernel-module-source-{SOURCE_RELEASE}":
        raise ValueError("source tree is not R580.178.04")
    build_sha = sha256_file(build_report_path)
    if build_sha != EXPECTED_BUILD_REPORT_SHA256:
        raise ValueError("pinned R580 pair build report SHA-256 mismatch")
    build = json.loads(build_report_path.read_text(encoding="utf-8"))
    if build.get("inputs", {}).get("source_package") != str(package):
        raise ValueError("build report does not identify the audited package")
    if build.get("build", {}).get("exit_code") != 0:
        raise ValueError("R580 pair build did not succeed")
    if build.get("qualification", {}).get("module_loaded_or_installed") is not False:
        raise ValueError("build report unexpectedly records a loaded/installed module")
    if build.get("qualification", {}).get("runtime_or_hardware_validated") is not False:
        raise ValueError("build report unexpectedly claims runtime/hardware validation")
    archive = build.get("inputs", {}).get("source_archive", {})
    if archive.get("sha256") != SOURCE_ARCHIVE_SHA256:
        raise ValueError("build report has an unexpected R580 source archive hash")
    patch_records = {
        Path(record.get("path", "")).name: record.get("sha256")
        for record in build.get("inputs", {}).get("patches", [])
    }
    if any(patch_records.get(name) != digest for name, digest in PATCH_HASHES.items()):
        raise ValueError("build report does not pin the isolated UVM patch series")
    source_files = {}
    for name in SOURCE_FILES:
        path = source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected regular R580 source file: {name}")
        source_files[name] = {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    bridge_path = BRIDGE_PATH
    if bridge_path.is_symlink() or not bridge_path.is_file():
        raise ValueError("expected regular hybrid UVM callback bridge")
    source_files[bridge_path.relative_to(ROOT).as_posix()] = {
        "path": bridge_path.relative_to(ROOT).as_posix(),
        "sha256": sha256_file(bridge_path),
        "bytes": bridge_path.stat().st_size,
    }
    route_headers = {}
    for path in ROUTE_HEADERS:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected regular UVM route header: {path.name}")
        route_headers[path.relative_to(ROOT).as_posix()] = {
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
    functions = extract_functions(source_root, bridge_path)
    # This allocator is in a file outside the main audit list and is needed to
    # distinguish an idempotent rollback from an unconditional RM free.
    semaphore_source_root = source_root
    page_alloc = c_function_definition(
        semaphore_source_root / "uvm_gpu_semaphore.c", "pool_page_alloc_buffers"
    )
    functions["semaphore_page_alloc"] = page_alloc
    result = analyze_functions(functions)
    return {
        "schema": "nvidia-r580-uvm-isolated-init-cleanup-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_RELEASE,
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {
            "build_report": {
                "path": build_report_path.relative_to(ROOT).as_posix(),
                "sha256": build_sha,
            },
            "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            "patches": PATCH_HASHES,
            "source_files": source_files,
            "route_headers": route_headers,
        },
        "result": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--build-report", type=Path, default=BUILD_REPORT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root, args.build_report)
        if args.output:
            payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
            fd = os.open(
                args.output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"isolated UVM init audit failed: {exc}", file=sys.stderr)
        return 2
    return 1 if report["result"]["status"] == "unresolved" else 0


if __name__ == "__main__":
    raise SystemExit(main())
