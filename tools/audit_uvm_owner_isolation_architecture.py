#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare single-UVM shared-memory and isolated-UVM owner designs statically.

This audit pins R580.178.04 source and the current R580 dual-RM callback bridge.
It is source analysis only: no kernel module, GPU, userspace driver, DMA mapping,
or runtime behavior is exercised.
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
from tools.audit_uvm_interface_ownership import parse_prototypes  # noqa: E402

SOURCE_TAG = "580.178.04"
SOURCE_ROOT = (
    ROOT / "build/experiments/private-open580-native-v4-softdep-v1-20261023"
    / "private/NVIDIA-kernel-module-source-580.178.04/kernel-open"
)
SOURCE_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
EXPECTED_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
BRIDGE_PATH = ROOT / "src/hybrid580_uvm_callback_bridge.c"
C1_REPORT = ROOT / "evidence/r580-uvm-cross-provider-static-v2-20261023T204103Z.json"
EXPECTED_C1_SHA256 = "a02b4d8b9e1498ba1aab379121ebb1f38c206bf5942d035ab96af98aaf63feb9"
EXPECTED_SOURCE_SHA256 = {
    "uvm.c": "6549ff9293e5a789d53f59c29cbc2af4d7d8aedd0bfe7519699c4239e7ad24b3",
    "uvm_global.c": "aeee2f257a289853f36d9c7b196f1e02d19b84695db44cdd2e00f28b0f1a4489",
    "uvm_global.h": "32c99fb632fa831da1fbae7c4e541e4fc35afd1d3bf94fe5f7ba57f97dc2e33c",
    "nvidia-uvm.Kbuild": "0e8d3d96e00d6ca8b6b564e4668dd70447d8b6bca9200845180ce7c66902328b",
    "hybrid580_uvm_callback_bridge.c": "c581cda76752f4dd4b903442309b5944dd2ff6eb9dd702c6dc4d91345aca86c5",
    "hybrid580_uvm_callback_bridge.h": "f68a880a5e54ebafb083c11f3b6349f5ed47462c1e4ac5db90b05ee176285b4d",
    "nv_uvm_interface.h": "68b6cae62ad0bdf6940d48a34084d789cd1f87a06b84310195cd2adc4b9e50f8",
    "nv_uvm_types.h": "5216a6a83924511f38c8a881ee0ffc601e2851e92e6a9b49810f9cc9e90dd614",
    "nv_uvm_interface.c": "c8a8df6968ea3a844ba224c4e83b33b2281cfb7c1ef5122e119a6b75b118f113",
    "uvm_rm_mem.c": "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7",
    "uvm_gpu.c": "b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700",
    "uvm_pmm_gpu.c": "35248129b757c9a405bed7adf7022ea108ebbd9bbb0b091a008935f1247dea9b",
    "uvm_gpu_semaphore.c": "1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f",
    "uvm_channel.c": "64fcdb55ecba388c8ed6c656ca72b60f2b6f4b8bc0ebaffd794ed1e78068a248",
    "uvm_push.c": "9628ada0b4007eff5af16525d0d71788045832e5ca268699e2ae82a5dc14b85e",
    "uvm_tracker.c": "756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41",
    "uvm_migrate_pageable.c": "e7178513d684596aadbe24c1f699eb9e7b13b7f39c19805fe213bbef090898da",
    "uvm_channel_test.c": "f846b5e2925258bb1643e389bee4016743a73a6f396571e0621aac109bb94e87",
    "uvm_map_external.c": "4115e9f2de1fc9ad460a61168e78e68ede19c57ac6216740dc57475b29d07511",
}

OS_PAGE_IMPORT_TYPES = (
    "struct page",
    "dma_addr_t",
    "struct sg_table",
    "struct scatterlist",
    "struct dma_buf",
    "struct vm_area_struct",
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


def _pinned_file(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"{label}: source must not be a symlink")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"{label}: expected a regular source file")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ValueError(f"pinned source SHA-256 mismatch for {label}: {actual}")
    return {"path": project_path(path), "sha256": actual, "bytes": path.stat().st_size}


def _function(path: Path, name: str) -> str:
    try:
        return c_function_definition(path, name)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract pinned function {name}: {exc}") from None


def _require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise ValueError("pinned source contract changed: " + description)


def classify_multi_registration(function_source: str) -> str:
    if re.search(
        r"if\s*\(\s*hybrid580_uvm_callbacks\.registered\s*\)\s*"
        r"\{\s*return\s+NV_ERR_IN_USE\s*;",
        function_source,
        re.DOTALL,
    ) is None:
        raise ValueError("unrecognized callback registration policy")
    if re.search(
        r"hybrid580_uvm_callback_register\s*\(\s*&hybrid580_uvm_callbacks",
        function_source,
    ) is None:
        raise ValueError("registration is not tied to the pinned single registry")
    return "rejected_while_registration_active"


def audit_sources(source_root: Path, bridge_path: Path) -> dict[str, Any]:
    source_root = Path(source_root)
    bridge_path = Path(bridge_path)
    if source_root.is_symlink() or bridge_path.is_symlink():
        raise ValueError("source root and bridge must not be symlinks")
    source_root = source_root.resolve(strict=True)
    bridge_path = bridge_path.resolve(strict=True)
    archive = SOURCE_ARCHIVE.resolve(strict=True)
    c1_report_path = C1_REPORT.resolve(strict=True)
    if source_root.name != "kernel-open":
        raise ValueError("source root must be the pinned R580 kernel-open tree")
    if source_root.parent.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source root is not NVIDIA R580.178.04")
    archive_sha = sha256_file(archive)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 archive SHA-256 mismatch")
    c1_sha = sha256_file(c1_report_path)
    if c1_sha != EXPECTED_C1_SHA256:
        raise ValueError("pinned C1 report SHA-256 mismatch")
    c1 = json.loads(c1_report_path.read_text(encoding="utf-8"))
    if c1.get("result", {}).get("cross_provider_admission") != "blocked":
        raise ValueError("pinned C1 report no longer establishes the admission blocker")

    paths = {
        "uvm.c": source_root / "nvidia-uvm/uvm.c",
        "uvm_global.c": source_root / "nvidia-uvm/uvm_global.c",
        "uvm_global.h": source_root / "nvidia-uvm/uvm_global.h",
        "nvidia-uvm.Kbuild": source_root / "nvidia-uvm/nvidia-uvm.Kbuild",
        "hybrid580_uvm_callback_bridge.c": bridge_path,
        "hybrid580_uvm_callback_bridge.h": bridge_path.with_suffix(".h"),
        "nv_uvm_interface.h": source_root / "common/inc/nv_uvm_interface.h",
        "nv_uvm_types.h": source_root / "common/inc/nv_uvm_types.h",
        "nv_uvm_interface.c": source_root / "nvidia/nv_uvm_interface.c",
        "uvm_rm_mem.c": source_root / "nvidia-uvm/uvm_rm_mem.c",
        "uvm_gpu.c": source_root / "nvidia-uvm/uvm_gpu.c",
        "uvm_pmm_gpu.c": source_root / "nvidia-uvm/uvm_pmm_gpu.c",
        "uvm_gpu_semaphore.c": source_root / "nvidia-uvm/uvm_gpu_semaphore.c",
        "uvm_channel.c": source_root / "nvidia-uvm/uvm_channel.c",
        "uvm_push.c": source_root / "nvidia-uvm/uvm_push.c",
        "uvm_tracker.c": source_root / "nvidia-uvm/uvm_tracker.c",
        "uvm_migrate_pageable.c": source_root / "nvidia-uvm/uvm_migrate_pageable.c",
        "uvm_channel_test.c": source_root / "nvidia-uvm/uvm_channel_test.c",
    }
    source_files = {
        label: _pinned_file(path, EXPECTED_SOURCE_SHA256[label], label)
        for label, path in paths.items()
    }
    uvm_text = paths["uvm.c"].read_text(encoding="utf-8")
    global_text = paths["uvm_global.h"].read_text(encoding="utf-8")
    kbuild_text = paths["nvidia-uvm.Kbuild"].read_text(encoding="utf-8")
    bridge_text = paths["hybrid580_uvm_callback_bridge.c"].read_text(encoding="utf-8")
    bridge_header = paths["hybrid580_uvm_callback_bridge.h"].read_text(encoding="utf-8")
    uvm_api_header = paths["nv_uvm_interface.h"].read_text(encoding="utf-8")
    uvm_types_header = paths["nv_uvm_types.h"].read_text(encoding="utf-8")

    funcs = {
        "uvm_file_is_nvidia_uvm": _function(paths["uvm.c"], "uvm_file_is_nvidia_uvm"),
        "uvm_api_mm_initialize": _function(paths["uvm.c"], "uvm_api_mm_initialize"),
        "uvm_chardev_create": _function(paths["uvm.c"], "uvm_chardev_create"),
        "uvm_register_callbacks": _function(paths["uvm_global.c"], "uvm_register_callbacks"),
        "uvm_unregister_callbacks": _function(paths["uvm_global.c"], "uvm_unregister_callbacks"),
        "uvm_global_init": _function(paths["uvm_global.c"], "uvm_global_init"),
        "uvm_global_exit": _function(paths["uvm_global.c"], "uvm_global_exit"),
        "hybrid580_uvm_register_callbacks_locked": _function(
            bridge_path, "hybrid580_uvm_register_callbacks_locked"
        ),
        "nvUvmInterfaceSessionCreate": _function(bridge_path, "nvUvmInterfaceSessionCreate"),
        "uvm_rm_mem_alloc": _function(paths["uvm_rm_mem.c"], "uvm_rm_mem_alloc"),
        "uvm_rm_mem_map_gpu": _function(paths["uvm_rm_mem.c"], "uvm_rm_mem_map_gpu"),
        "configure_address_space": _function(paths["uvm_gpu.c"], "configure_address_space"),
        "uvm_pmm_gpu_init": _function(paths["uvm_pmm_gpu.c"], "uvm_pmm_gpu_init"),
        "alloc_root_chunk": _function(paths["uvm_pmm_gpu.c"], "alloc_root_chunk"),
        "root_chunk_from_address": _function(paths["uvm_pmm_gpu.c"], "root_chunk_from_address"),
        "init_gpu": _function(paths["uvm_gpu.c"], "init_gpu"),
        "init_semaphore_pools": _function(paths["uvm_gpu.c"], "init_semaphore_pools"),
        "deinit_semaphore_pools": _function(paths["uvm_gpu.c"], "deinit_semaphore_pools"),
        "pool_page_alloc_buffers": _function(paths["uvm_gpu_semaphore.c"], "pool_page_alloc_buffers"),
        "uvm_gpu_semaphore_pool_map_gpu": _function(paths["uvm_gpu_semaphore.c"], "uvm_gpu_semaphore_pool_map_gpu"),
        "channel_create": _function(paths["uvm_channel.c"], "channel_create"),
        "channel_pool_add": _function(paths["uvm_channel.c"], "channel_pool_add"),
        "uvm_push_allow_dependencies_across_gpus": _function(paths["uvm_push.c"], "uvm_push_allow_dependencies_across_gpus"),
        "wait_for_other_gpus_if_needed": _function(paths["uvm_push.c"], "wait_for_other_gpus_if_needed"),
        "push_acquire_tracker_entry": _function(paths["uvm_push.c"], "push_acquire_tracker_entry"),
        "uvm_tracker_wait_for_other_gpus": _function(paths["uvm_tracker.c"], "uvm_tracker_wait_for_other_gpus"),
        "uvm_rm_mem_alloc_and_map_all": _function(paths["uvm_rm_mem.c"], "uvm_rm_mem_alloc_and_map_all"),
        "uvm_rm_mem_map_all_gpus": _function(paths["uvm_rm_mem.c"], "uvm_rm_mem_map_all_gpus"),
        "nvUvmInterfaceMemoryAllocSys": _function(paths["nv_uvm_interface.c"], "nvUvmInterfaceMemoryAllocSys"),
        "nvUvmInterfaceDupAllocation": _function(paths["nv_uvm_interface.c"], "nvUvmInterfaceDupAllocation"),
        "nvUvmInterfaceDupMemory": _function(paths["nv_uvm_interface.c"], "nvUvmInterfaceDupMemory"),
        "nvUvmInterfaceSetPageDirectory": _function(paths["nv_uvm_interface.c"], "nvUvmInterfaceSetPageDirectory"),
        "nvUvmInterfacePmaAllocPages": _function(paths["nv_uvm_interface.c"], "nvUvmInterfacePmaAllocPages"),
        "nvUvmInterfacePmaPinPages": _function(paths["nv_uvm_interface.c"], "nvUvmInterfacePmaPinPages"),
        "nvUvmInterfaceGetExternalAllocPtes": _function(paths["nv_uvm_interface.c"], "nvUvmInterfaceGetExternalAllocPtes"),
    }
    multi_registration = classify_multi_registration(
        funcs["hybrid580_uvm_register_callbacks_locked"]
    )

    _require(kbuild_text, r"obj-m\s*\+=\s*nvidia-uvm\.o", "one nvidia-uvm module target")
    _require(uvm_text, r'#define\s+NVIDIA_UVM_DEVICE_NAME\s+"nvidia-uvm"', "stock UVM device name")
    _require(funcs["uvm_chardev_create"], r"alloc_chrdev_region\s*\(", "dynamic UVM device number")
    _require(funcs["uvm_chardev_create"], r"cdev_add\s*\(", "one UVM cdev registration")
    _require(funcs["uvm_file_is_nvidia_uvm"], r"filp->f_op\s*==\s*&uvm_fops", "UVM fd file-ops identity")
    _require(funcs["uvm_api_mm_initialize"], r"fget\s*\(\s*params->uvmFd\s*\)", "UVM ioctl retrieves its UVM fd")
    _require(funcs["uvm_api_mm_initialize"], r"uvm_file_is_nvidia_uvm\s*\(\s*uvm_file\s*\)", "UVM ioctl validates module file identity")
    _require(global_text, r"uvm_parent_gpu_t\s*\*\s*parent_gpus\s*\[", "one global parent GPU table")
    _require(global_text, r"uvmGpuSessionHandle\s+rm_session_handle", "one global RM session field")
    _require(paths["uvm_global.c"].read_text(encoding="utf-8"), r"uvm_global_t\s+g_uvm_global\s*;", "module-global UVM state instance")
    _require(funcs["uvm_register_callbacks"], r"nvUvmInterfaceRegisterUvmCallbacks\s*\(", "UVM callback registration")
    _require(funcs["uvm_global_init"], r"uvm_register_callbacks\s*\(", "global init registers UVM callbacks")
    _require(funcs["uvm_global_init"], r"nvUvmInterfaceSessionCreate\s*\(", "UVM session creation")
    _require(funcs["uvm_unregister_callbacks"], r"nvUvmInterfaceDeRegisterUvmOps\s*\(", "UVM callback teardown")
    _require(funcs["uvm_global_exit"], r"uvm_unregister_callbacks\s*\(", "global exit deregisters UVM callbacks")
    _require(funcs["uvm_global_exit"], r"nvUvmInterfaceSessionDestroy\s*\(", "UVM session teardown")
    _require(bridge_text, r"static\s+struct\s+hybrid580_uvm_callback_registry\s+hybrid580_uvm_callbacks\s*;", "one bridge callback registry")
    _require(bridge_header, r"int\s+registered\s*;", "callback registry tracks one active registration")
    _require(funcs["nvUvmInterfaceSessionCreate"], r"hybrid580_open_session_create", "paired Open RM UVM session")
    _require(funcs["nvUvmInterfaceSessionCreate"], r"hybrid580_legacy_session_create", "paired legacy RM UVM session")
    _require(funcs["nvUvmInterfaceSessionCreate"], r"hybrid580_uvm_session_pair_create", "single logical UVM session fans out to provider sessions")

    prototypes = parse_prototypes(uvm_api_header)
    if len(prototypes) != 76:
        raise ValueError(f"pinned R580 UVM prototype count changed: {len(prototypes)}")
    prototypes_by_name = {item["name"]: item for item in prototypes}

    def declarations(api_name: str) -> list[str]:
        try:
            return [item["declaration"] for item in prototypes_by_name[api_name]["parameters"]]
        except KeyError:
            raise ValueError(f"pinned R580 UVM API is missing: {api_name}") from None

    typed_page_imports = []
    for prototype in prototypes:
        params = " ".join(item["declaration"] for item in prototype["parameters"])
        matched_types = [name for name in OS_PAGE_IMPORT_TYPES if name in params]
        if matched_types:
            typed_page_imports.append({"api": prototype["name"], "types": matched_types})

    _require(funcs["uvm_rm_mem_alloc"],
             r"nvUvmInterfaceMemoryAllocSys\s*\(\s*gpu->rm_address_space",
             "UVM system allocation is tied to the owning GPU RM address space")
    _require(funcs["uvm_rm_mem_alloc"], r"rm_mem->gpu_owner\s*=\s*gpu", "UVM records the allocation owner")
    _require(funcs["uvm_rm_mem_map_gpu"], r"nvUvmInterfaceDupAllocation\s*\(\s*gpu_owner->rm_address_space",
             "UVM duplicates a system allocation from its recorded owner VA space")
    _require(funcs["uvm_rm_mem_map_gpu"], r"gpu->rm_address_space", "UVM duplication targets the destination GPU VA space")
    _require(funcs["uvm_rm_mem_map_gpu"], r"UVM_ASSERT\s*\(\s*rm_mem->type\s*==\s*UVM_RM_MEM_TYPE_SYS\s*\)",
             "this UVM mapping path is restricted to system allocations")
    _require(funcs["nvUvmInterfaceMemoryAllocSys"], r"rm_gpu_ops_memory_alloc_sys\s*\(",
             "system allocation implementation crosses the proprietary RM boundary")
    _require(funcs["nvUvmInterfaceDupAllocation"], r"rm_gpu_ops_dup_allocation\s*\(",
             "allocation duplication implementation crosses the proprietary RM boundary")
    _require(funcs["uvm_pmm_gpu_init"],
             r"nvUvmInterfaceGetPmaObject\s*\(\s*uvm_gpu_device_handle\(gpu\)\s*,\s*&pmm->pma",
             "UVM obtains a PMA object from the individual GPU device")
    _require(funcs["alloc_root_chunk"], r"nvUvmInterfacePmaAllocPages\s*\(\s*pmm->pma",
             "PMA physical pages are allocated from that GPU PMA object")
    _require(funcs["alloc_root_chunk"], r"root_chunk_from_address\s*\(\s*pmm\s*,\s*pas\[i\]\s*\)",
             "PMA returned addresses are indexed in the owning GPU root-chunk inventory")
    _require(funcs["root_chunk_from_address"], r"gpu->mem_info\.max_allocatable_address",
             "PMA physical addresses are bounded by the owning GPU allocatable memory")
    _require(funcs["configure_address_space"], r"page_to_phys\s*\(\s*tree_alloc->handle\.page\s*\)",
             "system-aperture page-directory root comes from UVM's own page-tree page")
    _require(funcs["configure_address_space"], r"nvUvmInterfaceSetPageDirectory\s*\(",
             "UVM programs the GPU address-space page-directory root")
    _require(funcs["nvUvmInterfaceSetPageDirectory"], r"rm_gpu_ops_set_page_directory\s*\(",
             "page-directory operation crosses the proprietary RM boundary")

    init_semaphore_at = funcs["init_gpu"].find("init_semaphore_pools(gpu)")
    channel_manager_at = funcs["init_gpu"].find("uvm_channel_manager_create(gpu")
    if init_semaphore_at < 0 or channel_manager_at < 0 or init_semaphore_at >= channel_manager_at:
        raise ValueError("pinned UVM GPU init no longer creates semaphore pools before its channel manager")
    _require(funcs["init_semaphore_pools"],
             r"for_each_gpu\s*\(\s*other_gpu\s*\).*?uvm_gpu_semaphore_pool_map_gpu\s*\(\s*other_gpu->semaphore_pool\s*,\s*gpu\s*\)",
             "GPU admission maps pages in every prior GPU semaphore pool")
    _require(funcs["pool_page_alloc_buffers"],
             r"!gpu_semaphore_pool_is_secure\s*\(\s*pool\s*\).*?uvm_rm_mem_alloc_and_map_all\s*\(",
             "non-secure semaphore page allocation maps to all registered GPUs")
    _require(funcs["uvm_rm_mem_alloc_and_map_all"],
             r"uvm_rm_mem_alloc_and_map_cpu\s*\(.*?uvm_rm_mem_map_all_gpus\s*\(",
             "all-GPU memory allocation also creates a CPU mapping")
    _require(funcs["uvm_rm_mem_map_all_gpus"],
             r"for_each_gpu\s*\(\s*gpu\s*\).*?uvm_rm_mem_map_gpu\s*\(",
             "all-GPU memory mapping iterates the current UVM GPU inventory")
    _require(funcs["channel_create"],
             r"uvm_gpu_tracking_semaphore_alloc\s*\(\s*semaphore_pool\s*,\s*&channel->tracking_sem\s*\)",
             "each channel obtains its tracking semaphore from its GPU pool")
    _require(funcs["channel_pool_add"],
             r"for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*num_channels\s*;\s*i\+\+\s*\).*?channel_create\s*\(\s*pool\s*,\s*channel\s*\)",
             "channel pools eagerly create channels and their tracking semaphores")
    _require(funcs["push_acquire_tracker_entry"],
             r"uvm_channel_tracking_semaphore_get_gpu_va_in_channel\s*\(\s*entry_channel\s*,\s*channel\s*\)",
             "cross-GPU tracker acquire resolves the semaphore in the submitting channel GPU")
    _require(funcs["uvm_push_allow_dependencies_across_gpus"],
             r"return\s+!g_uvm_global\.conf_computing_enabled\s*;",
             "stock dependency policy allows cross-GPU semaphores in ordinary mode")
    _require(funcs["wait_for_other_gpus_if_needed"],
             r"if\s*\(\s*uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\)\s*return\s+NV_OK\s*;\s*return\s+uvm_tracker_wait_for_other_gpus\s*\(\s*tracker\s*,\s*gpu\s*\)",
             "disabling cross-GPU semaphore dependencies selects the CPU wait path")
    _require(funcs["uvm_tracker_wait_for_other_gpus"],
             r"wait_for_entry_with_spin\s*\(\s*entry\s*,\s*&spin\s*\).*?uvm_tracker_remove_completed\s*\(\s*tracker\s*\)",
             "CPU fallback waits for foreign GPU tracker entries then removes completed entries")

    surface = {
        "uvm_interface_prototype_count": len(prototypes),
        "os_page_import_types_searched": list(OS_PAGE_IMPORT_TYPES),
        "typed_os_page_import_prototypes": typed_page_imports,
        "typed_import_scope_note": (
            "The pinned public prototype scan found no parameters typed as Linux page, DMA, SG, "
            "dma-buf, or VMA objects. This does not exclude opaque/private RM paths or other "
            "kernel/user interfaces."
        ),
        "system_memory_allocation": {
            "api": "nvUvmInterfaceMemoryAllocSys",
            "parameters": declarations("nvUvmInterfaceMemoryAllocSys"),
            "documented_behavior": "allocates system memory and returns a GPU VA in the supplied VA space",
            "pinned_uvm_behavior": "allocates through gpu->rm_address_space and records that GPU as the allocation owner",
            "provider_neutral_import": False,
        },
        "cross_va_space_system_mapping": {
            "api": "nvUvmInterfaceDupAllocation",
            "parameters": declarations("nvUvmInterfaceDupAllocation"),
            "documented_behavior": "duplicates the RM physical handle backing a source allocation into a destination VA space; system allocations are accepted by the documented contract",
            "cross_provider_semantics": "not specified by the open header; the implementation is rm_gpu_ops_dup_allocation and the current hybrid bridge rejects cross-provider VA-space pairs before RM dispatch",
            "candidate_for_shared_semaphore_page": True,
            "cross_provider_mapping_proven": False,
        },
        "physical_memory_handle_mapping": {
            "dup_memory_api": "nvUvmInterfaceDupMemory",
            "dup_memory_parameters": declarations("nvUvmInterfaceDupMemory"),
            "external_pte_api": "nvUvmInterfaceGetExternalAllocPtes",
            "external_pte_parameters": declarations("nvUvmInterfaceGetExternalAllocPtes"),
            "interpretation": "uses RM client/device/physical-memory or duplicated-memory handles; no Linux OS-page object is present in the public prototype",
        },
        "pma_pages": {
            "alloc_parameters": declarations("nvUvmInterfacePmaAllocPages"),
            "pin_parameters": declarations("nvUvmInterfacePmaPinPages"),
            "documented_page_values": "PA base addresses allocated by the PMA object; allowed page sizes are 64 KiB, 128 KiB, or 2 MiB",
            "pinned_uvm_owner": "PMA object is obtained from the individual GPU device; returned PA indexes that GPU's root-chunk inventory and is bounded by its max_allocatable_address",
            "classification": "GPU physical-memory allocator, not host-page import",
        },
        "page_directory": {
            "parameters": declarations("nvUvmInterfaceSetPageDirectory"),
            "pinned_uvm_behavior": "programs the page-directory root for one RM VA space; UVM supplies its own page-tree physical address and receives an RM DMA address",
            "classification": "address-space page-table programming, not general OS-page import",
        },
        "rm_mapping_implementation_boundary": "rm_gpu_ops_* implementations are proprietary and were not inspected or executed",
        "typed_os_page_import_surface_declared": bool(typed_page_imports),
    }
    semaphore_surface = {
        "gpu_init_order": ["init_semaphore_pools", "uvm_channel_manager_create"],
        "init_maps_existing_pools_from_prior_gpus": True,
        "non_secure_page_alloc_maps_all_registered_gpus": True,
        "channel_pool_eagerly_allocates_tracking_semaphores": True,
        "cross_gpu_tracker_access": "acquire semaphore VA is resolved in the submitting channel GPU address space",
        "default_non_cc_policy": "cross-GPU semaphore dependencies allowed",
        "existing_cpu_wait_fallback": "wait_for_other_gpus_if_needed calls uvm_tracker_wait_for_other_gpus",
        "isolated_mode_requirements": [
            "skip cross-GPU semaphore-pool maps at GPU admission",
            "allocate/map semaphore pages only to CPU and their owner GPU",
            "force cross-GPU tracker dependencies through the existing CPU wait path",
            "keep mixed-provider peer and shared managed-memory routes fail-closed",
        ],
        "isolated_mode_implemented": False,
        "runtime_or_hardware_validated": False,
    }

    function_hashes = {
        name: hashlib.sha256(body.encode("utf-8")).hexdigest()
        for name, body in funcs.items()
    }
    return {
        "schema": "nvidia-uvm-owner-isolation-architecture-audit-v3",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "runtime_or_hardware_validated": False,
            "module_loaded_or_installed": False,
        },
        "inputs": {
            "source_archive": {"path": project_path(archive), "sha256": archive_sha},
            "c1_report": {"path": project_path(c1_report_path), "sha256": c1_sha},
            "source_files": source_files,
            "function_sha256": function_hashes,
        },
        "single_uvm": {
            "module_target": "nvidia-uvm.ko",
            "device_name": "nvidia-uvm",
            "device_registration": "one dynamically allocated dev_t and one cdev per module instance",
            "global_gpu_table": "parent_gpus",
            "global_rm_session": "one g_uvm_global.rm_session_handle per module instance",
            "file_identity_uses_fops_pointer": True,
            "ioctl_checks_the_originating_uvm_fd": True,
        },
        "bridge_registration": {
            "multi_uvm_registration": multi_registration,
            "callback_model": "one frontend registry fans out one UVM callback table to both RMs",
            "session_model": "one logical UVM session is paired across Open and legacy RMs",
        },
        "system_memory_mapping_surface": surface,
        "semaphore_dependency_surface": semaphore_surface,
        "architecture_comparison": {
            "shared_system_memory_mapping": {
                "classification": "candidate_for_full_shared_UVM_semantics",
                "required_contract": c1.get("result", {}).get("required_missing_contract"),
                "preserves_one_uvm_control_plane": True,
                "public_api_candidate": "MemoryAllocSys plus DupAllocation",
                "cross_provider_rm_support_proven": False,
                "unproven_requirements": [
                    "provider-local GPU mapping of the same system-memory backing",
                    "DMA/IOMMU address validity and lifetime for both devices",
                    "CPU/GPU visibility, semaphore ordering, invalidation and teardown",
                ],
            },
            "host_synchronized_isolated_gpu_execution": {
                "classification": "smallest_first_kernel_execution_experiment",
                "preserves_one_uvm_control_plane": True,
                "reuses_existing_host_wait_path": True,
                "requires_explicit_opt_in_mode": True,
                "requires": semaphore_surface["isolated_mode_requirements"],
                "initial_scope": [
                    "admit both provider-owned GPUs in one UVM instance",
                    "use separate per-device CUDA contexts and device-local allocations",
                    "force cross-GPU tracker dependencies to complete through host waits",
                ],
                "excluded_until_separately_proven": [
                    "cross-provider peer access and P2P",
                    "cross-provider managed-memory sharing or migration",
                    "performance equivalence to GPU-side semaphore dependencies",
                ],
                "runtime_or_hardware_validated": False,
            },
            "isolated_uvm_owners": {
                "classification": "larger_kernel_and_userspace_integration",
                "not_proven_impossible": True,
                "required_changes": [
                    "distinct module and user-visible device identities for each UVM owner",
                    "independent callback/session routing instead of the current single registry",
                    "one-process CUDA/IOCTL routing to the correct UVM fd and backend",
                    "explicit semantics for cross-owner managed memory and peer operations",
                ],
            },
            "first_experiment": "host_synchronized_isolated_gpu_execution",
            "decision_reason": (
                "A source-proven CPU wait fallback can avoid cross-GPU semaphore reads for an "
                "initial same-process, separate-context kernel test, while retaining one UVM "
                "control plane. This is narrower than full UVM/P2P interoperability and needs "
                "an explicit mode that avoids both admission-time and allocation-time semaphore "
                "maps. The full shared-memory route remains an independent follow-up because "
                "the public DupAllocation contract does not establish cross-provider RM support."
            ),
        },
        "interpretation": (
            "The source proves the current single-registry bridge rejects a second callback "
            "registration while active and the current UVM implementation binds an ioctl fd "
            "to one file-operations identity. It does not prove that separately renamed UVM "
            "modules or a complete user-space router are impossible. A host-synchronized "
            "isolated-context mode is selected only as the smallest first kernel-execution "
            "experiment; it is not implemented or validated. The public UVM prototypes expose "
            "no typed Linux-page/DMA/SG/dma-buf import surface. MemoryAllocSys plus DupAllocation "
            "is a candidate system-memory mapping path, but cross-provider RM semantics are "
            "undocumented and hidden behind proprietary rm_gpu_ops. PMA returns GPU physical "
            "addresses owned by a per-device PMA object; SetPageDirectory programs one GPU VA "
            "space's page-table root. Neither is a generic host-page import. DMA, coherence, "
            "semaphore correctness and hardware behavior remain unvalidated."
        ),
    }


def write_json(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
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
    parser.add_argument("--bridge", type=Path, default=BRIDGE_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root, args.bridge)
        if args.output:
            write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
