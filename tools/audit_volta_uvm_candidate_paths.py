#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trace R580 Volta UVM capability consumers into the R595 GV100 candidate.

This is a pinned static-source audit. It records source anchors for the old
Volta properties and the candidate mechanisms selected in their place; it does
not certify their runtime semantics or behavior on hardware.
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
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    checked_source_archive_root,
    extract_r580_uvm_c_sources,
)
from tools.audit_volta_uvm_capability_map import CAPABILITIES as R580_CAPABILITIES  # noqa: E402
from tools.audit_volta_uvm_capability_map import (  # noqa: E402
    _mask_c_comments_and_literals,
    _splice_c_lines,
)
from tools.audit_volta_uvm_property_delta import (  # noqa: E402
    scan_live_identifier_occurrences,
)
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    R580_SOURCE_ROOT,
    read_member,
)

DEFAULT_CANDIDATE_ROOT = ROOT / (
    "build/experiments/r595-gv100-hal-standard-nvidia-frontend-"
    "v15-20261028T004147Z"
)
DEFAULT_REPORT = ROOT / "evidence/volta-uvm-r580-r595-v15-capability-paths-v9-20261102.json"
EXPECTED_CANDIDATE_HAL_SHA256 = "3a7c5f6f892102663af00fdcb9e638a3a96a2b8cddd00af25d9054169106c248"


# Anchors are intentionally narrow. Each demonstrates a source path, not a
# claim that an inherited or newly selected callback is hardware-correct.
R595_CAPABILITY_PATHS = {
    "va_invalidate_supported": {
        "disposition": "volta-host-hal-callback-selected",
        "interpretation": (
            "The modern batch path dispatches invalidation through host_hal; "
            "the GV100 candidate row selects the Volta VA callback."
        ),
        "validation_needed": "Validate address, page-size, and membar semantics on GV100 hardware.",
        "anchors": [
            ("uvm_tlb_batch.c", "tree->gpu->parent->host_hal->tlb_invalidate_va(push,", "UVM caller"),
            ("uvm_hal.c", ".tlb_invalidate_va = uvm_hal_volta_host_tlb_invalidate_va,", "GV100 host HAL selection"),
            ("uvm_volta_host.c", "void uvm_hal_volta_host_tlb_invalidate_va(", "Volta callback definition"),
        ],
    },
    "va_range_invalidate_supported": {
        "disposition": "range-batching-policy-reworked",
        "interpretation": (
            "The candidate batches range records, uses max_ranges=8 to choose "
            "between recorded-range invalidations and invalidate-all, and "
            "dispatches each recorded range through the Volta VA callback. "
            "This is not the old capability-bit branch."
        ),
        "validation_needed": "Check range count, fallback threshold, ordering, and invalidation coverage on hardware.",
        "anchors": [
            ("uvm_volta.c", "parent_gpu->tlb_batch.max_ranges = 8;", "GV100 batch threshold"),
            ("uvm_tlb_batch.c", "batch->total_ranges > batch->tree->gpu->parent->tlb_batch.max_ranges", "all-invalidate fallback threshold"),
            ("uvm_tlb_batch.c", "tree->gpu->parent->host_hal->tlb_invalidate_va(push,", "recorded-range dispatch"),
            ("uvm_hal.c", ".tlb_invalidate_va = uvm_hal_volta_host_tlb_invalidate_va,", "GV100 host HAL selection"),
        ],
    },
    "can_map_sysmem_with_large_pages": {
        "disposition": "page-tree-and-mmu-hal-reworked",
        "interpretation": (
            "R595 selects sysmem mapping page sizes from the active page tree. "
            "The candidate's no-argument GV100 MMU factory wraps the Volta "
            "64 KiB mode and clones the Pascal MMU operations before applying "
            "Volta PTE/PDE callbacks; this establishes a static candidate path, "
            "not successful large-page sysmem mapping."
        ),
        "validation_needed": "Validate exposed page-size masks, CPU-page contiguity, PTE formats, and sysmem mappings on GV100.",
        "anchors": [
            ("uvm_mem.c", "return uvm_mmu_biggest_page_size_up_to(gpu_page_tree, mem->chunk_size);", "sysmem page-size selection"),
            ("uvm_hal.c", ".mmu_mode_hal = uvm_hal_mmu_mode_volta_r595,", "GV100 MMU HAL selection"),
            ("uvm_volta_mmu.c", "volta_mmu_mode_hal = *pascal_mmu_mode_hal;", "Pascal MMU operation inheritance"),
            ("uvm_volta_mmu.c", "volta_mmu_mode_hal.make_pte = make_pte_volta;", "Volta PTE override"),
            ("uvm_volta_mmu.c", "return uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K);", "64 KiB wrapper"),
        ],
    },
    "prefetch_fault_supported": {
        "disposition": "runtime-state-and-hal-reworked-with-guard-delta",
        "interpretation": (
            "R595 uses runtime prefetch state and dispatches through the arch "
            "HAL. The GV100 candidate selects Turing MMU prefetch helpers; the "
            "callback closure audit found the same low-level control operation, "
            "but the R580 prefetch_supported assertion is absent from this caller."
        ),
        "validation_needed": "Resolve the removed capability guard and validate prefetch-fault control and delivery on GV100.",
        "anchors": [
            ("uvm_gpu_replayable_faults.c", "parent_gpu->fault_buffer.prefetch_faults_enabled = true;", "runtime prefetch state"),
            ("uvm_gpu_replayable_faults.c", "parent_gpu->arch_hal->enable_prefetch_faults(parent_gpu);", "architecture HAL dispatch"),
            ("uvm_hal.c", ".enable_prefetch_faults = uvm_hal_turing_mmu_enable_prefetch_faults,", "GV100 prefetch callback selection"),
            ("uvm_hal.c", ".disable_prefetch_faults = uvm_hal_turing_mmu_disable_prefetch_faults,", "GV100 prefetch callback selection"),
        ],
    },
    "gpfifo_in_vidmem_supported": {
        "disposition": "location-policy-forwarded-to-rm",
        "interpretation": (
            "The old capability gate is absent. The candidate policy can choose "
            "VID memory for GPFIFO and forwards that location in channel "
            "allocation parameters; this source path does not prove RM acceptance."
        ),
        "validation_needed": "Validate GV100 RM allocation, mapping, coherency, and channel execution with GPFIFO in video memory.",
        "anchors": [
            ("uvm_channel.c", "manager->conf.gpfifo_loc = UVM_BUFFER_LOCATION_VID;", "VID location policy"),
            ("uvm_channel.c", "channel_alloc_params.gpFifoLoc = manager->conf.gpfifo_loc;", "RM channel-allocation request"),
            ("uvm_channel.c", "nvUvmInterfaceChannelAllocate(channel_get_tsg(channel),", "RM allocation call"),
        ],
    },
    "replayable_faults_supported": {
        "disposition": "mandatory-fault-buffer-init-with-gv100-hal-row",
        "interpretation": (
            "The modern ISR path initializes the fault buffer without the old "
            "capability branch. The candidate contains a GV100 fault-buffer "
            "HAL row; class and callback presence do not prove RM interrupt or replay behavior."
        ),
        "validation_needed": "Validate RM fault-buffer metadata, interrupts, replay, recovery, and teardown on GV100.",
        "anchors": [
            ("uvm_gpu_isr.c", "status = uvm_parent_gpu_fault_buffer_init(parent_gpu);", "fault-buffer initialization"),
            ("uvm_hal.c", ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,\n        .u.fault_buffer_ops = {", "GV100 fault-buffer row"),
            ("uvm_hal.c", ".read_put = uvm_hal_volta_fault_buffer_read_put,", "Volta fault-buffer callback"),
        ],
    },
    "non_replayable_faults_supported": {
        "disposition": "mandatory-init-with-gv100-fault-buffer-row",
        "interpretation": (
            "Modern fault-buffer initialization invokes the non-replayable "
            "path unconditionally once replayable setup succeeds. The GV100 "
            "table row is present, but entry layout and RM-provided buffer data remain unverified."
        ),
        "validation_needed": "Validate GV100 non-replayable entry sizing, ISR delivery, and error handling on hardware.",
        "anchors": [
            ("uvm_gpu_replayable_faults.c", "status = uvm_parent_gpu_fault_buffer_init_non_replayable_faults(parent_gpu);", "non-replayable init call"),
            ("uvm_hal.c", ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,\n        .u.fault_buffer_ops = {", "GV100 fault-buffer row"),
            ("uvm_hal.c", ".read_get = uvm_hal_volta_fault_buffer_read_get,", "Volta fault-buffer callback"),
        ],
    },
    "fault_cancel_va_supported": {
        "disposition": "mandatory-host-hal-callback-selected",
        "interpretation": (
            "R595 dispatches VA cancellation through host_hal. The candidate "
            "GV100 host row selects the Volta cancellation callback; the old "
            "capability fallback is no longer represented as a property bit."
        ),
        "validation_needed": "Validate VA targeting, cancellation mode, and synchronization on GV100.",
        "anchors": [
            ("uvm_gpu_replayable_faults.c", "gpu->parent->host_hal->cancel_faults_va(&push, pdb, fault_entry, cancel_va_mode);", "fault cancellation call"),
            ("uvm_hal.c", ".cancel_faults_va = uvm_hal_volta_cancel_faults_va,", "GV100 host HAL selection"),
            ("uvm_volta_host.c", "void uvm_hal_volta_cancel_faults_va(", "Volta callback definition"),
        ],
    },
    "scoped_atomics_supported": {
        "disposition": "legacy-system-wide-atomics-uapi-removed",
        "interpretation": (
            "R580 sets this flag for GV100 and uses it only to reject the legacy "
            "system-wide-atomics UVM ioctl policy. The R595 candidate contains "
            "neither ioctl definition nor route nor policy helper, so this is a "
            "retired UVM policy surface rather than an unmapped modern HAL capability. "
            "This says nothing about CUDA C++ atomic-scope support or older user-mode ABI compatibility."
        ),
        "validation_needed": "Confirm the R595 user-mode ABI does not issue the retired ioctls, and separately validate system-scope atomic correctness on GV100 hardware.",
        "anchors": [],
        "absent_candidate_tokens": [
            ("uvm_ioctl.h", "UVM_ENABLE_SYSTEM_WIDE_ATOMICS", "legacy enable ioctl definition"),
            ("uvm_ioctl.h", "UVM_DISABLE_SYSTEM_WIDE_ATOMICS", "legacy disable ioctl definition"),
            ("uvm.c", "UVM_ENABLE_SYSTEM_WIDE_ATOMICS", "legacy enable ioctl route"),
            ("uvm.c", "UVM_DISABLE_SYSTEM_WIDE_ATOMICS", "legacy disable ioctl route"),
            ("uvm_api.h", "uvm_api_enable_system_wide_atomics", "legacy enable handler declaration"),
            ("uvm_api.h", "uvm_api_disable_system_wide_atomics", "legacy disable handler declaration"),
            ("uvm_policy.c", "system_wide_atomics_set", "legacy policy implementation"),
        ],
    },
    "sparse_mappings_supported": {
        "disposition": "mmu-hal-sparse-pte-dispatch-with-pascal-inheritance",
        "interpretation": (
            "External sparse mappings call the active MMU HAL. The candidate "
            "Volta MMU mode clones Pascal operations and overrides PTE/PDE "
            "builders, so its sparse-PTE callback is inherited; the GV100 encoding is not hardware-verified."
        ),
        "validation_needed": "Validate the inherited sparse PTE encoding and invalid-PTE fault behavior on GV100.",
        "anchors": [
            ("uvm_map_external.c", "return range_vec->tree->hal->make_sparse_pte();", "sparse-PTE HAL dispatch"),
            ("uvm_volta_mmu.c", "volta_mmu_mode_hal = *pascal_mmu_mode_hal;", "Pascal MMU operation inheritance"),
            ("uvm_volta_mmu.c", "volta_mmu_mode_hal.make_pte = make_pte_volta;", "Volta PTE override"),
            ("uvm_volta_mmu.c", "volta_mmu_mode_hal.make_pde = make_pde_volta;", "Volta PDE override"),
        ],
    },
    "plc_supported": {
        "disposition": "gv100-restriction-restored-before-unmap",
        "interpretation": (
            "The candidate replaces R580's false PLC property with an explicit "
            "GV100 rejection of EnabledNoPlc, returning before overlap removal. "
            "This is a candidate-specific compatibility guard, not stock R595 behavior."
        ),
        "validation_needed": "Keep the exact rejection status and ordering under regression tests; validate RM and external-map behavior on a safe GV100 canary.",
        "anchors": [
            ("uvm_map_external.c", "if ((map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc) &&", "candidate GV100 restriction"),
            ("uvm_map_external.c", "(mapping_gpu->parent->rm_info.gpuArch == NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100))", "GV100 predicate"),
            ("uvm_map_external.c", "return NV_ERR_INVALID_DEVICE;", "preserved R580 status"),
            ("uvm_map_external.c", "status = uvm_unmap_external_in_range(external_range, mapping_gpu, base, base + length - 1, NULL);", "later overlap removal"),
        ],
    },
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def source_anchors(path: Path, anchor: str) -> list[dict[str, int]]:
    """Return source line numbers containing an exact, reviewable anchor."""
    if not anchor:
        raise ValueError("source anchor must not be empty")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"source anchor input must be a regular non-symlink file: {path}")
    logical, physical_lines = _splice_c_lines(path.read_text(encoding="utf-8"))
    code = _mask_c_comments_and_literals(logical)
    matches = []
    offset = 0
    while True:
        index = code.find(anchor, offset)
        if index < 0:
            break
        if index < len(physical_lines):
            matches.append({"line": physical_lines[index]})
        offset = index + max(1, len(anchor))
    return matches


def _extract_function(path: Path, declaration: str) -> dict:
    """Extract one C function using a comment/literal-masked brace scan."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"function input must be a regular non-symlink file: {path}")
    logical, physical_lines = _splice_c_lines(path.read_text(encoding="utf-8"))
    code = _mask_c_comments_and_literals(logical)
    start = code.find(declaration)
    if start < 0:
        raise ValueError(f"C function declaration is missing: {path}: {declaration}")
    if code.find(declaration, start + len(declaration)) >= 0:
        raise ValueError(f"C function declaration is ambiguous: {path}: {declaration}")
    opening = code.find("{", start + len(declaration))
    if opening < 0:
        raise ValueError(f"C function body is missing: {path}: {declaration}")

    depth = 0
    closing = None
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        raise ValueError(f"C function body has unbalanced braces: {path}: {declaration}")

    masked_source = code[start:closing + 1]
    normalized = "".join(masked_source.split()).encode("utf-8")
    return {
        "path": path.name,
        "sha256": sha256_file(path),
        "start_line": physical_lines[start],
        "end_line": physical_lines[closing],
        "normalized_sha256": sha256_bytes(normalized),
        "_masked_source": masked_source,
    }


def _required_source_anchor(source_root: Path, relative_path: str, anchor: str, role: str) -> dict:
    path = source_root / relative_path
    matches = source_anchors(path, anchor)
    if not matches:
        raise ValueError(f"required prefetch source anchor is missing: {relative_path}: {anchor}")
    return {
        "path": relative_path,
        "sha256": sha256_file(path),
        "role": role,
        "anchor": anchor,
        "matches": matches,
    }


def _required_raw_source_anchor(source_root: Path, relative_path: str, anchor: str, role: str) -> dict:
    """Capture an exact comment/documentation anchor that code masking removes."""
    path = source_root / relative_path
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required raw source input is missing or unsafe: {relative_path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    matches = [{"line": number} for number, line in enumerate(lines, 1) if anchor in line]
    if not matches:
        raise ValueError(f"required raw source anchor is missing: {relative_path}: {anchor}")
    return {
        "path": relative_path,
        "sha256": sha256_file(path),
        "role": role,
        "anchor": anchor,
        "matches": matches,
    }


def _normalized_function(function: dict) -> str:
    return " ".join(function["_masked_source"].split())


def build_p2p_direction_mapping_audit(candidate_root: Path) -> dict:
    """Trace R595 UVM's directional P2P consumer contract without guessing RM output semantics."""
    uvm_root = candidate_root / "nvidia-uvm"
    get_caps = _extract_function(
        uvm_root / "uvm_gpu.c", "static NV_STATUS get_parent_p2p_caps("
    )
    peers_init = _extract_function(
        uvm_root / "uvm_gpu.c", "static NV_STATUS parent_peers_init("
    )
    peer_aperture = _extract_function(
        uvm_root / "uvm_gpu.c", "static uvm_aperture_t parent_gpu_peer_aperture("
    )
    peer_dma_range = _extract_function(
        uvm_root / "uvm_gpu.c", "static bool gpu_phys_address_is_bar1p2p_peer("
    )
    interface = _extract_function(
        candidate_root / "nvidia/nv_uvm_interface.c",
        "NV_STATUS nvUvmInterfaceGetP2PCaps(",
    )

    get_caps_code = _normalized_function(get_caps)
    init_code = _normalized_function(peers_init)
    aperture_code = _normalized_function(peer_aperture)
    dma_code = _normalized_function(peer_dma_range)
    interface_code = _normalized_function(interface)

    expected_handle_order = (
        "if (uvm_parent_id_value(parent_gpu0->id) < uvm_parent_id_value(parent_gpu1->id)) { "
        "rm_device0 = parent_gpu0->rm_device; rm_device1 = parent_gpu1->rm_device; } else { "
        "rm_device0 = parent_gpu1->rm_device; rm_device1 = parent_gpu0->rm_device; } "
        "memset(p2p_caps_params, 0, sizeof(*p2p_caps_params)); status = uvm_rm_locked_call("
        "nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, p2p_caps_params));"
    )
    expected_peer_index = (
        "if (uvm_parent_id_value(local->id) < uvm_parent_id_value(remote->id)) peer_index = 0; "
        "else peer_index = 1;"
    )
    expected_dma_index = (
        "const int peer_index = (uvm_parent_id_cmp(gpu->parent->id, peer_parent_gpu->id) < 0) ? 0 : 1;"
    )
    checks = {
        "rm_handles_normalized_to_ascending_parent_id": expected_handle_order in get_caps_code,
        "interface_forwards_handle_order_unchanged": (
            "status = rm_gpu_ops_get_p2p_caps(sp, (gpuDeviceHandle)device1, "
            "(gpuDeviceHandle)device2, p2pCapsParams);" in interface_code
        ),
        "atomic_capability_indices_copied_without_swapping": all(
            f"parent_peer_caps->bar1_p2p_pcie_atomics_enabled[{index}] = "
            f"p2p_caps_params.bar1PcieAtomics[{index}];" in init_code
            for index in (0, 1)
        ),
        "lower_id_to_higher_id_uses_capability_index_zero": (
            expected_peer_index in aperture_code
            and "const bool enable_atomics = parent_peer_caps->bar1_p2p_pcie_atomics_enabled[peer_index];" in aperture_code
        ),
        "bar1_dma_range_uses_same_directional_index": (
            expected_dma_index in dma_code
            and "peer_caps->bar1_p2p_dma_base_address[peer_index]" in dma_code
            and "peer_caps->bar1_p2p_dma_size[peer_index]" in dma_code
        ),
    }
    if not all(checks.values()):
        missing = ", ".join(name for name, passed in checks.items() if not passed)
        raise ValueError(f"candidate UVM P2P direction mapping changed or is incomplete: {missing}")

    type_header = "common/inc/nv_uvm_types.h"
    peer_contract = _required_raw_source_anchor(
        candidate_root, type_header,
        "// Out: peerId[i] contains gpu[i]'s peer id of gpu[1 - i]. Only defined if",
        "documented peer-ID direction contract",
    )
    atomics_comment = _required_raw_source_anchor(
        candidate_root, type_header,
        "// True if GPU i can use PCIe atomics on locations in GPU[i-1]",
        "PCIe-atomics direction comment requiring clarification",
    )

    # The RM operation is called through a function-pointer ABI. Search only the
    # pinned candidate C/H source tree and report absence as a source-scope fact.
    definition_pattern = re.compile(
        r"\brm_gpu_ops_get_p2p_caps\s*\([^;{}]*\)\s*\{", re.DOTALL
    )
    definitions = []
    source_paths = []
    for path in candidate_root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"candidate RM producer scan rejects symlink: {path}")
        if not path.is_file() or path.suffix not in {".c", ".h"}:
            continue
        source_paths.append(path)
        logical, physical_lines = _splice_c_lines(path.read_text(encoding="utf-8"))
        masked = _mask_c_comments_and_literals(logical)
        for match in definition_pattern.finditer(masked):
            definitions.append({
                "path": path.relative_to(candidate_root).as_posix(),
                "line": physical_lines[match.start()],
            })
    if definitions:
        raise ValueError(f"RM P2P capability producer unexpectedly found in candidate source: {definitions}")

    rm_declaration = _required_source_anchor(
        candidate_root, "common/inc/rm-gpu-ops.h",
        "rm_gpu_ops_get_p2p_caps(", "declared RM operation with no C/H definition in candidate tree",
    )
    return {
        "classification": "static-r595-uvm-p2p-direction-consumer-audit",
        "candidate_source_anchors": [
            {"source_path": "nvidia-uvm/uvm_gpu.c", **{k: v for k, v in get_caps.items() if not k.startswith("_")},
             "role": "sorts RM handles by ascending UVM parent GPU ID before querying capabilities"},
            {"source_path": "nvidia-uvm/uvm_gpu.c", **{k: v for k, v in peers_init.items() if not k.startswith("_")},
             "role": "copies per-direction capability indices without permutation"},
            {"source_path": "nvidia-uvm/uvm_gpu.c", **{k: v for k, v in peer_aperture.items() if not k.startswith("_")},
             "role": "selects index zero for lower-ID local GPU and index one for reverse direction"},
            {"source_path": "nvidia-uvm/uvm_gpu.c", **{k: v for k, v in peer_dma_range.items() if not k.startswith("_")},
             "role": "uses the same local-to-remote direction index for BAR1 DMA range matching"},
            {"source_path": "nvidia/nv_uvm_interface.c", **{k: v for k, v in interface.items() if not k.startswith("_")},
             "role": "forwards the two device handles to RM in the order received"},
            peer_contract,
            atomics_comment,
            rm_declaration,
        ],
        "source_scan": {
            "c_header_file_count": len(source_paths),
            "rm_gpu_ops_get_p2p_caps_definition_count": 0,
            "qualification": "no-definition-found-in-scanned-candidate-C-H-source",
        },
        "consumer_direction_contract": {
            "capability_query_handle_order": "ascending UVM parent GPU ID",
            "bar1PcieAtomics_index_0": "consumer uses for lower-ID local GPU accessing higher-ID peer",
            "bar1PcieAtomics_index_1": "consumer uses for higher-ID local GPU accessing lower-ID peer",
            "index_copy_behavior": "UVM copies indices 0 and 1 without swapping",
            "interpretation": "Static consumer-side direction only; it does not establish how RM populates the fields or whether hardware honors the reported capability.",
        },
        "header_comment_review": {
            "peer_ids_comment_direction": "gpu[i] -> gpu[1 - i]",
            "bar1_pcie_atomics_comment_direction": "GPU i -> GPU[i-1]",
            "ambiguity": "The atomics direction comment is ambiguous: it leaves index zero undefined unless modulo-two indexing is intended; producer semantics are not established by the available open C/H source.",
        },
        "runtime_or_hardware_validated": False,
        "rm_capability_values_observed": False,
        "validation_needed": "Inspect the authorized RM producer contract or capture asymmetric [true,false] and [false,true] capability responses on a safe V100-capable canary; verify aperture choice and numeric transfer integrity in both directions.",
    }


def _extract_braced_region(path: Path, declaration: str) -> dict:
    """Extract a uniquely named C initializer/function region with balanced braces."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"braced-region input must be a regular non-symlink file: {path}")
    logical, physical_lines = _splice_c_lines(path.read_text(encoding="utf-8"))
    code = _mask_c_comments_and_literals(logical)
    start = code.find(declaration)
    if start < 0:
        raise ValueError(f"C region declaration is missing: {path}: {declaration}")
    if code.find(declaration, start + len(declaration)) >= 0:
        raise ValueError(f"C region declaration is ambiguous: {path}: {declaration}")
    opening = code.find("{", start + len(declaration))
    if opening < 0:
        raise ValueError(f"C region opening brace is missing: {path}: {declaration}")
    depth = 0
    closing = None
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        raise ValueError(f"C region has unbalanced braces: {path}: {declaration}")
    return {
        "path": path.name,
        "sha256": sha256_file(path),
        "_start_offset": opening,
        "_masked_source": code[opening:closing + 1],
        "_physical_lines": physical_lines[opening:closing + 1],
    }


def _extract_architecture_row(source_root: Path, architecture: str) -> dict:
    path = source_root / "uvm_hal.c"
    table = _extract_braced_region(path, "static uvm_hal_class_ops_t arch_table[]")
    code = table["_masked_source"]
    prefix = ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_"
    marker = f"{prefix}{architecture},"
    start = code.find(marker)
    if start < 0:
        raise ValueError(f"architecture row is missing from arch_table: {architecture}")
    if code.find(marker, start + len(marker)) >= 0:
        raise ValueError(f"architecture row is ambiguous in arch_table: {architecture}")
    next_row = code.find(prefix, start + len(marker))
    end = next_row if next_row >= 0 else len(code) - 1
    row = code[start:end]
    return {
        "path": "uvm_hal.c",
        "sha256": table["sha256"],
        "architecture": architecture,
        "start_line": table["_physical_lines"][start],
        "end_line": table["_physical_lines"][max(start, end - 1)],
        "parent_gp100": ".parent_id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100," in row,
        "enable_pascal_callback": ".enable_prefetch_faults = uvm_hal_pascal_mmu_enable_prefetch_faults," in row,
        "enable_turing_callback": ".enable_prefetch_faults = uvm_hal_turing_mmu_enable_prefetch_faults," in row,
        "disable_turing_callback": ".disable_prefetch_faults = uvm_hal_turing_mmu_disable_prefetch_faults," in row,
    }


def build_prefetch_callback_comparison(r580_root: Path, candidate_uvm_root: Path) -> dict:
    """Compare Volta prefetch control and its callback guards across branches."""
    r580_gp100_row = _extract_architecture_row(r580_root, "GP100")
    r580_gv100_row = _extract_architecture_row(r580_root, "GV100")
    candidate_gv100_row = _extract_architecture_row(candidate_uvm_root, "GV100")
    if not r580_gp100_row["enable_pascal_callback"] or not r580_gv100_row["parent_gp100"]:
        raise ValueError("R580 GV100 prefetch callback inheritance differs from the pinned path")
    if not candidate_gv100_row["enable_turing_callback"] or not candidate_gv100_row["disable_turing_callback"]:
        raise ValueError("candidate GV100 row does not select both Turing prefetch callbacks")

    old_helper = _extract_function(
        r580_root / "uvm_pascal_mmu.c",
        "static void mmu_set_prefetch_faults(uvm_parent_gpu_t *parent_gpu, bool enable)",
    )
    candidate_helper = _extract_function(
        candidate_uvm_root / "uvm_turing_mmu.c",
        "static void mmu_set_prefetch_faults(uvm_parent_gpu_t *parent_gpu, bool enable)",
    )
    if old_helper["normalized_sha256"] != candidate_helper["normalized_sha256"]:
        raise ValueError("R580 and candidate prefetch MMU control helpers differ")

    old_enable = _extract_function(
        r580_root / "uvm_pascal_mmu.c",
        "void uvm_hal_pascal_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)",
    )
    candidate_enable = _extract_function(
        candidate_uvm_root / "uvm_turing_mmu.c",
        "void uvm_hal_turing_mmu_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)",
    )
    old_guard = "UVM_ASSERT(parent_gpu->prefetch_fault_supported);" in old_enable["_masked_source"]
    candidate_guard = "UVM_ASSERT(parent_gpu->prefetch_fault_supported);" in candidate_enable["_masked_source"]
    if not old_guard or candidate_guard:
        raise ValueError("prefetch callback guard delta differs from the pinned R580/R595 candidate")

    old_anchors = [
        _required_source_anchor(r580_root, "uvm_hal.c", ".enable_prefetch_faults = uvm_hal_pascal_mmu_enable_prefetch_faults,", "GP100 inherited prefetch callback"),
        _required_source_anchor(r580_root, "uvm_hal.c", ".parent_id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100,", "GV100 inherits the GP100 architecture row"),
        _required_source_anchor(r580_root, "uvm_volta.c", "parent_gpu->prefetch_fault_supported = true;", "GV100 prefetch capability initialization"),
        _required_source_anchor(r580_root, "uvm_gpu_replayable_faults.c", "parent_gpu->fault_buffer.prefetch_faults_enabled = parent_gpu->prefetch_fault_supported;", "capability-gated replayable-fault initialization"),
    ]
    candidate_anchors = [
        _required_source_anchor(candidate_uvm_root, "uvm_hal.c", ".id = NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,", "candidate GV100 architecture row"),
        _required_source_anchor(candidate_uvm_root, "uvm_hal.c", ".enable_prefetch_faults = uvm_hal_turing_mmu_enable_prefetch_faults,", "direct GV100 Turing prefetch callback"),
        _required_source_anchor(candidate_uvm_root, "uvm_hal.c", ".disable_prefetch_faults = uvm_hal_turing_mmu_disable_prefetch_faults,", "direct GV100 Turing prefetch callback"),
        _required_source_anchor(candidate_uvm_root, "uvm_gpu_replayable_faults.c", "parent_gpu->fault_buffer.prefetch_faults_enabled = true;", "unconditional prefetch state at replayable-fault initialization"),
        _required_source_anchor(candidate_uvm_root, "uvm_gpu_replayable_faults.c", "parent_gpu->arch_hal->enable_prefetch_faults(parent_gpu);", "architecture-dispatched prefetch control"),
    ]

    return {
        "classification": "static-volta-prefetch-control-comparison",
        "r580_callback_inheritance": "GV100 parent_id selects GP100 arch row; GP100 row selects Pascal MMU enable callback",
        "candidate_callback_selection": "GV100 row directly selects Turing MMU enable/disable callbacks",
        "selected_architecture_rows": {
            "r580_gp100": r580_gp100_row,
            "r580_gv100": r580_gv100_row,
            "candidate_gv100": candidate_gv100_row,
        },
        "control_helper": {
            "r580": {key: value for key, value in old_helper.items() if not key.startswith("_")},
            "candidate": {key: value for key, value in candidate_helper.items() if not key.startswith("_")},
            "identical_after_comments_literals_and_whitespace_masked": True,
            "operation": "If pPrefetchCtrl is null, call nvUvmInterfaceTogglePrefetchFaults; otherwise read-modify-write FAULT_CTRL.PRF_FILTER to SEND_ALL or SEND_NONE.",
        },
        "enable_wrapper_guard": {
            "r580_prefetch_fault_supported_assertion": old_guard,
            "candidate_prefetch_fault_supported_assertion": candidate_guard,
            "r580_state_initialization": "Volta sets prefetch_fault_supported=true; replayable-fault initialization copies that capability into prefetch_faults_enabled.",
            "candidate_state_initialization": "Replayable-fault initialization sets prefetch_faults_enabled=true before dispatching the GV100 HAL callback.",
            "interpretation": "For the GV100 path, the removed assertion is replaced by explicit modern callback selection and unconditional fault-buffer prefetch enablement. Source establishes this candidate path, not hardware correctness or delivery behavior.",
        },
        "r580_source_anchors": old_anchors,
        "candidate_source_anchors": candidate_anchors,
        "runtime_or_hardware_validated": False,
        "validation_needed": "On a GV100 canary, validate RM-provided prefetch control mapping, enable/disable transitions, prefetch-fault delivery, replay, suspend/resume, and teardown.",
    }


def build_volta_noncoherent_aperture_comparison(r580_root: Path, candidate_uvm_root: Path) -> dict:
    """Trace the modern SYS_NON_COHERENT peer path through Volta MMU and CE HALs."""
    old_pte = _extract_function(r580_root / "uvm_volta_mmu.c", "static NvU64 make_pte_volta(")
    candidate_pte = _extract_function(candidate_uvm_root / "uvm_volta_mmu.c", "static NvU64 make_pte_volta(")
    old_peer = _extract_function(r580_root / "uvm_gpu.c", "static uvm_aperture_t parent_gpu_peer_aperture(")
    candidate_peer = _extract_function(candidate_uvm_root / "uvm_gpu.c", "static uvm_aperture_t parent_gpu_peer_aperture(")
    old_ce = _extract_function(r580_root / "uvm_volta_ce.c", "static NvU32 ce_aperture(")
    candidate_ce = _extract_function(candidate_uvm_root / "uvm_volta_ce.c", "static NvU32 ce_aperture(")

    old_pte_code = old_pte["_masked_source"]
    candidate_pte_code = candidate_pte["_masked_source"]
    old_peer_code = old_peer["_masked_source"]
    candidate_peer_code = candidate_peer["_masked_source"]
    old_ce_code = old_ce["_masked_source"]
    candidate_ce_code = candidate_ce["_masked_source"]

    candidate_checks = {
        "pte_sets_noncoherent_aperture_value": "aperture == UVM_APERTURE_SYS_NON_COHERENT" in candidate_pte_code and
            "NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY" in candidate_pte_code,
        "pte_uses_system_address_for_noncoherent_aperture": "aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT" in candidate_pte_code,
        "bar1_p2p_selects_noncoherent_when_pcie_atomics_unavailable": "parent_peer_caps->link_type == UVM_GPU_LINK_PCIE_BAR1" in candidate_peer_code and
            "bar1_p2p_pcie_atomics_enabled[peer_index]" in candidate_peer_code and
            "UVM_APERTURE_SYS_NON_COHERENT" in candidate_peer_code,
        "volta_ce_maps_noncoherent_sysmem": "UVM_APERTURE_SYS_NON_COHERENT" in candidate_ce_code and
            "NONCOHERENT_SYSMEM" in candidate_ce_code,
    }
    if not all(candidate_checks.values()):
        raise ValueError("candidate Volta SYS_NON_COHERENT PTE/P2P/CE path is incomplete")
    if any("UVM_APERTURE_SYS_NON_COHERENT" in code for code in (old_pte_code, old_peer_code, old_ce_code)):
        raise ValueError("R580 unexpectedly contains the candidate Volta SYS_NON_COHERENT path")

    hardware_anchors = []
    for source_root, label in ((r580_root, "r580"), (candidate_uvm_root, "candidate")):
        header = source_root / "hwref/volta/gv100/dev_mmu.h"
        aperture_field = "#define NV_MMU_VER2_PTE_APERTURE"
        noncoherent_value = "#define NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY"
        for anchor, role in (
            (aperture_field, f"{label} GV100 VER2 PTE aperture field"),
            (noncoherent_value, f"{label} GV100 VER2 noncoherent aperture encoding"),
        ):
            hardware_anchors.append(_required_source_anchor(source_root, "hwref/volta/gv100/dev_mmu.h", anchor, role))

    candidate_semantics = [
        _required_source_anchor(candidate_uvm_root, "uvm_gpu.c", "return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT;", "PCIe BAR1 peer atomic-capability selection"),
        _required_source_anchor(candidate_uvm_root, "uvm_gpu.c", "address += parent_peer_caps->bar1_p2p_dma_base_address[peer_index];", "BAR1 peer DMA address translation"),
        _required_source_anchor(candidate_uvm_root, "uvm_get_rm_ptes_test.c", "pte = hal->make_pte(aperture,", "UVM built-in RM-PTE validation test invokes the Volta PTE builder"),
        _required_source_anchor(candidate_uvm_root, "uvm_map_external.c", "nvUvmInterfaceGetExternalAllocPtes(", "external allocation PTEs are requested from RM"),
        _required_source_anchor(candidate_uvm_root, "uvm_get_rm_ptes_test.c", "aperture = get_aperture(", "built-in test derives the expected external-mapping aperture"),
    ]

    old_header_anchors = [
        _required_source_anchor(r580_root, "hwref/volta/gv100/dev_mmu.h", "#define NV_MMU_VER2_PTE_APERTURE", "R580 GV100 VER2 PTE aperture field"),
        _required_source_anchor(r580_root, "hwref/volta/gv100/dev_mmu.h", "#define NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY", "R580 GV100 VER2 noncoherent aperture encoding"),
        _required_source_anchor(r580_root, "clc3b5.h", "NVC3B5_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM", "R580 GV100 copy-engine noncoherent source mode"),
        _required_source_anchor(r580_root, "clc3b5.h", "NVC3B5_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM", "R580 GV100 copy-engine noncoherent destination mode"),
    ]
    candidate_ce_header_anchors = [
        _required_source_anchor(candidate_uvm_root, "clc3b5.h", "NVC3B5_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM", "candidate GV100 copy-engine noncoherent source mode"),
        _required_source_anchor(candidate_uvm_root, "clc3b5.h", "NVC3B5_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM", "candidate GV100 copy-engine noncoherent destination mode"),
    ]

    return {
        "classification": "static-volta-noncoherent-aperture-callpath-comparison",
        "r580": {
            "pte_builder": {key: value for key, value in old_pte.items() if not key.startswith("_")},
            "peer_aperture": {key: value for key, value in old_peer.items() if not key.startswith("_")},
            "copy_engine_aperture": {key: value for key, value in old_ce.items() if not key.startswith("_")},
            "peer_selection": "parent_gpu_peer_aperture returns UVM_APERTURE_PEER(peer_ids[peer_index]) for all links.",
            "volta_pte_and_ce_support_sys_noncoherent": False,
            "hardware_header_anchors": old_header_anchors,
        },
        "candidate": {
            "pte_builder": {key: value for key, value in candidate_pte.items() if not key.startswith("_")},
            "peer_aperture": {key: value for key, value in candidate_peer.items() if not key.startswith("_")},
            "copy_engine_aperture": {key: value for key, value in candidate_ce.items() if not key.startswith("_")},
            "checks": candidate_checks,
            "hardware_header_anchors": hardware_anchors,
            "copy_engine_header_anchors": candidate_ce_header_anchors,
            "source_semantics_anchors": candidate_semantics,
            "external_mapping_pte_source": "RM via nvUvmInterfaceGetExternalAllocPtes; the local make_pte path is also exercised by the built-in RM-PTE comparison test.",
        },
        "interpretation": "The R595 candidate adds a Volta path that selects SYS_NON_COHERENT for PCIe BAR1 peers when RM says PCIe atomics are unavailable, encodes the GV100 VER2 PTE aperture value, and maps it to Volta copy-engine NONCOHERENT_SYSMEM. R580 exposes the relevant enum and hardware constants but its UVM peer/CE/MMU paths do not select or encode this aperture.",
        "runtime_or_hardware_validated": False,
        "validation_needed": "On a GV100 pair or safe canary, validate RM P2P capability reports in both directions, BAR1 address mapping, CE source/destination transfers, external-map PTEs, PCIe atomic suppression, and numerical integrity under concurrency.",
    }


def extract_r580_uvm_selected_headers(archive_path: Path, source_root: Path, expected_root: str) -> None:
    """Add the two GV100 hardware headers needed by the static aperture audit."""
    relative_headers = (
        "hwref/volta/gv100/dev_mmu.h",
        "clc3b5.h",
    )
    with tarfile.open(archive_path, "r:*") as archive:
        archive_root = checked_source_archive_root(archive, expected_root)
        prefix = archive_root + "/kernel-open/nvidia-uvm/"
        for relative in relative_headers:
            archive_name = prefix + relative
            try:
                member = archive.getmember(archive_name)
            except KeyError as error:
                raise ValueError(f"required R580 GV100 hardware header is missing: {relative}") from error
            if not member.isfile():
                raise ValueError(f"required R580 header is not a regular archive file: {relative}")
            output = source_root / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(read_member(archive, archive_name))


def source_manifest(source_root: Path) -> tuple[int, str]:
    """Hash sorted relative C/H paths and content digests."""
    digest = hashlib.sha256()
    files = []
    for path in source_root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"candidate source manifest rejects symlink: {path}")
        if path.is_file() and path.suffix in {".c", ".h"}:
            files.append(path)
    for path in sorted(files):
        relative = path.relative_to(source_root).as_posix()
        content_hash = sha256_file(path)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content_hash.encode("ascii"))
        digest.update(b"\n")
    return len(files), digest.hexdigest()


def build_capability_report(r580_root: Path, candidate_uvm_root: Path) -> dict:
    """Resolve all R580 assignments/consumers and candidate path anchors."""
    old_fields = {item["field"] for item in R580_CAPABILITIES}
    if old_fields != set(R595_CAPABILITY_PATHS):
        raise ValueError("candidate mapping must cover every curated R580 capability exactly once")

    candidate_identifiers = {
        field.rsplit(".", 1)[-1] for field in old_fields
    }
    candidate_occurrences = scan_live_identifier_occurrences(candidate_uvm_root, candidate_identifiers)

    capabilities = []
    for old in R580_CAPABILITIES:
        field = old["field"]
        mapping = R595_CAPABILITY_PATHS[field]
        assignment = old["assignment"]
        assignment_path = r580_root / "uvm_volta.c"
        assignment_matches = source_anchors(assignment_path, assignment)
        if not assignment_matches:
            raise ValueError(f"pinned R580 Volta assignment is missing: {field}")

        old_path, old_anchor = old["r580_consumers"][0]
        old_consumer_path = r580_root / old_path
        old_consumer_matches = source_anchors(old_consumer_path, old_anchor)
        if not old_consumer_matches:
            raise ValueError(f"pinned R580 consumer anchor is missing for {field}: {old_path}")

        candidate_anchors = []
        for relative_path, anchor, role in mapping["anchors"]:
            path = candidate_uvm_root / relative_path
            if not path.is_file():
                raise ValueError(f"candidate source file is missing for {field}: {relative_path}")
            matches = source_anchors(path, anchor)
            if not matches:
                raise ValueError(f"candidate source anchor is missing for {field}: {relative_path}: {anchor}")
            candidate_anchors.append({
                "path": relative_path,
                "sha256": sha256_file(path),
                "role": role,
                "anchor": anchor,
                "matches": matches,
            })

        candidate_absent_tokens = []
        for relative_path, token, role in mapping.get("absent_candidate_tokens", []):
            path = candidate_uvm_root / relative_path
            if path.is_symlink() or not path.is_file():
                raise ValueError(
                    f"candidate source file is missing or unsafe for {field}: {relative_path}"
                )
            matches = source_anchors(path, token)
            if matches:
                raise ValueError(
                    f"legacy candidate token unexpectedly appears for {field}: "
                    f"{relative_path}: {token}"
                )
            candidate_absent_tokens.append({
                "path": relative_path,
                "sha256": sha256_file(path),
                "role": role,
                "token": token,
                "occurrences": [],
                "qualification": "absent-from-live-source",
            })

        identifier = field.rsplit(".", 1)[-1]
        absent = not candidate_occurrences.get(identifier)
        if not absent:
            raise ValueError(f"legacy capability identifier unexpectedly appears in candidate: {field}")

        capabilities.append({
            "field": field,
            "r580_assignment": {
                "path": "uvm_volta.c",
                "sha256": sha256_file(assignment_path),
                "anchor": assignment,
                "matches": assignment_matches,
            },
            "r580_consumer": {
                "path": old_path,
                "sha256": sha256_file(old_consumer_path),
                "anchor": old_anchor,
                "matches": old_consumer_matches,
            },
            "candidate_identifier_occurrence_count": 0,
            "candidate_disposition": mapping["disposition"],
            "candidate_interpretation": mapping["interpretation"],
            "candidate_source_anchors": candidate_anchors,
            "candidate_absent_source_tokens": candidate_absent_tokens,
            "validation_needed": mapping["validation_needed"],
            "runtime_or_hardware_validated": False,
        })

    return {
        "capabilities": capabilities,
        "capability_count": len(capabilities),
        "candidate_legacy_identifiers_absent_count": sum(
            item["candidate_identifier_occurrence_count"] == 0 for item in capabilities
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz")
    parser.add_argument("--expected-r580-sha256", default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256)
    parser.add_argument("--expected-r580-source-root", default=R580_SOURCE_ROOT)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATE_ROOT,
                        help="R595 candidate root containing nvidia-uvm/uvm_hal.c")
    parser.add_argument("--expected-candidate-hal-sha256", default=EXPECTED_CANDIDATE_HAL_SHA256)
    parser.add_argument("--candidate-branch", default="R595.99.02+GV100-HAL-v15")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    archive_path = args.r580_archive.resolve(strict=True)
    archive_hash = sha256_file(archive_path)
    if archive_hash != args.expected_r580_sha256:
        parser.error("R580 archive SHA-256 does not match the pinned value")

    candidate_root = args.candidate_root.resolve(strict=True)
    candidate_uvm = candidate_root / "nvidia-uvm"
    hal_path = candidate_uvm / "uvm_hal.c"
    if candidate_uvm.is_symlink() or not candidate_uvm.is_dir():
        parser.error("candidate nvidia-uvm directory must be a regular non-symlink directory")
    if not hal_path.is_file() or hal_path.is_symlink():
        parser.error("candidate UVM HAL source is missing")
    candidate_hal_hash = sha256_file(hal_path)
    if candidate_hal_hash != args.expected_candidate_hal_sha256:
        parser.error("candidate UVM HAL SHA-256 does not match the pinned v15 value")

    try:
        with tempfile.TemporaryDirectory(prefix="r580-volta-paths-") as temporary:
            r580_root = extract_r580_uvm_c_sources(
                archive_path, Path(temporary) / "nvidia-uvm", args.expected_r580_source_root,
            )
            extract_r580_uvm_selected_headers(
                archive_path, r580_root, args.expected_r580_source_root,
            )
            report_data = build_capability_report(r580_root, candidate_uvm)
            report_data["prefetch_callback_comparison"] = build_prefetch_callback_comparison(
                r580_root, candidate_uvm,
            )
            report_data["noncoherent_aperture_comparison"] = build_volta_noncoherent_aperture_comparison(
                r580_root, candidate_uvm,
            )
            report_data["p2p_direction_mapping"] = build_p2p_direction_mapping_audit(candidate_root)
            r580_initializer_hash = sha256_file(r580_root / "uvm_volta.c")
    except (OSError, tarfile.TarError, UnicodeError, ValueError, RuntimeError) as error:
        parser.error(f"cannot resolve static capability paths: {error}")

    file_count, manifest_hash = source_manifest(candidate_uvm)
    report = {
        "schema": "volta-uvm-r580-r595-candidate-path-audit-v9",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "pinned-static-source-callpath-audit",
        "candidate_branch": args.candidate_branch,
        "candidate_tree_is_experimental": True,
        "r580_source": {
            "archive": str(archive_path),
            "archive_sha256": archive_hash,
            "source_root": args.expected_r580_source_root,
            "volta_initializer_sha256": r580_initializer_hash,
        },
        "candidate_source": {
            "root": str(candidate_root),
            "uvm_source_file_count": file_count,
            "uvm_source_manifest_sha256": manifest_hash,
            "hal_source_sha256": candidate_hal_hash,
        },
        **report_data,
        "limitations": [
            "Source anchors establish candidate call paths and callback table selections only; they do not prove that the RM accepts the requests or that GV100 behaves correctly at runtime.",
            "The R580 and candidate prefetch MMU control helper bodies are statically identical after C comment/literal masking and whitespace elision; this does not prove register access safety, fault delivery, replay, or suspend/resume behavior on GV100.",
            "The old scoped-atoms flag only gated R580 system-wide-atomics ioctls; the R595 candidate lacks those definitions, routes, and helpers. User-mode ABI compatibility and GV100 atomic correctness remain untested.",
            "The R595 candidate's SYS_NON_COHERENT peer-aperture path is source-compatible with the pinned GV100 PTE/copy-engine encodings, but RM P2P capabilities, actual PCIe atomics, BAR1 mappings, transfers, and mixed-GPU behavior have not been tested on hardware.",
            "The P2P direction audit proves only the open UVM consumer's index usage and finds no RM capability producer definition in the scanned candidate C/H tree; capability-value direction and hardware behavior remain unknown.",
            "The PLC guard is a hybrid-candidate change and is not stock R595 behavior.",
            "No module was loaded and no GPU, UVM, CUDA, P2P, performance, or endurance test was run.",
        ],
    }
    report_path = args.report.resolve()
    if report_path.exists():
        parser.error(f"refusing to overwrite existing report: {report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(report_path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "report": str(report_path),
        "report_sha256": sha256_file(report_path),
        "candidate_branch": args.candidate_branch,
        "capability_count": report["capability_count"],
        "candidate_legacy_identifiers_absent_count": report["candidate_legacy_identifiers_absent_count"],
        "uvm_source_file_count": file_count,
        "uvm_source_manifest_sha256": manifest_hash,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
