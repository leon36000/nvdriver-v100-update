#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Produce a hash-pinned static map of removed Volta UVM capabilities.

The audit compares R580.178.04's Volta assignments and consumers with the
R615.71.10 UVM implementation. It records source anchors and modern references;
it does not infer that an R615 callback works on GV100 or validate hardware.
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


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
    SELECTOR_EXPECTATIONS,
    parse_gpu_hal_selector_contract,
    parse_hal_class_tables,
)

DEFAULT_R580_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
DEFAULT_R615_ARCHIVE = ROOT / ".cache/upstream/nvidia_driver-linux-x86_64-615.71.10-archive.tar.xz"
DEFAULT_R615_SOURCE = ROOT / ".cache/upstream/extracted-r615-71-10-package/kernel-open/nvidia-uvm"
DEFAULT_REPORT = ROOT / "evidence/r580178-vs-r6157110-volta-uvm-capability-map-v3-20261023.json"

R580_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
R615_ARCHIVE_SHA256 = "41e16cfbb3ba475c55b6ce5b2595e1a87a76948873a1a83f1b261f6b7ba0bf5b"
R615_UVM_MANIFEST_SHA256 = "994da262850e82910b5e9a9fa980f96a03fd33142b1ed6ad0fc44109347a2fbf"
R580_ARCHIVE_ROOT = "NVIDIA-kernel-module-source-580.178.04"
R615_EXPECTED_FILE_COUNT = 222


def _capability(field: str,
                assignment: str,
                r580_consumer: tuple[str, str],
                anchors: tuple[tuple[str, str], ...],
                classification: str,
                interpretation: str,
                validation: str) -> dict:
    return {
        "field": field,
        "assignment": assignment,
        "r580_consumers": (r580_consumer,),
        "r615_anchors": anchors,
        "classification": classification,
        "interpretation": interpretation,
        "validation_needed": validation,
    }


CAPABILITIES = (
    _capability(
        "va_invalidate_supported",
        "parent_gpu->tlb_batch.va_invalidate_supported = true;",
        ("uvm_tlb_batch.c", "if (!batch->tree->gpu->parent->tlb_batch.va_invalidate_supported)"),
        (("uvm_tlb_batch.c", "tree->gpu->parent->host_hal->tlb_invalidate_va(push,"),),
        "reworked-callback-no-GV100-proof",
        "R615 directly dispatches targeted VA invalidation through the host HAL; the old capability branch is absent.",
        "Add and validate the GV100 host-HAL callback, including address, page-size, and memory-barrier semantics.",
    ),
    _capability(
        "va_range_invalidate_supported",
        "parent_gpu->tlb_batch.va_range_invalidate_supported = true;",
        ("uvm_tlb_batch.c", "if (batch->tree->gpu->parent->tlb_batch.va_range_invalidate_supported)"),
        (("uvm_tlb_batch.c", "batch->total_ranges > batch->tree->gpu->parent->tlb_batch.max_ranges"),),
        "reworked-range-policy-no-GV100-proof",
        "R615 counts ranges and applies max_ranges without the old ranges-versus-pages capability selection.",
        "Validate GV100 range invalidation thresholds and fallback behavior under fragmented workloads.",
    ),
    _capability(
        "can_map_sysmem_with_large_pages",
        "parent_gpu->can_map_sysmem_with_large_pages = true;",
        ("uvm_mem.c", "if (gpu->parent->can_map_sysmem_with_large_pages) {"),
        (("uvm_mem.c", "return uvm_mmu_biggest_page_size_up_to(gpu_page_tree, mem->chunk_size);"),),
        "reworked-page-tree-selection-no-GV100-proof",
        "R615 chooses from the page sizes exposed by its MMU page tree; page-size selection alone does not prove Volta sysmem PTE support.",
        "Validate GV100 page-size masks, CPU-page contiguity, PTE formats, and sysmem mappings on hardware.",
    ),
    _capability(
        "prefetch_fault_supported",
        "parent_gpu->prefetch_fault_supported = true;",
        ("uvm_gpu_replayable_faults.c", "parent_gpu->fault_buffer.prefetch_faults_enabled = parent_gpu->prefetch_fault_supported;"),
        (("uvm_gpu_replayable_faults.c", "parent_gpu->fault_buffer.prefetch_faults_enabled = true;"),),
        "reworked-runtime-state-no-GV100-proof",
        "R615 sets runtime prefetch-fault state and expects an architecture HAL implementation; the old capability field is absent.",
        "Validate GV100 prefetch-fault control, RM fallback, and fault delivery with a real managed-memory workload.",
    ),
    _capability(
        "gpfifo_in_vidmem_supported",
        "parent_gpu->gpfifo_in_vidmem_supported = true;",
        ("uvm_channel.c", "if (!gpu->parent->gpfifo_in_vidmem_supported) {"),
        (
            ("uvm_channel.c", "manager->conf.gpfifo_loc = UVM_BUFFER_LOCATION_VID;"),
            ("uvm_channel.c", "channel_alloc_params.gpFifoLoc = manager->conf.gpfifo_loc;"),
        ),
        "allocation-policy-rm-request-no-feature-gate",
        "R615 selects a GPFIFO location from policy and memory/coherency state, then forwards it to RM; the open UVM code has no Volta capability gate.",
        "Validate RM acceptance, mapping, cache/coherency, and channel execution for a GV100 GPFIFO in video memory.",
    ),
    _capability(
        "replayable_faults_supported",
        "parent_gpu->replayable_faults_supported = true;",
        ("uvm_gpu_isr.c", "if (parent_gpu->replayable_faults_supported) {"),
        (("uvm_gpu_isr.c", "status = uvm_parent_gpu_fault_buffer_init(parent_gpu);"),),
        "mandatory-init-path-no-feature-gate",
        "R615 initializes replayable fault handling without the former capability check and relies on RM information and HAL methods.",
        "Restore a GV100 dispatch closure and validate buffer layout, interrupts, replay, cancellation, and recovery.",
    ),
    _capability(
        "non_replayable_faults_supported",
        "parent_gpu->non_replayable_faults_supported = true;",
        ("uvm_gpu_isr.c", "if (parent_gpu->non_replayable_faults_supported) {"),
        (("uvm_gpu_replayable_faults.c", "status = uvm_parent_gpu_fault_buffer_init_non_replayable_faults(parent_gpu);"),),
        "implicit-rm-hal-contract-no-GV100-proof",
        "R615 initializes non-replayable fault state through RM-provided buffer information and HAL entry sizing; the old gate is absent.",
        "Validate the GV100 fault-entry format, buffer sizes, ISR path, and error handling on hardware.",
    ),
    _capability(
        "fault_cancel_va_supported",
        "parent_gpu->fault_cancel_va_supported = true;",
        ("uvm_gpu_replayable_faults.c", "if (parent_gpu->fault_cancel_va_supported)"),
        (("uvm_gpu_replayable_faults.c", "gpu->parent->host_hal->cancel_faults_va(&push, pdb, fault_entry, cancel_va_mode);"),),
        "mandatory-hal-callback-no-GV100-proof",
        "R615 dispatches VA fault cancellation through a host-HAL callback without the historical capability fallback.",
        "Implement the GV100 callback and validate exact VA cancellation and fallback/error behavior.",
    ),
    _capability(
        "scoped_atomics_supported",
        "parent_gpu->scoped_atomics_supported = true;",
        ("uvm_policy.c", "if (gpu->parent->scoped_atomics_supported) {"),
        (),
        "no-equivalent-found-in-open-uvm",
        "R580 used this field to reject the legacy system-wide-atomics policy. No matching field or policy was found in the scanned R615 UVM C/H sources; this does not cover proprietary RM or user-mode ABI behavior.",
        "Compare exported UVM ABI and RM atomics semantics before deciding whether to restore, translate, or retire the legacy policy.",
    ),
    _capability(
        "sparse_mappings_supported",
        "parent_gpu->sparse_mappings_supported = true;",
        ("uvm_map_external.c", "if (!mapping_gpu->parent->sparse_mappings_supported) {"),
        (("uvm_map_external.c", "return range_vec->tree->hal->make_sparse_pte();"),),
        "hal-pte-callback-no-GV100-proof",
        "R615 writes sparse PTEs through an MMU HAL callback without the old capability guard; the available Turing implementation is not a Volta implementation.",
        "Implement GV100 sparse PTE encoding and validate invalid-PTE access/fault behavior on hardware.",
    ),
    _capability(
        "plc_supported",
        "parent_gpu->plc_supported = false;",
        ("uvm_map_external.c", "if ((map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc) && !mapping_gpu->parent->plc_supported)"),
        (
            ("uvm_map_external.c", "if (compression_type >= UvmGpuCompressionTypeCount)"),
            ("uvm_map_external.c", "map_rm_params.compression_type = params->perGpuAttributes[i].gpuCompressionType;"),
            ("uvm_map_external.c", "pte_buffer->mapping_info.compressionType    = map_rm_params->compression_type;"),
            ("uvm_map_external.c", "nvUvmInterfaceGetExternalAllocPtes(gpu_va_space->duped_gpu_va_space,"),
        ),
        "rm-forwarding-no-uvm-volta-gate-overlap-unmap-risk",
        "R615 validates the enum and forwards the compression type to RM without the R580 UVM-side Volta PLC guard. Its external-map path removes overlapping mappings before the compression mode reaches the RM PTE request. If RM rejects an unsupported GV100 mode, this ordering may leave the previous mapping removed; whether RM rejects that mode on GV100 is unknown.",
        "On a safe hardware canary, determine RM behavior for GV100 PLC modes and verify failure atomicity with an existing overlapping mapping before enabling this path.",
    ),
)

# These anchors are identical call sites in both releases. Their equality
# narrows source churn at the caller, but says nothing about selected HAL rows,
# callback implementations, RM behavior, or hardware semantics.
SHARED_CODE_ANCHORS = {
    "va_invalidate_supported": (
        ("uvm_tlb_batch.c", "tree->gpu->parent->host_hal->tlb_invalidate_va(push,"),
    ),
    "non_replayable_faults_supported": (
        ("uvm_gpu_replayable_faults.c", "uvm_parent_gpu_fault_buffer_init_non_replayable_faults(parent_gpu);"),
    ),
    "fault_cancel_va_supported": (
        ("uvm_gpu_replayable_faults.c", "gpu->parent->host_hal->cancel_faults_va(&push, pdb, fault_entry, cancel_va_mode);"),
    ),
    "sparse_mappings_supported": (
        ("uvm_map_external.c", "return range_vec->tree->hal->make_sparse_pte();"),
    ),
}

PLC_R580_UNMAP_ANCHOR = (
    "uvm_map_external.c",
    "status = uvm_unmap_external_in_range(external_range, mapping_gpu, base, base + length - 1, NULL);",
)
PLC_R615_ANCHORS = (
    ("uvm_map_external.c", "status = uvm_unmap_external_in_range(external_range, mapping_gpu, base, base + length - 1, NULL);"),
    ("uvm_map_external.c", "map_rm_params.compression_type = params->perGpuAttributes[i].gpuCompressionType;"),
    ("uvm_map_external.c", "uvm_va_range_map_rm_allocation(&external_range->va_range,"),
    ("uvm_map_external.c", "pte_buffer->mapping_info.compressionType    = map_rm_params->compression_type;"),
    ("uvm_map_external.c", "nvUvmInterfaceGetExternalAllocPtes(gpu_va_space->duped_gpu_va_space,"),
    ("uvm_map_external.c", "uvm_ext_gpu_map_destroy(external_range, ext_gpu_map, NULL);"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest_sha256(files: dict[str, bytes | str]) -> str:
    """Hash sorted path-NUL-content-SHA256-LF rows for C/H source files."""
    digest = hashlib.sha256()
    for relative_path, content in sorted(files.items()):
        if isinstance(content, str):
            content = content.encode("utf-8")
        row = hashlib.sha256(content).hexdigest()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(row.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _mask_c_comments_and_literals(text: str) -> str:
    """Mask C comments and quoted literals without changing source offsets.

    Translation-phase line splicing must already have been applied. An invalid
    unclosed quote ends at a physical newline so it cannot hide later code.
    """
    out = list(text)
    state = "code"
    i = 0
    while i < len(text):
        char = text[i]
        following = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "/":
                out[i] = out[i + 1] = " "
                state = "line_comment"
                i += 2
                continue
            if char == "/" and following == "*":
                out[i] = out[i + 1] = " "
                state = "block_comment"
                i += 2
                continue
            if char == '"':
                out[i] = " "
                state = "string"
            elif char == "'":
                out[i] = " "
                state = "character"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if char != "\n":
                out[i] = " "
        else:
            if char in "\r\n":
                # Unescaped newlines make a C string/character literal
                # malformed. Recover at the next physical line.
                state = "code"
            elif char == "\\":
                out[i] = " "
                if following and following not in "\r\n":
                    out[i + 1] = " "
                    i += 2
                    continue
            elif (state == "string" and char == '"') or (state == "character" and char == "'"):
                out[i] = " "
                state = "code"
            else:
                out[i] = " "
        i += 1
    return "".join(out)


def _splice_c_lines(text: str) -> tuple[str, list[int]]:
    """Apply C/GCC backslash-newline splicing and map chars to physical lines.

    GCC also accepts horizontal whitespace between the backslash and newline;
    preserve support for that diagnosed extension when scanning source.
    """
    logical = []
    physical_line_for_char = []
    line = 1
    index = 0
    while index < len(text):
        if text[index] == "\\":
            newline = index + 1
            while newline < len(text) and text[newline] in " \t\v\f":
                newline += 1
            if text.startswith("\r\n", newline):
                index = newline + 2
                line += 1
                continue
            if text.startswith("\n", newline):
                index = newline + 1
                line += 1
                continue

        char = text[index]
        logical.append(char)
        physical_line_for_char.append(line)
        if char == "\n":
            line += 1
        index += 1
    return "".join(logical), physical_line_for_char


def _physical_line(text: str, number: int) -> str:
    """Return one LF-delimited source line; Unicode separators are ordinary data."""
    lines = text.split("\n")
    if number < 1 or number > len(lines):
        return ""
    return lines[number - 1].removesuffix("\r")


def _line_hits(files: dict[str, str], relative_path: str, marker: str) -> list[dict]:
    text = files.get(relative_path)
    if text is None:
        return []
    logical, line_map = _splice_c_lines(text)
    code = _mask_c_comments_and_literals(logical)
    hits = []
    for match in re.finditer(re.escape(marker), code):
        line_number = line_map[match.start()] if match.start() < len(line_map) else 1
        hits.append({
            "path": relative_path,
            "line": line_number,
            "text": _physical_line(text, line_number).strip(),
            "logical_text": marker,
        })
    return hits


def _raw_line_hits(files: dict[str, str], relative_path: str, marker: str) -> list[dict]:
    """Find an exact documentation anchor, including its comment text."""
    text = files.get(relative_path)
    if text is None:
        return []
    hits = []
    for number, line in enumerate(text.split("\n"), 1):
        physical = line.removesuffix("\r")
        if marker in physical:
            hits.append({
                "path": relative_path,
                "line": number,
                "text": physical.strip(),
                "evidence_kind": "raw-documentation-line",
            })
    return hits


def audit_capability_sources(r580_files: dict[str, str],
                             r615_files: dict[str, str]) -> dict:
    """Map representative capability evidence and the GV100 dispatch prerequisite."""
    volta = r580_files.get("uvm_volta.c")
    if volta is None:
        raise ValueError("R580 uvm_volta.c is missing")

    r580_hal_source = r580_files.get("uvm_hal.c")
    r615_hal_source = r615_files.get("uvm_hal.c")
    if r580_hal_source is None or r615_hal_source is None:
        raise ValueError("R580 and R615 uvm_hal.c are required for the GV100 dispatch audit")
    r580_hal_tables = parse_hal_class_tables(r580_hal_source)
    r615_hal_tables = parse_hal_class_tables(r615_hal_source)
    r615_selector_contract = parse_gpu_hal_selector_contract(r615_hal_source)
    r580_target_presence = {}
    r615_target_presence = {}
    r615_missing_class_status = {}
    for table, target in REQUIRED_GV100_TABLE_TARGETS.items():
        if table not in r580_hal_tables or table not in r615_hal_tables:
            raise ValueError(f"required GV100 HAL class table missing: {table}")
        r580_target_presence[table] = any(row["id"] == target for row in r580_hal_tables[table])
        r615_target_presence[table] = any(row["id"] == target for row in r615_hal_tables[table])
        if not r580_target_presence[table]:
            raise ValueError(f"R580 historical GV100 class row missing from {table}: {target}")
        if not r615_target_presence[table]:
            r615_missing_class_status[table] = r615_selector_contract[table]["missing_class_status"]

    shared_anchors_by_field = {}
    for field, anchors in SHARED_CODE_ANCHORS.items():
        shared = []
        for relative_path, marker in anchors:
            old_hits = _line_hits(r580_files, relative_path, marker)
            modern_hits = _line_hits(r615_files, relative_path, marker)
            if not old_hits or not modern_hits:
                raise ValueError(f"{field}: shared R580/R615 code anchor missing: {relative_path}: {marker}")
            shared.append({
                "path": relative_path,
                "marker": marker,
                "r580_occurrences": old_hits,
                "r615_occurrences": modern_hits,
                "same_marker_in_both_releases": True,
                "semantic_limit": "identical caller text does not establish identical HAL, RM, or hardware behavior",
            })
        shared_anchors_by_field[field] = shared

    entries = []
    for spec in CAPABILITIES:
        assignment_hits = _line_hits(r580_files, "uvm_volta.c", spec["assignment"])
        if len(assignment_hits) != 1:
            raise ValueError(
                f"{spec['field']}: expected one exact R580 assignment, found {len(assignment_hits)}"
            )

        consumers = []
        for relative_path, marker in spec["r580_consumers"]:
            hits = _line_hits(r580_files, relative_path, marker)
            if not hits:
                raise ValueError(f"{spec['field']}: R580 consumer anchor missing: {relative_path}: {marker}")
            consumers.extend(hits)

        modern_anchors = []
        for relative_path, marker in spec["r615_anchors"]:
            hits = _line_hits(r615_files, relative_path, marker)
            if not hits:
                raise ValueError(f"{spec['field']}: R615 evidence anchor missing: {relative_path}: {marker}")
            modern_anchors.extend(hits)

        raw_occurrences = []
        code_occurrences = []
        identifier = re.compile(r"\b" + re.escape(spec["field"]) + r"\b")
        for relative_path, text in sorted(r615_files.items()):
            logical, line_map = _splice_c_lines(text)
            code = _mask_c_comments_and_literals(logical)
            for match in identifier.finditer(logical):
                line_number = line_map[match.start()]
                raw = _physical_line(text, line_number)
                raw_occurrences.append({
                    "path": relative_path,
                    "line": line_number,
                    "text": raw.strip(),
                    "logical_text": match.group(),
                })
            for match in identifier.finditer(code):
                line_number = line_map[match.start()]
                raw = _physical_line(text, line_number)
                code_occurrences.append({
                    "path": relative_path,
                    "line": line_number,
                    "text": raw.strip(),
                    "logical_text": match.group(),
                })

        entries.append({
            "field": spec["field"],
            "r580_assignment": assignment_hits[0],
            "r580_consumer_evidence": consumers,
            "r580_r615_shared_code_anchors": shared_anchors_by_field.get(spec["field"], []),
            "r615_classification": spec["classification"],
            "r615_source_evidence": modern_anchors,
            "r615_legacy_identifier_occurrences": raw_occurrences,
            "r615_legacy_identifier_code_occurrences": code_occurrences,
            "r615_legacy_identifier_absent_from_code": not code_occurrences,
            "interpretation": spec["interpretation"],
            "required_validation": spec["validation_needed"],
            "runtime_or_hardware_validated": False,
        })

    plc_guard = _line_hits(
        r580_files,
        "uvm_map_external.c",
        "if ((map_rm_params->compression_type == UvmGpuCompressionTypeEnabledNoPlc) && !mapping_gpu->parent->plc_supported)",
    )
    plc_old_unmap = _line_hits(r580_files, *PLC_R580_UNMAP_ANCHOR)
    plc_modern_evidence = _raw_line_hits(
        r615_files,
        "uvm.h",
        "UvmGpuCompressionTypeEnabledNoPlc compression type was used on one",
    )
    if not plc_modern_evidence:
        raise ValueError("R615 PLC API documentation anchor missing from uvm.h")
    for hit in plc_modern_evidence:
        hit["semantic_limit"] = "documented API error contract; not proof of RM behavior on GV100"
    for relative_path, marker in PLC_R615_ANCHORS:
        hits = _line_hits(r615_files, relative_path, marker)
        if not hits:
            raise ValueError(f"PLC risk evidence anchor missing: {relative_path}: {marker}")
        plc_modern_evidence.extend(hits)
    if not plc_guard or not plc_old_unmap:
        raise ValueError("R580 PLC guard/unmap ordering evidence is incomplete")
    if plc_guard[0]["line"] >= plc_old_unmap[0]["line"]:
        raise ValueError("R580 PLC rejection guard does not precede overlap unmap")

    return {
        "schema": "r580-r615-volta-uvm-capability-map-v2",
        "status": "analyzed-statically",
        "capability_count": len(entries),
        "capabilities": entries,
        "coverage": {
            "r580_consumer_evidence": "representative_not_exhaustive",
            "scanner": "C comments, literals, LF/CRLF line splices, and GCC horizontal-whitespace line-splice extension are masked; identifiers/macros are not preprocessed or expanded",
            "line_numbering": "physical LF-delimited lines; Unicode separators are ordinary source characters",
        },
        "prerequisites": {
            "r615_gv100_uvm_hal_dispatch": {
                "status": "missing_required_gv100_rows" if r615_missing_class_status else "required_gv100_rows_present",
                "r580_required_targets_present_by_table": r580_target_presence,
                "r580_all_required_targets_present": all(r580_target_presence.values()),
                "r615_required_targets_present_by_table": r615_target_presence,
                "r615_all_required_targets_present": all(r615_target_presence.values()),
                "r615_missing_targets": sorted(r615_missing_class_status),
                "r615_missing_class_status_by_table": r615_missing_class_status,
                "selector_contract": r615_selector_contract,
                "interpretation": "A missing target row reaches the audited R615 selector failure before a GV100 HAL pointer is installed; this is a source-level prerequisite finding, not a runtime initialization trace.",
            },
        },
        "behavioral_risks": [{
            "id": "plc-rejection-after-overlap-unmap",
            "priority": "high",
            "conditional_impact": True,
            "condition": "The R615 RM rejects the requested compression mode for GV100 after UVM has removed an overlapping mapping.",
            "r615_rm_rejection_on_gv100": "unknown",
            "potential_effect": "The requested new mapping may fail after the previous overlapping mapping has already been removed; source evidence does not establish RM rejection or the effect on a live GPU.",
            "r580_guard_prevents_this_ordering": {
                "function": "uvm_map_external_allocation_on_gpu",
                "guard": plc_guard[0],
                "overlap_unmap": plc_old_unmap[0],
                "guard_precedes_unmap": True,
            },
            "r615_source_evidence": plc_modern_evidence,
            "r615_static_path": [
                "uvm_map_external_allocation stores the per-GPU compression type and calls uvm_map_external_allocation_on_gpu",
                "uvm_map_external_allocation_on_gpu removes overlapping mappings before calling uvm_va_range_map_rm_allocation",
                "the mapping info carries compressionType into nvUvmInterfaceGetExternalAllocPtes; a failure tears down the new map, with no source evidence that the old overlap is restored",
            ],
            "interpretation": "conditional failure-atomicity risk; proprietary RM behavior on GV100 remains unknown",
        }],
        "runtime_or_hardware_validated": False,
        "limitations": [
            "Source anchors show code structure, not that a callback or policy works on GV100.",
            "R615 proprietary Resource Manager behavior and closed user-mode components are outside this source audit.",
            "The source scanner does not run the C preprocessor or resolve macros, token-pasting, generated code, or conditional compilation.",
            "No module was installed or loaded and no GPU was exercised by this audit.",
        ],
    }


def _read_r615_tree(source_root: Path) -> dict[str, bytes]:
    source_root = source_root.resolve(strict=True)
    if not source_root.is_dir():
        raise ValueError(f"R615 source root is not a directory: {source_root}")
    if any(path.is_symlink() for path in source_root.rglob("*")):
        raise ValueError("R615 source tree contains a symlink; refusing ambiguous manifest input")
    files = {
        path.relative_to(source_root).as_posix(): path.read_bytes()
        for path in source_root.rglob("*")
        if path.is_file() and path.suffix in {".c", ".h"}
    }
    if len(files) != R615_EXPECTED_FILE_COUNT:
        raise ValueError(f"expected {R615_EXPECTED_FILE_COUNT} R615 C/H files, found {len(files)}")
    manifest = source_manifest_sha256(files)
    if manifest != R615_UVM_MANIFEST_SHA256:
        raise ValueError(f"R615 UVM C/H manifest mismatch: {manifest}")
    return files


def _read_r580_archive(archive_path: Path) -> dict[str, str]:
    selected = {
        "uvm_volta.c": "uvm_volta.c",
        "uvm_hal.c": "uvm_hal.c",
        **{path: path for spec in CAPABILITIES for path, _ in spec["r580_consumers"]},
        **{path: path for anchors in SHARED_CODE_ANCHORS.values() for path, _ in anchors},
        PLC_R580_UNMAP_ANCHOR[0]: PLC_R580_UNMAP_ANCHOR[0],
    }
    result = {}
    prefix = R580_ARCHIVE_ROOT + "/kernel-open/nvidia-uvm/"
    with tarfile.open(archive_path, "r:*") as archive:
        for relative_path in selected:
            name = prefix + relative_path
            try:
                member = archive.getmember(name)
            except KeyError as error:
                raise ValueError(f"R580 archive member is missing: {name}") from error
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"R580 archive member is not a regular file: {name}")
            result[relative_path] = source.read().decode("utf-8", errors="strict")
    return result


def build_report(r580_archive: Path, r615_archive: Path, r615_source_root: Path) -> dict:
    r580_sha = sha256_file(r580_archive)
    r615_sha = sha256_file(r615_archive)
    if r580_sha != R580_ARCHIVE_SHA256:
        raise ValueError(f"R580 archive SHA-256 mismatch: {r580_sha}")
    if r615_sha != R615_ARCHIVE_SHA256:
        raise ValueError(f"R615 archive SHA-256 mismatch: {r615_sha}")

    modern_bytes = _read_r615_tree(r615_source_root)
    modern_text = {path: data.decode("utf-8", errors="strict") for path, data in modern_bytes.items()}
    r580_text = _read_r580_archive(r580_archive)
    r580_bytes = {path: data.encode("utf-8") for path, data in r580_text.items()}
    source_result = audit_capability_sources(r580_text, modern_text)
    return {
        **source_result,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {
            "r580": {
                "version": "580.178.04",
                "archive_sha256": r580_sha,
                "archive_root": R580_ARCHIVE_ROOT + "/kernel-open/nvidia-uvm",
                "selected_uvm_file_count": len(r580_bytes),
                "selected_uvm_files": sorted(r580_bytes),
                "selected_uvm_manifest_sha256": source_manifest_sha256(r580_bytes),
            },
            "r615": {
                "version": "615.71.10",
                "archive_sha256": r615_sha,
                "source_root": str(r615_source_root.resolve()),
                "c_header_file_count": len(modern_bytes),
                "c_header_manifest_sha256": source_manifest_sha256(modern_bytes),
                "manifest_algorithm": "sorted relative path + NUL + SHA256(file bytes) + LF",
            },
            "audit_script_sha256": sha256_file(Path(__file__)),
        },
    }


def _write_private_report(path: Path, report: dict) -> None:
    """Create or truncate a mode-0600 report without following a leaf symlink."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence report output")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--r615-archive", type=Path, default=DEFAULT_R615_ARCHIVE)
    parser.add_argument("--r615-source-root", type=Path, default=DEFAULT_R615_SOURCE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    try:
        report = build_report(
            args.r580_archive.resolve(strict=True),
            args.r615_archive.resolve(strict=True),
            args.r615_source_root.resolve(strict=True),
        )
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as error:
        parser.error(str(error))

    report_path = args.report.parent.resolve() / args.report.name
    try:
        _write_private_report(report_path, report)
    except OSError as error:
        parser.error(f"cannot write private report safely: {error}")
    print(json.dumps({
        "report": str(report_path),
        "report_sha256": sha256_file(report_path),
        "capability_count": report["capability_count"],
        "runtime_or_hardware_validated": False,
        "r615_code_occurrences": {
            item["field"]: len(item["r615_legacy_identifier_code_occurrences"])
            for item in report["capabilities"]
        },
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
