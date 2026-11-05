#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the R580 UVM VMA callbacks and their system-PM synchronization.

This is a pinned-source audit, not a kernel execution or suspend test.
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

from audit_uvm_pm_lifecycle import function_body
from audit_uvm_interface_ownership import strip_c_comments

RELATIVE_FILES = (
    "common/inc/nv-mm.h",
    "nvidia/nv-mmap.c",
    "nvidia-uvm/uvm.c",
    "nvidia-uvm/uvm_api.h",
    "nvidia-uvm/uvm_global.c",
    "nvidia-uvm/uvm_lock.h",
    "nvidia-uvm/uvm_va_space.c",
    "nvidia-uvm/uvm_va_space.h",
)


def _require(condition: bool, label: str, message: str) -> None:
    if not condition:
        raise ValueError(f"{label}: {message}")


def _ordered(body: str, tokens: tuple[str, ...], label: str) -> list[int]:
    positions: list[int] = []
    cursor = 0
    for token in tokens:
        position = body.find(token, cursor)
        if position < 0:
            raise ValueError(f"{label}: missing ordered token {token!r}")
        positions.append(position)
        cursor = position + len(token)
    return positions


def _call_count(source: str, function: str) -> int:
    return len(re.findall(rf"\b{re.escape(function)}\s*\(", source))


def audit_tree(root: Path, label: str) -> dict:
    root = root.resolve(strict=True)
    paths = {relative: root / relative for relative in RELATIVE_FILES}
    missing = [relative for relative, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError(f"{label}: missing source files: {', '.join(missing)}")
    raw = {relative: path.read_text(errors="strict") for relative, path in paths.items()}
    code = {relative: strip_c_comments(text) for relative, text in raw.items()}

    uvm = code["nvidia-uvm/uvm.c"]
    api = code["nvidia-uvm/uvm_api.h"]
    va_space = code["nvidia-uvm/uvm_va_space.c"]
    global_uvm = code["nvidia-uvm/uvm_global.c"]
    mm_header = code["common/inc/nv-mm.h"]

    managed_open, managed_open_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_open_managed")
    managed_close, managed_close_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_close_managed")
    managed_fault, managed_fault_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_fault")
    sem_open, sem_open_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_open_semaphore_pool")
    sem_close, sem_close_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_close_semaphore_pool")
    p2p_open, p2p_open_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_open_device_p2p")
    p2p_close, p2p_close_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_vm_close_device_p2p")
    uvm_mmap, uvm_mmap_line = function_body(raw["nvidia-uvm/uvm.c"], "uvm_mmap")
    cpu_fault, cpu_fault_line = function_body(raw["nvidia-uvm/uvm_va_space.c"], "uvm_va_space_cpu_fault")
    uvm_suspend, uvm_suspend_line = function_body(raw["nvidia-uvm/uvm_global.c"], "uvm_suspend")
    uvm_resume, uvm_resume_line = function_body(raw["nvidia-uvm/uvm_global.c"], "uvm_resume")
    vma_start_write, vma_start_write_line = function_body(raw["nvidia/nv-mmap.c"], "nv_vma_start_write")
    flags_set_word, flags_set_word_line = function_body(raw["common/inc/nv-mm.h"], "nv_vma_flags_set_word")
    vm_flags_set, vm_flags_set_line = function_body(raw["common/inc/nv-mm.h"], "nv_vm_flags_set")

    managed_open_va_lock = "uvm_va_space_down_write(va_space)" in managed_open
    managed_close_va_lock = "uvm_va_space_down_write(va_space)" in managed_close
    managed_close_teardown_rm_lock = "uvm_va_space_down_read_rm(va_space)" in managed_close
    managed_callbacks_without_pm = all(
        "g_uvm_global.pm.lock" not in body for body in (managed_open, managed_close)
    )
    managed_fault_pm_trylock = (
        "uvm_va_space_cpu_fault_managed(va_space, vmf)" in managed_fault and
        "uvm_down_read_trylock_no_tracking(&g_uvm_global.pm.lock)" in cpu_fault
    )
    if managed_fault_pm_trylock:
        _ordered(cpu_fault, (
            "uvm_down_read_trylock_no_tracking(&g_uvm_global.pm.lock)",
            "uvm_va_space_down_read(va_space)",
            "uvm_up_read_no_tracking(&g_uvm_global.pm.lock)",
        ), f"{label}: managed CPU fault PM/VA locking")

    semaphore_open_va_write = "uvm_va_space_down_write(va_space)" in sem_open
    semaphore_close_va_read = "uvm_va_space_down_read(va_space)" in sem_close
    p2p_open_va_write = "uvm_va_space_down_write(va_space)" in p2p_open
    p2p_close_is_empty = not p2p_close.strip()
    special_callbacks_without_pm = all(
        "g_uvm_global.pm.lock" not in body
        for body in (sem_open, sem_close, p2p_open, p2p_close)
    )

    _require(managed_open_va_lock and managed_close_va_lock, label,
             "managed VMA open/close no longer take the VA-space write lock")
    _require(managed_close_teardown_rm_lock, label,
             "managed VMA close lost its RM read-lock path for process teardown")
    _require(managed_callbacks_without_pm, label,
             "managed VMA open/close unexpectedly take the global UVM PM lock")
    _require(managed_fault_pm_trylock, label,
             "managed CPU fault lost nonblocking global PM admission")
    _require(semaphore_open_va_write and semaphore_close_va_read and p2p_open_va_write and
             p2p_close_is_empty and special_callbacks_without_pm,
             label, "semaphore-pool/device-P2P callback lock behavior changed")

    mmap_pm_trylock = "uvm_down_read_trylock(&g_uvm_global.pm.lock)" in uvm_mmap
    mmap_failed_disables_vma = re.search(
        r"if\s*\(!uvm_down_read_trylock\(&g_uvm_global\.pm\.lock\)\)\s*\{\s*"
        r"uvm_disable_vma\(vma\);\s*return\s+0;", uvm_mmap) is not None
    mmap_pm_released = "uvm_up_read(&g_uvm_global.pm.lock)" in uvm_mmap
    _require(mmap_pm_trylock and mmap_failed_disables_vma and mmap_pm_released,
             label, "UVM mmap PM admission or MAP_FIXED failure handling changed")

    suspend_pm_lock = "uvm_down_write(&g_uvm_global.pm.lock)" in uvm_suspend
    suspend_locks_all_va_spaces = (
        "uvm_mutex_lock(&g_uvm_global.va_spaces.lock)" in uvm_suspend and
        "list_for_each_entry(va_space, &g_uvm_global.va_spaces.list, list_node)" in uvm_suspend and
        "uvm_va_space_down_write(va_space)" in uvm_suspend
    )
    suspend_no_mmap_lock = "mmap_lock" not in uvm_suspend and "mmap_sem" not in uvm_suspend
    _require(suspend_pm_lock and suspend_locks_all_va_spaces and suspend_no_mmap_lock,
             label, "UVM suspend no longer takes global PM then every VA-space write lock")
    _ordered(uvm_suspend, (
        "uvm_down_write(&g_uvm_global.pm.lock)",
        "uvm_mutex_lock(&g_uvm_global.va_spaces.lock)",
        "uvm_va_space_down_write(va_space)",
    ), f"{label}: UVM suspend lock ordering")
    resume_releases_va_before_pm = (
        "uvm_va_space_up_write(va_space)" in uvm_resume and
        "uvm_up_write(&g_uvm_global.pm.lock)" in uvm_resume
    )
    _require(resume_releases_va_before_pm, label,
             "UVM resume no longer releases VA-space locks before the global PM lock")
    _ordered(uvm_resume, (
        "uvm_va_space_up_write(va_space)",
        "uvm_up_write(&g_uvm_global.pm.lock)",
    ), f"{label}: UVM resume unlock order")

    entry_macro = re.search(
        r"#define\s+UVM_ENTRY_WRAP\(line\)(.*?)#define\s+UVM_ENTRY_RET", api, re.S)
    entry_wrapper_only_thread_context = (
        entry_macro is not None and
        "uvm_thread_context_add" in entry_macro.group(1) and
        "g_uvm_global.pm.lock" not in entry_macro.group(1)
    )
    _require(entry_wrapper_only_thread_context, label,
             "UVM_ENTRY_WRAP is no longer only a thread-context wrapper")

    fallback_conditional = "#if !NV_CAN_CALL_VMA_START_WRITE" in mm_header
    flag_helper_calls_vma_write = "nv_vma_start_write(vma)" in flags_set_word
    vma_helper_uses_writer_sequence = (
        "nv_vma_enter_locked(vma, NV_FALSE)" in vma_start_write and
        "WRITE_ONCE(vma->vm_lock_seq, mm_lock_seq)" in vma_start_write and
        "nv_system_pm_lock" not in vma_start_write
    )
    uvm_flag_helper_calls = _call_count(uvm, "nv_vm_flags_set")
    _require(fallback_conditional and flag_helper_calls_vma_write and
             "NV_CAN_CALL_VMA_START_WRITE" in vm_flags_set and
             vma_helper_uses_writer_sequence and uvm_flag_helper_calls == 3,
             label, "nv_vma_start_write compatibility wrapper/call sites changed")

    return {
        "label": label,
        "source_root": str(root),
        "source_files": {
            relative: {
                "bytes": paths[relative].stat().st_size,
                "sha256": hashlib.sha256(paths[relative].read_bytes()).hexdigest(),
            }
            for relative in RELATIVE_FILES
        },
        "managed_vma": {
            "open_uses_va_space_write_lock": managed_open_va_lock,
            "close_uses_va_space_write_lock": managed_close_va_lock,
            "close_process_teardown_uses_va_space_rm_read_lock": managed_close_teardown_rm_lock,
            "open_close_take_global_pm_lock": not managed_callbacks_without_pm,
            "fault_dispatches_managed_cpu_fault": managed_fault_pm_trylock,
            "fault_pm_trylock_precedes_va_read_lock": True,
            "source_lines": {"open": managed_open_line, "close": managed_close_line,
                             "fault": managed_fault_line, "cpu_fault": cpu_fault_line},
        },
        "special_vmas": {
            "semaphore_pool_open_uses_va_space_write_lock": semaphore_open_va_write,
            "semaphore_pool_close_uses_va_space_read_lock": semaphore_close_va_read,
            "device_p2p_open_uses_va_space_write_lock": p2p_open_va_write,
            "device_p2p_close_is_empty": p2p_close_is_empty,
            "callbacks_take_global_pm_lock": not special_callbacks_without_pm,
            "source_lines": {"semaphore_open": sem_open_line, "semaphore_close": sem_close_line,
                             "device_p2p_open": p2p_open_line, "device_p2p_close": p2p_close_line},
        },
        "uvm_mmap": {
            "global_pm_read_trylock": mmap_pm_trylock,
            "pm_contention_disables_vma_and_returns_success": mmap_failed_disables_vma,
            "releases_global_pm_read_lock": mmap_pm_released,
            "source_line": uvm_mmap_line,
        },
        "uvm_suspend": {
            "takes_global_pm_write_lock": suspend_pm_lock,
            "locks_all_va_spaces_for_write": suspend_locks_all_va_spaces,
            "takes_no_mmap_lock": suspend_no_mmap_lock,
            "lock_order": ["global UVM PM write", "global VA-space list", "each VA-space write"],
            "holds_va_space_locks_until_resume": True,
            "source_line": uvm_suspend_line,
            "resume_releases_va_space_locks_before_global_pm": resume_releases_va_before_pm,
            "resume_source_line": uvm_resume_line,
        },
        "nv_vma_start_write": {
            "used_only_by_nv_vm_flags_set_clear_fallback": fallback_conditional and flag_helper_calls_vma_write,
            "protects_kernel_vma_writer_sequence": vma_helper_uses_writer_sequence,
            "uvm_nv_vm_flags_set_sites": uvm_flag_helper_calls,
            "source_lines": {"helper": vma_start_write_line,
                             "set_flags_fallback": flags_set_word_line,
                             "set_flags_wrapper": vm_flags_set_line},
        },
        "entry_wrapper": {"only_manages_thread_context": entry_wrapper_only_thread_context,
                          "acquires_global_pm_lock": False},
        "qualification": "static-source-contract-only",
    }


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", required=True,
                        help="exact R580 source root; repeat for independent trees")
    parser.add_argument("--label", action="append", required=True,
                        help="label corresponding to each --source")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.source) != len(args.label):
        parser.error("pass one --label for every --source")
    trees = [audit_tree(Path(root), label)
             for root, label in zip(args.source, args.label, strict=True)]
    keys = ("managed_vma", "special_vmas", "uvm_mmap", "uvm_suspend",
            "nv_vma_start_write", "entry_wrapper")

    def semantic_facts(tree: dict) -> dict:
        result = {}
        for key in keys:
            value = dict(tree[key])
            value.pop("source_lines", None)
            value.pop("source_line", None)
            result[key] = value
        return result

    if any(semantic_facts(tree) != semantic_facts(trees[0]) for tree in trees[1:]):
        raise ValueError("R580 Open and proprietary trees disagree on UVM VMA/PM semantics")
    report = {
        "schema": "hybrid580-uvm-vma-pm-v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_trees": trees,
        "independent_trees_agree": True,
        "design_constraints": {
            "vma_open_close_synchronized_by_va_space_locks": True,
            "managed_faults_back_off_on_global_pm_contention": True,
            "uvm_suspend_locks_pm_then_all_va_spaces": True,
            "nv_vma_start_write_is_not_a_pm_gate": True,
            "early_pm_notifier_proven_safe_for_uvm_suspend": False,
            "dpm_phase_coordinator_remains_unvalidated": True,
            "reason": (
                "R580 keeps non-returnable VMA open/close callbacks outside the global PM lock, "
                "and uvm_suspend synchronizes them by acquiring every VA-space write lock. "
                "This static contract does not demonstrate freezer or device-link ordering; "
                "do not call UVM from an early PM notifier on this evidence alone."
            ),
        },
        "qualification": "static-source-contract-only",
        "limitations": [
            "No UVM VMA callback, Linux PM notifier, device-link callback, RM operation, or kernel module ran.",
            "No suspend/resume or VMA mutation was tested on live hardware.",
            "Matching source semantics do not prove both backend RMs can share one live UVM instance.",
        ],
    }
    write_report(args.output, report)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"output": str(args.output), "sha256": digest,
                      "qualification": report["qualification"],
                      "trees": [tree["label"] for tree in trees]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"audit_r580_uvm_vma_pm: {exc}", file=sys.stderr)
        raise SystemExit(2)
