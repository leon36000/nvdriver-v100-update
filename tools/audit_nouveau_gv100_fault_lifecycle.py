#!/usr/bin/env python3
"""Audit pinned upstream Linux source for the Nouveau GV100 fault IRQ/work lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from tools.nouveau_gv100_rea_audit import (
    AuditError,
    extract_procedure_body,
    write_new_json,
)


UPSTREAM_COMMIT = "028ef9c96e96197026887c0f092424679298aae8"
PINNED_SOURCE_SHA256 = {
    "include/linux/workqueue.h": "0e2a48f4d301d57750761cc756545946cdef3c69e2a7c5c197621aa264453db6",
    "kernel/workqueue.c": "dc15fb16ec3e0627610ae22e7d727943475914a166d50281e887ddb906eea4ab",
    "drivers/gpu/drm/nouveau/nvkm/core/event.c": "8d81cd673058be1d221bd15aea87d9aa0c30ba7b8d4936564b8eb3707c138ec3",
    "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c": "10062d3bcb370a39dfa56f4fca675b125de7c03550316813654acdc794febd8d",
    "drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c": "d80a011ad4effdaac7275588870cd08bcbe92d42b6b0c9a4854247b4be319136",
    "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gp100.c": "b72440a15e1c17e8267d2f7c2fd55c4897a107a801f572ca64b9f1b6f72eb8ea",
    "drivers/gpu/drm/nouveau/nvkm/core/intr.c": "57b8d2205e8d1cd22c04c061cddf157dcdf972693d0c43a62fdf175a5bedbcff",
    "drivers/gpu/drm/nouveau/nvkm/core/subdev.c": "5dde7b0b501a36842803055aae8f01547cbf989d5278e767332bf48a53e715e3",
    "drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c": "19ebe48f5e39b05488681346a9547a5ff8e82ee0c40cc36a23a93a52e86bfd78",
    "drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c": "0d5aca122ac4aecea77c668924bbaf491b642e7c103ce4b1d33d00e0289ab626",
    "drivers/gpu/drm/nouveau/nvkm/subdev/mc/nv04.c": "bdf95057dc095b6e0f09fee47ab8d461b0b60b3af153edd4c3325955a5fc84e2",
    "drivers/gpu/drm/nouveau/nvkm/engine/fifo/base.c": "e0cef018aaa86f3be86daf6818c2963cd7468c89c0671543efd36a743753d53a",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _body(sources: Mapping[str, str], path: str, procedure: str) -> str:
    try:
        source = sources[path]
    except KeyError as exc:
        raise AuditError(f"missing pinned source: {path}") from exc
    return extract_procedure_body(source, procedure)


def _require_order(text: str, patterns: tuple[str, ...], check: str) -> None:
    cursor = 0
    for pattern in patterns:
        match = re.search(pattern, text[cursor:], re.MULTILINE | re.DOTALL)
        if not match:
            raise AuditError(f"source contract failed: {check}")
        cursor += match.end()


def audit_source_texts(
    source_texts: Mapping[str, str],
    expected_hashes: Mapping[str, str] = PINNED_SOURCE_SHA256,
) -> dict[str, Any]:
    """Validate exact source identities, then check the relevant lifecycle ordering."""
    if set(source_texts) != set(expected_hashes):
        raise AuditError("source set differs from the pinned Linux v7.0 audit inputs")

    source_rows = []
    for path in sorted(expected_hashes):
        digest = _sha256(source_texts[path].encode("utf-8"))
        if digest != expected_hashes[path]:
            raise AuditError(f"source digest mismatch: {path}")
        source_rows.append({"path": path, "sha256": digest})

    work_h = source_texts["include/linux/workqueue.h"]
    work_c = source_texts["kernel/workqueue.c"]
    event_c = source_texts["drivers/gpu/drm/nouveau/nvkm/core/event.c"]
    fault_c = source_texts["drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"]
    intr_c = source_texts["drivers/gpu/drm/nouveau/nvkm/core/intr.c"]
    subdev_c = source_texts["drivers/gpu/drm/nouveau/nvkm/core/subdev.c"]
    mc_base_c = source_texts["drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c"]
    mc_gp100_c = source_texts["drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c"]
    mc_nv04_c = source_texts["drivers/gpu/drm/nouveau/nvkm/subdev/mc/nv04.c"]
    fifo_base_c = source_texts["drivers/gpu/drm/nouveau/nvkm/engine/fifo/base.c"]

    _require_order(
        _body(source_texts, "kernel/workqueue.c", "process_one_work"),
        (r"set_work_pool_and_clear_pending\s*\(\s*work\b",
         r"worker\s*->\s*current_func\s*\(\s*work\s*\)"),
        "work_pending_cleared_before_callback",
    )
    _require_order(
        _body(source_texts, "kernel/workqueue.c", "queue_work_on"),
        (r"test_and_set_bit\s*\(\s*WORK_STRUCT_PENDING_BIT",
         r"__queue_work\s*\(",
         r"ret\s*=\s*true"),
        "queue_work_coalesces_while_pending",
    )
    _require_order(
        _body(source_texts, "kernel/workqueue.c", "flush_work"),
        (r"__flush_work\s*\(\s*work\s*,\s*false\s*\)",),
        "flush_work_waits_for_work_item",
    )
    if not re.search(
        r"@work is guaranteed to be idle(?:\s|\*)+on return if it hasn't been requeued since flush started",
        work_c,
    ):
        raise AuditError("source contract failed: flush_work_last_queueing_instance")

    _require_order(
        _body(source_texts, "include/linux/workqueue.h", "schedule_work"),
        (r"queue_work\s*\(\s*system_percpu_wq\s*,\s*work\s*\)",),
        "schedule_work_uses_kernel_workqueue",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/core/event.c", "nvkm_event_ntfy"),
        (r"read_lock_irqsave\s*\(\s*&event->list_lock",
         r"ntfy\s*->\s*func\s*\(",
         r"read_unlock_irqrestore\s*\(\s*&event->list_lock"),
        "notifier_callback_runs_under_list_read_lock",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/core/event.c", "nvkm_event_ntfy_remove"),
        (r"write_lock_irq\s*\(\s*&ntfy->event->list_lock",
         r"list_del_init\s*\(\s*&ntfy->head",
         r"write_unlock_irq\s*\(\s*&ntfy->event->list_lock"),
        "notifier_removal_waits_for_reader_section",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/core/event.c", "nvkm_event_ntfy_block_"),
        (r"atomic_xchg\s*\(\s*&ntfy->allowed\s*,\s*0\s*\)",
         r"nvkm_event_ntfy_state\s*\(\s*ntfy\s*\)",
         r"if\s*\(\s*wait\s*\)\s*nvkm_event_ntfy_remove\s*\(\s*ntfy\s*\)"),
        "notifier_block_disables_then_removes_waiting_notifier",
    )

    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_ntfy_nrpfb"),
        (r"schedule_work\s*\(\s*&fault->nrpfb_work\s*\)",),
        "fault_notification_schedules_worker",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_fini"),
        (r"nvkm_event_ntfy_block\s*\(\s*&fault->nrpfb\s*\)",
         r"flush_work\s*\(\s*&fault->nrpfb_work\s*\)",
         r"buffer\.fini\s*\(\s*fault->buffer\[0\]\s*\)",
         r"nvkm_mask\s*\(\s*fault->subdev\.device\s*,\s*0x100a34\s*,\s*0x80000000\s*,\s*0x80000000\s*\)"),
        "teardown_blocks_flushes_then_releases_buffer",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_oneinit"),
        (r"nvkm_event_ntfy_add\s*\(\s*&fault->event\s*,\s*0\s*,\s*NVKM_FAULT_BUFFER_EVENT_PENDING\s*,\s*true",),
        "fault_notifier_uses_waiting_registration",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_buffer_process"),
        (r"u32\s+get\s*=\s*nvkm_rd32\s*\(\s*device\s*,\s*buffer->get\s*\)",
         r"u32\s+put\s*=\s*nvkm_rd32\s*\(\s*device\s*,\s*buffer->put\s*\)",
         r"while\s*\(\s*get\s*!=\s*put\s*\)",
         r"if\s*\(\s*\+\+get\s*==\s*buffer->entries\s*\)",
         r"nvkm_wr32\s*\(\s*device\s*,\s*buffer->get\s*,\s*get\s*\)",
         r"nvkm_fifo_fault\s*\(\s*device->fifo\s*,\s*&info\s*\)"),
        "fault_ring_snapshot_wrap_and_publish_before_dispatch",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c", "nvkm_fault_ntfy_init"),
        (r"fault->func->buffer\.intr\s*\(\s*fault->buffer\[index\]\s*,\s*true\s*\)",),
        "event_reference_init_enables_buffer_interrupt",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c", "nvkm_fault_ntfy_fini"),
        (r"fault->func->buffer\.intr\s*\(\s*fault->buffer\[index\]\s*,\s*false\s*\)",),
        "event_reference_fini_disables_buffer_interrupt",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c", "nvkm_fault_oneinit_buffer"),
        (r"fault->func->buffer\.info\s*\(\s*buffer\s*\)",
         r"nvkm_memory_new\s*\(\s*device\s*,\s*NVKM_MEM_TARGET_INST\s*,\s*buffer->entries\s*\*\s*fault->func->buffer.entry_size\s*,\s*0x1000",
         r"buffer->addr\s*=\s*fault->func->buffer\.pin\s*\(\s*buffer\s*\)"),
        "ring_storage_sized_from_hardware_entries_and_pinned",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gp100.c", "gp100_fault_buffer_pin"),
        (r"nvkm_memory_bar2\s*\(\s*buffer->mem\s*\)",),
        "gp100_buffer_pin_uses_bar2",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c", "nvkm_fault_dtor"),
        (r"nvkm_event_ntfy_del\s*\(\s*&fault->nrpfb\s*\)",
         r"nvkm_event_fini\s*\(\s*&fault->event\s*\)",
         r"nvkm_memory_unref\s*\(\s*&fault->buffer\[i\]->mem\s*\)",
         r"kfree\s*\(\s*fault->buffer\[i\]\s*\)"),
        "destructor_removes_notifier_before_releasing_ring_memory",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_buffer_intr"),
        (r"if\s*\(\s*enable\s*\)\s*nvkm_mask\s*\(\s*device\s*,\s*0x100a2c\s*,\s*intr\s*,\s*intr\s*\)",
         r"else\s*nvkm_mask\s*\(\s*device\s*,\s*0x100a34\s*,\s*intr\s*,\s*intr\s*\)"),
        "gv100_buffer_interrupt_enable_disable_registers",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_init"),
        (r"nvkm_mask\s*\(\s*fault->subdev\.device\s*,\s*0x100a2c\s*,\s*0x80000000\s*,\s*0x80000000\s*\)",
         r"fault->func->buffer\.init\s*\(\s*fault->buffer\[0\]\s*\)",
         r"nvkm_event_ntfy_allow\s*\(\s*&fault->nrpfb\s*\)"),
        "gv100_startup_enables_source_then_ring_then_notification",
    )

    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/core/intr.c", "nvkm_intr"),
        (r"spin_lock\s*\(\s*&device->intr\.lock\s*\)",
         r"nvkm_intr_unarm_locked\s*\(\s*device\s*\)",
         r"nvkm_pci_msi_rearm\s*\(\s*device\s*\)",
         r"if\s*\(\s*!pending\s*\)",
         r"inth->func\s*\(\s*inth\s*\)",
         r"nvkm_intr_rearm_locked\s*\(\s*device\s*\)",
         r"spin_unlock\s*\(\s*&device->intr\.lock\s*\)"),
        "irq_handler_serializes_dispatch_and_rearms_after_handlers",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/core/intr.c", "nvkm_intr_subdev"),
        (r"nvkm_subdev_intr\s*\(\s*subdev\s*\)",),
        "irq_subdevice_handler_calls_subdevice_dispatch",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/core/subdev.c", "nvkm_subdev_intr"),
        (r"if\s*\(\s*subdev->func->intr\s*\)",
         r"subdev->func->intr\s*\(\s*subdev\s*\)"),
        "subdevice_dispatch_calls_architecture_interrupt_method",
    )
    if not re.search(
        r"\{\s*NVKM_SUBDEV_FAULT\s*,\s*0\s*,\s*0\s*,\s*0x00000200\s*,\s*true\s*\}",
        mc_gp100_c,
    ):
        raise AuditError("source contract failed: gp100_mc_maps_fault_subdevice_interrupt")
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c", "nvkm_mc_new_"),
        (r"nvkm_intr_add\s*\(\s*mc->func->intr\s*,\s*mc->func->intrs\s*,\s*&mc->subdev",
         r"mc->func->intr_nonstall\s*\?\s*2\s*:\s*1"),
        "mc_interrupt_topology_uses_configured_leaf_count",
    )
    if not re.search(r"\.intr_nonstall\s*=\s*true", mc_gp100_c):
        raise AuditError("source contract failed: gp100_mc_uses_two_interrupt_leaves")
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/mc/nv04.c", "nv04_mc_intr_pending"),
        (r"intr->stat\[leaf\]\s*=\s*nvkm_rd32\s*\(\s*mc->subdev\.device\s*,\s*0x000100\s*\+\s*\(\s*leaf\s*\*\s*4\s*\)\s*\)",
         r"if\s*\(\s*intr->stat\[leaf\]\s*\)",
         r"return\s+pending\s*;"),
        "mc_pending_snapshots_leaf_status_for_dispatch",
    )
    if re.search(r"nvkm_wr32\s*\(", _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/mc/nv04.c", "nv04_mc_intr_pending")):
        raise AuditError("source contract failed: mc_pending_only_snapshots_status")
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_intr_fault"),
        (r"nvkm_rd32\s*\(\s*device\s*,\s*0x100e4c\s*\)",
         r"nvkm_fifo_fault\s*\(\s*device->fifo\s*,\s*&info\s*\)"),
        "nonreplayable_fault_is_decoded_and_dispatched_inline",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_intr"),
        (r"if\s*\(\s*stat\s*&\s*0x80000000\s*\)",
         r"gv100_fault_intr_fault\s*\(\s*fault\s*\)",
         r"nvkm_wr32\s*\(\s*device\s*,\s*0x100e60\s*,\s*0x80000000\s*\)",
         r"stat\s*&=\s*~0x80000000"),
        "nonreplayable_fault_is_acknowledged_after_fifo_dispatch",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_intr"),
        (r"if\s*\(\s*stat\s*&\s*0x20000000\s*\)",
         r"if\s*\(\s*fault->buffer\[0\]\s*\)",
         r"nvkm_event_ntfy\s*\(\s*&fault->event\s*,\s*0\s*,\s*NVKM_FAULT_BUFFER_EVENT_PENDING\s*\)",
         r"stat\s*&=\s*~0x20000000"),
        "replayable_buffer0_requires_buffer_then_notifies",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c", "gv100_fault_intr"),
        (r"if\s*\(\s*stat\s*&\s*0x08000000\s*\)",
         r"if\s*\(\s*fault->buffer\[1\]\s*\)",
         r"nvkm_event_ntfy\s*\(\s*&fault->event\s*,\s*1\s*,\s*NVKM_FAULT_BUFFER_EVENT_PENDING\s*\)",
         r"stat\s*&=\s*~0x08000000"),
        "replayable_buffer1_requires_buffer_then_notifies",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/engine/fifo/base.c", "nvkm_fifo_fault"),
        (r"fifo->func->mmu_fault->recover\s*\(\s*fifo\s*,\s*info\s*\)" ,),
        "fifo_fault_delegates_to_mmu_recovery_callback",
    )
    _require_order(
        _body(source_texts, "drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c", "gp100_mc_new"),
        (r"if\s*\(\s*nvkm_gsp_rm\s*\(\s*device->gsp\s*\)\s*\)",
         r"return\s+-ENODEV\s*;",
         r"return\s+nvkm_mc_new_\s*\("),
        "gp100_mc_backend_rejects_gsp_rm_mode",
    )

    return {
        "schema": "nvidia-hybrid.nouveau-gv100-fault-lifecycle-source-audit.v3",
        "status": "ANALYZED_STATICALLY",
        "upstream": {
            "repository": "https://github.com/torvalds/linux",
            "commit": UPSTREAM_COMMIT,
            "tag": "v7.0",
        },
        "source_files": source_rows,
        "checks": {
            "work_pending_cleared_before_callback": True,
            "queue_work_coalesces_while_pending": True,
            "flush_work_waits_for_work_item": True,
            "flush_work_last_queueing_instance": True,
            "schedule_work_uses_kernel_workqueue": True,
            "notifier_callback_runs_under_list_read_lock": True,
            "notifier_removal_waits_for_reader_section": True,
            "notifier_block_disables_then_removes_waiting_notifier": True,
            "fault_notification_schedules_worker": True,
            "teardown_blocks_flushes_then_releases_buffer": True,
            "fault_notifier_uses_waiting_registration": True,
            "fault_ring_snapshot_wrap_and_publish_before_dispatch": True,
            "event_reference_init_enables_buffer_interrupt": True,
            "event_reference_fini_disables_buffer_interrupt": True,
            "ring_storage_sized_from_hardware_entries_and_pinned": True,
            "gp100_buffer_pin_uses_bar2": True,
            "destructor_removes_notifier_before_releasing_ring_memory": True,
            "gv100_buffer_interrupt_enable_disable_registers": True,
            "gv100_startup_enables_source_then_ring_then_notification": True,
            "irq_handler_serializes_dispatch_and_rearms_after_handlers": True,
            "irq_subdevice_handler_calls_subdevice_dispatch": True,
            "subdevice_dispatch_calls_architecture_interrupt_method": True,
            "gp100_mc_maps_fault_subdevice_interrupt": True,
            "mc_interrupt_topology_uses_configured_leaf_count": True,
            "gp100_mc_uses_two_interrupt_leaves": True,
            "mc_pending_snapshots_leaf_status_for_dispatch": True,
            "mc_pending_only_snapshots_status": True,
            "nonreplayable_fault_is_decoded_and_dispatched_inline": True,
            "nonreplayable_fault_is_acknowledged_after_fifo_dispatch": True,
            "replayable_buffer0_requires_buffer_then_notifies": True,
            "replayable_buffer1_requires_buffer_then_notifies": True,
            "fifo_fault_delegates_to_mmu_recovery_callback": True,
            "gp100_mc_backend_rejects_gsp_rm_mode": True,
        },
        "inference": (
            "Because process_one_work clears PENDING before calling the work function, "
            "schedule_work may queue one follow-up execution while the current worker runs; "
            "additional notifications coalesce while that follow-up is pending. The GV100 "
            "teardown first blocks and removes a wait=true notifier whose callback is protected "
            "by the event-list read lock, then disables the buffer interrupt and flushes work "
            "before releasing the buffer. The shared NVKM allocator sizes the instance-memory "
            "ring from the hardware entry count and pins it through BAR2. The v7.0 interrupt "
            "path routes the MC fault bit to the GV100 handler under the core interrupt lock. "
            "The non-replayable register fault is decoded, sent synchronously to FIFO recovery, "
            "then acknowledged; replayable buffer events schedule work only when the matching "
            "buffer exists. FIFO recovery itself is an architecture callback."
        ),
        "limitations": [
            "Upstream Linux source analysis only; Ubuntu module source-package equivalence is unknown.",
            "This does not validate GPU producer memory ordering, ring overflow behavior, or hardware interrupt delivery; no explicit DMA barrier is established by these source checks.",
            "The audited source explicitly acknowledges the non-replayable fault bit after synchronous FIFO dispatch; it does not establish how replayable buffer status is acknowledged by hardware or other code.",
            "This is Nouveau behavior, not NVIDIA Resource Manager implementation or ABI proof.",
            "No driver module was loaded and no GPU or CUDA execution was used.",
        ],
    }


def audit_source_tree(source_root: Path) -> dict[str, Any]:
    source_texts: dict[str, str] = {}
    for relative in PINNED_SOURCE_SHA256:
        path = source_root / relative
        try:
            source_texts[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise AuditError(f"could not read pinned source: {relative}") from exc
    return audit_source_texts(source_texts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True, help="Linux source tree at the pinned commit")
    parser.add_argument("--output", type=Path, required=True, help="new private JSON receipt; existing file is never overwritten")
    args = parser.parse_args(argv)
    try:
        report = audit_source_tree(args.source_root)
        write_new_json(args.output, report)
    except AuditError as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
