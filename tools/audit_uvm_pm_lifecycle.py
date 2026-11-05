#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the R580 UVM callback and system-PM source contract.

This is a static source audit. It does not validate Linux PM ordering on a live
host or prove that a two-provider bridge is safe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone

from audit_uvm_interface_ownership import strip_c_comments


RELATIVE_FILES = (
    "common/inc/nv_uvm_types.h",
    "nvidia/nv_uvm_interface.c",
    "nvidia/nv.c",
    "nvidia/nv-procfs.c",
    "nvidia-uvm/uvm_global.c",
    "nvidia-uvm/uvm_gpu.c",
    "nvidia-uvm/uvm_gpu_non_replayable_faults.c",
    "nvidia-uvm/uvm_gpu_isr.c",
    "nvidia-uvm/uvm_volta.c",
    "nvidia-uvm/uvm_blackwell.c",
    "nvidia-uvm/uvm.c",
    "nvidia-uvm/uvm_va_space.c",
)


def _matching(source: str, open_index: int, left: str, right: str) -> int:
    depth = 0
    state = "code"
    index = open_index
    while index < len(source):
        char = source[index]
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == left:
                depth += 1
            elif char == right:
                depth -= 1
                if depth == 0:
                    return index
        else:
            if char == "\\":
                index += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        index += 1
    raise ValueError(f"unbalanced C delimiters: {left}{right}")


def function_body(source: str, name: str) -> tuple[str, int]:
    code = strip_c_comments(source)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", code):
        open_paren = code.find("(", match.start())
        close_paren = _matching(code, open_paren, "(", ")")
        brace = close_paren + 1
        while brace < len(code) and code[brace].isspace():
            brace += 1
        if brace >= len(code) or code[brace] != "{":
            continue
        close_brace = _matching(code, brace, "{", "}")
        line = code.count("\n", 0, match.start()) + 1
        return code[brace + 1:close_brace], line
    raise ValueError(f"function definition not found: {name}")


def _ordered_positions(body: str, tokens: tuple[str, ...], function: str) -> list[int]:
    positions = []
    cursor = 0
    for token in tokens:
        position = body.find(token, cursor)
        if position < 0:
            raise ValueError(f"{function}: missing ordered source token {token!r}")
        positions.append(position)
        cursor = position + len(token)
    return positions


def _has_ordered_tokens(body: str, tokens: tuple[str, ...]) -> bool:
    try:
        _ordered_positions(body, tokens, "callback contract")
    except ValueError:
        return False
    return True


def _calls(body: str, function: str) -> bool:
    return re.search(rf"\b{re.escape(function)}\s*\(", body) is not None


def audit_tree(root: Path, label: str) -> dict:
    root = root.resolve(strict=True)
    files = {relative: root / relative for relative in RELATIVE_FILES}
    missing = [relative for relative, path in files.items() if not path.is_file()]
    if missing:
        raise ValueError(f"{label}: missing source files: {', '.join(missing)}")
    raw = {relative: path.read_text(errors="strict") for relative, path in files.items()}
    code = {relative: strip_c_comments(text) for relative, text in raw.items()}

    types = code["common/inc/nv_uvm_types.h"]
    signatures = {
        "suspend": r"typedef\s+NV_STATUS\s*\(\*uvmEventSuspend_t\)\s*\(\s*void\s*\)",
        "resume": r"typedef\s+NV_STATUS\s*\(\*uvmEventResume_t\)\s*\(\s*void\s*\)",
        "start_device": r"typedef\s+NV_STATUS\s*\(\*uvmEventStartDevice_t\)\s*\(\s*const\s+NvProcessorUuid\s*\*",
        "stop_device": r"typedef\s+NV_STATUS\s*\(\*uvmEventStopDevice_t\)\s*\(\s*const\s+NvProcessorUuid\s*\*",
        "isr_top_half": r"typedef\s+NV_STATUS\s*\(\*uvmEventIsrTopHalf_t\)\s*\(\s*const\s+NvProcessorUuid\s*\*",
        "drain_p2p": r"typedef\s+NV_STATUS\s*\(\*uvmEventDrainP2P_t\)\s*\(\s*const\s+NvProcessorUuid\s*\*",
        "resume_p2p": r"typedef\s+NV_STATUS\s*\(\*uvmEventResumeP2P_t\)\s*\(\s*const\s+NvProcessorUuid\s*\*",
    }
    signature_facts = {key: bool(re.search(pattern, types)) for key, pattern in signatures.items()}
    if not all(signature_facts.values()):
        raise ValueError(f"{label}: UVM callback prototype drift: {signature_facts}")

    interface = code["nvidia/nv_uvm_interface.c"]
    register, register_line = function_body(raw["nvidia/nv_uvm_interface.c"],
                                            "nvUvmInterfaceRegisterUvmCallbacks")
    deregister, deregister_line = function_body(raw["nvidia/nv_uvm_interface.c"],
                                                "nvUvmInterfaceDeRegisterUvmOps")
    isr, isr_line = function_body(raw["nvidia/nv_uvm_interface.c"], "nv_uvm_event_interrupt")
    single_slot = (
        "getUvmEvents() != NULL" in register and
        "NV_ERR_IN_USE" in register and
        "setUvmEvents(importedUvmOps)" in register
    )
    deregister_quiesces = (
        "setUvmEvents(NULL)" in deregister and
        "on_each_cpu(flush_top_half, NULL, 1)" in deregister and
        deregister.find("setUvmEvents(NULL)") <
        deregister.find("on_each_cpu(flush_top_half, NULL, 1)")
    )
    isr_single_atomic_read = isr.count("getUvmEvents()") == 1
    if not (single_slot and deregister_quiesces and isr_single_atomic_read):
        raise ValueError(
            f"{label}: callback lifecycle drift: single={single_slot}, "
            f"quiesce={deregister_quiesces}, isr_single_read={isr_single_atomic_read}"
        )

    driver_source = raw["nvidia/nv.c"]
    suspend_driver, suspend_driver_line = function_body(driver_source, "nv_suspend_devices")
    resume_driver, resume_driver_line = function_body(driver_source, "nv_resume_devices")
    _ordered_positions(suspend_driver,
                       ("nv_preempt_user_channels", "nv_uvm_suspend", "nvidia_suspend"),
                       "nv_suspend_devices")
    _ordered_positions(resume_driver,
                       ("nvidia_resume", "nv_uvm_resume", "nv_restore_user_channels"),
                       "nv_resume_devices")

    uvm_source = raw["nvidia-uvm/uvm_global.c"]
    suspend_uvm, suspend_uvm_line = function_body(uvm_source, "uvm_suspend")
    resume_uvm, resume_uvm_line = function_body(uvm_source, "uvm_resume")
    _ordered_positions(suspend_uvm,
                       ("uvm_down_write(&g_uvm_global.pm.lock)",
                        "g_uvm_global.pm.is_suspended = true"), "uvm_suspend")
    _ordered_positions(resume_uvm,
                       ("g_uvm_global.pm.is_suspended = false",
                        "uvm_up_write(&g_uvm_global.pm.lock)"), "uvm_resume")
    if "uvm_up_write(&g_uvm_global.pm.lock)" in suspend_uvm:
        raise ValueError(f"{label}: suspend unexpectedly releases the PM lock")

    # The hybrid frontend does not wrap every nvUvmInterface call in its own
    # system-PM gate. Validate the source-owned UVM barriers that cover user
    # entry, interrupt bottom halves, retained VA spaces and deferred release.
    suspend_barriers = (
        "uvm_down_write(&g_uvm_global.pm.lock)",
        "nv_kthread_q_flush(&g_uvm_global.global_q)",
        "uvm_gpu_fault_buffer_flush(gpu)",
        "uvm_parent_gpu_access_counters_set_ignore(gpu->parent, true)",
        "uvm_parent_gpu_set_isr_suspended(gpu->parent, true)",
        "nv_kthread_q_flush(&gpu->parent->isr.bottom_half_q)",
        "uvm_va_space_down_write(va_space)",
        "g_uvm_global.pm.is_suspended = true",
    )
    _ordered_positions(suspend_uvm, suspend_barriers, "uvm_suspend")
    rm_interrupt_service_match = re.search(r"\bservice_interrupts\s*\(", suspend_uvm)
    isr_suspension_position = suspend_uvm.find(
        "uvm_parent_gpu_set_isr_suspended(gpu->parent, true)")
    suspend_calls_rm_interrupt_service_before_isr_suspension = (
        rm_interrupt_service_match is not None and
        rm_interrupt_service_match.start() < isr_suspension_position
    )
    suspend_rm_interrupt_service_line = (
        suspend_uvm_line + suspend_uvm.count("\n", 0, rm_interrupt_service_match.start())
        if rm_interrupt_service_match is not None else None
    )
    kill_channel_queue_flush = (
        "nv_kthread_q_flush(&gpu->parent->isr.kill_channel_q)" in suspend_uvm
    )
    if not kill_channel_queue_flush:
        raise ValueError(f"{label}: missing UVM kill-channel worker flush")

    resume_barriers = (
        "g_uvm_global.pm.is_suspended = false",
        "uvm_up_write(&g_uvm_global.pm.lock)",
        "nv_kthread_q_flush(&g_uvm_global.deferred_release_q)",
    )
    _ordered_positions(resume_uvm, resume_barriers, "uvm_resume")

    service_interrupts, service_interrupts_line = function_body(
        raw["nvidia-uvm/uvm_gpu.c"], "service_interrupts")
    service_interrupts_process_only = (
        "UVM_ASSERT(!in_interrupt())" in service_interrupts and
        _calls(service_interrupts, "nvUvmInterfaceServiceDeviceInterruptsRM")
    )
    kill_channel_worker, kill_channel_worker_line = function_body(
        raw["nvidia-uvm/uvm_gpu_non_replayable_faults.c"], "kill_channel_delayed")
    kill_channel_schedule, kill_channel_schedule_line = function_body(
        raw["nvidia-uvm/uvm_gpu_non_replayable_faults.c"], "schedule_kill_channel")
    kill_channel_worker_is_drained = (
        kill_channel_queue_flush and
        _calls(kill_channel_schedule, "nv_kthread_q_schedule_q_item") and
        "&parent_gpu->isr.kill_channel_q" in kill_channel_schedule and
        _calls(kill_channel_worker, "nvUvmInterfaceReportNonReplayableFault")
    )
    if not service_interrupts_process_only:
        raise ValueError(f"{label}: UVM interrupt service lost process-context guard")
    if not kill_channel_worker_is_drained:
        raise ValueError(f"{label}: non-replayable-fault RM worker is not covered by suspend drain")
    explicit_non_replayable_flush = re.search(
        r"\b[A-Za-z_][A-Za-z0-9_]*non[A-Za-z0-9_]*replay[A-Za-z0-9_]*flush[A-Za-z0-9_]*\s*\(",
        suspend_uvm, re.IGNORECASE) is not None
    non_replayable_drain_guard = re.search(
        r"if\s*\(\s*gpu->parent->isr\.non_replayable_faults\.handling\s*\)\s*\{([^{}]*)\}",
        suspend_uvm)
    non_replayable_drain_block = (
        non_replayable_drain_guard.group(1) if non_replayable_drain_guard else "")
    non_replayable_drain_under_service_lock = _has_ordered_tokens(
        non_replayable_drain_block,
        ("uvm_parent_gpu_non_replayable_faults_isr_lock(gpu->parent)",
         "uvm_parent_gpu_service_non_replayable_fault_buffer(gpu->parent)",
         "uvm_parent_gpu_non_replayable_faults_isr_unlock(gpu->parent)"))
    suspend_drains_faults_after_bottom_half = _has_ordered_tokens(
        suspend_uvm,
        ("uvm_parent_gpu_set_isr_suspended(gpu->parent, true)",
         "nv_kthread_q_flush(&gpu->parent->isr.bottom_half_q)",
         "uvm_parent_gpu_non_replayable_faults_isr_lock(gpu->parent)",
         "uvm_parent_gpu_service_non_replayable_fault_buffer(gpu->parent)",
         "uvm_parent_gpu_non_replayable_faults_isr_unlock(gpu->parent)",
         "nv_kthread_q_flush(&gpu->parent->isr.kill_channel_q)"))

    non_replayable_source = raw["nvidia-uvm/uvm_gpu_non_replayable_faults.c"]
    non_replayable_service, non_replayable_service_line = function_body(
        non_replayable_source, "uvm_parent_gpu_service_non_replayable_fault_buffer")
    non_replayable_service_drains_until_empty = (
        _calls(non_replayable_service, "fetch_non_replayable_fault_buffer_entries") and
        _calls(non_replayable_service, "service_fault") and
        re.search(r"for\s*\([^;]*;\s*i\s*<\s*cached_faults\s*;", non_replayable_service) is not None and
        re.search(r"while\s*\(\s*cached_faults\s*>\s*0\s*\)", non_replayable_service) is not None
    )
    if not non_replayable_service_drains_until_empty:
        raise ValueError(f"{label}: non-replayable-fault handler no longer drains all cached batches")

    isr_source = raw["nvidia-uvm/uvm_gpu_isr.c"]
    non_replayable_scheduler, non_replayable_scheduler_line = function_body(
        isr_source, "schedule_non_replayable_faults_handler")
    isr_top_half, isr_top_half_line = function_body(isr_source, "uvm_isr_top_half")
    non_replayable_bottom_half, non_replayable_bottom_half_line = function_body(
        isr_source, "non_replayable_faults_isr_bottom_half")
    non_replayable_pending_query_isr_top_half = (
        _calls(non_replayable_scheduler, "uvm_parent_gpu_non_replayable_faults_pending") and
        _calls(non_replayable_scheduler, "nv_kthread_q_schedule_q_item") and
        "&parent_gpu->isr.bottom_half_q" in non_replayable_scheduler and
        _calls(isr_top_half, "schedule_non_replayable_faults_handler")
    )
    non_replayable_bottom_half_dispatches_service = _calls(
        non_replayable_bottom_half, "uvm_parent_gpu_service_non_replayable_fault_buffer")
    non_replayable_worker_queue_flushed = (
        "nv_kthread_q_flush(&gpu->parent->isr.bottom_half_q)" in suspend_uvm and
        non_replayable_pending_query_isr_top_half and
        non_replayable_bottom_half_dispatches_service
    )
    if not non_replayable_pending_query_isr_top_half:
        raise ValueError(f"{label}: non-replayable-fault ISR scheduling contract changed")
    if not non_replayable_bottom_half_dispatches_service:
        raise ValueError(f"{label}: non-replayable-fault bottom half lost its service routine")
    suspend_queries_pending_faults = (
        _calls(suspend_uvm, "uvm_parent_gpu_non_replayable_faults_pending") or
        _calls(suspend_uvm, "nvUvmInterfaceHasPendingNonReplayableFaults")
    )
    suspend_schedules_pending_fault_worker = _calls(
        suspend_uvm, "schedule_non_replayable_faults_handler")
    suspend_rescans_pending_faults = (
        suspend_queries_pending_faults or suspend_schedules_pending_fault_worker)

    volta_fault_source = code["nvidia-uvm/uvm_volta.c"]
    blackwell_fault_source = code["nvidia-uvm/uvm_blackwell.c"]
    volta_non_replayable_faults_supported = re.search(
        r"parent_gpu->non_replayable_faults_supported\s*=\s*true\s*;",
        volta_fault_source) is not None
    blackwell_non_replayable_faults_supported = re.search(
        r"parent_gpu->non_replayable_faults_supported\s*=\s*true\s*;",
        blackwell_fault_source) is not None
    if not volta_non_replayable_faults_supported:
        raise ValueError(f"{label}: Volta non-replayable fault support changed")
    if not blackwell_non_replayable_faults_supported:
        raise ValueError(f"{label}: Blackwell non-replayable fault support changed")

    uvm_file_source = raw["nvidia-uvm/uvm.c"]
    uvm_ioctl, uvm_ioctl_line = function_body(uvm_file_source, "uvm_unlocked_ioctl")
    uvm_mmap, uvm_mmap_line = function_body(uvm_file_source, "uvm_mmap")
    uvm_release, uvm_release_line = function_body(uvm_file_source, "uvm_release_va_space")
    uvm_deferred_release, uvm_deferred_release_line = function_body(
        uvm_file_source, "uvm_release_deferred")
    ioctl_trylock = "uvm_down_read_trylock(&g_uvm_global.pm.lock)" in uvm_ioctl
    ioctl_rejects_suspended = "return -EAGAIN" in uvm_ioctl
    ioctl_runs_handler_under_lock = _has_ordered_tokens(
        uvm_ioctl,
        ("uvm_down_read_trylock(&g_uvm_global.pm.lock)",
         "uvm_ioctl(filp, cmd, arg)",
         "uvm_up_read(&g_uvm_global.pm.lock)"),
    )
    mmap_trylock = "uvm_down_read_trylock(&g_uvm_global.pm.lock)" in uvm_mmap
    mmap_disables_when_suspended = (
        "uvm_disable_vma(vma)" in uvm_mmap and "return 0" in uvm_mmap
    )
    mmap_unlocks_pm = "uvm_up_read(&g_uvm_global.pm.lock)" in uvm_mmap
    release_tries_pm = "uvm_down_read_trylock(&g_uvm_global.pm.lock)" in uvm_release
    release_defers_when_suspended = (
        "nv_kthread_q_item_init" in uvm_release and
        "g_uvm_global.deferred_release_q" in uvm_release
    )
    deferred_release_waits_for_resume = (
        "uvm_down_read(&g_uvm_global.pm.lock)" in uvm_deferred_release and
        _has_ordered_tokens(
            uvm_deferred_release,
            ("uvm_down_read(&g_uvm_global.pm.lock)",
             "uvm_va_space_destroy(va_space)",
             "uvm_up_read(&g_uvm_global.pm.lock)"),
        )
    )
    uvm_fault_source = raw["nvidia-uvm/uvm_va_space.c"]
    uvm_cpu_fault, uvm_cpu_fault_line = function_body(
        uvm_fault_source, "uvm_va_space_cpu_fault")
    fault_trylock_rejects = (
        "uvm_down_read_trylock_no_tracking(&g_uvm_global.pm.lock)" in uvm_cpu_fault and
        "NV_ERR_BUSY_RETRY" in uvm_cpu_fault
    )
    if not (ioctl_trylock and ioctl_rejects_suspended and ioctl_runs_handler_under_lock):
        raise ValueError(f"{label}: UVM ioctl entry lost PM trylock/return contract")
    if not (mmap_trylock and mmap_disables_when_suspended and mmap_unlocks_pm):
        raise ValueError(f"{label}: UVM mmap lost nonblocking PM contract")
    if not (release_tries_pm and release_defers_when_suspended and
            deferred_release_waits_for_resume):
        raise ValueError(f"{label}: UVM release lost deferred PM teardown contract")
    if not fault_trylock_rejects:
        raise ValueError(f"{label}: UVM CPU fault lost nonblocking PM retry contract")

    # NVIDIA exposes two distinct system-power mechanisms in R580. The procfs
    # interface runs the global nv_suspend_devices()/nv_resume_devices() path;
    # Linux PCI PMOps call nvidia_suspend()/nvidia_resume() for one device.
    pci_suspend, pci_suspend_line = function_body(driver_source, "nv_pmops_suspend")
    pci_resume, pci_resume_line = function_body(driver_source, "nv_pmops_resume")
    device_suspend, device_suspend_line = function_body(driver_source, "nvidia_suspend")
    pci_suspend_device_local = (
        _calls(pci_suspend, "nvidia_suspend") and
        not _calls(pci_suspend, "nv_set_system_power_state") and
        not _calls(pci_suspend, "nv_uvm_suspend") and
        not _calls(pci_suspend, "nv_suspend_devices")
    )
    pci_resume_device_local = (
        _calls(pci_resume, "nvidia_resume") and
        not _calls(pci_resume, "nv_set_system_power_state") and
        not _calls(pci_resume, "nv_uvm_resume") and
        not _calls(pci_resume, "nv_resume_devices")
    )
    pci_path_explicitly_preempts_channels_or_suspends_uvm = (
        _calls(pci_suspend, "nv_preempt_user_channels") or
        _calls(pci_suspend, "nv_uvm_suspend") or
        _calls(pci_resume, "nv_restore_user_channels") or
        _calls(pci_resume, "nv_uvm_resume")
    )
    if not (pci_suspend_device_local and pci_resume_device_local):
        raise ValueError(
            f"{label}: PCI PM callback must stay device-local; "
            f"suspend={pci_suspend_device_local}, resume={pci_resume_device_local}"
        )
    dpm_has_explicit_uvm_or_channel_quiesce = (
        _calls(device_suspend, "nv_uvm_suspend") or
        _calls(device_suspend, "nv_preempt_user_channels")
    )

    procfs_source = raw["nvidia/nv-procfs.c"]
    procfs_suspend, procfs_suspend_line = function_body(
        procfs_source, "nv_procfs_write_suspend")
    procfs_init, procfs_init_line = function_body(procfs_source, "nv_procfs_init")
    procfs_global_dispatch = _calls(procfs_suspend, "nv_set_system_power_state")
    if not procfs_global_dispatch:
        raise ValueError(f"{label}: procfs suspend no longer enters global system PM state machine")
    procfs_path_format = re.search(
        r"snprintf\s*\(\s*nv_dir_name\s*,\s*sizeof\s*\(\s*nv_dir_name\s*\)\s*,\s*"
        r"\"driver/%s\"\s*,\s*nv_device_name\s*\)", procfs_init) is not None
    path_buffer = re.search(r"char\s+nv_dir_name\s*\[\s*([^\]]+)\]", procfs_init)
    if path_buffer is None:
        raise ValueError(f"{label}: could not identify nv_procfs_init path buffer")
    path_buffer_expr = " ".join(path_buffer.group(1).split())
    path_buffer_fits_module_name = (
        path_buffer_expr == 'sizeof("driver/" MODULE_NAME)' and procfs_path_format
    )
    module_name_binding = re.search(
        r"\bnv_device_name\s*=\s*MODULE_NAME\s*;", strip_c_comments(driver_source)
    ) is not None

    kernel_pm_notifier_supported = False
    kernel_pm_notifier_param_gated = False
    notifier_dispatches_global = False
    notifier_line = None
    init_body, _ = function_body(driver_source, "nvidia_init_module")
    kernel_pm_notifier_supported = _calls(init_body, "register_pm_notifier")
    if kernel_pm_notifier_supported:
        kernel_pm_notifier_param_gated = "NVreg_UseKernelSuspendNotifiers" in init_body
        notifier, notifier_line = function_body(driver_source, "nv_pm_notifier")
        notifier_dispatches_global = _calls(notifier, "nv_set_system_power_state")
        if not notifier_dispatches_global:
            raise ValueError(f"{label}: registered kernel PM notifier bypasses global state machine")

    state_machine, state_machine_line = function_body(driver_source, "nv_set_system_power_state")
    global_pm_uses_both_phases = (
        _calls(state_machine, "nv_suspend_devices") and
        _calls(state_machine, "nv_resume_devices")
    )

    return {
        "label": label,
        "source_root": str(root),
        "source_files": {
            relative: {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
            for relative, path in files.items()
        },
        "callback_prototypes": signature_facts,
        "callback_registration": {
            "single_registration_slot_rejects_second": single_slot,
            "de_registration_clears_then_quiesces_isr": deregister_quiesces,
            "isr_reads_published_callback_table_once": isr_single_atomic_read,
            "source_lines": {
                "register": register_line,
                "deregister": deregister_line,
                "isr": isr_line,
            },
        },
        "nvidia_global_pm_path": {
            "per_provider_preempts_local_channels_before_uvm_suspend_before_local_gpu_suspend": True,
            "resume_calls_uvm_before_restoring_local_user_channels": True,
            "uvm_suspend_holds_global_pm_write_lock_across_callback_return": True,
            "uvm_resume_clears_suspended_state_then_releases_global_pm_lock": True,
            "reached_by_nv_set_system_power_state": global_pm_uses_both_phases,
            "state_machine_source_line": state_machine_line,
            "source_lines": {
                "driver_suspend": suspend_driver_line,
                "driver_resume": resume_driver_line,
                "uvm_suspend": suspend_uvm_line,
                "uvm_resume": resume_uvm_line,
            },
        },
        "uvm_suspend_quiescence": {
            "takes_pm_write_lock_before_draining_work": True,
            "flushes_global_work_and_isr_queues": True,
            "takes_va_space_write_locks": True,
            "resume_releases_pm_lock_then_flushes_deferred_release": True,
            "kill_channel_worker_calls_rm_and_is_drained": kill_channel_worker_is_drained,
            "rm_hardware_fault_buffer_flush_is_not_present": not explicit_non_replayable_flush,
            "rm_get_fault_service_drains_batches_until_empty":
                non_replayable_service_drains_until_empty,
            "non_replayable_fault_isr_bottom_half_dispatches_service":
                non_replayable_bottom_half_dispatches_service,
            "non_replayable_pending_query_is_in_isr_top_half":
                non_replayable_pending_query_isr_top_half,
            "non_replayable_worker_queue_flushed_during_suspend": non_replayable_worker_queue_flushed,
            "suspend_rescans_pending_faults_before_queue_flush": suspend_rescans_pending_faults,
            "rm_get_fault_batches_synchronously_serviced_under_service_lock":
                non_replayable_drain_under_service_lock,
            "suspend_calls_rm_get_fault_service_after_bottom_half_before_kill_queue_flush":
                suspend_drains_faults_after_bottom_half,
            "suspend_queries_rm_pending_fault_status": suspend_queries_pending_faults,
            "suspend_calls_rm_device_interrupt_service_before_isr_suspension":
                suspend_calls_rm_interrupt_service_before_isr_suspension,
            "source_lines": {
                "suspend": suspend_uvm_line,
                "resume": resume_uvm_line,
                "suspend_rm_interrupt_service": suspend_rm_interrupt_service_line,
                "non_replayable_service": non_replayable_service_line,
                "non_replayable_scheduler": non_replayable_scheduler_line,
                "isr_top_half": isr_top_half_line,
                "non_replayable_bottom_half": non_replayable_bottom_half_line,
                "service_interrupts": service_interrupts_line,
                "schedule_kill_channel": kill_channel_schedule_line,
                "kill_channel_worker": kill_channel_worker_line,
            },
        },
        "architecture_fault_support": {
            "volta_non_replayable_faults_supported": volta_non_replayable_faults_supported,
            "blackwell_non_replayable_faults_supported": blackwell_non_replayable_faults_supported,
        },
        "uvm_callback_context": {
            "service_interrupts_rejects_interrupt_context": service_interrupts_process_only,
            "service_interrupts_calls_rm_interface": True,
            "kill_channel_rm_callback_is_on_deferred_worker": kill_channel_worker_is_drained,
        },
        "uvm_entry_admission": {
            "ioctl_trylocks_pm_and_returns_eagain": True,
            "mmap_trylocks_pm_and_disables_vma_on_failure": True,
            "release_defers_teardown_when_pm_write_locked": True,
            "fault_trylocks_pm_and_returns_busy_retry": True,
            "deferred_release_worker_waits_until_pm_resume": True,
            "source_lines": {
                "ioctl": uvm_ioctl_line,
                "mmap": uvm_mmap_line,
                "release": uvm_release_line,
                "deferred_release": uvm_deferred_release_line,
                "cpu_fault": uvm_cpu_fault_line,
            },
        },
        "pci_device_pm_ops": {
            "suspend_is_device_local": pci_suspend_device_local,
            "resume_is_device_local": pci_resume_device_local,
            "suspend_calls_global_uvm_pm": not pci_suspend_device_local,
            "resume_calls_global_uvm_pm": not pci_resume_device_local,
            "pci_path_explicitly_preempts_channels_or_suspends_uvm":
                pci_path_explicitly_preempts_channels_or_suspends_uvm,
            "device_suspend_helper_explicitly_preempts_channels_or_suspends_uvm":
                dpm_has_explicit_uvm_or_channel_quiesce,
            "source_lines": {
                "suspend": pci_suspend_line,
                "resume": pci_resume_line,
                "device_suspend_helper": device_suspend_line,
            },
        },
        "system_pm_entrypoints": {
            "procfs_suspend_calls_global_state_machine": procfs_global_dispatch,
            "kernel_pm_notifier_supported": kernel_pm_notifier_supported,
            "kernel_pm_notifier_registration_is_parameter_gated": kernel_pm_notifier_param_gated,
            "kernel_pm_notifier_dispatches_global_state_machine": notifier_dispatches_global,
            "source_lines": {
                "procfs_suspend": procfs_suspend_line,
                "procfs_init": procfs_init_line,
                "kernel_pm_notifier": notifier_line,
            },
        },
        "procfs_namespace": {
            "directory_uses_module_name": procfs_path_format and module_name_binding,
            "module_name_binding_present": module_name_binding,
            "path_format_is_driver_percent_s": procfs_path_format,
            "buffer_expression": path_buffer_expr,
            "buffer_sizes_module_named_path": path_buffer_fits_module_name,
            "note": (
                "A private module name must use a buffer sized for driver/<MODULE_NAME> "
                "including the NUL; the stock fixed 20-byte buffer is too short for the "
                "hybrid580 backend names."
            ),
        },
        "bridge_implication": (
            "The procfs command enters NVIDIA's global system-PM state machine, while "
            "nv_pmops_suspend/resume are per-device PCI callbacks and do not call UVM. "
            "Open R580 may also register a kernel PM notifier; the proprietary R580 tree "
            "does not. Global suspend/resume callbacks still have no UUID, and UVM keeps "
            "its global PM write lock held across suspend. A dual-provider design must "
            "audit notifier ownership, procfs orchestration, channel quiescence and GPU "
            "restore phases separately; merely deduplicating PCI callbacks is irrelevant."
        ),
        "qualification": "static-source-contract-only",
    }


COMMON_UVM_QUIESCENCE_FACTS = (
    "takes_pm_write_lock_before_draining_work",
    "flushes_global_work_and_isr_queues",
    "takes_va_space_write_locks",
    "resume_releases_pm_lock_then_flushes_deferred_release",
    "kill_channel_worker_calls_rm_and_is_drained",
    "rm_hardware_fault_buffer_flush_is_not_present",
    "rm_get_fault_service_drains_batches_until_empty",
    "non_replayable_fault_isr_bottom_half_dispatches_service",
    "non_replayable_pending_query_is_in_isr_top_half",
    "non_replayable_worker_queue_flushed_during_suspend",
    "suspend_rescans_pending_faults_before_queue_flush",
    "suspend_queries_rm_pending_fault_status",
    "suspend_calls_rm_device_interrupt_service_before_isr_suspension",
)


def _shared_contract_facts(tree: dict) -> tuple:
    quiescence = tree["uvm_suspend_quiescence"]
    return (
        tree["callback_prototypes"],
        {key: value for key, value in tree["callback_registration"].items()
         if key != "source_lines"},
        tree["nvidia_global_pm_path"][
            "uvm_suspend_holds_global_pm_write_lock_across_callback_return"],
        tree["nvidia_global_pm_path"][
            "uvm_resume_clears_suspended_state_then_releases_global_pm_lock"],
        tree["architecture_fault_support"],
        tuple(quiescence[key] for key in COMMON_UVM_QUIESCENCE_FACTS),
    )


def assert_independent_trees_agree(trees: list[dict]) -> None:
    if not trees:
        raise ValueError("at least one R580 source tree is required")
    expected = _shared_contract_facts(trees[0])
    if any(_shared_contract_facts(tree) != expected for tree in trees[1:]):
        raise ValueError("R580 source trees disagree on the audited shared UVM/PM contract")


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", required=True,
                        help="R580 kernel source root; repeat for independent trees")
    parser.add_argument("--label", action="append", required=True,
                        help="label corresponding to each --source")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.source) != len(args.label):
        parser.error("pass one --label for every --source")
    trees = [audit_tree(Path(root), label)
             for root, label in zip(args.source, args.label, strict=True)]
    assert_independent_trees_agree(trees)
    report = {
        "schema": "hybrid580-uvm-pm-lifecycle-v5",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_trees": trees,
        "independent_trees_agree": True,
        "qualification": "static-source-contract-only",
        "limitations": [
            "No provider modules were loaded and no Linux suspend/resume was attempted.",
            "The report distinguishes procfs/global NVIDIA PM from PCI device PM callbacks.",
            "This does not prove systemd choreography, Linux async device ordering, or a live bridge.",
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
        print(f"audit_uvm_pm_lifecycle: {exc}", file=sys.stderr)
        raise SystemExit(2)
