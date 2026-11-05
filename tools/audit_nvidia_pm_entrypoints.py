#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare NVIDIA kernel PM entry points without conflating PCI and UVM PM.

Static source audit only. It never loads a module or performs a sleep transition.
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

from audit_uvm_pm_lifecycle import _calls, _ordered_positions, function_body
from audit_uvm_interface_ownership import strip_c_comments


RELATIVE_FILES = (
    "nvidia/nv.c",
    "nvidia/nv-msi.c",
    "nvidia/nv-procfs.c",
    "nvidia/nv-pci.c",
    "nvidia-uvm/uvm_global.c",
    "nvidia/nv-kthread-q.c",
    "common/inc/nv-kthread-q.h",
    "common/inc/nv-linux.h",
)


def _control_bypass(body: str, operation: str) -> bool:
    control = re.search(
        r"if\s*\(\s*nv_is_control_device\s*\(\s*inode\s*\)\s*\)", body
    )
    dispatch = re.search(rf"\b{re.escape(operation)}\s*\(", body)
    lock = re.search(
        r"\b(?:nv_down_read_interruptible|down_read)\s*\(\s*&nv_system_pm_lock\s*\)",
        body,
    )
    return (control is not None and dispatch is not None and lock is not None and
            control.start() < dispatch.start() < lock.start())


def audit_tree(root: Path, label: str) -> dict:
    root = root.resolve(strict=True)
    files = {relative: root / relative for relative in RELATIVE_FILES}
    missing = [relative for relative, path in files.items() if not path.is_file()]
    if missing:
        raise ValueError(f"{label}: missing source files: {', '.join(missing)}")
    raw = {relative: path.read_text(errors="strict") for relative, path in files.items()}
    driver = raw["nvidia/nv.c"]
    msi_source = raw["nvidia/nv-msi.c"]
    procfs_source = raw["nvidia/nv-procfs.c"]
    pci_source = raw["nvidia/nv-pci.c"]
    uvm_source = raw["nvidia-uvm/uvm_global.c"]
    queue_source = raw["nvidia/nv-kthread-q.c"]
    linux_header = raw["common/inc/nv-linux.h"]

    pm_suspend, pm_suspend_line = function_body(driver, "nv_pmops_suspend")
    pm_resume, pm_resume_line = function_body(driver, "nv_pmops_resume")
    global_state, global_state_line = function_body(driver, "nv_set_system_power_state")
    suspend_devices, suspend_devices_line = function_body(driver, "nv_suspend_devices")
    resume_devices, resume_devices_line = function_body(driver, "nv_resume_devices")
    nvidia_suspend, nvidia_suspend_line = function_body(driver, "nvidia_suspend")
    procfs_suspend, procfs_suspend_line = function_body(
        procfs_source, "nv_procfs_write_suspend")
    procfs_init, procfs_init_line = function_body(procfs_source, "nv_procfs_init")
    init_module, init_module_line = function_body(driver, "nvidia_init_module")
    ordinary_open, ordinary_open_line = function_body(driver, "nvidia_open")
    ordinary_close, ordinary_close_line = function_body(driver, "nvidia_close")
    deferred_open, deferred_open_line = function_body(driver, "nvidia_open_deferred")
    power_management, power_management_line = function_body(
        driver, "nv_power_management")
    pci_remove, pci_remove_line = function_body(pci_source, "nv_pci_remove")
    pci_probe, pci_probe_line = function_body(pci_source, "nv_pci_probe")
    uvm_suspend, uvm_suspend_line = function_body(uvm_source, "uvm_suspend")
    start_device, start_device_line = function_body(driver, "nv_start_device")
    msix_request, msix_request_line = function_body(msi_source, "nv_request_msix_irq")
    irq_flags, irq_flags_line = function_body(linux_header, "nv_default_irq_flags")
    isr, isr_line = function_body(driver, "nvidia_isr")
    msix_isr, msix_isr_line = function_body(driver, "nvidia_isr_msix")
    msix_thread, msix_thread_line = function_body(
        driver, "nvidia_isr_msix_kthread_bh")
    shutdown_adapter, shutdown_adapter_line = function_body(
        driver, "nv_shutdown_adapter")
    queue_stop, queue_stop_line = function_body(queue_source, "nv_kthread_q_stop")
    queue_schedule, queue_schedule_line = function_body(
        queue_source, "nv_kthread_q_schedule_q_item")
    queue_raw_schedule, queue_raw_schedule_line = function_body(
        queue_source, "_raw_q_schedule")
    pm_suspend, pm_suspend_line = function_body(driver, "nv_pmops_suspend")
    pm_resume, pm_resume_line = function_body(driver, "nv_pmops_resume")

    pmops_device_local = (
        _calls(pm_suspend, "nvidia_suspend") and
        not any(_calls(pm_suspend, name) for name in
                ("nv_set_system_power_state", "nv_uvm_suspend", "nv_suspend_devices")) and
        _calls(pm_resume, "nvidia_resume") and
        not any(_calls(pm_resume, name) for name in
                ("nv_set_system_power_state", "nv_uvm_resume", "nv_resume_devices"))
    )
    explicit_channel_quiesce_in_dpm = any(
        _calls(body, name) for body in (pm_suspend, pm_resume, nvidia_suspend)
        for name in ("nv_preempt_user_channels", "nv_restore_user_channels")
    )
    explicit_uvm_pm_in_dpm = any(
        _calls(body, name) for body in (pm_suspend, pm_resume, nvidia_suspend)
        for name in ("nv_uvm_suspend", "nv_uvm_resume")
    )
    procfs_enters_global_state = _calls(procfs_suspend, "nv_set_system_power_state")
    if not pmops_device_local:
        raise ValueError(f"{label}: PCI PMOps no longer remain device-local")
    if not procfs_enters_global_state:
        raise ValueError(f"{label}: procfs suspend bypasses global PM state machine")
    if not (_calls(global_state, "nv_suspend_devices") and
            _calls(global_state, "nv_resume_devices")):
        raise ValueError(f"{label}: global PM state machine lost suspend/resume dispatch")

    control_open_bypasses = _control_bypass(ordinary_open, "nvidia_ctl_open")
    control_close_bypasses = _control_bypass(ordinary_close, "nvidia_ctl_close")
    deferred_open_bypasses = "nv_system_pm_lock" not in deferred_open
    open_queue_flush = re.search(
        r"nv_kthread_q_flush\s*\(\s*&nvl->open_q\s*\)", power_management
    )
    rm_power = re.search(r"\brm_power_management\s*\(", power_management)
    native_suspend_flushes_open_q = (
        open_queue_flush is not None and rm_power is not None and
        open_queue_flush.start() < rm_power.start()
    )
    native_dpm_bypasses_rwsem = all(
        "nv_system_pm_lock" not in body and
        "nv_set_system_power_state" not in body and _calls(body, expected)
        for body, expected in ((pm_suspend, "nvidia_suspend"),
                               (pm_resume, "nvidia_resume"))
    )
    pci_remove_bypasses_rwsem = (
        "nv_system_pm_lock" not in pci_remove and
        _calls(pci_remove, "nv_shutdown_adapter")
    )
    uvm_separate_pm_and_drain = all(
        token in uvm_suspend for token in (
            "g_uvm_global.pm.lock",
            "nv_kthread_q_flush(&g_uvm_global.global_q)",
            "gpu->parent->isr.bottom_half_q",
        )
    )
    rwsem_complete_lifetime_gate = not any((
        control_open_bypasses,
        control_close_bypasses,
        deferred_open_bypasses,
        native_dpm_bypasses_rwsem,
        pci_remove_bypasses_rwsem,
        uvm_separate_pm_and_drain,
    ))

    def ordered(body: str, markers: tuple[str, ...]) -> bool:
        clean = strip_c_comments(body)
        positions = []
        for marker in markers:
            match = re.search(marker, clean)
            if match is None:
                return False
            positions.append(match.start())
        return positions == sorted(positions)

    clean_irq_flags = strip_c_comments(irq_flags)
    legacy_irq_shared = bool(re.search(
        r"if\s*\(\s*\(\s*nv->flags\s*&\s*\(\s*NV_FLAG_USES_MSI\s*\|\s*"
        r"NV_FLAG_USES_MSIX\s*\)\s*\)\s*==\s*0\s*\)\s*"
        r"flags\s*\|=\s*IRQF_SHARED\s*;", clean_irq_flags))
    clean_start = " ".join(strip_c_comments(start_device).split())
    clean_probe = " ".join(strip_c_comments(pci_probe).split())
    legacy_irq_registration = re.search(
        r"request_threaded_irq\s*\(\s*nv->interrupt_line\s*,\s*nvidia_isr\s*,",
        clean_start)
    msix_irq_registration = re.search(
        r"\bnv_request_msix_irq\s*\(\s*nvl\s*\)", clean_start)
    bottom_half_item_init = re.search(
        r"nv_kthread_q_item_init\s*\(\s*&nvl->bottom_half_q_item\b", clean_start)
    bottom_half_queue_init = re.search(
        r"nv_kthread_q_init\s*\(\s*&nvl->bottom_half_q\b", clean_start)
    rm_adapter_init = re.search(r"\brm_init_adapter\s*\(", clean_start)
    open_flag_set = re.search(r"nv->flags\s*\|=\s*NV_FLAG_OPEN\b", clean_start)
    rm_private_init = re.search(r"\brm_init_private_state\s*\(", clean_probe)
    pci_bus_master = re.search(r"\bpci_set_master\s*\(", clean_probe)
    startup_irq_before_queue = (
        bottom_half_item_init is not None and
        all(match is not None and match.start() < bottom_half_item_init.start()
            for match in (legacy_irq_registration, msix_irq_registration))
    )
    startup_queue_order = (
        bottom_half_item_init is not None and bottom_half_queue_init is not None and
        bottom_half_item_init.start() < bottom_half_queue_init.start()
    )
    startup_queue_before_rm = (
        bottom_half_queue_init is not None and rm_adapter_init is not None and
        bottom_half_queue_init.start() < rm_adapter_init.start()
    )
    startup_rm_before_open = (
        rm_adapter_init is not None and open_flag_set is not None and
        rm_adapter_init.start() < open_flag_set.start()
    )
    probe_private_before_bus_master = (
        rm_private_init is not None and pci_bus_master is not None and
        rm_private_init.start() < pci_bus_master.start()
    )
    legacy_threaded_registration = bool(re.search(
        r"request_threaded_irq\s*\(\s*nv->interrupt_line\s*,\s*nvidia_isr\s*,\s*"
        r"nvidia_isr_kthread_bh\s*,\s*nv_default_irq_flags\s*\(\s*nv\s*\)",
        clean_start))
    clean_msix_request = strip_c_comments(msix_request)
    msix_threaded_registration = bool(re.search(
        r"request_threaded_irq\s*\(\s*msix_entries->vector\s*,\s*"
        r"nvidia_isr_msix\s*,\s*nvidia_isr_msix_kthread_bh\s*,\s*"
        r"nv_default_irq_flags\s*\(\s*nv\s*\)", clean_msix_request))
    msix_vector_counted = re.search(
        r"i\s*<\s*nvl->num_intr", clean_msix_request) is not None
    msix_partial_rollback = (
        re.search(r"for\s*\(\s*j\s*=\s*0\s*;\s*j\s*<\s*i\s*;",
                  clean_msix_request) is not None and
        _calls(clean_msix_request, "free_irq")
    )
    msix_top_serialized = ordered(msix_isr, (
        r"NV_SPIN_LOCK\s*\(\s*&nvl->msix_isr_lock\s*\)",
        r"nvidia_isr\s*\(",
        r"NV_SPIN_UNLOCK\s*\(\s*&nvl->msix_isr_lock\s*\)",
    ))
    msix_thread_serialized = ordered(msix_thread, (
        r"os_acquire_mutex\s*\(\s*nvl->msix_bh_mutex\s*\)",
        r"nvidia_isr_common_bh\s*\(",
        r"os_release_mutex\s*\(\s*nvl->msix_bh_mutex\s*\)",
    ))
    isr_schedules_bottom_half = (
        _calls(isr, "nv_kthread_q_schedule_q_item") and
        re.search(r"&nvl->bottom_half_q", strip_c_comments(isr)) is not None
    )
    clean_shutdown = strip_c_comments(shutdown_adapter)
    stop_queue = re.search(
        r"nv_kthread_q_stop\s*\(\s*&nvl->bottom_half_q\s*\)", clean_shutdown)
    irq_release_positions = [match.start() for pattern in (
        r"\bfree_irq\s*\(", r"\bnv_free_msix_irq\s*\(",
        r"\bnv_soc_free_irqs\s*\(")
        for match in re.finditer(pattern, clean_shutdown)]
    shutdown_queue_before_irq_release = (
        stop_queue is not None and bool(irq_release_positions) and
        all(stop_queue.start() < position for position in irq_release_positions)
    )
    pm_path = "\n".join((pm_suspend, nvidia_suspend, power_management))
    clean_pm_path = strip_c_comments(pm_path)
    suspend_path_has_irq_barrier = any(re.search(
        rf"\b{api}\s*\(", clean_pm_path) for api in
        ("synchronize_irq", "disable_irq", "disable_irq_nosync", "free_irq"))

    clean_queue_stop = strip_c_comments(queue_stop)
    clean_queue_schedule = strip_c_comments(queue_schedule)
    clean_queue_raw_schedule = strip_c_comments(queue_raw_schedule)
    queue_flush_position = re.search(
        r"\bnv_kthread_q_flush\s*\(", clean_queue_stop)
    queue_exit_position = re.search(
        r"\batomic_set\s*\(\s*&q->main_loop_should_exit\s*,\s*1\s*\)",
        clean_queue_stop)
    queue_schedule_exit = re.search(
        r"\batomic_read\s*\(\s*&q->main_loop_should_exit\s*\)",
        clean_queue_schedule)
    queue_schedule_enqueue = re.search(
        r"\b_raw_q_schedule\s*\(", clean_queue_schedule)
    queue_stop_flushes_before_exit = (
        queue_flush_position is not None and queue_exit_position is not None and
        queue_flush_position.start() < queue_exit_position.start()
    )
    queue_schedule_checks_before_enqueue = (
        queue_schedule_exit is not None and queue_schedule_enqueue is not None and
        queue_schedule_exit.start() < queue_schedule_enqueue.start()
    )
    raw_lock = re.search(
        r"\bspin_lock_irqsave\s*\(\s*&q->q_lock", clean_queue_raw_schedule)
    raw_exit_check = re.search(
        r"\batomic_read\s*\(\s*&q->main_loop_should_exit\s*\)",
        clean_queue_raw_schedule)
    raw_enqueue = re.search(r"\blist_add_tail\s*\(", clean_queue_raw_schedule)
    raw_unlock = re.search(
        r"\bspin_unlock_irqrestore\s*\(\s*&q->q_lock", clean_queue_raw_schedule)
    raw_exit_recheck_under_lock = (
        raw_lock is not None and raw_exit_check is not None and
        raw_enqueue is not None and raw_unlock is not None and
        raw_lock.start() < raw_exit_check.start() < raw_enqueue.start() < raw_unlock.start()
    )
    queue_exit_transition_locked = ordered(queue_stop, (
        r"spin_lock_irqsave\s*\(\s*&q->q_lock",
        r"atomic_set\s*\(\s*&q->main_loop_should_exit\s*,\s*1\s*\)",
        r"spin_unlock_irqrestore\s*\(\s*&q->q_lock",
    ))
    queue_stop_is_atomic_producer_barrier = (
        queue_exit_transition_locked and raw_exit_recheck_under_lock and
        queue_exit_position is not None and queue_flush_position is not None and
        queue_exit_position.start() < queue_flush_position.start()
    )
    queue_post_flush_enqueue_window = (
        queue_stop_flushes_before_exit and queue_schedule_checks_before_enqueue and
        not raw_exit_recheck_under_lock
    )

    _ordered_positions(suspend_devices,
                       ("nv_preempt_user_channels", "nv_uvm_suspend", "nvidia_suspend"),
                       "nv_suspend_devices")
    _ordered_positions(resume_devices,
                       ("nvidia_resume", "nv_uvm_resume", "nv_restore_user_channels"),
                       "nv_resume_devices")

    notifier_supported = _calls(init_module, "register_pm_notifier")
    notifier_parameter_gated = False
    notifier_dispatches_global = False
    notifier_line = None
    if notifier_supported:
        notifier_parameter_gated = "NVreg_UseKernelSuspendNotifiers" in init_module
        notifier, notifier_line = function_body(driver, "nv_pm_notifier")
        notifier_dispatches_global = _calls(notifier, "nv_set_system_power_state")
        if not notifier_dispatches_global:
            raise ValueError(f"{label}: kernel PM notifier bypasses global state machine")

    path_format = re.search(
        r"snprintf\s*\(\s*nv_dir_name\s*,\s*sizeof\s*\(\s*nv_dir_name\s*\)\s*,\s*"
        r"\"driver/%s\"\s*,\s*nv_device_name\s*\)", procfs_init) is not None
    path_buffer = re.search(r"char\s+nv_dir_name\s*\[\s*([^\]]+)\]", procfs_init)
    if path_buffer is None:
        raise ValueError(f"{label}: cannot find procfs path buffer")
    path_expr = " ".join(path_buffer.group(1).split())
    module_name_bound = re.search(
        r"\bnv_device_name\s*=\s*MODULE_NAME\s*;", strip_c_comments(driver)
    ) is not None

    return {
        "label": label,
        "source_root": str(root),
        "source_files": {
            relative: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                       "bytes": path.stat().st_size}
            for relative, path in files.items()
        },
        "pci_device_pm": {
            "callbacks_call_per_device_suspend_resume": pmops_device_local,
            "explicit_channel_preempt_or_restore_in_pmops_or_helper": explicit_channel_quiesce_in_dpm,
            "explicit_uvm_suspend_or_resume_in_pmops_or_helper": explicit_uvm_pm_in_dpm,
            "source_lines": {"suspend": pm_suspend_line, "resume": pm_resume_line,
                             "nvidia_suspend": nvidia_suspend_line},
        },
        "global_nvidia_pm": {
            "procfs_suspend_enters_global_state_machine": procfs_enters_global_state,
            "state_machine_dispatches_suspend_and_resume": True,
            "suspend_preempts_channels_then_suspends_uvm_then_local_gpus": True,
            "resume_restores_local_gpus_then_resumes_uvm_then_channels": True,
            "source_lines": {"procfs_suspend": procfs_suspend_line,
                             "state_machine": global_state_line,
                             "suspend_devices": suspend_devices_line,
                             "resume_devices": resume_devices_line},
        },
        "kernel_pm_notifier": {
            "registration_supported_in_source": notifier_supported,
            "registration_parameter_gated": notifier_parameter_gated,
            "notifier_dispatches_global_state_machine": notifier_dispatches_global,
            "source_lines": {"init": init_module_line, "notifier": notifier_line},
        },
        "procfs_namespace": {
            "directory_derived_from_module_name": path_format and module_name_bound,
            "buffer_expression": path_expr,
            "buffer_sized_for_private_module_name":
                path_expr == 'sizeof("driver/" MODULE_NAME)' and path_format,
            "source_line": procfs_init_line,
        },
        "lifetime_gate": {
            "control_open_bypasses_rwsem": control_open_bypasses,
            "control_close_bypasses_rwsem": control_close_bypasses,
            "deferred_open_bypasses_rwsem": deferred_open_bypasses,
            "native_suspend_flushes_deferred_opens_before_rm": native_suspend_flushes_open_q,
            "native_pci_dpm_bypasses_rwsem": native_dpm_bypasses_rwsem,
            "pci_remove_bypasses_rwsem_and_tears_down_adapter": pci_remove_bypasses_rwsem,
            "uvm_uses_separate_pm_lock_and_queue_drain": uvm_separate_pm_and_drain,
            "nv_system_pm_lock_is_complete_lifetime_gate": rwsem_complete_lifetime_gate,
            "source_lines": {
                "open": ordinary_open_line,
                "close": ordinary_close_line,
                "deferred_open": deferred_open_line,
                "power_management": power_management_line,
                "pci_remove": pci_remove_line,
                "uvm_suspend": uvm_suspend_line,
                "pmops_suspend": pm_suspend_line,
                "pmops_resume": pm_resume_line,
            },
        },
        "irq_lifecycle": {
            "legacy_irq_allows_sharing": legacy_irq_shared,
            "legacy_irq_uses_threaded_rm_handlers": legacy_threaded_registration,
            "msix_uses_threaded_per_vector_handlers":
                msix_threaded_registration and msix_vector_counted,
            "msix_setup_rolls_back_prior_vectors_on_partial_failure": msix_partial_rollback,
            "msix_top_half_serializes_rm_isr": msix_top_serialized,
            "msix_thread_serializes_common_bottom_half": msix_thread_serialized,
            "isr_can_schedule_provider_bottom_half_queue": isr_schedules_bottom_half,
            "shutdown_stops_bottom_half_queue_before_free_irq":
                shutdown_queue_before_irq_release,
            "suspend_path_explicitly_synchronizes_or_frees_irqs":
                suspend_path_has_irq_barrier,
            "suspend_path_calls_opaque_rm_power_management":
                _calls(power_management, "rm_power_management"),
            "source_lines": {
                "start_device": start_device_line,
                "msix_request": msix_request_line,
                "irq_flags": irq_flags_line,
                "isr": isr_line,
                "msix_isr": msix_isr_line,
                "msix_thread": msix_thread_line,
                "shutdown_adapter": shutdown_adapter_line,
                "nvidia_suspend": nvidia_suspend_line,
                "power_management": power_management_line,
            },
        },
        "startup_order": {
            "legacy_irq_registered_before_bottom_half_queue_setup":
                legacy_irq_registration is not None and bottom_half_item_init is not None and
                legacy_irq_registration.start() < bottom_half_item_init.start(),
            "msix_irq_registered_before_bottom_half_queue_setup":
                msix_irq_registration is not None and bottom_half_item_init is not None and
                msix_irq_registration.start() < bottom_half_item_init.start(),
            "both_irq_modes_registered_before_bottom_half_queue_setup":
                startup_irq_before_queue,
            "bottom_half_item_initialized_before_queue": startup_queue_order,
            "queue_initialized_before_rm_init_adapter": startup_queue_before_rm,
            "rm_init_adapter_before_open_flag": startup_rm_before_open,
            "rm_private_state_initialized_before_pci_bus_master":
                probe_private_before_bus_master,
            "source_lines": {
                "pci_probe": pci_probe_line,
                "start_device": start_device_line,
            },
            "qualification": "static-source-ordering-only",
        },
        "deferred_queue_lifecycle": {
            "stop_flushes_before_setting_exit": queue_stop_flushes_before_exit,
            "schedule_checks_exit_before_enqueue_entrypoint":
                queue_schedule_checks_before_enqueue,
            "raw_enqueue_rechecks_exit_under_queue_lock": raw_exit_recheck_under_lock,
            "stop_exit_transition_uses_queue_lock": queue_exit_transition_locked,
            "stop_is_atomic_producer_barrier": queue_stop_is_atomic_producer_barrier,
            "source_exposes_post_flush_enqueue_window": queue_post_flush_enqueue_window,
            "source_lines": {
                "stop": queue_stop_line,
                "schedule": queue_schedule_line,
                "raw_schedule": queue_raw_schedule_line,
            },
        },
        "qualification": "static-source-contract-only",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--label", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.source) != len(args.label):
        parser.error("pass one --label for every --source")
    trees = [audit_tree(root, label) for root, label in
             zip(args.source, args.label, strict=True)]
    report = {
        "schema": "nvidia-pm-entrypoints-v5",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audit_tool": {
            "path": str(Path(__file__).resolve()),
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "source_trees": trees,
        "qualification": "static-source-contract-only",
        "limitations": [
            "No provider modules were loaded and no Linux suspend/resume was attempted.",
            "The audit does not inspect opaque RM behavior behind rm_power_management().",
            "A source-level notifier registration path does not prove its runtime module parameter value.",
            "The audit does not prove Linux free_irq, threaded-IRQ, or vendor queue-drain semantics.",
            "Startup ordering does not establish whether PCI GPU interrupt sources are masked or can fire before RM adapter initialization.",
            "Source ordering alone does not establish whether queued bottom-half work can race shutdown.",
            "The queue race predicate is a source-level interleaving window, not a hardware reproducer.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({"output": str(args.output),
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      "trees": [tree["label"] for tree in trees]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"audit_nvidia_pm_entrypoints: {exc}", file=sys.stderr)
        raise SystemExit(2)
