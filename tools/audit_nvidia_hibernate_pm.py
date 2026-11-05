#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit NVIDIA hibernation callbacks against Linux DPM dispatch.

This is a bounded static audit of pinned source trees. It does not load a
module, enter system sleep, or claim that opaque RM operations are safe.
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

from audit_uvm_pm_lifecycle import _calls, function_body


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR_HEADER = ROOT / "src/hybrid580_system_pm_coordinator.h"
DRIVER_FILES = ("nvidia/nv.c", "nvidia/nv-procfs.c")
LINUX_FILES = ("main.c", "hibernate.c")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _ops_table(source: str, label: str) -> dict[str, str]:
    match = re.search(
        r"\bstruct\s+dev_pm_ops\s+nv_pm_ops\s*=\s*\{(?P<body>.*?)\}\s*;",
        source,
        re.S,
    )
    _require(match is not None, f"{label}: cannot locate nv_pm_ops initializer")
    table = dict(re.findall(r"\.([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)", match["body"]))
    required = {"suspend", "resume", "freeze", "thaw", "poweroff", "restore"}
    _require(required <= table.keys(), f"{label}: nv_pm_ops misses {sorted(required - table.keys())}")
    return {key: table[key] for key in sorted(required)}


def _source_fingerprint(root: Path, relative_files: tuple[str, ...]) -> dict:
    result = {}
    for relative in relative_files:
        path = root / relative
        result[relative] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
    return result


def _pm_dispatch(linux_root: Path) -> dict:
    main_source = (linux_root / "main.c").read_text(errors="strict")
    dispatch, dispatch_line = function_body(main_source, "pm_op")
    mappings = {
        "suspend": bool(re.search(r"case\s+PM_EVENT_SUSPEND\s*:\s*return\s+ops->suspend\s*;", dispatch)),
        "resume": bool(re.search(r"case\s+PM_EVENT_RESUME\s*:\s*return\s+ops->resume\s*;", dispatch)),
        "freeze": bool(re.search(r"case\s+PM_EVENT_FREEZE\s*:\s*(?:case\s+PM_EVENT_QUIESCE\s*:\s*)?return\s+ops->freeze\s*;", dispatch)),
        "quiesce": bool(re.search(r"case\s+PM_EVENT_QUIESCE\s*:\s*return\s+ops->freeze\s*;", dispatch)),
        "poweroff": bool(re.search(r"case\s+PM_EVENT_POWEROFF\s*:\s*(?:case\s+PM_EVENT_HIBERNATE\s*:\s*)?return\s+ops->poweroff\s*;", dispatch)),
        "hibernate": bool(re.search(r"case\s+PM_EVENT_HIBERNATE\s*:\s*return\s+ops->poweroff\s*;", dispatch)),
        "thaw": bool(re.search(r"case\s+PM_EVENT_THAW\s*:\s*(?:case\s+PM_EVENT_RECOVER\s*:\s*)?return\s+ops->thaw\s*;", dispatch)),
        "recover": bool(re.search(r"case\s+PM_EVENT_RECOVER\s*:\s*return\s+ops->thaw\s*;", dispatch)),
        "restore": bool(re.search(r"case\s+PM_EVENT_RESTORE\s*:\s*return\s+ops->restore\s*;", dispatch)),
    }
    event_errors = {
        "suspend": "Linux DPM SUSPEND no longer maps to suspend",
        "resume": "Linux DPM RESUME no longer maps to resume",
        "freeze": "Linux DPM FREEZE no longer maps to freeze",
        "quiesce": "Linux DPM QUIESCE no longer maps to freeze",
        "poweroff": "Linux DPM POWEROFF no longer maps to poweroff",
        "hibernate": "Linux DPM HIBERNATE no longer maps to poweroff",
        "thaw": "Linux DPM THAW no longer maps to thaw",
        "recover": "Linux DPM RECOVER no longer maps to thaw",
        "restore": "Linux DPM RESTORE no longer maps to restore",
    }
    for event, message in event_errors.items():
        _require(mappings[event], message)
    event_to_callback = {
        "PM_EVENT_SUSPEND": "suspend", "PM_EVENT_RESUME": "resume",
        "PM_EVENT_FREEZE": "freeze", "PM_EVENT_QUIESCE": "freeze",
        "PM_EVENT_POWEROFF": "poweroff", "PM_EVENT_HIBERNATE": "poweroff",
        "PM_EVENT_THAW": "thaw", "PM_EVENT_RECOVER": "thaw",
        "PM_EVENT_RESTORE": "restore",
    }
    return {
        "freeze": "freeze",
        "thaw": "thaw",
        "recover": "thaw",
        "restore": "restore",
        "event_to_dev_pm_ops": event_to_callback,
        "source_line": dispatch_line,
        "source_contract": mappings,
    }


def _resume_error_propagation(linux_root: Path) -> dict:
    """Check whether device-link resume waits carry supplier callback errors.

    Linux v7.0 orders a consumer after its suppliers using completion waits.
    A completed callback and a successful callback are different facts, so the
    audit also checks the resume callback's completion/error-record ordering
    and the scope in which DPM aggregates failures.
    """
    source = (linux_root / "main.c").read_text(errors="strict")
    wait_body, wait_line = function_body(source, "dpm_wait")
    suppliers_body, suppliers_line = function_body(source, "dpm_wait_for_suppliers")
    superior_body, superior_line = function_body(source, "dpm_wait_for_superior")

    _require(bool(re.search(r"wait_for_completion\s*\(\s*&dev->power.completion\s*\)", wait_body)),
             "Linux dpm_wait no longer waits on the device PM completion")
    _require(_calls(suppliers_body, "dpm_wait"),
             "Linux supplier ordering no longer waits on supplier completion")

    wait_chain = "\n".join((wait_body, suppliers_body, superior_body))
    checks_error = bool(re.search(
        r"(?:async_error|(?:supplier|dev)->power\.(?:resume_)?(?:error|status)|"
        r"device_pm_(?:get|read)_.*error)", wait_chain))
    _require(not checks_error,
             "Linux supplier callback status propagation changed; re-audit the hybrid recovery contract")
    _require(bool(re.search(r"return\s+device_pm_initialized\s*\(\s*dev\s*\)\s*;",
                            superior_body)),
             "Linux superior wait no longer returns only device initialization state")

    callbacks = {}
    for name in ("device_resume_noirq", "device_resume_early", "device_resume"):
        body, line = function_body(source, name)
        complete = body.find("complete_all(&dev->power.completion)")
        record_match = re.search(
            r"WRITE_ONCE\s*\(\s*async_error\s*,\s*error\s*\)", body)
        record = record_match.start() if record_match is not None else -1
        _require(complete >= 0 and record > complete,
                 f"Linux {name} no longer completes the device before recording its callback error")
        _require(bool(re.search(r"if\s*\(\s*error\s*\)\s*\{[^}]*WRITE_ONCE\s*\(\s*async_error\s*,\s*error\s*\)",
                                body, re.S)),
                 f"Linux {name} no longer records callback errors in the global async_error")
        callbacks[name] = {"source_line": line,
                           "signals_completion_before_error_record": True,
                           "error_record": "global async_error"}

    phase_functions = ("dpm_noirq_resume_devices", "dpm_resume_early", "dpm_resume")
    phases = {}
    for name in phase_functions:
        body, line = function_body(source, name)
        reset = re.search(r"\basync_error\s*=\s*0\s*;", body)
        synchronize = body.find("async_synchronize_full()")
        aggregate = body.find("READ_ONCE(async_error)")
        save = body.find("dpm_save_failed_step(")
        _require(reset is not None and synchronize >= 0 and aggregate > synchronize and save > aggregate,
                 f"Linux {name} no longer aggregates resume errors after async completion")
        phases[name] = {"source_line": line,
                        "resets_global_error_at_phase_start": True,
                        "aggregates_after_async_completion": True,
                        "per_device_error_latch": False}

    return {
        "source_lines": {"dpm_wait": wait_line,
                         "dpm_wait_for_suppliers": suppliers_line,
                         "dpm_wait_for_superior": superior_line},
        "supplier_ordering_waits_for_completion": True,
        "supplier_wait_checks_callback_status": False,
        "consumer_callback_may_run_after_supplier_resume_error": True,
        "resume_callbacks": callbacks,
        "resume_completion_signaled_before_global_error_record": all(
            callback["signals_completion_before_error_record"]
            for callback in callbacks.values()),
        "resume_phase_aggregation": phases,
        "resume_errors_aggregated_only_as_global_async_error": True,
        "hybrid_requirement": (
            "A provider-owned sticky per-device resume result must be queried by the aggregate "
            "consumer after supplier completions; device-link ordering alone cannot qualify GPU recovery."
        ),
    }


def _coordinator_dpm_mapping(header: Path) -> dict:
    header = Path(header).resolve(strict=True)
    source = header.read_text(errors="strict")
    body, line = function_body(source, "hybrid580_pm_dpm_action_for_event")
    switch = re.search(r"switch\s*\(\s*event\s*\)\s*\{([\s\S]*)\}", body)
    _require(switch is not None,
             "coordinator has no event switch in hybrid580_pm_dpm_action_for_event")
    actual: dict[str, str] = {}
    pending: list[str] = []
    tokens = re.finditer(
        r"\bcase\s+(HYBRID580_PM_DPM_[A-Z_]+)\s*:|"
        r"\breturn\s+(HYBRID580_PM_DPM_ACTION_[A-Z_]+)\s*;",
        switch.group(1))
    for token in tokens:
        event, action = token.groups()
        if event is not None:
            pending.append(event)
            continue
        for name in pending:
            if name in actual:
                raise ValueError(f"coordinator PM event is mapped more than once: {name}")
            actual[name] = action
        pending.clear()
    expected = {
        "HYBRID580_PM_DPM_SUSPEND": "HYBRID580_PM_DPM_ACTION_QUIESCE",
        "HYBRID580_PM_DPM_FREEZE": "HYBRID580_PM_DPM_ACTION_QUIESCE",
        "HYBRID580_PM_DPM_QUIESCE": "HYBRID580_PM_DPM_ACTION_QUIESCE",
        "HYBRID580_PM_DPM_POWEROFF": "HYBRID580_PM_DPM_ACTION_QUIESCE",
        "HYBRID580_PM_DPM_HIBERNATE": "HYBRID580_PM_DPM_ACTION_QUIESCE",
        "HYBRID580_PM_DPM_RESUME": "HYBRID580_PM_DPM_ACTION_RESTORE",
        "HYBRID580_PM_DPM_THAW": "HYBRID580_PM_DPM_ACTION_RESTORE",
        "HYBRID580_PM_DPM_RECOVER": "HYBRID580_PM_DPM_ACTION_RESTORE",
        "HYBRID580_PM_DPM_RESTORE": "HYBRID580_PM_DPM_ACTION_RESTORE",
        "HYBRID580_PM_DPM_UNRELATED": "HYBRID580_PM_DPM_ACTION_IGNORE",
    }
    if actual != expected:
        raise ValueError("coordinator PM event matrix differs from Linux v7.0 DPM callbacks: "
                         + json.dumps({"expected": expected, "actual": actual}, sort_keys=True))
    return {"header": str(header),
            "sha256": hashlib.sha256(header.read_bytes()).hexdigest(),
            "source_line": line, "event_to_coordinator_action": actual,
            "matches_linux_pm_ops": True}


def _hibernation_flow(linux_root: Path) -> dict:
    source = (linux_root / "hibernate.c").read_text(errors="strict")
    snapshot, snapshot_line = function_body(source, "hibernation_snapshot")
    hibernate, hibernate_line = function_body(source, "hibernate")
    has_freeze = "dpm_suspend(PMSG_FREEZE)" in snapshot
    resume_selects_recover_thaw_restore = bool(re.search(
        r"in_suspend\s*\?\s*\(\s*error\s*\?\s*PMSG_RECOVER\s*:\s*PMSG_THAW\s*\)\s*:\s*PMSG_RESTORE",
        snapshot,
    ))
    _require(has_freeze, "Linux hibernation snapshot no longer suspends devices with PMSG_FREEZE")
    _require(resume_selects_recover_thaw_restore,
             "Linux snapshot resume no longer selects RECOVER/THAW/RESTORE as audited")
    prepare = hibernate.find("pm_notifier_call_chain_robust(PM_HIBERNATION_PREPARE")
    snapshot_call = hibernate.find("hibernation_snapshot(")
    post = hibernate.find("pm_notifier_call_chain(PM_POST_HIBERNATION")
    _require(prepare >= 0 and snapshot_call > prepare and post > snapshot_call,
             "Linux hibernation prepare/snapshot/post ordering changed")
    return {
        "prepare_notifier_precedes_dpm_freeze": True,
        "post_notifier_follows_snapshot_dpm_resume": True,
        "snapshot_device_suspend_event": "PMSG_FREEZE",
        "snapshot_resume_success": "PMSG_THAW",
        "snapshot_resume_error": "PMSG_RECOVER",
        "restored_image_resume": "PMSG_RESTORE",
        "source_lines": {"snapshot": snapshot_line, "hibernate": hibernate_line},
    }


def audit_inputs(driver_root: Path, linux_root: Path, label: str,
                 coordinator_header: Path | None = None) -> dict:
    driver_root = driver_root.resolve(strict=True)
    linux_root = linux_root.resolve(strict=True)
    driver_paths = {relative: driver_root / relative for relative in DRIVER_FILES}
    linux_paths = {relative: linux_root / relative for relative in LINUX_FILES}
    missing = [str(path) for path in (*driver_paths.values(), *linux_paths.values()) if not path.is_file()]
    _require(not missing, f"{label}: missing source files: {', '.join(missing)}")
    driver_source = driver_paths["nvidia/nv.c"].read_text(errors="strict")
    procfs_source = driver_paths["nvidia/nv-procfs.c"].read_text(errors="strict")
    linux_dispatch = _pm_dispatch(linux_root)
    linux_resume_errors = _resume_error_propagation(linux_root)
    coordinator_mapping = (
        _coordinator_dpm_mapping(coordinator_header)
        if coordinator_header is not None else None)
    hibernation_flow = _hibernation_flow(linux_root)
    ops = _ops_table(driver_source, label)

    callbacks = {}
    for phase, expected in (("suspend", "nv_pmops_suspend"), ("resume", "nv_pmops_resume"),
                            ("freeze", "nv_pmops_freeze"), ("thaw", "nv_pmops_thaw"),
                            ("poweroff", "nv_pmops_poweroff"), ("restore", "nv_pmops_restore")):
        _require(ops[phase] == expected,
                 f"{label}: dev_pm_ops.{phase} maps to {ops[phase]}, expected {expected}")
        body, line = function_body(driver_source, ops[phase])
        callbacks[phase] = {"calls_nvidia_suspend": _calls(body, "nvidia_suspend"),
                            "calls_nvidia_resume": _calls(body, "nvidia_resume"),
                            "returns_zero_without_resume": phase in ("thaw", "poweroff") and
                            bool(re.search(r"return\s+0\s*;", body)) and
                            not _calls(body, "nvidia_resume"),
                            "source_line": line}

    _require(callbacks["freeze"]["calls_nvidia_suspend"],
             f"{label}: freeze callback no longer suspends the device")
    _require(callbacks["restore"]["calls_nvidia_resume"],
             f"{label}: restore callback no longer resumes the device")
    suspend_body, suspend_line = function_body(driver_source, "nvidia_suspend")
    resume_body, resume_line = function_body(driver_source, "nvidia_resume")
    nested_suspend_count = bool(re.search(
        r"NV_FLAG_SUSPENDED[\s\S]{0,160}suspend_count\s*\+\+",
        suspend_body))
    nested_resume_decrements_only = bool(re.search(
        r"if\s*\(\s*nvl->suspend_count\s*!=\s*0\s*\)\s*\{\s*nvl->suspend_count--\s*;\s*\}\s*else\s*\{",
        resume_body, re.S)) and "nv_power_management" in resume_body
    resume_clears_flag_only_after_success = bool(re.search(
        r"if\s*\(\s*status\s*==\s*NV_OK\s*\)\s*\{[^}]*NV_FLAG_SUSPENDED",
        resume_body, re.S))
    _require(nested_suspend_count, f"{label}: expected nested suspend_count increment not found")
    _require(nested_resume_decrements_only,
             f"{label}: expected nested resume decrement-versus-power-up contract not found")

    notifier_supported = "register_pm_notifier" in driver_source
    notifier_body = ""
    if notifier_supported:
        notifier_body, _ = function_body(driver_source, "nv_pm_notifier")
    notifier_hibernation_prepare = "PM_HIBERNATION_PREPARE" in notifier_body
    notifier_post_hibernation = "PM_POST_HIBERNATION" in notifier_body
    procfs_suspend, procfs_line = function_body(procfs_source, "nv_procfs_write_suspend")
    global_suspend, global_suspend_line = function_body(driver_source, "nv_suspend_devices")
    global_gpu_suspend_preserve_filtered = bool(re.search(
        r"if\s*\(\s*nv_dev_needs_vidmem_preservation\(nv\)\s*\)\s*\{"
        r"[\s\S]{0,320}nvidia_suspend\s*\(",
        global_suspend,
    ))
    global_pm = {
        "procfs_enters_global_power_state": _calls(procfs_suspend, "nv_set_system_power_state"),
        "global_suspend_includes_gpu_suspend_call": _calls(global_suspend, "nvidia_suspend"),
        "global_gpu_suspend_filtered_to_vidmem_preservation_devices": global_gpu_suspend_preserve_filtered,
        "global_suspend_calls_shared_uvm": _calls(global_suspend, "nv_uvm_suspend"),
        "kernel_notifier_supported": notifier_supported,
        "kernel_notifier_handles_hibernation_prepare": notifier_hibernation_prepare,
        "kernel_notifier_handles_post_hibernation": notifier_post_hibernation,
        "kernel_notifier_calls_global_power_state": _calls(notifier_body, "nv_set_system_power_state") if notifier_supported else False,
        "source_lines": {"procfs_suspend": procfs_line, "global_suspend_devices": global_suspend_line},
    }
    if not global_pm["procfs_enters_global_power_state"]:
        raise ValueError(f"{label}: procfs suspend does not enter global PM")

    overlap_hazard = (
        global_pm["global_suspend_includes_gpu_suspend_call"] and
        callbacks["freeze"]["calls_nvidia_suspend"] and
        callbacks["thaw"]["returns_zero_without_resume"] and
        nested_suspend_count and nested_resume_decrements_only
    )
    return {
        "label": label,
        "driver_source_root": str(driver_root),
        "linux_source_root": str(linux_root),
        "source_files": {
            "driver": _source_fingerprint(driver_root, DRIVER_FILES),
            "linux": _source_fingerprint(linux_root, LINUX_FILES),
        },
        "driver_pm_ops": ops,
        "driver_callbacks": callbacks,
        "linux_dpm_dispatch": linux_dispatch,
        "linux_resume_error_propagation": linux_resume_errors,
        "coordinator_dpm_mapping": coordinator_mapping,
        "hibernation_order": hibernation_flow,
        "suspend_counter": {
            "nested_suspend_increments": nested_suspend_count,
            "nested_resume_only_decrements": nested_resume_decrements_only,
            "physical_resume_clears_flag_only_after_success": resume_clears_flag_only_after_success,
            "source_lines": {"suspend": suspend_line, "resume": resume_line},
        },
        "global_pm": global_pm,
        "conditional_overlap_recovery_hazard": {
            "present_if_global_path_suspends_a_dpm_gpu": overlap_hazard,
            "statement": (
                "If a procfs/global PM path suspends a device before DPM FREEZE (R595's global "
                "loop filters the GPU phase to devices requiring video-memory preservation), "
                "DPM FREEZE "
                "increments suspend_count; Linux RECOVER/THAW reaches the driver's no-op thaw; "
                "one later global resume then only decrements the nested count. An additional "
                "resume is needed to clear the suspended flag. This is a conditional source "
                "interaction, not proof that every hibernation flow leaves a GPU suspended."
            ) if overlap_hazard else "The audited source combination does not establish this interaction.",
            "coordinator_rule": (
                "For the hybrid design, PREPARE should quiesce every provider's channels and "
                "suspend shared UVM exactly once, but leave GPU power transitions to PCI DPM. "
                "After DPM, POST must resume any provider GPU still suspended, resume shared "
                "UVM once, then restore channels. This avoids an extra NVIDIA suspend_count "
                "layer; it remains a design hypothesis until implemented and runtime-tested."
            ),
        },
        "qualification": "static-source-contract-only",
    }


def write_report(path: Path, report: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, action="append", required=True)
    parser.add_argument("--label", action="append", required=True)
    parser.add_argument("--linux", type=Path, required=True,
                        help="Linux source root containing main.c and hibernate.c")
    parser.add_argument("--linux-ref", required=True, help="tag/version and source provenance")
    parser.add_argument("--coordinator-header", type=Path,
                        default=COORDINATOR_HEADER,
                        help="hybrid coordinator header whose abstract DPM routes are audited")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.driver) != len(args.label):
        parser.error("pass one --label for every --driver")
    trees = [audit_inputs(root, args.linux, label, args.coordinator_header)
             for root, label in zip(args.driver, args.label, strict=True)]
    report = {
        "schema": "nvidia-hibernate-dpm-contract-v2",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "linux_reference": args.linux_ref,
        "source_trees": trees,
        "qualification": "static-source-contract-only",
        "limitations": [
            "Linux reference source is the upstream tag supplied to this audit; it is not an audit of Ubuntu's patched source tree.",
            "Opaque rm_power_management() behavior is outside the static contract.",
            "No module was loaded and no hibernation, suspend, recovery, or resume transition was attempted.",
            "The conditional suspend_count interaction must be confirmed against deployed hook settings and hardware before any PM coordinator is activated.",
        ],
    }
    digest = write_report(args.output, report)
    print(json.dumps({"output": str(args.output), "sha256": digest,
                      "trees": [tree["label"] for tree in trees]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"audit_nvidia_hibernate_pm: {exc}", file=sys.stderr)
        raise SystemExit(2)
