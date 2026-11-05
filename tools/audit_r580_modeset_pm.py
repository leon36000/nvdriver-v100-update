#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the exact R580 channel-depth path and modeset PM ownership surface.

This is a static source audit. It does not load modules or invoke a PM cycle.
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
from audit_uvm_interface_ownership import strip_c_comments


FILES = (
    "nvidia/nv.c",
    "nvidia/nv-modeset-interface.c",
    "nvidia-modeset/nvidia-modeset-linux.c",
    "common/inc/nv-chardev-numbers.h",
)


def _read_bundle(root: Path, label: str) -> tuple[dict[str, Path], dict[str, str]]:
    root = root.resolve(strict=True)
    paths = {relative: root / relative for relative in FILES}
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError(f"{label}: missing modeset/PM source: {', '.join(missing)}")
    return paths, {name: path.read_text(errors="strict") for name, path in paths.items()}


def audit_bundle(root: Path, label: str) -> dict:
    paths, raw = _read_bundle(root, label)
    driver = raw["nvidia/nv.c"]
    interface = strip_c_comments(raw["nvidia/nv-modeset-interface.c"])
    modeset = strip_c_comments(raw["nvidia-modeset/nvidia-modeset-linux.c"])
    modeset = re.sub(r"\\\r?\n", " ", modeset)

    suspend, suspend_line = function_body(driver, "nv_suspend_devices")
    resume, resume_line = function_body(driver, "nv_resume_devices")
    pci_suspend, pci_suspend_line = function_body(driver, "nvidia_suspend")
    pci_resume, pci_resume_line = function_body(driver, "nvidia_resume")
    callback_setter, setter_line = function_body(
        raw["nvidia/nv-modeset-interface.c"], "nvidia_modeset_set_callbacks")
    mode_suspend, mode_suspend_line = function_body(
        raw["nvidia/nv-modeset-interface.c"], "nvidia_modeset_suspend")
    mode_resume, mode_resume_line = function_body(
        raw["nvidia/nv-modeset-interface.c"], "nvidia_modeset_resume")
    nvkms_suspend, nvkms_suspend_line = function_body(
        raw["nvidia-modeset/nvidia-modeset-linux.c"], "nvkms_suspend")
    nvkms_resume, nvkms_resume_line = function_body(
        raw["nvidia-modeset/nvidia-modeset-linux.c"], "nvkms_resume")
    lock_pm, lock_line = function_body(
        raw["nvidia-modeset/nvidia-modeset-linux.c"], "nvkms_write_lock_pm_lock")
    unlock_pm, unlock_line = function_body(
        raw["nvidia-modeset/nvidia-modeset-linux.c"], "nvkms_write_unlock_pm_lock")
    register_chrdev, register_line = function_body(
        raw["nvidia-modeset/nvidia-modeset-linux.c"], "nvkms_register_chrdev")

    def guarded_global_call(body: str, direction: str) -> bool:
        call = f"nvidia_modeset_{direction}(0)"
        return re.search(
            r"if\s*\(\s*pm_action_depth\s*!=\s*NV_PM_ACTION_DEPTH_CHANNELS\s*\)\s*"
            r"\{\s*" + re.escape(call) + r"\s*;\s*\}", body) is not None

    suspend_modeset_pos = suspend.find("nvidia_modeset_suspend(0)")
    suspend_channels_pos = suspend.find("NV_PM_ACTION_DEPTH_CHANNELS")
    rollback = suspend[suspend.find("done:"):] if "done:" in suspend else ""
    channel_suspend_skips_modeset = guarded_global_call(suspend, "suspend")
    channel_resume_skips_modeset = (
        "resume_modeset:" in resume and guarded_global_call(resume, "resume")
    )
    channel_rollback_skips_modeset = guarded_global_call(rollback, "resume")
    per_gpu_suspend_keeps_modeset = _calls(pci_suspend, "nvidia_modeset_suspend") and (
        "nv->gpu_id" in pci_suspend
    )
    per_gpu_resume_keeps_modeset = _calls(pci_resume, "nvidia_modeset_resume") and (
        "nv->gpu_id" in pci_resume
    )
    if not _calls(suspend, "nv_preempt_user_channels"):
        raise ValueError(f"{label}: channel depth no longer preempts user channels")

    setter_rejects_second = (
        "nv_modeset_callbacks != NULL && cb != NULL" in callback_setter and
        "nv_modeset_callbacks == NULL && cb == NULL" in callback_setter and
        "return -EINVAL" in callback_setter
    )
    mode_callbacks_void = (
        re.search(r"\bvoid\s+nvidia_modeset_suspend\s*\(", interface) is not None and
        re.search(r"\bvoid\s+nvidia_modeset_resume\s*\(", interface) is not None and
        _calls(mode_suspend, "nv_modeset_callbacks->suspend") and
        _calls(mode_resume, "nv_modeset_callbacks->resume")
    )
    global_lock_pair = (
        "gpuId == 0" in nvkms_suspend and _calls(nvkms_suspend, "nvkms_write_lock_pm_lock") and
        "gpuId == 0" in nvkms_resume and _calls(nvkms_resume, "nvkms_write_unlock_pm_lock") and
        _calls(lock_pm, "down_write") and _calls(unlock_pm, "up_write")
    )

    numbers = strip_c_comments(raw["common/inc/nv-chardev-numbers.h"])
    major = re.search(r"#\s*define\s+NV_MAJOR_DEVICE_NUMBER\s+(\d+)", numbers)
    minor = re.search(r"#\s*define\s+NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE\s+(\d+)", numbers)
    fixed_chrdev_reservation = (
        major is not None and minor is not None and
        major.group(1) == "195" and minor.group(1) == "254" and
        re.search(r"register_chrdev_region\s*\(\s*NVKMS_RDEV\s*,\s*1\s*,", register_chrdev) is not None and
        re.search(r"#\s*define\s+NVKMS_RDEV\b\s*\(?\s*MKDEV\s*\(\s*NV_MAJOR_DEVICE_NUMBER\s*,\s*NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE", modeset) is not None
    )
    if not setter_rejects_second:
        raise ValueError(f"{label}: callback registration is no longer single-slot as audited")
    if not mode_callbacks_void:
        raise ValueError(f"{label}: modeset suspend/resume status contract changed")
    if not global_lock_pair:
        raise ValueError(f"{label}: global modeset PM lock is not paired")
    if not (channel_suspend_skips_modeset and channel_resume_skips_modeset and
            channel_rollback_skips_modeset and per_gpu_suspend_keeps_modeset and
            per_gpu_resume_keeps_modeset):
        raise ValueError(
            f"{label}: channels-only phase must defer NVKMS to balanced per-GPU PCI DPM callbacks"
        )
    if not fixed_chrdev_reservation:
        raise ValueError(f"{label}: fixed modeset device reservation changed")

    return {
        "label": label,
        "source_root": str(root.resolve()),
        "source_files": {
            name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "bytes": path.stat().st_size}
            for name, path in paths.items()
        },
        "provider_pm": {
            "channel_depth_skips_aggregate_modeset_suspend": channel_suspend_skips_modeset,
            "channel_depth_skips_aggregate_modeset_resume": channel_resume_skips_modeset,
            "channel_depth_rollback_skips_aggregate_modeset_resume": channel_rollback_skips_modeset,
            "pci_dpm_keeps_per_gpu_modeset_suspend": per_gpu_suspend_keeps_modeset,
            "pci_dpm_keeps_per_gpu_modeset_resume": per_gpu_resume_keeps_modeset,
            "modeset_suspend_precedes_channel_preemption": (
                suspend_modeset_pos >= 0 and
                suspend_modeset_pos < suspend.find("nv_preempt_user_channels")
            ),
            "source_lines": {"suspend": suspend_line, "resume": resume_line,
                             "pci_suspend": pci_suspend_line,
                             "pci_resume": pci_resume_line},
        },
        "modeset_interface": {
            "callback_slot_rejects_second_registration": setter_rejects_second,
            "suspend_resume_callbacks_return_no_status": mode_callbacks_void,
            "gpu_zero_pairs_global_write_lock_and_unlock": global_lock_pair,
            "global_write_lock_uses_down_write_up_write": True,
            "fixed_chrdev_reservation": fixed_chrdev_reservation,
            "fixed_chrdev_major": int(major.group(1)),
            "fixed_chrdev_minor": int(minor.group(1)),
            "source_lines": {"callback_setter": setter_line,
                             "suspend_dispatch": mode_suspend_line,
                             "resume_dispatch": mode_resume_line,
                             "nvkms_suspend": nvkms_suspend_line,
                             "nvkms_resume": nvkms_resume_line,
                             "write_lock": lock_line,
                             "write_unlock": unlock_line,
                             "register_chrdev": register_line},
        },
        "interpretation": [
            "The aggregate channels-only phase skips global NVKMS suspend/resume and its failed-suspend rollback; PCI DPM owns balanced per-GPU callbacks.",
            "The callback setter is one slot per provider-core instance; the source does not define a cross-provider owner.",
            "A modeset callback is void, so its failure cannot be aggregated by the provider PM state machine.",
            "The modeset module reserves one fixed device number; loading independent copies requires resolving that collision.",
            "The PCI DPM deferral contract is verified statically only; callback ordering, error paths, and runtime lock pairing have not run on a kernel.",
        ],
        "qualification": "static-source-contract-only",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, action="append", required=True,
                        help="provider bundle root containing nvidia/ and nvidia-modeset/")
    parser.add_argument("--label", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.source) != len(args.label):
        parser.error("pass one --label for every --source")
    bundles = [audit_bundle(root, label) for root, label in
               zip(args.source, args.label, strict=True)]
    report = {
        "schema": "r580-modeset-pm-audit-v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bundles": bundles,
        "qualification": "static-source-contract-only",
        "limitations": [
            "No module was loaded and no PM transition was executed.",
            "The report does not prove whether the two private cores would bind one modeset instance or two.",
            "The opaque RM modeset operations and display behavior are not inspected.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({"output": str(args.output),
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      "bundles": [bundle["label"] for bundle in bundles]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"audit_r580_modeset_pm: {exc}", file=sys.stderr)
        raise SystemExit(2)
