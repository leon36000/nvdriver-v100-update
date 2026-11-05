#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correct the lifecycle interpretation of the pinned PC3 V100 probe report."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT_SHA256 = "db7611cbe32731b269db5800ea7d3567e9c5d3f19c3c410c17c8eec9b3975b8f"
DEFAULT_INPUT = ROOT / "evidence/pc3-v100-elf-kprobe-address-v4-20261022.json"


def build_correction(report: dict, input_sha256: str) -> dict:
    if input_sha256 != INPUT_SHA256:
        raise ValueError("source report hash is not the pinned v4 evidence")
    if (report.get("schema") != "nvidia-hybrid-pc3-v100-elf-kprobe-address-transport-v1" or
            report.get("status") != "observed"):
        raise ValueError("source transport report is not the pinned observed schema")
    remote = report.get("remote")
    guest = remote.get("guest") if isinstance(remote, dict) else None
    if not isinstance(guest, dict) or guest.get("schema") != "nvidia-hybrid-pc3-v100-elf-kprobe-address-v1":
        raise ValueError("source guest report is missing")

    expected = {
        "control_probe": ("control", True),
        "control_absolute_probe": ("control_absolute", True),
        "nvidia_named_probe": ("nvidia_named", False),
        "nvidia_absolute_probe": ("nvidia_absolute", False),
    }
    states = {}
    for key, (event_name, registered) in expected.items():
        probe = guest.get(key)
        if (not isinstance(probe, dict) or probe.get("event_name") != event_name or
                probe.get("definition_added") is not registered or
                probe.get("event_enabled") is not False or probe.get("cleanup_verified") is not True):
            raise ValueError("source probe states do not match the pinned differential result")
        if registered and (probe.get("definition_removed") is not True or
                           probe.get("resolution") != "resolved_by_kernel"):
            raise ValueError("resolved control event was not removed")
        if not registered and (probe.get("error_errno") != 22 or
                               probe.get("resolution") != "failed"):
            raise ValueError("failed NVIDIA target event did not fail before creation")
        states[event_name] = {
            "trace_event_definition_added":registered,
            "event_enabled_observed":probe.get("event_enabled"),
            "definition_removed":probe.get("definition_removed") is True,
            "cleanup_verified":probe.get("cleanup_verified") is True,
            "registration_interpretation":("registered_disabled_then_removed" if registered else "not_registered"),
        }

    if (guest.get("kprobe_attached") is not False or
            guest.get("kernel_release") != "6.8.0-147-generic" or
            guest.get("kernel_probe_config", {}).get("config_dynamic_ftrace") != "y" or
            guest.get("kernel_probe_config", {}).get("config_kprobe_events_on_notrace") != "n"):
        raise ValueError("source legacy field or kernel identity/configuration changed")

    return {
        "schema":"nvidia-hybrid-pc3-v100-kprobe-semantics-correction-v1",
        "status":"interpreted",
        "source_report":"evidence/pc3-v100-elf-kprobe-address-v4-20261022.json",
        "source_report_sha256":input_sha256,
        "source_probe_sha256":report.get("probe_source_sha256"),
        "source_legacy_kprobe_attached_value":False,
        "corrected_lifecycle":states,
        "registered_disabled_events":["control", "control_absolute"],
        "handlers_enabled_by_runner":False,
        "all_created_event_definitions_removed":True,
        "nvidia_target_events_registered":False,
        "stock_driver_changed":False,
        "pci_binding_changed":False,
        "read_only":False,
        "interpretation":"The legacy kprobe_attached=false field did not mean that no kprobe was registered. Successful control trace-event definitions registered disabled kprobes and were removed; the runner never enabled their handlers. Both NVIDIA definitions failed with EINVAL before creation.",
        "kernel_source_basis":{
            "upstream_version":"Linux v6.8",
            "trace_kprobe_source":"https://github.com/torvalds/linux/blob/v6.8/kernel/trace/trace_kprobe.c#L2942-L2995",
            "notrace_guard_source":"https://github.com/torvalds/linux/blob/v6.8/kernel/trace/trace_kprobe.c#L2871-L2966",
            "disabled_probe_documentation":"https://github.com/torvalds/linux/blob/v6.8/Documentation/trace/kprobes.rst#L310-L317",
            "guest_distribution_source_verified":False,
            "limitation":"This source-backed interpretation uses upstream v6.8 and the guest's observed 6.8.0-147-generic configuration. The exact Ubuntu downstream source package was not diffed; the generic trace error does not prove which guard returned EINVAL for the NVIDIA target.",
        },
    }


def write_private_new(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output already exists")
    source = args.input.read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    report = json.loads(source.decode("utf-8", "strict"))
    correction = build_correction(report, source_hash)
    correction["created_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write_private_new(args.output, correction)
    print(json.dumps({"status":correction["status"], "evidence":str(args.output),
                      "source_report_sha256":source_hash}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
