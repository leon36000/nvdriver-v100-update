#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Record NVIDIA system-sleep script and systemd entry-point contracts.

This is a static inventory of installed text files. It does not invoke sleep,
write procfs, change systemd state, or test a driver transition.
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


PROC_SUSPEND_RE = re.compile(r"/proc/driver/[A-Za-z0-9_.-]+/suspend")
CANONICAL_GUARD_RE = re.compile(
    r"\[\s*!\s*-f\s+/proc/driver/nvidia/suspend\s*\]")


def _record(path: Path) -> tuple[dict, str]:
    resolved = path.resolve(strict=True)
    content = resolved.read_bytes()
    return ({"path": str(resolved),
             "sha256": hashlib.sha256(content).hexdigest(),
             "bytes": len(content)}, content.decode("utf-8", errors="strict"))


def audit_config(script: Path, units: list[Path], hooks: list[Path], label: str) -> dict:
    script_record, script_text = _record(script)
    paths = sorted(set(PROC_SUSPEND_RE.findall(script_text)))
    unit_records = []
    for unit in units:
        record, content = _record(unit)
        exec_start = [line.strip() for line in content.splitlines()
                      if line.lstrip().startswith("ExecStart=")]
        unit_records.append({**record,
                             "exec_start": exec_start,
                             "invokes_nvidia_sleep_script": any(
                                 "nvidia-sleep.sh" in line for line in exec_start)})
    hook_records = []
    for hook in hooks:
        record, content = _record(hook)
        hook_records.append({**record,
                             "references_nvidia_sleep_script": "nvidia-sleep.sh" in content,
                             "invokes_nvidia_sleep_script": "nvidia-sleep.sh" in content})
    return {
        "schema": "nvidia-system-sleep-hook-audit-v1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "label": label,
        "sleep_script": {
            **script_record,
            "suspend_files": paths,
            "canonical_path_guard_present": CANONICAL_GUARD_RE.search(script_text) is not None,
            "uses_only_canonical_nvidia_procfs_path": paths == ["/proc/driver/nvidia/suspend"],
        },
        "systemd_units": unit_records,
        "system_sleep_hooks": hook_records,
        "qualification": "installed-userspace-static-inventory-only",
        "limitations": [
            "No system suspend/resume was attempted.",
            "The result describes only the supplied host files and does not prove a hybrid PM protocol.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", type=Path, required=True,
                        help="installed NVIDIA sleep script")
    parser.add_argument("--unit", type=Path, action="append", default=[],
                        help="systemd unit to inspect; repeat as needed")
    parser.add_argument("--hook", type=Path, action="append", default=[],
                        help="systemd system-sleep hook to inspect; repeat as needed")
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = audit_config(args.script, args.unit, args.hook, args.label)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({"output": str(args.output),
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      "qualification": report["qualification"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"audit_nvidia_sleep_hook: {exc}", file=sys.stderr)
        raise SystemExit(2)
