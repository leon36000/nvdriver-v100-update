#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differentially resolve one kernel and one R580 module symbol.

The experiment sequentially adds uniquely named event definitions for a known
kernel control and the target NVIDIA symbol, verifies each remains disabled,
and removes each in a finally block. It never enables tracing or changes the
NVIDIA module, PCI binding, VM configuration, or firmware.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
AUDIT_TOOL_PATH = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
TARGET_MODULE = "nvidia"
TARGET_SYMBOL = "rm_init_adapter"
GROUP = "codex_v100_resolve_" + secrets.token_hex(6)
EVENT = "target"

GUEST_PROBE = r'''import csv,json,os,re,subprocess
from pathlib import Path

GROUP = __GROUP__
EVENTS = Path("/sys/kernel/tracing/kprobe_events")
TARGETS = (("control", "do_sys_openat2"),
           ("nvidia_target", "nvidia:rm_init_adapter"))
report = {
    "schema":"nvidia-hybrid-pc3-v100-kprobe-symbol-resolution-v1",
    "hostname":os.uname().nodename, "kernel_release":os.uname().release,
    "effective_uid":os.geteuid(), "event_group":GROUP,
    "stock_driver_changed":False, "pci_binding_changed":False,
    "kprobe_attached":False, "status":"preflight_failed"
}

def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

def run(argv):
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=20, check=False,
                              env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
    except (OSError, subprocess.TimeoutExpired):
        return None

def event_present(contents, event):
    if contents is None:
        return None
    for line in contents.splitlines():
        fields = line.split()
        if fields and fields[0].split(":", 1)[-1] == GROUP + "/" + event:
            return True
    return False

def append_command(command):
    fd = os.open(EVENTS, os.O_WRONLY | os.O_APPEND)
    try:
        payload = (command + "\n").encode("ascii")
        if os.write(fd, payload) != len(payload):
            raise OSError(5, "short tracefs control write")
    finally:
        os.close(fd)

def error_log_excerpt(target):
    text = read(Path("/sys/kernel/tracing/error_log"))
    if text is None:
        return []
    lines = text.splitlines()
    needle = GROUP + "/nvidia_target"
    index = next((i for i, line in enumerate(lines) if needle in line), None)
    if index is None:
        return []
    relevant = lines[max(0, index - 1):min(len(lines), index + 2)]
    return [re.sub(r"0x[0-9a-fA-F]+", "<address>", line.strip())[:240]
            for line in relevant]

def try_symbol(event, target):
    item = {"event_name":event, "target":target, "definition_added":False,
            "event_enabled":False, "definition_removed":False,
            "cleanup_verified":False, "resolution":"failed", "operation_stage":"preflight"}
    attempted = False
    enable_path = Path("/sys/kernel/tracing/events") / GROUP / event / "enable"
    try:
        if event_present(read(EVENTS), event) is not False:
            raise RuntimeError("event name collision or unreadable event list")
        attempted = True
        item["operation_stage"] = "write_definition"
        append_command("p:" + GROUP + "/" + event + " " + target)
        item["definition_added"] = event_present(read(EVENTS), event) is True
        if not item["definition_added"]:
            raise RuntimeError("kernel did not list the requested event")
        item["operation_stage"] = "verify_disabled"
        enable_value = read(enable_path)
        item["event_enabled"] = enable_value is not None and enable_value.strip() != "0"
        if enable_value is None or enable_value.strip() != "0":
            raise RuntimeError("event was not confirmed disabled")
        item["resolution"] = "resolved_by_kernel"
    except OSError as exc:
        item["error_class"] = type(exc).__name__
        item["error_errno"] = exc.errno if isinstance(exc.errno, int) else None
        item["error_operation"] = item["operation_stage"]
        item["trace_error_log_excerpt"] = error_log_excerpt(target)
    except Exception as exc:
        item["error_class"] = type(exc).__name__
        item["error_operation"] = item["operation_stage"]
    finally:
        if attempted:
            try:
                if event_present(read(EVENTS), event) is True:
                    item["operation_stage"] = "remove_definition"
                    append_command("-:" + GROUP + "/" + event)
                    item["definition_removed"] = True
                item["cleanup_verified"] = event_present(read(EVENTS), event) is False
                if item["cleanup_verified"]:
                    item["event_enabled"] = False
            except Exception as exc:
                item["cleanup_error_class"] = type(exc).__name__
    return item

try:
    if os.geteuid() != 0 or report["hostname"].split(".")[0] != "pc3-v100":
        raise RuntimeError("unexpected guest identity or privilege")
    gpu = run(["nvidia-smi", "--query-gpu=name,pci.bus_id,driver_version", "--format=csv,noheader"])
    rows = list(csv.reader(gpu.stdout.decode("utf-8", "replace").splitlines())) if gpu and gpu.returncode == 0 else []
    parsed = [{"name":r[0].strip(), "pci":r[1].strip(), "driver_version":r[2].strip()}
              for r in rows if len(r) == 3]
    report["gpus"] = parsed
    if len(parsed) != 1 or "Tesla V100" not in parsed[0]["name"] or not parsed[0]["driver_version"].startswith("580."):
        raise RuntimeError("unexpected guest GPU or driver branch")
    if not Path("/sys/module/nvidia").exists() or not EVENTS.is_file():
        raise RuntimeError("stock NVIDIA module or tracefs kprobe_events is unavailable")
    initial_events = read(EVENTS)
    if initial_events is None or GROUP + "/" in initial_events:
        raise RuntimeError("unique event group already exists or event list is unreadable")
    for event, target in TARGETS:
        report[event + "_probe"] = try_symbol(event, target)
    report["status"] = "completed" if all(
        report[event + "_probe"].get("cleanup_verified") is True for event, _ in TARGETS
    ) else "cleanup_failed"
except Exception as exc:
    report["error_class"] = type(exc).__name__
    report["status"] = "preflight_failed"
print(json.dumps(report, sort_keys=True))
'''


def load_audit_tool():
    spec = importlib.util.spec_from_file_location("pc3_v100_trace_capability_audit", AUDIT_TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 trace-capability tool is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def guest_probe_script() -> str:
    return GUEST_PROBE.replace("__GROUP__", repr(GROUP))


def validate_report(report: object) -> dict:
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-pc3-v100-kprobe-symbol-resolution-v1":
        raise ValueError("unsupported kprobe symbol-resolution report")
    control = report.get("control_probe")
    target = report.get("nvidia_target_probe")
    if (report.get("status") != "completed" or report.get("hostname") != "pc3-v100" or
            report.get("effective_uid") != 0 or report.get("event_group") != GROUP or
            report.get("stock_driver_changed") is not False or report.get("pci_binding_changed") is not False or
            report.get("kprobe_attached") is not False):
        raise ValueError("guest identity, scope or cleanup contract failed")
    if (not isinstance(control, dict) or control.get("target") != "do_sys_openat2" or
            control.get("resolution") != "resolved_by_kernel" or control.get("definition_added") is not True or
            control.get("event_enabled") is not False or control.get("definition_removed") is not True or
            control.get("cleanup_verified") is not True):
        raise ValueError("kernel control-symbol probe did not resolve and clean up")
    if (not isinstance(target, dict) or target.get("target") != "nvidia:rm_init_adapter" or
            target.get("resolution") not in ("resolved_by_kernel", "failed") or
            target.get("event_enabled") is not False or target.get("cleanup_verified") is not True or
            (target.get("resolution") == "resolved_by_kernel" and
             (target.get("definition_added") is not True or target.get("definition_removed") is not True))):
        raise ValueError("NVIDIA symbol probe state or cleanup is invalid")
    gpus = report.get("gpus")
    if (not isinstance(gpus, list) or len(gpus) != 1 or not isinstance(gpus[0], dict) or
            "Tesla V100" not in gpus[0].get("name", "") or
            not re.fullmatch(r"580\.\d+\.\d+", gpus[0].get("driver_version", ""))):
        raise ValueError("experiment did not target the stock R580 V100 guest")
    return report


def write_private_new(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    parser.add_argument("--credential-host", default="gx10-e526")
    parser.add_argument("--credential-file", default="/home/pc6/Desktop/ACCES-BANC-GPU.env")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    audit = load_audit_tool()
    reference = audit.load_reference_tool()
    started = datetime.now(timezone.utc)
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-v100-kprobe-symbol-resolution-transport-v1",
        "started_utc": started.isoformat(timespec="seconds"), "target": args.target,
        "host_key_alias": args.host_key_alias, "credential_host": args.credential_host,
        "credential_file": args.credential_file, "status": "failed",
        "event_group": GROUP, "event_name": EVENT,
        "module": TARGET_MODULE, "symbol": TARGET_SYMBOL,
        "operation_scope": "sequential temporary disabled control and NVIDIA event definitions; no probe enable",
        "transport_helper_sha256": audit.REFERENCE_TOOL_SHA256,
    }
    try:
        secret = reference.fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        wrapper = audit.remote_root_script(
            guest_probe_script(), reference.EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
            reference.DEFAULT_GUEST_KEY, reference.DEFAULT_GUEST_KNOWN_HOSTS,
            read_only=False, trace_event_definition_write_attempted=True)
        remote = "sudo -S -p '' python3 -c " + shlex.quote(wrapper)
        result = subprocess.run(
            reference.pc3_ssh_base(args.target, args.host_key_alias) + [remote],
            input=reference.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=130, check=False,
            env=audit.pc3_ssh_environment(os.environ))
        report["pc3_ssh_returncode"] = result.returncode
        report["remote_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        report["remote_stdout_bytes"] = len(result.stdout)
        report["remote_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        if result.returncode == 0:
            remote_report = json.loads(result.stdout.decode("utf-8", "strict"))
            host = remote_report.get("host", {})
            if (host.get("hostname", "").split(".")[0] != "pc3" or
                    host.get("sudo_identity_verified") is not True or
                    host.get("guest_host_key_verified") is not True or
                    remote_report.get("status") != "observed" or
                    remote_report.get("read_only") is not False or
                    remote_report.get("trace_event_definition_write_attempted") is not True):
                raise ValueError("strict PC3/guest host-key identity or remote observation failed")
            guest = remote_report.get("guest")
            report["remote"] = remote_report
            validate_report(guest)
            report["status"] = "completed"
        else:
            report["failure_stage"] = "pc3_remote_or_guest_transport"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "completed" else 1
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
