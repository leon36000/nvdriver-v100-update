#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve a stock R580 module function from its ELF section and loaded base.

The guest verifies a unique ET_REL symbol against the live module section map,
then attempts temporary trace-event definitions. Successfully defined control
events create registered-but-disabled kprobes on Linux 6.8; the runner never
enables event handlers and removes every definition it creates.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
AUDIT_TOOL_PATH = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
TARGETS = ("_nv000794rm", "_nv000790rm", "_nv031399rm", "rm_init_private_state", "rm_init_adapter")
GROUP = "codex_v100_elf_probe_" + __import__("secrets").token_hex(6)


def parse_readelf_snapshot(header, section_table, symbol_table):
    """Parse the bounded readelf output needed to map a module symbol."""
    elf_class = re.search(r"^\s*Class:\s+(\S+)", header, re.MULTILINE)
    elf_data = re.search(r"^\s*Data:\s+(.+)$", header, re.MULTILINE)
    elf_type = re.search(r"^\s*Type:\s+(\S+)", header, re.MULTILINE)
    machine = re.search(r"^\s*Machine:\s+(.+)$", header, re.MULTILINE)
    if not elf_class or elf_class.group(1) != "ELF64":
        raise ValueError("module is not ELF64")
    if not elf_data or "little endian" not in elf_data.group(1):
        raise ValueError("module is not little-endian ELF")
    if not elf_type or elf_type.group(1) != "REL":
        raise ValueError("module is not an ELF relocatable object")
    if not machine:
        raise ValueError("ELF machine is unavailable")

    sections = {}
    section_re = re.compile(
        r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s+(\S*)\s+.*$"
    )
    for line in section_table.splitlines():
        match = section_re.match(line)
        if not match:
            continue
        index, name, section_type, address, offset, size, flags = match.groups()
        sections[int(index)] = {
            "name": name,
            "type": section_type,
            "address": int(address, 16),
            "file_offset": int(offset, 16),
            "size": int(size, 16),
            "flags": flags,
            "allocated": "A" in flags,
            "executable": "X" in flags,
        }
    if not sections:
        raise ValueError("ELF section table could not be parsed")

    targets = set(TARGETS)
    symbols = {name: [] for name in TARGETS}
    symbol_re = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s+(\S+)(?:\s+.*)?$"
    )
    for line in symbol_table.splitlines():
        match = symbol_re.match(line)
        if not match:
            continue
        value, size, symbol_type, binding, visibility, section_index, name = match.groups()
        if name not in targets:
            continue
        entry = {
            "value": int(value, 16),
            "size": int(size),
            "type": symbol_type,
            "binding": binding,
            "visibility": visibility,
            "section_index": int(section_index) if section_index.isdecimal() else None,
        }
        section = sections.get(entry["section_index"])
        if section:
            entry.update({
                "section": section["name"],
                "section_size": section["size"],
                "section_allocated": section["allocated"],
                "section_executable": section["executable"],
            })
        symbols[name].append(entry)
    return {
        "elf_class": elf_class.group(1),
        "elf_type": elf_type.group(1),
        "machine": machine.group(1).strip(),
        "sections": sections,
        "target_symbols": symbols,
    }


def derive_loaded_address(symbol, section_base):
    """Return one validated loaded address; accept one symbol record or list."""
    if isinstance(symbol, list):
        if len(symbol) != 1:
            raise ValueError("target symbol is not unique")
        symbol = symbol[0]
    if not isinstance(symbol, dict):
        raise ValueError("target symbol record is malformed")
    required = ("value", "size", "section", "section_size", "section_allocated", "section_executable")
    if any(key not in symbol for key in required):
        raise ValueError("target symbol section is unresolved")
    value, size, section_size = symbol["value"], symbol["size"], symbol["section_size"]
    if symbol.get("type") != "FUNC" or not symbol["section_allocated"] or not symbol["section_executable"]:
        raise ValueError("target symbol is not in an allocated executable section")
    if (not isinstance(value, int) or not isinstance(size, int) or not isinstance(section_size, int) or
            value < 0 or section_size <= 0 or value >= section_size or
            (size > 0 and value + size > section_size)):
        raise ValueError("target symbol exceeds section bounds")
    if not isinstance(section_base, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{12,16}", section_base.strip()):
        raise ValueError("loaded section base is malformed")
    base = int(section_base.strip(), 16)
    # x86-64 kernel mappings are canonical high-half addresses. This catches
    # truncated, userspace, and stale textual values before a probe is formed.
    if base < 0xFFFF800000000000 or base > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("loaded section base is outside x86-64 kernel address space")
    address = base + value
    if address > 0xFFFFFFFFFFFFFFFF or address < base or address >= base + section_size:
        raise ValueError("resolved symbol address exceeds its loaded section")
    return {"resolved": True, "address": address, "section": symbol["section"]}


GUEST_PROBE = r'''import csv,hashlib,json,os,re,shutil,subprocess
from pathlib import Path

TARGETS = __TARGETS__
GROUP = __GROUP__
CONTROL = "do_sys_openat2"
EVENTS = Path("/sys/kernel/tracing/kprobe_events")

__ELF_PARSER_SOURCE__

def run(argv, timeout=60, pass_fds=()):
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                              check=False, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"},
                              pass_fds=pass_fds)
    except (OSError, subprocess.TimeoutExpired):
        return None

def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None

def find_unique_kallsyms_address(symbol):
    found = set()
    try:
        with open("/proc/kallsyms", "r", encoding="ascii", errors="replace") as stream:
            for line in stream:
                fields = line.split()
                if len(fields) >= 3 and fields[-1] == symbol:
                    try:
                        value = int(fields[0], 16)
                    except ValueError:
                        continue
                    if value:
                        found.add(value)
    except OSError:
        return None, "kallsyms_unreadable"
    if len(found) != 1:
        return None, "kernel_addresses_restricted" if not found else "symbol_ambiguous"
    address = next(iter(found))
    if address < 0xFFFF800000000000 or address > 0xFFFFFFFFFFFFFFFF:
        return None, "address_outside_kernel_range"
    return address, None

def config_value(lines, key):
    prefix = "CONFIG_" + key + "="
    unset = "# CONFIG_" + key + " is not set"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
        if line.strip() == unset:
            return "n"
    return "unknown"

def available_filter_targets(path):
    found = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                fields = line.split()
                if fields:
                    name = fields[0].split("[", 1)[0]
                    if name in TARGETS:
                        found.add(name)
    except OSError:
        return None
    return sorted(found)

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

def error_log_excerpt(event):
    text = read_text("/sys/kernel/tracing/error_log")
    if text is None:
        return []
    lines = text.splitlines()
    needle = GROUP + "/" + event
    index = next((i for i, line in enumerate(lines) if needle in line), None)
    if index is None:
        return []
    relevant = lines[max(0, index - 1):min(len(lines), index + 2)]
    address_re = re.compile(r"(?i)\b(?:0x)?[0-9a-f]{12,16}\b")
    return [address_re.sub("<address>", line.strip())[:240] for line in relevant]

def try_probe(event, target, target_kind):
    item = {"event_name":event, "target_kind":target_kind, "definition_added":False,
            "attempted":False, "event_enabled":False, "definition_removed":False, "cleanup_verified":False,
            "kernel_registration_state":"not_registered", "registered_disabled":False,
            "handlers_enabled":False,
            "resolution":"failed", "operation_stage":"preflight"}
    attempted = False
    enable_path = Path("/sys/kernel/tracing/events") / GROUP / event / "enable"
    try:
        if event_present(read_text(EVENTS), event) is not False:
            raise RuntimeError("event name collision or unreadable event list")
        attempted = True
        item["attempted"] = True
        item["operation_stage"] = "write_definition"
        append_command("p:" + GROUP + "/" + event + " " + target)
        item["definition_added"] = event_present(read_text(EVENTS), event) is True
        if not item["definition_added"]:
            raise RuntimeError("kernel did not list requested event")
        # Linux 6.8 trace_kprobe registers a kprobe when a dynamic event is
        # created, setting KPROBE_FLAG_DISABLED until its event is enabled.
        item["kernel_registration_state"] = "registered"
        item["operation_stage"] = "verify_disabled"
        enable_value = read_text(enable_path)
        item["event_enabled"] = None if enable_value is None else enable_value != "0"
        item["handlers_enabled"] = item["event_enabled"]
        if enable_value is None or enable_value != "0":
            raise RuntimeError("event was not confirmed disabled")
        item["kernel_registration_state"] = "registered_disabled"
        item["registered_disabled"] = True
        item["resolution"] = "resolved_by_kernel"
    except OSError as exc:
        item["error_class"] = type(exc).__name__
        item["error_errno"] = exc.errno if isinstance(exc.errno, int) else None
        item["error_operation"] = item["operation_stage"]
        item["trace_error_log_excerpt"] = error_log_excerpt(event)
    except Exception as exc:
        item["error_class"] = type(exc).__name__
        item["error_operation"] = item["operation_stage"]
    finally:
        if attempted:
            try:
                if event_present(read_text(EVENTS), event) is True:
                    item["operation_stage"] = "remove_definition"
                    append_command("-:" + GROUP + "/" + event)
                    item["definition_removed"] = True
                item["cleanup_verified"] = event_present(read_text(EVENTS), event) is False
                if item["cleanup_verified"]:
                    item["event_enabled"] = False
                    if item["kernel_registration_state"] == "registered_disabled":
                        item["kernel_registration_state"] = "removed_after_disabled_registration"
            except Exception as exc:
                item["cleanup_error_class"] = type(exc).__name__
    return item

report = {"schema":"nvidia-hybrid-pc3-v100-elf-kprobe-address-v2",
          "hostname":os.uname().nodename, "kernel_release":os.uname().release,
          "effective_uid":os.geteuid(), "event_group":GROUP,
          "stock_driver_changed":False, "pci_binding_changed":False,
          "kprobe_handlers_enabled_by_runner":False, "status":"preflight_failed"}
try:
    if os.geteuid() != 0 or report["hostname"].split(".")[0] != "pc3-v100":
        raise RuntimeError("unexpected V100 guest identity or privilege")
    gpu = run(["nvidia-smi", "--query-gpu=name,pci.bus_id,driver_version", "--format=csv,noheader"])
    rows = list(csv.reader(gpu.stdout.decode("utf-8", "replace").splitlines())) if gpu and gpu.returncode == 0 else []
    gpus = [{"name":r[0].strip(), "pci":r[1].strip(), "driver_version":r[2].strip()}
            for r in rows if len(r) == 3]
    report["gpus"] = gpus
    module_path_result = run(["modinfo", "-n", "nvidia"])
    module_version_result = run(["modinfo", "-F", "version", "nvidia"])
    module_path = module_path_result.stdout.decode("utf-8", "replace").strip() if module_path_result and module_path_result.returncode == 0 else ""
    module_version = module_version_result.stdout.decode("utf-8", "replace").strip() if module_version_result and module_version_result.returncode == 0 else ""
    if (len(gpus) != 1 or "Tesla V100" not in gpus[0]["name"] or
            not gpus[0]["driver_version"].startswith("580.") or module_version != gpus[0]["driver_version"] or
            not Path("/sys/module/nvidia").exists() or not EVENTS.is_file()):
        raise RuntimeError("unexpected stock R580 V100 or tracefs state")
    if not module_path.endswith(".zst"):
        raise RuntimeError("pinned guest module compression/layout changed")
    zstd = shutil.which("zstd")
    readelf = shutil.which("readelf")
    memfd_create = getattr(os, "memfd_create", None)
    if not zstd or not readelf or not memfd_create:
        raise RuntimeError("zstd, readelf, or memfd support is unavailable")
    decompressed = run([zstd, "-dc", "--", module_path], timeout=90)
    if decompressed is None or decompressed.returncode != 0:
        raise RuntimeError("stock module decompression failed")
    fd = memfd_create("nvidia-module-elf-probe", 0)
    try:
        view = memoryview(decompressed.stdout)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        elf_path = "/proc/self/fd/" + str(fd)
        header = run([readelf, "-hW", elf_path], pass_fds=(fd,))
        section_result = run([readelf, "-SW", elf_path], pass_fds=(fd,))
        symbol_result = run([readelf, "-WsW", elf_path], pass_fds=(fd,))
        if any(result is None or result.returncode != 0 for result in (header, section_result, symbol_result)):
            raise RuntimeError("readelf could not inspect the decompressed stock module")
        parsed = parse_readelf_snapshot(
            header.stdout.decode("utf-8", "replace"),
            section_result.stdout.decode("utf-8", "replace"),
            symbol_result.stdout.decode("utf-8", "replace"))
    finally:
        os.close(fd)
    symbol_records = parsed["target_symbols"].get("rm_init_adapter", [])
    if len(symbol_records) != 1:
        raise RuntimeError("rm_init_adapter symbol is absent or ambiguous in ELF")
    symbol = symbol_records[0]
    sections_dir = Path("/sys/module/nvidia/sections")
    section_file = sections_dir / symbol.get("section", "")
    section_base_text = read_text(section_file)
    resolved = derive_loaded_address(symbol, section_base_text)
    address = resolved["address"]
    report["module_elf"] = {
        "version":module_version,
        "compressed_bytes":os.stat(module_path).st_size,
        "decompressed_bytes":len(decompressed.stdout),
        "decompressed_sha256":hashlib.sha256(decompressed.stdout).hexdigest(),
        "elf_class":parsed["elf_class"], "elf_type":parsed["elf_type"], "machine":parsed["machine"],
        "target_symbol":{"name":"rm_init_adapter", "value_offset":symbol["value"],
            "size":symbol["size"], "type":symbol["type"], "binding":symbol["binding"],
            "section":symbol["section"], "section_index":symbol["section_index"],
            "section_size":symbol["section_size"], "section_allocated":symbol["section_allocated"],
            "section_executable":symbol["section_executable"],
            "runtime_section_base_readable":True, "address_inside_loaded_section":True},
        "runtime_section_address_persisted":False,
    }
    kernel_config = read_text("/boot/config-" + os.uname().release)
    config_lines = kernel_config.splitlines() if kernel_config is not None else []
    report["kernel_probe_config"] = {
        "config_dynamic_ftrace":config_value(config_lines, "DYNAMIC_FTRACE"),
        "config_function_tracer":config_value(config_lines, "FUNCTION_TRACER"),
        "config_kprobe_events_on_notrace":config_value(config_lines, "KPROBE_EVENTS_ON_NOTRACE"),
    }
    report["module_ftrace_target_names"] = available_filter_targets(
        "/sys/kernel/tracing/available_filter_functions")
    initial = read_text(EVENTS)
    if initial is None or GROUP + "/" in initial:
        raise RuntimeError("event group collision or unreadable tracefs event list")
    report["control_probe"] = try_probe("control", CONTROL, "kernel_symbol")
    control_address, control_address_error = find_unique_kallsyms_address(CONTROL)
    if control_address is None:
        report["control_absolute_probe"] = {
            "target_kind":"kernel_symbol_absolute_control", "resolution":"not_attempted",
            "attempted":False, "reason":control_address_error,
            "event_enabled":False, "cleanup_verified":True}
    else:
        report["control_absolute_probe"] = try_probe(
            "control_absolute", "0x" + format(control_address, "x"), "kernel_symbol_absolute_control")
        report["control_absolute_probe"]["attempted"] = True
    report["nvidia_named_probe"] = try_probe("nvidia_named", "nvidia:rm_init_adapter", "module_symbol")
    report["nvidia_absolute_probe"] = try_probe(
        "nvidia_absolute", "0x" + format(address, "x"), "elf_section_plus_loaded_base")
    probe_names = ("control_probe", "control_absolute_probe", "nvidia_named_probe", "nvidia_absolute_probe")
    probes = [report[name] for name in probe_names]
    report["kprobe_lifecycle"] = {
        "registered_disabled_events": [item["event_name"] for item in probes if item.get("registered_disabled") is True],
        "handlers_enabled_by_runner":False,
        "all_event_definitions_removed":all(item.get("cleanup_verified") is True for item in probes),
        "remaining_event_definitions_in_group":0 if all(item.get("cleanup_verified") is True for item in probes) else None,
        "registration_basis":"Linux 6.8 trace_kprobe creates a disabled kprobe for a newly defined event",
    }
    report["status"] = "completed" if all(
        report[name].get("cleanup_verified") is True
        for name in ("control_probe", "control_absolute_probe", "nvidia_named_probe", "nvidia_absolute_probe")) else "cleanup_failed"
except Exception as exc:
    report["error_class"] = type(exc).__name__
    safe_error = re.sub(r"(?i)\b(?:0x)?[0-9a-f]{12,16}\b", "<address>", str(exc))
    report["error_detail"] = safe_error[:180]
    report["status"] = "preflight_failed"
print(json.dumps(report, sort_keys=True))
'''


def guest_probe_script() -> str:
    parser_source = "\n".join(inspect.getsource(function) for function in (parse_readelf_snapshot, derive_loaded_address))
    return (GUEST_PROBE.replace("__TARGETS__", repr(TARGETS))
            .replace("__GROUP__", repr(GROUP))
            .replace("__ELF_PARSER_SOURCE__", parser_source))


def valid_test_report():
    return {
        "schema":"nvidia-hybrid-pc3-v100-elf-kprobe-address-v2", "status":"completed",
        "hostname":"pc3-v100", "effective_uid":0, "event_group":GROUP,
        "stock_driver_changed":False, "pci_binding_changed":False, "kprobe_handlers_enabled_by_runner":False,
        "gpus":[{"name":"Tesla V100-SXM2-16GB", "pci":"0000:00:05.0", "driver_version":"580.178.04"}],
        "module_elf":{"version":"580.178.04", "elf_class":"ELF64", "elf_type":"REL", "machine":"Advanced Micro Devices X86-64",
            "target_symbol":{"name":"rm_init_adapter", "value_offset":16, "size":32,
                "type":"FUNC", "binding":"GLOBAL", "section":".text", "section_index":1,
            "section_size":256, "section_allocated":True, "section_executable":True,
                "runtime_section_base_readable":True, "address_inside_loaded_section":True},
            "runtime_section_address_persisted":False},
        "kernel_probe_config":{"config_dynamic_ftrace":"y", "config_function_tracer":"y",
            "config_kprobe_events_on_notrace":"n"},
        "module_ftrace_target_names":[],
        "control_probe":{"event_name":"control", "target_kind":"kernel_symbol", "resolution":"resolved_by_kernel", "attempted":True,
            "definition_added":True, "definition_removed":True, "event_enabled":False, "cleanup_verified":True,
            "kernel_registration_state":"removed_after_disabled_registration", "registered_disabled":True,
            "handlers_enabled":False},
        "control_absolute_probe":{"event_name":"control_absolute", "target_kind":"kernel_symbol_absolute_control", "resolution":"resolved_by_kernel",
            "attempted":True, "definition_added":True, "definition_removed":True,
            "event_enabled":False, "cleanup_verified":True,
            "kernel_registration_state":"removed_after_disabled_registration", "registered_disabled":True,
            "handlers_enabled":False},
        "nvidia_named_probe":{"event_name":"nvidia_named", "target_kind":"module_symbol", "resolution":"failed", "attempted":True,
            "definition_added":False, "definition_removed":False, "error_errno":22,
            "event_enabled":False, "cleanup_verified":True, "kernel_registration_state":"not_registered",
            "registered_disabled":False, "handlers_enabled":False},
        "nvidia_absolute_probe":{"event_name":"nvidia_absolute", "target_kind":"elf_section_plus_loaded_base", "resolution":"failed", "attempted":True,
            "definition_added":False, "definition_removed":False, "error_errno":22,
            "event_enabled":False, "cleanup_verified":True, "kernel_registration_state":"not_registered",
            "registered_disabled":False, "handlers_enabled":False},
        "kprobe_lifecycle":{"registered_disabled_events":["control", "control_absolute"],
            "handlers_enabled_by_runner":False, "all_event_definitions_removed":True,
            "remaining_event_definitions_in_group":0,
            "registration_basis":"Linux 6.8 trace_kprobe creates a disabled kprobe for a newly defined event"},
    }


def _contains_pointer_key(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"address", "address_hex", "runtime_address", "candidate_address", "section_base"}:
                return True
            if _contains_pointer_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_pointer_key(item) for item in value)
    elif isinstance(value, str) and re.search(r"(?i)0x[0-9a-f]{12,16}(?![0-9a-f])", value):
        return True
    return False


def validate_report(report):
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-pc3-v100-elf-kprobe-address-v2":
        raise ValueError("unsupported V100 ELF address-probe report")
    if "kprobe_attached" in report:
        raise ValueError("ambiguous legacy kprobe attachment field is forbidden")
    if _contains_pointer_key(report):
        raise ValueError("kernel pointer leaked into report")
    if (report.get("status") != "completed" or report.get("hostname") != "pc3-v100" or
            report.get("effective_uid") != 0 or
            not re.fullmatch(r"codex_v100_elf_probe_[0-9a-f]{12}", str(report.get("event_group", ""))) or
            any(report.get(key) is not False for key in
                ("stock_driver_changed", "pci_binding_changed", "kprobe_handlers_enabled_by_runner"))):
        raise ValueError("guest identity, probe scope, or cleanup failed")
    gpus = report.get("gpus")
    if (not isinstance(gpus, list) or len(gpus) != 1 or "Tesla V100" not in gpus[0].get("name", "") or
            not re.fullmatch(r"580\.\d+\.\d+", gpus[0].get("driver_version", ""))):
        raise ValueError("probe did not run against the stock R580 V100 guest")
    module = report.get("module_elf")
    target = module.get("target_symbol") if isinstance(module, dict) else None
    if (not isinstance(target, dict) or module.get("version") != gpus[0].get("driver_version") or
            module.get("elf_class") != "ELF64" or module.get("elf_type") != "REL" or
            module.get("machine") != "Advanced Micro Devices X86-64" or
            target.get("name") != "rm_init_adapter" or target.get("type") != "FUNC" or
            target.get("binding") != "GLOBAL" or
            not target.get("section_allocated") or not target.get("section_executable") or
            target.get("runtime_section_base_readable") is not True or
            target.get("address_inside_loaded_section") is not True or
            module.get("runtime_section_address_persisted") is not False):
        raise ValueError("runtime symbol address was not derived from a verified executable ELF section")
    config = report.get("kernel_probe_config")
    if (not isinstance(config, dict) or config.get("config_dynamic_ftrace") not in ("y", "n") or
            config.get("config_function_tracer") not in ("y", "n") or
            config.get("config_kprobe_events_on_notrace") not in ("y", "n")):
        raise ValueError("kernel ftrace and kprobe protection configuration is incomplete")
    ftrace_targets = report.get("module_ftrace_target_names")
    if not isinstance(ftrace_targets, list) or any(name not in TARGETS for name in ftrace_targets):
        raise ValueError("module ftrace target inventory is malformed")
    for key, expected_kind in (("control_probe", "kernel_symbol"),
                               ("control_absolute_probe", "kernel_symbol_absolute_control"),
                               ("nvidia_named_probe", "module_symbol"),
                               ("nvidia_absolute_probe", "elf_section_plus_loaded_base")):
        probe = report.get(key)
        if not isinstance(probe, dict) or probe.get("target_kind") != expected_kind:
            raise ValueError("probe state or cleanup is invalid")
        if key == "control_absolute_probe" and probe.get("resolution") == "not_attempted":
            if (probe.get("attempted") is not False or probe.get("event_enabled") is not False or
                    probe.get("cleanup_verified") is not True):
                raise ValueError("unavailable control address was not safely skipped")
            continue
        if (probe.get("resolution") not in ("resolved_by_kernel", "failed") or
                probe.get("attempted") is not True or probe.get("event_enabled") is not False or
                probe.get("cleanup_verified") is not True):
            raise ValueError("probe state or cleanup is invalid")
        if probe.get("resolution") == "resolved_by_kernel" and (
                probe.get("definition_added") is not True or probe.get("definition_removed") is not True or
                probe.get("registered_disabled") is not True or
                probe.get("kernel_registration_state") != "removed_after_disabled_registration" or
                probe.get("handlers_enabled") is not False):
            raise ValueError("resolved disabled kprobe registration was not removed")
        if probe.get("resolution") == "failed" and (
                probe.get("definition_added") is not False or probe.get("registered_disabled") is not False or
                probe.get("kernel_registration_state") != "not_registered"):
            raise ValueError("failed target unexpectedly left a registered kprobe")
    if report["control_probe"].get("resolution") != "resolved_by_kernel":
        raise ValueError("kernel control probe did not resolve")
    lifecycle = report.get("kprobe_lifecycle")
    if (not isinstance(lifecycle, dict) or lifecycle.get("handlers_enabled_by_runner") is not False or
            lifecycle.get("all_event_definitions_removed") is not True or
            lifecycle.get("remaining_event_definitions_in_group") != 0 or
            set(lifecycle.get("registered_disabled_events", [])) !=
            {report[key].get("event_name") for key in ("control_probe", "control_absolute_probe")
             if report.get(key, {}).get("registered_disabled") is True}):
        raise ValueError("kprobe registration lifecycle or cleanup is incomplete")
    return report


def write_private_new(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def load_audit_tool():
    spec = importlib.util.spec_from_file_location("pc3_v100_trace_capability_audit", AUDIT_TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("PC3 transport audit tool is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        "schema":"nvidia-hybrid-pc3-v100-elf-kprobe-address-transport-v2",
        "started_utc":started.isoformat(timespec="seconds"), "target":args.target,
        "host_key_alias":args.host_key_alias, "credential_host":args.credential_host,
        "credential_file":args.credential_file, "status":"failed",
        "read_only":False, "trace_event_definition_write_attempted":True,
        "kprobe_handlers_enabled_by_runner":False, "stock_driver_changed":False, "pci_binding_changed":False,
        "event_group":GROUP,
        "operation_scope":"exact ELF section-base-derived address; temporary disabled kprobe-event registrations; event handlers never enabled by runner",
        "transport_helper_sha256":audit.REFERENCE_TOOL_SHA256,
        "probe_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
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
            stderr=subprocess.PIPE, timeout=180, check=False,
            env=audit.pc3_ssh_environment(os.environ))
        report["pc3_ssh_returncode"] = result.returncode
        report["remote_stdout_bytes"] = len(result.stdout)
        report["remote_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        report["remote_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        if result.returncode != 0:
            report["failure_stage"] = "pc3_or_guest_transport"
        else:
            remote_report = json.loads(result.stdout.decode("utf-8", "strict"))
            guest_report = remote_report.get("guest", {})
            lifecycle = guest_report.get("kprobe_lifecycle", {})
            # The generic transport helper predates disabled-event registration
            # semantics and emits the ambiguous field `kprobe_attached=false`.
            # Replace it with the guest's explicit lifecycle record.
            remote_report.pop("kprobe_attached", None)
            remote_report["kprobe_handlers_enabled_by_runner"] = (
                lifecycle.get("handlers_enabled_by_runner") is False)
            remote_report["kprobe_lifecycle"] = lifecycle
            report["remote"] = remote_report
            report["status"] = "observed"
            validate_report(remote_report.get("guest"))
            if remote_report.get("host", {}).get("guest_host_key_verified") is not True:
                raise ValueError("strict forwarded guest host-key verification failed")
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key:report[key] for key in
                          ("schema", "status", "failure_stage", "remote_stdout_bytes", "remote_stdout_sha256",
                           "remote_stderr_sha256", "evidence") if key in report}, sort_keys=True))
        return 0 if report["status"] == "observed" else 1
    except Exception as exc:
        report["status"] = "failed"
        report["failure_stage"] = report.get("failure_stage") or "execution_or_validation"
        report["error_class"] = type(exc).__name__
        safe_error = re.sub(r"(?i)\b(?:0x)?[0-9a-f]{12,16}\b", "<address>", str(exc))
        report["error"] = safe_error[:200]
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not args.evidence.exists():
            write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key:report[key] for key in
                          ("schema", "status", "failure_stage", "error_class", "evidence") if key in report}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
