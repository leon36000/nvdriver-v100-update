#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only inspection of R580 module ftrace sections and function entry calls."""
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
CAPABILITY_AUDIT_PATH = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
ELF_PROBE_PATH = ROOT / "tools/probe_pc3_v100_elf_kprobe_address.py"
TARGETS = ("_nv000794rm", "_nv000790rm", "_nv031399rm", "rm_init_private_state", "rm_init_adapter")


def ftrace_sections(sections: dict[int, dict]) -> list[dict]:
    return [
        {"name":section["name"], "type":section["type"], "size":section["size"],
         "allocated":section["allocated"], "executable":section["executable"]}
        for section in sections.values()
        if "mcount" in section["name"].lower() or "ftrace" in section["name"].lower()
    ]


def classify_disassembly(text: str, returncode: int, symbol: str) -> dict:
    if returncode != 0:
        return {"objdump_succeeded":False, "fentry_reference":None,
                "mcount_reference":None, "matching_line_count":None,
                "symbol_header_found":False, "instruction_line_count":None}
    header = re.compile(r"^\s*[0-9a-fA-F]+\s+<" + re.escape(symbol) + r">:\s*$")
    instruction = re.compile(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+\S")
    lines = text.splitlines()
    header_found = any(header.search(line) for line in lines)
    matching = [line.strip() for line in text.splitlines()
                if re.search(r"\b(?:__fentry__|_?mcount)\b", line)]
    return {
        "objdump_succeeded":True,
        "fentry_reference":any("__fentry__" in line for line in matching),
        "mcount_reference":any(re.search(r"\b_?mcount\b", line) for line in matching),
        "matching_line_count":len(matching),
        "symbol_header_found":header_found,
        "instruction_line_count":sum(1 for line in lines if instruction.search(line)),
    }


def config_value(lines: list[str], key: str) -> str:
    prefix = "CONFIG_" + key + "="
    unset = "# CONFIG_" + key + " is not set"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
        if line.strip() == unset:
            return "n"
    return "unknown"


def parse_os_release(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID", "PRETTY_NAME"}:
            result[key] = value.strip().strip('"').strip("'")
    return result


GUEST_PROBE = r'''import csv,hashlib,json,os,re,shutil,subprocess
from pathlib import Path

TARGETS = __TARGETS__
ELF_PARSER_SOURCE = __ELF_PARSER_SOURCE__
exec(compile(ELF_PARSER_SOURCE, "<pinned-elf-parser>", "exec"))

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

def ftrace_sections(sections):
    return [{"name":s["name"], "type":s["type"], "size":s["size"],
             "allocated":s["allocated"], "executable":s["executable"]}
            for s in sections.values()
            if "mcount" in s["name"].lower() or "ftrace" in s["name"].lower()]

def classify_disassembly(text, returncode, symbol):
    if returncode != 0:
        return {"objdump_succeeded":False, "fentry_reference":None,
                "mcount_reference":None, "matching_line_count":None,
                "symbol_header_found":False, "instruction_line_count":None}
    header = re.compile(r"^\s*[0-9a-fA-F]+\s+<" + re.escape(symbol) + r">:\s*$")
    instruction = re.compile(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+\S")
    lines = text.splitlines()
    header_found = any(header.search(line) for line in lines)
    matching = [line.strip() for line in text.splitlines()
                if re.search(r"\b(?:__fentry__|_?mcount)\b", line)]
    return {"objdump_succeeded":True,
            "fentry_reference":any("__fentry__" in line for line in matching),
            "mcount_reference":any(re.search(r"\b_?mcount\b", line) for line in matching),
            "matching_line_count":len(matching),
            "symbol_header_found":header_found,
            "instruction_line_count":sum(1 for line in lines if instruction.search(line))}

def config_value(lines, key):
    prefix = "CONFIG_" + key + "="
    unset = "# CONFIG_" + key + " is not set"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
        if line.strip() == unset:
            return "n"
    return "unknown"

def parse_os_release(text):
    result = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "VERSION_ID", "PRETTY_NAME"}:
            result[key] = value.strip().strip('"').strip("'")
    return result

report = {"schema":"nvidia-hybrid-pc3-v100-module-ftrace-v4",
          "hostname":os.uname().nodename, "kernel_release":os.uname().release,
          "effective_uid":os.geteuid(), "status":"preflight_failed",
          "execution_scope":{"read_only":True, "tracefs_write_attempted":False,
              "kprobe_event_definition_created":False, "experimental_module_loaded":False,
              "stock_driver_changed":False, "pci_binding_changed":False, "vm_management_issued":False}}
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
            not Path("/sys/module/nvidia").exists()):
        raise RuntimeError("unexpected stock R580 V100 guest")
    os_release = read_text("/etc/os-release")
    if os_release is not None:
        report["os_release"] = parse_os_release(os_release)
    package_names = ["linux-image-" + os.uname().release, "linux-modules-" + os.uname().release,
                     "linux-modules-extra-" + os.uname().release, "linux-headers-" + os.uname().release]
    report["installed_kernel_packages"] = []
    report["uninstalled_or_unresolved_kernel_packages"] = []
    for package_name in package_names:
        package_result = run(["dpkg-query", "-W", "-f=${binary:Package}=${Version}", package_name])
        if package_result is not None and package_result.returncode == 0:
            formatted = package_result.stdout.decode("utf-8", "replace").strip()
            package, separator, version = formatted.partition("=")
            if separator and version and version != "<none>":
                report["installed_kernel_packages"].append({"package":package, "version":version})
            else:
                report["uninstalled_or_unresolved_kernel_packages"].append(package_name)
    if not module_path.endswith(".zst"):
        raise RuntimeError("pinned guest module compression/layout changed")
    zstd, readelf, nm, objdump = (shutil.which(name) for name in ("zstd", "readelf", "nm", "objdump"))
    if not all((zstd, readelf, nm, objdump)) or not hasattr(os, "memfd_create"):
        raise RuntimeError("required ELF inspection tools or memfd support unavailable")
    decompressed = run([zstd, "-dc", "--", module_path], timeout=90)
    if decompressed is None or decompressed.returncode != 0:
        raise RuntimeError("stock module decompression failed")
    fd = os.memfd_create("nvidia-module-ftrace-audit", 0)
    try:
        view = memoryview(decompressed.stdout)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        elf_path = "/proc/self/fd/" + str(fd)
        header = run([readelf, "-hW", elf_path], pass_fds=(fd,))
        section_table = run([readelf, "-SW", elf_path], pass_fds=(fd,))
        symbol_table = run([readelf, "-WsW", elf_path], pass_fds=(fd,))
        nm_symbols = run([nm, "-an", "--defined-only", elf_path], pass_fds=(fd,))
        if any(x is None or x.returncode != 0 for x in (header, section_table, symbol_table, nm_symbols)):
            raise RuntimeError("ELF section or symbol inspection failed")
        parsed = parse_readelf_snapshot(header.stdout.decode("utf-8", "replace"),
            section_table.stdout.decode("utf-8", "replace"), symbol_table.stdout.decode("utf-8", "replace"))
        symbol_offsets = {}
        for line in nm_symbols.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[-1] in TARGETS:
                symbol_offsets[fields[-1]] = int(fields[0], 16)
        function_observations = {}
        for name in TARGETS:
            if name not in symbol_offsets:
                function_observations[name] = {"symbol_found":False, "objdump_succeeded":False,
                    "fentry_reference":None, "mcount_reference":None, "matching_line_count":None,
                    "symbol_header_found":False, "instruction_line_count":None}
                continue
            result = run([objdump, "-dr", "--disassemble=" + name, elf_path], timeout=60, pass_fds=(fd,))
            classified = classify_disassembly(result.stdout.decode("utf-8", "replace") if result else "",
                                               result.returncode if result else -1, name)
            function_observations[name] = {"symbol_found":True, **classified}
    finally:
        os.close(fd)
    config = read_text("/boot/config-" + os.uname().release)
    config_lines = config.splitlines() if config is not None else []
    report["kernel_config_sha256"] = hashlib.sha256(config.encode()).hexdigest() if config is not None else None
    report["kernel_config"] = {
        "config_dynamic_ftrace":config_value(config_lines, "DYNAMIC_FTRACE"),
        "config_function_tracer":config_value(config_lines, "FUNCTION_TRACER"),
        "config_kprobe_events_on_notrace":config_value(config_lines, "KPROBE_EVENTS_ON_NOTRACE"),
    }
    filter_targets = set()
    try:
        for line in Path("/sys/kernel/tracing/available_filter_functions").read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split()
            if fields and fields[0].split("[",1)[0] in TARGETS:
                filter_targets.add(fields[0].split("[",1)[0])
    except OSError:
        pass
    report["module_elf"] = {"version":module_version, "compressed_bytes":os.stat(module_path).st_size,
        "decompressed_bytes":len(decompressed.stdout), "decompressed_sha256":hashlib.sha256(decompressed.stdout).hexdigest(),
        "elf_class":parsed["elf_class"], "elf_type":parsed["elf_type"], "machine":parsed["machine"],
        "ftrace_related_sections":ftrace_sections(parsed["sections"]),
        "target_symbols":{name:{"value_offset":entry["value"], "size":entry["size"],
            "type":entry["type"], "section":entry.get("section")}
            for name,entries in parsed["target_symbols"].items() for entry in entries if len(entries) == 1}}
    report["target_fentry_inspection"] = function_observations
    report["available_filter_function_targets"] = sorted(filter_targets)
    report["status"] = "observed"
except Exception as exc:
    report["error_class"] = type(exc).__name__
    report["error_detail"] = str(exc)[:160]
    report["status"] = "preflight_failed"
print(json.dumps(report, sort_keys=True))
'''


def guest_probe_script() -> str:
    spec = importlib.util.spec_from_file_location("v100_elf_address_probe", ELF_PROBE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned ELF parser could not be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parser_source = inspect.getsource(module.parse_readelf_snapshot)
    return (GUEST_PROBE.replace("__TARGETS__", repr(TARGETS))
            .replace("__ELF_PARSER_SOURCE__", repr(parser_source)))


def load_capability_audit():
    spec = importlib.util.spec_from_file_location("pc3_v100_trace_capability_audit", CAPABILITY_AUDIT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 transport helper could not be imported")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_private_new(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def validate_report(report: object) -> dict:
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-pc3-v100-module-ftrace-v4":
        raise ValueError("unsupported V100 module ftrace report")
    scope = report.get("execution_scope")
    if (report.get("status") != "observed" or report.get("hostname") != "pc3-v100" or
            not isinstance(scope, dict) or scope.get("read_only") is not True or
            scope.get("tracefs_write_attempted") is not False or
            scope.get("kprobe_event_definition_created") is not False or
            scope.get("experimental_module_loaded") is not False or
            scope.get("stock_driver_changed") is not False or scope.get("pci_binding_changed") is not False):
        raise ValueError("guest identity or read-only scope failed")
    gpus = report.get("gpus")
    module = report.get("module_elf")
    if (not isinstance(gpus, list) or len(gpus) != 1 or "Tesla V100" not in gpus[0].get("name", "") or
            not gpus[0].get("driver_version", "").startswith("580.") or
            not isinstance(module, dict) or module.get("version") != gpus[0].get("driver_version") or
            module.get("elf_class") != "ELF64" or module.get("elf_type") != "REL" or
            module.get("machine") != "Advanced Micro Devices X86-64"):
        raise ValueError("stock R580 V100 module identity or ELF metadata is invalid")
    sections = module.get("ftrace_related_sections")
    functions = report.get("target_fentry_inspection")
    if (not isinstance(sections, list) or not isinstance(functions, dict) or
            set(functions) != set(TARGETS) or
            any(not isinstance(functions[name], dict) or functions[name].get("symbol_found") not in (True, False)
                for name in TARGETS)):
        raise ValueError("ftrace section or target-symbol inventory is incomplete")
    for name in TARGETS:
        observation = functions[name]
        if observation["symbol_found"]:
            if (observation.get("objdump_succeeded") is not True or
                    observation.get("symbol_header_found") is not True or
                    not isinstance(observation.get("instruction_line_count"), int) or
                    observation["instruction_line_count"] < 1):
                raise ValueError("target disassembly did not contain a verified function body")
        elif observation.get("symbol_header_found") or observation.get("instruction_line_count") is not None:
            raise ValueError("missing target symbol has contradictory disassembly evidence")
    if not isinstance(report.get("available_filter_function_targets"), list):
        raise ValueError("available_filter_functions inventory is malformed")
    return report


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
    audit = load_capability_audit()
    reference = audit.load_reference_tool()
    started = datetime.now(timezone.utc)
    report = {"schema":"nvidia-hybrid-pc3-v100-module-ftrace-transport-v4",
        "started_utc":started.isoformat(timespec="seconds"), "target":args.target,
        "host_key_alias":args.host_key_alias, "credential_host":args.credential_host,
        "credential_file":args.credential_file, "status":"failed", "read_only_requested":True,
        "tracefs_write_attempted":False, "kprobe_event_definition_created":False,
        "probe_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "elf_parser_source_sha256":hashlib.sha256(ELF_PROBE_PATH.read_bytes()).hexdigest()}
    try:
        secret = reference.fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        wrapper = audit.remote_root_script(guest_probe_script(), reference.EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
            reference.DEFAULT_GUEST_KEY, reference.DEFAULT_GUEST_KNOWN_HOSTS, read_only=True,
            trace_event_definition_write_attempted=False)
        remote = "sudo -S -p '' python3 -c " + shlex.quote(wrapper)
        result = subprocess.run(reference.pc3_ssh_base(args.target, args.host_key_alias) + [remote],
            input=reference.sudo_auth_stdin(secret), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=180, check=False, env=audit.pc3_ssh_environment(os.environ))
        report["pc3_ssh_returncode"] = result.returncode
        report["remote_stdout_bytes"] = len(result.stdout)
        report["remote_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        report["remote_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        if result.returncode != 0:
            report["failure_stage"] = "pc3_or_guest_transport"
        else:
            remote_report = json.loads(result.stdout.decode("utf-8", "strict"))
            guest = remote_report.get("guest")
            validate_report(guest)
            if (remote_report.get("host", {}).get("guest_host_key_verified") is not True or
                    remote_report.get("trace_event_definition_write_attempted") is not False):
                raise ValueError("strict guest identity or no-trace-write guarantee failed")
            report["remote"] = remote_report
            report["status"] = "observed"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report["evidence"] = str(args.evidence)
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key:report[key] for key in
            ("schema", "status", "failure_stage", "remote_stdout_bytes", "remote_stdout_sha256", "evidence")
            if key in report}, sort_keys=True))
        return 0 if report["status"] == "observed" else 1
    except Exception as exc:
        report["failure_stage"] = report.get("failure_stage") or "execution_or_validation"
        report["error_class"] = type(exc).__name__
        report["status"] = "failed"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report["evidence"] = str(args.evidence)
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key:report[key] for key in
            ("schema", "status", "failure_stage", "error_class", "evidence") if key in report}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
