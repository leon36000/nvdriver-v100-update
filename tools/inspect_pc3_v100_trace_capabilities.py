#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only inspection of R580 guest symbol and kprobe visibility.

The tool reuses the pinned PC3 transport helpers, strictly verifies the PC3
host and forwarded V100 guest, and does not create a probe or change a driver.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_TOOL = ROOT / "tools/run_pc3_v100_guest_reference.py"
REFERENCE_TOOL_SHA256 = "d0028ad31c74cf43198ffbecd10be0df8d2dd04e890202d07386a2f946da7574"
TARGET_SYMBOLS = ("_nv000794rm", "_nv000790rm", "_nv031399rm", "rm_init_private_state", "rm_init_adapter")
KPROBE_CONTROL_SYMBOLS = ("do_sys_openat2", "__x64_sys_getpid", "vfs_open", "schedule", "do_syscall_64")

GUEST_PROBE = r'''import csv,hashlib,json,os,re,shutil,stat,subprocess
from pathlib import Path

TARGETS = {"_nv000794rm", "_nv000790rm", "_nv031399rm", "rm_init_private_state", "rm_init_adapter"}
CONTROL_SYMBOLS = {"do_sys_openat2", "__x64_sys_getpid", "vfs_open", "schedule", "do_syscall_64"}

def run(argv, timeout=40):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                               check=False, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
        return result
    except (OSError, subprocess.TimeoutExpired):
        return None

def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

def config_value(lines, key):
    prefix = "CONFIG_" + key + "="
    unset = "# CONFIG_" + key + " is not set"
    for line in lines:
        if line.startswith(prefix):
            return line[len(prefix):]
        if line.strip() == unset:
            return "n"
    return "unknown"

def canonical_pci(value):
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match or int(match.group(3), 16) > 31:
        return None
    return f"{int(match.group(1),16)&0xffff:04x}:{int(match.group(2),16):02x}:{int(match.group(3),16):02x}.{int(match.group(4))}"

def target_names(path, targets=TARGETS):
    found = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                fields = line.split()
                if fields and fields[-1] in targets:
                    found.add(fields[-1])
    except OSError:
        return None
    return sorted(found)

def interface(path):
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {"present": False, "readable": False, "mode": None, "error": "not_found"}
    except PermissionError:
        return {"present": None, "readable": False, "mode": None, "error": "permission_denied"}
    try:
        if stat.S_ISDIR(st.st_mode):
            with os.scandir(path) as entries:
                next(entries, None)
        else:
            with open(path, "rb") as stream:
                stream.read(0)
        return {"present": True, "readable": True, "mode": oct(st.st_mode & 0o777), "error": None}
    except FileNotFoundError:
        return {"present": False, "readable": False, "mode": None, "error": "not_found"}
    except PermissionError:
        return {"present": True, "readable": False, "mode": oct(st.st_mode & 0o777), "error": "permission_denied"}
    except OSError as exc:
        return {"present": True, "readable": False, "mode": oct(st.st_mode & 0o777), "error": type(exc).__name__}

def main():
    report = {"schema":"nvidia-hybrid-pc3-v100-trace-capability-v3",
              "hostname":os.uname().nodename, "kernel_release":os.uname().release,
              "effective_uid":os.geteuid(),
              "execution_scope":{"read_only":True, "experimental_module_loaded":False,
                                 "stock_driver_changed":False, "pci_binding_changed":False,
                                 "vm_management_issued":False, "kprobe_attached":False}}
    gpu_result = run(["nvidia-smi", "--query-gpu=name,pci.bus_id,driver_version", "--format=csv,noheader"])
    gpu_rows = []
    if gpu_result is not None and gpu_result.returncode == 0:
        try:
            for row in csv.reader(gpu_result.stdout.decode("utf-8", "replace").splitlines()):
                if len(row) == 3:
                    gpu_rows.append({"name":row[0].strip(), "pci":canonical_pci(row[1].strip()),
                                     "driver_version":row[2].strip()})
        except csv.Error:
            pass
    report["gpus"] = gpu_rows
    report["stock_nvidia_module_loaded"] = Path("/sys/module/nvidia").exists()
    module_path_result = run(["modinfo", "-n", "nvidia"])
    module_version_result = run(["modinfo", "-F", "version", "nvidia"])
    module_path = (module_path_result.stdout.decode("utf-8", "replace").strip()
                   if module_path_result is not None and module_path_result.returncode == 0 else None)
    module_version = (module_version_result.stdout.decode("utf-8", "replace").strip()
                      if module_version_result is not None and module_version_result.returncode == 0 else None)
    module_stat = None
    module_symbols = {}
    module_symbol_types = {}
    nm_result = None
    symbol_source = None
    decompressor_returncode = None
    if module_path:
        try:
            st = os.stat(module_path)
            module_stat = {"basename":Path(module_path).name, "bytes":st.st_size}
            nm = shutil.which("nm")
            if nm:
                if module_path.endswith(".zst"):
                    zstd = shutil.which("zstd")
                    memfd_create = getattr(os, "memfd_create", None)
                    if zstd and memfd_create:
                        decompressed = run([zstd, "-dc", "--", module_path], timeout=60)
                        decompressor_returncode = decompressed.returncode if decompressed is not None else None
                        if decompressed is not None and decompressed.returncode == 0:
                            fd = memfd_create("nvidia-module-symbol-audit", 0)
                            try:
                                view = memoryview(decompressed.stdout)
                                while view:
                                    written = os.write(fd, view)
                                    view = view[written:]
                                nm_result = subprocess.run(
                                    [nm, "-an", "--defined-only", "/proc/self/fd/" + str(fd)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                    check=False, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"},
                                    pass_fds=(fd,))
                                symbol_source = "zstd_memfd"
                            finally:
                                os.close(fd)
                else:
                    nm_result = run([nm, "-an", "--defined-only", module_path], timeout=60)
                    symbol_source = "direct"
                if nm_result is not None and nm_result.returncode == 0:
                    for line in nm_result.stdout.decode("utf-8", "replace").splitlines():
                        fields = line.split()
                        if len(fields) >= 3 and fields[-1] in TARGETS:
                            module_symbols[fields[-1]] = fields[0]
                            module_symbol_types[fields[-1]] = fields[1]
        except OSError:
            pass
    report["stock_module"] = {"version":module_version, "file":module_stat,
                               "module_symbol_table_readable":bool(nm_result is not None and nm_result.returncode == 0),
                               "symbol_source":symbol_source, "decompressor_returncode":decompressor_returncode,
                               "target_symbol_offsets":module_symbols, "target_symbol_types":module_symbol_types}
    kallsyms = target_names("/proc/kallsyms")
    report["trace_interfaces"] = {
        "proc_kallsyms_target_names":kallsyms,
        "available_filter_functions_targets":target_names("/sys/kernel/tracing/available_filter_functions"),
        "debugfs_available_filter_functions_targets":target_names("/sys/kernel/debug/tracing/available_filter_functions"),
        "tracefs_kprobe_events":interface("/sys/kernel/tracing/kprobe_events"),
        "debugfs_kprobe_events":interface("/sys/kernel/debug/tracing/kprobe_events"),
        "debugfs_kprobes_list":interface("/sys/kernel/debug/kprobes/list"),
    }
    report["kernel_kprobe_control_candidates"] = {
        "proc_kallsyms":target_names("/proc/kallsyms", CONTROL_SYMBOLS),
        "available_filter_functions":target_names("/sys/kernel/tracing/available_filter_functions", CONTROL_SYMBOLS),
    }
    kptr = read_text("/proc/sys/kernel/kptr_restrict")
    config_path = "/boot/config-" + os.uname().release
    config = read_text(config_path)
    config_lines = (config or "").splitlines()
    mounts = (read_text("/proc/mounts") or "").splitlines()
    sudo_result = run(["sudo", "-n", "id", "-u"], timeout=5)
    cap_eff = None
    status_text = read_text("/proc/self/status")
    if status_text is not None:
        cap_match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", status_text, re.MULTILINE)
        if cap_match:
            cap_eff = int(cap_match.group(1), 16)
    bpf_tools = {name:bool(shutil.which(name)) for name in ("bpftrace", "bpftool", "clang")}
    lockdown = read_text("/sys/kernel/security/lockdown")
    bpf_runtime = {
        "tools_available":bpf_tools,
        "vmlinux_btf":interface("/sys/kernel/btf/vmlinux"),
        "bpffs":interface("/sys/fs/bpf"),
        "unprivileged_bpf_disabled":(read_text("/proc/sys/kernel/unprivileged_bpf_disabled") or "").strip() or None,
        "lockdown_state":lockdown.strip() if lockdown is not None else None,
        "effective_capabilities":{
            "cap_bpf":bool(cap_eff is not None and cap_eff & (1 << 39)),
            "cap_perfmon":bool(cap_eff is not None and cap_eff & (1 << 38)),
            "cap_sys_admin":bool(cap_eff is not None and cap_eff & (1 << 21)),
            "readable":cap_eff is not None,
        },
    }
    report["bpf_attachment_capabilities"] = bpf_runtime
    report["kernel_probe_config"] = {
        "kptr_restrict":kptr.strip() if kptr is not None else None,
        "config_file_present":config is not None,
        "config_kprobes":config_value(config_lines, "KPROBES"),
        "config_kprobe_events":config_value(config_lines, "KPROBE_EVENTS"),
        "config_kallsyms":config_value(config_lines, "KALLSYMS"),
        "config_kallsyms_all":config_value(config_lines, "KALLSYMS_ALL"),
        "config_modules":config_value(config_lines, "MODULES"),
        "config_module_unload":config_value(config_lines, "MODULE_UNLOAD"),
        "config_ftrace":config_value(config_lines, "FTRACE"),
        "config_function_tracer":config_value(config_lines, "FUNCTION_TRACER"),
        "config_bpf":config_value(config_lines, "BPF"),
        "config_bpf_syscall":config_value(config_lines, "BPF_SYSCALL"),
        "config_bpf_events":config_value(config_lines, "BPF_EVENTS"),
        "config_debug_info_btf":config_value(config_lines, "DEBUG_INFO_BTF"),
        "config_bpf_jit":config_value(config_lines, "BPF_JIT"),
        "config_fprobe":config_value(config_lines, "FPROBE"),
        "config_dynamic_ftrace":config_value(config_lines, "DYNAMIC_FTRACE"),
        "config_kprobe_events_on_notrace":config_value(config_lines, "KPROBE_EVENTS_ON_NOTRACE"),
        "tracefs_mounted":any(len(line.split()) > 2 and line.split()[2] == "tracefs" for line in mounts),
        "debugfs_mounted":any(len(line.split()) > 2 and line.split()[2] == "debugfs" for line in mounts),
        "tracefs_mountpoints":[line.split()[1] for line in mounts if len(line.split()) > 2 and line.split()[2] == "tracefs"],
        "debugfs_mountpoints":[line.split()[1] for line in mounts if len(line.split()) > 2 and line.split()[2] == "debugfs"],
        "tracefs_root":interface("/sys/kernel/tracing"),
        "debugfs_tracing_root":interface("/sys/kernel/debug/tracing"),
        "tracefs_available_filter_functions_file":interface("/sys/kernel/tracing/available_filter_functions"),
        "guest_sudo_root_nopasswd":bool(sudo_result is not None and sudo_result.returncode == 0 and
                                        sudo_result.stdout.decode("utf-8", "replace").strip() == "0"),
    }
    print(json.dumps(report, sort_keys=True))

main()
'''


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_reference_tool():
    digest = sha256(REFERENCE_TOOL)
    if digest != REFERENCE_TOOL_SHA256:
        raise RuntimeError(f"pinned PC3 transport helper hash mismatch: {digest}")
    spec = importlib.util.spec_from_file_location("pc3_v100_reference_transport", REFERENCE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("PC3 transport helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def guest_probe_script() -> str:
    return GUEST_PROBE


def remote_root_script(guest_code: str, expected_fingerprint: str, guest_key: str, known_hosts: str,
                       *, read_only: bool = True,
                       trace_event_definition_write_attempted: bool = False) -> str:
    guest_b64 = base64.b64encode(guest_code.encode("utf-8")).decode("ascii")
    return f'''import base64,hashlib,json,os,shlex,subprocess,sys,tempfile,stat
from pathlib import Path
EXPECTED_FINGERPRINT = {expected_fingerprint!r}
GUEST_KEY = {guest_key!r}
GUEST_KNOWN_HOSTS = {known_hosts!r}
EXPECTED_HOST = "pc3"
def run(argv, timeout=30):
    env={{k:v for k,v in os.environ.items() if not k.startswith(("LD_","CUDA_","NVIDIA_","PYTHON"))}}
    env.update({{"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"}})
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          check=False, env=env)
def verify_guest_host_key(known, expected_fingerprint):
    known_stat = known.lstat()
    if not (stat.S_ISREG(known_stat.st_mode) and known_stat.st_uid == 0 and not known_stat.st_mode & 0o022):
        raise RuntimeError("guest known-hosts ownership or mode is unsafe")
    selected = run(["ssh-keygen", "-F", "[127.0.0.1]:22223", "-f", str(known)], timeout=10)
    lines = [line for line in selected.stdout.decode("utf-8", "replace").splitlines()
             if line and not line.startswith("#")]
    if selected.returncode or not lines or any(line.split()[0].startswith("@") or len(line.split()) < 3 for line in lines):
        raise RuntimeError("guest host-key entry is invalid")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="codex-v100-known-hosts-",
                                     dir="/tmp", delete=False) as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write("\\n".join(lines) + "\\n")
        matched = stream.name
    try:
        fingerprints = run(["ssh-keygen", "-lf", matched], timeout=10)
    finally:
        os.unlink(matched)
    found = {{line.split()[1] for line in fingerprints.stdout.decode("utf-8", "replace").splitlines()
             if len(line.split()) > 1}}
    if fingerprints.returncode or found != {{expected_fingerprint}}:
        raise RuntimeError("guest endpoint does not match the pinned host key")
report = {{"schema":"nvidia-hybrid-pc3-v100-trace-capability-v3", "host":{{
    "hostname":os.uname().nodename, "kernel_release":os.uname().release,
    "sudo_identity_verified":os.geteuid() == 0, "guest_host_key_verified":False}},
    "read_only":{read_only!r}, "trace_event_definition_write_attempted":{trace_event_definition_write_attempted!r},
    "experimental_module_loaded":False, "stock_driver_changed":False,
    "pci_binding_changed":False, "vm_management_issued":False, "kprobe_attached":False}}
try:
    if os.geteuid() != 0 or report["host"]["hostname"].split(".")[0] != EXPECTED_HOST:
        raise RuntimeError("unexpected host identity or privilege")
    verify_guest_host_key(Path(GUEST_KNOWN_HOSTS), EXPECTED_FINGERPRINT)
    report["host"]["guest_host_key_verified"] = True
    guest_code = base64.b64decode({guest_b64!r}, validate=True).decode("utf-8", "strict")
    # The first-pass audit proved guest ubuntu can use non-interactive sudo.
    # Run this strictly read-only probe with the visibility needed for tracefs;
    # fail closed if that privilege is unavailable rather than infer absence.
    remote = "sudo -n python3 -c " + shlex.quote(guest_code)
    argv = ["ssh", "-F", "/dev/null", "-T", "-oBatchMode=yes", "-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile="+GUEST_KNOWN_HOSTS,
            "-oConnectTimeout=8", "-oConnectionAttempts=1", "-i", GUEST_KEY,
            "-p", "22223", "ubuntu@127.0.0.1", remote]
    result = run(argv, timeout=100)
    report["guest_transport"] = {{"returncode":result.returncode,
        "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),
        "stdout_bytes":len(result.stdout), "stderr_sha256":hashlib.sha256(result.stderr).hexdigest()}}
    if result.returncode != 0:
        report["status"] = "guest_query_failed"
    else:
        report["guest"] = json.loads(result.stdout.decode("utf-8", "strict"))
        report["status"] = "observed"
except Exception as exc:
    report["status"] = "observation_failed"
    report["error_class"] = type(exc).__name__
print(json.dumps(report, sort_keys=True))
'''


def validate_report(report: object) -> dict[str, object]:
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-pc3-v100-trace-capability-v3":
        raise ValueError("unsupported trace-capability report")
    host = report.get("host")
    guest = report.get("guest")
    if (not isinstance(host, dict) or host.get("hostname", "").split(".")[0] != "pc3" or
            host.get("sudo_identity_verified") is not True or host.get("guest_host_key_verified") is not True):
        raise ValueError("PC3 host identity or strict guest host-key verification failed")
    if report.get("status") != "observed" or not isinstance(guest, dict) or guest.get("hostname") != "pc3-v100":
        raise ValueError("wrong V100 guest or incomplete read-only observation")
    gpus = guest.get("gpus")
    if not isinstance(gpus, list) or len(gpus) != 1 or not isinstance(gpus[0], dict):
        raise ValueError("guest does not expose exactly one GPU")
    gpu = gpus[0]
    version = gpu.get("driver_version")
    if ("Tesla V100" not in gpu.get("name", "") or
            canonical_pci(gpu.get("pci")) != gpu.get("pci") or
            not isinstance(version, str) or not re.fullmatch(r"580\.\d+\.\d+", version)):
        raise ValueError("guest GPU identity is not one SM70 Tesla V100 on R580")
    if report.get("read_only") is not True or any(
        report.get(key) is not False
        for key in ("experimental_module_loaded", "stock_driver_changed", "pci_binding_changed",
                    "vm_management_issued", "kprobe_attached")
    ):
        raise ValueError("read-only scope was violated")
    bpf = guest.get("bpf_attachment_capabilities")
    config = guest.get("kernel_probe_config")
    if (not isinstance(bpf, dict) or not isinstance(config, dict) or
            not isinstance(bpf.get("tools_available"), dict) or
            not isinstance(bpf.get("effective_capabilities"), dict) or
            not isinstance(config.get("config_bpf_syscall"), str) or
            not isinstance(config.get("config_bpf_events"), str) or
            not isinstance(config.get("config_fprobe"), str)):
        raise ValueError("read-only BPF attach-capability inventory is missing")
    return report


def classify_transport_failure(returncode: int, stdout: bytes) -> str | None:
    """Separate an SSH transport failure from a remote command with no report."""
    if returncode == 255 and not stdout:
        return "pc3_ssh_transport"
    if returncode != 0 and not stdout:
        return "pc3_remote_execution"
    return None


def canonical_pci(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match or int(match.group(3), 16) > 31:
        return None
    return f"{int(match.group(1),16)&0xffff:04x}:{int(match.group(2),16):02x}:{int(match.group(3),16):02x}.{int(match.group(4))}"


def pc3_ssh_environment(source: dict[str, str]) -> dict[str, str]:
    """Keep the subprocess environment small while allowing the configured SSH agent."""
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    socket = source.get("SSH_AUTH_SOCK", "")
    if socket.startswith("/") and "\0" not in socket:
        env["SSH_AUTH_SOCK"] = socket
    pid = source.get("SSH_AGENT_PID", "")
    if pid.isascii() and pid.isdigit():
        env["SSH_AGENT_PID"] = pid
    return env


def remote_failure_summary(report: object) -> dict[str, object]:
    """Retain safe identity and transport fields without storing raw remote output."""
    if not isinstance(report, dict):
        return {}
    summary: dict[str, object] = {}
    for key in ("schema", "status", "error_class"):
        if isinstance(report.get(key), str):
            summary[key] = report[key]
    host = report.get("host")
    if isinstance(host, dict):
        allowed_host = ("hostname", "kernel_release", "sudo_identity_verified", "guest_host_key_verified")
        summary["host"] = {key: host[key] for key in allowed_host if key in host}
    transport = report.get("guest_transport")
    if isinstance(transport, dict):
        allowed_transport = ("returncode", "stdout_bytes", "stdout_sha256", "stderr_sha256")
        summary["guest_transport"] = {key: transport[key] for key in allowed_transport if key in transport}
    guest = report.get("guest")
    if isinstance(guest, dict):
        guest_summary: dict[str, object] = {}
        for key in ("hostname", "kernel_release", "effective_uid", "stock_nvidia_module_loaded"):
            if key in guest:
                guest_summary[key] = guest[key]
        gpus = guest.get("gpus")
        if isinstance(gpus, list):
            guest_summary["gpus"] = [
                {key: gpu[key] for key in ("name", "pci", "driver_version") if key in gpu}
                for gpu in gpus if isinstance(gpu, dict)
            ]
        module = guest.get("stock_module")
        if isinstance(module, dict):
            guest_summary["stock_module"] = {
                key: module[key] for key in (
                    "version", "file", "module_symbol_table_readable", "symbol_source",
                    "decompressor_returncode", "target_symbol_offsets", "target_symbol_types"
                )
                if key in module
            }
        interfaces = guest.get("trace_interfaces")
        if isinstance(interfaces, dict):
            guest_summary["trace_interfaces"] = {
                key: interfaces[key] for key in (
                    "proc_kallsyms_target_names", "available_filter_functions_targets",
                    "debugfs_available_filter_functions_targets", "tracefs_kprobe_events",
                    "debugfs_kprobe_events", "debugfs_kprobes_list", "tracefs_root",
                    "debugfs_tracing_root", "tracefs_available_filter_functions_file"
                ) if key in interfaces
            }
        controls = guest.get("kernel_kprobe_control_candidates")
        if isinstance(controls, dict):
            guest_summary["kernel_kprobe_control_candidates"] = {
                key: controls[key] for key in ("proc_kallsyms", "available_filter_functions")
                if key in controls
            }
        probe_config = guest.get("kernel_probe_config")
        if isinstance(probe_config, dict):
            guest_summary["kernel_probe_config"] = {
                key: probe_config[key] for key in (
                    "kptr_restrict", "config_file_present", "config_kprobes", "config_kprobe_events",
                    "config_kallsyms", "config_kallsyms_all", "config_modules", "config_module_unload",
                    "config_ftrace", "config_function_tracer", "config_bpf", "config_bpf_syscall",
                    "config_bpf_events", "config_debug_info_btf", "config_bpf_jit", "config_fprobe", "config_dynamic_ftrace",
                    "config_kprobe_events_on_notrace", "tracefs_mounted", "debugfs_mounted",
                    "tracefs_mountpoints", "debugfs_mountpoints", "guest_sudo_root_nopasswd"
                ) if key in probe_config
            }
        bpf = guest.get("bpf_attachment_capabilities")
        if isinstance(bpf, dict):
            guest_summary["bpf_attachment_capabilities"] = {
                key:bpf[key] for key in (
                    "tools_available", "vmlinux_btf", "bpffs", "unprivileged_bpf_disabled",
                    "lockdown_state", "effective_capabilities") if key in bpf
            }
        scope = guest.get("execution_scope")
        if isinstance(scope, dict):
            guest_summary["execution_scope"] = {
                key: scope[key] for key in (
                    "read_only", "experimental_module_loaded", "stock_driver_changed",
                    "pci_binding_changed", "vm_management_issued", "kprobe_attached"
                ) if key in scope
            }
        summary["guest"] = guest_summary
    return summary


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

    started = datetime.now(timezone.utc)
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-v100-trace-capability-transport-v2",
        "started_utc": started.isoformat(timespec="seconds"),
        "target": args.target,
        "host_key_alias": args.host_key_alias,
        "credential_host": args.credential_host,
        "credential_file": args.credential_file,
        "transport_helper_sha256": None,
        "status": "failed",
        "failure_stage": None,
        "read_only_requested": True,
    }
    try:
        reference = load_reference_tool()
        report["transport_helper_sha256"] = REFERENCE_TOOL_SHA256
        secret = reference.fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        script = remote_root_script(
            guest_probe_script(),
            reference.EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
            reference.DEFAULT_GUEST_KEY,
            reference.DEFAULT_GUEST_KNOWN_HOSTS,
        )
        remote = "sudo -S -p '' python3 -c " + shlex.quote(script)
        try:
            result = subprocess.run(
                reference.pc3_ssh_base(args.target, args.host_key_alias) + [remote],
                input=reference.sudo_auth_stdin(secret), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=130, check=False,
                env=pc3_ssh_environment(os.environ),
            )
        except (OSError, subprocess.TimeoutExpired):
            report["failure_stage"] = "pc3_ssh_transport"
            report["stderr_or_timeout"] = "transport failed or timed out"
        else:
            report["pc3_ssh_returncode"] = result.returncode
            report["remote_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
            report["remote_stdout_bytes"] = len(result.stdout)
            report["remote_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
            transport_failure = classify_transport_failure(result.returncode, result.stdout)
            if transport_failure:
                report["failure_stage"] = transport_failure
            else:
                try:
                    remote_report = json.loads(result.stdout.decode("utf-8", "strict"))
                except (UnicodeDecodeError, ValueError, TypeError, KeyError):
                    report["failure_stage"] = "remote_response_validation"
                else:
                    if result.returncode == 0:
                        try:
                            validate_report(remote_report)
                        except (ValueError, TypeError, KeyError) as exc:
                            report["failure_stage"] = "remote_report_validation"
                            report["validation_error_class"] = type(exc).__name__
                            report["validation_error"] = str(exc)[:180]
                            report["remote_summary"] = remote_failure_summary(remote_report)
                        else:
                            report["status"] = "observed"
                            report["remote"] = remote_report
                    else:
                        report["failure_stage"] = "remote_audit"
                        report["remote_summary"] = remote_failure_summary(remote_report)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        write_private_new(args.evidence, encoded)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["status"] == "observed" else 1
    except Exception as exc:
        report["failure_stage"] = report["failure_stage"] or "setup"
        report["error_class"] = type(exc).__name__
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        write_private_new(args.evidence, encoded)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
