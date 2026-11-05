#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect a bounded, read-only PC3 kernel/driver canary snapshot.

The default transport reuses the historical PC6-sourced sudo credential path.
Use --direct-pc3 to require the local SSH key and PC3's non-interactive sudo;
that mode never contacts another host. Collection only reads host policy,
loaded-module, device-node and process-FD use, PCI ownership, public MOK
certificate, package, module-file, and boot-artifact state. It never signs,
loads, installs, removes, or rebinds a driver.
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
import shlex
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import run_pc3_v100_guest_reference as pc3  # noqa: E402


STATE_SCHEMA = "nvidia-hybrid-canary-host-state-v2"
COLLECTOR_SCHEMA = "nvidia-hybrid-canary-host-state-collection-v3"
DEFAULT_TARGET = pc3.DEFAULT_PC3_TARGET
DEFAULT_CREDENTIAL_HOST = pc3.DEFAULT_CREDENTIAL_HOST
DEFAULT_CREDENTIAL_FILE = pc3.DEFAULT_CREDENTIAL_FILE
DEFAULT_HOST_KEY_ALIAS = pc3.DEFAULT_HOST_KEY_ALIAS
LEGACY_TRANSPORT_MODE = "pc6-sourced-sudo-auth"
DIRECT_TRANSPORT_MODE = "pc3-ssh-key-sudo-n"
REQUIRED_STATE_FIELDS = {
    "schema", "host", "observed_at_utc", "boot_id", "kernel_release", "kernel_vermagic",
    "secure_boot_enabled", "module_sig_enforce", "lockdown", "active_char_devices",
    "active_modules_scope", "active_modules", "loaded_nvidia_modules", "char_device_major_names",
    "gpu_ownership", "installed_nvidia_module", "loaded_nvidia_module_version",
    "local_module_signing_key_metadata",
}
SENSITIVE_KEY = re.compile(r"password|credential|secret|private.?key.?contents|private.?key.?pem|private.?key.?data", re.I)
SENSITIVE_VALUE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)


REMOTE_HOST_STATE_SCRIPT = r'''import datetime,errno,json,os,re,selectors,subprocess,time
import stat
from pathlib import Path

MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024

def read_text(path):
    return Path(path).read_text(encoding="utf-8", errors="strict").strip()

def run(argv, required=True, timeout=15, max_bytes=MAX_COMMAND_OUTPUT_BYTES):
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("invalid bounded command output limit")
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False,
                               env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
    selector = selectors.DefaultSelector()
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    try:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            events = selector.select(remaining) if remaining > 0 else []
            if not events:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _ in events:
                chunk = os.read(key.fd, min(65536, max_bytes - total + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError("bounded read-only command output exceeded limit")
                outputs[key.data].extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        return_code = process.wait(timeout=remaining)
        text = (bytes(outputs["stdout"]) + bytes(outputs["stderr"])).decode("utf-8", "replace")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if required and return_code != 0:
        raise RuntimeError("read-only host command failed: " + argv[0])
    return return_code, text

def run_stdout_bounded(argv, timeout=15, max_bytes=262144):
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, shell=False,
                               env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            events = selector.select(remaining) if remaining > 0 else []
            if not events:
                raise subprocess.TimeoutExpired(argv, timeout)
            for key, _ in events:
                chunk = os.read(key.fd, min(65536, max_bytes - len(output) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise RuntimeError("bounded read-only command output exceeded limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, timeout)
        return process.wait(timeout=remaining), bytes(output).decode("utf-8", "replace")
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()

MAX_PROC_ENTRIES = 32768
MAX_FDS_PER_PROCESS = 8192
MAX_TOTAL_FD_ENTRIES = 250000
MAX_GPU_DEVICE_OWNERS = 2048
MAX_GPU_DEVICE_NODES_PER_OWNER = 64
MAX_QUERY_OUTPUT_BYTES = 262144

def nvidia_character_major_names():
    names = {}
    active = False
    for line in Path("/proc/devices").read_text(encoding="ascii").splitlines():
        if line == "Character devices:":
            active = True
            continue
        if line == "Block devices:":
            break
        if active:
            fields = line.split(maxsplit=1)
            if len(fields) == 2 and fields[1].startswith("nvidia"):
                names[int(fields[0])] = fields[1]
    return names

def nvidia_device_labels(major_names):
    labels = {}
    candidates = list(Path("/dev").glob("nvidia*"))
    candidates.extend(Path("/dev/nvidia-caps").glob("*"))
    for path in candidates:
        try:
            metadata = path.stat()
        except OSError:
            continue
        if not stat.S_ISCHR(metadata.st_mode) or os.major(metadata.st_rdev) not in major_names:
            continue
        labels[(os.major(metadata.st_rdev), os.minor(metadata.st_rdev))] = str(path).removeprefix("/dev/")
    return labels

def gpu_node_label(major, minor, labels):
    return labels.get((major, minor),
                      "nvidia-major-" + str(major) + "-minor-" + str(minor))

def add_gpu_device_node(nodes, label, incomplete):
    if label not in nodes and len(nodes) >= MAX_GPU_DEVICE_NODES_PER_OWNER:
        incomplete("gpu-device-node-limit")
        return False
    nodes[label] = nodes.get(label, 0) + 1
    return True

def collect_gpu_device_fd_owners():
    owners = []
    scanned = 0
    fd_entries_scanned = 0
    incomplete_reasons = {}

    def incomplete(reason):
        incomplete_reasons[reason] = incomplete_reasons.get(reason, 0) + 1

    major_names = nvidia_character_major_names()
    labels = nvidia_device_labels(major_names)
    try:
        processes = Path("/proc").iterdir()
        for process in processes:
            if not process.name.isdigit():
                continue
            if scanned >= MAX_PROC_ENTRIES:
                incomplete("process-entry-limit")
                break
            scanned += 1
            try:
                comm = (process / "comm").read_text(encoding="utf-8", errors="replace").strip()[:64]
            except OSError:
                if process.exists():
                    incomplete("process-comm-unavailable")
                continue
            nodes = {}
            try:
                fd_entries = iter((process / "fd").iterdir())
                for index, fd_entry in enumerate(fd_entries):
                    if index >= MAX_FDS_PER_PROCESS or fd_entries_scanned >= MAX_TOTAL_FD_ENTRIES:
                        incomplete("fd-entry-limit" if index >= MAX_FDS_PER_PROCESS else
                                   "total-fd-entry-limit")
                        break
                    fd_entries_scanned += 1
                    try:
                        metadata = os.stat(fd_entry)
                    except OSError as error:
                        if process.exists():
                            if error.errno == errno.ENOENT:
                                incomplete("fd-stat-vanished")
                            elif error.errno in (errno.EACCES, errno.EPERM):
                                incomplete("fd-stat-permission")
                            else:
                                incomplete("fd-stat-other")
                        continue
                    major = os.major(metadata.st_rdev) if stat.S_ISCHR(metadata.st_mode) else -1
                    if major not in major_names:
                        continue
                    minor = os.minor(metadata.st_rdev)
                    relative = gpu_node_label(major, minor, labels)
                    if not add_gpu_device_node(nodes, relative, incomplete):
                        break
            except OSError:
                if process.exists():
                    incomplete("process-fd-directory-unavailable")
                continue
            if nodes:
                if len(owners) >= MAX_GPU_DEVICE_OWNERS:
                    incomplete("gpu-device-owner-limit")
                    break
                owners.append({"pid": int(process.name), "comm": comm,
                               "fd_count": sum(nodes.values()), "nodes": sorted(nodes)})
    except OSError:
        incomplete("proc-directory-unavailable")
    owners.sort(key=lambda item: item["pid"])
    if scanned == 0:
        incomplete("no-processes-observed")
    return {"proc_scan_complete": scanned > 0 and not incomplete_reasons,
            "proc_scan_incomplete_reasons": incomplete_reasons,
            "proc_processes_scanned": scanned,
            "proc_fd_entries_scanned": fd_entries_scanned,
            "device_fd_owners": owners}

def collect_gpu_compute_pids():
    try:
        code, text = run_stdout_bounded(
            ["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader"],
            timeout=15, max_bytes=MAX_QUERY_OUTPUT_BYTES)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return {"compute_query_complete": False, "compute_pids": []}
    if code != 0:
        return {"compute_query_complete": False, "compute_pids": []}
    pids = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.lower() == "no running processes found":
            continue
        if not re.fullmatch(r"[0-9]+", value) or int(value) <= 0:
            return {"compute_query_complete": False, "compute_pids": []}
        pids.append(int(value))
    return {"compute_query_complete": True, "compute_pids": sorted(set(pids))}

def collect_gpu_process_inventory(observed_at):
    inventory = {"schema": "pc3-gpu-process-inventory-v1",
                 "observed_at_utc": observed_at}
    inventory.update(collect_gpu_device_fd_owners())
    inventory.update(collect_gpu_compute_pids())
    return inventory

def module_field(field, name="nvidia", required=True):
    code, text = run(["modinfo", "-F", field, name], required=required)
    value = text.strip() if code == 0 else ""
    if required and not value:
        raise RuntimeError("required module metadata is unavailable: " + field)
    return value

kernel = os.uname().release
vermagic = module_field("vermagic")
installed_module = {"version": module_field("version"),
                    "signer": module_field("signer", required=False),
                    "vermagic": vermagic}
if vermagic.split()[0] != kernel:
    raise RuntimeError("installed NVIDIA module vermagic differs from running kernel")
try:
    loaded_module_version = read_text("/sys/module/nvidia/version")
except FileNotFoundError:
    loaded_module_version = None

sb_code, sb_text = run(["mokutil", "--sb-state"])
if re.search(r"secureboot\s+enabled", sb_text, re.I):
    secure_boot = True
elif re.search(r"secureboot\s+disabled", sb_text, re.I):
    secure_boot = False
else:
    raise RuntimeError("Secure Boot state is not recognizable")

sig_text = read_text("/sys/module/module/parameters/sig_enforce").upper()
if sig_text not in ("Y", "N", "1", "0"):
    raise RuntimeError("module signature enforcement state is not recognizable")
module_sig_enforce = sig_text in ("Y", "1")
lockdown_text = read_text("/sys/kernel/security/lockdown")
lockdown_match = re.search(r"\[(none|integrity|confidentiality)\]", lockdown_text, re.I)
if not lockdown_match:
    raise RuntimeError("kernel lockdown state is not recognizable")
lockdown = lockdown_match.group(1).lower()

loaded_modules = []
active_modules = []
for line in read_text("/proc/modules").splitlines():
    fields = line.split()
    if fields:
        active_modules.append({"name": fields[0]})
        if fields[0].startswith("nvidia"):
            loaded_modules.append(fields[0])

active_char_devices = []
device_paths = list(Path("/dev").glob("nvidia*"))
device_paths.extend(Path("/dev/nvidia-caps").glob("*"))
for path in sorted(set(device_paths)):
    if not (re.fullmatch(r"nvidia(?:[0-9]+|ctl|-modeset|-uvm(?:-tools)?|-caps(?:-imex-channels)?|-nvlink|-nvswitch|-fs)", path.name) or
            path.parent == Path("/dev/nvidia-caps")):
        continue
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        continue
    if not __import__("stat").S_ISCHR(metadata.st_mode):
        continue
    active_char_devices.append({"path": str(path), "major": os.major(metadata.st_rdev),
                                "minor": os.minor(metadata.st_rdev)})

char_device_major_names = []
in_char_devices = False
for line in read_text("/proc/devices").splitlines():
    if line == "Character devices:":
        in_char_devices = True
        continue
    if line == "Block devices:":
        in_char_devices = False
    if in_char_devices:
        fields = line.split(maxsplit=1)
        if len(fields) == 2:
            char_device_major_names.append({"major": int(fields[0]), "name": fields[1]})

try:
    lspci_code, lspci_text = run(["lspci", "-D", "-nn", "-d", "10de:"], required=False)
except (OSError, subprocess.SubprocessError):
    lspci_text = ""
pci_descriptions = {}
for line in lspci_text.splitlines():
    match = re.match(r"^([0-9a-fA-F:.]+)\s+(.+)$", line)
    if match:
        pci_descriptions[match.group(1).lower()] = match.group(2)

gpu_ownership = []
BDF_PATTERN = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]")

def optional_read(path):
    try:
        return read_text(path)
    except (OSError, ValueError):
        return None

def pci_topology(path):
    bdf = path.name.lower()
    resolved = path.resolve(strict=True)
    ancestors = []
    for parent in reversed(list(resolved.parents)):
        parent_bdf = parent.name.lower()
        if not BDF_PATTERN.fullmatch(parent_bdf):
            continue
        parent_device = Path("/sys/bus/pci/devices") / parent_bdf
        try:
            parent_vendor = read_text(parent_device / "vendor").lower().removeprefix("0x")
            parent_id = read_text(parent_device / "device").lower().removeprefix("0x")
            parent_class = read_text(parent_device / "class").lower().removeprefix("0x")
        except (OSError, ValueError):
            continue
        parent_driver = None
        try:
            parent_driver = (parent_device / "driver").resolve(strict=True).name
        except (OSError, RuntimeError):
            pass
        acs = []
        try:
            acs_code, acs_text = run(["lspci", "-D", "-vv", "-s", parent_bdf], required=False)
            if acs_code == 0:
                acs = [line.strip() for line in acs_text.splitlines()
                       if re.match(r"^\s*ACS(?:Cap|Ctl):", line)]
        except (OSError, subprocess.SubprocessError):
            pass
        ancestors.append({"pci": parent_bdf, "vendor_id": parent_vendor,
                          "device_id": parent_id, "class": parent_class,
                          "driver": parent_driver, "acs": acs})

    link = {name: optional_read(path / name) for name in (
        "current_link_speed", "current_link_width", "max_link_speed", "max_link_width")}

    group_id = None
    group_count = None
    group_nvidia_gpus = []
    try:
        group_root = (path / "iommu_group").resolve(strict=True)
        if not re.fullmatch(r"[0-9]+", group_root.name):
            raise RuntimeError("PCI IOMMU group name is invalid")
        group_id = int(group_root.name)
        group_devices = sorted((group_root / "devices").iterdir(), key=lambda item: item.name)
        group_count = len(group_devices)
        for member in group_devices:
            member_bdf = member.name.lower()
            if not BDF_PATTERN.fullmatch(member_bdf):
                continue
            member_device = Path("/sys/bus/pci/devices") / member_bdf
            try:
                member_vendor = read_text(member_device / "vendor").lower().removeprefix("0x")
                member_class = int(read_text(member_device / "class"), 16)
            except (OSError, ValueError):
                continue
            if member_vendor == "10de" and (member_class >> 16) == 0x03:
                group_nvidia_gpus.append(member_bdf)
    except FileNotFoundError:
        pass

    return {"pci_ancestors": ancestors,
            "link": link,
            "iommu_group": group_id,
            "iommu_group_device_count": group_count,
            "nvidia_gpu_bdfs_in_group": group_nvidia_gpus}

def driver_recovery_inventory():
    package_format = "${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"
    package_code, package_text = run(["dpkg-query", "-W", "-f=" + package_format])
    package_prefixes = ("nvidia-", "libnvidia-", "xserver-xorg-video-nvidia-",
                        "linux-image-", "linux-modules-",
                        "linux-headers-", "linux-firmware")
    package_exact = {"dkms", "shim-signed", "initramfs-tools", "grub-common",
                     "grub2-common", "grub-efi-amd64", "grub-efi-amd64-signed"}
    packages = []
    for line in package_text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        name, version, status = (field.strip() for field in fields)
        base_name = name.split(":", 1)[0]
        if status != "ii" or not (base_name in package_exact or
                                   base_name.startswith(package_prefixes)):
            continue
        packages.append({"name": name, "version": version, "status": status})
    packages.sort(key=lambda item: item["name"])

    module_files = []
    for name in sorted(loaded_modules):
        try:
            path_code, path_text = run(["modinfo", "-n", name], required=False)
        except (OSError, subprocess.SubprocessError):
            path_code, path_text = 127, ""
        module_path = path_text.strip().splitlines()[0] if path_text.strip() else ""
        entry = {"name": name, "path": module_path, "exists": False,
                 "size_bytes": None, "sha256": None,
                 "version": module_field("version", name, required=False),
                 "signer": module_field("signer", name, required=False),
                 "vermagic": module_field("vermagic", name, required=False)}
        if path_code == 0 and module_path and module_path.startswith("/"):
            try:
                module_file = Path(module_path)
                metadata = module_file.stat()
                if module_file.is_file():
                    digest = __import__("hashlib").sha256()
                    with module_file.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                    entry.update({"exists": True, "size_bytes": metadata.st_size,
                                  "sha256": digest.hexdigest()})
            except OSError:
                pass
        module_files.append(entry)

    boot_artifacts = []
    boot_dir = Path("/boot")
    for pattern, kind in (("vmlinuz*", "kernel"), ("initrd.img*", "initramfs")):
        for artifact in sorted(boot_dir.glob(pattern)):
            try:
                metadata = artifact.stat()
            except OSError:
                boot_artifacts.append({"name": artifact.name, "path": str(artifact),
                                       "kind": kind, "exists": False, "size_bytes": None})
                continue
            if artifact.is_file():
                boot_artifacts.append({"name": artifact.name, "path": str(artifact),
                                       "kind": kind, "exists": True,
                                       "size_bytes": metadata.st_size})
    boot_artifacts.sort(key=lambda item: item["name"])

    try:
        grub_code, grub_text = run(["grub-editenv", "/boot/grub/grubenv", "list"], required=False)
    except (OSError, subprocess.SubprocessError):
        grub_code, grub_text = 127, ""
    grub_values = {}
    if grub_code == 0:
        for line in grub_text.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in ("saved_entry", "next_entry"):
                grub_values[key] = value

    kernel_modules = []
    kernel_releases = sorted({item["name"][len("vmlinuz-"):]
                              for item in boot_artifacts
                              if item["name"].startswith("vmlinuz-")})
    for kernel_release in kernel_releases:
        try:
            path_code, path_text = run(["modinfo", "-k", kernel_release, "-n", "nvidia"],
                                       required=False)
        except (OSError, subprocess.SubprocessError):
            path_code, path_text = 127, ""
        module_path = path_text.strip().splitlines()[0] if path_text.strip() else ""
        module_file = Path(module_path) if path_code == 0 and module_path.startswith("/") else None
        try:
            module_stat = module_file.stat() if module_file is not None else None
            module_present = bool(module_stat is not None and module_file.is_file())
        except OSError:
            module_stat = None
            module_present = False
        entry = {"kernel_release": kernel_release, "module_present": module_present,
                 "path": str(module_file) if module_present else None,
                 "size_bytes": module_stat.st_size if module_present else None,
                 "sha256": None, "version": None, "signer": None, "vermagic": None}
        if module_present:
            digest = __import__("hashlib").sha256()
            with module_file.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            entry["sha256"] = digest.hexdigest()
            for field in ("version", "signer", "vermagic"):
                field_code, field_text = run(
                    ["modinfo", "-k", kernel_release, "-F", field, "nvidia"], required=False)
                if field_code == 0 and field_text.strip():
                    entry[field] = field_text.strip().splitlines()[0]
        kernel_modules.append(entry)

    return {"schema": "pc3-driver-recovery-inventory-v1",
            "package_query_complete": package_code == 0,
            "packages": packages,
            "module_file_hash_scope": "installed_file_on_disk_not_loaded_memory",
            "module_files_on_disk": module_files,
            "nvidia_module_by_kernel": kernel_modules,
            "boot_artifacts": boot_artifacts,
            "grub_environment": {"available": grub_code == 0,
                                 "saved_entry": grub_values.get("saved_entry"),
                                 "next_entry": grub_values.get("next_entry")}}

for path in sorted(Path("/sys/bus/pci/devices").glob("*")):
    try:
        vendor = read_text(path / "vendor").lower().removeprefix("0x")
        device = read_text(path / "device").lower().removeprefix("0x")
        pci_class = int(read_text(path / "class"), 16)
    except (OSError, ValueError):
        continue
    if vendor != "10de" or (pci_class >> 16) != 0x03:
        continue
    driver = None
    try:
        driver = (path / "driver").resolve(strict=True).name
    except (OSError, RuntimeError):
        pass
    bdf = path.name.lower()
    gpu_ownership.append({"pci": bdf, "vendor_id": vendor, "device_id": device,
                          "class": f"{pci_class:06x}", "driver": driver,
                          "model": pci_descriptions.get(bdf),
                          "pci_topology": pci_topology(path)})

certificate = Path("/var/lib/shim-signed/mok/MOK.der")
certificate_present = certificate.is_file() and not certificate.is_symlink()
certificate_enrolled = None
mok_test_result = "unknown"
if certificate_present:
    mok_code, mok_text = run(["mokutil", "--test-key", str(certificate)], required=False)
    if re.search(r"not\s+enrolled|not\s+in\s+the\s+mok\s+list|not\s+found", mok_text, re.I):
        certificate_enrolled = False
        mok_test_result = "not_enrolled"
    elif mok_code == 0:
        certificate_enrolled = True
        mok_test_result = "enrolled"

recovery_inventory = driver_recovery_inventory()

gpu_process_scan_started_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
gpu_process_inventory = collect_gpu_process_inventory(gpu_process_scan_started_at)
boot_id = read_text("/proc/sys/kernel/random/boot_id")
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
state = {
    "schema": "nvidia-hybrid-canary-host-state-v2",
    "host": os.uname().nodename,
    "observed_at_utc": now,
    "boot_id": boot_id,
    "kernel_release": kernel,
    "kernel_vermagic": vermagic,
    "secure_boot_enabled": secure_boot,
    "module_sig_enforce": module_sig_enforce,
    "lockdown": lockdown,
    "active_char_devices": active_char_devices,
    "active_modules_scope": "all",
    "active_modules": active_modules,
    "loaded_nvidia_modules": loaded_modules,
    "char_device_major_names": char_device_major_names,
    "gpu_ownership": gpu_ownership,
    "gpu_process_inventory": gpu_process_inventory,
    "installed_nvidia_module": installed_module,
    "loaded_nvidia_module_version": loaded_module_version,
    "local_module_signing_key_metadata": {
        "certificate_present": certificate_present,
        "certificate_enrolled": certificate_enrolled,
        "mok_test_result": mok_test_result,
    },
    "driver_recovery_inventory": recovery_inventory,
}
print(json.dumps(state, sort_keys=True, separators=(",", ":")))
'''


def _reject_duplicate_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key: " + key)
        output[key] = value
    return output


def parse_remote_json(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("remote host-state JSON is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("remote host-state result must be an object")
    return validate_host_state(value)


def _check_no_sensitive_material(value, path="snapshot"):
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY.search(str(key)):
                raise ValueError("sensitive field is forbidden in host-state snapshot: " + path + "." + str(key))
            _check_no_sensitive_material(child, path + "." + str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _check_no_sensitive_material(child, path + "[" + str(index) + "]")
    elif isinstance(value, str) and SENSITIVE_VALUE.search(value):
        raise ValueError("sensitive key material is forbidden in host-state snapshot: " + path)


def _validate_gpu_process_inventory(inventory: dict) -> None:
    fields = {"schema", "observed_at_utc", "proc_scan_complete", "proc_processes_scanned",
              "proc_fd_entries_scanned", "proc_scan_incomplete_reasons",
              "device_fd_owners", "compute_query_complete", "compute_pids"}
    if not isinstance(inventory, dict) or set(inventory) != fields:
        raise ValueError("GPU process inventory fields are invalid")
    observed_at = inventory["observed_at_utc"]
    if (inventory["schema"] != "pc3-gpu-process-inventory-v1" or
            not isinstance(observed_at, str) or
            not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", observed_at)):
        raise ValueError("GPU process inventory identity or timestamp is invalid")
    try:
        datetime.fromisoformat(observed_at[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("GPU process inventory timestamp is invalid") from error
    if type(inventory["proc_scan_complete"]) is not bool or type(inventory["compute_query_complete"]) is not bool:
        raise ValueError("GPU process inventory completeness flags are invalid")
    scanned = inventory["proc_processes_scanned"]
    if type(scanned) is not int or scanned < 0 or scanned > 32768:
        raise ValueError("GPU process inventory process count is invalid")
    fd_scanned = inventory["proc_fd_entries_scanned"]
    if type(fd_scanned) is not int or fd_scanned < 0 or fd_scanned > 250000:
        raise ValueError("GPU process inventory FD-entry count is invalid")
    reason_names = {"process-entry-limit", "process-comm-unavailable", "fd-entry-limit",
                    "total-fd-entry-limit", "fd-stat-vanished",
                    "fd-stat-permission", "fd-stat-other",
                    "gpu-device-node-limit", "process-fd-directory-unavailable",
                    "gpu-device-owner-limit", "proc-directory-unavailable",
                    "no-processes-observed"}
    reasons = inventory["proc_scan_incomplete_reasons"]
    if (not isinstance(reasons, dict) or set(reasons) - reason_names or
            any(type(count) is not int or count <= 0 or count > 250000
                for count in reasons.values())):
        raise ValueError("GPU process inventory incomplete-reason counts are invalid")
    expected_complete = scanned > 0 and not reasons
    if inventory["proc_scan_complete"] is not expected_complete:
        raise ValueError("GPU process inventory completeness flag disagrees with scan evidence")
    compute_pids = inventory["compute_pids"]
    if (not isinstance(compute_pids, list) or
            any(type(pid) is not int or pid <= 0 for pid in compute_pids) or
            compute_pids != sorted(set(compute_pids))):
        raise ValueError("GPU process inventory compute PIDs are invalid")
    owners = inventory["device_fd_owners"]
    if not isinstance(owners, list) or len(owners) > 2048:
        raise ValueError("GPU process inventory FD-owner list is invalid")
    owner_pids = []
    device_name = re.compile(r"(?:nvidia(?:[0-9]+|ctl|-(?:modeset|uvm|uvm-tools|nvlink|nvswitch|fs|caps-imex-channels)|-[A-Za-z0-9_.-]+-minor-[0-9]+)|nvidia-caps/[A-Za-z0-9_.-]+)")
    for owner in owners:
        if not isinstance(owner, dict) or set(owner) != {"pid", "comm", "fd_count", "nodes"}:
            raise ValueError("GPU process inventory FD-owner record is invalid")
        pid, comm, fd_count, nodes = (owner["pid"], owner["comm"], owner["fd_count"], owner["nodes"])
        if (type(pid) is not int or pid <= 0 or not isinstance(comm, str) or len(comm) > 64 or
                type(fd_count) is not int or not 0 < fd_count <= 250000 or not isinstance(nodes, list) or
                len(nodes) > 64 or not nodes or any(not isinstance(node, str) or not device_name.fullmatch(node)
                                 for node in nodes) or
                nodes != sorted(set(nodes)) or fd_count < len(nodes)):
            raise ValueError("GPU process inventory FD-owner fields are invalid")
        owner_pids.append(pid)
    if owner_pids != sorted(set(owner_pids)):
        raise ValueError("GPU process inventory FD-owner PIDs are invalid")


def validate_host_state(state: dict) -> dict:
    """Validate the bounded evidence shape; unknown security state is rejected."""
    _check_no_sensitive_material(state)
    if not isinstance(state, dict) or REQUIRED_STATE_FIELDS - set(state):
        raise ValueError("host-state snapshot is missing required fields")
    if state.get("schema") != STATE_SCHEMA:
        raise ValueError("unsupported host-state schema")
    if not isinstance(state.get("host"), str) or not state["host"].strip():
        raise ValueError("host name is missing")
    if (not isinstance(state.get("boot_id"), str) or
            not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             state["boot_id"])):
        raise ValueError("boot ID is invalid")
    if not isinstance(state.get("kernel_release"), str) or not state["kernel_release"].strip():
        raise ValueError("kernel release is missing")
    if not isinstance(state.get("kernel_vermagic"), str) or not state["kernel_vermagic"].strip():
        raise ValueError("kernel vermagic is missing")
    for key in ("secure_boot_enabled", "module_sig_enforce"):
        if type(state.get(key)) is not bool:
            raise ValueError("security policy is unknown: " + key)
    if state.get("lockdown") not in ("none", "integrity", "confidentiality"):
        raise ValueError("security policy is unknown: lockdown")
    observed_at = state.get("observed_at_utc")
    if not isinstance(observed_at, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", observed_at):
        raise ValueError("observation timestamp must be UTC RFC3339")
    try:
        datetime.fromisoformat(observed_at[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("observation timestamp must be UTC RFC3339") from error
    devices = state.get("active_char_devices")
    if not isinstance(devices, list):
        raise ValueError("active character devices must be a list")
    for item in devices:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str) or
                not item["path"].startswith("/dev/nvidia") or
                type(item.get("major")) is not int or item["major"] < 1 or
                type(item.get("minor")) is not int or item["minor"] < 0):
            raise ValueError("active character device record is invalid")
    if state.get("active_modules_scope") != "all":
        raise ValueError("complete active-module inventory is required")
    for field in ("active_modules", "loaded_nvidia_modules", "char_device_major_names", "gpu_ownership"):
        if not isinstance(state.get(field), list):
            raise ValueError(field + " must be a list")
    module_name = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
    active_names = []
    for item in state["active_modules"]:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str) or
                not module_name.fullmatch(item["name"])):
            raise ValueError("active module record is invalid")
        active_names.append(item["name"])
    if len(active_names) != len(set(active_names)):
        raise ValueError("active module inventory contains duplicate names")
    for name in state["loaded_nvidia_modules"]:
        if not isinstance(name, str) or not module_name.fullmatch(name) or not name.startswith("nvidia"):
            raise ValueError("loaded module record is invalid")
    expected_nvidia_names = [name for name in active_names if name.startswith("nvidia")]
    if state["loaded_nvidia_modules"] != expected_nvidia_names:
        raise ValueError("loaded NVIDIA module inventory differs from complete active-module inventory")
    major_names = []
    for item in state["char_device_major_names"]:
        if (not isinstance(item, dict) or type(item.get("major")) is not int or
                item["major"] < 1 or item["major"] > 4095 or
                not isinstance(item.get("name"), str) or
                not re.fullmatch(r"[A-Za-z0-9_./+-]{1,255}", item["name"])):
            raise ValueError("character-device major record is invalid")
        major_names.append((item["major"], item["name"]))
    if len(major_names) != len(set(major_names)):
        raise ValueError("character-device major inventory contains duplicates")
    for item in state["gpu_ownership"]:
        if (not isinstance(item, dict) or
                not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", item.get("pci", "")) or
                not re.fullmatch(r"[0-9a-f]{4}", item.get("vendor_id", "")) or
                item["vendor_id"] != "10de" or
                not re.fullmatch(r"[0-9a-f]{4}", item.get("device_id", "")) or
                item.get("driver") is not None and not isinstance(item.get("driver"), str)):
            raise ValueError("GPU ownership record is invalid")
        topology = item.get("pci_topology")
        if topology is not None:
            topology_fields = {"pci_ancestors", "link", "iommu_group",
                               "iommu_group_device_count", "nvidia_gpu_bdfs_in_group"}
            if not isinstance(topology, dict) or set(topology) != topology_fields:
                raise ValueError("PCI topology record is invalid")
            ancestors = topology["pci_ancestors"]
            if not isinstance(ancestors, list):
                raise ValueError("PCI topology ancestor list is invalid")
            ancestor_bdfs = []
            for ancestor in ancestors:
                if (not isinstance(ancestor, dict) or
                        set(ancestor) != {"pci", "vendor_id", "device_id", "class", "driver", "acs"} or
                        not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", ancestor.get("pci", "")) or
                        not re.fullmatch(r"[0-9a-f]{4}", ancestor.get("vendor_id", "")) or
                        not re.fullmatch(r"[0-9a-f]{4}", ancestor.get("device_id", "")) or
                        not re.fullmatch(r"[0-9a-f]{6}", ancestor.get("class", "")) or
                        (ancestor.get("driver") is not None and not isinstance(ancestor.get("driver"), str)) or
                        not isinstance(ancestor.get("acs"), list) or
                        any(not isinstance(line, str) or len(line) > 512 or
                            not re.match(r"^ACS(?:Cap|Ctl):", line)
                            for line in ancestor.get("acs", []))):
                    raise ValueError("PCI topology ancestor record is invalid")
                ancestor_bdfs.append(ancestor["pci"])
            if len(ancestor_bdfs) != len(set(ancestor_bdfs)) or item["pci"] in ancestor_bdfs:
                raise ValueError("PCI topology ancestor identities are invalid")
            link = topology["link"]
            link_fields = {"current_link_speed", "current_link_width", "max_link_speed", "max_link_width"}
            if (not isinstance(link, dict) or set(link) != link_fields or
                    any(value is not None and not isinstance(value, str) for value in link.values())):
                raise ValueError("PCI topology link record is invalid")
            group_id = topology["iommu_group"]
            group_count = topology["iommu_group_device_count"]
            group_gpus = topology["nvidia_gpu_bdfs_in_group"]
            if ((group_id is not None and (type(group_id) is not int or group_id < 0)) or
                    (group_count is not None and (type(group_count) is not int or group_count < 0)) or
                    not isinstance(group_gpus, list) or
                    any(not isinstance(bdf, str) or not re.fullmatch(
                        r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", bdf) for bdf in group_gpus) or
                    len(group_gpus) != len(set(group_gpus))):
                raise ValueError("PCI topology IOMMU group record is invalid")
            if group_id is None:
                if group_count is not None or group_gpus:
                    raise ValueError("PCI topology IOMMU group fields are inconsistent")
            elif group_count is None or item["pci"] not in group_gpus:
                raise ValueError("PCI topology IOMMU group record is incomplete")
    if "gpu_process_inventory" in state:
        _validate_gpu_process_inventory(state["gpu_process_inventory"])
    installed = state.get("installed_nvidia_module")
    if (not isinstance(installed, dict) or
            not isinstance(installed.get("version"), str) or not installed["version"].strip() or
            not isinstance(installed.get("signer"), str) or
            not isinstance(installed.get("vermagic"), str) or not installed["vermagic"].strip()):
        raise ValueError("installed NVIDIA module metadata is invalid")
    loaded_version = state.get("loaded_nvidia_module_version")
    if loaded_version is not None and not isinstance(loaded_version, str):
        raise ValueError("loaded NVIDIA module version is invalid")
    mok = state.get("local_module_signing_key_metadata")
    if (not isinstance(mok, dict) or type(mok.get("certificate_present")) is not bool or
            mok.get("certificate_enrolled") not in (True, False, None) or
            mok.get("mok_test_result") not in ("enrolled", "not_enrolled", "unknown") or
            (mok.get("mok_test_result") == "unknown") != (mok.get("certificate_enrolled") is None) or
            (mok.get("mok_test_result") == "enrolled") != (mok.get("certificate_enrolled") is True) or
            (mok.get("mok_test_result") == "not_enrolled") != (mok.get("certificate_enrolled") is False) or
            (not mok.get("certificate_present") and mok.get("mok_test_result") != "unknown")):
        raise ValueError("public MOK certificate metadata is invalid")
    recovery = state.get("driver_recovery_inventory")
    if recovery is not None:
        recovery_fields = {"schema", "package_query_complete", "packages",
                           "module_file_hash_scope", "module_files_on_disk", "nvidia_module_by_kernel",
                           "boot_artifacts", "grub_environment"}
        if (not isinstance(recovery, dict) or set(recovery) != recovery_fields or
                recovery.get("schema") != "pc3-driver-recovery-inventory-v1" or
                recovery.get("package_query_complete") is not True or
                recovery.get("module_file_hash_scope") !=
                "installed_file_on_disk_not_loaded_memory"):
            raise ValueError("driver recovery inventory header is invalid")
        packages = recovery.get("packages")
        if not isinstance(packages, list):
            raise ValueError("driver recovery inventory package list is invalid")
        package_names = []
        package_name_re = re.compile(r"^[A-Za-z0-9+_.:-]{1,255}$")
        package_version_re = re.compile(r"^[A-Za-z0-9+_.:~\-]{1,255}$")
        package_prefixes = ("nvidia-", "libnvidia-", "xserver-xorg-video-nvidia-",
                            "linux-image-", "linux-modules-",
                            "linux-headers-", "linux-firmware")
        package_exact = {"dkms", "shim-signed", "initramfs-tools", "grub-common",
                         "grub2-common", "grub-efi-amd64", "grub-efi-amd64-signed"}
        for package in packages:
            if (not isinstance(package, dict) or set(package) != {"name", "version", "status"} or
                    not isinstance(package.get("name"), str) or
                    not package_name_re.fullmatch(package["name"]) or
                    not isinstance(package.get("version"), str) or
                    not package_version_re.fullmatch(package["version"]) or
                    package.get("status") != "ii"):
                raise ValueError("driver recovery inventory package record is invalid")
            base_name = package["name"].split(":", 1)[0]
            if base_name not in package_exact and not base_name.startswith(package_prefixes):
                raise ValueError("driver recovery inventory package scope is invalid")
            package_names.append(package["name"])
        if package_names != sorted(set(package_names)):
            raise ValueError("driver recovery inventory packages are not unique and sorted")

        module_files = recovery.get("module_files_on_disk")
        if not isinstance(module_files, list):
            raise ValueError("driver recovery inventory module list is invalid")
        module_names = []
        for item in module_files:
            if (not isinstance(item, dict) or set(item) != {
                    "name", "path", "exists", "size_bytes", "sha256", "version", "signer", "vermagic"} or
                    not isinstance(item.get("name"), str) or not module_name.fullmatch(item["name"]) or
                    item["name"] not in state["loaded_nvidia_modules"] or
                    not isinstance(item.get("path"), str) or len(item["path"]) > 4096 or
                    type(item.get("exists")) is not bool or
                    any(not isinstance(item.get(field), str) for field in ("version", "signer", "vermagic"))):
                raise ValueError("driver recovery inventory module record is invalid")
            if item["exists"]:
                if (not item["path"].startswith("/") or
                        type(item.get("size_bytes")) is not int or item["size_bytes"] <= 0 or
                        not isinstance(item.get("sha256"), str) or
                        not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                    raise ValueError("driver recovery inventory module-file digest is invalid")
            elif item.get("size_bytes") is not None or item.get("sha256") is not None:
                raise ValueError("driver recovery inventory missing-module file fields are invalid")
            module_names.append(item["name"])
        if module_names != sorted(set(module_names)) or module_names != sorted(state["loaded_nvidia_modules"]):
            raise ValueError("driver recovery inventory does not cover the loaded NVIDIA module names")

        kernel_modules = recovery.get("nvidia_module_by_kernel")
        if not isinstance(kernel_modules, list):
            raise ValueError("driver recovery inventory per-kernel module list is invalid")
        kernel_releases = []
        for item in kernel_modules:
            if (not isinstance(item, dict) or set(item) != {
                    "kernel_release", "module_present", "path", "size_bytes", "sha256",
                    "version", "signer", "vermagic"} or
                    not isinstance(item.get("kernel_release"), str) or
                    not re.fullmatch(r"[A-Za-z0-9.+_-]{1,255}", item["kernel_release"]) or
                    type(item.get("module_present")) is not bool):
                raise ValueError("driver recovery inventory per-kernel module record is invalid")
            if item["module_present"]:
                if (not isinstance(item.get("path"), str) or
                        not item["path"].startswith("/lib/modules/" + item["kernel_release"] + "/") or
                        type(item.get("size_bytes")) is not int or item["size_bytes"] <= 0 or
                        not isinstance(item.get("sha256"), str) or
                        not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) or
                        not isinstance(item.get("version"), str) or not item["version"].strip() or
                        not isinstance(item.get("signer"), str) or
                        not isinstance(item.get("vermagic"), str) or not item["vermagic"].strip()):
                    raise ValueError("driver recovery inventory per-kernel module file is invalid")
            elif any(item.get(key) is not None for key in
                     ("path", "size_bytes", "sha256", "version", "signer", "vermagic")):
                raise ValueError("driver recovery inventory absent per-kernel module fields are invalid")
            kernel_releases.append(item["kernel_release"])
        if kernel_releases != sorted(set(kernel_releases)):
            raise ValueError("driver recovery inventory kernel releases are not unique and sorted")

        boot_artifacts = recovery.get("boot_artifacts")
        if not isinstance(boot_artifacts, list):
            raise ValueError("driver recovery inventory boot artifact list is invalid")
        artifact_names = []
        for item in boot_artifacts:
            if (not isinstance(item, dict) or set(item) != {"name", "path", "kind", "exists", "size_bytes"} or
                    not isinstance(item.get("name"), str) or
                    not re.fullmatch(r"(?:vmlinuz(?:[-.][A-Za-z0-9.+_-]+)?|initrd\.img(?:[-.][A-Za-z0-9.+_-]+)?)",
                                     item["name"]) or
                    item.get("path") != "/boot/" + item["name"] or
                    item.get("kind") not in ("kernel", "initramfs") or
                    type(item.get("exists")) is not bool or
                    (item["kind"] == "kernel") != item["name"].startswith("vmlinuz")):
                raise ValueError("driver recovery inventory boot artifact record is invalid")
            if item["exists"]:
                if type(item.get("size_bytes")) is not int or item["size_bytes"] <= 0:
                    raise ValueError("driver recovery inventory boot artifact size is invalid")
            elif item.get("size_bytes") is not None:
                raise ValueError("driver recovery inventory missing boot artifact size is invalid")
            artifact_names.append(item["name"])
        if artifact_names != sorted(set(artifact_names)):
            raise ValueError("driver recovery inventory boot artifacts are not unique and sorted")
        expected_kernel_releases = sorted({
            item["name"][len("vmlinuz-"):] for item in boot_artifacts
            if item["kind"] == "kernel" and item["name"].startswith("vmlinuz-")
        })
        if kernel_releases != expected_kernel_releases:
            raise ValueError("driver recovery inventory does not cover versioned boot kernels")

        grub = recovery.get("grub_environment")
        if (not isinstance(grub, dict) or set(grub) != {"available", "saved_entry", "next_entry"} or
                type(grub.get("available")) is not bool or
                any(grub.get(key) is not None and
                    (not isinstance(grub[key], str) or len(grub[key]) > 1024 or "\x00" in grub[key])
                    for key in ("saved_entry", "next_entry"))):
            raise ValueError("driver recovery inventory GRUB environment is invalid")
    return state


def make_report(state: dict, target: str, credential_host: str | None,
                host_key_alias: str = DEFAULT_HOST_KEY_ALIAS,
                transport_mode: str = LEGACY_TRANSPORT_MODE,
                identity_file_basename: str | None = None) -> dict:
    state = validate_host_state(state)
    if state["host"].lower() != "pc3":
        raise ValueError("expected PC3 host identity")
    if transport_mode not in (LEGACY_TRANSPORT_MODE, DIRECT_TRANSPORT_MODE):
        raise ValueError("unsupported PC3 host-state transport mode")
    if transport_mode == DIRECT_TRANSPORT_MODE:
        if target != DEFAULT_TARGET or host_key_alias != DEFAULT_HOST_KEY_ALIAS or credential_host is not None:
            raise ValueError("direct collection is restricted to the pinned PC3 SSH route")
        if (identity_file_basename is not None and
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", identity_file_basename)):
            raise ValueError("direct SSH identity metadata is invalid")
    else:
        if identity_file_basename is not None:
            raise ValueError("explicit SSH identity metadata is valid only for direct PC3 collection")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+", target):
            raise ValueError("PC3 target must be a user@host SSH alias")
        if not isinstance(credential_host, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", credential_host):
            raise ValueError("credential host must be a configured SSH alias")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", host_key_alias):
            raise ValueError("host-key alias must be a configured SSH alias")
    report = dict(state)
    report["collector_metadata"] = {
        "schema": COLLECTOR_SCHEMA,
        "qualification": "read-only-host-inventory",
        "local_collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "remote_script_sha256": hashlib.sha256(REMOTE_HOST_STATE_SCRIPT.encode("utf-8")).hexdigest(),
        "transport": {"mode": transport_mode, "target": target,
                      "ssh_gateway_alias": credential_host,
                      "host_key_alias": host_key_alias,
                      **({"identity_file_basename": identity_file_basename}
                         if identity_file_basename is not None else {}),
                      "sudo_value_logged": False, "sudo_value_persisted": False},
    }
    return report


def validate_collection_report(report: dict) -> dict:
    """Validate the snapshot and prove it came from this pinned PC3 collector."""
    state = validate_host_state(report)
    if state["host"].lower() != "pc3":
        raise ValueError("expected PC3 host identity")
    metadata = report.get("collector_metadata")
    transport = metadata.get("transport") if isinstance(metadata, dict) else None
    digest = re.compile(r"^[0-9a-f]{64}$")
    if (not isinstance(metadata, dict) or
            metadata.get("schema") != COLLECTOR_SCHEMA or
            metadata.get("qualification") != "read-only-host-inventory" or
            metadata.get("local_collector_sha256") !=
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest() or
            metadata.get("remote_script_sha256") !=
            hashlib.sha256(REMOTE_HOST_STATE_SCRIPT.encode("utf-8")).hexdigest() or
            not isinstance(transport, dict) or
            transport.get("target") != DEFAULT_TARGET or
            transport.get("host_key_alias") != DEFAULT_HOST_KEY_ALIAS or
            transport.get("sudo_value_logged") is not False or
            transport.get("sudo_value_persisted") is not False):
        raise ValueError("collector provenance is missing, stale, or mismatched")
    mode = transport.get("mode")
    identity_basename = transport.get("identity_file_basename")
    if (identity_basename is not None and
            (mode != DIRECT_TRANSPORT_MODE or
             not isinstance(identity_basename, str) or
             not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", identity_basename))):
        raise ValueError("collector SSH identity provenance is invalid")
    if ((mode == LEGACY_TRANSPORT_MODE and
         transport.get("ssh_gateway_alias") != DEFAULT_CREDENTIAL_HOST) or
        (mode == DIRECT_TRANSPORT_MODE and transport.get("ssh_gateway_alias") is not None) or
        mode not in (LEGACY_TRANSPORT_MODE, DIRECT_TRANSPORT_MODE)):
        raise ValueError("collector transport provenance is missing, stale, or mismatched")
    for field in ("local_collector_sha256", "remote_script_sha256"):
        if not digest.fullmatch(metadata[field]):
            raise ValueError("collector provenance digest is invalid")
    return report


def write_report(path: Path, report: dict) -> None:
    path = Path(path)
    evidence_root = (ROOT / "evidence").resolve(strict=True)
    try:
        path.parent.resolve(strict=True).relative_to(evidence_root)
    except (OSError, ValueError) as error:
        raise ValueError("host-state report must be written inside the private evidence tree") from error
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("host-state report destination is not a regular file")
        stream.write(payload)


def _remote_command() -> str:
    return "sudo -S -p '' python3 -c " + shlex.quote(REMOTE_HOST_STATE_SCRIPT)


def _direct_remote_command() -> str:
    return "sudo -n python3 -c " + shlex.quote(REMOTE_HOST_STATE_SCRIPT)


def direct_pc3_ssh_base(target: str = DEFAULT_TARGET,
                        host_key_alias: str = DEFAULT_HOST_KEY_ALIAS,
                        identity_file: Path | str | None = None) -> list[str]:
    """Build a key-only SSH command pinned to PC3; never consults another host."""
    argv = pc3.pc3_direct_ssh_base(target, host_key_alias)
    if identity_file is None:
        return argv
    identity = validate_direct_identity_file(identity_file)
    return argv[:1] + ["-i", str(identity), "-oIdentitiesOnly=yes"] + argv[1:]


def validate_direct_identity_file(identity_file: Path | str) -> Path:
    """Accept only a private regular key directly inside this user's ~/.ssh."""
    candidate = Path(identity_file)
    if not candidate.is_absolute():
        raise ValueError("PC3 SSH identity path must be absolute")
    ssh_dir = Path.home() / ".ssh"
    try:
        ssh_dir_info = ssh_dir.lstat()
        info = candidate.lstat()
        resolved_ssh_dir = ssh_dir.resolve(strict=True)
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except OSError:
        raise ValueError("PC3 SSH identity file or .ssh directory is unavailable") from None
    if (stat.S_ISLNK(ssh_dir_info.st_mode) or not stat.S_ISDIR(ssh_dir_info.st_mode) or
            resolved_parent != resolved_ssh_dir or
            stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or
            info.st_uid != os.geteuid() or (stat.S_IMODE(info.st_mode) & 0o077) != 0 or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", resolved_candidate.name)):
        raise ValueError("PC3 SSH identity must be a private regular file owned by this user in ~/.ssh")
    return resolved_candidate


def collect_host_state(target: str = DEFAULT_TARGET,
                       credential_host: str = DEFAULT_CREDENTIAL_HOST,
                       credential_file: str = DEFAULT_CREDENTIAL_FILE,
                       host_key_alias: str = DEFAULT_HOST_KEY_ALIAS,
                       timeout: int = 90) -> dict:
    secret = pc3.fetch_pc3_sudo_secret(credential_host, credential_file)
    try:
        argv = pc3.pc3_ssh_base(target, host_key_alias) + [_remote_command()]
        result = subprocess.run(argv, input=pc3.sudo_auth_stdin(secret),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only PC3 host-state SSH operation failed") from None
    finally:
        secret = None
    if result.returncode != 0:
        error_hash = hashlib.sha256(result.stderr).hexdigest()
        raise RuntimeError("read-only PC3 host-state command failed; stderr sha256=" + error_hash)
    return parse_remote_json(result.stdout)


def collect_host_state_direct(target: str = DEFAULT_TARGET,
                              host_key_alias: str = DEFAULT_HOST_KEY_ALIAS,
                              timeout: int = 90,
                              identity_file: Path | str | None = None) -> dict:
    """Collect through PC3's configured SSH key and non-interactive sudo only."""
    argv = direct_pc3_ssh_base(target, host_key_alias, identity_file) + [_direct_remote_command()]
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("direct read-only PC3 host-state SSH operation failed") from None
    if result.returncode != 0:
        error_hash = hashlib.sha256(result.stderr).hexdigest()
        raise RuntimeError("direct read-only PC3 host-state command failed; stderr sha256=" + error_hash)
    return parse_remote_json(result.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--host-key-alias", default=DEFAULT_HOST_KEY_ALIAS)
    parser.add_argument("--credential-host",
                        help="legacy sudo-credential source SSH alias (default: configured legacy host)")
    parser.add_argument("--credential-file",
                        help="legacy sudo-credential file path on the configured credential host")
    parser.add_argument("--direct-pc3", action="store_true",
                        help="use only the local SSH key to PC3 and sudo -n; never contact PC6")
    parser.add_argument("--identity-file", type=Path,
                        help="optional private key inside ~/.ssh for direct PC3-only authentication")
    parser.add_argument("--output", required=True, type=Path,
                        help="create a fresh mode-0600 snapshot; existing files are never overwritten")
    args = parser.parse_args(argv)
    try:
        if args.direct_pc3:
            if args.target != DEFAULT_TARGET or args.host_key_alias != DEFAULT_HOST_KEY_ALIAS:
                raise ValueError("--direct-pc3 requires the pinned pc3@pc3 target and pc3 host-key alias")
            if args.credential_host is not None or args.credential_file is not None:
                raise ValueError("--direct-pc3 cannot be combined with legacy credential-host options")
            identity = (validate_direct_identity_file(args.identity_file)
                        if args.identity_file is not None else None)
            state = collect_host_state_direct(args.target, args.host_key_alias,
                                              identity_file=identity)
            report = make_report(state, args.target, None, args.host_key_alias,
                                 transport_mode=DIRECT_TRANSPORT_MODE,
                                 identity_file_basename=identity.name if identity is not None else None)
        else:
            if args.identity_file is not None:
                raise ValueError("--identity-file requires --direct-pc3")
            credential_host = args.credential_host or DEFAULT_CREDENTIAL_HOST
            credential_file = args.credential_file or DEFAULT_CREDENTIAL_FILE
            state = collect_host_state(args.target, credential_host,
                                       credential_file, args.host_key_alias)
            report = make_report(state, args.target, credential_host, args.host_key_alias)
        write_report(args.output, report)
    except (OSError, ValueError, RuntimeError) as error:
        print("PC3 read-only host-state collection failed: " + str(error), file=sys.stderr)
        return 2
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"schema": COLLECTOR_SCHEMA, "status": "collected",
                      "host": report["host"], "observed_at_utc": report["observed_at_utc"],
                      "output": str(args.output.resolve()), "sha256": digest,
                      "qualification": "read-only-host-inventory"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
