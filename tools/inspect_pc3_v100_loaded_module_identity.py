#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only comparison of the loaded PC3 R580 module and its on-disk ELF build-id."""
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
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_AUDIT_PATH = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
DEFAULT_OBJECT = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-kernel.o_binary"
EXPECTED_OBJECT_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
RM_FUNCTION_NAMES = ("_nv031364rm", "_nv031399rm", "_nv049612rm")

GUEST_PROBE = r'''import csv,hashlib,json,os,re,shutil,stat,struct,subprocess
from pathlib import Path

EXPECTED_MODULES = ("nvidia", "nvidia_uvm", "nvidia_modeset", "nvidia_drm")
MAX_PROC_ENTRIES = 16384
MAX_DEVICE_OWNERS = 2048

def run(argv, timeout=60, pass_fds=()):
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False, pass_fds=pass_fds,
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
    except (OSError, subprocess.TimeoutExpired):
        return None

def parse_note(data):
    offset = 0
    ids = []
    while offset < len(data):
        if not any(data[offset:]):
            break
        if len(data) - offset < 12:
            raise ValueError("truncated ELF note header")
        namesz, descsz, note_type = struct.unpack_from("<III", data, offset)
        offset += 12
        name_end = offset + namesz
        desc_start = offset + ((namesz + 3) & ~3)
        desc_end = desc_start + descsz
        next_note = desc_start + ((descsz + 3) & ~3)
        if name_end > len(data) or desc_end > len(data) or next_note > len(data):
            raise ValueError("truncated ELF note payload")
        name = data[offset:name_end]
        desc = data[desc_start:desc_end]
        if name.rstrip(b"\0") == b"GNU" and note_type == 3:
            ids.append(desc.hex())
        offset = next_note
    if len(ids) != 1 or not ids[0]:
        raise ValueError("expected one GNU build-id note")
    return ids[0]

def elf_function_hashes(data, names):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise ValueError("expected ELF64 little-endian object")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    shoff, shentsize, shnum, shstrndx = header[5], header[10], header[11], header[12]
    if shentsize != 64 or not shnum or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
        raise ValueError("invalid ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
                for i in range(shnum)]
    def slice_checked(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("ELF section range is outside file")
        return data[offset:offset + size]
    names_blob = slice_checked(sections[shstrndx][4], sections[shstrndx][5])
    def string_at(blob, offset):
        if offset < 0 or offset >= len(blob):
            raise ValueError("ELF string offset is invalid")
        end = blob.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF string")
        return blob[offset:end].decode("utf-8", "strict")
    section_names = [string_at(names_blob, section[0]) if section[0] else ""
                     for section in sections]
    wanted = set(names)
    found = {}
    for index, section in enumerate(sections):
        if section[1] != 2:  # SHT_SYMTAB
            continue
        strings_index, entry_size = section[6], section[9]
        if strings_index >= shnum or entry_size != 24 or section[5] % entry_size:
            raise ValueError("invalid ELF symbol table")
        strings = slice_checked(sections[strings_index][4], sections[strings_index][5])
        symbols = slice_checked(section[4], section[5])
        for offset in range(0, len(symbols), entry_size):
            name_offset, info, _other, target_index, value, size = struct.unpack_from(
                "<IBBHQQ", symbols, offset)
            if not name_offset:
                continue
            name = string_at(strings, name_offset)
            if name not in wanted:
                continue
            if name in found or info & 0x0f != 2 or target_index >= shnum or size <= 0:
                raise ValueError("requested ELF function is duplicate or malformed")
            target = sections[target_index]
            if target[1] == 8 or not target[2] & 4:  # SHT_NOBITS / SHF_EXECINSTR
                raise ValueError("requested ELF function is not in executable bytes")
            if value < target[3]:
                raise ValueError("ELF function address precedes its section")
            relative_offset = value - target[3]
            if relative_offset + size > target[5]:
                raise ValueError("ELF function exceeds its executable section")
            file_offset = target[4] + relative_offset
            code = slice_checked(file_offset, size)
            found[name] = {"size":size, "section":section_names[target_index],
                           "sha256":hashlib.sha256(code).hexdigest()}
    if set(found) != wanted:
        raise ValueError("requested ELF function symbol is missing")
    return found

def one_gpu():
    result = run(["nvidia-smi", "--query-gpu=name,pci.bus_id,driver_version", "--format=csv,noheader"])
    if result is None or result.returncode != 0:
        raise RuntimeError("GPU identity query failed")
    rows = list(csv.reader(result.stdout.decode("utf-8", "replace").splitlines()))
    if len(rows) != 1 or len(rows[0]) != 3:
        raise RuntimeError("expected exactly one PC3 V100 guest GPU")
    return {"name":rows[0][0].strip(), "pci":rows[0][1].strip(),
            "driver_version":rows[0][2].strip()}

def module_usage():
    proc_refs = {}
    try:
        for line in Path("/proc/modules").read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[0] not in EXPECTED_MODULES:
                continue
            proc_refs[fields[0]] = int(fields[2])
    except (OSError, UnicodeError, ValueError):
        raise RuntimeError("kernel module reference inventory is unreadable")
    records = []
    for name in EXPECTED_MODULES:
        module_path = Path("/sys/module") / name
        if not module_path.is_dir():
            records.append({"name":name, "loaded":False, "proc_refcount":None,
                "sysfs_refcount":None, "sysfs_holders":[]})
            continue
        try:
            proc_refcount = proc_refs.get(name)
            raw_refcount = (module_path / "refcnt").read_text(encoding="ascii").strip()
            sysfs_refcount = int(raw_refcount)
            holders = sorted(item.name for item in (module_path / "holders").iterdir())
        except (OSError, UnicodeError, ValueError):
            raise RuntimeError("loaded module use or holder state is unreadable")
        if sysfs_refcount < 0 or (proc_refcount is not None and proc_refcount < 0):
            raise RuntimeError("loaded module reference count is invalid")
        records.append({"name":name, "loaded":True, "proc_refcount":proc_refcount,
            "sysfs_refcount":sysfs_refcount, "sysfs_holders":holders})
    return {"modules":records,
        "all_expected_loaded":all(item["loaded"] for item in records)}

def nvidia_device_users():
    owners = []
    fd_total = 0
    scanned = 0
    complete = True
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        scanned += 1
        if scanned > MAX_PROC_ENTRIES:
            complete = False
            break
        try:
            comm = (process / "comm").read_text(encoding="utf-8", errors="replace").strip()[:64]
        except OSError:
            if process.exists():
                complete = False
            continue
        fd_dir = process / "fd"
        try:
            fd_entries = list(fd_dir.iterdir())
        except OSError:
            if process.exists():
                complete = False
            continue
        nodes = {}
        for fd_entry in fd_entries:
            try:
                target = os.readlink(fd_entry)
            except OSError:
                if process.exists() and fd_entry.exists():
                    complete = False
                continue
            if not target.startswith("/dev/"):
                continue
            relative = target[5:].removesuffix(" (deleted)")
            if not (relative in ("nvidiactl", "nvidia-modeset", "nvidia-uvm",
                                "nvidia-uvm-tools") or
                    re.fullmatch(r"nvidia[0-9]+", relative) or
                    re.fullmatch(r"nvidia-caps/[A-Za-z0-9_.-]+", relative)):
                continue
            try:
                metadata = os.stat(fd_entry)
            except OSError:
                complete = False
                continue
            if not stat.S_ISCHR(metadata.st_mode):
                continue
            nodes[relative] = nodes.get(relative, 0) + 1
        if nodes:
            if len(owners) >= MAX_DEVICE_OWNERS:
                complete = False
                break
            count = sum(nodes.values())
            fd_total += count
            owners.append({"pid":int(process.name), "comm":comm,
                "fd_count":count, "nodes":sorted(nodes)})
    owners.sort(key=lambda item:item["pid"])
    return {"proc_scan_complete":complete, "proc_processes_scanned":scanned,
        "owner_process_count":len(owners), "fd_count":fd_total, "owners":owners}

def compute_processes():
    result = run(["nvidia-smi", "--query-compute-apps=pid", "--format=csv,noheader"], timeout=20)
    if result is None or result.returncode != 0:
        return {"query_complete":False, "pids":[]}
    lines = [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines()
             if line.strip()]
    pids = []
    for line in lines:
        if line.lower() == "no running processes found":
            continue
        if not re.fullmatch(r"[0-9]+", line):
            return {"query_complete":False, "pids":[]}
        pids.append(int(line))
    return {"query_complete":True, "pids":sorted(set(pids))}

report = {"schema":"nvidia-hybrid-pc3-v100-loaded-module-identity-v3",
          "hostname":os.uname().nodename, "kernel_release":os.uname().release,
          "effective_uid":os.geteuid(), "status":"preflight_failed",
          "execution_scope":{"read_only":True, "experimental_module_loaded":False,
              "stock_driver_changed":False, "pci_binding_changed":False,
              "vm_management_issued":False}}
try:
    if os.geteuid() != 0 or os.uname().nodename.split(".")[0] != "pc3-v100":
        raise RuntimeError("unexpected PC3 V100 guest identity or privilege")
    report["module_usage"] = module_usage()
    report["nvidia_device_fds"] = nvidia_device_users()
    report["compute_processes"] = compute_processes()
    devices = report["nvidia_device_fds"]
    compute = report["compute_processes"]
    report["quiescent_observed"] = (
        report["module_usage"]["all_expected_loaded"] is True and
        devices["proc_scan_complete"] is True and devices["owner_process_count"] == 0 and
        devices["fd_count"] == 0 and compute["query_complete"] is True and not compute["pids"])
    gpu = one_gpu()
    report["gpu"] = gpu
    module_dir = Path("/sys/module/nvidia")
    if not module_dir.is_dir():
        raise RuntimeError("stock nvidia module is not loaded")
    version_cmd = run(["modinfo", "-F", "version", "nvidia"])
    path_cmd = run(["modinfo", "-n", "nvidia"])
    if version_cmd is None or version_cmd.returncode or path_cmd is None or path_cmd.returncode:
        raise RuntimeError("nvidia module metadata lookup failed")
    module_version = version_cmd.stdout.decode("utf-8", "replace").strip()
    module_path = path_cmd.stdout.decode("utf-8", "replace").strip()
    if not module_version or module_version != gpu["driver_version"] or not module_path.endswith(".zst"):
        raise RuntimeError("loaded driver version or module layout does not match pinned expectation")
    report["module"] = {"name":"nvidia", "version":module_version,
                         "on_disk_path":module_path, "loaded":True}
    zstd, readelf = shutil.which("zstd"), shutil.which("readelf")
    if not zstd or not readelf:
        raise RuntimeError("zstd or readelf is unavailable")
    decompressed = run([zstd, "-dc", "--", module_path], timeout=90)
    if decompressed is None or decompressed.returncode:
        raise RuntimeError("on-disk module decompression failed")
    function_names = ("_nv031364rm", "_nv031399rm", "_nv049612rm")
    function_hashes = elf_function_hashes(decompressed.stdout, function_names)
    report["rm_function_hashes"] = {name:{"size":value["size"], "sha256":value["sha256"]}
        for name, value in function_hashes.items()}
    fd = os.memfd_create("pc3-loaded-nvidia-module-identity", 0)
    try:
        view = memoryview(decompressed.stdout)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        disk_elf_path = "/proc/self/fd/" + str(fd)
        notes = run([readelf, "-nW", disk_elf_path], timeout=30, pass_fds=(fd,))
        if notes is None or notes.returncode:
            raise RuntimeError("readelf could not inspect the on-disk module notes")
        matches = re.findall(r"Build ID: ([0-9a-fA-F]+)", notes.stdout.decode("utf-8", "replace"))
        if len(matches) != 1:
            raise RuntimeError("on-disk module has no readable GNU build-id")
        disk_build_id = matches[0].lower()
    finally:
        os.close(fd)
    loaded_note_path = module_dir / "notes/.note.gnu.build-id"
    try:
        loaded_note = loaded_note_path.read_bytes()
        loaded_build_id = parse_note(loaded_note)
        loaded_note_error = None
    except (OSError, ValueError) as exc:
        loaded_note = b""
        loaded_build_id = None
        loaded_note_error = type(exc).__name__
    report["on_disk_module"] = {"decompressed_bytes":len(decompressed.stdout),
        "decompressed_sha256":hashlib.sha256(decompressed.stdout).hexdigest(),
        "gnu_build_id":disk_build_id}
    report["loaded_module"] = {"sysfs_build_id_note_path":str(loaded_note_path),
        "sysfs_build_id_note_readable":loaded_build_id is not None,
        "sysfs_build_id_note_sha256":hashlib.sha256(loaded_note).hexdigest() if loaded_note else None,
        "gnu_build_id":loaded_build_id, "note_error_class":loaded_note_error}
    report["build_id_match"] = loaded_build_id == disk_build_id if loaded_build_id else None
    report["interpretation"] = (
        "Matching GNU build IDs tie the loaded module note to the on-disk R580 module build. "
        "A build-id match does not prove every loaded text/data byte is identical or establish "
        "the identity of a separate embedded nv-kernel.o_binary object. The module-use scan is "
        "a point observation; quiescence does not prove an unload, reinsert, or VM recovery path."
        if report["build_id_match"] else
        "The loaded-module build ID could not be matched to the on-disk module; exact loaded "
        "binary identity remains unresolved. The module-use scan is a point observation and "
        "does not prove an unload, reinsert, or VM recovery path."
    )
    report["status"] = "observed"
except Exception as exc:
    report["error_class"] = type(exc).__name__
    report["error_detail"] = str(exc)[:180]
    report["status"] = "preflight_failed"
print(json.dumps(report, sort_keys=True))
'''


def parse_gnu_build_id_note(data: bytes) -> str:
    """Extract exactly one GNU type-3 ELF note, using four-byte note alignment."""
    offset = 0
    ids: list[str] = []
    while offset < len(data):
        if not any(data[offset:]):
            break
        if len(data) - offset < 12:
            raise ValueError("truncated ELF note header")
        namesz, descsz, note_type = struct.unpack_from("<III", data, offset)
        offset += 12
        name_end = offset + namesz
        desc_start = offset + ((namesz + 3) & ~3)
        desc_end = desc_start + descsz
        next_note = desc_start + ((descsz + 3) & ~3)
        if name_end > len(data) or desc_end > len(data) or next_note > len(data):
            raise ValueError("truncated ELF note payload")
        name = data[offset:name_end]
        if name.rstrip(b"\0") == b"GNU" and note_type == 3:
            ids.append(data[desc_start:desc_end].hex())
        offset = next_note
    if len(ids) != 1 or not ids[0]:
        raise ValueError("expected one GNU build-id note")
    return ids[0]


def compare_build_id_notes(loaded_note: bytes, disk_note: bytes) -> dict[str, object]:
    loaded = parse_gnu_build_id_note(loaded_note)
    disk = parse_gnu_build_id_note(disk_note)
    return {"loaded_build_id": loaded, "disk_build_id": disk,
            "build_id_match": loaded == disk}


def elf_function_hashes(data: bytes, names: list[str] | tuple[str, ...]) -> dict[str, dict[str, object]]:
    """Hash exact bytes for named ELF64 little-endian STT_FUNC symbols."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise ValueError("expected ELF64 little-endian object")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    shoff, shentsize, shnum, shstrndx = header[5], header[10], header[11], header[12]
    if shentsize != 64 or not shnum or shstrndx >= shnum or shoff + shnum * shentsize > len(data):
        raise ValueError("invalid ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
                for i in range(shnum)]

    def slice_checked(offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("ELF section range is outside file")
        return data[offset:offset + size]

    names_blob = slice_checked(sections[shstrndx][4], sections[shstrndx][5])

    def string_at(blob: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(blob):
            raise ValueError("ELF string offset is invalid")
        end = blob.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF string")
        return blob[offset:end].decode("utf-8", "strict")

    section_names = [string_at(names_blob, section[0]) if section[0] else ""
                     for section in sections]
    wanted = set(names)
    if not wanted or any(not isinstance(name, str) or not name for name in wanted):
        raise ValueError("requested ELF function names are invalid")
    found: dict[str, dict[str, object]] = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        strings_index, entry_size = section[6], section[9]
        if strings_index >= shnum or entry_size != 24 or section[5] % entry_size:
            raise ValueError("invalid ELF symbol table")
        strings = slice_checked(sections[strings_index][4], sections[strings_index][5])
        symbols = slice_checked(section[4], section[5])
        for offset in range(0, len(symbols), entry_size):
            name_offset, info, _other, target_index, value, size = struct.unpack_from(
                "<IBBHQQ", symbols, offset)
            if not name_offset:
                continue
            name = string_at(strings, name_offset)
            if name not in wanted:
                continue
            if name in found or info & 0x0F != 2 or target_index >= shnum or size <= 0:
                raise ValueError("requested ELF function is duplicate or malformed")
            target = sections[target_index]
            if target[1] == 8 or not target[2] & 4:  # SHT_NOBITS / SHF_EXECINSTR
                raise ValueError("requested ELF function is not in executable bytes")
            if value < target[3]:
                raise ValueError("ELF function address precedes its section")
            relative_offset = value - target[3]
            if relative_offset + size > target[5]:
                raise ValueError("ELF function exceeds its executable section")
            code = slice_checked(target[4] + relative_offset, size)
            found[name] = {"size": size, "section": section_names[target_index],
                           "sha256": hashlib.sha256(code).hexdigest()}
    if set(found) != wanted:
        raise ValueError("requested ELF function symbol is missing")
    return found


def compare_function_code_hashes(expected: dict, observed: dict) -> dict[str, object]:
    """Compare per-function byte hashes and sizes without exposing code bytes."""
    if not isinstance(expected, dict) or not expected or not isinstance(observed, dict):
        raise ValueError("function hash maps are malformed")
    functions: dict[str, dict[str, object]] = {}
    for name, reference in expected.items():
        candidate = observed.get(name)
        if (not isinstance(reference, dict) or not isinstance(candidate, dict) or
                not isinstance(reference.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) or
                not isinstance(candidate.get("sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", candidate["sha256"]) or
                not isinstance(reference.get("size"), int) or reference["size"] <= 0 or
                not isinstance(candidate.get("size"), int) or candidate["size"] <= 0):
            raise ValueError("function hash entry is missing or malformed")
        functions[name] = {
            "expected_size": reference["size"],
            "observed_size": candidate["size"],
            "expected_sha256": reference["sha256"],
            "observed_sha256": candidate["sha256"],
            "match": reference["size"] == candidate["size"] and reference["sha256"] == candidate["sha256"],
        }
    return {"functions": functions, "all_match": set(expected) == set(observed) and
            all(item["match"] for item in functions.values())}


def load_capability_audit():
    spec = importlib.util.spec_from_file_location(
        "pc3_v100_trace_capability_audit", CAPABILITY_AUDIT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 transport helper could not be imported")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_reference_tool(audit):
    return audit.load_reference_tool()


def write_private_new(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def validate_guest_report(report: object) -> dict:
    if (not isinstance(report, dict) or
            report.get("schema") not in ("nvidia-hybrid-pc3-v100-loaded-module-identity-v1",
                                          "nvidia-hybrid-pc3-v100-loaded-module-identity-v2",
                                          "nvidia-hybrid-pc3-v100-loaded-module-identity-v3") or
            report.get("status") != "observed" or
            report.get("hostname") != "pc3-v100" or
            report.get("effective_uid") != 0):
        raise ValueError("wrong V100 guest identity or incomplete module observation")
    scope = report.get("execution_scope")
    gpu = report.get("gpu")
    module = report.get("module")
    loaded = report.get("loaded_module")
    disk = report.get("on_disk_module")
    if (not isinstance(scope, dict) or scope.get("read_only") is not True or
            any(scope.get(key) is not False for key in
                ("experimental_module_loaded", "stock_driver_changed", "pci_binding_changed", "vm_management_issued"))):
        raise ValueError("guest operation scope does not prove read-only inspection")
    if (not isinstance(gpu, dict) or gpu.get("name") != "Tesla V100-SXM2-16GB" or
            gpu.get("pci") != "00000000:00:05.0" or gpu.get("driver_version") != "580.178.04" or
            report.get("kernel_release") != "6.8.0-147-generic" or
            not isinstance(module, dict) or module.get("version") != "580.178.04" or
            module.get("loaded") is not True or
            not isinstance(loaded, dict) or not isinstance(disk, dict) or
            "build_id_match" not in report or
            report.get("build_id_match") not in (True, False, None)):
        raise ValueError("R580 V100 module or build-id observation is malformed")
    disk_id = disk.get("gnu_build_id")
    loaded_id = loaded.get("gnu_build_id")
    if (not isinstance(disk_id, str) or not re.fullmatch(r"[0-9a-f]{16,128}", disk_id) or
            not isinstance(disk.get("decompressed_sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", disk["decompressed_sha256"])):
        raise ValueError("on-disk module hash or GNU build-id is malformed")
    if loaded_id is not None and (not isinstance(loaded_id, str) or
                                  not re.fullmatch(r"[0-9a-f]{16,128}", loaded_id)):
        raise ValueError("loaded module GNU build-id is malformed")
    if report["build_id_match"] is True and loaded_id != disk_id:
        raise ValueError("build-id match flag contradicts the observed identifiers")
    if report["build_id_match"] is False and loaded_id == disk_id:
        raise ValueError("build-id mismatch flag contradicts the observed identifiers")
    if report["schema"].endswith(("-v2", "-v3")):
        functions = report.get("rm_function_hashes")
        if not isinstance(functions, dict) or set(functions) != set(RM_FUNCTION_NAMES):
            raise ValueError("guest RM function hash map is incomplete")
        for name, entry in functions.items():
            if (not isinstance(entry, dict) or not isinstance(entry.get("size"), int) or
                    entry["size"] <= 0 or not isinstance(entry.get("sha256"), str) or
                    not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                raise ValueError("guest RM function hash entry is malformed")
    if report["schema"].endswith("-v3"):
        expected_modules = ("nvidia", "nvidia_uvm", "nvidia_modeset", "nvidia_drm")
        usage = report.get("module_usage")
        devices = report.get("nvidia_device_fds")
        compute = report.get("compute_processes")
        if (not isinstance(usage, dict) or not isinstance(usage.get("modules"), list) or
                len(usage["modules"]) != len(expected_modules) or
                usage.get("all_expected_loaded") not in (True, False)):
            raise ValueError("guest module-use inventory is malformed")
        normalized_modules = []
        for item in usage["modules"]:
            if (not isinstance(item, dict) or
                    set(item) != {"name", "loaded", "proc_refcount", "sysfs_refcount", "sysfs_holders"} or
                    item.get("name") not in expected_modules or type(item.get("loaded")) is not bool or
                    not isinstance(item.get("sysfs_holders"), list) or
                    item["sysfs_holders"] != sorted(set(item["sysfs_holders"])) or
                    any(not isinstance(holder, str) or not re.fullmatch(r"[A-Za-z0-9_]+", holder)
                        for holder in item["sysfs_holders"])):
                raise ValueError("guest module-use record is malformed")
            for field in ("proc_refcount", "sysfs_refcount"):
                value = item[field]
                if value is not None and (type(value) is not int or value < 0):
                    raise ValueError("guest module-use reference count is malformed")
            if item["loaded"] != (item["sysfs_refcount"] is not None):
                raise ValueError("guest module-use loaded state contradicts sysfs")
            normalized_modules.append(item["name"])
        if (tuple(normalized_modules) != expected_modules or
                usage["all_expected_loaded"] != all(item["loaded"] for item in usage["modules"])):
            raise ValueError("guest module-use summary contradicts its records")
        if (not isinstance(devices, dict) or
                set(devices) != {"proc_scan_complete", "proc_processes_scanned",
                                 "owner_process_count", "fd_count", "owners"} or
                type(devices.get("proc_scan_complete")) is not bool or
                any(type(devices.get(field)) is not int or devices[field] < 0 for field in
                    ("proc_processes_scanned", "owner_process_count", "fd_count")) or
                not isinstance(devices.get("owners"), list) or
                devices["owner_process_count"] != len(devices["owners"])):
            raise ValueError("NVIDIA device-FD inventory is malformed")
        total_fds = 0
        pids = []
        for owner in devices["owners"]:
            if (not isinstance(owner, dict) or set(owner) != {"pid", "comm", "fd_count", "nodes"} or
                    type(owner.get("pid")) is not int or owner["pid"] <= 0 or
                    not isinstance(owner.get("comm"), str) or not owner["comm"] or
                    type(owner.get("fd_count")) is not int or owner["fd_count"] <= 0 or
                    not isinstance(owner.get("nodes"), list) or not owner["nodes"] or
                    owner["nodes"] != sorted(set(owner["nodes"])) or
                    any(not isinstance(node, str) or not re.fullmatch(
                        r"(?:nvidia[0-9]+|nvidiactl|nvidia-modeset|nvidia-uvm(?:-tools)?|nvidia-caps/[A-Za-z0-9_.-]+)", node)
                        for node in owner["nodes"])):
                raise ValueError("NVIDIA device-FD owner record is malformed")
            pids.append(owner["pid"])
            total_fds += owner["fd_count"]
        if (pids != sorted(set(pids)) or total_fds != devices["fd_count"]):
            raise ValueError("NVIDIA device-FD summary contradicts its owners")
        if (not isinstance(compute, dict) or set(compute) != {"query_complete", "pids"} or
                type(compute.get("query_complete")) is not bool or
                not isinstance(compute.get("pids"), list) or
                any(type(pid) is not int or pid <= 0 for pid in compute["pids"]) or
                compute["pids"] != sorted(set(compute["pids"]))):
            raise ValueError("NVIDIA compute-process inventory is malformed")
        expected_quiescence = (usage["all_expected_loaded"] is True and
            devices["proc_scan_complete"] is True and devices["owner_process_count"] == 0 and
            devices["fd_count"] == 0 and compute["query_complete"] is True and not compute["pids"])
        if report.get("quiescent_observed") is not expected_quiescence:
            raise ValueError("guest quiescence summary contradicts the observed process and module-use inventory")
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
    started = datetime.now(timezone.utc)
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-v100-loaded-module-identity-transport-v1",
        "started_utc": started.isoformat(timespec="seconds"),
        "target": args.target,
        "host_key_alias": args.host_key_alias,
        "credential_host": args.credential_host,
        "credential_file": args.credential_file,
        "status": "failed",
        "read_only_requested": True,
        "probe_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    try:
        audit = load_capability_audit()
        reference = load_reference_tool(audit)
        secret = reference.fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        wrapper = audit.remote_root_script(
            GUEST_PROBE, reference.EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
            reference.DEFAULT_GUEST_KEY, reference.DEFAULT_GUEST_KNOWN_HOSTS,
            read_only=True, trace_event_definition_write_attempted=False,
        )
        remote = "sudo -S -p '' python3 -c " + shlex.quote(wrapper)
        result = subprocess.run(
            reference.pc3_ssh_base(args.target, args.host_key_alias) + [remote],
            input=reference.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=180, check=False,
            env=audit.pc3_ssh_environment(os.environ),
        )
        report["pc3_ssh_returncode"] = result.returncode
        report["remote_stdout_bytes"] = len(result.stdout)
        report["remote_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        report["remote_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        if result.returncode:
            report["failure_stage"] = "pc3_or_guest_transport"
        else:
            remote_report = json.loads(result.stdout.decode("utf-8", "strict"))
            guest = validate_guest_report(remote_report.get("guest"))
            if (remote_report.get("host", {}).get("guest_host_key_verified") is not True or
                    remote_report.get("trace_event_definition_write_attempted") is not False or
                    remote_report.get("read_only") is not True):
                raise ValueError("strict PC3 identity or read-only transport validation failed")
            object_bytes = DEFAULT_OBJECT.read_bytes()
            object_sha256 = hashlib.sha256(object_bytes).hexdigest()
            if object_sha256 != EXPECTED_OBJECT_SHA256:
                raise ValueError("pinned local R580 object hash changed")
            expected_functions = elf_function_hashes(object_bytes, RM_FUNCTION_NAMES)
            report["rm_object_function_comparison"] = {
                "reference_object_sha256": object_sha256,
                **compare_function_code_hashes(expected_functions, guest["rm_function_hashes"]),
            }
            report["remote"] = remote_report
            report["status"] = "observed"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report["evidence"] = str(args.evidence)
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: report[key] for key in
            ("schema", "status", "failure_stage", "remote_stdout_sha256", "evidence")
            if key in report}, sort_keys=True))
        guest = report.get("remote", {}).get("guest", {}) if isinstance(report.get("remote"), dict) else {}
        comparison = report.get("rm_object_function_comparison", {})
        return 0 if (report["status"] == "observed" and guest.get("build_id_match") is True and
                     comparison.get("all_match") is True) else 1
    except Exception as exc:
        report["failure_stage"] = report.get("failure_stage") or "execution_or_validation"
        report["error_class"] = type(exc).__name__
        report["status"] = "failed"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report["evidence"] = str(args.evidence)
        write_private_new(args.evidence, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: report[key] for key in
            ("schema", "status", "failure_stage", "error_class", "evidence")
            if key in report}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
