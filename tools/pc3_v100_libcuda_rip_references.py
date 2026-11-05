#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Find bounded metadata for direct RIP-relative references in PC3 V100 libcuda.

The library is disassembled in place inside the pinned V100 guest. Only source
addresses, bounded section/symbol-anchor metadata, mnemonic and a coarse
reference class are retained. The proprietary binary, bytes, operands, symbols,
and pseudocode are never copied or written to evidence.
"""
from __future__ import annotations

import argparse
from collections import deque
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
from typing import Iterable, Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_HOST = "pc3"
EXPECTED_HOST_KERNEL = "7.0.0-38-generic"
EXPECTED_RTX_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_GUEST = "pc3-v100"
EXPECTED_GUEST_KERNEL = "6.8.0-147-generic"
EXPECTED_V100_UUID = "GPU-42d06a85-027a-75ea-7857-a8de27ad465e"
EXPECTED_V100_PCI = "0000:00:05.0"
EXPECTED_V100_DRIVER = "580.178.04"
EXPECTED_LIBCUDA = "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04"
EXPECTED_LIBCUDA_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
EXPECTED_LIBCUDA_BYTES = 96_284_520
GHIDRA_IMAGE_BASE = 0x100000
DEFAULT_TARGET_ELF_VMA = 0x5BDC70C
DEFAULT_MAX_MATCHES = 64
MAX_RETAINED_MATCHES = 128
MAX_DISASSEMBLY_LINES = 25_000_000
MAX_LINE_CHARS = 16_384
OUTPUT_PREFIX = "PC3_LIBCUDA_RIP_SCAN:"

SECTION_RE = re.compile(r"^Disassembly of section ([A-Za-z0-9._-]{1,80}):$")
SYMBOL_RE = re.compile(r"^\s*([0-9a-fA-F]{1,16})\s+<[^\n>]{0,1024}>:\s*$")
INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]{1,16}):\s+((?:[0-9a-fA-F]{2}\s+)+)"
    r"([A-Za-z][A-Za-z0-9_.]*)\s*(.*)$"
)
ADDRESS_ROW_RE = re.compile(r"^\s*[0-9a-fA-F]{1,16}:")
RIP_EXPRESSION_RE = re.compile(
    r"\[\s*rip(?:\s*([+-])\s*(0x[0-9a-fA-F]{1,16}))?\s*\]", re.IGNORECASE)
PCI_RE = re.compile(r"^([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])$")
SYMBOL_ANNOTATION_RE = re.compile(r"\s+<[^<>\n]{1,256}>")
SAFE_OPERANDS_RE = re.compile(r"^[A-Za-z0-9_.,:+*%$ \[\]()-]{0,192}$")


def _load_transport_helper():
    path = ROOT / "tools/run_pc3_v100_guest_reference.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 V100 guest transport helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_pci(value: str) -> str:
    match = PCI_RE.fullmatch(value)
    if match is None or int(match.group(3), 16) > 31:
        raise ValueError("invalid PCI identity")
    domain, bus, slot, function = match.groups()
    return f"{int(domain, 16) & 0xffff:04x}:{int(bus, 16):02x}:{int(slot, 16):02x}.{int(function)}"


def _reference_kind(mnemonic: str, operands: str, expression_start: int) -> str:
    """Classify a decoded direct RIP reference without assigning API semantics."""
    name = mnemonic.lower()
    if name == "lea":
        return "address_materialization"
    before_comment = operands.split("#", 1)[0].strip()
    first, separator, rest = before_comment.partition(",")
    destination_has_ref = expression_start < len(first)
    if name in {"cmp", "test", "bt", "prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2"}:
        return "read_or_compare"
    if name in {"call", "callq", "jmp", "jmpq"}:
        return "indirect_control_reference"
    if destination_has_ref and name in {
        "mov", "movabs", "movbe", "movnti", "movntq", "movntdq",
        "stos", "stosb", "stosd", "stosq", "stosw",
    }:
        return "write_candidate"
    if destination_has_ref and name in {
        "add", "adc", "and", "btc", "btr", "bts", "cmpxchg", "dec",
        "inc", "neg", "not", "or", "rol", "ror", "sal", "sar", "sbb",
        "shl", "shr", "sub", "xadd", "xchg", "xor",
    }:
        return "read_write_candidate"
    if separator and rest:
        return "read_candidate"
    return "unclassified_rip_memory_reference"


def scan_rip_references(
    lines: Iterable[str],
    *,
    target_va: int,
    elf_load_base: int,
    max_matches: int = DEFAULT_MAX_MATCHES,
    context_before: int = 0,
    context_after: int = 0,
) -> dict[str, Any]:
    """Stream objdump lines and retain only capped metadata for one ELF VMA."""
    if (type(target_va) is not int or type(elf_load_base) is not int or
            target_va < elf_load_base or elf_load_base < 0 or
            type(max_matches) is not int or not 1 <= max_matches <= MAX_RETAINED_MATCHES or
            type(context_before) is not int or not 0 <= context_before <= 16 or
            type(context_after) is not int or not 0 <= context_after <= 16):
        raise ValueError("invalid or unbounded RIP-reference scan parameters")

    section: str | None = None
    symbol_anchor: int | None = None
    previous_instructions: deque[dict[str, str | None]] = deque(maxlen=context_before)
    pending_contexts: list[dict[str, Any]] = []
    instruction_count = 0
    rip_count = 0
    malformed_decode_count = 0
    undecoded_byte_directive_count = 0
    line_count = 0
    match_count = 0
    matches: list[dict[str, str | None]] = []

    for line in lines:
        line_count += 1
        if line_count > MAX_DISASSEMBLY_LINES:
            raise ValueError("objdump line count exceeds the fixed scan bound")
        if not isinstance(line, str) or len(line) > MAX_LINE_CHARS:
            raise ValueError("objdump line exceeds the fixed scan bound")

        section_match = SECTION_RE.fullmatch(line.strip())
        if section_match:
            section = section_match.group(1)
            symbol_anchor = None
            previous_instructions.clear()
            pending_contexts.clear()
            continue
        symbol_match = SYMBOL_RE.fullmatch(line.rstrip("\r\n"))
        if symbol_match:
            symbol_anchor = int(symbol_match.group(1), 16)
            continue
        if not ADDRESS_ROW_RE.match(line):
            continue
        parsed = INSTRUCTION_RE.fullmatch(line.rstrip("\r\n"))
        if parsed is None:
            if re.search(r"\(bad\)|\.byte\b", line):
                if re.search(r"\.byte\b", line):
                    undecoded_byte_directive_count += 1
                else:
                    malformed_decode_count += 1
                continue
            malformed_decode_count += 1
            continue

        source_va = int(parsed.group(1), 16)
        encodings = parsed.group(2).split()
        if not 1 <= len(encodings) <= 15:
            malformed_decode_count += 1
            continue
        if source_va < elf_load_base:
            raise ValueError("decoded instruction precedes the ELF load base")
        mnemonic = parsed.group(3).lower()
        operands = parsed.group(4)
        instruction_count += 1

        safe_operands = operands.split("#", 1)[0].strip()
        safe_operands = SYMBOL_ANNOTATION_RE.sub("", safe_operands).strip()
        if not SAFE_OPERANDS_RE.fullmatch(safe_operands):
            safe_operands = None
        context_row: dict[str, str | None] = {
            "source_va": f"0x{source_va:x}",
            "source_rva": f"0x{source_va - elf_load_base:x}",
            "section": section,
            "mnemonic": mnemonic,
            "operands": safe_operands,
        }
        still_pending: list[dict[str, Any]] = []
        for pending in pending_contexts:
            if pending["remaining"] > 0:
                pending["match"]["linear_instruction_context"].append(context_row)
                pending["remaining"] -= 1
            if pending["remaining"] > 0:
                still_pending.append(pending)
        pending_contexts = still_pending

        for expression in RIP_EXPRESSION_RE.finditer(operands.split("#", 1)[0]):
            rip_count += 1
            sign, displacement_text = expression.groups()
            displacement = int(displacement_text, 16) if displacement_text else 0
            if sign == "-":
                displacement = -displacement
            referenced_va = source_va + len(encodings) + displacement
            if referenced_va != target_va:
                continue
            match_count += 1
            if len(matches) < max_matches:
                match: dict[str, Any] = {
                    "source_va": f"0x{source_va:x}",
                    "source_rva": f"0x{source_va - elf_load_base:x}",
                    "preceding_symbol_anchor_va": (f"0x{symbol_anchor:x}"
                                                   if symbol_anchor is not None else None),
                    "preceding_symbol_anchor_rva": (f"0x{symbol_anchor - elf_load_base:x}"
                                                     if symbol_anchor is not None else None),
                    "section": section,
                    "mnemonic": mnemonic,
                    "reference_kind": _reference_kind(mnemonic, operands, expression.start()),
                    "linear_instruction_context": [*previous_instructions, context_row],
                }
                matches.append(match)
                if context_after:
                    pending_contexts.append({"match": match, "remaining": context_after})
        if context_before:
            previous_instructions.append(context_row)

    return {
        "target_va": f"0x{target_va:x}",
        "target_rva": f"0x{target_va - elf_load_base:x}",
        "elf_load_base": f"0x{elf_load_base:x}",
        "line_count": line_count,
        "instruction_count": instruction_count,
        "rip_relative_reference_count": rip_count,
        "malformed_decode_count": malformed_decode_count,
        "undecoded_byte_directive_count": undecoded_byte_directive_count,
        "match_count": match_count,
        "matches": matches,
        "truncated": match_count > max_matches,
        "decode_scan_complete": malformed_decode_count == 0 and undecoded_byte_directive_count == 0,
    }


def _read_elf_layout(path: Path) -> dict[str, Any]:
    """Read only fixed ELF64 program-header metadata; never copy the image."""
    import struct

    with path.open("rb", buffering=0) as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
            raise ValueError("libcuda is not a little-endian ELF64 image")
        phoff = struct.unpack_from("<Q", header, 32)[0]
        phentsize = struct.unpack_from("<H", header, 54)[0]
        phnum = struct.unpack_from("<H", header, 56)[0]
        if phentsize < 56 or not 1 <= phnum <= 4096 or phoff > path.stat().st_size:
            raise ValueError("libcuda program-header table is invalid")
        loads: list[dict[str, int]] = []
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            entry = stream.read(56)
            if len(entry) != 56:
                raise ValueError("libcuda program-header table is truncated")
            p_type, _flags = struct.unpack_from("<II", entry, 0)
            if p_type != 1:  # PT_LOAD
                continue
            p_offset, p_vaddr, _paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", entry, 8)
            loads.append({"offset": p_offset, "vaddr": p_vaddr,
                          "file_size": p_filesz, "memory_size": p_memsz})
    if not loads:
        raise ValueError("libcuda has no PT_LOAD segments")
    base = min(item["vaddr"] for item in loads)
    end = max(item["vaddr"] + item["memory_size"] for item in loads)
    return {"load_base": base, "load_end_exclusive": end,
            "load_segment_count": len(loads), "segments": loads}


def _sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _guest_scan_main(argv: list[str]) -> int:
    if len(argv) != 7:
        raise SystemExit(2)
    path = Path(argv[0])
    target_va, ghidra_base, max_matches, context_before, context_after = (
        int(value, 0) for value in argv[1:6])
    # The final argument pins the expected ELF load base supplied by the caller.
    expected_elf_base = int(argv[6], 0)
    if str(path) != EXPECTED_LIBCUDA:
        raise SystemExit(2)

    host = os.uname().nodename
    kernel = os.uname().release
    smi = subprocess.run(
        ["nvidia-smi", "--query-gpu=name,uuid,pci.bus_id,driver_version",
         "--format=csv,noheader,nounits"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=20,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=False)
    rows = [[value.strip() for value in row] for row in
            __import__("csv").reader(smi.stdout.splitlines()) if row]
    if (host != EXPECTED_GUEST or kernel != EXPECTED_GUEST_KERNEL or smi.returncode != 0 or
            len(rows) != 1 or len(rows[0]) != 4 or not rows[0][0].startswith("Tesla V100") or
            rows[0][1] != EXPECTED_V100_UUID or canonical_pci(rows[0][2]) != EXPECTED_V100_PCI or
            rows[0][3] != EXPECTED_V100_DRIVER):
        raise SystemExit(3)

    resolved = path.resolve(strict=True)
    size, digest = _sha256_file(resolved)
    if size != EXPECTED_LIBCUDA_BYTES or digest != EXPECTED_LIBCUDA_SHA256:
        raise SystemExit(4)
    layout = _read_elf_layout(resolved)
    if layout["load_base"] != expected_elf_base:
        raise SystemExit(5)
    if not layout["load_base"] <= target_va < layout["load_end_exclusive"]:
        raise SystemExit(6)

    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    version = subprocess.run(["/usr/bin/objdump", "--version"], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=15, env=env, check=False)
    if version.returncode != 0 or not version.stdout.splitlines():
        raise SystemExit(7)
    process = subprocess.Popen(
        ["/usr/bin/objdump", "-d", "-M", "intel", "--wide", str(resolved)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        encoding="utf-8", errors="replace", env=env, close_fds=True)
    assert process.stdout is not None
    try:
        summary = scan_rip_references(
            process.stdout, target_va=target_va, elf_load_base=layout["load_base"],
            max_matches=max_matches, context_before=context_before,
            context_after=context_after)
    except BaseException:
        process.kill()
        process.wait(timeout=10)
        raise
    return_code = process.wait(timeout=180)
    if return_code != 0 or summary["instruction_count"] == 0:
        raise SystemExit(8)
    target_rva = target_va - layout["load_base"]
    result = {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-rip-scan-v1",
        "guest": {"hostname": host, "kernel_release": kernel,
                  "gpu": {"name": rows[0][0], "uuid": rows[0][1],
                          "pci": canonical_pci(rows[0][2]), "driver_version": rows[0][3]}},
        "library": {"basename": resolved.name, "bytes": size, "sha256": digest,
                    "elf_type": "ELF64-LE", "elf_layout": layout},
        "disassembler": {"path": "/usr/bin/objdump",
                         "version": version.stdout.splitlines()[0][:120],
                         "exit_code": return_code},
        "address_mapping": {"target_elf_vma": f"0x{target_va:x}",
                            "target_rva": f"0x{target_rva:x}",
                            "ghidra_image_base": f"0x{ghidra_base:x}",
                            "target_ghidra_address": f"0x{ghidra_base + target_rva:x}",
                            "elf_load_base": f"0x{layout['load_base']:x}"},
        "scan": summary,
        "scope": {"binary_copied": False, "binary_retained": False,
                  "raw_disassembly_retained": False, "symbols_retained": False,
                  "pseudocode_retained": False, "gpu_workload_run": False,
                  "driver_or_vm_changed": False},
        "limitations": [
            "The scanner resolves only decoded direct RIP-relative operands in objdump executable sections.",
            "A full linear sweep is not a control-flow graph; embedded data and invalid bytes may be missed or misdecoded.",
            "No match does not exclude indirect, GOT-mediated, dynamically computed, or runtime-generated references.",
            "Reference classes describe instruction form only and do not assign CUDA or feature semantics.",
        ],
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _remote_root_script(scanner_source: str) -> str:
    transport = _load_transport_helper()
    hostkey_helper = inspect.getsource(transport.verify_guest_host_key)
    return r'''import csv,json,os,platform,shlex,socket,stat,subprocess,sys,tempfile
from pathlib import Path
EXPECTED_HOST="pc3"
EXPECTED_KERNEL="7.0.0-38-generic"
EXPECTED_RTX_UUID="GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
GUEST_KEY="/var/lib/pc3-v100-vm/id_ed25519"
GUEST_KNOWN="/tmp/codex-pc3-vm-known_hosts"
GUEST_FINGERPRINT="SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
def call(argv,timeout=30,input_data=None):
 return subprocess.run(argv,input=input_data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
def fail(stage,code,check=None):
 row={"status":"failed","stage":stage,"code":code}
 if check is not None: row["check"]=check
 print(json.dumps(row,sort_keys=True,separators=(",",":")))
 raise SystemExit(code)
if socket.gethostname()!=EXPECTED_HOST or platform.release()!=EXPECTED_KERNEL: fail("host_identity",20)
bindings={}
for bdf in ("0000:02:00.0","0000:81:00.0"):
 try: bindings[bdf]=Path("/sys/bus/pci/devices/"+bdf+"/driver").resolve(strict=True).name
 except Exception: fail("host_pci_inventory",21)
if bindings!={"0000:02:00.0":"nvidia","0000:81:00.0":"vfio-pci"}: fail("host_pci_ownership",22)
smi=call(["nvidia-smi","--query-gpu=name,uuid,pci.bus_id,driver_version","--format=csv,noheader,nounits"],timeout=20)
rows=[[x.strip() for x in row] for row in csv.reader(smi.stdout.decode("utf-8","replace").splitlines()) if row]
if smi.returncode or len(rows)!=1 or len(rows[0])!=4 or rows[0][1]!=EXPECTED_RTX_UUID or rows[0][2]!="00000000:02:00.0" or rows[0][3]!="595.99.02": fail("host_gpu_inventory",23)
k=Path(GUEST_KEY).lstat()
if not stat.S_ISREG(k.st_mode) or k.st_uid!=0 or stat.S_IMODE(k.st_mode)!=0o600: fail("guest_key_metadata",24)
###HOSTKEY_HELPER###
try: verify_guest_host_key(Path(GUEST_KNOWN),GUEST_FINGERPRINT,0,call)
except Exception as error:
 allowed={"guest known-hosts ownership or mode is unsafe","guest host key entry for the forwarded endpoint is invalid","guest endpoint does not contain exactly the pinned host key"}
 detail=str(error) if str(error) in allowed else "unexpected verification exception"
 fail("guest_hostkey",28,type(error).__name__)
scanner_source=###SCANNER_SOURCE###
ssh=["ssh","-F","/dev/null","-T","-oBatchMode=yes","-oIdentitiesOnly=yes","-oStrictHostKeyChecking=yes","-oUserKnownHostsFile="+GUEST_KNOWN,"-oConnectTimeout=8","-oConnectionAttempts=1","-i",GUEST_KEY,"-p","22223","ubuntu@127.0.0.1"]
args=["python3","-","--guest-scan","/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04","0x5bdc70c","0x100000","64","4","8","0x0"]
remote=" ".join(shlex.quote(x) for x in args)
r=call(ssh+[remote],timeout=240,input_data=scanner_source.encode("utf-8"))
if r.returncode: fail("guest_scan",25,"exit_"+str(r.returncode))
try: guest=json.loads(r.stdout.decode("utf-8","strict"))
except Exception: fail("guest_result_decode",26)
if guest.get("schema")!="nvidia-hybrid-pc3-v100-libcuda-rip-scan-v1" or guest.get("scope",{}).get("binary_copied") is not False: fail("guest_result_contract",27)
print(json.dumps({"host":{"hostname":socket.gethostname(),"kernel_release":platform.release(),"pci_ownership":bindings,"nvidia_smi_gpu":{"name":rows[0][0],"uuid":rows[0][1],"pci":rows[0][2],"driver_version":rows[0][3]}},"guest_hostkey_fingerprint":GUEST_FINGERPRINT,"guest":guest},sort_keys=True,separators=(",",":")))
'''.replace("###HOSTKEY_HELPER###", hostkey_helper).replace(
        "###SCANNER_SOURCE###", repr(scanner_source))


def _validate_remote_result(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"host", "guest_hostkey_fingerprint", "guest"}:
        raise ValueError("remote PC3 result has an unsupported shape")
    host = value["host"]
    guest = value["guest"]
    if (not isinstance(host, dict) or host.get("hostname") != EXPECTED_HOST or
            host.get("kernel_release") != EXPECTED_HOST_KERNEL):
        raise ValueError("remote PC3 identity did not match the pinned host")
    if host.get("pci_ownership") != {"0000:02:00.0": "nvidia", "0000:81:00.0": "vfio-pci"}:
        raise ValueError("remote PC3 PCI ownership changed")
    host_gpu = host.get("nvidia_smi_gpu")
    if (not isinstance(host_gpu, dict) or host_gpu.get("uuid") != EXPECTED_RTX_UUID or
            host_gpu.get("pci") != "00000000:02:00.0" or host_gpu.get("driver_version") != "595.99.02" or
            not isinstance(host_gpu.get("name"), str) or "RTX 5080" not in host_gpu["name"]):
        raise ValueError("remote PC3 RTX 5080 identity did not match")
    if value.get("guest_hostkey_fingerprint") != "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts":
        raise ValueError("remote V100 guest host key did not match")
    if (not isinstance(guest, dict) or guest.get("schema") !=
            "nvidia-hybrid-pc3-v100-libcuda-rip-scan-v1"):
        raise ValueError("remote V100 guest report has an unsupported schema")
    scope = guest.get("scope")
    if not isinstance(scope, dict) or any(scope.get(k) is not False for k in (
            "binary_copied", "binary_retained", "raw_disassembly_retained", "symbols_retained",
            "pseudocode_retained", "gpu_workload_run", "driver_or_vm_changed")):
        raise ValueError("remote scan exceeded the declared static in-place scope")
    library = guest.get("library")
    if (not isinstance(library, dict) or library.get("sha256") != EXPECTED_LIBCUDA_SHA256 or
            library.get("bytes") != EXPECTED_LIBCUDA_BYTES):
        raise ValueError("remote libcuda identity did not match the pinned image")
    mapping = guest.get("address_mapping")
    if (not isinstance(mapping, dict) or mapping.get("target_elf_vma") != "0x5bdc70c" or
            mapping.get("target_rva") != "0x5bdc70c" or
            mapping.get("target_ghidra_address") != "0x5cdc70c"):
        raise ValueError("remote ELF/Ghidra address mapping is inconsistent")
    scan = guest.get("scan")
    if not isinstance(scan, dict) or type(scan.get("decode_scan_complete")) is not bool:
        raise ValueError("remote scan summary is missing or incomplete")
    if (scan.get("target_va") != "0x5bdc70c" or scan.get("target_rva") != "0x5bdc70c" or
            scan.get("elf_load_base") != "0x0"):
        raise ValueError("remote scan target does not match the pinned ELF address")
    for key in ("line_count", "instruction_count", "rip_relative_reference_count",
                "malformed_decode_count", "undecoded_byte_directive_count", "match_count"):
        if type(scan.get(key)) is not int or scan[key] < 0:
            raise ValueError("remote scan counter is invalid")
    matches = scan.get("matches")
    if not isinstance(matches, list) or len(matches) > DEFAULT_MAX_MATCHES:
        raise ValueError("remote match list exceeded its cap")
    if scan["match_count"] < len(matches) or scan.get("truncated") is not (scan["match_count"] > len(matches)):
        raise ValueError("remote scan match cap metadata is inconsistent")
    for row in matches:
        if not isinstance(row, dict) or set(row) != {
                "source_va", "source_rva", "preceding_symbol_anchor_va",
                "preceding_symbol_anchor_rva", "section", "mnemonic", "reference_kind",
                "linear_instruction_context"}:
            raise ValueError("remote reference metadata has an unexpected field")
        for item in row.values():
            if isinstance(item, list):
                if len(item) > 33:
                    raise ValueError("remote instruction context exceeded its cap")
                for context_row in item:
                    if not isinstance(context_row, dict) or set(context_row) != {
                            "source_va", "source_rva", "section", "mnemonic", "operands"}:
                        raise ValueError("remote instruction context has an unexpected field")
                    if any(value is not None and (not isinstance(value, str) or len(value) > 192)
                           for value in context_row.values()):
                        raise ValueError("remote instruction context has an invalid value")
                    operands = context_row.get("operands")
                    if operands is not None and SAFE_OPERANDS_RE.fullmatch(operands) is None:
                        raise ValueError("remote instruction context retained unsupported operand text")
            elif item is not None and (not isinstance(item, str) or len(item) > 96):
                raise ValueError("remote reference metadata has an invalid value")
    return value


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, help="new mode-0600 output report")
    args = parser.parse_args(argv)
    if args.evidence is None:
        parser.error("--evidence is required")
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    transport = _load_transport_helper()
    secret = transport.fetch_pc3_sudo_secret(
        transport.DEFAULT_CREDENTIAL_HOST, transport.DEFAULT_CREDENTIAL_FILE)
    source = Path(__file__).read_text(encoding="utf-8")
    remote = _remote_root_script(source)
    command = "sudo -S -p '' python3 -c " + shlex.quote(remote)
    try:
        result = subprocess.run(
            transport.pc3_ssh_base(transport.DEFAULT_PC3_TARGET, transport.DEFAULT_HOST_KEY_ALIAS) + [command],
            input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=270, check=False,
        )
    finally:
        secret = None
    if result.returncode != 0:
        try:
            failure = json.loads(result.stdout.decode("utf-8", "strict"))
        except (UnicodeDecodeError, ValueError):
            failure = {}
        stage = failure.get("stage") if isinstance(failure, dict) else None
        code = failure.get("code") if isinstance(failure, dict) else None
        check = failure.get("check") if isinstance(failure, dict) else None
        if not isinstance(stage, str) or re.fullmatch(r"[a-z_]{1,40}", stage) is None:
            stage = "transport_or_remote_execution"
        suffix = f"; {check}" if isinstance(check, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", check) else ""
        raise RuntimeError(f"guarded in-place PC3 V100 reference scan failed at {stage} (code {code}){suffix}")
    try:
        remote_result = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        raise RuntimeError("guarded PC3 scan returned invalid JSON") from None
    validated = _validate_remote_result(remote_result)
    report = {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-rip-evidence-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "qualification": "bounded-in-place-static-reference-metadata",
        "producer": {"tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     "hostkey_fingerprint": validated["guest_hostkey_fingerprint"]},
        "host": validated["host"],
        "guest": validated["guest"],
        "interpretation": (
            "A direct RIP-relative operand in the pinned R580 libcuda linear disassembly resolves to the selected ELF VMA. "
            "This is static reference metadata only; it does not prove that the instruction executes or define the global's semantics."
        ),
    }
    _write_report(args.evidence, report)
    print(json.dumps({"evidence": str(args.evidence), "qualification": report["qualification"],
                      "match_count": report["guest"]["scan"]["match_count"],
                      "sha256": hashlib.sha256(args.evidence.read_bytes()).hexdigest()}, sort_keys=True))
    return 0


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--guest-scan":
    raise SystemExit(_guest_scan_main(sys.argv[2:]))
elif __name__ == "__main__":
    raise SystemExit(main())
