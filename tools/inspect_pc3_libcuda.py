#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only, hash-pinned metadata inspection of PC3's installed libcuda."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any


EXPECTED_HOST = "pc3"
EXPECTED_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
TARGET = "pc3@pc3"
HOST_KEY_ALIAS = "pc3"
MAX_STDOUT = 64 * 1024
MAX_STDERR = 4 * 1024

REMOTE_SOURCE = r'''import csv,glob,hashlib,json,os,re,shutil,subprocess,sys

def run(argv, timeout=20):
    try:
        result=subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired):
        return None, "", ""

rc, gpu_text, _ = run(["nvidia-smi", "--query-gpu=name,uuid,pci.bus_id,driver_version",
                       "--format=csv,noheader,nounits"])
if rc != 0:
    raise SystemExit(20)
gpus=[]
for row in csv.reader(gpu_text.splitlines(), skipinitialspace=True):
    if len(row) != 4:
        raise SystemExit(21)
    gpus.append({"name":row[0], "uuid":row[1], "pci_bus_id":row[2], "driver_version":row[3]})

paths=[]
for pattern in ("/usr/lib/x86_64-linux-gnu/libcuda.so*",
                "/usr/lib/x86_64-linux-gnu/nvidia/current/libcuda.so*",
                "/usr/lib/nvidia-*/libcuda.so*"):
    paths.extend(glob.glob(pattern))
libs=[]
seen=set()
for link in sorted(paths):
    target=os.path.realpath(link)
    if target in seen or not os.path.isfile(target):
        continue
    seen.add(target)
    digest=hashlib.sha256()
    with open(target,"rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):
            digest.update(block)
    sec_rc, sections, _=run(["readelf","-SW",target])
    if sec_rc != 0:
        raise SystemExit(22)
    static_symtab=bool(re.search(r"^\s*\[\s*\d+\]\s+\.symtab\s+SYMTAB\b",sections,re.M))
    nm_rc, symbols, _=run(["nm","-D","--defined-only",target])
    if nm_rc != 0:
        raise SystemExit(23)
    symbol_lines=[line for line in symbols.splitlines() if line.strip()]
    markers=("binapi","finn","serialize","rmcontrol")
    symbol_matches=[line[:220] for line in symbol_lines
                    if any(marker in line.lower() for marker in markers)][:20]
    note_rc, note, _=run(["readelf","-n",target])
    if note_rc != 0:
        raise SystemExit(24)
    build_id_match=re.search(r"Build ID:\s*([0-9a-fA-F]+)",note)
    strings_counts={marker:0 for marker in ("BINAPI","FINN","20810108","NV2081")}
    strings_bin=shutil.which("strings")
    if strings_bin is None:
        raise SystemExit(25)
    try:
        proc=subprocess.Popen([strings_bin,"-a",target],stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        assert proc.stdout is not None
        for line in proc.stdout:
            lowered=line.decode("utf-8","replace").lower()
            for marker in strings_counts:
                strings_counts[marker]+=marker.lower() in lowered
        if proc.wait(timeout=30) != 0:
            raise SystemExit(26)
    except (OSError, subprocess.TimeoutExpired):
        try: proc.kill()
        except Exception: pass
        raise SystemExit(27)
    links=[link for link in sorted(paths) if os.path.realpath(link)==target]
    libs.append({"path":target,"links":links,"bytes":os.path.getsize(target),
                 "sha256":digest.hexdigest(),"build_id":build_id_match.group(1).lower() if build_id_match else None,
                 "static_symbol_table":static_symtab,"dynamic_export_count":len(symbol_lines),
                 "dynamic_symbol_marker_matches":symbol_matches,"string_marker_counts":strings_counts})
if not libs:
    raise SystemExit(28)
print(json.dumps({"hostname":os.uname().nodename,"kernel":os.uname().release,
                  "nvidia_smi":gpus,"libraries":libs},sort_keys=True,separators=(",",":")))
'''


def remote_command() -> list[str]:
    return [
        "ssh", "-F", "/dev/null", "-T", "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oUserKnownHostsFile=" + str(Path.home() / ".ssh/known_hosts"),
        "-oHostKeyAlias=" + HOST_KEY_ALIAS, "-oConnectTimeout=10",
        "-oConnectionAttempts=1", "--", TARGET,
        "python3 -c " + shlex.quote(REMOTE_SOURCE),
    ]


def canonical_pci(value: str) -> str:
    match=re.fullmatch(r"(?:([0-9a-fA-F]{4})|([0-9a-fA-F]{8})):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])",value)
    if not match:
        raise ValueError("remote PCI identity is malformed")
    domain4,domain8,bus,slot,function=match.groups()
    domain=int(domain4 or domain8,16)&0xffff
    if int(slot,16)>31:
        raise ValueError("remote PCI identity is malformed")
    return f"{domain:04x}:{int(bus,16):02x}:{int(slot,16):02x}.{function}"


def validate_snapshot(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("hostname") != EXPECTED_HOST:
        raise ValueError("remote host identity does not match PC3")
    if not isinstance(value.get("kernel"), str) or not value["kernel"]:
        raise ValueError("remote kernel identity is missing")
    gpus=value.get("nvidia_smi")
    if not isinstance(gpus,list) or len(gpus)!=1 or not isinstance(gpus[0],dict):
        raise ValueError("the expected RTX5080-only PC3 host inventory was not observed")
    try:
        pci=canonical_pci(gpus[0].get("pci_bus_id", ""))
    except ValueError:
        raise ValueError("the expected RTX5080-only PC3 host inventory was not observed") from None
    if (gpus[0].get("uuid")!=EXPECTED_UUID or pci!=EXPECTED_PCI or
        "RTX 5080" not in str(gpus[0].get("name","")) or
        not isinstance(gpus[0].get("driver_version"),str)):
        raise ValueError("the expected RTX5080-only PC3 host inventory was not observed")
    value=dict(value)
    value["nvidia_smi"]=[dict(gpus[0])]
    value["nvidia_smi"][0]["pci_bus_id"]=pci
    libs=value.get("libraries")
    if not isinstance(libs,list) or not libs:
        raise ValueError("no installed libcuda artifact was inspected")
    for lib in libs:
        if (not isinstance(lib,dict) or not isinstance(lib.get("path"),str) or
            type(lib.get("bytes")) is not int or lib["bytes"]<=0 or
            not re.fullmatch(r"[0-9a-f]{64}",str(lib.get("sha256",""))) or
            type(lib.get("dynamic_export_count")) is not int or
            not isinstance(lib.get("string_marker_counts"),dict)):
            raise ValueError("libcuda metadata is incomplete")
    return value


def inspect_pc3() -> dict[str, Any]:
    result=subprocess.run(remote_command(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=45, check=False)
    if result.returncode:
        raise ValueError(f"PC3 read-only inventory failed with SSH status {result.returncode}")
    if len(result.stdout)>MAX_STDOUT or len(result.stderr)>MAX_STDERR:
        raise ValueError("PC3 inventory output exceeded the fixed bound")
    try:
        snapshot=json.loads(result.stdout.decode("utf-8","strict"))
    except (UnicodeDecodeError,json.JSONDecodeError):
        raise ValueError("PC3 inventory did not return one JSON record") from None
    return validate_snapshot(snapshot)


def write_private_exclusive(path: Path, data: bytes) -> None:
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,"O_NOFOLLOW"):
        flags|=os.O_NOFOLLOW
    fd=os.open(path,flags,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb",closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args(argv)
    if args.output.exists():
        print("output already exists",file=sys.stderr)
        return 2
    try:
        snapshot=inspect_pc3()
        report={"schema":"nvidia-hybrid-pc3-libcuda-static-inspection-v1",
                "qualification":"read-only-static-inspection",
                "observed_at":datetime.now(timezone.utc).isoformat(),
                "target":TARGET,"host_key_alias":HOST_KEY_ALIAS,
                "host_key_checking":"strict","remote_source_sha256":hashlib.sha256(
                    REMOTE_SOURCE.encode("utf-8")).hexdigest(),
                "remote":snapshot,"gpu_workload_run":False,
                "library_contents_copied":False,
                "execution_scope":{"driver_or_module_changed":False,
                                   "gpu_state_changed":False,
                                   "firmware_or_vm_changed":False}}
        write_private_exclusive(args.output,
            (json.dumps(report,sort_keys=True,indent=2)+"\n").encode("utf-8"))
    except FileExistsError:
        print("output already exists",file=sys.stderr)
        return 2
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        print(str(exc),file=sys.stderr)
        return 1
    print(json.dumps({"qualification":report["qualification"],
                      "host":snapshot["hostname"],"gpu_count":len(snapshot["nvidia_smi"]),
                      "library_count":len(snapshot["libraries"]),"output":str(args.output)},
                     sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
