#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture a bounded, unprivileged, read-only GPU inventory from PC3."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import collect_pc3_canary_host_state as host_state  # noqa: E402
from tools import run_pc3_v100_private_open580_build as pc3_transport  # noqa: E402

REMOTE_SCRIPT = r'''import json,os,platform,socket,subprocess
from pathlib import Path

LIMIT=131072
def run(argv):
    try:
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,timeout=20,check=False,
                         env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        return {"argv":argv,"exit_code":p.returncode,
                "stdout":p.stdout[:LIMIT].decode("utf-8","replace"),
                "stdout_truncated":len(p.stdout)>LIMIT,
                "stderr":p.stderr[:8192].decode("utf-8","replace")}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {"argv":argv,"error":type(e).__name__}

def iommu_group(bdf):
    link=Path("/sys/bus/pci/devices")/bdf/"iommu_group"
    try:
        group=Path(os.readlink(link)).name
        members=sorted(item.name for item in
                       (Path("/sys/kernel/iommu_groups")/group/"devices").iterdir())
        return {"group_id":group,"members":members}
    except OSError as e:
        return {"error":type(e).__name__}

try:
    os_release=Path("/etc/os-release").read_text(encoding="utf-8",errors="strict")[:8192]
except OSError:
    os_release=""
modules=[]
try:
    for line in Path("/proc/modules").read_text(encoding="ascii",errors="replace").splitlines():
        if line.split() and line.split()[0].startswith("nvidia"):
            modules.append(line.split()[:6])
except OSError:
    pass
commands={
    "pci_nvidia":run(["lspci","-Dnnk","-d","10de:"]),
    "pci_topology":run(["lspci","-Dtv"]),
    "pci_rtx_upstream_port":run(["lspci","-D","-s","0000:00:06.0","-vv"]),
    "pci_v100_upstream_port":run(["lspci","-D","-s","0000:80:1b.0","-vv"]),
    "gpu_status_and_all_visible_processes":run(["nvidia-smi"]),
    "gpu_list":run(["nvidia-smi","-L"]),
    "gpu_query":run(["nvidia-smi","--query-gpu=index,name,uuid,pci.bus_id,driver_version,memory.total,compute_cap","--format=csv,noheader"]),
    "compute_processes":run(["nvidia-smi","--query-compute-apps=pid,process_name,gpu_uuid","--format=csv,noheader"]),
    "topology":run(["nvidia-smi","topo","-m"]),
    "v100_vm_service":run(["systemctl","show","pc3-v100-qemu.service",
                            "--property=ActiveState,SubState,MainPID","--no-pager"]),
    "v100_vm_libvirt_list":run(["virsh","list","--all"]),
    "v100_guest_dns":run(["getent","hosts","pc3-v100"]),
    "iommu_groups":{bdf:iommu_group(bdf) for bdf in
                    ("0000:02:00.0","0000:02:00.1","0000:81:00.0")},
}
qemu=[]
try:
    for entry in Path("/proc").iterdir():
        if entry.name.isdecimal():
            try:
                name=(entry/"comm").read_text(encoding="utf-8",errors="replace").strip()
            except OSError:
                continue
            if "qemu" in name.lower():
                qemu.append({"pid":int(entry.name),"comm":name})
except OSError:
    pass
print(json.dumps({"schema":"pc3-user-gpu-inventory-payload-v1",
 "hostname":socket.gethostname(),"uid":os.getuid(),"username":__import__("pwd").getpwuid(os.getuid()).pw_name,
 "kernel_release":platform.release(),"os_release":os_release,"loaded_nvidia_modules":modules,
 "qemu_process_names":qemu,"commands":commands},sort_keys=True,separators=(",",":")))
'''


def collect(identity_file: Path | str) -> dict:
    identity = host_state.validate_direct_identity_file(identity_file)
    pc3_transport.verify_pc3_host_key()
    argv = host_state.direct_pc3_ssh_base(identity_file=identity)
    remote_command = "python3 -c " + shlex.quote(REMOTE_SCRIPT)
    try:
        result = subprocess.run(argv + [remote_command], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only PC3 user inventory transport failed") from None
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise RuntimeError("read-only PC3 user inventory command failed")
    try:
        payload = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 user inventory returned invalid JSON") from None
    if (not isinstance(payload, dict) or
            payload.get("schema") != "pc3-user-gpu-inventory-payload-v1" or
            payload.get("hostname", "").split(".")[0].lower() != "pc3" or
            not isinstance(payload.get("commands"), dict)):
        raise RuntimeError("PC3 user inventory identity or schema mismatch")
    return {
        "schema": "pc3-user-gpu-inventory-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "unprivileged-read-only-pc3-inventory",
        "host": payload,
        "transport": {
            "mode": "pc3-direct-key-only",
            "target": "pc3@pc3",
            "host_key_alias": "pc3",
            "identity_file_basename": identity.name,
            "sudo_used": False,
            "remote_script_sha256": hashlib.sha256(REMOTE_SCRIPT.encode()).hexdigest(),
            "local_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "host_key_verified_against_pinned_known_hosts": True,
        },
        "scope": {
            "read_only": True,
            "driver_installed_or_loaded": False,
            "runtime_or_hardware_workload_tested": False,
            "sudo_only_state_not_visible": True,
        },
    }


def write_report(path: Path, report: dict) -> None:
    path = Path(path)
    evidence_root = (ROOT / "evidence").resolve(strict=True)
    try:
        path.parent.resolve(strict=True).relative_to(evidence_root)
    except (OSError, ValueError):
        raise ValueError("PC3 inventory report must be written inside evidence") from None
    data = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("PC3 inventory destination is not a regular file")
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = collect(args.identity_file)
        write_report(args.output, report)
    except (OSError, ValueError, RuntimeError) as error:
        print("PC3 user inventory failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps({"status":"collected","host":report["host"]["hostname"],
                      "output":str(args.output.resolve()),
                      "sha256":hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      "qualification":report["qualification"]},sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
