#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only audit of PC3's RTX 5080 IOMMU group and current QEMU GPU assignment."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
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

from tools import collect_pc3_canary_host_state as host_state_collector  # noqa: E402
from tools import run_pc3_v100_guest_reference as transport  # noqa: E402

REPORT_SCHEMA = "pc3-vm-gpu-recovery-control-audit-v4"
REMOTE_SCHEMA = "pc3-vm-gpu-recovery-control-remote-v4"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PROC_ENTRIES = 16
MAX_PROC_CMDLINE_BYTES = 2 * 1024 * 1024
BDF_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")

REMOTE_AUDIT_SCRIPT = r'''import hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path

MAX_PROC_ENTRIES=16
if len(sys.argv)!=2 or not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]",sys.argv[1]):
    raise SystemExit(2)
rtx_bdf=sys.argv[1]

def read_attr(path,name):
    try:return (path/name).read_text(encoding="ascii").strip().lower()
    except OSError:return None

rtx_device=Path("/sys/bus/pci/devices")/rtx_bdf
group_path=(rtx_device/"iommu_group").resolve(strict=True)
if group_path.parent!=Path("/sys/kernel/iommu_groups") or not group_path.name.isdigit():
    raise RuntimeError("RTX 5080 IOMMU group path is outside sysfs")
group_id=int(group_path.name)
members_path=group_path/"devices"
members=[]
for link in sorted(members_path.iterdir()):
    device=link.resolve(strict=True)
    try:driver=(device/"driver").resolve(strict=True).name
    except OSError:driver=None
    members.append({"pci":device.name.lower(),"vendor_id":read_attr(device,"vendor"),
        "device_id":read_attr(device,"device"),"class":read_attr(device,"class"),
        "driver":driver})
    if len(members)>16:raise RuntimeError("IOMMU group exceeds its inventory bound")

instances=[]
known_transports={"unix","tcp","telnet","udp","file","pipe","pty","stdio","vc","none","null","chardev","ringbuf"}
def option_values(args,name):
    values=[]
    index=0
    while index<len(args):
        item=args[index]
        if item==name and index+1<len(args):
            values.append(args[index+1]);index+=2;continue
        if item.startswith(name+"="):
            values.append(item[len(name)+1:])
        index+=1
    return values
def endpoint_transport(value):
    head=value.split(",",1)[0].lower()
    token=head.split(":",1)[0] if ":" in head else head.split("=",1)[0]
    return token if token in known_transports else "other"
def unix_endpoint_hashes(values):
    output=[]
    for value in values:
        head=value.split(",",1)[0]
        if head.startswith("unix:"):
            path=head[len("unix:"):]
            if path.startswith("path="):path=path[5:]
            if path:output.append(hashlib.sha256(path.encode()).hexdigest())
    return sorted(set(output))
def recovery_channels(process,args):
    monitor=option_values(args,"-monitor")
    qmp=option_values(args,"-qmp")
    serial=option_values(args,"-serial")
    expected_monitor=unix_endpoint_hashes(monitor)
    expected_qmp=unix_endpoint_hashes(qmp)
    socket_paths={}
    complete=True
    try:
        for line in Path("/proc/net/unix").read_text(encoding="utf-8",errors="replace").splitlines()[1:]:
            fields=line.split()
            if len(fields)>=7:
                path=" ".join(fields[7:]) if len(fields)>7 else ""
                socket_paths[fields[6]]=hashlib.sha256(path.encode()).hexdigest() if path else None
    except OSError:
        complete=False
    open_hashes=set()
    open_ptys=0
    try:
        entries=list((process/"fd").iterdir())
        if len(entries)>8192:complete=False;entries=entries[:8192]
        for entry in entries:
            try:target=os.readlink(entry)
            except OSError:
                if process.exists() and entry.exists():complete=False
                continue
            if re.fullmatch(r"/dev/pts/[0-9]+",target):open_ptys+=1
            match=re.fullmatch(r"socket:\[([0-9]+)\]",target)
            if match and match.group(1) in socket_paths and socket_paths[match.group(1)]:
                open_hashes.add(socket_paths[match.group(1)])
    except OSError:
        if process.exists():complete=False
    try:cgroup=(process/"cgroup").read_text(encoding="ascii",errors="replace")
    except OSError:cgroup=""
    unit_names=[]
    for line in cgroup.splitlines():
        parts=line.split(":",2)
        if len(parts)==3:
            unit_names.extend(part for part in parts[2].split("/")
                if part.endswith((".service",".scope")) and re.fullmatch(r"[A-Za-z0-9_.@:-]+",part))
    unit=unit_names[-1] if unit_names else None
    owner={"unit_name":unit,"query_complete":False,"active_state":None,"sub_state":None,
        "restart_policy":None,"restart_delay":None,"kill_mode":None}
    systemctl=shutil.which("systemctl")
    if unit and systemctl:
        try:
            queried=subprocess.run([systemctl,"show","--no-pager",
                "--property=Id,ActiveState,SubState,Restart,RestartUSec,KillMode",unit],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                timeout=8,check=False,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
            if queried.returncode==0 and len(queried.stdout)<=16384:
                properties={}
                for item in queried.stdout.decode("utf-8","replace").splitlines():
                    key,sep,value=item.partition("=")
                    if sep:properties[key]=value
                if properties.get("Id")==unit:
                    owner={"unit_name":unit,"query_complete":True,
                        "active_state":properties.get("ActiveState"),
                        "sub_state":properties.get("SubState"),
                        "restart_policy":properties.get("Restart"),
                        "restart_delay":properties.get("RestartUSec"),
                        "kill_mode":properties.get("KillMode")}
        except (OSError,subprocess.TimeoutExpired):
            pass
    return {"monitor_transports":sorted({endpoint_transport(v) for v in monitor}),
        "qmp_transports":sorted({endpoint_transport(v) for v in qmp}),
        "serial_transports":sorted({endpoint_transport(v) for v in serial}),
        "monitor_unix_socket_fd_match":bool(set(expected_monitor)&open_hashes),
        "qmp_unix_socket_fd_match":bool(set(expected_qmp)&open_hashes),
        "open_pty_fd_count":open_ptys,"fd_scan_complete":complete,
        "systemd_managed":any(part in cgroup for part in ("/system.slice/","/machine.slice/")),
        "systemd_owner":owner,
        "no_reboot_flag":"-no-reboot" in args,"no_shutdown_flag":"-no-shutdown" in args}
for process in Path("/proc").iterdir():
    if not process.name.isdigit():continue
    try:
        comm=(process/"comm").read_text(encoding="ascii").strip()
        if not comm.startswith("qemu-system-x86"):continue
        raw=(process/"cmdline").read_bytes()
    except OSError:
        continue
    if len(raw)>2*1024*1024:raise RuntimeError("QEMU command metadata exceeds its size bound")
    args=[item.decode("utf-8","replace") for item in raw.split(bytes([0])) if item]
    host_bdfs=sorted({match.group(1).lower() for arg in args
        for match in re.finditer(
            r"(?:^|,)host=(0000:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}[.][0-7])(?:,|$)",arg)})
    instances.append({"hostdev_bdfs":host_bdfs,
        "cmdline_sha256":hashlib.sha256(bytes([0]).join(arg.encode() for arg in args)).hexdigest(),
        "recovery_channels":recovery_channels(process,args)})
    if len(instances)>MAX_PROC_ENTRIES:
        raise RuntimeError("QEMU process inventory exceeds its bound")

report={"schema":"pc3-vm-gpu-recovery-control-remote-v4",
    "host":os.uname().nodename,"kernel_release":os.uname().release,
    "loaded_nvidia_module_version":Path("/sys/module/nvidia/version").read_text().strip(),
    "rtx5080_bdf":rtx_bdf,
    "rtx5080_iommu_group":{"group_id":group_id,"members":members},
    "hypervisor":{"virsh_available":shutil.which("virsh") is not None,
        "qm_available":shutil.which("qm") is not None,
        "qemu_binary_available":shutil.which("qemu-system-x86_64") is not None,
        "qemu_process_count":len(instances),"instances":instances},
    "system_state_changed":False}
print(json.dumps(report,sort_keys=True,separators=(",",":")))
'''


def _read_current_host_snapshot(path: Path) -> tuple[dict, str, str]:
    """Read a fresh private collector report without following the final path."""
    evidence_root = (ROOT / "evidence").resolve(strict=True)
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    try:
        path.parent.resolve(strict=True).relative_to(evidence_root)
    except (OSError, ValueError) as error:
        raise ValueError("fresh PC3 host snapshot must be inside the private evidence tree") from error
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or
                stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError("fresh PC3 host snapshot must be a private regular file")
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("fresh PC3 host snapshot exceeds its size bound")
    digest = hashlib.sha256(raw).hexdigest()
    snapshot = json.loads(raw.decode("utf-8", "strict"))
    if not isinstance(snapshot, dict):
        raise ValueError("fresh PC3 host snapshot must be an object")
    host_state_collector.validate_collection_report(snapshot)
    if (snapshot.get("collector_metadata", {}).get("transport", {}).get("mode") !=
            host_state_collector.DIRECT_TRANSPORT_MODE):
        raise ValueError("fresh PC3 host snapshot must use the direct PC3-only transport")
    return snapshot, digest, str(path.resolve(strict=True).relative_to(ROOT))


def _pci_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower().removeprefix("0x")
    return normalized if re.fullmatch(r"[0-9a-f]{4}", normalized) else None


def _snapshot_gpu_roles(snapshot: dict) -> tuple[dict, dict]:
    ownership = snapshot.get("gpu_ownership")
    if not isinstance(ownership, list):
        raise ValueError("fresh PC3 host snapshot lacks GPU ownership inventory")
    records = [item for item in ownership if isinstance(item, dict)]
    bdfs = [item.get("pci") for item in records]
    if (any(not isinstance(bdf, str) or not BDF_RE.fullmatch(bdf) for bdf in bdfs) or
            len(bdfs) != len(set(bdfs))):
        raise ValueError("PC3 GPU ownership inventory has invalid or duplicate PCI addresses")
    nvidia = [item for item in records if _pci_id(item.get("vendor_id")) == "10de"]
    rtx = [item for item in nvidia if _pci_id(item.get("device_id")) == "2c02"]
    if len(rtx) != 1 or rtx[0].get("driver") != "nvidia":
        raise ValueError("fresh host inventory must identify exactly one host-bound RTX 5080")
    vfio_gpus = [item for item in nvidia if item.get("driver") == "vfio-pci"]
    if len(vfio_gpus) != 1:
        raise ValueError("fresh host inventory must identify exactly one NVIDIA GPU assigned to VFIO")
    rtx_topology = rtx[0].get("pci_topology")
    vfio_topology = vfio_gpus[0].get("pci_topology")
    if (not isinstance(rtx_topology, dict) or type(rtx_topology.get("iommu_group")) is not int or
            type(rtx_topology.get("iommu_group_device_count")) is not int or
            rtx_topology["iommu_group_device_count"] < 1 or
            not isinstance(vfio_topology, dict) or type(vfio_topology.get("iommu_group")) is not int):
        raise ValueError("fresh host inventory lacks complete RTX/VFIO IOMMU topology")
    group_gpus = sorted(item["pci"] for item in nvidia
                        if isinstance(item.get("pci_topology"), dict) and
                        item["pci_topology"].get("iommu_group") == rtx_topology["iommu_group"])
    reported_group_gpus = rtx_topology.get("nvidia_gpu_bdfs_in_group")
    if (not isinstance(reported_group_gpus, list) or
            reported_group_gpus != sorted(set(reported_group_gpus)) or
            reported_group_gpus != group_gpus):
        raise ValueError("fresh RTX IOMMU GPU membership differs from the GPU ownership inventory")
    return rtx[0], vfio_gpus[0]


def validate_remote_report(remote: dict, snapshot: dict) -> dict:
    if not isinstance(remote, dict) or remote.get("schema") != REMOTE_SCHEMA:
        raise ValueError("unsupported PC3 VM assignment schema")
    if (remote.get("host") != "pc3" or remote.get("host") != snapshot.get("host") or
            remote.get("kernel_release") != snapshot.get("kernel_release") or
            remote.get("loaded_nvidia_module_version") !=
            snapshot.get("loaded_nvidia_module_version")):
        raise ValueError("PC3 VM assignment identity differs from the pinned host snapshot")
    if remote.get("system_state_changed") is not False:
        raise ValueError("VM assignment audit reports a system-state change")

    rtx_snapshot, vfio_gpu_snapshot = _snapshot_gpu_roles(snapshot)
    rtx_bdf = rtx_snapshot["pci"]
    vfio_gpu_bdf = vfio_gpu_snapshot["pci"]
    rtx_topology = rtx_snapshot["pci_topology"]
    group = remote.get("rtx5080_iommu_group")
    if (not isinstance(group, dict) or remote.get("rtx5080_bdf") != rtx_bdf or
            group.get("group_id") != rtx_topology["iommu_group"]):
        raise ValueError("RTX 5080 IOMMU group identity is invalid")
    members = group.get("members")
    member_fields = {"pci", "vendor_id", "device_id", "class", "driver"}
    if (not isinstance(members, list) or
            len(members) != rtx_topology["iommu_group_device_count"] or
            any(not isinstance(item, dict) or set(item) != member_fields or
                not isinstance(item.get("pci"), str) or not BDF_RE.fullmatch(item["pci"]) or
                _pci_id(item.get("vendor_id")) is None or
                _pci_id(item.get("device_id")) is None or
                not isinstance(item.get("class"), str) or
                not re.fullmatch(r"0x[0-9a-f]{6}", item["class"]) or
                (item.get("driver") is not None and
                 (not isinstance(item["driver"], str) or
                  not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", item["driver"])))
                for item in members) or
            [item["pci"] for item in members] != sorted({item["pci"] for item in members})):
        raise ValueError("RTX 5080 IOMMU group membership is malformed or incomplete")
    rtx_functions = [item for item in members if item["pci"] == rtx_bdf]
    if (len(rtx_functions) != 1 or _pci_id(rtx_functions[0]["vendor_id"]) != "10de" or
            _pci_id(rtx_functions[0]["device_id"]) != "2c02" or
            rtx_functions[0]["class"] != "0x030000" or rtx_functions[0]["driver"] != "nvidia"):
        raise ValueError("RTX 5080 host binding differs from the fresh host snapshot")
    snapshot_nvidia_members = {
        item["pci"]: item for item in snapshot["gpu_ownership"]
        if isinstance(item, dict) and isinstance(item.get("pci_topology"), dict) and
        item["pci_topology"].get("iommu_group") == rtx_topology["iommu_group"]
    }
    remote_nvidia_members = {item["pci"]: item for item in members
                             if _pci_id(item.get("vendor_id")) == "10de" and
                             item.get("class", "").startswith("0x03")}
    if set(remote_nvidia_members) != set(snapshot_nvidia_members):
        raise ValueError("RTX IOMMU group NVIDIA devices differ from the fresh host snapshot")
    for bdf, expected in snapshot_nvidia_members.items():
        observed = remote_nvidia_members[bdf]
        if (_pci_id(observed["device_id"]) != _pci_id(expected.get("device_id")) or
                observed["class"] != "0x" + str(expected.get("class", "")).lower() or
                observed["driver"] != expected.get("driver")):
            raise ValueError("RTX IOMMU group NVIDIA device identity differs from the fresh host snapshot")

    hypervisor = remote.get("hypervisor")
    expected_hypervisor_fields = {"virsh_available", "qm_available", "qemu_binary_available",
                                  "qemu_process_count", "instances"}
    if not isinstance(hypervisor, dict) or set(hypervisor) != expected_hypervisor_fields:
        raise ValueError("QEMU assignment metadata shape is invalid")
    for field in ("virsh_available", "qm_available", "qemu_binary_available"):
        if type(hypervisor[field]) is not bool:
            raise ValueError("hypervisor availability metadata is invalid")
    instances = hypervisor.get("instances")
    if (type(hypervisor.get("qemu_process_count")) is not int or
            hypervisor["qemu_process_count"] != 1 or not isinstance(instances, list) or
            len(instances) != 1 or hypervisor["qemu_binary_available"] is not True):
        raise ValueError("PC3 QEMU process inventory differs from the captured single-VM state")
    instance = instances[0]
    if not isinstance(instance, dict) or set(instance) != {
            "hostdev_bdfs", "cmdline_sha256", "recovery_channels"}:
        raise ValueError("QEMU assignment record exposes unexpected fields")
    bdfs = instance.get("hostdev_bdfs")
    digest = instance.get("cmdline_sha256")
    if (not isinstance(bdfs, list) or bdfs != sorted(set(bdfs)) or
            any(not isinstance(bdf, str) or not BDF_RE.fullmatch(bdf) for bdf in bdfs) or
            not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ValueError("QEMU PCI assignment or command digest is malformed")
    if vfio_gpu_bdf not in bdfs or any(item["pci"] in bdfs for item in members):
        raise ValueError("QEMU assignment does not preserve a VFIO GPU and host-bound RTX group")
    if any("argv" in item or "command_line" in item for item in instances):
        raise ValueError("raw QEMU command-line metadata must not be recorded")
    channels = instance.get("recovery_channels")
    channel_fields = {"monitor_transports", "qmp_transports", "serial_transports",
                      "monitor_unix_socket_fd_match", "qmp_unix_socket_fd_match",
                      "open_pty_fd_count", "fd_scan_complete", "systemd_managed",
                      "systemd_owner", "no_reboot_flag", "no_shutdown_flag"}
    if not isinstance(channels, dict) or set(channels) != channel_fields:
        raise ValueError("QEMU recovery-channel metadata shape is invalid")
    valid_transports = {"unix", "tcp", "telnet", "udp", "file", "pipe", "pty", "stdio",
                        "vc", "none", "null", "chardev", "ringbuf", "other"}
    for field in ("monitor_transports", "qmp_transports", "serial_transports"):
        values = channels.get(field)
        if (not isinstance(values, list) or values != sorted(set(values)) or
                any(not isinstance(value, str) or value not in valid_transports for value in values)):
            raise ValueError("QEMU recovery-channel transport list is malformed")
    for field in ("monitor_unix_socket_fd_match", "qmp_unix_socket_fd_match", "fd_scan_complete",
                  "systemd_managed", "no_reboot_flag", "no_shutdown_flag"):
        if type(channels.get(field)) is not bool:
            raise ValueError("QEMU recovery-channel flag is malformed")
    if channels["fd_scan_complete"] is not True:
        raise ValueError("QEMU recovery-channel FD scan is incomplete")
    if type(channels.get("open_pty_fd_count")) is not int or channels["open_pty_fd_count"] < 0:
        raise ValueError("QEMU pseudo-terminal count is malformed")
    owner = channels["systemd_owner"]
    owner_fields = {"unit_name", "query_complete", "active_state", "sub_state",
                    "restart_policy", "restart_delay", "kill_mode"}
    if not isinstance(owner, dict) or set(owner) != owner_fields or type(owner.get("query_complete")) is not bool:
        raise ValueError("QEMU systemd-owner metadata is malformed")
    unit = owner.get("unit_name")
    if unit is not None and (not isinstance(unit, str) or
                             not re.fullmatch(r"[A-Za-z0-9_.@:-]+", unit) or
                             not unit.endswith((".service", ".scope"))):
        raise ValueError("QEMU systemd unit identity is malformed")
    for field in ("active_state", "sub_state", "restart_policy", "restart_delay", "kill_mode"):
        value = owner.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 128 or
                                  re.search(r"[\x00-\x1f]", value)):
            raise ValueError("QEMU systemd property is malformed")
    if owner["query_complete"] and (unit is None or owner["active_state"] is None or
                                    owner["restart_policy"] is None):
        raise ValueError("QEMU systemd property set is incomplete")

    control_observed = channels["fd_scan_complete"] and (
        channels["monitor_unix_socket_fd_match"] or channels["qmp_unix_socket_fd_match"] or
        channels["open_pty_fd_count"] > 0)
    return {
        "schema": REPORT_SCHEMA,
        "status": "vm-assignment-observed",
        "host": "pc3",
        "kernel_release": snapshot["kernel_release"],
        "loaded_nvidia_module_version": snapshot["loaded_nvidia_module_version"],
        "rtx5080_bdf": rtx_bdf,
        "rtx5080_iommu_group": {"group_id": rtx_topology["iommu_group"], "members": members,
                                  "all_group_members_captured": True},
        "hypervisor": {"virsh_available": hypervisor["virsh_available"],
                       "qm_available": hypervisor["qm_available"],
                       "qemu_binary_available": hypervisor["qemu_binary_available"],
                       "qemu_process_count": hypervisor["qemu_process_count"],
                       "instances": instances},
        "host_control_channel_observed": control_observed,
        "qemu_unit_recovery_policy_observed": owner["restart_policy"] if owner["query_complete"] else None,
        "vm_reset_recovery_verified": False,
        "rtx5080_currently_assigned_to_vm": False,
        "vm_route_requires_rtx_and_audio_rebind": any(
            item["class"] == "0x040300" for item in members),
        "candidate_tested": False,
        "canary_ready": False,
        "state_changes": {"pc3_contacted": True, "system_or_vm_state_changed": False,
                          "pci_rebound": False, "qemu_reconfigured": False,
                          "candidate_loaded": False},
    }


def write_report(path: Path, report: dict, evidence_root: Path | None = None) -> None:
    path = Path(path)
    root = Path(evidence_root) if evidence_root is not None else ROOT / "evidence"
    root = root.resolve(strict=True)
    try:
        path.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        raise ValueError("VM assignment report must be inside the evidence tree") from None
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("VM assignment report destination is not a regular file")
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _remote_command(rtx_bdf: str) -> str:
    if not isinstance(rtx_bdf, str) or not BDF_RE.fullmatch(rtx_bdf):
        raise ValueError("RTX 5080 PCI address is invalid")
    return "sudo -n python3 -c " + shlex.quote(REMOTE_AUDIT_SCRIPT) + " " + shlex.quote(rtx_bdf)


def collect_remote(rtx_bdf: str, timeout: int = 90) -> dict:
    ssh_base = transport.pc3_direct_ssh_base(transport.DEFAULT_PC3_TARGET,
                                             transport.DEFAULT_HOST_KEY_ALIAS)
    try:
        result = subprocess.run(ssh_base + [_remote_command(rtx_bdf)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("direct read-only PC3 VM assignment query failed") from None
    if result.returncode != 0:
        raise RuntimeError("PC3 VM assignment query failed; stderr sha256=" +
                           hashlib.sha256(result.stderr).hexdigest())
    if len(result.stdout) > 1024 * 1024:
        raise RuntimeError("PC3 VM assignment report exceeds its size limit")
    report = json.loads(result.stdout.decode("utf-8", "strict"))
    if not isinstance(report, dict):
        raise RuntimeError("PC3 VM assignment query returned invalid JSON")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="create a new mode-0600 report under evidence; never overwrite")
    parser.add_argument("--direct-pc3", action="store_true",
                        help="required: use only the configured local SSH key and PC3 sudo -n")
    parser.add_argument("--host-snapshot", type=Path,
                        help="required: fresh mode-0600 PC3 host-state report from the direct collector")
    args = parser.parse_args(argv)
    try:
        if not args.direct_pc3:
            raise ValueError("this audit is PC3-direct-only; pass --direct-pc3")
        if args.host_snapshot is None:
            raise ValueError("--direct-pc3 requires a fresh --host-snapshot")
        snapshot, snapshot_sha256, snapshot_path = _read_current_host_snapshot(args.host_snapshot)
        rtx_snapshot, _ = _snapshot_gpu_roles(snapshot)
        remote = collect_remote(rtx_snapshot["pci"])
        result = validate_remote_report(remote, snapshot)
        result["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
        result["inputs"] = {"host_snapshot": {"path": snapshot_path,
                                              "sha256": snapshot_sha256}}
        result["audit_provenance"] = {
            "local_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "remote_script_sha256": hashlib.sha256(REMOTE_AUDIT_SCRIPT.encode()).hexdigest(),
            "transport": {"mode": "pc3-direct-key-sudo-n",
                          "target": transport.DEFAULT_PC3_TARGET,
                          "host_key_alias": transport.DEFAULT_HOST_KEY_ALIAS,
                          "sudo_value_logged": False, "sudo_value_persisted": False},
            "qualification": "read-only-pci-group-and-qemu-hostdev-metadata",
        }
        write_report(args.output, result)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print("PC3 VM assignment audit failed: " + str(error), file=sys.stderr)
        return 2
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"schema": REPORT_SCHEMA, "status": result["status"],
                      "canary_ready": result["canary_ready"],
                      "output": str(args.output.resolve()), "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
