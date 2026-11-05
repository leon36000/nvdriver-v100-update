#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Test the pinned R580 libcuda on PC3's RTX 5080 without replacing its driver.

The exact R580 compute-library package is already staged in PC3's private
canary directory. This runner verifies that package, extracts it into a fresh
private temporary directory with ``dpkg-deb -x`` (never runs package scripts),
and invokes the pinned CUDA probe through the ELF loader's isolated
``--library-path``. It does not install packages, load/unload modules, rebind
PCI devices, reset GPUs, or access the V100 guest.

This is a user-library/kernel-driver compatibility experiment only. A pass
does not qualify an R580 kernel module or a same-Linux Volta+Blackwell stack.
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
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = "pc3@pc3"
HOST_KEY_ALIAS = "pc3"
EXPECTED_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
EXPECTED_DRIVER = "595.99.02"
REMOTE_STAGE_DIR = "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33"
DEFAULT_REMOTE_STAGE_REPORT = ROOT / "evidence/pc3-r580-canary-local-deb-apt-simulation-v1-20261023T0956Z.json"
STAGE_REPORT_SHA256 = "1187b52e98a7b499bbe04f6326b901a434a34e76701e062ab51d5430dbe5091e"
PROBE_PATH = ROOT / "build/probe-pc3-rtx5080-event-close-v2-20261028/hybrid_cuda_probe"
PROBE_SHA256 = "df4ab2558a7315680eb55d91cfacd807926d0adf15d9835424e256a5eb43b71d"
MODULE_PATH = ROOT / "build/probe-pc3-rtx5080-event-close-v2-20261028/hybrid_probe.sm70-sm120.fatbin"
MODULE_SHA256 = "74cd97aabd47ab1abe720493bf54012a494472d9047b249d049300cda57e1741"
PACKAGE_MANIFEST = ROOT / "evidence/pc3-nvidia-canary-package-manifest-v1-20261023.json"
PACKAGE_MANIFEST_SHA256 = "8aa76d874bf9ebbf9fe0c5528b4fdeb9f932b17115232b0cdbb14f5470f6e764"
SIMULATION_SCHEMA = "pc3-r580-canary-local-deb-apt-simulation-v1"
EXPECTED_SIZES = [1, 31, 256, 4096, 65537]
MAX_REMOTE_OUTPUT = 512 * 1024

REMOTE_SCRIPT = r'''import base64, hashlib, json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

def run(argv, *, env=None, timeout=30):
    try:
        result=subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=env,
                              timeout=timeout, check=False)
        return {"exit_code":result.returncode,"stdout":result.stdout[:131072],
                "stderr":result.stderr[:8192],"timed_out":False}
    except subprocess.TimeoutExpired as error:
        return {"exit_code":124,"stdout":(error.stdout or "")[:131072],
                "stderr":(error.stderr or "")[:8192],"timed_out":True}

def digest_file(path):
    h=hashlib.sha256(); size=0
    with open(path,"rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):
            size+=len(block); h.update(block)
    return {"bytes":size,"sha256":h.hexdigest()}

def main():
    payload=json.load(sys.stdin)
    result={"schema":"pc3-r580-userland-rtx5080-probe-v1",
            "host":os.uname().nodename,"kernel":os.uname().release,
            "status":"not-run","package_scripts_run":False,
            "package_install_attempted":False,"driver_or_pci_modified":False,
            "module_load_or_unload_attempted":False,"gpu_reset_requested":False,
            "v100_guest_accessed":False,"cuda_probe":None,
            "remote_script_sha256":payload.get("remote_script_sha256"),
            "cleanup":{"attempted":False,"passed":False}}
    work=None
    try:
        if result["host"]!="pc3": raise ValueError("wrong remote host")
        if set(payload)!={"schema","remote_script_sha256","remote_package_path","remote_stage_dir",
                          "package_filename","package_sha256","package_size","probe","module","gpu_uuid","pci"}:
            raise ValueError("payload has missing or unexpected fields")
        if payload["schema"]!="pc3-r580-userland-rtx5080-payload-v1": raise ValueError("unsupported payload")
        import re
        if re.fullmatch(r"/var/tmp/codex-r580-canary-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}",payload["remote_stage_dir"]) is None:
            raise ValueError("remote stage directory escaped the private canary namespace")
        stage_path=Path(payload["remote_stage_dir"])
        if stage_path.is_symlink(): raise ValueError("remote stage directory must not be a symlink")
        stage=stage_path.resolve(strict=True)
        stage_stat=stage.stat()
        if not stat.S_ISDIR(stage_stat.st_mode) or stage_stat.st_uid!=os.getuid() or stage_stat.st_mode&0o077:
            raise ValueError("remote stage directory is not private and owned by the session user")
        target_dir=stage/"target"
        target_stat=target_dir.stat()
        if not stat.S_ISDIR(target_stat.st_mode) or target_stat.st_uid!=os.getuid() or target_stat.st_mode&0o077:
            raise ValueError("remote target directory is not private and owned by the session user")
        expected=stage/"target"/payload["package_filename"]
        package=Path(payload["remote_package_path"])
        if package!=expected or package.is_symlink(): raise ValueError("remote package path escaped the pinned stage")
        if package.name!="libnvidia-compute-580_580.196.07-1ubuntu1_amd64.deb": raise ValueError("wrong R580 compute package")
        ps=package.lstat()
        if not stat.S_ISREG(ps.st_mode) or ps.st_uid!=os.getuid() or ps.st_mode&0o077:
            raise ValueError("staged package is not a private regular file owned by the session user")
        package_identity=digest_file(package)
        if package_identity!={"bytes":payload["package_size"],"sha256":payload["package_sha256"]}:
            raise ValueError("staged package size or SHA-256 mismatch")
        metadata=run(["dpkg-deb","--field",str(package),"Package","Version","Architecture"])
        if metadata["exit_code"]!=0 or metadata["stdout"].splitlines()!=[
                "Package: libnvidia-compute-580","Version: 580.196.07-1ubuntu1","Architecture: amd64"]:
            raise ValueError("R580 package identity mismatch")
        result["package"]={"path":str(package),**package_identity,
                            "identity_verified":True,"package_scripts_run":False}

        gpu=run(["nvidia-smi","--query-gpu=name,uuid,pci.bus_id,driver_version",
                 "--format=csv,noheader,nounits"])
        if gpu["exit_code"]!=0: raise ValueError("baseline nvidia-smi failed")
        rows=[line.split(",") for line in gpu["stdout"].splitlines() if line.strip()]
        if len(rows)!=1 or len(rows[0])!=4: raise ValueError("unexpected PC3 GPU inventory")
        name,uuid,pci,driver=[field.strip() for field in rows[0]]
        if uuid!=payload["gpu_uuid"] or uuid!="GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77": raise ValueError("RTX UUID mismatch")
        if "RTX 5080" not in name or pci.replace("00000000:","0000:")!="0000:02:00.0": raise ValueError("RTX model or PCI identity mismatch")
        if driver!="595.99.02": raise ValueError("host driver changed from the pinned R595 baseline")
        apps=run(["nvidia-smi","--query-compute-apps=pid","--format=csv,noheader,nounits"])
        if apps["exit_code"]!=0: raise ValueError("could not confirm CUDA compute-process quiescence")
        pids=[line.strip() for line in apps["stdout"].splitlines()
              if line.strip() and "no running processes" not in line.lower()]
        if pids: raise ValueError("RTX 5080 has another compute process; refusing concurrent probe")
        result["gpu_before"]={"name":name,"uuid":uuid,"pci":pci,"kernel_driver":driver,
                               "compute_processes":pids,"identity_stdout":gpu["stdout"].strip()}

        work=Path(tempfile.mkdtemp(prefix="pc3-r580-userland-"))
        os.chmod(work,0o700)
        probe=work/"probe"; module=work/"module.fatbin"; extracted=work/"r580"
        for key,path in (("probe",probe),("module",module)):
            item=payload[key]
            data=base64.b64decode(item["base64"],validate=True)
            if len(data)!=item["bytes"] or hashlib.sha256(data).hexdigest()!=item["sha256"]:
                raise ValueError("uploaded artifact failed its pinned digest: "+key)
            with path.open("xb") as stream: stream.write(data)
            path.chmod(0o700 if key=="probe" else 0o600)
        unpack=run(["dpkg-deb","--extract",str(package),str(extracted)],timeout=90)
        if unpack["exit_code"]!=0: raise ValueError("private dpkg-deb data extraction failed")
        libdir=extracted/"usr/lib/x86_64-linux-gnu"
        libcuda=libdir/"libcuda.so.580.196.07"
        if libcuda.is_symlink() or not libcuda.is_file(): raise ValueError("R580 libcuda is absent or not a regular file")
        elf=run(["readelf","-h",str(libcuda)])
        if (elf["exit_code"]!=0 or "ELF64" not in elf["stdout"] or
                "Advanced Micro Devices X86-64" not in elf["stdout"]):
            raise ValueError("extracted libcuda is not the expected x86-64 ELF")
        result["user_library"]={"path":str(libcuda),**digest_file(libcuda),
                                "package_sha256":payload["package_sha256"],
                                "isolated_loader_path":str(libdir)}
        loader=Path("/lib64/ld-linux-x86-64.so.2")
        if not loader.exists(): raise ValueError("x86-64 dynamic loader is unavailable")
        clean={"PATH":"/usr/bin:/bin","LC_ALL":"C","CUDA_VISIBLE_DEVICES":uuid}
        def cuda_command(args, timeout):
            return run([str(loader),"--library-path",str(libdir),str(probe),*args],env=clean,timeout=timeout)
        listing=cuda_command(["--list","--expected-pci","0000:02:00.0"],35)
        result["inventory_probe"]={"exit_code":listing["exit_code"],"stdout":listing["stdout"],
                                   "stderr":listing["stderr"],"timed_out":listing["timed_out"]}
        if (listing["exit_code"]==2 and not listing["timed_out"] and
                "CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH)" in listing["stderr"]):
            result["status"]="compatibility-rejected"
            result["compatibility_outcome"]="r580-userland-r595-kernel-system-driver-mismatch"
        elif listing["exit_code"]!=0:
            raise ValueError("R580 libcuda initialization failed outside the recognized version-mismatch path")
        else:
            inventory=json.loads(listing["stdout"])
            if (inventory.get("schema")!="nvidia-hybrid-probe-v2" or inventory.get("status")!="inventory" or
                len(inventory.get("devices",[]))!=1 or inventory["devices"][0].get("sm")!=120 or
                inventory["devices"][0].get("pci_bus_id")!="0000:02:00.0" or
                not str(inventory.get("driver_library_path","")).startswith(str(libdir)+"/libcuda.so")):
                raise ValueError("R580 CUDA inventory did not resolve to the isolated library and RTX 5080")
            command=["--module",str(module),"--require-sm","70,120","--managed-memory",
                     "--managed-prefetch","--cuda-graphs","--expected-pci","0000:02:00.0"]
            probe_run=cuda_command(command,110)
            try: full=json.loads(probe_run["stdout"])
            except Exception: full={"invalid_json":True}
            result["inventory"]={"exit_code":listing["exit_code"],"report":inventory}
            result["cuda_probe"]={"exit_code":probe_run["exit_code"],"stdout":probe_run["stdout"],
                                  "stderr":probe_run["stderr"],"timed_out":probe_run["timed_out"],
                                  "report":full,"command":command}
            if probe_run["timed_out"]: raise ValueError("R580 user-library GPU probe timed out")
            result["status"]="probe-completed"
    except Exception as error:
        result["error"]=str(error)[:1000]
        result["status"]="probe-failed"
    finally:
        baseline=result.get("gpu_before")
        if baseline is not None and "gpu_after" not in result:
            after=run(["nvidia-smi","--query-gpu=name,uuid,pci.bus_id,driver_version",
                       "--format=csv,noheader,nounits"])
            result["gpu_after"]={"same_as_before":after["exit_code"]==0 and
                                 after["stdout"].strip()==baseline.get("identity_stdout"),
                                 "exit_code":after["exit_code"],
                                 "identity_stdout":after["stdout"].strip()}
        if work is not None:
            result["cleanup"]["attempted"]=True
            try: shutil.rmtree(work)
            except Exception: result["cleanup"]["passed"]=False
            else: result["cleanup"]["passed"]=not work.exists()
    print(json.dumps(result,sort_keys=True,separators=(",",":")))

main()
'''


def canonical_pci(value: str) -> str:
    match = re.fullmatch(r"(?:([0-9a-fA-F]{4})|([0-9a-fA-F]{8})):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match:
        raise ValueError("PCI identity is malformed")
    domain4, domain8, bus, slot, function = match.groups()
    if int(slot, 16) > 31:
        raise ValueError("PCI identity is malformed")
    return f"{int(domain4 or domain8,16)&0xffff:04x}:{int(bus,16):02x}:{int(slot,16):02x}.{function}"


def validate_remote_stage_dir(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(
            r"/var/tmp/codex-r580-canary-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}", value) is None:
        raise ValueError("remote stage directory is outside the pinned private canary namespace")
    return value


def validate_stage_report(path: Path, expected_stage_dir: str) -> dict:
    """Authenticate the exact reviewed dry-run before contacting PC3."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError("pinned stage report could not be safely opened") from error
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_mode & 0o077 or info.st_size > 1024 * 1024):
            raise ValueError("stage report must be a bounded private regular file owned by this user")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("stage report exceeds the bounded input size")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != STAGE_REPORT_SHA256:
        raise ValueError("stage report does not match its pinned SHA-256")
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("pinned stage report is not valid JSON") from error
    stage_dir = validate_remote_stage_dir(expected_stage_dir)
    if report.get("schema") != SIMULATION_SCHEMA:
        raise ValueError("pinned stage report has an unexpected schema")
    if report.get("remote_stage_dir") != stage_dir:
        raise ValueError("pinned stage report names a different stage directory")
    if (report.get("manifest_sha256") != PACKAGE_MANIFEST_SHA256 or
            report.get("package_install_invoked") is not False or
            report.get("driver_modified") is not False or
            report.get("maintainer_scripts_run") is not False or
            report.get("modules_loaded") is not False or
            report.get("pci_ownership_modified") is not False):
        raise ValueError("pinned stage report does not match the reviewed no-change package simulation")
    simulation = report.get("remote_summary", {}).get("apt_simulation")
    if (not isinstance(simulation, dict) or simulation.get("returncode") != 0 or
            simulation.get("download_or_install_performed") is not False or
            simulation.get("install_count") != 18 or simulation.get("remove_count") != 18):
        raise ValueError("pinned stage report lacks the expected 18-package APT simulation")
    return {
        "schema": report["schema"],
        "stage_report_sha256": digest,
        "remote_stage_dir": stage_dir,
        "install_count": simulation["install_count"],
        "remove_count": simulation["remove_count"],
        "manifest_sha256": report["manifest_sha256"],
    }


def validate_probe_result(report: object, exit_code: int, expected_pci: str,
                          expected_library_prefix: str) -> dict:
    if not isinstance(report, dict) or report.get("schema") != "nvidia-hybrid-probe-v2":
        raise ValueError("unexpected CUDA probe schema")
    if report.get("hybrid_validated") is not False:
        raise ValueError("R580 user-library experiment must not claim hybrid validation")
    if exit_code != 77 or report.get("status") != "incomplete":
        raise ValueError("expected the explicit missing-SM70 incomplete result")
    if report.get("required_sm") != [70, 120] or report.get("missing_sm") != [70]:
        raise ValueError("probe did not preserve the missing-Volta hybrid requirement")
    libpath = report.get("driver_library_path")
    if (not isinstance(libpath, str) or not Path(libpath).is_absolute() or
            not libpath.startswith(expected_library_prefix) or
            Path(libpath).name != "libcuda.so.580.196.07"):
        raise ValueError("probe did not load the pinned R580 libcuda")
    if type(report.get("driver_api")) is not int or report["driver_api"] <= 0:
        raise ValueError("probe lacks a valid R580 Driver API version")
    try:
        pci = canonical_pci(expected_pci)
    except ValueError as error:
        raise ValueError("expected PCI identity is malformed") from error
    devices = report.get("devices")
    if not isinstance(devices, list) or len(devices) != 1 or not isinstance(devices[0], dict):
        raise ValueError("R580 user-library probe must select exactly one GPU")
    device = devices[0]
    if canonical_pci(str(device.get("pci_bus_id", ""))) != pci:
        raise ValueError("R580 user-library probe selected a different PCI device")
    if device.get("sm") != 120 or "RTX 5080" not in str(device.get("name", "")):
        raise ValueError("R580 user-library probe selected a different GPU architecture")
    if device.get("targeted") is not True or device.get("tested") is not True:
        raise ValueError("RTX 5080 was enumerated but not exercised")
    for flag in ("architecture_kernel_passed", "synchronous_passed", "asynchronous_passed",
                 "managed_memory_passed", "managed_prefetch_passed", "cuda_graphs_passed"):
        if device.get(flag) is not True:
            raise ValueError("RTX 5080 did not pass " + flag)
    for key in ("synchronous_sizes", "asynchronous_sizes"):
        if device.get(key) != EXPECTED_SIZES:
            raise ValueError("RTX 5080 " + key + " did not match the pinned numeric suite")
    if device.get("cuda_graph_launches") != 2:
        raise ValueError("RTX 5080 did not pass both CUDA Graph replays")
    if device.get("cleanup_passed") is not True or device.get("cleanup_errors") != []:
        raise ValueError("RTX 5080 probe cleanup failed")
    if device.get("error") != "":
        raise ValueError("RTX 5080 probe reported a device error")
    return {
        "qualification": "rtx5080-r580-userland-only-hybrid-incomplete",
        "hybrid_validated": False,
        "rtx5080_kernel_passed": True,
        "driver_library_path": libpath,
        "driver_api": report["driver_api"],
        "pci": pci,
        "sm": 120,
        "numeric_sizes": EXPECTED_SIZES,
        "managed_memory_passed": True,
        "managed_prefetch_passed": True,
        "cuda_graph_launches": 2,
    }


def validate_mismatch_rejection(remote: object) -> dict:
    if not isinstance(remote, dict) or remote.get("status") != "compatibility-rejected":
        raise ValueError("remote result is not the recognized compatibility rejection")
    if remote.get("compatibility_outcome") != "r580-userland-r595-kernel-system-driver-mismatch":
        raise ValueError("remote result does not identify the pinned R580/R595 mismatch")
    inventory = remote.get("inventory_probe")
    if (not isinstance(inventory, dict) or inventory.get("exit_code") != 2 or
            inventory.get("timed_out") is not False or
            "CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH)" not in str(inventory.get("stderr", ""))):
        raise ValueError("R580 libcuda did not report the exact CUresult=803 mismatch")
    if remote.get("cuda_probe") is not None:
        raise ValueError("a mismatch-only result must not claim a kernel execution")
    before, after = remote.get("gpu_before"), remote.get("gpu_after")
    if (not isinstance(before, dict) or before.get("kernel_driver") != EXPECTED_DRIVER or
            before.get("uuid") != EXPECTED_UUID or not isinstance(after, dict) or
            after.get("same_as_before") is not True):
        raise ValueError("RTX 5080/R595 baseline was not preserved around the mismatch check")
    cleanup = remote.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("attempted") is not True or cleanup.get("passed") is not True:
        raise ValueError("R580 user-library scratch cleanup failed")
    library = remote.get("user_library")
    if (not isinstance(library, dict) or
            Path(str(library.get("path", ""))).name != "libcuda.so.580.196.07" or
            not re.fullmatch(r"[0-9a-f]{64}", str(library.get("sha256", "")))):
        raise ValueError("mismatch result lacks identity for the extracted R580 libcuda")
    return {
        "qualification": "r580-userland-r595-kernel-mismatch-rejected",
        "hybrid_validated": False,
        "rtx5080_kernel_passed": False,
        "cuda_context_created": False,
        "observed_error": "CUDA_ERROR_SYSTEM_DRIVER_MISMATCH (CUresult 803)",
        "finding": "R580 user space cannot pair with the R595 kernel driver on this host",
        "pci": EXPECTED_PCI,
        "kernel_driver": EXPECTED_DRIVER,
    }


def package_identity() -> dict:
    manifest_raw = PACKAGE_MANIFEST.read_bytes()
    if hashlib.sha256(manifest_raw).hexdigest() != PACKAGE_MANIFEST_SHA256:
        raise ValueError("pinned NVIDIA canary package manifest changed")
    manifest = json.loads(manifest_raw)
    entries = [item for item in manifest.get("packages", [])
               if item.get("transaction") == "target" and
               item.get("package") == "libnvidia-compute-580"]
    if len(entries) != 1:
        raise ValueError("pinned R580 compute package is missing or ambiguous")
    entry = entries[0]
    if (entry.get("version") != "580.196.07-1ubuntu1" or
            entry.get("architecture") != "amd64" or
            entry.get("filename") != "libnvidia-compute-580_580.196.07-1ubuntu1_amd64.deb"):
        raise ValueError("pinned R580 compute package identity changed")
    path = ROOT / ".cache/canary/pc3-r580-58019607/target" / entry["filename"]
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("local R580 compute package is not a private regular file")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
        raise ValueError("local R580 compute package differs from the pinned manifest")
    return {"path": str(path), "filename": entry["filename"], "bytes": size,
            "sha256": digest.hexdigest(), "package": entry["package"], "version": entry["version"]}


def remote_command() -> list[str]:
    return ["ssh", "-F", "/dev/null", "-T", "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oUserKnownHostsFile=" + str(Path.home() / ".ssh/known_hosts"),
            "-oHostKeyAlias=" + HOST_KEY_ALIAS, "-oConnectTimeout=10",
            "-oConnectionAttempts=1", "--", TARGET,
            "python3 -c " + shlex.quote(REMOTE_SCRIPT)]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--remote-stage-dir", default=REMOTE_STAGE_DIR)
    parser.add_argument("--remote-stage-report", type=Path, default=DEFAULT_REMOTE_STAGE_REPORT)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.evidence.exists() or args.evidence.is_symlink():
        raise SystemExit("evidence destination already exists")
    stage_dir = validate_remote_stage_dir(args.remote_stage_dir)
    try:
        stage_report_identity = validate_stage_report(args.remote_stage_report, stage_dir)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    package = package_identity()
    probe = PROBE_PATH.read_bytes()
    module = MODULE_PATH.read_bytes()
    if hashlib.sha256(probe).hexdigest() != PROBE_SHA256 or hashlib.sha256(module).hexdigest() != MODULE_SHA256:
        raise SystemExit("pinned CUDA probe or fatbin changed")
    probe_contract_path = ROOT / "tools/cuda_probe_contract.py"
    spec = importlib.util.spec_from_file_location("cuda_probe_contract_userland", probe_contract_path)
    if spec is None or spec.loader is None:
        raise SystemExit("CUDA probe contract validator unavailable")
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    probe_contract = contract.validate_probe_contract(PROBE_PATH, expected_sha256=PROBE_SHA256)
    payload = {
        "schema": "pc3-r580-userland-rtx5080-payload-v1",
        "remote_script_sha256": hashlib.sha256(REMOTE_SCRIPT.encode()).hexdigest(),
        "remote_package_path": stage_dir + "/target/" + package["filename"],
        "remote_stage_dir": stage_dir,
        "package_filename": package["filename"],
        "package_sha256": package["sha256"],
        "package_size": package["bytes"],
        "gpu_uuid": EXPECTED_UUID,
        "pci": EXPECTED_PCI,
        "probe": {"bytes": len(probe), "sha256": PROBE_SHA256,
                  "base64": base64.b64encode(probe).decode("ascii")},
        "module": {"bytes": len(module), "sha256": MODULE_SHA256,
                   "base64": base64.b64encode(module).decode("ascii")},
    }
    report = {
        "schema": "pc3-r580-userland-rtx5080-report-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": TARGET,
        "host_key_alias": HOST_KEY_ALIAS,
        "remote_stage_dir": stage_dir,
        "package": {key: package[key] for key in ("filename", "bytes", "sha256", "package", "version")},
        "probe": {"path": str(PROBE_PATH), "sha256": PROBE_SHA256, "contract": probe_contract},
        "fatbin": {"path": str(MODULE_PATH), "sha256": MODULE_SHA256},
        "remote_script_sha256": payload["remote_script_sha256"],
        "hardware_test_requested": True,
        "driver_or_pci_modified": False,
        "package_install_attempted": False,
        "module_load_or_unload_attempted": False,
        "v100_guest_accessed": False,
    }
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        result = subprocess.run(remote_command(), input=json.dumps(payload), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=240, check=False)
        report["ssh_exit_code"] = result.returncode
        report["ssh_stderr"] = result.stderr[:8192]
        report["ssh_stdout_sha256"] = hashlib.sha256(result.stdout.encode()).hexdigest()
        if len(result.stdout.encode()) > MAX_REMOTE_OUTPUT:
            raise ValueError("PC3 report exceeded the bounded output size")
        remote = json.loads(result.stdout)
        if remote.get("schema") != "pc3-r580-userland-rtx5080-probe-v1" or remote.get(
                "remote_script_sha256") != payload["remote_script_sha256"]:
            raise ValueError("PC3 returned an unexpected report or remote script identity")
        report["remote"] = remote
        cuda = remote.get("cuda_probe")
        if remote.get("status") == "compatibility-rejected":
            report["device_result"] = validate_mismatch_rejection(remote)
        elif remote.get("status") == "probe-completed" and isinstance(cuda, dict):
            report["device_result"] = validate_probe_result(
                cuda.get("report"), cuda.get("exit_code"), EXPECTED_PCI,
                remote["user_library"]["isolated_loader_path"] + "/")
        else:
            raise ValueError("R580 user-library probe did not complete: " + str(remote.get("error", "unknown remote error")))
        report["exit_code"] = 0
    except Exception as error:
        report["error"] = str(error)[:1200]
        report["exit_code"] = 2
    finally:
        try:
            data = json.dumps(report, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    print(json.dumps({"evidence": str(args.evidence), "exit_code": report["exit_code"],
                      "status": report.get("remote", {}).get("status", "transport-or-validation-failed")}))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
