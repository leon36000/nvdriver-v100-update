#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the pinned R580.196.07 libcuda on PC3's stock RTX 5080, process-local only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import run_pc3_rtx5080_ioctl_shape_reference as reference

TARGET = reference.EXPECTED_TARGET
HOST_KEY_ALIAS = reference.EXPECTED_HOST_KEY_ALIAS
EXPECTED_UUID = reference.EXPECTED_GPU_UUID
EXPECTED_PCI = reference.EXPECTED_PCI
EXPECTED_DRIVER = reference.EXPECTED_DRIVER
EXPECTED_KERNEL = reference.EXPECTED_KERNEL
EXPECTED_API = 13000
LIBCUDA_PATH = ROOT / "build/experiments/r58019607-runfile-extract-v1-20261029/NVIDIA-Linux-x86_64-580.196.07/libcuda.so.580.196.07"
LIBCUDA_BYTES = 96300904
LIBCUDA_SHA256 = "a5c77bf2de83c0ec06ecd368d224c3e0d653d658d6f99319921e976f21867b14"
SCHEMA = "nvidia-hybrid-pc3-rtx5080-r58019607-crossminor-v1"
REQUEST_SCHEMA = "nvidia-hybrid-pc3-rtx5080-r58019607-crossminor-request-v1"
SSH_OPTIONS = [
    "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
    "-o", "ConnectionAttempts=1", "-o", "HostKeyAlias=" + HOST_KEY_ALIAS,
]


REMOTE_SCRIPT = r'''import base64, hashlib, json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

EXPECTED_HOST="pc3"; EXPECTED_KERNEL="7.0.0-38-generic"
EXPECTED_UUID="GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI="0000:02:00.0"; EXPECTED_DRIVER="595.99.02"
EXPECTED_API=13000; REQUEST_SCHEMA="nvidia-hybrid-pc3-rtx5080-r58019607-crossminor-request-v1"
LIBCUDA_SHA256="a5c77bf2de83c0ec06ecd368d224c3e0d653d658d6f99319921e976f21867b14"
LIBCUDA_BYTES=96300904
PROBE_SHA256="38cd229ecee597b1a1f62871298dae900b5ff039b9ecca1388a72768fe880f6e"
FATBIN_SHA256="74cd97aabd47ab1abe720493bf54012a494472d9047b249d049300cda57e1741"
SAFE_ENV={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"}

def command(argv, timeout=20):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=timeout,check=False,shell=False,env=SAFE_ENV)
    if result.returncode: raise RuntimeError("read-only command failed: "+argv[0])
    return result.stdout.decode("utf-8","strict")

def digest(data): return hashlib.sha256(data).hexdigest()

def gpu_identity():
    import csv
    rows=list(csv.reader([x for x in command(["nvidia-smi","-i",EXPECTED_UUID,
        "--query-gpu=name,uuid,pci.bus_id,driver_version","--format=csv,noheader,nounits"]).splitlines() if x.strip()]))
    if len(rows)!=1 or len(rows[0])!=4: raise RuntimeError("GPU query malformed")
    name,uuid,pci,driver=[x.strip() for x in rows[0]]
    pci=pci.lower()
    if pci.startswith("00000000:"): pci=pci[4:]
    if (name!="NVIDIA GeForce RTX 5080" or uuid!=EXPECTED_UUID or pci!=EXPECTED_PCI or driver!=EXPECTED_DRIVER):
        raise RuntimeError("selected GPU identity mismatch")
    link=Path("/sys/bus/pci/devices")/EXPECTED_PCI/"driver"
    if not link.is_symlink() or link.resolve(strict=True).name!="nvidia": raise RuntimeError("GPU binding mismatch")
    return {"name":name,"uuid":uuid,"pci":pci,"driver_version":driver,"binding":"nvidia"}

def module_identity():
    version=Path("/sys/module/nvidia/version").read_text(encoding="ascii").strip()
    path=Path(command(["modinfo","-n","nvidia"]).strip()).resolve(strict=True)
    data=path.read_bytes()
    return {"loaded_version":version,"path":str(path),"sha256":digest(data),"bytes":len(data)}

def system_libcuda_identity():
    rows=[]
    for line in command(["ldconfig","-p"]).splitlines():
        if "libcuda.so.1" in line and "x86-64" in line and "=>" in line:
            rows.append(Path(line.split("=>",1)[1].strip()))
    if len(rows)!=1: raise RuntimeError("system libcuda resolution ambiguous")
    path=rows[0].resolve(strict=True); data=path.read_bytes()
    return {"path":str(path),"sha256":digest(data),"bytes":len(data)}

def compute_pids():
    output=command(["nvidia-smi","-i",EXPECTED_UUID,"--query-compute-apps=pid","--format=csv,noheader,nounits"])
    pids=[]
    for line in output.splitlines():
        value=line.strip()
        if not value or value.lower().startswith("no running processes"): continue
        if not value.isdigit(): raise RuntimeError("compute-process query malformed")
        pids.append(int(value))
    return sorted(set(pids))

def write_exact(path, data, executable=False):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(path,flags,0o700 if executable else 0o600)
    with os.fdopen(fd,"wb") as stream: stream.write(data)

def main():
    report={"schema":"nvidia-hybrid-pc3-rtx5080-r58019607-crossminor-remote-v1",
      "status":"failed","hostname":None,"kernel_release":None,"gpu_before":None,"gpu_after":None,
      "module_before":None,"module_after":None,"system_libcuda_before":None,"system_libcuda_after":None,
      "compute_pids_before":None,"compute_pids_after":None,"staged_artifacts":{},
      "staged_libcuda_path":None,"phase":None,
      "probe_exit_code":None,"cleanup_passed":False,"workspace_removed":False,
      "execution_scope":{"driver_or_module_changed":False,"pci_binding_changed":False,
                         "vm_management_issued":False,"gpu_reset_requested":False}}
    work=None; before=None
    try:
        request=json.load(sys.stdin)
        if request.get("schema")!=REQUEST_SCHEMA or set(request)!={"schema","artifacts"}:
            raise RuntimeError("request schema invalid")
        artifacts=request["artifacts"]
        if set(artifacts)!={"probe","fatbin","libcuda"}: raise RuntimeError("artifact set invalid")
        raw={}
        limits={"probe":(2*1024*1024,PROBE_SHA256),"fatbin":(2*1024*1024,FATBIN_SHA256),
                "libcuda":(LIBCUDA_BYTES,LIBCUDA_SHA256)}
        for name,item in artifacts.items():
            data=base64.b64decode(item.get("base64",""),validate=True)
            limit,expected=limits[name]
            if len(data)!=item.get("bytes") or len(data)>limit or digest(data)!=item.get("sha256") or expected!=item.get("sha256"):
                raise RuntimeError("staged artifact hash/size mismatch")
            raw[name]=data; report["staged_artifacts"][name]={"bytes":len(data),"sha256":digest(data)}
        report["hostname"]=os.uname().nodename; report["kernel_release"]=os.uname().release
        before={"gpu":gpu_identity(),"module":module_identity(),"system_libcuda":system_libcuda_identity()}
        report["gpu_before"]=before["gpu"]; report["module_before"]=before["module"]
        report["system_libcuda_before"]=before["system_libcuda"]
        if report["hostname"]!=EXPECTED_HOST or report["kernel_release"]!=EXPECTED_KERNEL or before["module"]["loaded_version"]!=EXPECTED_DRIVER:
            raise RuntimeError("PC3 host stack identity mismatch")
        pids=compute_pids(); report["compute_pids_before"]=pids
        if pids:
            report["status"]="skipped-busy"; report["error"]="selected GPU has active compute processes"
            report["cleanup_passed"]=True; report["workspace_removed"]=True
            print(json.dumps(report,sort_keys=True)); return 0
        work=Path(tempfile.mkdtemp(prefix="codex-rtx5080-r580196-")); work.chmod(0o700)
        libdir=work/"lib"; libdir.mkdir(mode=0o700)
        probe=work/"hybrid_cuda_probe"; fatbin=work/"hybrid_probe.sm70-sm120.fatbin"
        libcuda=libdir/"libcuda.so.1"
        write_exact(probe,raw["probe"],True); write_exact(fatbin,raw["fatbin"]); write_exact(libcuda,raw["libcuda"])
        report["staged_libcuda_path"]=str(libcuda)
        artifacts_before={str(path):{"bytes":path.stat().st_size,"sha256":digest(path.read_bytes())}
                          for path in (probe,fatbin,libcuda)}
        env={"PATH":"/usr/bin:/bin","LC_ALL":"C","CUDA_VISIBLE_DEVICES":EXPECTED_UUID,
             "LD_LIBRARY_PATH":str(libdir)}
        pids=compute_pids(); report["compute_pids_prelaunch"]=pids
        if pids: raise RuntimeError("selected GPU became busy before CUDA phase")
        argv=[str(probe),"--phase","kernel","--expected-pci",EXPECTED_PCI,"--module",str(fatbin)]
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=120,check=False,shell=False,env=env)
        report["probe_exit_code"]=result.returncode
        report["probe_stdout_sha256"]=digest(result.stdout); report["probe_stdout_bytes"]=len(result.stdout)
        report["probe_stderr_sha256"]=digest(result.stderr); report["probe_stderr_bytes"]=len(result.stderr)
        if len(result.stdout)>256*1024 or len(result.stderr)>64*1024: raise RuntimeError("probe output exceeds limit")
        phase=json.loads(result.stdout.decode("utf-8","strict").strip())
        report["phase"]=phase
        if result.returncode: raise RuntimeError("CUDA probe returned nonzero")
        if (phase.get("status")!="phase-passed" or phase.get("phase")!="kernel" or
            phase.get("driver_api")!=EXPECTED_API or phase.get("driver_library_path")!=str(libcuda) or
            phase.get("expected_pci")!=EXPECTED_PCI or phase.get("numeric_result_passed") is not True or
            phase.get("result_value")!=1200 or phase.get("expected_result")!=1200 or
            phase.get("cleanup_passed") is not True or phase.get("cleanup_errors")!=[] or phase.get("error")!=""):
            raise RuntimeError("probe result did not satisfy pinned R580/SM120 kernel contract")
        ops=set(phase.get("completed_operations",[]))
        required={"cuInit","cuDriverGetVersion","cuDeviceGetCount","cuDeviceGet","cuCtxCreate_v2",
                  "cuModuleLoad","cuModuleGetFunction(hybrid_arch)","cuMemAlloc_v2",
                  "cuLaunchKernel(hybrid_arch)","cuCtxSynchronize","cuMemcpyDtoH_v2"}
        if not required.issubset(ops): raise RuntimeError("required Driver API operations missing")
        if not isinstance(phase.get("selected_device"),dict) or phase["selected_device"].get("sm")!=120:
            raise RuntimeError("probe selected device is not SM120")
        report["compute_pids_after"]=compute_pids()
        after={"gpu":gpu_identity(),"module":module_identity(),"system_libcuda":system_libcuda_identity()}
        report["gpu_after"]=after["gpu"]; report["module_after"]=after["module"]
        report["system_libcuda_after"]=after["system_libcuda"]
        if before!=after: raise RuntimeError("host GPU, module, or system libcuda identity changed")
        if report["compute_pids_after"]: raise RuntimeError("compute process remains after probe")
        report["staged_artifacts_after"]={str(path):{"bytes":path.stat().st_size,"sha256":digest(path.read_bytes())}
                                           for path in (probe,fatbin,libcuda)}
        if report["staged_artifacts_after"]!=artifacts_before: raise RuntimeError("staged input changed")
        report["cleanup_passed"]=True; report["status"]="complete"
    except Exception as exc:
        report["error"]=type(exc).__name__+":"+str(exc)[:200]
    finally:
        if before is not None and report["compute_pids_after"] is None:
            try: report["compute_pids_after"]=compute_pids()
            except Exception: report["compute_pids_after"]=-1
        if before is not None and report["gpu_after"] is None:
            try:
                report["gpu_after"]=gpu_identity(); report["module_after"]=module_identity()
                report["system_libcuda_after"]=system_libcuda_identity()
                report["execution_scope"]["driver_or_module_changed"]=before["module"]!=report["module_after"]
                report["execution_scope"]["pci_binding_changed"]=before["gpu"]!=report["gpu_after"]
            except Exception: pass
        if work is not None:
            try:
                tmp=Path(tempfile.gettempdir()).resolve(strict=True); info=work.lstat()
                if (work.name.startswith("codex-rtx5080-r580196-") and work.parent.resolve(strict=True)==tmp
                    and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                    and info.st_uid==os.geteuid() and info.st_mode&0o077==0): shutil.rmtree(work)
                report["workspace_removed"]=not work.exists()
            except Exception: report["workspace_removed"]=False
        if before is not None:
            report["cleanup_passed"] = (report["workspace_removed"] is True and
                                          report["compute_pids_after"] == [])
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"] in ("complete","skipped-busy") else 2

sys.exit(main())
'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_libcuda(path: Path) -> dict[str, object]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("pinned R580.196.07 libcuda is unavailable") from exc
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        if (not stat.S_ISREG(info.st_mode) or path.name != "libcuda.so.580.196.07" or
                info.st_size != LIBCUDA_BYTES or digest.hexdigest() != LIBCUDA_SHA256):
            raise ValueError("libcuda differs from the exact R580.196.07 pin")
    return {"path": str(path.resolve(strict=True)), "bytes": info.st_size,
            "sha256": LIBCUDA_SHA256}


def validate_remote(report: object) -> dict[str, object]:
    def require(ok: bool, message: str) -> None:
        if not ok:
            raise ValueError(message)

    require(isinstance(report, dict) and report.get("schema") ==
            "nvidia-hybrid-pc3-rtx5080-r58019607-crossminor-remote-v1",
            "remote report schema mismatch")
    require(report.get("status") in ("complete", "failed") and report.get("hostname") == "pc3" and
            report.get("kernel_release") == EXPECTED_KERNEL, "PC3 host identity/status mismatch")
    gpu = report.get("gpu_before")
    require(isinstance(gpu, dict) and gpu.get("uuid") == EXPECTED_UUID and
            gpu.get("pci") == EXPECTED_PCI and gpu.get("driver_version") == EXPECTED_DRIVER and
            gpu.get("binding") == "nvidia" and report.get("gpu_after") == gpu,
            "RTX 5080 identity changed or mismatched")
    module = report.get("module_before")
    require(isinstance(module, dict) and module.get("loaded_version") == EXPECTED_DRIVER and
            report.get("module_after") == module, "R595 kernel module identity changed")
    system_libcuda = report.get("system_libcuda_before")
    require(isinstance(system_libcuda, dict) and report.get("system_libcuda_after") == system_libcuda,
            "system libcuda identity changed")
    staged = report.get("staged_artifacts")
    require(isinstance(staged, dict) and set(staged) == {"probe", "fatbin", "libcuda"} and
            staged["libcuda"] == {"bytes": LIBCUDA_BYTES, "sha256": LIBCUDA_SHA256} and
            staged["probe"].get("sha256") == reference.EXPECTED_ARTIFACTS["probe"][1] and
            staged["fatbin"].get("sha256") == reference.EXPECTED_ARTIFACTS["fatbin"][1],
            "remote staged artifacts mismatch")
    require(report.get("compute_pids_before") == [] and report.get("compute_pids_prelaunch") == [] and
            report.get("compute_pids_after") == [], "RTX 5080 compute-process guard failed")
    phase = report.get("phase")
    require(isinstance(phase, dict) and isinstance(report.get("staged_libcuda_path"), str) and
            phase.get("driver_library_path") == report.get("staged_libcuda_path"),
            "probe did not resolve the staged R580.196.07 library")
    require(report.get("cleanup_passed") is True and report.get("workspace_removed") is True and
            isinstance(report.get("execution_scope"), dict) and
            all(value is False for value in report["execution_scope"].values()),
            "remote cleanup or no-system-change assertion failed")
    if (report.get("status") == "failed" and report.get("probe_exit_code") == 2 and
            phase.get("status") == "phase-failed" and phase.get("driver_api") is None and
            phase.get("completed_operations") == [] and
            phase.get("error") == "cuInit failed with CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH): system has unsupported display driver / cuda driver combination"):
        return {"qualification": "r58019607-libcuda-rejected-by-stock-r595-system-driver-mismatch",
                "hybrid_validated": False, "kernel_passed": False,
                "failure_location": "cuInit", "cuda_result": 803,
                "incompatibility": "CUDA_ERROR_SYSTEM_DRIVER_MISMATCH"}
    require(report.get("status") == "complete" and phase.get("status") == "phase-passed" and
            phase.get("phase") == "kernel" and
            phase.get("driver_api") == EXPECTED_API and phase.get("result_value") == 1200 and
            phase.get("expected_result") == 1200 and phase.get("numeric_result_passed") is True,
            "R580.196.07 SM120 kernel result mismatch")
    device = phase.get("selected_device")
    require(isinstance(device, dict) and
            isinstance(device.get("name"), str) and
            device["name"].startswith("NVIDIA GeForce RTX 5080") and
            reference.canonical_pci(device.get("pci_bus_id", "")) == EXPECTED_PCI and
            device.get("sm") == 120 and device.get("compute_capability") == "12.0",
            "kernel result did not identify the selected SM120 RTX 5080")
    operations = phase.get("completed_operations")
    require(isinstance(operations, list) and {
        "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuCtxCreate_v2",
        "cuModuleLoad", "cuMemAlloc_v2", "cuLaunchKernel(hybrid_arch)",
        "cuCtxSynchronize", "cuMemcpyDtoH_v2"}.issubset(operations),
        "R580.196.07 kernel phase omitted required CUDA operations")
    return {"qualification": "r58019607-libcuda-on-stock-r595-rtx5080-kernel-validated",
            "hybrid_validated": False, "kernel_passed": True,
            "driver_api": EXPECTED_API, "gpu": "RTX 5080 SM120", "kernel_result": 1200}


def run(argv: list[str] | None = None, invoke=subprocess.run) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, default=reference.EXPECTED_ARTIFACTS["probe"][0])
    parser.add_argument("--fatbin", type=Path, default=reference.EXPECTED_ARTIFACTS["fatbin"][0])
    parser.add_argument("--libcuda", type=Path, default=LIBCUDA_PATH)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    report = {"schema": SCHEMA, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": TARGET, "host_key_alias": HOST_KEY_ALIAS, "expected_gpu_uuid": EXPECTED_UUID,
        "expected_pci": EXPECTED_PCI, "expected_kernel": EXPECTED_KERNEL,
        "expected_kernel_driver": EXPECTED_DRIVER, "expected_user_libcuda": "580.196.07",
        "exit_code": 2, "qualification": "failed", "local_artifacts": {}}
    paths = {"probe": args.probe, "fatbin": args.fatbin, "libcuda": args.libcuda}
    try:
        reference.validate_probe_build(args.probe.resolve(strict=True))
        pinned = pinned_libcuda(args.libcuda)
        request_artifacts = {}
        for name, path in paths.items():
            data = path.read_bytes()
            expected = (LIBCUDA_SHA256 if name == "libcuda" else
                        reference.EXPECTED_ARTIFACTS[name][1])
            if sha256_bytes(data) != expected:
                raise ValueError(name + " differs from pinned input")
            request_artifacts[name] = {"base64": base64.b64encode(data).decode("ascii"),
                "sha256": expected, "bytes": len(data)}
            report["local_artifacts"][name] = {"path": str(path.resolve()),
                "sha256": expected, "bytes": len(data)}
        report["user_libcuda_pin"] = pinned
        request = {"schema": REQUEST_SCHEMA, "artifacts": request_artifacts}
        command = SSH_OPTIONS + ["--", TARGET, "python3 -c " + shlex.quote(REMOTE_SCRIPT)]
        report["remote_script_sha256"] = sha256_bytes(REMOTE_SCRIPT.encode())
        result = invoke(command, input=json.dumps(request), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=240, check=False, shell=False)
        report["ssh_exit_code"] = result.returncode
        report["ssh_stdout_sha256"] = sha256_bytes(result.stdout.encode("utf-8", "replace"))
        report["ssh_stdout_bytes"] = len(result.stdout.encode("utf-8", "replace"))
        report["ssh_stderr_sha256"] = sha256_bytes(result.stderr.encode("utf-8", "replace"))
        report["ssh_stderr_bytes"] = len(result.stderr.encode("utf-8", "replace"))
        if len(result.stdout.encode("utf-8", "replace")) > 512 * 1024:
            raise ValueError("remote report exceeds output bound")
        remote = json.loads(result.stdout.strip())
        report["remote"] = remote
        if remote.get("status") == "skipped-busy":
            report["qualification"] = "rtx5080-test-skipped-busy"
            report["exit_code"] = 77
        else:
            report["remote_qualification"] = validate_remote(remote)
            expected_rejection = report["remote_qualification"]["qualification"].endswith(
                "rejected-by-stock-r595-system-driver-mismatch")
            if result.returncode != (2 if expected_rejection else 0):
                raise ValueError("remote worker returned nonzero")
            report["qualification"] = report["remote_qualification"]["qualification"]
            report["exit_code"] = 0
    except Exception as exc:
        report["error"] = type(exc).__name__ + ":" + str(exc)[:240]
    finally:
        report["local_artifacts_after"] = {}
        for name, path in paths.items():
            try:
                data = path.read_bytes()
                report["local_artifacts_after"][name] = {"bytes": len(data), "sha256": sha256_bytes(data)}
            except OSError:
                report["local_artifacts_after"][name] = None
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True); stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({"evidence": str(args.evidence), "exit_code": report["exit_code"],
                      "qualification": report["qualification"]}, sort_keys=True))
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(run())
