#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the pinned R580 UVM consumer against the PC3 guest frontend ABI.

The build is deliberately compile-only. It verifies that the target guest's
R580.178.04 UVM consumer resolves its standard ``nvUvmInterface`` imports from
the exact hash-pinned hybrid ``nvidia`` frontend built for that guest kernel.
No module is installed or loaded, and this tool does not access a GPU.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PINNED_PC3 = "pc3@pc3"
PINNED_PC3_ALIAS = "pc3"
PINNED_GUEST = "pc3-v100"
PINNED_KERNEL = "6.8.0-147-generic"
FRONTEND_REPORT_SCHEMA = "nvidia-hybrid-pc3-v100-hybrid-frontend-build-capture-v1"
RESULT_SCHEMA = "nvidia-hybrid-pc3-v100-uvm-consumer-build-result-v1"
CAPTURE_SCHEMA = "nvidia-hybrid-pc3-v100-uvm-consumer-build-capture-v1"
MAX_BUNDLE = 256 * 1024 * 1024
MAX_RESULT = 48 * 1024 * 1024
MAX_ARTIFACT_ARCHIVE = 32 * 1024 * 1024
MAX_ARTIFACT = 96 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
PROBE_PATH = ROOT / "tools/probe_r580_uvm_isolated_execution.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned project build helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_frontend_module_symvers(report_path: Path, symvers_path: Path) -> tuple[Path, str, str]:
    """Bind a local artifact to the exact guest build receipt that produced it."""
    report_path = Path(report_path)
    symvers_path = Path(symvers_path)
    if report_path.is_symlink() or symvers_path.is_symlink():
        raise ValueError("frontend report and Module.symvers must not be symlinks")
    report_path = report_path.resolve(strict=True)
    symvers_path = symvers_path.resolve(strict=True)
    if not report_path.is_relative_to(ROOT) or not symvers_path.is_relative_to(ROOT):
        raise ValueError("frontend inputs must be inside the canonical project")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("schema") != FRONTEND_REPORT_SCHEMA:
        raise ValueError("frontend receipt schema is unsupported")
    if (report.get("target") != PINNED_PC3 or
            report.get("guest_hostname") != PINNED_GUEST or
            report.get("guest_kernel_release") != PINNED_KERNEL):
        raise ValueError("frontend receipt does not target the pinned V100 guest")
    if any(report.get(key) is not False for key in (
            "module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested")):
        raise ValueError("frontend receipt crossed the compile-only boundary")
    build_report = report.get("builder_report")
    if (not isinstance(build_report, dict) or build_report.get("module_name") != "nvidia" or
            build_report.get("built_module_identity", {}).get("matches") is not True):
        raise ValueError("frontend build report does not prove the standard nvidia module identity")
    artifacts = report.get("retrieved_artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("frontend receipt has no retrieved artifact manifest")
    relative = symvers_path.relative_to(ROOT).as_posix()
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("path") == relative]
    if len(matches) != 1:
        raise ValueError("Module.symvers is not uniquely listed in the frontend receipt")
    raw = symvers_path.read_bytes()
    digest = _sha256(raw)
    if (matches[0].get("sha256") != digest or
            matches[0].get("bytes") != len(raw) or len(raw) == 0):
        raise ValueError("frontend Module.symvers differs from its captured manifest")
    frontend_module = symvers_path.parent / "nvidia.ko"
    module_relative = frontend_module.relative_to(ROOT).as_posix()
    module_records = [item for item in artifacts
                      if isinstance(item, dict) and item.get("path") == module_relative]
    if len(module_records) != 1 or not frontend_module.is_file() or frontend_module.is_symlink():
        raise ValueError("frontend receipt does not include the paired nvidia.ko artifact")
    if (_file_sha256(frontend_module) != module_records[0].get("sha256") or
            frontend_module.stat().st_size != module_records[0].get("bytes")):
        raise ValueError("frontend nvidia.ko differs from its captured manifest")
    return symvers_path, digest, _sha256(report_path.read_bytes())


def input_bundle_paths(frontend_symvers: Path) -> tuple[Path, ...]:
    """Collect only pinned UVM build inputs and the selected frontend ABI."""
    probe = _load_module(PROBE_PATH, "pc3_uvm_probe_inputs")
    paths = {
        PROBE_PATH.resolve(strict=True),
        (ROOT / "tools/build_hybrid_frontend.py").resolve(strict=True),
        (ROOT / "tools/audit_uvm_owner_isolation_architecture.py").resolve(strict=True),
        (ROOT / "tools/audit_hybrid_uvm_abi.py").resolve(strict=True),
        (ROOT / "tools/audit_uvm_interface_ownership.py").resolve(strict=True),
        Path(probe.SOURCE_ARCHIVE).resolve(strict=True),
        Path(frontend_symvers).resolve(strict=True),
        *[Path(p).resolve(strict=True) for p in probe.PATCHES],
    }
    for path in paths:
        cursor = path
        while cursor != ROOT and cursor != cursor.parent:
            if cursor.is_symlink():
                raise ValueError("UVM build input path contains a symlink")
            cursor = cursor.parent
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise ValueError("UVM build input is outside the project or not a regular file")
    return tuple(sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix()))


def build_input_archive(paths: tuple[Path, ...], frontend_symvers: Path) -> tuple[bytes, list[dict[str, Any]]]:
    probe = _load_module(PROBE_PATH, "pc3_uvm_probe_archive_paths")
    frontend_symvers = Path(frontend_symvers).resolve(strict=True)
    archive_path = Path(probe.SOURCE_ARCHIVE).resolve(strict=True)
    mapping = {
        frontend_symvers: "build/experiments/pc3-v100-uvm-consumer-input/frontend-Module.symvers",
        archive_path: ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz",
    }
    seen: set[str] = set()
    manifest: list[dict[str, Any]] = []
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for path in paths:
            path = Path(path).resolve(strict=True)
            source_path = path.relative_to(ROOT).as_posix()
            archive_path_name = mapping.get(path, source_path)
            pure = PurePosixPath(archive_path_name)
            if pure.is_absolute() or ".." in pure.parts or archive_path_name in seen:
                raise ValueError("duplicate or unsafe UVM build input path")
            seen.add(archive_path_name)
            raw = path.read_bytes()
            if len(raw) > MAX_BUNDLE:
                raise ValueError("one UVM build input exceeds its size bound")
            info = tarfile.TarInfo(archive_path_name)
            info.size = len(raw)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
            manifest.append({"path": archive_path_name, "source_path": source_path,
                             "bytes": len(raw), "sha256": _sha256(raw)})
    bundle = payload.getvalue()
    if not bundle or len(bundle) > MAX_BUNDLE:
        raise ValueError("UVM build input archive is outside the size bound")
    return bundle, manifest


GUEST_BUILD_SCRIPT = r'''import base64,datetime,hashlib,io,json,os,platform,re,shutil,signal,subprocess,sys,tarfile
EXPECTED_HOST="pc3-v100"
EXPECTED_KERNEL="6.8.0-147-generic"
MAX_BUNDLE=268435456
MAX_ARTIFACT_ARCHIVE=33554432
MAX_CAPTURED_ARTIFACT=100663296
MAX_OUTPUT=16777216
run_id=sys.argv[3]
expected_sha=sys.argv[2]
if not re.fullmatch(r"[0-9a-f]{32}",run_id): raise SystemExit(2)
if platform.node()!=EXPECTED_HOST or platform.release()!=EXPECTED_KERNEL: raise SystemExit(3)
bundle_path="/tmp/codex-hybrid-uvm-"+run_id+".tar"
scratch="/tmp/codex-hybrid-uvm-"+run_id
created_bundle=False
created_scratch=False
def digest(data): return hashlib.sha256(data).hexdigest()
def safe_name(name):
 p=__import__("pathlib").PurePosixPath(name)
 return not p.is_absolute() and bool(p.parts) and all(x not in ("",".","..") for x in p.parts) and not any(ord(c)<32 for c in name)
try:
 if not re.fullmatch(r"[0-9a-f]{64}",expected_sha): raise ValueError("invalid bundle digest")
 data=sys.stdin.buffer.read(MAX_BUNDLE+1)
 if len(data)>MAX_BUNDLE or digest(data)!=expected_sha: raise ValueError("bundle digest or size mismatch")
 fd=os.open(bundle_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as out: out.write(data);out.flush();os.fsync(out.fileno())
 created_bundle=True
 os.mkdir(scratch,0o700);created_scratch=True
 with tarfile.open(bundle_path,"r:") as archive:
  members=archive.getmembers()
  if not members or len(members)>1000: raise ValueError("bundle member count is invalid")
  seen=set();total=0
  for member in members:
   if not safe_name(member.name) or member.name in seen or not member.isfile() or member.size>MAX_BUNDLE:
    raise ValueError("bundle contains an unsafe member")
   seen.add(member.name);total+=member.size
  if total>MAX_BUNDLE: raise ValueError("bundle expands beyond its size bound")
  archive.extractall(scratch,members=members,filter="data")
 root=scratch
 binding=os.path.join(root,"build/experiments/pc3-v100-uvm-consumer-input/frontend-Module.symvers")
 report_path=os.path.join(root,"evidence/pc3-v100-uvm-consumer-"+run_id+".json")
 scratch_build=os.path.join(root,"build/experiments/pc3-v100-uvm-consumer-"+run_id+"/scratch")
 log_path=os.path.join(root,"evidence/logs/pc3-v100-uvm-consumer-"+run_id+".log")
 os.makedirs(os.path.dirname(report_path),mode=0o700,exist_ok=True)
 os.makedirs(os.path.dirname(log_path),mode=0o700,exist_ok=True)
 os.makedirs(os.path.dirname(scratch_build),mode=0o700,exist_ok=True)
 frontend_sha=digest(open(binding,"rb").read())
 command=[sys.executable,os.path.join(root,"tools/probe_r580_uvm_isolated_execution.py"),
  "--scratch",scratch_build,"--report",report_path,"--log",log_path,
  "--kernel-release",EXPECTED_KERNEL,"--source-version","580.178.04","--jobs","4",
  "--frontend-module-symvers",binding,"--expected-frontend-symvers-sha256",frontend_sha,
  "--frontend-module-name","nvidia"]
 env={"PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TMPDIR":"/tmp"}
 build=subprocess.Popen(command,cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
 try:
  stdout,stderr=build.communicate(timeout=1800);exit_code=build.returncode
 except subprocess.TimeoutExpired:
  try: os.killpg(build.pid,signal.SIGTERM)
  except ProcessLookupError: pass
  try: build.communicate(timeout=5)
  except subprocess.TimeoutExpired: pass
  try: os.killpg(build.pid,signal.SIGKILL)
  except ProcessLookupError: pass
  stdout,stderr=build.communicate();exit_code=124
 if len(stdout)+len(stderr)>MAX_OUTPUT: raise ValueError("UVM builder output exceeded its bound")
 try:
  with open(report_path,"rb") as stream: report_raw=stream.read(8*1024*1024+1)
  if len(report_raw)>8*1024*1024: raise ValueError("UVM report exceeded its bound")
  report=json.loads(report_raw.decode("utf-8","strict"))
 except Exception: report=None
 artifacts=[]
 if report is not None:
  candidates=[report_path,log_path]
  for item in report.get("build",{}).get("modules",{}).values():
   if isinstance(item,dict) and isinstance(item.get("path"),str): candidates.append(item["path"])
  module=os.path.join(scratch_build,"NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm.ko")
  candidates.extend([module,module[:-3]+".mod.c",os.path.join(scratch_build,"NVIDIA-kernel-module-source-580.178.04/kernel-open/Module.symvers")])
  seen_paths=set()
  for path in candidates:
   try:
    real=os.path.realpath(path)
    if not real.startswith(os.path.realpath(root)+os.sep) or os.path.islink(path) or not os.path.isfile(path) or path in seen_paths: continue
    seen_paths.add(path);size=os.path.getsize(path)
    if size>MAX_CAPTURED_ARTIFACT: continue
    with open(path,"rb") as stream: content=stream.read(MAX_CAPTURED_ARTIFACT+1)
    if len(content)>MAX_CAPTURED_ARTIFACT: continue
    rel=os.path.relpath(path,root)
    if safe_name(rel): artifacts.append((rel,content))
   except OSError: continue
 packed=io.BytesIO()
 with tarfile.open(fileobj=packed,mode="w:gz",compresslevel=6) as output:
  for rel,content in artifacts:
   info=tarfile.TarInfo(rel);info.size=len(content);info.mode=0o600;info.mtime=0
   output.addfile(info,io.BytesIO(content))
 packed_bytes=packed.getvalue()
 if len(packed_bytes)>MAX_ARTIFACT_ARCHIVE: raise ValueError("captured UVM artifacts exceeded their bound")
 config_path="/lib/modules/"+EXPECTED_KERNEL+"/build/include/config/auto.conf"
 kernel_config={"path":config_path,"sha256":None,"selected_options":{},"readable":False}
 try:
  with open(config_path,"rb") as stream: config_raw=stream.read(8*1024*1024+1)
  if len(config_raw)>8*1024*1024: raise ValueError("kernel config exceeds its bound")
  kernel_config["sha256"]=digest(config_raw);kernel_config["readable"]=True
  for line in config_raw.decode("ascii","replace").splitlines():
   if line.startswith(("CONFIG_GENDWARFKSYMS=","CONFIG_DEBUG_INFO=","CONFIG_MODVERSIONS=","CONFIG_MODULES=")):
    name,value=line.split("=",1);kernel_config["selected_options"][name]=value
 except OSError: pass
 result={"schema":"nvidia-hybrid-pc3-v100-uvm-consumer-build-result-v1","status":"completed" if report is not None else "failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":exit_code,"builder_stdout_sha256":digest(stdout),"builder_stderr_sha256":digest(stderr),
  "builder_output_bytes":len(stdout)+len(stderr),"builder_report":report,
  "builder_report_sha256":digest(report_raw) if report is not None else None,"kernel_build_config":kernel_config,
  "artifacts":[{"path":p,"bytes":len(c),"sha256":digest(c)} for p,c in artifacts],
  "artifact_archive_bytes":len(packed_bytes),"artifact_archive_sha256":digest(packed_bytes),
  "artifact_archive_base64":base64.b64encode(packed_bytes).decode("ascii"),
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
 if report is None: result["error"]=(stderr+stdout).decode("utf-8","replace")[-4096:] or "UVM builder did not write a report"
 elif exit_code!=0: result["error"]="UVM consumer build did not qualify"
except Exception as error:
 result={"schema":"nvidia-hybrid-pc3-v100-uvm-consumer-build-result-v1","status":"failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":None,"builder_stdout_sha256":digest(b""),"builder_stderr_sha256":digest(b""),
  "builder_output_bytes":0,"builder_report":None,"builder_report_sha256":None,"kernel_build_config":{},"artifacts":[],
  "artifact_archive_bytes":0,"artifact_archive_sha256":digest(b""),"artifact_archive_base64":"",
  "error":type(error).__name__+": "+str(error)[:180],"module_installed":False,"module_loaded":False,
  "gpu_accessed":False,"cuda_execution_tested":False}
finally:
 if created_scratch:
  try: shutil.rmtree(scratch)
  except OSError: pass
 if created_bundle:
  try: os.unlink(bundle_path)
  except OSError: pass
if "result" not in locals(): raise SystemExit("missing result")
result["scratch_removed"]=not os.path.lexists(scratch)
result["staged_bundle_removed"]=not os.path.lexists(bundle_path)
print(json.dumps(result,separators=(",",":"),sort_keys=True))
'''


def validate_guest_result(raw: bytes, run_id: str, bundle_sha: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RESULT:
        raise ValueError("guest result size is invalid")
    result = json.loads(raw.decode("utf-8", "strict"))
    required = {
        "schema", "status", "run_id", "bundle_sha256", "hostname", "kernel_release",
        "builder_exit_code", "builder_stdout_sha256", "builder_stderr_sha256",
        "builder_output_bytes", "builder_report", "builder_report_sha256", "kernel_build_config",
        "artifacts", "artifact_archive_bytes", "artifact_archive_sha256", "artifact_archive_base64",
        "module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested",
        "scratch_removed", "staged_bundle_removed",
    }
    has_error = isinstance(result, dict) and "error" in result
    if not isinstance(result, dict) or set(result) != (required | {"error"} if has_error else required):
        raise ValueError("guest result fields differ from the pinned schema")
    if result["schema"] != RESULT_SCHEMA:
        raise ValueError("guest result schema is unsupported")
    if (result["run_id"] != run_id or result["bundle_sha256"] != bundle_sha or
            result["hostname"] != PINNED_GUEST or result["kernel_release"] != PINNED_KERNEL):
        raise ValueError("guest build identity differs from the pinned V100 target")
    if any(result[key] is not False for key in (
            "module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested")):
        raise ValueError("guest build crossed the compile-only boundary")
    if result["scratch_removed"] is not True or result["staged_bundle_removed"] is not True:
        raise ValueError("guest scratch cleanup is not verified")
    if result["status"] not in ("completed", "failed"):
        raise ValueError("guest build status is invalid")
    if result["status"] == "failed" and not has_error:
        raise ValueError("guest build failure has no detail")
    if has_error and (not isinstance(result["error"], str) or not result["error"] or len(result["error"]) > 4096):
        raise ValueError("guest failure detail is invalid")
    if result["status"] == "completed":
        report = result["builder_report"]
        if (not isinstance(report, dict) or report.get("schema") != "r580-uvm-isolated-gpu-execution-build-v5" or
                report.get("build", {}).get("kernel_release") != PINNED_KERNEL):
            raise ValueError("UVM report targets the wrong kernel or schema")
        if type(result["builder_exit_code"]) is not int:
            raise ValueError("guest builder exit code is invalid")
        if type(result["builder_output_bytes"]) is not int or not 0 <= result["builder_output_bytes"] <= MAX_OUTPUT:
            raise ValueError("guest builder output size is invalid")
        for key in ("builder_stdout_sha256", "builder_stderr_sha256", "artifact_archive_sha256", "builder_report_sha256"):
            if not isinstance(result[key], str) or re.fullmatch(r"[0-9a-f]{64}", result[key]) is None:
                raise ValueError(f"guest {key} is invalid")
        if not isinstance(result["artifacts"], list) or not result["artifacts"] or len(result["artifacts"]) > 16:
            raise ValueError("guest artifact manifest is invalid")
        names = set()
        for artifact in result["artifacts"]:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "bytes", "sha256"}:
                raise ValueError("guest artifact record is invalid")
            path = artifact["path"]
            pure = PurePosixPath(path) if isinstance(path, str) else None
            if pure is None or pure.is_absolute() or ".." in pure.parts or not path.startswith(("build/", "evidence/")):
                raise ValueError("guest artifact path is unsafe")
            if path in names or type(artifact["bytes"]) is not int or not 0 <= artifact["bytes"] <= MAX_ARTIFACT:
                raise ValueError("guest artifact record is duplicated or oversized")
            if not isinstance(artifact["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None:
                raise ValueError("guest artifact digest is invalid")
            names.add(path)
        if type(result["artifact_archive_bytes"]) is not int or not 0 < result["artifact_archive_bytes"] <= MAX_ARTIFACT_ARCHIVE:
            raise ValueError("guest artifact archive size is invalid")
        packed = base64.b64decode(result["artifact_archive_base64"], validate=True)
        if len(packed) != result["artifact_archive_bytes"] or _sha256(packed) != result["artifact_archive_sha256"]:
            raise ValueError("guest artifact archive digest or size mismatch")
        result["_packed_artifacts"] = packed
    return result


def extract_artifacts(result: dict[str, Any]) -> list[dict[str, Any]]:
    packed = result.get("_packed_artifacts")
    if not isinstance(packed, bytes):
        raise ValueError("validated artifact archive is missing")
    expected = {record["path"]: record for record in result["artifacts"]}
    extracted = []
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected):
            raise ValueError("guest artifact archive member count differs from manifest")
        for member in members:
            if member.name not in expected or not member.isfile():
                raise ValueError("guest artifact archive contains an unmanifested member")
            raw = archive.extractfile(member).read(MAX_ARTIFACT + 1)
            record = expected[member.name]
            if len(raw) != record["bytes"] or _sha256(raw) != record["sha256"]:
                raise ValueError("guest artifact hash differs from its manifest")
            destination = (ROOT / member.name).resolve()
            if not destination.is_relative_to(ROOT) or destination.exists() or destination.is_symlink():
                raise ValueError("local artifact destination is unsafe or already exists")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            extracted.append({"path": member.name, "bytes": len(raw), "sha256": record["sha256"]})
    return extracted


def collect(frontend_report_path: Path, frontend_symvers: Path) -> tuple[dict[str, Any], int]:
    relay = _load_module(ROOT / "tools/run_pc3_v100_private_open580_build.py", "pc3_uvm_transport_relay")
    transport = relay.load_transport()
    relay.validate_pc3_transport_identity(PINNED_PC3, PINNED_PC3_ALIAS)
    relay.verify_pc3_host_key()
    if (transport.DEFAULT_PC3_TARGET != PINNED_PC3 or
            transport.DEFAULT_HOST_KEY_ALIAS != PINNED_PC3_ALIAS or
            transport.DEFAULT_CREDENTIAL_HOST != relay.PINNED_CREDENTIAL_HOST or
            transport.DEFAULT_CREDENTIAL_FILE != relay.PINNED_CREDENTIAL_FILE):
        raise RuntimeError("canonical PC3 transport or credential source changed")
    symvers, frontend_symvers_sha, frontend_report_sha = load_frontend_module_symvers(
        frontend_report_path, frontend_symvers)
    paths = input_bundle_paths(symvers)
    bundle, pinned_inputs = build_input_archive(paths, symvers)
    bundle_sha = _sha256(bundle)
    run_id = uuid.uuid4().hex
    # The shared, pinned PC3 relay accepts only this staging-path namespace.
    stage_path = f"/tmp/codex-open580-{run_id}.tar"
    guest_code = GUEST_BUILD_SCRIPT.encode()
    guest_sha = _sha256(guest_code)
    upload_command = " ".join(shlex.quote(value) for value in
                               ["python3", "-c", relay.PC3_UPLOAD_SCRIPT, stage_path, bundle_sha])
    upload = subprocess.run(transport.pc3_ssh_base(PINNED_PC3, PINNED_PC3_ALIAS) + [upload_command],
                            input=bundle, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=600, check=False)
    if upload.returncode != 0:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 rejected the hash-pinned UVM build bundle")
    try:
        receipt = json.loads(upload.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 returned an invalid UVM bundle receipt") from None
    if receipt != {"bytes": len(bundle), "sha256": bundle_sha}:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 staging receipt differs from the local UVM bundle")
    try:
        secret = transport.fetch_pc3_sudo_secret(relay.PINNED_CREDENTIAL_HOST, relay.PINNED_CREDENTIAL_FILE)
        guest_b64 = base64.b64encode(guest_code).decode("ascii")
        root_command = "sudo -S -p '' python3 -c " + shlex.quote(relay.PC3_ROOT_RUN_SCRIPT) + " " + " ".join(
            shlex.quote(value) for value in (stage_path, bundle_sha, run_id, guest_b64, guest_sha))
        try:
            response = subprocess.run(transport.pc3_ssh_base(PINNED_PC3, PINNED_PC3_ALIAS) + [root_command],
                                      input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=2500, check=False)
        except (OSError, subprocess.TimeoutExpired):
            relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
            raise RuntimeError("isolated V100 UVM build relay timed out or disconnected") from None
    finally:
        secret = None
    if response.returncode != 0 or len(response.stdout) > MAX_RESULT * 2:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 returned a failed UVM build envelope")
    try:
        envelope = json.loads(response.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 returned an invalid UVM build envelope") from None
    cleanup_retried = False
    if isinstance(envelope, dict) and envelope.get("pc3_bundle_removed") is False:
        cleanup_retried = relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
    envelope = relay.validate_pc3_root_envelope(envelope, cleanup_verified=cleanup_retried)
    guest_raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    guest = validate_guest_result(guest_raw, run_id, bundle_sha)
    artifacts = extract_artifacts(guest) if guest["status"] == "completed" else []
    build_report = guest.get("builder_report") or {}
    build = build_report.get("build", {})
    binding = build.get("frontend_consumer_binding") or {}
    qualification = build_report.get("qualification", {}).get("level", "failed")
    success = (guest.get("status") == "completed" and guest.get("builder_exit_code") == 0 and
               qualification == "compiled-frontend-bound-uvm" and binding.get("passed") is True and
               build.get("module_identity", {}).get("module_name_matches") is True)
    capture = {
        "schema": CAPTURE_SCHEMA,
        "status": "compiled-frontend-bound-uvm" if success else "build-failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": PINNED_PC3,
        "guest_hostname": guest["hostname"],
        "guest_kernel_release": guest["kernel_release"],
        "run_id": run_id,
        "bundle": {"bytes": len(bundle), "sha256": bundle_sha,
                   "guest_script_sha256": guest_sha, "pinned_inputs": pinned_inputs,
                   "runner_sha256": _file_sha256(Path(__file__).resolve()),
                   "frontend_report": frontend_report_path.resolve().relative_to(ROOT).as_posix(),
                   "frontend_report_sha256": frontend_report_sha,
                   "frontend_module_symvers": symvers.relative_to(ROOT).as_posix(),
                   "frontend_module_symvers_sha256": frontend_symvers_sha},
        "qualification": qualification,
        "frontend_consumer_binding": binding,
        "build_failure": guest.get("error"),
        "builder_exit_code": guest.get("builder_exit_code"),
        "builder_report_sha256": guest.get("builder_report_sha256"),
        "builder_report": build_report,
        "kernel_build_config": guest.get("kernel_build_config"),
        "retrieved_artifacts": artifacts,
        "remote_scratch_removed": guest["scratch_removed"],
        "remote_bundle_removed": guest["staged_bundle_removed"],
        "pc3_stage_bundle_removed": envelope["pc3_bundle_removed"] or cleanup_retried,
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
    }
    return capture, 0 if success else 1


def _write_private_json(path: Path, value: dict[str, Any]) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return _sha256(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-report", required=True,
                        help="captured PC3 guest frontend build report containing nvidia.ko and Module.symvers")
    parser.add_argument("--frontend-module-symvers", required=True,
                        help="exact captured frontend Module.symvers artifact")
    parser.add_argument("--report", help="new private report path inside evidence/")
    args = parser.parse_args(argv)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = Path(args.report) if args.report else Path(f"evidence/pc3-v100-uvm-consumer-build-{stamp}.json")
    if not report_path.is_absolute():
        report_path = ROOT / report_path
    report_path = Path(os.path.abspath(report_path))
    if not report_path.is_relative_to(ROOT) or not report_path.is_relative_to(ROOT / "evidence"):
        parser.error("report destination must be under evidence/")
    try:
        frontend_report = Path(args.frontend_report)
        if not frontend_report.is_absolute(): frontend_report = ROOT / frontend_report
        frontend_symvers = Path(args.frontend_module_symvers)
        if not frontend_symvers.is_absolute(): frontend_symvers = ROOT / frontend_symvers
        capture, exit_code = collect(frontend_report, frontend_symvers)
    except Exception as error:
        capture = {"schema": CAPTURE_SCHEMA, "status": "preflight-failed",
                   "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "target": PINNED_PC3,
                   "failure": f"{type(error).__name__}: {str(error)[:240]}",
                   "module_installed": False, "module_loaded": False,
                   "gpu_accessed": False, "cuda_execution_tested": False}
        exit_code = 2
    digest = _write_private_json(report_path, capture)
    print(json.dumps({"report": str(report_path), "sha256": digest, "status": capture["status"],
                      "qualification": capture.get("qualification")}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
