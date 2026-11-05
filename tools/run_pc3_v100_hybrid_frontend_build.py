#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the R580-ABI hybrid frontend on PC3's isolated V100 guest.

This stages only pinned project inputs and builds ``nvidia.ko`` against the
guest's exact 6.8.0-147 kernel headers and the already compiled private R580
providers. It never installs or loads a module, changes a device binding, or
executes CUDA.
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
PINNED_KERNEL = "6.8.0-147-generic"
PINNED_GUEST = "pc3-v100"
PINNED_PC3 = "pc3@pc3"
PINNED_PC3_ALIAS = "pc3"
MAX_BUNDLE = 256 * 1024 * 1024
MAX_RESULT = 48 * 1024 * 1024
MAX_ARTIFACT_ARCHIVE = 32 * 1024 * 1024
MAX_ARTIFACT = 64 * 1024 * 1024
MAX_ARTIFACT_COUNT = 64
MAX_OUTPUT = 16 * 1024 * 1024
EXPECTED_QUALIFICATION = "compiled-bdf-selected-gpu-file-frontend-kernel-module"
BUILD_TOOL = ROOT / "tools/build_hybrid_frontend.py"
TEST_INPUTS = (
    "tests/test_hybrid_frontend.py",
    "tests/test_hybrid_frontend_gpu.py",
    "tests/test_hybrid580_system_pm_coordinator.py",
    "tests/test_nvidia_hibernate_pm.py",
    "tests/test_uvm_pm_lifecycle_audit.py",
    "tests/test_hybrid580_frontend_admission.py",
    "tests/test_backend_device_ids_api.py",
    "tests/test_usermode_object.py",
    "tests/test_device_instance_map.py",
    "tests/test_standard_node_map.py",
    "tests/test_standard_node_devices.py",
    "tests/test_hybrid580_uvm_callback_bridge.py",
    "tests/test_hybrid580_uvm_event_compat.py",
    "tests/test_hybrid580_uvm_session_pair.py",
    "tests/test_hybrid580_uvm_gpu_registry.py",
    "tests/test_hybrid580_uvm_gpu_route.py",
    "tests/test_hybrid580_uvm_gpu_info_route.py",
    "tests/test_hybrid580_uvm_device_route.py",
    "tests/test_hybrid580_uvm_address_space_route.py",
    "tests/test_hybrid580_uvm_dup_memory_route.py",
    "tests/test_hybrid580_uvm_pma_route.py",
    "tests/test_hybrid580_uvm_external_mapping_route.py",
    "tests/test_hybrid580_uvm_info_registry.py",
    "tests/test_build_hybrid_frontend.py",
    "tests/fixtures/device_instance_map_contract.c",
    "tests/fixtures/hybrid580_uvm_callback_bridge_test.c",
    "tests/fixtures/hybrid580_uvm_event_compat_test.c",
    "tests/fixtures/hybrid580_uvm_session_pair_test.c",
    "tests/fixtures/hybrid580_uvm_gpu_registry_test.c",
    "tests/fixtures/hybrid580_uvm_gpu_route_test.c",
    "tests/fixtures/hybrid580_uvm_gpu_info_route_test.c",
    "tests/fixtures/hybrid580_uvm_device_route_test.c",
    "tests/fixtures/hybrid580_uvm_address_space_route_test.c",
    "tests/fixtures/hybrid580_uvm_dup_memory_route_test.c",
    "tests/fixtures/hybrid580_uvm_pma_route_test.c",
    "tests/fixtures/hybrid580_uvm_external_mapping_route_test.c",
    "tests/fixtures/hybrid580_uvm_info_registry_test.c",
    "tests/fixtures/standard_node_map_contract.c",
    "tests/fixtures/standard_node_devices_contract.c",
    "tests/fixtures/hybrid580_frontend_admission_test.c",
)
INCLUDE_DIRS = (
    "kernel-open/common/inc",
    "kernel-open",
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    "src/common/inc/swref",
    "src/nvidia/arch/nvalloc/unix/include",
)
HEADER_SUFFIXES = {".h", ".inc", ".inl", ".cuh", ".def"}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned build helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _add_regular_file(paths: set[Path], path: Path) -> None:
    candidate = path.absolute()
    cursor = candidate
    while cursor != ROOT and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("build input path contains a symlink")
        cursor = cursor.parent
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(ROOT) or not resolved.is_file():
        raise ValueError("build input is outside the canonical project or not a regular file")
    paths.add(resolved)


def input_bundle_paths(target_conftest: dict[str, Path] | None = None,
                       target_open_symvers: Path | None = None,
                       target_legacy_symvers: Path | None = None) -> tuple[Path, ...]:
    """Collect the exact frontend sources, tests, and R580 ABI inputs."""
    frontend = _load_module(BUILD_TOOL, "hybrid_frontend_build_input")
    open_tree, legacy_tree = frontend.default_provider_trees("r580")
    paths: set[Path] = {BUILD_TOOL.resolve(strict=True)}
    for name in frontend.FRONTEND_SOURCES:
        paths.add((ROOT / "src" / name).resolve(strict=True))
    project_source = ROOT / "src"
    for path in project_source.rglob("*"):
        if path.is_symlink() and path.suffix in HEADER_SUFFIXES:
            raise ValueError("project frontend headers contain a symlink")
        if path.is_file() and path.suffix in HEADER_SUFFIXES:
            _add_regular_file(paths, path)
    for name in TEST_INPUTS:
        paths.add((ROOT / name).resolve(strict=True))
    for path in (
        open_tree / "kernel-open/common/inc/nv_uvm_interface.h",
        legacy_tree / "common/inc/nv_uvm_interface.h",
    ):
        _add_regular_file(paths, path)
    if target_open_symvers is None:
        _add_regular_file(paths, open_tree / "kernel-open/Module.symvers")
    else:
        _add_regular_file(paths, target_open_symvers)
    if target_legacy_symvers is None:
        _add_regular_file(paths, legacy_tree / "Module.symvers")
    else:
        _add_regular_file(paths, target_legacy_symvers)
    for relative in INCLUDE_DIRS:
        directory = open_tree / relative
        if not directory.is_dir():
            raise FileNotFoundError(f"required R580 Open include directory is missing: {relative}")
        for path in directory.rglob("*"):
            if (target_open_symvers is not None and relative == "kernel-open" and
                    path == open_tree / "kernel-open/Module.symvers"):
                continue
            if (target_conftest is not None and relative == "kernel-open" and
                    path.is_relative_to(open_tree / "kernel-open/conftest") and path.suffix == ".h"):
                continue
            if path.is_symlink() and path.suffix in HEADER_SUFFIXES:
                raise ValueError("R580 Open headers contain a symlink")
            if path.is_file() and path.suffix in HEADER_SUFFIXES:
                _add_regular_file(paths, path)
    for relative in ("nvidia", "common/inc"):
        directory = legacy_tree / relative
        if not directory.is_dir():
            raise FileNotFoundError(f"required R580 proprietary include directory is missing: {relative}")
        for path in directory.rglob("*"):
            if path.is_symlink() and path.suffix in HEADER_SUFFIXES:
                raise ValueError("R580 proprietary headers contain a symlink")
            if path.is_file() and path.suffix in HEADER_SUFFIXES:
                _add_regular_file(paths, path)
    conftest = open_tree / "kernel-open/conftest"
    if target_conftest is None:
        for path in conftest.glob("*.h"):
            _add_regular_file(paths, path)
    else:
        for path in target_conftest.values():
            _add_regular_file(paths, path)
    return tuple(sorted(paths, key=lambda item: item.relative_to(ROOT).as_posix()))


def build_input_archive(paths: tuple[Path, ...], target_conftest: dict[str, Path] | None = None,
                        target_open_symvers: Path | None = None,
                        target_legacy_symvers: Path | None = None) -> tuple[bytes, list[dict[str, Any]]]:
    payload = io.BytesIO()
    records = []
    frontend = _load_module(BUILD_TOOL, "hybrid_frontend_archive_paths")
    open_tree, _ = frontend.default_provider_trees("r580")
    target_prefix = (open_tree / "kernel-open/conftest").relative_to(ROOT).as_posix()
    mapped = {path.resolve(strict=True): f"{target_prefix}/{name}"
              for name, path in (target_conftest or {}).items()}
    if target_open_symvers is not None:
        mapped[target_open_symvers.resolve(strict=True)] = (
            open_tree / "kernel-open/Module.symvers").relative_to(ROOT).as_posix()
    if target_legacy_symvers is not None:
        _, legacy_tree = frontend.default_provider_trees("r580")
        mapped[target_legacy_symvers.resolve(strict=True)] = (legacy_tree / "Module.symvers").relative_to(ROOT).as_posix()
    seen_names: set[str] = set()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for path in paths:
            source_relative = path.relative_to(ROOT).as_posix()
            relative = mapped.get(path.resolve(strict=True), source_relative)
            if relative in seen_names:
                raise ValueError("duplicate path in staged frontend input archive")
            seen_names.add(relative)
            size = path.stat().st_size
            if size > MAX_BUNDLE:
                raise ValueError("one build input exceeds the bundle size bound")
            archive.add(path, arcname=relative, recursive=False)
            records.append({"path": relative, "source_path": source_relative,
                            "bytes": size, "sha256": _file_sha256(path)})
    raw = payload.getvalue()
    if not raw or len(raw) > MAX_BUNDLE:
        raise ValueError("frontend build input archive size is invalid")
    return raw, records


GUEST_BUILD_SCRIPT = r'''import base64,datetime,hashlib,io,json,os,platform,re,shutil,signal,stat,subprocess,sys,tarfile,tempfile
EXPECTED_HOST="pc3-v100"
EXPECTED_KERNEL="6.8.0-147-generic"
MAX_BUNDLE=268435456
MAX_ARTIFACT_ARCHIVE=33554432
MAX_CAPTURED_ARTIFACT=67108864
MAX_ARTIFACT_COUNT=64
MAX_OUTPUT=16777216
run_id=sys.argv[3]
expected_sha=sys.argv[2]
if not re.fullmatch(r"[0-9a-f]{32}",run_id): raise SystemExit(2)
if platform.node()!=EXPECTED_HOST or platform.release()!=EXPECTED_KERNEL: raise SystemExit(3)
bundle_path="/tmp/codex-open580-"+run_id+".tar"
scratch="/tmp/codex-open580-"+run_id
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
  if not members or len(members)>10000: raise ValueError("bundle member count is invalid")
  seen=set();total=0
  for member in members:
   if not safe_name(member.name) or member.name in seen or not member.isfile() or member.size>MAX_BUNDLE:
    raise ValueError("bundle contains an unsafe member")
   total+=member.size;seen.add(member.name)
  if total>MAX_BUNDLE: raise ValueError("bundle expands beyond its size bound")
  archive.extractall(scratch,members=members,filter="data")
 root=scratch
 work=os.path.join(root,"build","experiments","pc3-v100-hybrid-frontend-"+run_id)
 report_path=os.path.join(root,"evidence","pc3-v100-hybrid-frontend-"+run_id+".json")
 os.makedirs(os.path.dirname(report_path),mode=0o700,exist_ok=True)
 command=[sys.executable,os.path.join(root,"tools","build_hybrid_frontend.py"),
  "--work",work,"--report",report_path,"--uvm-abi","r580","--module-name","nvidia"]
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
 if len(stdout)+len(stderr)>MAX_OUTPUT: raise ValueError("builder output exceeded its bound")
 try:
  with open(report_path,"rb") as stream: report_raw=stream.read(8*1024*1024+1)
  if len(report_raw)>8*1024*1024: raise ValueError("builder report exceeded its bound")
  report=json.loads(report_raw.decode("utf-8","strict"))
 except Exception: report=None
 artifacts=[]
 if report is not None:
  kernel_symvers_path="/lib/modules/"+EXPECTED_KERNEL+"/build/Module.symvers"
  kernel_symvers_capture=os.path.join(work,"kernel-inputs","Module.symvers")
  if os.path.islink(kernel_symvers_path) or not os.path.isfile(kernel_symvers_path):
   raise ValueError("exact guest kernel Module.symvers is unavailable or not a regular file")
  candidates=[report_path,os.path.join(work,"nvidia.ko"),os.path.join(work,"Kbuild"),
   os.path.join(work,"build.log"),os.path.join(work,"Module.symvers"),
   os.path.join(work,"undefined-symbols.log"),os.path.join(work,"module-info.log"),
   os.path.join(work,"backend-import-modversions.log"),kernel_symvers_path]
  try:
   candidates.extend(os.path.join(work,name) for name in sorted(os.listdir(work))
    if name.startswith(".") and name.endswith(".cmd"))
  except OSError: pass
  for path in candidates:
   try:
    if os.path.islink(path) or not os.path.isfile(path): continue
    size=os.path.getsize(path)
    if size>MAX_CAPTURED_ARTIFACT: continue
    with open(path,"rb") as stream: content=stream.read(MAX_CAPTURED_ARTIFACT+1)
    if len(content)>MAX_CAPTURED_ARTIFACT: continue
    rel=(os.path.relpath(kernel_symvers_capture,root) if path==kernel_symvers_path
     else os.path.relpath(path,root))
    if not safe_name(rel): continue
    artifacts.append((rel,content))
   except OSError: continue
 if len(artifacts)>MAX_ARTIFACT_COUNT: raise ValueError("captured artifact count exceeded its bound")
 packed=io.BytesIO()
 with tarfile.open(fileobj=packed,mode="w:gz",compresslevel=6) as output:
  for rel,content in artifacts:
   info=tarfile.TarInfo(rel);info.size=len(content);info.mode=0o600;info.mtime=0
   output.addfile(info,io.BytesIO(content))
 packed_bytes=packed.getvalue()
 if len(packed_bytes)>MAX_ARTIFACT_ARCHIVE: raise ValueError("captured build artifacts exceed their bound")
 config_path="/lib/modules/"+EXPECTED_KERNEL+"/build/include/config/auto.conf"
 kernel_config={"path":config_path,"sha256":None,"selected_options":{},"readable":False}
 try:
  with open(config_path,"rb") as stream: config_raw=stream.read(8*1024*1024+1)
  if len(config_raw)>8*1024*1024: raise ValueError("kernel auto.conf exceeds its bound")
  kernel_config["sha256"]=digest(config_raw);kernel_config["readable"]=True
  relevant=("CONFIG_GENDWARFKSYMS=","CONFIG_DEBUG_INFO=","CONFIG_MODVERSIONS=",
   "CONFIG_MODULES=","CONFIG_STACK_VALIDATION=","CONFIG_UNWINDER_ORC=",
   "CONFIG_RETPOLINE=","CONFIG_RETHUNK=","CONFIG_X86_KERNEL_IBT=")
  for line in config_raw.decode("ascii","replace").splitlines():
   if line.startswith(relevant):
    name,value=line.split("=",1);kernel_config["selected_options"][name]=value
 except OSError: pass
 result={"schema":"nvidia-hybrid-pc3-v100-hybrid-frontend-build-result-v1",
  "status":"completed" if report is not None else "failed","run_id":run_id,"bundle_sha256":expected_sha,
  "hostname":platform.node(),"kernel_release":platform.release(),"builder_exit_code":exit_code,
  "builder_stdout_sha256":digest(stdout),"builder_stderr_sha256":digest(stderr),
  "builder_output_bytes":len(stdout)+len(stderr),"builder_report":report,
  "builder_report_sha256":digest(report_raw) if report is not None else None,"kernel_build_config":kernel_config,
  "artifacts":[{"path":p,"bytes":len(c),"sha256":digest(c)} for p,c in artifacts],
  "artifact_archive_bytes":len(packed_bytes),"artifact_archive_sha256":digest(packed_bytes),
  "artifact_archive_base64":base64.b64encode(packed_bytes).decode("ascii"),
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
 if report is None:
  result["error"]=(stderr+stdout).decode("utf-8","replace")[-4096:] or "frontend builder did not write a report"
 elif exit_code!=0:
  result["error"]="frontend build exited nonzero"
except Exception as error:
 result={"schema":"nvidia-hybrid-pc3-v100-hybrid-frontend-build-result-v1","status":"failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":None,"builder_stdout_sha256":digest(b""),"builder_stderr_sha256":digest(b""),
  "builder_output_bytes":0,"builder_report":None,"builder_report_sha256":None,
  "kernel_build_config":{},"artifacts":[],
  "artifact_archive_bytes":0,"artifact_archive_sha256":digest(b""),"artifact_archive_base64":"",
  "error":type(error).__name__+": "+str(error)[:160],"module_installed":False,"module_loaded":False,
  "gpu_accessed":False,"cuda_execution_tested":False}
finally:
 if created_scratch:
  try: shutil.rmtree(scratch)
  except OSError: pass
 if created_bundle:
  try: os.unlink(bundle_path)
  except OSError: pass
 if "result" not in locals(): result={"schema":"nvidia-hybrid-pc3-v100-hybrid-frontend-build-result-v1",
  "status":"failed","run_id":run_id,"bundle_sha256":expected_sha,"hostname":EXPECTED_HOST,
  "kernel_release":EXPECTED_KERNEL,"builder_exit_code":None,"builder_stdout_sha256":digest(b""),
  "builder_stderr_sha256":digest(b""),"builder_output_bytes":0,"builder_report":None,
  "builder_report_sha256":None,"kernel_build_config":{},"artifacts":[],"artifact_archive_bytes":0,
  "artifact_archive_sha256":digest(b""),"artifact_archive_base64":"","error":"missing build result",
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
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
        "builder_output_bytes", "builder_report", "builder_report_sha256", "kernel_build_config", "artifacts",
        "artifact_archive_bytes", "artifact_archive_sha256", "artifact_archive_base64",
        "module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested",
        "scratch_removed", "staged_bundle_removed",
    }
    has_error = isinstance(result, dict) and "error" in result
    if not isinstance(result, dict) or set(result) != (required | {"error"} if has_error else required):
        raise ValueError("guest result fields differ from the pinned schema")
    if result["schema"] != "nvidia-hybrid-pc3-v100-hybrid-frontend-build-result-v1":
        raise ValueError("guest result schema is unsupported")
    if (result["run_id"] != run_id or result["bundle_sha256"] != bundle_sha or
            result["hostname"] != PINNED_GUEST or result["kernel_release"] != PINNED_KERNEL):
        raise ValueError("guest build identity differs from the pinned V100 target")
    if any(result[key] is not False for key in
           ("module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested")):
        raise ValueError("guest build crossed the compile-only boundary")
    if result["scratch_removed"] is not True or result["staged_bundle_removed"] is not True:
        raise ValueError("guest scratch cleanup is not verified")
    if result["status"] not in ("completed", "failed"):
        raise ValueError("guest build status is invalid")
    if (result["status"] == "failed" and not has_error) or (has_error and
            (not isinstance(result["error"], str) or not result["error"] or len(result["error"]) > 4096)):
        raise ValueError("guest failure detail is invalid")
    if result["status"] == "completed":
        config = result["kernel_build_config"]
        if (not isinstance(config, dict) or set(config) !=
                {"path", "sha256", "selected_options", "readable"} or
                type(config["readable"]) is not bool or
                not isinstance(config["selected_options"], dict)):
            raise ValueError("guest kernel-build config receipt is malformed")
        if config["readable"] and (not isinstance(config["sha256"], str) or
                re.fullmatch(r"[0-9a-f]{64}", config["sha256"]) is None):
            raise ValueError("guest kernel-build config hash is invalid")
        if not config["readable"] and config["sha256"] is not None:
            raise ValueError("unreadable kernel config has an unexpected hash")
        report = result["builder_report"]
        if not isinstance(report, dict) or report.get("kernel_release") != PINNED_KERNEL:
            raise ValueError("frontend report targets the wrong kernel")
        if type(result["builder_exit_code"]) is not int:
            raise ValueError("guest builder exit code is invalid")
        if (type(result["builder_output_bytes"]) is not int or
                not 0 <= result["builder_output_bytes"] <= MAX_OUTPUT):
            raise ValueError("guest builder output size is invalid")
        for key in ("builder_stdout_sha256", "builder_stderr_sha256", "artifact_archive_sha256",
                    "builder_report_sha256"):
            if not isinstance(result[key], str) or re.fullmatch(r"[0-9a-f]{64}", result[key]) is None:
                raise ValueError(f"guest {key} is invalid")
        if not isinstance(result["artifacts"], list) or not result["artifacts"] or len(result["artifacts"]) > MAX_ARTIFACT_COUNT:
            raise ValueError("guest artifact manifest is invalid")
        names = set()
        expected_kernel_symvers = (
            f"build/experiments/pc3-v100-hybrid-frontend-{run_id}/"
            "kernel-inputs/Module.symvers")
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
        if expected_kernel_symvers not in names:
            raise ValueError("guest result lacks the exact kernel Module.symvers artifact")
        if (type(result["artifact_archive_bytes"]) is not int or
                not 0 < result["artifact_archive_bytes"] <= MAX_ARTIFACT_ARCHIVE):
            raise ValueError("guest artifact archive size is invalid")
        packed = base64.b64decode(result["artifact_archive_base64"], validate=True)
        if (len(packed) != result["artifact_archive_bytes"] or len(packed) > MAX_ARTIFACT_ARCHIVE or
                _sha256(packed) != result["artifact_archive_sha256"]):
            raise ValueError("guest artifact archive digest or size mismatch")
        result["_packed_artifacts"] = packed
    return result


def extract_artifacts(result: dict[str, Any]) -> list[dict[str, Any]]:
    packed = result.get("_packed_artifacts")
    if not isinstance(packed, bytes):
        raise ValueError("validated artifact archive is missing")
    expected = {item["path"]: item for item in result["artifacts"]}
    extracted = []
    payloads = []
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
        members = archive.getmembers()
        if {member.name for member in members} != set(expected) or any(not member.isfile() for member in members):
            raise ValueError("guest artifact archive differs from its manifest")
        for member in members:
            record = expected[member.name]
            if member.size != record["bytes"] or member.size > MAX_ARTIFACT:
                raise ValueError("guest artifact size differs from its manifest")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("guest artifact cannot be read")
            data = source.read(MAX_ARTIFACT + 1)
            if len(data) != member.size or _sha256(data) != record["sha256"]:
                raise ValueError("guest artifact hash differs from its manifest")
            payloads.append((member.name, data, record["sha256"]))
    for name, data, digest in payloads:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] not in ("build", "evidence"):
            raise ValueError("artifact path escaped the canonical project")
        destination = ROOT / Path(*pure.parts)
        cursor = ROOT
        for part in pure.parts[:-1]:
            cursor = cursor / part
            try:
                info = cursor.lstat()
            except FileNotFoundError:
                cursor.mkdir(mode=0o700)
                info = cursor.lstat()
            if not stat_is_directory(info.st_mode) or cursor.is_symlink():
                raise ValueError("artifact parent contains a non-directory or symlink")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("artifact destination already exists")
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        extracted.append({"path": name, "bytes": len(data), "sha256": digest})
    return extracted


def write_private_json(path: Path, report: dict[str, Any]) -> str:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return _sha256(payload)


def load_target_conftest(report_path: Path) -> tuple[dict[str, Path], str]:
    candidate = report_path.absolute()
    cursor = candidate
    while cursor != ROOT and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("target Open R580 report path contains a symlink")
        cursor = cursor.parent
    report_path = candidate.resolve(strict=True)
    if not report_path.is_relative_to(ROOT) or not report_path.is_file():
        raise ValueError("target Open R580 build report must be a regular project file")
    report_raw = report_path.read_bytes()
    report = json.loads(report_raw.decode("utf-8", "strict"))
    builder = report.get("builder_report") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or
            report.get("schema") != "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1" or
            report.get("status") != "collected" or
            report.get("guest_hostname") != PINNED_GUEST or
            report.get("guest_kernel_release") != PINNED_KERNEL or
            report.get("builder_qualification") != "compiled-native-private-open580-provider-only" or
            not isinstance(builder, dict) or builder.get("kernel_release") != PINNED_KERNEL or
            report.get("module_installed") is not False or report.get("module_loaded") is not False):
        raise ValueError("target report does not prove a compile-only R580 Open build for this guest")
    conftest: dict[str, Path] = {}
    for artifact in report.get("retrieved_artifacts", []):
        if not isinstance(artifact, dict):
            raise ValueError("target Open R580 artifact manifest is malformed")
        relative = artifact.get("path")
        pure = PurePosixPath(relative) if isinstance(relative, str) else None
        if (pure is None or pure.is_absolute() or ".." in pure.parts or
                not relative.startswith("build/experiments/pc3-v100-private-open580-") or
                "private/NVIDIA-kernel-module-source-580.178.04/kernel-open/conftest" not in relative):
            continue
        if pure.suffix != ".h" or len(pure.parts) < 3:
            continue
        name = pure.name
        if name in conftest:
            raise ValueError("target Open build returned duplicate conftest headers")
        path = ROOT / Path(*pure.parts)
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError("target Open conftest artifact was not retrieved")
        if (type(artifact.get("bytes")) is not int or path.stat().st_size != artifact["bytes"] or
                artifact.get("sha256") != _file_sha256(path)):
            raise ValueError("target Open conftest artifact differs from its manifest")
        conftest[name] = path
    headers = conftest.get("headers.h")
    if headers is None or PINNED_KERNEL not in headers.read_text(encoding="utf-8", errors="replace"):
        raise ValueError("target Open build lacks the exact guest-kernel conftest headers.h")
    return conftest, _sha256(report_raw)


def load_target_symvers(report_path: Path, provider: str) -> tuple[Path, str]:
    if provider not in ("open", "legacy"):
        raise ValueError("unsupported target provider kind")
    candidate = report_path.absolute()
    cursor = candidate
    while cursor != ROOT and cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("target provider report path contains a symlink")
        cursor = cursor.parent
    report_path = candidate.resolve(strict=True)
    if not report_path.is_relative_to(ROOT) or not report_path.is_file():
        raise ValueError("target provider report must be a regular project file")
    raw = report_path.read_bytes()
    report = json.loads(raw.decode("utf-8", "strict"))
    if provider == "open":
        expected_schema = "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1"
        expected_qualification = "compiled-native-private-open580-provider-only"
        expected_prefix = "build/experiments/pc3-v100-private-open580-"
        expected_suffix = "/private/NVIDIA-kernel-module-source-580.178.04/kernel-open/Module.symvers"
    else:
        expected_schema = "nvidia-hybrid-pc3-v100-private-legacy580-build-capture-v1"
        expected_qualification = "compiled-module-and-CPU-model-only-with-inherited-vendor-objtool-warnings"
        expected_prefix = "build/experiments/pc3-v100-private-proprietary580-"
        expected_suffix = "/nvidia-580.178.04/Module.symvers"
    builder = report.get("builder_report") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or report.get("schema") != expected_schema or
            report.get("status") != "collected" or report.get("guest_hostname") != PINNED_GUEST or
            report.get("guest_kernel_release") != PINNED_KERNEL or
            report.get("builder_qualification") != expected_qualification or
            not isinstance(builder, dict) or report.get("module_installed") is not False or
            report.get("module_loaded") is not False or report.get("gpu_accessed") is not False or
            report.get("cuda_execution_tested") is not False):
        raise ValueError(f"target report does not prove the compile-only R580 {provider} provider for this guest")
    matches = []
    for artifact in report.get("retrieved_artifacts", []):
        if not isinstance(artifact, dict):
            raise ValueError("target provider artifact manifest is malformed")
        relative = artifact.get("path")
        pure = PurePosixPath(relative) if isinstance(relative, str) else None
        if (pure is None or pure.is_absolute() or ".." in pure.parts or
                not relative.startswith(expected_prefix) or not relative.endswith(expected_suffix)):
            continue
        path = ROOT / Path(*pure.parts)
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(f"target R580 {provider} Module.symvers was not retrieved")
        if (type(artifact.get("bytes")) is not int or path.stat().st_size != artifact["bytes"] or
                artifact.get("sha256") != _file_sha256(path)):
            raise ValueError(f"target R580 {provider} Module.symvers differs from its manifest")
        matches.append(path)
    if len(matches) != 1:
        raise ValueError(f"target R580 {provider} build must supply exactly one private Module.symvers")
    return matches[0], _sha256(raw)


def collect(target_conftest: dict[str, Path], target_report_sha256: str,
            target_report_path: Path, target_open_symvers: Path,
            target_open_report_sha256: str, target_open_report_path: Path,
            target_legacy_symvers: Path, target_legacy_report_sha256: str,
            target_legacy_report_path: Path) -> tuple[dict[str, Any], int]:
    relay = _load_module(ROOT / "tools/run_pc3_v100_private_open580_build.py", "pc3_open580_build_transport")
    transport = relay.load_transport()
    relay.validate_pc3_transport_identity(PINNED_PC3, PINNED_PC3_ALIAS)
    relay.verify_pc3_host_key()
    paths = input_bundle_paths(target_conftest, target_open_symvers, target_legacy_symvers)
    bundle, pinned_inputs = build_input_archive(
        paths, target_conftest, target_open_symvers, target_legacy_symvers)
    bundle_sha = _sha256(bundle)
    run_id = uuid.uuid4().hex
    stage_path = f"/tmp/codex-open580-{run_id}.tar"
    guest_code = GUEST_BUILD_SCRIPT.replace("EXPECTED_HOST=\"pc3-v100\"", f"EXPECTED_HOST=\"{PINNED_GUEST}\"")
    guest_code = guest_code.replace("EXPECTED_KERNEL=\"6.8.0-147-generic\"", f"EXPECTED_KERNEL=\"{PINNED_KERNEL}\"")
    guest_bytes = guest_code.encode()
    guest_sha = _sha256(guest_bytes)
    upload_command = " ".join(shlex.quote(value) for value in
                               ["python3", "-c", relay.PC3_UPLOAD_SCRIPT, stage_path, bundle_sha])
    upload = subprocess.run(transport.pc3_ssh_base(PINNED_PC3, PINNED_PC3_ALIAS) + [upload_command],
                            input=bundle, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=600, check=False)
    if upload.returncode != 0:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 rejected the hash-pinned frontend build bundle")
    try:
        receipt = json.loads(upload.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 returned an invalid frontend bundle receipt") from None
    if receipt != {"bytes": len(bundle), "sha256": bundle_sha}:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 staging receipt differs from the local bundle")
    try:
        secret = transport.fetch_pc3_sudo_secret(relay.PINNED_CREDENTIAL_HOST,
                                                 relay.PINNED_CREDENTIAL_FILE)
        guest_b64 = base64.b64encode(guest_bytes).decode("ascii")
        root_command = "sudo -S -p '' python3 -c " + shlex.quote(relay.PC3_ROOT_RUN_SCRIPT) + " " + " ".join(
            shlex.quote(value) for value in (stage_path, bundle_sha, run_id, guest_b64, guest_sha))
        try:
            response = subprocess.run(transport.pc3_ssh_base(PINNED_PC3, PINNED_PC3_ALIAS) + [root_command],
                                      input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=2500, check=False)
        except (OSError, subprocess.TimeoutExpired):
            relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
            raise RuntimeError("isolated V100 frontend build relay timed out or disconnected") from None
    finally:
        secret = None
    if response.returncode != 0 or len(response.stdout) > MAX_RESULT * 2:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("isolated V100 frontend build relay failed")
    try:
        envelope = json.loads(response.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 returned an invalid frontend build envelope") from None
    cleanup_retried = False
    if isinstance(envelope, dict) and envelope.get("pc3_bundle_removed") is False:
        cleanup_retried = relay.cleanup_pc3_bundle(
            transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
    try:
        envelope = relay.validate_pc3_root_envelope(envelope, cleanup_verified=cleanup_retried)
    except ValueError:
        relay.cleanup_pc3_bundle(transport, PINNED_PC3, PINNED_PC3_ALIAS, stage_path, bundle_sha)
        raise RuntimeError("PC3 frontend build transport or staging cleanup failed validation") from None
    guest_raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    guest = validate_guest_result(guest_raw, run_id, bundle_sha)
    extracted = extract_artifacts(guest) if guest["status"] == "completed" else []
    builder_report = guest.get("builder_report") or {}
    qualification = builder_report.get("qualification", "failed")
    capture = {
        "schema": "nvidia-hybrid-pc3-v100-hybrid-frontend-build-capture-v1",
        "status": "compiled" if qualification == EXPECTED_QUALIFICATION and guest["builder_exit_code"] == 0 else "build-failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": PINNED_PC3,
        "guest_hostname": guest["hostname"],
        "guest_kernel_release": guest["kernel_release"],
        "guest_hostkey_fingerprint": relay.GUEST_HOSTKEY_FINGERPRINT,
        "run_id": run_id,
        "bundle": {"bytes": len(bundle), "sha256": bundle_sha,
                   "guest_script_sha256": guest_sha, "pinned_inputs": pinned_inputs,
                   "runner_sha256": _file_sha256(Path(__file__).resolve()),
                   "transport_helper_sha256": _file_sha256(
                       ROOT / "tools/run_pc3_v100_private_open580_build.py"),
                   "target_open_build_report": target_report_path.relative_to(ROOT).as_posix(),
                   "target_open_build_report_sha256": target_report_sha256,
                   "target_open_symvers_sha256": _file_sha256(target_open_symvers),
                   "target_open_symvers_report": target_open_report_path.relative_to(ROOT).as_posix(),
                   "target_open_symvers_report_sha256": target_open_report_sha256,
                   "target_legacy_symvers_sha256": _file_sha256(target_legacy_symvers),
                   "target_legacy_symvers_report": target_legacy_report_path.relative_to(ROOT).as_posix(),
                   "target_legacy_symvers_report_sha256": target_legacy_report_sha256,
                   "target_conftest_headers": {name: _file_sha256(path)
                                                for name, path in sorted(target_conftest.items())}},
        "qualification": qualification,
        "build_failure": guest.get("error"),
        "builder_exit_code": guest["builder_exit_code"],
        "builder_report_sha256": guest["builder_report_sha256"],
        "builder_report": builder_report,
        "kernel_build_config": guest.get("kernel_build_config"),
        "retrieved_artifacts": extracted,
        "remote_scratch_removed": guest["scratch_removed"],
        "remote_bundle_removed": guest["staged_bundle_removed"],
        "pc3_stage_bundle_removed": envelope["pc3_bundle_removed"] or cleanup_retried,
        "pc3_stage_cleanup_retried": cleanup_retried,
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
    }
    return capture, 0 if capture["status"] == "compiled" else 1


def _safe_report_path(destination: Path) -> Path:
    try:
        relative = destination.relative_to(ROOT)
    except ValueError:
        raise ValueError("report path is outside the canonical project") from None
    if not relative.parts or relative.parts[0] != "evidence":
        raise ValueError("report path must be inside evidence/")
    cursor = ROOT
    for part in relative.parts[:-1]:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            cursor.mkdir(mode=0o700)
            info = cursor.lstat()
        if not cursor.is_dir() or cursor.is_symlink() or not stat_is_directory(info.st_mode):
            raise ValueError("report parent contains a non-directory or symlink")
    target = ROOT / relative
    if target.exists() or target.is_symlink():
        raise FileExistsError("report destination already exists")
    return target


def stat_is_directory(mode: int) -> bool:
    return (mode & 0o170000) == 0o040000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="private evidence report path inside the canonical project")
    parser.add_argument("--target-open-build-report", required=True,
                        help="compile-only PC3 V100 Open R580 build report that supplies guest conftest headers")
    parser.add_argument("--target-legacy-build-report", required=True,
                        help="compile-only PC3 V100 proprietary R580 build report that supplies guest Module.symvers")
    args = parser.parse_args(argv)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = Path(args.report) if args.report else Path(f"evidence/pc3-v100-hybrid-frontend-build-{stamp}.json")
    destination = report_path if report_path.is_absolute() else ROOT / report_path
    destination = Path(os.path.abspath(destination))
    try:
        destination = _safe_report_path(destination)
        target_report_path = Path(args.target_open_build_report)
        target_report_path = target_report_path if target_report_path.is_absolute() else ROOT / target_report_path
        target_conftest, target_report_sha = load_target_conftest(target_report_path)
        target_open_report_path = target_report_path.resolve(strict=True)
        target_open_symvers, target_open_report_sha = load_target_symvers(target_open_report_path, "open")
        target_legacy_report_path = Path(args.target_legacy_build_report)
        target_legacy_report_path = (target_legacy_report_path if target_legacy_report_path.is_absolute()
                                     else ROOT / target_legacy_report_path)
        target_legacy_report_path = target_legacy_report_path.resolve(strict=True)
        target_legacy_symvers, target_legacy_report_sha = load_target_symvers(
            target_legacy_report_path, "legacy")
        capture, exit_code = collect(
            target_conftest, target_report_sha, target_open_report_path,
            target_open_symvers, target_open_report_sha, target_open_report_path,
            target_legacy_symvers, target_legacy_report_sha, target_legacy_report_path)
    except Exception as error:
        capture = {
            "schema": "nvidia-hybrid-pc3-v100-hybrid-frontend-build-capture-v1",
            "status": "preflight-failed",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": PINNED_PC3,
            "failure": f"{type(error).__name__}: {str(error)[:200]}",
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
        }
        exit_code = 2
    digest = write_private_json(destination, capture)
    print(json.dumps({"report": str(destination), "sha256": digest, "status": capture["status"],
                      "qualification": capture.get("qualification")}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
