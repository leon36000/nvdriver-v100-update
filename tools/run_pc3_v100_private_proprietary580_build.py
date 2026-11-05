#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the private proprietary R580 provider for PC3's V100 guest kernel, compile-only."""
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
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPEN_RUNNER_PATH = ROOT / "tools/run_pc3_v100_private_open580_build.py"
OPEN_RUNNER_SPEC = importlib.util.spec_from_file_location("pc3_v100_open580_transport", OPEN_RUNNER_PATH)
OPEN_RUNNER = importlib.util.module_from_spec(OPEN_RUNNER_SPEC)
OPEN_RUNNER_SPEC.loader.exec_module(OPEN_RUNNER)

PINNED_HOSTNAME = OPEN_RUNNER.PINNED_HOSTNAME
PINNED_KERNEL_RELEASE = OPEN_RUNNER.PINNED_KERNEL_RELEASE
PINNED_PC3_TARGET = OPEN_RUNNER.PINNED_PC3_TARGET
PINNED_PC3_HOST_KEY_ALIAS = OPEN_RUNNER.PINNED_PC3_HOST_KEY_ALIAS
PINNED_CREDENTIAL_HOST = OPEN_RUNNER.PINNED_CREDENTIAL_HOST
PINNED_CREDENTIAL_FILE = OPEN_RUNNER.PINNED_CREDENTIAL_FILE
GUEST_HOSTKEY_FINGERPRINT = OPEN_RUNNER.GUEST_HOSTKEY_FINGERPRINT

MIB = 1024 * 1024
MAX_BUNDLE_BYTES = 384 * MIB
MAX_RESULT_BYTES = 250 * MIB
MAX_ARTIFACT_ARCHIVE_BYTES = 160 * MIB
MAX_CAPTURED_ARTIFACT_BYTES = 160 * MIB
MAX_MAKE_OUTPUT_BYTES = 16 * MIB
GUEST_RESULT_SCHEMA = "nvidia-hybrid-pc3-v100-private-legacy580-build-result-v1"
CAPTURE_SCHEMA = "nvidia-hybrid-pc3-v100-private-legacy580-build-capture-v1"


def _rename_transport_script(script: str) -> str:
    """Use the audited Open580 relay with distinct staging names and larger bounds."""
    return (script.replace("codex-open580-", "codex-legacy580-")
            .replace("268435456", str(MAX_BUNDLE_BYTES))
            .replace("50331648", str(MAX_RESULT_BYTES))
            .replace("nvidia-hybrid-pc3-v100-private-open580-transport-v1",
                     "nvidia-hybrid-pc3-v100-private-legacy580-transport-v1"))


PC3_UPLOAD_SCRIPT = _rename_transport_script(OPEN_RUNNER.PC3_UPLOAD_SCRIPT)
PC3_CLEANUP_SCRIPT = _rename_transport_script(OPEN_RUNNER.PC3_CLEANUP_SCRIPT)
PC3_ROOT_RUN_SCRIPT = _rename_transport_script(OPEN_RUNNER.PC3_ROOT_RUN_SCRIPT)


GUEST_BUILD_SCRIPT = r'''import base64,datetime,hashlib,io,json,os,platform,re,shutil,signal,stat,subprocess,sys,tarfile
EXPECTED_HOST="pc3-v100"
EXPECTED_KERNEL="6.8.0-147-generic"
JOBS=4
MAX_BUNDLE=402653184
MAX_ARTIFACT_ARCHIVE=167772160
MAX_CAPTURED_ARTIFACT=167772160
MAX_MAKE_OUTPUT=16777216
MAX_REPORT=16777216
SCHEMA="nvidia-hybrid-pc3-v100-private-legacy580-build-result-v1"
run_id=sys.argv[3]
if not re.fullmatch(r"[0-9a-f]{32}",run_id): raise SystemExit(2)
if platform.node()!=EXPECTED_HOST or platform.release()!=EXPECTED_KERNEL: raise SystemExit(3)
expected_sha=sys.argv[2]
bundle_path="/tmp/codex-legacy580-"+run_id+".tar"
scratch="/tmp/codex-legacy580-"+run_id
created_bundle=False
created_scratch=False
result=None
def digest_bytes(data): return hashlib.sha256(data).hexdigest()
def safe_name(name):
 p=__import__("pathlib").PurePosixPath(name)
 return not p.is_absolute() and bool(p.parts) and all(x not in ("",".","..") for x in p.parts) and not any(ord(c)<32 for c in name)
try:
 if not re.fullmatch(r"[0-9a-f]{64}",expected_sha): raise ValueError("invalid bundle digest")
 data=sys.stdin.buffer.read(MAX_BUNDLE+1)
 if len(data)>MAX_BUNDLE or digest_bytes(data)!=expected_sha: raise ValueError("staged bundle digest or size mismatch")
 fd=os.open(bundle_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as out: out.write(data);out.flush();os.fsync(out.fileno())
 created_bundle=True
 if platform.release()!=EXPECTED_KERNEL: raise ValueError("target kernel changed")
 os.mkdir(scratch,0o700);created_scratch=True
 with tarfile.open(bundle_path,"r:gz") as archive:
  members=archive.getmembers()
  if not members or len(members)>12000: raise ValueError("bundle member count is invalid")
  seen=set();total=0
  for member in members:
   if not safe_name(member.name) or member.name in seen or not (member.isfile() or member.isdir()) or member.size>MAX_BUNDLE:
    raise ValueError("bundle contains an unsafe member")
   if member.isfile(): total+=member.size
   seen.add(member.name)
  if total>MAX_BUNDLE: raise ValueError("bundle expanded beyond its size bound")
  archive.extractall(scratch,members=members,filter="data")
 root=scratch
 source=os.path.join(root,"tools","build_private_proprietary580.py")
 builder_report=os.path.join(root,"evidence","private-proprietary580-guestkernel-"+run_id+".json")
 work=os.path.join(root,"build","experiments","pc3-v100-private-proprietary580-"+run_id)
 os.makedirs(os.path.dirname(builder_report),mode=0o700,exist_ok=True)
 command=[sys.executable,source,"--work-dir",work,"--report",builder_report,
          "--kernel-release",EXPECTED_KERNEL,"--jobs",str(JOBS)]
 env={"PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TMPDIR":"/tmp"}
 build=subprocess.Popen(command,cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
  stderr=subprocess.PIPE,env=env,start_new_session=True)
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
 if len(stdout)+len(stderr)>MAX_MAKE_OUTPUT: raise ValueError("builder output exceeded its bound")
 try:
  with open(builder_report,"rb") as stream: report_raw=stream.read(MAX_REPORT+1)
  if len(report_raw)>MAX_REPORT: raise ValueError("builder report exceeded its bound")
  report=json.loads(report_raw.decode("utf-8","strict"))
 except Exception: report=None
 artifact_paths=[]
 if report is not None:
  artifact_paths.append(builder_report)
  module_path=os.path.join(work,"nvidia-580.178.04","hybrid580_legacy.ko")
  symvers_path=os.path.join(work,"nvidia-580.178.04","Module.symvers")
  composite_command_path=os.path.join(work,"nvidia-580.178.04",".hybrid580_legacy.o.cmd")
  conftest_symbols_path=os.path.join(work,"nvidia-580.178.04","conftest","symbols.h")
  target_config_path=os.path.join(work,"target-kernel.config")
  modifications_path=os.path.join(work,"MODIFICATIONS.md")
  artifact_paths.extend((module_path,symvers_path,composite_command_path,
                        conftest_symbols_path,target_config_path,modifications_path))
  for step in report.get("steps",[]):
   if isinstance(step,dict) and isinstance(step.get("log"),str): artifact_paths.append(step["log"])
 unique=[];seen=set()
 for path in artifact_paths:
  if path in seen: continue
  seen.add(path)
  try:
   real=os.path.realpath(path)
   if not real.startswith(os.path.realpath(root)+os.sep) or os.path.islink(path) or not os.path.isfile(path): continue
   size=os.path.getsize(path)
   if size>MAX_CAPTURED_ARTIFACT: continue
   with open(path,"rb") as stream: content=stream.read(MAX_CAPTURED_ARTIFACT+1)
   if len(content)>MAX_CAPTURED_ARTIFACT: continue
   rel=os.path.relpath(path,root)
   if not safe_name(rel): continue
   unique.append((rel,content))
  except OSError: continue
 packed=io.BytesIO()
 with tarfile.open(fileobj=packed,mode="w:gz",compresslevel=3) as output:
  for rel,content in unique:
   info=tarfile.TarInfo(rel);info.size=len(content);info.mode=0o600;info.mtime=0
   output.addfile(info,io.BytesIO(content))
 packed_bytes=packed.getvalue()
 if len(packed_bytes)>MAX_ARTIFACT_ARCHIVE: raise ValueError("captured build artifacts exceeded their bound")
 result={"schema":SCHEMA,"status":"completed" if report is not None and exit_code==0 else "failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":exit_code,"builder_stdout_sha256":digest_bytes(stdout),
  "builder_stderr_sha256":digest_bytes(stderr),"builder_output_bytes":len(stdout)+len(stderr),
  "builder_report":report,"builder_report_sha256":digest_bytes(report_raw) if report is not None else None,
  "artifacts":[{"path":rel,"bytes":len(content),"sha256":digest_bytes(content)} for rel,content in unique],
  "artifact_archive_bytes":len(packed_bytes),"artifact_archive_sha256":digest_bytes(packed_bytes),
  "artifact_archive_base64":base64.b64encode(packed_bytes).decode("ascii"),
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
 if report is not None and exit_code!=0:
  result["error"]=(str(report.get("error", "builder returned a nonzero exit code"))[:180] or
                    "builder returned a nonzero exit code")
except Exception as error:
 result={"schema":SCHEMA,"status":"failed","run_id":run_id,"bundle_sha256":expected_sha,
  "hostname":platform.node(),"kernel_release":platform.release(),"builder_exit_code":None,
  "builder_stdout_sha256":digest_bytes(b""),"builder_stderr_sha256":digest_bytes(b""),"builder_output_bytes":0,
  "builder_report":None,"builder_report_sha256":None,"artifacts":[],"artifact_archive_bytes":0,
  "artifact_archive_sha256":digest_bytes(b""),"artifact_archive_base64":"","error":type(error).__name__+": "+str(error)[:160],
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
finally:
 if created_scratch:
  try: shutil.rmtree(scratch)
  except OSError: pass
 if created_bundle:
  try: os.unlink(bundle_path)
  except OSError: pass
 result=result or {"schema":SCHEMA,"status":"failed","run_id":run_id,"bundle_sha256":expected_sha,
  "hostname":platform.node(),"kernel_release":platform.release(),"builder_exit_code":None,
  "builder_stdout_sha256":digest_bytes(b""),"builder_stderr_sha256":digest_bytes(b""),"builder_output_bytes":0,
  "builder_report":None,"builder_report_sha256":None,"artifacts":[],"artifact_archive_bytes":0,
  "artifact_archive_sha256":digest_bytes(b""),"artifact_archive_base64":"","error":"guest build ended without result",
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
 result["scratch_removed"]=not os.path.lexists(scratch)
 result["staged_bundle_removed"]=not os.path.lexists(bundle_path)
print(json.dumps(result,separators=(",",":"),sort_keys=True))
'''


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned build helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def input_bundle_paths() -> tuple[Path, ...]:
    builder = load_module(ROOT / "tools/build_private_proprietary580.py", "private_legacy580_bundle_builder")
    baseline = builder.baseline
    openrm_baseline = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
    open_source = ROOT / "build/experiments/r580-uvm-clean-v3-20261021/source"
    open_provider_source = ROOT / "build/experiments/private-open-pm-recovery-provider-v3-20261021/NVIDIA-kernel-module-source-580.178.04/kernel-open"
    previous_vendor_files = (
        "common/inc/nv-linux.h", "common/inc/nv.h", "nvidia/export_nvswitch.h",
        "nvidia/nv-caps-imex.c", "nvidia/nv-caps.c", "nvidia/nv-mmap.c",
        "nvidia/nv-pci-table.c", "nvidia/nv-pci.c", "nvidia/nv-platform.c",
        "nvidia/nv-procfs.c", "nvidia/nv.c", "nvidia/nvidia.Kbuild",
        "nvidia/nvlink_linux.c", "nvidia/nvlink_linux.h", "nvidia/procfs_nvswitch.c",
    )
    paths = {
        Path(__file__).resolve(), OPEN_RUNNER_PATH,
        ROOT / "tools/build_private_proprietary580.py",
        ROOT / "tools/build_proprietary580_wrapper_baseline.py",
        baseline.PACKAGE_DEB, builder.ARCHIVE,
        builder.PREVIOUS_REPORT, builder.PREVIOUS_SOURCE / "Module.symvers",
        builder.PREVIOUS_CONTROL_HEADER,
        builder.BASE / "nvidia.ko", builder.BASE / "Module.symvers",
        ROOT / "evidence/r580-proprietary-reference-acquisition-20261018.json",
        ROOT / "evidence/r580-external-dependencies-20261018.json",
        ROOT / "evidence/open580-wrapper-baseline-20261018.json",
        ROOT / "src/rm_session_endpoint.h", builder.GPU_SESSION_HEADER,
        builder.CONTROL_SESSION_HEADER, builder.GPU_CATALOG_HEADER,
        ROOT / "src/hybrid580_pm_provider_recovery.h",
        ROOT / "src/hybrid580_pm_provider_kernel.h",
        builder.PM_CHANNEL_DEPTH_TEST, builder.PM_RECOVERY_TEST,
        builder.PM_RECOVERY_PROVIDER_TEST,
        ROOT / "tests/fixtures/hybrid580_pm_provider_recovery_test.c",
        ROOT / "tests/test_private_proprietary580.py",
        ROOT / "tests/test_usermode_object.py",
        ROOT / "tests/test_private_backend_control_session.py",
        ROOT / "tests/test_private_backend_gpu_session.py",
        ROOT / "tests/test_private_backend_file_projection.py",
        ROOT / "tests/test_private_backend_pci.py",
        ROOT / "tests/gpu_session_register_harness.py",
        ROOT / "tools/probe_private_backend_chardev.py",
        ROOT / "tools/probe_private_backend_module.py",
        ROOT / "tools/audit_uvm_pm_lifecycle.py",
        ROOT / "tools/audit_uvm_interface_ownership.py",
        open_source / "kernel-open/common/inc/nv.h",
        open_source / "kernel-open/common/inc/nv-linux.h",
        open_source / "kernel-open/nvidia/nv.c",
        open_source / "kernel-open/nvidia/nv-procfs.c",
        open_source / "kernel-open/nvidia/nv-mmap.c",
        open_provider_source / "nvidia/nv.c",
        openrm_baseline / "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c",
    }
    paths.update(builder.PREVIOUS_SOURCE / relative for relative in previous_vendor_files)
    paths.update((ROOT / "patches/r580.178.04").glob("*.patch"))
    for relative in ("kernel-open/common/inc", "src/common/sdk/nvidia/inc",
                     "src/common/inc", "src/common/inc/swref",
                     "src/nvidia/arch/nvalloc/unix/include"):
        directory = openrm_baseline / relative
        paths.update(path for path in directory.rglob("*")
                     if path.is_file() and not path.is_symlink())
    paths.update(builder.PATCHES)
    paths.update(path for path in baseline.SOURCE_ROOT.rglob("*")
                 if path.is_file() and not path.is_symlink())
    previous = json.loads(builder.PREVIOUS_REPORT.read_text(encoding="utf-8"))
    for item in previous.get("source_changes", []):
        previous_path = Path(item["path"]).resolve(strict=True)
        if not previous_path.is_relative_to(builder.PREVIOUS_SOURCE.resolve(strict=True)):
            raise ValueError("previous source report contains an unsafe path")
        paths.add(previous_path)
    unique_paths = set()
    for raw_path in paths:
        raw_path = Path(raw_path)
        if raw_path.is_symlink() or not raw_path.is_file():
            raise ValueError("pinned build input is not a regular canonical project file")
        path = raw_path.resolve(strict=True)
        if not path.is_relative_to(ROOT):
            raise ValueError("pinned build input escaped the canonical project")
        unique_paths.add(path)
    unique = tuple(sorted(unique_paths, key=lambda path: path.as_posix()))
    return unique


def build_input_archive(paths: tuple[Path, ...]) -> tuple[bytes, list[dict[str, Any]]]:
    payload = io.BytesIO()
    records = []
    directories = set()
    for path in paths:
        if Path(path).is_symlink() or not Path(path).is_file():
            raise ValueError("build input escaped the canonical project or is not a regular file")
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_relative_to(ROOT):
            raise ValueError("build input escaped the canonical project")
        relative = resolved.relative_to(ROOT).as_posix()
        for parent in Path(relative).parents:
            if parent.as_posix() != ".":
                directories.add(parent.as_posix())
        records.append({"path": relative, "bytes": resolved.stat().st_size,
                        "sha256": OPEN_RUNNER.sha256_file(resolved)})
    with tarfile.open(fileobj=payload, mode="w:gz", compresslevel=3) as archive:
        for relative in sorted(directories, key=lambda value: (value.count("/"), value)):
            info = tarfile.TarInfo(relative + "/")
            info.type = tarfile.DIRTYPE
            info.mode = 0o700
            archive.addfile(info)
        for path in sorted(paths, key=lambda item: item.as_posix()):
            archive.add(path, arcname=path.relative_to(ROOT).as_posix(), recursive=False)
    raw = payload.getvalue()
    if not raw or len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("pinned build input archive exceeds its bounded transport size")
    return raw, records


def validate_guest_result(raw: bytes, run_id: str, bundle_sha256: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RESULT_BYTES:
        raise ValueError("guest private build result size is invalid")
    try:
        report = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("guest private build result is not valid JSON") from None
    required = {"schema", "status", "run_id", "bundle_sha256", "hostname", "kernel_release",
                "builder_exit_code", "builder_stdout_sha256", "builder_stderr_sha256",
                "builder_output_bytes", "builder_report", "builder_report_sha256", "artifacts",
                "artifact_archive_bytes", "artifact_archive_sha256", "artifact_archive_base64",
                "module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested",
                "scratch_removed", "staged_bundle_removed"}
    failure = isinstance(report, dict) and report.get("status") == "failed" and "error" in report
    if not isinstance(report, dict) or set(report) != (required | {"error"} if failure else required):
        raise ValueError("guest build result fields differ from the expected schema")
    if report["schema"] != GUEST_RESULT_SCHEMA or report["run_id"] != run_id or \
            report["bundle_sha256"] != bundle_sha256:
        raise ValueError("guest build result identity differs from the staged build")
    if report["hostname"] != PINNED_HOSTNAME or report["kernel_release"] != PINNED_KERNEL_RELEASE:
        raise ValueError("guest host or target kernel differs from the pinned V100 VM")
    if any(report[field] is not False for field in
           ("module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested")):
        raise ValueError("guest build crossed its compile-only boundary")
    if report["scratch_removed"] is not True or report["staged_bundle_removed"] is not True:
        raise ValueError("guest scratch or staged bundle cleanup was not verified")
    if report["status"] not in ("completed", "failed"):
        raise ValueError("guest build status is invalid")
    if failure and (not isinstance(report["error"], str) or not report["error"] or len(report["error"]) > 200):
        raise ValueError("guest failure detail is invalid")
    builder = report["builder_report"]
    if builder is None:
        if report["status"] != "failed" or report["artifacts"] or report["artifact_archive_bytes"] != 0:
            raise ValueError("guest returned an incomplete successful build result")
        return report
    if not isinstance(builder, dict) or builder.get("schema") != "private-proprietary580-v1":
        raise ValueError("private proprietary builder report schema is invalid")
    expected_report_sha = hashlib.sha256(
        (json.dumps(builder, indent=2, sort_keys=True) + "\n").encode("utf-8")).hexdigest()
    if report["builder_report_sha256"] != expected_report_sha:
        raise ValueError("builder report bytes do not match the captured report digest")
    build_passed = (report["status"] == "completed" and report["builder_exit_code"] == 0 and
                    builder.get("status") == "compiled-private-proprietary-backend" and
                    builder.get("qualification") in (
                        "compiled-module-and-CPU-model-only",
                        "compiled-module-and-CPU-model-only-with-inherited-vendor-objtool-warnings") and
                    builder.get("inputs_unchanged") is True and
                    builder.get("source_tree_unchanged") is True and builder.get("gpl_only_imports") == {})
    if report["status"] == "completed" and not build_passed:
        raise ValueError("private proprietary builder did not report the expected compile-only result")
    if report["status"] == "failed" and (report["builder_exit_code"] == 0 or
                                           builder.get("status") == "compiled-private-proprietary-backend"):
        raise ValueError("guest failed although the builder report claims success")
    if report["status"] not in ("failed", "completed"):
        raise ValueError("guest builder status is invalid")
    for field in ("builder_report_sha256", "builder_stdout_sha256", "builder_stderr_sha256",
                  "artifact_archive_sha256"):
        if not isinstance(report[field], str) or re.fullmatch(r"[0-9a-f]{64}", report[field]) is None:
            raise ValueError("guest build digest is invalid: " + field)
    if (type(report["builder_output_bytes"]) is not int or
            not 0 <= report["builder_output_bytes"] <= MAX_MAKE_OUTPUT_BYTES):
        raise ValueError("guest build output size is invalid")
    if (type(report["artifact_archive_bytes"]) is not int or
            not 0 < report["artifact_archive_bytes"] <= MAX_ARTIFACT_ARCHIVE_BYTES):
        raise ValueError("guest artifact archive size is invalid")
    artifacts = report["artifacts"]
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 64:
        raise ValueError("guest artifact manifest is invalid")
    seen = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ValueError("guest artifact record is invalid")
        path = item["path"]
        if (not isinstance(path, str) or PurePosixPath(path).is_absolute() or
                ".." in PurePosixPath(path).parts or not path.startswith(("build/", "evidence/"))):
            raise ValueError("guest artifact path is unsafe")
        if path in seen or type(item["bytes"]) is not int or \
                not 0 <= item["bytes"] <= MAX_CAPTURED_ARTIFACT_BYTES or \
                not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise ValueError("guest artifact record is duplicated or malformed")
        seen.add(path)
    if report["builder_report_sha256"] not in {item["sha256"] for item in artifacts
                                               if item["path"].startswith("evidence/")}:
        raise ValueError("captured builder report is missing or has a different digest")
    module_records = [item for item in artifacts if item["path"].endswith("/hybrid580_legacy.ko")]
    symvers_records = [item for item in artifacts if item["path"].endswith("/Module.symvers")]
    module = builder.get("module")
    if module is not None:
        if (len(module_records) != 1 or not isinstance(module, dict) or
                module.get("sha256") != module_records[0]["sha256"] or
                module.get("bytes") != module_records[0]["bytes"]):
            raise ValueError("captured private module differs from the builder report")
    if build_passed:
        if len(module_records) != 1 or len(symvers_records) != 1:
            raise ValueError("successful guest capture must include the private module and Module.symvers")
        metadata = builder.get("module_metadata")
        if (not isinstance(metadata, dict) or metadata.get("name") != ["hybrid580_legacy"] or
                metadata.get("license") != ["NVIDIA"] or metadata.get("alias") or
                not metadata.get("vermagic", [""])[0].startswith(PINNED_KERNEL_RELEASE + " ") or
                metadata.get("version") != ["580.178.04"]):
            raise ValueError("private proprietary module identity, license, alias, or vermagic is invalid")
        exports = builder.get("exports")
        conditional = builder.get("conditional_exports")
        if (not isinstance(conditional, dict) or
                set(conditional) != {"feature_macro", "feature_value", "symbol",
                                     "expected_present", "actual_present",
                                     "conftest_symbols_sha256"} or
                conditional.get("feature_macro") != "NV_IS_EXPORT_SYMBOL_GPL___vma_start_write" or
                type(conditional.get("feature_value")) is not int or
                conditional["feature_value"] not in (0, 1) or
                conditional.get("symbol") != "hybrid580_legacy_nv_vma_start_write" or
                conditional.get("expected_present") is not (conditional["feature_value"] == 1) or
                conditional.get("actual_present") is not (conditional["feature_value"] == 1) or
                not isinstance(conditional.get("conftest_symbols_sha256"), str) or
                re.fullmatch(r"[0-9a-f]{64}", conditional["conftest_symbols_sha256"]) is None):
            raise ValueError("private proprietary conditional export evidence is invalid")
        conftest_records = [item for item in artifacts if item["path"].endswith("/conftest/symbols.h")]
        if (len(conftest_records) != 1 or
                conftest_records[0]["sha256"] != conditional["conftest_symbols_sha256"]):
            raise ValueError("captured target conftest does not match conditional export evidence")
        conditional_symbol_present = "hybrid580_legacy_nv_vma_start_write" in exports \
            if isinstance(exports, dict) else False
        expected_export_count = 144 + conditional["feature_value"]
        if (not isinstance(exports, dict) or len(exports) != expected_export_count or
                any(not name.startswith("hybrid580_legacy_") for name in exports)):
            raise ValueError("private proprietary export set differs from the namespaced provider contract")
        if conditional_symbol_present is not (conditional["feature_value"] == 1):
            raise ValueError("conditional VMA wrapper presence differs from target conftest")
        target_validation = builder.get("target_kernel_validation")
        objtool_validation = builder.get("objtool_command")
        diagnostic_classification = (objtool_validation.get("diagnostic_classification")
                                     if isinstance(objtool_validation, dict) else None)
        metadata_skip_count = (objtool_validation.get("existing_link_metadata_skip_count", 0)
                               if isinstance(objtool_validation, dict) else None)
        metadata_skip_sections = (objtool_validation.get("existing_link_metadata_skip_sections", [])
                                  if isinstance(objtool_validation, dict) else None)
        warning_counts_by_kind = (objtool_validation.get("warning_counts_by_kind")
                                  if isinstance(objtool_validation, dict) else None)
        enhanced_objtool_report = (
            diagnostic_classification ==
            "exact-core-symbol-warnings-and-idempotent-link-metadata-skips")
        legacy_objtool_report = (
            diagnostic_classification ==
            "all-emitted-warnings-match-unchanged-proprietary-core")
        enhanced_objtool_details_valid = (
            not enhanced_objtool_report or
            (isinstance(warning_counts_by_kind, dict) and
             set(warning_counts_by_kind) == {"naked_return", "frame_pointer_call"} and
             all(type(count) is int and count >= 0
                 for count in warning_counts_by_kind.values()) and
             sum(warning_counts_by_kind.values()) == objtool_validation.get("warning_count") and
             type(metadata_skip_count) is int and metadata_skip_count >= 0 and
             isinstance(metadata_skip_sections, list) and
             metadata_skip_count == len(metadata_skip_sections) and
             metadata_skip_sections == sorted(metadata_skip_sections) and
             all(section in ("retpoline_sites", "return_sites")
                 for section in metadata_skip_sections)))
        if (not isinstance(target_validation, dict) or
                target_validation.get("kernel_release") != PINNED_KERNEL_RELEASE or
                not isinstance(target_validation.get("config_sha256"), str) or
                re.fullmatch(r"[0-9a-f]{64}", target_validation["config_sha256"]) is None or
                not isinstance(target_validation.get("config_features"), dict) or
                target_validation.get("objtool_present") is not True or
                not isinstance(objtool_validation, dict) or
                objtool_validation.get("mode") not in
                ("explicit-target-kernel-tool", "kbuild-and-explicit-target-kernel-tool") or
                objtool_validation.get("required_flags_present") !=
                ["--retpoline", "--rethunk", "--sls", "--stackval", "--prefix=16"] or
                type(objtool_validation.get("warning_count")) is not int or
                objtool_validation["warning_count"] < 0 or
                objtool_validation.get("warning_instances_from_unchanged_core") !=
                objtool_validation["warning_count"] or
                type(objtool_validation.get("warning_symbol_count")) is not int or
                objtool_validation["warning_symbol_count"] < 0 or
                not isinstance(objtool_validation.get("warning_symbol_set_sha256"), str) or
                re.fullmatch(r"[0-9a-f]{64}",
                             objtool_validation["warning_symbol_set_sha256"]) is None or
                objtool_validation.get("unclassified_diagnostics") != 0 or
                type(objtool_validation.get("exit_code")) is not int or
                not (legacy_objtool_report or enhanced_objtool_report) or
                (legacy_objtool_report and
                 (metadata_skip_count != 0 or metadata_skip_sections not in ([], None))) or
                not enhanced_objtool_details_valid or
                not isinstance(objtool_validation.get("sha256"), str) or
                re.fullmatch(r"[0-9a-f]{64}", objtool_validation["sha256"]) is None or
                objtool_validation.get("target_kernel_objtool_sha256") !=
                target_validation.get("objtool_sha256")):
            raise ValueError("target kernel or objtool validation evidence is invalid")
        config_records = [item for item in artifacts if item["path"].endswith("/target-kernel.config")]
        command_records = [item for item in artifacts
                           if item["path"].endswith("/.hybrid580_legacy.o.cmd")]
        if (len(config_records) != 1 or config_records[0]["sha256"] !=
                target_validation["config_sha256"] or len(command_records) != 1 or
                command_records[0]["sha256"] != objtool_validation["sha256"]):
            raise ValueError("captured kernel config or objtool command differs from build evidence")
        warning_qualification = builder.get("qualification") == \
            "compiled-module-and-CPU-model-only-with-inherited-vendor-objtool-warnings"
        if warning_qualification is not (objtool_validation["warning_count"] > 0 or
                                          objtool_validation["exit_code"] != 0):
            raise ValueError("build qualification does not reflect inherited objtool warnings")
    try:
        packed = base64.b64decode(report["artifact_archive_base64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("guest artifact archive encoding is invalid") from None
    if len(packed) != report["artifact_archive_bytes"] or hashlib.sha256(packed).hexdigest() != \
            report["artifact_archive_sha256"]:
        raise ValueError("guest artifact archive digest or length mismatch")
    if build_passed:
        with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
            symbol_members = [member for member in archive.getmembers()
                              if member.name.endswith("/conftest/symbols.h")]
            if len(symbol_members) != 1 or not symbol_members[0].isfile():
                raise ValueError("target conftest symbols artifact is absent or duplicated")
            symbol_data = archive.extractfile(symbol_members[0])
            if symbol_data is None:
                raise ValueError("target conftest symbols artifact cannot be read")
            try:
                symbols_text = symbol_data.read(MAX_CAPTURED_ARTIFACT_BYTES + 1).decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise ValueError("target conftest symbols artifact is not UTF-8") from None
            if len(symbols_text.encode("utf-8")) != symbol_members[0].size or \
                    symbol_members[0].size > MAX_CAPTURED_ARTIFACT_BYTES:
                raise ValueError("target conftest symbols artifact size is invalid")
            feature_rows = re.findall(
                r"^#define\s+NV_IS_EXPORT_SYMBOL_GPL___vma_start_write\s+([01])\s*$",
                symbols_text, flags=re.M)
            if (len(feature_rows) != 1 or
                    int(feature_rows[0]) != builder["conditional_exports"]["feature_value"]):
                raise ValueError("conditional export report differs from target conftest symbols")
            symbol_record = next(item for item in artifacts
                                 if item["path"] == symbol_members[0].name)
            if hashlib.sha256(symbols_text.encode("utf-8")).hexdigest() != symbol_record["sha256"]:
                raise ValueError("target conftest symbols digest differs from its artifact manifest")
    report["_artifact_archive_bytes"] = packed
    return report


def collect(jobs: int) -> tuple[dict[str, Any], int]:
    transport = OPEN_RUNNER.load_transport()
    OPEN_RUNNER.verify_pc3_host_key()
    if (transport.DEFAULT_PC3_TARGET != PINNED_PC3_TARGET or
            transport.DEFAULT_HOST_KEY_ALIAS != PINNED_PC3_HOST_KEY_ALIAS or
            transport.DEFAULT_CREDENTIAL_HOST != PINNED_CREDENTIAL_HOST or
            transport.DEFAULT_CREDENTIAL_FILE != PINNED_CREDENTIAL_FILE):
        raise RuntimeError("canonical PC3 transport or credential source changed")
    paths = input_bundle_paths()
    bundle, pinned_inputs = build_input_archive(paths)
    bundle_sha256 = hashlib.sha256(bundle).hexdigest()
    run_id = uuid.uuid4().hex
    pc3_stage = f"/tmp/codex-legacy580-{run_id}.tar"
    guest_code_bytes = GUEST_BUILD_SCRIPT.replace("JOBS=4", f"JOBS={jobs}").encode("utf-8")
    guest_code_sha = hashlib.sha256(guest_code_bytes).hexdigest()
    upload_command = " ".join(shlex.quote(part) for part in
                               ["python3", "-c", PC3_UPLOAD_SCRIPT, pc3_stage, bundle_sha256])
    try:
        upload = subprocess.run(transport.pc3_ssh_base(PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS) +
                                [upload_command], input=bundle, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired):
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 private proprietary build bundle upload failed or timed out") from None
    if upload.returncode != 0:
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 did not stage the private proprietary build input bundle")
    try:
        upload_receipt = json.loads(upload.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 private build bundle receipt is invalid") from None
    if upload_receipt != {"bytes": len(bundle), "sha256": bundle_sha256}:
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 staged bundle receipt differs from the local archive")
    try:
        secret = transport.fetch_pc3_sudo_secret(PINNED_CREDENTIAL_HOST, PINNED_CREDENTIAL_FILE)
    except Exception:
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise
    guest_b64 = base64.b64encode(guest_code_bytes).decode("ascii")
    root_command = "sudo -S -p '' python3 -c " + shlex.quote(PC3_ROOT_RUN_SCRIPT) + " " + " ".join(
        shlex.quote(value) for value in (pc3_stage, bundle_sha256, run_id, guest_b64, guest_code_sha))
    try:
        result = subprocess.run(transport.pc3_ssh_base(PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS) +
                                [root_command], input=transport.sudo_auth_stdin(secret),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2500, check=False)
    except (OSError, subprocess.TimeoutExpired):
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("isolated V100 guest private proprietary build transport failed") from None
    finally:
        secret = None
    if result.returncode != 0 or len(result.stdout) > MAX_RESULT_BYTES * 2:
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 did not return a bounded private legacy R580 build result")
    try:
        envelope = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 returned an invalid private legacy R580 transport envelope") from None
    cleanup_retried = False
    if isinstance(envelope, dict) and envelope.get("pc3_bundle_removed") is False:
        cleanup_retried = cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
    envelope_required = {"schema", "guest_ssh_exit_code", "guest_stdout_b64", "guest_stderr_sha256",
                         "hostkey_fingerprint", "pc3_bundle_removed"}
    if (not isinstance(envelope, dict) or set(envelope) != envelope_required or
            envelope.get("schema") != "nvidia-hybrid-pc3-v100-private-legacy580-transport-v1" or
            envelope.get("guest_ssh_exit_code") != 0 or
            envelope.get("hostkey_fingerprint") != GUEST_HOSTKEY_FINGERPRINT or
            not isinstance(envelope.get("pc3_bundle_removed"), bool) or
            (not envelope["pc3_bundle_removed"] and not cleanup_retried)):
        cleanup_pc3_bundle(transport, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 transport identity or staged-input cleanup failed")
    try:
        guest_stdout = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("PC3 private legacy result encoding is invalid") from None
    guest = validate_guest_result(guest_stdout, run_id, bundle_sha256)
    extracted = []
    if guest["artifacts"]:
        artifacts_view = {key: guest[key] for key in ("artifacts", "_artifact_archive_bytes")}
        extracted = extract_output_archive(artifacts_view)
    builder_report = guest.get("builder_report")
    qualification = ((builder_report or {}).get("qualification", "build-or-analysis-failed"))
    capture = {
        "schema": CAPTURE_SCHEMA,
        "status": "collected" if guest["status"] == "completed" else "build-failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": PINNED_PC3_TARGET,
        "guest_hostname": guest["hostname"],
        "guest_kernel_release": guest["kernel_release"],
        "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
        "run_id": run_id,
        "bundle": {"bytes": len(bundle), "sha256": bundle_sha256,
                   "guest_script_sha256": guest_code_sha,
                   "pc3_root_script_sha256": hashlib.sha256(PC3_ROOT_RUN_SCRIPT.encode()).hexdigest(),
                   "pc3_upload_script_sha256": hashlib.sha256(PC3_UPLOAD_SCRIPT.encode()).hexdigest(),
                   "inputs": pinned_inputs},
        "builder_qualification": qualification,
        "guest_error": guest.get("error"),
        "builder_exit_code": guest["builder_exit_code"],
        "builder_report_sha256": guest["builder_report_sha256"],
        "builder_report": builder_report,
        "retrieved_artifacts": extracted,
        "guest_stderr_sha256": envelope["guest_stderr_sha256"],
        "remote_scratch_removed": guest["scratch_removed"],
        "remote_bundle_removed": guest["staged_bundle_removed"],
        "pc3_stage_bundle_removed": envelope["pc3_bundle_removed"] or cleanup_retried,
        "pc3_stage_cleanup_retried": cleanup_retried,
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
    }
    return capture, (0 if guest["status"] == "completed" else 1)


def extract_output_archive(report: dict[str, Any]) -> list[dict[str, Any]]:
    packed = report.get("_artifact_archive_bytes")
    if not isinstance(packed, bytes):
        raise ValueError("validated guest artifact bytes are missing")
    expected = {item["path"]: item for item in report["artifacts"]}
    payloads = []
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
        members = archive.getmembers()
        if ({member.name for member in members} != set(expected) or
                any(not member.isfile() or member.issym() or member.islnk() for member in members)):
            raise ValueError("guest artifact archive contents differ from its manifest")
        for member in members:
            record = expected[member.name]
            if member.size != record["bytes"] or member.size > MAX_CAPTURED_ARTIFACT_BYTES:
                raise ValueError("guest artifact size differs from its manifest")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("guest artifact member cannot be read")
            data = source.read(MAX_CAPTURED_ARTIFACT_BYTES + 1)
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("guest artifact hash differs from its manifest")
            payloads.append((member.name, data, record["sha256"]))
    extracted = []
    for name, data, digest in payloads:
        destination = OPEN_RUNNER.safe_output_path(name)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        extracted.append({"path": name, "bytes": len(data), "sha256": digest})
    return extracted


def cleanup_pc3_bundle(transport: Any, path: str, digest: str) -> bool:
    command = " ".join(shlex.quote(part) for part in
                       ["python3", "-c", PC3_CLEANUP_SCRIPT, path, digest])
    try:
        result = subprocess.run(transport.pc3_ssh_base(PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS) +
                                [command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        receipt = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        return False
    return receipt in ({"removed": True, "already_missing": False},
                       {"removed": False, "already_missing": True})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="private evidence report path inside the canonical project")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 8:
        parser.error("jobs must be between one and eight")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = Path(args.report) if args.report else Path(
        f"evidence/pc3-v100-private-proprietary580-build-v1-{stamp}.json")
    destination = raw_path if raw_path.is_absolute() else ROOT / raw_path
    destination = Path(os.path.abspath(destination))
    try:
        rel = destination.relative_to(ROOT).as_posix()
    except ValueError:
        parser.error("report destination must remain inside the canonical project")
    if not rel.startswith("evidence/"):
        parser.error("capture report must be inside the evidence directory")
    try:
        destination = OPEN_RUNNER.safe_output_path(rel)
        capture, exit_code = collect(args.jobs)
    except Exception as error:
        capture = {
            "schema": CAPTURE_SCHEMA, "status": "failed",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": PINNED_PC3_TARGET, "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
            "compile_only": True, "module_installed": False, "module_loaded": False,
            "gpu_accessed": False, "cuda_execution_tested": False,
            "failure": f"{type(error).__name__}: {str(error)[:200]}",
        }
        exit_code = 2
    try:
        digest = OPEN_RUNNER.write_private_json(destination, capture)
    except OSError as error:
        print(f"could not publish private build evidence: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(destination), "sha256": digest,
                      "status": capture["status"],
                      "qualification": capture.get("builder_qualification")}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
