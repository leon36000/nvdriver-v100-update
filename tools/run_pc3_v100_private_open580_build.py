#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the pinned private Open R580 provider for PC3's V100 guest kernel, compile-only."""
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
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PINNED_HOSTNAME = "pc3-v100"
PINNED_KERNEL_RELEASE = "6.8.0-147-generic"
GUEST_HOSTKEY_FINGERPRINT = "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
PINNED_PC3_TARGET = "pc3@pc3"
PINNED_PC3_HOST_KEY_ALIAS = "pc3"
PINNED_PC3_HOST_KEY_FINGERPRINT = "SHA256:04QMvstMuydvbUvYWq7HguzzjN1RzwG8zoqL4olbs5g"
PINNED_CREDENTIAL_HOST = "gx10-e526"
PINNED_CREDENTIAL_FILE = "/home/pc6/Desktop/ACCES-BANC-GPU.env"
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_RESULT_BYTES = 48 * 1024 * 1024
MAX_ARTIFACT_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_CAPTURED_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_MAKE_OUTPUT_BYTES = 16 * 1024 * 1024


GUEST_BUILD_SCRIPT = r'''import base64,datetime,hashlib,io,json,os,platform,re,shutil,signal,stat,subprocess,sys,tarfile,tempfile
EXPECTED_HOST="pc3-v100"
EXPECTED_KERNEL="6.8.0-147-generic"
JOBS=4
MAX_BUNDLE=268435456
MAX_ARTIFACT_ARCHIVE=33554432
MAX_CAPTURED_ARTIFACT=67108864
MAX_MAKE_OUTPUT_BYTES=16777216
run_id=sys.argv[3]
if not re.fullmatch(r"[0-9a-f]{32}",run_id): raise SystemExit(2)
if platform.node()!=EXPECTED_HOST or platform.release()!=EXPECTED_KERNEL: raise SystemExit(3)
expected_sha=sys.argv[2]
bundle_path="/tmp/codex-open580-"+run_id+".tar"
scratch="/tmp/codex-open580-"+run_id
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
 with tarfile.open(bundle_path,"r:") as archive:
  members=archive.getmembers()
  if not members or len(members)>256: raise ValueError("bundle member count is invalid")
  seen=set()
  for member in members:
   if not safe_name(member.name) or member.name in seen or not member.isfile() or member.size>MAX_BUNDLE:
    raise ValueError("bundle contains an unsafe member")
   seen.add(member.name)
  archive.extractall(scratch,members=members,filter="data")
 root=scratch
 source=os.path.join(root,"tools","build_private_open580_wrapper.py")
 builder_report=os.path.join(root,"evidence","private-open580-guestkernel-"+run_id+".json")
 work=os.path.join(root,"build","experiments","pc3-v100-private-open580-"+run_id)
 legacy_module="build/experiments/private-proprietary-gpu-name-string-v3-20261028/nvidia-580.178.04/hybrid580_legacy.ko"
 os.makedirs(os.path.dirname(builder_report),mode=0o700,exist_ok=True)
 command=[sys.executable,source,"--work",work,"--report",builder_report,"--kernel-release",EXPECTED_KERNEL,"--jobs",str(JOBS),"--legacy-module",legacy_module]
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
  stdout,stderr=build.communicate()
  exit_code=124
 if len(stdout)+len(stderr)>MAX_MAKE_OUTPUT_BYTES: raise ValueError("builder output exceeded its bound")
 try:
  with open(builder_report,"rb") as stream: report_raw=stream.read(4*1024*1024+1)
  if len(report_raw)>4*1024*1024: raise ValueError("builder report exceeded its bound")
  report=json.loads(report_raw.decode("utf-8","strict"))
 except Exception: report=None
 artifact_paths=[]
 if report is not None:
  artifact_paths.append(builder_report)
  artifact_paths.append(os.path.join(work,"prepared-source-changes.patch"))
  source_top="NVIDIA-kernel-module-source-580.178.04"
  artifact_paths.extend([
   os.path.join(work,"baseline",source_top,"kernel-open","Module.symvers"),
   os.path.join(work,"private",source_top,"kernel-open","hybrid580_open.ko"),
   os.path.join(work,"private",source_top,"kernel-open","Module.symvers"),
  ])
  conftest_dir=os.path.join(work,"private",source_top,"kernel-open","conftest")
  if os.path.isdir(conftest_dir) and not os.path.islink(conftest_dir):
   artifact_paths.extend(os.path.join(conftest_dir,name) for name in sorted(os.listdir(conftest_dir))
    if name.endswith(".h"))
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
 with tarfile.open(fileobj=packed,mode="w:gz",compresslevel=6) as output:
  for rel,content in unique:
   info=tarfile.TarInfo(rel);info.size=len(content);info.mode=0o600;info.mtime=0
   output.addfile(info,io.BytesIO(content))
 packed_bytes=packed.getvalue()
 if len(packed_bytes)>MAX_ARTIFACT_ARCHIVE: raise ValueError("captured build artifacts exceeded their bound")
 result={"schema":"nvidia-hybrid-pc3-v100-private-open580-build-result-v1",
  "status":"completed" if report is not None else "failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":exit_code,"builder_stdout_sha256":digest_bytes(stdout),
  "builder_stderr_sha256":digest_bytes(stderr),"builder_output_bytes":len(stdout)+len(stderr),
  "builder_report":report,"builder_report_sha256":digest_bytes(report_raw) if report is not None else None,
  "artifacts":[{"path":rel,"bytes":len(content),"sha256":digest_bytes(content)} for rel,content in unique],
  "artifact_archive_bytes":len(packed_bytes),"artifact_archive_sha256":digest_bytes(packed_bytes),
  "artifact_archive_base64":base64.b64encode(packed_bytes).decode("ascii"),
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
except Exception as error:
 result={"schema":"nvidia-hybrid-pc3-v100-private-open580-build-result-v1","status":"failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":None,"builder_stdout_sha256":digest_bytes(b""),
  "builder_stderr_sha256":digest_bytes(b""),"builder_output_bytes":0,
  "builder_report":None,"builder_report_sha256":None,"artifacts":[],
  "artifact_archive_bytes":0,"artifact_archive_sha256":digest_bytes(b""),
  "artifact_archive_base64":"","error":type(error).__name__+": "+str(error)[:160],
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
finally:
 if created_scratch:
  try: shutil.rmtree(scratch)
  except OSError: pass
 if created_bundle:
  try: os.unlink(bundle_path)
  except OSError: pass
 result=result or {"schema":"nvidia-hybrid-pc3-v100-private-open580-build-result-v1","status":"failed",
  "run_id":run_id,"bundle_sha256":expected_sha,"hostname":platform.node(),"kernel_release":platform.release(),
  "builder_exit_code":None,"builder_stdout_sha256":digest_bytes(b""),
  "builder_stderr_sha256":digest_bytes(b""),"builder_output_bytes":0,
  "builder_report":None,"builder_report_sha256":None,"artifacts":[],
  "artifact_archive_bytes":0,"artifact_archive_sha256":digest_bytes(b""),
  "artifact_archive_base64":"","error":"guest build ended without result",
  "module_installed":False,"module_loaded":False,"gpu_accessed":False,"cuda_execution_tested":False}
 result["scratch_removed"]=not os.path.lexists(scratch)
 result["staged_bundle_removed"]=not os.path.lexists(bundle_path)
print(json.dumps(result,separators=(",",":"),sort_keys=True))
'''


PC3_UPLOAD_SCRIPT = r'''import hashlib,json,os,re,stat,sys
if len(sys.argv)!=3: raise SystemExit(2)
path,digest=sys.argv[1:]
if not re.fullmatch(r"/tmp/codex-open580-[0-9a-f]{32}\.tar",path) or not re.fullmatch(r"[0-9a-f]{64}",digest): raise SystemExit(3)
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
h=hashlib.sha256();size=0
try:
 with os.fdopen(fd,"wb") as out:
  while True:
   block=sys.stdin.buffer.read(1024*1024)
   if not block: break
   size+=len(block)
   if size>268435456: raise ValueError("bundle exceeded size bound")
   h.update(block);out.write(block)
  out.flush();os.fsync(out.fileno())
 if h.hexdigest()!=digest: raise ValueError("bundle digest mismatch")
 print(json.dumps({"bytes":size,"sha256":digest},separators=(",",":"),sort_keys=True))
except BaseException:
 try: os.unlink(path)
 except OSError: pass
 raise
'''


PC3_CLEANUP_SCRIPT = r'''import hashlib,json,os,re,stat,sys
if len(sys.argv)!=3: raise SystemExit(2)
path,digest=sys.argv[1:]
if not re.fullmatch(r"/tmp/codex-open580-[0-9a-f]{32}\.tar",path) or not re.fullmatch(r"[0-9a-f]{64}",digest): raise SystemExit(3)
try: st=os.lstat(path)
except FileNotFoundError:
 print(json.dumps({"removed":False,"already_missing":True},separators=(",",":"),sort_keys=True));raise SystemExit(0)
if not stat.S_ISREG(st.st_mode) or st.st_mode&0o077: raise SystemExit(4)
h=hashlib.sha256()
with open(path,"rb") as stream:
 for block in iter(lambda:stream.read(1024*1024),b""):h.update(block)
if h.hexdigest()!=digest: raise SystemExit(5)
os.unlink(path)
print(json.dumps({"removed":True,"already_missing":False},separators=(",",":"),sort_keys=True))
'''


PC3_ROOT_RUN_SCRIPT = r'''import base64,hashlib,json,os,re,shlex,stat,subprocess,sys
KEY="/var/lib/pc3-v100-vm/id_ed25519"
KNOWN="/tmp/codex-pc3-vm-known_hosts"
EXPECTED="SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
MAX_BUNDLE=268435456
MAX_RESULT=50331648
if os.geteuid()!=0 or len(sys.argv)!=6: raise SystemExit(2)
bundle_path,expected_sha,run_id,guest_code_b64,guest_code_sha=sys.argv[1:]
if not re.fullmatch(r"/tmp/codex-open580-[0-9a-f]{32}\.tar",bundle_path) or not re.fullmatch(r"[0-9a-f]{64}",expected_sha) or not re.fullmatch(r"[0-9a-f]{32}",run_id): raise SystemExit(3)
try: st=os.lstat(bundle_path)
except OSError: raise SystemExit(4)
if not stat.S_ISREG(st.st_mode) or st.st_mode&0o077 or st.st_size>MAX_BUNDLE: raise SystemExit(5)
def sha_file(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
 return h.hexdigest()
if sha_file(bundle_path)!=expected_sha: raise SystemExit(6)
try:key_st=os.lstat(KEY);known_st=os.lstat(KNOWN)
except OSError:raise SystemExit(7)
if not stat.S_ISREG(key_st.st_mode) or key_st.st_uid!=0 or stat.S_IMODE(key_st.st_mode)!=0o600:raise SystemExit(8)
if not stat.S_ISREG(known_st.st_mode) or known_st.st_uid!=0 or known_st.st_mode&0o022:raise SystemExit(9)
selected=subprocess.run(["/usr/bin/ssh-keygen","-F","[127.0.0.1]:22223","-f",KNOWN],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False)
lines=[x for x in selected.stdout.decode("utf-8","strict").splitlines() if x and not x.startswith("#")]
fps=set()
for line in lines:
 fields=line.split()
 if len(fields)<3 or fields[0].startswith("@"):raise SystemExit(10)
 blob=base64.b64decode(fields[2],validate=True)
 fps.add("SHA256:"+base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("="))
if selected.returncode or fps!={EXPECTED}:raise SystemExit(11)
try:guest_code=base64.b64decode(guest_code_b64,validate=True)
except Exception:raise SystemExit(12)
if hashlib.sha256(guest_code).hexdigest()!=guest_code_sha:raise SystemExit(13)
remote=shlex.join(["python3","-c",guest_code.decode("utf-8","strict"),"/tmp/codex-open580-"+run_id+".tar",expected_sha,run_id])
ssh=["/usr/bin/ssh","-F","/dev/null","-T","-oBatchMode=yes","-oIdentitiesOnly=yes","-oStrictHostKeyChecking=yes","-oUserKnownHostsFile="+KNOWN,"-oConnectTimeout=8","-oConnectionAttempts=1","-i",KEY,"-p","22223","ubuntu@127.0.0.1",remote]
try:
 with open(bundle_path,"rb") as stream:
  result=subprocess.run(ssh,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2400,check=False)
except Exception:raise SystemExit(14)
try:os.unlink(bundle_path)
except OSError:pc3_bundle_removed=False
else:pc3_bundle_removed=not os.path.lexists(bundle_path)
if len(result.stdout)>MAX_RESULT:raise SystemExit(15)
envelope={"schema":"nvidia-hybrid-pc3-v100-private-open580-transport-v1","guest_ssh_exit_code":result.returncode,"guest_stdout_b64":base64.b64encode(result.stdout).decode("ascii"),"guest_stderr_sha256":hashlib.sha256(result.stderr).hexdigest(),"hostkey_fingerprint":EXPECTED,"pc3_bundle_removed":pc3_bundle_removed}
print(json.dumps(envelope,separators=(",",":"),sort_keys=True))
'''


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_pc3_transport_identity(target: str, host_key_alias: str) -> None:
    if target != PINNED_PC3_TARGET or host_key_alias != PINNED_PC3_HOST_KEY_ALIAS:
        raise ValueError("target and host-key alias must match the pinned PC3 endpoint")


def validate_pc3_root_envelope(envelope: object, cleanup_verified: bool = False) -> dict[str, Any]:
    expected = {"schema", "guest_ssh_exit_code", "guest_stdout_b64", "guest_stderr_sha256",
                "hostkey_fingerprint", "pc3_bundle_removed"}
    if (not isinstance(envelope, dict) or set(envelope) != expected or
            envelope.get("schema") != "nvidia-hybrid-pc3-v100-private-open580-transport-v1" or
            envelope.get("guest_ssh_exit_code") != 0 or
            envelope.get("hostkey_fingerprint") != GUEST_HOSTKEY_FINGERPRINT or
            not isinstance(envelope.get("guest_stderr_sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", envelope["guest_stderr_sha256"]) is None or
            not isinstance(envelope.get("guest_stdout_b64"), str) or
            not isinstance(envelope.get("pc3_bundle_removed"), bool)):
        raise ValueError("PC3 guest identity or private build transport failed validation")
    try:
        guest_stdout = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("PC3 guest result encoding is invalid") from None
    if not guest_stdout or len(guest_stdout) > MAX_RESULT_BYTES:
        raise ValueError("PC3 guest result size is invalid")
    if not envelope["pc3_bundle_removed"] and not cleanup_verified:
        raise ValueError("PC3 stage cleanup is not verified")
    return envelope


def known_hosts_fingerprints(text: str) -> set[str]:
    fingerprints = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[1].startswith("@"):
            raise ValueError("pinned PC3 known_hosts entry is malformed")
        try:
            key = base64.b64decode(fields[2], validate=True)
        except ValueError:
            raise ValueError("pinned PC3 known_hosts key is malformed") from None
        fingerprint = base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")
        fingerprints.add("SHA256:" + fingerprint)
    return fingerprints


def verify_pc3_host_key() -> None:
    known_hosts = Path.home() / ".ssh/known_hosts"
    try:
        result = subprocess.run(["/usr/bin/ssh-keygen", "-F", PINNED_PC3_HOST_KEY_ALIAS,
                                 "-f", str(known_hosts)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("pinned PC3 host key could not be verified") from None
    if result.returncode != 0:
        raise RuntimeError("pinned PC3 host key is missing from known_hosts")
    try:
        observed = known_hosts_fingerprints(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        raise RuntimeError("pinned PC3 known_hosts entry is invalid") from None
    if observed != {PINNED_PC3_HOST_KEY_FINGERPRINT}:
        raise RuntimeError("PC3 host key fingerprint differs from the pinned endpoint")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned project build helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def input_bundle_paths() -> tuple[Path, ...]:
    builder = load_module(ROOT / "tools/build_private_open580_wrapper.py", "private_open580_bundle_builder")
    release = builder.source_release("580.178.04")
    legacy = json.loads(builder.LEGACY_REPORT.read_text(encoding="utf-8"))
    legacy_module = Path(legacy["module"]["path"])
    paths = [
        Path(__file__).resolve(),
        ROOT / "tools/build_private_open580_wrapper.py",
        ROOT / "tests/test_private_open580_wrapper.py",
        Path(release["archive"]),
        Path(release["core"]),
        builder.LEGACY_REPORT,
        legacy_module,
        legacy_module.parent / "Module.symvers",
    ]
    paths.extend(legacy_module.parent / "nvidia" / name for name in (
        "hybrid580-control-session.h", "hybrid580-gpu-session.h", "hybrid580-file-projection.h"))
    paths.extend(builder.patch_paths())
    paths.extend(ROOT / "src" / name for name in builder.AUTHORED_HEADERS)
    unique = tuple(dict.fromkeys(Path(path).resolve(strict=True) for path in paths))
    for path in unique:
        if not path.is_relative_to(ROOT) or path.is_symlink() or not path.is_file():
            raise ValueError("pinned build input is not a regular canonical project file")
    return unique


def build_input_archive(paths: tuple[Path, ...]) -> tuple[bytes, list[dict[str, Any]]]:
    payload = io.BytesIO()
    records = []
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for path in paths:
            relative = path.relative_to(ROOT).as_posix()
            info = path.stat()
            if info.st_size > MAX_BUNDLE_BYTES:
                raise ValueError("one pinned build input exceeds the bundle size bound")
            archive.add(path, arcname=relative, recursive=False)
            records.append({"path": relative, "bytes": info.st_size, "sha256": sha256_file(path)})
    raw = payload.getvalue()
    if not raw or len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("pinned build input archive size is invalid")
    return raw, records


def validate_guest_result(raw: bytes, run_id: str, bundle_sha256: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RESULT_BYTES:
        raise ValueError("guest build result size is invalid")
    try:
        report = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("guest build result is not valid UTF-8 JSON") from None
    required_fields = {"schema", "status", "run_id", "bundle_sha256", "hostname", "kernel_release", "builder_exit_code",
                       "builder_stdout_sha256", "builder_stderr_sha256", "builder_output_bytes",
                       "builder_report", "builder_report_sha256", "artifacts", "artifact_archive_bytes",
                       "artifact_archive_sha256", "artifact_archive_base64", "module_installed", "module_loaded",
                       "gpu_accessed", "cuda_execution_tested", "scratch_removed", "staged_bundle_removed"}
    has_failure_detail = isinstance(report, dict) and report.get("status") == "failed" and "error" in report
    if not isinstance(report, dict) or set(report) != (required_fields | {"error"} if has_failure_detail else required_fields):
        raise ValueError("guest build result fields differ from the expected schema")
    if report["schema"] != "nvidia-hybrid-pc3-v100-private-open580-build-result-v1":
        raise ValueError("guest build result schema is unsupported")
    if report["bundle_sha256"] != bundle_sha256:
        raise ValueError("guest bundle SHA-256 differs from the staged input")
    if (report["run_id"] != run_id or report["hostname"] != PINNED_HOSTNAME or
            report["kernel_release"] != PINNED_KERNEL_RELEASE):
        raise ValueError("guest build identity differs from the pinned V100 target")
    if report["module_installed"] is not False or report["module_loaded"] is not False or \
            report["gpu_accessed"] is not False or report["cuda_execution_tested"] is not False:
        raise ValueError("guest build crossed the compile-only execution boundary")
    if report["scratch_removed"] is not True or report["staged_bundle_removed"] is not True:
        raise ValueError("guest build scratch was not verified removed")
    if report["status"] not in ("completed", "failed"):
        raise ValueError("guest build status is invalid")
    if "error" in report and (report["status"] != "failed" or not isinstance(report["error"], str) or
                              not report["error"] or len(report["error"]) > 200):
        raise ValueError("guest build failure detail is invalid")
    if report["status"] == "completed":
        builder_report = report["builder_report"]
        if not isinstance(builder_report, dict) or builder_report.get("kernel_release") != PINNED_KERNEL_RELEASE:
            raise ValueError("builder report target kernel differs from the pinned guest")
        if report["builder_report_sha256"] is None or \
                re.fullmatch(r"[0-9a-f]{64}", report["builder_report_sha256"]) is None:
            raise ValueError("builder report SHA-256 is invalid")
        if type(report["builder_exit_code"]) is not int:
            raise ValueError("builder exit code is invalid")
        for field in ("builder_stdout_sha256", "builder_stderr_sha256", "artifact_archive_sha256"):
            if not isinstance(report[field], str) or re.fullmatch(r"[0-9a-f]{64}", report[field]) is None:
                raise ValueError(f"guest {field} is invalid")
        if type(report["builder_output_bytes"]) is not int or not 0 <= report["builder_output_bytes"] <= MAX_MAKE_OUTPUT_BYTES:
            raise ValueError("guest builder output size is invalid")
        if type(report["artifact_archive_bytes"]) is not int or not 0 < report["artifact_archive_bytes"] <= MAX_ARTIFACT_ARCHIVE_BYTES:
            raise ValueError("guest artifact archive size is invalid")
        artifacts = report["artifacts"]
        if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 64:
            raise ValueError("guest build artifact manifest is invalid")
        seen = set()
        for item in artifacts:
            if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
                raise ValueError("guest build artifact record is invalid")
            path = item["path"]
            if not isinstance(path, str) or PurePosixPath(path).is_absolute() or \
                    ".." in PurePosixPath(path).parts or not path.startswith(("build/", "evidence/")):
                raise ValueError("guest build artifact path is unsafe")
            if path in seen:
                raise ValueError("guest build artifact path is duplicated")
            seen.add(path)
            if type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_CAPTURED_ARTIFACT_BYTES:
                raise ValueError("guest build artifact size is invalid")
            if not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
                raise ValueError("guest build artifact SHA-256 is invalid")
        try:
            packed = base64.b64decode(report["artifact_archive_base64"], validate=True)
        except (ValueError, TypeError):
            raise ValueError("guest build artifact archive encoding is invalid") from None
        if len(packed) != report["artifact_archive_bytes"] or \
                hashlib.sha256(packed).hexdigest() != report["artifact_archive_sha256"]:
            raise ValueError("guest build artifact archive digest or size mismatch")
        report["_artifact_archive_bytes"] = packed
    if not isinstance(bundle_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", bundle_sha256) is None:
        raise ValueError("local pinned build bundle SHA-256 is invalid")
    return report


def safe_output_path(relative: str) -> Path:
    candidate = ROOT / relative
    candidate = Path(os.path.abspath(candidate))
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        raise ValueError("build artifact path escaped the canonical project") from None
    cursor = ROOT
    parts = candidate.parent.relative_to(ROOT).parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            cursor.mkdir(mode=0o700)
            info = cursor.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("build artifact parent contains an unsafe path component")
    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError("build artifact destination already exists")
    return candidate


def extract_output_archive(report: dict[str, Any]) -> list[dict[str, Any]]:
    packed = report.get("_artifact_archive_bytes")
    if not isinstance(packed, bytes):
        raise ValueError("validated guest artifact bytes are missing")
    expected = {item["path"]: item for item in report["artifacts"]}
    extracted = []
    payloads = []
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
        members = archive.getmembers()
        if ({m.name for m in members} != set(expected) or
                any(not m.isfile() or m.issym() or m.islnk() for m in members)):
            raise ValueError("guest artifact archive contents differ from its manifest")
        for member in members:
            record = expected[member.name]
            if member.size != record["bytes"] or member.size > MAX_CAPTURED_ARTIFACT_BYTES:
                raise ValueError("guest artifact member size differs from its manifest")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("guest artifact member cannot be read")
            data = source.read(MAX_CAPTURED_ARTIFACT_BYTES + 1)
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("guest artifact member hash differs from its manifest")
            payloads.append((member.name, data, record["sha256"]))
    for name, data, digest in payloads:
        destination = safe_output_path(name)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        extracted.append({"path": name, "bytes": len(data), "sha256": digest})
    return extracted


def load_transport():
    return load_module(ROOT / "tools/run_pc3_v100_guest_reference.py", "pc3_v100_guest_reference_transport")


def cleanup_pc3_bundle(transport, target: str, host_key_alias: str,
                       path: str, digest: str) -> bool:
    command = " ".join(shlex.quote(part) for part in
                       ["python3", "-c", PC3_CLEANUP_SCRIPT, path, digest])
    try:
        result = subprocess.run(transport.pc3_ssh_base(target, host_key_alias) + [command],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
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


def collect(jobs: int) -> tuple[dict[str, Any], int]:
    transport = load_transport()
    validate_pc3_transport_identity(PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS)
    verify_pc3_host_key()
    if (transport.DEFAULT_PC3_TARGET != PINNED_PC3_TARGET or
            transport.DEFAULT_HOST_KEY_ALIAS != PINNED_PC3_HOST_KEY_ALIAS or
            transport.DEFAULT_CREDENTIAL_HOST != PINNED_CREDENTIAL_HOST or
            transport.DEFAULT_CREDENTIAL_FILE != PINNED_CREDENTIAL_FILE):
        raise RuntimeError("canonical PC3 transport or credential source changed")
    paths = input_bundle_paths()
    bundle, pinned_inputs = build_input_archive(paths)
    bundle_sha256 = hashlib.sha256(bundle).hexdigest()
    run_id = uuid.uuid4().hex
    pc3_stage = f"/tmp/codex-open580-{run_id}.tar"
    guest_code_bytes = GUEST_BUILD_SCRIPT.replace("JOBS=4", f"JOBS={jobs}").encode("utf-8")
    guest_code_sha = hashlib.sha256(guest_code_bytes).hexdigest()
    upload_command = " ".join(shlex.quote(part) for part in
                               ["python3", "-c", PC3_UPLOAD_SCRIPT, pc3_stage, bundle_sha256])
    try:
        upload = subprocess.run(transport.pc3_ssh_base(PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS) + [upload_command],
                                input=bundle, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=600, check=False)
    except (OSError, subprocess.TimeoutExpired):
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 private build bundle upload failed or timed out") from None
    if upload.returncode != 0:
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 did not stage the private build input bundle")
    try:
        upload_receipt = json.loads(upload.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 private build bundle receipt is invalid") from None
    if upload_receipt != {"bytes": len(bundle), "sha256": bundle_sha256}:
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 private build bundle receipt differs from the local archive")
    try:
        secret = transport.fetch_pc3_sudo_secret(PINNED_CREDENTIAL_HOST, PINNED_CREDENTIAL_FILE)
    except Exception:
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise
    guest_b64 = base64.b64encode(guest_code_bytes).decode("ascii")
    root_command = "sudo -S -p '' python3 -c " + shlex.quote(PC3_ROOT_RUN_SCRIPT) + " " + " ".join(
        shlex.quote(value) for value in (pc3_stage, bundle_sha256, run_id, guest_b64, guest_code_sha))
    try:
        result = subprocess.run(transport.pc3_ssh_base(PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS) + [root_command],
                                input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=2500, check=False)
    except (OSError, subprocess.TimeoutExpired):
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("isolated V100 guest build transport failed or timed out") from None
    finally:
        secret = None
    if result.returncode != 0 or len(result.stdout) > MAX_RESULT_BYTES * 2:
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 did not return a bounded private Open R580 build result")
    try:
        envelope = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 returned an invalid private Open R580 build envelope") from None
    cleanup_retried = False
    if isinstance(envelope, dict) and envelope.get("pc3_bundle_removed") is False:
        cleanup_retried = cleanup_pc3_bundle(
            transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
    try:
        envelope = validate_pc3_root_envelope(envelope, cleanup_verified=cleanup_retried)
    except ValueError:
        cleanup_pc3_bundle(transport, PINNED_PC3_TARGET, PINNED_PC3_HOST_KEY_ALIAS, pc3_stage, bundle_sha256)
        raise RuntimeError("PC3 guest identity, result, or stage cleanup failed validation") from None
    guest_raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    guest = validate_guest_result(guest_raw, run_id, bundle_sha256)
    extracted = extract_output_archive(guest) if guest["status"] == "completed" else []
    builder_report = guest.get("builder_report") if guest["status"] == "completed" else None
    qualification = (builder_report or {}).get("qualification", "failed")
    capture = {
        "schema": "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1",
        "status": "collected" if guest["status"] == "completed" else "failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": PINNED_PC3_TARGET,
        "guest_hostname": guest.get("hostname"),
        "guest_kernel_release": guest.get("kernel_release"),
        "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
        "run_id": run_id,
        "bundle": {"bytes": len(bundle), "sha256": bundle_sha256,
                   "guest_script_sha256": guest_code_sha,
                   "pc3_root_script_sha256": hashlib.sha256(PC3_ROOT_RUN_SCRIPT.encode()).hexdigest(),
                   "pc3_upload_script_sha256": hashlib.sha256(PC3_UPLOAD_SCRIPT.encode()).hexdigest(),
                   "inputs": pinned_inputs},
        "builder_qualification": qualification,
        "guest_error": guest.get("error"),
        "builder_exit_code": guest.get("builder_exit_code"),
        "builder_report_sha256": guest.get("builder_report_sha256"),
        "builder_report": builder_report,
        "retrieved_artifacts": extracted,
        "guest_stderr_sha256": envelope["guest_stderr_sha256"],
        "remote_scratch_removed": guest.get("scratch_removed") is True,
        "remote_bundle_removed": guest.get("staged_bundle_removed") is True,
        "pc3_stage_bundle_removed": envelope["pc3_bundle_removed"] or cleanup_retried,
        "pc3_stage_cleanup_retried": cleanup_retried,
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
    }
    return capture, (0 if qualification == "compiled-native-private-open580-provider-only" else 1)


def write_private_json(path: Path, report: dict[str, Any]) -> str:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(payload).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="private evidence report path inside the canonical project")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 8:
        parser.error("jobs must be between one and eight")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = Path(args.report) if args.report else Path(f"evidence/pc3-v100-private-open580-build-v1-{stamp}.json")
    destination = raw_path if raw_path.is_absolute() else ROOT / raw_path
    destination = Path(os.path.abspath(destination))
    try:
        destination.relative_to(ROOT)
    except ValueError:
        parser.error("report destination must remain inside the canonical project")
    try:
        rel = destination.relative_to(ROOT).as_posix()
        if not rel.startswith("evidence/"):
            raise ValueError("capture report must be inside the evidence directory")
        destination = safe_output_path(rel)
        capture, exit_code = collect(args.jobs)
    except Exception as error:
        capture = {
            "schema": "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1",
            "status": "failed",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": PINNED_PC3_TARGET,
            "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
            "read_only_or_compile_only": True,
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "failure": f"{type(error).__name__}: {str(error)[:200]}",
        }
        exit_code = 2
    try:
        digest = write_private_json(destination, capture)
    except OSError as error:
        print(f"could not publish private build evidence: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(destination), "sha256": digest,
                      "status": capture["status"], "qualification": capture.get("builder_qualification")},
                     sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
