#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and canary-test the fixed-target R580 kprobe observer on PC3's V100 guest."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OBSERVER_DIR = ROOT / "probes/pc3_r580_kprobe_observer"
SOURCE_PATH = OBSERVER_DIR / "pc3_r580_kprobe_observer.c"
KBUILD_PATH = OBSERVER_DIR / "Kbuild"
AUDIT_PATH = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
MODULE_NAME = "pc3_r580_kprobe_observer"
TARGET_SYMBOL = "nvidia:rm_init_adapter"
SELECTOR_SYMBOLS = ("nvidia:_nv000790rm", "nvidia:_nv031399rm")
GUEST_SSH_TIMEOUT_SECONDS = 360
REMOTE_TIMEOUT_SECONDS = 420


def lookup_branch_capture_result(requested: bool, parameter_value: str | None,
                                 decision_before: int | None,
                                 decision_after: int | None,
                                 taken_before: int | None,
                                 taken_after: int | None,
                                 not_taken_before: int | None,
                                 not_taken_after: int | None,
                                 target_before: int | None,
                                 target_after: int | None) -> bool | None:
    """Require one JBE decision and a matching taken-edge target count."""
    if not requested:
        return None
    values=(decision_before,decision_after,taken_before,taken_after,
            not_taken_before,not_taken_after,target_before,target_after)
    if parameter_value not in ("Y", "1") or not all(
            isinstance(value,int) for value in values):
        return False
    decision_delta=decision_after-decision_before
    taken_delta=taken_after-taken_before
    not_taken_delta=not_taken_after-not_taken_before
    target_delta=target_after-target_before
    return (decision_delta==1 and taken_delta+not_taken_delta==decision_delta and
            taken_delta in (0,1) and not_taken_delta in (0,1) and
            target_delta==taken_delta)


LOOKUP_JOIN_PREDECESSOR_TARGETS = (
    "nvidia:_nv031364rm+0x31d", "nvidia:_nv031364rm+0x9c1",
    "nvidia:_nv031364rm+0xa94", "nvidia:_nv031364rm+0xaaa",
    "nvidia:_nv031364rm+0xdaa",
)
LOOKUP_JOIN_PREDECESSOR_PARAMETERS = (
    "lookup_join_031d_hits", "lookup_join_09c1_hits",
    "lookup_join_0a94_hits", "lookup_join_0aaa_hits",
    "lookup_join_0daa_hits",
)

SUCCESS_STATUSES = frozenset((
    "build_only_passed", "disabled_registration_passed",
    "active_registration_passed", "active_capture_passed",
    "active_selector_observation_passed", "active_selector_capture_passed",
    "active_lookup_callsite_capture_passed", "active_lookup_branch_capture_passed",
    "active_lookup_join_route_capture_passed",
    "active_lookup_return_site_capture_passed",
))


def status_is_success(status: str) -> bool:
    """Recognize every terminal success status emitted by the guest runner."""
    return status in SUCCESS_STATUSES


def lookup_join_predecessor_capture_result(
        requested: bool, parameter_value: str | None,
        before: dict[str, int | None] | None,
        after: dict[str, int | None] | None,
        callsite_delta: int | None) -> str | bool | None:
    """Identify exactly one fixed predecessor for one observed lookup call."""
    if not requested:
        return None
    expected = set(LOOKUP_JOIN_PREDECESSOR_TARGETS)
    if (parameter_value not in ("Y", "1") or not isinstance(before, dict) or
            not isinstance(after, dict) or set(before) != expected or
            set(after) != expected or callsite_delta != 1):
        return False
    if not all(isinstance(before[key], int) and isinstance(after[key], int)
               for key in expected):
        return False
    deltas = {key: after[key] - before[key] for key in expected}
    if any(delta < 0 for delta in deltas.values()):
        return False
    hits = [key for key, delta in deltas.items() if delta == 1]
    if sum(deltas.values()) != 1 or len(hits) != 1:
        return False
    return hits[0]


def lookup_return_site_capture_result(
        requested: bool, ready_before: str | None, ready_after: str | None,
        lookup_before: int | None, lookup_after: int | None,
        matches_before: int | None, matches_after: int | None,
        read_failures_before: int | None, read_failures_after: int | None,
        unmatched_before: int | None, unmatched_after: int | None) -> bool | None:
    """Require one lookup entry and one matching hidden return IP, with no faults."""
    if not requested:
        return None
    values = (lookup_before, lookup_after, matches_before, matches_after,
              read_failures_before, read_failures_after,
              unmatched_before, unmatched_after)
    if (ready_before not in ("Y", "1") or ready_after not in ("Y", "1") or
            not all(type(value) is int for value in values)):
        return False
    return (lookup_after - lookup_before == 1 and
            matches_after - matches_before == 1 and
            read_failures_after - read_failures_before == 0 and
            unmatched_after - unmatched_before == 0)


def lookup_join_return_route_capture_result(
        requested: bool, parameter_value: str | None,
        before: dict[str, int | None] | None,
        after: dict[str, int | None] | None,
        return_site_capture_passed: bool | None) -> str | bool | None:
    """Require one fixed predecessor in the window of one safe lookup match."""
    if not requested:
        return None
    expected = set(LOOKUP_JOIN_PREDECESSOR_TARGETS)
    if (parameter_value not in ("Y", "1") or return_site_capture_passed is not True or
            not isinstance(before, dict) or not isinstance(after, dict) or
            set(before) != expected or set(after) != expected):
        return False
    if not all(type(before[key]) is int and type(after[key]) is int
               for key in expected):
        return False
    deltas = {key: after[key] - before[key] for key in expected}
    if any(delta < 0 for delta in deltas.values()):
        return False
    hits = [key for key, delta in deltas.items() if delta == 1]
    if sum(deltas.values()) != 1 or len(hits) != 1:
        return False
    return hits[0]


def set_guest_ssh_timeout(wrapper: str) -> str:
    """Extend the pinned helper's inner SSH timeout with an exact one-token edit."""
    original = "result = run(argv, timeout=100)"
    if wrapper.count(original) != 1:
        raise RuntimeError("pinned PC3 transport wrapper timeout anchor changed")
    return wrapper.replace(original,
                           f"result = run(argv, timeout={GUEST_SSH_TIMEOUT_SECONDS})")

GUEST_PROBE = r'''import base64,csv,fcntl,hashlib,json,os,re,shutil,signal,stat,subprocess,tempfile,time
from pathlib import Path

MODULE = "pc3_r580_kprobe_observer"
TARGET = "nvidia:rm_init_adapter"
SELECTOR_TARGETS = ("nvidia:_nv000790rm", "nvidia:_nv031399rm")
LOOKUP_CALLSITE_TARGET = "nvidia:_nv031364rm+0x92"
LOOKUP_BRANCH_TARGET = "nvidia:_nv031364rm+0xd7e"
LOOKUP_BRANCH_DECISION_TARGET = "nvidia:_nv031364rm+0xa81"
LOOKUP_JOIN_PREDECESSOR_TARGETS = __LOOKUP_JOIN_PREDECESSOR_TARGETS__
LOOKUP_JOIN_PREDECESSOR_PARAMETERS = __LOOKUP_JOIN_PREDECESSOR_PARAMETERS__
OBSERVE_SELECTOR_PATH = __OBSERVE_SELECTOR_PATH__
CAPTURE_LOOKUP_CALLSITE = __CAPTURE_LOOKUP_CALLSITE__
CAPTURE_LOOKUP_BRANCH = __CAPTURE_LOOKUP_BRANCH__
CAPTURE_LOOKUP_RETURN_SITE = __CAPTURE_LOOKUP_RETURN_SITE__
CAPTURE_LOOKUP_JOIN_ROUTE = __CAPTURE_LOOKUP_JOIN_ROUTE__
CAPTURE_SELECTOR = (__CAPTURE_SELECTOR__ or CAPTURE_LOOKUP_CALLSITE)
FILES = __FILES__
REPORT = {
  "schema":("nvidia-hybrid-pc3-r580-direct-kprobe-canary-v12"
            if CAPTURE_LOOKUP_JOIN_ROUTE else
            "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v11"
            if CAPTURE_LOOKUP_RETURN_SITE else
            "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v10"
            if CAPTURE_LOOKUP_BRANCH else
            "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v7"
            if CAPTURE_LOOKUP_CALLSITE else
            "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v6"
            if CAPTURE_SELECTOR else
            "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v4"
            if OBSERVE_SELECTOR_PATH else "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v3"),
  "status":"preflight_failed",
  "hostname":os.uname().nodename,
  "kernel_release":os.uname().release,
  "effective_uid":os.geteuid(),
  "target":TARGET,
  "lookup_return_site_capture_requested":CAPTURE_LOOKUP_RETURN_SITE,
  "lookup_join_route_capture_requested":CAPTURE_LOOKUP_JOIN_ROUTE,
  "observer_module_loaded_at_end":False,
  "kprobe_attached_at_end":False,
  "stock_driver_changed":None,
  "final_integrity_passed":None,
  "final_integrity_failures":None,
  "pci_binding_changed":None,
  "pci_binding_change_requested":False,
  "firmware_or_vm_change":None,
  "firmware_or_vm_change_requested":False,
  "trace_event_definition_write_attempted":False,
  "runner_lock_acquired":False,
}
WORK = None
KEEP_WORK = False
CANARY_STARTED = False
CANARY_ATTEMPTED = False
LOCK_FD = None
OWNER_NONCE = int.from_bytes(os.urandom(8), "big") & ((1 << 63) - 1)
if OWNER_NONCE == 0:
    OWNER_NONCE = 1
REPORT["owner_nonce_sha256"] = hashlib.sha256(str(OWNER_NONCE).encode("ascii")).hexdigest()

def run(argv, timeout=30):
    env={k:v for k,v in os.environ.items() if not k.startswith(("LD_","CUDA_","NVIDIA_","PYTHON"))}
    env.update({"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"})
    try:
        result=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              timeout=timeout,check=False,env=env)
        return {"returncode":result.returncode,
                "stdout":result.stdout.decode("utf-8","replace"),
                "stderr":result.stderr.decode("utf-8","replace"),
                "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),
                "stderr_sha256":hashlib.sha256(result.stderr).hexdigest()}
    except subprocess.TimeoutExpired as exc:
        return {"returncode":None,"stdout":"","stderr":"timeout",
                "stdout_sha256":hashlib.sha256(exc.stdout or b"").hexdigest(),
                "stderr_sha256":hashlib.sha256(exc.stderr or b"").hexdigest(),
                "timed_out":True}
    except OSError as exc:
        return {"returncode":None,"stdout":"","stderr":"",
                "error_class":type(exc).__name__}

def target_lines():
    path=Path("/sys/kernel/debug/kprobes/list")
    if not path.is_file():
        return None
    try:
        return [re.sub(r"^(?:0x)?[0-9a-fA-F]+", "<kaslr-address-redacted>", line.strip(), count=1)
                for line in path.read_text(errors="replace").splitlines()
                if any(target.split(":",1)[1] in line
                       for target in (TARGET,)+SELECTOR_TARGETS+
                       (LOOKUP_CALLSITE_TARGET,LOOKUP_BRANCH_TARGET,
                        LOOKUP_BRANCH_DECISION_TARGET)+
                       LOOKUP_JOIN_PREDECESSOR_TARGETS)]
    except OSError:
        return None

def probe_targets_match(lines, expected_names, disabled):
    if (not isinstance(lines, list) or not isinstance(expected_names, (tuple, list)) or
        not expected_names or len(lines) != len(expected_names) or
        any(not isinstance(line, str) for line in lines)):
        return False
    for name in expected_names:
        if (not isinstance(name, str) or not name or
            sum(name in line for line in lines) != 1):
            return False
    return all(("[DISABLED]" in line) is disabled for line in lines)

def gpu_rows():
    result=run(["nvidia-smi","--query-gpu=name,pci.bus_id,driver_version",
                "--format=csv,noheader"],timeout=20)
    if result.get("returncode") != 0:
        return result,[]
    rows=[]
    for row in csv.reader(result["stdout"].splitlines()):
        if len(row)==3:
            rows.append({"name":row[0].strip(),"pci":row[1].strip(),
                         "driver_version":row[2].strip()})
    return result,rows

def compute_pids():
    result=run(["nvidia-smi","--query-compute-apps=pid",
                "--format=csv,noheader,nounits"],timeout=20)
    if result.get("returncode") != 0:
        return None,result
    pids=[]
    for line in result["stdout"].splitlines():
        value=line.strip()
        if not value:
            continue
        if value.isascii() and value.isdigit() and int(value)>0:
            pids.append(int(value))
        else:
            return None,result
    return pids,result

def parameter(name):
    try:
        return Path("/sys/module")/MODULE/"parameters"/name
    except Exception:
        return None

def read_parameter(name):
    path=parameter(name)
    try:
        return path.read_text().strip()
    except OSError:
        return None

def owns_module():
    if not Path("/sys/module").joinpath(MODULE).exists():
        return False
    return read_parameter("owner_nonce") == str(OWNER_NONCE)

def parameter_uint(name):
    value=read_parameter(name)
    if value is None or not value.isascii() or not value.isdigit():
        return None
    return int(value)

def kernel_taint():
    try:
        value=Path("/proc/sys/kernel/tainted").read_text().strip()
    except OSError:
        return None
    if not value.isascii() or not value.isdigit():
        return None
    return int(value)

def acquire_runner_lock(path="/run/pc3-r580-kprobe-observer.lock", expected_uid=0):
    flags=os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0)
    fd=os.open(path,flags,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=expected_uid:
            raise RuntimeError("observer lock file has an unexpected type, link count, or owner")
        if stat.S_IMODE(info.st_mode)!=0o600:
            os.fchmod(fd,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another PC3 observer runner holds the lock") from exc
        return fd
    except BaseException:
        os.close(fd)
        raise

def mark_runner_lock_unavailable():
    REPORT["status"]="runner_lock_unavailable"
    for name in ("observer_module_loaded_at_end","observer_module_owned_at_end",
                 "unowned_observer_module_at_end","kprobe_attached_at_end",
                 "target_probe_lines_at_end","target_probe_list_unchanged",
                 "kernel_taint_after","kernel_taint_unchanged",
                 "gpu_identity_unchanged","stock_driver_changed"):
        REPORT[name]=None

def final_integrity_violations(report):
    """Require independently observed clean state before qualifying a canary."""
    expected = {
      "stock_driver_changed":False,
      "kernel_taint_unchanged":True,
      "gpu_identity_unchanged":True,
      "target_probe_list_unchanged":True,
      "observer_module_loaded_at_end":False,
      "kprobe_attached_at_end":False,
      "unowned_observer_module_at_end":False,
    }
    return [name for name, value in expected.items() if report.get(name) is not value]

def final_status_after_cleanup(report, canary_attempted):
    if canary_attempted and final_integrity_violations(report):
        return "cleanup_or_integrity_failed"
    return report.get("status", "failed")

def parse_selector_observation(value):
    """Parse the single atomic count/scalar observation exposed by the module."""
    if not isinstance(value,str):
        return None
    match=re.fullmatch(r"([0-9a-fA-F]{8}) (unavailable|[0-9a-fA-F]{8})",
                       value.strip())
    if match is None:
        return None
    count=int(match.group(1),16)
    sample=None if match.group(2)=="unavailable" else int(match.group(2),16)
    return count,sample

def selector_observation_count(value):
    observation=parse_selector_observation(value)
    return observation[0] if observation is not None else None

def selector_capture_result(capture_requested, parameter_value,
                            before_observation, after_observation):
    """Accept one count increment and its scalar from the same atomic snapshot."""
    if not capture_requested:
        return None
    before=parse_selector_observation(before_observation)
    after=parse_selector_observation(after_observation)
    return (parameter_value in ("Y", "1") and before is not None and
            after is not None and after[0] - before[0] == 1 and
            after[1] is not None)

def parse_lookup_callsite_observation(value):
    """Parse one count plus the EDI/ESI/EDX tuple from a fixed callsite."""
    if not isinstance(value,str):
        return None
    match=re.fullmatch(
        r"([0-9a-fA-F]{16}) (unavailable|[0-9a-fA-F]{8} [0-9a-fA-F]{8} [0-9a-fA-F]{8})",
        value.strip())
    if match is None:
        return None
    count=int(match.group(1),16)
    if match.group(2)=="unavailable":
        return count,None
    return count,tuple(int(part,16) for part in match.group(2).split())

def lookup_callsite_capture_result(capture_requested, parameter_value,
                                   before_observation, after_observation,
                                   dropped_before, dropped_after,
                                   lookup_before=None, lookup_after=None):
    """Require one complete callsite tuple, no drops, and the same ESI at lookup entry."""
    if not capture_requested:
        return None
    before=parse_lookup_callsite_observation(before_observation)
    after=parse_lookup_callsite_observation(after_observation)
    result=(parameter_value in ("Y", "1") and before is not None and
            after is not None and before[1] is None and after[1] is not None and
            after[0]-before[0]==1 and isinstance(dropped_before,int) and
            isinstance(dropped_after,int) and dropped_before==0 and dropped_after==0)
    if not result:
        return False
    if lookup_before is None or lookup_after is None:
        return False
    lookup_before_value=parse_selector_observation(lookup_before)
    lookup_after_value=parse_selector_observation(lookup_after)
    return (lookup_before_value is not None and lookup_after_value is not None and
            lookup_after_value[0]-lookup_before_value[0]==1 and
            lookup_after_value[1] is not None and
            after[1][1]==lookup_after_value[1])

def lookup_branch_capture_result(capture_requested, parameter_value,
                                 decision_before, decision_after,
                                 taken_before, taken_after,
                                 not_taken_before, not_taken_after,
                                 target_before, target_after):
    """Require one JBE decision, outcome counts, and matching target hit."""
    if not capture_requested:
        return None
    values=(decision_before,decision_after,taken_before,taken_after,
            not_taken_before,not_taken_after,target_before,target_after)
    if parameter_value not in ("Y", "1") or not all(
            isinstance(value,int) for value in values):
        return False
    decision_delta=decision_after-decision_before
    taken_delta=taken_after-taken_before
    not_taken_delta=not_taken_after-not_taken_before
    target_delta=target_after-target_before
    return (decision_delta==1 and taken_delta+not_taken_delta==decision_delta and
            taken_delta in (0,1) and not_taken_delta in (0,1) and
            target_delta==taken_delta)

def lookup_join_predecessor_capture_result(requested, parameter_value,
                                           before, after, callsite_delta):
    """Identify exactly one fixed predecessor for one observed lookup call."""
    if not requested:
        return None
    expected=set(LOOKUP_JOIN_PREDECESSOR_TARGETS)
    if (parameter_value not in ("Y", "1") or not isinstance(before,dict) or
            not isinstance(after,dict) or set(before)!=expected or
            set(after)!=expected or callsite_delta!=1):
        return False
    if not all(isinstance(before[key],int) and isinstance(after[key],int)
               for key in expected):
        return False
    deltas={key:after[key]-before[key] for key in expected}
    if any(delta<0 for delta in deltas.values()):
        return False
    hits=[key for key,delta in deltas.items() if delta==1]
    if sum(deltas.values())!=1 or len(hits)!=1:
        return False
    return hits[0]

def lookup_return_site_capture_result(requested, ready_before, ready_after,
                                      lookup_before, lookup_after,
                                      matches_before, matches_after,
                                      read_failures_before, read_failures_after,
                                      unmatched_before, unmatched_after):
    if not requested:
        return None
    values=(lookup_before,lookup_after,matches_before,matches_after,
            read_failures_before,read_failures_after,
            unmatched_before,unmatched_after)
    if (ready_before not in ("Y","1") or ready_after not in ("Y","1") or
            not all(type(value) is int for value in values)):
        return False
    return (lookup_after-lookup_before==1 and
            matches_after-matches_before==1 and
            read_failures_after-read_failures_before==0 and
            unmatched_after-unmatched_before==0)

def lookup_join_return_route_capture_result(requested, parameter_value,
                                            before, after,
                                            return_site_capture_passed):
    if not requested:
        return None
    expected=set(LOOKUP_JOIN_PREDECESSOR_TARGETS)
    if (parameter_value not in ("Y", "1") or
        return_site_capture_passed is not True or
        not isinstance(before,dict) or not isinstance(after,dict) or
        set(before)!=expected or set(after)!=expected):
        return False
    if not all(type(before[key]) is int and type(after[key]) is int
               for key in expected):
        return False
    deltas={key:after[key]-before[key] for key in expected}
    if any(delta<0 for delta in deltas.values()):
        return False
    hits=[key for key,delta in deltas.items() if delta==1]
    if sum(deltas.values())!=1 or len(hits)!=1:
        return False
    return hits[0]

def write_source(work,name,encoded):
    data=base64.b64decode(encoded,validate=True)
    path=work/name
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return {"path":str(path),"bytes":len(data),
            "sha256":hashlib.sha256(data).hexdigest(),
            "mode":oct(path.stat().st_mode&0o777)}

def unload(stage):
    global CANARY_STARTED
    if not Path("/sys/module") .joinpath(MODULE).exists():
        CANARY_STARTED=False
        return {"stage":stage,"returncode":0,"already_absent":True,
                "module_absent_after":True,"target_probe_lines_after":target_lines()}
    if not owns_module():
        return {"stage":stage,"returncode":None,"owner_match":False,
                "module_absent_after":False,"target_probe_lines_after":target_lines(),
                "cleanup_refused":"module owner nonce does not match this runner"}
    result=run(["rmmod",MODULE],timeout=20)
    result["stage"]=stage
    result["module_absent_after"] = not Path("/sys/module").joinpath(MODULE).exists()
    result["target_probe_lines_after"] = target_lines()
    if result.get("module_absent_after") is True and result.get("target_probe_lines_after") == []:
        CANARY_STARTED=False
        return result
    result["cleanup_failed"] = True
    return result

def interrupted(signum, frame):
    raise RuntimeError("remote observer interrupted")

for _signal in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
    signal.signal(_signal, interrupted)

try:
    LOCK_FD=acquire_runner_lock()
    REPORT["runner_lock_acquired"]=True
    if os.geteuid()!=0 or REPORT["hostname"] != "pc3-v100":
        raise RuntimeError("unexpected guest identity or privilege")
    if REPORT["kernel_release"] != "6.8.0-147-generic":
        raise RuntimeError("guest kernel is not the pinned Ubuntu 6.8.0-147 kernel")
    if Path("/sys/module").joinpath(MODULE).exists():
        raise RuntimeError("observer module is already loaded")
    if not Path("/sys/module/nvidia").exists():
        raise RuntimeError("stock NVIDIA module is not loaded")
    if not Path("/sys/kernel/debug/kprobes/list").is_file():
        raise RuntimeError("readable Kprobes debug list is required for cleanup verification")
    before_result,before_gpus=gpu_rows()
    if (before_result.get("returncode")!=0 or len(before_gpus)!=1 or
        "Tesla V100" not in before_gpus[0]["name"] or
        before_gpus[0]["driver_version"]!="580.178.04"):
        raise RuntimeError("unexpected PC3 V100/R580 GPU inventory")
    initial_target_lines=target_lines()
    if initial_target_lines is None or initial_target_lines:
        raise RuntimeError("target already has a kprobe or kprobe list is unreadable")
    pids,pid_query=compute_pids()
    if pids is None:
        raise RuntimeError("could not establish whether a GPU compute workload is active")
    REPORT["gpu_before"]=before_gpus
    REPORT["compute_pids_before_count"]=len(pids)
    REPORT["workload_query_returncode"]=pid_query.get("returncode")
    REPORT["kernel_taint_before"]=kernel_taint()
    REPORT["target_probe_lines_before"]=initial_target_lines
    WORK=Path(tempfile.mkdtemp(prefix="pc3-r580-kprobe-",dir="/tmp"))
    os.chmod(WORK,0o700)
    input_records=[]
    for name,encoded in sorted(FILES.items()):
        input_records.append(write_source(WORK,name,encoded))
    REPORT["staged_inputs"]=input_records
    build=run(["make","-C","/lib/modules/"+REPORT["kernel_release"]+"/build",
               "M="+str(WORK),"modules"],timeout=90)
    REPORT["build"]={key:value for key,value in build.items() if key!="stdout" and key!="stderr"}
    REPORT["build"]["stdout_bytes"]=len(build.get("stdout",""))
    REPORT["build"]["stderr_bytes"]=len(build.get("stderr",""))
    if build.get("returncode")!=0 or build.get("timed_out"):
        REPORT["status"]="build_failed"
        REPORT["build"]["stderr_excerpt"]=build.get("stderr","")[-600:]
        raise RuntimeError("guest kernel module build failed")
    artifact=WORK/(MODULE+".ko")
    if not artifact.is_file():
        REPORT["status"]="build_failed"
        raise RuntimeError("Kbuild returned success without the expected module")
    artifact_bytes=artifact.read_bytes()
    REPORT["artifact"]={"path":str(artifact),"bytes":len(artifact_bytes),
                         "sha256":hashlib.sha256(artifact_bytes).hexdigest(),
                         "mode":oct(artifact.stat().st_mode&0o777)}
    modinfo=run(["modinfo","-F","vermagic",str(artifact)],timeout=10)
    license_info=run(["modinfo","-F","license",str(artifact)],timeout=10)
    REPORT["module_metadata"]={"vermagic":modinfo.get("stdout","").strip(),
                                "license":license_info.get("stdout","").strip(),
                                "vermagic_returncode":modinfo.get("returncode"),
                                "license_returncode":license_info.get("returncode")}
    if (modinfo.get("returncode")!=0 or license_info.get("returncode")!=0 or
        not modinfo.get("stdout","").startswith(REPORT["kernel_release"]+" ") or
        license_info.get("stdout","").strip()!="GPL"):
        REPORT["status"]="build_failed"
        raise RuntimeError("module vermagic or GPL license metadata does not match guest")

    if __BUILD_ONLY__:
        symbol="copy_from_kernel_nofault"
        nm=run(["nm","-u",str(artifact)],timeout=10)
        imported=(nm.get("returncode")==0 and
                  any(line.split() and line.split()[-1]==symbol
                      for line in nm.get("stdout","").splitlines()))
        symvers_path=Path("/lib/modules")/REPORT["kernel_release"]/"build"/"Module.symvers"
        export_rows=[]
        symvers_readable=False
        try:
            for line in symvers_path.read_text(errors="strict").splitlines():
                fields=line.split("\t")
                if len(fields)>=4 and fields[1]==symbol:
                    export_rows.append({"crc":fields[0],"provider":fields[2],
                                        "export_type":fields[3]})
            symvers_readable=True
        except OSError:
            pass
        symbol_check={"symbol":symbol,"nm_returncode":nm.get("returncode"),
                      "imported_by_module":imported,
                      "symvers_readable":symvers_readable,
                      "export_rows":export_rows}
        symbol_check["passed"]=(imported and symvers_readable and
            any(row["export_type"]=="EXPORT_SYMBOL_GPL" for row in export_rows))
        REPORT["kernel_symbol_resolution"]=symbol_check
        if not symbol_check["passed"]:
            REPORT["status"]="build_symbol_resolution_failed"
            raise RuntimeError("nofault helper import is not confirmed in the exact guest Module.symvers")
        REPORT["status"]="build_only_passed"
    else:
        CANARY_ATTEMPTED=True
        disabled_argv=["insmod",str(artifact),"owner_nonce="+str(OWNER_NONCE)]
        if OBSERVE_SELECTOR_PATH:
            disabled_argv.append("observe_selector_path=1")
        disabled_load=run(disabled_argv,timeout=20)
        disabled_owned=owns_module()
        CANARY_STARTED=disabled_owned
        disabled_state={"insmod_returncode":disabled_load.get("returncode"),
                        "insmod_stderr_sha256":disabled_load.get("stderr_sha256"),
                        "module_present":Path("/sys/module").joinpath(MODULE).exists(),
                        "owner_confirmed":disabled_owned,
                        "hits":read_parameter("hits"),"arm":read_parameter("arm"),
                        "selector_hits":parameter_uint("selector_hits"),
                        "lookup_hits":parameter_uint("lookup_hits"),
                        "target_probe_lines":target_lines()}
        REPORT["disabled_registration"]=disabled_state
        if disabled_state["insmod_returncode"]==0 and disabled_state["module_present"]:
            disabled_unload=unload("disabled")
        else:
            disabled_unload=unload("disabled")
        REPORT["disabled_registration"]["cleanup"]=disabled_unload
        expected_targets=(1+len(SELECTOR_TARGETS) if OBSERVE_SELECTOR_PATH else 1)
        expected_names=(tuple(target.split(":",1)[1] for target in SELECTOR_TARGETS)
                        if OBSERVE_SELECTOR_PATH else ())
        disabled_lines=disabled_state["target_probe_lines"]
        disabled_ok=(disabled_state["insmod_returncode"]==0 and
                     disabled_state["module_present"] is True and
                     disabled_state["owner_confirmed"] is True and
                     disabled_state["hits"]=="0" and disabled_state["arm"] in ("N","0") and
                     isinstance(disabled_lines,list) and
                     len(disabled_lines)==expected_targets and
                     all("[DISABLED]" in line for line in disabled_lines) and
                      all(any(name in line for line in disabled_lines)
                         for name in ("rm_init_adapter",)+expected_names) and
                      (not OBSERVE_SELECTOR_PATH or
                      disabled_state["selector_hits"]==0 and
                      disabled_state["lookup_hits"]==0) and
                     disabled_unload.get("module_absent_after") is True and
                     disabled_unload.get("target_probe_lines_after")==[])
        REPORT["disabled_registration"]["passed"]=disabled_ok
        if not disabled_ok:
            REPORT["status"]="disabled_registration_failed"
            raise RuntimeError("disabled registration or exact cleanup verification failed")

        if not __ACTIVE__:
            REPORT["status"]="disabled_registration_passed"
        else:
            active_pids,active_pid_query=compute_pids()
            REPORT["compute_pids_before_active_count"]=(
                len(active_pids) if active_pids is not None else None)
            REPORT["active_workload_query_returncode"]=active_pid_query.get("returncode")
            if active_pids is None:
                REPORT["active_registration"]={"status":"skipped_idle_state_unknown"}
                REPORT["status"]="disabled_registration_passed_active_state_unknown"
            elif active_pids:
                REPORT["active_registration"]={"status":"skipped_gpu_busy",
                    "reason":"GPU compute PIDs appeared before active test"}
                REPORT["status"]="disabled_registration_passed_gpu_busy"
            else:
                CANARY_ATTEMPTED=True
                active_argv=["insmod",str(artifact),"arm=1"]
                active_argv.append("owner_nonce="+str(OWNER_NONCE))
                if __CAPTURE_STATE__:
                    active_argv.append("capture_state=1")
                if OBSERVE_SELECTOR_PATH:
                    active_argv.append("observe_selector_path=1")
                if CAPTURE_SELECTOR:
                    active_argv.append("capture_selector=1")
                if CAPTURE_LOOKUP_CALLSITE:
                    active_argv.append("capture_lookup_callsite=1")
                if CAPTURE_LOOKUP_BRANCH:
                    active_argv.append("capture_lookup_branch=1")
                if CAPTURE_LOOKUP_RETURN_SITE:
                    active_argv.append("capture_lookup_return_site=1")
                if CAPTURE_LOOKUP_JOIN_ROUTE:
                    active_argv.append("capture_lookup_join_route=1")
                active_load=run(active_argv,timeout=20)
                active_owned=owns_module()
                CANARY_STARTED=active_owned
                lookup_observation_before=read_parameter("selector_observation")
                lookup_callsite_observation_before=read_parameter("lookup_callsite_observation") if CAPTURE_LOOKUP_CALLSITE else None
                lookup_callsite_dropped_before=(
                    parameter_uint("lookup_callsite_dropped")
                    if CAPTURE_LOOKUP_CALLSITE else None)
                active_state={"insmod_returncode":active_load.get("returncode"),
                          "insmod_stderr_sha256":active_load.get("stderr_sha256"),
                          "insmod_error_excerpt":(
                              re.sub(r"(?<![A-Za-z0-9])0x[0-9a-fA-F]+",
                                     "<address-redacted>",
                                     active_load.get("stderr", ""))[-600:]
                              if active_load.get("returncode") != 0 else None),
                          "module_present":Path("/sys/module").joinpath(MODULE).exists(),
                          "owner_confirmed":active_owned,
                          "hits_before_trigger":read_parameter("hits"),
                          "state_reads_before_trigger":parameter_uint("state_reads"),
                          "state_read_failures_before_trigger":parameter_uint("state_read_failures"),
                          "state_snapshot_before_trigger":read_parameter("state_snapshot"),
                          "selector_hits_before_trigger":parameter_uint("selector_hits"),
                          "selector_observation_before_trigger":lookup_observation_before,
                          "lookup_hits_before_trigger":selector_observation_count(lookup_observation_before),
                          "arm":read_parameter("arm"),
                          "capture_state":read_parameter("capture_state"),
                          "capture_selector":read_parameter("capture_selector"),
                          "capture_lookup_callsite":read_parameter("capture_lookup_callsite"),
                          "capture_lookup_branch":read_parameter("capture_lookup_branch"),
                          "capture_lookup_return_site":read_parameter("capture_lookup_return_site"),
                          "capture_lookup_join_route":read_parameter("capture_lookup_join_route"),
                          "lookup_return_site_ready_before":read_parameter("lookup_return_site_ready"),
                          "lookup_return_site_matches_before":parameter_uint("lookup_return_site_matches") if CAPTURE_LOOKUP_RETURN_SITE else None,
                          "lookup_return_site_read_failures_before":parameter_uint("lookup_return_site_read_failures") if CAPTURE_LOOKUP_RETURN_SITE else None,
                          "lookup_return_site_unmatched_before":parameter_uint("lookup_return_site_unmatched") if CAPTURE_LOOKUP_RETURN_SITE else None,
                          "lookup_callsite_observation_before":lookup_callsite_observation_before,
                          "lookup_callsite_dropped_before":lookup_callsite_dropped_before,
                          "lookup_branch_hits_before":parameter_uint("lookup_branch_hits") if CAPTURE_LOOKUP_BRANCH else None,
                          "lookup_branch_decision_hits_before":parameter_uint("lookup_branch_decision_hits") if CAPTURE_LOOKUP_BRANCH else None,
                          "lookup_branch_taken_hits_before":parameter_uint("lookup_branch_taken_hits") if CAPTURE_LOOKUP_BRANCH else None,
                          "lookup_branch_not_taken_hits_before":parameter_uint("lookup_branch_not_taken_hits") if CAPTURE_LOOKUP_BRANCH else None,
                          "lookup_join_predecessor_hits_before":{
                              target:parameter_uint(parameter) for target,parameter in
                              zip(LOOKUP_JOIN_PREDECESSOR_TARGETS,
                                  LOOKUP_JOIN_PREDECESSOR_PARAMETERS)}
                              if CAPTURE_LOOKUP_BRANCH or CAPTURE_LOOKUP_JOIN_ROUTE else None,
                          "observe_selector_path":read_parameter("observe_selector_path"),
                          "target_probe_lines":target_lines()}
                REPORT["active_registration"]=active_state
                if active_state["insmod_returncode"]==0 and active_state["module_present"]:
                    trigger=run(["nvidia-smi","-L"],timeout=30)
                    active_state["nvidia_smi_trigger"]={key:trigger.get(key) for key in (
                        "returncode","stdout_sha256","stderr_sha256","timed_out")}
                    active_state["trigger_passed"]=(trigger.get("returncode")==0 and
                                                      not trigger.get("timed_out"))
                    active_state["hits_after_trigger"]=read_parameter("hits")
                    active_state["state_reads_after_trigger"]=parameter_uint("state_reads")
                    active_state["state_read_failures_after_trigger"]=parameter_uint("state_read_failures")
                    active_state["state_snapshot_after_trigger"]=read_parameter("state_snapshot")
                    active_state["selector_hits_after_trigger"]=parameter_uint("selector_hits")
                    lookup_observation_after=read_parameter("selector_observation")
                    active_state["selector_observation_after_trigger"]=lookup_observation_after
                    active_state["lookup_hits_after_trigger"]=selector_observation_count(lookup_observation_after)
                    active_state["lookup_return_site_ready_after_trigger"]=read_parameter("lookup_return_site_ready") if CAPTURE_LOOKUP_RETURN_SITE else None
                    active_state["lookup_return_site_matches_after_trigger"]=(
                        parameter_uint("lookup_return_site_matches")
                        if CAPTURE_LOOKUP_RETURN_SITE else None)
                    active_state["lookup_return_site_read_failures_after_trigger"]=(
                        parameter_uint("lookup_return_site_read_failures")
                        if CAPTURE_LOOKUP_RETURN_SITE else None)
                    active_state["lookup_return_site_unmatched_after_trigger"]=(
                        parameter_uint("lookup_return_site_unmatched")
                        if CAPTURE_LOOKUP_RETURN_SITE else None)
                    lookup_callsite_observation_after=read_parameter("lookup_callsite_observation") if CAPTURE_LOOKUP_CALLSITE else None
                    active_state["lookup_callsite_observation_after_trigger"]=lookup_callsite_observation_after
                    active_state["lookup_callsite_dropped_after_trigger"]=(
                        parameter_uint("lookup_callsite_dropped")
                        if CAPTURE_LOOKUP_CALLSITE else None)
                    active_state["lookup_branch_hits_after_trigger"]=(
                        parameter_uint("lookup_branch_hits")
                        if CAPTURE_LOOKUP_BRANCH else None)
                    active_state["lookup_branch_decision_hits_after_trigger"]=(
                        parameter_uint("lookup_branch_decision_hits")
                        if CAPTURE_LOOKUP_BRANCH else None)
                    active_state["lookup_branch_taken_hits_after_trigger"]=(
                        parameter_uint("lookup_branch_taken_hits")
                        if CAPTURE_LOOKUP_BRANCH else None)
                    active_state["lookup_branch_not_taken_hits_after_trigger"]=(
                        parameter_uint("lookup_branch_not_taken_hits")
                        if CAPTURE_LOOKUP_BRANCH else None)
                    active_state["lookup_join_predecessor_hits_after_trigger"]=(
                        {target:parameter_uint(parameter)
                         for target,parameter in zip(
                             LOOKUP_JOIN_PREDECESSOR_TARGETS,
                             LOOKUP_JOIN_PREDECESSOR_PARAMETERS)}
                        if CAPTURE_LOOKUP_BRANCH or CAPTURE_LOOKUP_JOIN_ROUTE else None)
                    active_state["target_probe_lines_after_trigger"]=target_lines()
                active_cleanup=unload("active")
                active_state["cleanup"]=active_cleanup
                state_capture_ok=(not __CAPTURE_STATE__ or
                    active_state.get("capture_state") in ("Y","1") and
                    isinstance(active_state.get("state_reads_after_trigger"),int) and
                    isinstance(active_state.get("state_reads_before_trigger"),int) and
                    active_state["state_reads_after_trigger"] > active_state["state_reads_before_trigger"] and
                    isinstance(active_state.get("state_snapshot_after_trigger"),str) and
                    re.fullmatch(r"[0-9a-fA-F]{8} [0-9a-fA-F]{8}",
                                 active_state["state_snapshot_after_trigger"].strip()) is not None)
                active_state["state_capture_passed"]=(state_capture_ok
                    if __CAPTURE_STATE__ else None)
                selector_hits_delta=(
                    active_state["selector_hits_after_trigger"] -
                    active_state["selector_hits_before_trigger"]
                    if isinstance(active_state.get("selector_hits_after_trigger"),int) and
                    isinstance(active_state.get("selector_hits_before_trigger"),int) else None)
                lookup_hits_delta=(
                    active_state["lookup_hits_after_trigger"] -
                    active_state["lookup_hits_before_trigger"]
                    if isinstance(active_state.get("lookup_hits_after_trigger"),int) and
                    isinstance(active_state.get("lookup_hits_before_trigger"),int) else None)
                active_state["selector_hits_delta"]=selector_hits_delta
                active_state["lookup_hits_delta"]=lookup_hits_delta
                return_site_capture_result_value=lookup_return_site_capture_result(
                    CAPTURE_LOOKUP_RETURN_SITE,
                    active_state.get("lookup_return_site_ready_before"),
                    active_state.get("lookup_return_site_ready_after_trigger"),
                    active_state.get("lookup_hits_before_trigger"),
                    active_state.get("lookup_hits_after_trigger"),
                    active_state.get("lookup_return_site_matches_before"),
                    active_state.get("lookup_return_site_matches_after_trigger"),
                    active_state.get("lookup_return_site_read_failures_before"),
                    active_state.get("lookup_return_site_read_failures_after_trigger"),
                    active_state.get("lookup_return_site_unmatched_before"),
                    active_state.get("lookup_return_site_unmatched_after_trigger"))
                return_site_capture_ok=(return_site_capture_result_value is not False)
                active_state["lookup_return_site_capture_passed"]=(
                    return_site_capture_result_value)
                selector_capture_result_value=selector_capture_result(
                    CAPTURE_SELECTOR, active_state.get("capture_selector"),
                    active_state.get("selector_observation_before_trigger"),
                    active_state.get("selector_observation_after_trigger"))
                selector_capture_ok=(selector_capture_result_value is not False)
                active_state["selector_capture_passed"]=selector_capture_result_value
                callsite_capture_result_value=lookup_callsite_capture_result(
                    CAPTURE_LOOKUP_CALLSITE,
                    active_state.get("capture_lookup_callsite"),
                    active_state.get("lookup_callsite_observation_before"),
                    active_state.get("lookup_callsite_observation_after_trigger"),
                    active_state.get("lookup_callsite_dropped_before"),
                    active_state.get("lookup_callsite_dropped_after_trigger"),
                    active_state.get("selector_observation_before_trigger"),
                    active_state.get("selector_observation_after_trigger"))
                callsite_capture_ok=(callsite_capture_result_value is not False)
                active_state["lookup_callsite_capture_passed"]=(
                    callsite_capture_result_value)
                branch_hits_after=active_state.get(
                    "lookup_branch_hits_after_trigger")
                branch_hits_delta=(
                    branch_hits_after - active_state["lookup_branch_hits_before"]
                    if isinstance(branch_hits_after,int) and
                    isinstance(active_state.get("lookup_branch_hits_before"),int)
                    else None)
                active_state["lookup_branch_hits_delta"]=branch_hits_delta
                branch_capture_result_value=lookup_branch_capture_result(
                    CAPTURE_LOOKUP_BRANCH,
                    active_state.get("capture_lookup_branch"),
                    active_state.get("lookup_branch_decision_hits_before"),
                    active_state.get("lookup_branch_decision_hits_after_trigger"),
                    active_state.get("lookup_branch_taken_hits_before"),
                    active_state.get("lookup_branch_taken_hits_after_trigger"),
                    active_state.get("lookup_branch_not_taken_hits_before"),
                    active_state.get("lookup_branch_not_taken_hits_after_trigger"),
                    active_state.get("lookup_branch_hits_before"),
                    branch_hits_after)
                branch_capture_ok=(branch_capture_result_value is not False)
                active_state["lookup_branch_capture_passed"]=(
                    branch_capture_result_value)
                branch_taken_delta=(
                    active_state.get("lookup_branch_taken_hits_after_trigger") -
                    active_state.get("lookup_branch_taken_hits_before")
                    if isinstance(active_state.get("lookup_branch_taken_hits_after_trigger"),int) and
                    isinstance(active_state.get("lookup_branch_taken_hits_before"),int)
                    else None)
                branch_not_taken_delta=(
                    active_state.get("lookup_branch_not_taken_hits_after_trigger") -
                    active_state.get("lookup_branch_not_taken_hits_before")
                    if isinstance(active_state.get("lookup_branch_not_taken_hits_after_trigger"),int) and
                    isinstance(active_state.get("lookup_branch_not_taken_hits_before"),int)
                    else None)
                active_state["lookup_branch_taken_hits_delta"]=branch_taken_delta
                active_state["lookup_branch_not_taken_hits_delta"]=branch_not_taken_delta
                active_state["lookup_branch_outcome"]=(
                    "taken" if branch_taken_delta==1 else
                    "not_taken" if branch_not_taken_delta==1 else
                    None if not CAPTURE_LOOKUP_BRANCH else "ambiguous")
                join_predecessor_result=lookup_join_predecessor_capture_result(
                    CAPTURE_LOOKUP_BRANCH,
                    active_state.get("capture_lookup_branch"),
                    active_state.get("lookup_join_predecessor_hits_before"),
                    active_state.get("lookup_join_predecessor_hits_after_trigger"),
                    lookup_hits_delta)
                active_state["lookup_join_predecessor_capture_passed"]=(
                    None if join_predecessor_result is None else
                    join_predecessor_result is not False)
                active_state["lookup_join_predecessor_target"]=(
                    join_predecessor_result if isinstance(join_predecessor_result,str)
                    else None)
                join_return_route_result=lookup_join_return_route_capture_result(
                    CAPTURE_LOOKUP_JOIN_ROUTE,
                    active_state.get("capture_lookup_join_route"),
                    active_state.get("lookup_join_predecessor_hits_before"),
                    active_state.get("lookup_join_predecessor_hits_after_trigger"),
                    return_site_capture_result_value is True)
                active_state["lookup_join_route_capture_passed"]=(
                    None if join_return_route_result is None else
                    join_return_route_result is not False)
                active_state["lookup_join_route_target"]=(
                    join_return_route_result
                    if isinstance(join_return_route_result,str) else None)
                branch_decision_delta=(
                    active_state.get("lookup_branch_decision_hits_after_trigger") -
                    active_state.get("lookup_branch_decision_hits_before")
                    if isinstance(active_state.get("lookup_branch_decision_hits_after_trigger"),int) and
                    isinstance(active_state.get("lookup_branch_decision_hits_before"),int)
                    else None)
                active_state["lookup_branch_decision_hits_delta"]=branch_decision_delta
                branch_path_ok=(not CAPTURE_LOOKUP_BRANCH or
                    branch_capture_result_value is True or
                    branch_decision_delta==0 and join_predecessor_result is not False)
                active_state["lookup_branch_path_capture_passed"]=(
                    branch_path_ok if CAPTURE_LOOKUP_BRANCH else None)
                selector_path_ok=(not OBSERVE_SELECTOR_PATH or
                    active_state.get("observe_selector_path") in ("Y","1") and
                    isinstance(selector_hits_delta,int) and selector_hits_delta > 0 and
                    isinstance(lookup_hits_delta,int) and lookup_hits_delta > 0)
                active_state["selector_path_observation_passed"]=(selector_path_ok
                    if OBSERVE_SELECTOR_PATH else None)
                expected_active_names=("rm_init_adapter",)+(
                    tuple(target.split(":",1)[1] for target in SELECTOR_TARGETS)
                    if OBSERVE_SELECTOR_PATH else ())
                if CAPTURE_LOOKUP_CALLSITE:
                    expected_active_names+=(LOOKUP_CALLSITE_TARGET.split(":",1)[1],)
                    active_state["expected_lookup_callsite_target"]=(
                        LOOKUP_CALLSITE_TARGET)
                if CAPTURE_LOOKUP_BRANCH:
                    expected_active_names+=(LOOKUP_BRANCH_TARGET.split(":",1)[1],)
                    active_state["expected_lookup_branch_target"]=(
                        LOOKUP_BRANCH_TARGET)
                    expected_active_names+=(
                        LOOKUP_BRANCH_DECISION_TARGET.split(":",1)[1],)
                    active_state["expected_lookup_branch_decision_target"]=(
                        LOOKUP_BRANCH_DECISION_TARGET)
                    expected_active_names+=tuple(
                        target.split(":",1)[1]
                        for target in LOOKUP_JOIN_PREDECESSOR_TARGETS)
                if CAPTURE_LOOKUP_JOIN_ROUTE:
                    expected_active_names+=tuple(
                        target.split(":",1)[1]
                        for target in LOOKUP_JOIN_PREDECESSOR_TARGETS)
                active_targets_match=probe_targets_match(
                    active_state["target_probe_lines"], expected_active_names,
                    disabled=False)
                active_state["target_probe_lines_match_expected"]=(
                    active_targets_match)
                active_state["passed"]=(active_state["insmod_returncode"]==0 and
                    active_state["module_present"] is True and
                    active_state["owner_confirmed"] is True and
                    active_state["arm"] in ("Y","1") and
                    active_targets_match and
                    active_state.get("trigger_passed") is True and
                    isinstance(active_state.get("hits_after_trigger"),str) and
                    state_capture_ok and selector_path_ok and selector_capture_ok and
                    callsite_capture_ok and branch_path_ok and return_site_capture_ok and
                    join_predecessor_result is not False and
                    join_return_route_result is not False and
                    active_cleanup.get("module_absent_after") is True and
                    active_cleanup.get("target_probe_lines_after")==[])
                if active_state["passed"]:
                    active_state["observation"]=("hit" if int(active_state["hits_after_trigger"])>0 else "attached_no_hit")
                    REPORT["status"]=("active_lookup_branch_capture_passed"
                                      if CAPTURE_LOOKUP_BRANCH and
                                      branch_capture_result_value is True else
                                      "active_lookup_join_route_capture_passed"
                                      if CAPTURE_LOOKUP_JOIN_ROUTE and
                                      isinstance(join_return_route_result,str) else
                                      "active_lookup_return_site_capture_passed"
                                      if CAPTURE_LOOKUP_RETURN_SITE and
                                      return_site_capture_result_value is True else
                                      "active_lookup_join_route_capture_passed"
                                      if CAPTURE_LOOKUP_BRANCH else
                                      "active_lookup_callsite_capture_passed"
                                      if CAPTURE_LOOKUP_CALLSITE else
                                      "active_capture_passed" if __CAPTURE_STATE__ else
                                      "active_selector_capture_passed" if CAPTURE_SELECTOR else
                                      "active_selector_observation_passed" if OBSERVE_SELECTOR_PATH else
                                      "active_registration_passed")
                else:
                    REPORT["status"]="active_registration_failed"

except Exception as exc:
    if REPORT["status"]=="preflight_failed":
        REPORT["status"]="preflight_failed"
    REPORT["error_class"]=type(exc).__name__
finally:
    # A signal, parsing error, or failed assertion after insmod must still try
    # to remove the observer. Retain its private build directory if cleanup is
    # not confirmed so recovery does not lose the exact module artifact.
    if LOCK_FD is None:
        # A competing runner may own the module name and probe. Do not inspect,
        # classify, or attempt cleanup without our serialization lock.
        mark_runner_lock_unavailable()
    else:
        try:
            if owns_module():
                CANARY_STARTED=True
            if CANARY_STARTED and Path("/sys/module").joinpath(MODULE).exists() and owns_module():
                REPORT["fallback_cleanup"]=unload("finally")
        except Exception as cleanup_exc:
            REPORT["fallback_cleanup"]={"error_class":type(cleanup_exc).__name__}
        REPORT["observer_module_loaded_at_end"]=Path("/sys/module").joinpath(MODULE).exists()
        REPORT["observer_module_owned_at_end"]=owns_module()
        REPORT["unowned_observer_module_at_end"]=(
            REPORT["observer_module_loaded_at_end"] and
            not REPORT["observer_module_owned_at_end"])
        try:
            end_lines=target_lines()
            REPORT["target_probe_lines_at_end"]=end_lines
            REPORT["kprobe_attached_at_end"]=(end_lines is None or bool(end_lines))
        except Exception as cleanup_exc:
            REPORT["target_probe_lines_at_end"]=None
            REPORT["kprobe_attached_at_end"]=True
            REPORT["cleanup_check_error_class"]=type(cleanup_exc).__name__
        REPORT["target_probe_list_unchanged"]=(
            REPORT.get("target_probe_lines_before") is not None and
            REPORT.get("target_probe_lines_at_end") == REPORT.get("target_probe_lines_before"))
        REPORT["kernel_taint_after"]=kernel_taint()
        if isinstance(REPORT.get("kernel_taint_before"),int) and isinstance(
                REPORT.get("kernel_taint_after"),int):
            REPORT["kernel_taint_unchanged"]=(
                REPORT["kernel_taint_before"] == REPORT["kernel_taint_after"])
    if "gpu_before" in REPORT:
        try:
            after_result,after_gpus=gpu_rows()
            REPORT["gpu_after"]=after_gpus
            REPORT["gpu_identity_unchanged"]=(after_result.get("returncode")==0 and after_gpus==REPORT["gpu_before"])
            REPORT["stock_driver_changed"]=(not REPORT["gpu_identity_unchanged"] or
                                            not Path("/sys/module/nvidia").exists())
        except Exception as identity_exc:
            REPORT["gpu_identity_unchanged"]=False
            REPORT["stock_driver_changed"]=True
            REPORT["identity_check_error_class"]=type(identity_exc).__name__
    if CANARY_ATTEMPTED:
        REPORT["final_integrity_failures"]=final_integrity_violations(REPORT)
        REPORT["final_integrity_passed"]=not REPORT["final_integrity_failures"]
        REPORT["status"]=final_status_after_cleanup(REPORT, CANARY_ATTEMPTED)
        if not REPORT["final_integrity_passed"]:
            KEEP_WORK=True
    if REPORT.get("unowned_observer_module_at_end") is True:
        REPORT["status"]="observer_ownership_conflict"
        KEEP_WORK=True
    elif (REPORT.get("target_probe_list_unchanged") is False and
          not CANARY_STARTED):
        REPORT["status"]="external_probe_activity_detected"
        KEEP_WORK=True
    elif CANARY_STARTED and (REPORT["observer_module_loaded_at_end"] or
                             REPORT["kprobe_attached_at_end"] or
                             REPORT.get("stock_driver_changed") is True):
        REPORT["status"]="cleanup_or_identity_failed"
        KEEP_WORK=True
    if WORK is not None and WORK.exists():
        if CANARY_STARTED and Path("/sys/module").joinpath(MODULE).exists() and owns_module():
            REPORT["observer_module_loaded_at_end"]=True
            KEEP_WORK=True
        if not KEEP_WORK:
            shutil.rmtree(WORK,ignore_errors=True)
            REPORT["scratch_removed"]=not WORK.exists()
        else:
            REPORT["scratch_retained_for_recovery"]=str(WORK)
    if LOCK_FD is not None:
        try:
            os.close(LOCK_FD)
            LOCK_FD=None
        except OSError as lock_exc:
            REPORT["runner_lock_release_error_class"]=type(lock_exc).__name__
    print(json.dumps(REPORT,sort_keys=True))
'''


def load_tool(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load pinned PC3 transport helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def guest_probe_script(active: bool, build_only: bool = False,
                       capture_state: bool = False,
                       observe_selector_path: bool = False,
                       capture_selector: bool = False,
                       capture_lookup_callsite: bool = False,
                       capture_lookup_branch: bool = False,
                       capture_lookup_return_site: bool = False,
                       capture_lookup_join_route: bool = False) -> str:
    files = {
        SOURCE_PATH.name: base64.b64encode(SOURCE_PATH.read_bytes()).decode("ascii"),
        KBUILD_PATH.name: base64.b64encode(KBUILD_PATH.read_bytes()).decode("ascii"),
    }
    return (GUEST_PROBE.replace("__FILES__", repr(files))
            .replace("__ACTIVE__", repr(active))
            .replace("__BUILD_ONLY__", repr(build_only))
            .replace("__CAPTURE_STATE__", repr(capture_state))
            .replace("__OBSERVE_SELECTOR_PATH__", repr(observe_selector_path))
            .replace("__CAPTURE_SELECTOR__", repr(capture_selector))
            .replace("__CAPTURE_LOOKUP_CALLSITE__", repr(capture_lookup_callsite))
            .replace("__CAPTURE_LOOKUP_BRANCH__", repr(capture_lookup_branch))
            .replace("__CAPTURE_LOOKUP_RETURN_SITE__",
                     repr(capture_lookup_return_site))
            .replace("__CAPTURE_LOOKUP_JOIN_ROUTE__",
                     repr(capture_lookup_join_route))
            .replace("__LOOKUP_JOIN_PREDECESSOR_TARGETS__",
                     repr(LOOKUP_JOIN_PREDECESSOR_TARGETS))
            .replace("__LOOKUP_JOIN_PREDECESSOR_PARAMETERS__",
                     repr(LOOKUP_JOIN_PREDECESSOR_PARAMETERS)))


def write_private_new(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    parser.add_argument("--credential-host", default="gx10-e526")
    parser.add_argument("--credential-file", default="/home/pc6/Desktop/ACCES-BANC-GPU.env")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--active", action="store_true",
                        help="after disabled registration, arm the probe if no GPU compute PID is active")
    parser.add_argument("--build-only", action="store_true",
                        help="build and modpost against the exact guest kernel without loading the module")
    parser.add_argument("--capture-state", action="store_true",
                        help="with --active, nofault-read two documented nv_state_t scalars")
    parser.add_argument("--observe-selector-path", action="store_true",
                        help="with --active, count fixed R580 selector and descriptor-lookup entries")
    parser.add_argument("--capture-selector", action="store_true",
                        help="with --active --observe-selector-path, capture one 32-bit lookup argument")
    parser.add_argument("--capture-lookup-callsite", action="store_true",
                        help="with --active --observe-selector-path, capture EDI/ESI/EDX at the pinned pre-call instruction")
    parser.add_argument("--capture-lookup-branch", action="store_true",
                        help="with --active --observe-selector-path --capture-lookup-callsite, count the fixed branch target")
    parser.add_argument("--capture-lookup-return-site", action="store_true",
                        help="with --active --observe-selector-path, correlate helper entry by its hidden stack return address")
    parser.add_argument("--capture-lookup-join-route", action="store_true",
                        help="with return-site capture, count the five fixed predecessor blocks (no register snapshots)")
    args = parser.parse_args(argv)
    if args.build_only and (args.active or args.capture_state or args.observe_selector_path or args.capture_selector or args.capture_lookup_callsite or args.capture_lookup_branch or args.capture_lookup_return_site or args.capture_lookup_join_route):
        parser.error("--build-only cannot be combined with active or capture/observation options")
    if args.capture_state and not args.active:
        parser.error("--capture-state requires --active")
    if args.observe_selector_path and not args.active:
        parser.error("--observe-selector-path requires --active")
    if args.capture_selector and not args.active:
        parser.error("--capture-selector requires --active")
    if args.capture_selector and not args.observe_selector_path:
        parser.error("--capture-selector requires --observe-selector-path")
    if args.capture_lookup_callsite and not args.active:
        parser.error("--capture-lookup-callsite requires --active")
    if args.capture_lookup_callsite and not args.observe_selector_path:
        parser.error("--capture-lookup-callsite requires --observe-selector-path")
    if args.capture_lookup_branch and not args.active:
        parser.error("--capture-lookup-branch requires --active")
    if args.capture_lookup_branch and not args.observe_selector_path:
        parser.error("--capture-lookup-branch requires --observe-selector-path")
    if args.capture_lookup_branch and not args.capture_lookup_callsite:
        parser.error("--capture-lookup-branch requires --capture-lookup-callsite")
    if args.capture_lookup_return_site and not args.active:
        parser.error("--capture-lookup-return-site requires --active")
    if args.capture_lookup_return_site and not args.observe_selector_path:
        parser.error("--capture-lookup-return-site requires --observe-selector-path")
    if args.capture_lookup_return_site and (
            args.capture_selector or args.capture_lookup_callsite or
            args.capture_lookup_branch):
        parser.error("--capture-lookup-return-site is a standalone lookup capture mode")
    if args.capture_lookup_join_route and not args.active:
        parser.error("--capture-lookup-join-route requires --active")
    if args.capture_lookup_join_route and not args.observe_selector_path:
        parser.error("--capture-lookup-join-route requires --observe-selector-path")
    if args.capture_lookup_join_route and not args.capture_lookup_return_site:
        parser.error("--capture-lookup-join-route requires --capture-lookup-return-site")
    if args.capture_lookup_join_route and (
            args.capture_selector or args.capture_lookup_callsite or
            args.capture_lookup_branch):
        parser.error("--capture-lookup-join-route cannot combine with other data-capture modes")
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    inspector = load_tool(AUDIT_PATH, "pc3_v100_trace_capability_audit")
    reference = inspector.load_reference_tool()
    started = datetime.now(timezone.utc)
    source_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in (SOURCE_PATH, KBUILD_PATH)}
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-r580-direct-kprobe-canary-transport-v1",
        "started_utc": started.isoformat(timespec="seconds"),
        "target_host": args.target,
        "host_key_alias": args.host_key_alias,
        "credential_host": args.credential_host,
        "credential_file": args.credential_file,
        "module": MODULE_NAME,
        "target_symbol": TARGET_SYMBOL,
        "active_mode_requested": args.active,
        "build_only_mode_requested": args.build_only,
        "scalar_capture_requested": args.capture_state,
        "selector_path_observation_requested": args.observe_selector_path,
        "selector_scalar_capture_requested": args.capture_selector,
        "lookup_callsite_capture_requested": args.capture_lookup_callsite,
        "lookup_branch_capture_requested": args.capture_lookup_branch,
        "lookup_return_site_capture_requested": args.capture_lookup_return_site,
        "lookup_join_route_capture_requested": args.capture_lookup_join_route,
        "operation_scope": ("build and modpost in private guest /tmp only; no module load"
                            if args.build_only else
                            "build in private guest /tmp; disabled resolution test; optional brief active kprobe; immediate unregister; no driver install"),
        "source_hashes": source_hashes,
        "transport_helper_sha256": inspector.REFERENCE_TOOL_SHA256,
        "status": "failed",
    }
    stage = "fetch_pc3_sudo_credential"
    try:
        secret = reference.fetch_pc3_sudo_secret(args.credential_host, args.credential_file)
        stage = "construct_guest_transport"
        wrapper = inspector.remote_root_script(
            guest_probe_script(args.active, args.build_only, args.capture_state,
                               args.observe_selector_path, args.capture_selector,
                               args.capture_lookup_callsite,
                               args.capture_lookup_branch,
                               args.capture_lookup_return_site,
                               args.capture_lookup_join_route),
            reference.EXPECTED_GUEST_HOSTKEY_FINGERPRINT,
            reference.DEFAULT_GUEST_KEY, reference.DEFAULT_GUEST_KNOWN_HOSTS,
            read_only=False, trace_event_definition_write_attempted=False,
        )
        wrapper = set_guest_ssh_timeout(wrapper)
        report["guest_ssh_timeout_seconds"] = GUEST_SSH_TIMEOUT_SECONDS
        report["pc3_ssh_timeout_seconds"] = REMOTE_TIMEOUT_SECONDS
        report["transport_wrapper_sha256"] = hashlib.sha256(wrapper.encode("utf-8")).hexdigest()
        remote = "sudo -S -p '' python3 -c " + shlex.quote(wrapper)
        stage = "execute_pc3_transport"
        result = subprocess.run(
            reference.pc3_ssh_base(args.target, args.host_key_alias) + [remote],
            input=reference.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=REMOTE_TIMEOUT_SECONDS, check=False,
            env=inspector.pc3_ssh_environment(os.environ),
        )
        report["pc3_ssh_returncode"] = result.returncode
        report["remote_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        report["remote_stdout_bytes"] = len(result.stdout)
        report["remote_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        if result.returncode == 0:
            stage = "decode_transport_json"
            transport = json.loads(result.stdout.decode("utf-8", "strict"))
            host = transport.get("host", {})
            guest = transport.get("guest")
            report["transport_summary"] = {
                "schema": transport.get("schema"),
                "status": transport.get("status"),
                "read_only": transport.get("read_only"),
                "trace_event_definition_write_attempted": transport.get("trace_event_definition_write_attempted"),
                "pc3_hostname": host.get("hostname", "").split(".")[0],
                "sudo_identity_verified": host.get("sudo_identity_verified"),
                "guest_host_key_verified": host.get("guest_host_key_verified"),
                "guest_schema": guest.get("schema") if isinstance(guest, dict) else None,
                "guest_status": guest.get("status") if isinstance(guest, dict) else None,
            }
            checks = {
                "pc3_hostname": report["transport_summary"]["pc3_hostname"] == "pc3",
                "sudo_identity": host.get("sudo_identity_verified") is True,
                "guest_host_key": host.get("guest_host_key_verified") is True,
                "transport_status": transport.get("status") == "observed",
                "not_read_only": transport.get("read_only") is False,
                "no_trace_event_definition_write": transport.get("trace_event_definition_write_attempted") is False,
            }
            report["transport_validation"] = checks
            if not all(checks.values()):
                stage = "validate_transport_identity"
                raise ValueError("strict PC3/guest identity or transport scope failed")
            report["transport"] = {key: transport.get(key) for key in (
                "schema", "status", "read_only", "trace_event_definition_write_attempted",
                "guest_transport")}
            report["remote"] = guest
            if not isinstance(guest, dict) or guest.get("schema") not in (
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v12",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v11",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v2",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v3",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v4",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v5",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v6",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v7",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v8",
                    "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v10"):
                stage = "validate_guest_observer_report"
                raise ValueError("unsupported guest observer report")
            report["status"] = guest.get("status", "failed")
            for key in ("observer_module_loaded_at_end", "kprobe_attached_at_end",
                        "stock_driver_changed", "pci_binding_changed",
                        "pci_binding_change_requested", "firmware_or_vm_change",
                        "firmware_or_vm_change_requested"):
                report["guest_" + key] = guest.get(key)
        else:
            report["failure_stage"] = "pc3_remote_or_guest_transport"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_private_new(args.evidence, report)
        print(json.dumps({"status": report["status"], "evidence": str(args.evidence),
                          "evidence_sha256": hashlib.sha256(args.evidence.read_bytes()).hexdigest(),
                          "remote_status": report.get("remote", {}).get("status") if isinstance(report.get("remote"), dict) else None,
                          "kprobe_attached_at_end": report.get("remote", {}).get("kprobe_attached_at_end") if isinstance(report.get("remote"), dict) else None}, sort_keys=True))
        return 0 if status_is_success(str(report["status"])) else 1
    except Exception as exc:
        report["failure_stage"] = stage
        report["error_class"] = type(exc).__name__
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        write_private_new(args.evidence, report)
        print(json.dumps({"status": "failed", "error_class": type(exc).__name__,
                          "evidence": str(args.evidence),
                          "evidence_sha256": hashlib.sha256(args.evidence.read_bytes()).hexdigest()}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
