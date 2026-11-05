#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Arm or cancel a bounded PC3 host timer that can restart the V100 test VM."""
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
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = "pc3-v100-canary-watchdog-v1"
SERVICE_NAME = "pc3-v100-qemu.service"
REMOTE_PROGRAM = r'''import fcntl,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
ACTION=sys.argv[1]
CANARY_ID=sys.argv[2]
SECONDS=int(sys.argv[3])
SERVICE="pc3-v100-qemu.service"
PREFIX="codex-v100-canary-"
ROOT=Path("/run/pc3-v100-canary-watchdog")
EXPECTED_HOST="pc3"
def run(args,timeout=15):
    try:
        return subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=timeout,check=False,
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    except (OSError,subprocess.TimeoutExpired):
        return None
def prop_map(result):
    if result is None or result.returncode!=0 or len(result.stdout)>16384:return None
    output={}
    for line in result.stdout.decode("utf-8","replace").splitlines():
        key,sep,value=line.partition("=")
        if sep:output[key]=value
    return output
def write_status(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
if os.geteuid()!=0 or os.uname().nodename.split(".")[0]!=EXPECTED_HOST:
    raise SystemExit("wrong PC3 identity or privilege")
if not re.fullmatch(r"[a-f0-9]{32}",CANARY_ID):raise SystemExit("invalid canary identity")
unit=PREFIX+CANARY_ID
timer=unit+".timer"
service_unit=unit+".service"
if ACTION not in ("arm","cancel","self-test","inspect"):raise SystemExit("unsupported watchdog action")
if ACTION=="arm" and not 120<=SECONDS<=900:raise SystemExit("watchdog window outside 120..900 seconds")
state={"schema":"pc3-v100-canary-watchdog-remote-v1","action":ACTION,
    "canary_id":CANARY_ID,"host":"pc3","target_service":SERVICE,
    "system_state_changed":False,"timer_active":False,"rollback_started":False}
if ACTION=="self-test":
    command=["/usr/bin/systemd-run","--quiet","--unit="+unit,"--on-active=90s",
        "--collect","/usr/bin/true"]
    created=run(command,timeout=20)
    if created is None or created.returncode!=0:raise SystemExit("safe timer self-test could not arm")
    state["system_state_changed"]=True
    active=run(["/usr/bin/systemctl","is-active",timer])
    state["timer_active"]=active is not None and active.stdout.strip()==b"active"
    stopped=run(["/usr/bin/systemctl","stop",timer],timeout=20)
    after=run(["/usr/bin/systemctl","is-active",timer])
    state["timer_cancelled"]=stopped is not None and stopped.returncode==0 and after is not None and after.stdout.strip() in (b"inactive",b"unknown")
    state["status"]="self-test-passed" if state["timer_active"] and state["timer_cancelled"] else "self-test-failed"
    print(json.dumps(state,sort_keys=True,separators=(",",":")))
    raise SystemExit(0 if state["status"]=="self-test-passed" else 1)
elif ACTION=="inspect":
    state["system_state_changed"]=False
    try:
        root_stat=ROOT.lstat()
        status_path=ROOT/(CANARY_ID+".status")
        status_stat=status_path.lstat()
        if (not os.path.isdir(ROOT) or root_stat.st_uid!=0 or root_stat.st_mode&0o077 or
                not os.path.isfile(status_path) or status_stat.st_uid!=0 or
                status_stat.st_mode&0o077 or status_stat.st_size>8192):
            raise SystemExit("watchdog receipt ownership, type, or size is unsafe")
        status_data=json.loads(status_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        raise SystemExit("completed watchdog receipt is unavailable or invalid")
    if not isinstance(status_data,dict):raise SystemExit("watchdog receipt is not an object")
    expected_receipt={"event":"restart_finished","service":SERVICE,"returncode":0}
    if any(status_data.get(key)!=value for key,value in expected_receipt.items()):
        raise SystemExit("watchdog receipt does not confirm a successful QEMU restart")
    if status_data.get("action") not in (None,"systemctl-restart"):
        raise SystemExit("watchdog receipt records an unexpected restart action")
    props=prop_map(run(["/usr/bin/systemctl","show","--no-pager",
        "--property=Id,ActiveState,SubState,Restart,RestartUSec,KillMode,InvocationID,ActiveEnterTimestamp",SERVICE]))
    if props is None or props.get("Id")!=SERVICE:
        raise SystemExit("QEMU systemd state could not be read")
    qemu=[]
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():continue
        try:
            comm=(process/"comm").read_text(encoding="ascii").strip()
            raw=(process/"cmdline").read_bytes()
        except OSError:continue
        if not comm.startswith("qemu-system-x86"):continue
        args=[item.decode("utf-8","replace") for item in raw.split(bytes([0])) if item]
        has_v100=any(re.search(r"(?:^|,)host=0000:81:00[.]0(?:,|$)",arg) for arg in args)
        if has_v100:qemu.append(hashlib.sha256(bytes([0]).join(a.encode() for a in args)).hexdigest())
    timer_state=run(["/usr/bin/systemctl","is-active",timer])
    state.update({"status":"restart-finished","restart_event":status_data["event"],
        "restart_action":status_data.get("action"),
        "restart_returncode":status_data["returncode"],"qemu_service_active":props.get("ActiveState")=="active",
        "qemu_service_substate":props.get("SubState"),"qemu_unit_invocation_id":props.get("InvocationID"),
        "qemu_unit_active_enter_timestamp":props.get("ActiveEnterTimestamp"),
        "qemu_process_count":len(qemu),"qemu_command_digest":qemu[0] if len(qemu)==1 else None,
        "timer_active":timer_state is not None and timer_state.stdout.strip()==b"active"})
    if not state["qemu_service_active"] or len(qemu)!=1:
        state["status"]="restart-finished-qemu-not-active"
    print(json.dumps(state,sort_keys=True,separators=(",",":")))
    raise SystemExit(0 if state["status"]=="restart-finished" else 1)
elif ACTION=="arm":
    qemu=[]
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():continue
        try:
            comm=(process/"comm").read_text(encoding="ascii").strip()
            raw=(process/"cmdline").read_bytes()
        except OSError:continue
        if not comm.startswith("qemu-system-x86"):continue
        args=[item.decode("utf-8","replace") for item in raw.split(bytes([0])) if item]
        has_v100=any(re.search(r"(?:^|,)host=0000:81:00[.]0(?:,|$)",arg) for arg in args)
        if has_v100:qemu.append(hashlib.sha256(bytes([0]).join(a.encode() for a in args)).hexdigest())
    if len(qemu)!=1:raise SystemExit("expected exactly one V100-assigned QEMU process")
    props=prop_map(run(["/usr/bin/systemctl","show","--no-pager",
        "--property=Id,ActiveState,SubState,Restart,RestartUSec,KillMode",SERVICE]))
    if (props is None or props.get("Id")!=SERVICE or props.get("ActiveState")!="active" or
            props.get("Restart")!="on-failure" or props.get("KillMode")!="control-group"):
        raise SystemExit("pinned QEMU unit is not active with the observed restart policy")
    try:
        st=ROOT.lstat()
        if not (os.path.isdir(ROOT) and st.st_uid==0 and st.st_mode&0o077==0):
            raise SystemExit("watchdog state directory has unsafe ownership or permissions")
    except FileNotFoundError:
        os.mkdir(ROOT,0o700)
    lock_path=ROOT/(CANARY_ID+".lock")
    cancel_path=ROOT/(CANARY_ID+".cancel")
    status_path=ROOT/(CANARY_ID+".status")
    fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    os.close(fd)
    program_b64=sys.argv[4]
    try:program=__import__("base64").b64decode(program_b64,validate=True).decode("utf-8","strict")
    except Exception:raise SystemExit("watchdog payload encoding is invalid")
    encoded=__import__("base64").b64encode(program.encode()).decode("ascii")
    run_script="import base64;exec(compile(base64.b64decode("+repr(encoded)+"),'<canary-watchdog>','exec'))"
    command=["/usr/bin/systemd-run","--quiet","--unit="+unit,"--on-active="+str(SECONDS)+"s",
        "--timer-property=AccuracySec=1s","--collect","/usr/bin/python3","-c",run_script,
        "arm",CANARY_ID,str(SECONDS)]
    created=run(command,timeout=20)
    if created is None or created.returncode!=0:
        for path in (lock_path,cancel_path,status_path):
            try:path.unlink()
            except OSError:pass
        raise SystemExit("PC3 systemd could not arm the canary recovery timer")
    active=run(["/usr/bin/systemctl","is-active",timer])
    state["timer_active"]=active is not None and active.stdout.strip()==b"active"
    state["qemu_command_digest"]=qemu[0]
    state["unit_restart_delay"]=props.get("RestartUSec")
    state["system_state_changed"]=True
    state["status"]="armed" if state["timer_active"] else "armed-unverified"
else:
    lock_path=ROOT/(CANARY_ID+".lock")
    cancel_path=ROOT/(CANARY_ID+".cancel")
    status_path=ROOT/(CANARY_ID+".status")
    if not lock_path.exists():raise SystemExit("canary watchdog lock does not exist")
    fd=os.open(lock_path,os.O_RDWR|getattr(os,"O_NOFOLLOW",0))
    with os.fdopen(fd,"r+b") as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        if not cancel_path.exists():write_status(cancel_path,{"cancelled_at_unix":int(time.time())})
        stopped=run(["/usr/bin/systemctl","stop",timer],timeout=30)
        timer_state=run(["/usr/bin/systemctl","is-active",timer])
        service_state=run(["/usr/bin/systemctl","is-active",service_unit])
        state["timer_active"]=timer_state is not None and timer_state.stdout.strip()==b"active"
        state["rollback_started"]=service_state is not None and service_state.stdout.strip() not in (b"inactive",b"failed",b"unknown")
        state["rollback_status_record_exists"]=status_path.exists()
        state["system_state_changed"]=True
        if state["rollback_started"]:state["status"]="rollback-may-be-in-progress"
        elif stopped is not None and stopped.returncode==0 and not state["timer_active"]:
            state["status"]="cancelled"
            for path in (cancel_path,lock_path):
                try:path.unlink()
                except OSError:pass
        else:state["status"]="cancel-unverified"
if "status" not in state:state["status"]="armed-unverified"
print(json.dumps(state,sort_keys=True,separators=(",",":")))
raise SystemExit(0 if state["status"] in ("armed","cancelled","self-test-passed") else 1)
'''

WATCHDOG_SERVICE_PROGRAM = r'''import fcntl,json,os,subprocess,sys,time
from pathlib import Path
ACTION=sys.argv[1]
CANARY_ID=sys.argv[2]
ROOT=Path("/run/pc3-v100-canary-watchdog")
SERVICE="pc3-v100-qemu.service"
def write_status(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
def run(args):
    try:return subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,timeout=120,check=False,
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    except (OSError,subprocess.TimeoutExpired):return None
if ACTION!="arm" or os.geteuid()!=0 or os.uname().nodename.split(".")[0]!="pc3":raise SystemExit(2)
lock_path=ROOT/(CANARY_ID+".lock")
cancel_path=ROOT/(CANARY_ID+".cancel")
status_path=ROOT/(CANARY_ID+".status")
fd=os.open(lock_path,os.O_RDWR|getattr(os,"O_NOFOLLOW",0))
with os.fdopen(fd,"r+b") as lock:
    fcntl.flock(lock.fileno(),fcntl.LOCK_SH)
    if cancel_path.exists():raise SystemExit(0)
    write_status(status_path,{"event":"restart_requested","at_unix":int(time.time()),
        "service":SERVICE,"action":"systemctl-restart"})
    restarted=run(["/usr/bin/systemctl","restart",SERVICE])
    status_path.unlink()
    write_status(status_path,{"event":"restart_finished","at_unix":int(time.time()),
        "service":SERVICE,"action":"systemctl-restart",
        "returncode":restarted.returncode if restarted is not None else None})
    raise SystemExit(restarted.returncode if restarted is not None else 124)
'''


def remote_script(action: str, canary_id: str, seconds: int) -> str:
    if action not in ("arm", "cancel", "self-test", "inspect"):
        raise ValueError("unsupported watchdog action")
    if not re.fullmatch(r"[a-f0-9]{32}", canary_id):
        raise ValueError("canary ID must be a lowercase 32-character hex token")
    if action == "arm" and not 120 <= seconds <= 900:
        raise ValueError("watchdog timeout must be between 120 and 900 seconds")
    payload = base64.b64encode(WATCHDOG_SERVICE_PROGRAM.encode()).decode("ascii")
    return "sudo -S -p '' python3 -c " + shlex.quote(REMOTE_PROGRAM) + " " + " ".join(
        shlex.quote(item) for item in (action, canary_id, str(seconds), payload)
    )


def load_transport():
    path = ROOT / "tools/run_pc3_v100_guest_reference.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_watchdog_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 transport helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def collect(action: str, canary_id: str, seconds: int) -> dict:
    if action not in ("arm", "cancel", "self-test", "inspect"):
        raise ValueError("unsupported watchdog action")
    if not re.fullmatch(r"[a-f0-9]{32}", canary_id):
        raise ValueError("canary ID must be a lowercase 32-character hex token")
    if action == "arm" and not 120 <= seconds <= 900:
        raise ValueError("watchdog timeout must be between 120 and 900 seconds")
    transport = load_transport()
    secret = transport.fetch_pc3_sudo_secret(
        transport.DEFAULT_CREDENTIAL_HOST, transport.DEFAULT_CREDENTIAL_FILE)
    command = remote_script(action, canary_id, seconds)
    try:
        result = subprocess.run(
            transport.pc3_ssh_base(transport.DEFAULT_PC3_TARGET,
                                   transport.DEFAULT_HOST_KEY_ALIAS) + [command],
            input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("bounded PC3 watchdog operation failed or timed out") from None
    finally:
        secret = None
    if result.returncode != 0 or len(result.stdout) > 64 * 1024:
        raise RuntimeError("PC3 watchdog operation failed; stderr sha256=" +
                           hashlib.sha256(result.stderr).hexdigest())
    try:
        report = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 watchdog returned invalid JSON") from None
    expected_state_change = action != "inspect"
    if (not isinstance(report, dict) or report.get("schema") != "pc3-v100-canary-watchdog-remote-v1" or
            report.get("host") != "pc3" or report.get("action") != action or
            report.get("canary_id") != canary_id or report.get("target_service") != SERVICE_NAME or
            report.get("system_state_changed") is not expected_state_change):
        raise RuntimeError("PC3 watchdog identity or state-change report failed validation")
    if action == "arm" and (report.get("status") != "armed" or report.get("timer_active") is not True):
        raise RuntimeError("PC3 did not confirm the armed recovery timer")
    if action == "cancel" and report.get("status") != "cancelled":
        raise RuntimeError("PC3 did not confirm timer cancellation")
    if action == "self-test" and (report.get("status") != "self-test-passed" or
                                  report.get("timer_active") is not True or
                                  report.get("timer_cancelled") is not True):
        raise RuntimeError("PC3 harmless timer self-test did not pass")
    if action == "inspect" and (report.get("status") != "restart-finished" or
                                 report.get("restart_event") != "restart_finished" or
                                 report.get("restart_returncode") != 0 or
                                 report.get("qemu_service_active") is not True or
                                 report.get("qemu_process_count") != 1 or
                                 not re.fullmatch(r"[a-f0-9]{64}",
                                                  report.get("qemu_command_digest", ""))):
        raise RuntimeError("PC3 did not confirm a successful V100 QEMU service restart")
    return report


def validate_evidence_path(path: Path) -> Path:
    path = path.absolute()
    evidence_root = (ROOT / "evidence").resolve(strict=True)
    if path.exists():
        raise FileExistsError("watchdog evidence already exists")
    if not path.parent.resolve(strict=True).is_relative_to(evidence_root):
        raise ValueError("watchdog evidence must stay under the project evidence directory")
    return path


def write_evidence(path: Path, value: dict) -> str:
    path = validate_evidence_path(path)
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(payload).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("arm", "cancel", "self-test", "inspect"))
    parser.add_argument("--canary-id", required=True, help="lowercase 32-character hex operation ID")
    parser.add_argument("--seconds", type=int, default=300,
                        help="arm timeout in seconds (120..900); ignored by cancel/self-test")
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        args.evidence = validate_evidence_path(args.evidence)
        if not re.fullmatch(r"[a-f0-9]{32}", args.canary_id):
            raise ValueError("canary ID must be a lowercase 32-character hex token")
        if args.action == "arm" and not 120 <= args.seconds <= 900:
            raise ValueError("watchdog timeout must be between 120 and 900 seconds")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    report = {"schema": REPORT_SCHEMA, "action": args.action, "canary_id": args.canary_id,
              "target_service": SERVICE_NAME, "status": "failed",
              "remote_program_sha256": hashlib.sha256(REMOTE_PROGRAM.encode()).hexdigest(),
              "watchdog_payload_sha256": hashlib.sha256(WATCHDOG_SERVICE_PROGRAM.encode()).hexdigest(),
              "observed_at_utc": datetime.now(timezone.utc).isoformat()}
    try:
        remote = collect(args.action, args.canary_id, args.seconds)
        report.update({"status": remote["status"], "remote": remote,
                       "system_state_changed": remote["system_state_changed"]})
        digest = write_evidence(args.evidence, report)
    except Exception as error:
        report["error"] = str(error)[:240]
        report["system_state_changed"] = None
        try:
            digest = write_evidence(args.evidence, report)
        except OSError:
            print("could not persist private watchdog evidence", file=sys.stderr)
            return 2
        print(json.dumps({"status": "failed", "evidence": str(args.evidence),
                          "sha256": digest}, sort_keys=True))
        return 1
    print(json.dumps({"status": report["status"], "evidence": str(args.evidence),
                      "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
