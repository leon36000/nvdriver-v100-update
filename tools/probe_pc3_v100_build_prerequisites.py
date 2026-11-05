#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture read-only compiler, scratch-space, and Kbuild prerequisites on PC3's V100 guest."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAX_REMOTE_BYTES = 1024 * 1024
GUEST_KEY = "/var/lib/pc3-v100-vm/id_ed25519"
GUEST_KNOWN_HOSTS = "/tmp/codex-pc3-vm-known_hosts"
GUEST_HOSTKEY_FINGERPRINT = "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
REQUIRED_TOOLS = ("gcc", "make", "ld", "as", "nm", "objcopy", "strip", "readelf", "patch", "tar", "xz", "python3")
OPTIONAL_TOOLS = ("bc", "perl", "flex", "bison", "modinfo", "depmod", "zstd", "rsync")
KERNEL_BUILD_INPUTS = ("Makefile", "Module.symvers", "include/config/auto.conf",
                       "include/generated/autoconf.h", "include/generated/utsrelease.h",
                       "scripts/Makefile.build", "scripts/Makefile.modpost", "scripts/mod/modpost",
                       "scripts/basic/fixdep")


GUEST_SCRIPT = r'''import datetime,hashlib,json,os,platform,re,shutil,stat,subprocess,sys
TOOLS=@@TOOLS@@
REQUIRED=@@REQUIRED@@
INPUTS=@@INPUTS@@
def version(name):
 path=sys.executable if name=="python3" else shutil.which(name)
 if path is None: return {"path":None,"version":None}
 try:
  p=subprocess.run([path,"--version"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=8,check=False,env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
 except Exception: return {"path":path,"version":None}
 first=p.stdout.decode("utf-8","replace").splitlines()[0][:256] if p.stdout else ""
 return {"path":path,"version":first if p.returncode==0 and first else None}
def regular(path):
 try: return stat.S_ISREG(os.stat(path).st_mode)
 except OSError: return False
release=platform.release()
if not re.fullmatch(r"[A-Za-z0-9._+~-]{1,128}",release): raise SystemExit(2)
module_dir="/lib/modules/"+release
build_link=module_dir+"/build"
resolved=os.path.realpath(build_link) if os.path.exists(build_link) else None
if resolved is not None and not resolved.startswith(("/usr/src/","/lib/modules/","/usr/lib/modules/")): raise SystemExit(3)
def at(relative): return bool(resolved and regular(os.path.join(resolved,relative)))
def input_diagnostic(relative):
 path=os.path.join(resolved,relative) if resolved else ""
 try: entry=os.lstat(path)
 except OSError: return {"entry_exists":False,"is_symlink":False,"target_exists":False,"regular_file":False,"resolved_path":None}
 target_exists=os.path.exists(path)
 return {"entry_exists":True,"is_symlink":stat.S_ISLNK(entry.st_mode),"target_exists":target_exists,
         "regular_file":regular(path),"resolved_path":os.path.realpath(path)}
symvers=os.path.join(resolved,"Module.symvers") if resolved else None
symvers_exists=bool(symvers and regular(symvers))
symvers_bytes=os.stat(symvers).st_size if symvers_exists else None
symvers_sha256=None
if symvers_exists and 0<symvers_bytes<=64*1024*1024:
 h=hashlib.sha256()
 with open(symvers,"rb") as f:
  for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
 symvers_sha256=h.hexdigest()
st=os.statvfs("/tmp")
disk={"path":"/tmp","available_bytes":st.f_bavail*st.f_frsize,"available_inodes":st.f_favail}
tools={name:version(name) for name in TOOLS}
kernel_build={
 "build_link":build_link,
 "resolved_build_path":resolved,
 "makefile_exists":at("Makefile"),
 "generated_autoconf_exists":at("include/generated/autoconf.h"),
 "scripts_modpost_exists":at("scripts/mod/modpost"),
 "scripts_fixdep_exists":at("scripts/basic/fixdep"),
 "required_inputs":{relative:input_diagnostic(relative) for relative in INPUTS},
 "module_symvers_bytes":symvers_bytes,
 "module_symvers_sha256":symvers_sha256,
}
common_root=("/usr/src/linux-headers-"+release[:-len("-generic")]
             if release.endswith("-generic") else None)
required_inputs_ready=True
for relative,item in kernel_build["required_inputs"].items():
 expected_targets={os.path.realpath(os.path.join(resolved,relative))} if resolved else set()
 if common_root and os.path.isdir(common_root) and not os.path.islink(common_root):
  expected_targets.add(os.path.realpath(os.path.join(common_root,relative)))
 if not item["regular_file"] or item["resolved_path"] not in expected_targets:
  required_inputs_ready=False
kernel_build["ready"]=bool(all(kernel_build[k] for k in ("resolved_build_path","makefile_exists","generated_autoconf_exists","scripts_modpost_exists","scripts_fixdep_exists")) and symvers_bytes and symvers_sha256 and
                            required_inputs_ready)
tools_ready=all(tools[name]["path"] and tools[name]["version"] for name in REQUIRED)
ready=bool(tools_ready and kernel_build["ready"] and disk["available_bytes"]>0 and disk["available_inodes"]>0)
report={"schema":"nvidia-hybrid-pc3-v100-build-prerequisites-v1","observed_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),"hostname":platform.node(),"architecture":platform.machine(),"kernel_release":release,"tools":tools,"temporary_filesystem":disk,"kernel_build":kernel_build,"build_prerequisites_ready":ready,"read_only_guest_query":True,"mutation_performed":False}
print(json.dumps(report,separators=(",",":"),sort_keys=True))
'''.replace("@@TOOLS@@", repr(REQUIRED_TOOLS + OPTIONAL_TOOLS)).replace(
    "@@REQUIRED@@", repr(REQUIRED_TOOLS)).replace("@@INPUTS@@", repr(KERNEL_BUILD_INPUTS))


ROOT_REMOTE_SCRIPT = r'''import base64,hashlib,json,os,shlex,stat,subprocess,sys
KEY="/var/lib/pc3-v100-vm/id_ed25519"
KNOWN="/tmp/codex-pc3-vm-known_hosts"
EXPECTED="SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
if os.geteuid()!=0 or len(sys.argv)!=3: raise SystemExit(2)
try: key_st=os.lstat(KEY); known_st=os.lstat(KNOWN)
except OSError: raise SystemExit(3)
if not stat.S_ISREG(key_st.st_mode) or key_st.st_uid!=0 or stat.S_IMODE(key_st.st_mode)!=0o600: raise SystemExit(4)
if not stat.S_ISREG(known_st.st_mode) or known_st.st_uid!=0 or known_st.st_mode&0o022: raise SystemExit(5)
selected=subprocess.run(["/usr/bin/ssh-keygen","-F","[127.0.0.1]:22223","-f",KNOWN],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False)
lines=[x for x in selected.stdout.decode("utf-8","strict").splitlines() if x and not x.startswith("#")]
fingerprints=set()
for line in lines:
 fields=line.split()
 if len(fields)<3 or fields[0].startswith("@"): raise SystemExit(6)
 blob=base64.b64decode(fields[2],validate=True)
 fingerprints.add("SHA256:"+base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("="))
if selected.returncode or fingerprints!={EXPECTED}: raise SystemExit(7)
try: guest_code=base64.b64decode(sys.argv[1],validate=True)
except Exception: raise SystemExit(8)
if hashlib.sha256(guest_code).hexdigest()!=sys.argv[2]: raise SystemExit(9)
remote=shlex.join(["python3","-c",guest_code.decode("utf-8","strict")])
ssh=["/usr/bin/ssh","-F","/dev/null","-T","-oBatchMode=yes","-oIdentitiesOnly=yes","-oStrictHostKeyChecking=yes","-oUserKnownHostsFile="+KNOWN,"-oConnectTimeout=8","-oConnectionAttempts=1","-i",KEY,"-p","22223","ubuntu@127.0.0.1",remote]
try: result=subprocess.run(ssh,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,check=False)
except Exception: raise SystemExit(10)
if len(result.stdout)>1048576: raise SystemExit(11)
envelope={"schema":"nvidia-hybrid-pc3-v100-prerequisite-transport-v1","guest_ssh_exit_code":result.returncode,"guest_stdout_b64":base64.b64encode(result.stdout).decode("ascii"),"guest_stderr_sha256":hashlib.sha256(result.stderr).hexdigest(),"hostkey_fingerprint":EXPECTED}
print(json.dumps(envelope,separators=(",",":"),sort_keys=True))
'''


def load_transport():
    path = ROOT / "tools/run_pc3_v100_guest_reference.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("the pinned PC3 V100 guest transport is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_guest_report(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REMOTE_BYTES:
        raise ValueError("guest prerequisite report size is invalid")
    try:
        report = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("guest prerequisite report is not valid UTF-8 JSON") from None

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    required_fields = {"schema", "observed_at_utc", "hostname", "architecture", "kernel_release",
                       "tools", "temporary_filesystem", "kernel_build", "build_prerequisites_ready",
                       "read_only_guest_query", "mutation_performed"}
    require(isinstance(report, dict) and set(report) == required_fields,
            "guest prerequisite report fields differ from the expected schema")
    require(report["schema"] == "nvidia-hybrid-pc3-v100-build-prerequisites-v1",
            "guest prerequisite report schema is unsupported")
    try:
        observed = datetime.fromisoformat(report["observed_at_utc"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        observed = None
    require(observed is not None and observed.tzinfo is not None,
            "guest prerequisite timestamp is invalid")
    require(isinstance(report["hostname"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", report["hostname"]),
            "guest hostname is invalid")
    require(report["architecture"] in ("x86_64", "aarch64"), "guest architecture is invalid")
    release = report["kernel_release"]
    require(isinstance(release, str) and re.fullmatch(r"[A-Za-z0-9._+~-]{1,128}", release),
            "guest kernel release is invalid")
    tools = report["tools"]
    expected_tools = set(REQUIRED_TOOLS + OPTIONAL_TOOLS)
    require(isinstance(tools, dict) and set(tools) == expected_tools,
            "guest tool inventory differs from the expected tools")
    required_tools_ready = True
    for name, item in tools.items():
        require(isinstance(item, dict) and set(item) == {"path", "version"},
                "guest tool record fields are invalid")
        path, version = item["path"], item["version"]
        require(path is not None or version is None,
                "guest tool version exists without an executable path")
        if path is not None:
            require(isinstance(path, str) and path.startswith(
                    ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/")) and
                    len(path) <= 512 and ".." not in PurePosixPath(path).parts,
                    "guest tool path is invalid")
            if version is not None:
                require(isinstance(version, str) and 1 <= len(version) <= 256 and
                        not any(ord(char) < 32 for char in version),
                        "guest tool version is invalid")
        if name in REQUIRED_TOOLS and (path is None or version is None):
            required_tools_ready = False
    disk = report["temporary_filesystem"]
    require(isinstance(disk, dict) and set(disk) == {"path", "available_bytes", "available_inodes"} and
            disk["path"] == "/tmp", "guest temporary filesystem record is invalid")
    require(type(disk["available_bytes"]) is int and disk["available_bytes"] >= 0,
            "temporary filesystem available bytes are invalid")
    require(type(disk["available_inodes"]) is int and disk["available_inodes"] >= 0,
            "temporary filesystem available inodes are invalid")
    build = report["kernel_build"]
    build_fields = {"build_link", "resolved_build_path", "makefile_exists", "generated_autoconf_exists",
                    "scripts_modpost_exists", "scripts_fixdep_exists", "module_symvers_bytes",
                    "module_symvers_sha256", "required_inputs", "ready"}
    require(isinstance(build, dict) and set(build) == build_fields,
            "guest kernel build record fields are invalid")
    expected_build_link = "/lib/modules/" + release + "/build"
    require(build["build_link"] == expected_build_link,
            "kernel build link does not match the running kernel")
    resolved = build["resolved_build_path"]
    require(resolved is None or (isinstance(resolved, str) and
                                 resolved.startswith(("/usr/src/", "/lib/modules/", "/usr/lib/modules/")) and
                                 ".." not in PurePosixPath(resolved).parts),
            "resolved kernel build path is invalid")
    for key in ("makefile_exists", "generated_autoconf_exists", "scripts_modpost_exists", "scripts_fixdep_exists", "ready"):
        require(type(build[key]) is bool, "kernel build readiness field is invalid")
    required_inputs = build["required_inputs"]
    require(isinstance(required_inputs, dict) and set(required_inputs) == set(KERNEL_BUILD_INPUTS),
            "required Kbuild input inventory differs from the pinned builder")
    required_inputs_ready = True
    build_root_posix = PurePosixPath(resolved) if resolved is not None else None
    common_root_posix = (PurePosixPath("/usr/src/linux-headers-" + release[:-len("-generic")])
                         if release.endswith("-generic") else None)
    for relative, item in required_inputs.items():
        require(isinstance(item, dict) and set(item) == {"entry_exists", "is_symlink", "target_exists", "regular_file", "resolved_path"},
                "required Kbuild input diagnostic is invalid")
        for flag in ("entry_exists", "is_symlink", "target_exists", "regular_file"):
            require(type(item[flag]) is bool, "required Kbuild input state is invalid")
        resolved_input = item["resolved_path"]
        require((resolved_input is None and not item["entry_exists"]) or
                (isinstance(resolved_input, str) and item["entry_exists"] and
                 resolved_input.startswith(("/usr/src/", "/lib/modules/", "/usr/lib/modules/")) and
                 ".." not in PurePosixPath(resolved_input).parts),
                "required Kbuild input resolved path is invalid")
        if item["regular_file"] and not item["target_exists"]:
            raise ValueError("required Kbuild input regular-file state is inconsistent")
        expected_targets = set()
        if build_root_posix is not None:
            expected_targets.add(str(build_root_posix / relative))
        if common_root_posix is not None:
            expected_targets.add(str(common_root_posix / relative))
        if not item["regular_file"] or resolved_input not in expected_targets:
            required_inputs_ready = False
    symvers_bytes, symvers_digest = build["module_symvers_bytes"], build["module_symvers_sha256"]
    require((symvers_bytes is None) == (symvers_digest is None),
            "Module.symvers size and hash availability disagree")
    if symvers_bytes is not None:
        require(type(symvers_bytes) is int and 0 < symvers_bytes <= 64 * 1024 * 1024,
                "Module.symvers size is invalid")
        require(isinstance(symvers_digest, str) and re.fullmatch(r"[0-9a-f]{64}", symvers_digest),
                "Module.symvers SHA-256 is invalid")
    expected_kernel_ready = bool(resolved and build["makefile_exists"] and
                                 build["generated_autoconf_exists"] and build["scripts_modpost_exists"] and
                                 build["scripts_fixdep_exists"] and symvers_bytes and symvers_digest and required_inputs_ready)
    require(build["ready"] == expected_kernel_ready,
            "kernel build readiness disagrees with captured Kbuild inputs")
    expected_ready = bool(required_tools_ready and expected_kernel_ready and
                          disk["available_bytes"] > 0 and disk["available_inodes"] > 0)
    require(report["build_prerequisites_ready"] == expected_ready,
            "build prerequisite readiness disagrees with captured tools, space and Kbuild inputs")
    require(report["read_only_guest_query"] is True and report["mutation_performed"] is False,
            "guest prerequisite query is not marked read-only")
    return report


def output_path(value: str | None) -> Path:
    if value is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        candidate = ROOT / "evidence" / f"pc3-v100-build-prerequisites-{stamp}.json"
    else:
        raw = Path(value)
        candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = Path(os.path.abspath(candidate))
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        raise ValueError("prerequisite evidence must remain inside the canonical project") from None
    cursor = ROOT
    for part in candidate.parent.relative_to(ROOT).parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            cursor.mkdir(mode=0o700)
            info = cursor.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("prerequisite evidence directory contains an unsafe component")
    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError("prerequisite evidence destination already exists")
    return candidate


def write_private_json(path: Path, report: dict[str, Any]) -> str:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(payload).hexdigest()


def collect(transport, target: str, host_key_alias: str,
            credential_host: str, credential_file: str) -> dict[str, Any]:
    guest_bytes = GUEST_SCRIPT.encode("utf-8")
    guest_digest = hashlib.sha256(guest_bytes).hexdigest()
    guest_b64 = base64.b64encode(guest_bytes).decode("ascii")
    remote_command = "sudo -S -p '' python3 -c " + shlex.quote(ROOT_REMOTE_SCRIPT) + " " + \
        shlex.quote(guest_b64) + " " + shlex.quote(guest_digest)
    secret = transport.fetch_pc3_sudo_secret(credential_host, credential_file)
    try:
        result = subprocess.run(transport.pc3_ssh_base(target, host_key_alias) + [remote_command],
                                input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only prerequisite inventory transport failed") from None
    finally:
        secret = None
    if result.returncode != 0 or len(result.stdout) > MAX_REMOTE_BYTES:
        raise RuntimeError("PC3 did not return a bounded successful prerequisite inventory")
    try:
        envelope = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 returned an invalid prerequisite transport envelope") from None
    required_envelope = {"schema", "guest_ssh_exit_code", "guest_stdout_b64", "guest_stderr_sha256", "hostkey_fingerprint"}
    if (not isinstance(envelope, dict) or set(envelope) != required_envelope or
            envelope.get("schema") != "nvidia-hybrid-pc3-v100-prerequisite-transport-v1" or
            envelope.get("guest_ssh_exit_code") != 0 or
            envelope.get("hostkey_fingerprint") != GUEST_HOSTKEY_FINGERPRINT or
            not isinstance(envelope.get("guest_stderr_sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", envelope["guest_stderr_sha256"]) is None):
        raise RuntimeError("PC3 guest identity or prerequisite transport failed validation")
    try:
        guest_raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("PC3 guest prerequisite encoding is invalid") from None
    guest = validate_guest_report(guest_raw)
    return {
        "schema": "nvidia-hybrid-pc3-v100-build-prerequisites-capture-v1",
        "status": "collected",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "credential_host": credential_host,
        "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
        "guest_script_sha256": guest_digest,
        "transport_script_sha256": hashlib.sha256(ROOT_REMOTE_SCRIPT.encode()).hexdigest(),
        "guest_stderr_sha256": envelope["guest_stderr_sha256"],
        "guest": guest,
        "collection_scope": "compiler/binutils version availability, /tmp free bytes and inodes, and running-kernel Kbuild inputs",
        "read_only_guest_query": True,
        "host_or_guest_mutation_performed": False,
        "module_built_or_loaded": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="private JSON evidence path inside the canonical project")
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    parser.add_argument("--credential-host")
    parser.add_argument("--credential-file")
    args = parser.parse_args(argv)
    try:
        destination = output_path(args.output)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        transport = load_transport()
        report = collect(transport, args.target, args.host_key_alias,
                         args.credential_host or transport.DEFAULT_CREDENTIAL_HOST,
                         args.credential_file or transport.DEFAULT_CREDENTIAL_FILE)
        status = "collected"
    except Exception as error:
        report = {
            "schema": "nvidia-hybrid-pc3-v100-build-prerequisites-capture-v1",
            "status": "failed",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "target": args.target,
            "guest_hostkey_fingerprint": GUEST_HOSTKEY_FINGERPRINT,
            "read_only_guest_query": True,
            "host_or_guest_mutation_performed": False,
            "module_built_or_loaded": False,
            "failure": str(error)[:240],
        }
        status = "failed"
    try:
        digest = write_private_json(destination, report)
    except OSError as error:
        print(f"could not publish private prerequisite report: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": status, "report": str(destination), "sha256": digest}, sort_keys=True))
    return 0 if status == "collected" else 2


if __name__ == "__main__":
    raise SystemExit(main())
