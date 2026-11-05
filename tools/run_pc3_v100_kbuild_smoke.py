#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and remove an inert external kernel module in PC3's V100 guest.

The guest build runs as ubuntu in a temporary directory. It does not install or
load the module, change the driver, or invoke CUDA or the GPU.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PINNED_HOSTNAME = "pc3-v100"
PINNED_KERNEL_RELEASE = "6.8.0-147-generic"
PINNED_BUILD_PATH = "/usr/src/linux-headers-6.8.0-147-generic"
KERNEL_INPUT_FILES = (
    "Makefile",
    "Module.symvers",
    "include/config/auto.conf",
    "include/generated/autoconf.h",
    "include/generated/utsrelease.h",
    "scripts/Makefile.build",
    "scripts/Makefile.modpost",
    "scripts/mod/modpost",
    "scripts/basic/fixdep",
)
MAX_GUEST_BYTES = 2 * 1024 * 1024
MAX_MAKE_OUTPUT_BYTES = 16 * 1024 * 1024


GUEST_KBUILD_SCRIPT = r'''import hashlib,json,os,platform,re,shutil,stat,struct,subprocess,tempfile
HOSTNAME="pc3-v100"
RELEASE="6.8.0-147-generic"
BUILD="/lib/modules/"+RELEASE+"/build"
EXPECTED_BUILD="/usr/src/linux-headers-6.8.0-147-generic"
INPUTS=("Makefile","Module.symvers","include/config/auto.conf","include/generated/autoconf.h","include/generated/utsrelease.h","scripts/Makefile.build","scripts/Makefile.modpost","scripts/mod/modpost","scripts/basic/fixdep")
def safe_system_path(path):
 resolved=os.path.realpath(path)
 return resolved.startswith(("/usr/src/","/lib/modules/","/usr/lib/modules/"))
def digest_file(path):
 try:
  if not safe_system_path(path): return None
  st=os.stat(path)
  if not stat.S_ISREG(st.st_mode): return None
  digest=hashlib.sha256()
  with open(path,"rb") as stream:
   for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
  return digest.hexdigest()
 except OSError: return None
def input_hashes():
 return {name:digest_file(os.path.join(EXPECTED_BUILD,name)) for name in INPUTS}
if os.geteuid()==0: raise SystemExit("smoke test must run unprivileged")
if platform.node()!=HOSTNAME or platform.release()!=RELEASE: raise SystemExit("pinned guest identity mismatch")
if not os.path.isdir(BUILD) or os.path.realpath(BUILD)!=EXPECTED_BUILD: raise SystemExit("pinned kernel build path mismatch")
before=input_hashes()
work=None
created=False
removed=False
make_code=-1
stdout=b""
stderr=b""
output_complete=False
module=None
try:
 if any(value is None for value in before.values()): raise RuntimeError("required kernel build input is missing")
 work=tempfile.mkdtemp(prefix="codex-v100-kbuild-smoke-",dir="/tmp")
 created=True
 with open(os.path.join(work,"Makefile"),"w",encoding="ascii") as stream:
  stream.write("obj-m := codex_kbuild_smoke.o\n")
 with open(os.path.join(work,"codex_kbuild_smoke.c"),"w",encoding="ascii") as stream:
  stream.write("#include <linux/init.h>\n#include <linux/module.h>\nstatic int __init codex_kbuild_smoke_init(void) { return 0; }\nstatic void __exit codex_kbuild_smoke_exit(void) {}\nmodule_init(codex_kbuild_smoke_init);\nmodule_exit(codex_kbuild_smoke_exit);\nMODULE_LICENSE(\"GPL\");\n")
 env={"PATH":"/usr/bin:/bin","LC_ALL":"C","TMPDIR":"/tmp"}
 try:
  result=subprocess.run(["/usr/bin/make","-C",BUILD,"M="+work,"modules"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False,env=env)
  make_code=result.returncode
  stdout=result.stdout
  stderr=result.stderr
  output_complete=True
 except subprocess.TimeoutExpired as error:
  make_code=124
  stdout=error.stdout or b""
  stderr=error.stderr or b""
 path=os.path.join(work,"codex_kbuild_smoke.ko")
 try:
  with open(path,"rb") as stream: data=stream.read(128*1024*1024+1)
 except OSError: data=b""
 if data and len(data)<=128*1024*1024 and data[:4]==b"\x7fELF" and len(data)>=20:
  elf_class={1:32,2:64}.get(data[4],0)
  machine=struct.unpack_from("<H",data,18)[0] if data[5]==1 else 0
  module={"filename":"codex_kbuild_smoke.ko","bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"elf_class_bits":elf_class,"elf_machine":machine,"vermagic_matches":("vermagic="+RELEASE+" ").encode() in data}
except Exception:
 pass
finally:
 if work is None:
  removed=True
 else:
  try: shutil.rmtree(work)
  except OSError: pass
  removed=not os.path.lexists(work)
after=input_hashes()
passed=(created and removed and make_code==0 and output_complete and len(stdout)+len(stderr)<=16*1024*1024 and module is not None and module["elf_class_bits"]==64 and module["elf_machine"]==62 and module["vermagic_matches"] and before==after)
report={"schema":"nvidia-hybrid-pc3-v100-kbuild-smoke-result-v2","status":"passed" if passed else "failed","hostname":platform.node(),"kernel_release":platform.release(),"build_path":os.path.realpath(BUILD),"make_exit_code":make_code,"make_stdout_bytes":len(stdout),"make_stderr_bytes":len(stderr),"make_output_complete":output_complete,"make_stdout_sha256":hashlib.sha256(stdout).hexdigest(),"make_stderr_sha256":hashlib.sha256(stderr).hexdigest(),"temporary_directory_created":created,"temporary_directory_removed":removed,"kernel_inputs_before_sha256":before,"kernel_inputs_after_sha256":after,"module":module,"module_installed":False,"module_loaded":False,"gpu_execution_tested":False}
print(json.dumps(report,separators=(",",":"),sort_keys=True))
'''


def _load_inventory_tool():
    path = ROOT / "tools/collect_pc3_v100_package_inventory.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_package_inventory", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 guest transport is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_guest_smoke(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_GUEST_BYTES:
        raise ValueError("guest Kbuild result size is invalid")
    try:
        report = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("guest Kbuild result is not valid UTF-8 JSON") from None

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    fields = {
        "schema", "status", "hostname", "kernel_release", "build_path",
        "make_exit_code", "make_stdout_bytes", "make_stderr_bytes",
        "make_output_complete", "make_stdout_sha256", "make_stderr_sha256",
        "temporary_directory_created", "temporary_directory_removed",
        "kernel_inputs_before_sha256", "kernel_inputs_after_sha256", "module",
        "module_installed", "module_loaded", "gpu_execution_tested",
    }
    require(isinstance(report, dict) and set(report) == fields,
            "guest Kbuild result fields differ from the expected schema")
    require(report["schema"] == "nvidia-hybrid-pc3-v100-kbuild-smoke-result-v2",
            "guest Kbuild result schema is unsupported")
    require(report["hostname"] == PINNED_HOSTNAME and
            report["kernel_release"] == PINNED_KERNEL_RELEASE,
            "guest identity differs from the pinned V100 guest kernel")
    require(report["build_path"] == PINNED_BUILD_PATH,
            "guest build path differs from the pinned V100 kernel headers")
    require(type(report["make_exit_code"]) is int and -1 <= report["make_exit_code"] <= 255,
            "guest make exit status is invalid")
    for key in ("make_stdout_bytes", "make_stderr_bytes"):
        require(type(report[key]) is int and 0 <= report[key] <= 64 * 1024**2,
                f"guest {key} is invalid")
    require(isinstance(report["make_output_complete"], bool),
            "guest make output completeness flag is invalid")
    for key in ("make_stdout_sha256", "make_stderr_sha256"):
        require(isinstance(report[key], str) and re.fullmatch(r"[0-9a-f]{64}", report[key]),
                f"guest {key} is invalid")
    for key in ("temporary_directory_created", "temporary_directory_removed",
                "module_installed", "module_loaded", "gpu_execution_tested"):
        require(isinstance(report[key], bool), f"guest {key} flag is invalid")
    require(report["temporary_directory_removed"],
            "guest temporary directory was not fully cleaned up")
    require(not report["module_installed"] and not report["module_loaded"] and
            not report["gpu_execution_tested"],
            "guest result crossed the module execution boundary")

    before, after = report["kernel_inputs_before_sha256"], report["kernel_inputs_after_sha256"]
    require(isinstance(before, dict) and set(before) == set(KERNEL_INPUT_FILES) and
            isinstance(after, dict) and set(after) == set(KERNEL_INPUT_FILES),
            "guest kernel input fingerprint set is invalid")
    for mapping in (before, after):
        require(all(value is None or
                    (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))
                    for value in mapping.values()),
                "guest kernel input fingerprint is malformed")
    inputs_unchanged = before == after and all(value is not None for value in before.values())
    if report["status"] == "passed":
        require(inputs_unchanged, "guest kernel inputs changed during the smoke build")
    module = report["module"]
    module_valid = False
    if module is not None:
        module_fields = {"filename", "bytes", "sha256", "elf_class_bits", "elf_machine",
                         "vermagic_matches"}
        require(isinstance(module, dict) and set(module) == module_fields,
                "guest smoke module fields are invalid")
        require(module["filename"] == "codex_kbuild_smoke.ko",
                "guest smoke module filename is invalid")
        require(type(module["bytes"]) is int and 0 < module["bytes"] <= 128 * 1024**2,
                "guest smoke module size is invalid")
        require(isinstance(module["sha256"], str) and
                re.fullmatch(r"[0-9a-f]{64}", module["sha256"]),
                "guest smoke module SHA-256 is invalid")
        require(type(module["elf_class_bits"]) is int and
                type(module["elf_machine"]) is int,
                "guest smoke module ELF identity is invalid")
        require(isinstance(module["vermagic_matches"], bool),
                "guest smoke module vermagic flag is invalid")
        module_valid = (module["elf_class_bits"] == 64 and module["elf_machine"] == 62 and
                        module["vermagic_matches"])
        if report["status"] == "passed":
            require(module_valid, "guest smoke module ELF machine or vermagic is invalid")
    require(report["status"] in ("passed", "failed"),
            "guest Kbuild status is invalid")
    actual_pass = (report["temporary_directory_created"] and
                   report["make_exit_code"] == 0 and report["make_output_complete"] and
                   report["make_stdout_bytes"] + report["make_stderr_bytes"] <= MAX_MAKE_OUTPUT_BYTES and
                   inputs_unchanged and module_valid)
    require((report["status"] == "passed") == actual_pass,
            "guest Kbuild status contradicts the build result")
    return report


def collect(transport, target: str, host_key_alias: str) -> dict[str, Any]:
    inventory_tool = _load_inventory_tool()
    guest_bytes = GUEST_KBUILD_SCRIPT.encode("utf-8")
    guest_digest = hashlib.sha256(guest_bytes).hexdigest()
    guest_b64 = base64.b64encode(guest_bytes).decode("ascii")
    remote_command = ("sudo -S -p '' python3 -c " +
                      shlex.quote(inventory_tool.ROOT_REMOTE_SCRIPT) + " " +
                      shlex.quote(guest_b64) + " " + shlex.quote(guest_digest))
    secret = transport.fetch_pc3_sudo_secret(
        transport.DEFAULT_CREDENTIAL_HOST, transport.DEFAULT_CREDENTIAL_FILE)
    try:
        result = subprocess.run(
            transport.pc3_ssh_base(target, host_key_alias) + [remote_command],
            input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only PC3 transport or bounded guest build failed") from None
    finally:
        secret = None
    if result.returncode != 0 or len(result.stdout) > MAX_GUEST_BYTES:
        raise RuntimeError("PC3 did not return a bounded successful Kbuild smoke result")
    try:
        envelope = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 returned an invalid Kbuild smoke transport envelope") from None
    expected_fields = {"schema", "guest_ssh_exit_code", "guest_stdout_b64",
                       "guest_stderr_sha256", "hostkey_fingerprint"}
    if (not isinstance(envelope, dict) or set(envelope) != expected_fields or
            envelope.get("schema") != "nvidia-hybrid-pc3-v100-package-transport-v1" or
            envelope.get("guest_ssh_exit_code") != 0 or
            envelope.get("hostkey_fingerprint") != inventory_tool.GUEST_HOSTKEY_FINGERPRINT or
            not isinstance(envelope.get("guest_stderr_sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", envelope["guest_stderr_sha256"]) is None):
        raise RuntimeError("PC3 guest identity or Kbuild transport envelope failed validation")
    try:
        guest_raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("PC3 guest Kbuild result encoding is invalid") from None
    guest_report = validate_guest_smoke(guest_raw)
    return {
        "schema": "nvidia-hybrid-pc3-v100-kbuild-smoke-capture-v2",
        "status": guest_report["status"],
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "guest_hostkey_fingerprint": inventory_tool.GUEST_HOSTKEY_FINGERPRINT,
        "runner_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "host_transport_tool_sha256": hashlib.sha256(
            (ROOT / "tools/collect_pc3_v100_package_inventory.py").read_bytes()).hexdigest(),
        "transport_script_sha256": hashlib.sha256(
            inventory_tool.ROOT_REMOTE_SCRIPT.encode()).hexdigest(),
        "guest_script_sha256": guest_digest,
        "guest_stderr_sha256": envelope["guest_stderr_sha256"],
        "guest_result": guest_report,
        "qualification": "external-kernel-module-build-only",
        "module_installed": False,
        "module_loaded": False,
        "gpu_execution_tested": False,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="private JSON destination under the canonical project")
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    args = parser.parse_args(argv)
    inventory_tool = _load_inventory_tool()
    try:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        default_output = f"evidence/pc3-v100-kbuild-smoke-v2-{stamp}.json"
        destination = inventory_tool.output_path(args.output or default_output)
        report = collect(inventory_tool.load_transport(), args.target, args.host_key_alias)
        digest = inventory_tool.write_private_json(destination, report)
    except Exception as error:
        print(f"Kbuild smoke capture failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(destination), "sha256": digest,
                      "status": report["status"]}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
