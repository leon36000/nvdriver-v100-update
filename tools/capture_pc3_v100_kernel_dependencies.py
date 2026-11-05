#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the exact PC3 V100 guest crypto modules needed by its R580 stack.

The guest query is read-only and bound to the pinned PC3-to-guest SSH route.
It captures only the Linux 6.8.0-147 support-module dependency closure for
ecc/ecdh_generic/ecdsa_generic and five module-tree metadata files. It never
loads a module, runs CUDA, or changes guest or host driver state.
"""
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
import uuid
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
KERNEL_RELEASE = "6.8.0-147-generic"
GUEST_HOSTNAME = "pc3-v100"
GUEST_MODULE_ROOT = f"/lib/modules/{KERNEL_RELEASE}"
MODULE_NAMES = ("ecc", "ecdh_generic", "ecdsa_generic")
MODULE_DEPENDENCIES = {
    "ecc": [],
    "ecdh_generic": ["ecc"],
    "ecdsa_generic": ["ecc"],
}
METADATA_NAMES = (
    "modules.builtin", "modules.builtin.modinfo", "modules.dep",
    "modules.order", "modules.softdep",
)
MAX_REMOTE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024


GUEST_CAPTURE_SCRIPT = r'''import base64,hashlib,json,os,platform,re,socket,stat,subprocess
from pathlib import Path,PurePosixPath
RELEASE="6.8.0-147-generic"
ROOT=Path("/lib/modules")/RELEASE
MODULES=("ecc","ecdh_generic","ecdsa_generic")
METADATA=("modules.builtin","modules.builtin.modinfo","modules.dep","modules.order","modules.softdep")
MAX_FILE=4*1024*1024
def normalize(name):
 for suffix in (".ko.zst",".ko.xz",".ko.gz",".ko"):
  if name.endswith(suffix): return name[:-len(suffix)].replace("-","_")
 return name.replace("-","_")
def read_file(path,allowed_root):
 st=os.lstat(path)
 if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode): raise RuntimeError("unexpected module-tree file type")
 resolved=Path(path).resolve(strict=True)
 if not resolved.is_relative_to(allowed_root): raise RuntimeError("module-tree path escaped root")
 data=Path(path).read_bytes()
 if not data or len(data)>MAX_FILE: raise RuntimeError("module-tree file size outside capture bound")
 return data
if socket.gethostname()!="pc3-v100" or platform.release()!=RELEASE: raise RuntimeError("unexpected guest identity")
if ROOT.is_symlink() or not ROOT.is_dir(): raise RuntimeError("guest module root is unavailable")
ROOT=ROOT.resolve(strict=True)
dep_path=ROOT/"modules.dep"
dep_bytes=read_file(dep_path,ROOT)
paths={}; dependencies={}
for line in dep_bytes.decode("utf-8","strict").splitlines():
 target,sep,rest=line.partition(":")
 if not sep: raise RuntimeError("malformed modules.dep")
 rel=target.strip(); pure=PurePosixPath(rel)
 if pure.is_absolute() or ".." in pure.parts: raise RuntimeError("unsafe module-tree entry")
 name=normalize(pure.name)
 if name in paths: raise RuntimeError("ambiguous module name")
 paths[name]=rel; dependencies[name]=[normalize(PurePosixPath(x).name) for x in rest.split()]
builtin_path=ROOT/"modules.builtin"
builtin_bytes=read_file(builtin_path,ROOT)
builtin={normalize(PurePosixPath(x.strip()).name) for x in builtin_bytes.decode("utf-8","strict").splitlines() if x.strip()}
seen=set(); missing=set(); stack=list(MODULES)
while stack:
 name=normalize(stack.pop())
 if name in seen: continue
 seen.add(name)
 if name in builtin: continue
 if name not in paths: missing.add(name); continue
 stack.extend(dependencies[name])
if missing: raise RuntimeError("kernel module dependency is missing")
if seen!=set(MODULES): raise RuntimeError("crypto dependency closure changed")
records=[]
for name in sorted(seen):
 rel=paths[name]; pure=PurePosixPath(rel)
 if pure.parts[:2]!=("kernel","crypto") or normalize(pure.name)!=name: raise RuntimeError("crypto module path differs from allowlist")
 data=read_file(ROOT/rel,ROOT)
 info=subprocess.run(["/usr/sbin/modinfo","-F","depends",str(ROOT/rel)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"},check=False)
 if info.returncode: raise RuntimeError("modinfo failed for captured dependency")
 parsed=[normalize(x.strip()) for x in info.stdout.strip().split(",") if x.strip()]
 if parsed!=dependencies[name]: raise RuntimeError("modules.dep and modinfo dependencies disagree")
 records.append({"kind":"module","name":name,"path":rel,"depends":dependencies[name],"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"data_base64":base64.b64encode(data).decode("ascii")})
for name in METADATA:
 data=read_file(ROOT/name,ROOT)
 records.append({"kind":"metadata","name":name,"path":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"data_base64":base64.b64encode(data).decode("ascii")})
print(json.dumps({"schema":"pc3-v100-kernel-dependency-payload-v1","hostname":socket.gethostname(),"kernel_release":RELEASE,"module_root":"/lib/modules/"+RELEASE,"roots":list(MODULES),"missing":[],"files":records},sort_keys=True,separators=(",",":")))
'''


def validate_guest_capture(payload: bytes) -> dict[str, Any]:
    """Validate the pinned guest identity, closed dependency set, and every byte."""
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("guest dependency payload is not valid JSON") from None
    if not isinstance(value, dict) or value.get("schema") != "pc3-v100-kernel-dependency-payload-v1":
        raise ValueError("guest dependency payload schema differs")
    if value.get("hostname") != GUEST_HOSTNAME:
        raise ValueError("guest identity differs")
    if value.get("kernel_release") != KERNEL_RELEASE:
        raise ValueError("kernel release differs")
    if value.get("module_root") != GUEST_MODULE_ROOT:
        raise ValueError("module root differs")
    if value.get("roots") != list(MODULE_NAMES) or value.get("missing") != []:
        raise ValueError("dependency roots or missing-module set differs")
    records = value.get("files")
    if not isinstance(records, list) or len(records) > 2 * (len(MODULE_NAMES) + len(METADATA_NAMES)):
        raise ValueError("capture file set is malformed")

    modules: dict[str, dict[str, Any]] = {}
    metadata: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    total_bytes = 0
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("capture record is malformed")
        kind = record.get("kind")
        name = record.get("name")
        path = record.get("path")
        if kind not in ("module", "metadata") or not isinstance(name, str) or not isinstance(path, str):
            raise ValueError("capture record identity is malformed")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            label = "module" if kind == "module" else "metadata"
            raise ValueError(f"{label} path escapes its allowlisted tree")
        if path in seen_paths:
            raise ValueError("duplicate capture path")
        seen_paths.add(path)
        if kind == "module":
            if name not in MODULE_NAMES or pure.parts[:2] != ("kernel", "crypto"):
                raise ValueError("module set or module path differs")
            match = re.fullmatch(r"(.+?)\.ko(?:\.(?:zst|xz|gz))?", pure.name)
            if match is None or match.group(1).replace("-", "_") != name:
                raise ValueError("module path does not identify its name")
            depends = record.get("depends")
            if depends != MODULE_DEPENDENCIES[name]:
                raise ValueError("dependency graph differs")
            destination = f"lib/modules/{KERNEL_RELEASE}/{path}"
        else:
            if name not in METADATA_NAMES or path != name:
                raise ValueError("metadata set or path differs")
            if "depends" in record:
                raise ValueError("metadata record contains a module dependency field")
            destination = f"lib/modules/{KERNEL_RELEASE}/{name}"
        try:
            data = base64.b64decode(record.get("data_base64", ""), validate=True)
        except (ValueError, TypeError):
            raise ValueError("capture file encoding is malformed") from None
        expected_bytes = record.get("bytes")
        expected_hash = record.get("sha256")
        if (not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or
                expected_bytes <= 0 or expected_bytes > MAX_FILE_BYTES or
                len(data) != expected_bytes or not isinstance(expected_hash, str) or
                re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None or
                hashlib.sha256(data).hexdigest() != expected_hash):
            label = "module" if kind == "module" else "metadata"
            raise ValueError(f"{label} file identity differs")
        total_bytes += len(data)
        normalized = {"name": name, "path": destination, "bytes": len(data),
                      "sha256": expected_hash, "data": data}
        if kind == "module":
            normalized["guest_path"] = path
            normalized["depends"] = depends
            modules[name] = normalized
        else:
            metadata[name] = normalized
    if set(modules) != set(MODULE_NAMES):
        raise ValueError("module set differs")
    if set(metadata) != set(METADATA_NAMES):
        raise ValueError("metadata set differs")
    if total_bytes > MAX_REMOTE_BYTES:
        raise ValueError("capture exceeds its aggregate size bound")
    return {
        "schema": value["schema"],
        "hostname": GUEST_HOSTNAME,
        "kernel_release": KERNEL_RELEASE,
        "modules": [modules[name] for name in MODULE_NAMES],
        "metadata": metadata,
        "total_bytes": total_bytes,
    }


def _load_package_transport():
    path = ROOT / "tools/collect_pc3_v100_package_inventory.py"
    spec = importlib.util.spec_from_file_location("pc3_package_capture_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 package transport is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_guest_transport():
    path = ROOT / "tools/run_pc3_v100_guest_reference.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 guest transport is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect_guest(transport: Any, package_transport: Any, *, target: str,
                  host_key_alias: str) -> tuple[dict[str, Any], dict[str, Any]]:
    guest_bytes = GUEST_CAPTURE_SCRIPT.encode("utf-8")
    guest_digest = hashlib.sha256(guest_bytes).hexdigest()
    guest_b64 = base64.b64encode(guest_bytes).decode("ascii")
    remote_command = "sudo -S -p '' python3 -c " + shlex.quote(package_transport.ROOT_REMOTE_SCRIPT) + " " + \
        shlex.quote(guest_b64) + " " + shlex.quote(guest_digest)
    secret = transport.fetch_pc3_sudo_secret(
        transport.DEFAULT_CREDENTIAL_HOST, transport.DEFAULT_CREDENTIAL_FILE)
    try:
        result = subprocess.run(
            transport.pc3_ssh_base(target, host_key_alias) + [remote_command],
            input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only PC3 dependency capture transport failed") from None
    finally:
        secret = None
    if result.returncode != 0 or len(result.stdout) > MAX_REMOTE_BYTES:
        raise RuntimeError("PC3 dependency capture did not return a bounded response")
    try:
        envelope = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 dependency capture envelope is invalid") from None
    required = {"schema", "guest_ssh_exit_code", "guest_stdout_b64",
                "guest_stderr_sha256", "hostkey_fingerprint"}
    if (not isinstance(envelope, dict) or set(envelope) != required or
            envelope.get("schema") != "nvidia-hybrid-pc3-v100-package-transport-v1" or
            envelope.get("guest_ssh_exit_code") != 0 or
            envelope.get("hostkey_fingerprint") != package_transport.GUEST_HOSTKEY_FINGERPRINT or
            not isinstance(envelope.get("guest_stderr_sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", envelope["guest_stderr_sha256"]) is None):
        raise RuntimeError("PC3 guest identity or dependency envelope failed validation")
    try:
        raw = base64.b64decode(envelope["guest_stdout_b64"], validate=True)
    except (ValueError, TypeError):
        raise RuntimeError("PC3 dependency payload encoding is invalid") from None
    capture = validate_guest_capture(raw)
    transport_report = {
        "guest_hostkey_fingerprint": envelope["hostkey_fingerprint"],
        "guest_script_sha256": guest_digest,
        "guest_stderr_sha256": envelope["guest_stderr_sha256"],
        "root_transport_script_sha256": hashlib.sha256(
            package_transport.ROOT_REMOTE_SCRIPT.encode("utf-8")).hexdigest(),
    }
    return capture, transport_report


def _safe_destination(path: Path, subtree: str, *, must_not_exist: bool) -> Path:
    raw = path if path.is_absolute() else ROOT / path
    candidate = Path(os.path.abspath(raw))
    allowed = ROOT / subtree
    try:
        relative = candidate.relative_to(allowed)
    except ValueError:
        raise ValueError(f"destination must remain under {allowed}") from None
    cursor = ROOT
    for component in candidate.relative_to(ROOT).parts:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("destination path contains a symlink")
        if cursor != candidate and not stat.S_ISDIR(info.st_mode):
            raise ValueError("destination parent is not a directory")
    if must_not_exist and (candidate.exists() or candidate.is_symlink()):
        raise FileExistsError(f"refusing to overwrite {candidate}")
    return candidate


def materialize_capture(capture: dict[str, Any], output_dir: Path) -> list[dict[str, Any]]:
    output_dir = _safe_destination(output_dir, "build/experiments", must_not_exist=True)
    output_dir.mkdir(parents=True, mode=0o700)
    files = list(capture["modules"]) + list(capture["metadata"].values())
    result = []
    for item in files:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("validated capture destination escaped its stage")
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(item["data"])
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(destination, 0o600)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        if digest != item["sha256"]:
            raise ValueError("materialized dependency hash changed")
        result.append({
            "name": item["name"],
            "kind": "module" if "depends" in item else "metadata",
            "guest_path": item.get("guest_path", item["name"]),
            "path": destination.relative_to(ROOT).as_posix(),
            "bytes": item["bytes"],
            "sha256": digest,
            **({"depends": item["depends"]} if "depends" in item else {}),
        })
    return result


def _safe_report_path(path: Path) -> Path:
    candidate = _safe_destination(path, "evidence", must_not_exist=True)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def write_private_json(path: Path, report: dict[str, Any]) -> str:
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(payload).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", help="private report under evidence/")
    parser.add_argument("--output-dir", help="new isolated module tree under build/experiments/")
    parser.add_argument("--target", default="pc3@pc3")
    parser.add_argument("--host-key-alias", default="pc3")
    args = parser.parse_args(argv)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = Path(args.report) if args.report else Path("evidence") / f"pc3-v100-kernel-dependencies-{stamp}.json"
    output_dir = Path(args.output_dir) if args.output_dir else Path("build/experiments") / \
        f"pc3-v100-kernel-dependencies-{stamp}-{uuid.uuid4().hex[:12]}"
    try:
        report_path = _safe_report_path(report_path)
        output_dir = _safe_destination(output_dir, "build/experiments", must_not_exist=True)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2

    report: dict[str, Any] = {
        "schema": "pc3-v100-kernel-dependency-capture-v1",
        "status": "failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": args.target,
        "guest_hostname": GUEST_HOSTNAME,
        "kernel_release": KERNEL_RELEASE,
        "guest_hostkey_fingerprint": None,
        "read_only_guest_query": True,
        "guest_mutation_performed": False,
        "driver_or_gpu_execution_tested": False,
        "module_installed": False,
        "module_loaded": False,
        "cuda_execution_tested": False,
        "runtime_or_hardware_validated": False,
    }
    try:
        capture, transport_report = collect_guest(
            _load_guest_transport(), _load_package_transport(),
            target=args.target, host_key_alias=args.host_key_alias)
        captured_files = materialize_capture(capture, output_dir)
        report.update({
            "status": "captured",
            "qualification": "read-only-exact-kernel-support-module-capture",
            **transport_report,
            "module_root": GUEST_MODULE_ROOT,
            "roots": list(MODULE_NAMES),
            "hard_dependency_graph": {name: MODULE_DEPENDENCIES[name] for name in MODULE_NAMES},
            "files": captured_files,
            "total_bytes": capture["total_bytes"],
            "stage_root": output_dir.relative_to(ROOT).as_posix(),
        })
    except Exception as error:
        report["failure"] = str(error)[:240]
    digest = write_private_json(report_path, report)
    print(json.dumps({"status": report["status"], "report": str(report_path),
                      "sha256": digest, "stage_root": report.get("stage_root")}, sort_keys=True))
    return 0 if report["status"] == "captured" else 2


if __name__ == "__main__":
    raise SystemExit(main())
