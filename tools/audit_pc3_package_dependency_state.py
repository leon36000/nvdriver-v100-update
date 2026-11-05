#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect a bounded, read-only PC3 NVIDIA package-state diagnostic.

The query binds package-manager observations to a previously captured PC3
host snapshot. Its only APT invocation is an explicitly simulated,
no-download reinstall of the installed nvidia-driver-595-open version.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import run_pc3_v100_guest_reference as transport  # noqa: E402

REPORT_SCHEMA = "pc3-package-dependency-state-audit-v1"
REMOTE_SCHEMA = "pc3-package-manager-state-remote-v1"
STATE_SCHEMA = "nvidia-hybrid-canary-host-state-v2"
DEFAULT_SNAPSHOT = ROOT / "evidence/pc3-canary-host-state-continuation-v14-20261029T0137Z.json"
DEFAULT_SNAPSHOT_SHA256 = "8bf110384704a8900dde4a123b4865ac050f30ba02ac7306e03e0bf9c9feed83"
EXPECTED_PACKAGES = ("nvidia-driver-595-open", "xserver-xorg-video-nvidia-595")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$")


REMOTE_AUDIT_SCRIPT = r'''import hashlib,json,os,re,subprocess,sys

packages=("nvidia-driver-595-open","xserver-xorg-video-nvidia-595")
version_re=re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$")
package_re=re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.-]*(?::[A-Za-z0-9-]+)?$")
action_re=re.compile(r"^(Inst|Conf|Remv|Purg|Keep)\s+([^\s]+)(?:\s|$)")
limit=2*1024*1024

def run(argv,timeout=25):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,timeout=timeout,check=False,
        env=dict(os.environ,LC_ALL="C",LANG="C"))
    if len(result.stdout)>limit or len(result.stderr)>limit:
        raise RuntimeError("bounded command output exceeded limit")
    return result

def digest(value):
    return hashlib.sha256(value).hexdigest()

observed_packages={}
for name in packages:
    result=run(["dpkg-query","--show","--showformat=${db:Status-Abbrev}\\t${Version}\\n",name])
    lines=result.stdout.decode("utf-8","strict").splitlines()
    if result.returncode==0 and len(lines)==1:
        fields=lines[0].split("\t",1)
        if len(fields)!=2 or len(fields[0])!=3:
            raise RuntimeError("unexpected dpkg-query result shape")
        status,version=fields
        if version!="<none>" and not version_re.fullmatch(version):
            raise RuntimeError("unexpected package version format")
    elif result.returncode!=0 and not lines:
        status,version="un ","<none>"
    else:
        raise RuntimeError("dpkg-query failed or returned ambiguous package state")
    observed_packages[name]={"status":status,"version":version,
        "query_exit_code":result.returncode,
        "stdout_sha256":digest(result.stdout),"stderr_sha256":digest(result.stderr)}

audit=run(["dpkg","--audit"])
if audit.returncode<0 or audit.returncode>255:
    raise RuntimeError("unexpected dpkg audit exit code")

apt_actions=[]
driver=observed_packages[packages[0]]
apt_exit=125
apt_stdout=b""
apt_stderr=b""
apt_invoked=False
if driver["status"]=="ii " and version_re.fullmatch(driver["version"]):
    apt_invoked=True
    apt=run(["apt-get","--simulate","--no-download","-o","Debug::NoLocking=1",
             "--reinstall","install",packages[0]+"="+driver["version"]],timeout=35)
    apt_exit=apt.returncode
    apt_stdout,apt_stderr=apt.stdout,apt.stderr
    for line in apt_stdout.decode("utf-8","replace").splitlines():
        match=action_re.match(line)
        if match:
            operation,package=match.groups()
            if ":" in package:
                package=package.split(":",1)[0]
            if not package_re.fullmatch(package):
                raise RuntimeError("unexpected APT action package format")
            apt_actions.append({"operation":operation,"package":package})

report={"schema":"pc3-package-manager-state-remote-v1","host":os.uname().nodename,
    "kernel_release":os.uname().release,
    "loaded_nvidia_module_version":open("/sys/module/nvidia/version",encoding="ascii").read().strip(),
    "packages":observed_packages,
    "dpkg_audit":{"exit_code":audit.returncode,"stdout_sha256":digest(audit.stdout),
        "stderr_sha256":digest(audit.stderr),"stdout_nonempty":bool(audit.stdout.strip())},
    "apt_simulation":{"invoked":apt_invoked,"exit_code":apt_exit,
        "stdout_sha256":digest(apt_stdout),"stderr_sha256":digest(apt_stderr),"actions":apt_actions},
    "apt_network_or_package_state_changed":False}
print(json.dumps(report,sort_keys=True,separators=(",",":")))
'''


def _read_regular_nofollow(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("host snapshot must be a regular file")
        return stream.read(16 * 1024 * 1024 + 1)


def load_host_snapshot(path: Path, expected_sha256: str) -> dict:
    if not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256):
        raise ValueError("snapshot SHA-256 must be 64 lowercase hexadecimal characters")
    raw = _read_regular_nofollow(Path(path))
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("host snapshot exceeds the bounded input size")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("host snapshot SHA-256 does not match the pinned value")
    try:
        snapshot = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("host snapshot is not valid UTF-8 JSON") from None
    if (not isinstance(snapshot, dict) or snapshot.get("schema") != STATE_SCHEMA or
            not isinstance(snapshot.get("host"), str) or snapshot["host"].lower() != "pc3"):
        raise ValueError("expected a supported PC3 host-state snapshot")
    if (not isinstance(snapshot.get("kernel_release"), str) or
            not snapshot["kernel_release"] or "\n" in snapshot["kernel_release"]):
        raise ValueError("PC3 snapshot kernel identity is invalid")
    if (not isinstance(snapshot.get("loaded_nvidia_module_version"), str) or
            not VERSION_RE.fullmatch(snapshot["loaded_nvidia_module_version"])):
        raise ValueError("PC3 snapshot loaded NVIDIA module identity is invalid")
    return snapshot


def _require_hash(value: object, label: str) -> None:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ValueError(label + " must be a lowercase SHA-256 digest")


def validate_remote_report(remote: dict, snapshot: dict) -> dict:
    if not isinstance(remote, dict) or remote.get("schema") != REMOTE_SCHEMA:
        raise ValueError("unsupported PC3 remote package-state schema")
    if (not isinstance(remote.get("host"), str) or
            not isinstance(snapshot.get("host"), str) or
            remote["host"].lower() != snapshot["host"].lower() or
            remote["host"].lower() != "pc3" or
            remote.get("kernel_release") != snapshot.get("kernel_release") or
            remote.get("loaded_nvidia_module_version") != snapshot.get("loaded_nvidia_module_version")):
        raise ValueError("PC3 host, kernel, or loaded-driver identity drifted from the pinned snapshot")

    packages = remote.get("packages")
    if not isinstance(packages, dict) or set(packages) != set(EXPECTED_PACKAGES):
        raise ValueError("remote package set differs from the bounded NVIDIA query")
    normalized_packages = {}
    for name in EXPECTED_PACKAGES:
        record = packages[name]
        if not isinstance(record, dict) or record.get("status") not in ("ii ", "un ", "rc "):
            raise ValueError("remote dpkg package status is malformed")
        version = record.get("version")
        if version != "<none>" and (not isinstance(version, str) or not VERSION_RE.fullmatch(version)):
            raise ValueError("remote dpkg package version is malformed")
        exit_code = record.get("query_exit_code", 0 if record["status"] == "ii " else 1)
        if type(exit_code) is not int or exit_code not in (0, 1):
            raise ValueError("remote dpkg-query exit code is invalid")
        if ((record["status"] == "un " and (version != "<none>" or exit_code != 1)) or
                (record["status"] in ("ii ", "rc ") and (version == "<none>" or exit_code != 0))):
            raise ValueError("remote dpkg status, version, and query result disagree")
        _require_hash(record.get("stdout_sha256"), "dpkg-query stdout hash")
        _require_hash(record.get("stderr_sha256"), "dpkg-query stderr hash")
        normalized_packages[name] = {
            "status": record["status"], "version": version, "query_exit_code": exit_code,
            "stdout_sha256": record["stdout_sha256"], "stderr_sha256": record["stderr_sha256"],
        }

    audit = remote.get("dpkg_audit")
    if (not isinstance(audit, dict) or type(audit.get("exit_code")) is not int or
            not 0 <= audit["exit_code"] <= 255 or type(audit.get("stdout_nonempty")) is not bool):
        raise ValueError("remote dpkg audit result is malformed")
    _require_hash(audit.get("stdout_sha256"), "dpkg audit stdout hash")
    _require_hash(audit.get("stderr_sha256"), "dpkg audit stderr hash")

    apt = remote.get("apt_simulation")
    if (not isinstance(apt, dict) or type(apt.get("invoked")) is not bool or
            type(apt.get("exit_code")) is not int or not -1 <= apt["exit_code"] <= 255 or
            not isinstance(apt.get("actions"), list) or len(apt["actions"]) > 256):
        raise ValueError("remote APT simulation result is malformed")
    _require_hash(apt.get("stdout_sha256"), "APT simulation stdout hash")
    _require_hash(apt.get("stderr_sha256"), "APT simulation stderr hash")
    expected_apt_invoked = normalized_packages[EXPECTED_PACKAGES[0]]["status"] == "ii "
    if apt["invoked"] is not expected_apt_invoked:
        raise ValueError("APT simulation invocation does not match the installed driver package state")
    if not apt["invoked"] and (apt["exit_code"] != 125 or apt["actions"]):
        raise ValueError("skipped APT simulation has an unexpected result")
    normalized_actions = []
    for item in apt["actions"]:
        if (not isinstance(item, dict) or set(item) != {"operation", "package"} or
                item.get("operation") not in ("Inst", "Conf", "Keep") or
                not isinstance(item.get("package"), str) or not PACKAGE_RE.fullmatch(item["package"])):
            raise ValueError("APT simulation contains an unsupported or destructive action")
        normalized_actions.append(dict(item))
    if remote.get("apt_network_or_package_state_changed") is not False:
        raise ValueError("APT simulation did not attest to its no-download, no-mutation contract")

    return {
        "schema": REPORT_SCHEMA,
        "status": "package-state-observed",
        "host": "pc3",
        "kernel_release": snapshot["kernel_release"],
        "loaded_nvidia_module_version": snapshot["loaded_nvidia_module_version"],
        "packages": normalized_packages,
        "dpkg_audit": {key: audit[key] for key in
                        ("exit_code", "stdout_sha256", "stderr_sha256", "stdout_nonempty")},
        "apt_simulation": {"invoked": apt["invoked"], "exit_code": apt["exit_code"],
                            "stdout_sha256": apt["stdout_sha256"],
                            "stderr_sha256": apt["stderr_sha256"], "actions": normalized_actions},
        "state_changes": {"pc3_contacted": True, "package_database_modified": False,
                           "packages_installed": False, "packages_removed": False,
                           "apt_downloaded_packages": False, "driver_modules_changed": False},
    }


def _remote_command() -> str:
    return "sudo -S -p '' python3 -c " + shlex.quote(REMOTE_AUDIT_SCRIPT)


def collect_remote(target: str = transport.DEFAULT_PC3_TARGET,
                   credential_host: str = transport.DEFAULT_CREDENTIAL_HOST,
                   credential_file: str = transport.DEFAULT_CREDENTIAL_FILE,
                   host_key_alias: str = transport.DEFAULT_HOST_KEY_ALIAS,
                   timeout: int = 90) -> dict:
    secret = transport.fetch_pc3_sudo_secret(credential_host, credential_file)
    try:
        result = subprocess.run(
            transport.pc3_ssh_base(target, host_key_alias) + [_remote_command()],
            input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("bounded read-only PC3 package-state SSH query failed") from None
    finally:
        secret = None
    if result.returncode != 0:
        raise RuntimeError("PC3 package-state query failed; stderr sha256=" +
                           hashlib.sha256(result.stderr).hexdigest())
    if len(result.stdout) > 1024 * 1024:
        raise RuntimeError("PC3 package-state report exceeded the bounded output size")
    try:
        value = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 package-state query returned invalid JSON") from None
    if not isinstance(value, dict):
        raise RuntimeError("PC3 package-state query returned an invalid report")
    return value


def write_report(path: Path, report: dict, evidence_root: Path | None = None) -> None:
    path = Path(path)
    root = Path(evidence_root) if evidence_root is not None else ROOT / "evidence"
    root = root.resolve(strict=True)
    try:
        path.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        raise ValueError("package-state report must be written inside the evidence tree") from None
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("package-state report destination is not a regular file")
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--snapshot-sha256", default=DEFAULT_SNAPSHOT_SHA256)
    parser.add_argument("--output", type=Path, required=True,
                        help="create a fresh mode-0600 report under evidence; never overwrite")
    args = parser.parse_args(argv)
    try:
        snapshot = load_host_snapshot(args.snapshot, args.snapshot_sha256)
        remote = collect_remote()
        report = validate_remote_report(remote, snapshot)
        report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
        report["snapshot"] = {"path": str(args.snapshot.resolve()),
                              "sha256": args.snapshot_sha256}
        report["audit_provenance"] = {
            "local_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "remote_script_sha256": hashlib.sha256(REMOTE_AUDIT_SCRIPT.encode("utf-8")).hexdigest(),
            "transport": {"target": transport.DEFAULT_PC3_TARGET,
                          "host_key_alias": transport.DEFAULT_HOST_KEY_ALIAS,
                          "sudo_value_logged": False, "sudo_value_persisted": False},
            "qualification": "read-only-package-query-and-apt-simulation",
        }
        write_report(args.output, report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("PC3 package-state audit failed: " + str(error), file=sys.stderr)
        return 2
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"schema": REPORT_SCHEMA, "status": report["status"],
                      "host": report["host"], "output": str(args.output.resolve()),
                      "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
