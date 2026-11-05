#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only audit of PC3 kernel-module signing prerequisites for a hybrid canary.

The remote query inspects the running kernel policy, sign-file availability,
MOK certificate/enrollment state, and private-key file metadata. It never reads
the private key contents and never signs, installs, loads, or replaces modules.
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
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import run_pc3_v100_guest_reference as transport  # noqa: E402

REPORT_SCHEMA = "pc3-candidate-signing-preconditions-audit-v2"
REMOTE_SCHEMA = "pc3-candidate-signing-preconditions-remote-v2"
STATE_SCHEMA = "nvidia-hybrid-canary-host-state-v2"
PREFLIGHT_SCHEMA = "nvidia-hybrid-canary-preflight-v5"
DEFAULT_SNAPSHOT = ROOT / "evidence/pc3-canary-host-state-signing-preflight-v17-20261029T0155Z.json"
DEFAULT_SNAPSHOT_SHA256 = "1e0dd74f5d57da6c7270ad048f9e3296f611765d82107a5fdac67754e7b905ab"
PREFLIGHT_REPORT = ROOT / "evidence/pc3-canary-preflight-r595-r580-provider-identity-v5-20261029T0155Z.json"
PREFLIGHT_SHA256 = "f2d759be87fb8f7afe920f9e7129021db16b6fa1feb22f1d56eafea9ddbdd5ce"
EXPECTED_MOK_CERT_SHA256 = "27a69d9988202e45bf8d5d0ae48fb1d0047545c81c3cf90e19a9c55eac021ee3"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_MODULE_BYTES = 256 * 1024 * 1024


REMOTE_SIGNING_AUDIT_SCRIPT = r'''import hashlib,json,os,re,shutil,stat,subprocess
from pathlib import Path

def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()

def read_text(path):
    return Path(path).read_text(encoding="ascii",errors="strict").strip()

def file_metadata(path, hash_file=False):
    p=Path(path)
    try:
        info=p.lstat()
    except FileNotFoundError:
        return {"present":False,"regular":False,"symlink":False,"mode":None,
                "uid":None,"gid":None,"size_bytes":None,"sha256":None}
    symlink=stat.S_ISLNK(info.st_mode)
    regular=stat.S_ISREG(info.st_mode)
    sha=None
    if hash_file and regular and not symlink:
        digest=hashlib.sha256()
        size=0
        with p.open("rb") as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b""):
                size+=len(chunk)
                if size>4*1024*1024:
                    raise RuntimeError("bounded public signing artifact exceeds size limit")
                digest.update(chunk)
        sha=digest.hexdigest()
    return {"present":True,"regular":regular,"symlink":symlink,
            "mode":stat.S_IMODE(info.st_mode),"uid":info.st_uid,"gid":info.st_gid,
            "size_bytes":info.st_size,"sha256":sha}

kernel=os.uname().release
enforce_raw=read_text("/sys/module/module/parameters/sig_enforce").upper()
if enforce_raw not in ("Y","N","1","0"):
    raise RuntimeError("kernel module-signature enforcement state is unrecognizable")
enforce=enforce_raw in ("Y","1")
lockdown_text=read_text("/sys/kernel/security/lockdown")
lockdown_matches=re.findall(r"\[([A-Za-z]+)\]",lockdown_text)
lockdown=lockdown_matches[0] if len(lockdown_matches)==1 else lockdown_text
sign_candidates=[
    Path("/lib/modules")/kernel/"build/scripts/sign-file",
    Path("/usr/src")/("linux-headers-"+kernel)/"scripts/sign-file",
]
sign_file=None
for candidate in sign_candidates:
    try:
        info=candidate.stat()
        if stat.S_ISREG(info.st_mode) and os.access(candidate,os.X_OK):
            digest=hashlib.sha256()
            size=0
            with candidate.open("rb") as stream:
                for chunk in iter(lambda:stream.read(1024*1024),b""):
                    size+=len(chunk)
                    if size>4*1024*1024:
                        raise RuntimeError("sign-file tool exceeds size limit")
                    digest.update(chunk)
            sign_file={"available":True,"path":str(candidate.resolve()),
                       "sha256":digest.hexdigest(),"executable":True}
            break
    except FileNotFoundError:
        continue
if sign_file is None:
    sign_file={"available":False,"path":None,"sha256":None,"executable":False}

cert_path="/var/lib/shim-signed/mok/MOK.der"
key_path="/var/lib/shim-signed/mok/MOK.priv"
certificate=file_metadata(cert_path,hash_file=True)
private_key=file_metadata(key_path,hash_file=False)
if certificate["present"] and certificate["regular"] and not certificate["symlink"]:
    if certificate["sha256"]!="27a69d9988202e45bf8d5d0ae48fb1d0047545c81c3cf90e19a9c55eac021ee3":
        raise RuntimeError("public module-signing certificate differs from its pinned identity")
mok_exit=127
mok_stdout=b""
mok_stderr=b""
mok_state="certificate_missing"
if certificate["present"] and certificate["regular"] and not certificate["symlink"]:
    result=subprocess.run(["mokutil","--test-key",cert_path],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False,shell=False,
        env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","LANG":"C"})
    mok_exit=result.returncode
    mok_stdout,mok_stderr=result.stdout,result.stderr
    mok_text=(mok_stdout+mok_stderr).decode("utf-8",errors="replace")
    if re.search(r"not\s+enrolled|not\s+in\s+the\s+mok\s+list|not\s+found",mok_text,re.I):
        mok_state="not_enrolled"
    elif mok_exit==0:
        mok_state="enrolled"
    else:
        mok_state="unknown"

keyring_scan={"keyctl_available":shutil.which("keyctl") is not None,
    "proc_keys_present":os.path.exists("/proc/keys"),"proc_keys_readable":False,
    "entry_count":None,"certificate_subject":None,"matching_subject_entries":None,
    "matching_entries_sha256":digest_bytes(b""),"trust_verified":False}
if certificate["present"] and certificate["regular"] and not certificate["symlink"]:
    subject_result=subprocess.run(["openssl","x509","-inform","DER","-in",cert_path,
        "-noout","-subject","-nameopt","RFC2253"],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False,shell=False,
        env={"PATH":"/usr/bin:/bin","LC_ALL":"C","LANG":"C"})
    if subject_result.returncode==0:
        subject_lines=subject_result.stdout.decode("utf-8","strict").splitlines()
        subjects=[line[len("subject="):] for line in subject_lines
                  if line.startswith("subject=")]
        if len(subjects)==1 and subjects[0]:
            keyring_scan["certificate_subject"]=subjects[0]
            try:
                with open("/proc/keys","rb") as stream:
                    key_data=stream.read(4*1024*1024+1)
                if len(key_data)>4*1024*1024:
                    raise RuntimeError("kernel key metadata exceeds its size bound")
                key_lines=key_data.decode("ascii","replace").splitlines()
                matching=[line for line in key_lines if subjects[0] in line]
                matched_text=("\n".join(matching)+("\n" if matching else "")).encode()
                keyring_scan.update({"proc_keys_readable":True,"entry_count":len(key_lines),
                    "matching_subject_entries":len(matching),
                    "matching_entries_sha256":hashlib.sha256(matched_text).hexdigest()})
            except FileNotFoundError:
                keyring_scan["proc_keys_present"]=False

report={"schema":"pc3-candidate-signing-preconditions-remote-v2",
    "host":os.uname().nodename,"kernel_release":kernel,
    "loaded_nvidia_module_version":read_text("/sys/module/nvidia/version"),
    "module_sig_enforce":enforce,"module_sig_enforce_raw":enforce_raw,
    "lockdown":lockdown,
    "sign_file":sign_file,
    "mok_certificate":{"present":certificate["present"],
        "sha256":certificate["sha256"],"mokutil_exit_code":mok_exit,
        "enrollment_state":mok_state,
        "stdout_sha256":digest_bytes(mok_stdout),"stderr_sha256":digest_bytes(mok_stderr)},
    "mok_private_key_metadata":{key:private_key[key] for key in
        ("present","regular","symlink","mode","uid","gid","size_bytes")},
    "kernel_keyring_subject_scan":keyring_scan,
    "private_key_contents_read":False,
    "network_or_system_state_changed":False}
print(json.dumps(report,sort_keys=True,separators=(",",":")))
'''


def _read_regular_nofollow(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("pinned input must be a regular file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("pinned input exceeds its size limit")
    return raw


def load_pinned_json(path: Path, expected_sha256: str) -> dict:
    if not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256):
        raise ValueError("input SHA-256 must be 64 lowercase hexadecimal characters")
    raw = _read_regular_nofollow(Path(path), MAX_JSON_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("pinned input SHA-256 mismatch")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("pinned input is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise ValueError("pinned JSON root must be an object")
    return value


def validate_kernel_keyring_scan(scan: dict) -> dict:
    fields = {"keyctl_available", "proc_keys_present", "proc_keys_readable", "entry_count",
              "certificate_subject", "matching_subject_entries", "matching_entries_sha256",
              "trust_verified"}
    if not isinstance(scan, dict) or set(scan) != fields:
        raise ValueError("kernel-keyring subject-scan shape is invalid")
    for field in ("keyctl_available", "proc_keys_present", "proc_keys_readable",
                  "trust_verified"):
        if type(scan[field]) is not bool:
            raise ValueError("kernel-keyring subject-scan flags are invalid")
    if scan["trust_verified"]:
        raise ValueError("subject metadata cannot establish kernel signature trust")
    if (not isinstance(scan["matching_entries_sha256"], str) or
            not HASH_RE.fullmatch(scan["matching_entries_sha256"])):
        raise ValueError("kernel-keyring matching-entry digest is malformed")
    if scan["proc_keys_readable"]:
        if (not scan["proc_keys_present"] or type(scan["entry_count"]) is not int or
                scan["entry_count"] < 0 or
                not isinstance(scan["certificate_subject"], str) or
                not scan["certificate_subject"].startswith("CN=") or
                type(scan["matching_subject_entries"]) is not int or
                scan["matching_subject_entries"] < 0):
            raise ValueError("readable kernel-keyring subject scan is inconsistent")
        if (scan["matching_subject_entries"] == 0 and
                scan["matching_entries_sha256"] != hashlib.sha256(b"").hexdigest()):
            raise ValueError("empty kernel-keyring match set has a nonempty digest")
    elif any(scan[field] is not None for field in
             ("entry_count", "certificate_subject", "matching_subject_entries")):
        raise ValueError("unreadable kernel-keyring subject scan has unexpected metadata")
    return dict(scan)


def validate_remote_report(remote: dict, snapshot: dict) -> dict:
    if not isinstance(remote, dict) or remote.get("schema") != REMOTE_SCHEMA:
        raise ValueError("unsupported PC3 signing-preconditions schema")
    remote_host = remote.get("host")
    snapshot_host = snapshot.get("host")
    if (not isinstance(remote_host, str) or not isinstance(snapshot_host, str) or
            remote_host.lower() != "pc3" or
            remote_host.lower() != snapshot_host.lower() or
            remote.get("kernel_release") != snapshot.get("kernel_release") or
            remote.get("loaded_nvidia_module_version") !=
            snapshot.get("loaded_nvidia_module_version")):
        raise ValueError("PC3 host, kernel, or driver identity differs from the pinned snapshot")
    if (remote.get("module_sig_enforce") is not True or
            remote.get("module_sig_enforce_raw") not in ("Y", "1")):
        raise ValueError("PC3 module-signature enforcement differs from the captured secure policy")
    lockdown = remote.get("lockdown")
    if lockdown != snapshot.get("lockdown") or lockdown not in ("integrity", "confidentiality"):
        raise ValueError("PC3 lockdown state differs from the captured secure policy")

    sign_file = remote.get("sign_file")
    if (not isinstance(sign_file, dict) or type(sign_file.get("available")) is not bool or
            type(sign_file.get("executable")) is not bool or
            sign_file["available"] is not sign_file["executable"]):
        raise ValueError("kernel sign-file metadata is malformed")
    if sign_file["available"]:
        expected_sign_file = (
            f"/usr/src/linux-headers-{snapshot['kernel_release']}/scripts/sign-file"
        )
        if sign_file.get("path") != expected_sign_file:
            raise ValueError("kernel sign-file path is outside the expected header/build trees")
        if not isinstance(sign_file.get("sha256"), str) or not HASH_RE.fullmatch(sign_file["sha256"]):
            raise ValueError("kernel sign-file digest is malformed")
    elif sign_file.get("path") is not None or sign_file.get("sha256") is not None:
        raise ValueError("unavailable sign-file tool has unexpected metadata")

    cert = remote.get("mok_certificate")
    if (not isinstance(cert, dict) or type(cert.get("present")) is not bool or
            type(cert.get("mokutil_exit_code")) is not int or
            cert["mokutil_exit_code"] not in (0, 1, 127) or
            cert.get("enrollment_state") not in
            ("enrolled", "not_enrolled", "certificate_missing")):
        raise ValueError("MOK certificate/enrollment result is malformed")
    for field in ("stdout_sha256", "stderr_sha256"):
        if not isinstance(cert.get(field), str) or not HASH_RE.fullmatch(cert[field]):
            raise ValueError("MOK enrollment output digest is malformed")
    if cert["present"]:
        if not isinstance(cert.get("sha256"), str) or not HASH_RE.fullmatch(cert["sha256"]):
            raise ValueError("MOK certificate digest is malformed")
        if cert["sha256"] != EXPECTED_MOK_CERT_SHA256:
            raise ValueError("MOK certificate differs from the pinned public-key identity")
        if cert["mokutil_exit_code"] not in (0, 1):
            raise ValueError("MOK enrollment query did not complete")
        if cert["enrollment_state"] not in ("enrolled", "not_enrolled"):
            raise ValueError("MOK enrollment query returned an unknown result")
    elif (cert.get("sha256") is not None or cert["mokutil_exit_code"] != 127 or
          cert["enrollment_state"] != "certificate_missing"):
        raise ValueError("missing MOK certificate has inconsistent query metadata")
    snapshot_mok = snapshot.get("local_module_signing_key_metadata")
    if not isinstance(snapshot_mok, dict):
        raise ValueError("pinned snapshot lacks MOK enrollment state")
    enrolled = cert["enrollment_state"] == "enrolled"
    if (cert["present"] is not snapshot_mok.get("certificate_present") or
            enrolled is not snapshot_mok.get("certificate_enrolled")):
        raise ValueError("MOK certificate or enrollment state differs from the pinned snapshot")

    key = remote.get("mok_private_key_metadata")
    required_key_fields = {"present", "regular", "symlink", "mode", "uid", "gid", "size_bytes"}
    if not isinstance(key, dict) or set(key) != required_key_fields:
        raise ValueError("MOK private-key metadata shape is invalid")
    for field in ("present", "regular", "symlink"):
        if type(key[field]) is not bool:
            raise ValueError("MOK private-key metadata flags are invalid")
    for field in ("mode", "uid", "gid", "size_bytes"):
        if key[field] is not None and (type(key[field]) is not int or key[field] < 0):
            raise ValueError("MOK private-key stat field is invalid")
    if key["present"]:
        if (key["mode"] is None or key["uid"] is None or key["gid"] is None or
                key["size_bytes"] is None):
            raise ValueError("present MOK private key lacks stat metadata")
        if key["symlink"] or key["regular"] is not True:
            raise ValueError("MOK private-key file type is unsafe or inconsistent")
    if remote.get("private_key_contents_read") is not False:
        raise ValueError("private-key contents were accessed")
    if remote.get("network_or_system_state_changed") is not False:
        raise ValueError("remote signing audit reports a system or network mutation")
    keyring_scan = validate_kernel_keyring_scan(remote.get("kernel_keyring_subject_scan"))

    key_safe = (key["present"] and key["regular"] and not key["symlink"] and
                key["mode"] is not None and key["mode"] & 0o077 == 0 and key["uid"] == 0)
    return {
        "schema": REPORT_SCHEMA,
        "status": "signing-preconditions-observed",
        "host": "pc3",
        "kernel_release": snapshot["kernel_release"],
        "loaded_nvidia_module_version": snapshot["loaded_nvidia_module_version"],
        "module_sig_enforce": True,
        "lockdown": lockdown,
        "sign_file": dict(sign_file),
        "mok_certificate": {"present": cert["present"], "sha256": cert.get("sha256"),
                            "enrolled": enrolled,
                            "mokutil_exit_code": cert["mokutil_exit_code"]},
        "mok_private_key_metadata": {**key, "permissions_restricted": bool(key_safe)},
        "kernel_keyring_subject_scan": keyring_scan,
        "signature_trust_verified": False,
        "canary_ready": False,
        "state_changes": {"pc3_contacted": True, "private_key_contents_read": False,
                          "module_signed": False, "module_installed": False,
                          "module_loaded": False, "driver_or_key_state_changed": False},
    }


def _hash_file_nofollow(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("candidate module is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > MAX_MODULE_BYTES:
                raise ValueError("candidate module exceeds size bound")
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def validate_candidate_bundle(preflight: dict, snapshot: dict) -> list[dict]:
    if (preflight.get("schema") != PREFLIGHT_SCHEMA or preflight.get("host") != "pc3" or
            preflight.get("kernel_release") != snapshot.get("kernel_release") or
            preflight.get("canary_ready") is not False):
        raise ValueError("candidate preflight is not the expected blocked PC3 bundle")
    modules = preflight.get("candidate_modules")
    if not isinstance(modules, dict) or set(modules) != {"open", "legacy", "frontend", "uvm"}:
        raise ValueError("candidate preflight module roles are incomplete")
    summaries = []
    for role in ("open", "legacy", "frontend", "uvm"):
        module = modules[role]
        if not isinstance(module, dict) or not HASH_RE.fullmatch(module.get("sha256", "")):
            raise ValueError("candidate module identity is malformed")
        path = Path(module.get("path", ""))
        if not path.is_absolute() or _hash_file_nofollow(path) != module["sha256"]:
            raise ValueError("candidate module bytes differ from the blocked preflight")
        fields = {}
        for field in ("name", "signer", "sig_key", "sig_hashalgo", "vermagic"):
            result = subprocess.run(["modinfo", "-F", field, str(path)], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=30, check=False)
            if result.returncode != 0:
                raise RuntimeError("modinfo could not inspect a candidate module")
            fields[field] = result.stdout.decode("utf-8", "strict").strip()
        if fields["name"] != module.get("name"):
            raise ValueError("candidate module name differs from the blocked preflight")
        if fields["vermagic"].split()[0] != snapshot["kernel_release"]:
            raise ValueError("candidate module vermagic differs from the captured PC3 kernel")
        if any(fields[field] != module.get(field, "") for field in ("signer", "sig_key")):
            raise ValueError("candidate module signature metadata differs from the preflight")
        summaries.append({"role": role, "name": fields["name"], "path": str(path),
                          "sha256": module["sha256"], "vermagic": fields["vermagic"],
                          "signer": fields["signer"], "sig_key": fields["sig_key"],
                          "sig_hashalgo": fields["sig_hashalgo"],
                          "unsigned": not bool(fields["signer"] or fields["sig_key"] or
                                               fields["sig_hashalgo"])})
    if not all(item["unsigned"] for item in summaries):
        raise ValueError("candidate signature state changed after the blocked preflight")
    return summaries


def _remote_command() -> str:
    return "sudo -S -p '' python3 -c " + shlex.quote(REMOTE_SIGNING_AUDIT_SCRIPT)


def collect_remote(timeout: int = 90) -> dict:
    secret = transport.fetch_pc3_sudo_secret(
        transport.DEFAULT_CREDENTIAL_HOST, transport.DEFAULT_CREDENTIAL_FILE)
    try:
        result = subprocess.run(
            transport.pc3_ssh_base(transport.DEFAULT_PC3_TARGET,
                                   transport.DEFAULT_HOST_KEY_ALIAS) + [_remote_command()],
            input=transport.sudo_auth_stdin(secret), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only PC3 signing-preconditions SSH query failed") from None
    finally:
        secret = None
    if result.returncode != 0:
        raise RuntimeError("PC3 signing-preconditions query failed; stderr sha256=" +
                           hashlib.sha256(result.stderr).hexdigest())
    if len(result.stdout) > 1024 * 1024:
        raise RuntimeError("PC3 signing-preconditions report exceeds its size limit")
    try:
        report = json.loads(result.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 signing-preconditions query returned invalid JSON") from None
    if not isinstance(report, dict):
        raise RuntimeError("PC3 signing-preconditions query returned an invalid report")
    return report


def write_report(path: Path, report: dict, evidence_root: Path | None = None) -> None:
    path = Path(path)
    root = Path(evidence_root) if evidence_root is not None else ROOT / "evidence"
    root = root.resolve(strict=True)
    try:
        path.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        raise ValueError("signing-preconditions report must be inside the evidence tree") from None
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("signing-preconditions report destination is not a regular file")
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="create a new mode-0600 evidence report; never overwrite")
    args = parser.parse_args(argv)
    try:
        snapshot = load_pinned_json(DEFAULT_SNAPSHOT, DEFAULT_SNAPSHOT_SHA256)
        if (snapshot.get("schema") != STATE_SCHEMA or snapshot.get("host") != "pc3" or
                snapshot.get("secure_boot_enabled") is not True or
                snapshot.get("module_sig_enforce") is not True):
            raise ValueError("pinned PC3 snapshot does not describe the expected secure-boot policy")
        preflight = load_pinned_json(PREFLIGHT_REPORT, PREFLIGHT_SHA256)
        candidates = validate_candidate_bundle(preflight, snapshot)
        remote = collect_remote()
        result = validate_remote_report(remote, snapshot)
        result["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
        result["candidate_modules"] = candidates
        result["candidate_modules_unsigned"] = True
        result["signature_trust_verified"] = False
        result["canary_ready"] = False
        result["inputs"] = {
            "host_snapshot": {"path": str(DEFAULT_SNAPSHOT.relative_to(ROOT)),
                              "sha256": DEFAULT_SNAPSHOT_SHA256},
            "candidate_preflight": {"path": str(PREFLIGHT_REPORT.relative_to(ROOT)),
                                    "sha256": PREFLIGHT_SHA256},
        }
        result["audit_provenance"] = {
            "local_tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "remote_script_sha256": hashlib.sha256(REMOTE_SIGNING_AUDIT_SCRIPT.encode("utf-8")).hexdigest(),
            "transport": {"target": transport.DEFAULT_PC3_TARGET,
                          "host_key_alias": transport.DEFAULT_HOST_KEY_ALIAS,
                          "sudo_value_logged": False, "sudo_value_persisted": False},
            "qualification": "read-only-signing-input-metadata",
            "pinned_public_mok_certificate_sha256": EXPECTED_MOK_CERT_SHA256,
        }
        write_report(args.output, result)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("PC3 signing-preconditions audit failed: " + str(error), file=sys.stderr)
        return 2
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"schema": REPORT_SCHEMA, "status": result["status"],
                      "canary_ready": result["canary_ready"],
                      "output": str(args.output.resolve()), "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
