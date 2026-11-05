#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline, hash-bound preflight for one R595 UVM test module.

The tool inspects a candidate module and compares it with pinned PC3 and
recovery evidence. It never contacts PC3, signs or installs a module, or changes
kernel, GPU, or boot state. Archive identity alone cannot prove operational
recovery, so this evidence schema always leaves canary readiness blocked.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
HOST_SCHEMA = "nvidia-hybrid-canary-host-state-v2"
RECOVERY_SCHEMA = "pc3-r595-recovery-archive-audit-v1"
REPORT_SCHEMA = "pc3-r595-uvm-candidate-preflight-v1"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_MODULE_BYTES = 256 * 1024 * 1024


def _read_regular_nofollow(path: Path, limit: int) -> bytes:
    path = Path(path)
    before_path = path.lstat()
    if not stat.S_ISREG(before_path.st_mode):
        raise ValueError("pinned input must be a regular non-symlink file")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("O_NOFOLLOW is required for pinned inputs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(fd)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if identity(before_path) != identity(before):
            raise ValueError("pinned input changed before read")
        if before.st_size > limit:
            raise ValueError("pinned input exceeds its size bound")
        chunks = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise ValueError("pinned input exceeds its size bound")
            chunks.append(chunk)
        after = os.fstat(fd)
        if identity(before) != identity(after) or total != after.st_size:
            raise ValueError("pinned input changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_pinned_json(path: Path, expected_sha256: str) -> tuple[dict, str]:
    if not isinstance(expected_sha256, str) or not HASH_RE.fullmatch(expected_sha256):
        raise ValueError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    raw = _read_regular_nofollow(path, MAX_JSON_BYTES)
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError("pinned input SHA-256 mismatch")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("pinned input is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise ValueError("pinned JSON root must be an object")
    return value, actual_sha256


def _stable_module_hash(path: Path) -> tuple[str, int, tuple[int, int, int, int, int]]:
    path = Path(path)
    before_path = path.lstat()
    if not stat.S_ISREG(before_path.st_mode):
        raise ValueError("candidate module must be a regular non-symlink file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(fd)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if identity(before_path) != identity(before):
            raise ValueError("candidate module changed before hashing")
        if before.st_size > MAX_MODULE_BYTES:
            raise ValueError("candidate module exceeds its size bound")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > MAX_MODULE_BYTES:
                raise ValueError("candidate module exceeds its size bound")
            digest.update(chunk)
        after = os.fstat(fd)
        if identity(before) != identity(after) or total != after.st_size:
            raise ValueError("candidate module changed while hashing")
        return digest.hexdigest(), total, identity(after)
    finally:
        os.close(fd)


def inspect_candidate(path: Path, modinfo_run=subprocess.run) -> dict:
    path = Path(path)
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError("candidate module must be a regular non-symlink file")
    resolved = path.resolve(strict=True)
    resolved_stat = resolved.stat()
    file_identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                 row.st_mtime_ns, row.st_ctime_ns)
    if file_identity(initial) != file_identity(resolved_stat):
        raise ValueError("candidate module path changed during resolution")
    path = resolved
    digest_state = hashlib.sha256()
    total = 0
    source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(source_fd)
        if file_identity(before) != file_identity(resolved_stat):
            raise ValueError("candidate module changed before snapshot")
        if before.st_size > MAX_MODULE_BYTES:
            raise ValueError("candidate module exceeds its size bound")
        with tempfile.TemporaryDirectory(prefix="r595-uvm-preflight-") as snapshot_dir:
            snapshot_path = Path(snapshot_dir) / "candidate.ko"
            snapshot_fd = os.open(snapshot_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                  os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                while chunk := os.read(source_fd, 1024 * 1024):
                    total += len(chunk)
                    if total > MAX_MODULE_BYTES:
                        raise ValueError("candidate module exceeds its size bound")
                    digest_state.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(snapshot_fd, view)
                        if written <= 0:
                            raise OSError("short write while snapshotting candidate module")
                        view = view[written:]
                after = os.fstat(source_fd)
                if file_identity(before) != file_identity(after) or total != after.st_size:
                    raise ValueError("candidate module changed while snapshotting")
                os.fsync(snapshot_fd)
            finally:
                os.close(snapshot_fd)

            digest = digest_state.hexdigest()
            fields = {}
            for field in ("name", "version", "vermagic", "depends", "signer", "sig_key", "sig_hashalgo"):
                result = modinfo_run(["modinfo", "-F", field, str(snapshot_path)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=30, check=False)
                if result.returncode != 0:
                    raise RuntimeError("modinfo could not inspect the candidate snapshot")
                try:
                    fields[field] = result.stdout.decode("utf-8", "strict").strip()
                except UnicodeDecodeError:
                    raise ValueError("modinfo returned non-UTF-8 candidate metadata") from None

            current_digest, current_size, _ = _stable_module_hash(path)
            if (current_digest, current_size) != (digest, total):
                raise ValueError("candidate module changed during modinfo inspection")
    finally:
        os.close(source_fd)
    if not fields["name"] or not fields["version"] or not fields["vermagic"]:
        raise ValueError("candidate module lacks required modinfo identity fields")
    return {"path": str(path), "sha256": digest, "size_bytes": total, **fields}


def _normalize_module_name(name: str) -> str:
    return name.replace("-", "_").lower()


def _block(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


def _gpu_process_inventory_state(host: dict) -> tuple[bool, bool, bool]:
    inventory = host.get("gpu_process_inventory")
    if inventory is None:
        return False, False, False
    required = {"schema", "observed_at_utc", "proc_scan_complete", "proc_processes_scanned",
                "proc_fd_entries_scanned", "proc_scan_incomplete_reasons",
                "device_fd_owners", "compute_query_complete", "compute_pids"}
    if not isinstance(inventory, dict) or set(inventory) != required or inventory.get("schema") != "pc3-gpu-process-inventory-v1":
        raise ValueError("PC3 GPU process inventory is malformed")
    observed_at = inventory.get("observed_at_utc")
    if (not isinstance(observed_at, str) or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", observed_at) or
            type(inventory.get("proc_scan_complete")) is not bool or
            type(inventory.get("compute_query_complete")) is not bool or
            type(inventory.get("proc_processes_scanned")) is not int or
            not 0 <= inventory["proc_processes_scanned"] <= 32768 or
            type(inventory.get("proc_fd_entries_scanned")) is not int or
            not 0 <= inventory["proc_fd_entries_scanned"] <= 250000):
        raise ValueError("PC3 GPU process inventory is malformed")
    try:
        process_started = datetime.fromisoformat(observed_at[:-1] + "+00:00")
        snapshot_text = host.get("observed_at_utc")
        if (not isinstance(snapshot_text, str) or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", snapshot_text)):
            raise ValueError("invalid host timestamp")
        snapshot_observed = datetime.fromisoformat(snapshot_text[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("PC3 GPU process inventory is malformed") from error
    pids = inventory.get("compute_pids")
    owners = inventory.get("device_fd_owners")
    if (not isinstance(pids, list) or any(type(pid) is not int or pid <= 0 for pid in pids) or
            pids != sorted(set(pids)) or not isinstance(owners, list) or len(owners) > 2048):
        raise ValueError("PC3 GPU process inventory is malformed")
    owner_pids = []
    for owner in owners:
        if not isinstance(owner, dict) or set(owner) != {"pid", "comm", "fd_count", "nodes"}:
            raise ValueError("PC3 GPU process inventory is malformed")
        pid, comm, count, nodes = owner["pid"], owner["comm"], owner["fd_count"], owner["nodes"]
        if (type(pid) is not int or pid <= 0 or not isinstance(comm, str) or len(comm) > 64 or
                type(count) is not int or not 0 < count <= 250000 or
                not isinstance(nodes, list) or not 0 < len(nodes) <= 64 or
                any(not isinstance(node, str) or not re.fullmatch(
                    r"(?:nvidia(?:[0-9]+|ctl|-(?:modeset|uvm|uvm-tools|nvlink|nvswitch|fs|caps-imex-channels)|-[A-Za-z0-9_.-]+-minor-[0-9]+)|nvidia-caps/[A-Za-z0-9_.-]+)",
                    node) for node in nodes) or nodes != sorted(set(nodes)) or count < len(nodes)):
            raise ValueError("PC3 GPU process inventory is malformed")
        owner_pids.append(pid)
    if owner_pids != sorted(set(owner_pids)):
        raise ValueError("PC3 GPU process inventory is malformed")
    reason_names = {"process-entry-limit", "process-comm-unavailable", "fd-entry-limit",
                    "total-fd-entry-limit", "fd-stat-vanished",
                    "fd-stat-permission", "fd-stat-other",
                    "gpu-device-node-limit", "process-fd-directory-unavailable",
                    "gpu-device-owner-limit", "proc-directory-unavailable",
                    "no-processes-observed"}
    reasons = inventory.get("proc_scan_incomplete_reasons")
    if (not isinstance(reasons, dict) or set(reasons) - reason_names or
            any(type(count) is not int or count <= 0 or count > 250000
                for count in reasons.values())):
        raise ValueError("PC3 GPU process inventory is malformed")
    if inventory["proc_scan_complete"] is not (inventory["proc_processes_scanned"] > 0 and not reasons):
        raise ValueError("PC3 GPU process inventory completeness evidence is inconsistent")
    complete = (inventory["proc_scan_complete"] and inventory["compute_query_complete"] and
                len(owners) <= 2048 and
                all(len(owner["nodes"]) <= 64 for owner in owners))
    active = bool(pids or owners)
    now = datetime.now(timezone.utc)
    max_age = timedelta(seconds=120)
    stale = (process_started > snapshot_observed or
             snapshot_observed - process_started > max_age or
             now - snapshot_observed > max_age or
             snapshot_observed - now > timedelta(seconds=5) or
             now - process_started > max_age or
             process_started - now > timedelta(seconds=5))
    return complete, active, stale


def evaluate_preflight(host: dict, host_snapshot_sha256: str, candidate: dict,
                       recovery: dict, recovery_sha256: str) -> dict:
    if not HASH_RE.fullmatch(str(host_snapshot_sha256)) or not HASH_RE.fullmatch(str(recovery_sha256)):
        raise ValueError("input evidence hashes are malformed")
    if (not isinstance(host, dict) or host.get("schema") != HOST_SCHEMA or
            not isinstance(host.get("host"), str) or host["host"].lower() != "pc3"):
        raise ValueError("host snapshot must identify the supported PC3 inventory")
    if not isinstance(candidate, dict):
        raise ValueError("candidate module facts are malformed")
    required_candidate = {"path", "sha256", "size_bytes", "name", "version", "vermagic",
                          "depends", "signer", "sig_key", "sig_hashalgo"}
    if set(candidate) != required_candidate:
        raise ValueError("candidate module fact fields are incomplete or unexpected")
    if (not isinstance(candidate["path"], str) or not Path(candidate["path"]).is_absolute() or
            not HASH_RE.fullmatch(str(candidate["sha256"])) or
            type(candidate["size_bytes"]) is not int or candidate["size_bytes"] <= 0):
        raise ValueError("candidate module path, hash, or size is invalid")
    for field in ("name", "version", "vermagic", "depends", "signer", "sig_key", "sig_hashalgo"):
        if not isinstance(candidate[field], str):
            raise ValueError("candidate modinfo fields must be text")
    if _normalize_module_name(candidate["name"]) != "nvidia_uvm":
        raise ValueError("candidate is not the R595 nvidia-uvm module")
    kernel = host.get("kernel_release")
    driver = host.get("loaded_nvidia_module_version")
    if not isinstance(kernel, str) or not kernel or not isinstance(driver, str) or not driver:
        raise ValueError("PC3 snapshot lacks kernel or driver identity")
    if candidate["vermagic"].split()[0] != kernel:
        raise ValueError("candidate module vermagic differs from PC3 kernel")
    if candidate["version"] != driver:
        raise ValueError("candidate module version differs from the active R595 stack")
    dependencies = {_normalize_module_name(item.strip()) for item in candidate["depends"].split(",") if item.strip()}
    if "nvidia" not in dependencies:
        raise ValueError("candidate UVM module does not depend on the active NVIDIA frontend")

    if (not isinstance(recovery, dict) or recovery.get("schema") != RECOVERY_SCHEMA or
            recovery.get("status") != "all-archives-match-signed-ubuntu-indexes"):
        raise ValueError("R595 recovery archive audit is incomplete or failed")
    if (recovery.get("archive_count") != 20 or
            recovery.get("captured_snapshot_exact_version_matches") != 20):
        raise ValueError("R595 recovery archive audit does not cover all expected packages")
    recovery_host = recovery.get("host_snapshot")
    if (not isinstance(recovery_host, dict) or recovery_host.get("host") != "pc3" or
            recovery_host.get("kernel_release") != kernel or
            recovery_host.get("loaded_nvidia_module_version") != driver or
            recovery_host.get("sha256") != host_snapshot_sha256):
        raise ValueError("recovery audit is not bound to the exact current PC3 host snapshot")
    if recovery.get("operational_recovery_proven") is not False:
        raise ValueError("archive identity cannot promote operational recovery evidence")

    blockers = []
    loaded = host.get("loaded_nvidia_modules")
    if not isinstance(loaded, list) or any(not isinstance(item, str) for item in loaded):
        raise ValueError("host snapshot loaded-module inventory is malformed")
    if "nvidia_uvm" in {_normalize_module_name(item) for item in loaded}:
        blockers.append(_block("active-uvm-module-conflict",
                               "nvidia_uvm is loaded; replacing it requires a controlled module handoff"))

    active_nodes = host.get("active_char_devices")
    if not isinstance(active_nodes, list) or any(not isinstance(item, dict) for item in active_nodes):
        raise ValueError("host snapshot character-device inventory is malformed")
    uvm_nodes = [item for item in active_nodes if item.get("path") in
                 ("/dev/nvidia-uvm", "/dev/nvidia-uvm-tools")]
    if uvm_nodes:
        blockers.append(_block("active-uvm-device-conflict",
                               "active UVM device nodes are owned by the loaded production module"))

    enforcement = host.get("module_sig_enforce")
    if type(enforcement) is not bool:
        raise ValueError("host snapshot module-signature policy is malformed")
    is_signed = bool(candidate["signer"] or candidate["sig_key"] or candidate["sig_hashalgo"])
    if enforcement and not is_signed:
        blockers.append(_block("unsigned-under-enforced-signature-policy",
                               "candidate has no module signature while signature enforcement is active"))
    if enforcement:
        key = host.get("local_module_signing_key_metadata")
        if not isinstance(key, dict):
            raise ValueError("host snapshot lacks module-signing certificate state")
        if key.get("certificate_enrolled") is not True:
            blockers.append(_block("mok-certificate-not-enrolled",
                                   "the local module-signing certificate is not enrolled in MOK"))
        blockers.append(_block("signature-trust-unverified",
                               "the captured host inventory does not prove this module signature is trusted by the running kernel"))

    recovery_inventory = host.get("driver_recovery_inventory")
    if (not isinstance(recovery_inventory, dict) or
            not isinstance(recovery_inventory.get("module_files_on_disk"), list)):
        raise ValueError("host snapshot recovery module inventory is malformed")
    recovery_files = recovery_inventory["module_files_on_disk"]
    stock_uvm = next((item for item in recovery_files if isinstance(item, dict) and
                      _normalize_module_name(str(item.get("name", ""))) == "nvidia_uvm"), None)
    if stock_uvm and stock_uvm.get("sha256") == candidate["sha256"]:
        raise ValueError("candidate hash unexpectedly matches the installed stock UVM module")

    gpu_ownership = host.get("gpu_ownership")
    if not isinstance(gpu_ownership, list):
        raise ValueError("host snapshot GPU ownership inventory is malformed")
    if any(isinstance(gpu, dict) and gpu.get("driver") == "nvidia" for gpu in gpu_ownership):
        blockers.append(_block("host-gpu-owned-by-nvidia",
                               "a host GPU is bound to NVIDIA; replacing UVM can interrupt CUDA on that GPU"))
    process_inventory = host.get("gpu_process_inventory")
    if process_inventory is None:
        blockers.append(_block("gpu-process-state-not-captured",
                               "the host snapshot does not contain a process-level GPU-use inventory"))
    else:
        process_inventory_complete, gpu_processes_active, process_inventory_stale = _gpu_process_inventory_state(host)
        if not process_inventory_complete:
            reasons = process_inventory.get("proc_scan_incomplete_reasons", {})
            reason_summary = ", ".join(f"{name}={count}" for name, count in sorted(reasons.items()))
            detail = "the /proc device-FD scan or nvidia-smi compute-process query was incomplete"
            if reason_summary:
                detail += " (" + reason_summary + ")"
            blockers.append(_block("gpu-process-inventory-incomplete",
                                   detail))
        if gpu_processes_active:
            blockers.append(_block("gpu-processes-active",
                                   "the host snapshot reports NVIDIA device FDs or active compute PIDs"))
        if process_inventory_stale:
            blockers.append(_block("gpu-process-inventory-stale",
                                   "the process scan is not bound to a fresh host snapshot within 120 seconds"))

    if recovery.get("operational_recovery_proven") is False:
        blockers.append(_block("operational-recovery-unproven",
                               "verified package archives do not prove module, boot, or service restoration"))
    blockers.sort(key=lambda item: item["code"])
    return {
        "schema": REPORT_SCHEMA,
        "status": "blocked",
        "qualification": "offline-exact-candidate-static-preflight",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": "pc3",
        "kernel_release": kernel,
        "loaded_nvidia_module_version": driver,
        "host_snapshot": {"sha256": host_snapshot_sha256,
                          "observed_at_utc": host.get("observed_at_utc")},
        "recovery_audit": {"sha256": recovery_sha256,
                           "archive_count": recovery["archive_count"],
                           "operational_recovery_proven": False},
        "candidate_module": dict(candidate),
        "blockers": blockers,
        "canary_ready": False,
        "runtime_validated": False,
        "state_changes": {"module_loaded": False, "module_installed": False,
                           "module_signed": False, "pc3_contacted": False},
    }


def write_report(path: Path, report: dict, evidence_root: Path = EVIDENCE) -> str:
    path = Path(os.path.abspath(os.fspath(path)))
    evidence_root = Path(evidence_root).resolve(strict=True)
    if path.parent != evidence_root:
        raise ValueError("output must be inside the evidence tree")
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    directory_stat = evidence_root.lstat()
    directory_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW |
                       getattr(os, "O_CLOEXEC", 0))
    directory_fd = os.open(evidence_root, directory_flags)
    fd = None
    created = False
    try:
        opened_directory = os.fstat(directory_fd)
        if ((directory_stat.st_dev, directory_stat.st_ino) !=
                (opened_directory.st_dev, opened_directory.st_ino) or
                not stat.S_ISDIR(opened_directory.st_mode)):
            raise ValueError("evidence directory changed during report creation")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=directory_fd)
        created = True
        current_directory = evidence_root.lstat()
        if ((current_directory.st_dev, current_directory.st_ino) !=
                (opened_directory.st_dev, opened_directory.st_ino) or
                not stat.S_ISDIR(current_directory.st_mode)):
            os.close(fd)
            fd = None
            os.unlink(path.name, dir_fd=directory_fd)
            created = False
            raise ValueError("evidence directory changed during report creation")
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while creating evidence report")
            view = view[written:]
        os.fsync(fd)
        final_directory = evidence_root.lstat()
        if ((final_directory.st_dev, final_directory.st_ino) !=
                (opened_directory.st_dev, opened_directory.st_ino) or
                not stat.S_ISDIR(final_directory.st_mode)):
            raise ValueError("evidence directory changed during report creation")
    except Exception:
        if fd is not None:
            os.close(fd)
            fd = None
        if created:
            try:
                os.unlink(path.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory_fd)
    return hashlib.sha256(raw).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-snapshot", type=Path, required=True)
    parser.add_argument("--host-snapshot-sha256", required=True)
    parser.add_argument("--recovery-audit", type=Path, required=True)
    parser.add_argument("--recovery-audit-sha256", required=True)
    parser.add_argument("--candidate-module", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        host, host_sha = load_pinned_json(args.host_snapshot, args.host_snapshot_sha256)
        recovery, recovery_sha = load_pinned_json(args.recovery_audit, args.recovery_audit_sha256)
        candidate = inspect_candidate(args.candidate_module)
        report = evaluate_preflight(host, host_sha, candidate, recovery, recovery_sha)
        report_sha = write_report(args.output, report)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"preflight failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "canary_ready": report["canary_ready"],
                      "blocker_count": len(report["blockers"]), "output": str(args.output),
                      "sha256": report_sha}, sort_keys=True))
    return 0 if not report["blockers"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
