#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture a guarded, shape-only CUDA IOCTL reference on PC3's RTX 5080."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import base64
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
EXPECTED_TARGET = "pc3@pc3"
EXPECTED_HOST_KEY_ALIAS = "pc3"
EXPECTED_HOST = "pc3"
EXPECTED_KERNEL = "7.0.0-38-generic"
EXPECTED_GPU_NAME_PREFIX = "NVIDIA GeForce RTX 5080"
EXPECTED_GPU_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
EXPECTED_DRIVER = "595.99.02"
EXPECTED_DRIVER_API = 13020
REMOTE_SCHEMA = "nvidia-hybrid-pc3-rtx5080-ioctl-shape-reference-v2"
REQUEST_SCHEMA = "nvidia-hybrid-pc3-rtx5080-ioctl-shape-request-v2"
PROBE_BUILD_DIR = ROOT / "build/probe-managed-accessed-by-v2-20261029T0326Z"
EXPECTED_BUILD_SOURCES = {
    "kernels/hybrid_probe.cu": "6e6effc856fc12474c09f6b8b8006497d6c30e3133353abbb3159cb80bfd4541",
    "src/hybrid_cuda_probe.cpp": "dc2f19ab2b630b24701350ec5ce0b57f24d32248dd918da87fb8790081369dc3",
}
EXPECTED_ARTIFACTS = {
    "probe": (PROBE_BUILD_DIR / "hybrid_cuda_probe",
              "38cd229ecee597b1a1f62871298dae900b5ff039b9ecca1388a72768fe880f6e", True),
    "fatbin": (PROBE_BUILD_DIR / "hybrid_probe.sm70-sm120.fatbin",
               "74cd97aabd47ab1abe720493bf54012a494472d9047b249d049300cda57e1741", False),
    "observer": (ROOT / "build/rm_ioctl_observer-event-cleanup-lineage-v3-20261027/rm_ioctl_observer",
                 "8813e7429e55ae3bca93b7bce3bb5347224b42b46e78f439cb13a951cd244a3a", True),
}
SYNC_BOOST_OBSERVER_PATH = ROOT / "build/experiments/pc3-v100-sync-boost-group-capture-v2-20261029/observer"
SYNC_BOOST_OBSERVER_SHA256 = "ece2d885cb95bef2afabd10ad06375e6c043e75685f99182408052327db85fbd"
SYNC_BOOST_OBSERVER_BYTES = 269360
ARTIFACT_LIMIT = 2 * 1024 * 1024
SSH_OPTIONS = [
    "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
    "-o", "ConnectionAttempts=1", "-o", "HostKeyAlias=" + EXPECTED_HOST_KEY_ALIAS,
]


REMOTE_SCRIPT = r'''import base64, collections, hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

EXPECTED_HOST = "pc3"
EXPECTED_KERNEL = "7.0.0-38-generic"
EXPECTED_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
EXPECTED_DRIVER = "595.99.02"
EXPECTED_API = 13020
EXPECTED_NAME_PREFIX = "NVIDIA GeForce RTX 5080"
REMOTE_SCHEMA = "nvidia-hybrid-pc3-rtx5080-ioctl-shape-reference-v2"
REQUEST_SCHEMA = "nvidia-hybrid-pc3-rtx5080-ioctl-shape-request-v2"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
EXPECTED_REQUESTS = {
    0xc038464e: (56, "control"), 0xc028465e: (40, "control"),
    0xc01046ce: (16, "gpu"), 0xc01046cf: (16, "gpu"),
}

def command(argv, timeout=20):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, check=False, shell=False, env=SAFE_ENV)
    if result.returncode:
        raise RuntimeError("read-only command failed: " + argv[0])
    return result.stdout.decode("utf-8", "strict")

def canonical_pci(value):
    m = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not m or int(m.group(3), 16) > 31:
        raise RuntimeError("invalid observed PCI identity")
    return f"{int(m.group(1),16)&0xffff:04x}:{int(m.group(2),16):02x}:{int(m.group(3),16):02x}.{int(m.group(4))}"

def nvidia_char_major():
    in_characters = False
    matches = []
    for line in Path("/proc/devices").read_text(encoding="ascii").splitlines():
        if line.strip() == "Character devices:":
            in_characters = True
            continue
        if line.strip() == "Block devices:":
            in_characters = False
        if in_characters:
            fields = line.split()
            if len(fields) == 2 and fields[1] == "nvidia" and fields[0].isdigit():
                matches.append(int(fields[0]))
    if len(matches) != 1:
        raise RuntimeError("NVIDIA character-device major missing or ambiguous")
    return matches[0]

def cdev_identity(path, expected_major, expected_minor):
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISCHR(info.st_mode) or os.major(info.st_rdev) != expected_major or
            os.minor(info.st_rdev) != expected_minor):
        raise RuntimeError("NVIDIA character-node identity mismatch")
    return {"path": path, "major": os.major(info.st_rdev), "minor": os.minor(info.st_rdev)}

def gpu_identity():
    import csv
    rows = list(csv.reader([line for line in command([
        "nvidia-smi", "-i", EXPECTED_UUID,
        "--query-gpu=name,uuid,pci.bus_id,driver_version",
        "--format=csv,noheader,nounits"]).splitlines() if line.strip()]))
    if len(rows) != 1 or len(rows[0]) != 4:
        raise RuntimeError("selected GPU query malformed")
    name, uuid, pci, driver = [field.strip() for field in rows[0]]
    candidates = [path / "information" for path in Path("/proc/driver/nvidia/gpus").iterdir()
                  if path.is_dir() and
                  re.fullmatch(r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", path.name) and
                  canonical_pci(path.name) == EXPECTED_PCI]
    if len(candidates) != 1:
        raise RuntimeError("selected GPU proc identity missing or ambiguous")
    fields = dict(line.split(":", 1) for line in candidates[0].read_text(encoding="utf-8").splitlines() if ":" in line)
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    try:
        minor = int(fields["Device Minor"], 10)
    except (KeyError, ValueError):
        raise RuntimeError("selected GPU device minor unavailable") from None
    pci_device = Path("/sys/bus/pci/devices") / EXPECTED_PCI
    if not pci_device.is_dir():
        raise RuntimeError("selected GPU sysfs PCI device is unavailable")
    pci_resolved = pci_device.resolve(strict=True)
    if canonical_pci(pci_resolved.name) != EXPECTED_PCI:
        raise RuntimeError("selected GPU sysfs PCI identity mismatch")
    binding = (pci_device / "driver").resolve(strict=True).name
    node = "/dev/nvidia" + str(minor)
    major = nvidia_char_major()
    control_stat = os.stat("/dev/nvidiactl", follow_symlinks=False)
    if (not stat.S_ISCHR(control_stat.st_mode) or os.major(control_stat.st_rdev) != major or
            os.minor(control_stat.st_rdev) != 255):
        raise RuntimeError("NVIDIA control character-node identity mismatch")
    control_node = {"path": "/dev/nvidiactl", "major": os.major(control_stat.st_rdev),
                    "minor": os.minor(control_stat.st_rdev)}
    gpu_node = cdev_identity(node, major, minor)
    gpu_node["sysfs_pci"] = EXPECTED_PCI
    gpu_node["identity_source"] = "proc-driver-gpu-information+sysfs-pci-binding"
    if (os.uname().nodename != EXPECTED_HOST or
        os.uname().release != EXPECTED_KERNEL or
        not name.startswith(EXPECTED_NAME_PREFIX) or uuid != EXPECTED_UUID or
        canonical_pci(pci) != EXPECTED_PCI or driver != EXPECTED_DRIVER or
        "RTX 5080" not in fields.get("Model", "") or fields.get("GPU UUID") != EXPECTED_UUID or
        canonical_pci(fields.get("Bus Location", "")) != EXPECTED_PCI or
        binding != "nvidia"):
        raise RuntimeError("selected GPU identity mismatch")
    return {"name": name, "uuid": uuid, "pci": EXPECTED_PCI,
            "driver_version": driver, "binding": binding,
            "minor": minor, "node": node, "gpu_node": gpu_node,
            "control_node": control_node}

def module_identity():
    version_path = Path("/sys/module/nvidia/version")
    version = version_path.read_text(encoding="ascii").strip() if version_path.is_file() else None
    module_path = command(["modinfo", "-n", "nvidia"]).strip()
    resolved = Path(module_path).resolve(strict=True)
    return {"loaded_version": version, "path": str(resolved),
            "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
            "bytes": resolved.stat().st_size}

def libcuda_identity():
    entries = []
    for line in command(["ldconfig", "-p"]).splitlines():
        if "libcuda.so.1" in line and "x86-64" in line and "=>" in line:
            entries.append(Path(line.split("=>", 1)[1].strip()))
    if len(entries) != 1:
        raise RuntimeError("libcuda resolution missing or ambiguous")
    resolved = entries[0].resolve(strict=True)
    info = resolved.stat()
    if not resolved.name.startswith("libcuda.so.") or not stat.S_ISREG(info.st_mode) or info.st_size < 1024 * 1024:
        raise RuntimeError("resolved libcuda identity invalid")
    return {"path": str(resolved), "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
            "bytes": info.st_size}

def host_snapshot():
    return {"hostname": os.uname().nodename,
            "kernel_release": os.uname().release, "gpu": gpu_identity(),
            "module": module_identity(), "libcuda": libcuda_identity()}

def compute_pids():
    output = command(["nvidia-smi", "-i", EXPECTED_UUID,
        "--query-compute-apps=pid", "--format=csv,noheader,nounits"])
    pids = []
    for line in output.splitlines():
        value = line.strip()
        if not value or value.lower().startswith("no running processes"):
            continue
        if not value.isdigit():
            raise RuntimeError("compute-process query malformed")
        pids.append(int(value))
    return sorted(set(pids))

def summarize_observation(observation, gpu_path, expected_child_exit):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    expected_scope = (
        "exact requests 0xc038464e (56 bytes) and 0xc028465e (40 bytes) on the selected "
        "control path, and 0xc01046ce/0xc01046cf (16 bytes each) on the selected GPU path; "
        "emits only nonzero and changed byte offsets; raw values and pointers omitted")
    require(isinstance(observation, dict) and
            observation.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v26",
            "IOCTL observer schema mismatch")
    require(observation.get("trace_complete") is True and observation.get("errors") == [],
            "IOCTL observer trace is incomplete")
    require(observation.get("child_exit_code") == expected_child_exit == 0,
            "IOCTL observer child exit status mismatch")
    require(observation.get("control_path") == "/dev/nvidiactl" and
            observation.get("gpu_path") == gpu_path and
            observation.get("architecture") == "x86_64" and
            observation.get("pointer_bits") == 64 and
            observation.get("nested_pointers_read") is False and
            observation.get("snapshot_consistency") ==
            "per-task syscall stop; other threads may mutate shared packet memory" and
            observation.get("fd_identity_tracking") is False and
            observation.get("payload_scope") == expected_scope and
            "nested_pointer_scope" not in observation,
            "IOCTL observer exceeded the fixed path/device/ABI boundary")
    rows = observation.get("records")
    require(isinstance(rows, list), "IOCTL observer records are missing")
    expected = {
        0xc038464e: (56, "control"), 0xc028465e: (40, "control"),
        0xc01046ce: (16, "gpu"), 0xc01046cf: (16, "gpu"),
    }
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets",
                  "entry_snapshot_passed", "exit_snapshot_passed", "entry", "exit",
                  "syscall_return"}
    counts = collections.Counter()
    event_by_thread_fd = {0xc01046ce: collections.Counter(),
                          0xc01046cf: collections.Counter()}
    checks = {}
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == row_fields,
                "IOCTL observer row contains raw or unexpected fields")
        request = row.get("request")
        require(type(request) is int and request in expected,
                "IOCTL outside the selected allowlist")
        size, role = expected[request]
        require(row.get("operation") == "selected_ioctl_payload_shape" and
                row.get("packet_size") == size and row.get("fd_role") == role,
                "IOCTL request role or packet size mismatch")
        require(type(row.get("tid")) is int and row["tid"] > 0 and
                type(row.get("fd")) is int and row["fd"] >= 0,
                "IOCTL task or descriptor metadata invalid")
        require(row.get("syscall_return") == 0,
                "selected IOCTL did not return success")
        require(row.get("entry_snapshot_passed") is True and
                row.get("exit_snapshot_passed") is True and
                row.get("entry") is None and row.get("exit") is None,
                "IOCTL payload snapshot failed or was not redacted")
        for key in ("entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets"):
            offsets = row.get(key)
            require(isinstance(offsets, list) and
                    all(type(offset) is int and 0 <= offset < size for offset in offsets) and
                    offsets == sorted(set(offsets)),
                    "IOCTL byte offset metadata is invalid")
        counts[request] += 1
        check = checks.setdefault(request, {"packet_size": size, "fd_role": role,
            "all_success": True, "all_snapshots_complete": True, "changed_record_count": 0})
        if row["changed_offsets"]:
            check["changed_record_count"] += 1
        if request in event_by_thread_fd:
            event_by_thread_fd[request][(row["tid"], row["fd"])] += 1
    alloc, free = event_by_thread_fd[0xc01046ce], event_by_thread_fd[0xc01046cf]
    required = set(expected)
    present = set(counts)
    if not rows:
        coverage = "inconclusive"
    elif present == required and alloc == free:
        coverage = "complete"
    else:
        coverage = "partial"
    return {"trace_complete": True, "trace_error_count": 0,
        "record_count": len(rows),
        "request_counts": {"0x%08x" % request: counts[request]
                           for request in sorted(counts)},
        "request_contracts": {"0x%08x" % request: checks[request]
                              for request in sorted(checks)},
        "missing_requests": ["0x%08x" % request for request in sorted(required - present)],
        "coverage_status": coverage,
        "event_lifecycle": {"balanced_by_thread_gpu_descriptor": bool(alloc) and alloc == free,
            "allocation_count": counts[0xc01046ce],
            "free_count": counts[0xc01046cf],
            "matched_descriptor_groups": len(set(alloc) & set(free))}}

def write_artifact(path, data, executable):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o700 if executable else 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)

def artifact_identity(path):
    data = Path(path).read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

def main():
    report = {"schema": REMOTE_SCHEMA, "status": "failed",
        "capture_mode": None,
        "hostname": None, "kernel_release": None, "gpu": None, "gpu_after": None,
        "module_before": None, "module_after": None, "libcuda_before": None,
        "libcuda_after": None, "gpu_compute_process_count_before": None,
        "gpu_compute_process_count_prelaunch": None,
        "gpu_compute_process_count_after": None, "artifacts_before": {},
        "artifacts_after": {}, "cuda_visible_devices": None,
        "phase": None, "probe_exit_code": None, "observer_exit_code": None,
        "ioctl_observation": None, "cleanup_passed": False,
        "remote_workspace_removed": False,
        "execution_scope": {"driver_or_module_changed": False,
            "pci_binding_changed": False, "vm_management_issued": False,
            "gpu_reset_requested": False, "imex_configuration_changed": False}}
    work = None
    before = None
    try:
        request = json.load(sys.stdin)
        if request.get("schema") != REQUEST_SCHEMA:
            raise RuntimeError("request schema invalid")
        capture_mode = request.get("capture_mode")
        if capture_mode not in ("ioctl_shapes", "event_cleanup", "sync_boost_groups"):
            raise RuntimeError("capture mode invalid")
        report["capture_mode"] = capture_mode
        artifact_items = request.get("artifacts")
        if not isinstance(artifact_items, dict) or set(artifact_items) != {"probe", "fatbin", "observer"}:
            raise RuntimeError("artifact set invalid")
        artifact_bytes = {}
        for name, item in artifact_items.items():
            raw = base64.b64decode(item.get("base64", ""), validate=True)
            if not 1 <= len(raw) <= 2 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != item.get("sha256"):
                raise RuntimeError("artifact hash or size invalid")
            if len(raw) != item.get("bytes"):
                raise RuntimeError("artifact size changed")
            artifact_bytes[name] = raw
            report["artifacts_before"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        before = host_snapshot()
        report["hostname"] = before["hostname"]
        report["kernel_release"] = before["kernel_release"]
        report["gpu"] = before["gpu"]
        report["module_before"] = before["module"]
        report["libcuda_before"] = before["libcuda"]
        if before["module"]["loaded_version"] != EXPECTED_DRIVER:
            raise RuntimeError("loaded driver version mismatch")
        pids_before = compute_pids()
        report["gpu_compute_process_count_before"] = len(pids_before)
        if pids_before:
            report["status"] = "skipped-busy"
            raise RuntimeError("selected GPU has active compute processes")
        work = Path(tempfile.mkdtemp(prefix="codex-rtx5080-ioctl-"))
        work.chmod(0o700)
        paths = {"probe": work / "hybrid_cuda_probe",
                 "fatbin": work / "hybrid_probe.sm70-sm120.fatbin",
                 "observer": work / "rm_ioctl_observer"}
        for name, path in paths.items():
            write_artifact(path, artifact_bytes[name], name in ("probe", "observer"))
        phase_name = "enumerate" if capture_mode == "sync_boost_groups" else "kernel"
        probe_argv = [str(paths["probe"]), "--phase", phase_name,
                      "--expected-pci", EXPECTED_PCI]
        if capture_mode != "sync_boost_groups":
            probe_argv.extend(["--module", str(paths["fatbin"])])
        if capture_mode == "event_cleanup":
            probe_argv.append("--close-fds-on-exit")
        report["cuda_visible_devices"] = EXPECTED_UUID
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "CUDA_VISIBLE_DEVICES": EXPECTED_UUID}
        observer_path = work / "ioctl-observation.json"
        observer_argv = [str(paths["observer"]), "--output", str(observer_path),
            "--control-path", "/dev/nvidiactl", "--timeout-seconds", "65"]
        if capture_mode == "sync_boost_groups":
            observer_argv.append("--sync-boost-groups")
        else:
            observer_argv.extend(["--gpu-path", before["gpu"]["node"]])
            observer_argv.append("--ioctl-shapes")
        if capture_mode == "event_cleanup":
            observer_argv.append("--event-cleanup")
        observer_argv.extend(["--", *probe_argv])
        prelaunch_pids = compute_pids()
        report["gpu_compute_process_count_prelaunch"] = len(prelaunch_pids)
        if prelaunch_pids:
            raise RuntimeError("selected GPU became busy before the CUDA phase")
        observed = subprocess.run(observer_argv, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=115,
            check=False, shell=False, env=env)
        report["observer_exit_code"] = observed.returncode
        report["observer_stdout_sha256"] = hashlib.sha256(observed.stdout).hexdigest()
        report["observer_stderr_sha256"] = hashlib.sha256(observed.stderr).hexdigest()
        report["observer_output_bytes"] = len(observed.stdout)
        report["observer_error_bytes"] = len(observed.stderr)
        if observed.returncode != 0 or len(observed.stdout) > 256 * 1024 or len(observed.stderr) > 64 * 1024:
            raise RuntimeError("ioctl observer execution failed")
        info = observer_path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 1024 * 1024:
            raise RuntimeError("observer output file metadata invalid")
        observation_raw = observer_path.read_bytes()
        report["observer_report_sha256"] = hashlib.sha256(observation_raw).hexdigest()
        report["observer_report_bytes"] = len(observation_raw)
        observation = json.loads(observation_raw.decode("utf-8", "strict"))
        if capture_mode in ("event_cleanup", "sync_boost_groups"):
            # The host-side runner removes transient TID/FD values before persisting evidence.
            report["ioctl_observation"] = observation
        else:
            report["ioctl_observation"] = summarize_observation(
                observation, before["gpu"]["node"], observation.get("child_exit_code"))
        report["probe_exit_code"] = observation.get("child_exit_code")
        if type(report["probe_exit_code"]) is not int:
            raise RuntimeError("observer did not preserve the child probe exit code")
        probe_raw = observed.stdout.decode("utf-8", "strict").strip()
        report["phase"] = json.loads(probe_raw)
        if report["probe_exit_code"] != 0:
            raise RuntimeError("CUDA probe did not complete successfully")
        report["phase_stdout_sha256"] = hashlib.sha256(probe_raw.encode("utf-8")).hexdigest()
        report["phase_stdout_bytes"] = len(probe_raw.encode("utf-8"))
        phase = report["phase"]
        if not isinstance(phase, dict) or phase.get("driver_library_path") != before["libcuda"]["path"]:
            raise RuntimeError("CUDA phase did not use the resolved system libcuda")
        if phase.get("status") != "phase-passed" or phase.get("phase") != phase_name:
            raise RuntimeError("CUDA phase did not pass")
        report["artifacts_after"] = {name: artifact_identity(path)
                                     for name, path in paths.items()}
        report["gpu_compute_process_count_after"] = len(compute_pids())
        after = host_snapshot()
        report["gpu_after"] = after["gpu"]
        report["module_after"] = after["module"]
        report["libcuda_after"] = after["libcuda"]
        if before != after:
            raise RuntimeError("host GPU/driver/library identity changed during reference")
        if report["gpu_compute_process_count_after"] != 0:
            raise RuntimeError("selected GPU has active compute processes after probe")
        if report["artifacts_before"] != report["artifacts_after"]:
            raise RuntimeError("staged artifacts changed during reference")
        report["cleanup_passed"] = True
        report["status"] = "complete"
    except Exception as exc:
        report["error"] = type(exc).__name__ + ":" + str(exc)[:200]
    finally:
        if before is not None and report["gpu_compute_process_count_after"] is None:
            try:
                report["gpu_compute_process_count_after"] = len(compute_pids())
            except Exception:
                report["gpu_compute_process_count_after"] = -1
        if before is not None and report["gpu_after"] is None:
            try:
                after = host_snapshot()
                report["gpu_after"] = after["gpu"]
                report["module_after"] = after["module"]
                report["libcuda_after"] = after["libcuda"]
                report["execution_scope"]["driver_or_module_changed"] = before["module"] != after["module"]
                report["execution_scope"]["pci_binding_changed"] = before["gpu"]["binding"] != after["gpu"]["binding"]
            except Exception:
                pass
        if work is not None:
            try:
                temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
                st = work.lstat()
                if (work.name.startswith("codex-rtx5080-ioctl-") and
                    work.parent.resolve(strict=True) == temp_root and
                    stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
                    st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0):
                    shutil.rmtree(work)
                    report["remote_workspace_removed"] = not work.exists()
            except Exception:
                report["remote_workspace_removed"] = False
        elif report["status"] == "skipped-busy":
            report["remote_workspace_removed"] = True
            report["cleanup_passed"] = True
    if report["status"] == "complete" and not report["remote_workspace_removed"]:
        report["status"] = "incomplete"
        report["cleanup_passed"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in ("complete", "skipped-busy") else 2

sys.exit(main())
'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_pci(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value):
        raise ValueError("invalid PCI identity")
    domain, bus, slot_function = value.lower().split(":")
    if int(slot_function[:2], 16) > 31:
        raise ValueError("invalid PCI identity")
    return f"{int(domain,16)&0xffff:04x}:{bus}:{slot_function}"


def summarize_ioctl_observation(observation: object, gpu_path: str,
                                expected_child_exit: int) -> dict[str, object]:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    expected_scope = (
        "exact requests 0xc038464e (56 bytes) and 0xc028465e (40 bytes) on the selected "
        "control path, and 0xc01046ce/0xc01046cf (16 bytes each) on the selected GPU path; "
        "emits only nonzero and changed byte offsets; raw values and pointers omitted")
    require(isinstance(observation, dict) and
            observation.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v26",
            "IOCTL observer schema mismatch")
    require(observation.get("trace_complete") is True and observation.get("errors") == [],
            "IOCTL trace is incomplete")
    require(observation.get("child_exit_code") == expected_child_exit == 0,
            "IOCTL observer child exit status mismatch")
    require(observation.get("control_path") == "/dev/nvidiactl" and
            observation.get("gpu_path") == gpu_path and
            observation.get("architecture") == "x86_64" and
            observation.get("pointer_bits") == 64 and
            observation.get("nested_pointers_read") is False and
            observation.get("fd_identity_tracking") is False and
            observation.get("payload_scope") == expected_scope and
            "nested_pointer_scope" not in observation,
            "IOCTL observer exceeded the fixed path/device/ABI boundary")
    rows = observation.get("records")
    require(isinstance(rows, list), "IOCTL observer records are missing")
    expected = {
        0xc038464e: (56, "control"), 0xc028465e: (40, "control"),
        0xc01046ce: (16, "gpu"), 0xc01046cf: (16, "gpu"),
    }


    counts: dict[int, int] = {}
    rows_by_thread_fd: dict[int, dict[tuple[int, int], int]] = {
        0xc01046ce: {}, 0xc01046cf: {}}
    checks: dict[int, dict[str, object]] = {}
    row_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                  "entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets",
                  "entry_snapshot_passed", "exit_snapshot_passed", "entry", "exit",
                  "syscall_return"}
    for row in rows:
        require(isinstance(row, dict) and set(row) == row_fields and
                row.get("operation") == "selected_ioctl_payload_shape",
                "observer row has raw or unexpected fields")
        request = row.get("request")
        require(type(request) is int and request in expected,
                "IOCTL outside the selected allowlist")
        size, role = expected[request]
        require(row.get("packet_size") == size, "IOCTL packet size mismatch")
        require(row.get("fd_role") == role, "IOCTL descriptor role mismatch")
        require(type(row.get("tid")) is int and row["tid"] > 0 and
                type(row.get("fd")) is int and row["fd"] >= 0,
                "IOCTL task or descriptor metadata invalid")
        require(row.get("syscall_return") == 0, "selected IOCTL did not return success")
        require(row.get("entry_snapshot_passed") is True and
                row.get("exit_snapshot_passed") is True and
                row.get("entry") is None and row.get("exit") is None,
                "selected IOCTL payload snapshot incomplete or not redacted")
        for key in ("entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets"):
            offsets = row.get(key)
            require(isinstance(offsets, list) and
                    all(type(offset) is int and 0 <= offset < size for offset in offsets) and
                    offsets == sorted(set(offsets)),
                    "invalid byte-offset metadata")
        counts[request] = counts.get(request, 0) + 1
        check = checks.setdefault(request, {"packet_size": size, "fd_role": role,
            "all_success": True, "all_snapshots_complete": True, "changed_record_count": 0})
        if row["changed_offsets"]:
            check["changed_record_count"] = int(check["changed_record_count"]) + 1
        if request in rows_by_thread_fd:
            key = (row["tid"], row["fd"])
            rows_by_thread_fd[request][key] = rows_by_thread_fd[request].get(key, 0) + 1
    alloc, free = rows_by_thread_fd[0xc01046ce], rows_by_thread_fd[0xc01046cf]
    required = set(expected)
    present = set(counts)
    coverage = "inconclusive" if not rows else (
        "complete" if present == required and alloc == free else "partial")
    return {
        "trace_complete": True, "trace_error_count": 0, "record_count": len(rows),
        "request_counts": {f"0x{request:08x}": counts[request] for request in sorted(counts)},
        "request_contracts": {f"0x{request:08x}": checks[request] for request in sorted(checks)},
        "missing_requests": [f"0x{request:08x}" for request in sorted(required - present)],
        "coverage_status": coverage,
        "event_lifecycle": {"balanced_by_thread_gpu_descriptor": bool(alloc) and alloc == free,
            "allocation_count": counts.get(0xc01046ce, 0),
            "free_count": counts.get(0xc01046cf, 0),
            "matched_descriptor_groups": len(set(alloc) & set(free))},
    }


def summarize_event_cleanup_observation(observation: object, gpu_path: str,
                                        expected_child_exit: int) -> dict[str, object]:
    """Validate v27 and reduce transient descriptor lineage to safe aggregates."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    scope = (
        "selected event ioctls plus a fixed 16-byte root-free equality predicate "
        "and selected descriptor lifecycle; raw payload bytes and handle values "
        "omitted; temporary TID/FD/file-identity fields require summarization before evidence persistence")
    lifecycle_scope = (
        "selected control/GPU open, dup, fcntl-dup, close, and close_range metadata; "
        "clone tasks are accepted only when kcmp confirms a shared descriptor table; "
        "paths, descriptor values, and opaque file-identity tokens are transient; "
        "io_uring and external fd injection are not tracked")
    require(isinstance(observation, dict) and
            observation.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v27",
            "event-cleanup observer schema mismatch")
    require(observation.get("trace_complete") is True and observation.get("errors") == [],
            "event-cleanup observer trace is incomplete")
    require(observation.get("child_exit_code") == expected_child_exit == 0,
            "event-cleanup observer child exit status mismatch")
    require(observation.get("control_path") == "/dev/nvidiactl" and
            observation.get("gpu_path") == gpu_path and
            observation.get("architecture") == "x86_64" and
            observation.get("pointer_bits") == 64 and
            observation.get("snapshot_consistency") ==
            "per-task syscall stop; other threads may mutate shared packet memory",
            "event-cleanup observer path, ABI, or snapshot contract mismatch")
    require(observation.get("nested_pointers_read") is False and
            "nested_pointer_scope" not in observation and
            observation.get("payload_scope") == scope and
            observation.get("fd_lifecycle_scope") == lifecycle_scope,
            "event-cleanup observer scope or lifecycle boundary changed")
    require(observation.get("fd_identity_tracking") is True,
            "event-cleanup observer did not enable descriptor identity tracking")
    require(observation.get("fd_identity_capture_complete") is True,
            "event-cleanup observer could not prove complete descriptor identity coverage")

    expected = {
        0xc038464e: (56, "control"), 0xc028465e: (40, "control"),
        0xc01046ce: (16, "gpu"), 0xc01046cf: (16, "gpu"),
    }
    shape_fields = {"tid", "fd", "fd_role", "fd_file_id", "request", "packet_size", "operation",
                    "entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets",
                    "entry_snapshot_passed", "exit_snapshot_passed", "entry", "exit",
                    "syscall_return"}
    basic_fields = {"tid", "fd", "fd_role", "request", "packet_size", "operation",
                    "entry", "exit", "syscall_return"}
    identity_fields = basic_fields | {"fd_file_id"}
    rows = observation.get("records")
    require(isinstance(rows, list), "event-cleanup observer records are missing")

    counts: dict[int, int] = {}
    checks: dict[int, dict[str, object]] = {}
    alloc: dict[int, int] = {}
    free: dict[int, int] = {}
    outstanding: dict[int, int] = {}
    active_fds: dict[int, tuple[int, str]] = {}
    descriptor_refs: dict[int, int] = {}
    file_id_roles: dict[int, str] = {}
    open_counts = {"control": 0, "gpu": 0}
    dup_counts = {"control": 0, "gpu": 0}
    close_counts = {"control": 0, "gpu": 0}
    successful_close_counts = {"control": 0, "gpu": 0}
    root_free_count = 0
    root_free_candidate_count = 0
    root_free_success_count = 0
    root_free_success_after_alloc = 0
    pending_at_gpu_close = 0
    close_range_count = 0
    close_range_pending = 0
    shape_count = 0
    event_alloc_seen = False

    def validate_offsets(row: dict[str, object], packet_size: int) -> None:
        for name in ("entry_nonzero_offsets", "exit_nonzero_offsets", "changed_offsets"):
            offsets = row.get(name)
            require(isinstance(offsets, list) and
                    all(type(offset) is int and 0 <= offset < packet_size for offset in offsets) and
                    offsets == sorted(set(offsets)),
                    "event-cleanup ioctl has invalid byte-offset metadata")

    def add_descriptor(fd: int, file_id: int, role: str) -> None:
        require(fd not in active_fds,
                "descriptor lineage was opened or duplicated over an active fd")
        require(file_id not in file_id_roles or file_id_roles[file_id] == role,
                "tracked file identity changed descriptor role")
        active_fds[fd] = (file_id, role)
        descriptor_refs[file_id] = descriptor_refs.get(file_id, 0) + 1
        file_id_roles[file_id] = role

    def remove_descriptor(fd: int, file_id: int, role: str) -> bool:
        active = active_fds.get(fd)
        require(active == (file_id, role),
                "descriptor close does not match its tracked file identity")
        del active_fds[fd]
        remaining = descriptor_refs[file_id] - 1
        if remaining:
            descriptor_refs[file_id] = remaining
            return False
        del descriptor_refs[file_id]
        return True

    def count_final_gpu_close(file_id: int, role: str, route: str) -> None:
        nonlocal pending_at_gpu_close, close_range_pending
        if role != "gpu":
            return
        pending = outstanding.get(file_id, 0)
        if route == "gpu_close":
            pending_at_gpu_close += pending
        else:
            close_range_pending += pending
        outstanding[file_id] = 0

    for index, row in enumerate(rows):
        require(isinstance(row, dict), "event-cleanup observer row is malformed")
        operation = row.get("operation")
        if operation == "selected_ioctl_payload_shape":
            require(set(row) == shape_fields,
                    "event-cleanup ioctl row contains raw or unexpected fields")
            request = row.get("request")
            require(type(request) is int and request in expected,
                    "event-cleanup ioctl uses an unapproved request")
            packet_size, role = expected[request]
            file_id = row.get("fd_file_id")
            require(row.get("packet_size") == packet_size and row.get("fd_role") == role and
                    type(row.get("tid")) is int and row["tid"] > 0 and
                    type(row.get("fd")) is int and row["fd"] >= 0 and
                    type(file_id) is int and file_id > 0 and
                    active_fds.get(row["fd"]) == (file_id, role) and
                    row.get("syscall_return") == 0 and
                    row.get("entry_snapshot_passed") is True and
                    row.get("exit_snapshot_passed") is True and
                    row.get("entry") is None and row.get("exit") is None,
                    "event-cleanup ioctl envelope, descriptor lineage, or snapshot is invalid")
            validate_offsets(row, packet_size)
            counts[request] = counts.get(request, 0) + 1
            shape_count += 1
            check = checks.setdefault(request, {"packet_size": packet_size,
                "fd_role": role, "all_success": True,
                "all_snapshots_complete": True, "changed_record_count": 0})
            if row["changed_offsets"]:
                check["changed_record_count"] = int(check["changed_record_count"]) + 1
            if request == 0xc01046ce:
                alloc[file_id] = alloc.get(file_id, 0) + 1
                outstanding[file_id] = outstanding.get(file_id, 0) + 1
                event_alloc_seen = True
            elif request == 0xc01046cf:
                free[file_id] = free.get(file_id, 0) + 1
                if outstanding.get(file_id, 0):
                    outstanding[file_id] -= 1
            continue

        if operation == "root_free_predicate":
            root_fields = shape_fields | {"root_free_candidate", "root_free_succeeded"}
            file_id = row.get("fd_file_id")
            require(set(row) == root_fields and row.get("request") == 0xc0104629 and
                    row.get("packet_size") == 16 and row.get("fd_role") == "control" and
                    type(row.get("tid")) is int and row["tid"] > 0 and
                    type(row.get("fd")) is int and row["fd"] >= 0 and
                    type(file_id) is int and file_id > 0 and
                    active_fds.get(row["fd"]) == (file_id, "control") and
                    type(row.get("root_free_candidate")) is bool and
                    type(row.get("root_free_succeeded")) is bool and
                    row.get("entry_snapshot_passed") is True and
                    row.get("exit_snapshot_passed") is True and
                    row.get("entry") is None and row.get("exit") is None,
                    "root-free predicate row is malformed or unredacted")
            validate_offsets(row, 16)
            root_free_count += 1
            root_free_candidate_count += int(row["root_free_candidate"])
            root_free_success_count += int(row["root_free_succeeded"])
            if row["root_free_succeeded"]:
                require(row["root_free_candidate"] is True and row.get("syscall_return") == 0,
                        "root-free success contradicts its candidate or syscall result")
                if event_alloc_seen:
                    root_free_success_after_alloc += 1
            continue

        require(operation in ("fd_open", "fd_dup", "fd_close_range", "close"),
                f"event-cleanup observer row {index} has an unexpected operation")
        require(type(row.get("tid")) is int and row["tid"] > 0,
                "descriptor lifecycle row has an invalid task identifier")
        if operation in ("fd_open", "fd_dup", "close"):
            require(row.get("fd_role") in ("control", "gpu") and
                    type(row.get("fd")) is int and row["fd"] >= 0,
                    "selected descriptor lifecycle row has an invalid role or descriptor")
        if operation == "fd_open":
            file_id = row.get("fd_file_id")
            require(set(row) == identity_fields and row.get("entry") is None and
                    row.get("exit") is None and type(row.get("syscall_return")) is int and
                    row["syscall_return"] >= 0 and row["syscall_return"] == row["fd"] and
                    type(file_id) is int and file_id > 0,
                    "selected open record is malformed")
            add_descriptor(row["fd"], file_id, row["fd_role"])
            open_counts[row["fd_role"]] += 1
        elif operation == "fd_dup":
            file_id = row.get("fd_file_id")
            replaced_id = row.get("replaced_fd_file_id")
            source_fd = row.get("source_fd")
            require(set(row) == identity_fields | {"source_fd", "replaced_fd_file_id"} and
                    type(source_fd) is int and source_fd >= 0 and
                    row.get("entry") is None and row.get("exit") is None and
                    type(row.get("syscall_return")) is int and row["syscall_return"] >= 0 and
                    row["syscall_return"] == row["fd"] and
                    type(file_id) is int and file_id > 0 and
                    active_fds.get(source_fd) == (file_id, row["fd_role"]) and
                    (replaced_id is None or (type(replaced_id) is int and replaced_id > 0)),
                    "selected descriptor duplicate record is malformed")
            target = active_fds.get(row["fd"])
            if row["fd"] == source_fd:
                require(target == (file_id, row["fd_role"]) and replaced_id is None,
                        "self-dup record changed its descriptor lineage")
            else:
                if target is None:
                    require(replaced_id is None,
                            "duplicate reports replacing an inactive descriptor")
                else:
                    require(replaced_id == target[0],
                            "duplicate omitted the replaced descriptor identity")
                    was_final = remove_descriptor(row["fd"], target[0], target[1])
                    if was_final:
                        count_final_gpu_close(target[0], target[1], "gpu_close")
                add_descriptor(row["fd"], file_id, row["fd_role"])
            dup_counts[row["fd_role"]] += 1
        elif operation == "close":
            file_id = row.get("fd_file_id")
            require(set(row) == identity_fields | {"close_succeeded"} and
                    row.get("entry") is None and row.get("exit") is None and
                    type(row.get("syscall_return")) is int and
                    type(row.get("close_succeeded")) is bool and
                    row["close_succeeded"] == (row["syscall_return"] == 0) and
                    type(file_id) is int and file_id > 0 and
                    active_fds.get(row["fd"]) == (file_id, row["fd_role"]),
                    "selected descriptor close record is malformed")
            role = row["fd_role"]
            close_counts[role] += 1
            if row["close_succeeded"]:
                successful_close_counts[role] += 1
                was_final = remove_descriptor(row["fd"], file_id, role)
                if was_final:
                    count_final_gpu_close(file_id, role, "gpu_close")
        else:
            range_fields = {"first_fd", "last_fd", "flags"}
            descriptors = row.get("fd_descriptors")
            require(set(row) == identity_fields | {"fd_descriptors"} and
                    row.get("fd") == -1 and row.get("fd_role") == "other" and
                    row.get("fd_file_id") is None and isinstance(descriptors, list) and
                    all(isinstance(item, dict) and set(item) == {"fd", "file_id"} and
                        type(item.get("fd")) is int and item["fd"] >= 0 and
                        type(item.get("file_id")) is int and item["file_id"] > 0
                        for item in descriptors) and
                    isinstance(row.get("entry"), dict) and
                    set(row["entry"]) == range_fields and
                    type(row["entry"]["first_fd"]) is int and
                    type(row["entry"]["last_fd"]) is int and
                    0 <= row["entry"]["first_fd"] <= row["entry"]["last_fd"] <= 0xffffffff and
                    all(row["entry"]["first_fd"] <= item["fd"] <= row["entry"]["last_fd"]
                        for item in descriptors) and
                    [item["fd"] for item in descriptors] ==
                        sorted({item["fd"] for item in descriptors}) and
                    type(row["entry"]["flags"]) is int and
                    type(row.get("syscall_return")) is int and
                    row.get("exit") is None,
                    "close_range record is malformed")
            close_range_count += 1
            if row["syscall_return"] == 0:
                require(not row["entry"]["flags"] & 4,
                        "close_range CLOEXEC cannot represent an immediate file close")
                for item in descriptors:
                    active = active_fds.get(item["fd"])
                    require(active is not None and active[0] == item["file_id"],
                            "close_range descriptor does not match its tracked identity")
                    was_final = remove_descriptor(item["fd"], item["file_id"], active[1])
                    if was_final:
                        count_final_gpu_close(item["file_id"], active[1], "close_range")

    alloc_count, free_count = sum(alloc.values()), sum(free.values())
    groups = set(alloc) | set(free)
    unmatched_alloc = sum(max(0, alloc.get(key, 0) - free.get(key, 0)) for key in groups)
    unmatched_free = sum(max(0, free.get(key, 0) - alloc.get(key, 0)) for key in groups)
    matched_groups = sum(alloc.get(key, 0) > 0 and alloc.get(key, 0) == free.get(key, 0)
                         for key in groups)
    balanced = unmatched_alloc == 0 and unmatched_free == 0
    active_gpu_file_ids = {file_id for file_id, role in active_fds.values()
                           if role == "gpu"}
    active_gpu_aliases = sum(role == "gpu" for _file_id, role in active_fds.values())
    pending_on_open_gpu_files = sum(outstanding.get(file_id, 0)
                                    for file_id in active_gpu_file_ids)
    required = set(expected)
    present = set(counts)
    coverage = "inconclusive" if not shape_count else (
        "complete" if present == required and balanced else "partial")
    return {
        "trace_complete": True,
        "trace_error_count": 0,
        "record_count": shape_count,
        "observer_record_count": len(rows),
        "request_counts": {f"0x{request:08x}": counts[request] for request in sorted(counts)},
        "request_contracts": {f"0x{request:08x}": checks[request] for request in sorted(checks)},
        "missing_requests": [f"0x{request:08x}" for request in sorted(required - present)],
        "coverage_status": coverage,
        "event_lifecycle": {
            "balanced_by_file_identity": balanced,
            "allocation_count": alloc_count, "free_count": free_count,
            "matched_file_identity_groups": matched_groups,
        },
        "event_cleanup": {
            "rm_free_ioctl_count": root_free_count,
            "root_free_candidate_count": root_free_candidate_count,
            "root_free_success_count": root_free_success_count,
            "root_free_success_after_event_alloc_count": root_free_success_after_alloc,
            "gpu_open_count": open_counts["gpu"],
            "control_open_count": open_counts["control"],
            "gpu_dup_count": dup_counts["gpu"],
            "control_dup_count": dup_counts["control"],
            "gpu_close_count": close_counts["gpu"],
            "control_close_count": close_counts["control"],
            "successful_gpu_close_count": successful_close_counts["gpu"],
            "successful_control_close_count": successful_close_counts["control"],
            "pending_event_allocations_at_gpu_close": pending_at_gpu_close,
            "close_range_count": close_range_count,
            "pending_event_allocations_at_close_range": close_range_pending,
            "gpu_aliases_without_observed_close_at_process_exit": active_gpu_aliases,
            "gpu_file_identities_without_observed_close_at_process_exit": len(active_gpu_file_ids),
            "pending_event_allocations_on_open_gpu_files_at_process_exit": pending_on_open_gpu_files,
            "fd_identity_capture_complete": True,
            "cleanup_route_candidate_observed": bool(
                root_free_success_after_alloc or pending_at_gpu_close or close_range_pending),
            "causal_attribution": "not-proven",
        },
        "hybrid_validated": False,
    }

def validate_phase_result(report: object, exit_code: int,
                          libcuda_path: str) -> dict[str, object]:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(exit_code == 0, "SM120 kernel phase did not exit successfully")
    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-cuda-driver-phase-v1" and
            report.get("status") == "phase-passed" and
            report.get("phase") == "kernel",
            "unsupported or incomplete CUDA kernel phase report")
    require(canonical_pci(report.get("expected_pci", "")) == EXPECTED_PCI,
            "CUDA kernel phase PCI guard mismatch")
    require(type(report.get("driver_api")) is int and
            report.get("driver_api") == EXPECTED_DRIVER_API,
            "CUDA Driver API version mismatch")
    require(report.get("driver_library_path") == libcuda_path and
            Path(libcuda_path).is_absolute(),
            "CUDA kernel phase resolved a different libcuda library")
    device = report.get("selected_device")
    require(isinstance(device, dict) and
            isinstance(device.get("name"), str) and
            device["name"].startswith(EXPECTED_GPU_NAME_PREFIX) and
            device.get("sm") == 120 and device.get("compute_capability") == "12.0" and
            canonical_pci(device.get("pci_bus_id", "")) == EXPECTED_PCI and
            all(type(device.get(key)) is bool for key in (
                "concurrent_managed_access", "pageable_memory_access",
                "pageable_memory_access_uses_host_page_tables")),
            "selected GPU PCI/SM120 identity mismatch")
    operations = report.get("completed_operations")
    required_operations = {
        "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
        "cuDeviceGetName", "cuDeviceGetPCIBusId", "cuDeviceGetAttribute.major",
        "cuDeviceGetAttribute.minor", "cuDeviceGetAttribute.concurrent_managed_access",
        "cuDeviceGetAttribute.pageable_memory_access",
        "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables",
        "cuCtxCreate_v2", "cuCtxSetCurrent", "cuCtxGetDevice", "cuModuleLoad",
        "cuModuleGetFunction(hybrid_arch)", "cuMemAlloc_v2",
        "cuLaunchKernel(hybrid_arch)", "cuCtxSynchronize", "cuMemcpyDtoH_v2",
    }
    require(isinstance(operations, list) and required_operations.issubset(operations),
            "required CUDA kernel operations are missing")
    require(report.get("numeric_result_passed") is True and
            type(report.get("result_value")) is int and report.get("result_value") == 1200 and
            type(report.get("expected_result")) is int and report.get("expected_result") == 1200,
            "SM120 kernel numeric result failed")
    require(report.get("cleanup_passed") is True and
            report.get("cleanup_errors") == [] and report.get("error") == "",
            "CUDA kernel phase cleanup failed")
    return {"qualification": "rtx5080-r595-kernel-phase-validated",
            "sm120_kernel_passed": True, "hybrid_validated": False,
            "phase": "kernel", "numeric_result": 1200}


def validate_enumeration_phase_result(report: object, exit_code: int,
                                      libcuda_path: str) -> dict[str, object]:
    """Validate an enumeration-only CUDA phase without implying kernel execution."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(exit_code == 0, "CUDA enumeration phase did not exit successfully")
    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-cuda-driver-phase-v1" and
            report.get("status") == "phase-passed" and
            report.get("phase") == "enumerate",
            "unsupported or incomplete CUDA enumeration phase report")
    require(canonical_pci(report.get("expected_pci", "")) == EXPECTED_PCI,
            "CUDA enumeration PCI guard mismatch")
    require(type(report.get("driver_api")) is int and
            report.get("driver_api") == EXPECTED_DRIVER_API,
            "CUDA Driver API version mismatch")
    require(report.get("driver_library_path") == libcuda_path and
            Path(libcuda_path).is_absolute(),
            "CUDA enumeration resolved a different libcuda library")
    device = report.get("selected_device")
    require(isinstance(device, dict) and
            isinstance(device.get("name"), str) and
            device["name"].startswith(EXPECTED_GPU_NAME_PREFIX) and
            device.get("sm") == 120 and device.get("compute_capability") == "12.0" and
            canonical_pci(device.get("pci_bus_id", "")) == EXPECTED_PCI and
            all(type(device.get(key)) is bool for key in (
                "concurrent_managed_access", "pageable_memory_access",
                "pageable_memory_access_uses_host_page_tables")),
            "selected GPU PCI/SM120 identity mismatch")
    required_operations = {
        "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
        "cuDeviceGetName", "cuDeviceGetPCIBusId", "cuDeviceGetAttribute.major",
        "cuDeviceGetAttribute.minor", "cuDeviceGetAttribute.concurrent_managed_access",
        "cuDeviceGetAttribute.pageable_memory_access",
        "cuDeviceGetAttribute.pageable_memory_access_uses_host_page_tables",
    }
    operations = report.get("completed_operations")
    require(isinstance(operations, list) and
            all(isinstance(operation, str) for operation in operations),
            "CUDA enumeration operation list is malformed")
    missing_operations = required_operations - set(operations)
    require(not missing_operations,
            "required CUDA enumeration operation is missing: " +
            ",".join(sorted(missing_operations)))
    require(set(operations) == required_operations and
            len(operations) == len(required_operations),
            "enumeration phase reports an unexpected CUDA operation")
    require(report.get("numeric_result_passed") is False and
            report.get("result_value") is None and report.get("expected_result") is None,
            "enumeration-only phase unexpectedly reports a numeric kernel result")
    require(report.get("cleanup_passed") is True and
            report.get("cleanup_errors") == [] and report.get("error") == "",
            "CUDA enumeration phase cleanup failed")
    return {"qualification": "rtx5080-r595-enumeration-phase-validated",
            "enumeration_passed": True, "hybrid_validated": False,
            "phase": "enumerate", "driver_api": EXPECTED_DRIVER_API}


def summarize_sync_boost_observation(observation: object,
                                     expected_child_exit: int,
                                     expected_control_path: str = "/dev/nvidiactl") -> dict[str, object]:
    """Validate observer v32 and retain only bounded root-query metadata."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    expected_scope = (
        "exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; "
        "inline GPU IDs and group payloads omitted; raw addresses and handles omitted")
    expected_nested_scope = (
        "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; "
        "inline GPU IDs and group payloads omitted")
    require(isinstance(observation, dict) and
            observation.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v32",
            "SYNC_GPU_BOOST_GROUP_INFO observer schema mismatch")
    require(observation.get("trace_complete") is True and observation.get("errors") == [],
            "SYNC_GPU_BOOST_GROUP_INFO trace is incomplete")
    require(observation.get("child_exit_code") == expected_child_exit == 0,
            "SYNC_GPU_BOOST_GROUP_INFO child exit status mismatch")
    require(observation.get("control_path") == expected_control_path and
            "gpu_path" not in observation and
            observation.get("architecture") == "x86_64" and
            observation.get("pointer_bits") == 64 and
            observation.get("snapshot_consistency") ==
            "per-task syscall stop; other threads may mutate shared packet memory" and
            observation.get("fd_identity_tracking") is False and
            observation.get("payload_scope") == expected_scope,
            "SYNC_GPU_BOOST_GROUP_INFO observer path, ABI, or payload boundary mismatch")
    rows = observation.get("records")
    require(isinstance(rows, list), "SYNC_GPU_BOOST_GROUP_INFO records are missing")
    record_fields = {"tid", "fd", "fd_role", "request", "packet_size",
                     "operation", "entry", "exit", "syscall_return"}
    header_base = {"command", "flags", "params_size", "status", "hClientPresent",
                   "hObjectPresent", "client_object_equal",
                   "client_matches_prior_root_allocation",
                   "object_matches_prior_root_allocation"}
    expected_requests = {0xc020462a: 32, 0xc01046d3: 16}
    summarized_records = []
    successful_counts = []
    success_count = 0
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == record_fields and
                row.get("operation") == "rm_control_sync_boost_groups" and
                row.get("fd_role") == "control" and
                type(row.get("tid")) is int and row["tid"] > 0 and
                type(row.get("fd")) is int and row["fd"] >= 0,
                f"SYNC_GPU_BOOST_GROUP_INFO record {index} has an invalid envelope")
        request = row.get("request")
        require(type(request) is int and request in expected_requests and
                row.get("packet_size") == expected_requests[request],
                "IOCTL outside the selected root sync-boost command allowlist")
        syscall_return = row.get("syscall_return")
        require(type(syscall_return) is int,
                "SYNC_GPU_BOOST_GROUP_INFO syscall result is malformed")
        phase_headers = {}
        for phase_name in ("entry", "exit"):
            header = row.get(phase_name)
            is_success = syscall_return == 0 and isinstance(header, dict) and \
                header.get("status") == 0
            expected_fields = header_base | ({"syncBoostGroupCount"}
                                              if phase_name == "exit" and is_success else set())
            require(isinstance(header, dict) and set(header) == expected_fields and
                    header.get("command") == 0xa04 and header.get("flags") == 0 and
                    header.get("params_size") == 2244 and
                    type(header.get("status")) is int and
                    0 <= header["status"] <= 0xffffffff and
                    all(type(header.get(key)) is bool for key in (
                        "hClientPresent", "hObjectPresent", "client_object_equal",
                        "client_matches_prior_root_allocation",
                        "object_matches_prior_root_allocation")) and
                    header.get("hClientPresent") is True and
                    header.get("hObjectPresent") is True and
                    header.get("client_object_equal") is True and
                    (not (phase_name == "exit" and is_success) or
                     (header.get("client_matches_prior_root_allocation") is True and
                      header.get("object_matches_prior_root_allocation") is True)),
                    f"SYNC_GPU_BOOST_GROUP_INFO record {index} has malformed or non-root RM data; "
                    "a failed ioctl cannot carry an output count")
            if phase_name == "exit":
                count_present = "syncBoostGroupCount" in header
                if is_success:
                    require(count_present and type(header["syncBoostGroupCount"]) is int and
                            0 <= header["syncBoostGroupCount"] <= 16,
                            "sync-boost group count exceeds fixed output capacity or is malformed")
                else:
                    require(not count_present,
                            "failed ioctl contains stale output count from an incomplete RM result")
                phase_headers[phase_name] = {
                    key: header[key] for key in ("command", "flags", "params_size", "status")}
                if count_present:
                    phase_headers[phase_name]["syncBoostGroupCount"] = header["syncBoostGroupCount"]
            else:
                phase_headers[phase_name] = {
                    key: header[key] for key in ("command", "flags", "params_size", "status")}
        if syscall_return == 0 and row["exit"]["status"] == 0:
            success_count += 1
            successful_counts.append(row["exit"]["syncBoostGroupCount"])
        summarized_records.append({"request": request,
            "packet_size": expected_requests[request], "syscall_return": syscall_return,
            "entry": phase_headers["entry"], "exit": phase_headers["exit"]})

    snapshots = observation.get("sync_boost_group_payload_snapshots_read")
    require(type(snapshots) is int and snapshots == success_count and
            observation.get("nested_pointers_read") is (success_count > 0),
            "SYNC_GPU_BOOST_GROUP_INFO snapshot count differs from successful ioctl records")
    if success_count:
        require(observation.get("nested_pointer_scope") == expected_nested_scope,
                "SYNC_GPU_BOOST_GROUP_INFO nested read exceeded its exact field scope")
    else:
        require("nested_pointer_scope" not in observation,
                "observer reports a nested pointer scope without a successful read")
    return {"trace_complete": True, "trace_error_count": 0,
            "record_count": len(rows), "successful_record_count": success_count,
            "failed_record_count": len(rows) - success_count,
            "sync_boost_groups_observed": success_count > 0,
            "sync_boost_group_payload_snapshots_read": snapshots,
            "group_counts": successful_counts, "records": summarized_records,
            "hybrid_validated": False}


def validate_gpu_node_identity(gpu: object) -> bool:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(gpu, dict), "GPU identity is malformed")
    minor = gpu.get("minor")
    require(type(minor) is int and minor >= 0 and
            gpu.get("node") == "/dev/nvidia" + str(minor),
            "GPU node minor identity mismatch")
    gpu_node, control_node = gpu.get("gpu_node"), gpu.get("control_node")
    require(isinstance(gpu_node, dict) and isinstance(control_node, dict),
            "NVIDIA character-node metadata is missing")
    major = gpu_node.get("major")
    require(type(major) is int and major > 0 and
            gpu_node.get("path") == gpu["node"] and
            type(gpu_node.get("minor")) is int and gpu_node.get("minor") == minor and
            canonical_pci(gpu_node.get("sysfs_pci", "")) == EXPECTED_PCI and
            gpu_node.get("identity_source") ==
            "proc-driver-gpu-information+sysfs-pci-binding",
            "GPU character-node major/minor or sysfs PCI identity mismatch")
    require(control_node.get("path") == "/dev/nvidiactl" and
            type(control_node.get("major")) is int and
            control_node.get("major") == major and
            type(control_node.get("minor")) is int and control_node.get("minor") == 255,
            "NVIDIA control character-node major/minor mismatch")
    return True


def validate_remote_report(report: object, capture_mode: str = "ioctl_shapes") -> dict[str, object]:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict) and report.get("schema") == REMOTE_SCHEMA,
            "remote PC3 reference report schema is invalid")
    require(capture_mode in ("ioctl_shapes", "event_cleanup", "sync_boost_groups") and
            report.get("capture_mode") == capture_mode,
            "remote capture mode does not match the requested capture mode")
    if report.get("status") == "skipped-busy":
        require(report.get("hostname") == EXPECTED_HOST and
                report.get("gpu_compute_process_count_before", 0) > 0 and
                report.get("remote_workspace_removed") is True and
                report.get("cleanup_passed") is True,
                "busy-GPU skip report is inconsistent")
        return {"qualification": "rtx5080-reference-skipped-busy",
                "sm120_kernel_passed": False, "hybrid_validated": False}
    require(report.get("status") == "complete" and
            report.get("hostname") == EXPECTED_HOST and
            report.get("kernel_release") == EXPECTED_KERNEL,
            "reference did not complete on the pinned PC3 host")
    gpu = report.get("gpu")
    require(isinstance(gpu, dict) and gpu.get("uuid") == EXPECTED_GPU_UUID and
            gpu.get("pci") == EXPECTED_PCI and gpu.get("driver_version") == EXPECTED_DRIVER and
            gpu.get("binding") == "nvidia" and gpu.get("name", "").startswith(EXPECTED_GPU_NAME_PREFIX) and
            validate_gpu_node_identity(gpu),
            "selected GPU identity mismatch")
    require(report.get("gpu_after") == gpu, "selected GPU identity changed")
    module_before, module_after = report.get("module_before"), report.get("module_after")
    require(isinstance(module_before, dict) and module_before == module_after and
            module_before.get("loaded_version") == EXPECTED_DRIVER and
            type(module_before.get("bytes")) is int and module_before["bytes"] > 0 and
            re.fullmatch(r"[0-9a-f]{64}", module_before.get("sha256", "")) and
            Path(module_before.get("path", "")).is_absolute(),
            "module identity changed or is malformed")
    lib_before, lib_after = report.get("libcuda_before"), report.get("libcuda_after")
    require(isinstance(lib_before, dict) and lib_before == lib_after and
            type(lib_before.get("bytes")) is int and lib_before["bytes"] >= 1024 * 1024 and
            re.fullmatch(r"[0-9a-f]{64}", lib_before.get("sha256", "")) and
            Path(lib_before.get("path", "")).is_absolute(),
            "libcuda identity changed or is malformed")
    require(report.get("gpu_compute_process_count_before") == 0 and
            report.get("gpu_compute_process_count_after") == 0,
            "selected GPU was busy before or after the probe")
    expected_hashes = {name: spec[1] for name, spec in EXPECTED_ARTIFACTS.items()}
    if capture_mode == "sync_boost_groups":
        expected_hashes["observer"] = SYNC_BOOST_OBSERVER_SHA256
    before_artifacts, after_artifacts = report.get("artifacts_before"), report.get("artifacts_after")
    require(isinstance(before_artifacts, dict) and before_artifacts == after_artifacts and
            set(before_artifacts) == set(expected_hashes),
            "staged artifact identity changed")
    for name, digest in expected_hashes.items():
        item = before_artifacts[name]
        require(isinstance(item, dict) and item.get("sha256") == digest and
                type(item.get("bytes")) is int and 0 < item["bytes"] <= ARTIFACT_LIMIT,
                "staged artifact hash or size mismatch")
        if capture_mode == "sync_boost_groups" and name == "observer":
            require(item["bytes"] == SYNC_BOOST_OBSERVER_BYTES,
                    "sync-boost observer size differs from its pinned build")
    require(report.get("cuda_visible_devices") == EXPECTED_GPU_UUID and
            report.get("probe_exit_code") == 0,
            "CUDA phase did not use the pinned RTX device successfully")
    if capture_mode == "sync_boost_groups":
        phase = validate_enumeration_phase_result(
            report.get("phase"), report.get("probe_exit_code"), lib_before["path"])
    else:
        phase = validate_phase_result(report.get("phase"), report.get("probe_exit_code"),
                                      lib_before["path"])
    require(report.get("observer_exit_code") == 0,
            "ioctl observer failed")
    observation = report.get("ioctl_observation")
    if capture_mode == "sync_boost_groups":
        summary_fields = {"trace_complete", "trace_error_count", "record_count",
            "successful_record_count", "failed_record_count", "sync_boost_groups_observed",
            "sync_boost_group_payload_snapshots_read", "group_counts", "records",
            "hybrid_validated"}
        require(isinstance(observation, dict) and set(observation) == summary_fields and
                observation.get("trace_complete") is True and
                observation.get("trace_error_count") == 0 and
                observation.get("hybrid_validated") is False,
                "SYNC_GPU_BOOST_GROUP_INFO summary is raw, unredacted, or malformed")
        records = observation.get("records")
        counts = observation.get("group_counts")
        record_count = observation.get("record_count")
        success_count = observation.get("successful_record_count")
        failed_count = observation.get("failed_record_count")
        snapshots = observation.get("sync_boost_group_payload_snapshots_read")
        require(isinstance(records, list) and type(record_count) is int and
                record_count == len(records) and type(success_count) is int and
                type(failed_count) is int and success_count >= 0 and failed_count >= 0 and
                success_count + failed_count == record_count and
                type(snapshots) is int and snapshots == success_count and
                isinstance(counts, list) and len(counts) == success_count and
                all(type(value) is int and 0 <= value <= 16 for value in counts) and
                observation.get("sync_boost_groups_observed") is (success_count > 0),
                "SYNC_GPU_BOOST_GROUP_INFO aggregate counts are inconsistent")
        safe_record_fields = {"request", "packet_size", "syscall_return", "entry", "exit"}
        header_fields = {"command", "flags", "params_size", "status"}
        successful_rows = 0
        for row in records:
            require(isinstance(row, dict) and set(row) == safe_record_fields and
                    row.get("request") in (0xc020462a, 0xc01046d3) and
                    row.get("packet_size") ==
                    (32 if row.get("request") == 0xc020462a else 16) and
                    type(row.get("syscall_return")) is int,
                    "SYNC_GPU_BOOST_GROUP_INFO summary contains a raw or malformed record")
            for name in ("entry", "exit"):
                header = row.get(name)
                expected_fields = header_fields | ({"syncBoostGroupCount"}
                    if name == "exit" and row["syscall_return"] == 0 and
                    isinstance(header, dict) and header.get("status") == 0 else set())
                require(isinstance(header, dict) and set(header) == expected_fields and
                        header.get("command") == 0xa04 and header.get("flags") == 0 and
                        header.get("params_size") == 2244 and
                        type(header.get("status")) is int and
                        0 <= header["status"] <= 0xffffffff,
                        "SYNC_GPU_BOOST_GROUP_INFO safe record fields are inconsistent")
            successful = row["syscall_return"] == 0 and row["exit"]["status"] == 0
            require(("syncBoostGroupCount" in row["exit"]) is successful,
                    "SYNC_GPU_BOOST_GROUP_INFO output does not match successful RM status")
            if successful:
                successful_rows += 1
                require(type(row["exit"]["syncBoostGroupCount"]) is int and
                        0 <= row["exit"]["syncBoostGroupCount"] <= 16,
                        "SYNC_GPU_BOOST_GROUP_INFO safe output count is malformed")
        require(successful_rows == success_count and
                [row["exit"]["syncBoostGroupCount"] for row in records
                 if "syncBoostGroupCount" in row["exit"]] == counts,
                "SYNC_GPU_BOOST_GROUP_INFO record counts differ from the aggregate")
        require(report.get("cleanup_passed") is True and
                report.get("remote_workspace_removed") is True and
                report.get("gpu_compute_process_count_prelaunch") == 0,
                "CUDA enumeration, observer process, or remote workspace cleanup failed")
        scope = report.get("execution_scope")
        require(isinstance(scope, dict) and all(scope.get(key) is False for key in (
            "driver_or_module_changed", "pci_binding_changed", "vm_management_issued",
            "gpu_reset_requested", "imex_configuration_changed")),
            "reference reports an out-of-scope system change")
        if record_count == 0:
            qualification = "rtx5080-r595-enumeration-no-sync-boost-query-observed"
        elif success_count:
            qualification = "rtx5080-r595-enumeration-sync-boost-query-captured"
        else:
            qualification = "rtx5080-r595-enumeration-sync-boost-query-failed"
        return {**phase, "qualification": qualification,
                "sync_boost_groups_observed": bool(success_count),
                "sync_boost_group_record_count": record_count,
                "sync_boost_group_success_count": success_count,
                "sync_boost_group_failure_count": failed_count,
                "sync_boost_group_counts": counts,
                "hybrid_validated": False}
    require(isinstance(observation, dict) and observation.get("trace_complete") is True and
            observation.get("trace_error_count") == 0 and
            type(observation.get("record_count")) is int and observation["record_count"] >= 0,
            "selected IOCTL trace is incomplete")
    counts = observation.get("request_counts")
    contracts = observation.get("request_contracts")
    require(isinstance(counts, dict) and isinstance(contracts, dict),
            "selected IOCTL summaries are malformed")
    allowlist = {"0xc038464e": (56, "control"), "0xc028465e": (40, "control"),
                 "0xc01046ce": (16, "gpu"), "0xc01046cf": (16, "gpu")}
    require(set(counts).issubset(allowlist) and set(counts) == set(contracts),
            "selected IOCTL summary has an unexpected request")
    for request, count in counts.items():
        size, role = allowlist[request]
        contract = contracts[request]
        require(type(count) is int and count > 0 and isinstance(contract, dict) and
                contract.get("packet_size") == size and contract.get("fd_role") == role and
                contract.get("all_success") is True and
                contract.get("all_snapshots_complete") is True and
                type(contract.get("changed_record_count")) is int and
                0 <= contract["changed_record_count"] <= count,
                "selected IOCTL packet contract mismatch")
    require(observation["record_count"] == sum(counts.values()),
            "selected IOCTL record count mismatch")
    if capture_mode == "event_cleanup":
        summary_fields = {"trace_complete", "trace_error_count", "record_count",
            "observer_record_count", "request_counts", "request_contracts",
            "missing_requests", "coverage_status", "event_lifecycle", "event_cleanup",
            "hybrid_validated"}
        require(set(observation) == summary_fields and
                type(observation.get("observer_record_count")) is int and
                observation["observer_record_count"] >= observation["record_count"] and
                observation.get("hybrid_validated") is False,
                "event-cleanup summary is raw, unredacted, or malformed")
    lifecycle = observation.get("event_lifecycle")
    identity_balance_key = ("balanced_by_file_identity" if capture_mode == "event_cleanup"
                            else "balanced_by_thread_gpu_descriptor")
    identity_groups_key = ("matched_file_identity_groups" if capture_mode == "event_cleanup"
                           else "matched_descriptor_groups")
    require(isinstance(lifecycle, dict) and
            lifecycle.get("allocation_count") == counts.get("0xc01046ce", 0) and
            lifecycle.get("free_count") == counts.get("0xc01046cf", 0) and
            type(lifecycle.get(identity_balance_key)) is bool and
            type(lifecycle.get(identity_groups_key)) is int and
            lifecycle[identity_groups_key] >= 0,
            "event lifecycle summary is malformed")
    required = set(allowlist)
    expected_coverage = ("inconclusive" if observation["record_count"] == 0 else
                         "complete" if set(counts) == required and
                         lifecycle[identity_balance_key] else "partial")
    require(observation.get("missing_requests") == sorted(required - set(counts)) and
            observation.get("coverage_status") == expected_coverage,
            "IOCTL coverage classification is inconsistent")
    event_cleanup = None
    if capture_mode == "event_cleanup":
        event_cleanup = observation.get("event_cleanup")
        event_fields = {"rm_free_ioctl_count", "root_free_candidate_count",
            "root_free_success_count", "root_free_success_after_event_alloc_count",
            "gpu_open_count", "control_open_count", "gpu_dup_count", "control_dup_count",
            "gpu_close_count", "control_close_count", "successful_gpu_close_count",
            "successful_control_close_count", "pending_event_allocations_at_gpu_close",
            "close_range_count", "pending_event_allocations_at_close_range",
            "gpu_aliases_without_observed_close_at_process_exit",
            "gpu_file_identities_without_observed_close_at_process_exit",
            "pending_event_allocations_on_open_gpu_files_at_process_exit",
            "fd_identity_capture_complete", "cleanup_route_candidate_observed",
            "causal_attribution"}
        require(isinstance(event_cleanup, dict) and set(event_cleanup) == event_fields,
                "event-cleanup summary contains raw or unexpected fields")
        count_fields = event_fields - {"fd_identity_capture_complete",
            "cleanup_route_candidate_observed", "causal_attribution"}
        require(all(type(event_cleanup.get(key)) is int and event_cleanup[key] >= 0
                    for key in count_fields),
                "event-cleanup aggregate count is malformed")
        require(event_cleanup.get("fd_identity_capture_complete") is True and
                event_cleanup.get("causal_attribution") == "not-proven" and
                type(event_cleanup.get("cleanup_route_candidate_observed")) is bool and
                event_cleanup["root_free_success_count"] <=
                    event_cleanup["root_free_candidate_count"] <=
                    event_cleanup["rm_free_ioctl_count"] and
                event_cleanup["root_free_success_after_event_alloc_count"] <=
                    event_cleanup["root_free_success_count"] and
                event_cleanup["successful_gpu_close_count"] <= event_cleanup["gpu_close_count"] and
                event_cleanup["successful_control_close_count"] <= event_cleanup["control_close_count"] and
                event_cleanup["gpu_file_identities_without_observed_close_at_process_exit"] <=
                    event_cleanup["gpu_aliases_without_observed_close_at_process_exit"] and
                event_cleanup["cleanup_route_candidate_observed"] == bool(
                    event_cleanup["root_free_success_after_event_alloc_count"] or
                    event_cleanup["pending_event_allocations_at_gpu_close"] or
                    event_cleanup["pending_event_allocations_at_close_range"]),
                "event-cleanup aggregate semantics are inconsistent")
    require(report.get("cleanup_passed") is True and
            report.get("remote_workspace_removed") is True,
            "remote process or workspace cleanup failed")
    require(report.get("gpu_compute_process_count_prelaunch") == 0,
            "selected GPU was busy immediately before the probe")
    scope = report.get("execution_scope")
    require(isinstance(scope, dict) and all(scope.get(key) is False for key in (
        "driver_or_module_changed", "pci_binding_changed", "vm_management_issued",
        "gpu_reset_requested", "imex_configuration_changed")),
        "reference reports an out-of-scope system change")
    if capture_mode == "event_cleanup":
        qualification = ("rtx5080-r595-kernel-phase-validated-event-cleanup-captured"
                         if observation["coverage_status"] == "complete" else
                         "rtx5080-r595-kernel-phase-validated-event-cleanup-partial")
    else:
        qualification = ("rtx5080-r595-ioctl-kernel-phase-validated"
                         if observation["coverage_status"] == "complete" else
                         "rtx5080-r595-kernel-phase-validated-ioctl-coverage-partial")
    result = {**phase, "qualification": qualification,
            "request_counts": counts, "ioctl_coverage": observation["coverage_status"],
            "event_lifecycle": lifecycle, "hybrid_validated": False}
    if event_cleanup is not None:
        result["event_cleanup"] = event_cleanup
    return result


def artifact_payload(name: str, data: bytes,
                     expected_hash: str | None = None) -> dict[str, object]:
    if name not in EXPECTED_ARTIFACTS:
        raise ValueError("unexpected artifact name")
    if not data or len(data) > ARTIFACT_LIMIT:
        raise ValueError("artifact size outside bound")
    digest = sha256_bytes(data)
    pinned_hash = expected_hash or EXPECTED_ARTIFACTS[name][1]
    if digest != pinned_hash:
        raise ValueError("artifact hash differs from the pinned reference")
    return {"base64": base64.b64encode(data).decode("ascii"),
            "sha256": digest, "bytes": len(data)}


def validate_probe_build(probe_path: Path) -> dict[str, object]:
    from tools.cuda_probe_contract import validate_probe_contract

    manifest_path = PROBE_BUILD_DIR / "build-manifest.json"
    if probe_path.resolve(strict=True) != EXPECTED_ARTIFACTS["probe"][0].resolve():
        raise ValueError("probe path is not the current pinned build artifact")
    fatbin_path = EXPECTED_ARTIFACTS["fatbin"][0].resolve(strict=True)
    manifest_data = manifest_path.read_bytes()
    manifest = json.loads(manifest_data.decode("utf-8", "strict"))
    if manifest.get("schema") != "nvidia-hybrid-probe-build-v2" or \
            manifest.get("status") != "built-static-images":
        raise ValueError("probe build manifest schema or status mismatch")
    expected_sources = {str((ROOT / relative).resolve()): digest
                         for relative, digest in EXPECTED_BUILD_SOURCES.items()}
    if manifest.get("source_inputs_sha256") != expected_sources:
        raise ValueError("pinned probe build manifest has unexpected historical source inputs")
    if (manifest.get("probe", {}).get("path") != str(probe_path.resolve()) or
            manifest.get("probe", {}).get("sha256") != EXPECTED_ARTIFACTS["probe"][1] or
            manifest.get("fatbin", {}).get("path") != str(fatbin_path) or
            manifest.get("fatbin", {}).get("sha256") != EXPECTED_ARTIFACTS["fatbin"][1] or
            manifest.get("fatbin_images") != ["sm_70", "sm_120"] or
            manifest.get("probe_links_libcuda") is not False or
            sha256_bytes(probe_path.read_bytes()) != EXPECTED_ARTIFACTS["probe"][1] or
            sha256_bytes(fatbin_path.read_bytes()) != EXPECTED_ARTIFACTS["fatbin"][1]):
        raise ValueError("probe/fatbin build manifest does not match the pinned artifacts")
    contract = validate_probe_contract(probe_path, EXPECTED_ARTIFACTS["probe"][1])
    return {**contract,
            "build_manifest_path": str(manifest_path.resolve()),
            "build_manifest_sha256": sha256_bytes(manifest_data),
            "source_inputs_sha256": expected_sources,
            "fatbin_sha256": EXPECTED_ARTIFACTS["fatbin"][1]}


def run(argv: list[str] | None = None, invoke=subprocess.run) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, default=EXPECTED_ARTIFACTS["probe"][0])
    parser.add_argument("--module", "--fatbin", dest="fatbin", type=Path,
                        default=EXPECTED_ARTIFACTS["fatbin"][0])
    parser.add_argument("--ioctl-observer", type=Path, default=EXPECTED_ARTIFACTS["observer"][0])
    parser.add_argument("--sync-boost-observer", type=Path, default=SYNC_BOOST_OBSERVER_PATH)
    parser.add_argument("--event-cleanup", action="store_true",
                        help="capture redacted RM event cleanup and descriptor lifecycle")
    parser.add_argument("--sync-boost-groups", action="store_true",
                        help="capture only the root sync-boost groupCount during CUDA enumeration")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    if args.event_cleanup and args.sync_boost_groups:
        parser.error("--event-cleanup and --sync-boost-groups are mutually exclusive")
    capture_mode = ("sync_boost_groups" if args.sync_boost_groups else
                    "event_cleanup" if args.event_cleanup else "ioctl_shapes")
    observer_path = (args.sync_boost_observer if args.sync_boost_groups
                     else args.ioctl_observer)
    selected_observer_hash = (SYNC_BOOST_OBSERVER_SHA256 if args.sync_boost_groups
                              else EXPECTED_ARTIFACTS["observer"][1])
    selected_observer_bytes = (SYNC_BOOST_OBSERVER_BYTES if args.sync_boost_groups
                               else None)
    paths = {"probe": args.probe, "fatbin": args.fatbin, "observer": observer_path}
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-rtx5080-ioctl-shape-runner-v2",
        "capture_mode": capture_mode,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": EXPECTED_TARGET, "host_key_alias": EXPECTED_HOST_KEY_ALIAS,
        "expected_gpu_uuid": EXPECTED_GPU_UUID, "expected_pci": EXPECTED_PCI,
        "expected_driver": EXPECTED_DRIVER, "expected_kernel": EXPECTED_KERNEL,
        "local_artifacts": {}, "local_artifacts_after": {}, "exit_code": 2,
        "qualification": "failed"}
    try:
        build = validate_probe_build(args.probe.resolve(strict=True))
        report["probe_contract"] = build
        payload_artifacts = {}
        for name, path in paths.items():
            resolved = path.resolve(strict=True)
            executable = (name != "fatbin")
            if not resolved.is_file() or (executable and not os.access(resolved, os.X_OK)):
                raise ValueError("artifact must be the pinned regular file with required execute permission")
            data = resolved.read_bytes()
            encoded = artifact_payload(name, data,
                selected_observer_hash if name == "observer" else None)
            if name == "observer" and selected_observer_bytes is not None and \
                    encoded["bytes"] != selected_observer_bytes:
                raise ValueError("sync-boost observer size differs from its pinned build")
            payload_artifacts[name] = encoded
            report["local_artifacts"][name] = {"path": str(resolved),
                "sha256": encoded["sha256"], "bytes": encoded["bytes"]}
        request = {"schema": REQUEST_SCHEMA, "capture_mode": capture_mode,
                   "artifacts": payload_artifacts}
        remote_command = SSH_OPTIONS + ["--", EXPECTED_TARGET,
            "python3 -c " + shlex.quote(REMOTE_SCRIPT)]
        report["remote_script_sha256"] = sha256_bytes(REMOTE_SCRIPT.encode("utf-8"))
        result = invoke(remote_command, input=json.dumps(request), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
            check=False, shell=False)
        report["ssh_exit_code"] = result.returncode
        report["ssh_stdout_sha256"] = sha256_bytes(result.stdout.encode("utf-8", "replace"))
        report["ssh_stdout_bytes"] = len(result.stdout.encode("utf-8", "replace"))
        report["ssh_stderr_sha256"] = sha256_bytes(result.stderr.encode("utf-8", "replace"))
        report["ssh_stderr_bytes"] = len(result.stderr.encode("utf-8", "replace"))
        if len(result.stdout.encode("utf-8", "replace")) > 512 * 1024:
            raise ValueError("remote response exceeds size limit")
        try:
            remote = json.loads(result.stdout.strip())
        except (json.JSONDecodeError, TypeError):
            raise ValueError("remote worker did not return one JSON object") from None
        if capture_mode in ("event_cleanup", "sync_boost_groups") and \
                remote.get("ioctl_observation") is not None:
            gpu = remote.get("gpu")
            gpu_path = gpu.get("node") if isinstance(gpu, dict) else None
            if capture_mode == "event_cleanup":
                remote["ioctl_observation"] = summarize_event_cleanup_observation(
                    remote["ioctl_observation"], gpu_path, remote.get("probe_exit_code"))
            else:
                remote["ioctl_observation"] = summarize_sync_boost_observation(
                    remote["ioctl_observation"], remote.get("probe_exit_code"))
        report["remote"] = remote
        qualification = validate_remote_report(remote, capture_mode=capture_mode)
        report["remote_qualification"] = qualification
        if result.returncode != 0:
            raise ValueError("remote worker returned nonzero")
        if qualification["qualification"] == "rtx5080-reference-skipped-busy":
            report["qualification"] = qualification["qualification"]
            report["exit_code"] = 77
        else:
            report["qualification"] = qualification["qualification"]
            report["exit_code"] = 0
    except Exception as exc:
        report["error"] = type(exc).__name__ + ":" + str(exc)[:250]
    finally:
        for name, path in paths.items():
            try:
                data = path.read_bytes()
                report["local_artifacts_after"][name] = {
                    "sha256": sha256_bytes(data), "bytes": len(data)}
            except OSError:
                report["local_artifacts_after"][name] = None
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(args.evidence, flags, 0o600)
        except FileExistsError:
            raise
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps({"evidence": str(args.evidence),
        "exit_code": report["exit_code"], "qualification": report["qualification"]}, sort_keys=True))
    return int(report["exit_code"])


if __name__ == "__main__":
    sys.exit(run())
