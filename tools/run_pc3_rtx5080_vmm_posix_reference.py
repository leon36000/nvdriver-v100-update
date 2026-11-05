#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run an isolated, hash-pinned VMM POSIX-FD reference on PC3's RTX 5080.

The remote worker uses strict SSH host-key checking, exposes only the selected
GPU to short-lived CUDA processes, and makes no driver, PCI, VM, or IMEX changes.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PROBE_SOURCE = ROOT / "src/system_features_vmm_fabric_probe.py"
PROBE_SOURCE_SHA256 = "b7a903bf0dcad5f925ddc04fa1108b22b980a2a023c2998678ceb30e38be58a3"
PROBE_SOURCE_LIMIT = 64 * 1024
EXPECTED_TARGET = "pc3@pc3"
EXPECTED_HOST_KEY_ALIAS = "pc3"
EXPECTED_HOST = "pc3"
EXPECTED_GPU_NAME_PREFIX = "NVIDIA GeForce RTX 5080"
EXPECTED_GPU_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
EXPECTED_DRIVER = "595.99.02"
EXPECTED_DRIVER_API = 13020
SSH_OPTIONS = [
    "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
    "-o", "ConnectionAttempts=1", "-o", "HostKeyAlias=" + EXPECTED_HOST_KEY_ALIAS,
]


REMOTE_SCRIPT = r'''import base64, csv, hashlib, json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

EXPECTED_HOST = "pc3"
EXPECTED_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
EXPECTED_DRIVER = "595.99.02"
EXPECTED_API = "13020"
EXPECTED_NAME_PREFIX = "NVIDIA GeForce RTX 5080"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

def command(argv, timeout=20, env=None):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False,
                            shell=False, env=SAFE_ENV if env is None else env)
    if result.returncode:
        raise RuntimeError("read-only command failed: " + argv[0])
    return result.stdout.decode("utf-8", "strict")

def canonical_pci(value):
    import re
    match = re.fullmatch(r"([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])", value)
    if not match or int(match.group(3), 16) > 31:
        raise RuntimeError("invalid observed PCI identity")
    return f"{int(match.group(1),16)&0xffff:04x}:{int(match.group(2),16):02x}:{int(match.group(3),16):02x}.{int(match.group(4))}"

def compute_pids():
    output = command(["nvidia-smi", "-i", EXPECTED_UUID,
                      "--query-compute-apps=pid", "--format=csv,noheader,nounits"])
    pids = []
    for line in output.splitlines():
        value = line.strip()
        if not value or value.lower().startswith("no running processes"):
            continue
        if not value.isdigit():
            raise RuntimeError("compute_process_query_unrecognized")
        pids.append(int(value))
    return sorted(set(pids))

def module_identity():
    version_path = Path("/sys/module/nvidia/version")
    version = version_path.read_text(encoding="ascii").strip() if version_path.is_file() else None
    module_path = command(["modinfo", "-n", "nvidia"]).strip()
    resolved = Path(module_path).resolve(strict=True)
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return {"loaded_version": version, "path": str(resolved), "sha256": digest}

def libcuda_identity():
    entries = []
    for line in command(["ldconfig", "-p"]).splitlines():
        if "libcuda.so.1" in line and "x86-64" in line and "=>" in line:
            entries.append(Path(line.split("=>", 1)[1].strip()))
    if len(entries) != 1:
        raise RuntimeError("libcuda_so_1_resolution_missing_or_ambiguous")
    resolved = entries[0].resolve(strict=True)
    info = resolved.stat()
    if not resolved.name.startswith("libcuda.so.") or not stat.S_ISREG(info.st_mode) or info.st_size < 1024 * 1024:
        raise RuntimeError("resolved_libcuda_identity_invalid")
    return {"path": str(resolved), "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
            "bytes": info.st_size}

def gpu_identity():
    rows = list(csv.reader([line for line in command([
        "nvidia-smi", "-i", EXPECTED_UUID,
        "--query-gpu=name,uuid,pci.bus_id,driver_version",
        "--format=csv,noheader,nounits"]).splitlines() if line.strip()]))
    if len(rows) != 1 or len(rows[0]) != 4:
        raise RuntimeError("selected_gpu_query_malformed")
    name, uuid, pci, driver = [field.strip() for field in rows[0]]
    candidates = [Path("/proc/driver/nvidia/gpus") / item / "information"
                  for item in (EXPECTED_PCI, "0000" + EXPECTED_PCI)]
    candidates = [path for path in candidates if path.is_file()]
    if len(candidates) != 1:
        raise RuntimeError("selected_gpu_proc_identity_missing_or_ambiguous")
    fields = dict(line.split(":", 1) for line in candidates[0].read_text().splitlines() if ":" in line)
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    binding = (Path("/sys/bus/pci/devices") / EXPECTED_PCI / "driver").resolve(strict=True).name
    if (not name.startswith(EXPECTED_NAME_PREFIX) or uuid != EXPECTED_UUID or
            canonical_pci(pci) != EXPECTED_PCI or driver != EXPECTED_DRIVER or
            "RTX 5080" not in fields.get("Model", "") or fields.get("GPU UUID") != EXPECTED_UUID or
            binding != "nvidia"):
        raise RuntimeError("selected_gpu_identity_mismatch")
    return {"name": name, "uuid": uuid, "pci": EXPECTED_PCI,
            "driver_version": driver, "binding": binding}

def host_snapshot():
    return {"hostname": os.uname().nodename.split(".")[0],
            "kernel_release": os.uname().release,
            "gpu": gpu_identity(), "module": module_identity(),
            "libcuda": libcuda_identity()}

def write_private(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short_write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)

def main():
    payload = json.load(sys.stdin)
    report = {"schema": "nvidia-hybrid-pc3-rtx5080-vmm-posix-reference-v1",
              "status": "failed", "hostname": None, "kernel_release": None,
              "gpu": None, "gpu_after": None, "module_before": None, "module_after": None,
              "libcuda": None, "gpu_compute_processes_before": None,
              "gpu_compute_processes_after": None, "probe": None,
              "probe_source_sha256": None, "probe_source_bytes": None,
              "cuda_visible_devices": None,
              "probe_exit_code": None, "probe_stdout_sha256": None,
              "probe_stdout_bytes": None, "probe_stderr_sha256": None,
              "probe_stderr_bytes": None, "cleanup_passed": False,
              "remote_workspace_removed": False,
              "execution_scope": {"driver_or_module_changed": False,
                  "pci_binding_changed": False, "vm_management_issued": False,
                  "gpu_reset_requested": False, "imex_configuration_changed": False}}
    work = None
    try:
        if payload.get("schema") != "nvidia-hybrid-pc3-rtx5080-vmm-posix-request-v1":
            raise RuntimeError("request_schema_invalid")
        raw = base64.b64decode(payload.get("probe_base64", ""), validate=True)
        if (not 1 <= len(raw) <= 64 * 1024 or
                hashlib.sha256(raw).hexdigest() != payload.get("probe_sha256")):
            raise RuntimeError("probe_artifact_hash_or_size_invalid")
        report["probe_source_sha256"] = hashlib.sha256(raw).hexdigest()
        report["probe_source_bytes"] = len(raw)
        report["hostname"] = os.uname().nodename.split(".")[0]
        report["kernel_release"] = os.uname().release
        if report["hostname"] != EXPECTED_HOST:
            raise RuntimeError("unexpected_pc3_host")
        before = host_snapshot()
        if before["module"]["loaded_version"] != EXPECTED_DRIVER:
            raise RuntimeError("loaded_driver_version_mismatch")
        if report["hostname"] != EXPECTED_HOST:
            raise RuntimeError("unexpected_host")
        report["gpu"] = before["gpu"]
        report["module_before"] = before["module"]
        report["libcuda"] = before["libcuda"]
        report["gpu_compute_processes_before"] = compute_pids()
        if report["gpu_compute_processes_before"]:
            raise RuntimeError("selected_gpu_compute_process_active")
        work = Path(tempfile.mkdtemp(prefix="hybrid-rtx5080-vmm-posix-"))
        work.chmod(0o700)
        probe_path = work / "vmm_posix_probe.py"
        write_private(probe_path, raw)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("LD_", "CUDA_", "NVIDIA_", "PYTHON"))}
        env.update({"PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "CUDA_VISIBLE_DEVICES": EXPECTED_UUID,
            "NVIDIA_HYBRID_VMM_SHARE_KIND": "posix_fd",
            "NVIDIA_HYBRID_VMM_EXPECTED_PCI": EXPECTED_PCI,
            "NVIDIA_HYBRID_VMM_EXPECTED_DEVICE_NAME_PREFIX": EXPECTED_NAME_PREFIX,
            "NVIDIA_HYBRID_VMM_EXPECTED_SM": "120",
            "NVIDIA_HYBRID_VMM_EXPECTED_DRIVER_API": EXPECTED_API,
            "NVIDIA_HYBRID_VMM_LIBCUDA_PATH": before["libcuda"]["path"],
            "NVIDIA_HYBRID_VMM_CHILD_SOURCE_B64": base64.b64encode(raw).decode("ascii"),
            "NVIDIA_HYBRID_VMM_CHILD_SOURCE_B64_SHA256": hashlib.sha256(raw).hexdigest()})
        report["cuda_visible_devices"] = env["CUDA_VISIBLE_DEVICES"]
        result = subprocess.run([sys.executable, str(probe_path)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False,
            shell=False, env=env)
        report["probe_exit_code"] = result.returncode
        report["probe_stdout_bytes"] = len(result.stdout)
        report["probe_stdout_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        report["probe_stderr_bytes"] = len(result.stderr)
        report["probe_stderr_sha256"] = hashlib.sha256(result.stderr).hexdigest()
        if len(result.stdout) > 256 * 1024 or len(result.stderr) > 64 * 1024:
            raise RuntimeError("probe_output_limit_exceeded")
        try:
            report["probe"] = json.loads(result.stdout.decode("utf-8", "strict").strip())
        except Exception as exc:
            raise RuntimeError("probe_json_invalid") from exc
        report["gpu_compute_processes_after"] = compute_pids()
        after = host_snapshot()
        report["gpu_after"] = after["gpu"]
        report["module_after"] = after["module"]
        report["execution_scope"]["driver_or_module_changed"] = before["module"] != after["module"]
        report["execution_scope"]["pci_binding_changed"] = before["gpu"]["binding"] != after["gpu"]["binding"]
        unchanged = (before == after and not report["execution_scope"]["driver_or_module_changed"] and
                     not report["execution_scope"]["pci_binding_changed"] and
                     report["gpu_compute_processes_after"] == [])
        report["cleanup_passed"] = unchanged and result.returncode in (0, 2)
        report["status"] = "complete" if report["cleanup_passed"] else "incomplete"
    except Exception as exc:
        report["error"] = type(exc).__name__ + ":" + str(exc)[:200]
    finally:
        if work is not None:
            try:
                temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
                st = work.lstat()
                if (work.name.startswith("hybrid-rtx5080-vmm-posix-") and
                        work.parent.resolve(strict=True) == temp_root and
                        stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
                        st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0):
                    shutil.rmtree(work)
                    report["remote_workspace_removed"] = not work.exists()
            except Exception:
                report["remote_workspace_removed"] = False
        if report["status"] == "complete" and report["remote_workspace_removed"]:
            report["status"] = "complete"
        else:
            report["cleanup_passed"] = False
            if report["status"] == "complete":
                report["status"] = "incomplete"
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "complete" else 2

sys.exit(main())
'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def probe_artifact_payload(data: bytes, expected_sha256: str) -> dict[str, str]:
    if (not isinstance(data, bytes) or not 1 <= len(data) <= PROBE_SOURCE_LIMIT or
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or
            sha256_bytes(data) != expected_sha256):
        raise ValueError("VMM probe artifact size or hash mismatch")
    return {"base64": base64.b64encode(data).decode("ascii"), "sha256": expected_sha256}


def load_probe_source() -> bytes:
    if PROBE_SOURCE.is_symlink() or not PROBE_SOURCE.is_file():
        raise ValueError("hash-pinned VMM probe source is missing or redirected")
    data = PROBE_SOURCE.read_bytes()
    if len(data) > PROBE_SOURCE_LIMIT or sha256_bytes(data) != PROBE_SOURCE_SHA256:
        raise ValueError("hash-pinned VMM probe source failed its size/hash check")
    return data


def validate_probe_result(report: object, exit_code: int) -> dict[str, object]:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(exit_code in (0, 2), "VMM probe exited outside its observation contract")
    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-hybrid-driver-api-vmm-share-v1" and
            report.get("phase") == "vmm-posix_fd-share" and
            report.get("shareable_handle_kind") == "posix_fd" and
            report.get("shareable_handle_type") == 1 and
            report.get("shareable_handle_bytes") == 4 and
            report.get("expected_pci") == EXPECTED_PCI and
            report.get("driver_api") == EXPECTED_DRIVER_API,
            "VMM probe identity or POSIX-FD contract mismatch")
    device = report.get("device")
    require(isinstance(device, dict) and
            isinstance(device.get("name"), str) and
            device["name"].startswith(EXPECTED_GPU_NAME_PREFIX),
            "VMM probe selected GPU name mismatch")
    if device.get("pci_bus_id") != EXPECTED_PCI:
        raise ValueError("VMM probe PCI identity mismatch")
    require(device.get("sm") == 120 and device.get("compute_capability") == "12.0" and
            device.get("unified_addressing") == 1,
            "VMM probe architecture or UVA contract mismatch")
    support = device.get("posix_fd_handle_support")
    require(isinstance(support, dict) and support.get("status") == 0 and
            support.get("value") in (0, 1) and report.get("attribute_support") == support,
            "POSIX-FD support attribute is absent or disagrees")
    require(report.get("observation_valid") is True and
            type(report.get("cleanup_passed")) is bool and
            isinstance(report.get("cleanup_errors"), list),
            "VMM probe observation or cleanup metadata is malformed")
    require(report.get("cleanup_passed") is True and not report["cleanup_errors"],
            "CUDA cleanup did not pass")
    fd_opened = report.get("posix_shareable_fd_opened")
    fd_closed = report.get("posix_shareable_fd_closed")
    require(type(fd_opened) is bool and type(fd_closed) is bool and
            (not fd_opened or fd_closed),
            "POSIX descriptor cleanup did not pass")
    success = report.get("status") == "phase-passed"
    if success:
        child = report.get("child")
        require(exit_code == 0 and support.get("value") == 1 and fd_opened is True and
                report.get("numerical_phase_passed") is True and
                report.get("initial_values_match") is True and
                report.get("child_writeback_match") is True,
                "VMM numeric exchange did not pass in both directions")
        require(isinstance(child, dict) and child.get("status") == "phase-passed" and
                child.get("phase") == "vmm-posix_fd-importer" and
                child.get("numerical_phase_passed") is True and
                child.get("initial_values_match") is True and
                child.get("posix_shareable_fd_opened") is True and
                child.get("posix_shareable_fd_closed") is True and
                child.get("cleanup_passed") is True and child.get("cleanup_errors") == [],
                "VMM importer numeric or descriptor cleanup evidence is incomplete")
        require(isinstance(child.get("device"), dict) and
                child["device"].get("pci_bus_id") == EXPECTED_PCI and
                child["device"].get("sm") == 120,
                "VMM importer selected a different device")
    else:
        require(report.get("status") == "phase-failed" and exit_code == 0 and
                report.get("observation_valid") is True and
                (isinstance(report.get("failure_operation"), str) or
                 isinstance(report.get("error_class"), str)),
                "negative VMM observation lacks a typed API outcome")
    return {"qualification": ("rtx5080-vmm-posix-reference-validated" if success else
                              "rtx5080-vmm-posix-negative-observation-validated"),
            "numeric_exchange_passed": success, "hybrid_validated": False}


def build_request(probe: bytes) -> dict[str, str]:
    artifact = probe_artifact_payload(probe, PROBE_SOURCE_SHA256)
    return {"schema": "nvidia-hybrid-pc3-rtx5080-vmm-posix-request-v1",
            "probe_base64": artifact["base64"], "probe_sha256": artifact["sha256"]}


def validate_remote_report(report: object) -> dict[str, object]:
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(report, dict) and
            report.get("schema") == "nvidia-hybrid-pc3-rtx5080-vmm-posix-reference-v1" and
            report.get("status") == "complete" and
            report.get("hostname") == EXPECTED_HOST and
            isinstance(report.get("kernel_release"), str) and report["kernel_release"] and
            report.get("probe_source_sha256") == PROBE_SOURCE_SHA256 and
            type(report.get("probe_source_bytes")) is int and
            1 <= report["probe_source_bytes"] <= PROBE_SOURCE_LIMIT and
            report.get("cuda_visible_devices") == EXPECTED_GPU_UUID,
            "remote VMM reference did not complete on PC3")
    gpu = report.get("gpu")
    require(isinstance(gpu, dict) and gpu.get("uuid") == EXPECTED_GPU_UUID and
            gpu.get("pci") == EXPECTED_PCI and gpu.get("driver_version") == EXPECTED_DRIVER and
            gpu.get("binding") == "nvidia" and
            isinstance(gpu.get("name"), str) and gpu["name"].startswith(EXPECTED_GPU_NAME_PREFIX),
            "remote selected GPU identity mismatch")
    require(report.get("gpu_after") == gpu,
            "selected GPU identity changed during the probe")
    module_before, module_after = report.get("module_before"), report.get("module_after")
    require(isinstance(module_before, dict) and module_before == module_after and
            module_before.get("loaded_version") == EXPECTED_DRIVER and
            isinstance(module_before.get("path"), str) and module_before["path"].startswith("/") and
            re.fullmatch(r"[0-9a-f]{64}", module_before.get("sha256", "")) is not None,
            "loaded NVIDIA module identity changed or is malformed")
    library = report.get("libcuda")
    require(isinstance(library, dict) and isinstance(library.get("path"), str) and
            library["path"].startswith("/") and
            re.fullmatch(r"[0-9a-f]{64}", library.get("sha256", "")) is not None and
            type(library.get("bytes")) is int and library["bytes"] >= 1024 * 1024,
            "selected libcuda identity is malformed")
    require(report.get("gpu_compute_processes_before") == [] and
            report.get("gpu_compute_processes_after") == [] and
            report.get("cleanup_passed") is True and
            report.get("remote_workspace_removed") is True,
            "remote process or temporary-workspace cleanup did not pass")
    scope = report.get("execution_scope")
    require(isinstance(scope, dict) and
            all(scope.get(key) is False for key in (
                "driver_or_module_changed", "pci_binding_changed", "vm_management_issued",
                "gpu_reset_requested", "imex_configuration_changed")),
            "remote runner reports an out-of-scope system change")
    validated = validate_probe_result(report.get("probe"), report.get("probe_exit_code"))
    require(report["probe"].get("driver_library_path") == library["path"],
            "probe loaded a different libcuda path")
    return validated


def run(evidence: Path, invoke=subprocess.run) -> tuple[dict[str, object], int]:
    probe = load_probe_source()
    source_hash = sha256_bytes(probe)
    payload = build_request(probe)
    command = SSH_OPTIONS + ["--", EXPECTED_TARGET,
                             "python3 -c " + shlex.quote(REMOTE_SCRIPT)]
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-rtx5080-vmm-posix-runner-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": EXPECTED_TARGET, "host_key_alias": EXPECTED_HOST_KEY_ALIAS,
        "gpu_uuid": EXPECTED_GPU_UUID, "pci": EXPECTED_PCI,
        "probe_source": str(PROBE_SOURCE), "probe_source_sha256": source_hash,
        "runner_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "remote_script_sha256": sha256_bytes(REMOTE_SCRIPT.encode("utf-8")),
        "ssh_command": command, "exit_code": 2,
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    code = 2
    try:
        result = invoke(command, input=json.dumps(payload), text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=150, check=False, shell=False)
        report["ssh_exit_code"] = result.returncode
        report["ssh_stderr_sha256"] = sha256_bytes(result.stderr.encode("utf-8", "replace"))
        report["ssh_stderr_bytes"] = len(result.stderr.encode("utf-8", "replace"))
        report["ssh_stdout_sha256"] = sha256_bytes(result.stdout.encode("utf-8", "replace"))
        report["ssh_stdout_bytes"] = len(result.stdout.encode("utf-8", "replace"))
        if result.stdout:
            try:
                remote = json.loads(result.stdout.strip())
            except json.JSONDecodeError as exc:
                raise ValueError("remote response is not one JSON object") from exc
            report["remote"] = remote
            report["remote_qualification"] = validate_remote_report(remote)
            if result.returncode != 0:
                raise ValueError("remote worker returned nonzero after validation")
            report["qualification"] = report["remote_qualification"]["qualification"]
            code = 0
        else:
            report["error"] = "SSH returned no JSON result"
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        report["error"] = type(exc).__name__ + ":" + str(exc)[:250]
    finally:
        report["exit_code"] = code
        encoded = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    return report, code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    report, code = run(args.evidence)
    print(json.dumps({"evidence": str(args.evidence), "exit_code": code,
                      "qualification": report.get("qualification"),
                      "error": report.get("error")}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
