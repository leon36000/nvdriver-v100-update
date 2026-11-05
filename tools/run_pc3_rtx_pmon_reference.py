#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a pinned PC3 RTX 5080 CUDA benchmark beside an independent NVML monitor."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCHEMA = "nvidia-hybrid-pc3-rtx-pmon-runtime-witness-v1"
SUMMARY_SCHEMA = "nvidia-hybrid-pc3-rtx-pmon-runtime-summary-v1"
TARGET = "pc3@pc3"
HOST_KEY_ALIAS = "pc3"
GPU_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
GPU_PCI = "0000:02:00.0"
LIBCUDA_SHA256 = "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d"
PROBE_SHA256 = "c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422"
FATBIN_SHA256 = "8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70"
RUNNER_SHA256 = "0384723a7962042137d6380a1db484ae112168d8384dc6662a00c7258d159840"
CONTRACT_SHA256 = "9f65e31214f0b323198460879e015967baa3feec855df1177d371a5b8cf28506"
SAMPLES = 1001
PMON_COUNT = 20


class WitnessError(ValueError):
    """A capture does not contain enough independently correlated evidence."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _object(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise WitnessError(f"{name} must be an object")
    return value


def _private_path(path: Path, root: Path, *, output: bool = False) -> Path:
    if path.is_symlink():
        raise WitnessError("evidence path must not be a symlink")
    if output and path.exists():
        raise WitnessError("refusing to replace existing evidence")
    try:
        parent = path.parent.resolve(strict=True)
        parent.relative_to((root / "evidence" / "logs").resolve(strict=True))
    except (OSError, ValueError) as error:
        raise WitnessError("raw evidence must be under evidence/logs") from error
    return parent / path.name


def _summary_path(path: Path, root: Path) -> Path:
    if path.is_symlink() or path.exists():
        raise WitnessError("refusing to replace existing or symlinked summary")
    try:
        parent = path.parent.resolve(strict=True)
        parent.relative_to((root / "evidence").resolve(strict=True))
    except (OSError, ValueError) as error:
        raise WitnessError("summary parent is unavailable") from error
    try:
        parent.relative_to((root / "evidence" / "logs").resolve(strict=True))
    except ValueError:
        pass
    else:
        raise WitnessError("sanitized summary cannot be stored under evidence/logs")
    return parent / path.name


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _parse_pmon_rows(events: object, *, count: int) -> list[dict]:
    if not isinstance(events, list):
        raise WitnessError("pmon events must be a list")
    rows = []
    saw_header = False
    for event in events:
        event = _object(event, "pmon event")
        line = event.get("line")
        tick = event.get("monotonic_ns")
        if not isinstance(line, str) or type(tick) is not int or tick <= 0:
            raise WitnessError("pmon event has malformed content or clock")
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "#":
            if len(fields) >= 11 and fields[1:4] == ["gpu", "pid", "type"]:
                saw_header = True
            continue
        if not saw_header or len(fields) != 10:
            raise WitnessError("pmon output has an invalid header or row width")
        gpu, pid, process_type, sm, mem, enc, dec, jpg, ofa, command = fields
        if gpu != "0":
            raise WitnessError("pmon was not restricted to the single selected GPU")
        if pid == "-":
            if any(value != "-" for value in (process_type, sm, mem, enc, dec, jpg, ofa, command)):
                raise WitnessError("idle pmon row contains contradictory process data")
            rows.append({"monotonic_ns": tick, "pid": None, "type": None,
                         "sm": None, "mem": None, "command": None})
            continue
        if (not pid.isdecimal() or int(pid) <= 0 or process_type != "C" or
                command in ("", "-")):
            raise WitnessError("pmon process is not a CUDA compute process")
        if not sm.isdecimal() or not mem.isdecimal():
            raise WitnessError("pmon process utilization is unavailable")
        sm_value, mem_value = int(sm), int(mem)
        if sm_value > 100 or mem_value > 100:
            raise WitnessError("pmon utilization is outside the documented percentage range")
        rows.append({"monotonic_ns": tick, "pid": int(pid), "type": process_type,
                     "sm": sm_value, "mem": mem_value, "command": command})
    if not saw_header or len(rows) != count:
        raise WitnessError("pmon sample count or header differs from the pinned capture")
    return rows


def validate_witness(witness: object, *, capture_sha256: str) -> dict:
    witness = _object(witness, "pmon witness")
    if witness.get("schema") != SCHEMA:
        raise WitnessError("unexpected pmon witness schema")
    if (witness.get("target") != TARGET or witness.get("host_key_alias") != HOST_KEY_ALIAS or
            witness.get("gpu_uuid") != GPU_UUID or witness.get("pci") != GPU_PCI):
        raise WitnessError("pmon target or exact GPU identity differs from the approved PC3 route")
    if witness.get("capture_sha256") != capture_sha256:
        raise WitnessError("pmon witness is not bound to this CUDA capture")
    if witness.get("ssh_exit_code") != 0 or witness.get("pmon_exit_code") != 0:
        raise WitnessError("strict-SSH pmon observer did not complete successfully")
    if witness.get("benchmark_runner_exit_code") != 77:
        raise WitnessError("benchmark runner exit code differs from the fixed SM70-missing result")
    command = witness.get("ssh_argv")
    expected_command = ["ssh", "-l", "pc3", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                        "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=pc3", "--", "pc3",
                        "nvidia-smi", "pmon", "-i", GPU_UUID, "-s", "u", "-d", "1", "-c",
                        str(PMON_COUNT)]
    if command != expected_command:
        raise WitnessError("pmon command differs from the fixed strict-SSH monitor")
    if witness.get("sample_interval_seconds") != 1 or witness.get("sample_count_requested") != PMON_COUNT:
        raise WitnessError("pmon sampling interval or count differs from the fixed monitor")
    run_start = witness.get("benchmark_started_monotonic_ns")
    run_end = witness.get("benchmark_finished_monotonic_ns")
    monitor_start = witness.get("monitor_started_monotonic_ns")
    monitor_end = witness.get("monitor_finished_monotonic_ns")
    ready = witness.get("monitor_ready_monotonic_ns")
    if any(type(value) is not int or value <= 0 for value in (run_start, run_end, monitor_start, monitor_end, ready)):
        raise WitnessError("witness monotonic timing is malformed")
    if not (monitor_start <= ready < run_start < run_end < monitor_end):
        raise WitnessError("monitor and benchmark intervals do not establish concurrent observation")
    rows = _parse_pmon_rows(witness.get("events"), count=PMON_COUNT)
    in_window = [row for row in rows if run_start <= row["monotonic_ns"] <= run_end]
    active = [row for row in in_window if row["pid"] is not None]
    active_pids = {row["pid"] for row in active}
    active_commands = {row["command"] for row in active}
    sm_rows = [row for row in active if row["sm"] is not None and row["sm"] > 0]
    if (len(active_pids) != 1 or active_commands != {"probe"} or len(sm_rows) < 2):
        raise WitnessError("pmon did not observe one probe process with repeated nonzero SM use during the benchmark")
    if any(row["pid"] is not None and row["command"] != "probe" for row in rows):
        raise WitnessError("another process makes GPU activity attribution ambiguous")
    return {
        "sample_count": len(rows),
        "samples_during_benchmark": len(in_window),
        "probe_process_samples_during_benchmark": len(active),
        "nonzero_sm_samples_during_benchmark": len(sm_rows),
        "peak_sm_utilization_percent": max(row["sm"] for row in sm_rows),
        "peak_memory_utilization_percent": max(row["mem"] for row in sm_rows),
        "unique_probe_process_count": len(active_pids),
        "observed_process_name": "probe",
    }


def summarize_probe_reported_benchmark(benchmark: object) -> dict:
    """Keep aggregate timings while labeling them as an unqualified probe report."""
    benchmark = _object(benchmark, "probe-reported benchmark")
    if (benchmark.get("samples") != SAMPLES or
            benchmark.get("transfer_samples") != SAMPLES):
        raise WitnessError("probe-reported benchmark sample count is not pinned")

    def pair(values: object, median_key: str, p95_key: str, label: str) -> dict:
        values = _object(values, label)
        result = {}
        for output_key, input_key in (("median", median_key), ("p95", p95_key)):
            value = values.get(input_key)
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise WitnessError(f"probe-reported {label} {output_key} is invalid")
            result[output_key] = value
        return result

    launch = _object(benchmark.get("kernel_launch"), "kernel launch timings")
    if launch.get("samples") != SAMPLES or launch.get("kernel") != "hybrid_empty":
        raise WitnessError("probe-reported kernel launch is not the pinned measurement")
    transfers = benchmark.get("transfers")
    expected_sizes = [4096, 65536, 1048576, 16777216, 67108864]
    if not isinstance(transfers, list) or len(transfers) != len(expected_sizes):
        raise WitnessError("probe-reported transfer table is incomplete")

    reduced_transfers = []
    for transfer, expected_size in zip(transfers, expected_sizes, strict=True):
        transfer = _object(transfer, "transfer measurement")
        if (transfer.get("bytes") != expected_size or transfer.get("samples") != SAMPLES or
                transfer.get("data_integrity_passed") is not True):
            raise WitnessError("probe-reported transfer size, samples, or integrity is invalid")
        directions = {}
        for name, source in (("host_to_device", "h_to_d"), ("device_to_host", "d_to_h")):
            direction = _object(transfer.get(source), f"{name} transfer timings")
            if direction.get("data_integrity_passed") is not True:
                raise WitnessError(f"probe-reported {name} transfer integrity failed")
            directions[name] = {
                "device_event_us_per_copy": pair(
                    direction, "device_elapsed_us_per_copy_median",
                    "device_elapsed_us_per_copy_p95", f"{name} device timing"),
                "host_api_us_per_copy": pair(
                    direction, "host_api_us_per_copy_median",
                    "host_api_us_per_copy_p95", f"{name} host timing"),
                "gb_per_second": pair(
                    direction, "gb_per_second_median", "gb_per_second_p95",
                    f"{name} bandwidth"),
            }
        iterations = transfer.get("iterations_per_sample")
        if type(iterations) is not int or iterations < 1:
            raise WitnessError("probe-reported transfer iteration count is invalid")
        reduced_transfers.append({
            "bytes": expected_size,
            "samples": SAMPLES,
            "iterations_per_sample": iterations,
            "data_integrity_passed": True,
            **directions,
        })

    timing_sources = _object(benchmark.get("timing_sources"), "timing sources")
    if timing_sources != {"device": "CUDA events (cuEventElapsedTime)",
                          "host": "std::chrono::steady_clock"}:
        raise WitnessError("probe-reported benchmark timing sources are not recognized")
    return {
        "qualification": "probe-reported-unqualified-single-run",
        "samples": SAMPLES,
        "timing_sources": timing_sources,
        "kernel_launch": {
            "kernel": "hybrid_empty",
            "device_event_us": pair(launch, "device_elapsed_us_median",
                                     "device_elapsed_us_p95", "kernel device timing"),
            "host_api_us": pair(launch, "host_api_us_median",
                                 "host_api_us_p95", "kernel host timing"),
        },
        "transfers": reduced_transfers,
    }


def _verify_manifest(before: object, after: object, root: Path) -> dict:
    before = _object(before, "local artifacts")
    after = _object(after, "local artifacts after")
    expected = {"probe": PROBE_SHA256, "module": FATBIN_SHA256,
                "runner": RUNNER_SHA256, "cuda_probe_contract.py": CONTRACT_SHA256}
    if set(before) != set(expected) or set(after) != set(expected):
        raise WitnessError("capture has an unexpected pinned artifact set")
    verified = {}
    for name, digest in expected.items():
        initial = _object(before.get(name), f"artifact {name}")
        final = _object(after.get(name), f"artifact after {name}")
        if initial != final or set(initial) != {"bytes", "path", "sha256"}:
            raise WitnessError(f"artifact identity changed during the capture: {name}")
        path_value = initial.get("path")
        if not isinstance(path_value, str):
            raise WitnessError("local artifact path is missing")
        path = Path(path_value)
        if path.is_symlink():
            raise WitnessError("local artifact path is a symlink")
        try:
            path = path.resolve(strict=True)
            path.relative_to(root.resolve(strict=True))
            data = path.read_bytes()
        except (OSError, ValueError) as error:
            raise WitnessError("local artifact is missing or outside the project") from error
        if (_sha256(data) != digest or initial.get("sha256") != digest or
                initial.get("bytes") != len(data)):
            raise WitnessError(f"local artifact does not match its reviewed pin: {name}")
        verified[name] = {"sha256": digest, "bytes": len(data)}
    return verified


def summarize_capture(capture: object, witness: object, *, capture_sha256: str,
                      witness_sha256: str, root: Path = ROOT) -> dict:
    capture = _object(capture, "CUDA capture")
    if capture.get("schema") != "nvidia-hybrid-remote-selected-gpu-transport-v1":
        raise WitnessError("unexpected selected-GPU transport schema")
    if (capture.get("target") != TARGET or capture.get("host_key_alias") != HOST_KEY_ALIAS or
            capture.get("phase") is not None or capture.get("performance_benchmark_requested") is not True or
            capture.get("benchmark_samples") != SAMPLES):
        raise WitnessError("capture did not run the fixed isolated PC3 benchmark")
    if (capture.get("exit_code") != 77 or capture.get("ssh_exit_code") != 77 or
            capture.get("report_contract_validated") is not True or
            capture.get("qualification") != "rtx5080-report-contract-valid-hybrid-incomplete" or
            capture.get("cuda_execution_validated") is not False):
        raise WitnessError("capture does not match the expected incomplete-but-valid SM120 result")
    if capture.get("expected_libcuda_sha256") != LIBCUDA_SHA256:
        raise WitnessError("capture did not pin the expected stock R595 libcuda")
    monitor = validate_witness(witness, capture_sha256=capture_sha256)
    if witness.get("benchmark_runner_exit_code") != 77:
        raise WitnessError("local benchmark runner exit code differs from its validated capture")
    remote = _object(capture.get("remote"), "remote report")
    if (remote.get("exit_code") != 77 or remote.get("report_contract_validated") is not True or
            remote.get("qualification") != capture.get("qualification") or
            remote.get("remote_script_sha256") != capture.get("remote_script_sha256")):
        raise WitnessError("remote and local capture qualifications do not agree")
    tool = _object(capture.get("tool"), "selected-GPU runner identity")
    runner_path = root / "tools" / "run_remote_selected_gpu.py"
    if tool.get("sha256") != _sha256(runner_path.read_bytes()):
        raise WitnessError("selected-GPU runner source changed after capture")
    try:
        from tools.run_remote_selected_gpu import REMOTE_SCRIPT
        from tools.cuda_probe_contract import validate_performance_benchmark_report
    except (ImportError, OSError) as error:
        raise WitnessError("pinned validation helpers are unavailable") from error
    if capture.get("remote_script_sha256") != _sha256(REMOTE_SCRIPT.encode("utf-8")):
        raise WitnessError("remote script digest differs from the local reviewed source")
    ssh_argv = capture.get("ssh_argv")
    if (not isinstance(ssh_argv, list) or not ssh_argv or ssh_argv[0] != "ssh" or
            "StrictHostKeyChecking=yes" not in ssh_argv or "HostKeyAlias=pc3" not in ssh_argv):
        raise WitnessError("CUDA capture did not use the pinned strict-SSH route")
    selected = _object(remote.get("selected_nvidia_smi"), "selected GPU identity")
    if (selected.get("uuid") != GPU_UUID or selected.get("driver") != "595.99.02" or
            selected.get("name") != "NVIDIA GeForce RTX 5080" or
            selected.get("pci") not in ("00000000:02:00.0", "0000:02:00.0")):
        raise WitnessError("selected GPU identity differs from the pinned stock RTX 5080")
    before_lib = _object(remote.get("system_libcuda_before"), "pre-run libcuda")
    after_lib = _object(remote.get("system_libcuda_after"), "post-run libcuda")
    if (before_lib.get("sha256") != LIBCUDA_SHA256 or before_lib != after_lib or
            before_lib.get("path") != "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02"):
        raise WitnessError("stock libcuda changed or differs from the pinned identity")
    trust = _object(_object(remote.get("hardware_acceptance"), "acceptance report").get("probe_build_trust"),
                    "probe build trust")
    expected_trust = {"status": "trusted-pinned-build", "provenance": "pinned-probe-and-fatbin-sha256",
                      "probe_sha256": PROBE_SHA256, "module_sha256": FATBIN_SHA256}
    if trust.get("status") != "trusted-pinned-build" or trust.get("before_run") != expected_trust or trust.get("after_run") != expected_trust:
        raise WitnessError("remote probe/fatbin identity was not stable and pinned")
    acceptance = _object(remote.get("hardware_acceptance"), "acceptance report")
    probe = _object(acceptance.get("probe"), "CUDA probe report")
    if (probe.get("schema") != "nvidia-hybrid-probe-v2" or probe.get("status") != "incomplete" or
            probe.get("required_sm") != [70, 120] or probe.get("missing_sm") != [70] or
            probe.get("required_set_passed") is not False or
            probe.get("driver_library_path") != before_lib.get("path")):
        raise WitnessError("probe does not preserve the missing-SM70 boundary")
    devices = probe.get("devices")
    if not isinstance(devices, list) or len(devices) != 1:
        raise WitnessError("probe did not test exactly the pinned RTX device")
    device = _object(devices[0], "RTX probe result")
    if (device.get("name") != "NVIDIA GeForce RTX 5080" or device.get("sm") != 120 or
            device.get("pci_bus_id") != GPU_PCI or device.get("targeted") is not True or
            device.get("tested") is not True or device.get("architecture_kernel_passed") is not True or
            device.get("synchronous_passed") is not True or device.get("asynchronous_passed") is not True or
            device.get("cleanup_passed") is not True or device.get("cleanup_errors") != [] or
            device.get("performance_benchmark_passed") is not True):
        raise WitnessError("pinned SM120 numeric kernel, cleanup, or benchmark did not pass")
    benchmark = _object(device.get("performance_benchmark"), "per-device benchmark")
    validate_performance_benchmark_report(probe, True)
    if benchmark.get("samples") != SAMPLES or benchmark.get("transfer_samples") != SAMPLES:
        raise WitnessError("per-device benchmark sample count differs from the requested protocol")
    reported_performance = summarize_probe_reported_benchmark(benchmark)
    manifest = _verify_manifest(capture.get("local_artifacts"), capture.get("local_artifacts_after"), root)
    if not _manifest_matches(remote.get("artifacts_before"), capture.get("local_artifacts")) or not _manifest_matches(
            remote.get("artifacts_after"), capture.get("local_artifacts_after")):
        raise WitnessError("remote and local probe artifact manifests do not match")
    return {
        "schema": SUMMARY_SCHEMA,
        "observed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "qualification": "stock-rtx5080-cuda-kernel-observed-by-independent-nvml-pmon",
        "hardware_execution_validated": True,
        "cuda_execution_validated": True,
        "independent_hardware_attestation": False,
        "performance_benchmark_validated": False,
        "capture": {"sha256": capture_sha256, "report_contract": "passed",
                    "reported_exit_code": 77, "reason": "SM70 image absent on the RTX-only host"},
        "external_observer": {"kind": "nvidia-smi pmon process-utilization stream",
                              "transport": "separate strict-host-key SSH session to pc3",
                              "gpu_uuid": GPU_UUID, "gpu_pci_bus_id": GPU_PCI,
                              "sample_interval_seconds": 1, **monitor},
        "device": {"name": "NVIDIA GeForce RTX 5080", "compute_capability": "12.0",
                   "sm": 120, "pci_bus_id": GPU_PCI, "driver_version": "595.99.02",
                   "cuda_driver_api_version": probe.get("driver_api")},
        "cuda_result": {"targeted_numeric_kernels_passed": True,
                        "synchronous_sizes": device.get("synchronous_sizes"),
                        "asynchronous_sizes": device.get("asynchronous_sizes"),
                        "cleanup_passed": True},
        "stock_libcuda_sha256": LIBCUDA_SHA256,
        "probe_sha256": PROBE_SHA256,
        "fatbin_sha256": FATBIN_SHA256,
        "artifact_manifest": manifest,
        "probe_reported_performance": reported_performance,
        "raw_witness_sha256": witness_sha256,
        "limitations": ["Stock RTX 5080/R595 only; no candidate hybrid module was loaded.",
                        "The V100 was not targeted and remains outside this proof.",
                        "SM70 is missing, so the whole probe exits 77 and hybrid acceptance is incomplete.",
                        "pmon independently observed the process and SM utilization, but this is not cryptographic remote attestation.",
                        "Performance values are probe-reported from one stock run; they remain unqualified and are not a hybrid comparison."],
    }


def _manifest_matches(left: object, right: object) -> bool:
    if not isinstance(left, dict) or not isinstance(right, dict) or set(left) != set(right):
        return False
    return all(isinstance(left[name], dict) and isinstance(right[name], dict) and
               left[name].get("bytes") == right[name].get("bytes") and
               left[name].get("sha256") == right[name].get("sha256") for name in left)


def run(args: argparse.Namespace, root: Path = ROOT) -> int:
    capture_path = _private_path(args.capture, root, output=True)
    witness_path = _private_path(args.witness, root, output=True)
    summary_path = _summary_path(args.summary, root)
    if args.samples != SAMPLES:
        raise WitnessError("this execution witness requires the fixed 1001-sample benchmark")
    command = ["ssh", "-l", "pc3", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=pc3", "--", "pc3",
               "nvidia-smi", "pmon", "-i", GPU_UUID, "-s", "u", "-d", "1", "-c", str(PMON_COUNT)]
    events: list[dict] = []
    first_row = threading.Event()
    reader_done = threading.Event()
    monitor = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, encoding="utf-8", errors="replace", bufsize=1)
    monitor_started = time.monotonic_ns()

    def collect() -> None:
        assert monitor.stdout is not None
        for line in monitor.stdout:
            stamp = time.monotonic_ns()
            clean = line.rstrip("\r\n")
            events.append({"monotonic_ns": stamp, "line": clean})
            fields = clean.split()
            if fields and fields[0].isdigit():
                first_row.set()
        reader_done.set()

    thread = threading.Thread(target=collect, name="pc3-nvml-pmon-reader", daemon=True)
    thread.start()
    if not first_row.wait(8):
        monitor.terminate()
        monitor.wait(timeout=5)
        thread.join(timeout=5)
        raise WitnessError("strict-SSH pmon monitor produced no sample row")
    monitor_ready = time.monotonic_ns()
    runner_args = [sys.executable, "-B", str(root / "tools" / "run_remote_selected_gpu.py"),
                   "--target", TARGET, "--host-key-alias", HOST_KEY_ALIAS,
                   "--gpu-uuid", GPU_UUID, "--pci", GPU_PCI,
                   "--probe", str(root / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe"),
                   "--module", str(root / "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_probe.sm70-ptx_sm120a-cubin.fatbin"),
                   "--expected-libcuda-sha256", LIBCUDA_SHA256,
                   "--benchmark", "--benchmark-samples", str(SAMPLES), "--evidence", str(capture_path)]
    benchmark_start = time.monotonic_ns()
    try:
        completed = subprocess.run(runner_args, cwd=root, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=220, check=False)
    except subprocess.TimeoutExpired as error:
        benchmark_end = time.monotonic_ns()
        monitor.terminate()
        monitor.wait(timeout=5)
        thread.join(timeout=5)
        raise WitnessError("selected-GPU benchmark timed out; raw runner output is incomplete") from error
    benchmark_end = time.monotonic_ns()
    try:
        pmon_exit = monitor.wait(timeout=PMON_COUNT + 10)
    except subprocess.TimeoutExpired as error:
        monitor.terminate()
        monitor.wait(timeout=5)
        thread.join(timeout=5)
        raise WitnessError("pmon monitor did not finish at its fixed sample count") from error
    thread.join(timeout=5)
    if not reader_done.is_set():
        raise WitnessError("pmon output reader did not reach end of stream")
    if not capture_path.is_file():
        raise WitnessError("selected-GPU runner did not produce its reserved raw report")
    capture_bytes = capture_path.read_bytes()
    capture_hash = _sha256(capture_bytes)
    witness = {
        "schema": SCHEMA,
        "target": TARGET,
        "host_key_alias": HOST_KEY_ALIAS,
        "gpu_uuid": GPU_UUID,
        "pci": GPU_PCI,
        "ssh_argv": command,
        "ssh_exit_code": pmon_exit,
        "pmon_exit_code": pmon_exit,
        "sample_interval_seconds": 1,
        "sample_count_requested": PMON_COUNT,
        "monitor_started_monotonic_ns": monitor_started,
        "monitor_ready_monotonic_ns": monitor_ready,
        "monitor_finished_monotonic_ns": time.monotonic_ns(),
        "benchmark_started_monotonic_ns": benchmark_start,
        "benchmark_finished_monotonic_ns": benchmark_end,
        "benchmark_runner_exit_code": completed.returncode,
        "benchmark_runner_stdout_sha256": _sha256(completed.stdout.encode()),
        "benchmark_runner_stderr_sha256": _sha256(completed.stderr.encode()),
        "capture_sha256": capture_hash,
        "events": events,
    }
    witness_bytes = (json.dumps(witness, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(witness_path, witness_bytes, 0o600)
    try:
        capture = json.loads(capture_bytes.decode("utf-8", "strict"))
        summary = summarize_capture(capture, witness, capture_sha256=capture_hash,
                                    witness_sha256=_sha256(witness_bytes), root=root)
    except (UnicodeError, json.JSONDecodeError, WitnessError, ValueError, OSError) as error:
        print(f"hardware witness rejected: {error}", file=sys.stderr)
        return 2
    summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(summary_path, summary_bytes, 0o644)
    print(json.dumps({"summary": str(summary_path),
                      "qualification": summary["qualification"],
                      "capture_sha256": capture_hash,
                      "witness_sha256": _sha256(witness_bytes)}, sort_keys=True))
    return 0


def summarize_existing(args: argparse.Namespace, root: Path = ROOT) -> int:
    """Validate a previously captured pair without contacting PC3 or rerunning CUDA."""
    capture_path = _private_path(args.capture, root)
    witness_path = _private_path(args.witness, root)
    summary_path = _summary_path(args.summary, root)
    if any((path.stat().st_mode & 0o777) != 0o600 for path in (capture_path, witness_path)):
        raise WitnessError("raw capture and pmon witness must remain mode 0600")
    capture_bytes = capture_path.read_bytes()
    witness_bytes = witness_path.read_bytes()
    try:
        capture = json.loads(capture_bytes.decode("utf-8", "strict"))
        witness = json.loads(witness_bytes.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WitnessError("raw capture or witness is not valid UTF-8 JSON") from error
    capture_hash = _sha256(capture_bytes)
    summary = summarize_capture(capture, witness, capture_sha256=capture_hash,
                                witness_sha256=_sha256(witness_bytes), root=root)
    summary_bytes = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
    _write_exclusive(summary_path, summary_bytes, 0o644)
    print(json.dumps({"summary": str(summary_path),
                      "qualification": summary["qualification"],
                      "capture_sha256": capture_hash,
                      "witness_sha256": _sha256(witness_bytes)}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True, help="new raw report under evidence/logs")
    parser.add_argument("--witness", type=Path, required=True, help="new mode-0600 pmon witness under evidence/logs")
    parser.add_argument("--summary", type=Path, required=True, help="new sanitized receipt under evidence/")
    parser.add_argument("--samples", type=int, default=SAMPLES)
    parser.add_argument("--summarize-existing", action="store_true",
                        help="validate the supplied mode-0600 files without contacting PC3")
    args = parser.parse_args(argv)
    try:
        if args.summarize_existing:
            return summarize_existing(args)
        return run(args)
    except (OSError, WitnessError, subprocess.SubprocessError) as error:
        print(f"PC3 RTX pmon run failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
