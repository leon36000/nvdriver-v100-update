#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write a path-free receipt for a report-backed PC3 RTX stock benchmark."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SUMMARY_SCHEMA = "nvidia-hybrid-pc3-rtx-stock-benchmark-summary-v1"
EXPECTED_GPU = "NVIDIA GeForce RTX 5080"
EXPECTED_UUID = "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77"
EXPECTED_PCI = "0000:02:00.0"
EXPECTED_TRANSFER_BYTES = (4096, 65536, 1048576, 16777216, 67108864)


class SummaryError(ValueError):
    """The raw report does not prove the narrow stock-RTX benchmark contract."""


def _object(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise SummaryError(f"{name} must be an object")
    return value


def _positive_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SummaryError(f"{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise SummaryError(f"{name} must be finite and positive")
    return number


def _sample_series(value: object, count: int, name: str) -> list[float]:
    if not isinstance(value, list) or len(value) != count:
        raise SummaryError(f"{name} sample count differs from the report contract")
    return [_positive_number(item, name) for item in value]


def _percentile_summary(value: object, *, count: int, name: str) -> dict:
    record = _object(value, name)
    if record.get("samples") != count:
        raise SummaryError(f"{name} sample count differs from the report contract")
    median = _positive_number(record.get("median"), f"{name}.median")
    p95 = _positive_number(record.get("p95"), f"{name}.p95")
    if p95 < median:
        raise SummaryError(f"{name} p95 is below its median")
    _sample_series(record.get("values"), count, f"{name}.values")
    return {"median": median, "p95": p95, "samples": count}


def _input_path(value: str | Path, root: Path) -> tuple[Path, bytes]:
    path = Path(value)
    if path.is_symlink():
        raise SummaryError("raw report must not be a symlink")
    try:
        evidence = root / "evidence"
        logs = evidence / "logs"
        if evidence.is_symlink() or logs.is_symlink():
            raise SummaryError("evidence directories must not be symlinks")
        evidence_root = evidence.resolve(strict=True)
        evidence_root.relative_to(root)
        logs_root = logs.resolve(strict=True)
        logs_root.relative_to(evidence_root)
        resolved = path.resolve(strict=True)
        resolved.relative_to(logs_root)
    except (OSError, ValueError) as error:
        raise SummaryError("raw report must be inside evidence/logs") from error
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise SummaryError("raw report could not be opened without following links") from error
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SummaryError("raw report must be a regular file with permissions exactly 0600")
        if metadata.st_size < 1 or metadata.st_size > 16 * 1024 * 1024:
            raise SummaryError("raw report is empty or exceeds the 16 MiB limit")
        data = stream.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise SummaryError("raw report is empty or exceeds the 16 MiB limit")
    return resolved, data


def _acceptance_report(remote: dict) -> dict:
    commands = remote.get("commands")
    if not isinstance(commands, list):
        raise SummaryError("remote command records are missing")
    matches = []
    for command in commands:
        if not isinstance(command, dict) or not isinstance(command.get("stdout"), str):
            continue
        try:
            value = json.loads(command["stdout"])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == "nvidia-hybrid-hardware-acceptance-v2":
            matches.append(value)
    if len(matches) != 1:
        raise SummaryError("exactly one embedded hardware-acceptance report is required")
    return matches[0]


def _benchmark(device: dict, report: dict) -> dict:
    if (device.get("name") != EXPECTED_GPU or device.get("pci_bus_id") != EXPECTED_PCI or
            device.get("sm") != 120 or device.get("compute_capability") != "12.0" or
            device.get("performance_benchmark_passed") is not True):
        raise SummaryError("the benchmark is not a passing RTX 5080 SM120 result")
    benchmark = _object(device.get("performance_benchmark"), "performance benchmark")
    sample_count = report.get("benchmark_samples")
    transfer_sample_count = report.get("benchmark_transfer_samples")
    if (benchmark.get("schema") != "nvidia-cuda-performance-benchmark-v2" or
            benchmark.get("status") != "completed" or
            type(sample_count) is not int or sample_count < 1 or
            benchmark.get("samples") != sample_count or
            type(transfer_sample_count) is not int or transfer_sample_count < 1 or
            benchmark.get("transfer_samples") != transfer_sample_count or
            type(benchmark.get("launches_per_sample")) is not int or
            benchmark["launches_per_sample"] < 1 or
            type(benchmark.get("warmup_launches")) is not int or
            benchmark["warmup_launches"] < 0):
        raise SummaryError("benchmark completion or sample counts are invalid")

    kernel = _object(benchmark.get("kernel_launch"), "kernel launch")
    if kernel.get("samples") != sample_count:
        raise SummaryError("kernel launch sample count is invalid")
    kernel_summary = {}
    for key in ("device_elapsed_us", "host_api_us"):
        median_key, p95_key = f"{key}_median", f"{key}_p95"
        median = _positive_number(kernel.get(median_key), f"kernel_launch.{median_key}")
        p95 = _positive_number(kernel.get(p95_key), f"kernel_launch.{p95_key}")
        if p95 < median:
            raise SummaryError(f"kernel_launch.{p95_key} is below its median")
        _sample_series(kernel.get(f"{key}_samples"), sample_count,
                       f"kernel_launch.{key}_samples")
        kernel_summary[key] = {"median": median, "p95": p95, "samples": sample_count}

    graph = _object(benchmark.get("cuda_graph_launch"), "CUDA Graph launch")
    graph_summary = {
        name: _percentile_summary(graph.get(name), count=sample_count, name=f"cuda_graph_launch.{name}")
        for name in ("device_elapsed_us", "host_api_us")
    }

    transfers = benchmark.get("transfers")
    if not isinstance(transfers, list) or tuple(
            row.get("bytes") if isinstance(row, dict) else None for row in transfers
    ) != EXPECTED_TRANSFER_BYTES:
        raise SummaryError("pinned-transfer size set differs from the reviewed probe")
    transfer_summary = []
    for row in transfers:
        if (row.get("data_integrity_passed") is not True or
                row.get("samples") != transfer_sample_count):
            raise SummaryError("pinned-transfer integrity or sample count failed")
        directions = {}
        for name in ("h_to_d", "d_to_h"):
            direction = _object(row.get(name), f"transfer {name}")
            samples = direction.get("gb_per_second_samples")
            if (direction.get("data_integrity_passed") is not True or
                    not isinstance(samples, list) or len(samples) != transfer_sample_count):
                raise SummaryError(f"transfer {name} integrity or sample count failed")
            median = _positive_number(direction.get("gb_per_second_median"), f"{name}.median")
            p95 = _positive_number(direction.get("gb_per_second_p95"), f"{name}.p95")
            _sample_series(direction.get("gb_per_second_samples"), transfer_sample_count,
                           f"{name}.gb_per_second_samples")
            if p95 < median:
                raise SummaryError(f"transfer {name} p95 is below its median")
            directions[name] = {"median_gb_s": median, "p95_gb_s": p95}
        transfer_summary.append({"bytes": row["bytes"], "directions": directions,
                                 "data_integrity_passed": True,
                                 "samples_per_direction": transfer_sample_count})

    return {
        "status": "completed_report_claim",
        "samples": sample_count,
        "launches_per_sample": benchmark.get("launches_per_sample"),
        "warmup_launches": benchmark.get("warmup_launches"),
        "transfer_samples_per_direction": transfer_sample_count,
        "kernel_launch": kernel_summary,
        "cuda_graph_launch": graph_summary,
        "pinned_transfers": transfer_summary,
    }


def summarize_report(input_path: str | Path, root: Path = ROOT) -> dict:
    root = root.resolve(strict=True)
    resolved, raw = _input_path(input_path, root)
    try:
        capture = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SummaryError("raw report is not valid JSON") from error
    capture = _object(capture, "raw report")
    if (capture.get("schema") != "nvidia-hybrid-remote-selected-gpu-transport-v1" or
            capture.get("report_contract_validated") is not True or
            capture.get("qualification") != "rtx5080-report-contract-valid-hybrid-incomplete" or
            capture.get("exit_code") != 77):
        raise SummaryError("transport report is not the expected incomplete-hybrid result")
    if capture.get("performance_benchmark_requested") is not True:
        raise SummaryError("a stock RTX performance benchmark was not requested")
    observed_at = capture.get("observed_at_utc")
    if not isinstance(observed_at, str):
        raise SummaryError("capture timestamp is missing")
    try:
        timestamp = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise SummaryError("capture timestamp is invalid") from error
    if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
        raise SummaryError("capture timestamp must be UTC")

    remote = _object(capture.get("remote"), "remote report")
    if (remote.get("performance_benchmark_report_contract_passed") is not True or
            remote.get("performance_benchmark_validated") is not False or
            remote.get("cuda_execution_validated") is not False):
        raise SummaryError("benchmark/report attestation boundary is not explicit")
    gpu = _object(remote.get("selected_nvidia_smi"), "selected nvidia-smi identity")
    if (gpu.get("name") != EXPECTED_GPU or gpu.get("uuid") != EXPECTED_UUID or
            gpu.get("pci") not in (EXPECTED_PCI, "00000000:02:00.0") or
            gpu.get("driver") != "595.99.02"):
        raise SummaryError("selected stock GPU identity differs from the pinned RTX 5080")
    pre_lib = _object(remote.get("system_libcuda_before"), "pre-test libcuda")
    post_lib = _object(remote.get("system_libcuda_after"), "post-test libcuda")
    lib_hash = pre_lib.get("sha256")
    if (not isinstance(lib_hash, str) or len(lib_hash) != 64 or
            any(c not in "0123456789abcdef" for c in lib_hash) or
            capture.get("expected_libcuda_sha256") != lib_hash or
            post_lib.get("sha256") != lib_hash):
        raise SummaryError("system libcuda hash was not stable across the benchmark")
    cleanup = _object(remote.get("remote_work_cleanup"), "remote cleanup")
    if cleanup.get("passed") is not True or cleanup.get("removed") is not True:
        raise SummaryError("remote temporary-work cleanup did not pass")

    preflight = _object(remote.get("preflight"), "CUDA inventory preflight")
    preflight_devices = preflight.get("devices")
    preflight_device = (_object(preflight_devices[0], "preflight RTX device")
                        if isinstance(preflight_devices, list) and len(preflight_devices) == 1
                        else None)
    if (preflight.get("status") != "inventory" or preflight.get("driver_api") != 13020 or
            preflight_device is None or preflight_device.get("pci_bus_id") != EXPECTED_PCI or
            preflight_device.get("sm") != 120):
        raise SummaryError("CUDA inventory did not contain the isolated RTX 5080")

    acceptance = _acceptance_report(remote)
    probe = _object(acceptance.get("probe"), "hybrid probe report")
    missing_sm = probe.get("missing_sm")
    if (acceptance.get("exit_code") != 77 or
            acceptance.get("qualification") != "incomplete-hardware-missing" or
            acceptance.get("kernel_release") != "7.0.0-38-generic" or
            acceptance.get("performance_benchmark_requested") is not True or
            acceptance.get("validation_errors") != [] or
            probe.get("status") != "incomplete" or probe.get("hybrid_validated") is not False or
            probe.get("required_set_passed") is not False or missing_sm != [70] or
            probe.get("driver_api") != 13020):
        raise SummaryError("hybrid acceptance did not fail solely on the missing SM70 device")
    devices = probe.get("devices")
    if not isinstance(devices, list) or len(devices) != 1:
        raise SummaryError("hybrid probe did not contain exactly the selected RTX")
    device = _object(devices[0], "selected RTX benchmark device")

    return {
        "schema": SUMMARY_SCHEMA,
        "qualification": "stock-rtx-benchmark-report-pass-hybrid-gate-incomplete",
        "source_report_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_at_utc": observed_at,
        "host_hardware": {
            "gpu": EXPECTED_GPU,
            "pci_bus_id": EXPECTED_PCI,
            "compute_capability": "12.0",
            "driver": "595.99.02",
            "kernel": "7.0.0-38-generic",
            "cuda_driver_api": 13020,
            "libcuda_sha256_stable": lib_hash,
        },
        "stock_rtx_benchmark": _benchmark(device, capture),
        "hybrid_acceptance": {
            "missing_sm": missing_sm,
            "same_host_v100_blackwell_validated": False,
            "cuda_execution_independently_attested": False,
            "report_contract_validated": True,
            "remote_temporary_work_cleanup_passed": True,
        },
    }


def write_new_json(output: str | Path, summary: dict, root: Path = ROOT) -> Path:
    root = root.resolve(strict=True)
    path = Path(output)
    if not path.is_absolute():
        path = root / path
    if path.is_symlink() or path.exists():
        raise SummaryError("output must be a new regular file path")
    try:
        evidence_root = (root / "evidence").resolve(strict=True)
        evidence_root.relative_to(root)
        parent = path.parent.resolve(strict=True)
        parent.relative_to(evidence_root)
    except (OSError, ValueError) as error:
        raise SummaryError("output parent must be inside evidence") from error
    destination = parent / path.name
    if destination.exists() or destination.is_symlink():
        raise SummaryError("output already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError as error:
        raise SummaryError("output already exists") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="mode-0600 raw report under evidence/logs")
    parser.add_argument("--output", required=True, help="new sanitized receipt under evidence")
    args = parser.parse_args(argv)
    try:
        report = summarize_report(args.input)
        path = write_new_json(args.output, report)
    except (OSError, SummaryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"receipt": str(path.relative_to(ROOT)), "qualification": report["qualification"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
