# SPDX-License-Identifier: MIT
"""Local compatibility check for the CUDA probe report protocol."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
from typing import Callable


CONTRACT_SCHEMA = "nvidia-hybrid-probe-contract-v1"
REPORT_SCHEMA = "nvidia-hybrid-probe-v2"
REQUIRED_REPORT_FIELDS = {
    "memory_mode",
    "managed_prefetch_requested",
    "managed_prefetch_api",
    "devices",
    "cuda_graphs_requested",
    "cuda_graph_api",
}
REQUIRED_EXACT_DEVICE_MAP_FIELDS = {"expected_device_pci_by_sm"}
REQUIRED_DEVICE_FIELDS = {
    "concurrent_managed_access",
    "pageable_memory_access",
    "pageable_memory_access_uses_host_page_tables",
    "managed_memory_passed",
    "managed_prefetch_passed",
    "cuda_graphs_passed",
    "cuda_graph_launches",
}
REQUIRED_PERFORMANCE_REPORT_FIELDS = {"performance_benchmark_requested"}
REQUIRED_PERFORMANCE_DEVICE_FIELDS = {"performance_benchmark_passed", "performance_benchmark"}
REQUIRED_CONCURRENT_DISPATCH_FIELDS = {
    "concurrent_kernel_test_requested",
    "concurrent_kernel_dispatch_passed",
    "concurrent_kernel_dispatch",
}
REQUIRED_PEER_TRANSFER_FIELDS = {"peer_transfer_requested", "peer_transfer"}
REQUIRED_PEER_TRANSFER_REPORT_FIELDS = {
    "host_staged_fallback_passed", "host_staged_fallback_status",
}
REQUIRED_PEER_TRANSFER_DIRECTION_FIELDS = {
    "host_staged_sync_copy_passed", "host_staged_async_copy_passed",
    "host_staged_data_integrity_passed",
}
PEER_TRANSFER_REPORT_SCHEMA = "nvidia-hybrid-peer-transfer-v3"


def _canonical_peer_pci(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]",
            value):
        raise ValueError("invalid PCI identity")
    domain, bus, slot_function = value.lower().split(":")
    if int(slot_function[:2], 16) > 31:
        raise ValueError("invalid PCI slot")
    return domain.zfill(8) + ":" + bus + ":" + slot_function


def validate_peer_transfer_report(report: object, requested: bool,
                                  expected_device_pci_by_sm: dict[int, str] | None = None) -> None:
    """Validate peer and host-staged copies without claiming direct DMA."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(type(requested) is bool, "peer-transfer selection must be boolean")
    require(isinstance(report, dict), "CUDA probe report must be an object")
    require(report.get("peer_transfer_requested") is requested,
            "peer-transfer mode differs from the probe report")
    peer = report.get("peer_transfer")
    if not requested:
        require(peer is None, "unrequested peer-transfer report")
        return

    require(isinstance(peer, dict), "requested peer-transfer report is missing")
    required = {
        "schema", "status", "requested", "passed", "sm70_can_access_sm120",
        "sm120_can_access_sm70", "direct_peer_access_enabled", "direct_dma_attested",
        "sm70_pci_bus_id", "sm120_pci_bus_id", "bytes_per_direction",
        "host_staged_fallback_passed", "host_staged_fallback_status",
        "directions", "cleanup_passed", "error",
    }
    require(set(peer) == required, "peer-transfer report has unexpected or missing fields")
    require(peer.get("schema") == PEER_TRANSFER_REPORT_SCHEMA and
            peer.get("requested") is True,
            "unsupported peer-transfer report schema")
    status = peer.get("status")
    require(status in {
        "api-unavailable", "pair-unavailable", "contexts-unavailable", "query-failed",
        "copy-only-verified", "one-way-peer-memory-verified",
        "peer-memory-verified", "peer-kernel-failed", "copy-failed",
        "cleanup-failed",
    }, "unknown peer-transfer status")
    require(type(peer.get("passed")) is bool and
            type(peer.get("direct_peer_access_enabled")) is bool and
            peer.get("direct_dma_attested") is False and
            type(peer.get("cleanup_passed")) is bool and
            type(peer.get("host_staged_fallback_passed")) is bool,
            "peer-transfer report contains invalid qualification flags")
    fallback_status = peer.get("host_staged_fallback_status")
    require(fallback_status in {
        "pair-unavailable", "contexts-unavailable", "host-staged-verified",
        "copy-failed", "cleanup-failed",
    }, "unknown host-staged fallback status")
    require(type(peer.get("bytes_per_direction")) is int and
            peer["bytes_per_direction"] == 4096,
            "unexpected peer-transfer test size")
    require(isinstance(peer.get("error"), str), "peer-transfer error must be text")
    for key in ("sm70_can_access_sm120", "sm120_can_access_sm70"):
        require(peer.get(key) is None or type(peer[key]) is bool,
                "peer capability result must be boolean or null")
    directions = peer.get("directions")
    require(isinstance(directions, list) and len(directions) in (0, 2),
            "peer-transfer directions must be empty or bidirectional")
    normalized = {}
    for direction in directions:
        require(isinstance(direction, dict) and set(direction) == {
            "source_sm", "destination_sm", "direct_access_enabled",
            "direct_kernel_attempted", "direct_kernel_passed",
            "sync_copy_passed", "async_copy_passed", "data_integrity_passed",
            "host_staged_sync_copy_passed", "host_staged_async_copy_passed",
            "host_staged_data_integrity_passed",
        }, "peer-transfer direction has unexpected or missing fields")
        source, destination = direction.get("source_sm"), direction.get("destination_sm")
        require((source, destination) in ((70, 120), (120, 70)) and
                source not in normalized,
                "peer-transfer has duplicate or invalid direction")
        for key in ("direct_access_enabled", "direct_kernel_attempted",
                    "direct_kernel_passed", "sync_copy_passed",
                    "async_copy_passed", "data_integrity_passed",
                    "host_staged_sync_copy_passed",
                    "host_staged_async_copy_passed",
                    "host_staged_data_integrity_passed"):
            require(type(direction.get(key)) is bool,
                    "peer-transfer direction result must be boolean")
        require(not direction["direct_kernel_attempted"] or
                direction["direct_access_enabled"],
                "peer-kernel attempt requires enabled direct access")
        require(not direction["direct_kernel_passed"] or
                direction["direct_kernel_attempted"],
                "peer-kernel success requires an attempted kernel")
        capability_key = ("sm120_can_access_sm70" if source == 70 else
                          "sm70_can_access_sm120")
        require(not direction["direct_access_enabled"] or
                peer[capability_key] is True,
                "directional peer access contradicts queried capability")
        require(direction["data_integrity_passed"] is
                (direction["sync_copy_passed"] and direction["async_copy_passed"]),
                "peer-transfer integrity flag contradicts copy results")
        require(direction["host_staged_data_integrity_passed"] is
                (direction["host_staged_sync_copy_passed"] and
                 direction["host_staged_async_copy_passed"]),
                "host-staged integrity flag contradicts its copy results")
        normalized[source] = direction
    host_staged_copy_results_passed = (
        set(normalized) == {70, 120} and
        all(row["host_staged_data_integrity_passed"]
            for row in normalized.values())
    )
    require(peer["host_staged_fallback_passed"] is
            (host_staged_copy_results_passed and peer["cleanup_passed"]),
            "host-staged fallback flag contradicts copy or cleanup results")
    if not normalized:
        require(fallback_status in {"pair-unavailable", "contexts-unavailable"} and
                not peer["host_staged_fallback_passed"],
                "unavailable device pair cannot claim a host-staged fallback")
    elif fallback_status == "host-staged-verified":
        require(host_staged_copy_results_passed and peer["cleanup_passed"],
                "verified host-staged fallback requires both directions and cleanup")
    elif fallback_status == "copy-failed":
        require(set(normalized) == {70, 120} and peer["cleanup_passed"] and
                not host_staged_copy_results_passed,
                "host-staged copy-failed requires a failed direction and clean resources")
    else:
        require(not peer["cleanup_passed"],
                "host-staged cleanup-failed requires failed cleanup")
    enabled_directions = sum(row["direct_access_enabled"]
                             for row in normalized.values())
    require(peer["direct_peer_access_enabled"] is (enabled_directions == 2),
            "overall peer-access flag contradicts directional access")
    copy_results_passed = (set(normalized) == {70, 120} and
                           all(row["data_integrity_passed"]
                               for row in normalized.values()))
    kernels_passed = all(not row["direct_kernel_attempted"] or
                         row["direct_kernel_passed"]
                         for row in normalized.values())
    if status in {"copy-only-verified", "one-way-peer-memory-verified",
                  "peer-memory-verified"}:
        require(peer["passed"] and copy_results_passed and kernels_passed and
                peer["cleanup_passed"] and all(
                    row["direct_kernel_attempted"] is row["direct_access_enabled"]
                    for row in normalized.values()),
                "verified peer status requires passing copies, kernels, and cleanup")
    else:
        require(not peer["passed"], "failed or unavailable peer status cannot pass")
    if status == "copy-only-verified":
        require(enabled_directions == 0 and
                all(not row["direct_kernel_attempted"] for row in normalized.values()),
                "copy-only status cannot claim peer-memory access")
    elif status == "one-way-peer-memory-verified":
        require(enabled_directions == 1,
                "one-way peer-memory status requires one enabled direction")
    elif status == "peer-memory-verified":
        require(enabled_directions == 2,
                "peer-memory status requires bidirectional enabled access")
    elif status == "peer-kernel-failed":
        require(set(normalized) == {70, 120} and peer["cleanup_passed"] and any(
            row["direct_kernel_attempted"] and not row["direct_kernel_passed"]
            for row in normalized.values()),
            "peer-kernel-failed requires both directions, a failed peer-memory kernel, and cleanup")
    elif status == "copy-failed":
        require(set(normalized) == {70, 120} and peer["cleanup_passed"] and
                not copy_results_passed and kernels_passed,
                "copy-failed requires both directions, a failed copy path, and successful cleanup")
    elif status == "cleanup-failed":
        require(not peer["cleanup_passed"],
                "cleanup-failed status requires failed cleanup")
    else:
        require(not peer["direct_peer_access_enabled"] and not peer["passed"] and
                all(not row["direct_access_enabled"] and
                    not row["direct_kernel_attempted"] and
                    not row["direct_kernel_passed"] and
                    not row["sync_copy_passed"] and
                    not row["async_copy_passed"] and
                    not row["data_integrity_passed"]
                    for row in normalized.values()),
                "unavailable peer status contains direct-transfer evidence")
    if peer["direct_peer_access_enabled"]:
        require(peer["sm70_can_access_sm120"] is True and
                peer["sm120_can_access_sm70"] is True,
                "direct peer access claim lacks bidirectional capability")
    require(not peer["passed"] or peer["cleanup_passed"],
            "peer-transfer success cannot omit cleanup")
    if expected_device_pci_by_sm is not None:
        require(set(expected_device_pci_by_sm) == {70, 120},
                "peer transfer requires the exact pinned SM70 and SM120 pair")
        if status != "pair-unavailable":
            try:
                sm70_pci = _canonical_peer_pci(peer.get("sm70_pci_bus_id"))
                sm120_pci = _canonical_peer_pci(peer.get("sm120_pci_bus_id"))
            except (TypeError, ValueError):
                raise ValueError("peer-transfer PCI identity is invalid") from None
            require(sm70_pci == _canonical_peer_pci(expected_device_pci_by_sm[70]) and
                    sm120_pci == _canonical_peer_pci(expected_device_pci_by_sm[120]),
                    "peer-transfer identities differ from the pinned GPU pair")


def validate_performance_benchmark_report(report: object, requested: bool,
                                          expected_samples: int | None = None,
                                          expected_transfer_samples: int | None = None) -> None:
    """Validate the bounded, per-device performance-reference report shape.

    This checks integrity and internal consistency only. It does not qualify a
    hybrid driver, certify hardware, or compare performance across machines.
    """
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(type(requested) is bool, "performance benchmark selection must be boolean")
    require(expected_samples is None or
            (type(expected_samples) is int and 9 <= expected_samples <= 1001),
            "expected performance sample count must be 9 through 1001")
    require(expected_transfer_samples is None or
            (type(expected_transfer_samples) is int and
             7 <= expected_transfer_samples <= 1001),
            "expected transfer sample count must be 7 through 1001")
    require(requested or (expected_samples is None and
                          expected_transfer_samples is None),
            "expected performance sample counts require a benchmark")
    require(isinstance(report, dict), "CUDA probe report must be an object")
    requested_field = report.get("performance_benchmark_requested")
    require((requested_field is True if requested else
             (requested_field is None or requested_field is False)),
            "performance benchmark request differs from the probe report")
    devices = report.get("devices")
    require(isinstance(devices, list), "CUDA probe devices must be a list")
    if requested:
        require(len(devices) == 1, "performance benchmark requires one PCI-selected device")

    def samples(values: object, count: int, label: str) -> list[float]:
        require(isinstance(values, list) and len(values) == count,
                f"invalid {label} sample count")
        require(all(type(value) in (int, float) and math.isfinite(value) and value > 0
                    for value in values), f"invalid {label} sample")
        return [float(value) for value in values]

    def summary(values: list[float], median_value: object, p95_value: object,
                label: str) -> None:
        sorted_values = sorted(values)
        middle = len(values) // 2
        expected_median = (sorted_values[middle] if len(values) % 2 else
                           (sorted_values[middle - 1] + sorted_values[middle]) / 2)
        expected_p95 = sorted_values[math.ceil(0.95 * len(values)) - 1]
        require(type(median_value) in (int, float) and math.isfinite(median_value) and
                math.isclose(median_value, expected_median, rel_tol=1e-9, abs_tol=1e-12),
                f"{label} median does not match its samples")
        require(type(p95_value) in (int, float) and math.isfinite(p95_value) and
                math.isclose(p95_value, expected_p95, rel_tol=1e-9, abs_tol=1e-12),
                f"{label} p95 does not match its samples")

    for device in devices:
        require(isinstance(device, dict), "CUDA device result must be an object")
        if not requested:
            if "performance_benchmark_passed" in device:
                require(device["performance_benchmark_passed"] is False,
                        "unrequested performance benchmark claim")
            if "performance_benchmark" in device:
                require(device["performance_benchmark"] is None,
                        "unrequested performance benchmark report")
            continue
        passed = device.get("performance_benchmark_passed")
        benchmark = device.get("performance_benchmark")
        require(type(passed) is bool, "performance benchmark result must be boolean")
        require(device.get("targeted") is True and passed is True,
                "selected CUDA device did not complete the performance benchmark")
        require(isinstance(benchmark, dict) and
                benchmark.get("schema") == "nvidia-cuda-performance-benchmark-v2" and
                benchmark.get("status") == "completed",
                "unsupported or incomplete CUDA performance benchmark")
        require(benchmark.get("timing_sources") == {
            "host": "std::chrono::steady_clock",
            "device": "CUDA events (cuEventElapsedTime)"},
            "unknown CUDA performance timing sources")
        sample_count = benchmark.get("samples")
        require(type(sample_count) is int and 9 <= sample_count <= 1001 and
                (expected_samples is None or sample_count == expected_samples) and
                benchmark.get("warmup_launches") == 64 and
                benchmark.get("launches_per_sample") == 256,
                "unexpected CUDA kernel-launch benchmark configuration or sample count")
        direct = benchmark.get("kernel_launch")
        require(isinstance(direct, dict) and direct.get("kernel") == "hybrid_empty" and
                direct.get("samples") == sample_count, "invalid direct kernel-launch measurement")
        direct_host = samples(direct.get("host_api_us_samples"), sample_count, "launch host API")
        direct_device = samples(direct.get("device_elapsed_us_samples"), sample_count,
                                "launch device elapsed")
        summary(direct_host, direct.get("host_api_us_median"),
                direct.get("host_api_us_p95"), "launch host API")
        summary(direct_device, direct.get("device_elapsed_us_median"),
                direct.get("device_elapsed_us_p95"), "launch device elapsed")
        graph = benchmark.get("cuda_graph_launch")
        require(isinstance(graph, dict), "missing CUDA Graph launch measurements")
        for key in ("host_api_us", "device_elapsed_us"):
            metric = graph.get(key)
            require(isinstance(metric, dict) and metric.get("samples") == sample_count,
                    f"invalid CUDA Graph {key} metric")
            values = samples(metric.get("values"), sample_count, f"CUDA Graph {key}")
            summary(values, metric.get("median"), metric.get("p95"),
                    f"CUDA Graph {key}")
        transfers = benchmark.get("transfers")
        required_sizes = [4096, 65536, 1048576, 16777216, 67108864]
        target_bytes_per_sample = 8 * 1024 * 1024
        require(isinstance(transfers, list) and
                [row.get("bytes") if isinstance(row, dict) else None for row in transfers]
                == required_sizes, "unexpected pinned-transfer sizes")
        transfer_sample_count = benchmark.get("transfer_samples")
        if transfer_sample_count is None:
            # Historical v2 reports used seven transfer samples with nine launch samples.
            transfer_sample_count = transfers[0].get("samples") if transfers else None
        require(type(transfer_sample_count) is int and
                7 <= transfer_sample_count <= 1001 and
                (expected_transfer_samples is None or
                 transfer_sample_count == expected_transfer_samples),
                "unexpected pinned-transfer sample count")
        for row in transfers:
            expected_iterations = max(1, target_bytes_per_sample // row["bytes"])
            require(row.get("samples") == transfer_sample_count and
                    type(row.get("iterations_per_sample")) is int and
                    row["iterations_per_sample"] == expected_iterations and
                    row.get("data_integrity_passed") is True,
                    "unexpected pinned-transfer iteration count or integrity metadata")
            for direction in ("h_to_d", "d_to_h"):
                metric = row.get(direction)
                require(isinstance(metric, dict) and
                        metric.get("data_integrity_passed") is True,
                        f"{direction} transfer integrity failed")
                host = samples(metric.get("host_api_us_per_copy_samples"), transfer_sample_count,
                               f"{direction} host API")
                device_elapsed = samples(
                    metric.get("device_elapsed_us_per_copy_samples"), transfer_sample_count,
                    f"{direction} device elapsed")
                bandwidth = samples(metric.get("gb_per_second_samples"), transfer_sample_count,
                                    f"{direction} bandwidth")
                summary(host, metric.get("host_api_us_per_copy_median"),
                        metric.get("host_api_us_per_copy_p95"), f"{direction} host API")
                summary(device_elapsed,
                        metric.get("device_elapsed_us_per_copy_median"),
                        metric.get("device_elapsed_us_per_copy_p95"),
                        f"{direction} device elapsed")
                summary(bandwidth, metric.get("gb_per_second_median"),
                        metric.get("gb_per_second_p95"), f"{direction} bandwidth")
                for elapsed_us, gb_per_second in zip(device_elapsed, bandwidth):
                    expected_gb_per_second = row["bytes"] / (elapsed_us * 1000.0)
                    require(math.isclose(gb_per_second, expected_gb_per_second,
                                         rel_tol=1e-9, abs_tol=1e-12),
                            f"{direction} bandwidth does not match per-copy device time")


def validate_graph_api_claim(api: object, cuda_graphs_requested: bool,
                             performance_benchmark_requested: bool) -> None:
    """Distinguish functional graph replay from the benchmark's one-node graph timing."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(type(cuda_graphs_requested) is bool and
            type(performance_benchmark_requested) is bool,
            "CUDA Graph request selection must be boolean")
    require(isinstance(api, str), "missing CUDA Graph API identity")
    if performance_benchmark_requested:
        require(api == "cuGraphInstantiateWithFlags",
                "performance benchmark requires its CUDA Graph launch API")
    elif cuda_graphs_requested:
        require(api in ("cuGraphInstantiateWithFlags", "unavailable"),
                "unknown CUDA Graph API identity")
    else:
        require(api == "not-requested", "unrequested CUDA Graph API claim")


def validate_probe_contract(
    probe_path: str | Path,
    expected_sha256: str | None = None,
    invoke: Callable = subprocess.run,
    require_performance_benchmark: bool = False,
    require_exact_device_map: bool = False,
    require_concurrent_dispatch: bool = False,
    require_peer_transfer: bool = False,
) -> dict[str, object]:
    """Require the probe build that reports the fields its runner validates.

    ``--contract`` is a no-CUDA command. Hash checks bind its response to the
    exact probe bytes prepared for upload and catch a local replacement race.
    """
    path = Path(probe_path).resolve(strict=True)
    if (type(require_performance_benchmark) is not bool or
            type(require_exact_device_map) is not bool or
            type(require_concurrent_dispatch) is not bool or
            type(require_peer_transfer) is not bool):
        raise ValueError("CUDA probe contract selection must be boolean")
    try:
        before = path.read_bytes()
    except OSError:
        raise ValueError("CUDA probe artifact cannot be read") from None
    digest = hashlib.sha256(before).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("CUDA probe artifact changed before contract check")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("CUDA probe artifact is not an executable regular file")

    try:
        result = invoke(
            [str(path), "--contract"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("CUDA probe report contract could not be read") from None
    if result.returncode != 0:
        raise ValueError(
            "CUDA probe report contract is missing; rebuild the probe with tools/build_probe.py"
        )
    try:
        contract = json.loads(result.stdout)
    except (TypeError, ValueError):
        raise ValueError("CUDA probe report contract is malformed") from None
    if not isinstance(contract, dict):
        raise ValueError("CUDA probe report contract is malformed")
    version = contract.get("contract_version")
    probe_fields = contract.get("probe_report_fields")
    device_fields = contract.get("device_report_fields")
    peer_report_schema = contract.get("peer_transfer_report_schema")
    peer_report_fields = contract.get("peer_transfer_fields")
    peer_direction_fields = contract.get("peer_transfer_direction_fields")
    if (contract.get("schema") != CONTRACT_SCHEMA or
            type(version) is not int or version < 4 or
            contract.get("probe_report_schema") != REPORT_SCHEMA or
            not isinstance(probe_fields, list) or
            any(type(field) is not str for field in probe_fields) or
            not REQUIRED_REPORT_FIELDS.issubset(probe_fields) or
            not isinstance(device_fields, list) or
            any(type(field) is not str for field in device_fields) or
            not REQUIRED_DEVICE_FIELDS.issubset(device_fields) or
            (require_exact_device_map and
             (version < 6 or
              not REQUIRED_EXACT_DEVICE_MAP_FIELDS.issubset(probe_fields))) or
            (require_performance_benchmark and
             (version < 5 or
              not REQUIRED_PERFORMANCE_REPORT_FIELDS.issubset(probe_fields) or
              not REQUIRED_PERFORMANCE_DEVICE_FIELDS.issubset(device_fields))) or
            (require_concurrent_dispatch and
             (version < 7 or
              not REQUIRED_CONCURRENT_DISPATCH_FIELDS.issubset(probe_fields))) or
            (require_peer_transfer and
             (version < 10 or
              not REQUIRED_PEER_TRANSFER_FIELDS.issubset(probe_fields) or
              peer_report_schema != PEER_TRANSFER_REPORT_SCHEMA or
              not isinstance(peer_report_fields, list) or
              not REQUIRED_PEER_TRANSFER_REPORT_FIELDS.issubset(peer_report_fields) or
              not isinstance(peer_direction_fields, list) or
              not REQUIRED_PEER_TRANSFER_DIRECTION_FIELDS.issubset(peer_direction_fields)))):
        raise ValueError("CUDA probe report contract is incompatible")

    try:
        after_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise ValueError("CUDA probe artifact changed during contract check") from None
    if after_digest != digest:
        raise ValueError("CUDA probe artifact changed during contract check")
    return {
        "schema": CONTRACT_SCHEMA,
        "contract_version": version,
        "probe_report_schema": REPORT_SCHEMA,
        "probe_sha256": digest,
    }
