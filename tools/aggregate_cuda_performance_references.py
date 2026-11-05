#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate and summarize separate stock-driver CUDA performance references."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.cuda_probe_contract import validate_performance_benchmark_report

RTX_QUALIFICATION = "rtx5080-report-contract-valid-hybrid-incomplete"
V100_QUALIFICATION = "v100-reference-report-contract-valid"
BENCHMARK_SCHEMA = "nvidia-cuda-performance-benchmark-v2"
TRANSFER_SIZES = (4096, 65536, 1048576, 16777216, 67108864)
EXCLUDED_DIAGNOSTICS = (
    {
        "path": "evidence/pc3-rtx5080-performance-reference-v1-20261023T2345Z.json",
        "reason": "remote staging failed before CUDA because the required contract helper was omitted",
    },
    {
        "path": "evidence/pc3-rtx5080-performance-reference-v2-20261023T2347Z.json",
        "reason": "uses the superseded benchmark-v1 bandwidth normalization; remote qualification also rejected the graph API claim",
    },
    {
        "path": "evidence/pc3-rtx5080-performance-reference-v3-20261023T2350Z.json",
        "reason": "CUDA work completed under the old benchmark-v1 bandwidth formula, so per-copy small and medium transfer results are invalid",
    },
    {
        "path": "evidence/pc3-v100-performance-reference-v2-20261023T2356Z.json",
        "reason": "CUDA work completed, but the old graph API acceptance policy rejected the performance-only graph API claim",
    },
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def summarize_samples(values: list[float]) -> dict[str, object]:
    require(isinstance(values, list) and values and
            all(type(value) in (int, float) and math.isfinite(value) and value > 0
                for value in values),
            "timing sample set must contain finite positive numbers")
    ordered = sorted(float(value) for value in values)
    return {
        "sample_count": len(ordered),
        "median": statistics.median(ordered),
        "p95_nearest_rank": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "minimum": ordered[0],
        "maximum": ordered[-1],
        "values": ordered,
    }


def load_json(path: Path) -> tuple[dict, str]:
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot read evidence JSON {path}: {error}") from None
    require(isinstance(data, dict), f"evidence must be a JSON object: {path}")
    return data, hashlib.sha256(raw).hexdigest()


def verify_execution_attestation(root: dict) -> bool:
    """Return False until a detached-signature verifier and trusted key are installed.

    Fields inside a capture JSON (including ``cuda_execution_validated``) are
    assertions by that capture's producer. This project currently has no
    independently configured signing key or verifier, so they cannot qualify
    performance data for aggregation.
    """
    del root
    return False


def require_execution_attestation(root: dict, label: str) -> None:
    require(verify_execution_attestation(root),
            f"{label} benchmark aggregation is disabled: no independently "
            "verifiable execution attestation/signature verifier is configured")


def benchmark_and_device(probe: object, expected_sm: int) -> tuple[dict, dict]:
    require(isinstance(probe, dict), "missing CUDA probe report")
    require(probe.get("performance_benchmark_requested") is True,
            "reference did not request benchmark mode")
    validate_performance_benchmark_report(probe, True)
    devices = probe.get("devices")
    require(isinstance(devices, list) and len(devices) == 1,
            "reference must contain exactly one selected GPU")
    device = devices[0]
    require(device.get("sm") == expected_sm and device.get("targeted") is True and
            device.get("tested") is True and
            device.get("architecture_kernel_passed") is True and
            device.get("synchronous_passed") is True and
            device.get("asynchronous_passed") is True and
            device.get("cleanup_passed") is True and
            device.get("cleanup_errors") == [] and device.get("error") == "" and
            device.get("performance_benchmark_passed") is True,
            "selected GPU did not pass numeric, benchmark, and cleanup gates")
    benchmark = device.get("performance_benchmark")
    require(isinstance(benchmark, dict) and
            benchmark.get("schema") == BENCHMARK_SCHEMA and
            benchmark.get("status") == "completed",
            "reference does not contain corrected benchmark schema v2")
    require([row["bytes"] for row in benchmark["transfers"]] == list(TRANSFER_SIZES),
            "reference transfer sizes differ from the fixed protocol")
    return benchmark, device


def load_rtx_reference(path: Path) -> dict:
    root, evidence_sha256 = load_json(path)
    require_execution_attestation(root, "RTX")
    require(root.get("performance_benchmark_requested") is True,
            "RTX evidence did not request benchmark mode")
    remote = root.get("remote")
    require(isinstance(remote, dict) and
            remote.get("qualification") == RTX_QUALIFICATION and
            remote.get("performance_benchmark_validated") is True,
            "RTX evidence is not a validated stock-reference capture")
    commands = remote.get("commands")
    require(isinstance(commands, list), "RTX evidence has no remote command ledger")
    runners = [row for row in commands
               if isinstance(row, dict) and isinstance(row.get("argv"), list) and
               len(row["argv"]) >= 2 and row["argv"][0] == "/usr/bin/python3" and
               str(row["argv"][1]).endswith("/runner")]
    require(len(runners) == 1 and runners[0].get("exit_code") == 77,
            "RTX runner did not return the expected SM70-missing status")
    try:
        acceptance = json.loads(runners[0]["stdout"])
    except (TypeError, ValueError):
        raise ValueError("RTX acceptance output is missing or malformed") from None
    require(acceptance.get("qualification") == "incomplete-hardware-missing" and
            acceptance.get("performance_benchmark_requested") is True and
            acceptance.get("exit_code") == 77,
            "RTX result must remain an explicitly incomplete hybrid run")
    probe = acceptance.get("probe")
    benchmark, device = benchmark_and_device(probe, 120)
    require(probe.get("status") == "incomplete" and probe.get("missing_sm") == [70] and
            probe.get("hybrid_validated") is False and
            device.get("name") == "NVIDIA GeForce RTX 5080" and
            device.get("pci_bus_id") == "0000:02:00.0",
            "RTX identity or missing-SM70 boundary is inconsistent")
    selected = remote.get("selected_nvidia_smi")
    require(isinstance(selected, dict) and
            selected.get("name") == "NVIDIA GeForce RTX 5080" and
            selected.get("pci") == "00000000:02:00.0" and
            selected.get("uuid") == "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77" and
            selected.get("driver") == "595.99.02",
            "RTX nvidia-smi identity differs from the selected GPU")
    artifacts = acceptance.get("artifacts")
    local_artifacts = root.get("local_artifacts")
    require(isinstance(artifacts, dict) and isinstance(local_artifacts, dict) and
            artifacts.get("probe", {}).get("sha256") ==
            local_artifacts.get("probe", {}).get("sha256") and
            artifacts.get("module", {}).get("sha256") ==
            local_artifacts.get("module", {}).get("sha256"),
            "RTX remote and local artifact identities differ")
    return {
        "path": str(path.relative_to(ROOT)), "evidence_sha256": evidence_sha256,
        "observed_at_utc": acceptance["observed_at_utc"],
        "host": acceptance["host"], "kernel_release": acceptance["kernel_release"],
        "driver_version": selected["driver"], "driver_api": probe["driver_api"],
        "driver_library_path": probe["driver_library_path"],
        "gpu_name": device["name"], "gpu_uuid": selected["uuid"],
        "pci_bus_id": device["pci_bus_id"], "sm": device["sm"],
        "probe_sha256": artifacts["probe"]["sha256"],
        "fatbin_sha256": artifacts["module"]["sha256"], "benchmark": benchmark,
    }


def load_v100_reference(path: Path) -> dict:
    root, evidence_sha256 = load_json(path)
    require_execution_attestation(root, "V100")
    require(root.get("qualification") == V100_QUALIFICATION and
            root.get("performance_benchmark_requested") is True and
            root.get("exit_code") == 0,
            "V100 evidence is not a validated stock-reference capture")
    remote = root.get("remote")
    require(isinstance(remote, dict) and
            remote.get("qualification") == V100_QUALIFICATION and
            remote.get("performance_benchmark_requested") is True and
            remote.get("probe_exit_code") == 0,
            "V100 guest did not pass the numerical reference")
    execution = remote.get("execution_scope")
    require(isinstance(execution, dict) and
            execution.get("guest_driver_changed") is False and
            execution.get("module_loaded") is False and
            execution.get("pci_binding_changed") is False and
            execution.get("vm_management_issued") is False,
            "V100 reference changed driver, module, PCI binding, or VM state")
    probe = remote.get("probe")
    benchmark, device = benchmark_and_device(probe, 70)
    guest = remote.get("guest")
    require(isinstance(guest, dict) and
            guest.get("name") == "Tesla V100-SXM2-16GB" and
            guest.get("pci") == "0000:00:05.0" and
            guest.get("uuid") == "GPU-42d06a85-027a-75ea-7857-a8de27ad465e" and
            device.get("name") == guest["name"] and
            device.get("pci_bus_id") == guest["pci"] and
            probe.get("status") == "control-passed" and
            probe.get("missing_sm") == [] and
            probe.get("hybrid_validated") is False,
            "V100 identity or single-generation boundary is inconsistent")
    library = remote.get("driver_library")
    require(isinstance(library, dict) and
            library.get("path", "").endswith("libcuda.so.580.178.04"),
            "V100 reference did not use the installed R580 library")
    return {
        "path": str(path.relative_to(ROOT)), "evidence_sha256": evidence_sha256,
        "observed_at_utc": root["observed_at_utc"],
        "host": guest["hostname"], "kernel_release": guest["kernel_release"],
        "driver_version": guest["driver_version"], "driver_api": probe["driver_api"],
        "driver_library_path": library["path"], "driver_library_sha256": library["sha256"],
        "gpu_name": device["name"], "gpu_uuid": guest["uuid"],
        "pci_bus_id": device["pci_bus_id"], "sm": device["sm"],
        "temperature_c_before": int(guest["temperature_c_before"]),
        "utilization_percent_before": int(guest["utilization_percent_before"]),
        "probe_sha256": root["probe"]["sha256"],
        "fatbin_sha256": root["module"]["sha256"], "benchmark": benchmark,
    }


def pooled_metric(runs: list[dict], extractor) -> dict[str, object]:
    per_run = [extractor(run["benchmark"]) for run in runs]
    result = summarize_samples([value for group in per_run for value in group])
    result["per_run"] = [
        {"evidence": run["path"], **summarize_samples(values)}
        for run, values in zip(runs, per_run)
    ]
    return result


def summarize_group(runs: list[dict]) -> dict[str, object]:
    require(len(runs) >= 3, "at least three validated runs per GPU are required")
    require(len({run["path"] for run in runs}) == len(runs) and
            len({run["evidence_sha256"] for run in runs}) == len(runs) and
            len({run["observed_at_utc"] for run in runs}) == len(runs),
            "each reference run must be a distinct evidence capture")
    identity_keys = ("host", "kernel_release", "driver_version", "driver_api",
                     "driver_library_path", "gpu_name", "gpu_uuid", "pci_bus_id",
                     "sm", "probe_sha256", "fatbin_sha256")
    for key in identity_keys:
        require(len({run.get(key) for run in runs}) == 1,
                f"reference runs disagree on {key}")
    library_hashes = {run.get("driver_library_sha256") for run in runs
                      if "driver_library_sha256" in run}
    require(len(library_hashes) <= 1, "reference runs disagree on libcuda hash")
    launch = {
        "host_api_us_per_launch": pooled_metric(
            runs, lambda benchmark: benchmark["kernel_launch"]["host_api_us_samples"]),
        "device_elapsed_us_per_launch": pooled_metric(
            runs, lambda benchmark: benchmark["kernel_launch"]["device_elapsed_us_samples"]),
    }
    graph = {
        "host_api_us_per_replay": pooled_metric(
            runs, lambda benchmark: benchmark["cuda_graph_launch"]["host_api_us"]["values"]),
        "device_elapsed_us_per_replay": pooled_metric(
            runs, lambda benchmark: benchmark["cuda_graph_launch"]["device_elapsed_us"]["values"]),
    }
    transfers = []
    for size in TRANSFER_SIZES:
        transfer = {"bytes": size, "directions": {}}
        for direction in ("h_to_d", "d_to_h"):
            transfer["directions"][direction] = {
                "host_api_us_per_copy": pooled_metric(
                    runs, lambda benchmark, s=size, d=direction: next(
                        row[d]["host_api_us_per_copy_samples"]
                        for row in benchmark["transfers"] if row["bytes"] == s)),
                "device_elapsed_us_per_copy": pooled_metric(
                    runs, lambda benchmark, s=size, d=direction: next(
                        row[d]["device_elapsed_us_per_copy_samples"]
                        for row in benchmark["transfers"] if row["bytes"] == s)),
                "gb_per_second": pooled_metric(
                    runs, lambda benchmark, s=size, d=direction: next(
                        row[d]["gb_per_second_samples"]
                        for row in benchmark["transfers"] if row["bytes"] == s)),
            }
        transfers.append(transfer)
    first = runs[0]
    return {
        "identity": {key: first[key] for key in identity_keys},
        "driver_library_sha256": first.get("driver_library_sha256"),
        "validated_run_count": len(runs),
        "pooling_method": "pool per-process batch averages; report median and nearest-rank p95 across all batches; each per-run nearest-rank p95 is the maximum of its 7 or 9 samples",
        "runs": [{key: run[key] for key in run if key != "benchmark"}
                 for run in runs],
        "kernel_launch": launch, "cuda_graph_launch": graph,
        "pinned_transfers": transfers,
    }


def fmt(stats: dict) -> str:
    return f"{stats['median']:.3f} ({stats['p95_nearest_rank']:.3f})"


def render_markdown(report: dict) -> str:
    lines = [
        "# Separate stock-driver CUDA performance references",
        "",
        f"Generated {report['generated_at_utc']}. These are separate stock-environment baselines, not a hybrid-driver comparison.",
        "",
        f"Direct launch metrics are batch averages over 256 empty-kernel launches; graph metrics are batch averages over 256 one-node graph replays. The schema-v2 `host_api_us` values are host-side wall time per submitted operation, measured around the full submission lambda, including the Driver API wrapper and status check; they are not isolated call-only latency. CUDA-event elapsed values describe stream time around the empty-kernel operation, not useful kernel instruction time, and may include GPU idle bubbles while the host submits work. Pinned-copy bandwidth uses per-copy CUDA-event time, and the validator checks every sample against bytes divided by that elapsed time. Each capture has nine launch batches or seven transfer batches; its nearest-rank p95 is therefore its maximum observed batch. The pooled median and nearest-rank p95 summarize the batch observations across {report['rtx5080']['validated_run_count']} RTX processes and {report['v100']['validated_run_count']} V100 processes; with these sample counts, p95 is descriptive and not a stable tail-latency estimate.",
        "",
    ]
    for label, key in (("RTX 5080 — PC3 host", "rtx5080"),
                       ("Tesla V100 — PC3 guest VM", "v100")):
        group = report[key]
        identity = group["identity"]
        lines.extend([
            f"## {label}",
            "",
            f"{identity['gpu_name']} at {identity['pci_bus_id']} (SM{identity['sm']}); driver {identity['driver_version']}, Driver API {identity['driver_api']}, kernel {identity['kernel_release']} on {identity['host']}. The {group['validated_run_count']} runs use probe SHA-256 {identity['probe_sha256']} and fatbin SHA-256 {identity['fatbin_sha256']}.",
            "",
            "| Measurement | Median (p95) | Unit |",
            "|---|---:|---|",
            f"| Direct empty-kernel host submission wall time (wrapper + status check) | {fmt(group['kernel_launch']['host_api_us_per_launch'])} | µs/launch |",
            f"| Direct empty-kernel CUDA-event stream elapsed | {fmt(group['kernel_launch']['device_elapsed_us_per_launch'])} | µs/launch |",
            f"| One-node graph host submission wall time (wrapper + status check) | {fmt(group['cuda_graph_launch']['host_api_us_per_replay'])} | µs/replay |",
            f"| One-node graph CUDA-event stream elapsed | {fmt(group['cuda_graph_launch']['device_elapsed_us_per_replay'])} | µs/replay |",
            "",
            "| Pinned transfer size | H→D GB/s median (p95) | D→H GB/s median (p95) |",
            "|---:|---:|---:|",
        ])
        for transfer in group["pinned_transfers"]:
            h2d = transfer["directions"]["h_to_d"]["gb_per_second"]
            d2h = transfer["directions"]["d_to_h"]["gb_per_second"]
            lines.append(f"| {transfer['bytes']:,} bytes | {fmt(h2d)} | {fmt(d2h)} |")
        lines.extend(["", "Evidence files:"])
        for run in group["runs"]:
            lines.append(f"- {run['path']} — SHA-256 {run['evidence_sha256']}; observed {run['observed_at_utc']}.")
        if key == "rtx5080":
            lines.extend(["", "The host exposes SM120 only. The probe exits 77 because SM70 is absent and leaves hybrid_validated=false; this is an RTX-only stock reference."])
        else:
            lines.extend(["", "This capture uses the existing R580 V100 guest. It validates one SM70 device only and leaves hybrid_validated=false."])
        lines.append("")
    lines.extend([
        "## Limits",
        "",
        "The V100 guest and RTX 5080 host differ in GPU, Linux kernel, NVIDIA driver branch, VM boundary, and hardware path. Their values are reported separately and are not a speedup comparison. The empty kernel measures launch overhead, not useful model work; inference throughput and token latency were not measured. These isolated pinned-host copies do not measure UVM migration, P2P/NVLink, concurrent devices, or the proposed hybrid driver. No clock locking was used, so the results describe the observed stock environments and runtime state.",
        "",
        "## Excluded diagnostic captures",
        "",
        f"{len(EXCLUDED_DIAGNOSTICS)} diagnostic captures are excluded from the qualified summary and remain preserved:",
        *[f"- `{item['path']}` — {item['reason']}." for item in EXCLUDED_DIAGNOSTICS],
        "",
        "## Reproduction",
        "",
        "Build the SM70/SM120 probe bundle and run each stock GPU separately:",
        "",
        "    python3 tools/build_probe.py --output-dir build/probe-performance-v2-20261023",
        "",
        "    python3 tools/run_remote_selected_gpu.py --target pc3@pc3 --host-key-alias pc3 --gpu-uuid GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77 --pci 0000:02:00.0 --probe build/probe-performance-v2-20261023/hybrid_cuda_probe --module build/probe-performance-v2-20261023/hybrid_probe.sm70-sm120.fatbin --evidence evidence/rtx-reference.json --benchmark",
        "",
        "    python3 tools/run_pc3_v100_guest_reference.py --probe build/probe-performance-v2-20261023/hybrid_cuda_probe --module build/probe-performance-v2-20261023/hybrid_probe.sm70-sm120.fatbin --evidence evidence/v100-reference.json --benchmark",
        "",
        "Supply three unique evidence paths for each GPU using the repeated --rtx-report and --v100-report options of tools/aggregate_cuda_performance_references.py. It revalidates stock-reference qualification, PCI identity, common binary hashes, every raw benchmark sample, and every bandwidth/time pair before producing the JSON and Markdown outputs.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtx-report", type=Path, action="append", required=True)
    parser.add_argument("--v100-report", type=Path, action="append", required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rtx_runs = [load_rtx_reference(path.resolve(strict=True))
                    for path in args.rtx_report]
        v100_runs = [load_v100_reference(path.resolve(strict=True))
                     for path in args.v100_report]
        all_runs = rtx_runs + v100_runs
        require(len({run["probe_sha256"] for run in all_runs}) == 1,
                "references do not use one identical benchmark probe")
        require(len({run["fatbin_sha256"] for run in all_runs}) == 1,
                "references do not use one identical architecture fatbin")
        report = {
            "schema": "nvidia-cuda-performance-reference-summary-v1",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "qualification": "separate-stock-driver-reference-summaries",
            "benchmark_schema": BENCHMARK_SCHEMA,
            "common_artifacts": {
                "probe_sha256": all_runs[0]["probe_sha256"],
                "fatbin_sha256": all_runs[0]["fatbin_sha256"],
            },
            "rtx5080": summarize_group(rtx_runs),
            "v100": summarize_group(v100_runs),
            "interpretation": {
                "same_linux_hybrid_validated": False,
                "cross_gpu_speedup_claimed": False,
                "inference_throughput_measured": False,
                "p2p_or_uvm_performance_measured": False,
                "transfer_integrity_checked_each_run": True,
                "bandwidth_formula": "bytes per copy / CUDA-event microseconds per copy / 1000 = decimal GB/s",
            },
            "excluded_diagnostics": list(EXCLUDED_DIAGNOSTICS),
        }
        json_path = args.json_output.resolve()
        markdown_path = args.markdown_output.resolve()
        require(json_path != markdown_path, "summary output paths must differ")
        require(json_path.is_relative_to(ROOT) and markdown_path.is_relative_to(ROOT),
                "summary outputs must remain inside the canonical project")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        markdown_path.write_text(render_markdown(report))
        json_path.chmod(0o600)
        markdown_path.chmod(0o600)
        print(json.dumps({
            "qualification": report["qualification"],
            "rtx5080_runs": len(rtx_runs), "v100_runs": len(v100_runs),
            "json": str(json_path.relative_to(ROOT)),
            "markdown": str(markdown_path.relative_to(ROOT)),
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"qualification": "failed", "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
