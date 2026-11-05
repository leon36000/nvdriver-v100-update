#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a redacted receipt for one pinned PC3 RTX CUDA Graphs run."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.summarize_pc3_rtx_stock_phase import (
    SummaryError,
    _bound_path,
    _dict,
    _manifest_matches,
    write_new_json,
)

SUMMARY_SCHEMA = "nvidia-hybrid-rtx-stock-cuda-graphs-summary-v1"
QUALIFICATION = "report-contract-valid-no-independent-hardware-attestation"
REQUIRED_ARTIFACTS = {"cuda_probe_contract.py", "module", "probe", "runner"}
PINNED_ARTIFACTS = {
    "cuda_probe_contract.py": "9f65e31214f0b323198460879e015967baa3feec855df1177d371a5b8cf28506",
    "module": "8dc12fa61f5ed270c3122f5516c2afce43d9c39f5fa9a16f9a7e313fe34f6f70",
    "probe": "c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422",
    "runner": "0384723a7962042137d6380a1db484ae112168d8384dc6662a00c7258d159840",
}
EXPECTED_SIZES = [1, 31, 256, 4096, 65537]
EXPECTED_SM_SET = [70, 120]
EXPECTED_LIBCUDA = "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d"


def _artifact_hashes(before: object, after: object, root: Path) -> dict:
    before = _dict(before, "local artifacts")
    after = _dict(after, "post-run local artifacts")
    if set(before) != REQUIRED_ARTIFACTS or set(after) != REQUIRED_ARTIFACTS:
        raise SummaryError("captured artifact set is incomplete or unexpected")
    result = {}
    for name in sorted(REQUIRED_ARTIFACTS):
        initial = _dict(before[name], f"artifact {name}")
        final = _dict(after[name], f"artifact after {name}")
        if set(initial) != {"bytes", "path", "sha256"} or initial != final:
            raise SummaryError(f"artifact changed or has an unexpected manifest: {name}")
        path = _bound_path(initial["path"], root)
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if type(initial["bytes"]) is not int or initial["bytes"] != len(content):
            raise SummaryError(f"artifact size does not match: {name}")
        if initial["sha256"] != digest or digest != PINNED_ARTIFACTS[name]:
            raise SummaryError(f"artifact digest differs from its reviewed pin: {name}")
        result[name] = {"bytes": len(content), "sha256": digest}
    return result


def _utc_timestamp(value: object) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError("timestamp must be text")
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("timestamp must be UTC")
    except ValueError as error:
        raise SummaryError("capture timestamp is not a valid UTC timestamp") from error
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def summarize_report(report_path: Path, root: Path = ROOT) -> dict:
    """Validate a full acceptance report and emit only a safe evidence allowlist."""
    report_path = _bound_path(str(report_path), root, evidence_only=True)
    if report_path.stat().st_mode & 0o077:
        raise SummaryError("raw report permissions must deny group and other access")
    raw = report_path.read_bytes()
    try:
        capture = _dict(json.loads(raw.decode("utf-8", "strict")), "capture")
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SummaryError("raw report is not valid UTF-8 JSON") from error

    if capture.get("schema") != "nvidia-hybrid-remote-selected-gpu-transport-v1":
        raise SummaryError("unexpected transport report schema")
    if (capture.get("target") != "pc3@pc3" or capture.get("host_key_alias") != "pc3" or
            capture.get("phase") is not None or capture.get("phase_capture_requested") is not False or
            capture.get("cuda_graphs_requested") is not True or
            capture.get("expected_libcuda_sha256") != EXPECTED_LIBCUDA):
        raise SummaryError("capture must be a full CUDA Graphs run, not a phase report")
    if (capture.get("exit_code") != 77 or capture.get("ssh_exit_code") != 77 or
            capture.get("report_contract_validated") is not True or
            capture.get("qualification") != "rtx5080-report-contract-valid-hybrid-incomplete" or
            capture.get("cuda_execution_validated") is not False):
        raise SummaryError("transport contract or expected incomplete-hybrid result differs")

    remote = _dict(capture.get("remote"), "remote report")
    if (remote.get("exit_code") != 77 or remote.get("report_contract_validated") is not True or
            remote.get("qualification") != "rtx5080-report-contract-valid-hybrid-incomplete" or
            remote.get("cuda_execution_validated") is not False or
            remote.get("cuda_graphs_requested") is not True or
            remote.get("cuda_graphs_report_contract_passed") is not True or
            remote.get("cuda_graphs_validated") is not False):
        raise SummaryError("remote CUDA Graph report contract is incomplete or overclaims validation")

    acceptance = _dict(remote.get("hardware_acceptance"), "hardware acceptance")
    if (acceptance.get("exit_code") != 77 or
            acceptance.get("qualification") != "incomplete-hardware-missing" or
            acceptance.get("validation_errors") != []):
        raise SummaryError("full acceptance result is malformed")
    probe = _dict(acceptance.get("probe"), "CUDA probe report")
    if (probe.get("schema") != "nvidia-hybrid-probe-v2" or
            probe.get("status") != "incomplete" or
            probe.get("hybrid_validated") is not False or
            probe.get("required_sm") != EXPECTED_SM_SET or
            probe.get("missing_sm") != [70] or
            probe.get("cuda_graphs_requested") is not True or
            probe.get("cuda_graph_api") != "cuGraphInstantiateWithFlags" or
            probe.get("required_set_passed") is not False or
            probe.get("performance_benchmark_requested") is not False or
            probe.get("peer_transfer_requested") is not False):
        raise SummaryError("probe does not show the expected stock RTX-only incomplete result")

    devices = probe.get("devices")
    if not isinstance(devices, list) or len(devices) != 1:
        raise SummaryError("probe must report exactly the selected RTX device")
    device = _dict(devices[0], "selected CUDA device")
    if (device.get("name") != "NVIDIA GeForce RTX 5080" or
            device.get("pci_bus_id") != "0000:02:00.0" or
            device.get("compute_capability") != "12.0" or device.get("sm") != 120 or
            device.get("tested") is not True or device.get("targeted") is not True or
            device.get("synchronous_passed") is not True or
            device.get("asynchronous_passed") is not True or
            device.get("synchronous_sizes") != EXPECTED_SIZES or
            device.get("asynchronous_sizes") != EXPECTED_SIZES or
            device.get("architecture_kernel_passed") is not True or
            device.get("cuda_graphs_passed") is not True or
            device.get("cuda_graph_launches") != 2 or
            device.get("cleanup_passed") is not True or
            device.get("cleanup_errors") != [] or device.get("error") != ""):
        raise SummaryError("selected RTX numeric, graph, or cleanup report did not pass")

    selection = _dict(remote.get("selected_nvidia_smi"), "selected nvidia-smi identity")
    selected = _dict(remote.get("device_selection"), "selected device request")
    if (selection.get("name") != "NVIDIA GeForce RTX 5080" or
            selection.get("pci") != "00000000:02:00.0" or
            selection.get("driver") != "595.99.02" or
            selected.get("pci") != "0000:02:00.0" or
            selected.get("uuid") != selection.get("uuid")):
        raise SummaryError("targeted stock GPU identity differs from the reviewed RTX")
    before_cuda, after_cuda = remote.get("system_libcuda_before"), remote.get("system_libcuda_after")
    before_cuda = _dict(before_cuda, "pre-run libcuda")
    after_cuda = _dict(after_cuda, "post-run libcuda")
    if (before_cuda.get("sha256") != EXPECTED_LIBCUDA or
            after_cuda.get("sha256") != EXPECTED_LIBCUDA or
            before_cuda.get("sha256") != after_cuda.get("sha256")):
        raise SummaryError("stock libcuda pin changed across the run")

    cleanup = _dict(remote.get("remote_work_cleanup"), "remote workspace cleanup")
    if (cleanup.get("attempted") is not True or cleanup.get("passed") is not True or
            cleanup.get("removed") is not True or cleanup.get("retained_for_inspection") is not False):
        raise SummaryError("remote temporary-work cleanup is not confirmed")

    trust = _dict(acceptance.get("probe_build_trust"), "pinned probe build trust")
    before_trust = _dict(trust.get("before_run"), "pre-run probe trust")
    after_trust = _dict(trust.get("after_run"), "post-run probe trust")
    if (trust.get("status") != "trusted-pinned-build" or before_trust != after_trust or
            before_trust.get("status") != "trusted-pinned-build" or
            before_trust.get("provenance") != "pinned-probe-and-fatbin-sha256" or
            before_trust.get("probe_sha256") != PINNED_ARTIFACTS["probe"] or
            before_trust.get("module_sha256") != PINNED_ARTIFACTS["module"]):
        raise SummaryError("probe build identity was not stable and pinned")

    artifacts = _artifact_hashes(capture.get("local_artifacts"),
                                 capture.get("local_artifacts_after"), root)
    if (not _manifest_matches(remote.get("artifacts_before"), capture.get("local_artifacts")) or
            not _manifest_matches(remote.get("artifacts_after"), capture.get("local_artifacts_after"))):
        raise SummaryError("remote and local artifact identities differ")
    kernel = remote.get("kernel_release")
    if (not isinstance(kernel, str) or len(kernel) > 128 or
            not re.fullmatch(r"[A-Za-z0-9._+-]+", kernel)):
        raise SummaryError("kernel release is malformed")
    if type(probe.get("driver_api")) is not int or probe["driver_api"] != 13020:
        raise SummaryError("CUDA Driver API version differs from the stock RTX report")

    return {
        "schema": SUMMARY_SCHEMA,
        "observed_at_utc": _utc_timestamp(capture.get("observed_at_utc")),
        "qualification": QUALIFICATION,
        "source_report": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "device": {"name": "NVIDIA GeForce RTX 5080", "pci_bus_id": "0000:02:00.0",
                   "compute_capability": "12.0", "sm": 120, "driver_version": "595.99.02"},
        "kernel_release": kernel,
        "cuda_driver_api_version": 13020,
        "cuda_graph_api": "cuGraphInstantiateWithFlags",
        "cuda_graph_replays_reported_passed": 2,
        "synchronous_and_asynchronous_kernel_sizes_reported_passed": EXPECTED_SIZES,
        "resource_cleanup_reported_passed": True,
        "system_libcuda_sha256_before_and_after": EXPECTED_LIBCUDA,
        "system_libcuda_hash_stable": True,
        "missing_sm": [70],
        "hybrid_validated": False,
        "independent_hardware_attestation": False,
        "cuda_execution_validated": False,
        "artifacts": artifacts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="ignored raw full-acceptance report under evidence/logs")
    parser.add_argument("--output", required=True, type=Path,
                        help="new sanitized receipt under evidence/")
    args = parser.parse_args(argv)
    try:
        report = summarize_report(args.input, ROOT)
        write_new_json(args.output, report, ROOT)
    except (OSError, SummaryError) as error:
        print(f"summary failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"qualification": report["qualification"],
                      "output": str(args.output),
                      "source_sha256": report["source_report"]["sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
