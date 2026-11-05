#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a small, redacted receipt from a validated PC3 stock-GPU report."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SUMMARY_SCHEMA = "nvidia-hybrid-rtx-stock-phase-summary-v1"
REQUIRED_ARTIFACTS = {
    "cuda_probe_contract.py", "module", "observer", "probe", "runner"
}


class SummaryError(ValueError):
    """The input does not prove the narrow report contract being summarized."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dict(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise SummaryError(f"{name} must be an object")
    return value


def _bound_path(value: object, root: Path, *, evidence_only: bool = False) -> Path:
    if not isinstance(value, str) or not value:
        raise SummaryError("captured path is missing")
    path = Path(value)
    if path.is_symlink():
        raise SummaryError("captured path must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise SummaryError("captured path is missing or outside the project") from error
    if not resolved.is_file():
        raise SummaryError("captured path is not a regular file")
    if evidence_only:
        try:
            resolved.relative_to((root / "evidence" / "logs").resolve(strict=True))
        except (OSError, ValueError) as error:
            raise SummaryError("raw report must be kept under evidence/logs") from error
    return resolved


def _verify_artifacts(before: object, after: object, root: Path) -> dict:
    before = _dict(before, "local_artifacts")
    after = _dict(after, "local_artifacts_after")
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
        digest = sha256(content)
        if type(initial["bytes"]) is not int or initial["bytes"] != len(content):
            raise SummaryError(f"artifact size does not match: {name}")
        if initial["sha256"] != digest:
            raise SummaryError(f"artifact digest does not match: {name}")
        result[name] = {"bytes": len(content), "sha256": digest}
    return result


def _manifest_matches(left: object, right: object) -> bool:
    """Compare artifact content identity while intentionally ignoring private paths."""
    if not isinstance(left, dict) or not isinstance(right, dict) or set(left) != set(right):
        return False
    return all(
        isinstance(left[name], dict) and isinstance(right[name], dict)
        and left[name].get("bytes") == right[name].get("bytes")
        and left[name].get("sha256") == right[name].get("sha256")
        for name in left
    )


def summarize_report(report_path: Path, root: Path = ROOT) -> dict:
    """Validate and whitelist a single kernel-phase capture; never copy raw output."""
    report_path = _bound_path(str(report_path), root, evidence_only=True)
    raw_bytes = report_path.read_bytes()
    try:
        capture = _dict(json.loads(raw_bytes.decode("utf-8", "strict")), "capture")
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SummaryError("raw report is not valid UTF-8 JSON") from error

    if capture.get("schema") != "nvidia-hybrid-remote-selected-gpu-transport-v1":
        raise SummaryError("unexpected top-level capture schema")
    remote = _dict(capture.get("remote"), "remote report")
    phase_report = _dict(remote.get("phase_report"), "phase report")
    device = _dict(phase_report.get("selected_device"), "selected device")
    if capture.get("phase") != "kernel" or remote.get("phase") != "kernel" or phase_report.get("phase") != "kernel":
        raise SummaryError("capture is not a kernel phase")
    if capture.get("exit_code") != 0 or capture.get("ssh_exit_code") != 0 or remote.get("exit_code") != 0:
        raise SummaryError("capture did not complete with exit code zero")
    if capture.get("report_contract_validated") is not True or remote.get("report_contract_validated") is not True:
        raise SummaryError("local and remote report contracts did not both pass")
    if capture.get("qualification") != "rtx5080-cuda-phase-report-contract-valid":
        raise SummaryError("unexpected capture qualification")
    if capture.get("cuda_execution_validated") is not False or remote.get("cuda_execution_validated") is not False:
        raise SummaryError("the summary only accepts reports without independent hardware attestation")
    if phase_report.get("schema") != "nvidia-cuda-driver-phase-v1" or phase_report.get("status") != "phase-passed":
        raise SummaryError("unexpected CUDA phase report")
    if phase_report.get("numeric_result_passed") is not True or phase_report.get("cleanup_passed") is not True:
        raise SummaryError("numeric check or resource cleanup did not pass")
    if phase_report.get("cleanup_errors") != []:
        raise SummaryError("phase report contains cleanup errors")
    if (type(phase_report.get("expected_result")) is not int or
            type(phase_report.get("result_value")) is not int or
            phase_report.get("expected_result") != 1200 or phase_report.get("result_value") != 1200):
        raise SummaryError("numeric result differs from the pinned RTX probe expectation")
    if (device.get("name") != "NVIDIA GeForce RTX 5080" or device.get("pci_bus_id") != "0000:02:00.0"
            or device.get("compute_capability") != "12.0" or device.get("sm") != 120):
        raise SummaryError("selected device differs from the pinned RTX 5080 identity")
    if remote.get("device_alloc_records_seen") is not True or remote.get("device_alloc_payload_snapshots_read") != 2:
        raise SummaryError("device-allocation observer did not return the expected capture")
    cleanup = _dict(remote.get("remote_work_cleanup"), "remote cleanup")
    if cleanup.get("passed") is not True:
        raise SummaryError("remote temporary-work cleanup was not confirmed")

    before_lib_value = remote.get("system_libcuda_before")
    after_lib_value = remote.get("system_libcuda_after")
    library_hash = None
    library_hash_stable = None
    if before_lib_value is not None or after_lib_value is not None:
        before_lib = _dict(before_lib_value, "pre-test libcuda")
        after_lib = _dict(after_lib_value, "post-test libcuda")
        candidate_hash = before_lib.get("sha256")
        if (not isinstance(candidate_hash, str) or len(candidate_hash) != 64 or
                any(char not in "0123456789abcdef" for char in candidate_hash) or
                candidate_hash != after_lib.get("sha256")):
            raise SummaryError("system libcuda changed or its paired hashes are malformed")
        library_hash = candidate_hash
        library_hash_stable = True
    artifact_hashes = _verify_artifacts(
        capture.get("local_artifacts"), capture.get("local_artifacts_after"), root
    )
    if not _manifest_matches(remote.get("artifacts_before"), capture.get("local_artifacts")):
        raise SummaryError("remote and local pre-test artifact content differs")
    if not _manifest_matches(remote.get("artifacts_after"), capture.get("local_artifacts_after")):
        raise SummaryError("remote and local post-test artifact content differs")
    observed_at = capture.get("observed_at_utc")
    try:
        if not isinstance(observed_at, str):
            raise ValueError("timestamp must be text")
        parsed_time = datetime.fromisoformat(
            observed_at[:-1] + "+00:00" if observed_at.endswith("Z") else observed_at
        )
        if parsed_time.utcoffset() != timezone.utc.utcoffset(parsed_time):
            raise ValueError("timestamp must be UTC")
    except ValueError as error:
        raise SummaryError("capture timestamp is not a valid UTC timestamp") from error
    observed_at = parsed_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    kernel_release = remote.get("kernel_release")
    if (not isinstance(kernel_release, str) or not kernel_release or len(kernel_release) > 128 or
            any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-" for char in kernel_release)):
        raise SummaryError("kernel release is malformed")
    driver_api = phase_report.get("driver_api")
    if type(driver_api) is not int or driver_api <= 0:
        raise SummaryError("CUDA Driver API version is malformed")

    return {
        "schema": SUMMARY_SCHEMA,
        "observed_at_utc": observed_at,
        "qualification": "report-contract-valid-no-independent-hardware-attestation",
        "source_report": {"bytes": len(raw_bytes), "sha256": sha256(raw_bytes)},
        "phase": "kernel",
        "device": {
            "name": "NVIDIA GeForce RTX 5080",
            "pci_bus_id": "0000:02:00.0",
            "compute_capability": "12.0",
            "sm": 120,
        },
        "kernel_release": kernel_release,
        "cuda_driver_api_version": driver_api,
        "numeric_result": {
            "expected": 1200,
            "reported": 1200,
            "report_contract_passed": True,
        },
        "resource_cleanup_reported_passed": True,
        "device_alloc_observer": {
            "records_seen": True,
            "payload_snapshots_read": 2,
        },
        "system_libcuda_sha256_before_and_after": library_hash,
        "system_libcuda_hash_stable": library_hash_stable,
        "independent_hardware_attestation": False,
        "cuda_execution_validated": False,
        "artifacts": artifact_hashes,
    }


def write_new_json(path: Path, report: dict, root: Path = ROOT) -> None:
    """Write under the repository without replacing an existing receipt."""
    if path.is_symlink():
        raise SummaryError("output path must not be a symlink")
    parent = path.parent.resolve(strict=True)
    try:
        parent.relative_to((root / "evidence").resolve(strict=True))
    except ValueError as error:
        raise SummaryError("output directory must be under evidence/") from error
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with path.open("xb") as stream:
            stream.write(encoded)
    except FileExistsError as error:
        raise SummaryError("refusing to replace an existing receipt") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="ignored raw PC3 report under evidence/logs")
    parser.add_argument("--output", required=True, type=Path, help="new sanitized receipt path under the project")
    args = parser.parse_args(argv)
    try:
        report = summarize_report(args.input, ROOT)
        write_new_json(args.output, report, ROOT)
    except (OSError, SummaryError) as error:
        print(f"summary failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"qualification": report["qualification"], "output": str(args.output),
                      "source_sha256": report["source_report"]["sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
