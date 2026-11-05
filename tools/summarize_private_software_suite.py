#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sanitize a pinned software-suite report and its private unittest log."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.run_software_test_suite import (  # noqa: E402
    PINNED_PROBE_FATBIN_SHA256,
    PINNED_PROBE_SHA256,
)

HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
RUN_LINE = re.compile(rb"^Ran ([0-9]+) tests? in ([0-9]+(?:\.[0-9]+)?)s$", re.M)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_private_regular(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for private suite evidence")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode), "private suite input must be a regular file")
        _require(stat.S_IMODE(before.st_mode) == 0o600,
                 "private suite input must have mode 0600")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read()
        after = os.fstat(descriptor)
        _require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 "private suite input changed while being read")
        _require(len(payload) == before.st_size, "private suite input short read")
        return payload
    finally:
        os.close(descriptor)


def _validate_hash_map(value: object, label: str) -> dict[str, str]:
    _require(isinstance(value, dict) and bool(value), f"{label} hash map is missing")
    for name, digest in value.items():
        _require(isinstance(name, str) and isinstance(digest, str) and
                 HEX_DIGEST.fullmatch(digest) is not None,
                 f"{label} hash map contains an invalid entry")
    return value


def receipt_from_private_inputs(report_raw: bytes, log_raw: bytes) -> dict:
    try:
        report = json.loads(report_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("suite report is not UTF-8 JSON") from error
    _require(isinstance(report, dict), "suite report must be a JSON object")
    _require(report.get("schema") == "software-verification-openrm-hal-matrix-v1",
             "suite report schema is unsupported")
    _require(report.get("status") == "pass" and report.get("process_exit_code") == 0,
             "software suite did not pass")
    _require(report.get("qualification") == "software-suite-only" and
             report.get("runtime_or_hardware_validated") is False and
             report.get("loaded_or_installed") is False,
             "suite report overstates its qualification")
    _require(report.get("test_source_changes") == [] and
             report.get("implementation_source_changes") == [],
             "suite inputs changed while tests were running")

    tests_before = _validate_hash_map(report.get("test_source_sha256"), "test source")
    tests_after = _validate_hash_map(report.get("test_source_sha256_after"), "final test source")
    implementation_before = _validate_hash_map(
        report.get("implementation_sha256"), "implementation"
    )
    implementation_after = _validate_hash_map(
        report.get("implementation_sha256_after"), "final implementation"
    )
    _require(tests_before == tests_after, "test source hashes changed during the suite")
    _require(implementation_before == implementation_after,
             "implementation hashes changed during the suite")

    probe = report.get("probe")
    _require(isinstance(probe, dict) and probe.get("sha256") == PINNED_PROBE_SHA256,
             "suite report does not identify the pinned CUDA probe")
    _require(isinstance(probe.get("build_manifest"), dict),
             "suite report has no pinned probe manifest")
    fatbin_hash = report.get("probe_fatbin_sha256")
    # The current runner predates an explicit fatbin report field; its pinned
    # probe contract still binds the fatbin hash used by the suite.
    _require(fatbin_hash in (None, PINNED_PROBE_FATBIN_SHA256),
             "suite report identifies an unexpected CUDA probe fatbin")

    log_sha256 = hashlib.sha256(log_raw).hexdigest()
    _require(report.get("log_sha256") == log_sha256,
             "private suite log does not match its report digest")
    match = RUN_LINE.search(log_raw)
    _require(match is not None and re.search(rb"^OK$", log_raw, re.M) is not None,
             "private suite log has no successful unittest terminal summary")
    tests_run = report.get("tests_run")
    try:
        reported_seconds = float(report.get("reported_seconds"))
    except (TypeError, ValueError) as error:
        raise ValueError("suite runtime is missing") from error
    _require(isinstance(tests_run, int) and not isinstance(tests_run, bool) and
             tests_run == int(match.group(1)),
             "suite test count disagrees with the private log")
    _require(reported_seconds >= 0 and
             abs(reported_seconds - float(match.group(2))) < 0.0001,
             "suite duration disagrees with the private log")

    return {
        "schema": "software-verification-sanitized-v1",
        "classification": "pinned-cpu-software-suite",
        "status": "pass",
        "qualification": "software-suite-only",
        "tests_run": tests_run,
        "reported_seconds": reported_seconds,
        "test_input_count": len(tests_before),
        "implementation_input_count": len(implementation_before),
        "test_inputs_unchanged": True,
        "implementation_inputs_unchanged": True,
        "pinned_probe_sha256": PINNED_PROBE_SHA256,
        "pinned_probe_fatbin_sha256": PINNED_PROBE_FATBIN_SHA256,
        "private_report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "private_log_sha256": log_sha256,
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "limitations": [
            "This verifies only the pinned CPU/software test suite.",
            "It does not validate kernel-module loading, GPU initialization, CUDA runtime behavior, or hardware.",
            "Private reports and logs containing machine paths are excluded.",
        ],
    }


def write_new_receipt(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise ValueError("receipt output must not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_report", type=Path)
    parser.add_argument("private_log", type=Path)
    parser.add_argument("sanitized_output", type=Path)
    args = parser.parse_args(argv)
    try:
        report_raw = read_private_regular(args.private_report)
        log_raw = read_private_regular(args.private_log)
        receipt = receipt_from_private_inputs(report_raw, log_raw)
        parent = args.sanitized_output.parent.resolve(strict=True)
        _require(parent.is_relative_to(ROOT), "sanitized output must stay in the repository")
        output = parent / args.sanitized_output.name
        encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_new_receipt(output, encoded)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({
        "path": args.sanitized_output.as_posix(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "tests_run": receipt["tests_run"],
        "qualification": receipt["qualification"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
