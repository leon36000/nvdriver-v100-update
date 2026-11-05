#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run and privately record the exact-release CPU HAL lookup matrix."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.compare_openrm_gv100 import INPUTS, SOURCE_COMMITS  # noqa: E402
from tools.probe_r615_gv100_dispatch import (  # noqa: E402
    write_private_evidence_report,
)


TEST = ROOT / "tests/test_openrm_legacy_hal_lookup.py"
DEFAULT_EVIDENCE = ROOT / "evidence"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_private_raw_log(path, content, *, evidence_root=None):
    """Create a raw mode-0600 log beneath an evidence root without following links."""
    if evidence_root is None:
        evidence_root = ROOT.resolve(strict=True) / "evidence"
        path_error = "log path must be inside repository evidence"
    else:
        path_error = "log path must be inside evidence root"
    evidence_root = Path(evidence_root).resolve(strict=True)
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(evidence_root)
    except ValueError as error:
        raise ValueError(path_error) from error
    if not relative.parts or relative.name in ("", ".", ".."):
        raise ValueError("log path must name a file under evidence")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(evidence_root, directory_flags)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(
            relative.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("log destination is not a regular file")
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def run(report_path=None, log_path=None):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = Path(report_path) if report_path else (
            DEFAULT_EVIDENCE / f"openrm-hal-lookup-matrix-v2-{timestamp}.json"
    )
    log_path = Path(log_path) if log_path else (
            DEFAULT_EVIDENCE / "logs" / f"openrm-hal-lookup-matrix-v2-{timestamp}.log"
    )

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [
        sys.executable, "-B", "-m", "unittest",
        "tests.test_openrm_legacy_hal_lookup", "-v",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        raw_log = completed.stdout + completed.stderr
        ran_match = re.search(r"^Ran (\d+) tests? in ([0-9.]+)s$", raw_log, re.M)
        passed = (
            completed.returncode == 0
            and ran_match is not None
            and re.search(r"^OK$", raw_log, re.M) is not None
            and "FAILED" not in raw_log
            and "ERROR" not in raw_log
        )
        if ran_match is None:
            test_count, test_seconds = None, None
        else:
            test_count, test_seconds = int(ran_match.group(1)), float(ran_match.group(2))
        cases = [
            {
                "version": version,
                "repository_tag": version,
                "repository_commit": SOURCE_COMMITS[version],
                "archive": str((ROOT / ".cache/upstream" / filename).resolve()),
                "archive_sha256": expected_sha256,
                "test_case": "test_exact_registration_and_lookup_paths_for_all_pinned_releases",
                "result": "pass" if passed else "not-attributed",
                "scope": "The test iterates this exact pinned input as one subtest; any failed subtest makes the aggregate fail.",
            }
            for version, filename, _prefix, expected_sha256 in INPUTS
        ]
        implementation = {
            "tools/run_openrm_hal_lookup_matrix.py": _sha256(__file__),
            "tests/test_openrm_legacy_hal_lookup.py": _sha256(TEST),
            "tools/compare_openrm_gv100.py": _sha256(ROOT / "tools/compare_openrm_gv100.py"),
        }
        raw_log_bytes = raw_log.encode("utf-8")
        report = {
            "schema": "openrm-hal-lookup-matrix-v2",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "implementation_sha256": implementation,
            "unittest_tests_reported": test_count,
            "reported_seconds": test_seconds,
            "matrix_subtests": len(INPUTS),
            "cases": cases,
            "status": "pass" if passed else "fail",
            "process_exit_code": completed.returncode,
            "log": str(log_path),
            "log_sha256": hashlib.sha256(raw_log_bytes).hexdigest(),
            "qualification": "executed-source-contract-on-cpu",
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
            "limitations": [
                "The harness executes stock generated registration and lookup functions, but replaces registerHalModule_* with identity-only opaque tokens.",
                "No HAL callback, RM initialization, kernel module, GPU, or hardware path is exercised.",
                "A passing unittest aggregate establishes that every pinned subtest returned successfully; unittest does not emit a separate per-subtest pass line.",
            ],
        }
        _write_private_raw_log(log_path, raw_log_bytes)
        write_private_evidence_report(report_path, report)
        print(json.dumps(report, indent=2))
        return 0 if passed else 1
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"matrix runner failed: {error}", file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    return run(args.report, args.log)


if __name__ == "__main__":
    raise SystemExit(main())
