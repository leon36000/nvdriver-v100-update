#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sanitize a pinned R580/R595 fault-buffer host-harness report and log."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402


EXPECTED_SCHEMA = "codex.volta-fault-init-host-harness.v4"
EXPECTED_CLASSIFICATION = "host-cpu-execution-of-pinned-volta-fault-buffer-lifecycle-v5"
R580_ARCHIVE_SHA256 = "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"
R595_ARCHIVE_SHA256 = "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4"
R595_COMMIT = "d8257d95ae5fed364163e4df51db66df8b1ee0d2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_HASHES = {
    "r580": {
        "service_source_sha256": "c7991f9a9e029ae1e9dc4aba579ecb37c64408d9600117abdeec82fbc1b245b3",
        "non_replayable_source_sha256": "588e72e5e3163f2e9a3c1b0d78a5450c97a4393b5b0c8e024915c41460d0250b",
        "gpu_header_sha256": "11f5a41820746ffb1bc2d70729eaca257eeea3ca71ecbf4fc31fa4a1f3bc5a01",
        "volta_source_sha256": "2f6bb4ea1fd81e3a495802b0181573ff339e317c22dfb745ee3b2f4207343653",
    },
    "r595": {
        "service_source_sha256": "e2b98f550ad6ef3efb062d931834f09acd79ecd5fa140a2f54de8e77a5dfac2b",
        "non_replayable_source_sha256": "83fd573b3f5187ded355dec0a835f293716b0d271204d2c617864346fac01888",
        "gpu_header_sha256": "76c578d204b32499e0004d1f1f43f9a1ce6718be13faa1394a5a63d0d1c7f9b5",
        "volta_source_sha256": "ca662fc33698586ec524c939593b6a67fb196d1b03fc6eea19116e5a0553254e",
    },
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} is missing or is not a SHA-256 digest")
    return value


def _true(value: object, label: str) -> None:
    if value is not True:
        raise ValueError(f"{label} is not proven true by the raw report")


def _false(value: object, label: str) -> None:
    if value is not False:
        raise ValueError(f"{label} must remain false for this host-only receipt")


def _record(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} is missing")
    return value


def _check_source_pair(value: object) -> tuple[dict, dict]:
    pair = _record(value, "pinned source pair")
    if set(pair) != {"r580", "r595"}:
        raise ValueError("source pair must contain exactly R580 and R595")
    selected = {}
    for name in ("r580", "r595"):
        source = _record(pair[name], f"{name} source record")
        for field, expected in SOURCE_HASHES[name].items():
            actual = _digest(source.get(field), f"{name}.{field}")
            if actual != expected:
                raise ValueError(f"{name} source profile does not match the pinned release")
        selected[name] = source
    for field in (
        "init_body_without_prefetch_expression_sha256",
        "deinit_body_without_prefetch_expression_sha256",
        "fault_buffer_reinit_body_sha256",
        "non_replayable_deinit_body_sha256",
    ):
        left = _digest(selected["r580"].get(field), f"r580.{field}")
        right = _digest(selected["r595"].get(field), f"r595.{field}")
        if left != right:
            raise ValueError(f"R580/R595 normalized lifecycle contract differs: {field}")
    _true(selected["r580"].get("prefetch_capability_read_present"),
          "R580 prefetch capability read")
    _true(selected["r580"].get("deinit_prefetch_capability_read_present"),
          "R580 deinit capability read")
    _false(selected["r595"].get("prefetch_capability_read_present"),
           "R595 prefetch capability read")
    _false(selected["r595"].get("deinit_prefetch_capability_read_present"),
           "R595 deinit capability read")
    r580_volta = _record(selected["r580"].get("volta_capability_initialization"),
                         "R580 Volta capability initialization")
    r595_volta = _record(selected["r595"].get("volta_capability_initialization"),
                         "R595 Volta capability initialization")
    _true(r580_volta.get("prefetch_fault_supported_true"),
          "R580 GV100 prefetch initialization")
    _false(r595_volta.get("prefetch_fault_supported_true"),
           "R595 retired prefetch capability field")
    return selected["r580"], selected["r595"]


def build_summary(raw: dict, raw_sha256: str, log_sha256: str) -> dict:
    """Validate pinned host execution and return only portable evidence."""
    if raw.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("unexpected fault-init host-harness schema")
    if raw.get("status") != "passed":
        raise ValueError("fault-init host harness did not pass")
    if raw.get("classification") != EXPECTED_CLASSIFICATION:
        raise ValueError("unexpected fault-init evidence classification")
    raw_sha256 = _digest(raw_sha256, "raw report digest")
    log_sha256 = _digest(log_sha256, "raw log digest")
    created_utc = raw.get("created_utc")
    if not isinstance(created_utc, str):
        raise ValueError("raw report timestamp is missing")
    try:
        created_datetime = datetime.fromisoformat(created_utc.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("raw report timestamp is invalid") from exc
    if created_datetime.tzinfo is None or created_datetime.utcoffset() is None:
        raise ValueError("raw report timestamp must include a timezone")
    created_utc = created_datetime.astimezone(timezone.utc).isoformat()
    if raw.get("checks_passed") != 420 or raw.get("checks_per_implementation") != 210:
        raise ValueError("host lifecycle check count changed")
    if raw.get("implementations_executed") != 2 or raw.get("vectors_per_implementation") != 15:
        raise ValueError("host lifecycle vector count changed")
    if raw.get("expected_guard_count") != 6:
        raise ValueError("host guard vector count changed")
    if raw.get("assertion_guards") != [
        "--probe-zero-utlb", "--probe-non-divisible-buffer-size", "--probe-tracker-nonempty"
    ]:
        raise ValueError("host assertion guard set changed")
    _false(raw.get("hardware_validated"), "hardware validation")
    _false(raw.get("module_loaded"), "module load")

    r580, r595 = _check_source_pair(raw.get("source_pair"))
    counterfactual = _record(raw.get("prefetch_false_counterfactual"),
                             "prefetch counterfactual")
    if counterfactual.get("r580") != "enabled=false; callback=disable_prefetch_faults":
        raise ValueError("R580 counterfactual vector changed")
    if counterfactual.get("r595") != "enabled=true; callback=enable_prefetch_faults":
        raise ValueError("R595 counterfactual vector changed")
    if counterfactual.get("scope") != (
            "synthetic field value; GV100 source initializes R580 capability true, and R595 has no such field"):
        raise ValueError("prefetch counterfactual scope changed")
    if raw.get("compile_flags") != ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]:
        raise ValueError("host compiler flag set changed")

    return {
        "schema": "volta-fault-init-host-harness-sanitized-v1",
        "created_utc": created_utc,
        "sanitized_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "classification": "host-cpu-source-function-execution-with-synthetic-collaborators",
        "source_profile": "R580.196.07 / R595.112.07",
        "source_revisions": {
            "r580_archive_sha256": R580_ARCHIVE_SHA256,
            "r595_archive_sha256": R595_ARCHIVE_SHA256,
            "r595_commit": R595_COMMIT,
        },
        "source_hashes": {"r580": SOURCE_HASHES["r580"], "r595": SOURCE_HASHES["r595"]},
        "normalized_lifecycle_hashes": {
            "init_without_prefetch_expression": r580["init_body_without_prefetch_expression_sha256"],
            "deinit_without_prefetch_expression": r580["deinit_body_without_prefetch_expression_sha256"],
            "replayable_reinit": r580["fault_buffer_reinit_body_sha256"],
            "non_replayable_deinit": r580["non_replayable_deinit_body_sha256"],
        },
        "prefetch_capability_delta": {
            "r580_field_present_and_read": True,
            "r580_gv100_capability_initialized_true": True,
            "r595_legacy_field_present": False,
            "r595_prefetch_state_uses_runtime_field": True,
            "false_state_vector_is_synthetic_counterfactual": True,
        },
        "host_execution": {
            "implementations": 2,
            "vectors_per_implementation": 15,
            "checks_per_implementation": 210,
            "checks_passed": 420,
            "assertion_guard_count": 6,
            "compile_flags": raw.get("compile_flags"),
        },
        "raw_report_sha256": raw_sha256,
        "raw_log_sha256": log_sha256,
        "hardware_validated": False,
        "module_loaded": False,
        "cuda_validated": False,
        "limitations": [
            "The harness compiles and executes exact source functions on the CPU with synthetic RM, allocator, tracker, HAL, and ownership collaborators.",
            "It does not execute the Linux UVM ABI, RM implementation, module, GPU, DMA, interrupts, CUDA context, or live fault delivery.",
            "The R595 prefetch-false vector is a synthetic counterfactual, not an observed or supported GPU state.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw_path = args.input.resolve(strict=True)
        log_path = args.log.resolve(strict=True)
        raw_bytes = raw_path.read_bytes()
        log_bytes = log_path.read_bytes()
        raw = json.loads(raw_bytes)
        summary = build_summary(raw, _sha256(raw_bytes), _sha256(log_bytes))
        output_candidate = Path(args.output)
        if not output_candidate.is_absolute():
            output_candidate = ROOT / output_candidate
        output_path = Path(os.path.abspath(output_candidate))
        write_private_evidence_report(output_path, summary, repository_root=ROOT)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "schema": summary["schema"],
        "receipt_sha256": _sha256(output_path.read_bytes()),
        "checks_passed": summary["host_execution"]["checks_passed"],
        "hardware_validated": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
