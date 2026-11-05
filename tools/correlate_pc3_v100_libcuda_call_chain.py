#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correlate redacted V100 runtime return offsets with bounded Ghidra xrefs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LIBCUDA_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
EXPECTED_LIBCUDA_SIZE = 96_284_520
EXPECTED_CALLSITE_RVA = 0x48BC88
EXPECTED_MASKS = (9, 8, 1, 0)
HEX_RVA = re.compile(r"0x[0-9a-f]+\Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _offset(value: object, label: str) -> int:
    _require(isinstance(value, str) and HEX_RVA.fullmatch(value) is not None,
             f"{label} is malformed or not redacted")
    number = int(value, 16)
    _require(0 < number < EXPECTED_LIBCUDA_SIZE,
             f"{label} is outside the pinned libcuda image")
    return number


def correlate_reports(sensitivity: object, ghidra: object) -> dict[str, object]:
    """Validate both reports and correlate the first runtime caller frame to a Ghidra xref."""
    _require(isinstance(sensitivity, dict) and
             sensitivity.get("schema") == "nvidia-hybrid-v100-system-features-sensitivity-v1" and
             sensitivity.get("status") == "complete" and
             sensitivity.get("complete") is True and
             sensitivity.get("caller_chain_capture_requested") is True and
             sensitivity.get("api_outcomes_equal") is True and
             sensitivity.get("control_outcomes_equal") is True,
             "complete caller-chain sensitivity evidence is required")
    guest = sensitivity.get("guest")
    _require(isinstance(guest, dict) and guest.get("hostname") == "pc3-v100" and
             guest.get("kernel_release") == "6.8.0-147-generic",
             "sensitivity evidence is not from the pinned V100 guest")
    gpu = guest.get("gpu")
    _require(isinstance(gpu, dict) and gpu.get("name", "").startswith("Tesla V100") and
             gpu.get("uuid") == "GPU-42d06a85-027a-75ea-7857-a8de27ad465e" and
             gpu.get("pci") == "0000:00:05.0" and gpu.get("driver_version") == "580.178.04",
             "sensitivity GPU identity differs from the pinned V100")
    libcuda = guest.get("libcuda")
    _require(isinstance(libcuda, dict) and
             libcuda.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
             libcuda.get("driver_api") == 13000,
             "sensitivity libcuda identity differs from the pinned R580 image")

    runs = sensitivity.get("runs")
    _require(isinstance(runs, list) and len(runs) == len(EXPECTED_MASKS),
             "four ordered mask observations are required")
    first_chain: list[str] | None = None
    for expected_mask, run in zip(EXPECTED_MASKS, runs):
        _require(isinstance(run, dict) and run.get("requested_mask") == expected_mask and
                 type(run.get("requested_mask")) is int and
                 run.get("probe_exit_code") == 0,
                 "mask observations are missing, reordered, or unsuccessful")
        cuda = run.get("cuda")
        _require(isinstance(cuda, dict) and cuda.get("cu_init") == 0 and
                 cuda.get("device_count") == 1 and cuda.get("driver_api") == 13000,
                 "mask run did not preserve the pinned CUDA enumeration outcome")
        records = run.get("ioctl_records")
        _require(isinstance(records, list) and len(records) == 1,
                 "expected one SYSTEM_GET_FEATURES record per mask")
        record = records[0]
        _require(isinstance(record, dict) and record.get("transport") == "direct" and
                 record.get("kernel_mask") == 9 and record.get("exposed_mask") == expected_mask and
                 record.get("caller_image") == "libcuda.so.580.178.04" and
                 _offset(record.get("caller_offset"), "ioctl return RVA") == EXPECTED_CALLSITE_RVA and
                 record.get("caller_chain_anchor_found") is True and
                 record.get("caller_chain_truncated") is False,
                 "runtime callsite or mask record is inconsistent")
        chain = record.get("caller_chain_offsets")
        _require(isinstance(chain, list) and 1 <= len(chain) <= 8,
                 "bounded runtime caller chain is missing")
        for offset in chain:
            _offset(offset, "caller-chain RVA")
        if first_chain is None:
            first_chain = list(chain)
        else:
            _require(chain == first_chain,
                     "runtime caller chain is not stable across mask runs")

    _require(isinstance(ghidra, dict) and
             ghidra.get("schema") == "nvidia-hybrid-pc3-v100-libcuda-ghidra-function-v2" and
             ghidra.get("status") == "static_analysis_passed",
             "pinned Ghidra function metadata is required")
    input_meta = ghidra.get("input")
    finding = ghidra.get("finding")
    _require(isinstance(input_meta, dict) and
             input_meta.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
             isinstance(finding, dict) and
             _offset(finding.get("target_rva"), "Ghidra target RVA") == EXPECTED_CALLSITE_RVA and
             _offset(finding.get("function_entry_rva"), "Ghidra function entry RVA") <= EXPECTED_CALLSITE_RVA <
             int(str(finding.get("function_end_rva_exclusive")), 16),
             "Ghidra metadata is not for the observed pinned ioctl callsite")
    callers = finding.get("incoming_callers")
    _require(isinstance(callers, list) and type(finding.get("incoming_callers_truncated")) is bool,
             "bounded incoming caller references are missing")
    runtime_return = _offset(first_chain[0] if first_chain else None,
                             "first runtime caller return RVA")
    matches: list[dict[str, object]] = []
    for caller in callers:
        if not isinstance(caller, dict) or caller.get("reference_type") != "UNCONDITIONAL_CALL":
            continue
        try:
            source = _offset(caller.get("source_rva"), "static caller instruction RVA")
            entry = _offset(caller.get("source_function_entry_rva"),
                            "static caller function entry RVA")
        except ValueError:
            continue
        if source + 5 == runtime_return and isinstance(caller.get("source_function_name"), str):
            matches.append({
                "source_rva": f"0x{source:x}",
                "function_entry_rva": f"0x{entry:x}",
                "function_name": caller["source_function_name"],
                "reference_type": caller["reference_type"],
                "observed_return_delta_bytes": runtime_return - source,
            })
    _require(len(matches) == 1,
             "no static caller reference uniquely matches the runtime return offset")

    return {
        "schema": "nvidia-hybrid-v100-libcuda-call-chain-correlation-v1",
        "status": "correlated_static_and_runtime_metadata",
        "observation": {
            "gpu": {key: gpu[key] for key in ("name", "uuid", "pci", "driver_version")},
            "kernel_release": guest["kernel_release"],
            "libcuda_sha256": EXPECTED_LIBCUDA_SHA256,
            "driver_api": libcuda["driver_api"],
            "direct_ioctl_return_rva": f"0x{EXPECTED_CALLSITE_RVA:x}",
            "direct_function_name": finding["function_name"],
            "direct_function_entry_rva": finding["function_entry_rva"],
            "runtime_first_caller_return_rva": f"0x{runtime_return:x}",
            "static_call_reference": matches[0],
            "static_incoming_callers_truncated": finding["incoming_callers_truncated"],
            "caller_chain_offsets": first_chain,
            "same_chain_across_masks": True,
            "masks": list(EXPECTED_MASKS),
            "kernel_mask_per_run": 9,
            "controls_equal": True,
            "api_outcomes_equal": True,
        },
        "interpretation": (
            "The immediate runtime caller return offset matches the source RVA plus five bytes "
            "for one static unconditional-call reference into the observed ioctl helper. "
            "Ghidra's FUN_* labels are analysis-generated, not NVIDIA source names."
        ),
        "limits": [
            "The callsite correlation does not establish the caller's semantic purpose.",
            "It does not prove where SYSTEM_GET_FEATURES bits are consumed.",
            "The Ghidra incoming-reference list was truncated; the matched reference is present in its retained sample.",
            "No context creation, allocation, kernel execution, UVM migration, P2P, or hybrid driver path was exercised.",
        ],
    }


def correlate_stack_reports(sensitivity: object, ghidra_multi: object) -> dict[str, object]:
    """Map the observed return RVAs to Ghidra functions and classify static call edges."""
    _require(isinstance(ghidra_multi, dict) and
             ghidra_multi.get("schema") ==
             "nvidia-hybrid-pc3-v100-libcuda-ghidra-multi-function-v1" and
             ghidra_multi.get("status") == "static_analysis_passed",
             "multi-target Ghidra metadata is required")
    input_meta = ghidra_multi.get("input")
    findings = ghidra_multi.get("findings")
    _require(isinstance(input_meta, dict) and
             input_meta.get("sha256") == EXPECTED_LIBCUDA_SHA256 and
             isinstance(findings, list) and 1 <= len(findings) <= 8,
             "multi-target Ghidra input identity or finding count is invalid")

    by_target: dict[int, dict[str, object]] = {}
    for finding in findings:
        _require(isinstance(finding, dict), "Ghidra function finding is malformed")
        target = _offset(finding.get("target_rva"), "Ghidra target RVA")
        entry = _offset(finding.get("function_entry_rva"), "Ghidra function entry RVA")
        end_value = finding.get("function_end_rva_exclusive")
        _require(isinstance(end_value, str) and HEX_RVA.fullmatch(end_value) is not None,
                 "Ghidra function end RVA is malformed")
        end = int(end_value, 16)
        name = finding.get("function_name")
        count = finding.get("instruction_count")
        outgoing = finding.get("outgoing_calls")
        outgoing_truncated = finding.get("outgoing_calls_truncated")
        _require(entry <= target < end and isinstance(name, str) and
                 re.fullmatch(r"[A-Za-z0-9_.$?<>:+@-]{1,256}", name) is not None and
                 type(count) is int and count > 0 and isinstance(outgoing, list) and
                 type(outgoing_truncated) is bool,
                 "Ghidra function metadata is malformed or does not contain its target")
        _require(target not in by_target, "duplicate Ghidra target RVA")
        by_target[target] = finding

    direct = EXPECTED_CALLSITE_RVA
    chain: list[int] | None = None
    if isinstance(sensitivity, dict):
        runs = sensitivity.get("runs")
        if isinstance(runs, list) and runs and isinstance(runs[0], dict):
            records = runs[0].get("ioctl_records")
            if isinstance(records, list) and records and isinstance(records[0], dict):
                raw_chain = records[0].get("caller_chain_offsets")
                if isinstance(raw_chain, list):
                    chain = [_offset(value, "runtime caller-chain RVA") for value in raw_chain]
    _require(chain is not None and 1 <= len(chain) <= 8,
             "complete V100 caller-chain sensitivity evidence is required")

    first_finding = by_target.get(direct)
    _require(first_finding is not None,
             "multi-target Ghidra report is missing the direct ioctl callsite")
    single_report = {
        "schema": ghidra_multi["schema"].replace("multi-function-v1", "function-v2"),
        "status": ghidra_multi["status"],
        "input": input_meta,
        "finding": first_finding,
    }
    primary = correlate_reports(sensitivity, single_report)

    target_sequence = [direct, *chain]
    _require(len(set(target_sequence)) == len(target_sequence) and
             all(target in by_target for target in target_sequence),
             "multi-target Ghidra report does not cover the exact runtime stack")
    runtime_frames: list[dict[str, object]] = []
    for target in target_sequence:
        finding = by_target[target]
        runtime_frames.append({
            "return_rva": f"0x{target:x}",
            "function_name": finding["function_name"],
            "function_entry_rva": finding["function_entry_rva"],
            "function_end_rva_exclusive": finding["function_end_rva_exclusive"],
            "instruction_count": finding["instruction_count"],
            "incoming_callers_truncated": finding.get("incoming_callers_truncated"),
            "outgoing_calls_truncated": finding["outgoing_calls_truncated"],
        })

    call_edges: list[dict[str, object]] = []
    for index in range(1, len(target_sequence)):
        caller_return = target_sequence[index]
        caller = by_target[caller_return]
        callee = by_target[target_sequence[index - 1]]
        callee_entry = str(callee["function_entry_rva"])
        nearby: list[dict[str, object]] = []
        matched: list[dict[str, object]] = []
        for reference in caller["outgoing_calls"]:
            if not isinstance(reference, dict) or reference.get("reference_type") not in (
                    "UNCONDITIONAL_CALL", "COMPUTED_CALL", "CONDITIONAL_CALL"):
                continue
            try:
                source = _offset(reference.get("source_rva"), "outgoing-call source RVA")
            except ValueError:
                continue
            delta = caller_return - source
            if not 1 <= delta <= 15:
                continue
            item = {
                "source_rva": f"0x{source:x}",
                "target_rva": reference.get("target_rva"),
                "target_name": reference.get("target_name"),
                "reference_type": reference["reference_type"],
                "return_delta_bytes": delta,
            }
            nearby.append(item)
            if reference.get("target_rva") == callee_entry:
                matched.append(item)
        if len(matched) == 1:
            edge_status = "matched_static_call_reference"
        elif len(matched) > 1:
            edge_status = "ambiguous_static_call_references"
        elif nearby:
            edge_status = "nearby_reference_target_unresolved"
        elif caller["outgoing_calls_truncated"]:
            edge_status = "not_in_retained_reference_sample"
        else:
            edge_status = "no_matching_static_call_reference"
        call_edges.append({
            "caller_return_rva": f"0x{caller_return:x}",
            "caller_function_name": caller["function_name"],
            "callee_return_rva": f"0x{target_sequence[index - 1]:x}",
            "callee_function_name": callee["function_name"],
            "status": edge_status,
            "matching_references": matched,
            "nearby_call_references": nearby,
            "outgoing_reference_sample_truncated": caller["outgoing_calls_truncated"],
        })

    resolved = sum(edge["status"] == "matched_static_call_reference" for edge in call_edges)
    return {
        "status": "complete_stack_static_correlation" if resolved == len(call_edges)
                  else "partial_stack_static_correlation",
        "runtime_frames": runtime_frames,
        "call_edges": call_edges,
        "static_edges_resolved": resolved,
        "static_edges_total": len(call_edges),
        "first_frame_correlation": primary["observation"]["static_call_reference"],
        "same_chain_across_masks": True,
        "limits": [
            "Runtime frame membership and return offsets are observed; Ghidra function names are analysis-generated labels.",
            "Unmatched static edges may involve indirect dispatch, function-boundary mistakes, or missing references; they are unresolved, not proof of absence.",
            "The presence of cuInit in this stack identifies the tested entry path only; it does not establish feature-mask dataflow or behavior on other API paths.",
        ],
    }


def read_private_json(path: Path) -> tuple[dict[str, object], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence input")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                 "evidence inputs must be regular mode-0600 files")
        chunks = []
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
            digest.update(chunk)
        value = json.loads(b"".join(chunks).decode("utf-8", "strict"))
    finally:
        os.close(descriptor)
    _require(isinstance(value, dict), "evidence input must contain one JSON object")
    return value, digest.hexdigest()


def write_private_new(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensitivity-report", type=Path, required=True)
    parser.add_argument("--ghidra-report", type=Path, required=True)
    parser.add_argument("--stack-ghidra-report", type=Path,
                        help="optional one-import metadata report for all runtime stack RVAs")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        sensitivity, sensitivity_sha = read_private_json(args.sensitivity_report)
        ghidra, ghidra_sha = read_private_json(args.ghidra_report)
        report = correlate_reports(sensitivity, ghidra)
        report["inputs"] = {}
        if args.stack_ghidra_report is not None:
            stack_ghidra, stack_sha = read_private_json(args.stack_ghidra_report)
            report["stack_correlation"] = correlate_stack_reports(sensitivity, stack_ghidra)
            report["inputs"]["stack_ghidra_report"] = {
                "path": str(args.stack_ghidra_report.resolve()),
                "sha256": stack_sha,
            }
        report["generated_at_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report.setdefault("inputs", {}).update({
            "sensitivity_report": {"path": str(args.sensitivity_report.resolve()),
                                   "sha256": sensitivity_sha},
            "ghidra_report": {"path": str(args.ghidra_report.resolve()),
                              "sha256": ghidra_sha},
        })
        write_private_new(args.output, report)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        print(f"correlation failed: {error}", file=sys.stderr)
        return 1
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"status": report["status"],
                      "caller_function": report["observation"]["static_call_reference"]["function_name"],
                      "caller_return_rva": report["observation"]["runtime_first_caller_return_rva"],
                      "stack_correlation": report.get("stack_correlation"),
                      "output": str(args.output), "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
