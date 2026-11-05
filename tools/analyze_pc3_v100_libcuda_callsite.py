#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Locate one pinned PC3 V100 libcuda callsite with temporary Ghidra analysis.

Only bounded function metadata is retained. The proprietary input must be
provided separately and is never copied or deleted by this tool.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BINARY_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
DEFAULT_GHIDRA_HOME = ROOT / "build/tools/ghidra_12.1.4_PUBLIC"
DEFAULT_RVA = 0x48BC88
RESULT_PREFIX = "GHIDRA_RESULT:"
GHIDRA_SCRIPT = Path(__file__).with_name("GhidraLocateFunctionAtAddress.java")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.$?<>:+@-]{1,256}$")
_REFERENCE_TYPE_RE = re.compile(r"^[A-Z0-9_]{1,48}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hex_value(value: object, field: str) -> int:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise ValueError(f"invalid hexadecimal {field}")
    return int(value, 16)


def _validate_call_references(raw: object, *, key: str, incoming: bool) -> tuple[list[dict[str, object]], bool]:
    records = raw.get(key)
    truncated = raw.get(key + "_truncated")
    if not isinstance(records, list) or len(records) > 64 or type(truncated) is not bool:
        raise ValueError("Ghidra call reference metadata is missing or unbounded")
    normalized: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Ghidra call reference record is malformed")
        source_rva = _hex_value(record.get("source_rva"), "call reference source RVA")
        reference_type = record.get("reference_type")
        if not isinstance(reference_type, str) or _REFERENCE_TYPE_RE.fullmatch(reference_type) is None:
            raise ValueError("Ghidra call reference type is malformed")
        safe: dict[str, object] = {
            "source_rva": f"0x{source_rva:x}",
            "reference_type": reference_type,
        }
        if incoming:
            name = record.get("source_function_name")
            entry = record.get("source_function_entry_rva")
            if (not isinstance(name, str) or _NAME_RE.fullmatch(name) is None or
                    (entry is not None and not isinstance(entry, str))):
                raise ValueError("Ghidra incoming call reference metadata is malformed")
            safe["source_function_name"] = name
            safe["source_function_entry_rva"] = (
                f"0x{_hex_value(entry, 'caller entry RVA'):x}" if entry is not None else None
            )
        else:
            name = record.get("target_name")
            target_rva = record.get("target_rva")
            external = record.get("target_external")
            if (not isinstance(name, str) or _NAME_RE.fullmatch(name) is None or
                    (target_rva is not None and not isinstance(target_rva, str)) or
                    type(external) is not bool):
                raise ValueError("Ghidra outgoing call reference metadata is malformed")
            safe["target_name"] = name
            safe["target_rva"] = (
                f"0x{_hex_value(target_rva, 'callee RVA'):x}" if target_rva is not None else None
            )
            safe["target_external"] = external
        normalized.append(safe)
    normalized.sort(key=lambda item: (int(item["source_rva"], 16),
                                      str(item.get("source_function_name", item.get("target_name", "")))))
    return normalized, truncated


def parse_ghidra_result(text: str, *, expected_rva: int) -> dict[str, object]:
    """Validate a single Ghidra record and return only non-code metadata."""
    records = [line.split(RESULT_PREFIX, 1)[1] for line in text.splitlines()
               if RESULT_PREFIX in line]
    if len(records) != 1:
        raise ValueError("expected one Ghidra result record")
    payload = records[0].lstrip()
    try:
        raw, end = json.JSONDecoder().raw_decode(payload)
    except json.JSONDecodeError as error:
        raise ValueError("Ghidra result is not valid JSON") from error
    suffix = payload[end:].strip()
    if suffix not in ("", "(GhidraScript)"):
        raise ValueError("Ghidra result has an unexpected suffix")
    if not isinstance(raw, dict) or raw.get("schema") != "nvidia-hybrid-ghidra-function-at-rva-v2":
        raise ValueError("unsupported Ghidra result schema")
    if raw.get("status") != "function_found":
        raise ValueError("Ghidra did not identify a containing function")

    image_base = _hex_value(raw.get("image_base"), "image base")
    target_address = _hex_value(raw.get("target_address"), "target address")
    target_rva = _hex_value(raw.get("target_rva"), "target RVA")
    entry = _hex_value(raw.get("function_entry"), "function entry")
    end = _hex_value(raw.get("function_end_exclusive"), "function end")
    if target_rva != expected_rva or target_address != image_base + expected_rva:
        raise ValueError("Ghidra result does not match the expected target RVA")
    if not entry <= target_address < end:
        raise ValueError("Ghidra function range does not contain the callsite")
    name = raw.get("function_name")
    if not isinstance(name, str) or _NAME_RE.fullmatch(name) is None:
        raise ValueError("Ghidra function name is malformed")
    instruction_count = raw.get("instruction_count")
    if type(instruction_count) is not int or not 1 <= instruction_count <= 10_000_000:
        raise ValueError("Ghidra instruction count is invalid")
    if raw.get("decompiler_completed") is not True:
        raise ValueError("Ghidra decompiler did not complete")
    incoming_callers, incoming_truncated = _validate_call_references(
        raw, key="incoming_callers", incoming=True)
    outgoing_calls, outgoing_truncated = _validate_call_references(
        raw, key="outgoing_calls", incoming=False)

    return {
        "target_rva": f"0x{target_rva:x}",
        "image_base": f"0x{image_base:x}",
        "target_address": f"0x{target_address:x}",
        "function_name": name,
        "function_entry": f"0x{entry:x}",
        "function_end_exclusive": f"0x{end:x}",
        "function_entry_rva": f"0x{entry - image_base:x}",
        "function_end_rva_exclusive": f"0x{end - image_base:x}",
        "instruction_count": instruction_count,
        "decompiler_completed": True,
        "incoming_callers": incoming_callers,
        "incoming_callers_truncated": incoming_truncated,
        "outgoing_calls": outgoing_calls,
        "outgoing_calls_truncated": outgoing_truncated,
        "interpretation": (
            "Ghidra identified a function body containing the observed return-address RVA. "
            "This is static analysis metadata, not original source or proof of call semantics."
        ),
    }


def parse_ghidra_results(text: str, expected_rvas: list[int]) -> list[dict[str, object]]:
    """Parse one bounded Ghidra metadata record for each requested RVA."""
    if (not isinstance(expected_rvas, list) or not 1 <= len(expected_rvas) <= 8 or
            any(type(rva) is not int or rva < 0 or rva > 0xFFFFFFFFFFFFFFFF
                for rva in expected_rvas)):
        raise ValueError("expected one to eight valid target RVAs")
    if len(set(expected_rvas)) != len(expected_rvas):
        raise ValueError("duplicate target RVA")
    records = [line.split(RESULT_PREFIX, 1)[1] for line in text.splitlines()
               if RESULT_PREFIX in line]
    if len(records) != len(expected_rvas):
        raise ValueError("Ghidra result count does not match requested target RVAs")

    parsed_by_rva: dict[int, str] = {}
    for record in records:
        payload = record.lstrip()
        try:
            raw, end = json.JSONDecoder().raw_decode(payload)
        except json.JSONDecodeError as error:
            raise ValueError("Ghidra result is not valid JSON") from error
        if payload[end:].strip() not in ("", "(GhidraScript)"):
            raise ValueError("Ghidra result has an unexpected suffix")
        if not isinstance(raw, dict):
            raise ValueError("Ghidra result is not a JSON object")
        target_rva = _hex_value(raw.get("target_rva"), "target RVA")
        if target_rva in parsed_by_rva:
            raise ValueError("duplicate target RVA in Ghidra results")
        parsed_by_rva[target_rva] = json.dumps(raw, separators=(",", ":"))

    results = []
    for rva in expected_rvas:
        if rva not in parsed_by_rva:
            raise ValueError("Ghidra result count is missing a requested target RVA")
        results.append(parse_ghidra_result(
            RESULT_PREFIX + parsed_by_rva[rva], expected_rva=rva))
    return results


def _write_private_new(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)


def run_analysis(
    binary: Path,
    ghidra_home: Path = DEFAULT_GHIDRA_HOME,
    *,
    expected_rva: int = DEFAULT_RVA,
    report_path: Path | None = None,
) -> dict[str, object]:
    binary = Path(binary).resolve(strict=True)
    ghidra_home = Path(ghidra_home).resolve(strict=True)
    headless = ghidra_home / "support/analyzeHeadless"
    if not headless.is_file() or not os.access(headless, os.X_OK):
        raise FileNotFoundError("Ghidra analyzeHeadless is missing or not executable")
    if not GHIDRA_SCRIPT.is_file():
        raise FileNotFoundError("bounded Ghidra function-locator script is missing")
    binary_sha256 = sha256_file(binary)
    if binary_sha256 != EXPECTED_BINARY_SHA256:
        raise ValueError("input libcuda does not match the pinned PC3 V100 SHA-256")

    with tempfile.TemporaryDirectory(prefix="pc3-v100-ghidra-") as scratch_name:
        scratch = Path(scratch_name)
        project_dir = scratch / "project"
        home_dir = scratch / "home"
        project_dir.mkdir(mode=0o700)
        home_dir.mkdir(mode=0o700)
        command = [
            str(headless), str(project_dir), "pc3_v100_callsite",
            "-import", str(binary),
            "-scriptPath", str(GHIDRA_SCRIPT.parent),
            "-postScript", GHIDRA_SCRIPT.name, f"0x{expected_rva:x}",
        ]
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": str(home_dir),
            "TMPDIR": str(scratch),
        }
        java_home = ROOT / "build/tools/jdk21/usr/lib/jvm/java-21-openjdk-amd64"
        if java_home.is_dir():
            environment["JAVA_HOME"] = str(java_home)
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=900, env=environment,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Ghidra headless analysis exceeded 900 seconds") from error
        if completed.returncode != 0:
            # Suppress vendor logs: they can contain reconstructed symbol/code text.
            raise RuntimeError(f"Ghidra headless analysis exited with status {completed.returncode}")
        finding = parse_ghidra_result(completed.stdout + "\n" + completed.stderr,
                                      expected_rva=expected_rva)

    generated_at = datetime.now(timezone.utc).isoformat()
    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-ghidra-function-v2",
        "status": "static_analysis_passed",
        "generated_at": generated_at,
        "input": {
            "image": "libcuda.so.580.178.04",
            "sha256": binary_sha256,
            "expected_sha256": EXPECTED_BINARY_SHA256,
            "binary_retained_by_tool": False,
        },
        "tool": {
            "name": "Ghidra analyzeHeadless",
            "version_directory": ghidra_home.name,
            "script": GHIDRA_SCRIPT.name,
            "project_retained": False,
            "raw_decompiler_text_retained": False,
        },
        "finding": finding,
    }
    if report_path is not None:
        report_path = Path(report_path)
        if not report_path.is_absolute():
            report_path = ROOT / report_path
        _write_private_new(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def run_analysis_many(
    binary: Path,
    target_rvas: list[int],
    ghidra_home: Path = DEFAULT_GHIDRA_HOME,
    *,
    report_path: Path | None = None,
) -> dict[str, object]:
    """Analyze up to eight RVAs in one pinned Ghidra import and retain metadata only."""
    if (not isinstance(target_rvas, list) or not 2 <= len(target_rvas) <= 8 or
            any(type(rva) is not int or rva < 0 or rva > 0xFFFFFFFFFFFFFFFF
                for rva in target_rvas)):
        raise ValueError("multi-target analysis requires two to eight valid RVAs")
    if len(set(target_rvas)) != len(target_rvas):
        raise ValueError("duplicate target RVA")
    binary = Path(binary).resolve(strict=True)
    ghidra_home = Path(ghidra_home).resolve(strict=True)
    headless = ghidra_home / "support/analyzeHeadless"
    if not headless.is_file() or not os.access(headless, os.X_OK):
        raise FileNotFoundError("Ghidra analyzeHeadless is missing or not executable")
    if not GHIDRA_SCRIPT.is_file():
        raise FileNotFoundError("bounded Ghidra function-locator script is missing")
    binary_sha256 = sha256_file(binary)
    if binary_sha256 != EXPECTED_BINARY_SHA256:
        raise ValueError("input libcuda does not match the pinned PC3 V100 SHA-256")

    with tempfile.TemporaryDirectory(prefix="pc3-v100-ghidra-multi-") as scratch_name:
        scratch = Path(scratch_name)
        project_dir = scratch / "project"
        home_dir = scratch / "home"
        project_dir.mkdir(mode=0o700)
        home_dir.mkdir(mode=0o700)
        command = [
            str(headless), str(project_dir), "pc3_v100_call_chain",
            "-import", str(binary),
            "-scriptPath", str(GHIDRA_SCRIPT.parent),
            "-postScript", GHIDRA_SCRIPT.name,
            *[f"0x{rva:x}" for rva in target_rvas],
        ]
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": str(home_dir),
            "TMPDIR": str(scratch),
        }
        java_home = ROOT / "build/tools/jdk21/usr/lib/jvm/java-21-openjdk-amd64"
        if java_home.is_dir():
            environment["JAVA_HOME"] = str(java_home)
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, check=False,
                timeout=900, env=environment,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Ghidra headless analysis exceeded 900 seconds") from error
        if completed.returncode != 0:
            raise RuntimeError(f"Ghidra headless analysis exited with status {completed.returncode}")
        findings = parse_ghidra_results(completed.stdout + "\n" + completed.stderr,
                                        target_rvas)

    report: dict[str, object] = {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-ghidra-multi-function-v1",
        "status": "static_analysis_passed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "image": "libcuda.so.580.178.04",
            "sha256": binary_sha256,
            "expected_sha256": EXPECTED_BINARY_SHA256,
            "binary_retained_by_tool": False,
        },
        "tool": {
            "name": "Ghidra analyzeHeadless",
            "version_directory": ghidra_home.name,
            "script": GHIDRA_SCRIPT.name,
            "project_retained": False,
            "raw_decompiler_text_retained": False,
            "targets_in_one_import": True,
        },
        "findings": findings,
    }
    if report_path is not None:
        report_path = Path(report_path)
        if not report_path.is_absolute():
            report_path = ROOT / report_path
        _write_private_new(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True,
                        help="temporary local copy of the pinned guest libcuda image")
    parser.add_argument("--ghidra-home", type=Path, default=DEFAULT_GHIDRA_HOME)
    parser.add_argument("--rva", type=lambda value: int(value, 0), action="append",
                        help="image-relative RVA to analyze; may be supplied up to eight times")
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args(argv)
    target_rvas = args.rva or [DEFAULT_RVA]
    if any(rva < 0 or rva > 0xFFFFFFFFFFFFFFFF for rva in target_rvas):
        parser.error("--rva is outside the supported ELF64 range")
    if args.report is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        args.report = Path("evidence") / f"pc3-v100-libcuda-ghidra-function-v2-{timestamp}.json"
    try:
        if len(target_rvas) == 1:
            report = run_analysis(args.binary, args.ghidra_home,
                                  expected_rva=target_rvas[0], report_path=args.report)
            findings = [report["finding"]]
        else:
            report = run_analysis_many(args.binary, target_rvas, args.ghidra_home,
                                       report_path=args.report)
            findings = report["findings"]
    except (FileNotFoundError, RuntimeError, ValueError, OSError) as error:
        print(f"analysis failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": report["status"],
        "binary_sha256": report["input"]["sha256"],
        "findings": [{"target_rva": item["target_rva"],
                      "function_name": item["function_name"],
                      "function_entry_rva": item["function_entry_rva"]}
                     for item in findings],
        "report": str(args.report),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
