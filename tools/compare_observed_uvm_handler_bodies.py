#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare C token sequences for handlers in two captured stock V100 traces.

This is a source-level lexical comparison. It does not parse C semantics or
prove equivalence of callees, data structures, ABI payloads, or runtime work.
"""

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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEFAULT_ROUTE_REPORT = ROOT / (
    "evidence/r580-r595-v100-observed-uvm-route-coverage-v2-20261029.json"
)
DEFAULT_OUTPUT = ROOT / (
    "evidence/uvm-observed-handler-body-compare-v5-20261029.json"
)
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_TREE_SOURCE_BYTES = 256 * 1024 * 1024
IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
NUMBER_RE = re.compile(
    r"(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|[0-9]+)(?:[uUlL]+)?"
    r"|(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?[fFlL]?"
)
NV_STATUS_NAME_RE = re.compile(r"\bNV_STATUS\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(")
MULTI_CHAR_TOKENS = tuple(sorted((
    "...", "->", "++", "--", "&&", "||", "==", "!=", "<=", ">=",
    "+=", "-=", "*=", "/=", "%=", "<<", ">>", "&=", "|=", "^=", "##",
), key=len, reverse=True))
HIGH_COUNT_DIRECT_HELPERS = {
    "uvm_api_create_external_range": "uvm_create_external_range",
    "uvm_api_map_external_allocation": "uvm_map_external_allocation",
    "uvm_api_register_channel": "uvm_register_channel",
    "uvm_api_unregister_channel": "uvm_unregister_channel",
    "uvm_api_free": "uvm_free",
}


def _read_regular(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence and source verification")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file: {path}")
        if info.st_size > MAX_INPUT_BYTES:
            raise ValueError(f"{label} exceeds the input size limit: {path}")
        chunks = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise ValueError(f"{label} exceeds the input size limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _project_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError(f"{label} must be a repository-relative path")
    relative = Path(value)
    if any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError(f"{label} contains an unsafe path component")
    path = ROOT / relative
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(ROOT.resolve(strict=True)):
        raise ValueError(f"{label} resolves outside the repository")
    cursor = ROOT
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise ValueError(f"{label} traverses a symlink")
    return path


def _source_tree(source_record: dict[str, Any], label: str) -> tuple[Path, dict[str, Any]]:
    source = source_record.get("source")
    uvm_record = source.get("uvm.c") if isinstance(source, dict) else None
    if not isinstance(uvm_record, dict):
        raise ValueError(f"{label} route report lacks its pinned uvm.c input")
    source_path = _project_path(uvm_record.get("path"), f"{label} uvm.c path")
    raw = _read_regular(source_path, f"{label} route source")
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != uvm_record.get("sha256"):
        raise ValueError(f"{label} uvm.c differs from its route-coverage receipt")
    return source_path.parent, {
        "route_source": {
            "path": source_path.relative_to(ROOT).as_posix(),
            "sha256": actual_hash,
        }
    }


def tokenize_c(source: str) -> tuple[str, ...]:
    """Return C lexical tokens, discarding comments and whitespace only."""
    result: list[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated C block comment")
            index = end + 2
            continue
        if char in ('"', "'"):
            quote = char
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise ValueError("unterminated C string or character literal")
            result.append(source[index:end])
            index = end
            continue
        match = IDENTIFIER_RE.match(source, index) or NUMBER_RE.match(source, index)
        if match:
            result.append(match.group(0))
            index = match.end()
            continue
        operator = next((token for token in MULTI_CHAR_TOKENS
                         if source.startswith(token, index)), None)
        if operator:
            result.append(operator)
            index += len(operator)
            continue
        result.append(char)
        index += 1
    return tuple(result)


def _tokens_with_offsets(source: str) -> list[tuple[str, int, int]]:
    """Tokenize while retaining source offsets for braces and line anchors."""
    result: list[tuple[str, int, int]] = []
    index = 0
    while index < len(source):
        start = index
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated C block comment")
            index = end + 2
            continue
        if char in ('"', "'"):
            quote = char
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            else:
                raise ValueError("unterminated C string or character literal")
            result.append((source[start:index], start, index))
            continue
        match = IDENTIFIER_RE.match(source, index) or NUMBER_RE.match(source, index)
        if match:
            index = match.end()
            result.append((match.group(0), start, index))
            continue
        operator = next((token for token in MULTI_CHAR_TOKENS
                         if source.startswith(token, index)), None)
        if operator:
            index += len(operator)
            result.append((operator, start, index))
        else:
            index += 1
            result.append((char, start, index))
    return result


def extract_nv_status_handler(source: str, name: str) -> dict[str, Any] | None:
    """Find exactly one NV_STATUS function definition and return its tokens."""
    tokens = _tokens_with_offsets(source)
    values = [item[0] for item in tokens]
    matches: list[dict[str, Any]] = []
    for index in range(len(values) - 2):
        if values[index:index + 3] != ["NV_STATUS", name, "("]:
            continue
        paren_depth = 1
        cursor = index + 3
        while cursor < len(values) and paren_depth:
            if values[cursor] == "(":
                paren_depth += 1
            elif values[cursor] == ")":
                paren_depth -= 1
            cursor += 1
        if paren_depth:
            raise ValueError(f"unterminated parameter list for {name}")
        if cursor >= len(values) or values[cursor] != "{":
            continue  # A declaration is not a definition.
        brace_depth = 1
        body_cursor = cursor + 1
        while body_cursor < len(values) and brace_depth:
            if values[body_cursor] == "{":
                brace_depth += 1
            elif values[body_cursor] == "}":
                brace_depth -= 1
            body_cursor += 1
        if brace_depth:
            raise ValueError(f"unterminated function body for {name}")
        begin = tokens[index][1]
        finish = tokens[body_cursor - 1][2]
        matches.append({
            "tokens": tuple(values[index:body_cursor]),
            "start_line": source.count("\n", 0, begin) + 1,
            "end_line": source.count("\n", 0, finish) + 1,
        })
    if len(matches) > 1:
        raise ValueError(f"multiple NV_STATUS definitions found for {name}")
    return matches[0] if matches else None


def _load_tree_sources(root: Path, label: str) -> tuple[list[dict[str, str]], dict[Path, str]]:
    files = sorted(root.rglob("*.c"))
    if not files:
        raise ValueError(f"{label} UVM source tree has no C translation units")
    manifest: list[dict[str, str]] = []
    sources: dict[Path, str] = {}
    total = 0
    root_resolved = root.resolve(strict=True)
    for path in files:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root_resolved) or path.is_symlink():
            raise ValueError(f"{label} source tree contains a symlink or path escape")
        raw = _read_regular(path, f"{label} UVM C source")
        total += len(raw)
        if total > MAX_TREE_SOURCE_BYTES:
            raise ValueError(f"{label} UVM C source tree exceeds the size limit")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{label} UVM C source is not UTF-8: {path}") from error
        sources[path] = text
        manifest.append({
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return manifest, sources


def _find_handler(name: str, sources: dict[Path, str], label: str) -> dict[str, Any]:
    found = []
    for path, source in sources.items():
        definition = extract_nv_status_handler(source, name)
        if definition is not None:
            found.append((path, definition))
    if len(found) != 1:
        raise ValueError(f"{label} must contain one definition of {name}; found {len(found)}")
    path, definition = found[0]
    token_bytes = "\0".join(definition["tokens"]).encode("utf-8")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "start_line": definition["start_line"],
        "end_line": definition["end_line"],
        "token_count": len(definition["tokens"]),
        "token_sha256": hashlib.sha256(token_bytes).hexdigest(),
        "tokens": definition["tokens"],
    }


def _index_nv_status_declarations(sources: dict[Path, str]) -> dict[str, list[tuple[Path, str]]]:
    index: dict[str, list[tuple[Path, str]]] = {}
    for path, source in sources.items():
        for match in NV_STATUS_NAME_RE.finditer(source):
            index.setdefault(match.group(1), []).append((path, source))
    return index


def _indexed_handler(name: str, index: dict[str, list[tuple[Path, str]]],
                     label: str) -> dict[str, Any] | None:
    found = []
    for path, source in index.get(name, []):
        definition = extract_nv_status_handler(source, name)
        if definition is not None:
            found.append((path, definition))
    if len(found) > 1:
        raise ValueError(f"{label} has multiple NV_STATUS definitions for {name}")
    if not found:
        return None
    path, definition = found[0]
    token_bytes = "\0".join(definition["tokens"]).encode("utf-8")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "start_line": definition["start_line"],
        "end_line": definition["end_line"],
        "token_count": len(definition["tokens"]),
        "token_sha256": hashlib.sha256(token_bytes).hexdigest(),
        "tokens": definition["tokens"],
    }


def _direct_callees(tokens: tuple[str, ...], self_name: str) -> set[str]:
    excluded = {"if", "switch", "for", "while", "sizeof", "return", "typeof", "__typeof__"}
    return {
        tokens[index]
        for index in range(len(tokens) - 1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", tokens[index])
        and tokens[index + 1] == "("
        and tokens[index] not in excluded
        and tokens[index] != self_name
    }


def compare_observed_handlers(route_report_path: Path) -> dict[str, Any]:
    route_report_path = Path(route_report_path)
    raw_route_report = _read_regular(route_report_path, "UVM route-coverage report")
    try:
        route_report = json.loads(raw_route_report)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"UVM route-coverage report is invalid JSON: {error}") from None
    if (not isinstance(route_report, dict)
            or route_report.get("qualification") != "analyzed-statically"
            or route_report.get("runtime_compatibility_proven") is not False
            or route_report.get("hardware_tested") is not False):
        raise ValueError("input is not the expected non-runtime UVM route report")
    compatibility = route_report.get("observed_trace_compatibility")
    captures = compatibility.get("captures") if isinstance(compatibility, dict) else None
    expected_capture_count = compatibility.get("capture_count") if isinstance(compatibility, dict) else None
    if (not isinstance(captures, list) or len(captures) != 2
            or expected_capture_count != len(captures)):
        raise ValueError("route report must bind exactly two stock V100 captures")
    baseline_record = route_report.get("baseline")
    candidate_record = route_report.get("candidate")
    if not isinstance(baseline_record, dict) or not isinstance(candidate_record, dict):
        raise ValueError("route report lacks baseline/candidate source records")
    baseline_root, baseline_info = _source_tree(baseline_record, "baseline")
    candidate_root, candidate_info = _source_tree(candidate_record, "candidate")
    baseline_manifest, baseline_sources = _load_tree_sources(baseline_root, "baseline")
    candidate_manifest, candidate_sources = _load_tree_sources(candidate_root, "candidate")
    baseline_nv_status_index = _index_nv_status_declarations(baseline_sources)
    candidate_nv_status_index = _index_nv_status_declarations(candidate_sources)

    normalized_captures = []
    reference_requests = None
    request_names: dict[str, dict[str, Any]] = {}
    for capture in captures:
        if not isinstance(capture, dict) or not isinstance(capture.get("requests"), list):
            raise ValueError("route report contains a malformed V100 capture entry")
        rows = []
        for request in capture["requests"]:
            if not isinstance(request, dict):
                raise ValueError("route report contains a malformed request row")
            name = request.get("name")
            number = request.get("request")
            count = request.get("count")
            baseline_route = request.get("baseline")
            candidate_route = request.get("candidate")
            if (not isinstance(name, str) or not name.startswith("UVM_")
                    or not isinstance(number, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", number)
                    or type(count) is not int or count < 1
                    or not isinstance(baseline_route, dict)
                    or not isinstance(candidate_route, dict)
                    or baseline_route.get("status") != "routed"
                    or candidate_route.get("status") != "routed"):
                raise ValueError("route report contains an invalid or unrouted request")
            baseline_handler = baseline_route.get("handler")
            candidate_handler = candidate_route.get("handler")
            if not isinstance(baseline_handler, str) or baseline_handler != candidate_handler:
                raise ValueError(f"branches do not select the same handler for {name}")
            row = (name, number.lower(), count, baseline_handler)
            rows.append(row)
            prior = request_names.setdefault(name, {
                "name": name, "request": number.lower(), "count_each_capture": count,
                "handler": baseline_handler,
            })
            if prior != {"name": name, "request": number.lower(),
                         "count_each_capture": count, "handler": baseline_handler}:
                raise ValueError(f"request metadata varies across captures: {name}")
        if reference_requests is None:
            reference_requests = rows
        elif rows != reference_requests:
            raise ValueError("the two stock V100 captures do not have identical request metadata")
        capture_name = capture.get("capture")
        capture_hash = capture.get("capture_sha256")
        if (not isinstance(capture_name, str) or not isinstance(capture_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", capture_hash)):
            raise ValueError("route report capture identity is malformed")
        normalized_captures.append({
            "capture": capture_name,
            "capture_sha256": capture_hash,
            "driver_version": capture.get("driver_version"),
            "kernel_release": capture.get("kernel_release"),
            "guest_name": capture.get("guest_name"),
            "request_count": len(rows),
            "payload_bytes_observed": False,
        })

    if not request_names:
        raise ValueError("stock V100 captures contain no UVM handler requests")
    handlers = []
    handler_tokens: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for handler_name in sorted({row["handler"] for row in request_names.values()}):
        baseline = _find_handler(handler_name, baseline_sources, "baseline")
        candidate = _find_handler(handler_name, candidate_sources, "candidate")
        identical = baseline["tokens"] == candidate["tokens"]
        handler_tokens[handler_name] = (baseline["tokens"], candidate["tokens"])
        handlers.append({
            "handler": handler_name,
            "requests": [value for value in request_names.values()
                         if value["handler"] == handler_name],
            "baseline": {k: v for k, v in baseline.items() if k != "tokens"},
            "candidate": {k: v for k, v in candidate.items() if k != "tokens"},
            "token_sequences_identical": identical,
        })

    direct_helpers = []
    direct_helper_tokens: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for wrapper, helper in HIGH_COUNT_DIRECT_HELPERS.items():
        requests = [item for item in request_names.values()
                    if item["handler"] == wrapper]
        if not requests:
            raise ValueError(f"selected high-count wrapper is absent from captures: {wrapper}")
        for tokens in handler_tokens[wrapper]:
            if not any(tokens[index] == helper and tokens[index + 1] == "("
                       for index in range(len(tokens) - 1)):
                raise ValueError(f"{wrapper} does not directly call expected helper {helper}")
        baseline = _find_handler(helper, baseline_sources, "baseline")
        candidate = _find_handler(helper, candidate_sources, "candidate")
        direct_helper_tokens[helper] = (baseline["tokens"], candidate["tokens"])
        direct_helpers.append({
            "helper": helper,
            "directly_called_by_observed_handler": wrapper,
            "requests": requests,
            "baseline": {k: v for k, v in baseline.items() if k != "tokens"},
            "candidate": {k: v for k, v in candidate.items() if k != "tokens"},
            "token_sequences_identical": baseline["tokens"] == candidate["tokens"],
        })

    second_level_parents: dict[str, set[str]] = {}
    for helper, token_pair in direct_helper_tokens.items():
        for tokens in token_pair:
            for callee in _direct_callees(tokens, helper):
                second_level_parents.setdefault(callee, set()).add(helper)

    second_level_helpers = []
    second_level_out_of_scope = []
    for callee in sorted(second_level_parents):
        baseline = _indexed_handler(callee, baseline_nv_status_index, "baseline")
        candidate = _indexed_handler(callee, candidate_nv_status_index, "candidate")
        if baseline is None or candidate is None:
            second_level_out_of_scope.append({
                "callee": callee,
                "baseline_nv_status_definition_present": baseline is not None,
                "candidate_nv_status_definition_present": candidate is not None,
            })
            continue
        parents = sorted(second_level_parents[callee])
        operations = [request for helper in parents for request in request_names.values()
                      if request["handler"] == next(
                          row["directly_called_by_observed_handler"]
                          for row in direct_helpers if row["helper"] == helper
                      )]
        second_level_helpers.append({
            "helper": callee,
            "directly_called_by_helpers": parents,
            "observed_operations": operations,
            "baseline": {k: v for k, v in baseline.items() if k != "tokens"},
            "candidate": {k: v for k, v in candidate.items() if k != "tokens"},
            "token_sequences_identical": baseline["tokens"] == candidate["tokens"],
        })

    identical_count = sum(item["token_sequences_identical"] for item in handlers)
    identical_helper_count = sum(item["token_sequences_identical"] for item in direct_helpers)
    identical_second_level_count = sum(
        item["token_sequences_identical"] for item in second_level_helpers
    )
    implementation_bytes = _read_regular(Path(__file__), "handler comparison implementation")
    return {
        "schema": "nvidia-hybrid-observed-uvm-handler-body-token-compare-v3",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "analyzed-statically",
        "comparison_method": (
            "C lexical token sequences for the uniquely defined NV_STATUS handler, "
            "discarding only whitespace and comments; no AST or semantic analysis"
        ),
        "route_coverage_report": {
            "path": route_report_path.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(raw_route_report).hexdigest(),
        },
        "implementation": {
            "path": Path(__file__).relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(implementation_bytes).hexdigest(),
        },
        "source_trees": {
            "baseline": {**baseline_info, "c_files": baseline_manifest},
            "candidate": {**candidate_info, "c_files": candidate_manifest},
        },
        "captures": normalized_captures,
        "observed_handler_count": len(handlers),
        "token_identical_handler_count": identical_count,
        "different_handler_count": len(handlers) - identical_count,
        "handlers": handlers,
        "helper_comparison_scope": (
            "one directly called NV_STATUS helper for each selected high-count operation; "
            "not a recursive call-graph closure"
        ),
        "direct_helper_count": len(direct_helpers),
        "token_identical_direct_helper_count": identical_helper_count,
        "different_direct_helper_count": len(direct_helpers) - identical_helper_count,
        "direct_helpers": direct_helpers,
        "second_level_scope": (
            "unique NV_STATUS definitions called directly by the five selected helpers; "
            "other return types, macros, and deeper calls are out of scope"
        ),
        "second_level_nv_status_helper_count": len(second_level_helpers),
        "token_identical_second_level_helper_count": identical_second_level_count,
        "different_second_level_helper_count": len(second_level_helpers) - identical_second_level_count,
        "second_level_helpers": second_level_helpers,
        "second_level_callees_out_of_scope": second_level_out_of_scope,
        "payload_bytes_observed": False,
        "runtime_or_hardware_validated": False,
        "scope_limits": [
            "This is lexical identity, not semantic equivalence or ABI proof.",
            "Callees, macros, data structures, and generated code were not compared.",
            "The stock captures omit ioctl payload bytes.",
            "No candidate module was loaded and no GPU was accessed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route-report", type=Path, default=DEFAULT_ROUTE_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = compare_observed_handlers(args.route_report)
        from tools.probe_r615_gv100_dispatch import write_private_evidence_report

        written = write_private_evidence_report(args.output, report, ROOT)
        print(json.dumps({
            "path": written.relative_to(ROOT).as_posix(),
            "qualification": report["qualification"],
            "observed_handler_count": report["observed_handler_count"],
            "token_identical_handler_count": report["token_identical_handler_count"],
            "different_handler_count": report["different_handler_count"],
            "direct_helper_count": report["direct_helper_count"],
            "token_identical_direct_helper_count": report[
                "token_identical_direct_helper_count"
            ],
            "different_direct_helper_count": report["different_direct_helper_count"],
            "second_level_nv_status_helper_count": report[
                "second_level_nv_status_helper_count"
            ],
            "token_identical_second_level_helper_count": report[
                "token_identical_second_level_helper_count"
            ],
            "different_second_level_helper_count": report[
                "different_second_level_helper_count"
            ],
            "payload_bytes_observed": report["payload_bytes_observed"],
            "runtime_or_hardware_validated": report["runtime_or_hardware_validated"],
        }, indent=2))
        return 0
    except (OSError, ValueError) as error:
        print(f"UVM handler comparison failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
