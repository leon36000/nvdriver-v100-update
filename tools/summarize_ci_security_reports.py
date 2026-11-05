#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a privacy-preserving inventory from GitLab scanner JSON reports."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sys
from typing import Any


SCHEMA = "nvidia-hybrid-ci-security-report-summary-v3"
_SEVERITIES = frozenset({
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN",
    "ERROR", "WARNING", "NOTE", "BLOCKER", "EXPERIMENT", "INVENTORY",
})
_Finding = tuple[str, str, str, int | None]


def _severity(value: Any) -> str:
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in _SEVERITIES:
            return normalized
    return "UNKNOWN"


def _line(value: Any) -> int | None:
    return value if type(value) is int and 0 < value <= 2**31 - 1 else None


def _opaque_group_id(key: bytes, scanner: str, finding: _Finding) -> str:
    rule, severity, filename, start_line = finding
    payload = json.dumps(
        [scanner, rule, severity, filename, start_line], separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _top_groups(findings: list[_Finding], limit: int, *, scanner: str,
                group_key: bytes) -> list[dict[str, Any]]:
    counts = Counter(findings)
    ordered = sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0][1], item[0][3] or 0,
                          _opaque_group_id(group_key, scanner, item[0])),
    )[:limit]
    return [
        {
            "group_id": _opaque_group_id(group_key, scanner, finding),
            "severity": finding[1],
            "start_line": finding[3],
            "count": count,
        }
        for finding, count in ordered
    ]


def _required_text(item: dict[str, Any], field: str, report: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{report} report contains a finding without {field}")
    return value


def _read_report(path: Path, name: str) -> tuple[Any, dict[str, Any]]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(f"{name} report is not valid JSON") from None
    return document, {"status": "parsed", "size_bytes": len(raw)}


def _gitleaks(document: Any, limit: int, *, group_key: bytes) -> dict[str, Any]:
    if not isinstance(document, list):
        raise ValueError("Gitleaks report must be a JSON array")
    findings: list[_Finding] = []
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("Gitleaks report contains a malformed finding")
        rule = _required_text(item, "RuleID", "Gitleaks")
        filename = _required_text(item, "File", "Gitleaks")
        findings.append((rule, "UNKNOWN", filename, _line(item.get("StartLine"))))
    return {
        "finding_count": len(findings),
        "top_groups": _top_groups(
            findings, limit, scanner="gitleaks", group_key=group_key),
    }


def _semgrep(document: Any, limit: int, *, group_key: bytes) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise ValueError("Semgrep report must contain a results array")
    errors = document.get("errors")
    if not isinstance(errors, list):
        raise ValueError("Semgrep report errors field must be an array")
    error_categories = Counter()
    for error in errors:
        category = "other"
        if isinstance(error, dict):
            kind = error.get("type") or error.get("code") or error.get("error_type")
            if isinstance(kind, str):
                normalized = kind.lower()
                for marker, candidate in (
                    ("timeout", "timeout"),
                    ("parse", "parse"),
                    ("config", "configuration"),
                    ("rule", "rule"),
                    ("permission", "permission"),
                    ("internal", "internal"),
                ):
                    if marker in normalized:
                        category = candidate
                        break
        error_categories[category] += 1
    paths = document.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
        raise ValueError("Semgrep report must contain scanned paths")
    if any(not isinstance(path, str) for path in paths["scanned"]):
        raise ValueError("Semgrep report contains malformed scanned paths")
    skipped = paths.get("skipped", [])
    if not isinstance(skipped, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("path"), str)
        or not isinstance(item.get("reason"), str)
        for item in skipped
    ):
        raise ValueError("Semgrep report contains malformed skipped paths")

    findings: list[_Finding] = []
    for item in document["results"]:
        if not isinstance(item, dict):
            raise ValueError("Semgrep report contains a malformed finding")
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        rule = _required_text(item, "check_id", "Semgrep")
        filename = _required_text(item, "path", "Semgrep")
        findings.append((
            rule, _severity(extra.get("severity")), filename,
            _line(start.get("line")),
        ))
    return {
        "finding_count": len(findings),
        "scanned_target_count": len(paths["scanned"]),
        "skipped_target_count": len(skipped),
        "scanner_error_count": len(errors),
        "scanner_error_categories": dict(sorted(error_categories.items())),
        "top_groups": _top_groups(
            findings, limit, scanner="semgrep", group_key=group_key),
    }


def _trivy(document: Any, limit: int, *, group_key: bytes) -> dict[str, Any]:
    if (not isinstance(document, dict)
            or type(document.get("SchemaVersion")) is not int
            or document.get("SchemaVersion") != 2
            or not isinstance(document.get("Results"), list)):
        raise ValueError("Trivy report must use schema version 2 and contain a Results array")

    findings: list[_Finding] = []
    for result in document["Results"]:
        if not isinstance(result, dict):
            raise ValueError("Trivy report contains a malformed result")
        filename = _required_text(result, "Target", "Trivy")
        for field, rule_field in (("Misconfigurations", "ID"),
                                  ("Vulnerabilities", "VulnerabilityID"),
                                  ("Secrets", "RuleID")):
            entries = result.get(field, [])
            if not isinstance(entries, list):
                raise ValueError(f"Trivy {field} must be an array")
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError(f"Trivy {field} contains a malformed finding")
                rule = _required_text(item, rule_field, "Trivy")
                cause = item.get("CauseMetadata")
                cause = cause if isinstance(cause, dict) else {}
                findings.append((
                    rule,
                    _severity(item.get("Severity")),
                    filename,
                    _line(cause.get("StartLine", item.get("StartLine"))),
                ))
    return {
        "finding_count": len(findings),
        "top_groups": _top_groups(
            findings, limit, scanner="trivy", group_key=group_key),
    }


def summarize_reports(root: Path, *, max_groups: int = 20) -> dict[str, Any]:
    if max_groups < 1 or max_groups > 200:
        raise ValueError("max-groups must be between 1 and 200")
    specifications = (
        ("gitleaks", "gitleaks-report.json", _gitleaks),
        ("semgrep", "semgrep-report.json", _semgrep),
        ("trivy", "trivy-report.json", _trivy),
    )
    reports: dict[str, Any] = {}
    missing: list[str] = []
    group_key = secrets.token_bytes(32)
    for name, filename, summarize in specifications:
        path = root / filename
        if not path.is_file():
            reports[name] = {"status": "missing", "finding_count": None, "top_groups": []}
            missing.append(name)
            continue
        document, metadata = _read_report(path, name)
        metadata.update(summarize(document, max_groups, group_key=group_key))
        reports[name] = metadata
    scanner_error_count = sum(
        report.get("scanner_error_count", 0)
        for report in reports.values()
        if isinstance(report.get("scanner_error_count", 0), int)
    )
    status = (
        "reports_partial" if missing
        else "reports_with_scanner_errors" if scanner_error_count
        else "reports_complete"
    )
    return {
        "schema": SCHEMA,
        "status": status,
        "status_scope": "artifact_presence_schema_and_scanner_error_count",
        "scanner_error_count": scanner_error_count,
        "scanner_completion_verified": False,
        "missing_reports": missing,
        "reports": reports,
        "raw_finding_values_retained": False,
        "scanner_identifiers_retained": False,
        "file_paths_retained": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path,
                        help="write the sanitized JSON summary to this path")
    parser.add_argument("--max-groups", type=int, default=20)
    args = parser.parse_args()
    try:
        result = summarize_reports(args.root.resolve(strict=True), max_groups=args.max_groups)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(rendered, end="")
        return 0 if result["status"] == "reports_complete" else 2
    except OSError:
        print("security report summarization failed; details suppressed", file=sys.stderr)
        return 2
    except ValueError as error:
        # Parser errors are emitted only from fixed schema labels and fixed field names.
        # Filesystem failures remain generic above because their messages can include paths.
        print(f"security report summarization failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
