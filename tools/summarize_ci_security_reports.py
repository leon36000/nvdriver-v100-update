#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a secret-free inventory from GitLab security scanner JSON reports."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


SCHEMA = "nvidia-hybrid-ci-security-report-summary-v1"
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9._/-]+")


def _label(value: Any, *, limit: int = 160) -> str:
    if not isinstance(value, str):
        return "unknown"
    cleaned = _SAFE_LABEL.sub("_", value.strip())[:limit].strip("._/-")
    return cleaned or "unknown"


def _basename(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    normalized = value.replace("\\", "/")
    return _label(PurePosixPath(normalized).name, limit=128)


def _top_groups(findings: list[tuple[str, str, str]], limit: int) -> list[dict[str, Any]]:
    counts = Counter(findings)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [
        {"rule_id": rule, "severity": severity, "file": filename, "count": count}
        for (rule, severity, filename), count in ordered
    ]


def _read_report(path: Path, name: str) -> tuple[Any, dict[str, Any]]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{name} report is not valid JSON") from error
    return document, {
        "status": "read",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _gitleaks(document: Any, limit: int) -> dict[str, Any]:
    if not isinstance(document, list):
        raise ValueError("Gitleaks report must be a JSON array")
    findings = []
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("Gitleaks report contains a malformed finding")
        findings.append((_label(item.get("RuleID")), "unknown", _basename(item.get("File"))))
    return {"finding_count": len(findings), "top_groups": _top_groups(findings, limit)}


def _semgrep(document: Any, limit: int) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("results"), list):
        raise ValueError("Semgrep report must contain a results array")
    findings = []
    for item in document["results"]:
        if not isinstance(item, dict):
            raise ValueError("Semgrep report contains a malformed finding")
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        findings.append((
            _label(item.get("check_id")),
            _label(extra.get("severity")),
            _basename(item.get("path")),
        ))
    return {"finding_count": len(findings), "top_groups": _top_groups(findings, limit)}


def _trivy(document: Any, limit: int) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("Results", []), list):
        raise ValueError("Trivy report must contain a Results array")
    findings = []
    for result in document.get("Results", []):
        if not isinstance(result, dict):
            raise ValueError("Trivy report contains a malformed result")
        filename = _basename(result.get("Target"))
        for field, rule_field in (("Misconfigurations", "ID"),
                                  ("Vulnerabilities", "VulnerabilityID"),
                                  ("Secrets", "RuleID")):
            entries = result.get(field, []) or []
            if not isinstance(entries, list):
                raise ValueError(f"Trivy {field} must be an array")
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError(f"Trivy {field} contains a malformed finding")
                findings.append((
                    _label(item.get(rule_field)),
                    _label(item.get("Severity")),
                    filename,
                ))
    return {"finding_count": len(findings), "top_groups": _top_groups(findings, limit)}


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
    for name, filename, parser in specifications:
        path = root / filename
        if not path.is_file():
            reports[name] = {"status": "missing", "finding_count": None, "top_groups": []}
            missing.append(name)
            continue
        document, metadata = _read_report(path, name)
        metadata.update(parser(document, max_groups))
        reports[name] = metadata
    return {
        "schema": SCHEMA,
        "status": "complete" if not missing else "partial",
        "missing_reports": missing,
        "reports": reports,
        "raw_finding_values_retained": False,
        "full_paths_retained": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path,
                        help="write the sanitized JSON summary to this path")
    parser.add_argument("--max-groups", type=int, default=20)
    args = parser.parse_args()
    result = summarize_reports(args.root.resolve(strict=True), max_groups=args.max_groups)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"security report summarization failed: {error}", file=sys.stderr)
        raise SystemExit(2)
