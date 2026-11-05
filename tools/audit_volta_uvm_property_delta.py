#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare R580 and modern GV100 UVM architecture-property assignments.

The report is a lexical/source audit. It identifies old property names with
no live-code occurrence in the modern UVM tree; it does not infer semantic
replacement or runtime behavior.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_uvm_hal_dispatch import DEFAULT_R580_ARCHIVE  # noqa: E402
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    c_function_definition,
    extract_r580_uvm_c_sources,
)
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    R580_SOURCE_ROOT,
)

FUNCTION_NAME = "uvm_hal_volta_arch_init_properties"
FUNCTION_RELATIVE_PATH = Path("nvidia-uvm/uvm_volta.c")
COMMENT_PATTERN = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
LITERAL_PATTERN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
ASSIGNMENT_PATTERN = re.compile(
    r"parent_gpu->([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*?);", re.DOTALL
)


def strip_c_comments(source: str) -> str:
    """Remove C comments and literals before inspecting live source tokens."""
    source = LITERAL_PATTERN.sub(" ", source)
    return COMMENT_PATTERN.sub(" ", source)


def parse_parent_gpu_assignments(function_body: str) -> dict[str, str]:
    """Return unique parent_gpu field assignments from a parsed C function."""
    assignments: dict[str, str] = {}
    code = strip_c_comments(function_body)
    for field, value in ASSIGNMENT_PATTERN.findall(code):
        if field in assignments:
            raise ValueError(f"duplicate assignment to parent_gpu->{field}")
        assignments[field] = " ".join(value.split())
    if not assignments:
        raise ValueError("Volta architecture initializer has no parent_gpu assignments")
    return assignments


def scan_live_identifier_occurrences(source_root: Path,
                                     identifiers: set[str]) -> dict[str, list[dict]]:
    """Find identifier tokens in C/H code, excluding comments."""
    source_root = Path(source_root).resolve(strict=True)
    hits: dict[str, list[dict]] = {identifier: [] for identifier in identifiers}
    patterns = {
        identifier: re.compile(rf"\b{re.escape(identifier)}\b")
        for identifier in identifiers
    }
    for source_path in sorted(source_root.rglob("*")):
        if not source_path.is_file() or source_path.suffix not in {".c", ".h"}:
            continue
        source = strip_c_comments(source_path.read_text(encoding="utf-8", errors="strict"))
        for identifier, pattern in patterns.items():
            count = len(pattern.findall(source))
            if count:
                hits[identifier].append({
                    "path": source_path.relative_to(source_root).as_posix(),
                    "count": count,
                })
    return hits


def compare_property_assignments(r580: dict[str, str],
                                 modern: dict[str, str],
                                 modern_occurrences: dict[str, list[dict]]) -> dict:
    """Summarize assignments and the lexical fate of R580-only field names."""
    old_only = []
    changed = []
    for field in sorted(r580):
        if field not in modern:
            hits = modern_occurrences.get(field.rsplit(".", 1)[-1], [])
            old_only.append({
                "field": field,
                "r580_value": r580[field],
                "modern_live_identifier_occurrences": hits,
                "modern_live_identifier_occurrence_count": sum(
                    item["count"] for item in hits
                ),
            })
        elif r580[field] != modern[field]:
            changed.append({
                "field": field,
                "r580_value": r580[field],
                "modern_value": modern[field],
            })
    return {
        "r580_assignment_count": len(r580),
        "modern_assignment_count": len(modern),
        "common_assignment_count": len(set(r580) & set(modern)),
        "r580_only_assignments": old_only,
        "r580_only_assignment_count": len(old_only),
        "common_fields_with_changed_value": changed,
        "modern_only_assignments": {
            field: modern[field] for field in sorted(set(modern) - set(r580))
        },
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_function(source_root: Path) -> tuple[Path, str]:
    path = source_root / FUNCTION_RELATIVE_PATH
    if not path.is_file():
        raise ValueError(f"Volta initializer source is missing: {path}")
    body = c_function_definition(path, FUNCTION_NAME)
    return path, body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--expected-r580-sha256",
                        default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256)
    parser.add_argument("--expected-r580-source-root", default=R580_SOURCE_ROOT)
    parser.add_argument("--modern-source-root", type=Path, required=True,
                        help="root containing nvidia-uvm/uvm_volta.c")
    parser.add_argument("--modern-branch", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    archive_path = args.r580_archive.resolve(strict=True)
    archive_bytes = archive_path.read_bytes()
    archive_hash = _sha256(archive_bytes)
    if archive_hash != args.expected_r580_sha256:
        parser.error("R580 archive SHA-256 does not match the pinned value")

    modern_root = args.modern_source_root.resolve(strict=True)
    modern_uvm = modern_root / "nvidia-uvm"
    try:
        modern_path, modern_body = _extract_function(modern_root)
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))

    try:
        with tempfile.TemporaryDirectory(prefix="r580-volta-props-") as temporary:
            r580_uvm = extract_r580_uvm_c_sources(
                archive_path, Path(temporary) / "nvidia-uvm",
                args.expected_r580_source_root,
            )
            r580_path = r580_uvm / "uvm_volta.c"
            if not r580_path.is_file():
                raise ValueError(f"pinned R580 Volta source is missing: {r580_path}")
            r580_body = c_function_definition(r580_path, FUNCTION_NAME)
            r580_source_sha256 = _sha256(r580_path.read_bytes())
            r580_body_sha256 = _sha256(r580_body.encode())
            r580_assignments = parse_parent_gpu_assignments(r580_body)
    except (OSError, tarfile.TarError, ValueError, RuntimeError) as error:
        parser.error(f"cannot read pinned R580 Volta initializer: {error}")

    modern_assignments = parse_parent_gpu_assignments(modern_body)
    old_field_identifiers = {
        field.rsplit(".", 1)[-1]
        for field in set(r580_assignments) - set(modern_assignments)
    }
    occurrences = scan_live_identifier_occurrences(modern_uvm, old_field_identifiers)
    delta = compare_property_assignments(
        r580_assignments, modern_assignments, occurrences,
    )
    report = {
        "schema": "volta-uvm-property-delta-audit-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "pinned-source-lexical-property-audit",
        "modern_branch": args.modern_branch,
        "r580_archive": str(archive_path),
        "r580_archive_sha256": archive_hash,
        "r580_source_root": args.expected_r580_source_root,
        "r580_initializer": "kernel-open/nvidia-uvm/uvm_volta.c",
        "r580_initializer_sha256": r580_source_sha256,
        "r580_function_body_sha256": r580_body_sha256,
        "modern_source_root": str(modern_root),
        "modern_initializer": str(modern_path),
        "modern_initializer_sha256": _sha256(modern_path.read_bytes()),
        "modern_function_body_sha256": _sha256(modern_body.encode()),
        **delta,
        "limitations": [
            "A missing old identifier does not establish that its behavior was removed; modern code may encode the capability differently.",
            "This report does not infer replacements or validate callback semantics, UVM runtime, or hardware behavior.",
            "Only the Volta architecture-property initializer is compared; other initialization paths remain outside this report.",
        ],
    }
    report_path = args.report.resolve()
    if report_path.exists():
        parser.error(f"refusing to overwrite existing report: {report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({
        "report": str(report_path),
        "report_sha256": _sha256(report_path.read_bytes()),
        "modern_branch": args.modern_branch,
        "r580_assignments": delta["r580_assignment_count"],
        "modern_assignments": delta["modern_assignment_count"],
        "r580_only_assignments": delta["r580_only_assignment_count"],
        "r580_only_fields_with_no_modern_code_occurrence": sum(
            not item["modern_live_identifier_occurrence_count"]
            for item in delta["r580_only_assignments"]
        ),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
