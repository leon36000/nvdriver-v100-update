#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit pinned R580/R595 deferred-free caller lock-release source windows."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
R580_ROOT = ROOT / (
    "build/experiments/r580-nonreplayable-fault-drains-v3-20261028T0634Z/"
    "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
R595_ROOT = ROOT / (
    "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v15-20261028T004147Z/nvidia-uvm"
)
CALLER_FILES = (
    "uvm_map_external.c",
    "uvm_user_channel.c",
    "uvm_va_range.c",
    "uvm_va_range_device_p2p.c",
    "uvm_va_space.c",
    "uvm_va_space_mm.c",
)
EXPECTED_COUNTS = {
    "uvm_map_external.c": 2,
    "uvm_user_channel.c": 3,
    "uvm_va_range.c": 1,
    "uvm_va_range_device_p2p.c": 1,
    "uvm_va_space.c": 5,
    "uvm_va_space_mm.c": 1,
}
EXPECTED_SOURCE_SHA256 = {
    "r580_candidate": {
        "uvm_map_external.c": "1e72573e3ebc2c3117768ab0517e4b7e9acdb62af2368513a37500d6f13c11dd",
        "uvm_user_channel.c": "8fe5ce63871dbf7509c4ebbe7d0eeee8e0008693622479aed452d3b7c42015b6",
        "uvm_va_range.c": "10c80433314c9b38cc84f82ac156f2df9d0f5c9d3c73a9e64179047eb2148878",
        "uvm_va_range_device_p2p.c": "64090e24a6cd722769bf2023d3299485ce516eb03334adfbc459ebc0738c19b5",
        "uvm_va_space.c": "2309eb47fad1d4ec4f932f8eae58fc4802b2380a0a95be2e964a9897117b0418",
        "uvm_va_space_mm.c": "f9a8e86af533a538834fc55b04896703da16d76bb57d4f481532a85d287e905c",
    },
    "r595": {
        "uvm_map_external.c": "bd5284ad85f61bd7e368e056331c4e34efb9c169f99ba98ed3b539b6dd491e05",
        "uvm_user_channel.c": "9a6cec689eaf9c1edd1b7defa9ee7e74215382d802e7ab192b52caa1d0e93fe7",
        "uvm_va_range.c": "26c4c705ea797d0247740678b545d5b2394839eba61d79bef50182ffe6537787",
        "uvm_va_range_device_p2p.c": "8c3068201d9ef453f0f2efc365d6dd265cf0b5e465bb649913790c304c82503c",
        "uvm_va_space.c": "f332076b5d141b23cbe7acaccb48b2b07a0f8fe2e44832fd93551a4a8c345468",
        "uvm_va_space_mm.c": "3153e9d1e6444eaa7246dd2b2014583c90755fec77b48e38b77edd99bd83fc98",
    },
}
CALL_RE = re.compile(r"\buvm_deferred_free_object_list\s*\(\s*&deferred_free_list\s*\)\s*;")
RELEASE_RE = re.compile(
    r"\b(uvm_va_space_up_(?:read|write)(?:_rm)?|"
    r"uvm_va_space_mm_or_current_release(?:_unlock)?|uvm_up_read_mmap_lock|"
    r"uvm_mutex_unlock|uvm_spin_unlock)\s*\("
)
ACQUIRE_RE = re.compile(
    r"\b(uvm_va_space_down_(?:read|write)(?:_rm)?|"
    r"uvm_va_space_mm_or_current_retain_lock|uvm_down_read_mmap_lock|"
    r"uvm_mutex_lock|uvm_spin_lock)\s*\("
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _code_lines(source: str) -> list[str]:
    """Remove C comments while preserving line numbers and non-comment text."""
    result: list[str] = []
    in_block = False
    for line in source.splitlines():
        output: list[str] = []
        index = 0
        quote: str | None = None
        escaped = False
        while index < len(line):
            char = line[index]
            pair = line[index:index + 2]
            if in_block:
                if pair == "*/":
                    in_block = False
                    index += 2
                else:
                    index += 1
                continue
            if quote:
                output.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if pair == "//":
                break
            if pair == "/*":
                in_block = True
                index += 2
                continue
            if char in ('"', "'"):
                quote = char
            output.append(char)
            index += 1
        result.append("".join(output))
    return result


def _audit_source(root: Path, source_name: str) -> dict[str, Any]:
    expected_hashes = EXPECTED_SOURCE_SHA256[source_name]
    call_sites: list[dict[str, Any]] = []
    files: dict[str, dict[str, Any]] = {}
    issues: list[str] = []

    for filename in CALLER_FILES:
        path = root / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"{source_name} caller source must be a regular file: {filename}")
        source_hash = _sha256(path)
        if source_hash != expected_hashes[filename]:
            raise ValueError(f"{source_name} source SHA-256 mismatch for {filename}: {source_hash}")
        lines = _code_lines(path.read_text(encoding="utf-8"))
        file_sites: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            if not CALL_RE.search(line):
                continue
            window_start = max(0, index - 96)
            release_matches: list[tuple[int, str, str]] = []
            for prior_index in range(window_start, index):
                for match in RELEASE_RE.finditer(lines[prior_index]):
                    release_matches.append((prior_index, match.group(1), lines[prior_index].strip()))
            last_release = release_matches[-1] if release_matches else None
            if last_release is None:
                issues.append(f"{filename}:{index + 1}: no recognized release in prior 96 lines")
                release_index = window_start - 1
                release_record = None
                line_distance = None
            else:
                release_index, release_symbol, statement = last_release
                release_record = {
                    "symbol": release_symbol,
                    "line": release_index + 1,
                    "statement": statement,
                }
                line_distance = index - release_index

            acquisitions = []
            if last_release is not None:
                for after_index in range(release_index + 1, index):
                    for match in ACQUIRE_RE.finditer(lines[after_index]):
                        acquisitions.append({
                            "symbol": match.group(1),
                            "line": after_index + 1,
                            "statement": lines[after_index].strip(),
                        })
                if acquisitions:
                    issues.append(f"{filename}:{index + 1}: direct lock acquisition follows last release")

            site = {
                "source_file": filename,
                "line": index + 1,
                "last_release": release_record,
                "line_distance": line_distance,
                "direct_lock_acquisitions_after_last_release": acquisitions,
            }
            file_sites.append(site)
            call_sites.append(site)

        files[filename] = {
            "path": str(path.resolve()),
            "sha256": source_hash,
            "call_site_count": len(file_sites),
        }

    per_file_counts = {filename: files[filename]["call_site_count"] for filename in CALLER_FILES}
    if per_file_counts != EXPECTED_COUNTS:
        issues.append(f"unexpected call-site distribution: {per_file_counts}")
    if len(call_sites) != 13:
        issues.append(f"expected 13 call sites, observed {len(call_sites)}")

    return {
        "source_root": str(root.resolve()),
        "files": files,
        "per_file_counts": per_file_counts,
        "call_site_count": len(call_sites),
        "call_sites": call_sites,
        "direct_lock_window_checks_passed": not issues,
        "issues": issues,
    }


def audit_callers() -> dict[str, Any]:
    sources = {
        "r580_candidate": _audit_source(R580_ROOT, "r580_candidate"),
        "r595": _audit_source(R595_ROOT, "r595"),
    }
    return {
        "schema": "r580-r595-deferred-free-caller-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "static-source-analysis-only",
        "runtime_or_hardware_validated": False,
        "status": "pass" if all(
            source["direct_lock_window_checks_passed"] for source in sources.values()
        ) else "fail",
        "sources": sources,
        "scope": (
            "Pinned source-window audit of direct deferred-free call expressions. It records the nearest "
            "recognized direct lock-release token within 96 source lines and checks for a recognized direct "
            "lock-acquisition token after it. This is not path-sensitive, does not inspect locks taken inside "
            "called helpers, does not prove kernel lock state, and does not prove concurrency safety."
        ),
    }


def _write_new_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args(argv)
    report_path = args.report if args.report.is_absolute() else ROOT / args.report
    log_path = args.log if args.log.is_absolute() else ROOT / args.log
    report = audit_callers()
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    summary = {
        "report": str(report_path),
        "report_sha256": hashlib.sha256(encoded).hexdigest(),
        "status": report["status"],
        "sources": {
            name: {
                "call_site_count": source["call_site_count"],
                "direct_lock_window_checks_passed": source["direct_lock_window_checks_passed"],
                "issues": source["issues"],
            }
            for name, source in report["sources"].items()
        },
    }
    log = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_new_private(report_path, encoded)
    _write_new_private(log_path, log)
    print(json.dumps(summary, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
