#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit every direct R580 UVM tracker acquire in the isolated-GPU patch.

This is a narrow, hash-pinned source audit. It does not load a module, run a
GPU, or establish runtime synchronization, DMA, or memory-coherency behavior.
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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_hybrid_uvm_abi import c_function_definition  # noqa: E402
from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402

SOURCE_TAG = "580.178.04"
SOURCE_ROOT = (
    ROOT / "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
SOURCE_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
PATCH = ROOT / "patches/r580.178.04/uvm/0002-hybrid-isolated-gpu-execution.patch"
EXPECTED_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
EXPECTED_PATCH_SHA256 = "23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0"
EXPECTED_PATCHED_SOURCE_SHA256 = {
    "uvm_gpu.c": "23bb5a514a99b1c747e683ddd3612511647cc3e95745ccdc1b1e22db3d584197",
    "uvm_gpu_semaphore.c": "4224b4f808c9f86279cb97bfa9645e6b592ace4b2f4213e81848d1ebba4258a3",
    "uvm_push.c": "53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227",
    "uvm_migrate_pageable.c": "0aea84a9260f3ae70847e366ef83eae5d7119e0a4865ff631491200e004306bb",
    "uvm_channel_test.c": "f846b5e2925258bb1643e389bee4016743a73a6f396571e0621aac109bb94e87",
}
EXPECTED_DIRECT_CALLS = {
    "uvm_push.c": ("push_begin_acquire_with_info", "wrappers_wait_or_pass_a_null_tracker"),
    "uvm_migrate_pageable.c": (
        "uvm_migrate_vma_copy_pages_from",
        "cpu_wait_for_other_gpus_before_acquire",
    ),
    "uvm_channel_test.c": (
        "stress_test_all_gpus_in_va",
        "same_gpu_or_cross_gpu_dependencies_enabled",
    ),
}

_CALL_PATTERN = re.compile(r"\buvm_push_acquire_tracker\s*\(")
_MASK_PATTERN = re.compile(
    r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
    re.DOTALL,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _mask_comments_and_literals(text: str) -> str:
    """Blank comments and literals while preserving offsets and line numbers."""
    return _MASK_PATTERN.sub(
        lambda match: re.sub(r"[^\n]", " ", match.group(0)), text
    )


def _direct_call_sites(uvm_root: Path) -> list[dict[str, Any]]:
    sites: list[dict[str, Any]] = []
    for path in sorted(Path(uvm_root).rglob("*.c")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"UVM C source must be a regular non-symlink file: {path.name}")
        raw = path.read_text(encoding="utf-8")
        masked = _mask_comments_and_literals(raw)
        definition = None
        if path.name == "uvm_push.c":
            definition = re.search(
                r"\bvoid\s+uvm_push_acquire_tracker\s*\([^;{}]*\)\s*\{",
                masked,
            )
        for match in _CALL_PATTERN.finditer(masked):
            if definition and match.start() == definition.start() + definition.group(0).index(
                "uvm_push_acquire_tracker"
            ):
                continue
            sites.append(
                {
                    "file": path.relative_to(uvm_root).as_posix(),
                    "line": masked.count("\n", 0, match.start()) + 1,
                    "path": str(path),
                }
            )
    return sites


def _function(path: Path, name: str) -> str:
    try:
        return c_function_definition(path, name)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract UVM function {name}: {exc}") from None


def _ordered(
    text: str,
    patterns: list[str],
    description: str,
    *,
    failed_checks: list[str] | None = None,
    check_name: str | None = None,
) -> bool:
    cursor = 0
    for pattern in patterns:
        match = re.search(pattern, text[cursor:], re.DOTALL)
        if match is None:
            if failed_checks is not None:
                failed_checks.append(check_name or description)
                return False
            raise ValueError("unrecognized tracker-acquire protection: " + description)
        cursor += match.end()
    return True


def analyze_call_sites(uvm_root: Path) -> dict[str, Any]:
    """Recognize the complete current direct-acquire inventory or fail closed."""
    uvm_root = Path(uvm_root)
    sites = _direct_call_sites(uvm_root)
    counts: dict[str, int] = {}
    for site in sites:
        counts[site["file"]] = counts.get(site["file"], 0) + 1

    unreviewed = [
        {"file": site["file"], "function": None}
        for site in sites
        if site["file"] not in EXPECTED_DIRECT_CALLS or counts[site["file"]] != 1
    ]
    failed_checks: list[str] = []
    recognized = []
    for file_name, (function, protection) in EXPECTED_DIRECT_CALLS.items():
        if counts.get(file_name, 0) != 1:
            failed_checks.append(file_name)
            continue
        recognized.append({"file": file_name, "function": function, "protection": protection})

    push_path = uvm_root / "uvm_push.c"
    push_acquire = _function(push_path, "push_begin_acquire_with_info")
    if len(_CALL_PATTERN.findall(_mask_comments_and_literals(push_acquire))) != 1:
        failed_checks.append("uvm_push.c:push_begin_acquire_with_info")

    for name in (
        "__uvm_push_begin_acquire_with_info",
        "__uvm_push_begin_acquire_on_channel_with_info",
    ):
        try:
            wrapper = _function(push_path, name)
            _ordered(
                _mask_comments_and_literals(wrapper),
                [r"wait_for_other_gpus_if_needed\s*\(", r"push_begin_acquire_with_info\s*\("],
                f"{name} must CPU-wait before the shared acquire helper",
            )
        except ValueError:
            failed_checks.append(f"uvm_push.c:{name}")
    reserved = _function(push_path, "__uvm_push_begin_on_reserved_channel_with_info")
    if re.search(
        r"push_begin_acquire_with_info\s*\(\s*channel\s*,\s*NULL\s*,\s*push\s*,",
        _mask_comments_and_literals(reserved),
    ) is None:
        failed_checks.append("uvm_push.c:reserved-channel-null-tracker")

    migration = _function(uvm_root / "uvm_migrate_pageable.c", "uvm_migrate_vma_copy_pages_from")
    _ordered(
        _mask_comments_and_literals(migration),
        [
            r"if\s*\(\s*!uvm_push_allow_dependencies_across_gpus\s*\(\)\s*\)\s*\{",
            r"uvm_tracker_wait_for_other_gpus\s*\(\s*&zero_tracker\s*,\s*copying_gpu\s*\)",
            r"if\s*\(\s*status\s*!=\s*NV_OK\s*\)\s*\{\s*"
            r"uvm_tracker_wait_deinit\s*\(\s*&zero_tracker\s*\)\s*;\s*return\s+status\s*;\s*\}",
            r"migrate_vma_copy_begin_push\s*\(",
            r"uvm_push_acquire_tracker\s*\(\s*&push\s*,\s*&zero_tracker\s*\)",
        ],
        "pageable migration must wait and propagate errors before direct acquire",
        failed_checks=failed_checks,
        check_name="uvm_migrate_pageable.c:cpu-wait-before-acquire",
    )

    channel_test = _function(uvm_root / "uvm_channel_test.c", "stress_test_all_gpus_in_va")
    if re.search(
        r"if\s*\(\s*\(\s*random_stream->push\.gpu\s*==\s*gpu\s*\)\s*\|\|\s*"
        r"uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\)\s*\{\s*"
        r"uvm_push_acquire_tracker\s*\(",
        _mask_comments_and_literals(channel_test),
        re.DOTALL,
    ) is None:
        failed_checks.append("uvm_channel_test.c:same-gpu-or-enabled-guard")

    return {
        "status": "pass" if not unreviewed and not failed_checks else "fail",
        "direct_acquire_sites": recognized,
        "direct_acquire_count": len(sites),
        "unreviewed_direct_acquire_sites": unreviewed,
        "failed_protection_checks": sorted(set(failed_checks)),
        "scanner": "all recursive UVM C files; C comments and literals masked; definition excluded",
    }


def audit_sources(uvm_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    uvm_root = Path(uvm_root)
    if uvm_root.is_symlink():
        raise ValueError("UVM source root must not be a symlink")
    uvm_root = uvm_root.resolve(strict=True)
    if uvm_root.name != "nvidia-uvm" or uvm_root.parent.name != "kernel-open":
        raise ValueError("source root must be the R580 kernel-open/nvidia-uvm tree")
    source_package = uvm_root.parent.parent
    if source_package.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source tree is not NVIDIA R580.178.04")

    archive = SOURCE_ARCHIVE.resolve(strict=True)
    patch = PATCH.resolve(strict=True)
    archive_sha = sha256_file(archive)
    patch_sha = sha256_file(patch)
    if archive_sha != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 archive SHA-256 mismatch")
    if patch_sha != EXPECTED_PATCH_SHA256:
        raise ValueError("isolated-UVM patch SHA-256 mismatch")

    patched_files = {}
    for name, expected in EXPECTED_PATCHED_SOURCE_SHA256.items():
        path = uvm_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected a regular patched source file: {name}")
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"patched R580 source hash mismatch for {name}: {actual}")
        patched_files[name] = {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}

    all_sources = []
    for path in sorted(uvm_root.rglob("*.c")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"UVM C source must be a regular non-symlink file: {path.name}")
        all_sources.append({
            "file": path.relative_to(uvm_root).as_posix(),
            "sha256": sha256_file(path),
        })

    return {
        "schema": "nvidia-r580-uvm-isolated-tracker-acquire-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "runtime_or_hardware_validated": False,
            "module_loaded_or_installed": False,
        },
        "inputs": {
            "source_archive": {"path": project_path(archive), "sha256": archive_sha},
            "patch": {"path": project_path(patch), "sha256": patch_sha},
            "auditor": {
                "path": project_path(Path(__file__)),
                "sha256": sha256_file(Path(__file__)),
            },
            "patched_sources": patched_files,
            "scanned_c_sources": all_sources,
        },
        "result": analyze_call_sites(uvm_root),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = audit_sources(args.source_root)
        if args.report:
            write_private_evidence_report(args.report, report)
        print(json.dumps(report, indent=2))
        return 0 if report["result"]["status"] == "pass" else 1
    except (OSError, ValueError, RuntimeError, UnicodeError) as error:
        print(f"R580 UVM acquire audit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
