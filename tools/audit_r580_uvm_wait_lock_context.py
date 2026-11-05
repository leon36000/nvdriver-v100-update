#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Find R580 CPU tracker waits reachable while a VA-block mutex is held.

The report is hash-pinned source analysis. A possible fault-progress deadlock
is an engineering risk, not a proven deadlock or runtime observation.
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

SOURCE_TAG = "580.178.04"
SOURCE_ROOT = (
    ROOT / "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
SOURCE_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
PATCH = ROOT / "patches/r580.178.04/uvm/0002-hybrid-isolated-gpu-execution.patch"
EXPECTED_ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
EXPECTED_PATCH_SHA256 = "23145778c944ae2cf222a6df192d97a1b3260c564772f4b353d48f0cf0cb26f0"
SOURCE_FILES = ("uvm_push.c", "uvm_tracker.c", "uvm_va_block.c", "uvm_migrate_pageable.c")
EXPECTED_SOURCE_SHA256 = {
    "uvm_push.c": "53b1cdd7abc6f5dcea062a314b5580b05329868ad36a61f6a3f0d567f3326227",
    "uvm_tracker.c": "756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41",
    "uvm_va_block.c": "dd2821620e83cfaeb03fd765d64dcb75d82da83a38107afa4b0c2882570a7b03",
    "uvm_migrate_pageable.c": "0aea84a9260f3ae70847e366ef83eae5d7119e0a4865ff631491200e004306bb",
}


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


def _function(root: Path, file_name: str, name: str) -> str:
    try:
        return c_function_definition(Path(root) / file_name, name)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract {file_name}:{name}: {exc}") from None


def _has(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None


def analyze_sources(source_root: Path) -> dict[str, Any]:
    """Recognize the exact source chain in a source tree or a test mutation."""
    source_root = Path(source_root)
    wrapper = _function(source_root, "uvm_push.c", "__uvm_push_begin_acquire_with_info")
    wait_helper = _function(source_root, "uvm_push.c", "wait_for_other_gpus_if_needed")
    locked_unmap = _function(source_root, "uvm_va_block.c", "uvm_va_block_unmap")
    unmap_push = _function(source_root, "uvm_va_block.c", "block_unmap_gpu")
    pageable_wait = _function(source_root, "uvm_migrate_pageable.c", "uvm_migrate_vma_copy_pages_from")
    pageable_vma = _function(source_root, "uvm_migrate_pageable.c", "migrate_pageable_vma")

    checks = {
        "generic_wrapper_waits_before_channel_reservation": _has(
            wrapper,
            r"wait_for_other_gpus_if_needed\s*\(\s*tracker\s*,\s*manager->gpu\s*\).*?"
            r"push_reserve_channel\s*\(\s*manager\s*,\s*type\s*,\s*dst_gpu\s*,\s*&channel\s*\)",
        ),
        "va_block_unmap_requires_block_lock": _has(
            locked_unmap,
            r"uvm_assert_mutex_locked\s*\(\s*&va_block->lock\s*\).*?"
            r"block_unmap_gpu\s*\(\s*va_block\s*,",
        ),
        "locked_unmap_push_acquires_block_tracker": _has(
            unmap_push,
            r"uvm_push_begin_acquire\s*\(\s*gpu->channel_manager\s*,\s*"
            r"UVM_CHANNEL_TYPE_MEMOPS\s*,\s*&block->tracker\s*,",
        ),
        "wait_is_reached_by_cross_gpu_tracker": _has(
            wait_helper,
            r"if\s*\(\s*tracker\s*==\s*NULL\s*\).*?return\s+NV_OK\s*;.*?"
            r"if\s*\(\s*uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\).*?"
            r"return\s+NV_OK\s*;.*?uvm_tracker_wait_for_other_gpus\s*\(\s*tracker\s*,\s*gpu\s*\)",
        )
        and _has(
            _function(source_root, "uvm_tracker.c", "uvm_tracker_wait_for_other_gpus"),
            r"if\s*\(\s*uvm_tracker_entry_gpu\s*\(\s*entry\s*\)\s*==\s*gpu\s*\)\s*"
            r"continue\s*;.*?wait_for_entry_with_spin\s*\(\s*entry\s*,\s*&spin\s*\)",
        ),
        "pageable_zero_tracker_wait_precedes_copy_push": _has(
            pageable_wait,
            r"uvm_tracker_t\s+zero_tracker\s*=\s*UVM_TRACKER_INIT\s*\(\s*\).*?"
            r"if\s*\(\s*!uvm_push_allow_dependencies_across_gpus\s*\(\s*\)\s*\)\s*"
            r"\{\s*status\s*=\s*uvm_tracker_wait_for_other_gpus\s*\(\s*&zero_tracker\s*,\s*copying_gpu\s*\)\s*;"
            r".*?migrate_vma_copy_begin_push\s*\(",
        ),
        "pageable_zero_tracker_tracks_only_zero_push": (
            [value.strip() for value in re.findall(
                r"uvm_tracker_add_(?:tracker|push_safe)\s*\(\s*&zero_tracker\s*,\s*([^,)]+)",
                pageable_wait,
            )] == ["&zero_push"]
        ),
        "pageable_path_rejects_uvm_owned_vma": _has(
            pageable_vma,
            r"uvm_file_is_nvidia_uvm_va_space\s*\(\s*vma->vm_file\s*\)\s*\)\s*"
            r"return\s+NV_ERR_INVALID_ADDRESS\s*;",
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    status = "risk" if not failed else "unresolved"
    return {"status": status, "checks": checks, "failed_checks": failed}


def audit_sources(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise ValueError("UVM source root must not be a symlink")
    source_root = source_root.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be the R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != f"NVIDIA-kernel-module-source-{SOURCE_TAG}":
        raise ValueError("source tree is not NVIDIA R580.178.04")

    archive = SOURCE_ARCHIVE.resolve(strict=True)
    patch = PATCH.resolve(strict=True)
    archive_hash = sha256_file(archive)
    patch_hash = sha256_file(patch)
    if archive_hash != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("pinned R580 source archive SHA-256 mismatch")
    if patch_hash != EXPECTED_PATCH_SHA256:
        raise ValueError("isolated-UVM patch SHA-256 mismatch")

    source_files = {}
    for name, expected in EXPECTED_SOURCE_SHA256.items():
        path = source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source must be a regular non-symlink file: {name}")
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"pinned source SHA-256 mismatch for {name}: {actual}")
        source_files[name] = {"path": project_path(path), "sha256": actual, "bytes": path.stat().st_size}

    result = analyze_sources(source_root)
    return {
        "schema": "nvidia-r580-uvm-wait-lock-context-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": SOURCE_TAG,
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "inputs": {
            "source_archive": {"path": project_path(archive), "sha256": archive_hash},
            "patch": {"path": project_path(patch), "sha256": patch_hash},
            "source_files": source_files,
        },
        "result": result,
        "interpretation": (
            "The pinned path reaches the isolated-mode CPU tracker wait from a page-table "
            "unmap push while uvm_va_block_unmap asserts that va_block->lock is held. A GPU "
            "command whose completion requires UVM fault service on the same block could be "
            "unable to make progress until that lock is released. The patch also adds a distinct "
            "pageable-migration wait on zero_tracker before the copy push; the inspected pageable "
            "VMA path rejects NVIDIA UVM-owned VMAs, but this audit does not prove that all callers "
            "avoid holding other progress-critical locks. These are lock-context risks, not proof "
            "of a deadlock or runtime observations. Do not load-test this mode until each wait has "
            "a source-backed progress argument and a targeted fault/concurrency stress test."
        ),
    }


def write_json(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root)
        if args.output:
            write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    return 1 if report["result"]["status"] == "unresolved" else 0


if __name__ == "__main__":
    raise SystemExit(main())
