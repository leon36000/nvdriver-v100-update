#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trace cross-provider managed-memory staging against isolated R580 UVM.

This is a source-pinned static audit. It does not execute UVM or validate GPU
faults, page copies, liveness, or data integrity on hardware.
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


SOURCE_ROOT = (
    ROOT / "build/experiments/r580-uvm-standard-stack-consumer-v1-20261028T1414Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
)
BRIDGE_PATH = ROOT / "src/hybrid580_uvm_callback_bridge.c"
BUILD_REPORT = ROOT / "evidence/r580-uvm-standard-stack-consumer-v2-20261028T1420Z.json"
EXPECTED_SHA256 = {
    "uvm_va_block.c": "6e19e66f0dab6d25a18e67060df144c4fc9d7963ca926a1741f471466e27d73b",
    "uvm_push.c": "9ace70a23fb4316d7169446d8002a5ec1f293cf067bec24a7b6399c8a8b97e41",
    "uvm_tracker.c": "af78f7843aefe9682ddc3bf5a44a0fcaec0d59043e50d9fb1a0da51d058ed608",
    "uvm_gpu.c": "973408d4ed952a8b9244623ebe9b557dd49222f8c3a8f59de94f42328be3c215",
    "uvm_va_space.c": "f3ff460e979af67874cbaa274edcea587e0f22178ca2323437a26bc1ae294555",
    "hybrid580_uvm_callback_bridge.c": "c581cda76752f4dd4b903442309b5944dd2ff6eb9dd702c6dc4d91345aca86c5",
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


def _function(source_root: Path, file_name: str, name: str) -> str:
    try:
        return c_function_definition(Path(source_root) / file_name, name)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise ValueError(f"cannot extract {file_name}:{name}: {exc}") from None


def _matches(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None


def analyze_sources(source_root: Path, bridge_path: Path) -> dict[str, Any]:
    """Analyze source flow without relying on a running module or GPU."""
    source_root = Path(source_root)
    bridge_path = Path(bridge_path)
    block_copy = _function(source_root, "uvm_va_block.c", "block_copy_resident_pages")
    begin_push = _function(source_root, "uvm_va_block.c", "block_copy_begin_push")
    push_policy = _function(source_root, "uvm_push.c", "reject_other_gpus_if_isolated")
    tracker_check = _function(source_root, "uvm_tracker.c", "uvm_tracker_has_other_gpus")
    peer_discovery = _function(source_root, "uvm_gpu.c", "parent_peers_discover_nvlink")
    p2p_caps = c_function_definition(bridge_path, "nvUvmInterfaceGetP2PCaps")
    va_space_source = (source_root / "uvm_va_space.c").read_text()

    stage_order = [
        r"uvm_processor_mask_and\s*\(\s*src_processor_mask\s*,\s*"
        r"block_get_can_copy_from_mask\s*\(\s*block\s*,\s*dst_id\s*\)",
        r"uvm_processor_mask_andnot\s*\(\s*src_processor_mask\s*,\s*&block->resident\s*,\s*src_processor_mask\s*\)",
        r"block_copy_resident_pages_mask\s*\(\s*block\s*,\s*block_context\s*,\s*"
        r"UVM_ID_CPU\s*,\s*src_processor_mask",
        r"uvm_tracker_add_tracker_safe\s*\(\s*&block->tracker\s*,\s*&local_tracker\s*\)",
        r"block_copy_resident_pages_between\s*\(\s*block\s*,\s*block_context\s*,\s*"
        r"dst_id\s*,\s*NUMA_NO_NODE\s*,\s*UVM_ID_CPU",
    ]
    ordered = True
    cursor = 0
    for pattern in stage_order:
        match = re.search(pattern, block_copy[cursor:], re.MULTILINE | re.DOTALL)
        if match is None:
            ordered = False
            break
        cursor += match.end()

    checks = {
        "unsupported_residency_is_selected_for_cpu_staging": _matches(
            block_copy,
            r"uvm_processor_mask_andnot\s*\(\s*src_processor_mask\s*,\s*&block->resident\s*,\s*src_processor_mask\s*\)",
        ),
        "source_stage_tracker_is_merged_before_destination_stage": ordered,
        "each_stage_acquires_the_va_block_tracker": _matches(
            begin_push,
            r"tracker_ptr\s*=\s*&va_block->tracker;.*?"
            r"uvm_push_begin_acquire\s*\(.*?tracker_ptr",
        ),
        "isolated_mode_rejects_pending_other_gpu_tracker": _matches(
            push_policy,
            r"uvm_push_isolated_gpu_execution_enabled\s*\(\s*\).*?"
            r"uvm_tracker_has_other_gpus\s*\(\s*tracker\s*,\s*gpu\s*\)\s*\)\s*"
            r"return\s+NV_ERR_NOT_SUPPORTED",
        ),
        "completed_tracker_exempts_reject_path": _matches(
            tracker_check,
            r"uvm_tracker_is_completed\s*\(\s*tracker\s*\)\s*\)\s*return\s+false",
        ),
        "cross_provider_p2p_caps_report_no_link": _matches(
            p2p_caps,
            r"HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER\s*\)\s*\{.*?"
            r"p2pCapsParams->p2pLink\s*=\s*UVM_LINK_TYPE_NONE;.*?status\s*=\s*NV_OK",
        ),
        "uvm_static_peer_discovery_skips_no_link": _matches(
            peer_discovery,
            r"p2p_caps_params\.p2pLink\s*==\s*UVM_LINK_TYPE_NONE.*?continue\s*;",
        ),
        "va_space_direct_copy_pairs_are_only_added_by_peer_enable": (
            _matches(
                va_space_source,
                r"static\s+NV_STATUS\s+enable_peers\s*\(.*?"
                r"processor_mask_array_set\s*\(\s*va_space->can_copy_from\s*,\s*gpu1->id\s*,\s*gpu0->id\s*\)",
            )
            and _matches(
                va_space_source,
                r"processor_mask_array_set\s*\(\s*va_space->can_copy_from\s*,\s*gpu->id\s*,\s*gpu->id\s*\).*?"
                r"processor_mask_array_set\s*\(\s*va_space->can_copy_from\s*,\s*gpu->id\s*,\s*UVM_ID_CPU\s*\)",
            )
        ),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        behavior = "unresolved_source_contract"
    elif checks["completed_tracker_exempts_reject_path"]:
        behavior = "cross_provider_gpu_staging_can_be_rejected_when_source_tracker_is_pending"
    else:
        behavior = "cross_provider_gpu_staging_is_unconditionally_rejected"

    return {
        "status": "conditional_blocker" if not failed else "unresolved",
        "migration_behavior": behavior,
        "checks": checks,
        "failed_checks": failed,
        "interpretation": (
            "When a destination GPU cannot copy directly from a resident GPU, the pinned UVM "
            "path stages those pages through CPU memory, merges the first-stage tracker into "
            "the VA-block tracker, then queues the CPU-to-destination stage against that same "
            "tracker. The hybrid bridge reports no cross-provider P2P link, and isolated mode "
            "returns NV_ERR_NOT_SUPPORTED if the destination push sees an outstanding entry "
            "from another GPU. A completed source tracker is exempt, so the exact failure is "
            "conditional on work still being pending at the destination reservation. This is "
            "a static control-flow result; it is not a runtime failure, timing measurement, or "
            "proof that every migration attempt fails."
        ),
        "next_action": (
            "Design a lock-safe two-phase staging protocol and validate it with delayed source "
            "copy completion plus concurrent same-block fault/unmap. Do not replace the reject "
            "with an unbounded CPU tracker wait while the VA-block lock is held."
        ),
    }


def audit_sources(source_root: Path = SOURCE_ROOT, bridge_path: Path = BRIDGE_PATH) -> dict[str, Any]:
    source_root = Path(source_root)
    bridge_path = Path(bridge_path)
    if source_root.is_symlink() or bridge_path.is_symlink():
        raise ValueError("source root and bridge must not be symlinks")
    source_root = source_root.resolve(strict=True)
    bridge_path = bridge_path.resolve(strict=True)
    if source_root.name != "nvidia-uvm" or source_root.parent.name != "kernel-open":
        raise ValueError("source root must be the R580 kernel-open/nvidia-uvm tree")
    package = source_root.parent.parent
    if package.name != "NVIDIA-kernel-module-source-580.178.04":
        raise ValueError("source tree is not NVIDIA R580.178.04")
    if sha256_file(BUILD_REPORT) != "2277575e8672b0fae4dc47f272b60d632c12cc9d5a2fb298bcbc7102d1b7af27":
        raise ValueError("R580 standard-stack UVM build report changed")

    inputs: dict[str, dict[str, Any]] = {}
    for name, expected in EXPECTED_SHA256.items():
        path = bridge_path if name == "hybrid580_uvm_callback_bridge.c" else source_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected regular source file: {name}")
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"pinned source SHA-256 mismatch for {name}: {actual}")
        inputs[name] = {
            "path": project_path(path),
            "sha256": actual,
            "bytes": path.stat().st_size,
        }

    return {
        "schema": "nvidia-r580-uvm-staged-migration-isolation-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_release": "580.178.04",
        "qualification": {
            "level": "analyzed-statically",
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        },
        "build_reference": {
            "path": project_path(BUILD_REPORT),
            "sha256": sha256_file(BUILD_REPORT),
            "qualification": "compiled candidate source; not loaded or installed",
        },
        "inputs": inputs,
        "result": analyze_sources(source_root, bridge_path),
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
    parser.add_argument("--bridge", type=Path, default=BRIDGE_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_sources(args.source_root, args.bridge)
        if args.output:
            write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    return 1 if report["result"]["status"] == "unresolved" else 0


if __name__ == "__main__":
    raise SystemExit(main())
