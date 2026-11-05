#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fully rebuild the replayed R595.99.02 Open provider for the PC3 Linux 6.8 target.

The source copy and Kbuild outputs stay under /tmp. The report and build log
are preserved in the project. This tool never installs or loads a module.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_replayed_r595_open import (  # noqa: E402
    REPLAY_REPORT,
    REPLAY_REPORT_SHA256,
    R595_CORE,
    R595_CORE_SHA256,
    apply_kmod_softdep_overlay,
    source_from_replay_report,
    validate_replay_report,
    validate_replayed_source,
)

KERNEL_RELEASE = "6.8.0-147-generic"
REPLAYED_SOURCE_VERSION = "595.99.02"
KERNEL_HEADERS = Path(
    "/tmp/nvidia-hybrid-linux68-headers-20261029/tree/usr/src/linux-headers-"
    "6.8.0-147-generic"
)
KERNEL_SYMVERS_SHA256 = "8e7eb5798789b9610c324b3d9b13373d88c30ae17bb9e41e622efd05e0277a87"
GCC13 = Path(
    "/tmp/nvidia-hybrid-linux68-headers-20261029/gcc13-root/usr/bin/"
    "x86_64-linux-gnu-gcc-13"
)
GCC13_SHA256 = "1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26"
FRONTEND_SYMVERS = ROOT / "build/experiments/r595-hybrid-frontend-linux68-gcc13-v4/Module.symvers"
FRONTEND_SYMVERS_SHA256 = "40b11e3f5c9a5d54e1f5ec08216f1536d3d0061ad89f1a6c8030e16b0dd16f78"
PFN_PATCH = ROOT / "patches/r595.99.02/0013-open-pfn-backed-io-guard.patch"
PFN_PATCH_SHA256 = "018fd72247d5865639f5ea867226b9da9afa49a66aed3e2d7c711b2b0d2c625f"
PFN_PREIMAGE_SHA256 = "dcee9c5d88286ab8b07b6a9e991b64da7f125c0c8a387f11ab1aecbf5a0cd15e"
PFN_POSTIMAGE_SHA256 = "760a5ee564cd0f151aea337eca146578bed157c80c8152f9aa9b414db6576609"
LARGE_TABLE_PATCH = ROOT / "patches/r595.99.02/0015-open-large-page-table-vmalloc.patch"
LARGE_TABLE_PATCH_SHA256 = "92cad31b353b9be74d89805f9b942c11901c7c9d623febd93341513699eddb0c"
LARGE_TABLE_PREIMAGE_SHA256 = "609c30cfd12f92496e21f788c095721f6668c5a5d12e7f119f3e34a3d1c0a827"
LARGE_TABLE_POSTIMAGE_SHA256 = "bfd37cdb02d03b1b619cd4361f7cd99fd470cfa11f6329c771d3cfd704534735"
LARGE_TABLE_EXPECTED_OFFSET = 56
LARGE_TABLE_PATH = "kernel-open/nvidia/nv.c"
LARGE_TABLE_HEADER_PATH = "kernel-open/common/inc/nv-linux.h"
LARGE_TABLE_HEADER_PREIMAGE_SHA256 = "167ea8813202a758d4a70c113822de44bd82cd686a6de6891f445da74e27ccdb"
LARGE_TABLE_HEADER_POSTIMAGE_SHA256 = "77652d97ef1873066e776be6ce06686c10ebef03099712d49f4b62107b5bd6d3"
LARGE_TABLE_OS_INTERFACE_PATH = "kernel-open/nvidia/os-interface.c"
LARGE_TABLE_OS_INTERFACE_PREIMAGE_SHA256 = "75aa2f569379a3ccce2f438c09db68cc9ce0b0affd73612739561939fe982c35"
LARGE_TABLE_OS_INTERFACE_POSTIMAGE_SHA256 = "754593fc20cb1e663861a734959608f1ba68b73aff3ccaf9499a974118ec1394"
LARGE_TABLE_OVERLAY_PATHS = {
    LARGE_TABLE_PATH, LARGE_TABLE_HEADER_PATH, LARGE_TABLE_OS_INTERFACE_PATH,
}
PAGE_POOL_PROTOTYPES_PATCH = ROOT / "patches/r595.99.02/0016-open-page-pool-prototypes.patch"
PAGE_POOL_PROTOTYPES_PATCH_SHA256 = "2627993857d15e2ab17a5f6e43b83751e149c8a7ca78d5cd002f1904ea21471f"
PAGE_POOL_PROTOTYPES_FILES = {
    "kernel-open/common/inc/nv-linux.h": (
        "77652d97ef1873066e776be6ce06686c10ebef03099712d49f4b62107b5bd6d3",
        "b9a8822c3c54efbec9cad25e69de97d40768d73c7bb132152b9de764b1086f98",
    ),
    "kernel-open/nvidia/nv-vm.c": (
        "899ccf12b9c94effcb344be999878063cc6447d08a49def30131ba0c4692fcea",
        "7f9a78fa179a238fdabde00534d8c0bcde0fa22110e73fe05ddec3338f99edb0",
    ),
    "kernel-open/nvidia/nv.c": (
        "bfd37cdb02d03b1b619cd4361f7cd99fd470cfa11f6329c771d3cfd704534735",
        "9a52caa0181cac587cec0c0e0f8f4fc99faf49b87ddc3eb92ec6dbce5f602358",
    ),
}
PAGE_POOL_PROTOTYPES_OVERLAY_PATHS = set(PAGE_POOL_PROTOTYPES_FILES)
DMABUF_UNMAP_PATCH = ROOT / "patches/r595.99.02/0017-open-dmabuf-unmap-original-nents.patch"
DMABUF_UNMAP_PATCH_SHA256 = "15aa502cf2f1e94c11dca726fcf9025a8c2665960b35aeb6de76da60884733d8"
DMABUF_UNMAP_PATH = "kernel-open/nvidia/nv-dmabuf.c"
DMABUF_UNMAP_PREIMAGE_SHA256 = "a2c81ed69a537cf7c508ecd4e567a2d3016c5a1ae3dc534ca3f5a492b0a523f4"
DMABUF_UNMAP_POSTIMAGE_SHA256 = "582cb50a00f8ad560a95db2e84356df8d0e56e0e560680f25859a4a1bea41909"
DMABUF_UNMAP_OVERLAY_PATHS = {DMABUF_UNMAP_PATH}
MMAP_READONLY_PATCH = ROOT / "patches/r595.99.02/0018-open-mmap-readonly-before-pte-install.patch"
MMAP_READONLY_PATCH_SHA256 = "fe4879b3d6ea319e3c417dba7aa483034cfaac919dcf856ba54878c552be795d"
MMAP_READONLY_PATH = "kernel-open/nvidia/nv-mmap.c"
MMAP_READONLY_PREIMAGE_SHA256 = "6d83c986765d48d3c2df679a5e62c419c4df213967b1804d96ab25ed67a4e65a"
MMAP_READONLY_POSTIMAGE_SHA256 = "4f77149d44565df8e6306bb05482a112ebb3e563e1653a8d8b80851ca4665c97"
MMAP_READONLY_OVERLAY_PATHS = {MMAP_READONLY_PATH}
VM_RSS_COUNTER_PATCH = ROOT / "patches/r595.99.02/0019-open-vm-null-percpu-rss-counter-guard.patch"
VM_RSS_COUNTER_PATCH_SHA256 = "ef0c2e6f8465b5b954b9b3bdcf932ed9bd3f59338225b3d6b57dcc8d50afb5b8"
VM_RSS_COUNTER_PATH = "kernel-open/nvidia/nv-vm.c"
VM_RSS_COUNTER_PREIMAGE_SHA256 = "7f9a78fa179a238fdabde00534d8c0bcde0fa22110e73fe05ddec3338f99edb0"
VM_RSS_COUNTER_POSTIMAGE_SHA256 = "454690fbe0c64fd3c115ce1a7b939ac870d9d5adac760a7d6d7b99d4c736b550"
VM_RSS_COUNTER_OVERLAY_PATHS = {VM_RSS_COUNTER_PATH}
EXPECTED_PROVIDER_SYMVERS_SEMANTIC_SHA256 = "285db44e3d654091312049a2bb94d3b312ed806ec0169ec830a7362d6c56a549"
SOFTDEP_VALUE = "pre: ecdh_generic ecdsa_generic"
REFERENCE_MODULE = ROOT / "build/experiments/r595-open-softdep-linux68-gcc13-v2/hybrid580_open.ko"
REFERENCE_MODULE_SHA256 = "c2cf6650b9aac369b4467d4fa5b3f5f0a194c869c9142a9c7b37e0ee4f2f45e1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_file(path: Path, expected: str, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    actual = sha256(path)
    if actual != expected:
        raise ValueError(f"{label} hash mismatch: got {actual}, expected {expected}")
    return actual


def _run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
         timeout: int = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                              check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"could not run {argv[0]}: {error}") from None


def apply_pfn_guard_overlay(source: Path) -> dict[str, Any]:
    """Apply the pinned R595.112 page-backed-PFN safety guard with zero fuzz."""
    target = Path(source) / "kernel-open/nvidia/os-mlock.c"
    _verified_file(PFN_PATCH, PFN_PATCH_SHA256, "R595 PFN guard patch")
    _verified_file(target, PFN_PREIMAGE_SHA256, "R595 PFN guard preimage")
    argv = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(PFN_PATCH)]
    dry = _run(argv + ["--dry-run"], cwd=Path(source))
    if dry.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", dry.stdout + dry.stderr):
        raise ValueError("R595 PFN guard patch dry-run was not exact")
    applied = _run(argv, cwd=Path(source))
    if applied.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", applied.stdout + applied.stderr):
        raise ValueError("R595 PFN guard patch application was not exact")
    postimage = _verified_file(target, PFN_POSTIMAGE_SHA256, "R595 PFN guard postimage")
    return {
        "patch": str(PFN_PATCH), "patch_sha256": PFN_PATCH_SHA256,
        "preimage_sha256": PFN_PREIMAGE_SHA256, "postimage_sha256": postimage,
        "dry_run_exit_code": dry.returncode, "apply_exit_code": applied.returncode,
        "fuzz_used": False, "offset_used": False,
    }


def apply_large_page_table_overlay(source: Path) -> dict[str, Any]:
    """Backport the R595.112 page-table fix and required vmalloc wrapper ABI."""
    source = Path(source)
    files = (
        (LARGE_TABLE_HEADER_PATH, LARGE_TABLE_HEADER_PREIMAGE_SHA256,
         LARGE_TABLE_HEADER_POSTIMAGE_SHA256, "R595 nv_vmalloc wrapper preimage"),
        (LARGE_TABLE_OS_INTERFACE_PATH, LARGE_TABLE_OS_INTERFACE_PREIMAGE_SHA256,
         LARGE_TABLE_OS_INTERFACE_POSTIMAGE_SHA256, "R595 vmalloc callsite preimage"),
        (LARGE_TABLE_PATH, LARGE_TABLE_PREIMAGE_SHA256, LARGE_TABLE_POSTIMAGE_SHA256,
         "R595 replay nv.c before large page-table fix"),
    )
    _verified_file(LARGE_TABLE_PATCH, LARGE_TABLE_PATCH_SHA256,
                   "R595 large page-table patch")
    for relative, before, _, label in files:
        _verified_file(source / relative, before, label)
    argv = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(LARGE_TABLE_PATCH)]
    dry = _run(argv + ["--dry-run"], cwd=source)
    expected = re.compile(
        rf"Hunk #\d+ succeeded at \d+ \(offset {LARGE_TABLE_EXPECTED_OFFSET} lines?\)")
    dry_output = dry.stdout + dry.stderr
    patched_paths = [LARGE_TABLE_HEADER_PATH, LARGE_TABLE_OS_INTERFACE_PATH, LARGE_TABLE_PATH]
    checked_paths = re.findall(r"(?m)^checking file (.+)$", dry_output)
    if dry.returncode or re.search(r"\bfuzz\b", dry_output, re.I) or \
            len(expected.findall(dry_output)) != 2 or \
            len(re.findall(r"Hunk #\d+ succeeded", dry_output)) != 2 or \
            checked_paths != patched_paths:
        raise ValueError("large page-table overlay did not match its exact replay context")
    applied = _run(argv, cwd=source)
    applied_output = applied.stdout + applied.stderr
    if applied.returncode or re.search(r"\bfuzz\b", applied_output, re.I) or \
            len(expected.findall(applied_output)) != 2 or \
            len(re.findall(r"Hunk #\d+ succeeded", applied_output)) != 2 or \
            re.findall(r"(?m)^patching file (.+)$", applied_output) != patched_paths:
        raise ValueError("large page-table patch application differed from dry-run")
    postimages = {}
    for relative, _, after, label in files:
        postimages[relative] = _verified_file(
            source / relative, after, label.replace("preimage", "postimage"))
    return {
        "patch": str(LARGE_TABLE_PATCH),
        "patch_sha256": LARGE_TABLE_PATCH_SHA256,
        "preimage_sha256": {relative: before for relative, before, _, _ in files},
        "postimage_sha256": postimages,
        "expected_replay_line_offset": LARGE_TABLE_EXPECTED_OFFSET,
        "dry_run_exit_code": dry.returncode,
        "apply_exit_code": applied.returncode,
        "fuzz_used": False,
        "offset_used": True,
        "offset_lines": LARGE_TABLE_EXPECTED_OFFSET,
        "patched_paths": patched_paths,
    }


def apply_page_pool_prototypes_overlay(source: Path) -> dict[str, Any]:
    """Give R595 page-pool helpers explicit internal/shared prototypes."""
    source = Path(source)
    _verified_file(PAGE_POOL_PROTOTYPES_PATCH, PAGE_POOL_PROTOTYPES_PATCH_SHA256,
                   "R595 page-pool prototype patch")
    for relative, (before, _) in PAGE_POOL_PROTOTYPES_FILES.items():
        _verified_file(source / relative, before,
                       "R595 page-pool prototype preimage " + relative)
    argv = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(PAGE_POOL_PROTOTYPES_PATCH)]
    dry = _run(argv + ["--dry-run"], cwd=source)
    dry_output = dry.stdout + dry.stderr
    expected_paths = list(PAGE_POOL_PROTOTYPES_FILES)
    checked_paths = re.findall(r"(?m)^checking file (.+)$", dry_output)
    if dry.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", dry_output) or \
            checked_paths != expected_paths:
        raise ValueError("page-pool prototype overlay did not match its exact replay context")
    applied = _run(argv, cwd=source)
    applied_output = applied.stdout + applied.stderr
    patched_paths = re.findall(r"(?m)^patching file (.+)$", applied_output)
    if applied.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", applied_output) or \
            patched_paths != expected_paths:
        raise ValueError("page-pool prototype patch application differed from dry-run")
    postimages = {}
    for relative, (_, after) in PAGE_POOL_PROTOTYPES_FILES.items():
        postimages[relative] = _verified_file(
            source / relative, after, "R595 page-pool prototype postimage " + relative)
    return {
        "patch": str(PAGE_POOL_PROTOTYPES_PATCH),
        "patch_sha256": PAGE_POOL_PROTOTYPES_PATCH_SHA256,
        "preimage_sha256": {relative: before for relative, (before, _) in PAGE_POOL_PROTOTYPES_FILES.items()},
        "postimage_sha256": postimages,
        "dry_run_exit_code": dry.returncode,
        "apply_exit_code": applied.returncode,
        "fuzz_used": False,
        "offset_used": False,
        "patched_paths": patched_paths,
    }


def apply_dmabuf_unmap_overlay(source: Path) -> dict[str, Any]:
    """Pass the original scatterlist count when unmapping an sg_table."""
    source = Path(source)
    target = source / DMABUF_UNMAP_PATH
    _verified_file(DMABUF_UNMAP_PATCH, DMABUF_UNMAP_PATCH_SHA256,
                   "R595 dma-buf unmap patch")
    _verified_file(target, DMABUF_UNMAP_PREIMAGE_SHA256,
                   "R595 dma-buf unmap preimage")
    argv = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(DMABUF_UNMAP_PATCH)]
    dry = _run(argv + ["--dry-run"], cwd=source)
    dry_output = dry.stdout + dry.stderr
    expected_paths = [DMABUF_UNMAP_PATH]
    if dry.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", dry_output) or \
            re.findall(r"(?m)^checking file (.+)$", dry_output) != expected_paths:
        raise ValueError("dma-buf unmap overlay did not match its exact replay context")
    applied = _run(argv, cwd=source)
    applied_output = applied.stdout + applied.stderr
    patched_paths = re.findall(r"(?m)^patching file (.+)$", applied_output)
    if applied.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", applied_output) or \
            patched_paths != expected_paths:
        raise ValueError("dma-buf unmap patch application differed from dry-run")
    postimage = _verified_file(target, DMABUF_UNMAP_POSTIMAGE_SHA256,
                               "R595 dma-buf unmap postimage")
    return {
        "patch": str(DMABUF_UNMAP_PATCH),
        "patch_sha256": DMABUF_UNMAP_PATCH_SHA256,
        "preimage_sha256": DMABUF_UNMAP_PREIMAGE_SHA256,
        "postimage_sha256": postimage,
        "dry_run_exit_code": dry.returncode,
        "apply_exit_code": applied.returncode,
        "fuzz_used": False,
        "offset_used": False,
        "patched_paths": patched_paths,
    }


def apply_mmap_readonly_overlay(source: Path) -> dict[str, Any]:
    """Set VMA read-only PTE protections before the mapping path installs pages."""
    source = Path(source)
    target = source / MMAP_READONLY_PATH
    _verified_file(MMAP_READONLY_PATCH, MMAP_READONLY_PATCH_SHA256,
                   "R595 mmap read-only patch")
    _verified_file(target, MMAP_READONLY_PREIMAGE_SHA256,
                   "R595 mmap read-only preimage")
    argv = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(MMAP_READONLY_PATCH)]
    dry = _run(argv + ["--dry-run"], cwd=source)
    dry_output = dry.stdout + dry.stderr
    expected_paths = [MMAP_READONLY_PATH]
    if dry.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", dry_output) or \
            re.findall(r"(?m)^checking file (.+)$", dry_output) != expected_paths:
        raise ValueError("mmap read-only overlay did not match its exact replay context")
    applied = _run(argv, cwd=source)
    applied_output = applied.stdout + applied.stderr
    patched_paths = re.findall(r"(?m)^patching file (.+)$", applied_output)
    if applied.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", applied_output) or \
            patched_paths != expected_paths:
        raise ValueError("mmap read-only patch application differed from dry-run")
    postimage = _verified_file(target, MMAP_READONLY_POSTIMAGE_SHA256,
                               "R595 mmap read-only postimage")
    return {
        "patch": str(MMAP_READONLY_PATCH),
        "patch_sha256": MMAP_READONLY_PATCH_SHA256,
        "preimage_sha256": MMAP_READONLY_PREIMAGE_SHA256,
        "postimage_sha256": postimage,
        "dry_run_exit_code": dry.returncode,
        "apply_exit_code": applied.returncode,
        "fuzz_used": False,
        "offset_used": False,
        "patched_paths": patched_paths,
    }


def apply_vm_rss_counter_overlay(source: Path) -> dict[str, Any]:
    """Fail safely if the mm per-CPU RSS counter backing is unexpectedly absent."""
    source = Path(source)
    target = source / VM_RSS_COUNTER_PATH
    _verified_file(VM_RSS_COUNTER_PATCH, VM_RSS_COUNTER_PATCH_SHA256,
                   "R595 mm RSS-counter patch")
    _verified_file(target, VM_RSS_COUNTER_PREIMAGE_SHA256,
                   "R595 mm RSS-counter preimage")
    argv = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(VM_RSS_COUNTER_PATCH)]
    dry = _run(argv + ["--dry-run"], cwd=source)
    dry_output = dry.stdout + dry.stderr
    expected_paths = [VM_RSS_COUNTER_PATH]
    if dry.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", dry_output) or \
            re.findall(r"(?m)^checking file (.+)$", dry_output) != expected_paths:
        raise ValueError("mm RSS-counter overlay did not match its exact replay context")
    applied = _run(argv, cwd=source)
    applied_output = applied.stdout + applied.stderr
    patched_paths = re.findall(r"(?m)^patching file (.+)$", applied_output)
    if applied.returncode or re.search(r"(?im)\b(?:fuzz|offset)\b", applied_output) or \
            patched_paths != expected_paths:
        raise ValueError("mm RSS-counter patch application differed from dry-run")
    postimage = _verified_file(target, VM_RSS_COUNTER_POSTIMAGE_SHA256,
                               "R595 mm RSS-counter postimage")
    return {
        "patch": str(VM_RSS_COUNTER_PATCH),
        "patch_sha256": VM_RSS_COUNTER_PATCH_SHA256,
        "preimage_sha256": VM_RSS_COUNTER_PREIMAGE_SHA256,
        "postimage_sha256": postimage,
        "dry_run_exit_code": dry.returncode,
        "apply_exit_code": applied.returncode,
        "fuzz_used": False,
        "offset_used": False,
        "patched_paths": patched_paths,
    }


def build_command(source: Path, headers: Path, frontend_symvers: Path,
                  compiler: Path, jobs: int) -> list[str]:
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    return [
        "make", "-C", str(Path(source) / "kernel-open"),
        "KERNEL_UNAME=" + KERNEL_RELEASE,
        "SYSSRC=" + str(headers),
        "NV_KERNEL_MODULES=nvidia nvidia-uvm",
        "KBUILD_EXTRA_SYMBOLS=" + str(frontend_symvers),
        "CC=" + str(compiler),
        "-j" + str(jobs), "modules",
    ]


def validate_module_metadata(metadata: dict[str, str]) -> None:
    expected = {
        "name": "hybrid580_open", "version": REPLAYED_SOURCE_VERSION,
        "license": "Dual MIT/GPL", "softdep": SOFTDEP_VALUE,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            label = "soft dependency metadata" if key == "softdep" else f"module {key}"
            raise ValueError(f"{label} differs: got {metadata.get(key)!r}, expected {value!r}")
    if metadata.get("vermagic", "").split(maxsplit=1)[:1] != [KERNEL_RELEASE]:
        raise ValueError("module vermagic differs from the exact Linux 6.8 target")
    depends = sorted(item for item in metadata.get("depends", "").split(",") if item)
    if depends != ["ecc"]:
        raise ValueError("module hard dependency metadata differs from the exact target")


def provider_symvers_semantic_digest(path: Path) -> str:
    """Hash exported ABI rows without the build-root path embedded by Kbuild."""
    if Path(path).is_symlink() or not Path(path).is_file():
        raise ValueError(f"provider Module.symvers must be a regular non-symlink file: {path}")
    canonical_rows = []
    seen_symbols: set[str] = set()
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split()
        if len(fields) < 4:
            raise ValueError(f"malformed provider Module.symvers row {line_number}")
        crc, symbol, module_path, *export_metadata = fields
        if symbol in seen_symbols:
            raise ValueError(f"duplicate provider symbol in Module.symvers: {symbol}")
        seen_symbols.add(symbol)
        if Path(module_path).name != "hybrid580_open":
            raise ValueError(f"unexpected provider module in Module.symvers row {line_number}")
        canonical_rows.append(" ".join([crc, symbol, "hybrid580_open", *export_metadata]))
    if not canonical_rows:
        raise ValueError("provider Module.symvers is empty")
    canonical_rows.sort(key=lambda row: row.split()[1])
    return hashlib.sha256(("\n".join(canonical_rows) + "\n").encode()).hexdigest()


def validate_provider_symvers(path: Path) -> str:
    actual = provider_symvers_semantic_digest(path)
    if actual != EXPECTED_PROVIDER_SYMVERS_SEMANTIC_SHA256:
        raise ValueError(
            "exact-target R595 provider Module.symvers ABI mismatch: "
            f"got {actual}, expected {EXPECTED_PROVIDER_SYMVERS_SEMANTIC_SHA256}")
    return actual


def _safe_output(path: Path, allowed: Path, label: str) -> Path:
    root = allowed.resolve(strict=True)
    raw = path if path.is_absolute() else ROOT / path
    absolute = Path(os.path.abspath(raw))
    try:
        relative = absolute.relative_to(root)
    except ValueError:
        raise ValueError(f"{label} must stay below {root}") from None
    current = root
    if current.is_symlink():
        raise ValueError(f"{label} parent must not be a symlink")
    for component in relative.parts:
        current = current / component
        if current.exists() and current.is_symlink():
            raise ValueError(f"{label} path contains a symlink")
    if absolute.exists():
        raise ValueError(f"refusing to overwrite {label}: {absolute}")
    return absolute


def validate_output_paths(work_dir: Path, report_path: Path, log_path: Path) -> tuple[Path, Path, Path]:
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
    work = Path(os.path.abspath(work_dir))
    try:
        work.relative_to(temp_root)
    except ValueError:
        raise ValueError("full build work directory must stay under the temporary filesystem") from None
    if any(item.is_symlink() for item in (work, *work.parents) if item == temp_root or item.is_relative_to(temp_root)):
        raise ValueError("temporary build path contains a symlink")
    if work.exists():
        raise ValueError(f"refusing to overwrite full build work directory: {work}")
    report = _safe_output(Path(report_path), ROOT / "evidence", "build report")
    log = _safe_output(Path(log_path), ROOT / "evidence/logs", "build log")
    return work, report, log


def _modinfo(module: Path) -> dict[str, str]:
    result = {}
    for field in ("name", "version", "license", "vermagic", "depends", "softdep"):
        command = _run(["modinfo", "-F", field, str(module)])
        if command.returncode or command.stderr.strip():
            raise ValueError(f"modinfo could not read {field}: {command.stderr.strip()}")
        result[field] = command.stdout.strip()
    return result


def _report_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def run_full_build(*, work_dir: Path, report_path: Path, log_path: Path,
                   jobs: int = 2) -> dict[str, Any]:
    work, report_file, log_file = validate_output_paths(work_dir, report_path, log_path)
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    if hashlib.sha256(REPLAY_REPORT.read_bytes()).hexdigest() != REPLAY_REPORT_SHA256:
        raise ValueError("pinned R595 44-patch replay report hash mismatch")
    replay = json.loads(REPLAY_REPORT.read_text(encoding="utf-8"))
    validate_replay_report(replay)
    replay_source = source_from_replay_report(replay)
    source_artifacts = validate_replayed_source(replay_source, replay)

    header_symvers = KERNEL_HEADERS / "Module.symvers"
    input_hashes = {
        "replay_report": REPLAY_REPORT_SHA256,
        "kernel_headers_module_symvers": _verified_file(
            header_symvers, KERNEL_SYMVERS_SHA256, "Linux 6.8 headers Module.symvers"),
        "frontend_module_symvers": _verified_file(
            FRONTEND_SYMVERS, FRONTEND_SYMVERS_SHA256, "Linux 6.8 frontend Module.symvers"),
        "gcc13": _verified_file(GCC13, GCC13_SHA256, "GCC 13 compiler"),
        "r595_rm_core": _verified_file(R595_CORE, R595_CORE_SHA256, "R595 RM core"),
        "reference_open_module": _verified_file(
            REFERENCE_MODULE, REFERENCE_MODULE_SHA256, "incremental R595 Open reference module"),
        "r595_large_page_table_patch": _verified_file(
            LARGE_TABLE_PATCH, LARGE_TABLE_PATCH_SHA256, "R595 large page-table patch"),
        "r595_page_pool_prototypes_patch": _verified_file(
            PAGE_POOL_PROTOTYPES_PATCH, PAGE_POOL_PROTOTYPES_PATCH_SHA256,
            "R595 page-pool prototype patch"),
        "r595_dmabuf_unmap_patch": _verified_file(
            DMABUF_UNMAP_PATCH, DMABUF_UNMAP_PATCH_SHA256,
            "R595 dma-buf unmap patch"),
        "r595_mmap_readonly_patch": _verified_file(
            MMAP_READONLY_PATCH, MMAP_READONLY_PATCH_SHA256,
            "R595 mmap read-only patch"),
        "r595_vm_rss_counter_patch": _verified_file(
            VM_RSS_COUNTER_PATCH, VM_RSS_COUNTER_PATCH_SHA256,
            "R595 mm RSS-counter patch"),
    }
    input_paths = {
        "replay_report": REPLAY_REPORT,
        "kernel_headers_module_symvers": header_symvers,
        "frontend_module_symvers": FRONTEND_SYMVERS,
        "gcc13": GCC13,
        "r595_rm_core": R595_CORE,
        "reference_open_module": REFERENCE_MODULE,
        "r595_large_page_table_patch": LARGE_TABLE_PATCH,
        "r595_page_pool_prototypes_patch": PAGE_POOL_PROTOTYPES_PATCH,
        "r595_dmabuf_unmap_patch": DMABUF_UNMAP_PATCH,
        "r595_mmap_readonly_patch": MMAP_READONLY_PATCH,
        "r595_vm_rss_counter_patch": VM_RSS_COUNTER_PATCH,
    }
    implementation_hash = sha256(Path(__file__).resolve())
    if not (KERNEL_HEADERS / "Makefile").is_file() or not (KERNEL_HEADERS / "include/generated/autoconf.h").is_file():
        raise ValueError("exact-target Linux 6.8 kernel build tree is incomplete")

    work.mkdir(mode=0o700, parents=False)
    os.chmod(work, 0o700)
    candidate_source = work / "source"
    shutil.copytree(replay_source, candidate_source, symlinks=True)
    for current, dirs, files in os.walk(candidate_source, followlinks=False):
        for name in dirs + files:
            if (Path(current) / name).is_symlink():
                raise ValueError("replayed source copy unexpectedly contains symlinks")
    copied_artifacts = validate_replayed_source(candidate_source, replay)
    if copied_artifacts != source_artifacts:
        raise ValueError("private copy differs from the validated R595 replay tree")

    pfn_overlay = apply_pfn_guard_overlay(candidate_source)
    large_table_overlay = apply_large_page_table_overlay(candidate_source)
    page_pool_prototypes_overlay = apply_page_pool_prototypes_overlay(candidate_source)
    dmabuf_unmap_overlay = apply_dmabuf_unmap_overlay(candidate_source)
    mmap_readonly_overlay = apply_mmap_readonly_overlay(candidate_source)
    vm_rss_counter_overlay = apply_vm_rss_counter_overlay(candidate_source)
    softdep_overlay = apply_kmod_softdep_overlay(candidate_source)
    core_target = candidate_source / "kernel-open/nvidia/nv-kernel.o_binary"
    if core_target.exists() or core_target.is_symlink():
        raise ValueError("replayed source unexpectedly contains an RM core")
    shutil.copy2(R595_CORE, core_target)
    if sha256(core_target) != R595_CORE_SHA256:
        raise ValueError("private R595 RM core copy failed hash verification")

    argv = build_command(candidate_source, KERNEL_HEADERS, FRONTEND_SYMVERS, GCC13, jobs)
    env = os.environ.copy()
    cleared = []
    for name in (
        "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "EXTRA_CFLAGS", "MAKEFLAGS",
        "MFLAGS", "MAKEOVERRIDES", "CC", "CXX", "LD", "OBJCOPY", "TARGET_ARCH",
        "NV_VERBOSE", "NV_SPECTRE_V2",
    ):
        if name in env:
            cleared.append(name)
            env.pop(name)
    env["LC_ALL"] = "C"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log_file.open("x", encoding="utf-8") as stream:
        os.chmod(log_file, 0o600)
        stream.write("$ " + shlex.join(argv) + "\ncwd: " + str(ROOT) + "\n")
        stream.write("SYSSRC: " + str(KERNEL_HEADERS) + "\n")
        stream.flush()
        try:
            built = subprocess.run(argv, cwd=ROOT, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, timeout=3600, check=False)
            exit_code = built.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
            stream.write("\nTIMEOUT after 3600 seconds\n")
    log_hash = sha256(log_file)
    log_text = log_file.read_text(encoding="utf-8", errors="replace")
    warnings = [line for line in log_text.splitlines() if re.search(r"\bwarning:", line, re.I)]

    result: dict[str, Any] = {
        "schema": "nvidia-r595-linux68-full-replayed-open-build-v3",
        "status": "failed",
        "qualification": "failed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_version": REPLAYED_SOURCE_VERSION,
        "kernel_release": KERNEL_RELEASE,
        "target": "pc3@pc3",
        "guest_hostname": "pc3-v100",
        "inputs_sha256": input_hashes,
        "source_replay": {"path": str(REPLAY_REPORT), "sha256": REPLAY_REPORT_SHA256,
                          "patch_count": 44, "source_artifacts_verified": len(source_artifacts)},
        "source_overlays": {"pfn_backing_guard": pfn_overlay,
                            "large_page_table_vmalloc": large_table_overlay,
                            "page_pool_prototypes": page_pool_prototypes_overlay,
                            "dmabuf_original_nents_unmap": dmabuf_unmap_overlay,
                            "mmap_readonly_before_pte_install": mmap_readonly_overlay,
                            "vm_null_percpu_rss_counter_guard": vm_rss_counter_overlay,
                            "kmod_softdep": softdep_overlay},
        "build": {"argv": argv, "exit_code": exit_code,
                  "duration_seconds": round(time.monotonic() - started, 3),
                  "environment_names_cleared": cleared,
                  "log": {"path": str(log_file), "sha256": log_hash, "mode": "0600"},
                  "warning_count": len(warnings), "warning_samples": warnings[:20]},
        "work_dir": str(work),
        "module_loaded": False,
        "module_installed": False,
        "gpu_accessed": False,
        "runtime_or_hardware_validated": False,
    }
    try:
        if exit_code != 0:
            raise RuntimeError("exact-target full source Kbuild failed")
        module = candidate_source / "kernel-open/hybrid580_open.ko"
        symvers = candidate_source / "kernel-open/Module.symvers"
        types_header = candidate_source / "kernel-open/conftest/types.h"
        uvm_sidecar = candidate_source / "kernel-open/nvidia-uvm.ko"
        for path, label in ((module, "Open module"), (symvers, "provider Module.symvers"),
                            (types_header, "shared conftest header"), (uvm_sidecar, "UVM conftest sidecar")):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Kbuild did not produce {label}")
        if "#define NV_MEMORY_DEVICE_COHERENT_PRESENT" not in types_header.read_text():
            raise ValueError("shared Open/UVM conftest did not enable coherent device pages")
        provider_symvers_hash = validate_provider_symvers(symvers)
        metadata = _modinfo(module)
        validate_module_metadata(metadata)
        module_hash = sha256(module)
        ref_hash = sha256(REFERENCE_MODULE)
        for name, path in input_paths.items():
            if sha256(path) != input_hashes[name]:
                raise ValueError(f"pinned build input changed during Kbuild: {name}")
        if sha256(Path(__file__).resolve()) != implementation_hash:
            raise ValueError("build implementation changed during Kbuild")
        for relative, expected in source_artifacts.items():
            if relative in LARGE_TABLE_OVERLAY_PATHS or \
                    relative in PAGE_POOL_PROTOTYPES_OVERLAY_PATHS or \
                    relative in DMABUF_UNMAP_OVERLAY_PATHS or \
                    relative in MMAP_READONLY_OVERLAY_PATHS or \
                    relative in VM_RSS_COUNTER_OVERLAY_PATHS:
                continue
            _verified_file(candidate_source / relative, expected,
                           "pinned R595 replay artifact " + relative)
        for relative, expected in large_table_overlay["postimage_sha256"].items():
            if relative not in PAGE_POOL_PROTOTYPES_OVERLAY_PATHS:
                _verified_file(candidate_source / relative, expected,
                               "R595 overlay postimage " + relative)
        for relative, expected in page_pool_prototypes_overlay["postimage_sha256"].items():
            if relative not in VM_RSS_COUNTER_OVERLAY_PATHS:
                _verified_file(candidate_source / relative, expected,
                               "R595 page-pool prototype postimage " + relative)
        _verified_file(candidate_source / DMABUF_UNMAP_PATH,
                       dmabuf_unmap_overlay["postimage_sha256"],
                       "R595 dma-buf unmap overlay postimage " + DMABUF_UNMAP_PATH)
        _verified_file(candidate_source / MMAP_READONLY_PATH,
                       mmap_readonly_overlay["postimage_sha256"],
                       "R595 mmap read-only overlay postimage " + MMAP_READONLY_PATH)
        _verified_file(candidate_source / VM_RSS_COUNTER_PATH,
                       vm_rss_counter_overlay["postimage_sha256"],
                       "R595 mm RSS-counter overlay postimage " + VM_RSS_COUNTER_PATH)
        original_after = validate_replayed_source(replay_source, replay)
        if original_after != source_artifacts:
            raise ValueError("original shared replay source changed during isolated build")
        result.update({
            "status": "passed",
            "qualification": "compiled-full-source-replayed-exact-linux68",
            "module": {"path": str(module), "sha256": module_hash, "bytes": module.stat().st_size,
                       "identity": metadata},
            "symvers_sha256": sha256(symvers),
            "inputs_unchanged": True,
            "implementation_sha256": {
                "tools/build_r595_open_linux68_full.py": implementation_hash,
            },
            "provider_module_symvers": {
                "path": str(symvers), "raw_sha256": sha256(symvers),
                "semantic_abi_sha256": provider_symvers_hash,
                "normalization": "sort rows by symbol and replace the Kbuild module path with hybrid580_open",
            },
            "reference_incremental_module": {"path": str(REFERENCE_MODULE), "sha256": ref_hash,
                                             "identical_binary": module_hash == ref_hash},
            "shared_conftest": {"types_header_sha256": sha256(types_header),
                                "uvm_sidecar_sha256": sha256(uvm_sidecar),
                                "uvm_sidecar_in_hybrid_bundle": False},
            "source_unchanged": True,
        })
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"

    _report_write(report_file, result)
    result["report_path"] = str(report_file.resolve(strict=True))
    result["report_sha256"] = sha256(report_file)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args(argv)
    try:
        result = run_full_build(work_dir=args.work_dir, report_path=args.report,
                                log_path=args.log, jobs=args.jobs)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"build_r595_open_linux68_full: error: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": result["status"], "qualification": result["qualification"],
        "report": result["report_path"], "report_sha256": result["report_sha256"],
        "module": result.get("module"), "error": result.get("error"),
        "module_loaded": False, "module_installed": False,
        "runtime_or_hardware_validated": False,
    }, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
