#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trace R595 open RM's directional P2P-capability producer from pinned source.

This is a static source audit. It does not assert that PCIe atomics or P2P work
on a particular topology or GPU pair.
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
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_uvm_capability_map import (  # noqa: E402
    _mask_c_comments_and_literals,
    _splice_c_lines,
)

R595_99_ROOT = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02"
R595_99_ARCHIVE = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source.tar.gz"
R595_112_REPO = ROOT / "build/research/ogkm-595.112.07"
R595_SOURCE_RELATIVE = "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c"
R595_VERSION_RELATIVE = "version.mk"
R595_COPYING_RELATIVE = "COPYING"
R595_99_ARCHIVE_SHA256 = "b8891cb617683e28ef1e4c3add8dbc30e648b8cd6429a3d521f20dde44633262"
R595_99_SOURCE_SHA256 = "2f20858c33c165820f4bddd72174b4a7a57248a259b413db588f9f8927384512"
R595_99_VERSION_SHA256 = "f4e13a41ce676591b322c47d821ecf9d9b3f70171a0e221286162c5fada17234"
R595_99_TAG_OBJECT = "19f3b344ccbae68f19bdd1d628f54a08eaf5a712"
R595_99_COMMIT = "e394a404108a9ce5bba988c1dddf694dabbd4a43"
R595_112_TAG_OBJECT = "2e8dd6c0bbd2e08194b96abeb5c319717cd13682"
R595_112_COMMIT = "d8257d95ae5fed364163e4df51db66df8b1ee0d2"
R595_112_SOURCE_SHA256 = "e3cd52c0eb84554ad92e8ab6436e949492f45591307ff0b149a239367a837c8f"
DEFAULT_REPORT = ROOT / "evidence/r595-p2p-producer-v2-20261102.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}")
    return result.stdout.strip()


def _git_show(repo: Path, revision_path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", revision_path],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git show {revision_path} failed in {repo}: {detail}")
    return result.stdout


def _extract_function(source: str, name: str) -> dict:
    """Extract a unique RM function without counting braces in comments/literals."""
    logical, physical_lines = _splice_c_lines(source)
    masked = _mask_c_comments_and_literals(logical)
    declaration = re.compile(
        rf"(?m)^\s*(?:static\s+)?(?:NV_STATUS|NvBool)\s+{re.escape(name)}\s*\("
    )
    definitions = []
    for match in declaration.finditer(masked):
        opening = masked.find("{", match.end())
        semicolon = masked.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        depth = 0
        closing = None
        for index in range(opening, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None:
            raise ValueError(f"unbalanced function body: {name}")
        raw = logical[match.start():closing + 1]
        code = masked[match.start():closing + 1]
        definitions.append({
            "start_line": physical_lines[match.start()],
            "end_line": physical_lines[closing],
            "sha256": _sha256(raw.encode("utf-8")),
            "normalized_sha256": _sha256("".join(code.split()).encode("utf-8")),
            "_compact": "".join(code.split()),
        })
    if len(definitions) != 1:
        raise ValueError(f"expected one definition for {name}, found {len(definitions)}")
    return definitions[0]


def audit_p2p_source_text(source: str) -> dict:
    """Validate direction, owner, and access-gating relationships in RM source."""
    system = _extract_function(source, "getSystemP2PCaps")
    atomic = _extract_function(source, "_nvGpuOpsIsBar1P2pAtomicEnabled")
    producer = _extract_function(source, "nvGpuOpsGetP2PCaps")
    system_code = system["_compact"]
    atomic_code = atomic["_compact"]
    producer_code = producer["_compact"]

    checks = {
        "rm_access_requires_both_reads_and_writes": (
            "if(REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_READS_SUPPORTED,p2pCapsParams->p2pCaps)&&"
            "REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_WRITES_SUPPORTED,p2pCapsParams->p2pCaps))"
            in system_code
            and "p2pCaps->accessSupported=NV_TRUE;" in system_code
        ),
        "bar1_support_is_a_separate_rm_capability": (
            "p2pCaps->bar1Supported=!!REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PCI_BAR1_SUPPORTED,"
            "p2pCapsParams->p2pCaps);" in system_code
        ),
        "atomic_architecture_query_uses_owning_gpu": (
            "_nvGpuOpsGetDeviceArchByGpuId(session,pOwningGpu->gpuId,&arch)" in atomic_code
        ),
        "atomic_architecture_floor_is_blackwell_gb1xx": (
            "returnarch>=GPU_ARCHITECTURE_BLACKWELL_GB1XX;" in atomic_code
        ),
        "mapping_gpu_parameter_is_not_used_by_atomic_helper": atomic_code.count("pMappingGpu") == 1,
        "index_zero_maps_device1_to_device2_bar1": (
            "kbusGetBar1P2PDmaInfo_HAL(pLocalGpu,pRemoteGpu,GPU_GET_KERNEL_BUS(pRemoteGpu),"
            "&p2pCapsParams->bar1DmaAddress[0],&p2pCapsParams->bar1DmaSize[0])" in producer_code
            and "p2pCapsParams->bar1PcieAtomics[0]=_nvGpuOpsIsBar1P2pAtomicEnabled("
            "device1->session,pLocalGpu,pRemoteGpu);" in producer_code
        ),
        "index_one_maps_device2_to_device1_bar1": (
            "kbusGetBar1P2PDmaInfo_HAL(pRemoteGpu,pLocalGpu,GPU_GET_KERNEL_BUS(pLocalGpu),"
            "&p2pCapsParams->bar1DmaAddress[1],&p2pCapsParams->bar1DmaSize[1])" in producer_code
            and "p2pCapsParams->bar1PcieAtomics[1]=_nvGpuOpsIsBar1P2pAtomicEnabled("
            "device2->session,pRemoteGpu,pLocalGpu);" in producer_code
        ),
        "atomic_flags_default_false": (
            "p2pCapsParams->bar1PcieAtomics[0]=NV_FALSE;" in producer_code
            and "p2pCapsParams->bar1PcieAtomics[1]=NV_FALSE;" in producer_code
        ),
        "access_and_bar1_gates_precede_directional_queries": bool(re.search(
            r"if\(p2pCaps\.accessSupported\)\{.*?if\(p2pCaps\.bar1Supported\)\{",
            producer_code,
        )),
    }
    lines = source.splitlines()
    todo_lines = [
        index for index, line in enumerate(lines, 1)
        if "TODO: Bug 3264814" in line
    ]
    topology_comment_present = bool(todo_lines) and any(
        "bus topology and routing" in line for line in lines[max(0, todo_lines[0] - 1):todo_lines[0] + 3]
    )
    checks["source_retains_topology_and_routing_todo"] = topology_comment_present
    if not all(checks.values()):
        failed = ", ".join(key for key, value in checks.items() if not value)
        raise ValueError(f"R595 P2P producer contract changed or is incomplete: {failed}")

    return {
        "checks": checks,
        "functions": {
            "getSystemP2PCaps": {k: v for k, v in system.items() if not k.startswith("_")},
            "_nvGpuOpsIsBar1P2pAtomicEnabled": {k: v for k, v in atomic.items() if not k.startswith("_")},
            "nvGpuOpsGetP2PCaps": {k: v for k, v in producer.items() if not k.startswith("_")},
        },
        "direction_contract": {
            "bar1PcieAtomics_index_0": {
                "local_gpu": "device1 / pLocalGpu",
                "bar1_owner_gpu": "device2 / pRemoteGpu",
                "dma_bar_target": "device2 BAR1",
                "atomic_architecture_query": "device2 architecture",
            },
            "bar1PcieAtomics_index_1": {
                "local_gpu": "device2 / pRemoteGpu",
                "bar1_owner_gpu": "device1 / pLocalGpu",
                "dma_bar_target": "device1 BAR1",
                "atomic_architecture_query": "device1 architecture",
            },
            "atomic_helper": (
                "returns true when the BAR1 owning GPU architecture is at least Blackwell GB1xx; "
                "the mapping-GPU argument is not used in this helper"
            ),
            "eligibility_gates": (
                "RM first requires reads and writes in the P2P control response; BAR1 availability "
                "is separately gated before these two direction entries are populated"
            ),
            "topology_limit": (
                "the helper is architecture-based; nearby source retains a TODO to account for "
                "bus topology and routing. This is not proof that PCIe atomics work on a given path"
            ),
        },
        "topology_todo_lines": todo_lines,
        "runtime_or_hardware_validated": False,
    }


def _read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"source input must be a regular non-symlink file: {path}")
    return path.read_bytes()


def _archive_member(archive_path: Path, member_path: str) -> bytes:
    with tarfile.open(archive_path, "r:gz") as archive:
        matches = [member for member in archive.getmembers() if member.name == member_path]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError(f"expected one regular archive member: {member_path}")
        fileobj = archive.extractfile(matches[0])
        if fileobj is None:
            raise ValueError(f"archive member could not be read: {member_path}")
        return fileobj.read()


def _version_from_bytes(data: bytes, expected: str) -> str:
    text = data.decode("utf-8")
    match = re.search(r"(?m)^NVIDIA_VERSION\s*=\s*(\S+)\s*$", text)
    if not match or match.group(1) != expected:
        raise ValueError(f"source version.mk does not identify {expected}")
    return match.group(1)


def _license_from_bytes(data: bytes) -> str:
    header = data.decode("utf-8", errors="strict").splitlines()[:12]
    if not any("SPDX-License-Identifier: MIT" in line for line in header):
        raise ValueError("nv_gpu_ops.c does not carry the expected MIT SPDX header")
    return "MIT"


def _audit_59599(root: Path, archive_path: Path, upstream_repo: Path) -> dict:
    root = root.resolve(strict=True)
    archive_path = archive_path.resolve(strict=True)
    archive_bytes = _read_regular(archive_path)
    if _sha256(archive_bytes) != R595_99_ARCHIVE_SHA256:
        raise ValueError("R595.99.02 source archive SHA-256 differs from the pinned artifact")
    member_prefix = "open-gpu-kernel-modules-595.99.02/"
    members = {
        R595_SOURCE_RELATIVE: _archive_member(archive_path, member_prefix + R595_SOURCE_RELATIVE),
        R595_VERSION_RELATIVE: _archive_member(archive_path, member_prefix + R595_VERSION_RELATIVE),
        R595_COPYING_RELATIVE: _archive_member(archive_path, member_prefix + R595_COPYING_RELATIVE),
    }
    worktree = {key: _read_regular(root / key) for key in members}
    for key in members:
        if _sha256(worktree[key]) != _sha256(members[key]):
            raise ValueError(f"R595.99.02 extracted file differs from pinned source archive: {key}")
    upstream_repo = upstream_repo.resolve(strict=True)
    if _run_git(upstream_repo, "remote", "get-url", "origin") != \
            "https://github.com/NVIDIA/open-gpu-kernel-modules.git":
        raise ValueError("R595.99.02 tag object is not from NVIDIA's public repository")
    tag_object = _run_git(upstream_repo, "rev-parse", "refs/tags/595.99.02")
    tag_commit = _run_git(upstream_repo, "rev-parse", "595.99.02^{commit}")
    if tag_object != R595_99_TAG_OBJECT or tag_commit != R595_99_COMMIT or \
            "595.99.02" not in _run_git(upstream_repo, "tag", "--points-at", tag_commit).splitlines():
        raise ValueError("R595.99.02 public source tag differs from the pin")
    for key in members:
        upstream = _git_show(upstream_repo, f"{tag_commit}:{key}")
        if upstream != members[key]:
            raise ValueError(f"R595.99.02 archive member differs from the public tag: {key}")
    if _sha256(worktree[R595_SOURCE_RELATIVE]) != R595_99_SOURCE_SHA256:
        raise ValueError("R595.99.02 RM source SHA-256 differs from the pin")
    if _sha256(worktree[R595_VERSION_RELATIVE]) != R595_99_VERSION_SHA256:
        raise ValueError("R595.99.02 version.mk SHA-256 differs from the pin")
    source = worktree[R595_SOURCE_RELATIVE].decode("utf-8")
    result = audit_p2p_source_text(source)
    return {
        "version": _version_from_bytes(worktree[R595_VERSION_RELATIVE], "595.99.02"),
        "upstream_repository": "https://github.com/NVIDIA/open-gpu-kernel-modules.git",
        "upstream_tag": "595.99.02",
        "upstream_tag_object": tag_object,
        "upstream_commit": tag_commit,
        "source_archive": "build/research/open-gpu-kernel-modules-595.99.02/source.tar.gz",
        "source_archive_sha256": _sha256(archive_bytes),
        "source_file": R595_SOURCE_RELATIVE,
        "source_file_sha256": _sha256(worktree[R595_SOURCE_RELATIVE]),
        "version_file_sha256": _sha256(worktree[R595_VERSION_RELATIVE]),
        "file_license": _license_from_bytes(worktree[R595_SOURCE_RELATIVE]),
        **result,
    }


def _audit_595112(repo: Path) -> dict:
    repo = repo.resolve(strict=True)
    commit = _run_git(repo, "rev-parse", "HEAD")
    if commit != R595_112_COMMIT:
        raise ValueError(f"R595.112.07 source HEAD changed: {commit}")
    tag_object = _run_git(repo, "rev-parse", "refs/tags/595.112.07")
    if tag_object != R595_112_TAG_OBJECT:
        raise ValueError("R595.112.07 annotated tag object differs from the public pin")
    if "595.112.07" not in _run_git(repo, "tag", "--points-at", "HEAD").splitlines():
        raise ValueError("R595.112.07 source tag is not attached to the pinned commit")
    origin = _run_git(repo, "remote", "get-url", "origin")
    if origin != "https://github.com/NVIDIA/open-gpu-kernel-modules.git":
        raise ValueError("R595.112.07 source repository origin differs from NVIDIA's public repository")

    source_path = f"src/nvidia/src/kernel/rmapi/nv_gpu_ops.c"
    version_path = R595_VERSION_RELATIVE
    copying_path = R595_COPYING_RELATIVE
    committed = {
        source_path: subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{source_path}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout,
        version_path: subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{version_path}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout,
        copying_path: subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{copying_path}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout,
    }
    for relative, expected in committed.items():
        if _read_regular(repo / relative) != expected:
            raise ValueError(f"working source differs from pinned R595.112.07 commit: {relative}")
    if _sha256(committed[source_path]) != R595_112_SOURCE_SHA256:
        raise ValueError("R595.112.07 RM source SHA-256 differs from the pin")
    source = committed[source_path].decode("utf-8")
    result = audit_p2p_source_text(source)
    return {
        "version": _version_from_bytes(committed[version_path], "595.112.07"),
        "repository": "https://github.com/NVIDIA/open-gpu-kernel-modules.git",
        "tag": "595.112.07",
        "tag_object": tag_object,
        "commit": commit,
        "source_file": source_path,
        "source_file_sha256": _sha256(committed[source_path]),
        "version_file_sha256": _sha256(committed[version_path]),
        "file_license": _license_from_bytes(committed[source_path]),
        **result,
    }


def build_report(r59599_root: Path, r59599_archive: Path, r595112_repo: Path) -> dict:
    r595112_repo = r595112_repo.resolve(strict=True)
    r59599 = _audit_59599(r59599_root, r59599_archive, r595112_repo)
    r595112 = _audit_595112(r595112_repo)
    same_functions = all(
        r59599["functions"][name]["normalized_sha256"]
        == r595112["functions"][name]["normalized_sha256"]
        for name in r59599["functions"]
    )
    if not same_functions:
        raise ValueError("directional P2P producer functions differ between R595.99.02 and R595.112.07")
    return {
        "schema": "nvidia-open-rm-r595-p2p-producer-audit-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "pinned-open-source-static-audit",
        "license_review": "The analyzed RM source file identifies MIT; no NVIDIA proprietary binary or pseudocode is included.",
        "releases": {"595.99.02": r59599, "595.112.07": r595112},
        "cross_release_comparison": {
            "directional_producer_functions_identical_after_comment_literal_and_whitespace_masking": same_functions,
            "compared_functions": list(r59599["functions"]),
        },
        "scope_limits": [
            "Static source proves the reported code path and field direction only; it does not prove NVML/CUDA exposure or a working P2P mapping.",
            "The atomic flag is architecture-gated in the helper, while the source retains a TODO about PCIe topology and routing.",
            "No V100/RTX 5080 P2P capability response, PCIe atomic transaction, BAR1 mapping, transfer, or runtime test was observed in this audit.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r59599-root", type=Path, default=R595_99_ROOT)
    parser.add_argument("--r59599-archive", type=Path, default=R595_99_ARCHIVE)
    parser.add_argument("--r595112-repo", type=Path, default=R595_112_REPO)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    try:
        report = build_report(args.r59599_root, args.r59599_archive, args.r595112_repo)
    except (OSError, UnicodeError, tarfile.TarError, subprocess.CalledProcessError, ValueError) as error:
        parser.error(f"static P2P producer audit failed closed: {error}")

    output = args.report.resolve()
    if output.exists():
        parser.error(f"refusing to overwrite existing report: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "report": str(output),
        "report_sha256": _sha256(output.read_bytes()),
        "versions": [report["releases"][version]["version"] for version in report["releases"]],
        "producer_function_hashes_match": report["cross_release_comparison"]["directional_producer_functions_identical_after_comment_literal_and_whitespace_masking"],
        "runtime_or_hardware_validated": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
