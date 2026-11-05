#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare hash-pinned R595.99.02 and R595.112.07 open kernel sources."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
R595_99 = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
R595_99 /= "open-gpu-kernel-modules-595.99.02"
R595_112 = ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
R595_112 /= "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2"
ARCHIVES = {
    "595.99.02": (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source.tar.gz",
                  "b8891cb617683e28ef1e4c3add8dbc30e648b8cd6429a3d521f20dde44633262"),
    "595.112.07": (ROOT / ".cache/upstream/open-gpu-kernel-modules-595.112.07-d8257d95.tar.gz",
                   "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4"),
}
EXPECTED_C_H_FILES = 2172
EXPECTED_CHANGED = 93
EXPECTED_UVM_FILES = 213


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink input: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest(root: Path) -> tuple[dict[str, str], str]:
    files: dict[str, str] = {}
    for subtree in ("kernel-open", "src/nvidia"):
        directory = root / subtree
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"source subtree is missing or unsafe: {directory}")
        for path in directory.rglob("*"):
            if path.suffix not in {".c", ".h"}:
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"source input is missing or unsafe: {path}")
            relative = path.relative_to(root).as_posix()
            files[relative] = sha256_file(path)
    payload = "".join(f"{name} {digest}\n" for name, digest in sorted(files.items()))
    return files, sha256_bytes(payload.encode("utf-8"))


def version_at(root: Path) -> str:
    lines = (root / "README.md").read_text(encoding="utf-8").splitlines()
    match = next((line for line in lines if line.startswith("version ")), None)
    if match is None:
        raise ValueError(f"README version not found: {root}")
    return match.removeprefix("version ").rstrip(".")


def uvm_manifest(files: dict[str, str]) -> tuple[dict[str, str], str]:
    uvm = {name: digest for name, digest in files.items()
           if name.startswith("kernel-open/nvidia-uvm/")}
    payload = "".join(f"{name} {digest}\n" for name, digest in sorted(uvm.items()))
    return uvm, sha256_bytes(payload.encode("utf-8"))


def audit() -> dict:
    roots = {"595.99.02": R595_99, "595.112.07": R595_112}
    trees = {}
    manifests = {}
    for version, (archive, expected_archive_hash) in ARCHIVES.items():
        if not archive.is_file() or archive.is_symlink():
            raise ValueError(f"pinned source archive is missing or unsafe: {archive}")
        archive_hash = sha256_file(archive)
        if archive_hash != expected_archive_hash:
            raise ValueError(f"archive SHA-256 changed for R{version}: {archive_hash}")
        root = roots[version]
        if root.is_symlink() or not root.is_dir() or version_at(root) != version:
            raise ValueError(f"extracted source version mismatch for R{version}")
        files, manifest_hash = source_manifest(root)
        if len(files) != EXPECTED_C_H_FILES:
            raise ValueError(f"R{version} source file count changed: {len(files)}")
        uvm, uvm_hash = uvm_manifest(files)
        if len(uvm) != EXPECTED_UVM_FILES:
            raise ValueError(f"R{version} UVM file count changed: {len(uvm)}")
        trees[version] = {
            "archive": str(archive.relative_to(ROOT)),
            "archive_sha256": archive_hash,
            "source_root": str(root.relative_to(ROOT)),
            "readme_version": version,
            "c_h_file_count": len(files),
            "c_h_manifest_sha256": manifest_hash,
            "uvm_c_h_file_count": len(uvm),
            "uvm_manifest_sha256": uvm_hash,
        }
        manifests[version] = (files, uvm)

    old, old_uvm = manifests["595.99.02"]
    new, new_uvm = manifests["595.112.07"]
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    changed = sorted(name for name in old.keys() & new.keys()
                     if old[name] != new[name])
    uvm_added = sorted(new_uvm.keys() - old_uvm.keys())
    uvm_removed = sorted(old_uvm.keys() - new_uvm.keys())
    uvm_changed = sorted(name for name in old_uvm.keys() & new_uvm.keys()
                         if old_uvm[name] != new_uvm[name])
    if len(changed) != EXPECTED_CHANGED or added or removed:
        raise ValueError("R595 source delta differs from the pinned 93-file snapshot")
    if uvm_added or uvm_removed or uvm_changed:
        raise ValueError("R595 UVM source trees are not byte-identical")
    if Counter(name.split("/", 1)[0] for name in changed) != \
            Counter({"src": 76, "kernel-open": 17}):
        raise ValueError("R595 source delta partition changed")
    return {
        "schema": "r595-open-kernel-source-delta-v1",
        "qualification": "hash-pinned-source-comparison",
        "status": "passed",
        "runtime_or_hardware_validated": False,
        "modules_loaded_or_installed": False,
        "sources": trees,
        "delta": {
            "c_h_files_compared": EXPECTED_C_H_FILES,
            "added": added,
            "removed": removed,
            "changed_file_count": len(changed),
            "changed_by_tree": dict(sorted(Counter(
                name.split("/", 1)[0] for name in changed).items())),
            "changed_paths": changed,
        },
        "uvm_delta": {
            "c_h_files_compared": EXPECTED_UVM_FILES,
            "added": uvm_added,
            "removed": uvm_removed,
            "changed": uvm_changed,
            "byte_identical": True,
        },
        "interpretation": [
            "R595.112.07 adds no C/H change to the R595.99.02 UVM source tree.",
            "The pinned R595.112.07 nv.c change switches oversized P2P page tables to nv_vmalloc and the matching nv_vfree path.",
            "This generic Linux backend path can be backported independently; applicability to a live hybrid stack still requires build and hardware validation.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report_path = args.report or ROOT / "evidence" / \
        f"r595-open-kernel-source-delta-v1-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    report_path = Path(report_path).absolute()
    evidence = ROOT / "evidence"
    if not report_path.is_relative_to(evidence) or report_path.exists() or report_path.is_symlink():
        parser.error("report must be a new file below evidence/")
    try:
        report = audit()
    except (OSError, ValueError) as error:
        parser.error(str(error))
    report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({
        "status": report["status"],
        "changed_files": report["delta"]["changed_file_count"],
        "uvm_identical": report["uvm_delta"]["byte_identical"],
        "report": str(report_path),
        "sha256": sha256_file(report_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
