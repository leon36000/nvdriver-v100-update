#!/usr/bin/env python3
"""Probe the R580.178.04 private-provider patches against R580.196.07 sources.

This performs a hash-pinned source copy and patch-application experiment only.
It does not inspect or modify the proprietary core object, build a module,
install or load a driver, or access a GPU.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
RUNFILE = ROOT / ".cache/upstream/NVIDIA-Linux-x86_64-580.196.07.run"
RUNFILE_SHA256 = "0aab0518db53cf73c412dc7f32bbc850ca95e839d8923d0de4bff42c1c9169ce"
RUNFILE_BYTES = 397209845
EXTRACT_ROOT = (ROOT / "build/experiments/r58019607-runfile-extract-v1-20261029"
                / "NVIDIA-Linux-x86_64-580.196.07")
SOURCE_ROOT = EXTRACT_ROOT / "kernel"
CORE_RELATIVE = "nvidia/nv-kernel.o_binary"
CORE_SHA256 = "24c741bc9b378d66d128de985ae016a662f721bb10faa04511310bace4910f2c"
LIBCUDA_RELATIVE = "libcuda.so.580.196.07"
LIBCUDA_SHA256 = "a5c77bf2de83c0ec06ecd368d224c3e0d653d658d6f99319921e976f21867b14"
LICENSE_SHA256 = "c692fb14ad4f499c6aee1b9e144e6905148c420e6225b17cb2937366c1e507ad"
PATCH_DIR = ROOT / "patches/r580.178.04/proprietary"
NOTICE_PATCH = PATCH_DIR / "0010-local-modification-notices.patch"
EXPERIMENTAL_DEBUGGER_MASK_GUARD = (
    PATCH_DIR / "0049-private-legacy-debugger-mask-fail-closed.patch")
PATCHES = [p for p in sorted(PATCH_DIR.glob("*.patch"))
           if p not in (NOTICE_PATCH, EXPERIMENTAL_DEBUGGER_MASK_GUARD)] + [NOTICE_PATCH]
PATCH_MANIFEST_SHA256 = "fe87e5bffc0bcd91b382ef72ef9194416d6f82ac436d113a23d27ba7c2e716fd"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_fingerprint(root: Path) -> str:
    """Hash every source entry and reject links/special files before copying."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("source root is not a directory")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError("symlinked source input: " + relative)
        if path.is_dir():
            digest.update(("D\0" + relative + "\0").encode())
        elif path.is_file():
            digest.update(("F\0" + relative + "\0").encode())
            digest.update(bytes.fromhex(sha256(path)))
        else:
            raise ValueError("special source input: " + relative)
    return digest.hexdigest()


def patch_manifest_sha256(patches: list[Path]) -> str:
    rows = [f"{patch.name} {sha256(patch)}" for patch in patches]
    return hashlib.sha256(("\n".join(rows) + "\n").encode()).hexdigest()


def _safe_patch_paths(patch_path: Path) -> None:
    text = patch_path.read_text(errors="strict")
    found = 0
    for line in text.splitlines():
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue
        raw = line[4:].split("\t", 1)[0].split(" ", 1)[0]
        if raw == "/dev/null":
            continue
        if "\\" in raw or raw.startswith("/"):
            raise ValueError("unsafe patch path: " + raw)
        if raw.startswith(("a/", "b/")):
            raw = raw[2:]
        relative = PurePosixPath(raw)
        if not raw or relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
            raise ValueError("unsafe patch path: " + raw)
        found += 1
    if found == 0:
        raise ValueError("patch contains no file paths: " + patch_path.name)


def apply_patch_series(source_root: Path, scratch_root: Path, patches: list[Path],
                       *, core_relative: str) -> dict:
    source_root = Path(source_root).resolve(strict=True)
    scratch_root = Path(scratch_root).absolute()
    if scratch_root.exists():
        raise ValueError("scratch path already exists")
    core_posix = PurePosixPath(core_relative)
    if ("\\" in core_relative or core_posix.is_absolute() or
            any(part in ("", ".", "..") for part in core_posix.parts)):
        raise ValueError("unsafe proprietary core path")
    source_before = tree_fingerprint(source_root)
    core_path = source_root / core_relative
    if not core_path.is_file() or core_path.is_symlink():
        raise ValueError("proprietary core input is missing or not a regular file")
    core_before = sha256(core_path)
    for patch_path in patches:
        patch_path = Path(patch_path).resolve(strict=True)
        if not patch_path.is_file():
            raise ValueError("patch is not a regular file")
        _safe_patch_paths(patch_path)

    scratch_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_root, scratch_root, symlinks=False, copy_function=shutil.copy2)
    core_copy = scratch_root / core_relative
    results = []
    offsets = []
    fuzz = []
    failed_patch = None
    for patch_path in patches:
        completed = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch_path)],
            cwd=scratch_root,
            env={**os.environ, "LC_ALL": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        output = completed.stdout
        results.append({"patch": patch_path.name, "exit_code": completed.returncode,
                        "output": output.strip()})
        for line in output.splitlines():
            if "succeeded" in line and "offset" in line:
                offsets.append({"patch": patch_path.name, "line": line})
            if re.search(r"\bfuzz\b", line, flags=re.IGNORECASE):
                fuzz.append({"patch": patch_path.name, "line": line})
        if completed.returncode:
            failed_patch = patch_path.name
            break

    source_after = tree_fingerprint(source_root)
    core_after = sha256(core_copy) if core_copy.is_file() else None
    return {
        "source_tree_sha256_before": source_before,
        "source_tree_sha256_after": source_after,
        "source_tree_unchanged": source_before == source_after,
        "proprietary_core_sha256_before": core_before,
        "proprietary_core_sha256_after": core_after,
        "proprietary_core_unchanged": core_before == core_after,
        "patch_count": len(patches),
        "patches_applied_count": sum(row["exit_code"] == 0 for row in results),
        "all_patches_applied": failed_patch is None and len(results) == len(patches),
        "failed_patch": failed_patch,
        "fuzz_notices": fuzz,
        "offset_notices": offsets,
        "patch_results": results,
        "scratch_root": str(scratch_root),
        "build_performed": False,
        "install_or_load_performed": False,
        "hardware_accessed": False,
        "vendor_binary_reverse_engineered": False,
        "vendor_binary_modified": False,
    }


def _verify_release_inputs() -> dict:
    if sha256(RUNFILE) != RUNFILE_SHA256 or RUNFILE.stat().st_size != RUNFILE_BYTES:
        raise ValueError("R580.196.07 runfile hash or size mismatch")
    if patch_manifest_sha256(PATCHES) != PATCH_MANIFEST_SHA256 or len(PATCHES) != 48:
        raise ValueError("R580.178.04 proprietary patch set changed")
    if not (EXTRACT_ROOT / "README.txt").is_file() or "580.196.07" not in (EXTRACT_ROOT / "README.txt").read_text(errors="replace"):
        raise ValueError("extracted runfile does not identify as 580.196.07")
    core = SOURCE_ROOT / CORE_RELATIVE
    libcuda = EXTRACT_ROOT / LIBCUDA_RELATIVE
    license_path = EXTRACT_ROOT / "LICENSE"
    checks = ((core, CORE_SHA256, "proprietary core"),
              (libcuda, LIBCUDA_SHA256, "R580.196.07 libcuda"),
              (license_path, LICENSE_SHA256, "driver license"))
    for path, expected, label in checks:
        if not path.is_file() or sha256(path) != expected:
            raise ValueError(label + " hash mismatch")
    return {
        "runfile": {"path": str(RUNFILE), "sha256": RUNFILE_SHA256,
                    "bytes": RUNFILE_BYTES, "official_checksum_verified": True},
        "source_root": str(SOURCE_ROOT),
        "source_tree_sha256": tree_fingerprint(SOURCE_ROOT),
        "proprietary_core": {"path": str(core), "sha256": CORE_SHA256,
                             "bytes": core.stat().st_size, "contents_analyzed": False},
        "libcuda": {"path": str(libcuda), "sha256": LIBCUDA_SHA256,
                    "bytes": libcuda.stat().st_size},
        "license": {"path": str(license_path), "sha256": LICENSE_SHA256},
        "patch_set": {"version": "580.178.04", "count": len(PATCHES),
                      "manifest_sha256": PATCH_MANIFEST_SHA256},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path,
                        default=ROOT / "build/experiments/r58019607-proprietary-port-v1-20261029")
    parser.add_argument("--report", type=Path,
                        default=ROOT / "evidence/r580-19607-proprietary-patch-port-v2-20261029.json")
    args = parser.parse_args(argv)
    work = args.work_dir.resolve()
    report_path = args.report.resolve()
    if work.exists() or report_path.exists():
        parser.error("work and report paths must be unused")
    if not work.is_relative_to(ROOT / "build/experiments") or not report_path.is_relative_to(ROOT / "evidence"):
        parser.error("work/report paths must remain under build/experiments and evidence")

    report = {
        "schema": "r580-proprietary-source-port-probe-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "not-started",
        "version_under_test": "580.196.07",
        "patch_version": "580.178.04",
        "source_patch_probe_only": True,
        "license_boundary": {
            "proprietary_binary_reverse_engineered": False,
            "proprietary_binary_modified": False,
            "redistribution_authorized": False,
        },
        "work_dir": str(work),
    }
    try:
        report["inputs"] = _verify_release_inputs()
        patch_result = apply_patch_series(SOURCE_ROOT, work / "source", PATCHES,
                                          core_relative=CORE_RELATIVE)
        report["patch_probe"] = patch_result
        report["qualification"] = (
            "source-patches-applied-no-build"
            if patch_result["all_patches_applied"] and
            patch_result["proprietary_core_unchanged"] and
            patch_result["source_tree_unchanged"] and not patch_result["fuzz_notices"]
            else "source-patch-port-failed")
    except Exception as error:
        report["qualification"] = "source-patch-port-failed"
        report["error"] = f"{type(error).__name__}: {error}"

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({"qualification": report["qualification"],
                      "report": str(report_path),
                      "patches_applied": report.get("patch_probe", {}).get("patches_applied_count"),
                      "offset_notices": len(report.get("patch_probe", {}).get("offset_notices", [])),
                      "fuzz_notices": len(report.get("patch_probe", {}).get("fuzz_notices", [])),
                      "proprietary_core_unchanged": report.get("patch_probe", {}).get("proprietary_core_unchanged")},
                     indent=2))
    return 0 if report["qualification"] == "source-patches-applied-no-build" else 1


if __name__ == "__main__":
    raise SystemExit(main())
