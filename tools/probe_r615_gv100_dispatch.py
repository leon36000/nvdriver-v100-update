#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a private, compile-only R580 GV100 dispatch probe on exact R615.71.10.

The official R615 package archive and its complete ``kernel-open`` subtree are
verified before an isolated source copy is made. The candidate is never
installed or loaded; a successful link proves neither RM selection nor GPU
runtime semantics.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_archive_subtree_integrity import compare_archive_subtree  # noqa: E402
from tools.audit_volta_uvm_hal_dispatch import audit_volta_uvm_dispatch  # noqa: E402
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    R580_SOURCE_ROOT,
    build_overlay,
    prepare_overlay,
    read_member,
)

R615_RELEASE = "615.71.10"
R615_ARCHIVE_SHA256 = (
    "41e16cfbb3ba475c55b6ce5b2595e1a87a76948873a1a83f1b261f6b7ba0bf5b"
)
R615_KERNEL_OPEN_PREFIX = (
    "nvidia_driver-linux-x86_64-615.71.10-archive/kernel-open"
)
R615_KERNEL_OPEN_MANIFEST_SHA256 = (
    "cda8418daa9d2a512f27235c4f3800abdfb523cdbbc2ed9598e9183a72318a2d"
)
DEFAULT_R580_ARCHIVE = (
    ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
)
DEFAULT_R615_ARCHIVE = (
    ROOT / ".cache/upstream/nvidia_driver-linux-x86_64-615.71.10-archive.tar.xz"
)
DEFAULT_R615_KERNEL_OPEN = (
    ROOT / ".cache/upstream/extracted-r615-71-10-package/kernel-open"
)
DEFAULT_EXPECTED_R615_SOURCE_COUNT = 457
COMPILE_PROBE_ONLY = True


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summarize_build_output(output: str) -> dict:
    """Count compiler warning/error records without conflating them with link success."""
    lines = output.splitlines()
    return {
        "warning_line_count": sum(
            bool(re.search(r"\bwarning:", line, re.IGNORECASE)) for line in lines
        ),
        "compiler_error_line_count": sum(
            bool(re.search(r"\b(?:fatal\s+)?error:", line, re.IGNORECASE))
            for line in lines
        ),
    }


def validate_r615_source(archive: Path,
                         kernel_open: Path,
                         *,
                         expected_archive_sha256: str = R615_ARCHIVE_SHA256,
                         expected_manifest_sha256: str = R615_KERNEL_OPEN_MANIFEST_SHA256,
                         expected_file_count: int = DEFAULT_EXPECTED_R615_SOURCE_COUNT) -> dict:
    """Prove the extracted source is the complete pinned R615 kernel-open tree."""
    expected_archive_sha256 = expected_archive_sha256.lower()
    expected_manifest_sha256 = expected_manifest_sha256.lower()
    if len(expected_archive_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in expected_archive_sha256
    ):
        raise ValueError("expected R615 archive SHA-256 must be 64 lowercase hex characters")
    if len(expected_manifest_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in expected_manifest_sha256
    ):
        raise ValueError("expected R615 source manifest must be 64 lowercase hex characters")

    result = compare_archive_subtree(
        Path(archive),
        R615_KERNEL_OPEN_PREFIX,
        Path(kernel_open),
        expected_archive_sha256=expected_archive_sha256,
    )
    if not result["provenance_valid"]:
        raise ValueError("R615 kernel-open source provenance did not validate")
    if result["archive_manifest_sha256"] != expected_manifest_sha256:
        raise ValueError(
            "R615 kernel-open source manifest mismatch: "
            f"got {result['archive_manifest_sha256']}, expected {expected_manifest_sha256}"
        )
    if result["archive_file_count"] != expected_file_count:
        raise ValueError(
            "R615 kernel-open file count mismatch: "
            f"got {result['archive_file_count']}, "
            f"expected {expected_file_count}"
        )
    return result


def create_verified_r615_snapshot(archive: Path,
                                  kernel_open: Path,
                                  destination: Path,
                                  *,
                                  expected_archive_sha256: str = R615_ARCHIVE_SHA256,
                                  expected_manifest_sha256: str = R615_KERNEL_OPEN_MANIFEST_SHA256,
                                  expected_file_count: int = DEFAULT_EXPECTED_R615_SOURCE_COUNT) -> dict:
    """Copy the vendor tree privately, then verify the exact copy used as build input."""
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing source snapshot: {destination}")
    try:
        shutil.copytree(Path(kernel_open), destination, symlinks=True)
        provenance = validate_r615_source(
            archive,
            destination,
            expected_archive_sha256=expected_archive_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            expected_file_count=expected_file_count,
        )
    except BaseException:
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise
    return provenance


def validate_scratch_path(scratch: Path, repository_root: Path = ROOT) -> Path:
    """Require a fresh build directory directly under this repo's experiment root."""
    scratch = Path(scratch)
    if scratch.exists() or scratch.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing scratch tree: {scratch}")
    repository_root = Path(repository_root).resolve(strict=True)
    build_root = repository_root / "build"
    experiment_root = build_root / "experiments"
    if build_root.is_symlink() or experiment_root.is_symlink():
        raise ValueError("repository build/experiments path must not contain symlinks")
    if not build_root.is_dir() or not experiment_root.is_dir():
        raise ValueError("repository build/experiments is not a directory")
    experiment_root = experiment_root.resolve(strict=True)
    try:
        experiment_root.relative_to(repository_root)
    except ValueError as error:
        raise ValueError("repository build/experiments resolves outside repository") from error
    if scratch.name in ("", ".", ".."):
        raise ValueError("scratch path must name a new direct child directory")
    resolved_parent = scratch.parent.resolve(strict=True)
    if resolved_parent != experiment_root:
        raise ValueError(
            f"scratch path must be a direct child inside {experiment_root}: {scratch}"
        )
    resolved = resolved_parent / scratch.name
    try:
        resolved.relative_to(experiment_root)
    except ValueError as error:
        raise ValueError(
            f"scratch path must be inside {experiment_root}: {resolved}"
        ) from error
    return resolved


def _open_real_directory(path: Path) -> int:
    """Open a directory by walking from / without following any symlink component."""
    required_flags = ("O_NOFOLLOW", "O_DIRECTORY")
    if any(not hasattr(os, flag) for flag in required_flags):
        raise OSError("O_NOFOLLOW and O_DIRECTORY are required for private evidence output")
    absolute = Path(os.path.abspath(Path(path)))
    descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_report_path(path: Path, repository_root: Path = ROOT) -> Path:
    """Confine CLI evidence output to an existing, real directory under evidence/."""
    repository_root = Path(repository_root).resolve(strict=True)
    evidence_root = repository_root / "evidence"
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise ValueError("repository evidence path must be a real directory")
    path = Path(path)
    candidate = path if path.is_absolute() else repository_root / path
    candidate = Path(os.path.abspath(candidate))
    evidence_root = Path(os.path.abspath(evidence_root))
    try:
        relative = candidate.relative_to(evidence_root)
    except ValueError as error:
        raise ValueError(
            f"report path must be inside repository evidence: {candidate}"
        ) from error
    if not relative.parts or candidate.name in ("", ".", ".."):
        raise ValueError("report path must name a file inside repository evidence")
    parent_descriptor = _open_real_directory(candidate.parent)
    os.close(parent_descriptor)
    return candidate


def _write_private_report_at(parent_descriptor: int, name: str, report: dict) -> None:
    """Create a new mode-0600 JSON file relative to an already-open directory."""
    if name in ("", ".", ".."):
        raise ValueError("report path must name a file")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = None
    created = False
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent_descriptor)
    except BaseException:
        if created:
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_private_report(path: Path, report: dict) -> None:
    """Create a new mode-0600 JSON report without following or replacing paths."""
    path = Path(path)
    if path.name in ("", ".", ".."):
        raise ValueError("report path must name a file")
    parent_descriptor = _open_real_directory(path.parent)
    try:
        _write_private_report_at(parent_descriptor, path.name, report)
    finally:
        os.close(parent_descriptor)


def write_private_evidence_report(path: Path, report: dict,
                                 repository_root: Path = ROOT) -> Path:
    """Confine an evidence write and keep its opened parent directory pinned."""
    repository_root = Path(repository_root).resolve(strict=True)
    evidence_root = repository_root / "evidence"
    path = Path(path)
    candidate = path if path.is_absolute() else repository_root / path
    candidate = Path(os.path.abspath(candidate))
    evidence_root = Path(os.path.abspath(evidence_root))
    try:
        relative = candidate.relative_to(evidence_root)
    except ValueError as error:
        raise ValueError(
            f"report path must be inside repository evidence: {candidate}"
        ) from error
    if not relative.parts or relative.name in ("", ".", ".."):
        raise ValueError("report path must name a file inside repository evidence")

    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    repository_descriptor = _open_real_directory(repository_root)
    evidence_descriptor = None
    parent_descriptor = None
    try:
        evidence_descriptor = os.open(
            "evidence", directory_flags, dir_fd=repository_descriptor
        )
        parent_descriptor = evidence_descriptor
        evidence_descriptor = None
        for component in relative.parts[:-1]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=parent_descriptor
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        _write_private_report_at(parent_descriptor, relative.name, report)
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if evidence_descriptor is not None:
            os.close(evidence_descriptor)
        os.close(repository_descriptor)
    return candidate


def _tree_manifest(directory: Path) -> dict:
    """Hash a complete regular-file source tree using the archive manifest format."""
    import stat

    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("source tree manifest root must be a real directory")
    digest = hashlib.sha256()
    file_count = 0
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise ValueError(f"symlink in prepared source tree: {relative}")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"non-regular file in prepared source tree: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
        file_count += 1
    return {"manifest_sha256": digest.hexdigest(), "file_count": file_count}


def _implementation_fingerprints() -> dict:
    paths = (
        Path(__file__).resolve(strict=True),
        ROOT / "tools/probe_volta_uvm_port.py",
        ROOT / "tools/audit_archive_subtree_integrity.py",
        ROOT / "tools/audit_volta_uvm_hal_dispatch.py",
        ROOT / "tests/test_r615_gv100_dispatch_probe.py",
    )
    return {
        path.relative_to(ROOT).as_posix(): sha256_file(path)
        for path in paths
    }


def make_probe_report(*,
                      source_provenance: dict,
                      scratch: Path,
                      overlay: dict,
                      dispatch_audit: dict,
                      build: dict,
                      prepared_source_manifest: dict | None = None,
                      implementation_sha256: dict | None = None) -> dict:
    """Assemble accurate R615-labeled evidence from the existing overlay probe."""
    overlay_summary = dict(overlay)
    legacy_source_field = overlay_summary.pop("r595_source", None)
    overlay_summary["modern_source_root"] = legacy_source_field
    overlay_summary["compile_probe_only"] = COMPILE_PROBE_ONLY
    overlay_summary["runtime_semantics_validated"] = False
    overlay_summary["loaded_or_installed"] = False
    return {
        "schema": "r615-r580-gv100-dispatch-compile-probe-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base_release": f"NVIDIA Open R{R615_RELEASE}",
        "r615_archive_sha256": source_provenance["archive_sha256"],
        "r615_kernel_open_manifest_sha256": source_provenance[
            "archive_manifest_sha256"
        ],
        "r615_verified_snapshot_manifest_sha256": source_provenance.get(
            "extracted_manifest_sha256"
        ),
        "r615_verified_snapshot_file_count": source_provenance.get(
            "extracted_file_count"
        ),
        "r615_kernel_open_file_count": source_provenance["archive_file_count"],
        "source_provenance_valid": source_provenance["provenance_valid"],
        "modern_source_root": legacy_source_field,
        "r580_archive_sha256": overlay["r580_archive_sha256"],
        "scratch": str(scratch),
        "prepared_source_tree": prepared_source_manifest,
        "implementation_sha256": implementation_sha256 or _implementation_fingerprints(),
        "overlay_preparation": overlay_summary,
        "dispatch_audit": dispatch_audit,
        "build": build,
        "compile_probe_only": COMPILE_PROBE_ONLY,
        "module_linked_this_run": build.get("module_linked_this_run") is True,
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "limitations": [
            "The probe restores R580-derived UVM callback ancestry and GV100 HAL rows into a disposable R615 source copy.",
            "Compile-only adapters preserve source/build closure and do not establish valid R615 RM or GPU semantics.",
            "No kernel module was installed or loaded; no GPU was exercised by this tool.",
        ],
    }


def _r580_hal_source(archive_path: Path) -> str:
    with tarfile.open(archive_path, "r:*") as archive:
        member = f"{R580_SOURCE_ROOT}/kernel-open/nvidia-uvm/uvm_hal.c"
        return read_member(archive, member).decode("utf-8", errors="strict")


def run_probe(*,
              r580_archive: Path,
              r615_archive: Path,
              r615_kernel_open: Path,
              scratch: Path,
              jobs: int) -> dict:
    """Verify pinned inputs, prepare a fresh overlay, audit rows, and build only."""
    scratch = validate_scratch_path(scratch)
    implementation_sha256 = _implementation_fingerprints()
    with tempfile.TemporaryDirectory(
        prefix=f".{scratch.name}.r615-source-", dir=scratch.parent
    ) as temporary_directory:
        source_snapshot = Path(temporary_directory) / "kernel-open"
        source_provenance = create_verified_r615_snapshot(
            r615_archive, r615_kernel_open, source_snapshot
        )
        overlay = prepare_overlay(
            r580_archive,
            source_snapshot,
            scratch,
            expected_archive_sha256=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
            compile_probe_adapter=True,
            restore_callback_ancestors=True,
            restore_dispatch_ancestors=True,
        )
    modern_hal = (scratch / "nvidia-uvm/uvm_hal.c").read_text(
        encoding="utf-8", errors="strict"
    )
    dispatch_audit = audit_volta_uvm_dispatch(
        _r580_hal_source(Path(r580_archive)),
        modern_hal,
        modern_branch=f"NVIDIA Open R{R615_RELEASE} source overlay",
    )
    prepared_source_manifest = _tree_manifest(scratch)
    build = build_overlay(
        scratch,
        jobs,
        compile_probe_adapter=True,
        callback_ancestor_sources=tuple(overlay["added_callback_ancestor_sources"]),
    )
    build_log = Path(build["build_log"])
    if build_log.is_file():
        build_log.chmod(0o600)
        build.update(summarize_build_output(build_log.read_text(errors="replace")))
    else:
        build.update({"warning_line_count": None, "compiler_error_line_count": None})
    return make_probe_report(
        source_provenance=source_provenance,
        scratch=scratch,
        overlay=overlay,
        dispatch_audit=dispatch_audit,
        build=build,
        prepared_source_manifest=prepared_source_manifest,
        implementation_sha256=implementation_sha256,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--r615-archive", type=Path, default=DEFAULT_R615_ARCHIVE)
    parser.add_argument("--r615-kernel-open", type=Path, default=DEFAULT_R615_KERNEL_OPEN)
    parser.add_argument("--scratch", type=Path, required=True,
                        help="fresh directory under build/experiments; existing paths refused")
    parser.add_argument("--report", type=Path,
                        help="new private JSON file under repository evidence/ (default: evidence/<scratch-name>.json)")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    report_path = args.report or (
        ROOT / "evidence" / f"{Path(args.scratch).name}.json"
    )
    try:
        report_path = validate_report_path(report_path)
        report = run_probe(
            r580_archive=args.r580_archive,
            r615_archive=args.r615_archive,
            r615_kernel_open=args.r615_kernel_open,
            scratch=args.scratch,
            jobs=args.jobs,
        )
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"R615 GV100 dispatch compile probe failed: {error}", file=sys.stderr)
        return 1

    try:
        report_path = write_private_evidence_report(report_path, report)
    except (OSError, ValueError) as error:
        print(f"Could not write private probe report: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["dispatch_audit"]["modern_static_dispatch_candidate"] is not True:
        return 4
    if report["build"].get("build_command_succeeded") is not True:
        return 2
    if report["module_linked_this_run"] is not True:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
