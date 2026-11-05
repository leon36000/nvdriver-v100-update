#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the pinned R580.178.04 compute libraries without installing them.

The Debian archive is hash-pinned and its libcuda binary is compared with the
captured V100 guest file. Extraction is confined to a new private directory
under build/staging. No package scripts, CUDA calls, driver changes or GPU
access occur.
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
import stat
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_r58017804_libcuda_package import (  # noqa: E402
    ARCHIVE_PATH,
    EXPECTED_GUEST_LIBRARY,
    EXPECTED_PACKAGE,
    _safe_archive_path,
    verify_archive_file,
)
from tools.stage_nvidia_canary_packages import verify_deb_metadata  # noqa: E402

AUDIT_REPORT_PATH = ROOT / "evidence/r58017804-libcuda-package-binary-match-v1-20261028T1535Z.json"
AUDIT_REPORT_SHA256 = "79f4ab594e8f2d6474b966832b04467846427d414b4f5d6049cf4c9af6edafa5"
EXPECTED_GUEST_LIBRARY_SHA256 = EXPECTED_GUEST_LIBRARY["sha256"]
COMPUTE_DIRECTORY = PurePosixPath("usr/lib/x86_64-linux-gnu")
REQUIRED_LIBRARIES = {
    "libcuda": "libcuda.so.580.178.04",
    "ptx_jit_compiler": "libnvidia-ptxjitcompiler.so.580.178.04",
    "nvvm": "libnvidia-nvvm.so.580.178.04",
    "nvvm70": "libnvidia-nvvm70.so.4",
    "nvml": "libnvidia-ml.so.580.178.04",
    "cuda_debugger": "libcudadebugger.so.580.178.04",
}
DEFAULT_OUTPUT = ROOT / "build/staging/r58017804-compute-userland-v1"
DEFAULT_REPORT = ROOT / "evidence/r58017804-compute-userland-stage-v1-20261028T2154Z.json"
STAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inventory_tree(root: Path) -> list[dict[str, Any]]:
    """Return a hash inventory and reject special files or escaping symlinks."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("staged package root must be a real directory")
    root = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []

    def record(path: Path) -> dict[str, Any]:
        rel = PurePosixPath(path.relative_to(root).as_posix())
        if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
            raise ValueError("package member path is unsafe")
        info = path.lstat()
        item: dict[str, Any] = {"path": rel.as_posix()}
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            try:
                resolved_target = path.resolve(strict=True)
                resolved_target.relative_to(root)
            except (OSError, ValueError):
                raise ValueError("package symlink escapes stage root or is dangling") from None
            item.update({"type": "symlink", "target": target})
        elif stat.S_ISREG(info.st_mode):
            item.update({
                "type": "file",
                "bytes": info.st_size,
                "sha256": sha256_file(path),
            })
        else:
            raise ValueError("package contains a non-regular, non-symlink member")
        return item

    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        traverse = []
        for name in sorted(dirnames):
            path = current / name
            if path.is_symlink():
                entries.append(record(path))
            else:
                traverse.append(name)
        dirnames[:] = traverse
        for name in sorted(filenames):
            entries.append(record(current / name))
    entries.sort(key=lambda item: item["path"])
    if not entries:
        raise ValueError("staged package tree is empty")
    paths = [item["path"] for item in entries]
    if len(paths) != len(set(paths)):
        raise ValueError("staged package tree has duplicate paths")
    return entries


def validate_compute_userland(
    root: Path,
    entries: list[dict[str, Any]],
    *,
    expected_libcuda_sha256: str = EXPECTED_GUEST_LIBRARY_SHA256,
) -> dict[str, dict[str, Any]]:
    """Require the exact V100 libcuda and the matched compute library set."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_libcuda_sha256):
        raise ValueError("expected guest libcuda hash is malformed")
    by_path = {item["path"]: item for item in entries}
    result: dict[str, dict[str, Any]] = {}
    for role, basename in REQUIRED_LIBRARIES.items():
        rel = (COMPUTE_DIRECTORY / basename).as_posix()
        item = by_path.get(rel)
        if not item or item.get("type") != "file":
            if role == "ptx_jit_compiler":
                raise ValueError("R580.178.04 PTX JIT compiler is missing")
            raise ValueError(f"required R580.178.04 compute library is missing: {basename}")
        result[role] = {key: value for key, value in item.items() if key != "type"}
    if result["libcuda"]["sha256"] != expected_libcuda_sha256:
        raise ValueError("staged libcuda guest libcuda hash differs from the pinned V100 binary")

    libdir = Path(root).resolve(strict=True) / Path(*COMPUTE_DIRECTORY.parts)
    for link_name in ("libcuda.so", "libcuda.so.1"):
        link = libdir / link_name
        if not link.is_symlink():
            raise ValueError(f"expected libcuda loader symlink is missing: {link_name}")
        try:
            resolved = link.resolve(strict=True)
            resolved.relative_to(Path(root).resolve(strict=True))
        except (OSError, ValueError):
            raise ValueError("libcuda loader symlink escapes stage root or is dangling") from None
        if resolved.name != REQUIRED_LIBRARIES["libcuda"]:
            raise ValueError("libcuda loader symlink does not select the pinned R580 binary")
    return result


def _validate_destinations(output_dir: Path, report_path: Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    report_path = Path(report_path)
    allowed_stage = (ROOT / "build/staging").resolve(strict=True)
    allowed_evidence = (ROOT / "evidence").resolve(strict=True)
    for path, parent, label in (
        (output_dir, allowed_stage, "stage"),
        (report_path, allowed_evidence, "report"),
    ):
        if not STAGE_NAME.fullmatch(path.name):
            raise ValueError(f"{label} destination has an unsafe basename")
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"{label} destination already exists")
        try:
            resolved_parent = path.parent.resolve(strict=True)
            resolved_parent.relative_to(parent)
        except (OSError, ValueError):
            raise ValueError(f"{label} destination must remain under the project {label} directory") from None
        if resolved_parent != parent:
            raise ValueError(f"{label} destination must be a direct child of the project directory")
    return allowed_stage / output_dir.name, allowed_evidence / report_path.name


def _validate_provenance_report() -> dict[str, Any]:
    path = AUDIT_REPORT_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError("pinned libcuda provenance report is missing or unsafe")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != AUDIT_REPORT_SHA256:
        raise ValueError("pinned libcuda provenance report hash differs")
    try:
        report = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("pinned libcuda provenance report is malformed") from None
    if (report.get("schema") != "pc3-r58017804-libcuda-package-binary-match-v1" or
            report.get("status") != "archive-library-matches-v100-guest-capture" or
            report.get("archive", {}).get("sha256") != EXPECTED_PACKAGE["sha256"] or
            report.get("binary_comparison", {}).get("same_sha256") is not True or
            report.get("binary_comparison", {}).get("extracted_library", {}).get("sha256") !=
            EXPECTED_GUEST_LIBRARY_SHA256):
        raise ValueError("pinned libcuda provenance report no longer proves the expected package match")
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": AUDIT_REPORT_SHA256,
        "schema": report["schema"],
    }


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def stage_compute_userland(
    output_dir: Path = DEFAULT_OUTPUT,
    report_path: Path = DEFAULT_REPORT,
    *,
    archive_path: Path = ARCHIVE_PATH,
    runner=subprocess.run,
) -> dict[str, Any]:
    output_dir, report_path = _validate_destinations(output_dir, report_path)
    archive = _safe_archive_path(ROOT, Path(archive_path))
    provenance = _validate_provenance_report()

    archive_identity = verify_archive_file(archive, EXPECTED_PACKAGE)
    deb_identity = verify_deb_metadata(
        archive,
        {
            "package": EXPECTED_PACKAGE["package"],
            "version": EXPECTED_PACKAGE["version"],
            "architecture": EXPECTED_PACKAGE["architecture"],
        },
        runner=runner,
    )
    output_dir.mkdir(mode=0o700)
    try:
        extraction = runner(
            ["dpkg-deb", "--extract", str(archive.resolve(strict=True)), str(output_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if extraction.returncode != 0:
            raise RuntimeError("dpkg-deb data extraction failed")
        os.chmod(output_dir, 0o700)
        entries = inventory_tree(output_dir)
        components = validate_compute_userland(output_dir, entries)
        report: dict[str, Any] = {
            "schema": "r58017804-compute-userland-stage-v1",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "qualification": "pinned-compute-userland-staged; no runtime test",
            "package": {
                "path": str(archive.resolve(strict=True).relative_to(ROOT)),
                **archive_identity,
                "deb_identity": deb_identity,
            },
            "provenance_report": {
                **provenance,
            },
            "stage": {
                "path": str(output_dir.resolve(strict=True)),
                "mode": "0700",
                "file_count": len(entries),
                "libraries": components,
                "files": entries,
            },
            "tool_sha256": sha256_file(Path(__file__).resolve(strict=True)),
            "actions": {
                "package_scripts_run": False,
                "package_installed": False,
                "system_library_paths_changed": False,
                "module_loaded_or_installed": False,
                "cuda_api_called": False,
                "gpu_accessed": False,
            },
        }
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _write_exclusive(report_path, payload, 0o600)
    except Exception:
        shutil.rmtree(output_dir)
        raise
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    try:
        result = stage_compute_userland(args.output_dir, args.report)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"compute userland stage failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "schema": result["schema"],
        "stage": result["stage"]["path"],
        "file_count": result["stage"]["file_count"],
        "libcuda_sha256": result["stage"]["libraries"]["libcuda"]["sha256"],
        "report": str(args.report),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
