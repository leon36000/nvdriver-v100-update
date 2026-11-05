#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Download and stage a hash-pinned CUDA component set below build/tools.

This does not install packages, include a driver, change system paths, or
initialize a CUDA device. Vendor archives are kept local and are not intended
for source-control upload.
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
import tarfile
import tempfile
from typing import Any
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "configs/cuda-toolchains/cuda-12.9.2-linux-x86_64.json"
DEFAULT_CACHE = ROOT / "build/tools/cuda-12.9.2-downloads"
DEFAULT_OUTPUT = ROOT / "build/tools/cuda-12.9.2-toolchain"
ALLOWED_COMPONENTS = {
    "cuda_nvcc", "cuda_cccl", "cuda_cudart", "cuda_cuobjdump",
    "cuda_nvdisasm", "libnvfatbin", "libnvjitlink", "libcublas",
}
REQUIRED_COMPONENTS = {"cuda_nvcc", "cuda_cccl", "cuda_cudart", "cuda_cuobjdump", "libcublas"}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_lock(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("schema") != "nvdriver-cuda-toolchain-lock-v1":
        raise ValueError("unsupported CUDA toolchain lock schema")
    if (data.get("toolkit") != "12.9.2" or data.get("platform") != "linux-x86_64" or
            data.get("release_label") != "CUDA Toolkit 12.9 Update 2"):
        raise ValueError("CUDA release or platform differs from the reviewed pin")
    manifest = data.get("manifest")
    if (not isinstance(manifest, dict) or manifest.get("url") !=
            "https://developer.download.nvidia.com/compute/cuda/redist/redistrib_12.9.2.json" or
            not isinstance(manifest.get("sha256"), str) or
            not SHA256_RE.fullmatch(manifest["sha256"]) or
            not isinstance(manifest.get("bytes"), int) or manifest["bytes"] <= 0):
        raise ValueError("official CUDA redistribution manifest pin is invalid")
    components = data.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("component lock must be a nonempty list")
    seen: set[str] = set()
    for row in components:
        if not isinstance(row, dict):
            raise ValueError("component row must be an object")
        name, version, relative = row.get("name"), row.get("version"), row.get("path")
        if name not in ALLOWED_COMPONENTS or name in seen:
            raise ValueError("component is unknown, duplicated, or a driver component")
        seen.add(name)
        path = PurePosixPath(relative) if isinstance(relative, str) else PurePosixPath("/")
        if (path.is_absolute() or any(part in ("", ".", "..") for part in path.parts) or
                len(path.parts) != 3 or path.parts[1] != "linux-x86_64" or
                "-archive.tar.xz" not in path.name):
            raise ValueError(f"unsafe or malformed archive path for {name}")
        if not isinstance(version, str) or not version or not isinstance(row.get("bytes"), int):
            raise ValueError(f"component version/size is invalid for {name}")
        if not isinstance(row.get("sha256"), str) or not SHA256_RE.fullmatch(row["sha256"]):
            raise ValueError(f"component hash is invalid for {name}")
    if not REQUIRED_COMPONENTS.issubset(seen):
        raise ValueError("required compiler, runtime, CCCL, cuobjdump, or cuBLAS component is missing")
    excluded = data.get("excluded_components")
    if not isinstance(excluded, list) or "nvidia_driver" not in excluded or "cuda_compat" not in excluded:
        raise ValueError("lock must explicitly exclude driver and compatibility-driver packages")
    return data


def verify_against_manifest(lock: dict[str, Any], manifest_raw: bytes) -> dict[str, Any]:
    if hashlib.sha256(manifest_raw).hexdigest() != lock["manifest"]["sha256"]:
        raise ValueError("official CUDA redistribution manifest hash differs")
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("official CUDA redistribution manifest is malformed") from None
    verified = []
    for row in lock["components"]:
        upstream = manifest.get(row["name"], {}).get("linux-x86_64", {})
        expected = {"relative_path": row["path"], "sha256": row["sha256"], "size": str(row["bytes"])}
        if any(upstream.get(key) != value for key, value in expected.items()):
            raise ValueError(f"official manifest metadata differs for {row['name']}")
        verified.append(row["name"])
    return {"sha256": hashlib.sha256(manifest_raw).hexdigest(), "components": verified}


def _download(url: str, destination: Path, expected_sha256: str, expected_bytes: int) -> None:
    destination = Path(destination)
    if destination.is_symlink():
        raise ValueError("download cache destination may not be a symlink")
    if destination.exists():
        if destination.is_file() and destination.stat().st_size == expected_bytes and sha256_file(destination) == expected_sha256:
            return
        raise ValueError(f"cached file exists but does not match its pin: {destination.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    count = 0
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".part", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as output, urlopen(url, timeout=120) as response:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                output.write(block)
                digest.update(block)
                count += len(block)
            output.flush()
            os.fsync(output.fileno())
        if count != expected_bytes or digest.hexdigest() != expected_sha256:
            raise ValueError(f"download failed size/hash verification: {destination.name}")
        os.replace(name, destination)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise


def _safe_unpack(archive: Path, target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, mode="r:xz") as source:
        members = source.getmembers()
        if not members:
            raise ValueError("vendor archive is empty")
        roots: set[str] = set()
        for member in members:
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
                raise ValueError("archive contains an unsafe member path")
            roots.add(rel.parts[0])
            if not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError("archive contains an unsupported member type")
        if len(roots) != 1 or not next(iter(roots)).endswith("-archive"):
            raise ValueError("archive root does not match NVIDIA redist layout")
        source.extractall(target, members=members, filter="data")
    return target / next(iter(roots))


def _same_content(source: Path, destination: Path) -> bool:
    if source.is_symlink() and destination.is_symlink():
        return os.readlink(source) == os.readlink(destination)
    try:
        return (source.is_file() and destination.is_file() and
                sha256_file(source.resolve(strict=True)) == sha256_file(destination.resolve(strict=True)))
    except (OSError, ValueError):
        return False


def _overlay_component(source_root: Path, toolkit_root: Path) -> None:
    source_root = source_root.resolve(strict=True)
    toolkit_root.mkdir(parents=True, exist_ok=True)
    entries = sorted(source_root.rglob("*"), key=lambda p: (len(p.relative_to(source_root).parts), p.as_posix()))
    for source in entries:
        rel = source.relative_to(source_root)
        # Each package retains its own license in components/. A single merged
        # LICENSE/EULA is ambiguous and is not consumed by the toolchain.
        if len(rel.parts) == 1 and rel.name.lower() in {"license", "eula.txt"}:
            continue
        destination = toolkit_root / rel
        if source.is_dir() and not source.is_symlink():
            if destination.exists() or destination.is_symlink():
                if not destination.is_dir() or destination.is_symlink():
                    raise ValueError(f"toolkit component path collision at {rel}")
            else:
                destination.mkdir(parents=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            if not _same_content(source, destination):
                raise ValueError(f"toolkit component file collision at {rel}")
            continue
        if source.is_symlink():
            destination.symlink_to(os.readlink(source))
        elif source.is_file():
            relative_target = os.path.relpath(source, destination.parent)
            destination.symlink_to(relative_target)
        else:
            raise ValueError(f"unsupported staged entry at {rel}")


def _ensure_target_layout(toolkit_root: Path) -> None:
    """Add the target-root alias expected by NVCC's redist profile."""
    target = toolkit_root / "targets/x86_64-linux"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        if target.resolve(strict=True) != toolkit_root.resolve(strict=True):
            raise ValueError("existing CUDA target layout alias points outside the toolkit root")
        return
    if target.exists():
        if not target.is_dir():
            raise ValueError("CUDA target layout path is not a directory")
        for child in ("include", "lib"):
            expected = toolkit_root / child
            if not (target / child).exists() and expected.exists():
                (target / child).symlink_to(os.path.relpath(expected, target))
        return
    target.symlink_to("..")
    if target.resolve(strict=True) != toolkit_root.resolve(strict=True):
        raise ValueError("generated CUDA target layout alias does not resolve to the toolkit root")


def _within_build_tools(path: Path) -> Path:
    base = (ROOT / "build/tools").resolve(strict=True)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("stage path may not be a symlink")
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError("all downloads and extraction must remain below build/tools") from None
    return candidate


def _load_lock(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("CUDA toolchain lock is missing or unsafe")
    return validate_lock(json.loads(path.read_text(encoding="utf-8")))


def stage(lock_path: Path, cache_dir: Path, output_dir: Path, offline: bool = False) -> dict[str, Any]:
    lock = _load_lock(lock_path)
    cache = _within_build_tools(cache_dir)
    output = _within_build_tools(output_dir)
    if output.exists():
        raise ValueError(f"refusing to overwrite existing stage: {output}")
    cache.mkdir(parents=True, exist_ok=True)
    manifest_path = cache / "cuda-redistrib-12.9.2.json"
    if manifest_path.exists():
        if manifest_path.is_symlink() or sha256_file(manifest_path) != lock["manifest"]["sha256"]:
            raise ValueError("cached CUDA manifest differs from its pinned hash")
        manifest_raw = manifest_path.read_bytes()
    elif offline:
        raise ValueError("offline staging requires the pinned CUDA redistribution manifest in the cache")
    else:
        _download(lock["manifest"]["url"], manifest_path, lock["manifest"]["sha256"],
                  lock["manifest"]["bytes"])
        manifest_raw = manifest_path.read_bytes()
    manifest_check = verify_against_manifest(lock, manifest_raw)

    package_rows = []
    for row in lock["components"]:
        archive_path = cache / PurePosixPath(row["path"]).name
        if not archive_path.exists():
            if offline:
                raise ValueError(f"offline staging is missing {archive_path.name}")
            _download("https://developer.download.nvidia.com/compute/cuda/redist/" + row["path"],
                      archive_path, row["sha256"], row["bytes"])
        if archive_path.is_symlink() or archive_path.stat().st_size != row["bytes"] or sha256_file(archive_path) != row["sha256"]:
            raise ValueError(f"cached package differs from official pin: {archive_path.name}")
        package_rows.append({"name": row["name"], "version": row["version"],
                             "archive": archive_path.name, "bytes": row["bytes"],
                             "sha256": row["sha256"]})

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cuda-toolchain-stage-", dir=output.parent) as temporary:
        scratch = Path(temporary)
        components_root = scratch / "components"
        components_root.mkdir()
        toolkit_root = scratch / "toolkit"
        for row in lock["components"]:
            archive_path = cache / PurePosixPath(row["path"]).name
            component = _safe_unpack(archive_path, components_root / row["name"])
            _overlay_component(component, toolkit_root)
        _ensure_target_layout(toolkit_root)
        required = ["bin/nvcc", "bin/cuobjdump", "bin/nvdisasm", "include/cuda_runtime.h",
                    "include/cublas_v2.h", "targets/x86_64-linux/lib/libcudadevrt.a",
                    "targets/x86_64-linux/lib/libcublas.so"]
        missing = [relative for relative in required if not (toolkit_root / relative).exists()]
        if missing:
            raise ValueError("staged toolkit is missing expected files: " + ", ".join(missing))
        output.mkdir()
        shutil.copytree(components_root, output / "components", symlinks=True)
        shutil.copytree(toolkit_root, output / "toolkit", symlinks=True)
    return {
        "schema": "nvdriver-cuda-toolchain-stage-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "local-user-space-toolchain-stage-only",
        "toolkit": lock["toolkit"], "release_label": lock["release_label"],
        "platform": lock["platform"], "license": lock["license"],
        "lock_sha256": sha256_file(lock_path), "manifest": manifest_check,
        "packages": package_rows,
        "toolkit_root": str((output / "toolkit").relative_to(ROOT)),
        "state": {"driver_package_included": False, "system_files_modified": False,
                  "package_manager_used_for_install": False, "gpu_accessed": False,
                  "binary_executed": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    try:
        report = stage(args.lock, args.cache_dir, args.output, args.offline)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.error(str(error))
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        if args.json_out.exists():
            parser.error(f"refusing to overwrite existing report: {args.json_out}")
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.json_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
