#!/usr/bin/env python3
"""Verify a pinned llama.cpp CUDA build's configuration and embedded images.

This helper reads build metadata and runs cuobjdump only. It never executes the
llama binary, loads a CUDA driver, or accesses a GPU.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/inference/llama.cpp-cuda129-sm70v-sm120a.json"
SCHEMA_VERSION = 1


class VerificationError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file_identity(path: Path) -> dict[str, int | str]:
    """Hash and identify one stable regular file through the same descriptor."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise VerificationError("O_NOFOLLOW is required to identify runtime libraries")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise VerificationError(f"runtime dependency is not a regular file: {path.name}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise VerificationError(f"runtime dependency changed while being hashed: {path.name}")
        return {
            "size_bytes": before.st_size,
            "sha256": digest.hexdigest(),
            "device_major": os.major(before.st_dev),
            "device_minor": os.minor(before.st_dev),
            "inode": before.st_ino,
        }
    finally:
        os.close(descriptor)


def parse_cmake_cache(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith(("#", "//")):
            continue
        match = re.fullmatch(r"([^:=]+):[^=]+=([\s\S]*)", line)
        if not match:
            raise VerificationError(f"malformed CMakeCache entry at line {line_number}")
        key, value = match.groups()
        if key in values:
            raise VerificationError(f"duplicate CMakeCache key: {key}")
        values[key] = value
    return values


def count_image_entries(output: str, kind: str, architecture: str) -> int:
    if kind not in {"ELF", "PTX"}:
        raise ValueError("kind must be ELF or PTX")
    pattern = re.compile(rf"^{kind} file\s+\d+:\s+(.+?)\s*$", re.MULTILINE)
    return sum(1 for match in pattern.finditer(output) if architecture in match.group(1))


def matching_version_line(output: str, expected_fragment: str) -> str:
    expected = expected_fragment.casefold()
    return next(
        (line.strip() for line in output.splitlines() if expected in line.casefold()),
        "",
    )


def parse_needed_sonames(output: str) -> list[str]:
    """Return DT_NEEDED SONAMEs from GNU/LLVM readelf -d output."""
    names = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", output)
    if not names:
        raise VerificationError("ELF has no readable DT_NEEDED entries")
    if len(names) != len(set(names)):
        raise VerificationError("ELF contains duplicate DT_NEEDED entries")
    return sorted(names)


def run_checked(argv: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f"could not run {Path(argv[0]).name}: {error}") from error
    if result.returncode != 0:
        raise VerificationError(
            f"{Path(argv[0]).name} exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    return result.stdout + result.stderr


def _resolve_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve(strict=True)
    try:
        path.relative_to(root.resolve(strict=True))
    except ValueError as error:
        raise VerificationError(f"configured path escapes project root: {relative}") from error
    return path


def _resolve(root: Path, relative: str) -> Path:
    path = _resolve_path(root, relative)
    if not path.is_file():
        raise VerificationError(f"configured file is not regular: {relative}")
    return path


def _resolve_dir(root: Path, relative: str) -> Path:
    path = _resolve_path(root, relative)
    if not path.is_dir():
        raise VerificationError(f"configured path is not a directory: {relative}")
    return path


def _git(source: Path, *arguments: str) -> str:
    return run_checked(["git", "-C", str(source), *arguments]).strip()


def build_receipt(root: Path, config_path: Path) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError("unsupported profile schema")

    source = _resolve_dir(root, config["source"]["relative_path"])
    expected_commit = config["source"]["commit"]
    source_commit = _git(source, "rev-parse", "HEAD")
    if source_commit != expected_commit:
        raise VerificationError("llama.cpp source revision does not match the lock")
    if _git(source, "status", "--porcelain"):
        raise VerificationError("llama.cpp source tree is dirty")

    build_dir = _resolve_dir(root, config["build"]["relative_path"])
    cache_path = build_dir / "CMakeCache.txt"
    if not cache_path.is_file():
        raise VerificationError("CMakeCache.txt is missing")
    cache = parse_cmake_cache(cache_path)
    for key, expected in config["build"]["cmake_cache"].items():
        if cache.get(key) != expected:
            raise VerificationError(f"CMakeCache mismatch for {key}")

    compiler_versions = {}
    compiler_specs = config["build"]["toolchain"]["executables"]
    for name, spec in compiler_specs.items():
        configured_path = cache.get(spec["cmake_cache_key"])
        if not configured_path:
            raise VerificationError(f"CMakeCache is missing {spec['cmake_cache_key']}")
        executable = Path(configured_path)
        if not executable.is_absolute():
            executable = root / executable
        executable = executable.resolve(strict=True)
        try:
            executable.relative_to(root.resolve(strict=True))
        except ValueError as error:
            raise VerificationError(f"configured toolchain executable escapes project root: {name}") from error
        if not executable.is_file():
            raise VerificationError(f"configured toolchain executable is not regular: {name}")
        version_output = run_checked([str(executable), *spec["version_args"]])
        version_line = matching_version_line(version_output, spec["expected_fragment"])
        if not version_line:
            raise VerificationError(f"configured toolchain version mismatch for {name}")
        compiler_versions[name] = {
            "relative_path": str(executable.relative_to(root.resolve(strict=True))),
            "version_line": version_line,
            "expected_fragment_observed": spec["expected_fragment"],
            "sha256": sha256_file(executable),
        }

    toolkit_detail = cache.get("FIND_PACKAGE_MESSAGE_DETAILS_CUDAToolkit", "")
    expected_nvcc_version = compiler_specs["nvcc"]["expected_fragment"]
    if expected_nvcc_version.casefold() not in toolkit_detail.casefold():
        raise VerificationError("CMake did not report the locked CUDA toolkit compiler version")

    artifacts = []
    artifact_paths: dict[str, Path] = {}
    artifact_relative_paths: dict[str, str] = {}
    for expected in config["build"]["artifacts"]:
        path = _resolve(root, expected["relative_path"])
        actual_hash = sha256_file(path)
        if actual_hash != expected["sha256"]:
            raise VerificationError(f"SHA-256 mismatch for {expected['name']}")
        artifacts.append({
            "name": expected["name"],
            "relative_path": expected["relative_path"],
            "size_bytes": path.stat().st_size,
            "sha256": actual_hash,
        })
        artifact_paths[expected["name"]] = path
        artifact_relative_paths[expected["name"]] = expected["relative_path"]

    runtime_dependencies = []
    for expected in config["build"].get("runtime_dependencies", []):
        path = _resolve(root, expected["relative_path"])
        identity = regular_file_identity(path)
        if identity["sha256"] != expected["sha256"]:
            raise VerificationError(f"SHA-256 mismatch for runtime dependency {expected['name']}")
        runtime_dependencies.append({
            "name": expected["name"],
            "relative_path": expected["relative_path"],
            "resolved_path": str(path),
            **identity,
        })
        artifact_paths[expected["name"]] = path
        artifact_relative_paths[expected["name"]] = expected["relative_path"]

    elf_checks = []
    readelf_name = shutil.which("readelf")
    if config["build"].get("dynamic_dependency_checks"):
        if readelf_name is None:
            raise VerificationError("readelf is required for pinned dynamic-dependency checks")
        readelf = Path(readelf_name).resolve(strict=True)
        readelf_version = run_checked([str(readelf), "--version"])
        readelf_version_line = readelf_version.splitlines()[0].strip() if readelf_version.splitlines() else ""
        if not readelf_version_line:
            raise VerificationError("readelf returned no version information")
        for check in config["build"]["dynamic_dependency_checks"]:
            name = check["name"]
            path = artifact_paths.get(name)
            if path is None:
                raise VerificationError(f"dynamic-dependency check references an unlocked file: {name}")
            if check.get("relative_path") != artifact_relative_paths[name]:
                raise VerificationError(f"dynamic-dependency path disagrees with the file lock: {name}")
            output = run_checked([str(readelf), "-dW", str(path)])
            needed = parse_needed_sonames(output)
            required = check["required_needed"]
            if not isinstance(required, list) or not set(required).issubset(needed):
                raise VerificationError(f"required DT_NEEDED entries are absent from {name}")
            if not set(required).issubset({item["name"] for item in runtime_dependencies}):
                raise VerificationError(f"DT_NEEDED dependencies for {name} are not all hash-locked")
            elf_checks.append({"name": name, "relative_path": check.get("relative_path"),
                               "needed_sonames": needed, "required_needed": sorted(required)})
    else:
        readelf = None
        readelf_version_line = ""

    cuobjdump = _resolve(root, config["build"]["cuobjdump"]["relative_path"])
    cuobjdump_hash = sha256_file(cuobjdump)
    if cuobjdump_hash != config["build"]["cuobjdump"]["sha256"]:
        raise VerificationError("cuobjdump executable SHA-256 differs from the profile lock")
    cuobjdump_version = run_checked([str(cuobjdump), "--version"])
    cuobjdump_version_line = matching_version_line(
        cuobjdump_version,
        config["build"]["cuobjdump"]["version_expected_fragment"],
    )
    if not cuobjdump_version_line:
        raise VerificationError("cuobjdump version differs from the profile lock")
    elf_listing = run_checked([str(cuobjdump), "--list-elf", str(root / artifacts[1]["relative_path"])])
    ptx_listing = run_checked([str(cuobjdump), "--list-ptx", str(root / artifacts[1]["relative_path"])])
    sm120a_count = count_image_entries(elf_listing, "ELF", "sm_120a")
    sm70_count = count_image_entries(ptx_listing, "PTX", "sm_70")
    if sm120a_count < config["build"]["cuobjdump"]["sm120a_cubin_minimum_count"]:
        raise VerificationError("CUDA backend contains no required SM120a cubin")
    if sm70_count < config["build"]["cuobjdump"]["sm70_ptx_minimum_count"]:
        raise VerificationError("CUDA backend contains no required SM70 PTX image")

    smoke = config["cli_version_smoke"]
    smoke_log = _resolve(root, smoke["log_relative_path"])
    smoke_hash = sha256_file(smoke_log)
    if smoke_hash != smoke["log_sha256"]:
        raise VerificationError("CLI version log SHA-256 mismatch")
    smoke_text = smoke_log.read_text(encoding="utf-8")
    for required in (
        smoke["required_cuda_visible_devices_record"],
        smoke["required_exit_record"],
        smoke["required_commit_fragment"],
    ):
        if required not in smoke_text:
            raise VerificationError("CLI version smoke log is missing a required record")

    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "llama_cpp_cuda_artifact_inventory",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "profile_id": config["profile_id"],
        "verifier": {
            "relative_path": str(Path(__file__).resolve().relative_to(root.resolve(strict=True))),
            "sha256": sha256_file(Path(__file__).resolve()),
        },
        "proof_level": "COMPILED_AND_STATIC_IMAGES_INSPECTED",
        "source": {
            "repository": config["source"]["repository"],
            "commit": source_commit,
            "tree_clean": True,
        },
        "build": {
            "cmake_cache_sha256": sha256_file(cache_path),
            "cmake_settings": config["build"]["cmake_cache"],
            "toolchain_lock": {
                key: value for key, value in config["build"]["toolchain"].items()
                if key != "executables"
            },
            "toolchain_versions_observed": compiler_versions,
            "cmake_cuda_toolkit_detail": toolkit_detail,
            "artifacts": artifacts,
            "runtime_dependencies": runtime_dependencies,
            "dynamic_dependency_checks": elf_checks,
            "readelf": ({
                "relative_path": str(readelf),
                "sha256": sha256_file(readelf),
                "version_line": readelf_version_line,
            } if readelf is not None else None),
            "cuda_images": {"sm_70_ptx_count": sm70_count, "sm_120a_cubin_count": sm120a_count},
            "cuobjdump": {
                "relative_path": str(cuobjdump.relative_to(root.resolve(strict=True))),
                "sha256": cuobjdump_hash,
                "version_line": cuobjdump_version_line,
            },
        },
        "cli_version_smoke": {
            "log_sha256": smoke_hash,
            "cuda_visible_devices_empty": True,
            "exit_code": 0,
            "model_loaded": False,
            "inference_run": False,
        },
        "gpu_accessed_by_this_audit": False,
        "cuda_driver_runtime_validated": False,
        "same_process_v100_blackwell_validated": False,
        "p2p_enabled": False,
        "limitations": [
            "The tool inspects files and cuobjdump output; it does not execute the application or initialize CUDA.",
            "The CLI version smoke was recorded with CUDA_VISIBLE_DEVICES empty and is not inference validation.",
            "This CUDA 12.9.2 build is separate from the proposed pinned CUDA 12.8 profile.",
        ],
    }


def write_new_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, required=True, help="new receipt path; existing files are refused")
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        config_path = args.config if args.config.is_absolute() else root / args.config
        receipt = build_receipt(root, config_path.resolve(strict=True))
        output = args.output if args.output.is_absolute() else root / args.output
        write_new_json(output, receipt)
    except (OSError, json.JSONDecodeError, KeyError, VerificationError) as error:
        print(f"llama CUDA artifact verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "verified", "receipt": str(output), "proof_level": receipt["proof_level"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
