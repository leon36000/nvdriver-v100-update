#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a CUDA 12.9 SM70-PTX + SM120a-cubin Driver API probe.

The output is a local test artifact below build/ and is not a driver install.
This tool compiles and inspects images; it never runs the generated probe or
initializes a CUDA device.
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
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CUDA_ROOT = ROOT / "build/tools/cuda-12.9.2-toolchain-v2/toolkit"
DEFAULT_HOST_CXX = ROOT / "build/tools/host-gcc14/usr/bin/g++-14"
DEFAULT_OUTPUT = ROOT / "build/probe-cuda129-sm70v-sm120a-v2"
DEFAULT_STAGE_RECEIPT = ROOT / "evidence/cuda-toolchain-stage-v2-20261102.json"
COMPAT_HEADER = ROOT / "tools/cuda_host_compat/gcc14_glibc243_cuda129.h"
KERNEL_SOURCE = ROOT / "kernels/hybrid_probe.cu"
HOST_SOURCE = ROOT / "src/hybrid_cuda_probe.cpp"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_under_build(path: Path) -> Path:
    build = (ROOT / "build").resolve(strict=True)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("output directory may not be a symlink")
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(build)
    except ValueError:
        raise ValueError("output directory must remain below build/") from None
    return candidate


def run(command: list[str], *, cwd: Path = ROOT) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)
    row = {"argv": command, "exit_code": completed.returncode,
           "stdout": completed.stdout, "stderr": completed.stderr}
    if completed.returncode:
        raise RuntimeError(
            f"command exited {completed.returncode}: {' '.join(command)}\n"
            f"{completed.stdout}{completed.stderr}"
        )
    return row


def parse_image_inventory(elf_listing: str, ptx_listing: str) -> dict[str, Any]:
    cubins = re.findall(r"\b[A-Za-z0-9_.-]+\.sm_([0-9]+[a-z]*)\.cubin\b", elf_listing)
    ptx = re.findall(r"\b[A-Za-z0-9_.-]+\.sm_([0-9]+[a-z]*)\.ptx\b", ptx_listing)
    if "120a" not in cubins or "70" not in ptx:
        raise ValueError("fatbin must contain an SM120a cubin and SM70 PTX image")
    return {
        "cubins": sorted(set(cubins)),
        "ptx": sorted(set(ptx)),
        "sm120a_cubin_count": cubins.count("120a"),
        "sm70_ptx_count": ptx.count("70"),
    }


def reject_direct_libcuda_link(dynamic_tags: str) -> None:
    if any("NEEDED" in line and re.search(r"libcuda\.so", line)
           for line in dynamic_tags.splitlines()):
        raise ValueError("probe must resolve the Driver API dynamically, not link libcuda")


def validate_stage_receipt(stage_data: Any) -> None:
    state = stage_data.get("state") if isinstance(stage_data, dict) else None
    if (not isinstance(stage_data, dict) or
            stage_data.get("schema") != "nvdriver-cuda-toolchain-stage-v1" or
            stage_data.get("toolkit") != "12.9.2" or
            stage_data.get("qualification") != "local-user-space-toolchain-stage-only" or
            not isinstance(state, dict) or
            state.get("driver_package_included") is not False or
            state.get("system_files_modified") is not False or
            state.get("gpu_accessed") is not False or
            state.get("binary_executed") is not False):
        raise ValueError("CUDA toolkit stage receipt is not a valid no-driver local stage")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cuda-root", type=Path, default=DEFAULT_CUDA_ROOT)
    parser.add_argument("--host-cxx", type=Path, default=DEFAULT_HOST_CXX)
    parser.add_argument("--stage-receipt", type=Path, default=DEFAULT_STAGE_RECEIPT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    cuda_root = args.cuda_root.resolve(strict=True)
    host_cxx = args.host_cxx.resolve(strict=True)
    stage_receipt = args.stage_receipt.resolve(strict=True)
    output = require_under_build(args.output_dir)
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    for path in (KERNEL_SOURCE, HOST_SOURCE, COMPAT_HEADER,
                 cuda_root / "bin/nvcc", cuda_root / "bin/cuobjdump",
                 cuda_root / "include/cuda.h"):
        if not path.is_file():
            raise SystemExit(f"required input is missing: {path}")
    stage_data = json.loads(stage_receipt.read_text(encoding="utf-8"))
    validate_stage_receipt(stage_data)

    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    commands: list[dict[str, Any]] = []
    try:
        nvcc = str(cuda_root / "bin/nvcc")
        cuobjdump = str(cuda_root / "bin/cuobjdump")
        cxx = str(host_cxx)
        module = temp / "hybrid_probe.sm70-ptx_sm120a-cubin.fatbin"
        probe = temp / "hybrid_cuda_probe"
        commands.append(run([nvcc, "--version"]))
        commands.append(run([cxx, "--version"]))
        commands.append(run([cuobjdump, "--version"]))
        commands.append(run([
            nvcc, "--std=c++17", "--fatbin", "-U_GNU_SOURCE",
            "-D_POSIX_C_SOURCE=200809L", "-include", str(COMPAT_HEADER),
            "-ccbin", cxx,
            "--generate-code=arch=compute_70,code=compute_70",
            "--generate-code=arch=compute_120a,code=sm_120a",
            str(KERNEL_SOURCE), "-o", str(module),
        ]))
        elf_listing = run([cuobjdump, "--list-elf", str(module)])
        ptx_listing = run([cuobjdump, "--list-ptx", str(module)])
        images = parse_image_inventory(elf_listing["stdout"], ptx_listing["stdout"])
        commands.extend((elf_listing, ptx_listing))
        commands.append(run([
            cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic",
            "-Werror", "-I", str(cuda_root / "include"), str(HOST_SOURCE),
            "-pthread", "-ldl", "-o", str(probe),
        ]))
        dynamic = run(["readelf", "-dW", str(probe)])
        reject_direct_libcuda_link(dynamic["stdout"])
        commands.append(dynamic)
        manifest = {
            "schema": "nvidia-hybrid-probe-build-v2",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "built-static-images",
            "toolkit_stage_receipt_sha256": sha256(stage_receipt),
            "cuda_toolkit_root": str(cuda_root),
            "host_compiler": cxx,
            "source_inputs_sha256": {
                str(HOST_SOURCE.resolve()): sha256(HOST_SOURCE),
                str(KERNEL_SOURCE.resolve()): sha256(KERNEL_SOURCE),
            },
            "build_tool_sha256": sha256(Path(__file__).resolve()),
            "tool_inputs_sha256": {
                str(Path(nvcc).resolve()): sha256(Path(nvcc).resolve()),
                str(Path(cuobjdump).resolve()): sha256(Path(cuobjdump).resolve()),
                str(host_cxx): sha256(host_cxx),
                str((cuda_root / "include/cuda.h").resolve()): sha256(cuda_root / "include/cuda.h"),
            },
            "commands": commands,
            "images": images,
            "fatbin_images": ["sm_70", "sm_120a"],
            "fatbin_image_kinds": {"sm_70": "ptx", "sm_120a": "cubin"},
            "fatbin": {
                "path": str((output / module.name).resolve()),
                "sha256": sha256(module),
            },
            "probe": {
                "path": str((output / probe.name).resolve()),
                "sha256": sha256(probe),
            },
            "probe_directly_links_libcuda": False,
        }
        (temp / "build-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temp / "build-manifest.json", 0o644)
        output.parent.mkdir(parents=True, exist_ok=True)
        os.rename(temp, output)
        print(json.dumps(manifest, sort_keys=True))
        return 0
    except BaseException:
        shutil.rmtree(temp, ignore_errors=True)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        raise SystemExit(str(error))
