#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the isolated SM70 + SM120 Driver API probe using existing local tools."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
CUDA13 = Path(os.environ.get("CUDA13_ROOT", PROJECT / "tools/cuda13.1-front/usr/local/cuda-13.1")).resolve()
if not (CUDA13 / "version.json").is_file() and "CUDA13_ROOT" not in os.environ:
    CUDA13 = Path("/usr/local/cuda-13.1")
VOLTA_COMPILER = PROJECT / "bin/volta13"
CLANG = PROJECT / "tools/clang23-local/usr/lib/llvm-23/bin/clang++"
CLANG_ROOT = PROJECT / "tools/clang23-local/usr"
OUTPUT = ROOT / "build/probe-libcuda-override-v12-20261101"
COMMANDS = []


def run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        check=False,
    )
    COMMANDS.append({"argv": command, "exit_code": completed.returncode})
    if completed.returncode:
        raise RuntimeError(
            f"command exited {completed.returncode}: {' '.join(command)}\n{completed.stdout}"
        )
    return completed.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT)
    parser.add_argument("--kernel-source", type=Path,
                        default=ROOT / "kernels/hybrid_probe.cu")
    parser.add_argument("--host-source", type=Path,
                        default=ROOT / "src/hybrid_cuda_probe.cpp")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = args.kernel_source.resolve(strict=True)
    host_source = args.host_source.resolve(strict=True)
    if not source.is_file() or not host_source.is_file():
        raise SystemExit("probe source inputs must be regular files")
    for required in (
        VOLTA_COMPILER,
        CLANG,
        CUDA13 / "bin/ptxas",
        CUDA13 / "bin/fatbinary",
        CUDA13 / "bin/cuobjdump",
        CUDA13 / "include/cuda.h",
    ):
        if not required.exists():
            raise SystemExit(f"required existing tool is absent: {required}")

    source_inputs = {str(path): sha256(path) for path in (source, host_source)}
    sm70 = output / "hybrid_probe.sm70.cubin"
    ptx70 = output / "hybrid_probe.sm70.ptx"
    sm120 = output / "hybrid_probe.sm120.cubin"
    ptx120 = output / "hybrid_probe.sm120.ptx"
    fatbin = output / "hybrid_probe.sm70-sm120.fatbin"

    run([str(VOLTA_COMPILER), str(source), "-o", str(sm70), "--ptx-out", str(ptx70),
         "--cuda-path", str(CUDA13)])

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = ":".join(
        str(path) for path in (
            CLANG_ROOT / "lib/llvm-23/lib",
            CLANG_ROOT / "lib/x86_64-linux-gnu",
            CLANG_ROOT / "lib",
        )
    )
    cccl = CUDA13 / "targets/x86_64-linux/include/cccl"
    run([str(CLANG), "-x", "cuda", "--cuda-device-only",
         f"--cuda-path={CUDA13}", "--cuda-gpu-arch=sm_120", "-isystem", str(cccl),
         "-S", str(source), "-o", str(ptx120)], env=env)
    ptx = ptx120.read_text(errors="replace")
    if ".target sm_120" not in ptx:
        raise SystemExit("Clang output is not an SM120 PTX image")
    run([str(CUDA13 / "bin/ptxas"), "-arch=sm_120", str(ptx120), "-o", str(sm120)])

    if fatbin.exists():
        fatbin.unlink()
    run([str(CUDA13 / "bin/fatbinary"), "--64", f"--create={fatbin}",
         f"--image3=kind=elf,sm=70,file={sm70}",
         f"--image3=kind=elf,sm=120,file={sm120}"])
    listing = run([str(CUDA13 / "bin/cuobjdump"), "-lelf", str(fatbin)])
    if "sm_70.cubin" not in listing or "sm_120.cubin" not in listing:
        raise SystemExit("fatbin is missing one of the required cubin images\n" + listing)

    compiler = os.environ.get("CXX", "c++")
    probe = output / "hybrid_cuda_probe"
    run([compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic",
         "-I", str(CUDA13 / "include"), str(host_source),
         "-pthread", "-ldl", "-o", str(probe)])
    dynamic_tags = run(["readelf", "-dW", str(probe)])
    links_libcuda = any("NEEDED" in line and "libcuda.so" in line
                        for line in dynamic_tags.splitlines())
    if links_libcuda:
        raise RuntimeError("host probe unexpectedly links libcuda directly")
    if source_inputs != {path: sha256(Path(path)) for path in source_inputs}:
        raise RuntimeError("probe source changed during the build")
    host_compiler = Path(shutil.which(compiler) or compiler).resolve(strict=True)

    manifest = {
        "schema": "nvidia-hybrid-probe-build-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "built-static-images",
        "source_inputs_sha256": source_inputs,
        "build_tool_sha256": sha256(Path(__file__)),
        "tool_inputs_sha256": {str(path): sha256(path) for path in
                               (VOLTA_COMPILER, CLANG, host_compiler,
                                CUDA13 / "bin/ptxas", CUDA13 / "bin/fatbinary",
                                CUDA13 / "bin/cuobjdump", CUDA13 / "include/cuda.h")},
        "commands": COMMANDS,
        "sm120_compiler_library_path": env["LD_LIBRARY_PATH"],
        "cuda_toolkit": str(CUDA13),
        "sm70_cubin": {"path": str(sm70), "sha256": sha256(sm70)},
        "sm120_cubin": {"path": str(sm120), "sha256": sha256(sm120)},
        "fatbin": {"path": str(fatbin), "sha256": sha256(fatbin)},
        "fatbin_images": ["sm_70", "sm_120"],
        "probe": {"path": str(probe), "sha256": sha256(probe)},
        "probe_links_libcuda": links_libcuda,
    }
    (output / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
