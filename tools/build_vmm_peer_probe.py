#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a standalone VMM peer-memory probe against the pinned SM70/SM120 fatbin."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parent
CUDA13 = Path(os.environ.get(
    "CUDA13_ROOT", PROJECT / "tools/cuda13.1-front/usr/local/cuda-13.1")).resolve()
if not (CUDA13 / "version.json").is_file() and "CUDA13_ROOT" not in os.environ:
    CUDA13 = Path("/usr/local/cuda-13.1")
SOURCE = ROOT / "src/hybrid_cuda_vmm_peer_probe.cpp"
FATBIN = ROOT / "build/probe-peer-transfer-v3-20261031/hybrid_probe.sm70-sm120.fatbin"
EXPECTED_FATBIN_SHA256 = "9b6c772590c0e7ce6a95e36fb637b769eceef69856979761d739028d8b45675f"
DEFAULT_OUTPUT = ROOT / "build/vmm-peer-probe-v3-20261031"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str]) -> str:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError(f"command exited {result.returncode}: {' '.join(command)}\n{result.stdout}")
    return result.stdout


def main() -> int:
    output = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT
    if len(sys.argv) > 2:
        raise SystemExit("usage: build_vmm_peer_probe.py [OUTPUT_DIR]")
    if not SOURCE.is_file() or not FATBIN.is_file():
        raise SystemExit("pinned source or v3 fatbin is absent")
    fatbin_hash = sha256(FATBIN)
    if fatbin_hash != EXPECTED_FATBIN_SHA256:
        raise SystemExit(f"pinned SM70/SM120 fatbin hash mismatch: {fatbin_hash}")
    for required in (CUDA13 / "include/cuda.h", CUDA13 / "bin/cuobjdump"):
        if not required.is_file():
            raise SystemExit(f"required CUDA 13.1 input is absent: {required}")
    output.mkdir(parents=True, exist_ok=True)
    compiler_name = os.environ.get("CXX", "c++")
    compiler = Path(shutil.which(compiler_name) or compiler_name).resolve(strict=True)
    binary = output / "hybrid_cuda_vmm_peer_probe"
    command = [str(compiler), "-std=c++17", "-O2", "-Wall", "-Wextra",
               "-Wpedantic", "-Werror", "-I", str(CUDA13 / "include"),
               str(SOURCE), "-ldl", "-o", str(binary)]
    run(command)
    dynamic = run(["readelf", "-dW", str(binary)])
    if any("NEEDED" in line and "libcuda.so" in line for line in dynamic.splitlines()):
        raise RuntimeError("probe must resolve libcuda dynamically and must not link to it")
    image_listing = run([str(CUDA13 / "bin/cuobjdump"), "-lelf", str(FATBIN)])
    if "sm_70.cubin" not in image_listing or "sm_120.cubin" not in image_listing:
        raise RuntimeError("pinned peer-read fatbin is missing SM70 or SM120")
    manifest = {
        "schema": "nvidia-hybrid-vmm-peer-probe-build-v1",
        "qualification": "compiled-only-no-hardware-validation",
        "source": {"path": str(SOURCE), "sha256": sha256(SOURCE)},
        "binary": {"path": str(binary), "sha256": sha256(binary)},
        "fatbin": {"path": str(FATBIN), "sha256": fatbin_hash,
                   "images": ["sm_70", "sm_120"]},
        "cuda_header": {"path": str(CUDA13 / "include/cuda.h"),
                        "sha256": sha256(CUDA13 / "include/cuda.h")},
        "compiler": {"path": str(compiler), "sha256": sha256(compiler)},
        "command": command,
        "links_libcuda_directly": False,
        "mode": "explicit-vmm-access-no-cuCtxEnablePeerAccess",
    }
    (output / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
