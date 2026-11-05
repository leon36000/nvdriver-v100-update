#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and inspect a CUDA architecture image without initializing a GPU."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


SOURCE = b'''#include <cuda_runtime.h>
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

__global__ void hybrid_header_smoke(float *out)
{
    const unsigned int i = threadIdx.x;
    if (i < 4)
        out[i] = rsqrtf(static_cast<float>(i + 1));
}

int main()
{
    std::vector<float> values(4);
    return values.size() == 4 ? 0 : 1;
}
'''


def _version(binary: str, timeout: float) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": [binary, "--version"], "error": str(error)}
    return {
        "command": [binary, "--version"],
        "exit_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def run_probe(
    nvcc: str,
    cuobjdump: str,
    host_cxx: str,
    architecture: str,
    timeout: float,
) -> dict[str, Any]:
    """Build a host executable and confirm its embedded cubin target."""
    report: dict[str, Any] = {
        "schema": "nvdriver-cuda-compiler-smoke-v1",
        "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "qualification": "compiler-and-image-inspection-only",
        "gpu_accessed": False,
        "binary_executed": False,
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "architecture": architecture,
        "source_sha256": hashlib.sha256(SOURCE).hexdigest(),
        "toolchain": {
            "nvcc": nvcc,
            "nvcc_version": _version(nvcc, timeout),
            "host_cxx": host_cxx,
            "host_cxx_version": _version(host_cxx, timeout),
            "cuobjdump": cuobjdump,
            "cuobjdump_version": _version(cuobjdump, timeout),
        },
    }

    with tempfile.TemporaryDirectory(prefix="nvdriver-cuda-smoke-") as temp_dir:
        root = Path(temp_dir)
        source = root / "smoke.cu"
        binary = root / "smoke"
        source.write_bytes(SOURCE)
        command = [
            nvcc,
            "-std=c++17",
            f"-arch={architecture}",
            "-U_GNU_SOURCE",
            "-Xcompiler",
            "-Wall,-Wextra,-Werror",
            "-ccbin",
            host_cxx,
            str(source),
            "-o",
            str(binary),
        ]
        try:
            compiled = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            report["compile"] = {
                "command": command,
                "exit_code": compiled.returncode,
                "stdout": compiled.stdout,
                "stderr": compiled.stderr,
                "artifact_created": binary.is_file(),
                "artifact_sha256": (
                    hashlib.sha256(binary.read_bytes()).hexdigest()
                    if binary.is_file()
                    else None
                ),
            }
        except (OSError, subprocess.TimeoutExpired) as error:
            report["compile"] = {
                "command": command,
                "error": str(error),
                "artifact_created": False,
                "artifact_sha256": None,
            }

        if binary.is_file() and report["compile"].get("exit_code") == 0:
            inspect_command = [cuobjdump, "--list-elf", str(binary)]
            try:
                inspected = subprocess.run(
                    inspect_command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                output = inspected.stdout + inspected.stderr
                architectures = sorted(set(re.findall(r"\b(sm_[A-Za-z0-9]+)\.cubin\b", output)))
                report["image_inspection"] = {
                    "command": inspect_command,
                    "exit_code": inspected.returncode,
                    "output": output,
                    "architectures": architectures,
                    "requested_architecture_present": architecture in architectures,
                }
            except (OSError, subprocess.TimeoutExpired) as error:
                report["image_inspection"] = {
                    "command": inspect_command,
                    "error": str(error),
                    "architectures": [],
                    "requested_architecture_present": False,
                }
        else:
            report["image_inspection"] = {
                "skipped": "compilation did not create a successful executable",
                "architectures": [],
                "requested_architecture_present": False,
            }

    compile_result = report["compile"]
    versions_ok = all(
        report["toolchain"][name].get("exit_code") == 0
        for name in ("nvcc_version", "host_cxx_version", "cuobjdump_version")
    )
    report["passed"] = bool(
        versions_ok
        and compile_result.get("exit_code") == 0
        and compile_result.get("artifact_created")
        and report["image_inspection"].get("exit_code") == 0
        and report["image_inspection"].get("requested_architecture_present")
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvcc", default="nvcc", help="NVCC executable")
    parser.add_argument("--cuobjdump", default=None, help="cuobjdump executable")
    parser.add_argument("--host-cxx", default="g++", help="Host C++ compiler")
    parser.add_argument("--arch", default="sm_120a", help="Cubin architecture to build")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-command timeout in seconds")
    parser.add_argument("--json-out", type=Path, help="Write a new JSON receipt (existing files are refused)")
    args = parser.parse_args()

    cuobjdump = args.cuobjdump or shutil.which("cuobjdump")
    if cuobjdump is None:
        report: dict[str, Any] = {
            "schema": "nvdriver-cuda-compiler-smoke-v1",
            "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "qualification": "compiler-and-image-inspection-only",
            "gpu_accessed": False,
            "binary_executed": False,
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
            "architecture": args.arch,
            "passed": False,
            "error": "cuobjdump was not found; pass --cuobjdump or add it to PATH",
        }
    else:
        report = run_probe(args.nvcc, cuobjdump, args.host_cxx, args.arch, args.timeout)

    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        try:
            with args.json_out.open("x", encoding="utf-8") as stream:
                stream.write(serialized)
        except FileExistsError:
            print(f"refusing to overwrite existing receipt: {args.json_out}", file=sys.stderr)
            return 2
    print(serialized, end="")
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
