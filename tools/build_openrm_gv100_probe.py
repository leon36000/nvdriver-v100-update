#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the opt-in GV100 firmware-policy experiment from pinned full sources.

This compiles only. It never installs, loads, signs, or rebinds a module.
The patch deliberately leaves the missing GV100 HAL registration unresolved.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "ac24e02fc090c3e05c1fc03384b317ac2cc301b5"
ARCHIVE_SHA256 = "da4e454d493818027998fc9d7ef95fd5dd291d3d37119f1f81d12db85fc33190"
PATCH = ROOT / "patches/r595.104.02/0001-gv100-monolithic-firmware-policy.patch"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path, help="new directory; existing paths refused")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log_dir = ROOT / "evidence/logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    report_path = ROOT / "evidence" / f"openrm-gv100-firmware-probe-{stamp}.json"
    report = {"schema": "openrm-gv100-firmware-probe-v1", "source_tag": "595.104.02",
              "source_commit": COMMIT, "steps": [], "artifacts": [],
              "loaded_or_installed": False, "hardware_validated": False,
              "gv100_hal_registered": False, "uvm_volta_dispatch_integrated": False}

    def run_step(name, command, cwd, env=None):
        log = log_dir / f"openrm-gv100-{name}-{stamp}.log"
        start = time.monotonic()
        with log.open("x") as stream:
            try:
                result = subprocess.run(command, cwd=cwd, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, check=False, timeout=600)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        report["steps"].append({"name": name, "command": command, "cwd": str(cwd),
                                "exit_code": code, "duration_seconds": round(time.monotonic() - start, 3),
                                "log": str(log), "log_sha256": sha256(log)})
        if code:
            raise RuntimeError(f"{name} failed with exit {code}; see {log}")

    try:
        archive = args.source_archive.resolve(strict=True)
        if sha256(archive) != ARCHIVE_SHA256:
            raise ValueError("full R595 source archive does not match the pinned SHA-256")
        work = args.work_dir.resolve()
        if work.exists():
            raise FileExistsError(f"refusing to overwrite {work}")
        source_name = "open-gpu-kernel-modules-" + COMMIT
        with tarfile.open(archive) as tar:
            if any(member.name.split("/", 1)[0] != source_name for member in tar.getmembers()):
                raise ValueError("unexpected source archive root")
            work.mkdir(parents=True, exist_ok=False)
            tar.extractall(work, filter="data")
        source = work / source_name
        report.update(source=str(source), source_archive=str(archive),
                      archive_sha256=ARCHIVE_SHA256, patch=str(PATCH), patch_sha256=sha256(PATCH))
        env = os.environ.copy()
        env["OPENRM_SOURCE"] = str(source)
        run_step("policy-contract", [sys.executable, "-m", "unittest", "discover", "-s", "tests",
                                     "-p", "test_openrm_firmware_policy.py", "-v"], ROOT, env)
        run_step("patch", ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)], source)
        report["patched_osinit_sha256"] = sha256(source / "src/nvidia/arch/nvalloc/unix/src/osinit.c")
        run_step("modules", ["make", "modules", f"-j{args.jobs}",
                              "NV_KERNEL_MODULES=nvidia nvidia-uvm",
                              "EXTRA_CFLAGS=-DNV_HYBRID_EXPERIMENTAL_GV100"], source)
        for relative in ("src/nvidia/_out/Linux_x86_64/nv-kernel.o",
                         "kernel-open/nvidia.ko", "kernel-open/nvidia-uvm.ko"):
            path = source / relative
            if not path.is_file():
                raise RuntimeError(f"build reported success but artifact is missing: {relative}")
            artifact = {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
            if path.suffix == ".ko":
                info = subprocess.run(["modinfo", str(path)], capture_output=True, text=True, check=False)
                artifact["modinfo_exit_code"] = info.returncode
                artifact["modinfo"] = info.stdout
                if info.returncode:
                    raise RuntimeError(f"invalid module artifact: {path}")
            report["artifacts"].append(artifact)
        report["status"] = "compiled-experimental-firmware-route"
        code = 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        report.update(status="failed", error=str(error))
        code = 2
    report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
    with report_path.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(report_path), **report}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
