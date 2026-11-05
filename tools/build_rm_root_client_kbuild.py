#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile bridge objects with actual Kbuild flags, without making a module.

Requires the separately built official Open R580 wrapper for its generated
conftest headers. Does not alter that wrapper, link either RM, or execute RM.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess

from probe_rm_namespace_link import sha256

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "build/experiments/open580-wrapper-baseline-v1/NVIDIA-kernel-module-source-580.178.04"


def build(work, source=BASE, release=None):
    source = source.resolve(strict=True)
    release = release or os.uname().release
    kernel = (Path("/lib/modules") / release / "build").resolve(strict=True)
    conftest = source / "kernel-open/conftest"
    if release not in (conftest / "headers.h").read_text():
        raise ValueError("conftest kernel release mismatch")
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    inputs = [ROOT / "src" / name for name in
              ("rm_root_client.c", "rm_root_client.h", "rm_root_client_bindings.c", "rm_session_endpoint.h")]
    inputs += [Path(__file__).resolve(), kernel / ".config", kernel / "Module.symvers"]
    inputs += sorted(conftest.glob("*.h"))
    report = {"schema": "nvidia-hybrid-root-client-kbuild-v1",
              "observed_at_utc": datetime.now(timezone.utc).isoformat(),
              "qualification": "failed", "kernel_release": release,
              "input_sha256": {str(p): sha256(p) for p in inputs}, "steps": [],
              "loaded_or_installed": False, "module_produced": False,
              "rm_objects_linked": False, "real_rm_executed": False,
              "binary_rm_abi_validated": False, "wrapper_sources_modified": False}
    for p in inputs[:4]:
        shutil.copyfile(p, work / p.name)
    includes = [source / part for part in
                ("kernel-open/common/inc", "kernel-open", "src/common/sdk/nvidia/inc",
                 "src/common/inc", "src/common/inc/swref", "src/nvidia/arch/nvalloc/unix/include")]
    (work / "Kbuild").write_text(
        "obj-m += rm_root_client.o rm_root_client_bindings.o\n"
        "ccflags-y += -DNVRM -DNV_KERNEL_INTERFACE_LAYER -DNV_UVM_ENABLE "
        "-ffreestanding -fno-strict-aliasing -Werror\nccflags-y += " +
        " ".join("-I" + str(p) for p in includes) + "\n")
    report["generated_kbuild_sha256"] = sha256(work / "Kbuild")
    compiler = shutil.which("x86_64-linux-gnu-gcc")
    command = ["make", "-C", str(kernel), "M=" + str(work)]
    if compiler:
        command.append("CC=" + compiler)
    command += ["rm_root_client.o", "rm_root_client_bindings.o"]
    log = work / "build.log"
    with log.open("x") as stream:
        try:
            code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                  timeout=60, check=False).returncode
        except subprocess.TimeoutExpired:
            code = 124
    report["steps"].append({"argv": command, "exit_code": code,
                            "log": str(log), "log_sha256": sha256(log)})
    outputs = []
    if code == 0:
        for name in ("rm_root_client", "rm_root_client_bindings"):
            obj = work / (name + ".o")
            record = {"path": str(obj), "sha256": sha256(obj), "bytes": obj.stat().st_size}
            for flag, suffix in (("-h", "elf-header"), ("-Ws", "symbols")):
                result = subprocess.run(["readelf", flag, str(obj)], capture_output=True,
                                        text=True, timeout=15, check=True)
                target = work / (name + "-" + suffix + ".log")
                target.write_text(result.stdout)
                record[suffix] = {"path": str(target), "sha256": sha256(target)}
            record["kbuild_command"] = {"path": str(work / ("." + name + ".o.cmd")),
                                       "sha256": sha256(work / ("." + name + ".o.cmd"))}
            outputs.append(record)
        report["qualification"] = "compiled-kbuild-objects-only"
    else:
        report["error"] = f"Kbuild exited {code}; see {log}"
    report["outputs"] = outputs
    report["inputs_unchanged"] = all(sha256(Path(p)) == h for p, h in report["input_sha256"].items())
    if not report["inputs_unchanged"]:
        report.update(qualification="failed", error="input changed during build")
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("report already exists")
    report = build(args.work)
    with args.report.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report.get(k) for k in ("qualification", "error")}))
    return 0 if report["qualification"] == "compiled-kbuild-objects-only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
