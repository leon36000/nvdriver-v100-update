#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile a root-client bridge against actual R580 headers and link two RMs.

No real RM function is executed. Output remains ET_REL with host dependencies;
it is neither an installable module nor a claim of binary ABI/runtime validity.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from probe_rm_namespace_link import sha256, symbols

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
PAIR = ROOT / "build/experiments/same-branch-rm-link-v2/combined-rm.o"
PAIR_SHA = "74b89d249bac02c9d17ad24371dbd13fa06b9ea087dc13231e3a8e5349c31442"
NV_H_SHA = "bc5802ef5a0e47be045cac9b74e61a0092f0bb96fc1ede05e2361d164e3b7787"


def build(work, pair=PAIR, source=SOURCE):
    pair, source = pair.resolve(strict=True), source.resolve(strict=True)
    if sha256(pair) != PAIR_SHA or sha256(source / "kernel-open/common/inc/nv.h") != NV_H_SHA:
        raise ValueError("pinned R580 input mismatch")
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    tracked = [pair, Path(__file__).resolve(), ROOT / "tools/probe_rm_namespace_link.py"]
    tracked += [ROOT / "src" / name for name in
                ("rm_root_client.h", "rm_root_client.c", "rm_root_client_bindings.c", "rm_session_endpoint.h")]
    tracked += [source / name for name in
                ("kernel-open/common/inc/nv.h", "src/common/sdk/nvidia/inc/nvos.h",
                 "src/nvidia/arch/nvalloc/unix/include/nv_escape.h")]
    report = {
        "schema": "nvidia-hybrid-root-client-bridge-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "failed", "scope": "root-client-compile-and-relocatable-link-only",
        "source_version": "580.178.04", "input_sha256": {str(p): sha256(p) for p in tracked},
        "steps": [], "loaded_or_installed": False, "real_rm_executed": False,
        "binary_rm_abi_validated": False, "cuda_routing_implemented": False,
        "license_or_module_flavor_selected": False,
    }

    def run(name, command):
        log = work / (name + ".log")
        with log.open("x") as stream:
            try:
                code = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                      timeout=60, check=False).returncode
            except subprocess.TimeoutExpired:
                code = 124
        report["steps"].append({"name": name, "argv": command, "exit_code": code,
                                "log": str(log), "log_sha256": sha256(log)})
        if code:
            raise RuntimeError(f"{name}: exit {code}, see {log}")
        return log.read_text()

    try:
        run("compiler-version", ["cc", "--version"])
        run("linker-version", ["ld", "--version"])
        initial_strong, _, initial_undefined = symbols(run("pair-symbols", ["readelf", "-Ws", str(pair)]))
        required = {"rm_ioctl", "hybrid580_rm_ioctl"}
        if not required <= initial_strong:
            raise ValueError("two isolated rm_ioctl definitions are required")
        bridge_names = {"hybrid_root_alloc", "hybrid_root_alloc64", "hybrid_root_free", "hybrid_root_bind_r580",
                        "hybrid_root_alloc_session", "hybrid_root_alloc_session64"}
        if bridge_names & (initial_strong | initial_undefined):
            raise ValueError("bridge symbol already exists in RM pair")
        flags = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                 "-fno-stack-protector", "-fno-pic", "-fno-pie", "-DNVRM=1",
                 "-I" + str(ROOT / "src")]
        flags += ["-I" + str(source / part) for part in
                  ("kernel-open/common/inc", "src/common/sdk/nvidia/inc", "src/common/inc",
                   "src/common/inc/swref", "src/nvidia/arch/nvalloc/unix/include")]
        objects = []
        for stem in ("rm_root_client", "rm_root_client_bindings"):
            obj = work / (stem + ".o")
            run("compile-" + stem, ["cc", *flags, "-c", str(ROOT / "src" / (stem + ".c")), "-o", str(obj)])
            objects.append(obj)
        _, _, binding_undefined = symbols(run("binding-symbols", ["readelf", "-Ws", str(objects[1])]))
        if binding_undefined != required:
            raise ValueError(f"binding must reference both exact RM entries: {binding_undefined}")
        run("binding-relocations", ["readelf", "-rW", str(objects[1])])
        output = work / "root-client-dual-rm.o"
        run("relocatable-link", ["ld", "-r", "-o", str(output), str(pair), *map(str, objects)])
        final_strong, _, final_undefined = symbols(run("linked-symbols", ["readelf", "-Ws", str(output)]))
        if final_undefined != initial_undefined or final_strong != initial_strong | bridge_names:
            raise ValueError("unexpected dependency/definition changes during bridge linkage")
        report.update(qualification="compiled-and-relocatable-linked-only",
                      binding_targets=sorted(binding_undefined),
                      unresolved_symbol_count=len(final_undefined),
                      introduced_external_dependencies=[],
                      output={"path": str(output), "sha256": sha256(output), "bytes": output.stat().st_size})
    except (ValueError, RuntimeError, OSError) as exc:
        report["error"] = str(exc)
    report["inputs_unchanged"] = all(sha256(Path(p)) == value for p, value in report["input_sha256"].items())
    if not report["inputs_unchanged"]:
        report["qualification"] = "failed"
        report["error"] = "input changed during build"
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("report already exists; preserve previous evidence")
    report = build(args.work)
    with args.report.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report.get(key) for key in ("qualification", "unresolved_symbol_count", "error")}))
    return 0 if report["qualification"] == "compiled-and-relocatable-linked-only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
