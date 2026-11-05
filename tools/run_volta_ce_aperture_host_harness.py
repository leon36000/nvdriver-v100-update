#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute the pinned R580 and adapted Volta C3B5 aperture helpers.

This host-CPU harness verifies generated-field encodings and fail-closed
assertions. It does not submit commands to a copy engine or validate GPU I/O.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_mmu_adapter_contract import extract_function, sha256_file  # noqa: E402
from tools.audit_r595_uvm_hal_table_closure import parse_hal_class_tables  # noqa: E402
from tools.probe_r595_gv100_complete_hal import (  # noqa: E402
    DEFAULT_R580_ARCHIVE,
    read_member_from_archive,
)


HARNESS_PREFIX = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nvtypes.h"
#include "nvmisc.h"
#include "clb0b5.h"
#include "clc3b5.h"

typedef enum {
    UVM_APERTURE_SYS,
    UVM_APERTURE_SYS_NON_COHERENT,
    UVM_APERTURE_VID,
    UVM_APERTURE_PEER_0
} uvm_aperture_t;

#define HWCONST(d, r, f, c) DRF_DEF(d, _ ## r, _ ## f, _ ## c)
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "C3B5 field mismatch")
#define UVM_ASSERT_MSG(condition, ...) do { \
    if (!(condition)) { \
        fprintf(stderr, "UVM_ASSERT_MSG failed: %s\n", #condition); \
        abort(); \
    } \
} while (0)
'''


def _function(name: str, body: str) -> str:
    return f"static NvU32 {name}(uvm_aperture_t aperture)\n{{{body}\n}}\n"


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for evidence output")
    descriptor = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(descriptor)


def run(r580_archive: Path, candidate_volta_ce: Path, candidate_maxwell_ce: Path,
        candidate_uvm: Path,
        report_path: Path, log_path: Path, compiler: str = "cc") -> dict:
    r580_archive = r580_archive.resolve(strict=True)
    candidate_volta_ce = candidate_volta_ce.resolve(strict=True)
    candidate_maxwell_ce = candidate_maxwell_ce.resolve(strict=True)
    candidate_uvm = candidate_uvm.resolve(strict=True)
    common_inc = (candidate_uvm.parent / "common/inc").resolve(strict=True)
    if report_path.exists() or log_path.exists():
        raise FileExistsError("refusing to overwrite host-harness evidence")
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise ValueError(f"compiler not found: {compiler}")
    version = subprocess.run([compiler_path, "--version"], capture_output=True,
                             text=True, check=True)

    r580_ce = read_member_from_archive(
        r580_archive, "kernel-open/nvidia-uvm/uvm_volta_ce.c")
    r580_header = read_member_from_archive(
        r580_archive, "kernel-open/nvidia-uvm/clc3b5.h")
    r580_maxwell_ce = read_member_from_archive(
        r580_archive, "kernel-open/nvidia-uvm/uvm_maxwell_ce.c")
    r580_b0b5_header = read_member_from_archive(
        r580_archive, "kernel-open/nvidia-uvm/clb0b5.h")
    candidate_c3b5_path = candidate_uvm / "clc3b5.h"
    candidate_b0b5_path = candidate_uvm / "clb0b5.h"
    candidate_c3b5 = candidate_c3b5_path.read_text(encoding="utf-8")
    candidate_b0b5 = candidate_b0b5_path.read_text(encoding="utf-8")
    if r580_header != candidate_c3b5:
        raise ValueError("pinned R580 and candidate C3B5 headers are not byte-identical")
    if r580_b0b5_header != candidate_b0b5:
        raise ValueError("pinned R580 and candidate B0B5 headers are not byte-identical")

    candidate_volta_source = candidate_volta_ce.read_text(encoding="utf-8")
    candidate_maxwell_source = candidate_maxwell_ce.read_text(encoding="utf-8")
    functions = (
        _function("legacy_volta_ce_aperture", extract_function(r580_ce, "ce_aperture")),
        _function("candidate_volta_ce_aperture",
                  extract_function(candidate_volta_source, "ce_aperture")),
        _function("legacy_maxwell_ce_aperture",
                  extract_function(r580_maxwell_ce, "ce_aperture")),
        _function("candidate_maxwell_ce_aperture",
                  extract_function(candidate_maxwell_source, "ce_aperture")),
    )
    hal_source = (candidate_uvm / "uvm_hal.c").read_text(encoding="utf-8")
    ce_rows = parse_hal_class_tables(hal_source)["ce_table"]
    volta_rows = [row for row in ce_rows if row["id"] == "VOLTA_DMA_COPY_A"]
    if (len(volta_rows) != 1 or
            volta_rows[0]["assignments"].get("phys_mode") != "uvm_hal_maxwell_ce_phys_mode"):
        raise ValueError("candidate VOLTA_DMA_COPY_A no longer dispatches memcopies to Maxwell phys_mode")

    harness = HARNESS_PREFIX + "\n".join(functions) + r'''

static int check(const char *name, NvU32 actual, NvU32 expected)
{
    printf("%s actual=%u expected=%u\n", name, actual, expected);
    return actual == expected ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--probe-legacy-volta-noncoherent") == 0)
        return (int)legacy_volta_ce_aperture(UVM_APERTURE_SYS_NON_COHERENT);
    if (argc == 2 && strcmp(argv[1], "--probe-candidate-volta-invalid") == 0)
        return (int)candidate_volta_ce_aperture(UVM_APERTURE_PEER_0);
    if (argc == 2 && strcmp(argv[1], "--probe-legacy-maxwell-noncoherent") == 0)
        return (int)legacy_maxwell_ce_aperture(UVM_APERTURE_SYS_NON_COHERENT);
    if (argc == 2 && strcmp(argv[1], "--probe-candidate-maxwell-invalid") == 0)
        return (int)candidate_maxwell_ce_aperture(UVM_APERTURE_PEER_0);

    int failures = 0;
    failures += check("legacy-volta-system-coherent",
        legacy_volta_ce_aperture(UVM_APERTURE_SYS), 1);
    failures += check("candidate-volta-system-coherent",
        candidate_volta_ce_aperture(UVM_APERTURE_SYS), 1);
    failures += check("legacy-maxwell-system-coherent",
        legacy_maxwell_ce_aperture(UVM_APERTURE_SYS), 1);
    failures += check("candidate-maxwell-system-coherent",
        candidate_maxwell_ce_aperture(UVM_APERTURE_SYS), 1);
    failures += check("legacy-volta-video-memory",
        legacy_volta_ce_aperture(UVM_APERTURE_VID), 0);
    failures += check("candidate-volta-video-memory",
        candidate_volta_ce_aperture(UVM_APERTURE_VID), 0);
    failures += check("legacy-maxwell-video-memory",
        legacy_maxwell_ce_aperture(UVM_APERTURE_VID), 0);
    failures += check("candidate-maxwell-video-memory",
        candidate_maxwell_ce_aperture(UVM_APERTURE_VID), 0);
    failures += check("candidate-volta-system-noncoherent",
        candidate_volta_ce_aperture(UVM_APERTURE_SYS_NON_COHERENT), 2);
    failures += check("candidate-maxwell-system-noncoherent",
        candidate_maxwell_ce_aperture(UVM_APERTURE_SYS_NON_COHERENT), 2);
    return failures ? 1 : 0;
}
'''
    harness_bytes = harness.encode("utf-8")

    logs = []
    with tempfile.TemporaryDirectory(prefix="volta-ce-host-harness-") as directory:
        temporary = Path(directory)
        c_path = temporary / "volta_ce_host_harness.c"
        binary = temporary / "volta_ce_host_harness"
        c_path.write_bytes(harness_bytes)
        command = [compiler_path, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-I", str(common_inc), "-I", str(candidate_uvm), str(c_path), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True)
        logs.append("$ " + shlex.join(command) + "\n" + compiled.stdout + compiled.stderr)
        if compiled.returncode != 0:
            raise RuntimeError("CE host harness compilation failed; see log: " + "".join(logs))

        executed = subprocess.run([str(binary)], capture_output=True, text=True)
        logs.append("$ " + shlex.quote(str(binary)) + "\n" + executed.stdout + executed.stderr)
        if executed.returncode != 0:
            raise RuntimeError("CE aperture vectors failed; see log: " + "".join(logs))

        assertion_guards = (
            ("legacy-volta-noncoherent-not-supported", "--probe-legacy-volta-noncoherent"),
            ("candidate-volta-invalid-aperture-rejected", "--probe-candidate-volta-invalid"),
            ("legacy-maxwell-noncoherent-not-supported", "--probe-legacy-maxwell-noncoherent"),
            ("candidate-maxwell-invalid-aperture-rejected", "--probe-candidate-maxwell-invalid"),
        )
        guards = []
        for name, argument in assertion_guards:
            result = subprocess.run([str(binary), argument], capture_output=True,
                                    text=True, preexec_fn=_disable_core_dumps)
            logs.append("$ " + shlex.quote(str(binary)) + " " + argument + "\n"
                        "expected assertion rejection; returncode=" + str(result.returncode) + "\n"
                        + result.stdout + result.stderr)
            if (result.returncode != -signal.SIGABRT or
                    "UVM_ASSERT_MSG failed:" not in result.stderr):
                raise RuntimeError(f"CE aperture assertion guard failed: {name}")
            guards.append({"name": name, "status": "passed",
                           "returncode": result.returncode})

    lines = [line for line in "".join(logs).splitlines() if " actual=" in line]
    expected = [
        f"{name} actual={value} expected={value}"
        for name, value in (
            ("legacy-volta-system-coherent", 1),
            ("candidate-volta-system-coherent", 1),
            ("legacy-maxwell-system-coherent", 1),
            ("candidate-maxwell-system-coherent", 1),
            ("legacy-volta-video-memory", 0),
            ("candidate-volta-video-memory", 0),
            ("legacy-maxwell-video-memory", 0),
            ("candidate-maxwell-video-memory", 0),
            ("candidate-volta-system-noncoherent", 2),
            ("candidate-maxwell-system-noncoherent", 2),
        )
    ]
    if lines != expected:
        raise RuntimeError("CE harness result labels/values changed: " + repr(lines))

    log_bytes = "".join(logs).encode("utf-8")
    report = {
        "schema": "volta-ce-aperture-host-harness-v2",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "classification": "host-executed-source-callback-contract",
        "compiler": {"path": compiler_path, "version": version.stdout.splitlines()[0]},
        "compile_flags": ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        "harness_source_sha256": hashlib.sha256(harness_bytes).hexdigest(),
        "checks_passed": len(lines),
        "assertion_guard_checks_passed": len(guards),
        "assertion_guards": guards,
        "volta_phys_mode_dispatch": "uvm_hal_maxwell_ce_phys_mode",
        "dispatch_verified_from_candidate_hal_table": True,
        "sources": {
            "r580_ce_sha256": hashlib.sha256(r580_ce.encode()).hexdigest(),
            "candidate_volta_ce_path": str(candidate_volta_ce),
            "candidate_volta_ce_sha256": sha256_file(candidate_volta_ce),
            "r580_maxwell_ce_sha256": hashlib.sha256(r580_maxwell_ce.encode()).hexdigest(),
            "candidate_maxwell_ce_path": str(candidate_maxwell_ce),
            "candidate_maxwell_ce_sha256": sha256_file(candidate_maxwell_ce),
            "r580_c3b5_header_sha256": hashlib.sha256(r580_header.encode()).hexdigest(),
            "candidate_c3b5_header_path": str(candidate_c3b5_path),
            "candidate_c3b5_header_sha256": sha256_file(candidate_c3b5_path),
            "r580_b0b5_header_sha256": hashlib.sha256(r580_b0b5_header.encode()).hexdigest(),
            "candidate_b0b5_header_path": str(candidate_b0b5_path),
            "candidate_b0b5_header_sha256": sha256_file(candidate_b0b5_path),
        },
        "results": lines,
        "log": str(log_path),
        "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "hardware_validated": False,
        "module_loaded": False,
        "module_installed": False,
        "limitations": [
            "The harness executes selected aperture helper bodies on the host CPU, not on a GPU.",
            "B0B5/C3B5 generated field encodings come from pinned NVIDIA headers; their device behavior is not exercised.",
            "No copy-engine command submission, BAR1 access, P2P transfer, UVM operation, or CUDA workload is tested.",
        ],
    }
    report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_exclusive(log_path, log_bytes)
    write_exclusive(report_path, report_bytes)
    return {
        "status": report["status"],
        "report": str(report_path),
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "log": str(log_path),
        "log_sha256": report["log_sha256"],
        "checks_passed": len(lines),
        "assertion_guard_checks_passed": len(guards),
        "hardware_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--candidate-volta-ce", type=Path, required=True)
    parser.add_argument("--candidate-maxwell-ce", type=Path, required=True)
    parser.add_argument("--candidate-uvm", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    result = run(args.r580_archive, args.candidate_volta_ce,
                 args.candidate_maxwell_ce, args.candidate_uvm,
                 args.report, args.log, args.compiler)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"Volta CE host harness failed: {error}", file=sys.stderr)
        raise SystemExit(2)
