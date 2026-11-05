#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute the pinned R595 page-backed PFN guard on the host."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
          "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/"
          "kernel-open/nvidia/os-mlock.c")
PATCH = ROOT / "patches/r595.99.02/0013-open-pfn-backed-io-guard.patch"
SOURCE_SHA256 = "760a5ee564cd0f151aea337eca146578bed157c80c8152f9aa9b414db6576609"
PATCH_SHA256 = "018fd72247d5865639f5ea867226b9da9afa49a66aed3e2d7c711b2b0d2c625f"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def production_snippets(source_text: str) -> tuple[str, str]:
    """Extract the exact helper and caller bodies from the pinned kernel file."""
    helper_start = source_text.find("static inline NvBool nv_pfn_has_page_backing(")
    caller_start = source_text.find("static NV_STATUS get_io_ptes(")
    caller_end = source_text.find("\nNV_STATUS NV_API_CALL os_lookup_user_io_memory", caller_start)
    if min(helper_start, caller_start, caller_end) < 0 or not helper_start < caller_start < caller_end:
        raise ValueError("pinned os-mlock.c lacks the expected PFN helper/caller boundaries")
    helper_end = source_text.find("\n/*!", helper_start)
    if helper_end < 0 or helper_end >= caller_start:
        raise ValueError("could not isolate the pinned PFN helper")
    return source_text[helper_start:helper_end], source_text[caller_start:caller_end]


def harness_source(helper: str, caller: str) -> str:
    template = """#include <stdint.h>
#include <stdio.h>

typedef int NvBool;
typedef int NV_STATUS;
typedef unsigned long NvUPtr;
typedef unsigned long long NvU64;
struct vm_area_struct { int unused; };
#define NV_OK 0
#define NV_ERR_INVALID_ADDRESS (-1)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)

static unsigned long test_pfns[2];
static unsigned long test_count;
static unsigned long test_follow_index;
static int test_page_backed;
static unsigned int map_memory_calls;
static unsigned int pfn_valid_calls;

int nv_follow_pfn(struct vm_area_struct *vma, unsigned long address,
                  unsigned long *pfn)
{
    (void)vma;
    (void)address;
    if (test_follow_index >= test_count)
        return -1;
    *pfn = test_pfns[test_follow_index++];
    return 0;
}

int pfn_is_map_memory(unsigned long pfn)
{
    (void)pfn;
    ++map_memory_calls;
    return test_page_backed;
}

int pfn_valid(unsigned long pfn)
{
    (void)pfn;
    ++pfn_valid_calls;
    return test_page_backed;
}

__HELPER__

__CALLER__

static void reset(unsigned long count, int page_backed)
{
    test_pfns[0] = 0x1234UL;
    test_pfns[1] = 0x1235UL;
    test_count = count;
    test_follow_index = 0;
    test_page_backed = page_backed;
    map_memory_calls = 0;
    pfn_valid_calls = 0;
}

int main(void)
{
    struct vm_area_struct vma = {0};
    NvU64 *out[2];
    NvU64 *sentinel = (NvU64 *)(uintptr_t)0xdeadbeefUL;
    int status;

    reset(1, 1);
    out[0] = sentinel;
    status = get_io_ptes(&vma, 0, 1, out);
    if (status != NV_ERR_INVALID_ADDRESS || out[0] != sentinel)
        return 1;

    reset(2, 0);
    status = get_io_ptes(&vma, 0, 2, out);
    if (status != NV_OK || out[0] != (NvU64 *)(uintptr_t)(0x1234UL << PAGE_SHIFT)
        || out[1] != (NvU64 *)(uintptr_t)(0x1235UL << PAGE_SHIFT))
        return 2;

#ifdef NV_PFN_IS_MAP_MEMORY_PRESENT
    if (map_memory_calls != 2 || pfn_valid_calls != 0)
        return 3;
    puts("probe=pfn_is_map_memory");
#else
    if (pfn_valid_calls != 2 || map_memory_calls != 0)
        return 4;
    puts("probe=pfn_valid");
#endif
    puts("guard_rejects_backed_without_publish=pass");
    puts("allows_unbacked_contiguous_io=pass");
    return 0;
}
"""
    return template.replace("__HELPER__", helper).replace("__CALLER__", caller)


def run_variants(compiler: str = "gcc") -> list[dict]:
    if not SOURCE.is_file() or SOURCE.is_symlink() or sha256_file(SOURCE) != SOURCE_SHA256:
        raise ValueError("pinned R595.112 os-mlock.c is missing or changed")
    if not PATCH.is_file() or PATCH.is_symlink() or sha256_file(PATCH) != PATCH_SHA256:
        raise ValueError("R595.99 PFN guard patch is missing or changed")
    source_text = SOURCE.read_text()
    helper, caller = production_snippets(source_text)
    c_source = harness_source(helper, caller)
    c_source_hash = sha256_bytes(c_source.encode())
    version = subprocess.run([compiler, "--version"], capture_output=True,
                             text=True, check=True).stdout.splitlines()[0]
    variants = (
        ("pfn_is_map_memory", ["-DNV_PFN_IS_MAP_MEMORY_PRESENT"]),
        ("pfn_valid", []),
    )
    results = []
    with tempfile.TemporaryDirectory(prefix="r595-pfn-backed-host-") as temp:
        temp_root = Path(temp)
        for name, defines in variants:
            binary = temp_root / ("guard-" + name)
            command = [compiler, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                       *defines, "-x", "c", "-o", str(binary), "-"]
            compiled = subprocess.run(command, input=c_source, capture_output=True,
                                      text=True, check=False)
            if compiled.returncode != 0:
                raise RuntimeError(
                    f"{name} harness compile failed: {compiled.stderr[-4000:]}")
            ran = subprocess.run([str(binary)], capture_output=True, text=True,
                                 check=False)
            output = ran.stdout + ran.stderr
            if ran.returncode != 0 or f"probe={name}" not in output or \
                    "guard_rejects_backed_without_publish=pass" not in output or \
                    "allows_unbacked_contiguous_io=pass" not in output:
                raise RuntimeError(f"{name} harness failed: exit={ran.returncode}: {output}")
            results.append({
                "variant": name,
                "command": command,
                "generated_c_sha256": c_source_hash,
                "binary_sha256": sha256_file(binary),
                "compile_exit_code": compiled.returncode,
                "exit_code": ran.returncode,
                "output": output.strip().splitlines(),
            })
    return [{"compiler": compiler, "compiler_version": version,
             "source_path": str(SOURCE), "source_sha256": SOURCE_SHA256,
             "patch_sha256": PATCH_SHA256, "qualification": "exact-source-host-cpu-execution",
             **item} for item in results]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = args.report or ROOT / "evidence" / \
        f"r595-pfn-backed-io-host-harness-v1-{timestamp}.json"
    report_path = Path(report_path).absolute()
    evidence = ROOT / "evidence"
    if not report_path.is_relative_to(evidence) or report_path.exists() or report_path.is_symlink():
        parser.error("report must be new and stay below the evidence directory")
    try:
        variants = run_variants()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    report = {
        "schema": "r595-pfn-backed-io-host-harness-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "qualification": "exact-source-host-cpu-execution",
        "runtime_or_hardware_validated": False,
        "module_loaded_or_installed": False,
        "cases": variants,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "qualification": report["qualification"],
                      "cases": [{"variant": x["variant"], "exit_code": x["exit_code"],
                                 "output": x["output"]} for x in variants],
                      "report": str(report_path), "sha256": sha256_file(report_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
