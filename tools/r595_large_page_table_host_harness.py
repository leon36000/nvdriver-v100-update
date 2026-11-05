#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute the exact R595 large-P2P-page-table allocator on CPU."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_r595_open_linux68_full import apply_large_page_table_overlay  # noqa: E402
R595_99_ROOT = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/kernel-open")
R595_99 = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
           "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/nv.c")
R595_99_HEADER = R595_99_ROOT / "common/inc/nv-linux.h"
R595_99_OS_INTERFACE = R595_99_ROOT / "nvidia/os-interface.c"
R595_112_ROOT = (ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
                 "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/kernel-open")
R595_112 = (ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
            "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/"
            "kernel-open/nvidia/nv.c")
R595_112_HEADER = R595_112_ROOT / "common/inc/nv-linux.h"
R595_112_OS_INTERFACE = R595_112_ROOT / "nvidia/os-interface.c"
REPLAY_SOURCE = ROOT / "build/experiments/r595-syncboost-replay-v3/source"
REPLAY_NV_C = REPLAY_SOURCE / "kernel-open/nvidia/nv.c"
REPLAY_HEADER = REPLAY_SOURCE / "kernel-open/common/inc/nv-linux.h"
REPLAY_OS_INTERFACE = REPLAY_SOURCE / "kernel-open/nvidia/os-interface.c"
PATCH = ROOT / "patches/r595.99.02/0015-open-large-page-table-vmalloc.patch"
R595_99_SHA256 = "5d31dc828b62e74366e41884d27cdddc01fb44219ecdb3900cab7a3f1758757e"
R595_112_SHA256 = "963f6508a2a361fdce162f3e9917be0045f8fbe596a314c86d09ca07bdbf22af"
R595_99_HEADER_SHA256 = "812a54aa0234c91410b64b9a70c4bb666f7f0d7d367d7eecba80c7b5d990be0e"
R595_112_HEADER_SHA256 = "e2ddaca53f635952bb81dc01cc97a6d76c8be68099a0f40466f4abf20f1fe81e"
R595_99_OS_INTERFACE_SHA256 = "75aa2f569379a3ccce2f438c09db68cc9ce0b0affd73612739561939fe982c35"
R595_112_OS_INTERFACE_SHA256 = "754593fc20cb1e663861a734959608f1ba68b73aff3ccaf9499a974118ec1394"
REPLAY_NV_C_SHA256 = "609c30cfd12f92496e21f788c095721f6668c5a5d12e7f119f3e34a3d1c0a827"
REPLAY_HEADER_SHA256 = "167ea8813202a758d4a70c113822de44bd82cd686a6de6891f445da74e27ccdb"
REPLAY_OS_INTERFACE_SHA256 = "75aa2f569379a3ccce2f438c09db68cc9ce0b0affd73612739561939fe982c35"
REPLAY_NV_C_POSTIMAGE_SHA256 = "bfd37cdb02d03b1b619cd4361f7cd99fd470cfa11f6329c771d3cfd704534735"
REPLAY_HEADER_POSTIMAGE_SHA256 = "77652d97ef1873066e776be6ce06686c10ebef03099712d49f4b62107b5bd6d3"
REPLAY_OS_INTERFACE_POSTIMAGE_SHA256 = "754593fc20cb1e663861a734959608f1ba68b73aff3ccaf9499a974118ec1394"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def extract_function(source: str, marker: str) -> str:
    marker_at = source.find(marker)
    if marker_at < 0:
        raise ValueError(f"pinned nv.c lacks function marker: {marker}")
    start = source.rfind("static", 0, marker_at)
    if start < 0:
        raise ValueError(f"pinned nv.c lacks static declaration for {marker}")
    opening = source.find("{", marker_at)
    if opening < 0:
        raise ValueError(f"pinned nv.c lacks function body for {marker}")
    depth = 0
    state = "code"
    i = opening
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "line_comment":
            if ch == "\n":
                state = "code"
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state == "string":
            if ch == "\\":
                i += 1
            elif ch == '"':
                state = "code"
        elif state == "char":
            if ch == "\\":
                i += 1
            elif ch == "'":
                state = "code"
        elif ch == "/" and nxt == "/":
            state = "line_comment"
            i += 1
        elif ch == "/" and nxt == "*":
            state = "block_comment"
            i += 1
        elif ch == '"':
            state = "string"
        elif ch == "'":
            state = "char"
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise ValueError(f"unterminated function body for {marker}")


def production_snippets(source: str) -> tuple[str, str]:
    return (
        extract_function(source, "nv_alloc_t *nvos_create_alloc("),
        extract_function(source, "int nvos_free_alloc("),
    )


def harness_source(vmalloc_wrapper: str, vfree_wrapper: str,
                   create_alloc: str, free_alloc: str) -> str:
    template = r'''#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t NvU64;
typedef uint32_t NvU32;
typedef int32_t NvS32;
typedef int NvBool;
typedef unsigned int gfp_t;
typedef struct { int64_t value; } atomic64_t;
struct device { int unused; };
typedef struct { NvU64 phys_addr; unsigned long virt_addr; } nvidia_pte_t;
typedef struct nv_alloc_s {
    struct nv_alloc_s *next;
    struct device *dev;
    atomic64_t usage_count;
    unsigned int num_pages;
    nvidia_pte_t *page_table;
    unsigned int pid;
} nv_alloc_t;

#define NV_GFP_KERNEL 0x01
#define __GFP_ZERO 0x02
#define NV_DBG_ERRORS 1
#define NV_KZALLOC(ptr, size) do { (ptr) = test_kzalloc(size); } while (0)
#define NV_KFREE(ptr, size) test_kfree((ptr), (size))

static nvidia_pte_t page_memory_token;
static NvU64 last_alloc_size;
static unsigned int kvzalloc_calls, nv_vmalloc_calls;
static unsigned int kvfree_calls, nv_vfree_calls, struct_free_calls;
static unsigned int last_flags;
static NvU64 last_free_size;
static int fail_vmalloc;

static void *test_kzalloc(size_t size) { return calloc(1, size); }
static void test_kfree(void *ptr, size_t size)
{
    (void)size;
    ++struct_free_calls;
    free(ptr);
}
static void *kvzalloc(NvU64 size, unsigned int flags)
{
    ++kvzalloc_calls; last_alloc_size = size; last_flags = flags;
    return &page_memory_token;
}
static void *test___vmalloc(unsigned long size, unsigned int flags, ...)
{
    ++nv_vmalloc_calls; last_alloc_size = size; last_flags = flags;
    return fail_vmalloc ? NULL : &page_memory_token;
}
#define __vmalloc(...) test___vmalloc(__VA_ARGS__)
#define NV_MEMDBG_ADD(ptr, size) do { (void)(ptr); (void)(size); } while (0)
#define NV_MEMDBG_REMOVE(ptr, size) test_memdbg_remove((ptr), (size))
#define NV_VMALLOC_HAS_PGPROT_T_ARG 1
#define PAGE_KERNEL 0x04
static void test_memdbg_remove(void *ptr, NvU64 size)
{
    (void)ptr;
    last_free_size = size;
}
static void vfree(void *ptr)
{
    if (ptr == &page_memory_token) ++nv_vfree_calls;
}
static void kvfree(void *ptr)
{
    if (ptr == &page_memory_token) ++kvfree_calls;
}
static void atomic64_set(atomic64_t *value, int64_t number) { value->value = number; }
static int64_t atomic64_read(const atomic64_t *value) { return value->value; }
static unsigned int os_get_current_process(void) { return 17; }
static void nv_printf(int level, const char *format, ...)
{
    (void)level; (void)format;
}

__VMALLOC_WRAPPER__

__VFREE_WRAPPER__

__CREATE_ALLOC__

__FREE_ALLOC__

static void reset(void)
{
    last_alloc_size = 0;
    last_free_size = 0;
    kvzalloc_calls = nv_vmalloc_calls = kvfree_calls = nv_vfree_calls = 0;
    struct_free_calls = 0;
    last_flags = 0;
    fail_vmalloc = 0;
}

static int check_small_and_limit(void)
{
    struct device device = {0};
    NvU64 pages = (NvU64)INT_MAX / sizeof(nvidia_pte_t);
    NvU64 bytes = pages * sizeof(nvidia_pte_t);
    nv_alloc_t *allocation;

    reset();
    allocation = nvos_create_alloc(&device, 16);
    if (!allocation || kvzalloc_calls != 1 || nv_vmalloc_calls != 0 ||
        last_alloc_size != 16 * sizeof(nvidia_pte_t) ||
        last_flags != NV_GFP_KERNEL || allocation->pid != 17 ||
        nvos_free_alloc(allocation) != 0 || kvfree_calls != 1 || nv_vfree_calls != 0)
        return 1;

    reset();
    allocation = nvos_create_alloc(&device, pages);
    if (!allocation || bytes > INT_MAX || kvzalloc_calls != 1 || nv_vmalloc_calls != 0 ||
        last_alloc_size != bytes || nvos_free_alloc(allocation) != 0 ||
        kvfree_calls != 1 || nv_vfree_calls != 0)
        return 2;
    puts("small_and_INT_MAX_boundary=pass");
    return 0;
}

static int check_large_and_matching_free(void)
{
    struct device device = {0};
    NvU64 pages = (NvU64)INT_MAX / sizeof(nvidia_pte_t) + 1;
    NvU64 bytes = pages * sizeof(nvidia_pte_t);
    nv_alloc_t *allocation;

    reset();
    allocation = nvos_create_alloc(&device, pages);
    if (!allocation || bytes <= INT_MAX || kvzalloc_calls != 0 || nv_vmalloc_calls != 1 ||
        last_alloc_size != bytes || last_flags != (NV_GFP_KERNEL | __GFP_ZERO) ||
        nvos_free_alloc(allocation) != 0 || kvfree_calls != 0 || nv_vfree_calls != 1 ||
        last_free_size != bytes)
        return 3;
    puts("oversized_vmalloc_zeroed_and_matching_vfree=pass");
    return 0;
}

static int check_failures_and_bounds(void)
{
    struct device device = {0};
    nv_alloc_t *allocation;
    NvU64 overflow_pages = UINT64_MAX / sizeof(nvidia_pte_t) + 1;

    reset();
    fail_vmalloc = 1;
    allocation = nvos_create_alloc(&device,
        (NvU64)INT_MAX / sizeof(nvidia_pte_t) + 1);
    if (allocation || nv_vmalloc_calls != 1 || struct_free_calls != 1)
        return 4;

    reset();
    allocation = nvos_create_alloc(&device, overflow_pages);
    if (allocation || kvzalloc_calls || nv_vmalloc_calls || struct_free_calls)
        return 5;

    reset();
    allocation = nvos_create_alloc(&device, (NvU64)UINT_MAX + 1);
    if (allocation || kvzalloc_calls || nv_vmalloc_calls || struct_free_calls != 1)
        return 6;

    reset();
    allocation = nvos_create_alloc(&device, 1);
    if (!allocation) return 7;
    atomic64_set(&allocation->usage_count, 1);
    if (nvos_free_alloc(allocation) != 1 || kvfree_calls || nv_vfree_calls)
        return 8;
    atomic64_set(&allocation->usage_count, 0);
    if (nvos_free_alloc(allocation) != 0 || kvfree_calls != 1)
        return 9;
    puts("overflow_count_bounds_alloc_failure_and_busy_free=pass");
    return 0;
}

int main(void)
{
    int status;
    status = check_small_and_limit(); if (status) return status;
    status = check_large_and_matching_free(); if (status) return status;
    status = check_failures_and_bounds(); if (status) return status;
    return 0;
}
'''
    return (template.replace("__VMALLOC_WRAPPER__", vmalloc_wrapper)
            .replace("__VFREE_WRAPPER__", vfree_wrapper)
            .replace("__CREATE_ALLOC__", create_alloc)
            .replace("__FREE_ALLOC__", free_alloc))


def run(compiler: str = "gcc") -> dict:
    pinned_files = (
        (R595_99, R595_99_SHA256, "R595.99.02 nv.c"),
        (R595_99_HEADER, R595_99_HEADER_SHA256, "R595.99.02 nv-linux.h"),
        (R595_99_OS_INTERFACE, R595_99_OS_INTERFACE_SHA256,
         "R595.99.02 os-interface.c"),
        (R595_112, R595_112_SHA256, "R595.112.07 nv.c"),
        (R595_112_HEADER, R595_112_HEADER_SHA256, "R595.112.07 nv-linux.h"),
        (R595_112_OS_INTERFACE, R595_112_OS_INTERFACE_SHA256,
         "R595.112.07 os-interface.c"),
        (REPLAY_NV_C, REPLAY_NV_C_SHA256, "R595 replay nv.c"),
        (REPLAY_HEADER, REPLAY_HEADER_SHA256, "R595 replay nv-linux.h"),
        (REPLAY_OS_INTERFACE, REPLAY_OS_INTERFACE_SHA256,
         "R595 replay os-interface.c"),
    )
    for path, expected, label in pinned_files:
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise ValueError(f"{label} missing or hash mismatch: {path}")
    if PATCH.is_symlink() or not PATCH.is_file():
        raise ValueError("large page-table patch is missing or unsafe")

    upstream_alloc, upstream_free = production_snippets(R595_112.read_text())
    upstream_vmalloc = extract_function(
        R595_112_HEADER.read_text(), "nv_vmalloc(unsigned long size, gfp_t flags)")
    upstream_vfree = extract_function(
        R595_112_HEADER.read_text(), "nv_vfree(void *ptr, NvU64 size)")
    version = subprocess.run([compiler, "--version"], capture_output=True,
                             text=True, check=True).stdout.splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="r595-large-p2p-table-") as temp:
        source_root = Path(temp) / "source"
        for path, relative in ((REPLAY_HEADER, "kernel-open/common/inc/nv-linux.h"),
                                (REPLAY_OS_INTERFACE, "kernel-open/nvidia/os-interface.c"),
                                (REPLAY_NV_C, "kernel-open/nvidia/nv.c")):
            target = source_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        overlay = apply_large_page_table_overlay(source_root)
        patched_nv = (source_root / "kernel-open/nvidia/nv.c").read_text()
        patched_header = (source_root / "kernel-open/common/inc/nv-linux.h").read_text()
        patched_os_interface = (
            source_root / "kernel-open/nvidia/os-interface.c").read_text()
        create_alloc, free_alloc = production_snippets(patched_nv)
        vmalloc_wrapper = extract_function(
            patched_header, "nv_vmalloc(unsigned long size, gfp_t flags)")
        vfree_wrapper = extract_function(
            patched_header, "nv_vfree(void *ptr, NvU64 size)")
        if (create_alloc, free_alloc) != (upstream_alloc, upstream_free):
            raise ValueError("patched replay allocator functions differ from R595.112.07")
        if (vmalloc_wrapper, vfree_wrapper) != (upstream_vmalloc, upstream_vfree):
            raise ValueError("patched replay allocator wrappers differ from R595.112.07")
        if "*address = nv_vmalloc(alloc_size, GFP_KERNEL);" not in patched_os_interface:
            raise ValueError("patched replay vmalloc callsite does not pass GFP_KERNEL")
        c_source = harness_source(vmalloc_wrapper, vfree_wrapper,
                                  create_alloc, free_alloc)
        c_file = Path(temp) / "host-harness.c"
        binary = Path(temp) / "host-harness"
        c_file.write_text(c_source)
        command = [compiler, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                   str(c_file), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise RuntimeError(f"host harness compile failed: {compiled.stderr[-4000:]}")
        executed = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
        output = executed.stdout + executed.stderr
        if executed.returncode or output.count("=pass") != 3:
            raise RuntimeError(f"host harness failed: exit={executed.returncode}: {output}")
        return {
            "schema": "r595-large-p2p-page-table-host-harness-v2",
            "status": "passed",
            "qualification": "exact-patched-replay-source-host-cpu-execution",
            "runtime_or_hardware_validated": False,
            "module_loaded_or_installed": False,
            "source_path": str(REPLAY_SOURCE),
            "source_sha256": R595_112_SHA256,
            "baseline_path": str(R595_99),
            "baseline_sha256": R595_99_SHA256,
            "patch_path": str(PATCH),
            "patch_sha256": sha256_file(PATCH),
            "overlay": overlay,
            "harness_sha256": sha256_bytes(c_source.encode()),
            "compiler": compiler,
            "compiler_version": version,
            "compile_command": command,
            "compile_exit_code": compiled.returncode,
            "run_exit_code": executed.returncode,
            "output": output.strip().splitlines(),
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report_path = args.report or ROOT / "evidence" / \
        f"r595-large-p2p-page-table-host-harness-v1-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    report_path = Path(report_path).absolute()
    evidence = ROOT / "evidence"
    if not report_path.is_relative_to(evidence) or report_path.exists() or report_path.is_symlink():
        parser.error("report must be new and stay below the evidence directory")
    try:
        report = run()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"],
                      "qualification": report["qualification"],
                      "output": report["output"], "report": str(report_path),
                      "sha256": sha256_file(report_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
