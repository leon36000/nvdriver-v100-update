#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute pinned R595 BAR1 peer-aperture callbacks on the host.

This host harness extracts the exact source functions and supplies bounded
UVM/RM data-structure shims. It does not execute a PCIe or GPU transaction.
"""
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
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r595_noncoherent_bar1_consumers import (  # noqa: E402
    DEFAULT_CANDIDATE,
    DEFAULT_R595,
    extract_function,
    sha256_file,
)


C_HARNESS = r'''#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t NvU64;
typedef uint8_t NvU8;
typedef int uvm_parent_id_t;
typedef enum {
    UVM_APERTURE_SYS = 1,
    UVM_APERTURE_SYS_NON_COHERENT = 2,
    UVM_APERTURE_VID = 3,
    UVM_APERTURE_PEER_0 = 16
} uvm_aperture_t;
typedef enum {
    UVM_GPU_LINK_INVALID = 0,
    UVM_GPU_LINK_PCIE_BAR1 = 1,
    UVM_GPU_LINK_NVLINK = 2
} uvm_gpu_link_type_t;

#define UVM_ASSERT(condition) assert(condition)
#define UVM_APERTURE_PEER(peer_id) ((uvm_aperture_t)(UVM_APERTURE_PEER_0 + (peer_id)))
#define uvm_spin_lock(lock) ((void)(lock))
#define uvm_spin_unlock(lock) ((void)(lock))
#define for_each_parent_gpu_in_mask(parent_gpu, mask) \
    for (size_t mask_iteration = 0; \
         mask_iteration < (mask)->count && (((parent_gpu) = (mask)->items[mask_iteration]), true); \
         ++mask_iteration)

typedef struct {
    NvU64 peer_gpa_memory_window_start;
} peer_address_info_t;
typedef struct {
    NvU64 fabric_memory_window_start;
} nvswitch_info_t;
typedef struct uvm_parent_gpu_s {
    uvm_parent_id_t id;
    peer_address_info_t peer_address_info;
    nvswitch_info_t nvswitch_info;
} uvm_parent_gpu_t;
typedef struct {
    int ref_count;
    uvm_gpu_link_type_t link_type;
    bool bar1_p2p_pcie_atomics_enabled[2];
    NvU64 bar1_p2p_dma_base_address[2];
    NvU64 bar1_p2p_dma_size[2];
    NvU8 peer_ids[2];
} uvm_parent_gpu_peer_t;
typedef struct {
    uvm_parent_gpu_t *items[4];
    size_t count;
} uvm_parent_processor_mask_t;
typedef struct {
    int peer_gpu_lock;
    uvm_parent_processor_mask_t peer_gpu_mask;
} uvm_gpu_peer_info_t;
typedef struct {
    uvm_parent_gpu_t *parent;
    int id;
    uvm_gpu_peer_info_t peer_info;
} uvm_gpu_t;
typedef struct {
    uvm_aperture_t aperture;
    NvU64 address;
} uvm_gpu_phys_address_t;

static uvm_parent_gpu_peer_t *g_peer_caps;

static NvU64 uvm_parent_id_value(uvm_parent_id_t id) { return (NvU64)id; }
static int uvm_parent_id_cmp(uvm_parent_id_t left, uvm_parent_id_t right)
{
    return (left > right) - (left < right);
}
static int uvm_id_cmp(int left, int right) { return (left > right) - (left < right); }
static void uvm_parent_gpus_from_processor_mask(uvm_parent_processor_mask_t *parent_mask,
                                                 const uvm_parent_processor_mask_t *processor_mask)
{
    *parent_mask = *processor_mask;
}
static bool uvm_gpus_are_smc_peers(uvm_gpu_t *left, uvm_gpu_t *right)
{
    (void)left; (void)right; return false;
}
static uvm_parent_gpu_peer_t *parent_gpu_peer_caps(uvm_parent_gpu_t *left, uvm_parent_gpu_t *right)
{
    (void)left; (void)right; return g_peer_caps;
}
static bool uvm_parent_gpus_are_nvlink_direct_connected(uvm_parent_gpu_t *left, uvm_parent_gpu_t *right)
{
    (void)left; (void)right; return false;
}
static bool uvm_parent_gpus_are_nvswitch_connected(uvm_parent_gpu_t *left, uvm_parent_gpu_t *right)
{
    (void)left; (void)right; return false;
}
static bool uvm_aperture_is_sys(uvm_aperture_t aperture)
{
    return aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT;
}
static bool uvm_aperture_is_peer(uvm_aperture_t aperture)
{
    return aperture >= UVM_APERTURE_PEER_0;
}
static uvm_gpu_phys_address_t uvm_gpu_phys_address(uvm_aperture_t aperture, NvU64 address)
{
    uvm_gpu_phys_address_t result = { aperture, address };
    return result;
}

/*EXTRACTED_PARENT_GPU_PEER_APERTURE*/
/*EXTRACTED_UVM_GPU_PEER_APERTURE*/
/*EXTRACTED_UVM_GPU_PEER_PHYS_ADDRESS*/
/*EXTRACTED_GPU_PHYS_ADDRESS_IS_BAR1P2P_PEER*/

static int checks_run;
static void expect(bool condition, const char *label)
{
    ++checks_run;
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", label);
        assert(condition);
    }
}

int main(void)
{
    uvm_parent_gpu_t parent_low = { .id = 4 };
    uvm_parent_gpu_t parent_high = { .id = 9 };
    uvm_gpu_t gpu_low = { .parent = &parent_low, .id = 4 };
    uvm_gpu_t gpu_high = { .parent = &parent_high, .id = 9 };
    uvm_parent_gpu_peer_t caps = {
        .ref_count = 1,
        .link_type = UVM_GPU_LINK_PCIE_BAR1,
        .bar1_p2p_pcie_atomics_enabled = { true, false },
        .bar1_p2p_dma_base_address = { 0x10000000, 0x20000000 },
        .bar1_p2p_dma_size = { 0x100000, 0x200000 },
        .peer_ids = { 2, 7 }
    };
    const NvU64 offset = 0x2345;
    uvm_gpu_phys_address_t address;
    g_peer_caps = &caps;
    gpu_low.peer_info.peer_gpu_mask.items[0] = &parent_high;
    gpu_low.peer_info.peer_gpu_mask.count = 1;

    expect(parent_gpu_peer_aperture(&parent_low, &parent_high, &caps) == UVM_APERTURE_SYS,
           "low-to-high BAR1 selects coherent SYS when atomics are enabled");
    expect(parent_gpu_peer_aperture(&parent_high, &parent_low, &caps) == UVM_APERTURE_SYS_NON_COHERENT,
           "high-to-low BAR1 selects SYS_NON_COHERENT when atomics are disabled");
    address = uvm_gpu_peer_phys_address(&gpu_high, offset, &gpu_low);
    expect(address.aperture == UVM_APERTURE_SYS && address.address == 0x10000000 + offset,
           "low-to-high peer physical address adds BAR1 window zero base");
    address = uvm_gpu_peer_phys_address(&gpu_low, offset, &gpu_high);
    expect(address.aperture == UVM_APERTURE_SYS_NON_COHERENT && address.address == 0x20000000 + offset,
           "high-to-low peer physical address preserves noncoherent aperture and adds window one base");

    caps.bar1_p2p_pcie_atomics_enabled[0] = false;
    caps.bar1_p2p_pcie_atomics_enabled[1] = true;
    expect(parent_gpu_peer_aperture(&parent_low, &parent_high, &caps) == UVM_APERTURE_SYS_NON_COHERENT,
           "low-to-high direction uses its own disabled atomic capability");
    expect(parent_gpu_peer_aperture(&parent_high, &parent_low, &caps) == UVM_APERTURE_SYS,
           "high-to-low direction uses its own enabled atomic capability");
    address = uvm_gpu_peer_phys_address(&gpu_high, offset, &gpu_low);
    expect(address.aperture == UVM_APERTURE_SYS_NON_COHERENT && address.address == 0x10000000 + offset,
           "reversed capability retains BAR1 window zero address");
    address = uvm_gpu_peer_phys_address(&gpu_low, offset, &gpu_high);
    expect(address.aperture == UVM_APERTURE_SYS && address.address == 0x20000000 + offset,
           "reversed capability retains BAR1 window one address");

    caps.link_type = UVM_GPU_LINK_NVLINK;
    expect(parent_gpu_peer_aperture(&parent_low, &parent_high, &caps) == UVM_APERTURE_PEER_0 + 2,
           "non-BAR1 link returns the low-to-high peer aperture");
    expect(parent_gpu_peer_aperture(&parent_high, &parent_low, &caps) == UVM_APERTURE_PEER_0 + 7,
           "non-BAR1 link returns the high-to-low peer aperture");

    caps.link_type = UVM_GPU_LINK_PCIE_BAR1;
    caps.bar1_p2p_dma_base_address[0] = 0x10000000;
    caps.bar1_p2p_dma_size[0] = 0x1000;
    expect(gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                             uvm_gpu_phys_address(UVM_APERTURE_SYS, 0x10000000)),
           "coherent BAR1 base is recognized as a peer address");
    expect(gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                             uvm_gpu_phys_address(UVM_APERTURE_SYS_NON_COHERENT, 0x10000000)),
           "noncoherent BAR1 base is recognized as a peer address");
    expect(gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                             uvm_gpu_phys_address(UVM_APERTURE_SYS_NON_COHERENT, 0x10000FFF)),
           "last byte inside the BAR1 window is recognized");
    expect(!gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                              uvm_gpu_phys_address(UVM_APERTURE_SYS_NON_COHERENT, 0x10001000)),
           "exclusive BAR1 end is not recognized as a peer address");
    expect(!gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                              uvm_gpu_phys_address(UVM_APERTURE_SYS_NON_COHERENT, 0x0FFFFFFF)),
           "address before the BAR1 window is not recognized");
    expect(!gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                              uvm_gpu_phys_address(UVM_APERTURE_VID, 0x10000000)),
           "VID aperture is excluded from BAR1 peer recognition");
    caps.link_type = UVM_GPU_LINK_NVLINK;
    expect(!gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                              uvm_gpu_phys_address(UVM_APERTURE_SYS, 0x10000000)),
           "non-BAR1 links are excluded from BAR1 peer recognition");
    caps.link_type = UVM_GPU_LINK_PCIE_BAR1;
    gpu_low.peer_info.peer_gpu_mask.count = 0;
    expect(!gpu_phys_address_is_bar1p2p_peer(&gpu_low,
                                              uvm_gpu_phys_address(UVM_APERTURE_SYS_NON_COHERENT, 0x10000000)),
           "an empty peer mask yields no BAR1 peer address");
    printf("PASS: %d exact-source aperture/address/range vectors\n", checks_run);
    return 0;
}
'''


def extract_full_function(source: str, symbol: str) -> str:
    body, line = extract_function(source, symbol)
    del body, line
    from tools.probe_volta_uvm_port import _matching_c_brace, _mask_c_comments
    import re

    masked = _mask_c_comments(source)
    match = re.search(rf"\b{re.escape(symbol)}\s*\([^;{{}}]*\)\s*\{{", masked)
    if match is None:
        raise ValueError(f"missing definition of {symbol}")
    closing = _matching_c_brace(source, match.end() - 1)
    start = max(
        masked.rfind(";", 0, match.start()),
        masked.rfind("}", 0, match.start()),
        masked.rfind("{", 0, match.start()),
    ) + 1
    return source[start:closing + 1].strip()


def run_harness(r595_root: Path, candidate_root: Path, compiler: str = "cc") -> dict:
    r595_root = r595_root.resolve(strict=True)
    candidate_root = candidate_root.resolve(strict=True)
    r595_gpu = r595_root / "uvm_gpu.c"
    candidate_gpu = candidate_root / "uvm_gpu.c"
    r595_hash = sha256_file(r595_gpu)
    candidate_hash = sha256_file(candidate_gpu)
    if r595_hash != candidate_hash:
        raise ValueError("candidate uvm_gpu.c differs from pinned R595 source")

    source = r595_gpu.read_text(encoding="utf-8")
    extracted = {
        "parent_gpu_peer_aperture": extract_full_function(source, "parent_gpu_peer_aperture"),
        "uvm_gpu_peer_aperture": extract_full_function(source, "uvm_gpu_peer_aperture"),
        "uvm_gpu_peer_phys_address": extract_full_function(source, "uvm_gpu_peer_phys_address"),
        "gpu_phys_address_is_bar1p2p_peer": extract_full_function(source, "gpu_phys_address_is_bar1p2p_peer"),
    }
    c_source = C_HARNESS
    for symbol, marker in (
        ("parent_gpu_peer_aperture", "/*EXTRACTED_PARENT_GPU_PEER_APERTURE*/"),
        ("uvm_gpu_peer_aperture", "/*EXTRACTED_UVM_GPU_PEER_APERTURE*/"),
        ("uvm_gpu_peer_phys_address", "/*EXTRACTED_UVM_GPU_PEER_PHYS_ADDRESS*/"),
        ("gpu_phys_address_is_bar1p2p_peer", "/*EXTRACTED_GPU_PHYS_ADDRESS_IS_BAR1P2P_PEER*/"),
    ):
        if c_source.count(marker) != 1:
            raise ValueError(f"invalid C harness marker for {symbol}")
        c_source = c_source.replace(marker, extracted[symbol])

    cc_path = shutil.which(compiler)
    if cc_path is None:
        raise ValueError(f"compiler not found: {compiler}")
    cc_version = subprocess.run([cc_path, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="r595-bar1-peer-host-") as temporary:
        directory = Path(temporary)
        c_path = directory / "bar1_peer.c"
        binary_path = directory / "bar1_peer"
        c_path.write_text(c_source, encoding="utf-8")
        command = [cc_path, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", str(c_path), "-o", str(binary_path)]
        build = subprocess.run(command, capture_output=True, text=True)
        if build.returncode != 0:
            raise RuntimeError(f"host harness compilation failed ({build.returncode}):\n{build.stdout}{build.stderr}")
        execution = subprocess.run([str(binary_path)], capture_output=True, text=True)
        if execution.returncode != 0:
            raise RuntimeError(f"host harness execution failed ({execution.returncode}):\n{execution.stdout}{execution.stderr}")
        binary_hash = sha256_file(binary_path)
        c_hash = sha256_file(c_path)

    if "PASS: 18 exact-source aperture/address/range vectors" not in execution.stdout:
        raise RuntimeError(f"unexpected harness result: {execution.stdout!r}")
    return {
        "schema": "r595-bar1-peer-host-harness-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "qualification": "host-executed-exact-source-functions",
        "runtime_or_hardware_validated": False,
        "module_loaded_or_installed": False,
        "r595_source_root": str(r595_root),
        "candidate_root": str(candidate_root),
        "source_identity": {
            "R595_uvm_gpu_c_sha256": r595_hash,
            "candidate_uvm_gpu_c_sha256": candidate_hash,
            "matches": True,
        },
        "functions_extracted": list(extracted),
        "compiler": {"path": cc_path, "version": cc_version},
        "compile_command": command,
        "harness_c_sha256": c_hash,
        "harness_binary_sha256": binary_hash,
        "checks_passed": 18,
        "stdout": execution.stdout.strip(),
        "stderr": execution.stderr,
        "limits": [
            "The test uses a CPU shim for UVM/RM data and forces NVLink/NVSwitch predicates false in the BAR1 address vectors.",
            "It does not validate RM capability values, PCIe BAR1 mapping, DMA transactions, P2P, UVM, or GPU hardware behavior.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r595-root", type=Path, default=DEFAULT_R595)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--compiler", default="cc")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run_harness(args.r595_root, args.candidate_root, args.compiler)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"host harness failed: {error}", file=sys.stderr)
        return 2

    args.report.parent.mkdir(parents=True, exist_ok=True)
    previous_umask = os.umask(0o077)
    try:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        args.report.chmod(0o600)
    finally:
        os.umask(previous_umask)
    print(report["stdout"])
    print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
