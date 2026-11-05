#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute pinned Volta MMU callback bodies as a host test.

Only selected source functions and NVIDIA's generated field headers are used.
This does not load a kernel module or validate GPU behavior.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_mmu_adapter_contract import (  # noqa: E402
    _mask_c_comments,
    extract_function,
    sha256_file,
)


HARNESS_PREFIX = r'''#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "nvtypes.h"
#include "nvmisc.h"
#include "nv_uvm_user_types.h"
#include "hwref/volta/gv100/dev_mmu.h"

typedef enum {
    UVM_APERTURE_PEER_0, UVM_APERTURE_PEER_1, UVM_APERTURE_PEER_2,
    UVM_APERTURE_PEER_3, UVM_APERTURE_PEER_4, UVM_APERTURE_PEER_5,
    UVM_APERTURE_PEER_6, UVM_APERTURE_PEER_7, UVM_APERTURE_PEER_MAX,
    UVM_APERTURE_SYS, UVM_APERTURE_SYS_NON_COHERENT, UVM_APERTURE_VID,
    UVM_APERTURE_DEFAULT
} uvm_aperture_t;
typedef enum {
    UVM_PROT_NONE, UVM_PROT_READ_ONLY, UVM_PROT_READ_WRITE,
    UVM_PROT_READ_WRITE_ATOMIC
} uvm_prot_t;
typedef struct { NvU64 address; uvm_aperture_t aperture; } uvm_gpu_phys_address_t;
typedef struct { uvm_gpu_phys_address_t addr; } uvm_mmu_page_table_alloc_t;
typedef struct { NvU32 depth; } uvm_page_directory_t;
static struct { struct { int enabled; } ats; } g_uvm_global;
#define MMU_BIG 0
#define MMU_SMALL 1
enum {
    UVM_MMU_PTE_FLAGS_NONE = 0,
    UVM_MMU_PTE_FLAGS_CACHED = 1 << 0,
    UVM_MMU_PTE_FLAGS_ACCESS_COUNTERS_DISABLED = 1 << 1,
    UVM_MMU_PTE_FLAGS_MASK = (1 << 2) - 1
};

#define UVM_ASSERT(condition) assert(condition)
#define UVM_ASSERT_MSG(condition, ...) assert(condition)
#define UVM_APERTURE_PEER_ID(aperture) ({ \
    uvm_aperture_t _aperture = (aperture); \
    UVM_ASSERT(_aperture >= UVM_APERTURE_PEER_0 && _aperture < UVM_APERTURE_PEER_MAX); \
    (NvU32)_aperture; \
})
#define HWMASK64(d, r, f) DRF_MASK64(NV ## d ## _ ## r ## _ ## f)
#define HWSIZE(d, r, f) DRF_SIZE(NV ## d ## _ ## r ## _ ## f)
#define HWCONST64(d, r, f, c) DRF_DEF64(d, _ ## r, _ ## f, _ ## c)
#define HWVALUE64(d, r, f, v) ({ \
    NvU64 _v = (v); \
    NvU64 val = DRF_NUM64(d, _ ## r, _ ## f, _v); \
    UVM_ASSERT_MSG(_v == DRF_VAL64(d, _ ## r, _ ## f, val), \
                   "HWVALUE64 input does not fit its field"); \
    val; \
})
#define WRITE_HWCONST64(v, d, r, f, c) FLD_SET_DRF64(d, _ ## r, _ ## f, _ ## c, (v))
'''


def required_source(root: Path, relative: str) -> Path:
    path = (root / relative).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"not a source file: {path}")
    return path


def _function(name: str, signature: str, body: str, return_type: str = "NvU64") -> str:
    return f"static {return_type} {name}{signature}\n{{{body}\n}}\n"


def extract_test_vectors(page_tree_test: str) -> None:
    compact = "".join(page_tree_test.split())
    required_fragments = (
        "unmapped_pte(page_size)==0x20",
        "unmapped_pte(page_size)==0",
        "make_pte(UVM_APERTURE_SYS,0x399999999999000LL,UVM_PROT_READ_ONLY,UVM_MMU_PTE_FLAGS_CACHED)==0x399999999999C5",
        "make_pte(UVM_APERTURE_VID,0x1BBBBBB000LL,UVM_PROT_READ_ONLY,UVM_MMU_PTE_FLAGS_CACHED)==0x1BBBBBBC1",
        "make_pte(UVM_APERTURE_PEER_0,0x1BBBBBB000LL,UVM_PROT_READ_ONLY,UVM_MMU_PTE_FLAGS_CACHED)==0x1BBBBBBC3",
        "make_pte(UVM_APERTURE_PEER_0,0x5BBBBBBBB000LL,UVM_PROT_READ_ONLY,UVM_MMU_PTE_FLAGS_CACHED)==0x2DD1BBBBBBC3",
        "alloc_sys=fake_table_alloc(UVM_APERTURE_SYS,0x399999999999000LL)",
        "alloc_vid=fake_table_alloc(UVM_APERTURE_VID,0x1BBBBBB000LL)",
        "alloc_big_sys=fake_table_alloc(UVM_APERTURE_SYS,0x399999999999900LL)",
        "alloc_big_vid=fake_table_alloc(UVM_APERTURE_VID,0x1BBBBBBB00LL)",
        "pde_bits[0]==0x3999999999990C",
        "pde_bits[0]==0x1BBBBBB0A",
        "pde_bits[0]==0x3999999999999C&&pde_bits[1]==0x1BBBBBB0A",
        "pde_bits[0]==0x1BBBBBBBA&&pde_bits[1]==0x3999999999990C",
        "if(g_uvm_global.ats.enabled)TEST_CHECK_RET(pde_bits[0]==0x1BBBBBB2A)",
        "elseTEST_CHECK_RET(pde_bits[0]==0x1BBBBBB0A)",
    )
    missing = [fragment for fragment in required_fragments if fragment not in compact]
    if missing:
        raise ValueError("pinned R580 page-tree vectors changed (PTE/PDE): " + "; ".join(missing))


def _typedef_struct_body(source: str, name: str) -> str:
    source = _mask_c_comments(source)
    for match in re.finditer(r"typedef\s+struct\s*\{", source):
        opening = match.end() - 1
        depth = 0
        for offset in range(opening, len(source)):
            if source[offset] == "{":
                depth += 1
            elif source[offset] == "}":
                depth -= 1
                if depth == 0:
                    trailer = source[offset + 1:offset + 160]
                    if re.match(rf"\s*{re.escape(name)}\s*;", trailer):
                        return source[opening + 1:offset]
                    break
    raise ValueError(f"pinned R580 typedef not found: {name}")


def _tagged_struct_body(source: str, name: str) -> str:
    source = _mask_c_comments(source)
    match = re.search(rf"struct\s+{re.escape(name)}\s*\{{", source)
    if match is None:
        raise ValueError(f"pinned R580 struct not found: {name}")
    opening = match.end() - 1
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:offset]
    raise ValueError(f"unterminated pinned R580 struct: {name}")


def verify_pde_type_contract(hal_types: str,
                             mmu_header: str,
                             global_header: str,
                             r580_volta_mmu: str,
                             candidate_volta_mmu: str) -> None:
    """Check the bounded host shims against the exact R580 field declarations."""
    address_body = "".join(_typedef_struct_body(hal_types, "uvm_gpu_phys_address_t").split())
    if not re.search(r"NvU64address;uvm_aperture_taperture;", address_body):
        raise ValueError("pinned R580 physical-address field contract changed")

    alloc_body = "".join(_typedef_struct_body(mmu_header, "uvm_mmu_page_table_alloc_t").split())
    if "uvm_gpu_phys_address_taddr;" not in alloc_body:
        raise ValueError("pinned R580 page-table allocation address field changed")

    directory_body = "".join(_tagged_struct_body(mmu_header, "uvm_page_directory_struct").split())
    if "NvU32depth;" not in directory_body:
        raise ValueError("pinned R580 page-directory depth field changed")

    global_compact = "".join(_mask_c_comments(global_header).split())
    if not re.search(r"boolsupported;boolenabled;\}ats;", global_compact):
        raise ValueError("pinned R580 ATS-enabled global field contract changed")

    expected_macros = {"MMU_BIG": "0", "MMU_SMALL": "1"}
    for label, source in (("R580", r580_volta_mmu), ("candidate", candidate_volta_mmu)):
        macro_rows = re.findall(
            r"^[ \t]*#[ \t]*define[ \t]+(MMU_BIG|MMU_SMALL)[ \t]+([0-9]+)\b",
            _mask_c_comments(source),
            flags=re.MULTILINE,
        )
        macros = dict(macro_rows)
        if len(macro_rows) != 2 or macros != expected_macros:
            raise ValueError(f"{label} MMU_BIG/MMU_SMALL source contract changed: {macros}")


def verify_volta_mmu_header_identity(r580_header: bytes, candidate_header: bytes) -> None:
    """Require the staged GV100 field definitions to match the pinned R580 header."""
    if r580_header != candidate_header:
        raise ValueError("candidate GV100 MMU header differs from pinned R580 header")


def verify_type_contract(hal_types: str, mmu_header: str) -> None:
    """Ensure bounded C typedef shims retain exact pinned UVM enum values."""
    masked_hal = _mask_c_comments(hal_types)

    def enum_members(name: str) -> list[str]:
        match = re.search(
            rf"typedef\s+enum\s*\{{([^}}]*)\}}\s*{re.escape(name)}\s*;",
            masked_hal,
            flags=re.DOTALL,
        )
        if match is None:
            raise ValueError(f"pinned R580 enum definition not found: {name}")
        members = []
        for item in match.group(1).split(","):
            item = item.strip()
            if item:
                members.append(item.split("=", 1)[0].strip().split()[0])
        return members

    expected_apertures = [
        *(f"UVM_APERTURE_PEER_{index}" for index in range(8)),
        "UVM_APERTURE_PEER_MAX", "UVM_APERTURE_SYS",
        "UVM_APERTURE_SYS_NON_COHERENT", "UVM_APERTURE_VID",
        "UVM_APERTURE_DEFAULT", "UVM_APERTURE_MAX",
    ]
    expected_protections = [
        "UVM_PROT_NONE", "UVM_PROT_READ_ONLY", "UVM_PROT_READ_WRITE",
        "UVM_PROT_READ_WRITE_ATOMIC", "UVM_PROT_MAX",
    ]
    if enum_members("uvm_aperture_t") != expected_apertures:
        raise ValueError("pinned R580 aperture enumeration changed")
    if enum_members("uvm_prot_t") != expected_protections:
        raise ValueError("pinned R580 protection enumeration changed")
    peer_predicate = extract_function(hal_types, "uvm_aperture_is_peer")
    if "".join(peer_predicate.split()) != (
            "return(aperture>=UVM_APERTURE_PEER_0)&&(aperture<UVM_APERTURE_PEER_MAX);"):
        raise ValueError("pinned R580 peer-aperture range contract changed")
    peer_id_body = extract_function(hal_types, "UVM_APERTURE_PEER_ID")
    compact_peer_id = "".join(peer_id_body.split())
    if ("UVM_ASSERT(uvm_aperture_is_peer(aperture));" not in compact_peer_id or
            "return(NvU32)aperture;" not in compact_peer_id):
        raise ValueError("pinned R580 peer aperture ID mapping changed")

    compact_mmu = "".join(_mask_c_comments(mmu_header).split())
    expected_flags = (
        "UVM_MMU_PTE_FLAGS_NONE=0",
        "UVM_MMU_PTE_FLAGS_CACHED=(1<<0)",
        "UVM_MMU_PTE_FLAGS_ACCESS_COUNTERS_DISABLED=(1<<1)",
        "UVM_MMU_PTE_FLAGS_MASK=(1<<2)-1",
    )
    missing = [row for row in expected_flags if row not in compact_mmu]
    if missing:
        raise ValueError("pinned R580 PTE flag values changed: " + ", ".join(missing))


def build_harness(r580_uvm: Path, candidate_uvm: Path) -> tuple[str, dict[str, Path]]:
    files = {
        "r580_pascal_mmu": required_source(r580_uvm, "uvm_pascal_mmu.c"),
        "r580_volta_mmu": required_source(r580_uvm, "uvm_volta_mmu.c"),
        "r580_page_tree_test": required_source(r580_uvm, "uvm_page_tree_test.c"),
        "r580_hal_types": required_source(r580_uvm, "uvm_hal_types.h"),
        "r580_mmu_header": required_source(r580_uvm, "uvm_mmu.h"),
        "r580_global_h": required_source(r580_uvm, "uvm_global.h"),
        "candidate_pascal_mmu": required_source(candidate_uvm, "uvm_pascal_mmu.c"),
        "candidate_volta_mmu": required_source(candidate_uvm, "uvm_volta_mmu.c"),
        "nvtypes": required_source(r580_uvm.parent / "common/inc", "nvtypes.h"),
        "nvmisc": required_source(r580_uvm.parent / "common/inc", "nvmisc.h"),
        "uvm_user_types": required_source(r580_uvm.parent / "common/inc", "nv_uvm_user_types.h"),
        "r580_volta_dev_mmu": required_source(r580_uvm, "hwref/volta/gv100/dev_mmu.h"),
        "volta_dev_mmu": required_source(candidate_uvm, "hwref/volta/gv100/dev_mmu.h"),
        "pascal_dev_mmu": required_source(r580_uvm, "hwref/pascal/gp100/dev_mmu.h"),
    }
    verify_volta_mmu_header_identity(
        files["r580_volta_dev_mmu"].read_bytes(), files["volta_dev_mmu"].read_bytes())
    texts = {key: path.read_text(encoding="utf-8") for key, path in files.items()}
    extract_test_vectors(texts["r580_page_tree_test"])
    verify_type_contract(texts["r580_hal_types"], texts["r580_mmu_header"])
    verify_pde_type_contract(texts["r580_hal_types"], texts["r580_mmu_header"],
                             texts["r580_global_h"], texts["r580_volta_mmu"],
                             texts["candidate_volta_mmu"])

    function_sources = [
        _function("r580_make_pte_pascal",
                  "(uvm_aperture_t aperture, NvU64 address, uvm_prot_t prot, NvU64 flags)",
                  extract_function(texts["r580_pascal_mmu"], "make_pte_pascal")),
        _function("r580_unmapped_pte_pascal", "(NvU64 page_size)",
                  extract_function(texts["r580_pascal_mmu"], "unmapped_pte_pascal")),
        _function("r580_poisoned_pte_pascal", "(void)",
                  extract_function(texts["r580_pascal_mmu"], "poisoned_pte_pascal").replace(
                      "make_pte_pascal(", "r580_make_pte_pascal(", 1)),
        _function("r580_make_pte_volta",
                  "(uvm_aperture_t aperture, NvU64 address, uvm_prot_t prot, NvU64 flags)",
                  extract_function(texts["r580_volta_mmu"], "make_pte_volta")),
        _function("candidate_make_pte_volta",
                  "(uvm_aperture_t aperture, NvU64 address, uvm_prot_t prot, NvU64 flags)",
                  extract_function(texts["candidate_volta_mmu"], "make_pte_volta")),
        _function("candidate_unmapped_pte_pascal", "(void)",
                  extract_function(texts["candidate_pascal_mmu"], "unmapped_pte_pascal")),
    ]
    candidate_poisoned = extract_function(texts["candidate_pascal_mmu"], "poisoned_pte_pascal")

    pde_function_sources = []
    pde_functions = (
        ("entries_per_index_volta", "(NvU32 depth)", "NvU32"),
        ("single_pde_volta", "(uvm_mmu_page_table_alloc_t *phys_alloc, NvU32 depth)", "NvU64"),
        ("big_half_pde_volta", "(uvm_mmu_page_table_alloc_t *phys_alloc)", "NvU64"),
        ("small_half_pde_volta", "(uvm_mmu_page_table_alloc_t *phys_alloc)", "NvU64"),
        ("make_pde_volta", "(void *entry, uvm_mmu_page_table_alloc_t **phys_allocs, "
         "uvm_page_directory_t *dir, NvU32 child_index __attribute__((unused)))", "void"),
    )
    for prefix, source in (("r580", texts["r580_volta_mmu"]),
                           ("candidate", texts["candidate_volta_mmu"])):
        pde_function_sources.extend(
            f"#define {original} {prefix}_{original}" for original, _, _ in pde_functions
        )
        pde_function_sources.extend(
            _function(original, signature, extract_function(source, original),
                      return_type=return_type)
            for original, signature, return_type in pde_functions
        )
        pde_function_sources.extend(
            f"#undef {original}" for original, _, _ in pde_functions
        )

    harness = HARNESS_PREFIX + "\n".join(function_sources) + r'''
typedef struct {
    NvU64 (*make_pte)(uvm_aperture_t, NvU64, uvm_prot_t, NvU64);
} uvm_mmu_mode_hal_t;
typedef struct { uvm_mmu_mode_hal_t *hal; } uvm_page_tree_t;
''' + _function("candidate_poisoned_pte_pascal", "(uvm_page_tree_t *tree)", candidate_poisoned) + "\n" + "\n".join(pde_function_sources) + r'''

static int check(const char *name, NvU64 actual, NvU64 expected)
{
    printf("%s actual=0x%llx expected=0x%llx\n", name,
           (unsigned long long)actual, (unsigned long long)expected);
    return actual == expected ? 0 : 1;
}

static int check_pde_vector(const char *prefix,
                            void (*make_pde)(void *, uvm_mmu_page_table_alloc_t **,
                                             uvm_page_directory_t *, NvU32),
                            int vector)
{
    uvm_mmu_page_table_alloc_t alloc_sys = { .addr = {0x399999999999000ULL, UVM_APERTURE_SYS} };
    uvm_mmu_page_table_alloc_t alloc_vid = { .addr = {0x1BBBBBB000ULL, UVM_APERTURE_VID} };
    uvm_mmu_page_table_alloc_t alloc_big_sys = { .addr = {0x399999999999900ULL, UVM_APERTURE_SYS} };
    uvm_mmu_page_table_alloc_t alloc_big_vid = { .addr = {0x1BBBBBBB00ULL, UVM_APERTURE_VID} };
    uvm_mmu_page_table_alloc_t *phys_allocs[2] = {NULL, NULL};
    uvm_page_directory_t dir = { .depth = 0 };
    NvU64 pde_bits[2] = {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
    char label[96];
    int failures = 0;

    if (vector == 0 || vector == 1) {
        dir.depth = vector == 0 ? 0 : 3;
        make_pde(pde_bits, phys_allocs, &dir, 0);
        if (vector == 0) {
            snprintf(label, sizeof(label), "%s-zero-pde", prefix);
            failures += check(label, pde_bits[0], 0x0ULL);
        }
        else {
            snprintf(label, sizeof(label), "%s-zero-dual-pde-low", prefix);
            failures += check(label, pde_bits[0], 0x0ULL);
            snprintf(label, sizeof(label), "%s-zero-dual-pde-high", prefix);
            failures += check(label, pde_bits[1], 0x0ULL);
        }
        return failures;
    }

    if (vector == 2 || vector == 3) {
        phys_allocs[0] = vector == 2 ? &alloc_sys : &alloc_vid;
        dir.depth = 0;
        make_pde(pde_bits, phys_allocs, &dir, 0);
        snprintf(label, sizeof(label), "%s-single-%s-pde", prefix,
                 vector == 2 ? "sys" : "vid");
        return check(label, pde_bits[0], vector == 2 ? 0x3999999999990CULL : 0x1BBBBBB0AULL);
    }

    if (vector == 4 || vector == 5) {
        phys_allocs[0] = vector == 4 ? &alloc_big_sys : &alloc_big_vid;
        phys_allocs[1] = vector == 4 ? &alloc_vid : &alloc_sys;
        dir.depth = 3;
        make_pde(pde_bits, phys_allocs, &dir, 0);
        snprintf(label, sizeof(label), "%s-dual-pde-%s-low", prefix,
                 vector == 4 ? "big-sys-small-vid" : "big-vid-small-sys");
        failures += check(label, pde_bits[0], vector == 4 ? 0x3999999999999CULL : 0x1BBBBBBBAULL);
        snprintf(label, sizeof(label), "%s-dual-pde-%s-high", prefix,
                 vector == 4 ? "big-sys-small-vid" : "big-vid-small-sys");
        failures += check(label, pde_bits[1], vector == 4 ? 0x1BBBBBB0AULL : 0x3999999999990CULL);
        return failures;
    }

    phys_allocs[0] = &alloc_vid;
    dir.depth = 2;
    g_uvm_global.ats.enabled = vector == 7;
    make_pde(pde_bits, phys_allocs, &dir, 0);
    snprintf(label, sizeof(label), "%s-no-ats-depth2-%s", prefix,
             vector == 7 ? "enabled" : "disabled");
    return check(label, pde_bits[0], vector == 7 ? 0x1BBBBBB2AULL : 0x1BBBBBB0AULL);
}

static NvU64 next_pte_random(NvU64 *state)
{
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    return *state * 2685821657736338717ULL;
}

static int check_differential_pte_vectors(void)
{
    static const uvm_aperture_t apertures[] = {
        UVM_APERTURE_SYS, UVM_APERTURE_SYS_NON_COHERENT, UVM_APERTURE_VID,
        UVM_APERTURE_PEER_0, UVM_APERTURE_PEER_1, UVM_APERTURE_PEER_2,
        UVM_APERTURE_PEER_3, UVM_APERTURE_PEER_4, UVM_APERTURE_PEER_5,
        UVM_APERTURE_PEER_6, UVM_APERTURE_PEER_7,
    };
    static const uvm_prot_t protections[] = {
        UVM_PROT_READ_ONLY, UVM_PROT_READ_WRITE, UVM_PROT_READ_WRITE_ATOMIC,
    };
    static const NvU64 flags[] = {0, 1, 2, 3};
    static const NvU32 trials_per_tuple = 64;
    NvU64 state = 0x4d595df4d0f33173ULL;
    NvU32 vectors = 0;

    for (NvU32 aperture_index = 0;
         aperture_index < sizeof(apertures) / sizeof(apertures[0]);
         ++aperture_index) {
        const uvm_aperture_t aperture = apertures[aperture_index];
        const NvU64 address_mask =
            (aperture == UVM_APERTURE_SYS || aperture == UVM_APERTURE_SYS_NON_COHERENT)
                ? ((1ULL << 58) - 1)
                : ((1ULL << 47) - 1);

        for (NvU32 protection_index = 0;
             protection_index < sizeof(protections) / sizeof(protections[0]);
             ++protection_index) {
            for (NvU32 flag_index = 0;
                 flag_index < sizeof(flags) / sizeof(flags[0]);
                 ++flag_index) {
                for (NvU32 trial = 0; trial < trials_per_tuple; ++trial) {
                    NvU64 address;
                    NvU64 expected;
                    NvU64 actual;
                    const uvm_prot_t protection = protections[protection_index];
                    const NvU64 pte_flags = flags[flag_index];

                    if (trial == 0)
                        address = 0;
                    else if (trial == 1)
                        address = 0x1000ULL;
                    else if (trial == 2)
                        address = (aperture == UVM_APERTURE_SYS ||
                                   aperture == UVM_APERTURE_SYS_NON_COHERENT)
                                      ? (1ULL << 56) : (1ULL << 46);
                    else if (trial == 3)
                        address = address_mask & ~0xFFFULL;
                    else
                        address = next_pte_random(&state) & address_mask & ~0xFFFULL;

                    if (aperture == UVM_APERTURE_SYS_NON_COHERENT) {
                        expected = r580_make_pte_volta(UVM_APERTURE_SYS, address,
                                                       protection, pte_flags);
                        expected &= ~DRF_SHIFTMASK64(NV_MMU_VER2_PTE_APERTURE);
                        expected |= HWVALUE64(
                            _MMU_VER2, PTE, APERTURE,
                            NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY);
                    }
                    else {
                        expected = r580_make_pte_volta(aperture, address,
                                                       protection, pte_flags);
                    }
                    actual = candidate_make_pte_volta(aperture, address,
                                                      protection, pte_flags);
                    if (actual != expected) {
                        printf("pte-differential-mismatch vector=%u aperture=%u "
                               "address=0x%llx protection=%u flags=0x%llx "
                               "expected=0x%llx actual=0x%llx\n",
                               vectors, (unsigned)aperture,
                               (unsigned long long)address, (unsigned)protection,
                               (unsigned long long)pte_flags,
                               (unsigned long long)expected,
                               (unsigned long long)actual);
                        return 1;
                    }
                    ++vectors;
                }
            }
        }
    }

    printf("pte-differential-vectors=%u seed=0x4d595df4d0f33173 "
           "noncoherent=generated-field-substitution\n", vectors);
    return vectors == 8448 ? 0 : 1;
}

int main(int argc, char **argv)
{
    uvm_mmu_mode_hal_t hal = { .make_pte = candidate_make_pte_volta };
    uvm_page_tree_t tree = { .hal = &hal };
    int failures = 0;

    if (argc == 2 && strcmp(argv[1], "--probe-hwvalue64-overflow") == 0) {
        (void)HWVALUE64(_MMU_VER2, PDE, ADDRESS_SYS, 1ULL << 46);
        return 99;
    }
    if (argc == 2 && strcmp(argv[1], "--probe-peer-id-overflow") == 0) {
        (void)UVM_APERTURE_PEER_ID(UVM_APERTURE_SYS);
        return 98;
    }

    failures += check("r580-unmapped-64k", r580_unmapped_pte_pascal(UVM_PAGE_SIZE_64K), 0x20ULL);
    failures += check("r580-unmapped-4k", r580_unmapped_pte_pascal(UVM_PAGE_SIZE_4K), 0ULL);
    failures += check("candidate-unmapped-64k", candidate_unmapped_pte_pascal(), 0x20ULL);
    failures += check("sys-cached-readonly",
        candidate_make_pte_volta(UVM_APERTURE_SYS, 0x399999999999000ULL,
                                 UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED),
        0x399999999999C5ULL);
    failures += check("candidate-sys-noncoherent-bar1",
        candidate_make_pte_volta(UVM_APERTURE_SYS_NON_COHERENT,
                                 0x399999999999000ULL,
                                 UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED),
        0x399999999999C7ULL);
    failures += check("vid-cached-readonly",
        candidate_make_pte_volta(UVM_APERTURE_VID, 0x1BBBBBB000ULL,
                                 UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED),
        0x1BBBBBBC1ULL);
    failures += check("peer0-low-cached-readonly",
        candidate_make_pte_volta(UVM_APERTURE_PEER_0, 0x1BBBBBB000ULL,
                                 UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED),
        0x1BBBBBBC3ULL);
    failures += check("peer0-47bit-cached-readonly",
        candidate_make_pte_volta(UVM_APERTURE_PEER_0, 0x5BBBBBBBB000ULL,
                                 UVM_PROT_READ_ONLY, UVM_MMU_PTE_FLAGS_CACHED),
        0x2DD1BBBBBBC3ULL);
    failures += check("r580-poisoned-pascal", r580_poisoned_pte_pascal(), 0x1BAD000E9ULL);
    failures += check("candidate-poisoned-volta",
                      candidate_poisoned_pte_pascal(&tree), 0x1BAD000E9ULL);
    failures += check_differential_pte_vectors();
    for (int vector = 0; vector < 8; ++vector) {
        failures += check_pde_vector("r580", r580_make_pde_volta, vector);
        failures += check_pde_vector("candidate", candidate_make_pde_volta, vector);
    }
    return failures ? 1 : 0;
}
'''
    return harness, files


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _expected_result_labels() -> list[str]:
    labels = [
        "r580-unmapped-64k", "r580-unmapped-4k", "candidate-unmapped-64k",
        "sys-cached-readonly", "candidate-sys-noncoherent-bar1",
        "vid-cached-readonly", "peer0-low-cached-readonly",
        "peer0-47bit-cached-readonly", "r580-poisoned-pascal", "candidate-poisoned-volta",
    ]
    for vector in range(8):
        for prefix in ("r580", "candidate"):
            if vector == 0:
                suffixes = ["zero-pde"]
            elif vector == 1:
                suffixes = ["zero-dual-pde-low", "zero-dual-pde-high"]
            elif vector == 2:
                suffixes = ["single-sys-pde"]
            elif vector == 3:
                suffixes = ["single-vid-pde"]
            elif vector in (4, 5):
                order = "big-sys-small-vid" if vector == 4 else "big-vid-small-sys"
                suffixes = [f"dual-pde-{order}-low", f"dual-pde-{order}-high"]
            else:
                ats = "enabled" if vector == 7 else "disabled"
                suffixes = [f"no-ats-depth2-{ats}"]
            labels.extend(f"{prefix}-{suffix}" for suffix in suffixes)
    return labels


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


def run(r580_uvm: Path, candidate_uvm: Path, report_path: Path, log_path: Path,
        compiler: str = "cc") -> dict:
    r580_uvm = r580_uvm.resolve(strict=True)
    candidate_uvm = candidate_uvm.resolve(strict=True)
    common_inc = (r580_uvm.parent / "common/inc").resolve(strict=True)
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise ValueError(f"compiler not found: {compiler}")
    version = subprocess.run([compiler_path, "--version"], capture_output=True, text=True, check=True)
    harness, files = build_harness(r580_uvm, candidate_uvm)
    harness_bytes = harness.encode("utf-8")
    report_path = report_path.resolve()
    log_path = log_path.resolve()
    if report_path.exists() or log_path.exists():
        raise FileExistsError("refusing to overwrite host-harness evidence")

    logs = []
    with tempfile.TemporaryDirectory(prefix="volta-mmu-host-harness-") as directory:
        temporary = Path(directory)
        c_source = temporary / "volta_mmu_host_harness.c"
        binary = temporary / "volta_mmu_host_harness"
        c_source.write_bytes(harness_bytes)
        command = [compiler_path, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-I", str(common_inc), "-I", str(candidate_uvm), str(c_source), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True)
        logs.append("$ " + shlex.join(command) + "\n" + compiled.stdout + compiled.stderr)
        if compiled.returncode != 0:
            raise RuntimeError("host harness compilation failed; see log: " + "".join(logs))
        executed = subprocess.run([str(binary)], capture_output=True, text=True)
        logs.append("$ " + shlex.quote(str(binary)) + "\n" + executed.stdout + executed.stderr)
        if executed.returncode != 0:
            raise RuntimeError("host harness vector check failed; see log: " + "".join(logs))
        differential_summary = (
            "pte-differential-vectors=8448 seed=0x4d595df4d0f33173 "
            "noncoherent=generated-field-substitution"
        )
        if executed.stdout.count(differential_summary) != 1:
            raise RuntimeError("host harness differential vector summary missing or ambiguous")

        assertion_guards = (
            ("hwvalue64-field-overflow", "--probe-hwvalue64-overflow", "_v =="),
            ("peer-id-out-of-range", "--probe-peer-id-overflow",
             "_aperture >= UVM_APERTURE_PEER_0"),
        )
        guard_results = []
        for name, argument, expected_assertion in assertion_guards:
            probe = subprocess.run([str(binary), argument], capture_output=True, text=True,
                                   preexec_fn=_disable_core_dumps)
            logs.append("$ " + shlex.quote(str(binary)) + " " + argument + "\n"
                        "expected assertion rejection; returncode=" + str(probe.returncode) + "\n"
                        + probe.stdout + probe.stderr)
            if (probe.returncode != -signal.SIGABRT or expected_assertion not in probe.stderr):
                raise RuntimeError(f"assertion guard failed: {name}; see log: " + "".join(logs))
            guard_results.append({"name": name, "status": "passed",
                                  "expected_assertion_text": expected_assertion})

    results = [line for line in "".join(logs).splitlines() if " actual=0x" in line]
    result_labels = [line.split(" actual=0x", 1)[0] for line in results]
    if result_labels != _expected_result_labels():
        raise RuntimeError("host harness result-label set/order changed: " + repr(result_labels))

    log_bytes = "".join(logs).encode("utf-8")
    report = {
        "schema": "volta-mmu-host-harness-v6",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "classification": "host-executed-source-callback-contract",
        "compiler": {"path": compiler_path, "version": version.stdout.splitlines()[0]},
        "compile_flags": ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "harness_source_sha256": hashlib.sha256(harness_bytes).hexdigest(),
        "checks_passed": len(results),
        "assertion_guard_checks_passed": len(guard_results),
        "assertion_guard_results": guard_results,
        "differential_pte": {
            "vectors_passed": 8448,
            "seed_hex": "0x4d595df4d0f33173",
            "apertures": ["SYS", "SYS_NON_COHERENT", "VID", "PEER_0..PEER_7"],
            "protections": ["READ_ONLY", "READ_WRITE", "READ_WRITE_ATOMIC"],
            "flags": [0, 1, 2, 3],
            "addresses_per_aperture_protection_flags_tuple": 64,
            "system_address_bits": 58,
            "video_and_peer_address_bits": 47,
            "noncoherent_oracle": "R580 SYS encoding with only the generated GV100 aperture field replaced",
        },
        "results": results,
        "sources": {
            key: {"path": str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                  "sha256": sha256_file(path)}
            for key, path in files.items()
        },
        "log": str(log_path),
        "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "hardware_validated": False,
        "module_loaded": False,
        "module_installed": False,
        "limitations": [
            "The harness executes selected callback source on the host CPU, not the GPU.",
            "The aperture/protection, page-table allocation, page-directory, and ATS-global declarations are bounded test shims checked against pinned R580 field contracts; NVIDIA DRF macros and generated GV100 fields are included from pinned headers.",
            "Callback helper names are preprocessor-namespaced to execute R580 and candidate bodies in one host translation unit; the poisoned-PTE call target is similarly renamed to avoid symbol collision.",
            "The candidate generated GV100 MMU header must be byte-identical to the pinned R580 header. The HWVALUE64 shim retains the source round-trip assertion, exercised with a field-overflow rejection probe.",
            "This does not validate page-table memory ordering, GPU interpretation, UVM, CUDA, P2P, or any complete kernel module.",
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
        "checks_passed": report["checks_passed"],
        "hardware_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-uvm", type=Path, required=True)
    parser.add_argument("--candidate-uvm", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    print(json.dumps(run(args.r580_uvm, args.candidate_uvm,
                         args.report, args.log, args.compiler), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"host MMU harness failed: {error}", file=sys.stderr)
        raise SystemExit(2)
