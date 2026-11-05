#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host-execute the exact GV100 Volta fault-buffer index callbacks."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import run_volta_fault_decode_host_harness as source_tools

DEFAULT_R580_UVM = source_tools.DEFAULT_R580_UVM
DEFAULT_R595_UVM = source_tools.DEFAULT_R595_UVM
PINNED_VOLTA_FAULT_SOURCE_SHA256 = "d0b8cfcf715246b49741314e0009b78c798719b634269ee44a75ee12f9874e77"
PINNED_GV100_FB_HEADER_SHA256 = "0175a270fa5af9d3a62d7fda2c9e536b58551db6bb1e9c123b84ffeec9a32584"
PINNED_R580_SERVICE_SOURCE_SHA256 = "c7991f9a9e029ae1e9dc4aba579ecb37c64408d9600117abdeec82fbc1b245b3"
PINNED_R595_SERVICE_SOURCE_SHA256 = "e2b98f550ad6ef3efb062d931834f09acd79ecd5fa140a2f54de8e77a5dfac2b"
PINNED_R580_COMMON_HEADER_SHA256 = "0666a8f60e034f8461b06b208b1ebe8b8425ff91149fa956533c0a6bda3914d6"
PINNED_R595_COMMON_HEADER_SHA256 = "c93140e96f0dc70b6ae94a80aca1015f95464161f2af2d719dde849c80c8f977"
PINNED_R580_FLUSH_BODY_SHA256 = "2bccc613de4d63a923f5fb07dbad7bda8c3bde0952ddb466b133c5eb2edab81a"
PINNED_R595_FLUSH_BODY_SHA256 = "84bd10cc2b37265fb93c1b8e289928a785f481736c575684eb49f9aae13c6260"
FUNCTIONS = (
    ("uvm_hal_volta_fault_buffer_read_put",
     "NvU32 uvm_hal_volta_fault_buffer_read_put(uvm_parent_gpu_t *parent_gpu)"),
    ("uvm_hal_volta_fault_buffer_read_get",
     "NvU32 uvm_hal_volta_fault_buffer_read_get(uvm_parent_gpu_t *parent_gpu)"),
    ("uvm_hal_volta_fault_buffer_write_get",
     "void uvm_hal_volta_fault_buffer_write_get(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
)
RING_CALLBACKS = {
    "read_put": "uvm_hal_volta_fault_buffer_read_put",
    "read_get": "uvm_hal_volta_fault_buffer_read_get",
    "write_get": "uvm_hal_volta_fault_buffer_write_get",
}
GUARDS = (
    "--probe-put-getptr-corrupted",
    "--probe-get-out-of-range",
    "--probe-get-overflow-status",
    "--probe-write-get-out-of-range",
)
VOLTA_GET_REGISTER_FIELDS = {
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET(i)": "(0x00100E2C+(i)*20)",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET__SIZE_1": "2",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_PTR": "19:0",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_GETPTR_CORRUPTED": "30:30",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_GETPTR_CORRUPTED_NO": "0x00000000",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_GETPTR_CORRUPTED_YES": "0x00000001",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_GETPTR_CORRUPTED_CLEAR": "0x00000001",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_OVERFLOW": "31:31",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_OVERFLOW_NO": "0x00000000",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_OVERFLOW_YES": "0x00000001",
    "NV_PFB_PRI_MMU_FAULT_BUFFER_GET_OVERFLOW_CLEAR": "0x00000001",
}
SERVICE_HELPERS = (
    ("write_get",
     "static void write_get(uvm_parent_gpu_t *parent_gpu, NvU32 get)"),
    ("fault_buffer_skip_replayable_entry",
     "static void fault_buffer_skip_replayable_entry(uvm_parent_gpu_t *parent_gpu, NvU32 index)"),
)


def _read_get_register_contract(header_path: Path) -> dict[str, str]:
    """Read the exact GV100 GET field definitions used by the host harness."""
    definitions = {}
    for line in header_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#define "):
            continue
        parts = line.split(None, 2)
        if len(parts) != 3 or parts[1] not in VOLTA_GET_REGISTER_FIELDS:
            continue
        definitions[parts[1]] = parts[2].split("/*", 1)[0].strip()
    if definitions != VOLTA_GET_REGISTER_FIELDS:
        raise ValueError("GV100 GET register field contract differs from the pinned Volta layout")
    return dict(VOLTA_GET_REGISTER_FIELDS)


def _extract_service_drain_loop(source: str) -> str:
    masked = source_tools._mask_comments(source)
    matches = list(re.finditer(r"\bwhile\s*\(\s*get\s*!=\s*put\s*\)\s*\{", masked))
    if len(matches) != 1:
        raise ValueError(f"expected one replayable fault drain loop, found {len(matches)}")
    opening = matches[0].end() - 1
    depth = 0
    for offset in range(opening, len(masked)):
        if masked[offset] == "{":
            depth += 1
        elif masked[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[matches[0].start():offset + 1]
    raise ValueError("unterminated replayable fault drain loop")


def _build_source(uvm_root: Path) -> str:
    prefix = r'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nvtypes.h"
#include "nvstatus.h"
#include "nvmisc.h"
#include "hwref/volta/gv100/dev_fb.h"

#ifdef TEST_RELEASE_UVM_ASSERTS
// Pinned uvm_common.h compiles UVM_ASSERT away on release builds.
#define UVM_ASSERT(condition) do { (void)sizeof(condition); } while (0)
#define UVM_ASSERT_MSG(condition, ...) do { (void)sizeof(condition); } while (0)
#else
#define UVM_ASSERT(condition) assert(condition)
#define UVM_ASSERT_MSG(condition, ...) assert(condition)
#endif
#define READ_HWVALUE(v, d, r, f) DRF_VAL(d, _##r, _##f, (v))
#define HWCONST(d, r, f, c) DRF_DEF(d, _##r, _##f, _##c)
#define HWVALUE(d, r, f, v) ({ \
    NvU32 _field_value = (NvU32)(v); \
    NvU32 _encoded = DRF_NUM(d, _##r, _##f, _field_value); \
    UVM_ASSERT_MSG(_field_value == DRF_VAL(d, _##r, _##f, _encoded), "field value out of range"); \
    _encoded; \
})
#define UVM_SPIN_WHILE(condition, spin) for ((void)(spin); (condition); )

static struct { bool conf_computing_enabled; } g_uvm_global;
static NvU32 read_count;
static NvU32 write_count;
static NvU32 write_values[4];
static NvU32 entry_valid_calls;
static NvU32 entry_clear_calls;
static NvU32 entry_valid_indices[64];
static NvU32 entry_clear_indices[64];
static bool entry_state[64];
static NvU32 decrypt_iv_calls;
static NV_STATUS global_status;
static NV_STATUS channel_status;
static NV_STATUS tracker_status;
static NV_STATUS hw_flush_status;
static NV_STATUS parent_replay_status;
static NV_STATUS gpu_replay_status;
static NvU32 global_status_calls;
static NvU32 channel_error_calls;
static NvU32 tracker_wait_calls;
static NvU32 hw_flush_calls;
static NvU32 hw_flush_mode;
static NvU32 parent_replay_calls;
static NvU32 gpu_replay_calls;
static NvU32 assertion_count;
static NvU32 failures;

typedef enum {
    UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT,
    UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT,
    UVM_GPU_BUFFER_FLUSH_MODE_WAIT_UPDATE_PUT,
} uvm_gpu_buffer_flush_mode_t;
typedef enum { HW_FAULT_BUFFER_FLUSH_MODE_DISCARD, HW_FAULT_BUFFER_FLUSH_MODE_MOVE } hw_fault_buffer_flush_mode_t;
typedef enum {
    UVM_FAULT_REPLAY_TYPE_START,
    UVM_FAULT_REPLAY_TYPE_START_ACK_ALL,
    UVM_FAULT_REPLAY_TYPE_MAX,
} uvm_fault_replay_type_t;
typedef struct { NvU32 marker; } uvm_fault_service_batch_context_t;
static uvm_fault_service_batch_context_t test_batch_context = { .marker = 0x51A7 };
static uvm_fault_replay_type_t last_replay_type;
static uvm_fault_service_batch_context_t *last_batch_context;
typedef struct {
    NvU32 max_faults;
    NvU32 cached_get;
    NvU32 cached_put;
    NvU32 replay_tracker;
} uvm_fault_buffer_replayable_t;
typedef uvm_fault_buffer_replayable_t uvm_replayable_fault_buffer_t;
typedef struct {
    volatile NvU32 *pFaultBufferPut;
    volatile NvU32 *pFaultBufferGet;
} uvm_fault_buffer_rm_replayable_t;
typedef struct {
    uvm_fault_buffer_replayable_t replayable;
    struct { uvm_fault_buffer_rm_replayable_t replayable; } rm_info;
} uvm_fault_buffer_t;
typedef struct uvm_parent_gpu_struct uvm_parent_gpu_t;
typedef struct {
    bool (*entry_is_valid)(uvm_parent_gpu_t *, NvU32);
    void (*entry_clear_valid)(uvm_parent_gpu_t *, NvU32);
    NvU32 (*read_put)(uvm_parent_gpu_t *);
    void (*write_get)(uvm_parent_gpu_t *, NvU32);
} uvm_fault_buffer_hal_t;
struct uvm_parent_gpu_struct {
    uvm_fault_buffer_hal_t *fault_buffer_hal;
    uvm_fault_buffer_t fault_buffer;
    bool replayable_faults_supported;
    struct { struct { NvU32 service_lock; } replayable_faults; } isr;
};
typedef struct uvm_gpu_struct { void *channel_manager; } uvm_gpu_t;
typedef struct { NvU32 unused; } uvm_spin_loop_t;

static bool uvm_sem_is_locked(const void *sem) { (void)sem; return true; }
static NV_STATUS uvm_global_get_status(void) { ++global_status_calls; return global_status; }
static NV_STATUS uvm_channel_manager_check_errors(void *channel_manager)
{ (void)channel_manager; ++channel_error_calls; return channel_status; }
static NV_STATUS uvm_tracker_wait(NvU32 *tracker)
{ (void)tracker; ++tracker_wait_calls; return tracker_status; }
static NV_STATUS hw_fault_buffer_flush_locked(uvm_parent_gpu_t *parent_gpu,
                                               hw_fault_buffer_flush_mode_t mode)
{ (void)parent_gpu; ++hw_flush_calls; hw_flush_mode = (NvU32)mode; return hw_flush_status; }
static NV_STATUS push_replay_on_parent_gpu(uvm_parent_gpu_t *parent_gpu,
                                           uvm_fault_replay_type_t type,
                                           uvm_fault_service_batch_context_t *batch_context)
{ (void)parent_gpu; ++parent_replay_calls; last_replay_type = type; last_batch_context = batch_context; return parent_replay_status; }
static NV_STATUS push_replay_on_gpu(uvm_gpu_t *gpu,
                                    uvm_fault_replay_type_t type,
                                    uvm_fault_service_batch_context_t *batch_context)
{ (void)gpu; ++gpu_replay_calls; last_replay_type = type; last_batch_context = batch_context; return gpu_replay_status; }
static void uvm_conf_computing_fault_increment_decrypt_iv(uvm_parent_gpu_t *parent_gpu)
{ (void)parent_gpu; ++decrypt_iv_calls; }

static bool uvm_global_is_suspended(void) { return false; }
static NvU32 test_read_once(volatile NvU32 *address)
{
    ++read_count;
    return *address;
}
static void test_write_once(volatile NvU32 *address, NvU32 value)
{
    if (write_count < sizeof(write_values) / sizeof(write_values[0]))
        write_values[write_count] = value;
    ++write_count;
    *address = value;
}
#define READ_ONCE(value) test_read_once(&(value))
#define WRITE_ONCE(value, new_value) test_write_once(&(value), (new_value))
#define UVM_GPU_READ_ONCE(value) ({ UVM_ASSERT(!uvm_global_is_suspended()); READ_ONCE(value); })
#define UVM_GPU_WRITE_ONCE(value, new_value) do { \
    UVM_ASSERT(!uvm_global_is_suspended()); \
    WRITE_ONCE(value, new_value); \
} while (0)

static void reset_observation(void)
{
    read_count = 0;
    write_count = 0;
    memset(write_values, 0, sizeof(write_values));
}

static void check_value(const char *name, NvU64 actual, NvU64 expected)
{
    ++assertion_count;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s actual=0x%llx expected=0x%llx\n", name,
                (unsigned long long)actual, (unsigned long long)expected);
        ++failures;
    }
}
'''
    source = (uvm_root / "uvm_volta_fault_buffer.c").read_text(encoding="utf-8")
    replayable_source = (uvm_root / "uvm_gpu_replayable_faults.c").read_text(encoding="utf-8")
    functions = [prefix]
    for name, signature in FUNCTIONS:
        functions.append(signature + "\n{\n" + source_tools._extract_function(source, name) + "\n}\n")
    for name, signature in SERVICE_HELPERS:
        functions.append(signature + "\n{\n" + source_tools._extract_function(replayable_source, name) + "\n}\n")
    functions.append(
        "static NV_STATUS fault_buffer_flush_locked(uvm_parent_gpu_t *parent_gpu,\n"
        "                                           uvm_gpu_t *gpu,\n"
        "                                           uvm_gpu_buffer_flush_mode_t flush_mode,\n"
        "                                           uvm_fault_replay_type_t fault_replay,\n"
        "                                           uvm_fault_service_batch_context_t *batch_context)\n{\n"
        + source_tools._extract_function(replayable_source, "fault_buffer_flush_locked")
        + "\n}\n"
    )
    return "\n".join(functions) + _VECTOR_SUFFIX


_VECTOR_SUFFIX = r'''
static bool test_entry_is_valid(uvm_parent_gpu_t *parent_gpu, NvU32 index)
{
    UVM_ASSERT(index < parent_gpu->fault_buffer.replayable.max_faults);
    UVM_ASSERT(index < sizeof(entry_state) / sizeof(entry_state[0]));
    if (entry_valid_calls < sizeof(entry_valid_indices) / sizeof(entry_valid_indices[0]))
        entry_valid_indices[entry_valid_calls] = index;
    ++entry_valid_calls;
    return entry_state[index];
}

static void test_entry_clear_valid(uvm_parent_gpu_t *parent_gpu, NvU32 index)
{
    UVM_ASSERT(index < parent_gpu->fault_buffer.replayable.max_faults);
    UVM_ASSERT(index < sizeof(entry_state) / sizeof(entry_state[0]));
    if (entry_clear_calls < sizeof(entry_clear_indices) / sizeof(entry_clear_indices[0]))
        entry_clear_indices[entry_clear_calls] = index;
    ++entry_clear_calls;
    entry_state[index] = false;
}

static uvm_fault_buffer_hal_t test_fault_buffer_hal = {
    .entry_is_valid = test_entry_is_valid,
    .entry_clear_valid = test_entry_clear_valid,
    .read_put = uvm_hal_volta_fault_buffer_read_put,
    .write_get = uvm_hal_volta_fault_buffer_write_get,
};

static void reset_service_observation(void)
{
    reset_observation();
    global_status_calls = 0;
    channel_error_calls = 0;
    tracker_wait_calls = 0;
    hw_flush_calls = 0;
    hw_flush_mode = 0;
    parent_replay_calls = 0;
    gpu_replay_calls = 0;
    tracker_status = NV_OK;
    hw_flush_status = NV_OK;
    parent_replay_status = NV_OK;
    gpu_replay_status = NV_OK;
    channel_status = NV_OK;
    last_replay_type = 0;
    last_batch_context = NULL;
    entry_valid_calls = 0;
    entry_clear_calls = 0;
    decrypt_iv_calls = 0;
    memset(entry_valid_indices, 0, sizeof(entry_valid_indices));
    memset(entry_clear_indices, 0, sizeof(entry_clear_indices));
    memset(entry_state, 0, sizeof(entry_state));
}

static uvm_parent_gpu_t make_gpu(NvU32 max_faults,
                                 volatile NvU32 *put,
                                 volatile NvU32 *get)
{
    uvm_parent_gpu_t gpu = {
        .fault_buffer_hal = &test_fault_buffer_hal,
        .fault_buffer = {
            .replayable = { .max_faults = max_faults, .cached_get = 0, .cached_put = 0 },
            .rm_info = { .replayable = {
                .pFaultBufferPut = put,
                .pFaultBufferGet = get,
            }},
        },
        .replayable_faults_supported = true,
    };
    return gpu;
}

static NvU32 run_read_put_vector(NvU32 index)
{
    volatile NvU32 put = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_PUT, PTR, index);
    volatile NvU32 get = 0;
    uvm_parent_gpu_t gpu = make_gpu(1U << 20, &put, &get);
    NvU32 actual;
    reset_observation();
    actual = uvm_hal_volta_fault_buffer_read_put(&gpu);
    check_value("read-put-index", actual, index);
    check_value("read-put-read-once-count", read_count, 1);
    check_value("read-put-no-write", write_count, 0);
    return failures ? 1 : 0;
}

static NvU32 run_read_get_vector(NvU32 index)
{
    volatile NvU32 put = 0;
    volatile NvU32 get = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_GET, PTR, index);
    uvm_parent_gpu_t gpu = make_gpu(1U << 20, &put, &get);
    NvU32 actual;
    reset_observation();
    actual = uvm_hal_volta_fault_buffer_read_get(&gpu);
    check_value("read-get-index", actual, index);
    check_value("read-get-read-once-count", read_count, 1);
    check_value("read-get-no-write", write_count, 0);
    return failures ? 1 : 0;
}

static NvU32 run_write_get_vector(NvU32 index)
{
    volatile NvU32 put = 0;
    volatile NvU32 get = 0xA5A55A5A;
    uvm_parent_gpu_t gpu = make_gpu(64, &put, &get);
    NvU32 pointer = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_GET, PTR, index);
    NvU32 expected_clears = HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, GETPTR_CORRUPTED, CLEAR) |
                            HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, OVERFLOW, CLEAR);
    NvU32 expected_final = pointer | expected_clears;
    g_uvm_global.conf_computing_enabled = false;
    reset_observation();
    uvm_hal_volta_fault_buffer_write_get(&gpu, index);
    check_value("write-get-two-write-sequence", write_count, 2);
    check_value("write-get-pointer-first", write_values[0], pointer);
    check_value("write-get-clear-flags-second", write_values[1], expected_final);
    check_value("write-get-final-register", get, expected_final);
    return failures ? 1 : 0;
}

static NvU32 run_confidential_write_get_vector(NvU32 index)
{
    volatile NvU32 put = 0;
    volatile NvU32 get = 0xFFFFFFFF;
    uvm_parent_gpu_t gpu = make_gpu(64, &put, &get);
    NvU32 pointer = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_GET, PTR, index);
    g_uvm_global.conf_computing_enabled = true;
    reset_observation();
    uvm_hal_volta_fault_buffer_write_get(&gpu, index);
    check_value("cc-write-get-single-write", write_count, 1);
    check_value("cc-write-get-pointer-only", write_values[0], pointer);
    check_value("cc-write-get-register", get, pointer);
    g_uvm_global.conf_computing_enabled = false;
    return failures ? 1 : 0;
}

static NvU32 run_service_wrap_case(void)
{
    volatile NvU32 put = 0;
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t gpu = make_gpu(8, &put, &get_register);
    NvU32 clear_flags = HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, GETPTR_CORRUPTED, CLEAR) |
                        HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, OVERFLOW, CLEAR);
    NV_STATUS status;
    NvU32 expected_order[] = { 6, 7, 0, 1 };
    NvU32 i;
    reset_service_observation();
    g_uvm_global.conf_computing_enabled = false;
    global_status = NV_OK;
    gpu.fault_buffer.replayable.cached_get = 6;
    gpu.fault_buffer.replayable.cached_put = 2;
    entry_state[6] = entry_state[7] = entry_state[0] = entry_state[1] = true;
    status = fault_buffer_flush_locked(&gpu, NULL, UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START_ACK_ALL,
                                       &test_batch_context);
    check_value("drain-wrap-status", status, NV_OK);
    check_value("drain-wrap-clear-count", entry_clear_calls, 4);
    check_value("drain-wrap-valid-check-count", entry_valid_calls, 8);
    for (i = 0; i < 4; ++i)
        check_value("drain-wrap-clear-order", entry_clear_indices[i], expected_order[i]);
    check_value("drain-wrap-cached-get", gpu.fault_buffer.replayable.cached_get, 2);
    check_value("drain-wrap-write-count", write_count, 2);
    check_value("drain-wrap-write-pointer-first", write_values[0], 2);
    check_value("drain-wrap-write-clear-command-second", write_values[1], 2 | clear_flags);
    for (i = 0; i < 4; ++i)
        check_value("drain-wrap-entry-cleared", entry_state[expected_order[i]], false);
    check_value("drain-wrap-no-decrypt-iv", decrypt_iv_calls, 0);
    check_value("drain-wrap-parent-replay", parent_replay_calls, 1);
    check_value("drain-wrap-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static NvU32 run_service_empty_case(void)
{
    volatile NvU32 put = 0;
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t gpu = make_gpu(8, &put, &get_register);
    NV_STATUS status;
    reset_service_observation();
    g_uvm_global.conf_computing_enabled = false;
    global_status = NV_OK;
    gpu.fault_buffer.replayable.cached_get = 5;
    gpu.fault_buffer.replayable.cached_put = 5;
    status = fault_buffer_flush_locked(&gpu, NULL, UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START,
                                       &test_batch_context);
    check_value("drain-empty-status", status, NV_OK);
    check_value("drain-empty-clear-count", entry_clear_calls, 0);
    check_value("drain-empty-valid-count", entry_valid_calls, 0);
    check_value("drain-empty-write-count", write_count, 0);
    check_value("drain-empty-cached-get", gpu.fault_buffer.replayable.cached_get, 5);
    check_value("drain-empty-parent-replay", parent_replay_calls, 1);
    check_value("drain-empty-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static NvU32 run_service_error_case(void)
{
    volatile NvU32 put = 0;
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t gpu = make_gpu(8, &put, &get_register);
    NvU32 clear_flags = HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, GETPTR_CORRUPTED, CLEAR) |
                        HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, OVERFLOW, CLEAR);
    NV_STATUS status;
    reset_service_observation();
    g_uvm_global.conf_computing_enabled = false;
    global_status = (NV_STATUS)-1;
    gpu.fault_buffer.replayable.cached_get = 6;
    gpu.fault_buffer.replayable.cached_put = 1;
    entry_state[6] = true;
    entry_state[0] = true;
    status = fault_buffer_flush_locked(&gpu, NULL, UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START,
                                       &test_batch_context);
    check_value("drain-error-status", (NvU32)status, (NvU32)(NV_STATUS)-1);
    check_value("drain-error-clear-count", entry_clear_calls, 1);
    check_value("drain-error-cleared-index", entry_clear_indices[0], 6);
    check_value("drain-error-valid-check-count", entry_valid_calls, 3);
    check_value("drain-error-cached-get-stays-at-blocked-entry",
                gpu.fault_buffer.replayable.cached_get, 7);
    check_value("drain-error-write-count", write_count, 2);
    check_value("drain-error-write-pointer-first", write_values[0], 7);
    check_value("drain-error-write-clear-command-second", write_values[1], 7 | clear_flags);
    check_value("drain-error-earlier-entry-cleared", entry_state[6], false);
    check_value("drain-error-blocked-entry-preserved", entry_state[7], false);
    check_value("drain-error-later-entry-untouched", entry_state[0], true);
    check_value("drain-error-no-decrypt-iv", decrypt_iv_calls, 0);
    check_value("drain-error-global-status-count", global_status_calls, 1);
    check_value("drain-error-channel-status-count", channel_error_calls, 0);
    check_value("drain-error-no-parent-replay", parent_replay_calls, 0);
    check_value("drain-error-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static NvU32 run_service_wait_update_case(void)
{
    volatile NvU32 put = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_PUT, PTR, 1);
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t gpu = make_gpu(8, &put, &get_register);
    NvU32 clear_flags = HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, GETPTR_CORRUPTED, CLEAR) |
                        HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, OVERFLOW, CLEAR);
    NV_STATUS status;
    reset_service_observation();
    g_uvm_global.conf_computing_enabled = false;
    global_status = NV_OK;
    gpu.fault_buffer.replayable.cached_get = 7;
    entry_state[7] = true;
    entry_state[0] = true;
    status = fault_buffer_flush_locked(&gpu, NULL, UVM_GPU_BUFFER_FLUSH_MODE_WAIT_UPDATE_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START_ACK_ALL,
                                       &test_batch_context);
    check_value("drain-wait-update-status", status, NV_OK);
    check_value("drain-wait-update-tracker-wait", tracker_wait_calls, 1);
    check_value("drain-wait-update-hardware-flush", hw_flush_calls, 1);
    check_value("drain-wait-update-discard-mode", hw_flush_mode,
                HW_FAULT_BUFFER_FLUSH_MODE_DISCARD);
    check_value("drain-wait-update-read-put", read_count, 1);
    check_value("drain-wait-update-cached-put", gpu.fault_buffer.replayable.cached_put, 1);
    check_value("drain-wait-update-clear-count", entry_clear_calls, 2);
    check_value("drain-wait-update-clear-wrap-order", entry_clear_indices[0], 7);
    check_value("drain-wait-update-clear-wrap-order", entry_clear_indices[1], 0);
    check_value("drain-wait-update-register-write-count", write_count, 2);
    check_value("drain-wait-update-get-pointer-first", write_values[0], 1);
    check_value("drain-wait-update-clear-command-second", write_values[1], 1 | clear_flags);
    check_value("drain-wait-update-parent-replay", parent_replay_calls, 1);
    check_value("drain-wait-update-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static NvU32 run_service_tracker_wait_error_case(void)
{
    volatile NvU32 put = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_PUT, PTR, 2);
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t gpu = make_gpu(8, &put, &get_register);
    NV_STATUS status;
    reset_service_observation();
    tracker_status = (NV_STATUS)-2;
    gpu.fault_buffer.replayable.cached_get = 1;
    status = fault_buffer_flush_locked(&gpu, NULL, UVM_GPU_BUFFER_FLUSH_MODE_WAIT_UPDATE_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START,
                                       &test_batch_context);
    check_value("drain-tracker-error-status", (NvU32)status, (NvU32)(NV_STATUS)-2);
    check_value("drain-tracker-error-wait-once", tracker_wait_calls, 1);
    check_value("drain-tracker-error-no-hardware-flush", hw_flush_calls, 0);
    check_value("drain-tracker-error-no-register-read", read_count, 0);
    check_value("drain-tracker-error-no-entry-check", entry_valid_calls, 0);
    check_value("drain-tracker-error-no-entry-clear", entry_clear_calls, 0);
    check_value("drain-tracker-error-no-register-write", write_count, 0);
    check_value("drain-tracker-error-no-parent-replay", parent_replay_calls, 0);
    check_value("drain-tracker-error-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static NvU32 run_service_hw_flush_error_case(void)
{
    volatile NvU32 put = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_PUT, PTR, 2);
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t gpu = make_gpu(8, &put, &get_register);
    NV_STATUS status;
    reset_service_observation();
    hw_flush_status = (NV_STATUS)-3;
    gpu.fault_buffer.replayable.cached_get = 1;
    status = fault_buffer_flush_locked(&gpu, NULL, UVM_GPU_BUFFER_FLUSH_MODE_UPDATE_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START,
                                       &test_batch_context);
    check_value("drain-hw-error-status", (NvU32)status, (NvU32)(NV_STATUS)-3);
    check_value("drain-hw-error-no-tracker-wait", tracker_wait_calls, 0);
    check_value("drain-hw-error-flush-once", hw_flush_calls, 1);
    check_value("drain-hw-error-discard-mode", hw_flush_mode,
                HW_FAULT_BUFFER_FLUSH_MODE_DISCARD);
    check_value("drain-hw-error-no-register-read", read_count, 0);
    check_value("drain-hw-error-no-entry-check", entry_valid_calls, 0);
    check_value("drain-hw-error-no-entry-clear", entry_clear_calls, 0);
    check_value("drain-hw-error-no-register-write", write_count, 0);
    check_value("drain-hw-error-no-parent-replay", parent_replay_calls, 0);
    check_value("drain-hw-error-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static NvU32 run_service_gpu_replay_dispatch_case(void)
{
    volatile NvU32 put = 0;
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t parent = make_gpu(8, &put, &get_register);
    NvU32 channel_manager = 0;
    uvm_gpu_t gpu = { .channel_manager = &channel_manager };
    NV_STATUS status;
    reset_service_observation();
    global_status = NV_OK;
    channel_status = NV_OK;
    parent.fault_buffer.replayable.cached_get = 1;
    parent.fault_buffer.replayable.cached_put = 2;
    entry_state[1] = true;
    status = fault_buffer_flush_locked(&parent, &gpu, UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START_ACK_ALL,
                                       &test_batch_context);
    check_value("drain-gpu-dispatch-status", status, NV_OK);
    check_value("drain-gpu-dispatch-gpu-replay", gpu_replay_calls, 1);
    check_value("drain-gpu-dispatch-no-parent-replay", parent_replay_calls, 0);
    check_value("drain-gpu-dispatch-replay-type", last_replay_type,
                UVM_FAULT_REPLAY_TYPE_START_ACK_ALL);
    check_value("drain-gpu-dispatch-batch-context",
                (NvU64)(uintptr_t)last_batch_context,
                (NvU64)(uintptr_t)&test_batch_context);
    return failures ? 1 : 0;
}

static NvU32 run_service_channel_error_case(void)
{
    volatile NvU32 put = 0;
    volatile NvU32 get_register = 0;
    uvm_parent_gpu_t parent = make_gpu(8, &put, &get_register);
    NvU32 channel_manager = 0;
    uvm_gpu_t gpu = { .channel_manager = &channel_manager };
    NV_STATUS status;
    reset_service_observation();
    global_status = NV_OK;
    channel_status = (NV_STATUS)-4;
    parent.fault_buffer.replayable.cached_get = 6;
    parent.fault_buffer.replayable.cached_put = 1;
    entry_state[6] = true;
    entry_state[0] = true;
    status = fault_buffer_flush_locked(&parent, &gpu, UVM_GPU_BUFFER_FLUSH_MODE_CACHED_PUT,
                                       UVM_FAULT_REPLAY_TYPE_START,
                                       &test_batch_context);
    check_value("drain-channel-error-status", (NvU32)status, (NvU32)(NV_STATUS)-4);
    check_value("drain-channel-error-check-once", channel_error_calls, 1);
    check_value("drain-channel-error-skips-global-status", global_status_calls, 0);
    check_value("drain-channel-error-clears-prior-entry", entry_clear_calls, 1);
    check_value("drain-channel-error-preserves-blocked-get",
                parent.fault_buffer.replayable.cached_get, 7);
    check_value("drain-channel-error-no-parent-replay", parent_replay_calls, 0);
    check_value("drain-channel-error-no-gpu-replay", gpu_replay_calls, 0);
    return failures ? 1 : 0;
}

static int probe_guard(const char *mode)
{
    volatile NvU32 put = 0;
    volatile NvU32 get = 0;
    if (strcmp(mode, "--probe-put-getptr-corrupted") == 0) {
        uvm_parent_gpu_t gpu;
        put = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_PUT, PTR, 3) |
              HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_PUT, GETPTR_CORRUPTED, YES);
        gpu = make_gpu(64, &put, &get);
        return (int)uvm_hal_volta_fault_buffer_read_put(&gpu);
    }
    if (strcmp(mode, "--probe-get-out-of-range") == 0) {
        uvm_parent_gpu_t gpu;
        get = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_GET, PTR, 64);
        gpu = make_gpu(64, &put, &get);
        return (int)uvm_hal_volta_fault_buffer_read_get(&gpu);
    }
    if (strcmp(mode, "--probe-get-overflow-status") == 0 ||
        strcmp(mode, "--probe-get-overflow-status-release") == 0) {
        uvm_parent_gpu_t gpu;
        NvU32 actual;
        get = HWVALUE(_PFB_PRI_MMU, FAULT_BUFFER_GET, PTR, 3) |
              HWCONST(_PFB_PRI_MMU, FAULT_BUFFER_GET, OVERFLOW, YES);
        gpu = make_gpu(64, &put, &get);
        actual = uvm_hal_volta_fault_buffer_read_get(&gpu);
        printf("read-get-overflow-status-index=%u\n", actual);
        return strcmp(mode, "--probe-get-overflow-status-release") == 0 && actual == 3 ? 0 : 1;
    }
    if (strcmp(mode, "--probe-write-get-out-of-range") == 0) {
        uvm_parent_gpu_t gpu = make_gpu(64, &put, &get);
        uvm_hal_volta_fault_buffer_write_get(&gpu, 64);
        return 0;
    }
    return 2;
}

int main(int argc, char **argv)
{
    const NvU32 edge_indices[] = { 0, 1, (1U << 20) - 1 };
    const NvU32 write_indices[] = { 0, 17, 63 };
    const NvU32 confidential_indices[] = { 0, 63 };
    unsigned i;
    NvU32 vectors = 0;
    NvU32 checks_before = assertion_count;
    NvU32 before;
    if (argc == 2)
        return probe_guard(argv[1]);
    before = failures;
    for (i = 0; i < sizeof(edge_indices) / sizeof(edge_indices[0]); ++i) {
        failures += run_read_put_vector(edge_indices[i]);
        failures += run_read_get_vector(edge_indices[i]);
        vectors += 2;
    }
    for (i = 0; i < sizeof(write_indices) / sizeof(write_indices[0]); ++i) {
        failures += run_write_get_vector(write_indices[i]);
        ++vectors;
    }
    for (i = 0; i < sizeof(confidential_indices) / sizeof(confidential_indices[0]); ++i) {
        failures += run_confidential_write_get_vector(confidential_indices[i]);
        ++vectors;
    }
    failures += run_service_wrap_case();
    failures += run_service_empty_case();
    failures += run_service_error_case();
    failures += run_service_wait_update_case();
    failures += run_service_tracker_wait_error_case();
    failures += run_service_hw_flush_error_case();
    failures += run_service_gpu_replay_dispatch_case();
    failures += run_service_channel_error_case();
    vectors += 8;
    printf("summary vectors=%u service_cases=8 checks=%u failures=%u\n", vectors,
           assertion_count - checks_before, failures - before);
    return failures == before ? 0 : 1;
}
'''


def _source_records(r580_uvm: Path, r595_uvm: Path) -> dict:
    records = {}
    for name, root in (("r580", r580_uvm), ("r595", r595_uvm)):
        source_path = (root / "uvm_volta_fault_buffer.c").resolve(strict=True)
        fb_header_path = (root / "hwref/volta/gv100/dev_fb.h").resolve(strict=True)
        source_hash = source_tools.sha256_file(source_path)
        fb_header_hash = source_tools.sha256_file(fb_header_path)
        register_fields = _read_get_register_contract(fb_header_path)
        common_header_path = (root / "uvm_common.h").resolve(strict=True)
        common_header_hash = source_tools.sha256_file(common_header_path)
        hal_path = (root / "uvm_hal.c").resolve(strict=True)
        hal_hash = source_tools.sha256_file(hal_path)
        service_path = (root / "uvm_gpu_replayable_faults.c").resolve(strict=True)
        service_hash = source_tools.sha256_file(service_path)
        expected_service_hash = {
            "r580": PINNED_R580_SERVICE_SOURCE_SHA256,
            "r595": PINNED_R595_SERVICE_SOURCE_SHA256,
        }[name]
        if service_hash != expected_service_hash:
            raise ValueError(f"{name} replayable fault service source differs from pinned snapshot")
        if source_hash != PINNED_VOLTA_FAULT_SOURCE_SHA256:
            raise ValueError(f"{name} Volta fault-buffer source differs from pinned R580 snapshot")
        if fb_header_hash != PINNED_GV100_FB_HEADER_SHA256:
            raise ValueError(f"{name} GV100 framebuffer/fault-buffer register header differs")
        expected_common_header_hash = {
            "r580": PINNED_R580_COMMON_HEADER_SHA256,
            "r595": PINNED_R595_COMMON_HEADER_SHA256,
        }[name]
        if common_header_hash != expected_common_header_hash:
            raise ValueError(f"{name} UVM assertion-configuration header differs from pinned snapshot")
        hal_source = hal_path.read_text(encoding="utf-8")
        effective, origins = source_tools._resolve_gv100_fault_buffer_callbacks(hal_source)
        for field, expected in RING_CALLBACKS.items():
            if effective[field] != expected:
                raise ValueError(f"{name} GV100 HAL {field} callback selection changed")
        body_hashes = {
            function: source_tools._normalized_function_hash(
                source_path.read_text(encoding="utf-8"), function
            )
            for function, _signature in FUNCTIONS
        }
        service_source = service_path.read_text(encoding="utf-8")
        flush_body = source_tools._extract_function(service_source, "fault_buffer_flush_locked")
        flush_body_hash = source_tools._normalized_function_hash(
            service_source, "fault_buffer_flush_locked"
        )
        expected_flush_hash = {
            "r580": PINNED_R580_FLUSH_BODY_SHA256,
            "r595": PINNED_R595_FLUSH_BODY_SHA256,
        }[name]
        if flush_body_hash != expected_flush_hash:
            raise ValueError(f"{name} fault_buffer_flush_locked body differs from pinned snapshot")
        support_assert_present = re.search(
            r"UVM_ASSERT\s*\(\s*parent_gpu->replayable_faults_supported\s*\)",
            source_tools._mask_comments(flush_body),
        ) is not None
        if support_assert_present != (name == "r580"):
            raise ValueError(f"{name} replayable-support assertion differs from pinned contract")
        flush_body_without_support_assert = re.sub(
            r"UVM_ASSERT\s*\(\s*parent_gpu->replayable_faults_supported\s*\)\s*;",
            "",
            source_tools._mask_comments(flush_body),
        )
        flush_residual_hash = source_tools.sha256_bytes(
            "".join(flush_body_without_support_assert.split()).encode("utf-8")
        )
        drain_loop = _extract_service_drain_loop(service_source)
        normalized_drain = " ".join(source_tools._mask_comments(drain_loop).split())
        drain_body_hash = source_tools.sha256_bytes(normalized_drain.encode("utf-8"))
        service_helper_hashes = {
            function: source_tools._normalized_function_hash(service_source, function)
            for function, _signature in SERVICE_HELPERS
        }
        records[name] = {
            "root": str(root),
            "fault_source_sha256": source_hash,
            "dev_fb_header_sha256": fb_header_hash,
            "fault_buffer_get_register_fields": register_fields,
            "uvm_common_header_sha256": common_header_hash,
            "uvm_hal_source_sha256": hal_hash,
            "replayable_fault_service_source_sha256": service_hash,
            "drain_service_helper_body_sha256": service_helper_hashes,
            "drain_service_body_sha256": drain_body_hash,
            "drain_service_body_normalized": normalized_drain,
            "fault_buffer_flush_locked_body_sha256": flush_body_hash,
            "fault_buffer_flush_locked_body_without_support_assert_sha256": flush_residual_hash,
            "replayable_support_assert_present": support_assert_present,
            "gv100_fault_buffer_callbacks": {key: effective[key] for key in RING_CALLBACKS},
            "gv100_callback_origins": {key: origins[key] for key in RING_CALLBACKS},
            "function_body_sha256": body_hashes,
        }
    if records["r580"]["fault_source_sha256"] != records["r595"]["fault_source_sha256"]:
        raise ValueError("R580/R595 Volta fault-buffer source bytes differ")
    if records["r580"]["dev_fb_header_sha256"] != records["r595"]["dev_fb_header_sha256"]:
        raise ValueError("R580/R595 GV100 GET/PUT register definitions differ")
    if (records["r580"]["fault_buffer_get_register_fields"] !=
            records["r595"]["fault_buffer_get_register_fields"]):
        raise ValueError("R580/R595 GV100 GET register field contracts differ")
    if records["r580"]["function_body_sha256"] != records["r595"]["function_body_sha256"]:
        raise ValueError("R580/R595 Volta GET/PUT callback bodies differ")
    if records["r580"]["drain_service_helper_body_sha256"] != records["r595"]["drain_service_helper_body_sha256"]:
        raise ValueError("R580/R595 replayable fault service helper bodies differ")
    if records["r580"]["drain_service_body_sha256"] != records["r595"]["drain_service_body_sha256"]:
        raise ValueError("R580/R595 replayable fault drain loops differ")
    if records["r580"]["fault_buffer_flush_locked_body_without_support_assert_sha256"] != records["r595"]["fault_buffer_flush_locked_body_without_support_assert_sha256"]:
        raise ValueError("R580/R595 flush function differs beyond the replayable-support assertion")
    return records


def _write_json_private(path: Path, payload: dict) -> bytes:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    source_tools._write_exclusive(path.resolve(), encoded)
    return encoded


def run(r580_uvm: Path, r595_uvm: Path, report_path: Path, log_path: Path,
        compiler: str = "cc") -> dict:
    r580_uvm = r580_uvm.resolve(strict=True)
    r595_uvm = r595_uvm.resolve(strict=True)
    if report_path.exists() or log_path.exists():
        raise FileExistsError("refusing to overwrite fault-ring evidence")
    source_pair = _source_records(r580_uvm, r595_uvm)
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise ValueError(f"compiler not found: {compiler}")
    compiler_version = subprocess.run([compiler_path, "--version"], capture_output=True,
                                      text=True, check=True).stdout.splitlines()[0]
    logs = []
    outputs = {}
    release_status_outputs = {}
    failures = 0
    with tempfile.TemporaryDirectory(prefix="volta-fault-ring-host-") as directory:
        scratch = Path(directory)
        for label, root in (("r580", r580_uvm), ("r595", r595_uvm)):
            common = (root.parent / "common/inc").resolve(strict=True)
            c_path = scratch / f"{label}_fault_ring.c"
            binary = scratch / f"{label}_fault_ring"
            c_path.write_text(_build_source(root), encoding="utf-8")
            command = [compiler_path, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-I", str(common), "-I", str(root), str(c_path), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            logs.append("$ " + shlex.join(command) + "\n" + compiled.stdout + compiled.stderr)
            if compiled.returncode != 0:
                raise RuntimeError(f"{label} exact-source ring callback compile failed")
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            logs.append("$ " + shlex.quote(str(binary)) + "\n" + executed.stdout + executed.stderr)
            if executed.returncode != 0 or "summary vectors=19 service_cases=8 checks=122 failures=0" not in executed.stdout:
                raise RuntimeError(f"{label} exact-source ring callback vectors failed")
            outputs[label] = executed.stdout
            for guard in GUARDS:
                probe = subprocess.run([str(binary), guard], capture_output=True, text=True,
                                       preexec_fn=source_tools._disable_core_dumps)
                logs.append("$ " + shlex.quote(str(binary)) + " " + guard +
                            "\nexpected assertion rejection; returncode=" + str(probe.returncode) +
                            "\n" + probe.stdout + probe.stderr)
                if probe.returncode != -signal.SIGABRT:
                    raise RuntimeError(f"expected assertion guard failed: {label} {guard}")
                failures += 1
            release_binary = scratch / f"{label}_fault_ring_release_asserts"
            release_command = [compiler_path, "-DTEST_RELEASE_UVM_ASSERTS", "-std=gnu11", "-O2",
                               "-Wall", "-Wextra", "-Werror", "-I", str(common), "-I", str(root),
                               str(c_path), "-o", str(release_binary)]
            release_compiled = subprocess.run(release_command, capture_output=True, text=True)
            logs.append("$ " + shlex.join(release_command) + "\n" + release_compiled.stdout + release_compiled.stderr)
            if release_compiled.returncode != 0:
                raise RuntimeError(f"{label} release-assert model compile failed")
            release_probe = subprocess.run(
                [str(release_binary), "--probe-get-overflow-status-release"],
                capture_output=True,
                text=True,
            )
            logs.append("$ " + shlex.quote(str(release_binary)) +
                        " --probe-get-overflow-status-release\n" +
                        release_probe.stdout + release_probe.stderr)
            if release_probe.returncode != 0 or "read-get-overflow-status-index=3" not in release_probe.stdout:
                raise RuntimeError(f"{label} release-mode GET overflow status vector failed")
            release_status_outputs[label] = release_probe.stdout
    if outputs["r580"] != outputs["r595"]:
        raise RuntimeError("R580 and R595 exact-source fault-ring outputs differ")
    if release_status_outputs["r580"] != release_status_outputs["r595"]:
        raise RuntimeError("R580 and R595 release-mode GET overflow outputs differ")
    log_bytes = "".join(logs).encode("utf-8")
    log_sha256 = source_tools.sha256_bytes(log_bytes)
    source_tools._write_exclusive(log_path.resolve(), log_bytes)
    report = {
        "schema": "codex.volta-fault-ring-host-harness.v5",
        "status": "passed",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "host-cpu-execution-of-extracted-pinned-GV100-Volta-fault-ring-register-callbacks-and-full-replayable-buffer-flush",
        "implementations_executed": 2,
        "vectors_per_implementation": 19,
        "ring_callback_vectors_per_implementation": 11,
        "fault_buffer_flush_locked_cases_per_implementation": 8,
        "checks_per_implementation": 122,
        "checks_passed": 244,
        "release_status_probes_per_implementation": 1,
        "release_status_probes_passed": 2,
        "assertion_guards_per_implementation": list(GUARDS),
        "release_assert_model": "UVM_ASSERT not evaluated, matching the release branch in pinned uvm_common.h; test-only host model, not a production build",
        "hardware_validated": False,
        "dma_ordering_validated": False,
        "source_pair": source_pair,
        "compiler": {"path": compiler_path, "version": compiler_version},
        "compile_flags": ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        "release_compile_flags": ["-DTEST_RELEASE_UVM_ASSERTS", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": source_tools.sha256_file(Path(__file__).resolve()),
        },
        "report": {
            "path": str(report_path.resolve()),
            "mode": "0600",
        },
        "log": {"path": str(log_path.resolve()), "sha256": log_sha256, "mode": "0600"},
        "limits": [
            "Exact pinned Volta read_put, read_get, and write_get bodies are compiled and host-executed for both snapshots.",
            "The exact replayable fault drain loop, write_get service helper, and skip-entry helper are compiled and host-executed for both snapshots; source and normalized body hashes are recorded and compared.",
            "The complete pinned fault_buffer_flush_locked function is compiled and host-executed. Eight scenarios cover cached ring drain, wrap, empty ring, global/channel error status, tracker and hardware-flush early returns, UPDATE_PUT refresh, and parent/GPU replay dispatch.",
            "R580 asserts replayable_faults_supported while R595 omits that assertion. This is source-level evidence: the host test sets the synthetic R580 flag true; it does not establish that a live candidate initializes capabilities correctly.",
            "Entry callbacks, tracker, flush operation, status, lock state, replay dispatch, and register/MMIO storage are synthetic CPU collaborators.",
            "Synthetic volatile register words use instrumented CPU READ_ONCE/WRITE_ONCE shims; this checks C access ordering but not BAR access, CPU/GPU ordering, posted writes, or fault arrival races.",
            "Normal write_get checks the pointer write precedes a second write that clears GETPTR_CORRUPTED and OVERFLOW; confidential-computing mode checks the single pointer write path.",
            "Volta read_get checks the raw GET word against max_faults before extracting PTR. A synthetic GET OVERFLOW status bit trips the debug assertion shim; a separate release-assert model confirms PTR=3 is extracted when UVM_ASSERT is compiled away. This is not evidence of a release-build fault or a hardware failure.",
            "The release assertion behavior is source-pinned through uvm_common.h hashes; the host model uses a test-only define and does not reproduce the complete NVIDIA release configuration.",
            "No GPU, UVM module, interrupt, DMA, ring allocation, CUDA context, or runtime fault is exercised.",
        ],
        "expected_guard_count": failures,
        "result_stdout_sha256": {
            label: source_tools.sha256_bytes(text.encode("utf-8")) for label, text in outputs.items()
        },
        "release_status_probe_stdout_sha256": {
            label: source_tools.sha256_bytes(text.encode("utf-8"))
            for label, text in release_status_outputs.items()
        },
    }
    report_bytes = _write_json_private(report_path, report)
    return {
        "status": "passed",
        "report": str(report_path.resolve()),
        "report_sha256": source_tools.sha256_bytes(report_bytes),
        "log": str(log_path.resolve()),
        "log_sha256": log_sha256,
        "implementations_executed": 2,
        "vectors_per_implementation": 19,
        "ring_callback_vectors_per_implementation": 11,
        "fault_buffer_flush_locked_cases_per_implementation": 8,
        "checks_per_implementation": 122,
        "checks_passed": 244,
        "release_status_probes_passed": 2,
        "hardware_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-uvm", type=Path, default=DEFAULT_R580_UVM)
    parser.add_argument("--r595-uvm", type=Path, default=DEFAULT_R595_UVM)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--compiler", default="cc")
    args = parser.parse_args()
    print(json.dumps(run(args.r580_uvm, args.r595_uvm,
                         args.report, args.log, args.compiler), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"fault-ring host harness failed: {error}", file=sys.stderr)
        raise SystemExit(2)
