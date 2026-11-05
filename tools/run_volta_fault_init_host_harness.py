#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host-execute pinned R580/R595 replayable fault-buffer initialization."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
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
PINNED = {
    "r580": {
        "service": "c7991f9a9e029ae1e9dc4aba579ecb37c64408d9600117abdeec82fbc1b245b3",
        "gpu_header": "11f5a41820746ffb1bc2d70729eaca257eeea3ca71ecbf4fc31fa4a1f3bc5a01",
        "volta_source": "2f6bb4ea1fd81e3a495802b0181573ff339e317c22dfb745ee3b2f4207343653",
        "init_body": "9fab37556fa02c9b7efd4c7ad59a5d6d92a3b6a2963800b5102a7ad566f8b473",
        "reinit_body": "6b4cb874e7637d6fe5ad6be1ffcb724d6be5ce090bd38b14c645b3dde14c2bf4",
        "deinit_body": "8af117f2c38f592c1e1facf2c7c913d3d5f715233759a0f29b9d1d48c2cfe0a5",
        "parent_init_body": "5443ab1ea632d7c95f4f9e7df4964cf3fa93088c652d0678de6d71a746653a41",
        "parent_resume_body": "e8bbf1ac850e2483e25e64357366d5d52cc7390897499a11579565fb8cd93035",
        "parent_deinit_body": "968290b9ae9e285fe9786479f4c19bcdef0d335ab2a7305b7985b727acc3587c",
        "non_replayable_source": "588e72e5e3163f2e9a3c1b0d78a5450c97a4393b5b0c8e024915c41460d0250b",
        "non_replayable_init_body": "fb754753dcdcb2e85c33e0169d13aa267fb910964ffed87be0b49e65e0c25702",
        "non_replayable_deinit_body": "46be8c999dca2c53f460f5ad03025243b48703bae62d75093dcc1aeb0b171946",
    },
    "r595": {
        "service": "e2b98f550ad6ef3efb062d931834f09acd79ecd5fa140a2f54de8e77a5dfac2b",
        "gpu_header": "76c578d204b32499e0004d1f1f43f9a1ce6718be13faa1394a5a63d0d1c7f9b5",
        "volta_source": "ca662fc33698586ec524c939593b6a67fb196d1b03fc6eea19116e5a0553254e",
        "init_body": "675c94f2d66a0614991f4042bf75c0006517ffbe38b42e46fc69ba3920935f2f",
        "reinit_body": "6b4cb874e7637d6fe5ad6be1ffcb724d6be5ce090bd38b14c645b3dde14c2bf4",
        "deinit_body": "0dce92b4c39fb4db283cb1d60aef691f5856e2b8daaea2010f7b7cc90be11372",
        "parent_init_body": "d8ac4d8690ddf35245ac30c83bde7b5bd31ae5a78dacd1ec67aebd592ae536b1",
        "parent_resume_body": "7623abe672f950a6d89b452965c09cbdb2d42779ce6e9dec1dfa8aa703679f3b",
        "parent_deinit_body": "0d3c9ab13c084c3f55efad35658e9d1c58916cd7b89ff1f891d7016d7bd7d048",
        "non_replayable_source": "83fd573b3f5187ded355dec0a835f293716b0d271204d2c617864346fac01888",
        "non_replayable_init_body": "9bfd56443847d2b34c7c9f268ef757fdf98138d8d0c16efb484920b6e69f4759",
        "non_replayable_deinit_body": "46be8c999dca2c53f460f5ad03025243b48703bae62d75093dcc1aeb0b171946",
    },
}
GUARDS = ("--probe-zero-utlb", "--probe-non-divisible-buffer-size", "--probe-tracker-nonempty")


def _build_source(uvm_root: Path, is_r580: bool) -> str:
    prefix = r'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nvtypes.h"
#include "nvstatus.h"

#define UVM_ASSERT(condition) assert(condition)
#define UVM_ASSERT_MSG(condition, ...) assert(condition)
#define UVM_PERF_FAULT_BATCH_COUNT_MIN 2
#define UVM_PERF_FAULT_REPLAY_POLICY_MAX 3
#define UVM_PERF_FAULT_REPLAY_POLICY_DEFAULT 1
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define UVM_INFO_PRINT(...) test_info_print()
#define UVM_ERR_PRINT(...) ((void)0)
#define uvm_assert_mutex_locked(lock) ((void)(lock))
#define uvm_rm_locked_call(expression) (expression)
#define uvm_rm_locked_call_void(expression) ((void)(expression))

typedef struct { NvU32 words[4]; } test_fault_cache_entry_t;
typedef struct { NvU64 words[1]; } test_ordered_fault_cache_entry_t;
typedef struct {
    test_fault_cache_entry_t *fault_cache;
    test_ordered_fault_cache_entry_t *ordered_fault_cache;
    NvU32 *utlbs;
    NvU32 max_utlb_id;
} uvm_fault_service_batch_context_t;
typedef struct {
    NvU32 max_faults;
    NvU32 cached_get;
    NvU32 cached_put;
    NvU32 utlb_count;
    NvU32 replay_tracker;
    uvm_fault_service_batch_context_t batch_service_context;
    NvU32 replay_policy;
    NvU32 replay_update_put_ratio;
} uvm_replayable_fault_buffer_t;
typedef struct { NvU32 words[4]; } test_non_replayable_fault_cache_entry_t;
typedef struct {
    void *shadow_buffer_copy;
    test_non_replayable_fault_cache_entry_t *fault_cache;
    NvU32 max_faults;
    NvU32 clear_faulted_tracker;
    NvU32 fault_service_tracker;
} uvm_non_replayable_fault_buffer_t;
typedef struct { size_t bufferSize; } uvm_fault_buffer_rm_replayable_t;
typedef struct { size_t bufferSize; } uvm_fault_buffer_rm_non_replayable_t;
typedef struct {
    uvm_fault_buffer_rm_replayable_t replayable;
    uvm_fault_buffer_rm_non_replayable_t nonReplayable;
    NvU32 faultBufferHandle;
} uvm_fault_buffer_rm_info_t;
typedef struct {
    uvm_replayable_fault_buffer_t replayable;
    uvm_non_replayable_fault_buffer_t non_replayable;
    uvm_fault_buffer_rm_info_t rm_info;
    NvU32 max_batch_size;
    bool prefetch_faults_enabled;
} uvm_fault_buffer_t;
typedef struct uvm_parent_gpu_struct uvm_parent_gpu_t;
typedef struct {
    NvU32 (*entry_size)(uvm_parent_gpu_t *);
    NvU32 (*read_get)(uvm_parent_gpu_t *);
    NvU32 (*read_put)(uvm_parent_gpu_t *);
} uvm_fault_buffer_hal_t;
typedef struct {
    void (*enable_prefetch_faults)(uvm_parent_gpu_t *);
    void (*disable_prefetch_faults)(uvm_parent_gpu_t *);
} uvm_arch_hal_t;
struct uvm_parent_gpu_struct {
    uvm_fault_buffer_t fault_buffer;
    uvm_fault_buffer_hal_t *fault_buffer_hal;
    uvm_arch_hal_t *arch_hal;
    void *rm_device;
    bool prefetch_fault_supported;
    bool replayable_faults_supported;
    bool non_replayable_faults_supported;
};

static NvU32 uvm_perf_fault_batch_count;
static NvU32 uvm_perf_fault_replay_policy;
static NvU32 uvm_perf_fault_replay_update_put_ratio;
static NvU32 entry_size_value = 32;
static NvU32 read_get_value = 7;
static NvU32 read_put_value = 2;
static NV_STATUS owner_status;
static int allocation_fail_at = -1;
static NvU32 allocation_calls;
static size_t allocation_sizes[8];
static void *allocations[8];
static NvU32 tracker_init_calls;
static NvU32 tracker_deinit_calls;
static bool tracker_empty = true;
static NvU32 kvfree_calls;
static NvU32 kvfree_nonnull_calls;
static NvU32 owner_calls;
static NvU32 owner_true_calls;
static NvU32 owner_false_calls;
static void *owner_device;
static bool owner_flag;
static NV_STATUS rm_init_status;
static NvU32 rm_handle_on_init;
static NvU32 rm_init_calls;
static NvU32 rm_destroy_calls;
static NvU32 non_replayable_init_calls;
static NvU32 non_replayable_deinit_calls;
static NvU32 non_replayable_init_total;
static NvU32 non_replayable_deinit_total;
static NvU32 entry_size_calls;
static NvU32 read_get_calls;
static NvU32 read_put_calls;
static NvU32 prefetch_enable_calls;
static NvU32 prefetch_disable_calls;
static NvU32 info_print_calls;
static NvU32 assertion_count;
static NvU32 failures;
static NvU32 device_sentinel;
static struct { NvU32 global_lock; } g_uvm_global;

static void test_info_print(void) { ++info_print_calls; }
static void *uvm_kvmalloc_zero(size_t size)
{
    NvU32 slot = allocation_calls++;
    void *memory;
    if (slot < sizeof(allocation_sizes) / sizeof(allocation_sizes[0]))
        allocation_sizes[slot] = size;
    if ((int)slot == allocation_fail_at)
        return NULL;
    memory = calloc(1, size);
    if (slot < sizeof(allocations) / sizeof(allocations[0]))
        allocations[slot] = memory;
    return memory;
}
static void uvm_tracker_init(NvU32 *tracker)
{ ++tracker_init_calls; *tracker = 0x1234; }
static bool uvm_tracker_is_empty(NvU32 *tracker)
{ (void)tracker; return tracker_empty; }
static void uvm_tracker_deinit(NvU32 *tracker)
{ ++tracker_deinit_calls; *tracker = 0; }
static void uvm_kvfree(void *pointer)
{
    NvU32 i;
    ++kvfree_calls;
    if (pointer == NULL)
        return;
    ++kvfree_nonnull_calls;
    for (i = 0; i < sizeof(allocations) / sizeof(allocations[0]); ++i) {
        if (allocations[i] == pointer) {
            allocations[i] = NULL;
            break;
        }
    }
    free(pointer);
}
static NV_STATUS nvUvmInterfaceInitFaultInfo(void *device, uvm_fault_buffer_rm_info_t *info)
{
    (void)device;
    ++rm_init_calls;
    info->replayable.bufferSize = 256;
    info->nonReplayable.bufferSize = 96;
    info->faultBufferHandle = rm_handle_on_init;
    return rm_init_status;
}
static NV_STATUS nvUvmInterfaceOwnPageFaultIntr(void *device, bool own)
{
    ++owner_calls;
    if (own)
        ++owner_true_calls;
    else
        ++owner_false_calls;
    owner_device = device;
    owner_flag = own;
    return owner_status;
}
static void nvUvmInterfaceDestroyFaultInfo(void *device, uvm_fault_buffer_rm_info_t *info)
{ (void)device; (void)info; ++rm_destroy_calls; }
static NvU32 test_entry_size(uvm_parent_gpu_t *parent_gpu)
{ (void)parent_gpu; ++entry_size_calls; return entry_size_value; }
static NvU32 test_read_get(uvm_parent_gpu_t *parent_gpu)
{ (void)parent_gpu; ++read_get_calls; return read_get_value; }
static NvU32 test_read_put(uvm_parent_gpu_t *parent_gpu)
{ (void)parent_gpu; ++read_put_calls; return read_put_value; }
static void test_enable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
{ (void)parent_gpu; ++prefetch_enable_calls; }
static void test_disable_prefetch_faults(uvm_parent_gpu_t *parent_gpu)
{ (void)parent_gpu; ++prefetch_disable_calls; }
static uvm_fault_buffer_hal_t test_fault_buffer_hal = {
    .entry_size = test_entry_size,
    .read_get = test_read_get,
    .read_put = test_read_put,
};
static uvm_arch_hal_t test_arch_hal = {
    .enable_prefetch_faults = test_enable_prefetch_faults,
    .disable_prefetch_faults = test_disable_prefetch_faults,
};

static void check_value(const char *name, NvU64 actual, NvU64 expected)
{
    ++assertion_count;
    if (actual != expected) {
        fprintf(stderr, "FAIL %s actual=0x%llx expected=0x%llx\n", name,
                (unsigned long long)actual, (unsigned long long)expected);
        ++failures;
    }
}
static void reset_observation(void)
{
    NvU32 i;
    for (i = 0; i < sizeof(allocations) / sizeof(allocations[0]); ++i) {
        free(allocations[i]);
        allocations[i] = NULL;
        allocation_sizes[i] = 0;
    }
    allocation_calls = 0;
    allocation_fail_at = -1;
    tracker_init_calls = 0;
    tracker_deinit_calls = 0;
    tracker_empty = true;
    kvfree_calls = 0;
    kvfree_nonnull_calls = 0;
    owner_calls = 0;
    owner_true_calls = 0;
    owner_false_calls = 0;
    owner_device = NULL;
    owner_flag = false;
    rm_init_status = NV_OK;
    rm_handle_on_init = 0x55;
    rm_init_calls = 0;
    rm_destroy_calls = 0;
    non_replayable_init_calls = 0;
    non_replayable_deinit_calls = 0;
    entry_size_calls = 0;
    read_get_calls = 0;
    read_put_calls = 0;
    prefetch_enable_calls = 0;
    prefetch_disable_calls = 0;
    info_print_calls = 0;
    entry_size_value = 32;
    read_get_value = 7;
    read_put_value = 2;
    owner_status = NV_OK;
    uvm_perf_fault_batch_count = 4;
    uvm_perf_fault_replay_policy = 1;
    uvm_perf_fault_replay_update_put_ratio = 100;
}
static uvm_parent_gpu_t make_gpu(size_t buffer_size, NvU32 utlb_count, bool prefetch_supported)
{
    uvm_parent_gpu_t gpu = {
        .fault_buffer = {
            .replayable = { .utlb_count = utlb_count },
            .rm_info = { .replayable = { .bufferSize = buffer_size } },
        },
        .fault_buffer_hal = &test_fault_buffer_hal,
        .arch_hal = &test_arch_hal,
        .rm_device = &device_sentinel,
        .prefetch_fault_supported = prefetch_supported,
        .replayable_faults_supported = true,
        .non_replayable_faults_supported = true,
    };
    return gpu;
}
static void release_gpu_allocations(uvm_parent_gpu_t *gpu)
{
    free(gpu->fault_buffer.replayable.batch_service_context.fault_cache);
    free(gpu->fault_buffer.replayable.batch_service_context.ordered_fault_cache);
    free(gpu->fault_buffer.replayable.batch_service_context.utlbs);
    free(gpu->fault_buffer.non_replayable.shadow_buffer_copy);
    free(gpu->fault_buffer.non_replayable.fault_cache);
    gpu->fault_buffer.replayable.batch_service_context.fault_cache = NULL;
    gpu->fault_buffer.replayable.batch_service_context.ordered_fault_cache = NULL;
    gpu->fault_buffer.replayable.batch_service_context.utlbs = NULL;
    gpu->fault_buffer.non_replayable.shadow_buffer_copy = NULL;
    gpu->fault_buffer.non_replayable.fault_cache = NULL;
    memset(allocations, 0, sizeof(allocations));
}
'''
    if is_r580:
        prefix += "\n#define EXPECT_R580_SOURCE 1\n"
    else:
        prefix += "\n#define EXPECT_R580_SOURCE 0\n"
    source = (uvm_root / "uvm_gpu_replayable_faults.c").read_text(encoding="utf-8")
    non_replayable_source = (uvm_root / "uvm_gpu_non_replayable_faults.c").read_text(encoding="utf-8")
    functions = [prefix]
    for name, signature in (
        ("fault_buffer_deinit_replayable_faults",
         "static void fault_buffer_deinit_replayable_faults(uvm_parent_gpu_t *parent_gpu)"),
        ("fault_buffer_reinit_replayable_faults",
         "static void fault_buffer_reinit_replayable_faults(uvm_parent_gpu_t *parent_gpu)"),
        ("fault_buffer_init_replayable_faults",
         "static NV_STATUS fault_buffer_init_replayable_faults(uvm_parent_gpu_t *parent_gpu)"),
    ):
        functions.append(signature + "\n{\n" + source_tools._extract_function(source, name) + "\n}\n")
    for name, signature in (
        ("uvm_parent_gpu_fault_buffer_init_non_replayable_faults",
         "static NV_STATUS uvm_parent_gpu_fault_buffer_init_non_replayable_faults_exact(uvm_parent_gpu_t *parent_gpu)"),
        ("uvm_parent_gpu_fault_buffer_deinit_non_replayable_faults",
         "static void uvm_parent_gpu_fault_buffer_deinit_non_replayable_faults_exact(uvm_parent_gpu_t *parent_gpu)"),
    ):
        functions.append(signature + "\n{\n" + source_tools._extract_function(non_replayable_source, name) + "\n}\n")
    functions.append(r'''static NV_STATUS uvm_parent_gpu_fault_buffer_init_non_replayable_faults(uvm_parent_gpu_t *parent_gpu)
{
    ++non_replayable_init_calls;
    ++non_replayable_init_total;
    return uvm_parent_gpu_fault_buffer_init_non_replayable_faults_exact(parent_gpu);
}
static void uvm_parent_gpu_fault_buffer_deinit_non_replayable_faults(uvm_parent_gpu_t *parent_gpu)
{
    ++non_replayable_deinit_calls;
    ++non_replayable_deinit_total;
    uvm_parent_gpu_fault_buffer_deinit_non_replayable_faults_exact(parent_gpu);
}
''')
    for name, signature in (
        ("uvm_parent_gpu_fault_buffer_deinit",
         "void uvm_parent_gpu_fault_buffer_deinit(uvm_parent_gpu_t *parent_gpu)"),
        ("uvm_parent_gpu_fault_buffer_init",
         "NV_STATUS uvm_parent_gpu_fault_buffer_init(uvm_parent_gpu_t *parent_gpu)"),
        ("uvm_parent_gpu_fault_buffer_resume",
         "void uvm_parent_gpu_fault_buffer_resume(uvm_parent_gpu_t *parent_gpu)"),
    ):
        functions.append(signature + "\n{\n" + source_tools._extract_function(source, name) + "\n}\n")
    return "\n".join(functions) + _VECTOR_SUFFIX


_VECTOR_SUFFIX = r'''
static NvU32 run_success_case(void)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    uvm_perf_fault_batch_count = 99;
    uvm_perf_fault_replay_policy = 9;
    uvm_perf_fault_replay_update_put_ratio = 150;
    status = fault_buffer_init_replayable_faults(&gpu);
    check_value("init-success-status", status, NV_OK);
    check_value("init-success-allocation-count", allocation_calls, 3);
    check_value("init-success-max-faults", gpu.fault_buffer.replayable.max_faults, 8);
    check_value("init-success-clamped-batch-size", gpu.fault_buffer.max_batch_size, 8);
    check_value("init-success-fault-cache", gpu.fault_buffer.replayable.batch_service_context.fault_cache != NULL, true);
    check_value("init-success-ordered-cache", gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache != NULL, true);
    check_value("init-success-utlb-array", gpu.fault_buffer.replayable.batch_service_context.utlbs != NULL, true);
    check_value("init-success-tracker-init", tracker_init_calls, 1);
    check_value("init-success-rm-owner", owner_calls, 1);
    check_value("init-success-rm-device", (NvU64)(uintptr_t)owner_device, (NvU64)(uintptr_t)&device_sentinel);
    check_value("init-success-rm-own-flag", owner_flag, true);
    check_value("init-success-default-replay-policy", gpu.fault_buffer.replayable.replay_policy,
                UVM_PERF_FAULT_REPLAY_POLICY_DEFAULT);
    check_value("init-success-clamped-update-ratio", gpu.fault_buffer.replayable.replay_update_put_ratio, 100);
    check_value("init-success-prefetch-state", gpu.fault_buffer.prefetch_faults_enabled, true);
    check_value("init-success-prefetch-enable", prefetch_enable_calls, 1);
    check_value("init-success-prefetch-disable", prefetch_disable_calls, 0);
    check_value("init-success-read-get", read_get_calls, 1);
    check_value("init-success-read-put", read_put_calls, 1);
    check_value("init-success-cached-get", gpu.fault_buffer.replayable.cached_get, 7);
    check_value("init-success-cached-put", gpu.fault_buffer.replayable.cached_put, 2);
    read_get_value = 12;
    read_put_value = 9;
    fault_buffer_reinit_replayable_faults(&gpu);
    check_value("init-success-reinit-cached-get-refresh", gpu.fault_buffer.replayable.cached_get, 12);
    check_value("init-success-reinit-cached-put-refresh", gpu.fault_buffer.replayable.cached_put, 9);
    check_value("init-success-reinit-read-get-count", read_get_calls, 2);
    check_value("init-success-reinit-read-put-count", read_put_calls, 2);
    check_value("init-success-reinit-prefetch-enable-count", prefetch_enable_calls, 2);
    check_value("init-success-max-utlb-id", gpu.fault_buffer.replayable.batch_service_context.max_utlb_id, 0);
    check_value("init-success-fault-cache-bytes", allocation_sizes[0], 8 * sizeof(test_fault_cache_entry_t));
    check_value("init-success-ordered-cache-bytes", allocation_sizes[1], 8 * sizeof(test_ordered_fault_cache_entry_t));
    check_value("init-success-utlb-bytes", allocation_sizes[2], 3 * sizeof(NvU32));
    check_value("init-success-invalid-parameter-reports", info_print_calls, 3);
    fault_buffer_deinit_replayable_faults(&gpu);
    check_value("init-success-deinit-freed-three", kvfree_nonnull_calls, 3);
    check_value("init-success-deinit-tracker", tracker_deinit_calls, 1);
    check_value("init-success-deinit-cleared-pointers",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    check_value("init-success-deinit-no-prefetch-without-rm-handle", prefetch_enable_calls, 2);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_prefetch_capability_case(void)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, false);
    status = fault_buffer_init_replayable_faults(&gpu);
    check_value("init-prefetch-false-status", status, NV_OK);
    check_value("init-prefetch-false-state", gpu.fault_buffer.prefetch_faults_enabled,
                EXPECT_R580_SOURCE ? false : true);
    check_value("init-prefetch-false-enable-count", prefetch_enable_calls,
                EXPECT_R580_SOURCE ? 0 : 1);
    check_value("init-prefetch-false-disable-count", prefetch_disable_calls,
                EXPECT_R580_SOURCE ? 1 : 0);
    check_value("init-prefetch-false-read-get", read_get_calls, 1);
    check_value("init-prefetch-false-read-put", read_put_calls, 1);
    check_value("init-prefetch-false-cached-get", gpu.fault_buffer.replayable.cached_get, 7);
    check_value("init-prefetch-false-cached-put", gpu.fault_buffer.replayable.cached_put, 2);
    read_get_value = 3;
    read_put_value = 4;
    fault_buffer_reinit_replayable_faults(&gpu);
    check_value("init-prefetch-false-reinit-cached-get-refresh",
                gpu.fault_buffer.replayable.cached_get, 3);
    check_value("init-prefetch-false-reinit-cached-put-refresh",
                gpu.fault_buffer.replayable.cached_put, 4);
    check_value("init-prefetch-false-reinit-read-get-count", read_get_calls, 2);
    check_value("init-prefetch-false-reinit-read-put-count", read_put_calls, 2);
    check_value("init-prefetch-false-reinit-enable-count", prefetch_enable_calls,
                EXPECT_R580_SOURCE ? 0 : 2);
    check_value("init-prefetch-false-reinit-disable-count", prefetch_disable_calls,
                EXPECT_R580_SOURCE ? 2 : 0);
    fault_buffer_deinit_replayable_faults(&gpu);
    check_value("init-prefetch-false-deinit-freed-three", kvfree_nonnull_calls, 3);
    check_value("init-prefetch-false-deinit-tracker", tracker_deinit_calls, 1);
    check_value("init-prefetch-false-deinit-no-rm-reenable", prefetch_enable_calls,
                EXPECT_R580_SOURCE ? 0 : 2);
    check_value("init-prefetch-false-deinit-cleared-pointers",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    printf("prefetch-false enabled=%u enable_calls=%u disable_calls=%u\n",
           gpu.fault_buffer.prefetch_faults_enabled, prefetch_enable_calls,
           prefetch_disable_calls);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_allocation_failure_case(NvU32 fail_at)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    NvU32 expected_tracker = fail_at == 0 ? 0 : 1;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    allocation_fail_at = (int)fail_at;
    status = fault_buffer_init_replayable_faults(&gpu);
    check_value("init-allocation-failure-status", status, NV_ERR_NO_MEMORY);
    check_value("init-allocation-failure-count", allocation_calls, fail_at + 1);
    check_value("init-allocation-failure-tracker", tracker_init_calls, expected_tracker);
    check_value("init-allocation-failure-no-rm-owner", owner_calls, 0);
    check_value("init-allocation-failure-no-get-read", read_get_calls, 0);
    check_value("init-allocation-failure-no-put-read", read_put_calls, 0);
    check_value("init-allocation-failure-no-prefetch-enable", prefetch_enable_calls, 0);
    if (fail_at >= 1)
        check_value("init-allocation-failure-first-cache-retained",
                    gpu.fault_buffer.replayable.batch_service_context.fault_cache != NULL, true);
    if (fail_at >= 2)
        check_value("init-allocation-failure-second-cache-retained",
                    gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache != NULL, true);
    fault_buffer_deinit_replayable_faults(&gpu);
    check_value("init-allocation-failure-deinit-freed-retained",
                kvfree_nonnull_calls, fail_at);
    check_value("init-allocation-failure-deinit-tracker",
                tracker_deinit_calls, expected_tracker);
    check_value("init-allocation-failure-deinit-cleared-pointers",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_rm_ownership_failure_case(void)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    owner_status = (NV_STATUS)-5;
    status = fault_buffer_init_replayable_faults(&gpu);
    check_value("init-owner-failure-status", (NvU32)status, (NvU32)(NV_STATUS)-5);
    check_value("init-owner-failure-allocation-count", allocation_calls, 3);
    check_value("init-owner-failure-tracker-init", tracker_init_calls, 1);
    check_value("init-owner-failure-owner-call", owner_calls, 1);
    check_value("init-owner-failure-own-flag", owner_flag, true);
    check_value("init-owner-failure-fault-cache-retained",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache != NULL, true);
    check_value("init-owner-failure-ordered-cache-retained",
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache != NULL, true);
    check_value("init-owner-failure-utlb-retained",
                gpu.fault_buffer.replayable.batch_service_context.utlbs != NULL, true);
    check_value("init-owner-failure-no-get-read", read_get_calls, 0);
    check_value("init-owner-failure-no-prefetch-enable", prefetch_enable_calls, 0);
    fault_buffer_deinit_replayable_faults(&gpu);
    check_value("init-owner-failure-deinit-freed-three", kvfree_nonnull_calls, 3);
    check_value("init-owner-failure-deinit-tracker", tracker_deinit_calls, 1);
    check_value("init-owner-failure-deinit-no-rm-reenable", prefetch_enable_calls, 0);
    check_value("init-owner-failure-deinit-cleared-pointers",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_deinit_prefetch_case(bool has_rm_handle, bool prefetch_enabled,
                                      bool prefetch_supported)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    NvU32 expected_enable;
    reset_observation();
    gpu = make_gpu(256, 3, prefetch_supported);
    status = fault_buffer_init_replayable_faults(&gpu);
    check_value("deinit-prefetch-setup-status", status, NV_OK);
    gpu.fault_buffer.rm_info.faultBufferHandle = has_rm_handle ? 1 : 0;
    gpu.fault_buffer.prefetch_faults_enabled = prefetch_enabled;
    prefetch_enable_calls = 0;
    prefetch_disable_calls = 0;
    expected_enable = has_rm_handle && !prefetch_enabled &&
                      (prefetch_supported || !EXPECT_R580_SOURCE) ? 1 : 0;
    fault_buffer_deinit_replayable_faults(&gpu);
    check_value("deinit-prefetch-enable-count", prefetch_enable_calls, expected_enable);
    check_value("deinit-prefetch-freed-three", kvfree_nonnull_calls, 3);
    check_value("deinit-prefetch-tracker-deinitialized", tracker_deinit_calls, 1);
    check_value("deinit-prefetch-clear-pointer-fault-cache",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL, true);
    check_value("deinit-prefetch-clear-pointer-ordered-cache",
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL, true);
    check_value("deinit-prefetch-clear-pointer-utlbs",
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    printf("deinit-prefetch handle=%u enabled=%u supported=%u enable_calls=%u\n",
           has_rm_handle, prefetch_enabled, prefetch_supported, prefetch_enable_calls);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_parent_rm_init_failure_case(void)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    rm_init_status = (NV_STATUS)-6;
    rm_handle_on_init = 0xdead;
    status = uvm_parent_gpu_fault_buffer_init(&gpu);
    check_value("parent-rm-init-failure-status", (NvU32)status, (NvU32)(NV_STATUS)-6);
    check_value("parent-rm-init-failure-init-call", rm_init_calls, 1);
    check_value("parent-rm-init-failure-clears-partial-handle",
                gpu.fault_buffer.rm_info.faultBufferHandle, 0);
    check_value("parent-rm-init-failure-skips-pagefault-unown", owner_false_calls, 0);
    check_value("parent-rm-init-failure-skips-rm-destroy", rm_destroy_calls, 0);
    check_value("parent-rm-init-failure-no-buffer-allocations", allocation_calls, 0);
    check_value("parent-rm-init-failure-skips-nonreplay-init", non_replayable_init_calls, 0);
    check_value("parent-rm-init-failure-exact-nonreplay-deinit", non_replayable_deinit_calls, 1);
    check_value("parent-rm-init-failure-all-null-kvfree-count", kvfree_calls, 5);
    printf("parent-rm-init-failure handle=%u own_false=%u destroy=%u nonreplay_deinit=%u\n",
           gpu.fault_buffer.rm_info.faultBufferHandle, owner_false_calls, rm_destroy_calls,
           non_replayable_deinit_calls);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_parent_replayable_init_failure_case(void)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    allocation_fail_at = 1;
    status = uvm_parent_gpu_fault_buffer_init(&gpu);
    check_value("parent-replayable-init-failure-status", status, NV_ERR_NO_MEMORY);
    check_value("parent-replayable-init-failure-rm-call", rm_init_calls, 1);
    check_value("parent-replayable-init-failure-nonreplay-init", non_replayable_init_calls, 0);
    check_value("parent-replayable-init-failure-partial-buffer-freed", kvfree_nonnull_calls, 1);
    check_value("parent-replayable-init-failure-tracker-deinitialized", tracker_deinit_calls, 1);
    check_value("parent-replayable-init-failure-own-true", owner_true_calls, 0);
    check_value("parent-replayable-init-failure-own-false", owner_false_calls, 1);
    check_value("parent-replayable-init-failure-rm-destroy", rm_destroy_calls, 1);
    check_value("parent-replayable-init-failure-clears-handle",
                gpu.fault_buffer.rm_info.faultBufferHandle, 0);
    check_value("parent-replayable-init-failure-restores-prefetch", prefetch_enable_calls, 1);
    check_value("parent-replayable-init-failure-exact-nonreplay-deinit",
                non_replayable_deinit_calls, 1);
    check_value("parent-replayable-init-failure-all-kvfree-count", kvfree_calls, 5);
    check_value("parent-replayable-init-failure-clears-caches",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    printf("parent-replayable-init-failure own_true=%u own_false=%u destroy=%u prefetch=%u\n",
           owner_true_calls, owner_false_calls, rm_destroy_calls, prefetch_enable_calls);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_parent_nonreplayable_init_failure_case(NvU32 fail_at)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    allocation_fail_at = (int)fail_at;
    status = uvm_parent_gpu_fault_buffer_init(&gpu);
    check_value("parent-nonreplayable-init-failure-status", status, NV_ERR_NO_MEMORY);
    check_value("parent-nonreplayable-init-failure-init-call", non_replayable_init_calls, 1);
    check_value("parent-nonreplayable-init-failure-deinit-call", non_replayable_deinit_calls, 1);
    check_value("parent-nonreplayable-init-failure-allocation-count", allocation_calls, fail_at + 1);
    check_value("parent-nonreplayable-init-failure-exact-partial-free-count",
                kvfree_nonnull_calls, fail_at == 3 ? 3 : 4);
    check_value("parent-nonreplayable-init-failure-all-kvfree-count", kvfree_calls, 5);
    check_value("parent-nonreplayable-init-failure-tracker-deinit", tracker_deinit_calls, 1);
    check_value("parent-nonreplayable-init-failure-owner-true", owner_true_calls, 1);
    check_value("parent-nonreplayable-init-failure-owner-false", owner_false_calls, 1);
    check_value("parent-nonreplayable-init-failure-final-owner-flag", owner_flag, false);
    check_value("parent-nonreplayable-init-failure-rm-destroy", rm_destroy_calls, 1);
    check_value("parent-nonreplayable-init-failure-clears-handle",
                gpu.fault_buffer.rm_info.faultBufferHandle, 0);
    check_value("parent-nonreplayable-init-failure-no-extra-prefetch", prefetch_enable_calls, 1);
    check_value("parent-nonreplayable-init-failure-clears-shadow",
                gpu.fault_buffer.non_replayable.shadow_buffer_copy == NULL, true);
    check_value("parent-nonreplayable-init-failure-clears-nonreplay-cache",
                gpu.fault_buffer.non_replayable.fault_cache == NULL, true);
    check_value("parent-nonreplayable-init-failure-clears-caches",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    printf("parent-nonreplayable-init-failure fail_at=%u own_true=%u own_false=%u destroy=%u freed=%u\n",
           fail_at, owner_true_calls, owner_false_calls, rm_destroy_calls, kvfree_nonnull_calls);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static NvU32 run_parent_success_resume_deinit_case(void)
{
    uvm_parent_gpu_t gpu;
    NV_STATUS status;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    status = uvm_parent_gpu_fault_buffer_init(&gpu);
    check_value("parent-success-init-status", status, NV_OK);
    check_value("parent-success-allocation-count", allocation_calls, 5);
    check_value("parent-success-rm-handle", gpu.fault_buffer.rm_info.faultBufferHandle, 0x55);
    check_value("parent-success-exact-nonreplay-init", non_replayable_init_calls, 1);
    check_value("parent-success-nonreplay-shadow-buffer",
                gpu.fault_buffer.non_replayable.shadow_buffer_copy != NULL, true);
    check_value("parent-success-nonreplay-fault-cache",
                gpu.fault_buffer.non_replayable.fault_cache != NULL, true);
    check_value("parent-success-nonreplay-max-faults", gpu.fault_buffer.non_replayable.max_faults, 3);
    check_value("parent-success-nonreplay-shadow-size", allocation_sizes[3], 96);
    check_value("parent-success-nonreplay-cache-size", allocation_sizes[4],
                3 * sizeof(test_non_replayable_fault_cache_entry_t));
    check_value("parent-success-all-tracker-init", tracker_init_calls, 3);
    check_value("parent-success-owner-true", owner_true_calls, 1);
    read_get_value = 18;
    read_put_value = 19;
    uvm_parent_gpu_fault_buffer_resume(&gpu);
    check_value("parent-resume-refresh-get", gpu.fault_buffer.replayable.cached_get, 18);
    check_value("parent-resume-refresh-put", gpu.fault_buffer.replayable.cached_put, 19);
    check_value("parent-resume-enable-prefetch", prefetch_enable_calls, 2);
    check_value("parent-resume-get-calls", read_get_calls, 2);
    check_value("parent-resume-put-calls", read_put_calls, 2);
    uvm_parent_gpu_fault_buffer_deinit(&gpu);
    check_value("parent-deinit-exact-nonreplay-deinit", non_replayable_deinit_calls, 1);
    check_value("parent-deinit-frees-all", kvfree_nonnull_calls, 5);
    check_value("parent-deinit-all-kvfree-count", kvfree_calls, 5);
    check_value("parent-deinit-all-trackers-deinitialized", tracker_deinit_calls, 3);
    check_value("parent-deinit-owner-true", owner_true_calls, 1);
    check_value("parent-deinit-owner-false", owner_false_calls, 1);
    check_value("parent-deinit-final-owner-flag", owner_flag, false);
    check_value("parent-deinit-rm-destroy", rm_destroy_calls, 1);
    check_value("parent-deinit-clears-handle", gpu.fault_buffer.rm_info.faultBufferHandle, 0);
    check_value("parent-deinit-no-extra-prefetch", prefetch_enable_calls, 2);
    check_value("parent-deinit-clears-caches",
                gpu.fault_buffer.replayable.batch_service_context.fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.ordered_fault_cache == NULL &&
                gpu.fault_buffer.replayable.batch_service_context.utlbs == NULL, true);
    check_value("parent-deinit-clears-nonreplay-shadow",
                gpu.fault_buffer.non_replayable.shadow_buffer_copy == NULL, true);
    check_value("parent-deinit-clears-nonreplay-cache",
                gpu.fault_buffer.non_replayable.fault_cache == NULL, true);
    printf("parent-success-resume-deinit own_true=%u own_false=%u destroy=%u get=%u put=%u\n",
           owner_true_calls, owner_false_calls, rm_destroy_calls, read_get_calls, read_put_calls);
    release_gpu_allocations(&gpu);
    return failures ? 1 : 0;
}

static int probe_guard(const char *mode)
{
    uvm_parent_gpu_t gpu;
    reset_observation();
    gpu = make_gpu(256, 3, true);
    if (strcmp(mode, "--probe-zero-utlb") == 0)
        gpu.fault_buffer.replayable.utlb_count = 0;
    else if (strcmp(mode, "--probe-non-divisible-buffer-size") == 0)
        gpu.fault_buffer.rm_info.replayable.bufferSize = 255;
    else if (strcmp(mode, "--probe-tracker-nonempty") == 0) {
        gpu.fault_buffer.replayable.batch_service_context.fault_cache = calloc(1, 64);
        uvm_tracker_init(&gpu.fault_buffer.replayable.replay_tracker);
        tracker_empty = false;
        fault_buffer_deinit_replayable_faults(&gpu);
    }
    else
        return 2;
    return fault_buffer_init_replayable_faults(&gpu);
}

int main(int argc, char **argv)
{
    NvU32 checks_before = assertion_count;
    NvU32 before = failures;
    non_replayable_init_total = 0;
    non_replayable_deinit_total = 0;
    if (argc == 2)
        return probe_guard(argv[1]);
    run_success_case();
    run_prefetch_capability_case();
    run_allocation_failure_case(0);
    run_allocation_failure_case(1);
    run_allocation_failure_case(2);
    run_rm_ownership_failure_case();
    run_deinit_prefetch_case(false, false, true);
    run_deinit_prefetch_case(true, true, true);
    run_deinit_prefetch_case(true, false, true);
    run_deinit_prefetch_case(true, false, false);
    run_parent_rm_init_failure_case();
    run_parent_replayable_init_failure_case();
    run_parent_nonreplayable_init_failure_case(3);
    run_parent_nonreplayable_init_failure_case(4);
    run_parent_success_resume_deinit_case();
    printf("summary vectors=15 checks=%u failures=%u\n",
           assertion_count - checks_before, failures - before);
    printf("helper-invocations non_replayable_init=%u non_replayable_deinit=%u\n",
           non_replayable_init_total, non_replayable_deinit_total);
    return failures == before ? 0 : 1;
}
'''


def _source_records(r580_uvm: Path, r595_uvm: Path) -> dict:
    records = {}
    for name, root in (("r580", r580_uvm), ("r595", r595_uvm)):
        service_path = (root / "uvm_gpu_replayable_faults.c").resolve(strict=True)
        non_replayable_path = (root / "uvm_gpu_non_replayable_faults.c").resolve(strict=True)
        gpu_header_path = (root / "uvm_gpu.h").resolve(strict=True)
        volta_path = (root / "uvm_volta.c").resolve(strict=True)
        hashes = {
            "service_source_sha256": source_tools.sha256_file(service_path),
            "non_replayable_source_sha256": source_tools.sha256_file(non_replayable_path),
            "gpu_header_sha256": source_tools.sha256_file(gpu_header_path),
            "volta_source_sha256": source_tools.sha256_file(volta_path),
        }
        for key, value in hashes.items():
            expected = PINNED[name][key.removesuffix("_source_sha256") if key == "service_source_sha256" else key.removesuffix("_sha256")]
            if value != expected:
                raise ValueError(f"{name} {key} differs from pinned source: {value}")

        service_source = service_path.read_text(encoding="utf-8")
        non_replayable_source = non_replayable_path.read_text(encoding="utf-8")
        gpu_header = gpu_header_path.read_text(encoding="utf-8")
        volta_source = volta_path.read_text(encoding="utf-8")
        init_body_hash = source_tools._normalized_function_hash(
            service_source, "fault_buffer_init_replayable_faults"
        )
        deinit_body_hash = source_tools._normalized_function_hash(
            service_source, "fault_buffer_deinit_replayable_faults"
        )
        reinit_body_hash = source_tools._normalized_function_hash(
            service_source, "fault_buffer_reinit_replayable_faults"
        )
        if init_body_hash != PINNED[name]["init_body"]:
            raise ValueError(f"{name} replayable fault-buffer init body changed")
        if deinit_body_hash != PINNED[name]["deinit_body"]:
            raise ValueError(f"{name} replayable fault-buffer deinit body changed")
        if reinit_body_hash != PINNED[name]["reinit_body"]:
            raise ValueError(f"{name} replayable fault-buffer reinit body changed")
        non_replayable_init_hash = source_tools._normalized_function_hash(
            non_replayable_source, "uvm_parent_gpu_fault_buffer_init_non_replayable_faults"
        )
        non_replayable_deinit_hash = source_tools._normalized_function_hash(
            non_replayable_source, "uvm_parent_gpu_fault_buffer_deinit_non_replayable_faults"
        )
        if non_replayable_init_hash != PINNED[name]["non_replayable_init_body"]:
            raise ValueError(f"{name} non-replayable fault-buffer init helper changed")
        if non_replayable_deinit_hash != PINNED[name]["non_replayable_deinit_body"]:
            raise ValueError(f"{name} non-replayable fault-buffer deinit helper changed")
        non_replayable_init_body = source_tools._mask_comments(
            source_tools._extract_function(non_replayable_source,
                                           "uvm_parent_gpu_fault_buffer_init_non_replayable_faults")
        )
        non_replayable_capability_assert = re.search(
            r"UVM_ASSERT\s*\(\s*parent_gpu->non_replayable_faults_supported\s*\)",
            non_replayable_init_body,
        ) is not None
        if non_replayable_capability_assert != (name == "r580"):
            raise ValueError(f"{name} non-replayable capability assertion changed")
        normalized_non_replayable_init = re.sub(
            r"UVM_ASSERT\s*\(\s*parent_gpu->non_replayable_faults_supported\s*\)\s*;",
            "",
            non_replayable_init_body,
        )
        outer_hashes = {
            "parent_fault_buffer_init_body_sha256": source_tools._normalized_function_hash(
                service_source, "uvm_parent_gpu_fault_buffer_init"
            ),
            "parent_resume_body_sha256": source_tools._normalized_function_hash(
                service_source, "uvm_parent_gpu_fault_buffer_resume"
            ),
            "parent_deinit_body_sha256": source_tools._normalized_function_hash(
                service_source, "uvm_parent_gpu_fault_buffer_deinit"
            ),
        }
        for field, body_key in (("parent_fault_buffer_init_body_sha256", "parent_init_body"),
                                ("parent_resume_body_sha256", "parent_resume_body"),
                                ("parent_deinit_body_sha256", "parent_deinit_body")):
            if outer_hashes[field] != PINNED[name][body_key]:
                raise ValueError(f"{name} {field} differs from pinned source")
        parent_init_body = source_tools._mask_comments(
            source_tools._extract_function(service_source, "uvm_parent_gpu_fault_buffer_init")
        )
        parent_resume_body = source_tools._mask_comments(
            source_tools._extract_function(service_source, "uvm_parent_gpu_fault_buffer_resume")
        )
        parent_deinit_body = source_tools._mask_comments(
            source_tools._extract_function(service_source, "uvm_parent_gpu_fault_buffer_deinit")
        )
        replayable_asserts = {
            "replayable_capability_assert_in_parent_init": re.search(
                r"UVM_ASSERT\s*\(\s*parent_gpu->replayable_faults_supported\s*\)",
                parent_init_body,
            ) is not None,
            "replayable_capability_assert_in_parent_resume": re.search(
                r"UVM_ASSERT\s*\(\s*parent_gpu->replayable_faults_supported\s*\)",
                parent_resume_body,
            ) is not None,
        }
        nonreplayable_guards = {
            "nonreplayable_init_is_conditional": re.search(
                r"if\s*\(\s*parent_gpu->non_replayable_faults_supported\s*\)",
                parent_init_body,
            ) is not None,
            "nonreplayable_deinit_is_conditional": re.search(
                r"if\s*\(\s*parent_gpu->non_replayable_faults_supported\s*\)",
                parent_deinit_body,
            ) is not None,
        }
        expected_outer_contract = {
            "replayable_capability_assert_in_parent_init": name == "r580",
            "replayable_capability_assert_in_parent_resume": name == "r580",
        }
        expected_nonreplayable_guards = {
            "nonreplayable_init_is_conditional": name == "r580",
            "nonreplayable_deinit_is_conditional": name == "r580",
        }
        if replayable_asserts != expected_outer_contract:
            raise ValueError(f"{name} parent replayable capability assertion contract changed")
        if nonreplayable_guards != expected_nonreplayable_guards:
            raise ValueError(f"{name} parent non-replayable guard contract changed")
        init_body = source_tools._extract_function(service_source, "fault_buffer_init_replayable_faults")
        prefetch_read = re.search(
            r"prefetch_faults_enabled\s*=\s*parent_gpu->prefetch_fault_supported\s*;",
            source_tools._mask_comments(init_body),
        ) is not None
        if prefetch_read != (name == "r580"):
            raise ValueError(f"{name} prefetch capability expression changed")
        deinit_body = source_tools._extract_function(service_source, "fault_buffer_deinit_replayable_faults")
        deinit_prefetch_read = re.search(
            r"prefetch_fault_supported\s*&&\s*!parent_gpu->fault_buffer\.prefetch_faults_enabled",
            source_tools._mask_comments(deinit_body),
        ) is not None
        if deinit_prefetch_read != (name == "r580"):
            raise ValueError(f"{name} deinit prefetch capability expression changed")
        capability_fields = {
            field: re.search(r"\bbool\s+" + re.escape(field) + r"\s*;", gpu_header) is not None
            for field in ("prefetch_fault_supported", "replayable_faults_supported",
                          "non_replayable_faults_supported")
        }
        expected_capability_fields = {field: name == "r580" for field in capability_fields}
        if capability_fields != expected_capability_fields:
            raise ValueError(f"{name} capability field set differs from pinned contract")
        volte_fields = {
            "prefetch_fault_supported_true": re.search(
                r"parent_gpu->prefetch_fault_supported\s*=\s*true\s*;", volta_source
            ) is not None,
            "replayable_faults_supported_true": re.search(
                r"parent_gpu->replayable_faults_supported\s*=\s*true\s*;", volta_source
            ) is not None,
            "non_replayable_faults_supported_true": re.search(
                r"parent_gpu->non_replayable_faults_supported\s*=\s*true\s*;", volta_source
            ) is not None,
        }
        expected_volta_fields = {field: name == "r580" for field in volte_fields}
        if volte_fields != expected_volta_fields:
            raise ValueError(f"{name} Volta capability initialization differs from pinned contract")
        normalized_without_prefetch_source = re.sub(
            r"parent_gpu->fault_buffer\.prefetch_faults_enabled\s*=\s*(?:parent_gpu->prefetch_fault_supported|true)\s*;",
            "parent_gpu->fault_buffer.prefetch_faults_enabled = PREFETCH_CONTRACT;",
            source_tools._mask_comments(init_body),
        )
        normalized_deinit_without_prefetch = re.sub(
            r"parent_gpu->prefetch_fault_supported\s*&&\s*!parent_gpu->fault_buffer\.prefetch_faults_enabled|!parent_gpu->fault_buffer\.prefetch_faults_enabled",
            "PREFETCH_DISABLED_CONTRACT",
            source_tools._mask_comments(deinit_body),
        )
        records[name] = {
            **hashes,
            **outer_hashes,
            **replayable_asserts,
            **nonreplayable_guards,
            "fault_buffer_init_body_sha256": init_body_hash,
            "fault_buffer_deinit_body_sha256": deinit_body_hash,
            "fault_buffer_reinit_body_sha256": reinit_body_hash,
            "prefetch_capability_read_present": prefetch_read,
            "deinit_prefetch_capability_read_present": deinit_prefetch_read,
            "capability_fields_present": capability_fields,
            "volta_capability_initialization": volte_fields,
            "init_body_without_prefetch_expression_sha256": source_tools.sha256_bytes(
                "".join(normalized_without_prefetch_source.split()).encode("utf-8")
            ),
            "deinit_body_without_prefetch_expression_sha256": source_tools.sha256_bytes(
                "".join(normalized_deinit_without_prefetch.split()).encode("utf-8")
            ),
            "non_replayable_init_body_sha256": non_replayable_init_hash,
            "non_replayable_deinit_body_sha256": non_replayable_deinit_hash,
            "non_replayable_init_capability_assert_present": non_replayable_capability_assert,
            "non_replayable_init_without_capability_assert_sha256": source_tools.sha256_bytes(
                "".join(normalized_non_replayable_init.split()).encode("utf-8")
            ),
        }
    if records["r580"]["fault_buffer_reinit_body_sha256"] != records["r595"]["fault_buffer_reinit_body_sha256"]:
        raise ValueError("R580/R595 replayable fault-buffer reinit helper differs")
    if records["r580"]["deinit_body_without_prefetch_expression_sha256"] != records["r595"]["deinit_body_without_prefetch_expression_sha256"]:
        raise ValueError("R580/R595 deinit function differs beyond the prefetch capability expression")
    if records["r580"]["init_body_without_prefetch_expression_sha256"] != records["r595"]["init_body_without_prefetch_expression_sha256"]:
        raise ValueError("R580/R595 init function differs beyond the prefetch capability expression")
    if records["r580"]["non_replayable_deinit_body_sha256"] != records["r595"]["non_replayable_deinit_body_sha256"]:
        raise ValueError("R580/R595 non-replayable deinit helper differs")
    if records["r580"]["non_replayable_init_without_capability_assert_sha256"] != records["r595"]["non_replayable_init_without_capability_assert_sha256"]:
        raise ValueError("R580/R595 non-replayable init helper differs beyond its R580 capability assertion")
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
        raise FileExistsError("refusing to overwrite fault-init evidence")
    source_pair = _source_records(r580_uvm, r595_uvm)
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise ValueError(f"compiler not found: {compiler}")
    compiler_version = subprocess.run([compiler_path, "--version"], capture_output=True,
                                      text=True, check=True).stdout.splitlines()[0]
    logs = []
    outputs = {}
    guard_count = 0
    with tempfile.TemporaryDirectory(prefix="volta-fault-init-host-") as directory:
        scratch = Path(directory)
        for name, root in (("r580", r580_uvm), ("r595", r595_uvm)):
            common = (root.parent / "common/inc").resolve(strict=True)
            c_path = scratch / f"{name}_fault_init.c"
            binary = scratch / f"{name}_fault_init"
            c_path.write_text(_build_source(root, name == "r580"), encoding="utf-8")
            command = [compiler_path, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                       "-I", str(common), str(c_path), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            logs.append("$ " + shlex.join(command) + "\n" + compiled.stdout + compiled.stderr)
            if compiled.returncode != 0:
                raise RuntimeError(f"{name} exact-source fault-init compile failed")
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            logs.append("$ " + shlex.quote(str(binary)) + "\n" + executed.stdout + executed.stderr)
            summary = re.search(r"summary vectors=(\d+) checks=(\d+) failures=(\d+)", executed.stdout)
            helper_invocations = re.search(
                r"helper-invocations non_replayable_init=(\d+) non_replayable_deinit=(\d+)",
                executed.stdout,
            )
            if executed.returncode != 0 or summary is None or summary.group(1) != "15" or summary.group(3) != "0":
                raise RuntimeError(f"{name} exact-source fault-init vectors failed")
            if helper_invocations is None or helper_invocations.groups() != ("3", "5"):
                raise RuntimeError(f"{name} exact non-replayable helper invocation counts changed")
            checks = int(summary.group(2))
            if checks <= 67:
                raise RuntimeError(f"{name} deinit assertions were not added to the source harness")
            if name == "r580" and "prefetch-false enabled=0 enable_calls=0 disable_calls=2" not in executed.stdout:
                raise RuntimeError("R580 capability-gated prefetch disable path changed")
            if name == "r595" and "prefetch-false enabled=1 enable_calls=2 disable_calls=0" not in executed.stdout:
                raise RuntimeError("R595 unconditional prefetch behavior changed")
            outputs[name] = executed.stdout
            for guard in GUARDS:
                probe = subprocess.run([str(binary), guard], capture_output=True, text=True,
                                       preexec_fn=source_tools._disable_core_dumps)
                logs.append("$ " + shlex.quote(str(binary)) + " " + guard +
                            "\nexpected assertion rejection; returncode=" + str(probe.returncode) +
                            "\n" + probe.stdout + probe.stderr)
                if probe.returncode != -signal.SIGABRT:
                    raise RuntimeError(f"expected fault-init assertion guard failed: {name} {guard}")
                guard_count += 1
    checks_by_source = {
        name: int(re.search(r"summary vectors=15 checks=(\d+) failures=0", output).group(1))
        for name, output in outputs.items()
    }
    if checks_by_source["r580"] != checks_by_source["r595"]:
        raise RuntimeError("R580/R595 host harness assertion counts differ")
    if guard_count != len(GUARDS) * 2:
        raise RuntimeError("not all assertion guards were observed for both source trees")
    log_bytes = "".join(logs).encode("utf-8")
    log_sha256 = source_tools.sha256_bytes(log_bytes)
    source_tools._write_exclusive(log_path.resolve(), log_bytes)
    report = {
        "schema": "codex.volta-fault-init-host-harness.v4",
        "status": "passed",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "host-cpu-execution-of-pinned-volta-fault-buffer-lifecycle-v5",
        "supersedes": {
            "report": "volta-fault-buffer-parent-lifecycle-host-v4-20261028T061343Z.json",
            "reason": "v4 used synthetic non-replayable callbacks; v5 executes the exact pinned R580/R595 helpers through parent init, unwind, and teardown",
        },
        "implementations_executed": 2,
        "vectors_per_implementation": 15,
        "inner_helper_vectors_per_implementation": 10,
        "outer_caller_vectors_per_implementation": 5,
        "non_replayable_init_attempts_per_implementation": 3,
        "non_replayable_deinit_calls_per_implementation": 5,
        "checks_per_implementation": checks_by_source["r580"],
        "checks_passed": 2 * checks_by_source["r580"],
        "partial_cleanup_vectors_per_implementation": 4,
        "deinit_prefetch_vectors_per_implementation": 4,
        "reinit_vectors_per_implementation": 2,
        "reinit_contract": {
            "readback": "exact helper refreshes cached GET and PUT from the selected Volta HAL callbacks",
            "prefetch": "exact helper replays enable/disable according to fault_buffer.prefetch_faults_enabled",
            "states": ["prefetch-enabled", "prefetch-disabled"],
        },
        "assertion_guards": list(GUARDS),
        "expected_guard_count": guard_count,
        "prefetch_false_counterfactual": {
            "r580": "enabled=false; callback=disable_prefetch_faults",
            "r595": "enabled=true; callback=enable_prefetch_faults",
            "scope": "synthetic field value; GV100 source initializes R580 capability true, and R595 has no such field",
        },
        "deinit_prefetch_contract": {
            "r580": "reenable only when RM faultBufferHandle exists, prefetch is disabled, and prefetch_fault_supported is true",
            "r595": "reenable when RM faultBufferHandle exists and prefetch is disabled",
            "synthetic_case": "the final vector sets the compatibility-shim capability false on both sources; this is a R580 counterfactual and not a live R595 field",
        },
        "outer_caller_contract": {
            "executed_functions": [
                "uvm_parent_gpu_fault_buffer_init",
                "uvm_parent_gpu_fault_buffer_resume",
                "uvm_parent_gpu_fault_buffer_deinit",
            ],
            "r580": "asserts replayable support and conditionally initializes/deinitializes non-replayable fault buffers",
            "r595": "omits replayable support assertions and calls non-replayable init/deinit unconditionally",
            "failure_paths": [
                "RM init failure clears a partially populated faultBufferHandle and skips RM destroy",
                "replayable allocation failure unwinds partial UVM state and releases RM page-fault ownership",
                "first non-replayable allocation failure unwinds replayable state and destroys RM fault info",
                "second non-replayable allocation failure frees the partial shadow buffer, unwinds replayable state, and destroys RM fault info",
                "success followed by resume refresh and deinit releases owned resources",
            ],
            "synthetic_collaborators": [
                "nvUvmInterfaceInitFaultInfo",
                "nvUvmInterfaceOwnPageFaultIntr",
                "nvUvmInterfaceDestroyFaultInfo",
                "allocator, tracker, HAL callbacks, and synthetic non-replayable cache-entry representation",
            ],
        },
        "non_replayable_helper_contract": {
            "executed_functions": [
                "uvm_parent_gpu_fault_buffer_init_non_replayable_faults",
                "uvm_parent_gpu_fault_buffer_deinit_non_replayable_faults",
            ],
            "allocation_failures": ["shadow buffer allocation", "fault-cache allocation after shadow-buffer success"],
            "synthetic_inputs": {
                "rm_buffer_size_bytes": 96,
                "hal_entry_size_bytes": 32,
                "derived_max_faults": 3,
                "test_cache_entry_size_bytes": 16,
                "test_fault_cache_allocation_bytes": 48,
            },
            "scope": "exact helper arithmetic and control flow execute, but the cache-entry type layout is a host-harness substitute rather than the kernel UVM ABI type",
        },
        "hardware_validated": False,
        "module_loaded": False,
        "source_pair": source_pair,
        "compiler": {"path": compiler_path, "version": compiler_version},
        "compile_flags": ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"],
        "runner": {"path": str(Path(__file__).resolve()),
                   "sha256": source_tools.sha256_file(Path(__file__).resolve())},
        "report": {"path": str(report_path.resolve()), "mode": "0600"},
        "log": {"path": str(log_path.resolve()), "sha256": log_sha256, "mode": "0600"},
        "limits": [
            "Exact replayable init/reinit/deinit helpers, both exact non-replayable helpers, and the outer parent init/resume/deinit bodies are compiled and called for both pinned source trees.",
            "Exact fault_buffer_deinit_replayable_faults body is called after all three allocation failure points, RM page-fault ownership failure, and prefetch cleanup states; frees are counted and returned pointers checked null.",
            "The exact non-replayable init helper is reached three times per source and its exact deinit helper five times across RM-init failure, replayable-init failure, both non-replayable allocation failures, and successful resume/teardown.",
            "RM interface calls, allocator, trackers, HAL, and cache-entry type representation are synthetic collaborators; RM implementation bodies and the real kernel UVM ABI layout are not executed here.",
            "The nonempty-tracker guard aborts at the source UVM_ASSERT before deinit proceeds.",
            "HAL entry size, GET/PUT reads, prefetch callbacks, allocator, tracker, and RM ownership API are synthetic CPU collaborators; GET/PUT callback bodies are tested separately by the Volta ring harness.",
            "Partial-allocation cleanup executes the NVIDIA deinit helper against CPU allocations, not the kernel allocator or live RM objects.",
            "The R595 prefetch=false vector is a synthetic counterfactual because that release removed the prefetch_fault_supported field; it is not a supported live R595 GPU state.",
            "No UVM module, RM, GPU, DMA, interrupt, CUDA context, or runtime fault is exercised.",
        ],
        "result_stdout_sha256": {
            name: source_tools.sha256_bytes(output.encode("utf-8"))
            for name, output in outputs.items()
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
        "vectors_per_implementation": 15,
        "checks_passed": 2 * checks_by_source["r580"],
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
        print(f"fault-init host harness failed: {error}", file=sys.stderr)
        raise SystemExit(2)
