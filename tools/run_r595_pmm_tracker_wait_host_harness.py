#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile pinned R595 PMM/tracker bodies against gated host-only stubs."""
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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import run_volta_fault_decode_host_harness as source_tools  # noqa: E402


SOURCE_ROOT = ROOT / (
    "build/experiments/r595-pmm-tracker-wait-outside-root-bitlock-final-v1-20261029/"
    "candidate/nvidia-uvm"
)
SOURCE_HASHES = {
    "uvm_pmm_gpu.c": "f184f336b632575f077801db74e03635351ed56fe8cec1225bb066471911e52b",
    "uvm_tracker.c": "1b7fd32a785b78af5492c30a297e148f421af3e04108a587a641932d4ca7499a",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_sources() -> tuple[dict[str, str], dict[str, str]]:
    sources: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for name, expected in SOURCE_HASHES.items():
        path = SOURCE_ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"pinned source must be a regular file: {path}")
        payload = path.read_bytes()
        actual = _sha256(payload)
        if actual != expected:
            raise ValueError(f"pinned source SHA-256 mismatch for {name}: {actual}")
        sources[name] = payload.decode("utf-8")
        hashes[name] = actual
    return sources, hashes


def _mutate_wait_under_lock(pmm_source: str) -> str:
    unlock = "        root_chunk_unlock(pmm, root_chunk);\n\n"
    wait = (
        "        if (status == NV_ERR_NO_MEMORY) {\n"
        "            UVM_DBG_PRINT_RL(\"Failed to add tracker to tracker, waiting\\n\");\n"
        "            status = uvm_tracker_wait(tracker);\n"
        "        }"
    )
    old = unlock + wait
    new = wait + "\n\n" + unlock.rstrip()
    if pmm_source.count(old) != 1:
        raise ValueError("cannot construct the lock-held-wait negative control")
    return pmm_source.replace(old, new, 1)


def _translation_unit(pmm_source: str, tracker_source: str) -> str:
    pmm_free_body = source_tools._extract_function(pmm_source, "uvm_pmm_gpu_free")
    tracker_add_body = source_tools._extract_function(tracker_source, "uvm_tracker_add_tracker")
    tracker_static_body = source_tools._extract_function(tracker_source, "tracker_is_using_static_entries")
    tracker_entries_body = source_tools._extract_function(tracker_source, "uvm_tracker_get_entries")
    tracker_reserve_body = source_tools._extract_function(tracker_source, "uvm_tracker_reserve")
    merge_reserve_body = source_tools._extract_function(tracker_source, "reserve_for_entries_from_tracker")

    prefix = r'''#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int NV_STATUS;
typedef uint32_t NvU32;
typedef struct uvm_tracker_entry_struct {
    const void *channel;
    uint64_t value;
} uvm_tracker_entry_t;
typedef struct uvm_tracker_struct {
    uvm_tracker_entry_t static_entries[2];
    uvm_tracker_entry_t *dynamic_entries;
    size_t size;
    NvU32 max_size;
} uvm_tracker_t;
typedef struct uvm_gpu_root_chunk_struct {
    pthread_mutex_t bitlock;
    uvm_tracker_t tracker;
} uvm_gpu_root_chunk_t;
typedef struct uvm_gpu_chunk_struct {
    atomic_int state;
    bool is_referenced;
    uvm_gpu_root_chunk_t *root;
} uvm_gpu_chunk_t;
typedef struct uvm_pmm_gpu_struct { unsigned unused; } uvm_pmm_gpu_t;

#define NV_OK 0
#define NV_ERR_NO_MEMORY 1
#define UVM_PMM_GPU_CHUNK_STATE_ALLOCATED 3
#define UVM_PMM_GPU_CHUNK_STATE_TEMP_PINNED 4
#define UVM_PMM_GPU_CHUNK_STATE_FREE 2
#define UVM_ASSERT(condition) assert(condition)
#define UVM_ASSERT_MSG(condition, ...) assert(condition)
#define UVM_DBG_PRINT_RL(...) ((void)0)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define max(a, b) ((a) > (b) ? (a) : (b))
static uvm_tracker_entry_t *uvm_tracker_get_entries(uvm_tracker_t *tracker);
#define for_each_tracker_entry(entry, tracker) \
    for ((entry) = uvm_tracker_get_entries(tracker); \
         (size_t)((entry) - uvm_tracker_get_entries(tracker)) < (tracker)->size; \
         ++(entry))

static _Thread_local unsigned root_bitlock_depth;
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static bool tracker_wait_entered;
static bool release_tracker_wait;
static unsigned tracker_wait_calls;
static unsigned wait_root_bitlock_depth;
static unsigned reserve_allocator_attempts;
static unsigned allocator_failures_remaining = 2;
static atomic_bool competitor_acquired;
static atomic_uint free_calls;
static const char sibling_channel_a;
static const char sibling_channel_b;
static const char incoming_channel_c;

static bool uvm_tracker_is_empty(uvm_tracker_t *tracker)
{
    return tracker->size == 0;
}

static void *uvm_kvmalloc(size_t size)
{
    ++reserve_allocator_attempts;
    if (allocator_failures_remaining) {
        --allocator_failures_remaining;
        return NULL;
    }
    return malloc(size);
}

static void *uvm_kvrealloc(void *allocation, size_t size)
{
    ++reserve_allocator_attempts;
    if (allocator_failures_remaining) {
        --allocator_failures_remaining;
        return NULL;
    }
    return realloc(allocation, size);
}

static NvU32 roundup_pow_of_two(NvU32 value)
{
    NvU32 rounded = 1;
    while (rounded < value)
        rounded <<= 1;
    return rounded;
}

static void uvm_tracker_remove_completed(uvm_tracker_t *tracker)
{
    // Every seeded entry models an incomplete semaphore dependency.
    (void)tracker;
}

static NV_STATUS uvm_tracker_add_entry(uvm_tracker_t *tracker, uvm_tracker_entry_t *entry)
{
    uvm_tracker_entry_t *existing;
    for_each_tracker_entry(existing, tracker) {
        if (existing->channel == entry->channel) {
            if (existing->value < entry->value)
                existing->value = entry->value;
            return NV_OK;
        }
    }
    if (tracker->size >= tracker->max_size)
        return NV_ERR_NO_MEMORY;
    uvm_tracker_get_entries(tracker)[tracker->size++] = *entry;
    return NV_OK;
}

static NV_STATUS uvm_tracker_wait(uvm_tracker_t *tracker)
{
    (void)tracker;
    pthread_mutex_lock(&gate_mutex);
    ++tracker_wait_calls;
    wait_root_bitlock_depth = root_bitlock_depth;
    tracker_wait_entered = true;
    pthread_cond_broadcast(&gate_cond);
    while (!release_tracker_wait)
        pthread_cond_wait(&gate_cond, &gate_mutex);
    pthread_mutex_unlock(&gate_mutex);
    return NV_OK;
}

static uvm_gpu_root_chunk_t *root_chunk_from_chunk(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk)
{
    (void)pmm;
    return chunk->root;
}

static void root_chunk_lock(uvm_pmm_gpu_t *pmm, uvm_gpu_root_chunk_t *root)
{
    (void)pmm;
    assert(pthread_mutex_lock(&root->bitlock) == 0);
    ++root_bitlock_depth;
}

static void root_chunk_unlock(uvm_pmm_gpu_t *pmm, uvm_gpu_root_chunk_t *root)
{
    (void)pmm;
    assert(root_bitlock_depth == 1);
    --root_bitlock_depth;
    assert(pthread_mutex_unlock(&root->bitlock) == 0);
}

static NV_STATUS uvm_global_get_status(void)
{
    return NV_OK;
}

static void free_chunk(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk)
{
    (void)pmm;
    atomic_store_explicit(&chunk->state, UVM_PMM_GPU_CHUNK_STATE_FREE, memory_order_release);
    atomic_fetch_add_explicit(&free_calls, 1, memory_order_relaxed);
}

'''
    actual_tracker = (
        "static bool tracker_is_using_static_entries(uvm_tracker_t *tracker)\n"
        "{\n" + tracker_static_body + "\n}\n\n"
        "uvm_tracker_entry_t *uvm_tracker_get_entries(uvm_tracker_t *tracker)\n"
        "{\n" + tracker_entries_body + "\n}\n\n"
        "NV_STATUS uvm_tracker_reserve(uvm_tracker_t *tracker, NvU32 min_free_entries)\n"
        "{\n" + tracker_reserve_body + "\n}\n\n"
        "static NV_STATUS reserve_for_entries_from_tracker(uvm_tracker_t *dst, uvm_tracker_t *src)\n"
        "{\n" + merge_reserve_body + "\n}\n\n"
        "NV_STATUS uvm_tracker_add_tracker(uvm_tracker_t *dst, uvm_tracker_t *src)\n"
        "{\n" + tracker_add_body + "\n}\n\n"
    )
    actual_pmm = (
        "void uvm_pmm_gpu_free(uvm_pmm_gpu_t *pmm, uvm_gpu_chunk_t *chunk, uvm_tracker_t *tracker)\n"
        "{\n" + pmm_free_body + "\n}\n\n"
    )
    suffix = r'''
typedef struct {
    uvm_pmm_gpu_t *pmm;
    uvm_gpu_chunk_t *chunk;
    uvm_tracker_t *tracker;
} free_thread_args_t;

static void *free_thread(void *arg)
{
    free_thread_args_t *args = arg;
    uvm_pmm_gpu_free(args->pmm, args->chunk, args->tracker);
    return NULL;
}

static void *competitor_thread(void *arg)
{
    struct { uvm_pmm_gpu_t *pmm; uvm_gpu_root_chunk_t *root; } *args = arg;
    root_chunk_lock(args->pmm, args->root);
    atomic_store_explicit(&competitor_acquired, true, memory_order_release);
    root_chunk_unlock(args->pmm, args->root);
    pthread_mutex_lock(&gate_mutex);
    pthread_cond_broadcast(&gate_cond);
    pthread_mutex_unlock(&gate_mutex);
    return NULL;
}

static bool wait_for_flag(bool *flag)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    pthread_mutex_lock(&gate_mutex);
    while (!*flag) {
        int status = pthread_cond_timedwait(&gate_cond, &gate_mutex, &deadline);
        if (status != 0) {
            pthread_mutex_unlock(&gate_mutex);
            return false;
        }
    }
    pthread_mutex_unlock(&gate_mutex);
    return true;
}

static bool wait_for_competitor(void)
{
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        if (atomic_load_explicit(&competitor_acquired, memory_order_acquire))
            return true;
        nanosleep(&pause, NULL);
    }
    return atomic_load_explicit(&competitor_acquired, memory_order_acquire);
}

static bool tracker_matches_siblings(uvm_tracker_t *tracker)
{
    return tracker->size == 2 &&
           uvm_tracker_get_entries(tracker)[0].channel == &sibling_channel_a &&
           uvm_tracker_get_entries(tracker)[0].value == 101 &&
           uvm_tracker_get_entries(tracker)[1].channel == &sibling_channel_b &&
           uvm_tracker_get_entries(tracker)[1].value == 202;
}

int main(void)
{
    uvm_pmm_gpu_t pmm = {0};
    uvm_gpu_root_chunk_t root = {0};
    uvm_gpu_chunk_t chunk = {.state = ATOMIC_VAR_INIT(UVM_PMM_GPU_CHUNK_STATE_ALLOCATED),
                             .is_referenced = false, .root = &root};
    uvm_tracker_t incoming = {.size = 2, .max_size = 2,
                              .static_entries = {{&sibling_channel_b, 203}, {&incoming_channel_c, 303}}};
    free_thread_args_t free_args = {.pmm = &pmm, .chunk = &chunk, .tracker = &incoming};
    struct { uvm_pmm_gpu_t *pmm; uvm_gpu_root_chunk_t *root; } competitor_args = {.pmm = &pmm, .root = &root};
    pthread_t free_tid, competitor_tid;
    bool wait_seen, chunk_allocated_during_wait, no_free_during_wait;
    bool competitor_during_wait, sibling_preserved_during_wait, freed_after_wait;
    bool sibling_preserved_after_wait, incoming_unchanged_after_oom;
    int wait_depth;

    assert(pthread_mutex_init(&root.bitlock, NULL) == 0);
    root.tracker.size = 2;
    root.tracker.max_size = 2;
    root.tracker.static_entries[0] = (uvm_tracker_entry_t){&sibling_channel_a, 101};
    root.tracker.static_entries[1] = (uvm_tracker_entry_t){&sibling_channel_b, 202};

    assert(pthread_create(&free_tid, NULL, free_thread, &free_args) == 0);
    wait_seen = wait_for_flag(&tracker_wait_entered);
    pthread_mutex_lock(&gate_mutex);
    wait_depth = (int)wait_root_bitlock_depth;
    pthread_mutex_unlock(&gate_mutex);

    chunk_allocated_during_wait = atomic_load_explicit(&chunk.state, memory_order_acquire) ==
                                  UVM_PMM_GPU_CHUNK_STATE_ALLOCATED;
    no_free_during_wait = atomic_load_explicit(&free_calls, memory_order_relaxed) == 0;
    sibling_preserved_during_wait = tracker_matches_siblings(&root.tracker);

    assert(pthread_create(&competitor_tid, NULL, competitor_thread, &competitor_args) == 0);
    competitor_during_wait = wait_for_competitor();

    pthread_mutex_lock(&gate_mutex);
    release_tracker_wait = true;
    pthread_cond_broadcast(&gate_cond);
    pthread_mutex_unlock(&gate_mutex);
    assert(pthread_join(free_tid, NULL) == 0);
    assert(pthread_join(competitor_tid, NULL) == 0);

    freed_after_wait = atomic_load_explicit(&chunk.state, memory_order_acquire) ==
                       UVM_PMM_GPU_CHUNK_STATE_FREE &&
                       atomic_load_explicit(&free_calls, memory_order_relaxed) == 1;
    sibling_preserved_after_wait = tracker_matches_siblings(&root.tracker);
    incoming_unchanged_after_oom = incoming.size == 2 &&
                                   uvm_tracker_get_entries(&incoming)[0].channel == &sibling_channel_b &&
                                   uvm_tracker_get_entries(&incoming)[0].value == 203 &&
                                   uvm_tracker_get_entries(&incoming)[1].channel == &incoming_channel_c &&
                                   uvm_tracker_get_entries(&incoming)[1].value == 303;

    printf("{\"wait_calls\":%u,\"wait_root_bitlock_depth\":%d,"
           "\"competitor_acquired_root_bitlock_during_wait\":%s,"
           "\"chunk_unavailable_during_wait\":%s,\"free_delayed_until_wait_completion\":%s,"
           "\"reserve_allocator_attempts\":%u,\"root_tracker_sibling_entries_preserved\":%s,"
           "\"oom_merge_did_not_partially_copy_entries\":%s}\n",
           tracker_wait_calls, wait_depth,
           competitor_during_wait ? "true" : "false",
           (wait_seen && chunk_allocated_during_wait && no_free_during_wait) ? "true" : "false",
           freed_after_wait ? "true" : "false",
           reserve_allocator_attempts,
           (sibling_preserved_during_wait && sibling_preserved_after_wait) ? "true" : "false",
           (sibling_preserved_after_wait && incoming_unchanged_after_oom) ? "true" : "false");

    pthread_mutex_destroy(&root.bitlock);
    return wait_seen && tracker_wait_calls == 1 && wait_depth == 0 && competitor_during_wait &&
           chunk_allocated_during_wait && no_free_during_wait && freed_after_wait &&
           sibling_preserved_during_wait && sibling_preserved_after_wait && incoming_unchanged_after_oom &&
           reserve_allocator_attempts == 2 && allocator_failures_remaining == 0 ? 0 : 3;
}
'''
    return prefix + actual_tracker + actual_pmm + suffix


def run_harness(*, mutate_wait_under_root_bitlock: bool = False) -> dict[str, Any]:
    sources, hashes = _load_sources()
    pmm_source = sources["uvm_pmm_gpu.c"]
    if mutate_wait_under_root_bitlock:
        pmm_source = _mutate_wait_under_lock(pmm_source)

    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        raise RuntimeError("a C compiler is required for the isolated host harness")

    with tempfile.TemporaryDirectory(prefix="r595-pmm-tracker-wait-") as temp_name:
        temp = Path(temp_name)
        source_path = temp / "harness.c"
        executable = temp / "harness"
        source_path.write_text(_translation_unit(pmm_source, sources["uvm_tracker.c"]), encoding="utf-8")
        command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-pthread", str(source_path), "-o", str(executable)]
        compile_result = subprocess.run(command, capture_output=True, text=True, check=False)
        if compile_result.returncode != 0:
            execution = {"exit_code": None, "stdout": "", "stderr": "", "checks": None}
        else:
            execution_result = subprocess.run([str(executable)], capture_output=True, text=True,
                                              check=False, timeout=10)
            try:
                checks = json.loads(execution_result.stdout.strip().splitlines()[-1])
            except (IndexError, json.JSONDecodeError):
                checks = None
            execution = {"exit_code": execution_result.returncode,
                         "stdout": execution_result.stdout, "stderr": execution_result.stderr,
                         "checks": checks}

    return {
        "schema": "r595-pmm-tracker-wait-host-harness-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": {
            "level": "tested-isolated",
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
            "mutation_negative_control": mutate_wait_under_root_bitlock,
        },
        "scope": (
            "Exact hash-pinned R595 uvm_pmm_gpu_free, uvm_tracker_reserve, "
            "reserve_for_entries_from_tracker and uvm_tracker_add_tracker function bodies compiled "
            "on the host. Two allocation failures are injected at a stubbed uvm_kvmalloc boundary; "
            "pthread mutexes, tracker completion and chunk free-list publication remain stubs. "
            "This does not execute UVM kernel code, lockdep, a GPU, or hardware semaphores."
        ),
        "sources": {name: {"path": str((SOURCE_ROOT / name).resolve()), "sha256": digest}
                    for name, digest in hashes.items()},
        "implementation_sha256": {
            "tools/run_r595_pmm_tracker_wait_host_harness.py": _sha256(Path(__file__).read_bytes()),
            "tools/run_volta_fault_decode_host_harness.py": _sha256(
                (ROOT / "tools/run_volta_fault_decode_host_harness.py").read_bytes()
            ),
        },
        "compiler": compiler,
        "compile": {"command": command, "exit_code": compile_result.returncode,
                    "stdout": compile_result.stdout, "stderr": compile_result.stderr},
        "execution": execution,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutate-wait-under-root-bitlock", action="store_true",
                        help="run the negative-control mutation; expected to fail the harness")
    args = parser.parse_args()
    report = run_harness(mutate_wait_under_root_bitlock=args.mutate_wait_under_root_bitlock)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["compile"]["exit_code"] == 0 and (
        report["execution"]["exit_code"] == (3 if args.mutate_wait_under_root_bitlock else 0)
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
