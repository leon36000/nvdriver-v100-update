#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute pinned R580/R595 deferred-free list functions on the host."""
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

R580_SOURCE = ROOT / (
    "build/experiments/r580-nonreplayable-fault-drains-v3-20261028T0634Z/"
    "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/uvm_va_space.c"
)
R595_SOURCE = ROOT / (
    "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v15-20261028T004147Z/"
    "nvidia-uvm/uvm_va_space.c"
)
PINNED_SOURCE_SHA256 = {
    "r580_candidate": "2309eb47fad1d4ec4f932f8eae58fc4802b2380a0a95be2e964a9897117b0418",
    "r595": "f332076b5d141b23cbe7acaccb48b2b07a0f8fe2e44832fd93551a4a8c345468",
}
EXPECTED_LIST_FUNCTION_SHA256 = "fe8bdb2d7e37de6133eed2013e9f0c2298ccbfb1c23d8c4050d32c1aad824fe0"
EXPECTED_CHANNEL_SEMANTIC_SHA256 = "25be510456dc61bd7c81d926e6ee92edf3c3987a0148c53ac669c6e8e4ac1e54"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_functions(path: Path, expected: str, label: str) -> tuple[str, str, dict[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular, non-symlink source file")
    source = path.read_text(encoding="utf-8")
    file_hash = _sha256(path)
    if file_hash != expected:
        raise ValueError(f"{label} source SHA-256 mismatch: {file_hash}")
    list_body = source_tools._extract_function(source, "uvm_deferred_free_object_list")
    channel_body = source_tools._extract_function(source, "uvm_deferred_free_object_channel")
    list_hash = source_tools._normalized_function_hash(source, "uvm_deferred_free_object_list")
    channel_hash = source_tools._normalized_function_hash(source, "uvm_deferred_free_object_channel")
    semantic_channel_hash = hashlib.sha256(
        "".join(
            source_tools._mask_comments(
                channel_body.replace("uvm_gpu_fault_buffer_flush", "uvm_gpu_replayable_buffer_flush")
            ).split()
        ).encode("utf-8")
    ).hexdigest()
    if list_hash != EXPECTED_LIST_FUNCTION_SHA256:
        raise ValueError(f"{label} deferred-free list body changed: {list_hash}")
    if semantic_channel_hash != EXPECTED_CHANNEL_SEMANTIC_SHA256:
        raise ValueError(f"{label} deferred-free channel body changed: {semantic_channel_hash}")
    return list_body, channel_body, {
        "path": str(path.resolve()),
        "file_sha256": file_hash,
        "list_function_sha256": list_hash,
        "channel_function_sha256": channel_hash,
        "channel_semantic_function_sha256": semantic_channel_hash,
    }


def _translation_unit(r580_list: str, r580_channel: str, r595_list: str, r595_channel: str) -> str:
    prefix = r'''#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct list_head { struct list_head *next; struct list_head *prev; };

typedef enum {
    UVM_DEFERRED_FREE_OBJECT_TYPE_CHANNEL = 0,
    UVM_DEFERRED_FREE_OBJECT_GPU_VA_SPACE = 1,
    UVM_DEFERRED_FREE_OBJECT_TYPE_EXTERNAL_ALLOCATION = 2,
    UVM_DEFERRED_FREE_OBJECT_TYPE_DEVICE_P2P_MEM = 3,
    UVM_DEFERRED_FREE_OBJECT_TYPE_COUNT = 4
} uvm_deferred_free_object_type_t;

typedef struct {
    uvm_deferred_free_object_type_t type;
    struct list_head list_node;
} uvm_deferred_free_object_t;

typedef struct { uint64_t words[4]; } uvm_parent_processor_mask_t;
typedef struct {
    uvm_parent_processor_mask_t replayable;
    uvm_parent_processor_mask_t non_replayable;
    uvm_parent_processor_mask_t access_counters;
} flushed_gpus_t;
typedef struct { unsigned id; bool access_counters_supported; } uvm_parent_gpu_t;
typedef struct { uvm_parent_gpu_t *parent; } uvm_gpu_t;
typedef struct {
    uvm_deferred_free_object_t deferred_free;
    unsigned id;
} uvm_gpu_va_space_t;
typedef struct {
    uvm_deferred_free_object_t deferred_free;
    unsigned id;
} uvm_ext_gpu_map_t;
typedef struct {
    uvm_deferred_free_object_t deferred_free;
    unsigned id;
} uvm_device_p2p_mem_t;
typedef struct {
    unsigned guard;
    uvm_deferred_free_object_t deferred_free;
    uvm_gpu_t *gpu;
    unsigned engine_type;
} uvm_user_channel_t;

#define UVM_GPU_CHANNEL_ENGINE_TYPE_GR 1u
#define UVM_GPU_CHANNEL_ENGINE_TYPE_COPY 2u
#define container_of(pointer, type, member) \
    ((type *)((char *)(pointer) - offsetof(type, member)))
#define list_first_entry(head, type, member) \
    container_of((head)->next, type, member)
#define list_next_entry(pos, member) \
    container_of((pos)->member.next, __typeof__(*(pos)), member)
#define list_for_each_entry_safe(pos, next_pos, head, member) \
    for ((pos) = list_first_entry((head), __typeof__(*(pos)), member), \
         (next_pos) = list_next_entry((pos), member); \
         &((pos)->member) != (head); \
         (pos) = (next_pos), (next_pos) = list_next_entry((next_pos), member))
#define UVM_ASSERT_MSG(condition, ...) assert(condition)

static char events[256];
static unsigned event_count;
static unsigned mask_zero_calls, non_replayable_calls, replayable_calls;
static unsigned access_counter_calls, channel_destroy_calls;
static unsigned gpu_va_space_destroy_calls, external_free_calls, p2p_free_calls;
static flushed_gpus_t *active_masks;

static void event(char value)
{
    assert(event_count + 1 < sizeof(events));
    events[event_count++] = value;
    events[event_count] = '\0';
}

static void list_head_init(struct list_head *head)
{
    head->next = head;
    head->prev = head;
}

static void list_add_tail(struct list_head *node, struct list_head *head)
{
    node->prev = head->prev;
    node->next = head;
    head->prev->next = node;
    head->prev = node;
}

static void list_del(struct list_head *node)
{
    assert(node->prev->next == node && node->next->prev == node);
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node;
    node->prev = node;
    event('l');
}

static bool list_empty(const struct list_head *head)
{
    return head->next == head;
}

static bool is_unlinked(const struct list_head *node)
{
    return node->next == node && node->prev == node;
}

static void reset_observation(void)
{
    memset(events, 0, sizeof(events));
    event_count = 0;
    mask_zero_calls = 0;
    non_replayable_calls = 0;
    replayable_calls = 0;
    access_counter_calls = 0;
    channel_destroy_calls = 0;
    gpu_va_space_destroy_calls = 0;
    external_free_calls = 0;
    p2p_free_calls = 0;
    active_masks = NULL;
}

static void uvm_parent_processor_mask_zero(uvm_parent_processor_mask_t *mask)
{
    if (mask_zero_calls == 0)
        active_masks = container_of(mask, flushed_gpus_t, replayable);
    assert(active_masks != NULL);
    assert(mask == &active_masks->replayable || mask == &active_masks->non_replayable ||
           mask == &active_masks->access_counters);
    memset(mask, 0, sizeof(*mask));
    ++mask_zero_calls;
    event('0');
}

static bool uvm_parent_processor_mask_test_and_set(uvm_parent_processor_mask_t *mask, unsigned id)
{
    unsigned word = id / 64u;
    uint64_t bit = UINT64_C(1) << (id % 64u);
    bool was_set;
    assert(word < 4u);
    was_set = (mask->words[word] & bit) != 0;
    mask->words[word] |= bit;
    return was_set;
}

static bool mask_has(const uvm_parent_processor_mask_t *mask, unsigned id)
{
    return (mask->words[id / 64u] & (UINT64_C(1) << (id % 64u))) != 0;
}

static void uvm_parent_gpu_non_replayable_buffer_flush(uvm_parent_gpu_t *parent)
{
    assert(active_masks != NULL && mask_has(&active_masks->non_replayable, parent->id));
    ++non_replayable_calls;
    event('N');
}

static void uvm_gpu_fault_buffer_flush(uvm_gpu_t *gpu)
{
    assert(active_masks != NULL && mask_has(&active_masks->replayable, gpu->parent->id));
    ++replayable_calls;
    event('R');
}

static void uvm_gpu_replayable_buffer_flush(uvm_gpu_t *gpu)
{
    assert(active_masks != NULL && mask_has(&active_masks->replayable, gpu->parent->id));
    ++replayable_calls;
    event('R');
}

static void uvm_parent_gpu_access_counter_buffer_flush(uvm_parent_gpu_t *parent)
{
    assert(active_masks != NULL && mask_has(&active_masks->access_counters, parent->id));
    ++access_counter_calls;
    event('A');
}

static void uvm_user_channel_destroy_detached(uvm_user_channel_t *channel)
{
    unsigned id = channel->gpu->parent->id;
    assert(is_unlinked(&channel->deferred_free.list_node));
    assert(active_masks != NULL && mask_has(&active_masks->non_replayable, id));
    if (channel->engine_type == UVM_GPU_CHANNEL_ENGINE_TYPE_GR) {
        assert(mask_has(&active_masks->replayable, id));
        if (channel->gpu->parent->access_counters_supported)
            assert(mask_has(&active_masks->access_counters, id));
    }
    ++channel_destroy_calls;
    event('D');
}

static void destroy_gpu_va_space(uvm_gpu_va_space_t *object)
{
    assert(is_unlinked(&object->deferred_free.list_node));
    assert(object->id == 20u);
    ++gpu_va_space_destroy_calls;
    event('V');
}

static void uvm_ext_gpu_map_free(uvm_ext_gpu_map_t *object)
{
    assert(is_unlinked(&object->deferred_free.list_node));
    assert(object->id == 30u);
    ++external_free_calls;
    event('E');
}

static void uvm_va_range_free_device_p2p_mem(uvm_device_p2p_mem_t *object)
{
    assert(is_unlinked(&object->deferred_free.list_node));
    assert(object->id == 40u);
    ++p2p_free_calls;
    event('P');
}

static void init_object(uvm_deferred_free_object_t *object,
                        uvm_deferred_free_object_type_t type,
                        struct list_head *head)
{
    object->type = type;
    list_head_init(&object->list_node);
    list_add_tail(&object->list_node, head);
}

static void init_channel(uvm_user_channel_t *channel, uvm_gpu_t *gpu, unsigned engine_type,
                         struct list_head *head)
{
    memset(channel, 0, sizeof(*channel));
    channel->gpu = gpu;
    channel->engine_type = engine_type;
    init_object(&channel->deferred_free, UVM_DEFERRED_FREE_OBJECT_TYPE_CHANNEL, head);
}

'''
    suffix = r'''
typedef void (*list_function_t)(struct list_head *);

static void print_case(const char *source, const char *scenario, bool list_ok)
{
    printf("CASE|%s|%s|%s|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
           source, scenario, events, mask_zero_calls, non_replayable_calls,
           replayable_calls, access_counter_calls, channel_destroy_calls,
           gpu_va_space_destroy_calls, external_free_calls, p2p_free_calls,
           list_ok ? 1u : 0u, list_ok ? 1u : 0u);
}

static void run_empty(const char *source, list_function_t free_list)
{
    struct list_head list;
    reset_observation();
    list_head_init(&list);
    free_list(&list);
    print_case(source, "empty_list", list_empty(&list));
}

static void run_mixed(const char *source, list_function_t free_list)
{
    struct list_head list;
    uvm_parent_gpu_t parent1 = { 1u, true };
    uvm_parent_gpu_t parent2 = { 2u, true };
    uvm_gpu_t gpu1 = { &parent1 };
    uvm_gpu_t gpu2 = { &parent2 };
    uvm_user_channel_t copy1, gr1, gr2;
    uvm_gpu_va_space_t va_space;
    uvm_ext_gpu_map_t external;
    uvm_device_p2p_mem_t p2p;
    reset_observation();
    list_head_init(&list);
    init_channel(&copy1, &gpu1, UVM_GPU_CHANNEL_ENGINE_TYPE_COPY, &list);
    memset(&va_space, 0, sizeof(va_space));
    va_space.id = 20u;
    init_object(&va_space.deferred_free, UVM_DEFERRED_FREE_OBJECT_GPU_VA_SPACE, &list);
    init_channel(&gr1, &gpu1, UVM_GPU_CHANNEL_ENGINE_TYPE_GR, &list);
    memset(&external, 0, sizeof(external));
    external.id = 30u;
    init_object(&external.deferred_free, UVM_DEFERRED_FREE_OBJECT_TYPE_EXTERNAL_ALLOCATION, &list);
    memset(&p2p, 0, sizeof(p2p));
    p2p.id = 40u;
    init_object(&p2p.deferred_free, UVM_DEFERRED_FREE_OBJECT_TYPE_DEVICE_P2P_MEM, &list);
    init_channel(&gr2, &gpu2, UVM_GPU_CHANNEL_ENGINE_TYPE_GR, &list);
    free_list(&list);
    print_case(source, "mixed_all_types", list_empty(&list));
}

static void run_two_lists(const char *source, list_function_t free_list)
{
    struct list_head first, second;
    uvm_parent_gpu_t parent = { 1u, true };
    uvm_gpu_t gpu = { &parent };
    uvm_user_channel_t channel1, channel2;
    reset_observation();
    list_head_init(&first);
    list_head_init(&second);
    init_channel(&channel1, &gpu, UVM_GPU_CHANNEL_ENGINE_TYPE_COPY, &first);
    init_channel(&channel2, &gpu, UVM_GPU_CHANNEL_ENGINE_TYPE_COPY, &second);
    free_list(&first);
    free_list(&second);
    print_case(source, "two_lists_reset_masks", list_empty(&first) && list_empty(&second));
}

int main(void)
{
    run_empty("r580_candidate", r580_list);
    run_mixed("r580_candidate", r580_list);
    run_two_lists("r580_candidate", r580_list);
    run_empty("r595", r595_list);
    run_mixed("r595", r595_list);
    run_two_lists("r595", r595_list);
    return 0;
}
'''
    r580_channel_fn = (
        "static void r580_channel(uvm_deferred_free_object_t *object, flushed_gpus_t *flushed_gpus)\n{\n"
        + r580_channel + "\n}\n"
    )
    r595_channel_fn = (
        "static void r595_channel(uvm_deferred_free_object_t *object, flushed_gpus_t *flushed_gpus)\n{\n"
        + r595_channel + "\n}\n"
    )
    r580_list_fn = (
        "void r580_list(struct list_head *deferred_free_list)\n{\n"
        + r580_list.replace("uvm_deferred_free_object_channel", "r580_channel") + "\n}\n"
    )
    r595_list_fn = (
        "void r595_list(struct list_head *deferred_free_list)\n{\n"
        + r595_list.replace("uvm_deferred_free_object_channel", "r595_channel") + "\n}\n"
    )
    return prefix + r580_channel_fn + r580_list_fn + r595_channel_fn + r595_list_fn + suffix


def _parse_cases(stdout: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.startswith("CASE|"):
            continue
        fields = line.split("|")
        if len(fields) != 14:
            raise ValueError(f"unexpected deferred-free list output: {line!r}")
        cases.append({
            "source": fields[1],
            "scenario": fields[2],
            "event_order": fields[3],
            "mask_zero_calls": int(fields[4]),
            "non_replayable_flush_calls": int(fields[5]),
            "replayable_flush_calls": int(fields[6]),
            "access_counter_flush_calls": int(fields[7]),
            "channel_destroy_calls": int(fields[8]),
            "gpu_va_space_destroy_calls": int(fields[9]),
            "external_allocation_free_calls": int(fields[10]),
            "device_p2p_free_calls": int(fields[11]),
            "list_empty_after_walk": fields[12] == "1",
            "both_lists_empty_after_walk": fields[13] == "1",
        })
    if len(cases) != 6:
        raise ValueError(f"expected six executed list cases, observed {len(cases)}")
    return cases


def run_harness() -> dict[str, Any]:
    r580_list, r580_channel, r580_info = _load_functions(
        R580_SOURCE, PINNED_SOURCE_SHA256["r580_candidate"], "R580 candidate"
    )
    r595_list, r595_channel, r595_info = _load_functions(
        R595_SOURCE, PINNED_SOURCE_SHA256["r595"], "R595"
    )
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C compiler is required for exact-source host execution")
    with tempfile.TemporaryDirectory(prefix="deferred-free-list-host-") as directory:
        temporary = Path(directory)
        source_path = temporary / "deferred_free_list_harness.c"
        binary_path = temporary / "deferred_free_list_harness"
        source_path.write_text(
            _translation_unit(r580_list, r580_channel, r595_list, r595_channel), encoding="utf-8"
        )
        compile_command = [compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                           str(source_path), "-o", str(binary_path)]
        compiled = subprocess.run(compile_command, capture_output=True, text=True, timeout=30, check=False)
        if compiled.returncode != 0:
            raise RuntimeError(f"host harness compilation failed:\n{compiled.stdout}{compiled.stderr}")
        execute_command = [str(binary_path)]
        executed = subprocess.run(execute_command, capture_output=True, text=True, timeout=10, check=False)
        if executed.returncode != 0:
            raise RuntimeError(f"host harness execution failed:\n{executed.stdout}{executed.stderr}")
        cases = _parse_cases(executed.stdout)
    return {
        "schema": "r580-r595-deferred-free-object-list-host-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": {
            "level": "tested-isolated",
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
        },
        "source_functions": {"r580_candidate": r580_info, "r595": r595_info},
        "compile": {
            "command": compile_command,
            "exit_code": compiled.returncode,
            "stdout": compiled.stdout,
            "stderr": compiled.stderr,
        },
        "execution": {
            "command": execute_command,
            "exit_code": executed.returncode,
            "stdout": executed.stdout,
            "stderr": executed.stderr,
        },
        "cases": cases,
        "scope": (
            "Exact pinned list-walker and channel-helper bodies execute with synthetic Linux-style list links, "
            "masks, object containers, and RM/UVM callbacks. The tests cover list order, dispatch, per-call mask "
            "initialization, and unlink-before-free. This does not validate Linux list internals, kernel locks, "
            "RM, workqueues, GPU faults, module loading, CUDA, or hardware."
        ),
    }


def _write_new_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args(argv)
    report_path = args.report if args.report.is_absolute() else ROOT / args.report
    log_path = args.log if args.log.is_absolute() else ROOT / args.log
    report = run_harness()
    log = (
        "$ " + " ".join(report["compile"]["command"]) + "\n" +
        report["compile"]["stdout"] + report["compile"]["stderr"] +
        "$ " + " ".join(report["execution"]["command"]) + "\n" +
        report["execution"]["stdout"] + report["execution"]["stderr"]
    ).encode("utf-8")
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_new_private(report_path, encoded)
    _write_new_private(log_path, log)
    print(json.dumps({"report": str(report_path), "report_sha256": hashlib.sha256(encoded).hexdigest(),
                      "log": str(log_path), "log_sha256": hashlib.sha256(log).hexdigest(),
                      "cases": len(report["cases"]), "status": "pass"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
