#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute pinned R580/R595 deferred channel-free helper bodies."""
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
EXPECTED_SEMANTIC_FUNCTION_SHA256 = "25be510456dc61bd7c81d926e6ee92edf3c3987a0148c53ac669c6e8e4ac1e54"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_source(path: Path, expected: str, label: str) -> tuple[str, dict[str, str]]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular, non-symlink source file")
    source = path.read_text(encoding="utf-8")
    file_hash = sha256_file(path)
    if file_hash != expected:
        raise ValueError(f"{label} source SHA-256 mismatch: {file_hash}")
    body = source_tools._extract_function(source, "uvm_deferred_free_object_channel")
    function_hash = source_tools._normalized_function_hash(source, "uvm_deferred_free_object_channel")
    semantic_body = body.replace("uvm_gpu_fault_buffer_flush", "uvm_gpu_replayable_buffer_flush")
    semantic_hash = hashlib.sha256(
        "".join(source_tools._mask_comments(semantic_body).split()).encode("utf-8")
    ).hexdigest()
    if semantic_hash != EXPECTED_SEMANTIC_FUNCTION_SHA256:
        raise ValueError(f"{label} deferred-free semantic body changed: {semantic_hash}")
    return body, {
        "path": str(path.resolve()),
        "file_sha256": file_hash,
        "function_sha256": function_hash,
        "semantic_function_sha256": semantic_hash,
    }


def _translation_unit(r580_body: str, r595_body: str) -> str:
    prefix = r'''#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define UVM_GPU_CHANNEL_ENGINE_TYPE_GR 1u
#define UVM_GPU_CHANNEL_ENGINE_TYPE_COPY 2u
#define container_of(pointer, type, member) \
    ((type *)((char *)(pointer) - offsetof(type, member)))

typedef struct { uint64_t words[4]; } uvm_parent_processor_mask_t;
typedef struct {
    uvm_parent_processor_mask_t replayable;
    uvm_parent_processor_mask_t non_replayable;
    uvm_parent_processor_mask_t access_counters;
} flushed_gpus_t;
typedef struct { unsigned marker; } uvm_deferred_free_object_t;
typedef struct { unsigned id; bool access_counters_supported; } uvm_parent_gpu_t;
typedef struct { uvm_parent_gpu_t *parent; } uvm_gpu_t;
typedef struct {
    unsigned guard;
    uvm_deferred_free_object_t deferred_free;
    uvm_gpu_t *gpu;
    unsigned engine_type;
} uvm_user_channel_t;

static char events[64];
static unsigned event_count;
static unsigned non_replayable_calls;
static unsigned replayable_calls;
static unsigned access_counter_calls;
static unsigned destroy_calls;
static flushed_gpus_t *active_masks;

static void record_event(char event)
{
    assert(event_count + 1 < sizeof(events));
    events[event_count++] = event;
    events[event_count] = '\0';
}

static bool mask_test(const uvm_parent_processor_mask_t *mask, unsigned id)
{
    unsigned word = id / 64u;
    unsigned bit = id % 64u;
    assert(word < 4u);
    return (mask->words[word] & (UINT64_C(1) << bit)) != 0;
}

static bool uvm_parent_processor_mask_test_and_set(uvm_parent_processor_mask_t *mask,
                                                   unsigned id)
{
    bool was_set = mask_test(mask, id);
    unsigned word = id / 64u;
    unsigned bit = id % 64u;
    mask->words[word] |= UINT64_C(1) << bit;
    return was_set;
}

static void uvm_parent_gpu_non_replayable_buffer_flush(uvm_parent_gpu_t *parent)
{
    assert(mask_test(&active_masks->non_replayable, parent->id));
    ++non_replayable_calls;
    record_event('N');
}

static void uvm_gpu_fault_buffer_flush(uvm_gpu_t *gpu)
{
    assert(mask_test(&active_masks->replayable, gpu->parent->id));
    ++replayable_calls;
    record_event('R');
}

static void uvm_gpu_replayable_buffer_flush(uvm_gpu_t *gpu)
{
    assert(mask_test(&active_masks->replayable, gpu->parent->id));
    ++replayable_calls;
    record_event('R');
}

static void uvm_parent_gpu_access_counter_buffer_flush(uvm_parent_gpu_t *parent)
{
    assert(mask_test(&active_masks->access_counters, parent->id));
    ++access_counter_calls;
    record_event('A');
}

static void uvm_user_channel_destroy_detached(uvm_user_channel_t *channel)
{
    unsigned id = channel->gpu->parent->id;
    assert(mask_test(&active_masks->non_replayable, id));
    if (channel->engine_type == UVM_GPU_CHANNEL_ENGINE_TYPE_GR) {
        assert(mask_test(&active_masks->replayable, id));
        if (channel->gpu->parent->access_counters_supported)
            assert(mask_test(&active_masks->access_counters, id));
    }
    ++destroy_calls;
    record_event('D');
}

typedef void (*deferred_free_function_t)(uvm_deferred_free_object_t *, flushed_gpus_t *);

static void r580_candidate_free(uvm_deferred_free_object_t *object, flushed_gpus_t *flushed_gpus)
{
'''
    middle = r'''
}

static void r595_free(uvm_deferred_free_object_t *object, flushed_gpus_t *flushed_gpus)
{
'''
    suffix = r'''
}

static void init_channel(uvm_user_channel_t *channel, uvm_gpu_t *gpu, unsigned engine)
{
    memset(channel, 0, sizeof(*channel));
    channel->guard = 0x1234u;
    channel->gpu = gpu;
    channel->engine_type = engine;
}

static void reset_case(flushed_gpus_t *masks)
{
    memset(masks, 0, sizeof(*masks));
    active_masks = masks;
    memset(events, 0, sizeof(events));
    event_count = 0;
    non_replayable_calls = 0;
    replayable_calls = 0;
    access_counter_calls = 0;
    destroy_calls = 0;
}

static void run_case(const char *source, const char *scenario,
                     deferred_free_function_t free_channel)
{
    flushed_gpus_t masks;
    uvm_parent_gpu_t parents[3] = {
        { .id = 0u, .access_counters_supported = true },
        { .id = 1u, .access_counters_supported = true },
        { .id = 2u, .access_counters_supported = false },
    };
    uvm_gpu_t gpus[3] = { { &parents[0] }, { &parents[1] }, { &parents[2] } };
    uvm_user_channel_t channels[3];
    unsigned index;
    reset_case(&masks);

    if (strcmp(scenario, "multi_channels_same_parent") == 0) {
        init_channel(&channels[0], &gpus[0], UVM_GPU_CHANNEL_ENGINE_TYPE_COPY);
        init_channel(&channels[1], &gpus[0], UVM_GPU_CHANNEL_ENGINE_TYPE_GR);
        init_channel(&channels[2], &gpus[0], UVM_GPU_CHANNEL_ENGINE_TYPE_GR);
        for (index = 0; index < 3; ++index)
            free_channel(&channels[index].deferred_free, &masks);
    }
    else if (strcmp(scenario, "separate_parents_and_access_gate") == 0) {
        init_channel(&channels[0], &gpus[1], UVM_GPU_CHANNEL_ENGINE_TYPE_GR);
        init_channel(&channels[1], &gpus[2], UVM_GPU_CHANNEL_ENGINE_TYPE_GR);
        for (index = 0; index < 2; ++index)
            free_channel(&channels[index].deferred_free, &masks);
    }
    else if (strcmp(scenario, "gr_then_non_gr_same_parent") == 0) {
        init_channel(&channels[0], &gpus[0], UVM_GPU_CHANNEL_ENGINE_TYPE_GR);
        init_channel(&channels[1], &gpus[0], UVM_GPU_CHANNEL_ENGINE_TYPE_COPY);
        for (index = 0; index < 2; ++index)
            free_channel(&channels[index].deferred_free, &masks);
    }
    else {
        assert(false);
    }

    printf("CASE|%s|%s|%s|%u|%u|%u|%u|1\n", source, scenario, events,
           non_replayable_calls, replayable_calls, access_counter_calls, destroy_calls);
}

int main(void)
{
    run_case("r580_candidate", "multi_channels_same_parent", r580_candidate_free);
    run_case("r580_candidate", "separate_parents_and_access_gate", r580_candidate_free);
    run_case("r580_candidate", "gr_then_non_gr_same_parent", r580_candidate_free);
    run_case("r595", "multi_channels_same_parent", r595_free);
    run_case("r595", "separate_parents_and_access_gate", r595_free);
    run_case("r595", "gr_then_non_gr_same_parent", r595_free);
    return 0;
}
'''
    return prefix + r580_body + middle + r595_body + suffix


def _parse_cases(stdout: str) -> list[dict[str, Any]]:
    cases = []
    for line in stdout.splitlines():
        if not line.startswith("CASE|"):
            continue
        fields = line.split("|")
        if len(fields) != 9:
            raise ValueError(f"unexpected deferred-free harness output: {line!r}")
        cases.append({
            "source": fields[1],
            "scenario": fields[2],
            "event_order": fields[3],
            "non_replayable_flush_calls": int(fields[4]),
            "replayable_flush_calls": int(fields[5]),
            "access_counter_flush_calls": int(fields[6]),
            "destroy_calls": int(fields[7]),
            "all_channels_destroyed_after_required_flushes": fields[8] == "1",
        })
    if len(cases) != 6:
        raise ValueError(f"expected six executed cases, observed {len(cases)}")
    return cases


def run_harness() -> dict[str, Any]:
    r580_body, r580_info = _load_source(
        R580_SOURCE, PINNED_SOURCE_SHA256["r580_candidate"], "R580 candidate"
    )
    r595_body, r595_info = _load_source(
        R595_SOURCE, PINNED_SOURCE_SHA256["r595"], "R595"
    )
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C compiler is required for exact-source host execution")
    with tempfile.TemporaryDirectory(prefix="deferred-free-channel-host-") as directory:
        temporary = Path(directory)
        source_path = temporary / "deferred_free_harness.c"
        binary_path = temporary / "deferred_free_harness"
        source_path.write_text(_translation_unit(r580_body, r595_body), encoding="utf-8")
        compile_command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
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
        "schema": "r580-r595-deferred-free-channel-host-v1",
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
            "Exact channel-helper bodies run with synthetic masks, channel/parent objects, and flush/destroy APIs. "
            "Assertions cover once-per-parent flushes and flush-before-destroy only; this does not validate Linux "
            "UVM locks, RM, queue scheduling, GPU faults, module loading, CUDA, or hardware."
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
    try:
        report = run_harness()
        log = (
            "$ " + " ".join(report["compile"]["command"]) + "\n" +
            report["compile"]["stdout"] + report["compile"]["stderr"] +
            "$ " + " ".join(report["execution"]["command"]) + "\n" +
            report["execution"]["stdout"] + report["execution"]["stderr"]
        ).encode("utf-8")
        report["log"] = str(log_path.resolve())
        report["log_sha256"] = hashlib.sha256(log).hexdigest()
        _write_new_private(log_path, log)
        _write_new_private(
            report_path,
            (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"deferred-free channel host harness failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
