#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and execute the exact R580/R595 non-replayable flush helper bodies."""
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

R580_CANDIDATE = ROOT / (
    "build/experiments/r580-nonreplayable-fault-drains-v3-20261028T0634Z/"
    "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/"
    "uvm_gpu_non_replayable_faults.c"
)
R595_SOURCE = ROOT / (
    "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v15-20261028T004147Z/"
    "nvidia-uvm/uvm_gpu_non_replayable_faults.c"
)
PINNED = {
    "r580_candidate": "60c838bdaacce22010cc1de059a83113875b845a953b95d286bbc1fcd50da958",
    "r595": "83fd573b3f5187ded355dec0a835f293716b0d271204d2c617864346fac01888",
}
EXPECTED_FUNCTION_SHA256 = "d7f5c4b2fe33745ec7a6ce8c95612921b6480a32f5733158c30a646b1581a778"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_snapshot(path: Path, expected_sha256: str, label: str) -> tuple[str, dict[str, str]]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular, non-symlink source file")
    source = path.read_text(encoding="utf-8")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ValueError(f"{label} source SHA-256 mismatch: {actual}")
    function_hash = source_tools._normalized_function_hash(
        source, "uvm_parent_gpu_non_replayable_buffer_flush"
    )
    if function_hash != EXPECTED_FUNCTION_SHA256:
        raise ValueError(f"{label} normalized flush body changed: {function_hash}")
    return source_tools._extract_function(source, "uvm_parent_gpu_non_replayable_buffer_flush"), {
        "path": str(path.resolve()),
        "file_sha256": actual,
        "normalized_function_sha256": function_hash,
    }


def _translation_unit(r580_body: str, r595_body: str) -> str:
    prefix = r'''#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    struct {
        int interrupts_lock;
        int bottom_half_q;
    } isr;
} uvm_parent_gpu_t;

static uvm_parent_gpu_t test_parent;
static char events[8];
static unsigned event_count;
static unsigned scheduler_calls;
static unsigned queue_flush_calls;
static unsigned schedule_result;
static bool lock_held;
static bool scheduler_saw_lock;
static bool queue_flush_saw_unlocked;

static void record_event(char event)
{
    assert(event_count + 1 < sizeof(events));
    events[event_count++] = event;
    events[event_count] = '\0';
}

static void uvm_spin_lock_irqsave(int *lock)
{
    assert(lock == &test_parent.isr.interrupts_lock);
    assert(!lock_held);
    lock_held = true;
    *lock = 1;
    record_event('L');
}

static unsigned uvm_parent_gpu_schedule_non_replayable_faults_handler(
    uvm_parent_gpu_t *parent_gpu)
{
    assert(parent_gpu == &test_parent);
    assert(lock_held);
    scheduler_saw_lock = true;
    ++scheduler_calls;
    record_event('S');
    return schedule_result;
}

static void uvm_spin_unlock_irqrestore(int *lock)
{
    assert(lock == &test_parent.isr.interrupts_lock);
    assert(lock_held);
    lock_held = false;
    *lock = 0;
    record_event('U');
}

static void nv_kthread_q_flush(int *queue)
{
    assert(queue == &test_parent.isr.bottom_half_q);
    assert(!lock_held);
    queue_flush_saw_unlocked = true;
    ++queue_flush_calls;
    record_event('Q');
}

static void r580_candidate_flush(uvm_parent_gpu_t *parent_gpu)
{
'''
    middle = r'''
}

static void r595_flush(uvm_parent_gpu_t *parent_gpu)
{
'''
    suffix = r'''
}

static void run_case(const char *source, void (*flush)(uvm_parent_gpu_t *), unsigned result)
{
    memset(&test_parent, 0, sizeof(test_parent));
    memset(events, 0, sizeof(events));
    event_count = 0;
    scheduler_calls = 0;
    queue_flush_calls = 0;
    schedule_result = result;
    lock_held = false;
    scheduler_saw_lock = false;
    queue_flush_saw_unlocked = false;

    flush(&test_parent);

    assert(strcmp(events, "LSUQ") == 0);
    assert(!lock_held);
    assert(test_parent.isr.interrupts_lock == 0);
    assert(scheduler_saw_lock);
    assert(queue_flush_saw_unlocked);
    assert(scheduler_calls == 1);
    assert(queue_flush_calls == 1);
    printf("CASE|%s|%u|%s|%u|%u|%u|%u\n", source, result, events,
           scheduler_saw_lock, queue_flush_saw_unlocked,
           scheduler_calls, queue_flush_calls);
}

int main(void)
{
    run_case("r580_candidate", r580_candidate_flush, 0);
    run_case("r580_candidate", r580_candidate_flush, 1);
    run_case("r595", r595_flush, 0);
    run_case("r595", r595_flush, 1);
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
        if len(fields) != 8:
            raise ValueError(f"unexpected host harness output: {line!r}")
        cases.append({
            "source": fields[1],
            "scheduler_result": int(fields[2]),
            "event_order": fields[3],
            "scheduler_saw_interrupt_lock": bool(int(fields[4])),
            "queue_flush_saw_interrupt_lock_released": bool(int(fields[5])),
            "scheduler_calls": int(fields[6]),
            "queue_flush_calls": int(fields[7]),
        })
    if len(cases) != 4:
        raise ValueError(f"expected four executed cases, observed {len(cases)}")
    return cases


def run_harness() -> dict[str, Any]:
    r580_body, r580_info = _source_snapshot(R580_CANDIDATE, PINNED["r580_candidate"], "R580 candidate")
    r595_body, r595_info = _source_snapshot(R595_SOURCE, PINNED["r595"], "R595")
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("a C compiler is required for exact-source host execution")

    with tempfile.TemporaryDirectory(prefix="nonreplayable-flush-host-") as directory:
        temporary = Path(directory)
        source_path = temporary / "flush_harness.c"
        binary_path = temporary / "flush_harness"
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
        "schema": "r580-r595-nonreplayable-flush-host-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": {
            "level": "tested-isolated",
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
        },
        "source_functions": {
            "r580_candidate": r580_info,
            "r595": r595_info,
        },
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
            "Exact helper bodies execute with synthetic interrupt-lock, scheduler, and queue collaborators. "
            "This checks call ordering only; it does not validate kernel locking, races, RM, GPU interrupts, "
            "fault delivery, module loading, CUDA, or hardware."
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
        print(f"non-replayable flush host harness failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
