# SPDX-License-Identifier: MIT
"""Pin R595 UVM fault-tracker ordering across service-error paths."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / (
    "build/experiments/r595-hmm-migrate-aggregate-guard-v1-20261029/"
    "candidate/nvidia-uvm"
)
SOURCE_HASHES = {
    "uvm_gpu_non_replayable_faults.c": "83fd573b3f5187ded355dec0a835f293716b0d271204d2c617864346fac01888",
    "uvm_gpu_replayable_faults.c": "e2b98f550ad6ef3efb062d931834f09acd79ecd5fa140a2f54de8e77a5dfac2b",
    "uvm_tracker.c": "1b7fd32a785b78af5492c30a297e148f421af3e04108a587a641932d4ca7499a",
}


def _load_pinned(name: str) -> str:
    path = SOURCE_ROOT / name
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_HASHES[name]:
        raise AssertionError(f"pinned R595 source drift: {path}")
    return data.decode("utf-8")


def _function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    i = opening
    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and nxt == "/":
                state = "code"
                i += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        elif char == "/" and nxt == "/":
            state = "line-comment"
            i += 1
        elif char == "/" and nxt == "*":
            state = "block-comment"
            i += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:i]
        i += 1
    raise AssertionError(f"unterminated C function: {signature}")


def _assert_unconditional_block_tracker_merge(test: unittest.TestCase,
                                               source: str,
                                               signature: str,
                                               expected_destination: str) -> None:
    body = _function_body(source, signature)
    service_call = body.index("status = UVM_VA_BLOCK_RETRY_LOCKED")
    merge = body.index("tracker_status = uvm_tracker_add_tracker_safe")
    unlock = body.index("uvm_mutex_unlock(&va_block->lock)", merge)

    test.assertLess(service_call, merge)
    test.assertLess(merge, unlock)
    test.assertIn(expected_destination, body[merge:unlock])
    test.assertRegex(body, r"return\s+status\s*==\s*NV_OK\s*\?\s*tracker_status\s*:\s*status\s*;")
    test.assertNotRegex(
        body,
        r"if\s*\(\s*status\s*(?:==|!=)\s*NV_OK\s*\)\s*\{\s*"
        r"tracker_status\s*=\s*uvm_tracker_add_tracker_safe",
    )


class R595FaultServiceTrackerErrorPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.nonreplayable = _load_pinned("uvm_gpu_non_replayable_faults.c")
        cls.replayable = _load_pinned("uvm_gpu_replayable_faults.c")
        cls.tracker = _load_pinned("uvm_tracker.c")

    def test_nonreplayable_error_still_aggregates_block_tracker(self) -> None:
        _assert_unconditional_block_tracker_merge(
            self,
            self.nonreplayable,
            "static NV_STATUS service_managed_fault_in_block(",
            "fault_service_tracker",
        )

    def test_nonreplayable_clear_waits_before_register_write(self) -> None:
        body = _function_body(
            self.nonreplayable,
            "static NV_STATUS clear_faulted_register_on_gpu(",
        )
        self.assertLess(body.index("uvm_tracker_wait(tracker)"),
                        body.index("clear_faulted_channel_register"))

        service = _function_body(self.nonreplayable, "static NV_STATUS service_fault_once(")
        clear = service.index("if (status == NV_OK && !fault_entry->is_fatal)")
        self.assertLess(clear, service.index("clear_faulted_on_gpu(", clear))
        self.assertLess(service.index("uvm_tracker_clear(&non_replayable_faults->fault_service_tracker)", clear),
                        service.index("schedule_kill_channel(fault_entry, user_channel)"))

    def test_replayable_error_still_aggregates_block_tracker(self) -> None:
        _assert_unconditional_block_tracker_merge(
            self,
            self.replayable,
            "static NV_STATUS service_fault_batch_block(",
            "&batch_context->tracker",
        )

    def test_replayable_global_error_cancellation_reuses_batch_tracker(self) -> None:
        service = _function_body(
            self.replayable,
            "void uvm_parent_gpu_service_replayable_faults(",
        )
        self.assertIn("We may have issued replays even if status != NV_OK", service)
        self.assertIn("if (status != NV_OK)", service)
        self.assertIn("cancel_fault_batch(parent_gpu, batch_context,", service)

        cancel_batch = _function_body(self.replayable, "static void cancel_fault_batch(")
        self.assertIn("cancel_faults_all(batch_context, reason)", cancel_batch)
        cancel = _function_body(self.replayable, "static NV_STATUS cancel_faults_all(")
        flush = cancel.index("fault_buffer_flush_locked(")
        self.assertIn("batch_context", cancel[flush:])

        flush_body = _function_body(self.replayable, "static NV_STATUS fault_buffer_flush_locked(")
        self.assertIn("push_replay_on_gpu(gpu, fault_replay, batch_context)", flush_body)
        replay = _function_body(self.replayable, "static NV_STATUS push_replay_on_gpu(")
        self.assertIn("tracker = &batch_context->tracker", replay)
        self.assertIn("uvm_push_begin_acquire(gpu->channel_manager, UVM_CHANNEL_TYPE_MEMOPS, tracker", replay)

    def test_tracker_safe_only_waits_after_tracker_growth_failure(self) -> None:
        body = _function_body(self.tracker, "NV_STATUS uvm_tracker_add_tracker_safe(")
        self.assertRegex(
            body,
            r"status\s*=\s*uvm_tracker_add_tracker\(dst,\s*src\);\s*"
            r"if\s*\(status\s*==\s*NV_ERR_NO_MEMORY\)\s*\{[^}]*"
            r"status\s*=\s*uvm_tracker_wait\(src\);",
        )

    def test_mutations_that_skip_or_gate_error_aggregation_fail(self) -> None:
        signature = "static NV_STATUS service_fault_batch_block("
        original = _function_body(self.replayable, signature)
        skipped = original.replace(
            "tracker_status = uvm_tracker_add_tracker_safe(&batch_context->tracker, &va_block->tracker);",
            "tracker_status = NV_OK;",
            1,
        )
        gated = original.replace(
            "tracker_status = uvm_tracker_add_tracker_safe(&batch_context->tracker, &va_block->tracker);",
            "if (status == NV_OK) {\n"
            "        tracker_status = uvm_tracker_add_tracker_safe(&batch_context->tracker, &va_block->tracker);\n"
            "    }",
            1,
        )

        for mutant in (skipped, gated):
            with self.subTest(mutant="skipped" if mutant == skipped else "gated"):
                with self.assertRaises((AssertionError, ValueError)):
                    _assert_unconditional_block_tracker_merge(
                        self,
                        "static NV_STATUS service_fault_batch_block(" + "{" + mutant + "}",
                        "static NV_STATUS service_fault_batch_block(",
                        "&batch_context->tracker",
                    )


if __name__ == "__main__":
    unittest.main()
