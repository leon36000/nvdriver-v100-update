# SPDX-License-Identifier: MIT
"""Pin the R595 PMM tracker's OOM fallback outside the root-chunk bitlock."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / (
    "build/experiments/r595-pmm-tracker-wait-outside-root-bitlock-final-v1-20261029/"
    "candidate/nvidia-uvm"
)
SOURCE_HASHES = {
    "uvm_pmm_gpu.c": "f184f336b632575f077801db74e03635351ed56fe8cec1225bb066471911e52b",
    "uvm_tracker.c": "1b7fd32a785b78af5492c30a297e148f421af3e04108a587a641932d4ca7499a",
}


def _load_pinned(name: str) -> str:
    payload = (SOURCE_ROOT / name).read_bytes()
    if hashlib.sha256(payload).hexdigest() != SOURCE_HASHES[name]:
        raise AssertionError(f"pinned R595 source drift: {name}")
    return payload.decode("utf-8")


def _function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "char"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        elif char == "/" and next_char == "/":
            state = "line-comment"
            index += 1
        elif char == "/" and next_char == "*":
            state = "block-comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
        index += 1
    raise AssertionError(f"unterminated C function: {signature}")


def _assert_pmm_wait_contract(test: unittest.TestCase, source: str) -> None:
    body = _function_body(source, "void uvm_pmm_gpu_free(")
    lock = body.index("root_chunk_lock(pmm, root_chunk);")
    prune = body.index("uvm_tracker_remove_completed(&root_chunk->tracker);")
    merge = body.index("uvm_tracker_add_tracker(&root_chunk->tracker, tracker);")
    unlock = body.index("root_chunk_unlock(pmm, root_chunk);", merge)
    wait = body.index("status = uvm_tracker_wait(tracker);", unlock)
    free = body.index("free_chunk(pmm, chunk);", wait)

    test.assertLess(lock, prune)
    test.assertLess(prune, merge)
    test.assertLess(merge, unlock)
    test.assertLess(unlock, wait)
    test.assertLess(wait, free)
    test.assertRegex(
        body,
        r"if\s*\(\s*status\s*==\s*NV_ERR_NO_MEMORY\s*\)\s*"
        r"\{\s*UVM_DBG_PRINT_RL\(\"Failed to add tracker to tracker, waiting\\n\"\);\s*"
        r"status\s*=\s*uvm_tracker_wait\(tracker\);\s*\}",
    )
    test.assertIn("UVM_ASSERT(status == uvm_global_get_status());", body)
    test.assertNotIn("uvm_tracker_add_tracker_safe", body)


class R595PmmTrackerWaitOutsideRootLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pmm = _load_pinned("uvm_pmm_gpu.c")
        cls.tracker = _load_pinned("uvm_tracker.c")

    def test_pmm_free_releases_root_bitlock_before_oom_wait(self) -> None:
        _assert_pmm_wait_contract(self, self.pmm)

    def test_tracker_oom_return_precedes_any_entry_copy(self) -> None:
        body = _function_body(self.tracker, "NV_STATUS uvm_tracker_add_tracker(")
        first_reserve = body.index("uvm_tracker_reserve(dst, src->size)")
        prune_dst = body.index("uvm_tracker_remove_completed(dst);", first_reserve)
        prune_src = body.index("uvm_tracker_remove_completed(src);", prune_dst)
        retry = body.index("reserve_for_entries_from_tracker(dst, src);", prune_src)
        failed_return = body.index("if (status != NV_OK)", retry)
        entry_copy = body.index("for_each_tracker_entry(src_entry, src)", failed_return)
        self.assertLess(first_reserve, prune_dst)
        self.assertLess(prune_dst, prune_src)
        self.assertLess(prune_src, retry)
        self.assertLess(retry, failed_return)
        self.assertLess(failed_return, entry_copy)
        self.assertRegex(body[failed_return:entry_copy], r"return\s+status\s*;")

    def test_regressions_that_wait_under_lock_or_always_wait_are_rejected(self) -> None:
        signature = "void uvm_pmm_gpu_free("
        body = _function_body(self.pmm, signature)
        unlock = "        root_chunk_unlock(pmm, root_chunk);"
        wait_block = (
            "        if (status == NV_ERR_NO_MEMORY) {\n"
            "            UVM_DBG_PRINT_RL(\"Failed to add tracker to tracker, waiting\\n\");\n"
            "            status = uvm_tracker_wait(tracker);\n"
            "        }"
        )
        self.assertEqual(body.count(unlock), 1)
        self.assertEqual(body.count(wait_block), 1)

        waits_under_lock = self.pmm.replace(
            unlock + "\n\n" + wait_block,
            wait_block + "\n\n" + unlock,
            1,
        )
        unconditional_wait = self.pmm.replace(
            wait_block,
            "status = uvm_tracker_wait(tracker);",
            1,
        )
        for mutant in (waits_under_lock, unconditional_wait):
            with self.subTest(mutant="lock-held" if mutant == waits_under_lock else "unconditional"):
                with self.assertRaises((AssertionError, ValueError)):
                    _assert_pmm_wait_contract(self, mutant)


if __name__ == "__main__":
    unittest.main()
