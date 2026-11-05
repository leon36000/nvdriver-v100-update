# SPDX-License-Identifier: MIT
"""Source contracts for R595 HMM tracker/channel lifetime boundaries.

These checks pin the selected patched-source overlay and ensure tracker waits
remain inside the lock scopes used by HMM policy, migration, invalidation, and
GPU-VA-space teardown. They are static regression contracts, not a concurrency
or hardware test.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
UVM = ROOT / "build/experiments/r595-provider-id-validation-v1-20261029/candidate/nvidia-uvm"
SOURCE_SHA256 = {
    "uvm_hmm.c": "9fb7477ee9c9058493a99847f9395a22959c04ceed33f1120849ec3f71e38d04",
    "uvm_policy.c": "8843ff3468d51c9e93e1c08d04714244823638fcbc3c6e9fb021a11862cd2407",
    "uvm_tracker.c": "1b7fd32a785b78af5492c30a297e148f421af3e04108a587a641932d4ca7499a",
    "uvm_va_space.c": "f3396e769c7fd229ffede4af0345714f9f6001833c1c884c2fc78bda997e6be4",
    "uvm_va_block.c": "faf15872daf79ea83894ce24f7f8c4034809c03114a99da1fd0817288785c931",
    "uvm_user_channel.c": "9a6cec689eaf9c1edd1b7defa9ee7e74215382d802e7ab192b52caa1d0e93fe7",
    "uvm_push.c": "ed8fecb3dd53f5a845f1eeaff411a699f46538edc03c5e8e75bfaa112f3c7b42",
}


def _function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


class R595HmmTrackerWaitLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = {}
        for name, expected in SOURCE_SHA256.items():
            payload = (UVM / name).read_bytes()
            cls.sources[name] = payload.decode()
            if hashlib.sha256(payload).hexdigest() != expected:
                raise AssertionError(f"pinned R595 source changed: {name}")

    def test_policy_apis_wait_before_releasing_va_space_and_mm_locks(self) -> None:
        policy = self.sources["uvm_policy.c"]
        for signature, next_signature in (
            ("NV_STATUS uvm_api_set_preferred_location(", "NV_STATUS uvm_api_set_accessed_by("),
            ("static NV_STATUS accessed_by_set(", "NV_STATUS uvm_api_set_accessed_by("),
        ):
            with self.subTest(api=signature):
                body = _function_body(policy, signature, next_signature)
                wait = body.index("uvm_tracker_wait_deinit(&local_tracker);")
                va_unlock = body.index("uvm_va_space_up_write(va_space);")
                mm_unlock = body.index("uvm_va_space_mm_or_current_release_unlock(va_space, mm);")
                self.assertLess(wait, va_unlock)
                self.assertLess(va_unlock, mm_unlock)

    def test_deferred_hmm_eviction_wait_stays_inside_va_space_read_section(self) -> None:
        hmm = self.sources["uvm_hmm.c"]
        va_block = self.sources["uvm_va_block.c"]
        worker = _function_body(
            va_block,
            "static void block_add_eviction_mappings(void *args)",
            "static void block_add_eviction_mappings_entry(void *args)",
        )
        down = worker.index("uvm_va_space_down_read(va_space);")
        invoke = worker.index("uvm_hmm_block_add_eviction_mappings(va_space, va_block, block_context);")
        up = worker.index("uvm_va_space_up_read(va_space);", invoke)
        self.assertLess(down, invoke)
        self.assertLess(invoke, up)

        hmm_worker = _function_body(
            hmm,
            "void uvm_hmm_block_add_eviction_mappings(",
            "const uvm_va_policy_t *uvm_hmm_find_policy_end(",
        )
        copy = hmm_worker.index("uvm_tracker_add_tracker_safe(&local_tracker, &va_block->tracker);")
        unlock = hmm_worker.index("uvm_mutex_unlock(&va_block->lock);")
        wait = hmm_worker.index("uvm_tracker_wait_deinit(&local_tracker);")
        self.assertLess(copy, unlock)
        self.assertLess(unlock, wait)

    def test_hmm_oom_merge_wait_bypasses_isolated_provider_guard_under_block_lock(self) -> None:
        push = self.sources["uvm_push.c"]
        tracker = self.sources["uvm_tracker.c"]
        hmm = self.sources["uvm_hmm.c"]

        acquire_guard = _function_body(
            push,
            "static NV_STATUS wait_for_other_gpus_if_needed(",
            "static NV_STATUS push_begin_acquire_with_info(",
        )
        self.assertIn("uvm_push_isolated_gpu_execution_enabled()", acquire_guard)
        self.assertIn("uvm_tracker_has_other_providers(tracker, gpu)", acquire_guard)
        self.assertLess(
            acquire_guard.index("return NV_ERR_NOT_SUPPORTED;"),
            acquire_guard.index("uvm_tracker_wait_for_other_gpus(tracker, gpu);"),
        )

        add_safe = _function_body(
            tracker,
            "NV_STATUS uvm_tracker_add_tracker_safe(",
            "bool uvm_tracker_is_entry_completed(",
        )
        self.assertIn("status = uvm_tracker_wait(src);", add_safe)
        self.assertNotIn("uvm_push_isolated_gpu_execution_enabled()", add_safe)

        eviction = _function_body(
            hmm,
            "void uvm_hmm_block_add_eviction_mappings(",
            "const uvm_va_policy_t *uvm_hmm_find_policy_end(",
        )
        lock = eviction.index("uvm_mutex_lock(&va_block->lock);")
        map_call = eviction.index("uvm_va_block_add_mappings(")
        merge = eviction.index(
            "uvm_tracker_add_tracker_safe(&local_tracker, &va_block->tracker);"
        )
        unlock = eviction.index("uvm_mutex_unlock(&va_block->lock);", merge)
        wait = eviction.index("uvm_tracker_wait_deinit(&local_tracker);", unlock)
        self.assertLess(lock, map_call)
        self.assertLess(map_call, merge)
        self.assertLess(merge, unlock)
        self.assertLess(unlock, wait)

    def test_mmu_invalidator_waits_shared_block_tracker_under_block_lock(self) -> None:
        hmm = self.sources["uvm_hmm.c"]
        invalidate = _function_body(
            hmm,
            "static bool hmm_invalidate(",
            "static bool uvm_hmm_invalidate_entry(",
        )
        lock = invalidate.index("uvm_mutex_lock(&va_block->lock);")
        wait = invalidate.index("uvm_tracker_wait(&va_block->tracker);")
        unlock = invalidate.index("uvm_mutex_unlock(&va_block->lock);")
        self.assertLess(lock, wait)
        self.assertLess(wait, unlock)

    def test_successful_tracker_wait_prunes_completed_raw_channel_references(self) -> None:
        tracker = self.sources["uvm_tracker.c"]
        wait = _function_body(
            tracker,
            "NV_STATUS uvm_tracker_wait(uvm_tracker_t *tracker)",
            "NV_STATUS uvm_tracker_wait_for_other_gpus(",
        )
        completed = _function_body(
            tracker,
            "bool uvm_tracker_is_completed(uvm_tracker_t *tracker)",
            "uvm_gpu_t *uvm_tracker_entry_gpu(",
        )
        prune = _function_body(
            tracker,
            "void uvm_tracker_remove_completed(uvm_tracker_t *tracker)",
            "bool uvm_tracker_is_completed(",
        )
        self.assertIn("while (!uvm_tracker_is_completed(tracker)", wait)
        self.assertIn("uvm_tracker_remove_completed(tracker);", completed)
        self.assertIn("uvm_tracker_is_entry_completed(&entries[i])", prune)
        self.assertIn("entries[i] = entries[tracker->size];", prune)

    def test_gpu_va_space_teardown_defers_channel_free_until_hmm_blocks_join(self) -> None:
        va_space = self.sources["uvm_va_space.c"]
        hmm = self.sources["uvm_hmm.c"]
        channel = self.sources["uvm_user_channel.c"]

        remove = _function_body(
            va_space,
            "static void remove_gpu_va_space(",
            "NV_STATUS uvm_va_space_unregister_gpu_va_space(",
        )
        detach = remove.index("uvm_gpu_va_space_detach_all_user_channels(gpu_va_space, deferred_free_list);")
        hmm_remove = remove.index("uvm_hmm_remove_gpu_va_space(va_space, gpu_va_space, mm);")
        self.assertLess(detach, hmm_remove)

        hmm_remove_fn = _function_body(
            hmm,
            "void uvm_hmm_remove_gpu_va_space(",
            "static bool hmm_invalidate(",
        )
        self.assertIn(
            "hmm_va_block_remove_gpu_va_space(va_block, gpu_va_space, va_block_context);",
            hmm_remove_fn,
        )
        block_helper = _function_body(
            hmm,
            "static void hmm_va_block_remove_gpu_va_space(",
            "void uvm_hmm_remove_gpu_va_space(",
        )
        block_lock = block_helper.index("uvm_mutex_lock(&va_block->lock);")
        block_remove = block_helper.index("uvm_va_block_remove_gpu_va_space(va_block, gpu_va_space, va_block_context);")
        block_unlock = block_helper.index("uvm_mutex_unlock(&va_block->lock);")
        self.assertIn("uvm_range_tree_for_each_safe", hmm_remove_fn)
        self.assertIn("hmm_va_block_remove_gpu_va_space", hmm_remove_fn)
        self.assertLess(block_lock, block_remove)
        self.assertLess(block_remove, block_unlock)

        unregister = _function_body(
            va_space,
            "NV_STATUS uvm_va_space_unregister_gpu_va_space(",
            "bool uvm_va_space_single_gpu_in_parent(",
        )
        detach_and_join = unregister.index("remove_gpu_va_space(gpu_va_space, mm, &deferred_free_list);")
        unlock = unregister.index("uvm_va_space_up_write(va_space);", detach_and_join)
        free = unregister.index("uvm_deferred_free_object_list(&deferred_free_list);", unlock)
        self.assertLess(detach_and_join, unlock)
        self.assertLess(unlock, free)

        detach_fn = _function_body(channel, "void uvm_user_channel_detach(", "static void check_dead(")
        enqueue = detach_fn.index("uvm_deferred_free_object_add(deferred_free_list,")
        self.assertLess(enqueue, detach_fn.index("user_channel->gpu_va_space = NULL;"))


if __name__ == "__main__":
    unittest.main()
