# SPDX-License-Identifier: MIT
"""Regression contracts for raw R595 UVM tracker references at detach sites."""
from __future__ import annotations

import re
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "build/experiments/r595-isolated-provider-cache-v2-20261028T2040Z"
PATCH = ROOT / "patches/r595.99.02/0006-uvm-reject-completed-foreign-tracker-refs-before-detach.patch"
PATCH_7 = ROOT / "patches/r595.99.02/0007-prune-completed-block-trackers-before-eviction-guard.patch"
PREIMAGES = {
    "uvm_tracker.c": "b31982b1f3df6cac9f8eb1d7ba91d333853678d6cf78693910dc81f720c87ba9",
    "uvm_tracker.h": "c418834db3fe5ddd18688b6915394f5ab55dd681c657af50942c13624fe95804",
    "uvm_pmm_gpu.c": "c9cd25654dc8c7b92b02f35fa8e794ed375c4e8b00218ed018438816da42e038",
    "uvm_va_block.c": "faf15872daf79ea83894ce24f7f8c4034809c03114a99da1fd0817288785c931",
    "uvm_va_range.c": "26c4c705ea797d0247740678b545d5b2394839eba61d79bef50182ffe6537787",
    "uvm_va_space.c": "f3396e769c7fd229ffede4af0345714f9f6001833c1c884c2fc78bda997e6be4",
    "uvm_gpu.c": "925ffe7bad8362431e71985c77b76c8a84f16ab3b08e7c32115c503ea81f760d",
}


def _function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


def _assert_eviction_failure_cleanup(test: unittest.TestCase, pmm: str) -> None:
    evict = _function_body(
        pmm,
        "static NV_STATUS evict_root_chunk_from_va_block(",
        "\nvoid uvm_pmm_gpu_mark_chunk_evicted(",
    )
    test.assertRegex(
        evict,
        r"if \(isolated_gpu_execution && "
        r"uvm_tracker_has_other_gpus\(&va_block->tracker, gpu\)\)\s*"
        r"status = NV_ERR_NOT_SUPPORTED;\s*else\s*"
        r"status = uvm_va_block_evict_chunks\(va_block, gpu, "
        r"&root_chunk->chunk, &tracker\);",
    )

    unlock = evict.index("uvm_mutex_unlock(&va_block->lock);")
    test.assertIn("uvm_va_block_release(va_block);", evict)
    release = evict.index("uvm_va_block_release(va_block);")
    test.assertIn("if (status == NV_OK)", evict)
    success = evict.index("if (status == NV_OK)")
    test.assertLess(unlock, release)
    test.assertLess(release, success)
    cleanup_segment = evict[unlock:success]
    # The retained block must be released regardless of the eviction status.
    test.assertNotRegex(cleanup_segment, r"(?m)^\s*(?:if\s*\(|return\b|goto\b)")

    test.assertRegex(
        evict,
        r"if \(status == NV_OK\)\s*\{\s*"
        r"root_chunk_lock\(pmm, root_chunk\);\s*"
        r"status = uvm_tracker_add_tracker_safe\(&root_chunk->tracker, &tracker\);\s*"
        r"root_chunk_unlock\(pmm, root_chunk\);\s*\}",
    )
    deinit = evict.index("uvm_tracker_deinit(&tracker);")
    test.assertIn("uvm_mutex_lock(&pmm->lock);", evict[deinit:])
    relock = evict.index("uvm_mutex_lock(&pmm->lock);", deinit)
    returned = evict.index("return status;", relock)
    test.assertLess(success, deinit)
    test.assertLess(deinit, relock)
    test.assertLess(relock, returned)
    test.assertNotRegex(evict[deinit:relock], r"(?m)^\s*(?:if\s*\(|return\b|goto\b)")


def _assert_unregister_joins_tracker_lifetimes(test: unittest.TestCase, source_root: Path) -> None:
    uvm = source_root / "nvidia-uvm"
    block = (uvm / "uvm_va_block.c").read_text()
    range_source = (uvm / "uvm_va_range.c").read_text()
    va_space_source = (uvm / "uvm_va_space.c").read_text()
    gpu_source = (uvm / "uvm_gpu.c").read_text()

    unregister_locked = _function_body(
        block,
        "void uvm_va_block_unregister_gpu_locked(",
        "\nvoid uvm_va_block_unregister_gpu(",
    )
    test.assertIn("uvm_assert_mutex_locked(&va_block->lock);", unregister_locked)
    destroyed = unregister_locked.index("block_destroy_gpu_state(")
    test.assertIn("uvm_tracker_wait(&va_block->tracker)", unregister_locked)
    waited = unregister_locked.index("uvm_tracker_wait(&va_block->tracker)")
    test.assertLess(destroyed, waited)

    unregister_block = _function_body(
        block,
        "void uvm_va_block_unregister_gpu(",
        "\n// Tears down everything within the block",
    )
    test.assertIn("uvm_mutex_lock(&va_block->lock);", unregister_block)
    test.assertIn("uvm_va_block_unregister_gpu_locked(va_block, gpu, mm);", unregister_block)
    test.assertIn("uvm_mutex_unlock(&va_block->lock);", unregister_block)
    lock = unregister_block.index("uvm_mutex_lock(&va_block->lock);")
    call = unregister_block.index("uvm_va_block_unregister_gpu_locked(va_block, gpu, mm);")
    unlock = unregister_block.index("uvm_mutex_unlock(&va_block->lock);")
    test.assertLess(lock, call)
    test.assertLess(call, unlock)

    unregister_managed = _function_body(
        range_source,
        "static void va_range_unregister_gpu_managed(",
        "\nstatic void va_range_unregister_gpu_external(",
    )
    test.assertRegex(
        unregister_managed,
        r"for_each_va_block_in_va_range\(managed_range, va_block\)\s*"
        r"uvm_va_block_unregister_gpu\(va_block, gpu, mm\);",
    )

    unregister_va_ranges = _function_body(
        va_space_source,
        "static void unregister_gpu(",
        "\nNV_STATUS uvm_va_space_unregister_gpu(",
    )
    test.assertRegex(
        unregister_va_ranges,
        r"uvm_for_each_va_range\(va_range, va_space\)\s*"
        r"uvm_va_range_unregister_gpu\(va_range, gpu, mm, deferred_free_list\);",
    )

    unregister_va_space = _function_body(
        va_space_source,
        "NV_STATUS uvm_va_space_unregister_gpu(",
        "\nstatic void disable_egm_peers(",
    )
    unregistered = unregister_va_space.index(
        "unregister_gpu(va_space, gpu, mm, &deferred_free_list, peers_to_release);"
    )
    test.assertIn("uvm_gpu_release_locked(gpu);", unregister_va_space)
    released = unregister_va_space.index("uvm_gpu_release_locked(gpu);")
    test.assertLess(unregistered, released)

    deinit_gpu = _function_body(
        gpu_source,
        "static void deinit_gpu(",
        "\n// Do not not call this directly.",
    )
    test.assertIn("uvm_pmm_gpu_sync(&gpu->pmm);", deinit_gpu)
    pmm_sync = deinit_gpu.index("uvm_pmm_gpu_sync(&gpu->pmm);")
    test.assertIn("uvm_channel_manager_destroy(gpu->channel_manager);", deinit_gpu)
    channel_destroy = deinit_gpu.index("uvm_channel_manager_destroy(gpu->channel_manager);")
    test.assertLess(pmm_sync, channel_destroy)


def _assert_safe_tracker_detach(test: unittest.TestCase, source_root: Path) -> None:
    uvm = source_root / "nvidia-uvm"
    tracker_c = (uvm / "uvm_tracker.c").read_text()
    tracker_h = (uvm / "uvm_tracker.h").read_text()
    pmm = (uvm / "uvm_pmm_gpu.c").read_text()

    helper = _function_body(
        tracker_c,
        "bool uvm_tracker_has_other_gpus(",
        "bool uvm_tracker_has_other_providers(",
    )
    # Completion means the semaphore reached its value; the entry still owns a
    # raw channel pointer until it is removed or explicitly waited/cleared.
    test.assertNotIn("uvm_tracker_is_entry_completed", helper)
    test.assertRegex(helper, r"entry->channel\s*!=\s*NULL")
    test.assertIn("uvm_tracker_entry_gpu(entry) != gpu", helper)
    test.assertIsNotNone(re.search(
        r"Check channel references.*?includes completed entries",
        tracker_h,
        re.S,
    ))

    alloc = _function_body(
        pmm,
        "static NV_STATUS pmm_gpu_alloc(",
        "\nNV_STATUS uvm_pmm_gpu_alloc_kernel(",
    )
    prune = alloc.index("uvm_tracker_remove_completed(&root_chunk->tracker);")
    guard = alloc.index("uvm_tracker_has_other_gpus(&root_chunk->tracker, gpu)")
    copy = alloc.index("uvm_tracker_add_tracker_safe(&local_tracker, &root_chunk->tracker);")
    test.assertLess(prune, guard)
    test.assertLess(guard, copy)

    evict = _function_body(
        pmm,
        "static NV_STATUS evict_root_chunk_from_va_block(",
        "\nvoid uvm_pmm_gpu_mark_chunk_evicted(",
    )
    lock = evict.index("uvm_mutex_lock(&va_block->lock);")
    prune_text = "uvm_tracker_remove_completed(&va_block->tracker);"
    test.assertIn(prune_text, evict)
    prune = evict.index(prune_text)
    guard_text = "uvm_tracker_has_other_gpus(&va_block->tracker, gpu)"
    test.assertIn(guard_text, evict)
    guard = evict.index(guard_text)
    detach = evict.index("uvm_va_block_evict_chunks(")
    test.assertLess(lock, guard)
    test.assertLess(lock, prune)
    test.assertLess(prune, guard)
    test.assertLess(guard, detach)
    _assert_eviction_failure_cleanup(test, pmm)
    _assert_unregister_joins_tracker_lifetimes(test, source_root)


class R595TrackerDetachLifetimeTests(unittest.TestCase):
    def _apply_patch_to_pinned_preimage(self, root: Path) -> None:
        (root / "nvidia-uvm").mkdir()
        for name, expected in PREIMAGES.items():
            payload = (OVERLAY / "candidate/nvidia-uvm" / name).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)
            (root / "nvidia-uvm" / name).write_bytes(payload)
        for patch in (PATCH, PATCH_7):
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("offset", result.stdout.lower())
            self.assertNotIn("fuzz", result.stdout.lower())

    def test_patch_applies_to_exact_preimage_and_rejects_completed_references(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-detach-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            _assert_safe_tracker_detach(self, root)

    def test_mutated_guard_that_skips_completed_entries_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-mutation-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            tracker = root / "nvidia-uvm/uvm_tracker.c"
            source = tracker.read_text()
            source = source.replace(
                "for_each_tracker_entry(entry, tracker) {\n"
                "        if (entry->channel != NULL && uvm_tracker_entry_gpu(entry) != gpu)",
                "for_each_tracker_entry(entry, tracker) {\n"
                "        if (uvm_tracker_is_entry_completed(entry))\n"
                "            continue;\n"
                "        if (entry->channel != NULL && uvm_tracker_entry_gpu(entry) != gpu)",
                1,
            )
            tracker.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_eviction_guard_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-order-mutation-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text().replace(
                "uvm_tracker_has_other_gpus(&va_block->tracker, gpu)",
                "uvm_tracker_has_other_gpus(&root_chunk->tracker, gpu)",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_eviction_prune_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-prune-mutation-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text().replace(
                "uvm_tracker_remove_completed(&va_block->tracker);",
                "/* completed-entry prune omitted */",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_eviction_refusal_status_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-refusal-status-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text().replace(
                "status = NV_ERR_NOT_SUPPORTED;\n    else\n        status = uvm_va_block_evict_chunks(",
                "status = NV_OK;\n    else\n        status = uvm_va_block_evict_chunks(",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_eviction_retained_block_release_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-release-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text().replace(
                "    uvm_va_block_release(va_block);",
                "    /* retained VA block leaked */",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_eviction_success_gate_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-success-gate-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text().replace(
                "if (status == NV_OK) {\n        root_chunk_lock(pmm, root_chunk);",
                "if (status != NV_OK) {\n        root_chunk_lock(pmm, root_chunk);",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_eviction_pmm_relock_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-tracker-pmm-relock-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text().replace(
                "    uvm_mutex_lock(&pmm->lock);\n\n    return status;",
                "    /* PMM lock not reacquired */\n\n    return status;",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_unregister_tracker_wait_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-unregister-tracker-wait-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            path = root / "nvidia-uvm/uvm_va_block.c"
            source = path.read_text().replace(
                "    status = uvm_tracker_wait(&va_block->tracker);\n"
                "    if (status != NV_OK)\n"
                "        UVM_ASSERT(status == uvm_global_get_status());",
                "status = NV_OK; /* tracker wait omitted */",
                1,
            )
            path.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_unregister_block_lock_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-unregister-block-lock-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            path = root / "nvidia-uvm/uvm_va_block.c"
            source = path.read_text()
            start = source.index("void uvm_va_block_unregister_gpu(")
            end = source.index("\n// Tears down everything within the block", start)
            body = source[start:end]
            mutated = body.replace(
                "    uvm_mutex_lock(&va_block->lock);",
                "    /* block lock omitted */",
                1,
            )
            self.assertNotEqual(body, mutated)
            source = source[:start] + mutated + source[end:]
            path.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_unregister_managed_range_walk_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-unregister-range-walk-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            path = root / "nvidia-uvm/uvm_va_range.c"
            source = path.read_text().replace(
                "uvm_va_block_unregister_gpu(va_block, gpu, mm);",
                "/* per-block unregister omitted */",
                1,
            )
            path.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_va_space_release_order_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-unregister-release-order-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            path = root / "nvidia-uvm/uvm_va_space.c"
            source = path.read_text().replace(
                "    unregister_gpu(va_space, gpu, mm, &deferred_free_list, peers_to_release);",
                "    uvm_gpu_release_locked(gpu);\n\n"
                "    unregister_gpu(va_space, gpu, mm, &deferred_free_list, peers_to_release);",
                1,
            )
            path.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)

    def test_mutated_gpu_channel_teardown_order_fails_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-gpu-channel-teardown-order-") as temp:
            root = Path(temp)
            self._apply_patch_to_pinned_preimage(root)
            path = root / "nvidia-uvm/uvm_gpu.c"
            source = path.read_text().replace(
                "    uvm_pmm_gpu_sync(&gpu->pmm);\n\n"
                "    uvm_channel_manager_destroy(gpu->channel_manager);",
                "    uvm_channel_manager_destroy(gpu->channel_manager);",
                1,
            )
            path.write_text(source)
            with self.assertRaises(AssertionError):
                _assert_safe_tracker_detach(self, root)


if __name__ == "__main__":
    unittest.main()
