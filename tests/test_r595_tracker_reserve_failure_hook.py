# SPDX-License-Identifier: MIT
"""Pin the test-only R595 tracker-reserve OOM injection contract."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / (
    "build/experiments/r595-pmm-tracker-wait-outside-root-bitlock-final-v1-20261029/"
    "candidate/nvidia-uvm"
)
PATCH = ROOT / "patches/r595.99.02/0012-test-only-tracker-reserve-oom-injection.patch"
BASELINE_HASHES = {
    "uvm_tracker.c": "1b7fd32a785b78af5492c30a297e148f421af3e04108a587a641932d4ca7499a",
    "uvm_tracker.h": "d094522d6af1ae62bf31560ccd81c35b22c45b1949d2258506564cbd7365d4b3",
    "uvm_tracker_test.c": "517fe4ab345c0d90fc53a53dbf715bea1fea945dafc171142f74c5ae7240a0b9",
    "uvm_pmm_gpu.c": "f184f336b632575f077801db74e03635351ed56fe8cec1225bb066471911e52b",
    "uvm_pmm_gpu.h": "acb2593222e65b947b384ee7def82f41664ae1204d031aaa958a3affdc4a86dd",
    "uvm_pmm_test.c": "b18fd95e43127746237290bf165dc1c397e3dd6568565711afbd4b4c937b50ac",
}


class R595TrackerReserveFailureHookTests(unittest.TestCase):
    def _apply_patch(self, root: Path) -> dict[str, str]:
        self.assertTrue(PATCH.is_file(), f"missing candidate patch: {PATCH.name}")
        for name, expected in BASELINE_HASHES.items():
            payload = (SOURCE_ROOT / name).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected, name)
            target = root / "nvidia-uvm" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        result = subprocess.run(
            ["patch", "--batch", "--forward", "-p1", "-i", str(PATCH)],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotRegex(result.stdout, r"\b(?:offset|fuzz)\b")
        return {
            name: (root / "nvidia-uvm" / name).read_text(encoding="utf-8")
            for name in BASELINE_HASHES
        }

    def _assert_hook_contract(self, tracker: str, header: str, test: str) -> None:
        self.assertIn("UVM_TEST_TRACKER_OOM_INJECTION", tracker)
        self.assertIn("UVM_TEST_TRACKER_OOM_INJECTION", header)
        self.assertIn("status = NV_ERR_IN_USE;", tracker)
        reserve = tracker[tracker.index("NV_STATUS uvm_tracker_reserve("):]
        growth = reserve[reserve.index("if (tracker->size + min_free_entries > tracker->max_size)"):]
        self.assertLess(
            growth.index("uvm_tracker_test_oom_inject_should_fail(tracker)"),
            growth.index("uvm_kvmalloc("),
        )
        growth_guard = "#ifdef UVM_TEST_TRACKER_OOM_INJECTION"
        self.assertIn(growth_guard, growth)
        growth_guard_start = growth.index(growth_guard)
        growth_guard_end = growth.index("#endif", growth_guard_start)
        self.assertIn(
            "uvm_tracker_test_oom_inject_should_fail(tracker)",
            growth[growth_guard_start:growth_guard_end],
        )
        self.assertIn(
            "g_tracker_test_oom_target == tracker && g_tracker_test_oom_remaining > 0",
            tracker,
        )
        disarm_start = tracker.index("NvU32 uvm_tracker_test_oom_inject_disarm(")
        disarm_end = tracker.index("static bool uvm_tracker_test_oom_inject_should_fail(", disarm_start)
        disarm = tracker[disarm_start:disarm_end]
        self.assertIn("if (g_tracker_test_oom_target == tracker)", disarm)
        self.assertIn("uvm_tracker_test_oom_inject_disarm(&dst)", test)
        self.assertNotIn("uvm_tracker_test_oom_inject_disarm()", test)
        self.assertIn("uvm_tracker_test_oom_inject_arm(&dst, 2)", test)
        self.assertIn("hook_armed = true;", test)
        self.assertIn("hook_armed = false;", test)
        self.assertIn("uvm_tracker_add_tracker(&dst, &src)", test)
        self.assertIn("status != NV_ERR_NO_MEMORY", test)
        self.assertIn("src.size != 1", test)
        self.assertIn("dst.size != 0", test)
        self.assertIn("uvm_gpu_semaphore_set_payload(&sema, 1)", test)
        cleanup_reset = (
            "done:\n"
            "    // Reset the global hook on every exit before releasing the pending push.\n"
            "    if (hook_armed) {\n"
            "        uvm_tracker_test_oom_inject_disarm(&dst);\n"
            "    }"
        )
        self.assertIn(cleanup_reset, test)
        self.assertRegex(
            test,
            r"(?s)#ifdef UVM_TEST_TRACKER_OOM_INJECTION.*?"
            r"test_tracker_reserve_oom_injection\(va_space\).*?#endif",
        )
        test_hook_guard_start = test.index(growth_guard)
        test_hook_guard_end = test.index("#endif", test_hook_guard_start)
        self.assertIn(
            "static NV_STATUS test_tracker_reserve_oom_injection",
            test[test_hook_guard_start:test_hook_guard_end],
        )
        sanity_route = test[test.index("NV_STATUS uvm_test_tracker_sanity("):]
        route_guard_start = sanity_route.index(growth_guard)
        route_guard_end = sanity_route.index("#endif", route_guard_start)
        self.assertIn(
            "test_tracker_reserve_oom_injection(va_space)",
            sanity_route[route_guard_start:route_guard_end],
        )

    def test_patch_is_scoped_gated_and_exercises_two_pending_reserve_failures(self) -> None:
        patch_text = PATCH.read_text(encoding="utf-8")
        patched_paths = set(re.findall(r"^\+\+\+ b/(.+)$", patch_text, re.MULTILINE))
        self.assertEqual(
            patched_paths,
            {f"nvidia-uvm/{name}" for name in BASELINE_HASHES},
        )
        with tempfile.TemporaryDirectory(prefix="r595-tracker-oom-patch-") as temp:
            sources = self._apply_patch(Path(temp))

        self._assert_hook_contract(
            sources["uvm_tracker.c"], sources["uvm_tracker.h"], sources["uvm_tracker_test.c"]
        )

    def test_mutations_that_remove_target_filter_or_cleanup_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r595-tracker-oom-mutation-") as temp:
            sources = self._apply_patch(Path(temp))

        tracker = sources["uvm_tracker.c"]
        test = sources["uvm_tracker_test.c"]
        target_filter = "g_tracker_test_oom_target == tracker && g_tracker_test_oom_remaining > 0"
        unscoped = tracker.replace(target_filter, "true", 1)
        unowned_disarm = tracker.replace(
            "if (g_tracker_test_oom_target == tracker) {", "if (true) {", 1
        )
        uncleared = test.replace(
            "    if (hook_armed) {\n"
            "        uvm_tracker_test_oom_inject_disarm(&dst);\n"
            "    }",
            "    // cleanup omitted",
            1,
        )
        unguarded = tracker.replace(
            "#ifdef UVM_TEST_TRACKER_OOM_INJECTION\n"
            "        if (uvm_tracker_test_oom_inject_should_fail(tracker))",
            "        if (uvm_tracker_test_oom_inject_should_fail(tracker))",
            1,
        )
        mutants = (
            ("unscoped", unscoped, test),
            ("disarm-other-owner", unowned_disarm, test),
            ("no-reset", tracker, uncleared),
            ("unguarded", unguarded, test),
        )
        for name, mutant_tracker, mutant_test in mutants:
            with self.subTest(mutant=name):
                with self.assertRaises(AssertionError):
                    self._assert_hook_contract(mutant_tracker, sources["uvm_tracker.h"], mutant_test)

    def test_pmm_test_drives_real_free_fallback_while_root_lock_is_observed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="r595-pmm-tracker-oom-contract-") as temp:
            sources = self._apply_patch(Path(temp))

        pmm = sources["uvm_pmm_gpu.c"]
        pmm_header = sources["uvm_pmm_gpu.h"]
        pmm_test = sources["uvm_pmm_test.c"]
        tracker = sources["uvm_tracker.c"]
        tracker_header = sources["uvm_tracker.h"]

        self.assertIn("uvm_pmm_gpu_test_oom_inject_arm_root", pmm)
        self.assertIn("uvm_pmm_gpu_test_oom_inject_arm_root", pmm_header)
        free_start = pmm.index("void uvm_pmm_gpu_free(")
        free_end = pmm.index("NV_STATUS uvm_pmm_gpu_test_oom_inject_arm_root", free_start)
        free_body = pmm[free_start:free_end]
        self.assertLess(
            free_body.index("uvm_tracker_test_oom_inject_arm(&root_chunk->tracker, failures) == NV_OK"),
            free_body.index("uvm_tracker_add_tracker(&root_chunk->tracker, tracker)"),
        )
        self.assertIn("bool test_oom_hook_armed = false;", free_body)
        self.assertIn(
            "uvm_tracker_test_oom_inject_disarm(&root_chunk->tracker)", free_body
        )
        self.assertLess(
            free_body.index("root_chunk_unlock(pmm, root_chunk);"),
            free_body.index("uvm_tracker_wait(tracker);"),
        )
        self.assertLess(
            free_body.index("WRITE_ONCE(*g_pmm_test_oom_wait_entered, 1)"),
            free_body.index("uvm_tracker_wait(tracker);"),
        )
        self.assertIn("g_pmm_test_oom_wait_source == tracker", free_body)
        self.assertIn("uvm_tracker_deinit(&root_chunk->tracker)", pmm)
        self.assertIn("uvm_tracker_init(&root_chunk->tracker)", pmm)
        self.assertIn("UVM_TEST_TRACKER_OOM_INJECTION", pmm)
        self.assertIn("uvm_pmm_gpu_free(pmm, chunk, &src_tracker)", pmm_test)
        self.assertIn("UVM_CHANNEL_TYPE_GPU_INTERNAL", pmm_test)
        self.assertIn("UVM_CHANNEL_TYPE_MEMOPS", pmm_test)
        self.assertIn("seed_push.channel == src_push.channel", pmm_test)
        self.assertIn("uvm_pmm_gpu_test_oom_inject_disarm()", pmm_test)
        pmm_disarm_start = pmm.index("NvU32 uvm_pmm_gpu_test_oom_inject_disarm(")
        pmm_disarm = pmm[pmm_disarm_start:]
        self.assertIn("injected_failures = g_pmm_test_oom_injected_failures;", pmm_disarm)
        self.assertNotIn("uvm_tracker_test_oom_inject_disarm()", pmm_disarm)
        self.assertIn(
            "test_bit(release->root_index, release->pmm->root_chunks.bitlocks.bits)", pmm_test
        )
        self.assertNotIn(
            "test_bit(root_index, release->pmm->root_chunks.bitlocks.bits)", pmm_test
        )
        self.assertIn("schedule_delayed_work", pmm_test)
        self.assertIn("flush_delayed_work", pmm_test)
        self.assertIn("injected_failures != 2", pmm_test)
        self.assertIn("release.root_lock_released", pmm_test)
        worker_start = pmm_test.index("static void pmm_tracker_oom_release_work(")
        worker_end = pmm_test.index("#endif", worker_start)
        worker = pmm_test[worker_start:worker_end]
        self.assertIn("test_bit(release->root_index,", worker)
        self.assertNotIn("release->chunk", worker)
        self.assertLess(
            pmm_test.index("release.root_index = chunk->address / UVM_CHUNK_SIZE_MAX;"),
            pmm_test.index("uvm_pmm_gpu_free(pmm, chunk, &src_tracker);"),
        )
        self.assertRegex(
            pmm_test,
            r"(?s)#ifdef UVM_TEST_TRACKER_OOM_INJECTION.*?"
            r"test_pmm_tracker_reserve_oom_injection\(gpu\).*?#endif",
        )


if __name__ == "__main__":
    unittest.main()
