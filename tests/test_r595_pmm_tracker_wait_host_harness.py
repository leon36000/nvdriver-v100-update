# SPDX-License-Identifier: MIT
"""Execute the pinned R595 PMM/tracker functions with gated host stubs."""
from __future__ import annotations

import importlib
import unittest


harness = importlib.import_module("tools.run_r595_pmm_tracker_wait_host_harness")


class R595PmmTrackerWaitHostHarnessTests(unittest.TestCase):
    def test_pinned_functions_keep_lock_and_chunk_lifetime_invariants(self):
        report = harness.run_harness()

        self.assertEqual(report["qualification"]["level"], "tested-isolated")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertFalse(report["qualification"]["loaded_or_installed"])
        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertEqual(report["execution"]["exit_code"], 0)
        result = report["execution"]["checks"]
        self.assertEqual(result["wait_calls"], 1)
        self.assertEqual(result["wait_root_bitlock_depth"], 0)
        self.assertTrue(result["competitor_acquired_root_bitlock_during_wait"])
        self.assertTrue(result["chunk_unavailable_during_wait"])
        self.assertTrue(result["free_delayed_until_wait_completion"])
        self.assertTrue(result["root_tracker_sibling_entries_preserved"])
        self.assertTrue(result["oom_merge_did_not_partially_copy_entries"])
        self.assertEqual(result["reserve_allocator_attempts"], 2)

    def test_harness_rejects_lock_held_wait_mutation(self):
        report = harness.run_harness(mutate_wait_under_root_bitlock=True)

        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertNotEqual(report["execution"]["exit_code"], 0)
        result = report["execution"]["checks"]
        self.assertEqual(result["wait_root_bitlock_depth"], 1)
        self.assertFalse(result["competitor_acquired_root_bitlock_during_wait"])


if __name__ == "__main__":
    unittest.main()
