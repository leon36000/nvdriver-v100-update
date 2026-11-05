# SPDX-License-Identifier: MIT
"""Host-execute the exact deferred-free list walker and channel callback."""
import importlib
import importlib.util
import unittest


MODULE_NAME = "tools.run_deferred_free_object_list_host_harness"
harness = (
    importlib.import_module(MODULE_NAME)
    if importlib.util.find_spec(MODULE_NAME) is not None
    else None
)


class DeferredFreeObjectListHostHarnessTests(unittest.TestCase):
    def test_exact_list_walk_initializes_masks_dispatches_and_unlinks_in_order(self):
        self.assertIsNotNone(harness, "exact deferred-free list host runner is missing")
        report = harness.run_harness()

        self.assertEqual(report["qualification"]["level"], "tested-isolated")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertFalse(report["qualification"]["loaded_or_installed"])
        self.assertEqual(
            report["source_functions"]["r580_candidate"]["list_function_sha256"],
            "fe8bdb2d7e37de6133eed2013e9f0c2298ccbfb1c23d8c4050d32c1aad824fe0",
        )
        self.assertEqual(
            report["source_functions"]["r580_candidate"]["list_function_sha256"],
            report["source_functions"]["r595"]["list_function_sha256"],
        )

        cases = [case for case in report["cases"] if case["scenario"] == "mixed_all_types"]
        self.assertEqual(len(cases), 2)
        for case in cases:
            self.assertEqual(case["event_order"], "000lNDlVlRADlElPlNRAD")
            self.assertEqual(case["mask_zero_calls"], 3)
            self.assertEqual(case["non_replayable_flush_calls"], 2)
            self.assertEqual(case["replayable_flush_calls"], 2)
            self.assertEqual(case["access_counter_flush_calls"], 2)
            self.assertEqual(case["channel_destroy_calls"], 3)
            self.assertEqual(case["gpu_va_space_destroy_calls"], 1)
            self.assertEqual(case["external_allocation_free_calls"], 1)
            self.assertEqual(case["device_p2p_free_calls"], 1)
            self.assertTrue(case["list_empty_after_walk"])

    def test_empty_and_repeated_lists_have_independent_mask_state(self):
        self.assertIsNotNone(harness, "exact deferred-free list host runner is missing")
        report = harness.run_harness()

        cases = {(case["source"], case["scenario"]): case for case in report["cases"]}
        for source in ("r580_candidate", "r595"):
            empty = cases[(source, "empty_list")]
            self.assertEqual(empty["event_order"], "000")
            self.assertEqual(empty["mask_zero_calls"], 3)
            self.assertTrue(empty["list_empty_after_walk"])

            repeated = cases[(source, "two_lists_reset_masks")]
            self.assertEqual(repeated["event_order"], "000lND000lND")
            self.assertEqual(repeated["non_replayable_flush_calls"], 2)
            self.assertEqual(repeated["channel_destroy_calls"], 2)
            self.assertTrue(repeated["both_lists_empty_after_walk"])

    def test_report_explicitly_limits_the_host_execution_claim(self):
        self.assertIsNotNone(harness, "exact deferred-free list host runner is missing")
        report = harness.run_harness()

        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertEqual(report["execution"]["exit_code"], 0)
        self.assertIn("synthetic", report["scope"].lower())
        self.assertIn("does not validate", report["scope"].lower())


if __name__ == "__main__":
    unittest.main()
