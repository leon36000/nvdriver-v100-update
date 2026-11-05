# SPDX-License-Identifier: MIT
"""Host-execute deferred channel teardown and parent-mask behavior."""
import importlib
import unittest


harness = importlib.import_module("tools.run_deferred_free_channel_host_harness")


class DeferredFreeChannelHostHarnessTests(unittest.TestCase):
    def test_r580_and_r595_channel_helpers_flush_by_parent_before_destroy(self):
        report = harness.run_harness()

        self.assertEqual(report["qualification"]["level"], "tested-isolated")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertFalse(report["qualification"]["loaded_or_installed"])
        self.assertEqual(
            report["source_functions"]["r580_candidate"]["semantic_function_sha256"],
            report["source_functions"]["r595"]["semantic_function_sha256"],
        )
        self.assertEqual(
            report["source_functions"]["r595"]["semantic_function_sha256"],
            "25be510456dc61bd7c81d926e6ee92edf3c3987a0148c53ac669c6e8e4ac1e54",
        )
        self.assertEqual(len(report["cases"]), 6)
        expected = {
            "multi_channels_same_parent": ("NDRADD", 1, 1, 1, 3),
            "separate_parents_and_access_gate": ("NRADNRD", 2, 2, 1, 2),
            "gr_then_non_gr_same_parent": ("NRADD", 1, 1, 1, 2),
        }
        for case in report["cases"]:
            order, non_replayable, replayable, access, destroyed = expected[case["scenario"]]
            self.assertEqual(case["event_order"], order)
            self.assertEqual(case["non_replayable_flush_calls"], non_replayable)
            self.assertEqual(case["replayable_flush_calls"], replayable)
            self.assertEqual(case["access_counter_flush_calls"], access)
            self.assertEqual(case["destroy_calls"], destroyed)
            self.assertTrue(case["all_channels_destroyed_after_required_flushes"])

    def test_host_harness_discloses_stubbed_kernel_and_rm_behavior(self):
        report = harness.run_harness()

        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertEqual(report["execution"]["exit_code"], 0)
        self.assertIn("synthetic", report["scope"].lower())
        self.assertIn("not validate", report["scope"].lower())


if __name__ == "__main__":
    unittest.main()
