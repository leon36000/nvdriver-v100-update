# SPDX-License-Identifier: MIT
"""Host-execute the pinned R580/R595 non-replayable flush helper bodies."""
import importlib
import unittest


harness = importlib.import_module("tools.run_nonreplayable_flush_host_harness")


class NonReplayableFlushHostHarnessTests(unittest.TestCase):
    def test_candidate_and_r595_flush_helpers_order_lock_schedule_unlock_and_queue(self):
        report = harness.run_harness()

        self.assertEqual(report["qualification"]["level"], "tested-isolated")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertFalse(report["qualification"]["loaded_or_installed"])
        self.assertEqual(
            report["source_functions"]["r580_candidate"]["normalized_function_sha256"],
            report["source_functions"]["r595"]["normalized_function_sha256"],
        )
        self.assertEqual(
            report["source_functions"]["r595"]["normalized_function_sha256"],
            "d7f5c4b2fe33745ec7a6ce8c95612921b6480a32f5733158c30a646b1581a778",
        )
        self.assertEqual(len(report["cases"]), 4)
        for case in report["cases"]:
            self.assertEqual(case["event_order"], "LSUQ")
            self.assertTrue(case["scheduler_saw_interrupt_lock"])
            self.assertTrue(case["queue_flush_saw_interrupt_lock_released"])
            self.assertEqual(case["scheduler_calls"], 1)
            self.assertEqual(case["queue_flush_calls"], 1)

    def test_harness_labels_synthetic_dependencies_and_records_compilation(self):
        report = harness.run_harness()

        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertEqual(report["execution"]["exit_code"], 0)
        self.assertIn("synthetic", report["scope"].lower())
        self.assertNotIn("runtime or hardware validated", report["scope"].lower())


if __name__ == "__main__":
    unittest.main()
