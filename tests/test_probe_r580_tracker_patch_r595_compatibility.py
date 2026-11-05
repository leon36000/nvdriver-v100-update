# SPDX-License-Identifier: MIT
"""Keep the known R580-to-R595 UVM tracker-patch conflicts reproducible."""
import unittest

from tools import probe_r580_tracker_guard_r595_compatibility as probe


class R580TrackerPatchR595CompatibilityTests(unittest.TestCase):
    def test_pinned_r595_source_reports_only_the_known_conflicting_hunks(self):
        result = probe.probe()
        self.assertEqual(result["source"]["version"], "595.99.02")
        self.assertTrue(result["result"]["expected_r580_to_r595_conflict_observed"])
        self.assertEqual(
            result["result"]["rejected_hunks_by_file"],
            probe.EXPECTED_CONFLICTS,
        )
        self.assertNotRegex(result["result"]["output"], r"\bfuzz\b")


if __name__ == "__main__":
    unittest.main()
