# SPDX-License-Identifier: MIT
"""Compile the exact PFN guard source under both conftest branches."""
import unittest

from tools.r595_pfn_backing_host_harness import run_variants


class R595PfnBackingHostHarnessTests(unittest.TestCase):
    def test_backed_pfns_are_rejected_before_publication_in_both_branches(self):
        results = run_variants()
        self.assertEqual([item["variant"] for item in results],
                         ["pfn_is_map_memory", "pfn_valid"])
        for item in results:
            with self.subTest(variant=item["variant"]):
                self.assertEqual(item["exit_code"], 0, item["output"])
                self.assertIn("guard_rejects_backed_without_publish=pass",
                              item["output"])
                self.assertIn("allows_unbacked_contiguous_io=pass", item["output"])


if __name__ == "__main__":
    unittest.main()
