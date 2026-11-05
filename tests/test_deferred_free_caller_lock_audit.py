# SPDX-License-Identifier: MIT
"""Pin caller-side lock-release windows for deferred-free drains."""
import importlib
import importlib.util
import unittest


MODULE_NAME = "tools.audit_deferred_free_callers"
audit = (
    importlib.import_module(MODULE_NAME)
    if importlib.util.find_spec(MODULE_NAME) is not None
    else None
)


class DeferredFreeCallerLockAuditTests(unittest.TestCase):
    def test_all_pinned_callers_release_owner_locks_before_the_drain(self):
        self.assertIsNotNone(audit, "deferred-free caller lock audit is missing")
        report = audit.audit_callers()

        self.assertEqual(report["qualification"], "static-source-analysis-only")
        self.assertFalse(report["runtime_or_hardware_validated"])
        expected_counts = {
            "uvm_map_external.c": 2,
            "uvm_user_channel.c": 3,
            "uvm_va_range.c": 1,
            "uvm_va_range_device_p2p.c": 1,
            "uvm_va_space.c": 5,
            "uvm_va_space_mm.c": 1,
        }
        expected_last_releases = [
            "uvm_va_space_up_read",
            "uvm_va_space_up_read",
            "uvm_va_space_mm_or_current_release_unlock",
            "uvm_va_space_mm_or_current_release",
            "uvm_va_space_up_write",
            "uvm_va_space_up_write",
            "uvm_va_space_mm_or_current_release_unlock",
            "uvm_va_space_up_write",
            "uvm_up_read_mmap_lock",
            "uvm_up_read_mmap_lock",
            "uvm_va_space_up_write",
            "uvm_va_space_up_write",
            "uvm_spin_unlock",
        ]

        for release, source_name in (("r580", "r580_candidate"), ("r595", "r595")):
            source = report["sources"][source_name]
            self.assertEqual(source["call_site_count"], 13)
            self.assertEqual(source["per_file_counts"], expected_counts)
            self.assertEqual(len(source["call_sites"]), 13)
            self.assertEqual(
                [call["last_release"]["symbol"] for call in source["call_sites"]],
                expected_last_releases,
                release,
            )
            for call in source["call_sites"]:
                self.assertGreater(call["line_distance"], 0)
                self.assertLessEqual(call["line_distance"], 96)
                self.assertEqual(call["direct_lock_acquisitions_after_last_release"], [])

    def test_caller_sources_are_exact_and_report_scope_is_limited(self):
        self.assertIsNotNone(audit, "deferred-free caller lock audit is missing")
        report = audit.audit_callers()
        expected_hashes = {
            "r580_candidate": {
                "uvm_map_external.c": "1e72573e3ebc2c3117768ab0517e4b7e9acdb62af2368513a37500d6f13c11dd",
                "uvm_user_channel.c": "8fe5ce63871dbf7509c4ebbe7d0eeee8e0008693622479aed452d3b7c42015b6",
                "uvm_va_range.c": "10c80433314c9b38cc84f82ac156f2df9d0f5c9d3c73a9e64179047eb2148878",
                "uvm_va_range_device_p2p.c": "64090e24a6cd722769bf2023d3299485ce516eb03334adfbc459ebc0738c19b5",
                "uvm_va_space.c": "2309eb47fad1d4ec4f932f8eae58fc4802b2380a0a95be2e964a9897117b0418",
                "uvm_va_space_mm.c": "f9a8e86af533a538834fc55b04896703da16d76bb57d4f481532a85d287e905c",
            },
            "r595": {
                "uvm_map_external.c": "bd5284ad85f61bd7e368e056331c4e34efb9c169f99ba98ed3b539b6dd491e05",
                "uvm_user_channel.c": "9a6cec689eaf9c1edd1b7defa9ee7e74215382d802e7ab192b52caa1d0e93fe7",
                "uvm_va_range.c": "26c4c705ea797d0247740678b545d5b2394839eba61d79bef50182ffe6537787",
                "uvm_va_range_device_p2p.c": "8c3068201d9ef453f0f2efc365d6dd265cf0b5e465bb649913790c304c82503c",
                "uvm_va_space.c": "f332076b5d141b23cbe7acaccb48b2b07a0f8fe2e44832fd93551a4a8c345468",
                "uvm_va_space_mm.c": "3153e9d1e6444eaa7246dd2b2014583c90755fec77b48e38b77edd99bd83fc98",
            },
        }
        for source_name, files in expected_hashes.items():
            self.assertEqual(
                {name: item["sha256"] for name, item in report["sources"][source_name]["files"].items()},
                files,
                source_name,
            )

        self.assertIn("does not prove kernel lock state", report["scope"].lower())
        self.assertIn("not prove", report["scope"].lower())


if __name__ == "__main__":
    unittest.main()
