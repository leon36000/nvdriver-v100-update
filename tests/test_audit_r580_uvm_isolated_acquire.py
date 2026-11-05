# SPDX-License-Identifier: MIT
"""Regression tests for the isolated-UVM cross-GPU tracker-acquire census."""
from pathlib import Path
import importlib
import importlib.util
import shutil
import tempfile
import unittest

MODULE_NAME = "tools.audit_r580_uvm_isolated_acquire"


class R580UvmIsolatedAcquireAuditTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.fail("the isolated-UVM tracker-acquire audit is not implemented")
        self.audit = importlib.import_module(MODULE_NAME)

    def test_pinned_patch_accounts_for_every_direct_tracker_acquire(self):
        report = self.audit.audit_sources(self.audit.SOURCE_ROOT)

        self.assertEqual(report["result"]["status"], "pass")
        sites = report["result"]["direct_acquire_sites"]
        self.assertEqual(len(sites), 3)
        self.assertEqual(
            {(site["file"], site["function"], site["protection"]) for site in sites},
            {
                (
                    "uvm_channel_test.c",
                    "stress_test_all_gpus_in_va",
                    "same_gpu_or_cross_gpu_dependencies_enabled",
                ),
                (
                    "uvm_migrate_pageable.c",
                    "uvm_migrate_vma_copy_pages_from",
                    "cpu_wait_for_other_gpus_before_acquire",
                ),
                (
                    "uvm_push.c",
                    "push_begin_acquire_with_info",
                    "wrappers_wait_or_pass_a_null_tracker",
                ),
            },
        )
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])

    def test_new_direct_acquire_site_is_reported_as_unreviewed(self):
        source_root = Path(self.audit.SOURCE_ROOT)
        with tempfile.TemporaryDirectory(prefix="r580-uvm-acquire-mutation-") as temporary:
            mutated = Path(temporary)
            for name in ("uvm_push.c", "uvm_migrate_pageable.c", "uvm_channel_test.c"):
                shutil.copyfile(source_root / name, mutated / name)
            (mutated / "uvm_extra.c").write_text(
                "void new_path(uvm_push_t *push, uvm_tracker_t *tracker) {\n"
                "    uvm_push_acquire_tracker(push, tracker);\n"
                "}\n",
                encoding="utf-8",
            )

            result = self.audit.analyze_call_sites(mutated)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(
            result["unreviewed_direct_acquire_sites"],
            [{"file": "uvm_extra.c", "function": None}],
        )

    def test_missing_migration_cpu_wait_is_rejected(self):
        source_root = Path(self.audit.SOURCE_ROOT)
        with tempfile.TemporaryDirectory(prefix="r580-uvm-acquire-wait-mutation-") as temporary:
            mutated = Path(temporary)
            for name in ("uvm_push.c", "uvm_migrate_pageable.c", "uvm_channel_test.c"):
                shutil.copyfile(source_root / name, mutated / name)
            migration = mutated / "uvm_migrate_pageable.c"
            text = migration.read_text(encoding="utf-8")
            wait = "    // No cross-GPU semaphore mapping exists in isolated mode. Wait on the CPU.\n"
            start = text.index(wait)
            end = text.index("    status = migrate_vma_copy_begin_push", start)
            text = text[:start] + text[end:]
            migration.write_text(text, encoding="utf-8")

            result = self.audit.analyze_call_sites(mutated)

        self.assertEqual(result["status"], "fail")
        self.assertIn(
            "uvm_migrate_pageable.c:cpu-wait-before-acquire",
            result["failed_protection_checks"],
        )

    def test_generic_acquire_wrapper_without_host_wait_is_rejected(self):
        source_root = Path(self.audit.SOURCE_ROOT)
        with tempfile.TemporaryDirectory(prefix="r580-uvm-wrapper-wait-mutation-") as temporary:
            mutated = Path(temporary)
            for name in ("uvm_push.c", "uvm_migrate_pageable.c", "uvm_channel_test.c"):
                shutil.copyfile(source_root / name, mutated / name)
            push = mutated / "uvm_push.c"
            text = push.read_text(encoding="utf-8")
            wait = "    status = wait_for_other_gpus_if_needed(tracker, manager->gpu);\n"
            self.assertIn(wait, text)
            push.write_text(text.replace(wait, "", 1), encoding="utf-8")

            result = self.audit.analyze_call_sites(mutated)

        self.assertEqual(result["status"], "fail")
        self.assertIn(
            "uvm_push.c:__uvm_push_begin_acquire_with_info",
            result["failed_protection_checks"],
        )

    def test_channel_stress_acquire_without_same_gpu_guard_is_rejected(self):
        source_root = Path(self.audit.SOURCE_ROOT)
        with tempfile.TemporaryDirectory(prefix="r580-uvm-channel-guard-mutation-") as temporary:
            mutated = Path(temporary)
            for name in ("uvm_push.c", "uvm_migrate_pageable.c", "uvm_channel_test.c"):
                shutil.copyfile(source_root / name, mutated / name)
            channel_test = mutated / "uvm_channel_test.c"
            text = channel_test.read_text(encoding="utf-8")
            guard = "if ((random_stream->push.gpu == gpu) || uvm_push_allow_dependencies_across_gpus()) {"
            self.assertIn(guard, text)
            channel_test.write_text(text.replace(guard, "if (true) {", 1), encoding="utf-8")

            result = self.audit.analyze_call_sites(mutated)

        self.assertEqual(result["status"], "fail")
        self.assertIn(
            "uvm_channel_test.c:same-gpu-or-enabled-guard",
            result["failed_protection_checks"],
        )


if __name__ == "__main__":
    unittest.main()
