# SPDX-License-Identifier: MIT
"""Regression tests for lock-held tracker waits in the R580 isolation patch."""
from pathlib import Path
import importlib.util
import shutil
import tempfile
import unittest

MODULE_NAME = "tools.audit_r580_uvm_wait_lock_context"


class R580UvmWaitLockContextTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.fail("the R580 UVM wait lock-context audit is not implemented")
        from tools import audit_r580_uvm_wait_lock_context as audit
        self.audit = audit

    def _copy_sources(self, root):
        root = Path(root)
        for name in self.audit.SOURCE_FILES:
            shutil.copyfile(self.audit.SOURCE_ROOT / name, root / name)
        return root

    def test_pinned_source_reports_lock_held_cpu_wait_risk(self):
        report = self.audit.audit_sources(self.audit.SOURCE_ROOT)

        self.assertEqual(report["result"]["status"], "risk")
        self.assertEqual(
            report["result"]["checks"],
            {
                "generic_wrapper_waits_before_channel_reservation": True,
                "va_block_unmap_requires_block_lock": True,
                "locked_unmap_push_acquires_block_tracker": True,
                "wait_is_reached_by_cross_gpu_tracker": True,
                "pageable_zero_tracker_wait_precedes_copy_push": True,
                "pageable_zero_tracker_tracks_only_zero_push": True,
                "pageable_path_rejects_uvm_owned_vma": True,
            },
        )
        self.assertIn("not proof of a deadlock", report["interpretation"])
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])

    def test_missing_block_lock_assertion_removes_proven_lock_context(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-lock-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            text = path.read_text(encoding="utf-8")
            old = "    UVM_ASSERT(!uvm_va_block_is_dead(va_block));\n    uvm_assert_mutex_locked(&va_block->lock);"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "    UVM_ASSERT(!uvm_va_block_is_dead(va_block));", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["va_block_unmap_requires_block_lock"])

    def test_unmap_push_without_block_tracker_removes_wait_path(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-tracker-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            text = path.read_text(encoding="utf-8")
            old = (
                "    status = uvm_push_begin_acquire(gpu->channel_manager,\n"
                "                                    UVM_CHANNEL_TYPE_MEMOPS,\n"
                "                                    &block->tracker,\n"
                "                                    &push,\n"
                "                                    \"Unmapping pages in block"
            )
            self.assertIn(old, text)
            path.write_text(text.replace(old, old.replace("&block->tracker,", "NULL,"), 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["locked_unmap_push_acquires_block_tracker"])

    def test_removing_wrapper_wait_is_not_misreported_as_the_same_risk(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-wrapper-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_push.c"
            text = path.read_text(encoding="utf-8")
            old = "    status = wait_for_other_gpus_if_needed(tracker, manager->gpu);\n"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "    status = NV_OK;\n", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["generic_wrapper_waits_before_channel_reservation"])

    def test_pageable_zero_tracker_wait_is_audited_separately(self):
        report = self.audit.audit_sources(self.audit.SOURCE_ROOT)

        checks = report["result"]["checks"]
        self.assertTrue(checks["pageable_zero_tracker_wait_precedes_copy_push"])
        self.assertTrue(checks["pageable_zero_tracker_tracks_only_zero_push"])
        self.assertTrue(checks["pageable_path_rejects_uvm_owned_vma"])
        self.assertIn("pageable-migration wait", report["interpretation"])

    def test_removing_pageable_cpu_wait_is_not_misreported_as_complete(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-pageable-wait-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_migrate_pageable.c"
            text = path.read_text(encoding="utf-8")
            old = "status = uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu);"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "status = NV_OK;", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["pageable_zero_tracker_wait_precedes_copy_push"])

    def test_removing_pageable_uvm_vma_exclusion_invalidates_lock_classification(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-pageable-vma-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_migrate_pageable.c"
            text = path.read_text(encoding="utf-8")
            old = "    if (uvm_file_is_nvidia_uvm_va_space(vma->vm_file))\n        return NV_ERR_INVALID_ADDRESS;"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "    // mutation: removed UVM VMA exclusion", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["pageable_path_rejects_uvm_owned_vma"])


if __name__ == "__main__":
    unittest.main()
