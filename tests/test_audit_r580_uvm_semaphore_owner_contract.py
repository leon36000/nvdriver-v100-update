# SPDX-License-Identifier: MIT
"""Regression tests for isolated R580 UVM semaphore ownership and CPU waits."""
from pathlib import Path
import importlib.util
import shutil
import tempfile
import unittest

MODULE_NAME = "tools.audit_r580_uvm_semaphore_owner_contract"


class R580UvmSemaphoreOwnerContractTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.fail("the R580 UVM semaphore owner-contract audit is not implemented")
        from tools import audit_r580_uvm_semaphore_owner_contract as audit
        self.audit = audit

    def _copy_sources(self, root):
        root = Path(root)
        for name in self.audit.SOURCE_FILES:
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.audit.SOURCE_ROOT / name, destination)
        return root

    def test_pinned_source_proves_owner_cpu_wait_and_teardown_contract(self):
        report = self.audit.audit_sources(self.audit.SOURCE_ROOT)

        self.assertEqual(report["result"]["status"], "pass")
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertEqual(report["result"]["failed_checks"], [])
        self.assertEqual(
            set(report["result"]["checks"]),
            {
                "system_aperture",
                "isolated_page_cpu_and_owner_mapping",
                "owner_mapping_recorded_in_rm_state",
                "cross_gpu_mapping_skipped_and_teardown_guarded",
                "cpu_wait_observes_owner_tracking_semaphore",
                "free_unmaps_cpu_and_owner_gpu",
            },
        )

    def test_video_memory_semaphore_pool_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-aperture-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_gpu_semaphore.c"
            text = path.read_text(encoding="utf-8")
            old = "pool->aperture = UVM_APERTURE_SYS;"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "pool->aperture = UVM_APERTURE_VID;", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "fail")
        self.assertIn("system_aperture", result["failed_checks"])

    def test_missing_owner_gpu_va_mapping_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-owner-map-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_rm_mem.c"
            text = path.read_text(encoding="utf-8")
            old = "    rm_mem_set_gpu_va(rm_mem, gpu, gpu_va);"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "    /* owner mapping removed */", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "fail")
        self.assertIn("owner_mapping_recorded_in_rm_state", result["failed_checks"])

    def test_isolated_path_must_cpu_map_the_owner_allocation(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-cpu-map-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_gpu_semaphore.c"
            text = path.read_text(encoding="utf-8")
            old = "return uvm_rm_mem_alloc_and_map_cpu(gpu, memory_type, memory_size, 0, &page->memory);"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "return uvm_rm_mem_alloc(gpu, memory_type, memory_size, 0, &page->memory);", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "fail")
        self.assertIn("isolated_page_cpu_and_owner_mapping", result["failed_checks"])

    def test_cross_gpu_wait_must_poll_tracking_semaphore_completion(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-wait-chain-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_tracker.c"
            text = path.read_text(encoding="utf-8")
            old = "status = wait_for_entry_with_spin(entry, &spin);"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "status = NV_OK;", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "fail")
        self.assertIn("cpu_wait_observes_owner_tracking_semaphore", result["failed_checks"])

    def test_owner_teardown_must_release_cpu_and_gpu_mappings(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-free-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_rm_mem.c"
            text = path.read_text(encoding="utf-8")
            old = "    rm_mem_unmap_gpu(rm_mem, gpu_owner);"
            self.assertIn(old, text)
            path.write_text(text.replace(old, "    /* owner unmap removed */", 1), encoding="utf-8")
            result = self.audit.analyze_sources(root)

        self.assertEqual(result["status"], "fail")
        self.assertIn("free_unmaps_cpu_and_owner_gpu", result["failed_checks"])


if __name__ == "__main__":
    unittest.main()
