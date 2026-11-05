# SPDX-License-Identifier: MIT
"""Regression tests for PMM tracker waits under an R580 VA-block lock."""
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import audit_r580_uvm_pmm_wait_context as audit


class R580UvmPmmWaitContextTests(unittest.TestCase):
    def _copy_sources(self, root):
        root = Path(root)
        for name in audit.SOURCE_FILES:
            shutil.copyfile(audit.SOURCE_ROOT / name, root / name)
        return root

    def test_pinned_source_reports_conditional_route_and_isolated_lock_mitigation(self):
        report = audit.audit_sources(audit.SOURCE_ROOT)

        self.assertEqual(report["result"]["status"], "conditionally_mitigated")
        self.assertEqual(
            report["result"]["checks"],
            {
                "pmm_alloc_waits_for_foreign_gpu_tracker": True,
                "pmm_wait_follows_root_tracker_collection": True,
                "block_population_asserts_va_block_lock": True,
                "isolated_no_evict_alloc_releases_block_lock": True,
                "isolated_success_requeues_chunk_and_restarts": True,
                "default_no_evict_alloc_is_unchanged": True,
                "eviction_retry_releases_lock_before_pmm_alloc": True,
                "lock_retry_macro_repeats_more_processing": True,
                "migration_make_resident_uses_lock_retry": True,
                "hmm_gpu_fault_preallocation_precedes_migrate_vma_setup": True,
                "hmm_migration_preallocation_precedes_migrate_vma_setup": True,
                "isolated_hmm_gpu_fault_fails_closed_after_cpu_fault_path": True,
                "isolated_hmm_gpu_migration_fails_closed_after_sysmem_fallback": True,
                "hmm_gpu_fault_retry_is_wrapped_by_va_block_retry": True,
                "hmm_migration_retry_is_wrapped_by_va_block_retry": True,
                "fault_service_retry_paths_are_va_block_wrapped": True,
                "tracker_wait_polls_channel_tracking_semaphore": True,
                "channel_completion_refreshes_from_cpu_mapped_payload": True,
                "spin_loop_schedules_for_rm_uvm_progress": True,
                "tracker_wait_timeout_is_warning_only": True,
                "wait_uses_cpu_spin_entry_helper": True,
                "migration_selects_accessed_by_processors": True,
                "multiple_gpu_maps_accumulate_in_local_output_tracker": True,
                "gpu_map_acquires_global_tracker_but_appends_to_output": True,
                "migration_merges_local_tracker_into_va_block_tracker": True,
                "pmm_free_imports_va_block_tracker": True,
                "tracking_semaphore_uses_channel_gpu_owned_pool": True,
                "isolated_owner_semaphore_page_is_cpu_mapped_and_cross_gpu_mapping_is_skipped": True,
                "channel_tracking_semaphore_released_after_progress_and_rm_channel": True,
                "gpu_teardown_removes_tracker_references_and_syncs_before_semaphore_pool_free": True,
            },
        )
        self.assertIn("not proof of a deadlock", report["result"]["interpretation"].lower())
        self.assertIn("conditional route", report["result"]["interpretation"].lower())
        self.assertIn("unlocked in isolated mode", report["result"]["interpretation"].lower())
        self.assertIn("provider-affine memory duplication", report["result"]["interpretation"].lower())
        self.assertIn("deliberately disables those gpu-resident hmm paths", report["result"]["interpretation"].lower())
        self.assertNotIn("blocks second-provider uvm registration", report["result"]["interpretation"].lower())
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])

    def test_tracking_semaphore_allocated_from_other_gpu_pool_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-owner-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_channel.c"
            source = path.read_text(encoding="utf-8")
            old = "uvm_gpu_tracking_semaphore_alloc(semaphore_pool, &channel->tracking_sem)"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "uvm_gpu_tracking_semaphore_alloc(other_pool, &channel->tracking_sem)", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["tracking_semaphore_uses_channel_gpu_owned_pool"])

    def test_hmm_gpu_fault_preallocates_before_migrate_vma_page_locking(self):
        report = audit.audit_sources(audit.SOURCE_ROOT)

        self.assertTrue(report["result"]["checks"]["hmm_gpu_fault_preallocation_precedes_migrate_vma_setup"])
        self.assertTrue(report["result"]["checks"]["hmm_gpu_fault_retry_is_wrapped_by_va_block_retry"])

    def test_hmm_migration_preallocates_before_migrate_vma_page_locking(self):
        report = audit.audit_sources(audit.SOURCE_ROOT)

        self.assertTrue(report["result"]["checks"]["hmm_migration_preallocation_precedes_migrate_vma_setup"])
        self.assertTrue(report["result"]["checks"]["hmm_migration_retry_is_wrapped_by_va_block_retry"])

    def test_removing_isolated_hmm_gpu_fault_guard_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-hmm-guard-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_hmm.c"
            source = path.read_text(encoding="utf-8")
            guard = (
                "    if (uvm_push_isolated_gpu_execution_enabled())\n"
                "        return NV_ERR_NOT_SUPPORTED;\n"
            )
            self.assertIn(guard, source)
            path.write_text(source.replace(guard, "", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["isolated_hmm_gpu_fault_fails_closed_after_cpu_fault_path"])

    def test_removing_isolated_hmm_gpu_migration_guard_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-hmm-guard-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_hmm.c"
            source = path.read_text(encoding="utf-8")
            guard = (
                "    if (uvm_push_isolated_gpu_execution_enabled() && UVM_ID_IS_GPU(dest_id))\n"
                "        return NV_ERR_NOT_SUPPORTED;\n"
            )
            self.assertIn(guard, source)
            path.write_text(source.replace(guard, "", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(
            result["checks"]["isolated_hmm_gpu_migration_fails_closed_after_sysmem_fallback"]
        )

    def test_moving_isolated_hmm_gpu_fault_guard_after_population_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-hmm-guard-order-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_hmm.c"
            source = path.read_text(encoding="utf-8")
            guard = (
                "    if (uvm_push_isolated_gpu_execution_enabled())\n"
                "        return NV_ERR_NOT_SUPPORTED;\n"
            )
            self.assertIn(guard, source)
            source = source.replace(guard, "", 1)
            allocation_end = (
                "                                             new_residency_mask);\n"
            )
            self.assertIn(allocation_end + "    if (status != NV_OK)", source)
            source = source.replace(
                allocation_end + "    if (status != NV_OK)",
                allocation_end + guard + "    if (status != NV_OK)",
                1,
            )
            path.write_text(source, encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["isolated_hmm_gpu_fault_fails_closed_after_cpu_fault_path"])

    def test_moving_hmm_gpu_preallocation_after_page_locking_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-hmm-order-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_hmm.c"
            source = path.read_text(encoding="utf-8")
            old = "    status = uvm_va_block_populate_pages_gpu(va_block,\n"
            self.assertIn(old, source)
            # Mutation models moving the page allocation to after migrate_vma_setup_locked().
            source = source.replace(
                old,
                "    ret = migrate_vma_setup_locked(args, va_block);\n" + old,
                1,
            )
            path.write_text(source, encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["hmm_gpu_fault_preallocation_precedes_migrate_vma_setup"])

    def test_removing_replayable_fault_retry_wrapper_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-hmm-retry-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_gpu_replayable_faults.c"
            source = path.read_text(encoding="utf-8")
            old = "status = UVM_VA_BLOCK_RETRY_LOCKED(va_block, &va_block_retry,"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "status = (", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["fault_service_retry_paths_are_va_block_wrapped"])

    def test_removing_hmm_migration_retry_wrapper_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-hmm-migrate-retry-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_hmm.c"
            source = path.read_text(encoding="utf-8")
            old = "status = UVM_VA_BLOCK_RETRY_LOCKED(va_block,"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "status = (", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["hmm_migration_retry_is_wrapped_by_va_block_retry"])

    def test_isolated_mode_must_skip_cross_gpu_semaphore_pool_mapping(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-map-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_gpu.c"
            source = path.read_text(encoding="utf-8")
            old = "if (!uvm_push_allow_dependencies_across_gpus())\n        return NV_OK;"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "if (false)\n        return NV_OK;", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["isolated_owner_semaphore_page_is_cpu_mapped_and_cross_gpu_mapping_is_skipped"])

    def test_channel_tracking_semaphore_cannot_be_freed_before_progress_and_rm_channel(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-channel-free-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_channel.c"
            source = path.read_text(encoding="utf-8")
            old = "channel_update_progress_all(channel, UVM_CHANNEL_UPDATE_MODE_FORCE_ALL);"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "/* progress update removed */", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["channel_tracking_semaphore_released_after_progress_and_rm_channel"])

    def test_gpu_teardown_must_keep_sync_before_channel_and_semaphore_pool_destruction(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-gpu-teardown-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_gpu.c"
            source = path.read_text(encoding="utf-8")
            old = "uvm_pmm_gpu_sync(&gpu->pmm);"
            start = source.index("static void deinit_gpu(")
            end = source.index("\n}", start)
            function = source[start:end]
            self.assertIn(old, function)
            function = function.replace(old, "/* PMM sync removed */", 1)
            path.write_text(source[:start] + function + source[end:], encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["gpu_teardown_removes_tracker_references_and_syncs_before_semaphore_pool_free"])

    def test_isolated_allocation_without_unlock_invalidates_mitigation(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-unlock-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            source = path.read_text(encoding="utf-8")
            function_start = source.index("static NV_STATUS block_alloc_gpu_chunk(")
            function_end = source.index("\n}", function_start)
            function = source[function_start:function_end]
            old = "uvm_mutex_unlock(&block->lock);"
            self.assertIn(old, function)
            function = function.replace(old, "/* lock release removed */", 1)
            path.write_text(source[:function_start] + function + source[function_end:], encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["isolated_no_evict_alloc_releases_block_lock"])

    def test_isolated_success_without_retry_requeue_invalidates_mitigation(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-requeue-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            source = path.read_text(encoding="utf-8")
            old = "block_retry_add_free_chunk(retry, gpu_chunk);"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "/* retry requeue removed */", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["isolated_success_requeues_chunk_and_restarts"])

    def test_removing_eviction_unlock_is_detected_independently_of_isolated_unlock(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-eviction-unlock-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            source = path.read_text(encoding="utf-8")
            function_start = source.index("static NV_STATUS block_alloc_gpu_chunk(")
            function_end = source.index("\n}", function_start)
            function = source[function_start:function_end]
            eviction = function.index("UVM_PMM_ALLOC_FLAGS_EVICT")
            unlock = function.rfind("uvm_mutex_unlock(&block->lock)", 0, eviction)
            self.assertGreaterEqual(unlock, 0)
            marker = "/* eviction-path unlock removed */"
            function = function[:unlock] + marker + function[unlock + len("uvm_mutex_unlock(&block->lock);"):]
            path.write_text(source[:function_start] + function + source[function_end:], encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["eviction_retry_releases_lock_before_pmm_alloc"])

    def test_removing_retry_status_from_lock_macro_invalidates_restart_proof(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-retry-macro-mutation-") as temporary:
            root = self._copy_sources(temporary)
            header = audit.SOURCE_ROOT / "uvm_va_block.h"
            target = root / "uvm_va_block.h"
            shutil.copyfile(header, target)
            source = target.read_text(encoding="utf-8")
            old = "} while (__status == NV_ERR_MORE_PROCESSING_REQUIRED);"
            self.assertIn(old, source)
            target.write_text(source.replace(old, "} while (__status == NV_OK);", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["lock_retry_macro_repeats_more_processing"])

    def test_removing_scheduler_yield_invalidates_tracker_progress_proof(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-schedule-mutation-") as temporary:
            root = self._copy_sources(temporary)
            source_path = audit.SOURCE_ROOT / "uvm_common.c"
            target = root / "uvm_common.c"
            shutil.copyfile(source_path, target)
            source = target.read_text(encoding="utf-8")
            start = source.index("NV_STATUS uvm_spin_loop(")
            end = source.index("\n}", start)
            function = source[start:end]
            self.assertIn("schedule();", function)
            function = function.replace("schedule();", "cpu_relax();", 1)
            target.write_text(source[:start] + function + source[end:], encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["spin_loop_schedules_for_rm_uvm_progress"])

    def test_removing_cpu_payload_refresh_invalidates_completion_proof(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-payload-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_gpu_semaphore.c"
            shutil.copyfile(audit.SOURCE_ROOT / "uvm_gpu_semaphore.c", path)
            source = path.read_text(encoding="utf-8")
            old = "new_sem_value = uvm_gpu_semaphore_get_payload(&tracking_semaphore->semaphore);"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "new_sem_value = 0;", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["channel_completion_refreshes_from_cpu_mapped_payload"])

    def test_missing_lock_assertion_removes_proven_lock_context(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-lock-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            source = path.read_text(encoding="utf-8")
            old = "    uvm_assert_mutex_locked(&block->lock);\n    UVM_ASSERT(chunk_index < block_num_gpu_chunks(block, gpu));"
            self.assertIn(old, source)
            path.write_text(source.replace(old, old.splitlines()[1], 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["block_population_asserts_va_block_lock"])

    def test_removing_pmm_foreign_tracker_wait_invalidates_risk_classification(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-wait-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_pmm_gpu.c"
            source = path.read_text(encoding="utf-8")
            old = "status = uvm_tracker_wait_for_other_gpus(&local_tracker, gpu);"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "status = NV_OK;", 1), encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["pmm_alloc_waits_for_foreign_gpu_tracker"])

    def test_separating_gpu_map_output_from_shared_tracker_removes_reachability_chain(self):
        with tempfile.TemporaryDirectory(prefix="r580-pmm-merge-mutation-") as temporary:
            root = self._copy_sources(temporary)
            path = root / "uvm_va_block.c"
            source = path.read_text(encoding="utf-8")
            old = "return uvm_tracker_add_push_safe(out_tracker, &push);"
            start = source.index("static NV_STATUS block_map_gpu_to(")
            end = source.index("\n}", start)
            function = source[start:end]
            self.assertIn(old, function)
            mutated = function.replace(old, "return NV_OK;", 1)
            path.write_text(source[:start] + mutated + source[end:], encoding="utf-8")
            result = audit.analyze_sources(root)

        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["checks"]["gpu_map_acquires_global_tracker_but_appends_to_output"])


if __name__ == "__main__":
    unittest.main()
