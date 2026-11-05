# SPDX-License-Identifier: MIT
"""Mutation tests for isolated R580 UVM registration and cleanup contracts."""
import unittest

from tools import audit_r580_uvm_isolated_init_cleanup as audit


class R580UvmIsolatedInitCleanupTests(unittest.TestCase):
    def _functions(self):
        return audit.extract_functions(audit.SOURCE_ROOT)

    def test_pinned_build_avoids_cross_provider_semaphore_mapping_and_unwinds_failures(self):
        report = audit.audit_sources()
        checks = report["result"]["checks"]

        self.assertEqual(report["result"]["status"], "source_contracts_passed")
        self.assertEqual(len(checks), 17)
        self.assertTrue(all(checks.values()))
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertFalse(report["qualification"]["module_loaded_or_installed"])
        self.assertIn("do not prove runtime GPU initialization", report["result"]["interpretation"])

    def test_mapping_gate_moved_after_loop_is_detected(self):
        functions = self._functions()
        source = functions["init_semaphore_pools"]
        old = "if (!uvm_push_allow_dependencies_across_gpus()) return NV_OK; for_each_gpu(other_gpu)"
        self.assertIn(old, source)
        functions["init_semaphore_pools"] = source.replace(
            old,
            "for_each_gpu(other_gpu) if (!uvm_push_allow_dependencies_across_gpus()) return NV_OK;",
            1,
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(
            report["checks"]["isolated_registration_returns_before_foreign_semaphore_mapping"]
        )

    def test_gpu_publication_moved_before_init_failure_gate_is_detected(self):
        functions = self._functions()
        source = functions["add_gpu"]
        old = "status = init_gpu(gpu, gpu_info); if (status != NV_OK) goto error;"
        self.assertIn(old, source)
        functions["add_gpu"] = source.replace(
            old,
            "__set_bit(uvm_id_sub_processor_index(gpu->id), parent_gpu->valid_gpus); " + old,
            1,
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["failed_gpu_init_enters_remove_before_publication"])

    def test_missing_remove_to_deinit_edge_is_detected(self):
        functions = self._functions()
        source = functions["remove_gpu"]
        self.assertIn("deinit_gpu(gpu);", source)
        functions["remove_gpu"] = source.replace("deinit_gpu(gpu);", "", 1)

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["remove_gpu_deinitializes_before_freeing_gpu"])

    def test_missing_null_channel_manager_guard_is_detected(self):
        functions = self._functions()
        source = functions["channel_manager_destroy"]
        self.assertIn("if (channel_manager == NULL) return;", source)
        functions["channel_manager_destroy"] = source.replace(
            "if (channel_manager == NULL) return;", "", 1
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(
            report["checks"]["partial_init_channel_manager_cleanup_is_null_safe"]
        )

    def test_missing_mapping_state_guard_in_rm_unmap_is_detected(self):
        functions = self._functions()
        source = functions["rm_mem_unmap_gpu"]
        self.assertIn("if (!uvm_rm_mem_mapped_on_gpu(rm_mem, gpu)) return;", source)
        functions["rm_mem_unmap_gpu"] = source.replace(
            "if (!uvm_rm_mem_mapped_on_gpu(rm_mem, gpu)) return;", "", 1
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(
            report["checks"]["semaphore_rollback_unmaps_existing_pool_pages_before_local_destroy"]
        )

    def test_channel_copy_engine_query_without_device_owner_dispatch_is_detected(self):
        functions = self._functions()
        source = functions["bridge_query_copy_engines"]
        self.assertIn("hybrid580_uvm_device_call(device, caps", source)
        functions["bridge_query_copy_engines"] = source.replace(
            "hybrid580_uvm_device_call(device, caps", "hybrid580_legacy_QueryCopyEnginesCaps(device, caps", 1
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["copy_engine_caps_query_routes_by_registered_gpu_owner"])

    def test_tsg_and_channel_routes_are_required_for_channel_manager_init(self):
        functions = self._functions()
        functions["bridge_tsg_allocate"] = functions["bridge_tsg_allocate"].replace(
            "hybrid580_uvm_address_space_route_call(", "hybrid580_legacy_tsg_allocate(", 1
        )
        functions["bridge_channel_allocate"] = functions["bridge_channel_allocate"].replace(
            "params.provider", "unowned.provider", 1
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["tsg_create_routes_by_gpu_address_space_owner"])
        self.assertFalse(report["checks"]["channel_create_routes_by_tsg_owner_and_same_provider"])

    def test_address_space_owner_route_is_required_for_page_directory_setup(self):
        functions = self._functions()
        source = functions["bridge_set_page_directory"]
        self.assertIn("hybrid580_uvm_address_space_call(", source)
        functions["bridge_set_page_directory"] = source.replace(
            "hybrid580_uvm_address_space_call(", "hybrid580_legacy_set_page_directory(", 1
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["page_directory_programming_routes_by_gpu_address_space_owner"])

    def test_unsupported_paging_channel_is_gated_to_sriov_heavy_proxy_pool(self):
        functions = self._functions()
        source = functions["channel_manager_create_pools"]
        guard = "if (uvm_parent_gpu_needs_proxy_channel_pool(manager->gpu->parent))"
        self.assertIn(guard, source)
        functions["channel_manager_create_pools"] = source.replace(guard, "if (true)", 1)

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["unsupported_proxy_channel_api_is_limited_to_sriov_heavy_mode"])

    def test_flat_mapping_route_must_use_this_gpus_page_tree(self):
        functions = self._functions()
        source = functions["create_identity_mapping"]
        self.assertIn("uvm_page_table_range_vec_create(&gpu->address_space_tree", source)
        functions["create_identity_mapping"] = source.replace(
            "uvm_page_table_range_vec_create(&gpu->address_space_tree",
            "uvm_page_table_range_vec_create(NULL", 1
        )

        report = audit.analyze_functions(functions)

        self.assertFalse(report["checks"]["flat_mapping_setup_uses_the_gpu_local_page_tree_path"])


if __name__ == "__main__":
    unittest.main()
