# SPDX-License-Identifier: MIT
"""Pinned source tests for R595 UVM paging-channel callback reachability."""
from __future__ import annotations

import unittest

from tools import audit_r595_uvm_proxy_paging_gate as audit


class R595UvmProxyPagingGateTests(unittest.TestCase):
    def test_pinned_r595_releases_gate_proxy_callbacks_to_sriov_heavy(self):
        report = audit.audit_sources()

        self.assertEqual(report["result"]["status"], "source_contracts_passed")
        self.assertTrue(all(report["result"]["checks"].values()))
        self.assertEqual(report["source_branches"]["595.99.02"]["files"],
                         report["source_branches"]["595.112.07"]["files"])
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertFalse(report["qualification"]["guest_virtualization_mode_verified"])

    def test_sriov_heavy_predicate_drift_is_detected(self):
        functions, bridge = audit.load_default_functions()
        functions["proxy_pool_predicate"] = functions["proxy_pool_predicate"].replace(
            "uvm_parent_gpu_is_virt_mode_sriov_heavy",
            "uvm_parent_gpu_is_virt_mode_sriov_standard",
        )

        report = audit.analyze_functions(functions, bridge)

        self.assertFalse(report["checks"]["proxy_pool_requires_sriov_heavy"])

    def test_proxy_pool_creation_without_heavy_mode_gate_is_detected(self):
        functions, bridge = audit.load_default_functions()
        functions["create_pools"] = functions["create_pools"].replace(
            "if (uvm_parent_gpu_needs_proxy_channel_pool(manager->gpu->parent)) {",
            "if (true) {",
            1,
        )

        report = audit.analyze_functions(functions, bridge)

        self.assertFalse(report["checks"]["proxy_pool_creation_is_heavy_mode_gated"])

    def test_regular_channel_path_must_not_allocate_a_paging_channel(self):
        functions, bridge = audit.load_default_functions()
        functions["channel_create"] = functions["channel_create"].replace(
            "if (uvm_channel_is_proxy(channel)) status = proxy_channel_create(channel, pool->engine_index); else status = internal_channel_create(channel);",
            "status = proxy_channel_create(channel, pool->engine_index);",
            1,
        )

        report = audit.analyze_functions(functions, bridge)

        self.assertFalse(report["checks"]["proxy_allocator_is_selected_only_for_proxy_channels"])

    def test_bridge_cannot_publish_a_native_paging_handle(self):
        functions, bridge = audit.load_default_functions()
        bridge["paging_allocate"] = bridge["paging_allocate"].replace(
            "return NV_ERR_NOT_SUPPORTED;", "return NV_OK;", 1
        )

        report = audit.analyze_functions(functions, bridge)

        self.assertFalse(report["checks"]["paging_allocate_remains_fail_closed"])

    def test_proxy_va_map_must_return_before_callback_outside_heavy_mode(self):
        functions, bridge = audit.load_default_functions()
        functions["map_proxy"] = functions["map_proxy"].replace(
            "if (!uvm_parent_gpu_needs_proxy_channel_pool(gpu->parent)) return NV_OK;",
            "if (false) return NV_OK;",
            1,
        )

        report = audit.analyze_functions(functions, bridge)

        self.assertFalse(report["checks"]["proxy_va_mapping_is_heavy_mode_gated"])

    def test_proxy_va_unmap_must_require_a_prior_successful_map(self):
        functions, bridge = audit.load_default_functions()
        functions["unmap_proxy"] = functions["unmap_proxy"].replace(
            "if (!uvm_rm_mem_mapped_on_gpu_proxy(rm_mem, gpu)) return;",
            "if (false) return;",
            1,
        )

        report = audit.analyze_functions(functions, bridge)

        self.assertFalse(report["checks"]["proxy_va_unmap_requires_prior_proxy_mapping"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
