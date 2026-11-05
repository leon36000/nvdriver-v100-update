# SPDX-License-Identifier: MIT
"""Tests for source-backed comparison of hybrid UVM ownership designs."""
from pathlib import Path
import importlib
import importlib.util
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_NAME = "tools.audit_uvm_owner_isolation_architecture"


class UvmOwnerIsolationArchitectureTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.fail("the pinned UVM-owner architecture audit is not implemented")
        self.audit = importlib.import_module(MODULE_NAME)

    def test_pinned_sources_select_the_smallest_same_process_kernel_experiment(self):
        report = self.audit.audit_sources(
            self.audit.SOURCE_ROOT,
            self.audit.BRIDGE_PATH,
        )

        self.assertEqual(report["single_uvm"]["module_target"], "nvidia-uvm.ko")
        self.assertEqual(report["single_uvm"]["device_name"], "nvidia-uvm")
        self.assertEqual(report["single_uvm"]["global_gpu_table"], "parent_gpus")
        self.assertTrue(report["single_uvm"]["file_identity_uses_fops_pointer"])
        self.assertEqual(
            report["bridge_registration"]["multi_uvm_registration"],
            "rejected_while_registration_active",
        )
        self.assertEqual(
            report["architecture_comparison"]["first_experiment"],
            "host_synchronized_isolated_gpu_execution",
        )
        self.assertFalse(
            report["architecture_comparison"]["host_synchronized_isolated_gpu_execution"][
                "runtime_or_hardware_validated"
            ]
        )
        self.assertFalse(
            report["architecture_comparison"]["shared_system_memory_mapping"][
                "cross_provider_rm_support_proven"
            ]
        )
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])

    def test_r580_mapping_surface_distinguishes_candidate_va_duplication_from_host_page_import(self):
        report = self.audit.audit_sources(
            self.audit.SOURCE_ROOT,
            self.audit.BRIDGE_PATH,
        )
        surface = report["system_memory_mapping_surface"]
        self.assertEqual(surface["uvm_interface_prototype_count"], 76)
        self.assertEqual(surface["typed_os_page_import_prototypes"], [])
        self.assertFalse(surface["typed_os_page_import_surface_declared"])
        self.assertIn("does not exclude opaque/private RM paths", surface["typed_import_scope_note"])
        self.assertEqual(
            surface["system_memory_allocation"]["api"],
            "nvUvmInterfaceMemoryAllocSys",
        )
        self.assertTrue(
            surface["cross_va_space_system_mapping"]["candidate_for_shared_semaphore_page"]
        )
        self.assertFalse(
            surface["cross_va_space_system_mapping"]["cross_provider_mapping_proven"]
        )
        self.assertIn(
            "not specified by the open header",
            surface["cross_va_space_system_mapping"]["cross_provider_semantics"],
        )
        self.assertEqual(
            surface["cross_va_space_system_mapping"]["parameters"],
            ["uvmGpuAddressSpaceHandle srcVaSpace", "NvU64 srcAddress",
             "uvmGpuAddressSpaceHandle dstVaSpace", "NvU64 dstVaAlignment",
             "NvU64 *dstAddress"],
        )
        self.assertIn(
            "NvHandle hPhysMemory",
            surface["physical_memory_handle_mapping"]["dup_memory_parameters"],
        )
        self.assertIn(
            "NvHandle hMemory",
            surface["physical_memory_handle_mapping"]["external_pte_parameters"],
        )
        self.assertEqual(
            surface["rm_mapping_implementation_boundary"],
            "rm_gpu_ops_* implementations are proprietary and were not inspected or executed",
        )
        self.assertIn("GPU physical-memory allocator", surface["pma_pages"]["classification"])
        self.assertIn("max_allocatable_address", surface["pma_pages"]["pinned_uvm_owner"])
        self.assertEqual(
            surface["page_directory"]["classification"],
            "address-space page-table programming, not general OS-page import",
        )

    def test_callback_classifier_fails_closed_if_second_registration_is_not_rejected(self):
        with self.assertRaisesRegex(ValueError, "unrecognized callback registration"):
            self.audit.classify_multi_registration(
                "if (callbacks == NULL) return NV_ERR_INVALID_ARGUMENT;\n"
                "return NV_OK;"
            )

    def test_isolated_gpu_execution_requires_both_semaphore_mapping_gates_and_cpu_waits(self):
        report = self.audit.audit_sources(
            self.audit.SOURCE_ROOT,
            self.audit.BRIDGE_PATH,
        )
        surface = report["semaphore_dependency_surface"]
        self.assertTrue(surface["init_maps_existing_pools_from_prior_gpus"])
        self.assertTrue(surface["non_secure_page_alloc_maps_all_registered_gpus"])
        self.assertEqual(
            surface["gpu_init_order"],
            ["init_semaphore_pools", "uvm_channel_manager_create"],
        )
        self.assertEqual(
            surface["cross_gpu_tracker_access"],
            "acquire semaphore VA is resolved in the submitting channel GPU address space",
        )
        self.assertEqual(
            surface["default_non_cc_policy"],
            "cross-GPU semaphore dependencies allowed",
        )
        self.assertEqual(
            surface["existing_cpu_wait_fallback"],
            "wait_for_other_gpus_if_needed calls uvm_tracker_wait_for_other_gpus",
        )
        self.assertEqual(
            surface["isolated_mode_requirements"],
            [
                "skip cross-GPU semaphore-pool maps at GPU admission",
                "allocate/map semaphore pages only to CPU and their owner GPU",
                "force cross-GPU tracker dependencies through the existing CPU wait path",
                "keep mixed-provider peer and shared managed-memory routes fail-closed",
            ],
        )
        self.assertFalse(surface["isolated_mode_implemented"])
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")

    def test_report_writer_does_not_replace_prior_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_bytes(b"preserve\n")
            with self.assertRaises(FileExistsError):
                self.audit.write_json(path, {"status": "new"})
            self.assertEqual(path.read_bytes(), b"preserve\n")


if __name__ == "__main__":
    unittest.main()
