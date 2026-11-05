# SPDX-License-Identifier: MIT
"""Regression tests for the R580 UVM/RM memory-sharing interface audit."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

MODULE_NAME = "tools.audit_r580_uvm_semaphore_mapping_api"


class R580UvmSemaphoreMappingApiTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec(MODULE_NAME) is None:
            self.fail("the R580 UVM semaphore mapping API audit is not implemented")
        from tools import audit_r580_uvm_semaphore_mapping_api as audit
        self.audit = audit

    def _copy_inputs(self, root):
        root = Path(root)
        for name in (*self.audit.SOURCE_FILES, "uvm_ioctl.h", "uvm_map_external.c"):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.audit.SOURCE_ROOT / name, destination)
        return root

    def _analyze(self, **overrides):
        source_root = self.audit.SOURCE_ROOT
        inputs = {
            "header_text": self.audit.HEADER_PATH.read_text(encoding="utf-8"),
            "rm_source_text": self.audit.RM_SOURCE_PATH.read_text(encoding="utf-8"),
            "ioctl_text": (source_root / "uvm_ioctl.h").read_text(encoding="utf-8"),
            "external_map_text": (source_root / "uvm_map_external.c").read_text(encoding="utf-8"),
            "rm_interface_text": self.audit.RM_INTERFACE_PATH.read_text(encoding="utf-8"),
            "rm_gpu_ops_text": self.audit.RM_GPU_OPS_PATH.read_text(encoding="utf-8"),
            "hybrid_dup_route_text": self.audit.HYBRID_DUP_MEMORY_ROUTE_PATH.read_text(encoding="utf-8"),
            "hybrid_external_route_text": self.audit.HYBRID_EXTERNAL_MAPPING_ROUTE_PATH.read_text(encoding="utf-8"),
            "hybrid_bridge_text": self.audit.HYBRID_CALLBACK_BRIDGE_PATH.read_text(encoding="utf-8"),
            "hybrid_frontend_text": self.audit.HYBRID_FRONTEND_PATH.read_text(encoding="utf-8"),
            "hybrid_memory_owner_text": self.audit.HYBRID_MEMORY_OWNER_PATH.read_text(encoding="utf-8"),
            "uvm_control_fd_patch_text": self.audit.UVM_CONTROL_FD_PATCH.read_text(encoding="utf-8"),
        }
        inputs.update(overrides)
        return self.audit.analyze_interface(**inputs)

    def test_pinned_surface_confirms_rm_owned_memory_and_no_os_page_import(self):
        report = self.audit.audit_sources()

        self.assertEqual(report["result"]["status"], "gap-supported")
        self.assertEqual(report["qualification"]["level"], "analyzed-statically")
        self.assertFalse(report["qualification"]["runtime_or_hardware_validated"])
        self.assertEqual(report["result"]["failed_checks"], [])
        self.assertEqual(
            report["result"]["checks"],
            {
                "system_memory_allocated_in_rm_va_space": True,
                "cpu_mapping_uses_rm_allocation": True,
                "cross_va_mapping_uses_rm_duplication": True,
                "physical_duplication_requires_rm_handles": True,
                "public_interface_has_no_raw_os_page_import": True,
                "external_mapping_uses_rm_client_and_object_handles": True,
            },
        )
        self.assertIn("not proof", report["interpretation"])
        self.assertEqual(
            report["result"]["external_handle_path"]["status"],
            "source-owner-resolved-same-provider-only",
        )
        self.assertEqual(
            report["result"]["cross_provider_import"]["status"],
            "source-owner-resolved-same-provider-only",
        )
        self.assertTrue(all(report["result"]["cross_provider_import"]["checks"].values()))
        self.assertEqual(
            report["result"]["remaining_legacy_dup_memory_call_sites"]["status"],
            "three-direct-calls-hit-fail-closed-legacy-abi",
        )
        self.assertEqual(
            report["result"]["remaining_legacy_dup_memory_call_sites"]["count"], 3
        )
        self.assertEqual(
            set(report["result"]["relevant_api_signatures"]),
            {"MemoryAllocSys", "MemoryCpuMap", "DupAllocation", "DupMemory", "DupMemoryWithControlFd"},
        )

    def test_cross_provider_duplicate_requires_provider_guard_before_rm_call(self):
        route = self.audit.HYBRID_DUP_MEMORY_ROUTE_PATH.read_text(encoding="utf-8")
        old = "if (provider != source_provider)\n        return not_supported_status;"
        self.assertIn(old, route)
        mutated_route = route.replace(old, "if (provider == source_provider)\n        return not_supported_status;", 1)
        report = self._analyze(hybrid_dup_route_text=mutated_route)
        self.assertEqual(
            report["cross_provider_import"]["checks"][
                "duplicate_is_rejected_before_call_when_source_and_target_providers_differ"
            ], False,
        )
        self.assertEqual(report["cross_provider_import"]["status"], "unresolved")

    def test_owner_resolver_must_pin_exact_frontend_file(self):
        owner = self.audit.HYBRID_FRONTEND_PATH.read_text(encoding="utf-8")
        old = "front_file = fget((unsigned int)rm_control_fd);"
        self.assertIn(old, owner)
        report = self._analyze(hybrid_frontend_text=owner.replace(old, "front_file = NULL;", 1))
        self.assertFalse(
            report["cross_provider_import"]["checks"][
                "owner_pin_validates_frontend_fd_root_object_and_pins_memory"
            ]
        )
        self.assertEqual(report["cross_provider_import"]["status"], "unresolved")

    def test_uVM_patch_must_pass_control_fd_from_external_allocation(self):
        patch = self.audit.UVM_CONTROL_FD_PATCH.read_text(encoding="utf-8")
        old = "user_rm_mem->rm_control_fd"
        self.assertIn(old, patch)
        report = self._analyze(uvm_control_fd_patch_text=patch.replace(old, "-1", 1))
        self.assertFalse(
            report["cross_provider_import"]["checks"][
                "uvm_patch_passes_the_exact_rm_control_fd"
            ]
        )
        self.assertEqual(report["cross_provider_import"]["status"], "unresolved")

    def test_raw_linux_page_import_declaration_removes_gap_finding(self):
        header = self.audit.HEADER_PATH.read_text(encoding="utf-8")
        mutated = header + "\nNV_STATUS nvUvmInterfaceMapSystemMemory(uvmGpuAddressSpaceHandle vaSpace, struct page **pages, NvU32 pageCount, NvU64 *gpuVa);\n"

        result = self.audit.analyze_interface(
            mutated,
            self.audit.RM_SOURCE_PATH.read_text(encoding="utf-8"),
            (self.audit.SOURCE_ROOT / "uvm_ioctl.h").read_text(encoding="utf-8"),
            (self.audit.SOURCE_ROOT / "uvm_map_external.c").read_text(encoding="utf-8"),
        )

        self.assertNotEqual(result["status"], "gap-supported")
        self.assertFalse(result["checks"]["public_interface_has_no_raw_os_page_import"])
        self.assertEqual(
            result["raw_descriptor_api_names"],
            ["nvUvmInterfaceMapSystemMemory"],
        )

    def test_raw_linux_page_import_with_kernel_annotation_is_detected(self):
        header = self.audit.HEADER_PATH.read_text(encoding="utf-8")
        mutated = header + (
            "\nNV_STATUS nvUvmInterfaceMapSystemMemory("
            "uvmGpuAddressSpaceHandle vaSpace, struct page __user *pages, "
            "NvU32 pageCount, NvU64 *gpuVa);\n"
        )

        result = self.audit.analyze_interface(
            mutated,
            self.audit.RM_SOURCE_PATH.read_text(encoding="utf-8"),
            (self.audit.SOURCE_ROOT / "uvm_ioctl.h").read_text(encoding="utf-8"),
            (self.audit.SOURCE_ROOT / "uvm_map_external.c").read_text(encoding="utf-8"),
        )

        self.assertFalse(result["checks"]["public_interface_has_no_raw_os_page_import"])
        self.assertEqual(
            result["raw_descriptor_api_names"],
            ["nvUvmInterfaceMapSystemMemory"],
        )

    def test_legacy_dup_memory_must_not_dispatch_without_source_identity(self):
        bridge = self.audit.HYBRID_CALLBACK_BRIDGE_PATH.read_text(encoding="utf-8")
        old = "    return NV_ERR_NOT_SUPPORTED;\n}\nEXPORT_SYMBOL(nvUvmInterfaceDupMemory);"
        self.assertIn(old, bridge)
        mutated = bridge.replace(
            old,
            "    (void)hybrid580_uvm_dup_memory_route_duplicate(NULL);\n"
            "    return NV_ERR_NOT_SUPPORTED;\n}\n"
            "EXPORT_SYMBOL(nvUvmInterfaceDupMemory);",
            1,
        )

        report = self._analyze(hybrid_bridge_text=mutated)

        self.assertFalse(
            report["cross_provider_import"]["checks"][
                "legacy_dup_memory_abi_fails_closed_without_source_identity"
            ]
        )
        self.assertEqual(report["cross_provider_import"]["status"], "unresolved")

    def test_owner_pin_token_must_receive_the_memory_pin(self):
        owner = self.audit.HYBRID_FRONTEND_PATH.read_text(encoding="utf-8")
        old = "owner->pin = pin;"
        self.assertIn(old, owner)
        report = self._analyze(hybrid_frontend_text=owner.replace(old, "owner->pin = NULL;", 1))

        self.assertFalse(
            report["cross_provider_import"]["checks"][
                "owner_pin_validates_frontend_fd_root_object_and_pins_memory"
            ]
        )
        self.assertEqual(report["cross_provider_import"]["status"], "unresolved")

    def test_owner_pin_lifecycle_requires_unpin_and_quarantine_retention(self):
        owner = self.audit.HYBRID_FRONTEND_PATH.read_text(encoding="utf-8")
        quarantine_start = owner.index(
            "void hybrid580_frontend_uvm_memory_owner_quarantine_v1("
        )
        quarantine = owner[quarantine_start:]
        mutations = (
            owner.replace(
                "atomic_dec_if_positive(&pin->memory->uvm_memory_pins)",
                "atomic_read(&pin->memory->uvm_memory_pins)",
                1,
            ),
            owner[:quarantine_start] + quarantine.replace(
                "list_add(&pin->quarantine_link,\n"
                "                 &hybrid_front_uvm_quarantined_memory_pins);",
                "(void)&pin->quarantine_link;",
                1,
            ),
        )
        self.assertNotEqual(mutations[0], owner)
        self.assertNotEqual(mutations[1], owner)

        for mutated in mutations:
            with self.subTest(mutated_lifecycle=True):
                report = self._analyze(hybrid_frontend_text=mutated)
                self.assertFalse(
                    report["cross_provider_import"]["checks"][
                        "owner_pin_lifecycle_unpins_or_quarantines_the_reference"
                    ]
                )
                self.assertEqual(report["cross_provider_import"]["status"], "unresolved")

    def test_rm_handle_duplication_contract_is_required_for_gap_finding(self):
        header = self.audit.HEADER_PATH.read_text(encoding="utf-8")
        mutated = header.replace(
            "NV_STATUS nvUvmInterfaceDupAllocation(uvmGpuAddressSpaceHandle srcVaSpace,",
            "NV_STATUS nvUvmInterfaceDupAllocation(NvHandle srcHandle,",
            1,
        )

        result = self.audit.analyze_interface(
            mutated,
            self.audit.RM_SOURCE_PATH.read_text(encoding="utf-8"),
            (self.audit.SOURCE_ROOT / "uvm_ioctl.h").read_text(encoding="utf-8"),
            (self.audit.SOURCE_ROOT / "uvm_map_external.c").read_text(encoding="utf-8"),
        )

        self.assertNotEqual(result["status"], "gap-supported")
        self.assertFalse(result["checks"]["cross_va_mapping_uses_rm_duplication"])

    def test_rm_mapping_call_site_must_remain_rm_address_space_backed(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-map-api-mutation-") as temporary:
            root = self._copy_inputs(temporary)
            path = root / "uvm_rm_mem.c"
            source = path.read_text(encoding="utf-8")
            old = "nvUvmInterfaceDupAllocation(gpu_owner->rm_address_space,"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "nvUvmInterfaceDupAllocation(NULL,", 1), encoding="utf-8")
            result = self.audit.analyze_interface(
                self.audit.HEADER_PATH.read_text(encoding="utf-8"),
                path.read_text(encoding="utf-8"),
                (root / "uvm_ioctl.h").read_text(encoding="utf-8"),
                (root / "uvm_map_external.c").read_text(encoding="utf-8"),
            )

        self.assertNotEqual(result["status"], "gap-supported")
        self.assertFalse(result["checks"]["cross_va_mapping_uses_rm_duplication"])

    def test_external_mapping_must_keep_rm_import_handles_and_duplicate_path(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-external-handle-mutation-") as temporary:
            root = self._copy_inputs(temporary)
            path = root / "uvm_map_external.c"
            source = path.read_text(encoding="utf-8")
            old = "nvUvmInterfaceDupMemory(uvm_gpu_device_handle(mapping_gpu),"
            self.assertIn(old, source)
            path.write_text(source.replace(old, "nvUvmInterfaceGetExternalAllocPtes(uvm_gpu_va_space_get(va_space, mapping_gpu)->duped_gpu_va_space,", 1), encoding="utf-8")
            result = self.audit.analyze_interface(
                self.audit.HEADER_PATH.read_text(encoding="utf-8"),
                (root / "uvm_rm_mem.c").read_text(encoding="utf-8"),
                (root / "uvm_ioctl.h").read_text(encoding="utf-8"),
                path.read_text(encoding="utf-8"),
            )

        self.assertNotEqual(result["status"], "gap-supported")
        self.assertFalse(result["checks"]["external_mapping_uses_rm_client_and_object_handles"])

    def test_escaped_backslash_before_quote_does_not_hide_following_prototype(self):
        header = r'const char *note = "escaped\\"; NV_STATUS nvUvmInterfaceMemoryAllocSys(uvmGpuAddressSpaceHandle vaSpace);'

        prototypes = self.audit._interface_prototypes(header)

        self.assertIn("nvUvmInterfaceMemoryAllocSys", prototypes)


if __name__ == "__main__":
    unittest.main()
