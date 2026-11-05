#!/usr/bin/env python3
"""Contracts for the isolated R595 Open wrapper compiler."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "private_open595_wrapper", ROOT / "tools/build_private_open595_wrapper.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class PrivateOpen595WrapperTests(unittest.TestCase):
    def test_kbuild_namespace_preserves_r595_flags_and_changes_module_object(self):
        text = """include $(src)/nvidia/nvidia-sources.Kbuild
NVIDIA_OBJECTS = $(patsubst %.c,%.o,$(NVIDIA_SOURCES))
obj-m += nvidia.o
nvidia-y := $(NVIDIA_OBJECTS)

NVIDIA_KO = nvidia/nvidia.ko
NVIDIA_CFLAGS += -I$(src)/nvidia
NVIDIA_CFLAGS += -DNVIDIA_UNDEF_LEGACY_BIT_MACROS
NVIDIA_CFLAGS += -DLIBSPDM_CONFIG=\\\"nvspdm_rmconfig.h\\\"
nvidia-y += $(NVIDIA_BINARY_OBJECT_O)
"""
        changed = MODULE.transform_kbuild(text)
        self.assertIn("obj-m += hybrid580_open.o", changed)
        self.assertIn("hybrid580_open-y := $(NVIDIA_OBJECTS)", changed)
        self.assertIn("NVIDIA_KO = hybrid580_open.ko", changed)
        self.assertIn("hybrid580_open-y += $(NVIDIA_BINARY_OBJECT_O)", changed)
        self.assertIn("-include $(src)/nvidia/hybrid580-open-exports.h", changed)
        self.assertIn('-DLIBSPDM_CONFIG=\\\"nvspdm_rmconfig.h\\\"', changed)
        self.assertNotIn("nvidia-y", changed)

    def test_kbuild_transform_refuses_missing_or_ambiguous_anchors(self):
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_kbuild("obj-m += nvidia.o\n")
        duplicate = """obj-m += nvidia.o
nvidia-y := $(NVIDIA_OBJECTS)
NVIDIA_KO = nvidia/nvidia.ko
NVIDIA_CFLAGS += -I$(src)/nvidia
nvidia-y += $(NVIDIA_BINARY_OBJECT_O)
nvidia-y += $(NVIDIA_BINARY_OBJECT_O)
"""
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_kbuild(duplicate)

    def test_module_name_requires_the_exact_r595_literal(self):
        self.assertEqual(MODULE.transform_module_name('#define MODULE_NAME "nvidia"\n'),
                         '#define MODULE_NAME "hybrid580_open"\n')
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_module_name('#define MODULE_NAME "already_private"\n')
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_module_name('#define MODULE_NAME "nvidia"\n#define MODULE_NAME "nvidia"\n')

    def test_pci_selector_is_inserted_before_any_probe_io_and_device_count(self):
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/nv-pci.c")
        original = source.read_text()
        changed = MODULE.transform_nv_pci_selection(original)
        probe = changed[changed.index("nv_pci_probe\n("):changed.index("nv_pci_count_devices(void)")]
        gate = probe.index("if (!hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev)))")
        self.assertLess(gate, probe.index("nv_bar_index_to_os_bar_index"))
        self.assertLess(gate, probe.index('nv_printf(NV_DBG_SETUP, "NVRM: probing'))
        self.assertEqual(changed.count("static int hybrid_pci_bdf_selected("), 1)
        count = changed[changed.index("nv_pci_count_devices(void)"):changed.index(
            "nv_pci_is_valid_topology_for_direct_pci(")]
        self.assertEqual(count.count("hybrid_pci_bdf_selected(hybrid_gpu_pci, pci_name(pci_dev))"), 2)
        self.assertIn("&&\n            rm_is_supported_pci_device(", count)
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_nv_pci_selection(original.replace(
                "extern int NVreg_ExcludeAllGpus;", "extern int NVreg_Removed;"))

    def test_dynamic_private_chardev_replaces_fixed_major_lifecycle(self):
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/nv.c")
        original = source.read_text()
        changed = MODULE.transform_private_chardev(original)
        self.assertNotIn("MODULE_ALIAS_CHARDEV_MAJOR", changed)
        self.assertNotIn("rc = register_chrdev_region(", changed)
        self.assertIn("alloc_chrdev_region(&hybrid_chrdev_base, 0,", changed)
        self.assertIn("hybrid_unregister_chrdevs();", changed)
        self.assertNotIn("partial_chrdev_exit:", changed)
        self.assertIn("filp->f_op != &nvidia_fops", changed)
        self.assertIn("MAJOR(rdev) != MAJOR(hybrid_chrdev_base)", changed)
        helper = changed[changed.index("static int hybrid_register_chrdevs(void)"):
                         changed.index("static int __init nvidia_init_module(void)")]
        self.assertIn("cdev_del(&nv_linux_devices_cdev);", helper)
        self.assertIn("NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE + 1", helper)
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_private_chardev(original.replace(
                "MODULE_ALIAS_CHARDEV_MAJOR(NV_MAJOR_DEVICE_NUMBER);", ""))

    def test_procfs_buffer_uses_exact_private_module_path_size(self):
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/nv-procfs.c")
        original = source.read_text()
        changed = MODULE.transform_procfs_path(original)
        self.assertEqual(changed.count('char nv_dir_name[sizeof("driver/" MODULE_NAME)];'), 1)
        self.assertNotIn("char nv_dir_name[20];", changed)
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_procfs_path(original.replace("char nv_dir_name[20];", "char nv_dir_name[24];"))

    def test_pci_only_lifecycle_disables_unselected_gpu_and_platform_paths(self):
        root = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia")
        changed = MODULE.transform_pci_only_lifecycle(
            (root / "nv.c").read_text(),
            (root / "nv-pci-table.c").read_text(),
            (root / "nv-platform.c").read_text())
        nv, pci_table, platform = changed
        self.assertIn("const NvBool is_nvswitch_present = NV_FALSE;", nv)
        self.assertNotIn("nvswitch_init();", nv)
        self.assertNotIn("nvswitch_exit();", nv)
        self.assertNotIn("nv_platform_register_driver();", nv)
        self.assertNotIn("nv_platform_unregister_driver();", nv)
        self.assertNotIn("nv_platform_count_devices();", nv)
        self.assertIn("nv_pci_register_driver();", nv)
        self.assertNotIn("MODULE_DEVICE_TABLE(pci,", pci_table)
        self.assertNotIn("MODULE_DEVICE_TABLE(of,", platform)

    def test_builder_runs_non_idempotent_pci_lifecycle_transform_once(self):
        source = (ROOT / "tools/build_private_open595_wrapper.py").read_text()
        module = ast.parse(source)
        main = next(node for node in module.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = [node for node in ast.walk(main)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                 node.func.id == "transform_pci_only_lifecycle"]
        self.assertEqual(len(calls), 1)

    def test_builder_integrates_nvos56_bridge_as_an_explicit_private_export(self):
        source = (ROOT / "tools/build_private_open595_wrapper.py").read_text()
        module = ast.parse(source)
        main = next(node for node in module.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = [node for node in ast.walk(main)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                 node.func.id == "transform_update_device_mapping_info_r595"]
        self.assertEqual(len(calls), 1)
        self.assertIn("DEVICE_MAPPING_UPDATE_EXPORTS", ast.get_source_segment(source, main))

    def test_nvos56_adapter_compiles_from_the_actual_r595_control_header(self):
        control_patch = (ROOT / "patches/r580.178.04/"
                         "0009-private-open-control-session.patch").read_text()
        base_header = MODULE.extract_control_session_api_header(control_patch)
        mapping_patch = (ROOT / "patches/r580.178.04/"
                         "0041-private-open-update-device-mapping-info.patch").read_text()
        nv = "int hybrid580_open_control_session_create_v1("
        changed, header, api_names = MODULE.transform_update_device_mapping_info_r595(
            nv, base_header, mapping_patch)
        self.assertEqual(api_names, list(MODULE.DEVICE_MAPPING_UPDATE_EXPORTS))
        self.assertIn("#include <nvos.h>", header)
        self.assertIn("NVOS56_PARAMETERS *params", header)
        self.assertIn("NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO", changed)

    def test_nvos56_packet_and_escape_are_unchanged_across_r580_r595_r615(self):
        r580 = (ROOT / "build/experiments/r580-private-proprietary-build-v5-20261023/"
                "nvidia-580.178.04/common/inc/nvos.h").read_text()
        r615 = (ROOT / ".cache/upstream/extracted-r615-71-10-20261023/"
                "open-gpu-kernel-modules-6f3be8c9c3fb4ed6ffc607a0d32d31ce4db7fba5/"
                "src/common/sdk/nvidia/inc/nvos.h").read_text()
        r595 = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/src/common/sdk/nvidia/inc/nvos.h").read_text()
        def packet(text):
            start = text.index("#define NV04_UPDATE_DEVICE_MAPPING_INFO")
            end = text.index("} NVOS56_PARAMETERS;", start) + len("} NVOS56_PARAMETERS;")
            return text[start:end]
        self.assertEqual(packet(r580), packet(r595))
        self.assertEqual(packet(r580), packet(r615))
        escapes = []
        for path in (
            ROOT / "build/experiments/r580-private-proprietary-build-v5-20261023/"
            "nvidia-580.178.04/hybrid-sdk/nvidia/arch/nvalloc/unix/include/nv_escape.h",
            ROOT / ".cache/upstream/extracted-r615-71-10-20261023/"
            "open-gpu-kernel-modules-6f3be8c9c3fb4ed6ffc607a0d32d31ce4db7fba5/"
            "src/nvidia/arch/nvalloc/unix/include/nv_escape.h",
            ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
            "open-gpu-kernel-modules-595.99.02/src/nvidia/arch/nvalloc/unix/include/nv_escape.h"):
            text = path.read_text()
            line = next(line.strip() for line in text.splitlines()
                        if "#define NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO" in line)
            escapes.append(line)
        self.assertEqual(len(set(escapes)), 1)

    def test_file_projection_uses_r595_bitmap_identity_and_control_flag(self):
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/nv.c")
        patch = (ROOT / "patches/r580.178.04/"
                 "0008-private-open-file-projection.patch").read_text()
        changed = MODULE.transform_file_projection_r595(source.read_text(), patch)
        self.assertIn('#include "hybrid580-file-projection.h"', changed)
        self.assertIn("READ_ONCE(nvl->minor_num) != minor", changed)
        self.assertIn("!test_bit(minor, nv_linux_minor_bitmap)", changed)
        self.assertIn("nv_state_t *nv;", changed)
        self.assertIn("nv = NV_STATE_PTR(nvl);", changed)
        self.assertIn("(nv->flags & NV_FLAG_CONTROL) == 0", changed)
        self.assertNotIn("NV_FLAG_OPEN", changed)
        self.assertNotIn("nv_linux_minor_num_table", changed)
        self.assertIn("READ_ONCE(nv->removed)", changed)
        self.assertIn("MAJOR(rdev) != MAJOR(hybrid_chrdev_base)", changed)
        self.assertIn("hybrid580_open_project_file(filp, ctl)", changed)
        self.assertIn("hybrid580_open_register_file_projection_v1", changed)
        self.assertIn("hybrid580_open_unregister_file_projection_v1", changed)
        self.assertIn("filp->private_data == NULL", changed)
        self.assertIn("hybrid580_open_project_file(filp, NV_FALSE)", changed)
        matcher = changed[changed.index("static int nv_match_dev_state("):
                          changed.index("NvBool NV_API_CALL nv_match_gpu_os_info(")]
        self.assertIn("fput(back);", matcher)
        self.assertNotIn("LOCK_NV_LINUX_DEVICES", matcher)
        self.assertNotIn("down(&nv_linux_devices_lock)", matcher)

    def test_projection_api_header_is_extracted_exactly_from_r580_patch(self):
        patch = (ROOT / "patches/r580.178.04/"
                 "0008-private-open-file-projection.patch").read_text()
        header = MODULE.extract_projection_api_header(patch)
        self.assertTrue(header.startswith("/* SPDX-License-Identifier: MIT */\n"))
        self.assertIn("HYBRID580_FILE_PROJECTION_ABI_V1", header)
        self.assertIn("get_backing_file", header)
        self.assertEqual(header.count("struct hybrid580_file_projection_ops_v1 {"), 1)
        self.assertTrue(header.endswith("#endif\n"))
        with self.assertRaisesRegex(ValueError, "header"):
            MODULE.extract_projection_api_header(patch.replace(
                "+++ b/kernel-open/nvidia/hybrid580-file-projection.h",
                "+++ b/kernel-open/nvidia/other.h"))

    def test_control_session_patch_is_semantically_adapted_to_r595_layout(self):
        root = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02")
        nv = (root / "kernel-open/nvidia/nv.c").read_text()
        nv = MODULE.transform_private_chardev(nv)
        nv = MODULE.transform_file_projection_r595(
            nv, (ROOT / "patches/r580.178.04/0008-private-open-file-projection.patch").read_text())
        kbuild = MODULE.transform_kbuild((root / "kernel-open/nvidia/nvidia.Kbuild").read_text())
        patch = (ROOT / "patches/r580.178.04/"
                 "0009-private-open-control-session.patch").read_text()
        changed_nv, changed_kbuild = MODULE.transform_control_session_r595(nv, kbuild, patch)
        self.assertIn("hybrid580_control_session_invoke", changed_nv)
        self.assertIn("hybrid580_open_control_session_create_v1", changed_nv)
        self.assertIn("if (nvlfp == NULL)\n        return 0;", changed_nv)
        self.assertIn("NVIDIA_CFLAGS += -I$(src)/../src/common/sdk/nvidia/inc", changed_kbuild)
        self.assertIn("NVIDIA_CFLAGS += -I$(src)/../src/nvidia/arch/nvalloc/unix/include",
                      changed_kbuild)
        self.assertNotIn("NV_FLAG_OPEN", changed_nv)

    def test_sdk_rs_access_adapter_reuses_the_kernel_open_definition_set(self):
        root = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02")
        sdk_header = root / "src/common/sdk/nvidia/inc/rs_access.h"
        kernel_header = root / "kernel-open/common/inc/rs_access.h"
        original_sdk = sdk_header.read_text()
        original_kernel = kernel_header.read_text()

        adapted = MODULE.transform_sdk_rs_access_header_r595(
            original_sdk, original_kernel)

        self.assertIn(
            '#include "../../../../../kernel-open/common/inc/rs_access.h"', adapted)
        self.assertNotIn("typedef struct RS_ACCESS_MASK", adapted)
        self.assertEqual(adapted.count("#pragma once"), 1)
        self.assertTrue(adapted.startswith("/*"))
        with self.assertRaisesRegex(ValueError, "differ"):
            MODULE.transform_sdk_rs_access_header_r595(
                original_sdk, original_kernel + "\n/* drift */\n")

    def test_builder_applies_sdk_rs_access_adapter_to_private_copy_once(self):
        source = (ROOT / "tools/build_private_open595_wrapper.py").read_text()
        module = ast.parse(source)
        main = next(node for node in module.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = [node for node in ast.walk(main)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                 node.func.id == "transform_sdk_rs_access_header_r595"]
        self.assertEqual(len(calls), 1)

    def test_control_session_header_and_endpoint_contract_are_pinned_inputs(self):
        patch = (ROOT / "patches/r580.178.04/"
                 "0009-private-open-control-session.patch").read_text()
        header = MODULE.extract_control_session_api_header(patch)
        self.assertIn('#include "rm_session_endpoint.h"', header)
        self.assertIn("hybrid580_open_control_session_create_v1", header)
        endpoint = (ROOT / "src/rm_session_endpoint.h").read_text()
        self.assertIn("HYBRID_RM_SESSION_ABI_V1", endpoint)
        self.assertIn("backend_identity", endpoint)

    def test_gpu_session_patch_uses_exact_r595_anchor_and_pinned_header(self):
        root = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02")
        nv = MODULE.transform_private_chardev(
            (root / "kernel-open/nvidia/nv.c").read_text())
        projection = (ROOT / "patches/r580.178.04/"
                      "0008-private-open-file-projection.patch").read_text()
        nv = MODULE.transform_file_projection_r595(nv, projection)
        kbuild = MODULE.transform_kbuild(
            (root / "kernel-open/nvidia/nvidia.Kbuild").read_text())
        control = (ROOT / "patches/r580.178.04/"
                   "0009-private-open-control-session.patch").read_text()
        nv, kbuild = MODULE.transform_control_session_r595(nv, kbuild, control)
        gpu_patch = (ROOT / "patches/r580.178.04/"
                     "0010-private-open-gpu-session.patch").read_text()

        changed = MODULE.transform_gpu_session_r595(nv, gpu_patch)
        header = MODULE.extract_gpu_session_api_header(gpu_patch)

        self.assertIn('#include "hybrid580-gpu-session.h"', changed)
        self.assertEqual(changed.count("static NvBool hybrid580_open_gpu_bdf_valid("), 1)
        self.assertLess(changed.index("struct hybrid580_gpu_session {"),
                        changed.index("nv_file_private_t* NV_API_CALL nv_get_file_private("))
        self.assertIn("hybrid580_open_gpu_session_ioctl_v1", header)
        self.assertTrue(header.startswith("/* SPDX-License-Identifier: MIT */\n"))
        bdf_patch = (ROOT / "patches/r580.178.04/"
                     "0011-private-open-gpu-session-bdf-lookup.patch").read_text()
        changed, header = MODULE.transform_gpu_session_bdf_lookup_r595(
            changed, header, bdf_patch)
        self.assertEqual(changed.count(
            "int hybrid580_open_gpu_session_create_by_bdf_v1("), 1)
        self.assertIn("EXPORT_SYMBOL(hybrid580_open_gpu_session_create_by_bdf_v1);", changed)
        self.assertIn("find_minor_locked(minor)", changed)
        self.assertIn("int hybrid580_open_gpu_session_create_by_bdf_v1(", header)
        register_patch = (ROOT / "patches/r580.178.04/"
                          "0039-private-open-gpu-register-control.patch").read_text()
        changed, header = MODULE.transform_gpu_register_control_r595(
            changed, header, register_patch)
        register = changed[changed.index(
            "int hybrid580_open_gpu_session_register_control_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_gpu_session_register_control_v1);")]
        self.assertIn("get_file(control->file)", register)
        self.assertIn("rm_acquire_api_lock(sp)", register)
        self.assertIn("NVFP_TYPE_REGISTERED", register)
        self.assertIn("cmpxchg(&gpu_nvlfp->nvfp.ctl_nvfp, NULL,", register)
        self.assertIn("gpu_nvlfp->nvfp.ctl_nvfp_priv = control_file", register)
        self.assertIn("fput(control_file)", register)
        self.assertIn("struct hybrid580_control_session;", header)
        self.assertIn("int hybrid580_open_gpu_session_register_control_v1(", header)
        with self.assertRaisesRegex(ValueError, "already adapted"):
            MODULE.transform_gpu_register_control_r595(changed, header, register_patch)
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_gpu_session_r595(nv.replace(
                "nv_file_private_t* NV_API_CALL nv_get_file_private(",
                "nv_file_private_t* NV_API_CALL nv_get_file_private(", 1) +
                "nv_file_private_t* NV_API_CALL nv_get_file_private(\n", gpu_patch)

    def test_gpu_inventory_and_card_info_adapters_match_r595_layout(self):
        root = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02")
        nv = MODULE.transform_private_chardev(
            (root / "kernel-open/nvidia/nv.c").read_text())
        projection = (ROOT / "patches/r580.178.04/"
                      "0008-private-open-file-projection.patch").read_text()
        nv = MODULE.transform_file_projection_r595(nv, projection)
        kbuild = MODULE.transform_kbuild(
            (root / "kernel-open/nvidia/nvidia.Kbuild").read_text())
        control = (ROOT / "patches/r580.178.04/"
                   "0009-private-open-control-session.patch").read_text()
        nv, kbuild = MODULE.transform_control_session_r595(nv, kbuild, control)
        gpu_patch = (ROOT / "patches/r580.178.04/"
                     "0010-private-open-gpu-session.patch").read_text()
        nv = MODULE.transform_gpu_session_r595(nv, gpu_patch)
        gpu_header = MODULE.extract_gpu_session_api_header(gpu_patch)
        bdf_patch = (ROOT / "patches/r580.178.04/"
                     "0011-private-open-gpu-session-bdf-lookup.patch").read_text()
        nv, gpu_header = MODULE.transform_gpu_session_bdf_lookup_r595(
            nv, gpu_header, bdf_patch)
        inventory_patch = (ROOT / "patches/r580.178.04/"
                           "0012-private-open-gpu-inventory.patch").read_text()
        catalog = (ROOT / "src/hybrid580-gpu-catalog.h").read_text()

        changed, gpu_header = MODULE.transform_gpu_inventory_r595(
            nv, gpu_header, catalog, inventory_patch)

        self.assertIn("int hybrid580_open_gpu_inventory_v1(", changed)
        self.assertIn("for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)", changed)
        self.assertIn("record->backend_minor = nvl->minor_num;", changed)
        self.assertIn('#include "hybrid580-gpu-catalog.h"', gpu_header)
        self.assertIn("struct hybrid580_gpu_backend_record_v1 *records", gpu_header)
        self.assertIn("HYBRID580_GPU_MAX_BACKEND_DEVICES", catalog)

        card_patch = (ROOT / "patches/r580.178.04/"
                      "0015-private-open-card-info.patch").read_text()
        changed, gpu_header = MODULE.transform_gpu_card_info_r595(
            changed, gpu_header, card_patch)
        card_info = changed[changed.index("int hybrid580_open_gpu_card_info_v1("):
                            changed.index("EXPORT_SYMBOL(hybrid580_open_gpu_card_info_v1);")]
        self.assertIn("nvidia_read_card_info(typed_records, capacity)", card_info)
        self.assertIn("capacity > HYBRID580_GPU_MAX_BACKEND_DEVICES", card_info)
        self.assertIn("nv_down_read_interruptible(&nv_system_pm_lock)", card_info)
        self.assertIn("nv_kmem_cache_free_stack(sp);", card_info)
        self.assertIn("struct nv_ioctl_card_info;", gpu_header)
        self.assertIn("int hybrid580_open_gpu_card_info_v1(", gpu_header)
        self.assertEqual(changed.count("EXPORT_SYMBOL(hybrid580_open_gpu_card_info_v1);"), 1)

    def test_control_attach_adapter_preserves_r595_reset_aware_device_calls(self):
        root = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02")
        nv = MODULE.transform_private_chardev(
            (root / "kernel-open/nvidia/nv.c").read_text())
        projection = (ROOT / "patches/r580.178.04/"
                      "0008-private-open-file-projection.patch").read_text()
        nv = MODULE.transform_file_projection_r595(nv, projection)
        kbuild = MODULE.transform_kbuild(
            (root / "kernel-open/nvidia/nvidia.Kbuild").read_text())
        control_patch = (ROOT / "patches/r580.178.04/"
                         "0009-private-open-control-session.patch").read_text()
        nv, kbuild = MODULE.transform_control_session_r595(nv, kbuild, control_patch)
        control_header = MODULE.extract_control_session_api_header(control_patch)
        attach_patch = (ROOT / "patches/r580.178.04/"
                        "0014-private-control-attach-after-gpu.patch").read_text()

        changed, control_header = MODULE.transform_control_attach_r595(
            nv, control_header, attach_patch)

        self.assertIn("hybrid580_attach_gpus_to_file(nvlfp, sp, arg_copy, arg_size)", changed)
        self.assertIn("nvidia_dev_get(nvlfp->attached_gpus[i], sp, NV_FALSE", changed)
        self.assertIn("nvidia_dev_put(nvlfp->attached_gpus[i], sp, NV_FALSE", changed)
        self.assertEqual(changed.count(
            "static int hybrid580_attach_gpus_to_file(nv_linux_file_private_t *,"), 1)
        self.assertEqual(changed.count(
            "static int hybrid580_attach_gpus_to_file(\n    nv_linux_file_private_t *nvlfp"), 1)
        self.assertIn("hybrid580_attach_gpus_to_file(nvlfp, sp, arg_copy, arg_size)", changed)
        self.assertIn("hybrid580_open_control_session_attach_v1", control_header)
        self.assertIn("caller retains a session reference", control_header)

        id_info_patch = (ROOT / "patches/r580.178.04/"
                         "0016-private-open-gpu-id-info.patch").read_text()
        changed, control_header = MODULE.transform_gpu_id_info_r595(
            changed, control_header, id_info_patch)
        id_info = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_gpu_id_info_v1("):
            changed.index("EXPORT_SYMBOL(hybrid580_open_control_session_gpu_id_info_v1);")]
        self.assertIn("rm_kernel_rmapi_op(sp, &ops);", id_info)
        self.assertIn("NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2", id_info)
        self.assertIn("#include <nv-kernel-rmapi-ops.h>", changed)
        self.assertIn("#include <ctrl/ctrl0000/ctrl0000gpu.h>", control_header)
        self.assertIn("struct file;", control_header)

        query_patches = (
            ("0017-private-open-attached-ids.patch",
             "hybrid580_open_control_session_attached_ids_v1",
             "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS"),
            ("0018-private-open-probed-ids.patch",
             "hybrid580_open_control_session_probed_ids_v1",
             "NV0000_CTRL_CMD_GPU_GET_PROBED_IDS"),
            ("0019-private-open-device-ids.patch",
             "hybrid580_open_control_session_device_ids_v1",
             "NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS"),
        )
        for patch_name, api_name, command in query_patches:
            query_patch = (ROOT / "patches/r580.178.04" / patch_name).read_text()
            changed, control_header, adapted_api = MODULE.transform_control_query_r595(
                changed, control_header, query_patch)
            self.assertEqual(adapted_api, api_name)
            query = changed[changed.index(f"NV_STATUS {api_name}("):
                             changed.index(f"EXPORT_SYMBOL({api_name});")]
            self.assertIn(command, query)
            self.assertIn("rm_kernel_rmapi_op(sp, &ops);", query)
            self.assertIn(f"NV_STATUS {api_name}(", control_header)
        self.assertIn("Fixed output-only device-instance bitmask", control_header)

        device_patch = (ROOT / "patches/r580.178.04/"
                        "0020-private-open-device-object.patch").read_text()
        changed, control_header = MODULE.transform_device_object_r595(
            changed, control_header, device_patch)
        device_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_device_alloc_v1("):
            changed.index("EXPORT_SYMBOL(hybrid580_open_control_session_device_alloc_v1);")]
        device_free = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_device_free_v1("):
            changed.index("EXPORT_SYMBOL(hybrid580_open_control_session_device_free_v1);")]
        self.assertIn("params->hClientShare != 0 && params->hClientShare != h_root",
                      device_alloc)
        self.assertIn("params->hTargetClient != 0", device_alloc)
        self.assertIn(".hClass = NV01_DEVICE_0", device_alloc)
        self.assertIn(".op = NV04_ALLOC", device_alloc)
        self.assertIn(".op = NV01_FREE", device_free)
        self.assertIn("h_device == h_root", device_free)
        self.assertIn("#include <class/cl0080.h>", control_header)
        self.assertIn("NV0080_ALLOC_PARAMETERS *params", control_header)

        memory_patch = (ROOT / "patches/r580.178.04/"
                        "0021-private-open-memory-object.patch").read_text()
        changed, control_header, memory_apis = MODULE.transform_control_session_additions_r595(
            changed, control_header, memory_patch)
        self.assertEqual(memory_apis, [
            "hybrid580_open_control_session_memory_alloc_v1",
            "hybrid580_open_control_session_object_free_v1"])
        self.assertIn("#include <class/cl003e.h>", control_header)
        self.assertIn("#include <class/cl0040.h>", control_header)
        self.assertIn("#include <nvos.h>", control_header)
        self.assertIn("NV01_MEMORY_SYSTEM", changed)
        self.assertIn("NV01_MEMORY_LOCAL_USER", changed)
        self.assertIn(".op = NV04_ALLOC", changed)
        self.assertIn(".op = NV01_FREE", changed)

        vaspace_patch = (ROOT / "patches/r580.178.04/"
                         "0022-private-open-vaspace-object.patch").read_text()
        changed, control_header, vaspace_apis = (
            MODULE.transform_control_session_additions_r595(
                changed, control_header, vaspace_patch))
        self.assertEqual(vaspace_apis,
                         ["hybrid580_open_control_session_vaspace_alloc_v1"])
        self.assertIn("#include <class/cl90f1.h>", control_header)
        self.assertIn("FERMI_VASPACE_A", changed)
        self.assertIn("NV_VASPACE_ALLOCATION_FLAGS_SHARED_MANAGEMENT", changed)
        self.assertIn("NV_VASPACE_ALLOCATION_INDEX_GPU_MAX", changed)

        channel_group_patch = (ROOT / "patches/r580.178.04/"
                               "0023-private-open-channel-group-object.patch").read_text()
        changed, control_header, channel_group_apis = (
            MODULE.transform_control_session_additions_r595(
                changed, control_header, channel_group_patch))
        self.assertEqual(channel_group_apis,
                         ["hybrid580_open_control_session_channel_group_alloc_v1"])
        self.assertIn("#include <class/cla06c.h>", control_header)
        self.assertIn("NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS", control_header)
        channel_group_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_channel_group_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_channel_group_alloc_v1);")]
        self.assertIn(".hClass = KEPLER_CHANNEL_GROUP_A", channel_group_alloc)
        self.assertIn("params->hVASpace == 0", channel_group_alloc)
        self.assertIn("params->bIsCallingContextVgpuPlugin != NV_FALSE",
                      channel_group_alloc)
        self.assertIn(".op = NV04_ALLOC", channel_group_alloc)

        context_share_patch = (ROOT / "patches/r580.178.04/"
                               "0024-private-open-context-share-object.patch").read_text()
        changed, control_header, context_share_apis = (
            MODULE.transform_context_share_r595(
                changed, control_header, context_share_patch))
        self.assertEqual(context_share_apis,
                         ["hybrid580_open_control_session_context_share_alloc_v1"])
        self.assertIn("#include <class/cl9067.h>", control_header)
        self.assertIn("NV_CTXSHARE_ALLOCATION_PARAMETERS", control_header)
        context_share_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_context_share_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_context_share_alloc_v1);")]
        self.assertIn(".hClass = FERMI_CONTEXT_SHARE_A", context_share_alloc)
        self.assertIn(".hObjectParent = h_group", context_share_alloc)
        self.assertNotIn("params->hVASpace == 0", context_share_alloc)
        self.assertIn("NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED",
                      context_share_alloc)
        self.assertNotIn(": params->subctxId != 0", context_share_alloc)
        self.assertIn("*params = alloc_params", context_share_alloc)
        self.assertIn(".op = NV04_ALLOC", context_share_alloc)

        channel_patch = (ROOT / "patches/r580.178.04/"
                         "0025-private-open-channel-object.patch").read_text()
        changed, control_header, channel_apis = (
            MODULE.transform_channel_allocation_r595(
                changed, control_header, channel_patch))
        self.assertEqual(channel_apis,
                         ["hybrid580_open_control_session_channel_alloc_v1"])
        channel_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_channel_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_channel_alloc_v1);")]
        self.assertIn("class_id != VOLTA_CHANNEL_GPFIFO_A", channel_alloc)
        self.assertIn("class_id != BLACKWELL_CHANNEL_GPFIFO_A", channel_alloc)
        self.assertIn("class_id != BLACKWELL_CHANNEL_GPFIFO_B", channel_alloc)
        self.assertIn("params->hVASpace != 0", channel_alloc)
        self.assertIn("NVOS04_FLAGS_CHANNEL_TYPE_PHYSICAL", channel_alloc)
        self.assertIn("#include <class/clc36f.h>", control_header)
        self.assertIn("#include <class/clc96f.h>", control_header)
        self.assertIn("#include <class/clca6f.h>", control_header)

        subdevice_patch = (ROOT / "patches/r580.178.04/"
                           "0026-private-open-subdevice-and-tpc-mask.patch").read_text()
        changed, control_header, subdevice_apis = (
            MODULE.transform_control_session_additions_r595(
                changed, control_header, subdevice_patch))
        self.assertEqual(subdevice_apis, [
            "hybrid580_open_control_session_subdevice_alloc_v1",
            "hybrid580_open_control_session_gr_tpc_mask_v1"])
        self.assertIn("#include <class/cl2080.h>", control_header)
        self.assertIn("#include <ctrl/ctrl2080/ctrl2080gr.h>", control_header)
        subdevice_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_subdevice_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_subdevice_alloc_v1);")]
        tpc_mask = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_gr_tpc_mask_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_gr_tpc_mask_v1);")]
        self.assertIn(".hClass = NV20_SUBDEVICE_0", subdevice_alloc)
        self.assertIn("params->subDeviceId >= NV2080_MAX_SUBDEVICES", subdevice_alloc)
        self.assertIn("NV2080_CTRL_CMD_GR_GET_TPC_MASK", tpc_mask)
        self.assertIn(".op = NV04_CONTROL", tpc_mask)

        binapi_patch = (ROOT / "patches/r580.178.04/"
                        "0027-private-open-binapi-object.patch").read_text()
        changed, control_header, binapi_apis = (
            MODULE.transform_control_session_additions_r595(
                changed, control_header, binapi_patch))
        self.assertEqual(binapi_apis,
                         ["hybrid580_open_control_session_binapi_alloc_v1"])
        self.assertIn("#include <class/cl2081.h>", control_header)
        binapi_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_binapi_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_binapi_alloc_v1);")]
        self.assertIn(".hObjectParent = h_subdevice", binapi_alloc)
        self.assertIn(".hClass = NV2081_BINAPI", binapi_alloc)
        self.assertIn("params->reserved != 0", binapi_alloc)

        usermode_patch = (ROOT / "patches/r580.178.04/"
                          "0028-private-open-usermode-object.patch").read_text()
        changed, control_header, usermode_apis = (
            MODULE.transform_control_session_additions_r595(
                changed, control_header, usermode_patch))
        self.assertEqual(usermode_apis,
                         ["hybrid580_open_control_session_usermode_alloc_v1"])
        usermode_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_usermode_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_usermode_alloc_v1);")]
        self.assertIn("VOLTA_USERMODE_A", usermode_alloc)
        self.assertIn("HOPPER_USERMODE_A", usermode_alloc)
        self.assertIn("params->bBar1Mapping != NV_TRUE", usermode_alloc)
        self.assertIn("params->bPriv != NV_FALSE", usermode_alloc)
        self.assertIn(".paramsSize = params != NULL ? sizeof(alloc_params) : 0",
                      usermode_alloc)
        self.assertIn("#include <class/clc361.h>", control_header)
        self.assertIn("#include <class/clc661.h>", control_header)

        map_memory_patch = (ROOT / "patches/r580.178.04/"
                            "0029-private-open-map-memory.patch").read_text()
        changed, control_header, map_memory_apis = MODULE.transform_map_memory_r595(
            changed, control_header, map_memory_patch)
        self.assertEqual(map_memory_apis, [
            "hybrid580_open_control_session_map_memory_v1",
            "hybrid580_open_control_session_unmap_memory_v1"])
        self.assertEqual(changed.count(
            '#include "nv-unix-nvos-params-wrappers.h"'), 1)
        map_memory = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_map_memory_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_map_memory_v1);")]
        unmap_memory = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_unmap_memory_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_unmap_memory_v1);")]
        self.assertIn("nv_ioctl_nvos33_parameters_with_fd api", map_memory)
        self.assertIn("api.fd = fd", map_memory)
        self.assertIn("NV_ESC_RM_MAP_MEMORY", map_memory)
        self.assertIn("sizeof(api)", map_memory)
        self.assertIn("*params = api.params", map_memory)
        self.assertIn("params->status = 0xffffffffU", map_memory)
        self.assertIn("NV_ESC_RM_UNMAP_MEMORY", unmap_memory)
        self.assertIn("sizeof(*params)", unmap_memory)
        self.assertIn("NVOS33_PARAMETERS *params", control_header)
        self.assertIn("NVOS34_PARAMETERS *params", control_header)
        with self.assertRaisesRegex(ValueError, "already present"):
            MODULE.transform_map_memory_r595(changed, control_header, map_memory_patch)

        mapping_patch = (ROOT / "patches/r580.178.04/"
                         "0041-private-open-update-device-mapping-info.patch").read_text()
        changed, control_header, mapping_apis = (
            MODULE.transform_update_device_mapping_info_r595(
                changed, control_header, mapping_patch))
        self.assertEqual(mapping_apis, [
            "hybrid580_open_control_session_update_device_mapping_info_v1"])
        mapping_bridge = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_update_device_mapping_info_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_update_device_mapping_info_v1);")]
        self.assertIn("NVOS56_PARAMETERS api", mapping_bridge)
        self.assertIn("NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO", mapping_bridge)
        self.assertIn("sizeof(api)", mapping_bridge)
        self.assertIn("*params = api", mapping_bridge)
        self.assertIn("NVOS56_PARAMETERS *params", control_header)
        with self.assertRaisesRegex(ValueError, "already present"):
            MODULE.transform_update_device_mapping_info_r595(
                changed, control_header, mapping_patch)

        rusd_patch = (ROOT / "patches/r580.178.04/"
                      "0030-private-open-rusd-object.patch").read_text()
        changed, control_header, rusd_apis = MODULE.transform_rusd_allocation_r595(
            changed, control_header, rusd_patch)
        self.assertEqual(rusd_apis,
                         ["hybrid580_open_control_session_rusd_alloc_v1"])
        self.assertIn("#include <class/cl00de.h>", control_header)
        self.assertIn("const NV00DE_ALLOC_PARAMETERS *params", control_header)
        rusd_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_rusd_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_rusd_alloc_v1);")]
        self.assertIn("h_rusd == 0", rusd_alloc)
        self.assertIn(".hClass = RM_USER_SHARED_DATA", rusd_alloc)
        self.assertIn(".paramsSize = sizeof(alloc_params)", rusd_alloc)
        self.assertIn("*rm_status = alloc.status", rusd_alloc)
        self.assertIn("*returned_rusd = alloc.hObjectNew", rusd_alloc)
        with self.assertRaisesRegex(ValueError, "already present"):
            MODULE.transform_rusd_allocation_r595(changed, control_header, rusd_patch)

        engine_patch = (ROOT / "patches/r580.178.04/"
                        "0040-private-open-engine-object.patch").read_text()
        changed, control_header, engine_apis = MODULE.transform_engine_allocation_r595(
            changed, control_header, engine_patch)
        self.assertEqual(engine_apis,
                         ["hybrid580_open_control_session_engine_alloc_v1"])
        self.assertIn("#include <class/clcab5.h>", control_header)
        self.assertIn("#include <class/clcec0.h>", control_header)
        self.assertIn("NvHandle h_engine, NvU32 class_id", control_header)
        engine_alloc = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_engine_alloc_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_engine_alloc_v1);")]
        self.assertIn("class_id != BLACKWELL_DMA_COPY_B", engine_alloc)
        self.assertIn("class_id != BLACKWELL_COMPUTE_B", engine_alloc)
        self.assertIn(".pAllocParms = NvP64_NULL", engine_alloc)
        self.assertIn(".paramsSize = 0", engine_alloc)
        self.assertIn("rm_kernel_rmapi_op(sp, &ops)", engine_alloc)
        with self.assertRaisesRegex(ValueError, "already present"):
            MODULE.transform_engine_allocation_r595(changed, control_header,
                                                    engine_patch)

        sys_params_patch = (ROOT / "patches/r580.178.04/"
                            "0037-private-open-sys-params.patch").read_text()
        changed, control_header, sys_params_apis = MODULE.transform_sys_params_r595(
            changed, control_header, sys_params_patch)
        self.assertEqual(sys_params_apis,
                         ["hybrid580_open_control_session_sys_params_v1"])
        self.assertIn("static DEFINE_MUTEX(hybrid580_sys_params_lock);", changed)
        self.assertIn("mutex_lock(&hybrid580_sys_params_lock)", changed)
        self.assertIn("status = hybrid580_set_sys_params(nvl, api->memblock_size);",
                      changed)
        sys_params_api = changed[changed.index(
            "int hybrid580_open_control_session_sys_params_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_sys_params_v1);")]
        self.assertIn("nvlfp->nvptr != &nv_ctl_device", sys_params_api)
        self.assertIn("NV_FLAG_CONTROL", sys_params_api)
        self.assertIn("nv_check_gpu_state(nv)", sys_params_api)
        self.assertIn("hybrid580_set_sys_params(nvl, memblock_size)", sys_params_api)
        self.assertIn("int hybrid580_open_control_session_sys_params_v1(",
                      control_header)
        with self.assertRaisesRegex(ValueError, "already present"):
            MODULE.transform_sys_params_r595(changed, control_header,
                                             sys_params_patch)

    def test_build_version_bridge_uses_exact_r595_anchor_and_pointer_free_v2(self):
        patch = (ROOT / "patches/r580.178.04/"
                 "0038-private-open-build-version-v1.patch").read_text()
        header = (ROOT / "src/hybrid580-open-build-version.h").read_text()
        anchor = (
            '#include "hybrid580-control-session.h"\n'
            "EXPORT_SYMBOL(hybrid580_open_control_session_sys_params_v1);\n")
        changed = MODULE.transform_build_version_r595(anchor, patch, header)
        include = '#include "hybrid580-open-build-version.h"\n'
        self.assertEqual(changed.count(include), 1)
        self.assertLess(changed.index(include), changed.index(
            "EXPORT_SYMBOL(hybrid580_open_control_session_sys_params_v1);"))
        self.assertLess(changed.index(
            "EXPORT_SYMBOL(hybrid580_open_control_session_sys_params_v1);"),
            changed.index("NV_STATUS hybrid580_open_control_session_build_version_v1("))
        bridge = changed[changed.index(
            "NV_STATUS hybrid580_open_control_session_build_version_v1("):
            changed.index(
                "EXPORT_SYMBOL(hybrid580_open_control_session_build_version_v1);")]
        self.assertIn("NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION_V2", bridge)
        self.assertIn("result = kzalloc(sizeof(*result), GFP_KERNEL);", bridge)
        self.assertIn("KERNEL_POINTER_TO_NvP64(result)", bridge)
        self.assertIn("paramsSize = sizeof(*result)", bridge)
        self.assertIn("rm_kernel_rmapi_op(sp, &ops);", bridge)
        self.assertIn("*params = *result;", bridge)
        self.assertIn("kfree(result);", bridge)
        self.assertNotIn("NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS result =", bridge)
        allocation_tail = bridge[bridge.index("result = kzalloc("):]
        self.assertEqual(allocation_tail.count("return status;"), 1)
        self.assertLess(allocation_tail.index("kfree(result);"),
                        allocation_tail.index("return status;"))
        self.assertNotRegex(bridge, r"\bcopy_(?:from|to)_user\s*\(")
        with self.assertRaisesRegex(ValueError, "already adapted"):
            MODULE.transform_build_version_r595(changed, patch, header)
        with self.assertRaisesRegex(ValueError, "project contract"):
            MODULE.transform_build_version_r595(anchor, patch,
                header.replace("NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *params",
                               "NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS *params"))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            MODULE.transform_build_version_r595(anchor,
                patch.replace("rm_kernel_rmapi_op(sp, &ops);", "copy_to_user();"), header)

    def test_pm_channel_depth_enum_is_added_at_the_exact_r595_declaration(self):
        patch = (ROOT / "patches/r580.178.04/"
                 "0001-private-open-pm-channel-depth-enum.patch").read_text()
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/common/inc/nv.h")
        original = source.read_text()
        changed = MODULE.transform_pm_channel_depth_enum_r595(original, patch)
        enum = changed[changed.index(
            "typedef enum\n{\n    NV_PM_ACTION_DEPTH_DEFAULT,"):
            changed.index("} nv_pm_action_depth_t;")]
        self.assertEqual(enum.count("NV_PM_ACTION_DEPTH_CHANNELS"), 1)
        self.assertLess(enum.index("NV_PM_ACTION_DEPTH_UVM"),
                        enum.index("NV_PM_ACTION_DEPTH_CHANNELS"))
        self.assertTrue(enum.rstrip().endswith("NV_PM_ACTION_DEPTH_CHANNELS"))
        with self.assertRaisesRegex(ValueError, "already adapted"):
            MODULE.transform_pm_channel_depth_enum_r595(changed, patch)
        drifted = original.replace("    NV_PM_ACTION_DEPTH_UVM\n",
                                   "    NV_PM_ACTION_DEPTH_UVMX\n")
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_pm_channel_depth_enum_r595(drifted, patch)

    def test_pm_channel_depth_lifecycle_is_adapted_at_r595_function_anchors(self):
        base = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia")
        patch = (ROOT / "patches/r580.178.04/"
                 "0031-private-open-pm-channel-depth.patch").read_text()
        nv, procfs = MODULE.transform_pm_channel_depth_r595(
            (base / "nv.c").read_text(), (base / "nv-procfs.c").read_text(), patch)
        self.assertIn(".mmap      = nv_mmap_pm_guard,", nv)
        mmap_guard = nv[nv.index("static int nv_mmap_pm_guard("):nv.index(
            "static struct file_operations nvidia_fops")]
        self.assertIn("down_read_trylock(&nv_system_pm_lock)", mmap_guard)
        open_func = nv[nv.index("int\nnvidia_open("):nv.index("void nv_shutdown_adapter(")]
        self.assertLess(open_func.index("nv_down_read_interruptible(&nv_system_pm_lock)"),
                        open_func.index("nvidia_ctl_open(inode, file)"))
        close_func = nv[nv.index("int\nnvidia_close("):nv.index("unsigned int\nnvidia_poll(")]
        self.assertIn("nvidia_ctl_close_callback(nvlfp);", close_func)
        self.assertIn("nvidia_ctl_close_deferred", close_func)
        close_callback = nv[nv.index("static void\nnvidia_ctl_close_callback("):
                           nv.index("void NV_API_CALL\nnv_set_dma_address_size(")]
        self.assertIn("rm_cleanup_file_private", close_callback)
        self.assertIn("static void nvidia_ctl_close_deferred(void *data)", close_callback)
        self.assertNotIn("struct file *", close_callback)

        resume = nv[nv.index("static NV_STATUS\nnv_resume_devices("):
                    nv.index("static NV_STATUS\nnv_suspend_devices(")]
        self.assertIn("resume_uvm = NV_FALSE", resume)
        self.assertIn("if (resume_uvm)", resume)
        suspend = nv[nv.index("static NV_STATUS\nnv_suspend_devices("):
                     nv.index("NV_STATUS\nnv_set_system_power_state(")]
        self.assertIn("pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS", suspend)
        self.assertIn("uvm_suspended = (status == NV_OK);", suspend)
        self.assertIn("if (uvm_suspended)", suspend)
        self.assertIn("rollback_status = cleanup_status;", suspend)

        self.assertIn('sizeof("channels\\n")', procfs)
        self.assertIn('strcasecmp(kbuf, "channels")', procfs)
        self.assertIn('seq_printf(m, "default modeset uvm channels\\n");', procfs)
        with self.assertRaisesRegex(ValueError, "contract"):
            MODULE.transform_pm_channel_depth_r595(
                (base / "nv.c").read_text(), (base / "nv-procfs.c").read_text(),
                patch.replace('strcasecmp(kbuf, "channels")',
                              'strcasecmp(kbuf, "new-mode")'))

    def test_pm_vma_access_wrapper_preserves_the_r595_callback_contract(self):
        patch = (ROOT / "patches/r580.178.04/"
                 "0033-private-open-pm-vma-access-guard.patch").read_text()
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia/nv-mmap.c")
        changed = MODULE.transform_pm_vma_access_r595(source.read_text(), patch)
        unlocked = changed[changed.index("static int\nnvidia_vma_access_unlocked("):
                           changed.index("static int\nnvidia_vma_access(\n")]
        wrapper = changed[changed.index("static int\nnvidia_vma_access(\n"):
                          changed.index("static vm_fault_t nvidia_fault(")]
        self.assertIn("static int\nnvidia_vma_access_unlocked(", unlocked)
        self.assertIn("down_read_trylock(&nv_system_pm_lock)", wrapper)
        self.assertIn("return -EAGAIN;", wrapper)
        self.assertIn("nvidia_vma_access_unlocked(vma, addr, buffer, length, write)",
                      wrapper)
        self.assertIn("up_read(&nv_system_pm_lock);", wrapper)
        self.assertEqual(changed.count("nvidia_vma_access_unlocked("), 2)
        with self.assertRaisesRegex(ValueError, "already adapted"):
            MODULE.transform_pm_vma_access_r595(changed, patch)
        with self.assertRaisesRegex(ValueError, "contract"):
            MODULE.transform_pm_vma_access_r595(
                source.read_text(), patch.replace("down_read_trylock", "down_read"))

    def test_pm_free_list_publication_is_serialized_at_r595_inline_release(self):
        patch = (ROOT / "patches/r580.178.04/"
                 "0034-private-open-vma-free-list-lock.patch").read_text()
        source = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                  "open-gpu-kernel-modules-595.99.02/kernel-open/common/inc/nv-linux.h")
        changed = MODULE.transform_pm_free_list_lock_r595(source.read_text(), patch)
        release = changed[changed.index(
            "static inline NvBool nv_alloc_release("):changed.index(
                "// Default flags for ISRs")]
        lock = release.index("NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, eflags)")
        decrement = release.index("atomic64_dec_and_test(&at->usage_count)")
        insertion = release.index("nvlfp->free_list = at;")
        self.assertLess(lock, decrement)
        self.assertLess(decrement, insertion)
        self.assertEqual(release.count(
            "NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags)"), 2)
        self.assertLess(insertion, release.rindex(
            "NV_SPIN_UNLOCK_IRQRESTORE(&nvlfp->fp_lock, eflags)"))
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_pm_free_list_lock_r595(
                changed.replace("NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, eflags);",
                                "NV_SPIN_LOCK_IRQSAVE(&nvlfp->fp_lock, other);"), patch)

    def test_pm_recovery_provider_adapts_r595_callbacks_and_registered_uvm(self):
        base = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia")
        patch = (ROOT / "patches/r580.178.04/"
                 "0035-private-open-pm-recovery-provider.patch").read_text()
        nv, uvm = MODULE.transform_pm_recovery_provider_r595(
            (base / "nv.c").read_text(), (base / "nv_uvm_interface.c").read_text(), patch)

        provider_include = (
            "#define HYBRID580_PM_PROVIDER_PREFIX hybrid580_open_\n"
            "#define HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER 1\n"
            '#include "hybrid580-pm-provider-kernel.h"\n'
            "#undef HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER\n"
            "#undef HYBRID580_PM_PROVIDER_PREFIX\n")
        self.assertEqual(nv.count(provider_include), 1)
        self.assertLess(nv.index(provider_include), nv.index("int nv_pmops_suspend("))

        resume = nv[nv.index("int nv_pmops_resume("):
                    nv.index("int nv_pmops_freeze(")]
        self.assertIn("nvidia_resume(dev, NV_PM_ACTION_RESUME)", resume)
        self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_RESUME", resume)
        self.assertIn("!= 0 && rc == 0", resume)
        thaw = nv[nv.index("int nv_pmops_thaw("):
                  nv.index("int nv_pmops_restore(")]
        self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_THAW", thaw)
        self.assertIn("? 0 : -EIO", thaw)
        restore = nv[nv.index("int nv_pmops_restore("):
                     nv.index("int nv_pmops_poweroff(")]
        self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_RESTORE", restore)
        self.assertIn("!= 0 && rc == 0", restore)

        self.assertEqual(uvm.count(
            "NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void)"), 3)
        self.assertEqual(uvm.count(
            "NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void)"), 3)
        prototypes = uvm[uvm.index('#include "nv-linux.h"'):
                         uvm.index("#if defined(NV_UVM_ENABLE)")]
        self.assertIn("NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void);",
                      prototypes)
        self.assertIn("NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void);",
                      prototypes)
        enabled_start = uvm.index(
            "NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void)\n{")
        enabled = uvm[enabled_start:
            uvm.index("NV_STATUS nv_uvm_event_interrupt(")]
        self.assertEqual(enabled.count("struct UvmEventsLinux *events;"), 2)
        self.assertEqual(enabled.count("down(&g_pNvUvmEventsLock);"), 2)
        self.assertEqual(enabled.count("up(&g_pNvUvmEventsLock);"), 2)
        self.assertIn("status = NV_ERR_NOT_SUPPORTED;", enabled)
        self.assertIn("events->suspend()", enabled)
        self.assertIn("events->resume()", enabled)
        self.assertNotIn("UvmOpsUvmEvents", enabled)

        disabled = uvm[uvm.index("#else // NV_UVM_ENABLE"):]
        suspend_stub = disabled[disabled.index(
            "NV_STATUS hybrid580_open_nv_uvm_suspend_registered_v1(void)"):
            disabled.index("NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void)")]
        resume_stub = disabled[disabled.index(
            "NV_STATUS hybrid580_open_nv_uvm_resume_registered_v1(void)"):
            disabled.index("#endif // NV_UVM_ENABLE")]
        self.assertIn("return NV_ERR_NOT_SUPPORTED;", suspend_stub)
        self.assertIn("return NV_ERR_NOT_SUPPORTED;", resume_stub)

        with self.assertRaisesRegex(ValueError, "already adapted"):
            MODULE.transform_pm_recovery_provider_r595(nv, uvm, patch)
        drifted_uvm = (base / "nv_uvm_interface.c").read_text()
        suspend_start = drifted_uvm.index("NV_STATUS nv_uvm_suspend(void)")
        resume_start = drifted_uvm.index("NV_STATUS nv_uvm_resume(void)")
        suspend_source = drifted_uvm[suspend_start:resume_start]
        self.assertEqual(suspend_source.count("struct UvmEventsLinux *events;"), 1)
        drifted_uvm = (drifted_uvm[:suspend_start] +
                       suspend_source.replace("struct UvmEventsLinux *events;",
                                              "struct UvmEventsChanged *events;") +
                       drifted_uvm[resume_start:])
        with self.assertRaisesRegex(ValueError, "UVM event structure"):
            MODULE.transform_pm_recovery_provider_r595(
                (base / "nv.c").read_text(), drifted_uvm, patch)

    def test_pm_channel_dpm_modeset_is_exactly_suppressed_for_channels_depth(self):
        base = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
                "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia")
        depth_patch = (ROOT / "patches/r580.178.04/"
                       "0031-private-open-pm-channel-depth.patch").read_text()
        modeset_patch = (ROOT / "patches/r580.178.04/"
                         "0036-private-open-pm-channel-dpm-modeset.patch").read_text()
        nv, _ = MODULE.transform_pm_channel_depth_r595(
            (base / "nv.c").read_text(), (base / "nv-procfs.c").read_text(), depth_patch)
        changed = MODULE.transform_pm_channel_dpm_modeset_r595(nv, modeset_patch)

        resume_start = changed.index("static NV_STATUS\nnv_resume_devices(")
        suspend_start = changed.index("static NV_STATUS\nnv_suspend_devices(")
        resume = changed[resume_start:suspend_start]
        self.assertIn("resume_modeset:\n", resume)
        self.assertIn(
            "if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
            "    {\n"
            "        nvidia_modeset_resume(0);\n"
            "    }", resume)
        self.assertEqual(resume.count("nvidia_modeset_resume(0);"), 1)

        set_power_start = changed.index("NV_STATUS\nnv_set_system_power_state(", suspend_start)
        suspend = changed[suspend_start:set_power_start]
        self.assertIn(
            "if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
            "    {\n"
            "        nvidia_modeset_suspend(0);\n"
            "    }", suspend)
        self.assertIn(
            "if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS)\n"
            "        {\n"
            "            nvidia_modeset_resume(0);\n"
            "        }", suspend)
        self.assertEqual(suspend.count("nvidia_modeset_resume(0);"), 1)
        self.assertEqual(suspend.count("nvidia_modeset_suspend(0);"), 1)

        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_pm_channel_dpm_modeset_r595(
                nv.replace("resume_modeset:", "resume_modeset_changed:"), modeset_patch)

    def test_pm_provider_validates_r595_minor_ownership_through_device_list(self):
        source = (ROOT / "src/hybrid580_pm_provider_kernel.h").read_text()
        changed = MODULE.transform_pm_provider_kernel_r595(source)
        ownership = changed[changed.index(
            "static struct hybrid580_pm_provider_recovery_status *\n"
            "hybrid580_pm_provider_status_for_nvl("):
            changed.index("static nv_linux_state_t *\n"
                          "hybrid580_pm_provider_nvl_from_dev(")]
        self.assertIn("minor > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX", ownership)
        self.assertIn("candidate = nv_linux_devices", ownership)
        self.assertIn("candidate = candidate->next", ownership)
        self.assertIn("if (candidate == nvl)", ownership)
        self.assertNotIn("nv_linux_minor_num_table", ownership)
        self.assertIn("All callers hold nv_linux_devices_lock", ownership)
        with self.assertRaisesRegex(ValueError, "already adapted"):
            MODULE.transform_pm_provider_kernel_r595(changed)
        with self.assertRaisesRegex(ValueError, "anchor"):
            MODULE.transform_pm_provider_kernel_r595(
                source.replace("nv_linux_minor_num_table[minor] != nvl",
                               "nv_linux_minor_bitmap[minor] != nvl"))

    def test_symvers_parser_rejects_duplicates_and_bad_flavors(self):
        rows = "0x1234 foo kernel/export EXPORT_SYMBOL\n0xabcd bar kernel/export EXPORT_SYMBOL_GPL\n"
        self.assertEqual(MODULE.parse_symvers(rows),
                         {"foo": "EXPORT_SYMBOL", "bar": "EXPORT_SYMBOL_GPL"})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            MODULE.parse_symvers(rows + "0x1234 foo kernel/export EXPORT_SYMBOL\n")
        with self.assertRaisesRegex(ValueError, "flavor"):
            MODULE.parse_symvers("0x1234 foo kernel/export EXPORT_SYMBOL_FUTURE\n")

    def test_export_namespace_header_and_contract_are_exact_and_stable(self):
        exports = {"zeta": "EXPORT_SYMBOL_GPL", "alpha": "EXPORT_SYMBOL"}
        first = MODULE.private_export_header(exports)
        self.assertEqual(first, MODULE.private_export_header(exports))
        self.assertLess(first.index("#define alpha "), first.index("#define zeta "))
        expected = {"hybrid580_open_alpha": "EXPORT_SYMBOL",
                    "hybrid580_open_zeta": "EXPORT_SYMBOL_GPL"}
        MODULE.validate_private_exports(exports, expected)
        with self.assertRaisesRegex(ValueError, "explicit APIs"):
            MODULE.validate_private_exports(exports, {"alpha": "EXPORT_SYMBOL"})

    def test_projection_api_exports_are_explicit_and_must_match_exactly(self):
        original = {"alpha": "EXPORT_SYMBOL"}
        expected = {"hybrid580_open_alpha": "EXPORT_SYMBOL",
                    **MODULE.PROJECTION_EXPORTS}
        MODULE.validate_private_exports(original, expected, MODULE.PROJECTION_EXPORTS)
        with self.assertRaisesRegex(ValueError, "explicit APIs"):
            MODULE.validate_private_exports(original, expected)
        with self.assertRaisesRegex(ValueError, "duplicates"):
            MODULE.validate_private_exports(
                {"register_file_projection_v1": "EXPORT_SYMBOL"}, expected,
                {"hybrid580_open_register_file_projection_v1": "EXPORT_SYMBOL"})


if __name__ == "__main__":
    unittest.main()
