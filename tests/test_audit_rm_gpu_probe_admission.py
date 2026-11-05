# SPDX-License-Identifier: MIT
"""Tests for the source-backed PCI to RM HAL admission audit."""

import unittest

from tools.audit_rm_gpu_probe_admission import (
    AUDITED_VERSIONS,
    RELEASE_INPUTS,
    extract_function_body,
    parse_gpu_probe_admission,
)


def sources(*, generic_gate=True, firmware_fallback=True, probe_order=True,
            null_hal_skipped=True, disabled_profile=True):
    pci_gate = (
        "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) "
        "return NV_FALSE; if (rm_is_legacy_device(device, subvendor, subdevice, warning)) "
        "return NV_FALSE; return NV_TRUE;"
        if generic_gate else "return NV_TRUE;"
    )
    firmware_branch = (
        "if (rmStatus != NV_OK) { if (!gpumgrIsDeviceRmFirmwareCapable()) "
        "goto threadfree; goto print_unsupported; } "
        "rmStatus = rm_is_vgpu_supported_device(); goto threadfree; "
        "print_unsupported: ; threadfree: return rmStatus;"
        if firmware_fallback else
        "if (rmStatus != NV_OK) { goto threadfree; } "
        "rmStatus = rm_is_vgpu_supported_device(); goto threadfree; "
        "print_unsupported: ; threadfree: return rmStatus;"
    )
    probe_calls = (
        "rm_is_supported_pci_device(); pci_enable_device(); "
        "rm_is_supported_device(); rm_init_private_state();"
        if probe_order else
        "pci_enable_device(); rm_is_supported_pci_device(); "
        "rm_init_private_state(); rm_is_supported_device();"
    )
    null_hal = (
        "pHal = pHalMgr->pHalList[i]; if (pHal == NULL) continue; "
        "return NV_ERR_NOT_SUPPORTED;"
        if null_hal_skipped else
        "pHal = pHalMgr->pHalList[i]; return NV_ERR_NOT_SUPPORTED;"
    )
    gv100 = "{ 0x0, 0x0, 0x0 }, // GV100 (disabled)" if disabled_profile else "{ 0x1, 0x2, 0x3 }, // GV100"
    return {
        "kernel-open/nvidia/nv-pci-table.c": """
            struct pci_device_id nv_pci_table[] = {
                { .vendor = PCI_VENDOR_ID_NVIDIA, .device = PCI_ANY_ID,
                  .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID,
                  .class = (PCI_CLASS_DISPLAY_VGA << 8), .class_mask = ~0 },
                { .vendor = PCI_VENDOR_ID_NVIDIA, .device = PCI_ANY_ID,
                  .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID,
                  .class = (PCI_CLASS_DISPLAY_3D << 8), .class_mask = ~0 },
                { }
            };
        """,
        "kernel-open/nvidia/nv-pci.c": f"static int nv_pci_probe_body(void) {{ {probe_calls} }}",
        "src/nvidia/arch/nvalloc/unix/src/osapi.c": (
            "NvBool rm_is_nvidia_gpu_device(void) { "
            "const NvU16 nv_pci_vendor_id = 0x10DE; "
            "const NvU16 nv_pci_id_riva_tnt = 0x0020; "
            "const NvU8 nv_pci_class_display = 0x03; "
            "const NvU8 nv_pci_subclass_display_vga = 0x00; "
            "const NvU8 nv_pci_subclass_display_3d = 0x02; "
            "if (pci_class != nv_pci_class_display) return NV_FALSE; "
            "if ((pci_subclass != nv_pci_subclass_display_vga) && "
            "(pci_subclass != nv_pci_subclass_display_3d)) return NV_FALSE; "
            "if (vendor != nv_pci_vendor_id) return NV_FALSE; "
            "if (device < nv_pci_id_riva_tnt) return NV_FALSE; return NV_TRUE; }\n"
            f"NvBool rm_is_supported_pci_device(void) {{ {pci_gate} }}\n"
            "NvBool rm_is_legacy_device(void) { return NV_FALSE; }\n"
            "NvBool rm_is_legacy_arch(void) { NvBool legacy = NV_FALSE; return legacy; }\n"
            "NV_STATUS rm_is_supported_device(void) { NV_STATUS rmStatus; "
            "rmStatus = halmgrGetHalForGpu(); "
            f"{firmware_branch} }}"
        ),
        "src/nvidia/src/kernel/core/hal_mgr.c": f"NV_STATUS halmgrGetHalForGpu_IMPL(void) {{ {null_hal} }}",
        "src/nvidia/generated/rmconfig.h": (
            "#define RMCFG_CHIP_GV10X 1\n"
            f"#define RMCFG_CHIP_GV100 {0 if disabled_profile else 1}\n"
            f"#define RMCFG_CHIP_VOLTA_CLASSIC_GPUS {0 if disabled_profile else 1}\n"
        ),
        "src/nvidia/generated/g_chips2halspec_nvoc.c": "/* no GV100 */\n",
        "src/nvidia/generated/g_hal_register.h": "/* no registerHalModule_GV100 */\n",
        "src/nvidia/generated/g_hal_archimpl.h": gv100,
    }


class RmGpuProbeAdmissionTests(unittest.TestCase):
    def test_audit_covers_every_pinned_openrm_release(self):
        self.assertEqual(AUDITED_VERSIONS, tuple(entry[0] for entry in RELEASE_INPUTS))

    def test_balanced_function_extraction_ignores_comment_and_string_braces(self):
        source = 'static int target(void) { const char *s = "}"; /* } */ return 1; }'
        self.assertIn('return 1;', extract_function_body(source, "target"))

    def test_pinned_source_fixture_finds_missing_gv100_hal_admission(self):
        result = parse_gpu_probe_admission("fixture", sources())
        self.assertTrue(result["pci_table_is_generation_agnostic"])
        self.assertTrue(result["probe_gate_precedes_private_rm_init"])
        self.assertTrue(result["generic_pci_filter_has_no_hal_lookup"])
        self.assertTrue(result["rm_support_gate_requires_registered_hal"])
        self.assertTrue(result["firmware_capability_does_not_accept_missing_hal"])
        self.assertTrue(result["generated_profile_disables_gv100"])
        self.assertEqual(
            result["source_conclusion"],
            "generic-pci-match-no-gv100-admission-established-in-audited-generated-openrm-profile",
        )

    def test_audit_fails_closed_when_gate_order_is_changed(self):
        with self.assertRaisesRegex(ValueError, "probe gate order"):
            parse_gpu_probe_admission("fixture", sources(probe_order=False))

    def test_audit_does_not_count_probe_calls_inside_comments(self):
        text = sources()
        path = "kernel-open/nvidia/nv-pci.c"
        text[path] = (
            "static int nv_pci_probe_body(void) { /* "
            "rm_is_supported_pci_device(); pci_enable_device(); "
            "rm_is_supported_device(); rm_init_private_state(); */ return 0; }"
        )
        with self.assertRaisesRegex(ValueError, "probe gate order"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_rejects_a_legacy_architecture_true_return_path(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "NvBool legacy = NV_FALSE; return legacy;",
            "if (runtime) return NV_TRUE; return NV_FALSE;",
        )
        with self.assertRaisesRegex(ValueError, "legacy architecture gate"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_requires_pci_classifier_result_to_gate_admission(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) return NV_FALSE;",
            "rm_is_nvidia_gpu_device(klass, subclass, vendor, device);",
        )
        with self.assertRaisesRegex(ValueError, "generic PCI filter"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_rejects_wrapper_goto_that_bypasses_classifier_guard(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "NvBool rm_is_supported_pci_device(void) { ",
            "NvBool rm_is_supported_pci_device(void) { goto accept; ",
            1,
        ).replace(
            "return NV_TRUE; }\nNvBool rm_is_legacy_device",
            "accept: return NV_TRUE; }\nNvBool rm_is_legacy_device",
            1,
        )
        with self.assertRaisesRegex(ValueError, "unsupported control flow"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_rejects_classifier_guard_with_extra_condition(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) return NV_FALSE;",
            "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device) && NV_FALSE) "
            "return NV_FALSE;",
        )
        with self.assertRaisesRegex(ValueError, "generic PCI filter"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_rejects_classifier_guard_with_true_else_branch(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) return NV_FALSE;",
            "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) "
            "{ return NV_FALSE; } else { return NV_TRUE; }",
        )
        with self.assertRaisesRegex(ValueError, "generic PCI filter"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_rejects_nested_unreachable_classifier_guard(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) return NV_FALSE;",
            "if (NV_FALSE) { if (!rm_is_nvidia_gpu_device(klass, subclass, vendor, device)) "
            "return NV_FALSE; }",
        )
        with self.assertRaisesRegex(ValueError, "generic PCI filter"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_requires_every_pci_class_rejection_branch_to_return_false(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "if (pci_class != nv_pci_class_display) return NV_FALSE;",
            "if (pci_class != nv_pci_class_display) { ; }",
        )
        with self.assertRaisesRegex(ValueError, "generic NVIDIA PCI class checks"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_fails_closed_when_generic_pci_gate_has_hal_lookup(self):
        text = sources()
        text["src/nvidia/arch/nvalloc/unix/src/osapi.c"] = text[
            "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        ].replace(
            "if (rm_is_legacy_device(device, subvendor, subdevice, warning))",
            "halmgrGetHalForGpu(); if (rm_is_legacy_device(device, subvendor, subdevice, warning))",
        )
        with self.assertRaisesRegex(ValueError, "generic PCI filter is not generic"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_fails_closed_if_firmware_capability_bypasses_missing_hal(self):
        with self.assertRaisesRegex(ValueError, "firmware-capability fallback"):
            parse_gpu_probe_admission("fixture", sources(firmware_fallback=False))

    def test_audit_rejects_turning_hal_failure_into_success(self):
        text = sources()
        path = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
        text[path] = text[path].replace(
            "if (rmStatus != NV_OK) {",
            "if (rmStatus != NV_OK) { rmStatus = NV_OK;",
            1,
        )
        with self.assertRaisesRegex(ValueError, "firmware-capability fallback"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_requires_null_hal_slots_to_be_skipped(self):
        text = sources(null_hal_skipped=False)
        with self.assertRaisesRegex(ValueError, "HAL manager no longer"):
            parse_gpu_probe_admission("fixture", text)

    def test_audit_fails_closed_if_generated_profile_is_not_disabled(self):
        with self.assertRaisesRegex(ValueError, "not proven disabled"):
            parse_gpu_probe_admission("fixture", sources(disabled_profile=False))


if __name__ == "__main__":
    unittest.main()
