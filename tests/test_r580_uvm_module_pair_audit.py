"""Unit tests for the R580 nvidia/nvidia-uvm module-pair audit."""
from __future__ import annotations

import unittest

from tools.audit_r580_uvm_module_pair import (
    compare_uvm_interface,
    parse_module_symvers,
    parse_nm_undefined,
    parse_modinfo,
    summarize_build_log,
)


class R580UvmModulePairAuditTests(unittest.TestCase):
    def test_reads_only_nvidia_uvm_exports_from_selected_provider(self):
        text = (
            "0x00000001\tnvUvmInterfaceRegisterGpu\tnvidia\tEXPORT_SYMBOL\t\n"
            "0x00000002\tnvUvmInterfaceMemoryFree\tnvidia\tEXPORT_SYMBOL_GPL\t\n"
            "0x00000003\tnvUvmInterfaceOther\thybrid580_open\tEXPORT_SYMBOL\t\n"
            "0x00000004\tnvOtherSymbol\tnvidia\tEXPORT_SYMBOL\t\n"
        )
        self.assertEqual(
            parse_module_symvers(text, provider="nvidia"),
            {
                "nvUvmInterfaceRegisterGpu": {"crc": "0x00000001", "export": "EXPORT_SYMBOL"},
                "nvUvmInterfaceMemoryFree": {"crc": "0x00000002", "export": "EXPORT_SYMBOL_GPL"},
            },
        )

    def test_rejects_conflicting_provider_rows(self):
        text = (
            "0x00000001\tnvUvmInterfaceRegisterGpu\tnvidia\tEXPORT_SYMBOL\t\n"
            "0x00000002\tnvUvmInterfaceRegisterGpu\tnvidia\tEXPORT_SYMBOL_GPL\t\n"
        )
        with self.assertRaisesRegex(ValueError, "conflicting provider rows"):
            parse_module_symvers(text, provider="nvidia")

    def test_nm_undefined_symbols_and_exact_interface_closure(self):
        undefined = parse_nm_undefined(
            "                 U nvUvmInterfaceRegisterGpu\n"
            "                 U nvUvmInterfaceMemoryFree\n"
            "                 U printk\n"
            "                 w optional_symbol\n"
        )
        exports = {
            "nvUvmInterfaceRegisterGpu": {"crc": "0x1", "export": "EXPORT_SYMBOL"},
            "nvUvmInterfaceMemoryFree": {"crc": "0x2", "export": "EXPORT_SYMBOL_GPL"},
        }
        interface_imports = {name for name in undefined if name.startswith("nvUvmInterface")}
        result = compare_uvm_interface(interface_imports, exports)
        self.assertTrue(result["all_imports_resolved"])
        self.assertTrue(result["exact_interface_match"])
        self.assertEqual(result["import_count"], 2)
        self.assertEqual(result["unmatched_imports"], [])

    def test_reports_missing_import_without_accepting_a_partial_match(self):
        result = compare_uvm_interface(
            {"nvUvmInterfaceRegisterGpu", "nvUvmInterfaceSessionCreate"},
            {"nvUvmInterfaceRegisterGpu": {"crc": "0x1", "export": "EXPORT_SYMBOL"}},
        )
        self.assertFalse(result["all_imports_resolved"])
        self.assertFalse(result["exact_interface_match"])
        self.assertEqual(result["unmatched_imports"], ["nvUvmInterfaceSessionCreate"])

    def test_modinfo_and_build_log_remain_metadata_not_runtime_claims(self):
        metadata = parse_modinfo(
            "version: 580.178.04\ndepends: nvidia\nlicense: Dual MIT/GPL\n"
            "vermagic: 7.0.0-38-generic SMP preempt mod_unload modversions\n"
        )
        self.assertEqual(metadata["version"], "580.178.04")
        self.assertEqual(metadata["depends"], "nvidia")
        summary = summarize_build_log(
            "MODPOST Module.symvers\n"
            "warning: pahole version differs\n"
            "nvidia.o: warning: objtool: x+0x1: 'naked' return found in MITIGATION_RETHUNK build\n"
            "LD [M] nvidia.ko\nLD [M] nvidia-uvm.ko\n"
        )
        self.assertTrue(summary["has_both_module_link_steps"])
        self.assertEqual(summary["warning_line_count"], 2)
        self.assertEqual(summary["objtool_naked_return_warning_count"], 1)
        self.assertEqual(summary["error_lines"], [])
        with self.assertRaisesRegex(ValueError, "build log contains errors"):
            summarize_build_log("LD [M] nvidia.ko\nmake: *** [target] Error 2\n")


if __name__ == "__main__":
    unittest.main()
