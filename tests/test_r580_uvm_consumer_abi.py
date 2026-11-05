"""Tests for R580 UVM consumer/frontend module CRC validation."""
from __future__ import annotations

import unittest

from tools.audit_r580_uvm_consumer_abi import (
    compare_crc_tables,
    parse_dump_modversions,
    parse_frontend_symvers,
    summarize_build_log,
    validate_consumer_provider_abi,
)


class R580UvmConsumerAbiTests(unittest.TestCase):
    def test_parses_frontend_exports_and_actual_consumer_versions(self):
        symvers = (
            "0x00a1b2c3\tnvUvmInterfaceRegisterGpu\thybrid580_frontend\tEXPORT_SYMBOL\t\n"
            "0x00000002\tnvUvmInterfaceOther\tother_module\tEXPORT_SYMBOL\t\n"
            "0x00000003\tnvOther\thybrid580_frontend\tEXPORT_SYMBOL\t\n"
        )
        dump = (
            "0x00a1b2c3\tnvUvmInterfaceRegisterGpu\n"
            "0x00000004\tmodule_layout\n"
        )
        exports = parse_frontend_symvers(symvers)
        imports = parse_dump_modversions(dump)
        self.assertEqual(exports, {"nvUvmInterfaceRegisterGpu": "0x00a1b2c3"})
        self.assertEqual(imports, {"nvUvmInterfaceRegisterGpu": "0x00a1b2c3"})
        result = compare_crc_tables(imports, exports)
        self.assertTrue(result["exact_symbol_set_match"])
        self.assertTrue(result["all_crcs_match"])

    def test_parses_standard_nvidia_frontend_provider_by_exact_identity(self):
        symvers = (
            "0x00a1b2c3 nvUvmInterfaceRegisterGpu nvidia EXPORT_SYMBOL\n"
            "0x00000004 nvUvmInterfaceOther hybrid580_frontend EXPORT_SYMBOL\n"
        )
        self.assertEqual(
            parse_frontend_symvers(symvers, provider="nvidia"),
            {"nvUvmInterfaceRegisterGpu": "0x00a1b2c3"},
        )
        with self.assertRaisesRegex(ValueError, "unsupported frontend provider"):
            parse_frontend_symvers(symvers, provider="unrelated")

    def test_crc_mismatch_is_reported(self):
        result = compare_crc_tables(
            {"nvUvmInterfaceRegisterGpu": "0x00000001"},
            {"nvUvmInterfaceRegisterGpu": "0x00000002"},
        )
        self.assertFalse(result["all_crcs_match"])
        self.assertEqual(result["crc_mismatches"][0]["symbol"], "nvUvmInterfaceRegisterGpu")

    def test_missing_or_extra_symbols_fail_exact_set_match(self):
        result = compare_crc_tables(
            {"nvUvmInterfaceRegisterGpu": "0x00000001"},
            {
                "nvUvmInterfaceRegisterGpu": "0x00000001",
                "nvUvmInterfaceSessionCreate": "0x00000002",
            },
        )
        self.assertFalse(result["exact_symbol_set_match"])
        self.assertEqual(result["provider_only_symbols"], ["nvUvmInterfaceSessionCreate"])

    def test_provider_surplus_exports_do_not_break_consumer_abi(self):
        imports = {"nvUvmInterfaceRegisterGpu": "0x00000001"}
        exports = {
            "nvUvmInterfaceRegisterGpu": "0x00000001",
            "nvUvmInterfaceSessionCreate": "0x00000002",
        }
        result = validate_consumer_provider_abi(imports, exports)
        self.assertTrue(result["all_crcs_match"])
        self.assertFalse(result["exact_symbol_set_match"])
        self.assertEqual(result["provider_only_symbols"], ["nvUvmInterfaceSessionCreate"])

    def test_missing_provider_import_and_crc_mismatch_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "imports without provider exports"):
            validate_consumer_provider_abi(
                {"nvUvmInterfaceMissing": "0x00000001"}, {}
            )
        with self.assertRaisesRegex(ValueError, "consumer/provider CRC mismatch"):
            validate_consumer_provider_abi(
                {"nvUvmInterfaceRegisterGpu": "0x00000001"},
                {"nvUvmInterfaceRegisterGpu": "0x00000002"},
            )

    def test_build_log_requires_modpost_and_final_module_link(self):
        good = summarize_build_log(
            "MODPOST Module.symvers\nLD [M] nvidia-uvm.ko\nwarning: pahole mismatch\n"
        )
        self.assertTrue(good["nvidia_uvm_linked"])
        self.assertEqual(good["warning_line_count"], 1)
        with self.assertRaisesRegex(ValueError, "lacks successful"):
            summarize_build_log("CC [M] uvm.o\n")
        renamed = summarize_build_log(
            "MODPOST Module.symvers\nLD [M] hybrid580-uvm.ko\n",
            expected_module="hybrid580-uvm.ko",
        )
        self.assertTrue(renamed["nvidia_uvm_linked"])
        with self.assertRaisesRegex(ValueError, "lacks successful"):
            summarize_build_log(
                "MODPOST Module.symvers\nLD [M] nvidia-uvm.ko\n",
                expected_module="hybrid580-uvm.ko",
            )
        with self.assertRaisesRegex(ValueError, "contains errors"):
            summarize_build_log("MODPOST Module.symvers\nError 2\n")

    def test_rejects_conflicting_module_version_rows(self):
        with self.assertRaisesRegex(ValueError, "conflicting consumer CRC"):
            parse_dump_modversions(
                "0x00000001 nvUvmInterfaceRegisterGpu\n"
                "0x00000002 nvUvmInterfaceRegisterGpu\n"
            )


if __name__ == "__main__":
    unittest.main()
