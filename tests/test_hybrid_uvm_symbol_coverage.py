# SPDX-License-Identifier: MIT
"""Test the UVM symbol-coverage audit and versioned module import parsing."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "audit_hybrid_uvm_symbol_coverage",
    ROOT / "tools/audit_hybrid_uvm_symbol_coverage.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class HybridUvmSymbolCoverageTests(unittest.TestCase):
    def symbols(self, names, module, prefix=""):
        return {
            prefix + name: {"crc": "0x1234", "module": module, "export": "EXPORT_SYMBOL"}
            for name in names
        }

    def test_parser_reads_only_the_import_version_table(self):
        source = '''
static const struct modversion_info ____versions[] __used = {
    { 0x00001234, "nvUvmInterfaceRegisterGpu" },
    { 0xabcd0001, "schedule" },
};
KSYMTAB_FUNC(nvUvmInterfaceFakeExport, "", "");
'''
        self.assertEqual(AUDIT.parse_module_versions(source), {
            "nvUvmInterfaceRegisterGpu": "0x00001234", "schedule": "0xabcd0001"})

    def test_two_frontend_exports_leave_exact_api_gap_while_backends_are_complete(self):
        names = ["nvUvmInterfaceRegisterGpu", "nvUvmInterfaceUnregisterGpu",
                 "nvUvmInterfaceRegisterUvmCallbacks"]
        versions = {name: "0x1234" for name in names}
        imports = set(names) | {"schedule"}
        result = AUDIT.audit_coverage(
            versions, imports, self.symbols(names, "nvidia"),
            self.symbols([names[-1]], "hybrid580_frontend"),
            self.symbols(names, "hybrid580_open", "hybrid580_open_"),
            self.symbols(names, "hybrid580_legacy", "hybrid580_legacy_"))
        self.assertEqual(result["qualification"], "static-uvm-symbol-coverage-gap")
        self.assertEqual(result["missing_frontend_standard_exports"], names[:2])
        self.assertEqual(result["unresolved_after_frontend"], names[:2])
        self.assertEqual(result["missing_open_private_exports"], [])
        self.assertEqual(result["missing_legacy_private_exports"], [])

    def test_crc_mismatch_and_missing_provider_exports_are_reported(self):
        name = "nvUvmInterfaceRegisterGpu"
        result = AUDIT.audit_coverage(
            {name: "0x1234"}, {name}, self.symbols([name], "nvidia"),
            self.symbols([name], "hybrid580_frontend"),
            {"hybrid580_open_" + name: {"crc": "0xabcd", "module": "open", "export": "EXPORT_SYMBOL"}},
            {})
        self.assertEqual(result["frontend_crc_mismatches"], [])
        self.assertEqual(result["open_private_crc_mismatches"], ["hybrid580_open_" + name])
        self.assertEqual(result["missing_legacy_private_exports"], ["hybrid580_legacy_" + name])

    def test_resident_provider_overlap_is_reported_as_order_sensitive(self):
        imports = {
            "nvUvmInterfaceSameCrc": "0x00000001",
            "nvUvmInterfaceDifferentCrc": "0x00000002",
            "nvUvmInterfaceFrontendOnly": "0x00000003",
        }
        intended = {
            name: {"crc": crc, "module": "hybrid580_frontend", "export": "EXPORT_SYMBOL"}
            for name, crc in imports.items()
        }
        resident = {
            "nvUvmInterfaceSameCrc": {
                "crc": "0x00000001", "module": "nvidia", "export": "EXPORT_SYMBOL"},
            "nvUvmInterfaceDifferentCrc": {
                "crc": "0x000000ff", "module": "nvidia", "export": "EXPORT_SYMBOL"},
        }

        result = AUDIT.audit_global_symbol_precedence(imports, intended, resident)

        self.assertEqual(result["intended_provider_missing"], [])
        self.assertEqual(result["intended_provider_crc_mismatches"], [])
        self.assertEqual(result["matching_crc_overlaps"], ["nvUvmInterfaceSameCrc"])
        self.assertEqual(result["resident_crc_mismatches"], [{
            "symbol": "nvUvmInterfaceDifferentCrc",
            "consumer_crc": "0x00000002",
            "resident_crc": "0x000000ff",
        }])
        self.assertEqual(result["classification"], "order-sensitive-global-symbol-resolution")
        self.assertFalse(result["runtime_or_load_order_observed"])

    def test_no_resident_overlap_is_classified_as_isolated(self):
        imports = {"nvUvmInterfaceRegisterGpu": "0x00001234"}
        intended = {
            "nvUvmInterfaceRegisterGpu": {
                "crc": "0x00001234", "module": "hybrid580_frontend", "export": "EXPORT_SYMBOL"}}
        result = AUDIT.audit_global_symbol_precedence(imports, intended, {})
        self.assertEqual(result["classification"], "no-resident-export-overlap")

    def test_actual_import_set_must_match_modpost_version_array(self):
        with self.assertRaisesRegex(ValueError, "undefined-symbol set differs"):
            AUDIT.audit_coverage({}, {"nvUvmInterfaceRegisterGpu"}, {}, {}, {}, {})


if __name__ == "__main__":
    unittest.main()
