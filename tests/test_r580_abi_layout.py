# SPDX-License-Identifier: MIT
"""Bounded R580 header-layout probe; this test compiles declarations only."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
OPEN_ROOT = (ROOT / "build/experiments/openrm580-baseline-v1/"
             "NVIDIA-kernel-module-source-580.178.04")
PROP_ROOT = (ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/"
             "usr/src/nvidia-580.178.04")

SPEC = importlib.util.spec_from_file_location(
    "r580_abi_layout_probe", ROOT / "tools/probe_r580_abi_layout.py")
PROBE_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE_MODULE)


class R580AbiLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = PROBE_MODULE.probe(OPEN_ROOT, PROP_ROOT)

    def test_report_separates_source_text_compiled_layout_and_binary_rm_abi(self):
        self.assertEqual(self.report["schema"], "nvidia-r580-abi-layout-v1")
        self.assertIn("source_text", self.report)
        self.assertIn("compiled_layout", self.report)
        self.assertIn("binary_rm_abi", self.report)
        self.assertEqual(self.report["binary_rm_abi"]["qualification"],
                         "opaque-not-established")
        self.assertFalse(self.report["binary_rm_abi"]["layout_match_established"])

    def test_actual_open_and_proprietary_declarations_are_compiled_separately(self):
        variants = self.report["compiled_layout"]["variants"]
        self.assertEqual(set(variants), {"open", "proprietary_wrapper"})
        for variant in variants.values():
            for measured in variant["types"].values():
                self.assertEqual(measured["compile"]["exit_code"], 0,
                                 measured["compile"].get("diagnostic", ""))
                self.assertEqual(measured["execution"]["exit_code"], 0,
                                 measured["execution"].get("diagnostic", ""))
                self.assertEqual(measured["qualification"],
                                 "compiled-and-ran-host-layout-probe")
            self.assertIn("NvP64", variant["types"])
            self.assertIn("NvHandle", variant["types"])
            self.assertIn("nvidia_stack_t", variant["types"])
            self.assertIn("nv_state_t", variant["types"])
            self.assertIn("nv_file_private_t", variant["types"])
            for type_name in ("NVOS00_PARAMETERS", "NVOS21_PARAMETERS",
                              "NVOS54_PARAMETERS", "NVOS64_PARAMETERS"):
                self.assertIn(type_name, variant["types"])
        self.assertEqual(set(self.report["compiled_layout"]["layout_comparison"].values()),
                         {"equal"})
        wrappers = self.report["compiled_layout"]["ioctl_wrapper_types"]
        for measured in wrappers["open"]["types"].values():
            self.assertEqual(measured["qualification"],
                             "compiled-and-ran-host-layout-probe",
                             measured["compile"].get("diagnostic", ""))
        self.assertEqual(wrappers["proprietary_wrapper"]["qualification"],
                         "not-available-in-wrapper-source")

    def test_proprietary_missing_sdk_header_is_explicitly_recorded(self):
        sdk = self.report["source_text"]["nvos_header"]
        self.assertTrue(sdk["open_exists"])
        self.assertFalse(sdk["proprietary_wrapper_exists"])
        variants = self.report["compiled_layout"]["variants"]
        self.assertEqual(variants["proprietary_wrapper"]["nvos_declaration_source"],
                         "open-sdk-header-with-proprietary-wrapper-header-search-order")
        guard = self.report["source_text"]["rm_private_declaration_guard"]
        self.assertEqual(guard["macro"], "NVRM")
        self.assertEqual(guard["open_guard_line"], 258)
        self.assertEqual(guard["proprietary_guard_line"], 258)

    def test_text_hashes_and_compiled_layouts_remain_distinct_evidence(self):
        headers = self.report["source_text"]["header_comparisons"]
        self.assertTrue(headers["rm_nv_h"]["exact_equal"])
        self.assertTrue(headers["kernel_nvtypes_h"]["exact_equal"])
        self.assertFalse(headers["nv_linux_h"]["exact_equal"])
        self.assertTrue(self.report["safety"]["inputs_modified"] is False)
        self.assertFalse(self.report["binary_rm_abi"]["layout_match_established"])


if __name__ == "__main__":
    unittest.main()
