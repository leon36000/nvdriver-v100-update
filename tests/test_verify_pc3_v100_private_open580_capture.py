#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only parser and path contracts for retained PC3 module verification."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/verify_pc3_v100_private_open580_capture.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("verify_pc3_v100_private_open580_capture", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivateOpen580CaptureVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_tool_exists(self):
        self.assertTrue(TOOL_PATH.is_file())

    def test_parses_unique_private_export_records(self):
        exports = self.tool.parse_symvers(
            "0x11111111 hybrid580_open_first /tmp/private.ko EXPORT_SYMBOL\n"
            "0x22222222 hybrid580_open_second /tmp/private.ko EXPORT_SYMBOL_GPL\n")
        self.assertEqual(exports, {"hybrid580_open_first": "EXPORT_SYMBOL",
                                   "hybrid580_open_second": "EXPORT_SYMBOL_GPL"})

    def test_rejects_duplicate_or_invalid_private_export_records(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.tool.parse_symvers(
                "0x11111111 hybrid580_open_first /tmp/private.ko EXPORT_SYMBOL\n"
                "0x22222222 hybrid580_open_first /tmp/private.ko EXPORT_SYMBOL_GPL\n")
        with self.assertRaisesRegex(ValueError, "invalid"):
            self.tool.parse_symvers("0x11111111 public_name /tmp/private.ko EXPORT_SYMBOL_RESTRICTED\n")

    def test_parses_readelf_metadata_strings(self):
        strings = self.tool.parse_readelf_modinfo(
            "  [     0]  name=hybrid580_open\n"
            "  [    20]  license=Dual MIT/GPL\n"
            "  [    38]  alias=pci:v000010DEd*\n")
        self.assertEqual(strings["name"], ["hybrid580_open"])
        self.assertEqual(strings["license"], ["Dual MIT/GPL"])
        self.assertEqual(strings["alias"], ["pci:v000010DEd*"])

    def test_rejects_artifact_paths_outside_the_canonical_project(self):
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.tool.safe_artifact_path("build/../../etc/passwd")
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.tool.safe_artifact_path("/etc/passwd")


if __name__ == "__main__":
    unittest.main()
