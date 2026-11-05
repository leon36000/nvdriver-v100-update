# SPDX-License-Identifier: MIT
"""CPU contract tests for the bounded Ghidra callsite metadata parser."""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/analyze_pc3_v100_libcuda_callsite.py"


def load_tool():
    if not TOOL.is_file():
        return None
    spec = importlib.util.spec_from_file_location("pc3_v100_libcuda_callsite", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("callsite analyzer could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ghidra_result(**updates):
    result = {
        "schema": "nvidia-hybrid-ghidra-function-at-rva-v2",
        "status": "function_found",
        "target_rva": "0x48bc88",
        "image_base": "0x10000000",
        "target_address": "0x1048bc88",
        "function_name": "FUN_1048bc50",
        "function_entry": "0x1048bc50",
        "function_end_exclusive": "0x1048bcb1",
        "instruction_count": 23,
        "decompiler_completed": True,
        "incoming_callers": [
            {"source_rva": "0x48a000", "source_function_name": "FUN_0048a000",
             "source_function_entry_rva": "0x48a000", "reference_type": "UNCONDITIONAL_CALL"}
        ],
        "incoming_callers_truncated": False,
        "outgoing_calls": [
            {"source_rva": "0x48bc83", "target_name": "ioctl", "target_rva": None,
             "target_external": True, "reference_type": "UNCONDITIONAL_CALL"}
        ],
        "outgoing_calls_truncated": False,
    }
    result.update(updates)
    return "noise before\nINFO GhidraLocateFunctionAtAddress.java> GHIDRA_RESULT:" + json.dumps(result) + "\nnoise after\n"


def ghidra_result_for_rva(rva, name):
    base = 0x10000000
    entry = rva - 0x40
    end = rva + 0x40
    result = {
        "schema": "nvidia-hybrid-ghidra-function-at-rva-v2",
        "status": "function_found",
        "target_rva": hex(rva),
        "image_base": hex(base),
        "target_address": hex(base + rva),
        "function_name": name,
        "function_entry": hex(base + entry),
        "function_end_exclusive": hex(base + end),
        "instruction_count": 30,
        "decompiler_completed": True,
        "incoming_callers": [],
        "incoming_callers_truncated": False,
        "outgoing_calls": [],
        "outgoing_calls_truncated": False,
    }
    return "GHIDRA_RESULT:" + json.dumps(result)


class Pc3V100LibcudaCallsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def test_parses_only_bounded_metadata_and_derives_function_rva(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        result = self.tool.parse_ghidra_result(ghidra_result(), expected_rva=0x48BC88)
        self.assertEqual(result["function_entry_rva"], "0x48bc50")
        self.assertEqual(result["function_end_rva_exclusive"], "0x48bcb1")
        self.assertEqual(result["function_name"], "FUN_1048bc50")
        self.assertNotIn("pseudocode", result)
        self.assertEqual(result["incoming_callers"][0]["source_function_entry_rva"], "0x48a000")
        self.assertEqual(result["outgoing_calls"][0]["source_rva"], "0x48bc83")

    def test_rejects_malformed_call_reference_metadata(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        bad = ghidra_result()
        bad = bad.replace('"source_rva": "0x48a000"', '"source_rva": "../secret"')
        with self.assertRaisesRegex(ValueError, "call reference"):
            self.tool.parse_ghidra_result(bad, expected_rva=0x48BC88)

    def test_accepts_only_the_known_ghidra_logger_suffix(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        text = ghidra_result().replace("\nnoise after\n", " (GhidraScript)\nnoise after\n")
        result = self.tool.parse_ghidra_result(text, expected_rva=0x48BC88)
        self.assertEqual(result["target_rva"], "0x48bc88")

    def test_rejects_unexpected_text_after_the_metadata_record(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        text = ghidra_result().replace("\nnoise after\n", " source text\nnoise after\n")
        with self.assertRaisesRegex(ValueError, "unexpected suffix"):
            self.tool.parse_ghidra_result(text, expected_rva=0x48BC88)

    def test_rejects_a_result_for_another_target_rva(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        with self.assertRaisesRegex(ValueError, "target RVA"):
            self.tool.parse_ghidra_result(
                ghidra_result(target_rva="0x48bc89"), expected_rva=0x48BC88)

    def test_rejects_a_function_range_that_does_not_contain_the_callsite(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        with self.assertRaisesRegex(ValueError, "does not contain"):
            self.tool.parse_ghidra_result(
                ghidra_result(function_end_exclusive="0x1048bc80"),
                expected_rva=0x48BC88)

    def test_rejects_missing_or_ambiguous_result_records(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        with self.assertRaisesRegex(ValueError, "one Ghidra result"):
            self.tool.parse_ghidra_result("no structured result", expected_rva=0x48BC88)
        with self.assertRaisesRegex(ValueError, "one Ghidra result"):
            self.tool.parse_ghidra_result(
                ghidra_result() + ghidra_result(), expected_rva=0x48BC88)

    def test_rejects_incomplete_decompiler_analysis(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        with self.assertRaisesRegex(ValueError, "decompiler did not complete"):
            self.tool.parse_ghidra_result(
                ghidra_result(decompiler_completed=False), expected_rva=0x48BC88)

    def test_never_returns_decompiler_text(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        raw_text = "proprietary pseudocode must not be retained"
        result = self.tool.parse_ghidra_result(
            ghidra_result(pseudocode=raw_text, decompilation=raw_text),
            expected_rva=0x48BC88)
        self.assertNotIn(raw_text, json.dumps(result))
        self.assertNotIn("decompilation", result)

    def test_parses_multiple_bounded_function_records_in_target_order(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        text = "\n".join((ghidra_result_for_rva(0x495ACC, "FUN_00594f60"),
                           ghidra_result_for_rva(0x4600FC, "FUN_005600b0")))
        results = self.tool.parse_ghidra_results(text, [0x495ACC, 0x4600FC])
        self.assertEqual([item["target_rva"] for item in results],
                         ["0x495acc", "0x4600fc"])
        self.assertEqual([item["function_name"] for item in results],
                         ["FUN_00594f60", "FUN_005600b0"])

    def test_multi_target_parser_rejects_missing_or_ambiguous_records(self):
        self.assertIsNotNone(self.tool, "the Ghidra callsite analyzer is missing")
        first = ghidra_result_for_rva(0x495ACC, "FUN_00594f60")
        second = ghidra_result_for_rva(0x4600FC, "FUN_005600b0")
        with self.assertRaisesRegex(ValueError, "result count"):
            self.tool.parse_ghidra_results(first, [0x495ACC, 0x4600FC])
        with self.assertRaisesRegex(ValueError, "duplicate target"):
            self.tool.parse_ghidra_results(first + "\n" + first, [0x495ACC, 0x4600FC])


if __name__ == "__main__":
    unittest.main()
