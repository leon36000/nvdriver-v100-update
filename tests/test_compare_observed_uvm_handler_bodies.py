#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for hash-pinned comparison of observed UVM handler bodies."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.compare_observed_uvm_handler_bodies import (  # noqa: E402
    compare_observed_handlers,
    extract_nv_status_handler,
    tokenize_c,
)


class CompareObservedUvmHandlerBodiesTests(unittest.TestCase):
    def test_tokenizer_ignores_comments_and_layout_but_preserves_literals(self):
        self.assertEqual(
            tokenize_c('return /* comment */ value; // tail\n'),
            tokenize_c('return value;'),
        )
        self.assertNotEqual(tokenize_c('return "/* text */";'), tokenize_c('return "";'))

    def test_extracts_function_body_with_nested_braces_and_comment_markers(self):
        source = '''
            NV_STATUS selected(int x) {
                const char *text = "}";
                if (x) { /* } */ return NV_OK; }
                return NV_ERR_INVALID_ADDRESS;
            }
            NV_STATUS later(void) { return NV_OK; }
        '''
        body = extract_nv_status_handler(source, "selected")
        self.assertIsNotNone(body)
        self.assertEqual(body["tokens"][0:3], ("NV_STATUS", "selected", "("))
        self.assertEqual(body["end_line"], 6)

    def test_prototype_is_not_mistaken_for_a_function_definition(self):
        self.assertIsNone(extract_nv_status_handler("NV_STATUS selected(int x);", "selected"))

    def test_pinned_stock_trace_comparison_finds_only_free_wrapper_difference(self):
        report = compare_observed_handlers(
            ROOT / "evidence/r580-r595-v100-observed-uvm-route-coverage-v2-20261029.json"
        )
        self.assertEqual(report["qualification"], "analyzed-statically")
        self.assertFalse(report["runtime_or_hardware_validated"])
        self.assertFalse(report["payload_bytes_observed"])
        self.assertEqual(report["observed_handler_count"], 16)
        self.assertEqual(report["token_identical_handler_count"], 15)
        self.assertEqual(report["different_handler_count"], 1)
        differences = [item for item in report["handlers"]
                       if not item["token_sequences_identical"]]
        self.assertEqual([item["handler"] for item in differences], ["uvm_api_free"])
        identical = [item for item in report["handlers"]
                     if item["handler"] == "uvm_api_unregister_channel"]
        self.assertEqual(len(identical), 1)
        self.assertTrue(identical[0]["token_sequences_identical"])
        self.assertEqual(len(report["captures"]), 2)
        self.assertEqual(len(report["source_trees"]["baseline"]["c_files"]), 127)
        self.assertEqual(report["direct_helper_count"], 5)
        self.assertEqual(report["token_identical_direct_helper_count"], 4)
        helper_differences = [item["helper"] for item in report["direct_helpers"]
                              if not item["token_sequences_identical"]]
        self.assertEqual(helper_differences, ["uvm_free"])
        self.assertEqual(report["second_level_nv_status_helper_count"], 8)
        self.assertEqual(report["token_identical_second_level_helper_count"], 6)
        second_level_differences = [
            item["helper"] for item in report["second_level_helpers"]
            if not item["token_sequences_identical"]
        ]
        self.assertEqual(second_level_differences, [
            "uvm_map_external_allocation_on_gpu",
            "uvm_user_channel_create",
        ])
        map_helper = next(
            item for item in report["second_level_helpers"]
            if item["helper"] == "uvm_map_external_allocation_on_gpu"
        )
        self.assertIn("uvm_map_external_allocation", map_helper["directly_called_by_helpers"])


if __name__ == "__main__":
    unittest.main()
