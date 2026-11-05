# SPDX-License-Identifier: MIT
"""Tests for the source-only Volta UVM property delta audit."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_volta_uvm_property_delta import (  # noqa: E402
    compare_property_assignments,
    parse_parent_gpu_assignments,
    scan_live_identifier_occurrences,
    strip_c_comments,
)


class VoltaUvmPropertyDeltaTests(unittest.TestCase):
    def test_parses_nested_fields_and_normalizes_assignment_values(self):
        result = parse_parent_gpu_assignments("""
            void init(uvm_parent_gpu_t *parent_gpu) {
                parent_gpu->tlb_batch.max_ranges = 8;
                parent_gpu->peer_copy_mode = UVM_GPU_PEER_COPY_MODE_VIRTUAL;
            }
        """)

        self.assertEqual(result, {
            "tlb_batch.max_ranges": "8",
            "peer_copy_mode": "UVM_GPU_PEER_COPY_MODE_VIRTUAL",
        })

    def test_rejects_duplicate_assignments_for_one_property(self):
        with self.assertRaisesRegex(ValueError, "duplicate assignment"):
            parse_parent_gpu_assignments("""
                void init(uvm_parent_gpu_t *parent_gpu) {
                    parent_gpu->flag = true;
                    parent_gpu->flag = false;
                }
            """)

    def test_rejects_a_function_without_parent_gpu_properties(self):
        with self.assertRaisesRegex(ValueError, "no parent_gpu assignments"):
            parse_parent_gpu_assignments("void init(void) { return; }")

    def test_comment_mentions_do_not_count_as_live_modern_references(self):
        source = "/* old capability */\n// old capability\nint replacement;"
        self.assertNotIn("old capability", strip_c_comments(source))

    def test_assignment_in_a_comment_is_not_parsed_as_a_property(self):
        result = parse_parent_gpu_assignments("""
            void init(uvm_parent_gpu_t *parent_gpu) {
                // parent_gpu->removed = true;
                parent_gpu->kept = false;
            }
        """)
        self.assertEqual(result, {"kept": "false"})

    def test_scans_live_identifier_references_and_reports_relative_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "uvm_volta.c").write_text(
                "// capability_x\nconst char *s = \"capability_x\";\n"
                "parent_gpu->replacement_x = true;\n",
                encoding="utf-8",
            )
            hits = scan_live_identifier_occurrences(root, {"capability_x", "replacement_x"})

        self.assertEqual(hits["capability_x"], [])
        self.assertEqual(hits["replacement_x"], [
            {"path": "uvm_volta.c", "count": 1},
        ])

    def test_delta_distinguishes_absent_names_from_shared_value_changes(self):
        result = compare_property_assignments(
            {"removed": "true", "changed": "1"},
            {"changed": "2", "added": "false"},
            {"removed": [], "changed": [], "added": []},
        )

        self.assertEqual(result["r580_assignment_count"], 2)
        self.assertEqual(result["modern_assignment_count"], 2)
        self.assertEqual(result["r580_only_assignment_count"], 1)
        self.assertEqual(
            result["r580_only_assignments"][0]["modern_live_identifier_occurrence_count"],
            0,
        )
        self.assertEqual(result["common_fields_with_changed_value"], [
            {"field": "changed", "r580_value": "1", "modern_value": "2"},
        ])
        self.assertEqual(result["modern_only_assignments"], {"added": "false"})


if __name__ == "__main__":
    unittest.main()
