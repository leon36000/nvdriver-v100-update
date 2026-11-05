#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for branch-to-branch NVIDIA UVM ioctl dispatch inventory."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.compare_uvm_ioctl_routes import (  # noqa: E402
    R595_UVM_ROOT,
    R615_UVM_ROOT,
    compare_uvm_sources,
    _assess_observed_request,
    parse_uvm_source,
)


class CompareUvmIoctlRoutesTests(unittest.TestCase):
    def _source_tree(self, parent, name, source, header, linux_header=""):
        root = Path(parent) / name
        root.mkdir()
        (root / "uvm.c").write_text(source)
        (root / "uvm_ioctl.h").write_text(header)
        if linux_header is not None:
            (root / "uvm_linux_ioctl.h").write_text(linux_header)
        return root

    def test_branch_snapshot_records_range_group_removal_and_new_routes(self):
        report = compare_uvm_sources(
            R595_UVM_ROOT, R615_UVM_ROOT, "R595.99.02", "R615.78.08")
        removed = {
            "UVM_ALLOW_MIGRATION_RANGE_GROUPS",
            "UVM_CREATE_RANGE_GROUP",
            "UVM_DESTROY_RANGE_GROUP",
            "UVM_MIGRATE_RANGE_GROUP",
            "UVM_PREVENT_MIGRATION_RANGE_GROUPS",
            "UVM_SET_RANGE_GROUP",
        }
        added = {
            "UVM_IMPORT_DMA_BUF",
            "UVM_IS_DMA_BUF_IMPORT_SUPPORTED",
            "UVM_MAP_DMA_BUF",
            "UVM_QUERY_RESIDENCY",
            "UVM_UNMAP_DMA_BUF",
        }
        self.assertEqual(set(report["removed_dispatch_routes"]), removed)
        self.assertEqual(set(report["removed_ioctl_definitions"]), removed)
        self.assertEqual(set(report["added_dispatch_routes"]), added)
        self.assertEqual(set(report["added_ioctl_definitions"]), added)
        self.assertEqual(report["qualification"], "analyzed-statically")
        self.assertFalse(report["runtime_compatibility_proven"])
        self.assertFalse(report["hardware_tested"])

    def test_multiline_dispatch_routes_and_header_definitions_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._source_tree(
                tmp,
                "source",
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(\n    UVM_ONE,\n    handler_one);\n"
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_TWO, handler_two);\n",
                "#define UVM_ONE UVM_IOCTL_BASE(1)\n"
                "#define UVM_TWO UVM_IOCTL_BASE(0x2)\n",
            )
            parsed = parse_uvm_source(root, "fixture")
        self.assertEqual(parsed["route_count"], 2)
        self.assertEqual(parsed["ioctl_definition_count"], 2)
        self.assertEqual(parsed["route_definition_closure"], "closed")

    def test_observed_route_kinds_and_linux_direct_request_definitions_are_included(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._source_tree(
                tmp,
                "source",
                "UVM_ROUTE_CMD_STACK_NO_INIT_CHECK(UVM_INITIALIZE, init_handler);\n"
                "UVM_ROUTE_CMD_ALLOC_INIT_CHECK(UVM_ALLOC, alloc_handler);\n"
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_READY, ready_handler);\n",
                "#define UVM_ALLOC UVM_IOCTL_BASE(7)\n"
                "#define UVM_READY UVM_IOCTL_BASE(8)\n",
                "#define UVM_INITIALIZE 0x30000001\n",
            )
            parsed = parse_uvm_source(root, "fixture")

        self.assertEqual(parsed["route_count"], 1)
        self.assertEqual(parsed["all_route_count"], 3)
        self.assertEqual(parsed["all_routes"]["UVM_INITIALIZE"], "init_handler")
        self.assertEqual(parsed["route_kinds"]["UVM_INITIALIZE"], "UVM_ROUTE_CMD_STACK_NO_INIT_CHECK")
        self.assertEqual(parsed["linux_ioctl_definitions"]["UVM_INITIALIZE"], "0x30000001")
        self.assertEqual(parsed["route_definition_closure"], "closed")

    def test_partial_branch_snapshot_does_not_mislabel_missing_linux_definition_as_no_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._source_tree(
                tmp,
                "partial",
                "UVM_ROUTE_CMD_STACK_NO_INIT_CHECK(UVM_INITIALIZE, init_handler);\n",
                "#define UVM_OTHER UVM_IOCTL_BASE(7)\n",
                linux_header=None,
            )
            parsed = parse_uvm_source(root, "partial fixture")

        self.assertEqual(parsed["route_definition_closure"], "partial")
        result = _assess_observed_request(
            parsed, "UVM_INITIALIZE", 0x30000001, baseline_route_exists=True)
        self.assertEqual(result["status"], "route_present_definition_unavailable")
        self.assertTrue(result["dispatch_present"])
        self.assertFalse(result["ioctl_definition_present"])

    def test_duplicate_dispatch_route_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._source_tree(
                tmp,
                "source",
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ONE, handler_one);\n"
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ONE, handler_two);\n",
                "#define UVM_ONE UVM_IOCTL_BASE(1)\n",
            )
            with self.assertRaisesRegex(ValueError, "duplicate UVM dispatch routes"):
                parse_uvm_source(root, "fixture")

    def test_route_without_ioctl_definition_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._source_tree(
                tmp,
                "source",
                "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_ONE, handler_one);\n",
                "#define UVM_TWO UVM_IOCTL_BASE(2)\n",
            )
            with self.assertRaisesRegex(ValueError, "lack ioctl definitions"):
                parse_uvm_source(root, "fixture")


if __name__ == "__main__":
    unittest.main(verbosity=2)
