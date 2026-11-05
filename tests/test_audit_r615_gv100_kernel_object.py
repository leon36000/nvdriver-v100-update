# SPDX-License-Identifier: MIT
"""Tests for the bounded R615/R580 GV100 RM symbol-surface audit."""
from __future__ import annotations

import sys
import unittest

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_r615_gv100_kernel_object import (  # noqa: E402
    VOLTA_CLASS_METADATA,
    compare_gv100_functions,
    parse_gv100_functions,
    parse_readelf_symbols,
)


class R615Gv100KernelObjectAuditTests(unittest.TestCase):
    def test_volta_class_metadata_names_match_rm_symbol_spelling(self):
        self.assertEqual(
            VOLTA_CLASS_METADATA,
            (
                "VOLTA_USERMODE_AParentList",
                "VOLTA_USERMODE_A_RightsRequiredArray",
                "VOLTA_CHANNEL_GPFIFO_AParentList",
                "VOLTA_CHANNEL_GPFIFO_A_RightsRequiredArray",
            ),
        )

    def test_nm_parser_keeps_defined_gv100_functions_and_cold_clones(self):
        output = (
            "0000000000000010 0000000000000004 T busConstruct_GV100\n"
            "0000000000000020 0000000000000003 t mmuFault_GV100.cold\n"
            "                 U unresolved_GV100\n"
            "0000000000000030 0000000000000008 D VOLTA_USERMODE_AParentList\n"
        )

        self.assertEqual(
            parse_gv100_functions(output),
            {"busConstruct_GV100", "mmuFault_GV100.cold"},
        )

    def test_function_comparison_reports_shared_and_branch_only_names(self):
        result = compare_gv100_functions(
            {"a_GV100", "c_GV100"}, {"a_GV100", "b_GV100"}
        )

        self.assertEqual(result["shared"], ["a_GV100"])
        self.assertEqual(result["r615_only"], ["c_GV100"])
        self.assertEqual(result["r580_only"], ["b_GV100"])
        self.assertEqual(result["counts"], {"r615": 2, "r580": 2, "shared": 1})

    def test_readelf_parser_separates_gv100_file_markers_and_symbol_names(self):
        output = (
            "Symbol table '.symtab' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS kern_bus_gv100.c\n"
            "     2: 0000000000000000    32 FUNC    GLOBAL DEFAULT    1 kgmmuFault_GV100\n"
        )

        parsed = parse_readelf_symbols(output)

        self.assertEqual(parsed["gv100_file_markers"], ["kern_bus_gv100.c"])
        self.assertIn("kgmmuFault_GV100", parsed["symbol_names"])
        self.assertEqual(parsed["symbol_types"]["kgmmuFault_GV100"], "FUNC")


if __name__ == "__main__":
    unittest.main()
