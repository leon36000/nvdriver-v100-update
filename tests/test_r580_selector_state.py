# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from audit_r580_selector_state import (  # noqa: E402
    AuditError,
    inspect_source_flow,
    parse_nv_state_layouts,
    resolve_nv_state_layout,
)


DWARF_ONE = """
 <1><1198f>: Abbrev Number: 73 (DW_TAG_structure_type)
    <11990>   DW_AT_name        : (indirect string, offset: 0x34dc): nv_state_t
    <11994>   DW_AT_byte_size   : 784
    <1199a>   DW_AT_sibling     : <0x11d9c>
 <2><1199e>: Abbrev Number: 2 (DW_TAG_member)
    <1199f>   DW_AT_name        : (indirect string, offset: 0x7050): flags
    <119c7>   DW_AT_data_member_location: 16
 <2><11b43>: Abbrev Number: 5 (DW_TAG_member)
    <11b44>   DW_AT_name        : (indirect string, offset: 0x473b): disp_sw_soc_chip_id
    <11b50>   DW_AT_data_member_location: 628
 <2><11d9b>: Abbrev Number: 0
"""


class R580SelectorStateTests(unittest.TestCase):
    def test_extracts_nv_state_member_offsets_from_dwarf(self):
        structures = parse_nv_state_layouts(DWARF_ONE)
        layout = resolve_nv_state_layout(structures, "disp_sw_soc_chip_id")
        self.assertEqual(layout["byte_size"], 784)
        self.assertEqual(layout["member_offsets"]["disp_sw_soc_chip_id"], 628)
        self.assertEqual(layout["copies"], 1)

    def test_accepts_repeated_identical_type_records_from_compilation_units(self):
        layout = resolve_nv_state_layout(
            parse_nv_state_layouts(DWARF_ONE + DWARF_ONE), "disp_sw_soc_chip_id"
        )
        self.assertEqual(layout["copies"], 2)

    def test_rejects_conflicting_duplicate_type_records(self):
        conflicting = DWARF_ONE.replace("location: 628", "location: 624")
        with self.assertRaises(AuditError):
            resolve_nv_state_layout(
                parse_nv_state_layouts(DWARF_ONE + conflicting), "disp_sw_soc_chip_id"
            )

    def test_rejects_missing_or_nonconstant_member_location(self):
        missing = DWARF_ONE.replace("DW_AT_data_member_location: 628", "DW_AT_location: <expr>")
        with self.assertRaises(AuditError):
            resolve_nv_state_layout(parse_nv_state_layouts(missing), "disp_sw_soc_chip_id")

    def test_source_flow_requires_pci_zero_init_and_platform_only_setter(self):
        good = {
            "nv.c": "static int nv_start_device(nv_state_t *nv) { return rm_init_adapter(sp, nv); }",
            "nv-pci.c": "NV_KZALLOC(nvl, sizeof(nv_linux_state_t)); nv = NV_STATE_PTR(nvl);",
            "nv-linux.h": "#define NV_KZALLOC(ptr,size) (ptr) = kzalloc(size)\ntypedef struct nv_linux_state_s { nv_state_t nv_state; }; #define NV_STATE_PTR(nvl) &(((nv_linux_state_t *)(nvl))->nv_state)",
            "nv-platform.c": "static int nv_platform_device_display_probe(void) { of_property_read_u32(node, \"nvidia,disp-sw-soc-chip-id\", &nv->disp_sw_soc_chip_id); }",
            "nv.h": "NvU32 disp_sw_soc_chip_id;",
        }
        self.assertTrue(inspect_source_flow(good)["pci_state"]["initial_value_zero_from_kzalloc"])
        self.assertIsNotNone(inspect_source_flow(good)["pci_state"]["kzalloc_wrapper_line"])
        good["nv-pci.c"] = good["nv-pci.c"].replace("NV_KZALLOC", "NV_KMALLOC")
        with self.assertRaises(AuditError):
            inspect_source_flow(good)


if __name__ == "__main__":
    unittest.main()
