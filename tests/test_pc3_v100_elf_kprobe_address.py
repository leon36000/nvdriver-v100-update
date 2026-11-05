# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/probe_pc3_v100_elf_kprobe_address.py"
SPEC = importlib.util.spec_from_file_location("pc3_v100_elf_kprobe_address", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


HEADER = """ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
"""
SECTIONS = """There are 4 section headers, starting at offset 0x100:
  [Nr] Name              Type             Address           Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL             0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS         0000000000000000 000040 000100 00  AX  0   0 16
  [ 2] .rodata           PROGBITS         0000000000000000 000140 000020 00   A  0   0 16
  [ 3] .bss              NOBITS           0000000000000000 000160 000008 00  WA  0   0  8
"""
SYMBOLS = """Symbol table '.symtab' contains 1 entry:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000010    32 FUNC    GLOBAL DEFAULT    1 rm_init_adapter
"""


class PC3V100ElfKprobeAddressTests(unittest.TestCase):
    def test_readelf_parser_maps_function_offset_to_executable_allocated_section(self):
        parsed = TOOL.parse_readelf_snapshot(HEADER, SECTIONS, SYMBOLS)
        self.assertEqual(parsed["elf_type"], "REL")
        self.assertEqual(parsed["machine"], "Advanced Micro Devices X86-64")
        symbol = parsed["target_symbols"]["rm_init_adapter"][0]
        self.assertEqual(symbol["value"], 0x10)
        self.assertEqual(symbol["size"], 32)
        self.assertEqual(symbol["section"], ".text")
        self.assertTrue(symbol["section_allocated"])
        self.assertTrue(symbol["section_executable"])

    def test_loaded_address_requires_unique_in_bounds_executable_symbol_and_section(self):
        parsed = TOOL.parse_readelf_snapshot(HEADER, SECTIONS, SYMBOLS)
        symbol = parsed["target_symbols"]["rm_init_adapter"][0]
        resolution = TOOL.derive_loaded_address(symbol, "0xffffffffc1234000")
        self.assertTrue(resolution["resolved"])
        self.assertEqual(resolution["address"], 0xFFFFFFFFC1234010)
        self.assertEqual(resolution["section"], ".text")

    def test_loaded_address_rejects_non_kernel_or_malformed_section_base(self):
        parsed = TOOL.parse_readelf_snapshot(HEADER, SECTIONS, SYMBOLS)
        symbol = parsed["target_symbols"]["rm_init_adapter"][0]
        for base in ("not-an-address", "0x0000000000001000"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                TOOL.derive_loaded_address(symbol, base)

    def test_readelf_parser_rejects_unsupported_elf_and_duplicate_target_symbols(self):
        with self.assertRaisesRegex(ValueError, "relocatable"):
            TOOL.parse_readelf_snapshot(HEADER.replace("REL (Relocatable file)", "DYN (Shared object file)"), SECTIONS, SYMBOLS)
        duplicate = SYMBOLS + "     2: 0000000000000020    16 FUNC    GLOBAL DEFAULT    1 rm_init_adapter\n"
        parsed = TOOL.parse_readelf_snapshot(HEADER, SECTIONS, duplicate)
        with self.assertRaisesRegex(ValueError, "unique"):
            TOOL.derive_loaded_address(parsed["target_symbols"]["rm_init_adapter"], "0xffffffffc1234000")

    def test_readelf_parser_rejects_symbol_outside_executable_section(self):
        symbols = SYMBOLS.replace("0000000000000010    32", "00000000000000f0    32")
        parsed = TOOL.parse_readelf_snapshot(HEADER, SECTIONS, symbols)
        with self.assertRaisesRegex(ValueError, "section bounds"):
            TOOL.derive_loaded_address(parsed["target_symbols"]["rm_init_adapter"][0], "0xffffffffc1234000")

    def test_generated_remote_probe_never_enables_and_cleans_each_unique_event(self):
        source = TOOL.guest_probe_script()
        self.assertIn('"nvidia:rm_init_adapter"', source)
        self.assertIn('"0x" + format(address, "x")', source)
        self.assertIn("find_unique_kallsyms_address(CONTROL)", source)
        self.assertIn("KPROBE_EVENTS_ON_NOTRACE", source)
        self.assertIn("pass_fds=(fd,)", source)
        self.assertIn('append_command("-:" + GROUP + "/" + event)', source)
        self.assertIn('enable_value != "0"', source)
        self.assertNotIn('ENABLE.write_text("1")', source)
        self.assertNotIn('"kprobe_attached":False', source)
        self.assertIn('kernel_registration_state"] = "registered_disabled"', source)
        self.assertIn('"handlers_enabled_by_runner":False', source)
        compile(source, "<pc3-v100-elf-kprobe-address>", "exec")

    def test_report_validation_rejects_pointer_leaks_and_uncleaned_probe(self):
        report = TOOL.valid_test_report()
        self.assertEqual(TOOL.validate_report(report)["status"], "completed")
        self.assertEqual(report["kprobe_lifecycle"]["registered_disabled_events"],
                         ["control", "control_absolute"])
        leaked = TOOL.valid_test_report()
        leaked["nvidia_absolute_probe"]["address"] = "0xffffffffc1234010"
        with self.assertRaisesRegex(ValueError, "pointer"):
            TOOL.validate_report(leaked)
        leaked_text = TOOL.valid_test_report()
        leaked_text["nvidia_absolute_probe"]["diagnostic"] = "candidate=0xffffffffc1234010"
        with self.assertRaisesRegex(ValueError, "pointer"):
            TOOL.validate_report(leaked_text)
        uncleaned = TOOL.valid_test_report()
        uncleaned["nvidia_absolute_probe"]["cleanup_verified"] = False
        with self.assertRaisesRegex(ValueError, "cleanup"):
            TOOL.validate_report(uncleaned)

    def test_report_validation_distinguishes_disabled_registration_from_enablement(self):
        report = TOOL.valid_test_report()
        report["control_probe"]["registered_disabled"] = False
        with self.assertRaisesRegex(ValueError, "disabled kprobe registration"):
            TOOL.validate_report(report)
        report = TOOL.valid_test_report()
        report["kprobe_lifecycle"]["handlers_enabled_by_runner"] = True
        with self.assertRaisesRegex(ValueError, "lifecycle"):
            TOOL.validate_report(report)
        report = TOOL.valid_test_report()
        report["kprobe_attached"] = False
        with self.assertRaisesRegex(ValueError, "ambiguous legacy"):
            TOOL.validate_report(report)


if __name__ == "__main__":
    unittest.main()
