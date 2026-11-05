# SPDX-License-Identifier: MIT
import unittest

from tools.audit_r580_lookup_callsite import parse_disassembly


DISASSEMBLY = """\
Disassembly of section .text:

000000000003c100 <_nv031364rm>:
   3c18c:\t44 89 fe             \tmov    esi,r15d
   3c18f:\t44 89 f7             \tmov    edi,r14d
   3c192:\te8 00 00 00 00       \tcall   3c197 <_nv031364rm+0x97>
\t\t\t3c193: R_X86_64_PC32\t_nv031399rm-0x4
"""


class R580LookupCallsiteAuditTests(unittest.TestCase):
    def test_pins_call_instruction_offset_and_relocation_target(self):
        report = parse_disassembly(DISASSEMBLY)
        self.assertEqual(report["symbol_address"], 0x3C100)
        self.assertEqual(report["call_offset"], 0x92)
        self.assertEqual(report["call_address"], 0x3C192)
        self.assertEqual(report["instruction_bytes"], "e8 00 00 00 00")
        self.assertEqual(report["relocation_address"], 0x3C193)
        self.assertEqual(report["relocation_type"], "R_X86_64_PC32")
        self.assertEqual(report["target_symbol"], "_nv031399rm")
        self.assertEqual(report["addend"], -4)

    def test_rejects_wrong_call_offset(self):
        text = DISASSEMBLY.replace("3c192:", "3c193:").replace(
            "3c193: R_X86_64_PC32", "3c194: R_X86_64_PC32")
        with self.assertRaisesRegex(ValueError, "expected call instruction"):
            parse_disassembly(text)

    def test_rejects_non_call_at_pinned_offset(self):
        text = DISASSEMBLY.replace("e8 00 00 00 00", "90 90 90 90 90")
        with self.assertRaisesRegex(ValueError, "call opcode"):
            parse_disassembly(text)

    def test_rejects_wrong_relocation_target(self):
        text = DISASSEMBLY.replace("_nv031399rm-0x4", "_nv000000rm-0x4")
        with self.assertRaisesRegex(ValueError, "relocation target"):
            parse_disassembly(text)

    def test_rejects_missing_relocation(self):
        text = "\n".join(DISASSEMBLY.splitlines()[:-1])
        with self.assertRaisesRegex(ValueError, "relocation"):
            parse_disassembly(text)


if __name__ == "__main__":
    unittest.main()
