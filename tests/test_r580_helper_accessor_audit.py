# SPDX-License-Identifier: MIT
import unittest

from tools.audit_r580_helper_accessor import (
    EXPECTED_OBJECT_SHA256,
    build_static_helper_report,
    validate_helper_disassembly,
)


HELPER_DISASSEMBLY = """\
0000000000d61270 <_nv049612rm>:
  d61270: f3 0f 1e fa             endbr64
  d61274: 41 55                   push   r13
  d61276: 49 89 f5                mov    r13,rsi
  d61279: 41 54                   push   r12
  d6127b: 53                      push   rbx
  d6127c: 48 83 ed 10             sub    rbp,0x10
  d61280: 89 d3                   mov    ebx,edx
  d61282: 89 de                   mov    esi,ebx
  d61284: 48 8d 55 0f             lea    rdx,[rbp+0xf]
  d61288: c6 45 0f 00             mov    BYTE PTR [rbp+0xf],0x0
  d6128c: e8 00 00 00 00          call   d61291 <_nv049612rm+0x21>
                        d6128d: R_X86_64_PC32 _nv060447rm-0x4
  d61291: 80 7d 0f 00             cmp    BYTE PTR [rbp+0xf],0x0
  d61295: 41 89 c4                mov    r12d,eax
  d61298: 75 11                   jne    d612ab <_nv049612rm+0x3b>
  d6129a: 41 39 5d 10             cmp    DWORD PTR [r13+0x10],ebx
  d6129e: 76 20                   jbe    d612c0 <_nv049612rm+0x50>
  d612a0: 49 8b 45 00             mov    rax,QWORD PTR [r13+0x0]
  d612a4: c1 eb 02                shr    ebx,0x2
  d612a7: 44 8b 24 98             mov    r12d,DWORD PTR [rax+rbx*4]
  d612ab: 5b                      pop    rbx
  d612ac: 44 89 e0                mov    eax,r12d
  d612af: 41 5c                   pop    r12
  d612b1: 41 5d                   pop    r13
  d612b3: 48 83 c5 10             add    rbp,0x10
  d612b7: c3                      ret
  d612c0: be 00 00 f0 07          mov    esi,0x7f00000
  d612c5: bf 0a ad d2 0e          mov    edi,0xed2ad0a
  d612ca: 31 c0                   xor    eax,eax
  d612cc: e8 00 00 00 00          call   d612d1 <_nv049612rm+0x61>
                        d612cd: R_X86_64_PC32 _nv047869rm-0x4
  d612d1: bf f0 07 00 00          mov    edi,0x7f0
  d612d6: e8 00 00 00 00          call   d612db <_nv049612rm+0x6b>
                        d612d7: R_X86_64_PC32 _nv046745rm-0x4
  d612db: 5b                      pop    rbx
  d612dc: 44 89 e0                mov    eax,r12d
  d612df: 41 5c                   pop    r12
  d612e1: 41 5d                   pop    r13
  d612e3: 48 83 c5 10             add    rbp,0x10
  d612e7: c3                      ret
"""

CALLER_DISASSEMBLY = """\
000000000003c100 <_nv031364rm>:
   3cafc: 31 ff                   xor    edi,edi
   3cafe: ba 00 0a 00 00          mov    edx,0xa00
   3cb03: 48 8d 75 50             lea    rsi,[rbp+0x50]
   3cb0a: e8 00 00 00 00          call   3cb0f <_nv031364rm+0xa0f>
                        3cb0b: R_X86_64_PC32 _nv049612rm-0x4
   3cb1a: 41 89 c6                mov    r14d,eax
   3c18f: 44 89 f7                mov    edi,r14d
   3c192: e8 00 00 00 00          call   3c197 <_nv031364rm+0x97>
                        3c193: R_X86_64_PC32 _nv031399rm-0x4
"""


class R580HelperAccessorAuditTests(unittest.TestCase):
    def test_maps_conditional_bounded_word_read_and_fallback(self):
        result = validate_helper_disassembly(HELPER_DISASSEMBLY)
        self.assertEqual(result["symbol"], "_nv049612rm")
        self.assertEqual(result["buffer_offset_input"], "edx -> ebx")
        self.assertEqual(result["bounds_check"], "dword [r13+0x10] > ebx")
        self.assertEqual(result["word_load"], "dword [rax + ((ebx >> 2) * 4)], where rax = qword [r13+0x0]")
        self.assertEqual(result["return_modes"], [
            "saved_nv060447rm_eax_when_local_byte_nonzero",
            "loaded_32_bit_word_when_local_byte_zero_and_in_bounds",
            "saved_nv060447rm_eax_after_bounds_error_logging",
        ])

    def test_rejects_changed_bounds_or_data_index(self):
        changed_bounds = HELPER_DISASSEMBLY.replace(
            "jbe    d612c0", "jae    d612c0"
        )
        with self.assertRaisesRegex(ValueError, "unexpected helper instruction"):
            validate_helper_disassembly(changed_bounds)
        changed_index = HELPER_DISASSEMBLY.replace(
            "shr    ebx,0x2", "shr    ebx,0x1"
        )
        with self.assertRaisesRegex(ValueError, "unexpected helper instruction"):
            validate_helper_disassembly(changed_index)

    def test_rejects_helper_retarget_and_duplicate_relocation(self):
        changed = HELPER_DISASSEMBLY.replace(
            "_nv060447rm-0x4", "_nv060448rm-0x4"
        )
        with self.assertRaisesRegex(ValueError, "helper relocation"):
            validate_helper_disassembly(changed)
        duplicate = HELPER_DISASSEMBLY + (
            "                        d6128d: R_X86_64_PC32 _nv060447rm-0x4\n"
        )
        with self.assertRaisesRegex(ValueError, "helper relocation"):
            validate_helper_disassembly(duplicate)

    def test_report_pins_caller_and_callee_without_runtime_claims(self):
        report = build_static_helper_report(
            EXPECTED_OBJECT_SHA256, HELPER_DISASSEMBLY, CALLER_DISASSEMBLY
        )
        self.assertEqual(report["schema"], "rea-r580-helper-accessor-v1")
        self.assertEqual(report["qualification"], "analyzed_statically")
        self.assertEqual(report["inputs"]["rm_object_sha256"], EXPECTED_OBJECT_SHA256)
        self.assertEqual(report["caller_context"]["caller_offset"], 0xA0A)
        self.assertEqual(report["caller_context"]["argument_sources"]["edx"], "0xa00")
        self.assertEqual(report["caller_context"]["return_capture"], "eax -> r14d")
        self.assertEqual(report["caller_context"]["first_lookup_argument"], "r14d")
        self.assertNotIn("runtime_result", report)
        self.assertFalse(report["inputs"]["runtime_capture_used"])

    def test_report_rejects_wrong_object_or_disassembly(self):
        with self.assertRaisesRegex(ValueError, "pinned R580 object"):
            build_static_helper_report("0" * 64, HELPER_DISASSEMBLY, CALLER_DISASSEMBLY)
        with self.assertRaisesRegex(ValueError, "expected caller relocation"):
            build_static_helper_report(
                EXPECTED_OBJECT_SHA256,
                HELPER_DISASSEMBLY,
                CALLER_DISASSEMBLY.replace("_nv049612rm-0x4", "_nv049613rm-0x4"),
            )


if __name__ == "__main__":
    unittest.main()
