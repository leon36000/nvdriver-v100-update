# SPDX-License-Identifier: MIT
"""Reject misleading compiler/disassembly evidence for the bounded RM experiment."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "return_thunk_builder", ROOT / "tools/build_open580_return_thunk.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)

BASE = """00000000 <witness>:
   0: f3 0f 1e fa          endbr64
   4: 31 c0                xor %eax,%eax
   6: c3                   ret
"""
THUNK = """00000000 <witness>:
   0: f3 0f 1e fa          endbr64
   4: 31 c0                xor %eax,%eax
   6: e9 00 00 00 00       jmp b <witness+0xb>
            7: R_X86_64_PLT32 __x86_return_thunk-0x4
"""


class ReturnThunkEvidenceTests(unittest.TestCase):
    def test_exact_build_flags_use_existing_hook(self):
        cmd = BUILDER.build_command(Path("/scratch/source"), 4)
        self.assertIn("EXTRA_CFLAGS=-mfunction-return=thunk-extern", cmd)
        self.assertIn("NV_VERBOSE=1", cmd)
        self.assertFalse(any(x.startswith("CFLAGS=") for x in cmd))
        self.assertFalse(any("objtool" in x.lower() for x in cmd))
        with self.assertRaises(ValueError):
            BUILDER.build_command(Path("/scratch/source"), 0)

    def test_actual_return_requires_branch_relocation(self):
        self.assertTrue(BUILDER.disassembly_evidence(BASE, "witness")["raw_return"])
        row = BUILDER.disassembly_evidence(THUNK, "witness")
        self.assertFalse(row["raw_return"])
        self.assertTrue(row["return_thunk_jump"])
        # A symbol mentioned elsewhere does not prove the return was hardened.
        unrelated = BASE + "00000010 <other>:\n  11: R_X86_64_PLT32 __x86_return_thunk-0x4\n"
        self.assertFalse(BUILDER.disassembly_evidence(unrelated, "witness")["return_thunk_jump"])
        call = THUNK.replace("jmp b", "call b")
        self.assertFalse(BUILDER.disassembly_evidence(call, "witness")["return_thunk_jump"])
        off = THUNK.replace("7: R_X86", "17: R_X86")
        self.assertFalse(BUILDER.disassembly_evidence(off, "witness")["return_thunk_jump"])
        with self.assertRaises(ValueError):
            BUILDER.disassembly_evidence(THUNK, "missing")

    def test_compiler_flag_must_exist_on_every_c_compile(self):
        good = "cc -O2 -mfunction-return=thunk-extern -c generated/foo.c -o foo.o\n"
        self.assertEqual(BUILDER.audit_compile_commands(good)["c_compile_count"], 1)
        for text in ("EXTRA_CFLAGS=-mfunction-return=thunk-extern\n", good + "cc -c plain.c -o plain.o\n"):
            with self.assertRaises(ValueError):
                BUILDER.audit_compile_commands(text)


if __name__ == "__main__":
    unittest.main()
