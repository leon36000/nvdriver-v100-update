# SPDX-License-Identifier: MIT
"""Fail-closed checks for the pinned R595 UVM consumer REA receipt."""
import unittest

from tools.audit_r595_uvm_p2p_consumer import (
    AuditError,
    EXCERPT_SHA256,
    MODULE_SHA256,
    PROCEDURE,
    UPSTREAM_COMMIT,
    UPSTREAM_SOURCE_SHA256,
    validate_objdump,
    validate_rea_report,
    validate_source_excerpt,
)


VALID_DISASSEMBLY = """\
00000000000116a0 <get_parent_p2p_caps>:
   116a0: e8 00 00 00 00        call   116a5 <get_parent_p2p_caps+0x5>
   116a6: b9 09 00 00 00        mov    $0x9,%ecx
   116a8: 48 89 d7              mov    %rdx,%rdi
   116ab: 4c 89 c0              mov    %r8,%rax
   116ae: 31 c0                 xor    %eax,%eax
   116b0: f3 48 ab              rep stos %rax,(%rdi)
   116b3: 4c 89 c7              mov    %r8,%rdi
   116b6: e8 00 00 00 00        call   116bb <get_parent_p2p_caps+0x1b> 116b7: R_X86_64_PLT32 nvUvmInterfaceGetP2PCaps-0x4
"""


def valid_rea_report():
    return {
        "operation": "procedure_pseudo_code",
        "provider": {"id": "ghidra", "version": "12.1.4"},
        "parameters": {"procedure": PROCEDURE},
        "subject": {"digest": {"sha256": MODULE_SHA256}},
        "evidence_id": "ev_test_p2p_consumer",
        "normalized_result": (
            "NV_STATUS get_parent_p2p_caps() {\n"
            "  nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1);\n"
            "}\n"
        ),
    }


class AuditR595UvmP2pConsumerTests(unittest.TestCase):
    def test_rea_summary_requires_target_provider_and_named_call(self):
        summary = validate_rea_report(valid_rea_report(), MODULE_SHA256)
        self.assertEqual(summary["named_call"], "nvUvmInterfaceGetP2PCaps")
        self.assertFalse(summary["call_signature_reconstructed"])
        self.assertFalse(summary["pseudocode_retained"])
        self.assertNotIn("normalized_result", summary)

    def test_rea_summary_rejects_wrong_target_or_provider(self):
        report = valid_rea_report()
        report["subject"]["digest"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(AuditError, "do not match"):
            validate_rea_report(report, MODULE_SHA256)
        report = valid_rea_report()
        report["provider"]["id"] = "hopper"
        with self.assertRaisesRegex(AuditError, "Ghidra"):
            validate_rea_report(report, MODULE_SHA256)

    def test_rea_summary_rejects_missing_named_call(self):
        report = valid_rea_report()
        report["normalized_result"] = "NV_STATUS get_parent_p2p_caps() { return 0; }"
        with self.assertRaisesRegex(AuditError, "expected P2P call"):
            validate_rea_report(report, MODULE_SHA256)

    def test_disassembly_confirms_zero_fill_and_preserved_third_argument_register(self):
        result = validate_objdump(VALID_DISASSEMBLY)
        self.assertEqual(result["call_relocation"], "nvUvmInterfaceGetP2PCaps")
        self.assertEqual(result["zero_fill_qwords"], 9)
        self.assertEqual(result["zero_fill_bytes"], 72)
        self.assertTrue(result["output_pointer_preserved_through_call"])

    def test_disassembly_rejects_changed_output_pointer_register(self):
        changed = VALID_DISASSEMBLY.replace(
            "mov    %r8,%rdi",
            "xor    %edx,%edx",
        )
        with self.assertRaisesRegex(AuditError, "output pointer register changes"):
            validate_objdump(changed)

    def test_disassembly_rejects_missing_query_relocation_or_zero_fill(self):
        with self.assertRaisesRegex(AuditError, "relocated P2P-capability call"):
            validate_objdump(VALID_DISASSEMBLY.replace("R_X86_64_PLT32", "R_X86_64_PC32"))
        with self.assertRaisesRegex(AuditError, "output initialization"):
            validate_objdump(VALID_DISASSEMBLY.replace("rep stos %rax,(%rdi)", "nop"))

    def test_source_excerpt_is_pinned_to_unmodified_upstream_source(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        excerpt = root / (
            "tests/fixtures/upstream/nvidia-r595-uvm-p2p/595.112.07/"
            "uvm_gpu_p2p_consumer_excerpt.c"
        )
        summary = validate_source_excerpt(excerpt.read_bytes())
        self.assertEqual(summary["excerpt_sha256"], EXCERPT_SHA256)
        self.assertEqual(summary["commit"], UPSTREAM_COMMIT)
        self.assertEqual(summary["full_source_sha256"], UPSTREAM_SOURCE_SHA256)

    def test_source_excerpt_rejects_wrong_hash(self):
        with self.assertRaisesRegex(AuditError, "excerpt hash mismatch"):
            validate_source_excerpt(b"not the pinned source")


if __name__ == "__main__":
    unittest.main()
