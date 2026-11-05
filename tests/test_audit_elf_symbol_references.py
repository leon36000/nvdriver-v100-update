import subprocess
import tempfile
from pathlib import Path
import unittest

from tools.audit_elf_symbol_references import (
    audit,
    parse_relocation_references,
    parse_symbol,
)


class AuditElfSymbolReferencesTests(unittest.TestCase):
    def test_resolves_unique_local_function_symbol(self):
        symbols = """
Symbol table '.symtab' contains 2 entries:
   41: 0000000000b41e90    10 FUNC    LOCAL  DEFAULT    1 _nv020818rm
"""
        self.assertEqual(
            parse_symbol(symbols, "_nv020818rm"),
            {"index": 41, "value": 0xB41E90, "size": 10, "type": "FUNC", "binding": "LOCAL", "section_index": 1},
        )

    def test_relocation_matches_by_exact_symbol_index_and_section_addend(self):
        relocations = """
Relocation section '.rela.text' at offset 0x100 contains 2 entries:
0000000000000010  0000002900000002 R_X86_64_PC32 0000000000000000 _nv020818rm - 4
0000000000000020  0000000100000001 R_X86_64_64 0000000000000000 .text + b41e90
"""
        matches = parse_relocation_references(relocations, symbol_index=41, target_value=0xB41E90)
        self.assertEqual(len(matches), 2)
        self.assertEqual([m["match_kind"] for m in matches], ["symbol-index", "section-addend"])

    def test_ignores_same_named_symbol_with_different_symbol_index(self):
        relocations = """
Relocation section '.rela.data' at offset 0x100 contains 1 entry:
0000000000000030  0000002a00000001 R_X86_64_64 0000000000000000 _nv020818rm + 0
"""
        self.assertEqual(
            parse_relocation_references(relocations, symbol_index=41, target_value=0xB41E90),
            [],
        )

    def test_audit_separates_relocation_operands_from_objdump_annotations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reference.c"
            object_file = root / "reference.o"
            source.write_text("static void target(void) {}\nvoid (*dispatch)(void)=target;\n")
            subprocess.run(["cc", "-c", "-fno-pic", str(source), "-o", str(object_file)],
                           check=True, capture_output=True, text=True)
            report = audit(object_file, "target")
        results = report["results"]
        self.assertIn("annotated_disassembly_reference_count", results)
        self.assertGreaterEqual(results["direct_relocation_reference_count"], 1)
        self.assertNotIn("direct_code_reference_count", results)
        self.assertTrue(any(item["match_kind"] in ("symbol-index", "section-addend")
                            for item in results["direct_relocation_references"]))


if __name__ == "__main__":
    unittest.main()
