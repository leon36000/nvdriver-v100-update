# SPDX-License-Identifier: MIT
"""Unit tests for the RETHUNK warning provenance summarizer."""

from __future__ import annotations

import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_rethunk_warning_provenance import (
    AuditError,
    audit,
    classify_warnings,
    parse_nm_symbols,
    parse_warnings,
    write_receipt,
)


class WarningParserTests(unittest.TestCase):
    def test_parses_only_exact_rethunk_warning_lines(self):
        text = "\n".join([
            "hybrid.o: warning: objtool: fn_a+0x8: 'naked' return found in MITIGATION_RETHUNK build",
            "hybrid.o: warning: objtool: fn_b+0x10: 'naked' return found in MITIGATION_RETHUNK build",
            "hybrid.o: warning: objtool: other warning",
            "not-an-objtool-line",
        ])
        self.assertEqual(parse_warnings(text), ["fn_a", "fn_b"])

    def test_parses_symbol_table_names_and_ignores_undefined(self):
        self.assertEqual(
            parse_nm_symbols("opaque.o: 000000 T fn_a\nopaque.o: U fn_b\n"),
            {"fn_a"},
        )


class ClassificationTests(unittest.TestCase):
    def test_counts_duplicate_warning_rows_and_unique_names(self):
        result = classify_warnings(["blob_fn", "blob_fn", "src_fn"],
                                   {"blob_fn"}, {"src_fn"})
        self.assertEqual(result["warning_rows"], 3)
        self.assertEqual(result["unique_warning_symbols"], 2)
        self.assertEqual(result["opaque_only_rows"], 2)
        self.assertEqual(result["source_only_rows"], 1)

    def test_separates_overlap_and_unmatched_names(self):
        result = classify_warnings(["both", "missing"], {"both"}, {"both"})
        self.assertEqual(result["opaque_and_source_rows"], 1)
        self.assertEqual(result["unmatched_rows"], 1)
        self.assertEqual(result["match_basis"], "defined-symbol-name-only")


class AuditTests(unittest.TestCase):
    def _fake_nm(self, mapping):
        script = self.root / "nm-fixture"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib,sys\n"
            f"mapping={mapping!r}\n"
            "for arg in sys.argv[1:]:\n"
            " if arg.startswith('-'): continue\n"
            " for name in mapping.get(pathlib.Path(arg).name, []):\n"
            "  print(f'{arg}: 000000 T {name}')\n"
        )
        script.chmod(0o700)
        return str(script)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.src = self.root / "objects"
        self.src.mkdir()
        (self.src / "open.o").write_bytes(b"open-object")
        (self.root / "opaque.o").write_bytes(b"opaque-object")
        self.log = self.root / "build.log"
        self.log.write_text(
            "module.o: warning: objtool: opaque_fn+0x8: 'naked' return found in MITIGATION_RETHUNK build\n"
            "module.o: warning: objtool: open_fn+0xc: 'naked' return found in MITIGATION_RETHUNK build\n"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_audit_emits_only_counts_hashes_and_limits(self):
        nm = self._fake_nm({"opaque.o": ["opaque_fn"], "open.o": ["open_fn"]})
        receipt = audit(self.log, self.root / "opaque.o", self.src, nm_command=nm)
        self.assertEqual(receipt["classification"]["opaque_only_rows"], 1)
        self.assertEqual(receipt["classification"]["source_only_rows"], 1)
        self.assertNotIn("opaque_fn", str(receipt))
        self.assertNotIn("open_fn", str(receipt))
        self.assertEqual(receipt["inputs"]["source_object_count"], 1)

    def test_audit_fails_closed_without_matching_warnings(self):
        self.log.write_text("successful build\n")
        nm = self._fake_nm({})
        with self.assertRaises(AuditError):
            audit(self.log, self.root / "opaque.o", self.src, nm_command=nm)

    def test_receipt_creation_refuses_overwrite(self):
        destination = self.root / "receipt.json"
        write_receipt(destination, {"safe": True})
        with self.assertRaises(AuditError):
            write_receipt(destination, {"safe": False})
        self.assertIn('"safe": true', destination.read_text())


if __name__ == "__main__":
    unittest.main()
