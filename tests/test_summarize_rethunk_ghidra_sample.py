# SPDX-License-Identifier: MIT
"""Tests for sanitized Ghidra/objtool RETHUNK correlation evidence."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.summarize_rethunk_ghidra_sample import AuditError, summarize, write_receipt


class GhidraRethunkSampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.object = self.root / "nv-kernel.o_binary"
        self.object.write_bytes(b"synthetic ELF bytes")
        self.log = self.root / "objtool.log"
        self.log.write_text(
            "hybrid580_open.o: warning: objtool: sample_fn+0x6: 'naked' return found in MITIGATION_RETHUNK build\n"
            "hybrid580_open.o: warning: objtool: sample_fn+0x6: 'naked' return found in MITIGATION_RETHUNK build\n"
            "hybrid580_open.o: warning: objtool: other_fn+0x8: 'naked' return found in MITIGATION_RETHUNK build\n"
        )
        self.nm = self.root / "nm-fixture"
        self.nm.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "target=sys.argv[-1]\n"
            "print(f'{target}: 000000 t sample_fn')\n"
            "print(f'{target}: 000010 t sample_fn')\n"
        )
        self.nm.chmod(0o700)
        object_sha256 = hashlib.sha256(self.object.read_bytes()).hexdigest()
        log_sha256 = hashlib.sha256(self.log.read_bytes()).hexdigest()
        self.rea = self.root / "rea-evidence.json"
        self.rea.write_text(json.dumps({
            "operation": "analyze_function",
            "subject": {
                "name": self.object.name,
                "local_path": str(self.object.resolve()),
                "digest": {"sha256": object_sha256},
                "format": "elf",
                "architecture": "x86_64",
            },
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "analysis_profile": {
                "digest": "a" * 64,
                "parameters": {"import_mode": "ephemeral-source-immutable"},
            },
            "normalized_result": {
                "procedure": {
                    "name": "sample_fn",
                    "address": "0x1000",
                    "body": {
                        "available": True,
                        "ranges": [{"start": "0x1000", "end": "0x1006"}],
                        "total_bytes": 7,
                    },
                },
                "assembly": [
                    "0x1000: ENDBR64",
                    "0x1004: XOR EAX, EAX",
                    "0x1006: RET",
                ],
                "pseudocode": "private decompiler text that must not be copied",
            },
        }))
        self.provenance = self.root / "provenance.json"
        self.provenance.write_text(json.dumps({
            "schema": "nvidia-hybrid.rethunk-warning-provenance.v1",
            "status": "ANALYZED_STATICALLY",
            "inputs": {
                "objtool_log_sha256": log_sha256,
                "opaque_object_sha256": object_sha256,
            },
            "classification": {
                "warning_rows": 3,
                "opaque_only_rows": 3,
                "source_only_rows": 0,
                "opaque_and_source_rows": 0,
                "unmatched_rows": 0,
                "match_basis": "defined-symbol-name-only",
            },
        }))

    def tearDown(self):
        self.temp.cleanup()

    def _summarize(self):
        return summarize(self.log, self.object, self.rea, self.provenance,
                         nm_command=str(self.nm))

    def test_correlates_only_matching_ret_and_emits_sanitized_receipt(self):
        receipt = self._summarize()
        analysis = receipt["analysis"]
        self.assertEqual(analysis["function_symbol"], "sample_fn")
        self.assertEqual(analysis["opaque_object_symbol_definitions"], 2)
        self.assertEqual(analysis["objtool_warning_rows_for_symbol"], 2)
        self.assertEqual(analysis["objtool_warning_offsets_for_symbol"], {"0x6": 2})
        self.assertEqual(analysis["ghidra_ret_instruction_offset"], "0x6")
        self.assertEqual(analysis["warning_rows_at_ghidra_ret_offset"], 2)
        self.assertEqual(receipt["status"], "ANALYZED_STATICALLY")
        self.assertNotIn("private decompiler text", json.dumps(receipt))
        self.assertNotIn(str(self.root), json.dumps(receipt))

    def test_rejects_an_artifact_digest_mismatch(self):
        data = json.loads(self.rea.read_text())
        data["subject"]["digest"]["sha256"] = "0" * 64
        self.rea.write_text(json.dumps(data))
        with self.assertRaises(AuditError):
            self._summarize()

    def test_rejects_a_ret_with_no_matching_warning_offset(self):
        self.log.write_text(
            "hybrid580_open.o: warning: objtool: sample_fn+0x5: 'naked' return found in MITIGATION_RETHUNK build\n"
        )
        data = json.loads(self.provenance.read_text())
        data["inputs"]["objtool_log_sha256"] = hashlib.sha256(
            self.log.read_bytes()).hexdigest()
        data["classification"]["warning_rows"] = 1
        data["classification"]["opaque_only_rows"] = 1
        self.provenance.write_text(json.dumps(data))
        with self.assertRaises(AuditError):
            self._summarize()

    def test_rejects_a_provenance_report_from_another_log(self):
        data = json.loads(self.provenance.read_text())
        data["inputs"]["objtool_log_sha256"] = "b" * 64
        self.provenance.write_text(json.dumps(data))
        with self.assertRaises(AuditError):
            self._summarize()

    def test_receipt_creation_refuses_overwrite(self):
        destination = self.root / "receipt.json"
        receipt = self._summarize()
        write_receipt(destination, receipt)
        with self.assertRaises(AuditError):
            write_receipt(destination, {"status": "wrong"})
        self.assertIn('"status": "ANALYZED_STATICALLY"', destination.read_text())


if __name__ == "__main__":
    unittest.main()
