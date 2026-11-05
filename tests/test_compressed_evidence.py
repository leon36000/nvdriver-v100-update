#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for lossless compressed evidence transfer verification."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.verify_compressed_evidence import (
    SCHEMA,
    verify_compressed_evidence,
)


class CompressedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="compressed-evidence-")
        self.root = Path(self.temp.name)
        self.manifest_path = "evidence/compressed-manifest.json"
        self.original = b'{"result":"exact bytes\n","count":4}\n'
        self.stored_path = self.root / "evidence/report.json.gz"
        self.stored_path.parent.mkdir(parents=True)
        self.stored_path.write_bytes(gzip.compress(self.original, mtime=0))
        self._write_manifest(self.original)

    def tearDown(self):
        self.temp.cleanup()

    def _write_manifest(self, original):
        stored = (self.root / "evidence/report.json.gz").read_bytes()
        document = {
            "schema": SCHEMA,
            "manifest_path": self.manifest_path,
            "file_count": 1,
            "files": [{
                "original_path": "evidence/report.json",
                "stored_path": "evidence/report.json.gz",
                "original_size_bytes": len(original),
                "stored_size_bytes": len(stored),
                "original_sha256": hashlib.sha256(original).hexdigest(),
                "stored_sha256": hashlib.sha256(stored).hexdigest(),
            }],
        }
        path = self.root / self.manifest_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")

    def test_verifies_compressed_bytes_and_exact_decompressed_identity(self):
        result = verify_compressed_evidence(self.root, self.manifest_path)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["files_verified"], 1)
        self.assertEqual(result["original_bytes_verified"], len(self.original))

    def test_rejects_compressed_content_tampering(self):
        self.stored_path.write_bytes(self.stored_path.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ValueError, "compressed evidence size differs"):
            verify_compressed_evidence(self.root, self.manifest_path)


if __name__ == "__main__":
    unittest.main()
