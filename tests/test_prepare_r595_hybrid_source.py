# SPDX-License-Identifier: MIT
"""Tests for non-destructive R595 hybrid source preparation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.prepare_r595_hybrid_source import prepare  # noqa: E402


class PrepareR595HybridSourceTests(unittest.TestCase):
    def test_applies_patch_series_without_touching_source_and_pins_manifest(self):
        with tempfile.TemporaryDirectory(prefix="r595-source-prep-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "value.txt").write_text("old\n")
            patch_file = root / "change.patch"
            patch_file.write_text(
                "--- a/value.txt\n+++ b/value.txt\n"
                "@@ -1 +1 @@\n-old\n+new\n"
            )
            destination = root / "candidate"
            report = root / "report.json"

            result = prepare(source, destination, report, [patch_file])

            self.assertEqual(result["status"], "prepared")
            self.assertEqual((source / "value.txt").read_text(), "old\n")
            self.assertEqual((destination / "value.txt").read_text(), "new\n")
            self.assertTrue(result["patches"][0]["zero_offset_zero_fuzz"])
            self.assertEqual(json.loads(report.read_text())["status"], "prepared")
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    def test_refuses_to_overwrite_destination(self):
        with tempfile.TemporaryDirectory(prefix="r595-source-prep-no-overwrite-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            destination = root / "candidate"
            destination.mkdir()
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                prepare(source, destination, root / "report.json", [])


if __name__ == "__main__":
    unittest.main()
