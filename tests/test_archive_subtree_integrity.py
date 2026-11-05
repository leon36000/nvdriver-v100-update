# SPDX-License-Identifier: MIT
"""Tests for exact archive-subtree provenance checks."""
from pathlib import Path
import os
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_archive_subtree_integrity import (  # noqa: E402
    _write_private_report,
    compare_archive_subtree,
    source_manifest_sha256,
)


class ArchiveSubtreeIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "package.tar.gz"
        self.tree = self.root / "extracted"
        self.tree.mkdir()
        (self.tree / "a.c").write_bytes(b"alpha\n")
        (self.tree / "sub").mkdir()
        (self.tree / "sub/b.h").write_bytes(b"beta\n")
        self._write_archive([
            ("package/kernel-open/a.c", b"alpha\n", "file"),
            ("package/kernel-open/sub/b.h", b"beta\n", "file"),
        ])

    def tearDown(self):
        self.temp.cleanup()

    def _write_archive(self, entries):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = data.decode()
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    import io
                    archive.addfile(info, io.BytesIO(data))

    def _compare(self):
        return compare_archive_subtree(
            self.archive,
            "package/kernel-open",
            self.tree,
        )

    def test_matches_exact_files_and_records_path_sensitive_manifest(self):
        report = self._compare()

        self.assertTrue(report["byte_for_byte_match"])
        self.assertEqual(report["archive_file_count"], 2)
        self.assertEqual(report["extracted_file_count"], 2)
        self.assertEqual(report["archive_manifest_sha256"], report["extracted_manifest_sha256"])
        self.assertEqual(report["missing_from_extracted"], [])
        self.assertEqual(report["extra_in_extracted"], [])
        self.assertEqual(report["changed_files"], [])
        self.assertFalse(report["filesystem_metadata_compared"])
        self.assertNotEqual(
            source_manifest_sha256({"a.c": b"x"}),
            source_manifest_sha256({"renamed.c": b"x"}),
        )

    def test_reports_missing_extra_and_modified_files_without_claiming_match(self):
        (self.tree / "a.c").unlink()
        (self.tree / "sub/b.h").write_bytes(b"modified\n")
        (self.tree / "extra.c").write_bytes(b"extra\n")

        report = self._compare()

        self.assertFalse(report["byte_for_byte_match"])
        self.assertEqual(report["missing_from_extracted"], ["a.c"])
        self.assertEqual(report["extra_in_extracted"], ["extra.c"])
        self.assertEqual(report["changed_files"], ["sub/b.h"])

    def test_expected_archive_hash_is_part_of_overall_match(self):
        with self.assertRaisesRegex(ValueError, "archive SHA-256 mismatch"):
            compare_archive_subtree(
                self.archive,
                "package/kernel-open",
                self.tree,
                expected_archive_sha256="0" * 64,
            )

    def test_rejects_duplicate_archive_paths(self):
        self._write_archive([
            ("package/kernel-open/a.c", b"one", "file"),
            ("package/kernel-open/a.c", b"two", "file"),
        ])

        with self.assertRaisesRegex(ValueError, "duplicate archive path"):
            self._compare()

    def test_rejects_unsafe_paths_and_links_inside_subtree(self):
        for entry, message in [
            (("package/kernel-open/../escape.c", b"x", "file"), "unsafe archive path"),
            (("package/kernel-open/link", b"../outside", "symlink"), "non-regular archive member"),
        ]:
            with self.subTest(message=message):
                self._write_archive([entry])
                with self.assertRaisesRegex(ValueError, message):
                    self._compare()

    def test_rejects_symlinks_in_extracted_tree(self):
        target = self.root / "outside"
        target.write_bytes(b"outside")
        link = self.tree / "link"
        link.symlink_to(target)

        with self.assertRaisesRegex(ValueError, "symlink in extracted tree"):
            self._compare()

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is platform-specific")
    def test_private_report_writer_rejects_leaf_symlink_without_touching_target(self):
        outside = self.root / "outside.json"
        outside.write_text("preserve me\n", encoding="utf-8")
        link = self.root / "report.json"
        link.symlink_to(outside)

        with self.assertRaises(OSError):
            _write_private_report(link, {"provenance_valid": True})

        self.assertEqual(outside.read_text(encoding="utf-8"), "preserve me\n")

    def test_private_report_writer_sets_mode_0600(self):
        report = self.root / "evidence.json"

        _write_private_report(report, {"ok": True})

        self.assertEqual(report.stat().st_mode & 0o777, 0o600)

if __name__ == "__main__":
    unittest.main()
