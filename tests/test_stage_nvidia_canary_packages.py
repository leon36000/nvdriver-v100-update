# SPDX-License-Identifier: MIT
"""Integrity and path-safety contracts for the offline NVIDIA canary cache."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.stage_nvidia_canary_packages import (  # noqa: E402
    download_package,
    load_manifest,
    validate_package_entries,
    verify_deb_metadata,
)


class StageNvidiaCanaryPackagesTests(unittest.TestCase):
    def _entry(self, payload=b"verified-package-bytes"):
        filename = "nvidia-driver-test_580.1-1_amd64.deb"
        return {
            "transaction": "target",
            "package": "nvidia-driver-test",
            "version": "580.1-1",
            "architecture": "amd64",
            "filename": filename,
            "url": "https://developer.download.nvidia.com/repo/" + filename,
            "size": len(payload),
            "md5_from_apt_uri": hashlib.md5(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def test_validates_pinned_package_entry(self):
        entries = [self._entry()]
        self.assertEqual(validate_package_entries(entries), entries)

    def test_rejects_path_traversal_and_non_official_hosts(self):
        entry = self._entry()
        entry["filename"] = "../escape.deb"
        with self.assertRaisesRegex(ValueError, "safe basename"):
            validate_package_entries([entry])
        entry = self._entry()
        entry["url"] = entry["url"].replace("developer.download.nvidia.com", "example.invalid")
        with self.assertRaisesRegex(ValueError, "unapproved package host"):
            validate_package_entries([entry])

    def test_rejects_duplicate_names_and_bool_sizes(self):
        entry = self._entry()
        with self.assertRaisesRegex(ValueError, "duplicate package"):
            validate_package_entries([entry, dict(entry)])
        entry = self._entry()
        entry["size"] = True
        with self.assertRaisesRegex(ValueError, "positive integer"):
            validate_package_entries([entry])

    def test_download_hash_checks_and_sets_private_permissions(self):
        payload = b"verified-package-bytes"
        entry = self._entry(payload)
        with tempfile.TemporaryDirectory() as temporary:
            result = download_package(entry, Path(temporary), opener=lambda *_a, **_k: _Response(payload))
            path = Path(temporary) / entry["filename"]
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(result["verified"])
            self.assertEqual(result["sha256"], entry["sha256"])

    def test_size_mismatch_does_not_leave_a_partial_package(self):
        entry = self._entry(b"expected")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "size mismatch"):
                download_package(entry, Path(temporary), opener=lambda *_a, **_k: _Response(b"short"))
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_apt_md5_mismatch_does_not_leave_a_partial_package(self):
        payload = b"expected"
        entry = self._entry(payload)
        entry["md5_from_apt_uri"] = hashlib.md5(b"tampered").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "APT MD5 mismatch"):
                download_package(entry, Path(temporary), opener=lambda *_a, **_k: _Response(b"expected"))
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_hash_mismatch_does_not_leave_a_partial_package(self):
        entry = self._entry(b"expected")
        entry["md5_from_apt_uri"] = hashlib.md5(b"tampered").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                download_package(entry, Path(temporary), opener=lambda *_a, **_k: _Response(b"tampered"))
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_rejects_unapproved_redirect_and_https_downgrade(self):
        payload = b"verified-package-bytes"
        entry = self._entry(payload)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "redirect target"):
                download_package(entry, Path(temporary), opener=lambda *_a, **_k: _Response(
                    payload, "https://example.invalid/evil.deb"))
            with self.assertRaisesRegex(ValueError, "redirect target"):
                download_package(entry, Path(temporary), opener=lambda *_a, **_k: _Response(
                    payload, "http://developer.download.nvidia.com/repo/file.deb"))
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_existing_file_must_match_exact_pinned_hash(self):
        payload = b"verified-package-bytes"
        entry = self._entry(payload)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / entry["filename"]
            path.write_bytes(payload)
            path.chmod(0o600)
            result = download_package(entry, Path(temporary), opener=lambda *_a, **_k: self.fail("network must not be used"))
            self.assertTrue(result["already_present"])
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "existing file hash mismatch"):
                download_package(entry, Path(temporary), opener=lambda *_a, **_k: self.fail("network must not be used"))

    def test_checked_in_manifest_matches_the_reviewed_package_plan(self):
        from tools.stage_nvidia_canary_packages import load_manifest
        manifest, digest = load_manifest()
        self.assertEqual(digest, "8aa76d874bf9ebbf9fe0c5528b4fdeb9f932b17115232b0cdbb14f5470f6e764")
        self.assertEqual(manifest["package_count"], 36)
        self.assertEqual(manifest["transactions"]["target"]["bytes"], 312428150)
        self.assertEqual(manifest["transactions"]["rollback"]["bytes"], 247417522)

    def test_manifest_hash_is_checked_before_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text("not json")
            with self.assertRaisesRegex(ValueError, "manifest SHA-256 mismatch"):
                load_manifest(path, expected_sha256="0" * 64)

    def test_deb_metadata_must_match_manifest_without_running_scripts(self):
        entry = self._entry()
        calls = []

        class Result:
            returncode = 0
            stdout = "Package: nvidia-driver-test\nVersion: 580.1-1\nArchitecture: amd64\n"
            stderr = ""

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return Result()

        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / entry["filename"]
            package.write_bytes(b"data")
            result = verify_deb_metadata(package, entry, runner=runner)
        self.assertTrue(result["verified"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][0:2], ["dpkg-deb", "--field"])
        self.assertNotIn("--extract", calls[0][0])


class _Response:
    def __init__(self, payload, final_url=None):
        self.payload = payload
        self.final_url = final_url
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self.final_url

    def read(self, size=-1):
        if size < 0:
            size = len(self.payload) - self.offset
        result = self.payload[self.offset:self.offset + size]
        self.offset += len(result)
        return result


if __name__ == "__main__":
    unittest.main()
