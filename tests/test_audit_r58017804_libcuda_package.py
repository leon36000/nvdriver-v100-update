# SPDX-License-Identifier: MIT
"""Contracts for matching Ubuntu's R580.178.04 libcuda package to PC3 V100."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_r58017804_libcuda_package import (  # noqa: E402
    EXPECTED_GUEST_LIBRARY,
    EXPECTED_PACKAGE,
    compare_library_file,
    _safe_archive_path,
    validate_apt_record,
    validate_guest_observation,
    verify_archive_file,
)


class AuditR58017804LibcudaPackageTests(unittest.TestCase):
    def _guest(self):
        return {
            "schema": "nvidia-hybrid-pc3-v100-libcuda-bounded-window-v1",
            "guest": {
                "name": "pc3-v100",
                "gpu": {"driver_version": "580.178.04"},
                "libcuda": dict(EXPECTED_GUEST_LIBRARY),
            },
        }

    def _apt_fields(self):
        return {
            "Package": EXPECTED_PACKAGE["package"],
            "Version": EXPECTED_PACKAGE["version"],
            "Architecture": EXPECTED_PACKAGE["architecture"],
            "Filename": EXPECTED_PACKAGE["apt_filename"],
            "Size": str(EXPECTED_PACKAGE["size"]),
            "MD5sum": EXPECTED_PACKAGE["md5"],
            "SHA256": EXPECTED_PACKAGE["sha256"],
        }

    def test_accepts_exact_pinned_guest_library_observation(self):
        self.assertEqual(validate_guest_observation(self._guest()), EXPECTED_GUEST_LIBRARY)

    def test_rejects_guest_driver_or_library_hash_drift(self):
        data = self._guest()
        data["guest"]["gpu"]["driver_version"] = "580.196.07"
        with self.assertRaisesRegex(ValueError, "guest identity"):
            validate_guest_observation(data)
        data = self._guest()
        data["guest"]["libcuda"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "library identity"):
            validate_guest_observation(data)

    def test_apt_record_must_match_exact_archive_identity_and_hashes(self):
        fields = self._apt_fields()
        self.assertEqual(validate_apt_record(fields), {
            "package": EXPECTED_PACKAGE["package"],
            "version": EXPECTED_PACKAGE["version"],
            "architecture": EXPECTED_PACKAGE["architecture"],
            "filename": EXPECTED_PACKAGE["filename"],
            "apt_filename": EXPECTED_PACKAGE["apt_filename"],
            "size": EXPECTED_PACKAGE["size"],
            "md5": EXPECTED_PACKAGE["md5"],
            "sha256": EXPECTED_PACKAGE["sha256"],
        })
        fields["Version"] = "580.196.07-1ubuntu1"
        with self.assertRaisesRegex(ValueError, "APT package identity"):
            validate_apt_record(fields)

    def test_rehashes_archive_against_apt_size_md5_and_sha(self):
        payload = b"verified NVIDIA package"
        record = {"size": len(payload), "md5": hashlib.md5(payload).hexdigest(),
                  "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "package.deb"
            path.write_bytes(payload)
            self.assertEqual(verify_archive_file(path, record), {
                "bytes": len(payload), "md5": record["md5"], "sha256": record["sha256"]})
            path.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "archive bytes differ"):
                verify_archive_file(path, record)

    def test_extracted_library_must_match_guest_binary_and_rejects_symlink(self):
        payload = b"the exact guest library"
        expected = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "libcuda.so.580.178.04"
            path.write_bytes(payload)
            self.assertEqual(compare_library_file(path, expected), expected)
            path.unlink()
            target = Path(temporary) / "target"
            target.write_bytes(payload)
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                compare_library_file(path, expected)

    def test_archive_path_rejects_symlinked_parent_even_when_target_stays_inside_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            archive = real / EXPECTED_PACKAGE["filename"]
            archive.write_bytes(b"pinned later")
            (root / "alias").symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                _safe_archive_path(root, root / "alias" / EXPECTED_PACKAGE["filename"])


if __name__ == "__main__":
    unittest.main()
