# SPDX-License-Identifier: MIT
"""Offline integrity checks for the staged PC3 NVIDIA package bundle."""
import hashlib
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_pc3_staged_nvidia_bundle import (  # noqa: E402
    _safe_project_input,
    index_installed_packages,
    installed_package_matches,
    main,
    verify_staged_package,
)


class AuditPc3StagedNvidiaBundleTests(unittest.TestCase):
    def _fixture(self, temporary, payload=b"archive-data"):
        root = Path(temporary)
        package = root / ".cache/canary/rollback/package.deb"
        package.parent.mkdir(parents=True)
        package.write_bytes(payload)
        package.chmod(0o640)
        entry = {
            "transaction": "rollback",
            "package": "libnvidia-compute-595",
            "version": "595.99.02-0ubuntu0.26.04.1",
            "architecture": "amd64",
            "filename": "package.deb",
            "size": len(payload),
            "md5_from_apt_uri": hashlib.md5(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        staged = {
            "transaction": entry["transaction"],
            "package": entry["package"],
            "version": entry["version"],
            "architecture": entry["architecture"],
            "filename": entry["filename"],
            "path": ".cache/canary/rollback/package.deb",
            "bytes": len(payload),
            "md5": entry["md5_from_apt_uri"],
            "sha256": entry["sha256"],
        }
        return root, package, entry, staged

    @staticmethod
    def _deb_runner(entry):
        class Result:
            returncode = 0
            stdout = (
                "Package: %s\nVersion: %s\nArchitecture: %s\n"
                % (entry["package"], entry["version"], entry["architecture"])
            )
            stderr = ""

        return lambda *_args, **_kwargs: Result()

    def test_archive_is_rehashed_and_control_identity_checked_without_chmod(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, package, entry, staged = self._fixture(temporary)
            result = verify_staged_package(root, entry, staged, deb_runner=self._deb_runner(entry))
            self.assertEqual(result["sha256"], entry["sha256"])
            self.assertTrue(result["deb_control"]["verified"])
            self.assertEqual(package.stat().st_mode & 0o777, 0o640)

    def test_archive_hash_mismatch_fails_before_control_query(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, package, entry, staged = self._fixture(temporary)
            package.write_bytes(b"tampered archive")
            with self.assertRaisesRegex(ValueError, "archive hash or size"):
                verify_staged_package(root, entry, staged, deb_runner=lambda *_a, **_k: self.fail("must not query"))

    def test_stage_claim_must_match_manifest_and_filename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, _package, entry, staged = self._fixture(temporary)
            staged["version"] = "595.0"
            with self.assertRaisesRegex(ValueError, "stage identity differs"):
                verify_staged_package(root, entry, staged, deb_runner=self._deb_runner(entry))

    def test_symlink_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, package, entry, staged = self._fixture(temporary)
            staged["path"] = ".cache/canary/rollback/link/package.deb"
            link = root / ".cache/canary/rollback/link"
            link.symlink_to(package.parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                verify_staged_package(root, entry, staged, deb_runner=self._deb_runner(entry))

    def test_project_input_resolves_relative_path_and_rejects_symlinks_and_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            report = evidence / "host.json"
            report.write_text("{}")
            self.assertEqual(_safe_project_input(root, Path("evidence/host.json"), "host snapshot"), report)
            (root / "alias").symlink_to(evidence, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink component"):
                _safe_project_input(root, Path("alias/host.json"), "host snapshot")
            with self.assertRaisesRegex(ValueError, "escapes"):
                _safe_project_input(root, Path("../outside.json"), "host snapshot")

    def test_installed_package_index_normalizes_architecture_suffix(self):
        index = index_installed_packages([
            {"name": "libnvidia-compute-595:amd64", "status": "ii", "version": "595.99.02"},
            {"name": "nvidia-driver-other", "status": "rc", "version": "1"},
        ])
        self.assertTrue(installed_package_matches(
            {"package": "libnvidia-compute-595", "version": "595.99.02"}, index))
        self.assertFalse(installed_package_matches(
            {"package": "libnvidia-compute-595", "version": "595.99.03"}, index))
        self.assertFalse(installed_package_matches(
            {"package": "nvidia-driver-other", "version": "1"}, index))

    def test_cli_compares_against_requested_fresh_snapshot(self):
        snapshot = Path("evidence/pc3-current.json")
        output = Path("evidence/audit.json")
        report = {
            "status": "all-staged-archives-reverified",
            "verified_archive_count": 36,
            "rollback_snapshot_comparison": {
                "exact_package_version_matches": 17,
                "expected_package_count": 18,
                "operational_recovery_proven": False,
            },
        }
        with mock.patch("tools.audit_pc3_staged_nvidia_bundle.audit_bundle", return_value=report) as audit_mock, \
                mock.patch("tools.audit_pc3_staged_nvidia_bundle._write_private_exclusive") as write_mock, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--host-snapshot", str(snapshot), "--output", str(output)]), 0)
        audit_mock.assert_called_once_with(host_snapshot_path=snapshot)
        write_mock.assert_called_once_with(output, report)


if __name__ == "__main__":
    unittest.main()
