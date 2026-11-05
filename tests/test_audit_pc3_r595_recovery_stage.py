# SPDX-License-Identifier: MIT
"""CPU-only contracts for the offline PC3 R595 archive-set auditor."""

from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from tools import audit_pc3_r595_recovery_stage as recovery_audit
from tools.audit_pc3_r595_recovery_stage import (
    find_package_record,
    parse_control_paragraph,
    parse_packages_index,
    safe_bundle_file,
)


class RecoveryStageAuditContracts(unittest.TestCase):
    def test_historical_stage_annotation_is_separate_from_current_package_observation(self):
        classify = recovery_audit.classify_snapshot_package
        stage_index = {"nvidia-driver-595-open": ["595.99.02"]}
        current_index = {
            "nvidia-driver-595-open": ["595.99.02"],
            "xserver-xorg-video-nvidia-595": ["595.99.02"],
        }
        self.assertEqual(
            classify("xserver-xorg-video-nvidia-595", "595.99.02", stage_index),
            (False, "not-in-snapshot-included-for-metapackage-dependency"),
        )
        self.assertEqual(
            classify("xserver-xorg-video-nvidia-595", "595.99.02", current_index),
            (True, "installed-exact-in-snapshot"),
        )

    def test_stage_creation_snapshot_is_loaded_from_its_manifest_sha_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "evidence").mkdir()
            path = root / "evidence/stage-snapshot.json"
            snapshot = {
                "schema": "nvidia-hybrid-canary-host-state-v2",
                "host": "pc3",
                "kernel_release": "7.0.0-38-generic",
                "loaded_nvidia_module_version": "595.99.02",
                "driver_recovery_inventory": {
                    "package_query_complete": True,
                    "packages": [{"name": "nvidia-driver-595-open",
                                  "status": "ii", "version": "595.99.02"}],
                },
            }
            raw = json.dumps(snapshot, sort_keys=True).encode()
            path.write_bytes(raw)
            metadata = {"path": "evidence/stage-snapshot.json",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "kernel_release": snapshot["kernel_release"],
                        "loaded_nvidia_module_version": snapshot["loaded_nvidia_module_version"]}
            loaded, identity = recovery_audit.load_stage_creation_snapshot(root, metadata)
            self.assertEqual(loaded, snapshot)
            self.assertEqual(identity["sha256"], metadata["sha256"])
            metadata["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                recovery_audit.load_stage_creation_snapshot(root, metadata)

    def test_explicit_host_snapshot_requires_an_exact_sha256_pin(self):
        self.assertTrue(hasattr(recovery_audit, "resolve_host_snapshot_inputs"))
        snapshot_path = Path("evidence/fresh-pc3-state.json")
        snapshot_sha256 = "a" * 64
        self.assertEqual(
            recovery_audit.resolve_host_snapshot_inputs(snapshot_path, snapshot_sha256),
            (snapshot_path, snapshot_sha256),
        )
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            recovery_audit.resolve_host_snapshot_inputs(snapshot_path, None)
        with self.assertRaisesRegex(ValueError, "must be supplied together"):
            recovery_audit.resolve_host_snapshot_inputs(None, snapshot_sha256)
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            recovery_audit.resolve_host_snapshot_inputs(snapshot_path, "A" * 64)

    def test_host_snapshot_identity_requires_complete_pc3_package_inventory(self):
        self.assertTrue(hasattr(recovery_audit, "validate_host_snapshot_identity"))
        snapshot = {
            "schema": "nvidia-hybrid-canary-host-state-v2",
            "host": "pc3",
            "driver_recovery_inventory": {
                "package_query_complete": True,
                "packages": [],
            },
        }
        recovery_audit.validate_host_snapshot_identity(snapshot, "b" * 64, "b" * 64)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            recovery_audit.validate_host_snapshot_identity(snapshot, "b" * 64, "c" * 64)
        for altered in (
            {**snapshot, "host": "pc1"},
            {**snapshot, "driver_recovery_inventory": {"package_query_complete": False}},
            {**snapshot, "schema": "unexpected"},
        ):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                recovery_audit.validate_host_snapshot_identity(altered, "b" * 64, "b" * 64)

    def test_deb822_parser_preserves_folded_dependency_value(self):
        fields = parse_control_paragraph(
            "Package: nvidia-firmware-595\nVersion: 1\nDepends: libc6 (>= 2.34),\n"
            " nvidia-kernel-common-595\nArchitecture: amd64\n")
        self.assertEqual(fields["Depends"], "libc6 (>= 2.34), nvidia-kernel-common-595")

    def test_deb822_parser_rejects_duplicate_keys_and_orphan_continuations(self):
        for paragraph in ("Package: a\nPackage: b\n", " orphan\nPackage: a\n"):
            with self.subTest(paragraph=paragraph), self.assertRaises(ValueError):
                parse_control_paragraph(paragraph)

    def test_package_index_requires_one_exact_identity(self):
        raw = (b"Package: demo\nVersion: 1\nArchitecture: amd64\n"
               b"Filename: pool/demo.deb\nSize: 3\nSHA256: " + b"a" * 64 + b"\n\n")
        rows = parse_packages_index(raw)
        record = find_package_record(rows, "demo", "1", "amd64")
        self.assertEqual(record["Filename"], "pool/demo.deb")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            find_package_record(rows + rows, "demo", "1", "amd64")

    def test_bundle_path_rejects_escape_and_symlink_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "packages").mkdir()
            archive = root / "packages/demo.deb"
            archive.write_bytes(b"deb")
            self.assertEqual(safe_bundle_file(root, "packages/demo.deb"), archive)
            with self.assertRaisesRegex(ValueError, "escapes"):
                safe_bundle_file(root, "../outside.deb")
            link = root / "alias"
            link.symlink_to(root / "packages", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                safe_bundle_file(root, "alias/demo.deb")


if __name__ == "__main__":
    unittest.main()
