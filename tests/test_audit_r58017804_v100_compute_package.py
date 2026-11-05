#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for Ubuntu-signed R580 V100 compute-package matching."""
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/audit_r58017804_v100_compute_package.py"


def load_tool():
    if not TOOL_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("audit_r58017804_v100_compute_package", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ToolAvailability(unittest.TestCase):
    def test_signed_package_match_auditor_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "R580 V100 compute-package auditor is missing")


@unittest.skipUnless(TOOL_PATH.is_file(), "R580 V100 compute-package auditor is missing")
class PackageEvidenceContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_reads_exact_package_record_from_compressed_apt_index(self):
        stanza = (
            "Package: libnvidia-compute-580-server\n"
            "Version: 580.178.04-0ubuntu0.24.04.1\n"
            "Architecture: amd64\n"
            "Filename: pool/restricted/n/nvidia-graphics-drivers-580-server/libnvidia-compute-580-server_580.178.04-0ubuntu0.24.04.1_amd64.deb\n"
            "Size: 59444208\n"
            "SHA256: " + "a" * 64 + "\n"
            "Description: NVIDIA compute libraries\n continued text\n\n"
        ).encode("utf-8")
        fields = self.tool.parse_packages_index(lzma.compress(stanza),
                                                "libnvidia-compute-580-server",
                                                "580.178.04-0ubuntu0.24.04.1", "amd64")
        self.assertEqual(fields["Architecture"], "amd64")
        self.assertEqual(fields["SHA256"], "a" * 64)

    def test_loads_the_hash_pinned_historical_v1_inventory(self):
        raw = self.tool.EXPECTED_GUEST_REPORT.read_bytes()
        capture, inventory = self.tool.load_pinned_legacy_guest_inventory(raw)
        self.assertEqual(capture["schema"], self.tool.GUEST_CAPTURE_SCHEMA)
        self.assertEqual(inventory["schema"], "nvidia-hybrid-pc3-v100-package-inventory-v1")
        self.assertEqual(inventory["hostname"], "pc3-v100")
        self.assertEqual(len(inventory["packages"]), 75)
        self.assertEqual(len(inventory["libraries"]), 54)

    def test_rejects_mutated_historical_inventory_before_package_audit(self):
        capture = json.loads(self.tool.EXPECTED_GUEST_REPORT.read_text())
        capture["guest_inventory"]["packages"][0]["version"] = "forged"
        raw = json.dumps(capture, sort_keys=True).encode()
        with self.assertRaisesRegex(ValueError, "pinned historical guest capture"):
            self.tool.load_pinned_legacy_guest_inventory(raw)

    def test_keyring_snapshot_hashes_the_exact_private_file_used_for_verification(self):
        payload = b"pinned test keyring bytes"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.gpg"
            snapshot = root / "snapshot.gpg"
            source.write_bytes(payload)
            with mock.patch.object(self.tool, "KEYRING", source):
                size, digest = self.tool._snapshot_keyring(snapshot)
            self.assertEqual(size, len(payload))
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual(snapshot.read_bytes(), payload)
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)

    def test_keyring_snapshot_rejects_a_source_replaced_while_reading(self):
        payload = b"original keyring bytes"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.gpg"
            snapshot = root / "snapshot.gpg"
            source.write_bytes(payload)
            original_read = self.tool.os.read
            replaced = False

            def read_and_replace(descriptor, count):
                nonlocal replaced
                data = original_read(descriptor, count)
                if data and not replaced:
                    replacement = root / "replacement.gpg"
                    replacement.write_bytes(b"replacement keyring bytes")
                    replacement.replace(source)
                    replaced = True
                return data

            with mock.patch.object(self.tool, "KEYRING", source), \
                    mock.patch.object(self.tool.os, "read", side_effect=read_and_replace):
                with self.assertRaisesRegex(ValueError, "keyring changed during snapshot"):
                    self.tool._snapshot_keyring(snapshot)

    def test_reads_index_digest_only_from_signed_release_sha256_section(self):
        relative = "restricted/binary-amd64/Packages.xz"
        release = ("Origin: Ubuntu\nSHA256:\n " + "b" * 64 + " 123 " + relative +
                   "\nSHA512:\n " + "c" * 128 + " 123 " + relative + "\n")
        self.assertEqual(self.tool.parse_release_sha256(release, relative), (123, "b" * 64))

    def test_rejects_a_packages_index_without_the_exact_pin(self):
        stanza = ("Package: libnvidia-compute-580-server\n"
                  "Version: 580.173.02-0ubuntu0.24.04.1\n"
                  "Architecture: amd64\n\n").encode("utf-8")
        with self.assertRaisesRegex(ValueError, "exact package pin"):
            self.tool.parse_packages_index(lzma.compress(stanza),
                                           "libnvidia-compute-580-server",
                                           "580.178.04-0ubuntu0.24.04.1", "amd64")

    def test_compares_every_package_owned_library_path(self):
        payload = b"same library bytes"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_path = root / "usr/lib/x86_64-linux-gnu/libnvidia-example.so.580"
            file_path.parent.mkdir(parents=True)
            file_path.write_bytes(payload)
            guest = {"packages": [{"name": "libnvidia-compute-580-server:amd64",
                                   "version": "580.178.04-0ubuntu0.24.04.1"}],
                     "libraries": [{"package": "libnvidia-compute-580-server:amd64",
                                    "path": "/usr/lib/x86_64-linux-gnu/libnvidia-example.so.580",
                                    "resolved_path": "/usr/lib/x86_64-linux-gnu/libnvidia-example.so.580",
                                    "is_symlink": False, "bytes": len(payload), "sha256": digest}]}
            comparison = self.tool.compare_package_libraries(
                guest, root, "libnvidia-compute-580-server")
        self.assertEqual(comparison["paths"], 1)
        self.assertEqual(comparison["matched"], 1)
        self.assertEqual(comparison["different"], 0)
        self.assertEqual(comparison["missing"], 0)

    def test_reports_binary_mismatch_instead_of_counting_it_as_a_match(self):
        payload = b"archive binary"
        guest_payload = b"guest binary"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_path = root / "usr/lib/x86_64-linux-gnu/libnvidia-example.so.580"
            file_path.parent.mkdir(parents=True)
            file_path.write_bytes(payload)
            guest = {"packages": [{"name": "libnvidia-compute-580-server:amd64",
                                   "version": "580.178.04-0ubuntu0.24.04.1"}],
                     "libraries": [{"package": "libnvidia-compute-580-server:amd64",
                                    "path": "/usr/lib/x86_64-linux-gnu/libnvidia-example.so.580",
                                    "resolved_path": "/usr/lib/x86_64-linux-gnu/libnvidia-example.so.580",
                                    "is_symlink": False, "bytes": len(guest_payload),
                                    "sha256": hashlib.sha256(guest_payload).hexdigest()}]}
            comparison = self.tool.compare_package_libraries(
                guest, root, "libnvidia-compute-580-server")
        self.assertEqual(comparison["matched"], 0)
        self.assertEqual(comparison["different"], 1)

    def test_rejects_extracted_package_symlink_escaping_audit_directory(self):
        payload = b"guest library"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_path = root / "usr/lib/x86_64-linux-gnu/libnvidia-example.so.580"
            file_path.parent.mkdir(parents=True)
            file_path.symlink_to("/etc/passwd")
            guest = {"packages": [{"name": "libnvidia-compute-580-server:amd64",
                                   "version": "580.178.04-0ubuntu0.24.04.1"}],
                     "libraries": [{"package": "libnvidia-compute-580-server:amd64",
                                    "path": "/usr/lib/x86_64-linux-gnu/libnvidia-example.so.580",
                                    "resolved_path": "/etc/passwd", "is_symlink": True,
                                    "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}]}
            with self.assertRaisesRegex(ValueError, "escapes the extraction directory"):
                self.tool.compare_package_libraries(guest, root, "libnvidia-compute-580-server")


if __name__ == "__main__":
    unittest.main()
