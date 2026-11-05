# SPDX-License-Identifier: MIT
"""CPU-only firmware acquisition validation; no apt/network/driver execution."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('canary_firmware', ROOT / 'tools/acquire_canary_firmware.py')
firmware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firmware)


class CanaryFirmwareTests(unittest.TestCase):
    def metadata(self):
        return '\n'.join((
            'Package: ' + firmware.PACKAGE, 'Version: ' + firmware.VERSION,
            'Source: ' + firmware.SOURCE_PACKAGE, 'Architecture: amd64',
            'Filename: pool/restricted/n/nvidia-graphics-drivers-580/firmware.deb',
            'Size: 17', 'SHA256: ' + 'a' * 64, 'Description: firmware',
            ' continued description', ''))

    def test_exact_apt_index_record_required(self):
        result = firmware.select_metadata(self.metadata())
        self.assertEqual(result['Package'], firmware.PACKAGE)
        self.assertEqual(result['Description'], 'firmware\ncontinued description')
        for text in ('', self.metadata() + '\n' + self.metadata(),
                     self.metadata().replace(firmware.VERSION, '595.99.02'),
                     self.metadata().replace('Architecture: amd64', 'Architecture: arm64'),
                     self.metadata().replace(firmware.SOURCE_PACKAGE, 'another-source')):
            with self.subTest(text=text[:60]), self.assertRaises(ValueError):
                firmware.select_metadata(text)

    def test_missing_malformed_or_unsafe_index_integrity_is_rejected(self):
        for old, new in [('Size: 17', 'Size: 0'), ('Size: 17', 'Size: unknown'),
                         ('SHA256: ' + 'a' * 64, 'SHA256: bad'),
                         ('pool/restricted/n/nvidia-graphics-drivers-580/firmware.deb', '../../bad.deb'),
                         ('Package: ' + firmware.PACKAGE, 'Package: wrong')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                firmware.select_metadata(self.metadata().replace(old, new))

    def test_file_hash_size_missing_and_symlink_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'original firmware bytes'
            path = root / 'blob.bin'
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            result = firmware.verify_file(path, len(data), digest)
            self.assertEqual(result['sha256'], digest)
            for size, sha in ((len(data) + 1, digest), (len(data), '0' * 64)):
                with self.assertRaises(ValueError):
                    firmware.verify_file(path, size, sha)
            with self.assertRaises(FileNotFoundError):
                firmware.verify_file(root / 'missing', len(data), digest)
            link = root / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                firmware.verify_file(link, len(data), digest)

    def test_blob_and_license_paths_are_confined_to_extracted_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / 'extracted'
            for request in firmware.REQUESTS:
                path = tree / 'usr/lib/firmware' / request
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(request.encode())
            doc = tree / 'usr/share/doc' / firmware.PACKAGE
            doc.mkdir(parents=True)
            (doc / 'copyright').write_text('original license\n')
            blobs, licenses = firmware.inventory_extracted(tree)
            self.assertEqual([row['request'] for row in blobs], list(firmware.REQUESTS))
            self.assertEqual(len(licenses), 1)
            first = Path(blobs[0]['path'])
            first.unlink()
            with self.assertRaises(FileNotFoundError):
                firmware.inventory_extracted(tree)
            outside = root / 'outside'
            outside.write_bytes(b'outside')
            first.symlink_to(outside)
            with self.assertRaises(ValueError):
                firmware.inventory_extracted(tree)


if __name__ == '__main__':
    unittest.main()
