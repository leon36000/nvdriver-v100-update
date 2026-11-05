# SPDX-License-Identifier: MIT
"""Verify reproducible, no-overwrite build records for the RM probe."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.build_rm_root_id_probe import build


class RootIdProbeBuildTests(unittest.TestCase):
    def test_build_records_binary_and_transitive_vendor_header_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            output, report_path = work / 'probe', work / 'build.json'
            report = build(output, report_path)
            self.assertEqual(report['qualification'], 'compiled-only-no-driver-execution')
            saved = json.loads(report_path.read_text())
            self.assertEqual(saved['binary_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(saved['source_sha256'], hashlib.sha256(Path(saved['source']).read_bytes()).hexdigest())
            self.assertTrue(any(item['path'].endswith('/src/common/sdk/nvidia/inc/nvos.h')
                                for item in saved['inputs']))

    def test_existing_binary_is_preserved_and_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            output, report_path = work / 'probe', work / 'build.json'
            output.write_bytes(b'keep')
            report = build(output, report_path)
            self.assertEqual(report['qualification'], 'failed')
            self.assertEqual(output.read_bytes(), b'keep')
            self.assertEqual(json.loads(report_path.read_text())['qualification'], 'failed')


if __name__ == '__main__':
    unittest.main()
