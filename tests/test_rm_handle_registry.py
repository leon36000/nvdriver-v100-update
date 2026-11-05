# SPDX-License-Identifier: MIT
"""Unit-test the redaction observer's root-scoped live RM object map."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RmHandleRegistryTests(unittest.TestCase):
    def test_root_scoping_free_reuse_and_ambiguous_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "rm_handle_registry_test"
            result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(ROOT / "tests/fixtures/rm_handle_registry_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            self.assertIn("passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
