# SPDX-License-Identifier: MIT
"""Compile and exercise the shared-UVM PM state transition contract."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Hybrid580PmSharedUvmTests(unittest.TestCase):
    def test_suspend_resume_failures_and_retries_preserve_state(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_pm_shared_uvm_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-I", str(ROOT / "src"),
                 str(ROOT / "tests/fixtures/hybrid580_pm_shared_uvm_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
