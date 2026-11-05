# SPDX-License-Identifier: MIT
"""Compile and execute the CPU contract for UVM RM owner routing."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Hybrid580UvmOwnerMapTests(unittest.TestCase):
    def test_owner_selection_pinning_and_retirement_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_uvm_owner_map_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                 str(ROOT / "tests/fixtures/hybrid580_uvm_owner_map_test.c"), "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
