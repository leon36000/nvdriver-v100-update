# SPDX-License-Identifier: MIT
"""Compose owner-routed R580 GV100 info, device creation, and FB-info calls."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Hybrid580UvmAttachHandoffTests(unittest.TestCase):
    def test_mixed_generation_devices_keep_independent_rm_owners(self):
        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-attach-") as directory:
            binary = Path(directory) / "hybrid580_uvm_attach_handoff_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined",
                 str(ROOT / "tests/fixtures/hybrid580_uvm_attach_handoff_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(0, build.returncode, build.stdout + build.stderr)

            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(0, run.returncode, run.stdout + run.stderr)
            self.assertIn(
                "R580 GV100 + open Blackwell dual-owner UVM handoff passed",
                run.stdout,
            )


if __name__ == "__main__":
    unittest.main()
