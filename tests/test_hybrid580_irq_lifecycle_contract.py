# SPDX-License-Identifier: MIT
"""Compile and run the isolated R580 IRQ-lifetime protocol model."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class Hybrid580IrqLifecycleContractTests(unittest.TestCase):
    def test_msi_legacy_remove_and_partial_setup_interleavings(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_irq_lifecycle_contract_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-pthread",
                 str(ROOT / "tests/fixtures/hybrid580_irq_lifecycle_contract_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
