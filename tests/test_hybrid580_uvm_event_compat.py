# SPDX-License-Identifier: MIT
"""Check the R595-to-R580 Linux UVM event-table adaptation."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
R595_INC = (ROOT / "build/experiments/r595-r580-open-fullbuild-v3-20261023"
            / "source/kernel-open/common/inc")


class Hybrid580UvmEventCompatTests(unittest.TestCase):
    def test_linux_event_fields_map_to_the_exact_legacy_order(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_uvm_event_compat_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(R595_INC),
                 str(ROOT / "tests/fixtures/hybrid580_uvm_event_compat_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
