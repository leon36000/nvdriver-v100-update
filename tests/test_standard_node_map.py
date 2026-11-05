# SPDX-License-Identifier: MIT
"""CPU/UBSan contract for standard NVIDIA control/GPU minor resolution."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPEN = ROOT / (
    "build/experiments/private-open-gpu-inventory-v2/"
    "NVIDIA-kernel-module-source-580.178.04"
)
FIXTURE = ROOT / "tests/fixtures/standard_node_map_contract.c"


class StandardNodeMapTests(unittest.TestCase):
    def test_r580_standard_minor_resolution_under_ubsan(self):
        with tempfile.TemporaryDirectory(prefix="standard-node-map-") as temporary:
            binary = Path(temporary) / "standard-node-map-contract"
            include = OPEN / "kernel-open/common/inc"
            build = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", "-I", str(ROOT / "src"),
                    "-I", str(include), str(FIXTURE),
                    str(ROOT / "src/hybrid580-gpu-catalog.c"),
                    str(ROOT / "src/hybrid580-standard-node-map.c"),
                    "-o", str(binary),
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            env = os.environ.copy()
            env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
            result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("standard node map scenarios: 5", result.stdout)


if __name__ == "__main__":
    unittest.main()
