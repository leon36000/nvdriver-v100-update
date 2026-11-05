# SPDX-License-Identifier: MIT
"""CPU/UBSan lifecycle tests for standard NVIDIA character nodes."""
import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/standard_node_devices_contract.c"
FIXTURE_INCLUDE = ROOT / "tests/fixtures/include"
REFERENCE_HEADER = ROOT / (
    "build/experiments/private-open-gpu-inventory-v2/"
    "NVIDIA-kernel-module-source-580.178.04/"
    "kernel-open/common/inc/nv-chardev-numbers.h"
)
REFERENCE_HEADER_SHA256 = (
    "405047bb836229f55f39955d2565e2aad2e470bd796bdf6b6f7a8795fe12ea64"
)
NODE_ABI_VALUES = {
    "NV_MAJOR_DEVICE_NUMBER": 195,
    "NV_MINOR_DEVICE_NUMBER_REGULAR_MAX": 247,
    "NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE": 254,
    "NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE": 255,
}


class StandardNodeDeviceTests(unittest.TestCase):
    def test_fixture_values_match_the_pinned_r580_reference_when_available(self):
        if not REFERENCE_HEADER.is_file():
            self.skipTest("optional local R580.178.04 source snapshot is absent")
        contents = REFERENCE_HEADER.read_bytes()
        self.assertEqual(hashlib.sha256(contents).hexdigest(),
                         REFERENCE_HEADER_SHA256)
        text = contents.decode("ascii")
        for macro, expected in NODE_ABI_VALUES.items():
            with self.subTest(macro=macro):
                match = re.search(
                    rf"^#define\s+{re.escape(macro)}\s+(\d+)\s*$",
                    text, re.MULTILINE,
                )
                self.assertIsNotNone(match, macro)
                self.assertEqual(int(match.group(1)), expected)

    def test_registration_nodes_and_every_failure_unwind_under_ubsan(self):
        with tempfile.TemporaryDirectory(prefix="standard-node-devices-") as temporary:
            binary = Path(temporary) / "standard-node-devices-contract"
            build = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", "-I", str(ROOT / "src"),
                    "-I", str(FIXTURE_INCLUDE), str(FIXTURE),
                    str(ROOT / "src/hybrid580-gpu-catalog.c"),
                    str(ROOT / "src/hybrid580-standard-node-map.c"),
                    str(ROOT / "src/hybrid580-standard-node-devices.c"),
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
            self.assertIn("standard node device scenarios: 10", result.stdout)


if __name__ == "__main__":
    unittest.main()
