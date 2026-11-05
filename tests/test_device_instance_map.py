# SPDX-License-Identifier: MIT
"""CPU/UBSan contract for the merged 32-bit RM device-instance namespace."""
import os
import subprocess
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/device_instance_map_contract.c'


class DeviceInstanceMapTests(unittest.TestCase):
    def test_mapping_grouping_bounds_and_failure_atomicity(self):
        with tempfile.TemporaryDirectory(prefix='device-instance-map-') as temporary:
            binary = Path(temporary) / 'device-instance-map-contract'
            build = subprocess.run(
                ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=undefined', '-I', str(ROOT / 'src'), str(FIXTURE),
                 str(ROOT / 'src/hybrid580-gpu-catalog.c'),
                 str(ROOT / 'src/hybrid580-device-instance-map.c'),
                 '-o', str(binary)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            env = os.environ.copy()
            env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
            result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('device instance map scenarios: 7', result.stdout)


if __name__ == '__main__':
    unittest.main()
