# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run_selector(selector):
    return subprocess.run(
        [sys.executable, str(ROOT / "tools/r580_descriptor_key.py"), selector],
        capture_output=True,
        text=True,
    )


class R580DescriptorKeyTests(unittest.TestCase):
    def test_callsite_key_uses_the_0x90_normalization_and_zero_other_words(self):
        result = run_selector("0x12345678")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["descriptor_key"],
                         {"0x88": 0, "0x8c": 0, "0x90": 0x567, "0x94": 0})

    def test_special_0x23a_nibble_is_remapped_to_four(self):
        result = run_selector("0x23a0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["descriptor_key"]["0x90"], 0x234)

    def test_special_remap_requires_both_byte_and_nibble(self):
        for selector, expected in (("0x23b0", 0x23B), ("0x24a0", 0x24A)):
            with self.subTest(selector=selector):
                result = run_selector(selector)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["descriptor_key"]["0x90"], expected)

    def test_selector_must_fit_the_observed_32_bit_field(self):
        for selector in ("-1", "0x100000000"):
            with self.subTest(selector=selector):
                result = run_selector(selector)
                self.assertNotEqual(result.returncode, 0)

    def test_cli_emits_machine_readable_key(self):
        result = run_selector("0x23a0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '{"selector":9120,"descriptor_key":{"0x88":0,"0x8c":0,"0x90":564,"0x94":0}}\n')


if __name__ == "__main__":
    unittest.main()
