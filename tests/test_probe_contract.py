#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CLI contract tests for the isolated hybrid CUDA Driver API probe."""

import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HYBRID_PROBE", ROOT / "build/hybrid_cuda_probe"))


class ProbeContractTests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run(
            [str(PROBE), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_help_explains_device_and_module_modes(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--require-sm", result.stdout)
        self.assertIn("--module", result.stdout)
        self.assertIn("--managed-prefetch", result.stdout)
        self.assertIn("hybrid_validated", result.stdout)

    def test_phase_probe_documents_the_bounded_stages(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for phase in ("initialize", "enumerate", "context", "allocation", "module", "kernel"):
            with self.subTest(phase=phase):
                self.assertIn(phase, result.stdout)

    def test_phase_probe_requires_an_exact_gpu_selector_and_known_phase(self):
        missing_selector = self.invoke("--phase", "initialize")
        self.assertEqual(missing_selector.returncode, 64)
        self.assertIn("requires --expected-pci", missing_selector.stderr)
        unknown = self.invoke("--phase", "invented", "--expected-pci", "0000:02:00.0")
        self.assertEqual(unknown.returncode, 64)
        self.assertIn("unsupported phase", unknown.stderr)

    def test_managed_prefetch_requires_managed_memory(self):
        result = self.invoke("--managed-prefetch", "--module", "/does/not/need/to/exist")
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("requires --managed-memory", result.stderr)

    def test_unknown_architecture_is_rejected_as_usage_error(self):
        result = self.invoke("--require-sm", "70,not-a-number")
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)

    def test_module_is_required_for_execution(self):
        result = self.invoke("--require-sm", "120")
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertIn("--module", result.stderr)

    def test_expected_pci_rejects_malformed_or_duplicate_selectors(self):
        for address in ("", "02:00.0", "0000:02:20.0", "0000:02:00.8", "0000:gg:00.0"):
            with self.subTest(address=address):
                result = self.invoke("--list", "--expected-pci", address)
                self.assertEqual(result.returncode, 64)
                self.assertIn("PCI", result.stderr)
        result = self.invoke("--list", "--expected-pci", "0000:02:00.0",
                             "--expected-pci", "0000:03:00.0")
        self.assertEqual(result.returncode, 64)
        self.assertIn("once", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
