# SPDX-License-Identifier: MIT
"""Contract tests for the no-GPU NVCC architecture smoke helper."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/verify_nvcc_cuda_smoke.py"


class NvccCudaSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nvcc-smoke-contract-")
        self.root = Path(self.temp.name)
        self.nvcc = self.root / "fake-nvcc"
        self.host_cxx = self.root / "fake-g++"
        self.cuobjdump = self.root / "fake-cuobjdump"
        self.nvcc.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "if '--version' in sys.argv:\n"
            "    print('Cuda compilation tools, release 13.1')\n"
            "    raise SystemExit(8 if os.environ.get('FAKE_NVCC_VERSION_FAIL') else 0)\n"
            "if '-U_GNU_SOURCE' not in sys.argv or '-arch=sm_120a' not in sys.argv: raise SystemExit(9)\n"
            "if os.environ.get('FAKE_NVCC_FAIL'): print('synthetic compile failure', file=sys.stderr); raise SystemExit(1)\n"
            "out=pathlib.Path(sys.argv[sys.argv.index('-o')+1]); out.write_bytes(b'fake executable'); raise SystemExit(0)\n",
            encoding="utf-8",
        )
        self.host_cxx.write_text(
            "#!/usr/bin/env python3\nprint('g++ (test fixture) 15.2.0')\n",
            encoding="utf-8",
        )
        self.cuobjdump.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "if '--version' in sys.argv:\n"
            "    print('Cuda compilation tools, release 13.1')\n"
            "    raise SystemExit(8 if os.environ.get('FAKE_CUOBJDUMP_VERSION_FAIL') else 0)\n"
            "print('ELF file 1: smoke.1.sm_120a.cubin')\n"
            "print('ELF file 2: smoke.2.sm_120a.cubin')\n",
            encoding="utf-8",
        )
        for tool in (self.nvcc, self.host_cxx, self.cuobjdump):
            tool.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, extra_env=None):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--nvcc",
                str(self.nvcc),
                "--cuobjdump",
                str(self.cuobjdump),
                "--host-cxx",
                str(self.host_cxx),
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=10,
        )

    def test_success_requires_requested_cubin_and_stays_hardware_unvalidated(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["passed"])
        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertIn("-U_GNU_SOURCE", report["compile"]["command"])
        self.assertEqual(report["image_inspection"]["architectures"], ["sm_120a"])
        self.assertEqual(report["toolchain"]["cuobjdump_version"]["exit_code"], 0)
        self.assertFalse(report["gpu_accessed"])
        self.assertFalse(report["binary_executed"])
        self.assertFalse(report["runtime_or_hardware_validated"])

    def test_compile_failure_is_preserved_as_failure(self):
        result = self.invoke({"FAKE_NVCC_FAIL": "1"})
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertFalse(report["passed"])
        self.assertEqual(report["compile"]["exit_code"], 1)
        self.assertIn("synthetic compile failure", report["compile"]["stderr"])
        self.assertEqual(report["image_inspection"]["architectures"], [])

    def test_toolchain_version_failure_prevents_pass(self):
        result = self.invoke({"FAKE_NVCC_VERSION_FAIL": "1"})
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["toolchain"]["nvcc_version"]["exit_code"], 8)
        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertTrue(report["image_inspection"]["requested_architecture_present"])
        self.assertFalse(report["passed"])

    def test_cuobjdump_version_failure_prevents_pass(self):
        result = self.invoke({"FAKE_CUOBJDUMP_VERSION_FAIL": "1"})
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["toolchain"]["cuobjdump_version"]["exit_code"], 8)
        self.assertEqual(report["compile"]["exit_code"], 0)
        self.assertTrue(report["image_inspection"]["requested_architecture_present"])
        self.assertFalse(report["passed"])

    def test_existing_json_receipt_is_not_overwritten(self):
        receipt = self.root / "receipt.json"
        receipt.write_text("preserve\n", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--nvcc",
                str(self.nvcc),
                "--cuobjdump",
                str(self.cuobjdump),
                "--host-cxx",
                str(self.host_cxx),
                "--json-out",
                str(receipt),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(receipt.read_text(encoding="utf-8"), "preserve\n")


if __name__ == "__main__":
    unittest.main()
