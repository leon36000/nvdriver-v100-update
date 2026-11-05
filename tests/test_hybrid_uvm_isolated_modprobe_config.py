# SPDX-License-Identifier: MIT
"""Verify the candidate-only modprobe option needed for isolated hybrid UVM."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "packaging/modprobe.d/hybrid580-standard-uvm.conf"
ISOLATED_PATCH = ROOT / "patches/r580.178.04/uvm/0007-reject-cross-gpu-tracker-dependencies.patch"
UVM_BUILD_REPORT = ROOT / "evidence/r580-uvm-standard-stack-consumer-v2-20261028T1420Z.json"


class HybridUvmIsolatedModprobeConfigTests(unittest.TestCase):
    def test_candidate_options_enable_isolation_without_aliasing_module_identity(self):
        config_text = CONFIG.read_text(encoding="utf-8")
        active = [line.strip() for line in config_text.splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(active, [
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1",
        ])
        self.assertNotIn("alias nvidia-uvm", config_text)

        patch = ISOLATED_PATCH.read_text(encoding="utf-8")
        self.assertIn("static bool uvm_hybrid_isolated_gpu_execution = false;", patch)
        self.assertIn("module_param(uvm_hybrid_isolated_gpu_execution, bool, 0444);", patch)

    def test_modprobe_parses_the_candidate_option_without_loading_a_module(self):
        modprobe = shutil.which("modprobe")
        if modprobe is None:
            self.skipTest("modprobe is not installed")

        with tempfile.TemporaryDirectory(prefix="hybrid-uvm-options-") as temporary:
            config = Path(temporary) / "modprobe.conf"
            config.write_text(CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
            result = subprocess.run(
                [modprobe, "--config", str(config), "--showconfig"],
                capture_output=True, text=True, timeout=10, check=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        options = [line.strip() for line in result.stdout.splitlines()
                   if line.strip().startswith("options nvidia_uvm ")]
        self.assertEqual(options, [
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1",
        ])
        self.assertEqual(result.stderr, "")

    def test_exact_candidate_module_exposes_the_configured_boolean_parameter(self):
        report = json.loads(UVM_BUILD_REPORT.read_text(encoding="utf-8"))
        module = report["build"]["modules"]["nvidia-uvm.ko"]
        path = Path(module["path"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), module["sha256"])

        modinfo = shutil.which("modinfo")
        if modinfo is None:
            self.fail("modinfo is required to verify the built candidate parameter")
        result = subprocess.run(
            [modinfo, "-p", str(path)], capture_output=True, text=True,
            timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        matching = [line for line in result.stdout.splitlines()
                    if line.startswith("uvm_hybrid_isolated_gpu_execution:")]
        self.assertEqual(len(matching), 1, result.stdout)
        self.assertIn("(bool)", matching[0])
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
