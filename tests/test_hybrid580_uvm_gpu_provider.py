# SPDX-License-Identifier: MIT
"""Compile and execute the dual-provider GPU identity comparison contract."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Hybrid580UvmGpuProviderTests(unittest.TestCase):
    def test_cached_provider_query_is_a_frontend_owned_uuid_dispatch(self):
        provider_header = (ROOT / "src/hybrid580_uvm_provider_dispatch.h").read_text()
        bridge = (ROOT / "src/hybrid580_uvm_callback_bridge.c").read_text()
        builder = (ROOT / "tools/build_hybrid_frontend.py").read_text()

        self.assertIn("nvUvmInterfaceGetGpuProvider(", provider_header)
        self.assertIn("HYBRID580_UVM_PROVIDER_ID_OPEN", provider_header)
        self.assertIn("HYBRID580_UVM_PROVIDER_ID_LEGACY", provider_header)
        self.assertIn("hybrid580_uvm_gpu_registry_lookup(", bridge)
        self.assertIn("EXPORT_SYMBOL(nvUvmInterfaceGetGpuProvider)", bridge)
        self.assertIn("'nvUvmInterfaceGetGpuProvider'", builder)

    def test_same_provider_and_cross_provider_gpu_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_uvm_gpu_provider_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                 str(ROOT / "tests/fixtures/hybrid580_uvm_gpu_provider_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("provider comparison passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
