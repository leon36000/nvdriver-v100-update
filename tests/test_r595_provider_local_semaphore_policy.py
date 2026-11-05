#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for a fail-closed, provider-local R595 semaphore mapping patch."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/r595.99.02/0002-uvm-provider-local-system-semaphore-pools.patch"
SOURCE_ROOT = ROOT / "build/experiments/r595-r580-patch-replay-fabric-status-v9-20261024/source/kernel-open/nvidia-uvm"
PREIMAGES = {
    "uvm_gpu.c": "66881c4ae46461314d41342b2a27df9119d68d68f90d181e3a32670dcc19f590",
    "uvm_gpu_semaphore.c": "1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f",
}


class R595ProviderLocalSemaphorePolicyTests(unittest.TestCase):
    def test_policy_patch_applies_to_exact_inputs_and_skips_only_foreign_owners(self):
        baseline = {}
        for name, expected_hash in PREIMAGES.items():
            source = (SOURCE_ROOT / name).read_bytes()
            self.assertEqual(hashlib.sha256(source).hexdigest(), expected_hash)
            baseline[name] = source

        with tempfile.TemporaryDirectory(prefix="r595-local-sem-patch-") as temp:
            root = Path(temp) / "nvidia-uvm"
            root.mkdir()
            for name, source in baseline.items():
                (root / name).write_bytes(source)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root.parent, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("offset", result.stdout.lower())
            self.assertNotIn("fuzz", result.stdout.lower())

            gpu = (root / "uvm_gpu.c").read_text()
            sem = (root / "uvm_gpu_semaphore.c").read_text()
            self.assertIn("nvUvmInterfaceAreGpuProvidersSame(", gpu)
            self.assertIn("if (!same_provider)", gpu)
            self.assertIn("nvUvmInterfaceAreGpuProvidersSame(", sem)
            self.assertIn("uvm_rm_mem_alloc_and_map_cpu(", sem)
            self.assertIn("uvm_rm_mem_map_gpu(page->memory, other_gpu, 0)", sem)
            self.assertNotIn("uvm_rm_mem_alloc_and_map_all(gpu, memory_type", sem)
            self.assertIn("uvm_rm_mem_free(page->memory);", sem)


if __name__ == "__main__":
    unittest.main()
