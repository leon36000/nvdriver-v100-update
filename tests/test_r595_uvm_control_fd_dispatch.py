#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contract tests for the private R595 UVM address-space FD dispatch patch."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/experiments/r595-gv100-hal-client-share-policy-frontend-v1/nvidia-uvm/uvm_va_space.c"
PATCH = ROOT / "patches/r595.99.02/0001-uvm-rm-control-fd-address-space-dispatch.patch"
SOURCE_SHA256 = "f332076b5d141b23cbe7acaccb48b2b07a0f8fe2e44832fd93551a4a8c345468"


class R595UvmControlFdDispatchTests(unittest.TestCase):
    def test_patch_is_pinned_and_applies_without_fuzz(self):
        source = SOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), SOURCE_SHA256)
        patch = PATCH.read_bytes()
        with tempfile.TemporaryDirectory(prefix="r595-uvm-rmfd-test-") as temp:
            root = Path(temp)
            uvm = root / "nvidia-uvm"
            uvm.mkdir()
            (uvm / "uvm_va_space.c").write_bytes(source)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "-p1", "-i", str(PATCH)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("fuzz", result.stdout.lower())
            self.assertNotIn("offset", result.stdout.lower())
            self.assertTrue((uvm / "hybrid580_uvm_control_fd_dispatch.h").is_file())

            patched = (uvm / "uvm_va_space.c").read_text()
            self.assertIn("fget((unsigned int)user_rm_va_space->rm_control_fd)", patched)
            self.assertIn("fput(rm_control_file);", patched)
            self.assertIn("nvUvmInterfaceDupAddressSpaceWithControlFd(", patched)
            self.assertNotIn("(void)user_rm_va_space->rm_control_fd;", patched)
            self.assertNotIn("nvUvmInterfaceDupAddressSpace(uvm_gpu_device_handle(gpu)", patched)

    def test_extension_prototype_matches_frontend_contract(self):
        prototype = (ROOT / "src/hybrid580_uvm_control_fd_dispatch.h").read_text()
        self.assertIn(
            "NV_STATUS nvUvmInterfaceDupAddressSpaceWithControlFd(\n"
            "    struct file *rmControlFile,",
            prototype,
        )
        patch = PATCH.read_text()
        for fragment in (
            "struct file *rmControlFile,",
            "uvmGpuDeviceHandle device,",
            "NvHandle hClient,",
            "NvHandle hUserVASpace,",
            "uvmGpuAddressSpaceHandle *vaSpace,",
            "UvmGpuAddressSpaceInfo *vaSpaceInfo);",
        ):
            self.assertIn(fragment, patch)


if __name__ == "__main__":
    unittest.main()
