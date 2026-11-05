#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression contract for owner-aware R595 UVM device-P2P duplication."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / (
    "build/research/open-gpu-kernel-modules-595.99.02/source/"
    "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm/"
    "uvm_va_range_device_p2p.c"
)
IOCTL_HEADER = ROOT / (
    "build/research/open-gpu-kernel-modules-595.99.02/source/"
    "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm/uvm_ioctl.h"
)
PATCH = ROOT / "patches/r595.99.02/0004-uvm-device-p2p-control-fd.patch"
SOURCE_SHA256 = "8c3068201d9ef453f0f2efc365d6dd265cf0b5e465bb649913790c304c82503c"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class R595DeviceP2PControlFdTests(unittest.TestCase):
    def test_pinned_ioctl_provides_fd_but_all_dup_sites_drop_it(self):
        source_bytes = SOURCE.read_bytes()
        self.assertEqual(sha256(source_bytes), SOURCE_SHA256)
        source = source_bytes.decode()
        self.assertEqual(source.count("nvUvmInterfaceDupMemory("), 3)

        ioctl = IOCTL_HEADER.read_text()
        params = ioctl[ioctl.index("} UVM_ALLOC_DEVICE_P2P_PARAMS;") - 700:]
        self.assertIn("NvS32                   rmCtrlFd;", params)

        entry = source[source.index("NV_STATUS uvm_api_alloc_device_p2p("):]
        self.assertIn(
            "alloc_coherent_device_p2p(gpu, params->hClient, params->hMemory, &p2p_mem)",
            entry,
        )
        self.assertIn(
            "alloc_zone_device_p2p(gpu, params->hClient, params->hMemory, &p2p_mem)",
            entry,
        )

    def test_exact_patch_threads_ioctl_fd_through_all_p2p_duplication_paths(self):
        source_bytes = SOURCE.read_bytes()
        self.assertEqual(sha256(source_bytes), SOURCE_SHA256)
        PATCH.read_bytes()

        with tempfile.TemporaryDirectory(prefix="r595-device-p2p-control-fd-") as temp:
            root = Path(temp) / "nvidia-uvm"
            root.mkdir()
            (root / "uvm_va_range_device_p2p.c").write_bytes(source_bytes)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("offset", result.stdout.lower())
            self.assertNotIn("fuzz", result.stdout.lower())

            patched = (root / "uvm_va_range_device_p2p.c").read_text()
            self.assertEqual(patched.count("nvUvmInterfaceDupMemory("), 0)
            self.assertEqual(
                patched.count("nvUvmInterfaceDupMemoryWithControlFd(rm_control_fd,"), 3
            )
            self.assertRegex(
                patched,
                r"alloc_coherent_device_p2p\(gpu, params->rmCtrlFd, params->hClient,\s*"
                r"params->hMemory, &p2p_mem\)",
            )
            self.assertRegex(
                patched,
                r"alloc_zone_device_p2p\(gpu, params->rmCtrlFd, params->hClient,\s*"
                r"params->hMemory, &p2p_mem\)",
            )
            self.assertIn(
                "alloc_device_p2p_mem(gpu, rm_control_fd, client, memory, &p2p_mem)",
                patched,
            )
            for function in (
                "alloc_device_p2p_mem",
                "alloc_zone_device_p2p",
                "alloc_coherent_device_p2p",
            ):
                body = patched[patched.index(f"static NV_STATUS {function}("):]
                signature = body[:body.index("{")]
                self.assertIn("int rm_control_fd", signature)


if __name__ == "__main__":
    unittest.main()
