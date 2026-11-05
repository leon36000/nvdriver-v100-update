#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression contract for routing R595 external allocations by source RM FD."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm/uvm_map_external.c"
FIXTURE_SOURCE = ROOT / "tests/fixtures/r595_uvm_external_map_callsite.c"
BRIDGE = ROOT / "src/hybrid580_uvm_callback_bridge.c"
PATCH = ROOT / "patches/r595.99.02/0003-uvm-external-allocation-control-fd.patch"
SOURCE_SHA256 = "90de5bb57f41ce3f4c7d1316b8c8541e87dd3f23457aef81f9241273c86ad409"
FIXTURE_SOURCE_SHA256 = "87bad135f952132b865fe275c6482cd3c63e76a7757cc820ced8da156a076825"
BRIDGE_SHA256 = "c581cda76752f4dd4b903442309b5944dd2ff6eb9dd702c6dc4d91345aca86c5"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _patch_input() -> tuple[bytes, bool]:
    force_fixture = os.environ.get("NVIDIA_HYBRID_TEST_USE_R595_FIXTURE") == "1"
    if SOURCE.is_file() and not force_fixture:
        source_bytes = SOURCE.read_bytes()
        if sha256(source_bytes) != SOURCE_SHA256:
            raise AssertionError("local R595 UVM source differs from the pinned input")
        return source_bytes, True

    source_bytes = FIXTURE_SOURCE.read_bytes()
    if sha256(source_bytes) != FIXTURE_SOURCE_SHA256:
        raise AssertionError("R595 UVM callsite fixture differs from its pinned input")
    return source_bytes, False


class R595ExternalMapControlFdTests(unittest.TestCase):
    def test_pinned_source_retains_control_fd_but_calls_fail_closed_legacy_api(self):
        source_bytes, _is_full_source = _patch_input()
        source = source_bytes.decode()
        self.assertIn(".rm_control_fd = params->rmCtrlFd", source)
        self.assertIn("nvUvmInterfaceDupMemory(uvm_gpu_device_handle(mapping_gpu)", source)
        self.assertNotIn("nvUvmInterfaceDupMemoryWithControlFd(", source)

        bridge_bytes = BRIDGE.read_bytes()
        self.assertEqual(sha256(bridge_bytes), BRIDGE_SHA256)
        bridge = bridge_bytes.decode()
        self.assertIn("nvUvmInterfaceDupMemoryWithControlFd(", bridge)
        self.assertIn("return NV_ERR_NOT_SUPPORTED;", bridge[bridge.index("NV_STATUS nvUvmInterfaceDupMemory("):])

    def test_exact_patch_routes_external_duplication_through_control_fd(self):
        source_bytes, is_full_source = _patch_input()
        PATCH.read_bytes()

        with tempfile.TemporaryDirectory(prefix="r595-ext-map-control-fd-") as temp:
            root = Path(temp) / "nvidia-uvm"
            root.mkdir()
            (root / "uvm_map_external.c").write_bytes(source_bytes)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root.parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("fuzz", result.stdout.lower())
            if is_full_source:
                self.assertNotIn("offset", result.stdout.lower())

            patched = (root / "uvm_map_external.c").read_text()
            self.assertIn('#include "hybrid580_uvm_memory_dispatch.h"', patched)
            self.assertIn("nvUvmInterfaceDupMemoryWithControlFd(user_rm_mem->rm_control_fd,\n                                                        uvm_gpu_device_handle(mapping_gpu),", patched)
            self.assertNotIn("nvUvmInterfaceDupMemory(uvm_gpu_device_handle(mapping_gpu)", patched)

            header = (root / "hybrid580_uvm_memory_dispatch.h").read_text()
            self.assertIn("NV_STATUS nvUvmInterfaceDupMemoryWithControlFd(", header)
            self.assertIn("int rmControlFd", header)
            self.assertIn("uvmGpuDeviceHandle device", header)


if __name__ == "__main__":
    unittest.main()
