#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the production scope of R595 UVM's cross-GPU DupAllocation route."""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
R595_UVM = ROOT / (
    "build/research/open-gpu-kernel-modules-595.99.02/source/"
    "open-gpu-kernel-modules-595.99.02/kernel-open/nvidia-uvm"
)
CANDIDATE_UVM = ROOT / (
    "build/experiments/r595-gv100-fd-aware-device-p2p-v1-20261028T1838Z/"
    "nvidia-uvm"
)
RM_MEM = R595_UVM / "uvm_rm_mem.c"
RM_MEM_H = R595_UVM / "uvm_rm_mem.h"
PUSHBUFFER = R595_UVM / "uvm_pushbuffer.c"
BASE_SEMAPHORE = R595_UVM / "uvm_gpu_semaphore.c"
CANDIDATE_SEMAPHORE = CANDIDATE_UVM / "uvm_gpu_semaphore.c"
RM_MEM_SHA256 = "fdf517f711ce9ae3421e4af2e7fe128f0db4182000eeed32504eacc82d1a43d7"
PUSHBUFFER_SHA256 = "7031f10fc2215d792d58675b503623be5792e13fa4304d14f9b60b811a0a812c"
BASE_SEMAPHORE_SHA256 = "1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f"
CANDIDATE_SEMAPHORE_SHA256 = "19f0ce4f4a7dfaa329eb5eebb72418126a6be05887d28b40c1279736d9b72ee2"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class R595DupAllocationScopeTests(unittest.TestCase):
    def test_only_dupallocation_route_is_system_memory_map_and_is_provider_affine(self):
        rm_mem = RM_MEM.read_text()
        self.assertEqual(sha256(RM_MEM), RM_MEM_SHA256)
        self.assertEqual(
            rm_mem.count("status = uvm_rm_locked_call(nvUvmInterfaceDupAllocation("), 1
        )
        self.assertIn("UVM_ASSERT(rm_mem->type == UVM_RM_MEM_TYPE_SYS);", rm_mem)
        self.assertIn("gpu_owner->rm_address_space", rm_mem)
        self.assertIn("gpu->rm_address_space", rm_mem)
        self.assertIn("if (status != NV_OK) {", rm_mem)

        header = RM_MEM_H.read_text()
        self.assertIn(
            "Mapping/unmapping on a GPU different from the owner is only supported\n"
            "// for system memory.",
            header,
        )

    def test_all_gpu_system_map_is_semaphore_only_in_production_and_now_filtered(self):
        self.assertEqual(sha256(BASE_SEMAPHORE), BASE_SEMAPHORE_SHA256)
        self.assertEqual(sha256(PUSHBUFFER), PUSHBUFFER_SHA256)
        base_semaphore = BASE_SEMAPHORE.read_text()
        self.assertIn("uvm_rm_mem_alloc_and_map_all(gpu, memory_type", base_semaphore)

        production_callers = []
        for path in R595_UVM.glob("*.c"):
            if path.name.endswith("_test.c"):
                continue
            for line_number, line in enumerate(path.read_text().splitlines(), 1):
                if "uvm_rm_mem_alloc_and_map_all(" not in line:
                    continue
                if "NV_STATUS uvm_rm_mem_alloc_and_map_all(" in line:
                    continue
                production_callers.append((path.name, line_number))
        self.assertEqual([name for name, _ in production_callers], ["uvm_gpu_semaphore.c"])

        candidate = CANDIDATE_SEMAPHORE.read_text()
        self.assertEqual(sha256(CANDIDATE_SEMAPHORE), CANDIDATE_SEMAPHORE_SHA256)
        self.assertIn("nvUvmInterfaceAreGpuProvidersSame(", candidate)
        self.assertIn("uvm_rm_mem_alloc_and_map_cpu(gpu, memory_type", candidate)
        self.assertNotIn("uvm_rm_mem_alloc_and_map_all(gpu, memory_type", candidate)

    def test_confidential_pushbuffer_mapping_uses_its_channel_gpu_as_owner_and_target(self):
        pushbuffer = PUSHBUFFER.read_text()
        self.assertIn("uvm_gpu_t *gpu = channel_manager->gpu;", pushbuffer)
        self.assertIn("uvm_rm_mem_alloc_and_map_cpu(gpu,", pushbuffer)
        self.assertIn(
            "uvm_rm_mem_map_gpu(pushbuffer->memory_unprotected_sysmem, gpu, pushbuffer_alignment)",
            pushbuffer,
        )
        rm_mem = RM_MEM.read_text()
        self.assertIn("rm_mem->gpu_owner = gpu;", rm_mem)


if __name__ == "__main__":
    unittest.main()
