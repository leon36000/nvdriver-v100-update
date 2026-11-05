# SPDX-License-Identifier: MIT
"""Patch and mutation contracts for the pinned R595 hybrid UVM overlay."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/r595.99.02/0005-uvm-cache-provider-and-isolate-cross-provider-tracking.patch"
OVERLAY = ROOT / "build/experiments/r595-gv100-fd-aware-device-p2p-v1-20261028T1838Z"

PREIMAGES = {
    "hybrid580_uvm_provider_dispatch.h": "b19f5fba4e5c877a8cb906c156595f313b7238638430a9b00385662ba088a378",
    "uvm_gpu.c": "1cafe1ac49ed0a01c19e213dc8f79276bd477dd4587afb778b9b8d4cb7a715e3",
    "uvm_gpu.h": "76c578d204b32499e0004d1f1f43f9a1ce6718be13faa1394a5a63d0d1c7f9b5",
    "uvm_gpu_semaphore.c": "19f0ce4f4a7dfaa329eb5eebb72418126a6be05887d28b40c1279736d9b72ee2",
    "uvm_tracker.c": "756ce284db092691c5e346c9180299c98e050d4391242c53c19d14fcdff13e41",
    "uvm_tracker.h": "17db41fd3fbbaa9aec3047f7c226514085ae0d5479c572f99aa3dd36e9403058",
    "uvm_push.c": "9628ada0b4007eff5af16525d0d71788045832e5ca268699e2ae82a5dc14b85e",
    "uvm_push.h": "ba2970bac58980f83f03ccf7f512c67fcce66451a59cd1367847520fbf72253f",
    "uvm_migrate_pageable.c": "e7178513d684596aadbe24c1f699eb9e7b13b7f39c19805fe213bbef090898da",
    "uvm_pmm_gpu.c": "074cd307b7700270453fa4509fcbdf12400165fb1dd4cfb7cd8e8997554640ff",
}


def validate_overlay(root: Path) -> None:
    uvm = root / "nvidia-uvm"
    provider = (uvm / "hybrid580_uvm_provider_dispatch.h").read_text()
    gpu = (uvm / "uvm_gpu.c").read_text()
    gpu_h = (uvm / "uvm_gpu.h").read_text()
    semaphore = (uvm / "uvm_gpu_semaphore.c").read_text()
    tracker = (uvm / "uvm_tracker.c").read_text()
    tracker_h = (uvm / "uvm_tracker.h").read_text()
    push = (uvm / "uvm_push.c").read_text()
    push_h = (uvm / "uvm_push.h").read_text()
    migrate = (uvm / "uvm_migrate_pageable.c").read_text()
    pmm = (uvm / "uvm_pmm_gpu.c").read_text()

    assert "nvUvmInterfaceGetGpuProvider(" in provider
    assert "HYBRID580_UVM_PROVIDER_ID_OPEN" in provider
    assert "HYBRID580_UVM_PROVIDER_ID_LEGACY" in provider
    assert "nvUvmInterfaceGetGpuProvider(&parent_gpu->uuid, &gpu->hybrid_provider_id)" in gpu
    assert "NvU32 hybrid_provider_id;" in gpu_h
    assert "nvUvmInterfaceAreGpuProvidersSame(" not in gpu
    assert "nvUvmInterfaceAreGpuProvidersSame(" not in semaphore
    assert "other_gpu->hybrid_provider_id != gpu->hybrid_provider_id" in gpu
    assert "other_gpu->hybrid_provider_id != gpu->hybrid_provider_id" in semaphore
    assert "uvm_tracker_has_other_providers" in tracker
    assert "uvm_tracker_has_other_gpus" in tracker
    assert "uvm_tracker_has_other_providers" in tracker_h
    assert "uvm_tracker_has_other_gpus" in tracker_h
    assert "uvm_tracker_has_other_providers(tracker, gpu)" in push
    assert "uvm_hybrid_isolated_gpu_execution" in push
    assert "uvm_push_isolated_gpu_execution_enabled" in push_h
    assert "hybrid_provider_id" in migrate
    assert "uvm_tracker_has_other_gpus(&root_chunk->tracker, gpu)" in pmm
    assert "uvm_tracker_has_other_gpus(&va_block->tracker, gpu)" in pmm

    # The allocation guard runs after a chunk has been allocated. Its failure
    # path must unlock the root chunk and count the current chunk so the common
    # unwind frees it. Keep this ordering pinned: a missing i++ leaks chunks.
    alloc_start = pmm.index("static NV_STATUS pmm_gpu_alloc(")
    alloc_end = pmm.index("\nNV_STATUS uvm_pmm_gpu_alloc_kernel(", alloc_start)
    alloc = pmm[alloc_start:alloc_end]
    guard_start = alloc.index("// The local copy would retain raw channel pointers")
    guard_end = alloc.index(
        "status = uvm_tracker_add_tracker_safe(&local_tracker, &root_chunk->tracker);",
        guard_start,
    )
    alloc_guard = alloc[guard_start:guard_end]
    assert "status = NV_ERR_NOT_SUPPORTED;" in alloc_guard
    assert "i++;" in alloc_guard
    assert "goto error;" in alloc_guard
    assert alloc_guard.index("root_chunk_unlock(pmm, root_chunk);") < alloc_guard.index("i++;")
    assert alloc_guard.index("i++;") < alloc_guard.index("goto error;")
    alloc_unwind = alloc[alloc.index("error:"):]
    assert alloc_unwind.index("uvm_tracker_deinit(&local_tracker);") < alloc_unwind.index("while (i-- > 0)")
    assert alloc_unwind.index("while (i-- > 0)") < alloc_unwind.index("free_chunk(pmm, chunks[i]);")
    assert "memset(chunks, 0, sizeof(chunks[0]) * num_chunks);" in alloc_unwind

    # Eviction must reject before detaching the tracker, release the VA-block
    # reference on every result, and reacquire the PMM lock on every return.
    evict_start = pmm.index("static NV_STATUS evict_root_chunk_from_va_block(")
    evict_end = pmm.index("\nvoid uvm_pmm_gpu_mark_chunk_evicted(", evict_start)
    evict = pmm[evict_start:evict_end]
    guard = "uvm_tracker_has_other_gpus(&va_block->tracker, gpu)"
    assert evict.index("uvm_mutex_lock(&va_block->lock);") < evict.index(guard)
    assert evict.index(guard) < evict.index("uvm_va_block_evict_chunks(")
    assert evict.index("uvm_mutex_unlock(&va_block->lock);") < evict.index("uvm_va_block_release(va_block);")
    assert evict.index("uvm_va_block_release(va_block);") < evict.index("uvm_mutex_lock(&pmm->lock);")

    for name, text in (("tracker", tracker), ("push", push),
                       ("semaphore", semaphore), ("PMM", pmm),
                       ("pageable migration", migrate)):
        assert "nvUvmInterfaceGetGpuProvider(" not in text, (
            f"provider lookup that takes a mutex leaked into {name} path")


class R595IsolatedProviderGuardTests(unittest.TestCase):
    def test_patch_applies_without_offset_to_exact_existing_candidate_overlay(self):
        with tempfile.TemporaryDirectory(prefix="r595-provider-guard-") as temp:
            root = Path(temp)
            (root / "nvidia-uvm").mkdir()
            for name, expected_hash in PREIMAGES.items():
                source = OVERLAY / "nvidia-uvm" / name
                payload = source.read_bytes()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_hash)
                (root / "nvidia-uvm" / name).write_bytes(payload)

            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("offset", result.stdout.lower())
            self.assertNotIn("fuzz", result.stdout.lower())
            validate_overlay(root)

    def test_mutated_gpu_registration_does_not_pass_the_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-provider-mutation-") as temp:
            root = Path(temp)
            (root / "nvidia-uvm").mkdir()
            for name in PREIMAGES:
                shutil.copyfile(OVERLAY / "nvidia-uvm" / name,
                                root / "nvidia-uvm" / name)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            gpu = root / "nvidia-uvm/uvm_gpu.c"
            gpu.write_text(gpu.read_text().replace(
                "nvUvmInterfaceGetGpuProvider(&parent_gpu->uuid, &gpu->hybrid_provider_id)",
                "NV_OK", 1))
            with self.assertRaises(AssertionError):
                validate_overlay(root)

    def test_mutated_pmm_allocation_unwind_does_not_pass_the_contract(self):
        with tempfile.TemporaryDirectory(prefix="r595-pmm-unwind-mutation-") as temp:
            root = Path(temp)
            (root / "nvidia-uvm").mkdir()
            for name in PREIMAGES:
                shutil.copyfile(OVERLAY / "nvidia-uvm" / name,
                                root / "nvidia-uvm" / name)
            result = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=root, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            pmm = root / "nvidia-uvm/uvm_pmm_gpu.c"
            source = pmm.read_text()
            source = source.replace(
                "status = NV_ERR_NOT_SUPPORTED;\n            root_chunk_unlock(pmm, root_chunk);\n            i++;\n            goto error;",
                "status = NV_ERR_NOT_SUPPORTED;\n            root_chunk_unlock(pmm, root_chunk);\n            goto error;",
                1,
            )
            pmm.write_text(source)
            with self.assertRaises(AssertionError):
                validate_overlay(root)


if __name__ == "__main__":
    unittest.main()
