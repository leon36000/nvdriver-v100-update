# SPDX-License-Identifier: MIT
"""Contracts for retrying isolated UVM PMM allocation outside VA-block lock."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools import probe_r580_uvm_isolated_execution as probe
from tools.audit_hybrid_uvm_abi import c_function_definition


PATCH_NAME = "0008-pmm-allocation-outside-va-block-lock.patch"
PATCH = probe.ROOT / "patches/r580.178.04/uvm" / PATCH_NAME
BASE = (
    probe.ROOT
    / "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm/uvm_va_block.c"
)


class R580UvmPmmAllocationRetryTests(unittest.TestCase):
    def _patched_function(self) -> str:
        self.assertTrue(BASE.is_file(), f"pinned source fixture missing: {BASE}")
        with tempfile.TemporaryDirectory(prefix="r580-uvm-pmm-retry-") as temporary:
            root = Path(temporary)
            target = root / "kernel-open/nvidia-uvm/uvm_va_block.c"
            target.parent.mkdir(parents=True)
            shutil.copyfile(BASE, target)
            result = subprocess.run(
                ["patch", "--batch", "--fuzz=0", "--forward", "-p1", "-i", str(PATCH)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return c_function_definition(target, "block_alloc_gpu_chunk")

    def test_pmm_retry_overlay_precedes_staged_migration_guards(self):
        self.assertTrue(PATCH.is_file(), "the opt-in PMM lock-release patch must exist")
        self.assertEqual(probe.PATCHES[-7].name, PATCH_NAME)
        self.assertEqual(
            [patch.name for patch in probe.PATCHES[-6:]],
            [
                "0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
                "0010-reject-unsupported-isolated-staged-migrations.patch",
                "0011-preflight-unsupported-staging-before-unmap.patch",
                "0012-exact-isolated-staged-page-mask.patch",
                "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
                "0014-reject-foreign-pmm-trackers-before-eviction.patch",
            ],
        )

    def test_isolated_no_eviction_allocation_releases_lock_and_restarts_on_success(self):
        function = self._patched_function()
        isolated = function.index("if (uvm_push_isolated_gpu_execution_enabled())")
        unlock = function.index("uvm_mutex_unlock(&block->lock)", isolated)
        allocation = function.index("UVM_PMM_ALLOC_FLAGS_NONE", isolated)
        success = function.index("if (status == NV_OK)", allocation)
        add_to_retry = function.index("block_retry_add_free_chunk(retry, gpu_chunk)", success)
        restart = function.index("status = NV_ERR_MORE_PROCESSING_REQUIRED", add_to_retry)
        relock = function.index("uvm_mutex_lock(&block->lock)", restart)
        return_status = function.index("if (status != NV_ERR_NO_MEMORY)", relock)
        eviction = function.index("UVM_PMM_ALLOC_FLAGS_EVICT", return_status)

        self.assertLess(unlock, allocation)
        self.assertLess(allocation, success)
        self.assertLess(success, add_to_retry)
        self.assertLess(add_to_retry, restart)
        self.assertLess(restart, relock)
        self.assertLess(relock, return_status)
        self.assertLess(return_status, eviction)

    def test_default_mode_keeps_the_existing_direct_allocation_path(self):
        function = self._patched_function()
        isolated = function.index("if (uvm_push_isolated_gpu_execution_enabled())")
        default = function.index("else {", isolated)
        direct_allocation = function.index("uvm_pmm_gpu_alloc_user(", default)
        self.assertLess(isolated, default)
        self.assertNotIn("uvm_mutex_unlock(&block->lock)", function[default:direct_allocation])
        self.assertIn("UVM_PMM_ALLOC_FLAGS_NONE", function[direct_allocation:])


if __name__ == "__main__":
    unittest.main()
