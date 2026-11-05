# SPDX-License-Identifier: MIT
"""Contracts for fail-closed cross-GPU synchronization in isolated R580 UVM."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools import probe_r580_uvm_isolated_execution as probe
from tools.audit_hybrid_uvm_abi import c_function_definition


PATCH_NAME = "0007-reject-cross-gpu-tracker-dependencies.patch"
BASE = (
    probe.ROOT
    / "build/experiments/r580-uvm-isolated-gpu-execution-v5-20261023T2130Z"
    / "NVIDIA-kernel-module-source-580.178.04/kernel-open"
)
SOURCES = (
    "nvidia-uvm/uvm_tracker.c",
    "nvidia-uvm/uvm_tracker.h",
    "nvidia-uvm/uvm_push.c",
    "nvidia-uvm/uvm_push.h",
    "nvidia-uvm/uvm_migrate_pageable.c",
    "nvidia-uvm/uvm_gpu.c",
    "nvidia-uvm/uvm_gpu_semaphore.c",
)


class R580UvmIsolatedFailClosedTests(unittest.TestCase):
    def _patched_source(self, temporary: str) -> Path:
        root = Path(temporary)
        for relative in SOURCES:
            target = root / "kernel-open" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BASE / relative, target)

        patches = [patch for patch in probe.PATCHES if patch.name == PATCH_NAME]
        self.assertEqual(len(patches), 1, "the fail-closed patch must be in the build chain")
        result = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "--forward", "-p1", "-i", str(patches[0])],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return root / "kernel-open/nvidia-uvm"

    def test_fail_closed_and_hmm_guard_overlays_are_last_in_build_chain(self):
        self.assertEqual(probe.PATCHES[-8].name, PATCH_NAME)
        self.assertEqual(
            [patch.name for patch in probe.PATCHES[-10:]],
            [
                "0005-pass-control-fd-to-dup-address-space.patch",
                "0006-pin-control-file-before-va-space-registration.patch",
                PATCH_NAME,
                "0008-pmm-allocation-outside-va-block-lock.patch",
                "0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
                "0010-reject-unsupported-isolated-staged-migrations.patch",
                "0011-preflight-unsupported-staging-before-unmap.patch",
                "0012-exact-isolated-staged-page-mask.patch",
                "0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
                "0014-reject-foreign-pmm-trackers-before-eviction.patch",
            ],
        )

    def test_tracker_query_prunes_completed_entries_before_owner_comparison(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-fail-closed-") as temporary:
            uvm = self._patched_source(temporary)
            tracker = c_function_definition(uvm / "uvm_tracker.c", "uvm_tracker_has_other_gpus")

        self.assertLess(
            tracker.index("uvm_tracker_is_completed(tracker)"),
            tracker.index("for_each_tracker_entry(entry, tracker)"),
        )
        self.assertIn("uvm_tracker_entry_gpu(entry) != gpu", tracker)
        self.assertIn("return true;", tracker)
        self.assertIn("return false;", tracker)

    def test_push_acquire_rejects_pending_foreign_gpu_work_without_waiting(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-fail-closed-") as temporary:
            uvm = self._patched_source(temporary)
            push = (uvm / "uvm_push.c").read_text(encoding="utf-8")
            helper = c_function_definition(uvm / "uvm_push.c", "reject_other_gpus_if_isolated")
            wrappers = (
                c_function_definition(uvm / "uvm_push.c", "__uvm_push_begin_acquire_with_info"),
                c_function_definition(uvm / "uvm_push.c", "__uvm_push_begin_acquire_on_channel_with_info"),
            )

        self.assertIn("uvm_tracker_has_other_gpus(tracker, gpu)", helper)
        self.assertIn("return NV_ERR_NOT_SUPPORTED;", helper)
        isolated = helper.index("uvm_push_isolated_gpu_execution_enabled()")
        reject = helper.index("return NV_ERR_NOT_SUPPORTED;", isolated)
        confidential_wait = helper.index("uvm_tracker_wait_for_other_gpus(tracker, gpu)")
        self.assertLess(reject, confidential_wait)
        isolated_success = helper.index("return NV_OK;", reject)
        self.assertLess(isolated_success, confidential_wait)
        self.assertIn("if (!uvm_push_allow_dependencies_across_gpus())", helper)
        for wrapper in wrappers:
            check = wrapper.index("reject_other_gpus_if_isolated(")
            error = wrapper.index("if (status != NV_OK)", check)
            reserve = wrapper.find("push_reserve_channel(", check)
            self.assertLess(check, error)
            if reserve >= 0:
                self.assertLess(error, reserve)
        self.assertIn("uvm_tracker_wait_for_other_gpus", push)
        self.assertNotIn("wait_for_other_gpus_if_needed", push)

    def test_cross_gpu_pageable_copy_is_rejected_before_allocating_or_zeroing_pages(self):
        with tempfile.TemporaryDirectory(prefix="r580-uvm-fail-closed-") as temporary:
            uvm = self._patched_source(temporary)
            migration = c_function_definition(
                uvm / "uvm_migrate_pageable.c", "uvm_migrate_vma_copy_pages_from"
            )

        guard = migration.index("if (uvm_push_isolated_gpu_execution_enabled() &&")
        allocation = migration.index("for_each_set_bit(i, page_mask, state->num_pages)")
        zeroing = migration.index("migrate_vma_zero_begin_push(")
        self.assertLess(guard, allocation)
        self.assertLess(guard, zeroing)
        isolated = migration[guard:allocation]
        self.assertIn("UVM_ID_IS_GPU(src_id)", isolated)
        self.assertIn("UVM_ID_IS_GPU(dst_id)", isolated)
        self.assertIn("!uvm_id_equal(src_id, dst_id)", isolated)
        self.assertIn("return NV_ERR_NOT_SUPPORTED;", isolated)
        wait = migration.index("uvm_tracker_wait_for_other_gpus(&zero_tracker, copying_gpu)")
        copy = migration.index("migrate_vma_copy_begin_push(", wait)
        zero = migration.index("uvm_tracker_add_push_safe(&zero_tracker, &zero_push)")
        self.assertLess(zero, wait)
        self.assertLess(wait, copy)
        self.assertIn("if (!uvm_push_allow_dependencies_across_gpus())", migration)


if __name__ == "__main__":
    unittest.main()
