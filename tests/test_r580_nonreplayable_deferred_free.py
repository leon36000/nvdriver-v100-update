# SPDX-License-Identifier: MIT
"""Audit a bounded R595-to-R580 deferred-channel fault-flush backport."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from run_volta_fault_decode_host_harness import _extract_function, _normalized_function_hash

R580_ROOT = ROOT / (
    "build/experiments/r580-uvm-standard-module-private-frontend-v1-20261027T220300Z/"
    "NVIDIA-kernel-module-source-580.178.04/kernel-open"
)
R595_ROOT = ROOT / (
    "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v15-20261028T004147Z/nvidia-uvm"
)
PATCH = ROOT / "patches/r580.178.04/uvm/0002-flush-nonreplayable-on-deferred-free.patch"
SUSPEND_PATCH = ROOT / "patches/r580.178.04/uvm/0001-suspend-drain-non-replayable-faults.patch"
BASE_HASHES = {
    "nvidia-uvm/uvm_global.c":
        "aeee2f257a289853f36d9c7b196f1e02d19b84695db44cdd2e00f28b0f1a4489",
    "nvidia-uvm/uvm_gpu_non_replayable_faults.c":
        "588e72e5e3163f2e9a3c1b0d78a5450c97a4393b5b0c8e024915c41460d0250b",
    "nvidia-uvm/uvm_gpu_non_replayable_faults.h":
        "b4ce0fd6568d81ec7167d6dd5cc3ca57fec8c53c630e8120dda5ed56bc1f1cb4",
    "nvidia-uvm/uvm_gpu_isr.c":
        "456ee47bb83564cc1ada830538781256bb246bf82888601d3c3f2b3a2bc777f5",
    "nvidia-uvm/uvm_gpu_isr.h":
        "b815157c32452de84375818a302bc5c35b79491decfb2c310a853330b577b2fd",
    "nvidia-uvm/uvm_va_space.c":
        "cff2ab99e9b45143865413cd15d78381ead57b370f4b3bc32ac7584ca9e91693",
}


class R580NonReplayableDeferredFreeTests(unittest.TestCase):
    def test_backport_applies_cleanly_and_drains_each_parent_before_channel_destroy(self):
        with tempfile.TemporaryDirectory(prefix="r580-nonreplayable-deferred-free-") as directory:
            tree = Path(directory)
            for relative, expected_hash in BASE_HASHES.items():
                source = R580_ROOT / relative
                self.assertEqual(expected_hash, hashlib.sha256(source.read_bytes()).hexdigest(), relative)
                destination = tree / "kernel-open" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

            applied = subprocess.run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
                cwd=tree, check=False, capture_output=True, text=True,
            )
            self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
            self.assertNotIn("offset", applied.stdout.lower() + applied.stderr.lower())
            self.assertNotIn("fuzz", applied.stdout.lower() + applied.stderr.lower())

            non_replayable = (tree / "kernel-open/nvidia-uvm/uvm_gpu_non_replayable_faults.c").read_text()
            r595_non_replayable = (R595_ROOT / "uvm_gpu_non_replayable_faults.c").read_text()
            flush_body = _extract_function(non_replayable, "uvm_parent_gpu_non_replayable_buffer_flush")
            self.assertEqual(
                _normalized_function_hash(r595_non_replayable, "uvm_parent_gpu_non_replayable_buffer_flush"),
                _normalized_function_hash(non_replayable, "uvm_parent_gpu_non_replayable_buffer_flush"),
            )
            flush = flush_body
            ordered_calls = [
                "uvm_spin_lock_irqsave(&parent_gpu->isr.interrupts_lock)",
                "uvm_parent_gpu_schedule_non_replayable_faults_handler(parent_gpu)",
                "uvm_spin_unlock_irqrestore(&parent_gpu->isr.interrupts_lock)",
                "nv_kthread_q_flush(&parent_gpu->isr.bottom_half_q)",
            ]
            offsets = [flush.index(call) for call in ordered_calls]
            self.assertEqual(sorted(offsets), offsets)

            pending = _extract_function(non_replayable, "uvm_parent_gpu_non_replayable_faults_pending")
            self.assertIn("uvm_assert_spinlock_locked(&parent_gpu->isr.interrupts_lock)", pending)

            isr = (tree / "kernel-open/nvidia-uvm/uvm_gpu_isr.c").read_text()
            self.assertIn("unsigned uvm_parent_gpu_schedule_non_replayable_faults_handler(", isr)
            self.assertIn("uvm_parent_gpu_schedule_non_replayable_faults_handler(parent_gpu);", isr)
            self.assertNotIn("static unsigned uvm_parent_gpu_schedule_non_replayable_faults_handler(", isr)

            va_space = (tree / "kernel-open/nvidia-uvm/uvm_va_space.c").read_text()
            deferred_free = _extract_function(va_space, "uvm_deferred_free_object_channel")
            self.assertIn("flushed_gpus->non_replayable", deferred_free)
            self.assertIn("uvm_parent_gpu_non_replayable_buffer_flush(gpu->parent)", deferred_free)
            self.assertIn("channel->engine_type == UVM_GPU_CHANNEL_ENGINE_TYPE_GR", deferred_free)
            self.assertLess(
                deferred_free.index("uvm_parent_gpu_non_replayable_buffer_flush(gpu->parent)"),
                deferred_free.index("uvm_user_channel_destroy_detached(channel)"),
            )
            self.assertIn("uvm_parent_processor_mask_test_and_set(&flushed_gpus->non_replayable", deferred_free)
            self.assertIn("uvm_parent_processor_mask_test_and_set(&flushed_gpus->replayable", deferred_free)
            self.assertIn("uvm_parent_processor_mask_test_and_set(&flushed_gpus->access_counters", deferred_free)
            self.assertIn("uvm_gpu_fault_buffer_flush(gpu)", deferred_free)
            list_function = _extract_function(va_space, "uvm_deferred_free_object_list")
            for name in ("replayable", "non_replayable", "access_counters"):
                self.assertIn(f"uvm_parent_processor_mask_zero(&flushed_gpus.{name})", list_function)

    def test_suspend_and_deferred_free_backports_apply_in_sequence(self):
        with tempfile.TemporaryDirectory(prefix="r580-combined-fault-drains-") as directory:
            tree = Path(directory)
            for relative, expected_hash in BASE_HASHES.items():
                source = R580_ROOT / relative
                self.assertEqual(expected_hash, hashlib.sha256(source.read_bytes()).hexdigest(), relative)
                destination = tree / "kernel-open" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

            for patch_path in (SUSPEND_PATCH, PATCH):
                applied = subprocess.run(
                    ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_path)],
                    cwd=tree, check=False, capture_output=True, text=True,
                )
                self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
                self.assertNotIn("offset", applied.stdout.lower() + applied.stderr.lower())
                self.assertNotIn("fuzz", applied.stdout.lower() + applied.stderr.lower())

            global_source = (tree / "kernel-open/nvidia-uvm/uvm_global.c").read_text()
            self.assertIn("uvm_parent_gpu_service_non_replayable_fault_buffer(gpu->parent);", global_source)
            va_space = (tree / "kernel-open/nvidia-uvm/uvm_va_space.c").read_text()
            deferred_free = _extract_function(va_space, "uvm_deferred_free_object_channel")
            self.assertIn("uvm_parent_gpu_non_replayable_buffer_flush(gpu->parent)", deferred_free)


if __name__ == "__main__":
    unittest.main()
