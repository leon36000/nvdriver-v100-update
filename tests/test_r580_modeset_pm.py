# SPDX-License-Identifier: MIT
"""Tests for the pinned R580 modeset/system-PM source audit."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "r580_modeset_pm_audit", ROOT / "tools/audit_r580_modeset_pm.py")
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


def write_fixture(root: Path, *, suspend_guard=True, resume_guard=True,
                  rollback_guard=True, global_unlock=True, fixed_minor=True):
    (root / "nvidia").mkdir(parents=True)
    (root / "nvidia-modeset").mkdir()
    (root / "common/inc").mkdir(parents=True)
    minor_value = "254" if fixed_minor else "255"
    (root / "common/inc/nv-chardev-numbers.h").write_text(
        "#define NV_MAJOR_DEVICE_NUMBER 195\n"
        "#define NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE " + minor_value + "\n")
    suspend_call = ("if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS) { "
                    "nvidia_modeset_suspend(0); } " if suspend_guard else
                    "nvidia_modeset_suspend(0); ")
    rollback_call = ("if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS) { "
                     "nvidia_modeset_resume(0); } " if rollback_guard else
                     "nvidia_modeset_resume(0); ")
    resume_call = ("if (pm_action_depth != NV_PM_ACTION_DEPTH_CHANNELS) { "
                   "nvidia_modeset_resume(0); } " if resume_guard else
                   "nvidia_modeset_resume(0); ")
    (root / "nvidia/nv.c").write_text(
        "static int nv_suspend_devices(int pm_action_depth) { "
        + suspend_call +
        "if (pm_action_depth == NV_PM_ACTION_DEPTH_MODESET) return NV_OK; "
        "nv_preempt_user_channels(); "
        "if (pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS) return NV_OK; "
        "done: if (status != NV_OK) { " + rollback_call + " } "
        "return NV_OK; } "
        "static int nv_resume_devices(int pm_action_depth) { "
        "if (pm_action_depth == NV_PM_ACTION_DEPTH_MODESET) goto resume_modeset; "
        "if (pm_action_depth == NV_PM_ACTION_DEPTH_CHANNELS) { "
        "nv_restore_user_channels(); goto resume_modeset; } "
        "resume_modeset: " + resume_call + "return NV_OK; } "
        "static int nvidia_suspend(void) { nvidia_modeset_suspend(nv->gpu_id); return 0; } "
        "static int nvidia_resume(void) { nvidia_modeset_resume(nv->gpu_id); return 0; }"
    )
    (root / "nvidia/nv-modeset-interface.c").write_text(
        "static const nvidia_modeset_callbacks_t *nv_modeset_callbacks; "
        "static int nvidia_modeset_set_callbacks(const nvidia_modeset_callbacks_t *cb) { "
        "if ((nv_modeset_callbacks != NULL && cb != NULL) || "
        "(nv_modeset_callbacks == NULL && cb == NULL)) return -EINVAL; "
        "nv_modeset_callbacks = cb; return 0; } "
        "void nvidia_modeset_suspend(NvU32 gpuId) { "
        "if (nv_modeset_callbacks) nv_modeset_callbacks->suspend(gpuId); } "
        "void nvidia_modeset_resume(NvU32 gpuId) { "
        "if (nv_modeset_callbacks) nv_modeset_callbacks->resume(gpuId); }\n"
    )
    (root / "nvidia-modeset/nvidia-modeset-linux.c").write_text(
        "#define NVKMS_RDEV MKDEV(NV_MAJOR_DEVICE_NUMBER, NV_MINOR_DEVICE_NUMBER_MODESET_DEVICE)\n"
        "static inline void nvkms_write_lock_pm_lock(void) { down_write(&nvkms_pm_lock); } "
        "static inline void nvkms_write_unlock_pm_lock(void) { up_write(&nvkms_pm_lock); } "
        "static void nvkms_suspend(NvU32 gpuId) { "
        "if (gpuId == 0) nvkms_write_lock_pm_lock(); down(&nvkms_lock); "
        "nvKmsSuspend(gpuId); up(&nvkms_lock); } "
        "static void nvkms_resume(NvU32 gpuId) { down(&nvkms_lock); "
        "nvKmsResume(gpuId); up(&nvkms_lock); "
        + ("if (gpuId == 0) nvkms_write_unlock_pm_lock(); "
           if global_unlock else "")
        + "} int nvkms_register_chrdev(void) { "
        "return register_chrdev_region(NVKMS_RDEV, 1, \"nvidia-modeset\"); }\n"
    )


class R580ModesetPmAuditTests(unittest.TestCase):
    def test_channel_depth_skips_aggregate_modeset_and_preserves_per_gpu_dpm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root)
            report = AUDIT.audit_bundle(root, "fixture")
            provider = report["provider_pm"]
            modeset = report["modeset_interface"]
            self.assertTrue(provider["channel_depth_skips_aggregate_modeset_suspend"])
            self.assertTrue(provider["channel_depth_skips_aggregate_modeset_resume"])
            self.assertTrue(provider["channel_depth_rollback_skips_aggregate_modeset_resume"])
            self.assertTrue(provider["pci_dpm_keeps_per_gpu_modeset_suspend"])
            self.assertTrue(provider["pci_dpm_keeps_per_gpu_modeset_resume"])
            self.assertTrue(provider["modeset_suspend_precedes_channel_preemption"])
            self.assertTrue(modeset["callback_slot_rejects_second_registration"])
            self.assertTrue(modeset["suspend_resume_callbacks_return_no_status"])
            self.assertTrue(modeset["gpu_zero_pairs_global_write_lock_and_unlock"])
            self.assertTrue(modeset["fixed_chrdev_reservation"])
            self.assertEqual(report["qualification"], "static-source-contract-only")

    def test_rejects_global_modeset_lock_without_matching_resume_unlock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, global_unlock=False)
            with self.assertRaisesRegex(ValueError, "global modeset PM lock is not paired"):
                AUDIT.audit_bundle(root, "unpaired")

    def test_rejects_unbalanced_channel_depth_modeset_guards(self):
        for changed in ({"suspend_guard": False}, {"resume_guard": False},
                        {"rollback_guard": False}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_fixture(root, **changed)
                with self.assertRaisesRegex(ValueError, "channels-only phase must defer NVKMS"):
                    AUDIT.audit_bundle(root, "unguarded")

    def test_rejects_modeset_character_device_shape_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_fixture(root, fixed_minor=False)
            with self.assertRaisesRegex(ValueError, "fixed modeset device reservation changed"):
                AUDIT.audit_bundle(root, "changed-minor")


if __name__ == "__main__":
    unittest.main()
