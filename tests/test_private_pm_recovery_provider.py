# SPDX-License-Identifier: MIT
"""Source contract for the two private R580 PM recovery provider builds."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PrivatePmRecoveryProviderTests(unittest.TestCase):
    def test_both_builders_compile_the_namespaced_provider_api(self):
        open_builder = (ROOT / "tools/probe_private_backend_chardev.py").read_text()
        legacy_builder = (ROOT / "tools/build_private_proprietary580.py").read_text()
        self.assertIn("0035-private-open-pm-recovery-provider.patch", open_builder)
        self.assertIn("0035-private-legacy-pm-recovery-provider.patch", legacy_builder)
        for source_name in ("hybrid580-pm-provider-kernel.h",
                            "hybrid580-pm-provider-recovery.h"):
            self.assertIn(source_name, open_builder)
            self.assertIn(source_name, legacy_builder)
        self.assertIn("hybrid580_open_pm_recovery_' + operation + '_v1",
                      open_builder)
        self.assertIn("hybrid580_legacy_pm_recovery_' + operation + '_v1",
                      legacy_builder)
        self.assertIn("('begin', 'recover', 'end')", open_builder)
        self.assertIn("('begin', 'recover', 'end')", legacy_builder)
        self.assertIn("hybrid580_open_pm_channels_' + operation + '_v1", open_builder)
        self.assertIn("hybrid580_legacy_pm_channels_' + operation + '_v1", legacy_builder)
        self.assertIn("('suspend', 'resume')", open_builder)
        self.assertIn("('suspend', 'resume')", legacy_builder)
        self.assertIn("'new_pm_channels_exports_exact'", legacy_builder)
        self.assertIn("'new_pm_recovery_exports_exact'", legacy_builder)
        self.assertIn("len(actual) != len(wanted)", legacy_builder)

    def test_linux_provider_records_resume_thaw_restore_and_fallback(self):
        bridge = (ROOT / "src/hybrid580_pm_provider_kernel.h").read_text()
        self.assertIn("LOCK_NV_LINUX_DEVICES();", bridge)
        self.assertIn("hybrid580_pm_provider_status_for_nvl", bridge)
        self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_RESUME", bridge)
        self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_THAW", bridge)
        self.assertIn("NV_STATUS rm_status = nvidia_resume(", bridge)
        self.assertIn("nvl->dev, NV_PM_ACTION_RESUME", bridge)
        self.assertIn("NV_FLAG_SUSPENDED", bridge)
        self.assertIn("nvl->suspend_count", bridge)
        self.assertIn("if (nvl->dev == NULL)", bridge)
        self.assertIn("if (first_error == 0)\n        hybrid580_pm_provider_active_generation = 0;",
                      bridge)

    def test_namespaced_pm_exports_have_prior_prototypes(self):
        bridge = (ROOT / "src/hybrid580_pm_provider_kernel.h").read_text()
        for api in (
            "pm_recovery_begin_v1", "pm_recovery_recover_v1", "pm_recovery_end_v1",
            "pm_channels_suspend_v1", "pm_channels_resume_v1",
        ):
            self.assertIn(f"HYBRID580_PM_PROVIDER_API({api})", bridge)
            self.assertIn(f"EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API({api}))", bridge)
        shared = bridge[bridge.index("#ifdef HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER"):
                        bridge.index("#endif /* HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER */")]
        self.assertIn("pm_shared_uvm_suspend_v1)(void);", shared)
        self.assertIn("pm_shared_uvm_resume_v1)(void);", shared)

    def test_channels_are_tracked_per_gpu_and_resume_errors_are_retried(self):
        bridge = (ROOT / "src/hybrid580_pm_provider_kernel.h").read_text()
        recovery = (ROOT / "src/hybrid580_pm_provider_recovery.h").read_text()
        self.assertIn("pm_channels_suspend_v1", bridge)
        self.assertIn("pm_channels_resume_v1", bridge)
        self.assertIn("nv_preempt_user_channels(NV_STATE_PTR(nvl))", bridge)
        self.assertIn("nv_restore_user_channels(NV_STATE_PTR(nvl))", bridge)
        self.assertIn("hybrid580_pm_provider_channels_suspend_attempt(", bridge)
        self.assertIn("hybrid580_pm_provider_channels_restore_result(", bridge)
        self.assertIn("if (provider_status->channels_suspended)", bridge)
        self.assertIn("if (!provider_status->channels_suspended)", bridge)
        self.assertIn("if (status->channels_suspended)\n        return -EBUSY;", recovery)
        self.assertIn("channels_generation", recovery)
        self.assertIn("hybrid580_pm_provider_active_channels_generation", bridge)
        recovery_body = bridge[bridge.index(
            "int\nHYBRID580_PM_PROVIDER_API(pm_recovery_recover_v1)("):
                               bridge.index("EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_recovery_recover_v1))")]
        self.assertNotIn("active_channels_generation != 0", recovery_body)
        end_body = bridge[bridge.index(
            "int\nHYBRID580_PM_PROVIDER_API(pm_recovery_end_v1)("):
                          bridge.index("EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_recovery_end_v1))")]
        self.assertNotIn("active_channels_generation", end_body)
        suspend_export = bridge.index(
            "EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_channels_suspend_v1))")
        resume_body = bridge[bridge.index(
            "int HYBRID580_PM_PROVIDER_API(pm_channels_resume_v1)(", suspend_export):
                             bridge.index("EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_channels_resume_v1))")]
        self.assertNotIn("provider_status->armed", resume_body)
        self.assertIn("if (first_error == 0)\n        hybrid580_pm_provider_active_channels_generation = 0;",
                      resume_body)

    def test_patch_hooks_record_the_actual_linux_pm_callback_kind(self):
        for patch_name, prefix in (
            ("patches/r580.178.04/0035-private-open-pm-recovery-provider.patch",
             "hybrid580_open_"),
            ("patches/r580.178.04/proprietary/0035-private-legacy-pm-recovery-provider.patch",
             "hybrid580_legacy_"),
        ):
            patch = (ROOT / patch_name).read_text()
            self.assertIn("HYBRID580_PM_PROVIDER_PREFIX " + prefix, patch)
            self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_RESUME", patch)
            self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_RESTORE", patch)
            self.assertIn("HYBRID580_PM_PROVIDER_CALLBACK_THAW", patch)

    def test_shared_uvm_suspend_resume_has_one_open_provider_owner(self):
        bridge = (ROOT / "src/hybrid580_pm_provider_kernel.h").read_text()
        open_patch = (ROOT / "patches/r580.178.04/0035-private-open-pm-recovery-provider.patch").read_text()
        legacy_patch = (ROOT / "patches/r580.178.04/proprietary/0035-private-legacy-pm-recovery-provider.patch").read_text()
        open_builder = (ROOT / "tools/probe_private_backend_chardev.py").read_text()
        self.assertIn("#define HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER 1", open_patch)
        self.assertNotIn("HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER", legacy_patch)
        self.assertIn("nv_uvm_suspend_registered_v1", open_patch)
        self.assertIn("nv_uvm_resume_registered_v1", open_patch)
        self.assertIn("events != NULL && events->suspend != NULL", open_patch)
        self.assertIn("events != NULL && events->resume != NULL", open_patch)
        self.assertIn("NV_ERR_NOT_SUPPORTED", open_patch)
        self.assertIn("hybrid580-pm-shared-uvm.h", bridge)
        self.assertIn("hybrid580_pm_shared_uvm_suspend(", bridge)
        self.assertIn("hybrid580_pm_shared_uvm_resume(", bridge)
        self.assertIn("pm_shared_uvm_suspend_v1", bridge)
        self.assertIn("pm_shared_uvm_resume_v1", bridge)
        self.assertIn("hybrid580_open_pm_shared_uvm_' + operation + '_v1", open_builder)
        self.assertIn("('suspend', 'resume')", open_builder)
        self.assertIn("test_hybrid580_pm_shared_uvm.py", open_builder)


if __name__ == "__main__":
    unittest.main()
