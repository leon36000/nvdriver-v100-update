# SPDX-License-Identifier: MIT
"""Tests for NVIDIA/Linux hibernation callback interaction audit."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import audit_nvidia_hibernate_pm as AUDIT  # noqa: E402


def write_inputs(root: Path, *, thaw_resumes=False, recovery_maps_to_thaw=True,
                 coordinator_recover_action="HYBRID580_PM_DPM_ACTION_RESTORE",
                 supplier_wait_checks_error=False):
    driver = root / "driver"
    linux = root / "linux"
    coordinator = root / "coordinator"
    (driver / "nvidia").mkdir(parents=True)
    linux.mkdir()
    coordinator.mkdir()
    thaw_body = "return nvidia_resume(dev);" if thaw_resumes else "return 0;"
    recover_case = "case PM_EVENT_RECOVER: return ops->thaw;" if recovery_maps_to_thaw else "case PM_EVENT_RECOVER: return ops->resume;"
    (driver / "nvidia/nv.c").write_text(
        "struct dev_pm_ops nv_pm_ops = {"
        ".suspend=nv_pmops_suspend,.resume=nv_pmops_resume,"
        ".freeze=nv_pmops_freeze,.thaw=nv_pmops_thaw,"
        ".poweroff=nv_pmops_poweroff,.restore=nv_pmops_restore};\n"
        "int nv_pmops_suspend(struct device *dev) {"
        "status=nvidia_suspend(dev,NV_PM_ACTION_STANDBY,NV_FALSE);"
        "if(status!=NV_OK)nvidia_resume(dev,NV_PM_ACTION_RESUME);return status;}\n"
        "int nv_pmops_resume(struct device *dev) {"
        "return nvidia_resume(dev,NV_PM_ACTION_RESUME);}\n"
        "int nv_pmops_freeze(struct device *dev) {"
        "status=nvidia_suspend(dev,NV_PM_ACTION_HIBERNATE,NV_FALSE);"
        "if(status!=NV_OK)nvidia_resume(dev,NV_PM_ACTION_RESUME);return status;}\n"
        f"int nv_pmops_thaw(struct device *dev) {{{thaw_body}}}\n"
        "int nv_pmops_restore(struct device *dev) {"
        "return nvidia_resume(dev,NV_PM_ACTION_RESUME);}\n"
        "int nv_pmops_poweroff(struct device *dev) {return 0;}\n"
        "int nv_pm_notifier(struct notifier_block *nb,unsigned long event,void *unused) {"
        "switch(event){case PM_HIBERNATION_PREPARE: state=HIBERNATE;break;"
        "case PM_POST_HIBERNATION: state=RUNNING;break;default:return NOTIFY_DONE;}"
        "return nv_set_system_power_state(state);}\n"
        "NV_STATUS nvidia_suspend(struct device *dev) {"
        "if((nv->flags & NV_FLAG_SUSPENDED)!=0){nvl->suspend_count++;goto out;}"
        "nv->flags |= NV_FLAG_SUSPENDED;out:return NV_OK;}\n"
        "NV_STATUS nvidia_resume(struct device *dev) {"
        "if((nv->flags & NV_FLAG_SUSPENDED)==0)goto out;"
        "if(nvl->suspend_count!=0){nvl->suspend_count--;}else{"
        "status=nv_power_management(nv);if(status==NV_OK)"
        "nv->flags &= ~NV_FLAG_SUSPENDED;}out:return status;}\n"
        "int nv_suspend_devices(void){nv_preempt_user_channels();"
        "nv_uvm_suspend();nvidia_suspend(dev);return 0;}\n"
        "int nv_set_system_power_state(int state){return nv_suspend_devices();}\n"
    )
    (driver / "nvidia/nv-procfs.c").write_text(
        "ssize_t nv_procfs_write_suspend(void) {"
        "return nv_set_system_power_state(power_state);}\n"
    )
    supplier_error_check = (
        "if (link->supplier->power.resume_error) return false;"
        if supplier_wait_checks_error else "")
    (linux / "main.c").write_text(
        "static void dpm_wait(struct device *dev,bool async){"
        "if(async)wait_for_completion(&dev->power.completion);}\n"
        "static void dpm_wait_for_suppliers(struct device *dev,bool async){"
        "struct device_link *link;dev_for_each_link_to_supplier(link,dev){"
        "if(link->status!=DL_STATE_DORMANT)dpm_wait(link->supplier,async);"
        f"{supplier_error_check}"
        "}}\n"
        "static bool dpm_wait_for_superior(struct device *dev,bool async){"
        "dpm_wait(dev->parent,async);dpm_wait_for_suppliers(dev,async);"
        "return device_pm_initialized(dev);}\n"
        "static void device_resume_noirq(struct device *dev){"
        "int error=callback(dev);complete_all(&dev->power.completion);"
        "if(error){WRITE_ONCE(async_error,error);}}\n"
        "static void device_resume_early(struct device *dev){"
        "int error=callback(dev);complete_all(&dev->power.completion);"
        "if(error){WRITE_ONCE(async_error,error);}}\n"
        "static void device_resume(struct device *dev){"
        "int error=callback(dev);complete_all(&dev->power.completion);"
        "if(error){WRITE_ONCE(async_error,error);}}\n"
        "static void dpm_noirq_resume_devices(void){async_error=0;"
        "async_synchronize_full();if(READ_ONCE(async_error))"
        "dpm_save_failed_step(SUSPEND_RESUME_NOIRQ);}\n"
        "void dpm_resume_early(void){async_error=0;async_synchronize_full();"
        "if(READ_ONCE(async_error))dpm_save_failed_step(SUSPEND_RESUME_EARLY);}\n"
        "void dpm_resume(void){async_error=0;async_synchronize_full();"
        "if(READ_ONCE(async_error))dpm_save_failed_step(SUSPEND_RESUME);}\n"
        "static pm_callback_t pm_op(const struct dev_pm_ops *ops,pm_message_t state){"
        "switch(state.event){case PM_EVENT_SUSPEND:return ops->suspend;"
        "case PM_EVENT_RESUME:return ops->resume;"
        "case PM_EVENT_FREEZE:return ops->freeze;"
        "case PM_EVENT_QUIESCE:return ops->freeze;"
        "case PM_EVENT_POWEROFF:return ops->poweroff;"
        "case PM_EVENT_HIBERNATE:return ops->poweroff;"
        "case PM_EVENT_THAW:return ops->thaw;"
        f"{recover_case}"
        "case PM_EVENT_RESTORE:return ops->restore;}return NULL;}\n"
    )
    (linux / "hibernate.c").write_text(
        "static int hibernation_snapshot(void){"
        "error=dpm_suspend(PMSG_FREEZE);"
        "msg=in_suspend?(error?PMSG_RECOVER:PMSG_THAW):PMSG_RESTORE;"
        "dpm_resume(msg);return error;}\n"
        "int hibernate(void){"
        "error=pm_notifier_call_chain_robust(PM_HIBERNATION_PREPARE,PM_POST_HIBERNATION);"
        "if(error)goto out;error=hibernation_snapshot();"
        "pm_notifier_call_chain(PM_POST_HIBERNATION);out:return error;}\n"
    )
    (coordinator / "hybrid580_system_pm_coordinator.h").write_text(
        "static inline enum hybrid580_pm_dpm_action "
        "hybrid580_pm_dpm_action_for_event(enum hybrid580_pm_dpm_event event){"
        "switch(event){"
        "case HYBRID580_PM_DPM_SUSPEND:"
        "case HYBRID580_PM_DPM_FREEZE:"
        "case HYBRID580_PM_DPM_QUIESCE:"
        "case HYBRID580_PM_DPM_POWEROFF:"
        "case HYBRID580_PM_DPM_HIBERNATE:"
        "return HYBRID580_PM_DPM_ACTION_QUIESCE;"
        "case HYBRID580_PM_DPM_RESUME:"
        "case HYBRID580_PM_DPM_THAW:"
        "case HYBRID580_PM_DPM_RECOVER:"
        "case HYBRID580_PM_DPM_RESTORE:"
        f"return {coordinator_recover_action};"
        "case HYBRID580_PM_DPM_UNRELATED:"
        "return HYBRID580_PM_DPM_ACTION_IGNORE;"
        "default:return HYBRID580_PM_DPM_ACTION_IGNORE;}}\n"
    )


class NvidiaHibernatePmTests(unittest.TestCase):
    def test_finds_thaw_recover_and_restore_callback_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root)
            report = AUDIT.audit_inputs(root / "driver", root / "linux", "synthetic-r580")
            self.assertEqual(report["driver_pm_ops"]["freeze"], "nv_pmops_freeze")
            self.assertEqual(report["linux_dpm_dispatch"]["recover"], "thaw")
            self.assertEqual(report["linux_dpm_dispatch"]["restore"], "restore")
            self.assertTrue(report["driver_callbacks"]["thaw"]["returns_zero_without_resume"])
            self.assertTrue(report["driver_callbacks"]["restore"]["calls_nvidia_resume"])
            self.assertTrue(report["suspend_counter"]["nested_suspend_increments"])
            self.assertTrue(report["suspend_counter"]["nested_resume_only_decrements"])
            self.assertTrue(report["hibernation_order"]["prepare_notifier_precedes_dpm_freeze"])
            error_contract = report["linux_resume_error_propagation"]
            self.assertFalse(error_contract["supplier_wait_checks_callback_status"])
            self.assertTrue(error_contract["resume_completion_signaled_before_global_error_record"])
            self.assertTrue(error_contract["resume_errors_aggregated_only_as_global_async_error"])

    def test_rejects_new_linux_supplier_error_propagation_without_reaudit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root, supplier_wait_checks_error=True)
            with self.assertRaisesRegex(ValueError, "supplier callback status propagation changed"):
                AUDIT.audit_inputs(root / "driver", root / "linux", "changed-linux")

    def test_hybrid_event_matrix_matches_every_pinned_linux_dpm_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root)
            report = AUDIT.audit_inputs(
                root / "driver", root / "linux", "synthetic-r580",
                coordinator_header=root / "coordinator/hybrid580_system_pm_coordinator.h")
            self.assertTrue(report["coordinator_dpm_mapping"]["matches_linux_pm_ops"])
            self.assertEqual(
                report["linux_dpm_dispatch"]["event_to_dev_pm_ops"]["PM_EVENT_RESTORE"],
                "restore")

    def test_hybrid_event_matrix_rejects_recover_routed_to_quiesce(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root, coordinator_recover_action="HYBRID580_PM_DPM_ACTION_QUIESCE")
            with self.assertRaisesRegex(ValueError, "coordinator PM event matrix differs"):
                AUDIT.audit_inputs(
                    root / "driver", root / "linux", "unsafe",
                    coordinator_header=root / "coordinator/hybrid580_system_pm_coordinator.h")

    def test_rejects_recover_event_routed_away_from_thaw(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root, recovery_maps_to_thaw=False)
            with self.assertRaisesRegex(ValueError, "RECOVER no longer maps to thaw"):
                AUDIT.audit_inputs(root / "driver", root / "linux", "unsafe")

    def test_records_a_thaw_that_actually_resumes_instead_of_assuming_noop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root, thaw_resumes=True)
            report = AUDIT.audit_inputs(root / "driver", root / "linux", "changed-driver")
            self.assertFalse(report["driver_callbacks"]["thaw"]["returns_zero_without_resume"])
            self.assertTrue(report["driver_callbacks"]["thaw"]["calls_nvidia_resume"])

    def test_report_writer_is_private_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_inputs(root)
            report_path = root / "report.json"
            AUDIT.write_report(report_path, AUDIT.audit_inputs(
                root / "driver", root / "linux", "synthetic-r580"))
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                AUDIT.write_report(report_path, {})


if __name__ == "__main__":
    unittest.main()
