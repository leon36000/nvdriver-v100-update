# SPDX-License-Identifier: MIT
"""Tests for the source-pinned R580 callback/PM lifecycle audit."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "uvm_pm_lifecycle_audit", ROOT / "tools/audit_uvm_pm_lifecycle.py")
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


def write_source_tree(root: Path, *, preempt_first=True, clear_before_barrier=True,
                      flush_kill_channel=True, uvm_ioctl_trylock=True,
                      volta_non_replayable=True, blackwell_non_replayable=True,
                      drains_non_replayable=True,
                      drain_non_replayable_synchronously=False,
                      drain_non_replayable_under_service_lock=True,
                      service_interrupts_before_suspend=False,
                      service_interrupts_after_isr_suspend=False):
    synchronous_drain = ""
    if drain_non_replayable_synchronously:
        lock_call = (" uvm_parent_gpu_non_replayable_faults_isr_lock(gpu->parent);"
                     if drain_non_replayable_under_service_lock else "")
        unlock_call = (" uvm_parent_gpu_non_replayable_faults_isr_unlock(gpu->parent);"
                       if drain_non_replayable_under_service_lock else "")
        synchronous_drain = (
            " if (gpu->parent->isr.non_replayable_faults.handling) {" + lock_call +
            " uvm_parent_gpu_service_non_replayable_fault_buffer(gpu->parent);" +
            unlock_call + " }")
    files = {
        "common/inc/nv_uvm_types.h": """
            typedef NV_STATUS (*uvmEventSuspend_t) (void);
            typedef NV_STATUS (*uvmEventResume_t) (void);
            typedef NV_STATUS (*uvmEventStartDevice_t) (const NvProcessorUuid *uuid);
            typedef NV_STATUS (*uvmEventStopDevice_t) (const NvProcessorUuid *uuid);
            typedef NV_STATUS (*uvmEventIsrTopHalf_t) (const NvProcessorUuid *uuid);
            typedef NV_STATUS (*uvmEventDrainP2P_t) (const NvProcessorUuid *uuid);
            typedef NV_STATUS (*uvmEventResumeP2P_t) (const NvProcessorUuid *uuid);
        """,
        "nvidia/nv_uvm_interface.c": (
            "NV_STATUS nvUvmInterfaceRegisterUvmCallbacks(struct UvmOpsUvmEvents *importedUvmOps) {"
            " if (!importedUvmOps) return NV_ERR_INVALID_ARGUMENT;"
            " if (getUvmEvents() != NULL) return NV_ERR_IN_USE;"
            " setUvmEvents(importedUvmOps); return NV_OK; }"
            " void nvUvmInterfaceDeRegisterUvmOps(void) {"
            + (" setUvmEvents(NULL); on_each_cpu(flush_top_half, NULL, 1);" if clear_before_barrier
               else " on_each_cpu(flush_top_half, NULL, 1); setUvmEvents(NULL);")
            + " }"
            " NV_STATUS nv_uvm_event_interrupt(const NvU8 *uuid) {"
            " struct UvmOpsUvmEvents *events = getUvmEvents();"
            " if (events && events->isrTopHalf) return events->isrTopHalf(uuid);"
            " return NV_ERR_NO_INTR_PENDING; }"
        ),
        "nvidia/nv.c": (
            "static NV_STATUS nv_suspend_devices(void) {"
            + (" nv_preempt_user_channels(); nv_uvm_suspend(); nvidia_suspend();"
               if preempt_first else " nv_uvm_suspend(); nv_preempt_user_channels(); nvidia_suspend();")
            + " return NV_OK; }"
            " static NV_STATUS nv_resume_devices(void) {"
            " nvidia_resume(); nv_uvm_resume(); nv_restore_user_channels(); return NV_OK; }"
            " static int nv_pmops_suspend(struct device *dev) {"
            " return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE); }"
            " static int nv_pmops_resume(struct device *dev) {"
            " return nvidia_resume(dev, NV_PM_ACTION_RESUME); }"
            " static NV_STATUS nvidia_suspend(struct device *dev, int action, int procfs) {"
            " return nv_power_management(); }"
            " static int nv_pm_notifier(struct notifier_block *nb, unsigned long event, void *unused) {"
            " return nv_set_system_power_state(power_state, depth); }"
            " static int nvidia_init_module(void) {"
            " if (NVreg_UseKernelSuspendNotifiers) return register_pm_notifier(&nv_pm_nb);"
            " return 0; }"
            " static int nv_set_system_power_state(int state, int depth) {"
            " if (state) return nv_suspend_devices(); return nv_resume_devices(); }"
            " const char *nv_device_name = MODULE_NAME;"
        ),
        "nvidia/nv-procfs.c": (
            "static ssize_t nv_procfs_write_suspend(struct file *file, const char __user *buf,"
            " size_t count, loff_t *pos) {"
            " status = nv_set_system_power_state(power_state, nv_pm_action_depth);"
            " return status ? -EIO : count; }"
            " int nv_procfs_init(void) {"
            " char nv_dir_name[sizeof(\"driver/\" MODULE_NAME)];"
            " snprintf(nv_dir_name, sizeof(nv_dir_name), \"driver/%s\", nv_device_name);"
            " return 0; }"
        ),
        "nvidia-uvm/uvm_global.c": (
            "static NV_STATUS uvm_suspend(void) {"
            " uvm_down_write(&g_uvm_global.pm.lock);"
            " nv_kthread_q_flush(&g_uvm_global.global_q);"
            " uvm_gpu_fault_buffer_flush(gpu);"
            " uvm_parent_gpu_access_counters_set_ignore(gpu->parent, true);"
            + (" service_interrupts(gpu->parent);" if service_interrupts_before_suspend else "")
            +
            " uvm_parent_gpu_set_isr_suspended(gpu->parent, true);"
            + (" service_interrupts(gpu->parent);" if service_interrupts_after_isr_suspend else "")
            +
            " nv_kthread_q_flush(&gpu->parent->isr.bottom_half_q);"
            + synchronous_drain
            + (" if (handling) nv_kthread_q_flush(&gpu->parent->isr.kill_channel_q);"
               if flush_kill_channel else " if (handling) skip_kill_channel_flush();")
            + " uvm_va_space_down_write(va_space);"
            " g_uvm_global.pm.is_suspended = true; return NV_OK; }"
            " static NV_STATUS uvm_resume(void) { g_uvm_global.pm.is_suspended = false;"
            " uvm_up_write(&g_uvm_global.pm.lock);"
            " nv_kthread_q_flush(&g_uvm_global.deferred_release_q); return NV_OK; }"
        ),
        "nvidia-uvm/uvm_gpu.c": (
            "static NV_STATUS service_interrupts(uvm_parent_gpu_t *parent_gpu) {"
            " UVM_ASSERT(!in_interrupt());"
            " return uvm_rm_locked_call(nvUvmInterfaceServiceDeviceInterruptsRM(parent_gpu->rm_device));"
            " }"
        ),
        "nvidia-uvm/uvm_gpu_non_replayable_faults.c": (
            "void uvm_parent_gpu_service_non_replayable_fault_buffer(void *parent_gpu) {"
            " do { fetch_non_replayable_fault_buffer_entries(parent_gpu, &cached_faults);"
            " for (i = 0; i < cached_faults; ++i) service_fault(parent_gpu, entry);"
            + (" } while (cached_faults > 0); }" if drains_non_replayable else
               " } while (cached_faults < 0); }")
            +
            "static void kill_channel_delayed(void *channel) {"
            " nvUvmInterfaceReportNonReplayableFault(device, packet); }"
            " static void schedule_kill_channel(void *channel) {"
            " nv_kthread_q_schedule_q_item(&parent_gpu->isr.kill_channel_q, &item); }"
        ),
        "nvidia-uvm/uvm_gpu_isr.c": (
            "static unsigned schedule_non_replayable_faults_handler(void *parent_gpu) {"
            " if (!uvm_parent_gpu_non_replayable_faults_pending(parent_gpu)) return 0;"
            " return nv_kthread_q_schedule_q_item(&parent_gpu->isr.bottom_half_q,"
            " &parent_gpu->isr.non_replayable_faults.bottom_half_q_item); }"
            "static NV_STATUS uvm_isr_top_half(void *uuid) {"
            " schedule_non_replayable_faults_handler(parent_gpu); return NV_OK; }"
            "static void non_replayable_faults_isr_bottom_half(void *parent_gpu) {"
            " uvm_parent_gpu_service_non_replayable_fault_buffer(parent_gpu); }"
        ),
        "nvidia-uvm/uvm.c": (
            "static long uvm_unlocked_ioctl(void) {"
            + (" if (!uvm_down_read_trylock(&g_uvm_global.pm.lock)) return -EAGAIN;"
               if uvm_ioctl_trylock else " if (uvm_pm_lock_disabled()) return -EAGAIN;")
            + " ret = uvm_ioctl(filp, cmd, arg);"
            " uvm_up_read(&g_uvm_global.pm.lock); return ret; }"
            " static int uvm_mmap(void) {"
            " if (!uvm_down_read_trylock(&g_uvm_global.pm.lock)) {"
            " uvm_disable_vma(vma); return 0; }"
            " ret = uvm_map(vma); uvm_up_read(&g_uvm_global.pm.lock); return ret; }"
            " static void uvm_release_deferred(void *data) {"
            " uvm_down_read(&g_uvm_global.pm.lock);"
            " uvm_va_space_destroy(va_space);"
            " uvm_up_read(&g_uvm_global.pm.lock); }"
            " static void uvm_release_va_space(void) {"
            " if (uvm_down_read_trylock(&g_uvm_global.pm.lock)) {"
            " uvm_va_space_destroy(va_space); uvm_up_read(&g_uvm_global.pm.lock); }"
            " else { nv_kthread_q_item_init(&item, uvm_release_deferred, va_space);"
            " nv_kthread_q_schedule_q_item(&g_uvm_global.deferred_release_q, &item); } }"
        ),
        "nvidia-uvm/uvm_va_space.c": (
            "static vm_fault_t uvm_va_space_cpu_fault(void) {"
            " if (!uvm_down_read_trylock_no_tracking(&g_uvm_global.pm.lock)) {"
            " status = NV_ERR_BUSY_RETRY; goto convert_error; }"
            " return fault_service(); }"
        ),
        "nvidia-uvm/uvm_volta.c": (
            "static void init_volta(uvm_parent_gpu_t *parent_gpu) {"
            " parent_gpu->non_replayable_faults_supported = "
            + ("true" if volta_non_replayable else "false") + "; }"
        ),
        "nvidia-uvm/uvm_blackwell.c": (
            "static void init_blackwell(uvm_parent_gpu_t *parent_gpu) {"
            " parent_gpu->non_replayable_faults_supported = "
            + ("true" if blackwell_non_replayable else "false") + "; }"
        ),
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class UvmPmLifecycleAuditTests(unittest.TestCase):
    def test_reports_and_requires_uvm_internal_quiescence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root, "uvm-quiescence")
            facts = report["uvm_suspend_quiescence"]
            self.assertTrue(facts["takes_pm_write_lock_before_draining_work"])
            self.assertTrue(facts["flushes_global_work_and_isr_queues"])
            self.assertTrue(facts["takes_va_space_write_locks"])
            self.assertTrue(facts["resume_releases_pm_lock_then_flushes_deferred_release"])
            self.assertTrue(facts["kill_channel_worker_calls_rm_and_is_drained"])
            self.assertTrue(facts["rm_hardware_fault_buffer_flush_is_not_present"])
            self.assertTrue(report["uvm_callback_context"][
                "service_interrupts_rejects_interrupt_context"])

    def test_reports_non_replayable_fault_support_on_volta_and_blackwell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root, "non-replayable-fault-architectures")
            facts = report["architecture_fault_support"]
            self.assertTrue(facts["volta_non_replayable_faults_supported"])
            self.assertTrue(facts["blackwell_non_replayable_faults_supported"])

    def test_reports_non_replayable_fault_worker_drain_and_suspend_queue_flush(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            facts = AUDIT.audit_tree(root, "non-replayable-worker-drain")[
                "uvm_suspend_quiescence"]
            self.assertTrue(facts["rm_get_fault_service_drains_batches_until_empty"])
            self.assertNotIn("rm_shadow_fault_service_drains_until_empty", facts)
            self.assertTrue(facts["non_replayable_fault_isr_bottom_half_dispatches_service"])
            self.assertTrue(facts["non_replayable_worker_queue_flushed_during_suspend"])
            self.assertTrue(facts["non_replayable_pending_query_is_in_isr_top_half"])
            self.assertFalse(facts["suspend_rescans_pending_faults_before_queue_flush"])

    def test_reports_synchronous_non_replayable_drain_inside_suspend_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, drain_non_replayable_synchronously=True)
            facts = AUDIT.audit_tree(root, "synchronous-non-replayable-drain")[
                "uvm_suspend_quiescence"]
            self.assertTrue(facts["rm_get_fault_batches_synchronously_serviced_under_service_lock"])
            self.assertTrue(facts[
                "suspend_calls_rm_get_fault_service_after_bottom_half_before_kill_queue_flush"])
            self.assertFalse(facts["suspend_queries_rm_pending_fault_status"])
            self.assertTrue(facts["rm_hardware_fault_buffer_flush_is_not_present"])
            self.assertFalse(facts["suspend_rescans_pending_faults_before_queue_flush"])
            self.assertFalse(facts[
                "suspend_calls_rm_device_interrupt_service_before_isr_suspension"])

    def test_reports_rm_interrupt_service_before_isr_suspend_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, service_interrupts_before_suspend=True)
            facts = AUDIT.audit_tree(root, "rm-service-before-isr-barrier")[
                "uvm_suspend_quiescence"]
            self.assertTrue(facts[
                "suspend_calls_rm_device_interrupt_service_before_isr_suspension"])

    def test_reports_rm_interrupt_service_with_whitespace_before_parenthesis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, service_interrupts_before_suspend=True)
            path = root / "nvidia-uvm/uvm_global.c"
            source = path.read_text()
            self.assertIn("service_interrupts(gpu->parent);", source)
            path.write_text(source.replace(
                "service_interrupts(gpu->parent);",
                "service_interrupts (gpu->parent);", 1))
            facts = AUDIT.audit_tree(root, "rm-service-whitespace-call")[
                "uvm_suspend_quiescence"]
            self.assertTrue(facts[
                "suspend_calls_rm_device_interrupt_service_before_isr_suspension"])

    def test_does_not_treat_rm_interrupt_service_after_isr_suspend_as_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, service_interrupts_after_isr_suspend=True)
            facts = AUDIT.audit_tree(root, "rm-service-after-isr-barrier")[
                "uvm_suspend_quiescence"]
            self.assertFalse(facts[
                "suspend_calls_rm_device_interrupt_service_before_isr_suspension"])

    def test_independent_tree_agreement_includes_rm_interrupt_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline"
            changed = root / "changed"
            write_source_tree(baseline)
            write_source_tree(changed, service_interrupts_before_suspend=True)
            reports = [
                AUDIT.audit_tree(baseline, "baseline"),
                AUDIT.audit_tree(changed, "changed"),
            ]
            with self.assertRaisesRegex(ValueError, "disagree"):
                AUDIT.assert_independent_trees_agree(reports)

    def test_does_not_certify_non_replayable_drain_without_service_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, drain_non_replayable_synchronously=True,
                              drain_non_replayable_under_service_lock=False)
            facts = AUDIT.audit_tree(root, "synchronous-drain-without-lock")[
                "uvm_suspend_quiescence"]
            self.assertFalse(facts["rm_get_fault_batches_synchronously_serviced_under_service_lock"])
            self.assertFalse(facts["suspend_rescans_pending_faults_before_queue_flush"])

    def test_does_not_certify_fault_drain_before_bottom_half_queue_flush(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, drain_non_replayable_synchronously=True)
            source = root / "nvidia-uvm/uvm_global.c"
            text = source.read_text()
            bottom_half_flush = "nv_kthread_q_flush(&gpu->parent->isr.bottom_half_q);"
            unlock = "uvm_parent_gpu_non_replayable_faults_isr_unlock(gpu->parent);"
            self.assertEqual(text.count(bottom_half_flush), 1)
            self.assertEqual(text.count(unlock), 1)
            text = text.replace(bottom_half_flush, "", 1)
            text = text.replace(unlock, unlock + " " + bottom_half_flush, 1)
            source.write_text(text)

            facts = AUDIT.audit_tree(root, "fault-drain-before-worker-flush")[
                "uvm_suspend_quiescence"]
            self.assertTrue(facts["rm_get_fault_batches_synchronously_serviced_under_service_lock"])
            self.assertFalse(facts[
                "suspend_calls_rm_get_fault_service_after_bottom_half_before_kill_queue_flush"])

    def test_rejects_non_replayable_service_that_stops_draining(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, drains_non_replayable=False)
            with self.assertRaisesRegex(ValueError, "non-replayable-fault handler no longer drains"):
                AUDIT.audit_tree(root, "partial-non-replayable-drain")

    def test_rejects_volta_without_non_replayable_fault_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, volta_non_replayable=False)
            with self.assertRaisesRegex(ValueError, "Volta non-replayable fault support changed"):
                AUDIT.audit_tree(root, "volta-fault-capability-drift")

    def test_rejects_missing_kill_channel_queue_drain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, flush_kill_channel=False)
            with self.assertRaisesRegex(ValueError, "missing UVM kill-channel worker flush"):
                AUDIT.audit_tree(root, "missing-uvm-worker-drain")

    def test_reports_own_uvm_ioctl_mmap_release_and_fault_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root, "uvm-entry-admission")
            facts = report["uvm_entry_admission"]
            self.assertTrue(facts["ioctl_trylocks_pm_and_returns_eagain"])
            self.assertTrue(facts["mmap_trylocks_pm_and_disables_vma_on_failure"])
            self.assertTrue(facts["release_defers_teardown_when_pm_write_locked"])
            self.assertTrue(facts["fault_trylocks_pm_and_returns_busy_retry"])

    def test_rejects_uvm_ioctl_without_pm_trylock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, uvm_ioctl_trylock=False)
            with self.assertRaisesRegex(ValueError, "UVM ioctl entry lost PM trylock"):
                AUDIT.audit_tree(root, "uvm-ioctl-without-pm-gate")

    def test_distinguishes_global_procfs_pm_from_per_device_dpm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            report = AUDIT.audit_tree(root, "fixture")
            self.assertTrue(report["callback_registration"][
                "single_registration_slot_rejects_second"])
            self.assertTrue(report["callback_registration"][
                "de_registration_clears_then_quiesces_isr"])
            self.assertTrue(report["nvidia_global_pm_path"][
                "per_provider_preempts_local_channels_before_uvm_suspend_before_local_gpu_suspend"])
            self.assertTrue(report["nvidia_global_pm_path"][
                "uvm_suspend_holds_global_pm_write_lock_across_callback_return"])
            self.assertTrue(report["pci_device_pm_ops"]["suspend_is_device_local"])
            self.assertFalse(report["pci_device_pm_ops"]["suspend_calls_global_uvm_pm"])
            self.assertFalse(report["pci_device_pm_ops"][
                "pci_path_explicitly_preempts_channels_or_suspends_uvm"])
            self.assertTrue(report["system_pm_entrypoints"]["procfs_suspend_calls_global_state_machine"])
            self.assertTrue(report["system_pm_entrypoints"]["kernel_pm_notifier_supported"])
            self.assertTrue(report["system_pm_entrypoints"][
                "kernel_pm_notifier_registration_is_parameter_gated"])
            self.assertTrue(report["procfs_namespace"]["buffer_sizes_module_named_path"])

    def test_accepts_legacy_backend_without_global_kernel_pm_notifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            driver = root / "nvidia/nv.c"
            text = driver.read_text().replace(
                " return register_pm_notifier(&nv_pm_nb);", " return 0;")
            text = text.replace(
                " static int nv_pm_notifier(struct notifier_block *nb, unsigned long event, void *unused) {"
                " return nv_set_system_power_state(power_state, depth); }", "")
            driver.write_text(text)
            report = AUDIT.audit_tree(root, "legacy-no-notifier")
            self.assertFalse(report["system_pm_entrypoints"]["kernel_pm_notifier_supported"])
            self.assertTrue(report["system_pm_entrypoints"]["procfs_suspend_calls_global_state_machine"])

    def test_rejects_global_uvm_suspend_in_device_pm_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root)
            driver = root / "nvidia/nv.c"
            driver.write_text(driver.read_text().replace(
                "return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE);",
                "nv_uvm_suspend(); return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE);"))
            with self.assertRaisesRegex(ValueError, "PCI PM callback must stay device-local"):
                AUDIT.audit_tree(root, "bad-pci-pm")

    def test_rejects_unsafe_preemption_or_isr_teardown_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, preempt_first=False)
            with self.assertRaisesRegex(ValueError, "missing ordered source token"):
                AUDIT.audit_tree(root, "bad-pm-order")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_source_tree(root, clear_before_barrier=False)
            with self.assertRaisesRegex(ValueError, "callback lifecycle drift"):
                AUDIT.audit_tree(root, "bad-isr-teardown")


if __name__ == "__main__":
    unittest.main()
