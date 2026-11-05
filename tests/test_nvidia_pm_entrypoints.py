# SPDX-License-Identifier: MIT
"""Tests for NVIDIA PCI-DPM versus global PM source classification."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "nvidia_pm_entrypoints", ROOT / "tools/audit_nvidia_pm_entrypoints.py")
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


def write_tree(root: Path, *, notifier=True, private_path=True, device_local=True):
    root.joinpath("nvidia").mkdir(parents=True)
    root.joinpath("nvidia-uvm").mkdir()
    root.joinpath("nvidia/nv.c").write_text(
        "int nv_pmops_suspend(struct device *dev) { "
        + ("return nvidia_suspend(dev);" if device_local
           else "nv_uvm_suspend(); return nvidia_suspend(dev);")
        + " } int nv_pmops_resume(struct device *dev) { return nvidia_resume(dev); } "
        "int nvidia_suspend(struct device *dev) { return nv_power_management(); } "
        "int nv_suspend_devices(void) { nv_preempt_user_channels(); nv_uvm_suspend(); "
        "nvidia_suspend(dev); return 0; } "
        "int nv_resume_devices(void) { nvidia_resume(dev); nv_uvm_resume(); "
        "nv_restore_user_channels(); return 0; } "
        "int nv_set_system_power_state(int state) { "
        "if (state) return nv_suspend_devices(); return nv_resume_devices(); } "
        + ("int nv_pm_notifier(void) { return nv_set_system_power_state(state); } "
           "int nvidia_init_module(void) { if (NVreg_UseKernelSuspendNotifiers) "
           "return register_pm_notifier(&nv_pm_nb); return 0; } "
           if notifier else "int nvidia_init_module(void) { return 0; } ")
        + "const char *nv_device_name = MODULE_NAME;\n")
    buffer = 'sizeof("driver/" MODULE_NAME)' if private_path else "20"
    root.joinpath("nvidia/nv-procfs.c").write_text(
        "ssize_t nv_procfs_write_suspend(void) { "
        "return nv_set_system_power_state(power_state); } "
        "int nv_procfs_init(void) { char nv_dir_name[" + buffer + "]; "
        "snprintf(nv_dir_name, sizeof(nv_dir_name), \"driver/%s\", nv_device_name); "
        "return 0; }\n")
    root.joinpath("nvidia-uvm/uvm_global.c").write_text("/* not inspected here */\n")
    with root.joinpath("nvidia/nv.c").open("a") as source:
        source.write(
            "int nvidia_open(struct inode *inode, struct file *file) { "
            "if (nv_is_control_device(inode)) return nvidia_ctl_open(inode, file); "
            "nv_down_read_interruptible(&nv_system_pm_lock); "
            "up_read(&nv_system_pm_lock); return 0; } "
            "int nvidia_close(struct inode *inode, struct file *file) { "
            "if (nv_is_control_device(inode)) return nvidia_ctl_close(inode, file); "
            "down_read(&nv_system_pm_lock); up_read(&nv_system_pm_lock); return 0; } "
            "static void nvidia_open_deferred(void *data) { "
            "down(&nvl->ldata_lock); nv_open_device_for_nvlfp(); "
            "up(&nvl->ldata_lock); } "
        "NV_STATUS nv_power_management(void) { "
        "nv_kthread_q_flush(&nvl->open_q); "
        "return rm_power_management(sp, nv, action); } "
        "int nv_pmops_suspend(struct device *dev) { "
        "return nvidia_suspend(dev, NV_PM_ACTION_STANDBY, NV_FALSE); } "
        "int nv_pmops_resume(struct device *dev) { "
        "return nvidia_resume(dev, NV_PM_ACTION_RESUME); } "
        "static int nv_start_device(nv_state_t *nv, nvidia_stack_t *sp) { "
        "if (nv->flags & NV_FLAG_USES_MSIX) { nv_request_msix_irq(nvl); } "
        "else { request_threaded_irq(nv->interrupt_line, nvidia_isr, "
        "nvidia_isr_kthread_bh, nv_default_irq_flags(nv), name, (void *)nvl); } "
        "nv_kthread_q_item_init(&nvl->bottom_half_q_item, callback, nv); "
        "nv_kthread_q_init(&nvl->bottom_half_q, name); "
        "rm_init_adapter(sp, nv); nv->flags |= NV_FLAG_OPEN; "
        "return 0; } "
        "irqreturn_t nvidia_isr(int irq, void *arg) { "
        "rm_gpu_handle_mmu_faults(...); nv_uvm_event_interrupt(...); "
        "rm_isr(...); nv_kthread_q_schedule_q_item(&nvl->bottom_half_q, "
        "&nvl->bottom_half_q_item); return IRQ_HANDLED; } "
        "irqreturn_t nvidia_isr_msix(int irq, void *arg) { "
        "NV_SPIN_LOCK(&nvl->msix_isr_lock); ret = nvidia_isr(irq, arg); "
        "NV_SPIN_UNLOCK(&nvl->msix_isr_lock); return ret; } "
        "irqreturn_t nvidia_isr_msix_kthread_bh(int irq, void *data) { "
        "os_acquire_mutex(nvl->msix_bh_mutex); ret = nvidia_isr_common_bh(data); "
        "os_release_mutex(nvl->msix_bh_mutex); return ret; } "
        "void nv_shutdown_adapter(...) { rm_disable_adapter(...); "
        "nv_kthread_q_stop(&nvl->bottom_half_q); free_irq(...); }\n")
    root.joinpath("nvidia/nv-pci.c").write_text(
        "static int nv_pci_probe(struct pci_dev *pdev) { "
        "pci_enable_device(pdev); rm_init_private_state(sp, nv); "
        "pci_set_master(pdev); return 0; } "
        "static void nv_pci_remove(struct pci_dev *pdev) { "
        "nv_linux_stop_open_q(nvl); nv_shutdown_adapter(sp, nv, nvl); }\n")
    root.joinpath("nvidia/nv-msi.c").write_text(
        "int nv_request_msix_irq(nv_linux_state_t *nvl) { "
        "for (i = 0, msix_entries = nvl->msix_entries; i < nvl->num_intr; "
        "i++, msix_entries++) { "
        "rc = request_threaded_irq(msix_entries->vector, nvidia_isr_msix, "
        "nvidia_isr_msix_kthread_bh, nv_default_irq_flags(nv), name, "
        "(void *)nvl); if (rc) { for (j = 0; j < i; j++) "
        "free_irq(nvl->msix_entries[j].vector, (void *)nvl); break; } } "
        "return rc; }\n")
    root.joinpath("common/inc").mkdir(parents=True)
    root.joinpath("common/inc/nv-linux.h").write_text(
        "static inline NvU32 nv_default_irq_flags(nv_state_t *nv) { "
        "NvU32 flags = 0; if ((nv->flags & "
        "(NV_FLAG_USES_MSI | NV_FLAG_USES_MSIX)) == 0) "
        "flags |= IRQF_SHARED; return flags; }\n")
    root.joinpath("nvidia/nv-kthread-q.c").write_text(
        "void nv_kthread_q_stop(nv_kthread_q_t *q) { "
        "nv_kthread_q_flush(q); if (!list_empty(&q->q_list_head)) warn(); "
        "if (!atomic_read(&q->main_loop_should_exit)) { "
        "atomic_set(&q->main_loop_should_exit, 1); up(&q->q_sem); "
        "kthread_stop(q->q_kthread); } } "
        "int nv_kthread_q_schedule_q_item(nv_kthread_q_t *q, "
        "nv_kthread_q_item_t *q_item) { "
        "if (atomic_read(&q->main_loop_should_exit)) return 0; "
        "return _raw_q_schedule(q, q_item); } "
        "static int _raw_q_schedule(nv_kthread_q_t *q, "
        "nv_kthread_q_item_t *q_item) { "
        "spin_lock_irqsave(&q->q_lock, flags); "
        "if (list_empty(&q_item->q_list_node)) "
        "list_add_tail(&q_item->q_list_node, &q->q_list_head); "
        "spin_unlock_irqrestore(&q->q_lock, flags); up(&q->q_sem); return 1; }\n")
    root.joinpath("common/inc/nv-kthread-q.h").write_text(
        "void nv_kthread_q_stop(nv_kthread_q_t *q);\n")
    root.joinpath("nvidia-uvm/uvm_global.c").write_text(
        "NV_STATUS uvm_suspend(void) { "
        "uvm_down_write(&g_uvm_global.pm.lock); "
        "nv_kthread_q_flush(&g_uvm_global.global_q); "
        "nv_kthread_q_flush(&gpu->parent->isr.bottom_half_q); return NV_OK; }\n")


class NvidiaPmEntrypointTests(unittest.TestCase):
    def test_classifies_private_r580_procfs_and_device_pm_separately(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            report = AUDIT.audit_tree(root, "private-r580")
            self.assertTrue(report["pci_device_pm"]["callbacks_call_per_device_suspend_resume"])
            self.assertFalse(report["pci_device_pm"][
                "explicit_channel_preempt_or_restore_in_pmops_or_helper"])
            self.assertTrue(report["global_nvidia_pm"][
                "procfs_suspend_enters_global_state_machine"])
            self.assertTrue(report["kernel_pm_notifier"]["registration_supported_in_source"])
            self.assertTrue(report["kernel_pm_notifier"]["registration_parameter_gated"])
            self.assertTrue(report["procfs_namespace"]["buffer_sized_for_private_module_name"])

    def test_accepts_r580_without_notifier_and_flags_short_private_path_buffer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, notifier=False, private_path=False)
            report = AUDIT.audit_tree(root, "r580")
            self.assertFalse(report["kernel_pm_notifier"]["registration_supported_in_source"])
            self.assertFalse(report["procfs_namespace"]["buffer_sized_for_private_module_name"])

    def test_rejects_global_uvm_call_from_pci_pmops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root, device_local=False)
            with self.assertRaisesRegex(ValueError, "PCI PMOps no longer remain device-local"):
                AUDIT.audit_tree(root, "unsafe")

    def test_reports_rwsem_lifetime_gaps_and_detects_remove_path_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            report = AUDIT.audit_tree(root, "r580-lifetime")
            gate = report.get("lifetime_gate")
            self.assertIsNotNone(gate, "audit must classify PM lifetime-gate coverage")
            self.assertTrue(gate["control_open_bypasses_rwsem"])
            self.assertTrue(gate["control_close_bypasses_rwsem"])
            self.assertTrue(gate["deferred_open_bypasses_rwsem"])
            self.assertTrue(gate["native_suspend_flushes_deferred_opens_before_rm"])
            self.assertTrue(gate["pci_remove_bypasses_rwsem_and_tears_down_adapter"])
            self.assertTrue(gate["uvm_uses_separate_pm_lock_and_queue_drain"])
            self.assertFalse(gate["nv_system_pm_lock_is_complete_lifetime_gate"])

            pci = root / "nvidia/nv-pci.c"
            source = pci.read_text()
            pci.write_text(source.replace(
                "nv_pci_remove(struct pci_dev *pdev) { ",
                "nv_pci_remove(struct pci_dev *pdev) { "
                "down_read(&nv_system_pm_lock); ", 1))
            changed = AUDIT.audit_tree(root, "r580-lifetime-mutated")
            self.assertFalse(changed["lifetime_gate"][
                "pci_remove_bypasses_rwsem_and_tears_down_adapter"])

    def test_reports_irq_sharing_isr_serialization_and_deferred_work_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            report = AUDIT.audit_tree(root, "r580-irq-lifetime")
            irq = report.get("irq_lifecycle")
            self.assertIsNotNone(irq, "audit must classify provider IRQ lifecycle")
            self.assertTrue(irq["legacy_irq_allows_sharing"])
            self.assertTrue(irq["msix_uses_threaded_per_vector_handlers"])
            self.assertTrue(irq["msix_setup_rolls_back_prior_vectors_on_partial_failure"])
            self.assertTrue(irq["msix_top_half_serializes_rm_isr"])
            self.assertTrue(irq["msix_thread_serializes_common_bottom_half"])
            self.assertTrue(irq["isr_can_schedule_provider_bottom_half_queue"])
            self.assertTrue(irq["shutdown_stops_bottom_half_queue_before_free_irq"])
            self.assertFalse(irq["suspend_path_explicitly_synchronizes_or_frees_irqs"])

    def test_reports_the_conditional_pre_init_irq_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            startup = AUDIT.audit_tree(root, "r580-startup").get("startup_order")
            self.assertIsNotNone(startup, "audit must classify pre-init IRQ ordering")
            self.assertTrue(startup["legacy_irq_registered_before_bottom_half_queue_setup"])
            self.assertTrue(startup["msix_irq_registered_before_bottom_half_queue_setup"])
            self.assertTrue(startup["bottom_half_item_initialized_before_queue"])
            self.assertTrue(startup["queue_initialized_before_rm_init_adapter"])
            self.assertTrue(startup["rm_init_adapter_before_open_flag"])
            self.assertTrue(startup["rm_private_state_initialized_before_pci_bus_master"])

    def test_startup_audit_detects_queue_order_and_pci_probe_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            driver = root / "nvidia/nv.c"
            driver.write_text(driver.read_text().replace(
                "nv_kthread_q_item_init(&nvl->bottom_half_q_item, callback, nv); "
                "nv_kthread_q_init(&nvl->bottom_half_q, name);",
                "nv_kthread_q_init(&nvl->bottom_half_q, name); "
                "nv_kthread_q_item_init(&nvl->bottom_half_q_item, callback, nv);", 1))
            startup = AUDIT.audit_tree(root, "r580-reordered-start") ["startup_order"]
            self.assertFalse(startup["bottom_half_item_initialized_before_queue"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            pci = root / "nvidia/nv-pci.c"
            pci.write_text(pci.read_text().replace(
                "rm_init_private_state(sp, nv); pci_set_master(pdev);",
                "pci_set_master(pdev); rm_init_private_state(sp, nv);", 1))
            startup = AUDIT.audit_tree(root, "r580-reordered-probe") ["startup_order"]
            self.assertFalse(startup["rm_private_state_initialized_before_pci_bus_master"])

    def test_detects_irq_sharing_and_shutdown_order_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            header = root / "common/inc/nv-linux.h"
            header.write_text(header.read_text().replace("flags |= IRQF_SHARED;", ""))
            irq = AUDIT.audit_tree(root, "r580-no-shared-irq")["irq_lifecycle"]
            self.assertFalse(irq["legacy_irq_allows_sharing"])

            with tempfile.TemporaryDirectory() as second_directory:
                second = Path(second_directory)
                write_tree(second)
                driver = second / "nvidia/nv.c"
                source = driver.read_text()
                source = source.replace(
                    "nv_kthread_q_stop(&nvl->bottom_half_q); free_irq(...);",
                    "free_irq(...); nv_kthread_q_stop(&nvl->bottom_half_q);")
                driver.write_text(source)
                irq = AUDIT.audit_tree(
                    second, "r580-mutated-shutdown-order")["irq_lifecycle"]
                self.assertFalse(irq["shutdown_stops_bottom_half_queue_before_free_irq"])

    def test_classifies_post_flush_queue_race_and_recognizes_a_locked_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_tree(root)
            report = AUDIT.audit_tree(root, "r580-queue-window")
            queue = report.get("deferred_queue_lifecycle")
            self.assertIsNotNone(queue, "audit must classify queue shutdown ordering")
            self.assertTrue(queue["stop_flushes_before_setting_exit"])
            self.assertTrue(queue["schedule_checks_exit_before_enqueue_entrypoint"])
            self.assertFalse(queue["raw_enqueue_rechecks_exit_under_queue_lock"])
            self.assertFalse(queue["stop_exit_transition_uses_queue_lock"])
            self.assertFalse(queue["stop_is_atomic_producer_barrier"])
            self.assertTrue(queue["source_exposes_post_flush_enqueue_window"])

            queue_source = root / "nvidia/nv-kthread-q.c"
            queue_source.write_text(
                "void nv_kthread_q_stop(nv_kthread_q_t *q) { "
                "spin_lock_irqsave(&q->q_lock, flags); "
                "atomic_set(&q->main_loop_should_exit, 1); "
                "spin_unlock_irqrestore(&q->q_lock, flags); "
                "nv_kthread_q_flush(q); } "
                "int nv_kthread_q_schedule_q_item(nv_kthread_q_t *q, "
                "nv_kthread_q_item_t *q_item) { "
                "if (atomic_read(&q->main_loop_should_exit)) return 0; "
                "return _raw_q_schedule(q, q_item); } "
                "static int _raw_q_schedule(nv_kthread_q_t *q, "
                "nv_kthread_q_item_t *q_item) { "
                "spin_lock_irqsave(&q->q_lock, flags); "
                "if (!atomic_read(&q->main_loop_should_exit) && "
                "list_empty(&q_item->q_list_node)) "
                "list_add_tail(&q_item->q_list_node, &q->q_list_head); "
                "spin_unlock_irqrestore(&q->q_lock, flags); return 1; }\n")
            safe = AUDIT.audit_tree(root, "r580-queue-gated")
            self.assertTrue(safe["deferred_queue_lifecycle"][
                "raw_enqueue_rechecks_exit_under_queue_lock"])
            self.assertTrue(safe["deferred_queue_lifecycle"][
                "stop_exit_transition_uses_queue_lock"])
            self.assertTrue(safe["deferred_queue_lifecycle"][
                "stop_is_atomic_producer_barrier"])
            self.assertFalse(safe["deferred_queue_lifecycle"][
                "source_exposes_post_flush_enqueue_window"])


if __name__ == "__main__":
    unittest.main()
