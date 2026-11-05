import hashlib
import unittest

from tools.audit_nouveau_gv100_fault_lifecycle import (
    AuditError,
    audit_source_texts,
)


SOURCE_TEXTS = {
    "include/linux/workqueue.h": """
static inline bool schedule_work(struct work_struct *work) {
    return queue_work(system_percpu_wq, work);
}
""",
    "kernel/workqueue.c": """
static void process_one_work(struct worker *worker, struct work_struct *work) {
    set_work_pool_and_clear_pending(work, id, flags);
    worker->current_func(work);
}
static bool queue_work_on(int cpu, struct workqueue_struct *wq, struct work_struct *work) {
    if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work)) && !clear_pending_if_disabled(work)) {
        __queue_work(cpu, wq, work);
        ret = true;
    }
}
bool flush_work(struct work_struct *work) {
    return __flush_work(work, false);
}
/* @work is guaranteed to be idle on return if it hasn't been requeued since flush started */
""",
    "drivers/gpu/drm/nouveau/nvkm/core/event.c": """
static void nvkm_event_ntfy_remove(struct nvkm_event_ntfy *ntfy) {
    write_lock_irq(&ntfy->event->list_lock);
    list_del_init(&ntfy->head);
    write_unlock_irq(&ntfy->event->list_lock);
}
static void nvkm_event_ntfy_block_(struct nvkm_event_ntfy *ntfy, bool wait) {
    if (atomic_xchg(&ntfy->allowed, 0) == 1) {
        nvkm_event_ntfy_state(ntfy);
        if (wait) nvkm_event_ntfy_remove(ntfy);
    }
}
void nvkm_event_ntfy(struct nvkm_event *event, int id, u32 bits) {
    read_lock_irqsave(&event->list_lock, flags);
    if (atomic_read(&ntfy->allowed)) ntfy->func(ntfy, bits);
    read_unlock_irqrestore(&event->list_lock, flags);
}
""",
    "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c": """
static int gv100_fault_ntfy_nrpfb(struct nvkm_event_ntfy *ntfy, u32 bits) {
    schedule_work(&fault->nrpfb_work);
}
static void gv100_fault_fini(struct nvkm_fault *fault) {
    nvkm_event_ntfy_block(&fault->nrpfb);
    flush_work(&fault->nrpfb_work);
    fault->func->buffer.fini(fault->buffer[0]);
    nvkm_mask(fault->subdev.device, 0x100a34, 0x80000000, 0x80000000);
}
static void gv100_fault_init(struct nvkm_fault *fault) {
    nvkm_mask(fault->subdev.device, 0x100a2c, 0x80000000, 0x80000000);
    fault->func->buffer.init(fault->buffer[0]);
    nvkm_event_ntfy_allow(&fault->nrpfb);
}
static void gv100_fault_buffer_intr(struct nvkm_fault_buffer *buffer, bool enable) {
    if (enable) nvkm_mask(device, 0x100a2c, intr, intr);
    else nvkm_mask(device, 0x100a34, intr, intr);
}
int gv100_fault_oneinit(struct nvkm_fault *fault) {
    nvkm_event_ntfy_add(&fault->event, 0, NVKM_FAULT_BUFFER_EVENT_PENDING, true,
                        gv100_fault_ntfy_nrpfb, &fault->nrpfb);
}
void gv100_fault_buffer_process(struct work_struct *work) {
    u32 get = nvkm_rd32(device, buffer->get);
    u32 put = nvkm_rd32(device, buffer->put);
    while (get != put) {
        if (++get == buffer->entries)
            get = 0;
        nvkm_wr32(device, buffer->get, get);
        nvkm_fifo_fault(device->fifo, &info);
    }
}
static void gv100_fault_intr_fault(struct nvkm_fault *fault) {
    addrlo = nvkm_rd32(device, 0x100e4c);
    nvkm_fifo_fault(device->fifo, &info);
}
static void gv100_fault_intr(struct nvkm_fault *fault) {
    if (stat & 0x80000000) {
        gv100_fault_intr_fault(fault);
        nvkm_wr32(device, 0x100e60, 0x80000000);
        stat &= ~0x80000000;
    }
    if (stat & 0x20000000) {
        if (fault->buffer[0]) {
            nvkm_event_ntfy(&fault->event, 0, NVKM_FAULT_BUFFER_EVENT_PENDING);
            stat &= ~0x20000000;
        }
    }
    if (stat & 0x08000000) {
        if (fault->buffer[1]) {
            nvkm_event_ntfy(&fault->event, 1, NVKM_FAULT_BUFFER_EVENT_PENDING);
            stat &= ~0x08000000;
        }
    }
}
""",
    "drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c": """
static void nvkm_fault_ntfy_fini(struct nvkm_event *event, int type, int index) {
    fault->func->buffer.intr(fault->buffer[index], false);
}
static void nvkm_fault_ntfy_init(struct nvkm_event *event, int type, int index) {
    fault->func->buffer.intr(fault->buffer[index], true);
}
static int nvkm_fault_oneinit_buffer(struct nvkm_fault *fault, int id) {
    fault->func->buffer.info(buffer);
    ret = nvkm_memory_new(device, NVKM_MEM_TARGET_INST, buffer->entries *
                          fault->func->buffer.entry_size, 0x1000, true, &buffer->mem);
    buffer->addr = fault->func->buffer.pin(buffer);
}
static void *nvkm_fault_dtor(struct nvkm_subdev *subdev) {
    nvkm_event_ntfy_del(&fault->nrpfb);
    nvkm_event_fini(&fault->event);
    nvkm_memory_unref(&fault->buffer[i]->mem);
    kfree(fault->buffer[i]);
}
""",
    "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gp100.c": """
u64 gp100_fault_buffer_pin(struct nvkm_fault_buffer *buffer) {
    return nvkm_memory_bar2(buffer->mem);
}
""",
    "drivers/gpu/drm/nouveau/nvkm/core/intr.c": """
static irqreturn_t nvkm_intr(int irq, void *arg) {
    spin_lock(&device->intr.lock);
    if (!device->intr.armed) goto done_unlock;
    nvkm_intr_unarm_locked(device);
    nvkm_pci_msi_rearm(device);
    if (!pending) goto done;
    if (inth->func(inth) == IRQ_HANDLED) ret = IRQ_HANDLED;
done:
    nvkm_intr_rearm_locked(device);
done_unlock:
    spin_unlock(&device->intr.lock);
    return ret;
}
static irqreturn_t nvkm_intr_subdev(struct nvkm_inth *inth) {
    nvkm_subdev_intr(subdev);
    return IRQ_HANDLED;
}
""",
    "drivers/gpu/drm/nouveau/nvkm/core/subdev.c": """
void nvkm_subdev_intr(struct nvkm_subdev *subdev) {
    if (subdev->func->intr)
        subdev->func->intr(subdev);
}
""",
    "drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c": """
int nvkm_mc_new_(const struct nvkm_mc_func *func, struct nvkm_device *device,
                 enum nvkm_subdev_type type, int inst, struct nvkm_mc **pmc) {
    mc->func = func;
    if (mc->func->intr) {
        ret = nvkm_intr_add(mc->func->intr, mc->func->intrs, &mc->subdev,
                            mc->func->intr_nonstall ? 2 : 1, &mc->intr);
    }
    return 0;
}
""",
    "drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c": """
const struct nvkm_intr_data gp100_mc_intrs[] = {
    { NVKM_SUBDEV_FAULT, 0, 0, 0x00000200, true },
    {},
};
static const struct nvkm_mc_func gp100_mc = {
    .intr_nonstall = true,
};
int gp100_mc_new(struct nvkm_device *device, enum nvkm_subdev_type type,
                 int inst, struct nvkm_mc **pmc) {
    if (nvkm_gsp_rm(device->gsp))
        return -ENODEV;
    return nvkm_mc_new_(&gp100_mc, device, type, inst, pmc);
}
""",
    "drivers/gpu/drm/nouveau/nvkm/subdev/mc/nv04.c": """
bool nv04_mc_intr_pending(struct nvkm_intr *intr) {
    for (leaf = 0; leaf < intr->leaves; leaf++) {
        intr->stat[leaf] = nvkm_rd32(mc->subdev.device, 0x000100 + (leaf * 4));
        if (intr->stat[leaf]) pending = true;
    }
    return pending;
}
""",
    "drivers/gpu/drm/nouveau/nvkm/engine/fifo/base.c": """
void nvkm_fifo_fault(struct nvkm_fifo *fifo, struct nvkm_fault_data *info) {
    return fifo->func->mmu_fault->recover(fifo, info);
}
""",
}


def fixture_hashes():
    return {
        path: hashlib.sha256(text.encode("utf-8")).hexdigest()
        for path, text in SOURCE_TEXTS.items()
    }


class NouveauGv100FaultLifecycleTests(unittest.TestCase):
    def test_pinned_contract_records_requeue_and_shutdown_invariants(self):
        result = audit_source_texts(SOURCE_TEXTS, fixture_hashes())
        self.assertEqual(result["status"], "ANALYZED_STATICALLY")
        self.assertTrue(result["checks"]["work_pending_cleared_before_callback"])
        self.assertTrue(result["checks"]["queue_work_coalesces_while_pending"])
        self.assertTrue(result["checks"]["notifier_removal_waits_for_reader_section"])
        self.assertTrue(result["checks"]["teardown_blocks_flushes_then_releases_buffer"])
        self.assertFalse(any("pseudocode" in row for row in result["source_files"]))

    def test_worker_order_change_is_rejected_even_when_hashes_are_recomputed(self):
        changed = dict(SOURCE_TEXTS)
        changed["kernel/workqueue.c"] = changed["kernel/workqueue.c"].replace(
            "set_work_pool_and_clear_pending(work, id, flags);\n    worker->current_func(work);",
            "worker->current_func(work);\n    set_work_pool_and_clear_pending(work, id, flags);",
        )
        with self.assertRaisesRegex(AuditError, "work_pending_cleared_before_callback"):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_teardown_reordering_is_rejected_even_when_hashes_are_recomputed(self):
        changed = dict(SOURCE_TEXTS)
        changed["drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"] = (
            changed["drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"].replace(
                "nvkm_event_ntfy_block(&fault->nrpfb);\n    flush_work(&fault->nrpfb_work);",
                "flush_work(&fault->nrpfb_work);\n    nvkm_event_ntfy_block(&fault->nrpfb);",
            )
        )
        with self.assertRaisesRegex(AuditError, "teardown_blocks_flushes_then_releases_buffer"):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_wrong_pinned_hash_fails_before_contract_evaluation(self):
        with self.assertRaisesRegex(AuditError, "source digest mismatch"):
            audit_source_texts(SOURCE_TEXTS)

    def test_buffer_interrupt_disable_path_is_required(self):
        changed = dict(SOURCE_TEXTS)
        changed["drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c"] = (
            changed["drivers/gpu/drm/nouveau/nvkm/subdev/fault/base.c"].replace(
                "fault->func->buffer.intr(fault->buffer[index], false);",
                "fault->func->buffer.intr(fault->buffer[index], true);",
            )
        )
        with self.assertRaisesRegex(
            AuditError, "event_reference_fini_disables_buffer_interrupt"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_buffer_startup_order_is_required(self):
        changed = dict(SOURCE_TEXTS)
        changed["drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"] = (
            changed["drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"].replace(
                "fault->func->buffer.init(fault->buffer[0]);\n    nvkm_event_ntfy_allow(&fault->nrpfb);",
                "nvkm_event_ntfy_allow(&fault->nrpfb);\n    fault->func->buffer.init(fault->buffer[0]);",
            )
        )
        with self.assertRaisesRegex(
            AuditError, "gv100_startup_enables_source_then_ring_then_notification"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_irq_and_fault_route_records_sync_and_deferred_paths(self):
        result = audit_source_texts(SOURCE_TEXTS, fixture_hashes())
        self.assertEqual(result["status"], "ANALYZED_STATICALLY")
        self.assertTrue(result["checks"]["irq_handler_serializes_dispatch_and_rearms_after_handlers"])
        self.assertTrue(result["checks"]["nonreplayable_fault_is_acknowledged_after_fifo_dispatch"])
        self.assertTrue(result["checks"]["replayable_buffer0_requires_buffer_then_notifies"])
        self.assertTrue(result["checks"]["fifo_fault_delegates_to_mmu_recovery_callback"])
        self.assertEqual(len(result["checks"]), 33)

    def test_irq_rearm_must_follow_subdevice_handler(self):
        changed = dict(SOURCE_TEXTS)
        path = "drivers/gpu/drm/nouveau/nvkm/core/intr.c"
        changed[path] = changed[path].replace(
            "if (inth->func(inth) == IRQ_HANDLED) ret = IRQ_HANDLED;\ndone:\n    nvkm_intr_rearm_locked(device);",
            "nvkm_intr_rearm_locked(device);\n    if (inth->func(inth) == IRQ_HANDLED) ret = IRQ_HANDLED;\ndone:",
        )
        with self.assertRaisesRegex(
            AuditError, "irq_handler_serializes_dispatch_and_rearms_after_handlers"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_nonreplayable_fault_cannot_be_acknowledged_before_dispatch(self):
        changed = dict(SOURCE_TEXTS)
        path = "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"
        changed[path] = changed[path].replace(
            "gv100_fault_intr_fault(fault);\n        nvkm_wr32(device, 0x100e60, 0x80000000);",
            "nvkm_wr32(device, 0x100e60, 0x80000000);\n        gv100_fault_intr_fault(fault);",
        )
        with self.assertRaisesRegex(
            AuditError, "nonreplayable_fault_is_acknowledged_after_fifo_dispatch"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_replayable_fault_requires_matching_buffer_before_notification(self):
        changed = dict(SOURCE_TEXTS)
        path = "drivers/gpu/drm/nouveau/nvkm/subdev/fault/gv100.c"
        changed[path] = changed[path].replace(
            "if (fault->buffer[0]) {", "if (buffer_is_valid) {"
        )
        with self.assertRaisesRegex(
            AuditError, "replayable_buffer0_requires_buffer_then_notifies"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_missing_mc_fault_interrupt_route_is_rejected(self):
        changed = dict(SOURCE_TEXTS)
        path = "drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c"
        changed[path] = changed[path].replace(
            "{ NVKM_SUBDEV_FAULT, 0, 0, 0x00000200, true },", ""
        )
        with self.assertRaisesRegex(
            AuditError, "gp100_mc_maps_fault_subdevice_interrupt"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))

    def test_gsp_rm_backend_guard_is_required_for_gp100_mc(self):
        changed = dict(SOURCE_TEXTS)
        path = "drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c"
        changed[path] = changed[path].replace("return -ENODEV;", "return 0;")
        with self.assertRaisesRegex(
            AuditError, "gp100_mc_backend_rejects_gsp_rm_mode"
        ):
            audit_source_texts(changed, fixture_hashes_for(changed))


def fixture_hashes_for(source_texts):
    return {
        path: hashlib.sha256(text.encode("utf-8")).hexdigest()
        for path, text in source_texts.items()
    }


if __name__ == "__main__":
    unittest.main()
