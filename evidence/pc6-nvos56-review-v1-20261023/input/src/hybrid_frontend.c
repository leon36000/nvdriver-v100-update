/* SPDX-License-Identifier: MIT */
/* Experimental ROOT and BDF-selected GPU-file frontend. Its private inventory
 * query is not NVIDIA's CARD_INFO or a CUDA driver ABI. Typed RM map/unmap and
 * control/GPU-file mmap/poll delegate to a selected native backend; the VMA
 * retains the backend file whose RM mapping context was created. Events, UVM
 * and the remaining RM control surface are absent.
 * This source is compiled in its own Dual MIT/GPL module; neither RM is linked
 * into it. Runtime execution requires separately authorized canary installation.
 */
#include <linux/anon_inodes.h>
#include <linux/build_bug.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include "hybrid580_frontend_admission.h"
#include "hybrid580_pm_provider_recovery.h"
#include "hybrid580_system_pm_coordinator.h"
#include "rm_root_client.h"
#include "hybrid580-control-session.h"
#include "hybrid580-open-build-version.h"
#include "hybrid580-file-projection.h"
#include "hybrid580-gpu-session.h"
#include "hybrid580-device-instance-map.h"
#include "hybrid580-standard-node-devices.h"
#include "hybrid580-standard-node-map.h"
#include "hybrid580_ioctl.h"
#include "nv-ioctl.h"
#include "nv-chardev-numbers.h"
#include "nv-unix-nvos-params-wrappers.h"
#include <class/cl003e.h>
#include <class/cl0040.h>
#include <class/cl90f1.h>
#include <class/cl9067.h>

/* Both private backend headers are authenticated and compared by the builder.
 * Their opaque tags/guards are intentionally identical; typeof preserves the
 * exact public declaration without including two conflicting guarded copies.
 */
extern __typeof__(hybrid580_open_control_session_create_v1) hybrid580_legacy_control_session_create_v1;
extern __typeof__(hybrid580_open_control_session_attach_v1) hybrid580_legacy_control_session_attach_v1;
extern __typeof__(hybrid580_open_control_session_map_memory_v1)
    hybrid580_legacy_control_session_map_memory_v1;
extern __typeof__(hybrid580_open_control_session_unmap_memory_v1)
    hybrid580_legacy_control_session_unmap_memory_v1;
extern __typeof__(hybrid580_open_control_session_update_device_mapping_info_v1)
    hybrid580_legacy_control_session_update_device_mapping_info_v1;
extern __typeof__(hybrid580_open_control_session_sys_params_v1)
    hybrid580_legacy_control_session_sys_params_v1;
extern __typeof__(hybrid580_open_control_session_put_v1) hybrid580_legacy_control_session_put_v1;
extern __typeof__(hybrid580_open_control_session_file_v1) hybrid580_legacy_control_session_file_v1;
extern __typeof__(hybrid580_open_control_session_gpu_id_info_v1)
    hybrid580_legacy_control_session_gpu_id_info_v1;
extern __typeof__(hybrid580_open_control_session_attached_ids_v1)
    hybrid580_legacy_control_session_attached_ids_v1;
extern __typeof__(hybrid580_open_control_session_probed_ids_v1)
    hybrid580_legacy_control_session_probed_ids_v1;
extern __typeof__(hybrid580_open_control_session_device_ids_v1)
    hybrid580_legacy_control_session_device_ids_v1;
extern __typeof__(hybrid580_open_control_session_device_alloc_v1)
    hybrid580_legacy_control_session_device_alloc_v1;
extern __typeof__(hybrid580_open_control_session_subdevice_alloc_v1)
    hybrid580_legacy_control_session_subdevice_alloc_v1;
extern __typeof__(hybrid580_open_control_session_gr_tpc_mask_v1)
    hybrid580_legacy_control_session_gr_tpc_mask_v1;
extern __typeof__(hybrid580_open_control_session_p2p_register_va_space_v1)
    hybrid580_legacy_control_session_p2p_register_va_space_v1;
extern __typeof__(hybrid580_open_control_session_p2p_unregister_va_space_v1)
    hybrid580_legacy_control_session_p2p_unregister_va_space_v1;
extern __typeof__(hybrid580_open_control_session_p2p_register_vidmem_v1)
    hybrid580_legacy_control_session_p2p_register_vidmem_v1;
extern __typeof__(hybrid580_open_control_session_p2p_unregister_vidmem_v1)
    hybrid580_legacy_control_session_p2p_unregister_vidmem_v1;
extern __typeof__(hybrid580_open_control_session_binapi_alloc_v1)
    hybrid580_legacy_control_session_binapi_alloc_v1;
extern __typeof__(hybrid580_open_control_session_rusd_alloc_v1)
    hybrid580_legacy_control_session_rusd_alloc_v1;
extern __typeof__(hybrid580_open_control_session_usermode_alloc_v1)
    hybrid580_legacy_control_session_usermode_alloc_v1;
extern __typeof__(hybrid580_open_control_session_device_free_v1)
    hybrid580_legacy_control_session_device_free_v1;
extern __typeof__(hybrid580_open_control_session_memory_alloc_v1)
    hybrid580_legacy_control_session_memory_alloc_v1;
extern __typeof__(hybrid580_open_control_session_object_free_v1)
    hybrid580_legacy_control_session_object_free_v1;
extern __typeof__(hybrid580_open_control_session_vaspace_alloc_v1)
    hybrid580_legacy_control_session_vaspace_alloc_v1;
extern __typeof__(hybrid580_open_control_session_channel_group_alloc_v1)
    hybrid580_legacy_control_session_channel_group_alloc_v1;
extern __typeof__(hybrid580_open_control_session_context_share_alloc_v1)
    hybrid580_legacy_control_session_context_share_alloc_v1;
extern __typeof__(hybrid580_open_control_session_channel_alloc_v1)
    hybrid580_legacy_control_session_channel_alloc_v1;
extern __typeof__(hybrid580_open_control_session_engine_alloc_v1)
    hybrid580_legacy_control_session_engine_alloc_v1;
extern __typeof__(hybrid580_open_register_file_projection_v1) hybrid580_legacy_register_file_projection_v1;
extern __typeof__(hybrid580_open_unregister_file_projection_v1) hybrid580_legacy_unregister_file_projection_v1;
extern __typeof__(hybrid580_open_gpu_session_create_by_bdf_v1) hybrid580_legacy_gpu_session_create_by_bdf_v1;
extern __typeof__(hybrid580_open_gpu_session_put_v1) hybrid580_legacy_gpu_session_put_v1;
extern __typeof__(hybrid580_open_gpu_session_file_v1) hybrid580_legacy_gpu_session_file_v1;
extern __typeof__(hybrid580_open_gpu_session_ioctl_v1) hybrid580_legacy_gpu_session_ioctl_v1;
extern __typeof__(hybrid580_open_gpu_session_register_control_v1)
    hybrid580_legacy_gpu_session_register_control_v1;
extern __typeof__(hybrid580_open_gpu_inventory_v1) hybrid580_legacy_gpu_inventory_v1;
extern __typeof__(hybrid580_open_gpu_card_info_v1) hybrid580_legacy_gpu_card_info_v1;

/* The two private R580 providers expose namespaced system-PM operations. The
 * Open provider owns the single shared UVM suspend/resume entrypoint; both
 * providers own their own per-GPU channels and DPM recovery records.
 */
extern int hybrid580_open_pm_recovery_begin_v1(unsigned long long generation);
extern int hybrid580_open_pm_recovery_recover_v1(
    unsigned long long generation, unsigned int expected_callback);
extern int hybrid580_open_pm_recovery_end_v1(unsigned long long generation);
extern int hybrid580_open_pm_channels_suspend_v1(unsigned long long generation);
extern int hybrid580_open_pm_channels_resume_v1(unsigned long long generation);
extern int hybrid580_open_pm_shared_uvm_suspend_v1(void);
extern int hybrid580_open_pm_shared_uvm_resume_v1(void);
extern int hybrid580_legacy_pm_recovery_begin_v1(unsigned long long generation);
extern int hybrid580_legacy_pm_recovery_recover_v1(
    unsigned long long generation, unsigned int expected_callback);
extern int hybrid580_legacy_pm_recovery_end_v1(unsigned long long generation);
extern int hybrid580_legacy_pm_channels_suspend_v1(unsigned long long generation);
extern int hybrid580_legacy_pm_channels_resume_v1(unsigned long long generation);

typedef int (*hybrid_gpu_create_fn)(struct file *, const char *, struct hybrid580_gpu_session **);
typedef void (*hybrid_gpu_put_fn)(struct hybrid580_gpu_session *);
typedef struct file *(*hybrid_gpu_file_fn)(struct hybrid580_gpu_session *);
typedef long (*hybrid_gpu_ioctl_fn)(struct hybrid580_gpu_session *, unsigned int, unsigned long);
typedef int (*hybrid_gpu_register_control_fn)(
    struct hybrid580_gpu_session *, struct hybrid580_control_session *);
typedef int (*hybrid_control_attach_fn)(struct hybrid580_control_session *, const NvU32 *, NvU32);

enum hybrid_front_file_kind {
    HYBRID_FRONT_CONTROL_FILE,
    HYBRID_FRONT_GPU_FILE,
};

enum hybrid_front_map_state {
    HYBRID_FRONT_MAP_EMPTY = 0,
    HYBRID_FRONT_MAP_RESERVED,
    HYBRID_FRONT_MAP_READY,
    HYBRID_FRONT_MAP_MAPPING,
    HYBRID_FRONT_MAP_CONSUMED,
    HYBRID_FRONT_MAP_POISONED,
};

enum hybrid_front_gpu_association_state {
    HYBRID_FRONT_GPU_PRIVATE_ASSOCIATION = 0,
    HYBRID_FRONT_GPU_STANDARD_UNREGISTERED,
    HYBRID_FRONT_GPU_STANDARD_REGISTERING,
    HYBRID_FRONT_GPU_STANDARD_REGISTERED,
    HYBRID_FRONT_GPU_STANDARD_FAILED,
};

struct hybrid_front_file_base {
    enum hybrid_front_file_kind kind;
};

struct hybrid_front_gpu_file {
    struct hybrid_front_file_base base;
    spinlock_t map_lock;
    spinlock_t owner_lock;
    wait_queue_head_t association_wait;
    enum hybrid_front_map_state pending_map_state;
    unsigned int pending_map_backend;
    struct file *control_front;
    enum hybrid_front_gpu_association_state association_state;
    unsigned int frontend_index;
    char bdf[HYBRID580_GPU_BDF_SIZE];
    struct hybrid580_gpu_session *session;
    unsigned int backend;
    hybrid_gpu_put_fn put;
    hybrid_gpu_file_fn file;
    hybrid_gpu_ioctl_fn ioctl;
    hybrid_gpu_register_control_fn register_control;
};

#define HYBRID_FRONT_MAX_ROOTS 256U
struct hybrid_front_rm_object {
    struct hybrid_front_rm_object *next;
    NvHandle handle;
    NvHandle parent_handle;
    NvHandle backend_handle;
    NvHandle backend_parent_handle;
    NvHandle vaspace_handle;
    NvHandle error_object_handle;
    NvHandle ecc_error_object_handle;
    NvHandle buffer_object_handle;
    NvHandle context_share_handle;
    NvHandle userd_memory_handles[NV_MAX_SUBDEVICES];
    NvU32 class_id;
    unsigned int backend;
    NvU32 backend_device_instance;
    NvU32 p2p_registration_refs;
};

struct hybrid_front_root {
    struct hybrid_front_root *next;
    struct hybrid_root_client root;
    struct hybrid580_device_instance_map_v1 device_map;
    struct hybrid_front_rm_object *objects;
    unsigned int object_count;
    bool device_map_valid;
};

#define HYBRID_FRONT_MAX_DEVICE_OBJECTS 256U

struct hybrid_front_file;
struct hybrid_front_forward {
    struct hybrid_front_file *front;
    unsigned int backend;
    struct hybrid_rm_session_endpoint_v1 actual;
};

struct hybrid_front_file {
    struct hybrid_front_file_base base;
    struct mutex transaction_lock;
    spinlock_t map_lock;
    enum hybrid_front_map_state pending_map_state;
    unsigned int pending_map_backend;
    spinlock_t session_lock;
    struct hybrid580_control_session *sessions[2];
    struct hybrid_rm_session_endpoint_v1 endpoints[2];
    struct hybrid_front_forward forwards[2];
    struct hybrid_front_root *roots;
    struct hybrid580_gpu_catalog_v1 *catalog;
    unsigned int root_count;
    unsigned int object_count;
    unsigned int operation_inflight;
    bool stateful_started;
    bool attach_attempted;
    bool attach_committed;
    bool quarantined; /* Never allow new allocations after ambiguous side effects. */
};

static const struct file_operations hybrid_front_fops;
static NV_STATUS NV_API_CALL hybrid_front_invoke(
    void *context, NvU32 command, void *payload, NvU32 size);

/* A global admission gate lets the early PM notifier stop new frontend work
 * without waiting before the task freezer. Sleepable entries wait freezably;
 * the later aggregate DPM callback drains only operations already admitted.
 */
static DEFINE_SPINLOCK(hybrid_front_admission_lock);
static DECLARE_WAIT_QUEUE_HEAD(hybrid_front_admission_wait);
/* SYS_PARAMS mutates module-wide control-device state, so serialize it across
 * separate frontend opens and poison the module if only one RM accepts it. */
static DEFINE_MUTEX(hybrid_front_sys_params_lock);
static bool hybrid_front_sys_params_poisoned;
static struct hybrid580_frontend_admission_state hybrid_front_admission_state;
static struct hybrid580_system_pm hybrid_front_system_pm_state;

static int hybrid_front_admission_block(void);
static void hybrid_front_admission_drain(void);
static int hybrid_front_admission_unblock(void);

static int hybrid_front_pm_block(void *context)
{
    (void)context;
    return hybrid_front_admission_block();
}

static int hybrid_front_pm_drain(void *context)
{
    (void)context;
    hybrid_front_admission_drain();
    return 0;
}

static int hybrid_front_pm_begin_recovery(void *context, unsigned int backend,
                                          unsigned long long generation)
{
    (void)context;
    if (backend == HYBRID580_PM_BACKEND_OPEN)
        return hybrid580_open_pm_recovery_begin_v1(generation);
    if (backend == HYBRID580_PM_BACKEND_LEGACY)
        return hybrid580_legacy_pm_recovery_begin_v1(generation);
    return -EINVAL;
}

static int hybrid_front_pm_end_recovery(void *context, unsigned int backend,
                                        unsigned long long generation)
{
    (void)context;
    if (backend == HYBRID580_PM_BACKEND_OPEN)
        return hybrid580_open_pm_recovery_end_v1(generation);
    if (backend == HYBRID580_PM_BACKEND_LEGACY)
        return hybrid580_legacy_pm_recovery_end_v1(generation);
    return -EINVAL;
}

static int hybrid_front_pm_suspend_channels(void *context, unsigned int backend)
{
    unsigned long long generation = hybrid_front_system_pm_state.generation;

    (void)context;
    if (backend == HYBRID580_PM_BACKEND_OPEN)
        return hybrid580_open_pm_channels_suspend_v1(generation);
    if (backend == HYBRID580_PM_BACKEND_LEGACY)
        return hybrid580_legacy_pm_channels_suspend_v1(generation);
    return -EINVAL;
}

static int hybrid_front_pm_drain_irqs(void *context, unsigned int backend)
{
    (void)context;

    if (backend != HYBRID580_PM_BACKEND_OPEN &&
        backend != HYBRID580_PM_BACKEND_LEGACY)
        return -EINVAL;

    /* Fail closed until each provider has a teardown-participating IRQ
     * lifetime pin and a proven drain for its deferred RM bottom halves.
     * synchronize_irq() alone neither prevents new vectors nor drains the
     * separate bottom-half work queue, and the current provider wrappers do
     * not yet maintain the lifetime pin needed to race safely with close. */
    return -EOPNOTSUPP;
}

static int hybrid_front_pm_suspend_uvm(void *context)
{
    (void)context;
    return hybrid580_open_pm_shared_uvm_suspend_v1();
}

static int hybrid_front_pm_recover_devices(
    void *context, unsigned int backend, unsigned long long generation,
    enum hybrid580_pm_dpm_event event)
{
    unsigned int callback;

    (void)context;
    switch (event) {
    case HYBRID580_PM_DPM_RESUME:
        callback = HYBRID580_PM_PROVIDER_CALLBACK_RESUME;
        break;
    case HYBRID580_PM_DPM_RESTORE:
        callback = HYBRID580_PM_PROVIDER_CALLBACK_RESTORE;
        break;
    case HYBRID580_PM_DPM_THAW:
    case HYBRID580_PM_DPM_RECOVER:
        callback = HYBRID580_PM_PROVIDER_CALLBACK_THAW;
        break;
    default:
        return -EINVAL;
    }

    if (backend == HYBRID580_PM_BACKEND_OPEN)
        return hybrid580_open_pm_recovery_recover_v1(generation, callback);
    if (backend == HYBRID580_PM_BACKEND_LEGACY)
        return hybrid580_legacy_pm_recovery_recover_v1(generation, callback);
    return -EINVAL;
}

static int hybrid_front_pm_resume_uvm(void *context)
{
    (void)context;
    return hybrid580_open_pm_shared_uvm_resume_v1();
}

static int hybrid_front_pm_restore_channels(void *context, unsigned int backend)
{
    unsigned long long generation = hybrid_front_system_pm_state.generation;

    (void)context;
    if (backend == HYBRID580_PM_BACKEND_OPEN)
        return hybrid580_open_pm_channels_resume_v1(generation);
    if (backend == HYBRID580_PM_BACKEND_LEGACY)
        return hybrid580_legacy_pm_channels_resume_v1(generation);
    return -EINVAL;
}

static int hybrid_front_pm_unblock(void *context)
{
    (void)context;
    return hybrid_front_admission_unblock();
}

static const struct hybrid580_system_pm_ops hybrid_front_system_pm_ops = {
    .block_frontend = hybrid_front_pm_block,
    .drain_frontend = hybrid_front_pm_drain,
    .begin_recovery_cycle = hybrid_front_pm_begin_recovery,
    .end_recovery_cycle = hybrid_front_pm_end_recovery,
    .suspend_channels = hybrid_front_pm_suspend_channels,
    .drain_irqs = hybrid_front_pm_drain_irqs,
    .suspend_uvm = hybrid_front_pm_suspend_uvm,
    .recover_and_verify_devices = hybrid_front_pm_recover_devices,
    .resume_uvm = hybrid_front_pm_resume_uvm,
    .restore_channels = hybrid_front_pm_restore_channels,
    .unblock_frontend = hybrid_front_pm_unblock,
};

/* These adapters are intentionally not registered with Linux yet. A later
 * change must first prove DPM aggregation ordering, UVM callback coverage,
 * notifier freezer semantics and every rollback path on the target kernel.
 */
static int __used hybrid_front_system_pm_notify(
    enum hybrid580_pm_notifier_event event)
{
    return hybrid580_system_pm_notify(&hybrid_front_system_pm_state,
                                      &hybrid_front_system_pm_ops, event);
}

static int __used hybrid_front_system_pm_dpm(
    enum hybrid580_pm_dpm_event event)
{
    return hybrid580_system_pm_dpm(&hybrid_front_system_pm_state,
                                   &hybrid_front_system_pm_ops, event);
}

static int hybrid_front_admission_try_enter(void)
{
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&hybrid_front_admission_lock, flags);
    rc = hybrid580_frontend_admission_try_enter_locked(
        &hybrid_front_admission_state);
    spin_unlock_irqrestore(&hybrid_front_admission_lock, flags);
    return rc;
}

static int hybrid_front_admission_enter(void)
{
    int rc;

    for (;;) {
        rc = wait_event_freezable(hybrid_front_admission_wait,
            !READ_ONCE(hybrid_front_admission_state.blocked));
        if (rc != 0)
            return rc;
        rc = hybrid_front_admission_try_enter();
        if (rc != -EAGAIN)
            return rc;
    }
}

static int hybrid_front_admission_enter_release(void)
{
    int rc;

    /* VFS ignores a release() return value. Keep cleanup mandatory while
     * remaining freezable, even if a signal arrives during a suspended PM
     * cycle. TASK_UNINTERRUPTIBLE avoids abandoning the final close. */
    for (;;) {
        wait_event_state(hybrid_front_admission_wait,
            !READ_ONCE(hybrid_front_admission_state.blocked),
            (TASK_UNINTERRUPTIBLE | TASK_FREEZABLE));
        rc = hybrid_front_admission_try_enter();
        if (rc != -EAGAIN)
            return rc;
    }
}

static void hybrid_front_admission_leave(void)
{
    unsigned long flags;
    bool drained;
    int rc;

    spin_lock_irqsave(&hybrid_front_admission_lock, flags);
    rc = hybrid580_frontend_admission_leave_locked(
        &hybrid_front_admission_state);
    drained = hybrid580_frontend_admission_is_drained_locked(
        &hybrid_front_admission_state);
    spin_unlock_irqrestore(&hybrid_front_admission_lock, flags);
    WARN_ON_ONCE(rc != 0);
    if (drained)
        wake_up_all(&hybrid_front_admission_wait);
}

static int __maybe_unused hybrid_front_admission_block(void)
{
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&hybrid_front_admission_lock, flags);
    rc = hybrid580_frontend_admission_block_locked(
        &hybrid_front_admission_state);
    spin_unlock_irqrestore(&hybrid_front_admission_lock, flags);
    if (rc == 0)
        wake_up_all(&hybrid_front_admission_wait);
    return rc;
}

static void __maybe_unused hybrid_front_admission_drain(void)
{
    wait_event(hybrid_front_admission_wait,
        READ_ONCE(hybrid_front_admission_state.active) == 0);
}

static int __maybe_unused hybrid_front_admission_unblock(void)
{
    unsigned long flags;
    int rc;

    spin_lock_irqsave(&hybrid_front_admission_lock, flags);
    rc = hybrid580_frontend_admission_unblock_locked(
        &hybrid_front_admission_state);
    spin_unlock_irqrestore(&hybrid_front_admission_lock, flags);
    if (rc == 0)
        wake_up_all(&hybrid_front_admission_wait);
    return rc;
}

/* Snapshot each private backend while its own GPU list is locked, then merge
 * the immutable arrays by BDF. Backend-local minor and GPU IDs remain scoped
 * to the selected RM. Cross-backend hotplug atomicity is not provided; opening
 * a BDF still revalidates it against the live backend minor table.
 */
static int hybrid_front_catalog_create(struct hybrid_front_file *state)
{
    struct hybrid580_gpu_backend_record_v1 *legacy = NULL, *open = NULL;
    struct hybrid580_gpu_catalog_v1 *catalog = NULL;
    NvU32 legacy_count = 0, open_count = 0;
    int rc;

    /* The catalog is multi-page; avoid requiring a high-order contiguous
     * allocation on every control-file open. These buffers are only touched
     * in process context and kvfree accepts both kmalloc/vmalloc backing.
     */
    catalog = kvzalloc(sizeof(*catalog), GFP_KERNEL);
    legacy = kvcalloc(HYBRID580_GPU_MAX_BACKEND_DEVICES, sizeof(*legacy), GFP_KERNEL);
    open = kvcalloc(HYBRID580_GPU_MAX_BACKEND_DEVICES, sizeof(*open), GFP_KERNEL);
    if (catalog == NULL || legacy == NULL || open == NULL) {
        rc = -ENOMEM;
        goto out;
    }
    rc = hybrid580_legacy_gpu_inventory_v1(
        legacy, HYBRID580_GPU_MAX_BACKEND_DEVICES, &legacy_count);
    if (rc != 0)
        goto out;
    rc = hybrid580_open_gpu_inventory_v1(
        open, HYBRID580_GPU_MAX_BACKEND_DEVICES, &open_count);
    if (rc != 0)
        goto out;
    rc = hybrid580_gpu_catalog_build_v1(legacy, legacy_count,
                                        open, open_count, catalog);
    if (rc == 0) {
        state->catalog = catalog;
        catalog = NULL;
    }
out:
    kvfree(open);
    kvfree(legacy);
    kvfree(catalog);
    return rc;
}

/* A mapping is published once after both creates succeed. VFS keeps front
 * alive through fget or iterate_fd's files lock; its private_data and owned
 * sessions remain immutable until final release. These callbacks neither
 * sleep nor acquire a mutex and return exactly one backing-file reference.
 */
static struct file *hybrid_front_project_legacy(struct file *front, bool ctl)
{
    struct hybrid_front_file_base *base;
    struct hybrid_front_file *state;
    struct hybrid_front_gpu_file *gpu;
    struct file *back = NULL;
    unsigned long flags;
    if (front == NULL || front->f_op != &hybrid_front_fops || front->private_data == NULL)
        return NULL;
    base = front->private_data;
    if (ctl && base->kind == HYBRID_FRONT_CONTROL_FILE) {
        state = front->private_data;
        spin_lock_irqsave(&state->session_lock, flags);
        back = hybrid580_legacy_control_session_file_v1(state->sessions[0]);
        spin_unlock_irqrestore(&state->session_lock, flags);
        return back;
    }
    if (!ctl && base->kind == HYBRID_FRONT_GPU_FILE) {
        gpu = front->private_data;
        return gpu->backend == HYBRID580_BACKEND_LEGACY ? gpu->file(gpu->session) : NULL;
    }
    return NULL;
}

static struct file *hybrid_front_project_open(struct file *front, bool ctl)
{
    struct hybrid_front_file_base *base;
    struct hybrid_front_file *state;
    struct hybrid_front_gpu_file *gpu;
    struct file *back = NULL;
    unsigned long flags;
    if (front == NULL || front->f_op != &hybrid_front_fops || front->private_data == NULL)
        return NULL;
    base = front->private_data;
    if (ctl && base->kind == HYBRID_FRONT_CONTROL_FILE) {
        state = front->private_data;
        spin_lock_irqsave(&state->session_lock, flags);
        back = hybrid580_open_control_session_file_v1(state->sessions[1]);
        spin_unlock_irqrestore(&state->session_lock, flags);
        return back;
    }
    if (!ctl && base->kind == HYBRID_FRONT_GPU_FILE) {
        gpu = front->private_data;
        return gpu->backend == HYBRID580_BACKEND_OPEN ? gpu->file(gpu->session) : NULL;
    }
    return NULL;
}

static void hybrid_front_gpu_discard(struct hybrid_front_gpu_file *gpu)
{
    if (gpu == NULL)
        return;
    if (gpu->session != NULL)
        gpu->put(gpu->session);
    if (gpu->control_front != NULL)
        fput(gpu->control_front);
    kfree(gpu);
}

static int hybrid_front_gpu_release(struct inode *inode, struct file *front)
{
    struct hybrid_front_gpu_file *gpu = front->private_data;
    (void)inode;
    front->private_data = NULL;
    hybrid_front_gpu_discard(gpu);
    return 0;
}

static struct file *hybrid_front_gpu_owner_get(
    struct hybrid_front_gpu_file *gpu,
    enum hybrid_front_gpu_association_state *association)
{
    struct file *control_front;
    unsigned long flags;

    if (gpu == NULL)
        return NULL;
    spin_lock_irqsave(&gpu->owner_lock, flags);
    control_front = gpu->control_front;
    if (control_front != NULL)
        get_file(control_front);
    if (association != NULL)
        *association = gpu->association_state;
    spin_unlock_irqrestore(&gpu->owner_lock, flags);
    return control_front;
}

static int hybrid_front_gpu_register_begin(struct hybrid_front_gpu_file *gpu)
{
    unsigned long flags;
    int rc = 0;

    spin_lock_irqsave(&gpu->owner_lock, flags);
    if (gpu->association_state != HYBRID_FRONT_GPU_STANDARD_UNREGISTERED)
        rc = gpu->association_state == HYBRID_FRONT_GPU_STANDARD_REGISTERING ?
            -EBUSY : -EINVAL;
    else
        gpu->association_state = HYBRID_FRONT_GPU_STANDARD_REGISTERING;
    spin_unlock_irqrestore(&gpu->owner_lock, flags);
    return rc;
}

static void hybrid_front_gpu_register_finish(
    struct hybrid_front_gpu_file *gpu,
    enum hybrid_front_gpu_association_state result,
    struct file **new_control_front)
{
    struct file *old_control_front = NULL;
    unsigned long flags;
    bool changed = false;

    spin_lock_irqsave(&gpu->owner_lock, flags);
    if (gpu->association_state == HYBRID_FRONT_GPU_STANDARD_REGISTERING) {
        if (result == HYBRID_FRONT_GPU_STANDARD_REGISTERED &&
            new_control_front != NULL && *new_control_front != NULL) {
            old_control_front = gpu->control_front;
            gpu->control_front = *new_control_front;
            *new_control_front = NULL; /* Transfer the fget reference. */
        }
        gpu->association_state = result;
        changed = true;
    }
    spin_unlock_irqrestore(&gpu->owner_lock, flags);
    if (old_control_front != NULL)
        fput(old_control_front);
    if (changed)
        wake_up_interruptible_poll(&gpu->association_wait,
                                   EPOLLIN | EPOLLRDNORM | EPOLLERR);
}

static enum hybrid_front_gpu_association_state
hybrid_front_gpu_association_snapshot(struct hybrid_front_gpu_file *gpu)
{
    enum hybrid_front_gpu_association_state association;
    unsigned long flags;

    spin_lock_irqsave(&gpu->owner_lock, flags);
    association = gpu->association_state;
    spin_unlock_irqrestore(&gpu->owner_lock, flags);
    return association;
}

static bool hybrid_front_control_matches_gpu(
    const struct hybrid_front_file *control,
    const struct hybrid_front_gpu_file *gpu)
{
    const struct hybrid580_gpu_catalog_entry_v1 *entry;

    if (control == NULL || gpu == NULL || control->catalog == NULL ||
        !hybrid580_standard_nodes_catalog_matches_v1(control->catalog) ||
        gpu->frontend_index >= control->catalog->count)
        return false;
    entry = &control->catalog->entries[gpu->frontend_index];
    return entry->frontend_index == gpu->frontend_index &&
        entry->frontend_gpu_id == gpu->frontend_index + 1U &&
        entry->backend == gpu->backend &&
        memcmp(entry->bdf, gpu->bdf, sizeof(gpu->bdf)) == 0;
}

/* NV_ESC_REGISTER_FD connects a standard /dev/nvidiaN open to the exact
 * control-file session selected by libcuda. The backend handles its native
 * ctl_nvfp reference; this frontend changes its transaction owner only after
 * that registration succeeds. Ambiguous backend failure poisons this GPU fd.
 */
static long hybrid_front_gpu_register_control_fd(
    struct hybrid_front_gpu_file *gpu, int control_fd)
{
    struct file *control_front = NULL;
    struct hybrid_front_file_base *base;
    struct hybrid_front_file *control;
    long rc;

    if (control_fd < 0)
        return -EBADF;
    control_front = fget((unsigned int)control_fd);
    if (control_front == NULL)
        return -EBADF;
    if (control_front->f_op != &hybrid_front_fops ||
        control_front->private_data == NULL) {
        rc = -EINVAL;
        goto out;
    }
    base = control_front->private_data;
    if (base->kind != HYBRID_FRONT_CONTROL_FILE) {
        rc = -EINVAL;
        goto out;
    }
    control = control_front->private_data;
    if (!hybrid_front_control_matches_gpu(control, gpu)) {
        rc = -EXDEV;
        goto out;
    }
    rc = hybrid_front_gpu_register_begin(gpu);
    if (rc != 0)
        goto out;

    rc = mutex_lock_interruptible(&control->transaction_lock);
    if (rc != 0) {
        hybrid_front_gpu_register_finish(
            gpu, HYBRID_FRONT_GPU_STANDARD_UNREGISTERED, NULL);
        goto out;
    }
    /* Quarantine is transaction-lock protected. Recheck after acquiring the
     * lock so a concurrent ambiguous operation cannot quarantine this control
     * session between validation and provider registration. No backend side
     * effect has started, so leave the GPU fd eligible for a clean retry. */
    if (control->quarantined) {
        mutex_unlock(&control->transaction_lock);
        hybrid_front_gpu_register_finish(
            gpu, HYBRID_FRONT_GPU_STANDARD_UNREGISTERED, NULL);
        rc = -EXDEV;
        goto out;
    }
    if (gpu->register_control == NULL ||
        control->sessions[gpu->backend] == NULL)
        rc = -ENODEV;
    else
        rc = gpu->register_control(gpu->session,
                                   control->sessions[gpu->backend]);
    if (rc == 0)
        control->stateful_started = true;
    mutex_unlock(&control->transaction_lock);

    if (rc == 0)
        hybrid_front_gpu_register_finish(
            gpu, HYBRID_FRONT_GPU_STANDARD_REGISTERED, &control_front);
    else
        hybrid_front_gpu_register_finish(
            gpu, HYBRID_FRONT_GPU_STANDARD_FAILED, NULL);
out:
    if (control_front != NULL)
        fput(control_front);
    return rc;
}

static long hybrid_front_gpu_register_fd(struct hybrid_front_gpu_file *gpu,
                                         unsigned int command,
                                         unsigned long argument)
{
    nv_ioctl_register_fd_t request;

    if (_IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        _IOC_SIZE(command) != sizeof(request))
        return -EINVAL;
    if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
        return -EFAULT;
    return hybrid_front_gpu_register_control_fd(gpu, request.ctl_fd);
}

/* R580 unwraps XFER before dispatching its inner command. Inspect and copy
 * both layers here so a standard GPU file cannot register a different control
 * fd through the generic backend ioctl path, including during a user-memory
 * race. Non-REGISTER XFER calls remain on the existing route. */
static long hybrid_front_gpu_register_fd_xfer(
    struct hybrid_front_gpu_file *gpu, unsigned int command,
    unsigned long argument, bool *handled)
{
    nv_ioctl_register_fd_t request;
    nv_ioctl_xfer_t xfer;

    *handled = true;
    if (_IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        _IOC_SIZE(command) != sizeof(xfer))
        return -EINVAL;
    if (copy_from_user(&xfer, (void __user *)argument, sizeof(xfer)))
        return -EFAULT;
    if (xfer.cmd != NV_ESC_REGISTER_FD) {
        *handled = false;
        return 0;
    }
    if (xfer.size != sizeof(request))
        return -EINVAL;
    if (copy_from_user(&request,
                       (void __user *)NvP64_VALUE(xfer.ptr),
                       sizeof(request)))
        return -EFAULT;
    return hybrid_front_gpu_register_control_fd(gpu, request.ctl_fd);
}

/* Only NVIDIA ioctl numbers are passed through this test GPU descriptor.
 * Backing-file projection supplies the matching backend GPU file when the
 * vendor ioctl resolves a GPU or REGISTER_FD relationship. */
static long hybrid_front_gpu_ioctl(struct file *front, unsigned int command,
                                   unsigned long argument)
{
    struct hybrid_front_gpu_file *gpu = front->private_data;
    struct hybrid_front_file *state;
    struct file *control_front;
    enum hybrid_front_gpu_association_state association;
    long rc;
    if (gpu == NULL || gpu->session == NULL)
        return -EBADF;
    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC)
        return -ENOTTY;
    control_front = hybrid_front_gpu_owner_get(gpu, &association);
    if (control_front == NULL || control_front->private_data == NULL) {
        if (control_front != NULL)
            fput(control_front);
        return -EBADF;
    }
    if (association != HYBRID_FRONT_GPU_PRIVATE_ASSOCIATION &&
        _IOC_NR(command) == NV_ESC_REGISTER_FD) {
        fput(control_front);
        return hybrid_front_gpu_register_fd(gpu, command, argument);
    }
    if (association != HYBRID_FRONT_GPU_PRIVATE_ASSOCIATION &&
        _IOC_NR(command) == NV_ESC_IOCTL_XFER_CMD) {
        bool handled;

        rc = hybrid_front_gpu_register_fd_xfer(
            gpu, command, argument, &handled);
        if (handled) {
            fput(control_front);
            return rc;
        }
    }
    if (association == HYBRID_FRONT_GPU_STANDARD_UNREGISTERED ||
        association == HYBRID_FRONT_GPU_STANDARD_REGISTERING ||
        association == HYBRID_FRONT_GPU_STANDARD_FAILED) {
        fput(control_front);
        return association == HYBRID_FRONT_GPU_STANDARD_UNREGISTERED ?
            -ENOTCONN : -EIO;
    }
    state = control_front->private_data;
    if (state->base.kind != HYBRID_FRONT_CONTROL_FILE) {
        fput(control_front);
        return -EBADF;
    }
    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0) {
        fput(control_front);
        return rc;
    }
    state->stateful_started = true;
    rc = gpu->ioctl(gpu->session, command, argument);
    mutex_unlock(&state->transaction_lock);
    fput(control_front);
    return rc;
}

/* RM installs its mmap context on the backend struct file selected by the
 * projection hook. NVIDIA's mmap callbacks also recover nvlfp from vm_file,
 * and later VMA operations retain that backend file. Transfer the initial VMA
 * reference with the kernel's vma_set_file() helper before invoking the native
 * callback; this keeps mmap, fault, split/fork and close on the same backend
 * file whose RM ioctl created the map context.
 */
static int hybrid_front_map_begin(spinlock_t *lock,
                                  enum hybrid_front_map_state *map_state,
                                  unsigned int *backend)
{
    unsigned long flags;
    int rc = 0;

    spin_lock_irqsave(lock, flags);
    if (*map_state == HYBRID_FRONT_MAP_READY &&
        (*backend == HYBRID580_BACKEND_LEGACY ||
         *backend == HYBRID580_BACKEND_OPEN))
        *map_state = HYBRID_FRONT_MAP_MAPPING;
    else if (*map_state == HYBRID_FRONT_MAP_POISONED)
        rc = -EIO;
    else if (*map_state == HYBRID_FRONT_MAP_EMPTY)
        rc = -EINVAL;
    else
        rc = -EBUSY;
    spin_unlock_irqrestore(lock, flags);
    return rc;
}

static void hybrid_front_map_finish(spinlock_t *lock,
                                    enum hybrid_front_map_state *map_state,
                                    bool success)
{
    unsigned long flags;

    spin_lock_irqsave(lock, flags);
    if (*map_state == HYBRID_FRONT_MAP_MAPPING)
        *map_state = success ? HYBRID_FRONT_MAP_CONSUMED :
                               HYBRID_FRONT_MAP_READY;
    spin_unlock_irqrestore(lock, flags);
}

static struct file *hybrid_front_control_file(struct hybrid_front_file *state,
                                              unsigned int backend)
{
    if (state == NULL)
        return NULL;
    if (backend == HYBRID580_BACKEND_LEGACY)
        return hybrid580_legacy_control_session_file_v1(state->sessions[0]);
    if (backend == HYBRID580_BACKEND_OPEN)
        return hybrid580_open_control_session_file_v1(state->sessions[1]);
    return NULL;
}

/* NV_ESC_RM_MAP_MEMORY stores its mmap context against the descriptor embedded
 * in NVOS33. Only allow a matching successful MAP followed by mmap on that
 * exact frontend open-file description. vma_set_file transfers the VMA to the
 * selected backend file so faults, split/fork and close use the same RM context.
 * Native R580 permits one pending map context per file; after consumption the
 * caller must open another target descriptor before requesting another map. */
static int hybrid_front_gpu_mmap_inner(struct file *front, struct vm_area_struct *vma)
{
    struct hybrid_front_file_base *base;
    struct hybrid_front_gpu_file *gpu = NULL;
    struct hybrid_front_file *state;
    struct file *back = NULL;
    struct file *owner_front = NULL;
    enum hybrid_front_gpu_association_state association;
    spinlock_t *map_lock;
    enum hybrid_front_map_state *map_state;
    unsigned int *map_backend;
    unsigned int backend;
    int rc;

    if (front == NULL || vma == NULL || front->private_data == NULL)
        return -EINVAL;

    base = front->private_data;
    if (base->kind == HYBRID_FRONT_CONTROL_FILE) {
        state = front->private_data;
        map_lock = &state->map_lock;
        map_state = &state->pending_map_state;
        map_backend = &state->pending_map_backend;
    } else if (base->kind == HYBRID_FRONT_GPU_FILE) {
        gpu = front->private_data;
        if (gpu->session == NULL || gpu->file == NULL)
            return -EBADF;
        owner_front = hybrid_front_gpu_owner_get(gpu, &association);
        if (owner_front == NULL || owner_front->private_data == NULL) {
            if (owner_front != NULL)
                fput(owner_front);
            return -EBADF;
        }
        if (association == HYBRID_FRONT_GPU_STANDARD_UNREGISTERED ||
            association == HYBRID_FRONT_GPU_STANDARD_REGISTERING ||
            association == HYBRID_FRONT_GPU_STANDARD_FAILED) {
            fput(owner_front);
            return association == HYBRID_FRONT_GPU_STANDARD_UNREGISTERED ?
                -ENOTCONN : -EIO;
        }
        state = owner_front->private_data;
        if (state->base.kind != HYBRID_FRONT_CONTROL_FILE)
            goto bad_gpu_owner;
        map_lock = &gpu->map_lock;
        map_state = &gpu->pending_map_state;
        map_backend = &gpu->pending_map_backend;
    } else {
        return -EINVAL;
    }

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0) {
        if (owner_front != NULL)
            fput(owner_front);
        return rc;
    }
    rc = hybrid_front_map_begin(map_lock, map_state, map_backend);
    if (rc != 0)
        goto done;
    state->stateful_started = true;
    backend = READ_ONCE(*map_backend);

    if (gpu == NULL) {
        back = hybrid_front_control_file(state, backend);
    } else {
        if (gpu->backend != backend) {
            rc = -EXDEV;
            goto finish;
        }
        back = gpu->file(gpu->session);
    }
    if (back == NULL) {
        rc = -ENODEV;
        goto finish;
    }
    if (back->f_op == NULL || back->f_op->mmap == NULL) {
        rc = -EOPNOTSUPP;
        goto put_back;
    }

    vma_set_file(vma, back);
    rc = back->f_op->mmap(back, vma);

put_back:
    fput(back);
finish:
    hybrid_front_map_finish(map_lock, map_state, rc == 0);
done:
    mutex_unlock(&state->transaction_lock);
    if (owner_front != NULL)
        fput(owner_front);
    return rc;

bad_gpu_owner:
    fput(owner_front);
    return -EBADF;
}

static int hybrid_front_gpu_mmap(struct file *front, struct vm_area_struct *vma)
{
    int rc = hybrid_front_admission_try_enter();

    /* Linux calls file_operations.mmap with the caller's mmap_lock held.
     * Never park a freezable task while retaining that mm-wide lock. */
    if (rc != 0)
        return rc;
    rc = hybrid_front_gpu_mmap_inner(front, vma);
    hybrid_front_admission_leave();
    return rc;
}

/* R580/R595 nvidia_poll() evaluates the native GPU file-private event state
 * and registers its waitqueue through poll_wait(file, ...). Keep that exact
 * backend file and the kernel's poll_table together. Mirror O_NONBLOCK from
 * the frontend open-file description because NVIDIA checks backend f_flags.
 * Do not take the frontend transaction mutex here: poll may be called from
 * epoll while epoll locks are
 * held, and the NVIDIA poll callback has its own event-state synchronization.
 * The immutable GPU session owns a backend-file reference for this callback;
 * gpu->file() adds one temporary reference, while poll_wait's qproc may retain
 * another for select/poll wait-table lifetime.
 */
static __poll_t hybrid_front_gpu_poll_inner(struct file *front, poll_table *wait)
{
    struct hybrid_front_file_base *base;
    struct hybrid_front_gpu_file *gpu;
    struct file *back;
    enum hybrid_front_gpu_association_state association;
    int back_flags;
    __poll_t mask;

    if (front == NULL || front->private_data == NULL)
        return POLLERR;

    base = front->private_data;
    if (base->kind == HYBRID_FRONT_CONTROL_FILE)
        return 0;
    if (base->kind != HYBRID_FRONT_GPU_FILE)
        return POLLERR;

    gpu = front->private_data;
    if (gpu->session == NULL || gpu->file == NULL)
        return POLLERR;

    association = hybrid_front_gpu_association_snapshot(gpu);
    if (association == HYBRID_FRONT_GPU_STANDARD_UNREGISTERED ||
        association == HYBRID_FRONT_GPU_STANDARD_REGISTERING) {
        /* Queue before the second state read so a concurrent successful
         * REGISTER_FD cannot be missed by a blocked poll/epoll waiter. */
        poll_wait(front, &gpu->association_wait, wait);
        association = hybrid_front_gpu_association_snapshot(gpu);
        if (association == HYBRID_FRONT_GPU_STANDARD_UNREGISTERED ||
            association == HYBRID_FRONT_GPU_STANDARD_REGISTERING)
            return 0;
        if (association == HYBRID_FRONT_GPU_STANDARD_FAILED)
            return EPOLLERR;
    } else if (association == HYBRID_FRONT_GPU_STANDARD_FAILED) {
        return EPOLLERR;
    }

    /* gpu->file() is a non-sleeping reference accessor on the immutable
     * session, so this path remains usable while epoll holds its locks. */
    back = gpu->file(gpu->session);
    if (back == NULL)
        return POLLERR;
    if (back->f_op == NULL || back->f_op->poll == NULL) {
        fput(back);
        return POLLERR;
    }

    back_flags = READ_ONCE(back->f_flags);
    back_flags = (back_flags & ~O_NONBLOCK) |
                 (READ_ONCE(front->f_flags) & O_NONBLOCK);
    WRITE_ONCE(back->f_flags, back_flags);
    mask = back->f_op->poll(back, wait);
    fput(back);
    return mask;
}

static __poll_t hybrid_front_gpu_poll(struct file *front, poll_table *wait)
{
    int rc;
    __poll_t mask;

    /* Queue before testing the gate so reopening cannot be missed by epoll. */
    poll_wait(front, &hybrid_front_admission_wait, wait);
    rc = hybrid_front_admission_try_enter();
    if (rc == -EAGAIN)
        return 0;
    if (rc != 0)
        return EPOLLERR;
    mask = hybrid_front_gpu_poll_inner(front, wait);
    hybrid_front_admission_leave();
    return mask;
}

static bool hybrid_front_bdf_valid(const char *bdf)
{
    unsigned int i;
    if (bdf == NULL || strnlen(bdf, 16) != 12 || bdf[12] != '\0' ||
        bdf[13] != '\0' || bdf[14] != '\0' || bdf[15] != '\0')
        return false;
    for (i = 0; i < 12; ++i) {
        bool hex = (bdf[i] >= '0' && bdf[i] <= '9') ||
                   (bdf[i] >= 'a' && bdf[i] <= 'f');
        if ((i == 4 || i == 7) ? bdf[i] != ':' :
            i == 10 ? bdf[i] != '.' : !hex)
            return false;
    }
    return bdf[11] <= '7';
}

static int hybrid_front_gpu_file_create(
    struct file *control_front, const char *bdf,
    enum hybrid_front_gpu_association_state association,
    unsigned int expected_index, struct hybrid_front_gpu_file **out)
{
    struct hybrid_front_file_base *base;
    struct hybrid_front_file *control;
    struct hybrid580_gpu_catalog_entry_v1 *entry = NULL;
    struct hybrid_front_gpu_file *gpu;
    unsigned int i;
    int rc;

    if (out == NULL)
        return -EINVAL;
    *out = NULL;
    if (control_front == NULL || control_front->f_op != &hybrid_front_fops ||
        control_front->private_data == NULL || !hybrid_front_bdf_valid(bdf))
        return -EINVAL;
    base = control_front->private_data;
    if (base->kind != HYBRID_FRONT_CONTROL_FILE)
        return -EINVAL;
    control = control_front->private_data;
    if (control->catalog == NULL)
        return -ENODEV;
    for (i = 0; i < control->catalog->count; ++i) {
        if (memcmp(control->catalog->entries[i].bdf, bdf,
                   HYBRID580_GPU_BDF_SIZE) == 0) {
            entry = &control->catalog->entries[i];
            break;
        }
    }
    if (entry == NULL || (expected_index != ~0U &&
                          entry->frontend_index != expected_index))
        return -ENODEV;

    gpu = kzalloc(sizeof(*gpu), GFP_KERNEL);
    if (gpu == NULL)
        return -ENOMEM;
    gpu->base.kind = HYBRID_FRONT_GPU_FILE;
    spin_lock_init(&gpu->map_lock);
    spin_lock_init(&gpu->owner_lock);
    init_waitqueue_head(&gpu->association_wait);
    gpu->pending_map_state = HYBRID_FRONT_MAP_EMPTY;
    gpu->pending_map_backend = HYBRID580_BACKEND_LEGACY;
    gpu->control_front = get_file(control_front);
    gpu->association_state = association;
    gpu->frontend_index = entry->frontend_index;
    memcpy(gpu->bdf, entry->bdf, sizeof(gpu->bdf));
    gpu->backend = entry->backend;
    if (entry->backend == HYBRID580_BACKEND_LEGACY) {
        gpu->put = hybrid580_legacy_gpu_session_put_v1;
        gpu->file = hybrid580_legacy_gpu_session_file_v1;
        gpu->ioctl = hybrid580_legacy_gpu_session_ioctl_v1;
        gpu->register_control = hybrid580_legacy_gpu_session_register_control_v1;
        rc = hybrid580_legacy_gpu_session_create_by_bdf_v1(
            control_front, entry->bdf, &gpu->session);
    } else if (entry->backend == HYBRID580_BACKEND_OPEN) {
        gpu->put = hybrid580_open_gpu_session_put_v1;
        gpu->file = hybrid580_open_gpu_session_file_v1;
        gpu->ioctl = hybrid580_open_gpu_session_ioctl_v1;
        gpu->register_control = hybrid580_open_gpu_session_register_control_v1;
        rc = hybrid580_open_gpu_session_create_by_bdf_v1(
            control_front, entry->bdf, &gpu->session);
    } else {
        rc = -EINVAL;
    }
    if (rc != 0) {
        hybrid_front_gpu_discard(gpu);
        return rc == -EXDEV ? -ENODEV : rc;
    }
    *out = gpu;
    return 0;
}

static int hybrid_front_open_gpu_fd(struct file *control_front,
                                    unsigned long argument)
{
    struct hybrid580_open_gpu_v1 request;
    struct hybrid_front_gpu_file *gpu;
    struct file *gpu_front;
    int fd, rc;

    if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
        return -EFAULT;
    if (request.struct_size != sizeof(request) || request.flags != 0 ||
        request.gpu_fd != 0 || request.backend != 0 ||
        request.reserved[0] != 0 || request.reserved[1] != 0 ||
        !hybrid_front_bdf_valid(request.bdf))
        return -EINVAL;

    rc = hybrid_front_gpu_file_create(control_front, request.bdf,
        HYBRID_FRONT_GPU_PRIVATE_ASSOCIATION, ~0U, &gpu);
    if (rc != 0)
        return rc;

    gpu_front = anon_inode_getfile("hybrid580-gpu", &hybrid_front_fops, gpu,
                                   O_RDWR | O_CLOEXEC);
    if (IS_ERR(gpu_front)) {
        rc = PTR_ERR(gpu_front);
        hybrid_front_gpu_discard(gpu);
        return rc;
    }
    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        fput(gpu_front);
        return fd;
    }
    request.gpu_fd = fd;
    request.backend = gpu->backend;
    if (copy_to_user((void __user *)argument, &request, sizeof(request))) {
        put_unused_fd(fd);
        fput(gpu_front);
        return -EFAULT;
    }
    /* Publish the descriptor only after copyout succeeds. */
    fd_install(fd, gpu_front);
    return 0;
}

/* Attach is a cross-backend transaction. Build and attach a disposable pair
 * while the control file is still clean, then publish both sessions under the
 * atomic projection lock. On failure, the old pair remains selected and all
 * candidate references are dropped after releasing the frontend mutex. */
static long hybrid_front_attach_gpus(struct file *front, const void __user *user_ids,
                                     size_t bytes)
{
    struct hybrid_front_file *state = front->private_data;
    struct hybrid580_gpu_attach_plan_v1 *plan = NULL;
    struct hybrid580_control_session *candidate[2] = { NULL, NULL };
    struct hybrid580_control_session *retired[2] = { NULL, NULL };
    struct hybrid_rm_session_endpoint_v1 candidate_ep[2] = { { 0 }, { 0 } };
    NvU32 *frontend_ids = NULL;
    NvU32 count;
    unsigned long flags;
    unsigned int i;
    long rc;

    if (state == NULL || state->catalog == NULL || bytes == 0 ||
        bytes % sizeof(NvU32) != 0)
        return -EINVAL;
    count = bytes / sizeof(NvU32);
    if (count > HYBRID580_GPU_MAX_DEVICES)
        return -E2BIG;
    frontend_ids = kvcalloc(count, sizeof(*frontend_ids), GFP_KERNEL);
    plan = kvzalloc(sizeof(*plan), GFP_KERNEL);
    if (frontend_ids == NULL || plan == NULL) {
        rc = -ENOMEM;
        goto out;
    }
    if (copy_from_user(frontend_ids, user_ids, bytes)) {
        rc = -EFAULT;
        goto out;
    }
    rc = hybrid580_gpu_catalog_plan_attach_v1(
        state->catalog, frontend_ids, count, plan);
    if (rc != 0)
        goto out;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        goto out;
    if (state->stateful_started || state->operation_inflight != 0 || state->attach_attempted ||
        state->root_count != 0 || state->quarantined) {
        rc = -EBUSY;
        goto unlock;
    }

    rc = hybrid580_legacy_control_session_create_v1(front, &candidate[0], &candidate_ep[0]);
    if (rc != 0)
        goto unlock;
    rc = hybrid580_open_control_session_create_v1(front, &candidate[1], &candidate_ep[1]);
    if (rc != 0)
        goto unlock;

    state->attach_attempted = true;
    for (i = 0; i < 2; ++i) {
        hybrid_control_attach_fn attach = i == HYBRID580_BACKEND_LEGACY ?
            hybrid580_legacy_control_session_attach_v1 :
            hybrid580_open_control_session_attach_v1;
        if (plan->backends[i].count == 0)
            continue;
        rc = attach(candidate[i], plan->backends[i].backend_gpu_ids,
                    plan->backends[i].count);
        if (rc != 0) {
            state->quarantined = true;
            goto unlock;
        }
    }

    spin_lock_irqsave(&state->session_lock, flags);
    retired[0] = state->sessions[0];
    retired[1] = state->sessions[1];
    state->sessions[0] = candidate[0];
    state->sessions[1] = candidate[1];
    spin_unlock_irqrestore(&state->session_lock, flags);
    for (i = 0; i < 2; ++i) {
        state->forwards[i].actual = candidate_ep[i];
        state->forwards[i].front = state;
        state->forwards[i].backend = i;
        state->endpoints[i] = candidate_ep[i];
        state->endpoints[i].invoke = hybrid_front_invoke;
        state->endpoints[i].context = &state->forwards[i];
    }
    candidate[0] = NULL;
    candidate[1] = NULL;
    state->attach_committed = true;
    state->stateful_started = true;
    rc = 0;
unlock:
    mutex_unlock(&state->transaction_lock);
out:
    if (candidate[1] != NULL)
        hybrid580_open_control_session_put_v1(candidate[1]);
    if (candidate[0] != NULL)
        hybrid580_legacy_control_session_put_v1(candidate[0]);
    if (retired[1] != NULL)
        hybrid580_open_control_session_put_v1(retired[1]);
    if (retired[0] != NULL)
        hybrid580_legacy_control_session_put_v1(retired[0]);
    kvfree(plan);
    kvfree(frontend_ids);
    return rc;
}

static long hybrid_front_attach_ioctl(struct file *front, unsigned int command,
                                      unsigned long argument)
{
    size_t bytes;
    const void __user *user_ids;
    unsigned int number = _IOC_NR(command);

    if (number == NV_ESC_ATTACH_GPUS_TO_FD) {
        bytes = _IOC_SIZE(command);
        user_ids = (const void __user *)argument;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, (void __user *)argument, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_ATTACH_GPUS_TO_FD)
            return -ENOTTY;
        bytes = xfer.size;
        user_ids = (const void __user *)NvP64_VALUE(xfer.ptr);
    } else {
        return -ENOTTY;
    }
    return hybrid_front_attach_gpus(front, user_ids, bytes);
}

/* Detect contradictory successful ID reuse before the broker can rollback a
 * newly observed handle. The current frontend transaction mutex protects this
 * bounded registry. Returning transport failure prevents the broker from
 * treating an alias of an existing allocation as new FREE-able ownership.
 */
static NV_STATUS NV_API_CALL hybrid_front_invoke(void *context, NvU32 command, void *payload, NvU32 size)
{
    struct hybrid_front_forward *forward = context;
    struct hybrid_front_file *state = forward->front;
    struct hybrid_front_root *node;
    NvHandle observed;
    NV_STATUS embedded, transport;
    transport = forward->actual.invoke(forward->actual.context, command, payload, size);
    if (transport != NV_OK || command != NV_ESC_RM_ALLOC)
        return transport;
    if (size == sizeof(NVOS21_PARAMETERS)) {
        observed = ((NVOS21_PARAMETERS *)payload)->hObjectNew;
        embedded = ((NVOS21_PARAMETERS *)payload)->status;
    } else if (size == sizeof(NVOS64_PARAMETERS)) {
        observed = ((NVOS64_PARAMETERS *)payload)->hObjectNew;
        embedded = ((NVOS64_PARAMETERS *)payload)->status;
    } else {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (embedded != NV_OK || observed == 0)
        return transport;
    for (node = state->roots; node != NULL; node = node->next) {
        struct hybrid_front_rm_object *device;
        if (node->root.slot[forward->backend].handle == observed) {
            node->root.state = HYBRID_ROOT_QUARANTINED;
            node->root.slot[forward->backend].uncertain = NV_TRUE;
            state->quarantined = true;
            return NV_ERR_INVALID_STATE;
        }
        for (device = node->objects; device != NULL; device = device->next) {
            if (device->handle == observed) {
                node->root.state = HYBRID_ROOT_QUARANTINED;
                node->root.slot[forward->backend].uncertain = NV_TRUE;
                state->quarantined = true;
                return NV_ERR_INVALID_STATE;
            }
        }
    }
    return transport;
}

/* Resolve the common client/root namespace, then route this one metadata
 * command to the RM that owns the synthetic GPU ID. Both backend RM requests
 * use their own ROOT handle and GPU ID; neither namespace crosses the call. */
static long hybrid_front_gpu_id_info(struct hybrid_front_file *state,
                                     NVOS54_PARAMETERS *control,
                                     NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *params)
{
    struct hybrid_front_root *root;
    struct hybrid580_gpu_catalog_entry_v1 entry;
    struct hybrid580_control_session *session;
    NvU32 control_status = 0xffffffffU;
    NvHandle backend_root;
    NV_STATUS transport;
    int rc;

    if (state == NULL || state->catalog == NULL || control == NULL || params == NULL ||
        control->cmd != NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 ||
        control->flags != 0 || control->paramsSize != sizeof(*params) ||
        control->hClient == 0 || control->hObject != control->hClient || params->gpuId == 0)
        return -EINVAL;

    rc = hybrid580_gpu_catalog_lookup_front_id_v1(state->catalog, params->gpuId, &entry);
    if (rc != 0 || entry.frontend_gpu_id != params->gpuId ||
        (entry.backend != HYBRID580_BACKEND_LEGACY &&
         entry.backend != HYBRID580_BACKEND_OPEN))
        return -EINVAL;

    for (root = state->roots; root != NULL; root = root->next)
        if (root->root.id == control->hClient)
            break;
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[0].handle != control->hClient ||
        root->root.slot[1].handle != control->hClient)
        return -EINVAL;

    backend_root = root->root.slot[entry.backend].handle;
    session = state->sessions[entry.backend];
    if (backend_root == 0 || session == NULL)
        return -EINVAL;

    /* The RM receives only typed kernel-owned memory. Input fields documented
     * as outputs are cleared so caller data cannot influence the backend. */
    params->gpuFlags = 0;
    params->deviceInstance = 0;
    params->subDeviceInstance = 0;
    params->sliStatus = 0;
    params->boardId = 0;
    params->gpuInstance = 0;
    params->numaId = 0;
    params->gpuId = entry.backend_gpu_id;
    if (entry.backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_gpu_id_info_v1(
            session, backend_root, backend_root, 0, params, &control_status);
    else
        transport = hybrid580_open_control_session_gpu_id_info_v1(
            session, backend_root, backend_root, 0, params, &control_status);

    /* Always return the frontend namespace, including RM error responses. */
    params->gpuId = entry.frontend_gpu_id;
    control->status = transport == NV_OK ? control_status : transport;
    return transport == NV_OK ? 0 : -EINVAL;
}

/* RM handles share one per-file namespace across roots and children. The
 * frontend serializes every stateful operation with transaction_lock, so this
 * bounded scan also detects handles returned by a later ROOT allocation that
 * collide with an earlier NV01_DEVICE_0 object. */
static bool hybrid_front_handle_in_use(const struct hybrid_front_file *state,
                                       NvHandle handle)
{
    const struct hybrid_front_root *root;

    if (state == NULL || handle == 0)
        return false;
    for (root = state->roots; root != NULL; root = root->next) {
        const struct hybrid_front_rm_object *device;

        if (root->root.id == handle ||
            root->root.slot[HYBRID580_BACKEND_LEGACY].handle == handle ||
            root->root.slot[HYBRID580_BACKEND_OPEN].handle == handle)
            return true;
        for (device = root->objects; device != NULL; device = device->next)
            if (device->handle == handle)
                return true;
    }
    return false;
}

/* Narrow user-buffer adapter for direct NVOS54 and the documented XFER
 * envelope. No other RM_CONTROL command or embedded pointer is forwarded. */
static int hybrid_front_validate_attached_ids(
    const struct hybrid580_gpu_catalog_v1 *catalog, unsigned int backend,
    const NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *params, NvU32 *count)
{
    bool saw_invalid = false;
    NvU32 expected = 0;
    NvU32 actual = 0;
    unsigned int i, j;

    if (catalog == NULL || params == NULL || count == NULL || backend > HYBRID580_BACKEND_OPEN ||
        catalog->count > HYBRID580_GPU_MAX_DEVICES)
        return -EINVAL;

    for (i = 0; i < NV0000_CTRL_GPU_MAX_ATTACHED_GPUS; ++i) {
        NvU32 gpu_id = params->gpuIds[i];
        bool found = false;

        if (gpu_id == NV0000_CTRL_GPU_INVALID_ID) {
            saw_invalid = true;
            continue;
        }
        if (saw_invalid || gpu_id == 0)
            return -EINVAL;
        for (j = 0; j < catalog->count; ++j) {
            const struct hybrid580_gpu_catalog_entry_v1 *entry = &catalog->entries[j];
            if (entry->backend == backend && entry->backend_gpu_id == gpu_id) {
                found = true;
                break;
            }
        }
        if (!found)
            return -EAGAIN;
        for (j = 0; j < i; ++j)
            if (params->gpuIds[j] == gpu_id)
                return -EAGAIN;
        ++actual;
    }

    for (i = 0; i < catalog->count; ++i)
        if (catalog->entries[i].backend == backend)
            ++expected;
    if (actual != expected)
        return -EAGAIN;
    *count = actual;
    return 0;
}

/* Merge both fixed-size RM tables into the same BDF-sorted namespace as the
 * private catalog. Stale IDs, duplicate/noncontiguous rows, missing devices or
 * more than the documented 32-entry user ABI fail closed instead of truncating. */
static long hybrid_front_attached_ids(struct hybrid_front_file *state,
                                      NVOS54_PARAMETERS *control,
                                      NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *params)
{
    struct hybrid_front_root *root;
    NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS backend_ids[2];
    NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS merged;
    NvU32 control_status[2] = { NV_ERR_INVALID_ARGUMENT, NV_ERR_INVALID_ARGUMENT };
    NvU32 backend_count[2] = { 0, 0 };
    NvHandle h_root[2];
    NV_STATUS transport;
    unsigned int backend, i;
    NvU32 out = 0;
    int rc;

    if (state == NULL || state->catalog == NULL || control == NULL || params == NULL)
        return -EINVAL;
    memset(&merged, 0xff, sizeof(merged));
    *params = merged;
    control->status = NV_ERR_INVALID_ARGUMENT;
    if (control->cmd != NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS || control->flags != 0 ||
        control->paramsSize != sizeof(*params) || control->hClient == 0 ||
        control->hObject != control->hClient)
        return -EINVAL;

    for (root = state->roots; root != NULL; root = root->next)
        if (root->root.id == control->hClient)
            break;
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[0].handle != control->hClient ||
        root->root.slot[1].handle != control->hClient) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }

    h_root[HYBRID580_BACKEND_LEGACY] = root->root.slot[HYBRID580_BACKEND_LEGACY].handle;
    h_root[HYBRID580_BACKEND_OPEN] = root->root.slot[HYBRID580_BACKEND_OPEN].handle;
    for (backend = HYBRID580_BACKEND_LEGACY; backend <= HYBRID580_BACKEND_OPEN; ++backend) {
        memset(&backend_ids[backend], 0xff, sizeof(backend_ids[backend]));
        if (backend == HYBRID580_BACKEND_LEGACY)
            transport = hybrid580_legacy_control_session_attached_ids_v1(
                state->sessions[backend], h_root[backend], h_root[backend], 0,
                &backend_ids[backend], &control_status[backend]);
        else
            transport = hybrid580_open_control_session_attached_ids_v1(
                state->sessions[backend], h_root[backend], h_root[backend], 0,
                &backend_ids[backend], &control_status[backend]);
        if (transport != NV_OK) {
            control->status = transport;
            return -EINVAL;
        }
        if (control_status[backend] != NV_OK) {
            control->status = control_status[backend];
            return -EINVAL;
        }
        rc = hybrid_front_validate_attached_ids(state->catalog, backend,
                                                 &backend_ids[backend],
                                                 &backend_count[backend]);
        if (rc != 0) {
            control->status = rc == -EAGAIN ? NV_ERR_INVALID_STATE : NV_ERR_INVALID_ARGUMENT;
            return -EINVAL;
        }
    }

    if (backend_count[HYBRID580_BACKEND_LEGACY] +
        backend_count[HYBRID580_BACKEND_OPEN] > NV0000_CTRL_GPU_MAX_ATTACHED_GPUS) {
        control->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return -EINVAL;
    }

    memset(&merged, 0xff, sizeof(merged));
    for (i = 0; i < state->catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *entry = &state->catalog->entries[i];
        unsigned int j;
        if (entry->backend > HYBRID580_BACKEND_OPEN) {
            control->status = NV_ERR_INVALID_STATE;
            return -EINVAL;
        }
        for (j = 0; j < backend_count[entry->backend]; ++j) {
            if (backend_ids[entry->backend].gpuIds[j] == entry->backend_gpu_id)
                break;
        }
        if (j == backend_count[entry->backend])
            continue;
        if (out >= NV0000_CTRL_GPU_MAX_ATTACHED_GPUS) {
            control->status = NV_ERR_INSUFFICIENT_RESOURCES;
            return -EINVAL;
        }
        merged.gpuIds[out++] = entry->frontend_gpu_id;
    }
    if (out != backend_count[HYBRID580_BACKEND_LEGACY] +
               backend_count[HYBRID580_BACKEND_OPEN]) {
        control->status = NV_ERR_INVALID_STATE;
        return -EINVAL;
    }

    *params = merged;
    control->status = NV_OK;
    return 0;
}

/* Build a combined device-instance namespace from both RMs' global valid-ID
 * masks and the complete BDF catalog. R580 implements GET_DEVICE_IDS through
 * gpumgrGetDeviceInstanceMask(), so this is intentionally independent of a
 * client's attached-GPU subset. Cache only after every typed ID-info result
 * agrees with both backend masks. */
static NV_STATUS hybrid_front_device_instance_map(
    struct hybrid_front_file *state, struct hybrid_front_root *root,
    struct hybrid580_device_instance_map_v1 *result)
{
    NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS device_ids[2] = { { 0 }, { 0 } };
    NvU32 backend_device_ids[2] = { 0, 0 };
    NvU32 control_status[2] = { NV_ERR_INVALID_ARGUMENT, NV_ERR_INVALID_ARGUMENT };
    struct hybrid580_device_instance_observation_v1 *observations = NULL;
    struct hybrid580_device_instance_map_v1 candidate = { 0 };
    NvHandle h_root[2];
    unsigned int backend, i;
    NV_STATUS status = NV_ERR_INVALID_STATE;
    long rc;

    if (result == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || state->catalog == NULL || root == NULL ||
        root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.id == 0 || root->root.slot[HYBRID580_BACKEND_LEGACY].handle != root->root.id ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != root->root.id) {
        memset(result, 0, sizeof(*result));
        return NV_ERR_INVALID_OBJECT_HANDLE;
    }
    if (root->device_map_valid) {
        *result = root->device_map;
        return NV_OK;
    }
    /* result may alias root->device_map; clear only after the valid-cache
     * branch so a repeated allocation cannot erase its own cached mapping. */
    memset(result, 0, sizeof(*result));

    h_root[HYBRID580_BACKEND_LEGACY] = root->root.slot[HYBRID580_BACKEND_LEGACY].handle;
    h_root[HYBRID580_BACKEND_OPEN] = root->root.slot[HYBRID580_BACKEND_OPEN].handle;
    for (backend = HYBRID580_BACKEND_LEGACY;
         backend <= HYBRID580_BACKEND_OPEN; ++backend) {
        NV_STATUS transport;
        control_status[backend] = NV_ERR_INVALID_ARGUMENT;
        if (backend == HYBRID580_BACKEND_LEGACY)
            transport = hybrid580_legacy_control_session_device_ids_v1(
                state->sessions[backend], h_root[backend], h_root[backend], 0,
                &device_ids[backend], &control_status[backend]);
        else
            transport = hybrid580_open_control_session_device_ids_v1(
                state->sessions[backend], h_root[backend], h_root[backend], 0,
                &device_ids[backend], &control_status[backend]);
        if (transport != NV_OK) {
            status = transport;
            goto out;
        }
        if (control_status[backend] != NV_OK) {
            status = control_status[backend];
            goto out;
        }
        backend_device_ids[backend] = device_ids[backend].deviceIds;
    }

    if (state->catalog->count != 0) {
        observations = kvcalloc(state->catalog->count, sizeof(*observations), GFP_KERNEL);
        if (observations == NULL) {
            status = NV_ERR_NO_MEMORY;
            goto out;
        }
    }

    for (i = 0; i < state->catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *entry =
            &state->catalog->entries[i];
        NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS info = { 0 };
        NVOS54_PARAMETERS id_control;

        if (entry->frontend_index != i || entry->frontend_gpu_id != i + 1U ||
            entry->backend > HYBRID580_BACKEND_OPEN || entry->backend_gpu_id == 0) {
            status = NV_ERR_INVALID_STATE;
            goto out;
        }
        info.gpuId = entry->frontend_gpu_id;
        id_control = (NVOS54_PARAMETERS) {
            .hClient = root->root.id,
            .hObject = root->root.id,
            .cmd = NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2,
            .flags = 0,
            .paramsSize = sizeof(info),
            .status = NV_ERR_INVALID_ARGUMENT,
        };
        rc = hybrid_front_gpu_id_info(state, &id_control, &info);
        if (rc != 0 || id_control.status != NV_OK ||
            info.gpuId != entry->frontend_gpu_id ||
            info.deviceInstance >= HYBRID580_RM_MAX_DEVICE_INSTANCES) {
            status = id_control.status == NV_OK ? NV_ERR_INVALID_STATE : id_control.status;
            goto out;
        }
        observations[i] = (struct hybrid580_device_instance_observation_v1) {
            .frontend_gpu_id = entry->frontend_gpu_id,
            .backend_gpu_id = entry->backend_gpu_id,
            .backend_device_instance = info.deviceInstance,
        };
    }

    rc = hybrid580_device_instance_map_build_v1(
        state->catalog, observations, state->catalog->count,
        backend_device_ids, &candidate);
    if (rc != 0) {
        status = rc == -E2BIG ? NV_ERR_INSUFFICIENT_RESOURCES : NV_ERR_INVALID_STATE;
        goto out;
    }
    root->device_map = candidate;
    root->device_map_valid = true;
    *result = candidate;
    status = NV_OK;
out:
    kvfree(observations);
    return status;
}

static long hybrid_front_device_ids(struct hybrid_front_file *state,
                                    NVOS54_PARAMETERS *control,
                                    NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *params)
{
    struct hybrid_front_root *root;
    struct hybrid580_device_instance_map_v1 map;
    NV_STATUS status;

    if (params == NULL)
        return -EINVAL;
    params->deviceIds = 0;
    if (control == NULL)
        return -EINVAL;
    control->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || state->catalog == NULL ||
        control->cmd != NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS || control->flags != 0 ||
        control->paramsSize != sizeof(*params) || control->hClient == 0 ||
        control->hObject != control->hClient)
        return -EINVAL;
    for (root = state->roots; root != NULL; root = root->next)
        if (root->root.id == control->hClient)
            break;
    if (root == NULL) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    status = hybrid_front_device_instance_map(state, root, &map);
    if (status != NV_OK) {
        control->status = status;
        return -EINVAL;
    }
    params->deviceIds = map.frontend_device_ids;
    control->status = NV_OK;
    return 0;
}

/* Merge the two backend-local probed and excluded ID tables through the
 * immutable BDF catalog. No RM-local identifier is exposed to the caller. */
static long hybrid_front_probed_ids(struct hybrid_front_file *state,
                                    NVOS54_PARAMETERS *control,
                                    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *params)
{
    struct hybrid_front_root *root;
    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *backend_ids;
    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS merged;
    NvU32 control_status[2] = { NV_ERR_INVALID_ARGUMENT, NV_ERR_INVALID_ARGUMENT };
    NvHandle h_root[2];
    NV_STATUS transport;
    unsigned int backend;
    NvU32 gpu_count = 0, excluded_count = 0;
    int rc;

    BUILD_BUG_ON(NV0000_CTRL_GPU_MAX_PROBED_GPUS !=
                 HYBRID580_GPU_MAX_PROBED_IDS);
    if (state == NULL || state->catalog == NULL || control == NULL || params == NULL)
        return -EINVAL;
    memset(&merged, 0xff, sizeof(merged));
    memset(merged.gpuFlags, 0, sizeof(merged.gpuFlags));
    *params = merged;
    control->status = NV_ERR_INVALID_ARGUMENT;
    if (control->cmd != NV0000_CTRL_CMD_GPU_GET_PROBED_IDS || control->flags != 0 ||
        control->paramsSize != sizeof(*params) || control->hClient == 0 ||
        control->hObject != control->hClient)
        return -EINVAL;

    for (root = state->roots; root != NULL; root = root->next)
        if (root->root.id == control->hClient)
            break;
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != control->hClient ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != control->hClient) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }

    /* Two SDK output tables plus the merged result exceed the kernel's
     * 1 KiB frame warning threshold. Keep backend scratch off the stack. */
    backend_ids = kcalloc(2, sizeof(*backend_ids), GFP_KERNEL);
    if (backend_ids == NULL) {
        control->status = NV_ERR_NO_MEMORY;
        return -ENOMEM;
    }

    h_root[HYBRID580_BACKEND_LEGACY] =
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle;
    h_root[HYBRID580_BACKEND_OPEN] =
        root->root.slot[HYBRID580_BACKEND_OPEN].handle;
    for (backend = HYBRID580_BACKEND_LEGACY;
         backend <= HYBRID580_BACKEND_OPEN; ++backend) {
        memset(&backend_ids[backend], 0xff, sizeof(backend_ids[backend]));
        if (backend == HYBRID580_BACKEND_LEGACY)
            transport = hybrid580_legacy_control_session_probed_ids_v1(
                state->sessions[backend], h_root[backend], h_root[backend], 0,
                &backend_ids[backend], &control_status[backend]);
        else
            transport = hybrid580_open_control_session_probed_ids_v1(
                state->sessions[backend], h_root[backend], h_root[backend], 0,
                &backend_ids[backend], &control_status[backend]);
        if (transport != NV_OK) {
            control->status = transport;
            kfree(backend_ids);
            return -EINVAL;
        }
        if (control_status[backend] != NV_OK) {
            control->status = control_status[backend];
            kfree(backend_ids);
            return -EINVAL;
        }
    }

    rc = hybrid580_gpu_catalog_merge_probed_ids_v1(
        state->catalog, NV0000_CTRL_GPU_INVALID_ID,
        backend_ids[HYBRID580_BACKEND_LEGACY].gpuIds,
        backend_ids[HYBRID580_BACKEND_LEGACY].excludedGpuIds,
        backend_ids[HYBRID580_BACKEND_LEGACY].gpuFlags,
        backend_ids[HYBRID580_BACKEND_OPEN].gpuIds,
        backend_ids[HYBRID580_BACKEND_OPEN].excludedGpuIds,
        backend_ids[HYBRID580_BACKEND_OPEN].gpuFlags,
        NV0000_CTRL_GPU_MAX_PROBED_GPUS, NV0000_CTRL_GPU_MAX_PROBED_GPUS,
        merged.gpuIds, merged.excludedGpuIds, merged.gpuFlags,
        &gpu_count, &excluded_count);
    kfree(backend_ids);
    if (rc != 0) {
        if (rc == -E2BIG)
            control->status = NV_ERR_INSUFFICIENT_RESOURCES;
        else if (rc == -ENOENT || rc == -EEXIST)
            control->status = NV_ERR_INVALID_STATE;
        else
            control->status = NV_ERR_INVALID_ARGUMENT;
        return -EINVAL;
    }

    *params = merged;
    control->status = NV_OK;
    return 0;
}

static long hybrid_front_gpu_id_info_ioctl(struct hybrid_front_file *state,
                                            unsigned int command,
                                            unsigned long argument)
{
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS params;
    struct hybrid_front_root *root;
    struct hybrid580_gpu_catalog_entry_v1 gpu;
    struct hybrid580_device_instance_map_v1 device_map;
    struct hybrid580_device_instance_entry_v1 instance;
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    size_t size;
    unsigned int number = _IOC_NR(command);
    long rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        size = _IOC_SIZE(command);
        if (size != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        size = xfer.size;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, size))
        return -EFAULT;
    if (control.cmd != NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 ||
        control.flags != 0 || control.paramsSize != sizeof(params) ||
        NvP64_VALUE(control.params) == NULL)
        return -ENOTTY;
    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, sizeof(params)))
        return -EFAULT;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    rc = hybrid_front_gpu_id_info(state, &control, &params);
    if (rc == 0 && control.status == NV_OK) {
        NV_STATUS map_status = NV_ERR_INVALID_OBJECT_HANDLE;

        for (root = state->roots; root != NULL; root = root->next)
            if (root->root.id == control.hClient)
                break;
        if (root != NULL) {
            if (hybrid580_gpu_catalog_lookup_front_id_v1(
                    state->catalog, params.gpuId, &gpu) != 0) {
                map_status = NV_ERR_INVALID_ARGUMENT;
            } else {
                map_status = hybrid_front_device_instance_map(
                    state, root, &device_map);
                if (map_status == NV_OK &&
                    hybrid580_device_instance_map_lookup_backend_v1(
                        &device_map, gpu.backend, params.deviceInstance,
                        &instance) != 0)
                    map_status = NV_ERR_INVALID_STATE;
            }
        }
        if (map_status == NV_OK) {
            params.deviceInstance = instance.frontend_device_instance;
        } else {
            /* Never publish a backend-local device instance if the combined
             * catalog/mask map cannot prove its frontend identity. */
            params.deviceInstance = 0;
            control.status = map_status;
            rc = -EINVAL;
        }
    } else {
        /* RM error paths may leave a partial local instance in the payload. */
        params.deviceInstance = 0;
    }
    mutex_unlock(&state->transaction_lock);

    if (copy_to_user(user_params, &params, sizeof(params)))
        return -EFAULT;
    if (copy_to_user(user_control, &control, sizeof(control)))
        return -EFAULT;
    return rc;
}

static long hybrid_front_attached_ids_ioctl(struct hybrid_front_file *state,
                                             unsigned int command,
                                             unsigned long argument)
{
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS params;
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    size_t size;
    unsigned int number = _IOC_NR(command);
    long rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        size = _IOC_SIZE(command);
        if (size != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        size = xfer.size;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, size))
        return -EFAULT;
    if (control.cmd != NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS ||
        control.flags != 0 || control.paramsSize != sizeof(params) ||
        NvP64_VALUE(control.params) == NULL)
        return -ENOTTY;
    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, sizeof(params)))
        return -EFAULT;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    rc = hybrid_front_attached_ids(state, &control, &params);
    mutex_unlock(&state->transaction_lock);

    if (copy_to_user(user_params, &params, sizeof(params)))
        return -EFAULT;
    if (copy_to_user(user_control, &control, sizeof(control)))
        return -EFAULT;
    return rc;
}

static long hybrid_front_device_ids_ioctl(struct hybrid_front_file *state,
                                           unsigned int command,
                                           unsigned long argument)
{
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS params = { 0 };
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    size_t size;
    unsigned int number = _IOC_NR(command);
    long rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        size = _IOC_SIZE(command);
        if (size != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        size = xfer.size;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, size))
        return -EFAULT;
    if (control.cmd != NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS ||
        control.flags != 0 || control.paramsSize != sizeof(params) ||
        NvP64_VALUE(control.params) == NULL)
        return -ENOTTY;
    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, sizeof(params)))
        return -EFAULT;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    rc = hybrid_front_device_ids(state, &control, &params);
    mutex_unlock(&state->transaction_lock);

    if (copy_to_user(user_params, &params, sizeof(params)))
        return -EFAULT;
    if (copy_to_user(user_control, &control, sizeof(control)))
        return -EFAULT;
    return rc;
}

static long hybrid_front_probed_ids_ioctl(struct hybrid_front_file *state,
                                           unsigned int command,
                                           unsigned long argument)
{
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS params;
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    size_t size;
    unsigned int number = _IOC_NR(command);
    long rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        size = _IOC_SIZE(command);
        if (size != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        size = xfer.size;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, size))
        return -EFAULT;
    if (control.cmd != NV0000_CTRL_CMD_GPU_GET_PROBED_IDS ||
        control.flags != 0 || control.paramsSize != sizeof(params) ||
        NvP64_VALUE(control.params) == NULL)
        return -ENOTTY;
    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, sizeof(params)))
        return -EFAULT;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    rc = hybrid_front_probed_ids(state, &control, &params);
    mutex_unlock(&state->transaction_lock);

    if (copy_to_user(user_params, &params, sizeof(params)))
        return -EFAULT;
    if (copy_to_user(user_control, &control, sizeof(control)))
        return -EFAULT;
    return rc;
}

static long hybrid_front_build_version_ioctl(struct hybrid_front_file *state,
                                               unsigned int command,
                                               unsigned long argument);
static long hybrid_front_gr_tpc_mask_ioctl(struct hybrid_front_file *state,
                                            unsigned int command,
                                            unsigned long argument);
static long hybrid_front_p2p_control_ioctl(struct hybrid_front_file *state,
                                            unsigned int command,
                                            unsigned long argument);

/* Inspect the typed RM command first; only verified fixed-size GPU
 * metadata tables cross the backend boundary. Generic controls stay denied. */
static long hybrid_front_rm_control_ioctl(struct hybrid_front_file *state,
                                          unsigned int command,
                                          unsigned long argument)
{
    NVOS54_PARAMETERS control;
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    size_t size;
    unsigned int number = _IOC_NR(command);

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        size = _IOC_SIZE(command);
        if (size != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        size = xfer.size;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, size))
        return -EFAULT;
    if (control.cmd == NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION)
        return hybrid_front_build_version_ioctl(state, command, argument);
    if (control.cmd == NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2)
        return hybrid_front_gpu_id_info_ioctl(state, command, argument);
    if (control.cmd == NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS)
        return hybrid_front_attached_ids_ioctl(state, command, argument);
    if (control.cmd == NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS)
        return hybrid_front_device_ids_ioctl(state, command, argument);
    if (control.cmd == NV0000_CTRL_CMD_GPU_GET_PROBED_IDS)
        return hybrid_front_probed_ids_ioctl(state, command, argument);
    if (control.cmd == NV2080_CTRL_CMD_GR_GET_TPC_MASK)
        return hybrid_front_gr_tpc_mask_ioctl(state, command, argument);
    if (control.cmd == NV503C_CTRL_CMD_REGISTER_VA_SPACE ||
        control.cmd == NV503C_CTRL_CMD_UNREGISTER_VA_SPACE ||
        control.cmd == NV503C_CTRL_CMD_REGISTER_VIDMEM ||
        control.cmd == NV503C_CTRL_CMD_UNREGISTER_VIDMEM)
        return hybrid_front_p2p_control_ioctl(state, command, argument);
    /* PID registration is intentionally not forwarded: it binds RM client
     * processes into the legacy P2P trust domain and was not observed in the
     * installed-driver validation workload. */
    if (control.cmd == NV503C_CTRL_CMD_REGISTER_PID)
        return -ENOTTY;
    return -ENOTTY;
}

static int hybrid_front_control_state_open(struct file *front,
                                           bool require_standard_catalog)
{
    struct hybrid_front_file *state;
    int rc;
    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (state == NULL)
        return -ENOMEM;
    state->base.kind = HYBRID_FRONT_CONTROL_FILE;
    mutex_init(&state->transaction_lock);
    spin_lock_init(&state->map_lock);
    state->pending_map_state = HYBRID_FRONT_MAP_EMPTY;
    state->pending_map_backend = HYBRID580_BACKEND_LEGACY;
    spin_lock_init(&state->session_lock);
    rc = hybrid580_legacy_control_session_create_v1(front, &state->sessions[0], &state->forwards[0].actual);
    if (rc != 0)
        goto free_state;
    rc = hybrid580_open_control_session_create_v1(front, &state->sessions[1], &state->forwards[1].actual);
    if (rc != 0)
        goto put_legacy;
    for (unsigned int i = 0; i < 2; ++i) {
        state->forwards[i].front = state;
        state->forwards[i].backend = i;
        state->endpoints[i] = state->forwards[i].actual;
        state->endpoints[i].invoke = hybrid_front_invoke;
        state->endpoints[i].context = &state->forwards[i];
    }
    rc = hybrid_front_catalog_create(state);
    if (rc != 0)
        goto put_open;
    if (require_standard_catalog &&
        !hybrid580_standard_nodes_catalog_matches_v1(state->catalog)) {
        rc = -ESTALE;
        goto put_open;
    }
    front->private_data = state;
    return 0;
 put_open:
    hybrid580_open_control_session_put_v1(state->sessions[1]);
 put_legacy:
    hybrid580_legacy_control_session_put_v1(state->sessions[0]);
 free_state:
    kvfree(state->catalog);
    kfree(state);
    return rc;
}

static int hybrid_front_open_standard_gpu(
    struct file *front,
    const struct hybrid580_standard_node_resolution_v1 *resolution)
{
    struct hybrid_front_gpu_file *gpu;
    struct file *control_front;
    int rc;

    if (resolution == NULL ||
        resolution->kind != HYBRID580_STANDARD_NODE_GPU)
        return -EINVAL;
    control_front = anon_inode_getfile("hybrid580-node-control",
        &hybrid_front_fops, NULL, O_RDWR | O_CLOEXEC);
    if (IS_ERR(control_front))
        return PTR_ERR(control_front);
    rc = hybrid_front_control_state_open(control_front, true);
    if (rc != 0) {
        fput(control_front);
        return rc;
    }
    rc = hybrid_front_gpu_file_create(control_front, resolution->bdf,
        HYBRID_FRONT_GPU_STANDARD_UNREGISTERED,
        resolution->frontend_index, &gpu);
    if (rc != 0) {
        fput(control_front);
        return rc;
    }
    front->private_data = gpu;
    fput(control_front);
    return 0;
}

static int hybrid_front_open_inner(struct inode *inode, struct file *front)
{
    struct hybrid580_standard_node_resolution_v1 resolution;
    int rc;

    /* misc_open supplies a miscdevice private_data initially. Standard nodes
     * arrive through major195 with the SDK-defined control/GPU minors.
     */
    front->private_data = NULL;
    if (inode != NULL && MAJOR(inode->i_rdev) == NV_MAJOR_DEVICE_NUMBER) {
        rc = hybrid580_standard_nodes_resolve_v1(MINOR(inode->i_rdev),
                                                  &resolution);
        if (rc != 0)
            return rc;
        if (resolution.kind == HYBRID580_STANDARD_NODE_CONTROL)
            return hybrid_front_control_state_open(front, true);
        if (resolution.kind == HYBRID580_STANDARD_NODE_GPU)
            return hybrid_front_open_standard_gpu(front, &resolution);
        return -ENODEV;
    }
    return hybrid_front_control_state_open(front, false);
}

static int hybrid_front_open(struct inode *inode, struct file *front)
{
    int rc = hybrid_front_admission_enter();

    if (rc != 0)
        return rc;
    rc = hybrid_front_open_inner(inode, front);
    hybrid_front_admission_leave();
    return rc;
}

static int hybrid_front_release_inner(struct inode *inode, struct file *front)
{
    struct hybrid_front_file_base *base = front->private_data;
    struct hybrid_front_file *state;
    struct hybrid580_control_session *legacy, *open;
    (void)inode;
    if (base == NULL)
        return 0;
    if (base->kind == HYBRID_FRONT_GPU_FILE)
        return hybrid_front_gpu_release(inode, front);
    if (base->kind != HYBRID_FRONT_CONTROL_FILE)
        return -EINVAL;
    state = front->private_data;
    /* Only final VFS release reaches here: no active ioctl/projector retains
     * this frontend file. Unpublish before backend puts, outside all locks. */
    front->private_data = NULL;
    mutex_lock(&state->transaction_lock);
    while (state->roots != NULL) {
        struct hybrid_front_root *node = state->roots;
        struct hybrid_front_rm_object *device;
        state->roots = node->next;
        if (node->root.state == HYBRID_ROOT_ACTIVE)
            (void)hybrid_root_free(&node->root);
        device = node->objects;
        while (device != NULL) {
            struct hybrid_front_rm_object *next = device->next;
            kfree(device);
            device = next;
        }
        kfree(node);
    }
    state->root_count = 0;
    state->object_count = 0;
    /* Never retry an ambiguous allocation/free. Quarantine survives until
     * these backend files undergo their genuine, possibly deferred release. */
    legacy = state->sessions[0];
    open = state->sessions[1];
    mutex_unlock(&state->transaction_lock);
    hybrid580_open_control_session_put_v1(open);
    hybrid580_legacy_control_session_put_v1(legacy);
    kvfree(state->catalog);
    kfree(state);
    return 0;
}

static int hybrid_front_release(struct inode *inode, struct file *front)
{
    int rc = hybrid_front_admission_enter_release();

    if (WARN_ON_ONCE(rc != 0))
        return rc;
    rc = hybrid_front_release_inner(inode, front);
    hybrid_front_admission_leave();
    return rc;
}

/* Intrusive root registry: root allocations are infrequent; lookup is linear
 * and bounded by 256 records. This is a resource bound, not a performance claim.
 * One opaque broker per client permits independent namespaces on the same pair
 * of genuine backend files. All records, including no-ID quarantine, remain
 * owned until known FREE success or final frontend close.
 */
static void hybrid_front_alloc(struct hybrid_front_file *state, void *packet, unsigned int size)
{
    struct hybrid_front_root *node;
    NV_STATUS *status = size == sizeof(NVOS21_PARAMETERS) ?
        &((NVOS21_PARAMETERS *)packet)->status : &((NVOS64_PARAMETERS *)packet)->status;
    if (state->quarantined) {
        *status = NV_ERR_INVALID_STATE;
        return;
    }
    if (state->root_count >= HYBRID_FRONT_MAX_ROOTS) {
        *status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    node = kzalloc(sizeof(*node), GFP_KERNEL);
    if (node == NULL) {
        *status = NV_ERR_NO_MEMORY;
        return;
    }
    if (size == sizeof(NVOS21_PARAMETERS))
        (void)hybrid_root_alloc_session(&node->root, state->endpoints, packet);
    else
        (void)hybrid_root_alloc_session64(&node->root, state->endpoints, packet);
    if (node->root.state == HYBRID_ROOT_EMPTY) {
        kfree(node);
        return;
    }
    node->next = state->roots;
    state->roots = node;
    ++state->root_count;
    if (node->root.state == HYBRID_ROOT_QUARANTINED)
        state->quarantined = true;
}

static struct hybrid_front_root *hybrid_front_find_root(
    struct hybrid_front_file *state, NvHandle root_handle)
{
    struct hybrid_front_root *root;

    for (root = state->roots; root != NULL; root = root->next)
        if (root->root.id == root_handle)
            return root;
    return NULL;
}

static struct hybrid_front_rm_object *hybrid_front_find_object(
    struct hybrid_front_root *root, NvHandle object_handle)
{
    struct hybrid_front_rm_object *object;

    if (root == NULL || object_handle == 0)
        return NULL;
    for (object = root->objects; object != NULL; object = object->next)
        if (object->handle == object_handle)
            return object;
    return NULL;
}

/* Resolve the exact owning RM from the tracked NV20_SUBDEVICE_0 handle. The
 * native command has a fixed-size, pointer-free payload and remains an
 * allowlisted route; command IDs or handles are never guessed from ranges. */
static long hybrid_front_gr_tpc_mask(
    struct hybrid_front_file *state, NVOS54_PARAMETERS *control,
    NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *subdevice, *device;
    struct hybrid580_control_session *session;
    NvU32 control_status = 0xffffffffU;
    NvHandle backend_root;
    NV_STATUS transport;

    if (state == NULL || control == NULL || params == NULL ||
        control->cmd != NV2080_CTRL_CMD_GR_GET_TPC_MASK ||
        control->flags != NVOS54_FLAGS_NONE ||
        control->paramsSize != sizeof(*params) || control->hClient == 0 ||
        control->hObject == 0) {
        if (control != NULL)
            control->status = NV_ERR_INVALID_ARGUMENT;
        return -EINVAL;
    }

    root = hybrid_front_find_root(state, control->hClient);
    if (state->quarantined || root == NULL ||
        root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != control->hClient ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != control->hClient) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    subdevice = hybrid_front_find_object(root, control->hObject);
    if (subdevice == NULL || subdevice->class_id != NV20_SUBDEVICE_0 ||
        subdevice->backend > HYBRID580_BACKEND_OPEN) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    device = hybrid_front_find_object(root, subdevice->parent_handle);
    if (device == NULL || device->class_id != NV01_DEVICE_0 ||
        device->backend != subdevice->backend ||
        subdevice->backend_parent_handle != device->backend_handle) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }

    backend_root = root->root.slot[subdevice->backend].handle;
    session = state->sessions[subdevice->backend];
    if (backend_root == 0 || backend_root != control->hClient || session == NULL) {
        control->status = NV_ERR_INVALID_STATE;
        return -EINVAL;
    }
    params->tpcMask = 0;
    if (subdevice->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_gr_tpc_mask_v1(
            session, backend_root, subdevice->backend_handle,
            control->flags, params, &control_status);
    else
        transport = hybrid580_open_control_session_gr_tpc_mask_v1(
            session, backend_root, subdevice->backend_handle,
            control->flags, params, &control_status);
    control->status = transport == NV_OK ? control_status : transport;
    return transport == NV_OK ? 0 : -EINVAL;
}

/* The observed V100 controls refer to frontend objects. Resolve every object
 * within this root and the P2P object's device, then substitute only backend
 * handles. This legacy-only path does not imply a Blackwell P2P capability. */
static long hybrid_front_p2p_control(
    struct hybrid_front_file *state, NVOS54_PARAMETERS *control, void *params,
    bool *backend_attempted, bool *transport_failed)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *p2p, *subdevice, *device;
    struct hybrid580_control_session *session;
    NvHandle backend_root;
    NvU32 control_status = NV_ERR_INVALID_ARGUMENT;
    NV_STATUS transport = NV_ERR_INVALID_ARGUMENT;

    if (backend_attempted != NULL)
        *backend_attempted = false;
    if (transport_failed != NULL)
        *transport_failed = false;
    if (state == NULL || control == NULL || params == NULL ||
        control->flags != NVOS54_FLAGS_NONE || control->hClient == 0 ||
        control->hObject == 0) {
        if (control != NULL)
            control->status = NV_ERR_INVALID_ARGUMENT;
        return -EINVAL;
    }
    root = hybrid_front_find_root(state, control->hClient);
    if (state->quarantined || root == NULL ||
        root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != control->hClient ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != control->hClient) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    p2p = hybrid_front_find_object(root, control->hObject);
    if (p2p == NULL || p2p->class_id != NV50_THIRD_PARTY_P2P ||
        p2p->backend != HYBRID580_BACKEND_LEGACY) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    subdevice = hybrid_front_find_object(root, p2p->parent_handle);
    if (subdevice == NULL || subdevice->class_id != NV20_SUBDEVICE_0 ||
        subdevice->backend != HYBRID580_BACKEND_LEGACY ||
        subdevice->backend_handle != p2p->backend_parent_handle) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    device = hybrid_front_find_object(root, subdevice->parent_handle);
    if (device == NULL || device->class_id != NV01_DEVICE_0 ||
        device->backend != HYBRID580_BACKEND_LEGACY ||
        device->backend_handle != subdevice->backend_parent_handle) {
        control->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return -EINVAL;
    }
    backend_root = root->root.slot[HYBRID580_BACKEND_LEGACY].handle;
    session = state->sessions[HYBRID580_BACKEND_LEGACY];
    if (backend_root == 0 || backend_root != control->hClient || session == NULL) {
        control->status = NV_ERR_INVALID_STATE;
        return -EINVAL;
    }

    switch (control->cmd) {
    case NV503C_CTRL_CMD_REGISTER_VA_SPACE: {
        NV503C_CTRL_REGISTER_VA_SPACE_PARAMS backend_params =
            *(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS *)params;
        struct hybrid_front_rm_object *vaspace =
            hybrid_front_find_object(root, backend_params.hVASpace);
        if (control->paramsSize != sizeof(backend_params) || vaspace == NULL ||
            vaspace->class_id != FERMI_VASPACE_A ||
            vaspace->backend != HYBRID580_BACKEND_LEGACY ||
            vaspace->parent_handle != device->handle ||
            vaspace->backend_parent_handle != device->backend_handle) {
            control->status = vaspace == NULL ? NV_ERR_INVALID_OBJECT_HANDLE :
                NV_ERR_INVALID_ARGUMENT;
            return -EINVAL;
        }
        if (p2p->p2p_registration_refs == ~(NvU32)0 ||
            vaspace->p2p_registration_refs == ~(NvU32)0) {
            control->status = NV_ERR_INSUFFICIENT_RESOURCES;
            return -EINVAL;
        }
        backend_params.hVASpace = vaspace->backend_handle;
        if (backend_attempted != NULL)
            *backend_attempted = true;
        transport = hybrid580_legacy_control_session_p2p_register_va_space_v1(
            session, backend_root, p2p->backend_handle, &backend_params,
            &control_status);
        if (transport == NV_OK && control_status == NV_OK) {
            ++p2p->p2p_registration_refs;
            ++vaspace->p2p_registration_refs;
            *(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS *)params = backend_params;
        }
        break;
    }
    case NV503C_CTRL_CMD_UNREGISTER_VA_SPACE: {
        NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS backend_params =
            *(NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS *)params;
        struct hybrid_front_rm_object *vaspace =
            hybrid_front_find_object(root, backend_params.hVASpace);
        if (control->paramsSize != sizeof(backend_params) || vaspace == NULL ||
            vaspace->class_id != FERMI_VASPACE_A ||
            vaspace->backend != HYBRID580_BACKEND_LEGACY ||
            vaspace->parent_handle != device->handle ||
            vaspace->backend_parent_handle != device->backend_handle) {
            control->status = vaspace == NULL ? NV_ERR_INVALID_OBJECT_HANDLE :
                NV_ERR_INVALID_ARGUMENT;
            return -EINVAL;
        }
        if (p2p->p2p_registration_refs == 0 ||
            vaspace->p2p_registration_refs == 0) {
            control->status = NV_ERR_INVALID_STATE;
            return -EINVAL;
        }
        backend_params.hVASpace = vaspace->backend_handle;
        if (backend_attempted != NULL)
            *backend_attempted = true;
        transport = hybrid580_legacy_control_session_p2p_unregister_va_space_v1(
            session, backend_root, p2p->backend_handle, &backend_params,
            &control_status);
        if (transport == NV_OK && control_status == NV_OK) {
            --p2p->p2p_registration_refs;
            --vaspace->p2p_registration_refs;
        }
        break;
    }
    case NV503C_CTRL_CMD_REGISTER_VIDMEM: {
        NV503C_CTRL_REGISTER_VIDMEM_PARAMS backend_params =
            *(NV503C_CTRL_REGISTER_VIDMEM_PARAMS *)params;
        struct hybrid_front_rm_object *memory =
            hybrid_front_find_object(root, backend_params.hMemory);
        const NvU64 max_u64 = ~(NvU64)0;
        if (control->paramsSize != sizeof(backend_params) || memory == NULL ||
            memory->class_id != NV01_MEMORY_LOCAL_USER ||
            memory->backend != HYBRID580_BACKEND_LEGACY ||
            memory->parent_handle != device->handle ||
            memory->backend_parent_handle != device->backend_handle) {
            control->status = memory == NULL ? NV_ERR_INVALID_OBJECT_HANDLE :
                NV_ERR_INVALID_ARGUMENT;
            return -EINVAL;
        }
        if (backend_params.size == 0 ||
            ((backend_params.address | backend_params.size |
              backend_params.offset) & 0xffffULL) != 0 ||
            backend_params.address > max_u64 - backend_params.size ||
            backend_params.offset > max_u64 - backend_params.size) {
            control->status = NV_ERR_INVALID_ARGUMENT;
            return -EINVAL;
        }
        if (p2p->p2p_registration_refs == ~(NvU32)0 ||
            memory->p2p_registration_refs == ~(NvU32)0) {
            control->status = NV_ERR_INSUFFICIENT_RESOURCES;
            return -EINVAL;
        }
        backend_params.hMemory = memory->backend_handle;
        if (backend_attempted != NULL)
            *backend_attempted = true;
        transport = hybrid580_legacy_control_session_p2p_register_vidmem_v1(
            session, backend_root, p2p->backend_handle, &backend_params,
            &control_status);
        if (transport == NV_OK && control_status == NV_OK) {
            ++p2p->p2p_registration_refs;
            ++memory->p2p_registration_refs;
        }
        break;
    }
    case NV503C_CTRL_CMD_UNREGISTER_VIDMEM: {
        NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS backend_params =
            *(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS *)params;
        struct hybrid_front_rm_object *memory =
            hybrid_front_find_object(root, backend_params.hMemory);
        if (control->paramsSize != sizeof(backend_params) || memory == NULL ||
            memory->class_id != NV01_MEMORY_LOCAL_USER ||
            memory->backend != HYBRID580_BACKEND_LEGACY ||
            memory->parent_handle != device->handle ||
            memory->backend_parent_handle != device->backend_handle) {
            control->status = memory == NULL ? NV_ERR_INVALID_OBJECT_HANDLE :
                NV_ERR_INVALID_ARGUMENT;
            return -EINVAL;
        }
        if (p2p->p2p_registration_refs == 0 ||
            memory->p2p_registration_refs == 0) {
            control->status = NV_ERR_INVALID_STATE;
            return -EINVAL;
        }
        backend_params.hMemory = memory->backend_handle;
        if (backend_attempted != NULL)
            *backend_attempted = true;
        transport = hybrid580_legacy_control_session_p2p_unregister_vidmem_v1(
            session, backend_root, p2p->backend_handle, &backend_params,
            &control_status);
        if (transport == NV_OK && control_status == NV_OK) {
            --p2p->p2p_registration_refs;
            --memory->p2p_registration_refs;
        }
        break;
    }
    default:
        control->status = NV_ERR_NOT_SUPPORTED;
        return -ENOTTY;
    }

    if (transport != NV_OK && transport_failed != NULL)
        *transport_failed = true;
    control->status = transport == NV_OK ? control_status : transport;
    return transport == NV_OK ? 0 : -EINVAL;
}

/* Adapt the legacy V1 build-version ABI without passing its three user
 * pointers into RM. R580 already implements V1 in terms of pointer-free V2;
 * preserve the observed null-pointer size query, exact NUL-inclusive sizing,
 * and changelist publication only after all three string copies succeed. */
static long hybrid_front_build_version_ioctl(struct hybrid_front_file *state,
                                               unsigned int command,
                                               unsigned long argument)
{
    NVOS54_PARAMETERS control;
    NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS params;
    NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *result = NULL;
    nv_ioctl_xfer_t xfer;
    struct hybrid_front_root *root;
    struct hybrid580_control_session *session = NULL;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    void __user *driver_user, *version_user, *title_user;
    NvU32 control_status = 0xffffffffU;
    size_t driver_length, version_length, title_length, max_length;
    unsigned int number = _IOC_NR(command);
    NV_STATUS transport = NV_ERR_INVALID_STATE;
    long rc = 0;
    int lock_rc;

    if (state == NULL || _IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        if (_IOC_SIZE(command) != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        if (user_control == NULL)
            return -EINVAL;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, sizeof(control)))
        return -EFAULT;
    if (control.cmd != NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION ||
        control.flags != NVOS54_FLAGS_NONE ||
        control.paramsSize != sizeof(params) || control.hClient == 0 ||
        control.hObject != control.hClient || NvP64_VALUE(control.params) == NULL)
        return -EINVAL;

    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, sizeof(params)))
        return -EFAULT;
    driver_user = (void __user *)NvP64_VALUE(params.pDriverVersionBuffer);
    version_user = (void __user *)NvP64_VALUE(params.pVersionBuffer);
    title_user = (void __user *)NvP64_VALUE(params.pTitleBuffer);

    lock_rc = mutex_lock_interruptible(&state->transaction_lock);
    if (lock_rc != 0)
        return lock_rc;
    result = kzalloc(sizeof(*result), GFP_KERNEL);
    if (result == NULL) {
        control.status = NV_ERR_NO_MEMORY;
    } else {
        root = hybrid_front_find_root(state, control.hClient);
        if (state->quarantined || root == NULL ||
            root->root.state != HYBRID_ROOT_ACTIVE ||
            root->root.slot[HYBRID580_BACKEND_LEGACY].handle != control.hClient ||
            root->root.slot[HYBRID580_BACKEND_OPEN].handle != control.hClient) {
            control.status = NV_ERR_INVALID_OBJECT_HANDLE;
            rc = -EINVAL;
        } else if (state->sessions[HYBRID580_BACKEND_OPEN] == NULL) {
            control.status = NV_ERR_INVALID_STATE;
            rc = -EINVAL;
        } else {
            session = state->sessions[HYBRID580_BACKEND_OPEN];
            transport = hybrid580_open_control_session_build_version_v1(
                session, root->root.slot[HYBRID580_BACKEND_OPEN].handle,
                root->root.slot[HYBRID580_BACKEND_OPEN].handle,
                NVOS54_FLAGS_NONE, result, &control_status);
            if (transport != NV_OK) {
                control.status = transport;
                rc = -EINVAL;
            } else if (control_status == 0xffffffffU) {
                /* A provider that did not publish RM status is never success. */
                control.status = NV_ERR_INVALID_STATE;
            } else {
                control.status = control_status;
            }
        }
    }
    mutex_unlock(&state->transaction_lock);

    if (rc == 0 && control.status == NV_OK) {
        driver_length = strnlen(result->driverVersionBuffer,
            sizeof(result->driverVersionBuffer));
        version_length = strnlen(result->versionBuffer,
            sizeof(result->versionBuffer));
        title_length = strnlen(result->titleBuffer,
            sizeof(result->titleBuffer));
        if (driver_length == sizeof(result->driverVersionBuffer) ||
            version_length == sizeof(result->versionBuffer) ||
            title_length == sizeof(result->titleBuffer)) {
            control.status = NV_ERR_INVALID_PARAM_STRUCT;
        } else {
            ++driver_length;
            ++version_length;
            ++title_length;
            max_length = driver_length;
            if (version_length > max_length)
                max_length = version_length;
            if (title_length > max_length)
                max_length = title_length;

            /* Historical V1 treats any missing buffer as a sizing query and
             * does not touch the other buffers or changelist fields. */
            if (driver_user == NULL || version_user == NULL || title_user == NULL) {
                params.sizeOfStrings = (NvU32)max_length;
            } else if (params.sizeOfStrings < max_length) {
                control.status = NV_ERR_INVALID_PARAM_STRUCT;
            } else if (copy_to_user(driver_user, result->driverVersionBuffer,
                                    driver_length) ||
                       copy_to_user(version_user, result->versionBuffer,
                                    version_length) ||
                       copy_to_user(title_user, result->titleBuffer,
                                    title_length)) {
                control.status = NV_ERR_INVALID_PARAM_STRUCT;
            } else {
                params.changelistNumber = result->changelistNumber;
                params.officialChangelistNumber =
                    result->officialChangelistNumber;
            }
        }
    }

    kfree(result);
    if (copy_to_user(user_params, &params, sizeof(params)))
        return -EFAULT;
    if (copy_to_user(user_control, &control, sizeof(control)))
        return -EFAULT;
    return rc;
}

static long hybrid_front_p2p_control_ioctl(struct hybrid_front_file *state,
                                            unsigned int command,
                                            unsigned long argument)
{
    union {
        NV503C_CTRL_REGISTER_VA_SPACE_PARAMS register_va_space;
        NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS unregister_va_space;
        NV503C_CTRL_REGISTER_VIDMEM_PARAMS register_vidmem;
        NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS unregister_vidmem;
    } params;
    NVOS54_PARAMETERS control;
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    size_t params_size;
    unsigned int number = _IOC_NR(command);
    long rc;
    int lock_rc;
    bool backend_attempted = false, transport_failed = false;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        if (_IOC_SIZE(command) != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, sizeof(control)))
        return -EFAULT;
    switch (control.cmd) {
    case NV503C_CTRL_CMD_REGISTER_VA_SPACE:
        params_size = sizeof(params.register_va_space);
        break;
    case NV503C_CTRL_CMD_UNREGISTER_VA_SPACE:
        params_size = sizeof(params.unregister_va_space);
        break;
    case NV503C_CTRL_CMD_REGISTER_VIDMEM:
        params_size = sizeof(params.register_vidmem);
        break;
    case NV503C_CTRL_CMD_UNREGISTER_VIDMEM:
        params_size = sizeof(params.unregister_vidmem);
        break;
    /* The dispatcher keeps the observed PID-registration control denied. */
    case NV503C_CTRL_CMD_REGISTER_PID:
    default:
        return -ENOTTY;
    }
    if (control.flags != NVOS54_FLAGS_NONE ||
        control.paramsSize != params_size || control.hClient == 0 ||
        control.hObject == 0 || NvP64_VALUE(control.params) == NULL)
        return -EINVAL;
    memset(&params, 0, sizeof(params));
    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, params_size))
        return -EFAULT;

    lock_rc = mutex_lock_interruptible(&state->transaction_lock);
    if (lock_rc != 0)
        return lock_rc;
    rc = hybrid_front_p2p_control(state, &control, &params,
                                  &backend_attempted, &transport_failed);
    if (transport_failed)
        state->quarantined = true;
    if (copy_to_user(user_params, &params, params_size)) {
        if (backend_attempted)
            state->quarantined = true;
        rc = -EFAULT;
    }
    if (copy_to_user(user_control, &control, sizeof(control))) {
        if (backend_attempted)
            state->quarantined = true;
        rc = -EFAULT;
    }
    mutex_unlock(&state->transaction_lock);
    return rc;
}

static long hybrid_front_gr_tpc_mask_ioctl(struct hybrid_front_file *state,
                                            unsigned int command,
                                            unsigned long argument)
{
    NVOS54_PARAMETERS control;
    NV2080_CTRL_GR_GET_TPC_MASK_PARAMS params;
    nv_ioctl_xfer_t xfer;
    void __user *user = (void __user *)argument;
    void __user *user_control = user;
    void __user *user_params;
    size_t size;
    unsigned int number = _IOC_NR(command);
    long rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
        return -EINVAL;
    if (number == NV_ESC_RM_CONTROL) {
        size = _IOC_SIZE(command);
        if (size != sizeof(control))
            return -EINVAL;
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_RM_CONTROL)
            return -ENOTTY;
        if (xfer.size != sizeof(control))
            return -EINVAL;
        user_control = (void __user *)NvP64_VALUE(xfer.ptr);
        size = xfer.size;
    } else {
        return -ENOTTY;
    }
    if (copy_from_user(&control, user_control, size))
        return -EFAULT;
    if (control.cmd != NV2080_CTRL_CMD_GR_GET_TPC_MASK ||
        control.flags != NVOS54_FLAGS_NONE ||
        control.paramsSize != sizeof(params) ||
        NvP64_VALUE(control.params) == NULL)
        return -ENOTTY;
    user_params = (void __user *)NvP64_VALUE(control.params);
    if (copy_from_user(&params, user_params, sizeof(params)))
        return -EFAULT;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    rc = hybrid_front_gr_tpc_mask(state, &control, &params);
    mutex_unlock(&state->transaction_lock);

    if (copy_to_user(user_params, &params, sizeof(params)))
        return -EFAULT;
    if (copy_to_user(user_control, &control, sizeof(control)))
        return -EFAULT;
    return rc;
}

/* Bridge one class-typed NV01_DEVICE_0 request. Outer and nested packets are
 * copied into kernel memory before entry. deviceId is translated from the
 * frontend's BDF-ordered namespace to the owning RM's local instance. */
static void hybrid_front_device_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    const NV0080_ALLOC_PARAMETERS *user_params)
{
    struct hybrid_front_root *root;
    struct hybrid580_device_instance_entry_v1 instance;
    struct hybrid_front_rm_object *device;
    NV0080_ALLOC_PARAMETERS params;
    NvHandle backend_root, returned_device = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport, status;
    int rc;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || user_params == NULL ||
        packet->hRoot == 0 || packet->hObjectParent != packet->hRoot ||
        packet->hObjectNew == 0 || packet->hClass != NV01_DEVICE_0 ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*user_params)) ||
        (user_params->hClientShare != 0 &&
         user_params->hClientShare != packet->hRoot) ||
        user_params->hTargetClient != 0 || user_params->hTargetDevice != 0)
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    status = hybrid_front_device_instance_map(state, root, &root->device_map);
    if (status != NV_OK) {
        packet->status = status;
        return;
    }
    rc = hybrid580_device_instance_map_lookup_front_v1(
        &root->device_map, user_params->deviceId, &instance);
    if (rc != 0 || instance.backend > HYBRID580_BACKEND_OPEN) {
        packet->status = rc == -ENOENT ? NV_ERR_INVALID_ARGUMENT :
            NV_ERR_INVALID_STATE;
        return;
    }

    device = kzalloc(sizeof(*device), GFP_KERNEL);
    if (device == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    params = *user_params;
    params.deviceId = instance.backend_device_instance;
    backend_root = root->root.slot[instance.backend].handle;
    if (instance.backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_device_alloc_v1(
            state->sessions[instance.backend], backend_root,
            packet->hObjectNew, &params, &returned_device, &rm_status);
    else
        transport = hybrid580_open_control_session_device_alloc_v1(
            state->sessions[instance.backend], backend_root,
            packet->hObjectNew, &params, &returned_device, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_device != packet->hObjectNew) {
        /* A child may exist even when transport/status/output disagree. Do
         * not guess a FREE; retain the backend ROOT until genuine file close. */
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(device);
        return;
    }

    device->handle = packet->hObjectNew;
    device->backend_handle = returned_device;
    device->parent_handle = packet->hObjectParent;
    device->backend_parent_handle = backend_root;
    device->class_id = NV01_DEVICE_0;
    device->backend = instance.backend;
    device->backend_device_instance = instance.backend_device_instance;
    device->next = root->objects;
    root->objects = device;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* NV20_SUBDEVICE_0 is the typed RM object used by the observed GR controls.
 * This frontend has one physical subdevice per PCI GPU, so it accepts only
 * subDeviceId 0 and binds the child to its tracked NV01_DEVICE_0 backend. */
static void hybrid_front_subdevice_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    const NV2080_ALLOC_PARAMETERS *user_params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *object;
    NvHandle backend_root, returned_subdevice = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || user_params == NULL || packet->hRoot == 0 ||
        packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        packet->hClass != NV20_SUBDEVICE_0 || user_params->subDeviceId != 0 ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*user_params)))
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV01_DEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN ||
        parent->backend_parent_handle != root->root.slot[parent->backend].handle) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[parent->backend].handle;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_subdevice_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, user_params,
            &returned_subdevice, &rm_status);
    else
        transport = hybrid580_open_control_session_subdevice_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, user_params,
            &returned_subdevice, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_subdevice != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_subdevice;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->class_id = NV20_SUBDEVICE_0;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* NV2081_BINAPI is the observed common child of NV20_SUBDEVICE_0 on both
 * installed driver branches. Its SDK payload is one reserved word; accept
 * only zero and allow the SDK's optional omitted-payload form. */
static void hybrid_front_binapi_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    const NV2081_ALLOC_PARAMETERS *user_params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *object;
    NvHandle backend_root, returned_binapi = 0;
    NV2081_ALLOC_PARAMETERS empty_params = { 0 };
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || packet->hRoot == 0 || packet->hObjectParent == 0 ||
        packet->hObjectNew == 0 || packet->hClass != NV2081_BINAPI ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 &&
         packet->paramsSize != sizeof(NV2081_ALLOC_PARAMETERS)) ||
        (packet->paramsSize == sizeof(NV2081_ALLOC_PARAMETERS) &&
         user_params == NULL) ||
        (user_params != NULL && user_params->reserved != 0))
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV20_SUBDEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[parent->backend].handle;
    if (user_params == NULL)
        user_params = &empty_params;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_binapi_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, user_params,
            &returned_binapi, &rm_status);
    else
        transport = hybrid580_open_control_session_binapi_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, user_params,
            &returned_binapi, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_binapi != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_binapi;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->class_id = NV2081_BINAPI;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* RM_USER_SHARED_DATA is an observed fixed-size child of a subdevice. Preserve
 * every bit of its 64-bit polledDataMask and keep the object on that parent's
 * RM; controls on this class remain denied until separately observed. */
static void hybrid_front_rusd_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    const NV00DE_ALLOC_PARAMETERS *user_params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *object;
    NvHandle backend_root, returned_rusd = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || user_params == NULL || packet->hRoot == 0 ||
        packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        packet->hClass != RM_USER_SHARED_DATA ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 &&
         packet->paramsSize != sizeof(NV00DE_ALLOC_PARAMETERS)))
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV20_SUBDEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[parent->backend].handle;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_rusd_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, user_params,
            &returned_rusd, &rm_status);
    else
        transport = hybrid580_open_control_session_rusd_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, user_params,
            &returned_rusd, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_rusd != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_rusd;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->class_id = RM_USER_SHARED_DATA;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* The installed R580 V100 CUDA probe allocated this class once with the
 * fixed BAR1 type. Keep that observed child on the Volta proprietary RM;
 * cross-backend or unmeasured P2P modes are intentionally rejected. */
static void hybrid_front_p2p_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    const NV503C_ALLOC_PARAMETERS *user_params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *object;
    NvHandle backend_root, returned_p2p = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || packet->hRoot == 0 || packet->hObjectParent == 0 ||
        packet->hObjectNew == 0 || packet->hClass != NV50_THIRD_PARTY_P2P ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 &&
         packet->paramsSize != sizeof(NV503C_ALLOC_PARAMETERS)) ||
        user_params == NULL ||
        user_params->flags != NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1)
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV20_SUBDEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (parent->backend != HYBRID580_BACKEND_LEGACY) {
        packet->status = NV_ERR_NOT_SUPPORTED;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[HYBRID580_BACKEND_LEGACY].handle;
    transport = hybrid580_legacy_control_session_p2p_alloc_v1(
        state->sessions[HYBRID580_BACKEND_LEGACY], backend_root,
        parent->backend_handle, packet->hObjectNew, packet->paramsSize, user_params,
        &returned_p2p, &rm_status);
    if (transport != NV_OK || rm_status != NV_OK ||
        returned_p2p != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_p2p;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->class_id = NV50_THIRD_PARTY_P2P;
    object->backend = HYBRID580_BACKEND_LEGACY;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* The installed-driver fixed-header captures place VOLTA_USERMODE_A on the
 * V100 backend and HOPPER_USERMODE_A on Blackwell. These objects back the
 * architecture-specific usermode doorbell mapping. Hopper parameters are
 * optional in R580 but, when present, are copied into a fixed kernel buffer;
 * privileged mappings remain outside this non-privileged bridge. */
static void hybrid_front_usermode_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    const NV_HOPPER_USERMODE_A_PARAMS *user_params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *object;
    NvHandle backend_root, returned_usermode = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;
    unsigned int expected_backend;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || packet->hRoot == 0 || packet->hObjectParent == 0 ||
        packet->hObjectNew == 0 || packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->hClass != VOLTA_USERMODE_A &&
         packet->hClass != HOPPER_USERMODE_A) ||
        (packet->hClass == VOLTA_USERMODE_A && user_params != NULL) ||
        (user_params != NULL &&
         ((user_params->bBar1Mapping != NV_FALSE &&
           user_params->bBar1Mapping != NV_TRUE) ||
          user_params->bPriv != NV_FALSE)))
        return;

    expected_backend = packet->hClass == VOLTA_USERMODE_A ?
        HYBRID580_BACKEND_LEGACY : HYBRID580_BACKEND_OPEN;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV20_SUBDEVICE_0 ||
        parent->backend != expected_backend) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[parent->backend].handle;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_usermode_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, packet->hClass,
            user_params, &returned_usermode, &rm_status);
    else
        transport = hybrid580_open_control_session_usermode_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, packet->hClass,
            user_params, &returned_usermode, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_usermode != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_usermode;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->class_id = packet->hClass;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* The VASPACE object is a typed R580 RM resource. Internal-only ownership
 * modes and pointer-independent fields outside this frontend's manager are
 * rejected before either backend sees the allocation. */
static bool hybrid_front_vaspace_params_valid(
    const NV_VASPACE_ALLOCATION_PARAMETERS *params)
{
    NvU32 flags;

    if (params == NULL)
        return false;
    flags = (NvU32)params->flags;
    return params->index < NV_VASPACE_ALLOCATION_INDEX_GPU_MAX &&
        (flags & ~0x7fffU) == 0 &&
        (flags & (NV_VASPACE_ALLOCATION_FLAGS_SHARED_MANAGEMENT |
                  NV_VASPACE_ALLOCATION_FLAGS_IS_EXTERNALLY_OWNED |
                  NV_VASPACE_ALLOCATION_FLAGS_VA_INTERNAL_LIMIT |
                  NV_VASPACE_ALLOCATION_FLAGS_ENABLE_NVLINK_ATS_TEST)) == 0 &&
        params->vaStartInternal == 0 && params->vaLimitInternal == 0 &&
        params->pasid == 0 &&
        (params->bigPageSize == 0 ||
         params->bigPageSize == NV_VASPACE_BIG_PAGE_SIZE_64K ||
         params->bigPageSize == NV_VASPACE_BIG_PAGE_SIZE_128K);
}

/* Bridge a tracked FERMI_VASPACE_A child. Parameters are copied by the
 * ioctl boundary and contain no userspace pointers. RM outputs are copied back
 * only after the backend has received its own typed kernel buffer. */
static void hybrid_front_vaspace_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    NV_VASPACE_ALLOCATION_PARAMETERS *params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *object;
    NvHandle backend_root, returned_vaspace = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || params == NULL || packet->hRoot == 0 ||
        packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        packet->hClass != FERMI_VASPACE_A ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*params)) ||
        !hybrid_front_vaspace_params_valid(params))
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV01_DEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[parent->backend].handle;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_vaspace_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, params,
            &returned_vaspace, &rm_status);
    else
        transport = hybrid580_open_control_session_vaspace_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, params,
            &returned_vaspace, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_vaspace != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_vaspace;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->class_id = FERMI_VASPACE_A;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* KEPLER_CHANNEL_GROUP_A is common to the observed R580/V100 and R595/
 * Blackwell class graphs. Its hVASpace and optional notifier handles live in
 * the public frontend namespace; resolve all of them to the selected RM and
 * retain references so a VASpace/notifier cannot be freed while a TSG uses it.
 */
static void hybrid_front_channel_group_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *vaspace, *error = NULL, *ecc_error = NULL;
    struct hybrid_front_rm_object *object;
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS backend_params;
    NvHandle backend_root, frontend_vaspace, frontend_error, frontend_ecc_error;
    NvHandle returned_group = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || params == NULL || packet->hRoot == 0 ||
        packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        packet->hClass != KEPLER_CHANNEL_GROUP_A ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*params)) ||
        params->hVASpace == 0 ||
        params->bIsCallingContextVgpuPlugin != NV_FALSE)
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV01_DEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    frontend_vaspace = params->hVASpace;
    vaspace = hybrid_front_find_object(root, frontend_vaspace);
    if (vaspace == NULL || vaspace->class_id != FERMI_VASPACE_A ||
        vaspace->parent_handle != packet->hObjectParent ||
        vaspace->backend != parent->backend ||
        vaspace->backend_parent_handle != parent->backend_handle) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    frontend_error = params->hObjectError;
    if (frontend_error != 0) {
        error = hybrid_front_find_object(root, frontend_error);
        if (error == NULL ||
            (error->class_id != NV01_MEMORY_SYSTEM &&
             error->class_id != NV01_MEMORY_LOCAL_USER) ||
            error->parent_handle != packet->hObjectParent ||
            error->backend != parent->backend ||
            error->backend_parent_handle != parent->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    frontend_ecc_error = params->hObjectEccError;
    if (frontend_ecc_error != 0) {
        ecc_error = hybrid_front_find_object(root, frontend_ecc_error);
        if (ecc_error == NULL ||
            (ecc_error->class_id != NV01_MEMORY_SYSTEM &&
             ecc_error->class_id != NV01_MEMORY_LOCAL_USER) ||
            ecc_error->parent_handle != packet->hObjectParent ||
            ecc_error->backend != parent->backend ||
            ecc_error->backend_parent_handle != parent->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }

    backend_params = *params;
    backend_params.hVASpace = vaspace->backend_handle;
    if (error != NULL)
        backend_params.hObjectError = error->backend_handle;
    if (ecc_error != NULL)
        backend_params.hObjectEccError = ecc_error->backend_handle;
    backend_root = root->root.slot[parent->backend].handle;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_channel_group_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, &backend_params,
            &returned_group, &rm_status);
    else
        transport = hybrid580_open_control_session_channel_group_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, &backend_params,
            &returned_group, &rm_status);
    *params = backend_params;
    params->hVASpace = frontend_vaspace;
    params->hObjectError = frontend_error;
    params->hObjectEccError = frontend_ecc_error;

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_group != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_group;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->vaspace_handle = frontend_vaspace;
    object->error_object_handle = frontend_error;
    object->ecc_error_object_handle = frontend_ecc_error;
    object->class_id = KEPLER_CHANNEL_GROUP_A;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

static bool hybrid_front_context_share_params_valid(
    const NV_CTXSHARE_ALLOCATION_PARAMETERS *params)
{
    if (params == NULL || (params->flags & ~0x3U) != 0)
        return false;
    if (params->flags == NV_CTXSHARE_ALLOCATION_FLAGS_SUBCONTEXT_SPECIFIED)
        return (params->subctxId & 0x80000000U) == 0;
    return params->subctxId == 0;
}

/* FERMI_CONTEXT_SHARE_A is a channel-group child that shares the group's
 * VASpace. Translate the handle to the owning RM and retain both the parent
 * edge and the VASpace reference for ordered teardown. */
static void hybrid_front_context_share_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    NV_CTXSHARE_ALLOCATION_PARAMETERS *params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *group, *vaspace, *device, *object;
    NV_CTXSHARE_ALLOCATION_PARAMETERS backend_params;
    NvHandle backend_root, frontend_vaspace;
    NvHandle returned_context_share = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || !hybrid_front_context_share_params_valid(params) ||
        packet->hRoot == 0 || packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        packet->hClass != FERMI_CONTEXT_SHARE_A ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*params)) ||
        params->hVASpace == 0)
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    group = hybrid_front_find_object(root, packet->hObjectParent);
    if (group == NULL || group->class_id != KEPLER_CHANNEL_GROUP_A ||
        group->backend > HYBRID580_BACKEND_OPEN || group->vaspace_handle == 0 ||
        group->vaspace_handle != params->hVASpace) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    device = hybrid_front_find_object(root, group->parent_handle);
    vaspace = hybrid_front_find_object(root, group->vaspace_handle);
    if (device == NULL || device->class_id != NV01_DEVICE_0 ||
        device->backend != group->backend ||
        device->backend_handle != group->backend_parent_handle ||
        vaspace == NULL || vaspace->class_id != FERMI_VASPACE_A ||
        vaspace->parent_handle != device->handle ||
        vaspace->backend != group->backend ||
        vaspace->backend_parent_handle != device->backend_handle) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }

    frontend_vaspace = params->hVASpace;
    backend_params = *params;
    backend_params.hVASpace = vaspace->backend_handle;
    backend_root = root->root.slot[group->backend].handle;
    if (group->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_context_share_alloc_v1(
            state->sessions[group->backend], backend_root,
            group->backend_handle, packet->hObjectNew, &backend_params,
            &returned_context_share, &rm_status);
    else
        transport = hybrid580_open_control_session_context_share_alloc_v1(
            state->sessions[group->backend], backend_root,
            group->backend_handle, packet->hObjectNew, &backend_params,
            &returned_context_share, &rm_status);
    *params = backend_params;
    params->hVASpace = frontend_vaspace;

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_context_share != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_context_share;
    object->parent_handle = group->handle;
    object->backend_parent_handle = group->backend_handle;
    object->vaspace_handle = frontend_vaspace;
    object->class_id = FERMI_CONTEXT_SHARE_A;
    object->backend = group->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

static bool hybrid_front_channel_memory_desc_zero(
    const NV_MEMORY_DESC_PARAMS *desc)
{
    return desc->base == 0 && desc->size == 0 &&
        desc->addressSpace == 0 && desc->cacheAttrib == 0;
}

/* These fields are private/internal inputs or output-only memory descriptors.
 * The installed R580 and R595 channel captures have them clear at both ends. */
static bool hybrid_front_channel_internal_fields_zero(
    const NV_CHANNEL_ALLOC_PARAMS *params)
{
    NvU32 i;

    if (params->hObjectEccError != 0 || params->hPhysChannelGroup != 0 ||
        params->internalFlags != 0 || params->ProcessID != 0 ||
        params->SubProcessID != 0 || params->tpcConfigID != 0 ||
        !hybrid_front_channel_memory_desc_zero(&params->instanceMem) ||
        !hybrid_front_channel_memory_desc_zero(&params->userdMem) ||
        !hybrid_front_channel_memory_desc_zero(&params->ramfcMem) ||
        !hybrid_front_channel_memory_desc_zero(&params->mthdbufMem) ||
        !hybrid_front_channel_memory_desc_zero(&params->errorNotifierMem) ||
        !hybrid_front_channel_memory_desc_zero(&params->eccErrorNotifierMem))
        return false;
    for (i = 0; i < CC_CHAN_ALLOC_IV_SIZE_DWORD; ++i)
        if (params->encryptIv[i] != 0 || params->decryptIv[i] != 0)
            return false;
    for (i = 0; i < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; ++i)
        if (params->hmacNonce[i] != 0)
            return false;
    return true;
}

/* The R580 V100 and R595 RTX5080 captures exercise physical channels with
 * flags 0 and, on Blackwell, GROUP_CHANNEL_RUNQUEUE=ONE (wire bit 4). Keep
 * unobserved options closed: several other bits are reserved for kernel,
 * vGPU, protected-memory or internal allocation policy. */
static bool hybrid_front_channel_flags_valid(NvU32 flags)
{
    const NvU32 runqueue_one =
        (NvU32)NVOS04_FLAGS_GROUP_CHANNEL_RUNQUEUE_ONE << 4U;
    const NvU32 allowed_mask = 0x3U | runqueue_one;

    return (flags & 0x3U) == NVOS04_FLAGS_CHANNEL_TYPE_PHYSICAL &&
        (flags & ~allowed_mask) == 0;
}

struct hybrid_front_channel_handle_refs {
    NvHandle error;
    NvHandle buffer;
    NvHandle context_share;
    NvHandle vaspace;
    NvHandle userd[NV_MAX_SUBDEVICES];
};

static bool hybrid_front_channel_backend_handles_match(
    const NV_CHANNEL_ALLOC_PARAMS *actual,
    const struct hybrid_front_channel_handle_refs *frontend,
    struct hybrid_front_root *root, NvHandle expected_error,
    NvHandle expected_buffer, NvHandle expected_context_share)
{
    struct hybrid_front_rm_object *userd;
    NvU32 i;

    if (actual->hObjectError != expected_error ||
        actual->hObjectBuffer != expected_buffer ||
        actual->hContextShare != expected_context_share ||
        actual->hVASpace != 0 || actual->hObjectEccError != 0 ||
        actual->hPhysChannelGroup != 0)
        return false;
    for (i = 0; i < NV_MAX_SUBDEVICES; ++i) {
        if (frontend->userd[i] == 0) {
            if (actual->hUserdMemory[i] != 0)
                return false;
            continue;
        }
        userd = hybrid_front_find_object(root, frontend->userd[i]);
        if (userd == NULL || actual->hUserdMemory[i] != userd->backend_handle)
            return false;
    }
    return true;
}

/* Bridge the two observed physical GPFIFO classes. Volta is routed only to
 * the proprietary backend and Blackwell only to the Open backend. A channel
 * is a TSG child: its VASpace comes from the tracked group, so explicit
 * hVASpace, ECC/physical-group handles, and private RM fields are rejected. */
static void hybrid_front_channel_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    NV_CHANNEL_ALLOC_PARAMS *params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *group, *device, *error = NULL;
    struct hybrid_front_rm_object *buffer = NULL, *share = NULL, *userd;
    struct hybrid_front_rm_object *object;
    struct hybrid_front_channel_handle_refs frontend_handles;
    NV_CHANNEL_ALLOC_PARAMS backend_params;
    NvHandle backend_root, returned_channel = 0;
    NvU32 rm_status = 0xffffffffU, i;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || params == NULL || packet->hRoot == 0 ||
        packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        (packet->hClass != VOLTA_CHANNEL_GPFIFO_A &&
         packet->hClass != BLACKWELL_CHANNEL_GPFIFO_A) ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*params)) ||
        params->hVASpace != 0 ||
        !hybrid_front_channel_flags_valid(params->flags) ||
        !hybrid_front_channel_internal_fields_zero(params))
        return;
    for (i = 0; i < NV_MAX_SUBDEVICES; ++i)
        if (params->hUserdMemory[i] == 0 && params->userdOffset[i] != 0)
            return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    group = hybrid_front_find_object(root, packet->hObjectParent);
    if (group == NULL || group->class_id != KEPLER_CHANNEL_GROUP_A ||
        group->backend > HYBRID580_BACKEND_OPEN ||
        (group->backend == HYBRID580_BACKEND_LEGACY &&
         packet->hClass != VOLTA_CHANNEL_GPFIFO_A) ||
        (group->backend == HYBRID580_BACKEND_OPEN &&
         packet->hClass != BLACKWELL_CHANNEL_GPFIFO_A)) {
        packet->status = group == NULL ? NV_ERR_INVALID_OBJECT_HANDLE :
            NV_ERR_INVALID_CLASS;
        return;
    }
    device = hybrid_front_find_object(root, group->parent_handle);
    if (device == NULL || device->class_id != NV01_DEVICE_0 ||
        device->backend != group->backend ||
        device->backend_handle != group->backend_parent_handle ||
        group->vaspace_handle == 0) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    {
        struct hybrid_front_rm_object *vaspace =
            hybrid_front_find_object(root, group->vaspace_handle);
        if (vaspace == NULL || vaspace->class_id != FERMI_VASPACE_A ||
            vaspace->parent_handle != device->handle ||
            vaspace->backend != group->backend ||
            vaspace->backend_parent_handle != device->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    if (params->hObjectError != 0) {
        error = hybrid_front_find_object(root, params->hObjectError);
        if (error == NULL || error->class_id != NV01_MEMORY_SYSTEM ||
            error->parent_handle != device->handle ||
            error->backend != group->backend ||
            error->backend_parent_handle != device->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    if (params->hObjectBuffer != 0) {
        buffer = hybrid_front_find_object(root, params->hObjectBuffer);
        if (buffer == NULL || buffer->class_id != NV01_MEMORY_LOCAL_USER ||
            buffer->parent_handle != device->handle ||
            buffer->backend != group->backend ||
            buffer->backend_parent_handle != device->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    if (params->hContextShare != 0) {
        share = hybrid_front_find_object(root, params->hContextShare);
        if (share == NULL || share->class_id != FERMI_CONTEXT_SHARE_A ||
            share->parent_handle != group->handle ||
            share->backend != group->backend ||
            share->backend_parent_handle != group->backend_handle ||
            share->vaspace_handle != group->vaspace_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    for (i = 0; i < NV_MAX_SUBDEVICES; ++i) {
        if (params->hUserdMemory[i] == 0)
            continue;
        userd = hybrid_front_find_object(root, params->hUserdMemory[i]);
        if (userd == NULL || userd->class_id != NV01_MEMORY_LOCAL_USER ||
            userd->parent_handle != device->handle ||
            userd->backend != group->backend ||
            userd->backend_parent_handle != device->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }

    frontend_handles.error = params->hObjectError;
    frontend_handles.buffer = params->hObjectBuffer;
    frontend_handles.context_share = params->hContextShare;
    frontend_handles.vaspace = params->hVASpace;
    memcpy(frontend_handles.userd, params->hUserdMemory,
           sizeof(frontend_handles.userd));
    backend_params = *params;
    if (error != NULL)
        backend_params.hObjectError = error->backend_handle;
    if (buffer != NULL)
        backend_params.hObjectBuffer = buffer->backend_handle;
    if (share != NULL)
        backend_params.hContextShare = share->backend_handle;
    for (i = 0; i < NV_MAX_SUBDEVICES; ++i) {
        if (frontend_handles.userd[i] != 0) {
            userd = hybrid_front_find_object(root,
                                              frontend_handles.userd[i]);
            backend_params.hUserdMemory[i] = userd->backend_handle;
        }
    }
    backend_root = root->root.slot[group->backend].handle;
    if (group->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_channel_alloc_v1(
            state->sessions[group->backend], backend_root,
            group->backend_handle, packet->hObjectNew, packet->hClass,
            &backend_params, &returned_channel, &rm_status);
    else
        transport = hybrid580_open_control_session_channel_alloc_v1(
            state->sessions[group->backend], backend_root,
            group->backend_handle, packet->hObjectNew, packet->hClass,
            &backend_params, &returned_channel, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_channel != packet->hObjectNew ||
        !hybrid_front_channel_backend_handles_match(&backend_params,
            &frontend_handles, root,
            error != NULL ? error->backend_handle : frontend_handles.error,
            buffer != NULL ? buffer->backend_handle : frontend_handles.buffer,
            share != NULL ? share->backend_handle : frontend_handles.context_share) ||
        !hybrid_front_channel_internal_fields_zero(&backend_params)) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    *params = backend_params;
    params->hObjectError = frontend_handles.error;
    params->hObjectBuffer = frontend_handles.buffer;
    params->hContextShare = frontend_handles.context_share;
    params->hVASpace = frontend_handles.vaspace;
    for (i = 0; i < NV_MAX_SUBDEVICES; ++i)
        params->hUserdMemory[i] = frontend_handles.userd[i];

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_channel;
    object->parent_handle = group->handle;
    object->backend_parent_handle = group->backend_handle;
    object->vaspace_handle = group->vaspace_handle;
    object->error_object_handle = frontend_handles.error;
    object->buffer_object_handle = frontend_handles.buffer;
    object->context_share_handle = frontend_handles.context_share;
    for (i = 0; i < NV_MAX_SUBDEVICES; ++i)
        object->userd_memory_handles[i] = frontend_handles.userd[i];
    object->class_id = packet->hClass;
    object->backend = group->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* Engine objects are children of the matching generation's GPFIFO channel.
 * R580 and R595 traces show the four classes below with outer paramsSize=0;
 * their nested allocation payloads were not captured. Do not read the user
 * pointer: this adapter forwards a fixed, pointer-free zero-size allocation. */
static void hybrid_front_engine_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *channel, *object;
    unsigned int backend;
    NvU32 parent_class;
    NvHandle backend_root, returned_engine = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || packet->hRoot == 0 || packet->hObjectParent == 0 ||
        packet->hObjectNew == 0 || packet->paramsSize != 0 ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE)
        return;
    if (packet->hClass == VOLTA_DMA_COPY_A ||
        packet->hClass == VOLTA_COMPUTE_A) {
        backend = HYBRID580_BACKEND_LEGACY;
        parent_class = VOLTA_CHANNEL_GPFIFO_A;
    } else if (packet->hClass == BLACKWELL_DMA_COPY_B ||
               packet->hClass == BLACKWELL_COMPUTE_B) {
        backend = HYBRID580_BACKEND_OPEN;
        parent_class = BLACKWELL_CHANNEL_GPFIFO_A;
    } else {
        packet->status = NV_ERR_INVALID_CLASS;
        return;
    }
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    channel = hybrid_front_find_object(root, packet->hObjectParent);
    if (channel == NULL || channel->class_id != parent_class ||
        channel->backend != backend) {
        packet->status = channel == NULL ? NV_ERR_INVALID_OBJECT_HANDLE :
            NV_ERR_INVALID_CLASS;
        return;
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_root = root->root.slot[backend].handle;
    if (backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_engine_alloc_v1(
            state->sessions[backend], backend_root, channel->backend_handle,
            packet->hObjectNew, packet->hClass, &returned_engine, &rm_status);
    else
        transport = hybrid580_open_control_session_engine_alloc_v1(
            state->sessions[backend], backend_root, channel->backend_handle,
            packet->hObjectNew, packet->hClass, &returned_engine, &rm_status);

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_engine != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_engine;
    object->parent_handle = channel->handle;
    object->backend_parent_handle = channel->backend_handle;
    object->class_id = packet->hClass;
    object->backend = backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

/* System/local-user allocations now accept either the backend default
 * VASpace or a live FERMI_VASPACE_A child of the exact same device and RM.
 * The frontend handle is resolved by ownership; only the backend-local
 * object handle is placed in the kernel-owned allocation parameters. */
static void hybrid_front_memory_alloc64(
    struct hybrid_front_file *state, NVOS64_PARAMETERS *packet,
    NV_MEMORY_ALLOCATION_PARAMS *params)
{
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *parent, *vaspace = NULL, *object;
    NV_MEMORY_ALLOCATION_PARAMS backend_params;
    NvHandle frontend_vaspace, backend_root, returned_object = 0;
    NvU32 rm_status = 0xffffffffU;
    NV_STATUS transport;

    if (packet == NULL)
        return;
    packet->status = NV_ERR_INVALID_ARGUMENT;
    if (state == NULL || params == NULL || packet->hRoot == 0 ||
        packet->hObjectParent == 0 || packet->hObjectNew == 0 ||
        (packet->hClass != NV01_MEMORY_SYSTEM &&
         packet->hClass != NV01_MEMORY_LOCAL_USER) ||
        packet->pRightsRequested != NvP64_NULL ||
        packet->flags != NVOS64_FLAGS_NONE ||
        (packet->paramsSize != 0 && packet->paramsSize != sizeof(*params)))
        return;
    if (state->quarantined) {
        packet->status = NV_ERR_INVALID_STATE;
        return;
    }
    root = hybrid_front_find_root(state, packet->hRoot);
    if (root == NULL || root->root.state != HYBRID_ROOT_ACTIVE ||
        root->root.slot[HYBRID580_BACKEND_LEGACY].handle != packet->hRoot ||
        root->root.slot[HYBRID580_BACKEND_OPEN].handle != packet->hRoot) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    parent = hybrid_front_find_object(root, packet->hObjectParent);
    if (parent == NULL || parent->class_id != NV01_DEVICE_0 ||
        parent->backend > HYBRID580_BACKEND_OPEN) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }
    frontend_vaspace = params->hVASpace;
    if (frontend_vaspace != 0) {
        vaspace = hybrid_front_find_object(root, frontend_vaspace);
        if (vaspace == NULL || vaspace->class_id != FERMI_VASPACE_A ||
            vaspace->parent_handle != packet->hObjectParent ||
            vaspace->backend != parent->backend ||
            vaspace->backend_parent_handle != parent->backend_handle) {
            packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
            return;
        }
    }
    if (state->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS ||
        root->object_count >= HYBRID_FRONT_MAX_DEVICE_OBJECTS) {
        packet->status = NV_ERR_INSUFFICIENT_RESOURCES;
        return;
    }
    if (hybrid_front_handle_in_use(state, packet->hObjectNew)) {
        packet->status = NV_ERR_INVALID_OBJECT_HANDLE;
        return;
    }

    object = kzalloc(sizeof(*object), GFP_KERNEL);
    if (object == NULL) {
        packet->status = NV_ERR_NO_MEMORY;
        return;
    }
    backend_params = *params;
    backend_params.address = NvP64_NULL;
    backend_params.limit = 0;
    backend_params.zcullCovg = 0;
    if (vaspace != NULL)
        backend_params.hVASpace = vaspace->backend_handle;
    backend_root = root->root.slot[parent->backend].handle;
    if (parent->backend == HYBRID580_BACKEND_LEGACY)
        transport = hybrid580_legacy_control_session_memory_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, packet->hClass,
            &backend_params, &returned_object, &rm_status);
    else
        transport = hybrid580_open_control_session_memory_alloc_v1(
            state->sessions[parent->backend], backend_root,
            parent->backend_handle, packet->hObjectNew, packet->hClass,
            &backend_params, &returned_object, &rm_status);
    *params = backend_params;
    params->hVASpace = frontend_vaspace;

    if (transport != NV_OK || rm_status != NV_OK ||
        returned_object != packet->hObjectNew) {
        root->root.state = HYBRID_ROOT_QUARANTINED;
        state->quarantined = true;
        packet->status = transport != NV_OK ? transport :
            (rm_status != NV_OK ? rm_status : NV_ERR_INVALID_STATE);
        kfree(object);
        return;
    }

    object->handle = packet->hObjectNew;
    object->backend_handle = returned_object;
    object->parent_handle = packet->hObjectParent;
    object->backend_parent_handle = parent->backend_handle;
    object->vaspace_handle = frontend_vaspace;
    object->class_id = packet->hClass;
    object->backend = parent->backend;
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
    ++state->object_count;
    packet->status = NV_OK;
}

static NV_STATUS hybrid_front_free(struct hybrid_front_file *state, NVOS00_PARAMETERS *packet)
{
    struct hybrid_front_root **link = &state->roots;
    struct hybrid_front_root *node;
    NV_STATUS status;
    if (packet->hRoot == 0 || packet->hObjectOld == 0)
        return NV_ERR_INVALID_OBJECT_HANDLE;
    while (*link != NULL && (*link)->root.id != packet->hRoot)
        link = &(*link)->next;
    if (*link == NULL)
        return NV_ERR_INVALID_OBJECT_HANDLE;
    node = *link;
    if (node->root.state != HYBRID_ROOT_ACTIVE)
        return NV_ERR_INVALID_STATE;

    if (packet->hObjectOld == packet->hRoot) {
        if (packet->hObjectParent != 0 &&
            packet->hObjectParent != packet->hRoot)
            return NV_ERR_INVALID_OBJECT_HANDLE;
        status = hybrid_root_free(&node->root);
        if (node->root.state == HYBRID_ROOT_EMPTY) {
            struct hybrid_front_rm_object *device = node->objects;
            while (device != NULL) {
                struct hybrid_front_rm_object *next = device->next;
                kfree(device);
                device = next;
            }
            state->object_count -= node->object_count;
            *link = node->next;
            --state->root_count;
            kfree(node);
        } else {
            state->quarantined = true;
        }
        return status;
    }

    {
        struct hybrid_front_rm_object **object_link = &node->objects;
        struct hybrid_front_rm_object *object;
        NvHandle backend_root;
        NvU32 rm_status = 0xffffffffU;
        NV_STATUS transport;

        while (*object_link != NULL &&
               (*object_link)->handle != packet->hObjectOld)
            object_link = &(*object_link)->next;
        if (*object_link == NULL)
            return NV_ERR_INVALID_OBJECT_HANDLE;
        object = *object_link;
        if (packet->hObjectParent != object->parent_handle ||
            object->backend > HYBRID580_BACKEND_OPEN)
            return NV_ERR_INVALID_OBJECT_HANDLE;
        if (object->p2p_registration_refs != 0)
            return NV_ERR_INVALID_OBJECT_HANDLE;
        {
            struct hybrid_front_rm_object *child;

            /* Preserve RM parent-before-child lifetime ordering and VASpace
             * references locally. RM may reject either FREE, but relying on
             * that would make a known invalid request ambiguous. */
            for (child = node->objects; child != NULL; child = child->next) {
                if (child->parent_handle == object->handle ||
                    child->vaspace_handle == object->handle ||
                    child->error_object_handle == object->handle ||
                    child->ecc_error_object_handle == object->handle ||
                    child->buffer_object_handle == object->handle ||
                    child->context_share_handle == object->handle)
                    return NV_ERR_INVALID_OBJECT_HANDLE;
                {
                    NvU32 i;
                    for (i = 0; i < NV_MAX_SUBDEVICES; ++i)
                        if (child->userd_memory_handles[i] == object->handle)
                            return NV_ERR_INVALID_OBJECT_HANDLE;
                }
            }
        }
        backend_root = node->root.slot[object->backend].handle;
        if (object->class_id == NV01_DEVICE_0) {
            if (object->parent_handle != packet->hRoot)
                return NV_ERR_INVALID_STATE;
            if (object->backend == HYBRID580_BACKEND_LEGACY)
                transport = hybrid580_legacy_control_session_device_free_v1(
                    state->sessions[object->backend], backend_root,
                    object->backend_handle, &rm_status);
            else
                transport = hybrid580_open_control_session_device_free_v1(
                    state->sessions[object->backend], backend_root,
                    object->handle, &rm_status);
        } else if (object->class_id == NV01_MEMORY_SYSTEM ||
                   object->class_id == NV01_MEMORY_LOCAL_USER ||
                   object->class_id == NV20_SUBDEVICE_0 ||
                   object->class_id == NV2081_BINAPI ||
                   object->class_id == RM_USER_SHARED_DATA ||
                   object->class_id == NV50_THIRD_PARTY_P2P ||
                   object->class_id == VOLTA_USERMODE_A ||
                   object->class_id == HOPPER_USERMODE_A ||
                   object->class_id == FERMI_VASPACE_A ||
                   object->class_id == KEPLER_CHANNEL_GROUP_A ||
                   object->class_id == FERMI_CONTEXT_SHARE_A ||
                   object->class_id == VOLTA_CHANNEL_GPFIFO_A ||
                   object->class_id == BLACKWELL_CHANNEL_GPFIFO_A ||
                   object->class_id == VOLTA_DMA_COPY_A ||
                   object->class_id == VOLTA_COMPUTE_A ||
                   object->class_id == BLACKWELL_DMA_COPY_B ||
                   object->class_id == BLACKWELL_COMPUTE_B) {
            if (object->backend == HYBRID580_BACKEND_LEGACY)
                transport = hybrid580_legacy_control_session_object_free_v1(
                    state->sessions[object->backend], backend_root,
                    object->backend_parent_handle, object->backend_handle, &rm_status);
            else
                transport = hybrid580_open_control_session_object_free_v1(
                    state->sessions[object->backend], backend_root,
                    object->backend_parent_handle, object->backend_handle, &rm_status);
        } else {
            return NV_ERR_INVALID_STATE;
        }

        if (transport != NV_OK || rm_status != NV_OK) {
            node->root.state = HYBRID_ROOT_QUARANTINED;
            state->quarantined = true;
            return transport != NV_OK ? transport : rm_status;
        }
        *object_link = object->next;
        --node->object_count;
        --state->object_count;
        kfree(object);
    }
    return NV_OK;
}

static long hybrid_front_catalog_count(struct hybrid_front_file *state,
                                       unsigned long argument)
{
    struct hybrid580_gpu_count_v1 request;
    void __user *user = (void __user *)argument;

    if (state == NULL || state->catalog == NULL)
        return -ENODEV;
    if (copy_from_user(&request, user, sizeof(request)))
        return -EFAULT;
    if (request.struct_size != sizeof(request) || request.count != 0 ||
        request.reserved[0] != 0 || request.reserved[1] != 0)
        return -EINVAL;
    request.count = state->catalog->count;
    return copy_to_user(user, &request, sizeof(request)) ? -EFAULT : 0;
}

static long hybrid_front_catalog_info(struct hybrid_front_file *state,
                                      unsigned long argument)
{
    struct hybrid580_gpu_info_v1 request;
    void __user *user = (void __user *)argument;

    if (state == NULL || state->catalog == NULL)
        return -ENODEV;
    if (copy_from_user(&request, user, sizeof(request)))
        return -EFAULT;
    if (request.struct_size != sizeof(request) ||
        request.reserved[0] != 0 || request.reserved[1] != 0)
        return -EINVAL;
    if (request.index >= state->catalog->count)
        return -EINVAL;
    request.entry = state->catalog->entries[request.index];
    return copy_to_user(user, &request, sizeof(request)) ? -EFAULT : 0;
}

static int hybrid_front_find_card_info(
    const nv_ioctl_card_info_t *records, NvU32 count,
    const struct hybrid580_gpu_catalog_entry_v1 *entry,
    nv_ioctl_card_info_t *result)
{
    NvU32 i, matches = 0;

    for (i = 0; i < count; ++i) {
        const nv_ioctl_card_info_t *record = &records[i];
        if (!record->valid || record->minor_number != entry->backend_minor)
            continue;
        if (record->gpu_id != entry->backend_gpu_id ||
            record->pci_info.domain != entry->domain ||
            record->pci_info.bus != entry->bus ||
            record->pci_info.slot != entry->slot ||
            record->pci_info.function != entry->function ||
            record->pci_info.vendor_id != entry->vendor_id ||
            record->pci_info.device_id != entry->device_id)
            return -EAGAIN;
        *result = *record;
        ++matches;
    }
    return matches == 1 ? 0 : -EAGAIN;
}

/* NVIDIA's card-info record embeds backend-local minor and GPU IDs. Return a
 * BDF-ordered merged view with synthetic per-open IDs; keep resource fields
 * intact for a later device-node/mmap adapter. This metadata path does not yet
 * make libcuda usable because standard nodes and the full RM ABI are absent.
 */
static long hybrid_front_card_info(struct hybrid_front_file *state,
                                   unsigned int ioctl_command,
                                   unsigned long argument)
{
    nv_ioctl_card_info_t *user_records = NULL;
    nv_ioctl_card_info_t *legacy = NULL, *open = NULL;
    size_t bytes;
    NvU32 user_capacity, legacy_count = 0, open_count = 0, i;
    int rc = 0;
    unsigned int number = _IOC_NR(ioctl_command);
    void __user *user_pointer = (void __user *)argument;

    if (number == NV_ESC_CARD_INFO) {
        bytes = _IOC_SIZE(ioctl_command);
    } else if (number == NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (_IOC_SIZE(ioctl_command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user_pointer, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd != NV_ESC_CARD_INFO)
            return -ENOTTY;
        bytes = xfer.size;
        user_pointer = (void __user *)NvP64_VALUE(xfer.ptr);
    } else {
        return -ENOTTY;
    }

    if (bytes > HYBRID580_GPU_MAX_DEVICES * sizeof(nv_ioctl_card_info_t))
        return -EINVAL;
    user_capacity = bytes / sizeof(nv_ioctl_card_info_t);
    if (bytes != 0) {
        user_records = kvzalloc(bytes, GFP_KERNEL);
        if (user_records == NULL)
            return -ENOMEM;
        /* Match the native wrapper's input-copy precedence and preserve any
         * trailing partial-record bytes, which its card-info helper ignores. */
        if (copy_from_user(user_records, user_pointer, bytes)) {
            rc = -EFAULT;
            goto out;
        }
    }
    if (user_capacity < state->catalog->count) {
        if (user_capacity != 0)
            memset(user_records, 0,
                   user_capacity * sizeof(nv_ioctl_card_info_t));
        rc = -EINVAL;
        goto copy_out;
    }

    legacy = kvcalloc(HYBRID580_GPU_MAX_BACKEND_DEVICES,
                      sizeof(*legacy), GFP_KERNEL);
    open = kvcalloc(HYBRID580_GPU_MAX_BACKEND_DEVICES,
                    sizeof(*open), GFP_KERNEL);
    if (legacy == NULL || open == NULL) {
        rc = -ENOMEM;
        goto zero_and_copy;
    }
    rc = hybrid580_legacy_gpu_card_info_v1(
        (struct nv_ioctl_card_info *)legacy,
        HYBRID580_GPU_MAX_BACKEND_DEVICES, &legacy_count);
    if (rc != 0)
        goto zero_and_copy;
    rc = hybrid580_open_gpu_card_info_v1(
        (struct nv_ioctl_card_info *)open,
        HYBRID580_GPU_MAX_BACKEND_DEVICES, &open_count);
    if (rc != 0)
        goto zero_and_copy;
    if (legacy_count > HYBRID580_GPU_MAX_BACKEND_DEVICES ||
        open_count > HYBRID580_GPU_MAX_BACKEND_DEVICES ||
        legacy_count + open_count != state->catalog->count) {
        rc = -EAGAIN;
        goto zero_and_copy;
    }

    for (i = 0; i < state->catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *entry =
            &state->catalog->entries[i];
        struct hybrid580_gpu_catalog_entry_v1 verified;
        const nv_ioctl_card_info_t *backend_records;
        NvU32 backend_count;
        nv_ioctl_card_info_t *merged = &user_records[entry->frontend_index];

        rc = hybrid580_gpu_catalog_lookup_backend_minor_v1(
            state->catalog, entry->backend, entry->backend_minor, &verified);
        if (rc != 0 || verified.frontend_index != i ||
            entry->frontend_index != i ||
            entry->frontend_gpu_id != i + 1U ||
            (entry->backend != HYBRID580_BACKEND_LEGACY &&
             entry->backend != HYBRID580_BACKEND_OPEN)) {
            rc = -EINVAL;
            goto zero_and_copy;
        }
        backend_records = entry->backend == HYBRID580_BACKEND_LEGACY ? legacy : open;
        backend_count = entry->backend == HYBRID580_BACKEND_LEGACY ?
            legacy_count : open_count;
        rc = hybrid_front_find_card_info(backend_records, backend_count,
                                          entry, merged);
        if (rc != 0)
            goto zero_and_copy;
        merged->minor_number = entry->frontend_index;
        merged->gpu_id = entry->frontend_gpu_id;
    }
    goto copy_out;

zero_and_copy:
    if (user_capacity != 0)
        memset(user_records, 0,
               user_capacity * sizeof(nv_ioctl_card_info_t));
copy_out:
    if (bytes != 0 && copy_to_user(user_pointer, user_records, bytes))
        rc = -EFAULT;
out:
    kvfree(open);
    kvfree(legacy);
    kvfree(user_records);
    return rc;
}

struct hybrid_front_map_binding {
    spinlock_t *lock;
    enum hybrid_front_map_state *state;
    unsigned int *backend;
};

struct hybrid_front_map_owner {
    struct hybrid_front_root *root;
    struct hybrid_front_rm_object *device;
    struct hybrid_front_rm_object *memory;
    unsigned int backend;
    NvHandle backend_root;
    NvHandle backend_device;
    NvHandle backend_memory;
};

static NV_STATUS hybrid_front_map_owner_resolve(
    struct hybrid_front_file *state, NvHandle h_client, NvHandle h_device,
    NvHandle h_memory, struct hybrid_front_map_owner *owner)
{
    struct hybrid_front_map_owner resolved = { 0 };
    unsigned int backend;

    if (state == NULL || owner == NULL || h_client == 0 || h_device == 0 ||
        h_memory == 0)
        return NV_ERR_INVALID_ARGUMENT;
    resolved.root = hybrid_front_find_root(state, h_client);
    if (resolved.root == NULL || resolved.root->root.state != HYBRID_ROOT_ACTIVE)
        return NV_ERR_INVALID_CLIENT;
    resolved.device = hybrid_front_find_object(resolved.root, h_device);
    resolved.memory = hybrid_front_find_object(resolved.root, h_memory);
    if (resolved.device == NULL || resolved.memory == NULL ||
        (resolved.device->class_id != NV01_DEVICE_0 &&
         resolved.device->class_id != NV20_SUBDEVICE_0) ||
        resolved.device->backend != resolved.memory->backend ||
        (resolved.device->backend != HYBRID580_BACKEND_LEGACY &&
         resolved.device->backend != HYBRID580_BACKEND_OPEN))
        return NV_ERR_INVALID_ARGUMENT;

    backend = resolved.device->backend;
    resolved.backend = backend;
    resolved.backend_root = resolved.root->root.slot[backend].handle;
    resolved.backend_device = resolved.device->backend_handle;
    resolved.backend_memory = resolved.memory->backend_handle;
    if (resolved.backend_root == 0 || resolved.backend_device == 0 ||
        resolved.backend_memory == 0)
        return NV_ERR_INVALID_STATE;
    *owner = resolved;
    return NV_OK;
}

/* Resolve a tracked RM child to its physical NV01_DEVICE_0 ancestor. Every
 * parent edge must match the backend handle saved at allocation time. This
 * prevents an otherwise valid same-backend handle from selecting another GPU
 * in a multi-GPU RM session. */
static struct hybrid_front_rm_object *hybrid_front_gpu_ancestor(
    struct hybrid_front_root *root, struct hybrid_front_rm_object *object)
{
    unsigned int depth;

    if (root == NULL || object == NULL)
        return NULL;
    for (depth = 0; depth < root->object_count; ++depth) {
        struct hybrid_front_rm_object *parent;

        if (object->backend > HYBRID580_BACKEND_OPEN ||
            object->backend_handle == 0)
            return NULL;
        if (object->class_id == NV01_DEVICE_0) {
            if (object->parent_handle != root->root.id ||
                object->backend_parent_handle !=
                    root->root.slot[object->backend].handle)
                return NULL;
            return object;
        }
        if (object->parent_handle == 0 ||
            object->parent_handle == root->root.id)
            return NULL;
        parent = hybrid_front_find_object(root, object->parent_handle);
        if (parent == NULL || parent->backend != object->backend ||
            parent->backend_handle != object->backend_parent_handle)
            return NULL;
        if (object->class_id == NV20_SUBDEVICE_0 &&
            parent->class_id != NV01_DEVICE_0)
            return NULL;
        object = parent;
    }
    return NULL;
}

static bool hybrid_front_mapping_object_supported(NvU32 class_id)
{
    return class_id == NV01_MEMORY_SYSTEM ||
        class_id == NV01_MEMORY_LOCAL_USER ||
        class_id == VOLTA_CHANNEL_GPFIFO_A ||
        class_id == BLACKWELL_CHANNEL_GPFIFO_A;
}

static NV_STATUS hybrid_front_mapping_update_owner_resolve(
    struct hybrid_front_file *state, NvHandle h_client, NvHandle h_device,
    NvHandle h_memory, struct hybrid_front_map_owner *owner)
{
    struct hybrid_front_map_owner resolved;
    struct hybrid_front_rm_object *device_gpu, *memory_gpu;
    NV_STATUS status;

    status = hybrid_front_map_owner_resolve(state, h_client, h_device,
                                             h_memory, &resolved);
    if (status != NV_OK)
        return status;
    if (!hybrid_front_mapping_object_supported(resolved.memory->class_id))
        return NV_ERR_INVALID_ARGUMENT;
    device_gpu = hybrid_front_gpu_ancestor(resolved.root, resolved.device);
    memory_gpu = hybrid_front_gpu_ancestor(resolved.root, resolved.memory);
    if (device_gpu == NULL || memory_gpu == NULL || device_gpu != memory_gpu ||
        device_gpu->backend != resolved.backend)
        return NV_ERR_INVALID_ARGUMENT;
    *owner = resolved;
    return NV_OK;
}

static int hybrid_front_map_target_reserve(
    struct file *origin, struct file *target, unsigned int backend,
    struct hybrid_front_map_binding *binding)
{
    struct hybrid_front_file_base *base;
    struct hybrid_front_file *control;
    struct hybrid_front_gpu_file *gpu;
    unsigned long flags;
    int rc = 0;

    if (origin == NULL || target == NULL || binding == NULL ||
        target->f_op != &hybrid_front_fops || target->private_data == NULL)
        return -EBADF;
    base = target->private_data;
    if (base->kind == HYBRID_FRONT_CONTROL_FILE) {
        control = target->private_data;
        if (control->sessions[backend] == NULL)
            return -ENODEV;
        binding->lock = &control->map_lock;
        binding->state = &control->pending_map_state;
        binding->backend = &control->pending_map_backend;
    } else if (base->kind == HYBRID_FRONT_GPU_FILE) {
        gpu = target->private_data;
        if (gpu->control_front != origin || gpu->backend != backend)
            return -EXDEV;
        binding->lock = &gpu->map_lock;
        binding->state = &gpu->pending_map_state;
        binding->backend = &gpu->pending_map_backend;
    } else {
        return -EBADF;
    }

    spin_lock_irqsave(binding->lock, flags);
    if (*binding->state != HYBRID_FRONT_MAP_EMPTY)
        rc = *binding->state == HYBRID_FRONT_MAP_POISONED ? -EIO : -EBUSY;
    else {
        *binding->backend = backend;
        *binding->state = HYBRID_FRONT_MAP_RESERVED;
    }
    spin_unlock_irqrestore(binding->lock, flags);
    return rc;
}

static void hybrid_front_map_target_finish(
    const struct hybrid_front_map_binding *binding,
    enum hybrid_front_map_state next)
{
    unsigned long flags;

    if (binding == NULL || binding->lock == NULL || binding->state == NULL)
        return;
    spin_lock_irqsave(binding->lock, flags);
    if (*binding->state == HYBRID_FRONT_MAP_RESERVED)
        *binding->state = next;
    spin_unlock_irqrestore(binding->lock, flags);
}

static NV_STATUS hybrid_front_backend_map_memory(
    struct hybrid_front_file *state, unsigned int backend,
    NVOS33_PARAMETERS *params, NvS32 fd)
{
    if (backend == HYBRID580_BACKEND_LEGACY)
        return hybrid580_legacy_control_session_map_memory_v1(
            state->sessions[0], params, fd);
    if (backend == HYBRID580_BACKEND_OPEN)
        return hybrid580_open_control_session_map_memory_v1(
            state->sessions[1], params, fd);
    return NV_ERR_INVALID_ARGUMENT;
}

static NV_STATUS hybrid_front_backend_unmap_memory(
    struct hybrid_front_file *state, unsigned int backend,
    NVOS34_PARAMETERS *params)
{
    if (backend == HYBRID580_BACKEND_LEGACY)
        return hybrid580_legacy_control_session_unmap_memory_v1(
            state->sessions[0], params);
    if (backend == HYBRID580_BACKEND_OPEN)
        return hybrid580_open_control_session_unmap_memory_v1(
            state->sessions[1], params);
    return NV_ERR_INVALID_ARGUMENT;
}

static NV_STATUS hybrid_front_backend_update_device_mapping_info(
    struct hybrid_front_file *state, unsigned int backend,
    NVOS56_PARAMETERS *params)
{
    if (backend == HYBRID580_BACKEND_LEGACY)
        return hybrid580_legacy_control_session_update_device_mapping_info_v1(
            state->sessions[HYBRID580_BACKEND_LEGACY], params);
    if (backend == HYBRID580_BACKEND_OPEN)
        return hybrid580_open_control_session_update_device_mapping_info_v1(
            state->sessions[HYBRID580_BACKEND_OPEN], params);
    return NV_ERR_INVALID_ARGUMENT;
}

static long hybrid_front_update_device_mapping_info_ioctl(
    struct hybrid_front_file *state, unsigned int command,
    unsigned long argument)
{
    NVOS56_PARAMETERS user_packet, backend_packet;
    struct hybrid_front_map_owner owner;
    NV_STATUS transport, owner_status;
    void __user *user = (void __user *)argument;
    long rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_NR(command) != NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        _IOC_SIZE(command) != sizeof(user_packet))
        return -EINVAL;
    if (copy_from_user(&user_packet, user, sizeof(user_packet)))
        return -EFAULT;
    user_packet.status = 0xffffffffU;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    if (state->quarantined) {
        user_packet.status = NV_ERR_INVALID_STATE;
        rc = 0;
        goto copy_status;
    }
    owner_status = hybrid_front_mapping_update_owner_resolve(
        state, user_packet.hClient, user_packet.hDevice, user_packet.hMemory,
        &owner);
    if (owner_status != NV_OK) {
        user_packet.status = owner_status;
        rc = 0;
        goto copy_status;
    }

    backend_packet = user_packet;
    backend_packet.hClient = owner.backend_root;
    backend_packet.hDevice = owner.backend_device;
    backend_packet.hMemory = owner.backend_memory;
    backend_packet.status = 0xffffffffU;
    state->stateful_started = true;
    transport = hybrid_front_backend_update_device_mapping_info(
        state, owner.backend, &backend_packet);
    if (transport != NV_OK) {
        /* The RM call may have changed a process mapping before a transport
         * failure obscured its status. Do not guess whether retry is safe. */
        state->quarantined = true;
        rc = -EINVAL;
        goto copy_status;
    }
    if (backend_packet.status == 0xffffffffU) {
        state->quarantined = true;
        user_packet.status = NV_ERR_INVALID_STATE;
        rc = -EINVAL;
        goto copy_status;
    }
    user_packet.status = backend_packet.status;
    if (copy_to_user(user, &user_packet, sizeof(user_packet))) {
        if (user_packet.status == NV_OK)
            state->quarantined = true;
        rc = -EFAULT;
        goto out;
    }
    rc = 0;
    goto out;

copy_status:
    if (copy_to_user(user, &user_packet, sizeof(user_packet)))
        rc = -EFAULT;
out:
    mutex_unlock(&state->transaction_lock);
    return rc;
}

static long hybrid_front_map_memory_ioctl(struct file *front,
                                          struct hybrid_front_file *state,
                                          unsigned int command,
                                          unsigned long argument)
{
    nv_ioctl_nvos33_parameters_with_fd user_packet;
    NVOS33_PARAMETERS backend_packet;
    struct hybrid_front_map_owner owner;
    struct hybrid_front_map_binding binding = { 0 };
    struct file *target = NULL;
    NV_STATUS transport, owner_status;
    void __user *user = (void __user *)argument;
    bool reserved = false;
    int rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_NR(command) != NV_ESC_RM_MAP_MEMORY ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        _IOC_SIZE(command) != sizeof(user_packet))
        return -EINVAL;
    if (copy_from_user(&user_packet, user, sizeof(user_packet)))
        return -EFAULT;
    user_packet.params.status = 0xffffffffU;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    if (state->quarantined) {
        user_packet.params.status = NV_ERR_INVALID_STATE;
        rc = 0;
        goto copy_status;
    }
    owner_status = hybrid_front_map_owner_resolve(
        state, user_packet.params.hClient, user_packet.params.hDevice,
        user_packet.params.hMemory, &owner);
    if (owner_status != NV_OK) {
        user_packet.params.status = owner_status;
        rc = 0;
        goto copy_status;
    }
    if (user_packet.fd < 0) {
        user_packet.params.status = NV_ERR_INVALID_ARGUMENT;
        rc = 0;
        goto copy_status;
    }
    target = fget(user_packet.fd);
    if (target == NULL) {
        user_packet.params.status = NV_ERR_INVALID_ARGUMENT;
        rc = 0;
        goto copy_status;
    }
    rc = hybrid_front_map_target_reserve(front, target, owner.backend, &binding);
    if (rc == -EXDEV || rc == -EBADF || rc == -ENODEV) {
        user_packet.params.status = NV_ERR_INVALID_ARGUMENT;
        rc = 0;
        goto copy_status;
    }
    if (rc != 0)
        goto out;
    reserved = true;

    backend_packet = user_packet.params;
    backend_packet.hClient = owner.backend_root;
    backend_packet.hDevice = owner.backend_device;
    backend_packet.hMemory = owner.backend_memory;
    backend_packet.status = 0xffffffffU;
    state->stateful_started = true;
    transport = hybrid_front_backend_map_memory(
        state, owner.backend, &backend_packet, user_packet.fd);
    user_packet.params.status = backend_packet.status;
    user_packet.params.flags = backend_packet.flags;
    user_packet.params.pLinearAddress = backend_packet.pLinearAddress;

    if (transport != NV_OK) {
        state->quarantined = true;
        hybrid_front_map_target_finish(&binding, HYBRID_FRONT_MAP_POISONED);
        reserved = false;
        rc = -EINVAL;
        goto copy_status;
    }
    if (backend_packet.status != NV_OK) {
        hybrid_front_map_target_finish(&binding, HYBRID_FRONT_MAP_EMPTY);
        reserved = false;
        rc = 0;
        goto copy_status;
    }

    /* Publish READY only after all outputs reached userspace. On a copyout
     * fault the RM may already own an mmap context, so the fd is poisoned and
     * must be closed instead of allowing a second, ambiguous map attempt. */
    if (copy_to_user(user, &user_packet, sizeof(user_packet))) {
        state->quarantined = true;
        hybrid_front_map_target_finish(&binding, HYBRID_FRONT_MAP_POISONED);
        reserved = false;
        rc = -EFAULT;
        goto out;
    }
    hybrid_front_map_target_finish(&binding, HYBRID_FRONT_MAP_READY);
    reserved = false;
    rc = 0;
    goto out;

copy_status:
    if (copy_to_user(user, &user_packet, sizeof(user_packet)))
        rc = -EFAULT;
out:
    if (reserved)
        hybrid_front_map_target_finish(&binding, HYBRID_FRONT_MAP_EMPTY);
    if (target != NULL)
        fput(target);
    mutex_unlock(&state->transaction_lock);
    return rc;
}

static long hybrid_front_unmap_memory_ioctl(struct hybrid_front_file *state,
                                            unsigned int command,
                                            unsigned long argument)
{
    NVOS34_PARAMETERS user_packet, backend_packet;
    struct hybrid_front_map_owner owner;
    NV_STATUS transport, owner_status;
    void __user *user = (void __user *)argument;
    int rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_NR(command) != NV_ESC_RM_UNMAP_MEMORY ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        _IOC_SIZE(command) != sizeof(user_packet))
        return -EINVAL;
    if (copy_from_user(&user_packet, user, sizeof(user_packet)))
        return -EFAULT;
    user_packet.status = 0xffffffffU;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    owner_status = hybrid_front_map_owner_resolve(
        state, user_packet.hClient, user_packet.hDevice,
        user_packet.hMemory, &owner);
    if (owner_status != NV_OK) {
        user_packet.status = owner_status;
        rc = 0;
        goto copy_status;
    }

    backend_packet = user_packet;
    backend_packet.hClient = owner.backend_root;
    backend_packet.hDevice = owner.backend_device;
    backend_packet.hMemory = owner.backend_memory;
    backend_packet.status = 0xffffffffU;
    state->stateful_started = true;
    transport = hybrid_front_backend_unmap_memory(
        state, owner.backend, &backend_packet);
    user_packet.status = backend_packet.status;
    if (transport != NV_OK)
        state->quarantined = true;
    rc = transport == NV_OK ? 0 : -EINVAL;
copy_status:
    if (copy_to_user(user, &user_packet, sizeof(user_packet)))
        rc = -EFAULT;
    mutex_unlock(&state->transaction_lock);
    return rc;
}

/* NV_ESC_SYS_PARAMS is a Linux/RM wrapper operation on nv_ctl_device, not an
 * RM_CONTROL command. Decode its single fixed field and apply the native
 * R580 set-once contract to both isolated Resource Managers. A failure in the
 * second provider leaves a one-sided process-global mutation, so fail closed
 * for every frontend ioctl until the module is reloaded. */
static long hybrid_front_sys_params_ioctl(struct hybrid_front_file *state,
                                          unsigned int command,
                                          unsigned long argument)
{
    nv_ioctl_sys_params_t params;
    void __user *user = (void __user *)argument;
    int rc;

    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_NR(command) != NV_ESC_SYS_PARAMS ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        _IOC_SIZE(command) != sizeof(params))
        return -EINVAL;
    if (copy_from_user(&params, user, sizeof(params)))
        return -EFAULT;

    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0)
        return rc;
    if (state->quarantined || READ_ONCE(hybrid_front_sys_params_poisoned)) {
        rc = -EIO;
        goto out_state;
    }

    rc = mutex_lock_interruptible(&hybrid_front_sys_params_lock);
    if (rc != 0)
        goto out_state;
    if (READ_ONCE(hybrid_front_sys_params_poisoned)) {
        rc = -EIO;
        goto out_global;
    }
    if (state->sessions[HYBRID580_BACKEND_LEGACY] == NULL ||
        state->sessions[HYBRID580_BACKEND_OPEN] == NULL) {
        rc = -ENODEV;
        goto out_global;
    }

    rc = hybrid580_legacy_control_session_sys_params_v1(
        state->sessions[HYBRID580_BACKEND_LEGACY], params.memblock_size);
    if (rc == 0) {
        rc = hybrid580_open_control_session_sys_params_v1(
            state->sessions[HYBRID580_BACKEND_OPEN], params.memblock_size);
        if (rc != 0) {
            state->quarantined = true;
            WRITE_ONCE(hybrid_front_sys_params_poisoned, true);
        }
    }

out_global:
    mutex_unlock(&hybrid_front_sys_params_lock);
    if (copy_to_user(user, &params, sizeof(params)))
        rc = -EFAULT;
out_state:
    mutex_unlock(&state->transaction_lock);
    return rc;
}

static long hybrid_front_ioctl_inner(struct file *front, unsigned int command, unsigned long argument)
{
    struct hybrid_front_file_base *base = front->private_data;
    struct hybrid_front_file *state;
    union {
        NVOS21_PARAMETERS alloc21;
        NVOS64_PARAMETERS alloc64;
        NVOS00_PARAMETERS free;
    } packet;
    NV0080_ALLOC_PARAMETERS device_params = { 0 };
    NV2080_ALLOC_PARAMETERS subdevice_params = { 0 };
    NV2081_ALLOC_PARAMETERS binapi_params = { 0 };
    NV00DE_ALLOC_PARAMETERS rusd_params = { 0 };
    NV503C_ALLOC_PARAMETERS p2p_params = { 0 };
    NV_HOPPER_USERMODE_A_PARAMS usermode_params = { 0 };
    NV_MEMORY_ALLOCATION_PARAMS memory_params = { 0 };
    NV_VASPACE_ALLOCATION_PARAMETERS vaspace_params = { 0 };
    NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS channel_group_params = { 0 };
    NV_CTXSHARE_ALLOCATION_PARAMETERS context_share_params = { 0 };
    NV_CHANNEL_ALLOC_PARAMS *channel_params = NULL;
    bool device_params_valid = false;
    bool subdevice_params_valid = false;
    bool binapi_params_valid = false;
    bool rusd_params_valid = false;
    bool p2p_params_valid = false;
    bool usermode_params_valid = false;
    bool memory_params_valid = false;
    bool vaspace_params_valid = false;
    bool channel_group_params_valid = false;
    bool context_share_params_valid = false;
    bool channel_params_valid = false;
    void __user *memory_params_user = NULL;
    void __user *vaspace_params_user = NULL;
    void __user *channel_group_params_user = NULL;
    void __user *context_share_params_user = NULL;
    void __user *p2p_params_user = NULL;
    void __user *channel_params_user = NULL;
    unsigned int size = _IOC_SIZE(command), number = _IOC_NR(command);
    void __user *user = (void __user *)argument;
    int rc;
    /* Project-specific descriptor discovery is deliberately distinct from
     * NVIDIA's ioctl namespace and CUDA's standard device enumeration. */
    if (base == NULL)
        return -EBADF;
    if (base->kind == HYBRID_FRONT_GPU_FILE)
        return hybrid_front_gpu_ioctl(front, command, argument);
    if (base->kind != HYBRID_FRONT_CONTROL_FILE)
        return -EBADF;
    state = front->private_data;
    if (_IOC_TYPE(command) == HYBRID580_IOCTL_MAGIC) {
        if (command == HYBRID580_IOCTL_OPEN_GPU) {
            rc = mutex_lock_interruptible(&state->transaction_lock);
            if (rc != 0)
                return rc;
            if (state->quarantined) {
                mutex_unlock(&state->transaction_lock);
                return -EIO;
            }
            ++state->operation_inflight;
            mutex_unlock(&state->transaction_lock);
            rc = hybrid_front_open_gpu_fd(front, argument);
            mutex_lock(&state->transaction_lock);
            if (rc == 0)
                state->stateful_started = true;
            --state->operation_inflight;
            mutex_unlock(&state->transaction_lock);
            return rc;
        }
        if (command == HYBRID580_IOCTL_GET_GPU_COUNT)
            return hybrid_front_catalog_count(state, argument);
        if (command == HYBRID580_IOCTL_GET_GPU_INFO)
            return hybrid_front_catalog_info(state, argument);
        return -ENOTTY;
    }
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_SYS_PARAMS)
        return hybrid_front_sys_params_ioctl(state, command, argument);
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_RM_MAP_MEMORY)
        return hybrid_front_map_memory_ioctl(front, state, command, argument);
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC &&
        number == NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO)
        return hybrid_front_update_device_mapping_info_ioctl(
            state, command, argument);
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_RM_UNMAP_MEMORY)
        return hybrid_front_unmap_memory_ioctl(state, command, argument);
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_RM_CONTROL)
        return hybrid_front_rm_control_ioctl(state, command, argument);
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_CARD_INFO)
        return hybrid_front_card_info(state, command, argument);
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (_IOC_SIZE(command) != sizeof(xfer))
            return -EINVAL;
        if (copy_from_user(&xfer, user, sizeof(xfer)))
            return -EFAULT;
        if (xfer.cmd == NV_ESC_CARD_INFO)
            return hybrid_front_card_info(state, command, argument);
        if (xfer.cmd == NV_ESC_ATTACH_GPUS_TO_FD)
            return hybrid_front_attach_ioctl(front, command, argument);
        if (xfer.cmd == NV_ESC_RM_CONTROL)
            return hybrid_front_rm_control_ioctl(state, command, argument);
        return -ENOTTY;
    }
    if (_IOC_TYPE(command) == NV_IOCTL_MAGIC && number == NV_ESC_ATTACH_GPUS_TO_FD)
        return hybrid_front_attach_ioctl(front, command, argument);
    /* This is still an experimental, restricted ABI on /dev/hybrid580ctl,
     * not libcuda's ABI. Unknown/child controls never reach either RM. Only
     * allowlisted RM allocations/frees and typed controls are translated;
     * generic RM_CONTROL, RM event objects and UVM are denied here. GPU-file
     * mmap/poll are separate file_operations callbacks. */
    if (_IOC_TYPE(command) != NV_IOCTL_MAGIC ||
        _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE) ||
        !((number == NV_ESC_RM_ALLOC &&
           (size == sizeof(packet.alloc21) || size == sizeof(packet.alloc64))) ||
          (number == NV_ESC_RM_FREE && size == sizeof(packet.free))))
        return -EINVAL;
    memset(&packet, 0, sizeof(packet));
    if (copy_from_user(&packet, user, size))
        return -EFAULT;
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == NV01_DEVICE_0 &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(device_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        if (copy_from_user(&device_params,
                           (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms),
                           sizeof(device_params)))
            return -EFAULT;
        device_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == NV20_SUBDEVICE_0 &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(subdevice_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        if (copy_from_user(&subdevice_params,
                           (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms),
                           sizeof(subdevice_params)))
            return -EFAULT;
        subdevice_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == NV2081_BINAPI &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(binapi_params))) {
        if (NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
            if (copy_from_user(&binapi_params,
                    (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms),
                    sizeof(binapi_params)))
                return -EFAULT;
            binapi_params_valid = true;
        } else if (packet.alloc64.paramsSize == 0) {
            binapi_params_valid = true;
        }
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == RM_USER_SHARED_DATA &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(rusd_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        if (copy_from_user(&rusd_params,
                (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms),
                sizeof(rusd_params)))
            return -EFAULT;
        rusd_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == NV50_THIRD_PARTY_P2P &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(p2p_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        p2p_params_user =
            (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms);
        if (copy_from_user(&p2p_params, p2p_params_user, sizeof(p2p_params)))
            return -EFAULT;
        p2p_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == VOLTA_USERMODE_A &&
        packet.alloc64.paramsSize == 0)
        usermode_params_valid = true;
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == HOPPER_USERMODE_A &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(usermode_params))) {
        if (NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
            if (copy_from_user(&usermode_params,
                    (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms),
                    sizeof(usermode_params)))
                return -EFAULT;
            usermode_params_valid = true;
        } else if (packet.alloc64.paramsSize == 0) {
            usermode_params_valid = true;
        }
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == FERMI_VASPACE_A &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(vaspace_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        vaspace_params_user =
            (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms);
        if (copy_from_user(&vaspace_params, vaspace_params_user,
                           sizeof(vaspace_params)))
            return -EFAULT;
        vaspace_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == KEPLER_CHANNEL_GROUP_A &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(channel_group_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        channel_group_params_user =
            (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms);
        if (copy_from_user(&channel_group_params, channel_group_params_user,
                           sizeof(channel_group_params)))
            return -EFAULT;
        channel_group_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        packet.alloc64.hClass == FERMI_CONTEXT_SHARE_A &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(context_share_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        context_share_params_user =
            (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms);
        if (copy_from_user(&context_share_params, context_share_params_user,
                           sizeof(context_share_params)))
            return -EFAULT;
        context_share_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        (packet.alloc64.hClass == VOLTA_CHANNEL_GPFIFO_A ||
        packet.alloc64.hClass == BLACKWELL_CHANNEL_GPFIFO_A) &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(*channel_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        channel_params_user =
            (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms);
        channel_params = kzalloc(sizeof(*channel_params), GFP_KERNEL);
        if (channel_params == NULL)
            return -ENOMEM;
        if (copy_from_user(channel_params, channel_params_user,
                           sizeof(*channel_params))) {
            kfree(channel_params);
            return -EFAULT;
        }
        channel_params_valid = true;
    }
    if (number == NV_ESC_RM_ALLOC && size == sizeof(packet.alloc64) &&
        (packet.alloc64.hClass == NV01_MEMORY_SYSTEM ||
         packet.alloc64.hClass == NV01_MEMORY_LOCAL_USER) &&
        (packet.alloc64.paramsSize == 0 ||
         packet.alloc64.paramsSize == sizeof(memory_params)) &&
        NvP64_VALUE(packet.alloc64.pAllocParms) != NULL) {
        memory_params_user =
            (void __user *)NvP64_VALUE(packet.alloc64.pAllocParms);
        if (copy_from_user(&memory_params, memory_params_user,
                           sizeof(memory_params)))
            return -EFAULT;
        memory_params_valid = true;
    }
    rc = mutex_lock_interruptible(&state->transaction_lock);
    if (rc != 0) {
        kfree(channel_params);
        return rc;
    }
    if (number == NV_ESC_RM_ALLOC) {
        state->stateful_started = true;
        if (size == sizeof(packet.alloc64) &&
            packet.alloc64.hClass == NV01_DEVICE_0) {
            hybrid_front_device_alloc64(state, &packet.alloc64,
                                        device_params_valid ?
                                        &device_params : NULL);
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == NV20_SUBDEVICE_0) {
            hybrid_front_subdevice_alloc64(state, &packet.alloc64,
                subdevice_params_valid ? &subdevice_params : NULL);
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == NV2081_BINAPI) {
            hybrid_front_binapi_alloc64(state, &packet.alloc64,
                binapi_params_valid ? &binapi_params : NULL);
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == RM_USER_SHARED_DATA) {
            hybrid_front_rusd_alloc64(state, &packet.alloc64,
                rusd_params_valid ? &rusd_params : NULL);
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == NV50_THIRD_PARTY_P2P) {
            hybrid_front_p2p_alloc64(state, &packet.alloc64,
                p2p_params_valid ? &p2p_params : NULL);
        } else if (size == sizeof(packet.alloc64) &&
                   (packet.alloc64.hClass == VOLTA_USERMODE_A ||
                    packet.alloc64.hClass == HOPPER_USERMODE_A)) {
            if (usermode_params_valid)
                hybrid_front_usermode_alloc64(state, &packet.alloc64,
                    packet.alloc64.hClass == HOPPER_USERMODE_A &&
                    NvP64_VALUE(packet.alloc64.pAllocParms) != NULL ?
                        &usermode_params : NULL);
            else
                packet.alloc64.status = NV_ERR_INVALID_ARGUMENT;
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == FERMI_VASPACE_A) {
            hybrid_front_vaspace_alloc64(state, &packet.alloc64,
                                         vaspace_params_valid ?
                                         &vaspace_params : NULL);
            if (vaspace_params_valid &&
                copy_to_user(vaspace_params_user, &vaspace_params,
                             sizeof(vaspace_params))) {
                mutex_unlock(&state->transaction_lock);
                return -EFAULT;
            }
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == KEPLER_CHANNEL_GROUP_A) {
            hybrid_front_channel_group_alloc64(state, &packet.alloc64,
                channel_group_params_valid ? &channel_group_params : NULL);
            if (channel_group_params_valid &&
                copy_to_user(channel_group_params_user, &channel_group_params,
                             sizeof(channel_group_params))) {
                mutex_unlock(&state->transaction_lock);
                return -EFAULT;
            }
        } else if (size == sizeof(packet.alloc64) &&
                   packet.alloc64.hClass == FERMI_CONTEXT_SHARE_A) {
            hybrid_front_context_share_alloc64(state, &packet.alloc64,
                context_share_params_valid ? &context_share_params : NULL);
            if (context_share_params_valid &&
                copy_to_user(context_share_params_user, &context_share_params,
                             sizeof(context_share_params))) {
                mutex_unlock(&state->transaction_lock);
                return -EFAULT;
            }
        } else if (size == sizeof(packet.alloc64) &&
                   (packet.alloc64.hClass == VOLTA_CHANNEL_GPFIFO_A ||
                    packet.alloc64.hClass == BLACKWELL_CHANNEL_GPFIFO_A)) {
            hybrid_front_channel_alloc64(state, &packet.alloc64,
                channel_params_valid ? channel_params : NULL);
            if (channel_params_valid &&
                copy_to_user(channel_params_user, channel_params,
                             sizeof(*channel_params))) {
                kfree(channel_params);
                mutex_unlock(&state->transaction_lock);
                return -EFAULT;
            }
        } else if (size == sizeof(packet.alloc64) &&
                   (packet.alloc64.hClass == VOLTA_DMA_COPY_A ||
                    packet.alloc64.hClass == VOLTA_COMPUTE_A ||
                    packet.alloc64.hClass == BLACKWELL_DMA_COPY_B ||
                    packet.alloc64.hClass == BLACKWELL_COMPUTE_B)) {
            hybrid_front_engine_alloc64(state, &packet.alloc64);
        } else if (size == sizeof(packet.alloc64) &&
                   (packet.alloc64.hClass == NV01_MEMORY_SYSTEM ||
                    packet.alloc64.hClass == NV01_MEMORY_LOCAL_USER)) {
            hybrid_front_memory_alloc64(state, &packet.alloc64,
                                        memory_params_valid ?
                                        &memory_params : NULL);
            if (memory_params_valid &&
                copy_to_user(memory_params_user, &memory_params,
                             sizeof(memory_params))) {
                /* Keep successful/ambiguous ownership recorded. Final ROOT
                 * teardown is the only safe recovery after output is lost. */
                mutex_unlock(&state->transaction_lock);
                return -EFAULT;
            }
        } else if ((size == sizeof(packet.alloc21) &&
                    (packet.alloc21.hClass == NV01_ROOT ||
                     packet.alloc21.hClass == NV01_ROOT_CLIENT)) ||
                   (size == sizeof(packet.alloc64) &&
                    (packet.alloc64.hClass == NV01_ROOT ||
                     packet.alloc64.hClass == NV01_ROOT_CLIENT))) {
            hybrid_front_alloc(state, &packet, size);
        } else if (size == sizeof(packet.alloc21)) {
            packet.alloc21.status = NV_ERR_INVALID_CLASS;
        } else {
            packet.alloc64.status = NV_ERR_INVALID_CLASS;
        }
    } else {
        state->stateful_started = true;
        packet.free.status = hybrid_front_free(state, &packet.free);
    }
    /* A failed copy-out must retain all ownership/state; final close performs
     * known cleanup or quarantined file teardown. No retry/reinitialization. */
    rc = copy_to_user(user, &packet, size) ? -EFAULT : 0;
    mutex_unlock(&state->transaction_lock);
    kfree(channel_params);
    return rc;
}

static long hybrid_front_ioctl(struct file *front, unsigned int command,
                               unsigned long argument)
{
    long rc;

    if (READ_ONCE(hybrid_front_sys_params_poisoned))
        return -EIO;
    rc = hybrid_front_admission_enter();

    if (rc != 0)
        return rc;
    rc = hybrid_front_ioctl_inner(front, command, argument);
    hybrid_front_admission_leave();
    return rc;
}

static const struct file_operations hybrid_front_fops = {
    .owner = THIS_MODULE,
    .open = hybrid_front_open,
    .release = hybrid_front_release,
    .unlocked_ioctl = hybrid_front_ioctl,
    .mmap = hybrid_front_gpu_mmap,
    .poll = hybrid_front_gpu_poll,
#ifdef CONFIG_COMPAT
    .compat_ioctl = hybrid_front_ioctl,
#endif
};

static const struct hybrid580_file_projection_ops_v1 hybrid_legacy_projection = {
    .abi_version = HYBRID580_FILE_PROJECTION_ABI_V1,
    .struct_size = sizeof(struct hybrid580_file_projection_ops_v1),
    .owner = THIS_MODULE,
    .frontend_fops = &hybrid_front_fops,
    .get_backing_file = hybrid_front_project_legacy,
};
static const struct hybrid580_file_projection_ops_v1 hybrid_open_projection = {
    .abi_version = HYBRID580_FILE_PROJECTION_ABI_V1,
    .struct_size = sizeof(struct hybrid580_file_projection_ops_v1),
    .owner = THIS_MODULE,
    .frontend_fops = &hybrid_front_fops,
    .get_backing_file = hybrid_front_project_open,
};
static struct hybrid580_gpu_catalog_v1 *hybrid_front_node_catalog;

static int hybrid_front_standard_nodes_init(void)
{
    struct hybrid_front_file inventory = { 0 };
    int rc;

    rc = hybrid_front_catalog_create(&inventory);
    if (rc != 0)
        return rc;
    rc = hybrid580_standard_nodes_register_v1(inventory.catalog,
                                               &hybrid_front_fops);
    if (rc != 0) {
        kvfree(inventory.catalog);
        return rc;
    }
    hybrid_front_node_catalog = inventory.catalog;
    return 0;
}

static void hybrid_front_standard_nodes_exit(void)
{
    hybrid580_standard_nodes_unregister_v1();
    kvfree(hybrid_front_node_catalog);
    hybrid_front_node_catalog = NULL;
}

static struct miscdevice hybrid_front_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "hybrid580ctl",
    .fops = &hybrid_front_fops,
    .mode = 0600,
};
static bool enable_control;
static bool hybrid_front_registered;
module_param(enable_control, bool, 0400);
MODULE_PARM_DESC(enable_control, "Opt in to experimental hybrid580ctl; default false");

static int __init hybrid_front_init(void)
{
    int rc;
    /* Loading dependencies still initializes their global RM resources. A
     * false flag only suppresses this module's providers/device/session work. */
    if (!enable_control)
        return 0;
    rc = hybrid580_legacy_register_file_projection_v1(&hybrid_legacy_projection);
    if (rc != 0)
        return rc;
    rc = hybrid580_open_register_file_projection_v1(&hybrid_open_projection);
    if (rc != 0)
        goto unregister_legacy;
    rc = hybrid_front_standard_nodes_init();
    if (rc != 0)
        goto unregister_open;
    rc = misc_register(&hybrid_front_device);
    if (rc != 0)
        goto unregister_nodes;
    hybrid_front_registered = true;
    return 0;
 unregister_nodes:
    hybrid_front_standard_nodes_exit();
 unregister_open:
    (void)hybrid580_open_unregister_file_projection_v1(&hybrid_open_projection);
 unregister_legacy:
    (void)hybrid580_legacy_unregister_file_projection_v1(&hybrid_legacy_projection);
    return rc;
}

static void __exit hybrid_front_exit(void)
{
    if (!hybrid_front_registered)
        return;
    misc_deregister(&hybrid_front_device);
    hybrid_front_standard_nodes_exit();
    (void)hybrid580_open_unregister_file_projection_v1(&hybrid_open_projection);
    (void)hybrid580_legacy_unregister_file_projection_v1(&hybrid_legacy_projection);
    hybrid_front_registered = false;
}

module_init(hybrid_front_init);
module_exit(hybrid_front_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("Experimental two-session R580 ROOT and BDF GPU-file frontend; not CUDA ABI");
