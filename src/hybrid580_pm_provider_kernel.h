/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_PM_PROVIDER_KERNEL_H
#define HYBRID580_PM_PROVIDER_KERNEL_H

/*
 * R580 Linux-wrapper bridge for the per-GPU recovery contract. Include this
 * once from nv.c after the device list/table and nvidia_resume() are defined,
 * with HYBRID580_PM_PROVIDER_PREFIX set to the backend's private namespace.
 * All record access is serialized by nv_linux_devices_lock. The status API
 * does not register PM callbacks or alter ordinary system-PM behavior unless
 * a matching generation was explicitly armed by the hybrid coordinator.
 */
#include "hybrid580-pm-provider-recovery.h"

#define HYBRID580_PM_PROVIDER_JOIN_INNER(a, b) a##b
#define HYBRID580_PM_PROVIDER_JOIN(a, b) \
    HYBRID580_PM_PROVIDER_JOIN_INNER(a, b)
#define HYBRID580_PM_PROVIDER_API(name) \
    HYBRID580_PM_PROVIDER_JOIN(HYBRID580_PM_PROVIDER_PREFIX, name)

int HYBRID580_PM_PROVIDER_API(pm_recovery_begin_v1)(
    unsigned long long generation);
int HYBRID580_PM_PROVIDER_API(pm_recovery_recover_v1)(
    unsigned long long generation, unsigned int expected_callback);
int HYBRID580_PM_PROVIDER_API(pm_recovery_end_v1)(
    unsigned long long generation);
int HYBRID580_PM_PROVIDER_API(pm_channels_suspend_v1)(
    unsigned long long generation);
int HYBRID580_PM_PROVIDER_API(pm_channels_resume_v1)(
    unsigned long long generation);

#ifdef HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER
int HYBRID580_PM_PROVIDER_API(pm_shared_uvm_suspend_v1)(void);
int HYBRID580_PM_PROVIDER_API(pm_shared_uvm_resume_v1)(void);
#endif

static struct hybrid580_pm_provider_recovery_status
    hybrid580_pm_provider_status[NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1];
static unsigned long long hybrid580_pm_provider_last_generation;
static unsigned long long hybrid580_pm_provider_active_generation;
static unsigned long long hybrid580_pm_provider_active_channels_generation;

static struct hybrid580_pm_provider_recovery_status *
hybrid580_pm_provider_status_for_nvl(nv_linux_state_t *nvl)
{
    NvU32 minor;

    if (nvl == NULL)
        return NULL;
    minor = nvl->minor_num;
    if (minor > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX ||
        nv_linux_minor_num_table[minor] != nvl)
        return NULL;
    return &hybrid580_pm_provider_status[minor];
}

static nv_linux_state_t *
hybrid580_pm_provider_nvl_from_dev(struct device *dev)
{
    if (dev == NULL)
        return NULL;
    if (dev_is_pci(dev))
        return pci_get_drvdata(to_pci_dev(dev));
    return dev_get_drvdata(dev);
}

static int
hybrid580_pm_provider_record_dpm_callback(
    struct device *dev, unsigned int callback, int error)
{
    nv_linux_state_t *nvl;
    struct hybrid580_pm_provider_recovery_status *status;
    unsigned long long generation;
    int rc = 0;

    LOCK_NV_LINUX_DEVICES();
    generation = hybrid580_pm_provider_active_generation;
    if (generation == 0)
        goto done;

    nvl = hybrid580_pm_provider_nvl_from_dev(dev);
    status = hybrid580_pm_provider_status_for_nvl(nvl);
    if (status == NULL)
        rc = -ENODEV;
    else
        rc = hybrid580_pm_provider_recovery_record_callback(
            status, generation, callback, error);

done:
    UNLOCK_NV_LINUX_DEVICES();
    return rc;
}

static int
hybrid580_pm_provider_verify_live(nv_linux_state_t *nvl)
{
    nv_state_t *nv = NV_STATE_PTR(nvl);
    int rc = 0;

    down(&nvl->ldata_lock);
    if ((nv->flags & NV_FLAG_SUSPENDED) != 0 || nvl->suspend_count != 0)
        rc = -EIO;
    up(&nvl->ldata_lock);
    return rc;
}

int
HYBRID580_PM_PROVIDER_API(pm_recovery_begin_v1)(
    unsigned long long generation)
{
    nv_linux_state_t *nvl;
    unsigned int count = 0;
    int rc = 0;

    if (generation == 0)
        return -EINVAL;

    LOCK_NV_LINUX_DEVICES();
    if (hybrid580_pm_provider_active_generation != 0 ||
        hybrid580_pm_provider_active_channels_generation != 0)
        rc = -EBUSY;
    else if (generation <= hybrid580_pm_provider_last_generation)
        rc = -ESTALE;
    else if (nv_linux_devices == NULL)
        rc = -ENODEV;

    if (rc != 0)
        goto done;

    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *status =
            hybrid580_pm_provider_status_for_nvl(nvl);

        if (status == NULL)
        {
            rc = -ENODEV;
            goto done;
        }
        if (status->armed || status->channels_suspended)
        {
            rc = -EBUSY;
            goto done;
        }
        if (generation <= status->generation)
        {
            rc = -ESTALE;
            goto done;
        }
        count++;
    }

    if (count == 0)
    {
        rc = -ENODEV;
        goto done;
    }

    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *status =
            hybrid580_pm_provider_status_for_nvl(nvl);

        rc = hybrid580_pm_provider_recovery_begin(status, generation);
        if (rc != 0)
            goto done;
    }

    hybrid580_pm_provider_last_generation = generation;
    hybrid580_pm_provider_active_generation = generation;

done:
    UNLOCK_NV_LINUX_DEVICES();
    return rc;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_recovery_begin_v1));

int
HYBRID580_PM_PROVIDER_API(pm_recovery_recover_v1)(
    unsigned long long generation, unsigned int expected_callback)
{
    nv_linux_state_t *nvl;
    unsigned int count = 0;
    int first_error = 0;

    if (generation == 0 ||
        expected_callback < HYBRID580_PM_PROVIDER_CALLBACK_RESUME ||
        expected_callback > HYBRID580_PM_PROVIDER_CALLBACK_THAW)
        return -EINVAL;

    LOCK_NV_LINUX_DEVICES();
    if (hybrid580_pm_provider_active_generation != generation)
    {
        first_error = -ESTALE;
        goto done;
    }
    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *status =
            hybrid580_pm_provider_status_for_nvl(nvl);
        int rc;

        if (status == NULL)
        {
            first_error = -ENODEV;
            goto done;
        }
        rc = hybrid580_pm_provider_recovery_check(
            status, generation, expected_callback, 0);
        if (rc != 0)
        {
            first_error = rc;
            goto done;
        }
        count++;
    }

    if (count == 0)
    {
        first_error = -ENODEV;
        goto done;
    }

    if (expected_callback == HYBRID580_PM_PROVIDER_CALLBACK_THAW)
    {
        for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
        {
            struct hybrid580_pm_provider_recovery_status *status =
                hybrid580_pm_provider_status_for_nvl(nvl);
            int rc;

            if (status->fallback_observed)
                continue;

            down(&nvl->ldata_lock);
            rc = nvl->suspend_count == 0 ? 0 : -EBUSY;
            up(&nvl->ldata_lock);

            if (rc == 0)
            {
                if (nvl->dev == NULL)
                    rc = -ENODEV;
                else
                {
                    NV_STATUS rm_status = nvidia_resume(
                        nvl->dev, NV_PM_ACTION_RESUME);

                    rc = rm_status == NV_OK ?
                        hybrid580_pm_provider_verify_live(nvl) : -EIO;
                }
            }

            if (hybrid580_pm_provider_recovery_record_fallback(
                    status, generation, rc) != 0 && rc == 0)
                rc = -EIO;
            if (rc != 0 && first_error == 0)
                first_error = rc;
        }
    }

    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *status =
            hybrid580_pm_provider_status_for_nvl(nvl);
        int rc;

        if (expected_callback != HYBRID580_PM_PROVIDER_CALLBACK_THAW)
        {
            rc = hybrid580_pm_provider_verify_live(nvl);
            if (rc != 0)
                (void)hybrid580_pm_provider_recovery_record_callback(
                    status, generation, expected_callback, rc);
        }
        else
        {
            rc = hybrid580_pm_provider_recovery_check(
                status, generation, expected_callback, 1);
        }

        if (rc != 0 && first_error == 0)
            first_error = rc;
    }

done:
    UNLOCK_NV_LINUX_DEVICES();
    return first_error;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_recovery_recover_v1));

int
HYBRID580_PM_PROVIDER_API(pm_recovery_end_v1)(
    unsigned long long generation)
{
    unsigned int minor;
    int first_error = 0;

    if (generation == 0)
        return -EINVAL;

    LOCK_NV_LINUX_DEVICES();
    if (hybrid580_pm_provider_active_generation != generation)
    {
        first_error = -ESTALE;
        goto done;
    }
    for (minor = 0; minor <= NV_MINOR_DEVICE_NUMBER_REGULAR_MAX; minor++)
    {
        struct hybrid580_pm_provider_recovery_status *status =
            &hybrid580_pm_provider_status[minor];
        int rc;

        if (!status->armed || status->generation != generation)
            continue;
        rc = hybrid580_pm_provider_recovery_end(status, generation);
        if (rc != 0 && first_error == 0)
            first_error = rc;
    }
    if (first_error == 0)
        hybrid580_pm_provider_active_generation = 0;

done:
    UNLOCK_NV_LINUX_DEVICES();
    return first_error;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_recovery_end_v1));

/* The aggregate frontend owns the system-PM sequence. Track channel state per
 * GPU in a separate generation latch from DPM callback recovery, so channel
 * restart remains available after the resume callback results are retired.
 * A partial stop or failed restart is retried only for affected devices. In contrast to the
 * driver's global procfs suspend entrypoint, these operations touch channels
 * only; PCI DPM remains responsible for GPU power and per-GPU NVKMS state.
 */
int HYBRID580_PM_PROVIDER_API(pm_channels_suspend_v1)(
    unsigned long long generation)
{
    nv_linux_state_t *nvl;
    unsigned int count = 0;
    int first_error = 0;

    if (generation == 0)
        return -EINVAL;

    LOCK_NV_LINUX_DEVICES();
    if (hybrid580_pm_provider_active_generation != generation)
    {
        first_error = -ESTALE;
        goto done;
    }
    if (hybrid580_pm_provider_active_channels_generation != 0)
    {
        first_error = -EBUSY;
        goto done;
    }
    if (nv_linux_devices == NULL)
    {
        first_error = -ENODEV;
        goto done;
    }

    /* Validate the complete provider inventory before changing any GPU. */
    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *provider_status =
            hybrid580_pm_provider_status_for_nvl(nvl);

        if (provider_status == NULL || !provider_status->armed ||
            provider_status->generation != generation)
        {
            first_error = -ESTALE;
            goto done;
        }
        if (provider_status->channels_suspended)
        {
            first_error = -EBUSY;
            goto done;
        }
        if (nvl->dev == NULL)
        {
            first_error = -ENODEV;
            goto done;
        }
        count++;
    }
    if (count == 0)
    {
        first_error = -ENODEV;
        goto done;
    }

    hybrid580_pm_provider_active_channels_generation = generation;

    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *provider_status =
            hybrid580_pm_provider_status_for_nvl(nvl);
        NV_STATUS nv_status;

        first_error = hybrid580_pm_provider_channels_suspend_attempt(
            provider_status, generation);
        if (first_error != 0)
            goto done;

        nv_status = nv_preempt_user_channels(NV_STATE_PTR(nvl));
        if (nv_status != NV_OK)
        {
            first_error = -EIO;
            goto done;
        }
    }

done:
    UNLOCK_NV_LINUX_DEVICES();
    return first_error;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_channels_suspend_v1));

int HYBRID580_PM_PROVIDER_API(pm_channels_resume_v1)(
    unsigned long long generation)
{
    nv_linux_state_t *nvl;
    int first_error = 0;

    if (generation == 0)
        return -EINVAL;

    LOCK_NV_LINUX_DEVICES();
    if (hybrid580_pm_provider_active_channels_generation != generation)
    {
        first_error = -ESTALE;
        goto done;
    }
    if (nv_linux_devices == NULL)
    {
        first_error = -ENODEV;
        goto done;
    }

    for (nvl = nv_linux_devices; nvl != NULL; nvl = nvl->next)
    {
        struct hybrid580_pm_provider_recovery_status *provider_status =
            hybrid580_pm_provider_status_for_nvl(nvl);
        int rc;

        if (provider_status == NULL ||
            provider_status->generation != generation)
        {
            if (first_error == 0)
                first_error = -ESTALE;
            continue;
        }
        if (!provider_status->channels_suspended)
            continue;
        if (nvl->dev == NULL)
        {
            rc = -ENODEV;
        }
        else
        {
            NV_STATUS nv_status = nv_restore_user_channels(NV_STATE_PTR(nvl));

            rc = nv_status == NV_OK ? 0 : -EIO;
        }
        rc = hybrid580_pm_provider_channels_restore_result(
            provider_status, generation, rc);
        if (rc != 0 && first_error == 0)
            first_error = rc;
    }

    if (first_error == 0)
        hybrid580_pm_provider_active_channels_generation = 0;

done:
    UNLOCK_NV_LINUX_DEVICES();
    return first_error;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_channels_resume_v1));

#ifdef HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER
#include <linux/mutex.h>
#include "hybrid580-pm-shared-uvm.h"

/*
 * Architecture C uses the Open backend as the sole entry to the shared UVM
 * callback table. Call only after the frontend has drained ordinary work and
 * selected channels-only device PM on both providers.
 */
static DEFINE_MUTEX(hybrid580_pm_provider_shared_uvm_lock);
static struct hybrid580_pm_shared_uvm_state
    hybrid580_pm_provider_shared_uvm_state;

extern NV_STATUS HYBRID580_PM_PROVIDER_API(nv_uvm_suspend_registered_v1)(void);
extern NV_STATUS HYBRID580_PM_PROVIDER_API(nv_uvm_resume_registered_v1)(void);

static int hybrid580_pm_provider_call_shared_uvm_suspend(void *unused)
{
    NV_STATUS status;

    (void)unused;
    status = HYBRID580_PM_PROVIDER_API(nv_uvm_suspend_registered_v1)();
    return status == NV_OK ? 0 : -EIO;
}

static int hybrid580_pm_provider_call_shared_uvm_resume(void *unused)
{
    NV_STATUS status;

    (void)unused;
    status = HYBRID580_PM_PROVIDER_API(nv_uvm_resume_registered_v1)();
    return status == NV_OK ? 0 : -EIO;
}

int HYBRID580_PM_PROVIDER_API(pm_shared_uvm_suspend_v1)(void)
{
    int rc;

    mutex_lock(&hybrid580_pm_provider_shared_uvm_lock);
    rc = hybrid580_pm_shared_uvm_suspend(
        &hybrid580_pm_provider_shared_uvm_state,
        hybrid580_pm_provider_call_shared_uvm_suspend, NULL);
    mutex_unlock(&hybrid580_pm_provider_shared_uvm_lock);
    return rc;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_shared_uvm_suspend_v1));

int HYBRID580_PM_PROVIDER_API(pm_shared_uvm_resume_v1)(void)
{
    int rc;

    mutex_lock(&hybrid580_pm_provider_shared_uvm_lock);
    rc = hybrid580_pm_shared_uvm_resume(
        &hybrid580_pm_provider_shared_uvm_state,
        hybrid580_pm_provider_call_shared_uvm_resume, NULL);
    mutex_unlock(&hybrid580_pm_provider_shared_uvm_lock);
    return rc;
}
EXPORT_SYMBOL(HYBRID580_PM_PROVIDER_API(pm_shared_uvm_resume_v1));
#endif /* HYBRID580_PM_PROVIDER_SHARED_UVM_OWNER */

#undef HYBRID580_PM_PROVIDER_API
#undef HYBRID580_PM_PROVIDER_JOIN
#undef HYBRID580_PM_PROVIDER_JOIN_INNER

#endif /* HYBRID580_PM_PROVIDER_KERNEL_H */
