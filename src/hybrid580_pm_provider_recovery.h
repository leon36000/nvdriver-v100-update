/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_PM_PROVIDER_RECOVERY_H
#define HYBRID580_PM_PROVIDER_RECOVERY_H

/*
 * Shared CPU/kernel provider-side DPM result contract. Callers must serialize
 * every operation on one record; the NVIDIA wrapper uses its device-list
 * semaphore for that purpose. This structure is not independently concurrent.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

enum hybrid580_pm_provider_callback {
    HYBRID580_PM_PROVIDER_CALLBACK_RESUME = 1,
    HYBRID580_PM_PROVIDER_CALLBACK_RESTORE = 2,
    HYBRID580_PM_PROVIDER_CALLBACK_THAW = 3,
};

struct hybrid580_pm_provider_recovery_status {
    unsigned long long generation;
    int first_error;
    int fallback_error;
    unsigned int callback;
    unsigned int armed;
    unsigned int observed;
    unsigned int fallback_observed;
    unsigned int channels_suspended;
    unsigned long long channels_generation;
};

static inline int
hybrid580_pm_provider_recovery_begin(
    struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation)
{
    if (status == 0 || generation == 0)
        return -EINVAL;
    if (status->channels_suspended)
        return -EBUSY;
    if (status->generation == ~0ULL)
        return -EOVERFLOW;
    if (generation <= status->generation)
        return -ESTALE;

    status->generation = generation;
    status->first_error = 0;
    status->fallback_error = 0;
    status->callback = 0;
    status->armed = 1;
    status->observed = 0;
    status->fallback_observed = 0;
    status->channels_suspended = 0;
    status->channels_generation = 0;
    return 0;
}

static inline int
hybrid580_pm_provider_channels_suspend_attempt(
    struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation)
{
    if (status == 0 || generation == 0)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;
    if (status->channels_suspended)
        return -EALREADY;
    status->channels_suspended = 1;
    status->channels_generation = generation;
    return 0;
}

static inline int
hybrid580_pm_provider_channels_restore_result(
    struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation, int error)
{
    if (status == 0 || generation == 0 || error > 0)
        return -EINVAL;
    if (!status->channels_suspended ||
        status->channels_generation != generation ||
        status->generation != generation)
        return -ESTALE;
    if (error != 0)
        return error;
    status->channels_suspended = 0;
    status->channels_generation = 0;
    return 0;
}

static inline int
hybrid580_pm_provider_recovery_record_callback(
    struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation, unsigned int callback, int error)
{
    if (status == 0 || error > 0 ||
        callback < HYBRID580_PM_PROVIDER_CALLBACK_RESUME ||
        callback > HYBRID580_PM_PROVIDER_CALLBACK_THAW)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;

    if (!status->observed) {
        status->callback = callback;
        status->observed = 1;
    } else if (status->callback != callback && status->first_error == 0) {
        status->first_error = -EPROTO;
        return -EPROTO;
    }

    if (error != 0 && status->first_error == 0)
        status->first_error = error;
    return 0;
}

static inline int
hybrid580_pm_provider_recovery_record_fallback(
    struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation, int error)
{
    if (status == 0 || error > 0)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;
    if (!status->observed)
        return -EAGAIN;
    if (status->callback != HYBRID580_PM_PROVIDER_CALLBACK_THAW)
        return -EPROTO;

    status->fallback_observed = 1;
    if (error != 0 && status->fallback_error == 0)
        status->fallback_error = error;
    return 0;
}

static inline int
hybrid580_pm_provider_recovery_check(
    const struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation, unsigned int expected_callback,
    int require_fallback)
{
    if (status == 0 || generation == 0 ||
        expected_callback < HYBRID580_PM_PROVIDER_CALLBACK_RESUME ||
        expected_callback > HYBRID580_PM_PROVIDER_CALLBACK_THAW ||
        (require_fallback != 0 && require_fallback != 1))
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;
    if (!status->observed)
        return -EAGAIN;
    if (status->callback != expected_callback)
        return -EPROTO;
    if (status->first_error != 0)
        return status->first_error;
    if (expected_callback == HYBRID580_PM_PROVIDER_CALLBACK_THAW) {
        if (require_fallback && !status->fallback_observed)
            return -EAGAIN;
        if (status->fallback_observed)
            return status->fallback_error;
    } else if (require_fallback || status->fallback_observed) {
        return -EPROTO;
    }
    return 0;
}

static inline int
hybrid580_pm_provider_recovery_end(
    struct hybrid580_pm_provider_recovery_status *status,
    unsigned long long generation)
{
    if (status == 0 || generation == 0)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;
    status->armed = 0;
    return 0;
}

#endif /* HYBRID580_PM_PROVIDER_RECOVERY_H */
