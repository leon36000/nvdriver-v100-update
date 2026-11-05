/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_PM_RECOVERY_STATUS_H
#define HYBRID580_PM_RECOVERY_STATUS_H

/*
 * CPU-testable contract for a per-GPU DPM recovery result. The eventual
 * provider implementation must protect equivalent state with kernel-safe
 * atomics/locking; this plain struct is not a concurrent kernel primitive.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>

struct hybrid580_pm_recovery_status {
    unsigned long long generation;
    int first_error;
    bool armed;
    bool observed;
};

static inline int
hybrid580_pm_recovery_begin(struct hybrid580_pm_recovery_status *status,
                            unsigned long long generation)
{
    if (status == NULL || generation == 0)
        return -EINVAL;
    if (status->generation == ~0ULL)
        return -EOVERFLOW;
    if (generation <= status->generation)
        return -ESTALE;

    status->generation = generation;
    status->first_error = 0;
    status->armed = true;
    status->observed = false;
    return 0;
}

static inline int
hybrid580_pm_recovery_record(struct hybrid580_pm_recovery_status *status,
                             unsigned long long generation, int error)
{
    if (status == NULL || error > 0)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;

    status->observed = true;
    if (error != 0 && status->first_error == 0)
        status->first_error = error;
    return 0;
}

static inline int
hybrid580_pm_recovery_check(const struct hybrid580_pm_recovery_status *status,
                            unsigned long long generation)
{
    if (status == NULL || generation == 0)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;
    if (!status->observed)
        return -EAGAIN;
    return status->first_error;
}

static inline int
hybrid580_pm_recovery_end(struct hybrid580_pm_recovery_status *status,
                          unsigned long long generation)
{
    if (status == NULL || generation == 0)
        return -EINVAL;
    if (!status->armed || status->generation != generation)
        return -ESTALE;
    status->armed = false;
    return 0;
}

#endif /* HYBRID580_PM_RECOVERY_STATUS_H */
