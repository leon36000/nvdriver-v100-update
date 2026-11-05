/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_PM_SHARED_UVM_H
#define HYBRID580_PM_SHARED_UVM_H

/*
 * CPU/kernel state contract for the one shared UVM PM callback pair. Callers
 * must serialize transitions externally; the Open provider does so with a
 * mutex. A failed callback leaves the prior phase intact so the coordinator
 * can retry or keep system-PM admission closed.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

enum hybrid580_pm_shared_uvm_phase {
    HYBRID580_PM_SHARED_UVM_RUNNING = 0,
    HYBRID580_PM_SHARED_UVM_SUSPENDED = 1,
};

struct hybrid580_pm_shared_uvm_state {
    unsigned int phase;
};

typedef int (*hybrid580_pm_shared_uvm_callback)(void *context);

static inline int
hybrid580_pm_shared_uvm_suspend(
    struct hybrid580_pm_shared_uvm_state *state,
    hybrid580_pm_shared_uvm_callback callback, void *context)
{
    int rc;

    if (state == 0 || callback == 0)
        return -EINVAL;
    if (state->phase == HYBRID580_PM_SHARED_UVM_SUSPENDED)
        return -EBUSY;
    if (state->phase != HYBRID580_PM_SHARED_UVM_RUNNING)
        return -EINVAL;

    rc = callback(context);
    if (rc > 0)
        return -EPROTO;
    if (rc == 0)
        state->phase = HYBRID580_PM_SHARED_UVM_SUSPENDED;
    return rc;
}

static inline int
hybrid580_pm_shared_uvm_resume(
    struct hybrid580_pm_shared_uvm_state *state,
    hybrid580_pm_shared_uvm_callback callback, void *context)
{
    int rc;

    if (state == 0 || callback == 0 ||
        state->phase != HYBRID580_PM_SHARED_UVM_SUSPENDED)
        return -EINVAL;

    rc = callback(context);
    if (rc > 0)
        return -EPROTO;
    if (rc == 0)
        state->phase = HYBRID580_PM_SHARED_UVM_RUNNING;
    return rc;
}

#endif /* HYBRID580_PM_SHARED_UVM_H */
