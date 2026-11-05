/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_SYSTEM_PM_COORDINATOR_H
#define HYBRID580_SYSTEM_PM_COORDINATOR_H

/*
 * CPU-testable phase model for a dual-R580 system-PM coordinator.
 *
 * This header deliberately does not register Linux PM callbacks or device
 * links. The caller must serialize calls and map system notifiers and DPM
 * events through the event routers below. The aggregate DPM consumer must be
 * ordered before every GPU supplier on suspend and after every supplier on
 * resume. Do not call UVM suspend from the pre-freezer notifier. Callbacks
 * must tolerate cleanup after a failed operation. In particular, a channel
 * suspend can affect a prefix of the provider's GPUs before returning an
 * error, so the coordinator records the backend as attempted before calling
 * it and always calls restore during rollback. Provider recovery callbacks
 * must use the transition generation to check per-device sticky errors and
 * handle Linux THAW/RECOVER paths where NVIDIA's device callback is a no-op.
 * In R580 the inspected Linux wrapper sends FIFO control 0x20801117 from
 * rm_stop_user_channels; the matching public header describes it as disabling
 * usermode-channel scheduling, while the UVM source separately states that RM
 * preempts user channels before UVM suspend. The proprietary command
 * implementation and this invariant are not runtime-verified here. The model
 * does not validate Linux wiring or prove that the provider prevents new
 * fault-capable work.
 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#endif

#define HYBRID580_PM_OPEN_MASK   (1u << 0)
#define HYBRID580_PM_LEGACY_MASK (1u << 1)
#define HYBRID580_PM_ALL_BACKENDS \
    (HYBRID580_PM_OPEN_MASK | HYBRID580_PM_LEGACY_MASK)

enum hybrid580_pm_backend {
    HYBRID580_PM_BACKEND_OPEN = 0,
    HYBRID580_PM_BACKEND_LEGACY = 1,
};

enum hybrid580_pm_phase {
    HYBRID580_PM_RUNNING = 0,
    HYBRID580_PM_ADMISSION_CLOSED,
    HYBRID580_PM_DPM_SUSPENDING,
    HYBRID580_PM_SUSPENDED,
    HYBRID580_PM_DPM_RESUMING,
    HYBRID580_PM_DPM_RESUMED,
    HYBRID580_PM_FAILED,
};

enum hybrid580_pm_cycle {
    HYBRID580_PM_CYCLE_NONE = 0,
    HYBRID580_PM_CYCLE_SUSPEND,
    HYBRID580_PM_CYCLE_HIBERNATION,
    HYBRID580_PM_CYCLE_RESTORE,
};

/* Abstract IDs mirror the pinned Linux v7.0 PM notifier and DPM event names. */
enum hybrid580_pm_notifier_event {
    HYBRID580_PM_NOTIFY_SUSPEND_PREPARE = 1,
    HYBRID580_PM_NOTIFY_POST_SUSPEND,
    HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE,
    HYBRID580_PM_NOTIFY_POST_HIBERNATION,
    HYBRID580_PM_NOTIFY_RESTORE_PREPARE,
    HYBRID580_PM_NOTIFY_POST_RESTORE,
    HYBRID580_PM_NOTIFY_UNRELATED,
};

enum hybrid580_pm_dpm_event {
    HYBRID580_PM_DPM_SUSPEND = 1,
    HYBRID580_PM_DPM_RESUME,
    HYBRID580_PM_DPM_FREEZE,
    HYBRID580_PM_DPM_QUIESCE,
    HYBRID580_PM_DPM_POWEROFF,
    HYBRID580_PM_DPM_HIBERNATE,
    HYBRID580_PM_DPM_THAW,
    HYBRID580_PM_DPM_RECOVER,
    HYBRID580_PM_DPM_RESTORE,
    HYBRID580_PM_DPM_UNRELATED,
};

enum hybrid580_pm_status {
    HYBRID580_PM_OK = 0,
    HYBRID580_PM_IGNORED = 1,
    HYBRID580_PM_INVALID = -EINVAL,
    HYBRID580_PM_BUSY = -EBUSY,
    HYBRID580_PM_ROLLBACK_FAILED = -EUCLEAN,
    HYBRID580_PM_RESUME_FAILED = -EIO,
};

struct hybrid580_system_pm_ops {
    void *context;
    int (*block_frontend)(void *context);
    int (*drain_frontend)(void *context);
    int (*begin_recovery_cycle)(void *context, unsigned int backend,
                                unsigned long long generation);
    int (*end_recovery_cycle)(void *context, unsigned int backend,
                              unsigned long long generation);
    int (*suspend_channels)(void *context, unsigned int backend);
    int (*drain_irqs)(void *context, unsigned int backend);
    int (*suspend_uvm)(void *context);
    int (*recover_and_verify_devices)(void *context, unsigned int backend,
                                      unsigned long long generation,
                                      enum hybrid580_pm_dpm_event event);
    int (*resume_uvm)(void *context);
    int (*restore_channels)(void *context, unsigned int backend);
    int (*unblock_frontend)(void *context);
};

struct hybrid580_system_pm {
    enum hybrid580_pm_phase phase;
    enum hybrid580_pm_cycle cycle;
    unsigned long long generation;
    unsigned int recovery_armed;
    unsigned int channels_suspended;
    bool frontend_blocked;
    bool uvm_suspended;
    int original_error;
    int cleanup_error;
};

static inline bool
hybrid580_system_pm_ops_valid(const struct hybrid580_system_pm_ops *ops)
{
    return ops != NULL && ops->block_frontend != NULL &&
           ops->drain_frontend != NULL && ops->suspend_channels != NULL &&
           ops->begin_recovery_cycle != NULL && ops->end_recovery_cycle != NULL &&
           ops->drain_irqs != NULL && ops->suspend_uvm != NULL &&
           ops->recover_and_verify_devices != NULL &&
           ops->resume_uvm != NULL && ops->restore_channels != NULL &&
           ops->unblock_frontend != NULL;
}

static inline unsigned int
hybrid580_system_pm_backend_mask(unsigned int backend)
{
    if (backend == HYBRID580_PM_BACKEND_OPEN)
        return HYBRID580_PM_OPEN_MASK;
    if (backend == HYBRID580_PM_BACKEND_LEGACY)
        return HYBRID580_PM_LEGACY_MASK;
    return 0;
}

static inline int
hybrid580_system_pm_end_recovery_cycles(
    struct hybrid580_system_pm *state,
    const struct hybrid580_system_pm_ops *ops)
{
    static const unsigned int end_order[] = {
        HYBRID580_PM_BACKEND_LEGACY,
        HYBRID580_PM_BACKEND_OPEN,
    };
    size_t i;
    int first_error = 0;

    for (i = 0; i < sizeof(end_order) / sizeof(end_order[0]); ++i) {
        unsigned int backend = end_order[i];
        unsigned int mask = hybrid580_system_pm_backend_mask(backend);
        int error;

        if ((state->recovery_armed & mask) == 0)
            continue;
        error = ops->end_recovery_cycle(ops->context, backend,
                                        state->generation);
        if (error == 0)
            state->recovery_armed &= ~mask;
        else if (first_error == 0)
            first_error = error;
    }
    if (first_error != 0 && state->cleanup_error == 0)
        state->cleanup_error = first_error;
    return first_error;
}

static inline bool
hybrid580_pm_cycle_valid(enum hybrid580_pm_cycle cycle)
{
    return cycle == HYBRID580_PM_CYCLE_SUSPEND ||
           cycle == HYBRID580_PM_CYCLE_HIBERNATION ||
           cycle == HYBRID580_PM_CYCLE_RESTORE;
}

static inline int
hybrid580_system_pm_begin_for_cycle(struct hybrid580_system_pm *state,
                                    const struct hybrid580_system_pm_ops *ops,
                                    enum hybrid580_pm_cycle cycle)
{
    int error;

    if (!hybrid580_pm_cycle_valid(cycle))
        return HYBRID580_PM_INVALID;
    if (state == NULL || !hybrid580_system_pm_ops_valid(ops))
        return HYBRID580_PM_INVALID;
    if (state->phase == HYBRID580_PM_FAILED)
        return HYBRID580_PM_ROLLBACK_FAILED;
    if (state->phase != HYBRID580_PM_RUNNING)
        return HYBRID580_PM_BUSY;
    if (state->generation == ~0ULL)
        return -EOVERFLOW;
    if (state->recovery_armed != 0 || state->channels_suspended != 0 ||
        state->frontend_blocked ||
        state->uvm_suspended || state->cycle != HYBRID580_PM_CYCLE_NONE)
        return HYBRID580_PM_INVALID;

    state->phase = HYBRID580_PM_ADMISSION_CLOSED;
    state->original_error = 0;
    state->cleanup_error = 0;

    error = ops->block_frontend(ops->context);
    if (error != 0) {
        /* The atomic-on-error callback contract leaves the gate unchanged. */
        state->phase = HYBRID580_PM_RUNNING;
        state->original_error = error;
        return error;
    }
    state->frontend_blocked = true;
    state->cycle = cycle;
    state->generation++;

    /* Arm provider-owned per-GPU latches before Linux starts DPM. This
     * callback changes bookkeeping only; it must not transition hardware. */
    error = ops->begin_recovery_cycle(ops->context,
                                      HYBRID580_PM_BACKEND_OPEN,
                                      state->generation);
    if (error == 0) {
        state->recovery_armed |= HYBRID580_PM_OPEN_MASK;
        error = ops->begin_recovery_cycle(ops->context,
                                          HYBRID580_PM_BACKEND_LEGACY,
                                          state->generation);
        if (error == 0)
            state->recovery_armed |= HYBRID580_PM_LEGACY_MASK;
    }
    if (error != 0) {
        int cleanup = hybrid580_system_pm_end_recovery_cycles(state, ops);

        state->original_error = error;
        if (cleanup == 0)
            cleanup = ops->unblock_frontend(ops->context);
        if (cleanup != 0) {
            state->cleanup_error = cleanup;
            state->phase = HYBRID580_PM_FAILED;
            return HYBRID580_PM_ROLLBACK_FAILED;
        }
        state->frontend_blocked = false;
        state->cycle = HYBRID580_PM_CYCLE_NONE;
        state->phase = HYBRID580_PM_RUNNING;
        return error;
    }

    /* This pre-freezer phase closes admission only; it does not drain UVM. */
    return HYBRID580_PM_OK;
}

static inline int
hybrid580_system_pm_begin(struct hybrid580_system_pm *state,
                          const struct hybrid580_system_pm_ops *ops)
{
    return hybrid580_system_pm_begin_for_cycle(
        state, ops, HYBRID580_PM_CYCLE_SUSPEND);
}

static inline int
hybrid580_system_pm_suspend_after_freezer(struct hybrid580_system_pm *state,
                                          const struct hybrid580_system_pm_ops *ops)
{
    static const unsigned int suspend_order[] = {
        HYBRID580_PM_BACKEND_OPEN,
        HYBRID580_PM_BACKEND_LEGACY,
    };
    static const unsigned int rollback_order[] = {
        HYBRID580_PM_BACKEND_LEGACY,
        HYBRID580_PM_BACKEND_OPEN,
    };
    static const unsigned int drain_order[] = {
        HYBRID580_PM_BACKEND_OPEN,
        HYBRID580_PM_BACKEND_LEGACY,
    };
    size_t i;
    int error;

    if (state == NULL || !hybrid580_system_pm_ops_valid(ops))
        return HYBRID580_PM_INVALID;
    if (state->phase == HYBRID580_PM_FAILED)
        return HYBRID580_PM_ROLLBACK_FAILED;
    if (state->phase != HYBRID580_PM_ADMISSION_CLOSED || !state->frontend_blocked)
        return HYBRID580_PM_INVALID;
    if (state->channels_suspended != 0 || state->uvm_suspended)
        return HYBRID580_PM_INVALID;

    state->phase = HYBRID580_PM_DPM_SUSPENDING;

    /* This runs only after the process freezer has completed. */
    error = ops->drain_frontend(ops->context);
    if (error != 0)
        goto rollback;

    for (i = 0; i < sizeof(suspend_order) / sizeof(suspend_order[0]); ++i) {
        unsigned int backend = suspend_order[i];

        state->channels_suspended |=
            hybrid580_system_pm_backend_mask(backend);
        error = ops->suspend_channels(ops->context, backend);
        if (error != 0)
            goto rollback;
    }

    /*
     * Wait for each provider's current hard and threaded IRQ handlers only
     * after every provider's channel-suspend callback has succeeded. This does
     * not mask future interrupts. The current R580 callback issues a global
     * scheduling-disable control; its runtime preemption guarantee remains
     * unverified. A kernel adapter must prove that no new fault-capable work
     * can appear before using this as the UVM boundary.
     */
    for (i = 0; i < sizeof(drain_order) / sizeof(drain_order[0]); ++i) {
        error = ops->drain_irqs(ops->context, drain_order[i]);
        if (error != 0)
            goto rollback;
    }

    error = ops->suspend_uvm(ops->context);
    if (error != 0)
        goto rollback;
    state->uvm_suspended = true;
    state->phase = HYBRID580_PM_SUSPENDED;
    return HYBRID580_PM_OK;

rollback:
    state->original_error = error;

    /* UVM is resumed before any user channel is restored. */
    if (state->uvm_suspended) {
        int cleanup = ops->resume_uvm(ops->context);

        if (cleanup != 0) {
            state->cleanup_error = cleanup;
            state->phase = HYBRID580_PM_FAILED;
            return HYBRID580_PM_ROLLBACK_FAILED;
        }
        state->uvm_suspended = false;
    }

    for (i = 0; i < sizeof(rollback_order) / sizeof(rollback_order[0]); ++i) {
        unsigned int backend = rollback_order[i];
        unsigned int mask = hybrid580_system_pm_backend_mask(backend);
        int cleanup;

        if ((state->channels_suspended & mask) == 0)
            continue;
        cleanup = ops->restore_channels(ops->context, backend);
        if (cleanup == 0)
            state->channels_suspended &= ~mask;
        else if (state->cleanup_error == 0)
            state->cleanup_error = cleanup;
    }

    if (state->cleanup_error == 0 && state->channels_suspended == 0) {
        state->phase = HYBRID580_PM_ADMISSION_CLOSED;
        return error;
    }

    state->phase = HYBRID580_PM_FAILED;
    return HYBRID580_PM_ROLLBACK_FAILED;
}

static inline int
hybrid580_system_pm_resume_after_suppliers_for_event(
    struct hybrid580_system_pm *state,
    const struct hybrid580_system_pm_ops *ops,
    enum hybrid580_pm_dpm_event event)
{
    static const unsigned int recover_order[] = {
        HYBRID580_PM_BACKEND_OPEN,
        HYBRID580_PM_BACKEND_LEGACY,
    };
    static const unsigned int restore_order[] = {
        HYBRID580_PM_BACKEND_LEGACY,
        HYBRID580_PM_BACKEND_OPEN,
    };
    size_t i;
    int error;

    if (state == NULL || !hybrid580_system_pm_ops_valid(ops))
        return HYBRID580_PM_INVALID;
    if (state->phase == HYBRID580_PM_FAILED)
        return HYBRID580_PM_RESUME_FAILED;
    if (state->phase != HYBRID580_PM_SUSPENDED)
        return HYBRID580_PM_INVALID;
    if (!state->frontend_blocked || !state->uvm_suspended ||
        state->channels_suspended != HYBRID580_PM_ALL_BACKENDS)
        return HYBRID580_PM_INVALID;

    state->phase = HYBRID580_PM_DPM_RESUMING;
    state->original_error = 0;
    state->cleanup_error = 0;

    /* Restore every provider's device before reopening the shared UVM. */
    for (i = 0; i < sizeof(recover_order) / sizeof(recover_order[0]); ++i) {
        error = ops->recover_and_verify_devices(ops->context, recover_order[i],
                                                state->generation, event);
        if (error != 0 && state->original_error == 0)
            state->original_error = error;
    }

    /* The provider latches span exactly one Linux DPM recovery event. Always
     * retire them before attempting to resume shared UVM, even on errors. */
    error = hybrid580_system_pm_end_recovery_cycles(state, ops);
    if (error != 0 && state->original_error == 0)
        state->original_error = error;
    if (state->original_error != 0) {
        state->phase = HYBRID580_PM_FAILED;
        return HYBRID580_PM_RESUME_FAILED;
    }

    error = ops->resume_uvm(ops->context);
    if (error != 0) {
        state->original_error = error;
        state->phase = HYBRID580_PM_FAILED;
        return HYBRID580_PM_RESUME_FAILED;
    }
    state->uvm_suspended = false;

    for (i = 0; i < sizeof(restore_order) / sizeof(restore_order[0]); ++i) {
        unsigned int backend = restore_order[i];
        unsigned int mask = hybrid580_system_pm_backend_mask(backend);

        error = ops->restore_channels(ops->context, backend);
        if (error == 0)
            state->channels_suspended &= ~mask;
        else if (state->cleanup_error == 0)
            state->cleanup_error = error;
    }

    if (state->cleanup_error != 0 || state->channels_suspended != 0) {
        state->original_error = state->cleanup_error != 0 ?
                                state->cleanup_error : -EIO;
        state->phase = HYBRID580_PM_FAILED;
        return HYBRID580_PM_RESUME_FAILED;
    }

    /* User admission stays closed until the matching post notifier. */
    state->phase = HYBRID580_PM_DPM_RESUMED;
    return HYBRID580_PM_OK;
}

static inline int
hybrid580_system_pm_resume_after_suppliers(struct hybrid580_system_pm *state,
                                           const struct hybrid580_system_pm_ops *ops)
{
    return hybrid580_system_pm_resume_after_suppliers_for_event(
        state, ops, HYBRID580_PM_DPM_RESUME);
}

static inline int
hybrid580_system_pm_complete_for_cycle(struct hybrid580_system_pm *state,
                                      const struct hybrid580_system_pm_ops *ops,
                                      enum hybrid580_pm_cycle cycle)
{
    int error;

    if (!hybrid580_pm_cycle_valid(cycle))
        return HYBRID580_PM_INVALID;
    if (state == NULL || !hybrid580_system_pm_ops_valid(ops))
        return HYBRID580_PM_INVALID;
    if (state->phase == HYBRID580_PM_FAILED)
        return HYBRID580_PM_RESUME_FAILED;
    if (state->phase != HYBRID580_PM_ADMISSION_CLOSED &&
        state->phase != HYBRID580_PM_DPM_RESUMED)
        return HYBRID580_PM_INVALID;
    if (!state->frontend_blocked || state->uvm_suspended ||
        state->channels_suspended != 0 || state->cycle != cycle)
        return HYBRID580_PM_INVALID;

    /* A DPM abort may skip the aggregate resume event. Retire any remaining
     * bookkeeping before reopening user admission. */
    error = hybrid580_system_pm_end_recovery_cycles(state, ops);
    if (error != 0) {
        state->original_error = error;
        state->phase = HYBRID580_PM_FAILED;
        return HYBRID580_PM_RESUME_FAILED;
    }

    error = ops->unblock_frontend(ops->context);
    if (error != 0) {
        state->original_error = error;
        state->phase = HYBRID580_PM_FAILED;
        return HYBRID580_PM_RESUME_FAILED;
    }

    state->frontend_blocked = false;
    state->phase = HYBRID580_PM_RUNNING;
    state->cycle = HYBRID580_PM_CYCLE_NONE;
    return HYBRID580_PM_OK;
}

static inline int
hybrid580_system_pm_complete(struct hybrid580_system_pm *state,
                             const struct hybrid580_system_pm_ops *ops)
{
    return hybrid580_system_pm_complete_for_cycle(
        state, ops, HYBRID580_PM_CYCLE_SUSPEND);
}

static inline int
hybrid580_system_pm_notify(struct hybrid580_system_pm *state,
                           const struct hybrid580_system_pm_ops *ops,
                           enum hybrid580_pm_notifier_event event)
{
    if (state == NULL || !hybrid580_system_pm_ops_valid(ops))
        return HYBRID580_PM_INVALID;

    switch (event) {
    case HYBRID580_PM_NOTIFY_SUSPEND_PREPARE:
        return hybrid580_system_pm_begin_for_cycle(
            state, ops, HYBRID580_PM_CYCLE_SUSPEND);
    case HYBRID580_PM_NOTIFY_POST_SUSPEND:
        return hybrid580_system_pm_complete_for_cycle(
            state, ops, HYBRID580_PM_CYCLE_SUSPEND);
    case HYBRID580_PM_NOTIFY_HIBERNATION_PREPARE:
        return hybrid580_system_pm_begin_for_cycle(
            state, ops, HYBRID580_PM_CYCLE_HIBERNATION);
    case HYBRID580_PM_NOTIFY_POST_HIBERNATION:
        return hybrid580_system_pm_complete_for_cycle(
            state, ops, HYBRID580_PM_CYCLE_HIBERNATION);
    case HYBRID580_PM_NOTIFY_RESTORE_PREPARE:
        return hybrid580_system_pm_begin_for_cycle(
            state, ops, HYBRID580_PM_CYCLE_RESTORE);
    case HYBRID580_PM_NOTIFY_POST_RESTORE:
        return hybrid580_system_pm_complete_for_cycle(
            state, ops, HYBRID580_PM_CYCLE_RESTORE);
    case HYBRID580_PM_NOTIFY_UNRELATED:
    default:
        return HYBRID580_PM_IGNORED;
    }
}

enum hybrid580_pm_dpm_action {
    HYBRID580_PM_DPM_ACTION_IGNORE = 0,
    HYBRID580_PM_DPM_ACTION_QUIESCE,
    HYBRID580_PM_DPM_ACTION_RESTORE,
};

static inline enum hybrid580_pm_dpm_action
hybrid580_pm_dpm_action_for_event(enum hybrid580_pm_dpm_event event)
{
    switch (event) {
    case HYBRID580_PM_DPM_SUSPEND:
    case HYBRID580_PM_DPM_FREEZE:
    case HYBRID580_PM_DPM_QUIESCE:
    case HYBRID580_PM_DPM_POWEROFF:
    case HYBRID580_PM_DPM_HIBERNATE:
        return HYBRID580_PM_DPM_ACTION_QUIESCE;
    case HYBRID580_PM_DPM_RESUME:
    case HYBRID580_PM_DPM_THAW:
    case HYBRID580_PM_DPM_RECOVER:
    case HYBRID580_PM_DPM_RESTORE:
        return HYBRID580_PM_DPM_ACTION_RESTORE;
    case HYBRID580_PM_DPM_UNRELATED:
    default:
        return HYBRID580_PM_DPM_ACTION_IGNORE;
    }
}

static inline int
hybrid580_system_pm_dpm(struct hybrid580_system_pm *state,
                        const struct hybrid580_system_pm_ops *ops,
                        enum hybrid580_pm_dpm_event event)
{
    enum hybrid580_pm_dpm_action action = hybrid580_pm_dpm_action_for_event(event);

    if (state == NULL || !hybrid580_system_pm_ops_valid(ops))
        return HYBRID580_PM_INVALID;
    if (action == HYBRID580_PM_DPM_ACTION_IGNORE)
        return HYBRID580_PM_IGNORED;
    if (action == HYBRID580_PM_DPM_ACTION_QUIESCE)
        return hybrid580_system_pm_suspend_after_freezer(state, ops);

    /* A previous suspend/freeze callback may have rolled itself back before
     * Linux sends the matching THAW/RECOVER. Do not restore it a second time. */
    if (state->phase == HYBRID580_PM_ADMISSION_CLOSED &&
        state->cycle != HYBRID580_PM_CYCLE_NONE && state->frontend_blocked &&
        !state->uvm_suspended && state->channels_suspended == 0)
        return HYBRID580_PM_OK;
    return hybrid580_system_pm_resume_after_suppliers_for_event(state, ops, event);
}

#endif /* HYBRID580_SYSTEM_PM_COORDINATOR_H */
