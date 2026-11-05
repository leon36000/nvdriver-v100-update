/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_IRQ_LIFECYCLE_CONTRACT_H
#define HYBRID580_IRQ_LIFECYCLE_CONTRACT_H

/*
 * CPU-testable protocol model for a future per-GPU IRQ lifecycle adapter.
 *
 * This contract is deliberately not wired into either NVIDIA provider. The
 * caller must serialize state transitions. mark_device_sources_masked()
 * records an externally completed GPU-specific source-mask operation; this
 * model cannot prove that R580 has a usable operation or that it handles a
 * handler already in flight. Shared Linux IRQ lines are never disabled here.
 * A production drain must remain fail-closed until those hardware/provider
 * semantics and all deferred-work producers are established from source.
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

#define HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS 64u

enum hybrid580_irq_mode {
    HYBRID580_IRQ_MODE_SHARED_LEGACY = 1,
    HYBRID580_IRQ_MODE_MSIX = 2,
};

enum hybrid580_irq_phase {
    HYBRID580_IRQ_PHASE_REGISTERING = 1,
    HYBRID580_IRQ_PHASE_LIVE,
    HYBRID580_IRQ_PHASE_QUIESCING,
    HYBRID580_IRQ_PHASE_QUIESCED,
    HYBRID580_IRQ_PHASE_RESUMING,
    HYBRID580_IRQ_PHASE_DEAD,
};

enum hybrid580_irq_owner {
    HYBRID580_IRQ_OWNER_NONE = 0,
    HYBRID580_IRQ_OWNER_PM,
    HYBRID580_IRQ_OWNER_LAST_CLOSE,
    HYBRID580_IRQ_OWNER_REMOVE,
    HYBRID580_IRQ_OWNER_SETUP_ABORT,
};

struct hybrid580_irq_lifecycle {
    enum hybrid580_irq_mode mode;
    enum hybrid580_irq_phase phase;
    enum hybrid580_irq_owner owner;
    unsigned int expected_vectors;
    unsigned long long expected_mask;
    unsigned long long registered_mask;
    unsigned long long synchronized_mask;
    unsigned int active_handlers[HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS];
    unsigned int deferred_pending;
    unsigned int deferred_running;
    bool device_sources_masked;
    bool admission_open;
    bool queue_flush_started;
    bool queue_flush_completed;
};

static inline unsigned long long
hybrid580_irq_lifecycle_mask(unsigned int count)
{
    if (count == HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS)
        return ~0ULL;
    return (1ULL << count) - 1ULL;
}

static inline bool
hybrid580_irq_lifecycle_owner_valid(enum hybrid580_irq_owner owner)
{
    return owner == HYBRID580_IRQ_OWNER_PM ||
           owner == HYBRID580_IRQ_OWNER_LAST_CLOSE ||
           owner == HYBRID580_IRQ_OWNER_REMOVE;
}

static inline int
hybrid580_irq_lifecycle_init(struct hybrid580_irq_lifecycle *state,
                             enum hybrid580_irq_mode mode,
                             unsigned int expected_vectors)
{
    unsigned int i;

    if (state == NULL || expected_vectors == 0 ||
        expected_vectors > HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS ||
        (mode != HYBRID580_IRQ_MODE_SHARED_LEGACY &&
         mode != HYBRID580_IRQ_MODE_MSIX) ||
        (mode == HYBRID580_IRQ_MODE_SHARED_LEGACY && expected_vectors != 1))
        return -EINVAL;

    state->mode = mode;
    state->phase = HYBRID580_IRQ_PHASE_REGISTERING;
    state->owner = HYBRID580_IRQ_OWNER_NONE;
    state->expected_vectors = expected_vectors;
    state->expected_mask = hybrid580_irq_lifecycle_mask(expected_vectors);
    state->registered_mask = 0;
    state->synchronized_mask = 0;
    state->deferred_pending = 0;
    state->deferred_running = 0;
    state->device_sources_masked = false;
    state->admission_open = false;
    state->queue_flush_started = false;
    state->queue_flush_completed = false;
    for (i = 0; i < HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS; ++i)
        state->active_handlers[i] = 0;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_mark_device_sources_masked(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL)
        return -EINVAL;
    if (state->phase != HYBRID580_IRQ_PHASE_REGISTERING &&
        state->phase != HYBRID580_IRQ_PHASE_QUIESCING &&
        state->phase != HYBRID580_IRQ_PHASE_RESUMING)
        return -EINVAL;
    state->device_sources_masked = true;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_register_vector(struct hybrid580_irq_lifecycle *state,
                                        unsigned int vector)
{
    unsigned long long bit;

    if (state == NULL || vector >= HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS)
        return -EINVAL;
    if (state->phase != HYBRID580_IRQ_PHASE_REGISTERING ||
        !state->device_sources_masked)
        return -ESHUTDOWN;
    if (vector >= state->expected_vectors)
        return -EINVAL;
    bit = 1ULL << vector;
    if ((state->registered_mask & bit) != 0)
        return -EALREADY;
    state->registered_mask |= bit;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_activate(struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_REGISTERING ||
        !state->device_sources_masked ||
        state->registered_mask != state->expected_mask)
        return -EINVAL;
    state->phase = HYBRID580_IRQ_PHASE_LIVE;
    state->admission_open = true;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_unmask_device_sources(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL ||
        (state->phase != HYBRID580_IRQ_PHASE_LIVE &&
         state->phase != HYBRID580_IRQ_PHASE_RESUMING) ||
        !state->admission_open || !state->device_sources_masked)
        return -EINVAL;

    state->device_sources_masked = false;
    if (state->phase == HYBRID580_IRQ_PHASE_RESUMING) {
        state->phase = HYBRID580_IRQ_PHASE_LIVE;
        state->owner = HYBRID580_IRQ_OWNER_NONE;
        state->synchronized_mask = 0;
        state->queue_flush_started = false;
        state->queue_flush_completed = false;
    }
    return 0;
}

static inline int
hybrid580_irq_lifecycle_handler_enter(struct hybrid580_irq_lifecycle *state,
                                      unsigned int vector)
{
    if (state == NULL || vector >= HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS)
        return -EINVAL;
    if (state->phase != HYBRID580_IRQ_PHASE_LIVE ||
        !state->admission_open || state->device_sources_masked)
        return -ESHUTDOWN;
    if ((state->registered_mask & (1ULL << vector)) == 0)
        return -EINVAL;
    if (state->active_handlers[vector] == ~0u)
        return -EOVERFLOW;
    state->active_handlers[vector]++;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_queue_from_handler(
    struct hybrid580_irq_lifecycle *state, unsigned int vector)
{
    if (state == NULL || vector >= HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS)
        return -EINVAL;
    if (state->queue_flush_started || state->queue_flush_completed ||
        state->phase == HYBRID580_IRQ_PHASE_QUIESCED ||
        state->phase == HYBRID580_IRQ_PHASE_DEAD)
        return -ESHUTDOWN;
    if (state->active_handlers[vector] == 0)
        return -EINVAL;
    if (state->deferred_pending == ~0u)
        return -EOVERFLOW;
    state->deferred_pending++;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_handler_exit(struct hybrid580_irq_lifecycle *state,
                                     unsigned int vector)
{
    if (state == NULL || vector >= HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS ||
        state->active_handlers[vector] == 0)
        return -EINVAL;
    state->active_handlers[vector]--;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_begin_quiesce(struct hybrid580_irq_lifecycle *state,
                                      enum hybrid580_irq_owner owner)
{
    if (state == NULL || !hybrid580_irq_lifecycle_owner_valid(owner))
        return -EINVAL;
    if (state->phase != HYBRID580_IRQ_PHASE_LIVE ||
        state->owner != HYBRID580_IRQ_OWNER_NONE ||
        state->device_sources_masked)
        return -EBUSY;
    state->phase = HYBRID580_IRQ_PHASE_QUIESCING;
    state->owner = owner;
    state->admission_open = false;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_abort_registration(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_REGISTERING ||
        !state->device_sources_masked)
        return -EINVAL;
    state->phase = HYBRID580_IRQ_PHASE_QUIESCING;
    state->owner = HYBRID580_IRQ_OWNER_SETUP_ABORT;
    state->admission_open = false;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_synchronize_vector(
    struct hybrid580_irq_lifecycle *state, unsigned int vector)
{
    unsigned long long bit;

    if (state == NULL || vector >= HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS)
        return -EINVAL;
    if (state->phase != HYBRID580_IRQ_PHASE_QUIESCING ||
        !state->device_sources_masked)
        return -EAGAIN;
    bit = 1ULL << vector;
    if ((state->registered_mask & bit) == 0)
        return -EINVAL;
    if (state->active_handlers[vector] != 0)
        return -EBUSY;
    if ((state->synchronized_mask & bit) != 0)
        return -EALREADY;
    state->synchronized_mask |= bit;
    return 0;
}

static inline bool
hybrid580_irq_lifecycle_handlers_idle(
    const struct hybrid580_irq_lifecycle *state)
{
    unsigned int i;

    for (i = 0; i < state->expected_vectors; ++i) {
        if (state->active_handlers[i] != 0)
            return false;
    }
    return true;
}

static inline int
hybrid580_irq_lifecycle_flush_queue_begin(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_QUIESCING)
        return -EINVAL;
    if (!state->device_sources_masked || !hybrid580_irq_lifecycle_handlers_idle(state) ||
        (state->synchronized_mask & state->registered_mask) != state->registered_mask ||
        state->queue_flush_started)
        return -EAGAIN;
    state->queue_flush_started = true;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_deferred_begin(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL ||
        (state->phase != HYBRID580_IRQ_PHASE_LIVE &&
         state->phase != HYBRID580_IRQ_PHASE_QUIESCING) ||
        state->queue_flush_completed || state->deferred_pending == 0)
        return -EINVAL;
    if (state->deferred_running == ~0u)
        return -EOVERFLOW;
    state->deferred_pending--;
    state->deferred_running++;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_deferred_complete(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL ||
        (state->phase != HYBRID580_IRQ_PHASE_LIVE &&
         state->phase != HYBRID580_IRQ_PHASE_QUIESCING) ||
        state->queue_flush_completed || state->deferred_running == 0)
        return -EINVAL;
    state->deferred_running--;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_flush_queue_complete(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_QUIESCING ||
        !state->queue_flush_started)
        return -EINVAL;
    if (state->deferred_pending != 0 || state->deferred_running != 0)
        return -EAGAIN;
    state->queue_flush_completed = true;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_quiesce_complete(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_QUIESCING ||
        !state->device_sources_masked ||
        (state->synchronized_mask & state->registered_mask) != state->registered_mask ||
        !hybrid580_irq_lifecycle_handlers_idle(state) ||
        !state->queue_flush_completed || state->deferred_pending != 0 ||
        state->deferred_running != 0)
        return -EAGAIN;
    state->phase = HYBRID580_IRQ_PHASE_QUIESCED;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_resume_begin(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_QUIESCED ||
        state->owner != HYBRID580_IRQ_OWNER_PM ||
        !state->device_sources_masked || !state->queue_flush_completed)
        return -EINVAL;
    state->phase = HYBRID580_IRQ_PHASE_RESUMING;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_resume_open_gate(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_RESUMING ||
        !state->device_sources_masked || state->admission_open)
        return -EINVAL;
    state->admission_open = true;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_release_vector(
    struct hybrid580_irq_lifecycle *state, unsigned int vector)
{
    unsigned long long bit;

    if (state == NULL || vector >= HYBRID580_IRQ_LIFECYCLE_MAX_VECTORS)
        return -EINVAL;
    if (state->phase != HYBRID580_IRQ_PHASE_QUIESCED ||
        state->owner == HYBRID580_IRQ_OWNER_NONE ||
        state->owner == HYBRID580_IRQ_OWNER_PM || !state->device_sources_masked ||
        !state->queue_flush_completed)
        return -EAGAIN;
    bit = 1ULL << vector;
    if ((state->registered_mask & bit) == 0 ||
        (state->synchronized_mask & bit) == 0 ||
        state->active_handlers[vector] != 0)
        return -EINVAL;
    state->registered_mask &= ~bit;
    state->synchronized_mask &= ~bit;
    return 0;
}

static inline int
hybrid580_irq_lifecycle_shutdown_complete(
    struct hybrid580_irq_lifecycle *state)
{
    if (state == NULL || state->phase != HYBRID580_IRQ_PHASE_QUIESCED ||
        state->owner == HYBRID580_IRQ_OWNER_NONE ||
        state->owner == HYBRID580_IRQ_OWNER_PM ||
        !state->device_sources_masked || state->registered_mask != 0 ||
        !state->queue_flush_completed || state->deferred_pending != 0 ||
        state->deferred_running != 0 ||
        !hybrid580_irq_lifecycle_handlers_idle(state))
        return -EAGAIN;
    state->phase = HYBRID580_IRQ_PHASE_DEAD;
    return 0;
}

#endif
