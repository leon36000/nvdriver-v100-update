/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_FRONTEND_ADMISSION_H
#define HYBRID580_FRONTEND_ADMISSION_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#endif

/*
 * Small state contract shared by the frontend and its CPU fixture. Every
 * helper with a `_locked` suffix requires the caller to serialize the state.
 * The kernel adapter uses a spinlock; the fixture uses a pthread mutex.
 */
struct hybrid580_frontend_admission_state {
    unsigned int active;
    bool blocked;
};

static inline void
hybrid580_frontend_admission_init(
    struct hybrid580_frontend_admission_state *state)
{
    if (state == NULL)
        return;
    state->active = 0;
    state->blocked = false;
}

static inline int
hybrid580_frontend_admission_try_enter_locked(
    struct hybrid580_frontend_admission_state *state)
{
    if (state == NULL)
        return -EINVAL;
    if (state->blocked)
        return -EAGAIN;
    if (state->active == ~0U)
        return -EOVERFLOW;
    ++state->active;
    return 0;
}

static inline int
hybrid580_frontend_admission_leave_locked(
    struct hybrid580_frontend_admission_state *state)
{
    if (state == NULL || state->active == 0)
        return -EINVAL;
    --state->active;
    return 0;
}

static inline int
hybrid580_frontend_admission_block_locked(
    struct hybrid580_frontend_admission_state *state)
{
    if (state == NULL)
        return -EINVAL;
    if (state->blocked)
        return -EBUSY;
    state->blocked = true;
    return 0;
}

static inline int
hybrid580_frontend_admission_unblock_locked(
    struct hybrid580_frontend_admission_state *state)
{
    if (state == NULL || !state->blocked)
        return -EINVAL;
    state->blocked = false;
    return 0;
}

static inline bool
hybrid580_frontend_admission_is_drained_locked(
    const struct hybrid580_frontend_admission_state *state)
{
    return state != NULL && state->active == 0;
}

static inline bool
hybrid580_frontend_admission_is_blocked_locked(
    const struct hybrid580_frontend_admission_state *state)
{
    return state == NULL || state->blocked;
}

#endif
