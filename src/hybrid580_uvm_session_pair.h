/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_SESSION_PAIR_H
#define HYBRID580_UVM_SESSION_PAIR_H

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <string.h>
#endif

#include "hybrid580_uvm_owner_map.h"

/* A pair is a CPU-side contract for one logical UVM session backed by two
 * independent RM sessions. It is not wired into the kernel frontend. The
 * caller must serialize every operation and keep each provider context alive
 * until the pair reaches EMPTY. Provider create callbacks set *handle to zero
 * first; on failure, a nonzero output means a partial resource is owned and
 * must be destroyed. A RETRYABLE destroy result guarantees that ownership was
 * not released, so retry cannot double-free. AMBIGUOUS is quarantined forever
 * by this primitive and is never retried. The initialized pair is itself
 * noncopyable: bytewise copies would duplicate ownership of both native RM
 * sessions. Move it only while externally serialized, then clear the source.
 */
enum hybrid580_uvm_destroy_result {
    HYBRID580_UVM_DESTROYED = 0,
    HYBRID580_UVM_DESTROY_RETRYABLE = 1,
    HYBRID580_UVM_DESTROY_AMBIGUOUS = 2,
};

enum hybrid580_uvm_session_pair_status {
    HYBRID580_UVM_SESSION_OK = 0,
    HYBRID580_UVM_SESSION_OPEN_CREATE_FAILED = -1,
    HYBRID580_UVM_SESSION_LEGACY_CREATE_FAILED = -2,
    HYBRID580_UVM_SESSION_INVALID = -3,
    HYBRID580_UVM_SESSION_BUSY = -4,
    HYBRID580_UVM_SESSION_INVALID_HANDLE = -5,
    HYBRID580_UVM_SESSION_ROLLBACK_PENDING = -6,
    HYBRID580_UVM_SESSION_DESTROY_PENDING = -7,
    HYBRID580_UVM_SESSION_QUARANTINED = -8,
};

enum hybrid580_uvm_session_pair_state {
    HYBRID580_UVM_SESSION_PAIR_EMPTY = 0,
    HYBRID580_UVM_SESSION_PAIR_ACTIVE = 1,
    HYBRID580_UVM_SESSION_PAIR_CLEANUP_PENDING = 2,
    HYBRID580_UVM_SESSION_PAIR_QUARANTINED = 3,
};

struct hybrid580_uvm_provider_ops {
    void *context;
    int (*create)(void *context, uintptr_t *handle);
    enum hybrid580_uvm_destroy_result (*destroy)(void *context, uintptr_t handle);
};

struct hybrid580_uvm_session_pair {
    uintptr_t public_identity;
    uintptr_t native_open;
    uintptr_t native_legacy;
    uint8_t live_mask;
    uint8_t quarantined_mask;
    enum hybrid580_uvm_session_pair_state state;
    struct hybrid580_uvm_provider_ops open_ops;
    struct hybrid580_uvm_provider_ops legacy_ops;
};

static inline void hybrid580_uvm_session_pair_reset(
    struct hybrid580_uvm_session_pair *pair)
{
    memset(pair, 0, sizeof(*pair));
}

static inline enum hybrid580_uvm_session_pair_status
hybrid580_uvm_session_pair_destroy_one(struct hybrid580_uvm_session_pair *pair,
                                       enum hybrid580_uvm_provider provider)
{
    uint8_t bit = (uint8_t)provider;
    uintptr_t *handle;
    struct hybrid580_uvm_provider_ops *ops;
    enum hybrid580_uvm_destroy_result result;

    if ((pair->live_mask & bit) == 0 || (pair->quarantined_mask & bit) != 0)
        return HYBRID580_UVM_SESSION_OK;
    if (provider == HYBRID580_UVM_PROVIDER_OPEN) {
        handle = &pair->native_open;
        ops = &pair->open_ops;
    } else {
        handle = &pair->native_legacy;
        ops = &pair->legacy_ops;
    }
    if (*handle == 0 || ops->destroy == NULL) {
        pair->quarantined_mask |= bit;
        pair->state = HYBRID580_UVM_SESSION_PAIR_QUARANTINED;
        return HYBRID580_UVM_SESSION_QUARANTINED;
    }

    result = ops->destroy(ops->context, *handle);
    if (result == HYBRID580_UVM_DESTROYED) {
        pair->live_mask &= (uint8_t)~bit;
        *handle = 0;
        return HYBRID580_UVM_SESSION_OK;
    }
    if (result == HYBRID580_UVM_DESTROY_RETRYABLE) {
        pair->state = HYBRID580_UVM_SESSION_PAIR_CLEANUP_PENDING;
        return HYBRID580_UVM_SESSION_DESTROY_PENDING;
    }

    /* Unknown enum values are treated as ambiguous, never as retryable. */
    pair->quarantined_mask |= bit;
    pair->state = HYBRID580_UVM_SESSION_PAIR_QUARANTINED;
    return HYBRID580_UVM_SESSION_QUARANTINED;
}

static inline enum hybrid580_uvm_session_pair_status
hybrid580_uvm_session_pair_finish_cleanup(struct hybrid580_uvm_session_pair *pair)
{
    if (pair->quarantined_mask != 0) {
        pair->state = HYBRID580_UVM_SESSION_PAIR_QUARANTINED;
        return HYBRID580_UVM_SESSION_QUARANTINED;
    }
    if (pair->live_mask != 0) {
        pair->state = HYBRID580_UVM_SESSION_PAIR_CLEANUP_PENDING;
        return HYBRID580_UVM_SESSION_DESTROY_PENDING;
    }
    hybrid580_uvm_session_pair_reset(pair);
    return HYBRID580_UVM_SESSION_OK;
}

static inline enum hybrid580_uvm_session_pair_status
hybrid580_uvm_session_pair_rollback(struct hybrid580_uvm_session_pair *pair,
                                    enum hybrid580_uvm_provider first,
                                    enum hybrid580_uvm_provider second,
                                    enum hybrid580_uvm_session_pair_status original)
{
    (void)hybrid580_uvm_session_pair_destroy_one(pair, first);
    if (second != 0)
        (void)hybrid580_uvm_session_pair_destroy_one(pair, second);
    if (pair->live_mask == 0 && pair->quarantined_mask == 0) {
        hybrid580_uvm_session_pair_reset(pair);
        return original;
    }
    return hybrid580_uvm_session_pair_finish_cleanup(pair) ==
                   HYBRID580_UVM_SESSION_QUARANTINED
               ? HYBRID580_UVM_SESSION_QUARANTINED
               : HYBRID580_UVM_SESSION_ROLLBACK_PENDING;
}

static inline enum hybrid580_uvm_session_pair_status
hybrid580_uvm_session_pair_create(struct hybrid580_uvm_session_pair *pair,
                                  struct hybrid580_uvm_provider_ops open_ops,
                                  struct hybrid580_uvm_provider_ops legacy_ops)
{
    uintptr_t open_handle = 0;
    uintptr_t legacy_handle = 0;
    int status;

    if (pair == NULL)
        return HYBRID580_UVM_SESSION_INVALID;
    if (pair->state != HYBRID580_UVM_SESSION_PAIR_EMPTY)
        return HYBRID580_UVM_SESSION_BUSY;
    if (pair->live_mask != 0 || pair->quarantined_mask != 0 ||
        pair->public_identity != 0 || pair->native_open != 0 ||
        pair->native_legacy != 0 || open_ops.create == NULL ||
        open_ops.destroy == NULL || legacy_ops.create == NULL ||
        legacy_ops.destroy == NULL)
        return HYBRID580_UVM_SESSION_INVALID;

    pair->open_ops = open_ops;
    pair->legacy_ops = legacy_ops;
    status = open_ops.create(open_ops.context, &open_handle);
    if (status != 0) {
        if (open_handle == 0) {
            hybrid580_uvm_session_pair_reset(pair);
            return HYBRID580_UVM_SESSION_OPEN_CREATE_FAILED;
        }
        pair->native_open = open_handle;
        pair->live_mask = HYBRID580_UVM_PROVIDER_OPEN;
        pair->state = HYBRID580_UVM_SESSION_PAIR_CLEANUP_PENDING;
        return hybrid580_uvm_session_pair_rollback(
            pair, HYBRID580_UVM_PROVIDER_OPEN, 0,
            HYBRID580_UVM_SESSION_OPEN_CREATE_FAILED);
    }
    if (open_handle == 0) {
        hybrid580_uvm_session_pair_reset(pair);
        return HYBRID580_UVM_SESSION_INVALID_HANDLE;
    }
    pair->native_open = open_handle;
    pair->live_mask = HYBRID580_UVM_PROVIDER_OPEN;

    status = legacy_ops.create(legacy_ops.context, &legacy_handle);
    if (status != 0) {
        if (legacy_handle != 0) {
            pair->native_legacy = legacy_handle;
            pair->live_mask |= HYBRID580_UVM_PROVIDER_LEGACY;
            return hybrid580_uvm_session_pair_rollback(
                pair, HYBRID580_UVM_PROVIDER_LEGACY,
                HYBRID580_UVM_PROVIDER_OPEN,
                HYBRID580_UVM_SESSION_LEGACY_CREATE_FAILED);
        }
        return hybrid580_uvm_session_pair_rollback(
            pair, HYBRID580_UVM_PROVIDER_OPEN, 0,
            HYBRID580_UVM_SESSION_LEGACY_CREATE_FAILED);
    }
    if (legacy_handle == 0)
        return hybrid580_uvm_session_pair_rollback(
            pair, HYBRID580_UVM_PROVIDER_OPEN, 0,
            HYBRID580_UVM_SESSION_INVALID_HANDLE);

    pair->native_legacy = legacy_handle;
    pair->live_mask = HYBRID580_UVM_PROVIDER_BOTH;
    pair->public_identity = open_handle;
    pair->state = HYBRID580_UVM_SESSION_PAIR_ACTIVE;
    return HYBRID580_UVM_SESSION_OK;
}

/* Success clears the public identity before releasing either backend. A
 * retryable result preserves only still-owned handles; ambiguous outcomes are
 * retained and never dispatched again. Provider cleanup order is Open then
 * proprietary and is an abstraction choice, not a proven RM ordering rule.
 */
static inline enum hybrid580_uvm_session_pair_status
hybrid580_uvm_session_pair_publish_identity(
    struct hybrid580_uvm_session_pair *pair, uintptr_t public_identity)
{
    if (pair == NULL || public_identity == 0 ||
        pair->state != HYBRID580_UVM_SESSION_PAIR_ACTIVE ||
        pair->live_mask != HYBRID580_UVM_PROVIDER_BOTH ||
        pair->native_open == 0 || pair->native_legacy == 0 ||
        public_identity == pair->native_open ||
        public_identity == pair->native_legacy)
        return HYBRID580_UVM_SESSION_INVALID;

    pair->public_identity = public_identity;
    return HYBRID580_UVM_SESSION_OK;
}

static inline enum hybrid580_uvm_session_pair_status
hybrid580_uvm_session_pair_destroy(struct hybrid580_uvm_session_pair *pair)
{
    if (pair == NULL)
        return HYBRID580_UVM_SESSION_INVALID;
    if (pair->state == HYBRID580_UVM_SESSION_PAIR_EMPTY)
        return HYBRID580_UVM_SESSION_OK;
    if (pair->state != HYBRID580_UVM_SESSION_PAIR_ACTIVE &&
        pair->state != HYBRID580_UVM_SESSION_PAIR_CLEANUP_PENDING &&
        pair->state != HYBRID580_UVM_SESSION_PAIR_QUARANTINED)
        return HYBRID580_UVM_SESSION_INVALID;

    pair->public_identity = 0;
    (void)hybrid580_uvm_session_pair_destroy_one(
        pair, HYBRID580_UVM_PROVIDER_OPEN);
    (void)hybrid580_uvm_session_pair_destroy_one(
        pair, HYBRID580_UVM_PROVIDER_LEGACY);
    return hybrid580_uvm_session_pair_finish_cleanup(pair);
}

#endif /* HYBRID580_UVM_SESSION_PAIR_H */
