/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_INFO_REGISTRY_H
#define HYBRID580_UVM_INFO_REGISTRY_H

#include "hybrid580_uvm_device_route.h"

#define HYBRID580_UVM_INFO_BUCKET_COUNT 64U

enum hybrid580_uvm_info_kind {
    HYBRID580_UVM_INFO_FAULT = 1,
    HYBRID580_UVM_INFO_ACCESS_COUNTER = 2,
    HYBRID580_UVM_INFO_CSL = 3,
};

enum hybrid580_uvm_info_status {
    HYBRID580_UVM_INFO_OK = 0,
    HYBRID580_UVM_INFO_INVALID = -1,
    HYBRID580_UVM_INFO_NOT_FOUND = -2,
    HYBRID580_UVM_INFO_DUPLICATE = -3,
    HYBRID580_UVM_INFO_BUSY = -4,
    HYBRID580_UVM_INFO_OWNER_MISMATCH = -5,
    HYBRID580_UVM_INFO_QUARANTINED = -6,
    HYBRID580_UVM_INFO_OVERFLOW = -7,
    HYBRID580_UVM_INFO_CROSS_PROVIDER = -8,
};

/* identity is the address of a UVM-owned R580 ABI info structure. Fast fault
 * APIs receive no device argument, so the registry preserves which private RM
 * populated that structure. The bridge protects every operation here with a
 * spinlock; backend calls run after dropping it while an active pin prevents
 * teardown. */
struct hybrid580_uvm_info_entry {
    uintptr_t identity;
    uintptr_t device_identity;
    uintptr_t parent_identity;
    enum hybrid580_uvm_provider provider;
    enum hybrid580_uvm_info_kind kind;
    uint32_t active_calls;
    uint8_t retiring;
    uint8_t quarantined;
    struct hybrid580_uvm_info_entry *next;
};

struct hybrid580_uvm_info_registry {
    size_t count;
    struct hybrid580_uvm_info_entry *buckets[
        HYBRID580_UVM_INFO_BUCKET_COUNT];
};

struct hybrid580_uvm_info_pin {
    struct hybrid580_uvm_info_entry *entry;
    uintptr_t identity;
    uintptr_t device_identity;
    enum hybrid580_uvm_provider provider;
    enum hybrid580_uvm_info_kind kind;
    uint8_t active;
};

static inline int hybrid580_uvm_info_kind_valid(
    enum hybrid580_uvm_info_kind kind)
{
    return kind == HYBRID580_UVM_INFO_FAULT ||
           kind == HYBRID580_UVM_INFO_ACCESS_COUNTER ||
           kind == HYBRID580_UVM_INFO_CSL;
}

static inline size_t hybrid580_uvm_info_bucket(uintptr_t identity)
{
    identity = (identity >> 4) ^ (identity >> 12) ^ (identity >> 21);
    return (size_t)(identity & (HYBRID580_UVM_INFO_BUCKET_COUNT - 1));
}

static inline struct hybrid580_uvm_info_entry **
hybrid580_uvm_info_find_link(struct hybrid580_uvm_info_registry *registry,
                             uintptr_t identity)
{
    struct hybrid580_uvm_info_entry **link;

    if (registry == NULL || identity == 0)
        return NULL;
    link = &registry->buckets[hybrid580_uvm_info_bucket(identity)];
    while (*link != NULL && (*link)->identity != identity)
        link = &(*link)->next;
    return link;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_record(
    struct hybrid580_uvm_info_registry *registry,
    struct hybrid580_uvm_info_entry *entry, uintptr_t identity,
    uintptr_t device_identity, enum hybrid580_uvm_provider provider,
    enum hybrid580_uvm_info_kind kind)
{
    struct hybrid580_uvm_info_entry **link;

    if (registry == NULL || entry == NULL || identity == 0 ||
        device_identity == 0 || !hybrid580_uvm_provider_is_single(provider) ||
        !hybrid580_uvm_info_kind_valid(kind) || entry->identity != 0 ||
        entry->device_identity != 0 || entry->parent_identity != 0 ||
        entry->provider != 0 ||
        entry->kind != 0 || entry->active_calls != 0 || entry->retiring ||
        entry->quarantined || entry->next != NULL)
        return HYBRID580_UVM_INFO_INVALID;
    link = hybrid580_uvm_info_find_link(registry, identity);
    if (link == NULL)
        return HYBRID580_UVM_INFO_INVALID;
    if (*link != NULL)
        return HYBRID580_UVM_INFO_DUPLICATE;

    entry->identity = identity;
    entry->device_identity = device_identity;
    entry->provider = provider;
    entry->kind = kind;
    entry->next = NULL;
    *link = entry;
    ++registry->count;
    return HYBRID580_UVM_INFO_OK;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_pin(
    struct hybrid580_uvm_info_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_info_kind kind, uintptr_t expected_device,
    struct hybrid580_uvm_info_pin *pin)
{
    struct hybrid580_uvm_info_entry **link;
    struct hybrid580_uvm_info_entry *entry;

    if (registry == NULL || pin == NULL || identity == 0 ||
        !hybrid580_uvm_info_kind_valid(kind))
        return HYBRID580_UVM_INFO_INVALID;
    link = hybrid580_uvm_info_find_link(registry, identity);
    if (link == NULL || *link == NULL)
        return HYBRID580_UVM_INFO_NOT_FOUND;
    entry = *link;
    if (entry->kind != kind ||
        (expected_device != 0 && entry->device_identity != expected_device))
        return HYBRID580_UVM_INFO_OWNER_MISMATCH;
    if (entry->quarantined)
        return HYBRID580_UVM_INFO_QUARANTINED;
    if (entry->retiring)
        return HYBRID580_UVM_INFO_BUSY;
    if (entry->active_calls == (uint32_t)~(uint32_t)0)
        return HYBRID580_UVM_INFO_OVERFLOW;

    ++entry->active_calls;
    *pin = (struct hybrid580_uvm_info_pin) {
        .entry = entry,
        .identity = entry->identity,
        .device_identity = entry->device_identity,
        .provider = entry->provider,
        .kind = entry->kind,
        .active = 1,
    };
    return HYBRID580_UVM_INFO_OK;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_unpin(
    struct hybrid580_uvm_info_registry *registry,
    struct hybrid580_uvm_info_pin *pin)
{
    struct hybrid580_uvm_info_entry **link;
    struct hybrid580_uvm_info_entry *entry;

    if (registry == NULL || pin == NULL || !pin->active || pin->entry == NULL)
        return HYBRID580_UVM_INFO_INVALID;
    link = hybrid580_uvm_info_find_link(registry, pin->identity);
    if (link == NULL || *link != pin->entry)
        return HYBRID580_UVM_INFO_NOT_FOUND;
    entry = *link;
    if (entry->identity != pin->identity || entry->kind != pin->kind ||
        entry->provider != pin->provider ||
        entry->device_identity != pin->device_identity ||
        entry->active_calls == 0) {
        entry->quarantined = 1;
        return HYBRID580_UVM_INFO_QUARANTINED;
    }

    --entry->active_calls;
    pin->active = 0;
    pin->entry = NULL;
    return HYBRID580_UVM_INFO_OK;
}

/* Pin a transaction's complete context set under the caller's spinlock.
 * CSL key rotation has one provider stack, so mixed-owner context arrays must
 * be rejected before any RM observes them. On any error all acquired pins are
 * released before returning. */
static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_pin_many_same_provider(
    struct hybrid580_uvm_info_registry *registry,
    const uintptr_t *identities, size_t count,
    enum hybrid580_uvm_info_kind kind,
    struct hybrid580_uvm_info_pin *pins,
    enum hybrid580_uvm_provider *provider_out)
{
    enum hybrid580_uvm_provider provider = 0;
    enum hybrid580_uvm_info_status status;
    size_t i, j;

    if (provider_out != NULL)
        *provider_out = 0;
    if (registry == NULL || identities == NULL || pins == NULL || count == 0 ||
        !hybrid580_uvm_info_kind_valid(kind))
        return HYBRID580_UVM_INFO_INVALID;

    /* Do not overwrite a caller's existing pin and silently leak its active
     * reference. Callers pass a zeroed array for each new transaction. */
    for (i = 0; i < count; ++i) {
        if (pins[i].active || pins[i].entry != NULL)
            return HYBRID580_UVM_INFO_INVALID;
    }

    for (i = 0; i < count; ++i) {
        if (identities[i] == 0) {
            status = HYBRID580_UVM_INFO_INVALID;
            goto unwind;
        }
        for (j = 0; j < i; ++j) {
            if (identities[j] == identities[i]) {
                status = HYBRID580_UVM_INFO_DUPLICATE;
                goto unwind;
            }
        }
        status = hybrid580_uvm_info_registry_pin(
            registry, identities[i], kind, 0, &pins[i]);
        if (status != HYBRID580_UVM_INFO_OK)
            goto unwind;
        if (i == 0)
            provider = pins[i].provider;
        else if (provider != pins[i].provider) {
            status = HYBRID580_UVM_INFO_CROSS_PROVIDER;
            ++i;
            goto unwind;
        }
    }
    if (provider_out != NULL)
        *provider_out = provider;
    return HYBRID580_UVM_INFO_OK;

unwind:
    while (i > 0) {
        --i;
        if (pins[i].active &&
            hybrid580_uvm_info_registry_unpin(registry, &pins[i]) !=
                HYBRID580_UVM_INFO_OK)
            return HYBRID580_UVM_INFO_QUARANTINED;
    }
    return status;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_unpin_many(
    struct hybrid580_uvm_info_registry *registry,
    struct hybrid580_uvm_info_pin *pins, size_t count)
{
    enum hybrid580_uvm_info_status status = HYBRID580_UVM_INFO_OK;
    size_t i;

    if (registry == NULL || pins == NULL)
        return HYBRID580_UVM_INFO_INVALID;
    for (i = count; i > 0; --i) {
        if (pins[i - 1].active &&
            hybrid580_uvm_info_registry_unpin(registry, &pins[i - 1]) !=
                HYBRID580_UVM_INFO_OK)
            status = HYBRID580_UVM_INFO_QUARANTINED;
    }
    return status;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_begin_retire(
    struct hybrid580_uvm_info_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_info_kind kind, uintptr_t expected_device,
    struct hybrid580_uvm_info_entry **entry_out)
{
    struct hybrid580_uvm_info_entry **link;
    struct hybrid580_uvm_info_entry *entry;

    if (entry_out != NULL)
        *entry_out = NULL;
    if (registry == NULL || identity == 0 ||
        !hybrid580_uvm_info_kind_valid(kind))
        return HYBRID580_UVM_INFO_INVALID;
    link = hybrid580_uvm_info_find_link(registry, identity);
    if (link == NULL || *link == NULL)
        return HYBRID580_UVM_INFO_NOT_FOUND;
    entry = *link;
    if (entry->kind != kind ||
        (expected_device != 0 && entry->device_identity != expected_device))
        return HYBRID580_UVM_INFO_OWNER_MISMATCH;
    if (entry->quarantined)
        return HYBRID580_UVM_INFO_QUARANTINED;
    if (entry->retiring || entry->active_calls != 0)
        return HYBRID580_UVM_INFO_BUSY;

    entry->retiring = 1;
    if (entry_out != NULL)
        *entry_out = entry;
    return HYBRID580_UVM_INFO_OK;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_finish_retire(
    struct hybrid580_uvm_info_registry *registry,
    struct hybrid580_uvm_info_entry *entry, int backend_succeeded,
    struct hybrid580_uvm_info_entry **removed)
{
    struct hybrid580_uvm_info_entry **link;

    if (removed != NULL)
        *removed = NULL;
    if (registry == NULL || entry == NULL || !entry->retiring ||
        entry->active_calls != 0 || entry->identity == 0)
        return HYBRID580_UVM_INFO_INVALID;
    link = hybrid580_uvm_info_find_link(registry, entry->identity);
    if (link == NULL || *link != entry) {
        entry->quarantined = 1;
        return HYBRID580_UVM_INFO_QUARANTINED;
    }
    if (!backend_succeeded) {
        entry->retiring = 0;
        return HYBRID580_UVM_INFO_OK;
    }

    *link = entry->next;
    entry->next = NULL;
    --registry->count;
    if (removed != NULL)
        *removed = entry;
    return HYBRID580_UVM_INFO_OK;
}

static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_quarantine(
    struct hybrid580_uvm_info_registry *registry, uintptr_t identity)
{
    struct hybrid580_uvm_info_entry **link =
        hybrid580_uvm_info_find_link(registry, identity);

    if (link == NULL || *link == NULL)
        return HYBRID580_UVM_INFO_NOT_FOUND;
    (*link)->quarantined = 1;
    return HYBRID580_UVM_INFO_OK;
}

static inline int hybrid580_uvm_info_registry_has_parent(
    const struct hybrid580_uvm_info_registry *registry,
    uintptr_t device_identity)
{
    size_t i;

    if (registry == NULL || device_identity == 0)
        return 0;
    for (i = 0; i < HYBRID580_UVM_INFO_BUCKET_COUNT; ++i) {
        const struct hybrid580_uvm_info_entry *entry;
        for (entry = registry->buckets[i]; entry != NULL; entry = entry->next) {
            if (entry->device_identity == device_identity)
                return 1;
        }
    }
    return 0;
}

/* CSL contexts created for channels carry a second lifetime edge. Fault-buffer
 * CSL contexts are embedded in FaultInfo and intentionally have no channel
 * parent. The bridge sets this only while a just-recorded CSL entry is still
 * retiring, before backend initialization can publish it to fast paths. */
static inline enum hybrid580_uvm_info_status
hybrid580_uvm_info_registry_set_channel_parent(
    struct hybrid580_uvm_info_registry *registry, uintptr_t identity,
    uintptr_t device_identity, uintptr_t channel_identity)
{
    struct hybrid580_uvm_info_entry **link;

    if (registry == NULL || identity == 0 || device_identity == 0 ||
        channel_identity == 0 || identity == channel_identity)
        return HYBRID580_UVM_INFO_INVALID;
    link = hybrid580_uvm_info_find_link(registry, identity);
    if (link == NULL || *link == NULL)
        return HYBRID580_UVM_INFO_NOT_FOUND;
    if ((*link)->kind != HYBRID580_UVM_INFO_CSL ||
        (*link)->device_identity != device_identity)
        return HYBRID580_UVM_INFO_OWNER_MISMATCH;
    if (!(*link)->retiring || (*link)->quarantined ||
        (*link)->active_calls != 0)
        return HYBRID580_UVM_INFO_BUSY;
    if ((*link)->parent_identity != 0 &&
        (*link)->parent_identity != channel_identity)
        return HYBRID580_UVM_INFO_OWNER_MISMATCH;
    (*link)->parent_identity = channel_identity;
    return HYBRID580_UVM_INFO_OK;
}

static inline size_t hybrid580_uvm_info_registry_quarantine_channel_parent(
    const struct hybrid580_uvm_info_registry *registry,
    uintptr_t channel_identity)
{
    size_t i;
    size_t quarantined = 0;

    if (registry == NULL || channel_identity == 0)
        return 0;
    for (i = 0; i < HYBRID580_UVM_INFO_BUCKET_COUNT; ++i) {
        struct hybrid580_uvm_info_entry *entry;
        for (entry = registry->buckets[i]; entry != NULL; entry = entry->next) {
            if (entry->kind == HYBRID580_UVM_INFO_CSL &&
                entry->parent_identity == channel_identity) {
                entry->quarantined = 1;
                ++quarantined;
            }
        }
    }
    return quarantined;
}

#endif
