/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_PMA_ROUTE_H
#define HYBRID580_UVM_PMA_ROUTE_H

#include "hybrid580_uvm_device_route.h"

#define HYBRID580_UVM_PMA_REGISTRY_CAPACITY HYBRID580_UVM_GPU_REGISTRY_CAPACITY

struct hybrid580_uvm_pma_entry {
    uintptr_t native_pma;
    uintptr_t stats_identity;
    uintptr_t device_identity;
    enum hybrid580_uvm_provider provider;
    uint32_t active_calls;
    uint8_t callbacks_registered;
    uint8_t quarantined;
    uint8_t active;
};

struct hybrid580_uvm_pma_registry {
    uint32_t count;
    struct hybrid580_uvm_pma_entry
        entries[HYBRID580_UVM_PMA_REGISTRY_CAPACITY];
};

struct hybrid580_uvm_pma_pin {
    size_t slot;
    uintptr_t native_pma;
    uintptr_t device_identity;
    enum hybrid580_uvm_provider provider;
    uint8_t active;
};

enum hybrid580_uvm_pma_status {
    HYBRID580_UVM_PMA_OK = 0,
    HYBRID580_UVM_PMA_INVALID = -1,
    HYBRID580_UVM_PMA_NOT_FOUND = -2,
    HYBRID580_UVM_PMA_AMBIGUOUS = -3,
    HYBRID580_UVM_PMA_FULL = -4,
    HYBRID580_UVM_PMA_BUSY = -5,
};

static inline size_t hybrid580_uvm_pma_find_free(
    const struct hybrid580_uvm_pma_registry *registry)
{
    size_t i;

    if (registry == NULL)
        return SIZE_MAX;
    for (i = 0; i < HYBRID580_UVM_PMA_REGISTRY_CAPACITY; ++i) {
        if (!registry->entries[i].active)
            return i;
    }
    return SIZE_MAX;
}

static inline enum hybrid580_uvm_pma_status
hybrid580_uvm_pma_registry_record(
    const struct hybrid580_uvm_device_registry *devices,
    struct hybrid580_uvm_pma_registry *registry,
    uintptr_t public_device, uintptr_t native_pma, uintptr_t stats_identity,
    int *quarantine)
{
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    size_t free_slot, match = SIZE_MAX, i;

    if (quarantine != NULL)
        *quarantine = 0;
    if (devices == NULL || registry == NULL || public_device == 0 ||
        native_pma == 0 || stats_identity == 0)
        return HYBRID580_UVM_PMA_INVALID;
    if (hybrid580_uvm_device_registry_lookup(devices, public_device,
                                             &provider, &native_device) !=
            HYBRID580_UVM_DEVICE_REGISTRY_OK || native_device == 0)
        return HYBRID580_UVM_PMA_INVALID;

    for (i = 0; i < HYBRID580_UVM_PMA_REGISTRY_CAPACITY; ++i) {
        const struct hybrid580_uvm_pma_entry *entry = &registry->entries[i];

        if (!entry->active || entry->native_pma != native_pma)
            continue;
        if (match != SIZE_MAX) {
            registry->entries[match].quarantined = 1;
            registry->entries[i].quarantined = 1;
            if (quarantine != NULL)
                *quarantine = 1;
            return HYBRID580_UVM_PMA_AMBIGUOUS;
        }
        match = i;
    }
    if (match != SIZE_MAX) {
        struct hybrid580_uvm_pma_entry *entry = &registry->entries[match];

        if (!entry->quarantined && entry->provider == provider &&
            entry->device_identity == public_device &&
            entry->stats_identity == stats_identity)
            return HYBRID580_UVM_PMA_OK;
        entry->quarantined = 1;
        if (quarantine != NULL)
            *quarantine = 1;
        return HYBRID580_UVM_PMA_AMBIGUOUS;
    }

    free_slot = hybrid580_uvm_pma_find_free(registry);
    if (free_slot == SIZE_MAX)
        return HYBRID580_UVM_PMA_FULL;
    registry->entries[free_slot] = (struct hybrid580_uvm_pma_entry) {
        .native_pma = native_pma,
        .stats_identity = stats_identity,
        .device_identity = public_device,
        .provider = provider,
        .active = 1,
    };
    ++registry->count;
    return HYBRID580_UVM_PMA_OK;
}

static inline enum hybrid580_uvm_pma_status hybrid580_uvm_pma_registry_pin(
    struct hybrid580_uvm_pma_registry *registry, uintptr_t native_pma,
    struct hybrid580_uvm_pma_pin *pin)
{
    size_t match = SIZE_MAX, i;

    if (pin != NULL)
        memset(pin, 0, sizeof(*pin));
    if (registry == NULL || native_pma == 0 || pin == NULL)
        return HYBRID580_UVM_PMA_INVALID;
    for (i = 0; i < HYBRID580_UVM_PMA_REGISTRY_CAPACITY; ++i) {
        struct hybrid580_uvm_pma_entry *entry = &registry->entries[i];

        if (!entry->active || entry->native_pma != native_pma)
            continue;
        if (match != SIZE_MAX) {
            registry->entries[match].quarantined = 1;
            entry->quarantined = 1;
            return HYBRID580_UVM_PMA_AMBIGUOUS;
        }
        match = i;
    }
    if (match == SIZE_MAX)
        return HYBRID580_UVM_PMA_NOT_FOUND;
    if (registry->entries[match].quarantined)
        return HYBRID580_UVM_PMA_AMBIGUOUS;
    if (registry->entries[match].active_calls == ~(uint32_t)0)
        return HYBRID580_UVM_PMA_BUSY;

    ++registry->entries[match].active_calls;
    *pin = (struct hybrid580_uvm_pma_pin) {
        .slot = match,
        .native_pma = native_pma,
        .device_identity = registry->entries[match].device_identity,
        .provider = registry->entries[match].provider,
        .active = 1,
    };
    return HYBRID580_UVM_PMA_OK;
}

static inline enum hybrid580_uvm_pma_status hybrid580_uvm_pma_registry_unpin(
    struct hybrid580_uvm_pma_registry *registry,
    struct hybrid580_uvm_pma_pin *pin)
{
    struct hybrid580_uvm_pma_entry *entry;

    if (registry == NULL || pin == NULL || !pin->active ||
        pin->slot >= HYBRID580_UVM_PMA_REGISTRY_CAPACITY)
        return HYBRID580_UVM_PMA_INVALID;
    entry = &registry->entries[pin->slot];
    if (!entry->active || entry->native_pma != pin->native_pma ||
        entry->device_identity != pin->device_identity ||
        entry->provider != pin->provider || entry->active_calls == 0)
        return HYBRID580_UVM_PMA_INVALID;
    --entry->active_calls;
    memset(pin, 0, sizeof(*pin));
    return HYBRID580_UVM_PMA_OK;
}

static inline enum hybrid580_uvm_pma_status
hybrid580_uvm_pma_registry_set_callbacks(
    struct hybrid580_uvm_pma_registry *registry,
    const struct hybrid580_uvm_pma_pin *pin, int registered)
{
    struct hybrid580_uvm_pma_entry *entry;

    if (registry == NULL || pin == NULL || !pin->active ||
        pin->slot >= HYBRID580_UVM_PMA_REGISTRY_CAPACITY ||
        (registered != 0 && registered != 1))
        return HYBRID580_UVM_PMA_INVALID;
    entry = &registry->entries[pin->slot];
    if (!entry->active || entry->quarantined ||
        entry->native_pma != pin->native_pma ||
        entry->device_identity != pin->device_identity ||
        entry->provider != pin->provider || entry->active_calls == 0)
        return HYBRID580_UVM_PMA_INVALID;
    if (registered && entry->callbacks_registered)
        return HYBRID580_UVM_PMA_BUSY;
    entry->callbacks_registered = registered != 0;
    return HYBRID580_UVM_PMA_OK;
}

static inline enum hybrid580_uvm_pma_status
hybrid580_uvm_pma_registry_quarantine_pin(
    struct hybrid580_uvm_pma_registry *registry,
    const struct hybrid580_uvm_pma_pin *pin)
{
    struct hybrid580_uvm_pma_entry *entry;

    if (registry == NULL || pin == NULL || !pin->active ||
        pin->slot >= HYBRID580_UVM_PMA_REGISTRY_CAPACITY)
        return HYBRID580_UVM_PMA_INVALID;
    entry = &registry->entries[pin->slot];
    if (!entry->active || entry->native_pma != pin->native_pma ||
        entry->device_identity != pin->device_identity ||
        entry->provider != pin->provider || entry->active_calls == 0)
        return HYBRID580_UVM_PMA_INVALID;
    entry->quarantined = 1;
    return HYBRID580_UVM_PMA_OK;
}

static inline enum hybrid580_uvm_pma_status
hybrid580_uvm_pma_registry_device_destroy_check(
    const struct hybrid580_uvm_pma_registry *registry,
    uintptr_t public_device)
{
    size_t i;

    if (registry == NULL || public_device == 0)
        return HYBRID580_UVM_PMA_INVALID;
    for (i = 0; i < HYBRID580_UVM_PMA_REGISTRY_CAPACITY; ++i) {
        const struct hybrid580_uvm_pma_entry *entry = &registry->entries[i];

        if (entry->active && entry->device_identity == public_device &&
            (entry->quarantined || entry->active_calls != 0 ||
             entry->callbacks_registered))
            return HYBRID580_UVM_PMA_BUSY;
    }
    return HYBRID580_UVM_PMA_OK;
}

static inline enum hybrid580_uvm_pma_status
hybrid580_uvm_pma_registry_release_device(
    struct hybrid580_uvm_pma_registry *registry, uintptr_t public_device)
{
    size_t i;
    enum hybrid580_uvm_pma_status status;

    status = hybrid580_uvm_pma_registry_device_destroy_check(registry,
                                                              public_device);
    if (status != HYBRID580_UVM_PMA_OK)
        return status;
    for (i = 0; i < HYBRID580_UVM_PMA_REGISTRY_CAPACITY; ++i) {
        struct hybrid580_uvm_pma_entry *entry = &registry->entries[i];

        if (entry->active && entry->device_identity == public_device) {
            memset(entry, 0, sizeof(*entry));
            --registry->count;
        }
    }
    return HYBRID580_UVM_PMA_OK;
}

#endif /* HYBRID580_UVM_PMA_ROUTE_H */
