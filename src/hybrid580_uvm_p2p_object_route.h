/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_P2P_OBJECT_ROUTE_H
#define HYBRID580_UVM_P2P_OBJECT_ROUTE_H

#include "hybrid580_uvm_device_route.h"

#define HYBRID580_UVM_P2P_OBJECT_CAPACITY 256U
#define HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE 0x80000000U

struct hybrid580_uvm_p2p_object_entry {
    uint32_t public_handle;
    uint32_t native_handle;
    uintptr_t session_identity;
    uintptr_t parent_device1;
    uintptr_t parent_device2;
    enum hybrid580_uvm_provider provider;
    uint8_t quarantined;
    uint8_t active;
};

struct hybrid580_uvm_p2p_object_registry {
    uint32_t count;
    uint32_t next_public_handle;
    struct hybrid580_uvm_p2p_object_entry
        entries[HYBRID580_UVM_P2P_OBJECT_CAPACITY];
};

struct hybrid580_uvm_p2p_object_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_session;
    uint32_t (*create)(void *context, uintptr_t native_device1,
                       uintptr_t native_device2, uint32_t *native_handle);
    void (*destroy)(void *context, uintptr_t native_session,
                    uint32_t native_handle);
};

enum hybrid580_uvm_p2p_object_status {
    HYBRID580_UVM_P2P_OBJECT_OK = 0,
    HYBRID580_UVM_P2P_OBJECT_INVALID = -1,
    HYBRID580_UVM_P2P_OBJECT_NOT_FOUND = -2,
    HYBRID580_UVM_P2P_OBJECT_CROSS_PROVIDER = -3,
    HYBRID580_UVM_P2P_OBJECT_FULL = -4,
    HYBRID580_UVM_P2P_OBJECT_BACKEND_BUSY = -5,
};

static inline int hybrid580_uvm_p2p_object_backend_ops_valid(
    struct hybrid580_uvm_p2p_object_backend_ops open,
    struct hybrid580_uvm_p2p_object_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           open.native_session != 0 && open.create != NULL &&
           open.destroy != NULL &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           legacy.native_session != 0 && legacy.create != NULL &&
           legacy.destroy != NULL;
}

static inline size_t hybrid580_uvm_p2p_object_find_public(
    const struct hybrid580_uvm_p2p_object_registry *registry,
    uint32_t public_handle)
{
    size_t i;

    if (registry == NULL || public_handle == 0)
        return SIZE_MAX;
    for (i = 0; i < HYBRID580_UVM_P2P_OBJECT_CAPACITY; ++i) {
        if (registry->entries[i].active &&
            registry->entries[i].public_handle == public_handle)
            return i;
    }
    return SIZE_MAX;
}

static inline int hybrid580_uvm_p2p_object_has_parent(
    const struct hybrid580_uvm_p2p_object_registry *registry,
    uintptr_t public_device)
{
    size_t i;

    if (registry == NULL || public_device == 0)
        return 0;
    for (i = 0; i < HYBRID580_UVM_P2P_OBJECT_CAPACITY; ++i) {
        const struct hybrid580_uvm_p2p_object_entry *entry =
            &registry->entries[i];
        if (entry->active && (entry->parent_device1 == public_device ||
                              entry->parent_device2 == public_device))
            return 1;
    }
    return 0;
}

static inline size_t hybrid580_uvm_p2p_object_free_slot(
    const struct hybrid580_uvm_p2p_object_registry *registry)
{
    size_t i;

    if (registry == NULL)
        return SIZE_MAX;
    for (i = 0; i < HYBRID580_UVM_P2P_OBJECT_CAPACITY; ++i) {
        if (!registry->entries[i].active)
            return i;
    }
    return SIZE_MAX;
}

static inline void hybrid580_uvm_p2p_object_quarantine_slot(
    struct hybrid580_uvm_p2p_object_registry *registry, size_t slot,
    uintptr_t session_identity, uintptr_t public_device1,
    uintptr_t public_device2, enum hybrid580_uvm_provider provider,
    uint32_t ambiguous_native_handle)
{
    registry->entries[slot] = (struct hybrid580_uvm_p2p_object_entry) {
        .native_handle = ambiguous_native_handle,
        .session_identity = session_identity,
        .parent_device1 = public_device1,
        .parent_device2 = public_device2,
        .provider = provider,
        .quarantined = 1,
        .active = 1,
    };
    ++registry->count;
}

static inline uint32_t hybrid580_uvm_p2p_object_next_public(
    const struct hybrid580_uvm_p2p_object_registry *registry)
{
    uint32_t candidate;
    unsigned attempt;

    if (registry == NULL)
        return 0;
    candidate = registry->next_public_handle;
    if (candidate < HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE)
        candidate = HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE;
    for (attempt = 0; attempt <= HYBRID580_UVM_P2P_OBJECT_CAPACITY; ++attempt) {
        if (candidate != 0 &&
            hybrid580_uvm_p2p_object_find_public(registry, candidate) == SIZE_MAX)
            return candidate;
        ++candidate;
        if (candidate < HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE)
            candidate = HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE;
    }
    return 0;
}

static inline uint32_t hybrid580_uvm_p2p_object_route_create(
    const struct hybrid580_uvm_device_registry *devices,
    struct hybrid580_uvm_p2p_object_registry *registry,
    uintptr_t session_identity, uintptr_t public_device1,
    uintptr_t public_device2,
    struct hybrid580_uvm_p2p_object_backend_ops open,
    struct hybrid580_uvm_p2p_object_backend_ops legacy,
    uint32_t no_memory_status, uint32_t generic_status,
    uint32_t not_supported_status, uint32_t *public_handle,
    int *quarantine)
{
    enum hybrid580_uvm_provider provider1 = 0;
    enum hybrid580_uvm_provider provider2 = 0;
    struct hybrid580_uvm_p2p_object_backend_ops *selected;
    uintptr_t native_device1 = 0;
    uintptr_t native_device2 = 0;
    uint32_t native_handle = 0;
    uint32_t new_public_handle;
    uint32_t backend_status;
    enum hybrid580_uvm_device_registry_status device_status1;
    enum hybrid580_uvm_device_registry_status device_status2;
    size_t slot;
    size_t i;

    if (public_handle == NULL)
        return generic_status;
    *public_handle = 0;
    if (quarantine != NULL)
        *quarantine = 0;
    if (devices == NULL || registry == NULL || session_identity == 0 ||
        public_device1 == 0 || public_device2 == 0 ||
        public_device1 == public_device2 ||
        !hybrid580_uvm_p2p_object_backend_ops_valid(open, legacy))
        return generic_status;
    slot = hybrid580_uvm_p2p_object_free_slot(registry);
    if (slot == SIZE_MAX)
        return no_memory_status;

    device_status1 = hybrid580_uvm_device_registry_lookup(
        devices, public_device1, &provider1, &native_device1);
    device_status2 = hybrid580_uvm_device_registry_lookup(
        devices, public_device2, &provider2, &native_device2);
    if (device_status1 != HYBRID580_UVM_DEVICE_REGISTRY_OK ||
        device_status2 != HYBRID580_UVM_DEVICE_REGISTRY_OK) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    if (provider1 != provider2)
        return not_supported_status;
    selected = provider1 == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider1 == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL || native_device1 == 0 || native_device2 == 0)
        return generic_status;

    backend_status = selected->create(selected->context, native_device1,
                                       native_device2, &native_handle);
    if (backend_status != 0) {
        if (native_handle != 0) {
            hybrid580_uvm_p2p_object_quarantine_slot(
                registry, slot, session_identity, public_device1,
                public_device2, provider1, native_handle);
            if (quarantine != NULL)
                *quarantine = 1;
        }
        return backend_status;
    }
    if (native_handle == 0) {
        hybrid580_uvm_p2p_object_quarantine_slot(
            registry, slot, session_identity, public_device1,
            public_device2, provider1, 0);
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    for (i = 0; i < HYBRID580_UVM_P2P_OBJECT_CAPACITY; ++i) {
        const struct hybrid580_uvm_p2p_object_entry *entry =
            &registry->entries[i];
        if (entry->active && entry->provider == provider1 &&
            entry->native_handle == native_handle) {
            hybrid580_uvm_p2p_object_quarantine_slot(
                registry, slot, session_identity, public_device1,
                public_device2, provider1, native_handle);
            if (quarantine != NULL)
                *quarantine = 1;
            return generic_status;
        }
    }
    new_public_handle = hybrid580_uvm_p2p_object_next_public(registry);
    if (new_public_handle == 0) {
        hybrid580_uvm_p2p_object_quarantine_slot(
            registry, slot, session_identity, public_device1,
            public_device2, provider1, native_handle);
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }

    registry->entries[slot] = (struct hybrid580_uvm_p2p_object_entry) {
        .public_handle = new_public_handle,
        .native_handle = native_handle,
        .session_identity = session_identity,
        .parent_device1 = public_device1,
        .parent_device2 = public_device2,
        .provider = provider1,
        .active = 1,
    };
    ++registry->count;
    registry->next_public_handle = new_public_handle + 1;
    if (registry->next_public_handle < HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE)
        registry->next_public_handle = HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE;
    *public_handle = new_public_handle;
    return 0;
}

static inline enum hybrid580_uvm_p2p_object_status
hybrid580_uvm_p2p_object_route_destroy(
    struct hybrid580_uvm_p2p_object_registry *registry,
    uintptr_t session_identity, uint32_t public_handle,
    struct hybrid580_uvm_p2p_object_backend_ops open,
    struct hybrid580_uvm_p2p_object_backend_ops legacy)
{
    struct hybrid580_uvm_p2p_object_entry *entry;
    struct hybrid580_uvm_p2p_object_backend_ops *selected;
    size_t slot;

    if (registry == NULL || session_identity == 0 || public_handle == 0 ||
        !hybrid580_uvm_p2p_object_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_P2P_OBJECT_INVALID;
    slot = hybrid580_uvm_p2p_object_find_public(registry, public_handle);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_P2P_OBJECT_NOT_FOUND;
    entry = &registry->entries[slot];
    if (entry->quarantined)
        return HYBRID580_UVM_P2P_OBJECT_INVALID;
    if (entry->session_identity != session_identity)
        return HYBRID580_UVM_P2P_OBJECT_INVALID;
    selected = entry->provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               entry->provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return HYBRID580_UVM_P2P_OBJECT_INVALID;

    selected->destroy(selected->context, selected->native_session,
                      entry->native_handle);
    memset(entry, 0, sizeof(*entry));
    --registry->count;
    return HYBRID580_UVM_P2P_OBJECT_OK;
}

#endif /* HYBRID580_UVM_P2P_OBJECT_ROUTE_H */
