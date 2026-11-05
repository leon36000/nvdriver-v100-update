/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_ADDRESS_SPACE_ROUTE_H
#define HYBRID580_UVM_ADDRESS_SPACE_ROUTE_H

#include "hybrid580_uvm_device_route.h"

#define HYBRID580_UVM_ADDRESS_SPACE_BUCKET_COUNT 256U

enum hybrid580_uvm_address_space_registry_status {
    HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK = 0,
    HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID = -1,
    HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_NOT_FOUND = -2,
    HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_DUPLICATE = -3,
    HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_BUSY = -4,
};

/* Intrusive hash entries are allocated before the backend creates an RM
 * object. This avoids an allocation failure after the RM has returned a live
 * handle and supports an unbounded number of process VA spaces up to memory.
 */
struct hybrid580_uvm_address_space_entry {
    uintptr_t identity;
    uintptr_t native_handle;
    uintptr_t parent_device;
    enum hybrid580_uvm_provider provider;
    struct hybrid580_uvm_address_space_entry *next;
};

struct hybrid580_uvm_address_space_registry {
    size_t count;
    struct hybrid580_uvm_address_space_entry *buckets[
        HYBRID580_UVM_ADDRESS_SPACE_BUCKET_COUNT];
};

struct hybrid580_uvm_address_space_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*create)(void *context, uintptr_t native_device,
                       unsigned long long va_base,
                       unsigned long long va_size, int enable_ats,
                       uintptr_t *native_space, void *space_info);
    void (*destroy)(void *context, uintptr_t native_space);
};

struct hybrid580_uvm_address_space_call_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*call)(void *context, uintptr_t native_space, void *params);
};

struct hybrid580_uvm_address_space_duplicate_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*duplicate)(void *context, uintptr_t native_device,
                          uint32_t user_client, uint32_t user_va_space,
                          uintptr_t *native_space, void *space_info);
    void (*destroy)(void *context, uintptr_t native_space);
};

struct hybrid580_uvm_address_space_dup_allocation_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*duplicate)(void *context, uintptr_t native_src_space,
                          unsigned long long src_address,
                          uintptr_t native_dst_space,
                          unsigned long long dst_alignment,
                          unsigned long long *dst_address);
};

static inline size_t hybrid580_uvm_address_space_bucket(uintptr_t identity)
{
    identity = (identity >> 4) ^ (identity >> 13) ^ (identity >> 23);
    return (size_t)(identity & (HYBRID580_UVM_ADDRESS_SPACE_BUCKET_COUNT - 1));
}

static inline struct hybrid580_uvm_address_space_entry **
hybrid580_uvm_address_space_find_link(
    struct hybrid580_uvm_address_space_registry *registry, uintptr_t identity)
{
    struct hybrid580_uvm_address_space_entry **link;

    if (registry == NULL || identity == 0)
        return NULL;
    link = &registry->buckets[hybrid580_uvm_address_space_bucket(identity)];
    while (*link != NULL && (*link)->identity != identity)
        link = &(*link)->next;
    return link;
}

static inline size_t hybrid580_uvm_address_space_registry_count(
    const struct hybrid580_uvm_address_space_registry *registry)
{
    return registry == NULL ? 0 : registry->count;
}

static inline int hybrid580_uvm_address_space_registry_has_parent(
    const struct hybrid580_uvm_address_space_registry *registry,
    uintptr_t parent_device)
{
    size_t i;

    if (registry == NULL || parent_device == 0)
        return 0;
    for (i = 0; i < HYBRID580_UVM_ADDRESS_SPACE_BUCKET_COUNT; ++i) {
        const struct hybrid580_uvm_address_space_entry *entry;
        for (entry = registry->buckets[i]; entry != NULL; entry = entry->next) {
            if (entry->parent_device == parent_device)
                return 1;
        }
    }
    return 0;
}

static inline enum hybrid580_uvm_address_space_registry_status
hybrid580_uvm_address_space_registry_lookup(
    const struct hybrid580_uvm_address_space_registry *registry,
    uintptr_t identity, enum hybrid580_uvm_provider *provider,
    uintptr_t *native_handle, uintptr_t *parent_device)
{
    struct hybrid580_uvm_address_space_entry **link;

    if (registry == NULL || provider == NULL || identity == 0)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    link = hybrid580_uvm_address_space_find_link(
        (struct hybrid580_uvm_address_space_registry *)registry, identity);
    if (link == NULL || *link == NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_NOT_FOUND;
    *provider = (*link)->provider;
    if (native_handle != NULL)
        *native_handle = (*link)->native_handle;
    if (parent_device != NULL)
        *parent_device = (*link)->parent_device;
    return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK;
}

static inline enum hybrid580_uvm_address_space_registry_status
hybrid580_uvm_address_space_registry_insert(
    struct hybrid580_uvm_address_space_registry *registry,
    struct hybrid580_uvm_address_space_entry *entry, uintptr_t native_handle,
    uintptr_t parent_device, enum hybrid580_uvm_provider provider)
{
    struct hybrid580_uvm_address_space_entry **link;

    if (registry == NULL || entry == NULL || native_handle == 0 ||
        parent_device == 0 || !hybrid580_uvm_provider_is_single(provider) ||
        entry->identity != 0 || entry->native_handle != 0 || entry->next != NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    link = hybrid580_uvm_address_space_find_link(registry, native_handle);
    if (link == NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    if (*link != NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_DUPLICATE;

    entry->identity = native_handle;
    entry->native_handle = native_handle;
    entry->parent_device = parent_device;
    entry->provider = provider;
    entry->next = NULL;
    *link = entry;
    ++registry->count;
    return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK;
}

static inline enum hybrid580_uvm_address_space_registry_status
hybrid580_uvm_address_space_registry_remove(
    struct hybrid580_uvm_address_space_registry *registry, uintptr_t identity,
    struct hybrid580_uvm_address_space_entry **removed)
{
    struct hybrid580_uvm_address_space_entry **link;
    struct hybrid580_uvm_address_space_entry *entry;

    if (removed != NULL)
        *removed = NULL;
    if (registry == NULL || identity == 0)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    link = hybrid580_uvm_address_space_find_link(registry, identity);
    if (link == NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    if (*link == NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_NOT_FOUND;
    entry = *link;
    *link = entry->next;
    entry->next = NULL;
    --registry->count;
    if (removed != NULL)
        *removed = entry;
    return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK;
}

static inline int hybrid580_uvm_address_space_backend_ops_valid(
    struct hybrid580_uvm_address_space_backend_ops open,
    struct hybrid580_uvm_address_space_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.create != NULL && open.destroy != NULL &&
           legacy.create != NULL && legacy.destroy != NULL;
}

static inline uint32_t hybrid580_uvm_address_space_route_create(
    const struct hybrid580_uvm_device_registry *devices,
    struct hybrid580_uvm_address_space_registry *spaces,
    struct hybrid580_uvm_address_space_entry *reserved_entry,
    uintptr_t public_device, unsigned long long va_base,
    unsigned long long va_size, int enable_ats, void *space_info,
    struct hybrid580_uvm_address_space_backend_ops open,
    struct hybrid580_uvm_address_space_backend_ops legacy,
    uint32_t no_memory_status, uint32_t invalid_argument_status,
    uint32_t generic_status, uintptr_t *public_space, int *quarantine)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_address_space_backend_ops *selected;
    uintptr_t native_device = 0;
    uintptr_t native_space = 0;
    uint32_t backend_status;
    enum hybrid580_uvm_device_registry_status device_status;
    enum hybrid580_uvm_address_space_registry_status space_status;

    if (public_space == NULL)
        return generic_status;
    *public_space = 0;
    if (quarantine != NULL)
        *quarantine = 0;
    if (spaces == NULL || reserved_entry == NULL || space_info == NULL ||
        !hybrid580_uvm_address_space_backend_ops_valid(open, legacy))
        return generic_status;
    if (va_size == 0)
        return invalid_argument_status;
    device_status = hybrid580_uvm_device_registry_lookup(
        devices, public_device, &provider, &native_device);
    if (device_status != HYBRID580_UVM_DEVICE_REGISTRY_OK) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return generic_status;

    backend_status = selected->create(selected->context, native_device,
                                      va_base, va_size, enable_ats,
                                      &native_space, space_info);
    if (backend_status != 0) {
        if (native_space != 0 && quarantine != NULL)
            *quarantine = 1;
        return backend_status;
    }
    if (native_space == 0)
        return generic_status;

    space_status = hybrid580_uvm_address_space_registry_insert(
        spaces, reserved_entry, native_space, public_device, provider);
    if (space_status == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_DUPLICATE) {
        /* The new value may alias a live VA-space RM object. Do not destroy
         * either allocation until ownership is externally reconciled. */
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    if (space_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        selected->destroy(selected->context, native_space);
        return space_status == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_BUSY ?
               no_memory_status : generic_status;
    }
    *public_space = native_space;
    return 0;
}

static inline int hybrid580_uvm_address_space_duplicate_ops_valid(
    struct hybrid580_uvm_address_space_duplicate_backend_ops open,
    struct hybrid580_uvm_address_space_duplicate_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.duplicate != NULL && open.destroy != NULL &&
           legacy.duplicate != NULL && legacy.destroy != NULL;
}

/* DupAddressSpace takes a device plus user RM handles, not an existing UVM
 * address-space identity. Resolve the device first, duplicate only inside its
 * owning RM, then publish the returned kernel address-space identity under
 * that device. A failed call with a non-null output or a colliding live
 * identity is ambiguous and must never be speculatively destroyed. */
static inline uint32_t hybrid580_uvm_address_space_route_duplicate(
    const struct hybrid580_uvm_device_registry *devices,
    struct hybrid580_uvm_address_space_registry *spaces,
    struct hybrid580_uvm_address_space_entry *reserved_entry,
    uintptr_t public_device, uint32_t user_client, uint32_t user_va_space,
    void *space_info,
    struct hybrid580_uvm_address_space_duplicate_backend_ops open,
    struct hybrid580_uvm_address_space_duplicate_backend_ops legacy,
    uint32_t no_memory_status, uint32_t generic_status,
    uintptr_t *public_space, int *quarantine)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_address_space_duplicate_backend_ops *selected;
    uintptr_t native_device = 0;
    uintptr_t native_space = 0;
    uint32_t backend_status;
    enum hybrid580_uvm_device_registry_status device_status;
    enum hybrid580_uvm_address_space_registry_status space_status;

    if (public_space == NULL)
        return generic_status;
    *public_space = 0;
    if (quarantine != NULL)
        *quarantine = 0;
    if (devices == NULL || spaces == NULL || reserved_entry == NULL ||
        space_info == NULL ||
        !hybrid580_uvm_address_space_duplicate_ops_valid(open, legacy))
        return generic_status;

    device_status = hybrid580_uvm_device_registry_lookup(
        devices, public_device, &provider, &native_device);
    if (device_status != HYBRID580_UVM_DEVICE_REGISTRY_OK) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return generic_status;

    backend_status = selected->duplicate(selected->context, native_device,
                                          user_client, user_va_space,
                                          &native_space, space_info);
    if (backend_status != 0) {
        if (native_space != 0 && quarantine != NULL)
            *quarantine = 1;
        return backend_status;
    }
    if (native_space == 0)
        return generic_status;

    space_status = hybrid580_uvm_address_space_registry_insert(
        spaces, reserved_entry, native_space, public_device, provider);
    if (space_status == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_DUPLICATE) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    if (space_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        selected->destroy(selected->context, native_space);
        return space_status == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_BUSY ?
               no_memory_status : generic_status;
    }

    *public_space = native_space;
    return 0;
}

static inline int hybrid580_uvm_address_space_call_backend_ops_valid(
    struct hybrid580_uvm_address_space_call_backend_ops open,
    struct hybrid580_uvm_address_space_call_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.call != NULL && legacy.call != NULL;
}

static inline enum hybrid580_uvm_address_space_registry_status
hybrid580_uvm_address_space_route_call(
    const struct hybrid580_uvm_address_space_registry *spaces,
    uintptr_t public_space, void *params,
    struct hybrid580_uvm_address_space_call_backend_ops open,
    struct hybrid580_uvm_address_space_call_backend_ops legacy,
    uint32_t *backend_status)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_address_space_call_backend_ops *selected;
    uintptr_t native_space = 0;
    enum hybrid580_uvm_address_space_registry_status status;

    if (backend_status == NULL || params == NULL ||
        !hybrid580_uvm_address_space_call_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    *backend_status = 0;
    status = hybrid580_uvm_address_space_registry_lookup(
        spaces, public_space, &provider, &native_space, NULL);
    if (status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK)
        return status;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;

    *backend_status = selected->call(selected->context, native_space, params);
    return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK;
}

static inline int hybrid580_uvm_address_space_dup_allocation_ops_valid(
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops open,
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.duplicate != NULL && legacy.duplicate != NULL;
}

/* DupAllocation consumes two RM VA-space handles. Resolve both identities
 * first and only call an RM that owns both. The source/destination spaces may
 * belong to different devices, but one RM must own both handles; cross-RM
 * migration cannot be represented by passing an opaque handle to the other
 * provider. Do not publish an address if the backend reports failure. */
static inline uint32_t hybrid580_uvm_address_space_route_dup_allocation(
    const struct hybrid580_uvm_address_space_registry *spaces,
    uintptr_t public_src_space, unsigned long long src_address,
    uintptr_t public_dst_space, unsigned long long dst_alignment,
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops open,
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops legacy,
    uint32_t invalid_argument_status, uint32_t not_supported_status,
    uint32_t generic_status, unsigned long long *public_dst_address,
    int *quarantine)
{
    enum hybrid580_uvm_provider src_provider = 0;
    enum hybrid580_uvm_provider dst_provider = 0;
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops *selected;
    uintptr_t native_src_space = 0;
    uintptr_t native_dst_space = 0;
    unsigned long long staged_dst_address = 0;
    uint32_t backend_status;
    enum hybrid580_uvm_address_space_registry_status src_status;
    enum hybrid580_uvm_address_space_registry_status dst_status;

    if (public_dst_address == NULL)
        return generic_status;
    *public_dst_address = 0;
    if (quarantine != NULL)
        *quarantine = 0;
    if (spaces == NULL ||
        !hybrid580_uvm_address_space_dup_allocation_ops_valid(open, legacy))
        return generic_status;
    if (public_src_space == 0 || public_dst_space == 0 ||
        public_src_space == public_dst_space)
        return invalid_argument_status;

    src_status = hybrid580_uvm_address_space_registry_lookup(
        spaces, public_src_space, &src_provider, &native_src_space, NULL);
    dst_status = hybrid580_uvm_address_space_registry_lookup(
        spaces, public_dst_space, &dst_provider, &native_dst_space, NULL);
    if (src_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK ||
        dst_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    if (src_provider != dst_provider)
        return not_supported_status;

    selected = src_provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               src_provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL || native_src_space == 0 || native_dst_space == 0) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }

    backend_status = selected->duplicate(
        selected->context, native_src_space, src_address, native_dst_space,
        dst_alignment, &staged_dst_address);
    if (backend_status != 0) {
        if (staged_dst_address != 0 && quarantine != NULL)
            *quarantine = 1;
        return backend_status;
    }
    if (staged_dst_address == 0) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }

    *public_dst_address = staged_dst_address;
    return 0;
}

static inline enum hybrid580_uvm_address_space_registry_status
hybrid580_uvm_address_space_route_destroy(
    struct hybrid580_uvm_address_space_registry *spaces,
    uintptr_t public_space,
    struct hybrid580_uvm_address_space_backend_ops open,
    struct hybrid580_uvm_address_space_backend_ops legacy,
    struct hybrid580_uvm_address_space_entry **removed)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_address_space_backend_ops *selected;
    uintptr_t native_space = 0;
    enum hybrid580_uvm_address_space_registry_status status;

    if (removed != NULL)
        *removed = NULL;
    if (spaces == NULL ||
        !hybrid580_uvm_address_space_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;
    status = hybrid580_uvm_address_space_registry_lookup(
        spaces, public_space, &provider, &native_space, NULL);
    if (status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK)
        return status;
    if (hybrid580_uvm_address_space_registry_has_parent(spaces, public_space))
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_BUSY;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL || native_space != public_space)
        return HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_INVALID;

    selected->destroy(selected->context, native_space);
    return hybrid580_uvm_address_space_registry_remove(spaces, public_space,
                                                        removed);
}

#endif /* HYBRID580_UVM_ADDRESS_SPACE_ROUTE_H */
