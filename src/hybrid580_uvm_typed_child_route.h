/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_TYPED_CHILD_ROUTE_H
#define HYBRID580_UVM_TYPED_CHILD_ROUTE_H

#include "hybrid580_uvm_owner_map.h"

#define HYBRID580_UVM_TYPED_CHILD_BUCKET_COUNT 256U
#define HYBRID580_UVM_TYPED_CHILD_REFCOUNT_MAX ((uint32_t)0xffffffffU)

enum hybrid580_uvm_typed_child_kind {
    HYBRID580_UVM_TYPED_CHILD_TSG = 1,
    HYBRID580_UVM_TYPED_CHILD_CHANNEL = 2,
    HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL = 3,
    HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY = 4,
};

enum hybrid580_uvm_typed_child_parent_kind {
    HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE = 1,
    HYBRID580_UVM_TYPED_CHILD_PARENT_TSG = 2,
    HYBRID580_UVM_TYPED_CHILD_PARENT_CHANNEL = 3,
    HYBRID580_UVM_TYPED_CHILD_PARENT_RETAINED_CHANNEL = 4,
    HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE = 5,
    HYBRID580_UVM_TYPED_CHILD_PARENT_DUPED_MEMORY = 6,
};

enum hybrid580_uvm_typed_child_status {
    HYBRID580_UVM_TYPED_CHILD_OK = 0,
    HYBRID580_UVM_TYPED_CHILD_INVALID = -1,
    HYBRID580_UVM_TYPED_CHILD_NOT_FOUND = -2,
    HYBRID580_UVM_TYPED_CHILD_DUPLICATE = -3,
    HYBRID580_UVM_TYPED_CHILD_BAD_PARENT = -4,
    HYBRID580_UVM_TYPED_CHILD_HAS_CHILDREN = -5,
    HYBRID580_UVM_TYPED_CHILD_REFCOUNT_OVERFLOW = -6,
};

struct hybrid580_uvm_typed_child_entry {
    uintptr_t identity;
    uintptr_t native_handle;
    uintptr_t parent_identity;
    enum hybrid580_uvm_typed_child_parent_kind parent_kind;
    enum hybrid580_uvm_provider provider;
    enum hybrid580_uvm_typed_child_kind kind;
    uint32_t references;
    struct hybrid580_uvm_typed_child_entry *next;
};

struct hybrid580_uvm_typed_child_registry {
    size_t count;
    struct hybrid580_uvm_typed_child_entry *buckets[
        HYBRID580_UVM_TYPED_CHILD_BUCKET_COUNT];
};

struct hybrid580_uvm_typed_child_call_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*call)(void *context, uintptr_t native_handle, void *params);
};

struct hybrid580_uvm_typed_child_destroy_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    void (*destroy)(void *context, uintptr_t native_handle);
};

static inline int hybrid580_uvm_typed_child_kind_valid(
    enum hybrid580_uvm_typed_child_kind kind)
{
    return kind == HYBRID580_UVM_TYPED_CHILD_TSG ||
           kind == HYBRID580_UVM_TYPED_CHILD_CHANNEL ||
           kind == HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL ||
           kind == HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY;
}

static inline int hybrid580_uvm_typed_child_parent_kind_valid(
    enum hybrid580_uvm_typed_child_parent_kind kind)
{
    return kind == HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE ||
           kind == HYBRID580_UVM_TYPED_CHILD_PARENT_TSG ||
           kind == HYBRID580_UVM_TYPED_CHILD_PARENT_CHANNEL ||
           kind == HYBRID580_UVM_TYPED_CHILD_PARENT_RETAINED_CHANNEL ||
           kind == HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE ||
           kind == HYBRID580_UVM_TYPED_CHILD_PARENT_DUPED_MEMORY;
}

static inline size_t hybrid580_uvm_typed_child_bucket(
    uintptr_t identity, enum hybrid580_uvm_typed_child_kind kind)
{
    identity = (identity >> 4) ^ (identity >> 13) ^ (identity >> 23) ^
               ((uintptr_t)kind << 7);
    return (size_t)(identity & (HYBRID580_UVM_TYPED_CHILD_BUCKET_COUNT - 1));
}

static inline struct hybrid580_uvm_typed_child_entry **
hybrid580_uvm_typed_child_find_link(
    struct hybrid580_uvm_typed_child_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_typed_child_kind kind)
{
    struct hybrid580_uvm_typed_child_entry **link;

    if (registry == NULL || identity == 0 ||
        !hybrid580_uvm_typed_child_kind_valid(kind))
        return NULL;
    link = &registry->buckets[hybrid580_uvm_typed_child_bucket(identity, kind)];
    while (*link != NULL &&
           ((*link)->identity != identity || (*link)->kind != kind))
        link = &(*link)->next;
    return link;
}

static inline size_t hybrid580_uvm_typed_child_registry_count(
    const struct hybrid580_uvm_typed_child_registry *registry)
{
    return registry == NULL ? 0 : registry->count;
}

static inline int hybrid580_uvm_typed_child_registry_has_parent(
    const struct hybrid580_uvm_typed_child_registry *registry,
    uintptr_t parent_identity,
    enum hybrid580_uvm_typed_child_parent_kind parent_kind)
{
    size_t bucket;

    if (registry == NULL || parent_identity == 0 ||
        !hybrid580_uvm_typed_child_parent_kind_valid(parent_kind))
        return 0;
    for (bucket = 0; bucket < HYBRID580_UVM_TYPED_CHILD_BUCKET_COUNT; ++bucket) {
        const struct hybrid580_uvm_typed_child_entry *entry;
        for (entry = registry->buckets[bucket]; entry != NULL;
             entry = entry->next) {
            if (entry->parent_identity == parent_identity &&
                entry->parent_kind == parent_kind)
                return 1;
        }
    }
    return 0;
}

static inline enum hybrid580_uvm_typed_child_status
hybrid580_uvm_typed_child_registry_lookup(
    const struct hybrid580_uvm_typed_child_registry *registry,
    uintptr_t identity, enum hybrid580_uvm_typed_child_kind kind,
    enum hybrid580_uvm_provider *provider, uintptr_t *native_handle,
    uintptr_t *parent_identity,
    enum hybrid580_uvm_typed_child_parent_kind *parent_kind)
{
    struct hybrid580_uvm_typed_child_entry **link;

    if (registry == NULL || identity == 0 || provider == NULL ||
        !hybrid580_uvm_typed_child_kind_valid(kind))
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    link = hybrid580_uvm_typed_child_find_link(
        (struct hybrid580_uvm_typed_child_registry *)registry, identity, kind);
    if (link == NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    if (*link == NULL)
        return HYBRID580_UVM_TYPED_CHILD_NOT_FOUND;
    *provider = (*link)->provider;
    if (native_handle != NULL)
        *native_handle = (*link)->native_handle;
    if (parent_identity != NULL)
        *parent_identity = (*link)->parent_identity;
    if (parent_kind != NULL)
        *parent_kind = (*link)->parent_kind;
    return HYBRID580_UVM_TYPED_CHILD_OK;
}

/* TSG parents live in the address-space registry. A channel's parent is a
 * tracked TSG and must share its provider; cross-RM channel groups are invalid.
 */
static inline enum hybrid580_uvm_typed_child_status
hybrid580_uvm_typed_child_registry_insert(
    struct hybrid580_uvm_typed_child_registry *registry,
    struct hybrid580_uvm_typed_child_entry *entry, uintptr_t identity,
    uintptr_t parent_identity,
    enum hybrid580_uvm_typed_child_parent_kind parent_kind,
    enum hybrid580_uvm_typed_child_kind kind,
    enum hybrid580_uvm_provider provider)
{
    struct hybrid580_uvm_typed_child_entry **link;

    if (registry == NULL || entry == NULL || identity == 0 || parent_identity == 0 ||
        !hybrid580_uvm_typed_child_kind_valid(kind) ||
        !hybrid580_uvm_typed_child_parent_kind_valid(parent_kind) ||
        !hybrid580_uvm_provider_is_single(provider) || entry->identity != 0 ||
        entry->native_handle != 0 || entry->parent_identity != 0 ||
        entry->parent_kind != 0 || entry->references != 0 ||
        entry->next != NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    if ((kind == HYBRID580_UVM_TYPED_CHILD_TSG &&
         parent_kind != HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE) ||
        (kind == HYBRID580_UVM_TYPED_CHILD_CHANNEL &&
         parent_kind != HYBRID580_UVM_TYPED_CHILD_PARENT_TSG) ||
        (kind == HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL &&
         parent_kind != HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE) ||
        (kind == HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY &&
         parent_kind != HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE))
        return HYBRID580_UVM_TYPED_CHILD_BAD_PARENT;
    if (kind == HYBRID580_UVM_TYPED_CHILD_CHANNEL) {
        enum hybrid580_uvm_provider parent_provider = 0;
        enum hybrid580_uvm_typed_child_status parent_status =
            hybrid580_uvm_typed_child_registry_lookup(
                registry, parent_identity, HYBRID580_UVM_TYPED_CHILD_TSG,
                &parent_provider, NULL, NULL, NULL);
        if (parent_status != HYBRID580_UVM_TYPED_CHILD_OK ||
            parent_provider != provider)
            return HYBRID580_UVM_TYPED_CHILD_BAD_PARENT;
    }
    link = hybrid580_uvm_typed_child_find_link(registry, identity, kind);
    if (link == NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    if (*link != NULL) {
        struct hybrid580_uvm_typed_child_entry *existing = *link;

        /* R580 documents RetainChannel's opaque state as refcounted. Multiple
         * retains of the same channel may therefore return one pointer. Keep
         * its one bridge identity until each matching ReleaseChannel arrives.
         * A different parent or provider remains ambiguous and is rejected. */
        if (kind == HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL &&
            existing->native_handle == identity &&
            existing->parent_identity == parent_identity &&
            existing->parent_kind == parent_kind &&
            existing->provider == provider) {
            if (existing->references == HYBRID580_UVM_TYPED_CHILD_REFCOUNT_MAX)
                return HYBRID580_UVM_TYPED_CHILD_REFCOUNT_OVERFLOW;
            ++existing->references;
            return HYBRID580_UVM_TYPED_CHILD_OK;
        }
        return HYBRID580_UVM_TYPED_CHILD_DUPLICATE;
    }

    *entry = (struct hybrid580_uvm_typed_child_entry) {
        .identity = identity,
        .native_handle = identity,
        .parent_identity = parent_identity,
        .parent_kind = parent_kind,
        .provider = provider,
        .kind = kind,
        .references = 1,
    };
    *link = entry;
    ++registry->count;
    return HYBRID580_UVM_TYPED_CHILD_OK;
}

static inline enum hybrid580_uvm_typed_child_status
hybrid580_uvm_typed_child_registry_remove(
    struct hybrid580_uvm_typed_child_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_typed_child_kind kind,
    struct hybrid580_uvm_typed_child_entry **removed)
{
    struct hybrid580_uvm_typed_child_entry **link;
    enum hybrid580_uvm_typed_child_parent_kind parent_kind;
    struct hybrid580_uvm_typed_child_entry *entry;

    if (removed != NULL)
        *removed = NULL;
    if (registry == NULL || identity == 0 ||
        !hybrid580_uvm_typed_child_kind_valid(kind))
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    parent_kind = kind == HYBRID580_UVM_TYPED_CHILD_TSG ?
                  HYBRID580_UVM_TYPED_CHILD_PARENT_TSG :
                  kind == HYBRID580_UVM_TYPED_CHILD_CHANNEL ?
                  HYBRID580_UVM_TYPED_CHILD_PARENT_CHANNEL :
                  kind == HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL ?
                  HYBRID580_UVM_TYPED_CHILD_PARENT_RETAINED_CHANNEL :
                  HYBRID580_UVM_TYPED_CHILD_PARENT_DUPED_MEMORY;
    if (hybrid580_uvm_typed_child_registry_has_parent(registry, identity,
                                                       parent_kind))
        return HYBRID580_UVM_TYPED_CHILD_HAS_CHILDREN;
    link = hybrid580_uvm_typed_child_find_link(registry, identity, kind);
    if (link == NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    if (*link == NULL)
        return HYBRID580_UVM_TYPED_CHILD_NOT_FOUND;
    entry = *link;
    if (entry->references != 1)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    *link = entry->next;
    entry->next = NULL;
    --registry->count;
    if (removed != NULL)
        *removed = entry;
    return HYBRID580_UVM_TYPED_CHILD_OK;
}

static inline int hybrid580_uvm_typed_child_call_ops_valid(
    struct hybrid580_uvm_typed_child_call_backend_ops open,
    struct hybrid580_uvm_typed_child_call_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.call != NULL && legacy.call != NULL;
}

static inline enum hybrid580_uvm_typed_child_status
hybrid580_uvm_typed_child_route_call(
    const struct hybrid580_uvm_typed_child_registry *registry,
    uintptr_t identity, enum hybrid580_uvm_typed_child_kind kind,
    void *params, struct hybrid580_uvm_typed_child_call_backend_ops open,
    struct hybrid580_uvm_typed_child_call_backend_ops legacy,
    uint32_t *backend_status)
{
    enum hybrid580_uvm_provider provider = 0;
    uintptr_t native_handle = 0;
    struct hybrid580_uvm_typed_child_call_backend_ops *selected;
    enum hybrid580_uvm_typed_child_status status;

    if (backend_status == NULL || params == NULL ||
        !hybrid580_uvm_typed_child_call_ops_valid(open, legacy))
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    *backend_status = 0;
    status = hybrid580_uvm_typed_child_registry_lookup(
        registry, identity, kind, &provider, &native_handle, NULL, NULL);
    if (status != HYBRID580_UVM_TYPED_CHILD_OK)
        return status;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    *backend_status = selected->call(selected->context, native_handle, params);
    return HYBRID580_UVM_TYPED_CHILD_OK;
}

static inline int hybrid580_uvm_typed_child_destroy_ops_valid(
    struct hybrid580_uvm_typed_child_destroy_backend_ops open,
    struct hybrid580_uvm_typed_child_destroy_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.destroy != NULL && legacy.destroy != NULL;
}

/* Caller serializes this map with the UVM bridge lock. Destroy is refused
 * while a child survives, then the provider-specific RM object is destroyed
 * and only afterward is the public identity removed.
 */
static inline enum hybrid580_uvm_typed_child_status
hybrid580_uvm_typed_child_route_destroy(
    struct hybrid580_uvm_typed_child_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_typed_child_kind kind,
    struct hybrid580_uvm_typed_child_destroy_backend_ops open,
    struct hybrid580_uvm_typed_child_destroy_backend_ops legacy,
    struct hybrid580_uvm_typed_child_entry **removed)
{
    enum hybrid580_uvm_provider provider = 0;
    uintptr_t native_handle = 0;
    struct hybrid580_uvm_typed_child_destroy_backend_ops *selected;
    struct hybrid580_uvm_typed_child_entry **link;
    enum hybrid580_uvm_typed_child_status status;
    enum hybrid580_uvm_typed_child_parent_kind parent_kind;
    struct hybrid580_uvm_typed_child_entry *entry;

    if (removed != NULL)
        *removed = NULL;
    if (registry == NULL || identity == 0 ||
        !hybrid580_uvm_typed_child_kind_valid(kind) ||
        !hybrid580_uvm_typed_child_destroy_ops_valid(open, legacy))
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    parent_kind = kind == HYBRID580_UVM_TYPED_CHILD_TSG ?
                  HYBRID580_UVM_TYPED_CHILD_PARENT_TSG :
                  kind == HYBRID580_UVM_TYPED_CHILD_CHANNEL ?
                  HYBRID580_UVM_TYPED_CHILD_PARENT_CHANNEL :
                  kind == HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL ?
                  HYBRID580_UVM_TYPED_CHILD_PARENT_RETAINED_CHANNEL :
                  HYBRID580_UVM_TYPED_CHILD_PARENT_DUPED_MEMORY;
    if (hybrid580_uvm_typed_child_registry_has_parent(registry, identity,
                                                       parent_kind))
        return HYBRID580_UVM_TYPED_CHILD_HAS_CHILDREN;
    status = hybrid580_uvm_typed_child_registry_lookup(
        registry, identity, kind, &provider, &native_handle, NULL, NULL);
    if (status != HYBRID580_UVM_TYPED_CHILD_OK)
        return status;
    link = hybrid580_uvm_typed_child_find_link(registry, identity, kind);
    if (link == NULL || *link == NULL)
        return HYBRID580_UVM_TYPED_CHILD_NOT_FOUND;
    entry = *link;
    if (entry->references == 0 ||
        (kind != HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL &&
         entry->references != 1))
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;
    selected->destroy(selected->context, native_handle);

    if (kind == HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL &&
        entry->references > 1) {
        --entry->references;
        return HYBRID580_UVM_TYPED_CHILD_OK;
    }

    {
        *link = entry->next;
        entry->next = NULL;
        --registry->count;
        if (removed != NULL)
            *removed = entry;
    }
    return HYBRID580_UVM_TYPED_CHILD_OK;
}

#endif
