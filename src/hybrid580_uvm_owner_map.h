/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_OWNER_MAP_H
#define HYBRID580_UVM_OWNER_MAP_H

#ifdef __KERNEL__
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>
#define HYBRID580_UVM_U32_MAX U32_MAX
#define HYBRID580_UVM_U64_MAX U64_MAX
#else
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define HYBRID580_UVM_U32_MAX UINT32_MAX
#define HYBRID580_UVM_U64_MAX UINT64_MAX
#endif

/* The owner map stores UVM-visible identities separately from provider-native
 * handles. For ordinary RM objects they are the same pointer; for the logical
 * session and caller-owned fault/CSL structures they may differ. The caller
 * must serialize every operation (kernel integration: protect map mutations
 * and pins with a suitable lock, then call the backend without holding it).
 */
enum hybrid580_uvm_provider {
    HYBRID580_UVM_PROVIDER_OPEN = 1,
    HYBRID580_UVM_PROVIDER_LEGACY = 2,
};

#define HYBRID580_UVM_PROVIDER_BOTH \
    (HYBRID580_UVM_PROVIDER_OPEN | HYBRID580_UVM_PROVIDER_LEGACY)

enum hybrid580_uvm_object_kind {
    HYBRID580_UVM_SESSION = 1,
    HYBRID580_UVM_DEVICE,
    HYBRID580_UVM_ADDRESS_SPACE,
    HYBRID580_UVM_TSG,
    HYBRID580_UVM_CHANNEL,
    HYBRID580_UVM_COPY_ENGINE,
    HYBRID580_UVM_PAGING_CHANNEL,
    HYBRID580_UVM_PMA,
    HYBRID580_UVM_RETAINED_CHANNEL,
    HYBRID580_UVM_CPU_MAPPING,
    HYBRID580_UVM_FAULT_INFO,
    HYBRID580_UVM_CSL_CONTEXT,
};

enum hybrid580_uvm_owner_status {
    HYBRID580_UVM_OWNER_OK = 0,
    HYBRID580_UVM_OWNER_INVALID = -1,
    HYBRID580_UVM_OWNER_NOT_FOUND = -2,
    HYBRID580_UVM_OWNER_DUPLICATE = -3,
    HYBRID580_UVM_OWNER_FULL = -4,
    HYBRID580_UVM_OWNER_WRONG_KIND = -5,
    HYBRID580_UVM_OWNER_WRONG_PROVIDER = -6,
    HYBRID580_UVM_OWNER_BUSY = -7,
    HYBRID580_UVM_OWNER_HAS_CHILDREN = -8,
    HYBRID580_UVM_OWNER_PARENT_CLOSING = -9,
    HYBRID580_UVM_OWNER_BAD_REFERENCE = -10,
};

struct hybrid580_uvm_owner_entry {
    uintptr_t identity;
    uintptr_t parent_identity;
    uintptr_t native_open;
    uintptr_t native_legacy;
    uint64_t generation;
    uint32_t active_calls;
    enum hybrid580_uvm_object_kind kind;
    uint8_t provider_mask;
    uint8_t active;
    uint8_t retiring;
    uint8_t reserved;
};

struct hybrid580_uvm_owner_map {
    struct hybrid580_uvm_owner_entry *entries;
    size_t capacity;
    size_t count;
    uint64_t next_generation;
};

/* Ownership reference tokens are linear: acquire one pin and consume it with
 * exactly one unpin. Do not copy, persist, forge or concurrently reuse a token.
 * The generation field rejects stale tokens after identity reuse, but C cannot
 * detect two bytewise copies released during the same live generation.
 */
struct hybrid580_uvm_owner_ref {
    uintptr_t identity;
    uintptr_t native_handle;
    uint64_t generation;
    enum hybrid580_uvm_object_kind kind;
    enum hybrid580_uvm_provider provider;
};

static inline int hybrid580_uvm_provider_is_single(enum hybrid580_uvm_provider provider)
{
    return provider == HYBRID580_UVM_PROVIDER_OPEN ||
           provider == HYBRID580_UVM_PROVIDER_LEGACY;
}

static inline int hybrid580_uvm_provider_mask_valid(uint8_t mask)
{
    return mask == HYBRID580_UVM_PROVIDER_OPEN ||
           mask == HYBRID580_UVM_PROVIDER_LEGACY ||
           mask == HYBRID580_UVM_PROVIDER_BOTH;
}

static inline int hybrid580_uvm_kind_valid(enum hybrid580_uvm_object_kind kind)
{
    return kind >= HYBRID580_UVM_SESSION && kind <= HYBRID580_UVM_CSL_CONTEXT;
}

static inline int hybrid580_uvm_owner_map_init(struct hybrid580_uvm_owner_map *map,
                                                struct hybrid580_uvm_owner_entry *entries,
                                                size_t capacity)
{
    if (map == NULL || entries == NULL || capacity == 0 ||
        capacity > SIZE_MAX / sizeof(*entries))
        return HYBRID580_UVM_OWNER_INVALID;
    memset(entries, 0, capacity * sizeof(*entries));
    map->entries = entries;
    map->capacity = capacity;
    map->count = 0;
    map->next_generation = 1;
    return HYBRID580_UVM_OWNER_OK;
}

static inline size_t hybrid580_uvm_owner_find(const struct hybrid580_uvm_owner_map *map,
                                               uintptr_t identity)
{
    if (map == NULL || map->entries == NULL || identity == 0)
        return SIZE_MAX;
    for (size_t i = 0; i < map->capacity; ++i) {
        if (map->entries[i].active && map->entries[i].identity == identity)
            return i;
    }
    return SIZE_MAX;
}

static inline int hybrid580_uvm_owner_has_children(
    const struct hybrid580_uvm_owner_map *map, uintptr_t identity)
{
    for (size_t i = 0; i < map->capacity; ++i) {
        const struct hybrid580_uvm_owner_entry *child = &map->entries[i];
        if (child->active && child->parent_identity == identity)
            return 1;
    }
    return 0;
}

/* A BOTH session is represented by the Open child session as its UVM-visible
 * identity while retaining both provider child sessions. Ordinary child
 * objects carry a single-provider mask and retain provider-native pointers.
 */
static inline int hybrid580_uvm_owner_add(struct hybrid580_uvm_owner_map *map,
                                           uintptr_t identity,
                                           enum hybrid580_uvm_object_kind kind,
                                           uintptr_t parent_identity,
                                           uint8_t provider_mask,
                                           uintptr_t native_open,
                                           uintptr_t native_legacy)
{
    size_t free_slot = SIZE_MAX;
    size_t parent_slot;

    if (map == NULL || map->entries == NULL || identity == 0 ||
        !hybrid580_uvm_kind_valid(kind) ||
        !hybrid580_uvm_provider_mask_valid(provider_mask))
        return HYBRID580_UVM_OWNER_INVALID;
    if (((provider_mask & HYBRID580_UVM_PROVIDER_OPEN) != 0) != (native_open != 0) ||
        ((provider_mask & HYBRID580_UVM_PROVIDER_LEGACY) != 0) != (native_legacy != 0))
        return HYBRID580_UVM_OWNER_INVALID;
    if (map->next_generation == 0)
        return HYBRID580_UVM_OWNER_FULL;
    if (hybrid580_uvm_owner_find(map, identity) != SIZE_MAX)
        return HYBRID580_UVM_OWNER_DUPLICATE;

    if (parent_identity != 0) {
        parent_slot = hybrid580_uvm_owner_find(map, parent_identity);
        if (parent_slot == SIZE_MAX)
            return HYBRID580_UVM_OWNER_NOT_FOUND;
        if (map->entries[parent_slot].retiring)
            return HYBRID580_UVM_OWNER_PARENT_CLOSING;
        if ((provider_mask & map->entries[parent_slot].provider_mask) != provider_mask)
            return HYBRID580_UVM_OWNER_WRONG_PROVIDER;
    }

    for (size_t i = 0; i < map->capacity; ++i) {
        if (!map->entries[i].active) {
            free_slot = i;
            break;
        }
    }
    if (free_slot == SIZE_MAX)
        return HYBRID580_UVM_OWNER_FULL;

    map->entries[free_slot] = (struct hybrid580_uvm_owner_entry){
        .identity = identity,
        .parent_identity = parent_identity,
        .native_open = native_open,
        .native_legacy = native_legacy,
        .generation = map->next_generation,
        .kind = kind,
        .provider_mask = provider_mask,
        .active = 1,
    };
    map->next_generation = map->next_generation == HYBRID580_UVM_U64_MAX ? 0 :
                           map->next_generation + 1;
    ++map->count;
    return HYBRID580_UVM_OWNER_OK;
}

static inline int hybrid580_uvm_owner_pin_internal(
    struct hybrid580_uvm_owner_map *map, uintptr_t identity,
    enum hybrid580_uvm_object_kind expected_kind,
    enum hybrid580_uvm_provider provider, int allow_retiring,
    struct hybrid580_uvm_owner_ref *ref)
{
    size_t slot;
    struct hybrid580_uvm_owner_entry *entry;
    uintptr_t native_handle;

    if (map == NULL || ref == NULL || !hybrid580_uvm_provider_is_single(provider) ||
        !hybrid580_uvm_kind_valid(expected_kind) || identity == 0)
        return HYBRID580_UVM_OWNER_INVALID;
    if (ref->identity != 0)
        return HYBRID580_UVM_OWNER_BAD_REFERENCE;
    slot = hybrid580_uvm_owner_find(map, identity);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_OWNER_NOT_FOUND;
    entry = &map->entries[slot];
    if (entry->kind != expected_kind)
        return HYBRID580_UVM_OWNER_WRONG_KIND;
    if (entry->retiring && !allow_retiring)
        return HYBRID580_UVM_OWNER_BUSY;
    if (allow_retiring &&
        (!entry->retiring || entry->active_calls != 0 ||
         hybrid580_uvm_owner_has_children(map, identity)))
        return HYBRID580_UVM_OWNER_BUSY;
    if ((entry->provider_mask & provider) == 0)
        return HYBRID580_UVM_OWNER_WRONG_PROVIDER;
    if (entry->active_calls == HYBRID580_UVM_U32_MAX)
        return HYBRID580_UVM_OWNER_BUSY;
    native_handle = provider == HYBRID580_UVM_PROVIDER_OPEN ?
                    entry->native_open : entry->native_legacy;
    if (native_handle == 0)
        return HYBRID580_UVM_OWNER_INVALID;
    ++entry->active_calls;
    *ref = (struct hybrid580_uvm_owner_ref){
        .identity = identity,
        .native_handle = native_handle,
        .generation = entry->generation,
        .kind = expected_kind,
        .provider = provider,
    };
    return HYBRID580_UVM_OWNER_OK;
}

static inline int hybrid580_uvm_owner_pin(struct hybrid580_uvm_owner_map *map,
                                           uintptr_t identity,
                                           enum hybrid580_uvm_object_kind expected_kind,
                                           enum hybrid580_uvm_provider provider,
                                           struct hybrid580_uvm_owner_ref *ref)
{
    return hybrid580_uvm_owner_pin_internal(map, identity, expected_kind, provider,
                                             0, ref);
}

/* A single cleanup operation may pin a retiring leaf after begin_retire has
 * observed no active users or children. It does not permit ordinary use or
 * cancel retirement. Unpin it before retrying a failed backend destructor.
 */
static inline int hybrid580_uvm_owner_pin_for_cleanup(
    struct hybrid580_uvm_owner_map *map, uintptr_t identity,
    enum hybrid580_uvm_object_kind expected_kind,
    enum hybrid580_uvm_provider provider, struct hybrid580_uvm_owner_ref *ref)
{
    return hybrid580_uvm_owner_pin_internal(map, identity, expected_kind, provider,
                                             1, ref);
}

static inline int hybrid580_uvm_owner_unpin(struct hybrid580_uvm_owner_map *map,
                                             struct hybrid580_uvm_owner_ref *ref)
{
    size_t slot;
    struct hybrid580_uvm_owner_entry *entry;

    if (map == NULL || ref == NULL || ref->identity == 0 ||
        !hybrid580_uvm_provider_is_single(ref->provider))
        return HYBRID580_UVM_OWNER_BAD_REFERENCE;
    slot = hybrid580_uvm_owner_find(map, ref->identity);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_OWNER_BAD_REFERENCE;
    entry = &map->entries[slot];
    if (entry->kind != ref->kind || entry->generation != ref->generation ||
        entry->active_calls == 0 ||
        (ref->provider == HYBRID580_UVM_PROVIDER_OPEN &&
         (entry->provider_mask & HYBRID580_UVM_PROVIDER_OPEN) == 0) ||
        (ref->provider == HYBRID580_UVM_PROVIDER_LEGACY &&
         (entry->provider_mask & HYBRID580_UVM_PROVIDER_LEGACY) == 0) ||
        ref->native_handle != (ref->provider == HYBRID580_UVM_PROVIDER_OPEN ?
                               entry->native_open : entry->native_legacy))
        return HYBRID580_UVM_OWNER_BAD_REFERENCE;
    --entry->active_calls;
    memset(ref, 0, sizeof(*ref));
    return HYBRID580_UVM_OWNER_OK;
}

static inline int hybrid580_uvm_owner_pin_pair(struct hybrid580_uvm_owner_map *map,
                                                uintptr_t first_identity,
                                                enum hybrid580_uvm_object_kind first_kind,
                                                uintptr_t second_identity,
                                                enum hybrid580_uvm_object_kind second_kind,
                                                enum hybrid580_uvm_provider provider,
                                                struct hybrid580_uvm_owner_ref *first_ref,
                                                struct hybrid580_uvm_owner_ref *second_ref)
{
    int status;

    if (first_ref == NULL || second_ref == NULL || first_ref == second_ref)
        return HYBRID580_UVM_OWNER_INVALID;
    if (first_ref->identity != 0 || second_ref->identity != 0)
        return HYBRID580_UVM_OWNER_BAD_REFERENCE;
    status = hybrid580_uvm_owner_pin(map, first_identity, first_kind, provider, first_ref);
    if (status != HYBRID580_UVM_OWNER_OK)
        return status;
    status = hybrid580_uvm_owner_pin(map, second_identity, second_kind, provider, second_ref);
    if (status != HYBRID580_UVM_OWNER_OK) {
        (void)hybrid580_uvm_owner_unpin(map, first_ref);
        return status;
    }
    return HYBRID580_UVM_OWNER_OK;
}

/* Begin retirement before calling the backend destructor. This is idempotent:
 * it closes ordinary pins/child creation and reports users/children that must
 * drain first. It leaves the identity present so cleanup and failure retry
 * still have an owner record.
 */
static inline int hybrid580_uvm_owner_begin_retire(
    struct hybrid580_uvm_owner_map *map, uintptr_t identity,
    enum hybrid580_uvm_object_kind expected_kind)
{
    size_t slot;
    struct hybrid580_uvm_owner_entry *entry;

    if (map == NULL || map->entries == NULL || identity == 0 ||
        !hybrid580_uvm_kind_valid(expected_kind))
        return HYBRID580_UVM_OWNER_INVALID;
    slot = hybrid580_uvm_owner_find(map, identity);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_OWNER_NOT_FOUND;
    entry = &map->entries[slot];
    if (entry->kind != expected_kind)
        return HYBRID580_UVM_OWNER_WRONG_KIND;
    entry->retiring = 1;
    if (entry->active_calls != 0)
        return HYBRID580_UVM_OWNER_BUSY;
    if (hybrid580_uvm_owner_has_children(map, identity))
        return HYBRID580_UVM_OWNER_HAS_CHILDREN;
    return HYBRID580_UVM_OWNER_OK;
}

/* Call only after the backend confirms destruction/unregistration. This
 * finalizes a previously begun retirement; failures leave the identity
 * retiring and available for a controlled cleanup retry.
 */
static inline int hybrid580_uvm_owner_finish_retire(
    struct hybrid580_uvm_owner_map *map, uintptr_t identity,
    enum hybrid580_uvm_object_kind expected_kind)
{
    size_t slot;
    struct hybrid580_uvm_owner_entry *entry;

    if (map == NULL || map->entries == NULL || identity == 0 ||
        !hybrid580_uvm_kind_valid(expected_kind))
        return HYBRID580_UVM_OWNER_INVALID;
    slot = hybrid580_uvm_owner_find(map, identity);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_OWNER_NOT_FOUND;
    entry = &map->entries[slot];
    if (entry->kind != expected_kind)
        return HYBRID580_UVM_OWNER_WRONG_KIND;
    if (!entry->retiring)
        return HYBRID580_UVM_OWNER_INVALID;
    if (entry->active_calls != 0)
        return HYBRID580_UVM_OWNER_BUSY;
    if (hybrid580_uvm_owner_has_children(map, identity))
        return HYBRID580_UVM_OWNER_HAS_CHILDREN;
    memset(entry, 0, sizeof(*entry));
    --map->count;
    return HYBRID580_UVM_OWNER_OK;
}

#endif /* HYBRID580_UVM_OWNER_MAP_H */
