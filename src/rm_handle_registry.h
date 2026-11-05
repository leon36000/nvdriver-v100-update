/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_RM_HANDLE_REGISTRY_H
#define HYBRID580_RM_HANDLE_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

/* The observer already bounds the syscall journal to 8192 records. Keeping a
 * separate bounded live-object table makes exhaustion explicit and fail-closed. */
#define RM_HANDLE_REGISTRY_CAPACITY 8192U

enum rm_handle_resolution {
    RM_HANDLE_ABSENT = 0,
    RM_HANDLE_RESOLVED = 1,
    RM_HANDLE_NOT_OBSERVED = 2,
    RM_HANDLE_INVALID_ROOT = 3,
    RM_HANDLE_AMBIGUOUS = 4,
};

struct rm_handle_registry_entry {
    uint32_t root;
    uint32_t handle;
    uint32_t parent_handle;
    uint32_t class_id;
    unsigned int active;
};

struct rm_handle_registry {
    size_t count;
    struct rm_handle_registry_entry entries[RM_HANDLE_REGISTRY_CAPACITY];
};

static inline enum rm_handle_resolution rm_handle_registry_lookup(
    const struct rm_handle_registry *registry, uint32_t root, uint32_t handle,
    uint32_t *class_id)
{
    size_t matches = 0;
    uint32_t found_class = 0;

    if (class_id != NULL)
        *class_id = 0;
    if (handle == 0)
        return RM_HANDLE_ABSENT;
    if (root == 0 || registry == NULL)
        return RM_HANDLE_INVALID_ROOT;

    for (size_t i = 0; i < RM_HANDLE_REGISTRY_CAPACITY; ++i) {
        const struct rm_handle_registry_entry *entry = &registry->entries[i];
        if (entry->active && entry->root == root && entry->handle == handle) {
            ++matches;
            found_class = entry->class_id;
        }
    }
    if (matches == 0)
        return RM_HANDLE_NOT_OBSERVED;
    if (matches != 1)
        return RM_HANDLE_AMBIGUOUS;
    if (class_id != NULL)
        *class_id = found_class;
    return RM_HANDLE_RESOLVED;
}

/* Resolve a handle to its owning root only when the observed live-object
 * evidence gives exactly one answer. RM handles are root-scoped, so callers
 * must not guess a root for control packets that carry hClient but no hRoot. */
static inline enum rm_handle_resolution rm_handle_registry_root_for_handle(
    const struct rm_handle_registry *registry, uint32_t handle,
    uint32_t *root)
{
    size_t matches = 0;
    uint32_t found_root = 0;

    if (root != NULL)
        *root = 0;
    if (handle == 0)
        return RM_HANDLE_ABSENT;
    if (registry == NULL)
        return RM_HANDLE_INVALID_ROOT;

    for (size_t i = 0; i < RM_HANDLE_REGISTRY_CAPACITY; ++i) {
        const struct rm_handle_registry_entry *entry = &registry->entries[i];
        if (entry->active && entry->handle == handle) {
            ++matches;
            found_root = entry->root;
        }
    }
    if (matches == 0)
        return RM_HANDLE_NOT_OBSERVED;
    if (matches != 1)
        return RM_HANDLE_AMBIGUOUS;
    if (root != NULL)
        *root = found_root;
    return RM_HANDLE_RESOLVED;
}

/* Resolve only the direct parent's class. The parent handle itself never
 * leaves the bounded in-memory registry or appears in observer output. */
static inline enum rm_handle_resolution rm_handle_registry_lookup_parent_class(
    const struct rm_handle_registry *registry, uint32_t root, uint32_t handle,
    uint32_t *parent_class_id)
{
    size_t matches = 0;
    uint32_t parent_handle = 0;

    if (parent_class_id != NULL)
        *parent_class_id = 0;
    if (handle == 0)
        return RM_HANDLE_ABSENT;
    if (root == 0 || registry == NULL)
        return RM_HANDLE_INVALID_ROOT;

    for (size_t i = 0; i < RM_HANDLE_REGISTRY_CAPACITY; ++i) {
        const struct rm_handle_registry_entry *entry = &registry->entries[i];
        if (entry->active && entry->root == root && entry->handle == handle) {
            ++matches;
            parent_handle = entry->parent_handle;
        }
    }
    if (matches == 0)
        return RM_HANDLE_NOT_OBSERVED;
    if (matches != 1)
        return RM_HANDLE_AMBIGUOUS;
    return rm_handle_registry_lookup(registry, root, parent_handle,
                                     parent_class_id);
}

/* Returns 0 on insertion, -1 for invalid input, -2 for duplicate live identity,
 * and -3 when the bounded table is full. Numeric handles may repeat under a
 * different root, as RM handles are root-scoped. */
static inline int rm_handle_registry_insert(struct rm_handle_registry *registry,
                                            uint32_t root, uint32_t handle,
                                            uint32_t parent_handle,
                                            uint32_t class_id)
{
    size_t free_slot = RM_HANDLE_REGISTRY_CAPACITY;

    if (registry == NULL || root == 0 || handle == 0)
        return -1;
    for (size_t i = 0; i < RM_HANDLE_REGISTRY_CAPACITY; ++i) {
        struct rm_handle_registry_entry *entry = &registry->entries[i];
        if (!entry->active) {
            if (free_slot == RM_HANDLE_REGISTRY_CAPACITY)
                free_slot = i;
            continue;
        }
        if (entry->root == root && entry->handle == handle)
            return -2;
    }
    if (free_slot == RM_HANDLE_REGISTRY_CAPACITY)
        return -3;
    registry->entries[free_slot] = (struct rm_handle_registry_entry){
        .root = root,
        .handle = handle,
        .parent_handle = parent_handle,
        .class_id = class_id,
        .active = 1,
    };
    ++registry->count;
    return 0;
}

/* Returns 1 when removed, 0 when no live identity was observed, and -2 if the
 * evidence is ambiguous. */
static inline int rm_handle_registry_remove(struct rm_handle_registry *registry,
                                            uint32_t root, uint32_t handle)
{
    size_t found = RM_HANDLE_REGISTRY_CAPACITY;
    size_t matches = 0;

    if (registry == NULL || root == 0 || handle == 0)
        return 0;
    for (size_t i = 0; i < RM_HANDLE_REGISTRY_CAPACITY; ++i) {
        struct rm_handle_registry_entry *entry = &registry->entries[i];
        if (entry->active && entry->root == root && entry->handle == handle) {
            found = i;
            ++matches;
        }
    }
    if (matches == 0)
        return 0;
    if (matches != 1)
        return -2;
    registry->entries[found].active = 0;
    --registry->count;
    return 1;
}

static inline size_t rm_handle_registry_remove_root(
    struct rm_handle_registry *registry, uint32_t root)
{
    size_t removed = 0;

    if (registry == NULL || root == 0)
        return 0;
    for (size_t i = 0; i < RM_HANDLE_REGISTRY_CAPACITY; ++i) {
        struct rm_handle_registry_entry *entry = &registry->entries[i];
        if (entry->active && entry->root == root) {
            entry->active = 0;
            ++removed;
        }
    }
    registry->count -= removed;
    return removed;
}

#endif
