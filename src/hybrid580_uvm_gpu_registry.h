/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_GPU_REGISTRY_H
#define HYBRID580_UVM_GPU_REGISTRY_H

#include "hybrid580-gpu-catalog.h"
#include "hybrid580_uvm_owner_map.h"

#define HYBRID580_UVM_GPU_UUID_BYTES 16U
#define HYBRID580_UVM_GPU_REGISTRY_CAPACITY HYBRID580_GPU_MAX_DEVICES

#ifdef __KERNEL__
#define HYBRID580_UVM_GPU_REFCOUNT_MAX U32_MAX
#else
#define HYBRID580_UVM_GPU_REFCOUNT_MAX UINT32_MAX
#endif

enum hybrid580_uvm_gpu_registry_status {
    HYBRID580_UVM_GPU_REGISTRY_OK = 0,
    HYBRID580_UVM_GPU_REGISTRY_INVALID = -1,
    HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND = -2,
    HYBRID580_UVM_GPU_REGISTRY_PROVIDER_CONFLICT = -3,
    HYBRID580_UVM_GPU_REGISTRY_FULL = -4,
    HYBRID580_UVM_GPU_REGISTRY_REFCOUNT_OVERFLOW = -5,
};

struct hybrid580_uvm_gpu_registry_entry {
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES];
    uint32_t references;
    enum hybrid580_uvm_provider provider;
    uint8_t active;
};

struct hybrid580_uvm_gpu_registry {
    uint32_t count;
    struct hybrid580_uvm_gpu_registry_entry entries[HYBRID580_UVM_GPU_REGISTRY_CAPACITY];
};

static inline size_t hybrid580_uvm_gpu_registry_find(
    const struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES])
{
    size_t i;

    if (registry == NULL || uuid == NULL)
        return SIZE_MAX;
    for (i = 0; i < HYBRID580_UVM_GPU_REGISTRY_CAPACITY; ++i) {
        if (registry->entries[i].active &&
            memcmp(registry->entries[i].uuid, uuid,
                   HYBRID580_UVM_GPU_UUID_BYTES) == 0)
            return i;
    }
    return SIZE_MAX;
}

static inline enum hybrid580_uvm_gpu_registry_status
hybrid580_uvm_gpu_registry_lookup(
    const struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    enum hybrid580_uvm_provider *provider,
    uint32_t *references)
{
    size_t slot;

    if (registry == NULL || uuid == NULL || provider == NULL)
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;
    slot = hybrid580_uvm_gpu_registry_find(registry, uuid);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND;
    *provider = registry->entries[slot].provider;
    if (references != NULL)
        *references = registry->entries[slot].references;
    return HYBRID580_UVM_GPU_REGISTRY_OK;
}

/* Compare frontend provider ownership without exposing provider-native GPU
 * handles. Unknown or unregistered UUIDs are errors, never compatible by
 * default. */
static inline enum hybrid580_uvm_gpu_registry_status
hybrid580_uvm_gpu_registry_same_provider(
    const struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid1[HYBRID580_UVM_GPU_UUID_BYTES],
    const unsigned char uuid2[HYBRID580_UVM_GPU_UUID_BYTES], int *same)
{
    enum hybrid580_uvm_provider provider1 = 0;
    enum hybrid580_uvm_provider provider2 = 0;
    enum hybrid580_uvm_gpu_registry_status status;

    if (same == NULL)
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;
    *same = 0;

    status = hybrid580_uvm_gpu_registry_lookup(registry, uuid1, &provider1, NULL);
    if (status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return status;
    status = hybrid580_uvm_gpu_registry_lookup(registry, uuid2, &provider2, NULL);
    if (status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return status;

    *same = provider1 == provider2;
    return HYBRID580_UVM_GPU_REGISTRY_OK;
}

/* Call only after the selected backend's RegisterGpu succeeded. Repeated
 * UUID registration is reference-counted; a UUID may never change provider. */
static inline enum hybrid580_uvm_gpu_registry_status
hybrid580_uvm_gpu_registry_record_success(
    struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    enum hybrid580_uvm_provider provider)
{
    size_t slot, free_slot = SIZE_MAX, i;

    if (registry == NULL || uuid == NULL || !hybrid580_uvm_provider_is_single(provider))
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;
    slot = hybrid580_uvm_gpu_registry_find(registry, uuid);
    if (slot != SIZE_MAX) {
        if (registry->entries[slot].provider != provider)
            return HYBRID580_UVM_GPU_REGISTRY_PROVIDER_CONFLICT;
        if (registry->entries[slot].references == HYBRID580_UVM_GPU_REFCOUNT_MAX)
            return HYBRID580_UVM_GPU_REGISTRY_REFCOUNT_OVERFLOW;
        ++registry->entries[slot].references;
        return HYBRID580_UVM_GPU_REGISTRY_OK;
    }

    for (i = 0; i < HYBRID580_UVM_GPU_REGISTRY_CAPACITY; ++i) {
        if (!registry->entries[i].active) {
            free_slot = i;
            break;
        }
    }
    if (free_slot == SIZE_MAX)
        return HYBRID580_UVM_GPU_REGISTRY_FULL;

    memcpy(registry->entries[free_slot].uuid, uuid,
           HYBRID580_UVM_GPU_UUID_BYTES);
    registry->entries[free_slot].provider = provider;
    registry->entries[free_slot].references = 1;
    registry->entries[free_slot].active = 1;
    ++registry->count;
    return HYBRID580_UVM_GPU_REGISTRY_OK;
}

/* Release one successful provider registration after calling its matching
 * void UnregisterGpu API. The entry disappears only at the last reference. */
static inline enum hybrid580_uvm_gpu_registry_status
hybrid580_uvm_gpu_registry_release(
    struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    enum hybrid580_uvm_provider *provider,
    uint32_t *references)
{
    size_t slot;

    if (registry == NULL || uuid == NULL || provider == NULL)
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;
    slot = hybrid580_uvm_gpu_registry_find(registry, uuid);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND;
    if (registry->entries[slot].references == 0)
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;

    *provider = registry->entries[slot].provider;
    --registry->entries[slot].references;
    if (registry->entries[slot].references == 0) {
        memset(&registry->entries[slot], 0, sizeof(registry->entries[slot]));
        --registry->count;
    }
    if (references != NULL)
        *references = registry->entries[slot].active ?
                      registry->entries[slot].references : 0;
    return HYBRID580_UVM_GPU_REGISTRY_OK;
}

#endif /* HYBRID580_UVM_GPU_REGISTRY_H */
