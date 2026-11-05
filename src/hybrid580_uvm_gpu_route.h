/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_GPU_ROUTE_H
#define HYBRID580_UVM_GPU_ROUTE_H

#include "hybrid580_uvm_gpu_registry.h"

struct hybrid580_uvm_gpu_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*register_gpu)(void *context,
                             const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
                             void *platform_info, size_t platform_info_size);
    void (*unregister_gpu)(void *context,
                           const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES]);
};

/* GetGpuInfo consumes UVM's caller-owned client handles; route those inputs to
 * the UUID owner without exposing a provider-native GPU handle to UVM. */
struct hybrid580_uvm_gpu_info_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*get_gpu_info)(void *context,
                             const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
                             const void *client_info, void *gpu_info);
};

static inline int hybrid580_uvm_gpu_info_backend_ops_valid(
    struct hybrid580_uvm_gpu_info_backend_ops open,
    struct hybrid580_uvm_gpu_info_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.get_gpu_info != NULL && legacy.get_gpu_info != NULL;
}

/* Do not retry an owner failure against the other RM. The UVM client and SMC
 * handles belong to the RM which created the UUID-owning physical device. */
static inline uint32_t hybrid580_uvm_gpu_route_get_info(
    const struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    const void *client_info, void *gpu_info, size_t gpu_info_size,
    struct hybrid580_uvm_gpu_info_backend_ops open,
    struct hybrid580_uvm_gpu_info_backend_ops legacy,
    uint32_t uuid_not_found_status, uint32_t generic_status)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_gpu_info_backend_ops *selected;
    enum hybrid580_uvm_gpu_registry_status status;
    uint32_t provider_status;

    /* Providers may fill part of the result before reporting an error. */
    if (gpu_info != NULL && gpu_info_size != 0)
        memset(gpu_info, 0, gpu_info_size);

    if (registry == NULL || uuid == NULL || client_info == NULL ||
        gpu_info == NULL || gpu_info_size == 0 ||
        !hybrid580_uvm_gpu_info_backend_ops_valid(open, legacy))
        return generic_status;

    status = hybrid580_uvm_gpu_registry_lookup(registry, uuid, &provider, NULL);
    if (status == HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND)
        return uuid_not_found_status;
    if (status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return generic_status;

    if (provider == HYBRID580_UVM_PROVIDER_OPEN)
        selected = &open;
    else if (provider == HYBRID580_UVM_PROVIDER_LEGACY)
        selected = &legacy;
    else
        return generic_status;

    provider_status = selected->get_gpu_info(selected->context, uuid,
                                              client_info, gpu_info);
    if (provider_status != 0)
        memset(gpu_info, 0, gpu_info_size);
    return provider_status;
}

static inline int hybrid580_uvm_gpu_backend_ops_valid(
    struct hybrid580_uvm_gpu_backend_ops open,
    struct hybrid580_uvm_gpu_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.register_gpu != NULL && open.unregister_gpu != NULL &&
           legacy.register_gpu != NULL && legacy.unregister_gpu != NULL;
}

static inline uint32_t hybrid580_uvm_gpu_registry_error(
    enum hybrid580_uvm_gpu_registry_status status,
    uint32_t no_memory_status, uint32_t generic_status)
{
    if (status == HYBRID580_UVM_GPU_REGISTRY_FULL ||
        status == HYBRID580_UVM_GPU_REGISTRY_REFCOUNT_OVERFLOW)
        return no_memory_status;
    if (status == HYBRID580_UVM_GPU_REGISTRY_OK)
        return 0;
    return generic_status;
}

/* Resolve a new UUID by asking each isolated provider. The R580 provider
 * contract reports GPU_UUID_NOT_FOUND for a UUID it does not own. Once a
 * provider is recorded, repeated registrations call only that provider. */
static inline uint32_t hybrid580_uvm_gpu_route_register(
    struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    void *platform_info, size_t platform_info_size,
    void *open_platform_info, void *legacy_platform_info,
    struct hybrid580_uvm_gpu_backend_ops open,
    struct hybrid580_uvm_gpu_backend_ops legacy,
    uint32_t uuid_not_found_status,
    uint32_t no_memory_status,
    uint32_t generic_status)
{
    enum hybrid580_uvm_provider provider = 0;
    uint32_t references = 0;
    uint32_t open_status, legacy_status;
    void *selected_platform_info = NULL;
    enum hybrid580_uvm_gpu_registry_status map_status;

    if (registry == NULL || uuid == NULL || platform_info == NULL ||
        platform_info_size == 0 || open_platform_info == NULL ||
        legacy_platform_info == NULL ||
        !hybrid580_uvm_gpu_backend_ops_valid(open, legacy))
        return generic_status;

    map_status = hybrid580_uvm_gpu_registry_lookup(registry, uuid, &provider,
                                                    &references);
    if (map_status == HYBRID580_UVM_GPU_REGISTRY_OK) {
        struct hybrid580_uvm_gpu_backend_ops *selected;
        uint32_t selected_status;
        if (references == HYBRID580_UVM_GPU_REFCOUNT_MAX)
            return no_memory_status;
        selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open : &legacy;
        selected_platform_info = provider == HYBRID580_UVM_PROVIDER_OPEN ?
                                 open_platform_info : legacy_platform_info;
        memset(selected_platform_info, 0, platform_info_size);
        selected_status = selected->register_gpu(selected->context, uuid,
                                                 selected_platform_info,
                                                 platform_info_size);
        if (selected_status != 0)
            return selected_status;
        map_status = hybrid580_uvm_gpu_registry_record_success(registry, uuid,
                                                               provider);
        if (map_status != HYBRID580_UVM_GPU_REGISTRY_OK) {
            selected->unregister_gpu(selected->context, uuid);
            return hybrid580_uvm_gpu_registry_error(map_status,
                                                     no_memory_status,
                                                     generic_status);
        }
        memcpy(platform_info, selected_platform_info, platform_info_size);
        return 0;
    }
    if (map_status != HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND)
        return hybrid580_uvm_gpu_registry_error(map_status, no_memory_status,
                                                 generic_status);

    memset(open_platform_info, 0, platform_info_size);
    memset(legacy_platform_info, 0, platform_info_size);
    open_status = open.register_gpu(open.context, uuid, open_platform_info,
                                    platform_info_size);
    legacy_status = legacy.register_gpu(legacy.context, uuid, legacy_platform_info,
                                        platform_info_size);

    if (open_status == 0 && legacy_status == 0) {
        open.unregister_gpu(open.context, uuid);
        legacy.unregister_gpu(legacy.context, uuid);
        return generic_status;
    }

    if (open_status == 0 && legacy_status == uuid_not_found_status) {
        provider = HYBRID580_UVM_PROVIDER_OPEN;
        selected_platform_info = open_platform_info;
    } else if (legacy_status == 0 && open_status == uuid_not_found_status) {
        provider = HYBRID580_UVM_PROVIDER_LEGACY;
        selected_platform_info = legacy_platform_info;
    } else {
        if (open_status == 0)
            open.unregister_gpu(open.context, uuid);
        if (legacy_status == 0)
            legacy.unregister_gpu(legacy.context, uuid);
        if (open_status != 0 && open_status != uuid_not_found_status)
            return open_status;
        if (legacy_status != 0 && legacy_status != uuid_not_found_status)
            return legacy_status;
        return uuid_not_found_status;
    }

    map_status = hybrid580_uvm_gpu_registry_record_success(registry, uuid,
                                                           provider);
    if (map_status != HYBRID580_UVM_GPU_REGISTRY_OK) {
        if (provider == HYBRID580_UVM_PROVIDER_OPEN)
            open.unregister_gpu(open.context, uuid);
        else
            legacy.unregister_gpu(legacy.context, uuid);
        return hybrid580_uvm_gpu_registry_error(map_status, no_memory_status,
                                                 generic_status);
    }

    memcpy(platform_info, selected_platform_info, platform_info_size);
    return 0;
}

static inline enum hybrid580_uvm_gpu_registry_status
hybrid580_uvm_gpu_route_unregister(
    struct hybrid580_uvm_gpu_registry *registry,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    struct hybrid580_uvm_gpu_backend_ops open,
    struct hybrid580_uvm_gpu_backend_ops legacy)
{
    enum hybrid580_uvm_provider provider = 0;
    uint32_t references;
    enum hybrid580_uvm_gpu_registry_status status;

    if (registry == NULL || uuid == NULL ||
        !hybrid580_uvm_gpu_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;
    status = hybrid580_uvm_gpu_registry_lookup(registry, uuid, &provider,
                                                &references);
    if (status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return status;
    if (references == 0)
        return HYBRID580_UVM_GPU_REGISTRY_INVALID;

    if (provider == HYBRID580_UVM_PROVIDER_OPEN)
        open.unregister_gpu(open.context, uuid);
    else
        legacy.unregister_gpu(legacy.context, uuid);
    return hybrid580_uvm_gpu_registry_release(registry, uuid, &provider, NULL);
}

#endif /* HYBRID580_UVM_GPU_ROUTE_H */
