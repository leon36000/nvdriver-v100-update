/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_DEVICE_ROUTE_H
#define HYBRID580_UVM_DEVICE_ROUTE_H

#include "hybrid580_uvm_gpu_registry.h"

enum hybrid580_uvm_device_registry_status {
    HYBRID580_UVM_DEVICE_REGISTRY_OK = 0,
    HYBRID580_UVM_DEVICE_REGISTRY_INVALID = -1,
    HYBRID580_UVM_DEVICE_REGISTRY_NOT_FOUND = -2,
    HYBRID580_UVM_DEVICE_REGISTRY_DUPLICATE = -3,
    HYBRID580_UVM_DEVICE_REGISTRY_FULL = -4,
    HYBRID580_UVM_DEVICE_REGISTRY_BUSY = -5,
};

struct hybrid580_uvm_device_registry_entry {
    uintptr_t identity;
    uintptr_t native_handle;
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES];
    enum hybrid580_uvm_provider provider;
    uint8_t active;
};

/* DeviceCreate returns an opaque pointer-sized native RM identity. Keeping
 * that pointer as UVM's opaque handle lets every later interface use it
 * unchanged, while this table records which private RM may consume it. The
 * bridge serializes access to this fixed inventory with its UVM mutex.
 */
struct hybrid580_uvm_device_registry {
    uint32_t count;
    struct hybrid580_uvm_device_registry_entry
        entries[HYBRID580_UVM_GPU_REGISTRY_CAPACITY];
};

struct hybrid580_uvm_device_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_session;
    uint32_t (*create)(void *context, uintptr_t native_session,
                       const void *gpu_info,
                       const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
                       int create_smc_partition, uintptr_t *native_device);
    void (*destroy)(void *context, uintptr_t native_device);
};

struct hybrid580_uvm_device_call_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*call)(void *context, uintptr_t native_device, void *params);
};

struct hybrid580_uvm_device_pair_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*call)(void *context, uintptr_t native_device1,
                     uintptr_t native_device2, void *params);
};

enum hybrid580_uvm_device_pair_route_status {
    HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK = 0,
    HYBRID580_UVM_DEVICE_PAIR_ROUTE_INVALID = -1,
    HYBRID580_UVM_DEVICE_PAIR_ROUTE_NOT_FOUND = -2,
    HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER = -3,
};

static inline size_t hybrid580_uvm_device_registry_find(
    const struct hybrid580_uvm_device_registry *registry, uintptr_t identity)
{
    size_t i;

    if (registry == NULL || identity == 0)
        return SIZE_MAX;
    for (i = 0; i < HYBRID580_UVM_GPU_REGISTRY_CAPACITY; ++i) {
        if (registry->entries[i].active &&
            registry->entries[i].identity == identity)
            return i;
    }
    return SIZE_MAX;
}

static inline uint32_t hybrid580_uvm_device_registry_count(
    const struct hybrid580_uvm_device_registry *registry)
{
    return registry == NULL ? 0 : registry->count;
}

static inline int hybrid580_uvm_device_registry_has_room(
    const struct hybrid580_uvm_device_registry *registry)
{
    size_t i;

    if (registry == NULL)
        return 0;
    for (i = 0; i < HYBRID580_UVM_GPU_REGISTRY_CAPACITY; ++i) {
        if (!registry->entries[i].active)
            return 1;
    }
    return 0;
}

static inline enum hybrid580_uvm_device_registry_status
hybrid580_uvm_device_registry_record(
    struct hybrid580_uvm_device_registry *registry, uintptr_t native_handle,
    enum hybrid580_uvm_provider provider,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES])
{
    size_t i;

    if (registry == NULL || native_handle == 0 || uuid == NULL ||
        !hybrid580_uvm_provider_is_single(provider))
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;
    if (hybrid580_uvm_device_registry_find(registry, native_handle) != SIZE_MAX)
        return HYBRID580_UVM_DEVICE_REGISTRY_DUPLICATE;
    for (i = 0; i < HYBRID580_UVM_GPU_REGISTRY_CAPACITY; ++i) {
        if (!registry->entries[i].active) {
            registry->entries[i] = (struct hybrid580_uvm_device_registry_entry) {
                .identity = native_handle,
                .native_handle = native_handle,
                .provider = provider,
                .active = 1,
            };
            memcpy(registry->entries[i].uuid, uuid,
                   HYBRID580_UVM_GPU_UUID_BYTES);
            ++registry->count;
            return HYBRID580_UVM_DEVICE_REGISTRY_OK;
        }
    }
    return HYBRID580_UVM_DEVICE_REGISTRY_FULL;
}

static inline enum hybrid580_uvm_device_registry_status
hybrid580_uvm_device_registry_lookup(
    const struct hybrid580_uvm_device_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_provider *provider, uintptr_t *native_handle)
{
    size_t slot;

    if (registry == NULL || identity == 0 || provider == NULL)
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;
    slot = hybrid580_uvm_device_registry_find(registry, identity);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_DEVICE_REGISTRY_NOT_FOUND;
    *provider = registry->entries[slot].provider;
    if (native_handle != NULL)
        *native_handle = registry->entries[slot].native_handle;
    return HYBRID580_UVM_DEVICE_REGISTRY_OK;
}

static inline enum hybrid580_uvm_device_registry_status
hybrid580_uvm_device_registry_release(
    struct hybrid580_uvm_device_registry *registry, uintptr_t identity,
    enum hybrid580_uvm_provider provider)
{
    size_t slot;

    if (registry == NULL || identity == 0 ||
        !hybrid580_uvm_provider_is_single(provider))
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;
    slot = hybrid580_uvm_device_registry_find(registry, identity);
    if (slot == SIZE_MAX)
        return HYBRID580_UVM_DEVICE_REGISTRY_NOT_FOUND;
    if (registry->entries[slot].provider != provider)
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;
    memset(&registry->entries[slot], 0, sizeof(registry->entries[slot]));
    --registry->count;
    return HYBRID580_UVM_DEVICE_REGISTRY_OK;
}

static inline int hybrid580_uvm_device_backend_ops_valid(
    struct hybrid580_uvm_device_backend_ops open,
    struct hybrid580_uvm_device_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.native_session != 0 && legacy.native_session != 0 &&
           open.create != NULL && open.destroy != NULL &&
           legacy.create != NULL && legacy.destroy != NULL;
}

/* Create only on the RM that registered this UUID. The other provider is
 * never an error fallback: its session and device handle are unrelated RM
 * objects. SMC/GI child devices are refused until their separate handle
 * namespace has an explicit translation map.
 */
static inline uint32_t hybrid580_uvm_device_route_create(
    const struct hybrid580_uvm_gpu_registry *gpus,
    struct hybrid580_uvm_device_registry *devices,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    const void *gpu_info, int create_smc_partition,
    struct hybrid580_uvm_device_backend_ops open,
    struct hybrid580_uvm_device_backend_ops legacy,
    uint32_t uuid_not_found_status, uint32_t no_memory_status,
    uint32_t not_supported_status, uint32_t generic_status,
    uintptr_t *public_device, int *quarantine)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_device_backend_ops *selected;
    enum hybrid580_uvm_gpu_registry_status gpu_status;
    enum hybrid580_uvm_device_registry_status device_status;
    uintptr_t native_device = 0;
    uint32_t status;

    if (public_device == NULL)
        return generic_status;
    *public_device = 0;
    if (quarantine != NULL)
        *quarantine = 0;
    if (gpus == NULL || devices == NULL || uuid == NULL || gpu_info == NULL ||
        !hybrid580_uvm_device_backend_ops_valid(open, legacy))
        return generic_status;
    if (create_smc_partition)
        return not_supported_status;
    gpu_status = hybrid580_uvm_gpu_registry_lookup(gpus, uuid, &provider, NULL);
    if (gpu_status == HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND)
        return uuid_not_found_status;
    if (gpu_status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return generic_status;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return generic_status;
    if (!hybrid580_uvm_device_registry_has_room(devices))
        return no_memory_status;

    status = selected->create(selected->context, selected->native_session,
                              gpu_info, uuid, create_smc_partition,
                              &native_device);
    if (status != 0) {
        /* A failed create with a non-null output has ambiguous ownership. */
        if (native_device != 0 && quarantine != NULL)
            *quarantine = 1;
        return status;
    }
    if (native_device == 0)
        return generic_status;

    device_status = hybrid580_uvm_device_registry_record(devices, native_device,
                                                          provider, uuid);
    if (device_status == HYBRID580_UVM_DEVICE_REGISTRY_DUPLICATE) {
        /* It could alias the already-live object. Destroying it could tear
         * down that object, so retain the ambiguity and pin the frontend. */
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    if (device_status != HYBRID580_UVM_DEVICE_REGISTRY_OK) {
        selected->destroy(selected->context, native_device);
        return device_status == HYBRID580_UVM_DEVICE_REGISTRY_FULL ?
               no_memory_status : generic_status;
    }

    *public_device = native_device;
    return 0;
}

static inline int hybrid580_uvm_device_call_backend_ops_valid(
    struct hybrid580_uvm_device_call_backend_ops open,
    struct hybrid580_uvm_device_call_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.call != NULL && legacy.call != NULL;
}

/* Route a device-scoped API through the provider recorded at creation. Return
 * the ownership lookup separately from the backend NV_STATUS so callers can
 * distinguish an unknown handle from a normal RM failure. */
static inline enum hybrid580_uvm_device_registry_status
hybrid580_uvm_device_route_call(
    const struct hybrid580_uvm_device_registry *devices,
    uintptr_t public_device, void *params,
    struct hybrid580_uvm_device_call_backend_ops open,
    struct hybrid580_uvm_device_call_backend_ops legacy,
    uint32_t *backend_status)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_device_call_backend_ops *selected;
    uintptr_t native_device = 0;
    enum hybrid580_uvm_device_registry_status status;

    if (backend_status == NULL || params == NULL ||
        !hybrid580_uvm_device_call_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;
    *backend_status = 0;
    status = hybrid580_uvm_device_registry_lookup(devices, public_device,
                                                   &provider, &native_device);
    if (status != HYBRID580_UVM_DEVICE_REGISTRY_OK)
        return status;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;

    *backend_status = selected->call(selected->context, native_device, params);
    return HYBRID580_UVM_DEVICE_REGISTRY_OK;
}

static inline int hybrid580_uvm_device_pair_backend_ops_valid(
    struct hybrid580_uvm_device_pair_backend_ops open,
    struct hybrid580_uvm_device_pair_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN && open.call != NULL &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           legacy.call != NULL;
}

/* A device-pair API can only receive native handles from one RM namespace.
 * Report a cross-provider pair distinctly so the standard UVM facade can
 * synthesize a documented no-link result for capability queries or reject an
 * operation that must allocate an RM object. Never guess one owner or pass a
 * foreign provider's pointer to a backend. */
static inline enum hybrid580_uvm_device_pair_route_status
hybrid580_uvm_device_route_pair_call(
    const struct hybrid580_uvm_device_registry *devices,
    uintptr_t public_device1, uintptr_t public_device2, void *params,
    struct hybrid580_uvm_device_pair_backend_ops open,
    struct hybrid580_uvm_device_pair_backend_ops legacy,
    uint32_t *backend_status)
{
    enum hybrid580_uvm_provider provider1 = 0;
    enum hybrid580_uvm_provider provider2 = 0;
    struct hybrid580_uvm_device_pair_backend_ops *selected;
    uintptr_t native_device1 = 0;
    uintptr_t native_device2 = 0;
    enum hybrid580_uvm_device_registry_status status1;
    enum hybrid580_uvm_device_registry_status status2;

    if (backend_status == NULL || params == NULL || devices == NULL ||
        public_device1 == 0 || public_device2 == 0 ||
        public_device1 == public_device2 ||
        !hybrid580_uvm_device_pair_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_DEVICE_PAIR_ROUTE_INVALID;
    *backend_status = 0;
    status1 = hybrid580_uvm_device_registry_lookup(
        devices, public_device1, &provider1, &native_device1);
    status2 = hybrid580_uvm_device_registry_lookup(
        devices, public_device2, &provider2, &native_device2);
    if (status1 != HYBRID580_UVM_DEVICE_REGISTRY_OK ||
        status2 != HYBRID580_UVM_DEVICE_REGISTRY_OK)
        return HYBRID580_UVM_DEVICE_PAIR_ROUTE_NOT_FOUND;
    if (provider1 != provider2)
        return HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER;

    selected = provider1 == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider1 == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL || native_device1 == 0 || native_device2 == 0)
        return HYBRID580_UVM_DEVICE_PAIR_ROUTE_INVALID;
    *backend_status = selected->call(selected->context, native_device1,
                                     native_device2, params);
    return HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK;
}

/* The standard R580 interface returns void, so a returned RM destructor call
 * is the only observable completion point. The caller holds the bridge lock
 * and quarantines the module if the ownership record is inconsistent.
 */
static inline enum hybrid580_uvm_device_registry_status
hybrid580_uvm_device_route_destroy(
    struct hybrid580_uvm_device_registry *devices, uintptr_t public_device,
    struct hybrid580_uvm_device_backend_ops open,
    struct hybrid580_uvm_device_backend_ops legacy)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_device_backend_ops *selected;
    uintptr_t native_device = 0;
    enum hybrid580_uvm_device_registry_status status;

    if (devices == NULL ||
        !hybrid580_uvm_device_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;
    status = hybrid580_uvm_device_registry_lookup(devices, public_device,
                                                   &provider, &native_device);
    if (status != HYBRID580_UVM_DEVICE_REGISTRY_OK)
        return status;
    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL || native_device != public_device)
        return HYBRID580_UVM_DEVICE_REGISTRY_INVALID;

    selected->destroy(selected->context, native_device);
    return hybrid580_uvm_device_registry_release(devices, public_device,
                                                  provider);
}

#endif /* HYBRID580_UVM_DEVICE_ROUTE_H */
