/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_gpu_route.h"

#define STATUS_UUID_NOT_FOUND UINT32_C(0xe0010001)
#define STATUS_NO_MEMORY      UINT32_C(0xe0010002)
#define STATUS_GENERIC        UINT32_C(0xe0010003)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0010004)

struct gpu_platform_result {
    uint64_t dma_start;
    uint64_t dma_limit;
    uint32_t provider_mark;
};

struct fake_provider {
    uint32_t register_status;
    uint32_t mark;
    unsigned register_calls;
    unsigned unregister_calls;
};

static uint32_t fake_register(void *context, const unsigned char *uuid,
                              void *platform_info, size_t platform_info_size)
{
    struct fake_provider *provider = context;
    struct gpu_platform_result result = {
        .dma_start = 0x10000000ULL + provider->mark,
        .dma_limit = 0x1fffffffULL,
        .provider_mark = provider->mark,
    };
    assert(uuid != NULL);
    ++provider->register_calls;
    if (provider->register_status == 0) {
        assert(platform_info_size == sizeof(result));
        memcpy(platform_info, &result, sizeof(result));
    }
    return provider->register_status;
}

static void fake_unregister(void *context, const unsigned char *uuid)
{
    struct fake_provider *provider = context;
    assert(uuid != NULL);
    ++provider->unregister_calls;
}

static struct hybrid580_uvm_gpu_backend_ops make_ops(
    struct fake_provider *provider, enum hybrid580_uvm_provider owner)
{
    return (struct hybrid580_uvm_gpu_backend_ops) {
        .context = provider,
        .provider = owner,
        .register_gpu = fake_register,
        .unregister_gpu = fake_unregister,
    };
}

static uint32_t register_gpu(struct hybrid580_uvm_gpu_registry *registry,
                             const unsigned char *uuid,
                             struct gpu_platform_result *output,
                             struct fake_provider *open,
                             struct fake_provider *legacy)
{
    struct gpu_platform_result open_result = {0};
    struct gpu_platform_result legacy_result = {0};
    return hybrid580_uvm_gpu_route_register(
        registry, uuid, output, sizeof(*output), &open_result, &legacy_result,
        make_ops(open, HYBRID580_UVM_PROVIDER_OPEN),
        make_ops(legacy, HYBRID580_UVM_PROVIDER_LEGACY),
        STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY, STATUS_GENERIC);
}

static enum hybrid580_uvm_gpu_registry_status unregister_gpu(
    struct hybrid580_uvm_gpu_registry *registry, const unsigned char *uuid,
    struct fake_provider *open, struct fake_provider *legacy)
{
    return hybrid580_uvm_gpu_route_unregister(
        registry, uuid, make_ops(open, HYBRID580_UVM_PROVIDER_OPEN),
        make_ops(legacy, HYBRID580_UVM_PROVIDER_LEGACY));
}

int main(void)
{
    struct hybrid580_uvm_gpu_registry registry = {0};
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0};
    struct gpu_platform_result output;
    struct fake_provider open = {.register_status = 0, .mark = 1};
    struct fake_provider legacy = {.register_status = STATUS_UUID_NOT_FOUND, .mark = 2};
    enum hybrid580_uvm_provider owner = 0;
    uint32_t references = 0;

    uuid[0] = 0x71;
    memset(&output, 0xa5, sizeof(output));
    assert(register_gpu(&registry, uuid, &output, &open, &legacy) == 0);
    assert(output.provider_mark == 1 && open.register_calls == 1 &&
           legacy.register_calls == 1);
    assert(hybrid580_uvm_gpu_registry_lookup(&registry, uuid, &owner,
                                              &references) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(owner == HYBRID580_UVM_PROVIDER_OPEN && references == 1);

    /* Existing UUIDs are routed only to their recorded provider. */
    legacy.register_status = STATUS_PROVIDER_ERROR;
    assert(register_gpu(&registry, uuid, &output, &open, &legacy) == 0);
    assert(open.register_calls == 2 && legacy.register_calls == 1);
    assert(hybrid580_uvm_gpu_registry_lookup(&registry, uuid, &owner,
                                              &references) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(references == 2);
    {
        size_t slot = hybrid580_uvm_gpu_registry_find(&registry, uuid);
        unsigned open_calls = open.register_calls;
        unsigned legacy_calls = legacy.register_calls;
        assert(slot != SIZE_MAX);
        registry.entries[slot].references = HYBRID580_UVM_GPU_REFCOUNT_MAX;
        assert(register_gpu(&registry, uuid, &output, &open, &legacy) == STATUS_NO_MEMORY);
        assert(open.register_calls == open_calls && legacy.register_calls == legacy_calls);
        registry.entries[slot].references = references;
    }
    assert(unregister_gpu(&registry, uuid, &open, &legacy) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(open.unregister_calls == 1 && legacy.unregister_calls == 0);
    assert(unregister_gpu(&registry, uuid, &open, &legacy) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(open.unregister_calls == 2 && registry.count == 0);

    /* Two positive matches are rejected and both backend references undone. */
    open.register_status = 0;
    legacy.register_status = 0;
    assert(register_gpu(&registry, uuid, &output, &open, &legacy) == STATUS_GENERIC);
    assert(open.unregister_calls == 3 && legacy.unregister_calls == 1);
    assert(registry.count == 0);

    /* An error on the non-owning provider rolls back the positive provider. */
    legacy.register_status = STATUS_PROVIDER_ERROR;
    assert(register_gpu(&registry, uuid, &output, &open, &legacy) == STATUS_PROVIDER_ERROR);
    assert(open.unregister_calls == 4 && registry.count == 0);

    /* Both providers missing returns the documented absence status. */
    open.register_status = STATUS_UUID_NOT_FOUND;
    legacy.register_status = STATUS_UUID_NOT_FOUND;
    assert(register_gpu(&registry, uuid, &output, &open, &legacy) == STATUS_UUID_NOT_FOUND);
    assert(registry.count == 0);
    assert(unregister_gpu(&registry, uuid, &open, &legacy) ==
           HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND);
    assert(open.unregister_calls == 4 && legacy.unregister_calls == 1);

    puts("UVM GPU route/provider-probe/rollback/refcount scenarios passed");
    return 0;
}
