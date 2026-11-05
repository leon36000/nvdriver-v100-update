/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_gpu_route.h"
#include "../../src/hybrid580_uvm_device_route.h"

#define STATUS_UUID_NOT_FOUND UINT32_C(0xe0010001)
#define STATUS_NO_MEMORY      UINT32_C(0xe0010002)
#define STATUS_NOT_SUPPORTED  UINT32_C(0xe0010003)
#define STATUS_GENERIC        UINT32_C(0xe0010004)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0010005)

struct gpu_client_info {
    uintptr_t client;
    uintptr_t smc_partition;
};

struct gpu_info {
    uint32_t gpu_arch;
    uint32_t gpu_implementation;
    uint32_t host_class;
    uint32_t ce_class;
};

struct platform_info {
    enum hybrid580_uvm_provider provider;
    uint32_t marker;
};

struct fb_info {
    uint64_t max_allocatable_address;
    uint32_t provider_marker;
};

/* The open-backend values are routing sentinels, not Blackwell RM values. */
struct fake_provider {
    enum hybrid580_uvm_provider provider;
    unsigned char owned_uuid[HYBRID580_UVM_GPU_UUID_BYTES];
    uint32_t info_status;
    uintptr_t expected_client;
    uintptr_t expected_session;
    uintptr_t native_device;
    struct gpu_info gpu_info;
    uint32_t fb_provider_marker;
    uint64_t fb_max_allocatable_address;
    unsigned register_calls;
    unsigned unregister_calls;
    unsigned info_calls;
    unsigned create_calls;
    unsigned device_calls;
    unsigned destroy_calls;
};

struct fake_backends {
    struct hybrid580_uvm_gpu_backend_ops open_gpu;
    struct hybrid580_uvm_gpu_backend_ops legacy_gpu;
    struct hybrid580_uvm_gpu_info_backend_ops open_info;
    struct hybrid580_uvm_gpu_info_backend_ops legacy_info;
    struct hybrid580_uvm_device_backend_ops open_device;
    struct hybrid580_uvm_device_backend_ops legacy_device;
    struct hybrid580_uvm_device_call_backend_ops open_call;
    struct hybrid580_uvm_device_call_backend_ops legacy_call;
};

struct attached_gpu {
    struct gpu_info info;
    struct platform_info platform;
    struct platform_info open_platform;
    struct platform_info legacy_platform;
    uintptr_t public_device;
};

static uint32_t fake_register_gpu(
    void *context, const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    void *platform, size_t platform_size)
{
    struct fake_provider *provider = context;
    struct platform_info *info = platform;

    assert(uuid != NULL && info != NULL && platform_size == sizeof(*info));
    ++provider->register_calls;
    if (memcmp(uuid, provider->owned_uuid, HYBRID580_UVM_GPU_UUID_BYTES) != 0)
        return STATUS_UUID_NOT_FOUND;
    info->provider = provider->provider;
    info->marker = 0x58000000U | (uint32_t)provider->provider;
    return 0;
}

static void fake_unregister_gpu(
    void *context, const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES])
{
    struct fake_provider *provider = context;
    assert(uuid != NULL);
    assert(memcmp(uuid, provider->owned_uuid,
                  HYBRID580_UVM_GPU_UUID_BYTES) == 0);
    ++provider->unregister_calls;
}

static uint32_t fake_get_gpu_info(
    void *context, const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    const void *client_info, void *gpu_info)
{
    struct fake_provider *provider = context;
    const struct gpu_client_info *client = client_info;

    assert(uuid != NULL && client != NULL && gpu_info != NULL);
    assert(memcmp(uuid, provider->owned_uuid,
                  HYBRID580_UVM_GPU_UUID_BYTES) == 0);
    assert(client->client == provider->expected_client);
    assert(client->smc_partition == 0);
    ++provider->info_calls;
    if (provider->info_status != 0)
        return provider->info_status;
    memcpy(gpu_info, &provider->gpu_info, sizeof(provider->gpu_info));
    return 0;
}

static uint32_t fake_device_create(
    void *context, uintptr_t session, const void *gpu_info,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    int create_smc_partition, uintptr_t *device)
{
    struct fake_provider *provider = context;

    assert(session == provider->expected_session);
    assert(memcmp(uuid, provider->owned_uuid,
                  HYBRID580_UVM_GPU_UUID_BYTES) == 0);
    assert(gpu_info != NULL && device != NULL && !create_smc_partition);
    assert(memcmp(gpu_info, &provider->gpu_info,
                  sizeof(provider->gpu_info)) == 0);
    ++provider->create_calls;
    *device = provider->native_device;
    return 0;
}

static void fake_device_destroy(void *context, uintptr_t device)
{
    struct fake_provider *provider = context;
    assert(device == provider->native_device);
    ++provider->destroy_calls;
}

static uint32_t fake_get_fb_info(void *context, uintptr_t device, void *params)
{
    struct fake_provider *provider = context;
    struct fb_info *info = params;

    assert(device == provider->native_device && info != NULL);
    ++provider->device_calls;
    info->max_allocatable_address = provider->fb_max_allocatable_address;
    info->provider_marker = provider->fb_provider_marker;
    return 0;
}

static void attach_gpu(
    struct hybrid580_uvm_gpu_registry *gpus,
    struct hybrid580_uvm_device_registry *devices,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    struct gpu_client_info *client,
    enum hybrid580_uvm_provider expected_owner,
    const struct fake_backends *backends,
    struct attached_gpu *attached)
{
    uint32_t status;
    int quarantine = 0;

    assert(hybrid580_uvm_gpu_route_register(
               gpus, uuid, &attached->platform, sizeof(attached->platform),
               &attached->open_platform, &attached->legacy_platform,
               backends->open_gpu, backends->legacy_gpu,
               STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY, STATUS_GENERIC) == 0);
    assert(attached->platform.provider == expected_owner);

    assert(hybrid580_uvm_gpu_route_get_info(
               gpus, uuid, client, &attached->info, sizeof(attached->info),
               backends->open_info,
               backends->legacy_info, STATUS_UUID_NOT_FOUND,
               STATUS_GENERIC) == 0);

    status = hybrid580_uvm_device_route_create(
        gpus, devices, uuid, &attached->info, 0, backends->open_device,
        backends->legacy_device, STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY,
        STATUS_NOT_SUPPORTED, STATUS_GENERIC, &attached->public_device,
        &quarantine);
    assert(status == 0 && !quarantine && attached->public_device != 0);
}

static void verify_fb_info(
    struct hybrid580_uvm_device_registry *devices,
    const struct fake_backends *backends, struct fake_provider *owner,
    uintptr_t public_device)
{
    struct fb_info fb = {0};
    uint32_t backend_status = UINT32_MAX;
    enum hybrid580_uvm_device_registry_status device_status;

    device_status = hybrid580_uvm_device_route_call(
        devices, public_device, &fb, backends->open_call,
        backends->legacy_call, &backend_status);
    assert(device_status == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(backend_status == 0);
    assert(fb.provider_marker == owner->fb_provider_marker);
    assert(fb.max_allocatable_address == owner->fb_max_allocatable_address);
}

int main(void)
{
    struct hybrid580_uvm_gpu_registry gpus = {0};
    struct hybrid580_uvm_device_registry devices = {0};
    const unsigned char v100_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x70, 0x10};
    const unsigned char blackwell_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x12, 0x00};
    struct gpu_client_info v100_client = {.client = 0x5800};
    struct gpu_client_info blackwell_client = {.client = 0x5950};
    struct fake_provider open = {
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .owned_uuid = {0x12, 0x00},
        .expected_client = 0x5950,
        .expected_session = 0x8000,
        .native_device = 0x8100,
        /* Synthetic sentinels deliberately do not claim Blackwell class IDs. */
        .gpu_info = {0x9900, 0x09, 0x9901, 0x9902},
        .fb_provider_marker = 0x5950,
        .fb_max_allocatable_address = UINT64_C(0x2800000000),
    };
    struct fake_provider legacy = {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .owned_uuid = {0x70, 0x10},
        .expected_client = 0x5800,
        .expected_session = 0x5800,
        .native_device = 0x5810,
        /* Source-derived R580 GV100 selectors; not a live RM capture. */
        .gpu_info = {0x140, 0x1, 0xc36f, 0xc3b5},
        .fb_provider_marker = 0x5800,
        .fb_max_allocatable_address = UINT64_C(0x1800000000),
    };
    struct fake_backends backends = {
        .open_gpu = {
            .context = &open,
            .provider = HYBRID580_UVM_PROVIDER_OPEN,
            .register_gpu = fake_register_gpu,
            .unregister_gpu = fake_unregister_gpu,
        },
        .legacy_gpu = {
            .context = &legacy,
            .provider = HYBRID580_UVM_PROVIDER_LEGACY,
            .register_gpu = fake_register_gpu,
            .unregister_gpu = fake_unregister_gpu,
        },
        .open_info = {
            .context = &open,
            .provider = HYBRID580_UVM_PROVIDER_OPEN,
            .get_gpu_info = fake_get_gpu_info,
        },
        .legacy_info = {
            .context = &legacy,
            .provider = HYBRID580_UVM_PROVIDER_LEGACY,
            .get_gpu_info = fake_get_gpu_info,
        },
        .open_device = {
            .context = &open,
            .provider = HYBRID580_UVM_PROVIDER_OPEN,
            .native_session = open.expected_session,
            .create = fake_device_create,
            .destroy = fake_device_destroy,
        },
        .legacy_device = {
            .context = &legacy,
            .provider = HYBRID580_UVM_PROVIDER_LEGACY,
            .native_session = legacy.expected_session,
            .create = fake_device_create,
            .destroy = fake_device_destroy,
        },
        .open_call = {
            .context = &open,
            .provider = HYBRID580_UVM_PROVIDER_OPEN,
            .call = fake_get_fb_info,
        },
        .legacy_call = {
            .context = &legacy,
            .provider = HYBRID580_UVM_PROVIDER_LEGACY,
            .call = fake_get_fb_info,
        },
    };
    struct attached_gpu v100 = {0};
    struct attached_gpu blackwell = {0};
    uint32_t error_status;

    attach_gpu(&gpus, &devices, v100_uuid, &v100_client,
               HYBRID580_UVM_PROVIDER_LEGACY, &backends, &v100);
    attach_gpu(&gpus, &devices, blackwell_uuid, &blackwell_client,
               HYBRID580_UVM_PROVIDER_OPEN, &backends, &blackwell);
    {
        enum hybrid580_uvm_provider owner = 0;
        assert(hybrid580_uvm_gpu_registry_lookup(&gpus, v100_uuid, &owner,
                                                 NULL) ==
               HYBRID580_UVM_GPU_REGISTRY_OK);
        assert(owner == HYBRID580_UVM_PROVIDER_LEGACY);
        assert(hybrid580_uvm_gpu_registry_lookup(&gpus, blackwell_uuid,
                                                 &owner, NULL) ==
               HYBRID580_UVM_GPU_REGISTRY_OK);
        assert(owner == HYBRID580_UVM_PROVIDER_OPEN);
    }
    assert(hybrid580_uvm_device_registry_count(&devices) == 2);

    /* Both opaque device handles remain live and route to their own RM. */
    verify_fb_info(&devices, &backends, &legacy, v100.public_device);
    verify_fb_info(&devices, &backends, &open, blackwell.public_device);
    assert(open.register_calls == 2 && legacy.register_calls == 2);
    assert(open.info_calls == 1 && legacy.info_calls == 1);
    assert(open.create_calls == 1 && legacy.create_calls == 1);
    assert(open.device_calls == 1 && legacy.device_calls == 1);

    /* A selected owner's error is returned; it never retries the other RM. */
    legacy.info_status = STATUS_PROVIDER_ERROR;
    error_status = hybrid580_uvm_gpu_route_get_info(
        &gpus, v100_uuid, &v100_client, &v100.info, sizeof(v100.info),
        backends.open_info,
        backends.legacy_info, STATUS_UUID_NOT_FOUND, STATUS_GENERIC);
    assert(error_status == STATUS_PROVIDER_ERROR);
    assert(open.info_calls == 1 && legacy.info_calls == 2);

    assert(hybrid580_uvm_device_route_destroy(
               &devices, v100.public_device, backends.open_device,
               backends.legacy_device) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_route_destroy(
               &devices, blackwell.public_device, backends.open_device,
               backends.legacy_device) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_route_unregister(
               &gpus, v100_uuid, backends.open_gpu,
               backends.legacy_gpu) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_route_unregister(
               &gpus, blackwell_uuid, backends.open_gpu,
               backends.legacy_gpu) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(open.destroy_calls == 1 && legacy.destroy_calls == 1);
    assert(open.unregister_calls == 1 && legacy.unregister_calls == 1);
    {
        enum hybrid580_uvm_provider owner = 0;
        assert(hybrid580_uvm_gpu_registry_lookup(&gpus, v100_uuid, &owner,
                                                 NULL) ==
               HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND);
        assert(hybrid580_uvm_gpu_registry_lookup(&gpus, blackwell_uuid,
                                                 &owner, NULL) ==
               HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND);
    }
    assert(hybrid580_uvm_device_registry_count(&devices) == 0);

    puts("R580 GV100 + open Blackwell dual-owner UVM handoff passed (synthetic backends)");
    return 0;
}
