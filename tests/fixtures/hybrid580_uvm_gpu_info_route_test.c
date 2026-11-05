/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_gpu_route.h"

#define STATUS_UUID_NOT_FOUND UINT32_C(0xe0010001)
#define STATUS_GENERIC        UINT32_C(0xe0010003)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0010004)

struct gpu_client_info {
    uint32_t client;
    uint32_t smc_partition;
};

struct gpu_info {
    uint32_t provider;
    uint32_t payload;
};

struct fake_provider {
    uint32_t status;
    uint32_t provider;
    unsigned calls;
};

static uint32_t fake_get_gpu_info(void *context,
                                  const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
                                  const void *client_info, void *gpu_info)
{
    struct fake_provider *provider = context;
    const struct gpu_client_info *client = client_info;
    struct gpu_info *info = gpu_info;

    assert(uuid != NULL && client != NULL && info != NULL);
    ++provider->calls;
    assert(client->client == 0x1234 && client->smc_partition == 0);
    info->provider = provider->provider;
    info->payload = 0xabc00000U | provider->provider;
    /* Model a provider that writes fields and then fails. */
    return provider->status;
}

static struct hybrid580_uvm_gpu_info_backend_ops make_ops(
    struct fake_provider *provider, enum hybrid580_uvm_provider owner)
{
    return (struct hybrid580_uvm_gpu_info_backend_ops) {
        .context = provider,
        .provider = owner,
        .get_gpu_info = fake_get_gpu_info,
    };
}

int main(void)
{
    struct hybrid580_uvm_gpu_registry registry = {0};
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x81};
    unsigned char unknown_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x82};
    struct gpu_client_info client = {.client = 0x1234};
    struct gpu_info output = {0};
    struct fake_provider open = {.provider = HYBRID580_UVM_PROVIDER_OPEN};
    struct fake_provider legacy = {.provider = HYBRID580_UVM_PROVIDER_LEGACY};

    assert(hybrid580_uvm_gpu_registry_record_success(
               &registry, uuid, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, uuid, &client, &output, sizeof(output),
               make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN),
               make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY),
               STATUS_UUID_NOT_FOUND, STATUS_GENERIC) == 0);
    assert(output.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           output.payload == (0xabc00000U | HYBRID580_UVM_PROVIDER_OPEN));
    assert(open.calls == 1 && legacy.calls == 0);

    /* An owner error never falls through to the other RM. */
    open.status = STATUS_PROVIDER_ERROR;
    memset(&output, 0xa5, sizeof(output));
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, uuid, &client, &output, sizeof(output),
               make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN),
               make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY),
               STATUS_UUID_NOT_FOUND, STATUS_GENERIC) == STATUS_PROVIDER_ERROR);
    assert(output.provider == 0 && output.payload == 0);
    assert(open.calls == 2 && legacy.calls == 0);

    /* Unknown UUIDs and invalid backend topology do not call either RM. */
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, unknown_uuid, &client, &output, sizeof(output),
               make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN),
               make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY),
               STATUS_UUID_NOT_FOUND, STATUS_GENERIC) == STATUS_UUID_NOT_FOUND);
    assert(open.calls == 2 && legacy.calls == 0);

    assert(hybrid580_uvm_gpu_registry_record_success(
               &registry, unknown_uuid, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_route_get_info(
               &registry, unknown_uuid, &client, &output, sizeof(output),
               make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN),
               make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY),
               STATUS_UUID_NOT_FOUND, STATUS_GENERIC) == 0);
    assert(legacy.calls == 1 && output.provider == HYBRID580_UVM_PROVIDER_LEGACY);

    puts("UVM GPU info UUID-owner routing/no-fallback scenarios passed");
    return 0;
}
