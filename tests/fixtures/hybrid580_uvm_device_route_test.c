/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_device_route.h"

#define STATUS_UUID_NOT_FOUND UINT32_C(0xe0011001)
#define STATUS_NO_MEMORY      UINT32_C(0xe0011002)
#define STATUS_GENERIC        UINT32_C(0xe0011003)
#define STATUS_NOT_SUPPORTED  UINT32_C(0xe0011004)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0011005)

struct fake_backend {
    uint32_t create_status;
    uintptr_t created_handle;
    uintptr_t expected_session;
    const void *expected_gpu_info;
    unsigned create_calls;
    unsigned destroy_calls;
    unsigned call_calls;
    uintptr_t last_destroyed;
    uintptr_t last_called;
};

struct fake_p2p_caps {
    uint64_t bar1_dma_address[2];
    uint64_t bar1_dma_size[2];
    uint8_t bar1_pcie_atomics[2];
};

struct fake_pair_backend {
    uint32_t status;
    unsigned calls;
    uintptr_t last_device1;
    uintptr_t last_device2;
    struct fake_p2p_caps response;
};

static uint32_t fake_create(void *context, uintptr_t session,
                            const void *gpu_info, const unsigned char *uuid,
                            int create_smc_partition, uintptr_t *device)
{
    struct fake_backend *backend = context;
    assert(session == backend->expected_session);
    assert(gpu_info == backend->expected_gpu_info);
    assert(uuid != NULL && !create_smc_partition);
    ++backend->create_calls;
    *device = backend->created_handle;
    return backend->create_status;
}

static void fake_destroy(void *context, uintptr_t device)
{
    struct fake_backend *backend = context;
    ++backend->destroy_calls;
    backend->last_destroyed = device;
}

static uint32_t fake_device_call(void *context, uintptr_t device, void *params)
{
    struct fake_backend *backend = context;
    assert(params != NULL);
    ++backend->call_calls;
    backend->last_called = device;
    return backend->create_status;
}

static uint32_t fake_pair_call(void *context, uintptr_t device1,
                               uintptr_t device2, void *params)
{
    struct fake_pair_backend *backend = context;

    assert(device1 != 0 && device2 != 0 && device1 != device2);
    assert(params != NULL);
    ++backend->calls;
    backend->last_device1 = device1;
    backend->last_device2 = device2;
    if (backend->status == 0)
        *(struct fake_p2p_caps *)params = backend->response;
    return backend->status;
}

static struct hybrid580_uvm_device_backend_ops make_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_device_backend_ops) {
        .context = backend,
        .provider = provider,
        .native_session = backend->expected_session,
        .create = fake_create,
        .destroy = fake_destroy,
    };
}

static struct hybrid580_uvm_device_pair_backend_ops make_pair_ops(
    struct fake_pair_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_device_pair_backend_ops) {
        .context = backend,
        .provider = provider,
        .call = fake_pair_call,
    };
}

static void own_gpu(struct hybrid580_uvm_gpu_registry *gpus,
                    const unsigned char *uuid,
                    enum hybrid580_uvm_provider provider)
{
    assert(hybrid580_uvm_gpu_registry_record_success(gpus, uuid, provider) ==
           HYBRID580_UVM_GPU_REGISTRY_OK);
}

int main(void)
{
    struct hybrid580_uvm_gpu_registry gpus = {0};
    struct hybrid580_uvm_device_registry devices = {0};
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x18};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x70};
    const uint32_t open_info = 0x1234;
    const uint32_t legacy_info = 0x5678;
    struct fake_backend open = {
        .created_handle = 0x1000,
        .expected_session = 0x2000,
        .expected_gpu_info = &open_info,
    };
    struct fake_backend legacy = {
        .created_handle = 0x3000,
        .expected_session = 0x4000,
        .expected_gpu_info = &legacy_info,
    };
    struct hybrid580_uvm_device_backend_ops open_ops =
        make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_device_backend_ops legacy_ops =
        make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    uintptr_t public_device = 0;
    uint32_t call_params = 0xabc;
    uint32_t backend_status = 0;
    int quarantine = 0;

    own_gpu(&gpus, open_uuid, HYBRID580_UVM_PROVIDER_OPEN);
    own_gpu(&gpus, legacy_uuid, HYBRID580_UVM_PROVIDER_LEGACY);

    assert(hybrid580_uvm_device_route_create(
               &gpus, &devices, open_uuid, &open_info, 0,
               open_ops, legacy_ops, STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &public_device, &quarantine) == 0);
    assert(public_device == open.created_handle && !quarantine);
    assert(open.create_calls == 1 && legacy.create_calls == 0);
    assert(hybrid580_uvm_device_registry_count(&devices) == 1);

    /* Device-scoped APIs dispatch through the handle owner and preserve the
     * owner error without trying the other RM. */
    open.create_status = STATUS_PROVIDER_ERROR;
    {
        struct hybrid580_uvm_device_call_backend_ops open_call = {
            .context = &open,
            .provider = HYBRID580_UVM_PROVIDER_OPEN,
            .call = fake_device_call,
        };
        struct hybrid580_uvm_device_call_backend_ops legacy_call = {
            .context = &legacy,
            .provider = HYBRID580_UVM_PROVIDER_LEGACY,
            .call = fake_device_call,
        };
        assert(hybrid580_uvm_device_route_call(
                   &devices, public_device, &call_params, open_call, legacy_call,
                   &backend_status) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
        assert(backend_status == STATUS_PROVIDER_ERROR);
        assert(open.call_calls == 1 && open.last_called == open.created_handle);
        assert(legacy.call_calls == 0);
        assert(hybrid580_uvm_device_route_call(
                   &devices, 0xdead, &call_params, open_call, legacy_call,
                   &backend_status) == HYBRID580_UVM_DEVICE_REGISTRY_NOT_FOUND);
        assert(open.call_calls == 1 && legacy.call_calls == 0);
    }
    open.create_status = 0;

    /* Destroy uses the recorded device owner, never a UUID guess/fallback. */
    assert(hybrid580_uvm_device_route_destroy(
               &devices, public_device, open_ops, legacy_ops) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(open.destroy_calls == 1 && open.last_destroyed == open.created_handle);
    assert(legacy.destroy_calls == 0 && hybrid580_uvm_device_registry_count(&devices) == 0);

    /* The owner error is returned directly; the other provider is not tried. */
    legacy.create_status = STATUS_PROVIDER_ERROR;
    public_device = UINTPTR_MAX;
    assert(hybrid580_uvm_device_route_create(
               &gpus, &devices, legacy_uuid, &legacy_info, 0,
               open_ops, legacy_ops, STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &public_device, &quarantine) ==
           STATUS_PROVIDER_ERROR);
    assert(public_device == 0 && legacy.create_calls == 1 && open.create_calls == 1);

    /* Partition handles are not silently treated as physical devices. */
    assert(hybrid580_uvm_device_route_create(
               &gpus, &devices, open_uuid, &open_info, 1,
               open_ops, legacy_ops, STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &public_device, &quarantine) ==
           STATUS_NOT_SUPPORTED);
    assert(open.create_calls == 1 && public_device == 0);

    /* A duplicate native pointer is ambiguous: keep the old owner and pin. */
    open.created_handle = 0x1000;
    assert(hybrid580_uvm_device_registry_record(
               &devices, open.created_handle, HYBRID580_UVM_PROVIDER_OPEN,
               open_uuid) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    public_device = UINTPTR_MAX;
    quarantine = 0;
    assert(hybrid580_uvm_device_route_create(
               &gpus, &devices, open_uuid, &open_info, 0,
               open_ops, legacy_ops, STATUS_UUID_NOT_FOUND, STATUS_NO_MEMORY,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &public_device, &quarantine) ==
           STATUS_GENERIC);
    assert(public_device == 0 && quarantine && open.destroy_calls == 1);
    assert(hybrid580_uvm_device_registry_count(&devices) == 1);

    assert(hybrid580_uvm_device_route_destroy(
               &devices, 0xdead, open_ops, legacy_ops) ==
           HYBRID580_UVM_DEVICE_REGISTRY_NOT_FOUND);

    /* Pair calls must stay within one RM handle namespace. On a same-provider
     * success, preserve the caller's normalized handle order and every
     * directional field in the P2P response. Cross-provider pairs are rejected
     * before either backend receives a foreign handle. */
    {
        struct fake_pair_backend open_pair = {
            .response = {
                .bar1_dma_address = {0x100000, 0x900000000ull},
                .bar1_dma_size = {0x4000, 0x200000},
                .bar1_pcie_atomics = {1, 0},
            },
        };
        struct fake_pair_backend legacy_pair = {
            .response = {
                .bar1_dma_address = {0x200000, 0xa00000000ull},
                .bar1_dma_size = {0x8000, 0x400000},
                .bar1_pcie_atomics = {0, 0},
            },
        };
        struct hybrid580_uvm_device_pair_backend_ops open_pair_ops =
            make_pair_ops(&open_pair, HYBRID580_UVM_PROVIDER_OPEN);
        struct hybrid580_uvm_device_pair_backend_ops legacy_pair_ops =
            make_pair_ops(&legacy_pair, HYBRID580_UVM_PROVIDER_LEGACY);
        struct fake_p2p_caps caps = {0};
        enum hybrid580_uvm_device_pair_route_status pair_status;

        assert(hybrid580_uvm_device_registry_record(
                   &devices, 0x1001, HYBRID580_UVM_PROVIDER_OPEN,
                   open_uuid) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
        assert(hybrid580_uvm_device_registry_record(
                   &devices, 0x3000, HYBRID580_UVM_PROVIDER_LEGACY,
                   legacy_uuid) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
        assert(hybrid580_uvm_device_registry_record(
                   &devices, 0x3001, HYBRID580_UVM_PROVIDER_LEGACY,
                   legacy_uuid) == HYBRID580_UVM_DEVICE_REGISTRY_OK);

        pair_status = hybrid580_uvm_device_route_pair_call(
            &devices, 0x1000, 0x1001, &caps, open_pair_ops, legacy_pair_ops,
            &backend_status);
        assert(pair_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK);
        assert(backend_status == 0 && open_pair.calls == 1 &&
               legacy_pair.calls == 0);
        assert(open_pair.last_device1 == 0x1000 &&
               open_pair.last_device2 == 0x1001);
        assert(caps.bar1_dma_address[0] == 0x100000 &&
               caps.bar1_dma_address[1] == 0x900000000ull);
        assert(caps.bar1_dma_size[0] == 0x4000 &&
               caps.bar1_dma_size[1] == 0x200000);
        assert(caps.bar1_pcie_atomics[0] == 1 &&
               caps.bar1_pcie_atomics[1] == 0);

        memset(&caps, 0, sizeof(caps));
        pair_status = hybrid580_uvm_device_route_pair_call(
            &devices, 0x3000, 0x3001, &caps, open_pair_ops, legacy_pair_ops,
            &backend_status);
        assert(pair_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK);
        assert(backend_status == 0 && legacy_pair.calls == 1 &&
               open_pair.calls == 1);
        assert(legacy_pair.last_device1 == 0x3000 &&
               legacy_pair.last_device2 == 0x3001);
        assert(caps.bar1_dma_address[0] == 0x200000 &&
               caps.bar1_dma_address[1] == 0xa00000000ull);
        assert(caps.bar1_dma_size[0] == 0x8000 &&
               caps.bar1_dma_size[1] == 0x400000);
        assert(caps.bar1_pcie_atomics[0] == 0 &&
               caps.bar1_pcie_atomics[1] == 0);

        backend_status = UINT32_MAX;
        pair_status = hybrid580_uvm_device_route_pair_call(
            &devices, 0x1000, 0x3000, &caps, open_pair_ops, legacy_pair_ops,
            &backend_status);
        assert(pair_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER);
        assert(backend_status == 0 && open_pair.calls == 1 &&
               legacy_pair.calls == 1);

        pair_status = hybrid580_uvm_device_route_pair_call(
            &devices, 0x1000, 0xdead, &caps, open_pair_ops, legacy_pair_ops,
            &backend_status);
        assert(pair_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_NOT_FOUND);
        assert(open_pair.calls == 1 && legacy_pair.calls == 1);

        pair_status = hybrid580_uvm_device_route_pair_call(
            &devices, 0x1000, 0x1000, &caps, open_pair_ops, legacy_pair_ops,
            &backend_status);
        assert(pair_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_INVALID);
        assert(open_pair.calls == 1 && legacy_pair.calls == 1);

        open_pair.status = STATUS_PROVIDER_ERROR;
        pair_status = hybrid580_uvm_device_route_pair_call(
            &devices, 0x1000, 0x1001, &caps, open_pair_ops, legacy_pair_ops,
            &backend_status);
        assert(pair_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK);
        assert(backend_status == STATUS_PROVIDER_ERROR &&
               open_pair.calls == 2 && legacy_pair.calls == 1);
    }

    puts("UVM device ownership and same/cross-provider P2P route scenarios passed");
    return 0;
}
