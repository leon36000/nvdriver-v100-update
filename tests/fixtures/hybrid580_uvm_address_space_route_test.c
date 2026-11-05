/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_address_space_route.h"

#define STATUS_NO_MEMORY      UINT32_C(0xe0012001)
#define STATUS_INVALID_ARGUMENT UINT32_C(0xe0012002)
#define STATUS_GENERIC        UINT32_C(0xe0012003)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0012004)

struct fake_backend {
    uintptr_t expected_device;
    uintptr_t created_space;
    uint32_t create_status;
    uint32_t call_status;
    unsigned create_calls;
    unsigned call_calls;
    unsigned destroy_calls;
    uintptr_t last_destroyed;
    uintptr_t last_called;
};

struct fake_address_space_info {
    uint64_t page_size;
    uint32_t provider;
};

static uint32_t fake_create(void *context, uintptr_t device,
                            unsigned long long va_base,
                            unsigned long long va_size, int enable_ats,
                            uintptr_t *space, void *info)
{
    struct fake_backend *backend = context;
    struct fake_address_space_info *out = info;
    assert(device == backend->expected_device);
    assert(va_base == 0x100000ULL && va_size == 0x10000000ULL);
    assert(!enable_ats);
    ++backend->create_calls;
    *space = backend->created_space;
    if (backend->create_status == 0) {
        out->page_size = 0x10000;
        out->provider = (uint32_t)device;
    }
    return backend->create_status;
}

static void fake_destroy(void *context, uintptr_t space)
{
    struct fake_backend *backend = context;
    ++backend->destroy_calls;
    backend->last_destroyed = space;
}

static uint32_t fake_space_call(void *context, uintptr_t space, void *params)
{
    struct fake_backend *backend = context;
    assert(params != NULL);
    ++backend->call_calls;
    backend->last_called = space;
    return backend->call_status;
}

static struct hybrid580_uvm_address_space_backend_ops make_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_address_space_backend_ops) {
        .context = backend,
        .provider = provider,
        .create = fake_create,
        .destroy = fake_destroy,
    };
}

int main(void)
{
    struct hybrid580_uvm_device_registry devices = {0};
    struct hybrid580_uvm_address_space_registry spaces = {0};
    struct hybrid580_uvm_address_space_entry open_slot = {0};
    struct hybrid580_uvm_address_space_entry legacy_slot = {0};
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x10};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x20};
    struct fake_address_space_info output = {0};
    struct fake_backend open = {
        .expected_device = 0x100,
        .created_space = 0x1000,
    };
    struct fake_backend legacy = {
        .expected_device = 0x200,
        .created_space = 0x2000,
    };
    struct hybrid580_uvm_address_space_backend_ops open_ops =
        make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_address_space_backend_ops legacy_ops =
        make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    struct hybrid580_uvm_address_space_call_backend_ops open_call = {
        .context = &open,
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .call = fake_space_call,
    };
    struct hybrid580_uvm_address_space_call_backend_ops legacy_call = {
        .context = &legacy,
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .call = fake_space_call,
    };
    struct hybrid580_uvm_address_space_entry *removed = NULL;
    uintptr_t public_space = 0;
    uint32_t backend_status = 0;
    int quarantine = 0;

    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x100, HYBRID580_UVM_PROVIDER_OPEN, open_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x200, HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);

    public_space = UINTPTR_MAX;
    assert(hybrid580_uvm_address_space_route_create(
               &devices, &spaces, &open_slot, 0x100, 0x100000, 0,
               0, &output, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_INVALID_ARGUMENT, STATUS_GENERIC, &public_space,
               &quarantine) == STATUS_INVALID_ARGUMENT);
    assert(public_space == 0 && open.create_calls == 0 && !quarantine);

    assert(hybrid580_uvm_address_space_route_create(
               &devices, &spaces, &open_slot, 0x100, 0x100000, 0x10000000,
               0, &output, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_INVALID_ARGUMENT, STATUS_GENERIC, &public_space,
               &quarantine) == 0);
    assert(public_space == 0x1000 && output.provider == 0x100);
    assert(open.create_calls == 1 && legacy.create_calls == 0);
    assert(hybrid580_uvm_address_space_registry_count(&spaces) == 1);
    assert(hybrid580_uvm_address_space_registry_has_parent(&spaces, 0x100));

    open.call_status = STATUS_PROVIDER_ERROR;
    assert(hybrid580_uvm_address_space_route_call(
               &spaces, 0x1000, &output, open_call, legacy_call,
               &backend_status) == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(backend_status == STATUS_PROVIDER_ERROR);
    assert(open.call_calls == 1 && open.last_called == 0x1000);
    assert(legacy.call_calls == 0);
    assert(hybrid580_uvm_address_space_route_call(
               &spaces, 0xdead, &output, open_call, legacy_call,
               &backend_status) == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_NOT_FOUND);
    assert(open.call_calls == 1 && legacy.call_calls == 0);
    open.call_status = 0;

    /* A second live handle collision is ambiguous and is never destroyed. */
    {
        uintptr_t collided = 0;
        quarantine = 0;
        assert(hybrid580_uvm_address_space_route_create(
                   &devices, &spaces, &legacy_slot, 0x100, 0x100000,
                   0x10000000, 0, &output, open_ops, legacy_ops,
                   STATUS_NO_MEMORY, STATUS_INVALID_ARGUMENT, STATUS_GENERIC,
                   &collided, &quarantine) == STATUS_GENERIC);
        assert(collided == 0 && quarantine && open.destroy_calls == 0);
        assert(open.create_calls == 2 && legacy.create_calls == 0);
    }

    assert(hybrid580_uvm_address_space_route_create(
               &devices, &spaces, &legacy_slot, 0x200, 0x100000, 0x10000000,
               0, &output, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_INVALID_ARGUMENT, STATUS_GENERIC, &public_space,
               &quarantine) == 0);
    assert(public_space == 0x2000 && output.provider == 0x200);
    assert(legacy.create_calls == 1);
    legacy.call_status = STATUS_PROVIDER_ERROR;
    assert(hybrid580_uvm_address_space_route_call(
               &spaces, 0x2000, &output, open_call, legacy_call,
               &backend_status) == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(backend_status == STATUS_PROVIDER_ERROR);
    assert(legacy.call_calls == 1 && legacy.last_called == 0x2000);
    assert(open.call_calls == 1);

    /* Provider errors are not retried on the other RM. */
    legacy.create_status = STATUS_PROVIDER_ERROR;
    {
        uintptr_t failed = UINTPTR_MAX;
        assert(hybrid580_uvm_address_space_route_create(
                   &devices, &spaces, &legacy_slot, 0x200, 0x100000,
                   0x10000000, 0, &output, open_ops, legacy_ops,
                   STATUS_NO_MEMORY, STATUS_INVALID_ARGUMENT, STATUS_GENERIC,
                   &failed, &quarantine) == STATUS_PROVIDER_ERROR);
        assert(failed == 0 && open.create_calls == 2 && legacy.create_calls == 2);
    }
    legacy.create_status = 0;

    assert(hybrid580_uvm_address_space_route_destroy(
               &spaces, 0x1000, open_ops, legacy_ops, &removed) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(removed == &open_slot);
    assert(open.destroy_calls == 1 && open.last_destroyed == 0x1000);
    assert(!hybrid580_uvm_address_space_registry_has_parent(&spaces, 0x100));
    assert(hybrid580_uvm_address_space_route_destroy(
               &spaces, 0x2000, open_ops, legacy_ops, &removed) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(removed == &legacy_slot);
    assert(legacy.destroy_calls == 1 && legacy.last_destroyed == 0x2000);
    assert(hybrid580_uvm_address_space_registry_count(&spaces) == 0);
    puts("UVM dynamic address-space owner/parent/destroy scenarios passed");
    return 0;
}
