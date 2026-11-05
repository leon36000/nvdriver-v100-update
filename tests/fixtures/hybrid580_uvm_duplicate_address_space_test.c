/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_address_space_route.h"

#define STATUS_NO_MEMORY UINT32_C(0xe0012101)
#define STATUS_GENERIC UINT32_C(0xe0012102)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0012103)
#define STATUS_NOT_SUPPORTED UINT32_C(0xe0012104)

struct fake_info {
    uint64_t big_page_size;
    uint32_t marker;
};

struct fake_backend {
    uintptr_t expected_device;
    uintptr_t duplicate_handle;
    uint32_t duplicate_status;
    unsigned duplicates;
    unsigned destroys;
    unsigned calls;
    uintptr_t last_destroyed;
    uintptr_t last_called;
};

struct fake_dup_allocation_backend {
    unsigned calls;
};

static uint32_t fake_duplicate(void *context, uintptr_t device,
                               uint32_t user_client, uint32_t user_va_space,
                               uintptr_t *native_space, void *space_info)
{
    struct fake_backend *backend = context;
    struct fake_info *info = space_info;

    assert(device == backend->expected_device);
    assert(user_client == UINT32_C(0x1234));
    assert(user_va_space == UINT32_C(0x5678));
    assert(native_space != NULL && info != NULL);
    ++backend->duplicates;
    *native_space = backend->duplicate_handle;
    if (backend->duplicate_status == 0) {
        info->big_page_size = UINT64_C(0x10000);
        info->marker = (uint32_t)device;
    }
    return backend->duplicate_status;
}

static void fake_destroy(void *context, uintptr_t native_space)
{
    struct fake_backend *backend = context;
    ++backend->destroys;
    backend->last_destroyed = native_space;
}

static uint32_t unused_create(void *context, uintptr_t device,
                              unsigned long long va_base,
                              unsigned long long va_size, int enable_ats,
                              uintptr_t *native_space, void *space_info)
{
    (void)context;
    (void)device;
    (void)va_base;
    (void)va_size;
    (void)enable_ats;
    (void)native_space;
    (void)space_info;
    return STATUS_GENERIC;
}

static uint32_t fake_call(void *context, uintptr_t native_space, void *params)
{
    struct fake_backend *backend = context;
    assert(params != NULL);
    ++backend->calls;
    backend->last_called = native_space;
    return 0;
}

static uint32_t fake_dup_allocation(void *context, uintptr_t native_src_space,
                                    unsigned long long src_address,
                                    uintptr_t native_dst_space,
                                    unsigned long long dst_alignment,
                                    unsigned long long *dst_address)
{
    struct fake_dup_allocation_backend *backend = context;
    (void)native_src_space;
    (void)src_address;
    (void)native_dst_space;
    (void)dst_alignment;
    (void)dst_address;
    ++backend->calls;
    return STATUS_GENERIC;
}

static struct hybrid580_uvm_address_space_duplicate_backend_ops make_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_address_space_duplicate_backend_ops) {
        .context = backend,
        .provider = provider,
        .duplicate = fake_duplicate,
        .destroy = fake_destroy,
    };
}

int main(void)
{
    struct hybrid580_uvm_device_registry devices = {0};
    struct hybrid580_uvm_address_space_registry spaces = {0};
    struct hybrid580_uvm_address_space_entry open_space = {0};
    struct hybrid580_uvm_address_space_entry legacy_space = {0};
    struct hybrid580_uvm_address_space_entry error_space = {0};
    struct hybrid580_uvm_address_space_entry collision_space = {0};
    struct fake_backend open = {
        .expected_device = 0x100,
        .duplicate_handle = 0x1001,
    };
    struct fake_backend legacy = {
        .expected_device = 0x200,
        .duplicate_handle = 0x2001,
    };
    struct fake_dup_allocation_backend open_alloc = {0};
    struct fake_dup_allocation_backend legacy_alloc = {0};
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x10};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x20};
    struct fake_info open_info = {0};
    struct fake_info legacy_info = {0};
    struct fake_info error_info = {0};
    struct fake_info collision_info = {0};
    struct hybrid580_uvm_address_space_duplicate_backend_ops open_ops =
        make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_address_space_duplicate_backend_ops legacy_ops =
        make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    struct hybrid580_uvm_address_space_backend_ops open_destroy_ops = {
        .context = &open,
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .create = unused_create,
        .destroy = fake_destroy,
    };
    struct hybrid580_uvm_address_space_backend_ops legacy_destroy_ops = {
        .context = &legacy,
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .create = unused_create,
        .destroy = fake_destroy,
    };
    struct hybrid580_uvm_address_space_call_backend_ops open_call = {
        .context = &open,
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .call = fake_call,
    };
    struct hybrid580_uvm_address_space_call_backend_ops legacy_call = {
        .context = &legacy,
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .call = fake_call,
    };
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops open_alloc_ops = {
        .context = &open_alloc,
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .duplicate = fake_dup_allocation,
    };
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops legacy_alloc_ops = {
        .context = &legacy_alloc,
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .duplicate = fake_dup_allocation,
    };
    struct hybrid580_uvm_address_space_entry *removed = NULL;
    uintptr_t public_space = UINTPTR_MAX;
    uintptr_t parent_device = 0;
    enum hybrid580_uvm_provider owner = 0;
    uint32_t backend_status = 0;
    unsigned long long destination_address = UINT64_MAX;
    int quarantine = 0;
    unsigned char route_params = 0;

    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x100, HYBRID580_UVM_PROVIDER_OPEN, open_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x200, HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);

    assert(hybrid580_uvm_address_space_route_duplicate(
               &devices, &spaces, &open_space, 0x100, 0x1234, 0x5678,
               &open_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, &public_space, &quarantine) == 0);
    assert(public_space == 0x1001 && open_info.big_page_size == 0x10000 &&
           open_info.marker == 0x100);
    assert(open.duplicates == 1 && legacy.duplicates == 0 && !quarantine);
    assert(hybrid580_uvm_address_space_registry_lookup(
               &spaces, public_space, &owner, NULL, &parent_device) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(owner == HYBRID580_UVM_PROVIDER_OPEN && parent_device == 0x100);
    assert(hybrid580_uvm_address_space_route_call(
               &spaces, public_space, &route_params, open_call, legacy_call,
               &backend_status) == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(open.last_called == 0x1001 && legacy.calls == 0);

    public_space = 0;
    assert(hybrid580_uvm_address_space_route_duplicate(
               &devices, &spaces, &legacy_space, 0x200, 0x1234, 0x5678,
               &legacy_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, &public_space, &quarantine) == 0);
    assert(public_space == 0x2001 && legacy_info.marker == 0x200);
    assert(open.duplicates == 1 && legacy.duplicates == 1 && !quarantine);

    /* Both provider-owned GPU address spaces coexist in one registry, but a
     * cross-provider allocation must fail before either RM is called. */
    destination_address = UINT64_MAX;
    quarantine = 1;
    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x1001, UINT64_C(0xabcdef0000), 0x2001,
               UINT64_C(0x200000), open_alloc_ops, legacy_alloc_ops,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED, STATUS_GENERIC,
               &destination_address, &quarantine) == STATUS_NOT_SUPPORTED);
    assert(destination_address == 0 && !quarantine &&
           open_alloc.calls == 0 && legacy_alloc.calls == 0);

    /* A failed native duplicate with a returned pointer is ambiguous: the
     * identity stays unpublished and is never destroyed speculatively. */
    open.duplicate_status = STATUS_PROVIDER_ERROR;
    open.duplicate_handle = 0x3001;
    public_space = UINTPTR_MAX;
    assert(hybrid580_uvm_address_space_route_duplicate(
               &devices, &spaces, &error_space, 0x100, 0x1234, 0x5678,
               &error_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, &public_space, &quarantine) ==
           STATUS_PROVIDER_ERROR);
    assert(public_space == 0 && quarantine && open.destroys == 0);
    open.duplicate_status = 0;

    /* A second live native identity is quarantined, not destroyed. */
    open.duplicate_handle = 0x1001;
    quarantine = 0;
    public_space = UINTPTR_MAX;
    assert(hybrid580_uvm_address_space_route_duplicate(
               &devices, &spaces, &collision_space, 0x100, 0x1234, 0x5678,
               &collision_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, &public_space, &quarantine) == STATUS_GENERIC);
    assert(public_space == 0 && quarantine && open.destroys == 0);
    assert(hybrid580_uvm_address_space_registry_count(&spaces) == 2);

    assert(hybrid580_uvm_address_space_route_destroy(
               &spaces, 0x1001, open_destroy_ops, legacy_destroy_ops,
               &removed) == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(removed == &open_space && open.destroys == 1 &&
           open.last_destroyed == 0x1001);
    assert(hybrid580_uvm_address_space_route_destroy(
               &spaces, 0x2001, open_destroy_ops, legacy_destroy_ops,
               &removed) == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(removed == &legacy_space && legacy.destroys == 1 &&
           legacy.last_destroyed == 0x2001);
    assert(hybrid580_uvm_address_space_registry_count(&spaces) == 0);
    puts("UVM dual-provider address spaces and fail-closed cross-provider allocation passed");
    return 0;
}
