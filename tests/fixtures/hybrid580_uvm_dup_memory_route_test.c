/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_dup_memory_route.h"

#define STATUS_NO_MEMORY UINT32_C(0xe0012201)
#define STATUS_GENERIC UINT32_C(0xe0012202)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0012203)
#define STATUS_NOT_SUPPORTED UINT32_C(0xe0012204)

struct fake_memory_info {
    uint64_t size;
    uint32_t provider_marker;
};

struct fake_backend {
    uintptr_t expected_device;
    uintptr_t duplicate_handle;
    uint32_t duplicate_status;
    uint32_t free_status;
    unsigned duplicate_calls;
    unsigned free_calls;
    uintptr_t last_freed;
};

static uint32_t fake_duplicate(void *context, uintptr_t device,
                               uint32_t client, uint32_t physical_handle,
                               uintptr_t *duplicate_handle, void *memory_info)
{
    struct fake_backend *backend = context;
    struct fake_memory_info *info = memory_info;

    assert(device == backend->expected_device);
    assert(client == UINT32_C(0x11));
    assert(physical_handle == UINT32_C(0x22));
    assert(duplicate_handle != NULL);
    ++backend->duplicate_calls;
    *duplicate_handle = backend->duplicate_handle;
    if (info != NULL && backend->duplicate_status == 0) {
        info->size = UINT64_C(0x100000);
        info->provider_marker = (uint32_t)device;
    }
    return backend->duplicate_status;
}

static uint32_t fake_free(void *context, uintptr_t device,
                          uintptr_t duplicate_handle)
{
    struct fake_backend *backend = context;
    assert(device == backend->expected_device);
    backend->last_freed = duplicate_handle;
    ++backend->free_calls;
    return backend->free_status;
}

static struct hybrid580_uvm_dup_memory_backend_ops make_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_dup_memory_backend_ops) {
        .context = backend,
        .provider = provider,
        .duplicate = fake_duplicate,
        .release = fake_free,
    };
}

int main(void)
{
    struct hybrid580_uvm_device_registry devices = {0};
    struct hybrid580_uvm_typed_child_registry children = {0};
    struct hybrid580_uvm_typed_child_entry open_memory = {0};
    struct hybrid580_uvm_typed_child_entry legacy_memory = {0};
    struct hybrid580_uvm_typed_child_entry partial_memory = {0};
    struct hybrid580_uvm_typed_child_entry collision_memory = {0};
    struct fake_backend open = {
        .expected_device = 0x1000,
        .duplicate_handle = 0x111,
    };
    struct fake_backend legacy = {
        .expected_device = 0x2000,
        .duplicate_handle = 0x222,
    };
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x10};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x20};
    struct fake_memory_info open_info = {0};
    struct fake_memory_info legacy_info = {0};
    struct fake_memory_info partial_info = {0};
    struct fake_memory_info collision_info = {0};
    struct hybrid580_uvm_dup_memory_backend_ops open_ops =
        make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_dup_memory_backend_ops legacy_ops =
        make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    struct hybrid580_uvm_typed_child_entry *removed = NULL;
    uintptr_t public_handle = UINTPTR_MAX;
    uintptr_t parent = 0;
    enum hybrid580_uvm_provider provider = 0;
    uint32_t backend_status = STATUS_GENERIC;
    int quarantine = 0;

    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x1000, HYBRID580_UVM_PROVIDER_OPEN, open_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x2000, HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);

    assert(hybrid580_uvm_dup_memory_route_duplicate(
               &devices, &children, &open_memory, 0x1000,
               HYBRID580_UVM_PROVIDER_OPEN, 0x11, 0x22,
               &open_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED,
               &public_handle, &quarantine) == 0);
    assert(public_handle == 0x111 && open_info.size == 0x100000 &&
           open_info.provider_marker == 0x1000);
    assert(open.duplicate_calls == 1 && legacy.duplicate_calls == 0 &&
           !quarantine);
    assert(hybrid580_uvm_typed_child_registry_lookup(
               &children, public_handle, HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
               &provider, NULL, &parent, NULL) == HYBRID580_UVM_TYPED_CHILD_OK);
    assert(provider == HYBRID580_UVM_PROVIDER_OPEN && parent == 0x1000);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &children, 0x1000, HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE));

    public_handle = 0;
    assert(hybrid580_uvm_dup_memory_route_duplicate(
               &devices, &children, &legacy_memory, 0x2000,
               HYBRID580_UVM_PROVIDER_LEGACY, 0x11, 0x22,
               &legacy_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED,
               &public_handle, &quarantine) == 0);
    assert(public_handle == 0x222 && legacy_info.provider_marker == 0x2000);
    assert(open.duplicate_calls == 1 && legacy.duplicate_calls == 1);

    /* An unknown target is rejected before dispatch, so it has no ambiguous
     * output and must not quarantine a valid source allocation. */
    public_handle = UINTPTR_MAX;
    quarantine = 1;
    assert(hybrid580_uvm_dup_memory_route_duplicate(
               &devices, &children, &partial_memory, 0x3000,
               HYBRID580_UVM_PROVIDER_OPEN, 0x11, 0x22,
               &partial_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED,
               &public_handle, &quarantine) == STATUS_GENERIC);
    assert(public_handle == 0 && !quarantine && open.duplicate_calls == 1 &&
           legacy.duplicate_calls == 1);

    /* A target-provider handle collision must not be tried for a source
     * allocation owned by the other RM. */
    public_handle = UINTPTR_MAX;
    quarantine = 0;
    assert(hybrid580_uvm_dup_memory_route_duplicate(
               &devices, &children, &partial_memory, 0x1000,
               HYBRID580_UVM_PROVIDER_LEGACY, 0x11, 0x22,
               &partial_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED,
               &public_handle, &quarantine) == STATUS_NOT_SUPPORTED);
    assert(public_handle == 0 && !quarantine && open.duplicate_calls == 1 &&
           legacy.duplicate_calls == 1);

    /* Provider failure with a non-null output is ambiguous and unpublished. */
    open.duplicate_status = STATUS_PROVIDER_ERROR;
    open.duplicate_handle = 0x333;
    public_handle = UINTPTR_MAX;
    assert(hybrid580_uvm_dup_memory_route_duplicate(
               &devices, &children, &partial_memory, 0x1000,
               HYBRID580_UVM_PROVIDER_OPEN, 0x11, 0x22,
               &partial_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED,
               &public_handle, &quarantine) ==
           STATUS_PROVIDER_ERROR);
    assert(public_handle == 0 && quarantine && open.free_calls == 0);
    open.duplicate_status = 0;

    /* A live handle collision is quarantined without releasing either owner. */
    open.duplicate_handle = 0x111;
    quarantine = 0;
    public_handle = UINTPTR_MAX;
    assert(hybrid580_uvm_dup_memory_route_duplicate(
               &devices, &children, &collision_memory, 0x1000,
               HYBRID580_UVM_PROVIDER_OPEN, 0x11, 0x22,
               &collision_info, open_ops, legacy_ops, STATUS_NO_MEMORY,
               STATUS_GENERIC, STATUS_NOT_SUPPORTED,
               &public_handle, &quarantine) == STATUS_GENERIC);
    assert(public_handle == 0 && quarantine && open.free_calls == 0);

    /* Wrong-device release is rejected. RM failure keeps the owner record so
     * the caller can retry; only a successful release removes the dependency. */
    assert(hybrid580_uvm_dup_memory_route_release(
               &devices, &children, 0x2000, 0x111, open_ops, legacy_ops,
               &backend_status, &removed) == HYBRID580_UVM_TYPED_CHILD_BAD_PARENT);
    assert(open.free_calls == 0 && legacy.free_calls == 0);
    open.free_status = STATUS_PROVIDER_ERROR;
    assert(hybrid580_uvm_dup_memory_route_release(
               &devices, &children, 0x1000, 0x111, open_ops, legacy_ops,
               &backend_status, &removed) == HYBRID580_UVM_TYPED_CHILD_OK);
    assert(backend_status == STATUS_PROVIDER_ERROR && removed == NULL);
    assert(open.free_calls == 1 && open.last_freed == 0x111);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &children, 0x1000, HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE));
    open.free_status = 0;
    assert(hybrid580_uvm_dup_memory_route_release(
               &devices, &children, 0x1000, 0x111, open_ops, legacy_ops,
               &backend_status, &removed) == HYBRID580_UVM_TYPED_CHILD_OK);
    assert(backend_status == 0 && removed == &open_memory);
    assert(open.free_calls == 2 && open.last_freed == 0x111);
    assert(!hybrid580_uvm_typed_child_registry_has_parent(
               &children, 0x1000, HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE));
    assert(hybrid580_uvm_dup_memory_route_release(
               &devices, &children, 0x2000, 0x222, open_ops, legacy_ops,
               &backend_status, &removed) == HYBRID580_UVM_TYPED_CHILD_OK);
    assert(backend_status == 0 && removed == &legacy_memory &&
           legacy.free_calls == 1 && legacy.last_freed == 0x222);
    assert(hybrid580_uvm_typed_child_registry_count(&children) == 0);

    puts("UVM duplicate-memory provider, device parent, and retry scenarios passed");
    return 0;
}
