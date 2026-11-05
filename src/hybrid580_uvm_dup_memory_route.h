/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_DUP_MEMORY_ROUTE_H
#define HYBRID580_UVM_DUP_MEMORY_ROUTE_H

#include "hybrid580_uvm_device_route.h"
#include "hybrid580_uvm_typed_child_route.h"

struct hybrid580_uvm_dup_memory_backend_ops {
    void *context;
    enum hybrid580_uvm_provider provider;
    uint32_t (*duplicate)(void *context, uintptr_t native_device,
                          uint32_t client, uint32_t physical_handle,
                          uintptr_t *duplicate_handle, void *memory_info);
    uint32_t (*release)(void *context, uintptr_t native_device,
                        uintptr_t duplicate_handle);
};

static inline int hybrid580_uvm_dup_memory_backend_ops_valid(
    struct hybrid580_uvm_dup_memory_backend_ops open,
    struct hybrid580_uvm_dup_memory_backend_ops legacy)
{
    return open.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           legacy.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           open.duplicate != NULL && open.release != NULL &&
           legacy.duplicate != NULL && legacy.release != NULL;
}

/* Duplicate only when the source allocation and target device are owned by
 * the same RM provider. Cross-provider raw NvHandle values are namespaced and
 * must never be tried in the target RM without an explicit import operation.
 * The output handle is not visible until its provider/device dependency is
 * recorded. A partial backend result or handle collision is ambiguous and is
 * quarantined rather than freed speculatively. */
static inline uint32_t hybrid580_uvm_dup_memory_route_duplicate(
    const struct hybrid580_uvm_device_registry *devices,
    struct hybrid580_uvm_typed_child_registry *children,
    struct hybrid580_uvm_typed_child_entry *reserved_entry,
    uintptr_t public_device, enum hybrid580_uvm_provider source_provider,
    uint32_t client, uint32_t physical_handle,
    void *memory_info, struct hybrid580_uvm_dup_memory_backend_ops open,
    struct hybrid580_uvm_dup_memory_backend_ops legacy,
    uint32_t no_memory_status, uint32_t generic_status,
    uint32_t not_supported_status,
    uintptr_t *public_handle, int *quarantine)
{
    enum hybrid580_uvm_provider provider = 0;
    struct hybrid580_uvm_dup_memory_backend_ops *selected;
    uintptr_t native_device = 0;
    uintptr_t native_handle = 0;
    uint32_t backend_status;
    enum hybrid580_uvm_device_registry_status device_status;
    enum hybrid580_uvm_typed_child_status child_status;

    if (public_handle == NULL)
        return generic_status;
    *public_handle = 0;
    if (quarantine != NULL)
        *quarantine = 0;
    if (reserved_entry == NULL)
        return no_memory_status;
    if (devices == NULL || children == NULL ||
        public_device == 0 || source_provider == 0 || physical_handle == 0 ||
        reserved_entry->identity != 0 || reserved_entry->native_handle != 0 ||
        reserved_entry->parent_identity != 0 || reserved_entry->parent_kind != 0 ||
        reserved_entry->references != 0 || reserved_entry->next != NULL ||
        !hybrid580_uvm_dup_memory_backend_ops_valid(open, legacy))
        return generic_status;

    device_status = hybrid580_uvm_device_registry_lookup(
        devices, public_device, &provider, &native_device);
    if (device_status != HYBRID580_UVM_DEVICE_REGISTRY_OK)
        /* No provider call has started, so an invalid/unregistered target is
         * a clean rejection and must not retain the source allocation. */
        return generic_status;
    if (provider != source_provider)
        return not_supported_status;

    selected = provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return generic_status;

    backend_status = selected->duplicate(selected->context, native_device,
                                          client, physical_handle,
                                          &native_handle, memory_info);
    if (backend_status != 0) {
        if (native_handle != 0 && quarantine != NULL)
            *quarantine = 1;
        return backend_status;
    }
    if (native_handle == 0) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }

    child_status = hybrid580_uvm_typed_child_registry_insert(
        children, reserved_entry, native_handle, public_device,
        HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE,
        HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY, provider);
    if (child_status != HYBRID580_UVM_TYPED_CHILD_OK) {
        if (quarantine != NULL)
            *quarantine = 1;
        return generic_status;
    }
    *public_handle = native_handle;
    return 0;
}

/* A FreeDupedHandle failure leaves the owner record intact so UVM can retry.
 * Validate the supplied device against both the device table and the recorded
 * parent before invoking the backend; successful RM release is followed by
 * removal while the caller holds the bridge lock. */
static inline enum hybrid580_uvm_typed_child_status
hybrid580_uvm_dup_memory_route_release(
    const struct hybrid580_uvm_device_registry *devices,
    struct hybrid580_uvm_typed_child_registry *children,
    uintptr_t public_device, uintptr_t public_handle,
    struct hybrid580_uvm_dup_memory_backend_ops open,
    struct hybrid580_uvm_dup_memory_backend_ops legacy,
    uint32_t *backend_status,
    struct hybrid580_uvm_typed_child_entry **removed)
{
    enum hybrid580_uvm_provider device_provider = 0;
    enum hybrid580_uvm_provider handle_provider = 0;
    struct hybrid580_uvm_dup_memory_backend_ops *selected;
    uintptr_t native_device = 0;
    uintptr_t native_handle = 0;
    uintptr_t parent_device = 0;
    enum hybrid580_uvm_device_registry_status device_status;
    enum hybrid580_uvm_typed_child_status child_status;

    if (backend_status != NULL)
        *backend_status = 0;
    if (removed != NULL)
        *removed = NULL;
    if (devices == NULL || children == NULL || public_device == 0 ||
        public_handle == 0 || backend_status == NULL ||
        !hybrid580_uvm_dup_memory_backend_ops_valid(open, legacy))
        return HYBRID580_UVM_TYPED_CHILD_INVALID;

    device_status = hybrid580_uvm_device_registry_lookup(
        devices, public_device, &device_provider, &native_device);
    if (device_status != HYBRID580_UVM_DEVICE_REGISTRY_OK)
        return HYBRID580_UVM_TYPED_CHILD_BAD_PARENT;
    child_status = hybrid580_uvm_typed_child_registry_lookup(
        children, public_handle, HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
        &handle_provider, &native_handle, &parent_device, NULL);
    if (child_status != HYBRID580_UVM_TYPED_CHILD_OK)
        return child_status;
    if (parent_device != public_device || handle_provider != device_provider)
        return HYBRID580_UVM_TYPED_CHILD_BAD_PARENT;
    selected = handle_provider == HYBRID580_UVM_PROVIDER_OPEN ? &open :
               handle_provider == HYBRID580_UVM_PROVIDER_LEGACY ? &legacy : NULL;
    if (selected == NULL)
        return HYBRID580_UVM_TYPED_CHILD_INVALID;

    *backend_status = selected->release(selected->context, native_device,
                                         native_handle);
    if (*backend_status != 0)
        return HYBRID580_UVM_TYPED_CHILD_OK;
    return hybrid580_uvm_typed_child_registry_remove(
        children, public_handle, HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
        removed);
}

#endif /* HYBRID580_UVM_DUP_MEMORY_ROUTE_H */
