/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_typed_child_route.h"

#define STATUS_OK UINT32_C(0)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0013001)

struct fake_backend {
    uintptr_t expected_native;
    uintptr_t other_native;
    uintptr_t third_native;
    uintptr_t last_called;
    uintptr_t last_destroyed;
    uint32_t status;
    unsigned calls;
    unsigned destroys;
};

static uint32_t fake_call(void *context, uintptr_t native_handle, void *params)
{
    struct fake_backend *backend = context;
    assert(params != NULL);
    assert(native_handle == backend->expected_native ||
           native_handle == backend->other_native ||
           native_handle == backend->third_native);
    backend->last_called = native_handle;
    ++backend->calls;
    return backend->status;
}

static void fake_destroy(void *context, uintptr_t native_handle)
{
    struct fake_backend *backend = context;
    assert(native_handle == backend->expected_native ||
           native_handle == backend->other_native ||
           native_handle == backend->third_native);
    backend->last_destroyed = native_handle;
    ++backend->destroys;
}

static struct hybrid580_uvm_typed_child_call_backend_ops make_call_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_typed_child_call_backend_ops) {
        .context = backend,
        .provider = provider,
        .call = fake_call,
    };
}

static struct hybrid580_uvm_typed_child_destroy_backend_ops make_destroy_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_typed_child_destroy_backend_ops) {
        .context = backend,
        .provider = provider,
        .destroy = fake_destroy,
    };
}

int main(void)
{
    struct hybrid580_uvm_typed_child_registry registry = {0};
    struct hybrid580_uvm_typed_child_entry open_tsg = {0};
    struct hybrid580_uvm_typed_child_entry open_retained = {0};
    struct hybrid580_uvm_typed_child_entry open_retained_alias = {0};
    struct hybrid580_uvm_typed_child_entry retained_overflow = {0};
    struct hybrid580_uvm_typed_child_entry retained_wrong_parent = {0};
    struct hybrid580_uvm_typed_child_entry retained_wrong_provider = {0};
    struct hybrid580_uvm_typed_child_entry open_channel = {0};
    struct hybrid580_uvm_typed_child_entry open_channel_alias = {0};
    struct hybrid580_uvm_typed_child_entry legacy_tsg = {0};
    struct hybrid580_uvm_typed_child_entry legacy_channel = {0};
    struct hybrid580_uvm_typed_child_entry duplicate = {0};
    struct hybrid580_uvm_typed_child_entry wrong_provider_child = {0};
    struct fake_backend open = {
        .expected_native = 0x1100, .other_native = 0x1000,
        .third_native = 0x1400,
    };
    struct fake_backend legacy = {
        .expected_native = 0x2200, .other_native = 0x2000,
    };
    struct hybrid580_uvm_typed_child_entry *removed = NULL;
    struct hybrid580_uvm_typed_child_entry **retained_link = NULL;
    struct hybrid580_uvm_typed_child_call_backend_ops open_call =
        make_call_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_typed_child_call_backend_ops legacy_call =
        make_call_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    struct hybrid580_uvm_typed_child_destroy_backend_ops open_destroy =
        make_destroy_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_typed_child_destroy_backend_ops legacy_destroy =
        make_destroy_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    enum hybrid580_uvm_provider provider_handle = 0;
    uintptr_t native_handle = 0;
    uint32_t backend_status = 0;
    unsigned char params = 0;

    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &open_tsg, 0x1000, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_TSG,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &open_retained, 0x1400, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    /* RetainChannel is refcounted. RM may return the same opaque pointer for
     * repeated retains of one channel, so its bridge identity stays live
     * until the matching final release. */
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &open_retained_alias, 0x1400, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    retained_link = hybrid580_uvm_typed_child_find_link(
        &registry, 0x1400, HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL);
    assert(retained_link != NULL && *retained_link != NULL &&
           (*retained_link)->references == 2);
    (*retained_link)->references = HYBRID580_UVM_TYPED_CHILD_REFCOUNT_MAX;
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &retained_overflow, 0x1400, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_REFCOUNT_OVERFLOW);
    assert((*retained_link)->references ==
           HYBRID580_UVM_TYPED_CHILD_REFCOUNT_MAX);
    (*retained_link)->references = 2;
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &retained_wrong_parent, 0x1400, 0x0200,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_DUPLICATE);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &retained_wrong_provider, 0x1400, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_TYPED_CHILD_DUPLICATE);
    assert((*retained_link)->references == 2);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &registry, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE));
    assert(hybrid580_uvm_typed_child_route_call(
               &registry, 0x1400,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL, &params,
               open_call, legacy_call, &backend_status) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(backend_status == STATUS_OK && open.calls == 1 && legacy.calls == 0);
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x1400,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == NULL && open.destroys == 1);
    assert((*retained_link)->references == 1);
    assert(hybrid580_uvm_typed_child_registry_count(&registry) == 2);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &registry, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE));
    assert(hybrid580_uvm_typed_child_route_call(
               &registry, 0x1400,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL, &params,
               open_call, legacy_call, &backend_status) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x1400,
               HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == &open_retained && open.destroys == 2);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &open_channel, 0x1100, 0x1000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG,
               HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    /* The numeric handle can alias across types. Destroy checks must be
     * qualified by the actual parent kind. */
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &open_channel_alias, 0x1000, 0x1000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG,
               HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &wrong_provider_child, 0x3300, 0x1000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG,
               HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_TYPED_CHILD_BAD_PARENT);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &registry, 0x1000, HYBRID580_UVM_TYPED_CHILD_PARENT_TSG));
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x1000, HYBRID580_UVM_TYPED_CHILD_TSG,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_HAS_CHILDREN);
    assert(open.destroys == 2 && removed == NULL);

    assert(hybrid580_uvm_typed_child_route_call(
               &registry, 0x1100, HYBRID580_UVM_TYPED_CHILD_CHANNEL, &params,
               open_call, legacy_call, &backend_status) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(backend_status == STATUS_OK && open.calls == 3 && legacy.calls == 0);
    assert(open.last_called == 0x1100);

    /* A provider error is preserved without cross-RM fallback. */
    open.status = STATUS_PROVIDER_ERROR;
    assert(hybrid580_uvm_typed_child_route_call(
               &registry, 0x1000, HYBRID580_UVM_TYPED_CHILD_TSG, &params,
               open_call, legacy_call, &backend_status) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(backend_status == STATUS_PROVIDER_ERROR);
    assert(open.calls == 4 && legacy.calls == 0);
    open.status = STATUS_OK;

    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &legacy_tsg, 0x2000, 0x0200,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_TSG,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &legacy_channel, 0x2200, 0x2000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG,
               HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_registry_lookup(
               &registry, 0x2200, HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               &provider_handle, &native_handle, NULL, NULL) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(provider_handle == HYBRID580_UVM_PROVIDER_LEGACY &&
           native_handle == 0x2200);

    assert(hybrid580_uvm_typed_child_registry_insert(
               &registry, &duplicate, 0x1000, 0x0100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_TSG,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_TYPED_CHILD_DUPLICATE);
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x1000, HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == &open_channel_alias && open.last_destroyed == 0x1000);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &registry, 0x1000, HYBRID580_UVM_TYPED_CHILD_PARENT_TSG));
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x1100, HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == &open_channel && open.destroys == 4 &&
           open.last_destroyed == 0x1100);
    assert(!hybrid580_uvm_typed_child_registry_has_parent(
               &registry, 0x1000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG));
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x1000, HYBRID580_UVM_TYPED_CHILD_TSG,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == &open_tsg && open.destroys == 5 &&
           open.last_destroyed == 0x1000);
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x2200, HYBRID580_UVM_TYPED_CHILD_CHANNEL,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == &legacy_channel && legacy.destroys == 1);
    assert(hybrid580_uvm_typed_child_route_destroy(
               &registry, 0x2000, HYBRID580_UVM_TYPED_CHILD_TSG,
               open_destroy, legacy_destroy, &removed) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed == &legacy_tsg && legacy.destroys == 2);
    assert(hybrid580_uvm_typed_child_registry_count(&registry) == 0);
    assert(hybrid580_uvm_typed_child_route_call(
               &registry, 0xdead, HYBRID580_UVM_TYPED_CHILD_TSG, &params,
               open_call, legacy_call, &backend_status) ==
           HYBRID580_UVM_TYPED_CHILD_NOT_FOUND);
    puts("UVM typed TSG/channel provider and parent routing scenarios passed");
    return 0;
}
