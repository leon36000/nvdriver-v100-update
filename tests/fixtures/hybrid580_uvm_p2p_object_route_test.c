/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_p2p_object_route.h"

#define STATUS_NOT_SUPPORTED UINT32_C(0xe0025601)
#define STATUS_GENERIC UINT32_C(0xe0025602)
#define STATUS_NO_MEMORY UINT32_C(0xe0025603)
#define STATUS_BACKEND_ERROR UINT32_C(0xe0025604)

struct fake_backend {
    uintptr_t expected_device1;
    uintptr_t expected_device2;
    uintptr_t expected_session;
    uint32_t next_native_handle;
    uint32_t create_status;
    uint32_t partial_handle;
    unsigned create_calls;
    unsigned destroy_calls;
    uint32_t last_destroyed;
};

static uint32_t fake_create(void *context, uintptr_t device1,
                            uintptr_t device2, uint32_t *native_handle)
{
    struct fake_backend *backend = context;
    assert(device1 == backend->expected_device1);
    assert(device2 == backend->expected_device2);
    assert(native_handle != NULL);
    ++backend->create_calls;
    *native_handle = backend->create_status == 0 ?
                     backend->next_native_handle : backend->partial_handle;
    return backend->create_status;
}

static void fake_destroy(void *context, uintptr_t session,
                         uint32_t native_handle)
{
    struct fake_backend *backend = context;
    assert(session == backend->expected_session);
    ++backend->destroy_calls;
    backend->last_destroyed = native_handle;
}

static struct hybrid580_uvm_p2p_object_backend_ops make_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_p2p_object_backend_ops) {
        .context = backend,
        .provider = provider,
        .native_session = backend->expected_session,
        .create = fake_create,
        .destroy = fake_destroy,
    };
}

int main(void)
{
    struct hybrid580_uvm_device_registry devices = {0};
    struct hybrid580_uvm_p2p_object_registry objects = {0};
    unsigned char uuids[4][HYBRID580_UVM_GPU_UUID_BYTES] = {
        {0x11}, {0x12}, {0x21}, {0x22},
    };
    struct fake_backend open = {
        .expected_device1 = 0x1001,
        .expected_device2 = 0x1002,
        .expected_session = 0x5001,
        .next_native_handle = 0x51,
    };
    struct fake_backend legacy = {
        .expected_device1 = 0x2001,
        .expected_device2 = 0x2002,
        .expected_session = 0x5002,
        .next_native_handle = 0x51,
    };
    struct hybrid580_uvm_p2p_object_backend_ops open_ops =
        make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_p2p_object_backend_ops legacy_ops =
        make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    const uintptr_t session = 0x8001;
    uint32_t open_public = 0;
    uint32_t legacy_public = 0;
    uint32_t backend_error_handle = 0;
    int quarantine = 0;
    size_t i;

    for (i = 0; i < 4; ++i) {
        uintptr_t handle = i < 2 ? 0x1001 + i : 0x2001 + (i - 2);
        enum hybrid580_uvm_provider provider = i < 2 ?
            HYBRID580_UVM_PROVIDER_OPEN : HYBRID580_UVM_PROVIDER_LEGACY;
        assert(hybrid580_uvm_device_registry_record(
                   &devices, handle, provider, uuids[i]) ==
               HYBRID580_UVM_DEVICE_REGISTRY_OK);
    }

    assert(hybrid580_uvm_p2p_object_route_create(
               &devices, &objects, session, 0x1001, 0x1002,
               open_ops, legacy_ops, STATUS_NO_MEMORY, STATUS_GENERIC,
               STATUS_NOT_SUPPORTED, &open_public, &quarantine) == 0);
    assert(open_public >= HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE);
    assert(open_public != open.next_native_handle && !quarantine);
    assert(open.create_calls == 1 && legacy.create_calls == 0);
    assert(objects.count == 1 &&
           hybrid580_uvm_p2p_object_has_parent(&objects, 0x1001) &&
           hybrid580_uvm_p2p_object_has_parent(&objects, 0x1002));

    /* Reused native identity is ambiguous: preserve the prior object and
     * quarantine both device parents for the unpublishable second object. */
    quarantine = 0;
    assert(hybrid580_uvm_p2p_object_route_create(
               &devices, &objects, session, 0x1001, 0x1002,
               open_ops, legacy_ops, STATUS_NO_MEMORY, STATUS_GENERIC,
               STATUS_NOT_SUPPORTED, &backend_error_handle,
               &quarantine) == STATUS_GENERIC);
    assert(backend_error_handle == 0 && quarantine && objects.count == 2 &&
           hybrid580_uvm_p2p_object_has_parent(&objects, 0x1001) &&
           open.create_calls == 2);

    /* RM handles may overlap across providers; UVM receives distinct bridge
     * identities and destruction is translated back to the recorded RM. */
    assert(hybrid580_uvm_p2p_object_route_create(
               &devices, &objects, session, 0x2001, 0x2002,
               open_ops, legacy_ops, STATUS_NO_MEMORY, STATUS_GENERIC,
               STATUS_NOT_SUPPORTED, &legacy_public, &quarantine) == 0);
    assert(legacy_public != open_public && legacy_public >=
           HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE);
    assert(open.create_calls == 2 && legacy.create_calls == 1);
    assert(hybrid580_uvm_p2p_object_has_parent(&objects, 0x2001));

    assert(hybrid580_uvm_p2p_object_route_create(
               &devices, &objects, session, 0x1001, 0x2001,
               open_ops, legacy_ops, STATUS_NO_MEMORY, STATUS_GENERIC,
               STATUS_NOT_SUPPORTED, &backend_error_handle,
               &quarantine) == STATUS_NOT_SUPPORTED);
    assert(backend_error_handle == 0 && open.create_calls == 2 &&
           legacy.create_calls == 1 && !quarantine);

    assert(hybrid580_uvm_p2p_object_route_destroy(
               &objects, session + 1, open_public, open_ops, legacy_ops) ==
           HYBRID580_UVM_P2P_OBJECT_INVALID);
    assert(open.destroy_calls == 0);
    assert(hybrid580_uvm_p2p_object_route_destroy(
               &objects, session, open_public, open_ops, legacy_ops) ==
           HYBRID580_UVM_P2P_OBJECT_OK);
    assert(open.destroy_calls == 1 && open.last_destroyed == 0x51);
    assert(hybrid580_uvm_p2p_object_has_parent(&objects, 0x1001) &&
           objects.count == 2);
    assert(hybrid580_uvm_p2p_object_route_destroy(
               &objects, session, legacy_public, open_ops, legacy_ops) ==
           HYBRID580_UVM_P2P_OBJECT_OK);
    assert(legacy.destroy_calls == 1 && legacy.last_destroyed == 0x51 &&
           objects.count == 1);
    assert(hybrid580_uvm_p2p_object_route_destroy(
               &objects, session, legacy_public, open_ops, legacy_ops) ==
           HYBRID580_UVM_P2P_OBJECT_NOT_FOUND);

    /* A backend error after publishing a handle is ambiguous and pinned. */
    open.create_status = STATUS_BACKEND_ERROR;
    open.partial_handle = 0x77;
    quarantine = 0;
    assert(hybrid580_uvm_p2p_object_route_create(
               &devices, &objects, session, 0x1001, 0x1002,
               open_ops, legacy_ops, STATUS_NO_MEMORY, STATUS_GENERIC,
               STATUS_NOT_SUPPORTED, &backend_error_handle,
               &quarantine) == STATUS_BACKEND_ERROR);
    assert(backend_error_handle == 0 && quarantine && objects.count == 2 &&
           hybrid580_uvm_p2p_object_has_parent(&objects, 0x1001) &&
           hybrid580_uvm_p2p_object_has_parent(&objects, 0x1002));
    puts("UVM P2P-object owner, opaque handle, lifetime and mixed-RM routes passed");
    return 0;
}
