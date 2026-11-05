/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_device_route.h"

#define STATUS_BACKEND_ERROR UINT32_C(0xe0014501)

struct pair_params {
    uint32_t marker;
};

struct fake_backend {
    uintptr_t expected_device1;
    uintptr_t expected_device2;
    uint32_t result_status;
    unsigned calls;
};

static uint32_t fake_pair_call(void *context, uintptr_t device1,
                               uintptr_t device2, void *opaque_params)
{
    struct fake_backend *backend = context;
    struct pair_params *params = opaque_params;

    assert(device1 == backend->expected_device1);
    assert(device2 == backend->expected_device2);
    assert(params != NULL && params->marker == 0x13579bdfU);
    ++backend->calls;
    return backend->result_status;
}

int main(void)
{
    struct hybrid580_uvm_device_registry devices = {0};
    unsigned char open_uuid1[HYBRID580_UVM_GPU_UUID_BYTES] = {0x11};
    unsigned char open_uuid2[HYBRID580_UVM_GPU_UUID_BYTES] = {0x12};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x21};
    struct fake_backend open = {
        .expected_device1 = 0x1001,
        .expected_device2 = 0x1002,
    };
    struct fake_backend legacy = {
        .expected_device1 = 0x2001,
        .expected_device2 = 0x2002,
    };
    struct hybrid580_uvm_device_pair_backend_ops open_ops = {
        .context = &open,
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .call = fake_pair_call,
    };
    struct hybrid580_uvm_device_pair_backend_ops legacy_ops = {
        .context = &legacy,
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .call = fake_pair_call,
    };
    struct pair_params params = {.marker = 0x13579bdfU};
    uint32_t backend_status = UINT32_MAX;

    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x1001, HYBRID580_UVM_PROVIDER_OPEN, open_uuid1) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x1002, HYBRID580_UVM_PROVIDER_OPEN, open_uuid2) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x2001, HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x2002, HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);

    assert(hybrid580_uvm_device_route_pair_call(
               &devices, 0x1001, 0x1002, &params, open_ops, legacy_ops,
               &backend_status) == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK);
    assert(backend_status == 0 && open.calls == 1 && legacy.calls == 0);
    assert(hybrid580_uvm_device_route_pair_call(
               &devices, 0x2001, 0x2002, &params, open_ops, legacy_ops,
               &backend_status) == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK);
    assert(backend_status == 0 && open.calls == 1 && legacy.calls == 1);

    /* The Open RM cannot consume the legacy RM's device handle, and vice versa. */
    assert(hybrid580_uvm_device_route_pair_call(
               &devices, 0x1001, 0x2001, &params, open_ops, legacy_ops,
               &backend_status) ==
           HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER);
    assert(open.calls == 1 && legacy.calls == 1);

    assert(hybrid580_uvm_device_route_pair_call(
               &devices, 0x1001, 0xdead, &params, open_ops, legacy_ops,
               &backend_status) == HYBRID580_UVM_DEVICE_PAIR_ROUTE_NOT_FOUND);
    assert(hybrid580_uvm_device_route_pair_call(
               &devices, 0x1001, 0x1001, &params, open_ops, legacy_ops,
               &backend_status) == HYBRID580_UVM_DEVICE_PAIR_ROUTE_INVALID);
    assert(open.calls == 1 && legacy.calls == 1);

    open.result_status = STATUS_BACKEND_ERROR;
    assert(hybrid580_uvm_device_route_pair_call(
               &devices, 0x1001, 0x1002, &params, open_ops, legacy_ops,
               &backend_status) == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK);
    assert(backend_status == STATUS_BACKEND_ERROR && open.calls == 2);
    puts("UVM device-pair provider routing and cross-provider isolation passed");
    return 0;
}
