/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/hybrid580_uvm_pma_route.h"

static const unsigned char uuid_open[HYBRID580_UVM_GPU_UUID_BYTES] = {0x11};
static const unsigned char uuid_legacy[HYBRID580_UVM_GPU_UUID_BYTES] = {0x22};
static const unsigned char uuid_open2[HYBRID580_UVM_GPU_UUID_BYTES] = {0x33};

int main(void)
{
    struct hybrid580_uvm_device_registry devices = {0};
    struct hybrid580_uvm_pma_registry registry = {0};
    struct hybrid580_uvm_pma_pin outer = {0};
    struct hybrid580_uvm_pma_pin nested = {0};
    enum hybrid580_uvm_provider provider = 0;
    uintptr_t device = 0;
    int quarantine = 0;

    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x1001, HYBRID580_UVM_PROVIDER_OPEN, uuid_open) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x2001, HYBRID580_UVM_PROVIDER_LEGACY, uuid_legacy) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &devices, 0x3001, HYBRID580_UVM_PROVIDER_OPEN, uuid_open2) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);

    /* The exact native PMA pointer is an opaque key. It is never dereferenced
     * by the bridge, but it must resolve to precisely one provider and device. */
    assert(hybrid580_uvm_pma_registry_record(
               &devices, &registry, 0x1001, 0xa100, 0xb100, &quarantine) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_record(
               &devices, &registry, 0x1001, 0xa100, 0xb100, &quarantine) ==
           HYBRID580_UVM_PMA_OK);
    assert(!quarantine && registry.count == 1);
    assert(hybrid580_uvm_pma_registry_pin(&registry, 0xa100, &outer) ==
           HYBRID580_UVM_PMA_OK);
    assert(outer.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           outer.device_identity == 0x1001 && outer.native_pma == 0xa100);

    /* PMA eviction can re-enter UVM and free pages on the same PMA while an
     * allocation is in flight. Pinning must be nestable and must not retain
     * the bridge mutex across the backend call. */
    assert(hybrid580_uvm_pma_registry_pin(&registry, 0xa100, &nested) ==
           HYBRID580_UVM_PMA_OK);
    assert(registry.entries[outer.slot].active_calls == 2);
    assert(hybrid580_uvm_pma_registry_device_destroy_check(&registry, 0x1001) ==
           HYBRID580_UVM_PMA_BUSY);
    assert(hybrid580_uvm_pma_registry_unpin(&registry, &nested) ==
           HYBRID580_UVM_PMA_OK);
    assert(registry.entries[outer.slot].active_calls == 1);
    assert(hybrid580_uvm_pma_registry_unpin(&registry, &outer) ==
           HYBRID580_UVM_PMA_OK);
    assert(registry.entries[0].active_calls == 0);

    assert(hybrid580_uvm_pma_registry_pin(&registry, 0xa100, &outer) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_set_callbacks(&registry, &outer, 1) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_unpin(&registry, &outer) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_device_destroy_check(&registry, 0x1001) ==
           HYBRID580_UVM_PMA_BUSY);
    assert(hybrid580_uvm_pma_registry_pin(&registry, 0xa100, &outer) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_set_callbacks(&registry, &outer, 0) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_unpin(&registry, &outer) ==
           HYBRID580_UVM_PMA_OK);
    assert(hybrid580_uvm_pma_registry_device_destroy_check(&registry, 0x1001) ==
           HYBRID580_UVM_PMA_OK);

    /* A clean device teardown retires its PMA mapping so bounded slots can be
     * reused without leaving a stale pointer route behind. */
    assert(hybrid580_uvm_pma_registry_record(
               &devices, &registry, 0x3001, 0xa300, 0xb300, &quarantine) ==
           HYBRID580_UVM_PMA_OK);
    assert(registry.count == 2);
    assert(hybrid580_uvm_pma_registry_release_device(&registry, 0x3001) ==
           HYBRID580_UVM_PMA_OK);
    assert(registry.count == 1 &&
           hybrid580_uvm_pma_registry_pin(&registry, 0xa300, &outer) ==
               HYBRID580_UVM_PMA_NOT_FOUND);

    /* Live native pointer collisions across RMs are not routable. Quarantine
     * both parent devices rather than sending one RM's pointer to the other. */
    assert(hybrid580_uvm_pma_registry_record(
               &devices, &registry, 0x2001, 0xa100, 0xb200, &quarantine) ==
           HYBRID580_UVM_PMA_AMBIGUOUS);
    assert(quarantine && registry.count == 1);
    assert(hybrid580_uvm_pma_registry_pin(&registry, 0xa100, &outer) ==
           HYBRID580_UVM_PMA_AMBIGUOUS);
    assert(hybrid580_uvm_pma_registry_device_destroy_check(&registry, 0x1001) ==
           HYBRID580_UVM_PMA_BUSY);
    /* The failed second GetPmaObject never publishes its pointer, so its
     * failed GPU initialization may destroy that backend device. The first
     * owner stays quarantined because its previously published pointer is no
     * longer unambiguous. */
    assert(hybrid580_uvm_pma_registry_device_destroy_check(&registry, 0x2001) ==
           HYBRID580_UVM_PMA_OK);

    assert(hybrid580_uvm_pma_registry_pin(&registry, 0xdead, &outer) ==
           HYBRID580_UVM_PMA_NOT_FOUND);
    assert(hybrid580_uvm_device_registry_lookup(
               &devices, 0x1001, &provider, &device) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(provider == HYBRID580_UVM_PROVIDER_OPEN && device == 0x1001);
    puts("UVM PMA owner, recursive callback, pointer collision and teardown checks passed");
    return 0;
}
