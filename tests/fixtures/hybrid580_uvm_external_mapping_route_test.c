/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_external_mapping_route.h"

int main(void)
{
    struct hybrid580_uvm_address_space_registry spaces = {0};
    struct hybrid580_uvm_address_space_entry space_open = {0};
    struct hybrid580_uvm_address_space_entry space_legacy = {0};
    struct hybrid580_uvm_typed_child_registry children = {0};
    struct hybrid580_uvm_typed_child_entry memory_open = {0};
    struct hybrid580_uvm_typed_child_entry memory_legacy = {0};
    struct hybrid580_uvm_external_mapping_route route = {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .native_va_space = 0xfeed,
        .native_memory = 0xbeef,
    };

    assert(hybrid580_uvm_address_space_registry_insert(
               &spaces, &space_open, 0x1101, 0x1001,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &spaces, &space_legacy, 0x2201, 0x2001,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);

    /* Native duplicated memory is an NvHandle-sized RM object. Its device
     * parent is distinct from the VA-space parent's device by design. */
    assert(hybrid580_uvm_typed_child_registry_insert(
               &children, &memory_open, 0x3301, 0x1002,
               HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE,
               HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
               HYBRID580_UVM_PROVIDER_OPEN) == HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &children, &memory_legacy, 0x4401, 0x2002,
               HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE,
               HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
               HYBRID580_UVM_PROVIDER_LEGACY) == HYBRID580_UVM_TYPED_CHILD_OK);

    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0x1101, 0x3301, &route) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_OK);
    assert(route.provider == HYBRID580_UVM_PROVIDER_OPEN &&
           route.native_va_space == 0x1101 && route.native_memory == 0x3301);

    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0x2201, 0x4401, &route) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_OK);
    assert(route.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           route.native_va_space == 0x2201 && route.native_memory == 0x4401);

    /* A VA space and duplicated allocation owned by different RMs must not
     * be mixed, and failure must leave all caller-visible route data intact. */
    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0x1101, 0x4401, &route) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_PROVIDER_MISMATCH);
    assert(route.provider == HYBRID580_UVM_PROVIDER_LEGACY &&
           route.native_va_space == 0x2201 && route.native_memory == 0x4401);
    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0xdead, 0x3301, &route) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_SPACE_UNKNOWN);
    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0x1101, 0xdead, &route) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_MEMORY_UNKNOWN);
    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0, 0x3301, &route) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_INVALID);
    assert(hybrid580_uvm_external_mapping_resolve(
               &spaces, &children, 0x1101, 0x3301, NULL) ==
           HYBRID580_UVM_EXTERNAL_MAPPING_INVALID);

    puts("external mapping VA-space and duplicated-memory owner checks passed");
    return 0;
}
