/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_EXTERNAL_MAPPING_ROUTE_H
#define HYBRID580_UVM_EXTERNAL_MAPPING_ROUTE_H

#include "hybrid580_uvm_address_space_route.h"
#include "hybrid580_uvm_typed_child_route.h"

enum hybrid580_uvm_external_mapping_status {
    HYBRID580_UVM_EXTERNAL_MAPPING_OK = 0,
    HYBRID580_UVM_EXTERNAL_MAPPING_INVALID = -1,
    HYBRID580_UVM_EXTERNAL_MAPPING_SPACE_UNKNOWN = -2,
    HYBRID580_UVM_EXTERNAL_MAPPING_MEMORY_UNKNOWN = -3,
    HYBRID580_UVM_EXTERNAL_MAPPING_PROVIDER_MISMATCH = -4,
    HYBRID580_UVM_EXTERNAL_MAPPING_HANDLE_RANGE = -5,
};

struct hybrid580_uvm_external_mapping_route {
    enum hybrid580_uvm_provider provider;
    uintptr_t native_va_space;
    uint32_t native_memory;
};

/* Resolve the two independent native identities only when their owner RMs
 * agree. Their device parents are intentionally not required to match: R580
 * UVM can query an allocation while mapping it in another GPU's VA space.
 * Callers serialize registry access and backend execution with the bridge's
 * lifetime lock so neither object can be retired during this lookup/use.
 */
static inline enum hybrid580_uvm_external_mapping_status
hybrid580_uvm_external_mapping_resolve(
    const struct hybrid580_uvm_address_space_registry *address_spaces,
    const struct hybrid580_uvm_typed_child_registry *typed_children,
    uintptr_t public_va_space, uintptr_t public_memory,
    struct hybrid580_uvm_external_mapping_route *route)
{
    enum hybrid580_uvm_provider space_provider = 0;
    enum hybrid580_uvm_provider memory_provider = 0;
    uintptr_t native_va_space = 0;
    uintptr_t native_memory = 0;
    enum hybrid580_uvm_address_space_registry_status space_status;
    enum hybrid580_uvm_typed_child_status memory_status;

    if (address_spaces == NULL || typed_children == NULL || route == NULL ||
        public_va_space == 0 || public_memory == 0)
        return HYBRID580_UVM_EXTERNAL_MAPPING_INVALID;

    space_status = hybrid580_uvm_address_space_registry_lookup(
        address_spaces, public_va_space, &space_provider, &native_va_space,
        NULL);
    if (space_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK)
        return HYBRID580_UVM_EXTERNAL_MAPPING_SPACE_UNKNOWN;

    memory_status = hybrid580_uvm_typed_child_registry_lookup(
        typed_children, public_memory, HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
        &memory_provider, &native_memory, NULL, NULL);
    if (memory_status != HYBRID580_UVM_TYPED_CHILD_OK)
        return HYBRID580_UVM_EXTERNAL_MAPPING_MEMORY_UNKNOWN;

    if (space_provider != memory_provider)
        return HYBRID580_UVM_EXTERNAL_MAPPING_PROVIDER_MISMATCH;
    if (native_memory == 0 || native_memory > (uintptr_t)~(uint32_t)0)
        return HYBRID580_UVM_EXTERNAL_MAPPING_HANDLE_RANGE;

    route->provider = space_provider;
    route->native_va_space = native_va_space;
    route->native_memory = (uint32_t)native_memory;
    return HYBRID580_UVM_EXTERNAL_MAPPING_OK;
}

#endif
