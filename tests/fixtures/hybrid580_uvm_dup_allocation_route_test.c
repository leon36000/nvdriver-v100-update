/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../../src/hybrid580_uvm_address_space_route.h"

#define STATUS_INVALID_ARGUMENT UINT32_C(0xe0012301)
#define STATUS_NOT_SUPPORTED UINT32_C(0xe0012302)
#define STATUS_GENERIC UINT32_C(0xe0012303)
#define STATUS_PROVIDER_ERROR UINT32_C(0xe0012304)

struct fake_backend {
    uintptr_t expected_src;
    uintptr_t expected_dst;
    unsigned long long expected_src_address;
    unsigned long long expected_alignment;
    unsigned long long output_address;
    uint32_t status;
    unsigned calls;
    uintptr_t last_src;
    uintptr_t last_dst;
};

static uint32_t fake_duplicate(void *context, uintptr_t src_space,
                               unsigned long long src_address,
                               uintptr_t dst_space,
                               unsigned long long alignment,
                               unsigned long long *dst_address)
{
    struct fake_backend *backend = context;
    assert(dst_address != NULL);
    assert(src_space == backend->expected_src);
    assert(dst_space == backend->expected_dst);
    assert(src_address == backend->expected_src_address);
    assert(alignment == backend->expected_alignment);
    ++backend->calls;
    backend->last_src = src_space;
    backend->last_dst = dst_space;
    *dst_address = backend->output_address;
    return backend->status;
}

static struct hybrid580_uvm_address_space_dup_allocation_backend_ops make_ops(
    struct fake_backend *backend, enum hybrid580_uvm_provider provider)
{
    return (struct hybrid580_uvm_address_space_dup_allocation_backend_ops) {
        .context = backend,
        .provider = provider,
        .duplicate = fake_duplicate,
    };
}

int main(void)
{
    struct hybrid580_uvm_address_space_registry spaces = {0};
    struct hybrid580_uvm_address_space_entry open_src = {0};
    struct hybrid580_uvm_address_space_entry open_dst = {0};
    struct hybrid580_uvm_address_space_entry legacy_src = {0};
    struct hybrid580_uvm_address_space_entry legacy_dst = {0};
    struct fake_backend open = {
        .expected_src = 0x1000,
        .expected_dst = 0x1001,
        .expected_src_address = 0xabcdef0000ULL,
        .expected_alignment = 0x200000ULL,
        .output_address = 0x7000000000ULL,
    };
    struct fake_backend legacy = {
        .expected_src = 0x2000,
        .expected_dst = 0x2001,
        .expected_src_address = 0xabcdef0000ULL,
        .expected_alignment = 0x200000ULL,
        .output_address = 0x7100000000ULL,
    };
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops open_ops =
        make_ops(&open, HYBRID580_UVM_PROVIDER_OPEN);
    struct hybrid580_uvm_address_space_dup_allocation_backend_ops legacy_ops =
        make_ops(&legacy, HYBRID580_UVM_PROVIDER_LEGACY);
    unsigned char route_params = 0;
    unsigned long long dst_address = UINT64_MAX;
    int quarantine = 0;

    assert(hybrid580_uvm_address_space_registry_insert(
               &spaces, &open_src, 0x1000, 0x0100,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &spaces, &open_dst, 0x1001, 0x0101,
               HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &spaces, &legacy_src, 0x2000, 0x0200,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &spaces, &legacy_dst, 0x2001, 0x0201,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);

    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x1000, 0xabcdef0000ULL, 0x1001, 0x200000ULL,
               open_ops, legacy_ops, STATUS_INVALID_ARGUMENT,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &dst_address,
               &quarantine) == 0);
    assert(dst_address == 0x7000000000ULL && open.calls == 1 &&
           legacy.calls == 0 && open.last_src == 0x1000 &&
           open.last_dst == 0x1001 && !quarantine);

    dst_address = 0;
    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x2000, 0xabcdef0000ULL, 0x2001, 0x200000ULL,
               open_ops, legacy_ops, STATUS_INVALID_ARGUMENT,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &dst_address,
               &quarantine) == 0);
    assert(dst_address == 0x7100000000ULL && legacy.calls == 1 && !quarantine);

    /* Neither RM can consume the other's address-space handle. */
    dst_address = UINT64_MAX;
    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x1000, 0xabcdef0000ULL, 0x2000, 0x200000ULL,
               open_ops, legacy_ops, STATUS_INVALID_ARGUMENT,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &dst_address,
               &quarantine) == STATUS_NOT_SUPPORTED);
    assert(dst_address == 0 && open.calls == 1 && legacy.calls == 1 &&
           !quarantine);

    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x1000, 0xabcdef0000ULL, 0x1000, 0x200000ULL,
               open_ops, legacy_ops, STATUS_INVALID_ARGUMENT,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &dst_address,
               &quarantine) == STATUS_INVALID_ARGUMENT);
    assert(open.calls == 1 && legacy.calls == 1);

    /* A failed backend with a partial output clears public state and pins. */
    open.status = STATUS_PROVIDER_ERROR;
    open.output_address = 0xdead0000ULL;
    dst_address = UINT64_MAX;
    quarantine = 0;
    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x1000, 0xabcdef0000ULL, 0x1001, 0x200000ULL,
               open_ops, legacy_ops, STATUS_INVALID_ARGUMENT,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &dst_address,
               &quarantine) == STATUS_PROVIDER_ERROR);
    assert(dst_address == 0 && quarantine && open.calls == 2 && legacy.calls == 1);

    dst_address = UINT64_MAX;
    assert(hybrid580_uvm_address_space_route_dup_allocation(
               &spaces, 0x1000, 0xabcdef0000ULL, 0xbeef, 0x200000ULL,
               open_ops, legacy_ops, STATUS_INVALID_ARGUMENT,
               STATUS_NOT_SUPPORTED, STATUS_GENERIC, &dst_address,
               &quarantine) == STATUS_GENERIC);
    assert(dst_address == 0 && quarantine && open.calls == 2 && legacy.calls == 1);
    (void)route_params;
    puts("UVM duplicate-allocation same-provider and cross-provider scenarios passed");
    return 0;
}
