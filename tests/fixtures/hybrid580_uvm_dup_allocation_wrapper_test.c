/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef unsigned long long NvU64;
typedef void *uvmGpuAddressSpaceHandle;

#define NV_OK                          UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT       UINT32_C(0xe0013301)
#define NV_ERR_NOT_SUPPORTED          UINT32_C(0xe0013302)
#define NV_ERR_GENERIC                UINT32_C(0xe0013303)
#define TEST_PROVIDER_ERROR           UINT32_C(0xe0013304)
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_address_space_route.h"

struct fake_backend {
    uintptr_t expected_src;
    uintptr_t expected_dst;
    NvU64 expected_src_address;
    NvU64 expected_alignment;
    NvU64 result_address;
    NV_STATUS status;
    unsigned calls;
};

static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_src;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_dst;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_src;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_dst;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
static int hybrid580_uvm_callback_lock;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_quarantine_pins;

static void hybrid580_test_mutex_lock(int *lock)
{
    assert(lock == &hybrid580_uvm_callback_lock);
    assert(hybrid580_test_lock_depth == 0);
    ++hybrid580_test_lock_depth;
    ++hybrid580_test_lock_calls;
}

static void hybrid580_test_mutex_unlock(int *lock)
{
    assert(lock == &hybrid580_uvm_callback_lock);
    assert(hybrid580_test_lock_depth == 1);
    --hybrid580_test_lock_depth;
    ++hybrid580_test_unlock_calls;
}

#define mutex_lock(lock) hybrid580_test_mutex_lock(lock)
#define mutex_unlock(lock) hybrid580_test_mutex_unlock(lock)

static NV_STATUS hybrid580_test_rm_duplicate(
    struct fake_backend *backend, uvmGpuAddressSpaceHandle src_space,
    NvU64 src_address, uvmGpuAddressSpaceHandle dst_space,
    NvU64 alignment, NvU64 *dst_address)
{
    assert(dst_address != NULL);
    assert((uintptr_t)src_space == backend->expected_src);
    assert((uintptr_t)dst_space == backend->expected_dst);
    assert(src_address == backend->expected_src_address);
    assert(alignment == backend->expected_alignment);
    ++backend->calls;
    *dst_address = backend->result_address;
    return backend->status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceDupAllocation(
    uvmGpuAddressSpaceHandle src_space, NvU64 src_address,
    uvmGpuAddressSpaceHandle dst_space, NvU64 alignment,
    NvU64 *dst_address)
{
    return hybrid580_test_rm_duplicate(&hybrid580_test_open, src_space,
        src_address, dst_space, alignment, dst_address);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceDupAllocation(
    uvmGpuAddressSpaceHandle src_space, NvU64 src_address,
    uvmGpuAddressSpaceHandle dst_space, NvU64 alignment,
    NvU64 *dst_address)
{
    return hybrid580_test_rm_duplicate(&hybrid580_test_legacy, src_space,
        src_address, dst_space, alignment, dst_address);
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_DUP_ALLOCATION_BACKEND_ADAPTERS */
/* INSERT_EXACT_DUP_ALLOCATION_PROVIDER_OPS */
/* INSERT_EXACT_DUP_ALLOCATION_PUBLIC_WRAPPER */

static void hybrid580_test_reset(void)
{
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    memset(&hybrid580_test_open_src, 0, sizeof(hybrid580_test_open_src));
    memset(&hybrid580_test_open_dst, 0, sizeof(hybrid580_test_open_dst));
    memset(&hybrid580_test_legacy_src, 0,
           sizeof(hybrid580_test_legacy_src));
    memset(&hybrid580_test_legacy_dst, 0,
           sizeof(hybrid580_test_legacy_dst));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_open.expected_src = 0x1000;
    hybrid580_test_open.expected_dst = 0x1001;
    hybrid580_test_legacy.expected_src = 0x2000;
    hybrid580_test_legacy.expected_dst = 0x2001;
    hybrid580_test_open.expected_src_address = UINT64_C(0xabcdef0000);
    hybrid580_test_legacy.expected_src_address = UINT64_C(0xabcdef0000);
    hybrid580_test_open.expected_alignment = UINT64_C(0x200000);
    hybrid580_test_legacy.expected_alignment = UINT64_C(0x200000);
    hybrid580_test_open.result_address = UINT64_C(0x7000000000);
    hybrid580_test_legacy.result_address = UINT64_C(0x7100000000);

    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_src,
               0x1000, 0x0100, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_dst,
               0x1001, 0x0101, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_src,
               0x2000, 0x0200,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_dst,
               0x2001, 0x0201,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
}

static NV_STATUS hybrid580_test_duplicate(uintptr_t src, uintptr_t dst,
                                           NvU64 *dst_address)
{
    return nvUvmInterfaceDupAllocation((uvmGpuAddressSpaceHandle)src,
        UINT64_C(0xabcdef0000), (uvmGpuAddressSpaceHandle)dst,
        UINT64_C(0x200000), dst_address);
}

static void hybrid580_test_provider_selection_and_cross_provider_refusal(void)
{
    NvU64 address = UINT64_MAX;

    hybrid580_test_reset();
    assert(hybrid580_test_duplicate(0x1000, 0x1001, &address) == NV_OK);
    assert(address == UINT64_C(0x7000000000));
    assert(hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 0);

    address = UINT64_MAX;
    assert(hybrid580_test_duplicate(0x2000, 0x2001, &address) == NV_OK);
    assert(address == UINT64_C(0x7100000000));
    assert(hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 1);

    address = UINT64_MAX;
    assert(hybrid580_test_duplicate(0x1000, 0x2000, &address) ==
           NV_ERR_NOT_SUPPORTED);
    assert(address == 0 && hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 1 &&
           hybrid580_test_quarantine_pins == 0);

    address = UINT64_MAX;
    assert(hybrid580_test_duplicate(0x1000, 0x1000, &address) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(address == 0 && hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 1);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_errors_clear_outputs_and_quarantine(void)
{
    NvU64 address = UINT64_MAX;

    hybrid580_test_reset();
    hybrid580_test_open.status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.result_address = UINT64_C(0xdead0000);
    assert(hybrid580_test_duplicate(0x1000, 0x1001, &address) ==
           TEST_PROVIDER_ERROR);
    assert(address == 0 && hybrid580_test_open.calls == 1 &&
           hybrid580_test_legacy.calls == 0 &&
           hybrid580_test_quarantine_pins == 1);

    hybrid580_test_reset();
    address = UINT64_MAX;
    assert(hybrid580_test_duplicate(0x1000, 0xbeef, &address) ==
           NV_ERR_GENERIC);
    assert(address == 0 && hybrid580_test_open.calls == 0 &&
           hybrid580_test_legacy.calls == 0 &&
           hybrid580_test_quarantine_pins == 1);

    hybrid580_test_reset();
    assert(nvUvmInterfaceDupAllocation(
               (uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0xabcdef0000),
               (uvmGpuAddressSpaceHandle)0x1001,
               UINT64_C(0x200000), NULL) == NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_lock_calls == 0 &&
           hybrid580_test_open.calls == 0 &&
           hybrid580_test_legacy.calls == 0);

    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

int main(void)
{
    hybrid580_test_provider_selection_and_cross_provider_refusal();
    hybrid580_test_errors_clear_outputs_and_quarantine();
    puts("exact UVM DupAllocation wrapper, same-provider dispatch, and failure quarantine passed");
    return 0;
}
