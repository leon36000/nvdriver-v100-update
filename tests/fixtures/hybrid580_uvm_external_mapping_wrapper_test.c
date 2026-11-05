/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvHandle;
typedef unsigned long long NvU64;
typedef void *uvmGpuAddressSpaceHandle;

typedef struct {
    NvU64 marker;
} UvmGpuExternalMappingInfo;

typedef struct {
    NvU64 marker;
} UvmGpuExternalPhysAddrInfo;

#define NV_OK                           UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT        UINT32_C(0xe0013501)
#define NV_ERR_NOT_SUPPORTED           UINT32_C(0xe0013502)
#define NV_ERR_INVALID_OBJECT_HANDLE   UINT32_C(0xe0013503)
#define NV_ERR_INVALID_STATE           UINT32_C(0xe0013504)
#define TEST_PROVIDER_ERROR            UINT32_C(0xe0013505)
#define NV_ERR_GENERIC                 UINT32_C(0xe0013506)
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_external_mapping_route.h"

struct fake_backend {
    uintptr_t expected_va_space;
    uint32_t expected_memory;
    NvU64 expected_offset;
    NvU64 expected_size;
    NvU64 result_marker;
    NV_STATUS status;
    unsigned ptes_calls;
    unsigned phys_calls;
};

static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_space;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_space;
static struct hybrid580_uvm_typed_child_entry hybrid580_test_open_memory;
static struct hybrid580_uvm_typed_child_entry hybrid580_test_legacy_memory;
static int hybrid580_uvm_callback_lock;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;

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

static NV_STATUS hybrid580_test_get_ptes(struct fake_backend *backend,
    uvmGpuAddressSpaceHandle va_space, NvHandle memory, NvU64 offset,
    NvU64 size, UvmGpuExternalMappingInfo *info)
{
    assert(info != NULL);
    assert((uintptr_t)va_space == backend->expected_va_space);
    assert(memory == backend->expected_memory);
    assert(offset == backend->expected_offset && size == backend->expected_size);
    ++backend->ptes_calls;
    info->marker = backend->result_marker;
    return backend->status;
}

static NV_STATUS hybrid580_test_get_phys(struct fake_backend *backend,
    uvmGpuAddressSpaceHandle va_space, NvHandle memory, NvU64 offset,
    NvU64 size, UvmGpuExternalPhysAddrInfo *info)
{
    assert(info != NULL);
    assert((uintptr_t)va_space == backend->expected_va_space);
    assert(memory == backend->expected_memory);
    assert(offset == backend->expected_offset && size == backend->expected_size);
    ++backend->phys_calls;
    info->marker = backend->result_marker;
    return backend->status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceGetExternalAllocPtes(
    uvmGpuAddressSpaceHandle va_space, NvHandle memory, NvU64 offset,
    NvU64 size, UvmGpuExternalMappingInfo *info)
{
    return hybrid580_test_get_ptes(&hybrid580_test_open, va_space, memory,
                                    offset, size, info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceGetExternalAllocPtes(
    uvmGpuAddressSpaceHandle va_space, NvHandle memory, NvU64 offset,
    NvU64 size, UvmGpuExternalMappingInfo *info)
{
    return hybrid580_test_get_ptes(&hybrid580_test_legacy, va_space, memory,
                                    offset, size, info);
}

NV_STATUS hybrid580_open_nvUvmInterfaceGetExternalAllocPhysAddrs(
    uvmGpuAddressSpaceHandle va_space, NvHandle memory, NvU64 offset,
    NvU64 size, UvmGpuExternalPhysAddrInfo *info)
{
    return hybrid580_test_get_phys(&hybrid580_test_open, va_space, memory,
                                    offset, size, info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceGetExternalAllocPhysAddrs(
    uvmGpuAddressSpaceHandle va_space, NvHandle memory, NvU64 offset,
    NvU64 size, UvmGpuExternalPhysAddrInfo *info)
{
    return hybrid580_test_get_phys(&hybrid580_test_legacy, va_space, memory,
                                    offset, size, info);
}

/* INSERT_EXACT_EXTERNAL_MAPPING_STATUS_AND_WRAPPERS */

static void hybrid580_test_reset(void)
{
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_uvm_typed_children, 0,
           sizeof(hybrid580_uvm_typed_children));
    memset(&hybrid580_test_open_space, 0, sizeof(hybrid580_test_open_space));
    memset(&hybrid580_test_legacy_space, 0,
           sizeof(hybrid580_test_legacy_space));
    memset(&hybrid580_test_open_memory, 0, sizeof(hybrid580_test_open_memory));
    memset(&hybrid580_test_legacy_memory, 0,
           sizeof(hybrid580_test_legacy_memory));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_open.expected_va_space = 0x1100;
    hybrid580_test_open.expected_memory = 0x3301;
    hybrid580_test_open.expected_offset = UINT64_C(0x4000);
    hybrid580_test_open.expected_size = UINT64_C(0x8000);
    hybrid580_test_open.result_marker = UINT64_C(0xabc001);
    hybrid580_test_open.status = NV_OK;
    hybrid580_test_legacy.expected_va_space = 0x2200;
    hybrid580_test_legacy.expected_memory = 0x4401;
    hybrid580_test_legacy.expected_offset = UINT64_C(0x4000);
    hybrid580_test_legacy.expected_size = UINT64_C(0x8000);
    hybrid580_test_legacy.result_marker = UINT64_C(0xabc002);
    hybrid580_test_legacy.status = NV_OK;

    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_space,
               0x1100, 0x1000, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_space,
               0x2200, 0x2000, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &hybrid580_uvm_typed_children, &hybrid580_test_open_memory,
               0x3301, 0x1002, HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE,
               HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
               HYBRID580_UVM_PROVIDER_OPEN) == HYBRID580_UVM_TYPED_CHILD_OK);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &hybrid580_uvm_typed_children, &hybrid580_test_legacy_memory,
               0x4401, 0x2002, HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE,
               HYBRID580_UVM_TYPED_CHILD_DUPED_MEMORY,
               HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
}

static void hybrid580_test_provider_routing_uses_both_object_owners(void)
{
    UvmGpuExternalMappingInfo ptes = {0};
    UvmGpuExternalPhysAddrInfo phys = {0};

    hybrid580_test_reset();
    assert(nvUvmInterfaceGetExternalAllocPtes((uvmGpuAddressSpaceHandle)0x1100,
               0x3301, UINT64_C(0x4000), UINT64_C(0x8000), &ptes) == NV_OK);
    assert(ptes.marker == UINT64_C(0xabc001) &&
           hybrid580_test_open.ptes_calls == 1 &&
           hybrid580_test_legacy.ptes_calls == 0);
    assert(nvUvmInterfaceGetExternalAllocPhysAddrs(
               (uvmGpuAddressSpaceHandle)0x2200, 0x4401,
               UINT64_C(0x4000), UINT64_C(0x8000), &phys) == NV_OK);
    assert(phys.marker == UINT64_C(0xabc002) &&
           hybrid580_test_legacy.phys_calls == 1 &&
           hybrid580_test_open.phys_calls == 0);

    assert(nvUvmInterfaceGetExternalAllocPtes((uvmGpuAddressSpaceHandle)0x1100,
               0x4401, UINT64_C(0x4000), UINT64_C(0x8000), &ptes) ==
           NV_ERR_NOT_SUPPORTED);
    assert(hybrid580_test_open.ptes_calls == 1 &&
           hybrid580_test_legacy.ptes_calls == 0);
    assert(nvUvmInterfaceGetExternalAllocPhysAddrs(
               (uvmGpuAddressSpaceHandle)0xdead, 0x3301,
               UINT64_C(0x4000), UINT64_C(0x8000), &phys) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    hybrid580_test_open.status = TEST_PROVIDER_ERROR;
    assert(nvUvmInterfaceGetExternalAllocPtes((uvmGpuAddressSpaceHandle)0x1100,
               0x3301, UINT64_C(0x4000), UINT64_C(0x8000), &ptes) ==
           TEST_PROVIDER_ERROR);
    assert(hybrid580_test_open.ptes_calls == 2);
    assert(nvUvmInterfaceGetExternalAllocPtes(NULL, 0x3301, 0, 1, &ptes) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceGetExternalAllocPhysAddrs(
               (uvmGpuAddressSpaceHandle)0x1100, 0x3301, 0, 1, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

int main(void)
{
    hybrid580_test_provider_routing_uses_both_object_owners();
    puts("exact UVM external mapping wrappers enforce both owner providers");
    return 0;
}
