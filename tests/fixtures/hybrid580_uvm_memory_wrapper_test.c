/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint8_t NvBool;
typedef uint32_t NvHandle;
typedef uint32_t NvU32;
typedef unsigned long long NvU64;
typedef unsigned long long NvLength;
typedef unsigned long long UvmGpuPointer;
typedef void *uvmGpuAddressSpaceHandle;

typedef struct {
    NvU64 gpuPhysOffset;
    NvU64 pageSize;
    NvU64 alignment;
    NvBool bContiguousPhysAlloc;
    NvBool bMemGrowsDown;
    NvBool bPersistentVidmem;
    NvHandle hPhysHandle;
    NvBool bUnprotected;
} UvmGpuAllocInfo;

_Static_assert(sizeof(UvmGpuAllocInfo) == 40, "R595 UvmGpuAllocInfo size");
_Static_assert(offsetof(UvmGpuAllocInfo, pageSize) == 8,
               "R595 UvmGpuAllocInfo.pageSize offset");
_Static_assert(offsetof(UvmGpuAllocInfo, hPhysHandle) == 28,
               "R595 UvmGpuAllocInfo.hPhysHandle offset");

#define NV_OK                    UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0013401)
#define NV_ERR_GENERIC          UINT32_C(0xe0013402)
#define TEST_PROVIDER_ERROR     UINT32_C(0xe0013403)
#define NV_ERR_NOT_SUPPORTED    UINT32_C(0xe0013404)
#define NV_ERR_NO_MEMORY        UINT32_C(0xe0013405)
#define NV_FALSE 0U
#define NV_TRUE 1U
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_address_space_route.h"

struct fake_backend {
    uintptr_t expected_space;
    NvLength expected_length;
    NvU64 expected_page_size;
    UvmGpuPointer result_gpu_pointer;
    UvmGpuAllocInfo result_alloc_info;
    void *result_cpu_pointer;
    NV_STATUS alloc_status;
    NV_STATUS map_status;
    int write_gpu_pointer;
    int write_alloc_info;
    int write_cpu_pointer;
    UvmGpuPointer expected_free_pointer;
    void *expected_unmap_pointer;
    unsigned fb_calls;
    unsigned sys_calls;
    unsigned free_calls;
    unsigned map_calls;
    unsigned unmap_calls;
};

static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_space;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_space;
static int hybrid580_uvm_callback_lock;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
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

static NV_STATUS hybrid580_test_alloc(struct fake_backend *backend,
    uvmGpuAddressSpaceHandle va_space, NvLength length,
    UvmGpuPointer *gpu_pointer, UvmGpuAllocInfo *alloc_info,
    unsigned *calls)
{
    assert((uintptr_t)va_space == backend->expected_space);
    assert(length == backend->expected_length);
    ++*calls;
    if (backend->write_gpu_pointer)
        *gpu_pointer = backend->result_gpu_pointer;
    if (backend->write_alloc_info)
        *alloc_info = backend->result_alloc_info;
    return backend->alloc_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceMemoryAllocFB(
    uvmGpuAddressSpaceHandle va_space, NvLength length,
    UvmGpuPointer *gpu_pointer, UvmGpuAllocInfo *alloc_info)
{
    return hybrid580_test_alloc(&hybrid580_test_open, va_space, length,
        gpu_pointer, alloc_info, &hybrid580_test_open.fb_calls);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceMemoryAllocFB(
    uvmGpuAddressSpaceHandle va_space, NvLength length,
    UvmGpuPointer *gpu_pointer, UvmGpuAllocInfo *alloc_info)
{
    return hybrid580_test_alloc(&hybrid580_test_legacy, va_space, length,
        gpu_pointer, alloc_info, &hybrid580_test_legacy.fb_calls);
}

NV_STATUS hybrid580_open_nvUvmInterfaceMemoryAllocSys(
    uvmGpuAddressSpaceHandle va_space, NvLength length,
    UvmGpuPointer *gpu_pointer, UvmGpuAllocInfo *alloc_info)
{
    return hybrid580_test_alloc(&hybrid580_test_open, va_space, length,
        gpu_pointer, alloc_info, &hybrid580_test_open.sys_calls);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceMemoryAllocSys(
    uvmGpuAddressSpaceHandle va_space, NvLength length,
    UvmGpuPointer *gpu_pointer, UvmGpuAllocInfo *alloc_info)
{
    return hybrid580_test_alloc(&hybrid580_test_legacy, va_space, length,
        gpu_pointer, alloc_info, &hybrid580_test_legacy.sys_calls);
}

void hybrid580_open_nvUvmInterfaceMemoryFree(
    uvmGpuAddressSpaceHandle va_space, UvmGpuPointer gpu_pointer)
{
    assert((uintptr_t)va_space == hybrid580_test_open.expected_space);
    assert(gpu_pointer == hybrid580_test_open.expected_free_pointer);
    ++hybrid580_test_open.free_calls;
}

void hybrid580_legacy_nvUvmInterfaceMemoryFree(
    uvmGpuAddressSpaceHandle va_space, UvmGpuPointer gpu_pointer)
{
    assert((uintptr_t)va_space == hybrid580_test_legacy.expected_space);
    assert(gpu_pointer == hybrid580_test_legacy.expected_free_pointer);
    ++hybrid580_test_legacy.free_calls;
}

static NV_STATUS hybrid580_test_map(struct fake_backend *backend,
    uvmGpuAddressSpaceHandle va_space, UvmGpuPointer gpu_pointer,
    NvLength length, void **cpu_pointer, NvU64 page_size, unsigned *calls)
{
    assert((uintptr_t)va_space == backend->expected_space);
    assert(gpu_pointer == UINT64_C(0x123456780000));
    assert(length == backend->expected_length);
    assert(page_size == backend->expected_page_size);
    ++*calls;
    if (backend->write_cpu_pointer)
        *cpu_pointer = backend->result_cpu_pointer;
    return backend->map_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceMemoryCpuMap(
    uvmGpuAddressSpaceHandle va_space, UvmGpuPointer gpu_pointer,
    NvLength length, void **cpu_pointer, NvU64 page_size)
{
    return hybrid580_test_map(&hybrid580_test_open, va_space, gpu_pointer,
        length, cpu_pointer, page_size, &hybrid580_test_open.map_calls);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceMemoryCpuMap(
    uvmGpuAddressSpaceHandle va_space, UvmGpuPointer gpu_pointer,
    NvLength length, void **cpu_pointer, NvU64 page_size)
{
    return hybrid580_test_map(&hybrid580_test_legacy, va_space, gpu_pointer,
        length, cpu_pointer, page_size, &hybrid580_test_legacy.map_calls);
}

void hybrid580_open_nvUvmInterfaceMemoryCpuUnMap(
    uvmGpuAddressSpaceHandle va_space, void *cpu_pointer)
{
    assert((uintptr_t)va_space == hybrid580_test_open.expected_space);
    assert(cpu_pointer == hybrid580_test_open.expected_unmap_pointer);
    ++hybrid580_test_open.unmap_calls;
}

void hybrid580_legacy_nvUvmInterfaceMemoryCpuUnMap(
    uvmGpuAddressSpaceHandle va_space, void *cpu_pointer)
{
    assert((uintptr_t)va_space == hybrid580_test_legacy.expected_space);
    assert(cpu_pointer == hybrid580_test_legacy.expected_unmap_pointer);
    ++hybrid580_test_legacy.unmap_calls;
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_MEMORY_PARAM_TYPES */
/* INSERT_EXACT_MEMORY_HELPERS_AND_ADAPTERS */
/* INSERT_EXACT_MEMORY_PROVIDER_OPS */
/* INSERT_EXACT_MEMORY_PUBLIC_WRAPPERS */

static void hybrid580_test_reset(void)
{
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_test_open_space, 0, sizeof(hybrid580_test_open_space));
    memset(&hybrid580_test_legacy_space, 0,
           sizeof(hybrid580_test_legacy_space));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_open.expected_space = 0x1000;
    hybrid580_test_legacy.expected_space = 0x2000;
    hybrid580_test_open.expected_length = UINT64_C(0x8000);
    hybrid580_test_legacy.expected_length = UINT64_C(0x10000);
    hybrid580_test_open.expected_page_size = UINT64_C(0x1000);
    hybrid580_test_legacy.expected_page_size = UINT64_C(0x10000);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_space,
               0x1000, 0x0100, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_space,
               0x2000, 0x0200, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
}

static void hybrid580_test_allocations_are_provider_scoped_and_failure_safe(void)
{
    UvmGpuPointer gpu_pointer = UINT64_MAX;
    UvmGpuAllocInfo alloc_info = {
        0x11110000, 0x10000, 0x1000, NV_FALSE, NV_FALSE, NV_FALSE, 0x11,
        NV_FALSE
    };

    hybrid580_test_reset();
    hybrid580_test_open.alloc_status = NV_OK;
    hybrid580_test_open.write_gpu_pointer = 1;
    hybrid580_test_open.write_alloc_info = 1;
    hybrid580_test_open.result_gpu_pointer = UINT64_C(0x51000000);
    hybrid580_test_open.result_alloc_info =
        (UvmGpuAllocInfo){0x51000000, 0x20000, 0x10000, NV_TRUE, NV_FALSE,
                           NV_TRUE, 0x51, NV_FALSE};
    assert(nvUvmInterfaceMemoryAllocFB((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x8000), &gpu_pointer, &alloc_info) == NV_OK);
    assert(gpu_pointer == UINT64_C(0x51000000) &&
           alloc_info.gpuPhysOffset == UINT64_C(0x51000000) &&
           alloc_info.pageSize == 0x20000 && alloc_info.alignment == 0x10000 &&
           alloc_info.bContiguousPhysAlloc == NV_TRUE &&
           alloc_info.bMemGrowsDown == NV_FALSE &&
           alloc_info.bPersistentVidmem == NV_TRUE &&
           alloc_info.hPhysHandle == 0x51 &&
           alloc_info.bUnprotected == NV_FALSE);
    assert(hybrid580_test_open.fb_calls == 1 &&
           hybrid580_test_legacy.fb_calls == 0);

    hybrid580_test_legacy.alloc_status = NV_OK;
    hybrid580_test_legacy.write_gpu_pointer = 1;
    hybrid580_test_legacy.write_alloc_info = 1;
    hybrid580_test_legacy.result_gpu_pointer = UINT64_C(0x62000000);
    hybrid580_test_legacy.result_alloc_info =
        (UvmGpuAllocInfo){0x62000000, 0x10000, 0x2000, NV_FALSE, NV_TRUE,
                           NV_FALSE, 0x62, NV_TRUE};
    gpu_pointer = UINT64_MAX;
    alloc_info = (UvmGpuAllocInfo){0x22220000, 0x8000, 0x4000, NV_TRUE,
                                   NV_FALSE, NV_TRUE, 0x22, NV_FALSE};
    assert(nvUvmInterfaceMemoryAllocSys((uvmGpuAddressSpaceHandle)0x2000,
               UINT64_C(0x10000), &gpu_pointer, &alloc_info) == NV_OK);
    assert(gpu_pointer == UINT64_C(0x62000000) &&
           alloc_info.gpuPhysOffset == UINT64_C(0x62000000) &&
           alloc_info.pageSize == 0x10000 && alloc_info.alignment == 0x2000 &&
           alloc_info.bContiguousPhysAlloc == NV_FALSE &&
           alloc_info.bMemGrowsDown == NV_TRUE &&
           alloc_info.bPersistentVidmem == NV_FALSE &&
           alloc_info.hPhysHandle == 0x62 &&
           alloc_info.bUnprotected == NV_TRUE);
    assert(hybrid580_test_legacy.sys_calls == 1 &&
           hybrid580_test_open.sys_calls == 0);

    hybrid580_test_open.alloc_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.write_gpu_pointer = 0;
    hybrid580_test_open.write_alloc_info = 0;
    gpu_pointer = UINT64_MAX;
    alloc_info = (UvmGpuAllocInfo){0x33330000, 0x4000, 0x2000, NV_FALSE,
                                   NV_TRUE, NV_FALSE, 0x33, NV_TRUE};
    assert(nvUvmInterfaceMemoryAllocFB((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x8000), &gpu_pointer, &alloc_info) ==
           TEST_PROVIDER_ERROR);
    assert(gpu_pointer == 0 && alloc_info.gpuPhysOffset == 0x33330000 &&
           alloc_info.pageSize == 0x4000 && alloc_info.alignment == 0x2000 &&
           alloc_info.bContiguousPhysAlloc == NV_FALSE &&
           alloc_info.bMemGrowsDown == NV_TRUE &&
           alloc_info.bPersistentVidmem == NV_FALSE &&
           alloc_info.hPhysHandle == 0x33 &&
           alloc_info.bUnprotected == NV_TRUE &&
           hybrid580_test_quarantine_pins == 0);

    hybrid580_test_open.write_gpu_pointer = 1;
    hybrid580_test_open.result_gpu_pointer = UINT64_C(0xdead0000);
    gpu_pointer = UINT64_MAX;
    assert(nvUvmInterfaceMemoryAllocFB((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x8000), &gpu_pointer, &alloc_info) ==
           TEST_PROVIDER_ERROR);
    assert(gpu_pointer == 0 && alloc_info.gpuPhysOffset == 0x33330000 &&
           alloc_info.pageSize == 0x4000 && alloc_info.alignment == 0x2000 &&
           alloc_info.bMemGrowsDown == NV_TRUE &&
           hybrid580_test_quarantine_pins == 1);

    hybrid580_test_open.alloc_status = NV_OK;
    hybrid580_test_open.result_gpu_pointer = 0;
    gpu_pointer = UINT64_MAX;
    assert(nvUvmInterfaceMemoryAllocFB((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x8000), &gpu_pointer, &alloc_info) == NV_ERR_GENERIC);
    assert(gpu_pointer == 0 && hybrid580_test_quarantine_pins == 2);

    gpu_pointer = UINT64_MAX;
    assert(nvUvmInterfaceMemoryAllocFB((uvmGpuAddressSpaceHandle)0x9999,
               UINT64_C(0x8000), &gpu_pointer, &alloc_info) == NV_ERR_INVALID_ARGUMENT);
    assert(gpu_pointer == 0 && hybrid580_test_open.fb_calls == 4 &&
           hybrid580_test_legacy.fb_calls == 0);
    assert(nvUvmInterfaceMemoryAllocFB((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x8000), NULL, &alloc_info) == NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceMemoryAllocSys((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x8000), &gpu_pointer, NULL) == NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_cpu_map_and_unmap_route_by_address_space_owner(void)
{
    void *cpu_pointer = (void *)(uintptr_t)UINTPTR_MAX;
    void *mapped = (void *)(uintptr_t)0xabc000;

    hybrid580_test_reset();
    hybrid580_test_open.map_status = NV_OK;
    hybrid580_test_open.write_cpu_pointer = 1;
    hybrid580_test_open.result_cpu_pointer = mapped;
    hybrid580_test_open.expected_unmap_pointer = mapped;
    assert(nvUvmInterfaceMemoryCpuMap((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x123456780000), UINT64_C(0x8000), &cpu_pointer,
               UINT64_C(0x1000)) == NV_OK);
    assert(cpu_pointer == mapped && hybrid580_test_open.map_calls == 1 &&
           hybrid580_test_legacy.map_calls == 0);
    nvUvmInterfaceMemoryCpuUnMap((uvmGpuAddressSpaceHandle)0x1000, mapped);
    assert(hybrid580_test_open.unmap_calls == 1 &&
           hybrid580_test_legacy.unmap_calls == 0);

    hybrid580_test_legacy.map_status = NV_OK;
    hybrid580_test_legacy.write_cpu_pointer = 1;
    hybrid580_test_legacy.result_cpu_pointer = mapped;
    hybrid580_test_legacy.expected_unmap_pointer = mapped;
    cpu_pointer = NULL;
    assert(nvUvmInterfaceMemoryCpuMap((uvmGpuAddressSpaceHandle)0x2000,
               UINT64_C(0x123456780000), UINT64_C(0x10000), &cpu_pointer,
               UINT64_C(0x10000)) == NV_OK);
    assert(cpu_pointer == mapped && hybrid580_test_legacy.map_calls == 1 &&
           hybrid580_test_open.map_calls == 1);
    nvUvmInterfaceMemoryCpuUnMap((uvmGpuAddressSpaceHandle)0x2000, mapped);
    assert(hybrid580_test_legacy.unmap_calls == 1);

    hybrid580_test_open.map_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.result_cpu_pointer = (void *)(uintptr_t)0xdead000;
    cpu_pointer = mapped;
    assert(nvUvmInterfaceMemoryCpuMap((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x123456780000), UINT64_C(0x8000), &cpu_pointer,
               UINT64_C(0x1000)) == TEST_PROVIDER_ERROR);
    assert(cpu_pointer == NULL && hybrid580_test_quarantine_pins == 1);

    hybrid580_test_open.map_status = NV_OK;
    hybrid580_test_open.result_cpu_pointer = NULL;
    cpu_pointer = mapped;
    assert(nvUvmInterfaceMemoryCpuMap((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x123456780000), UINT64_C(0x8000), &cpu_pointer,
               UINT64_C(0x1000)) == NV_ERR_GENERIC);
    assert(cpu_pointer == NULL && hybrid580_test_quarantine_pins == 2);

    assert(nvUvmInterfaceMemoryCpuMap((uvmGpuAddressSpaceHandle)0x1000,
               UINT64_C(0x123456780000), UINT64_C(0x8000), NULL,
               UINT64_C(0x1000)) == NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_free_routes_and_ignores_invalid_inputs(void)
{
    hybrid580_test_reset();
    hybrid580_test_open.expected_free_pointer = UINT64_C(0x51000000);
    hybrid580_test_legacy.expected_free_pointer = UINT64_C(0x62000000);
    nvUvmInterfaceMemoryFree((uvmGpuAddressSpaceHandle)0x1000,
                            UINT64_C(0x51000000));
    nvUvmInterfaceMemoryFree((uvmGpuAddressSpaceHandle)0x2000,
                            UINT64_C(0x62000000));
    assert(hybrid580_test_open.free_calls == 1 &&
           hybrid580_test_legacy.free_calls == 1);
    nvUvmInterfaceMemoryFree(NULL, UINT64_C(0x51000000));
    nvUvmInterfaceMemoryFree((uvmGpuAddressSpaceHandle)0x1000, 0);
    nvUvmInterfaceMemoryCpuUnMap(NULL, (void *)(uintptr_t)0xabc000);
    nvUvmInterfaceMemoryCpuUnMap((uvmGpuAddressSpaceHandle)0x1000, NULL);
    assert(hybrid580_test_open.free_calls == 1 &&
           hybrid580_test_open.unmap_calls == 0 &&
           hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

int main(void)
{
    hybrid580_test_allocations_are_provider_scoped_and_failure_safe();
    hybrid580_test_cpu_map_and_unmap_route_by_address_space_owner();
    hybrid580_test_free_routes_and_ignores_invalid_inputs();
    puts("exact UVM memory allocation and CPU mapping wrappers passed");
    return 0;
}
