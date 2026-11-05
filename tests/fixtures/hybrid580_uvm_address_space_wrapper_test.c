/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvBool;
typedef uint32_t NvHandle;
typedef void *uvmGpuDeviceHandle;
typedef void *uvmGpuAddressSpaceHandle;

typedef struct {
    uint64_t page_size;
    uint64_t va_base;
    uint64_t va_size;
    uint32_t provider_marker;
} UvmGpuAddressSpaceInfo;

#define NV_OK                    UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0013101)
#define NV_ERR_NO_MEMORY        UINT32_C(0xe0013102)
#define NV_ERR_GENERIC          UINT32_C(0xe0013103)
#define TEST_PROVIDER_ERROR     UINT32_C(0xe0013104)
#define NV_FALSE                UINT32_C(0)
#define NV_TRUE                 UINT32_C(1)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_address_space_route.h"
#include "src/hybrid580_uvm_typed_child_route.h"

struct fake_backend {
    uintptr_t expected_device;
    uintptr_t created_space;
    uint32_t create_status;
    int expected_ats;
    unsigned create_calls;
    unsigned destroy_calls;
    uintptr_t last_destroyed;
};

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static int hybrid580_uvm_callback_lock;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_kzalloc_calls;
static unsigned hybrid580_test_kfree_calls;
static unsigned hybrid580_test_quarantine_pins;
static int hybrid580_test_fail_kzalloc;

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

static void *hybrid580_test_kzalloc(size_t size, unsigned int flags)
{
    assert(flags == GFP_KERNEL);
    ++hybrid580_test_kzalloc_calls;
    if (hybrid580_test_fail_kzalloc)
        return NULL;
    return calloc(1, size);
}

static void hybrid580_test_kfree(void *pointer)
{
    if (pointer != NULL) {
        ++hybrid580_test_kfree_calls;
        free(pointer);
    }
}

#define mutex_lock(lock) hybrid580_test_mutex_lock(lock)
#define mutex_unlock(lock) hybrid580_test_mutex_unlock(lock)
#define kzalloc(size, flags) hybrid580_test_kzalloc((size), (flags))
#define kfree(pointer) hybrid580_test_kfree(pointer)

static NV_STATUS hybrid580_test_rm_create(
    struct fake_backend *backend, uvmGpuDeviceHandle device,
    unsigned long long va_base, unsigned long long va_size, NvBool enable_ats,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    assert((uintptr_t)device == backend->expected_device);
    assert(va_base == UINT64_C(0x100000));
    assert(va_size == UINT64_C(0x10000000));
    assert((enable_ats != NV_FALSE) == backend->expected_ats);
    ++backend->create_calls;
    *space = (uvmGpuAddressSpaceHandle)backend->created_space;
    if (backend->create_status == NV_OK) {
        info->page_size = UINT64_C(0x10000);
        info->va_base = va_base;
        info->va_size = va_size;
        info->provider_marker = (uint32_t)backend->expected_device;
    }
    return backend->create_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceAddressSpaceCreate(
    uvmGpuDeviceHandle device, unsigned long long va_base,
    unsigned long long va_size, NvBool enable_ats,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    return hybrid580_test_rm_create(&hybrid580_test_open, device, va_base,
                                    va_size, enable_ats, space, info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceAddressSpaceCreate(
    uvmGpuDeviceHandle device, unsigned long long va_base,
    unsigned long long va_size, NvBool enable_ats,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    return hybrid580_test_rm_create(&hybrid580_test_legacy, device, va_base,
                                    va_size, enable_ats, space, info);
}

void hybrid580_open_nvUvmInterfaceAddressSpaceDestroy(
    uvmGpuAddressSpaceHandle space)
{
    ++hybrid580_test_open.destroy_calls;
    hybrid580_test_open.last_destroyed = (uintptr_t)space;
}

void hybrid580_legacy_nvUvmInterfaceAddressSpaceDestroy(
    uvmGpuAddressSpaceHandle space)
{
    ++hybrid580_test_legacy.destroy_calls;
    hybrid580_test_legacy.last_destroyed = (uintptr_t)space;
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_ADDRESS_SPACE_BACKEND_ADAPTERS */
/* INSERT_EXACT_ADDRESS_SPACE_PROVIDER_OPS */
/* INSERT_EXACT_ADDRESS_SPACE_PUBLIC_WRAPPERS */

static void hybrid580_test_reset(void)
{
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x10};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x20};

    memset(&hybrid580_uvm_devices, 0, sizeof(hybrid580_uvm_devices));
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_uvm_typed_children, 0,
           sizeof(hybrid580_uvm_typed_children));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_kzalloc_calls = 0;
    hybrid580_test_kfree_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_fail_kzalloc = 0;
    hybrid580_test_open.expected_device = 0x1000;
    hybrid580_test_open.created_space = 0x1100;
    hybrid580_test_open.expected_ats = 1;
    hybrid580_test_legacy.expected_device = 0x2000;
    hybrid580_test_legacy.created_space = 0x2200;
    hybrid580_test_legacy.expected_ats = 0;
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, 0x1000,
               HYBRID580_UVM_PROVIDER_OPEN, open_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, 0x2000,
               HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
}

static NV_STATUS hybrid580_test_create(
    uintptr_t device, uvmGpuAddressSpaceHandle *space,
    UvmGpuAddressSpaceInfo *info, NvBool enable_ats)
{
    return nvUvmInterfaceAddressSpaceCreate(
        (uvmGpuDeviceHandle)device, UINT64_C(0x100000), UINT64_C(0x10000000),
        enable_ats, space, info);
}

static void hybrid580_test_create_destroy_and_parent_lifetime(void)
{
    uvmGpuAddressSpaceHandle space = (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    UvmGpuAddressSpaceInfo info = {0};
    struct hybrid580_uvm_typed_child_entry *child = calloc(1, sizeof(*child));
    struct hybrid580_uvm_typed_child_entry *removed_child = NULL;

    assert(child != NULL);
    hybrid580_test_reset();
    assert(hybrid580_test_create(0x1000, &space, &info, NV_TRUE) == NV_OK);
    assert((uintptr_t)space == 0x1100 && info.page_size == 0x10000 &&
           info.va_base == 0x100000 && info.va_size == 0x10000000 &&
           info.provider_marker == 0x1000);
    assert(hybrid580_test_open.create_calls == 1 &&
           hybrid580_test_legacy.create_calls == 0);
    assert(hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 1);
    assert(hybrid580_uvm_typed_child_registry_insert(
               &hybrid580_uvm_typed_children, child, 0x900, (uintptr_t)space,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
               HYBRID580_UVM_TYPED_CHILD_TSG,
               HYBRID580_UVM_PROVIDER_OPEN) == HYBRID580_UVM_TYPED_CHILD_OK);

    nvUvmInterfaceAddressSpaceDestroy(space);
    assert(hybrid580_test_open.destroy_calls == 0 &&
           hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 1 &&
           hybrid580_test_quarantine_pins == 1);
    assert(hybrid580_uvm_typed_child_registry_remove(
               &hybrid580_uvm_typed_children, 0x900,
               HYBRID580_UVM_TYPED_CHILD_TSG, &removed_child) ==
           HYBRID580_UVM_TYPED_CHILD_OK);
    assert(removed_child == child);
    free(removed_child);

    nvUvmInterfaceAddressSpaceDestroy(space);
    assert(hybrid580_test_open.destroy_calls == 1 &&
           hybrid580_test_open.last_destroyed == (uintptr_t)space &&
           hybrid580_test_legacy.destroy_calls == 0);
    assert(hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 0);
    assert(hybrid580_test_kzalloc_calls == 1 &&
           hybrid580_test_kfree_calls == 1);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_provider_selection_and_failure_boundaries(void)
{
    uvmGpuAddressSpaceHandle space = NULL;
    UvmGpuAddressSpaceInfo info = {0};

    hybrid580_test_reset();
    assert(hybrid580_test_create(0x2000, &space, &info, NV_FALSE) == NV_OK);
    assert((uintptr_t)space == 0x2200 && info.provider_marker == 0x2000);
    assert(hybrid580_test_open.create_calls == 0 &&
           hybrid580_test_legacy.create_calls == 1);
    nvUvmInterfaceAddressSpaceDestroy(space);
    assert(hybrid580_test_legacy.destroy_calls == 1 &&
           hybrid580_test_open.destroy_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_legacy.create_status = TEST_PROVIDER_ERROR;
    space = (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    info.page_size = UINT64_MAX;
    assert(hybrid580_test_create(0x2000, &space, &info, NV_FALSE) ==
           TEST_PROVIDER_ERROR);
    assert(space == NULL && info.page_size == 0 && info.va_base == 0 &&
           info.va_size == 0 && info.provider_marker == 0);
    assert(hybrid580_test_legacy.create_calls == 1 &&
           hybrid580_test_open.create_calls == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_kfree_calls == 1);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_ambiguous_identity_and_alloc_failure(void)
{
    uvmGpuAddressSpaceHandle space = NULL;
    UvmGpuAddressSpaceInfo info = {0};

    hybrid580_test_reset();
    assert(hybrid580_test_create(0x1000, &space, &info, NV_TRUE) == NV_OK);
    space = (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    info.page_size = UINT64_MAX;
    assert(hybrid580_test_create(0x1000, &space, &info, NV_TRUE) ==
           NV_ERR_GENERIC);
    assert(space == NULL && info.page_size == 0 &&
           hybrid580_test_open.create_calls == 2 &&
           hybrid580_test_open.destroy_calls == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 1);

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc = 1;
    space = (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    info.page_size = UINT64_MAX;
    assert(hybrid580_test_create(0x1000, &space, &info, NV_TRUE) ==
           NV_ERR_NO_MEMORY);
    assert(space == NULL && info.page_size == 0 &&
           hybrid580_test_open.create_calls == 0 &&
           hybrid580_test_lock_calls == 0);
}

int main(void)
{
    hybrid580_test_create_destroy_and_parent_lifetime();
    hybrid580_test_provider_selection_and_failure_boundaries();
    hybrid580_test_ambiguous_identity_and_alloc_failure();
    puts("exact UVM address-space create/destroy wrappers and parent lifetime passed");
    return 0;
}
