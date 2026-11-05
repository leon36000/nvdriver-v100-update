/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvBool;
typedef uint32_t NvU32;
typedef uint32_t NvHandle;
typedef void *uvmGpuDeviceHandle;
typedef void *uvmGpuAddressSpaceHandle;

typedef struct {
    uint64_t page_size;
    uint64_t va_base;
    uint64_t va_size;
    uint32_t provider_marker;
} UvmGpuAddressSpaceInfo;

struct file {
    uintptr_t identity;
};

#define NV_OK                          UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT       UINT32_C(0xe0013201)
#define NV_ERR_NO_MEMORY              UINT32_C(0xe0013202)
#define NV_ERR_INVALID_STATE          UINT32_C(0xe0013203)
#define NV_ERR_INVALID_OBJECT_HANDLE  UINT32_C(0xe0013204)
#define NV_ERR_GENERIC                UINT32_C(0xe0013205)
#define TEST_PROVIDER_ERROR           UINT32_C(0xe0013206)
#define TEST_OWNER_ERROR              UINT32_C(0xe0013207)
#define NV_FALSE                      UINT32_C(0)
#define NV_TRUE                       UINT32_C(1)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580-gpu-catalog.h"
#include "src/hybrid580_uvm_address_space_route.h"
#include "src/hybrid580_uvm_typed_child_route.h"
#include "src/hybrid580_frontend_uvm_address_space_owner.h"

struct hybrid_front_uvm_address_space_owner_pin {
    uint32_t marker;
};

struct fake_backend {
    uintptr_t expected_device;
    NvHandle expected_root;
    NvHandle expected_vaspace;
    uintptr_t created_space;
    NV_STATUS duplicate_status;
    unsigned duplicate_calls;
    unsigned destroy_calls;
    uintptr_t last_destroyed;
};

struct fake_owner {
    unsigned backend;
    NvHandle root;
    NvHandle vaspace;
    NvU32 pin_status;
    unsigned pin_calls;
    unsigned unpin_calls;
    unsigned quarantine_calls;
};

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static int hybrid580_uvm_callback_lock;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
static struct fake_owner hybrid580_test_owner;
static struct hybrid_front_uvm_address_space_owner_pin hybrid580_test_pin = {
    .marker = UINT32_C(0xfeed),
};
static struct file hybrid580_test_file = {.identity = 0xdead};
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_kzalloc_calls;
static unsigned hybrid580_test_kfree_calls;
static unsigned hybrid580_test_quarantine_pins;
static int hybrid580_test_fail_kzalloc_at;

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
    if (hybrid580_test_fail_kzalloc_at ==
        (int)hybrid580_test_kzalloc_calls)
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

NvU32 hybrid580_frontend_uvm_address_space_owner_pin_v1(
    struct file *rm_control_file, NvHandle public_client,
    NvHandle public_vaspace,
    struct hybrid580_frontend_address_space_owner *owner)
{
    assert(rm_control_file == &hybrid580_test_file);
    assert(rm_control_file->identity == 0xdead);
    assert(public_client == UINT32_C(0x11));
    assert(public_vaspace == UINT32_C(0x22));
    assert(owner != NULL);
    ++hybrid580_test_owner.pin_calls;
    if (hybrid580_test_owner.pin_status != NV_OK)
        return hybrid580_test_owner.pin_status;
    owner->backend = hybrid580_test_owner.backend;
    owner->backend_root = hybrid580_test_owner.root;
    owner->backend_vaspace = hybrid580_test_owner.vaspace;
    owner->pin = &hybrid580_test_pin;
    return NV_OK;
}

void hybrid580_frontend_uvm_address_space_owner_unpin_v1(
    struct hybrid580_frontend_address_space_owner *owner)
{
    assert(owner != NULL && owner->pin == &hybrid580_test_pin);
    ++hybrid580_test_owner.unpin_calls;
    owner->pin = NULL;
}

void hybrid580_frontend_uvm_address_space_owner_quarantine_v1(
    struct hybrid580_frontend_address_space_owner *owner)
{
    assert(owner != NULL && owner->pin == &hybrid580_test_pin);
    ++hybrid580_test_owner.quarantine_calls;
    owner->pin = NULL;
}

static NV_STATUS hybrid580_test_rm_duplicate(
    struct fake_backend *backend, uvmGpuDeviceHandle device,
    NvHandle client, NvHandle user_vaspace,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    assert((uintptr_t)device == backend->expected_device);
    assert(client == backend->expected_root);
    assert(user_vaspace == backend->expected_vaspace);
    assert(space != NULL && info != NULL);
    ++backend->duplicate_calls;
    *space = (uvmGpuAddressSpaceHandle)backend->created_space;
    if (backend->duplicate_status == NV_OK) {
        info->page_size = UINT64_C(0x10000);
        info->va_base = UINT64_C(0x400000);
        info->va_size = UINT64_C(0x20000000);
        info->provider_marker = (uint32_t)backend->expected_device;
    }
    return backend->duplicate_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceDupAddressSpace(
    uvmGpuDeviceHandle device, NvHandle client, NvHandle user_vaspace,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    return hybrid580_test_rm_duplicate(&hybrid580_test_open, device, client,
                                       user_vaspace, space, info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceDupAddressSpace(
    uvmGpuDeviceHandle device, NvHandle client, NvHandle user_vaspace,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    return hybrid580_test_rm_duplicate(&hybrid580_test_legacy, device, client,
                                       user_vaspace, space, info);
}

NV_STATUS hybrid580_open_nvUvmInterfaceAddressSpaceCreate(
    uvmGpuDeviceHandle device, unsigned long long va_base,
    unsigned long long va_size, NvBool enable_ats,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    (void)device;
    (void)va_base;
    (void)va_size;
    (void)enable_ats;
    (void)space;
    (void)info;
    return NV_ERR_GENERIC;
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceAddressSpaceCreate(
    uvmGpuDeviceHandle device, unsigned long long va_base,
    unsigned long long va_size, NvBool enable_ats,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    (void)device;
    (void)va_base;
    (void)va_size;
    (void)enable_ats;
    (void)space;
    (void)info;
    return NV_ERR_GENERIC;
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

/* INSERT_EXACT_DUP_ADDRESS_SPACE_BACKEND_ADAPTERS */
/* INSERT_EXACT_DUP_ADDRESS_SPACE_PROVIDER_OPS */
/* INSERT_EXACT_DUP_ADDRESS_SPACE_PUBLIC_WRAPPERS */

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
    memset(&hybrid580_test_owner, 0, sizeof(hybrid580_test_owner));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_kzalloc_calls = 0;
    hybrid580_test_kfree_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_fail_kzalloc_at = 0;
    hybrid580_test_open.expected_device = 0x1000;
    hybrid580_test_open.expected_root = UINT32_C(0x31);
    hybrid580_test_open.expected_vaspace = UINT32_C(0x32);
    hybrid580_test_open.created_space = 0x1100;
    hybrid580_test_legacy.expected_device = 0x2000;
    hybrid580_test_legacy.expected_root = UINT32_C(0x41);
    hybrid580_test_legacy.expected_vaspace = UINT32_C(0x42);
    hybrid580_test_legacy.created_space = 0x2200;
    hybrid580_test_owner.backend = HYBRID580_BACKEND_OPEN;
    hybrid580_test_owner.root = UINT32_C(0x31);
    hybrid580_test_owner.vaspace = UINT32_C(0x32);

    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, 0x1000,
               HYBRID580_UVM_PROVIDER_OPEN, open_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, 0x2000,
               HYBRID580_UVM_PROVIDER_LEGACY, legacy_uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
}

static NV_STATUS hybrid580_test_duplicate(
    struct file *control_file, uintptr_t device,
    uvmGpuAddressSpaceHandle *space, UvmGpuAddressSpaceInfo *info)
{
    return nvUvmInterfaceDupAddressSpaceWithControlFd(
        control_file, (uvmGpuDeviceHandle)device, UINT32_C(0x11),
        UINT32_C(0x22), space, info);
}

static void hybrid580_test_open_legacy_dispatch_and_cleanup(void)
{
    uvmGpuAddressSpaceHandle space = NULL;
    UvmGpuAddressSpaceInfo info = {0};

    hybrid580_test_reset();
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == NV_OK);
    assert((uintptr_t)space == 0x1100 && info.page_size == 0x10000 &&
           info.va_base == 0x400000 && info.va_size == 0x20000000 &&
           info.provider_marker == 0x1000);
    assert(hybrid580_test_open.duplicate_calls == 1 &&
           hybrid580_test_legacy.duplicate_calls == 0);
    assert(hybrid580_test_owner.pin_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_owner.quarantine_calls == 0);
    nvUvmInterfaceAddressSpaceDestroy(space);
    assert(hybrid580_test_open.destroy_calls == 1 &&
           hybrid580_test_legacy.destroy_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_owner.backend = HYBRID580_BACKEND_LEGACY;
    hybrid580_test_owner.root = UINT32_C(0x41);
    hybrid580_test_owner.vaspace = UINT32_C(0x42);
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x2000, &space,
                                    &info) == NV_OK);
    assert((uintptr_t)space == 0x2200 && info.provider_marker == 0x2000);
    assert(hybrid580_test_open.duplicate_calls == 0 &&
           hybrid580_test_legacy.duplicate_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 1);
    nvUvmInterfaceAddressSpaceDestroy(space);
    assert(hybrid580_test_legacy.destroy_calls == 1 &&
           hybrid580_test_open.destroy_calls == 0);
}

static void hybrid580_test_rejects_owner_device_mismatch_and_bad_handles(void)
{
    uvmGpuAddressSpaceHandle space =
        (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    UvmGpuAddressSpaceInfo info = {.page_size = UINT64_MAX};

    hybrid580_test_reset();
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x2000, &space,
                                    &info) == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(space == NULL && info.page_size == 0 &&
           hybrid580_test_owner.pin_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_open.duplicate_calls == 0 &&
           hybrid580_test_legacy.duplicate_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_owner.backend = UINT32_C(0xff);
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == NV_ERR_INVALID_STATE);
    assert(space == NULL && hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_lock_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_owner.pin_status = TEST_OWNER_ERROR;
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == TEST_OWNER_ERROR);
    assert(space == NULL && hybrid580_test_owner.pin_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 0 &&
           hybrid580_test_lock_calls == 0);

    hybrid580_test_reset();
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0xdead, &space,
                                    &info) == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(space == NULL && hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_open.duplicate_calls == 0 &&
           hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_allocation_failures_and_ambiguous_outputs(void)
{
    uvmGpuAddressSpaceHandle space =
        (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    UvmGpuAddressSpaceInfo info = {.page_size = UINT64_MAX};

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 1;
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == NV_ERR_NO_MEMORY);
    assert(space == NULL && info.page_size == 0 &&
           hybrid580_test_owner.pin_calls == 0 &&
           hybrid580_test_lock_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 2;
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == NV_ERR_NO_MEMORY);
    assert(space == NULL && info.page_size == 0 &&
           hybrid580_test_owner.pin_calls == 0 &&
           hybrid580_test_kfree_calls == 1);

    hybrid580_test_reset();
    hybrid580_test_open.duplicate_status = TEST_PROVIDER_ERROR;
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == TEST_PROVIDER_ERROR);
    assert(space == NULL && info.page_size == 0 && info.va_base == 0 &&
           info.va_size == 0 && hybrid580_test_open.duplicate_calls == 1 &&
           hybrid580_test_legacy.duplicate_calls == 0);
    assert(hybrid580_test_owner.quarantine_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 0 &&
           hybrid580_test_quarantine_pins == 1);
    assert(hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 0);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_live_identity_collision_is_not_destroyed(void)
{
    uvmGpuAddressSpaceHandle space = NULL;
    UvmGpuAddressSpaceInfo info = {0};

    hybrid580_test_reset();
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == NV_OK);
    assert((uintptr_t)space == 0x1100);
    space = (uvmGpuAddressSpaceHandle)UINTPTR_MAX;
    info.page_size = UINT64_MAX;
    assert(hybrid580_test_duplicate(&hybrid580_test_file, 0x1000, &space,
                                    &info) == NV_ERR_GENERIC);
    assert(space == NULL && info.page_size == 0 && info.va_base == 0 &&
           info.va_size == 0 && info.provider_marker == 0);
    assert(hybrid580_test_open.duplicate_calls == 2 &&
           hybrid580_test_legacy.duplicate_calls == 0 &&
           hybrid580_test_open.destroy_calls == 0);
    assert(hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 1);
    assert(hybrid580_test_owner.pin_calls == 2 &&
           hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_owner.quarantine_calls == 1 &&
           hybrid580_test_quarantine_pins == 1);

    nvUvmInterfaceAddressSpaceDestroy((uvmGpuAddressSpaceHandle)0x1100);
    assert(hybrid580_test_open.destroy_calls == 1 &&
           hybrid580_test_open.last_destroyed == 0x1100);
    assert(hybrid580_uvm_address_space_registry_count(
               &hybrid580_uvm_address_spaces) == 0);
}

int main(void)
{
    hybrid580_test_open_legacy_dispatch_and_cleanup();
    hybrid580_test_rejects_owner_device_mismatch_and_bad_handles();
    hybrid580_test_allocation_failures_and_ambiguous_outputs();
    hybrid580_test_live_identity_collision_is_not_destroyed();
    puts("exact UVM duplicate-address-space wrapper, owner pin, provider dispatch, and cleanup passed");
    return 0;
}
