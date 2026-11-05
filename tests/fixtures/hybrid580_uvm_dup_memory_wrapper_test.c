/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvU32;
typedef uint32_t NvHandle;
typedef void *uvmGpuDeviceHandle;

typedef struct {
    uint64_t size;
    uint32_t flags;
    uint32_t provider_marker;
} UvmGpuMemoryInfo;

#define NV_OK                      UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT   UINT32_C(0xe0013001)
#define NV_ERR_NO_MEMORY          UINT32_C(0xe0013002)
#define NV_ERR_NOT_SUPPORTED      UINT32_C(0xe0013003)
#define NV_ERR_GENERIC            UINT32_C(0xe0013004)
#define NV_ERR_INVALID_STATE      UINT32_C(0xe0013005)
#define TEST_PROVIDER_ERROR       UINT32_C(0xe0013006)
#define TEST_OWNER_ERROR          UINT32_C(0xe0013007)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580-gpu-catalog.h"
#include "src/hybrid580_uvm_dup_memory_route.h"
#include "src/hybrid580_frontend_uvm_memory_owner.h"

struct hybrid580_frontend_memory_owner_pin {
    uint32_t marker;
};

struct fake_rm {
    uintptr_t expected_device;
    NvHandle expected_root;
    NvHandle expected_memory;
    NvHandle duplicate_handle;
    NV_STATUS duplicate_status;
    NV_STATUS free_status;
    unsigned duplicate_calls;
    unsigned free_calls;
    uintptr_t last_freed;
};

struct fake_owner_source {
    unsigned backend;
    NvHandle backend_root;
    NvHandle backend_memory;
    NvU32 pin_status;
    unsigned pin_calls;
    unsigned unpin_calls;
    unsigned quarantine_calls;
    int expected_control_fd;
    NvHandle expected_public_client;
    NvHandle expected_public_memory;
};

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static int hybrid580_uvm_callback_lock;
static struct fake_rm hybrid580_test_open_rm;
static struct fake_rm hybrid580_test_legacy_rm;
static struct fake_owner_source hybrid580_test_owner;
static struct hybrid580_frontend_memory_owner_pin hybrid580_test_pin = {
    .marker = UINT32_C(0xfeed),
};
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_quarantine_pins;
static unsigned hybrid580_test_kzalloc_calls;
static unsigned hybrid580_test_kfree_calls;
static unsigned hybrid580_test_fail_kzalloc_at;

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
    if (hybrid580_test_fail_kzalloc_at == hybrid580_test_kzalloc_calls)
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

NvU32 hybrid580_frontend_uvm_memory_owner_pin_v1(
    int rm_control_fd, NvHandle public_client, NvHandle public_memory,
    struct hybrid580_frontend_memory_owner *owner)
{
    assert(owner != NULL);
    ++hybrid580_test_owner.pin_calls;
    assert(rm_control_fd == hybrid580_test_owner.expected_control_fd);
    assert(public_client == hybrid580_test_owner.expected_public_client);
    assert(public_memory == hybrid580_test_owner.expected_public_memory);
    if (hybrid580_test_owner.pin_status != NV_OK)
        return hybrid580_test_owner.pin_status;
    owner->backend = hybrid580_test_owner.backend;
    owner->backend_root = hybrid580_test_owner.backend_root;
    owner->backend_memory = hybrid580_test_owner.backend_memory;
    owner->pin = &hybrid580_test_pin;
    return NV_OK;
}

void hybrid580_frontend_uvm_memory_owner_unpin_v1(
    struct hybrid580_frontend_memory_owner *owner)
{
    assert(owner != NULL && owner->pin == &hybrid580_test_pin);
    ++hybrid580_test_owner.unpin_calls;
    owner->pin = NULL;
}

void hybrid580_frontend_uvm_memory_owner_quarantine_v1(
    struct hybrid580_frontend_memory_owner *owner)
{
    assert(owner != NULL && owner->pin == &hybrid580_test_pin);
    ++hybrid580_test_owner.quarantine_calls;
    owner->pin = NULL;
}

static NV_STATUS hybrid580_test_rm_duplicate(
    struct fake_rm *rm, uintptr_t device, NvHandle client,
    NvHandle physical_memory, NvHandle *duplicate, UvmGpuMemoryInfo *info)
{
    assert(device == rm->expected_device);
    assert(client == rm->expected_root);
    assert(physical_memory == rm->expected_memory);
    assert(duplicate != NULL);
    ++rm->duplicate_calls;
    *duplicate = (NvHandle)rm->duplicate_handle;
    if (info != NULL && rm->duplicate_status == NV_OK) {
        info->size = UINT64_C(0x100000) + (uint64_t)device;
        info->flags = UINT32_C(0x55aa);
        info->provider_marker = (uint32_t)device;
    }
    return rm->duplicate_status;
}

static NV_STATUS hybrid580_test_rm_free(struct fake_rm *rm, uintptr_t device,
                                         NvHandle duplicate)
{
    assert(device == rm->expected_device);
    ++rm->free_calls;
    rm->last_freed = duplicate;
    return rm->free_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceDupMemory(
    uvmGpuDeviceHandle device, NvHandle client, NvHandle physical_memory,
    NvHandle *duplicate, UvmGpuMemoryInfo *info)
{
    assert(hybrid580_test_owner.backend_root ==
           hybrid580_test_open_rm.expected_root);
    assert(hybrid580_test_owner.backend_memory ==
           hybrid580_test_open_rm.expected_memory);
    return hybrid580_test_rm_duplicate(&hybrid580_test_open_rm,
        (uintptr_t)device, client, physical_memory, duplicate, info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceDupMemory(
    uvmGpuDeviceHandle device, NvHandle client, NvHandle physical_memory,
    NvHandle *duplicate, UvmGpuMemoryInfo *info)
{
    assert(hybrid580_test_owner.backend_root ==
           hybrid580_test_legacy_rm.expected_root);
    assert(hybrid580_test_owner.backend_memory ==
           hybrid580_test_legacy_rm.expected_memory);
    return hybrid580_test_rm_duplicate(&hybrid580_test_legacy_rm,
        (uintptr_t)device, client, physical_memory, duplicate, info);
}

NV_STATUS hybrid580_open_nvUvmInterfaceFreeDupedHandle(
    uvmGpuDeviceHandle device, NvHandle duplicate)
{
    return hybrid580_test_rm_free(&hybrid580_test_open_rm,
                                   (uintptr_t)device, duplicate);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceFreeDupedHandle(
    uvmGpuDeviceHandle device, NvHandle duplicate)
{
    return hybrid580_test_rm_free(&hybrid580_test_legacy_rm,
                                   (uintptr_t)device, duplicate);
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_DUP_MEMORY_BACKEND_ADAPTERS */
/* INSERT_EXACT_DUP_MEMORY_PROVIDER_OPS */
/* INSERT_EXACT_DUP_MEMORY_PUBLIC_WRAPPERS */

static void hybrid580_test_reset(void)
{
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x10};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x20};

    memset(&hybrid580_uvm_devices, 0, sizeof(hybrid580_uvm_devices));
    memset(&hybrid580_uvm_typed_children, 0,
           sizeof(hybrid580_uvm_typed_children));
    memset(&hybrid580_test_open_rm, 0, sizeof(hybrid580_test_open_rm));
    memset(&hybrid580_test_legacy_rm, 0, sizeof(hybrid580_test_legacy_rm));
    memset(&hybrid580_test_owner, 0, sizeof(hybrid580_test_owner));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_kzalloc_calls = 0;
    hybrid580_test_kfree_calls = 0;
    hybrid580_test_fail_kzalloc_at = 0;

    hybrid580_test_owner.expected_control_fd = 9;
    hybrid580_test_owner.expected_public_client = UINT32_C(0x11);
    hybrid580_test_owner.expected_public_memory = UINT32_C(0x22);
    hybrid580_test_owner.backend = HYBRID580_BACKEND_OPEN;
    hybrid580_test_owner.backend_root = UINT32_C(0x31);
    hybrid580_test_owner.backend_memory = UINT32_C(0x32);
    hybrid580_test_open_rm.expected_device = 0x1000;
    hybrid580_test_open_rm.expected_root = UINT32_C(0x31);
    hybrid580_test_open_rm.expected_memory = UINT32_C(0x32);
    hybrid580_test_legacy_rm.expected_device = 0x2000;
    hybrid580_test_legacy_rm.expected_root = UINT32_C(0x41);
    hybrid580_test_legacy_rm.expected_memory = UINT32_C(0x42);
    hybrid580_test_open_rm.duplicate_handle = UINT32_C(0x111);
    hybrid580_test_legacy_rm.duplicate_handle = UINT32_C(0x222);

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
    uintptr_t device, NvHandle *duplicate, UvmGpuMemoryInfo *info)
{
    return nvUvmInterfaceDupMemoryWithControlFd(
        9, (uvmGpuDeviceHandle)device, UINT32_C(0x11), UINT32_C(0x22),
        duplicate, info);
}

static void hybrid580_test_success_and_retryable_free(void)
{
    NvHandle duplicate = UINT32_MAX;
    UvmGpuMemoryInfo info = {0};

    hybrid580_test_reset();
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) == NV_OK);
    assert(duplicate == UINT32_C(0x111));
    assert(info.size == UINT64_C(0x101000) && info.flags == UINT32_C(0x55aa) &&
           info.provider_marker == UINT32_C(0x1000));
    assert(hybrid580_test_open_rm.duplicate_calls == 1 &&
           hybrid580_test_legacy_rm.duplicate_calls == 0);
    assert(hybrid580_test_owner.pin_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_owner.quarantine_calls == 0);
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 1);

    assert(nvUvmInterfaceFreeDupedHandle(
               (uvmGpuDeviceHandle)0x2000, duplicate) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(hybrid580_test_open_rm.free_calls == 0 &&
           hybrid580_test_legacy_rm.free_calls == 0);
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 1 &&
           hybrid580_test_quarantine_pins == 1);

    hybrid580_test_open_rm.free_status = TEST_PROVIDER_ERROR;
    assert(nvUvmInterfaceFreeDupedHandle(
               (uvmGpuDeviceHandle)0x1000, duplicate) == TEST_PROVIDER_ERROR);
    assert(hybrid580_test_open_rm.free_calls == 1 &&
           hybrid580_test_open_rm.last_freed == duplicate);
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 1);

    hybrid580_test_open_rm.free_status = NV_OK;
    assert(nvUvmInterfaceFreeDupedHandle(
               (uvmGpuDeviceHandle)0x1000, duplicate) == NV_OK);
    assert(hybrid580_test_open_rm.free_calls == 2 &&
           hybrid580_test_legacy_rm.free_calls == 0);
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);
    assert(hybrid580_test_kzalloc_calls == 2 &&
           hybrid580_test_kfree_calls == 2);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_legacy_owner_dispatch(void)
{
    NvHandle duplicate = 0;
    UvmGpuMemoryInfo info = {0};

    hybrid580_test_reset();
    hybrid580_test_owner.backend = HYBRID580_BACKEND_LEGACY;
    hybrid580_test_owner.backend_root = UINT32_C(0x41);
    hybrid580_test_owner.backend_memory = UINT32_C(0x42);
    assert(hybrid580_test_duplicate(0x2000, &duplicate, &info) == NV_OK);
    assert(duplicate == UINT32_C(0x222) &&
           info.provider_marker == UINT32_C(0x2000));
    assert(hybrid580_test_open_rm.duplicate_calls == 0 &&
           hybrid580_test_legacy_rm.duplicate_calls == 1);
    assert(hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_owner.quarantine_calls == 0);
    assert(nvUvmInterfaceFreeDupedHandle(
               (uvmGpuDeviceHandle)0x2000, duplicate) == NV_OK);
    assert(hybrid580_test_legacy_rm.free_calls == 1 &&
           hybrid580_test_open_rm.free_calls == 0);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_failures_clear_outputs_and_release_owner(void)
{
    NvHandle duplicate = UINT32_MAX;
    UvmGpuMemoryInfo info = {.size = UINT64_MAX, .flags = UINT32_MAX,
                             .provider_marker = UINT32_MAX};

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 1;
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) ==
           NV_ERR_NO_MEMORY);
    assert(duplicate == 0 && info.size == 0 && info.flags == 0 &&
           info.provider_marker == 0);
    assert(hybrid580_test_owner.pin_calls == 0 &&
           hybrid580_test_open_rm.duplicate_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 2;
    duplicate = UINT32_MAX;
    info.size = UINT64_MAX;
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) ==
           NV_ERR_NO_MEMORY);
    assert(duplicate == 0 && info.size == 0 &&
           hybrid580_test_owner.pin_calls == 0 &&
           hybrid580_test_kfree_calls == 1);

    hybrid580_test_reset();
    hybrid580_test_owner.pin_status = TEST_OWNER_ERROR;
    duplicate = UINT32_MAX;
    info.size = UINT64_MAX;
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) ==
           TEST_OWNER_ERROR);
    assert(duplicate == 0 && info.size == 0 &&
           hybrid580_test_owner.pin_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 0 &&
           hybrid580_test_open_rm.duplicate_calls == 0 &&
           hybrid580_test_kfree_calls == 2);

    hybrid580_test_reset();
    hybrid580_test_owner.backend = UINT32_C(0xff);
    duplicate = UINT32_MAX;
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) ==
           NV_ERR_INVALID_STATE);
    assert(duplicate == 0 && hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_open_rm.duplicate_calls == 0 &&
           hybrid580_test_lock_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_owner.backend = HYBRID580_BACKEND_LEGACY;
    hybrid580_test_owner.backend_root = UINT32_C(0x41);
    hybrid580_test_owner.backend_memory = UINT32_C(0x42);
    duplicate = UINT32_MAX;
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) ==
           NV_ERR_NOT_SUPPORTED);
    assert(duplicate == 0 && hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_open_rm.duplicate_calls == 0 &&
           hybrid580_test_legacy_rm.duplicate_calls == 0);

    hybrid580_test_reset();
    duplicate = UINT32_MAX;
    info.size = UINT64_MAX;
    assert(hybrid580_test_duplicate(0xdead, &duplicate, &info) ==
           NV_ERR_GENERIC);
    assert(duplicate == 0 && info.size == 0 &&
           hybrid580_test_owner.unpin_calls == 1 &&
           hybrid580_test_open_rm.duplicate_calls == 0 &&
           hybrid580_test_legacy_rm.duplicate_calls == 0);

    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_invalid_args_and_optional_info(void)
{
    NvHandle duplicate = UINT32_MAX;
    UvmGpuMemoryInfo info = {.size = UINT64_MAX, .flags = UINT32_MAX,
                             .provider_marker = UINT32_MAX};

    hybrid580_test_reset();
    assert(nvUvmInterfaceDupMemoryWithControlFd(
               9, NULL, UINT32_C(0x11), UINT32_C(0x22), &duplicate,
               &info) == NV_ERR_INVALID_ARGUMENT);
    assert(duplicate == 0 && info.size == 0 && info.flags == 0 &&
           info.provider_marker == 0);
    assert(hybrid580_test_kzalloc_calls == 0 &&
           hybrid580_test_owner.pin_calls == 0);

    hybrid580_test_reset();
    duplicate = UINT32_MAX;
    assert(hybrid580_test_duplicate(0x1000, &duplicate, NULL) == NV_OK);
    assert(duplicate == UINT32_C(0x111));
    assert(hybrid580_test_kzalloc_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 1);
    assert(nvUvmInterfaceFreeDupedHandle(
               (uvmGpuDeviceHandle)0x1000, duplicate) == NV_OK);
    assert(hybrid580_test_kfree_calls == 1);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_ambiguous_rm_output_is_quarantined(void)
{
    NvHandle duplicate = UINT32_MAX;
    UvmGpuMemoryInfo info = {.size = UINT64_MAX, .flags = UINT32_MAX,
                             .provider_marker = UINT32_MAX};

    hybrid580_test_reset();
    hybrid580_test_open_rm.duplicate_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open_rm.duplicate_handle = UINT32_C(0x333);
    assert(hybrid580_test_duplicate(0x1000, &duplicate, &info) ==
           TEST_PROVIDER_ERROR);
    assert(duplicate == 0 && info.size == 0 && info.flags == 0 &&
           info.provider_marker == 0);
    assert(hybrid580_test_open_rm.duplicate_calls == 1 &&
           hybrid580_test_legacy_rm.duplicate_calls == 0);
    assert(hybrid580_test_owner.quarantine_calls == 1 &&
           hybrid580_test_owner.unpin_calls == 0 &&
           hybrid580_test_quarantine_pins == 1);
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);
    assert(hybrid580_test_kzalloc_calls == 2 &&
           hybrid580_test_kfree_calls == 2);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

int main(void)
{
    hybrid580_test_success_and_retryable_free();
    hybrid580_test_legacy_owner_dispatch();
    hybrid580_test_failures_clear_outputs_and_release_owner();
    hybrid580_test_invalid_args_and_optional_info();
    hybrid580_test_ambiguous_rm_output_is_quarantined();
    puts("exact UVM duplicate-memory wrappers, owner pins, provider routing, and retryable free passed");
    return 0;
}
