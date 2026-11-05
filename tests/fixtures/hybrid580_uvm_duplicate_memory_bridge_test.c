/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t NvU32;
typedef uint32_t NvHandle;
typedef uint32_t NV_STATUS;
typedef void *uvmGpuDeviceHandle;

#include "hybrid580_frontend_uvm_memory_owner.h"
#include "hybrid580_uvm_dup_memory_route.h"

typedef struct UvmGpuMemoryInfo {
    uint64_t size;
    uint32_t provider_marker;
} UvmGpuMemoryInfo;

#define NV_OK UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0012200)
#define NV_ERR_NO_MEMORY UINT32_C(0xe0012201)
#define NV_ERR_GENERIC UINT32_C(0xe0012202)
#define NV_ERR_NOT_SUPPORTED UINT32_C(0xe0012204)
#define NV_ERR_INVALID_STATE UINT32_C(0xe0012205)
#define GFP_KERNEL 0
#define HYBRID580_BACKEND_LEGACY 0U
#define HYBRID580_BACKEND_OPEN 1U
#define pr_emerg(...) ((void)0)

static unsigned int allocation_calls;
static unsigned int allocation_successes;
static unsigned int allocation_frees;
static unsigned int fail_allocation_call;
static unsigned int pin_calls;
static unsigned int unpin_calls[2];
static unsigned int quarantine_calls[2];
static unsigned int pinned_state_calls;
static unsigned int mutex_depth;
static unsigned char owner_tokens[2];
static struct hybrid580_frontend_memory_owner next_owner;
static NV_STATUS next_pin_status = NV_OK;

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static int hybrid580_uvm_callback_lock;

struct fake_duplicate_backend {
    enum hybrid580_uvm_provider provider;
    uintptr_t expected_device;
    uint32_t expected_client;
    uint32_t expected_memory;
    uintptr_t output_handle;
    uint32_t status;
    uint32_t marker;
    unsigned int calls;
    unsigned int releases;
};

static struct fake_duplicate_backend open_backend = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .expected_device = 0x3000,
    .expected_client = 0x911,
    .expected_memory = 0x955,
    .output_handle = 0xa001,
    .marker = 0xa1,
};
static struct fake_duplicate_backend legacy_backend = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .expected_device = 0x4000,
    .expected_client = 0x811,
    .expected_memory = 0x855,
    .output_handle = 0xa002,
    .marker = 0xb2,
};

static void *kzalloc(size_t size, int flags)
{
    (void)flags;
    ++allocation_calls;
    if (allocation_calls == fail_allocation_call)
        return NULL;
    void *pointer = calloc(1, size);
    if (pointer != NULL)
        ++allocation_successes;
    return pointer;
}

static void kfree(void *pointer)
{
    if (pointer != NULL) {
        ++allocation_frees;
        free(pointer);
    }
}

static void mutex_lock(int *lock)
{
    assert(lock == &hybrid580_uvm_callback_lock);
    assert(mutex_depth == 0);
    ++mutex_depth;
}

static void mutex_unlock(int *lock)
{
    assert(lock == &hybrid580_uvm_callback_lock);
    assert(mutex_depth == 1);
    --mutex_depth;
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++pinned_state_calls;
}

NvU32 hybrid580_frontend_uvm_memory_owner_pin_v1(
    int rm_control_fd, NvHandle public_client, NvHandle public_memory,
    struct hybrid580_frontend_memory_owner *owner)
{
    assert(owner != NULL);
    ++pin_calls;
    if (next_pin_status != NV_OK)
        return next_pin_status;
    assert(public_client == 0x110 && public_memory == 0x120);
    if (rm_control_fd == 50) {
        next_owner = (struct hybrid580_frontend_memory_owner) {
            .backend = HYBRID580_BACKEND_LEGACY,
            .backend_root = 0x811,
            .backend_memory = 0x855,
            .pin = (void *)&owner_tokens[0],
        };
    } else if (rm_control_fd == 51) {
        next_owner = (struct hybrid580_frontend_memory_owner) {
            .backend = HYBRID580_BACKEND_OPEN,
            .backend_root = 0x911,
            .backend_memory = 0x955,
            .pin = (void *)&owner_tokens[1],
        };
    } else {
        return UINT32_C(0xe0012206);
    }
    *owner = next_owner;
    return NV_OK;
}

void hybrid580_frontend_uvm_memory_owner_unpin_v1(
    struct hybrid580_frontend_memory_owner *owner)
{
    assert(owner != NULL && owner->pin != NULL);
    if (owner->pin == (void *)&owner_tokens[0])
        ++unpin_calls[0];
    else if (owner->pin == (void *)&owner_tokens[1])
        ++unpin_calls[1];
    else
        assert(!"unexpected owner pin token");
    memset(owner, 0, sizeof(*owner));
}

void hybrid580_frontend_uvm_memory_owner_quarantine_v1(
    struct hybrid580_frontend_memory_owner *owner)
{
    assert(owner != NULL && owner->pin != NULL);
    if (owner->pin == (void *)&owner_tokens[0])
        ++quarantine_calls[0];
    else if (owner->pin == (void *)&owner_tokens[1])
        ++quarantine_calls[1];
    else
        assert(!"unexpected quarantined pin token");
    memset(owner, 0, sizeof(*owner));
}

static uint32_t fake_duplicate(void *context, uintptr_t device,
                               uint32_t client, uint32_t memory,
                               uintptr_t *duplicate_handle, void *memory_info)
{
    struct fake_duplicate_backend *backend = context;
    assert(backend != NULL && duplicate_handle != NULL);
    assert(backend->provider != 0 && device == backend->expected_device);
    assert(client == backend->expected_client);
    assert(memory == backend->expected_memory);
    ++backend->calls;
    *duplicate_handle = backend->output_handle;
    if (memory_info != NULL && backend->status == NV_OK) {
        struct UvmGpuMemoryInfo *info = memory_info;
        info->size = UINT64_C(0x100000) + backend->marker;
        info->provider_marker = backend->marker;
    }
    return backend->status;
}

static uint32_t fake_release(void *context, uintptr_t device,
                             uintptr_t duplicate_handle)
{
    struct fake_duplicate_backend *backend = context;
    assert(device == backend->expected_device);
    assert(duplicate_handle == backend->output_handle);
    ++backend->releases;
    return NV_OK;
}

static const struct hybrid580_uvm_dup_memory_backend_ops
hybrid580_open_dup_memory_ops = {
    .context = &open_backend,
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .duplicate = fake_duplicate,
    .release = fake_release,
};
static const struct hybrid580_uvm_dup_memory_backend_ops
hybrid580_legacy_dup_memory_ops = {
    .context = &legacy_backend,
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .duplicate = fake_duplicate,
    .release = fake_release,
};

/* INSERT_EXACT_PRODUCTION_WRAPPER */

/* INSERT_EXACT_PRODUCTION_FREE_WRAPPER */

struct fake_user_rm_memory {
    int rm_control_fd;
    NvHandle user_client;
    NvHandle user_object;
};

struct fake_mapping_gpu {
    uintptr_t device;
};

struct fake_external_mem_handle {
    struct fake_mapping_gpu *gpu;
    NvHandle rm_handle;
};

struct fake_external_gpu_map {
    struct fake_external_mem_handle *mem_handle;
};

static NV_STATUS uvm_rm_locked_call(NV_STATUS status)
{
    return status;
}

static uvmGpuDeviceHandle uvm_gpu_device_handle(struct fake_mapping_gpu *gpu)
{
    assert(gpu != NULL);
    return (uvmGpuDeviceHandle)gpu->device;
}

static NV_STATUS invoke_r595_external_map_duplicate(
    int rm_control_fd, uintptr_t device, NvHandle client, NvHandle memory,
    NvHandle *duplicate, struct UvmGpuMemoryInfo *memory_info)
{
    struct fake_user_rm_memory user_memory = {
        .rm_control_fd = rm_control_fd,
        .user_client = client,
        .user_object = memory,
    };
    struct fake_mapping_gpu map_gpu_value = {.device = device};
    struct fake_external_mem_handle memory_handle = {
        .gpu = &map_gpu_value,
        .rm_handle = UINT32_C(0xdeadbeef),
    };
    struct fake_external_gpu_map external_gpu_map_value = {
        .mem_handle = &memory_handle,
    };
    struct fake_user_rm_memory *user_rm_mem = &user_memory;
    struct fake_mapping_gpu *mapping_gpu = &map_gpu_value;
    struct fake_external_gpu_map *ext_gpu_map = &external_gpu_map_value;
    struct UvmGpuMemoryInfo mem_info = {
        .size = UINT64_C(0xdeadbeef),
        .provider_marker = UINT32_C(0xdeadbeef),
    };
    NV_STATUS status;

    if (duplicate == NULL || memory_info == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *duplicate = UINT32_C(0xdeadbeef);
    *memory_info = (struct UvmGpuMemoryInfo){
        UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};

    /* INSERT_EXACT_R595_EXTERNAL_MAP_CALL */

    *duplicate = ext_gpu_map->mem_handle->rm_handle;
    *memory_info = mem_info;
    return status;
}

static NV_STATUS invoke_r595_release_rm_handle(uintptr_t device,
                                                NvHandle duplicate)
{
    struct fake_mapping_gpu map_gpu_value = {.device = device};
    struct fake_external_mem_handle memory_handle = {
        .gpu = &map_gpu_value,
        .rm_handle = duplicate,
    };
    struct fake_external_mem_handle *mem_handle = &memory_handle;
    NV_STATUS status;

    /* INSERT_EXACT_R595_FREE_DUPED_HANDLE_CALL */

    assert(status == NV_OK);
    return status;
}

static void cleanup_duplicate(uintptr_t public_device, uintptr_t public_handle)
{
    assert(nvUvmInterfaceFreeDupedHandle(
        (uvmGpuDeviceHandle)public_device, (NvHandle)public_handle) == NV_OK);
}

int main(void)
{
    unsigned char open_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x31};
    unsigned char legacy_uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0x42};
    NvHandle duplicated = UINT32_C(0xdeadbeef);
    struct UvmGpuMemoryInfo info = {UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    uint32_t calls_before;

    assert(hybrid580_uvm_device_registry_record(
        &hybrid580_uvm_devices, 0x3000, HYBRID580_UVM_PROVIDER_OPEN,
        open_uuid) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(hybrid580_uvm_device_registry_record(
        &hybrid580_uvm_devices, 0x4000, HYBRID580_UVM_PROVIDER_LEGACY,
        legacy_uuid) == HYBRID580_UVM_DEVICE_REGISTRY_OK);

    /* Both allocation failures return before owner pinning and keep outputs zero. */
    fail_allocation_call = allocation_calls + 1;
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        51, (uvmGpuDeviceHandle)(uintptr_t)0x3000, 0x110, 0x120,
        &duplicated, &info) == NV_ERR_NO_MEMORY);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0 &&
           pin_calls == 0 && allocation_successes == allocation_frees);
    fail_allocation_call = allocation_calls + 2;
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        51, (uvmGpuDeviceHandle)(uintptr_t)0x3000, 0x110, 0x120,
        &duplicated, &info) == NV_ERR_NO_MEMORY);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0 &&
           pin_calls == 0 && allocation_successes == allocation_frees);
    fail_allocation_call = 0;

    /* Public source handles collide across frontend files; FD 51 selects OPEN. */
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        51, (uvmGpuDeviceHandle)(uintptr_t)0x3000, 0x110, 0x120,
        &duplicated, &info) == NV_OK);
    assert(duplicated == 0xa001 && info.provider_marker == 0xa1 &&
           info.size == UINT64_C(0x1000a1));
    assert(open_backend.calls == 1 && legacy_backend.calls == 0);
    assert(unpin_calls[1] == 1 && quarantine_calls[1] == 0 && mutex_depth == 0);
    cleanup_duplicate(0x3000, duplicated);
    duplicated = 0;
    memset(&info, 0, sizeof(info));

    /* FD 50 selects LEGACY even though the public handles match the OPEN file. */
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        50, (uvmGpuDeviceHandle)(uintptr_t)0x4000, 0x110, 0x120,
        &duplicated, &info) == NV_OK);
    assert(duplicated == 0xa002 && info.provider_marker == 0xb2 &&
           info.size == UINT64_C(0x1000b2));
    assert(open_backend.calls == 1 && legacy_backend.calls == 1);
    assert(unpin_calls[0] == 1 && mutex_depth == 0);
    cleanup_duplicate(0x4000, duplicated);

    /* Cross-provider mismatch is rejected before either RM callback. */
    calls_before = open_backend.calls + legacy_backend.calls;
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        50, (uvmGpuDeviceHandle)(uintptr_t)0x3000, 0x110, 0x120,
        &duplicated, &info) ==
        NV_ERR_NOT_SUPPORTED);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0);
    assert(open_backend.calls + legacy_backend.calls == calls_before);
    assert(unpin_calls[0] == 2 && quarantine_calls[0] == 0 && mutex_depth == 0);

    /* A provider error with a partial native handle retains the source pin. */
    open_backend.status = UINT32_C(0xe0013300);
    open_backend.output_handle = 0xa003;
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        51, (uvmGpuDeviceHandle)(uintptr_t)0x3000, 0x110, 0x120,
        &duplicated, &info) ==
        open_backend.status);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0);
    assert(open_backend.calls == 2 && legacy_backend.calls == 1);
    assert(unpin_calls[1] == 1 && quarantine_calls[1] == 1 &&
           pinned_state_calls == 1 && mutex_depth == 0);
    open_backend.status = NV_OK;
    open_backend.output_handle = 0xa001;

    /* Invalid owner acquisition remains fail-closed and leaves outputs zero. */
    next_pin_status = UINT32_C(0xe0014400);
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(nvUvmInterfaceDupMemoryWithControlFd(
        99, (uvmGpuDeviceHandle)(uintptr_t)0x3000, 0x110, 0x120,
        &duplicated, &info) ==
        next_pin_status);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0);
    assert(open_backend.calls == 2 && legacy_backend.calls == 1 &&
           pin_calls == 5 && mutex_depth == 0);
    next_pin_status = NV_OK;

    assert(hybrid580_uvm_typed_child_registry_count(
        &hybrid580_uvm_typed_children) == 0);

    /* Compose the exact R595 external-map callsite with the production
     * FD-aware bridge. Identical public source handles route by their control
     * FD, while a mismatched destination provider is rejected before RM. */
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(invoke_r595_external_map_duplicate(
        51, 0x3000, 0x110, 0x120, &duplicated, &info) == NV_OK);
    assert(duplicated == 0xa001 && info.provider_marker == 0xa1 &&
           info.size == UINT64_C(0x1000a1));
    assert(open_backend.calls == 3 && legacy_backend.calls == 1);
    /* A later map-setup error frees the duplicate through R595's exact
     * release callback; the hybrid wrapper must route it to the same owner. */
    assert(invoke_r595_release_rm_handle(0x3000, duplicated) == NV_OK);
    assert(open_backend.releases == 2 && legacy_backend.releases == 1);
    assert(hybrid580_uvm_typed_child_registry_count(
        &hybrid580_uvm_typed_children) == 0);

    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(invoke_r595_external_map_duplicate(
        50, 0x4000, 0x110, 0x120, &duplicated, &info) == NV_OK);
    assert(duplicated == 0xa002 && info.provider_marker == 0xb2 &&
           info.size == UINT64_C(0x1000b2));
    assert(open_backend.calls == 3 && legacy_backend.calls == 2);
    cleanup_duplicate(0x4000, duplicated);

    calls_before = open_backend.calls + legacy_backend.calls;
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(invoke_r595_external_map_duplicate(
        50, 0x3000, 0x110, 0x120, &duplicated, &info) ==
        NV_ERR_NOT_SUPPORTED);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0);
    assert(open_backend.calls + legacy_backend.calls == calls_before);
    assert(unpin_calls[0] == 4 && quarantine_calls[0] == 0 && mutex_depth == 0);
    assert(hybrid580_uvm_typed_child_registry_count(
        &hybrid580_uvm_typed_children) == 0);

    /* The patched UVM path must also quarantine partial RM state on error and
     * leave no handle or metadata for UVM to publish. */
    open_backend.status = UINT32_C(0xe0013300);
    open_backend.output_handle = 0xa004;
    duplicated = UINT32_C(0xdeadbeef);
    info = (struct UvmGpuMemoryInfo){UINT64_C(0xdeadbeef), UINT32_C(0xdeadbeef)};
    assert(invoke_r595_external_map_duplicate(
        51, 0x3000, 0x110, 0x120, &duplicated, &info) == open_backend.status);
    assert(duplicated == 0 && info.size == 0 && info.provider_marker == 0);
    assert(open_backend.calls == 4 && legacy_backend.calls == 2);
    assert(unpin_calls[1] == 2 && quarantine_calls[1] == 2 &&
           pinned_state_calls == 2 && mutex_depth == 0);
    assert(hybrid580_uvm_typed_child_registry_count(
        &hybrid580_uvm_typed_children) == 0);
    open_backend.status = NV_OK;
    open_backend.output_handle = 0xa001;
    assert(allocation_successes == allocation_frees);
    puts("R595 external-map duplicate/free composition passed");
    return 0;
}
