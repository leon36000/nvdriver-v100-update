/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/hybrid580_uvm_device_route.h"
#include "src/hybrid580_uvm_session_pair.h"

typedef uint32_t NV_STATUS;
typedef uint32_t NvBool;
typedef void *uvmGpuSessionHandle;
typedef void *uvmGpuDeviceHandle;

typedef struct {
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES];
} NvProcessorUuid;

typedef struct {
    uint32_t marker;
} UvmGpuInfo;

#define NV_OK                       UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT    UINT32_C(0xe0012001)
#define NV_ERR_GPU_UUID_NOT_FOUND  UINT32_C(0xe0012002)
#define NV_ERR_NO_MEMORY           UINT32_C(0xe0012003)
#define NV_ERR_NOT_SUPPORTED       UINT32_C(0xe0012004)
#define NV_ERR_GENERIC             UINT32_C(0xe0012005)
#define TEST_PROVIDER_ERROR        UINT32_C(0xe0012006)
#define NV_FALSE                   UINT32_C(0)
#define NV_TRUE                    UINT32_C(1)

struct fake_session_backend {
    uintptr_t handle;
    unsigned create_calls;
    unsigned destroy_calls;
};

struct fake_rm_backend {
    NV_STATUS create_status;
    uintptr_t created_handle;
    uintptr_t expected_session;
    const UvmGpuInfo *expected_gpu_info;
    unsigned char expected_uuid[HYBRID580_UVM_GPU_UUID_BYTES];
    unsigned create_calls;
    unsigned destroy_calls;
    uintptr_t last_destroyed;
    unsigned char last_uuid[HYBRID580_UVM_GPU_UUID_BYTES];
};

static struct hybrid580_uvm_session_pair hybrid580_uvm_sessions;
static struct hybrid580_uvm_gpu_registry hybrid580_uvm_gpu_registry;
static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static int hybrid580_uvm_callback_lock;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_quarantine_pins;
static struct fake_rm_backend hybrid580_test_open_rm;
static struct fake_rm_backend hybrid580_test_legacy_rm;

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
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

static enum hybrid580_uvm_destroy_result fake_session_destroy(
    void *context, uintptr_t handle)
{
    struct fake_session_backend *backend = context;
    assert(handle == backend->handle);
    ++backend->destroy_calls;
    return HYBRID580_UVM_DESTROYED;
}

static int fake_session_create(void *context, uintptr_t *handle)
{
    struct fake_session_backend *backend = context;
    ++backend->create_calls;
    *handle = backend->handle;
    return 0;
}

static NV_STATUS fake_rm_device_create(struct fake_rm_backend *backend,
    uvmGpuSessionHandle session, const UvmGpuInfo *gpu_info,
    const NvProcessorUuid *gpu_uuid, NvBool create_smc_partition,
    uvmGpuDeviceHandle *device)
{
    assert(device != NULL && gpu_uuid != NULL);
    *device = NULL;
    ++backend->create_calls;
    assert((uintptr_t)session == backend->expected_session);
    assert(gpu_info == backend->expected_gpu_info);
    assert(create_smc_partition == NV_FALSE);
    assert(memcmp(gpu_uuid->uuid, backend->expected_uuid,
                  sizeof(backend->expected_uuid)) == 0);
    memcpy(backend->last_uuid, gpu_uuid->uuid, sizeof(backend->last_uuid));
    if (backend->create_status == NV_OK)
        *device = (uvmGpuDeviceHandle)backend->created_handle;
    return backend->create_status;
}

static void fake_rm_device_destroy(struct fake_rm_backend *backend,
                                   uvmGpuDeviceHandle device)
{
    ++backend->destroy_calls;
    backend->last_destroyed = (uintptr_t)device;
}

static NV_STATUS hybrid580_open_nvUvmInterfaceDeviceCreate(
    uvmGpuSessionHandle session, const UvmGpuInfo *gpu_info,
    const NvProcessorUuid *gpu_uuid, uvmGpuDeviceHandle *device,
    NvBool create_smc_partition)
{
    return fake_rm_device_create(&hybrid580_test_open_rm, session, gpu_info,
                                 gpu_uuid, create_smc_partition, device);
}

static NV_STATUS hybrid580_legacy_nvUvmInterfaceDeviceCreate(
    uvmGpuSessionHandle session, const UvmGpuInfo *gpu_info,
    const NvProcessorUuid *gpu_uuid, uvmGpuDeviceHandle *device,
    NvBool create_smc_partition)
{
    return fake_rm_device_create(&hybrid580_test_legacy_rm, session, gpu_info,
                                 gpu_uuid, create_smc_partition, device);
}

static void hybrid580_open_nvUvmInterfaceDeviceDestroy(uvmGpuDeviceHandle device)
{
    fake_rm_device_destroy(&hybrid580_test_open_rm, device);
}

static void hybrid580_legacy_nvUvmInterfaceDeviceDestroy(uvmGpuDeviceHandle device)
{
    fake_rm_device_destroy(&hybrid580_test_legacy_rm, device);
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_DEVICE_ADAPTERS */
/* INSERT_EXACT_PUBLIC_DEVICE_CREATE */

static void test_public_device_create_wrapper(void)
{
    struct fake_session_backend open_session = {.handle = 0x2000};
    struct fake_session_backend legacy_session = {.handle = 0x4000};
    struct hybrid580_uvm_provider_ops open_session_ops = {
        .context = &open_session,
        .create = fake_session_create,
        .destroy = fake_session_destroy,
    };
    struct hybrid580_uvm_provider_ops legacy_session_ops = {
        .context = &legacy_session,
        .create = fake_session_create,
        .destroy = fake_session_destroy,
    };
    NvProcessorUuid open_uuid = {.uuid = {0x18}};
    NvProcessorUuid legacy_uuid = {.uuid = {0x70}};
    NvProcessorUuid unknown_uuid = {.uuid = {0x99}};
    UvmGpuInfo open_info = {.marker = 0x1234};
    UvmGpuInfo legacy_info = {.marker = 0x5678};
    uvmGpuDeviceHandle device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    enum hybrid580_uvm_provider owner = 0;
    uintptr_t native_handle = 0;
    unsigned open_create_calls;
    unsigned legacy_create_calls;

    memset(&hybrid580_uvm_sessions, 0, sizeof(hybrid580_uvm_sessions));
    memset(&hybrid580_uvm_gpu_registry, 0, sizeof(hybrid580_uvm_gpu_registry));
    memset(&hybrid580_uvm_devices, 0, sizeof(hybrid580_uvm_devices));
    memset(&hybrid580_test_open_rm, 0, sizeof(hybrid580_test_open_rm));
    memset(&hybrid580_test_legacy_rm, 0, sizeof(hybrid580_test_legacy_rm));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_quarantine_pins = 0;

    assert(hybrid580_uvm_session_pair_create(
               &hybrid580_uvm_sessions, open_session_ops,
               legacy_session_ops) == HYBRID580_UVM_SESSION_OK);
    assert(open_session.create_calls == 1 && legacy_session.create_calls == 1);
    hybrid580_test_open_rm.expected_session = open_session.handle;
    hybrid580_test_open_rm.expected_gpu_info = &open_info;
    memcpy(hybrid580_test_open_rm.expected_uuid, open_uuid.uuid,
           sizeof(open_uuid.uuid));
    hybrid580_test_open_rm.created_handle = 0x1000;
    hybrid580_test_open_rm.create_status = NV_OK;
    hybrid580_test_legacy_rm.expected_session = legacy_session.handle;
    hybrid580_test_legacy_rm.expected_gpu_info = &legacy_info;
    memcpy(hybrid580_test_legacy_rm.expected_uuid, legacy_uuid.uuid,
           sizeof(legacy_uuid.uuid));
    hybrid580_test_legacy_rm.created_handle = 0x3000;
    hybrid580_test_legacy_rm.create_status = NV_OK;
    assert(hybrid580_uvm_gpu_registry_record_success(
               &hybrid580_uvm_gpu_registry, open_uuid.uuid,
               HYBRID580_UVM_PROVIDER_OPEN) == HYBRID580_UVM_GPU_REGISTRY_OK);
    assert(hybrid580_uvm_gpu_registry_record_success(
               &hybrid580_uvm_gpu_registry, legacy_uuid.uuid,
               HYBRID580_UVM_PROVIDER_LEGACY) == HYBRID580_UVM_GPU_REGISTRY_OK);

    /* Public argument checks clear the output without taking the lock. */
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &open_info,
               &open_uuid, NULL, NV_FALSE) == NV_ERR_INVALID_ARGUMENT);
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, NULL,
               &open_uuid, &device, NV_FALSE) == NV_ERR_INVALID_ARGUMENT);
    assert(device == NULL && hybrid580_test_lock_calls == 0);
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &open_info,
               NULL, &device, NV_FALSE) == NV_ERR_INVALID_ARGUMENT);
    assert(device == NULL && hybrid580_test_lock_calls == 0);

    /* Each registered UUID uses only its owning native session and RM. */
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &open_info,
               &open_uuid, &device, NV_FALSE) == NV_OK);
    assert((uintptr_t)device == hybrid580_test_open_rm.created_handle);
    assert(hybrid580_test_open_rm.create_calls == 1 &&
           hybrid580_test_legacy_rm.create_calls == 0);
    assert(memcmp(hybrid580_test_open_rm.last_uuid, open_uuid.uuid,
                  sizeof(open_uuid.uuid)) == 0);
    assert(hybrid580_uvm_device_registry_lookup(
               &hybrid580_uvm_devices, (uintptr_t)device, &owner,
               &native_handle) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(owner == HYBRID580_UVM_PROVIDER_OPEN && native_handle == (uintptr_t)device);

    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &legacy_info,
               &legacy_uuid, &device, NV_FALSE) == NV_OK);
    assert((uintptr_t)device == hybrid580_test_legacy_rm.created_handle);
    assert(hybrid580_test_open_rm.create_calls == 1 &&
           hybrid580_test_legacy_rm.create_calls == 1);
    assert(hybrid580_uvm_device_registry_lookup(
               &hybrid580_uvm_devices, (uintptr_t)device, &owner,
               &native_handle) == HYBRID580_UVM_DEVICE_REGISTRY_OK);
    assert(owner == HYBRID580_UVM_PROVIDER_LEGACY && native_handle == (uintptr_t)device);

    /* Bad sessions, unknown UUIDs, and SMC requests never reach either RM. */
    open_create_calls = hybrid580_test_open_rm.create_calls;
    legacy_create_calls = hybrid580_test_legacy_rm.create_calls;
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(NULL, &open_info, &open_uuid, &device,
                                      NV_FALSE) == NV_ERR_INVALID_ARGUMENT);
    assert(device == NULL);
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate((uvmGpuSessionHandle)0xdead, &open_info,
               &open_uuid, &device, NV_FALSE) == NV_ERR_INVALID_ARGUMENT);
    assert(device == NULL);
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &open_info,
               &unknown_uuid, &device, NV_FALSE) == NV_ERR_GPU_UUID_NOT_FOUND);
    assert(device == NULL);
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &open_info,
               &open_uuid, &device, NV_TRUE) == NV_ERR_NOT_SUPPORTED);
    assert(device == NULL);
    assert(hybrid580_test_open_rm.create_calls == open_create_calls &&
           hybrid580_test_legacy_rm.create_calls == legacy_create_calls);

    /* An owner failure is returned directly without retrying the other RM. */
    hybrid580_test_legacy_rm.create_status = TEST_PROVIDER_ERROR;
    hybrid580_test_legacy_rm.created_handle = 0;
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &legacy_info,
               &legacy_uuid, &device, NV_FALSE) == TEST_PROVIDER_ERROR);
    assert(device == NULL && hybrid580_test_open_rm.create_calls == open_create_calls);
    assert(hybrid580_test_legacy_rm.create_calls == legacy_create_calls + 1);

    /* A duplicate native identity is ambiguous: clear output and pin state. */
    hybrid580_test_legacy_rm.create_status = NV_OK;
    hybrid580_test_legacy_rm.created_handle = hybrid580_test_open_rm.created_handle;
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &legacy_info,
               &legacy_uuid, &device, NV_FALSE) == NV_ERR_GENERIC);
    assert(device == NULL && hybrid580_test_quarantine_pins == 1);
    assert(hybrid580_test_legacy_rm.destroy_calls == 0);
    assert(hybrid580_uvm_device_registry_count(&hybrid580_uvm_devices) == 2);

    /* A session pair torn down through its own lifecycle is no longer usable. */
    assert(hybrid580_uvm_session_pair_destroy(&hybrid580_uvm_sessions) ==
           HYBRID580_UVM_SESSION_OK);
    assert(open_session.destroy_calls == 1 && legacy_session.destroy_calls == 1);
    device = (uvmGpuDeviceHandle)UINTPTR_MAX;
    assert(nvUvmInterfaceDeviceCreate(
               (uvmGpuSessionHandle)&hybrid580_uvm_sessions, &open_info,
               &open_uuid, &device, NV_FALSE) == NV_ERR_INVALID_ARGUMENT);
    assert(device == NULL && hybrid580_test_open_rm.create_calls == open_create_calls &&
           hybrid580_test_legacy_rm.create_calls == legacy_create_calls + 2);

    assert(hybrid580_test_lock_depth == 0);
    assert(hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

int main(void)
{
    test_public_device_create_wrapper();
    puts("exact public DeviceCreate wrapper, production adapters, and UUID owner route passed");
    return 0;
}
