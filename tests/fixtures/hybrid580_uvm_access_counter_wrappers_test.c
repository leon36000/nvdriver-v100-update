/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hybrid580_uvm_info_registry.h"

typedef uint32_t NV_STATUS;
typedef uint32_t NvU32;
typedef void *uvmGpuDeviceHandle;
typedef struct { unsigned char opaque[32]; } UvmGpuAccessCntrInfo;
typedef struct { unsigned char opaque[24]; } UvmGpuAccessCntrConfig;

#define NV_OK UINT32_C(0)
#define NV_ERR_GENERIC UINT32_C(0x000000ff)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0x0000001f)
#define NV_ERR_INVALID_OBJECT_HANDLE UINT32_C(0x00000046)
#define NV_ERR_INSUFFICIENT_RESOURCES UINT32_C(0x00000055)
#define NV_ERR_NOT_SUPPORTED UINT32_C(0x00000056)
#define NV_ERR_INVALID_STATE UINT32_C(0x00000057)
#define NV_ERR_NO_MEMORY UINT32_C(0x00000058)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_info_registry hybrid580_uvm_infos;
static int hybrid580_uvm_callback_lock;
static int hybrid580_uvm_info_lock;
static unsigned mutex_lock_calls;
static unsigned mutex_unlock_calls;
static unsigned spin_lock_calls;
static unsigned spin_unlock_calls;
static unsigned quarantine_calls;
static unsigned allocation_calls;
static unsigned fail_allocation_on;
static unsigned live_allocations;
static NV_STATUS reentrant_destroy_status;
static int attempt_reentrant_destroy;

static void mutex_lock(int *lock)
{
    assert(lock != NULL && *lock == 0);
    *lock = 1;
    ++mutex_lock_calls;
}

static void mutex_unlock(int *lock)
{
    assert(lock != NULL && *lock == 1);
    *lock = 0;
    ++mutex_unlock_calls;
}

#define spin_lock_irqsave(lock, flags) do { \
    assert((lock) != NULL && *(lock) == 0); \
    *(lock) = 1; \
    (flags) = 0; \
    ++spin_lock_calls; \
} while (0)

#define spin_unlock_irqrestore(lock, flags) do { \
    (void)(flags); \
    assert((lock) != NULL && *(lock) == 1); \
    *(lock) = 0; \
    ++spin_unlock_calls; \
} while (0)

static void *kzalloc(size_t size, unsigned int flags)
{
    void *allocation;
    (void)flags;
    ++allocation_calls;
    if (fail_allocation_on != 0 && allocation_calls == fail_allocation_on)
        return NULL;
    allocation = calloc(1, size);
    if (allocation != NULL)
        ++live_allocations;
    return allocation;
}

static void kfree(void *allocation)
{
    if (allocation != NULL) {
        assert(live_allocations > 0);
        --live_allocations;
        free(allocation);
    }
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++quarantine_calls;
}

struct fake_backend {
    NV_STATUS init_status;
    NV_STATUS destroy_status;
    NV_STATUS enable_status;
    NV_STATUS disable_status;
    unsigned calls[4];
    uintptr_t expected_device;
    UvmGpuAccessCntrInfo *last_info;
    const UvmGpuAccessCntrConfig *last_config;
    NvU32 last_index;
};

static struct fake_backend backends[3];

NV_STATUS nvUvmInterfaceDestroyAccessCntrInfo(
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *info);

static void fake_backend_call(enum hybrid580_uvm_provider provider,
                              unsigned operation)
{
    assert(provider == HYBRID580_UVM_PROVIDER_OPEN ||
           provider == HYBRID580_UVM_PROVIDER_LEGACY);
    assert(hybrid580_uvm_callback_lock == 0);
    assert(hybrid580_uvm_info_lock == 0);
    ++backends[provider].calls[operation];
}

#define DEFINE_FAKE_BACKEND(prefix, provider_id) \
static NV_STATUS prefix##InitAccessCntrInfo( \
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *info, NvU32 index) \
{ \
    fake_backend_call((provider_id), 0); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(info != NULL); \
    backends[(provider_id)].last_info = info; \
    backends[(provider_id)].last_index = index; \
    return backends[(provider_id)].init_status; \
} \
static NV_STATUS prefix##DestroyAccessCntrInfo( \
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *info) \
{ \
    fake_backend_call((provider_id), 1); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(info == backends[(provider_id)].last_info); \
    return backends[(provider_id)].destroy_status; \
} \
static NV_STATUS prefix##EnableAccessCntr( \
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *info, \
    const UvmGpuAccessCntrConfig *config) \
{ \
    fake_backend_call((provider_id), 2); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(info == backends[(provider_id)].last_info && config != NULL); \
    backends[(provider_id)].last_config = config; \
    if (attempt_reentrant_destroy) \
        reentrant_destroy_status = nvUvmInterfaceDestroyAccessCntrInfo( \
            device, info); \
    return backends[(provider_id)].enable_status; \
} \
static NV_STATUS prefix##DisableAccessCntr( \
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *info) \
{ \
    fake_backend_call((provider_id), 3); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(info == backends[(provider_id)].last_info); \
    return backends[(provider_id)].disable_status; \
}

DEFINE_FAKE_BACKEND(hybrid580_open_nvUvmInterface,
                    HYBRID580_UVM_PROVIDER_OPEN)
DEFINE_FAKE_BACKEND(hybrid580_legacy_nvUvmInterface,
                    HYBRID580_UVM_PROVIDER_LEGACY)

/* INSERT_EXACT_ACCESS_COUNTER_OPS_TYPE */

/* INSERT_EXACT_ACCESS_COUNTER_BACKEND_OPS */

/* INSERT_EXACT_ACCESS_COUNTER_HELPERS */

/* INSERT_EXACT_ACCESS_COUNTER_PUBLIC_WRAPPERS */

static void record_device(uintptr_t identity,
                          enum hybrid580_uvm_provider provider)
{
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0};
    uuid[0] = (unsigned char)identity;
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, identity, provider, uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
    backends[provider].expected_device = identity;
}

static struct hybrid580_uvm_info_entry *find_info(uintptr_t identity)
{
    struct hybrid580_uvm_info_entry **link =
        hybrid580_uvm_info_find_link(&hybrid580_uvm_infos, identity);
    return link == NULL ? NULL : *link;
}

static unsigned count_calls(enum hybrid580_uvm_provider provider)
{
    unsigned total = 0;
    size_t i;
    for (i = 0; i < sizeof(backends[provider].calls) /
                        sizeof(backends[provider].calls[0]); ++i)
        total += backends[provider].calls[i];
    return total;
}

static void release_registered_infos(void)
{
    size_t i;
    for (i = 0; i < HYBRID580_UVM_INFO_BUCKET_COUNT; ++i) {
        struct hybrid580_uvm_info_entry *entry =
            hybrid580_uvm_infos.buckets[i];
        while (entry != NULL) {
            struct hybrid580_uvm_info_entry *next = entry->next;
            kfree(entry);
            entry = next;
        }
    }
}

static void reset_fixture(void)
{
    release_registered_infos();
    assert(live_allocations == 0);
    memset(&hybrid580_uvm_devices, 0, sizeof(hybrid580_uvm_devices));
    memset(&hybrid580_uvm_infos, 0, sizeof(hybrid580_uvm_infos));
    memset(backends, 0, sizeof(backends));
    assert(hybrid580_uvm_callback_lock == 0 && hybrid580_uvm_info_lock == 0);
    assert(mutex_lock_calls == mutex_unlock_calls);
    assert(spin_lock_calls == spin_unlock_calls);
    quarantine_calls = 0;
    allocation_calls = 0;
    fail_allocation_on = 0;
    attempt_reentrant_destroy = 0;
    reentrant_destroy_status = NV_ERR_GENERIC;
}

static void test_owner_pins_reentrant_retire_and_quarantine(void)
{
    const uintptr_t open_device = (uintptr_t)0x6606;
    const uintptr_t legacy_device = (uintptr_t)0x7707;
    UvmGpuAccessCntrInfo info = {{0}};
    UvmGpuAccessCntrConfig config = {{0}};
    struct hybrid580_uvm_info_entry *entry;

    reset_fixture();
    record_device(open_device, HYBRID580_UVM_PROVIDER_OPEN);
    record_device(legacy_device, HYBRID580_UVM_PROVIDER_LEGACY);
    assert(nvUvmInterfaceInitAccessCntrInfo(
               (uvmGpuDeviceHandle)open_device, &info, 9) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[0] == 1);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].last_index == 9);
    assert(count_calls(HYBRID580_UVM_PROVIDER_LEGACY) == 0);
    assert(hybrid580_uvm_infos.count == 1 && live_allocations == 1);
    entry = find_info((uintptr_t)&info);
    assert(entry != NULL && entry->kind == HYBRID580_UVM_INFO_ACCESS_COUNTER &&
           entry->provider == HYBRID580_UVM_PROVIDER_OPEN &&
           entry->device_identity == open_device && !entry->retiring &&
           !entry->quarantined && entry->active_calls == 0);

    /* A live callback pin prevents recursive teardown while the RM runs. */
    attempt_reentrant_destroy = 1;
    assert(nvUvmInterfaceEnableAccessCntr(
               (uvmGpuDeviceHandle)open_device, &info, &config) == NV_OK);
    attempt_reentrant_destroy = 0;
    assert(reentrant_destroy_status == NV_ERR_INVALID_STATE);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[2] == 1);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].last_config == &config);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[1] == 0);
    assert(entry->active_calls == 0 && !entry->retiring && !entry->quarantined);

    /* Provider failures propagate, release the active pin, and permit retry. */
    backends[HYBRID580_UVM_PROVIDER_OPEN].enable_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceEnableAccessCntr(
               (uvmGpuDeviceHandle)open_device, &info, &config) ==
           NV_ERR_GENERIC);
    assert(entry->active_calls == 0);
    backends[HYBRID580_UVM_PROVIDER_OPEN].disable_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceDisableAccessCntr(
               (uvmGpuDeviceHandle)open_device, &info) == NV_ERR_GENERIC);
    assert(entry->active_calls == 0 && !entry->quarantined);

    assert(nvUvmInterfaceDestroyAccessCntrInfo(
               (uvmGpuDeviceHandle)legacy_device, &info) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[1] == 0);
    assert(count_calls(HYBRID580_UVM_PROVIDER_LEGACY) == 0);

    backends[HYBRID580_UVM_PROVIDER_OPEN].destroy_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceDestroyAccessCntrInfo(
               (uvmGpuDeviceHandle)open_device, &info) == NV_ERR_GENERIC);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[1] == 1);
    assert(quarantine_calls == 1 && hybrid580_uvm_infos.count == 1);
    assert(entry->quarantined && !entry->retiring);
    assert(nvUvmInterfaceDisableAccessCntr(
               (uvmGpuDeviceHandle)open_device, &info) == NV_ERR_INVALID_STATE);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[3] == 1);
    assert(live_allocations == 1);
}

static void test_init_failure_validation_and_allocation_failure(void)
{
    const uintptr_t legacy_device = (uintptr_t)0x8808;
    const uintptr_t unknown_device = (uintptr_t)0x9909;
    UvmGpuAccessCntrInfo info = {{0}};
    UvmGpuAccessCntrConfig config = {{0}};

    reset_fixture();
    record_device(legacy_device, HYBRID580_UVM_PROVIDER_LEGACY);
    backends[HYBRID580_UVM_PROVIDER_LEGACY].init_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceInitAccessCntrInfo(
               (uvmGpuDeviceHandle)legacy_device, &info, 3) == NV_ERR_GENERIC);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[0] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[1] == 0);

    assert(nvUvmInterfaceInitAccessCntrInfo(
               (uvmGpuDeviceHandle)unknown_device, &info, 3) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(nvUvmInterfaceInitAccessCntrInfo(NULL, &info, 3) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceInitAccessCntrInfo(
               (uvmGpuDeviceHandle)legacy_device, NULL, 3) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceEnableAccessCntr(
               (uvmGpuDeviceHandle)legacy_device, &info, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceDisableAccessCntr(
               (uvmGpuDeviceHandle)legacy_device, NULL) ==
           NV_ERR_INVALID_ARGUMENT);

    backends[HYBRID580_UVM_PROVIDER_LEGACY].init_status = NV_OK;
    assert(nvUvmInterfaceInitAccessCntrInfo(
               (uvmGpuDeviceHandle)legacy_device, &info, 5) == NV_OK);
    assert(nvUvmInterfaceEnableAccessCntr(
               (uvmGpuDeviceHandle)legacy_device, &info, &config) == NV_OK);
    assert(nvUvmInterfaceDisableAccessCntr(
               (uvmGpuDeviceHandle)legacy_device, &info) == NV_OK);
    assert(nvUvmInterfaceDestroyAccessCntrInfo(
               (uvmGpuDeviceHandle)legacy_device, &info) == NV_OK);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[0] == 2 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[1] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[2] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[3] == 1);

    fail_allocation_on = allocation_calls + 1;
    assert(nvUvmInterfaceInitAccessCntrInfo(
               (uvmGpuDeviceHandle)legacy_device, &info, 3) == NV_ERR_NO_MEMORY);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[0] == 2);
}

int main(void)
{
    test_owner_pins_reentrant_retire_and_quarantine();
    test_init_failure_validation_and_allocation_failure();
    assert(hybrid580_uvm_callback_lock == 0 && hybrid580_uvm_info_lock == 0);
    assert(mutex_lock_calls == mutex_unlock_calls);
    assert(spin_lock_calls == spin_unlock_calls);
    puts("exact UVM access-counter owner and lifetime wrappers passed");
    return 0;
}
