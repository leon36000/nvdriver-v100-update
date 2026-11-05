/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvBool;
typedef uint32_t NvHandle;
typedef void *uvmGpuAddressSpaceHandle;
typedef struct {
    uint32_t resourceCount;
    uint32_t marker;
} UvmGpuChannelInstanceInfo;
typedef struct {
    uint32_t marker;
} UvmGpuChannelResourceBindParams;

#define HYBRID580_UVM_ABI_R580 1
#define UVM_GPU_CHANNEL_MAX_RESOURCES 4U
#define NV_OK                    UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0013701)
#define NV_ERR_NO_MEMORY        UINT32_C(0xe0013702)
#define NV_ERR_GENERIC          UINT32_C(0xe0013703)
#define TEST_PROVIDER_ERROR     UINT32_C(0xe0013704)
#define NV_FALSE                UINT32_C(0)
#define NV_TRUE                 UINT32_C(1)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_address_space_route.h"
#include "src/hybrid580_uvm_typed_child_route.h"

struct fake_backend {
    uintptr_t expected_space;
    NvHandle expected_client;
    NvHandle expected_channel;
    uintptr_t result_channel;
    UvmGpuChannelInstanceInfo result_info;
    UvmGpuChannelResourceBindParams *expected_bind_params;
    NV_STATUS retain_status;
    NV_STATUS bind_status;
    unsigned retain_calls;
    unsigned bind_calls;
    unsigned release_calls;
    unsigned stop_calls;
    uintptr_t last_released;
    uintptr_t last_bound;
    uintptr_t last_stopped;
    NvBool last_immediate;
};

static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_space;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_space;
static int hybrid580_uvm_callback_lock;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
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
    if (hybrid580_test_kzalloc_calls == hybrid580_test_fail_kzalloc_at)
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

static NV_STATUS hybrid580_test_retain(
    struct fake_backend *backend, uvmGpuAddressSpaceHandle va_space,
    NvHandle client, NvHandle channel, void **retained_channel,
    UvmGpuChannelInstanceInfo *channel_info)
{
    assert((uintptr_t)va_space == backend->expected_space);
    assert(client == backend->expected_client);
    assert(channel == backend->expected_channel);
    assert(retained_channel != NULL && channel_info != NULL);
    ++backend->retain_calls;
    *retained_channel = (void *)backend->result_channel;
    *channel_info = backend->result_info;
    return backend->retain_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceRetainChannel(
    uvmGpuAddressSpaceHandle va_space, NvHandle client, NvHandle channel,
    void **retained_channel, UvmGpuChannelInstanceInfo *channel_info)
{
    return hybrid580_test_retain(&hybrid580_test_open, va_space, client,
                                 channel, retained_channel, channel_info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceRetainChannel(
    uvmGpuAddressSpaceHandle va_space, NvHandle client, NvHandle channel,
    void **retained_channel, UvmGpuChannelInstanceInfo *channel_info)
{
    return hybrid580_test_retain(&hybrid580_test_legacy, va_space, client,
                                 channel, retained_channel, channel_info);
}

static NV_STATUS hybrid580_test_bind(
    struct fake_backend *backend, void *retained_channel,
    UvmGpuChannelResourceBindParams *bind_params)
{
    assert((uintptr_t)retained_channel == backend->result_channel);
    assert(bind_params == backend->expected_bind_params);
    ++backend->bind_calls;
    backend->last_bound = (uintptr_t)retained_channel;
    return backend->bind_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceBindChannelResources(
    void *retained_channel,
    UvmGpuChannelResourceBindParams *bind_params)
{
    return hybrid580_test_bind(&hybrid580_test_open, retained_channel,
                               bind_params);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceBindChannelResources(
    void *retained_channel,
    UvmGpuChannelResourceBindParams *bind_params)
{
    return hybrid580_test_bind(&hybrid580_test_legacy, retained_channel,
                               bind_params);
}

static void hybrid580_test_release(struct fake_backend *backend,
                                   void *retained_channel)
{
    assert((uintptr_t)retained_channel == backend->result_channel);
    ++backend->release_calls;
    backend->last_released = (uintptr_t)retained_channel;
}

void hybrid580_open_nvUvmInterfaceReleaseChannel(void *retained_channel)
{
    hybrid580_test_release(&hybrid580_test_open, retained_channel);
}

void hybrid580_legacy_nvUvmInterfaceReleaseChannel(void *retained_channel)
{
    hybrid580_test_release(&hybrid580_test_legacy, retained_channel);
}

static void hybrid580_test_stop(struct fake_backend *backend,
                                void *retained_channel, NvBool immediate)
{
    assert((uintptr_t)retained_channel == backend->result_channel);
    assert(immediate == NV_TRUE || immediate == NV_FALSE);
    ++backend->stop_calls;
    backend->last_stopped = (uintptr_t)retained_channel;
    backend->last_immediate = immediate;
}

void hybrid580_open_nvUvmInterfaceStopChannel(void *retained_channel,
                                               NvBool immediate)
{
    hybrid580_test_stop(&hybrid580_test_open, retained_channel, immediate);
}

void hybrid580_legacy_nvUvmInterfaceStopChannel(void *retained_channel,
                                                  NvBool immediate)
{
    hybrid580_test_stop(&hybrid580_test_legacy, retained_channel, immediate);
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_RETAINED_CHANNEL_TYPES */
/* INSERT_EXACT_RETAINED_CHANNEL_ADAPTERS */
/* INSERT_EXACT_RETAINED_CHANNEL_OPS */
/* INSERT_EXACT_RETAINED_CHANNEL_PUBLIC_WRAPPERS */

static void hybrid580_test_reset(void)
{
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_uvm_typed_children, 0,
           sizeof(hybrid580_uvm_typed_children));
    memset(&hybrid580_test_open_space, 0, sizeof(hybrid580_test_open_space));
    memset(&hybrid580_test_legacy_space, 0,
           sizeof(hybrid580_test_legacy_space));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_kzalloc_calls = 0;
    hybrid580_test_kfree_calls = 0;
    hybrid580_test_fail_kzalloc_at = 0;
    hybrid580_test_open.expected_space = 0x1000;
    hybrid580_test_open.expected_client = 0x51;
    hybrid580_test_open.expected_channel = 0x61;
    hybrid580_test_open.result_channel = 0x3100;
    hybrid580_test_open.result_info.resourceCount = 2;
    hybrid580_test_open.result_info.marker = 0xa001;
    hybrid580_test_open.retain_status = NV_OK;
    hybrid580_test_open.bind_status = TEST_PROVIDER_ERROR;
    hybrid580_test_legacy.expected_space = 0x2000;
    hybrid580_test_legacy.expected_client = 0x52;
    hybrid580_test_legacy.expected_channel = 0x62;
    hybrid580_test_legacy.result_channel = 0x3200;
    hybrid580_test_legacy.result_info.resourceCount = 3;
    hybrid580_test_legacy.result_info.marker = 0xb001;
    hybrid580_test_legacy.retain_status = NV_OK;
    hybrid580_test_legacy.bind_status = NV_OK;
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_space,
               0x1000, 0x0100, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_space,
               0x2000, 0x0200, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
}

static uint32_t hybrid580_test_retained_refs(uintptr_t identity)
{
    struct hybrid580_uvm_typed_child_entry **link =
        hybrid580_uvm_typed_child_find_link(
            &hybrid580_uvm_typed_children, identity,
            HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL);
    assert(link != NULL && *link != NULL);
    return (*link)->references;
}

static void hybrid580_test_assert_locks_balanced(void)
{
    assert(hybrid580_test_lock_depth == 0);
    assert(hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_provider_routes_and_reference_counting(void)
{
    UvmGpuChannelResourceBindParams open_bind = {.marker = 0x71};
    UvmGpuChannelResourceBindParams legacy_bind = {.marker = 0x72};
    UvmGpuChannelInstanceInfo info = {0};
    void *retained = NULL;

    hybrid580_test_reset();
    hybrid580_test_open.expected_bind_params = &open_bind;
    hybrid580_test_legacy.expected_bind_params = &legacy_bind;
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == NV_OK);
    assert((uintptr_t)retained == 0x3100 && info.marker == 0xa001 &&
           info.resourceCount == 2 && hybrid580_test_open.retain_calls == 1 &&
           hybrid580_test_legacy.retain_calls == 0);
    info = (UvmGpuChannelInstanceInfo){0};
    retained = NULL;
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == NV_OK);
    assert((uintptr_t)retained == 0x3100 && info.marker == 0xa001 &&
           hybrid580_test_open.retain_calls == 2 &&
           hybrid580_test_retained_refs(0x3100) == 2);

    assert(nvUvmInterfaceBindChannelResources(retained, &open_bind) ==
           TEST_PROVIDER_ERROR);
    assert(hybrid580_test_open.bind_calls == 1 &&
           hybrid580_test_open.last_bound == 0x3100 &&
           hybrid580_test_legacy.bind_calls == 0);
    nvUvmInterfaceStopChannel(retained, NV_TRUE);
    assert(hybrid580_test_open.stop_calls == 1 &&
           hybrid580_test_open.last_stopped == 0x3100 &&
           hybrid580_test_open.last_immediate == NV_TRUE);

    nvUvmInterfaceReleaseChannel(retained);
    assert(hybrid580_test_open.release_calls == 1 &&
           hybrid580_test_retained_refs(0x3100) == 1 &&
           hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 1);
    nvUvmInterfaceReleaseChannel(retained);
    assert(hybrid580_test_open.release_calls == 2 &&
           hybrid580_test_open.last_released == 0x3100 &&
           hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);

    retained = NULL;
    info = (UvmGpuChannelInstanceInfo){0};
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x2000,
               0x52, 0x62, &retained, &info) == NV_OK);
    assert((uintptr_t)retained == 0x3200 && info.marker == 0xb001 &&
           info.resourceCount == 3 && hybrid580_test_legacy.retain_calls == 1 &&
           hybrid580_test_open.retain_calls == 2);
    assert(nvUvmInterfaceBindChannelResources(retained, &legacy_bind) == NV_OK);
    nvUvmInterfaceStopChannel(retained, NV_FALSE);
    nvUvmInterfaceReleaseChannel(retained);
    assert(hybrid580_test_legacy.bind_calls == 1 &&
           hybrid580_test_legacy.last_bound == 0x3200 &&
           hybrid580_test_legacy.stop_calls == 1 &&
           hybrid580_test_legacy.last_immediate == NV_FALSE &&
           hybrid580_test_legacy.release_calls == 1 &&
           hybrid580_test_legacy.last_released == 0x3200);
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);
    assert(hybrid580_test_kzalloc_calls == 6 &&
           hybrid580_test_kfree_calls == 6);
    hybrid580_test_assert_locks_balanced();
}

static void hybrid580_test_cross_provider_alias_and_unknown_handles_fail_closed(void)
{
    void *open_retained = NULL;
    void *legacy_retained = (void *)(uintptr_t)UINTPTR_MAX;
    UvmGpuChannelInstanceInfo info = {0};
    UvmGpuChannelResourceBindParams bind = {.marker = 0x73};

    hybrid580_test_reset();
    hybrid580_test_open.result_channel = 0x4100;
    hybrid580_test_legacy.result_channel = 0x4100;
    hybrid580_test_open.expected_bind_params = &bind;
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &open_retained, &info) == NV_OK);
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x2000,
               0x52, 0x62, &legacy_retained, &info) == NV_ERR_GENERIC);
    assert((uintptr_t)open_retained == 0x4100 && legacy_retained == NULL &&
           info.marker == 0 && info.resourceCount == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_legacy.release_calls == 0 &&
           hybrid580_test_retained_refs(0x4100) == 1);
    assert(nvUvmInterfaceBindChannelResources(
               (void *)(uintptr_t)0x9999, &bind) == NV_ERR_INVALID_ARGUMENT);
    nvUvmInterfaceStopChannel((void *)(uintptr_t)0x9999, NV_FALSE);
    nvUvmInterfaceReleaseChannel((void *)(uintptr_t)0x9999);
    assert(hybrid580_test_quarantine_pins == 4 &&
           hybrid580_test_open.bind_calls == 0 &&
           hybrid580_test_legacy.bind_calls == 0 &&
           hybrid580_test_open.stop_calls == 0 &&
           hybrid580_test_legacy.stop_calls == 0 &&
           hybrid580_test_open.release_calls == 0 &&
           hybrid580_test_legacy.release_calls == 0);
    nvUvmInterfaceReleaseChannel(open_retained);
    assert(hybrid580_test_open.release_calls == 1 &&
           hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);
    hybrid580_test_assert_locks_balanced();
}

static void hybrid580_test_retain_failures_and_resource_count_limit(void)
{
    void *retained = (void *)(uintptr_t)UINTPTR_MAX;
    UvmGpuChannelInstanceInfo info = {.resourceCount = 0xdead,
                                      .marker = 0xbeef};

    hybrid580_test_reset();
    hybrid580_test_open.retain_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.result_channel = 0x5100;
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == TEST_PROVIDER_ERROR);
    assert(retained == NULL && info.resourceCount == 0 && info.marker == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_open.release_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_open.result_channel = 0;
    retained = (void *)(uintptr_t)UINTPTR_MAX;
    info = (UvmGpuChannelInstanceInfo){.resourceCount = 0xdead,
                                       .marker = 0xbeef};
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == NV_ERR_GENERIC);
    assert(retained == NULL && info.resourceCount == 0 && info.marker == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);

    hybrid580_test_reset();
    hybrid580_test_open.result_info.resourceCount =
        UVM_GPU_CHANNEL_MAX_RESOURCES + 1U;
    retained = (void *)(uintptr_t)UINTPTR_MAX;
    info = (UvmGpuChannelInstanceInfo){.resourceCount = 0xdead,
                                       .marker = 0xbeef};
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == NV_ERR_INVALID_ARGUMENT);
    assert(retained == NULL && info.resourceCount == 0 && info.marker == 0 &&
           hybrid580_test_open.retain_calls == 1 &&
           hybrid580_test_open.release_calls == 1 &&
           hybrid580_test_open.last_released == 0x3100 &&
           hybrid580_test_quarantine_pins == 0 &&
           hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);
    hybrid580_test_assert_locks_balanced();

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 1;
    retained = (void *)(uintptr_t)UINTPTR_MAX;
    info = (UvmGpuChannelInstanceInfo){.resourceCount = 0xdead,
                                       .marker = 0xbeef};
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == NV_ERR_NO_MEMORY);
    assert(retained == NULL && info.resourceCount == 0 && info.marker == 0 &&
           hybrid580_test_open.retain_calls == 0 &&
           hybrid580_test_lock_calls == 0);
    hybrid580_test_assert_locks_balanced();

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 2;
    retained = (void *)(uintptr_t)UINTPTR_MAX;
    assert(nvUvmInterfaceRetainChannel((uvmGpuAddressSpaceHandle)0x1000,
               0x51, 0x61, &retained, &info) == NV_ERR_NO_MEMORY);
    assert(retained == NULL && hybrid580_test_open.retain_calls == 0 &&
           hybrid580_test_kfree_calls == 1 &&
           hybrid580_test_lock_calls == 0);
    hybrid580_test_assert_locks_balanced();
}

int main(void)
{
    hybrid580_test_provider_routes_and_reference_counting();
    hybrid580_test_cross_provider_alias_and_unknown_handles_fail_closed();
    hybrid580_test_retain_failures_and_resource_count_limit();
    puts("exact retained-channel UVM wrappers preserve provider/refcount lifetimes");
    return 0;
}
