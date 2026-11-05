/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t NV_STATUS;
typedef uint32_t NvHandle;
typedef struct { uint32_t marker; } UvmGpuTsgAllocParams;
typedef struct { uint32_t marker; } UvmGpuChannelAllocParams;
typedef struct { uintptr_t fields[4]; } UvmGpuChannelInfo;
typedef void *uvmGpuAddressSpaceHandle;
typedef void *uvmGpuTsgHandle;
typedef void *uvmGpuChannelHandle;

#define NV_OK                    UINT32_C(0)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0013601)
#define NV_ERR_NO_MEMORY        UINT32_C(0xe0013602)
#define NV_ERR_GENERIC          UINT32_C(0xe0013603)
#define TEST_PROVIDER_ERROR     UINT32_C(0xe0013604)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

#include "src/hybrid580_uvm_address_space_route.h"
#include "src/hybrid580_uvm_typed_child_route.h"
#include "src/hybrid580_uvm_info_registry.h"

struct fake_backend {
    uintptr_t expected_space;
    uintptr_t expected_tsg;
    const UvmGpuTsgAllocParams *expected_tsg_params;
    const UvmGpuChannelAllocParams *expected_channel_params;
    uintptr_t result_tsg;
    uintptr_t result_channel;
    UvmGpuChannelInfo result_channel_info;
    NV_STATUS tsg_status;
    NV_STATUS channel_status;
    unsigned tsg_allocate_calls;
    unsigned tsg_destroy_calls;
    unsigned channel_allocate_calls;
    unsigned channel_destroy_calls;
    uintptr_t last_tsg_destroyed;
    uintptr_t last_channel_destroyed;
};

static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static struct hybrid580_uvm_address_space_entry hybrid580_test_open_space;
static struct hybrid580_uvm_address_space_entry hybrid580_test_legacy_space;
static struct hybrid580_uvm_info_entry hybrid580_test_csl_entry;
static int hybrid580_uvm_callback_lock;
static int hybrid580_uvm_info_lock;
static struct hybrid580_uvm_info_registry hybrid580_uvm_infos;
static struct fake_backend hybrid580_test_open;
static struct fake_backend hybrid580_test_legacy;
static unsigned hybrid580_test_lock_depth;
static unsigned hybrid580_test_lock_calls;
static unsigned hybrid580_test_unlock_calls;
static unsigned hybrid580_test_info_lock_depth;
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

static void hybrid580_test_spin_lock_irqsave(int *lock, unsigned long *flags)
{
    assert(lock == &hybrid580_uvm_info_lock);
    assert(hybrid580_test_lock_depth == 1);
    assert(hybrid580_test_info_lock_depth == 0);
    *flags = 0;
    ++hybrid580_test_info_lock_depth;
}

static void hybrid580_test_spin_unlock_irqrestore(int *lock,
                                                   unsigned long flags)
{
    assert(lock == &hybrid580_uvm_info_lock);
    assert(flags == 0 && hybrid580_test_info_lock_depth == 1);
    --hybrid580_test_info_lock_depth;
}

#define mutex_lock(lock) hybrid580_test_mutex_lock(lock)
#define mutex_unlock(lock) hybrid580_test_mutex_unlock(lock)
#define kzalloc(size, flags) hybrid580_test_kzalloc((size), (flags))
#define kfree(pointer) hybrid580_test_kfree(pointer)
#define spin_lock_irqsave(lock, flags) \
    hybrid580_test_spin_lock_irqsave((lock), &(flags))
#define spin_unlock_irqrestore(lock, flags) \
    hybrid580_test_spin_unlock_irqrestore((lock), (flags))

static NV_STATUS hybrid580_test_tsg_allocate(
    struct fake_backend *backend, uvmGpuAddressSpaceHandle va_space,
    const UvmGpuTsgAllocParams *alloc_params, uvmGpuTsgHandle *tsg)
{
    assert((uintptr_t)va_space == backend->expected_space);
    assert(alloc_params == backend->expected_tsg_params);
    ++backend->tsg_allocate_calls;
    *tsg = (uvmGpuTsgHandle)backend->result_tsg;
    return backend->tsg_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceTsgAllocate(
    uvmGpuAddressSpaceHandle va_space,
    const UvmGpuTsgAllocParams *alloc_params, uvmGpuTsgHandle *tsg)
{
    return hybrid580_test_tsg_allocate(&hybrid580_test_open, va_space,
                                       alloc_params, tsg);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceTsgAllocate(
    uvmGpuAddressSpaceHandle va_space,
    const UvmGpuTsgAllocParams *alloc_params, uvmGpuTsgHandle *tsg)
{
    return hybrid580_test_tsg_allocate(&hybrid580_test_legacy, va_space,
                                       alloc_params, tsg);
}

void hybrid580_open_nvUvmInterfaceTsgDestroy(uvmGpuTsgHandle tsg)
{
    assert((uintptr_t)tsg != 0);
    ++hybrid580_test_open.tsg_destroy_calls;
    hybrid580_test_open.last_tsg_destroyed = (uintptr_t)tsg;
}

void hybrid580_legacy_nvUvmInterfaceTsgDestroy(uvmGpuTsgHandle tsg)
{
    assert((uintptr_t)tsg != 0);
    ++hybrid580_test_legacy.tsg_destroy_calls;
    hybrid580_test_legacy.last_tsg_destroyed = (uintptr_t)tsg;
}

static NV_STATUS hybrid580_test_channel_allocate(
    struct fake_backend *backend, uvmGpuTsgHandle tsg,
    const UvmGpuChannelAllocParams *alloc_params,
    uvmGpuChannelHandle *channel, UvmGpuChannelInfo *channel_info)
{
    assert((uintptr_t)tsg == backend->expected_tsg);
    assert(alloc_params == backend->expected_channel_params);
    ++backend->channel_allocate_calls;
    *channel = (uvmGpuChannelHandle)backend->result_channel;
    *channel_info = backend->result_channel_info;
    return backend->channel_status;
}

NV_STATUS hybrid580_open_nvUvmInterfaceChannelAllocate(
    const uvmGpuTsgHandle tsg,
    const UvmGpuChannelAllocParams *alloc_params,
    uvmGpuChannelHandle *channel, UvmGpuChannelInfo *channel_info)
{
    return hybrid580_test_channel_allocate(&hybrid580_test_open, tsg,
        alloc_params, channel, channel_info);
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceChannelAllocate(
    const uvmGpuTsgHandle tsg,
    const UvmGpuChannelAllocParams *alloc_params,
    uvmGpuChannelHandle *channel, UvmGpuChannelInfo *channel_info)
{
    return hybrid580_test_channel_allocate(&hybrid580_test_legacy, tsg,
        alloc_params, channel, channel_info);
}

void hybrid580_open_nvUvmInterfaceChannelDestroy(uvmGpuChannelHandle channel)
{
    assert((uintptr_t)channel != 0);
    ++hybrid580_test_open.channel_destroy_calls;
    hybrid580_test_open.last_channel_destroyed = (uintptr_t)channel;
}

void hybrid580_legacy_nvUvmInterfaceChannelDestroy(uvmGpuChannelHandle channel)
{
    assert((uintptr_t)channel != 0);
    ++hybrid580_test_legacy.channel_destroy_calls;
    hybrid580_test_legacy.last_channel_destroyed = (uintptr_t)channel;
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++hybrid580_test_quarantine_pins;
}

/* INSERT_EXACT_TSG_CHANNEL_TYPES */
/* INSERT_EXACT_TSG_CHANNEL_ADAPTERS */
/* INSERT_EXACT_TSG_CHANNEL_OPS */
/* INSERT_EXACT_TSG_CHANNEL_PUBLIC_WRAPPERS */

static void hybrid580_test_reset(void)
{
    memset(&hybrid580_uvm_address_spaces, 0,
           sizeof(hybrid580_uvm_address_spaces));
    memset(&hybrid580_uvm_typed_children, 0,
           sizeof(hybrid580_uvm_typed_children));
    memset(&hybrid580_test_open_space, 0, sizeof(hybrid580_test_open_space));
    memset(&hybrid580_test_legacy_space, 0,
           sizeof(hybrid580_test_legacy_space));
    memset(&hybrid580_test_csl_entry, 0, sizeof(hybrid580_test_csl_entry));
    memset(&hybrid580_uvm_infos, 0, sizeof(hybrid580_uvm_infos));
    memset(&hybrid580_test_open, 0, sizeof(hybrid580_test_open));
    memset(&hybrid580_test_legacy, 0, sizeof(hybrid580_test_legacy));
    hybrid580_test_lock_depth = 0;
    hybrid580_test_lock_calls = 0;
    hybrid580_test_unlock_calls = 0;
    hybrid580_test_info_lock_depth = 0;
    hybrid580_test_quarantine_pins = 0;
    hybrid580_test_kzalloc_calls = 0;
    hybrid580_test_kfree_calls = 0;
    hybrid580_test_fail_kzalloc_at = 0;
    hybrid580_test_open.expected_space = 0x1000;
    hybrid580_test_open.expected_tsg = 0x1100;
    hybrid580_test_open.result_tsg = 0x1100;
    hybrid580_test_open.expected_tsg_params = NULL;
    hybrid580_test_open.expected_channel_params = NULL;
    hybrid580_test_open.result_channel = 0x1200;
    hybrid580_test_open.channel_status = NV_OK;
    hybrid580_test_open.result_channel_info.fields[0] = 0xa001;
    hybrid580_test_open.result_channel_info.fields[1] = 0xa002;
    hybrid580_test_legacy.expected_space = 0x2000;
    hybrid580_test_legacy.expected_tsg = 0x2200;
    hybrid580_test_legacy.result_tsg = 0x2200;
    hybrid580_test_legacy.expected_tsg_params = NULL;
    hybrid580_test_legacy.expected_channel_params = NULL;
    hybrid580_test_legacy.result_channel = 0x2300;
    hybrid580_test_legacy.channel_status = NV_OK;
    hybrid580_test_legacy.result_channel_info.fields[0] = 0xb001;
    hybrid580_test_legacy.result_channel_info.fields[1] = 0xb002;
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_open_space,
               0x1000, 0x0100, HYBRID580_UVM_PROVIDER_OPEN) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
    assert(hybrid580_uvm_address_space_registry_insert(
               &hybrid580_uvm_address_spaces, &hybrid580_test_legacy_space,
               0x2000, 0x0200, HYBRID580_UVM_PROVIDER_LEGACY) ==
           HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK);
}

static void hybrid580_test_successful_open_and_legacy_parent_lifecycles(void)
{
    UvmGpuTsgAllocParams open_tsg_params = {.marker = 0x11};
    UvmGpuTsgAllocParams legacy_tsg_params = {.marker = 0x22};
    UvmGpuChannelAllocParams open_channel_params = {.marker = 0x33};
    UvmGpuChannelAllocParams legacy_channel_params = {.marker = 0x44};
    uvmGpuTsgHandle open_tsg = NULL;
    uvmGpuTsgHandle legacy_tsg = NULL;
    uvmGpuChannelHandle open_channel = NULL;
    uvmGpuChannelHandle legacy_channel = NULL;
    UvmGpuChannelInfo info = {0};

    hybrid580_test_reset();
    hybrid580_test_open.expected_tsg_params = &open_tsg_params;
    hybrid580_test_legacy.expected_tsg_params = &legacy_tsg_params;
    hybrid580_test_open.expected_channel_params = &open_channel_params;
    hybrid580_test_legacy.expected_channel_params = &legacy_channel_params;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &open_tsg_params, &open_tsg) == NV_OK);
    assert((uintptr_t)open_tsg == 0x1100 &&
           hybrid580_test_open.tsg_allocate_calls == 1 &&
           hybrid580_test_legacy.tsg_allocate_calls == 0);
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x2000,
               &legacy_tsg_params, &legacy_tsg) == NV_OK);
    assert((uintptr_t)legacy_tsg == 0x2200 &&
           hybrid580_test_legacy.tsg_allocate_calls == 1);
    assert(hybrid580_uvm_typed_child_registry_has_parent(
               &hybrid580_uvm_typed_children, 0x1000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE));

    assert(nvUvmInterfaceChannelAllocate(open_tsg, &open_channel_params,
               &open_channel, &info) == NV_OK);
    assert((uintptr_t)open_channel == 0x1200 &&
           info.fields[0] == 0xa001 && info.fields[1] == 0xa002 &&
           hybrid580_test_open.channel_allocate_calls == 1 &&
           hybrid580_test_legacy.channel_allocate_calls == 0);
    info = (UvmGpuChannelInfo){0};
    assert(nvUvmInterfaceChannelAllocate(legacy_tsg, &legacy_channel_params,
               &legacy_channel, &info) == NV_OK);
    assert((uintptr_t)legacy_channel == 0x2300 &&
           info.fields[0] == 0xb001 && info.fields[1] == 0xb002 &&
           hybrid580_test_legacy.channel_allocate_calls == 1);

    /* TSG destruction is refused while a channel child remains live. */
    nvUvmInterfaceTsgDestroy(open_tsg);
    assert(hybrid580_test_open.tsg_destroy_calls == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_uvm_typed_child_registry_has_parent(
               &hybrid580_uvm_typed_children, 0x1100,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG));

    nvUvmInterfaceChannelDestroy(open_channel);
    assert(hybrid580_test_open.channel_destroy_calls == 1 &&
           hybrid580_test_open.last_channel_destroyed == 0x1200);
    nvUvmInterfaceTsgDestroy(open_tsg);
    assert(hybrid580_test_open.tsg_destroy_calls == 1 &&
           hybrid580_test_open.last_tsg_destroyed == 0x1100);

    nvUvmInterfaceChannelDestroy(legacy_channel);
    nvUvmInterfaceTsgDestroy(legacy_tsg);
    assert(hybrid580_test_legacy.channel_destroy_calls == 1 &&
           hybrid580_test_legacy.last_channel_destroyed == 0x2300 &&
           hybrid580_test_legacy.tsg_destroy_calls == 1 &&
           hybrid580_test_legacy.last_tsg_destroyed == 0x2200);
    assert(!hybrid580_uvm_typed_child_registry_has_parent(
               &hybrid580_uvm_typed_children, 0x1000,
               HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE));
    assert(hybrid580_uvm_typed_child_registry_count(
               &hybrid580_uvm_typed_children) == 0);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_info_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_live_csl_context_quarantines_channel(void)
{
    UvmGpuTsgAllocParams tsg_params = {.marker = 0x71};
    UvmGpuChannelAllocParams channel_params = {.marker = 0x72};
    uvmGpuTsgHandle tsg = NULL;
    uvmGpuChannelHandle channel = NULL;
    UvmGpuChannelInfo info = {0};
    struct hybrid580_uvm_info_entry *retiring_entry = NULL;
    struct hybrid580_uvm_info_entry *removed_entry = NULL;
    struct hybrid580_uvm_info_pin pin = {0};

    hybrid580_test_reset();
    hybrid580_test_open.expected_tsg_params = &tsg_params;
    hybrid580_test_open.expected_channel_params = &channel_params;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &tsg) == NV_OK);
    assert(nvUvmInterfaceChannelAllocate(tsg, &channel_params,
               &channel, &info) == NV_OK);
    assert(hybrid580_uvm_info_registry_record(
               &hybrid580_uvm_infos, &hybrid580_test_csl_entry, 0x3100,
               0x0100, HYBRID580_UVM_PROVIDER_OPEN,
               HYBRID580_UVM_INFO_CSL) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_begin_retire(
               &hybrid580_uvm_infos, 0x3100, HYBRID580_UVM_INFO_CSL,
               0x0100, &retiring_entry) == HYBRID580_UVM_INFO_OK);
    assert(retiring_entry == &hybrid580_test_csl_entry);
    assert(hybrid580_uvm_info_registry_set_channel_parent(
               &hybrid580_uvm_infos, 0x3100, 0x0100,
               (uintptr_t)channel) == HYBRID580_UVM_INFO_OK);
    assert(hybrid580_uvm_info_registry_finish_retire(
               &hybrid580_uvm_infos, retiring_entry, 0,
               &removed_entry) == HYBRID580_UVM_INFO_OK);
    assert(removed_entry == NULL && !hybrid580_test_csl_entry.retiring &&
           hybrid580_test_csl_entry.parent_identity == (uintptr_t)channel);

    nvUvmInterfaceChannelDestroy(channel);
    assert(hybrid580_test_open.channel_destroy_calls == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_csl_entry.quarantined &&
           hybrid580_uvm_infos.count == 1 &&
           hybrid580_uvm_typed_child_registry_has_parent(
               &hybrid580_uvm_typed_children, (uintptr_t)tsg,
               HYBRID580_UVM_TYPED_CHILD_PARENT_TSG));
    assert(hybrid580_uvm_info_registry_pin(
               &hybrid580_uvm_infos, 0x3100, HYBRID580_UVM_INFO_CSL,
               0x0100, &pin) == HYBRID580_UVM_INFO_QUARANTINED);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_info_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

static void hybrid580_test_failures_and_partial_outputs_are_quarantined(void)
{
    UvmGpuTsgAllocParams tsg_params = {.marker = 0x55};
    UvmGpuChannelAllocParams channel_params = {.marker = 0x66};
    uvmGpuTsgHandle tsg = (uvmGpuTsgHandle)(uintptr_t)UINTPTR_MAX;
    uvmGpuChannelHandle channel = (uvmGpuChannelHandle)(uintptr_t)UINTPTR_MAX;
    UvmGpuChannelInfo info;

    hybrid580_test_reset();
    hybrid580_test_fail_kzalloc_at = 1;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &tsg) == NV_ERR_NO_MEMORY);
    assert(tsg == NULL && hybrid580_test_open.tsg_allocate_calls == 0 &&
           hybrid580_test_lock_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_open.expected_tsg_params = &tsg_params;
    hybrid580_test_open.tsg_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.result_tsg = 0xdead;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &tsg) == TEST_PROVIDER_ERROR);
    assert(tsg == NULL && hybrid580_test_open.tsg_allocate_calls == 1 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_open.tsg_destroy_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_open.expected_tsg_params = &tsg_params;
    hybrid580_test_open.result_tsg = 0;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &tsg) == NV_ERR_GENERIC);
    assert(tsg == NULL && hybrid580_test_quarantine_pins == 1);

    hybrid580_test_reset();
    hybrid580_test_open.expected_tsg_params = &tsg_params;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &tsg) == NV_OK);
    assert((uintptr_t)tsg == 0x1100);
    hybrid580_test_open.result_tsg = 0x1100;
    uvmGpuTsgHandle duplicate_tsg = (uvmGpuTsgHandle)(uintptr_t)UINTPTR_MAX;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &duplicate_tsg) == NV_ERR_GENERIC);
    assert(duplicate_tsg == NULL && hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_open.tsg_destroy_calls == 0);

    hybrid580_test_reset();
    hybrid580_test_open.expected_tsg_params = &tsg_params;
    assert(nvUvmInterfaceTsgAllocate((uvmGpuAddressSpaceHandle)0x1000,
               &tsg_params, &tsg) == NV_OK);
    hybrid580_test_fail_kzalloc_at = hybrid580_test_kzalloc_calls + 1;
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceChannelAllocate(tsg, &channel_params, &channel,
               &info) == NV_ERR_NO_MEMORY);
    assert(channel == NULL && info.fields[0] == 0 &&
           hybrid580_test_open.channel_allocate_calls == 0);

    hybrid580_test_fail_kzalloc_at = 0;
    hybrid580_test_open.expected_channel_params = &channel_params;
    hybrid580_test_open.channel_status = TEST_PROVIDER_ERROR;
    hybrid580_test_open.result_channel = 0xdead;
    hybrid580_test_open.result_channel_info.fields[0] = 0xdead;
    memset(&info, 0xa5, sizeof(info));
    assert(nvUvmInterfaceChannelAllocate(tsg, &channel_params, &channel,
               &info) == TEST_PROVIDER_ERROR);
    assert(channel == NULL && info.fields[0] == 0 &&
           hybrid580_test_quarantine_pins == 1 &&
           hybrid580_test_open.channel_destroy_calls == 0);

    assert(nvUvmInterfaceChannelAllocate(tsg, &channel_params, NULL,
               &info) == NV_ERR_INVALID_ARGUMENT);
    channel = (uvmGpuChannelHandle)(uintptr_t)UINTPTR_MAX;
    assert(nvUvmInterfaceChannelAllocate(tsg, &channel_params, &channel,
               NULL) == NV_ERR_INVALID_ARGUMENT);
    assert(channel == NULL);
    assert(hybrid580_test_lock_depth == 0 &&
           hybrid580_test_info_lock_depth == 0 &&
           hybrid580_test_lock_calls == hybrid580_test_unlock_calls);
}

int main(void)
{
    hybrid580_test_successful_open_and_legacy_parent_lifecycles();
    hybrid580_test_live_csl_context_quarantines_channel();
    hybrid580_test_failures_and_partial_outputs_are_quarantined();
    puts("exact UVM TSG/channel wrappers preserve providers and parent lifetimes");
    return 0;
}
