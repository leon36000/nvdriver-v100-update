/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hybrid580_uvm_info_registry.h"

typedef uint32_t NV_STATUS;
typedef uint32_t NvU32;
typedef uint8_t NvBool;
typedef void *uvmGpuDeviceHandle;

#define NV_OK UINT32_C(0)
#define NV_ERR_GENERIC UINT32_C(0x000000ff)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0x0000001f)
#define NV_ERR_INVALID_OBJECT_HANDLE UINT32_C(0x00000046)
#define NV_ERR_INSUFFICIENT_RESOURCES UINT32_C(0x00000055)
#define NV_ERR_NOT_SUPPORTED UINT32_C(0x00000056)
#define NV_ERR_INVALID_STATE UINT32_C(0x00000057)
#define NV_ERR_NO_MEMORY UINT32_C(0x00000058)
#define NV_FALSE ((NvBool)0)
#define NV_TRUE ((NvBool)1)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

typedef struct UvmCslContext_tag {
    struct ccslContext_t *ctx;
    void *nvidia_stack;
} UvmCslContext;

/* The ABI census pins UvmGpuFaultInfo to 184 bytes and cslCtx to offset 88.
 * Only the fields touched by these wrappers are modeled here. */
typedef struct UvmGpuFaultInfo_tag {
    struct {
        unsigned char opaque_prefix[88];
        UvmCslContext cslCtx;
    } replayable;
    unsigned char nonReplayable[64];
    uint64_t faultBufferHandle;
    void *pDevice;
} UvmGpuFaultInfo;

_Static_assert(sizeof(UvmCslContext) == 16, "pinned CSL context size");
_Static_assert(offsetof(UvmGpuFaultInfo, replayable.cslCtx) == 88,
               "pinned embedded CSL identity offset");
_Static_assert(sizeof(UvmGpuFaultInfo) == 184,
               "pinned R580/R595 fault-info size");

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
    (void)flags;
    ++allocation_calls;
    if (fail_allocation_on != 0 && allocation_calls == fail_allocation_on)
        return NULL;
    void *allocation = calloc(1, size);
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
    NV_STATUS has_pending_status;
    NV_STATUS get_faults_status;
    NV_STATUS flush_status;
    NV_STATUS toggle_status;
    NV_STATUS report_status;
    NV_STATUS own_interrupt_status;
    NV_STATUS service_interrupts_status;
    NvBool pending;
    NvU32 fault_count;
    NvU32 fault_word;
    unsigned calls[9];
    NvBool last_flush;
    NvBool last_toggle;
    NvBool last_own_interrupts;
    const void *last_fault_packet;
    uintptr_t expected_device;
    UvmGpuFaultInfo *last_info;
};

static struct fake_backend backends[3];

static void fake_backend_call(enum hybrid580_uvm_provider provider,
                             unsigned operation)
{
    assert(provider == HYBRID580_UVM_PROVIDER_OPEN ||
           provider == HYBRID580_UVM_PROVIDER_LEGACY);
    assert(hybrid580_uvm_callback_lock == (operation >= 6 ? 1 : 0));
    assert(hybrid580_uvm_info_lock == 0);
    ++backends[provider].calls[operation];
}

#define DEFINE_FAKE_BACKEND(prefix, provider_id) \
static NV_STATUS prefix##InitFaultInfo(uvmGpuDeviceHandle device, \
                                        UvmGpuFaultInfo *info) \
{ \
    fake_backend_call((provider_id), 0); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(info != NULL); \
    backends[(provider_id)].last_info = info; \
    info->replayable.cslCtx.ctx = (struct ccslContext_t *)(uintptr_t)0xabc1; \
    info->replayable.cslCtx.nvidia_stack = (void *)(uintptr_t)0xabc2; \
    return backends[(provider_id)].init_status; \
} \
static NV_STATUS prefix##DestroyFaultInfo(uvmGpuDeviceHandle device, \
                                           UvmGpuFaultInfo *info) \
{ \
    fake_backend_call((provider_id), 1); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(info == backends[(provider_id)].last_info); \
    return backends[(provider_id)].destroy_status; \
} \
static NV_STATUS prefix##HasPendingNonReplayableFaults( \
    UvmGpuFaultInfo *info, NvBool *has_pending) \
{ \
    fake_backend_call((provider_id), 2); \
    assert(info == backends[(provider_id)].last_info && has_pending != NULL); \
    *has_pending = backends[(provider_id)].pending; \
    return backends[(provider_id)].has_pending_status; \
} \
static NV_STATUS prefix##GetNonReplayableFaults( \
    UvmGpuFaultInfo *info, void *buffer, NvU32 *num_faults) \
{ \
    fake_backend_call((provider_id), 3); \
    assert(info == backends[(provider_id)].last_info); \
    assert(buffer != NULL && num_faults != NULL); \
    if (backends[(provider_id)].get_faults_status == NV_OK) { \
        *(NvU32 *)buffer = backends[(provider_id)].fault_word; \
        *num_faults = backends[(provider_id)].fault_count; \
    } \
    return backends[(provider_id)].get_faults_status; \
} \
static NV_STATUS prefix##FlushReplayableFaultBuffer( \
    UvmGpuFaultInfo *info, NvBool copy_and_flush) \
{ \
    fake_backend_call((provider_id), 4); \
    assert(info == backends[(provider_id)].last_info); \
    backends[(provider_id)].last_flush = copy_and_flush; \
    return backends[(provider_id)].flush_status; \
} \
static NV_STATUS prefix##TogglePrefetchFaults( \
    UvmGpuFaultInfo *info, NvBool enable) \
{ \
    fake_backend_call((provider_id), 5); \
    assert(info == backends[(provider_id)].last_info); \
    backends[(provider_id)].last_toggle = enable; \
    return backends[(provider_id)].toggle_status; \
} \
static NV_STATUS prefix##ReportNonReplayableFault( \
    uvmGpuDeviceHandle device, const void *fault_packet) \
{ \
    fake_backend_call((provider_id), 6); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    assert(fault_packet != NULL); \
    backends[(provider_id)].last_fault_packet = fault_packet; \
    return backends[(provider_id)].report_status; \
} \
static NV_STATUS prefix##OwnPageFaultIntr( \
    uvmGpuDeviceHandle device, NvBool own_interrupts) \
{ \
    fake_backend_call((provider_id), 7); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    backends[(provider_id)].last_own_interrupts = own_interrupts; \
    return backends[(provider_id)].own_interrupt_status; \
} \
static NV_STATUS prefix##ServiceDeviceInterruptsRM( \
    uvmGpuDeviceHandle device) \
{ \
    fake_backend_call((provider_id), 8); \
    assert((uintptr_t)device == backends[(provider_id)].expected_device); \
    return backends[(provider_id)].service_interrupts_status; \
}

DEFINE_FAKE_BACKEND(hybrid580_open_nvUvmInterface,
                    HYBRID580_UVM_PROVIDER_OPEN)
DEFINE_FAKE_BACKEND(hybrid580_legacy_nvUvmInterface,
                    HYBRID580_UVM_PROVIDER_LEGACY)

/* INSERT_EXACT_FAULT_INFO_OPS_TYPE */

/* INSERT_EXACT_FAULT_INFO_BACKEND_OPS */

/* INSERT_EXACT_NON_REPLAYABLE_FAULT_CALL_STRUCT */

/* INSERT_EXACT_DEVICE_CALL_AND_REPORT_ADAPTERS */

/* INSERT_EXACT_FAULT_INFO_HELPERS */

/* INSERT_EXACT_FAULT_INFO_PUBLIC_WRAPPERS */

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

static unsigned count_backend_calls(enum hybrid580_uvm_provider provider)
{
    unsigned total = 0;
    size_t i;
    for (i = 0; i < sizeof(backends[provider].calls) /
                        sizeof(backends[provider].calls[0]); ++i)
        total += backends[provider].calls[i];
    return total;
}

static void free_registered_infos(void)
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
    free_registered_infos();
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
}

static void assert_fault_pair(const UvmGpuFaultInfo *info,
                              uintptr_t device_identity,
                              enum hybrid580_uvm_provider provider)
{
    uintptr_t fault_identity = (uintptr_t)info;
    uintptr_t csl_identity = (uintptr_t)&info->replayable.cslCtx;
    struct hybrid580_uvm_info_entry *fault = find_info(fault_identity);
    struct hybrid580_uvm_info_entry *csl = find_info(csl_identity);

    assert(fault != NULL && csl != NULL && fault != csl);
    assert(fault->kind == HYBRID580_UVM_INFO_FAULT &&
           csl->kind == HYBRID580_UVM_INFO_CSL);
    assert(fault->identity == fault_identity && csl->identity == csl_identity);
    assert(fault->device_identity == device_identity &&
           csl->device_identity == device_identity);
    assert(fault->provider == provider && csl->provider == provider);
    assert(!fault->retiring && !csl->retiring &&
           !fault->quarantined && !csl->quarantined);
    assert(fault->active_calls == 0 && csl->active_calls == 0);
    assert(fault->parent_identity == 0 && csl->parent_identity == 0);
}

static void test_open_owner_lifecycle_and_queries(void)
{
    const uintptr_t open_device = (uintptr_t)0x1101;
    const uintptr_t legacy_device = (uintptr_t)0x2202;
    UvmGpuFaultInfo info = {0};
    NvBool pending = NV_FALSE;
    NvU32 fault_count = UINT32_MAX;
    NvU32 fault_word = 0;
    NvU32 fault_packet = UINT32_C(0xcafe1234);
    unsigned legacy_calls;

    reset_fixture();
    record_device(open_device, HYBRID580_UVM_PROVIDER_OPEN);
    record_device(legacy_device, HYBRID580_UVM_PROVIDER_LEGACY);
    backends[HYBRID580_UVM_PROVIDER_OPEN].pending = NV_TRUE;
    backends[HYBRID580_UVM_PROVIDER_OPEN].fault_count = 3;
    backends[HYBRID580_UVM_PROVIDER_OPEN].fault_word = UINT32_C(0x13579bdf);

    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)open_device,
                                       &info) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[0] == 1);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY) == 0);
    assert(hybrid580_uvm_infos.count == 2 && live_allocations == 2);
    assert_fault_pair(&info, open_device, HYBRID580_UVM_PROVIDER_OPEN);
    assert(info.replayable.cslCtx.ctx ==
           (struct ccslContext_t *)(uintptr_t)0xabc1);

    /* Duplicate identities are rejected before either RM is re-entered. */
    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)open_device,
                                       &info) == NV_ERR_INVALID_STATE);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[0] == 1);
    assert(hybrid580_uvm_infos.count == 2 && live_allocations == 2);

    /* A device from another RM cannot retire this fault/CSL pair. */
    assert(nvUvmInterfaceDestroyFaultInfo((uvmGpuDeviceHandle)legacy_device,
                                          &info) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[1] == 0);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY) == 0);
    assert_fault_pair(&info, open_device, HYBRID580_UVM_PROVIDER_OPEN);

    assert(nvUvmInterfaceHasPendingNonReplayableFaults(&info, &pending) == NV_OK);
    assert(pending == NV_TRUE);
    assert(nvUvmInterfaceGetNonReplayableFaults(&info, &fault_word,
                                                &fault_count) == NV_OK);
    assert(fault_word == UINT32_C(0x13579bdf) && fault_count == 3);
    assert(nvUvmInterfaceFlushReplayableFaultBuffer(&info, NV_TRUE) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].last_flush == NV_TRUE);
    assert(nvUvmInterfaceTogglePrefetchFaults(&info, NV_FALSE) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].last_toggle == NV_FALSE);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[2] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_OPEN].calls[3] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_OPEN].calls[4] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_OPEN].calls[5] == 1);
    assert_fault_pair(&info, open_device, HYBRID580_UVM_PROVIDER_OPEN);

    /* The device-owned RM report path forwards the opaque packet verbatim. */
    assert(nvUvmInterfaceReportNonReplayableFault(
               (uvmGpuDeviceHandle)open_device, &fault_packet) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[6] == 1);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].last_fault_packet ==
           &fault_packet);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[6] == 0);
    backends[HYBRID580_UVM_PROVIDER_OPEN].report_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceReportNonReplayableFault(
               (uvmGpuDeviceHandle)open_device, &fault_packet) ==
           NV_ERR_GENERIC);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[6] == 2);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[6] == 0);
    legacy_calls = count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY);
    assert(nvUvmInterfaceReportNonReplayableFault(
               (uvmGpuDeviceHandle)legacy_device, &fault_packet) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[6] == 1);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].last_fault_packet ==
           &fault_packet);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_OPEN) == 7);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY) == legacy_calls + 1);
    assert(nvUvmInterfaceReportNonReplayableFault(NULL, &fault_packet) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceReportNonReplayableFault(
               (uvmGpuDeviceHandle)open_device, NULL) == NV_ERR_INVALID_ARGUMENT);

    assert(nvUvmInterfaceOwnPageFaultIntr(
               (uvmGpuDeviceHandle)open_device, NV_TRUE) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[7] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_OPEN].last_own_interrupts == NV_TRUE);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[7] == 0);
    backends[HYBRID580_UVM_PROVIDER_OPEN].own_interrupt_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceOwnPageFaultIntr(
               (uvmGpuDeviceHandle)open_device, NV_FALSE) == NV_ERR_GENERIC);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[7] == 2 &&
           backends[HYBRID580_UVM_PROVIDER_OPEN].last_own_interrupts == NV_FALSE);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[7] == 0);
    assert(nvUvmInterfaceOwnPageFaultIntr(
               (uvmGpuDeviceHandle)legacy_device, NV_FALSE) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[7] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].last_own_interrupts ==
               NV_FALSE);
    assert(nvUvmInterfaceOwnPageFaultIntr(
               (uvmGpuDeviceHandle)open_device, (NvBool)2) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[7] == 2);

    assert(nvUvmInterfaceServiceDeviceInterruptsRM(
               (uvmGpuDeviceHandle)open_device) == NV_OK);
    assert(nvUvmInterfaceServiceDeviceInterruptsRM(
               (uvmGpuDeviceHandle)legacy_device) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[8] == 1 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[8] == 1);
    backends[HYBRID580_UVM_PROVIDER_OPEN].service_interrupts_status =
        NV_ERR_GENERIC;
    assert(nvUvmInterfaceServiceDeviceInterruptsRM(
               (uvmGpuDeviceHandle)open_device) == NV_ERR_GENERIC);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[8] == 2 &&
           backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[8] == 1);

    legacy_calls = count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY);
    backends[HYBRID580_UVM_PROVIDER_OPEN].get_faults_status = NV_ERR_GENERIC;
    fault_count = UINT32_MAX;
    assert(nvUvmInterfaceGetNonReplayableFaults(&info, &fault_word,
                                                &fault_count) == NV_ERR_GENERIC);
    assert(fault_count == 0 &&
           backends[HYBRID580_UVM_PROVIDER_OPEN].calls[3] == 2);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY) == legacy_calls);

    assert(nvUvmInterfaceDestroyFaultInfo((uvmGpuDeviceHandle)open_device,
                                          &info) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_OPEN].calls[1] == 1);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    pending = NV_TRUE;
    assert(nvUvmInterfaceHasPendingNonReplayableFaults(&info, &pending) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(pending == NV_FALSE);
    fault_count = UINT32_MAX;
    assert(nvUvmInterfaceGetNonReplayableFaults(&info, &fault_word,
                                                &fault_count) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(fault_count == 0);
}

static void test_legacy_init_failure_and_failed_destroy_quarantine(void)
{
    const uintptr_t legacy_device = (uintptr_t)0x3303;
    UvmGpuFaultInfo info = {0};
    NvBool pending = NV_TRUE;

    reset_fixture();
    record_device(legacy_device, HYBRID580_UVM_PROVIDER_LEGACY);
    backends[HYBRID580_UVM_PROVIDER_LEGACY].init_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)legacy_device,
                                       &info) == NV_ERR_GENERIC);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[0] == 1);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_OPEN) == 0);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[1] == 0);

    backends[HYBRID580_UVM_PROVIDER_LEGACY].init_status = NV_OK;
    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)legacy_device,
                                       &info) == NV_OK);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[0] == 2);
    assert(hybrid580_uvm_infos.count == 2 && live_allocations == 2);
    assert_fault_pair(&info, legacy_device, HYBRID580_UVM_PROVIDER_LEGACY);

    backends[HYBRID580_UVM_PROVIDER_LEGACY].destroy_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceDestroyFaultInfo((uvmGpuDeviceHandle)legacy_device,
                                          &info) == NV_ERR_GENERIC);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[1] == 1);
    assert(quarantine_calls == 1 && hybrid580_uvm_infos.count == 2);
    assert(find_info((uintptr_t)&info)->quarantined);
    assert(find_info((uintptr_t)&info.replayable.cslCtx)->quarantined);
    assert(nvUvmInterfaceHasPendingNonReplayableFaults(&info, &pending) ==
           NV_ERR_INVALID_STATE);
    assert(pending == NV_FALSE);
    assert(backends[HYBRID580_UVM_PROVIDER_LEGACY].calls[2] == 0);
    assert(live_allocations == 2);
}

static void test_invalid_unknown_owner_and_allocation_failure(void)
{
    const uintptr_t open_device = (uintptr_t)0x4404;
    const uintptr_t unknown_device = (uintptr_t)0x5505;
    UvmGpuFaultInfo info = {0};
    unsigned calls_before;

    reset_fixture();
    calls_before = allocation_calls;
    assert(nvUvmInterfaceInitFaultInfo(NULL, &info) == NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)open_device, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(allocation_calls == calls_before && live_allocations == 0);

    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)unknown_device,
                                       &info) == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_OPEN) == 0 &&
           count_backend_calls(HYBRID580_UVM_PROVIDER_LEGACY) == 0);

    record_device(open_device, HYBRID580_UVM_PROVIDER_OPEN);
    fail_allocation_on = allocation_calls + 2;
    assert(nvUvmInterfaceInitFaultInfo((uvmGpuDeviceHandle)open_device,
                                       &info) == NV_ERR_NO_MEMORY);
    assert(hybrid580_uvm_infos.count == 0 && live_allocations == 0);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_OPEN) == 0);

    calls_before = count_backend_calls(HYBRID580_UVM_PROVIDER_OPEN);
    assert(nvUvmInterfaceFlushReplayableFaultBuffer(&info, (NvBool)2) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceTogglePrefetchFaults(&info, (NvBool)2) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceHasPendingNonReplayableFaults(&info, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceGetNonReplayableFaults(&info, NULL, NULL) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(count_backend_calls(HYBRID580_UVM_PROVIDER_OPEN) == calls_before);
}

int main(void)
{
    test_open_owner_lifecycle_and_queries();
    test_legacy_init_failure_and_failed_destroy_quarantine();
    test_invalid_unknown_owner_and_allocation_failure();
    assert(hybrid580_uvm_callback_lock == 0 && hybrid580_uvm_info_lock == 0);
    assert(mutex_lock_calls == mutex_unlock_calls);
    assert(spin_lock_calls == spin_unlock_calls);
    puts("exact UVM fault and interrupt routes passed");
    return 0;
}
