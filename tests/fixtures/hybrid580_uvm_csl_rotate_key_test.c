/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hybrid580_uvm_info_registry.h"

typedef uint32_t NV_STATUS;
typedef uint32_t NvU32;
typedef uint8_t NvU8;
typedef uint64_t NvU64;
typedef uint32_t NvBool;
typedef uint32_t UvmCslOperation;
typedef struct UvmCslIv { uint8_t bytes[16]; } UvmCslIv;
typedef struct UvmCslContext { uintptr_t tag; } UvmCslContext;
typedef void *uvmGpuChannelHandle;

#define NV_OK UINT32_C(0)
#define NV_ERR_GENERIC UINT32_C(0xff)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0x1f)
#define NV_ERR_INVALID_OBJECT_HANDLE UINT32_C(0x46)
#define NV_ERR_INSUFFICIENT_RESOURCES UINT32_C(0x55)
#define NV_ERR_NOT_SUPPORTED UINT32_C(0x56)
#define NV_ERR_INVALID_STATE UINT32_C(0x57)
#define NV_ERR_NO_MEMORY UINT32_C(0x58)
#define GFP_KERNEL 0U
#define EXPORT_SYMBOL(symbol)
#define pr_emerg(...) ((void)0)

static struct hybrid580_uvm_info_registry hybrid580_uvm_infos;
static int hybrid580_uvm_info_lock;
static unsigned spin_lock_calls;
static unsigned spin_unlock_calls;
static unsigned allocation_calls;
static unsigned fail_allocation_on;
static unsigned live_allocations;
static unsigned quarantine_calls;
static unsigned open_calls;
static unsigned legacy_calls;
static unsigned open_iv_calls;
static unsigned legacy_iv_calls;
static UvmCslContext **last_context_list;
static NvU32 last_context_count;
static UvmCslOperation last_operation;
static NV_STATUS fake_backend_status = NV_OK;

static void *test_kcalloc(size_t count, size_t size, unsigned int flags)
{
    void *allocation;

    (void)flags;
    ++allocation_calls;
    if (allocation_calls == fail_allocation_on)
        return NULL;
    allocation = calloc(count, size);
    if (allocation != NULL)
        ++live_allocations;
    return allocation;
}

static void test_kfree(void *allocation)
{
    if (allocation == NULL)
        return;
    assert(live_allocations != 0);
    --live_allocations;
    free(allocation);
}

#define kcalloc(count, size, flags) test_kcalloc((count), (size), (flags))
#define kfree(allocation) test_kfree(allocation)
#define spin_lock_irqsave(lock, flags) do { \
    assert((lock) != 0); \
    assert(*(lock) == 0); \
    *(lock) = 1; \
    (flags) = 0; \
    ++spin_lock_calls; \
} while (0)
#define spin_unlock_irqrestore(lock, flags) do { \
    (void)(flags); \
    assert((lock) != 0); \
    assert(*(lock) == 1); \
    *(lock) = 0; \
    ++spin_unlock_calls; \
} while (0)

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++quarantine_calls;
}

/* INSERT_EXACT_CSL_OPS_TYPE */

static NV_STATUS fake_rotate_key(enum hybrid580_uvm_provider provider,
                                 UvmCslContext *context_list[],
                                 NvU32 context_count)
{
    NvU32 i;

    assert(hybrid580_uvm_info_lock == 0);
    assert(context_list != NULL && context_count != 0);
    last_context_list = context_list;
    last_context_count = context_count;
    for (i = 0; i < context_count; ++i) {
        struct hybrid580_uvm_info_entry **link;
        struct hybrid580_uvm_info_entry *retiring = NULL;

        assert(context_list[i] != NULL);
        link = hybrid580_uvm_info_find_link(
            &hybrid580_uvm_infos, (uintptr_t)context_list[i]);
        assert(link != NULL && *link != NULL);
        assert((*link)->provider == provider);
        assert((*link)->kind == HYBRID580_UVM_INFO_CSL);
        assert((*link)->active_calls == 1);
        assert(hybrid580_uvm_info_registry_begin_retire(
            &hybrid580_uvm_infos, (uintptr_t)context_list[i],
            HYBRID580_UVM_INFO_CSL, 0, &retiring) ==
            HYBRID580_UVM_INFO_BUSY);
        assert(retiring == NULL);
    }
    return fake_backend_status;
}

static NV_STATUS fake_open_rotate_key(UvmCslContext *context_list[],
                                      NvU32 context_count)
{
    ++open_calls;
    return fake_rotate_key(HYBRID580_UVM_PROVIDER_OPEN,
                           context_list, context_count);
}

static NV_STATUS fake_legacy_rotate_key(UvmCslContext *context_list[],
                                        NvU32 context_count)
{
    ++legacy_calls;
    return fake_rotate_key(HYBRID580_UVM_PROVIDER_LEGACY,
                           context_list, context_count);
}

static NV_STATUS fake_rotate_iv(enum hybrid580_uvm_provider provider,
                                UvmCslContext *context,
                                UvmCslOperation operation)
{
    struct hybrid580_uvm_info_entry **link;
    struct hybrid580_uvm_info_entry *retiring = NULL;

    assert(hybrid580_uvm_info_lock == 0);
    assert(context != NULL);
    link = hybrid580_uvm_info_find_link(
        &hybrid580_uvm_infos, (uintptr_t)context);
    assert(link != NULL && *link != NULL);
    assert((*link)->provider == provider);
    assert((*link)->kind == HYBRID580_UVM_INFO_CSL);
    assert((*link)->active_calls == 1);
    assert(hybrid580_uvm_info_registry_begin_retire(
        &hybrid580_uvm_infos, (uintptr_t)context,
        HYBRID580_UVM_INFO_CSL, 0, &retiring) == HYBRID580_UVM_INFO_BUSY);
    assert(retiring == NULL);
    last_operation = operation;
    return fake_backend_status;
}

static NV_STATUS fake_open_rotate_iv(UvmCslContext *context,
                                     UvmCslOperation operation)
{
    ++open_iv_calls;
    return fake_rotate_iv(HYBRID580_UVM_PROVIDER_OPEN, context, operation);
}

static NV_STATUS fake_legacy_rotate_iv(UvmCslContext *context,
                                       UvmCslOperation operation)
{
    ++legacy_iv_calls;
    return fake_rotate_iv(HYBRID580_UVM_PROVIDER_LEGACY, context, operation);
}

/* INSERT_EXACT_CSL_BACKEND_TABLES */

/* INSERT_EXACT_CSL_HELPERS */

/* INSERT_EXACT_CSL_PUBLIC_WRAPPERS */

static struct hybrid580_uvm_info_entry *record_context(
    UvmCslContext *context, enum hybrid580_uvm_provider provider,
    uintptr_t device_identity)
{
    struct hybrid580_uvm_info_entry *entry = calloc(1, sizeof(*entry));

    assert(entry != NULL);
    assert(hybrid580_uvm_info_registry_record(
        &hybrid580_uvm_infos, entry, (uintptr_t)context, device_identity,
        provider, HYBRID580_UVM_INFO_CSL) == HYBRID580_UVM_INFO_OK);
    return entry;
}

static void assert_unpinned(struct hybrid580_uvm_info_entry *entry)
{
    assert(entry != NULL && entry->active_calls == 0);
}

int main(void)
{
    UvmCslContext open_a = { .tag = 1 };
    UvmCslContext open_b = { .tag = 2 };
    UvmCslContext legacy_a = { .tag = 3 };
    UvmCslContext unknown = { .tag = 4 };
    struct hybrid580_uvm_info_entry *entry_open_a;
    struct hybrid580_uvm_info_entry *entry_open_b;
    struct hybrid580_uvm_info_entry *entry_legacy_a;
    UvmCslContext *same_open[] = { &open_a, &open_b };
    UvmCslContext *same_legacy[] = { &legacy_a };
    UvmCslContext *mixed[] = { &open_a, &legacy_a };
    UvmCslContext *duplicate[] = { &open_a, &open_a };
    UvmCslContext *missing[] = { &open_a, &unknown };
    UvmCslContext *null_member[] = { &open_a, NULL };
    unsigned calls_before;

    entry_open_a = record_context(&open_a, HYBRID580_UVM_PROVIDER_OPEN, 0xa1);
    entry_open_b = record_context(&open_b, HYBRID580_UVM_PROVIDER_OPEN, 0xa2);
    entry_legacy_a = record_context(
        &legacy_a, HYBRID580_UVM_PROVIDER_LEGACY, 0xb1);

    fake_backend_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceCslRotateKey(same_open, 2) == NV_ERR_GENERIC);
    assert(open_calls == 1 && legacy_calls == 0);
    assert(last_context_list == same_open && last_context_count == 2);
    assert_unpinned(entry_open_a);
    assert_unpinned(entry_open_b);

    fake_backend_status = NV_OK;
    assert(nvUvmInterfaceCslRotateKey(same_legacy, 1) == NV_OK);
    assert(open_calls == 1 && legacy_calls == 1);
    assert(last_context_list == same_legacy && last_context_count == 1);
    assert_unpinned(entry_legacy_a);

    fake_backend_status = NV_ERR_GENERIC;
    assert(nvUvmInterfaceCslRotateIv(&open_b, 0x1234) == NV_ERR_GENERIC);
    assert(open_iv_calls == 1 && legacy_iv_calls == 0);
    assert(last_operation == 0x1234);
    assert_unpinned(entry_open_b);
    fake_backend_status = NV_OK;
    assert(nvUvmInterfaceCslRotateIv(&legacy_a, 0x5678) == NV_OK);
    assert(open_iv_calls == 1 && legacy_iv_calls == 1);
    assert(last_operation == 0x5678);
    assert_unpinned(entry_legacy_a);
    calls_before = open_iv_calls + legacy_iv_calls;
    assert(nvUvmInterfaceCslRotateIv(&unknown, 1) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(open_iv_calls + legacy_iv_calls == calls_before);

    entry_open_b->retiring = 1;
    assert(nvUvmInterfaceCslRotateIv(&open_b, 1) == NV_ERR_INVALID_STATE);
    entry_open_b->retiring = 0;
    entry_open_b->quarantined = 1;
    assert(nvUvmInterfaceCslRotateIv(&open_b, 1) == NV_ERR_INVALID_STATE);
    entry_open_b->quarantined = 0;
    assert(open_iv_calls + legacy_iv_calls == calls_before);
    assert_unpinned(entry_open_b);

    calls_before = open_calls + legacy_calls;
    assert(nvUvmInterfaceCslRotateKey(mixed, 2) == NV_ERR_NOT_SUPPORTED);
    assert(open_calls + legacy_calls == calls_before);
    assert_unpinned(entry_open_a);
    assert_unpinned(entry_legacy_a);

    assert(nvUvmInterfaceCslRotateKey(duplicate, 2) == NV_ERR_INVALID_STATE);
    assert(open_calls + legacy_calls == calls_before);
    assert_unpinned(entry_open_a);

    assert(nvUvmInterfaceCslRotateKey(missing, 2) ==
           NV_ERR_INVALID_OBJECT_HANDLE);
    assert(open_calls + legacy_calls == calls_before);
    assert_unpinned(entry_open_a);

    entry_open_a->retiring = 1;
    assert(nvUvmInterfaceCslRotateKey(same_open, 2) == NV_ERR_INVALID_STATE);
    entry_open_a->retiring = 0;
    entry_open_a->quarantined = 1;
    assert(nvUvmInterfaceCslRotateKey(same_open, 2) == NV_ERR_INVALID_STATE);
    entry_open_a->quarantined = 0;
    assert(open_calls + legacy_calls == calls_before);
    assert_unpinned(entry_open_a);

    assert(nvUvmInterfaceCslRotateKey(null_member, 2) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceCslRotateKey(NULL, 1) == NV_ERR_INVALID_ARGUMENT);
    assert(nvUvmInterfaceCslRotateKey(same_open, 0) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(live_allocations == 0);

    fail_allocation_on = allocation_calls + 1;
    assert(nvUvmInterfaceCslRotateKey(same_open, 2) == NV_ERR_NO_MEMORY);
    assert(live_allocations == 0);
    fail_allocation_on = allocation_calls + 2;
    assert(nvUvmInterfaceCslRotateKey(same_open, 2) == NV_ERR_NO_MEMORY);
    assert(live_allocations == 0);
    fail_allocation_on = 0;

    assert(hybrid580_uvm_info_lock == 0);
    assert(spin_lock_calls == spin_unlock_calls);
    assert(quarantine_calls == 0);
    assert(live_allocations == 0);
    free(entry_open_a);
    free(entry_open_b);
    free(entry_legacy_a);
    puts("exact CSL key-rotation ownership and lifetime: PASS");
    return 0;
}
