/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nv_uvm_copy_engine_caps_excerpt.h"
#include "hybrid580_uvm_device_route.h"

typedef uint32_t NV_STATUS;
typedef void *uvmGpuDeviceHandle;

#define NV_OK UINT32_C(0)
#define NV_ERR_GENERIC UINT32_C(0x0000ffff)
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0x0000001f)

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static int hybrid580_uvm_callback_lock;
static unsigned lock_calls;
static unsigned unlock_calls;
static unsigned quarantine_calls;

static NV_STATUS open_status = NV_OK;
static NV_STATUS legacy_status = NV_OK;
static unsigned open_calls;
static unsigned legacy_calls;
static uintptr_t expected_open_device = (uintptr_t)0x7101;
static uintptr_t expected_legacy_device = (uintptr_t)0x7102;

static void mutex_lock(int *lock)
{
    assert(lock != NULL && *lock == 0);
    *lock = 1;
    ++lock_calls;
}

static void mutex_unlock(int *lock)
{
    assert(lock != NULL && *lock == 1);
    *lock = 0;
    ++unlock_calls;
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++quarantine_calls;
}

#define pr_emerg(...) ((void)0)

extern NV_STATUS hybrid580_open_nvUvmInterfaceQueryCopyEnginesCaps(
    uvmGpuDeviceHandle device, UvmGpuCopyEnginesCaps *caps);
/* INSERT_EXACT_R580_COPY_CAPS_TYPES */
extern NV_STATUS hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps(
    uvmGpuDeviceHandle device,
    struct hybrid580_r580_UvmGpuCopyEnginesCaps *caps);

/* INSERT_EXACT_COPY_CAPS_TRANSLATION */
/* INSERT_EXACT_COPY_CAPS_ADAPTERS */
/* INSERT_EXACT_DEVICE_CALL_HELPER */
/* INSERT_EXACT_COPY_CAPS_PUBLIC_WRAPPER */

NV_STATUS hybrid580_open_nvUvmInterfaceQueryCopyEnginesCaps(
    uvmGpuDeviceHandle device, UvmGpuCopyEnginesCaps *caps)
{
    assert((uintptr_t)device == expected_open_device);
    assert(caps != NULL);
    ++open_calls;
    caps->copyEngineCaps[0].supported = NV_TRUE;
    caps->copyEngineCaps[0].shared = NV_TRUE;
    caps->copyEngineCaps[0].scrub = NV_TRUE;
    caps->copyEngineCaps[0].cePceMask = UINT32_C(0x12345678);
    caps->copyEngineCaps[63].p2p = NV_TRUE;
    caps->copyEngineCaps[63].scrub = NV_TRUE;
    caps->copyEngineCaps[63].cePceMask = UINT32_C(0x80000002);
    return open_status;
}

NV_STATUS hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps(
    uvmGpuDeviceHandle device,
    struct hybrid580_r580_UvmGpuCopyEnginesCaps *caps)
{
    assert((uintptr_t)device == expected_legacy_device);
    assert(caps != NULL);
    ++legacy_calls;
    caps->copyEngineCaps[0].supported = NV_TRUE;
    caps->copyEngineCaps[0].grce = NV_TRUE;
    caps->copyEngineCaps[0].shared = NV_TRUE;
    caps->copyEngineCaps[0].sysmemRead = NV_TRUE;
    caps->copyEngineCaps[0].sysmem = NV_TRUE;
    caps->copyEngineCaps[0].nvlinkP2p = NV_TRUE;
    caps->copyEngineCaps[0].p2p = NV_TRUE;
    caps->copyEngineCaps[0].secure = NV_TRUE;
    caps->copyEngineCaps[0].cePceMask = UINT32_C(0x12345678);
    caps->copyEngineCaps[63].supported = NV_TRUE;
    caps->copyEngineCaps[63].p2p = NV_TRUE;
    caps->copyEngineCaps[63].cePceMask = UINT32_C(0x80000002);
    return legacy_status;
}

static void record_device(uintptr_t identity, enum hybrid580_uvm_provider provider,
                          unsigned char uuid_seed)
{
    unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0};
    uuid[0] = uuid_seed;
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, identity, provider, uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
}

static void assert_caps_are_zero(const UvmGpuCopyEnginesCaps *caps)
{
    const unsigned char *bytes = (const unsigned char *)caps;
    size_t i;
    for (i = 0; i < sizeof(*caps); ++i)
        assert(bytes[i] == 0);
}

int main(void)
{
    UvmGpuCopyEnginesCaps caps;
    unsigned calls_before;

    _Static_assert(UVM_COPY_ENGINE_COUNT_MAX == 64,
                   "test requires pinned R595 copy-engine array bound");
    _Static_assert(sizeof(((UvmGpuCopyEnginesCaps *)0)->copyEngineCaps) /
                       sizeof(UvmGpuCopyEngineCaps) == 64,
                   "R595 public payload must expose 64 engine slots");

    record_device(expected_open_device, HYBRID580_UVM_PROVIDER_OPEN, 0x71);
    record_device(expected_legacy_device, HYBRID580_UVM_PROVIDER_LEGACY, 0x72);

    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceQueryCopyEnginesCaps(
               (uvmGpuDeviceHandle)expected_legacy_device, &caps) == NV_OK);
    assert(legacy_calls == 1 && open_calls == 0);
    assert(caps.copyEngineCaps[0].supported && caps.copyEngineCaps[0].grce &&
           caps.copyEngineCaps[0].shared && caps.copyEngineCaps[0].sysmemRead &&
           !caps.copyEngineCaps[0].sysmemWrite && caps.copyEngineCaps[0].sysmem &&
           caps.copyEngineCaps[0].nvlinkP2p && caps.copyEngineCaps[0].p2p &&
           caps.copyEngineCaps[0].secure);
    assert(!caps.copyEngineCaps[0].scrub);
    assert(caps.copyEngineCaps[0].cePceMask == UINT32_C(0x12345678));
    assert(caps.copyEngineCaps[63].supported && caps.copyEngineCaps[63].p2p);
    assert(!caps.copyEngineCaps[63].scrub);
    assert(caps.copyEngineCaps[63].cePceMask == UINT32_C(0x80000002));
    assert(unlock_calls == lock_calls && hybrid580_uvm_callback_lock == 0);

    memset(&caps, 0, sizeof(caps));
    assert(nvUvmInterfaceQueryCopyEnginesCaps(
               (uvmGpuDeviceHandle)expected_open_device, &caps) == NV_OK);
    assert(open_calls == 1 && legacy_calls == 1);
    assert(caps.copyEngineCaps[0].scrub &&
           caps.copyEngineCaps[0].cePceMask == UINT32_C(0x12345678));
    assert(caps.copyEngineCaps[63].scrub && caps.copyEngineCaps[63].p2p &&
           caps.copyEngineCaps[63].cePceMask == UINT32_C(0x80000002));

    /* Owner errors are returned without fallback; partial backend writes clear. */
    legacy_status = NV_ERR_GENERIC;
    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceQueryCopyEnginesCaps(
               (uvmGpuDeviceHandle)expected_legacy_device, &caps) == NV_ERR_GENERIC);
    assert(legacy_calls == 2 && open_calls == 1);
    assert_caps_are_zero(&caps);

    /* Unknown public handles are quarantined and never sent to either RM. */
    memset(&caps, 0xa5, sizeof(caps));
    calls_before = open_calls + legacy_calls;
    assert(nvUvmInterfaceQueryCopyEnginesCaps(
               (uvmGpuDeviceHandle)(uintptr_t)0x7fff, &caps) ==
           NV_ERR_INVALID_ARGUMENT);
    assert_caps_are_zero(&caps);
    assert(open_calls + legacy_calls == calls_before);
    assert(quarantine_calls == 1);

    /* Invalid device input clears the payload without taking the bridge lock. */
    calls_before = lock_calls;
    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceQueryCopyEnginesCaps(NULL, &caps) ==
           NV_ERR_INVALID_ARGUMENT);
    assert_caps_are_zero(&caps);
    assert(lock_calls == calls_before && unlock_calls == lock_calls);

    assert(hybrid580_uvm_device_registry_count(&hybrid580_uvm_devices) == 2);
    puts("exact UVM copy-engine capability wrapper scenarios passed");
    return 0;
}
