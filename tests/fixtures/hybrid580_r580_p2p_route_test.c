/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nv_uvm_types.h"
#include "nv_uvm_user_types.h"
#include "hybrid580_uvm_abi_compat.h"
#include "hybrid580_uvm_device_route.h"

#ifndef NV_OK
#define NV_OK UINT32_C(0)
#endif
#define NV_ERR_INVALID_ARGUMENT UINT32_C(0xe0010001)
#define NV_ERR_INVALID_STATE UINT32_C(0xe0010002)
#define NV_ERR_GENERIC UINT32_C(0xe0010003)

_Static_assert(sizeof(struct hybrid580_r580_UvmGpuP2PCapsParams) == 64,
               "R580 backend fixture must use the pinned 64-byte payload");
_Static_assert(sizeof(UvmGpuP2PCapsParams) == 72,
               "R595 frontend fixture must use the pinned 72-byte payload");
_Static_assert(sizeof(NvBool) == 1,
               "pinned R595 NvBool ABI excerpt must use one byte");
_Static_assert(offsetof(UvmGpuP2PCapsParams, bar1PcieAtomics) == 64,
               "R595 PCIe atomic fields must begin at byte 64");
_Static_assert(UVM_LINK_TYPE_PCIE_BAR1 == 2 && UVM_LINK_TYPE_NVLINK_1 == 3 &&
               UVM_LINK_TYPE_C2C == 8,
               "pinned R595 link enum excerpt has unexpected values");

static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static int hybrid580_uvm_callback_lock;
static unsigned legacy_calls;
static unsigned open_calls;
static unsigned quarantine_calls;
static uintptr_t last_legacy_device1;
static uintptr_t last_legacy_device2;
static enum {
    LEGACY_RESULT_BAR1 = 0,
    LEGACY_RESULT_INVALID_LINK,
    LEGACY_RESULT_ERROR,
} legacy_result;

#define mutex_lock(lock) ((void)(lock))
#define mutex_unlock(lock) ((void)(lock))
#define pr_emerg(...) ((void)0)

static void hybrid580_uvm_pin_quarantined_state(void)
{
    ++quarantine_calls;
}

static NV_STATUS hybrid580_legacy_nvUvmInterfaceGetP2PCaps(
    uvmGpuDeviceHandle device1, uvmGpuDeviceHandle device2,
    struct hybrid580_r580_UvmGpuP2PCapsParams *caps)
{
    ++legacy_calls;
    last_legacy_device1 = (uintptr_t)device1;
    last_legacy_device2 = (uintptr_t)device2;
    caps->peerIds[0] = 0x12;
    caps->peerIds[1] = 0x34;
    caps->egmPeerIds[0] = 0x56;
    caps->optimalNvlinkWriteCEs[1] = 7;
    caps->totalLinkLineRateMBps = 1234;
    if (legacy_result == LEGACY_RESULT_INVALID_LINK) {
        caps->p2pLink = HYBRID580_R580_LINK_TYPE_NVLINK_1;
        caps->bar1DmaSize[0] = 4096;
        return NV_OK;
    }
    caps->p2pLink = HYBRID580_R580_LINK_TYPE_PCIE;
    caps->bar1DmaAddress[0] = UINT64_C(0x100000);
    caps->bar1DmaSize[0] = UINT64_C(0x4000);
    caps->bar1DmaAddress[1] = UINT64_C(0x900000000);
    caps->bar1DmaSize[1] = UINT64_C(0x200000);
    if (legacy_result == LEGACY_RESULT_ERROR)
        return NV_ERR_GENERIC;
    return NV_OK;
}

static uint32_t test_open_get_p2p_caps(void *context, uintptr_t device1,
                                       uintptr_t device2, void *params)
{
    UvmGpuP2PCapsParams *caps = params;
    (void)context;
    (void)device1;
    (void)device2;
    ++open_calls;
    caps->p2pLink = UVM_LINK_TYPE_PCIE;
    caps->totalLinkLineRateMBps = 987;
    return NV_OK;
}

static const struct hybrid580_uvm_device_pair_backend_ops
hybrid580_open_p2p_caps_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = test_open_get_p2p_caps,
};

/* INSERT_EXTRACTED_PRODUCTION_FUNCTIONS */

static int p2p_caps_are_zero(const UvmGpuP2PCapsParams *caps)
{
    return caps->peerIds[0] == 0 && caps->peerIds[1] == 0 &&
           caps->egmPeerIds[0] == 0 && caps->egmPeerIds[1] == 0 &&
           caps->p2pLink == UVM_LINK_TYPE_NONE &&
           caps->optimalNvlinkWriteCEs[0] == 0 &&
           caps->optimalNvlinkWriteCEs[1] == 0 &&
           caps->totalLinkLineRateMBps == 0 &&
           caps->bar1DmaAddress[0] == 0 && caps->bar1DmaAddress[1] == 0 &&
           caps->bar1DmaSize[0] == 0 && caps->bar1DmaSize[1] == 0 &&
           caps->bar1PcieAtomics[0] == NV_FALSE &&
           caps->bar1PcieAtomics[1] == NV_FALSE;
}

static void record_device(uintptr_t identity,
                          enum hybrid580_uvm_provider provider)
{
    static const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES] = {0};
    assert(hybrid580_uvm_device_registry_record(
               &hybrid580_uvm_devices, identity, provider, uuid) ==
           HYBRID580_UVM_DEVICE_REGISTRY_OK);
}

int main(void)
{
    static int legacy1;
    static int legacy2;
    static int open1;
    static int unknown;
    uvmGpuDeviceHandle legacy1_handle = (uvmGpuDeviceHandle)&legacy1;
    uvmGpuDeviceHandle legacy2_handle = (uvmGpuDeviceHandle)&legacy2;
    uvmGpuDeviceHandle open1_handle = (uvmGpuDeviceHandle)&open1;
    uvmGpuDeviceHandle unknown_handle = (uvmGpuDeviceHandle)&unknown;
    UvmGpuP2PCapsParams caps;
    unsigned initial_quarantine;

    record_device((uintptr_t)legacy1_handle, HYBRID580_UVM_PROVIDER_LEGACY);
    record_device((uintptr_t)legacy2_handle, HYBRID580_UVM_PROVIDER_LEGACY);
    record_device((uintptr_t)open1_handle, HYBRID580_UVM_PROVIDER_OPEN);

    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(legacy1_handle, legacy2_handle, &caps) ==
           NV_OK);
    assert(legacy_calls == 1 && open_calls == 0);
    assert(last_legacy_device1 == (uintptr_t)legacy1_handle);
    assert(last_legacy_device2 == (uintptr_t)legacy2_handle);
    assert(caps.peerIds[0] == 0x12 && caps.peerIds[1] == 0x34);
    assert(caps.egmPeerIds[0] == 0x56);
    assert(caps.optimalNvlinkWriteCEs[1] == 7);
    assert(caps.totalLinkLineRateMBps == 1234);
    assert(caps.p2pLink == UVM_LINK_TYPE_PCIE_BAR1);
    assert(caps.bar1DmaAddress[0] == UINT64_C(0x100000));
    assert(caps.bar1DmaSize[0] == UINT64_C(0x4000));
    assert(caps.bar1DmaAddress[1] == UINT64_C(0x900000000));
    assert(caps.bar1DmaSize[1] == UINT64_C(0x200000));
    assert(caps.bar1PcieAtomics[0] == NV_FALSE);
    assert(caps.bar1PcieAtomics[1] == NV_FALSE);

    legacy_result = LEGACY_RESULT_INVALID_LINK;
    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(legacy1_handle, legacy2_handle, &caps) ==
           NV_ERR_INVALID_STATE);
    assert(legacy_calls == 2 && p2p_caps_are_zero(&caps));

    legacy_result = LEGACY_RESULT_ERROR;
    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(legacy2_handle, legacy1_handle, &caps) ==
           NV_ERR_GENERIC);
    assert(legacy_calls == 3 && p2p_caps_are_zero(&caps));
    assert(last_legacy_device1 == (uintptr_t)legacy2_handle);
    assert(last_legacy_device2 == (uintptr_t)legacy1_handle);

    legacy_result = LEGACY_RESULT_BAR1;
    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(legacy1_handle, open1_handle, &caps) ==
           NV_OK);
    assert(legacy_calls == 3 && open_calls == 0 && p2p_caps_are_zero(&caps));

    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(open1_handle, open1_handle, &caps) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(open_calls == 0);

    initial_quarantine = quarantine_calls;
    memset(&caps, 0xa5, sizeof(caps));
    assert(nvUvmInterfaceGetP2PCaps(unknown_handle, legacy1_handle, &caps) ==
           NV_ERR_INVALID_ARGUMENT);
    assert(quarantine_calls == initial_quarantine + 1);
    assert(legacy_calls == 3 && open_calls == 0);

    puts("R580 P2P adapter and production route contract passed");
    return 0;
}
