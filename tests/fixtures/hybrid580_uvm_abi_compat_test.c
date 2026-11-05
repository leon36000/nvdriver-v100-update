/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "nv_uvm_types.h"
#include "nv_uvm_user_types.h"
#include "../../src/hybrid580_uvm_abi_compat.h"

_Static_assert(sizeof(struct hybrid580_r580_UvmGpuP2PCapsParams) == 64,
               "R580 P2P payload must remain 64 bytes");
_Static_assert(sizeof(UvmGpuP2PCapsParams) == 72,
               "R595 P2P payload must include its appended atomic flags");
_Static_assert(offsetof(UvmGpuP2PCapsParams, bar1PcieAtomics) == 64,
               "R595 BAR1 atomic capability offset changed");
_Static_assert(offsetof(struct hybrid580_r580_UvmGpuP2PCapsParams,
                        bar1DmaAddress) ==
               offsetof(UvmGpuP2PCapsParams, bar1DmaAddress),
               "R580 and R595 common P2P prefix changed");
_Static_assert(sizeof(struct hybrid580_r580_UvmGpuCopyEngineCaps) == 8,
               "R580 copy-engine payload size changed");
_Static_assert(offsetof(struct hybrid580_r580_UvmGpuCopyEngineCaps, cePceMask) == 4,
               "R580 copy-engine mask offset changed");
_Static_assert(sizeof(struct hybrid580_r580_UvmGpuChannelInstanceInfo) == 1120,
               "R580 retained-channel payload must remain 1120 bytes");
_Static_assert(offsetof(struct hybrid580_r580_UvmGpuChannelInstanceInfo,
                        pRunlistPRIBaseRegister) == 1104,
               "R580 runlist base offset changed");
_Static_assert(offsetof(UvmGpuChannelInstanceInfo, workSubmissionOffset) == 1104,
               "R595 work-submission offset changed");
_Static_assert(offsetof(UvmGpuChannelInstanceInfo, workSubmissionToken) == 1112,
               "R595 work-submission token changed");
_Static_assert(sizeof(struct hybrid580_r580_UvmPmaStatistics) == 48,
               "R580 PMA statistics prefix must remain 48 bytes");
_Static_assert(offsetof(struct hybrid580_r580_UvmPmaStatistics, numFreePages64k) ==
               offsetof(UvmPmaStatistics, numFreePages64k),
               "PMA free-64K counter prefix changed");
_Static_assert(offsetof(struct hybrid580_r580_UvmPmaStatistics, numFreePages2m) ==
               offsetof(UvmPmaStatistics, numFreePages2m),
               "PMA free-2M counter prefix changed");

static void test_p2p_translation(void)
{
    struct hybrid580_r580_UvmGpuP2PCapsParams legacy = {0};
    UvmGpuP2PCapsParams modern = {0};
    unsigned int link;

    legacy.peerIds[0] = 0x12;
    legacy.peerIds[1] = 0x34;
    legacy.egmPeerIds[0] = 0x56;
    legacy.optimalNvlinkWriteCEs[1] = 7;
    legacy.totalLinkLineRateMBps = 1234;
    legacy.bar1DmaAddress[0] = 0x100000;
    legacy.bar1DmaSize[0] = 0x4000;
    legacy.p2pLink = HYBRID580_R580_LINK_TYPE_PCIE;
    assert(hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.peerIds[0] == 0x12 && modern.peerIds[1] == 0x34);
    assert(modern.egmPeerIds[0] == 0x56);
    assert(modern.optimalNvlinkWriteCEs[1] == 7);
    assert(modern.totalLinkLineRateMBps == 1234);
    assert(modern.bar1DmaAddress[0] == 0x100000);
    assert(modern.bar1DmaSize[0] == 0x4000);
    assert(modern.p2pLink == UVM_LINK_TYPE_PCIE_BAR1);
    assert(modern.bar1PcieAtomics[0] == NV_FALSE);
    assert(modern.bar1PcieAtomics[1] == NV_FALSE);

    /* R580's two BAR1 directions are separate capability results. Preserve
     * each base/size pair while keeping the unreported R595 atomics false. */
    legacy.bar1DmaAddress[1] = 0x900000000ull;
    legacy.bar1DmaSize[1] = 0x200000;
    assert(hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.bar1DmaAddress[0] == 0x100000);
    assert(modern.bar1DmaSize[0] == 0x4000);
    assert(modern.bar1DmaAddress[1] == 0x900000000ull);
    assert(modern.bar1DmaSize[1] == 0x200000);
    assert(modern.bar1PcieAtomics[0] == NV_FALSE);
    assert(modern.bar1PcieAtomics[1] == NV_FALSE);

    /* PCIe without a BAR1 DMA window stays ordinary PCIe. */
    legacy.p2pLink = HYBRID580_R580_LINK_TYPE_PCIE;
    legacy.bar1DmaAddress[0] = legacy.bar1DmaAddress[1] = 0;
    legacy.bar1DmaSize[0] = legacy.bar1DmaSize[1] = 0;
    assert(hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.p2pLink == UVM_LINK_TYPE_PCIE);
    assert(modern.bar1PcieAtomics[0] == NV_FALSE);
    assert(modern.bar1PcieAtomics[1] == NV_FALSE);

    legacy.p2pLink = HYBRID580_R580_LINK_TYPE_NONE;
    assert(hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.p2pLink == UVM_LINK_TYPE_NONE);

    for (link = HYBRID580_R580_LINK_TYPE_NVLINK_1;
         link <= HYBRID580_R580_LINK_TYPE_NVLINK_5; ++link) {
        legacy.p2pLink = link;
        legacy.bar1DmaSize[0] = legacy.bar1DmaSize[1] = 0;
        legacy.bar1DmaAddress[0] = legacy.bar1DmaAddress[1] = 0;
        assert(hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
        assert(modern.p2pLink == link + 1);
    }
    legacy.p2pLink = HYBRID580_R580_LINK_TYPE_C2C;
    assert(hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.p2pLink == UVM_LINK_TYPE_C2C);

    legacy.p2pLink = HYBRID580_R580_LINK_TYPE_NVLINK_1;
    legacy.bar1DmaAddress[0] = 0x100000;
    legacy.bar1DmaSize[0] = 4096;
    modern.bar1DmaAddress[1] = 0xfeed;
    modern.bar1DmaSize[1] = 0xbeef;
    assert(!hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.p2pLink == UVM_LINK_TYPE_NONE);
    assert(modern.bar1DmaAddress[1] == 0);
    assert(modern.bar1DmaSize[0] == 0);

    legacy.p2pLink = 99;
    assert(!hybrid580_uvm_p2p_caps_from_r580(&modern, &legacy));
    assert(modern.p2pLink == UVM_LINK_TYPE_NONE);
}

static void test_copy_caps_translation(void)
{
    struct hybrid580_r580_UvmGpuCopyEnginesCaps legacy = {0};
    UvmGpuCopyEnginesCaps modern = {0};

    legacy.copyEngineCaps[0].supported = NV_TRUE;
    legacy.copyEngineCaps[0].grce = NV_TRUE;
    legacy.copyEngineCaps[0].sysmemRead = NV_TRUE;
    legacy.copyEngineCaps[0].secure = NV_TRUE;
    legacy.copyEngineCaps[0].cePceMask = 0x12345678;
    legacy.copyEngineCaps[63].p2p = NV_TRUE;
    legacy.copyEngineCaps[63].cePceMask = 0x80000000;
    hybrid580_uvm_copy_caps_from_r580(&modern, &legacy);

    assert(modern.copyEngineCaps[0].supported);
    assert(modern.copyEngineCaps[0].grce);
    assert(modern.copyEngineCaps[0].sysmemRead);
    assert(modern.copyEngineCaps[0].secure);
    assert(!modern.copyEngineCaps[0].scrub);
    assert(modern.copyEngineCaps[0].cePceMask == 0x12345678);
    assert(modern.copyEngineCaps[63].p2p);
    assert(!modern.copyEngineCaps[63].scrub);
    assert(modern.copyEngineCaps[63].cePceMask == 0x80000000);
}

static void test_channel_translation(void)
{
    NvU32 runlist_registers[64] = {0};
    struct hybrid580_r580_UvmGpuChannelInstanceInfo legacy = {0};
    UvmGpuChannelInstanceInfo modern = {0};

    legacy.base = 0x1234000;
    legacy.sysmem = NV_TRUE;
    legacy.runlistId = 11;
    legacy.chId = 17;
    legacy.bTsgChannel = NV_TRUE;
    legacy.tsgId = 23;
    legacy.resourceCount = 1;
    legacy.resourceInfo[0].resourceDescriptor = (NvP64)(uintptr_t)0x9988;
    legacy.resourceInfo[0].resourceId = 37;
    legacy.clearFaultedToken = 41;
    legacy.pChramChannelRegister = (volatile NvU32 *)0x1000;
    legacy.pRunlistPRIBaseRegister = runlist_registers;
    legacy.smcEngineId = 0;
    legacy.smcEngineVeIdOffset = 0;

    assert(hybrid580_uvm_channel_info_from_r580(&modern, &legacy));
    assert(modern.base == legacy.base);
    assert(modern.sysmem == legacy.sysmem);
    assert(modern.runlistId == legacy.runlistId);
    assert(modern.chId == legacy.chId);
    assert(modern.bTsgChannel == legacy.bTsgChannel);
    assert(modern.tsgId == legacy.tsgId);
    assert(modern.resourceCount == 1);
    assert(modern.resourceInfo[0].resourceDescriptor ==
           (NvP64)(uintptr_t)0x9988);
    assert(modern.resourceInfo[0].resourceId == 37);
    assert(modern.clearFaultedToken == 41);
    assert(modern.pChramChannelRegister == legacy.pChramChannelRegister);
    assert(modern.workSubmissionOffset ==
           (volatile NvU32 *)((NvU8 *)runlist_registers + 0x90));
    assert(modern.workSubmissionToken == 17);
    assert(modern.smcEngineId == 0 && modern.smcEngineVeIdOffset == 0);
}

static void test_channel_translation_rejects_oversized_resource_count(void)
{
    struct hybrid580_r580_UvmGpuChannelInstanceInfo legacy = {0};
    UvmGpuChannelInstanceInfo modern;
    UvmGpuChannelInstanceInfo before;
    NvU32 i;

    legacy.resourceCount = UVM_GPU_CHANNEL_MAX_RESOURCES;
    for (i = 0; i < UVM_GPU_CHANNEL_MAX_RESOURCES; ++i)
        legacy.resourceInfo[i].resourceId = i + 1;
    assert(hybrid580_uvm_channel_info_from_r580(&modern, &legacy));
    assert(modern.resourceCount == UVM_GPU_CHANNEL_MAX_RESOURCES);
    assert(modern.resourceInfo[UVM_GPU_CHANNEL_MAX_RESOURCES - 1].resourceId ==
           UVM_GPU_CHANNEL_MAX_RESOURCES);

    memset(&modern, 0xa5, sizeof(modern));
    memcpy(&before, &modern, sizeof(before));
    legacy.resourceCount = UVM_GPU_CHANNEL_MAX_RESOURCES + 1;
    assert(!hybrid580_uvm_channel_info_from_r580(&modern, &legacy));
    assert(memcmp(&modern, &before, sizeof(modern)) == 0);
}

int main(void)
{
    test_p2p_translation();
    test_copy_caps_translation();
    test_channel_translation();
    test_channel_translation_rejects_oversized_resource_count();
    puts("R580 payloads are explicitly translated into the R595 UVM ABI: passed");
    return 0;
}
