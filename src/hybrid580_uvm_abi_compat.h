/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_ABI_COMPAT_H
#define HYBRID580_UVM_ABI_COMPAT_H

/*
 * R580's private RM exports use these older UVM payload layouts. They are
 * intentionally separate from the R595 public UVM types: modversion CRCs
 * prove which provider symbol is resolved, not that the caller's C payload
 * layout is correct.
 */
struct hybrid580_r580_UvmGpuP2PCapsParams {
    NvU32 peerIds[2];
    NvU32 egmPeerIds[2];
    NvU32 p2pLink;
    NvU32 optimalNvlinkWriteCEs[2];
    NvU32 totalLinkLineRateMBps;
    NvU64 bar1DmaAddress[2];
    NvU64 bar1DmaSize[2];
};

struct hybrid580_r580_UvmGpuCopyEngineCaps {
    NvBool supported:1;
    NvBool grce:1;
    NvBool shared:1;
    NvBool sysmemRead:1;
    NvBool sysmemWrite:1;
    NvBool sysmem:1;
    NvBool nvlinkP2p:1;
    NvBool p2p:1;
    NvBool secure:1;
    NvU32 cePceMask;
};

struct hybrid580_r580_UvmGpuCopyEnginesCaps {
    struct hybrid580_r580_UvmGpuCopyEngineCaps copyEngineCaps[UVM_COPY_ENGINE_COUNT_MAX];
};

/* R580 PMA statistics are a stable six-counter prefix. The pinned R595 UVM
 * runtime reads numFreePages64k and numFreePages2m from this shared object;
 * its appended localizable-region counters are not supplied by R580. */
struct hybrid580_r580_UvmPmaStatistics {
    volatile NvU64 numPages2m;
    volatile NvU64 numFreePages64k;
    volatile NvU64 numFreePages2m;
    volatile NvU64 numPages2mProtected;
    volatile NvU64 numFreePages64kProtected;
    volatile NvU64 numFreePages2mProtected;
};

struct hybrid580_r580_UvmGpuChannelInstanceInfo {
    NvU64 base;
    NvBool sysmem;
    NvU32 runlistId;
    NvU32 chId;
    NvBool bInSubctx;
    NvU32 subctxId;
    NvBool bTsgChannel;
    NvU32 tsgId;
    NvU32 tsgMaxSubctxCount;
    UvmGpuChannelResourceInfo resourceInfo[UVM_GPU_CHANNEL_MAX_RESOURCES];
    NvU32 resourceCount;
    NvU32 channelEngineType;
    NvU32 clearFaultedToken;
    volatile NvU32 *pChramChannelRegister;
    volatile NvU32 *pRunlistPRIBaseRegister;
    NvU32 smcEngineId;
    NvU32 smcEngineVeIdOffset;
};

/* Values from the pinned R580 UVM_LINK_TYPE declaration. R595 inserted
 * PCIE_BAR1 at value 2, shifting every later link enumerant by one. */
#define HYBRID580_R580_LINK_TYPE_NONE       0u
#define HYBRID580_R580_LINK_TYPE_PCIE       1u
#define HYBRID580_R580_LINK_TYPE_NVLINK_1   2u
#define HYBRID580_R580_LINK_TYPE_NVLINK_2   3u
#define HYBRID580_R580_LINK_TYPE_NVLINK_3   4u
#define HYBRID580_R580_LINK_TYPE_NVLINK_4   5u
#define HYBRID580_R580_LINK_TYPE_NVLINK_5   6u
#define HYBRID580_R580_LINK_TYPE_C2C        7u

#define HYBRID580_R580_RUNLIST_INTERNAL_DOORBELL_OFFSET 0x090u
#define HYBRID580_R580_RUNLIST_INTERNAL_DOORBELL_CHID_MASK 0x00000fffu

static inline int hybrid580_uvm_r580_link_type_to_r595(
    NvU32 r580_link_type, int has_bar1_dma, NvU32 *r595_link_type)
{
    if (r595_link_type == NULL)
        return 0;

    if (has_bar1_dma) {
        /* R595 requires the BAR1 link classification whenever it reports a
         * BAR1 DMA window. R580 could only label this as PCIe. */
        if (r580_link_type != HYBRID580_R580_LINK_TYPE_PCIE)
            return 0;
        *r595_link_type = UVM_LINK_TYPE_PCIE_BAR1;
        return 1;
    }

    switch (r580_link_type) {
        case HYBRID580_R580_LINK_TYPE_NONE:
            *r595_link_type = UVM_LINK_TYPE_NONE;
            return 1;
        case HYBRID580_R580_LINK_TYPE_PCIE:
            *r595_link_type = UVM_LINK_TYPE_PCIE;
            return 1;
        case HYBRID580_R580_LINK_TYPE_NVLINK_1:
            *r595_link_type = UVM_LINK_TYPE_NVLINK_1;
            return 1;
        case HYBRID580_R580_LINK_TYPE_NVLINK_2:
            *r595_link_type = UVM_LINK_TYPE_NVLINK_2;
            return 1;
        case HYBRID580_R580_LINK_TYPE_NVLINK_3:
            *r595_link_type = UVM_LINK_TYPE_NVLINK_3;
            return 1;
        case HYBRID580_R580_LINK_TYPE_NVLINK_4:
            *r595_link_type = UVM_LINK_TYPE_NVLINK_4;
            return 1;
        case HYBRID580_R580_LINK_TYPE_NVLINK_5:
            *r595_link_type = UVM_LINK_TYPE_NVLINK_5;
            return 1;
        case HYBRID580_R580_LINK_TYPE_C2C:
            *r595_link_type = UVM_LINK_TYPE_C2C;
            return 1;
        default:
            return 0;
    }
}

static inline int hybrid580_uvm_p2p_caps_from_r580(
    UvmGpuP2PCapsParams *r595,
    const struct hybrid580_r580_UvmGpuP2PCapsParams *r580)
{
    NvU32 link_type;
    int has_bar1_dma;

    if (r595 == NULL || r580 == NULL)
        return 0;

    *r595 = (UvmGpuP2PCapsParams){0};
    has_bar1_dma = r580->bar1DmaSize[0] != 0 || r580->bar1DmaSize[1] != 0;
    if (!hybrid580_uvm_r580_link_type_to_r595(r580->p2pLink,
                                               has_bar1_dma,
                                               &link_type))
        return 0;

    r595->peerIds[0] = r580->peerIds[0];
    r595->peerIds[1] = r580->peerIds[1];
    r595->egmPeerIds[0] = r580->egmPeerIds[0];
    r595->egmPeerIds[1] = r580->egmPeerIds[1];
    r595->p2pLink = link_type;
    r595->optimalNvlinkWriteCEs[0] = r580->optimalNvlinkWriteCEs[0];
    r595->optimalNvlinkWriteCEs[1] = r580->optimalNvlinkWriteCEs[1];
    r595->totalLinkLineRateMBps = r580->totalLinkLineRateMBps;
    r595->bar1DmaAddress[0] = r580->bar1DmaAddress[0];
    r595->bar1DmaAddress[1] = r580->bar1DmaAddress[1];
    r595->bar1DmaSize[0] = r580->bar1DmaSize[0];
    r595->bar1DmaSize[1] = r580->bar1DmaSize[1];
    /* R580 has no PCIe atomics capability fields. False is conservative. */
    r595->bar1PcieAtomics[0] = NV_FALSE;
    r595->bar1PcieAtomics[1] = NV_FALSE;
    return 1;
}

static inline void hybrid580_uvm_copy_caps_from_r580(
    UvmGpuCopyEnginesCaps *r595,
    const struct hybrid580_r580_UvmGpuCopyEnginesCaps *r580)
{
    NvU32 i;

    *r595 = (UvmGpuCopyEnginesCaps){0};
    for (i = 0; i < UVM_COPY_ENGINE_COUNT_MAX; ++i) {
        r595->copyEngineCaps[i].supported = r580->copyEngineCaps[i].supported;
        r595->copyEngineCaps[i].grce = r580->copyEngineCaps[i].grce;
        r595->copyEngineCaps[i].shared = r580->copyEngineCaps[i].shared;
        r595->copyEngineCaps[i].sysmemRead = r580->copyEngineCaps[i].sysmemRead;
        r595->copyEngineCaps[i].sysmemWrite = r580->copyEngineCaps[i].sysmemWrite;
        r595->copyEngineCaps[i].sysmem = r580->copyEngineCaps[i].sysmem;
        r595->copyEngineCaps[i].nvlinkP2p = r580->copyEngineCaps[i].nvlinkP2p;
        r595->copyEngineCaps[i].p2p = r580->copyEngineCaps[i].p2p;
        r595->copyEngineCaps[i].secure = r580->copyEngineCaps[i].secure;
        r595->copyEngineCaps[i].scrub = NV_FALSE;
        r595->copyEngineCaps[i].cePceMask = r580->copyEngineCaps[i].cePceMask;
    }
}

static inline int hybrid580_uvm_channel_info_from_r580(
    UvmGpuChannelInstanceInfo *r595,
    const struct hybrid580_r580_UvmGpuChannelInstanceInfo *r580)
{
    NvU32 i;

    if (r595 == NULL || r580 == NULL ||
        r580->resourceCount > UVM_GPU_CHANNEL_MAX_RESOURCES)
        return 0;

    *r595 = (UvmGpuChannelInstanceInfo){0};
    r595->base = r580->base;
    r595->sysmem = r580->sysmem;
    r595->runlistId = r580->runlistId;
    r595->chId = r580->chId;
    r595->bInSubctx = r580->bInSubctx;
    r595->subctxId = r580->subctxId;
    r595->bTsgChannel = r580->bTsgChannel;
    r595->tsgId = r580->tsgId;
    r595->tsgMaxSubctxCount = r580->tsgMaxSubctxCount;
    for (i = 0; i < UVM_GPU_CHANNEL_MAX_RESOURCES; ++i)
        r595->resourceInfo[i] = r580->resourceInfo[i];
    r595->resourceCount = r580->resourceCount;
    r595->channelEngineType = r580->channelEngineType;
    r595->clearFaultedToken = r580->clearFaultedToken;
    r595->pChramChannelRegister = r580->pChramChannelRegister;

    /* R580's pRunlistPRIBaseRegister is a runlist base, not the R595 doorbell
     * address. Mirror R580's source path: base + 0x90 and CHID[11:0]. */
    if (r580->pRunlistPRIBaseRegister != NULL) {
        r595->workSubmissionOffset = (volatile NvU32 *)
            ((NvU8 *)r580->pRunlistPRIBaseRegister +
             HYBRID580_R580_RUNLIST_INTERNAL_DOORBELL_OFFSET);
        r595->workSubmissionToken =
            r580->chId & HYBRID580_R580_RUNLIST_INTERNAL_DOORBELL_CHID_MASK;
    }
    r595->smcEngineId = r580->smcEngineId;
    r595->smcEngineVeIdOffset = r580->smcEngineVeIdOffset;
    return 1;
}

#endif /* HYBRID580_UVM_ABI_COMPAT_H */
