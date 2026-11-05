/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>
#include "nvmisc.h"
#include "nv_uvm_types.h"
#include "nv_uvm_user_types.h"

static void print_offset_field(const char *name, size_t offset, int *first)
{
    if (!*first)
        putchar(',');
    printf("\"%s\":%zu", name, offset);
    *first = 0;
}

int main(void)
{
    int first;

    printf("{\"p2p_size\":%zu,", sizeof(UvmGpuP2PCapsParams));
#ifdef HYBRID_BRANCH_R595
    printf("\"link_pcie_bar1\":%u,", UVM_LINK_TYPE_PCIE_BAR1);
#endif
    printf("\"link_pcie\":%u,", UVM_LINK_TYPE_PCIE);
    printf("\"link_nvlink1\":%u,", UVM_LINK_TYPE_NVLINK_1);
    printf("\"link_c2c\":%u,", UVM_LINK_TYPE_C2C);
    printf("\"copy_caps_size\":%zu,", sizeof(UvmGpuCopyEngineCaps));
    printf("\"copy_mask_offset\":%zu,", offsetof(UvmGpuCopyEngineCaps, cePceMask));
    printf("\"channel_size\":%zu,", sizeof(UvmGpuChannelInstanceInfo));
#ifdef HYBRID_BRANCH_R595
    printf("\"channel_divergence_offset\":%zu,",
           offsetof(UvmGpuChannelInstanceInfo, workSubmissionOffset));
#else
    printf("\"channel_divergence_offset\":%zu,",
           offsetof(UvmGpuChannelInstanceInfo, pRunlistPRIBaseRegister));
#endif
    printf("\"pma_size\":%zu,", sizeof(UvmPmaStatistics));
    printf("\"pma_free64k_offset\":%zu,",
           offsetof(UvmPmaStatistics, numFreePages64k));
    printf("\"pma_free2m_offset\":%zu,",
           offsetof(UvmPmaStatistics, numFreePages2m));
#ifdef HYBRID_BRANCH_R595
    printf("\"event_table_size\":%zu,",
           sizeof(struct UvmEventsLinux));
    printf("\"event_isr_top_half_offset\":%zu,",
           offsetof(struct UvmEventsLinux, isrTopHalf));
    printf("\"event_suspend_offset\":%zu,",
           offsetof(struct UvmEventsLinux, suspend));
    printf("\"event_resume_offset\":%zu,",
           offsetof(struct UvmEventsLinux, resume));
    printf("\"event_drain_p2p_offset\":%zu,",
           offsetof(struct UvmEventsLinux, drainP2P));
    printf("\"event_resume_p2p_offset\":%zu,",
           offsetof(struct UvmEventsLinux, resumeP2P));
#else
    printf("\"event_table_size\":%zu,",
           sizeof(struct UvmOpsUvmEvents));
    printf("\"event_suspend_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, suspend));
    printf("\"event_resume_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, resume));
    printf("\"event_start_device_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, startDevice));
    printf("\"event_stop_device_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, stopDevice));
    printf("\"event_isr_top_half_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, isrTopHalf));
    printf("\"event_drain_p2p_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, drainP2P));
    printf("\"event_resume_p2p_offset\":%zu,",
           offsetof(struct UvmOpsUvmEvents, resumeP2P));
#endif
    printf("\"gpu_info_size\":%zu,\"gpu_info_offsets\":{",
           sizeof(UvmGpuInfo));
    first = 1;
#define PRINT_GPU_INFO_OFFSET(field) \
    print_offset_field(#field, offsetof(UvmGpuInfo, field), &first)
    PRINT_GPU_INFO_OFFSET(name);
    PRINT_GPU_INFO_OFFSET(uuid);
    PRINT_GPU_INFO_OFFSET(gpuArch);
    PRINT_GPU_INFO_OFFSET(gpuImplementation);
    PRINT_GPU_INFO_OFFSET(hostClass);
    PRINT_GPU_INFO_OFFSET(ceClass);
    PRINT_GPU_INFO_OFFSET(computeClass);
    PRINT_GPU_INFO_OFFSET(gpuInTcc);
    PRINT_GPU_INFO_OFFSET(subdeviceCount);
    PRINT_GPU_INFO_OFFSET(virtMode);
    PRINT_GPU_INFO_OFFSET(isSimulated);
    PRINT_GPU_INFO_OFFSET(gpcCount);
    PRINT_GPU_INFO_OFFSET(maxGpcCount);
    PRINT_GPU_INFO_OFFSET(tpcCount);
    PRINT_GPU_INFO_OFFSET(maxTpcPerGpcCount);
    PRINT_GPU_INFO_OFFSET(accessCntrBufferCount);
    PRINT_GPU_INFO_OFFSET(smcEnabled);
    PRINT_GPU_INFO_OFFSET(smcSwizzId);
    PRINT_GPU_INFO_OFFSET(smcUserClientInfo);
    PRINT_GPU_INFO_OFFSET(gpuConfComputeCaps);
    PRINT_GPU_INFO_OFFSET(sysmemLink);
    PRINT_GPU_INFO_OFFSET(sysmemLinkRateMBps);
    PRINT_GPU_INFO_OFFSET(systemMemoryWindowStart);
    PRINT_GPU_INFO_OFFSET(systemMemoryWindowSize);
    PRINT_GPU_INFO_OFFSET(connectedToSwitch);
    PRINT_GPU_INFO_OFFSET(nvswitchMemoryWindowStart);
    PRINT_GPU_INFO_OFFSET(egmEnabled);
    PRINT_GPU_INFO_OFFSET(egmPeerId);
    PRINT_GPU_INFO_OFFSET(egmBaseAddr);
    PRINT_GPU_INFO_OFFSET(nvswitchEgmMemoryWindowStart);
    PRINT_GPU_INFO_OFFSET(atsSupport);
    PRINT_GPU_INFO_OFFSET(nonPasidAtsSupport);
    PRINT_GPU_INFO_OFFSET(cdmmEnabled);
    PRINT_GPU_INFO_OFFSET(nvlDirectConnect);
    PRINT_GPU_INFO_OFFSET(nvlDirectConnectMemoryWindowStart);
#undef PRINT_GPU_INFO_OFFSET
    printf("},\"gpu_client_info_size\":%zu,\"gpu_client_info_offsets\":{",
           sizeof(UvmGpuClientInfo));
    first = 1;
    print_offset_field("hClient", offsetof(UvmGpuClientInfo, hClient), &first);
    print_offset_field("hSmcPartRef", offsetof(UvmGpuClientInfo, hSmcPartRef), &first);
    printf("},\"gpu_conf_caps_size\":%zu,\"gpu_conf_caps_offsets\":{",
           sizeof(UvmGpuConfComputeCaps));
    first = 1;
    print_offset_field("bConfComputingEnabled",
                       offsetof(UvmGpuConfComputeCaps, bConfComputingEnabled), &first);
    print_offset_field("bKeyRotationEnabled",
                       offsetof(UvmGpuConfComputeCaps, bKeyRotationEnabled), &first);
    printf("},\"fb_info_size\":%zu,\"fb_info_offsets\":{",
           sizeof(UvmGpuFbInfo));
    first = 1;
#define PRINT_FB_INFO_OFFSET(field) \
    print_offset_field(#field, offsetof(UvmGpuFbInfo, field), &first)
    PRINT_FB_INFO_OFFSET(maxAllocatableAddress);
    PRINT_FB_INFO_OFFSET(heapSize);
    PRINT_FB_INFO_OFFSET(reservedHeapSize);
    PRINT_FB_INFO_OFFSET(bZeroFb);
    PRINT_FB_INFO_OFFSET(maxVidmemPageSize);
    PRINT_FB_INFO_OFFSET(bStaticBar1Enabled);
    PRINT_FB_INFO_OFFSET(bStaticBar1WriteCombined);
    PRINT_FB_INFO_OFFSET(staticBar1StartOffset);
    PRINT_FB_INFO_OFFSET(staticBar1Size);
    PRINT_FB_INFO_OFFSET(heapStart);
#undef PRINT_FB_INFO_OFFSET
    printf("},\"pma_options_size\":%zu,\"pma_options_offsets\":{",
           sizeof(UvmPmaAllocationOptions));
    first = 1;
#define PRINT_PMA_OPTION_OFFSET(field) \
    print_offset_field(#field, offsetof(UvmPmaAllocationOptions, field), &first)
    PRINT_PMA_OPTION_OFFSET(flags);
    PRINT_PMA_OPTION_OFFSET(minimumSpeed);
    PRINT_PMA_OPTION_OFFSET(physBegin);
    PRINT_PMA_OPTION_OFFSET(physEnd);
    PRINT_PMA_OPTION_OFFSET(regionId);
    PRINT_PMA_OPTION_OFFSET(alignment);
    PRINT_PMA_OPTION_OFFSET(numPagesAllocated);
    PRINT_PMA_OPTION_OFFSET(resultFlags);
#undef PRINT_PMA_OPTION_OFFSET
    printf("},\"pma_allocation_flags\":{");
    first = 1;
#define PRINT_PMA_FLAG(name) \
    print_offset_field(#name, (size_t)UVM_PMA_##name, &first)
    PRINT_PMA_FLAG(ALLOCATE_ALLOW_PARTIAL);
    PRINT_PMA_FLAG(ALLOCATE_CONTIGUOUS);
    PRINT_PMA_FLAG(ALLOCATE_DONT_EVICT);
    PRINT_PMA_FLAG(ALLOCATE_NO_ZERO);
    PRINT_PMA_FLAG(ALLOCATE_PINNED);
    PRINT_PMA_FLAG(ALLOCATE_PROTECTED_REGION);
    PRINT_PMA_FLAG(ALLOCATE_RESULT_IS_ZERO);
    PRINT_PMA_FLAG(ALLOCATE_SPECIFY_ADDRESS_RANGE);
#undef PRINT_PMA_FLAG
    printf("},");
    printf("\"channel_resource_size\":%zu,", sizeof(UvmGpuChannelResourceInfo));
    printf("\"fault_metadata_size\":%zu,\"fault_metadata_offsets\":{",
           sizeof(UvmFaultMetadataPacket));
    first = 1;
    print_offset_field("authTag", offsetof(UvmFaultMetadataPacket, authTag), &first);
    print_offset_field("valid", offsetof(UvmFaultMetadataPacket, valid), &first);
    printf("},\"csl_context_size\":%zu,\"csl_context_offsets\":{",
           sizeof(UvmCslContext));
    first = 1;
    print_offset_field("ctx", offsetof(UvmCslContext, ctx), &first);
    print_offset_field("nvidia_stack", offsetof(UvmCslContext, nvidia_stack), &first);
    printf("},\"fault_info_size\":%zu,\"fault_info_top_offsets\":{",
           sizeof(UvmGpuFaultInfo));
    first = 1;
    print_offset_field("replayable", offsetof(UvmGpuFaultInfo, replayable), &first);
    print_offset_field("nonReplayable", offsetof(UvmGpuFaultInfo, nonReplayable), &first);
    print_offset_field("faultBufferHandle",
                       offsetof(UvmGpuFaultInfo, faultBufferHandle), &first);
    print_offset_field("pDevice", offsetof(UvmGpuFaultInfo, pDevice), &first);
    printf("},\"fault_info_replayable_size\":%zu,\"fault_info_replayable_offsets\":{",
           sizeof(((UvmGpuFaultInfo *)0)->replayable));
    first = 1;
#define PRINT_REPLAYABLE_FAULT_OFFSET(field) \
    print_offset_field(#field, \
                       offsetof(UvmGpuFaultInfo, replayable.field) - \
                           offsetof(UvmGpuFaultInfo, replayable), &first)
    PRINT_REPLAYABLE_FAULT_OFFSET(pFaultBufferGet);
    PRINT_REPLAYABLE_FAULT_OFFSET(pFaultBufferPut);
    PRINT_REPLAYABLE_FAULT_OFFSET(pFaultBufferInfo);
    PRINT_REPLAYABLE_FAULT_OFFSET(pPmcIntr);
    PRINT_REPLAYABLE_FAULT_OFFSET(pPmcIntrEnSet);
    PRINT_REPLAYABLE_FAULT_OFFSET(pPmcIntrEnClear);
    PRINT_REPLAYABLE_FAULT_OFFSET(pPrefetchCtrl);
    PRINT_REPLAYABLE_FAULT_OFFSET(replayableFaultMask);
    PRINT_REPLAYABLE_FAULT_OFFSET(bufferAddress);
    PRINT_REPLAYABLE_FAULT_OFFSET(bufferSize);
    PRINT_REPLAYABLE_FAULT_OFFSET(bufferMetadata);
    PRINT_REPLAYABLE_FAULT_OFFSET(cslCtx);
#undef PRINT_REPLAYABLE_FAULT_OFFSET
    printf("},\"fault_info_nonreplayable_size\":%zu,\"fault_info_nonreplayable_offsets\":{",
           sizeof(((UvmGpuFaultInfo *)0)->nonReplayable));
    first = 1;
#define PRINT_NONREPLAYABLE_FAULT_OFFSET(field) \
    print_offset_field(#field, \
                       offsetof(UvmGpuFaultInfo, nonReplayable.field) - \
                           offsetof(UvmGpuFaultInfo, nonReplayable), &first)
    PRINT_NONREPLAYABLE_FAULT_OFFSET(shadowBufferAddress);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(shadowBufferContext);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(bufferSize);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(isr_sp);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(isr_bh_sp);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(pFaultBufferPut);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(shadowBufferGet);
    PRINT_NONREPLAYABLE_FAULT_OFFSET(shadowBufferMetadata);
#undef PRINT_NONREPLAYABLE_FAULT_OFFSET
    printf("}}\n");
    return 0;
}
