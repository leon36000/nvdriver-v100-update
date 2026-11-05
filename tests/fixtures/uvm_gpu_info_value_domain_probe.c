/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stddef.h>

#include "nvmisc.h"
#include "nv_uvm_types.h"
#include "nv_uvm_user_types.h"
#include "ctrl2080mc.h"

static void print_offset_field(const char *name, size_t offset, int *first)
{
    if (!*first)
        putchar(',');
    printf("\"%s\":%zu", name, offset);
    *first = 0;
}

int main(void)
{
    int first = 1;
    printf("{\"gpu_info_size\":%zu,\"gpu_info_offsets\":{",
           sizeof(UvmGpuInfo));
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
    printf("},\"gpu_arch_gv100\":%u,",
           (unsigned)NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100);
    printf("\"virt_mode\":{\"none\":%u,\"legacy\":%u,"
           "\"sriov_heavy\":%u,\"sriov_standard\":%u,\"count\":%u},",
           (unsigned)UVM_VIRT_MODE_NONE,
           (unsigned)UVM_VIRT_MODE_LEGACY,
           (unsigned)UVM_VIRT_MODE_SRIOV_HEAVY,
           (unsigned)UVM_VIRT_MODE_SRIOV_STANDARD,
           (unsigned)UVM_VIRT_MODE_COUNT);
    printf("\"sysmem_link\":{\"none\":%u,\"pcie\":%u,",
           (unsigned)UVM_LINK_TYPE_NONE,
           (unsigned)UVM_LINK_TYPE_PCIE);
#ifdef HYBRID_BRANCH_R595
    printf("\"pcie_bar1\":%u,", (unsigned)UVM_LINK_TYPE_PCIE_BAR1);
#endif
    printf("\"nvlink1\":%u,\"nvlink2\":%u,\"nvlink3\":%u,"
           "\"nvlink4\":%u,\"nvlink5\":%u,\"c2c\":%u}}\n",
           (unsigned)UVM_LINK_TYPE_NVLINK_1,
           (unsigned)UVM_LINK_TYPE_NVLINK_2,
           (unsigned)UVM_LINK_TYPE_NVLINK_3,
           (unsigned)UVM_LINK_TYPE_NVLINK_4,
           (unsigned)UVM_LINK_TYPE_NVLINK_5,
           (unsigned)UVM_LINK_TYPE_C2C);
    return 0;
}
