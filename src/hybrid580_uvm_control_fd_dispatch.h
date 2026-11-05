/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_CONTROL_FD_DISPATCH_H
#define HYBRID580_UVM_CONTROL_FD_DISPATCH_H

/* Included after nv_uvm_interface.h, whose types and NV_STATUS are used. */
struct file;
NV_STATUS nvUvmInterfaceDupMemoryWithControlFd(
    int rmControlFd,
    uvmGpuDeviceHandle device,
    NvHandle hClient,
    NvHandle hPhysMemory,
    NvHandle *hDupMemory,
    UvmGpuMemoryInfo *pGpuMemoryInfo);

/* Hybrid-only dispatcher: tie the caller-owned VA-space handles to the exact
 * frontend control file before invoking the matching private RM provider. */
NV_STATUS nvUvmInterfaceDupAddressSpaceWithControlFd(
    struct file *rmControlFile,
    uvmGpuDeviceHandle device,
    NvHandle hClient,
    NvHandle hUserVASpace,
    uvmGpuAddressSpaceHandle *vaSpace,
    UvmGpuAddressSpaceInfo *vaSpaceInfo);

#endif
