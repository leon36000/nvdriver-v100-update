/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_UVM_PROVIDER_DISPATCH_H
#define HYBRID580_UVM_PROVIDER_DISPATCH_H

/* Included after nv_uvm_interface.h, whose types and NV_STATUS are used. */
#define HYBRID580_UVM_PROVIDER_ID_OPEN   1U
#define HYBRID580_UVM_PROVIDER_ID_LEGACY 2U

/* Get the immutable frontend owner for a registered GPU UUID. This call takes
 * the bridge mutex and must only run in registration/setup paths, never while
 * a UVM tracker, VA-block, or PMM lock is held. */
NV_STATUS nvUvmInterfaceGetGpuProvider(
    const NvProcessorUuid *gpuUuid,
    NvU32 *providerId);

NV_STATUS nvUvmInterfaceAreGpuProvidersSame(
    const NvProcessorUuid *gpuUuid1,
    const NvProcessorUuid *gpuUuid2,
    NvBool *sameProvider);

#endif
