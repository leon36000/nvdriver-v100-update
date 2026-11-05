/* SPDX-License-Identifier: MIT */
/* A declaration in this comment must not be counted:
   NV_STATUS nvUvmInterfaceFake(uvmGpuDeviceHandle device);
*/
NV_STATUS nvUvmInterfaceSessionCreate(uvmGpuSessionHandle *session,
                                     UvmPlatformInfo *platformInfo);
NV_STATUS nvUvmInterfaceDeviceCreate(uvmGpuSessionHandle session,
                                    const NvProcessorUuid *gpuUuid,
                                    uvmGpuDeviceHandle *device);
NV_STATUS nvUvmInterfaceGetP2PCaps(uvmGpuDeviceHandle device1,
                                   uvmGpuDeviceHandle device2,
                                   UvmP2PCaps *caps);
NV_STATUS nvUvmInterfaceQueryCaps(uvmGpuDeviceHandle device,
                                 UvmGpuCaps *caps);
NV_STATUS nvUvmInterfaceRegisterGpu(const NvProcessorUuid *gpuUuid,
                                    UvmGpuPlatformInfo *gpuInfo);
void nvUvmInterfaceRegisterUvmCallbacks(struct UvmOpsUvmEvents *ops);
NV_STATUS nvUvmInterfaceGetPmaObject(uvmGpuDeviceHandle device, void **pPma,
                                    const UvmPmaStatistics **stats);
NV_STATUS nvUvmInterfacePmaAllocPages(void *pPma, NvLength pageCount);
NV_STATUS nvUvmInterfacePmaRegisterEvictionCallbacks(void *pPma,
                                    uvmPmaEvictPagesCallback evictPages,
                                    void *callbackData);
NV_STATUS nvUvmInterfaceFlushReplayableFaultBuffer(UvmGpuFaultInfo *pFaultInfo,
                                                   NvBool bCopyAndFlush);
NV_STATUS nvUvmInterfaceCslInitContext(UvmCslContext *context,
                                       uvmGpuChannelHandle channel);
NV_STATUS nvUvmInterfaceCslEncrypt(UvmCslContext *context, NvU32 size,
                                   NvU8 *input, NvU8 *output);
