/* SPDX-License-Identifier: MIT */
/*
 * Partial standard-name UVM bridge: fan out the callback-table registration
 * and logical session lifetime to both private R580 RMs, while routing each
 * GPU UUID and registration lifetime to its owning RM. Remaining
 * nvUvmInterface exports still need typed owner routing.
 */
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "nv_uvm_interface.h"
#pragma GCC diagnostic pop
#include "hybrid580_uvm_control_fd_dispatch.h"
#ifndef HYBRID580_UVM_ABI_R580
#include "hybrid580_uvm_abi_compat.h"
#include "hybrid580_uvm_event_compat.h"
#endif
#include "hybrid580_uvm_callback_bridge.h"
#include "hybrid580_uvm_session_pair.h"
#include "hybrid580_uvm_gpu_route.h"
#include "hybrid580_uvm_provider_dispatch.h"
#include "hybrid580_uvm_device_route.h"
#include "hybrid580_uvm_address_space_route.h"
#include "hybrid580_uvm_typed_child_route.h"
#include "hybrid580_uvm_dup_memory_route.h"
#include "hybrid580_uvm_p2p_object_route.h"
#include "hybrid580_uvm_pma_route.h"
#include "hybrid580_uvm_external_mapping_route.h"
#include "hybrid580_uvm_info_registry.h"
#include "hybrid580_frontend_uvm_memory_owner.h"
#include "hybrid580_frontend_uvm_address_space_owner.h"

#ifdef HYBRID580_UVM_ABI_R580
extern __typeof__(nvUvmInterfaceRegisterUvmCallbacks)
    hybrid580_open_nvUvmInterfaceRegisterUvmCallbacks;
extern __typeof__(nvUvmInterfaceRegisterUvmCallbacks)
    hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks;
extern __typeof__(nvUvmInterfaceDeRegisterUvmOps)
    hybrid580_open_nvUvmInterfaceDeRegisterUvmOps;
extern __typeof__(nvUvmInterfaceDeRegisterUvmOps)
    hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps;
#else
extern __typeof__(nvUvmInterfaceRegisterUvmEvents)
    hybrid580_open_nvUvmInterfaceRegisterUvmEvents;
extern __typeof__(nvUvmInterfaceDeRegisterUvmEvents)
    hybrid580_open_nvUvmInterfaceDeRegisterUvmEvents;
extern NV_STATUS hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks(
    struct UvmOpsUvmEvents *importedUvmOps);
extern void hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps(void);
#endif
extern __typeof__(nvUvmInterfaceSessionCreate)
    hybrid580_open_nvUvmInterfaceSessionCreate;
extern __typeof__(nvUvmInterfaceSessionCreate)
    hybrid580_legacy_nvUvmInterfaceSessionCreate;
extern __typeof__(nvUvmInterfaceSessionDestroy)
    hybrid580_open_nvUvmInterfaceSessionDestroy;
extern __typeof__(nvUvmInterfaceSessionDestroy)
    hybrid580_legacy_nvUvmInterfaceSessionDestroy;
extern __typeof__(nvUvmInterfaceRegisterGpu)
    hybrid580_open_nvUvmInterfaceRegisterGpu;
extern __typeof__(nvUvmInterfaceRegisterGpu)
    hybrid580_legacy_nvUvmInterfaceRegisterGpu;
extern __typeof__(nvUvmInterfaceUnregisterGpu)
    hybrid580_open_nvUvmInterfaceUnregisterGpu;
extern __typeof__(nvUvmInterfaceUnregisterGpu)
    hybrid580_legacy_nvUvmInterfaceUnregisterGpu;
extern __typeof__(nvUvmInterfaceGetGpuInfo)
    hybrid580_open_nvUvmInterfaceGetGpuInfo;
extern __typeof__(nvUvmInterfaceGetGpuInfo)
    hybrid580_legacy_nvUvmInterfaceGetGpuInfo;
extern __typeof__(nvUvmInterfaceDeviceCreate)
    hybrid580_open_nvUvmInterfaceDeviceCreate;
extern __typeof__(nvUvmInterfaceDeviceCreate)
    hybrid580_legacy_nvUvmInterfaceDeviceCreate;
extern __typeof__(nvUvmInterfaceDeviceDestroy)
    hybrid580_open_nvUvmInterfaceDeviceDestroy;
extern __typeof__(nvUvmInterfaceDeviceDestroy)
    hybrid580_legacy_nvUvmInterfaceDeviceDestroy;
extern __typeof__(nvUvmInterfaceGetFbInfo)
    hybrid580_open_nvUvmInterfaceGetFbInfo;
extern __typeof__(nvUvmInterfaceGetFbInfo)
    hybrid580_legacy_nvUvmInterfaceGetFbInfo;
extern __typeof__(nvUvmInterfaceQueryCaps)
    hybrid580_open_nvUvmInterfaceQueryCaps;
extern __typeof__(nvUvmInterfaceQueryCaps)
    hybrid580_legacy_nvUvmInterfaceQueryCaps;
extern __typeof__(nvUvmInterfaceQueryCopyEnginesCaps)
    hybrid580_open_nvUvmInterfaceQueryCopyEnginesCaps;
#ifdef HYBRID580_UVM_ABI_R580
extern __typeof__(nvUvmInterfaceQueryCopyEnginesCaps)
    hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps;
#else
extern NV_STATUS hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps(
    uvmGpuDeviceHandle device,
    struct hybrid580_r580_UvmGpuCopyEnginesCaps *caps);
#endif
extern __typeof__(nvUvmInterfaceGetEccInfo)
    hybrid580_open_nvUvmInterfaceGetEccInfo;
extern __typeof__(nvUvmInterfaceGetEccInfo)
    hybrid580_legacy_nvUvmInterfaceGetEccInfo;
extern __typeof__(nvUvmInterfaceGetNvlinkInfo)
    hybrid580_open_nvUvmInterfaceGetNvlinkInfo;
extern __typeof__(nvUvmInterfaceGetNvlinkInfo)
    hybrid580_legacy_nvUvmInterfaceGetNvlinkInfo;
#ifndef HYBRID580_UVM_ABI_R580
/* R595-only access-bits APIs: the R580 RM has no corresponding interface. */
extern __typeof__(nvUvmInterfaceAccessBitsBufAlloc)
    hybrid580_open_nvUvmInterfaceAccessBitsBufAlloc;
extern __typeof__(nvUvmInterfaceAccessBitsBufFree)
    hybrid580_open_nvUvmInterfaceAccessBitsBufFree;
extern __typeof__(nvUvmInterfaceAccessBitsDump)
    hybrid580_open_nvUvmInterfaceAccessBitsDump;
#endif
extern __typeof__(nvUvmInterfaceGetP2PCaps)
    hybrid580_open_nvUvmInterfaceGetP2PCaps;
#ifdef HYBRID580_UVM_ABI_R580
extern __typeof__(nvUvmInterfaceGetP2PCaps)
    hybrid580_legacy_nvUvmInterfaceGetP2PCaps;
#else
extern NV_STATUS hybrid580_legacy_nvUvmInterfaceGetP2PCaps(
    uvmGpuDeviceHandle device1,
    uvmGpuDeviceHandle device2,
    struct hybrid580_r580_UvmGpuP2PCapsParams *p2pCapsParams);
#endif
extern __typeof__(nvUvmInterfaceP2pObjectCreate)
    hybrid580_open_nvUvmInterfaceP2pObjectCreate;
extern __typeof__(nvUvmInterfaceP2pObjectCreate)
    hybrid580_legacy_nvUvmInterfaceP2pObjectCreate;
extern __typeof__(nvUvmInterfaceP2pObjectDestroy)
    hybrid580_open_nvUvmInterfaceP2pObjectDestroy;
extern __typeof__(nvUvmInterfaceP2pObjectDestroy)
    hybrid580_legacy_nvUvmInterfaceP2pObjectDestroy;
extern __typeof__(nvUvmInterfaceGetPmaObject)
    hybrid580_open_nvUvmInterfaceGetPmaObject;
extern __typeof__(nvUvmInterfaceGetPmaObject)
    hybrid580_legacy_nvUvmInterfaceGetPmaObject;
extern __typeof__(nvUvmInterfacePmaRegisterEvictionCallbacks)
    hybrid580_open_nvUvmInterfacePmaRegisterEvictionCallbacks;
extern __typeof__(nvUvmInterfacePmaRegisterEvictionCallbacks)
    hybrid580_legacy_nvUvmInterfacePmaRegisterEvictionCallbacks;
extern __typeof__(nvUvmInterfacePmaUnregisterEvictionCallbacks)
    hybrid580_open_nvUvmInterfacePmaUnregisterEvictionCallbacks;
extern __typeof__(nvUvmInterfacePmaUnregisterEvictionCallbacks)
    hybrid580_legacy_nvUvmInterfacePmaUnregisterEvictionCallbacks;
extern __typeof__(nvUvmInterfacePmaAllocPages)
    hybrid580_open_nvUvmInterfacePmaAllocPages;
extern __typeof__(nvUvmInterfacePmaAllocPages)
    hybrid580_legacy_nvUvmInterfacePmaAllocPages;
extern __typeof__(nvUvmInterfacePmaPinPages)
    hybrid580_open_nvUvmInterfacePmaPinPages;
extern __typeof__(nvUvmInterfacePmaPinPages)
    hybrid580_legacy_nvUvmInterfacePmaPinPages;
extern __typeof__(nvUvmInterfacePmaFreePages)
    hybrid580_open_nvUvmInterfacePmaFreePages;
extern __typeof__(nvUvmInterfacePmaFreePages)
    hybrid580_legacy_nvUvmInterfacePmaFreePages;
extern __typeof__(nvUvmInterfaceGetExternalAllocPtes)
    hybrid580_open_nvUvmInterfaceGetExternalAllocPtes;
extern __typeof__(nvUvmInterfaceGetExternalAllocPtes)
    hybrid580_legacy_nvUvmInterfaceGetExternalAllocPtes;
extern __typeof__(nvUvmInterfaceGetExternalAllocPhysAddrs)
    hybrid580_open_nvUvmInterfaceGetExternalAllocPhysAddrs;
extern __typeof__(nvUvmInterfaceGetExternalAllocPhysAddrs)
    hybrid580_legacy_nvUvmInterfaceGetExternalAllocPhysAddrs;
extern __typeof__(nvUvmInterfaceInitFaultInfo)
    hybrid580_open_nvUvmInterfaceInitFaultInfo;
extern __typeof__(nvUvmInterfaceInitFaultInfo)
    hybrid580_legacy_nvUvmInterfaceInitFaultInfo;
extern __typeof__(nvUvmInterfaceDestroyFaultInfo)
    hybrid580_open_nvUvmInterfaceDestroyFaultInfo;
extern __typeof__(nvUvmInterfaceDestroyFaultInfo)
    hybrid580_legacy_nvUvmInterfaceDestroyFaultInfo;
extern __typeof__(nvUvmInterfaceHasPendingNonReplayableFaults)
    hybrid580_open_nvUvmInterfaceHasPendingNonReplayableFaults;
extern __typeof__(nvUvmInterfaceHasPendingNonReplayableFaults)
    hybrid580_legacy_nvUvmInterfaceHasPendingNonReplayableFaults;
extern __typeof__(nvUvmInterfaceGetNonReplayableFaults)
    hybrid580_open_nvUvmInterfaceGetNonReplayableFaults;
extern __typeof__(nvUvmInterfaceGetNonReplayableFaults)
    hybrid580_legacy_nvUvmInterfaceGetNonReplayableFaults;
extern __typeof__(nvUvmInterfaceFlushReplayableFaultBuffer)
    hybrid580_open_nvUvmInterfaceFlushReplayableFaultBuffer;
extern __typeof__(nvUvmInterfaceFlushReplayableFaultBuffer)
    hybrid580_legacy_nvUvmInterfaceFlushReplayableFaultBuffer;
extern __typeof__(nvUvmInterfaceTogglePrefetchFaults)
    hybrid580_open_nvUvmInterfaceTogglePrefetchFaults;
extern __typeof__(nvUvmInterfaceTogglePrefetchFaults)
    hybrid580_legacy_nvUvmInterfaceTogglePrefetchFaults;
extern __typeof__(nvUvmInterfaceInitAccessCntrInfo)
    hybrid580_open_nvUvmInterfaceInitAccessCntrInfo;
extern __typeof__(nvUvmInterfaceInitAccessCntrInfo)
    hybrid580_legacy_nvUvmInterfaceInitAccessCntrInfo;
extern __typeof__(nvUvmInterfaceDestroyAccessCntrInfo)
    hybrid580_open_nvUvmInterfaceDestroyAccessCntrInfo;
extern __typeof__(nvUvmInterfaceDestroyAccessCntrInfo)
    hybrid580_legacy_nvUvmInterfaceDestroyAccessCntrInfo;
extern __typeof__(nvUvmInterfaceEnableAccessCntr)
    hybrid580_open_nvUvmInterfaceEnableAccessCntr;
extern __typeof__(nvUvmInterfaceEnableAccessCntr)
    hybrid580_legacy_nvUvmInterfaceEnableAccessCntr;
extern __typeof__(nvUvmInterfaceDisableAccessCntr)
    hybrid580_open_nvUvmInterfaceDisableAccessCntr;
extern __typeof__(nvUvmInterfaceDisableAccessCntr)
    hybrid580_legacy_nvUvmInterfaceDisableAccessCntr;
extern __typeof__(nvUvmInterfaceReportNonReplayableFault)
    hybrid580_open_nvUvmInterfaceReportNonReplayableFault;
extern __typeof__(nvUvmInterfaceReportNonReplayableFault)
    hybrid580_legacy_nvUvmInterfaceReportNonReplayableFault;
extern __typeof__(nvUvmInterfaceReportFatalError)
    hybrid580_open_nvUvmInterfaceReportFatalError;
extern __typeof__(nvUvmInterfaceReportFatalError)
    hybrid580_legacy_nvUvmInterfaceReportFatalError;
extern __typeof__(nvUvmInterfaceCslInitContext)
    hybrid580_open_nvUvmInterfaceCslInitContext;
extern __typeof__(nvUvmInterfaceCslInitContext)
    hybrid580_legacy_nvUvmInterfaceCslInitContext;
extern __typeof__(nvUvmInterfaceDeinitCslContext)
    hybrid580_open_nvUvmInterfaceDeinitCslContext;
extern __typeof__(nvUvmInterfaceDeinitCslContext)
    hybrid580_legacy_nvUvmInterfaceDeinitCslContext;
extern __typeof__(nvUvmInterfaceCslRotateKey)
    hybrid580_open_nvUvmInterfaceCslRotateKey;
extern __typeof__(nvUvmInterfaceCslRotateKey)
    hybrid580_legacy_nvUvmInterfaceCslRotateKey;
extern __typeof__(nvUvmInterfaceCslRotateIv)
    hybrid580_open_nvUvmInterfaceCslRotateIv;
extern __typeof__(nvUvmInterfaceCslRotateIv)
    hybrid580_legacy_nvUvmInterfaceCslRotateIv;
extern __typeof__(nvUvmInterfaceCslEncrypt)
    hybrid580_open_nvUvmInterfaceCslEncrypt;
extern __typeof__(nvUvmInterfaceCslEncrypt)
    hybrid580_legacy_nvUvmInterfaceCslEncrypt;
extern __typeof__(nvUvmInterfaceCslDecrypt)
    hybrid580_open_nvUvmInterfaceCslDecrypt;
extern __typeof__(nvUvmInterfaceCslDecrypt)
    hybrid580_legacy_nvUvmInterfaceCslDecrypt;
extern __typeof__(nvUvmInterfaceCslSign)
    hybrid580_open_nvUvmInterfaceCslSign;
extern __typeof__(nvUvmInterfaceCslSign)
    hybrid580_legacy_nvUvmInterfaceCslSign;
extern __typeof__(nvUvmInterfaceCslQueryMessagePool)
    hybrid580_open_nvUvmInterfaceCslQueryMessagePool;
extern __typeof__(nvUvmInterfaceCslQueryMessagePool)
    hybrid580_legacy_nvUvmInterfaceCslQueryMessagePool;
extern __typeof__(nvUvmInterfaceCslIncrementIv)
    hybrid580_open_nvUvmInterfaceCslIncrementIv;
extern __typeof__(nvUvmInterfaceCslIncrementIv)
    hybrid580_legacy_nvUvmInterfaceCslIncrementIv;
extern __typeof__(nvUvmInterfaceCslLogEncryption)
    hybrid580_open_nvUvmInterfaceCslLogEncryption;
extern __typeof__(nvUvmInterfaceCslLogEncryption)
    hybrid580_legacy_nvUvmInterfaceCslLogEncryption;
extern __typeof__(nvUvmInterfaceAddressSpaceCreate)
    hybrid580_open_nvUvmInterfaceAddressSpaceCreate;
extern __typeof__(nvUvmInterfaceAddressSpaceCreate)
    hybrid580_legacy_nvUvmInterfaceAddressSpaceCreate;
extern __typeof__(nvUvmInterfaceDupAddressSpace)
    hybrid580_open_nvUvmInterfaceDupAddressSpace;
extern __typeof__(nvUvmInterfaceDupAddressSpace)
    hybrid580_legacy_nvUvmInterfaceDupAddressSpace;
extern __typeof__(nvUvmInterfaceDupAllocation)
    hybrid580_open_nvUvmInterfaceDupAllocation;
extern __typeof__(nvUvmInterfaceDupAllocation)
    hybrid580_legacy_nvUvmInterfaceDupAllocation;
extern __typeof__(nvUvmInterfaceAddressSpaceDestroy)
    hybrid580_open_nvUvmInterfaceAddressSpaceDestroy;
extern __typeof__(nvUvmInterfaceAddressSpaceDestroy)
    hybrid580_legacy_nvUvmInterfaceAddressSpaceDestroy;
extern __typeof__(nvUvmInterfaceSetPageDirectory)
    hybrid580_open_nvUvmInterfaceSetPageDirectory;
extern __typeof__(nvUvmInterfaceSetPageDirectory)
    hybrid580_legacy_nvUvmInterfaceSetPageDirectory;
extern __typeof__(nvUvmInterfaceUnsetPageDirectory)
    hybrid580_open_nvUvmInterfaceUnsetPageDirectory;
extern __typeof__(nvUvmInterfaceUnsetPageDirectory)
    hybrid580_legacy_nvUvmInterfaceUnsetPageDirectory;
extern __typeof__(nvUvmInterfaceOwnPageFaultIntr)
    hybrid580_open_nvUvmInterfaceOwnPageFaultIntr;
extern __typeof__(nvUvmInterfaceOwnPageFaultIntr)
    hybrid580_legacy_nvUvmInterfaceOwnPageFaultIntr;
extern __typeof__(nvUvmInterfaceServiceDeviceInterruptsRM)
    hybrid580_open_nvUvmInterfaceServiceDeviceInterruptsRM;
extern __typeof__(nvUvmInterfaceServiceDeviceInterruptsRM)
    hybrid580_legacy_nvUvmInterfaceServiceDeviceInterruptsRM;
extern __typeof__(nvUvmInterfaceMemoryAllocFB)
    hybrid580_open_nvUvmInterfaceMemoryAllocFB;
extern __typeof__(nvUvmInterfaceMemoryAllocFB)
    hybrid580_legacy_nvUvmInterfaceMemoryAllocFB;
extern __typeof__(nvUvmInterfaceMemoryAllocSys)
    hybrid580_open_nvUvmInterfaceMemoryAllocSys;
extern __typeof__(nvUvmInterfaceMemoryAllocSys)
    hybrid580_legacy_nvUvmInterfaceMemoryAllocSys;
extern __typeof__(nvUvmInterfaceMemoryFree)
    hybrid580_open_nvUvmInterfaceMemoryFree;
extern __typeof__(nvUvmInterfaceMemoryFree)
    hybrid580_legacy_nvUvmInterfaceMemoryFree;
extern __typeof__(nvUvmInterfaceMemoryCpuMap)
    hybrid580_open_nvUvmInterfaceMemoryCpuMap;
extern __typeof__(nvUvmInterfaceMemoryCpuMap)
    hybrid580_legacy_nvUvmInterfaceMemoryCpuMap;
extern __typeof__(nvUvmInterfaceMemoryCpuUnMap)
    hybrid580_open_nvUvmInterfaceMemoryCpuUnMap;
extern __typeof__(nvUvmInterfaceMemoryCpuUnMap)
    hybrid580_legacy_nvUvmInterfaceMemoryCpuUnMap;
extern __typeof__(nvUvmInterfaceDupMemory)
    hybrid580_open_nvUvmInterfaceDupMemory;
extern __typeof__(nvUvmInterfaceDupMemory)
    hybrid580_legacy_nvUvmInterfaceDupMemory;
extern __typeof__(nvUvmInterfaceFreeDupedHandle)
    hybrid580_open_nvUvmInterfaceFreeDupedHandle;
extern __typeof__(nvUvmInterfaceFreeDupedHandle)
    hybrid580_legacy_nvUvmInterfaceFreeDupedHandle;
extern __typeof__(nvUvmInterfaceTsgAllocate)
    hybrid580_open_nvUvmInterfaceTsgAllocate;
extern __typeof__(nvUvmInterfaceTsgAllocate)
    hybrid580_legacy_nvUvmInterfaceTsgAllocate;
extern __typeof__(nvUvmInterfaceTsgDestroy)
    hybrid580_open_nvUvmInterfaceTsgDestroy;
extern __typeof__(nvUvmInterfaceTsgDestroy)
    hybrid580_legacy_nvUvmInterfaceTsgDestroy;
extern __typeof__(nvUvmInterfaceChannelAllocate)
    hybrid580_open_nvUvmInterfaceChannelAllocate;
extern __typeof__(nvUvmInterfaceChannelAllocate)
    hybrid580_legacy_nvUvmInterfaceChannelAllocate;
extern __typeof__(nvUvmInterfaceChannelDestroy)
    hybrid580_open_nvUvmInterfaceChannelDestroy;
extern __typeof__(nvUvmInterfaceChannelDestroy)
    hybrid580_legacy_nvUvmInterfaceChannelDestroy;
extern __typeof__(nvUvmInterfaceRetainChannel)
    hybrid580_open_nvUvmInterfaceRetainChannel;
#ifdef HYBRID580_UVM_ABI_R580
extern __typeof__(nvUvmInterfaceRetainChannel)
    hybrid580_legacy_nvUvmInterfaceRetainChannel;
#else
extern NV_STATUS hybrid580_legacy_nvUvmInterfaceRetainChannel(
    uvmGpuAddressSpaceHandle vaSpace,
    NvHandle hClient,
    NvHandle hChannel,
    void **retainedChannel,
    struct hybrid580_r580_UvmGpuChannelInstanceInfo *channelInstanceInfo);
#endif
extern __typeof__(nvUvmInterfaceBindChannelResources)
    hybrid580_open_nvUvmInterfaceBindChannelResources;
extern __typeof__(nvUvmInterfaceBindChannelResources)
    hybrid580_legacy_nvUvmInterfaceBindChannelResources;
extern __typeof__(nvUvmInterfaceReleaseChannel)
    hybrid580_open_nvUvmInterfaceReleaseChannel;
extern __typeof__(nvUvmInterfaceReleaseChannel)
    hybrid580_legacy_nvUvmInterfaceReleaseChannel;
extern __typeof__(nvUvmInterfaceStopChannel)
    hybrid580_open_nvUvmInterfaceStopChannel;
extern __typeof__(nvUvmInterfaceStopChannel)
    hybrid580_legacy_nvUvmInterfaceStopChannel;
extern __typeof__(nvUvmInterfaceGetChannelResourcePtes)
    hybrid580_open_nvUvmInterfaceGetChannelResourcePtes;
extern __typeof__(nvUvmInterfaceGetChannelResourcePtes)
    hybrid580_legacy_nvUvmInterfaceGetChannelResourcePtes;

static DEFINE_MUTEX(hybrid580_uvm_callback_lock);
static DEFINE_SPINLOCK(hybrid580_uvm_info_lock);
static struct hybrid580_uvm_callback_registry hybrid580_uvm_callbacks;

struct hybrid580_uvm_session_provider_context {
    UvmPlatformInfo platform;
    NV_STATUS create_status;
    NV_STATUS destroy_status;
};

struct hybrid580_uvm_session_result {
    enum hybrid580_uvm_session_pair_status code;
    NV_STATUS backend_status;
};

static struct hybrid580_uvm_session_provider_context hybrid580_open_session_context;
static struct hybrid580_uvm_session_provider_context hybrid580_legacy_session_context;
static struct hybrid580_uvm_session_pair hybrid580_uvm_sessions;
static bool hybrid580_uvm_quarantine_module_pin;
static struct hybrid580_uvm_gpu_registry hybrid580_uvm_gpu_registry;
static struct hybrid580_uvm_device_registry hybrid580_uvm_devices;
static struct hybrid580_uvm_address_space_registry hybrid580_uvm_address_spaces;
static struct hybrid580_uvm_typed_child_registry hybrid580_uvm_typed_children;
static struct hybrid580_uvm_pma_registry hybrid580_uvm_pmas;
static struct hybrid580_uvm_info_registry hybrid580_uvm_infos;
static struct hybrid580_uvm_p2p_object_registry hybrid580_uvm_p2p_objects = {
    .next_public_handle = HYBRID580_UVM_P2P_PUBLIC_HANDLE_BASE,
};

struct hybrid580_uvm_pma_backend_ops {
    enum hybrid580_uvm_provider provider;
    NV_STATUS (*register_callbacks)(void *pma,
                                    uvmPmaEvictPagesCallback evict_pages,
                                    uvmPmaEvictRangeCallback evict_range,
                                    void *callback_data);
    void (*unregister_callbacks)(void *pma);
    NV_STATUS (*allocate_pages)(void *pma, NvLength page_count, NvU64 page_size,
                                UvmPmaAllocationOptions *options, NvU64 *pages);
    NV_STATUS (*pin_pages)(void *pma, NvU64 *pages, NvLength page_count,
                           NvU64 page_size, NvU32 flags);
    void (*free_pages)(void *pma, NvU64 *pages, NvLength page_count,
                       NvU64 page_size, NvU32 flags);
};

struct hybrid580_uvm_fault_info_backend_ops {
    enum hybrid580_uvm_provider provider;
    NV_STATUS (*init)(uvmGpuDeviceHandle device,
                      UvmGpuFaultInfo *pFaultInfo);
    NV_STATUS (*destroy)(uvmGpuDeviceHandle device,
                         UvmGpuFaultInfo *pFaultInfo);
    NV_STATUS (*has_pending)(UvmGpuFaultInfo *pFaultInfo,
                             NvBool *hasPendingFaults);
    NV_STATUS (*get_faults)(UvmGpuFaultInfo *pFaultInfo, void *pFaultBuffer,
                            NvU32 *numFaults);
    NV_STATUS (*flush)(UvmGpuFaultInfo *pFaultInfo, NvBool bCopyAndFlush);
    NV_STATUS (*toggle_prefetch)(UvmGpuFaultInfo *pFaultInfo, NvBool bEnable);
};

struct hybrid580_uvm_access_cntr_backend_ops {
    enum hybrid580_uvm_provider provider;
    NV_STATUS (*init)(uvmGpuDeviceHandle device,
                      UvmGpuAccessCntrInfo *pAccessCntrInfo,
                      NvU32 accessCntrIndex);
    NV_STATUS (*destroy)(uvmGpuDeviceHandle device,
                         UvmGpuAccessCntrInfo *pAccessCntrInfo);
    NV_STATUS (*enable)(uvmGpuDeviceHandle device,
                        UvmGpuAccessCntrInfo *pAccessCntrInfo,
                        const UvmGpuAccessCntrConfig *pAccessCntrConfig);
    NV_STATUS (*disable)(uvmGpuDeviceHandle device,
                         UvmGpuAccessCntrInfo *pAccessCntrInfo);
};

struct hybrid580_uvm_csl_backend_ops {
    enum hybrid580_uvm_provider provider;
    NV_STATUS (*init_context)(UvmCslContext *uvmCslContext,
                              uvmGpuChannelHandle channel);
    void (*deinit_context)(UvmCslContext *uvmCslContext);
    NV_STATUS (*rotate_key)(UvmCslContext *contextList[],
                            NvU32 contextListCount);
    NV_STATUS (*rotate_iv)(UvmCslContext *uvmCslContext,
                           UvmCslOperation operation);
    NV_STATUS (*encrypt)(UvmCslContext *uvmCslContext, NvU32 bufferSize,
                         NvU8 const *inputBuffer, UvmCslIv *encryptIv,
                         NvU8 *outputBuffer, NvU8 *authTagBuffer);
    NV_STATUS (*decrypt)(UvmCslContext *uvmCslContext, NvU32 bufferSize,
                         NvU8 const *inputBuffer,
                         UvmCslIv const *decryptIv, NvU32 keyRotationId,
                         NvU8 *outputBuffer, NvU8 const *addAuthData,
                         NvU32 addAuthDataSize,
                         NvU8 const *authTagBuffer);
    NV_STATUS (*sign)(UvmCslContext *uvmCslContext, NvU32 bufferSize,
                      NvU8 const *inputBuffer, NvU8 *authTagBuffer);
    NV_STATUS (*query_message_pool)(UvmCslContext *uvmCslContext,
                                    UvmCslOperation operation,
                                    NvU64 *messageNum);
    NV_STATUS (*increment_iv)(UvmCslContext *uvmCslContext,
                               UvmCslOperation operation, NvU64 increment,
                               UvmCslIv *iv);
    NV_STATUS (*log_encryption)(UvmCslContext *uvmCslContext,
                                UvmCslOperation operation,
                                NvU32 bufferSize);
};

static const struct hybrid580_uvm_pma_backend_ops hybrid580_open_pma_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .register_callbacks = hybrid580_open_nvUvmInterfacePmaRegisterEvictionCallbacks,
    .unregister_callbacks = hybrid580_open_nvUvmInterfacePmaUnregisterEvictionCallbacks,
    .allocate_pages = hybrid580_open_nvUvmInterfacePmaAllocPages,
    .pin_pages = hybrid580_open_nvUvmInterfacePmaPinPages,
    .free_pages = hybrid580_open_nvUvmInterfacePmaFreePages,
};

static const struct hybrid580_uvm_pma_backend_ops hybrid580_legacy_pma_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .register_callbacks = hybrid580_legacy_nvUvmInterfacePmaRegisterEvictionCallbacks,
    .unregister_callbacks = hybrid580_legacy_nvUvmInterfacePmaUnregisterEvictionCallbacks,
    .allocate_pages = hybrid580_legacy_nvUvmInterfacePmaAllocPages,
    .pin_pages = hybrid580_legacy_nvUvmInterfacePmaPinPages,
    .free_pages = hybrid580_legacy_nvUvmInterfacePmaFreePages,
};

static const struct hybrid580_uvm_fault_info_backend_ops
hybrid580_open_fault_info_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .init = hybrid580_open_nvUvmInterfaceInitFaultInfo,
    .destroy = hybrid580_open_nvUvmInterfaceDestroyFaultInfo,
    .has_pending = hybrid580_open_nvUvmInterfaceHasPendingNonReplayableFaults,
    .get_faults = hybrid580_open_nvUvmInterfaceGetNonReplayableFaults,
    .flush = hybrid580_open_nvUvmInterfaceFlushReplayableFaultBuffer,
    .toggle_prefetch = hybrid580_open_nvUvmInterfaceTogglePrefetchFaults,
};

static const struct hybrid580_uvm_fault_info_backend_ops
hybrid580_legacy_fault_info_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .init = hybrid580_legacy_nvUvmInterfaceInitFaultInfo,
    .destroy = hybrid580_legacy_nvUvmInterfaceDestroyFaultInfo,
    .has_pending = hybrid580_legacy_nvUvmInterfaceHasPendingNonReplayableFaults,
    .get_faults = hybrid580_legacy_nvUvmInterfaceGetNonReplayableFaults,
    .flush = hybrid580_legacy_nvUvmInterfaceFlushReplayableFaultBuffer,
    .toggle_prefetch = hybrid580_legacy_nvUvmInterfaceTogglePrefetchFaults,
};

static const struct hybrid580_uvm_access_cntr_backend_ops
hybrid580_open_access_cntr_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .init = hybrid580_open_nvUvmInterfaceInitAccessCntrInfo,
    .destroy = hybrid580_open_nvUvmInterfaceDestroyAccessCntrInfo,
    .enable = hybrid580_open_nvUvmInterfaceEnableAccessCntr,
    .disable = hybrid580_open_nvUvmInterfaceDisableAccessCntr,
};

static const struct hybrid580_uvm_access_cntr_backend_ops
hybrid580_legacy_access_cntr_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .init = hybrid580_legacy_nvUvmInterfaceInitAccessCntrInfo,
    .destroy = hybrid580_legacy_nvUvmInterfaceDestroyAccessCntrInfo,
    .enable = hybrid580_legacy_nvUvmInterfaceEnableAccessCntr,
    .disable = hybrid580_legacy_nvUvmInterfaceDisableAccessCntr,
};

static const struct hybrid580_uvm_csl_backend_ops hybrid580_open_csl_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .init_context = hybrid580_open_nvUvmInterfaceCslInitContext,
    .deinit_context = hybrid580_open_nvUvmInterfaceDeinitCslContext,
    .rotate_key = hybrid580_open_nvUvmInterfaceCslRotateKey,
    .rotate_iv = hybrid580_open_nvUvmInterfaceCslRotateIv,
    .encrypt = hybrid580_open_nvUvmInterfaceCslEncrypt,
    .decrypt = hybrid580_open_nvUvmInterfaceCslDecrypt,
    .sign = hybrid580_open_nvUvmInterfaceCslSign,
    .query_message_pool = hybrid580_open_nvUvmInterfaceCslQueryMessagePool,
    .increment_iv = hybrid580_open_nvUvmInterfaceCslIncrementIv,
    .log_encryption = hybrid580_open_nvUvmInterfaceCslLogEncryption,
};

static const struct hybrid580_uvm_csl_backend_ops hybrid580_legacy_csl_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .init_context = hybrid580_legacy_nvUvmInterfaceCslInitContext,
    .deinit_context = hybrid580_legacy_nvUvmInterfaceDeinitCslContext,
    .rotate_key = hybrid580_legacy_nvUvmInterfaceCslRotateKey,
    .rotate_iv = hybrid580_legacy_nvUvmInterfaceCslRotateIv,
    .encrypt = hybrid580_legacy_nvUvmInterfaceCslEncrypt,
    .decrypt = hybrid580_legacy_nvUvmInterfaceCslDecrypt,
    .sign = hybrid580_legacy_nvUvmInterfaceCslSign,
    .query_message_pool = hybrid580_legacy_nvUvmInterfaceCslQueryMessagePool,
    .increment_iv = hybrid580_legacy_nvUvmInterfaceCslIncrementIv,
    .log_encryption = hybrid580_legacy_nvUvmInterfaceCslLogEncryption,
};

static void hybrid580_uvm_pin_quarantined_state(void);

static const struct hybrid580_uvm_fault_info_backend_ops *
hybrid580_uvm_fault_info_backend(enum hybrid580_uvm_provider provider)
{
    if (provider == hybrid580_open_fault_info_ops.provider)
        return &hybrid580_open_fault_info_ops;
    if (provider == hybrid580_legacy_fault_info_ops.provider)
        return &hybrid580_legacy_fault_info_ops;
    return NULL;
}

static const struct hybrid580_uvm_access_cntr_backend_ops *
hybrid580_uvm_access_cntr_backend(enum hybrid580_uvm_provider provider)
{
    if (provider == hybrid580_open_access_cntr_ops.provider)
        return &hybrid580_open_access_cntr_ops;
    if (provider == hybrid580_legacy_access_cntr_ops.provider)
        return &hybrid580_legacy_access_cntr_ops;
    return NULL;
}

static const struct hybrid580_uvm_csl_backend_ops *
hybrid580_uvm_csl_backend(enum hybrid580_uvm_provider provider)
{
    if (provider == hybrid580_open_csl_ops.provider)
        return &hybrid580_open_csl_ops;
    if (provider == hybrid580_legacy_csl_ops.provider)
        return &hybrid580_legacy_csl_ops;
    return NULL;
}

static NV_STATUS hybrid580_uvm_info_status_to_nv(
    enum hybrid580_uvm_info_status status)
{
    switch (status) {
        case HYBRID580_UVM_INFO_OK:
            return NV_OK;
        case HYBRID580_UVM_INFO_INVALID:
            return NV_ERR_INVALID_ARGUMENT;
        case HYBRID580_UVM_INFO_NOT_FOUND:
        case HYBRID580_UVM_INFO_OWNER_MISMATCH:
            return NV_ERR_INVALID_OBJECT_HANDLE;
        case HYBRID580_UVM_INFO_OVERFLOW:
            return NV_ERR_INSUFFICIENT_RESOURCES;
        case HYBRID580_UVM_INFO_CROSS_PROVIDER:
            return NV_ERR_NOT_SUPPORTED;
        case HYBRID580_UVM_INFO_DUPLICATE:
        case HYBRID580_UVM_INFO_BUSY:
        case HYBRID580_UVM_INFO_QUARANTINED:
        default:
            return NV_ERR_INVALID_STATE;
    }
}

/* Caller holds hybrid580_uvm_callback_lock. The info entry is published as
 * retiring before the backend initializes the caller-owned structure. This
 * reserves the identity and keeps parent-device teardown from racing init. */
static NV_STATUS hybrid580_uvm_info_reserve_locked(
    struct hybrid580_uvm_info_entry *entry, uintptr_t identity,
    uintptr_t device_identity, enum hybrid580_uvm_provider provider,
    enum hybrid580_uvm_info_kind kind, int *registered)
{
    unsigned long flags;
    enum hybrid580_uvm_info_status info_status;

    if (registered != NULL)
        *registered = 0;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_record(
        &hybrid580_uvm_infos, entry, identity, device_identity, provider, kind);
    if (info_status == HYBRID580_UVM_INFO_OK) {
        if (registered != NULL)
            *registered = 1;
        info_status = hybrid580_uvm_info_registry_begin_retire(
            &hybrid580_uvm_infos, identity, kind, device_identity, NULL);
        if (info_status != HYBRID580_UVM_INFO_OK)
            (void)hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, identity);
    }
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK && registered != NULL &&
        *registered) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM info identity reservation is inconsistent (%d); frontend pinned\n",
                 info_status);
    }
    return hybrid580_uvm_info_status_to_nv(info_status);
}

/* backend_status==NV_OK publishes the reserved object; an init failure
 * removes the reservation. This follows the pinned UVM caller contract: it
 * clears the returned RM handle and skips Destroy*Info after failed init.
 * It does not assert that RM itself rolled back any partial allocation. */
static NV_STATUS hybrid580_uvm_info_finish_init(
    struct hybrid580_uvm_info_entry *entry, NV_STATUS backend_status)
{
    struct hybrid580_uvm_info_entry *removed = NULL;
    unsigned long flags;
    enum hybrid580_uvm_info_status info_status;

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, entry, backend_status == NV_OK ? 0 : 1,
        &removed);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM info init completion is inconsistent (%d); frontend pinned\n",
                 info_status);
        return NV_ERR_INVALID_STATE;
    }
    if (removed != NULL)
        kfree(removed);
    return backend_status;
}

static NV_STATUS hybrid580_uvm_info_device_owner_locked(
    uvmGpuDeviceHandle device, enum hybrid580_uvm_provider *provider,
    uintptr_t *native_device)
{
    enum hybrid580_uvm_device_registry_status owner_status;

    if (device == NULL || provider == NULL || native_device == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *provider = 0;
    *native_device = 0;
    owner_status = hybrid580_uvm_device_registry_lookup(
        &hybrid580_uvm_devices, (uintptr_t)device, provider, native_device);
    if (owner_status != HYBRID580_UVM_DEVICE_REGISTRY_OK ||
        *native_device == 0 || !hybrid580_uvm_provider_is_single(*provider))
        return NV_ERR_INVALID_OBJECT_HANDLE;
    return NV_OK;
}

/* Resolve a public UVM channel through its TSG and public VA-space back to
 * the device owner. Caller holds hybrid580_uvm_callback_lock. The CSL RM
 * context must be initialized with the channel handle from that same RM. */
static NV_STATUS hybrid580_uvm_channel_owner_locked(
    uvmGpuChannelHandle channel, enum hybrid580_uvm_provider *provider,
    uintptr_t *native_channel, uintptr_t *device_identity)
{
    enum hybrid580_uvm_provider channel_provider = 0;
    enum hybrid580_uvm_provider tsg_provider = 0;
    enum hybrid580_uvm_provider address_space_provider = 0;
    enum hybrid580_uvm_provider device_provider = 0;
    enum hybrid580_uvm_typed_child_parent_kind channel_parent_kind = 0;
    enum hybrid580_uvm_typed_child_parent_kind tsg_parent_kind = 0;
    enum hybrid580_uvm_typed_child_status child_status;
    enum hybrid580_uvm_address_space_registry_status address_status;
    uintptr_t channel_native = 0;
    uintptr_t tsg_identity = 0;
    uintptr_t tsg_native = 0;
    uintptr_t public_va_space = 0;
    uintptr_t public_device = 0;
    uintptr_t native_device = 0;

    if (channel == NULL || provider == NULL || native_channel == NULL ||
        device_identity == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *provider = 0;
    *native_channel = 0;
    *device_identity = 0;

    child_status = hybrid580_uvm_typed_child_registry_lookup(
        &hybrid580_uvm_typed_children, (uintptr_t)channel,
        HYBRID580_UVM_TYPED_CHILD_CHANNEL, &channel_provider,
        &channel_native, &tsg_identity, &channel_parent_kind);
    if (child_status != HYBRID580_UVM_TYPED_CHILD_OK || channel_native == 0 ||
        tsg_identity == 0 ||
        channel_parent_kind != HYBRID580_UVM_TYPED_CHILD_PARENT_TSG)
        return NV_ERR_INVALID_CHANNEL;

    child_status = hybrid580_uvm_typed_child_registry_lookup(
        &hybrid580_uvm_typed_children, tsg_identity,
        HYBRID580_UVM_TYPED_CHILD_TSG, &tsg_provider, &tsg_native,
        &public_va_space, &tsg_parent_kind);
    if (child_status != HYBRID580_UVM_TYPED_CHILD_OK || tsg_native == 0 ||
        public_va_space == 0 ||
        tsg_parent_kind != HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE ||
        tsg_provider != channel_provider)
        return NV_ERR_INVALID_CHANNEL;

    address_status = hybrid580_uvm_address_space_registry_lookup(
        &hybrid580_uvm_address_spaces, public_va_space,
        &address_space_provider, NULL, &public_device);
    if (address_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK ||
        public_device == 0 || address_space_provider != channel_provider)
        return NV_ERR_INVALID_CHANNEL;

    if (hybrid580_uvm_info_device_owner_locked(
            (uvmGpuDeviceHandle)public_device, &device_provider,
            &native_device) != NV_OK || native_device == 0 ||
        device_provider != channel_provider)
        return NV_ERR_INVALID_CHANNEL;

    *provider = channel_provider;
    *native_channel = channel_native;
    *device_identity = public_device;
    return NV_OK;
}

/* Reserve the fault-info object and its embedded RM-owned CSL context as one
 * identity pair. UVM initializes that embedded context inside InitFaultInfo;
 * the frontend deliberately never reads its opaque RM fields. */
static NV_STATUS hybrid580_uvm_info_reserve_fault_pair_locked(
    struct hybrid580_uvm_info_entry *fault_entry,
    struct hybrid580_uvm_info_entry *csl_entry,
    uintptr_t fault_identity, uintptr_t csl_identity,
    uintptr_t device_identity, enum hybrid580_uvm_provider provider,
    int *registered)
{
    unsigned long flags;
    enum hybrid580_uvm_info_status info_status;
    enum hybrid580_uvm_info_status cleanup_status;
    int inconsistent = 0;

    if (registered != NULL)
        *registered = 0;
    if (fault_entry == NULL || csl_entry == NULL || fault_identity == 0 ||
        csl_identity == 0 || fault_identity == csl_identity ||
        device_identity == 0 ||
        !hybrid580_uvm_provider_is_single(provider))
        return NV_ERR_INVALID_ARGUMENT;

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_record(
        &hybrid580_uvm_infos, fault_entry, fault_identity, device_identity,
        provider, HYBRID580_UVM_INFO_FAULT);
    if (info_status != HYBRID580_UVM_INFO_OK)
        goto unlock;

    info_status = hybrid580_uvm_info_registry_record(
        &hybrid580_uvm_infos, csl_entry, csl_identity, device_identity,
        provider, HYBRID580_UVM_INFO_CSL);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        cleanup_status = hybrid580_uvm_info_registry_begin_retire(
            &hybrid580_uvm_infos, fault_identity, HYBRID580_UVM_INFO_FAULT,
            device_identity, NULL);
        if (cleanup_status == HYBRID580_UVM_INFO_OK)
            cleanup_status = hybrid580_uvm_info_registry_finish_retire(
                &hybrid580_uvm_infos, fault_entry, 1, NULL);
        if (cleanup_status != HYBRID580_UVM_INFO_OK) {
            (void)hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, fault_identity);
            inconsistent = 1;
        }
        goto unlock;
    }

    if (registered != NULL)
        *registered = 1;
    info_status = hybrid580_uvm_info_registry_begin_retire(
        &hybrid580_uvm_infos, fault_identity, HYBRID580_UVM_INFO_FAULT,
        device_identity, NULL);
    if (info_status == HYBRID580_UVM_INFO_OK)
        info_status = hybrid580_uvm_info_registry_begin_retire(
            &hybrid580_uvm_infos, csl_identity, HYBRID580_UVM_INFO_CSL,
            device_identity, NULL);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, fault_identity);
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, csl_identity);
        inconsistent = 1;
    }

unlock:
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (inconsistent) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault/CSL pair reservation is inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return hybrid580_uvm_info_status_to_nv(info_status);
}

static NV_STATUS hybrid580_uvm_info_finish_fault_pair_init(
    struct hybrid580_uvm_info_entry *fault_entry,
    struct hybrid580_uvm_info_entry *csl_entry, NV_STATUS backend_status)
{
    struct hybrid580_uvm_info_entry *removed_fault = NULL;
    struct hybrid580_uvm_info_entry *removed_csl = NULL;
    unsigned long flags;
    enum hybrid580_uvm_info_status fault_status;
    enum hybrid580_uvm_info_status csl_status;

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    fault_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, fault_entry, backend_status != NV_OK,
        &removed_fault);
    csl_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, csl_entry, backend_status != NV_OK,
        &removed_csl);
    if (fault_status != HYBRID580_UVM_INFO_OK)
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, fault_entry->identity);
    if (csl_status != HYBRID580_UVM_INFO_OK)
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, csl_entry->identity);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);

    if (removed_fault != NULL)
        kfree(removed_fault);
    if (removed_csl != NULL)
        kfree(removed_csl);
    if (fault_status != HYBRID580_UVM_INFO_OK ||
        csl_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault/CSL pair init completion is inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return backend_status;
}

static NV_STATUS hybrid580_uvm_info_begin_fault_retire_locked(
    uintptr_t fault_identity, uintptr_t csl_identity,
    uintptr_t device_identity, enum hybrid580_uvm_provider provider,
    struct hybrid580_uvm_info_entry **fault_entry_out,
    struct hybrid580_uvm_info_entry **csl_entry_out)
{
    unsigned long flags;
    enum hybrid580_uvm_info_status info_status;
    enum hybrid580_uvm_info_status rollback_status;
    int inconsistent = 0;

    *fault_entry_out = NULL;
    *csl_entry_out = NULL;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_begin_retire(
        &hybrid580_uvm_infos, fault_identity, HYBRID580_UVM_INFO_FAULT,
        device_identity, fault_entry_out);
    if (info_status != HYBRID580_UVM_INFO_OK)
        goto unlock;
    if ((*fault_entry_out)->provider != provider) {
        info_status = HYBRID580_UVM_INFO_OWNER_MISMATCH;
        goto rollback_fault;
    }

    info_status = hybrid580_uvm_info_registry_begin_retire(
        &hybrid580_uvm_infos, csl_identity, HYBRID580_UVM_INFO_CSL,
        device_identity, csl_entry_out);
    if (info_status != HYBRID580_UVM_INFO_OK)
        goto rollback_fault;
    if ((*csl_entry_out)->provider != provider) {
        info_status = HYBRID580_UVM_INFO_OWNER_MISMATCH;
        rollback_status = hybrid580_uvm_info_registry_finish_retire(
            &hybrid580_uvm_infos, *csl_entry_out, 0, NULL);
        if (rollback_status != HYBRID580_UVM_INFO_OK) {
            (void)hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, csl_identity);
            inconsistent = 1;
        }
        *csl_entry_out = NULL;
        goto rollback_fault;
    }
    goto unlock;

rollback_fault:
    rollback_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, *fault_entry_out, 0, NULL);
    if (rollback_status != HYBRID580_UVM_INFO_OK) {
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, fault_identity);
        inconsistent = 1;
    }
    *fault_entry_out = NULL;
unlock:
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (inconsistent) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault/CSL retirement rollback is inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return hybrid580_uvm_info_status_to_nv(info_status);
}

static NV_STATUS hybrid580_uvm_info_finish_fault_pair_destroy(
    struct hybrid580_uvm_info_entry *fault_entry,
    struct hybrid580_uvm_info_entry *csl_entry, NV_STATUS backend_status)
{
    struct hybrid580_uvm_info_entry *removed_fault = NULL;
    struct hybrid580_uvm_info_entry *removed_csl = NULL;
    unsigned long flags;
    enum hybrid580_uvm_info_status fault_status;
    enum hybrid580_uvm_info_status csl_status;
    int backend_failed = backend_status != NV_OK;

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    fault_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, fault_entry, !backend_failed, &removed_fault);
    csl_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, csl_entry, !backend_failed, &removed_csl);
    if (backend_failed) {
        if (fault_status == HYBRID580_UVM_INFO_OK)
            fault_status = hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, fault_entry->identity);
        if (csl_status == HYBRID580_UVM_INFO_OK)
            csl_status = hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, csl_entry->identity);
    }
    if (fault_status != HYBRID580_UVM_INFO_OK)
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, fault_entry->identity);
    if (csl_status != HYBRID580_UVM_INFO_OK)
        (void)hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, csl_entry->identity);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);

    if (removed_fault != NULL)
        kfree(removed_fault);
    if (removed_csl != NULL)
        kfree(removed_csl);
    if (backend_failed || fault_status != HYBRID580_UVM_INFO_OK ||
        csl_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault/CSL pair destroy was not fully completed; frontend pinned\n");
        return backend_failed ? backend_status : NV_ERR_INVALID_STATE;
    }
    return backend_status;
}

static NV_STATUS hybrid580_uvm_info_begin_retire_locked(
    uintptr_t identity, uintptr_t device_identity,
    enum hybrid580_uvm_info_kind kind, enum hybrid580_uvm_provider provider,
    struct hybrid580_uvm_info_entry **entry_out)
{
    unsigned long flags;
    enum hybrid580_uvm_info_status info_status;
    int inconsistent = 0;

    *entry_out = NULL;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_begin_retire(
        &hybrid580_uvm_infos, identity, kind, device_identity, entry_out);
    if (info_status == HYBRID580_UVM_INFO_OK &&
        (*entry_out)->provider != provider) {
        enum hybrid580_uvm_info_status finish_status =
            hybrid580_uvm_info_registry_finish_retire(
            &hybrid580_uvm_infos, *entry_out, 0, NULL);
        if (finish_status != HYBRID580_UVM_INFO_OK) {
            (void)hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, identity);
            inconsistent = 1;
        }
        *entry_out = NULL;
        info_status = HYBRID580_UVM_INFO_OWNER_MISMATCH;
    }
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (inconsistent) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM info provider mismatch left retire state inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return hybrid580_uvm_info_status_to_nv(info_status);
}

static NV_STATUS hybrid580_uvm_info_finish_retire(
    struct hybrid580_uvm_info_entry *entry, NV_STATUS backend_status)
{
    struct hybrid580_uvm_info_entry *removed = NULL;
    unsigned long flags;
    enum hybrid580_uvm_info_status info_status;
    int backend_failed = backend_status != NV_OK;

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_finish_retire(
        &hybrid580_uvm_infos, entry, !backend_failed, &removed);
    if (info_status == HYBRID580_UVM_INFO_OK && backend_failed)
        info_status = hybrid580_uvm_info_registry_quarantine(
            &hybrid580_uvm_infos, entry->identity);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM info teardown completion is inconsistent (%d); frontend pinned\n",
                 info_status);
        return NV_ERR_INVALID_STATE;
    }
    if (removed != NULL)
        kfree(removed);
    if (backend_failed) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM info backend destruction failed; owner quarantined and frontend pinned\n");
    }
    return backend_status;
}

/* CSL methods can run from secure-channel and fault paths. Their owner lookup
 * is therefore a non-sleeping registry pin, and backend execution happens
 * without the frontend callback mutex or registry spinlock held. */
static NV_STATUS hybrid580_uvm_csl_pin(
    UvmCslContext *uvmCslContext, struct hybrid580_uvm_info_pin *pin)
{
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;

    if (uvmCslContext == NULL || pin == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_pin(
        &hybrid580_uvm_infos, (uintptr_t)uvmCslContext,
        HYBRID580_UVM_INFO_CSL, 0, pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    return hybrid580_uvm_info_status_to_nv(info_status);
}

static NV_STATUS hybrid580_uvm_csl_unpin(
    struct hybrid580_uvm_info_pin *pin)
{
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos, pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM CSL call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return NV_OK;
}

static const struct hybrid580_uvm_pma_backend_ops *
hybrid580_uvm_pma_backend(enum hybrid580_uvm_provider provider)
{
    if (provider == hybrid580_open_pma_ops.provider)
        return &hybrid580_open_pma_ops;
    if (provider == hybrid580_legacy_pma_ops.provider)
        return &hybrid580_legacy_pma_ops;
    return NULL;
}

static NV_STATUS hybrid580_uvm_pma_status_to_nv(
    enum hybrid580_uvm_pma_status status)
{
    switch (status) {
        case HYBRID580_UVM_PMA_OK:
            return NV_OK;
        case HYBRID580_UVM_PMA_NOT_FOUND:
            return NV_ERR_INVALID_OBJECT_HANDLE;
        case HYBRID580_UVM_PMA_FULL:
            return NV_ERR_NO_MEMORY;
        case HYBRID580_UVM_PMA_BUSY:
            return NV_ERR_INVALID_STATE;
        case HYBRID580_UVM_PMA_AMBIGUOUS:
        case HYBRID580_UVM_PMA_INVALID:
        default:
            return NV_ERR_INVALID_STATE;
    }
}

/* PMA allocation can synchronously invoke UVM eviction callbacks, which can
 * re-enter these exports to free pages. Hold a registry pin while the RM call
 * runs, but never retain hybrid580_uvm_callback_lock across the backend. */
static NV_STATUS hybrid580_uvm_pma_pin(void *pma,
                                       struct hybrid580_uvm_pma_pin *pin)
{
    enum hybrid580_uvm_pma_status status;

    if (pma == NULL || pin == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_pma_registry_pin(&hybrid580_uvm_pmas,
                                             (uintptr_t)pma, pin);
    if (status != HYBRID580_UVM_PMA_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM PMA identity is unknown or ambiguous (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return hybrid580_uvm_pma_status_to_nv(status);
}

static void hybrid580_uvm_pma_unpin(
    struct hybrid580_uvm_pma_pin *pin, int callback_state)
{
    enum hybrid580_uvm_pma_status status = HYBRID580_UVM_PMA_OK;

    mutex_lock(&hybrid580_uvm_callback_lock);
    if (callback_state >= 0)
        status = hybrid580_uvm_pma_registry_set_callbacks(
            &hybrid580_uvm_pmas, pin, callback_state);
    if (status != HYBRID580_UVM_PMA_OK) {
        hybrid580_uvm_pma_registry_quarantine_pin(&hybrid580_uvm_pmas, pin);
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM PMA callback state is inconsistent (%d); frontend pinned\n",
                 status);
    }
    if (hybrid580_uvm_pma_registry_unpin(&hybrid580_uvm_pmas, pin) !=
        HYBRID580_UVM_PMA_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM PMA call pin is inconsistent; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}

static uint32_t hybrid580_open_gpu_register(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    void *platform_info, size_t platform_info_size)
{
    (void)context;
    if (platform_info_size != sizeof(UvmGpuPlatformInfo))
        return NV_ERR_INVALID_ARGUMENT;
    return (uint32_t)hybrid580_open_nvUvmInterfaceRegisterGpu(
        (const NvProcessorUuid *)uuid, (UvmGpuPlatformInfo *)platform_info);
}

static void hybrid580_open_gpu_unregister(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES])
{
    (void)context;
    hybrid580_open_nvUvmInterfaceUnregisterGpu((const NvProcessorUuid *)uuid);
}

static uint32_t hybrid580_legacy_gpu_register(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    void *platform_info, size_t platform_info_size)
{
    (void)context;
    if (platform_info_size != sizeof(UvmGpuPlatformInfo))
        return NV_ERR_INVALID_ARGUMENT;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceRegisterGpu(
        (const NvProcessorUuid *)uuid, (UvmGpuPlatformInfo *)platform_info);
}

static void hybrid580_legacy_gpu_unregister(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES])
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceUnregisterGpu((const NvProcessorUuid *)uuid);
}

static const struct hybrid580_uvm_gpu_backend_ops hybrid580_open_gpu_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .register_gpu = hybrid580_open_gpu_register,
    .unregister_gpu = hybrid580_open_gpu_unregister,
};

static const struct hybrid580_uvm_gpu_backend_ops hybrid580_legacy_gpu_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .register_gpu = hybrid580_legacy_gpu_register,
    .unregister_gpu = hybrid580_legacy_gpu_unregister,
};

static uint32_t hybrid580_open_gpu_get_info(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    const void *client_info, void *gpu_info)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceGetGpuInfo(
        (const NvProcessorUuid *)uuid, (const UvmGpuClientInfo *)client_info,
        (UvmGpuInfo *)gpu_info);
}

static uint32_t hybrid580_legacy_gpu_get_info(void *context,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    const void *client_info, void *gpu_info)
{
    UvmGpuInfo *info = gpu_info;
#ifndef HYBRID580_UVM_ABI_R580
    NvU32 r595_sysmem_link;
#endif
    NV_STATUS status;

    (void)context;
    status = hybrid580_legacy_nvUvmInterfaceGetGpuInfo(
        (const NvProcessorUuid *)uuid, (const UvmGpuClientInfo *)client_info,
        info);
    if (status != NV_OK) {
        memset(info, 0, sizeof(*info));
        return (uint32_t)status;
    }

#ifndef HYBRID580_UVM_ABI_R580
    /* When an R580 RM is paired with the R595 UVM consumer, reproduce the
     * old UVM clamp before the newer consumer builds parent_gpu state. */
    if (info->accessCntrBufferCount > 1)
        info->accessCntrBufferCount = 1;

    /* R580 inserted no PCIe-BAR1 enum value, so its NVLink/C2C numbers are
     * one lower than R595's UVM_LINK_TYPE values. Normalize before R595 UVM
     * consumes UvmGpuInfo::sysmemLink. UvmGpuInfo carries no BAR1 DMA mapping. */
    if (!hybrid580_uvm_r580_link_type_to_r595(info->sysmemLink, NV_FALSE,
                                               &r595_sysmem_link)) {
        memset(info, 0, sizeof(*info));
        return NV_ERR_NOT_SUPPORTED;
    }
    info->sysmemLink = r595_sysmem_link;
#endif
    return NV_OK;
}

static const struct hybrid580_uvm_gpu_info_backend_ops hybrid580_open_gpu_info_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .get_gpu_info = hybrid580_open_gpu_get_info,
};

static const struct hybrid580_uvm_gpu_info_backend_ops hybrid580_legacy_gpu_info_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .get_gpu_info = hybrid580_legacy_gpu_get_info,
};

static uint32_t hybrid580_open_device_create(
    void *context, uintptr_t native_session, const void *gpu_info,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    int create_smc_partition, uintptr_t *native_device)
{
    uvmGpuDeviceHandle device = NULL;
    NV_STATUS status;

    (void)context;
    *native_device = 0;
    status = hybrid580_open_nvUvmInterfaceDeviceCreate(
        (uvmGpuSessionHandle)native_session, (const UvmGpuInfo *)gpu_info,
        (const NvProcessorUuid *)uuid, &device,
        create_smc_partition ? NV_TRUE : NV_FALSE);
    *native_device = (uintptr_t)device;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_device_create(
    void *context, uintptr_t native_session, const void *gpu_info,
    const unsigned char uuid[HYBRID580_UVM_GPU_UUID_BYTES],
    int create_smc_partition, uintptr_t *native_device)
{
    uvmGpuDeviceHandle device = NULL;
    NV_STATUS status;

    (void)context;
    *native_device = 0;
    status = hybrid580_legacy_nvUvmInterfaceDeviceCreate(
        (uvmGpuSessionHandle)native_session, (const UvmGpuInfo *)gpu_info,
        (const NvProcessorUuid *)uuid, &device,
        create_smc_partition ? NV_TRUE : NV_FALSE);
    *native_device = (uintptr_t)device;
    return (uint32_t)status;
}

static void hybrid580_open_device_destroy(void *context, uintptr_t device)
{
    (void)context;
    hybrid580_open_nvUvmInterfaceDeviceDestroy((uvmGpuDeviceHandle)device);
}

static void hybrid580_legacy_device_destroy(void *context, uintptr_t device)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceDeviceDestroy((uvmGpuDeviceHandle)device);
}

static uint32_t hybrid580_open_dup_memory(
    void *context, uintptr_t device, uint32_t client,
    uint32_t physical_handle, uintptr_t *duplicate_handle,
    void *memory_info)
{
    NvHandle native_handle = 0;
    NV_STATUS status;

    (void)context;
    *duplicate_handle = 0;
    status = hybrid580_open_nvUvmInterfaceDupMemory(
        (uvmGpuDeviceHandle)device, (NvHandle)client,
        (NvHandle)physical_handle, &native_handle,
        (UvmGpuMemoryInfo *)memory_info);
    *duplicate_handle = (uintptr_t)native_handle;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_dup_memory(
    void *context, uintptr_t device, uint32_t client,
    uint32_t physical_handle, uintptr_t *duplicate_handle,
    void *memory_info)
{
    NvHandle native_handle = 0;
    NV_STATUS status;

    (void)context;
    *duplicate_handle = 0;
    status = hybrid580_legacy_nvUvmInterfaceDupMemory(
        (uvmGpuDeviceHandle)device, (NvHandle)client,
        (NvHandle)physical_handle, &native_handle,
        (UvmGpuMemoryInfo *)memory_info);
    *duplicate_handle = (uintptr_t)native_handle;
    return (uint32_t)status;
}

static uint32_t hybrid580_open_free_duped_handle(
    void *context, uintptr_t device, uintptr_t duplicate_handle)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceFreeDupedHandle(
        (uvmGpuDeviceHandle)device, (NvHandle)duplicate_handle);
}

static uint32_t hybrid580_legacy_free_duped_handle(
    void *context, uintptr_t device, uintptr_t duplicate_handle)
{
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceFreeDupedHandle(
        (uvmGpuDeviceHandle)device, (NvHandle)duplicate_handle);
}

static const struct hybrid580_uvm_dup_memory_backend_ops
hybrid580_open_dup_memory_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .duplicate = hybrid580_open_dup_memory,
    .release = hybrid580_open_free_duped_handle,
};

static const struct hybrid580_uvm_dup_memory_backend_ops
hybrid580_legacy_dup_memory_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .duplicate = hybrid580_legacy_dup_memory,
    .release = hybrid580_legacy_free_duped_handle,
};

static uint32_t hybrid580_open_address_space_create(
    void *context, uintptr_t device, unsigned long long vaBase,
    unsigned long long vaSize, int enableAts, uintptr_t *native_space,
    void *space_info)
{
    uvmGpuAddressSpaceHandle vaSpace = NULL;
    NV_STATUS status;

    (void)context;
    *native_space = 0;
    status = hybrid580_open_nvUvmInterfaceAddressSpaceCreate(
        (uvmGpuDeviceHandle)device, vaBase, vaSize,
        enableAts ? NV_TRUE : NV_FALSE, &vaSpace,
        (UvmGpuAddressSpaceInfo *)space_info);
    *native_space = (uintptr_t)vaSpace;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_address_space_create(
    void *context, uintptr_t device, unsigned long long vaBase,
    unsigned long long vaSize, int enableAts, uintptr_t *native_space,
    void *space_info)
{
    uvmGpuAddressSpaceHandle vaSpace = NULL;
    NV_STATUS status;

    (void)context;
    *native_space = 0;
    status = hybrid580_legacy_nvUvmInterfaceAddressSpaceCreate(
        (uvmGpuDeviceHandle)device, vaBase, vaSize,
        enableAts ? NV_TRUE : NV_FALSE, &vaSpace,
        (UvmGpuAddressSpaceInfo *)space_info);
    *native_space = (uintptr_t)vaSpace;
    return (uint32_t)status;
}

static uint32_t hybrid580_open_address_space_duplicate(
    void *context, uintptr_t device, uint32_t user_client,
    uint32_t user_va_space, uintptr_t *native_space, void *space_info)
{
    uvmGpuAddressSpaceHandle vaSpace = NULL;
    NV_STATUS status;

    (void)context;
    *native_space = 0;
    status = hybrid580_open_nvUvmInterfaceDupAddressSpace(
        (uvmGpuDeviceHandle)device, (NvHandle)user_client,
        (NvHandle)user_va_space, &vaSpace,
        (UvmGpuAddressSpaceInfo *)space_info);
    *native_space = (uintptr_t)vaSpace;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_address_space_duplicate(
    void *context, uintptr_t device, uint32_t user_client,
    uint32_t user_va_space, uintptr_t *native_space, void *space_info)
{
    uvmGpuAddressSpaceHandle vaSpace = NULL;
    NV_STATUS status;

    (void)context;
    *native_space = 0;
    status = hybrid580_legacy_nvUvmInterfaceDupAddressSpace(
        (uvmGpuDeviceHandle)device, (NvHandle)user_client,
        (NvHandle)user_va_space, &vaSpace,
        (UvmGpuAddressSpaceInfo *)space_info);
    *native_space = (uintptr_t)vaSpace;
    return (uint32_t)status;
}

static uint32_t hybrid580_open_address_space_dup_allocation(
    void *context, uintptr_t src_space, unsigned long long src_address,
    uintptr_t dst_space, unsigned long long dst_alignment,
    unsigned long long *dst_address)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceDupAllocation(
        (uvmGpuAddressSpaceHandle)src_space, src_address,
        (uvmGpuAddressSpaceHandle)dst_space, dst_alignment, dst_address);
}

static uint32_t hybrid580_legacy_address_space_dup_allocation(
    void *context, uintptr_t src_space, unsigned long long src_address,
    uintptr_t dst_space, unsigned long long dst_alignment,
    unsigned long long *dst_address)
{
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceDupAllocation(
        (uvmGpuAddressSpaceHandle)src_space, src_address,
        (uvmGpuAddressSpaceHandle)dst_space, dst_alignment, dst_address);
}

static void hybrid580_open_address_space_destroy(void *context, uintptr_t vaSpace)
{
    (void)context;
    hybrid580_open_nvUvmInterfaceAddressSpaceDestroy(
        (uvmGpuAddressSpaceHandle)vaSpace);
}

static void hybrid580_legacy_address_space_destroy(void *context,
                                                    uintptr_t vaSpace)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceAddressSpaceDestroy(
        (uvmGpuAddressSpaceHandle)vaSpace);
}

static const struct hybrid580_uvm_address_space_backend_ops
hybrid580_open_address_space_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .create = hybrid580_open_address_space_create,
    .destroy = hybrid580_open_address_space_destroy,
};

static const struct hybrid580_uvm_address_space_backend_ops
hybrid580_legacy_address_space_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .create = hybrid580_legacy_address_space_create,
    .destroy = hybrid580_legacy_address_space_destroy,
};

static const struct hybrid580_uvm_address_space_duplicate_backend_ops
hybrid580_open_address_space_duplicate_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .duplicate = hybrid580_open_address_space_duplicate,
    .destroy = hybrid580_open_address_space_destroy,
};

static const struct hybrid580_uvm_address_space_duplicate_backend_ops
hybrid580_legacy_address_space_duplicate_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .duplicate = hybrid580_legacy_address_space_duplicate,
    .destroy = hybrid580_legacy_address_space_destroy,
};

static const struct hybrid580_uvm_address_space_dup_allocation_backend_ops
hybrid580_open_address_space_dup_allocation_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .duplicate = hybrid580_open_address_space_dup_allocation,
};

static const struct hybrid580_uvm_address_space_dup_allocation_backend_ops
hybrid580_legacy_address_space_dup_allocation_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .duplicate = hybrid580_legacy_address_space_dup_allocation,
};

struct hybrid580_uvm_set_page_directory_params {
    NvU64 physAddress;
    unsigned numEntries;
    NvBool bVidMemAperture;
    NvU32 pasid;
    NvU64 *dmaAddress;
};

static uint32_t hybrid580_open_set_page_directory(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_set_page_directory_params *args = params;
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceSetPageDirectory(
        (uvmGpuAddressSpaceHandle)vaSpace, args->physAddress, args->numEntries,
        args->bVidMemAperture, args->pasid, args->dmaAddress);
}

static uint32_t hybrid580_legacy_set_page_directory(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_set_page_directory_params *args = params;
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceSetPageDirectory(
        (uvmGpuAddressSpaceHandle)vaSpace, args->physAddress, args->numEntries,
        args->bVidMemAperture, args->pasid, args->dmaAddress);
}

static uint32_t hybrid580_open_unset_page_directory(void *context,
    uintptr_t vaSpace, void *params)
{
    (void)context;
    (void)params;
    return (uint32_t)hybrid580_open_nvUvmInterfaceUnsetPageDirectory(
        (uvmGpuAddressSpaceHandle)vaSpace);
}

static uint32_t hybrid580_legacy_unset_page_directory(void *context,
    uintptr_t vaSpace, void *params)
{
    (void)context;
    (void)params;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceUnsetPageDirectory(
        (uvmGpuAddressSpaceHandle)vaSpace);
}

struct hybrid580_uvm_memory_alloc_params {
    NvLength length;
    UvmGpuPointer *gpu_pointer;
    UvmGpuAllocInfo *alloc_info;
    UvmGpuAllocInfo backend_alloc_info;
    UvmGpuPointer backend_gpu_pointer;
    int ambiguous_output;
};

static uint32_t hybrid580_open_memory_alloc_fb(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_alloc_params *args = params;
    NV_STATUS status;

    (void)context;
    args->backend_gpu_pointer = 0;
    status = hybrid580_open_nvUvmInterfaceMemoryAllocFB(
        (uvmGpuAddressSpaceHandle)vaSpace, args->length,
        &args->backend_gpu_pointer, &args->backend_alloc_info);
    if (status == NV_OK && args->backend_gpu_pointer != 0) {
        *args->gpu_pointer = args->backend_gpu_pointer;
        *args->alloc_info = args->backend_alloc_info;
    } else if (status == NV_OK) {
        args->ambiguous_output = 1;
        status = NV_ERR_GENERIC;
    } else if (args->backend_gpu_pointer != 0 ||
               args->backend_alloc_info.gpuPhysOffset !=
                   args->alloc_info->gpuPhysOffset ||
               args->backend_alloc_info.hPhysHandle !=
                   args->alloc_info->hPhysHandle) {
        args->ambiguous_output = 1;
    }
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_memory_alloc_fb(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_alloc_params *args = params;
    NV_STATUS status;

    (void)context;
    args->backend_gpu_pointer = 0;
    status = hybrid580_legacy_nvUvmInterfaceMemoryAllocFB(
        (uvmGpuAddressSpaceHandle)vaSpace, args->length,
        &args->backend_gpu_pointer, &args->backend_alloc_info);
    if (status == NV_OK && args->backend_gpu_pointer != 0) {
        *args->gpu_pointer = args->backend_gpu_pointer;
        *args->alloc_info = args->backend_alloc_info;
    } else if (status == NV_OK) {
        args->ambiguous_output = 1;
        status = NV_ERR_GENERIC;
    } else if (args->backend_gpu_pointer != 0 ||
               args->backend_alloc_info.gpuPhysOffset !=
                   args->alloc_info->gpuPhysOffset ||
               args->backend_alloc_info.hPhysHandle !=
                   args->alloc_info->hPhysHandle) {
        args->ambiguous_output = 1;
    }
    return (uint32_t)status;
}

static uint32_t hybrid580_open_memory_alloc_sys(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_alloc_params *args = params;
    NV_STATUS status;

    (void)context;
    args->backend_gpu_pointer = 0;
    status = hybrid580_open_nvUvmInterfaceMemoryAllocSys(
        (uvmGpuAddressSpaceHandle)vaSpace, args->length,
        &args->backend_gpu_pointer, &args->backend_alloc_info);
    if (status == NV_OK && args->backend_gpu_pointer != 0) {
        *args->gpu_pointer = args->backend_gpu_pointer;
        *args->alloc_info = args->backend_alloc_info;
    } else if (status == NV_OK) {
        args->ambiguous_output = 1;
        status = NV_ERR_GENERIC;
    } else if (args->backend_gpu_pointer != 0 ||
               args->backend_alloc_info.gpuPhysOffset !=
                   args->alloc_info->gpuPhysOffset ||
               args->backend_alloc_info.hPhysHandle !=
                   args->alloc_info->hPhysHandle) {
        args->ambiguous_output = 1;
    }
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_memory_alloc_sys(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_alloc_params *args = params;
    NV_STATUS status;

    (void)context;
    args->backend_gpu_pointer = 0;
    status = hybrid580_legacy_nvUvmInterfaceMemoryAllocSys(
        (uvmGpuAddressSpaceHandle)vaSpace, args->length,
        &args->backend_gpu_pointer, &args->backend_alloc_info);
    if (status == NV_OK && args->backend_gpu_pointer != 0) {
        *args->gpu_pointer = args->backend_gpu_pointer;
        *args->alloc_info = args->backend_alloc_info;
    } else if (status == NV_OK) {
        args->ambiguous_output = 1;
        status = NV_ERR_GENERIC;
    } else if (args->backend_gpu_pointer != 0 ||
               args->backend_alloc_info.gpuPhysOffset !=
                   args->alloc_info->gpuPhysOffset ||
               args->backend_alloc_info.hPhysHandle !=
                   args->alloc_info->hPhysHandle) {
        args->ambiguous_output = 1;
    }
    return (uint32_t)status;
}

struct hybrid580_uvm_memory_free_params {
    UvmGpuPointer gpu_pointer;
};

static uint32_t hybrid580_open_memory_free(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_free_params *args = params;
    (void)context;
    hybrid580_open_nvUvmInterfaceMemoryFree(
        (uvmGpuAddressSpaceHandle)vaSpace, args->gpu_pointer);
    return NV_OK;
}

static uint32_t hybrid580_legacy_memory_free(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_free_params *args = params;
    (void)context;
    hybrid580_legacy_nvUvmInterfaceMemoryFree(
        (uvmGpuAddressSpaceHandle)vaSpace, args->gpu_pointer);
    return NV_OK;
}

struct hybrid580_uvm_memory_cpu_map_params {
    UvmGpuPointer gpu_pointer;
    NvLength length;
    void **cpu_pointer;
    NvU64 page_size;
    void *backend_cpu_pointer;
    int ambiguous_output;
};

static uint32_t hybrid580_open_memory_cpu_map(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_cpu_map_params *args = params;
    NV_STATUS status;
    (void)context;
    args->backend_cpu_pointer = NULL;
    status = hybrid580_open_nvUvmInterfaceMemoryCpuMap(
        (uvmGpuAddressSpaceHandle)vaSpace, args->gpu_pointer, args->length,
        &args->backend_cpu_pointer, args->page_size);
    if (status == NV_OK && args->backend_cpu_pointer != NULL)
        *args->cpu_pointer = args->backend_cpu_pointer;
    else if (status == NV_OK) {
        args->ambiguous_output = 1;
        status = NV_ERR_GENERIC;
    }
    else if (args->backend_cpu_pointer != NULL)
        args->ambiguous_output = 1;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_memory_cpu_map(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_cpu_map_params *args = params;
    NV_STATUS status;
    (void)context;
    args->backend_cpu_pointer = NULL;
    status = hybrid580_legacy_nvUvmInterfaceMemoryCpuMap(
        (uvmGpuAddressSpaceHandle)vaSpace, args->gpu_pointer, args->length,
        &args->backend_cpu_pointer, args->page_size);
    if (status == NV_OK && args->backend_cpu_pointer != NULL)
        *args->cpu_pointer = args->backend_cpu_pointer;
    else if (status == NV_OK) {
        args->ambiguous_output = 1;
        status = NV_ERR_GENERIC;
    }
    else if (args->backend_cpu_pointer != NULL)
        args->ambiguous_output = 1;
    return (uint32_t)status;
}

struct hybrid580_uvm_memory_cpu_unmap_params {
    void *cpu_pointer;
};

static uint32_t hybrid580_open_memory_cpu_unmap(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_cpu_unmap_params *args = params;
    (void)context;
    hybrid580_open_nvUvmInterfaceMemoryCpuUnMap(
        (uvmGpuAddressSpaceHandle)vaSpace, args->cpu_pointer);
    return NV_OK;
}

static uint32_t hybrid580_legacy_memory_cpu_unmap(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_memory_cpu_unmap_params *args = params;
    (void)context;
    hybrid580_legacy_nvUvmInterfaceMemoryCpuUnMap(
        (uvmGpuAddressSpaceHandle)vaSpace, args->cpu_pointer);
    return NV_OK;
}

static uint32_t hybrid580_open_own_page_fault_intr(void *context,
    uintptr_t device, void *params)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceOwnPageFaultIntr(
        (uvmGpuDeviceHandle)device, *(NvBool *)params);
}

static uint32_t hybrid580_legacy_own_page_fault_intr(void *context,
    uintptr_t device, void *params)
{
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceOwnPageFaultIntr(
        (uvmGpuDeviceHandle)device, *(NvBool *)params);
}

static uint32_t hybrid580_open_service_device_interrupts(void *context,
    uintptr_t device, void *params)
{
    (void)context;
    (void)params;
    return (uint32_t)hybrid580_open_nvUvmInterfaceServiceDeviceInterruptsRM(
        (uvmGpuDeviceHandle)device);
}

static uint32_t hybrid580_legacy_service_device_interrupts(void *context,
    uintptr_t device, void *params)
{
    (void)context;
    (void)params;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceServiceDeviceInterruptsRM(
        (uvmGpuDeviceHandle)device);
}

struct hybrid580_uvm_non_replayable_fault_call {
    const void *fault_packet;
};

static uint32_t hybrid580_open_report_non_replayable_fault(
    void *context, uintptr_t device, void *params)
{
    struct hybrid580_uvm_non_replayable_fault_call *call = params;

    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceReportNonReplayableFault(
        (uvmGpuDeviceHandle)device, call->fault_packet);
}

static uint32_t hybrid580_legacy_report_non_replayable_fault(
    void *context, uintptr_t device, void *params)
{
    struct hybrid580_uvm_non_replayable_fault_call *call = params;

    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceReportNonReplayableFault(
        (uvmGpuDeviceHandle)device, call->fault_packet);
}

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_open_set_page_directory_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_set_page_directory,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_legacy_set_page_directory_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_set_page_directory,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_open_unset_page_directory_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_unset_page_directory,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_legacy_unset_page_directory_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_unset_page_directory,
};

#define HYBRID580_UVM_MEMORY_OPS(name) \
static const struct hybrid580_uvm_address_space_call_backend_ops \
hybrid580_open_##name##_ops = { \
    .provider = HYBRID580_UVM_PROVIDER_OPEN, .call = hybrid580_open_##name, \
}; \
static const struct hybrid580_uvm_address_space_call_backend_ops \
hybrid580_legacy_##name##_ops = { \
    .provider = HYBRID580_UVM_PROVIDER_LEGACY, .call = hybrid580_legacy_##name, \
}

HYBRID580_UVM_MEMORY_OPS(memory_alloc_fb);
HYBRID580_UVM_MEMORY_OPS(memory_alloc_sys);
HYBRID580_UVM_MEMORY_OPS(memory_free);
HYBRID580_UVM_MEMORY_OPS(memory_cpu_map);
HYBRID580_UVM_MEMORY_OPS(memory_cpu_unmap);

#undef HYBRID580_UVM_MEMORY_OPS

struct hybrid580_uvm_tsg_allocate_params {
    const UvmGpuTsgAllocParams *alloc_params;
    uintptr_t native_tsg;
    enum hybrid580_uvm_provider provider;
};

static uint32_t hybrid580_open_tsg_allocate(void *context,
    uintptr_t native_address_space, void *params)
{
    struct hybrid580_uvm_tsg_allocate_params *args = params;
    uvmGpuTsgHandle tsg = NULL;
    NV_STATUS status;

    (void)context;
    args->provider = HYBRID580_UVM_PROVIDER_OPEN;
    status = hybrid580_open_nvUvmInterfaceTsgAllocate(
        (uvmGpuAddressSpaceHandle)native_address_space, args->alloc_params,
        &tsg);
    args->native_tsg = (uintptr_t)tsg;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_tsg_allocate(void *context,
    uintptr_t native_address_space, void *params)
{
    struct hybrid580_uvm_tsg_allocate_params *args = params;
    uvmGpuTsgHandle tsg = NULL;
    NV_STATUS status;

    (void)context;
    args->provider = HYBRID580_UVM_PROVIDER_LEGACY;
    status = hybrid580_legacy_nvUvmInterfaceTsgAllocate(
        (uvmGpuAddressSpaceHandle)native_address_space, args->alloc_params,
        &tsg);
    args->native_tsg = (uintptr_t)tsg;
    return (uint32_t)status;
}

static void hybrid580_open_tsg_destroy(void *context, uintptr_t native_tsg)
{
    (void)context;
    hybrid580_open_nvUvmInterfaceTsgDestroy((uvmGpuTsgHandle)native_tsg);
}

static void hybrid580_legacy_tsg_destroy(void *context, uintptr_t native_tsg)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceTsgDestroy((uvmGpuTsgHandle)native_tsg);
}

struct hybrid580_uvm_channel_allocate_params {
    const UvmGpuChannelAllocParams *alloc_params;
    uintptr_t native_channel;
    enum hybrid580_uvm_provider provider;
    UvmGpuChannelInfo channel_info;
};

static uint32_t hybrid580_open_channel_allocate(void *context,
    uintptr_t native_tsg, void *params)
{
    struct hybrid580_uvm_channel_allocate_params *args = params;
    uvmGpuChannelHandle channel = NULL;
    NV_STATUS status;

    (void)context;
    args->provider = HYBRID580_UVM_PROVIDER_OPEN;
    status = hybrid580_open_nvUvmInterfaceChannelAllocate(
        (const uvmGpuTsgHandle)native_tsg, args->alloc_params, &channel,
        &args->channel_info);
    args->native_channel = (uintptr_t)channel;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_channel_allocate(void *context,
    uintptr_t native_tsg, void *params)
{
    struct hybrid580_uvm_channel_allocate_params *args = params;
    uvmGpuChannelHandle channel = NULL;
    NV_STATUS status;

    (void)context;
    args->provider = HYBRID580_UVM_PROVIDER_LEGACY;
    status = hybrid580_legacy_nvUvmInterfaceChannelAllocate(
        (const uvmGpuTsgHandle)native_tsg, args->alloc_params, &channel,
        &args->channel_info);
    args->native_channel = (uintptr_t)channel;
    return (uint32_t)status;
}

static void hybrid580_open_channel_destroy(void *context,
                                            uintptr_t native_channel)
{
    (void)context;
    hybrid580_open_nvUvmInterfaceChannelDestroy(
        (uvmGpuChannelHandle)native_channel);
}

static void hybrid580_legacy_channel_destroy(void *context,
                                             uintptr_t native_channel)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceChannelDestroy(
        (uvmGpuChannelHandle)native_channel);
}

struct hybrid580_uvm_retain_channel_params {
    NvHandle client;
    NvHandle channel;
    uintptr_t native_retained_channel;
    enum hybrid580_uvm_provider provider;
    UvmGpuChannelInstanceInfo channel_info;
#ifndef HYBRID580_UVM_ABI_R580
    /* Keep the R580 output payload in the existing heap-owned call object;
     * its 1120-byte layout must not consume kernel stack. */
    struct hybrid580_r580_UvmGpuChannelInstanceInfo legacy_channel_info;
#endif
};

static uint32_t hybrid580_open_retain_channel(void *context,
    uintptr_t native_address_space, void *params)
{
    struct hybrid580_uvm_retain_channel_params *args = params;
    void *retained_channel = NULL;
    NV_STATUS status;
    (void)context;
    args->provider = HYBRID580_UVM_PROVIDER_OPEN;
    status = hybrid580_open_nvUvmInterfaceRetainChannel(
        (uvmGpuAddressSpaceHandle)native_address_space, args->client,
        args->channel, &retained_channel, &args->channel_info);
    if (status == NV_OK &&
        args->channel_info.resourceCount > UVM_GPU_CHANNEL_MAX_RESOURCES) {
        if (retained_channel != NULL)
            hybrid580_open_nvUvmInterfaceReleaseChannel(retained_channel);
        retained_channel = NULL;
        status = NV_ERR_INVALID_ARGUMENT;
    }
    args->native_retained_channel = (uintptr_t)retained_channel;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_retain_channel(void *context,
    uintptr_t native_address_space, void *params)
{
    struct hybrid580_uvm_retain_channel_params *args = params;
    void *retained_channel = NULL;
    NV_STATUS status;
    (void)context;
    args->provider = HYBRID580_UVM_PROVIDER_LEGACY;
#ifdef HYBRID580_UVM_ABI_R580
    status = hybrid580_legacy_nvUvmInterfaceRetainChannel(
        (uvmGpuAddressSpaceHandle)native_address_space, args->client,
        args->channel, &retained_channel, &args->channel_info);
#else
    args->legacy_channel_info =
        (struct hybrid580_r580_UvmGpuChannelInstanceInfo){0};
    status = hybrid580_legacy_nvUvmInterfaceRetainChannel(
        (uvmGpuAddressSpaceHandle)native_address_space, args->client,
        args->channel, &retained_channel, &args->legacy_channel_info);
#endif
#ifndef HYBRID580_UVM_ABI_R580
    if (status == NV_OK &&
        !hybrid580_uvm_channel_info_from_r580(&args->channel_info,
                                               &args->legacy_channel_info)) {
        if (retained_channel != NULL)
            hybrid580_legacy_nvUvmInterfaceReleaseChannel(retained_channel);
        retained_channel = NULL;
        status = NV_ERR_INVALID_ARGUMENT;
    }
#endif
    if (status == NV_OK &&
        args->channel_info.resourceCount > UVM_GPU_CHANNEL_MAX_RESOURCES) {
        if (retained_channel != NULL)
            hybrid580_legacy_nvUvmInterfaceReleaseChannel(retained_channel);
        retained_channel = NULL;
        status = NV_ERR_INVALID_ARGUMENT;
    }
    args->native_retained_channel = (uintptr_t)retained_channel;
    return (uint32_t)status;
}

struct hybrid580_uvm_bind_channel_resources_params {
    UvmGpuChannelResourceBindParams *bind_params;
};

static uint32_t hybrid580_open_bind_channel_resources(void *context,
    uintptr_t retained_channel, void *params)
{
    struct hybrid580_uvm_bind_channel_resources_params *args = params;
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceBindChannelResources(
        (void *)retained_channel, args->bind_params);
}

static uint32_t hybrid580_legacy_bind_channel_resources(void *context,
    uintptr_t retained_channel, void *params)
{
    struct hybrid580_uvm_bind_channel_resources_params *args = params;
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceBindChannelResources(
        (void *)retained_channel, args->bind_params);
}

struct hybrid580_uvm_stop_channel_params {
    NvBool immediate;
};

static uint32_t hybrid580_open_stop_channel(void *context,
    uintptr_t retained_channel, void *params)
{
    struct hybrid580_uvm_stop_channel_params *args = params;
    (void)context;
    hybrid580_open_nvUvmInterfaceStopChannel((void *)retained_channel,
                                              args->immediate);
    return NV_OK;
}

static uint32_t hybrid580_legacy_stop_channel(void *context,
    uintptr_t retained_channel, void *params)
{
    struct hybrid580_uvm_stop_channel_params *args = params;
    (void)context;
    hybrid580_legacy_nvUvmInterfaceStopChannel((void *)retained_channel,
                                                args->immediate);
    return NV_OK;
}

static void hybrid580_open_release_channel(void *context,
                                           uintptr_t retained_channel)
{
    (void)context;
    hybrid580_open_nvUvmInterfaceReleaseChannel((void *)retained_channel);
}

static void hybrid580_legacy_release_channel(void *context,
                                              uintptr_t retained_channel)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceReleaseChannel((void *)retained_channel);
}

struct hybrid580_uvm_channel_resource_ptes_params {
    NvP64 resource_descriptor;
    NvU64 offset;
    NvU64 size;
    UvmGpuExternalMappingInfo backend_info;
};

static uint32_t hybrid580_open_get_channel_resource_ptes(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_channel_resource_ptes_params *args = params;
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceGetChannelResourcePtes(
        (uvmGpuAddressSpaceHandle)vaSpace, args->resource_descriptor,
        args->offset, args->size, &args->backend_info);
}

static uint32_t hybrid580_legacy_get_channel_resource_ptes(void *context,
    uintptr_t vaSpace, void *params)
{
    struct hybrid580_uvm_channel_resource_ptes_params *args = params;
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceGetChannelResourcePtes(
        (uvmGpuAddressSpaceHandle)vaSpace, args->resource_descriptor,
        args->offset, args->size, &args->backend_info);
}

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_open_tsg_allocate_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_tsg_allocate,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_legacy_tsg_allocate_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_tsg_allocate,
};

static const struct hybrid580_uvm_typed_child_call_backend_ops
hybrid580_open_channel_allocate_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_channel_allocate,
};

static const struct hybrid580_uvm_typed_child_call_backend_ops
hybrid580_legacy_channel_allocate_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_channel_allocate,
};

static const struct hybrid580_uvm_typed_child_destroy_backend_ops
hybrid580_open_tsg_destroy_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .destroy = hybrid580_open_tsg_destroy,
};

static const struct hybrid580_uvm_typed_child_destroy_backend_ops
hybrid580_legacy_tsg_destroy_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .destroy = hybrid580_legacy_tsg_destroy,
};

static const struct hybrid580_uvm_typed_child_destroy_backend_ops
hybrid580_open_channel_destroy_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .destroy = hybrid580_open_channel_destroy,
};

static const struct hybrid580_uvm_typed_child_destroy_backend_ops
hybrid580_legacy_channel_destroy_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .destroy = hybrid580_legacy_channel_destroy,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_open_retain_channel_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_retain_channel,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_legacy_retain_channel_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_retain_channel,
};

static const struct hybrid580_uvm_typed_child_call_backend_ops
hybrid580_open_bind_channel_resources_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_bind_channel_resources,
};

static const struct hybrid580_uvm_typed_child_call_backend_ops
hybrid580_legacy_bind_channel_resources_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_bind_channel_resources,
};

static const struct hybrid580_uvm_typed_child_call_backend_ops
hybrid580_open_stop_channel_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_stop_channel,
};

static const struct hybrid580_uvm_typed_child_call_backend_ops
hybrid580_legacy_stop_channel_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_stop_channel,
};

static const struct hybrid580_uvm_typed_child_destroy_backend_ops
hybrid580_open_release_channel_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .destroy = hybrid580_open_release_channel,
};

static const struct hybrid580_uvm_typed_child_destroy_backend_ops
hybrid580_legacy_release_channel_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .destroy = hybrid580_legacy_release_channel,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_open_get_channel_resource_ptes_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_get_channel_resource_ptes,
};

static const struct hybrid580_uvm_address_space_call_backend_ops
hybrid580_legacy_get_channel_resource_ptes_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_get_channel_resource_ptes,
};

static const struct hybrid580_uvm_device_call_backend_ops
hybrid580_open_own_page_fault_intr_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_own_page_fault_intr,
};

static const struct hybrid580_uvm_device_call_backend_ops
hybrid580_legacy_own_page_fault_intr_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_own_page_fault_intr,
};

static const struct hybrid580_uvm_device_call_backend_ops
hybrid580_open_service_device_interrupts_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_service_device_interrupts,
};

static const struct hybrid580_uvm_device_call_backend_ops
hybrid580_legacy_service_device_interrupts_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_service_device_interrupts,
};

#define HYBRID580_DEFINE_DEVICE_QUERY(name, param_type) \
static uint32_t hybrid580_open_##name(void *context, uintptr_t device, void *params) \
{ \
    (void)context; \
    return (uint32_t)hybrid580_open_nvUvmInterface##name( \
        (uvmGpuDeviceHandle)device, (param_type *)params); \
} \
static uint32_t hybrid580_legacy_##name(void *context, uintptr_t device, void *params) \
{ \
    (void)context; \
    return (uint32_t)hybrid580_legacy_nvUvmInterface##name( \
        (uvmGpuDeviceHandle)device, (param_type *)params); \
}

HYBRID580_DEFINE_DEVICE_QUERY(GetFbInfo, UvmGpuFbInfo)
HYBRID580_DEFINE_DEVICE_QUERY(QueryCaps, UvmGpuCaps)
HYBRID580_DEFINE_DEVICE_QUERY(GetEccInfo, UvmGpuEccInfo)
HYBRID580_DEFINE_DEVICE_QUERY(GetNvlinkInfo, UvmGpuNvlinkInfo)

#undef HYBRID580_DEFINE_DEVICE_QUERY

static uint32_t hybrid580_open_QueryCopyEnginesCaps(void *context,
    uintptr_t device, void *params)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceQueryCopyEnginesCaps(
        (uvmGpuDeviceHandle)device, (UvmGpuCopyEnginesCaps *)params);
}

static uint32_t hybrid580_legacy_QueryCopyEnginesCaps(void *context,
    uintptr_t device, void *params)
{
#ifdef HYBRID580_UVM_ABI_R580
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps(
        (uvmGpuDeviceHandle)device, (UvmGpuCopyEnginesCaps *)params);
#else
    struct hybrid580_r580_UvmGpuCopyEnginesCaps legacy_caps = {0};
    NV_STATUS status;
    (void)context;

    status = hybrid580_legacy_nvUvmInterfaceQueryCopyEnginesCaps(
        (uvmGpuDeviceHandle)device, &legacy_caps);
    if (status == NV_OK)
        hybrid580_uvm_copy_caps_from_r580((UvmGpuCopyEnginesCaps *)params,
                                          &legacy_caps);
    return (uint32_t)status;
#endif
}

static uint32_t hybrid580_open_get_p2p_caps(void *context,
    uintptr_t device1, uintptr_t device2, void *params)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceGetP2PCaps(
        (uvmGpuDeviceHandle)device1, (uvmGpuDeviceHandle)device2,
        (UvmGpuP2PCapsParams *)params);
}

static uint32_t hybrid580_legacy_get_p2p_caps(void *context,
    uintptr_t device1, uintptr_t device2, void *params)
{
#ifdef HYBRID580_UVM_ABI_R580
    (void)context;
    return (uint32_t)hybrid580_legacy_nvUvmInterfaceGetP2PCaps(
        (uvmGpuDeviceHandle)device1, (uvmGpuDeviceHandle)device2,
        (UvmGpuP2PCapsParams *)params);
#else
    struct hybrid580_r580_UvmGpuP2PCapsParams legacy_caps = {0};
    NV_STATUS status;
    (void)context;
    status = hybrid580_legacy_nvUvmInterfaceGetP2PCaps(
        (uvmGpuDeviceHandle)device1, (uvmGpuDeviceHandle)device2,
        &legacy_caps);
    if (status == NV_OK &&
        !hybrid580_uvm_p2p_caps_from_r580((UvmGpuP2PCapsParams *)params,
                                          &legacy_caps))
        status = NV_ERR_INVALID_STATE;
    return (uint32_t)status;
#endif
}

static const struct hybrid580_uvm_device_pair_backend_ops
hybrid580_open_p2p_caps_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .call = hybrid580_open_get_p2p_caps,
};

static const struct hybrid580_uvm_device_pair_backend_ops
hybrid580_legacy_p2p_caps_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .call = hybrid580_legacy_get_p2p_caps,
};

static uint32_t hybrid580_open_p2p_object_create(
    void *context, uintptr_t device1, uintptr_t device2,
    uint32_t *native_handle)
{
    NvHandle handle = 0;
    NV_STATUS status;

    (void)context;
    *native_handle = 0;
    status = hybrid580_open_nvUvmInterfaceP2pObjectCreate(
        (uvmGpuDeviceHandle)device1, (uvmGpuDeviceHandle)device2, &handle);
    *native_handle = (uint32_t)handle;
    return (uint32_t)status;
}

static uint32_t hybrid580_legacy_p2p_object_create(
    void *context, uintptr_t device1, uintptr_t device2,
    uint32_t *native_handle)
{
    NvHandle handle = 0;
    NV_STATUS status;

    (void)context;
    *native_handle = 0;
    status = hybrid580_legacy_nvUvmInterfaceP2pObjectCreate(
        (uvmGpuDeviceHandle)device1, (uvmGpuDeviceHandle)device2, &handle);
    *native_handle = (uint32_t)handle;
    return (uint32_t)status;
}

static void hybrid580_open_p2p_object_destroy(void *context,
    uintptr_t native_session, uint32_t native_handle)
{
    (void)context;
    hybrid580_open_nvUvmInterfaceP2pObjectDestroy(
        (uvmGpuSessionHandle)native_session, (NvHandle)native_handle);
}

static void hybrid580_legacy_p2p_object_destroy(void *context,
    uintptr_t native_session, uint32_t native_handle)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceP2pObjectDestroy(
        (uvmGpuSessionHandle)native_session, (NvHandle)native_handle);
}

static struct hybrid580_uvm_p2p_object_backend_ops
hybrid580_open_p2p_object_ops(void)
{
    return (struct hybrid580_uvm_p2p_object_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .native_session = hybrid580_uvm_sessions.native_open,
        .create = hybrid580_open_p2p_object_create,
        .destroy = hybrid580_open_p2p_object_destroy,
    };
}

static struct hybrid580_uvm_p2p_object_backend_ops
hybrid580_legacy_p2p_object_ops(void)
{
    return (struct hybrid580_uvm_p2p_object_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .native_session = hybrid580_uvm_sessions.native_legacy,
        .create = hybrid580_legacy_p2p_object_create,
        .destroy = hybrid580_legacy_p2p_object_destroy,
    };
}

static NV_STATUS hybrid580_uvm_device_call(uvmGpuDeviceHandle device,
                                           void *params,
                                           uint32_t (*open_call)(void *, uintptr_t, void *),
                                           uint32_t (*legacy_call)(void *, uintptr_t, void *))
{
    struct hybrid580_uvm_device_call_backend_ops open_ops = {
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .call = open_call,
    };
    struct hybrid580_uvm_device_call_backend_ops legacy_ops = {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .call = legacy_call,
    };
    enum hybrid580_uvm_device_registry_status owner_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;

    if (device == NULL || params == NULL || open_call == NULL ||
        legacy_call == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_device_route_call(
        &hybrid580_uvm_devices, (uintptr_t)device, params, open_ops,
        legacy_ops, &backend_status);
    if (owner_status == HYBRID580_UVM_DEVICE_REGISTRY_OK) {
        status = (NV_STATUS)backend_status;
    } else {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM device query ownership map inconsistency (%d); frontend pinned\n",
                 owner_status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}

#ifndef HYBRID580_UVM_ABI_R580
struct hybrid580_uvm_access_bits_dump_call {
    UvmGpuAccessBitsBufferAlloc *info;
    UVM_ACCESS_BITS_DUMP_MODE mode;
};

static uint32_t hybrid580_open_access_bits_alloc(void *context,
                                                  uintptr_t native_device,
                                                  void *params)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceAccessBitsBufAlloc(
        (uvmGpuDeviceHandle)native_device,
        (UvmGpuAccessBitsBufferAlloc *)params);
}

static uint32_t hybrid580_open_access_bits_free(void *context,
                                                uintptr_t native_device,
                                                void *params)
{
    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceAccessBitsBufFree(
        (uvmGpuDeviceHandle)native_device,
        (UvmGpuAccessBitsBufferAlloc *)params);
}

static uint32_t hybrid580_open_access_bits_dump(void *context,
                                                uintptr_t native_device,
                                                void *params)
{
    struct hybrid580_uvm_access_bits_dump_call *call = params;

    (void)context;
    return (uint32_t)hybrid580_open_nvUvmInterfaceAccessBitsDump(
        (uvmGpuDeviceHandle)native_device, call->info, call->mode);
}

static uint32_t hybrid580_uvm_access_bits_not_supported(void *context,
                                                         uintptr_t native_device,
                                                         void *params)
{
    (void)context;
    (void)native_device;
    (void)params;
    return NV_ERR_NOT_SUPPORTED;
}
#endif

static NV_STATUS hybrid580_uvm_address_space_call(
    uvmGpuAddressSpaceHandle vaSpace, void *params,
    struct hybrid580_uvm_address_space_call_backend_ops open_ops,
    struct hybrid580_uvm_address_space_call_backend_ops legacy_ops)
{
    enum hybrid580_uvm_address_space_registry_status owner_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;

    if (vaSpace == NULL || params == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_address_space_route_call(
        &hybrid580_uvm_address_spaces, (uintptr_t)vaSpace, params,
        open_ops, legacy_ops, &backend_status);
    if (owner_status == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        status = (NV_STATUS)backend_status;
    } else {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM address-space ownership map inconsistency (%d); frontend pinned\n",
                 owner_status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}

static int hybrid580_open_register(void *context, void *callbacks)
{
    (void)context;
#ifdef HYBRID580_UVM_ABI_R580
    return hybrid580_open_nvUvmInterfaceRegisterUvmCallbacks(callbacks);
#else
    return hybrid580_open_nvUvmInterfaceRegisterUvmEvents(callbacks);
#endif
}

static int hybrid580_legacy_register(void *context, void *callbacks)
{
    (void)context;
    return hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks(callbacks);
}

static void hybrid580_open_deregister(void *context)
{
    (void)context;
#ifdef HYBRID580_UVM_ABI_R580
    hybrid580_open_nvUvmInterfaceDeRegisterUvmOps();
#else
    hybrid580_open_nvUvmInterfaceDeRegisterUvmEvents();
#endif
}

static void hybrid580_legacy_deregister(void *context)
{
    (void)context;
    hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps();
}

static const struct hybrid580_uvm_callback_backend hybrid580_open_uvm_backend = {
    .register_callbacks = hybrid580_open_register,
    .deregister_callbacks = hybrid580_open_deregister,
};

static const struct hybrid580_uvm_callback_backend hybrid580_legacy_uvm_backend = {
    .register_callbacks = hybrid580_legacy_register,
    .deregister_callbacks = hybrid580_legacy_deregister,
};

#ifndef HYBRID580_UVM_ABI_R580
/* R580 RM retains the translated callback table until deregistration. */
static struct UvmOpsUvmEvents hybrid580_legacy_uvm_events;
#endif

static NV_STATUS hybrid580_uvm_register_callbacks_locked(
    void *open_callbacks, void *legacy_callbacks)
{
    struct hybrid580_uvm_callback_result result;

    if (open_callbacks == NULL || legacy_callbacks == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (hybrid580_uvm_callbacks.registered) {
        return NV_ERR_IN_USE;
    }
    result = hybrid580_uvm_callback_register(&hybrid580_uvm_callbacks,
                                               open_callbacks,
                                               legacy_callbacks,
                                               hybrid580_open_uvm_backend,
                                               hybrid580_legacy_uvm_backend);

    switch (result.code) {
    case HYBRID580_UVM_CALLBACK_OK:
        return NV_OK;
    case HYBRID580_UVM_CALLBACK_INVALID:
        return NV_ERR_INVALID_ARGUMENT;
    case HYBRID580_UVM_CALLBACK_BUSY:
        return NV_ERR_IN_USE;
    case HYBRID580_UVM_CALLBACK_OPEN_FAILED:
    case HYBRID580_UVM_CALLBACK_LEGACY_FAILED:
        return result.backend_status;
    }

    return NV_ERR_GENERIC;
}

#ifdef HYBRID580_UVM_ABI_R580
static NV_STATUS hybrid580_uvm_register_callbacks(void *open_callbacks,
                                                   void *legacy_callbacks)
{
    NV_STATUS status;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_register_callbacks_locked(open_callbacks,
                                                       legacy_callbacks);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
#endif

static void hybrid580_uvm_deregister_callbacks(void)
{
    mutex_lock(&hybrid580_uvm_callback_lock);
    hybrid580_uvm_callback_unregister(&hybrid580_uvm_callbacks,
                                      hybrid580_open_uvm_backend,
                                      hybrid580_legacy_uvm_backend);
#ifndef HYBRID580_UVM_ABI_R580
    memset(&hybrid580_legacy_uvm_events, 0,
           sizeof(hybrid580_legacy_uvm_events));
#endif
    mutex_unlock(&hybrid580_uvm_callback_lock);
}

#ifdef HYBRID580_UVM_ABI_R580
NV_STATUS nvUvmInterfaceRegisterUvmCallbacks(
    struct UvmOpsUvmEvents *importedUvmOps)
{
    return hybrid580_uvm_register_callbacks(importedUvmOps, importedUvmOps);
}
EXPORT_SYMBOL(nvUvmInterfaceRegisterUvmCallbacks);

void nvUvmInterfaceDeRegisterUvmOps(void)
{
    hybrid580_uvm_deregister_callbacks();
}
EXPORT_SYMBOL(nvUvmInterfaceDeRegisterUvmOps);
#else
NV_STATUS nvUvmInterfaceRegisterUvmEvents(struct UvmEventsLinux *importedEvents)
{
    NV_STATUS status;

    if (importedEvents == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    hybrid580_legacy_uvm_events = hybrid580_uvm_event_compat_from_linux(
        importedEvents);
    status = hybrid580_uvm_register_callbacks_locked(
        importedEvents, &hybrid580_legacy_uvm_events);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceRegisterUvmEvents);

void nvUvmInterfaceDeRegisterUvmEvents(void)
{
    hybrid580_uvm_deregister_callbacks();
}
EXPORT_SYMBOL(nvUvmInterfaceDeRegisterUvmEvents);
#endif

static int hybrid580_open_session_create(void *context, uintptr_t *handle)
{
    struct hybrid580_uvm_session_provider_context *provider = context;
    uvmGpuSessionHandle native_session = NULL;

    memset(&provider->platform, 0, sizeof(provider->platform));
    provider->create_status = hybrid580_open_nvUvmInterfaceSessionCreate(
        &native_session, &provider->platform);
    *handle = (uintptr_t)native_session;
    return provider->create_status == NV_OK ? 0 : -1;
}

static int hybrid580_legacy_session_create(void *context, uintptr_t *handle)
{
    struct hybrid580_uvm_session_provider_context *provider = context;
    uvmGpuSessionHandle native_session = NULL;

    memset(&provider->platform, 0, sizeof(provider->platform));
    provider->create_status = hybrid580_legacy_nvUvmInterfaceSessionCreate(
        &native_session, &provider->platform);
    *handle = (uintptr_t)native_session;
    return provider->create_status == NV_OK ? 0 : -1;
}

static enum hybrid580_uvm_destroy_result
hybrid580_open_session_destroy(void *context, uintptr_t handle)
{
    struct hybrid580_uvm_session_provider_context *provider = context;

    provider->destroy_status = hybrid580_open_nvUvmInterfaceSessionDestroy(
        (uvmGpuSessionHandle)handle);
    return provider->destroy_status == NV_OK ? HYBRID580_UVM_DESTROYED :
                                                HYBRID580_UVM_DESTROY_AMBIGUOUS;
}

static enum hybrid580_uvm_destroy_result
hybrid580_legacy_session_destroy(void *context, uintptr_t handle)
{
    struct hybrid580_uvm_session_provider_context *provider = context;

    provider->destroy_status = hybrid580_legacy_nvUvmInterfaceSessionDestroy(
        (uvmGpuSessionHandle)handle);
    return provider->destroy_status == NV_OK ? HYBRID580_UVM_DESTROYED :
                                                HYBRID580_UVM_DESTROY_AMBIGUOUS;
}

static struct hybrid580_uvm_session_result
hybrid580_uvm_create_result(enum hybrid580_uvm_session_pair_status status)
{
    struct hybrid580_uvm_session_result result = {
        .code = status,
        .backend_status = NV_OK,
    };

    if (hybrid580_open_session_context.create_status != NV_OK)
        result.backend_status = hybrid580_open_session_context.create_status;
    else if (hybrid580_legacy_session_context.create_status != NV_OK)
        result.backend_status = hybrid580_legacy_session_context.create_status;

    if (hybrid580_open_session_context.destroy_status != NV_OK)
        result.backend_status = hybrid580_open_session_context.destroy_status;
    else if (hybrid580_legacy_session_context.destroy_status != NV_OK)
        result.backend_status = hybrid580_legacy_session_context.destroy_status;

    return result;
}

static NV_STATUS hybrid580_uvm_session_backend_status(
    const struct hybrid580_uvm_session_result *result)
{
    if (result->backend_status != NV_OK)
        return result->backend_status;

    switch (result->code) {
    case HYBRID580_UVM_SESSION_OK:
        return NV_OK;
    case HYBRID580_UVM_SESSION_BUSY:
        return NV_ERR_IN_USE;
    case HYBRID580_UVM_SESSION_INVALID:
        return NV_ERR_INVALID_ARGUMENT;
    case HYBRID580_UVM_SESSION_INVALID_HANDLE:
        return NV_ERR_GENERIC;
    default:
        return NV_ERR_GENERIC;
    }
}

static void hybrid580_uvm_pin_quarantined_state(void)
{
    if (hybrid580_uvm_quarantine_module_pin)
        return;

    /* An RM destroy or UVM ownership-map inconsistency leaves native state
     * ambiguous. Keep this module and both dependency providers resident
     * instead of unloading code under a possibly live RM resource. Recovery
     * currently requires reboot.
     */
    if (try_module_get(THIS_MODULE))
        hybrid580_uvm_quarantine_module_pin = true;
    else
        pr_emerg("hybrid580 UVM ownership is quarantined but frontend pin failed\n");
}

NV_STATUS nvUvmInterfaceSessionCreate(uvmGpuSessionHandle *session,
                                      UvmPlatformInfo *platformInfo)
{
    struct hybrid580_uvm_provider_ops open_ops = {
        .context = &hybrid580_open_session_context,
        .create = hybrid580_open_session_create,
        .destroy = hybrid580_open_session_destroy,
    };
    struct hybrid580_uvm_provider_ops legacy_ops = {
        .context = &hybrid580_legacy_session_context,
        .create = hybrid580_legacy_session_create,
        .destroy = hybrid580_legacy_session_destroy,
    };
    struct hybrid580_uvm_session_result result;
    enum hybrid580_uvm_session_pair_status pair_status;
    NV_STATUS status;

    if (session == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *session = NULL;
    if (platformInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    memset(&hybrid580_open_session_context, 0, sizeof(hybrid580_open_session_context));
    memset(&hybrid580_legacy_session_context, 0, sizeof(hybrid580_legacy_session_context));

    pair_status = hybrid580_uvm_session_pair_create(&hybrid580_uvm_sessions,
                                                     open_ops, legacy_ops);
    if (pair_status == HYBRID580_UVM_SESSION_OK &&
        (hybrid580_open_session_context.platform.atsSupported !=
             hybrid580_legacy_session_context.platform.atsSupported ||
         hybrid580_open_session_context.platform.confComputingEnabled !=
             hybrid580_legacy_session_context.platform.confComputingEnabled)) {
        pair_status = hybrid580_uvm_session_pair_destroy(&hybrid580_uvm_sessions);
        if (pair_status == HYBRID580_UVM_SESSION_OK) {
            status = NV_ERR_INVALID_STATE;
        } else {
            result = hybrid580_uvm_create_result(pair_status);
            hybrid580_uvm_pin_quarantined_state();
            status = hybrid580_uvm_session_backend_status(&result);
        }
        goto out;
    }

    if (pair_status != HYBRID580_UVM_SESSION_OK) {
        result = hybrid580_uvm_create_result(pair_status);
        if (hybrid580_uvm_sessions.state != HYBRID580_UVM_SESSION_PAIR_EMPTY)
            hybrid580_uvm_pin_quarantined_state();
        status = hybrid580_uvm_session_backend_status(&result);
        goto out;
    }

    pair_status = hybrid580_uvm_session_pair_publish_identity(
        &hybrid580_uvm_sessions, (uintptr_t)&hybrid580_uvm_sessions);
    if (pair_status != HYBRID580_UVM_SESSION_OK) {
        pair_status = hybrid580_uvm_session_pair_destroy(&hybrid580_uvm_sessions);
        if (pair_status == HYBRID580_UVM_SESSION_OK) {
            status = NV_ERR_INVALID_ARGUMENT;
        } else {
            result = hybrid580_uvm_create_result(pair_status);
            hybrid580_uvm_pin_quarantined_state();
            status = hybrid580_uvm_session_backend_status(&result);
        }
        goto out;
    }

    platformInfo->atsSupported = hybrid580_open_session_context.platform.atsSupported;
    platformInfo->confComputingEnabled =
        hybrid580_open_session_context.platform.confComputingEnabled;
    *session = (uvmGpuSessionHandle)&hybrid580_uvm_sessions;
    status = NV_OK;

out:
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceSessionCreate);

NV_STATUS nvUvmInterfaceSessionDestroy(uvmGpuSessionHandle session)
{
    struct hybrid580_uvm_session_result result;
    enum hybrid580_uvm_session_pair_status pair_status;
    NV_STATUS status;

    mutex_lock(&hybrid580_uvm_callback_lock);
    if ((uintptr_t)session != (uintptr_t)&hybrid580_uvm_sessions ||
        hybrid580_uvm_sessions.state != HYBRID580_UVM_SESSION_PAIR_ACTIVE) {
        mutex_unlock(&hybrid580_uvm_callback_lock);
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (hybrid580_uvm_device_registry_count(&hybrid580_uvm_devices) != 0) {
        mutex_unlock(&hybrid580_uvm_callback_lock);
        return NV_ERR_IN_USE;
    }
    if (hybrid580_uvm_p2p_objects.count != 0) {
        mutex_unlock(&hybrid580_uvm_callback_lock);
        return NV_ERR_IN_USE;
    }

    pair_status = hybrid580_uvm_session_pair_destroy(&hybrid580_uvm_sessions);
    result = hybrid580_uvm_create_result(pair_status);
    status = hybrid580_uvm_session_backend_status(&result);
    if (pair_status != HYBRID580_UVM_SESSION_OK)
        hybrid580_uvm_pin_quarantined_state();
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceSessionDestroy);

NV_STATUS nvUvmInterfaceRegisterGpu(const NvProcessorUuid *gpuUuid,
                                    UvmGpuPlatformInfo *gpuInfo)
{
    UvmGpuPlatformInfo open_info = {0};
    UvmGpuPlatformInfo legacy_info = {0};
    uint32_t status;

    if (gpuInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(gpuInfo, 0, sizeof(*gpuInfo));
    if (gpuUuid == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    if (sizeof(gpuUuid->uuid) != HYBRID580_UVM_GPU_UUID_BYTES)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_gpu_route_register(
        &hybrid580_uvm_gpu_registry, gpuUuid->uuid, gpuInfo, sizeof(*gpuInfo),
        &open_info, &legacy_info, hybrid580_open_gpu_ops,
        hybrid580_legacy_gpu_ops, NV_ERR_GPU_UUID_NOT_FOUND,
        NV_ERR_NO_MEMORY, NV_ERR_GENERIC);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return (NV_STATUS)status;
}
EXPORT_SYMBOL(nvUvmInterfaceRegisterGpu);

void nvUvmInterfaceUnregisterGpu(const NvProcessorUuid *gpuUuid)
{
    enum hybrid580_uvm_gpu_registry_status status;

    if (gpuUuid == NULL)
        return;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_gpu_route_unregister(
        &hybrid580_uvm_gpu_registry, gpuUuid->uuid,
        hybrid580_open_gpu_ops, hybrid580_legacy_gpu_ops);
    mutex_unlock(&hybrid580_uvm_callback_lock);

    if (status != HYBRID580_UVM_GPU_REGISTRY_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM GPU registration map inconsistency (%d); frontend pinned\n",
                 status);
    }
}
EXPORT_SYMBOL(nvUvmInterfaceUnregisterGpu);

NV_STATUS nvUvmInterfaceGetGpuProvider(const NvProcessorUuid *gpuUuid,
                                      NvU32 *providerId)
{
    enum hybrid580_uvm_gpu_registry_status status;
    enum hybrid580_uvm_provider provider = 0;

    if (gpuUuid == NULL || providerId == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *providerId = 0;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_gpu_registry_lookup(
        &hybrid580_uvm_gpu_registry, gpuUuid->uuid, &provider, NULL);
    mutex_unlock(&hybrid580_uvm_callback_lock);

    if (status == HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND)
        return NV_ERR_GPU_UUID_NOT_FOUND;
    if (status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return NV_ERR_GENERIC;

    if (provider == HYBRID580_UVM_PROVIDER_OPEN)
        *providerId = HYBRID580_UVM_PROVIDER_ID_OPEN;
    else if (provider == HYBRID580_UVM_PROVIDER_LEGACY)
        *providerId = HYBRID580_UVM_PROVIDER_ID_LEGACY;
    else
        return NV_ERR_GENERIC;

    return NV_OK;
}
EXPORT_SYMBOL(nvUvmInterfaceGetGpuProvider);

NV_STATUS nvUvmInterfaceAreGpuProvidersSame(
    const NvProcessorUuid *gpuUuid1,
    const NvProcessorUuid *gpuUuid2,
    NvBool *sameProvider)
{
    enum hybrid580_uvm_gpu_registry_status status;
    int same = 0;

    if (gpuUuid1 == NULL || gpuUuid2 == NULL || sameProvider == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *sameProvider = NV_FALSE;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_gpu_registry_same_provider(
        &hybrid580_uvm_gpu_registry, gpuUuid1->uuid, gpuUuid2->uuid, &same);
    mutex_unlock(&hybrid580_uvm_callback_lock);

    if (status == HYBRID580_UVM_GPU_REGISTRY_NOT_FOUND)
        return NV_ERR_GPU_UUID_NOT_FOUND;
    if (status != HYBRID580_UVM_GPU_REGISTRY_OK)
        return NV_ERR_GENERIC;

    *sameProvider = same ? NV_TRUE : NV_FALSE;
    return NV_OK;
}
EXPORT_SYMBOL(nvUvmInterfaceAreGpuProvidersSame);

NV_STATUS nvUvmInterfaceGetGpuInfo(const NvProcessorUuid *gpuUuid,
                                   const UvmGpuClientInfo *pGpuClientInfo,
                                   UvmGpuInfo *pGpuInfo)
{
    uint32_t status;

    if (pGpuInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(pGpuInfo, 0, sizeof(*pGpuInfo));
    if (gpuUuid == NULL || pGpuClientInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    /* This frontend exposes physical GPUs only. SMC partition handles have
     * their own RM namespace and are not translated by the current API. */
    if (pGpuClientInfo->hSmcPartRef != 0)
        return NV_ERR_NOT_SUPPORTED;
    if (sizeof(gpuUuid->uuid) != HYBRID580_UVM_GPU_UUID_BYTES)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_gpu_route_get_info(
        &hybrid580_uvm_gpu_registry, gpuUuid->uuid, pGpuClientInfo, pGpuInfo,
        sizeof(*pGpuInfo),
        hybrid580_open_gpu_info_ops, hybrid580_legacy_gpu_info_ops,
        NV_ERR_GPU_UUID_NOT_FOUND, NV_ERR_GENERIC);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return (NV_STATUS)status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetGpuInfo);

NV_STATUS nvUvmInterfaceDeviceCreate(uvmGpuSessionHandle session,
                                     const UvmGpuInfo *pGpuInfo,
                                     const NvProcessorUuid *gpuUuid,
                                     uvmGpuDeviceHandle *device,
                                     NvBool bCreateSmcPartition)
{
    struct hybrid580_uvm_device_backend_ops open_ops;
    struct hybrid580_uvm_device_backend_ops legacy_ops;
    uintptr_t public_device = 0;
    int quarantine = 0;
    uint32_t status;

    if (device == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *device = NULL;
    if (pGpuInfo == NULL || gpuUuid == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    if (session != (uvmGpuSessionHandle)&hybrid580_uvm_sessions ||
        hybrid580_uvm_sessions.state != HYBRID580_UVM_SESSION_PAIR_ACTIVE) {
        mutex_unlock(&hybrid580_uvm_callback_lock);
        return NV_ERR_INVALID_ARGUMENT;
    }

    open_ops = (struct hybrid580_uvm_device_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .native_session = (uintptr_t)hybrid580_uvm_sessions.native_open,
        .create = hybrid580_open_device_create,
        .destroy = hybrid580_open_device_destroy,
    };
    legacy_ops = (struct hybrid580_uvm_device_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .native_session = (uintptr_t)hybrid580_uvm_sessions.native_legacy,
        .create = hybrid580_legacy_device_create,
        .destroy = hybrid580_legacy_device_destroy,
    };
    status = hybrid580_uvm_device_route_create(
        &hybrid580_uvm_gpu_registry, &hybrid580_uvm_devices, gpuUuid->uuid,
        pGpuInfo, bCreateSmcPartition != NV_FALSE, open_ops, legacy_ops,
        NV_ERR_GPU_UUID_NOT_FOUND, NV_ERR_NO_MEMORY, NV_ERR_NOT_SUPPORTED,
        NV_ERR_GENERIC, &public_device, &quarantine);
    if (status == 0)
        *device = (uvmGpuDeviceHandle)public_device;
    if (quarantine) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM device create returned ambiguous native state; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return (NV_STATUS)status;
}
EXPORT_SYMBOL(nvUvmInterfaceDeviceCreate);

void nvUvmInterfaceDeviceDestroy(uvmGpuDeviceHandle device)
{
    struct hybrid580_uvm_device_backend_ops open_ops;
    struct hybrid580_uvm_device_backend_ops legacy_ops;
    enum hybrid580_uvm_device_registry_status status;
    enum hybrid580_uvm_pma_status pma_status;
    unsigned long info_flags;
    int info_parent_busy;

    mutex_lock(&hybrid580_uvm_callback_lock);
    open_ops = (struct hybrid580_uvm_device_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_OPEN,
        .native_session = (uintptr_t)hybrid580_uvm_sessions.native_open,
        .create = hybrid580_open_device_create,
        .destroy = hybrid580_open_device_destroy,
    };
    legacy_ops = (struct hybrid580_uvm_device_backend_ops) {
        .provider = HYBRID580_UVM_PROVIDER_LEGACY,
        .native_session = (uintptr_t)hybrid580_uvm_sessions.native_legacy,
        .create = hybrid580_legacy_device_create,
        .destroy = hybrid580_legacy_device_destroy,
    };
    pma_status = hybrid580_uvm_pma_registry_device_destroy_check(
        &hybrid580_uvm_pmas, (uintptr_t)device);
    spin_lock_irqsave(&hybrid580_uvm_info_lock, info_flags);
    info_parent_busy = hybrid580_uvm_info_registry_has_parent(
        &hybrid580_uvm_infos, (uintptr_t)device);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, info_flags);
    if (pma_status != HYBRID580_UVM_PMA_OK)
        status = HYBRID580_UVM_DEVICE_REGISTRY_BUSY;
    else if (info_parent_busy ||
        hybrid580_uvm_address_space_registry_has_parent(
            &hybrid580_uvm_address_spaces, (uintptr_t)device) ||
        hybrid580_uvm_p2p_object_has_parent(&hybrid580_uvm_p2p_objects,
                                             (uintptr_t)device) ||
        hybrid580_uvm_typed_child_registry_has_parent(
            &hybrid580_uvm_typed_children, (uintptr_t)device,
            HYBRID580_UVM_TYPED_CHILD_PARENT_DEVICE))
        status = HYBRID580_UVM_DEVICE_REGISTRY_BUSY;
    else
        status = hybrid580_uvm_device_route_destroy(
            &hybrid580_uvm_devices, (uintptr_t)device, open_ops, legacy_ops);
    if (status == HYBRID580_UVM_DEVICE_REGISTRY_OK &&
        hybrid580_uvm_pma_registry_release_device(
            &hybrid580_uvm_pmas, (uintptr_t)device) != HYBRID580_UVM_PMA_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM PMA ownership release failed after device teardown; frontend pinned\n");
    }
    if (status != HYBRID580_UVM_DEVICE_REGISTRY_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM device ownership map inconsistency (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceDeviceDestroy);

NV_STATUS nvUvmInterfaceGetPmaObject(uvmGpuDeviceHandle device,
                                     void **pPma,
                                     const UvmPmaStatistics **pPmaPubStats)
{
    enum hybrid580_uvm_device_registry_status owner_status;
    enum hybrid580_uvm_pma_status pma_status;
    enum hybrid580_uvm_provider provider = 0;
    uintptr_t native_device = 0;
    void *native_pma = NULL;
    const UvmPmaStatistics *native_stats = NULL;
    NV_STATUS status;
    int quarantine = 0;

    if (pPma == NULL || pPmaPubStats == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *pPma = NULL;
    *pPmaPubStats = NULL;
    if (device == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_device_registry_lookup(
        &hybrid580_uvm_devices, (uintptr_t)device, &provider, &native_device);
    if (owner_status != HYBRID580_UVM_DEVICE_REGISTRY_OK || native_device == 0) {
        status = NV_ERR_INVALID_OBJECT_HANDLE;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM PMA device owner is unknown (%d); frontend pinned\n",
                 owner_status);
        goto out;
    }

    if (provider == HYBRID580_UVM_PROVIDER_OPEN)
        status = hybrid580_open_nvUvmInterfaceGetPmaObject(
            (uvmGpuDeviceHandle)native_device, &native_pma, &native_stats);
    else if (provider == HYBRID580_UVM_PROVIDER_LEGACY)
        status = hybrid580_legacy_nvUvmInterfaceGetPmaObject(
            (uvmGpuDeviceHandle)native_device, &native_pma, &native_stats);
    else {
        status = NV_ERR_INVALID_STATE;
        goto out;
    }
    if (status != NV_OK)
        goto out;
    if (native_pma == NULL || native_stats == NULL) {
        status = NV_ERR_INVALID_STATE;
        goto out;
    }

    pma_status = hybrid580_uvm_pma_registry_record(
        &hybrid580_uvm_devices, &hybrid580_uvm_pmas, (uintptr_t)device,
        (uintptr_t)native_pma, (uintptr_t)native_stats, &quarantine);
    if (pma_status != HYBRID580_UVM_PMA_OK) {
        status = hybrid580_uvm_pma_status_to_nv(pma_status);
        if (quarantine) {
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM PMA native pointer is ambiguous; affected owner quarantined and frontend pinned\n");
        }
        goto out;
    }

    /* UVM reads these volatile statistics in place. R580 has a 48-byte
     * six-counter prefix and R595 appends localizable-region counters. The
     * pinned R595 runtime only reads numFreePages64k/numFreePages2m, whose
     * offsets remain in that prefix; never expose the newer tail as present. */
    *pPma = native_pma;
    *pPmaPubStats = native_stats;
out:
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetPmaObject);

NV_STATUS nvUvmInterfacePmaRegisterEvictionCallbacks(
    void *pPma, uvmPmaEvictPagesCallback evictPages,
    uvmPmaEvictRangeCallback evictRange, void *callbackData)
{
    struct hybrid580_uvm_pma_pin pin = {0};
    const struct hybrid580_uvm_pma_backend_ops *ops;
    NV_STATUS status;

    if (evictPages == NULL || evictRange == NULL || callbackData == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    status = hybrid580_uvm_pma_pin(pPma, &pin);
    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_pma_backend(pin.provider);
    if (ops == NULL) {
        hybrid580_uvm_pma_unpin(&pin, -1);
        return NV_ERR_INVALID_STATE;
    }

    status = ops->register_callbacks(pPma, evictPages, evictRange, callbackData);
    hybrid580_uvm_pma_unpin(&pin, status == NV_OK ? 1 : -1);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfacePmaRegisterEvictionCallbacks);

void nvUvmInterfacePmaUnregisterEvictionCallbacks(void *pPma)
{
    struct hybrid580_uvm_pma_pin pin = {0};
    const struct hybrid580_uvm_pma_backend_ops *ops;
    NV_STATUS status;

    status = hybrid580_uvm_pma_pin(pPma, &pin);
    if (status != NV_OK)
        return;
    ops = hybrid580_uvm_pma_backend(pin.provider);
    if (ops == NULL) {
        hybrid580_uvm_pma_unpin(&pin, -1);
        return;
    }
    ops->unregister_callbacks(pPma);
    hybrid580_uvm_pma_unpin(&pin, 0);
}
EXPORT_SYMBOL(nvUvmInterfacePmaUnregisterEvictionCallbacks);

NV_STATUS nvUvmInterfacePmaAllocPages(void *pPma, NvLength pageCount,
                                      NvU64 pageSize,
                                      UvmPmaAllocationOptions *pPmaAllocOptions,
                                      NvU64 *pPages)
{
    struct hybrid580_uvm_pma_pin pin = {0};
    const struct hybrid580_uvm_pma_backend_ops *ops;
    NV_STATUS status;

    if ((pageCount != 0 && pPages == NULL) || pPmaAllocOptions == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    status = hybrid580_uvm_pma_pin(pPma, &pin);
    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_pma_backend(pin.provider);
    if (ops == NULL) {
        hybrid580_uvm_pma_unpin(&pin, -1);
        return NV_ERR_INVALID_STATE;
    }
    status = ops->allocate_pages(pPma, pageCount, pageSize,
                                 pPmaAllocOptions, pPages);
    hybrid580_uvm_pma_unpin(&pin, -1);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfacePmaAllocPages);

NV_STATUS nvUvmInterfacePmaPinPages(void *pPma, NvU64 *pPages,
                                    NvLength pageCount, NvU64 pageSize,
                                    NvU32 flags)
{
    struct hybrid580_uvm_pma_pin pin = {0};
    const struct hybrid580_uvm_pma_backend_ops *ops;
    NV_STATUS status;

    if (pageCount != 0 && pPages == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    status = hybrid580_uvm_pma_pin(pPma, &pin);
    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_pma_backend(pin.provider);
    if (ops == NULL) {
        hybrid580_uvm_pma_unpin(&pin, -1);
        return NV_ERR_INVALID_STATE;
    }
    status = ops->pin_pages(pPma, pPages, pageCount, pageSize, flags);
    hybrid580_uvm_pma_unpin(&pin, -1);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfacePmaPinPages);

void nvUvmInterfacePmaFreePages(void *pPma, NvU64 *pPages,
                                NvLength pageCount, NvU64 pageSize,
                                NvU32 flags)
{
    struct hybrid580_uvm_pma_pin pin = {0};
    const struct hybrid580_uvm_pma_backend_ops *ops;
    NV_STATUS status;

    if (pageCount != 0 && pPages == NULL) {
        pr_emerg("hybrid580 UVM PMA free received a null page array; request dropped\n");
        mutex_lock(&hybrid580_uvm_callback_lock);
        hybrid580_uvm_pin_quarantined_state();
        mutex_unlock(&hybrid580_uvm_callback_lock);
        return;
    }
    status = hybrid580_uvm_pma_pin(pPma, &pin);
    if (status != NV_OK)
        return;
    ops = hybrid580_uvm_pma_backend(pin.provider);
    if (ops == NULL) {
        hybrid580_uvm_pma_unpin(&pin, -1);
        return;
    }
    ops->free_pages(pPma, pPages, pageCount, pageSize, flags);
    hybrid580_uvm_pma_unpin(&pin, -1);
}
EXPORT_SYMBOL(nvUvmInterfacePmaFreePages);

NV_STATUS nvUvmInterfaceGetFbInfo(uvmGpuDeviceHandle device,
                                  UvmGpuFbInfo *fbInfo)
{
    NV_STATUS status;

    if (fbInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(fbInfo, 0, sizeof(*fbInfo));
    status = hybrid580_uvm_device_call(device, fbInfo,
                                       hybrid580_open_GetFbInfo,
                                       hybrid580_legacy_GetFbInfo);
    if (status != NV_OK)
        memset(fbInfo, 0, sizeof(*fbInfo));
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetFbInfo);

NV_STATUS nvUvmInterfaceQueryCaps(uvmGpuDeviceHandle device,
                                  UvmGpuCaps *caps)
{
    NV_STATUS status;

    if (caps == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(caps, 0, sizeof(*caps));
    status = hybrid580_uvm_device_call(device, caps,
                                       hybrid580_open_QueryCaps,
                                       hybrid580_legacy_QueryCaps);
    if (status != NV_OK)
        memset(caps, 0, sizeof(*caps));
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceQueryCaps);

NV_STATUS nvUvmInterfaceQueryCopyEnginesCaps(uvmGpuDeviceHandle device,
                                             UvmGpuCopyEnginesCaps *caps)
{
    NV_STATUS status;

    if (caps == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(caps, 0, sizeof(*caps));
    status = hybrid580_uvm_device_call(device, caps,
                                       hybrid580_open_QueryCopyEnginesCaps,
                                       hybrid580_legacy_QueryCopyEnginesCaps);
    if (status != NV_OK)
        memset(caps, 0, sizeof(*caps));
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceQueryCopyEnginesCaps);

NV_STATUS nvUvmInterfaceGetEccInfo(uvmGpuDeviceHandle device,
                                   UvmGpuEccInfo *eccInfo)
{
    NV_STATUS status;

    if (eccInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(eccInfo, 0, sizeof(*eccInfo));
    status = hybrid580_uvm_device_call(device, eccInfo,
                                       hybrid580_open_GetEccInfo,
                                       hybrid580_legacy_GetEccInfo);
    if (status != NV_OK)
        memset(eccInfo, 0, sizeof(*eccInfo));
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetEccInfo);

NV_STATUS nvUvmInterfaceGetNvlinkInfo(uvmGpuDeviceHandle device,
                                      UvmGpuNvlinkInfo *nvlinkInfo)
{
    NV_STATUS status;

    if (nvlinkInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(nvlinkInfo, 0, sizeof(*nvlinkInfo));
    status = hybrid580_uvm_device_call(device, nvlinkInfo,
                                       hybrid580_open_GetNvlinkInfo,
                                       hybrid580_legacy_GetNvlinkInfo);
    if (status != NV_OK)
        memset(nvlinkInfo, 0, sizeof(*nvlinkInfo));
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetNvlinkInfo);

#ifndef HYBRID580_UVM_ABI_R580
NV_STATUS nvUvmInterfaceAccessBitsBufAlloc(
    uvmGpuDeviceHandle device,
    UvmGpuAccessBitsBufferAlloc *pAccessBitsInfo)
{
    if (device == NULL || pAccessBitsInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    return hybrid580_uvm_device_call(device, pAccessBitsInfo,
                                     hybrid580_open_access_bits_alloc,
                                     hybrid580_uvm_access_bits_not_supported);
}
EXPORT_SYMBOL(nvUvmInterfaceAccessBitsBufAlloc);

NV_STATUS nvUvmInterfaceAccessBitsBufFree(
    uvmGpuDeviceHandle device,
    UvmGpuAccessBitsBufferAlloc *pAccessBitsInfo)
{
    if (device == NULL || pAccessBitsInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    return hybrid580_uvm_device_call(device, pAccessBitsInfo,
                                     hybrid580_open_access_bits_free,
                                     hybrid580_uvm_access_bits_not_supported);
}
EXPORT_SYMBOL(nvUvmInterfaceAccessBitsBufFree);

NV_STATUS nvUvmInterfaceAccessBitsDump(
    uvmGpuDeviceHandle device,
    UvmGpuAccessBitsBufferAlloc *pAccessBitsInfo,
    UVM_ACCESS_BITS_DUMP_MODE mode)
{
    struct hybrid580_uvm_access_bits_dump_call call = {
        .info = pAccessBitsInfo,
        .mode = mode,
    };

    if (device == NULL || pAccessBitsInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    switch (mode) {
        case UVM_ACCESS_BITS_DUMP_MODE_AGGREGATE:
        case UVM_ACCESS_BITS_DUMP_MODE_DIFF:
        case UVM_ACCESS_BITS_DUMP_MODE_CURRENT:
            break;
        default:
            return NV_ERR_INVALID_ARGUMENT;
    }

    return hybrid580_uvm_device_call(device, &call,
                                     hybrid580_open_access_bits_dump,
                                     hybrid580_uvm_access_bits_not_supported);
}
EXPORT_SYMBOL(nvUvmInterfaceAccessBitsDump);
#endif

NV_STATUS nvUvmInterfaceGetP2PCaps(uvmGpuDeviceHandle device1,
                                   uvmGpuDeviceHandle device2,
                                   UvmGpuP2PCapsParams *p2pCapsParams)
{
    enum hybrid580_uvm_device_pair_route_status route_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;

    if (p2pCapsParams == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(p2pCapsParams, 0, sizeof(*p2pCapsParams));
    if (device1 == NULL || device2 == NULL || device1 == device2)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    route_status = hybrid580_uvm_device_route_pair_call(
        &hybrid580_uvm_devices, (uintptr_t)device1, (uintptr_t)device2,
        p2pCapsParams, hybrid580_open_p2p_caps_ops,
        hybrid580_legacy_p2p_caps_ops, &backend_status);
    if (route_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_OK) {
        status = (NV_STATUS)backend_status;
        if (status != NV_OK)
            memset(p2pCapsParams, 0, sizeof(*p2pCapsParams));
    } else if (route_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_CROSS_PROVIDER) {
        /* Neither RM can query or establish links with the other's opaque
         * device handle. Report no UVM peer link so mixed-provider GPU
         * discovery can continue; explicit peer-object creation remains
         * separately gated and will not be sent to either RM. */
        p2pCapsParams->p2pLink = UVM_LINK_TYPE_NONE;
        status = NV_OK;
    } else {
        status = NV_ERR_INVALID_ARGUMENT;
        if (route_status == HYBRID580_UVM_DEVICE_PAIR_ROUTE_NOT_FOUND) {
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM P2P device ownership is unknown; frontend pinned\n");
        }
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetP2PCaps);

NV_STATUS nvUvmInterfaceP2pObjectCreate(uvmGpuDeviceHandle device1,
                                       uvmGpuDeviceHandle device2,
                                       NvHandle *hP2pObject)
{
    uint32_t public_handle = 0;
    int quarantine = 0;
    NV_STATUS status;

    if (hP2pObject == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *hP2pObject = 0;
    if (device1 == NULL || device2 == NULL || device1 == device2)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = (NV_STATUS)hybrid580_uvm_p2p_object_route_create(
        &hybrid580_uvm_devices, &hybrid580_uvm_p2p_objects,
        (uintptr_t)&hybrid580_uvm_sessions, (uintptr_t)device1,
        (uintptr_t)device2, hybrid580_open_p2p_object_ops(),
        hybrid580_legacy_p2p_object_ops(), NV_ERR_NO_MEMORY, NV_ERR_GENERIC,
        NV_ERR_NOT_SUPPORTED, &public_handle, &quarantine);
    if (status == NV_OK)
        *hP2pObject = (NvHandle)public_handle;
    if (quarantine) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM P2P-object identity is ambiguous; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceP2pObjectCreate);

void nvUvmInterfaceP2pObjectDestroy(uvmGpuSessionHandle session,
                                    NvHandle hP2pObject)
{
    enum hybrid580_uvm_p2p_object_status status;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_p2p_object_route_destroy(
        &hybrid580_uvm_p2p_objects, (uintptr_t)session,
        (uint32_t)hP2pObject, hybrid580_open_p2p_object_ops(),
        hybrid580_legacy_p2p_object_ops());
    if (status != HYBRID580_UVM_P2P_OBJECT_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM P2P-object owner inconsistency (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceP2pObjectDestroy);

NV_STATUS nvUvmInterfaceOwnPageFaultIntr(uvmGpuDeviceHandle device,
                                         NvBool bOwnInterrupts)
{
    NvBool requested = bOwnInterrupts;

    if (bOwnInterrupts != NV_TRUE && bOwnInterrupts != NV_FALSE)
        return NV_ERR_INVALID_ARGUMENT;
    return hybrid580_uvm_device_call(device, &requested,
                                     hybrid580_open_own_page_fault_intr,
                                     hybrid580_legacy_own_page_fault_intr);
}
EXPORT_SYMBOL(nvUvmInterfaceOwnPageFaultIntr);

NV_STATUS nvUvmInterfaceServiceDeviceInterruptsRM(uvmGpuDeviceHandle device)
{
    unsigned char params = 0;

    return hybrid580_uvm_device_call(
        device, &params, hybrid580_open_service_device_interrupts,
        hybrid580_legacy_service_device_interrupts);
}
EXPORT_SYMBOL(nvUvmInterfaceServiceDeviceInterruptsRM);

NV_STATUS nvUvmInterfaceReportNonReplayableFault(uvmGpuDeviceHandle device,
                                                 const void *pFaultPacket)
{
    struct hybrid580_uvm_non_replayable_fault_call call = {
        .fault_packet = pFaultPacket,
    };

    if (device == NULL || pFaultPacket == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    return hybrid580_uvm_device_call(
        device, &call, hybrid580_open_report_non_replayable_fault,
        hybrid580_legacy_report_non_replayable_fault);
}
EXPORT_SYMBOL(nvUvmInterfaceReportNonReplayableFault);

void nvUvmInterfaceReportFatalError(NV_STATUS error)
{
    /* This UVM notification is global, has no device identity, and is allowed
     * from bottom-half contexts. Send it to both RM domains without taking a
     * sleeping frontend lock so clients owned by either backend are notified. */
    hybrid580_open_nvUvmInterfaceReportFatalError(error);
    hybrid580_legacy_nvUvmInterfaceReportFatalError(error);
}
EXPORT_SYMBOL(nvUvmInterfaceReportFatalError);

/* The pinned R580 UVM contract marks all paging-channel interfaces as
 * SR-IOV-heavy-only. This physical-GPU frontend has no vGPU paging-channel
 * translation, so allocation fails closed and no native paging handle can be
 * exposed to the common UVM module. */
NV_STATUS nvUvmInterfacePagingChannelAllocate(
    uvmGpuDeviceHandle device,
    const UvmGpuPagingChannelAllocParams *allocParams,
    UvmGpuPagingChannelHandle *channel,
    UvmGpuPagingChannelInfo *channelInfo)
{
    if (channel != NULL)
        *channel = NULL;
    if (channelInfo != NULL)
        memset(channelInfo, 0, sizeof(*channelInfo));
    if (device == NULL || allocParams == NULL || channel == NULL ||
        channelInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    return NV_ERR_NOT_SUPPORTED;
}
EXPORT_SYMBOL(nvUvmInterfacePagingChannelAllocate);

void nvUvmInterfacePagingChannelDestroy(UvmGpuPagingChannelHandle channel)
{
    /* Allocate never returns a native or public paging-channel handle. */
    (void)channel;
}
EXPORT_SYMBOL(nvUvmInterfacePagingChannelDestroy);

NV_STATUS nvUvmInterfacePagingChannelsMap(uvmGpuAddressSpaceHandle srcVaSpace,
                                          UvmGpuPointer srcAddress,
                                          uvmGpuDeviceHandle device,
                                          NvU64 *dstAddress)
{
    if (dstAddress != NULL)
        *dstAddress = 0;
    if (srcVaSpace == NULL || device == NULL || dstAddress == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    (void)srcAddress;
    return NV_ERR_NOT_SUPPORTED;
}
EXPORT_SYMBOL(nvUvmInterfacePagingChannelsMap);

void nvUvmInterfacePagingChannelsUnmap(uvmGpuAddressSpaceHandle srcVaSpace,
                                       UvmGpuPointer srcAddress,
                                       uvmGpuDeviceHandle device)
{
    /* No mapping can have been created by the fail-closed Map implementation. */
    (void)srcVaSpace;
    (void)srcAddress;
    (void)device;
}
EXPORT_SYMBOL(nvUvmInterfacePagingChannelsUnmap);

NV_STATUS nvUvmInterfacePagingChannelPushStream(
    UvmGpuPagingChannelHandle channel, char *methodStream,
    NvU32 methodStreamSize)
{
    if (channel == NULL || methodStream == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    (void)methodStreamSize;
    return NV_ERR_NOT_SUPPORTED;
}
EXPORT_SYMBOL(nvUvmInterfacePagingChannelPushStream);

NV_STATUS nvUvmInterfaceAddressSpaceCreate(uvmGpuDeviceHandle device,
                                           unsigned long long vaBase,
                                           unsigned long long vaSize,
                                           NvBool enableAts,
                                           uvmGpuAddressSpaceHandle *vaSpace,
                                           UvmGpuAddressSpaceInfo *vaSpaceInfo)
{
    struct hybrid580_uvm_address_space_entry *entry;
    uintptr_t public_space = 0;
    int quarantine = 0;
    NV_STATUS status;

    if (vaSpace == NULL || vaSpaceInfo == NULL || device == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *vaSpace = NULL;
    memset(vaSpaceInfo, 0, sizeof(*vaSpaceInfo));
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = (NV_STATUS)hybrid580_uvm_address_space_route_create(
        &hybrid580_uvm_devices, &hybrid580_uvm_address_spaces, entry,
        (uintptr_t)device, vaBase, vaSize, enableAts != NV_FALSE,
        vaSpaceInfo, hybrid580_open_address_space_ops,
        hybrid580_legacy_address_space_ops, NV_ERR_NO_MEMORY,
        NV_ERR_INVALID_ARGUMENT, NV_ERR_GENERIC, &public_space, &quarantine);
    if (status == NV_OK)
        *vaSpace = (uvmGpuAddressSpaceHandle)public_space;
    else
        memset(vaSpaceInfo, 0, sizeof(*vaSpaceInfo));
    if (quarantine) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM address-space creation returned ambiguous native state; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (status != NV_OK)
        kfree(entry);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceAddressSpaceCreate);

NV_STATUS nvUvmInterfaceDupAddressSpaceWithControlFd(
    struct file *rmControlFile, uvmGpuDeviceHandle device, NvHandle hUserClient,
    NvHandle hUserVASpace, uvmGpuAddressSpaceHandle *vaSpace,
    UvmGpuAddressSpaceInfo *vaSpaceInfo)
{
    struct hybrid580_uvm_address_space_entry *entry;
    struct hybrid580_frontend_address_space_owner owner = {0};
    UvmGpuAddressSpaceInfo *staged_info;
    enum hybrid580_uvm_provider expected_provider = 0;
    enum hybrid580_uvm_provider registered_provider = 0;
    uintptr_t registered_device = 0;
    uintptr_t public_space = 0;
    int quarantine = 0;
    NV_STATUS status;

    if (vaSpace == NULL || vaSpaceInfo == NULL || device == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    if (rmControlFile == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *vaSpace = NULL;
    memset(vaSpaceInfo, 0, sizeof(*vaSpaceInfo));
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;
    staged_info = kzalloc(sizeof(*staged_info), GFP_KERNEL);
    if (staged_info == NULL) {
        kfree(entry);
        return NV_ERR_NO_MEMORY;
    }

    status = (NV_STATUS)hybrid580_frontend_uvm_address_space_owner_pin_v1(
        rmControlFile, (uint32_t)hUserClient, (uint32_t)hUserVASpace, &owner);
    if (status != NV_OK)
        goto out_free;
    if (owner.backend == HYBRID580_BACKEND_OPEN)
        expected_provider = HYBRID580_UVM_PROVIDER_OPEN;
    else if (owner.backend == HYBRID580_BACKEND_LEGACY)
        expected_provider = HYBRID580_UVM_PROVIDER_LEGACY;
    else {
        status = NV_ERR_INVALID_STATE;
        goto out_unpin;
    }

    mutex_lock(&hybrid580_uvm_callback_lock);
    if (hybrid580_uvm_device_registry_lookup(
            &hybrid580_uvm_devices, (uintptr_t)device,
            &registered_provider, &registered_device) !=
            HYBRID580_UVM_DEVICE_REGISTRY_OK ||
        registered_device == 0 || registered_provider != expected_provider) {
        status = NV_ERR_INVALID_OBJECT_HANDLE;
    } else {
        status = (NV_STATUS)hybrid580_uvm_address_space_route_duplicate(
            &hybrid580_uvm_devices, &hybrid580_uvm_address_spaces, entry,
            (uintptr_t)device, owner.backend_root, owner.backend_vaspace,
            staged_info, hybrid580_open_address_space_duplicate_ops,
            hybrid580_legacy_address_space_duplicate_ops, NV_ERR_NO_MEMORY,
            NV_ERR_GENERIC, &public_space, &quarantine);
    }
    if (status == NV_OK) {
        *vaSpace = (uvmGpuAddressSpaceHandle)public_space;
        *vaSpaceInfo = *staged_info;
    }
    if (quarantine) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM duplicated address-space identity is ambiguous; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (quarantine)
        hybrid580_frontend_uvm_address_space_owner_quarantine_v1(&owner);
    else
        hybrid580_frontend_uvm_address_space_owner_unpin_v1(&owner);
    if (status != NV_OK)
        kfree(entry);
    kfree(staged_info);
    return status;

out_unpin:
    hybrid580_frontend_uvm_address_space_owner_unpin_v1(&owner);
out_free:
    kfree(entry);
    kfree(staged_info);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceDupAddressSpaceWithControlFd);

/* The original ABI has no control-file identity. It cannot safely resolve a
 * public VASpace across frontend root/provider namespaces, so patched UVM
 * callers use the explicit-fd dispatcher and direct calls fail closed. */
NV_STATUS nvUvmInterfaceDupAddressSpace(uvmGpuDeviceHandle device,
                                        NvHandle hUserClient,
                                        NvHandle hUserVASpace,
                                        uvmGpuAddressSpaceHandle *vaSpace,
                                        UvmGpuAddressSpaceInfo *vaSpaceInfo)
{
    (void)device;
    (void)hUserClient;
    (void)hUserVASpace;
    if (vaSpace == NULL || vaSpaceInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *vaSpace = NULL;
    memset(vaSpaceInfo, 0, sizeof(*vaSpaceInfo));
    return NV_ERR_NOT_SUPPORTED;
}
EXPORT_SYMBOL(nvUvmInterfaceDupAddressSpace);

NV_STATUS nvUvmInterfaceDupAllocation(uvmGpuAddressSpaceHandle srcVaSpace,
                                     NvU64 srcAddress,
                                     uvmGpuAddressSpaceHandle dstVaSpace,
                                     NvU64 dstVaAlignment,
                                     NvU64 *dstAddress)
{
    int quarantine = 0;
    NV_STATUS status;

    if (dstAddress == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *dstAddress = 0;
    if (srcVaSpace == NULL || dstVaSpace == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = (NV_STATUS)hybrid580_uvm_address_space_route_dup_allocation(
        &hybrid580_uvm_address_spaces, (uintptr_t)srcVaSpace, srcAddress,
        (uintptr_t)dstVaSpace, dstVaAlignment,
        hybrid580_open_address_space_dup_allocation_ops,
        hybrid580_legacy_address_space_dup_allocation_ops,
        NV_ERR_INVALID_ARGUMENT, NV_ERR_NOT_SUPPORTED, NV_ERR_GENERIC,
        dstAddress, &quarantine);
    if (quarantine) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM duplicated allocation has ambiguous address-space ownership; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceDupAllocation);

void nvUvmInterfaceAddressSpaceDestroy(uvmGpuAddressSpaceHandle vaSpace)
{
    struct hybrid580_uvm_address_space_entry *removed = NULL;
    enum hybrid580_uvm_address_space_registry_status status;

    mutex_lock(&hybrid580_uvm_callback_lock);
    if (hybrid580_uvm_typed_child_registry_has_parent(
            &hybrid580_uvm_typed_children, (uintptr_t)vaSpace,
            HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE))
        status = HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_BUSY;
    else
        status = hybrid580_uvm_address_space_route_destroy(
            &hybrid580_uvm_address_spaces, (uintptr_t)vaSpace,
            hybrid580_open_address_space_ops,
            hybrid580_legacy_address_space_ops, &removed);
    if (status == HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        kfree(removed);
    } else {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM address-space destroy refused or ownership inconsistent (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceAddressSpaceDestroy);

NV_STATUS nvUvmInterfaceTsgAllocate(uvmGpuAddressSpaceHandle vaSpace,
                                    const UvmGpuTsgAllocParams *allocParams,
                                    uvmGpuTsgHandle *tsg)
{
    struct hybrid580_uvm_typed_child_entry *entry;
    struct hybrid580_uvm_tsg_allocate_params params = {
        .alloc_params = allocParams,
    };
    enum hybrid580_uvm_address_space_registry_status owner_status;
    enum hybrid580_uvm_typed_child_status child_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;
    bool entry_published = false;

    if (tsg == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *tsg = NULL;
    if (vaSpace == NULL || allocParams == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;

    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_address_space_route_call(
        &hybrid580_uvm_address_spaces, (uintptr_t)vaSpace, &params,
        hybrid580_open_tsg_allocate_ops, hybrid580_legacy_tsg_allocate_ops,
        &backend_status);
    if (owner_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM TSG allocation address-space ownership mismatch (%d); frontend pinned\n",
                 owner_status);
    } else if (backend_status != NV_OK) {
        status = (NV_STATUS)backend_status;
        if (params.native_tsg != 0) {
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM TSG allocation returned partial native state; frontend pinned\n");
        }
    } else if (params.native_tsg == 0) {
        status = NV_ERR_GENERIC;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM TSG allocation succeeded without a handle; frontend pinned\n");
    } else {
        child_status = hybrid580_uvm_typed_child_registry_insert(
            &hybrid580_uvm_typed_children, entry, params.native_tsg,
            (uintptr_t)vaSpace,
            HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
            HYBRID580_UVM_TYPED_CHILD_TSG,
            params.provider);
        if (child_status == HYBRID580_UVM_TYPED_CHILD_OK) {
            *tsg = (uvmGpuTsgHandle)params.native_tsg;
            status = NV_OK;
            entry_published = true;
        } else {
            status = NV_ERR_GENERIC;
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM TSG handle publication failed (%d); frontend pinned\n",
                     child_status);
        }
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (!entry_published)
        kfree(entry);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceTsgAllocate);

void nvUvmInterfaceTsgDestroy(uvmGpuTsgHandle tsg)
{
    struct hybrid580_uvm_typed_child_entry *removed = NULL;
    enum hybrid580_uvm_typed_child_status status;

    if (tsg == NULL)
        return;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_typed_child_route_destroy(
        &hybrid580_uvm_typed_children, (uintptr_t)tsg,
        HYBRID580_UVM_TYPED_CHILD_TSG, hybrid580_open_tsg_destroy_ops,
        hybrid580_legacy_tsg_destroy_ops, &removed);
    if (status == HYBRID580_UVM_TYPED_CHILD_OK) {
        kfree(removed);
    } else {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM TSG destroy refused or ownership inconsistent (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceTsgDestroy);

NV_STATUS nvUvmInterfaceChannelAllocate(const uvmGpuTsgHandle tsg,
                                        const UvmGpuChannelAllocParams *allocParams,
                                        uvmGpuChannelHandle *channel,
                                        UvmGpuChannelInfo *channelInfo)
{
    struct hybrid580_uvm_typed_child_entry *entry;
    struct hybrid580_uvm_channel_allocate_params params = {
        .alloc_params = allocParams,
    };
    enum hybrid580_uvm_typed_child_status owner_status;
    enum hybrid580_uvm_typed_child_status child_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;
    bool entry_published = false;

    if (channel == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *channel = NULL;
    if (channelInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(channelInfo, 0, sizeof(*channelInfo));
    if (tsg == NULL || allocParams == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;

    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_typed_child_route_call(
        &hybrid580_uvm_typed_children, (uintptr_t)tsg,
        HYBRID580_UVM_TYPED_CHILD_TSG, &params,
        hybrid580_open_channel_allocate_ops,
        hybrid580_legacy_channel_allocate_ops, &backend_status);
    if (owner_status != HYBRID580_UVM_TYPED_CHILD_OK) {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM channel allocation TSG ownership mismatch (%d); frontend pinned\n",
                 owner_status);
    } else if (backend_status != NV_OK) {
        status = (NV_STATUS)backend_status;
        if (params.native_channel != 0) {
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM channel allocation returned partial native state; frontend pinned\n");
        }
    } else if (params.native_channel == 0) {
        status = NV_ERR_GENERIC;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM channel allocation succeeded without a handle; frontend pinned\n");
    } else {
        child_status = hybrid580_uvm_typed_child_registry_insert(
            &hybrid580_uvm_typed_children, entry, params.native_channel,
            (uintptr_t)tsg, HYBRID580_UVM_TYPED_CHILD_PARENT_TSG,
            HYBRID580_UVM_TYPED_CHILD_CHANNEL,
            params.provider);
        if (child_status == HYBRID580_UVM_TYPED_CHILD_OK) {
            *channel = (uvmGpuChannelHandle)params.native_channel;
            *channelInfo = params.channel_info;
            status = NV_OK;
            entry_published = true;
        } else {
            status = NV_ERR_GENERIC;
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM channel handle publication failed (%d); frontend pinned\n",
                     child_status);
        }
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (!entry_published)
        kfree(entry);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceChannelAllocate);

void nvUvmInterfaceChannelDestroy(uvmGpuChannelHandle channel)
{
    struct hybrid580_uvm_typed_child_entry *removed = NULL;
    enum hybrid580_uvm_typed_child_status status;
    unsigned long flags;
    int csl_context_busy;

    if (channel == NULL)
        return;
    mutex_lock(&hybrid580_uvm_callback_lock);
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    csl_context_busy = hybrid580_uvm_info_registry_quarantine_channel_parent(
        &hybrid580_uvm_infos, (uintptr_t)channel);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (csl_context_busy) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM channel destroy refused while a CSL context is live; frontend pinned\n");
        mutex_unlock(&hybrid580_uvm_callback_lock);
        return;
    }
    status = hybrid580_uvm_typed_child_route_destroy(
        &hybrid580_uvm_typed_children, (uintptr_t)channel,
        HYBRID580_UVM_TYPED_CHILD_CHANNEL,
        hybrid580_open_channel_destroy_ops,
        hybrid580_legacy_channel_destroy_ops, &removed);
    if (status == HYBRID580_UVM_TYPED_CHILD_OK) {
        kfree(removed);
    } else {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM channel destroy ownership inconsistency (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceChannelDestroy);

NV_STATUS nvUvmInterfaceRetainChannel(uvmGpuAddressSpaceHandle vaSpace,
                                      NvHandle hClient, NvHandle hChannel,
                                      void **retainedChannel,
                                      UvmGpuChannelInstanceInfo *channelInstanceInfo)
{
    struct hybrid580_uvm_typed_child_entry *entry;
    struct hybrid580_uvm_retain_channel_params *params;
    enum hybrid580_uvm_address_space_registry_status owner_status;
    enum hybrid580_uvm_typed_child_status child_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;
    bool entry_published = false;

    if (retainedChannel == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *retainedChannel = NULL;
    if (channelInstanceInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(channelInstanceInfo, 0, sizeof(*channelInstanceInfo));
    if (vaSpace == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    params = kzalloc(sizeof(*params), GFP_KERNEL);
    if (params == NULL)
        return NV_ERR_NO_MEMORY;
    params->client = hClient;
    params->channel = hChannel;
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL) {
        kfree(params);
        return NV_ERR_NO_MEMORY;
    }

    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_address_space_route_call(
        &hybrid580_uvm_address_spaces, (uintptr_t)vaSpace, params,
        hybrid580_open_retain_channel_ops,
        hybrid580_legacy_retain_channel_ops, &backend_status);
    if (owner_status != HYBRID580_UVM_ADDRESS_SPACE_REGISTRY_OK) {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM retained-channel address-space ownership mismatch (%d); frontend pinned\n",
                 owner_status);
    } else if (backend_status != NV_OK) {
        status = (NV_STATUS)backend_status;
        if (params->native_retained_channel != 0) {
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM retain-channel returned partial native state; frontend pinned\n");
        }
    } else if (params->native_retained_channel == 0) {
        status = NV_ERR_GENERIC;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM retain-channel succeeded without a handle; frontend pinned\n");
    } else {
        child_status = hybrid580_uvm_typed_child_registry_insert(
            &hybrid580_uvm_typed_children, entry,
            params->native_retained_channel, (uintptr_t)vaSpace,
            HYBRID580_UVM_TYPED_CHILD_PARENT_ADDRESS_SPACE,
            HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL, params->provider);
        if (child_status == HYBRID580_UVM_TYPED_CHILD_OK) {
            *retainedChannel = (void *)params->native_retained_channel;
            *channelInstanceInfo = params->channel_info;
            status = NV_OK;
            /* An identical retained pointer increments the existing entry's
             * refcount; the reserved candidate node then remains caller-owned. */
            entry_published = entry->identity != 0;
        } else {
            status = NV_ERR_GENERIC;
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM retained-channel publication failed (%d); frontend pinned\n",
                     child_status);
        }
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (!entry_published)
        kfree(entry);
    kfree(params);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceRetainChannel);

NV_STATUS nvUvmInterfaceBindChannelResources(
    void *retainedChannel,
    UvmGpuChannelResourceBindParams *channelResourceBindParams)
{
    struct hybrid580_uvm_bind_channel_resources_params params = {
        .bind_params = channelResourceBindParams,
    };
    enum hybrid580_uvm_typed_child_status owner_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;

    if (retainedChannel == NULL || channelResourceBindParams == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_typed_child_route_call(
        &hybrid580_uvm_typed_children, (uintptr_t)retainedChannel,
        HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL, &params,
        hybrid580_open_bind_channel_resources_ops,
        hybrid580_legacy_bind_channel_resources_ops, &backend_status);
    if (owner_status == HYBRID580_UVM_TYPED_CHILD_OK) {
        status = (NV_STATUS)backend_status;
    } else {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM bind-channel ownership mismatch (%d); frontend pinned\n",
                 owner_status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceBindChannelResources);

void nvUvmInterfaceReleaseChannel(void *retainedChannel)
{
    struct hybrid580_uvm_typed_child_entry *removed = NULL;
    enum hybrid580_uvm_typed_child_status status;

    if (retainedChannel == NULL)
        return;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_typed_child_route_destroy(
        &hybrid580_uvm_typed_children, (uintptr_t)retainedChannel,
        HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL,
        hybrid580_open_release_channel_ops,
        hybrid580_legacy_release_channel_ops, &removed);
    if (status == HYBRID580_UVM_TYPED_CHILD_OK) {
        kfree(removed);
    } else {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM release-channel ownership inconsistency (%d); frontend pinned\n",
                 status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceReleaseChannel);

void nvUvmInterfaceStopChannel(void *retainedChannel, NvBool bImmediate)
{
    struct hybrid580_uvm_stop_channel_params params = {
        .immediate = bImmediate,
    };
    enum hybrid580_uvm_typed_child_status owner_status;
    uint32_t backend_status = NV_ERR_GENERIC;

    if (retainedChannel == NULL ||
        (bImmediate != NV_TRUE && bImmediate != NV_FALSE))
        return;
    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_typed_child_route_call(
        &hybrid580_uvm_typed_children, (uintptr_t)retainedChannel,
        HYBRID580_UVM_TYPED_CHILD_RETAINED_CHANNEL, &params,
        hybrid580_open_stop_channel_ops,
        hybrid580_legacy_stop_channel_ops, &backend_status);
    if (owner_status != HYBRID580_UVM_TYPED_CHILD_OK ||
        backend_status != NV_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM stop-channel ownership inconsistency (%d, 0x%x); frontend pinned\n",
                 owner_status, backend_status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
}
EXPORT_SYMBOL(nvUvmInterfaceStopChannel);

NV_STATUS nvUvmInterfaceGetChannelResourcePtes(
    uvmGpuAddressSpaceHandle vaSpace, NvP64 resourceDescriptor,
    NvU64 offset, NvU64 size,
    UvmGpuExternalMappingInfo *externalMappingInfo)
{
    struct hybrid580_uvm_channel_resource_ptes_params params = {
        .resource_descriptor = resourceDescriptor,
        .offset = offset,
        .size = size,
    };
    NV_STATUS status;

    if (externalMappingInfo == NULL || vaSpace == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    params.backend_info = *externalMappingInfo;
    status = hybrid580_uvm_address_space_call(
        vaSpace, &params, hybrid580_open_get_channel_resource_ptes_ops,
        hybrid580_legacy_get_channel_resource_ptes_ops);
    *externalMappingInfo = params.backend_info;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetChannelResourcePtes);

NV_STATUS nvUvmInterfaceSetPageDirectory(uvmGpuAddressSpaceHandle vaSpace,
                                         NvU64 physAddress, unsigned numEntries,
                                         NvBool bVidMemAperture, NvU32 pasid,
                                         NvU64 *dmaAddress)
{
    struct hybrid580_uvm_set_page_directory_params params = {
        .physAddress = physAddress,
        .numEntries = numEntries,
        .bVidMemAperture = bVidMemAperture,
        .pasid = pasid,
        .dmaAddress = dmaAddress,
    };
    NV_STATUS status;

    if (dmaAddress == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    memset(dmaAddress, 0, sizeof(*dmaAddress));
    status = hybrid580_uvm_address_space_call(
        vaSpace, &params, hybrid580_open_set_page_directory_ops,
        hybrid580_legacy_set_page_directory_ops);
    if (status != NV_OK)
        memset(dmaAddress, 0, sizeof(*dmaAddress));
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceSetPageDirectory);

NV_STATUS nvUvmInterfaceUnsetPageDirectory(uvmGpuAddressSpaceHandle vaSpace)
{
    unsigned char params = 0;
    return hybrid580_uvm_address_space_call(
        vaSpace, &params, hybrid580_open_unset_page_directory_ops,
        hybrid580_legacy_unset_page_directory_ops);
}
EXPORT_SYMBOL(nvUvmInterfaceUnsetPageDirectory);

static NV_STATUS hybrid580_uvm_memory_alloc(
    uvmGpuAddressSpaceHandle vaSpace, NvLength length,
    UvmGpuPointer *gpuPointer, UvmGpuAllocInfo *allocInfo,
    struct hybrid580_uvm_address_space_call_backend_ops open_ops,
    struct hybrid580_uvm_address_space_call_backend_ops legacy_ops)
{
    struct hybrid580_uvm_memory_alloc_params params;
    NV_STATUS status;

    if (gpuPointer == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *gpuPointer = 0;
    if (allocInfo == NULL || vaSpace == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    memset(&params, 0, sizeof(params));
    params.length = length;
    params.gpu_pointer = gpuPointer;
    params.alloc_info = allocInfo;
    params.backend_alloc_info = *allocInfo;
    status = hybrid580_uvm_address_space_call(vaSpace, &params,
                                               open_ops, legacy_ops);
    if (status != NV_OK && params.ambiguous_output) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM memory allocation returned partial native output; frontend pinned\n");
    }
    return status;
}

NV_STATUS nvUvmInterfaceMemoryAllocFB(uvmGpuAddressSpaceHandle vaSpace,
                                      NvLength length,
                                      UvmGpuPointer *gpuPointer,
                                      UvmGpuAllocInfo *allocInfo)
{
    return hybrid580_uvm_memory_alloc(
        vaSpace, length, gpuPointer, allocInfo,
        hybrid580_open_memory_alloc_fb_ops,
        hybrid580_legacy_memory_alloc_fb_ops);
}
EXPORT_SYMBOL(nvUvmInterfaceMemoryAllocFB);

NV_STATUS nvUvmInterfaceMemoryAllocSys(uvmGpuAddressSpaceHandle vaSpace,
                                       NvLength length,
                                       UvmGpuPointer *gpuPointer,
                                       UvmGpuAllocInfo *allocInfo)
{
    return hybrid580_uvm_memory_alloc(
        vaSpace, length, gpuPointer, allocInfo,
        hybrid580_open_memory_alloc_sys_ops,
        hybrid580_legacy_memory_alloc_sys_ops);
}
EXPORT_SYMBOL(nvUvmInterfaceMemoryAllocSys);

void nvUvmInterfaceMemoryFree(uvmGpuAddressSpaceHandle vaSpace,
                              UvmGpuPointer gpuPointer)
{
    struct hybrid580_uvm_memory_free_params params = {
        .gpu_pointer = gpuPointer,
    };

    if (vaSpace == NULL || gpuPointer == 0)
        return;
    (void)hybrid580_uvm_address_space_call(
        vaSpace, &params, hybrid580_open_memory_free_ops,
        hybrid580_legacy_memory_free_ops);
}
EXPORT_SYMBOL(nvUvmInterfaceMemoryFree);

NV_STATUS nvUvmInterfaceMemoryCpuMap(uvmGpuAddressSpaceHandle vaSpace,
                                     UvmGpuPointer gpuPointer,
                                     NvLength length, void **cpuPtr,
                                     NvU64 pageSize)
{
    struct hybrid580_uvm_memory_cpu_map_params params = {
        .gpu_pointer = gpuPointer,
        .length = length,
        .cpu_pointer = cpuPtr,
        .page_size = pageSize,
    };
    NV_STATUS status;

    if (cpuPtr == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *cpuPtr = NULL;
    if (vaSpace == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    status = hybrid580_uvm_address_space_call(
        vaSpace, &params, hybrid580_open_memory_cpu_map_ops,
        hybrid580_legacy_memory_cpu_map_ops);
    if (status != NV_OK) {
        *cpuPtr = NULL;
        if (params.ambiguous_output) {
            hybrid580_uvm_pin_quarantined_state();
            pr_emerg("hybrid580 UVM CPU mapping returned partial native output; frontend pinned\n");
        }
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceMemoryCpuMap);

void nvUvmInterfaceMemoryCpuUnMap(uvmGpuAddressSpaceHandle vaSpace,
                                  void *cpuPtr)
{
    struct hybrid580_uvm_memory_cpu_unmap_params params = {
        .cpu_pointer = cpuPtr,
    };

    if (vaSpace == NULL || cpuPtr == NULL)
        return;
    (void)hybrid580_uvm_address_space_call(
        vaSpace, &params, hybrid580_open_memory_cpu_unmap_ops,
        hybrid580_legacy_memory_cpu_unmap_ops);
}
EXPORT_SYMBOL(nvUvmInterfaceMemoryCpuUnMap);

NV_STATUS nvUvmInterfaceDupMemoryWithControlFd(
    int rmControlFd, uvmGpuDeviceHandle device, NvHandle hClient,
    NvHandle hPhysMemory, NvHandle *hDupMemory,
    UvmGpuMemoryInfo *pGpuMemoryInfo)
{
    struct hybrid580_uvm_typed_child_entry *entry;
    struct hybrid580_frontend_memory_owner owner = {0};
    enum hybrid580_uvm_provider source_provider;
    UvmGpuMemoryInfo *staged_info = NULL;
    uintptr_t public_handle = 0;
    int quarantine = 0;
    NV_STATUS status;

    if (hDupMemory == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *hDupMemory = 0;
    if (pGpuMemoryInfo != NULL)
        memset(pGpuMemoryInfo, 0, sizeof(*pGpuMemoryInfo));
    if (device == NULL || hClient == 0 || hPhysMemory == 0)
        return NV_ERR_INVALID_ARGUMENT;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;
    if (pGpuMemoryInfo != NULL) {
        staged_info = kzalloc(sizeof(*staged_info), GFP_KERNEL);
        if (staged_info == NULL) {
            kfree(entry);
            return NV_ERR_NO_MEMORY;
        }
    }

    status = (NV_STATUS)hybrid580_frontend_uvm_memory_owner_pin_v1(
        rmControlFd, (uint32_t)hClient, (uint32_t)hPhysMemory, &owner);
    if (status != NV_OK) {
        kfree(entry);
        kfree(staged_info);
        return status;
    }
    if (owner.backend == HYBRID580_BACKEND_OPEN)
        source_provider = HYBRID580_UVM_PROVIDER_OPEN;
    else if (owner.backend == HYBRID580_BACKEND_LEGACY)
        source_provider = HYBRID580_UVM_PROVIDER_LEGACY;
    else {
        hybrid580_frontend_uvm_memory_owner_unpin_v1(&owner);
        kfree(entry);
        kfree(staged_info);
        return NV_ERR_INVALID_STATE;
    }

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = (NV_STATUS)hybrid580_uvm_dup_memory_route_duplicate(
        &hybrid580_uvm_devices, &hybrid580_uvm_typed_children, entry,
        (uintptr_t)device, source_provider, owner.backend_root,
        owner.backend_memory,
        staged_info, hybrid580_open_dup_memory_ops,
        hybrid580_legacy_dup_memory_ops, NV_ERR_NO_MEMORY, NV_ERR_GENERIC,
        NV_ERR_NOT_SUPPORTED,
        &public_handle, &quarantine);
    if (status == NV_OK) {
        *hDupMemory = (NvHandle)public_handle;
        if (pGpuMemoryInfo != NULL)
            *pGpuMemoryInfo = *staged_info;
    }
    if (quarantine) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM duplicated-memory handle is ambiguous; frontend pinned\n");
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (quarantine)
        hybrid580_frontend_uvm_memory_owner_quarantine_v1(&owner);
    else
        hybrid580_frontend_uvm_memory_owner_unpin_v1(&owner);
    if (status != NV_OK)
        kfree(entry);
    kfree(staged_info);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceDupMemoryWithControlFd);

/* The original ABI has no control-file identity. It cannot safely resolve a
 * public handle across provider namespaces, so patched UVM callers use the
 * explicit-fd variant above and legacy direct calls fail closed. */
NV_STATUS nvUvmInterfaceDupMemory(uvmGpuDeviceHandle device,
                                  NvHandle hClient,
                                  NvHandle hPhysMemory,
                                  NvHandle *hDupMemory,
                                  UvmGpuMemoryInfo *pGpuMemoryInfo)
{
    (void)device;
    (void)hClient;
    (void)hPhysMemory;
    if (hDupMemory == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *hDupMemory = 0;
    if (pGpuMemoryInfo != NULL)
        memset(pGpuMemoryInfo, 0, sizeof(*pGpuMemoryInfo));
    return NV_ERR_NOT_SUPPORTED;
}
EXPORT_SYMBOL(nvUvmInterfaceDupMemory);

NV_STATUS nvUvmInterfaceFreeDupedHandle(uvmGpuDeviceHandle device,
                                        NvHandle hPhysHandle)
{
    struct hybrid580_uvm_typed_child_entry *removed = NULL;
    enum hybrid580_uvm_typed_child_status owner_status;
    uint32_t backend_status = NV_ERR_GENERIC;
    NV_STATUS status;

    if (device == NULL || hPhysHandle == 0)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    owner_status = hybrid580_uvm_dup_memory_route_release(
        &hybrid580_uvm_devices, &hybrid580_uvm_typed_children,
        (uintptr_t)device, (uintptr_t)hPhysHandle,
        hybrid580_open_dup_memory_ops, hybrid580_legacy_dup_memory_ops,
        &backend_status, &removed);
    if (owner_status == HYBRID580_UVM_TYPED_CHILD_OK) {
        status = (NV_STATUS)backend_status;
        if (status == NV_OK) {
            if (removed != NULL) {
                kfree(removed);
            } else {
                status = NV_ERR_GENERIC;
                hybrid580_uvm_pin_quarantined_state();
                pr_emerg("hybrid580 UVM freed memory handle was not retired; frontend pinned\n");
            }
        }
    } else {
        status = NV_ERR_INVALID_ARGUMENT;
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM free-duplicated-handle ownership mismatch (%d); frontend pinned\n",
                 owner_status);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceFreeDupedHandle);

static NV_STATUS hybrid580_uvm_external_mapping_status_to_nv(
    enum hybrid580_uvm_external_mapping_status status)
{
    switch (status) {
    case HYBRID580_UVM_EXTERNAL_MAPPING_OK:
        return NV_OK;
    case HYBRID580_UVM_EXTERNAL_MAPPING_INVALID:
        return NV_ERR_INVALID_ARGUMENT;
    case HYBRID580_UVM_EXTERNAL_MAPPING_SPACE_UNKNOWN:
    case HYBRID580_UVM_EXTERNAL_MAPPING_MEMORY_UNKNOWN:
    case HYBRID580_UVM_EXTERNAL_MAPPING_HANDLE_RANGE:
        return NV_ERR_INVALID_OBJECT_HANDLE;
    case HYBRID580_UVM_EXTERNAL_MAPPING_PROVIDER_MISMATCH:
        return NV_ERR_NOT_SUPPORTED;
    default:
        return NV_ERR_GENERIC;
    }
}

NV_STATUS nvUvmInterfaceGetExternalAllocPtes(
    uvmGpuAddressSpaceHandle vaSpace, NvHandle hDupedMemory, NvU64 offset,
    NvU64 size, UvmGpuExternalMappingInfo *gpuExternalMappingInfo)
{
    struct hybrid580_uvm_external_mapping_route route = {0};
    enum hybrid580_uvm_external_mapping_status route_status;
    NV_STATUS status;

    if (vaSpace == NULL || hDupedMemory == 0 ||
        gpuExternalMappingInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    route_status = hybrid580_uvm_external_mapping_resolve(
        &hybrid580_uvm_address_spaces, &hybrid580_uvm_typed_children,
        (uintptr_t)vaSpace, (uintptr_t)hDupedMemory, &route);
    if (route_status != HYBRID580_UVM_EXTERNAL_MAPPING_OK) {
        status = hybrid580_uvm_external_mapping_status_to_nv(route_status);
    } else if (route.provider == HYBRID580_UVM_PROVIDER_OPEN) {
        status = hybrid580_open_nvUvmInterfaceGetExternalAllocPtes(
            (uvmGpuAddressSpaceHandle)route.native_va_space,
            (NvHandle)route.native_memory, offset, size,
            gpuExternalMappingInfo);
    } else if (route.provider == HYBRID580_UVM_PROVIDER_LEGACY) {
        status = hybrid580_legacy_nvUvmInterfaceGetExternalAllocPtes(
            (uvmGpuAddressSpaceHandle)route.native_va_space,
            (NvHandle)route.native_memory, offset, size,
            gpuExternalMappingInfo);
    } else {
        status = NV_ERR_INVALID_STATE;
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetExternalAllocPtes);

NV_STATUS nvUvmInterfaceGetExternalAllocPhysAddrs(
    uvmGpuAddressSpaceHandle vaSpace, NvHandle hDupedMemory, NvU64 offset,
    NvU64 size, UvmGpuExternalPhysAddrInfo *gpuExternalPhysAddrInfo)
{
    struct hybrid580_uvm_external_mapping_route route = {0};
    enum hybrid580_uvm_external_mapping_status route_status;
    NV_STATUS status;

    if (vaSpace == NULL || hDupedMemory == 0 ||
        gpuExternalPhysAddrInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    mutex_lock(&hybrid580_uvm_callback_lock);
    route_status = hybrid580_uvm_external_mapping_resolve(
        &hybrid580_uvm_address_spaces, &hybrid580_uvm_typed_children,
        (uintptr_t)vaSpace, (uintptr_t)hDupedMemory, &route);
    if (route_status != HYBRID580_UVM_EXTERNAL_MAPPING_OK) {
        status = hybrid580_uvm_external_mapping_status_to_nv(route_status);
    } else if (route.provider == HYBRID580_UVM_PROVIDER_OPEN) {
        status = hybrid580_open_nvUvmInterfaceGetExternalAllocPhysAddrs(
            (uvmGpuAddressSpaceHandle)route.native_va_space,
            (NvHandle)route.native_memory, offset, size,
            gpuExternalPhysAddrInfo);
    } else if (route.provider == HYBRID580_UVM_PROVIDER_LEGACY) {
        status = hybrid580_legacy_nvUvmInterfaceGetExternalAllocPhysAddrs(
            (uvmGpuAddressSpaceHandle)route.native_va_space,
            (NvHandle)route.native_memory, offset, size,
            gpuExternalPhysAddrInfo);
    } else {
        status = NV_ERR_INVALID_STATE;
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetExternalAllocPhysAddrs);

NV_STATUS nvUvmInterfaceInitFaultInfo(uvmGpuDeviceHandle device,
                                      UvmGpuFaultInfo *pFaultInfo)
{
    const struct hybrid580_uvm_fault_info_backend_ops *ops;
    struct hybrid580_uvm_info_entry *fault_entry;
    struct hybrid580_uvm_info_entry *csl_entry;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    uintptr_t csl_identity;
    NV_STATUS status;
    int registered = 0;

    if (device == NULL || pFaultInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    fault_entry = kzalloc(sizeof(*fault_entry), GFP_KERNEL);
    csl_entry = kzalloc(sizeof(*csl_entry), GFP_KERNEL);
    if (fault_entry == NULL || csl_entry == NULL) {
        kfree(fault_entry);
        kfree(csl_entry);
        return NV_ERR_NO_MEMORY;
    }
    csl_identity = (uintptr_t)&pFaultInfo->replayable.cslCtx;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_info_device_owner_locked(
        device, &provider, &native_device);
    ops = status == NV_OK ? hybrid580_uvm_fault_info_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL)
        status = NV_ERR_INVALID_STATE;
    if (status == NV_OK)
        status = hybrid580_uvm_info_reserve_fault_pair_locked(
            fault_entry, csl_entry, (uintptr_t)pFaultInfo, csl_identity,
            (uintptr_t)device, provider, &registered);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (status != NV_OK) {
        if (!registered) {
            kfree(fault_entry);
            kfree(csl_entry);
        }
        return status;
    }

    status = ops->init((uvmGpuDeviceHandle)native_device, pFaultInfo);
    return hybrid580_uvm_info_finish_fault_pair_init(
        fault_entry, csl_entry, status);
}
EXPORT_SYMBOL(nvUvmInterfaceInitFaultInfo);

NV_STATUS nvUvmInterfaceDestroyFaultInfo(uvmGpuDeviceHandle device,
                                         UvmGpuFaultInfo *pFaultInfo)
{
    const struct hybrid580_uvm_fault_info_backend_ops *ops;
    struct hybrid580_uvm_info_entry *fault_entry = NULL;
    struct hybrid580_uvm_info_entry *csl_entry = NULL;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    NV_STATUS status;

    if (device == NULL || pFaultInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_info_device_owner_locked(
        device, &provider, &native_device);
    ops = status == NV_OK ? hybrid580_uvm_fault_info_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL)
        status = NV_ERR_INVALID_STATE;
    if (status == NV_OK)
        status = hybrid580_uvm_info_begin_fault_retire_locked(
            (uintptr_t)pFaultInfo,
            (uintptr_t)&pFaultInfo->replayable.cslCtx,
            (uintptr_t)device, provider, &fault_entry, &csl_entry);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (status != NV_OK)
        return status;

    status = ops->destroy((uvmGpuDeviceHandle)native_device, pFaultInfo);
    return hybrid580_uvm_info_finish_fault_pair_destroy(
        fault_entry, csl_entry, status);
}
EXPORT_SYMBOL(nvUvmInterfaceDestroyFaultInfo);

NV_STATUS nvUvmInterfaceHasPendingNonReplayableFaults(
    UvmGpuFaultInfo *pFaultInfo, NvBool *hasPendingFaults)
{
    const struct hybrid580_uvm_fault_info_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;
    NV_STATUS status;

    if (pFaultInfo == NULL || hasPendingFaults == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *hasPendingFaults = NV_FALSE;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_pin(
        &hybrid580_uvm_infos, (uintptr_t)pFaultInfo,
        HYBRID580_UVM_INFO_FAULT, 0, &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK)
        return hybrid580_uvm_info_status_to_nv(info_status);

    ops = hybrid580_uvm_fault_info_backend(pin.provider);
    status = ops != NULL ? ops->has_pending(pFaultInfo, hasPendingFaults) :
                           NV_ERR_INVALID_STATE;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos,
                                                     &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault-info call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceHasPendingNonReplayableFaults);

NV_STATUS nvUvmInterfaceGetNonReplayableFaults(UvmGpuFaultInfo *pFaultInfo,
                                               void *pFaultBuffer,
                                               NvU32 *numFaults)
{
    const struct hybrid580_uvm_fault_info_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;
    NV_STATUS status;

    if (pFaultInfo == NULL || pFaultBuffer == NULL || numFaults == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *numFaults = 0;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_pin(
        &hybrid580_uvm_infos, (uintptr_t)pFaultInfo,
        HYBRID580_UVM_INFO_FAULT, 0, &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK)
        return hybrid580_uvm_info_status_to_nv(info_status);

    ops = hybrid580_uvm_fault_info_backend(pin.provider);
    status = ops != NULL ? ops->get_faults(pFaultInfo, pFaultBuffer, numFaults) :
                           NV_ERR_INVALID_STATE;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos,
                                                     &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault-info call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceGetNonReplayableFaults);

NV_STATUS nvUvmInterfaceFlushReplayableFaultBuffer(
    UvmGpuFaultInfo *pFaultInfo, NvBool bCopyAndFlush)
{
    const struct hybrid580_uvm_fault_info_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;
    NV_STATUS status;

    if (pFaultInfo == NULL ||
        (bCopyAndFlush != NV_FALSE && bCopyAndFlush != NV_TRUE))
        return NV_ERR_INVALID_ARGUMENT;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_pin(
        &hybrid580_uvm_infos, (uintptr_t)pFaultInfo,
        HYBRID580_UVM_INFO_FAULT, 0, &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK)
        return hybrid580_uvm_info_status_to_nv(info_status);

    ops = hybrid580_uvm_fault_info_backend(pin.provider);
    status = ops != NULL ? ops->flush(pFaultInfo, bCopyAndFlush) :
                           NV_ERR_INVALID_STATE;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos,
                                                     &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault-info call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceFlushReplayableFaultBuffer);

NV_STATUS nvUvmInterfaceTogglePrefetchFaults(UvmGpuFaultInfo *pFaultInfo,
                                             NvBool bEnable)
{
    const struct hybrid580_uvm_fault_info_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;
    NV_STATUS status;

    if (pFaultInfo == NULL || (bEnable != NV_FALSE && bEnable != NV_TRUE))
        return NV_ERR_INVALID_ARGUMENT;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_pin(
        &hybrid580_uvm_infos, (uintptr_t)pFaultInfo,
        HYBRID580_UVM_INFO_FAULT, 0, &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK)
        return hybrid580_uvm_info_status_to_nv(info_status);

    ops = hybrid580_uvm_fault_info_backend(pin.provider);
    status = ops != NULL ? ops->toggle_prefetch(pFaultInfo, bEnable) :
                           NV_ERR_INVALID_STATE;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos,
                                                     &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM fault-info call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceTogglePrefetchFaults);

NV_STATUS nvUvmInterfaceInitAccessCntrInfo(
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *pAccessCntrInfo,
    NvU32 accessCntrIndex)
{
    const struct hybrid580_uvm_access_cntr_backend_ops *ops;
    struct hybrid580_uvm_info_entry *entry;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    NV_STATUS status;
    int registered = 0;

    if (device == NULL || pAccessCntrInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_info_device_owner_locked(
        device, &provider, &native_device);
    ops = status == NV_OK ? hybrid580_uvm_access_cntr_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL)
        status = NV_ERR_INVALID_STATE;
    if (status == NV_OK)
        status = hybrid580_uvm_info_reserve_locked(
            entry, (uintptr_t)pAccessCntrInfo, (uintptr_t)device, provider,
            HYBRID580_UVM_INFO_ACCESS_COUNTER, &registered);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (status != NV_OK) {
        if (!registered)
            kfree(entry);
        return status;
    }

    status = ops->init((uvmGpuDeviceHandle)native_device, pAccessCntrInfo,
                       accessCntrIndex);
    return hybrid580_uvm_info_finish_init(entry, status);
}
EXPORT_SYMBOL(nvUvmInterfaceInitAccessCntrInfo);

NV_STATUS nvUvmInterfaceDestroyAccessCntrInfo(
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *pAccessCntrInfo)
{
    const struct hybrid580_uvm_access_cntr_backend_ops *ops;
    struct hybrid580_uvm_info_entry *entry = NULL;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    NV_STATUS status;

    if (device == NULL || pAccessCntrInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_info_device_owner_locked(
        device, &provider, &native_device);
    ops = status == NV_OK ? hybrid580_uvm_access_cntr_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL)
        status = NV_ERR_INVALID_STATE;
    if (status == NV_OK)
        status = hybrid580_uvm_info_begin_retire_locked(
            (uintptr_t)pAccessCntrInfo, (uintptr_t)device,
            HYBRID580_UVM_INFO_ACCESS_COUNTER, provider, &entry);
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (status != NV_OK)
        return status;

    status = ops->destroy((uvmGpuDeviceHandle)native_device, pAccessCntrInfo);
    return hybrid580_uvm_info_finish_retire(entry, status);
}
EXPORT_SYMBOL(nvUvmInterfaceDestroyAccessCntrInfo);

NV_STATUS nvUvmInterfaceEnableAccessCntr(
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *pAccessCntrInfo,
    const UvmGpuAccessCntrConfig *pAccessCntrConfig)
{
    const struct hybrid580_uvm_access_cntr_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    enum hybrid580_uvm_info_status info_status;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    unsigned long flags;
    NV_STATUS status;
    int pin_inconsistent = 0;

    if (device == NULL || pAccessCntrInfo == NULL ||
        pAccessCntrConfig == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_info_device_owner_locked(
        device, &provider, &native_device);
    if (status == NV_OK) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_pin(
            &hybrid580_uvm_infos, (uintptr_t)pAccessCntrInfo,
            HYBRID580_UVM_INFO_ACCESS_COUNTER, (uintptr_t)device, &pin);
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
        status = hybrid580_uvm_info_status_to_nv(info_status);
    }
    if (status == NV_OK && pin.provider != provider) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_unpin(
            &hybrid580_uvm_infos, &pin);
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
        pin_inconsistent = info_status != HYBRID580_UVM_INFO_OK;
        status = info_status == HYBRID580_UVM_INFO_OK ?
                 NV_ERR_INVALID_OBJECT_HANDLE : NV_ERR_INVALID_STATE;
    }
    ops = status == NV_OK ? hybrid580_uvm_access_cntr_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_unpin(
            &hybrid580_uvm_infos, &pin);
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
        pin_inconsistent = info_status != HYBRID580_UVM_INFO_OK;
        status = NV_ERR_INVALID_STATE;
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (pin_inconsistent) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM access-counter pin cleanup failed; frontend pinned\n");
    }
    if (status != NV_OK)
        return status;

    status = ops->enable((uvmGpuDeviceHandle)native_device, pAccessCntrInfo,
                         pAccessCntrConfig);
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos,
                                                     &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM access-counter call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceEnableAccessCntr);

NV_STATUS nvUvmInterfaceDisableAccessCntr(
    uvmGpuDeviceHandle device, UvmGpuAccessCntrInfo *pAccessCntrInfo)
{
    const struct hybrid580_uvm_access_cntr_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    enum hybrid580_uvm_info_status info_status;
    enum hybrid580_uvm_provider provider;
    uintptr_t native_device;
    unsigned long flags;
    NV_STATUS status;
    int pin_inconsistent = 0;

    if (device == NULL || pAccessCntrInfo == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_info_device_owner_locked(
        device, &provider, &native_device);
    if (status == NV_OK) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_pin(
            &hybrid580_uvm_infos, (uintptr_t)pAccessCntrInfo,
            HYBRID580_UVM_INFO_ACCESS_COUNTER, (uintptr_t)device, &pin);
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
        status = hybrid580_uvm_info_status_to_nv(info_status);
    }
    if (status == NV_OK && pin.provider != provider) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_unpin(
            &hybrid580_uvm_infos, &pin);
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
        pin_inconsistent = info_status != HYBRID580_UVM_INFO_OK;
        status = info_status == HYBRID580_UVM_INFO_OK ?
                 NV_ERR_INVALID_OBJECT_HANDLE : NV_ERR_INVALID_STATE;
    }
    ops = status == NV_OK ? hybrid580_uvm_access_cntr_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_unpin(
            &hybrid580_uvm_infos, &pin);
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
        pin_inconsistent = info_status != HYBRID580_UVM_INFO_OK;
        status = NV_ERR_INVALID_STATE;
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (pin_inconsistent) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM access-counter pin cleanup failed; frontend pinned\n");
    }
    if (status != NV_OK)
        return status;

    status = ops->disable((uvmGpuDeviceHandle)native_device, pAccessCntrInfo);
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin(&hybrid580_uvm_infos,
                                                     &pin);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM access-counter call pin was inconsistent; frontend pinned\n");
        return NV_ERR_INVALID_STATE;
    }
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceDisableAccessCntr);

NV_STATUS nvUvmInterfaceCslInitContext(UvmCslContext *uvmCslContext,
                                       uvmGpuChannelHandle channel)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_entry *entry;
    enum hybrid580_uvm_provider provider;
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;
    uintptr_t native_channel;
    uintptr_t device_identity;
    NV_STATUS status;
    int registered = 0;
    int parent_quarantined = 0;

    if (uvmCslContext == NULL || channel == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL)
        return NV_ERR_NO_MEMORY;

    mutex_lock(&hybrid580_uvm_callback_lock);
    status = hybrid580_uvm_channel_owner_locked(
        channel, &provider, &native_channel, &device_identity);
    ops = status == NV_OK ? hybrid580_uvm_csl_backend(provider) : NULL;
    if (status == NV_OK && ops == NULL)
        status = NV_ERR_INVALID_STATE;
    if (status == NV_OK)
        status = hybrid580_uvm_info_reserve_locked(
            entry, (uintptr_t)uvmCslContext, device_identity, provider,
            HYBRID580_UVM_INFO_CSL, &registered);
    if (status == NV_OK) {
        spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
        info_status = hybrid580_uvm_info_registry_set_channel_parent(
            &hybrid580_uvm_infos, (uintptr_t)uvmCslContext,
            device_identity, (uintptr_t)channel);
        if (info_status != HYBRID580_UVM_INFO_OK) {
            (void)hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, (uintptr_t)uvmCslContext);
            parent_quarantined = 1;
            status = NV_ERR_INVALID_STATE;
        }
        spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    }
    mutex_unlock(&hybrid580_uvm_callback_lock);
    if (parent_quarantined) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM CSL channel-parent registration failed; frontend pinned\n");
    }
    if (status != NV_OK) {
        if (!registered)
            kfree(entry);
        return status;
    }

    status = ops->init_context(uvmCslContext,
                               (uvmGpuChannelHandle)native_channel);
    return hybrid580_uvm_info_finish_init(entry, status);
}
EXPORT_SYMBOL(nvUvmInterfaceCslInitContext);

void nvUvmInterfaceDeinitCslContext(UvmCslContext *uvmCslContext)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_entry *entry = NULL;
    struct hybrid580_uvm_info_entry **link;
    enum hybrid580_uvm_info_status info_status;
    enum hybrid580_uvm_provider provider = 0;
    unsigned long flags;

    if (uvmCslContext == NULL)
        return;

    mutex_lock(&hybrid580_uvm_callback_lock);
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_begin_retire(
        &hybrid580_uvm_infos, (uintptr_t)uvmCslContext,
        HYBRID580_UVM_INFO_CSL, 0, &entry);
    if (info_status == HYBRID580_UVM_INFO_OK)
        provider = entry->provider;
    else if (info_status != HYBRID580_UVM_INFO_NOT_FOUND) {
        link = hybrid580_uvm_info_find_link(
            &hybrid580_uvm_infos, (uintptr_t)uvmCslContext);
        if (link != NULL && *link != NULL &&
            (*link)->kind == HYBRID580_UVM_INFO_CSL)
            (void)hybrid580_uvm_info_registry_quarantine(
                &hybrid580_uvm_infos, (uintptr_t)uvmCslContext);
    }
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    mutex_unlock(&hybrid580_uvm_callback_lock);

    /* The R580 API explicitly treats an already-deinitialized context as a
     * no-op. An unknown identity is the equivalent safe frontend case. */
    if (info_status == HYBRID580_UVM_INFO_NOT_FOUND)
        return;
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM CSL deinit could not retire its owner (%d); frontend pinned\n",
                 info_status);
        return;
    }

    ops = hybrid580_uvm_csl_backend(provider);
    if (ops == NULL) {
        (void)hybrid580_uvm_info_finish_retire(entry, NV_ERR_INVALID_STATE);
        return;
    }
    ops->deinit_context(uvmCslContext);
    (void)hybrid580_uvm_info_finish_retire(entry, NV_OK);
}
EXPORT_SYMBOL(nvUvmInterfaceDeinitCslContext);

NV_STATUS nvUvmInterfaceCslRotateKey(UvmCslContext *contextList[],
                                     NvU32 contextListCount)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin *pins;
    uintptr_t *identities;
    enum hybrid580_uvm_provider provider = 0;
    enum hybrid580_uvm_info_status info_status;
    unsigned long flags;
    NV_STATUS status;
    NvU32 i;

    if (contextList == NULL || contextListCount == 0)
        return NV_ERR_INVALID_ARGUMENT;
    identities = kcalloc(contextListCount, sizeof(*identities), GFP_KERNEL);
    pins = kcalloc(contextListCount, sizeof(*pins), GFP_KERNEL);
    if (identities == NULL || pins == NULL) {
        kfree(identities);
        kfree(pins);
        return NV_ERR_NO_MEMORY;
    }
    for (i = 0; i < contextListCount; ++i) {
        if (contextList[i] == NULL) {
            kfree(identities);
            kfree(pins);
            return NV_ERR_INVALID_ARGUMENT;
        }
        identities[i] = (uintptr_t)contextList[i];
    }

    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_pin_many_same_provider(
        &hybrid580_uvm_infos, identities, contextListCount,
        HYBRID580_UVM_INFO_CSL, pins, &provider);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        status = hybrid580_uvm_info_status_to_nv(info_status);
        goto done;
    }

    ops = hybrid580_uvm_csl_backend(provider);
    status = ops != NULL ? ops->rotate_key(contextList, contextListCount) :
                           NV_ERR_INVALID_STATE;
    spin_lock_irqsave(&hybrid580_uvm_info_lock, flags);
    info_status = hybrid580_uvm_info_registry_unpin_many(
        &hybrid580_uvm_infos, pins, contextListCount);
    spin_unlock_irqrestore(&hybrid580_uvm_info_lock, flags);
    if (info_status != HYBRID580_UVM_INFO_OK) {
        hybrid580_uvm_pin_quarantined_state();
        pr_emerg("hybrid580 UVM CSL key-rotation pins were inconsistent; frontend pinned\n");
        status = NV_ERR_INVALID_STATE;
    }

done:
    kfree(pins);
    kfree(identities);
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslRotateKey);

NV_STATUS nvUvmInterfaceCslRotateIv(UvmCslContext *uvmCslContext,
                                    UvmCslOperation operation)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->rotate_iv(uvmCslContext, operation) :
                           NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslRotateIv);

NV_STATUS nvUvmInterfaceCslEncrypt(UvmCslContext *uvmCslContext,
                                   NvU32 bufferSize,
                                   NvU8 const *inputBuffer,
                                   UvmCslIv *encryptIv,
                                   NvU8 *outputBuffer,
                                   NvU8 *authTagBuffer)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->encrypt(uvmCslContext, bufferSize,
                                        inputBuffer, encryptIv, outputBuffer,
                                        authTagBuffer) : NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslEncrypt);

NV_STATUS nvUvmInterfaceCslDecrypt(UvmCslContext *uvmCslContext,
                                   NvU32 bufferSize,
                                   NvU8 const *inputBuffer,
                                   UvmCslIv const *decryptIv,
                                   NvU32 keyRotationId,
                                   NvU8 *outputBuffer,
                                   NvU8 const *addAuthData,
                                   NvU32 addAuthDataSize,
                                   NvU8 const *authTagBuffer)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->decrypt(
        uvmCslContext, bufferSize, inputBuffer, decryptIv, keyRotationId,
        outputBuffer, addAuthData, addAuthDataSize, authTagBuffer) :
        NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslDecrypt);

NV_STATUS nvUvmInterfaceCslSign(UvmCslContext *uvmCslContext,
                                NvU32 bufferSize,
                                NvU8 const *inputBuffer,
                                NvU8 *authTagBuffer)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->sign(uvmCslContext, bufferSize, inputBuffer,
                                     authTagBuffer) : NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslSign);

NV_STATUS nvUvmInterfaceCslQueryMessagePool(UvmCslContext *uvmCslContext,
                                            UvmCslOperation operation,
                                            NvU64 *messageNum)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->query_message_pool(
        uvmCslContext, operation, messageNum) : NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslQueryMessagePool);

NV_STATUS nvUvmInterfaceCslIncrementIv(UvmCslContext *uvmCslContext,
                                       UvmCslOperation operation,
                                       NvU64 increment,
                                       UvmCslIv *iv)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->increment_iv(
        uvmCslContext, operation, increment, iv) : NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslIncrementIv);

NV_STATUS nvUvmInterfaceCslLogEncryption(UvmCslContext *uvmCslContext,
                                         UvmCslOperation operation,
                                         NvU32 bufferSize)
{
    const struct hybrid580_uvm_csl_backend_ops *ops;
    struct hybrid580_uvm_info_pin pin = {0};
    NV_STATUS status = hybrid580_uvm_csl_pin(uvmCslContext, &pin);

    if (status != NV_OK)
        return status;
    ops = hybrid580_uvm_csl_backend(pin.provider);
    status = ops != NULL ? ops->log_encryption(
        uvmCslContext, operation, bufferSize) : NV_ERR_INVALID_STATE;
    if (hybrid580_uvm_csl_unpin(&pin) != NV_OK)
        return NV_ERR_INVALID_STATE;
    return status;
}
EXPORT_SYMBOL(nvUvmInterfaceCslLogEncryption);
