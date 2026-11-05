/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_TEST_NVIDIA_R595_UVM_TYPES_H
#define HYBRID580_TEST_NVIDIA_R595_UVM_TYPES_H

/*
 * Minimal test shim, not a replacement for NVIDIA's public header. It supplies
 * only the surrounding types needed to compile the production R580 adapter.
 * The R595 P2P payload and link enum below come from the exact, notice-bearing
 * excerpts pinned by test_hybrid580_r580_p2p_route.py. Other declarations are
 * test scaffolding and carry no claim about the complete UVM ABI.
 */
#include <stdint.h>

typedef uint8_t NvU8;
typedef uint32_t NvU32;
typedef uint64_t NvU64;
typedef NvU8 NvBool;

#define NV_TRUE ((NvBool)1)
#define NV_FALSE ((NvBool)0)
#define UVM_COPY_ENGINE_COUNT_MAX 4
#define UVM_GPU_CHANNEL_MAX_RESOURCES 8

typedef uint32_t UvmGpuChannelResourceInfo;

typedef struct UvmGpuCopyEngineCaps_tag
{
    NvBool supported;
    NvBool grce;
    NvBool shared;
    NvBool sysmemRead;
    NvBool sysmemWrite;
    NvBool sysmem;
    NvBool nvlinkP2p;
    NvBool p2p;
    NvBool secure;
    NvBool scrub;
    NvU32 cePceMask;
} UvmGpuCopyEngineCaps;

typedef struct UvmGpuCopyEnginesCaps_tag
{
    UvmGpuCopyEngineCaps copyEngineCaps[UVM_COPY_ENGINE_COUNT_MAX];
} UvmGpuCopyEnginesCaps;

#include "../nv_uvm_link_type_enum_excerpt.h"
#include "../nv_uvm_p2p_caps_struct_excerpt.h"

typedef struct UvmGpuChannelInstanceInfo_tag
{
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
    volatile NvU32 *workSubmissionOffset;
    NvU32 workSubmissionToken;
    volatile NvU32 *pChramChannelRegister;
    NvU32 smcEngineId;
    NvU32 smcEngineVeIdOffset;
} UvmGpuChannelInstanceInfo;

#endif
