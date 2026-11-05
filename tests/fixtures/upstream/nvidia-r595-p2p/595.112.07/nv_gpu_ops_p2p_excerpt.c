/*
 * SPDX-FileCopyrightText: Copyright (c) 2013-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * Verbatim function excerpts from NVIDIA/open-gpu-kernel-modules tag 595.112.07.
 * Tag object: 2e8dd6c0bbd2e08194b96abeb5c319717cd13682
 * Commit: d8257d95ae5fed364163e4df51db66df8b1ee0d2
 * Original path: src/nvidia/src/kernel/rmapi/nv_gpu_ops.c
 * Original file SHA-256: e3cd52c0eb84554ad92e8ab6436e949492f45591307ff0b149a239367a837c8f
 * Excerpted functions retain their original source text; no pseudocode is included.
 */

/* Original lines 3032-3112 */

// Get R/W/A access capabilities and the link type between the two given GPUs
static NV_STATUS getSystemP2PCaps(struct gpuDevice *device1,
                                  struct gpuDevice *device2,
                                  struct systemP2PCaps *p2pCaps,
                                  RMAPI_TYPE rmapiType)
{
    NV0000_CTRL_SYSTEM_GET_P2P_CAPS_V2_PARAMS *p2pCapsParams = NULL;
    NV_STATUS status = NV_OK;

    p2pCapsParams = portMemAllocNonPaged(sizeof(*p2pCapsParams));
    if (p2pCapsParams == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto done;
    }

    status = rmSystemP2PCapsControl(device1, device2, p2pCapsParams, rmapiType);
    if (status != NV_OK)
        goto done;

    portMemSet(p2pCaps, 0, sizeof(*p2pCaps));
    p2pCaps->peerIds[0] = p2pCapsParams->busPeerIds[0 * 2 + 1];
    p2pCaps->peerIds[1] = p2pCapsParams->busPeerIds[1 * 2 + 0];
    p2pCaps->egmPeerIds[0] = p2pCapsParams->busEgmPeerIds[0 * 2 + 1];
    p2pCaps->egmPeerIds[1] = p2pCapsParams->busEgmPeerIds[1 * 2 + 0];
    p2pCaps->nvlinkSupported = !!REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_NVLINK_SUPPORTED, p2pCapsParams->p2pCaps);
    p2pCaps->atomicSupported = !!REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_ATOMICS_SUPPORTED, p2pCapsParams->p2pCaps);
    p2pCaps->bar1Supported = !!REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PCI_BAR1_SUPPORTED, p2pCapsParams->p2pCaps);

    // TODO: Bug 1768805: Check both reads and writes since RM seems to be
    //       currently incorrectly reporting just the P2P write cap on some
    //       systems that cannot support P2P at all. See the bug for more
    //       details.
    if (REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_READS_SUPPORTED, p2pCapsParams->p2pCaps) &&
        REF_VAL(NV0000_CTRL_SYSTEM_GET_P2P_CAPS_WRITES_SUPPORTED, p2pCapsParams->p2pCaps))
    {
        p2pCaps->accessSupported = NV_TRUE;
    }

    if (p2pCaps->nvlinkSupported)
    {
        //
        // Exactly one CE is expected to be recommended for transfers between
        // NvLink peers.
        //
        // In case of a single GPU, kceGetP2PCes() returns all possible CEs. In
        // that case, set the lowest bit only to keep the assert happy.
        //
        if (device1 == device2)
        {
            p2pCapsParams->p2pOptimalWriteCEs &=
                                (~p2pCapsParams->p2pOptimalWriteCEs + 1);
        }

        NV_ASSERT(nvPopCount32(p2pCapsParams->p2pOptimalWriteCEs) == 1);

        // Query the write mask only; UVM has no use for the read mask
        p2pCaps->optimalNvlinkWriteCEs[0] = BIT_IDX_32(p2pCapsParams->p2pOptimalWriteCEs);

        // Query the P2P capabilities of device2->device1, which may be
        // different from those of device1->device2
        status = rmSystemP2PCapsControl(device2, device1, p2pCapsParams, rmapiType);
        if (status != NV_OK)
            goto done;

        if (device1 == device2)
        {
            p2pCapsParams->p2pOptimalWriteCEs &=
                                (~p2pCapsParams->p2pOptimalWriteCEs + 1);
        }

        NV_ASSERT(nvPopCount32(p2pCapsParams->p2pOptimalWriteCEs) == 1);

        p2pCaps->optimalNvlinkWriteCEs[1] = BIT_IDX_32(p2pCapsParams->p2pOptimalWriteCEs);
    }

done:
    portMemFree(p2pCapsParams);
    return status;
}

/* Original lines 3175-3189 */
// TODO: Bug 3264814: [HOPPER][RM] Support Bar1 P2P PCIE Atomics
// The logic here should consider bus topology and routing between
// the two GPUs.

// TODO: Bug 3264814: [HOPPER][RM] Support Bar1 P2P PCIE Atomics
// The logic here should consider bus topology and routing between
// the two GPUs.
NvBool _nvGpuOpsIsBar1P2pAtomicEnabled(struct gpuSession *session, OBJGPU *pMappingGpu, OBJGPU *pOwningGpu)
{
    NvU32 arch;
    NV_STATUS status = _nvGpuOpsGetDeviceArchByGpuId(session, pOwningGpu->gpuId, &arch);

    NV_ASSERT_OR_RETURN(status == NV_OK, 0);
    return arch >= GPU_ARCHITECTURE_BLACKWELL_GB1XX;
}

/* Original lines 3190-3331 */

NV_STATUS nvGpuOpsGetP2PCaps(struct gpuDevice *device1,
                             struct gpuDevice *device2,
                             getP2PCapsParams *p2pCapsParams)
{
    NV_STATUS status = NV_OK;
    NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS *nvlinkStatus1 = NULL;
    NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS *nvlinkStatus2 = NULL;
    struct systemP2PCaps p2pCaps;

    if (!device1 || !device2)
        return NV_ERR_INVALID_ARGUMENT;

    if (device1->session != device2->session)
        return NV_ERR_INVALID_ARGUMENT;

    if (!p2pCapsParams)
        return NV_ERR_INVALID_ARGUMENT;

    status = allocNvlinkStatus(device1->session->handle,
                               device1->subhandle,
                               &nvlinkStatus1);
    if (status != NV_OK)
        goto cleanup;

    status = allocNvlinkStatus(device2->session->handle,
                               device2->subhandle,
                               &nvlinkStatus2);
    if (status != NV_OK)
        goto cleanup;

    portMemSet(p2pCapsParams, 0, sizeof(*p2pCapsParams));
    p2pCapsParams->peerIds[0]      = (NvU32)-1;
    p2pCapsParams->peerIds[1]      = (NvU32)-1;
    p2pCapsParams->egmPeerIds[0]      = (NvU32)-1;
    p2pCapsParams->egmPeerIds[1]      = (NvU32)-1;
    p2pCapsParams->bar1DmaAddress[0]  = (NvU64)-1;
    p2pCapsParams->bar1DmaAddress[1]  = (NvU64)-1;
    p2pCapsParams->bar1DmaSize[0]     = (NvU64)0;
    p2pCapsParams->bar1DmaSize[1]     = (NvU64)0;
    p2pCapsParams->bar1PcieAtomics[0] = NV_FALSE;
    p2pCapsParams->bar1PcieAtomics[1] = NV_FALSE;
    p2pCapsParams->p2pLink         = UVM_LINK_TYPE_NONE;

    status = getSystemP2PCaps(device1, device2, &p2pCaps,
                              RMAPI_EXTERNAL_KERNEL);
    if (status != NV_OK)
        goto cleanup;

    if (p2pCaps.accessSupported)
    {
        p2pCapsParams->peerIds[0] = p2pCaps.peerIds[0];
        p2pCapsParams->peerIds[1] = p2pCaps.peerIds[1];
        p2pCapsParams->egmPeerIds[0] = p2pCaps.egmPeerIds[0];
        p2pCapsParams->egmPeerIds[1] = p2pCaps.egmPeerIds[1];

        if (p2pCaps.nvlinkSupported)
        {
            NvU32 nvlinkVersion;
            NvU32 linkBandwidthMBps;

            NV_ASSERT(p2pCaps.atomicSupported);

            status = getNvlinkP2PCaps(device1,
                                      device2,
                                      nvlinkStatus1,
                                      nvlinkStatus2,
                                      &nvlinkVersion,
                                      &linkBandwidthMBps);
            if (status != NV_OK)
                goto cleanup;

            p2pCapsParams->p2pLink                  = rmControlToUvmNvlinkVersion(nvlinkVersion);
            p2pCapsParams->optimalNvlinkWriteCEs[0] = p2pCaps.optimalNvlinkWriteCEs[0];
            p2pCapsParams->optimalNvlinkWriteCEs[1] = p2pCaps.optimalNvlinkWriteCEs[1];

            NV_ASSERT(p2pCapsParams->p2pLink != UVM_LINK_TYPE_NONE);
            NV_ASSERT(linkBandwidthMBps != 0);

            p2pCapsParams->totalLinkLineRateMBps    = linkBandwidthMBps;
        }
        else
        {
            NvU32 linkBandwidthMBps1, linkBandwidthMBps2;

            status = getPCIELinkRateMBps(device1->session->handle,
                                         device1->subhandle,
                                         &linkBandwidthMBps1);
            if (status != NV_OK)
                goto cleanup;

            status = getPCIELinkRateMBps(device2->session->handle,
                                         device2->subhandle,
                                         &linkBandwidthMBps2);
            if (status != NV_OK)
                goto cleanup;

            if (p2pCaps.bar1Supported)
            {
                OBJGPU *pLocalGpu    = gpumgrGetGpuFromId(device1->gpuId);
                OBJGPU *pRemoteGpu   = gpumgrGetGpuFromId(device2->gpuId);

                // Get BAR1 P2P DMA info using from local to peer
                NV_CHECK_OK_OR_GOTO(status, LEVEL_ERROR,
                    kbusGetBar1P2PDmaInfo_HAL(pLocalGpu,
                                              pRemoteGpu,
                                              GPU_GET_KERNEL_BUS(pRemoteGpu),
                                              &p2pCapsParams->bar1DmaAddress[0],
                                              &p2pCapsParams->bar1DmaSize[0]),
                    cleanup);
                p2pCapsParams->bar1PcieAtomics[0] = _nvGpuOpsIsBar1P2pAtomicEnabled(device1->session,
                                                                                    pLocalGpu,
                                                                                    pRemoteGpu);

                // Get BAR1 P2P DMA info using from peer to local
                NV_CHECK_OK_OR_GOTO(status, LEVEL_ERROR,
                    kbusGetBar1P2PDmaInfo_HAL(pRemoteGpu,
                                              pLocalGpu,
                                              GPU_GET_KERNEL_BUS(pLocalGpu),
                                              &p2pCapsParams->bar1DmaAddress[1],
                                              &p2pCapsParams->bar1DmaSize[1]),
                    cleanup);
                p2pCapsParams->bar1PcieAtomics[1] = _nvGpuOpsIsBar1P2pAtomicEnabled(device2->session,
                                                                                    pRemoteGpu,
                                                                                    pLocalGpu);
                p2pCapsParams->p2pLink = UVM_LINK_TYPE_PCIE_BAR1;
            }
            else
            {
                p2pCapsParams->p2pLink = UVM_LINK_TYPE_PCIE;
            }

            p2pCapsParams->totalLinkLineRateMBps = NV_MIN(linkBandwidthMBps1, linkBandwidthMBps2);
        }
    }

cleanup:
    portMemFree(nvlinkStatus1);
    portMemFree(nvlinkStatus2);

    return status;
}
