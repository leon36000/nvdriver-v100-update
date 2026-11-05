/*
 * SPDX-FileCopyrightText: Copyright (c) 2013-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/* Source: NVIDIA-kernel-module-source-580.196.07/src/nvidia/src/kernel/rmapi/nv_gpu_ops.c
 * Source archive SHA-256: 21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084
 * Source file SHA-256: 98e4fcca21a17eb9b52793805f4d3a0f8ab9468a4f7154c0eddc2714b1443722
 * Exact function lines: 3173-3302
 * SPDX notice retained from source; excerpt is for static regression tests.
 */


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

                // Get BAR1 P2P DMA info using from peer to local
                NV_CHECK_OK_OR_GOTO(status, LEVEL_ERROR,
                    kbusGetBar1P2PDmaInfo_HAL(pRemoteGpu,
                                              pLocalGpu,
                                              GPU_GET_KERNEL_BUS(pLocalGpu),
                                              &p2pCapsParams->bar1DmaAddress[1],
                                              &p2pCapsParams->bar1DmaSize[1]),
                    cleanup);
            }

            p2pCapsParams->p2pLink               = UVM_LINK_TYPE_PCIE;
            p2pCapsParams->totalLinkLineRateMBps = NV_MIN(linkBandwidthMBps1, linkBandwidthMBps2);
        }
    }

cleanup:
    portMemFree(nvlinkStatus1);
    portMemFree(nvlinkStatus2);

    return status;
}
