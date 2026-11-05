/*
 * SPDX-FileCopyrightText: Copyright (c) 2014-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/* Source: NVIDIA-kernel-module-source-580.196.07/src/nvidia/interface/nv_uvm_types.h
 * Source archive SHA-256: 21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084
 * Source file SHA-256: ee22643e79d6b7dae56ac52da517bae19b6594b1bf9564baeb68df10af6d5922
 * Exact structure lines: 511-542
 * SPDX notice retained from source; excerpt is for static regression tests.
 */


typedef struct UvmGpuP2PCapsParams_tag
{
    // Out: peerId[i] contains gpu[i]'s peer id of gpu[1 - i]. Only defined if
    // the GPUs are direct peers.
    NvU32 peerIds[2];

    // Out: peerId[i] contains gpu[i]'s EGM peer id of gpu[1 - i]. Only defined
    // if the GPUs are direct peers and EGM enabled in the system.
    NvU32 egmPeerIds[2];

    // Out: UVM_LINK_TYPE
    NvU32 p2pLink;

    // Out: optimalNvlinkWriteCEs[i] contains gpu[i]'s optimal CE for writing to
    // gpu[1 - i]. The CE indexes are valid only if the GPUs are NVLink peers.
    //
    // The value returned by RM for this field may change when a GPU is
    // registered with RM for the first time, so UVM needs to query it again
    // each time a GPU is registered.
    NvU32 optimalNvlinkWriteCEs[2];

    // Out: Maximum unidirectional bandwidth between the peers in megabytes per
    // second, not taking into account the protocols overhead. The reported
    // bandwidth for indirect peers is zero.
    NvU32 totalLinkLineRateMBps;

    // Out: IOMMU/DMA mappings of bar1 of the respective peer vidmem.
    // Size is 0 if bar1 p2p is not supported.
    NvU64 bar1DmaAddress[2];
    NvU64 bar1DmaSize[2];
} UvmGpuP2PCapsParams;
