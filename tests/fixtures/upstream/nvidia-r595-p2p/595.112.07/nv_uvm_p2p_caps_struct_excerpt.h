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

/* Source: open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2/src/nvidia/interface/nv_uvm_types.h
 * Source archive SHA-256: 567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4
 * Source file SHA-256: 9bbe94713cfd6215ecb74e4626c19077e386009fe340fe156f94de9693ea635e
 * Exact structure lines: 517-554
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

    // True if GPU i can use PCIe atomics on locations in GPU[i-1]
    // BAR1. This implies that GPU[i] can issue PCIe atomics,
    // GPU[i-1] can accept PCIe atomics, and the bus interconnect
    // between the two GPUs can correctly route PCIe atomics.
    NvBool bar1PcieAtomics[2];
} UvmGpuP2PCapsParams;
