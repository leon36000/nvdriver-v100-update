/*******************************************************************************
    Copyright (c) 2015-2025 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

/* Source: NVIDIA/open-gpu-kernel-modules R595.112.07, commit
 * d8257d95ae5fed364163e4df51db66df8b1ee0d2. Unmodified upstream
 * uvm_gpu.c SHA-256: 66881c4ae46461314d41342b2a27df9119d68d68f90d181e3a32670dcc19f590.
 * Only the direction-relevant functions are excerpted; the MIT notice above
 * is retained verbatim from the original source file.
 */

static uvm_aperture_t parent_gpu_peer_aperture(uvm_parent_gpu_t *local,
                                               uvm_parent_gpu_t *remote,
                                               uvm_parent_gpu_peer_t *parent_peer_caps)
{
    size_t peer_index;

    UVM_ASSERT(parent_peer_caps->ref_count);
    UVM_ASSERT(parent_peer_caps->link_type != UVM_GPU_LINK_INVALID);

    if (uvm_parent_id_value(local->id) < uvm_parent_id_value(remote->id))
        peer_index = 0;
    else
        peer_index = 1;

    if (parent_peer_caps->link_type == UVM_GPU_LINK_PCIE_BAR1) {
        // UVM_APERTURE_SYS can be used if either the local (accessing) GPU
        // _DOES NOT_ use PCIE atomics, or the remote (owning) GPU _DOES_
        // accept PCIE atomics. Moreover, the bus topology needs to support
        // routing of PCIe atomics between the devices.
        //
        // If either of the above conditions is not met we need to use
        // UVM_APERTURE_SYS_NON_COHERENT to prevent use of PCIe atomics.
        // RM provides the consolidated information in P2P properties.
        const bool enable_atomics = parent_peer_caps->bar1_p2p_pcie_atomics_enabled[peer_index];
        return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT;
    }

    return UVM_APERTURE_PEER(parent_peer_caps->peer_ids[peer_index]);
}

static NV_STATUS get_parent_p2p_caps(uvm_parent_gpu_t *parent_gpu0,
                                     uvm_parent_gpu_t *parent_gpu1,
                                     UvmGpuP2PCapsParams *p2p_caps_params)
{
    NV_STATUS status;
    uvmGpuDeviceHandle rm_device0, rm_device1;

    if (uvm_parent_id_value(parent_gpu0->id) < uvm_parent_id_value(parent_gpu1->id)) {
        rm_device0 = parent_gpu0->rm_device;
        rm_device1 = parent_gpu1->rm_device;
    }
    else {
        rm_device0 = parent_gpu1->rm_device;
        rm_device1 = parent_gpu0->rm_device;
    }

    memset(p2p_caps_params, 0, sizeof(*p2p_caps_params));
    status = uvm_rm_locked_call(nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, p2p_caps_params));
    if (status != NV_OK) {
        UVM_ERR_PRINT("nvUvmInterfaceGetP2PCaps() failed with error: %s, for GPU0:%s and GPU1:%s\n",
                       nvstatusToString(status),
                       uvm_parent_gpu_name(parent_gpu0),
                       uvm_parent_gpu_name(parent_gpu1));
        return status;
    }

    return NV_OK;
}

static NV_STATUS parent_peers_init(uvm_parent_gpu_t *parent_gpu0,
                                   uvm_parent_gpu_t *parent_gpu1,
                                   uvm_parent_gpu_peer_t *parent_peer_caps)
{
    UvmGpuP2PCapsParams p2p_caps_params;
    uvm_gpu_link_type_t link_type;
    NvHandle p2p_handle;
    NV_STATUS status;

    UVM_ASSERT(parent_peer_caps->ref_count == 0);

    status = create_parent_p2p_object(parent_gpu0, parent_gpu1, &p2p_handle);
    if (status != NV_OK)
        return status;

    status = get_parent_p2p_caps(parent_gpu0, parent_gpu1, &p2p_caps_params);
    if (status != NV_OK)
        goto cleanup;

    // check for peer-to-peer compatibility (PCI-E or NvLink).
    link_type = get_gpu_link_type(p2p_caps_params.p2pLink);
    if (link_type == UVM_GPU_LINK_INVALID || link_type == UVM_GPU_LINK_C2C) {
        status = NV_ERR_NOT_SUPPORTED;
        goto cleanup;
    }

    status = init_procfs_parent_peer_files(parent_gpu0, parent_gpu1);
    if (status != NV_OK)
        goto cleanup;

    parent_peer_caps->ref_count = 1;
    parent_peer_caps->p2p_handle = p2p_handle;
    parent_peer_caps->link_type = link_type;
    parent_peer_caps->total_link_line_rate_mbyte_per_s = p2p_caps_params.totalLinkLineRateMBps;

    if (parent_gpu0->egm.enabled || parent_gpu1->egm.enabled)
        UVM_ASSERT(parent_peer_caps->link_type >= UVM_GPU_LINK_NVLINK_2);

    // Initialize peer ids and establish peer mappings
    // Peer id from min(gpu_id0, gpu_id1) -> max(gpu_id0, gpu_id1)
    parent_peer_caps->peer_ids[0] = p2p_caps_params.peerIds[0];
    parent_peer_caps->egm_peer_ids[0] = p2p_caps_params.egmPeerIds[0];

    // Peer id from max(gpu_id0, gpu_id1) -> min(gpu_id0, gpu_id1)
    parent_peer_caps->peer_ids[1] = p2p_caps_params.peerIds[1];
    parent_peer_caps->egm_peer_ids[1] = p2p_caps_params.egmPeerIds[1];

    parent_peer_caps->optimalNvlinkWriteCEs[0] = p2p_caps_params.optimalNvlinkWriteCEs[0];
    parent_peer_caps->optimalNvlinkWriteCEs[1] = p2p_caps_params.optimalNvlinkWriteCEs[1];

    // Set IOMMU/DMA mappings for bar1 p2p
    parent_peer_caps->bar1_p2p_dma_base_address[0] = p2p_caps_params.bar1DmaAddress[0];
    parent_peer_caps->bar1_p2p_dma_base_address[1] = p2p_caps_params.bar1DmaAddress[1];
    parent_peer_caps->bar1_p2p_dma_size[0] = p2p_caps_params.bar1DmaSize[0];
    parent_peer_caps->bar1_p2p_dma_size[1] = p2p_caps_params.bar1DmaSize[1];
    parent_peer_caps->bar1_p2p_pcie_atomics_enabled[0] = p2p_caps_params.bar1PcieAtomics[0];
    parent_peer_caps->bar1_p2p_pcie_atomics_enabled[1] = p2p_caps_params.bar1PcieAtomics[1];

    if (parent_peer_caps->bar1_p2p_dma_size[0] || parent_peer_caps->bar1_p2p_dma_size[1])
        UVM_ASSERT(link_type == UVM_GPU_LINK_PCIE_BAR1);

    return NV_OK;

cleanup:
    uvm_rm_locked_call_void(nvUvmInterfaceP2pObjectDestroy(uvm_global_session_handle(), p2p_handle));

    return status;
}

static bool gpu_phys_address_is_bar1p2p_peer(uvm_gpu_t *gpu, uvm_gpu_phys_address_t address)
{
    bool is_peer = false;
    uvm_parent_processor_mask_t peer_parent_gpus;
    uvm_parent_gpu_t *peer_parent_gpu;

    // BAR1 P2P is accessed via sys aperture
    if (!uvm_aperture_is_sys(address.aperture))
        return false;

    uvm_spin_lock(&gpu->peer_info.peer_gpu_lock);
    uvm_parent_gpus_from_processor_mask(&peer_parent_gpus, &gpu->peer_info.peer_gpu_mask);
    for_each_parent_gpu_in_mask(peer_parent_gpu, &peer_parent_gpus) {
        const uvm_parent_gpu_peer_t *peer_caps = parent_gpu_peer_caps(gpu->parent, peer_parent_gpu);
        const int peer_index = (uvm_parent_id_cmp(gpu->parent->id, peer_parent_gpu->id) < 0) ? 0 : 1;

        UVM_ASSERT(peer_caps->ref_count > 0);
        if (peer_caps->link_type != UVM_GPU_LINK_PCIE_BAR1)
            continue;

        if (address.address >= peer_caps->bar1_p2p_dma_base_address[peer_index] &&
            address.address < (peer_caps->bar1_p2p_dma_base_address[peer_index] + peer_caps->bar1_p2p_dma_size[peer_index])) {
            is_peer = true;
            break;
        }
    }
    uvm_spin_unlock(&gpu->peer_info.peer_gpu_lock);

    return is_peer;
}
