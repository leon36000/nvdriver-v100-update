/*******************************************************************************
    Copyright (c) 2016-2025 NVIDIA Corporation

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

/* Minimal patch fixture copied from NVIDIA open-gpu-kernel-modules 595.99.02,
 * kernel-open/nvidia-uvm/uvm_map_external.c. The complete pinned file is used
 * by local tests when present; this excerpt keeps the patch contract runnable
 * from a clean source checkout without committing generated research trees. */

#include "uvm_tlb_batch.h"
#include "nv_uvm_interface.h"
#include "nv_uvm_types.h"
#include "nv_uvm_user_types.h"

    uvm_rm_user_object_t user_rm_mem =
    {
        .rm_control_fd = params->rmCtrlFd,
        .user_client   = params->hClient,
        .user_object   = params->hMemory
    };

    // Dup the memory. This verifies the input handles, takes a ref count on the
    // physical allocation so it can't go away under us, and returns us the
    // allocation info.
    status = uvm_rm_locked_call(nvUvmInterfaceDupMemory(uvm_gpu_device_handle(mapping_gpu),
                                                        user_rm_mem->user_client,
                                                        user_rm_mem->user_object,
                                                        &ext_gpu_map->mem_handle->rm_handle,
                                                        &mem_info));
    if (status != NV_OK) {
        UVM_DBG_PRINT("Failed to dup memory handle {0x%x, 0x%x}: %s, GPU: %s\n",
                      user_rm_mem->user_client,
                      user_rm_mem->user_object,
                      nvstatusToString(status),
                      uvm_gpu_name(mapping_gpu));
        goto error;
    }

/* The R595 cleanup callback frees the duplicate after map-setup failure. */
static void uvm_release_rm_handle(struct nv_kref *ref)
{
    uvm_ext_gpu_mem_handle *mem_handle =
        container_of(ref, uvm_ext_gpu_mem_handle, ref_count);

    if (mem_handle->rm_handle) {
        NV_STATUS status;

        status = uvm_rm_locked_call(nvUvmInterfaceFreeDupedHandle(uvm_gpu_device_handle(mem_handle->gpu),
                                                                  mem_handle->rm_handle));
        UVM_ASSERT(status == NV_OK);
    }
    uvm_kvfree(mem_handle);
}
