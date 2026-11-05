/* SPDX-License-Identifier: MIT */
#ifndef HYBRID_RM_SESSION_ENDPOINT_H
#define HYBRID_RM_SESSION_ENDPOINT_H

#include <nvtypes.h>
#include <nvstatus.h>
#include <nv-kernel-interface-api.h>

#define HYBRID_RM_SESSION_ABI_V1 1U
typedef NV_STATUS (NV_API_CALL *hybrid_rm_session_invoke_fn)(
    void *context, NvU32 command, void *payload, NvU32 size);

/* Private kernel contract, not a CUDA/userspace ABI. Different identity
 * tokens do not prove independent RM globals. A callback may serve several
 * separately owned backend sessions. No stack/control/nvfp is retained here.
 */
struct hybrid_rm_session_endpoint_v1 {
    NvU32 abi_version;
    NvU32 struct_size;
    hybrid_rm_session_invoke_fn invoke;
    void *context;
    const void *backend_identity;
    const void *file_identity;
};

#endif
