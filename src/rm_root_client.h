/* SPDX-License-Identifier: MIT */
#ifndef HYBRID_RM_ROOT_CLIENT_H
#define HYBRID_RM_ROOT_CLIENT_H

/* cpuopsys.h (via nvtypes) establishes NV_LINUX before nv.h selects stddef. */
#include <nvtypes.h>
#include <nv.h>
#include <nvos.h>
#include <nv_escape.h>
#include "rm_session_endpoint.h"

/* Exact NVIDIA R580 signature; no reconstructed SDK structs. */
typedef NV_STATUS (NV_API_CALL *hybrid_rm_ioctl_fn)(
    nvidia_stack_t *, nv_state_t *, nv_file_private_t *, NvU32, void *, NvU32);

struct hybrid_rm_endpoint {
    hybrid_rm_ioctl_fn ioctl;
    nvidia_stack_t *stack;
    nv_state_t *control;
    nv_file_private_t *file;
};

enum hybrid_root_state {
    HYBRID_ROOT_EMPTY = 0,
    HYBRID_ROOT_ALLOCATING,
    HYBRID_ROOT_ACTIVE,
    HYBRID_ROOT_CLOSING,
    HYBRID_ROOT_QUARANTINED
};

struct hybrid_root_slot {
    struct hybrid_rm_endpoint endpoint;
    struct hybrid_rm_session_endpoint_v1 session;
    NvHandle handle;       /* confirmed successful allocation only */
    NvHandle observed;     /* diagnostic output; NEVER proof of ownership */
    NV_STATUS alloc_transport, alloc_status;
    NV_STATUS free_transport, free_status;
    NvBool uncertain;
};

struct hybrid_root_client {
    enum hybrid_root_state state;
    NvHandle id;
    struct hybrid_root_slot slot[2]; /* legacy first, Open second */
};

/* Caller contract:
 * - Zero-initialize once; never reset/reuse a quarantined record.
 * - Serialize ALL broker operations with a caller-owned frontend file/session
 *   mutex held for each complete transaction. Reentrancy is rejected, but
 *   this API supplies no inter-thread locking primitive or reference pin.
 * - Raw API: hold valid stack/control/file objects throughout the lifetime.
 * - Session API: hold the owned session and its file/module references until
 *   every retained allocation has been freed or backend teardown completed,
 *   including quarantined records. Copying the endpoint takes no reference.
 *   The callback supplies PM/stack/security state separately for EACH call;
 *   neither a temporary stack nor a PM lock is retained by the root broker.
 *   Session callbacks must not retain the request buffer after returning.
 * - Endpoints must reach isolated RM instances, with distinct nvfp storage.
 *   Pointer inequality alone cannot establish global-state isolation.
 * - Calls occur within the RM runtime/security environment required by rm_ioctl.
 *
 * First executable slice only: NVOS21/NVOS64 ROOT/ROOT_CLIENT automatic root
 * allocation, NULL class parameters. NVOS64 accepts NULL rights and flags NONE
 * only; serialized parameters and unknown flags fail before backend calls.
 * No generic ioctl, embedded pointer copy, child-object routing, enumeration,
 * file close hook or UVM bridge yet. Preserving a 48-byte allocation form does
 * not establish that an observed libcuda request has supported root contents.
 * Every backend allocation failure (even with zero output ID), ambiguous
 * success output and failed free quarantine the record. No absence of partial
 * side effects is inferred from an opaque backend's error response.
 * Cleanup of quarantined resources requires backend-aware file teardown; this
 * API deliberately does not retry ambiguous operations or clear ownership.
 */
NV_STATUS hybrid_root_alloc(struct hybrid_root_client *,
                            const struct hybrid_rm_endpoint [2], NVOS21_PARAMETERS *);
NV_STATUS hybrid_root_alloc64(struct hybrid_root_client *,
                              const struct hybrid_rm_endpoint [2], NVOS64_PARAMETERS *);
NV_STATUS hybrid_root_alloc_session(struct hybrid_root_client *,
    const struct hybrid_rm_session_endpoint_v1 [2], NVOS21_PARAMETERS *);
NV_STATUS hybrid_root_alloc_session64(struct hybrid_root_client *,
    const struct hybrid_rm_session_endpoint_v1 [2], NVOS64_PARAMETERS *);
NV_STATUS hybrid_root_free(struct hybrid_root_client *);

/* Compile/link-only binding; does not initialize either RM instance. */
void hybrid_root_bind_r580(struct hybrid_rm_endpoint [2]);
#endif
