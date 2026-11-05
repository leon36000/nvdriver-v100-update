/* SPDX-License-Identifier: MIT */
#include "rm_root_client.h"

/* Neither RM status channel may accidentally inherit success from its input. */
#define STATUS_UNWRITTEN ((NV_STATUS)0xffffffffU)

static NV_STATUS failure(NV_STATUS transport, NV_STATUS payload)
{
    if (transport != NV_OK)
        return transport;
    if (payload != NV_OK && payload != STATUS_UNWRITTEN)
        return payload;
    return NV_ERR_INVALID_STATE;
}

static NvBool endpoints_valid(const struct hybrid_rm_endpoint e[2])
{
    if (!e)
        return NV_FALSE;
    for (unsigned i = 0; i < 2; ++i)
        if (!e[i].ioctl || !e[i].stack || !e[i].control || !e[i].file ||
            !NV_IS_CTL_DEVICE(e[i].control))
            return NV_FALSE;
    return e[0].file != e[1].file && e[0].ioctl != e[1].ioctl;
}

static NvBool sessions_valid(const struct hybrid_rm_session_endpoint_v1 e[2])
{
    if (!e)
        return NV_FALSE;
    for (unsigned i = 0; i < 2; ++i)
        if (e[i].abi_version != HYBRID_RM_SESSION_ABI_V1 ||
            e[i].struct_size != sizeof(e[i]) || !e[i].invoke || !e[i].context ||
            !e[i].backend_identity || !e[i].file_identity)
            return NV_FALSE;
    return e[0].context != e[1].context &&
           e[0].backend_identity != e[1].backend_identity &&
           e[0].file_identity != e[1].file_identity;
}

static NV_STATUS slot_invoke(struct hybrid_root_slot *slot, NvU32 command,
                             void *payload, NvU32 size)
{
    if (slot->session.invoke)
        return slot->session.invoke(slot->session.context, command, payload, size);
    return slot->endpoint.ioctl(slot->endpoint.stack, slot->endpoint.control,
                                slot->endpoint.file, command, payload, size);
}

/* Free only allocations whose successful statuses established ownership.
 * Always attempt the other known allocation, even if one cleanup fails. */
static NV_STATUS release_known(struct hybrid_root_client *c)
{
    NV_STATUS result = NV_OK;
    for (int i = 1; i >= 0; --i) {
        struct hybrid_root_slot *s = &c->slot[i];
        if (s->handle) {
            NVOS00_PARAMETERS p = {0};
            p.hRoot = p.hObjectOld = s->handle;
            p.status = STATUS_UNWRITTEN;
            s->free_transport = slot_invoke(s, NV_ESC_RM_FREE, &p, sizeof(p));
            s->free_status = p.status;
            if (s->free_transport == NV_OK && s->free_status == NV_OK)
                s->handle = 0;
            else {
                s->uncertain = NV_TRUE;
                if (result == NV_OK)
                    result = failure(s->free_transport, s->free_status);
            }
        }
    }
    if (c->slot[0].uncertain || c->slot[1].uncertain ||
        c->slot[0].handle || c->slot[1].handle) {
        c->state = HYBRID_ROOT_QUARANTINED;
        if (result == NV_OK)
            result = NV_ERR_INVALID_STATE;
    } else {
        c->id = 0;
        c->state = HYBRID_ROOT_EMPTY;
    }
    return result;
}

enum root_packet_kind { ROOT_PACKET_21, ROOT_PACKET_64 };

static NvBool root_fields_valid(NvHandle root, NvHandle parent, NvHandle object,
                               NvV32 class_id, NvP64 parameters, NvU32 size)
{
    return !root && !parent && !object &&
        (class_id == NV01_ROOT || class_id == NV01_ROOT_CLIENT) &&
        !parameters && !size;
}

/* The packet kind is chosen only by the two typed public entry points. Each
 * wire form retains its real SDK layout and its own status-field offset. */
static NV_STATUS root_alloc_common(struct hybrid_root_client *c,
                                   const struct hybrid_rm_endpoint e[2],
                                   const struct hybrid_rm_session_endpoint_v1 sessions[2],
                                   enum root_packet_kind kind, void *request)
{
    NvHandle *request_object;
    NvV32 *request_status;
    NvBool valid;
    if (!c || !request)
        return NV_ERR_INVALID_ARGUMENT;
    if (kind == ROOT_PACKET_21) {
        NVOS21_PARAMETERS *p = request;
        request_object = &p->hObjectNew;
        request_status = &p->status;
        valid = root_fields_valid(p->hRoot, p->hObjectParent, p->hObjectNew,
                                  p->hClass, p->pAllocParms, p->paramsSize);
    } else {
        NVOS64_PARAMETERS *p = request;
        request_object = &p->hObjectNew;
        request_status = &p->status;
        valid = root_fields_valid(p->hRoot, p->hObjectParent, p->hObjectNew,
                                  p->hClass, p->pAllocParms, p->paramsSize) &&
            !p->pRightsRequested && p->flags == NVOS64_FLAGS_NONE;
    }
    if (c->state != HYBRID_ROOT_EMPTY) {
        *request_status = NV_ERR_INVALID_STATE;
        return NV_ERR_INVALID_STATE;
    }
    if (!(e ? endpoints_valid(e) : sessions_valid(sessions)) || !valid) {
        *request_status = NV_ERR_INVALID_ARGUMENT;
        return NV_ERR_INVALID_ARGUMENT;
    }
    c->state = HYBRID_ROOT_ALLOCATING;
    c->id = 0;
    for (unsigned i = 0; i < 2; ++i) {
        c->slot[i] = (struct hybrid_root_slot){0};
        /* Snapshot the dispatch identity, not a temporary per-call stack.
         * The caller continues to own the referenced session/file lifetime. */
        if (e)
            c->slot[i].endpoint = e[i];
        else
            c->slot[i].session = sessions[i];
    }
    NV_STATUS error = NV_OK;
    for (unsigned i = 0; i < 2; ++i) {
        struct hybrid_root_slot *s = &c->slot[i];
        union {
            NVOS21_PARAMETERS p21;
            NVOS64_PARAMETERS p64;
        } packet;
        void *payload;
        NvU32 size;
        NvV32 *payload_status;
        NvHandle *payload_object;
        NvHandle desired = i ? c->slot[0].handle : 0;
        /* R580 RS_COMPATABILITY_MODE=1 uses a nonzero hRoot as the requested
         * root-client ID; hObjectNew is the returned resource handle. Static
         * source supports this within one RsServer. Cross-backend use is only
         * valid if the two endpoints own independent RM client domains. */
        if (kind == ROOT_PACKET_21) {
            packet.p21 = (NVOS21_PARAMETERS){0};
            packet.p21.hClass = NV01_ROOT_CLIENT;
            packet.p21.hRoot = desired;
            packet.p21.status = STATUS_UNWRITTEN;
            payload = &packet.p21;
            size = sizeof(packet.p21);
            payload_status = &packet.p21.status;
            payload_object = &packet.p21.hObjectNew;
        } else {
            packet.p64 = (NVOS64_PARAMETERS){0};
            packet.p64.hClass = NV01_ROOT_CLIENT;
            packet.p64.hRoot = desired;
            packet.p64.flags = NVOS64_FLAGS_NONE;
            packet.p64.status = STATUS_UNWRITTEN;
            payload = &packet.p64;
            size = sizeof(packet.p64);
            payload_status = &packet.p64.status;
            payload_object = &packet.p64.hObjectNew;
        }
        s->alloc_transport = slot_invoke(s, NV_ESC_RM_ALLOC, payload, size);
        s->alloc_status = *payload_status;
        s->observed = *payload_object;
        if (s->alloc_transport != NV_OK || s->alloc_status != NV_OK) {
            /* Source writes hObjectNew even on some failures. A returned handle
             * with failure is not safe to FREE: it may be already rolled back. */
            /* Even failure with no output ID cannot prove the opaque backend
             * left no partial state. Keep the file-lifetime cleanup obligation. */
            s->uncertain = NV_TRUE;
            error = failure(s->alloc_transport, s->alloc_status);
            break;
        }
        if (!s->observed) {
            s->uncertain = NV_TRUE;
            error = NV_ERR_INVALID_OBJECT_HANDLE;
            break;
        }
        s->handle = s->observed;
        if (i && s->handle != c->slot[0].handle) {
            error = NV_ERR_INVALID_OBJECT_HANDLE;
            break;
        }
    }
    if (error != NV_OK) {
        c->state = HYBRID_ROOT_CLOSING;
        (void)release_known(c); /* retained per-slot statuses distinguish cleanup failures */
        *request_status = error;
        return error;
    }
    c->id = c->slot[0].handle;
    c->state = HYBRID_ROOT_ACTIVE;
    *request_object = c->id;
    /* R580 RmIoctl normalizes the ROOT alias to ROOT_CLIENT. The installed
     * RTX5080 trace confirms this output mutation for NVOS64. Publish it only
     * after both allocations succeeded, alongside the mirrored handle. */
    if (kind == ROOT_PACKET_21)
        ((NVOS21_PARAMETERS *)request)->hClass = NV01_ROOT_CLIENT;
    else
        ((NVOS64_PARAMETERS *)request)->hClass = NV01_ROOT_CLIENT;
    *request_status = NV_OK;
    return NV_OK;
}

NV_STATUS hybrid_root_alloc(struct hybrid_root_client *c,
                            const struct hybrid_rm_endpoint e[2], NVOS21_PARAMETERS *request)
{
    return root_alloc_common(c, e, 0, ROOT_PACKET_21, request);
}

NV_STATUS hybrid_root_alloc64(struct hybrid_root_client *c,
                              const struct hybrid_rm_endpoint e[2], NVOS64_PARAMETERS *request)
{
    return root_alloc_common(c, e, 0, ROOT_PACKET_64, request);
}

NV_STATUS hybrid_root_alloc_session(struct hybrid_root_client *c,
    const struct hybrid_rm_session_endpoint_v1 e[2], NVOS21_PARAMETERS *request)
{
    return root_alloc_common(c, 0, e, ROOT_PACKET_21, request);
}

NV_STATUS hybrid_root_alloc_session64(struct hybrid_root_client *c,
    const struct hybrid_rm_session_endpoint_v1 e[2], NVOS64_PARAMETERS *request)
{
    return root_alloc_common(c, 0, e, ROOT_PACKET_64, request);
}

NV_STATUS hybrid_root_free(struct hybrid_root_client *c)
{
    if (!c)
        return NV_ERR_INVALID_ARGUMENT;
    if (c->state != HYBRID_ROOT_ACTIVE)
        return NV_ERR_INVALID_STATE;
    c->state = HYBRID_ROOT_CLOSING;
    return release_known(c);
}
