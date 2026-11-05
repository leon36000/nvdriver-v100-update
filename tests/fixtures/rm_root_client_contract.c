/* SPDX-License-Identifier: MIT
 * Fake callbacks only. No NVIDIA RM binary is executed by this fixture. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "rm_root_client.h"

#if FIXTURE_ALLOC64
typedef NVOS64_PARAMETERS root_parameters;
#if FIXTURE_SESSION
#define root_alloc hybrid_root_alloc_session64
#else
#define root_alloc hybrid_root_alloc64
#endif
#else
typedef NVOS21_PARAMETERS root_parameters;
#if FIXTURE_SESSION
#define root_alloc hybrid_root_alloc_session
#else
#define root_alloc hybrid_root_alloc
#endif
#endif

_Static_assert(sizeof(NVOS21_PARAMETERS) == 32, "NVOS21 size");
_Static_assert(sizeof(NVOS64_PARAMETERS) == 48, "NVOS64 size");
_Static_assert(__builtin_offsetof(NVOS21_PARAMETERS, status) !=
               __builtin_offsetof(NVOS64_PARAMETERS, status), "status is not layout-compatible");

static struct hybrid_root_client client;
static nvidia_stack_t stacks[2];
static nv_state_t controls[2];
static nv_file_private_t files[2];
#if FIXTURE_SESSION
struct fake_session { int backend; };
static struct fake_session sessions[2] = {{0},{1}};
static int backend_identity[2];
static struct hybrid_rm_session_endpoint_v1 endpoints[2];
static nvidia_stack_t *active_stack;
static unsigned pm_depth;
#else
static struct hybrid_rm_endpoint endpoints[2];
#endif
static root_parameters request;
static const char *scenario;
static int calls[2], frees[2], sequence[8], sequence_count;

static NV_STATUS invoke(int backend, nvidia_stack_t *sp, nv_state_t *nv,
                        nv_file_private_t *fp, NvU32 cmd, void *data, NvU32 size)
{
#if FIXTURE_SESSION
    assert(sp == active_stack && sp != &stacks[0] && sp != &stacks[1]);
    assert(pm_depth == 1); /* model per-call PM/stack lifetime, not a Linux PM test */
#else
    assert(sp == &stacks[backend]);
#endif
    assert(nv == &controls[backend] && fp == &files[backend]);
    if (cmd == NV_ESC_RM_ALLOC) {
        root_parameters *p = data;
        assert(size == sizeof(*p));
        assert(p->hRoot == (backend ? 0xc1000042U : 0U));
        assert(p->hObjectParent == 0 && p->hObjectNew == 0);
        assert(p->hClass == NV01_ROOT_CLIENT && p->paramsSize == 0 && !p->pAllocParms);
#if FIXTURE_ALLOC64
        assert(p->pRightsRequested == 0 && p->flags == NVOS64_FLAGS_NONE);
#endif
        assert(request.hObjectNew == 0); /* publish only after BOTH succeed */
        calls[backend]++;
        sequence[sequence_count++] = backend;
        if (!strcmp(scenario, "reentrant")) {
            root_parameters nested = {0};
            nested.hClass = NV01_ROOT_CLIENT;
            assert(root_alloc(&client, endpoints, &nested) == NV_ERR_INVALID_STATE);
            assert(hybrid_root_free(&client) == NV_ERR_INVALID_STATE);
        }
        if ((!strcmp(scenario, "first-reject") && !backend) ||
            ((!strcmp(scenario, "second-reject") || !strcmp(scenario, "rollback-failure")) && backend)) {
            p->status = NV_ERR_INVALID_ARGUMENT;
            return NV_OK;
        }
        if (!strcmp(scenario, "transport-error") && backend)
            return NV_ERR_INVALID_ARGUMENT;
        if (!strcmp(scenario, "missing-status") && backend) {
            p->hObjectNew = 0xc1000042U;
            return NV_OK;
        }
        if (!strcmp(scenario, "ambiguous-output") && backend) {
            p->hObjectNew = 0xc1000042U;
            p->status = NV_ERR_INVALID_ARGUMENT;
            return NV_OK;
        }
        p->hObjectNew = !strcmp(scenario, "zero-id") && backend ? 0 : 0xc1000042U;
        if (!strcmp(scenario, "mismatched-id") && backend)
            p->hObjectNew++;
        p->status = NV_OK;
        return NV_OK;
    }
    assert(cmd == NV_ESC_RM_FREE && size == sizeof(NVOS00_PARAMETERS));
    NVOS00_PARAMETERS *p = data;
    assert(p->hRoot == (backend && !strcmp(scenario, "mismatched-id") ? 0xc1000043U : 0xc1000042U));
    assert(p->hObjectOld == p->hRoot && p->hObjectParent == 0);
    frees[backend]++;
    sequence[sequence_count++] = backend + 2;
    if (backend && !strcmp(scenario, "free-missing-status"))
        return NV_OK;
    p->status = ((!strcmp(scenario, "rollback-failure") && !backend) ||
                 (!strcmp(scenario, "close-failure") && backend)) ? NV_ERR_INVALID_STATE : NV_OK;
    if (backend && !strcmp(scenario, "free-transport-error"))
        return NV_ERR_INVALID_ARGUMENT;
    return NV_OK;
}

#if FIXTURE_SESSION
static NV_STATUS NV_API_CALL session_invoke(void *context, NvU32 command, void *data, NvU32 size)
{
    struct fake_session *session = context;
    nvidia_stack_t temporary_stack;
    assert(pm_depth == 0);
    pm_depth = 1;
    active_stack = &temporary_stack;
    NV_STATUS result = invoke(session->backend, active_stack,
        &controls[session->backend], &files[session->backend], command, data, size);
    active_stack = NULL;
    pm_depth = 0;
    return result;
}
#else
static NV_STATUS NV_API_CALL legacy(nvidia_stack_t *s, nv_state_t *n, nv_file_private_t *f,
                                   NvU32 c, void *d, NvU32 z) { return invoke(0,s,n,f,c,d,z); }
static NV_STATUS NV_API_CALL modern(nvidia_stack_t *s, nv_state_t *n, nv_file_private_t *f,
                                   NvU32 c, void *d, NvU32 z) { return invoke(1,s,n,f,c,d,z); }
#endif

int main(int argc, char **argv)
{
    assert(argc == 2);
    scenario = argv[1];
    controls[0].flags = controls[1].flags = NV_FLAG_CONTROL;
#if FIXTURE_SESSION
    for (unsigned i = 0; i < 2; ++i)
        endpoints[i] = (struct hybrid_rm_session_endpoint_v1){
            .abi_version = HYBRID_RM_SESSION_ABI_V1, .struct_size = sizeof(endpoints[i]),
            .invoke = session_invoke, .context = &sessions[i],
            .backend_identity = &backend_identity[i], .file_identity = &files[i]};
#else
    endpoints[0] = (struct hybrid_rm_endpoint){legacy, &stacks[0], &controls[0], &files[0]};
    endpoints[1] = (struct hybrid_rm_endpoint){modern, &stacks[1], &controls[1], &files[1]};
#endif
    request.hClass = !strcmp(scenario, "root-alias") ? NV01_ROOT : NV01_ROOT_CLIENT;
#if FIXTURE_ALLOC64
    if (!strcmp(scenario, "unsupported64")) {
        request.pRightsRequested = (NvP64)(NvUPtr)1;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.pRightsRequested = 0;
        request.flags = NVOS64_FLAGS_FINN_SERIALIZED;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.flags = 0x80000000U;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.flags = 2;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        assert(!calls[0] && !calls[1] && client.state == HYBRID_ROOT_EMPTY);
        assert(request.hObjectNew == 0);
        return 0;
    }
#endif
    if (!strcmp(scenario, "alias")) {
#if FIXTURE_SESSION
        endpoints[1].file_identity = endpoints[0].file_identity;
#else
        endpoints[1].file = endpoints[0].file;
#endif
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        assert(!calls[0] && !calls[1]);
        return 0;
    }
    if (!strcmp(scenario, "invalid-input")) {
        assert(root_alloc(NULL, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        assert(root_alloc(&client, NULL, &request) == NV_ERR_INVALID_ARGUMENT);
        assert(root_alloc(&client, endpoints, NULL) == NV_ERR_INVALID_ARGUMENT);
        assert(hybrid_root_free(NULL) == NV_ERR_INVALID_ARGUMENT);
        assert(hybrid_root_free(&client) == NV_ERR_INVALID_STATE);
        request.pAllocParms = (NvP64)(NvUPtr)1;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.pAllocParms = 0;
        request.paramsSize = 1;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.paramsSize = 0;
        request.hObjectParent = 1;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.hObjectParent = 0;
        request.hObjectNew = 1;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.hObjectNew = 0;
        request.hRoot = 1;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.hRoot = 0;
        request.hClass = 0xdead;
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        request.hClass = NV01_ROOT_CLIENT;
#if FIXTURE_SESSION
        endpoints[1].context = NULL;
#else
        controls[1].flags = 0;
#endif
        assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_ARGUMENT);
        assert(!calls[0] && !calls[1] && client.state == HYBRID_ROOT_EMPTY);
        return 0;
    }
#if FIXTURE_SESSION
    if (!strncmp(scenario, "session-invalid-", 16)) {
        const char *field = scenario + 16;
        if (!strcmp(field,"version")) endpoints[1].abi_version++;
        else if (!strcmp(field,"size")) endpoints[1].struct_size--;
        else if (!strcmp(field,"invoke")) endpoints[1].invoke=NULL;
        else if (!strcmp(field,"context")) endpoints[1].context=NULL;
        else if (!strcmp(field,"backend")) endpoints[1].backend_identity=NULL;
        else if (!strcmp(field,"file")) endpoints[1].file_identity=NULL;
        else if (!strcmp(field,"alias-context")) endpoints[1].context=endpoints[0].context;
        else if (!strcmp(field,"alias-backend")) endpoints[1].backend_identity=endpoints[0].backend_identity;
        else assert(!"unknown invalid-session fixture");
        assert(root_alloc(&client,endpoints,&request)==NV_ERR_INVALID_ARGUMENT);
        assert(request.status==NV_ERR_INVALID_ARGUMENT && !request.hObjectNew);
        assert(!calls[0] && !calls[1] && client.state==HYBRID_ROOT_EMPTY);
        return 0;
    }
#endif
    NV_STATUS status = root_alloc(&client, endpoints, &request);
    if (!strcmp(scenario, "success") || !strcmp(scenario, "root-alias") || !strcmp(scenario, "reentrant") ||
        !strcmp(scenario, "reuse") || !strcmp(scenario, "close-failure") ||
        !strcmp(scenario, "free-transport-error") || !strcmp(scenario, "free-missing-status")) {
        assert(status == NV_OK && request.status == NV_OK && request.hObjectNew == 0xc1000042U);
        assert(client.state == HYBRID_ROOT_ACTIVE && client.id == request.hObjectNew);
        assert(request.hClass == NV01_ROOT_CLIENT); /* observed ROOT alias normalization */
        root_parameters nested = {0};
        nested.hClass = NV01_ROOT_CLIENT;
        assert(root_alloc(&client, endpoints, &nested) == NV_ERR_INVALID_STATE);
        /* Caller mutation of its endpoint array must not redirect cleanup. */
#if FIXTURE_SESSION
        /* No raw stack/control/nvfp may be retained by the session route. */
        for (unsigned i = 0; i < 2; ++i) {
            assert(client.slot[i].endpoint.stack == NULL && client.slot[i].endpoint.control == NULL);
            assert(client.slot[i].endpoint.file == NULL && client.slot[i].endpoint.ioctl == NULL);
        }
        assert(pm_depth == 0 && active_stack == NULL);
        memset(endpoints, 0, sizeof(endpoints));
#else
        endpoints[0].file = NULL;
#endif
        NV_STATUS closed = hybrid_root_free(&client);
        assert(frees[0] == 1 && frees[1] == 1 && sequence[2] == 3 && sequence[3] == 2);
        if (!strcmp(scenario, "close-failure") || !strcmp(scenario, "free-transport-error") ||
            !strcmp(scenario, "free-missing-status")) {
            assert(closed != NV_OK && client.state == HYBRID_ROOT_QUARANTINED);
            assert(client.slot[1].handle && !client.slot[0].handle);
            assert(hybrid_root_free(&client) == NV_ERR_INVALID_STATE);
            assert(frees[1] == 1); /* never retry an ambiguous free */
        } else {
            assert(closed == NV_OK && client.state == HYBRID_ROOT_EMPTY && !client.id);
            if (!strcmp(scenario, "reuse")) {
#if FIXTURE_SESSION
                for (unsigned i = 0; i < 2; ++i)
                    endpoints[i] = client.slot[i].session;
#else
                endpoints[0].file = &files[0];
#endif
                request.hObjectNew = 0;
                assert(root_alloc(&client, endpoints, &request) == NV_OK);
                assert(hybrid_root_free(&client) == NV_OK);
            }
        }
    } else {
        assert(status != NV_OK && request.status != NV_OK && !request.hObjectNew);
        assert(!strcmp(scenario, "first-reject") || frees[0] == 1);
        if (!strcmp(scenario, "first-reject"))
            assert(!calls[1] && !frees[0] && !frees[1]);
        if (!strcmp(scenario, "mismatched-id"))
            assert(frees[1] == 1 && sequence[2] == 3 && sequence[3] == 2);
        else
            assert(!frees[1]);
        int quarantine = !strcmp(scenario, "first-reject") || !strcmp(scenario, "second-reject") ||
            !strcmp(scenario, "transport-error") || !strcmp(scenario, "ambiguous-output") ||
            !strcmp(scenario, "missing-status") || !strcmp(scenario, "zero-id") || !strcmp(scenario, "rollback-failure");
        assert(client.state == (quarantine ? HYBRID_ROOT_QUARANTINED : HYBRID_ROOT_EMPTY));
        if (quarantine) {
            assert(hybrid_root_free(&client) == NV_ERR_INVALID_STATE);
            request.hObjectNew = 0;
            assert(root_alloc(&client, endpoints, &request) == NV_ERR_INVALID_STATE);
        }
    }
    puts("fake-RM contract passed; no real RM executed");
    return 0;
}
