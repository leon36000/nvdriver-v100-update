/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t NvU32;
typedef uint32_t NvHandle;
typedef uint32_t NV_STATUS;

#define HYBRID580_BACKEND_LEGACY 0U
#define HYBRID580_BACKEND_OPEN 1U
#define HYBRID_ROOT_ACTIVE 1U
#define NV_OK 0
#define NVOS54_FLAGS_NONE 0U
#define NV_ERR_INVALID_ARGUMENT 0x56
#define NV_ERR_INVALID_OBJECT_HANDLE 0x57
#define NV_ERR_INVALID_STATE 0x58
#define NV2080_CTRL_CMD_GPU_GET_NAME_STRING 0x20800110U
#define NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII 0U
#define NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE 1U
#define NV20_SUBDEVICE_0 0x2080U
#define NV01_DEVICE_0 0x80U

typedef struct {
    NvU32 gpuNameStringFlags;
    union {
        uint8_t ascii[64];
        uint16_t unicode[64];
    } gpuNameString;
} NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS;

typedef struct {
    NvHandle handle;
} hybrid_front_root_slot;

typedef struct {
    unsigned int state;
    hybrid_front_root_slot slot[2];
} hybrid_front_root_state;

typedef struct hybrid_front_rm_object {
    NvHandle handle;
    NvHandle parent_handle;
    NvHandle backend_handle;
    NvHandle backend_parent_handle;
    NvU32 class_id;
    unsigned int backend;
} hybrid_front_rm_object;

typedef struct hybrid_front_root {
    hybrid_front_root_state root;
    hybrid_front_rm_object objects[4];
    size_t object_count;
} hybrid_front_root;

struct hybrid580_control_session {
    unsigned int backend;
};

struct hybrid_front_file {
    struct hybrid580_control_session *sessions[2];
    bool quarantined;
};

typedef struct {
    NvHandle hClient;
    NvHandle hObject;
    NvU32 cmd;
    NvU32 flags;
    void *params;
    NvU32 paramsSize;
    NvU32 status;
} NVOS54_PARAMETERS;

static hybrid_front_root *test_root;
static unsigned int calls[2];
static NvHandle seen_root[2];
static NvHandle seen_subdevice[2];

static bool hybrid_front_file_is_quarantined(struct hybrid_front_file *state)
{
    return state->quarantined;
}

static hybrid_front_root *hybrid_front_find_root(
    struct hybrid_front_file *state, NvHandle client)
{
    (void)state;
    if (test_root->root.slot[HYBRID580_BACKEND_LEGACY].handle != client)
        return NULL;
    return test_root;
}

static hybrid_front_rm_object *hybrid_front_find_object(
    hybrid_front_root *root, NvHandle handle)
{
    size_t i;
    for (i = 0; i < root->object_count; ++i) {
        if (root->objects[i].handle == handle)
            return &root->objects[i];
    }
    return NULL;
}

static NV_STATUS test_gpu_name_string(
    struct hybrid580_control_session *session, NvHandle root,
    NvHandle subdevice, NvU32 flags,
    NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *params,
    NvU32 *control_status)
{
    unsigned int backend = session->backend;
    assert(backend <= HYBRID580_BACKEND_OPEN);
    ++calls[backend];
    seen_root[backend] = root;
    seen_subdevice[backend] = subdevice;
    assert(flags == 0);
    assert(params->gpuNameStringFlags ==
           NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII ||
           params->gpuNameStringFlags ==
           NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE);
    memset(&params->gpuNameString, 0, sizeof(params->gpuNameString));
    if (backend == HYBRID580_BACKEND_LEGACY)
        memcpy(params->gpuNameString.ascii, "Tesla V100", sizeof("Tesla V100"));
    else
        memcpy(params->gpuNameString.ascii, "RTX 5080", sizeof("RTX 5080"));
    *control_status = NV_OK;
    return NV_OK;
}

#define hybrid580_legacy_control_session_gpu_name_string_v1 \
    test_gpu_name_string
#define hybrid580_open_control_session_gpu_name_string_v1 \
    test_gpu_name_string

/* INSERT_EXACT_PRODUCTION_RESOLVER */

static void reset_calls(void)
{
    memset(calls, 0, sizeof(calls));
    memset(seen_root, 0, sizeof(seen_root));
    memset(seen_subdevice, 0, sizeof(seen_subdevice));
}

int main(void)
{
    struct hybrid_front_file state = {0};
    struct hybrid580_control_session legacy = {HYBRID580_BACKEND_LEGACY};
    struct hybrid580_control_session open = {HYBRID580_BACKEND_OPEN};
    hybrid_front_root root = {0};
    NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS params = {0};
    NVOS54_PARAMETERS control = {
        .hClient = 0x44,
        .hObject = 0x101,
        .cmd = NV2080_CTRL_CMD_GPU_GET_NAME_STRING,
        .flags = 0,
        .params = &params,
        .paramsSize = sizeof(params),
        .status = 0xffffffffU,
    };
    long rc;

    root.root.state = HYBRID_ROOT_ACTIVE;
    root.root.slot[HYBRID580_BACKEND_LEGACY].handle = 0x44;
    root.root.slot[HYBRID580_BACKEND_OPEN].handle = 0x44;
    root.object_count = 4;
    root.objects[0] = (hybrid_front_rm_object) {
        .handle = 0x301, .backend_handle = 0x11,
        .class_id = NV01_DEVICE_0, .backend = HYBRID580_BACKEND_LEGACY,
    };
    root.objects[1] = (hybrid_front_rm_object) {
        .handle = 0x101, .parent_handle = 0x301, .backend_handle = 0x21,
        .backend_parent_handle = 0x11, .class_id = NV20_SUBDEVICE_0,
        .backend = HYBRID580_BACKEND_LEGACY,
    };
    root.objects[2] = (hybrid_front_rm_object) {
        .handle = 0x302, .backend_handle = 0x12,
        .class_id = NV01_DEVICE_0, .backend = HYBRID580_BACKEND_OPEN,
    };
    root.objects[3] = (hybrid_front_rm_object) {
        .handle = 0x102, .parent_handle = 0x302, .backend_handle = 0x22,
        .backend_parent_handle = 0x12, .class_id = NV20_SUBDEVICE_0,
        .backend = HYBRID580_BACKEND_OPEN,
    };
    test_root = &root;
    state.sessions[HYBRID580_BACKEND_LEGACY] = &legacy;
    state.sessions[HYBRID580_BACKEND_OPEN] = &open;

    params.gpuNameStringFlags = NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII;
    rc = hybrid_front_gpu_name_string(&state, &control, &params);
    assert(rc == 0 && control.status == NV_OK);
    assert(calls[HYBRID580_BACKEND_LEGACY] == 1 &&
           calls[HYBRID580_BACKEND_OPEN] == 0);
    assert(seen_root[HYBRID580_BACKEND_LEGACY] == 0x44 &&
           seen_subdevice[HYBRID580_BACKEND_LEGACY] == 0x21);
    assert(strcmp((const char *)params.gpuNameString.ascii, "Tesla V100") == 0);

    reset_calls();
    control.hObject = 0x102;
    params.gpuNameStringFlags = NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_UNICODE;
    rc = hybrid_front_gpu_name_string(&state, &control, &params);
    assert(rc == 0 && control.status == NV_OK);
    assert(calls[HYBRID580_BACKEND_LEGACY] == 0 &&
           calls[HYBRID580_BACKEND_OPEN] == 1);
    assert(seen_root[HYBRID580_BACKEND_OPEN] == 0x44 &&
           seen_subdevice[HYBRID580_BACKEND_OPEN] == 0x22);

    reset_calls();
    params.gpuNameStringFlags = 2;
    rc = hybrid_front_gpu_name_string(&state, &control, &params);
    assert(rc != 0 && control.status == NV_ERR_INVALID_ARGUMENT);
    assert(calls[0] == 0 && calls[1] == 0);

    params.gpuNameStringFlags = NV2080_CTRL_GPU_GET_NAME_STRING_FLAGS_TYPE_ASCII;
    root.objects[3].backend_parent_handle ^= 1U;
    rc = hybrid_front_gpu_name_string(&state, &control, &params);
    assert(rc != 0 && control.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(calls[0] == 0 && calls[1] == 0);

    state.quarantined = true;
    root.objects[3].backend_parent_handle = 0x12;
    rc = hybrid_front_gpu_name_string(&state, &control, &params);
    assert(rc != 0 && control.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(calls[0] == 0 && calls[1] == 0);

    puts("GPU name-string owner-routing tests passed");
    return 0;
}
