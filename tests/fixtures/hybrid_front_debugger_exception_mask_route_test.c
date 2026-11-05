/* SPDX-License-Identifier: MIT */
/* Host fixture: production frontend code is inserted by its Python test. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

typedef uint32_t NvU32;
typedef uint32_t NvHandle;
typedef uintptr_t NvP64;
typedef int NV_STATUS;

#define __user
#define NvP64_VALUE(value) ((void *)(uintptr_t)(value))
#define NvP64_NULL ((NvP64)0)
#define NV_IOCTL_MAGIC 'F'
#define NV_IOCTL_BASE 200U
#define NV_ESC_RM_CONTROL 0x2aU
#define NV_ESC_IOCTL_XFER_CMD (NV_IOCTL_BASE + 11U)
#define NVOS54_FLAGS_NONE 0U
#define NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK 0x83de0309U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_FATAL 0x01U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_TRAP 0x02U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_SINGLE_STEP 0x04U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_INT 0x08U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_CILP 0x10U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PREEMPTION_STARTED 0x20U
#define NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL 0xffffU

#define NV0000_CTRL_CMD_SYSTEM_GET_FEATURES 0x00000001U
#define NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS 0x00000002U
#define NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO 0x00000003U
#define NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION 0x00000004U
#define NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 0x00000005U
#define NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS 0x00000006U
#define NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS 0x00000007U
#define NV0000_CTRL_CMD_GPU_GET_PROBED_IDS 0x00000008U
#define NV2080_CTRL_CMD_GR_GET_TPC_MASK 0x00000009U
#define NV90E6_CTRL_CMD_MASTER_GET_ERROR_INTR_OFFSET_MASK 0x0000000aU
#define NV2080_CTRL_CMD_GPU_GET_NAME_STRING 0x0000000bU
#define NV503C_CTRL_CMD_REGISTER_VA_SPACE 0x0000000cU
#define NV503C_CTRL_CMD_UNREGISTER_VA_SPACE 0x0000000dU
#define NV503C_CTRL_CMD_REGISTER_VIDMEM 0x0000000eU
#define NV503C_CTRL_CMD_UNREGISTER_VIDMEM 0x0000000fU
#define NV503C_CTRL_CMD_REGISTER_PID 0x00000010U

enum {
    NV_OK = 0,
    NV_ERR_INVALID_ARGUMENT = 1,
    NV_ERR_INVALID_OBJECT_HANDLE = 2,
    NV_ERR_INVALID_STATE = 3,
    NV_ERR_NOT_SUPPORTED = 4,
    NV_ERR_TEST_TRANSPORT = 5,
};

enum {
    HYBRID580_BACKEND_LEGACY = 0,
    HYBRID580_BACKEND_OPEN = 1,
};

enum {
    HYBRID_ROOT_EMPTY = 0,
    HYBRID_ROOT_ACTIVE = 2,
};

enum {
    NV01_DEVICE_0 = 0x80U,
    NV20_SUBDEVICE_0 = 0x200U,
    VOLTA_COMPUTE_A = 0xc3c0U,
    BLACKWELL_COMPUTE_B = 0xcec0U,
    GT200_DEBUGGER = 0x83deU,
};

typedef struct {
    NvU32 exceptionMask;
} NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS;

typedef struct {
    NvHandle hClient;
    NvHandle hObject;
    NvU32 cmd;
    NvU32 flags;
    NvP64 params;
    NvU32 paramsSize;
    NvU32 status;
} NVOS54_PARAMETERS;

typedef struct {
    NvU32 cmd;
    NvU32 size;
    NvP64 ptr;
} nv_ioctl_xfer_t;

struct mutex { int held; };
struct hybrid580_control_session { unsigned int identity; };

struct hybrid_root_slot { NvHandle handle; };
struct hybrid_root_client {
    int state;
    NvHandle id;
    struct hybrid_root_slot slot[2];
};

struct hybrid_front_rm_object {
    struct hybrid_front_rm_object *next;
    NvHandle handle;
    NvHandle parent_handle;
    NvHandle backend_handle;
    NvHandle backend_parent_handle;
    NvHandle debuggee_handle;
    NvU32 class_id;
    unsigned int backend;
};

struct hybrid_front_root {
    struct hybrid_front_root *next;
    struct hybrid_root_client root;
    struct hybrid_front_rm_object *objects;
    unsigned int object_count;
};

struct hybrid_front_file {
    struct mutex transaction_lock;
    struct hybrid_front_root *roots;
    struct hybrid580_control_session *sessions[2];
    struct { int counter; } quarantine_pending;
    bool quarantined;
};

struct provider_record {
    unsigned int calls;
    struct hybrid580_control_session *session;
    NvHandle client;
    NvHandle debugger;
    NvU32 mask;
    NV_STATUS transport;
    NvU32 rm_status;
};

static struct provider_record legacy_record;
static struct provider_record open_record;

#define atomic_read(value) ((value)->counter)

static int mutex_lock_interruptible(struct mutex *lock)
{
    assert(lock != NULL && lock->held == 0);
    lock->held = 1;
    return 0;
}

static void mutex_unlock(struct mutex *lock)
{
    assert(lock != NULL && lock->held == 1);
    lock->held = 0;
}

static unsigned long copy_from_user(void *destination, const void *source,
                                   size_t size)
{
    if (destination == NULL || source == NULL)
        return size;
    memcpy(destination, source, size);
    return 0;
}

static unsigned long copy_to_user(void *destination, const void *source,
                                 size_t size)
{
    if (destination == NULL || source == NULL)
        return size;
    memcpy(destination, source, size);
    return 0;
}

static NV_STATUS fake_provider(struct provider_record *record,
                               struct hybrid580_control_session *session,
                               NvHandle client, NvHandle debugger,
                               NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,
                               NvU32 *control_status)
{
    ++record->calls;
    record->session = session;
    record->client = client;
    record->debugger = debugger;
    record->mask = params->exceptionMask;
    if (record->transport == NV_OK)
        *control_status = record->rm_status;
    return record->transport;
}

NV_STATUS hybrid580_legacy_control_session_debugger_exception_mask_v1(
    struct hybrid580_control_session *session, NvHandle client,
    NvHandle debugger, NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,
    NvU32 *control_status)
{
    return fake_provider(&legacy_record, session, client, debugger, params,
                         control_status);
}

NV_STATUS hybrid580_open_control_session_debugger_exception_mask_v1(
    struct hybrid580_control_session *session, NvHandle client,
    NvHandle debugger, NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,
    NvU32 *control_status)
{
    return fake_provider(&open_record, session, client, debugger, params,
                         control_status);
}

#define UNEXPECTED_CONTROL_HANDLER(name) \
    long name(struct hybrid_front_file *state, unsigned int command, \
              unsigned long argument) \
    { \
        (void)state; (void)command; (void)argument; \
        assert(!"unrelated RM control reached by debugger-route fixture"); \
        return -ENOTTY; \
    }

UNEXPECTED_CONTROL_HANDLER(hybrid_front_system_features_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_fabric_status_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_sync_boost_groups_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_client_share_policy_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_build_version_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_gpu_id_info_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_attached_ids_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_device_ids_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_probed_ids_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_gr_tpc_mask_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_master_error_intr_offset_mask_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_gpu_name_string_ioctl)
UNEXPECTED_CONTROL_HANDLER(hybrid_front_p2p_control_ioctl)

static long hybrid_front_debugger_exception_mask_ioctl(
    struct hybrid_front_file *state, unsigned int command,
    unsigned long argument);
static struct hybrid_front_rm_object *hybrid_front_gpu_ancestor(
    struct hybrid_front_root *root, struct hybrid_front_rm_object *object);

__PRODUCTION_FUNCTIONS__

static void clear_records(void)
{
    memset(&legacy_record, 0, sizeof(legacy_record));
    memset(&open_record, 0, sizeof(open_record));
    legacy_record.transport = NV_OK;
    open_record.transport = NV_OK;
}

static void link_object(struct hybrid_front_root *root,
                        struct hybrid_front_rm_object *object)
{
    object->next = root->objects;
    root->objects = object;
    ++root->object_count;
}

struct fixture {
    struct hybrid_front_file file;
    struct hybrid_front_root root;
    struct hybrid580_control_session legacy_session;
    struct hybrid580_control_session open_session;
    struct hybrid_front_rm_object legacy_compute;
    struct hybrid_front_rm_object legacy_debugger;
    struct hybrid_front_rm_object blackwell_compute;
    struct hybrid_front_rm_object blackwell_debugger;
};

static void fixture_init(struct fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    clear_records();

    fixture->file.sessions[HYBRID580_BACKEND_LEGACY] =
        &fixture->legacy_session;
    fixture->file.sessions[HYBRID580_BACKEND_OPEN] = &fixture->open_session;

    fixture->root.root.state = HYBRID_ROOT_ACTIVE;
    fixture->root.root.id = 0x51U;
    /* The root broker mirrors the numeric root handle across isolated RMs. */
    fixture->root.root.slot[HYBRID580_BACKEND_LEGACY].handle = 0x51U;
    fixture->root.root.slot[HYBRID580_BACKEND_OPEN].handle = 0x51U;
    fixture->file.roots = &fixture->root;

    fixture->legacy_compute = (struct hybrid_front_rm_object){
        .handle = 0x101U, .parent_handle = 0x51U,
        .backend_handle = 0x801U, .backend_parent_handle = 0x51U,
        .class_id = VOLTA_COMPUTE_A,
        .backend = HYBRID580_BACKEND_LEGACY,
    };
    fixture->legacy_debugger = (struct hybrid_front_rm_object){
        .handle = 0x102U, .parent_handle = 0x101U,
        .backend_handle = 0x901U, .backend_parent_handle = 0x801U,
        .debuggee_handle = 0x101U, .class_id = GT200_DEBUGGER,
        .backend = HYBRID580_BACKEND_LEGACY,
    };
    fixture->blackwell_compute = (struct hybrid_front_rm_object){
        .handle = 0x201U, .parent_handle = 0x51U,
        .backend_handle = 0x802U, .backend_parent_handle = 0x51U,
        .class_id = BLACKWELL_COMPUTE_B,
        .backend = HYBRID580_BACKEND_OPEN,
    };
    fixture->blackwell_debugger = (struct hybrid_front_rm_object){
        .handle = 0x202U, .parent_handle = 0x201U,
        .backend_handle = 0x902U, .backend_parent_handle = 0x802U,
        .debuggee_handle = 0x201U, .class_id = GT200_DEBUGGER,
        .backend = HYBRID580_BACKEND_OPEN,
    };

    link_object(&fixture->root, &fixture->legacy_compute);
    link_object(&fixture->root, &fixture->legacy_debugger);
    link_object(&fixture->root, &fixture->blackwell_compute);
    link_object(&fixture->root, &fixture->blackwell_debugger);
}

static long issue_control(struct fixture *fixture, NvHandle client,
                          NvHandle object, NvU32 command, NvU32 flags,
                          NvU32 params_size, NvU32 mask,
                          NVOS54_PARAMETERS *returned_control)
{
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS params = {
        .exceptionMask = mask,
    };
    NVOS54_PARAMETERS control = {
        .hClient = client,
        .hObject = object,
        .cmd = command,
        .flags = flags,
        .params = (NvP64)(uintptr_t)&params,
        .paramsSize = params_size,
        .status = 0xffffffffU,
    };
    long rc = hybrid_front_rm_control_ioctl(
        &fixture->file,
        _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL, NVOS54_PARAMETERS),
        (unsigned long)(uintptr_t)&control);

    if (returned_control != NULL)
        *returned_control = control;
    return rc;
}

static long issue_xfer_control(struct fixture *fixture, NvHandle client,
                               NvHandle object, NvU32 xfer_command,
                               NvU32 xfer_size, bool null_control,
                               NVOS54_PARAMETERS *returned_control)
{
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS params = {
        .exceptionMask = 0x3aU,
    };
    NVOS54_PARAMETERS control = {
        .hClient = client,
        .hObject = object,
        .cmd = NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK,
        .flags = NVOS54_FLAGS_NONE,
        .params = (NvP64)(uintptr_t)&params,
        .paramsSize = sizeof(params),
        .status = 0xffffffffU,
    };
    nv_ioctl_xfer_t xfer = {
        .cmd = xfer_command,
        .size = xfer_size,
        .ptr = null_control ? NvP64_NULL : (NvP64)(uintptr_t)&control,
    };
    unsigned int ioctl_command =
        _IOWR(NV_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD, nv_ioctl_xfer_t);
    long rc = hybrid_front_rm_control_ioctl(
        &fixture->file, ioctl_command, (unsigned long)(uintptr_t)&xfer);

    if (returned_control != NULL)
        *returned_control = control;
    return rc;
}

static void assert_only_legacy_received(struct fixture *fixture)
{
    assert(legacy_record.calls == 1U);
    assert(open_record.calls == 0U);
    assert(legacy_record.session == &fixture->legacy_session);
    assert(legacy_record.client == 0x51U);
    assert(legacy_record.debugger == 0x901U);
    assert(legacy_record.mask == 0x3aU);
}

void assert_only_open_received(struct fixture *fixture)
{
    assert(open_record.calls == 1U);
    assert(legacy_record.calls == 0U);
    assert(open_record.session == &fixture->open_session);
    assert(open_record.client == 0x51U);
    assert(open_record.debugger == 0x902U);
    assert(open_record.mask == 0x3aU);
}

static void test_valid_provider_routes(void)
{
    struct fixture fixture;
    NVOS54_PARAMETERS returned;
    long rc;

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK,
                       NVOS54_FLAGS_NONE,
                       sizeof(NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS),
                       0x3aU, &returned);
    assert(rc == 0 && returned.status == NV_OK);
    assert_only_legacy_received(&fixture);

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0x202U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK,
                       NVOS54_FLAGS_NONE,
                       sizeof(NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS),
                       0x3aU, &returned);
#if defined(HYBRID580_UVM_ABI_R580)
    assert(rc == -EINVAL && returned.status == NV_ERR_NOT_SUPPORTED);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);
#else
    assert(rc == 0 && returned.status == NV_OK);
    assert_only_open_received(&fixture);
#endif
}

static void test_wrapped_xfer_routes_and_rejects_malformed_envelopes(void)
{
    struct fixture fixture;
    NVOS54_PARAMETERS returned;
    long rc;

    fixture_init(&fixture);
    rc = issue_xfer_control(&fixture, 0x51U, 0x102U,
                            NV_ESC_RM_CONTROL, sizeof(NVOS54_PARAMETERS),
                            false, &returned);
    assert(rc == 0 && returned.status == NV_OK);
    assert_only_legacy_received(&fixture);

    fixture_init(&fixture);
    rc = issue_xfer_control(&fixture, 0x51U, 0x202U,
                            NV_ESC_RM_CONTROL, sizeof(NVOS54_PARAMETERS),
                            false, &returned);
#if defined(HYBRID580_UVM_ABI_R580)
    assert(rc == -EINVAL && returned.status == NV_ERR_NOT_SUPPORTED);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);
#else
    assert(rc == 0 && returned.status == NV_OK);
    assert_only_open_received(&fixture);
#endif

    fixture_init(&fixture);
    rc = issue_xfer_control(&fixture, 0x51U, 0x102U,
                            NV_ESC_RM_CONTROL + 1U,
                            sizeof(NVOS54_PARAMETERS), false, &returned);
    assert(rc == -ENOTTY);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_xfer_control(&fixture, 0x51U, 0x102U,
                            NV_ESC_RM_CONTROL,
                            sizeof(NVOS54_PARAMETERS) - 4U,
                            false, &returned);
    assert(rc == -EINVAL);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_xfer_control(&fixture, 0x51U, 0x102U,
                            NV_ESC_RM_CONTROL,
                            sizeof(NVOS54_PARAMETERS), true, &returned);
    assert(rc == -EFAULT);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);
}

static void test_invalid_owner_target_and_controls_fail_closed(void)
{
    struct fixture fixture;
    NVOS54_PARAMETERS returned;
    long rc;

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x99U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0xdeadU,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0x101U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    fixture.legacy_debugger.backend = HYBRID580_BACKEND_OPEN;
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    fixture.legacy_debugger.backend = 2U;
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    fixture.blackwell_debugger.backend_parent_handle = 0x7ffU;
    rc = issue_control(&fixture, 0x51U, 0x202U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK + 1U, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -ENOTTY);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 1U, 4U,
                       0x3aU, &returned);
    assert(rc == -ENOTTY);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x40U, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_ARGUMENT);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);
}

static void test_missing_owner_session_and_quarantine_fail_closed(void)
{
    struct fixture fixture;
    NVOS54_PARAMETERS returned;
    long rc;

    fixture_init(&fixture);
    fixture.file.sessions[HYBRID580_BACKEND_OPEN] = NULL;
    rc = issue_control(&fixture, 0x51U, 0x202U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_STATE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    fixture.file.quarantined = true;
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EIO && returned.status == NV_ERR_INVALID_STATE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);

    fixture_init(&fixture);
    fixture.root.root.state = HYBRID_ROOT_EMPTY;
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(rc == -EINVAL && returned.status == NV_ERR_INVALID_OBJECT_HANDLE);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);
}

static void test_transport_failure_never_tries_other_provider(void)
{
    struct fixture fixture;
    NVOS54_PARAMETERS returned;
    long rc;

    fixture_init(&fixture);
#if defined(HYBRID580_UVM_ABI_R580)
    legacy_record.transport = NV_ERR_TEST_TRANSPORT;
    rc = issue_control(&fixture, 0x51U, 0x102U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(legacy_record.calls == 1U && open_record.calls == 0U);
#else
    open_record.transport = NV_ERR_TEST_TRANSPORT;
    rc = issue_control(&fixture, 0x51U, 0x202U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
    assert(open_record.calls == 1U && legacy_record.calls == 0U);
#endif
    assert(rc == -EINVAL && returned.status == NV_ERR_TEST_TRANSPORT);
}

static void test_rm_status_failure_is_returned_without_cross_provider_retry(void)
{
    struct fixture fixture;
    NVOS54_PARAMETERS returned;
    long rc;

    fixture_init(&fixture);
    open_record.rm_status = NV_ERR_TEST_TRANSPORT;
    rc = issue_control(&fixture, 0x51U, 0x202U,
                       NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK, 0U, 4U,
                       0x3aU, &returned);
#if defined(HYBRID580_UVM_ABI_R580)
    assert(rc == -EINVAL && returned.status == NV_ERR_NOT_SUPPORTED);
    assert(legacy_record.calls == 0U && open_record.calls == 0U);
#else
    /* RM error is the NVOS54 status; successful transport retains ioctl rc 0. */
    assert(rc == 0 && returned.status == NV_ERR_TEST_TRANSPORT);
    assert(open_record.calls == 1U && legacy_record.calls == 0U);
#endif
}

int main(void)
{
    test_valid_provider_routes();
    test_wrapped_xfer_routes_and_rejects_malformed_envelopes();
    test_invalid_owner_target_and_controls_fail_closed();
    test_missing_owner_session_and_quarantine_fail_closed();
    test_transport_failure_never_tries_other_provider();
    test_rm_status_failure_is_returned_without_cross_provider_retry();
    puts("production frontend debugger route passed");
    return 0;
}
