/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
static long harness_ptrace(enum __ptrace_request request, ...)
{
    long word = 0;
    if (request != PTRACE_PEEKDATA) {
        errno = EINVAL;
        return -1;
    }
    va_list arguments;
    va_start(arguments, request);
    (void)va_arg(arguments, pid_t);
    void *address = va_arg(arguments, void *);
    va_end(arguments);
    memcpy(&word, address, sizeof(word));
    return word;
}
#define ptrace harness_ptrace
#define main rm_ioctl_observer_program_main
#include "../../src/rm_ioctl_observer.c"
#undef main
#undef ptrace

#include <stdio.h>

enum {
    TEST_ROOT_A = 0x1001,
    TEST_ROOT_B = 0x2002,
    TEST_DEBUGGER_HANDLE = 0x3003,
};

static int check(int condition, int failure_code)
{
    return condition ? 0 : failure_code;
}

int main(void)
{
    struct channel_handle_class_ref class_ref;
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS mask_payload = {
        .exceptionMask = NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_FATAL |
                         NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_TRAP,
    };
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS other_payload = {
        .exceptionMask = NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_INT,
    };
    NVOS54_PARAMETERS control = {0};
    struct record observed_control = {0};
    struct rm_control_info control_info = {0};
    int status;

    if (rm_handle_registry_insert(&handle_registry, TEST_ROOT_A, TEST_ROOT_A,
                                  0, NV01_ROOT_CLIENT) != 0 ||
        rm_handle_registry_insert(&handle_registry, TEST_ROOT_B, TEST_ROOT_B,
                                  0, NV01_ROOT_CLIENT) != 0 ||
        rm_handle_registry_insert(&handle_registry, TEST_ROOT_A,
                                  TEST_DEBUGGER_HANDLE, TEST_ROOT_A,
                                  GT200_DEBUGGER) != 0)
        return 10;

    records[0].is_debugger_alloc = 1;
    records[0].returned = 1;
    records[0].result = 0;
    records[0].has_exit = 1;
    records[0].exit.root = TEST_ROOT_A;
    records[0].exit.object = TEST_DEBUGGER_HANDLE;
    records[0].exit.klass = GT200_DEBUGGER;
    records[0].exit.status = NV_OK;
    nrecords = 1;

    status = check(matches_prior_debugger_allocation(TEST_ROOT_A,
                                                      TEST_DEBUGGER_HANDLE), 1);
    if (status)
        return status;
    class_ref = debugger_control_object_class(TEST_ROOT_A,
                                              TEST_DEBUGGER_HANDLE);
    status = check(class_ref.resolution == RM_HANDLE_RESOLVED &&
                   class_ref.class_id == GT200_DEBUGGER, 2);
    if (status)
        return status;

    status = check(!matches_prior_debugger_allocation(TEST_ROOT_B,
                                                       TEST_DEBUGGER_HANDLE), 3);
    if (status)
        return status;
    class_ref = debugger_control_object_class(TEST_ROOT_B,
                                              TEST_DEBUGGER_HANDLE);
    status = check(class_ref.resolution == RM_HANDLE_NOT_OBSERVED, 4);
    if (status)
        return status;

    if (rm_handle_registry_remove(&handle_registry, TEST_ROOT_A,
                                  TEST_DEBUGGER_HANDLE) != 1)
        return 5;
    status = check(matches_prior_debugger_allocation(TEST_ROOT_A,
                                                      TEST_DEBUGGER_HANDLE), 6);
    if (status)
        return status;
    class_ref = debugger_control_object_class(TEST_ROOT_A,
                                              TEST_DEBUGGER_HANDLE);
    status = check(class_ref.resolution == RM_HANDLE_NOT_OBSERVED, 7);
    if (status)
        return status;

    records[0].result = -1;
    status = check(!matches_prior_debugger_allocation(TEST_ROOT_A,
                                                       TEST_DEBUGGER_HANDLE), 8);
    if (status)
        return status;

    /* Exercise the observer's real allocation update path. RM allocators may
     * supply hObjectNew=0 and receive the root client handle only on exit. */
    memset(&handle_registry, 0, sizeof(handle_registry));
    memset(records, 0, sizeof(records));
    nrecords = 0;
    capture_debugger_lifecycle = 1;
    records[nrecords] = (struct record){
        .is_alloc = 1,
        .has_entry = 1,
        .returned = 1,
        .has_exit = 1,
        .result = 0,
        .entry = {
            .layout = 64,
            .root = 0,
            .parent = 0,
            .object = 0,
            .klass = NV01_ROOT,
        },
        .exit = {
            .layout = 64,
            .root = 0,
            .parent = 0,
            .object = 0x4004,
            .klass = NV01_ROOT_CLIENT,
            .status = NV_OK,
        },
    };
    update_handle_registry(&records[nrecords]);
    ++nrecords;
    records[nrecords] = (struct record){
        .is_alloc = 1,
        .is_debugger_alloc = 1,
        .has_entry = 1,
        .returned = 1,
        .has_exit = 1,
        .result = 0,
        .entry = {
            .layout = 64,
            .root = 0x4004,
            .parent = 0x4004,
            .object = 0x5005,
            .klass = GT200_DEBUGGER,
        },
        .exit = {
            .layout = 64,
            .root = 0x4004,
            .parent = 0x4004,
            .object = 0x5005,
            .klass = GT200_DEBUGGER,
            .status = NV_OK,
        },
    };
    update_handle_registry(&records[nrecords]);
    ++nrecords;
    status = check(matches_prior_debugger_allocation(0x4004, 0x5005), 9);
    if (status)
        return status;
    class_ref = debugger_control_object_class(0x4004, 0x5005);
    status = check(class_ref.resolution == RM_HANDLE_RESOLVED &&
                   class_ref.class_id == GT200_DEBUGGER, 10);
    if (status)
        return status;

    /* Exercise the real fixed-payload parser through a bounded local ptrace
     * memory shim. No device or ioctl is opened by this harness. */
    control.hClient = 0x4004;
    control.hObject = 0x5005;
    control.cmd = NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK;
    control.flags = NVOS54_FLAGS_NONE;
    control.paramsSize = sizeof(mask_payload);
    control.params = &mask_payload;
    control.status = NV_OK;
    observed_control.is_debugger_control = 1;
    observed_control.request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                                     NVOS54_PARAMETERS);
    observed_control.packet_address = (uint64_t)(uintptr_t)&control;
    observed_control.params_address = (uint64_t)(uintptr_t)&mask_payload;
    observed_control.rm_command = control.cmd;
    observed_control.rm_flags = control.flags;
    observed_control.rm_params_size = control.paramsSize;
    observed_control.client_handle = control.hClient;
    observed_control.object_handle = control.hObject;
    int header_status = snapshot_rm_control_header(getpid(), &observed_control,
                                                    &control_info, 0);
    if (header_status) {
        fprintf(stderr, "entry-header-failed request=%llx nr=%u size=%u params=%u\n",
                (unsigned long long)observed_control.request,
                (unsigned)_IOC_NR(observed_control.request),
                (unsigned)_IOC_SIZE(observed_control.request),
                control_info.params_size);
        return 11;
    }
    if (snapshot_debugger_exception_mask_payload(getpid(), &observed_control,
                                                  &control_info, 0) ||
        !control_info.debugger_exception_mask_payload_valid ||
        control_info.debugger_exception_mask != mask_payload.exceptionMask) {
        fprintf(stderr, "entry-mask-failed error=%s size=%u mask=%u valid=%d\n",
                failure, control_info.params_size,
                control_info.debugger_exception_mask,
                control_info.debugger_exception_mask_payload_valid);
        return 11;
    }
    observed_control.rm_control_entry = control_info;

    /* The NVOS54 params pointer must remain stable across the syscall. */
    control.params = &other_payload;
    memset(&control_info, 0, sizeof(control_info));
    if (!snapshot_rm_control_header(getpid(), &observed_control,
                                    &control_info, 1))
        return 12;
    control.params = &mask_payload;
    memset(&control_info, 0, sizeof(control_info));
    if (snapshot_rm_control_header(getpid(), &observed_control,
                                   &control_info, 1) ||
        snapshot_debugger_exception_mask_payload(getpid(), &observed_control,
                                                  &control_info, 1) ||
        !control_info.debugger_exception_mask_user_buffer_entry_exit_compared ||
        !control_info.debugger_exception_mask_user_buffer_entry_exit_equal)
        return 13;

    mask_payload.exceptionMask = 0x3f;
    memset(&control_info, 0, sizeof(control_info));
    if (snapshot_rm_control_header(getpid(), &observed_control,
                                   &control_info, 0) ||
        snapshot_debugger_exception_mask_payload(getpid(), &observed_control,
                                                  &control_info, 0) ||
        control_info.debugger_exception_mask != 0x3f)
        return 14;

    mask_payload.exceptionMask = NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL;
    memset(&control_info, 0, sizeof(control_info));
    if (snapshot_rm_control_header(getpid(), &observed_control,
                                   &control_info, 0) ||
        snapshot_debugger_exception_mask_payload(getpid(), &observed_control,
                                                  &control_info, 0) ||
        control_info.debugger_exception_mask !=
            NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL)
        return 15;

    failure[0] = '\0';
    mask_payload.exceptionMask = 0x40;
    memset(&control_info, 0, sizeof(control_info));
    if (snapshot_rm_control_header(getpid(), &observed_control,
                                   &control_info, 0) ||
        !snapshot_debugger_exception_mask_payload(getpid(), &observed_control,
                                                   &control_info, 0) ||
        !strstr(failure, "undocumented bits"))
        return 16;

    failure[0] = '\0';
    struct record malformed_control = observed_control;
    memset(&control_info, 0, sizeof(control_info));
    control_info.command = NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK;
    control_info.params_size = sizeof(mask_payload);
    malformed_control.params_address = 0;
    if (!snapshot_debugger_exception_mask_payload(getpid(), &malformed_control,
                                                   &control_info, 0) ||
        !strstr(failure, "invalid GT200_DEBUGGER exception-mask control shape"))
        return 17;

    failure[0] = '\0';
    malformed_control = observed_control;
    control_info.params_size = sizeof(mask_payload) - 1;
    if (!snapshot_debugger_exception_mask_payload(getpid(), &malformed_control,
                                                   &control_info, 0) ||
        !strstr(failure, "invalid GT200_DEBUGGER exception-mask control shape"))
        return 18;

    failure[0] = '\0';
    observed_control.is_debugger_control = 0;
    observed_control.params_address = 1;
    memset(&control_info, 0, sizeof(control_info));
    control_info.command = NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK;
    control_info.params_size = sizeof(mask_payload);
    if (snapshot_debugger_exception_mask_payload(getpid(), &observed_control,
                                                  &control_info, 0) ||
        failure[0] || debugger_exception_mask_payload_snapshots_read != 4)
        return 19;

    puts("root-scoped-live-allocation-handle-relation-and-exception-mask-pass");
    return 0;
}
