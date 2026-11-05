/* SPDX-License-Identifier: MIT
 * Test-only LD_PRELOAD shim for a single SYSTEM_GET_FEATURES CUDA process.
 * It rewrites only a successful, fixed-size root-global answer in process
 * memory. It never issues an ioctl of its own or changes kernel state.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unwind.h>
#include <unistd.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv-ioctl.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <ctrl/ctrl0000/ctrl0000system.h>
#include <ctrl/ctrl2080/ctrl2080gpu.h>

_Static_assert(sizeof(NVOS54_PARAMETERS) == 32, "NVOS54 ABI");
_Static_assert(sizeof(nv_ioctl_xfer_t) == 16, "NV_IOCTL_XFER ABI");
_Static_assert(sizeof(NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS) == 4,
               "SYSTEM_GET_FEATURES payload ABI");
_Static_assert(NV_IOCTL_MAGIC == 'F', "NVIDIA ioctl magic");
_Static_assert(NV_ESC_RM_CONTROL == 0x2a && NV_ESC_IOCTL_XFER_CMD == 211,
               "NVIDIA ioctl numbers");
_Static_assert(NV0000_CTRL_CMD_SYSTEM_GET_FEATURES == 0x1f0,
               "SYSTEM_GET_FEATURES command");

#define HYBRID_CALLER_CHAIN_MAX 24

struct caller_chain_capture {
    void *direct_address;
    const char *direct_image;
    uintptr_t offsets[HYBRID_CALLER_CHAIN_MAX];
    size_t count;
    int direct_seen;
    int truncated;
};

static __thread int caller_chain_active;

int hybrid_system_features_override_match(
    unsigned long request,
    void *argument,
    NvU32 replacement,
    NvU32 *kernel_value,
    const char **transport,
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS **payload)
{
    NVOS54_PARAMETERS *control = NULL;

    if (argument == NULL || kernel_value == NULL || transport == NULL ||
        payload == NULL || _IOC_TYPE(request) != NV_IOCTL_MAGIC ||
        _IOC_DIR(request) != (_IOC_READ | _IOC_WRITE))
        return 0;

    if (_IOC_NR(request) == NV_ESC_RM_CONTROL &&
        _IOC_SIZE(request) == sizeof(*control)) {
        control = argument;
        *transport = "direct";
    }
    else if (_IOC_NR(request) == NV_ESC_IOCTL_XFER_CMD &&
             _IOC_SIZE(request) == sizeof(nv_ioctl_xfer_t)) {
        nv_ioctl_xfer_t *xfer = argument;

        if (xfer->cmd != NV_ESC_RM_CONTROL ||
            xfer->size != sizeof(*control) || NvP64_VALUE(xfer->ptr) == NULL)
            return 0;
        control = (NVOS54_PARAMETERS *)NvP64_VALUE(xfer->ptr);
        *transport = "xfer";
    }
    else {
        return 0;
    }

    if (control == NULL || control->hClient == 0 ||
        control->hObject != control->hClient ||
        control->cmd != NV0000_CTRL_CMD_SYSTEM_GET_FEATURES ||
        control->flags != NVOS54_FLAGS_NONE || control->paramsSize != 4 ||
        control->status != NV_OK || NvP64_VALUE(control->params) == NULL)
        return 0;

    *payload = (NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *)
        NvP64_VALUE(control->params);
    *kernel_value = (*payload)->featuresMask;
    (*payload)->featuresMask = replacement;
    return 1;
}

static int read_override(NvU32 *value)
{
    const char *text = getenv("HYBRID_FEATURES_MASK_OVERRIDE");
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0')
        return 0;
    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX)
        return -1;
    *value = (NvU32)parsed;
    return 1;
}

static int caller_location(void *address, char *image, size_t image_size,
                           uintptr_t *offset)
{
    Dl_info information;
    const char *basename;
    const char *slash;
    size_t index;

    if (address == NULL || image == NULL || image_size < 2 || offset == NULL ||
        dladdr(address, &information) == 0 || information.dli_fname == NULL ||
        information.dli_fbase == NULL ||
        (uintptr_t)address < (uintptr_t)information.dli_fbase)
        return 0;

    slash = strrchr(information.dli_fname, '/');
    basename = slash == NULL ? information.dli_fname : slash + 1;
    for (index = 0; basename[index] != '\0' && index + 1 < image_size; ++index) {
        unsigned char value = (unsigned char)basename[index];
        image[index] = ((value >= 'a' && value <= 'z') ||
                        (value >= 'A' && value <= 'Z') ||
                        (value >= '0' && value <= '9') || value == '.' ||
                        value == '_' || value == '-' || value == '+') ?
            (char)value : '_';
    }
    if (index == 0)
        return 0;
    image[index] = '\0';
    *offset = (uintptr_t)address - (uintptr_t)information.dli_fbase;
    return 1;
}

static _Unwind_Reason_Code capture_caller_frame(
    struct _Unwind_Context *context, void *argument)
{
    struct caller_chain_capture *capture = argument;
    uintptr_t instruction = (uintptr_t)_Unwind_GetIP(context);
    char image[256];
    uintptr_t offset = 0;

    if (instruction == 0)
        return _URC_NO_REASON;
    if (!capture->direct_seen) {
        if ((void *)instruction == capture->direct_address)
            capture->direct_seen = 1;
        return _URC_NO_REASON;
    }
    if ((void *)instruction == capture->direct_address)
        return _URC_NO_REASON;
    if (!caller_location((void *)instruction, image, sizeof(image), &offset))
        return capture->count == 0 ? _URC_NO_REASON : _URC_END_OF_STACK;
    if (strcmp(image, capture->direct_image) != 0)
        return _URC_END_OF_STACK;
    if (capture->count == HYBRID_CALLER_CHAIN_MAX) {
        capture->truncated = 1;
        return _URC_END_OF_STACK;
    }
    capture->offsets[capture->count++] = offset;
    return _URC_NO_REASON;
}

static int capture_caller_chain(void *direct_address, const char *direct_image,
                                uintptr_t *offsets, size_t *count,
                                int *truncated)
{
    struct caller_chain_capture capture = {
        .direct_address = direct_address,
        .direct_image = direct_image,
    };

    if (direct_address == NULL || direct_image == NULL || offsets == NULL ||
        count == NULL || truncated == NULL || caller_chain_active)
        return 0;
    caller_chain_active = 1;
    (void)_Unwind_Backtrace(capture_caller_frame, &capture);
    caller_chain_active = 0;
    memcpy(offsets, capture.offsets, capture.count * sizeof(offsets[0]));
    *count = capture.count;
    *truncated = capture.truncated;
    return capture.direct_seen;
}

static int record_override(const char *transport, NvU32 kernel_value,
                           NvU32 exposed_value, void *caller_address)
{
    const char *path = getenv("HYBRID_FEATURES_TRACE_PATH");
    const char *capture_requested = getenv("HYBRID_FEATURES_CAPTURE_CALL_CHAIN");
    char line[1024];
    char caller_image[256] = "unresolved";
    char caller_offset_json[2 + sizeof(uintptr_t) * 2 + 3];
    char caller_chain_json[1024] = "[]";
    uintptr_t caller_chain_offsets[HYBRID_CALLER_CHAIN_MAX] = { 0 };
    size_t caller_chain_count = 0;
    struct stat info;
    uintptr_t caller_offset = 0;
    int fd;
    int length;
    ssize_t written;
    int caller_resolved;
    int caller_chain_truncated = 0;
    int caller_chain_anchor_found = 0;
    int capture_chain = capture_requested != NULL &&
                        strcmp(capture_requested, "1") == 0;
    size_t index;
    size_t chain_length = 0;

    if (path == NULL || path[0] == '\0')
        return -1;
    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0777) != 0600) {
        close(fd);
        return -1;
    }
    caller_resolved = caller_location(caller_address, caller_image,
                                      sizeof(caller_image), &caller_offset);
    if (caller_resolved) {
        int offset_length = snprintf(caller_offset_json, sizeof(caller_offset_json),
                                     "\"0x%llx\"",
                                     (unsigned long long)caller_offset);
        if (offset_length <= 0 ||
            (size_t)offset_length >= sizeof(caller_offset_json)) {
            close(fd);
            return -1;
        }
    }
    else {
        memcpy(caller_offset_json, "null", sizeof("null"));
    }
    if (capture_chain) {
        if (caller_resolved)
            caller_chain_anchor_found = capture_caller_chain(
                caller_address, caller_image, caller_chain_offsets,
                &caller_chain_count, &caller_chain_truncated);
        chain_length = (size_t)snprintf(caller_chain_json,
                                        sizeof(caller_chain_json), "[");
        if (chain_length >= sizeof(caller_chain_json)) {
            close(fd);
            return -1;
        }
        for (index = 0; index < caller_chain_count; ++index) {
            int part_length = snprintf(
                caller_chain_json + chain_length,
                sizeof(caller_chain_json) - chain_length,
                "%s\"0x%llx\"", index == 0 ? "" : ",",
                (unsigned long long)caller_chain_offsets[index]);
            if (part_length <= 0 ||
                (size_t)part_length >= sizeof(caller_chain_json) - chain_length) {
                close(fd);
                return -1;
            }
            chain_length += (size_t)part_length;
        }
        if (chain_length + 2 > sizeof(caller_chain_json)) {
            close(fd);
            return -1;
        }
        caller_chain_json[chain_length++] = ']';
        caller_chain_json[chain_length] = '\0';
        length = snprintf(line, sizeof(line),
                          "{\"transport\":\"%s\",\"kernel_mask\":%u,\"exposed_mask\":%u,\"caller_image\":\"%s\",\"caller_offset\":%s,\"caller_chain_offsets\":%s,\"caller_chain_anchor_found\":%s,\"caller_chain_truncated\":%s}\n",
                          transport, kernel_value, exposed_value, caller_image,
                          caller_offset_json, caller_chain_json,
                          caller_chain_anchor_found ? "true" : "false",
                          caller_chain_truncated ? "true" : "false");
    }
    else {
        length = snprintf(line, sizeof(line),
                          "{\"transport\":\"%s\",\"kernel_mask\":%u,\"exposed_mask\":%u,\"caller_image\":\"%s\",\"caller_offset\":%s}\n",
                          transport, kernel_value, exposed_value, caller_image,
                          caller_offset_json);
    }
    if (length <= 0 || (size_t)length >= sizeof(line)) {
        close(fd);
        return -1;
    }
    written = write(fd, line, (size_t)length);
    close(fd);
    return written == length ? 0 : -1;
}

static int name_string_control(unsigned long request, void *argument,
                               const char **transport,
                               NVOS54_PARAMETERS **control)
{
    const char *trace_path = getenv("HYBRID_GPU_NAME_CALLER_TRACE_PATH");
    nv_ioctl_xfer_t *xfer;

    if (trace_path == NULL || trace_path[0] == '\0' ||
        argument == NULL || transport == NULL || control == NULL ||
        _IOC_TYPE(request) != NV_IOCTL_MAGIC ||
        _IOC_DIR(request) != (_IOC_READ | _IOC_WRITE))
        return 0;

    if (_IOC_NR(request) == NV_ESC_RM_CONTROL &&
        _IOC_SIZE(request) == sizeof(**control)) {
        *transport = "direct";
        *control = argument;
    }
    else if (_IOC_NR(request) == NV_ESC_IOCTL_XFER_CMD &&
             _IOC_SIZE(request) == sizeof(*xfer)) {
        xfer = argument;
        if (xfer->cmd != NV_ESC_RM_CONTROL ||
            xfer->size != sizeof(**control) || NvP64_VALUE(xfer->ptr) == NULL)
            return 0;
        *transport = "xfer";
        *control = NvP64_VALUE(xfer->ptr);
    }
    else {
        return 0;
    }

    return *control != NULL &&
           (*control)->cmd == NV2080_CTRL_CMD_GPU_GET_NAME_STRING;
}

static int record_name_string_caller(const char *transport,
                                     const NVOS54_PARAMETERS *control,
                                     int ioctl_result, void *caller_address)
{
    const char *path = getenv("HYBRID_GPU_NAME_CALLER_TRACE_PATH");
    char caller_image[256] = "unresolved";
    char caller_offset_json[2 + sizeof(uintptr_t) * 2 + 3];
    char caller_chain_json[1024] = "[]";
    char line[2049];
    uintptr_t caller_chain_offsets[HYBRID_CALLER_CHAIN_MAX] = { 0 };
    size_t caller_chain_count = 0;
    struct stat info;
    uintptr_t caller_offset = 0;
    int caller_resolved;
    int caller_chain_truncated = 0;
    int caller_chain_anchor_found = 0;
    int fd;
    int length;
    ssize_t written;
    size_t chain_length;
    size_t index;

    if (path == NULL || path[0] == '\0' || control == NULL ||
        (strcmp(transport, "direct") != 0 && strcmp(transport, "xfer") != 0))
        return -1;
    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0777) != 0600) {
        close(fd);
        return -1;
    }

    caller_resolved = caller_location(caller_address, caller_image,
                                      sizeof(caller_image), &caller_offset);
    if (caller_resolved) {
        int offset_length = snprintf(caller_offset_json, sizeof(caller_offset_json),
                                     "\"0x%llx\"",
                                     (unsigned long long)caller_offset);
        if (offset_length <= 0 ||
            (size_t)offset_length >= sizeof(caller_offset_json)) {
            close(fd);
            return -1;
        }
        caller_chain_anchor_found = capture_caller_chain(
            caller_address, caller_image, caller_chain_offsets,
            &caller_chain_count, &caller_chain_truncated);
    }
    else {
        memcpy(caller_offset_json, "null", sizeof("null"));
    }

    chain_length = (size_t)snprintf(caller_chain_json,
                                    sizeof(caller_chain_json), "[");
    if (chain_length >= sizeof(caller_chain_json)) {
        close(fd);
        return -1;
    }
    for (index = 0; index < caller_chain_count; ++index) {
        int part_length = snprintf(caller_chain_json + chain_length,
                                   sizeof(caller_chain_json) - chain_length,
                                   "%s\"0x%llx\"", index == 0 ? "" : ",",
                                   (unsigned long long)caller_chain_offsets[index]);
        if (part_length <= 0 ||
            (size_t)part_length >= sizeof(caller_chain_json) - chain_length) {
            close(fd);
            return -1;
        }
        chain_length += (size_t)part_length;
    }
    if (chain_length + 2 > sizeof(caller_chain_json)) {
        close(fd);
        return -1;
    }
    caller_chain_json[chain_length++] = ']';
    caller_chain_json[chain_length] = '\0';

    length = snprintf(line, sizeof(line),
                      "{\"command\":\"0x%08x\",\"transport\":\"%s\","
                      "\"flags\":%u,\"params_size\":%u,\"ioctl_result\":%d,"
                      "\"embedded_status\":%u,\"caller_image\":\"%s\","
                      "\"caller_offset\":%s,\"caller_chain_offsets\":%s,"
                      "\"caller_chain_anchor_found\":%s,"
                      "\"caller_chain_truncated\":%s}\n",
                      control->cmd, transport, control->flags, control->paramsSize,
                      ioctl_result, control->status, caller_image,
                      caller_offset_json, caller_chain_json,
                      caller_chain_anchor_found ? "true" : "false",
                      caller_chain_truncated ? "true" : "false");
    if (length <= 0 || (size_t)length >= sizeof(line)) {
        close(fd);
        return -1;
    }
    written = write(fd, line, (size_t)length);
    close(fd);
    return written == length ? 0 : -1;
}

int ioctl(int fd, unsigned long request, ...)
{
    typedef int (*ioctl_function)(int, unsigned long, ...);
    ioctl_function real_ioctl = (ioctl_function)dlsym(RTLD_NEXT, "ioctl");
    void *argument;
    NvU32 replacement = 0;
    int override_state = 0;
    int result;
    int saved_errno;
    const char *name_transport = NULL;
    NVOS54_PARAMETERS *name_control = NULL;
    va_list arguments;
    int is_direct = (_IOC_TYPE(request) == NV_IOCTL_MAGIC &&
                     _IOC_DIR(request) == (_IOC_READ | _IOC_WRITE) &&
                     _IOC_NR(request) == NV_ESC_RM_CONTROL &&
                     _IOC_SIZE(request) == sizeof(NVOS54_PARAMETERS));
    int is_xfer = (_IOC_TYPE(request) == NV_IOCTL_MAGIC &&
                   _IOC_DIR(request) == (_IOC_READ | _IOC_WRITE) &&
                   _IOC_NR(request) == NV_ESC_IOCTL_XFER_CMD &&
                   _IOC_SIZE(request) == sizeof(nv_ioctl_xfer_t));
    void *caller_address = __builtin_return_address(0);

    if (is_direct || is_xfer)
        override_state = read_override(&replacement);
    if (real_ioctl == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if ((is_direct || is_xfer) && override_state < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Linux ioctl interposition must forward even legacy requests whose
     * argument is not encoded in the request number. */
    va_start(arguments, request);
    argument = va_arg(arguments, void *);
    va_end(arguments);
    result = real_ioctl(fd, request, argument);
    saved_errno = errno;
    if (result == 0 &&
        name_string_control(request, argument, &name_transport, &name_control))
        (void)record_name_string_caller(name_transport, name_control, result,
                                        caller_address);
    if (result == 0 && override_state > 0) {
        NvU32 kernel_value = 0;
        const char *transport = NULL;
        NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *payload = NULL;

        if (hybrid_system_features_override_match(
                request, argument, replacement, &kernel_value, &transport,
                &payload) &&
            record_override(transport, kernel_value, replacement,
                            caller_address) != 0)
            payload->featuresMask = kernel_value;
    }
    errno = saved_errno;
    return result;
}
