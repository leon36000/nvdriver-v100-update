/* SPDX-License-Identifier: MIT */
/*
 * Bounded, installed-driver RM probe for the NVOS64 root-ID mirror request.
 * It opens only /dev/nvidiactl and issues one RM_ALLOC plus one RM_FREE after
 * a confirmed allocation. It does not create a CUDA context or touch a GPU.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"

_Static_assert(sizeof(NVOS64_PARAMETERS) == 48, "NVOS64 size");
_Static_assert(offsetof(NVOS64_PARAMETERS, status) == 40, "NVOS64 status offset");
_Static_assert(sizeof(NVOS00_PARAMETERS) == 16, "NVOS00 size");
_Static_assert(offsetof(NVOS00_PARAMETERS, status) == 12, "NVOS00 status offset");
_Static_assert(NV_IOCTL_MAGIC == 'F', "ioctl magic");
_Static_assert(NV_ESC_RM_ALLOC == 0x2b && NV_ESC_RM_FREE == 0x29, "RM ioctl numbers");
_Static_assert(NV01_ROOT == 0 && NV01_ROOT_CLIENT == 0x41, "ROOT classes");

#define STATUS_UNWRITTEN ((NvV32)0xffffffffU)

struct call_result {
    bool attempted;
    int syscall_return;
    int error_number;
    NvV32 status;
    NvHandle root;
    NvHandle parent;
    NvHandle object;
    NvV32 class_id;
    bool passed;
};

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s --allocate-root | --mirror-root-id UINT32_NONZERO | --hold-root\n", program);
}

static bool wait_for_release(int timeout_ms, int *wait_error)
{
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        *wait_error = errno;
        return false;
    }

    char token[8] = {0};
    size_t length = 0;
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            *wait_error = errno;
            return false;
        }
        int64_t elapsed_ms = ((int64_t)now.tv_sec - (int64_t)start.tv_sec) * 1000 +
                             ((int64_t)now.tv_nsec - (int64_t)start.tv_nsec) / 1000000;
        int remaining_ms = timeout_ms - (int)elapsed_ms;
        if (remaining_ms <= 0) {
            *wait_error = ETIMEDOUT;
            return false;
        }

        struct pollfd descriptor = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
        int ready = poll(&descriptor, 1, remaining_ms);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            *wait_error = errno;
            return false;
        }
        if (ready == 0) {
            *wait_error = ETIMEDOUT;
            return false;
        }
        if (descriptor.revents & POLLNVAL) {
            *wait_error = EBADF;
            return false;
        }

        char byte;
        ssize_t count = read(STDIN_FILENO, &byte, 1);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            *wait_error = errno;
            return false;
        }
        if (count == 0) {
            *wait_error = EPIPE;
            return false;
        }
        if (length >= sizeof(token)) {
            *wait_error = EPROTO;
            return false;
        }
        token[length++] = byte;
        if (byte == '\n') {
            *wait_error = 0;
            return length == sizeof(token) && memcmp(token, "release\n", sizeof(token)) == 0;
        }
    }
}

static bool parse_id(const char *text, NvHandle *id)
{
    if (!text || !*text || !id)
        return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (!isdigit(*p))
            return false;
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !end || *end || value == 0 || value > UINT32_MAX)
        return false;
    *id = (NvHandle)value;
    return true;
}

static void emit_call(const struct call_result *r)
{
    printf("{\"attempted\":%s,\"syscall_return\":%d,\"errno\":%d,"
           "\"embedded_status\":%u,\"hRoot\":%u,\"hObjectParent\":%u,"
           "\"hObject\":%u,\"hClass\":%u,\"passed\":%s}",
           r->attempted ? "true" : "false", r->syscall_return, r->error_number,
           r->status, r->root, r->parent, r->object, r->class_id,
           r->passed ? "true" : "false");
}

int main(int argc, char **argv)
{
    bool mirror = false;
    bool hold = false;
    NvHandle requested_id = 0;
    if (argc == 2 && strcmp(argv[1], "--allocate-root") == 0) {
        mirror = false;
    } else if (argc == 3 && strcmp(argv[1], "--mirror-root-id") == 0 &&
               parse_id(argv[2], &requested_id)) {
        mirror = true;
    } else if (argc == 2 && strcmp(argv[1], "--hold-root") == 0) {
        hold = true;
    } else {
        usage(argv[0]);
        return 2;
    }

    struct call_result allocation = {0}, release = {0};
    NVOS64_PARAMETERS packet = {0};
    bool control_opened = false;
    bool control_closed = false;
    bool release_received = false;
    int close_error = 0;
    int wait_error = 0;
    packet.hRoot = requested_id;
    packet.hClass = mirror ? NV01_ROOT_CLIENT : NV01_ROOT;
    packet.flags = NVOS64_FLAGS_NONE;
    packet.status = STATUS_UNWRITTEN;

    int fd = open("/dev/nvidiactl", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        allocation.error_number = errno;
        goto report;
    }
    control_opened = true;
    struct stat st;
    int stat_result = fstat(fd, &st);
    if (stat_result != 0 || !S_ISCHR(st.st_mode)) {
        allocation.error_number = stat_result != 0 ? errno : ENODEV;
        control_closed = close(fd) == 0;
        close_error = control_closed ? 0 : errno;
        goto report;
    }

    allocation.attempted = true;
    allocation.syscall_return = ioctl(fd,
        _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, NVOS64_PARAMETERS), &packet);
    allocation.error_number = allocation.syscall_return < 0 ? errno : 0;
    allocation.status = packet.status;
    allocation.root = packet.hRoot;
    allocation.parent = packet.hObjectParent;
    allocation.object = packet.hObjectNew;
    allocation.class_id = packet.hClass;
    bool confirmed = allocation.syscall_return == 0 && allocation.status == NV_OK &&
                     allocation.object != 0;
    allocation.passed = confirmed && packet.hClass == NV01_ROOT_CLIENT &&
                        packet.hRoot == requested_id && packet.hObjectParent == 0 &&
                        packet.pAllocParms == 0 && packet.paramsSize == 0 &&
                        packet.pRightsRequested == 0 &&
                        packet.flags == NVOS64_FLAGS_NONE &&
                        (!mirror || packet.hObjectNew == requested_id);

    if (hold && allocation.passed) {
        printf("{\"schema\":\"nvidia-hybrid-rm-root-id-probe-v1\","
               "\"event\":\"root-held\",\"action\":\"hold-root\","
               "\"requested_id\":0,\"allocated_id\":%u,"
               "\"gpu_context_opened\":false}\n", allocation.object);
        fflush(stdout);
        release_received = wait_for_release(30000, &wait_error);
    }

    /* A known-success allocation is freed even if its output shape is wrong.
     * An error response or zero handle is ambiguous; do not guess a FREE ID. */
    if (confirmed) {
        NVOS00_PARAMETERS free_packet = {0};
        free_packet.hRoot = allocation.object;
        free_packet.hObjectParent = allocation.object;
        free_packet.hObjectOld = allocation.object;
        free_packet.status = STATUS_UNWRITTEN;
        release.attempted = true;
        release.syscall_return = ioctl(fd,
            _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_FREE, NVOS00_PARAMETERS), &free_packet);
        release.error_number = release.syscall_return < 0 ? errno : 0;
        release.status = free_packet.status;
        release.root = free_packet.hRoot;
        release.parent = free_packet.hObjectParent;
        release.object = free_packet.hObjectOld;
        release.passed = release.syscall_return == 0 && release.status == NV_OK &&
                         release.root == allocation.object &&
                         release.parent == allocation.object &&
                         release.object == allocation.object;
    }

    control_closed = close(fd) == 0;
    close_error = control_closed ? 0 : errno;
    bool success = allocation.passed && release.passed && control_closed &&
                   (!hold || release_received);
    printf("{\"schema\":\"nvidia-hybrid-rm-root-id-probe-v1\","
           "\"qualification\":\"%s\",\"action\":\"%s\",\"requested_id\":%u,"
           "\"request\":{\"layout\":\"NVOS64\",\"hRoot\":%u,\"hClass\":%u},"
           "\"allocation\":",
           success ? "root-allocation-and-free-passed" : "not-validated",
           hold ? "hold-root" : mirror ? "mirror-root-id" : "allocate-root", requested_id,
           requested_id, mirror ? NV01_ROOT_CLIENT : NV01_ROOT);
    emit_call(&allocation);
    printf(",\"allocated_id\":%u,\"returned_requested_id\":%s,\"free\":",
           confirmed ? allocation.object : 0,
           mirror && confirmed && allocation.object == requested_id ? "true" :
           mirror ? "false" : "null");
    emit_call(&release);
    printf(",\"control_opened\":%s,\"control_close_succeeded\":%s,"
           "\"control_close_errno\":%d,\"cleanup_passed\":%s,"
           "\"release_received\":%s,\"hold_wait_error\":%d,"
           "\"gpu_context_opened\":false,\"success\":%s}\n",
           control_opened ? "true" : "false", control_closed ? "true" : "false", close_error,
           release.passed && control_closed ? "true" : "false",
           hold ? (release_received ? "true" : "false") : "null", wait_error,
           success ? "true" : "false");
    return success ? 0 : 2;

report:
    printf("{\"schema\":\"nvidia-hybrid-rm-root-id-probe-v1\","
           "\"qualification\":\"not-validated\",\"action\":\"%s\","
           "\"requested_id\":%u,\"request\":{"
           "\"layout\":\"NVOS64\",\"hRoot\":%u,\"hClass\":%u},"
           "\"allocation\":",
           hold ? "hold-root" : mirror ? "mirror-root-id" : "allocate-root", requested_id,
           requested_id, mirror ? NV01_ROOT_CLIENT : NV01_ROOT);
    emit_call(&allocation);
    printf(",\"allocated_id\":0,\"returned_requested_id\":%s,\"free\":",
           mirror ? "false" : "null");
    emit_call(&release);
    printf(",\"control_opened\":%s,\"control_close_succeeded\":%s,"
           "\"control_close_errno\":%d,\"cleanup_passed\":false,"
           "\"gpu_context_opened\":false,\"success\":false}\n",
           control_opened ? "true" : "false", control_closed ? "true" : "false",
           close_error);
    return 2;
}
