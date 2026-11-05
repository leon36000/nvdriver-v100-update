/* SPDX-License-Identifier: MIT */
/*
 * Process-local A/B fault injector for a stock-driver V100 CUDA probe.
 * It denies every exact match in one selected NV503C BAR1 allocation/control
 * operation family in the current process. It does not install, load, or
 * modify a kernel driver.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <class/cl503c.h>
#include <ctrl/ctrl503c.h>

#if !defined(__x86_64__)
#error "The V100 guest A/B runner currently targets Linux x86_64 only"
#endif

_Static_assert(sizeof(NVOS64_PARAMETERS) == 48, "pinned R580 NVOS64 ABI");
_Static_assert(sizeof(NVOS00_PARAMETERS) == 16, "pinned R580 NVOS00 ABI");
_Static_assert(sizeof(NVOS54_PARAMETERS) == 32, "pinned R580 NVOS54 ABI");
_Static_assert(sizeof(NV503C_ALLOC_PARAMETERS) == 4, "NV503C allocation ABI");
_Static_assert(NV50_THIRD_PARTY_P2P == 0x503c, "NV503C object class");
_Static_assert(NV503C_CTRL_CMD_REGISTER_VA_SPACE == 0x503c0102,
               "NV503C register VA-space command");
_Static_assert(NV503C_CTRL_CMD_REGISTER_VIDMEM == 0x503c0104,
               "NV503C register vidmem command");
_Static_assert(NV503C_CTRL_CMD_UNREGISTER_VIDMEM == 0x503c0105,
               "NV503C unregister vidmem command");
_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, NVOS64_PARAMETERS) ==
               0xc030462b, "pinned RM_ALLOC ioctl");
_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL, NVOS54_PARAMETERS) ==
               0xc020462a, "pinned RM_CONTROL ioctl");
_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_FREE, NVOS00_PARAMETERS) ==
               0xc0104629, "pinned RM_FREE ioctl");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) == 16,
               "NV503C VA-space control ABI");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS) == 32,
               "NV503C register-vidmem control ABI");
_Static_assert(sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS) == 4,
               "NV503C unregister-vidmem control ABI");

#define MAX_TRACKED_P2P_OBJECTS 64

#ifndef NV_RM_CONTROL_DEVICE
#define NV_RM_CONTROL_DEVICE "/dev/nvidiactl"
#endif

struct tracked_object {
    NvHandle root;
    NvHandle object;
};

static struct tracked_object tracked[MAX_TRACKED_P2P_OBJECTS];
static pthread_mutex_t tracked_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rm_transaction_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t ioctl_once = PTHREAD_ONCE_INIT;
static pthread_once_t control_device_once = PTHREAD_ONCE_INIT;
static int (*next_ioctl)(int, unsigned long, ...);
_Atomic uintptr_t hybrid_rm_next_ioctl_address
    __attribute__((visibility("hidden")));
static dev_t control_device_rdev;
static int control_device_available;

uintptr_t hybrid_rm_resolve_next_ioctl(void)
    __attribute__((visibility("hidden")));
int hybrid_rm_target_ioctl_dispatch(int fd, unsigned long request,
                                    unsigned long raw_argument)
    __attribute__((visibility("hidden")));

static const unsigned long alloc_request =
    _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC, NVOS64_PARAMETERS);
static const unsigned long free_request =
    _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_FREE, NVOS00_PARAMETERS);
static const unsigned long control_request =
    _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL, NVOS54_PARAMETERS);

enum fault_mode {
    FAULT_NONE,
    FAULT_ALLOC,
    FAULT_REGISTER_VA,
    FAULT_REGISTER_VIDMEM,
    FAULT_UNREGISTER_VIDMEM,
};

static void resolve_next_ioctl(void)
{
    void *symbol = dlsym(RTLD_NEXT, "ioctl");

    memcpy(&next_ioctl, &symbol, sizeof(next_ioctl));
    atomic_store_explicit(&hybrid_rm_next_ioctl_address,
                          (uintptr_t)symbol, memory_order_release);
}

static void resolve_control_device(void)
{
    struct stat info;

    if (stat(NV_RM_CONTROL_DEVICE, &info) == 0 && S_ISCHR(info.st_mode)) {
        control_device_rdev = info.st_rdev;
        control_device_available = 1;
    }
}

static int is_control_device_fd(int fd)
{
    struct stat info;

    (void)pthread_once(&control_device_once, resolve_control_device);
    return control_device_available && fstat(fd, &info) == 0 &&
           S_ISCHR(info.st_mode) && info.st_rdev == control_device_rdev;
}

static int safe_read_process(void *destination, const void *source, size_t length)
{
    struct iovec local = {.iov_base = destination, .iov_len = length};
    struct iovec remote = {.iov_base = (void *)source, .iov_len = length};
    ssize_t copied = (ssize_t)syscall(SYS_process_vm_readv, getpid(),
                                      &local, 1, &remote, 1, 0);

    return copied == (ssize_t)length ? 0 : -1;
}

static enum fault_mode selected_mode(void)
{
    const char *value = getenv("HYBRID_RM_P2P_FAULT");

    if (value == NULL)
        return FAULT_NONE;
    if (strcmp(value, "alloc") == 0)
        return FAULT_ALLOC;
    if (strcmp(value, "register-va") == 0)
        return FAULT_REGISTER_VA;
    if (strcmp(value, "register-vidmem") == 0)
        return FAULT_REGISTER_VIDMEM;
    if (strcmp(value, "unregister-vidmem") == 0)
        return FAULT_UNREGISTER_VIDMEM;
    return FAULT_NONE;
}

enum track_result {
    TRACK_INVALID,
    TRACK_ALREADY_PRESENT,
    TRACK_ADDED,
    TRACK_TABLE_FULL,
};

static enum track_result track_object(NvHandle root, NvHandle object)
{
    size_t i;
    size_t empty = MAX_TRACKED_P2P_OBJECTS;

    if (root == 0 || object == 0)
        return TRACK_INVALID;
    pthread_mutex_lock(&tracked_lock);
    for (i = 0; i < MAX_TRACKED_P2P_OBJECTS; ++i) {
        if (tracked[i].root == root && tracked[i].object == object) {
            pthread_mutex_unlock(&tracked_lock);
            return TRACK_ALREADY_PRESENT;
        }
        if (empty == MAX_TRACKED_P2P_OBJECTS && tracked[i].object == 0)
            empty = i;
    }
    if (empty < MAX_TRACKED_P2P_OBJECTS) {
        tracked[empty].root = root;
        tracked[empty].object = object;
        pthread_mutex_unlock(&tracked_lock);
        return TRACK_ADDED;
    }
    pthread_mutex_unlock(&tracked_lock);
    return TRACK_TABLE_FULL;
}

static void untrack_object(NvHandle root, NvHandle object)
{
    size_t i;

    pthread_mutex_lock(&tracked_lock);
    for (i = 0; i < MAX_TRACKED_P2P_OBJECTS; ++i) {
        if (tracked[i].root == root && tracked[i].object == object) {
            tracked[i].root = 0;
            tracked[i].object = 0;
            break;
        }
    }
    pthread_mutex_unlock(&tracked_lock);
}

static int is_tracked_object(NvHandle root, NvHandle object)
{
    size_t i;
    int found = 0;

    pthread_mutex_lock(&tracked_lock);
    for (i = 0; i < MAX_TRACKED_P2P_OBJECTS; ++i) {
        if (tracked[i].root == root && tracked[i].object == object) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&tracked_lock);
    return found;
}

static const char *mode_name(enum fault_mode mode)
{
    switch (mode) {
    case FAULT_ALLOC: return "alloc";
    case FAULT_REGISTER_VA: return "register-va";
    case FAULT_REGISTER_VIDMEM: return "register-vidmem";
    case FAULT_UNREGISTER_VIDMEM: return "unregister-vidmem";
    case FAULT_NONE: break;
    }
    return "none";
}

static int deny_selected(enum fault_mode mode)
{
    static const char prefix[] = "HYBRID_RM_P2P_FAULT denied=";
    static const char suffix[] = " errno=EIO\n";
    char message[sizeof(prefix) + sizeof("unregister-vidmem") + sizeof(suffix)];
    size_t prefix_length = sizeof(prefix) - 1;
    size_t name_length = strlen(mode_name(mode));
    size_t suffix_length = sizeof(suffix) - 1;

    memcpy(message, prefix, prefix_length);
    memcpy(message + prefix_length, mode_name(mode), name_length);
    memcpy(message + prefix_length + name_length, suffix, suffix_length);
    (void)syscall(SYS_write, STDERR_FILENO, message,
                  prefix_length + name_length + suffix_length);
    errno = EIO;
    return -1;
}

static void report_tracking_overflow(void)
{
    static const char message[] = "HYBRID_RM_P2P_FAULT tracking-overflow\n";

    (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1);
}

static size_t selected_control_size(enum fault_mode mode, NvU32 command)
{
    switch (mode) {
    case FAULT_REGISTER_VA:
        return command == NV503C_CTRL_CMD_REGISTER_VA_SPACE
            ? sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) : 0;
    case FAULT_REGISTER_VIDMEM:
        return command == NV503C_CTRL_CMD_REGISTER_VIDMEM
            ? sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS) : 0;
    case FAULT_UNREGISTER_VIDMEM:
        return command == NV503C_CTRL_CMD_UNREGISTER_VIDMEM
            ? sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS) : 0;
    case FAULT_ALLOC:
    case FAULT_NONE:
        return 0;
    }
    return 0;
}

uintptr_t hybrid_rm_resolve_next_ioctl(void)
{
    (void)pthread_once(&ioctl_once, resolve_next_ioctl);
    if (next_ioctl == NULL) {
        errno = ENOSYS;
        return (uintptr_t)0;
    }
    return atomic_load_explicit(&hybrid_rm_next_ioctl_address,
                                memory_order_acquire);
}

int hybrid_rm_target_ioctl_dispatch(int fd, unsigned long request,
                                    unsigned long raw_argument)
{
    void *argument = (void *)(uintptr_t)raw_argument;
    enum fault_mode mode = selected_mode();
    int result;

    (void)pthread_once(&ioctl_once, resolve_next_ioctl);
    if (next_ioctl == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if ((request != alloc_request && request != control_request &&
         request != free_request) || !is_control_device_fd(fd))
        return next_ioctl(fd, request, argument);

    if (request == alloc_request && argument != NULL) {
        NVOS64_PARAMETERS allocation;

        if (safe_read_process(&allocation, argument, sizeof(allocation)) == 0 &&
            allocation.hClass == NV50_THIRD_PARTY_P2P &&
            allocation.paramsSize == sizeof(NV503C_ALLOC_PARAMETERS) &&
            allocation.pAllocParms != 0) {
            NV503C_ALLOC_PARAMETERS parameters;

            if (safe_read_process(&parameters,
                    (const void *)(uintptr_t)allocation.pAllocParms,
                    sizeof(parameters)) != 0)
                return next_ioctl(fd, request, argument);
            if (parameters.flags == NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1) {
                if (mode == FAULT_ALLOC)
                    return deny_selected(mode);
                if (mode == FAULT_REGISTER_VA ||
                    mode == FAULT_REGISTER_VIDMEM ||
                    mode == FAULT_UNREGISTER_VIDMEM) {
                    enum track_result tracking;

                    pthread_mutex_lock(&rm_transaction_lock);
                    result = next_ioctl(fd, request, argument);
                    if (result == 0 &&
                        safe_read_process(&allocation, argument,
                                          sizeof(allocation)) == 0 &&
                        allocation.status == 0) {
                        tracking = track_object(allocation.hRoot,
                                                allocation.hObjectNew);
                        if (tracking == TRACK_TABLE_FULL)
                            report_tracking_overflow();
                    }
                    pthread_mutex_unlock(&rm_transaction_lock);
                    return result;
                }
            }
            result = next_ioctl(fd, request, argument);
            return result;
        }
    }

    if (request == control_request && argument != NULL) {
        NVOS54_PARAMETERS control;

        if (safe_read_process(&control, argument, sizeof(control)) == 0) {
            size_t payload_size = selected_control_size(mode, control.cmd);

            if (payload_size != 0 && control.paramsSize == payload_size &&
                control.params != 0) {
                unsigned char payload[sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS)];

                if (safe_read_process(payload,
                        (const void *)(uintptr_t)control.params, payload_size) == 0) {
                    int result;

                    pthread_mutex_lock(&rm_transaction_lock);
                    if (is_tracked_object(control.hClient, control.hObject)) {
                        result = deny_selected(mode);
                    } else {
                        result = next_ioctl(fd, request, argument);
                    }
                    pthread_mutex_unlock(&rm_transaction_lock);
                    return result;
                }
            }
        }
        return next_ioctl(fd, request, argument);
    }

    if (request == free_request && argument != NULL) {
        NVOS00_PARAMETERS free_parameters;

        if (mode == FAULT_REGISTER_VA || mode == FAULT_REGISTER_VIDMEM ||
            mode == FAULT_UNREGISTER_VIDMEM) {
            pthread_mutex_lock(&rm_transaction_lock);
            result = next_ioctl(fd, request, argument);
            if (result == 0 &&
                safe_read_process(&free_parameters, argument,
                                  sizeof(free_parameters)) == 0 &&
                free_parameters.status == 0)
                untrack_object(free_parameters.hRoot,
                               free_parameters.hObjectOld);
            pthread_mutex_unlock(&rm_transaction_lock);
        } else {
            result = next_ioctl(fd, request, argument);
        }
        return result;
    }

    return next_ioctl(fd, request, argument);
}
