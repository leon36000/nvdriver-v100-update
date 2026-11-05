/* SPDX-License-Identifier: MIT */
/* Synthetic ioctl traffic only; this fixture never opens a GPU device. */
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <class/cl503c.h>
#include <ctrl/ctrl503c.h>

typedef void (*reset_fn)(void);
typedef unsigned int (*count_fn)(void);
static int test_fd = -1;

#define TEST_SCALAR_IOCTL _IOW('x', 1, int)

static void fake_counters(reset_fn *reset, count_fn *allocations,
                          count_fn *controls, count_fn *frees)
{
    *reset = (reset_fn)dlsym(RTLD_DEFAULT, "fake_ioctl_reset");
    *allocations = (count_fn)dlsym(RTLD_DEFAULT, "fake_ioctl_allocations");
    *controls = (count_fn)dlsym(RTLD_DEFAULT, "fake_ioctl_controls");
    *frees = (count_fn)dlsym(RTLD_DEFAULT, "fake_ioctl_frees");
    assert(*reset != NULL && *allocations != NULL && *controls != NULL &&
           *frees != NULL);
    (*reset)();
}

static int allocate(unsigned int class_id, unsigned int flags,
                    NvHandle root, NvHandle *object)
{
    NV503C_ALLOC_PARAMETERS p2p = {.flags = flags};
    NVOS64_PARAMETERS packet = {
        .hRoot = root,
        .hObjectParent = 0x100U,
        .hClass = class_id,
        .pAllocParms = (NvP64)(uintptr_t)&p2p,
        .paramsSize = sizeof(p2p),
    };
    int result = ioctl(test_fd, _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC,
                                      NVOS64_PARAMETERS), &packet);
    if (result == 0)
        *object = packet.hObjectNew;
    return result;
}

static int control_sized(NvHandle root, NvHandle object, NvU32 command,
                         NvU32 params_size)
{
    unsigned char payload[sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS)] = {0};
    NVOS54_PARAMETERS packet = {
        .hClient = root,
        .hObject = object,
        .cmd = command,
        .params = (NvP64)(uintptr_t)payload,
        .paramsSize = params_size,
    };
    return ioctl(test_fd, _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                                NVOS54_PARAMETERS), &packet);
}

static NvU32 expected_control_size(NvU32 command)
{
    if (command == NV503C_CTRL_CMD_REGISTER_VA_SPACE)
        return sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS);
    if (command == NV503C_CTRL_CMD_REGISTER_VIDMEM)
        return sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS);
    return sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS);
}

static int control(NvHandle root, NvHandle object, NvU32 command)
{
    NvU32 size = command == NV503C_CTRL_CMD_REGISTER_PID
        ? sizeof(NV503C_CTRL_REGISTER_PID_PARAMS)
        : expected_control_size(command);
    return control_sized(root, object, command, size);
}

static NvU32 command_for_mode(const char *mode)
{
    if (strcmp(mode, "register-va") == 0)
        return NV503C_CTRL_CMD_REGISTER_VA_SPACE;
    if (strcmp(mode, "register-vidmem") == 0)
        return NV503C_CTRL_CMD_REGISTER_VIDMEM;
    if (strcmp(mode, "unregister-vidmem") == 0)
        return NV503C_CTRL_CMD_UNREGISTER_VIDMEM;
    return 0;
}

int main(int argc, char **argv)
{
    reset_fn reset;
    count_fn allocations;
    count_fn controls;
    count_fn frees;
    NvHandle object = 0;
    const char *mode;
    const char *test_device;

    assert(argc == 2);
    mode = argv[1];
    test_device = strcmp(mode, "control-fd-mismatch") == 0
        ? "/dev/zero" : "/dev/null";
    test_fd = open(test_device, O_RDONLY | O_CLOEXEC);
    assert(test_fd >= 0);
    fake_counters(&reset, &allocations, &controls, &frees);

    if (strcmp(mode, "non-nvidia-fd") == 0 ||
        strcmp(mode, "control-fd-mismatch") == 0) {
        assert(allocate(NV50_THIRD_PARTY_P2P,
                        NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,
                        0x41U, &object) == 0);
        assert(allocations() == 1 && controls() == 0 && frees() == 0);
        puts("non-NVIDIA descriptor forwarded");
        return 0;
    }

    if (strcmp(mode, "tracking-overflow") == 0) {
        NvHandle last_root = 0;
        unsigned int i;

        for (i = 0; i < 65; ++i) {
            last_root = 0x100U + i;
            assert(allocate(NV50_THIRD_PARTY_P2P,
                            NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,
                            last_root, &object) == 0);
        }
        assert(allocations() == 65);
        assert(control(last_root, object,
                       NV503C_CTRL_CMD_REGISTER_VA_SPACE) == 0);
        assert(controls() == 1);
        puts("overflow object was not faulted");
        return 0;
    }

    if (strcmp(mode, "abi-forwarding") == 0) {
        assert(ioctl(test_fd, FIOCLEX) == 0);
        assert(ioctl(test_fd, TEST_SCALAR_IOCTL, 7) == 0);
        puts("no-argument and scalar ioctls forwarded");
        return 0;
    }

    if (strcmp(mode, "abi-forwarding-scalar-cold") == 0) {
        assert(ioctl(test_fd, TEST_SCALAR_IOCTL, 7) == 0);
        assert(ioctl(test_fd, FIOCLEX) == 0);
        puts("cold scalar and no-argument ioctls forwarded");
        return 0;
    }

    if (strcmp(mode, "alloc") == 0) {
        errno = 0;
        assert(allocate(NV50_THIRD_PARTY_P2P,
                        NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,
                        0x41U, &object) == -1);
        assert(errno == EIO);
        assert(allocations() == 0);
        assert(allocate(NV50_THIRD_PARTY_P2P,
                        NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_NVLINK,
                        0x41U, &object) == 0);
        assert(allocations() == 1);
        assert(controls() == 0 && frees() == 0);
        puts("alloc-denied and non-BAR1 forwarded");
        return 0;
    }

    if (command_for_mode(mode) != 0) {
        assert(allocate(NV50_THIRD_PARTY_P2P,
                        NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1,
                        0x41U, &object) == 0);
        assert(object == 0x55aaU && allocations() == 1);

        errno = 0;
        assert(control(0x41U, object, command_for_mode(mode)) == -1);
        assert(errno == EIO);
        assert(control(0x41U, object + 1U,
                       command_for_mode(mode)) == 0);
        assert(control(0x42U, object,
                       command_for_mode(mode)) == 0);
        assert(control(0x41U, object, NV503C_CTRL_CMD_REGISTER_PID) == 0);
        assert(control_sized(0x41U, object,
                             command_for_mode(mode), 0) == 0);
        assert(controls() == 4);
        assert(frees() == 0);
        puts("control-denied only for tracked P2P object and selected method");
        return 0;
    }

    assert(allocate(NV50_THIRD_PARTY_P2P,
                    NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_NVLINK,
                    0x41U, &object) == 0);
    assert(allocations() == 1);
    assert(control(0x41U, object, NV503C_CTRL_CMD_REGISTER_VA_SPACE) == 0);
    assert(controls() == 1);
    errno = 0;
    assert(ioctl(test_fd, _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC,
                                NVOS64_PARAMETERS),
                 (void *)(uintptr_t)1) == -1);
    assert(errno == EFAULT);
    assert(frees() == 0);
    puts("unselected request forwarded");
    return 0;
}
