/* SPDX-License-Identifier: MIT
 * Exercise the preload ioctl hook against the controlled fake ioctl below.
 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv-ioctl.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <ctrl/ctrl0000/ctrl0000system.h>
#include <ctrl/ctrl2080/ctrl2080gpu.h>

__attribute__((noinline)) static int nested_ioctl(int fd, unsigned long request,
                                                  void *argument)
{
    return ioctl(fd, request, argument);
}

int main(int argc, char **argv)
{
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params = { .featuresMask = 0 };
    NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS name_params = { 0 };
    NVOS54_PARAMETERS control = { 0 };
    nv_ioctl_xfer_t xfer = { 0 };
    unsigned long request;
    void *argument;

    assert(argc == 2);
    control.hClient = 0x100U;
    control.hObject = 0x100U;
    control.cmd = NV0000_CTRL_CMD_SYSTEM_GET_FEATURES;
    control.flags = NVOS54_FLAGS_NONE;
    control.params = NV_PTR_TO_NvP64(&params);
    control.paramsSize = sizeof(params);
    if (strcmp(argv[1], "direct") == 0 ||
        strcmp(argv[1], "nested-direct") == 0) {
        request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                        NVOS54_PARAMETERS);
        argument = &control;
    }
    else if (strcmp(argv[1], "xfer") == 0) {
        xfer.cmd = NV_ESC_RM_CONTROL;
        xfer.size = sizeof(control);
        xfer.ptr = NV_PTR_TO_NvP64(&control);
        request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD,
                        nv_ioctl_xfer_t);
        argument = &xfer;
    }
    else {
        return 2;
    }

    errno = 0;
    assert((strcmp(argv[1], "nested-direct") == 0 ?
            nested_ioctl(3, request, argument) : ioctl(3, request, argument)) == 0);
    assert(params.featuresMask == 8U);
    assert(control.status == NV_OK);
    assert(errno == EBUSY);

    control.cmd = NV2080_CTRL_CMD_GPU_GET_NAME_STRING;
    control.params = NV_PTR_TO_NvP64(&name_params);
    control.paramsSize = sizeof(name_params);
    control.status = 0xffffffffU;
    if (strcmp(argv[1], "xfer") == 0) {
        xfer.cmd = NV_ESC_RM_CONTROL;
        xfer.size = sizeof(control);
        xfer.ptr = NV_PTR_TO_NvP64(&control);
        request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD,
                        nv_ioctl_xfer_t);
        argument = &xfer;
    }
    else {
        request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                        NVOS54_PARAMETERS);
        argument = &control;
    }
    errno = 0;
    assert(nested_ioctl(3, request, argument) == 0);
    assert(control.status == NV_OK);
    assert(errno == EBUSY);

    errno = 0;
    assert(ioctl(3, 0x1234UL) == 0);
    assert(errno == EDOM);
    errno = 0;
    assert(ioctl(3, 0x1235UL, (void *)(uintptr_t)0x12345678U) == 0);
    assert(errno == ERANGE);
    puts("runtime feature-mask override: OK");
    return 0;
}
