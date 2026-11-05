/* SPDX-License-Identifier: MIT
 * Test double at the kernel ioctl boundary; no GPU or driver is accessed.
 */
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv-ioctl.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <ctrl/ctrl0000/ctrl0000system.h>
#include <ctrl/ctrl2080/ctrl2080gpu.h>

int ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    void *argument;
    NVOS54_PARAMETERS *control = NULL;

    (void)fd;
    if (request == 0x1234UL) {
        errno = EDOM;
        return 0;
    }
    if (request == 0x1235UL) {
        void *legacy_argument;
        va_start(arguments, request);
        legacy_argument = va_arg(arguments, void *);
        va_end(arguments);
        if (legacy_argument != (void *)(uintptr_t)0x12345678U) {
            errno = EFAULT;
            return -1;
        }
        errno = ERANGE;
        return 0;
    }
    if (_IOC_TYPE(request) != NV_IOCTL_MAGIC ||
        _IOC_DIR(request) != (_IOC_READ | _IOC_WRITE)) {
        errno = ENOTTY;
        return -1;
    }
    va_start(arguments, request);
    argument = va_arg(arguments, void *);
    va_end(arguments);

    if (_IOC_NR(request) == NV_ESC_RM_CONTROL &&
        _IOC_SIZE(request) == sizeof(*control)) {
        control = argument;
    }
    else if (_IOC_NR(request) == NV_ESC_IOCTL_XFER_CMD &&
             _IOC_SIZE(request) == sizeof(nv_ioctl_xfer_t)) {
        nv_ioctl_xfer_t *xfer = argument;
        if (xfer->cmd == NV_ESC_RM_CONTROL &&
            xfer->size == sizeof(*control))
            control = NvP64_VALUE(xfer->ptr);
    }
    if (control == NULL || control->flags != NVOS54_FLAGS_NONE ||
        NvP64_VALUE(control->params) == NULL) {
        errno = ENOTTY;
        return -1;
    }
    if (control->cmd == NV0000_CTRL_CMD_SYSTEM_GET_FEATURES &&
        control->paramsSize == sizeof(NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS)) {
        ((NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *)
            NvP64_VALUE(control->params))->featuresMask = 9U;
    }
    else if (control->cmd == NV2080_CTRL_CMD_GPU_GET_NAME_STRING &&
             control->paramsSize == sizeof(NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS)) {
        /* The fake RM returns only a successful status; payload bytes stay untouched. */
    }
    else {
        errno = ENOTTY;
        return -1;
    }
    control->status = NV_OK;
    errno = EBUSY;
    return 0;
}
