/* SPDX-License-Identifier: MIT */
/* Synthetic downstream ioctl implementation for the process-local shim test. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <class/cl503c.h>

static unsigned int allocations;
static unsigned int controls;
static unsigned int frees;

#define TEST_SCALAR_IOCTL _IOW('x', 1, int)

void fake_ioctl_reset(void)
{
    allocations = 0;
    controls = 0;
    frees = 0;
}

unsigned int fake_ioctl_allocations(void) { return allocations; }
unsigned int fake_ioctl_controls(void) { return controls; }
unsigned int fake_ioctl_frees(void) { return frees; }

int ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    void *argument;

    (void)fd;

    if (request == FIOCLEX)
        return 0;
    if (request == TEST_SCALAR_IOCTL) {
        int scalar;

        va_start(arguments, request);
        scalar = va_arg(arguments, int);
        va_end(arguments);
        if (scalar != 7U) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    va_start(arguments, request);
    argument = va_arg(arguments, void *);
    va_end(arguments);

    if (argument == (void *)(uintptr_t)1) {
        errno = EFAULT;
        return -1;
    }

    if (request == _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_ALLOC,
                         NVOS64_PARAMETERS)) {
        NVOS64_PARAMETERS *allocation = argument;
        ++allocations;
        allocation->hObjectNew = allocation->hClass == NV50_THIRD_PARTY_P2P
            ? 0x55aaU : 0x1234U;
        allocation->status = 0;
        return 0;
    }
    if (request == _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                         NVOS54_PARAMETERS)) {
        ++controls;
        ((NVOS54_PARAMETERS *)argument)->status = 0;
        return 0;
    }
    if (request == _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_FREE,
                         NVOS00_PARAMETERS)) {
        ++frees;
        ((NVOS00_PARAMETERS *)argument)->status = 0;
        return 0;
    }
    return 0;
}
