/* SPDX-License-Identifier: MIT */
/* Compile against pinned public NVIDIA source headers; no driver is loaded. */
#include <stddef.h>
#include <sys/ioctl.h>

#include "nvos.h"
#include "nv-ioctl.h"
#include "nv-ioctl-numbers.h"
#include "nv_escape.h"
#include "nv-unix-nvos-params-wrappers.h"

_Static_assert(sizeof(NVOS33_PARAMETERS) == 48, "NVOS33 base ABI size");
_Static_assert(offsetof(NVOS33_PARAMETERS, offset) == 16, "NVOS33 offset");
_Static_assert(offsetof(NVOS33_PARAMETERS, length) == 24, "NVOS33 length");
_Static_assert(offsetof(NVOS33_PARAMETERS, pLinearAddress) == 32,
               "NVOS33 returned address");
_Static_assert(offsetof(NVOS33_PARAMETERS, status) == 40, "NVOS33 status");
_Static_assert(offsetof(NVOS33_PARAMETERS, flags) == 44, "NVOS33 flags");
_Static_assert(sizeof(nv_ioctl_nvos33_parameters_with_fd) == 56,
               "NVOS33 plus fd ioctl ABI size");
_Static_assert(offsetof(nv_ioctl_nvos33_parameters_with_fd, fd) == 48,
               "NVOS33 plus fd offset");

_Static_assert(sizeof(NVOS56_PARAMETERS) == 40, "NVOS56 ABI size");
_Static_assert(offsetof(NVOS56_PARAMETERS, pOldCpuAddress) == 16,
               "NVOS56 old address");
_Static_assert(offsetof(NVOS56_PARAMETERS, pNewCpuAddress) == 24,
               "NVOS56 new address");
_Static_assert(offsetof(NVOS56_PARAMETERS, status) == 32, "NVOS56 status");

_Static_assert(sizeof(nv_ioctl_alloc_os_event_t) == 16,
               "OS event ioctl ABI size");
_Static_assert(offsetof(nv_ioctl_alloc_os_event_t, fd) == 8,
               "OS event fd offset");
_Static_assert(offsetof(nv_ioctl_alloc_os_event_t, Status) == 12,
               "OS event status offset");
_Static_assert(sizeof(nv_ioctl_free_os_event_t) == 16,
               "OS event free ioctl ABI size");
_Static_assert(offsetof(nv_ioctl_free_os_event_t, fd) == 8,
               "OS event free fd offset");

_Static_assert(NV_ESC_RM_MAP_MEMORY == 0x4e, "map-memory escape number");
_Static_assert(NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO == 0x5e,
               "device-mapping escape number");
_Static_assert(NV_ESC_ALLOC_OS_EVENT == 0xce, "allocate-event escape number");
_Static_assert(NV_ESC_FREE_OS_EVENT == 0xcf, "free-event escape number");

_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_MAP_MEMORY,
                     nv_ioctl_nvos33_parameters_with_fd) == 0xc038464e,
               "observed map-memory request");
_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO,
                     NVOS56_PARAMETERS) == 0xc028465e,
               "observed update-mapping request");
_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_ALLOC_OS_EVENT,
                     nv_ioctl_alloc_os_event_t) == 0xc01046ce,
               "observed allocate-event request");
_Static_assert(_IOWR(NV_IOCTL_MAGIC, NV_ESC_FREE_OS_EVENT,
                     nv_ioctl_free_os_event_t) == 0xc01046cf,
               "observed free-event request");

int main(void)
{
    return 0;
}
