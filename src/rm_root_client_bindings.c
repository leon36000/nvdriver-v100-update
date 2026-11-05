/* SPDX-License-Identifier: MIT */
#include "rm_root_client.h"

/* GNU typeof preserves the vendor NV_API_CALL and parameter types exactly. */
extern __typeof__(rm_ioctl) hybrid580_rm_ioctl;
_Static_assert(__builtin_types_compatible_p(hybrid_rm_ioctl_fn, __typeof__(&rm_ioctl)),
               "R580 rm_ioctl signature changed");

void hybrid_root_bind_r580(struct hybrid_rm_endpoint endpoints[2])
{
    /* Caller supplies each stack, control nv and isolated file-private state. */
    endpoints[0].ioctl = rm_ioctl;
    endpoints[1].ioctl = hybrid580_rm_ioctl;
}
