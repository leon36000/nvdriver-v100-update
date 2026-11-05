/* SPDX-License-Identifier: MIT */
#include "hybrid580-standard-node-map.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <nv-chardev-numbers.h>

static int hybrid580_standard_node_bdf_valid(
    const struct hybrid580_gpu_catalog_entry_v1 *entry)
{
    hybrid580_u32 domain = 0, bus = 0, slot = 0, function = 0, i;

    if (entry->reserved != 0 || entry->backend > HYBRID580_BACKEND_OPEN ||
        entry->backend_minor >= HYBRID580_GPU_MAX_BACKEND_DEVICES ||
        entry->backend_gpu_id == HYBRID580_GPU_FRONT_ID_INVALID ||
        entry->vendor_id != 0x10deU || entry->device_id == 0 ||
        entry->bdf[4] != ':' || entry->bdf[7] != ':' || entry->bdf[10] != '.')
        return -EINVAL;
    for (i = 0; i < 12; ++i) {
        hybrid580_u32 value;
        char ch = entry->bdf[i];
        if (i == 4 || i == 7 || i == 10)
            continue;
        if (ch >= '0' && ch <= '9')
            value = (hybrid580_u32)(ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            value = (hybrid580_u32)(ch - 'a') + 10U;
        else
            return -EINVAL;
        if (i < 4)
            domain = (domain << 4) | value;
        else if (i < 7)
            bus = (bus << 4) | value;
        else if (i < 10)
            slot = (slot << 4) | value;
        else
            function = value;
    }
    for (i = 12; i < HYBRID580_GPU_BDF_SIZE; ++i)
        if (entry->bdf[i] != '\0')
            return -EINVAL;
    if (domain != entry->domain || bus != entry->bus ||
        slot != entry->slot || function != entry->function ||
        slot > 31U || function > 7U)
        return -EINVAL;
    return 0;
}

int hybrid580_standard_node_resolve_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 minor,
    struct hybrid580_standard_node_resolution_v1 *resolution)
{
    const struct hybrid580_gpu_catalog_entry_v1 *entry;

    if (resolution == NULL)
        return -EINVAL;
    memset(resolution, 0, sizeof(*resolution));
    if (catalog == NULL)
        return -EINVAL;
    if (catalog->count > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U)
        return -E2BIG;
    if (minor == NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE) {
        resolution->kind = HYBRID580_STANDARD_NODE_CONTROL;
        return 0;
    }
    if (minor > NV_MINOR_DEVICE_NUMBER_REGULAR_MAX || minor >= catalog->count)
        return -ENODEV;

    entry = &catalog->entries[minor];
    if (entry->frontend_index != minor || entry->frontend_gpu_id != minor + 1U ||
        hybrid580_standard_node_bdf_valid(entry) != 0)
        return -EINVAL;
    resolution->kind = HYBRID580_STANDARD_NODE_GPU;
    resolution->frontend_index = entry->frontend_index;
    resolution->frontend_gpu_id = entry->frontend_gpu_id;
    resolution->backend = entry->backend;
    resolution->backend_minor = entry->backend_minor;
    resolution->backend_gpu_id = entry->backend_gpu_id;
    memcpy(resolution->bdf, entry->bdf, sizeof(resolution->bdf));
    return 0;
}
