/* SPDX-License-Identifier: MIT */
#include "hybrid580-device-instance-map.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

static int hybrid580_device_instance_map_fail(
    struct hybrid580_device_instance_map_v1 *map, int error)
{
    memset(map, 0, sizeof(*map));
    return error;
}

static int hybrid580_device_instance_map_valid(
    const struct hybrid580_device_instance_map_v1 *map)
{
    hybrid580_u32 i, j, expected_mask, backend_masks[2] = {0, 0};

    if (map == NULL || map->count > HYBRID580_RM_MAX_DEVICE_INSTANCES)
        return -EINVAL;
    expected_mask = map->count == HYBRID580_RM_MAX_DEVICE_INSTANCES ?
        0xffffffffU : ((1U << map->count) - 1U);
    if (map->frontend_device_ids != expected_mask)
        return -EINVAL;

    for (i = 0; i < map->count; ++i) {
        const struct hybrid580_device_instance_entry_v1 *entry =
            &map->entries[i];
        hybrid580_u32 bit;

        if (entry->frontend_device_instance != i ||
            entry->backend > HYBRID580_BACKEND_OPEN ||
            entry->backend_device_instance >= HYBRID580_RM_MAX_DEVICE_INSTANCES ||
            entry->first_frontend_gpu_id == HYBRID580_GPU_FRONT_ID_INVALID ||
            entry->gpu_count == 0)
            return -EINVAL;
        bit = 1U << entry->backend_device_instance;
        if ((map->backend_device_ids[entry->backend] & bit) == 0)
            return -EINVAL;
        for (j = 0; j < i; ++j)
            if (map->entries[j].backend == entry->backend &&
                map->entries[j].backend_device_instance ==
                    entry->backend_device_instance)
                return -EINVAL;
        backend_masks[entry->backend] |= bit;
    }
    if (backend_masks[HYBRID580_BACKEND_LEGACY] !=
            map->backend_device_ids[HYBRID580_BACKEND_LEGACY] ||
        backend_masks[HYBRID580_BACKEND_OPEN] !=
            map->backend_device_ids[HYBRID580_BACKEND_OPEN])
        return -EINVAL;
    return 0;
}

int hybrid580_device_instance_map_build_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    const struct hybrid580_device_instance_observation_v1 *observations,
    hybrid580_u32 observation_count,
    const hybrid580_u32 backend_device_ids[2],
    struct hybrid580_device_instance_map_v1 *map)
{
    struct hybrid580_device_instance_map_v1 candidate;
    hybrid580_u32 observed_masks[2] = {0, 0};
    hybrid580_u32 i, j;

    if (map == NULL)
        return -EINVAL;
    memset(map, 0, sizeof(*map));
    memset(&candidate, 0, sizeof(candidate));
    if (catalog == NULL || backend_device_ids == NULL ||
        catalog->count > HYBRID580_GPU_MAX_DEVICES)
        return hybrid580_device_instance_map_fail(map, -EINVAL);
    if (observation_count != catalog->count ||
        (observation_count != 0 && observations == NULL))
        return hybrid580_device_instance_map_fail(map, -EINVAL);

    for (i = 0; i < catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *gpu =
            &catalog->entries[i];
        const struct hybrid580_device_instance_observation_v1 *observation =
            &observations[i];
        struct hybrid580_device_instance_entry_v1 *instance = NULL;
        hybrid580_u32 backend, local_id, bit;

        if (gpu->frontend_index != i || gpu->frontend_gpu_id != i + 1U ||
            gpu->backend > HYBRID580_BACKEND_OPEN || gpu->backend_gpu_id == 0 ||
            observation->frontend_gpu_id != gpu->frontend_gpu_id ||
            observation->backend_gpu_id != gpu->backend_gpu_id)
            return hybrid580_device_instance_map_fail(map, -EINVAL);

        backend = gpu->backend;
        local_id = observation->backend_device_instance;
        if (local_id >= HYBRID580_RM_MAX_DEVICE_INSTANCES)
            return hybrid580_device_instance_map_fail(map, -EINVAL);
        bit = 1U << local_id;
        observed_masks[backend] |= bit;

        for (j = 0; j < candidate.count; ++j) {
            struct hybrid580_device_instance_entry_v1 *prior =
                &candidate.entries[j];
            if (prior->backend == backend &&
                prior->backend_device_instance == local_id) {
                instance = prior;
                break;
            }
        }
        if (instance != NULL) {
            ++instance->gpu_count;
            continue;
        }
        if (candidate.count == HYBRID580_RM_MAX_DEVICE_INSTANCES)
            return hybrid580_device_instance_map_fail(map, -E2BIG);

        instance = &candidate.entries[candidate.count];
        instance->frontend_device_instance = candidate.count;
        instance->backend = backend;
        instance->backend_device_instance = local_id;
        instance->first_frontend_gpu_id = gpu->frontend_gpu_id;
        instance->gpu_count = 1;
        candidate.frontend_device_ids |= 1U << candidate.count;
        candidate.backend_device_ids[backend] |= bit;
        ++candidate.count;
    }

    if (observed_masks[HYBRID580_BACKEND_LEGACY] !=
            backend_device_ids[HYBRID580_BACKEND_LEGACY] ||
        observed_masks[HYBRID580_BACKEND_OPEN] !=
            backend_device_ids[HYBRID580_BACKEND_OPEN])
        return hybrid580_device_instance_map_fail(map, -EINVAL);
    if (hybrid580_device_instance_map_valid(&candidate) != 0)
        return hybrid580_device_instance_map_fail(map, -EINVAL);

    *map = candidate;
    return 0;
}

int hybrid580_device_instance_map_lookup_front_v1(
    const struct hybrid580_device_instance_map_v1 *map,
    hybrid580_u32 frontend_device_instance,
    struct hybrid580_device_instance_entry_v1 *entry)
{
    if (map == NULL || entry == NULL ||
        hybrid580_device_instance_map_valid(map) != 0)
        return -EINVAL;
    if (frontend_device_instance >= map->count)
        return -ENOENT;
    *entry = map->entries[frontend_device_instance];
    return 0;
}

int hybrid580_device_instance_map_lookup_backend_v1(
    const struct hybrid580_device_instance_map_v1 *map,
    hybrid580_u32 backend,
    hybrid580_u32 backend_device_instance,
    struct hybrid580_device_instance_entry_v1 *entry)
{
    hybrid580_u32 i;

    if (map == NULL || entry == NULL || backend > HYBRID580_BACKEND_OPEN ||
        backend_device_instance >= HYBRID580_RM_MAX_DEVICE_INSTANCES ||
        hybrid580_device_instance_map_valid(map) != 0)
        return -EINVAL;
    for (i = 0; i < map->count; ++i) {
        const struct hybrid580_device_instance_entry_v1 *candidate =
            &map->entries[i];
        if (candidate->backend != backend ||
            candidate->backend_device_instance != backend_device_instance)
            continue;
        *entry = *candidate;
        return 0;
    }
    return -ENOENT;
}
