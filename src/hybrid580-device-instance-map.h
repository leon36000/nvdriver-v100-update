/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_DEVICE_INSTANCE_MAP_H
#define HYBRID580_DEVICE_INSTANCE_MAP_H

#include "hybrid580-gpu-catalog.h"

#define HYBRID580_RM_MAX_DEVICE_INSTANCES 32U
#define HYBRID580_DEVICE_INSTANCE_INVALID 0xffffffffU

/* One fixed GPU_GET_ID_INFO_V2 result, paired with the BDF catalog entry
 * whose frontend GPU ID was queried. The backend selector is taken from the
 * catalog rather than duplicated in this observation. */
struct hybrid580_device_instance_observation_v1 {
    hybrid580_u32 frontend_gpu_id;
    hybrid580_u32 backend_gpu_id;
    hybrid580_u32 backend_device_instance;
};

/* A device instance may represent a backend-local group of GPUs. Never merge
 * equal local instance numbers from different RM backends into one object. */
struct hybrid580_device_instance_entry_v1 {
    hybrid580_u32 frontend_device_instance;
    hybrid580_u32 backend;
    hybrid580_u32 backend_device_instance;
    hybrid580_u32 first_frontend_gpu_id;
    hybrid580_u32 gpu_count;
};

struct hybrid580_device_instance_map_v1 {
    hybrid580_u32 count;
    hybrid580_u32 frontend_device_ids;
    hybrid580_u32 backend_device_ids[2];
    struct hybrid580_device_instance_entry_v1 entries[
        HYBRID580_RM_MAX_DEVICE_INSTANCES];
};

/* Build a BDF-ordered synthetic RM device-instance namespace. Observations
 * must align exactly with the sorted catalog; each backend mask must equal
 * the set of instances found by GPU_GET_ID_INFO_V2. Multiple GPUs can share
 * one instance within one backend. Output is all-zero on every error. */
int hybrid580_device_instance_map_build_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    const struct hybrid580_device_instance_observation_v1 *observations,
    hybrid580_u32 observation_count,
    const hybrid580_u32 backend_device_ids[2],
    struct hybrid580_device_instance_map_v1 *map);

int hybrid580_device_instance_map_lookup_front_v1(
    const struct hybrid580_device_instance_map_v1 *map,
    hybrid580_u32 frontend_device_instance,
    struct hybrid580_device_instance_entry_v1 *entry);

int hybrid580_device_instance_map_lookup_backend_v1(
    const struct hybrid580_device_instance_map_v1 *map,
    hybrid580_u32 backend,
    hybrid580_u32 backend_device_instance,
    struct hybrid580_device_instance_entry_v1 *entry);

#endif
