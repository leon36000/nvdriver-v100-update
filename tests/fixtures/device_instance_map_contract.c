/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hybrid580-device-instance-map.h"

static struct hybrid580_gpu_backend_record_v1 gpu_record(
    const char *bdf, unsigned int backend_minor, unsigned int gpu_id,
    unsigned int domain, unsigned int bus)
{
    struct hybrid580_gpu_backend_record_v1 record = {0};
    strcpy(record.bdf, bdf);
    record.backend_minor = backend_minor;
    record.backend_gpu_id = gpu_id;
    record.domain = domain;
    record.bus = bus;
    record.vendor_id = 0x10de;
    record.device_id = 0x2c02;
    return record;
}

static void expect_zero_map(const struct hybrid580_device_instance_map_v1 *map)
{
    struct hybrid580_device_instance_map_v1 zero = {0};
    assert(memcmp(map, &zero, sizeof(zero)) == 0);
}

int main(void)
{
    struct hybrid580_gpu_catalog_v1 catalog = {0};
    struct hybrid580_gpu_backend_record_v1 legacy[HYBRID580_GPU_MAX_BACKEND_DEVICES] = {0};
    struct hybrid580_gpu_backend_record_v1 open[HYBRID580_GPU_MAX_BACKEND_DEVICES] = {0};
    struct hybrid580_device_instance_observation_v1 observations[HYBRID580_GPU_MAX_DEVICES] = {0};
    struct hybrid580_device_instance_map_v1 map = {0};
    struct hybrid580_device_instance_entry_v1 entry = {0};
    hybrid580_u32 backend_masks[2] = {0};
    unsigned int cases = 0;

    /* The two RMs both use local instance zero. BDF order gives stable front IDs. */
    legacy[0] = gpu_record("0000:03:00.0", 0, 5, 0, 3);
    open[0] = gpu_record("0000:02:00.0", 0, 512, 0, 2);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, open, 1, &catalog) == 0);
    assert(catalog.entries[0].backend == HYBRID580_BACKEND_OPEN);
    observations[0] = (struct hybrid580_device_instance_observation_v1){1, 512, 0};
    observations[1] = (struct hybrid580_device_instance_observation_v1){2, 5, 0};
    backend_masks[HYBRID580_BACKEND_LEGACY] = 1U;
    backend_masks[HYBRID580_BACKEND_OPEN] = 1U;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == 0);
    assert(map.count == 2 && map.frontend_device_ids == 3U);
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 0, &entry) == 0);
    assert(entry.backend == HYBRID580_BACKEND_OPEN && entry.backend_device_instance == 0);
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 1, &entry) == 0);
    assert(entry.backend == HYBRID580_BACKEND_LEGACY && entry.backend_device_instance == 0);
    assert(hybrid580_device_instance_map_lookup_backend_v1(
        &map, HYBRID580_BACKEND_OPEN, 0, &entry) == 0 &&
        entry.frontend_device_instance == 0);
    map.backend_device_ids[HYBRID580_BACKEND_LEGACY] |= 1U << 31;
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 0, &entry) == -EINVAL);
    map.backend_device_ids[HYBRID580_BACKEND_LEGACY] = 1U;
    map.entries[1].backend = HYBRID580_BACKEND_OPEN;
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 0, &entry) == -EINVAL);
    map.entries[1].backend = HYBRID580_BACKEND_LEGACY;
    ++cases;

    /* Several BDFs can belong to one backend RM device group. Preserve that group. */
    memset(&catalog, 0, sizeof(catalog));
    memset(observations, 0, sizeof(observations));
    memset(&map, 0, sizeof(map));
    legacy[0] = gpu_record("0000:01:00.0", 0, 5, 0, 1);
    legacy[1] = gpu_record("0000:03:00.0", 1, 6, 0, 3);
    open[0] = gpu_record("0000:02:00.0", 0, 512, 0, 2);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, open, 1, &catalog) == 0);
    observations[0] = (struct hybrid580_device_instance_observation_v1){1, 5, 7};
    observations[1] = (struct hybrid580_device_instance_observation_v1){2, 512, 3};
    observations[2] = (struct hybrid580_device_instance_observation_v1){3, 6, 7};
    backend_masks[HYBRID580_BACKEND_LEGACY] = 1U << 7;
    backend_masks[HYBRID580_BACKEND_OPEN] = 1U << 3;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == 0);
    assert(map.count == 2 && map.entries[0].gpu_count == 2 &&
           map.entries[1].gpu_count == 1 && map.frontend_device_ids == 3U);
    assert(hybrid580_device_instance_map_lookup_backend_v1(
        &map, HYBRID580_BACKEND_LEGACY, 7, &entry) == 0 &&
        entry.frontend_device_instance == 0);
    assert(hybrid580_device_instance_map_lookup_backend_v1(
        &map, HYBRID580_BACKEND_OPEN, 3, &entry) == 0 &&
        entry.frontend_device_instance == 1);
    ++cases;

    /* A missing or extra backend mask bit is an incomplete/stale inventory. */
    backend_masks[HYBRID580_BACKEND_LEGACY] = 1U << 6;
    memset(&map, 0xa5, sizeof(map));
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == -EINVAL);
    expect_zero_map(&map);
    backend_masks[HYBRID580_BACKEND_LEGACY] = (1U << 7) | (1U << 8);
    memset(&map, 0xa5, sizeof(map));
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == -EINVAL);
    expect_zero_map(&map);
    ++cases;

    /* Refuse stale/misordered GPU metadata, malformed instance IDs, and bad masks. */
    backend_masks[HYBRID580_BACKEND_LEGACY] = 1U << 7;
    observations[1].backend_gpu_id = 999;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == -EINVAL);
    expect_zero_map(&map);
    observations[1].backend_gpu_id = 512;
    observations[1].backend_device_instance = 32;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == -EINVAL);
    expect_zero_map(&map);
    observations[1].backend_device_instance = 3;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count - 1, backend_masks, &map) == -EINVAL);
    expect_zero_map(&map);
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 0, &entry) == -ENOENT);
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 32, &entry) == -ENOENT);
    ++cases;

    /* Physical GPU count may exceed the 32 logical RM groups. */
    memset(&catalog, 0, sizeof(catalog));
    memset(legacy, 0, sizeof(legacy));
    memset(open, 0, sizeof(open));
    memset(observations, 0, sizeof(observations));
    for (unsigned int i = 0; i < 65; ++i) {
        snprintf(legacy[i].bdf, sizeof(legacy[i].bdf), "0000:%02x:00.0", i);
        legacy[i].backend_minor = i;
        legacy[i].backend_gpu_id = i + 100;
        legacy[i].domain = 0;
        legacy[i].bus = i;
        legacy[i].vendor_id = 0x10de;
        legacy[i].device_id = 0x1db6;
    }
    assert(hybrid580_gpu_catalog_build_v1(legacy, 65, open, 0, &catalog) == 0);
    for (unsigned int i = 0; i < catalog.count; ++i)
        observations[i] = (struct hybrid580_device_instance_observation_v1){
            catalog.entries[i].frontend_gpu_id,
            catalog.entries[i].backend_gpu_id,
            7,
        };
    backend_masks[HYBRID580_BACKEND_LEGACY] = 1U << 7;
    backend_masks[HYBRID580_BACKEND_OPEN] = 0;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == 0);
    assert(map.count == 1 && map.entries[0].gpu_count == 65 &&
           map.entries[0].backend_device_instance == 7);
    ++cases;

    /* The ABI has a 32-bit instance mask; reject a 33rd merged device group. */
    memset(&catalog, 0, sizeof(catalog));
    memset(legacy, 0, sizeof(legacy));
    memset(open, 0, sizeof(open));
    memset(observations, 0, sizeof(observations));
    for (unsigned int i = 0; i < HYBRID580_RM_MAX_DEVICE_INSTANCES; ++i) {
        snprintf(legacy[i].bdf, sizeof(legacy[i].bdf), "0000:%02x:00.0", i);
        legacy[i].backend_minor = i;
        legacy[i].backend_gpu_id = i + 1;
        legacy[i].domain = 0;
        legacy[i].bus = i;
        legacy[i].vendor_id = 0x10de;
        legacy[i].device_id = 0x2c02;
    }
    open[0] = gpu_record("0001:00:00.0", 0, 512, 1, 0);
    assert(hybrid580_gpu_catalog_build_v1(
        legacy, HYBRID580_RM_MAX_DEVICE_INSTANCES, open, 1, &catalog) == 0);
    for (unsigned int i = 0; i < catalog.count; ++i)
        observations[i] = (struct hybrid580_device_instance_observation_v1){
            catalog.entries[i].frontend_gpu_id,
            catalog.entries[i].backend_gpu_id,
            catalog.entries[i].backend == HYBRID580_BACKEND_LEGACY ? i : 0,
        };
    backend_masks[HYBRID580_BACKEND_LEGACY] = UINT32_MAX;
    backend_masks[HYBRID580_BACKEND_OPEN] = 1U;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == -E2BIG);
    expect_zero_map(&map);
    ++cases;

    /* The exact 32-instance ABI boundary must preserve bit 31 safely. */
    memset(&catalog, 0, sizeof(catalog));
    memset(legacy, 0, sizeof(legacy));
    memset(open, 0, sizeof(open));
    memset(observations, 0, sizeof(observations));
    for (unsigned int i = 0; i < HYBRID580_RM_MAX_DEVICE_INSTANCES - 1; ++i) {
        snprintf(legacy[i].bdf, sizeof(legacy[i].bdf), "0000:%02x:00.0", i + 0x20);
        legacy[i].backend_minor = i;
        legacy[i].backend_gpu_id = i + 1;
        legacy[i].domain = 0;
        legacy[i].bus = i + 0x20;
        legacy[i].vendor_id = 0x10de;
        legacy[i].device_id = 0x2c02;
    }
    open[0] = gpu_record("0000:01:00.0", 0, 512, 0, 1);
    assert(hybrid580_gpu_catalog_build_v1(
        legacy, HYBRID580_RM_MAX_DEVICE_INSTANCES - 1, open, 1, &catalog) == 0);
    for (unsigned int i = 0; i < catalog.count; ++i)
        observations[i] = (struct hybrid580_device_instance_observation_v1){
            catalog.entries[i].frontend_gpu_id,
            catalog.entries[i].backend_gpu_id,
            catalog.entries[i].backend == HYBRID580_BACKEND_OPEN ?
                HYBRID580_RM_MAX_DEVICE_INSTANCES - 1 :
                catalog.entries[i].backend_gpu_id - 1,
        };
    backend_masks[HYBRID580_BACKEND_LEGACY] = 0x7fffffffU;
    backend_masks[HYBRID580_BACKEND_OPEN] = 0x80000000U;
    assert(hybrid580_device_instance_map_build_v1(
        &catalog, observations, catalog.count, backend_masks, &map) == 0);
    assert(map.count == HYBRID580_RM_MAX_DEVICE_INSTANCES &&
           map.frontend_device_ids == UINT32_MAX);
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 0, &entry) == 0 &&
           entry.backend == HYBRID580_BACKEND_OPEN &&
           entry.backend_device_instance == 31);
    assert(hybrid580_device_instance_map_lookup_front_v1(&map, 31, &entry) == 0 &&
           entry.backend == HYBRID580_BACKEND_LEGACY &&
           entry.backend_device_instance == 30);
    assert(hybrid580_device_instance_map_lookup_backend_v1(
        &map, HYBRID580_BACKEND_OPEN, 31, &entry) == 0 &&
        entry.frontend_device_instance == 0);
    ++cases;

    printf("device instance map scenarios: %u\n", cases);
    return 0;
}
