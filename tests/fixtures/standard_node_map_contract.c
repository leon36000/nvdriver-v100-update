/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "nv-chardev-numbers.h"
#include "hybrid580-standard-node-map.h"

static struct hybrid580_gpu_backend_record_v1 record(
    const char *bdf, unsigned int backend, unsigned int backend_minor,
    unsigned int backend_gpu_id, unsigned int bus)
{
    struct hybrid580_gpu_backend_record_v1 item = {0};
    strcpy(item.bdf, bdf);
    item.backend_minor = backend_minor;
    item.backend_gpu_id = backend_gpu_id;
    item.domain = 0;
    item.bus = bus;
    item.vendor_id = 0x10de;
    item.device_id = backend == HYBRID580_BACKEND_OPEN ? 0x2c02 : 0x1db6;
    return item;
}

static void expect_zero(const struct hybrid580_standard_node_resolution_v1 *value)
{
    const struct hybrid580_standard_node_resolution_v1 zero = {0};
    assert(memcmp(value, &zero, sizeof(zero)) == 0);
}

int main(void)
{
    struct hybrid580_gpu_catalog_v1 catalog = {0};
    struct hybrid580_gpu_backend_record_v1 legacy[2] = {
        record("0000:81:00.0", HYBRID580_BACKEND_LEGACY, 0, 5, 0x81),
        record("0000:82:00.0", HYBRID580_BACKEND_LEGACY, 1, 6, 0x82),
    };
    struct hybrid580_gpu_backend_record_v1 open[1] = {
        record("0000:02:00.0", HYBRID580_BACKEND_OPEN, 0, 512, 0x02),
    };
    struct hybrid580_standard_node_resolution_v1 resolved = {0};
    unsigned int cases = 0;

    assert(NV_MINOR_DEVICE_NUMBER_REGULAR_MAX == 247);
    assert(NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE == 255);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, open, 1, &catalog) == 0);

    assert(hybrid580_standard_node_resolve_v1(
        &catalog, 0, &resolved) == 0);
    assert(resolved.kind == HYBRID580_STANDARD_NODE_GPU);
    assert(resolved.frontend_index == 0 && resolved.frontend_gpu_id == 1);
    assert(resolved.backend == HYBRID580_BACKEND_OPEN);
    assert(hybrid580_standard_node_resolve_v1(
        &catalog, 1, &resolved) == 0);
    assert(resolved.frontend_index == 1 && resolved.frontend_gpu_id == 2);
    assert(resolved.backend == HYBRID580_BACKEND_LEGACY);
    assert(hybrid580_standard_node_resolve_v1(
        &catalog, 2, &resolved) == 0);
    assert(resolved.frontend_index == 2 && resolved.frontend_gpu_id == 3);
    assert(resolved.backend == HYBRID580_BACKEND_LEGACY);
    ++cases;

    memset(&resolved, 0xa5, sizeof(resolved));
    assert(hybrid580_standard_node_resolve_v1(
        &catalog, NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE, &resolved) == 0);
    assert(resolved.kind == HYBRID580_STANDARD_NODE_CONTROL);
    assert(resolved.frontend_index == 0 && resolved.frontend_gpu_id == 0 &&
           resolved.backend == 0);
    ++cases;

    for (unsigned int minor = 3; minor <= NV_MINOR_DEVICE_NUMBER_REGULAR_MAX; ++minor) {
        memset(&resolved, 0xa5, sizeof(resolved));
        assert(hybrid580_standard_node_resolve_v1(
            &catalog, minor, &resolved) == -ENODEV);
        expect_zero(&resolved);
    }
    for (unsigned int minor = 248; minor < NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE; ++minor) {
        memset(&resolved, 0xa5, sizeof(resolved));
        assert(hybrid580_standard_node_resolve_v1(
            &catalog, minor, &resolved) == -ENODEV);
        expect_zero(&resolved);
    }
    assert(hybrid580_standard_node_resolve_v1(&catalog, 256, &resolved) == -ENODEV);
    expect_zero(&resolved);
    ++cases;

    struct hybrid580_gpu_catalog_v1 invalid = catalog;
    invalid.entries[0].frontend_index = 9;
    memset(&resolved, 0xa5, sizeof(resolved));
    assert(hybrid580_standard_node_resolve_v1(&invalid, 0, &resolved) == -EINVAL);
    expect_zero(&resolved);
    invalid = catalog;
    invalid.entries[1].backend = 2;
    memset(&resolved, 0xa5, sizeof(resolved));
    assert(hybrid580_standard_node_resolve_v1(&invalid, 1, &resolved) == -EINVAL);
    expect_zero(&resolved);
    invalid = catalog;
    invalid.entries[2].bdf[0] = 'G';
    memset(&resolved, 0xa5, sizeof(resolved));
    assert(hybrid580_standard_node_resolve_v1(&invalid, 2, &resolved) == -EINVAL);
    expect_zero(&resolved);
    ++cases;

    invalid = catalog;
    invalid.count = HYBRID580_GPU_MAX_BACKEND_DEVICES + 1;
    memset(&resolved, 0xa5, sizeof(resolved));
    assert(hybrid580_standard_node_resolve_v1(&invalid, 0, &resolved) == -E2BIG);
    expect_zero(&resolved);
    assert(hybrid580_standard_node_resolve_v1(NULL, 0, &resolved) == -EINVAL);
    assert(hybrid580_standard_node_resolve_v1(&catalog, 0, NULL) == -EINVAL);
    ++cases;

    printf("standard node map scenarios: %u\n", cases);
    return 0;
}
