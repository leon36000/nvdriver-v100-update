#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU regression tests for the deterministic dual-backend GPU catalog."""

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GpuCatalogTests(unittest.TestCase):
    def test_catalog_contract_and_failure_atomicity(self):
        source = r'''#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hybrid580-gpu-catalog.h"

static struct hybrid580_gpu_backend_record_v1 record(
    const char *bdf, unsigned int minor, unsigned int gpu_id,
    unsigned int domain, unsigned int bus, unsigned int slot,
    unsigned int function)
{
    struct hybrid580_gpu_backend_record_v1 r = {0};
    strcpy(r.bdf, bdf);
    r.backend_minor = minor;
    r.backend_gpu_id = gpu_id;
    r.domain = domain;
    r.bus = bus;
    r.slot = slot;
    r.function = function;
    r.vendor_id = 0x10de;
    r.device_id = 0x2684;
    return r;
}

int main(void)
{
    struct hybrid580_gpu_catalog_v1 *catalog = calloc(1, sizeof(*catalog));
    assert(catalog != NULL);
    struct hybrid580_gpu_backend_record_v1 legacy[2] = {
        record("0000:65:00.0", 3, 44, 0, 0x65, 0, 0),
        record("0001:01:02.3", 9, 45, 1, 1, 2, 3),
    };
    struct hybrid580_gpu_backend_record_v1 open[1] = {
        record("0000:01:00.0", 3, 44, 0, 1, 0, 0),
    };
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, open, 1, catalog) == 0);
    assert(catalog->count == 3);
    assert(catalog->entries[0].frontend_index == 0);
    assert(catalog->entries[0].frontend_gpu_id == 1);
    assert(strcmp(catalog->entries[0].bdf, "0000:01:00.0") == 0);
    assert(catalog->entries[0].backend == HYBRID580_BACKEND_OPEN);
    assert(catalog->entries[0].backend_minor == 3);
    assert(catalog->entries[0].backend_gpu_id == 44);
    assert(catalog->entries[1].frontend_index == 1);
    assert(catalog->entries[1].frontend_gpu_id == 2);
    assert(strcmp(catalog->entries[1].bdf, "0000:65:00.0") == 0);
    assert(catalog->entries[1].backend == HYBRID580_BACKEND_LEGACY);
    assert(catalog->entries[2].frontend_index == 2);
    assert(strcmp(catalog->entries[2].bdf, "0001:01:02.3") == 0);
    assert(catalog->entries[2].domain == 1 && catalog->entries[2].bus == 1);
    assert(catalog->entries[2].slot == 2 && catalog->entries[2].function == 3);
    struct hybrid580_gpu_catalog_entry_v1 resolved = {0};
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog, 1, &resolved) == 0);
    assert(resolved.backend == HYBRID580_BACKEND_OPEN && resolved.backend_gpu_id == 44);
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog, 2, &resolved) == 0);
    assert(resolved.backend == HYBRID580_BACKEND_LEGACY && resolved.backend_gpu_id == 44);
    assert(hybrid580_gpu_catalog_lookup_backend_minor_v1(catalog,
        HYBRID580_BACKEND_OPEN, 3, &resolved) == 0);
    assert(resolved.frontend_index == 0 && resolved.frontend_gpu_id == 1 &&
           resolved.backend_gpu_id == 44);
    assert(hybrid580_gpu_catalog_lookup_backend_minor_v1(catalog,
        HYBRID580_BACKEND_LEGACY, 3, &resolved) == 0);
    assert(resolved.frontend_index == 1 && resolved.frontend_gpu_id == 2 &&
           resolved.backend_gpu_id == 44);
    assert(hybrid580_gpu_catalog_lookup_backend_minor_v1(catalog,
        HYBRID580_BACKEND_OPEN, 9, &resolved) == -ENOENT);
    assert(hybrid580_gpu_catalog_lookup_backend_minor_v1(catalog,
        2, 3, &resolved) == -EINVAL);
    struct hybrid580_gpu_attach_plan_v1 *plan = calloc(1, sizeof(*plan));
    assert(plan != NULL);
    hybrid580_u32 requested[] = { 3, 1, 2 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, requested, 3, plan) == 0);
    assert(plan->count == 3);
    assert(plan->frontend_gpu_ids[0] == 3 && plan->frontend_gpu_ids[1] == 1 &&
           plan->frontend_gpu_ids[2] == 2);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].count == 2);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].frontend_gpu_ids[0] == 3);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].backend_gpu_ids[0] == 45);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].frontend_gpu_ids[1] == 2);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].backend_gpu_ids[1] == 44);
    assert(plan->backends[HYBRID580_BACKEND_OPEN].count == 1);
    assert(plan->backends[HYBRID580_BACKEND_OPEN].frontend_gpu_ids[0] == 1);
    assert(plan->backends[HYBRID580_BACKEND_OPEN].backend_gpu_ids[0] == 44);

    hybrid580_u32 duplicate[] = { 2, 2 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, duplicate, 2, plan) == 0);
    assert(plan->count == 2);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].count == 2);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].backend_gpu_ids[0] == 44);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].backend_gpu_ids[1] == 44);
    hybrid580_u32 placeholders[] = { 0, 3, 0, 1 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, placeholders, 4, plan) == 0);
    assert(plan->count == 4 && plan->frontend_gpu_ids[0] == 0 &&
           plan->frontend_gpu_ids[1] == 3 && plan->frontend_gpu_ids[2] == 0 &&
           plan->frontend_gpu_ids[3] == 1);
    assert(plan->backends[HYBRID580_BACKEND_LEGACY].count == 1 &&
           plan->backends[HYBRID580_BACKEND_LEGACY].backend_gpu_ids[0] == 45);
    assert(plan->backends[HYBRID580_BACKEND_OPEN].count == 1 &&
           plan->backends[HYBRID580_BACKEND_OPEN].backend_gpu_ids[0] == 44);
    hybrid580_u32 zero_only[] = { 0 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, zero_only, 1, plan) == 0);
    assert(plan->count == 1 && plan->frontend_gpu_ids[0] == 0 &&
           plan->backends[0].count == 0 && plan->backends[1].count == 0);
    hybrid580_u32 unknown[] = { 4 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, unknown, 1, plan) == -ENOENT);
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, NULL, 1, plan) == -EINVAL);
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, requested, 0, plan) == -EINVAL);
    hybrid580_u32 repeated_backend_id[] = { 2, 3 };
    catalog->entries[2].backend_gpu_id = catalog->entries[1].backend_gpu_id;
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, repeated_backend_id,
        2, plan) == -EEXIST);
    catalog->entries[2].backend_gpu_id = 45;
    catalog->entries[0].backend = 2;
    hybrid580_u32 invalid_backend[] = { 1 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, invalid_backend,
        1, plan) == -EINVAL);
    catalog->entries[0].backend = HYBRID580_BACKEND_OPEN;
    catalog->entries[0].backend_gpu_id = 0;
    hybrid580_u32 unattachable[] = { 1 };
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, unattachable, 1, plan) == -EINVAL);
    catalog->entries[0].backend_gpu_id = 44;
    free(plan);
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog,
        HYBRID580_GPU_FRONT_ID_INVALID, &resolved) == -EINVAL);
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog, 4, &resolved) == -ENOENT);
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog, 0xffffffffU,
        &resolved) == -ENOENT);
    struct hybrid580_gpu_catalog_entry_v1 first_order[3];
    memcpy(first_order, catalog->entries, sizeof(first_order));
    struct hybrid580_gpu_backend_record_v1 reordered_legacy[2] = { legacy[1], legacy[0] };
    assert(hybrid580_gpu_catalog_build_v1(reordered_legacy, 2, open, 1, catalog) == 0);
    for (unsigned int i = 0; i < 3; ++i) {
        assert(catalog->entries[i].frontend_index == first_order[i].frontend_index);
        assert(strcmp(catalog->entries[i].bdf, first_order[i].bdf) == 0);
        assert(catalog->entries[i].backend == first_order[i].backend);
        assert(catalog->entries[i].backend_minor == first_order[i].backend_minor);
    }

    assert(hybrid580_gpu_catalog_build_v1(NULL, 0, NULL, 0, catalog) == 0);
    assert(catalog->count == 0);
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog, 1, &resolved) == -ENOENT);

    legacy[1] = record("0000:65:00.1", 3, 45, 0, 0x65, 0, 1);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, NULL, 0, catalog) == -EEXIST);
    assert(catalog->count == 0);
    legacy[1] = record("0001:01:02.3", 9, 44, 1, 1, 2, 3);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, NULL, 0, catalog) == -EEXIST);
    assert(catalog->count == 0);
    legacy[1] = record("0000:65:00.1", 9, 45, 0, 0x65, 0, 1);
    open[0] = record("0000:65:00.1", 3, 46, 0, 0x65, 0, 1);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, open, 1, catalog) == -EEXIST);
    assert(catalog->count == 0);
    open[0] = record("0000:01:00.0", 3, 44, 0, 1, 0, 0);
    legacy[0] = record("0000:65:00.0", 3, 44, 0, 0x64, 0, 0);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, open, 1, catalog) == -EINVAL);
    assert(catalog->count == 0);
    legacy[0] = record("0000:20:00.0", 3, 44, 0, 0x20, 0x20, 0);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, NULL, 0, catalog) == -EINVAL);
    assert(catalog->count == 0);
    legacy[0] = record("0000:65:00.0", 3, 44, 0, 0x65, 0, 0);
    legacy[0].vendor_id = 0x1234;
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, NULL, 0, catalog) == -EINVAL);
    assert(catalog->count == 0);
    legacy[0] = record("0000:65:00.8", 3, 44, 0, 0x65, 0, 8);
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, NULL, 0, catalog) == -EINVAL);
    assert(catalog->count == 0);
    legacy[0] = record("0000:65:00.0", 3, 44, 0, 0x65, 0, 0);
    legacy[0].reserved = 1;
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, NULL, 0, catalog) == -EINVAL);
    assert(catalog->count == 0);
    legacy[0] = record("0000:65:00.0", 3, 44, 0, 0x65, 0, 0);
    legacy[0].bdf[12] = 'x';
    assert(hybrid580_gpu_catalog_build_v1(legacy, 1, NULL, 0, catalog) == -EINVAL);
    assert(catalog->count == 0);
    assert(hybrid580_gpu_catalog_build_v1(NULL, 1, NULL, 0, catalog) == -EINVAL);
    assert(catalog->count == 0);
    assert(hybrid580_gpu_catalog_build_v1(NULL, 0, NULL, 0, NULL) == -EINVAL);

    struct hybrid580_gpu_backend_record_v1 legacy_full[HYBRID580_GPU_MAX_BACKEND_DEVICES] = {0};
    struct hybrid580_gpu_backend_record_v1 open_full[HYBRID580_GPU_MAX_BACKEND_DEVICES] = {0};
    for (unsigned int i = 0; i < HYBRID580_GPU_MAX_BACKEND_DEVICES; ++i) {
        snprintf(legacy_full[i].bdf, sizeof(legacy_full[i].bdf), "0000:%02x:00.0", i);
        legacy_full[i].backend_minor = i;
        legacy_full[i].backend_gpu_id = i + 1;
        legacy_full[i].domain = 0;
        legacy_full[i].bus = i;
        legacy_full[i].vendor_id = 0x10de;
        snprintf(open_full[i].bdf, sizeof(open_full[i].bdf), "0001:%02x:00.0", i);
        open_full[i].backend_minor = i;
        open_full[i].backend_gpu_id = i + 1;
        open_full[i].domain = 1;
        open_full[i].bus = i;
        open_full[i].vendor_id = 0x10de;
    }
    assert(hybrid580_gpu_catalog_build_v1(legacy_full,
        HYBRID580_GPU_MAX_BACKEND_DEVICES, open_full,
        HYBRID580_GPU_MAX_BACKEND_DEVICES, catalog) == 0);
    assert(catalog->count == HYBRID580_GPU_MAX_DEVICES);
    assert(catalog->entries[0].frontend_index == 0);
    assert(catalog->entries[HYBRID580_GPU_MAX_DEVICES - 1].frontend_index ==
        HYBRID580_GPU_MAX_DEVICES - 1);
    assert(catalog->entries[HYBRID580_GPU_MAX_DEVICES - 1].frontend_gpu_id ==
        HYBRID580_GPU_MAX_DEVICES);
    assert(hybrid580_gpu_catalog_lookup_front_id_v1(catalog,
        HYBRID580_GPU_MAX_DEVICES, &resolved) == 0);
    assert(resolved.frontend_index == HYBRID580_GPU_MAX_DEVICES - 1);
    assert(catalog->entries[HYBRID580_GPU_MAX_BACKEND_DEVICES].backend ==
        HYBRID580_BACKEND_OPEN);
    struct hybrid580_gpu_attach_plan_v1 *full_plan = calloc(1, sizeof(*full_plan));
    hybrid580_u32 all_ids[HYBRID580_GPU_MAX_DEVICES];
    assert(full_plan != NULL);
    for (unsigned int i = 0; i < HYBRID580_GPU_MAX_DEVICES; ++i)
        all_ids[i] = i + 1;
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, all_ids,
        HYBRID580_GPU_MAX_DEVICES, full_plan) == 0);
    assert(full_plan->count == HYBRID580_GPU_MAX_DEVICES);
    assert(full_plan->backends[HYBRID580_BACKEND_LEGACY].count ==
        HYBRID580_GPU_MAX_BACKEND_DEVICES);
    assert(full_plan->backends[HYBRID580_BACKEND_OPEN].count ==
        HYBRID580_GPU_MAX_BACKEND_DEVICES);
    hybrid580_u32 repeated_ids[HYBRID580_GPU_MAX_DEVICES];
    for (unsigned int i = 0; i < HYBRID580_GPU_MAX_DEVICES; ++i)
        repeated_ids[i] = 2;
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, repeated_ids,
        HYBRID580_GPU_MAX_DEVICES, full_plan) == 0);
    assert(full_plan->count == HYBRID580_GPU_MAX_DEVICES);
    assert(full_plan->backends[HYBRID580_BACKEND_LEGACY].count ==
        HYBRID580_GPU_MAX_DEVICES);
    free(full_plan);

    struct hybrid580_gpu_backend_record_v1 too_many[HYBRID580_GPU_MAX_BACKEND_DEVICES + 1] = {0};
    assert(hybrid580_gpu_catalog_build_v1(too_many,
        HYBRID580_GPU_MAX_BACKEND_DEVICES + 1, NULL, 0, catalog) == -E2BIG);
    assert(catalog->count == 0);
    hybrid580_u32 too_many_ids[HYBRID580_GPU_MAX_DEVICES + 1] = {0};
    full_plan = calloc(1, sizeof(*full_plan));
    assert(full_plan != NULL);
    assert(hybrid580_gpu_catalog_plan_attach_v1(catalog, too_many_ids,
        HYBRID580_GPU_MAX_DEVICES + 1, full_plan) == -E2BIG);
    for (size_t i = 0; i < sizeof(*full_plan); ++i)
        assert(((const unsigned char *)full_plan)[i] == 0);
    free(full_plan);
    puts("GPU catalog scenarios: deterministic indices, backend-local IDs, partition order and bounds");
    free(catalog);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="gpu-catalog-") as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "catalog.c"
            executable = tmp_path / "catalog"
            harness.write_text(source)
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                 "-I", str(ROOT / "src"), str(harness), str(ROOT / "src/hybrid580-gpu-catalog.c"),
                 "-o", str(executable)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
            self.assertIn("GPU catalog scenarios:", result.stdout)


if __name__ == "__main__":
    unittest.main()
