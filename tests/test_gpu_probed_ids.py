# SPDX-License-Identifier: MIT
"""CPU regression tests for the fixed-size merged GPU probed-ID table."""

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class GpuProbedIdsTests(unittest.TestCase):
    def test_merge_is_bdf_ordered_typed_and_failure_atomic(self):
        source = r'''#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hybrid580-gpu-catalog.h"

#define CAP 4U
#define INVALID 0xffffffffU

static struct hybrid580_gpu_backend_record_v1 record(
    const char *bdf, unsigned int minor, unsigned int gpu_id,
    unsigned int bus)
{
    struct hybrid580_gpu_backend_record_v1 r = {0};
    strcpy(r.bdf, bdf);
    r.backend_minor = minor;
    r.backend_gpu_id = gpu_id;
    r.bus = bus;
    r.vendor_id = 0x10de;
    r.device_id = 0x2684;
    return r;
}

static void fill_invalid(unsigned int *ids)
{
    for (unsigned int i = 0; i < CAP; ++i)
        ids[i] = INVALID;
}

int main(void)
{
    struct hybrid580_gpu_catalog_v1 *catalog = calloc(1, sizeof(*catalog));
    assert(catalog != NULL);
    struct hybrid580_gpu_backend_record_v1 legacy[] = {
        record("0000:81:00.0", 0, 5, 0x81),
        record("0000:03:00.0", 1, 7, 0x03),
    };
    struct hybrid580_gpu_backend_record_v1 open[] = {
        record("0000:02:00.0", 0, 512, 0x02),
        record("0000:90:00.0", 1, 513, 0x90),
    };
    assert(hybrid580_gpu_catalog_build_v1(legacy, 2, open, 2, catalog) == 0);

    unsigned int legacy_ids[CAP], legacy_excluded[CAP], legacy_flags[CAP] = { 8, 2, 0, 0 };
    unsigned int open_ids[CAP], open_excluded[CAP], open_flags[CAP] = { 1, 4, 0, 0 };
    unsigned int result_ids[CAP], result_excluded[CAP], result_flags[CAP];
    unsigned int result_count = 99, excluded_count = 99;
    fill_invalid(legacy_ids); fill_invalid(legacy_excluded);
    fill_invalid(open_ids); fill_invalid(open_excluded);
    legacy_ids[0] = 5;
    legacy_excluded[0] = 7;
    open_ids[0] = 512;
    open_excluded[0] = 513;

    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, CAP,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == 0);
    assert(result_count == 2 && excluded_count == 2);
    assert(result_ids[0] == 1 && result_flags[0] == 1);
    assert(result_ids[1] == 3 && result_flags[1] == 8);
    assert(result_excluded[0] == 2 && result_excluded[1] == 4);
    for (unsigned int i = result_count; i < CAP; ++i)
        assert(result_ids[i] == INVALID && result_flags[i] == 0);
    for (unsigned int i = excluded_count; i < CAP; ++i)
        assert(result_excluded[i] == INVALID);

    /* A hole before a later valid row is malformed, not a shorter list. */
    legacy_ids[1] = INVALID;
    legacy_ids[2] = 5;
    result_ids[0] = 0x12345678;
    result_count = 77;
    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, CAP,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == -EINVAL);
    assert(result_ids[0] == 0x12345678 && result_count == 77);

    fill_invalid(legacy_ids); legacy_ids[0] = 0xdeadbeef;
    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, CAP,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == -ENOENT);

    fill_invalid(legacy_ids); legacy_ids[0] = 5; legacy_ids[1] = 5;
    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, CAP,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == -EEXIST);

    fill_invalid(legacy_ids); legacy_ids[0] = 5;
    legacy_excluded[0] = 5;
    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, CAP,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == -EEXIST);
    legacy_excluded[0] = 7;

    /* The merged ABI has a fixed capacity; it must never silently truncate. */
    fill_invalid(legacy_ids); fill_invalid(open_ids);
    legacy_ids[0] = 5; open_ids[0] = 512;
    result_ids[0] = 0x87654321;
    result_count = 55;
    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, 1,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == -E2BIG);
    assert(result_ids[0] == 0x87654321 && result_count == 55);

    /* A corrupt catalog with duplicate backend IDs is detected as ambiguous. */
    catalog->entries[2].backend_gpu_id = catalog->entries[1].backend_gpu_id;
    fill_invalid(legacy_ids); legacy_ids[0] = 7;
    assert(hybrid580_gpu_catalog_merge_probed_ids_v1(catalog, INVALID,
        legacy_ids, legacy_excluded, legacy_flags,
        open_ids, open_excluded, open_flags, CAP, CAP,
        result_ids, result_excluded, result_flags,
        &result_count, &excluded_count) == -EEXIST);

    puts("GPU probed-ID scenarios: BDF merge, flag pairing, malformed tables, unknown IDs, ambiguity and overflow");
    free(catalog);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="gpu-probed-ids-") as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "probed-ids.c"
            executable = tmp_path / "probed-ids"
            harness.write_text(source)
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                 "-I", str(ROOT / "src"), str(harness), str(ROOT / "src/hybrid580-gpu-catalog.c"),
                 "-o", str(executable)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(executable)], check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("GPU probed-ID scenarios:", result.stdout)


if __name__ == "__main__":
    unittest.main()
