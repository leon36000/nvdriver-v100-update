/* SPDX-License-Identifier: MIT */
#include "hybrid580-gpu-catalog.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

static int hybrid580_gpu_hex_value(char value, hybrid580_u32 *digit)
{
    if (value >= '0' && value <= '9')
        *digit = (hybrid580_u32)(value - '0');
    else if (value >= 'a' && value <= 'f')
        *digit = (hybrid580_u32)(value - 'a') + 10U;
    else
        return -EINVAL;
    return 0;
}

static int hybrid580_gpu_parse_hex(const char *bdf, hybrid580_u32 first,
                                   hybrid580_u32 count, hybrid580_u32 *value)
{
    hybrid580_u32 result = 0, digit, i;
    for (i = 0; i < count; ++i) {
        if (hybrid580_gpu_hex_value(bdf[first + i], &digit) != 0)
            return -EINVAL;
        result = (result << 4) | digit;
    }
    *value = result;
    return 0;
}

static int hybrid580_gpu_record_valid(
    const struct hybrid580_gpu_backend_record_v1 *record)
{
    hybrid580_u32 domain, bus, slot, function, i;

    if (record->backend_minor >= HYBRID580_GPU_MAX_BACKEND_DEVICES ||
        record->reserved != 0 ||
        record->bdf[4] != ':' || record->bdf[7] != ':' ||
        record->bdf[10] != '.')
        return -EINVAL;
    for (i = 0; i < 12; ++i)
        if (record->bdf[i] == '\0')
            return -EINVAL;
    for (i = 12; i < HYBRID580_GPU_BDF_SIZE; ++i)
        if (record->bdf[i] != '\0')
            return -EINVAL;
    if (hybrid580_gpu_parse_hex(record->bdf, 0, 4, &domain) != 0 ||
        hybrid580_gpu_parse_hex(record->bdf, 5, 2, &bus) != 0 ||
        hybrid580_gpu_parse_hex(record->bdf, 8, 2, &slot) != 0 ||
        hybrid580_gpu_parse_hex(record->bdf, 11, 1, &function) != 0 ||
        slot > 31U || function > 7U || domain != record->domain ||
        bus != record->bus || slot != record->slot ||
        function != record->function || record->vendor_id != 0x10deU)
        return -EINVAL;
    return 0;
}

static int hybrid580_gpu_append(
    const struct hybrid580_gpu_backend_record_v1 *records,
    hybrid580_u32 count, hybrid580_u32 backend,
    struct hybrid580_gpu_catalog_v1 *catalog)
{
    hybrid580_u32 i, j;

    for (i = 0; i < count; ++i) {
        struct hybrid580_gpu_catalog_entry_v1 *entry;
        if (hybrid580_gpu_record_valid(&records[i]) != 0)
            return -EINVAL;
        for (j = 0; j < catalog->count; ++j) {
            const struct hybrid580_gpu_catalog_entry_v1 *prior =
                &catalog->entries[j];
            if (strcmp(prior->bdf, records[i].bdf) == 0)
                return -EEXIST;
            if (prior->backend == backend &&
                prior->backend_minor == records[i].backend_minor)
                return -EEXIST;
            if (records[i].backend_gpu_id != 0 &&
                prior->backend == backend &&
                prior->backend_gpu_id == records[i].backend_gpu_id)
                return -EEXIST;
        }
        entry = &catalog->entries[catalog->count++];
        memcpy(entry->bdf, records[i].bdf, sizeof(entry->bdf));
        entry->backend = backend;
        entry->backend_minor = records[i].backend_minor;
        entry->backend_gpu_id = records[i].backend_gpu_id;
        entry->domain = records[i].domain;
        entry->bus = records[i].bus;
        entry->slot = records[i].slot;
        entry->function = records[i].function;
        entry->vendor_id = records[i].vendor_id;
        entry->device_id = records[i].device_id;
    }
    return 0;
}

static void hybrid580_gpu_catalog_sort(struct hybrid580_gpu_catalog_v1 *catalog)
{
    hybrid580_u32 i;
    for (i = 1; i < catalog->count; ++i) {
        struct hybrid580_gpu_catalog_entry_v1 item = catalog->entries[i];
        hybrid580_u32 j = i;
        while (j != 0 && strcmp(catalog->entries[j - 1].bdf, item.bdf) > 0) {
            catalog->entries[j] = catalog->entries[j - 1];
            --j;
        }
        catalog->entries[j] = item;
    }
    for (i = 0; i < catalog->count; ++i) {
        catalog->entries[i].frontend_index = i;
        catalog->entries[i].frontend_gpu_id = i + 1U;
    }
}

static int hybrid580_gpu_catalog_fail(struct hybrid580_gpu_catalog_v1 *catalog,
                                      int error)
{
    memset(catalog, 0, sizeof(*catalog));
    return error;
}

int hybrid580_gpu_catalog_build_v1(
    const struct hybrid580_gpu_backend_record_v1 *legacy,
    hybrid580_u32 legacy_count,
    const struct hybrid580_gpu_backend_record_v1 *open,
    hybrid580_u32 open_count,
    struct hybrid580_gpu_catalog_v1 *catalog)
{
    int rc;

    if (catalog == NULL)
        return -EINVAL;
    memset(catalog, 0, sizeof(*catalog));
    if (legacy_count > HYBRID580_GPU_MAX_BACKEND_DEVICES ||
        open_count > HYBRID580_GPU_MAX_BACKEND_DEVICES)
        return -E2BIG;
    if ((legacy_count != 0 && legacy == NULL) ||
        (open_count != 0 && open == NULL))
        return -EINVAL;

    rc = hybrid580_gpu_append(legacy, legacy_count,
                              HYBRID580_BACKEND_LEGACY, catalog);
    if (rc != 0)
        return hybrid580_gpu_catalog_fail(catalog, rc);
    rc = hybrid580_gpu_append(open, open_count,
                              HYBRID580_BACKEND_OPEN, catalog);
    if (rc != 0)
        return hybrid580_gpu_catalog_fail(catalog, rc);

    hybrid580_gpu_catalog_sort(catalog);
    return 0;
}

int hybrid580_gpu_catalog_lookup_front_id_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 frontend_gpu_id,
    struct hybrid580_gpu_catalog_entry_v1 *entry)
{
    hybrid580_u32 index;
    const struct hybrid580_gpu_catalog_entry_v1 *source;

    if (catalog == NULL || entry == NULL ||
        frontend_gpu_id == HYBRID580_GPU_FRONT_ID_INVALID ||
        catalog->count > HYBRID580_GPU_MAX_DEVICES)
        return -EINVAL;
    if (frontend_gpu_id > catalog->count)
        return -ENOENT;

    index = frontend_gpu_id - 1U;
    source = &catalog->entries[index];
    if (source->frontend_index != index ||
        source->frontend_gpu_id != frontend_gpu_id)
        return -EINVAL;
    *entry = *source;
    return 0;
}

int hybrid580_gpu_catalog_lookup_backend_minor_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 backend,
    hybrid580_u32 backend_minor,
    struct hybrid580_gpu_catalog_entry_v1 *entry)
{
    hybrid580_u32 i;
    const struct hybrid580_gpu_catalog_entry_v1 *match = NULL;

    if (catalog == NULL || entry == NULL ||
        catalog->count > HYBRID580_GPU_MAX_DEVICES ||
        backend > HYBRID580_BACKEND_OPEN ||
        backend_minor >= HYBRID580_GPU_MAX_BACKEND_DEVICES)
        return -EINVAL;

    for (i = 0; i < catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *candidate =
            &catalog->entries[i];
        if (candidate->backend != backend ||
            candidate->backend_minor != backend_minor)
            continue;
        if (match != NULL)
            return -EEXIST;
        if (candidate->frontend_index != i ||
            candidate->frontend_gpu_id != i + 1U)
            return -EINVAL;
        match = candidate;
    }
    if (match == NULL)
        return -ENOENT;
    *entry = *match;
    return 0;
}

static int hybrid580_gpu_catalog_find_backend_gpu_id_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 backend,
    hybrid580_u32 backend_gpu_id,
    const struct hybrid580_gpu_catalog_entry_v1 **entry)
{
    hybrid580_u32 i;
    const struct hybrid580_gpu_catalog_entry_v1 *match = NULL;

    if (catalog == NULL || entry == NULL ||
        catalog->count > HYBRID580_GPU_MAX_DEVICES ||
        backend > HYBRID580_BACKEND_OPEN)
        return -EINVAL;

    for (i = 0; i < catalog->count; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *candidate =
            &catalog->entries[i];
        if (candidate->frontend_index != i ||
            candidate->frontend_gpu_id != i + 1U ||
            candidate->backend > HYBRID580_BACKEND_OPEN)
            return -EINVAL;
        if (candidate->backend != backend ||
            candidate->backend_gpu_id != backend_gpu_id)
            continue;
        if (match != NULL)
            return -EEXIST;
        match = candidate;
    }
    if (match == NULL)
        return -ENOENT;
    *entry = match;
    return 0;
}

int hybrid580_gpu_catalog_lookup_backend_gpu_id_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 backend,
    hybrid580_u32 backend_gpu_id,
    struct hybrid580_gpu_catalog_entry_v1 *entry)
{
    const struct hybrid580_gpu_catalog_entry_v1 *match;
    int rc;

    if (entry == NULL)
        return -EINVAL;
    rc = hybrid580_gpu_catalog_find_backend_gpu_id_v1(
        catalog, backend, backend_gpu_id, &match);
    if (rc != 0)
        return rc;
    *entry = *match;
    return 0;
}

struct hybrid580_probed_id_item {
    hybrid580_u32 catalog_index;
    hybrid580_u32 flags;
};

static int hybrid580_gpu_catalog_collect_probed_list_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 backend,
    hybrid580_u32 invalid_id,
    const hybrid580_u32 *ids,
    const hybrid580_u32 *flags,
    hybrid580_u32 input_capacity,
    hybrid580_u32 output_capacity,
    struct hybrid580_probed_id_item *items,
    hybrid580_u32 *item_count)
{
    hybrid580_u32 i, j;
    hybrid580_u32 saw_invalid = 0;

    if (ids == NULL || items == NULL || item_count == NULL)
        return -EINVAL;
    for (i = 0; i < input_capacity; ++i) {
        const struct hybrid580_gpu_catalog_entry_v1 *entry;
        hybrid580_u32 position;
        int rc;

        if (ids[i] == invalid_id) {
            saw_invalid = 1U;
            continue;
        }
        if (saw_invalid)
            return -EINVAL;
        if (*item_count >= output_capacity)
            return -E2BIG;
        rc = hybrid580_gpu_catalog_find_backend_gpu_id_v1(
            catalog, backend, ids[i], &entry);
        if (rc != 0)
            return rc;
        for (j = 0; j < *item_count; ++j)
            if (items[j].catalog_index ==
                    (hybrid580_u32)(entry - catalog->entries) ||
                strcmp(catalog->entries[items[j].catalog_index].bdf,
                       entry->bdf) == 0)
                return -EEXIST;

        position = *item_count;
        while (position != 0 &&
               strcmp(catalog->entries[items[position - 1U].catalog_index].bdf,
                      entry->bdf) > 0) {
            items[position] = items[position - 1U];
            --position;
        }
        items[position].catalog_index =
            (hybrid580_u32)(entry - catalog->entries);
        items[position].flags = flags == NULL ? 0U : flags[i];
        ++*item_count;
    }
    return 0;
}

int hybrid580_gpu_catalog_merge_probed_ids_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 invalid_id,
    const hybrid580_u32 *legacy_gpu_ids,
    const hybrid580_u32 *legacy_excluded_gpu_ids,
    const hybrid580_u32 *legacy_gpu_flags,
    const hybrid580_u32 *open_gpu_ids,
    const hybrid580_u32 *open_excluded_gpu_ids,
    const hybrid580_u32 *open_gpu_flags,
    hybrid580_u32 input_capacity,
    hybrid580_u32 output_capacity,
    hybrid580_u32 *frontend_gpu_ids,
    hybrid580_u32 *frontend_excluded_gpu_ids,
    hybrid580_u32 *frontend_gpu_flags,
    hybrid580_u32 *frontend_gpu_count,
    hybrid580_u32 *frontend_excluded_gpu_count)
{
    struct hybrid580_probed_id_item gpu_items[HYBRID580_GPU_MAX_PROBED_IDS];
    struct hybrid580_probed_id_item excluded_items[HYBRID580_GPU_MAX_PROBED_IDS];
    hybrid580_u32 gpu_count = 0, excluded_count = 0, i, j;
    int rc;

    if (catalog == NULL || catalog->count > HYBRID580_GPU_MAX_DEVICES ||
        legacy_gpu_ids == NULL || legacy_excluded_gpu_ids == NULL ||
        legacy_gpu_flags == NULL || open_gpu_ids == NULL ||
        open_excluded_gpu_ids == NULL || open_gpu_flags == NULL ||
        frontend_gpu_ids == NULL || frontend_excluded_gpu_ids == NULL ||
        frontend_gpu_flags == NULL || frontend_gpu_count == NULL ||
        frontend_excluded_gpu_count == NULL || input_capacity == 0 ||
        input_capacity > HYBRID580_GPU_MAX_PROBED_IDS || output_capacity == 0 ||
        output_capacity > HYBRID580_GPU_MAX_PROBED_IDS)
        return -EINVAL;

    rc = hybrid580_gpu_catalog_collect_probed_list_v1(
        catalog, HYBRID580_BACKEND_LEGACY, invalid_id, legacy_gpu_ids,
        legacy_gpu_flags, input_capacity, output_capacity, gpu_items, &gpu_count);
    if (rc != 0)
        return rc;
    rc = hybrid580_gpu_catalog_collect_probed_list_v1(
        catalog, HYBRID580_BACKEND_OPEN, invalid_id, open_gpu_ids,
        open_gpu_flags, input_capacity, output_capacity, gpu_items, &gpu_count);
    if (rc != 0)
        return rc;
    rc = hybrid580_gpu_catalog_collect_probed_list_v1(
        catalog, HYBRID580_BACKEND_LEGACY, invalid_id, legacy_excluded_gpu_ids,
        NULL, input_capacity, output_capacity, excluded_items, &excluded_count);
    if (rc != 0)
        return rc;
    rc = hybrid580_gpu_catalog_collect_probed_list_v1(
        catalog, HYBRID580_BACKEND_OPEN, invalid_id, open_excluded_gpu_ids,
        NULL, input_capacity, output_capacity, excluded_items, &excluded_count);
    if (rc != 0)
        return rc;

    for (i = 0; i < gpu_count; ++i)
        for (j = 0; j < excluded_count; ++j)
            if (gpu_items[i].catalog_index == excluded_items[j].catalog_index ||
                strcmp(catalog->entries[gpu_items[i].catalog_index].bdf,
                       catalog->entries[excluded_items[j].catalog_index].bdf) == 0)
                return -EEXIST;

    /* Publish only after both backends and both compact lists validate. */
    for (i = 0; i < output_capacity; ++i) {
        frontend_gpu_ids[i] = invalid_id;
        frontend_excluded_gpu_ids[i] = invalid_id;
        frontend_gpu_flags[i] = 0;
    }
    for (i = 0; i < gpu_count; ++i) {
        frontend_gpu_ids[i] =
            catalog->entries[gpu_items[i].catalog_index].frontend_gpu_id;
        frontend_gpu_flags[i] = gpu_items[i].flags;
    }
    for (i = 0; i < excluded_count; ++i)
        frontend_excluded_gpu_ids[i] =
            catalog->entries[excluded_items[i].catalog_index].frontend_gpu_id;
    *frontend_gpu_count = gpu_count;
    *frontend_excluded_gpu_count = excluded_count;
    return 0;
}

static int hybrid580_gpu_catalog_fail_attach_plan_v1(
    struct hybrid580_gpu_attach_plan_v1 *plan, int error)
{
    memset(plan, 0, sizeof(*plan));
    return error;
}

int hybrid580_gpu_catalog_plan_attach_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    const hybrid580_u32 *frontend_gpu_ids,
    hybrid580_u32 count,
    struct hybrid580_gpu_attach_plan_v1 *plan)
{
    hybrid580_u32 i, j;
    int rc;

    if (plan == NULL)
        return -EINVAL;
    memset(plan, 0, sizeof(*plan));
    if (catalog == NULL || catalog->count > HYBRID580_GPU_MAX_DEVICES)
        return -EINVAL;
    if (count == 0)
        return -EINVAL;
    if (count > HYBRID580_GPU_MAX_DEVICES)
        return -E2BIG;
    if (frontend_gpu_ids == NULL)
        return -EINVAL;

    for (i = 0; i < count; ++i) {
        struct hybrid580_gpu_catalog_entry_v1 entry;
        struct hybrid580_gpu_attach_partition_v1 *partition;
        if (frontend_gpu_ids[i] == HYBRID580_GPU_FRONT_ID_INVALID) {
            /* NV_ESC_ATTACH_GPUS_TO_FD accepts zero placeholders and the
             * R580 wrapper stores then skips them. Preserve them in the
             * original request view, but do not route them to either RM. */
            plan->frontend_gpu_ids[i] = HYBRID580_GPU_FRONT_ID_INVALID;
            plan->count = i + 1U;
            continue;
        }
        rc = hybrid580_gpu_catalog_lookup_front_id_v1(
            catalog, frontend_gpu_ids[i], &entry);
        if (rc != 0)
            goto fail;
        if ((entry.backend != HYBRID580_BACKEND_LEGACY &&
             entry.backend != HYBRID580_BACKEND_OPEN) ||
            entry.backend_gpu_id == 0)
            goto invalid;

        partition = &plan->backends[entry.backend];
        for (j = 0; j < partition->count; ++j)
            if (partition->backend_gpu_ids[j] == entry.backend_gpu_id &&
                partition->frontend_gpu_ids[j] != frontend_gpu_ids[i])
                goto duplicate;
        if (partition->count >= HYBRID580_GPU_MAX_DEVICES)
            goto too_big;

        plan->frontend_gpu_ids[i] = frontend_gpu_ids[i];
        plan->count = i + 1U;
        j = partition->count++;
        partition->frontend_gpu_ids[j] = frontend_gpu_ids[i];
        partition->backend_gpu_ids[j] = entry.backend_gpu_id;
    }
    return 0;

duplicate:
    return hybrid580_gpu_catalog_fail_attach_plan_v1(plan, -EEXIST);
invalid:
    return hybrid580_gpu_catalog_fail_attach_plan_v1(plan, -EINVAL);
too_big:
    return hybrid580_gpu_catalog_fail_attach_plan_v1(plan, -E2BIG);
fail:
    return hybrid580_gpu_catalog_fail_attach_plan_v1(plan, rc);
}
