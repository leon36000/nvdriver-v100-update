/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_GPU_CATALOG_H
#define HYBRID580_GPU_CATALOG_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u8 hybrid580_u8;
typedef __u16 hybrid580_u16;
typedef __u32 hybrid580_u32;
#else
#include <stdint.h>
typedef uint8_t hybrid580_u8;
typedef uint16_t hybrid580_u16;
typedef uint32_t hybrid580_u32;
#endif

#define HYBRID580_GPU_MAX_BACKEND_DEVICES 248U
#define HYBRID580_GPU_MAX_DEVICES (2U * HYBRID580_GPU_MAX_BACKEND_DEVICES)
#define HYBRID580_GPU_MAX_PROBED_IDS 32U
#define HYBRID580_GPU_BDF_SIZE 16U

#define HYBRID580_BACKEND_LEGACY 0U
#define HYBRID580_BACKEND_OPEN 1U
#define HYBRID580_GPU_FRONT_ID_INVALID 0U

/* Backend-local inventory record. backend_minor and backend_gpu_id are
 * private to one RM instance and must never be exposed as merged IDs. */
struct hybrid580_gpu_backend_record_v1 {
    char bdf[HYBRID580_GPU_BDF_SIZE];
    hybrid580_u32 backend_minor;
    hybrid580_u32 backend_gpu_id;
    hybrid580_u16 domain;
    hybrid580_u8 bus;
    hybrid580_u8 slot;
    hybrid580_u8 function;
    hybrid580_u8 reserved;
    hybrid580_u16 vendor_id;
    hybrid580_u16 device_id;
};

struct hybrid580_gpu_catalog_entry_v1 {
    char bdf[HYBRID580_GPU_BDF_SIZE];
    hybrid580_u32 frontend_index;
    hybrid580_u32 frontend_gpu_id;
    hybrid580_u32 backend;
    hybrid580_u32 backend_minor;
    hybrid580_u32 backend_gpu_id;
    hybrid580_u16 domain;
    hybrid580_u8 bus;
    hybrid580_u8 slot;
    hybrid580_u8 function;
    hybrid580_u8 reserved;
    hybrid580_u16 vendor_id;
    hybrid580_u16 device_id;
};

struct hybrid580_gpu_catalog_v1 {
    hybrid580_u32 count;
    struct hybrid580_gpu_catalog_entry_v1 entries[HYBRID580_GPU_MAX_DEVICES];
};

struct hybrid580_gpu_attach_partition_v1 {
    hybrid580_u32 count;
    hybrid580_u32 frontend_gpu_ids[HYBRID580_GPU_MAX_DEVICES];
    hybrid580_u32 backend_gpu_ids[HYBRID580_GPU_MAX_DEVICES];
};

/* Pure mapping result for one NVIDIA attach request. frontend_gpu_ids keeps
 * the caller's original order; each backend partition keeps its subsequence
 * order. This is a planning primitive only, not an attach transaction. */
struct hybrid580_gpu_attach_plan_v1 {
    hybrid580_u32 count;
    hybrid580_u32 frontend_gpu_ids[HYBRID580_GPU_MAX_DEVICES];
    struct hybrid580_gpu_attach_partition_v1 backends[2];
};

/* Merge two backend-local inventories into one deterministic BDF-ordered
 * index space. Reject ambiguous duplicate BDFs and local-minor collisions.
 * On failure, output is empty; callers must allocate the catalog off-stack. */
int hybrid580_gpu_catalog_build_v1(
    const struct hybrid580_gpu_backend_record_v1 *legacy,
    hybrid580_u32 legacy_count,
    const struct hybrid580_gpu_backend_record_v1 *open,
    hybrid580_u32 open_count,
    struct hybrid580_gpu_catalog_v1 *catalog);

/* Resolve a synthetic, nonzero frontend GPU ID to its backend-local record.
 * IDs are catalog order + 1 so zero remains available as the driver's
 * attach-list empty value. This is not yet NVIDIA's public RM ABI. */
int hybrid580_gpu_catalog_lookup_front_id_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 frontend_gpu_id,
    struct hybrid580_gpu_catalog_entry_v1 *entry);

/* Resolve an R580-local device minor without confusing equal minor numbers
 * owned by the other backend. Reject malformed or ambiguous catalog state. */
int hybrid580_gpu_catalog_lookup_backend_minor_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 backend,
    hybrid580_u32 backend_minor,
    struct hybrid580_gpu_catalog_entry_v1 *entry);

/* Resolve a backend-local RM GPU ID. Ambiguous or malformed catalog entries
 * fail closed; callers must never assume IDs from two RM instances coincide. */
int hybrid580_gpu_catalog_lookup_backend_gpu_id_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 backend,
    hybrid580_u32 backend_gpu_id,
    struct hybrid580_gpu_catalog_entry_v1 *entry);

/* Merge NVIDIA's fixed GPU_GET_PROBED_IDS tables into the frontend namespace.
 * Input tables must contain compact IDs followed only by invalid_id. GPU
 * flags stay paired with gpuIds; excluded IDs have no flags. Results are
 * BDF-sorted and written only after every row maps uniquely. input_capacity
 * and output_capacity are bounded by 32 (the pinned R580 SDK ABI). */
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
    hybrid580_u32 *frontend_excluded_gpu_count);

/* Translate a frontend ID list into backend-local ID subsequences without
 * changing caller order. Duplicate requests and native zero placeholders are
 * preserved in the original request view; zero placeholders are omitted from
 * backend subsequences. Unknown IDs and unattachable local IDs fail atomically. */
int hybrid580_gpu_catalog_plan_attach_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    const hybrid580_u32 *frontend_gpu_ids,
    hybrid580_u32 count,
    struct hybrid580_gpu_attach_plan_v1 *plan);

#endif
