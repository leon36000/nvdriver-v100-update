/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_STANDARD_NODE_MAP_H
#define HYBRID580_STANDARD_NODE_MAP_H

#include "hybrid580-gpu-catalog.h"

enum hybrid580_standard_node_kind_v1 {
    HYBRID580_STANDARD_NODE_INVALID = 0,
    HYBRID580_STANDARD_NODE_CONTROL = 1,
    HYBRID580_STANDARD_NODE_GPU = 2,
};

/* Resolution of one R580-compatible standard char-device minor. */
struct hybrid580_standard_node_resolution_v1 {
    hybrid580_u32 kind;
    hybrid580_u32 frontend_index;
    hybrid580_u32 frontend_gpu_id;
    hybrid580_u32 backend;
    hybrid580_u32 backend_minor;
    hybrid580_u32 backend_gpu_id;
    char bdf[HYBRID580_GPU_BDF_SIZE];
};

/* Resolve the SDK-defined control minor or BDF-ordered GPU minor. On error,
 * output is cleared. Only regular NVIDIA minors and the control minor exist;
 * reserved gaps and stale/out-of-range GPU nodes fail closed.
 */
int hybrid580_standard_node_resolve_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    hybrid580_u32 minor,
    struct hybrid580_standard_node_resolution_v1 *resolution);

#endif
