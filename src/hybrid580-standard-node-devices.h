/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_STANDARD_NODE_DEVICES_H
#define HYBRID580_STANDARD_NODE_DEVICES_H

#include "hybrid580-gpu-catalog.h"
#include "hybrid580-standard-node-map.h"

#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <sys/types.h>
struct file_operations;
#endif

/* Registers standard NVIDIA major 195 with the R580 control minor and the
 * BDF-ordered GPU minors. The catalog is borrowed until unregister returns.
 * Registration is opt-in and fails if any other driver owns that major.
 */
int hybrid580_standard_nodes_register_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog,
    const struct file_operations *fops);
void hybrid580_standard_nodes_unregister_v1(void);
int hybrid580_standard_nodes_active_v1(void);
int hybrid580_standard_nodes_resolve_v1(
    hybrid580_u32 minor,
    struct hybrid580_standard_node_resolution_v1 *resolution);
int hybrid580_standard_nodes_catalog_matches_v1(
    const struct hybrid580_gpu_catalog_v1 *catalog);

#endif
