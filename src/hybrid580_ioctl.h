/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_IOCTL_H
#define HYBRID580_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include "hybrid580-gpu-catalog.h"

#define HYBRID580_IOCTL_MAGIC 'H'
#define HYBRID580_OPEN_GPU_V1 1U
#define HYBRID580_GET_GPU_COUNT_V1 2U
#define HYBRID580_GET_GPU_INFO_V1 3U

/* Experimental descriptor-opening request on /dev/hybrid580ctl.
 * Inputs: struct_size, zero flags, canonical PCI BDF in bdf, zero outputs.
 * Outputs: a CLOEXEC GPU-file descriptor and the backend that owns the BDF.
 * This is a project test/control ABI, not NVIDIA's CUDA or RM ABI.
 */
struct hybrid580_open_gpu_v1 {
    __u32 struct_size;
    __u32 flags;
    char bdf[16];
    __s32 gpu_fd;
    __u32 backend;
    __u32 reserved[2];
};

/* Private inventory query for validating the two-backend index map. This is
 * not NVIDIA's NV_ESC_CARD_INFO or the CUDA Driver API. */
struct hybrid580_gpu_count_v1 {
    __u32 struct_size;
    __u32 count;
    __u32 reserved[2];
};

struct hybrid580_gpu_info_v1 {
    __u32 struct_size;
    __u32 index;
    struct hybrid580_gpu_catalog_entry_v1 entry;
    __u32 reserved[2];
};

#define HYBRID580_IOCTL_OPEN_GPU \
    _IOWR(HYBRID580_IOCTL_MAGIC, HYBRID580_OPEN_GPU_V1, struct hybrid580_open_gpu_v1)
#define HYBRID580_IOCTL_GET_GPU_COUNT \
    _IOWR(HYBRID580_IOCTL_MAGIC, HYBRID580_GET_GPU_COUNT_V1, struct hybrid580_gpu_count_v1)
#define HYBRID580_IOCTL_GET_GPU_INFO \
    _IOWR(HYBRID580_IOCTL_MAGIC, HYBRID580_GET_GPU_INFO_V1, struct hybrid580_gpu_info_v1)

#endif
