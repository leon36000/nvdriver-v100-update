/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_GPU_SESSION_H
#define HYBRID580_GPU_SESSION_H

#include <linux/fs.h>
#include <nvtypes.h>
#include "hybrid580-gpu-catalog.h"

struct hybrid580_gpu_session;
struct hybrid580_control_session;
struct nv_ioctl_card_info;

/* Internal kernel API. The BDF must match the selected backend GPU. The
 * session retains the genuine NVIDIA GPU file created by nvidia_open().
 * Callers hold a session reference across projected lookups and ioctls.
 */
int hybrid580_open_gpu_session_create_v1(
    struct file *anchor, NvU32 minor, const char *expected_bdf,
    struct hybrid580_gpu_session **out);
int hybrid580_open_gpu_session_create_by_bdf_v1(
    struct file *anchor, const char *expected_bdf,
    struct hybrid580_gpu_session **out);
void hybrid580_open_gpu_session_get_v1(struct hybrid580_gpu_session *session);
void hybrid580_open_gpu_session_put_v1(struct hybrid580_gpu_session *session);
struct file *hybrid580_open_gpu_session_file_v1(
    struct hybrid580_gpu_session *session);
long hybrid580_open_gpu_session_ioctl_v1(
    struct hybrid580_gpu_session *session, unsigned int command,
    unsigned long argument);
/* Reproduce NV_ESC_REGISTER_FD using the exact pinned control session already
 * validated by the hybrid frontend. The provider retains the native control
 * file reference in the GPU file's RM private state until GPU close. */
int hybrid580_open_gpu_session_register_control_v1(
    struct hybrid580_gpu_session *gpu,
    struct hybrid580_control_session *control);
int hybrid580_open_gpu_inventory_v1(
    struct hybrid580_gpu_backend_record_v1 *records,
    NvU32 capacity, NvU32 *count);
int hybrid580_open_gpu_card_info_v1(
    struct nv_ioctl_card_info *records, NvU32 capacity, NvU32 *count);

#endif
