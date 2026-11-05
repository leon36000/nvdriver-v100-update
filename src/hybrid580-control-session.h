/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_CONTROL_SESSION_H
#define HYBRID580_CONTROL_SESSION_H

#include "rm_session_endpoint.h"
#include <nv-ioctl.h>
#include <nvos.h>
#include <ctrl/ctrl0000/ctrl0000gpu.h>
#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>
#include <class/cl0080.h>
#include <class/cl50a0.h>
#include <class/cl003e.h>
#include <class/cl0040.h>
#include <class/cl90f1.h>
#include <class/cla06c.h>
#include <class/cl9067.h>
#include <class/cl90e6.h>
#include <class/cl2080.h>
#include <ctrl/ctrl2080/ctrl2080gpu.h>
#include <class/cl2081.h>
#include <class/cl00de.h>
#include <class/cl503c.h>
#include <class/clc361.h>
#include <class/clc661.h>
#include <class/clc36f.h>
#include <class/clc96f.h>
#include <class/clc3b5.h>
#include <class/clc3c0.h>
#include <class/clcab5.h>
#include <class/clcec0.h>
#include <class/cl83de.h>
#include <ctrl/ctrl83de.h>
#include <ctrl/ctrl2080/ctrl2080gr.h>
#include <ctrl/ctrl90e6.h>
#include <ctrl/ctrl503c.h>
#include <alloc/alloc_channel.h>
#include <nvos.h>

struct file;
struct hybrid580_control_session;
/* Private kernel API, not a userspace/CUDA ABI. Create/invoke/put-final run in
 * process context. Anchor is caller-owned and held throughout creation. This
 * opens only an unpublished control file, never a GPU or userspace fd.
 * Calls execute with current caller credentials; no implicit worker override.
 * Caller holds a session reference through invoke and while publishing a
 * projection mapping. get/file may run atomically. file returns one get_file
 * reference; frontend owns and must release it. Endpoint copies take no refs.
 * Serialize frontend close/unpublication before dropping its session refs.
 * No final put while holding locks needed by vendor release. fput can defer
 * RM cleanup: return from final put does not certify synchronous teardown.
 * Invoke accepts kernel-owned ROOT alloc32/64 and root FREE packets only,
 * without embedded pointers. It never retains payload after returning.
 * Status return is transport; embedded NVOS status remains the RM's output.
 */
int hybrid580_open_control_session_create_v1(struct file *anchor,
    struct hybrid580_control_session **out,
    struct hybrid_rm_session_endpoint_v1 *endpoint);
void hybrid580_open_control_session_get_v1(struct hybrid580_control_session *);
void hybrid580_open_control_session_put_v1(struct hybrid580_control_session *);
struct file *hybrid580_open_control_session_file_v1(struct hybrid580_control_session *);
int hybrid580_open_control_session_attach_v1(
    struct hybrid580_control_session *, const NvU32 *gpu_ids, NvU32 count);
/* Preserve the vendor NV_ESC_RM_MAP_MEMORY path, including its fd-based
 * mmap-context installation and native RM security checks. The caller supplies
 * a kernel-owned fixed packet; fd is the caller's live descriptor in current's
 * fd table and must resolve through the registered file-projection hook.
 * Transport status and NVOS33/NVOS34 embedded status remain distinct. */
NV_STATUS hybrid580_open_control_session_map_memory_v1(
    struct hybrid580_control_session *, NVOS33_PARAMETERS *params, NvS32 fd);
NV_STATUS hybrid580_open_control_session_unmap_memory_v1(
    struct hybrid580_control_session *, NVOS34_PARAMETERS *params);
/* Update a process-local CPU mapping key for one tracked RM memory/channel
 * object. NVOS56's NvP64 fields are scalar address values, not buffers: keep
 * their bits unchanged and invoke synchronously in the calling process so RM
 * resolves its per-process mapping. The packet is kernel-owned and fixed-size. */
NV_STATUS hybrid580_open_control_session_update_device_mapping_info_v1(
    struct hybrid580_control_session *, NVOS56_PARAMETERS *params);
/* NVIDIA's OS-level NV_ESC_SYS_PARAMS ioctl has one fixed NvU64 input and
 * mutates the backend control-device state; it is not an RM_CONTROL packet.
 * The bridge accepts only the decoded value and never retains user memory. */
int hybrid580_open_control_session_sys_params_v1(
    struct hybrid580_control_session *, NvU64 memblock_size);
/* Fixed, pointer-free NV_ESC_CHECK_VERSION_STR payload. The provider executes
 * RM's native check against a kernel-owned copy before the frontend publishes
 * a reply; this can run before any GPU is attached or initialized. */
NV_STATUS hybrid580_open_control_session_check_version_v1(
    struct hybrid580_control_session *, nv_ioctl_rm_api_version_t *params,
    NvU32 size);
/* One command-specific kernel-buffer bridge. The GPU ID is backend-local;
 * caller must select the owning session and must never pass user pointers. */
NV_STATUS hybrid580_open_control_session_gpu_id_info_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS *params,
    NvU32 *control_status);
NV_STATUS hybrid580_open_control_session_attached_ids_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS *params,
    NvU32 *control_status);
NV_STATUS hybrid580_open_control_session_probed_ids_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS *params,
    NvU32 *control_status);
/* Fixed output-only device-instance bitmask used to construct the frontend
 * RM namespace. Never expose a backend-local mask directly to CUDA clients. */
NV_STATUS hybrid580_open_control_session_device_ids_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS *params,
    NvU32 *control_status);
/* Return only the provider-local group count. Group and GPU IDs never leave
 * the owning RM because this operation is root-global across both providers. */
NV_STATUS hybrid580_open_control_session_sync_boost_groups_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NvU32 *group_count, NvU32 *control_status);
/* Narrow NV01_DEVICE_0 lifecycle bridge. The object handle is supplied by
 * the frontend namespace; parameters are kernel-owned and class-typed. Only
 * same-root client sharing is accepted, never cross-client/device handles. */
NV_STATUS hybrid580_open_control_session_device_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_device,
    const NV0080_ALLOC_PARAMETERS *params, NvHandle *returned_device,
    NvU32 *rm_status);
NV_STATUS hybrid580_open_control_session_device_free_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_device,
    NvU32 *rm_status);
/* Typed system/local-user allocation bridge. The caller supplies a
 * kernel-owned NV_MEMORY_ALLOCATION_PARAMS and a parent in this RM session. */
NV_STATUS hybrid580_open_control_session_memory_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_parent,
    NvHandle h_object, NvU32 class_id, NV_MEMORY_ALLOCATION_PARAMS *params,
    NvHandle *returned_object, NvU32 *rm_status);
NV_STATUS hybrid580_open_control_session_object_free_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_parent,
    NvHandle h_object, NvU32 *rm_status);
/* Typed FERMI_VASPACE_A allocation bridge. Parameters contain no pointers;
 * shared/external-management requests remain outside this private adapter. */
NV_STATUS hybrid580_open_control_session_vaspace_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_device,
    NvHandle h_vaspace, NV_VASPACE_ALLOCATION_PARAMETERS *params,
    NvHandle *returned_vaspace, NvU32 *rm_status);

/* Typed KEPLER_CHANNEL_GROUP_A bridge. All object references are handles;
 * the caller must keep VASpace/notifier children alive through group teardown. */
NV_STATUS hybrid580_open_control_session_channel_group_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_device,
    NvHandle h_group, NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS *params,
    NvHandle *returned_group, NvU32 *rm_status);

/* Typed FERMI_CONTEXT_SHARE_A allocation, scoped to a channel group and its
 * already tracked VASpace. This fixed-size payload contains no user pointers. */
NV_STATUS hybrid580_open_control_session_context_share_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_group,
    NvHandle h_context_share, NV_CTXSHARE_ALLOCATION_PARAMETERS *params,
    NvHandle *returned_context_share, NvU32 *rm_status);

/* Typed GPFIFO channel allocation. The frontend supplies a kernel-owned
 * payload whose handles belong to this exact backend session. */
NV_STATUS hybrid580_open_control_session_channel_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_group,
    NvHandle h_channel, NvU32 class_id, NV_CHANNEL_ALLOC_PARAMS *params,
    NvHandle *returned_channel, NvU32 *rm_status);

/* Four observed architecture-specific Compute/DMA objects are optional-payload
 * children of a physical GPFIFO channel. The wrapper accepts no allocation
 * payload and uses the RM status separately from transport status. */
NV_STATUS hybrid580_open_control_session_engine_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_channel,
    NvHandle h_engine, NvU32 class_id, NvHandle *returned_engine,
    NvU32 *rm_status);

/* Narrow GT200_DEBUGGER bridge. The allocation payload is copied by the
 * frontend and its nested client/compute handles must already be translated
 * into this provider's RM namespace. R580 forwards the public exception-mask
 * control through its RM API and reports transport and RM status separately;
 * the Volta runtime class-dispatch result remains to be resolved. */
NV_STATUS hybrid580_open_control_session_debugger_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_parent,
    NvHandle h_debugger, const NV83DE_ALLOC_PARAMETERS *params,
    NvHandle *returned_debugger, NvU32 *rm_status);
NV_STATUS hybrid580_open_control_session_debugger_exception_mask_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_debugger,
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS *params,
    NvU32 *control_status);

/* Single physical-device NV20_SUBDEVICE_0 object, owned by the same backend
 * as its NV01_DEVICE_0 parent. The frontend currently accepts subDeviceId 0. */
NV_STATUS hybrid580_open_control_session_subdevice_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_device,
    NvHandle h_subdevice, const NV2080_ALLOC_PARAMETERS *params,
    NvHandle *returned_subdevice, NvU32 *rm_status);
/* Fixed, input-only root-client share policy request shared by R580/R595. */
NV_STATUS hybrid580_open_control_session_client_share_policy_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, RS_SHARE_POLICY *policy, NvU32 *control_status);
/* V100-only GF100_SUBDEVICE_MASTER child of a tracked NV20 subdevice. R580
 * NV_GPU_OPS passes a fixed four-byte input scratch payload for this class. */
NV_STATUS hybrid580_legacy_control_session_master_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvHandle h_master, const NvS32 *params, NvHandle *returned_master,
    NvU32 *rm_status);
/* Fixed pointer-free ECC/NVLink interrupt offset/mask query on that child. */
NV_STATUS hybrid580_legacy_control_session_master_error_intr_offset_mask_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_master,
    NvU32 flags,
    NV90E6_CTRL_MASTER_GET_ERROR_INTR_OFFSET_MASK_PARAMS *params,
    NvU32 *control_status);
/* Fixed-size GR query routed through an already tracked subdevice handle. */
NV_STATUS hybrid580_open_control_session_gr_tpc_mask_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvU32 flags, NV2080_CTRL_GR_GET_TPC_MASK_PARAMS *params,
    NvU32 *control_status);
/* Fixed-size, pointer-free NV20_SUBDEVICE_0 name query. The adapter accepts
 * only the R580 ASCII or UTF-16 selector and returns the backend RM status. */
NV_STATUS hybrid580_open_control_session_gpu_name_string_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvU32 flags, NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *params,
    NvU32 *control_status);

/* NV2081_BINAPI is a fixed, pointer-free child of NV20_SUBDEVICE_0. */
NV_STATUS hybrid580_open_control_session_binapi_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvHandle h_binapi, const NV2081_ALLOC_PARAMETERS *params,
    NvHandle *returned_binapi, NvU32 *rm_status);

/* Fixed eight-byte RM_USER_SHARED_DATA child observed on R595/Blackwell.
 * The complete polledDataMask is passed unchanged to its owning RM. */
NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvHandle h_rusd, const NV00DE_ALLOC_PARAMETERS *params,
    NvHandle *returned_rusd, NvU32 *rm_status);

/* Observed R580 V100 BAR1 P2P child; intentionally bound to the legacy RM. */
NV_STATUS hybrid580_legacy_control_session_p2p_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvHandle h_p2p, NvU32 params_size,
    const NV503C_ALLOC_PARAMETERS *params,
    NvHandle *returned_p2p, NvU32 *rm_status);

/* Fixed, pointer-free NV503C controls observed on the V100/R580 path. These
 * signatures are shared for header substitution, but only the legacy R580
 * backend exports them; the Open/Blackwell backend has no corresponding
 * export or routing permission in the hybrid frontend. */
NV_STATUS hybrid580_open_control_session_p2p_register_va_space_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_p2p,
    NV503C_CTRL_REGISTER_VA_SPACE_PARAMS *params, NvU32 *control_status);
NV_STATUS hybrid580_open_control_session_p2p_unregister_va_space_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_p2p,
    NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS *params, NvU32 *control_status);
NV_STATUS hybrid580_open_control_session_p2p_register_vidmem_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_p2p,
    NV503C_CTRL_REGISTER_VIDMEM_PARAMS *params, NvU32 *control_status);
NV_STATUS hybrid580_open_control_session_p2p_unregister_vidmem_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_p2p,
    NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS *params, NvU32 *control_status);

/* Volta and Hopper usermode doorbell-memory classes, with optional typed
 * Hopper mapping parameters and no caller-owned pointers. */
NV_STATUS hybrid580_open_control_session_usermode_alloc_v1(
    struct hybrid580_control_session *, NvHandle h_root, NvHandle h_subdevice,
    NvHandle h_usermode, NvU32 class_id,
    const NV_HOPPER_USERMODE_A_PARAMS *params,
    NvHandle *returned_usermode, NvU32 *rm_status);

#endif
