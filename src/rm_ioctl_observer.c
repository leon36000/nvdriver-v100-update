/* SPDX-License-Identifier: MIT
 * Read-only syscall observer of one explicitly launched process and its threads.
 * It never opens a GPU or writes to a tracee. Optional GPU-ID-info mode reads
 * only the exact, fixed-size NVIDIA ID-info parameter block.
 * Build against the pinned NVIDIA SDK; this is a Linux x86_64 userspace tool.
 */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/audit.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/close_range.h>
#include <linux/kcmp.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>
#include "nvtypes.h"
#include "nvos.h"
#include "nv-ioctl.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include "nv-unix-nvos-params-wrappers.h"
#include <ctrl/ctrl0000/ctrl0000gpu.h>
#include <ctrl/ctrl0000/ctrl0000system.h>
#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>
#include <alloc/alloc_channel.h>
#include <class/cl0080.h>
#include <class/cl2080.h>
#include <class/clc36f.h>
#include <class/clc96f.h>
#include <class/cl00de.h>
#include <class/cl2081.h>
#include <class/cl503c.h>
#include <class/cl83de.h>
#include <ctrl/ctrl83de/ctrl83dedebug.h>
#include <ctrl/ctrl503c.h>
#include "hybrid_binapi_payload_shape.h"
#include "rm_handle_registry.h"
#include "ioctl_payload_shape.h"
#include "uvm_ioctl.h"

#if !defined(__x86_64__)
#error This observer requires Linux x86_64
#endif
_Static_assert(sizeof(NVOS21_PARAMETERS)==32, "NVOS21");
_Static_assert(sizeof(NVOS64_PARAMETERS)==48, "NVOS64");
_Static_assert(sizeof(NVOS00_PARAMETERS)==16, "NVOS00");
_Static_assert(sizeof(NVOS54_PARAMETERS)==32, "NVOS54");
_Static_assert(sizeof(NV0080_ALLOC_PARAMETERS)==56, "NV0080 allocation payload");
_Static_assert(offsetof(NV0080_ALLOC_PARAMETERS,deviceId)==0,
               "NV0080 deviceId offset");
_Static_assert(offsetof(NV0080_ALLOC_PARAMETERS,vaSpaceSize)==24,
               "NV0080 vaSpaceSize offset");
_Static_assert(offsetof(NV0080_ALLOC_PARAMETERS,vaMode)==48,
               "NV0080 vaMode offset");
_Static_assert(sizeof(NV2080_ALLOC_PARAMETERS)==4, "NV2080 allocation payload");
_Static_assert(offsetof(NV2080_ALLOC_PARAMETERS,subDeviceId)==0,
               "NV2080 subDeviceId offset");
_Static_assert(sizeof(NV2081_ALLOC_PARAMETERS)==4, "NV2081 allocation payload");
_Static_assert(offsetof(NV2081_ALLOC_PARAMETERS,reserved)==0,
               "NV2081 reserved offset");
_Static_assert(sizeof(NV83DE_ALLOC_PARAMETERS)==12, "NV83DE allocation payload");
_Static_assert(offsetof(NV83DE_ALLOC_PARAMETERS,hDebuggerClient_Obsolete)==0,
               "NV83DE obsolete client offset");
_Static_assert(offsetof(NV83DE_ALLOC_PARAMETERS,hAppClient)==4,
               "NV83DE application client offset");
_Static_assert(offsetof(NV83DE_ALLOC_PARAMETERS,hClass3dObject)==8,
               "NV83DE debuggee object offset");
_Static_assert(sizeof(nv_ioctl_xfer_t)==16, "NV_IOCTL_XFER");
_Static_assert(sizeof(NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS)==32, "GPU_ID_INFO_V2");
_Static_assert(sizeof(NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS)==128, "GPU_GET_ATTACHED_IDS");
_Static_assert(sizeof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS)==384, "GPU_GET_PROBED_IDS");
_Static_assert(sizeof(NVOS33_PARAMETERS)==48, "NVOS33 map parameters");
_Static_assert(sizeof(NVOS34_PARAMETERS)==32, "NVOS34 unmap parameters");
_Static_assert(sizeof(nv_ioctl_nvos33_parameters_with_fd)==56,
               "R580 map wrapper");
_Static_assert(offsetof(nv_ioctl_nvos33_parameters_with_fd,fd)==48,
               "R580 map wrapper fd offset");
_Static_assert(offsetof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS,excludedGpuIds)==128,
               "GPU_GET_PROBED_IDS excluded IDs offset");
_Static_assert(offsetof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS,gpuFlags)==256,
               "GPU_GET_PROBED_IDS flags offset");
_Static_assert(offsetof(NVOS21_PARAMETERS,status)==28, "NVOS21 status");
_Static_assert(offsetof(NVOS64_PARAMETERS,status)==40, "NVOS64 status");
_Static_assert(offsetof(NVOS00_PARAMETERS,status)==12, "NVOS00 status");
_Static_assert(NV_IOCTL_MAGIC=='F', "ioctl magic");
_Static_assert(NV_ESC_RM_ALLOC==0x2b && NV_ESC_RM_FREE==0x29, "escapes");
_Static_assert(NV_ESC_RM_CONTROL==0x2a && NV_ESC_IOCTL_XFER_CMD==211, "control escapes");
_Static_assert(NV_ESC_RM_MAP_MEMORY==0x4e && NV_ESC_RM_UNMAP_MEMORY==0x4f,
               "map escapes");
_Static_assert(NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2==0x205, "GPU_ID_INFO_V2 command");
_Static_assert(NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS==0x201, "GPU_GET_ATTACHED_IDS command");
_Static_assert(NV0000_CTRL_CMD_GPU_GET_PROBED_IDS==0x214, "GPU_GET_PROBED_IDS command");
_Static_assert(NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS==0x136,
               "SYSTEM_GET_FABRIC_STATUS command");
_Static_assert(NV0000_CTRL_CMD_SYSTEM_GET_FEATURES==0x1f0,
               "SYSTEM_GET_FEATURES command");
_Static_assert(sizeof(NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS)==4,
               "SYSTEM_GET_FEATURES payload");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS,featuresMask)==0,
               "SYSTEM_GET_FEATURES mask offset");
_Static_assert(sizeof(NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS)==4,
               "SYSTEM_GET_FABRIC_STATUS payload");
_Static_assert(NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO==0xa04,
               "SYNC_GPU_BOOST_GROUP_INFO command");
_Static_assert(sizeof(NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS)==2244,
               "SYNC_GPU_BOOST_GROUP_INFO payload");
_Static_assert(offsetof(NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS,groupCount)==0,
               "SYNC_GPU_BOOST_GROUP_INFO groupCount offset");
_Static_assert(offsetof(NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS,fabricStatus)==0,
               "SYSTEM_GET_FABRIC_STATUS enum offset");
_Static_assert(NV01_ROOT==0 && NV01_ROOT_CLIENT==0x41, "root classes");
_Static_assert(VOLTA_CHANNEL_GPFIFO_A==0xc36f, "Volta channel class");
_Static_assert(BLACKWELL_CHANNEL_GPFIFO_A==0xc96f, "Blackwell channel class");
_Static_assert(RM_USER_SHARED_DATA==0xde, "RUSD class");
_Static_assert(sizeof(NV00DE_ALLOC_PARAMETERS)==8, "RUSD allocation payload");
_Static_assert(NV50_THIRD_PARTY_P2P==0x503c, "third-party P2P class");
_Static_assert(NV2081_BINAPI==0x2081, "BINAPI object class");
_Static_assert(NV83DE_CTRL_CMD_SM_DEBUG_MODE_ENABLE==0x83de0301,
               "GT200_DEBUGGER control command");
_Static_assert(sizeof(NV503C_ALLOC_PARAMETERS)==4, "third-party P2P payload");
_Static_assert(offsetof(NV503C_ALLOC_PARAMETERS,flags)==0, "third-party P2P flags offset");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS)==16,
               "P2P register VA-space parameters");
_Static_assert(sizeof(NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS)==4,
               "P2P unregister VA-space parameters");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS)==32,
               "P2P register vidmem parameters");
_Static_assert(sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS)==4,
               "P2P unregister vidmem parameters");
_Static_assert(sizeof(NV503C_CTRL_REGISTER_PID_PARAMS)==4,
               "P2P register PID parameters");
_Static_assert(UVM_REGISTER_GPU_VASPACE==25,
               "UVM_REGISTER_GPU_VASPACE request");
_Static_assert(sizeof(UVM_REGISTER_GPU_VASPACE_PARAMS)==32,
               "UVM_REGISTER_GPU_VASPACE payload");
_Static_assert(offsetof(UVM_REGISTER_GPU_VASPACE_PARAMS,rmCtrlFd)==16,
               "UVM_REGISTER_GPU_VASPACE rmCtrlFd offset");
_Static_assert(UVM_MAP_EXTERNAL_ALLOCATION==33,
               "UVM_MAP_EXTERNAL_ALLOCATION request");
_Static_assert(sizeof(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS)==9264,
               "UVM_MAP_EXTERNAL_ALLOCATION payload");
_Static_assert(offsetof(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS,rmCtrlFd)==9248,
               "UVM_MAP_EXTERNAL_ALLOCATION rmCtrlFd offset");
#define NV_CHANNEL_ALLOC_PARAMS_EXPECTED_SIZE 368U
_Static_assert(sizeof(NV_CHANNEL_ALLOC_PARAMS)==NV_CHANNEL_ALLOC_PARAMS_EXPECTED_SIZE,
               "R580 channel allocation payload");
enum channel_payload_state {
    CHANNEL_PAYLOAD_NONE=0,
    CHANNEL_PAYLOAD_R580_R595_PARSED=1,
};
#define MAX_TASKS 1024
#define MAX_RECORDS 8192
#define MAX_TRACKED_FDS 65536
#define MAX_RANGE_FILE_IDS 64
#define OBSERVED_NV2081_BINAPI_CONTROL 0x20810108U
#define OBSERVED_IOCTL_SHAPE_CARD_INFO 0xc038464eUL
#define OBSERVED_IOCTL_SHAPE_CONTROL_5E 0xc028465eUL
#define OBSERVED_IOCTL_SHAPE_GPU_CONTROL_CE 0xc01046ceUL
#define OBSERVED_IOCTL_SHAPE_GPU_CONTROL_CF 0xc01046cfUL
#define OBSERVED_IOCTL_SHAPE_RM_FREE 0xc0104629UL
_Static_assert(OBSERVED_IOCTL_SHAPE_RM_FREE==
               _IOWR(NV_IOCTL_MAGIC,NV_ESC_RM_FREE,NVOS00_PARAMETERS),
               "NV_ESC_RM_FREE fixed request");
struct packet {
    int layout;
    uint32_t root,parent,object,klass,size,flags,status;
    uint64_t params,rights;
};
struct gpu_id_info {
    uint32_t command,flags,params_size,status;
    uint32_t gpu_id,gpu_flags,device_instance,subdevice_instance;
    uint32_t sli_status,board_id,gpu_instance;
    int32_t numa_id;
    int client_handle_present,object_handle_present;
    int client_matches_prior_root,object_matches_prior_root,client_object_equal;
};
struct attached_ids_info {
    uint32_t command,flags,params_size,status;
    int client_handle_present,object_handle_present;
    int client_matches_prior_root,object_matches_prior_root,client_object_equal;
    uint32_t gpu_ids[NV0000_CTRL_GPU_MAX_ATTACHED_GPUS];
};
struct probed_ids_info {
    uint32_t command,flags,params_size,status;
    int client_handle_present,object_handle_present,client_object_equal;
    int client_matches_prior_root,object_matches_prior_root;
    uint32_t gpu_ids[NV0000_CTRL_GPU_MAX_PROBED_GPUS];
    uint32_t excluded_gpu_ids[NV0000_CTRL_GPU_MAX_PROBED_GPUS];
    uint32_t gpu_flags[NV0000_CTRL_GPU_MAX_PROBED_GPUS];
};
struct p2p_control_info {
    uint32_t command,payload_bytes;
    int recognized,payload_valid,handle_present,token_nonzero;
    int address_aligned,size_nonzero,size_aligned,offset_aligned;
    int offset_size_no_overflow,address_size_no_overflow;
};
struct channel_handle_class_ref {
    enum rm_handle_resolution resolution;
    uint32_t class_id;
};
struct rm_control_info {
    uint32_t command,flags,params_size,status,client_handle,object_handle;
    int client_object_equal,client_matches_prior_root,object_matches_prior_root;
    int object_handle_matches_prior_debugger_allocation;
    uint32_t fabric_status;
    int fabric_status_payload_valid;
    uint32_t system_features_mask;
    int system_features_payload_valid;
    uint32_t sync_boost_group_count;
    int sync_boost_group_payload_valid;
    uint32_t debugger_exception_mask;
    int debugger_exception_mask_payload_valid;
    int debugger_exception_mask_user_buffer_entry_exit_compared;
    int debugger_exception_mask_user_buffer_entry_exit_equal;
    struct channel_handle_class_ref object_class;
    struct hybrid_binapi_payload_shape binapi_payload;
    struct p2p_control_info p2p;
};
struct map_memory_info {
    uint64_t length,backend_file_id;
    uint32_t status,flags,backend_fd;
    int client_handle_present,device_handle_present,memory_handle_present;
    int offset_nonzero,linear_address_present,backend_fd_role;
    struct channel_handle_class_ref memory_class;
};
struct mmap_info {
    uint64_t length,file_id;
    uint32_t prot,flags;
    int offset_zero;
};
struct unmap_memory_info {
    uint32_t status,flags;
    int client_handle_present,device_handle_present,memory_handle_present;
    int linear_address_present;
};
struct channel_memory_desc_info {
    uint64_t size;
    uint32_t address_space,cache_attrib;
    int base_present;
};
struct channel_alloc_info {
    uint32_t class_payload_bytes,flags,gp_fifo_entries,engine_type,subdevice_id;
    uint32_t payload_state;
    unsigned int userd_memory_present_count,userd_offset_nonzero_count;
    int payload_valid;
    int object_error_present,object_buffer_present,gp_fifo_offset_nonzero;
    int context_share_present,vaspace_present,cid_present,ecc_error_present;
    int phys_channel_group_present,internal_flags_zero;
    int error_notifier_zero,ecc_error_notifier_zero;
    int process_id_zero,subprocess_id_zero,encrypt_iv_zero,decrypt_iv_zero;
    int hmac_nonce_zero,tpc_config_id_zero;
    struct channel_handle_class_ref parent_class;
    struct channel_handle_class_ref object_error_class,object_buffer_class;
    struct channel_handle_class_ref context_share_class,vaspace_class;
    struct channel_handle_class_ref ecc_error_class,phys_channel_group_class;
    struct channel_handle_class_ref userd_memory_class[NV_MAX_SUBDEVICES];
    struct channel_memory_desc_info instance_mem,userd_mem,ramfc_mem,mthdbuf_mem;
};
struct rusd_alloc_info {
    uint64_t polled_data_mask;
    int payload_valid;
};
struct p2p_alloc_info {
    uint32_t flags,type,unknown_flag_bits;
    int payload_present;
};
struct device_alloc_info {
    uint32_t device_id,flags,va_mode;
    uint64_t va_space_size;
    int payload_valid,client_share_kind,target_client_zero,target_device_zero;
    int va_start_internal_zero,va_limit_internal_zero;
};
struct subdevice_alloc_info {
    uint32_t subdevice_id;
    int payload_valid;
};
struct binapi_alloc_info {
    int reserved_zero;
    int payload_valid;
};
struct debugger_alloc_info {
    uint32_t obsolete_client_handle, app_client_handle, debuggee_3d_handle;
    int payload_valid, obsolete_client_zero, app_client_matches_root;
    int app_client_matches_parent, app_client_matches_debuggee;
    struct channel_handle_class_ref app_client_class, debuggee_3d_class;
    struct channel_handle_class_ref debuggee_3d_parent_class;
    struct channel_handle_class_ref parent_class;
};
struct record {
    pid_t tid;
    int fd;
    uint64_t request,address,packet_address,params_address,fd_file_id;
    uint64_t fd_replaced_file_id;
    uint64_t xfer_payload_address,client_handle,object_handle;
    unsigned size,rm_command,rm_flags,rm_params_size;
    int is_alloc,is_class_tracking_only,is_gpu_id_info,is_attached_ids;
    int is_probed_ids,is_rm_control,is_fabric_status,is_system_features;
    int is_sync_boost_groups;
    int is_ioctl_shape,shape_entry_snapshot_passed,shape_exit_snapshot_passed;
    int is_root_free_predicate,root_free_candidate,root_free_succeeded;
    int is_binapi_control,is_device_alloc,is_subdevice_alloc,is_binapi_alloc;
    int is_debugger_alloc,is_debugger_free,is_debugger_control;
    int is_debugger_control_candidate;
    uint32_t debugger_free_class;
    struct channel_handle_class_ref debugger_control_object_class;
    int is_uvm_vaspace_fd,is_uvm_map_external_fd;
    int uvm_fd_matches_entry,rm_ctrl_matches_entry;
    int rm_ctrl_matches_exit,rm_ctrl_is_negative,rm_ctrl_field_read;
    int32_t observed_rm_ctrl_fd;
    uint64_t rm_ctrl_file_id_entry;
    int rm_ctrl_identity_tracked_entry,rm_ctrl_same_file_identity_exit;
    int rm_ctrl_field_unchanged_exit;
    int rm_ctrl_no_mutation_pending_entry,rm_ctrl_no_mutation_pending_exit;
    int fd_role;
    int is_channel_alloc,is_rusd_alloc,is_p2p_alloc,is_map_memory,is_unmap_memory,is_mmap,is_close;
    int fd_event_kind;
    int fd_source;
    uint64_t fd_range_first,fd_range_last;
    uint64_t fd_range_file_ids[MAX_RANGE_FILE_IDS];
    int fd_range_fds[MAX_RANGE_FILE_IDS];
    uint32_t fd_range_file_id_count,fd_range_flags;
    int has_entry,has_exit,returned;
    int64_t result;
    struct packet entry,exit;
    struct gpu_id_info gpu_entry,gpu_exit;
    struct attached_ids_info attached_entry,attached_exit;
    struct probed_ids_info probed_entry,probed_exit;
    struct rm_control_info rm_control_entry,rm_control_exit;
    struct map_memory_info map_entry,map_exit;
    struct unmap_memory_info unmap_entry,unmap_exit;
    struct mmap_info mmap;
    struct channel_alloc_info channel_entry,channel_exit;
    struct rusd_alloc_info rusd_entry,rusd_exit;
    struct p2p_alloc_info p2p_entry,p2p_exit;
    struct device_alloc_info device_alloc_entry,device_alloc_exit;
    struct subdevice_alloc_info subdevice_alloc_entry,subdevice_alloc_exit;
    struct binapi_alloc_info binapi_alloc_entry,binapi_alloc_exit;
    struct debugger_alloc_info debugger_alloc_entry,debugger_alloc_exit;
    int binapi_entry_payload_valid;
    uint8_t binapi_entry_payload[HYBRID_BINAPI_PARAM_BYTES];
    uint8_t shape_entry_raw[HYBRID_IOCTL_SHAPE_MAX_BYTES];
    uint8_t shape_entry_nonzero[HYBRID_IOCTL_SHAPE_MAX_BYTES];
    uint8_t shape_exit_nonzero[HYBRID_IOCTL_SHAPE_MAX_BYTES];
    uint8_t shape_changed[HYBRID_IOCTL_SHAPE_MAX_BYTES];
};
enum fd_op_kind { FD_OP_NONE=0,FD_OP_OPEN,FD_OP_DUP,FD_OP_FCNTL_DUP,FD_OP_CLOSE_RANGE };
struct task {
    pid_t tid;
    int alive,newborn,pending,fd_op_kind,fd_op_source,fd_op_target;
    uint64_t fd_op_arg0,fd_op_arg1,fd_op_arg2,fd_op_source_id,fd_op_request;
};
struct fd_identity { uint64_t file_id; int role; };
/* One emergency slot retains a newborn when the ordinary task limit is hit. */
static struct task tasks[MAX_TASKS+1];
static struct record records[MAX_RECORDS];
static struct fd_identity fd_identities[MAX_TRACKED_FDS];
static size_t ntasks,nrecords;
static uint64_t next_fd_file_id=1;
static int fd_identity_capture_complete=1;
static char failure[256];
static const char *control_path="/dev/nvidiactl";
static const char *gpu_path;
static int capture_gpu_id_info;
static int capture_attached_ids;
static int capture_probed_ids;
static int capture_rm_control;
static int capture_rm_control_headers;
static int capture_fabric_status;
static unsigned int fabric_status_payload_snapshots_read;
static int capture_system_features;
static int capture_sync_boost_groups;
static int capture_ioctl_shapes;
static int capture_event_cleanup;
static unsigned int system_features_payload_snapshots_read;
static unsigned int sync_boost_group_payload_snapshots_read;
static unsigned int debugger_exception_mask_payload_snapshots_read;
static int capture_channel_alloc;
static int capture_rusd_alloc;
static int capture_p2p_alloc;
static int capture_p2p_control;
static int capture_binapi_control;
static int capture_device_alloc;
static int capture_subdevice_alloc;
static int capture_binapi_alloc;
static int capture_debugger_alloc;
static int capture_debugger_lifecycle;
static int capture_map_memory;
static int capture_uvm_vaspace_fd;
static const char *uvm_path="/dev/nvidia-uvm";
static size_t uvm_vaspace_records_seen;
static size_t uvm_map_external_records_seen;
static unsigned int channel_payload_snapshots_read;
static unsigned int rusd_payload_snapshots_read;
static unsigned int p2p_payload_snapshots_read;
static unsigned int p2p_control_payload_snapshots_read;
static unsigned int binapi_payload_snapshots_read;
static unsigned int device_alloc_payload_snapshots_read;
static unsigned int subdevice_alloc_payload_snapshots_read;
static unsigned int binapi_alloc_payload_snapshots_read;
static unsigned int debugger_alloc_payload_snapshots_read;
static unsigned int debugger_free_unresolved_count;
static unsigned int debugger_control_unresolved_count;
static struct rm_handle_registry handle_registry;
static volatile sig_atomic_t interrupted;
static void on_signal(int sig) { interrupted=sig; }
static void json_string(FILE *f,const char *s);
static void fail(const char *reason) {
    if (!failure[0]) snprintf(failure,sizeof(failure),"%s",reason);
}
static double monotime(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return -1;
    return t.tv_sec+t.tv_nsec/1e9;
}
static int resume(pid_t tid,int sig) {
    if (ptrace(PTRACE_SYSCALL,tid,0,(void *)(intptr_t)sig)<0) {
        fail("PTRACE_SYSCALL failed"); return -1;
    }
    return 0;
}
static int add_task(pid_t tid,int newborn) {
    if (ntasks>MAX_TASKS) { fail("task tracking overflow"); return -1; }
    tasks[ntasks++]=(struct task){.tid=tid,.alive=1,.newborn=newborn,
        .pending=-1,.fd_op_source=-1,.fd_op_target=-1};
    if (ntasks>MAX_TASKS) { fail("task limit exceeded"); return -1; }
    return 0;
}
static int read_memory(pid_t tid,uint64_t address,void *output,size_t size) {
    size_t offset=0;
    if (!address || address>UINT64_MAX-size) return -1;
    while (offset<size) {
        long word; size_t n=size-offset;
        if (n>sizeof(word)) n=sizeof(word);
        errno=0; word=ptrace(PTRACE_PEEKDATA,tid,(void *)(uintptr_t)(address+offset),0);
        if (word==-1 && errno) return -1;
        memcpy((char *)output+offset,&word,n); offset+=n;
    }
    return 0;
}
static void erase_bytes(uint8_t *bytes,size_t size) {
    volatile uint8_t *cursor=bytes;
    while (size--)
        *cursor++=0;
}
static size_t selected_ioctl_shape_size(uint64_t request) {
    switch (request) {
    case OBSERVED_IOCTL_SHAPE_CARD_INFO: return 56;
    case OBSERVED_IOCTL_SHAPE_CONTROL_5E: return 40;
    case OBSERVED_IOCTL_SHAPE_GPU_CONTROL_CE: return 16;
    case OBSERVED_IOCTL_SHAPE_GPU_CONTROL_CF: return 16;
    case OBSERVED_IOCTL_SHAPE_RM_FREE: return sizeof(NVOS00_PARAMETERS);
    default: return 0;
    }
}
static int snapshot_ioctl_shape(pid_t tid,struct record *r,int exit_snapshot) {
    uint8_t raw[HYBRID_IOCTL_SHAPE_MAX_BYTES]={0};
    size_t expected=selected_ioctl_shape_size(r->request);
    int result=-1;

    if (!expected || r->size!=expected || r->address==0)
        goto out;
    if (read_memory(tid,r->address,raw,expected))
        goto out;
    if (!exit_snapshot) {
        memcpy(r->shape_entry_raw,raw,expected);
        if (r->request==OBSERVED_IOCTL_SHAPE_RM_FREE) {
            NVOS00_PARAMETERS params;
            memcpy(&params,raw,sizeof(params));
            r->is_root_free_predicate=1;
            r->root_free_candidate=params.hObjectOld==params.hRoot;
        }
        for (size_t i=0;i<expected;i++)
            r->shape_entry_nonzero[i]=(uint8_t)(raw[i]!=0);
        r->shape_entry_snapshot_passed=1;
        result=0;
        goto out;
    }
    if (!r->shape_entry_snapshot_passed)
        goto out;
    if (hybrid_ioctl_payload_shape(expected,r->shape_entry_raw,raw,
                                   r->shape_entry_nonzero,
                                   r->shape_exit_nonzero,r->shape_changed))
        goto out;
    if (r->is_root_free_predicate) {
        NVOS00_PARAMETERS params;
        memcpy(&params,raw,sizeof(params));
        r->root_free_succeeded=r->root_free_candidate && r->returned &&
            r->result==0 && params.status==NV_OK;
    }
    r->shape_exit_snapshot_passed=1;
    result=0;
out:
    erase_bytes(raw,sizeof(raw));
    if (exit_snapshot)
        erase_bytes(r->shape_entry_raw,sizeof(r->shape_entry_raw));
    return result;
}
static int snapshot(pid_t tid,const struct record *r,struct packet *p) {
    memset(p,0,sizeof(*p));
    if (r->is_alloc && r->size==sizeof(NVOS21_PARAMETERS)) {
        NVOS21_PARAMETERS v;
        if (read_memory(tid,r->address,&v,sizeof(v))) return -1;
        p->layout=21; p->root=v.hRoot; p->parent=v.hObjectParent;
        p->object=v.hObjectNew; p->klass=v.hClass; p->params=(uintptr_t)v.pAllocParms;
        p->size=v.paramsSize; p->status=v.status;
    } else if (r->is_alloc && r->size==sizeof(NVOS64_PARAMETERS)) {
        NVOS64_PARAMETERS v;
        if (read_memory(tid,r->address,&v,sizeof(v))) return -1;
        p->layout=64; p->root=v.hRoot; p->parent=v.hObjectParent;
        p->object=v.hObjectNew; p->klass=v.hClass; p->params=(uintptr_t)v.pAllocParms;
        p->rights=(uintptr_t)v.pRightsRequested; p->size=v.paramsSize; p->flags=v.flags;
        p->status=v.status;
    } else if (!r->is_alloc && r->size==sizeof(NVOS00_PARAMETERS)) {
        NVOS00_PARAMETERS v;
        if (read_memory(tid,r->address,&v,sizeof(v))) return -1;
        p->layout=0; p->root=v.hRoot; p->parent=v.hObjectParent;
        p->object=v.hObjectOld; p->status=v.status;
    } else { fail("unsupported RM packet size"); return -1; }
    return 0;
}
static int is_channel_gpfifo_class(uint32_t klass) {
    return klass==VOLTA_CHANNEL_GPFIFO_A ||
           klass==BLACKWELL_CHANNEL_GPFIFO_A;
}
static struct channel_handle_class_ref channel_handle_class(uint32_t root,
                                                            uint32_t handle)
{
    struct channel_handle_class_ref result = {0};
    result.resolution = rm_handle_registry_lookup(&handle_registry, root, handle,
                                                  &result.class_id);
    return result;
}
static struct channel_handle_class_ref channel_handle_parent_class(
    uint32_t root, uint32_t handle)
{
    struct channel_handle_class_ref result = {0};
    result.resolution = rm_handle_registry_lookup_parent_class(
        &handle_registry, root, handle, &result.class_id);
    return result;
}
static struct channel_handle_class_ref debugger_control_object_class(
    uint32_t client_handle, uint32_t object_handle)
{
    struct channel_handle_class_ref result = {0};
    uint32_t root = 0;

    result.resolution = rm_handle_registry_root_for_handle(
        &handle_registry, client_handle, &root);
    if (result.resolution != RM_HANDLE_RESOLVED)
        return result;
    result.resolution = rm_handle_registry_lookup(
        &handle_registry, root, object_handle, &result.class_id);
    return result;
}
static void update_handle_registry(const struct record *record)
{
    const struct packet *packet;
    uint32_t root;
    int rc;

    if ((!capture_channel_alloc && !capture_map_memory && !capture_p2p_control &&
         !capture_binapi_control && !capture_debugger_alloc &&
         !capture_debugger_lifecycle) || record == NULL ||
        !record->has_entry || !record->returned ||
        !record->has_exit || record->result != 0 ||
        record->exit.status != NV_OK ||
        (!record->is_alloc && _IOC_NR(record->request) != NV_ESC_RM_FREE))
        return;
    /* RM_ALLOC may request hObjectNew == 0 and receive its actual handle only
     * in the returned NVOS64 packet. Resolve lifecycle relationships from the
     * successful output packet; the entry packet can contain no root handle
     * and can therefore make every later hClient appear unobserved. RM_FREE
     * still uses its input identity below. */
    packet = record->is_alloc ? &record->exit : &record->entry;
    if (record->is_alloc) {
        root = packet->root;
        if (root == 0 && (packet->klass == NV01_ROOT ||
                          packet->klass == NV01_ROOT_CLIENT) &&
            packet->parent == 0)
            root = packet->object;
        if (root == 0 || packet->object == 0)
            return;
        rc = rm_handle_registry_insert(&handle_registry, root, packet->object,
                                       packet->parent, packet->klass);
        if (rc == -2)
            fail("duplicate live RM handle identity in selected paths");
        else if (rc == -3)
            fail("RM handle registry capacity exceeded");
        else if (rc != 0)
            fail("invalid RM handle registry allocation identity");
        return;
    }

    if (packet->root == 0 || packet->object == 0)
        return;
    if (packet->object == packet->root) {
        (void)rm_handle_registry_remove_root(&handle_registry, packet->root);
        return;
    }
    rc = rm_handle_registry_remove(&handle_registry, packet->root,
                                   packet->object);
    if (rc == -2)
        fail("ambiguous live RM handle identity during free");
}

static const char *handle_resolution_name(enum rm_handle_resolution value)
{
    switch (value) {
    case RM_HANDLE_ABSENT: return "absent";
    case RM_HANDLE_RESOLVED: return "resolved";
    case RM_HANDLE_NOT_OBSERVED: return "not-observed-live-object";
    case RM_HANDLE_INVALID_ROOT: return "invalid-root";
    case RM_HANDLE_AMBIGUOUS: return "ambiguous";
    default: return "unknown";
    }
}
static void channel_handle_class_ref_json(FILE *f,
                                           const struct channel_handle_class_ref *ref)
{
    fputs("{\"resolution\":", f);
    json_string(f, handle_resolution_name(ref->resolution));
    fputs(",\"classId\":", f);
    if (ref->resolution == RM_HANDLE_RESOLVED)
        fprintf(f, "%u", ref->class_id);
    else
        fputs("null", f);
    fputc('}', f);
}
static int bytes_are_zero(const void *data,size_t size) {
    const unsigned char *bytes=data;
    for (size_t i=0;i<size;i++) if (bytes[i]) return 0;
    return 1;
}
static void summarize_channel_memory_desc(
    struct channel_memory_desc_info *out,const NV_MEMORY_DESC_PARAMS *in)
{
    out->base_present=in->base!=0;
    out->size=in->size;
    out->address_space=in->addressSpace;
    out->cache_attrib=in->cacheAttrib;
}
static int snapshot_channel_alloc(pid_t tid,const struct packet *packet,
                                  struct channel_alloc_info *out) {
    NV_CHANNEL_ALLOC_PARAMS params;
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || !is_channel_gpfifo_class(packet->klass)) {
        fail("unsupported channel allocation packet layout");
        return -1;
    }
    if (!packet->params || read_memory(tid,packet->params,&params,sizeof(params))) {
        fail("cannot read channel allocation payload");
        return -1;
    }
    /* R580/R595 RM class metadata, not NVOS64.paramsSize, fixes this copy size. */
    out->class_payload_bytes=sizeof(params);
    out->parent_class=channel_handle_class(packet->root,packet->parent);
    out->object_error_class=channel_handle_class(packet->root,params.hObjectError);
    out->object_buffer_class=channel_handle_class(packet->root,params.hObjectBuffer);
    out->context_share_class=channel_handle_class(packet->root,params.hContextShare);
    out->vaspace_class=channel_handle_class(packet->root,params.hVASpace);
    out->ecc_error_class=channel_handle_class(packet->root,params.hObjectEccError);
    out->phys_channel_group_class=
        channel_handle_class(packet->root,params.hPhysChannelGroup);
    for (size_t i=0;i<NV_MAX_SUBDEVICES;i++)
        out->userd_memory_class[i]=
            channel_handle_class(packet->root,params.hUserdMemory[i]);
    out->object_error_present=params.hObjectError!=0;
    out->object_buffer_present=params.hObjectBuffer!=0;
    out->gp_fifo_offset_nonzero=params.gpFifoOffset!=0;
    out->gp_fifo_entries=params.gpFifoEntries;
    out->flags=params.flags;
    out->context_share_present=params.hContextShare!=0;
    out->vaspace_present=params.hVASpace!=0;
    for (size_t i=0;i<NV_MAX_SUBDEVICES;i++) {
        out->userd_memory_present_count+=params.hUserdMemory[i]!=0;
        out->userd_offset_nonzero_count+=params.userdOffset[i]!=0;
    }
    out->engine_type=params.engineType;
    out->cid_present=params.cid!=0;
    out->subdevice_id=params.subDeviceId;
    out->ecc_error_present=params.hObjectEccError!=0;
    summarize_channel_memory_desc(&out->instance_mem,&params.instanceMem);
    summarize_channel_memory_desc(&out->userd_mem,&params.userdMem);
    summarize_channel_memory_desc(&out->ramfc_mem,&params.ramfcMem);
    summarize_channel_memory_desc(&out->mthdbuf_mem,&params.mthdbufMem);
    out->phys_channel_group_present=params.hPhysChannelGroup!=0;
    out->internal_flags_zero=params.internalFlags==0;
    out->error_notifier_zero=bytes_are_zero(&params.errorNotifierMem,
                                            sizeof(params.errorNotifierMem));
    out->ecc_error_notifier_zero=bytes_are_zero(&params.eccErrorNotifierMem,
                                                sizeof(params.eccErrorNotifierMem));
    out->process_id_zero=params.ProcessID==0;
    out->subprocess_id_zero=params.SubProcessID==0;
    out->encrypt_iv_zero=bytes_are_zero(params.encryptIv,sizeof(params.encryptIv));
    out->decrypt_iv_zero=bytes_are_zero(params.decryptIv,sizeof(params.decryptIv));
    out->hmac_nonce_zero=bytes_are_zero(params.hmacNonce,sizeof(params.hmacNonce));
    out->tpc_config_id_zero=params.tpcConfigID==0;
    out->payload_valid=1;
    out->payload_state=CHANNEL_PAYLOAD_R580_R595_PARSED;
    ++channel_payload_snapshots_read;
    return 0;
}
static int snapshot_rusd_alloc(pid_t tid,const struct packet *packet,
                               const struct packet *entry,
                               struct rusd_alloc_info *out) {
    NV00DE_ALLOC_PARAMETERS params;
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || packet->klass!=RM_USER_SHARED_DATA) {
        fail("unsupported RM_USER_SHARED_DATA allocation packet");
        return -1;
    }
    if (entry != NULL &&
        (packet->root!=entry->root || packet->parent!=entry->parent ||
         packet->object!=entry->object || packet->klass!=entry->klass ||
         packet->params!=entry->params)) {
        fail("RM_USER_SHARED_DATA allocation packet changed");
        return -1;
    }
    /* resource_list.h marks this payload required; outer paramsSize can be
     * zero because RM copies the class-metadata size, not this envelope size. */
    if (packet->params==0 ||
        read_memory(tid,packet->params,&params,sizeof(params))) {
        fail("cannot read RM_USER_SHARED_DATA allocation payload");
        return -1;
    }
    out->polled_data_mask=params.polledDataMask;
    out->payload_valid=1;
    ++rusd_payload_snapshots_read;
    return 0;
}
static int snapshot_p2p_alloc(pid_t tid,const struct packet *packet,
                              const struct packet *entry,
                              struct p2p_alloc_info *out) {
    NV503C_ALLOC_PARAMETERS params;
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || packet->klass!=NV50_THIRD_PARTY_P2P) {
        fail("unsupported NV50_THIRD_PARTY_P2P allocation packet");
        return -1;
    }
    if (entry != NULL &&
        (packet->root!=entry->root || packet->parent!=entry->parent ||
         packet->object!=entry->object || packet->klass!=entry->klass ||
         packet->params!=entry->params)) {
        fail("NV50_THIRD_PARTY_P2P allocation packet changed");
        return -1;
    }
    /* R580/R595 resource_list.h marks the four-byte payload optional. A null
     * pointer means RM's class default; a non-null pointer is read at the
     * class-metadata size regardless of the outer NVOS64.paramsSize. */
    if (packet->params==0)
        return 0;
    if (read_memory(tid,packet->params,&params,sizeof(params))) {
        fail("cannot read NV50_THIRD_PARTY_P2P allocation payload");
        return -1;
    }
    out->flags=params.flags;
    out->type=params.flags & 0x3U;
    out->unknown_flag_bits=params.flags & ~0x3U;
    out->payload_present=1;
    ++p2p_payload_snapshots_read;
    return 0;
}
static int snapshot_device_alloc(pid_t tid,const struct packet *packet,
                                 const struct packet *entry,
                                 struct device_alloc_info *out) {
    NV0080_ALLOC_PARAMETERS params={0};
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || packet->klass!=NV01_DEVICE_0) {
        fail("unsupported NV01_DEVICE_0 allocation packet");
        return -1;
    }
    if (entry != NULL &&
        (packet->layout!=entry->layout || packet->root!=entry->root ||
         packet->parent!=entry->parent || packet->object!=entry->object ||
         packet->klass!=entry->klass || packet->params!=entry->params ||
         packet->size!=entry->size)) {
        fail("NV01_DEVICE_0 allocation packet changed");
        return -1;
    }
    /* The pinned class metadata marks this payload optional. If present,
     * RM copies its fixed class size even when outer paramsSize is zero. */
    if (packet->params==0) {
        if (packet->size!=0) {
            fail("NV01_DEVICE_0 has a null payload with nonzero paramsSize");
            return -1;
        }
        return 0;
    }
    if (read_memory(tid,packet->params,&params,sizeof(params))) {
        explicit_bzero(&params,sizeof(params));
        fail("cannot read NV0080 allocation payload");
        return -1;
    }
    out->device_id=params.deviceId;
    out->flags=(uint32_t)params.flags;
    out->va_space_size=params.vaSpaceSize;
    out->va_mode=(uint32_t)params.vaMode;
    out->client_share_kind=params.hClientShare==0 ? 0 :
        params.hClientShare==packet->root ? 1 : 2;
    out->target_client_zero=params.hTargetClient==0;
    out->target_device_zero=params.hTargetDevice==0;
    out->va_start_internal_zero=params.vaStartInternal==0;
    out->va_limit_internal_zero=params.vaLimitInternal==0;
    out->payload_valid=1;
    explicit_bzero(&params,sizeof(params));
    ++device_alloc_payload_snapshots_read;
    return 0;
}
static int snapshot_subdevice_alloc(pid_t tid,const struct packet *packet,
                                    const struct packet *entry,
                                    struct subdevice_alloc_info *out) {
    NV2080_ALLOC_PARAMETERS params={0};
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || packet->klass!=NV20_SUBDEVICE_0) {
        fail("unsupported NV20_SUBDEVICE_0 allocation packet");
        return -1;
    }
    if (entry != NULL &&
        (packet->layout!=entry->layout || packet->root!=entry->root ||
         packet->parent!=entry->parent || packet->object!=entry->object ||
         packet->klass!=entry->klass || packet->params!=entry->params ||
         packet->size!=entry->size)) {
        fail("NV20_SUBDEVICE_0 allocation packet changed");
        return -1;
    }
    /* R580/R595 register this payload as optional. RM class metadata, rather
     * than outer paramsSize, controls the fixed four-byte parameter copy. */
    if (packet->params==0) {
        if (packet->size!=0) {
            fail("NV20_SUBDEVICE_0 has a null payload with nonzero paramsSize");
            return -1;
        }
        return 0;
    }
    if (packet->size!=0 && packet->size!=sizeof(params)) {
        fail("NV20_SUBDEVICE_0 has an unsupported paramsSize");
        return -1;
    }
    if (read_memory(tid,packet->params,&params,sizeof(params))) {
        explicit_bzero(&params,sizeof(params));
        fail("cannot read NV2080 allocation payload");
        return -1;
    }
    out->subdevice_id=params.subDeviceId;
    out->payload_valid=1;
    explicit_bzero(&params,sizeof(params));
    ++subdevice_alloc_payload_snapshots_read;
    return 0;
}
static int snapshot_binapi_alloc(pid_t tid,const struct packet *packet,
                                 const struct packet *entry,
                                 struct binapi_alloc_info *out) {
    NV2081_ALLOC_PARAMETERS params={0};
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || packet->klass!=NV2081_BINAPI) {
        fail("unsupported NV2081_BINAPI allocation packet");
        return -1;
    }
    if (entry != NULL &&
        (packet->layout!=entry->layout || packet->root!=entry->root ||
         packet->parent!=entry->parent || packet->object!=entry->object ||
         packet->klass!=entry->klass || packet->params!=entry->params ||
         packet->size!=entry->size)) {
        fail("NV2081_BINAPI allocation packet changed");
        return -1;
    }
    /* R580/R595 resource metadata marks these fixed four bytes optional.
     * Record only a zero predicate; the reserved word itself is never emitted. */
    if (packet->params==0) {
        if (packet->size!=0) {
            fail("NV2081_BINAPI has a null payload with nonzero paramsSize");
            return -1;
        }
        return 0;
    }
    if (packet->size!=0 && packet->size!=sizeof(params)) {
        fail("NV2081_BINAPI has an unsupported paramsSize");
        return -1;
    }
    if (read_memory(tid,packet->params,&params,sizeof(params))) {
        explicit_bzero(&params,sizeof(params));
        fail("cannot read NV2081 allocation payload");
        return -1;
    }
    out->reserved_zero=params.reserved==0;
    out->payload_valid=1;
    explicit_bzero(&params,sizeof(params));
    ++binapi_alloc_payload_snapshots_read;
    return 0;
}
static int snapshot_debugger_alloc(pid_t tid,const struct packet *packet,
                                   const struct packet *entry,
                                   const struct debugger_alloc_info *expected,
                                   struct debugger_alloc_info *out) {
    NV83DE_ALLOC_PARAMETERS params={0};
    memset(out,0,sizeof(*out));
    if (packet->layout!=64 || packet->klass!=GT200_DEBUGGER) {
        fail("unsupported GT200_DEBUGGER allocation packet");
        return -1;
    }
    if (packet->size!=0 && packet->size!=sizeof(params)) {
        fail("unexpected GT200_DEBUGGER allocation parameter size");
        return -1;
    }
    if (entry != NULL &&
        (packet->layout!=entry->layout || packet->root!=entry->root ||
         packet->parent!=entry->parent || packet->object!=entry->object ||
         packet->klass!=entry->klass || packet->params!=entry->params ||
         packet->size!=entry->size)) {
        fail("GT200_DEBUGGER allocation packet changed");
        return -1;
    }
    /* cl83de metadata requires this fixed payload. The observed outer
     * paramsSize is zero, so read exactly the class-header size, never the
     * user-supplied outer size. Only relational metadata leaves this function. */
    if (packet->params==0 ||
        read_memory(tid,packet->params,&params,sizeof(params))) {
        explicit_bzero(&params,sizeof(params));
        fail("cannot read required GT200_DEBUGGER allocation payload");
        return -1;
    }
    out->obsolete_client_handle=params.hDebuggerClient_Obsolete;
    out->app_client_handle=params.hAppClient;
    out->debuggee_3d_handle=params.hClass3dObject;
    out->obsolete_client_zero=params.hDebuggerClient_Obsolete==0;
    out->app_client_matches_root=params.hAppClient==packet->root;
    out->app_client_matches_parent=params.hAppClient==packet->parent;
    out->app_client_matches_debuggee=params.hAppClient==params.hClass3dObject;
    out->app_client_class=channel_handle_class(packet->root,params.hAppClient);
    out->debuggee_3d_class=channel_handle_class(packet->root,params.hClass3dObject);
    out->debuggee_3d_parent_class=
        channel_handle_parent_class(packet->root,params.hClass3dObject);
    out->parent_class=channel_handle_class(packet->root,packet->parent);
    out->payload_valid=1;
    explicit_bzero(&params,sizeof(params));
    ++debugger_alloc_payload_snapshots_read;
    if (expected != NULL &&
        (out->obsolete_client_handle!=expected->obsolete_client_handle ||
         out->app_client_handle!=expected->app_client_handle ||
         out->debuggee_3d_handle!=expected->debuggee_3d_handle)) {
        explicit_bzero(out,sizeof(*out));
        fail("GT200_DEBUGGER nested handles changed across RM_ALLOC");
        return -1;
    }
    return 0;
}
static int identify_rm_control(pid_t tid,uint64_t request,uint64_t argument,
                               struct record *r) {
    unsigned number=_IOC_NR(request),size=_IOC_SIZE(request);
    uint64_t packet_address=argument;
    NVOS54_PARAMETERS control;

    if (_IOC_TYPE(request)!=NV_IOCTL_MAGIC ||
        _IOC_DIR(request)!=(_IOC_READ|_IOC_WRITE))
        return 0;
    if (number==NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (size!=sizeof(xfer)) {
            fail(capture_system_features ?
                 "invalid SYSTEM_GET_FEATURES ioctl XFER header size" :
                 capture_fabric_status ?
                 "invalid Fabric Status ioctl XFER header size" :
                 "invalid ioctl XFER header size");
            return -1;
        }
        if (read_memory(tid,argument,&xfer,sizeof(xfer))) {
            fail("cannot read top-level ioctl XFER packet");
            return -1;
        }
        if (xfer.cmd!=NV_ESC_RM_CONTROL)
            return 0;
        if (xfer.size!=sizeof(control)) {
            if (capture_rm_control || capture_fabric_status || capture_system_features ||
                capture_debugger_lifecycle) {
                r->is_rm_control=1;
                fail(capture_system_features ?
                     "invalid SYSTEM_GET_FEATURES RM_CONTROL XFER payload size" :
                     capture_fabric_status ?
                     "invalid Fabric Status RM_CONTROL XFER payload size" :
                     "invalid RM_CONTROL XFER payload size");
                return -1;
            }
            return 0;
        }
        packet_address=(uint64_t)(uintptr_t)xfer.ptr;
        r->xfer_payload_address=packet_address;
    } else if (number==NV_ESC_RM_CONTROL) {
        if (size!=sizeof(control)) {
            if (capture_rm_control || capture_fabric_status || capture_system_features ||
                capture_debugger_lifecycle) {
                r->is_rm_control=1;
                fail(capture_system_features ?
                     "invalid SYSTEM_GET_FEATURES RM_CONTROL ioctl packet size" :
                     capture_fabric_status ?
                     "invalid Fabric Status RM_CONTROL ioctl packet size" :
                     "invalid RM_CONTROL ioctl packet size");
                return -1;
            }
            return 0;
        }
    } else {
        return 0;
    }
    if (capture_rm_control || capture_fabric_status || capture_system_features)
        r->is_rm_control=1;
    if (read_memory(tid,packet_address,&control,sizeof(control))) {
        fail("cannot read RM_CONTROL header");
        return -1;
    }
    if ((uint32_t)control.cmd==NV0000_CTRL_CMD_SYSTEM_GET_FEATURES) {
        if (capture_system_features) r->is_system_features=1;
        else if (!capture_rm_control && !capture_debugger_lifecycle) return 0;
    } else if ((uint32_t)control.cmd==NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS) {
        if (capture_fabric_status) r->is_fabric_status=1;
        else if (!capture_rm_control && !capture_debugger_lifecycle) return 0;
    } else if ((uint32_t)control.cmd==NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2) {
        if (capture_gpu_id_info) r->is_gpu_id_info=1;
        else if (!capture_rm_control && !capture_debugger_lifecycle) return 0;
    } else if ((uint32_t)control.cmd==NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS) {
        if (capture_attached_ids) r->is_attached_ids=1;
        else if (!capture_rm_control && !capture_debugger_lifecycle) return 0;
    } else if ((uint32_t)control.cmd==NV0000_CTRL_CMD_GPU_GET_PROBED_IDS) {
        if (capture_probed_ids) r->is_probed_ids=1;
        else if (!capture_rm_control && !capture_debugger_lifecycle) return 0;
    } else if (!capture_rm_control && !capture_debugger_lifecycle) return 0;

    /* Once the exact command is identified, malformed size/null-pointer
     * inputs are represented as failed observations and never dereferenced. */
    r->packet_address=packet_address;
    r->params_address=(uint64_t)(uintptr_t)control.params;
    r->client_handle=(uint32_t)control.hClient;
    r->object_handle=(uint32_t)control.hObject;
    r->rm_command=(uint32_t)control.cmd;
    r->is_sync_boost_groups = capture_sync_boost_groups &&
        r->rm_command==NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO;
    r->rm_flags=(uint32_t)control.flags;
    r->rm_params_size=(uint32_t)control.paramsSize;
    r->is_binapi_control=capture_binapi_control &&
                         r->rm_command==OBSERVED_NV2081_BINAPI_CONTROL;
    if (capture_debugger_lifecycle) {
        r->debugger_control_object_class = debugger_control_object_class(
            r->client_handle, r->object_handle);
        r->is_debugger_control =
            r->debugger_control_object_class.resolution == RM_HANDLE_RESOLVED &&
            r->debugger_control_object_class.class_id == GT200_DEBUGGER;
        if (r->debugger_control_object_class.resolution != RM_HANDLE_RESOLVED &&
            (r->rm_command & 0xffff0000U) == 0x83de0000U) {
            ++debugger_control_unresolved_count;
            r->is_debugger_control_candidate = 1;
            r->is_rm_control = 1;
        }
        if (r->is_debugger_control)
            r->is_rm_control = 1;
    }
    if (capture_debugger_lifecycle && !r->is_debugger_control &&
        !r->is_debugger_control_candidate &&
        !r->is_gpu_id_info && !r->is_attached_ids && !r->is_probed_ids &&
        !r->is_fabric_status && !r->is_system_features &&
        !r->is_sync_boost_groups && !r->is_binapi_control && !capture_rm_control)
        return 0;
    return 1;
}
static int matches_prior_root_client(uint32_t handle) {
    if (!handle) return 0;
    for (size_t i=0;i<nrecords;i++) {
        const struct record *prior=&records[i];
        if (prior->is_alloc && prior->returned && prior->result==0 &&
            prior->has_exit && prior->exit.klass==NV01_ROOT_CLIENT &&
            prior->exit.status==NV_OK && prior->exit.object==handle)
            return 1;
    }
    return 0;
}
static int matches_prior_debugger_allocation(uint32_t client_handle,
                                             uint32_t object_handle) {
    uint32_t root = 0;
    if (!object_handle ||
        rm_handle_registry_root_for_handle(&handle_registry, client_handle,
                                           &root) != RM_HANDLE_RESOLVED)
        return 0;
    for (size_t i=0;i<nrecords;i++) {
        const struct record *prior=&records[i];
        if (prior->is_debugger_alloc && prior->returned && prior->result==0 &&
            prior->has_exit && prior->exit.root==root &&
            prior->exit.object==object_handle &&
            prior->exit.klass==GT200_DEBUGGER && prior->exit.status==NV_OK)
            return 1;
    }
    return 0;
}
static size_t p2p_control_expected_size(uint32_t command) {
    switch (command) {
    case NV503C_CTRL_CMD_REGISTER_VA_SPACE:
        return sizeof(NV503C_CTRL_REGISTER_VA_SPACE_PARAMS);
    case NV503C_CTRL_CMD_UNREGISTER_VA_SPACE:
        return sizeof(NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS);
    case NV503C_CTRL_CMD_REGISTER_VIDMEM:
        return sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS);
    case NV503C_CTRL_CMD_UNREGISTER_VIDMEM:
        return sizeof(NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS);
    case NV503C_CTRL_CMD_REGISTER_PID:
        return sizeof(NV503C_CTRL_REGISTER_PID_PARAMS);
    default:
        return 0;
    }
}
static int snapshot_p2p_control_payload(pid_t tid,const struct record *r,
                                        struct p2p_control_info *out) {
    const size_t expected=p2p_control_expected_size(r->rm_command);
    memset(out,0,sizeof(*out));
    if (!expected)
        return 0;
    out->recognized=1;
    out->command=r->rm_command;
    out->payload_bytes=(uint32_t)expected;
    if (r->rm_params_size!=expected) {
        fail("NV503C P2P RM_CONTROL has an unexpected fixed payload size");
        return -1;
    }
    if (!r->params_address) {
        fail("NV503C P2P RM_CONTROL has a null nested payload");
        return -1;
    }
    switch (r->rm_command) {
    case NV503C_CTRL_CMD_REGISTER_VA_SPACE: {
        NV503C_CTRL_REGISTER_VA_SPACE_PARAMS params;
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            fail("cannot read NV503C register-VA-space payload");
            return -1;
        }
        out->handle_present=params.hVASpace!=0;
        out->token_nonzero=params.vaSpaceToken!=0;
        break;
    }
    case NV503C_CTRL_CMD_UNREGISTER_VA_SPACE: {
        NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS params;
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            fail("cannot read NV503C unregister-VA-space payload");
            return -1;
        }
        out->handle_present=params.hVASpace!=0;
        break;
    }
    case NV503C_CTRL_CMD_REGISTER_VIDMEM: {
        NV503C_CTRL_REGISTER_VIDMEM_PARAMS params;
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            fail("cannot read NV503C register-vidmem payload");
            return -1;
        }
        out->handle_present=params.hMemory!=0;
        out->address_aligned=(params.address&UINT64_C(0xffff))==0;
        out->size_nonzero=params.size!=0;
        out->size_aligned=(params.size&UINT64_C(0xffff))==0;
        out->offset_aligned=(params.offset&UINT64_C(0xffff))==0;
        out->offset_size_no_overflow=params.size<=UINT64_MAX-params.offset;
        out->address_size_no_overflow=params.size<=UINT64_MAX-params.address;
        break;
    }
    case NV503C_CTRL_CMD_UNREGISTER_VIDMEM: {
        NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS params;
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            fail("cannot read NV503C unregister-vidmem payload");
            return -1;
        }
        out->handle_present=params.hMemory!=0;
        break;
    }
    case NV503C_CTRL_CMD_REGISTER_PID: {
        NV503C_CTRL_REGISTER_PID_PARAMS params;
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            fail("cannot read NV503C register-PID payload");
            return -1;
        }
        out->handle_present=params.hClient!=0;
        break;
    }
    default:
        return 0;
    }
    out->payload_valid=1;
    ++p2p_control_payload_snapshots_read;
    return 0;
}
static int snapshot_rm_control_header(pid_t tid,const struct record *r,
                                      struct rm_control_info *out,
                                      int exit_snapshot) {
    NVOS54_PARAMETERS control;
    uint64_t current_params;

    memset(out,0,sizeof(*out));
    if (read_memory(tid,r->packet_address,&control,sizeof(control)))
        return -1;
    current_params=(uint64_t)(uintptr_t)control.params;
    if ((uint32_t)control.cmd!=r->rm_command ||
        (uint32_t)control.flags!=r->rm_flags ||
        (uint32_t)control.paramsSize!=r->rm_params_size ||
        current_params!=r->params_address ||
        (uint32_t)control.hClient!=r->client_handle ||
        (uint32_t)control.hObject!=r->object_handle)
        return -1;
    if (_IOC_NR(r->request)==NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (read_memory(tid,r->address,&xfer,sizeof(xfer)) ||
            xfer.cmd!=NV_ESC_RM_CONTROL || xfer.size!=sizeof(control) ||
            (uint64_t)(uintptr_t)xfer.ptr!=r->packet_address)
            return -1;
    }
    out->command=(uint32_t)control.cmd;
    out->flags=(uint32_t)control.flags;
    out->params_size=(uint32_t)control.paramsSize;
    out->status=(uint32_t)control.status;
    out->client_handle=(uint32_t)control.hClient;
    out->object_handle=(uint32_t)control.hObject;
    out->client_object_equal=control.hClient!=0 && control.hClient==control.hObject;
    out->client_matches_prior_root=matches_prior_root_client(out->client_handle);
    out->object_matches_prior_root=matches_prior_root_client(out->object_handle);
    out->object_handle_matches_prior_debugger_allocation =
        matches_prior_debugger_allocation(out->client_handle,out->object_handle);
    if (capture_p2p_control || capture_binapi_control) {
        out->object_class=channel_handle_class((uint32_t)control.hClient,
                                               (uint32_t)control.hObject);
    }
    if (capture_p2p_control) {
        if (snapshot_p2p_control_payload(tid,r,&out->p2p))
            return -1;
    }
    if (capture_fabric_status && r->is_fabric_status) {
        NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS params;
        if (out->command!=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS ||
            out->flags!=NVOS54_FLAGS_NONE ||
            out->params_size!=sizeof(params) || !r->params_address) {
            fail("invalid Fabric Status RM_CONTROL shape");
            return -1;
        }
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            explicit_bzero(&params,sizeof(params));
            fail("cannot read Fabric Status payload");
            return -1;
        }
        out->fabric_status=params.fabricStatus;
        out->fabric_status_payload_valid=1;
        explicit_bzero(&params,sizeof(params));
        ++fabric_status_payload_snapshots_read;
    }
    if (capture_system_features && r->is_system_features) {
        NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params;
        if (out->command!=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES ||
            out->flags!=NVOS54_FLAGS_NONE ||
            out->params_size!=sizeof(params) || !r->params_address) {
            fail("invalid SYSTEM_GET_FEATURES RM_CONTROL shape");
            return -1;
        }
        if (read_memory(tid,r->params_address,&params,sizeof(params))) {
            explicit_bzero(&params,sizeof(params));
            fail("cannot read SYSTEM_GET_FEATURES payload");
            return -1;
        }
        out->system_features_mask=params.featuresMask;
        out->system_features_payload_valid=1;
        explicit_bzero(&params,sizeof(params));
        ++system_features_payload_snapshots_read;
    }
    if (capture_sync_boost_groups && r->is_sync_boost_groups && exit_snapshot) {
        NvU32 group_count;
        /* Do not mistake the caller's seeded [out] field for an RM result.
         * The count is valid only after both ioctl transport and RM succeed. */
        if (!r->returned || r->result!=0 || out->status!=NV_OK)
            return 0;
        if (out->command!=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO ||
            out->flags!=NVOS54_FLAGS_NONE ||
            out->params_size!=sizeof(NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS) ||
            !r->params_address) {
            fail("invalid sync boost group RM_CONTROL shape");
            return -1;
        }
        if (read_memory(tid,r->params_address,&group_count,sizeof(group_count))) {
            fail("cannot read sync boost group payload");
            return -1;
        }
        if (group_count>NV0000_SYNC_GPU_BOOST_MAX_GROUPS) {
            fail("sync boost group count exceeds the fixed output capacity");
            return -1;
        }
        out->sync_boost_group_count=group_count;
        out->sync_boost_group_payload_valid=1;
        ++sync_boost_group_payload_snapshots_read;
    }
    return 0;
}
static int debugger_exception_mask_is_documented(uint32_t mask) {
    const uint32_t documented_bits =
        NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_FATAL |
        NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_TRAP |
        NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_SINGLE_STEP |
        NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_INT |
        NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_CILP |
        NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PREEMPTION_STARTED;

    return mask == NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_ALL ||
           (mask & ~documented_bits) == 0;
}
static int snapshot_debugger_exception_mask_payload(
        pid_t tid, const struct record *r, struct rm_control_info *out,
        int exit_snapshot) {
    NV83DE_CTRL_DEBUG_SET_EXCEPTION_MASK_PARAMS params = {0};

    /* Do not follow candidate or otherwise unresolved command pointers. */
    if (!r->is_debugger_control ||
        out->command != NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK)
        return 0;
    if (out->params_size != sizeof(params) || !r->params_address) {
        fail("invalid GT200_DEBUGGER exception-mask control shape");
        return -1;
    }
    if (read_memory(tid,r->params_address,&params,sizeof(params))) {
        explicit_bzero(&params,sizeof(params));
        fail("cannot read fixed GT200_DEBUGGER exception-mask payload");
        return -1;
    }
    if (!debugger_exception_mask_is_documented(params.exceptionMask)) {
        explicit_bzero(&params,sizeof(params));
        fail("GT200_DEBUGGER exception mask contains undocumented bits");
        return -1;
    }
    out->debugger_exception_mask=params.exceptionMask;
    out->debugger_exception_mask_payload_valid=1;
    if (exit_snapshot) {
        if (!r->rm_control_entry.debugger_exception_mask_payload_valid) {
            explicit_bzero(&params,sizeof(params));
            fail("GT200_DEBUGGER exception-mask exit has no validated entry snapshot");
            return -1;
        }
        out->debugger_exception_mask_user_buffer_entry_exit_compared=1;
        out->debugger_exception_mask_user_buffer_entry_exit_equal =
            params.exceptionMask ==
                r->rm_control_entry.debugger_exception_mask;
    }
    explicit_bzero(&params,sizeof(params));
    ++debugger_exception_mask_payload_snapshots_read;
    return 0;
}
static int snapshot_binapi_control_payload(pid_t tid,struct record *r,
                                            struct rm_control_info *out,
                                            int is_exit) {
    struct hybrid_binapi_payload_shape *shape=&out->binapi_payload;
    memset(shape,0,sizeof(*shape));
    shape->payload_equal=-1;
    if (!r->is_binapi_control)
        return 0;
    if (out->command!=OBSERVED_NV2081_BINAPI_CONTROL ||
        out->params_size!=HYBRID_BINAPI_PARAM_BYTES) {
        fail("BINAPI RM_CONTROL has an unexpected fixed payload size");
        return -1;
    }
    if (out->object_class.resolution!=RM_HANDLE_RESOLVED ||
        out->object_class.class_id!=NV2081_BINAPI) {
        fail("BINAPI RM_CONTROL object class is not a live NV2081_BINAPI");
        return -1;
    }
    if (!r->params_address) {
        fail("BINAPI RM_CONTROL has a null payload pointer");
        return -1;
    }

    if (!is_exit) {
        explicit_bzero(r->binapi_entry_payload,sizeof(r->binapi_entry_payload));
        r->binapi_entry_payload_valid=0;
        if (read_memory(tid,r->params_address,r->binapi_entry_payload,
                        sizeof(r->binapi_entry_payload))) {
            explicit_bzero(r->binapi_entry_payload,sizeof(r->binapi_entry_payload));
            fail("cannot read fixed 992-byte NV2081_BINAPI payload");
            return -1;
        }
        if (hybrid_binapi_payload_entry_shape(r->binapi_entry_payload,shape)) {
            explicit_bzero(r->binapi_entry_payload,sizeof(r->binapi_entry_payload));
            fail("cannot summarize fixed NV2081_BINAPI payload");
            return -1;
        }
        r->binapi_entry_payload_valid=1;
    } else {
        uint8_t exit_payload[HYBRID_BINAPI_PARAM_BYTES]={0};
        if (!r->binapi_entry_payload_valid) {
            fail("BINAPI payload exit has no validated entry snapshot");
            return -1;
        }
        if (read_memory(tid,r->params_address,exit_payload,sizeof(exit_payload))) {
            explicit_bzero(exit_payload,sizeof(exit_payload));
            explicit_bzero(r->binapi_entry_payload,sizeof(r->binapi_entry_payload));
            r->binapi_entry_payload_valid=0;
            fail("cannot read fixed 992-byte NV2081_BINAPI exit payload");
            return -1;
        }
        if (hybrid_binapi_payload_exit_shape(exit_payload,
                                             r->binapi_entry_payload,shape)) {
            explicit_bzero(exit_payload,sizeof(exit_payload));
            explicit_bzero(r->binapi_entry_payload,sizeof(r->binapi_entry_payload));
            r->binapi_entry_payload_valid=0;
            fail("cannot compare fixed NV2081_BINAPI payload snapshots");
            return -1;
        }
        explicit_bzero(exit_payload,sizeof(exit_payload));
        explicit_bzero(r->binapi_entry_payload,sizeof(r->binapi_entry_payload));
        r->binapi_entry_payload_valid=0;
    }
    ++binapi_payload_snapshots_read;
    return 0;
}
static int snapshot_gpu_id_info(pid_t tid,const struct record *r,
                                struct gpu_id_info *out) {
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS params;
    uint64_t current_params;

    memset(out,0,sizeof(*out));
    if (read_memory(tid,r->packet_address,&control,sizeof(control)))
        return -1;
    current_params=(uint64_t)(uintptr_t)control.params;
    if ((uint32_t)control.cmd!=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2 ||
        control.paramsSize!=sizeof(params) ||
        current_params!=r->params_address ||
        (uint32_t)control.hClient!=r->client_handle ||
        (uint32_t)control.hObject!=r->object_handle)
        return -1;
    if (_IOC_NR(r->request)==NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (read_memory(tid,r->address,&xfer,sizeof(xfer)) ||
            xfer.cmd!=NV_ESC_RM_CONTROL || xfer.size!=sizeof(control) ||
            (uint64_t)(uintptr_t)xfer.ptr!=r->packet_address)
            return -1;
    }
    if (read_memory(tid,r->params_address,&params,sizeof(params)))
        return -1;

    out->command=(uint32_t)control.cmd;
    out->flags=control.flags;
    out->params_size=control.paramsSize;
    out->status=(uint32_t)control.status;
    out->client_handle_present=(control.hClient!=0);
    out->object_handle_present=(control.hObject!=0);
    out->client_matches_prior_root=matches_prior_root_client((uint32_t)control.hClient);
    out->object_matches_prior_root=matches_prior_root_client((uint32_t)control.hObject);
    out->client_object_equal=control.hClient!=0 && control.hClient==control.hObject;
    out->gpu_id=params.gpuId;
    out->gpu_flags=params.gpuFlags;
    out->device_instance=params.deviceInstance;
    out->subdevice_instance=params.subDeviceInstance;
    out->sli_status=params.sliStatus;
    out->board_id=params.boardId;
    out->gpu_instance=params.gpuInstance;
    out->numa_id=params.numaId;
    return 0;
}
static int snapshot_attached_ids(pid_t tid,const struct record *r,
                                 struct attached_ids_info *out) {
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS params;
    uint64_t current_params;

    memset(out,0,sizeof(*out));
    if (read_memory(tid,r->packet_address,&control,sizeof(control)))
        return -1;
    current_params=(uint64_t)(uintptr_t)control.params;
    if ((uint32_t)control.cmd!=NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS ||
        control.paramsSize!=sizeof(params) || current_params!=r->params_address ||
        (uint32_t)control.hClient!=r->client_handle ||
        (uint32_t)control.hObject!=r->object_handle)
        return -1;
    if (_IOC_NR(r->request)==NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (read_memory(tid,r->address,&xfer,sizeof(xfer)) ||
            xfer.cmd!=NV_ESC_RM_CONTROL || xfer.size!=sizeof(control) ||
            (uint64_t)(uintptr_t)xfer.ptr!=r->packet_address)
            return -1;
    }
    if (read_memory(tid,r->params_address,&params,sizeof(params)))
        return -1;

    out->command=(uint32_t)control.cmd;
    out->flags=control.flags;
    out->params_size=control.paramsSize;
    out->status=(uint32_t)control.status;
    out->client_handle_present=(control.hClient!=0);
    out->object_handle_present=(control.hObject!=0);
    out->client_matches_prior_root=matches_prior_root_client((uint32_t)control.hClient);
    out->object_matches_prior_root=matches_prior_root_client((uint32_t)control.hObject);
    out->client_object_equal=control.hClient!=0 && control.hClient==control.hObject;
    memcpy(out->gpu_ids,params.gpuIds,sizeof(out->gpu_ids));
    return 0;
}
static int snapshot_probed_ids(pid_t tid,const struct record *r,
                               struct probed_ids_info *out) {
    NVOS54_PARAMETERS control;
    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS params;
    uint64_t current_params;

    memset(out,0,sizeof(*out));
    if (read_memory(tid,r->packet_address,&control,sizeof(control)))
        return -1;
    current_params=(uint64_t)(uintptr_t)control.params;
    if ((uint32_t)control.cmd!=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS ||
        control.paramsSize!=sizeof(params) || current_params!=r->params_address ||
        (uint32_t)control.hClient!=r->client_handle ||
        (uint32_t)control.hObject!=r->object_handle)
        return -1;
    if (_IOC_NR(r->request)==NV_ESC_IOCTL_XFER_CMD) {
        nv_ioctl_xfer_t xfer;
        if (read_memory(tid,r->address,&xfer,sizeof(xfer)) ||
            xfer.cmd!=NV_ESC_RM_CONTROL || xfer.size!=sizeof(control) ||
            (uint64_t)(uintptr_t)xfer.ptr!=r->packet_address)
            return -1;
    }
    if (read_memory(tid,r->params_address,&params,sizeof(params)))
        return -1;

    out->command=(uint32_t)control.cmd;
    out->flags=(uint32_t)control.flags;
    out->params_size=(uint32_t)control.paramsSize;
    out->status=(uint32_t)control.status;
    out->client_handle_present=control.hClient!=0;
    out->object_handle_present=control.hObject!=0;
    out->client_object_equal=control.hClient!=0 && control.hClient==control.hObject;
    out->client_matches_prior_root=matches_prior_root_client((uint32_t)control.hClient);
    out->object_matches_prior_root=matches_prior_root_client((uint32_t)control.hObject);
    memcpy(out->gpu_ids,params.gpuIds,sizeof(out->gpu_ids));
    memcpy(out->excluded_gpu_ids,params.excludedGpuIds,sizeof(out->excluded_gpu_ids));
    memcpy(out->gpu_flags,params.gpuFlags,sizeof(out->gpu_flags));
    return 0;
}
static int descriptor_role(pid_t tid,int fd) {
    char path[80],target[PATH_MAX+1];
    ssize_t count;

    if (fd < 0)
        return 3;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%d",(long)tid,fd);
    count=readlink(path,target,sizeof(target)-1);
    if (count<0)
        return 3;
    target[count]=0;
    if (!strcmp(target,control_path))
        return 0;
    if (gpu_path != NULL && !strcmp(target,gpu_path))
        return 1;
    return 2;
}
static int descriptor_matches_path(pid_t tid,int fd,const char *expected_path) {
    char path[80],target[PATH_MAX+1];
    ssize_t count;

    if (fd<0 || expected_path==NULL)
        return 0;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%d",(long)tid,fd);
    count=readlink(path,target,sizeof(target)-1);
    if (count<0)
        return 0;
    target[count]=0;
    return !strcmp(target,expected_path);
}
static int read_exact_int32(pid_t tid,uint64_t address,int32_t *output) {
    struct iovec local={.iov_base=output,.iov_len=sizeof(*output)};
    struct iovec remote={.iov_base=(void *)(uintptr_t)address,
                         .iov_len=sizeof(*output)};
    ssize_t count;

    if (!address || address>UINT64_MAX-sizeof(*output))
        return -1;
    do {
        count=process_vm_readv(tid,&local,1,&remote,1,0);
    } while (count<0 && errno==EINTR);
    return count==(ssize_t)sizeof(*output)?0:-1;
}
static uint64_t tracked_file_id(int fd) {
    if (fd<0 || fd>=MAX_TRACKED_FDS)
        return 0;
    return fd_identities[fd].file_id;
}
static void assign_file_id(int fd,int role,uint64_t file_id) {
    if (fd<0 || fd>=MAX_TRACKED_FDS) {
        if (role<=1) fail("selected descriptor exceeds file-identity tracking range");
        return;
    }
    fd_identities[fd].file_id=file_id;
    fd_identities[fd].role=role;
}
static void invalidate_all_file_ids(void) {
    for (size_t fd=0;fd<MAX_TRACKED_FDS;fd++) {
        if (fd_identities[fd].file_id)
            fd_identity_capture_complete=0;
        fd_identities[fd].file_id=0;
        fd_identities[fd].role=2;
    }
}
static void append_fd_event(pid_t tid,int fd,int role,int kind,int64_t result,
                            int source_fd,uint64_t file_id,uint64_t replaced_file_id,
                            uint64_t request) {
    if (nrecords==MAX_RECORDS) { fail("record limit exceeded"); return; }
    struct record *r=&records[nrecords++];
    memset(r,0,sizeof(*r));
    r->tid=tid;
    r->fd=fd;
    r->fd_role=role;
    r->fd_event_kind=kind;
    r->fd_source=source_fd;
    r->fd_file_id=file_id;
    r->fd_replaced_file_id=replaced_file_id;
    r->request=request;
    r->returned=1;
    r->result=result;
}
static void start_fd_op(struct task *task,int kind,int source,int target,
                        uint64_t arg0,uint64_t arg1,uint64_t arg2,
                        uint64_t request) {
    task->fd_op_kind=kind;
    task->fd_op_source=source;
    task->fd_op_target=target;
    task->fd_op_arg0=arg0;
    task->fd_op_arg1=arg1;
    task->fd_op_arg2=arg2;
    task->fd_op_source_id=tracked_file_id(source);
    task->fd_op_request=request;
}
static int fd_lifecycle_entry(struct task *task,
                              const struct ptrace_syscall_info *info) {
    uint64_t nr=info->entry.nr;
    int source=-1,target=-1,source_role=2,target_role=2;
#ifdef SYS_unshare
    if (capture_uvm_vaspace_fd && nr==SYS_unshare &&
        (info->entry.args[0]&CLONE_FILES)) {
        /* A private fd table cannot be merged into this process-wide model. */
        fd_identity_capture_complete=0;
        return 1;
    }
#endif
    if (nr==SYS_openat
#ifdef SYS_open
        || nr==SYS_open
#endif
#ifdef SYS_openat2
        || nr==SYS_openat2
#endif
       ) {
        start_fd_op(task,FD_OP_OPEN,-1,-1,info->entry.args[0],
                    info->entry.args[1],info->entry.args[2],nr);
        return 1;
    }
#ifdef SYS_dup
    if (nr==SYS_dup) {
        source=(int)info->entry.args[0];
        source_role=descriptor_role(task->tid,source);
        if (source_role<=1)
            start_fd_op(task,FD_OP_DUP,source,-1,0,0,0,nr);
        return 1;
    }
#endif
#ifdef SYS_dup2
    if (nr==SYS_dup2) {
        source=(int)info->entry.args[0]; target=(int)info->entry.args[1];
        source_role=descriptor_role(task->tid,source);
        target_role=descriptor_role(task->tid,target);
        if (source_role<=1 || target_role<=1)
            start_fd_op(task,FD_OP_DUP,source,target,0,0,0,nr);
        return 1;
    }
#endif
#ifdef SYS_dup3
    if (nr==SYS_dup3) {
        source=(int)info->entry.args[0]; target=(int)info->entry.args[1];
        source_role=descriptor_role(task->tid,source);
        target_role=descriptor_role(task->tid,target);
        if (source_role<=1 || target_role<=1)
            start_fd_op(task,FD_OP_DUP,source,target,0,0,0,nr);
        return 1;
    }
#endif
#ifdef SYS_fcntl
    if (nr==SYS_fcntl &&
        (info->entry.args[1]==F_DUPFD || info->entry.args[1]==F_DUPFD_CLOEXEC)) {
        source=(int)info->entry.args[0];
        source_role=descriptor_role(task->tid,source);
        if (source_role<=1)
            start_fd_op(task,FD_OP_FCNTL_DUP,source,-1,info->entry.args[1],
                        info->entry.args[2],0,nr);
        return 1;
    }
#endif
#ifdef SYS_close_range
    if (nr==SYS_close_range) {
        start_fd_op(task,FD_OP_CLOSE_RANGE,-1,-1,info->entry.args[0],
                    info->entry.args[1],info->entry.args[2],nr);
        return 1;
    }
#endif
    return 0;
}
static void finish_fd_op(struct task *task,int64_t result) {
    int kind=task->fd_op_kind;
    if (kind==FD_OP_NONE)
        return;
    if (kind==FD_OP_OPEN && result>=0 && result<=INT_MAX) {
        int fd=(int)result;
        int role=descriptor_role(task->tid,fd);
        if (role<=1) {
            if (next_fd_file_id==0 || next_fd_file_id==UINT64_MAX) {
                fail("file-identity counter exhausted");
            } else {
                uint64_t id=next_fd_file_id++;
                assign_file_id(fd,role,id);
                append_fd_event(task->tid,fd,role,1,result,-1,id,0,
                                task->fd_op_request);
            }
        }
    } else if ((kind==FD_OP_DUP || kind==FD_OP_FCNTL_DUP) && result>=0 &&
               result<=INT_MAX) {
        int fd=(int)result;
        int role=descriptor_role(task->tid,fd);
        if (role<=1) {
            uint64_t id=task->fd_op_source_id;
            uint64_t replaced_id=task->fd_op_target==fd &&
                task->fd_op_target!=task->fd_op_source?
                tracked_file_id(fd):0;
            if (!id)
                fd_identity_capture_complete=0;
            assign_file_id(fd,role,id);
            append_fd_event(task->tid,fd,role,2,result,task->fd_op_source,id,
                            replaced_id,task->fd_op_request);
        } else if (task->fd_op_target>=0) {
            if (capture_event_cleanup && tracked_file_id(fd))
                fd_identity_capture_complete=0;
            assign_file_id(fd,role,0);
        }
    } else if (kind==FD_OP_CLOSE_RANGE) {
        uint64_t first=task->fd_op_arg0,last=task->fd_op_arg1;
        uint64_t capped=last;
        if (result==0 && (task->fd_op_arg2 & CLOSE_RANGE_UNSHARE))
            fd_identity_capture_complete=0;
        if (result==0 && first<MAX_TRACKED_FDS && capped>=MAX_TRACKED_FDS)
            capped=MAX_TRACKED_FDS-1;
        struct record *range_record=NULL;
        if (nrecords==MAX_RECORDS) {
            fail("record limit exceeded");
        } else {
            range_record=&records[nrecords++];
            memset(range_record,0,sizeof(*range_record));
            range_record->tid=task->tid;
            range_record->fd=-1;
            range_record->fd_role=2;
            range_record->fd_event_kind=3;
            range_record->fd_range_first=first;
            range_record->fd_range_last=last;
            range_record->fd_range_flags=(uint32_t)task->fd_op_arg2;
            range_record->request=task->fd_op_request;
            range_record->returned=1;
            range_record->result=result;
        }
        if (result==0 && first<MAX_TRACKED_FDS && first<=capped) {
            for (uint64_t fd=first;fd<=capped;fd++) {
                uint64_t file_id=fd_identities[fd].file_id;
                int role=fd_identities[fd].role;
                if (capture_event_cleanup && role<=1 && !file_id)
                    fd_identity_capture_complete=0;
                if (capture_event_cleanup && !(task->fd_op_arg2 & CLOSE_RANGE_CLOEXEC) &&
                    file_id && role<=1 && range_record) {
                    if (range_record->fd_range_file_id_count==MAX_RANGE_FILE_IDS) {
                        fail("selected close-range descriptor list overflow");
                    } else {
                        uint32_t index=range_record->fd_range_file_id_count++;
                        range_record->fd_range_file_ids[index]=file_id;
                        range_record->fd_range_fds[index]=(int)fd;
                    }
                }
                if (!file_id)
                    continue;
                if (task->fd_op_arg2 & CLOSE_RANGE_CLOEXEC) {
                    fd_identities[fd].file_id=0;
                    fd_identity_capture_complete=0;
                } else {
                    fd_identities[fd].file_id=0;
                    fd_identities[fd].role=2;
                }
                if (task->fd_op_arg2 & CLOSE_RANGE_UNSHARE)
                    fd_identity_capture_complete=0;
            }
        }
    }
    task->fd_op_kind=FD_OP_NONE;
    task->fd_op_source=-1;
    task->fd_op_target=-1;
    task->fd_op_source_id=0;
    task->fd_op_request=0;
}
static int fd_identity_transition_pending(int fd) {
    if (fd<0)
        return 0;
    for (size_t i=0;i<ntasks;i++) {
        const struct task *task=&tasks[i];
        if (!task->alive)
            continue;
        if (task->pending>=0 && (size_t)task->pending<nrecords) {
            const struct record *r=&records[task->pending];
            if (r->is_close && r->fd==fd)
                return 1;
        }
        if (task->fd_op_kind==FD_OP_DUP && task->fd_op_target==fd &&
            task->fd_op_source!=fd)
            return 1;
        if (task->fd_op_kind==FD_OP_CLOSE_RANGE &&
            (uint64_t)fd>=task->fd_op_arg0 && (uint64_t)fd<=task->fd_op_arg1)
            return 1;
    }
    return 0;
}
static int snapshot_map_memory(pid_t tid,const struct record *r,
                               struct map_memory_info *out) {
    nv_ioctl_nvos33_parameters_with_fd wrapper;
    const NVOS33_PARAMETERS *params;

    if (_IOC_TYPE(r->request)!=NV_IOCTL_MAGIC ||
        _IOC_NR(r->request)!=NV_ESC_RM_MAP_MEMORY ||
        _IOC_DIR(r->request)!=(_IOC_READ|_IOC_WRITE) ||
        r->size!=sizeof(wrapper))
        return -1;
    if (read_memory(tid,r->address,&wrapper,sizeof(wrapper)))
        return -1;
    params=&wrapper.params;
    memset(out,0,sizeof(*out));
    out->length=params->length;
    out->status=(uint32_t)params->status;
    out->flags=(uint32_t)params->flags;
    out->client_handle_present=params->hClient!=0;
    out->device_handle_present=params->hDevice!=0;
    out->memory_handle_present=params->hMemory!=0;
    out->offset_nonzero=params->offset!=0;
    out->linear_address_present=params->pLinearAddress!=0;
    out->memory_class=channel_handle_class(params->hClient,params->hMemory);
    out->backend_fd=wrapper.fd;
    out->backend_fd_role=descriptor_role(tid,wrapper.fd);
    out->backend_file_id=tracked_file_id((int)wrapper.fd);
    if (out->backend_fd_role<=1 && !out->backend_file_id)
        fd_identity_capture_complete=0;
    return 0;
}
static int snapshot_unmap_memory(pid_t tid,const struct record *r,
                                 struct unmap_memory_info *out) {
    NVOS34_PARAMETERS params;

    if (_IOC_TYPE(r->request)!=NV_IOCTL_MAGIC ||
        _IOC_NR(r->request)!=NV_ESC_RM_UNMAP_MEMORY ||
        _IOC_DIR(r->request)!=(_IOC_READ|_IOC_WRITE) ||
        r->size!=sizeof(params))
        return -1;
    if (read_memory(tid,r->address,&params,sizeof(params)))
        return -1;
    memset(out,0,sizeof(*out));
    out->status=(uint32_t)params.status;
    out->flags=(uint32_t)params.flags;
    out->client_handle_present=params.hClient!=0;
    out->device_handle_present=params.hDevice!=0;
    out->memory_handle_present=params.hMemory!=0;
    out->linear_address_present=params.pLinearAddress!=0;
    return 0;
}
static void mmap_entry(struct task *task,const struct ptrace_syscall_info *info) {
    uint64_t raw_fd=info->entry.args[4];
    char path[80],target[PATH_MAX+1];
    ssize_t count;
    int role;
    if (task->pending>=0) { fail("unpaired syscall entry"); return; }
    if (task->fd_op_kind!=FD_OP_NONE) { fail("unpaired descriptor-lifecycle syscall"); return; }
    if (raw_fd>INT_MAX) return;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%u",(long)task->tid,(unsigned)raw_fd);
    count=readlink(path,target,sizeof(target)-1);
    if (count<0) return;
    target[count]=0;
    if (!strcmp(target,control_path))
        role=0;
    else if (gpu_path!=NULL && !strcmp(target,gpu_path))
        role=1;
    else
        return;
    if (nrecords==MAX_RECORDS) { fail("record limit exceeded"); return; }
    struct record *r=&records[nrecords];
    memset(r,0,sizeof(*r));
    r->tid=task->tid;
    r->fd=(int)raw_fd;
    r->fd_role=role;
    r->fd_file_id=tracked_file_id((int)raw_fd);
    r->request=SYS_mmap;
    r->is_mmap=1;
    r->mmap.length=info->entry.args[1];
    r->mmap.prot=(uint32_t)info->entry.args[2];
    r->mmap.flags=(uint32_t)info->entry.args[3];
    r->mmap.offset_zero=info->entry.args[5]==0;
    r->mmap.file_id=tracked_file_id((int)raw_fd);
    if (!r->mmap.file_id)
        fd_identity_capture_complete=0;
    r->has_entry=1;
    task->pending=(int)nrecords++;
}
static void close_entry(struct task *task,const struct ptrace_syscall_info *info) {
    uint64_t raw_fd=info->entry.args[0];
    int role;
    if (task->pending>=0) { fail("unpaired syscall entry"); return; }
    if (raw_fd>INT_MAX) return;
    role=descriptor_role(task->tid,(int)raw_fd);
    if (role>1) return;
    if (nrecords==MAX_RECORDS) { fail("record limit exceeded"); return; }
    struct record *r=&records[nrecords];
    memset(r,0,sizeof(*r));
    r->tid=task->tid;
    r->fd=(int)raw_fd;
    r->fd_role=role;
    r->fd_file_id=tracked_file_id((int)raw_fd);
    if (!r->fd_file_id)
        fd_identity_capture_complete=0;
    r->request=SYS_close;
    r->is_close=1;
    r->has_entry=1;
    task->pending=(int)nrecords++;
}
static void entry(struct task *task,const struct ptrace_syscall_info *info) {
    uint64_t request=info->entry.args[1];
    char path[80],target[PATH_MAX+1]; ssize_t count;
    unsigned number=_IOC_NR(request);
    int fd_role;
    if (task->pending>=0) { fail("unpaired syscall entry"); return; }
    if (task->fd_op_kind!=FD_OP_NONE) { fail("unpaired descriptor-lifecycle syscall"); return; }
    if ((capture_map_memory || capture_event_cleanup || capture_uvm_vaspace_fd) &&
        info->entry.nr==SYS_close) {
        close_entry(task,info);
        return;
    }
    if (capture_map_memory && info->entry.nr==SYS_mmap) {
        mmap_entry(task,info);
        return;
    }
    if ((capture_map_memory || capture_event_cleanup || capture_uvm_vaspace_fd) &&
        fd_lifecycle_entry(task,info))
        return;
    if (capture_uvm_vaspace_fd) {
        int is_vaspace=request==UVM_REGISTER_GPU_VASPACE;
        int is_map_external=request==UVM_MAP_EXTERNAL_ALLOCATION;
        if (info->entry.nr!=SYS_ioctl || (!is_vaspace && !is_map_external) ||
            info->entry.args[0]>INT_MAX ||
            !descriptor_matches_path(task->tid,(int)info->entry.args[0],uvm_path))
            return;
        if (nrecords==MAX_RECORDS) {
            fail("record limit exceeded");
            return;
        }
        struct record *r=&records[nrecords];
        uint64_t argument=info->entry.args[2];
        const uint64_t offset=is_vaspace?
                offsetof(UVM_REGISTER_GPU_VASPACE_PARAMS,rmCtrlFd):
                offsetof(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS,rmCtrlFd);
        memset(r,0,sizeof(*r));
        r->tid=task->tid;
        r->fd=-1;
        r->address=argument;
        r->request=request;
        r->size=(unsigned)(is_vaspace?sizeof(UVM_REGISTER_GPU_VASPACE_PARAMS):
                                      sizeof(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS));
        r->is_uvm_vaspace_fd=is_vaspace;
        r->is_uvm_map_external_fd=is_map_external;
        r->uvm_fd_matches_entry=1;
        task->pending=(int)nrecords++;
        if (is_vaspace)
            ++uvm_vaspace_records_seen;
        else
            ++uvm_map_external_records_seen;
        if (argument>UINT64_MAX-offset ||
            read_exact_int32(task->tid,argument+offset,&r->observed_rm_ctrl_fd)) {
            fail("cannot read exact UVM rmCtrlFd field at ioctl entry");
            return;
        }
        r->rm_ctrl_field_read=1;
        r->rm_ctrl_is_negative=r->observed_rm_ctrl_fd<0;
        r->rm_ctrl_matches_entry=descriptor_matches_path(
                task->tid,r->observed_rm_ctrl_fd,control_path);
        if (r->observed_rm_ctrl_fd>=0) {
            int transition_pending=fd_identity_transition_pending(
                    r->observed_rm_ctrl_fd);
            r->rm_ctrl_no_mutation_pending_entry=!transition_pending;
            if (transition_pending)
                fd_identity_capture_complete=0;
            r->rm_ctrl_file_id_entry=tracked_file_id(r->observed_rm_ctrl_fd);
            r->rm_ctrl_identity_tracked_entry=
                    r->rm_ctrl_file_id_entry!=0 && !transition_pending;
            if (transition_pending)
                r->rm_ctrl_file_id_entry=0;
            if (r->rm_ctrl_matches_entry && !r->rm_ctrl_identity_tracked_entry)
                fd_identity_capture_complete=0;
        }
        r->has_entry=1;
        return;
    }
    if (capture_ioctl_shapes) {
        if (info->entry.nr!=SYS_ioctl)
            return;
        uint64_t request=info->entry.args[1];
        size_t expected=selected_ioctl_shape_size(request);
        if (request==OBSERVED_IOCTL_SHAPE_RM_FREE && !capture_event_cleanup)
            expected=0;
        if (!expected || _IOC_SIZE(request)!=expected ||
            info->entry.args[0]>INT_MAX)
            return;
        int role=descriptor_role(task->tid,(int)info->entry.args[0]);
        int expected_role=(request==OBSERVED_IOCTL_SHAPE_GPU_CONTROL_CE ||
                           request==OBSERVED_IOCTL_SHAPE_GPU_CONTROL_CF)?1:0;
        if (role!=expected_role)
            return;
        if (nrecords==MAX_RECORDS) {
            fail("record limit exceeded");
            return;
        }
        struct record *r=&records[nrecords];
        memset(r,0,sizeof(*r));
        r->tid=task->tid;
        r->fd=(int)info->entry.args[0];
        r->fd_role=role;
        if (capture_event_cleanup) {
            r->fd_file_id=tracked_file_id(r->fd);
            if (!r->fd_file_id)
                fd_identity_capture_complete=0;
        }
        r->request=request;
        r->address=info->entry.args[2];
        r->size=(unsigned)expected;
        r->is_ioctl_shape=1;
        task->pending=(int)nrecords++;
        if (snapshot_ioctl_shape(task->tid,r,0))
            fail("cannot read exact selected ioctl-shape input buffer");
        else
            r->has_entry=1;
        return;
    }
    if (info->entry.nr!=SYS_ioctl || _IOC_TYPE(request)!=NV_IOCTL_MAGIC)
        return;
    if (capture_map_memory) {
        if (number!=NV_ESC_RM_MAP_MEMORY && number!=NV_ESC_RM_UNMAP_MEMORY &&
            number!=NV_ESC_RM_ALLOC && number!=NV_ESC_RM_FREE)
            return;
    } else if (number!=NV_ESC_RM_ALLOC && number!=NV_ESC_RM_FREE &&
               !((capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
                  capture_rm_control || capture_fabric_status || capture_system_features ||
                  capture_debugger_lifecycle) &&
                 (number==NV_ESC_RM_CONTROL || number==NV_ESC_IOCTL_XFER_CMD)))
        return;
    if (info->entry.args[0]>INT_MAX) return;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%u",(long)task->tid,(unsigned)info->entry.args[0]);
    count=readlink(path,target,sizeof(target)-1);
    if (count<0) { fail("cannot resolve matching ioctl descriptor"); return; }
    target[count]=0;
    if (!strcmp(target,control_path))
        fd_role=0;
    else if (gpu_path != NULL && !strcmp(target,gpu_path))
        fd_role=1;
    else
        return;
    if (nrecords==MAX_RECORDS) { fail("record limit exceeded"); return; }
    struct record candidate={0};
    struct record *r=&records[nrecords];
    r->tid=task->tid; r->fd=(int)info->entry.args[0]; r->fd_role=fd_role;
    if (capture_map_memory || capture_event_cleanup) {
        r->fd_file_id=tracked_file_id(r->fd);
        if (!r->fd_file_id)
            fd_identity_capture_complete=0;
    }
    r->request=request; r->address=info->entry.args[2];
    r->packet_address=r->address;
    r->size=_IOC_SIZE(request); r->is_alloc=number==NV_ESC_RM_ALLOC;
    r->is_map_memory=capture_map_memory && number==NV_ESC_RM_MAP_MEMORY;
    r->is_unmap_memory=capture_map_memory && number==NV_ESC_RM_UNMAP_MEMORY;
    if (r->is_map_memory || r->is_unmap_memory) {
        task->pending=(int)nrecords++;
        if (r->is_map_memory) {
            if (snapshot_map_memory(task->tid,r,&r->map_entry))
                fail("cannot read fixed NVOS33 map wrapper or invalid map ioctl layout");
            else r->has_entry=1;
        } else {
            if (snapshot_unmap_memory(task->tid,r,&r->unmap_entry))
                fail("cannot read fixed NVOS34 unmap packet or invalid unmap ioctl layout");
            else r->has_entry=1;
        }
        return;
    }
    if (capture_map_memory &&
        (number==NV_ESC_RM_ALLOC || number==NV_ESC_RM_FREE)) {
        r->is_class_tracking_only=1;
        task->pending=(int)nrecords++;
        if (snapshot(task->tid,r,&r->entry))
            fail("cannot read fixed RM_ALLOC/RM_FREE header for map class resolution");
        else if (capture_rusd_alloc && r->is_alloc &&
                 r->entry.klass==RM_USER_SHARED_DATA) {
            r->is_rusd_alloc=1;
            if (!snapshot_rusd_alloc(task->tid,&r->entry,NULL,&r->rusd_entry))
                r->has_entry=1;
        }
        else
            r->has_entry=1;
        return;
    }
    if (number!=NV_ESC_RM_ALLOC && number!=NV_ESC_RM_FREE) {
        candidate.tid=r->tid; candidate.fd=r->fd; candidate.request=r->request;
        candidate.address=r->address; candidate.size=r->size;
        int selected=identify_rm_control(task->tid,request,r->address,&candidate);
        if (selected<=0) {
            if (selected<0 && (candidate.is_gpu_id_info || candidate.is_attached_ids ||
                               candidate.is_probed_ids ||
                               candidate.is_rm_control)) {
                *r=candidate;
                task->pending=(int)nrecords++;
            }
            return;
        }
        *r=candidate;
    }
    task->pending=(int)nrecords++;
    if (r->is_gpu_id_info) {
        if (snapshot_gpu_id_info(task->tid,r,&r->gpu_entry))
            fail("cannot read GPU ID-info payload or invalid parameter size");
        else r->has_entry=1;
    } else if (r->is_attached_ids) {
        if (snapshot_attached_ids(task->tid,r,&r->attached_entry))
            fail("cannot read attached-ID payload or invalid parameter size");
        else r->has_entry=1;
    } else if (r->is_probed_ids) {
        if (snapshot_probed_ids(task->tid,r,&r->probed_entry))
            fail("cannot read probed-ID payload or invalid parameter size");
        else r->has_entry=1;
    } else if (r->is_rm_control) {
        if (snapshot_rm_control_header(task->tid,r,&r->rm_control_entry,0))
            fail("cannot read RM_CONTROL header or packet changed");
        else {
            r->has_entry=1;
            if (snapshot_debugger_exception_mask_payload(
                    task->tid,r,&r->rm_control_entry,0))
                return;
            if (r->is_binapi_control)
                (void)snapshot_binapi_control_payload(task->tid,r,
                                                       &r->rm_control_entry,0);
        }
    } else if (snapshot(task->tid,r,&r->entry)) {
        fail("cannot read RM entry packet or unsupported size");
    } else if (capture_channel_alloc && r->is_alloc &&
               is_channel_gpfifo_class(r->entry.klass)) {
        r->is_channel_alloc=1;
        (void)snapshot_channel_alloc(task->tid,&r->entry,&r->channel_entry);
        r->has_entry=1;
    } else if (capture_rusd_alloc && r->is_alloc &&
               r->entry.klass==RM_USER_SHARED_DATA) {
        r->is_rusd_alloc=1;
        if (!snapshot_rusd_alloc(task->tid,&r->entry,NULL,&r->rusd_entry))
            r->has_entry=1;
    } else if (capture_p2p_alloc && r->is_alloc &&
               r->entry.klass==NV50_THIRD_PARTY_P2P) {
        r->is_p2p_alloc=1;
        if (!snapshot_p2p_alloc(task->tid,&r->entry,NULL,&r->p2p_entry))
            r->has_entry=1;
    } else if (capture_device_alloc && r->is_alloc &&
               r->entry.klass==NV01_DEVICE_0) {
        r->is_device_alloc=1;
        if (!snapshot_device_alloc(task->tid,&r->entry,NULL,
                                  &r->device_alloc_entry))
            r->has_entry=1;
    } else if (capture_subdevice_alloc && r->is_alloc &&
               r->entry.klass==NV20_SUBDEVICE_0) {
        r->is_subdevice_alloc=1;
        if (!snapshot_subdevice_alloc(task->tid,&r->entry,NULL,
                                      &r->subdevice_alloc_entry))
            r->has_entry=1;
    } else if (capture_binapi_alloc && r->is_alloc &&
               r->entry.klass==NV2081_BINAPI) {
        r->is_binapi_alloc=1;
        if (!snapshot_binapi_alloc(task->tid,&r->entry,NULL,
                                   &r->binapi_alloc_entry))
            r->has_entry=1;
    } else if (capture_debugger_lifecycle && !r->is_alloc) {
        struct channel_handle_class_ref class_ref;
        if (snapshot(task->tid,r,&r->entry)) {
            fail("cannot read fixed RM_FREE header for debugger lifecycle capture");
        } else {
            class_ref = channel_handle_class(r->entry.root,r->entry.object);
            if (r->entry.root != 0 && r->entry.object != 0 &&
                class_ref.resolution != RM_HANDLE_RESOLVED)
                ++debugger_free_unresolved_count;
            if (class_ref.resolution == RM_HANDLE_RESOLVED &&
                class_ref.class_id == GT200_DEBUGGER) {
                r->is_debugger_free=1;
                r->debugger_free_class=class_ref.class_id;
            } else {
                r->is_class_tracking_only=1;
            }
            r->has_entry=1;
        }
    } else if ((capture_debugger_alloc || capture_debugger_lifecycle) &&
               r->is_alloc &&
               r->entry.klass==GT200_DEBUGGER) {
        r->is_debugger_alloc=1;
        if (!snapshot_debugger_alloc(task->tid,&r->entry,NULL,NULL,
                                     &r->debugger_alloc_entry))
            r->has_entry=1;
    } else if (capture_debugger_alloc || capture_debugger_lifecycle) {
        r->is_class_tracking_only=1;
        r->has_entry=1;
    } else r->has_entry=1;
}
static void syscall_stop(struct task *task) {
    struct ptrace_syscall_info info;
    memset(&info,0,sizeof(info));
    long count=ptrace(PTRACE_GET_SYSCALL_INFO,task->tid,sizeof(info),&info);
    if (count<0) { fail("PTRACE_GET_SYSCALL_INFO unavailable"); return; }
    if ((size_t)count<offsetof(struct ptrace_syscall_info,entry)) {
        fail("truncated syscall-stop information"); return;
    }
    if (info.arch!=AUDIT_ARCH_X86_64) { fail("unsupported tracee architecture"); return; }
    if (info.op==PTRACE_SYSCALL_INFO_ENTRY) {
        if ((size_t)count<offsetof(struct ptrace_syscall_info,entry.args)+sizeof(info.entry.args)) {
            fail("truncated syscall entry"); return;
        }
        if (info.entry.nr & 0x40000000ULL) { fail("x32 tracee ABI unsupported"); return; }
        entry(task,&info);
    }
    else if (info.op==PTRACE_SYSCALL_INFO_EXIT) {
        if ((size_t)count<offsetof(struct ptrace_syscall_info,exit.is_error)+sizeof(info.exit.is_error)) {
            fail("truncated syscall exit"); return;
        }
        if (task->pending>=0) {
            struct record *r=&records[task->pending];
            r->returned=1; r->result=info.exit.rval;
            if (r->is_uvm_vaspace_fd || r->is_uvm_map_external_fd) {
                if (r->rm_ctrl_field_read) {
                    const uint64_t offset=r->is_uvm_vaspace_fd?
                            offsetof(UVM_REGISTER_GPU_VASPACE_PARAMS,rmCtrlFd):
                            offsetof(UVM_MAP_EXTERNAL_ALLOCATION_PARAMS,rmCtrlFd);
                    int32_t fd_at_exit=0;
                    if (r->address>UINT64_MAX-offset ||
                        read_exact_int32(task->tid,r->address+offset,&fd_at_exit)) {
                        fail("cannot reread exact UVM rmCtrlFd field at ioctl return");
                    } else {
                        r->rm_ctrl_field_unchanged_exit=
                                fd_at_exit==r->observed_rm_ctrl_fd;
                        if (!r->rm_ctrl_field_unchanged_exit)
                            fd_identity_capture_complete=0;
                    }
                    r->rm_ctrl_matches_exit=descriptor_matches_path(
                            task->tid,r->observed_rm_ctrl_fd,control_path);
                    int transition_pending=fd_identity_transition_pending(
                            r->observed_rm_ctrl_fd);
                    r->rm_ctrl_no_mutation_pending_exit=!transition_pending;
                    if (transition_pending)
                        fd_identity_capture_complete=0;
                    r->rm_ctrl_same_file_identity_exit=
                            r->rm_ctrl_identity_tracked_entry &&
                            !transition_pending &&
                            tracked_file_id(r->observed_rm_ctrl_fd)==r->rm_ctrl_file_id_entry;
                }
                r->has_exit=1;
            } else if (r->is_ioctl_shape) {
                if (snapshot_ioctl_shape(task->tid,r,1))
                    fail("cannot read exact selected ioctl-shape output buffer");
                else
                    r->has_exit=1;
            } else if (r->is_map_memory) {
                if (snapshot_map_memory(task->tid,r,&r->map_exit))
                    fail("cannot read fixed NVOS33 map exit wrapper or packet changed");
                else r->has_exit=1;
            } else if (r->is_unmap_memory) {
                if (snapshot_unmap_memory(task->tid,r,&r->unmap_exit))
                    fail("cannot read fixed NVOS34 unmap exit packet or packet changed");
                else r->has_exit=1;
            } else if (r->is_mmap) {
                r->has_exit=1;
            } else if (r->is_close) {
                r->has_exit=1;
                if (r->result==0) {
                    assign_file_id(r->fd,2,0);
                } else {
                    assign_file_id(r->fd,2,0);
                    fd_identity_capture_complete=0;
                }
            } else if (r->is_gpu_id_info) {
                if (snapshot_gpu_id_info(task->tid,r,&r->gpu_exit))
                    fail("cannot read GPU ID-info exit payload or packet changed");
                else r->has_exit=1;
            } else if (r->is_attached_ids) {
                if (snapshot_attached_ids(task->tid,r,&r->attached_exit))
                    fail("cannot read attached-ID exit payload or packet changed");
                else r->has_exit=1;
            } else if (r->is_probed_ids) {
                if (snapshot_probed_ids(task->tid,r,&r->probed_exit))
                    fail("cannot read probed-ID exit payload or packet changed");
                else r->has_exit=1;
            } else if (r->is_rm_control) {
                if (snapshot_rm_control_header(task->tid,r,&r->rm_control_exit,1))
                    fail("cannot read RM_CONTROL exit header or packet changed");
                else {
                    if (snapshot_debugger_exception_mask_payload(
                            task->tid,r,&r->rm_control_exit,1)) {
                        /* Keep the failed capture out of the accepted trace. */
                    } else {
                        r->has_exit=1;
                    }
                    if (r->is_binapi_control)
                        (void)snapshot_binapi_control_payload(task->tid,r,
                                                               &r->rm_control_exit,1);
                }
            } else if (r->is_debugger_free) {
                if (snapshot(task->tid,r,&r->exit) ||
                    r->exit.layout!=r->entry.layout ||
                    r->exit.root!=r->entry.root ||
                    r->exit.parent!=r->entry.parent ||
                    r->exit.object!=r->entry.object)
                    fail("GT200_DEBUGGER RM_FREE packet changed");
                else
                    r->has_exit=1;
            } else if (snapshot(task->tid,r,&r->exit))
                fail("cannot read RM exit packet");
            else if (r->is_channel_alloc) {
                (void)snapshot_channel_alloc(task->tid,&r->exit,&r->channel_exit);
                r->has_exit=1;
            } else if (r->is_rusd_alloc) {
                if (!snapshot_rusd_alloc(task->tid,&r->exit,&r->entry,
                                         &r->rusd_exit))
                    r->has_exit=1;
            } else if (r->is_p2p_alloc) {
                if (!snapshot_p2p_alloc(task->tid,&r->exit,&r->entry,
                                        &r->p2p_exit))
                    r->has_exit=1;
            } else if (r->is_device_alloc) {
                if (!snapshot_device_alloc(task->tid,&r->exit,&r->entry,
                                          &r->device_alloc_exit))
                    r->has_exit=1;
            } else if (r->is_subdevice_alloc) {
                if (!snapshot_subdevice_alloc(task->tid,&r->exit,&r->entry,
                                              &r->subdevice_alloc_exit))
                    r->has_exit=1;
            } else if (r->is_binapi_alloc) {
                if (!snapshot_binapi_alloc(task->tid,&r->exit,&r->entry,
                                           &r->binapi_alloc_exit))
                    r->has_exit=1;
            } else if (r->is_debugger_alloc) {
                if (!snapshot_debugger_alloc(task->tid,&r->exit,&r->entry,
                                             &r->debugger_alloc_entry,
                                             &r->debugger_alloc_exit))
                    r->has_exit=1;
            } else r->has_exit=1;
            update_handle_registry(r);
            task->pending=-1;
        } else if (task->fd_op_kind!=FD_OP_NONE) {
            finish_fd_op(task,info.exit.rval);
        }
    } else fail("unexpected syscall-stop information");
}
static int same_thread_group(pid_t tid,pid_t child) {
    char path[80],line[256]; FILE *f;
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)tid);
    f=fopen(path,"r"); if (!f) return 0;
    while (fgets(line,sizeof(line),f)) {
        long tgid;
        if (sscanf(line,"Tgid: %ld",&tgid)==1) { fclose(f); return tgid==child; }
    }
    fclose(f); return 0;
}
static int same_file_table(pid_t first,pid_t second) {
    long result=syscall(SYS_kcmp,first,second,KCMP_FILES,0,0);
    if (result<0)
        return -1;
    return result==0;
}
static void json_string(FILE *f,const char *s) {
    fputc('"',f);
    for (;*s;s++) {
        unsigned char c=(unsigned char)*s;
        if (c=='"' || c=='\\') { fputc('\\',f); fputc(c,f); }
        else if (c<32 || c>=127) fprintf(f,"\\u%04x",c);
        else fputc(c,f);
    }
    fputc('"',f);
}
static void packet_json(FILE *f,const struct packet *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hRoot\":%u,\"hObjectParent\":%u,\"%s\":%u,\"status\":%u",
        p->layout,p->root,p->parent,p->layout?"hObjectNew":"hObjectOld",p->object,p->status);
    if (p->layout) {
        fprintf(f,",\"hClass\":%u,\"root_class\":%s,\"pAllocParms\":%llu,\"paramsSize\":%u",
            p->klass,(p->klass==NV01_ROOT || p->klass==NV01_ROOT_CLIENT)?"true":"false",
            (unsigned long long)p->params,p->size);
        if (p->layout==64) fprintf(f,",\"pRightsRequested\":%llu,\"flags\":%u",(unsigned long long)p->rights,p->flags);
    }
    fputc('}',f);
}
static void gpu_id_info_json(FILE *f,const struct gpu_id_info *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"command\":%u,\"flags\":%u,\"params_size\":%u,\"status\":%u,"
            "\"client_handle_present\":%s,\"object_handle_present\":%s,"
            "\"client_matches_prior_root_allocation\":%s,"
            "\"object_matches_prior_root_allocation\":%s,\"client_object_equal\":%s,"
            "\"gpuId\":%u,\"gpuFlags\":%u,\"deviceInstance\":%u,"
            "\"subDeviceInstance\":%u,\"sliStatus\":%u,\"boardId\":%u,"
            "\"gpuInstance\":%u,\"numaId\":%d}",
        p->command,p->flags,p->params_size,p->status,
        p->client_handle_present?"true":"false",
        p->object_handle_present?"true":"false",
        p->client_matches_prior_root?"true":"false",
        p->object_matches_prior_root?"true":"false",
        p->client_object_equal?"true":"false",p->gpu_id,p->gpu_flags,
        p->device_instance,p->subdevice_instance,p->sli_status,p->board_id,
        p->gpu_instance,p->numa_id);
}
static void attached_ids_json(FILE *f,const struct attached_ids_info *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"command\":%u,\"flags\":%u,\"params_size\":%u,\"status\":%u,"
            "\"client_handle_present\":%s,\"object_handle_present\":%s,"
            "\"client_matches_prior_root_allocation\":%s,"
            "\"object_matches_prior_root_allocation\":%s,\"client_object_equal\":%s,\"gpuIds\":[",
        p->command,p->flags,p->params_size,p->status,
        p->client_handle_present?"true":"false",
        p->object_handle_present?"true":"false",
        p->client_matches_prior_root?"true":"false",
        p->object_matches_prior_root?"true":"false",
        p->client_object_equal?"true":"false");
    for (size_t i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
        fprintf(f,"%s%u",i?",":"",p->gpu_ids[i]);
    fputs("]}",f);
}
static void probed_ids_json(FILE *f,const struct probed_ids_info *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"command\":%u,\"flags\":%u,\"params_size\":%u,\"status\":%u,"
            "\"client_handle_present\":%s,\"object_handle_present\":%s,"
            "\"client_matches_prior_root_allocation\":%s,"
            "\"object_matches_prior_root_allocation\":%s,\"client_object_equal\":%s,\"gpuIds\":[",
        p->command,p->flags,p->params_size,p->status,
        p->client_handle_present?"true":"false",
        p->object_handle_present?"true":"false",
        p->client_matches_prior_root?"true":"false",
        p->object_matches_prior_root?"true":"false",
        p->client_object_equal?"true":"false");
    for (size_t i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++)
        fprintf(f,"%s%u",i?",":"",p->gpu_ids[i]);
    fputs("],\"excludedGpuIds\":[",f);
    for (size_t i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++)
        fprintf(f,"%s%u",i?",":"",p->excluded_gpu_ids[i]);
    fputs("],\"gpuFlags\":[",f);
    for (size_t i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++)
        fprintf(f,"%s%u",i?",":"",p->gpu_flags[i]);
    fputs("]}",f);
}
static void p2p_control_json(FILE *f,const struct p2p_control_info *p) {
    if (!p->recognized) {
        fputs("null",f);
        return;
    }
    fprintf(f,"{\"command\":%u,\"payloadBytes\":%u,\"payloadValid\":%s,"
              "\"inputHandlePresent\":%s",
            p->command,p->payload_bytes,p->payload_valid?"true":"false",
            p->handle_present?"true":"false");
    if (p->command==NV503C_CTRL_CMD_REGISTER_VA_SPACE)
        fprintf(f,",\"vaSpaceTokenNonzeroAtSnapshot\":%s",
                p->token_nonzero?"true":"false");
    if (p->command==NV503C_CTRL_CMD_REGISTER_VIDMEM)
        fprintf(f,",\"addressAligned64K\":%s,\"sizeNonzero\":%s,"
                  "\"sizeAligned64K\":%s,\"offsetAligned64K\":%s,"
                  "\"offsetAndSizeDoNotOverflow\":%s,"
                  "\"addressAndSizeDoNotOverflow\":%s",
                p->address_aligned?"true":"false",
                p->size_nonzero?"true":"false",
                p->size_aligned?"true":"false",
                p->offset_aligned?"true":"false",
                p->offset_size_no_overflow?"true":"false",
                p->address_size_no_overflow?"true":"false");
    fputc('}',f);
}
static void bytes_hex_json(FILE *f,const uint8_t *bytes,size_t size) {
    static const char hex[]="0123456789abcdef";
    fputc('"',f);
    for (size_t i=0;i<size;i++) {
        fputc(hex[(bytes[i]>>4)&0xf],f);
        fputc(hex[bytes[i]&0xf],f);
    }
    fputc('"',f);
}
static void binapi_payload_json(FILE *f,
                                const struct hybrid_binapi_payload_shape *p) {
    fprintf(f,"{\"payloadBytes\":%u,\"payloadValid\":%s,"
              "\"nonzeroU32Count\":%u,\"nonzeroU32MaskLsbFirst\":",
            HYBRID_BINAPI_PARAM_BYTES,p->payload_valid?"true":"false",
            p->nonzero_u32_count);
    bytes_hex_json(f,p->nonzero_u32_mask,sizeof(p->nonzero_u32_mask));
    fprintf(f,",\"changedByteCount\":%u,\"changedByteMaskLsbFirst\":",
            p->changed_byte_count);
    bytes_hex_json(f,p->changed_byte_mask,sizeof(p->changed_byte_mask));
    fputs(",\"entryExitPayloadEqual\":",f);
    if (p->payload_equal<0)
        fputs("null",f);
    else
        fputs(p->payload_equal?"true":"false",f);
    fputc('}',f);
}
static void rm_control_json(FILE *f,const struct rm_control_info *p,int exists,
                            int redact_handles,int include_p2p,
                            int include_binapi,int include_fabric_status,
                            int include_system_features,
                            int include_sync_boost_groups,
                            int include_debugger_allocation_relation) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"command\":%u,\"flags\":%u,\"params_size\":%u,\"status\":%u,",
        p->command,p->flags,p->params_size,p->status);
    if (redact_handles)
        fprintf(f,"\"hClientPresent\":%s,\"hObjectPresent\":%s,",
                p->client_handle?"true":"false",p->object_handle?"true":"false");
    else
        fprintf(f,"\"hClient\":%u,\"hObject\":%u,",
                p->client_handle,p->object_handle);
    fprintf(f,"\"client_object_equal\":%s,"
            "\"client_matches_prior_root_allocation\":%s,"
            "\"object_matches_prior_root_allocation\":%s",
        p->client_object_equal?"true":"false",
        p->client_matches_prior_root?"true":"false",
        p->object_matches_prior_root?"true":"false");
    if (include_debugger_allocation_relation)
        fprintf(f,",\"object_handle_matches_prior_debugger_allocation\":%s",
                p->object_handle_matches_prior_debugger_allocation?"true":"false");
    if (include_fabric_status && p->fabric_status_payload_valid)
        fprintf(f,",\"fabricStatus\":%u",p->fabric_status);
    if (include_system_features && p->system_features_payload_valid)
        fprintf(f,",\"featuresMask\":%u",p->system_features_mask);
    if (include_sync_boost_groups && p->sync_boost_group_payload_valid)
        fprintf(f,",\"syncBoostGroupCount\":%u",p->sync_boost_group_count);
    if (p->debugger_exception_mask_payload_valid)
        fprintf(f,",\"exceptionMask\":%u",p->debugger_exception_mask);
    if (p->debugger_exception_mask_user_buffer_entry_exit_compared)
        fprintf(f,",\"exceptionMaskUserBufferEntryExitEqual\":%s",
                p->debugger_exception_mask_user_buffer_entry_exit_equal?"true":"false");
    if (include_p2p) {
        fputs(",\"p2pControl\":",f);
        p2p_control_json(f,&p->p2p);
        fputs(",\"objectClass\":",f);
        channel_handle_class_ref_json(f,&p->object_class);
    }
    if (include_binapi) {
        fputs(",\"objectClass\":",f);
        channel_handle_class_ref_json(f,&p->object_class);
        fputs(",\"binapiPayload\":",f);
        binapi_payload_json(f,&p->binapi_payload);
    }
    fputc('}',f);
}
static const char *fd_role_name(int role) {
    switch (role) {
    case 0: return "control";
    case 1: return "gpu";
    case 2: return "other";
    default: return "unknown";
    }
}
static void map_memory_json(FILE *f,const struct map_memory_info *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"length\":%llu,\"status\":%u,\"flags\":%u,"
              "\"hClientPresent\":%s,\"hDevicePresent\":%s,"
              "\"hMemoryPresent\":%s,\"offsetNonzero\":%s,"
              "\"linearAddressPresent\":%s,\"memoryObjectClass\":",
            (unsigned long long)p->length,p->status,p->flags,
            p->client_handle_present?"true":"false",
            p->device_handle_present?"true":"false",
            p->memory_handle_present?"true":"false",
            p->offset_nonzero?"true":"false",
            p->linear_address_present?"true":"false");
    channel_handle_class_ref_json(f,&p->memory_class);
    fprintf(f,",\"backendFd\":%u,"
              "\"backendFdRole\":\"%s\",\"backendFileId\":",
            p->backend_fd,
            fd_role_name(p->backend_fd_role));
    if (p->backend_file_id)
        fprintf(f,"%llu}",(unsigned long long)p->backend_file_id);
    else
        fputs("null}",f);
}
static void fd_file_id_json(FILE *f,uint64_t file_id) {
    if (file_id) fprintf(f,"%llu",(unsigned long long)file_id);
    else fputs("null",f);
}
static void mmap_json(FILE *f,const struct mmap_info *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"length\":%llu,\"prot\":%u,\"flags\":%u,\"offsetZero\":%s}",
            (unsigned long long)p->length,p->prot,p->flags,
            p->offset_zero?"true":"false");
}
static void unmap_memory_json(FILE *f,const struct unmap_memory_info *p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"status\":%u,\"flags\":%u,"
              "\"hClientPresent\":%s,\"hDevicePresent\":%s,"
              "\"hMemoryPresent\":%s,\"linearAddressPresent\":%s}",
            p->status,p->flags,
            p->client_handle_present?"true":"false",
            p->device_handle_present?"true":"false",
            p->memory_handle_present?"true":"false",
            p->linear_address_present?"true":"false");
}
static void json_bool(FILE *f,int value) {
    fputs(value?"true":"false",f);
}
static void ioctl_shape_offsets_json(FILE *f,const uint8_t *mask,size_t size) {
    fputc('[',f);
    int first=1;
    for (size_t i=0;i<size;i++) {
        if (!mask[i])
            continue;
        fprintf(f,"%s%zu",first?"":",",i);
        first=0;
    }
    fputc(']',f);
}
static void channel_memory_desc_json(FILE *f,
                                     const struct channel_memory_desc_info *p) {
    fputs("{\"basePresent\":",f); json_bool(f,p->base_present);
    fprintf(f,",\"size\":%llu,\"addressSpace\":%u,\"cacheAttrib\":%u}",
            (unsigned long long)p->size,p->address_space,p->cache_attrib);
}
static void channel_alloc_payload_json(FILE *f,const struct channel_alloc_info *p) {
    fputs("{\"classPayloadBytes\":",f); fprintf(f,"%u",p->class_payload_bytes);
    fputs(",\"hObjectErrorPresent\":",f); json_bool(f,p->object_error_present);
    fputs(",\"hObjectBufferPresent\":",f); json_bool(f,p->object_buffer_present);
    fputs(",\"gpFifoOffsetNonzero\":",f); json_bool(f,p->gp_fifo_offset_nonzero);
    fprintf(f,",\"gpFifoEntries\":%u,\"flags\":%u",p->gp_fifo_entries,p->flags);
    fputs(",\"hContextSharePresent\":",f); json_bool(f,p->context_share_present);
    fputs(",\"hVASpacePresent\":",f); json_bool(f,p->vaspace_present);
    fprintf(f,",\"hUserdMemoryPresentCount\":%u,\"userdOffsetNonzeroCount\":%u,"
              "\"engineType\":%u,\"subDeviceId\":%u",
            p->userd_memory_present_count,p->userd_offset_nonzero_count,
            p->engine_type,p->subdevice_id);
    fputs(",\"cidPresent\":",f); json_bool(f,p->cid_present);
    fputs(",\"hObjectEccErrorPresent\":",f); json_bool(f,p->ecc_error_present);
    fputs(",\"memoryDescriptors\":{\"instanceMem\":",f);
    channel_memory_desc_json(f,&p->instance_mem);
    fputs(",\"userdMem\":",f); channel_memory_desc_json(f,&p->userd_mem);
    fputs(",\"ramfcMem\":",f); channel_memory_desc_json(f,&p->ramfc_mem);
    fputs(",\"mthdbufMem\":",f); channel_memory_desc_json(f,&p->mthdbuf_mem);
    fputs("},\"reservedFields\":{\"hPhysChannelGroupPresent\":",f);
    json_bool(f,p->phys_channel_group_present);
    fputs(",\"internalFlagsZero\":",f); json_bool(f,p->internal_flags_zero);
    fputs(",\"errorNotifierMemZero\":",f); json_bool(f,p->error_notifier_zero);
    fputs(",\"eccErrorNotifierMemZero\":",f); json_bool(f,p->ecc_error_notifier_zero);
    fputs(",\"processIdZero\":",f); json_bool(f,p->process_id_zero);
    fputs(",\"subProcessIdZero\":",f); json_bool(f,p->subprocess_id_zero);
    fputs(",\"encryptIvZero\":",f); json_bool(f,p->encrypt_iv_zero);
    fputs(",\"decryptIvZero\":",f); json_bool(f,p->decrypt_iv_zero);
    fputs(",\"hmacNonceZero\":",f); json_bool(f,p->hmac_nonce_zero);
    fputs(",\"tpcConfigIdZero\":",f); json_bool(f,p->tpc_config_id_zero);
    fputs("},\"objectClasses\":{\"parent\":",f);
    channel_handle_class_ref_json(f,&p->parent_class);
    fputs(",\"hObjectError\":",f);
    channel_handle_class_ref_json(f,&p->object_error_class);
    fputs(",\"hObjectBuffer\":",f);
    channel_handle_class_ref_json(f,&p->object_buffer_class);
    fputs(",\"hContextShare\":",f);
    channel_handle_class_ref_json(f,&p->context_share_class);
    fputs(",\"hVASpace\":",f);
    channel_handle_class_ref_json(f,&p->vaspace_class);
    fputs(",\"hObjectEccError\":",f);
    channel_handle_class_ref_json(f,&p->ecc_error_class);
    fputs(",\"hPhysChannelGroup\":",f);
    channel_handle_class_ref_json(f,&p->phys_channel_group_class);
    fputs(",\"hUserdMemory\":[",f);
    for (size_t i=0;i<NV_MAX_SUBDEVICES;i++) {
        if (i)
            fputc(',',f);
        channel_handle_class_ref_json(f,&p->userd_memory_class[i]);
    }
    fputs("]",f);
    fputs("}}",f);
}
static const char *channel_payload_state_name(uint32_t state) {
    switch (state) {
    case CHANNEL_PAYLOAD_R580_R595_PARSED: return "r580-r595-class-layout-parsed";
    default: return "no-payload";
    }
}
static void channel_alloc_json(FILE *f,const struct packet *packet,
                               const struct channel_alloc_info *channel,
                               int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,"
              "\"channelPayloadState\":\"%s\",\"channel\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false",channel_payload_state_name(channel->payload_state));
    if (channel->payload_valid)
        channel_alloc_payload_json(f,channel);
    else
        fputs("null",f);
    fputc('}',f);
}
static void rusd_alloc_json(FILE *f,const struct packet *packet,
                            const struct rusd_alloc_info *rusd,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,"
              "\"rusdPayloadState\":\"%s\",\"rusd\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false",
            rusd->payload_valid?"r580-r595-class-layout-parsed":"unavailable");
    if (rusd->payload_valid)
        fprintf(f,"{\"classPayloadBytes\":%zu,\"polledDataMask\":%llu}",
                sizeof(NV00DE_ALLOC_PARAMETERS),
                (unsigned long long)rusd->polled_data_mask);
    else
        fputs("null",f);
    fputc('}',f);
}
static const char *p2p_type_name(uint32_t type) {
    switch (type) {
    case NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_PROPRIETARY: return "proprietary";
    case NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_BAR1: return "bar1";
    case NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_NVLINK: return "nvlink";
    default: return "unknown";
    }
}
static void p2p_alloc_json(FILE *f,const struct packet *packet,
                           const struct p2p_alloc_info *p2p,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,\"p2pPayloadState\":\"%s\",\"p2p\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false",
            p2p->payload_present?"r580-r595-class-layout-parsed":"optional-payload-omitted");
    if (p2p->payload_present)
        fprintf(f,"{\"classPayloadBytes\":%zu,\"flags\":%u,\"type\":%u,\"typeName\":\"%s\",\"unknownFlagBits\":%u}",
                sizeof(NV503C_ALLOC_PARAMETERS),p2p->flags,p2p->type,
                p2p_type_name(p2p->type),p2p->unknown_flag_bits);
    else
        fputs("null",f);
    fputc('}',f);
}
static const char *client_share_kind_name(int value) {
    switch (value) {
    case 0: return "zero";
    case 1: return "same-as-root";
    default: return "other-nonzero";
    }
}
static void device_alloc_json(FILE *f,const struct packet *packet,
                              const struct device_alloc_info *device,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,\"deviceAlloc\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false");
    if (!device->payload_valid) {
        fputs("null}",f);
        return;
    }
    fprintf(f,"{\"classPayloadBytes\":%zu,\"deviceId\":%u,\"hClientShare\":\"%s\","
              "\"targetClientZero\":%s,\"targetDeviceZero\":%s,\"flags\":%u,"
              "\"vaSpaceSize\":%llu,\"vaStartInternalZero\":%s,"
              "\"vaLimitInternalZero\":%s,\"vaMode\":%u}}",
            sizeof(NV0080_ALLOC_PARAMETERS),device->device_id,
            client_share_kind_name(device->client_share_kind),
            device->target_client_zero?"true":"false",
            device->target_device_zero?"true":"false",device->flags,
            (unsigned long long)device->va_space_size,
            device->va_start_internal_zero?"true":"false",
            device->va_limit_internal_zero?"true":"false",device->va_mode);
}
static void subdevice_alloc_json(FILE *f,const struct packet *packet,
                                 const struct subdevice_alloc_info *subdevice,
                                 int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,\"subdeviceAlloc\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false");
    if (subdevice->payload_valid)
        fprintf(f,"{\"classPayloadBytes\":%zu,\"subDeviceId\":%u}}",
                sizeof(NV2080_ALLOC_PARAMETERS),subdevice->subdevice_id);
    else
        fputs("null}",f);
}
static void binapi_alloc_json(FILE *f,const struct packet *packet,
                              const struct binapi_alloc_info *binapi,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,\"binapiAlloc\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false");
    if (binapi->payload_valid)
        fprintf(f,"{\"classPayloadBytes\":%zu,\"reservedZero\":%s}}",
                sizeof(NV2081_ALLOC_PARAMETERS),binapi->reserved_zero?"true":"false");
    else
        fputs("null}",f);
}
static void debugger_alloc_json(FILE *f,const struct packet *packet,
                                const struct debugger_alloc_info *debugger,
                                int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"hClass\":%u,\"paramsSize\":%u,\"flags\":%u,\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,\"hObjectNewPresent\":%s,"
              "\"pAllocParmsPresent\":%s,\"pRightsRequestedPresent\":%s,\"debuggerAlloc\":",
            packet->layout,packet->klass,packet->size,packet->flags,packet->status,
            packet->root?"true":"false",packet->parent?"true":"false",
            packet->object?"true":"false",packet->params?"true":"false",
            packet->rights?"true":"false");
    if (!debugger->payload_valid) {
        fputs("null}",f);
        return;
    }
    fprintf(f,"{\"classPayloadBytes\":%zu,\"obsoleteClientZero\":%s,"
              "\"appClientPresent\":%s,\"appClientMatchesRoot\":%s,"
              "\"appClientMatchesParent\":%s,\"appClientEqualsDebuggee\":%s,"
              "\"debuggee3dHandlePresent\":%s,\"appClientClassWithinRoot\":",
            sizeof(NV83DE_ALLOC_PARAMETERS),
            debugger->obsolete_client_zero?"true":"false",
            debugger->app_client_handle?"true":"false",
            debugger->app_client_matches_root?"true":"false",
            debugger->app_client_matches_parent?"true":"false",
            debugger->app_client_matches_debuggee?"true":"false",
            debugger->debuggee_3d_handle?"true":"false");
    channel_handle_class_ref_json(f,&debugger->app_client_class);
    fputs(",\"debuggee3dClassWithinRoot\":",f);
    channel_handle_class_ref_json(f,&debugger->debuggee_3d_class);
    fputs(",\"debuggee3dParentClassWithinRoot\":",f);
    channel_handle_class_ref_json(f,&debugger->debuggee_3d_parent_class);
    fputs(",\"parentClassWithinRoot\":",f);
    channel_handle_class_ref_json(f,&debugger->parent_class);
    fputs("}}",f);
}
static void debugger_free_json(FILE *f,const struct packet *packet,
                               uint32_t class_id,int exists) {
    if (!exists) { fputs("null",f); return; }
    fprintf(f,"{\"layout\":\"NVOS%02d\",\"status\":%u,"
              "\"hRootPresent\":%s,\"hObjectParentPresent\":%s,"
              "\"hObjectOldPresent\":%s,\"objectClassWithinRoot\":%u}",
            packet->layout,packet->status,packet->root?"true":"false",
            packet->parent?"true":"false",packet->object?"true":"false",
            class_id);
}
static const char *nested_pointer_scope(void) {
    if (capture_debugger_lifecycle)
        return "exact NV83DE allocation parameters plus fixed NVOS54 headers for resolved GT200_DEBUGGER controls and unresolved 0x83de command candidates; only exact 4-byte exceptionMask for resolved 0x83de0309 controls is followed after fixed-size, non-null-pointer, and documented-bit checks; RM_FREE class resolution is root-scoped; a redacted hObject-to-prior-GT200_DEBUGGER-allocation equality is emitted; raw handles and addresses omitted";
    if (capture_debugger_alloc)
        return "exact NV83DE_ALLOC_PARAMETERS 12-byte payload for GT200_DEBUGGER only; emits handle presence and within-root class relations including the debuggee direct-parent class; raw handles and addresses omitted";
    if (capture_sync_boost_groups)
        return "exact NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS groupCount field only; inline GPU IDs and group payloads omitted";
    if (capture_system_features)
        return "exact NV0000_CTRL_CMD_SYSTEM_GET_FEATURES 4-byte featuresMask only; raw addresses and handles omitted";
    if (capture_fabric_status)
        return "exact NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS 4-byte enum only; raw addresses and handles omitted";
    if (capture_map_memory && capture_rusd_alloc)
        return "RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS fixed 8-byte polledDataMask only, plus exact pinned R580 NVOS33/NVOS34 map packets and selected-file lifecycle metadata; other allocation payloads and raw addresses/handles omitted";
    if (capture_binapi_alloc)
        return "NV2081_BINAPI NV2081_ALLOC_PARAMETERS fixed 4-byte reserved zero predicate only; handles omitted";
    if (capture_subdevice_alloc)
        return "NV20_SUBDEVICE_0 NV2080_ALLOC_PARAMETERS fixed 4-byte subDeviceId only; handles omitted";
    if (capture_device_alloc)
        return "NV01_DEVICE_0 NV0080_ALLOC_PARAMETERS fixed 56-byte payload only; client handles are relational booleans; internal VA addresses are omitted";
    if (capture_binapi_control)
        return "exact 992-byte top-level NV2081_BINAPI control payload for command 0x20810108; no contained pointer is followed; raw bytes, addresses, and handles omitted";
    if (capture_channel_alloc)
        return "VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed using the byte-identical pinned R580.178.04/R595.99.02 NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted";
    if (capture_rusd_alloc)
        return "RM_USER_SHARED_DATA NV00DE_ALLOC_PARAMETERS only, parsed as the pinned 8-byte polledDataMask; raw addresses and handles omitted";
    if (capture_p2p_alloc)
        return "NV50_THIRD_PARTY_P2P NV503C_ALLOC_PARAMETERS only, parsed as the pinned 4-byte flags word; raw addresses and handles omitted";
    if (capture_p2p_control)
        return "exact NV503C register/unregister VA-space, register/unregister vidmem, and register-PID fixed parameter structures; raw addresses, handles, and VA-space tokens omitted";
    static char scope[384];
    const char *selected[3];
    size_t count=0;
    if (capture_gpu_id_info)
        selected[count++]="NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2";
    if (capture_attached_ids)
        selected[count++]="NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS";
    if (capture_probed_ids)
        selected[count++]="NV0000_CTRL_CMD_GPU_GET_PROBED_IDS";
    if (count==1)
        snprintf(scope,sizeof(scope),"exact %s payload only; addresses omitted",selected[0]);
    else if (count==2)
        snprintf(scope,sizeof(scope),"exact %s and %s payloads only; addresses omitted",
                 selected[0],selected[1]);
    else if (count==3)
        snprintf(scope,sizeof(scope),"exact %s, %s, and %s payloads only; addresses omitted",
                 selected[0],selected[1],selected[2]);
    else
        scope[0]=0;
    return scope;
}
static int write_report(FILE *f,int child_exit) {
    for (size_t i=0;i<nrecords;i++)
        if (records[i].is_ioctl_shape)
            erase_bytes(records[i].shape_entry_raw,sizeof(records[i].shape_entry_raw));
    int version=capture_debugger_lifecycle?39:capture_debugger_alloc?34:capture_sync_boost_groups?32:capture_uvm_vaspace_fd?31:capture_event_cleanup?27:capture_ioctl_shapes?26:capture_system_features?25:capture_fabric_status?24:capture_rm_control_headers?23:capture_map_memory && capture_rusd_alloc?22:capture_binapi_alloc?21:capture_subdevice_alloc?20:capture_device_alloc?19:capture_binapi_control?18:capture_p2p_control?17:capture_p2p_alloc?16:capture_map_memory?15:capture_rusd_alloc?14:capture_channel_alloc?9:capture_probed_ids?6:capture_rm_control?5:
                capture_attached_ids?4:capture_gpu_id_info?3:1;
    int nested=capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
               capture_rusd_alloc || capture_p2p_alloc || channel_payload_snapshots_read!=0 ||
               p2p_control_payload_snapshots_read!=0 || binapi_payload_snapshots_read!=0 ||
               fabric_status_payload_snapshots_read!=0 ||
               system_features_payload_snapshots_read!=0 ||
               sync_boost_group_payload_snapshots_read!=0 ||
               device_alloc_payload_snapshots_read!=0 ||
               subdevice_alloc_payload_snapshots_read!=0 ||
               binapi_alloc_payload_snapshots_read!=0 ||
               debugger_alloc_payload_snapshots_read!=0 ||
               debugger_exception_mask_payload_snapshots_read!=0;
    fprintf(f,"{\"schema\":\"nvidia-hybrid-rm-ioctl-observer-v%d\",\"trace_complete\":%s,\"child_exit_code\":",
        version,
        failure[0]?"false":"true");
    if (child_exit<0) fputs("null",f); else fprintf(f,"%d",child_exit);
    fputs(",\"control_path\":",f); json_string(f,control_path);
    if (gpu_path) {
        fputs(",\"gpu_path\":",f);
        json_string(f,gpu_path);
    }
    fprintf(f,",\"architecture\":\"x86_64\",\"pointer_bits\":64,\"nested_pointers_read\":%s,\"snapshot_consistency\":\"%s\",\"fd_identity_tracking\":%s",
        nested?"true":"false",
        capture_uvm_vaspace_fd?
            "UVM rmCtrlFd is sampled per-task at ioctl entry and return; other threads may mutate shared packet memory":
            "per-task syscall stop; other threads may mutate shared packet memory",
        (capture_map_memory || capture_event_cleanup || capture_uvm_vaspace_fd)?"true":"false");
    if (capture_uvm_vaspace_fd) {
        fputs(",\"uvm_path\":",f);
        json_string(f,uvm_path);
        fputs(",\"payload_scope\":\"reads only pinned 4-byte rmCtrlFd fields in UVM_REGISTER_GPU_VASPACE (offset 16) and UVM_MAP_EXTERNAL_ALLOCATION (offset 9248) at syscall entry and return; checks selected-node, transient in-memory file identity and pending close/dup/range mutation; emits only booleans; raw descriptor, payload, TID, file identity and ioctl argument address omitted\"",f);
        fputs(",\"fd_lifecycle_scope\":\"selected control-node open, dup, fcntl-dup, close and close_range metadata across traced shared descriptor tables; io_uring and external descriptor injection are not tracked\"",f);
        fprintf(f,",\"fd_identity_capture_complete\":%s",fd_identity_capture_complete?"true":"false");
        fprintf(f,",\"uvm_vaspace_records_seen\":%zu",uvm_vaspace_records_seen);
        fprintf(f,",\"uvm_map_external_records_seen\":%zu",uvm_map_external_records_seen);
    }
    if (capture_channel_alloc)
        fputs(",\"object_class_resolution_scope\":\"successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed\"",f);
    if (capture_debugger_alloc)
        fputs(",\"object_class_resolution_scope\":\"successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; lookup is keyed by NVOS64 root and handle and emits only object and direct-parent class IDs/presence; unresolved means no unique live object was observed\"",f);
    if (capture_debugger_lifecycle)
        fputs(",\"object_class_resolution_scope\":\"successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; debugger control hClient is resolved to one observed root before resolving hObject; a redacted hObject equality against prior successful GT200_DEBUGGER allocations is recorded; unresolved free classes and debugger-command candidates emit redacted fixed headers; raw handles are omitted\"",f);
    if (capture_map_memory)
        fputs(",\"object_class_resolution_scope\":\"successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed\"",f);
    if (capture_binapi_control)
        fputs(",\"object_class_resolution_scope\":\"successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed\"",f);
    if (capture_channel_alloc)
        fprintf(f,",\"channel_payload_snapshots_read\":%u",channel_payload_snapshots_read);
    if (capture_rusd_alloc)
        fprintf(f,",\"rusd_payload_snapshots_read\":%u",rusd_payload_snapshots_read);
    if (capture_p2p_alloc)
        fprintf(f,",\"p2p_payload_snapshots_read\":%u",p2p_payload_snapshots_read);
    if (capture_p2p_control)
        fprintf(f,",\"p2p_control_payload_snapshots_read\":%u",
                p2p_control_payload_snapshots_read);
    if (capture_binapi_control)
        fprintf(f,",\"binapi_payload_snapshots_read\":%u",
                binapi_payload_snapshots_read);
    if (capture_device_alloc)
        fprintf(f,",\"device_alloc_payload_snapshots_read\":%u",
                device_alloc_payload_snapshots_read);
    if (capture_subdevice_alloc)
        fprintf(f,",\"subdevice_alloc_payload_snapshots_read\":%u",
                subdevice_alloc_payload_snapshots_read);
    if (capture_binapi_alloc)
        fprintf(f,",\"binapi_alloc_payload_snapshots_read\":%u",
                binapi_alloc_payload_snapshots_read);
    if (capture_debugger_alloc || capture_debugger_lifecycle)
        fprintf(f,",\"debugger_alloc_payload_snapshots_read\":%u",
                debugger_alloc_payload_snapshots_read);
    if (capture_debugger_lifecycle) {
        fprintf(f,",\"debugger_free_unresolved_class_count\":%u",
                debugger_free_unresolved_count);
        fprintf(f,",\"debugger_control_unresolved_candidate_count\":%u",
                debugger_control_unresolved_count);
        fprintf(f,",\"debugger_exception_mask_payload_snapshots_read\":%u",
                debugger_exception_mask_payload_snapshots_read);
    }
    if (capture_fabric_status)
        fprintf(f,",\"fabric_status_payload_snapshots_read\":%u",
                fabric_status_payload_snapshots_read);
    if (capture_system_features)
        fprintf(f,",\"system_features_payload_snapshots_read\":%u",
                system_features_payload_snapshots_read);
    if (capture_sync_boost_groups)
        fprintf(f,",\"sync_boost_group_payload_snapshots_read\":%u",
                sync_boost_group_payload_snapshots_read);
    if (nested || capture_channel_alloc || capture_subdevice_alloc || capture_binapi_alloc ||
        capture_debugger_alloc || capture_debugger_lifecycle) {
        fputs(",\"nested_pointer_scope\":",f);
        json_string(f,nested_pointer_scope());
    }
    if (capture_event_cleanup)
        fputs(",\"payload_scope\":\"selected event ioctls plus a fixed 16-byte root-free equality predicate and selected descriptor lifecycle; raw payload bytes and handle values omitted; temporary TID/FD/file-identity fields require summarization before evidence persistence\"",f);
    else if (capture_ioctl_shapes)
        fputs(",\"payload_scope\":\"exact requests 0xc038464e (56 bytes) and 0xc028465e (40 bytes) on the selected control path, and 0xc01046ce/0xc01046cf (16 bytes each) on the selected GPU path; emits only nonzero and changed byte offsets; raw values and pointers omitted\"",f);
    else if (capture_system_features)
        fputs(",\"payload_scope\":\"exact root-global SYSTEM_GET_FEATURES 4-byte mask plus fixed RM_CONTROL headers; raw addresses and handles omitted\"",f);
    else if (capture_sync_boost_groups)
        fputs(",\"payload_scope\":\"exact root-global SYNC_GPU_BOOST_GROUP_INFO groupCount field only; inline GPU IDs and group payloads omitted; raw addresses and handles omitted\"",f);
    else if (capture_fabric_status)
        fputs(",\"payload_scope\":\"exact root-global Fabric Manager status enum plus fixed RM_CONTROL headers; raw addresses and handles omitted\"",f);
    else if (capture_p2p_control)
        fputs(",\"payload_scope\":\"RM_CONTROL headers plus exact NV503C P2P control payloads; raw addresses, handles, and VA-space tokens omitted; other nested parameter payloads omitted\"",f);
    else if (capture_binapi_control)
        fputs(",\"payload_scope\":\"RM_CONTROL headers plus exact 992-byte NV2081_BINAPI payload-shape metadata; contained pointers are never followed; raw bytes, addresses, and handles omitted\"",f);
    else if (capture_device_alloc)
        fputs(",\"payload_scope\":\"NV01_DEVICE_0 fixed class parameters only; handles are redacted and internal VA addresses are omitted\"",f);
    else if (capture_subdevice_alloc)
        fputs(",\"payload_scope\":\"NV20_SUBDEVICE_0 fixed class parameters only; handles omitted\"",f);
    else if (capture_binapi_alloc)
        fputs(",\"payload_scope\":\"NV2081_BINAPI fixed class parameters only; raw reserved value, handles omitted\"",f);
    else if (capture_debugger_lifecycle)
        fputs(",\"payload_scope\":\"GT200_DEBUGGER allocations, class-resolved GT200_DEBUGGER frees, fixed NVOS54 headers plus a redacted hObject-to-prior-debugger-allocation equality, and exact 4-byte exceptionMask snapshots for resolved 0x83de0309 controls only; null pointers, size mismatch, and undocumented bits fail closed; unresolved command candidates are never dereferenced; raw handles and addresses omitted\"",f);
    else if (capture_debugger_alloc)
        fputs(",\"payload_scope\":\"NV83DE_ALLOC_PARAMETERS exact 12-byte fixed payload on GT200_DEBUGGER allocations only; raw handles, pointers, and payload bytes omitted\"",f);
    else if (capture_rm_control_headers)
        fputs(",\"payload_scope\":\"fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted\"",f);
    else if (capture_rm_control && !nested)
        fputs(",\"payload_scope\":\"fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted\"",f);
    else if (capture_rm_control)
        fputs(",\"payload_scope\":\"RM_CONTROL headers plus explicitly selected fixed metadata payloads; other nested parameters omitted\"",f);
    if (capture_map_memory && capture_rusd_alloc)
        fputs(",\"payload_scope\":\"exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device open/dup/close/mmap metadata, transient RM_ALLOC/RM_FREE class resolution, and fixed RM_USER_SHARED_DATA 8-byte polling-mask snapshots only; addresses, paths, and handles omitted\"",f);
    else if (capture_map_memory)
        fputs(",\"payload_scope\":\"exact pinned R580 NVOS33 map wrapper and NVOS34 unmap packet, selected-device open/dup/close/mmap metadata, and transient RM_ALLOC/RM_FREE class resolution; no allocation payloads emitted; addresses, paths, and handles omitted\"",f);
    if (capture_map_memory)
        fputs(",\"fd_lifecycle_scope\":\"opaque file IDs assigned at observed open/openat/openat2 and dup/dup2/dup3/fcntl(F_DUPFD*) calls; close() removes an ID; close_range invalidates affected IDs; exec invalidates inherited IDs; io_uring and external fd injection are not tracked; VMA file references remain kernel-owned\"",f);
    if (capture_map_memory)
        fprintf(f,",\"fd_identity_capture_complete\":%s",fd_identity_capture_complete?"true":"false");
    if (capture_event_cleanup) {
        fputs(",\"fd_lifecycle_scope\":\"selected control/GPU open, dup, fcntl-dup, close, and close_range metadata; clone tasks are accepted only when kcmp confirms a shared descriptor table; paths, descriptor values, and opaque file-identity tokens are transient; io_uring and external fd injection are not tracked\"",f);
        fprintf(f,",\"fd_identity_capture_complete\":%s",fd_identity_capture_complete?"true":"false");
    }
    fputs(",\"records\":[",f);
    size_t written=0;
    for (size_t i=0;i<nrecords;i++) {
        struct record *r=&records[i];
        if ((capture_channel_alloc && !r->is_channel_alloc) ||
            (capture_rusd_alloc && !capture_map_memory && !r->is_rusd_alloc) ||
            (capture_p2p_alloc && !r->is_p2p_alloc) ||
            (capture_device_alloc && !r->is_device_alloc) ||
            (capture_subdevice_alloc && !r->is_subdevice_alloc) ||
            (capture_binapi_alloc && !r->is_binapi_alloc) ||
            (capture_debugger_alloc && !r->is_debugger_alloc) ||
            (capture_debugger_lifecycle && !r->is_debugger_alloc &&
             !r->is_debugger_free && !r->is_debugger_control &&
             !r->is_debugger_control_candidate) ||
            (capture_binapi_control && !r->is_binapi_control) ||
            (capture_rm_control_headers && !r->is_rm_control) ||
            (capture_fabric_status && !r->is_fabric_status) ||
            (capture_system_features && !r->is_system_features) ||
            (capture_sync_boost_groups && !r->is_sync_boost_groups) ||
            (r->is_class_tracking_only && !r->is_rusd_alloc))
            continue;
        if (capture_uvm_vaspace_fd) {
            if (!r->is_uvm_vaspace_fd && !r->is_uvm_map_external_fd)
                continue;
            fprintf(f,"%s{\"operation\":\"%s\",\"request\":%llu,\"field_read_at_entry\":%s,\"rm_ctrl_fd_identity_tracked_at_entry\":%s,\"rm_ctrl_fd_same_file_identity_at_exit\":%s,\"rm_ctrl_fd_field_unchanged_at_exit\":%s,\"rm_ctrl_fd_no_mutation_pending_at_entry\":%s,\"rm_ctrl_fd_no_mutation_pending_at_exit\":%s,\"uvm_fd_matches_selected_node_at_entry\":%s,\"rm_ctrl_fd_matches_control_node_at_entry\":%s,\"rm_ctrl_fd_matches_control_node_at_exit\":%s,\"rm_ctrl_fd_is_negative\":%s,\"exit_observed\":%s,\"syscall_return\":",
                written?",":"",
                r->is_uvm_vaspace_fd?"uvm_register_gpu_vaspace":"uvm_map_external_allocation",
                (unsigned long long)r->request,
                r->rm_ctrl_field_read?"true":"false",
                r->rm_ctrl_identity_tracked_entry?"true":"false",
                r->rm_ctrl_same_file_identity_exit?"true":"false",
                r->rm_ctrl_field_unchanged_exit?"true":"false",
                r->rm_ctrl_no_mutation_pending_entry?"true":"false",
                r->rm_ctrl_no_mutation_pending_exit?"true":"false",
                r->uvm_fd_matches_entry?"true":"false",
                r->rm_ctrl_matches_entry?"true":"false",
                r->rm_ctrl_matches_exit?"true":"false",
                r->rm_ctrl_is_negative?"true":"false",
                r->has_exit?"true":"false");
            if (r->returned)
                fprintf(f,"%lld",(long long)r->result);
            else
                fputs("null",f);
            fputc('}',f);
            r->observed_rm_ctrl_fd=0;
            r->rm_ctrl_file_id_entry=0;
            r->address=0;
            ++written;
            continue;
        }
        const char *operation=r->fd_event_kind==1?"fd_open":r->fd_event_kind==2?"fd_dup":
            r->fd_event_kind==3?"fd_close_range":
            r->is_root_free_predicate?"root_free_predicate":
            r->is_ioctl_shape?"selected_ioctl_payload_shape":
            r->is_close?"close":r->is_mmap?"mmap":r->is_map_memory?"map_memory":
            r->is_unmap_memory?"unmap_memory":
            r->is_gpu_id_info?"gpu_id_info_v2":
            r->is_attached_ids?"gpu_attached_ids":
            r->is_probed_ids?"gpu_probed_ids":
            r->is_binapi_control?"binapi_control":
            r->is_debugger_control?"gt200_debugger_control":
            r->is_debugger_control_candidate?"gt200_debugger_control_candidate":
            r->is_debugger_free?"gt200_debugger_free":
            r->is_system_features?"rm_control_system_features":
            r->is_fabric_status?"rm_control_fabric_status":
            r->is_sync_boost_groups?"rm_control_sync_boost_groups":
            r->is_device_alloc?"device_alloc":
            r->is_subdevice_alloc?"subdevice_alloc":
            r->is_binapi_alloc?"binapi_alloc":
            r->is_debugger_alloc?"gt200_debugger_alloc":
            r->is_rm_control?"rm_control_header":
            r->is_channel_alloc?"channel_alloc":
            r->is_rusd_alloc?"rusd_alloc":
            r->is_p2p_alloc?"p2p_alloc":
            r->is_alloc?"alloc":"free";
        fprintf(f,"%s{\"tid\":%ld,\"fd\":%d,\"fd_role\":\"%s\",\"request\":%llu,\"packet_size\":%u,\"operation\":\"%s\"",
            written?",":"",(long)r->tid,r->fd,
            fd_role_name(r->fd_role),
            (unsigned long long)r->request,r->size,operation);
        if (r->is_debugger_control || r->is_debugger_control_candidate) {
            fputs(",\"debuggerTargetObjectClassWithinRoot\":",f);
            channel_handle_class_ref_json(f,&r->debugger_control_object_class);
        }
        if (r->is_ioctl_shape) {
            fputs(",\"entry_nonzero_offsets\":",f);
            ioctl_shape_offsets_json(f,r->shape_entry_nonzero,r->size);
            fputs(",\"exit_nonzero_offsets\":",f);
            ioctl_shape_offsets_json(f,r->shape_exit_nonzero,r->size);
            fputs(",\"changed_offsets\":",f);
            ioctl_shape_offsets_json(f,r->shape_changed,r->size);
            fputs(",\"entry_snapshot_passed\":",f);
            json_bool(f,r->shape_entry_snapshot_passed);
            fputs(",\"exit_snapshot_passed\":",f);
            json_bool(f,r->shape_exit_snapshot_passed);
        }
        if (r->is_root_free_predicate) {
            fputs(",\"root_free_candidate\":",f);
            json_bool(f,r->root_free_candidate);
            fputs(",\"root_free_succeeded\":",f);
            json_bool(f,r->root_free_succeeded);
        }
        if (capture_map_memory || capture_event_cleanup) {
            fputs(",\"fd_file_id\":",f);
            fd_file_id_json(f,r->fd_file_id);
        }
        if (capture_event_cleanup && r->fd_event_kind==3) {
            fputs(",\"fd_descriptors\":[",f);
            for (uint32_t j=0;j<r->fd_range_file_id_count;j++)
                fprintf(f,"%s{\"fd\":%d,\"file_id\":%llu}",j?",":"",
                        r->fd_range_fds[j],
                        (unsigned long long)r->fd_range_file_ids[j]);
            fputc(']',f);
        }
        if (r->fd_event_kind==2) {
            fprintf(f,",\"source_fd\":%d",r->fd_source);
            if (capture_event_cleanup) {
                fputs(",\"replaced_fd_file_id\":",f);
                fd_file_id_json(f,r->fd_replaced_file_id);
            }
        }
        fputs(",\"entry\":",f);
        ++written;
        if (r->fd_event_kind==3)
            fprintf(f,"{\"first_fd\":%llu,\"last_fd\":%llu,\"flags\":%u}",
                    (unsigned long long)r->fd_range_first,
                    (unsigned long long)r->fd_range_last,r->fd_range_flags);
        else if (r->fd_event_kind || r->is_close || r->is_ioctl_shape)
            fputs("null",f);
        else if (r->is_map_memory)
            map_memory_json(f,&r->map_entry,r->has_entry);
        else if (r->is_unmap_memory)
            unmap_memory_json(f,&r->unmap_entry,r->has_entry);
        else if (r->is_mmap)
            mmap_json(f,&r->mmap,r->has_entry);
        else if (r->is_gpu_id_info)
            gpu_id_info_json(f,&r->gpu_entry,r->has_entry);
        else if (r->is_attached_ids)
            attached_ids_json(f,&r->attached_entry,r->has_entry);
        else if (r->is_probed_ids)
            probed_ids_json(f,&r->probed_entry,r->has_entry);
        else if (r->is_debugger_free)
            debugger_free_json(f,&r->entry,r->debugger_free_class,r->has_entry);
        else if (r->is_rm_control)
            rm_control_json(f,&r->rm_control_entry,r->has_entry,
                            capture_p2p_control || capture_binapi_control || capture_rm_control_headers || capture_fabric_status || capture_system_features || capture_sync_boost_groups || capture_debugger_lifecycle,
                            capture_p2p_control,capture_binapi_control,capture_fabric_status,capture_system_features,
                            capture_sync_boost_groups,
                            capture_debugger_lifecycle &&
                                (r->is_debugger_control || r->is_debugger_control_candidate));
        else if (r->is_channel_alloc)
            channel_alloc_json(f,&r->entry,&r->channel_entry,r->has_entry);
        else if (r->is_rusd_alloc)
            rusd_alloc_json(f,&r->entry,&r->rusd_entry,r->has_entry);
        else if (r->is_p2p_alloc)
            p2p_alloc_json(f,&r->entry,&r->p2p_entry,r->has_entry);
        else if (r->is_device_alloc)
            device_alloc_json(f,&r->entry,&r->device_alloc_entry,r->has_entry);
        else if (r->is_subdevice_alloc)
            subdevice_alloc_json(f,&r->entry,&r->subdevice_alloc_entry,r->has_entry);
        else if (r->is_binapi_alloc)
            binapi_alloc_json(f,&r->entry,&r->binapi_alloc_entry,r->has_entry);
        else if (r->is_debugger_alloc)
            debugger_alloc_json(f,&r->entry,&r->debugger_alloc_entry,r->has_entry);
        else
            packet_json(f,&r->entry,r->has_entry);
        fputs(",\"exit\":",f);
        if (r->fd_event_kind || r->is_close || r->is_ioctl_shape)
            fputs("null",f);
        else if (r->is_map_memory)
            map_memory_json(f,&r->map_exit,r->has_exit);
        else if (r->is_unmap_memory)
            unmap_memory_json(f,&r->unmap_exit,r->has_exit);
        else if (r->is_mmap)
            fputs("null",f);
        else if (r->is_gpu_id_info)
            gpu_id_info_json(f,&r->gpu_exit,r->has_exit);
        else if (r->is_attached_ids)
            attached_ids_json(f,&r->attached_exit,r->has_exit);
        else if (r->is_probed_ids)
            probed_ids_json(f,&r->probed_exit,r->has_exit);
        else if (r->is_debugger_free)
            debugger_free_json(f,&r->exit,r->debugger_free_class,r->has_exit);
        else if (r->is_rm_control)
            rm_control_json(f,&r->rm_control_exit,r->has_exit,
                            capture_p2p_control || capture_binapi_control || capture_rm_control_headers || capture_fabric_status || capture_system_features || capture_sync_boost_groups || capture_debugger_lifecycle,
                            capture_p2p_control,capture_binapi_control,capture_fabric_status,capture_system_features,
                            capture_sync_boost_groups,
                            capture_debugger_lifecycle &&
                                (r->is_debugger_control || r->is_debugger_control_candidate));
        else if (r->is_channel_alloc)
            channel_alloc_json(f,&r->exit,&r->channel_exit,r->has_exit);
        else if (r->is_rusd_alloc)
            rusd_alloc_json(f,&r->exit,&r->rusd_exit,r->has_exit);
        else if (r->is_p2p_alloc)
            p2p_alloc_json(f,&r->exit,&r->p2p_exit,r->has_exit);
        else if (r->is_device_alloc)
            device_alloc_json(f,&r->exit,&r->device_alloc_exit,r->has_exit);
        else if (r->is_subdevice_alloc)
            subdevice_alloc_json(f,&r->exit,&r->subdevice_alloc_exit,r->has_exit);
        else if (r->is_binapi_alloc)
            binapi_alloc_json(f,&r->exit,&r->binapi_alloc_exit,r->has_exit);
        else if (r->is_debugger_alloc)
            debugger_alloc_json(f,&r->exit,&r->debugger_alloc_exit,r->has_exit);
        else
            packet_json(f,&r->exit,r->has_exit);
        fputs(",\"syscall_return\":",f);
        if (r->is_close) {
            if (r->returned) {
                fprintf(f,"%lld,\"close_succeeded\":%s",(long long)r->result,
                        r->result==0?"true":"false");
            } else {
                fputs("null,\"close_succeeded\":null",f);
            }
        } else if (r->is_mmap) {
            fputs("null,\"mmap_succeeded\":",f);
            if (r->returned) fputs(r->result>=0?"true":"false",f); else fputs("null",f);
        } else if (r->returned) fprintf(f,"%lld",(long long)r->result); else fputs("null",f);
        fputc('}',f);
        if (r->is_debugger_alloc || r->is_debugger_free ||
            r->is_debugger_control || r->is_debugger_control_candidate) {
            explicit_bzero(&r->entry,sizeof(r->entry));
            explicit_bzero(&r->exit,sizeof(r->exit));
            explicit_bzero(&r->debugger_alloc_entry,sizeof(r->debugger_alloc_entry));
            explicit_bzero(&r->debugger_alloc_exit,sizeof(r->debugger_alloc_exit));
            explicit_bzero(&r->rm_control_entry,sizeof(r->rm_control_entry));
            explicit_bzero(&r->rm_control_exit,sizeof(r->rm_control_exit));
            r->debugger_free_class=0;
        }
    }
    fputs("],\"errors\":[",f);
    if (failure[0]) json_string(f,failure);
    fputs("]}\n",f);
    return fflush(f) || ferror(f);
}
static void cleanup(void) {
    /* Only tasks obtained from our TRACEME child and its ptrace events. */
    for (size_t i=0;i<ntasks;i++) if (tasks[i].alive) kill(tasks[i].tid,SIGKILL);
    double deadline=monotime()+2;
    while (monotime()<deadline) {
        int alive=0;
        for (size_t i=0;i<ntasks;i++) if (tasks[i].alive) {
            int status; pid_t got=waitpid(tasks[i].tid,&status,__WALL|WNOHANG);
            if (got==tasks[i].tid) {
                if (WIFEXITED(status)||WIFSIGNALED(status)) tasks[i].alive=0;
                else ptrace(PTRACE_CONT,tasks[i].tid,0,(void *)(intptr_t)SIGKILL);
            } else if (got<0 && errno==ECHILD) tasks[i].alive=0;
            alive+=tasks[i].alive;
        }
        if (!alive) return;
        struct timespec delay={0,100000}; nanosleep(&delay,0);
    }
    fail("cleanup timeout");
}
int main(int argc,char **argv) {
    const char *output=NULL; int command=0,seconds=60,child_exit=-1,report_fd;
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"--")) { command=i+1; break; }
        if (!strcmp(argv[i],"--output") && i+1<argc) output=argv[++i];
        else if (!strcmp(argv[i],"--control-path") && i+1<argc) control_path=argv[++i];
        else if (!strcmp(argv[i],"--gpu-path") && i+1<argc) gpu_path=argv[++i];
        else if (!strcmp(argv[i],"--gpu-id-info")) capture_gpu_id_info=1;
        else if (!strcmp(argv[i],"--attached-ids")) capture_attached_ids=1;
        else if (!strcmp(argv[i],"--probed-ids")) capture_probed_ids=1;
        else if (!strcmp(argv[i],"--rm-control")) capture_rm_control=1;
        else if (!strcmp(argv[i],"--rm-control-headers")) {
            capture_rm_control=1;
            capture_rm_control_headers=1;
        }
        else if (!strcmp(argv[i],"--fabric-status")) capture_fabric_status=1;
        else if (!strcmp(argv[i],"--system-features")) capture_system_features=1;
        else if (!strcmp(argv[i],"--sync-boost-groups")) {
            capture_sync_boost_groups=1;
            capture_rm_control=1;
        }
        else if (!strcmp(argv[i],"--ioctl-shapes")) capture_ioctl_shapes=1;
        else if (!strcmp(argv[i],"--event-cleanup")) capture_event_cleanup=1;
        else if (!strcmp(argv[i],"--p2p-control")) capture_p2p_control=1;
        else if (!strcmp(argv[i],"--binapi-control")) capture_binapi_control=1;
        else if (!strcmp(argv[i],"--device-alloc")) capture_device_alloc=1;
        else if (!strcmp(argv[i],"--subdevice-alloc")) capture_subdevice_alloc=1;
        else if (!strcmp(argv[i],"--binapi-alloc")) capture_binapi_alloc=1;
        else if (!strcmp(argv[i],"--gt200-debugger-alloc")) capture_debugger_alloc=1;
        else if (!strcmp(argv[i],"--gt200-debugger-lifecycle")) capture_debugger_lifecycle=1;
        else if (!strcmp(argv[i],"--channel-alloc")) capture_channel_alloc=1;
        else if (!strcmp(argv[i],"--rusd-alloc")) capture_rusd_alloc=1;
        else if (!strcmp(argv[i],"--p2p-alloc")) capture_p2p_alloc=1;
        else if (!strcmp(argv[i],"--map-memory")) capture_map_memory=1;
        else if (!strcmp(argv[i],"--uvm-vaspace-fd")) capture_uvm_vaspace_fd=1;
        else if (!strcmp(argv[i],"--uvm-path") && i+1<argc) uvm_path=argv[++i];
        else if (!strcmp(argv[i],"--timeout-seconds") && i+1<argc) {
            char *end; long n=strtol(argv[++i],&end,10);
            if (*end || n<1 || n>65) return 2;
            seconds=(int)n;
        } else return 2;
    }
    if (!output || !command || command>=argc || control_path[0]!='/' ||
        strlen(control_path)>=PATH_MAX || uvm_path[0]!='/' ||
        strlen(uvm_path)>=PATH_MAX ||
        (gpu_path && (gpu_path[0]!='/' || strlen(gpu_path)>=PATH_MAX ||
                      !strcmp(gpu_path,control_path)))) return 2;
    if (capture_sync_boost_groups &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control_headers || capture_fabric_status ||
         capture_system_features || capture_ioctl_shapes || capture_event_cleanup ||
         capture_channel_alloc || capture_rusd_alloc || capture_p2p_alloc ||
         capture_p2p_control || capture_binapi_control || capture_device_alloc ||
         capture_subdevice_alloc || capture_binapi_alloc || capture_map_memory ||
         capture_uvm_vaspace_fd || gpu_path)) return 2;
    if (capture_uvm_vaspace_fd &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_rm_control_headers || capture_fabric_status ||
         capture_system_features || capture_ioctl_shapes || capture_event_cleanup ||
         capture_channel_alloc || capture_rusd_alloc || capture_p2p_alloc ||
         capture_p2p_control || capture_binapi_control || capture_device_alloc ||
         capture_subdevice_alloc || capture_binapi_alloc || capture_map_memory ||
         gpu_path)) return 2;
    if (capture_ioctl_shapes &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_rm_control_headers || capture_fabric_status ||
         capture_system_features || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_p2p_control || capture_binapi_control ||
         capture_device_alloc || capture_subdevice_alloc || capture_binapi_alloc ||
         capture_map_memory)) return 2;
    if (capture_ioctl_shapes && !gpu_path) return 2;
    if (capture_event_cleanup && !capture_ioctl_shapes) return 2;
    if (capture_fabric_status &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_rm_control_headers || capture_p2p_control ||
         capture_binapi_control || capture_device_alloc || capture_subdevice_alloc ||
         capture_binapi_alloc || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_map_memory || gpu_path)) return 2;
    if (capture_system_features &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_rm_control_headers || capture_fabric_status ||
         capture_p2p_control || capture_binapi_control || capture_device_alloc ||
         capture_subdevice_alloc || capture_binapi_alloc || capture_channel_alloc ||
         capture_rusd_alloc || capture_p2p_alloc || capture_map_memory || gpu_path)) return 2;
    if (capture_channel_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_rusd_alloc || capture_p2p_alloc)) return 2;
    if (capture_map_memory &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_channel_alloc || capture_p2p_alloc)) return 2;
    if (capture_rusd_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_p2p_alloc)) return 2;
    if (capture_p2p_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control)) return 2;
    if (capture_p2p_control &&
        (!capture_rm_control || capture_gpu_id_info || capture_attached_ids ||
         capture_probed_ids || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_map_memory)) return 2;
    if (capture_binapi_control &&
        (!capture_rm_control || capture_gpu_id_info || capture_attached_ids ||
         capture_probed_ids || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_p2p_control || capture_map_memory)) return 2;
    if (capture_binapi_control && !gpu_path) return 2;
    if (capture_rm_control_headers &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_channel_alloc || capture_rusd_alloc || capture_p2p_alloc ||
         capture_p2p_control || capture_binapi_control || capture_device_alloc ||
         capture_subdevice_alloc || capture_binapi_alloc || capture_map_memory || gpu_path)) return 2;
    if (capture_device_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_p2p_control || capture_binapi_control ||
         capture_map_memory || capture_subdevice_alloc || !gpu_path)) return 2;
    if (capture_subdevice_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_p2p_control || capture_binapi_control ||
         capture_map_memory || capture_device_alloc || !gpu_path)) return 2;
    if (capture_binapi_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_p2p_control || capture_binapi_control ||
         capture_map_memory || capture_device_alloc || capture_subdevice_alloc ||
         !gpu_path)) return 2;
    if (capture_debugger_alloc &&
        (capture_gpu_id_info || capture_attached_ids || capture_probed_ids ||
         capture_rm_control || capture_rm_control_headers || capture_fabric_status ||
         capture_system_features || capture_sync_boost_groups || capture_ioctl_shapes ||
         capture_event_cleanup || capture_channel_alloc || capture_rusd_alloc ||
         capture_p2p_alloc || capture_p2p_control || capture_binapi_control ||
         capture_device_alloc || capture_subdevice_alloc || capture_binapi_alloc ||
         capture_map_memory || capture_uvm_vaspace_fd || !gpu_path)) return 2;
    if (capture_debugger_lifecycle &&
        (capture_debugger_alloc || capture_gpu_id_info || capture_attached_ids ||
         capture_probed_ids || capture_rm_control || capture_rm_control_headers ||
         capture_fabric_status || capture_system_features || capture_sync_boost_groups ||
         capture_ioctl_shapes || capture_event_cleanup || capture_channel_alloc ||
         capture_rusd_alloc || capture_p2p_alloc || capture_p2p_control ||
         capture_binapi_control || capture_device_alloc || capture_subdevice_alloc ||
         capture_binapi_alloc || capture_map_memory || capture_uvm_vaspace_fd ||
         !gpu_path)) return 2;
    if (gpu_path && !capture_channel_alloc && !capture_map_memory &&
        !capture_rusd_alloc && !capture_p2p_alloc && !capture_binapi_control &&
        !capture_device_alloc && !capture_subdevice_alloc && !capture_binapi_alloc &&
        !capture_debugger_alloc && !capture_debugger_lifecycle &&
        !capture_ioctl_shapes) return 2;
    for (size_t fd=0;fd<MAX_TRACKED_FDS;fd++)
        fd_identities[fd].role=2;
    report_fd=open(output,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (report_fd<0) { perror("new output file required"); return 2; }
    FILE *report=fdopen(report_fd,"w");
    if (!report) { close(report_fd); return 2; }
    struct sigaction action={0}; action.sa_handler=on_signal;
    sigaction(SIGINT,&action,NULL); sigaction(SIGTERM,&action,NULL);
    pid_t child=fork();
    if (!child) {
        fclose(report);
        if (ptrace(PTRACE_TRACEME,0,0,0)<0) _exit(125);
        raise(SIGSTOP); execvp(argv[command],&argv[command]); _exit(127);
    }
    if (child<0) fail("fork failed");
    else {
        add_task(child,0);
        int initial=0,status=0;
        double deadline=monotime()+seconds;
        while (!failure[0]) {
            int alive=0,progress=0;
            if (interrupted) { fail("observer interrupted"); break; }
            if (monotime()>deadline) { fail("trace timeout"); break; }
            for (size_t i=0;i<ntasks && !failure[0];i++) if (tasks[i].alive) {
                struct task *t=&tasks[i]; alive++;
                pid_t got=waitpid(t->tid,&status,__WALL|WNOHANG);
                if (!got) continue;
                if (got<0) { if (errno!=EINTR) fail("waitpid failed"); continue; }
                progress=1;
                if (WIFEXITED(status)||WIFSIGNALED(status)) {
                    if (t->pending>=0) fail("tracee exited during observed ioctl");
                    if (t->fd_op_kind!=FD_OP_NONE)
                        fail("tracee exited during descriptor-lifecycle syscall");
                    t->alive=0;
                    if (t->tid==child) child_exit=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
                    if (!initial) fail("child could not start ptrace");
                    continue;
                }
                if (!WIFSTOPPED(status)) { fail("unexpected wait status"); break; }
                int sig=WSTOPSIG(status),event=(unsigned)status>>16;
                if (!initial) {
                    if (t->tid!=child || sig!=SIGSTOP) { fail("missing initial stop"); break; }
                    unsigned long opts=PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL;
                    if (ptrace(PTRACE_SETOPTIONS,child,0,(void *)opts)<0) { fail("PTRACE_SETOPTIONS failed"); break; }
                    initial=1; resume(child,0); continue;
                }
                if (event==PTRACE_EVENT_CLONE || event==PTRACE_EVENT_FORK || event==PTRACE_EVENT_VFORK) {
                    unsigned long new_tid=0;
                    if (ptrace(PTRACE_GETEVENTMSG,t->tid,0,&new_tid)<0 || !new_tid || new_tid>INT_MAX) { fail("invalid new-task event"); break; }
                    if (add_task((pid_t)new_tid,1)<0)
                        break;
                    if (event!=PTRACE_EVENT_CLONE ||
                        !same_thread_group((pid_t)new_tid,child)) {
                        fail("forked processes are unsupported");
                        break;
                    }
                    if (capture_event_cleanup || capture_uvm_vaspace_fd) {
                        int shared=same_file_table(child,(pid_t)new_tid);
                        if (shared<0) {
                            fail("kcmp could not verify the cloned task descriptor table");
                            break;
                        }
                        if (!shared) {
                            fail("cloned task has an unsupported separate descriptor table");
                            break;
                        }
                    }
                    resume(t->tid,0);
                } else if (event==PTRACE_EVENT_EXEC) {
                    if (t->tid!=child || ntasks!=1) { fail("threaded re-exec unsupported"); break; }
                    invalidate_all_file_ids();
                    resume(t->tid,0);
                } else if (event) fail("unsupported ptrace event");
                else if (sig==(SIGTRAP|0x80)) { syscall_stop(t); if (!failure[0]) resume(t->tid,0); }
                else if (t->newborn && sig==SIGSTOP) { t->newborn=0; resume(t->tid,0); }
                else {
                    siginfo_t si;
                    if (ptrace(PTRACE_GETSIGINFO,t->tid,0,&si)<0) { fail("group stop unsupported"); break; }
                    resume(t->tid,sig);
                }
            }
            if (!alive) break;
            if (!progress) { struct timespec delay={0,100000}; nanosleep(&delay,0); }
        }
        if (failure[0]) cleanup();
        if (child_exit<0 && !failure[0]) fail("missing child exit status");
    }
    int result=failure[0]?2:child_exit;
    if (write_report(report,child_exit)) result=2;
    if (fclose(report)) result=2;
    return result;
}
