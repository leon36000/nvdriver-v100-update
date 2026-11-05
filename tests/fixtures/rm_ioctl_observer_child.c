/* SPDX-License-Identifier: MIT
 * Synthetic packets sent to /dev/null: no NVIDIA RM or GPU execution. */
#define _GNU_SOURCE
#define OBSERVED_NV2081_BINAPI_CONTROL 0x20810108U
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include "nvtypes.h"
#include "nvos.h"
#include "nv_escape.h"
#include "nv-ioctl.h"
#include "nv-unix-nvos-params-wrappers.h"
#include <ctrl/ctrl0000/ctrl0000gpu.h>
#include <ctrl/ctrl0000/ctrl0000system.h>
#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>
#include <alloc/alloc_channel.h>
#include <class/cl0080.h>
#include <class/cl2080.h>
#include <class/cl2081.h>
#include <class/clc36f.h>
#include <class/clc96f.h>
#include <class/cl00de.h>
#include <class/cl503c.h>
#include <class/cl83de.h>
#include <ctrl/ctrl83de/ctrl83dedebug.h>
#include <class/clc397.h>
#include <ctrl/ctrl503c.h>
static volatile sig_atomic_t signals;
static void handler(int sig) { (void)sig; signals++; }
static void packets(int fd,unsigned seed) {
    NVOS21_PARAMETERS p21={0};
    p21.hRoot=seed; p21.hObjectParent=17; p21.hObjectNew=18;
    p21.hClass=NV01_ROOT_CLIENT; p21.pAllocParms=(void *)(uintptr_t)0x123456789abcdef0ULL;
    p21.paramsSize=23; p21.status=0xfedcba98;
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS21_PARAMETERS),&p21);
    NVOS64_PARAMETERS p64={0};
    p64.hRoot=seed+1; p64.hClass=NV01_ROOT;
    p64.pRightsRequested=(void *)(uintptr_t)0xfedcba9876543210ULL;
    p64.paramsSize=99; p64.flags=1; p64.status=0xabcdef01;
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&p64);
    NVOS00_PARAMETERS freep={seed+2,33,44,0x11223344};
    ioctl(fd,_IOWR('F',NV_ESC_RM_FREE,NVOS00_PARAMETERS),&freep);
}
static void gpu_id_info(int fd,unsigned gpu_id,unsigned seed) {
    NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS params={0};
    params.gpuId=gpu_id; params.gpuFlags=seed+1; params.deviceInstance=seed+2;
    params.subDeviceInstance=seed+3; params.sliStatus=seed+4; params.boardId=seed+5;
    params.gpuInstance=seed+6; params.numaId=(NvS32)(seed+7);
    NVOS54_PARAMETERS request={0};
    request.hClient=seed+10; request.hObject=seed+11;
    request.cmd=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2; request.flags=0;
    request.params=&params; request.paramsSize=sizeof(params); request.status=seed+12;
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
}
static void attached_ids(int fd,unsigned first,unsigned second,unsigned seed,int xfer) {
    NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS params;
    for (unsigned i=0;i<NV0000_CTRL_GPU_MAX_ATTACHED_GPUS;i++)
        params.gpuIds[i]=NV0000_CTRL_GPU_INVALID_ID;
    params.gpuIds[0]=first;
    if (second!=NV0000_CTRL_GPU_INVALID_ID) params.gpuIds[1]=second;
    NVOS54_PARAMETERS request={0};
    request.hClient=seed; request.hObject=seed;
    request.cmd=NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS; request.flags=0;
    request.params=&params; request.paramsSize=sizeof(params); request.status=seed+1;
    if (!xfer) {
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    } else {
        nv_ioctl_xfer_t packet={0}; packet.cmd=NV_ESC_RM_CONTROL;
        packet.size=sizeof(request); packet.ptr=&request;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&packet);
    }
}
static void sync_boost_groups(int fd, unsigned group_count, int bad_size,
                              int bad_pointer, int xfer) {
    NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params={0};
    params.groupCount=group_count;
    NVOS54_PARAMETERS request={0};
    request.hClient=71; request.hObject=71;
    request.cmd=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO;
    request.flags=NVOS54_FLAGS_NONE;
    request.params=bad_pointer?(NvP64)(uintptr_t)1:(NvP64)&params;
    request.paramsSize=bad_size?sizeof(params)-4:sizeof(params);
    request.status=0xabcdef01U;
    if (!xfer) {
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    } else {
        nv_ioctl_xfer_t packet={0}; packet.cmd=NV_ESC_RM_CONTROL;
        packet.size=sizeof(request); packet.ptr=&request;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&packet);
    }
}
static void probed_ids(int fd,unsigned first,unsigned excluded,unsigned flags,unsigned seed,int xfer) {
    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS params;
    for (unsigned i=0;i<NV0000_CTRL_GPU_MAX_PROBED_GPUS;i++) {
        params.gpuIds[i]=NV0000_CTRL_GPU_INVALID_ID;
        params.excludedGpuIds[i]=NV0000_CTRL_GPU_INVALID_ID;
        params.gpuFlags[i]=0;
    }
    params.gpuIds[0]=first;
    params.excludedGpuIds[0]=excluded;
    params.gpuFlags[0]=flags;
    NVOS54_PARAMETERS request={0};
    request.hClient=seed; request.hObject=seed;
    request.cmd=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS; request.flags=0;
    request.params=&params; request.paramsSize=sizeof(params); request.status=seed+1;
    if (!xfer) {
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    } else {
        nv_ioctl_xfer_t packet={0}; packet.cmd=NV_ESC_RM_CONTROL;
        packet.size=sizeof(request); packet.ptr=&request;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&packet);
    }
}
static void rm_control_headers(int fd) {
    NVOS54_PARAMETERS direct={0};
    direct.hClient=71; direct.hObject=72; direct.cmd=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2;
    direct.flags=3; direct.params=(void *)(uintptr_t)1;
    direct.paramsSize=4096; direct.status=41;
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&direct);

    NVOS54_PARAMETERS wrapped={0};
    wrapped.hClient=81; wrapped.hObject=82; wrapped.cmd=0x12345678;
    wrapped.flags=5; wrapped.params=(void *)(uintptr_t)1;
    wrapped.paramsSize=8192; wrapped.status=51;
    nv_ioctl_xfer_t xfer={0}; xfer.cmd=NV_ESC_RM_CONTROL;
    xfer.size=sizeof(wrapped); xfer.ptr=&wrapped;
    ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
}
static void rm_control_generic_headers(int fd) {
    NVOS54_PARAMETERS direct={0};
    direct.hClient=91; direct.hObject=92; direct.cmd=0x12345679;
    direct.flags=7; direct.params=(void *)(uintptr_t)1;
    direct.paramsSize=4096; direct.status=61;
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&direct);

    NVOS54_PARAMETERS wrapped={0};
    wrapped.hClient=101; wrapped.hObject=102; wrapped.cmd=0x1234567a;
    wrapped.flags=9; wrapped.params=(void *)(uintptr_t)1;
    wrapped.paramsSize=8192; wrapped.status=71;
    nv_ioctl_xfer_t xfer={0}; xfer.cmd=NV_ESC_RM_CONTROL;
    xfer.size=sizeof(wrapped); xfer.ptr=&wrapped;
    ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
}
static void fabric_status(int fd, int malformed_size, int bad_pointer) {
    NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS params={
        .fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_INITIALIZED,
    };
    NVOS54_PARAMETERS direct={0};
    direct.hClient=101; direct.hObject=101;
    direct.cmd=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS;
    direct.flags=NVOS54_FLAGS_NONE;
    direct.params=bad_pointer?(void *)(uintptr_t)1:&params;
    direct.paramsSize=sizeof(params)+(malformed_size?4:0);
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&direct);
    if (!malformed_size && !bad_pointer) {
        params.fabricStatus=NV0000_CTRL_GET_SYSTEM_FABRIC_STATUS_IN_PROGRESS;
        NVOS54_PARAMETERS wrapped={0};
        wrapped.hClient=202; wrapped.hObject=202;
        wrapped.cmd=NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS;
        wrapped.flags=NVOS54_FLAGS_NONE;
        wrapped.params=&params; wrapped.paramsSize=sizeof(params);
        nv_ioctl_xfer_t xfer={0}; xfer.cmd=NV_ESC_RM_CONTROL;
        xfer.size=sizeof(wrapped); xfer.ptr=&wrapped;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
    }
}
static void system_features(int fd, int malformed_size, int bad_pointer) {
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params={.featuresMask=0xa5a55a5aU};
    NVOS54_PARAMETERS direct={0};
    direct.hClient=301; direct.hObject=301;
    direct.cmd=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES;
    direct.flags=NVOS54_FLAGS_NONE;
    direct.params=bad_pointer?(void *)(uintptr_t)1:&params;
    direct.paramsSize=sizeof(params)+(malformed_size?4:0);
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&direct);
    if (!malformed_size && !bad_pointer) {
        params.featuresMask=0x13579bdfU;
        NVOS54_PARAMETERS wrapped={0};
        wrapped.hClient=302; wrapped.hObject=302;
        wrapped.cmd=NV0000_CTRL_CMD_SYSTEM_GET_FEATURES;
        wrapped.flags=NVOS54_FLAGS_NONE;
        wrapped.params=&params; wrapped.paramsSize=sizeof(params);
        nv_ioctl_xfer_t xfer={0}; xfer.cmd=NV_ESC_RM_CONTROL;
        xfer.size=sizeof(wrapped); xfer.ptr=&wrapped;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
    }
}
static void binapi_control_unresolved(int fd) {
    NVOS54_PARAMETERS request={0};
    request.hClient=0x10203040U;
    request.hObject=0x30405060U;
    request.cmd=OBSERVED_NV2081_BINAPI_CONTROL;
    request.params=(void *)(uintptr_t)1;
    request.paramsSize=992;
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
}
static void device_alloc(int fd, int no_params, int bad_pointer) {
    NV0080_ALLOC_PARAMETERS params={
        .deviceId=13,
        .hClientShare=0xaabbccddU,
        .hTargetClient=0x13579bdfU,
        .hTargetDevice=0x2468ace0U,
        .flags=0x403,
        .vaSpaceSize=0x123000,
        .vaStartInternal=0x444000,
        .vaLimitInternal=0x888000,
        .vaMode=2,
    };
    NVOS64_PARAMETERS packet={
        .hRoot=0xaabbccddU,
        .hObjectParent=0xaabbccddU,
        .hObjectNew=0xccddeeffU,
        .hClass=NV01_DEVICE_0,
        .pAllocParms=bad_pointer?(NvP64)(uintptr_t)1:
            no_params?NvP64_NULL:(NvP64)&params,
        .pRightsRequested=NvP64_NULL,
        .paramsSize=0,
        .flags=0,
        .status=0xdeadbeefU,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&packet);
}
static void subdevice_alloc(int fd, unsigned subdevice_id, int bad_pointer) {
    NV2080_ALLOC_PARAMETERS params={.subDeviceId=subdevice_id};
    NVOS64_PARAMETERS packet={
        .hRoot=0xaabbccddU,
        .hObjectParent=0x11223344U,
        .hObjectNew=0xccddeeffU,
        .hClass=NV20_SUBDEVICE_0,
        .pAllocParms=bad_pointer?(NvP64)(uintptr_t)1:(NvP64)&params,
        .pRightsRequested=NvP64_NULL,
        .paramsSize=0,
        .flags=NVOS64_FLAGS_NONE,
        .status=0xdeadbeefU,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&packet);
}
static void binapi_alloc(int fd, unsigned reserved, int payload_present, int bad_pointer) {
    NV2081_ALLOC_PARAMETERS params={.reserved=reserved};
    NVOS64_PARAMETERS packet={
        .hRoot=0xaabbccddU,
        .hObjectParent=0x11223344U,
        .hObjectNew=0xccddeeffU,
        .hClass=NV2081_BINAPI,
        .pAllocParms=bad_pointer?(NvP64)(uintptr_t)1:
            payload_present?(NvP64)&params:NvP64_NULL,
        .pRightsRequested=NvP64_NULL,
        .paramsSize=0,
        .flags=NVOS64_FLAGS_NONE,
        .status=0xdeadbeefU,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&packet);
}
static void gt200_debugger_alloc(int fd, int bad_pointer, int null_payload,
                                 unsigned params_size) {
    const NvHandle root=0xaabbccddU, device=0x11223344U;
    const NvHandle debuggee=0x55667788U, debugger=0xccddeeffU;
    NV83DE_ALLOC_PARAMETERS params={
        .hDebuggerClient_Obsolete=0,
        .hAppClient=root,
        .hClass3dObject=debuggee,
    };
    NVOS64_PARAMETERS root_packet={
        .hObjectNew=root,.hClass=NV01_ROOT_CLIENT,.status=NV_OK,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&root_packet);
    NVOS64_PARAMETERS device_packet={
        .hRoot=root,.hObjectParent=root,.hObjectNew=device,
        .hClass=NV01_DEVICE_0,.status=NV_OK,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&device_packet);
    NVOS64_PARAMETERS debuggee_packet={
        .hRoot=root,.hObjectParent=device,.hObjectNew=debuggee,
        .hClass=VOLTA_A,.status=NV_OK,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&debuggee_packet);
    NVOS64_PARAMETERS packet={
        .hRoot=root,.hObjectParent=device,.hObjectNew=debugger,
        .hClass=GT200_DEBUGGER,
        .pAllocParms=bad_pointer?(NvP64)(uintptr_t)1:
            null_payload?NvP64_NULL:(NvP64)&params,
        .pRightsRequested=NvP64_NULL,.paramsSize=params_size,
        .flags=NVOS64_FLAGS_NONE,.status=NV_OK,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&packet);
}
static void gt200_debugger_lifecycle_unresolved(int fd) {
    NVOS00_PARAMETERS free_packet={
        .hRoot=0x11223344U,
        .hObjectParent=0x55667788U,
        .hObjectOld=0x99aabbccU,
    };
    ioctl(fd,_IOWR('F',NV_ESC_RM_FREE,NVOS00_PARAMETERS),&free_packet);

    NVOS54_PARAMETERS direct={0};
    direct.hClient=0x10203040U;
    direct.hObject=0U;
    direct.cmd=NV83DE_CTRL_CMD_SM_DEBUG_MODE_ENABLE;
    direct.params=(NvP64)(uintptr_t)1;
    direct.paramsSize=sizeof(uint32_t);
    ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&direct);

    NVOS54_PARAMETERS wrapped=direct;
    wrapped.hObject=0x30405060U;
    nv_ioctl_xfer_t xfer={0};
    xfer.cmd=NV_ESC_RM_CONTROL;
    xfer.size=sizeof(wrapped);
    xfer.ptr=&wrapped;
    ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
}
static void p2p_control_request(int fd,unsigned command,void *params,
                                unsigned params_size,unsigned seed,int xfer) {
    NVOS54_PARAMETERS request={0};
    request.hClient=seed;
    request.hObject=seed+1;
    request.cmd=command;
    request.params=params;
    request.paramsSize=params_size;
    if (!xfer) {
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    } else {
        nv_ioctl_xfer_t packet={0};
        packet.cmd=NV_ESC_RM_CONTROL;
        packet.size=sizeof(request);
        packet.ptr=&request;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&packet);
    }
}
static void p2p_control_sequence(int fd) {
    NV503C_CTRL_REGISTER_VA_SPACE_PARAMS register_va={0};
    register_va.hVASpace=0x71425364U;
    register_va.vaSpaceToken=UINT64_C(0x123456789abcdef0);
    p2p_control_request(fd,NV503C_CTRL_CMD_REGISTER_VA_SPACE,&register_va,
                        sizeof(register_va),0x10203040U,0);

    NV503C_CTRL_UNREGISTER_VA_SPACE_PARAMS unregister_va={0};
    unregister_va.hVASpace=0x72536475U;
    p2p_control_request(fd,NV503C_CTRL_CMD_UNREGISTER_VA_SPACE,&unregister_va,
                        sizeof(unregister_va),0x20304050U,0);

    NV503C_CTRL_REGISTER_VIDMEM_PARAMS register_vidmem={0};
    register_vidmem.hMemory=0x73647586U;
    register_vidmem.address=UINT64_C(0x765432100000);
    register_vidmem.size=UINT64_C(0x40000);
    register_vidmem.offset=UINT64_C(0x10000);
    p2p_control_request(fd,NV503C_CTRL_CMD_REGISTER_VIDMEM,&register_vidmem,
                        sizeof(register_vidmem),0x30405060U,1);

    NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS unregister_vidmem={0};
    unregister_vidmem.hMemory=0x748596a7U;
    p2p_control_request(fd,NV503C_CTRL_CMD_UNREGISTER_VIDMEM,&unregister_vidmem,
                        sizeof(unregister_vidmem),0x40506070U,0);

    NV503C_CTRL_REGISTER_PID_PARAMS register_pid={0};
    register_pid.hClient=0x7596a7b8U;
    p2p_control_request(fd,NV503C_CTRL_CMD_REGISTER_PID,&register_pid,
                        sizeof(register_pid),0x50607080U,0);
}
static void rm_control_xfer_bad_pointer(int fd) {
    nv_ioctl_xfer_t xfer={0}; xfer.cmd=NV_ESC_RM_CONTROL;
    xfer.size=sizeof(NVOS54_PARAMETERS); xfer.ptr=(void *)(uintptr_t)1;
    ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
}
static void map_memory(int control_fd,int backend_fd,
                       uint32_t client_handle,uint32_t memory_handle) {
    nv_ioctl_nvos33_parameters_with_fd map={0};
    map.params.hClient=client_handle;
    map.params.hDevice=0x24681357U;
    map.params.hMemory=memory_handle;
    map.params.offset=UINT64_C(0xfedcba9876543210);
    map.params.length=UINT64_C(0x0000000001000000);
    map.params.pLinearAddress=(NvP64)(uintptr_t)UINT64_C(0x123456789abcdef0);
    map.params.status=0x10203040U;
    map.params.flags=0x55667788U;
    map.fd=backend_fd;
    ioctl(control_fd,_IOWR('F',NV_ESC_RM_MAP_MEMORY,
                           nv_ioctl_nvos33_parameters_with_fd),&map);
}
static void unmap_memory(int control_fd) {
    NVOS34_PARAMETERS unmap={0};
    unmap.hClient=0x11112222U;
    unmap.hDevice=0x33334444U;
    unmap.hMemory=0x55556666U;
    unmap.pLinearAddress=(NvP64)(uintptr_t)UINT64_C(0x0fedcba987654321);
    unmap.status=0x89abcdefU;
    unmap.flags=0x778899aaU;
    ioctl(control_fd,_IOWR('F',NV_ESC_RM_UNMAP_MEMORY,NVOS34_PARAMETERS),&unmap);
}
static void class_tracking_only(int control_fd) {
    NVOS64_PARAMETERS alloc={0};
    NVOS00_PARAMETERS free_packet={0};
    alloc.hRoot=0x10293847U;
    alloc.hObjectParent=0x56473829U;
    alloc.hObjectNew=0x89abcdefU;
    alloc.hClass=0x00c661U;
    alloc.status=0xdead0001U;
    free_packet.hRoot=0x10293847U;
    free_packet.hObjectParent=0x56473829U;
    free_packet.hObjectOld=0x89abcdefU;
    free_packet.status=0xdead0002U;
    ioctl(control_fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&alloc);
    ioctl(control_fd,_IOWR('F',NV_ESC_RM_FREE,NVOS00_PARAMETERS),&free_packet);
}
static void channel_alloc(int fd, int bad_pointer, int bad_size,
                          int blackwell, int zero_size, int null_pointer) {
    NV_CHANNEL_ALLOC_PARAMS params={0};
    params.hObjectError=0x01020304U;
    params.hObjectBuffer=0x11223344U;
    params.gpFifoOffset=UINT64_C(0x1122334455667788);
    params.gpFifoEntries=64;
    params.flags=5;
    params.hContextShare=0x55667788U;
    params.hVASpace=0x99aabbccU;
    params.hUserdMemory[0]=0x1234abcU;
    params.userdOffset[0]=UINT64_C(0x8877665544332211);
    params.engineType=0x31;
    params.cid=0xdeadbeefU;
    params.subDeviceId=1;
    params.hObjectEccError=0xabcdef01U;
    params.instanceMem=(NV_MEMORY_DESC_PARAMS){UINT64_C(0x0101010102020202),4096,2,3};
    params.userdMem=(NV_MEMORY_DESC_PARAMS){UINT64_C(0x0303030304040404),8192,4,5};
    params.ramfcMem=(NV_MEMORY_DESC_PARAMS){UINT64_C(0x0505050506060606),16384,6,7};
    params.mthdbufMem=(NV_MEMORY_DESC_PARAMS){UINT64_C(0x0707070708080808),32768,8,9};
    NVOS64_PARAMETERS request={0};
    request.hRoot=991; request.hObjectParent=882; request.hObjectNew=773;
    request.hClass=blackwell ? BLACKWELL_CHANNEL_GPFIFO_A : VOLTA_CHANNEL_GPFIFO_A;
    request.pAllocParms=null_pointer ? NULL :
                        bad_pointer ? (void *)(uintptr_t)1 : &params;
    request.paramsSize=zero_size ? 0 : bad_size ? sizeof(params)-8 : sizeof(params);
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&request);
}
static void rusd_alloc(int fd, uint64_t mask, int bad_pointer, int null_pointer,
                       unsigned params_size) {
    NV00DE_ALLOC_PARAMETERS params={0};
    params.polledDataMask=mask;
    NVOS64_PARAMETERS request={0};
    request.hRoot=0x10203040U;
    request.hObjectParent=0x20304050U;
    request.hObjectNew=0x30405060U;
    request.hClass=RM_USER_SHARED_DATA;
    request.pAllocParms=null_pointer?NULL:
        bad_pointer?(void *)(uintptr_t)1:&params;
    request.paramsSize=params_size;
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&request);
}
static void p2p_alloc(int fd, NvU32 flags, int bad_pointer, int null_pointer) {
    NV503C_ALLOC_PARAMETERS params={.flags=flags};
    NVOS64_PARAMETERS request={0};
    request.hRoot=0x10203040U;
    request.hObjectParent=0x20304050U;
    request.hObjectNew=0x30405060U;
    request.hClass=NV50_THIRD_PARTY_P2P;
    request.pAllocParms=null_pointer?NULL:
        bad_pointer?(void *)(uintptr_t)1:&params;
    request.paramsSize=0; /* class metadata is optional in both pinned RMs */
    ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS64_PARAMETERS),&request);
}
struct job { int fd; unsigned seed; };
static void *thread(void *arg) {
    struct job *j=arg;
    for (unsigned i=0;i<3;i++) { packets(j->fd,j->seed+i*10); raise(SIGUSR1); }
    return NULL;
}
int main(int argc,char **argv) {
    if (argc!=2) return 90;
    int fd=open("/dev/null",O_RDWR);
    if (fd<0) return 91;
    struct sigaction a={0}; a.sa_handler=handler; sigaction(SIGUSR1,&a,NULL);
    if (!strcmp(argv[1],"basic")) { packets(fd,7); puts("child stdout passed"); fputs("child stderr passed\n",stderr); }
    else if (!strcmp(argv[1],"threads")) {
        pthread_t threads[2]; struct job jobs[2]={{fd,100},{fd,200}};
        for (int i=0;i<2;i++) if (pthread_create(&threads[i],NULL,thread,&jobs[i])) return 92;
        for (int i=0;i<2;i++) pthread_join(threads[i],NULL);
    } else if (!strcmp(argv[1],"x32")) syscall(SYS_getpid|0x40000000UL);
    else if (!strcmp(argv[1],"invalid-fd")) ioctl(999999,_IOWR('F',NV_ESC_RM_ALLOC,NVOS21_PARAMETERS),(void *)1);
    else if (!strcmp(argv[1],"bad-pointer")) ioctl(fd,_IOWR('F',NV_ESC_RM_ALLOC,NVOS21_PARAMETERS),(void *)1);
    else if (!strcmp(argv[1],"bad-size")) ioctl(fd,_IOC(_IOC_READ|_IOC_WRITE,'F',NV_ESC_RM_ALLOC,40),(void *)1);
    else if (!strcmp(argv[1],"signal")) { raise(SIGUSR1); packets(fd,7); raise(SIGUSR1); }
    else if (!strcmp(argv[1],"id-info")) {
        packets(fd,7); gpu_id_info(fd,77,1);
        /* Exercise the XFER envelope without changing the nested command. */
        NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS params={0}; params.gpuId=88;
        params.gpuFlags=11; params.deviceInstance=12; params.subDeviceInstance=13;
        params.sliStatus=14; params.boardId=15; params.gpuInstance=17; params.numaId=18;
        NVOS54_PARAMETERS request={0}; request.hClient=20; request.hObject=21;
        request.cmd=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2; request.params=&params;
        request.paramsSize=sizeof(params); request.status=22;
        nv_ioctl_xfer_t xfer={0}; xfer.cmd=NV_ESC_RM_CONTROL;
        xfer.size=sizeof(request); xfer.ptr=&request;
        ioctl(fd,_IOWR('F',NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t),&xfer);
    }
    else if (!strcmp(argv[1],"id-info-bad-pointer")) {
        packets(fd,7); NVOS54_PARAMETERS request={0};
        request.cmd=NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2;
        request.params=(void *)(uintptr_t)1; request.paramsSize=sizeof(NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS);
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    }
    else if (!strcmp(argv[1],"attached-ids")) {
        packets(fd,7);
        attached_ids(fd,7,11,NV0000_CTRL_GPU_INVALID_ID,0);
        attached_ids(fd,22,NV0000_CTRL_GPU_INVALID_ID,31,1);
    }
    else if (!strcmp(argv[1],"attached-ids-bad-pointer")) {
        packets(fd,7); NVOS54_PARAMETERS request={0};
        request.hClient=1; request.hObject=1;
        request.cmd=NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS;
        request.params=(void *)(uintptr_t)1;
        request.paramsSize=sizeof(NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS);
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    }
    else if (!strcmp(argv[1],"probed-ids")) {
        packets(fd,7);
        probed_ids(fd,7,13,1,41,0);
        probed_ids(fd,22,NV0000_CTRL_GPU_INVALID_ID,0,51,1);
    }
    else if (!strcmp(argv[1],"probed-ids-bad-pointer")) {
        packets(fd,7); NVOS54_PARAMETERS request={0};
        request.hClient=1; request.hObject=1;
        request.cmd=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS;
        request.params=(void *)(uintptr_t)1;
        request.paramsSize=sizeof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS);
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    }
    else if (!strcmp(argv[1],"probed-ids-bad-size")) {
        packets(fd,7); NVOS54_PARAMETERS request={0};
        request.hClient=1; request.hObject=1;
        request.cmd=NV0000_CTRL_CMD_GPU_GET_PROBED_IDS;
        request.params=(void *)(uintptr_t)1;
        request.paramsSize=sizeof(NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS)-4;
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    }
    else if (!strcmp(argv[1],"rm-control")) {
        packets(fd,7); rm_control_headers(fd);
    }
    else if (!strcmp(argv[1],"sync-boost-groups")) {
        sync_boost_groups(fd,3,0,0,0);
        sync_boost_groups(fd,0,0,0,1);
    }
    else if (!strcmp(argv[1],"sync-boost-groups-bad-size"))
        sync_boost_groups(fd,0,1,0,0);
    else if (!strcmp(argv[1],"sync-boost-groups-bad-pointer"))
        sync_boost_groups(fd,0,0,1,0);
    else if (!strcmp(argv[1],"sync-boost-groups-bad-count"))
        sync_boost_groups(fd,17,0,0,0);
    else if (!strcmp(argv[1],"fabric-status")) {
        NVOS54_PARAMETERS unrelated={0};
        unrelated.cmd=0x12345678; unrelated.flags=NVOS54_FLAGS_NONE;
        unrelated.params=(void *)(uintptr_t)1; unrelated.paramsSize=4;
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&unrelated);
        fabric_status(fd,0,0);
    }
    else if (!strcmp(argv[1],"fabric-status-bad-size")) fabric_status(fd,1,0);
    else if (!strcmp(argv[1],"fabric-status-bad-pointer")) fabric_status(fd,0,1);
    else if (!strcmp(argv[1],"system-features")) {
        NVOS54_PARAMETERS unrelated={0};
        unrelated.cmd=0x12345678; unrelated.flags=NVOS54_FLAGS_NONE;
        unrelated.params=(void *)(uintptr_t)1; unrelated.paramsSize=4;
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&unrelated);
        system_features(fd,0,0);
    }
    else if (!strcmp(argv[1],"system-features-bad-size")) system_features(fd,1,0);
    else if (!strcmp(argv[1],"system-features-bad-pointer")) system_features(fd,0,1);
    else if (!strcmp(argv[1],"rm-control-mixed")) {
        packets(fd,7); gpu_id_info(fd,77,1);
        attached_ids(fd,22,NV0000_CTRL_GPU_INVALID_ID,31,1);
        rm_control_generic_headers(fd);
    }
    else if (!strcmp(argv[1],"binapi-control-unresolved")) {
        binapi_control_unresolved(fd);
    }
    else if (!strcmp(argv[1],"device-alloc")) device_alloc(fd,0,0);
    else if (!strcmp(argv[1],"device-alloc-no-params")) device_alloc(fd,1,0);
    else if (!strcmp(argv[1],"device-alloc-bad-pointer")) device_alloc(fd,0,1);
    else if (!strcmp(argv[1],"subdevice-alloc")) subdevice_alloc(fd,0,0);
    else if (!strcmp(argv[1],"subdevice-alloc-nonzero")) subdevice_alloc(fd,7,0);
    else if (!strcmp(argv[1],"subdevice-alloc-bad-pointer")) subdevice_alloc(fd,0,1);
    else if (!strcmp(argv[1],"binapi-alloc")) binapi_alloc(fd,0,1,0);
    else if (!strcmp(argv[1],"binapi-alloc-nonzero")) binapi_alloc(fd,0x12345678U,1,0);
    else if (!strcmp(argv[1],"binapi-alloc-no-params")) binapi_alloc(fd,0,0,0);
    else if (!strcmp(argv[1],"binapi-alloc-bad-pointer")) binapi_alloc(fd,0,1,1);
    else if (!strcmp(argv[1],"gt200-debugger-alloc")) gt200_debugger_alloc(fd,0,0,0);
    else if (!strcmp(argv[1],"gt200-debugger-alloc-null-payload")) gt200_debugger_alloc(fd,0,1,0);
    else if (!strcmp(argv[1],"gt200-debugger-alloc-bad-pointer")) gt200_debugger_alloc(fd,1,0,0);
    else if (!strcmp(argv[1],"gt200-debugger-alloc-bad-size")) gt200_debugger_alloc(fd,0,0,1);
    else if (!strcmp(argv[1],"gt200-debugger-lifecycle-unresolved"))
        gt200_debugger_lifecycle_unresolved(fd);
    else if (!strcmp(argv[1],"rm-control-xfer-bad-pointer")) {
        packets(fd,7); rm_control_xfer_bad_pointer(fd);
    }
    else if (!strcmp(argv[1],"map-memory") ||
             !strcmp(argv[1],"map-memory-mmap")) {
        int backend_fd=open("/dev/zero",O_RDWR);
        if (backend_fd<0) return 95;
        class_tracking_only(fd);
        map_memory(fd,backend_fd,0x13572468U,0xdeadbeefU);
        if (!strcmp(argv[1],"map-memory-mmap")) {
            void *mapping=mmap(NULL,4096,PROT_READ,MAP_PRIVATE,backend_fd,0);
            if (mapping==MAP_FAILED) return 96;
            if (munmap(mapping,4096)) return 97;
        }
        unmap_memory(fd);
        close(backend_fd);
    }
    else if (!strcmp(argv[1],"map-memory-dup")) {
        int backend_fd=open("/dev/zero",O_RDWR);
        if (backend_fd<0) return 95;
        int duplicate_fd=dup(backend_fd);
        if (duplicate_fd<0) return 96;
        map_memory(fd,backend_fd,0x13572468U,0xdeadbeefU);
        map_memory(fd,duplicate_fd,0x13572468U,0xdeadbeefU);
        unmap_memory(fd);
        close(backend_fd);
        close(duplicate_fd);
    }
    else if (!strcmp(argv[1],"map-memory-bad-pointer")) {
        ioctl(fd,_IOWR('F',NV_ESC_RM_MAP_MEMORY,
                       nv_ioctl_nvos33_parameters_with_fd),(void *)(uintptr_t)1);
    }
    else if (!strcmp(argv[1],"map-memory-bad-size")) {
        ioctl(fd,_IOC(_IOC_READ|_IOC_WRITE,'F',NV_ESC_RM_MAP_MEMORY,
                      sizeof(NVOS33_PARAMETERS)),(void *)(uintptr_t)1);
    }
    else if (!strcmp(argv[1],"unmap-memory-bad-pointer")) {
        ioctl(fd,_IOWR('F',NV_ESC_RM_UNMAP_MEMORY,NVOS34_PARAMETERS),
              (void *)(uintptr_t)1);
    }
    else if (!strcmp(argv[1],"unmap-memory-bad-size")) {
        ioctl(fd,_IOC(_IOC_READ|_IOC_WRITE,'F',NV_ESC_RM_UNMAP_MEMORY,24),
              (void *)(uintptr_t)1);
    }
    else if (!strcmp(argv[1],"channel-alloc")) channel_alloc(fd,0,0,0,1,0);
    else if (!strcmp(argv[1],"channel-alloc-two-paths")) {
        int gpu_fd=open("/dev/zero",O_RDWR);
        if (gpu_fd<0) return 94;
        channel_alloc(fd,0,0,0,1,0);
        channel_alloc(gpu_fd,0,0,1,1,0);
        close(gpu_fd);
    }
    else if (!strcmp(argv[1],"channel-alloc-bad-pointer")) channel_alloc(fd,1,0,0,1,0);
    else if (!strcmp(argv[1],"channel-alloc-bad-size")) channel_alloc(fd,0,1,0,0,0);
    else if (!strcmp(argv[1],"channel-alloc-blackwell")) channel_alloc(fd,0,0,1,1,0);
    else if (!strcmp(argv[1],"channel-alloc-blackwell-no-params")) channel_alloc(fd,0,0,1,1,1);
    else if (!strcmp(argv[1],"rusd-alloc"))
        rusd_alloc(fd,NV00DE_RUSD_POLL_CLOCK|NV00DE_RUSD_POLL_PERF,0,0,0);
    else if (!strcmp(argv[1],"rusd-alloc-two-paths")) {
        int gpu_fd=open("/dev/zero",O_RDWR);
        if (gpu_fd<0) return 94;
        rusd_alloc(fd,0,0,0,0);
        rusd_alloc(gpu_fd,NV00DE_RUSD_POLL_MEMORY,0,0,8);
        close(gpu_fd);
    }
    else if (!strcmp(argv[1],"rusd-alloc-bad-pointer"))
        rusd_alloc(fd,0,1,0,0);
    else if (!strcmp(argv[1],"rusd-alloc-null-pointer"))
        rusd_alloc(fd,0,0,1,0);
    else if (!strcmp(argv[1],"rusd-map-memory")) {
        int backend_fd=open("/dev/zero",O_RDWR);
        if (backend_fd<0) return 94;
        rusd_alloc(fd,0,0,0,0);
        map_memory(fd,backend_fd,0x10203040U,0x30405060U);
        unmap_memory(fd);
        close(backend_fd);
    }
    else if (!strcmp(argv[1],"p2p-alloc"))
        p2p_alloc(fd,NV503C_ALLOC_PARAMETERS_FLAGS_TYPE_NVLINK|0xa0U,0,0);
    else if (!strcmp(argv[1],"p2p-alloc-no-params"))
        p2p_alloc(fd,0,0,1);
    else if (!strcmp(argv[1],"p2p-alloc-bad-pointer"))
        p2p_alloc(fd,0,1,0);
    else if (!strcmp(argv[1],"p2p-control")) {
        packets(fd,7); p2p_control_sequence(fd);
    }
    else if (!strcmp(argv[1],"p2p-control-bad-size")) {
        NV503C_CTRL_UNREGISTER_VIDMEM_PARAMS params={.hMemory=1};
        p2p_control_request(fd,NV503C_CTRL_CMD_UNREGISTER_VIDMEM,&params,
                            sizeof(params)-1,0x60708090U,0);
    }
    else if (!strcmp(argv[1],"p2p-control-bad-pointer")) {
        p2p_control_request(fd,NV503C_CTRL_CMD_REGISTER_VIDMEM,
                            (void *)(uintptr_t)1,
                            sizeof(NV503C_CTRL_REGISTER_VIDMEM_PARAMS),
                            0x708090a0U,0);
    }
    else if (!strcmp(argv[1],"p2p-control-unrelated")) {
        NVOS54_PARAMETERS request={0};
        request.hClient=0x8090a0b0U; request.hObject=0x90a0b0c0U;
        request.cmd=0x12345678; request.params=(void *)(uintptr_t)1;
        request.paramsSize=1;
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    }
    else if (!strcmp(argv[1],"other-control")) {
        packets(fd,7); NVOS54_PARAMETERS request={0};
        request.cmd=0x12345678; request.params=(void *)(uintptr_t)1; request.paramsSize=1;
        ioctl(fd,_IOWR('F',NV_ESC_RM_CONTROL,NVOS54_PARAMETERS),&request);
    }
    else if (!strcmp(argv[1],"fork")) { pid_t pid=fork(); if (!pid) { sleep(30); return 0; } waitpid(pid,NULL,0); }
    else if (!strcmp(argv[1],"timeout")) sleep(30);
    else if (!strcmp(argv[1],"nonzero")) return 77;
    else return 93;
    close(fd); return 0;
}
