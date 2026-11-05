/* SPDX-License-Identifier: MIT */
#include <stddef.h>
#include <stdio.h>

#include "class/cl0080.h"
#include "ctrl/ctrl0000/ctrl0000gpu.h"
#include "ctrl/ctrl2080/ctrl2080gpu.h"
#include "ctrl/ctrl2080/ctrl2080nvlink.h"

int main(void)
{
    printf("{\"gpu_get_name_string_cmd\":%u,"
           "\"gpu_get_name_string_size\":%zu,"
           "\"gpu_get_name_string_buffer_offset\":%zu,"
           "\"gpu_get_name_string_buffer_size\":%zu,",
           NV2080_CTRL_CMD_GPU_GET_NAME_STRING,
           sizeof(NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS),
           offsetof(NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS, gpuNameString),
           sizeof(((NV2080_CTRL_GPU_GET_NAME_STRING_PARAMS *)0)->gpuNameString));

#ifdef NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS
    printf("\"gpu_query_ecc_status_cmd\":%u,"
           "\"gpu_query_ecc_status_size\":%zu,"
           "\"gpu_ecc_unit_count\":%u,",
           NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS,
           sizeof(NV2080_CTRL_GPU_QUERY_ECC_STATUS_PARAMS),
           NV2080_CTRL_GPU_ECC_UNIT_COUNT);
#else
    printf("\"gpu_query_ecc_status_cmd\":null,"
           "\"gpu_query_ecc_status_size\":null,"
           "\"gpu_ecc_unit_count\":null,");
#endif

    printf("\"nvlink_get_status_cmd\":%u,"
           "\"nvlink_max_array_size\":%u,"
           "\"nvlink_link_status_info_size\":%zu,"
           "\"nvlink_get_status_size\":%zu,"
           "\"nvlink_link_info_offset\":%zu,"
           "\"nv01_device_class_id\":%u,"
           "\"nv0080_alloc_params_size\":%zu,"
           "\"nv0080_device_id_offset\":%zu,"
           "\"nv0080_flags_offset\":%zu,"
           "\"nv0080_va_space_size_offset\":%zu,"
           "\"nv0080_va_mode_offset\":%zu,"
           "\"gpu_get_device_ids_cmd\":%u,"
           "\"gpu_get_device_ids_size\":%zu,"
           "\"gpu_get_device_ids_value_offset\":%zu}\n",
           NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS,
           NV2080_CTRL_NVLINK_MAX_ARR_SIZE,
           sizeof(NV2080_CTRL_NVLINK_LINK_STATUS_INFO),
           sizeof(NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS),
           offsetof(NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS_PARAMS, linkInfo),
           NV01_DEVICE_0,
           sizeof(NV0080_ALLOC_PARAMETERS),
           offsetof(NV0080_ALLOC_PARAMETERS, deviceId),
           offsetof(NV0080_ALLOC_PARAMETERS, flags),
           offsetof(NV0080_ALLOC_PARAMETERS, vaSpaceSize),
           offsetof(NV0080_ALLOC_PARAMETERS, vaMode),
           NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS,
           sizeof(NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS),
           offsetof(NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS, deviceIds));
    return 0;
}
