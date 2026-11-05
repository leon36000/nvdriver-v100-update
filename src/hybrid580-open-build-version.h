/* SPDX-License-Identifier: MIT */
#ifndef HYBRID580_OPEN_BUILD_VERSION_H
#define HYBRID580_OPEN_BUILD_VERSION_H

#include "hybrid580-control-session.h"
#include <ctrl/ctrl0000/ctrl0000system.h>

/* R580 build-version metadata is system-wide and pointer-free at the RM
 * boundary. The frontend adapts the old user-facing V1 packet. */
NV_STATUS hybrid580_open_control_session_build_version_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_V2_PARAMS *params,
    NvU32 *control_status);

/* Pointer-free, fixed-size root metadata query; only the Open R580 backend
 * owns this provider because the frontend uses one root-global answer. */
NV_STATUS hybrid580_open_control_session_system_features_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *params,
    NvU32 *control_status);

/* Root-global Fabric Manager readiness query; the frontend selects Open only. */
NV_STATUS hybrid580_open_control_session_fabric_status_v1(
    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,
    NvU32 flags, NV0000_CTRL_SYSTEM_GET_FABRIC_STATUS_PARAMS *params,
    NvU32 *control_status);

#endif
