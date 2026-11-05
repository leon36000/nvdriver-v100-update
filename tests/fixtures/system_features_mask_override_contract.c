/* SPDX-License-Identifier: MIT
 * CPU contract tests for the process-local SYSTEM_GET_FEATURES test shim.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "nvtypes.h"
#include "nvos.h"
#include "nv-ioctl.h"
#include "nv_escape.h"
#include "nv-ioctl-numbers.h"
#include <ctrl/ctrl0000/ctrl0000system.h>

extern int hybrid_system_features_override_match(
    unsigned long request,
    void *argument,
    NvU32 replacement,
    NvU32 *kernel_value,
    const char **transport,
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS **payload);

static NVOS54_PARAMETERS root_control(
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *params)
{
    NVOS54_PARAMETERS control = { 0 };
    control.hClient = 0x100U;
    control.hObject = 0x100U;
    control.cmd = NV0000_CTRL_CMD_SYSTEM_GET_FEATURES;
    control.flags = NVOS54_FLAGS_NONE;
    control.params = NV_PTR_TO_NvP64(params);
    control.paramsSize = sizeof(*params);
    control.status = NV_OK;
    return control;
}

static void direct_replacement(void)
{
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params = { .featuresMask = 9U };
    NVOS54_PARAMETERS control = root_control(&params);
    NvU32 original = 0;
    const char *transport = NULL;
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *payload = NULL;
    unsigned long request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                                  NVOS54_PARAMETERS);

    assert(hybrid_system_features_override_match(
        request, &control, 8U, &original, &transport, &payload) == 1);
    assert(original == 9U);
    assert(params.featuresMask == 8U);
    assert(payload == &params);
    assert(transport != NULL && transport[0] == 'd');
}

static void xfer_replacement(void)
{
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params = { .featuresMask = 8U };
    NVOS54_PARAMETERS control = root_control(&params);
    nv_ioctl_xfer_t xfer = { 0 };
    NvU32 original = 0;
    const char *transport = NULL;
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *payload = NULL;
    unsigned long request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD,
                                  nv_ioctl_xfer_t);

    xfer.cmd = NV_ESC_RM_CONTROL;
    xfer.size = sizeof(control);
    xfer.ptr = NV_PTR_TO_NvP64(&control);
    assert(hybrid_system_features_override_match(
        request, &xfer, 9U, &original, &transport, &payload) == 1);
    assert(original == 8U);
    assert(params.featuresMask == 9U);
    assert(payload == &params);
    assert(transport != NULL && transport[0] == 'x');
}

static void malformed_or_failed_answers_are_untouched(void)
{
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params = { .featuresMask = 9U };
    NVOS54_PARAMETERS control = root_control(&params);
    NvU32 original = 77U;
    const char *transport = "sentinel";
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *payload = NULL;
    unsigned long request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_RM_CONTROL,
                                  NVOS54_PARAMETERS);

    control.hObject++;
    assert(hybrid_system_features_override_match(
        request, &control, 0U, &original, &transport, &payload) == 0);
    assert(params.featuresMask == 9U && original == 77U);
    control = root_control(&params);
    control.paramsSize = 8U;
    assert(hybrid_system_features_override_match(
        request, &control, 0U, &original, &transport, &payload) == 0);
    assert(params.featuresMask == 9U && original == 77U);
    control = root_control(&params);
    control.status = NV_ERR_INVALID_STATE;
    assert(hybrid_system_features_override_match(
        request, &control, 0U, &original, &transport, &payload) == 0);
    assert(params.featuresMask == 9U && original == 77U);
    control = root_control(&params);
    control.flags = 1U;
    assert(hybrid_system_features_override_match(
        request, &control, 0U, &original, &transport, &payload) == 0);
    assert(params.featuresMask == 9U && original == 77U);
    control = root_control(&params);
    control.cmd = 0x136U;
    assert(hybrid_system_features_override_match(
        request, &control, 0U, &original, &transport, &payload) == 0);
    assert(params.featuresMask == 9U && original == 77U);
}

static void malformed_xfer_is_untouched(void)
{
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS params = { .featuresMask = 9U };
    NVOS54_PARAMETERS control = root_control(&params);
    nv_ioctl_xfer_t xfer = { 0 };
    NvU32 original = 77U;
    const char *transport = "sentinel";
    NV0000_CTRL_SYSTEM_GET_FEATURES_PARAMS *payload = NULL;
    unsigned long request = _IOWR(NV_IOCTL_MAGIC, NV_ESC_IOCTL_XFER_CMD,
                                  nv_ioctl_xfer_t);

    xfer.cmd = NV_ESC_RM_CONTROL;
    xfer.size = sizeof(control) - 1U;
    xfer.ptr = NV_PTR_TO_NvP64(&control);
    assert(hybrid_system_features_override_match(
        request, &xfer, 0U, &original, &transport, &payload) == 0);
    assert(params.featuresMask == 9U && original == 77U);
}

int main(void)
{
    direct_replacement();
    xfer_replacement();
    malformed_or_failed_answers_are_untouched();
    malformed_xfer_is_untouched();
    puts("system features mask override contract: OK");
    return 0;
}
