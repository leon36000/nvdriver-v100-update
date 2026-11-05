/* SPDX-License-Identifier: MIT */
/*
 * Compile against the pinned R580.196.07 or R595.112.07 headers to report the
 * identifiers used by the source-level GV100 UVM HAL contract. This is not an
 * RM or GPU runtime capture.
 */
#include <stdio.h>

#include "ctrl2080mc.h"
#include "clc36f.h"
#include "clc3b5.h"
#include "clc3c0.h"

int main(void)
{
    printf("{\"gpu_arch\":%u,\"host_class\":%u,\"ce_class\":%u,"
           "\"compute_class\":%u}\n",
           (unsigned)NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100,
           (unsigned)VOLTA_CHANNEL_GPFIFO_A,
           (unsigned)VOLTA_DMA_COPY_A,
           (unsigned)VOLTA_COMPUTE_A);
    return 0;
}
