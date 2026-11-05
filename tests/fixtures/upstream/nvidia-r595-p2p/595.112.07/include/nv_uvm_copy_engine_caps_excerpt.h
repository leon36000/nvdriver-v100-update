/*
 * SPDX-FileCopyrightText: Copyright (c) 2014-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * Exact copy-engine capability declarations excerpted from NVIDIA R595.112.07
 * nv_uvm_types.h, commit d8257d95ae5fed364163e4df51db66df8b1ee0d2,
 * source SHA-256 5515b06a13072584d4668251c2e31bbb724118c914691eb4abf1cd76c1b63e65.
 * Primitive Nv* typedefs below are test scaffolding, not an upstream excerpt.
 */
#ifndef TEST_NV_UVM_COPY_ENGINE_CAPS_EXCERPT_H
#define TEST_NV_UVM_COPY_ENGINE_CAPS_EXCERPT_H

#include <stdint.h>

typedef uint8_t NvBool;
typedef uint32_t NvU32;

#define NV_TRUE ((NvBool)1)
#define NV_FALSE ((NvBool)0)

#define UVM_COPY_ENGINE_COUNT_MAX 64

typedef struct
{
    NvBool supported:1;
    NvBool grce:1;
    NvBool shared:1;
    NvBool sysmemRead:1;
    NvBool sysmemWrite:1;
    NvBool sysmem:1;
    NvBool nvlinkP2p:1;
    NvBool p2p:1;
    NvBool secure:1;
    NvBool scrub:1;
    NvU32 cePceMask;
} UvmGpuCopyEngineCaps;

typedef struct UvmGpuCopyEnginesCaps_tag
{
    UvmGpuCopyEngineCaps copyEngineCaps[UVM_COPY_ENGINE_COUNT_MAX];
} UvmGpuCopyEnginesCaps;

#endif
