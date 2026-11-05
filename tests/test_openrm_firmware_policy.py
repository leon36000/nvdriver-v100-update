# SPDX-License-Identifier: MIT
"""Execute upstream RmFetchGspRmImages with fake firmware I/O, never a GPU.

The test compiles the actual pinned function and firmware-family header. Only
the register decoder and OS firmware service are replaced at their boundary.
"""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "ac24e02fc090c3e05c1fc03384b317ac2cc301b5"
SOURCE = Path(os.environ.get("OPENRM_SOURCE", ROOT / ".cache/upstream" / ("open-gpu-kernel-modules-" + COMMIT)))
OSINIT = Path("src/nvidia/arch/nvalloc/unix/src/osinit.c")
PATCH = ROOT / "patches/r595.104.02/0001-gv100-monolithic-firmware-policy.patch"
OSINIT_SHA256 = "11a135a856de9f87555df72adb479251bfaba7c0492c77ae152d59bb24eb2ca2"
FAMILY_SELECTOR = Path("src/nvidia/arch/nvalloc/common/inc/nv-firmware-chip-family-select.h")
FAMILY_SELECTOR_SHA256 = "6e3fc29f96e55163df2011ab72540d25b5ac615b9b9998f90c8f4192f76b76da"

PRELUDE = r'''
#include <stddef.h>
#include <nvtypes.h>
#include <nv-firmware-chip-family-select.h>
#include <assert.h>
#include <string.h>
typedef int NV_STATUS;
#define NV_OK 0
#define NV_ERR_NOT_SUPPORTED 1
#define LIBOS_LOG_DECODE_ENABLE 0
#define GPU_ARCH_SHIFT 4
#define NV_PRINTF(...) ((void)0)
#define portMemSet memset
typedef struct { NvU32 pmc_boot_42; } nv_priv_t;
typedef struct {
    nv_priv_t priv;
    NvBool allow_fallback_to_monolithic_rm;
    NvBool request_fw_client_rm;
} nv_state_t;
typedef struct { const void *pBuf; NvU64 size; } GSP_FIRMWARE;
#define NV_GET_NV_PRIV(nv) (&(nv)->priv)
static NvU32 input_arch, input_impl;
static unsigned fetch_calls;
static int available;
static nv_firmware_chip_family_t fetched_family;
static NvU32 decodePmcBoot42Architecture(NvU32 unused) {
    (void)unused; return input_arch >> GPU_ARCH_SHIFT;
}
#undef DRF_VAL
#define DRF_VAL(d,r,f,v) (input_impl)
static const void *nv_get_firmware(nv_state_t *nv, nv_firmware_type_t type,
    nv_firmware_chip_family_t family, const void **buffer, NvU64 *size) {
    (void)nv; assert(type == NV_FIRMWARE_TYPE_GSP);
    ++fetch_calls; fetched_family = family;
    if (!available || family == NV_FIRMWARE_CHIP_FAMILY_NULL) return NULL;
    *buffer = "fixture firmware"; *size = 16;
    return *buffer;
}
'''

CHECKS = r'''
static void check_case(NvU32 arch, NvU32 impl, int firmware_available,
    unsigned expected_calls, NV_STATUS expected_status, int expected_client,
    nv_firmware_chip_family_t expected_family) {
    input_arch = arch; input_impl = impl; available = firmware_available;
    fetch_calls = 0; fetched_family = NV_FIRMWARE_CHIP_FAMILY_END;
    nv_state_t nv = {0}; nv.request_fw_client_rm = NV_TRUE;
    GSP_FIRMWARE fw; memset(&fw, 0xa5, sizeof(fw));
    const void *handle = (void *)1, *log_handle = (void *)1;
    NV_STATUS status = RmFetchGspRmImages(&nv, &fw, &handle, &log_handle);
    assert(status == expected_status);
    assert(fetch_calls == expected_calls);
    if (expected_calls) assert(fetched_family == expected_family);
    if (expected_client >= 0) assert(nv.request_fw_client_rm == expected_client);
    if (!expected_calls) {
        assert(handle == NULL && log_handle == NULL && fw.pBuf == NULL && fw.size == 0);
    }
}
int main(void) {
#ifdef NV_HYBRID_EXPERIMENTAL_GV100
    check_case(GPU_ARCHITECTURE_VOLTA, GPU_IMPLEMENTATION_GV100, 0, 0, NV_OK, 0, 0);
    check_case(GPU_ARCHITECTURE_VOLTA, GPU_IMPLEMENTATION_GV100, 1, 0, NV_OK, 0, 0);
#else
    check_case(GPU_ARCHITECTURE_VOLTA, GPU_IMPLEMENTATION_GV100, 0, 1, NV_ERR_NOT_SUPPORTED, -1, NV_FIRMWARE_CHIP_FAMILY_NULL);
#endif
    /* A nearby but unhandled implementation may not acquire the bypass. */
    check_case(GPU_ARCHITECTURE_VOLTA, 1, 0, 1, NV_ERR_NOT_SUPPORTED, -1, NV_FIRMWARE_CHIP_FAMILY_NULL);
    check_case(GPU_ARCHITECTURE_VOLTA2, GPU_IMPLEMENTATION_GV11B, 0, 1, NV_ERR_NOT_SUPPORTED, -1, NV_FIRMWARE_CHIP_FAMILY_NULL);
    const struct { NvU32 arch, impl; nv_firmware_chip_family_t family; } controls[] = {
        {GPU_ARCHITECTURE_TURING, GPU_IMPLEMENTATION_TU102, NV_FIRMWARE_CHIP_FAMILY_TU10X},
        {GPU_ARCHITECTURE_AMPERE, GPU_IMPLEMENTATION_GA100, NV_FIRMWARE_CHIP_FAMILY_GA100},
        {GPU_ARCHITECTURE_ADA, GPU_IMPLEMENTATION_AD102, NV_FIRMWARE_CHIP_FAMILY_AD10X},
        {GPU_ARCHITECTURE_HOPPER, GPU_IMPLEMENTATION_GH100, NV_FIRMWARE_CHIP_FAMILY_GH100},
        {GPU_ARCHITECTURE_BLACKWELL_GB1XX, GPU_IMPLEMENTATION_GB100, NV_FIRMWARE_CHIP_FAMILY_GB10X},
        {GPU_ARCHITECTURE_BLACKWELL_GB2XX, GPU_IMPLEMENTATION_GB202, NV_FIRMWARE_CHIP_FAMILY_GB20X},
        {GPU_ARCHITECTURE_BLACKWELL_GB2XX, GPU_IMPLEMENTATION_GB203, NV_FIRMWARE_CHIP_FAMILY_GB20X},
    };
    for (unsigned i = 0; i < sizeof(controls)/sizeof(controls[0]); ++i) {
        check_case(controls[i].arch, controls[i].impl, 0, 1, NV_ERR_NOT_SUPPORTED, -1, controls[i].family);
        check_case(controls[i].arch, controls[i].impl, 1, 1, NV_OK, 1, controls[i].family);
    }
    return 0;
}
'''


class OpenRmFirmwarePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (SOURCE / OSINIT).is_file():
            raise unittest.SkipTest("pinned complete R595.104.02 source cache is required (OPENRM_SOURCE)")
        cls.original = (SOURCE / OSINIT).read_text()
        if hashlib.sha256((SOURCE / OSINIT).read_bytes()).hexdigest() != OSINIT_SHA256:
            raise RuntimeError("upstream osinit.c differs from the pinned input")
        if hashlib.sha256((SOURCE / FAMILY_SELECTOR).read_bytes()).hexdigest() != FAMILY_SELECTOR_SHA256:
            raise RuntimeError("firmware-family selector differs from the pinned input")

    def run_contract(self, patched, enabled):
        with tempfile.TemporaryDirectory(prefix="openrm-policy-test-") as directory:
            root = Path(directory)
            source_file = root / OSINIT
            source_file.parent.mkdir(parents=True)
            shutil.copyfile(SOURCE / OSINIT, source_file)
            if patched:
                result = subprocess.run(["patch", "--batch", "--forward", "-p1", "-i", str(PATCH)],
                                        cwd=root, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            source = source_file.read_text()
            start = source.index("static NV_STATUS RmFetchGspRmImages\n")
            end = source.index("static void _checkP2pChipsetSupport(", start)
            license_text = source[:source.index("#include")]
            harness = root / "policy.c"
            harness.write_text(license_text + PRELUDE + source[start:end] + CHECKS)
            # The upstream function leaves the log-handle parameter unused when
            # LIBOS logging is disabled, as it is in this focused contract.
            command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                       "-isystem", str(SOURCE / "src/common/sdk/nvidia/inc"),
                       "-isystem", str(SOURCE / "src/common/inc"),
                       "-isystem", str(SOURCE / "src/common/inc/swref"),
                       "-isystem", str(SOURCE / "kernel-open/common/inc"),
                       "-isystem", str(SOURCE / "src/nvidia/arch/nvalloc/common/inc")]
            if enabled:
                command.append("-DNV_HYBRID_EXPERIMENTAL_GV100")
            command += [str(harness), "-o", str(root / "policy")]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(root / "policy")], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stock_source_demonstrates_the_early_gv100_failure(self):
        self.run_contract(patched=False, enabled=False)

    def test_patch_disabled_retains_stock_behavior(self):
        self.run_contract(patched=True, enabled=False)

    def test_opt_in_only_skips_firmware_for_exact_gv100(self):
        self.run_contract(patched=True, enabled=True)


if __name__ == "__main__":
    unittest.main()
