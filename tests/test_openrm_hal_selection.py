# SPDX-License-Identifier: MIT
"""Execute pinned generated HAL selectors on CPU to expose unsafe fallthrough.

This is a source-contract experiment. It does not construct a real RM object or
validate the selected callbacks on hardware. Callback bodies are sentinels.
"""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "ac24e02fc090c3e05c1fc03384b317ac2cc301b5"
SOURCE = Path(os.environ.get("OPENRM_SOURCE", ROOT / ".cache/upstream" /
                             ("open-gpu-kernel-modules-" + COMMIT)))


def function_source(text, signature):
    """Extract a named, brace-balanced generated C function without rewriting it."""
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise ValueError("unterminated generated selector")


class OpenRmHalSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generated = SOURCE / "src/nvidia/generated"
        mapper = generated / "g_chips2halspec_nvoc.c"
        table = generated / "g_gpu_arch_nvoc.c"
        if not mapper.is_file() or not table.is_file():
            raise unittest.SkipTest("pinned complete R595.104.02 source cache required")
        # Hashes identify the actual generated inputs, not reconstructed logic.
        cls.input_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in (mapper, table)}
        expected = {
            "g_chips2halspec_nvoc.c": "f112674d8191a09662bf8e1a3f5b920773a95d6aae6e61fe79382d405fbade3e",
            "g_gpu_arch_nvoc.c": "fdeaf48bbaad15f428894a2cac90d83df6131121dfe4c87da13f3405fd647879",
        }
        if cls.input_hashes != expected:
            raise RuntimeError("generated HAL inputs differ from pinned R595.104.02")
        cls.selectors = (
            function_source(mapper.read_text(), "void __nvoc_init_halspec_ChipHal(") + "\n" +
            function_source(table.read_text(), "static void __nvoc_init_funcTable_GpuArch_1("))

    def compile_and_run(self, checks):
        prelude = r'''
#include <assert.h>
#include <stdint.h>
typedef uint32_t NvU32;
typedef struct { unsigned short __nvoc_HalVarIdx; } ChipHal;
typedef struct GpuArch GpuArch;
struct GpuArch {
    ChipHal chipHal;
    NvU32 (*__gpuarchGetSystemPhysAddrWidth__)(GpuArch *);
    NvU32 (*__gpuarchGetDmaAddrWidth__)(GpuArch *);
    NvU32 (*__gpuarchGetGpcFuseStatusOffset__)(GpuArch *);
};
#define staticCast(p,t) (p)
#define PORT_UNREFERENCED_VARIABLE(v) ((void)(v))
/* Unique sentinels identify pointer selection; no physical widths inferred. */
#define SENTINEL(name, id) static NvU32 name(GpuArch *p) { (void)p; return id; }
SENTINEL(gpuarchGetSystemPhysAddrWidth_T234D, 1)
SENTINEL(gpuarchGetSystemPhysAddrWidth_GB10B, 2)
SENTINEL(gpuarchGetSystemPhysAddrWidth_TU102, 3)
SENTINEL(gpuarchGetSystemPhysAddrWidth_GH100, 4)
SENTINEL(gpuarchGetDmaAddrWidth_GB10B, 5)
SENTINEL(gpuarchGetDmaAddrWidth_b2b553, 6)
SENTINEL(gpuarchGetGpcFuseStatusOffset_GB10B, 7)
SENTINEL(gpuarchGetGpcFuseStatusOffset_b2b553, 8)
'''
        with tempfile.TemporaryDirectory(prefix="openrm-hal-selection-") as directory:
            root = Path(directory)
            source = root / "selector.c"
            source.write_text(prelude + self.selectors + "\nint main(void) {\n" + checks + "\nreturn 0;\n}\n")
            result = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                 str(source), "-o", str(root / "selector")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(root / "selector")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gv100_has_no_chip_mapping_and_zero_index_uses_hopper_default(self):
        self.compile_and_run(r'''
    ChipHal unmatched = {0xffff};
    __nvoc_init_halspec_ChipHal(&unmatched, 0x14, 0, 0); /* GV100 */
    assert(unmatched.__nvoc_HalVarIdx == 0xffff);
    GpuArch arch = {0}; /* zero-allocated NVOC storage */
    __nvoc_init_halspec_ChipHal(&arch.chipHal, 0x14, 0, 0);
    assert(arch.chipHal.__nvoc_HalVarIdx == 0);
    __nvoc_init_funcTable_GpuArch_1(&arch);
    assert(arch.__gpuarchGetSystemPhysAddrWidth__ == gpuarchGetSystemPhysAddrWidth_GH100);
''')

    def test_supported_control_chips_select_their_existing_paths(self):
        self.compile_and_run(r'''
    GpuArch arch = {0};
    __nvoc_init_halspec_ChipHal(&arch.chipHal, 0x16, 2, 0); /* TU102 */
    assert(arch.chipHal.__nvoc_HalVarIdx == 37);
    __nvoc_init_funcTable_GpuArch_1(&arch);
    assert(arch.__gpuarchGetSystemPhysAddrWidth__ == gpuarchGetSystemPhysAddrWidth_TU102);
    __nvoc_init_halspec_ChipHal(&arch.chipHal, 0x1b, 2, 0); /* GB202 */
    assert(arch.chipHal.__nvoc_HalVarIdx == 67);
    __nvoc_init_funcTable_GpuArch_1(&arch);
    assert(arch.__gpuarchGetSystemPhysAddrWidth__ == gpuarchGetSystemPhysAddrWidth_GH100);
    __nvoc_init_halspec_ChipHal(&arch.chipHal, 0x1b, 3, 0); /* GB203 */
    assert(arch.chipHal.__nvoc_HalVarIdx == 68);
    __nvoc_init_funcTable_GpuArch_1(&arch);
    assert(arch.__gpuarchGetSystemPhysAddrWidth__ == gpuarchGetSystemPhysAddrWidth_GH100);
''')


if __name__ == "__main__":
    unittest.main()
