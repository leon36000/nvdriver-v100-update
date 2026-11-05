# SPDX-License-Identifier: MIT
"""Compile pinned OpenRM exported-control entries without calling callbacks.

This source-contract test checks the generated dispatch initializer and its
real route-flag macro. It produces an object file only: no physical callback
body is provided or invoked, and no runtime/hardware outcome is inferred.
"""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "ac24e02fc090c3e05c1fc03384b317ac2cc301b5"
SOURCE = Path(os.environ.get(
    "OPENRM_SOURCE",
    ROOT / ".cache/upstream" / ("open-gpu-kernel-modules-" + COMMIT),
))

PINNED_SHA256 = {
    "src/nvidia/generated/g_subdevice_nvoc.c":
        "d79fbe8b6e39b42a671fb70b713d2c7811b28f4bcaf2a625f0fd06928c7428d0",
    "src/nvidia/generated/g_subdevice_nvoc.h":
        "7fe72a0032fdfdeb46ffa6ec919ec9db98971392e056a43b3a4a62656066627c",
    "src/nvidia/inc/kernel/rmapi/control.h":
        "97ad0672655e41a8599c5f7ca74dc90b6fbac7df809507239f0d180cc0684bfa",
    "src/nvidia/src/kernel/gpu/gr/kernel_graphics.c":
        "c31b4abd71f87c7f46e068b9d2a72c27c635124df5b1802553895cb8a11fdc16",
    "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080internal.h":
        "032c84d1d9e822d77909f8ce3c1ed668a66852d4d62863aa5fd05940a884f230",
}

METHODS = {
    0x20800A1F: {
        "name": "STATIC_KGR_GET_CAPS",
        "flags": 0x100C0,
        "callback": "subdeviceCtrlCmdKGrInternalStaticGetCaps_IMPL",
        "param_type": "NV2080_CTRL_INTERNAL_STATIC_GR_GET_CAPS_PARAMS",
    },
    0x20800A2A: {
        "name": "STATIC_KGR_GET_INFO",
        "flags": 0x1C0C0,
        "callback": "subdeviceCtrlCmdKGrInternalStaticGetInfo_IMPL",
        "param_type": "NV2080_CTRL_INTERNAL_STATIC_GR_GET_INFO_PARAMS",
    },
    0x20800A36: {
        "name": "GPU_GET_CHIP_INFO",
        "flags": 0x404C0,
        "callback": "subdeviceCtrlCmdInternalGetChipInfo_IMPL",
        "param_type": "NV2080_CTRL_INTERNAL_GPU_GET_CHIP_INFO_PARAMS",
    },
}


def function_source(text, signature):
    """Return one source function by balancing its braces."""
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
    raise ValueError(f"unterminated source function: {signature}")


def balanced_initializer_end(text, opening):
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    raise ValueError("unterminated generated method initializer")


def macro_definition(text, name, function_like=False):
    suffix = r"\(" if function_like else r"\b"
    match = re.search(r"(?m)^#define\s+" + re.escape(name) + suffix, text)
    if match is None:
        raise ValueError(f"missing source macro: {name}")
    lines = text[match.start():].splitlines()
    definition = [lines[0]]
    while definition[-1].rstrip().endswith("\\"):
        definition.append(lines[len(definition)])
    return "\n".join(definition)


def parse_method_entries(source_text):
    array_name = "static const struct NVOC_EXPORTED_METHOD_DEF __nvoc_exported_method_def_Subdevice[]"
    array_start = source_text.index(array_name)
    entries = {}
    for match in re.finditer(r"(?m)^[ \t]*\{\s*/\*\s*\[\s*\d+\s*\]\s*\*/", source_text[array_start:]):
        opening = source_text.index("{", array_start + match.start())
        end = balanced_initializer_end(source_text, opening)
        block = source_text[opening:end]
        method_match = re.search(r"/\*methodId=\*/\s*(0x[0-9a-fA-F]+)u", block)
        if method_match is None:
            continue
        method_id = int(method_match.group(1), 16)
        if method_id in METHODS:
            if method_id in entries:
                raise ValueError(f"duplicate exported method id 0x{method_id:x}")
            entries[method_id] = block
    if set(entries) != set(METHODS):
        missing = sorted(set(METHODS) - set(entries))
        raise ValueError("missing generated method entries: " + ", ".join(hex(x) for x in missing))
    return entries


def source_macro_value(text, name):
    match = re.search(
        r"(?m)^#define\s+" + re.escape(name) + r"\s+\(0x([0-9a-fA-F]+)\)",
        text,
    )
    if match is None:
        raise ValueError(f"missing control ID macro: {name}")
    return int(match.group(1), 16)


class OpenRmPhysicalControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_dir():
            raise unittest.SkipTest("pinned complete R595.104.02 source cache required")
        missing = [rel for rel in PINNED_SHA256 if not (SOURCE / rel).is_file()]
        if missing:
            raise unittest.SkipTest("missing pinned OpenRM inputs: " + ", ".join(missing))

        hashes = {
            rel: hashlib.sha256((SOURCE / rel).read_bytes()).hexdigest()
            for rel in PINNED_SHA256
        }
        if hashes != PINNED_SHA256:
            mismatches = [
                f"{rel}: expected {PINNED_SHA256[rel]}, got {hashes[rel]}"
                for rel in PINNED_SHA256
                if hashes[rel] != PINNED_SHA256[rel]
            ]
            raise RuntimeError("pinned R595.104.02 input mismatch: " + "; ".join(mismatches))

        generated = SOURCE / "src/nvidia/generated/g_subdevice_nvoc.c"
        generated_header = SOURCE / "src/nvidia/generated/g_subdevice_nvoc.h"
        control_header = SOURCE / "src/nvidia/inc/kernel/rmapi/control.h"
        graphics_source = SOURCE / "src/nvidia/src/kernel/gpu/gr/kernel_graphics.c"
        ctrl_header = SOURCE / "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080internal.h"

        generated_text = generated.read_text()
        control_text = control_header.read_text()
        graphics_text = graphics_source.read_text()
        ctrl_text = ctrl_header.read_text()
        generated_header_text = generated_header.read_text()

        load_static_info = function_source(
            graphics_text, "NV_STATUS\nkgraphicsLoadStaticInfo_KERNEL\n("
        )
        self_controls = (
            "NV2080_CTRL_CMD_INTERNAL_STATIC_KGR_GET_CAPS",
            "NV2080_CTRL_CMD_INTERNAL_STATIC_KGR_GET_INFO",
        )
        if not all(command in load_static_info for command in self_controls):
            raise RuntimeError("kernel graphics static-info calls differ from pinned contract")

        expected_command_ids = {
            "NV2080_CTRL_CMD_INTERNAL_STATIC_KGR_GET_CAPS": 0x20800A1F,
            "NV2080_CTRL_CMD_INTERNAL_STATIC_KGR_GET_INFO": 0x20800A2A,
            "NV2080_CTRL_CMD_INTERNAL_GPU_GET_CHIP_INFO": 0x20800A36,
        }
        for name, expected in expected_command_ids.items():
            if source_macro_value(ctrl_text, name) != expected:
                raise RuntimeError(f"pinned command ID changed for {name}")

        cls.entries = parse_method_entries(generated_text)
        for method_id, metadata in METHODS.items():
            block = cls.entries[method_id]
            if f"/*flags=*/      0x{metadata['flags']:x}u" not in block:
                raise RuntimeError(f"unexpected flags for {metadata['name']}")
            if f"&{metadata['callback']}" not in block:
                raise RuntimeError(f"unexpected implementation symbol for {metadata['name']}")

        cls.route_macro = macro_definition(
            control_text, "NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG", function_like=True
        )
        cls.route_flags = "\n".join((
            macro_definition(control_text, "RMCTRL_FLAGS_ROUTE_TO_PHYSICAL"),
            macro_definition(control_text, "RMCTRL_FLAGS_PHYSICAL_IMPLEMENTED_ON_VGPU_GUEST"),
        ))

        default_start = generated_text.index("// By default, all exported methods are enabled.")
        default_end = generated_text.index("\n#endif\n", default_start) + len("\n#endif")
        cls.generated_default = generated_text[default_start:default_end]

        prototype_matches = re.findall(
            r"(?m)^NV_STATUS subdeviceCtrlCmdInternalGetChipInfo_IMPL\(struct Subdevice \*pSubdevice, "
            r"NV2080_CTRL_INTERNAL_GPU_GET_CHIP_INFO_PARAMS \*pParams\);$",
            generated_header_text,
        )
        if not prototype_matches or len(set(prototype_matches)) != 1:
            raise RuntimeError("local GetChipInfo prototype differs or is missing")
        cls.local_prototype = prototype_matches[0]

    def test_generated_physical_entries_compile_to_null_dispatch(self):
        entry_decls = "\n\n".join(
            f"const struct NVOC_EXPORTED_METHOD_DEF method_{method_id:08x} = {self.entries[method_id]};"
            for method_id in METHODS
        )
        c_source = f'''
#include <stddef.h>
#include <stdint.h>

#define NV_PRINTF_STRINGS_ALLOWED 0
{self.route_flags}
{self.route_macro}
{self.generated_default}

typedef uint32_t NV_STATUS;
typedef struct {{ uint8_t opaque; }} NV2080_CTRL_INTERNAL_STATIC_GR_GET_CAPS_PARAMS;
typedef struct {{ uint8_t opaque; }} NV2080_CTRL_INTERNAL_STATIC_GR_GET_INFO_PARAMS;
typedef struct {{ uint8_t opaque; }} NV2080_CTRL_INTERNAL_GPU_GET_CHIP_INFO_PARAMS;
struct Subdevice;
{self.local_prototype}

struct NVOC_CLASS_DEF {{ struct {{ uint32_t opaque; }} classInfo; }};
const struct NVOC_CLASS_DEF __nvoc_class_def_Subdevice = {{ {{ 0U }} }};

struct NVOC_EXPORTED_METHOD_DEF {{
    void (*pFunc)(void);
    uint32_t flags;
    uint32_t accessRight;
    uint32_t methodId;
    size_t paramSize;
    const void *pClassInfo;
}};

_Static_assert(NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG(0x100c0u),
               "GET_CAPS must be omitted from this local method table");
_Static_assert(NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG(0x1c0c0u),
               "GET_INFO must be omitted from this local method table");
_Static_assert(!NVOC_EXPORTED_METHOD_DISABLED_BY_FLAG(0x404c0u),
               "GetChipInfo guest implementation keeps its local entry");

{entry_decls}
'''

        with tempfile.TemporaryDirectory(prefix="openrm-physical-controls-") as directory:
            temp = Path(directory)
            c_file = temp / "physical_controls.c"
            object_file = temp / "physical_controls.o"
            c_file.write_text(c_source)
            compile_result = subprocess.run(
                [
                    "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-cast-function-type", "-c", str(c_file), "-o", str(object_file),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                compile_result.returncode, 0,
                compile_result.stdout + compile_result.stderr,
            )

            symbols = subprocess.run(
                ["nm", "-u", str(object_file)], capture_output=True, text=True
            )
            self.assertEqual(symbols.returncode, 0, symbols.stdout + symbols.stderr)
            undefined = set(re.findall(r"(?m)^\s*U\s+(\S+)", symbols.stdout))
            # Disabled branches must not leave relocations to the two physical
            # implementation symbols. The enabled local entry deliberately
            # leaves only an unresolved symbol reference; it is never linked or called.
            self.assertNotIn(METHODS[0x20800A1F]["callback"], undefined)
            self.assertNotIn(METHODS[0x20800A2A]["callback"], undefined)
            self.assertIn(METHODS[0x20800A36]["callback"], undefined)


if __name__ == "__main__":
    unittest.main()
