# SPDX-License-Identifier: MIT
"""Execute exact-release OpenRM HAL registration and lookup code on CPU.

For each hash-pinned public OpenRM archive, this compiles the stock generated
HAL enum, chip table, REGISTER_ALL_HALS family dispatch, and halmgr lookup
functions. Only registerHalModule_* is stubbed, using identity-only opaque
tokens; no HAL implementation or callback is provided. Include trees are
materialized from regular archive members only into a fresh temporary folder.

This proves source-level registration and lookup reachability for these exact
generated profiles. It does not execute RM initialization, HAL callbacks,
kernel modules, GPUs, or hardware.
"""

import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import unittest

from tools.compare_openrm_gv100 import INPUTS, SOURCE_COMMITS, _read_regular_snapshot


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_CACHE = ROOT / ".cache/upstream"
SOURCE_FILES = (
    "src/nvidia/generated/g_hal.h",
    "src/nvidia/generated/g_hal_archimpl.h",
    "src/nvidia/generated/g_hal_register.h",
    "src/nvidia/generated/g_hal_mgr_nvoc.h",
    "src/nvidia/src/kernel/core/hal_mgr.c",
)
INCLUDE_TREES = (
    "src/common/sdk/nvidia/inc",
    "src/common/inc/swref/published",
)
POSITIVE_CONTROLS = ("TU102", "GB202", "GB203")


def function_source(text, signature):
    """Extract one brace-balanced stock C function without rewriting it."""
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
    raise ValueError(f"unterminated generated function: {signature}")


def brace_balanced_end(text, opening):
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    raise ValueError("unterminated generated initializer")


def _safe_relative_member(name, prefix):
    """Return an archive-relative path, rejecting absolute/traversal names."""
    path = PurePosixPath(name)
    root = PurePosixPath(prefix)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe archive member path: {name!r}")
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    if not relative.parts:
        return None
    return relative


def _archive_sources(version, filename, prefix, expected_sha256, destination):
    """Verify one archive snapshot and collect exact sources plus safe includes."""
    archive_path = ARCHIVE_CACHE / filename
    snapshot = _read_regular_snapshot(archive_path)
    actual_sha256 = hashlib.sha256(snapshot).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError(f"{version} archive digest differs from pinned source")

    required = {prefix + "/" + name: name for name in SOURCE_FILES}
    required_seen = set()
    texts = {}
    include_seen = set()
    tree_prefixes = tuple(prefix + "/" + name + "/" for name in INCLUDE_TREES)

    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:*") as archive:
        for member in archive:
            source_relative = required.get(member.name)
            is_include_member = member.name.startswith(tree_prefixes)
            if source_relative is None and not is_include_member:
                continue

            relative = _safe_relative_member(member.name, prefix)
            if relative is None:
                raise ValueError(f"invalid selected archive member: {member.name}")

            if source_relative is not None:
                if member.name in required_seen:
                    raise ValueError(f"duplicate source member: {member.name}")
                required_seen.add(member.name)
                if not member.isfile():
                    raise ValueError(f"source member is not regular: {member.name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"could not read source member: {member.name}")
                texts[source_relative] = stream.read().decode("utf-8", errors="strict")
                continue

            # The include subtrees are selected inputs, so fail closed on links,
            # special files, duplicate paths, or traversal instead of extracting
            # through tarfile's path-handling helpers.
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"non-regular selected include: {member.name}")
            if member.name in include_seen:
                raise ValueError(f"duplicate selected include: {member.name}")
            include_seen.add(member.name)
            target = destination.joinpath(*relative.parts)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError(f"include escaped temporary root: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"could not read selected include: {member.name}")
            target.write_bytes(stream.read())

    missing = sorted(set(required) - required_seen)
    if missing:
        raise ValueError("missing selected source members: " + ", ".join(missing))
    return {
        "version": version,
        "repository_tag": version,
        "repository_commit": SOURCE_COMMITS[version],
        "archive": str(archive_path),
        "archive_sha256": actual_sha256,
        "source_sha256": {
            relative: hashlib.sha256(texts[relative].encode("utf-8")).hexdigest()
            for relative in SOURCE_FILES
        },
        "include_file_count": len(include_seen),
        "texts": texts,
    }


def _prepare_translation_unit(texts, version):
    generated = "src/nvidia/generated/"
    hal_header = texts[generated + "g_hal.h"]
    archimpl_header = texts[generated + "g_hal_archimpl.h"]
    registration_header = texts[generated + "g_hal_register.h"]
    manager_header = texts[generated + "g_hal_mgr_nvoc.h"]
    manager_source = texts["src/nvidia/src/kernel/core/hal_mgr.c"]

    enum_marker = hal_header.index("// HAL_IMPLEMENTATION enum")
    enum_start = hal_header.index("typedef enum", enum_marker)
    enum_end = hal_header.index("} HAL_IMPLEMENTATION;", enum_start) + len("} HAL_IMPLEMENTATION;")
    hal_enum = hal_header[enum_start:enum_end]
    enum_names = set(re.findall(r"\bHAL_IMPL_([A-Z0-9]+)\b", hal_enum))
    if "GV100" not in enum_names:
        raise RuntimeError(f"{version} stock enum has no GV100 sentinel")

    table_decl = archimpl_header.index("const struct ChipID")
    table_match = re.search(r"}\s*chipID\s*\[\]\s*=\s*\{", archimpl_header[table_decl:])
    if table_match is None:
        raise RuntimeError(f"{version} stock chipID initializer not found")
    table_open = table_decl + table_match.end() - 1
    chip_table = archimpl_header[table_decl:brace_balanced_end(archimpl_header, table_open)] + ";"

    registration_symbols = re.findall(
        r"\bNV_STATUS\s+registerHalModule_([A-Z0-9]+)\(void\)\s*;",
        registration_header,
    )
    if not registration_symbols or len(set(registration_symbols)) != len(registration_symbols):
        raise RuntimeError(f"{version} registration declarations missing or duplicated")
    if "GV100" in registration_symbols or "registerHalModule_GV100" in registration_header:
        raise RuntimeError(f"{version} stock header unexpectedly declares GV100 HAL")
    missing_enum = sorted(set(registration_symbols) - enum_names)
    if missing_enum:
        raise RuntimeError(f"{version} registration has no matching enum: {missing_enum}")
    missing_positive = sorted(set(POSITIVE_CONTROLS) - set(registration_symbols))
    if missing_positive:
        raise RuntimeError(f"{version} missing positive HAL controls: {missing_positive}")

    family_names = re.findall(
        r"static\s+NV_STATUS\s+NV_INLINE\s+(REGISTER_[A-Z0-9_]+)\(void\)",
        registration_header,
    )
    if "REGISTER_ALL_HALS" not in family_names:
        raise RuntimeError(f"{version} stock REGISTER_ALL_HALS not found")
    registration_functions = "\n\n".join(
        function_source(registration_header, f"static NV_STATUS NV_INLINE {name}(void)")
        for name in family_names
    )
    manager_list_field = re.search(r"struct OBJHAL \*pHalList\[(\d+)\];", manager_header)
    if manager_list_field is None:
        raise RuntimeError(f"{version} stock OBJHALMGR pHalList field not found")
    halmgr_functions = "\n\n".join((
        function_source(manager_source, "static NvBool\n_halmgrIsTegraSupported"),
        function_source(manager_source, "static NvBool\n_halmgrIsChipSupported"),
        function_source(manager_source, "NV_STATUS\nhalmgrGetHalForGpu_IMPL"),
    ))
    registration_stubs = "\n\n".join(
        f'''NV_STATUS registerHalModule_{name}(void)
{{
    ++registration_calls;
    active_manager->pHalList[HAL_IMPL_{name}] =
        (struct OBJHAL *)&registration_tokens[HAL_IMPL_{name}];
    return NV_OK;
}}'''
        for name in registration_symbols
    )

    source = f'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <nvstatus.h>
#include <nv_ref.h>

/* RM status, NvU32/NvBool and PMC DRF macros come from exact release headers. */
#define NV_PRINTF_STRINGS_ALLOWED 0
#define NV_PRINTF(...) ((void)0)
#define LEVEL_INFO 0

{hal_enum}

/* Only the stock pHalList ABI used by the extracted functions is represented. */
struct OBJHAL;
typedef struct OBJHAL OBJHAL;
typedef struct OBJHALMGR {{
    struct OBJHAL *pHalList[{manager_list_field.group(1)}];
}} OBJHALMGR;

{chip_table}

static OBJHALMGR *active_manager;
static unsigned registration_calls;
static unsigned char registration_tokens[HAL_IMPL_MAXIMUM];

{registration_stubs}

{registration_functions}

{halmgr_functions}

#define PMC_BOOT42(architecture, implementation) \\
    (DRF_NUM(_PMC, _BOOT_42, _ARCHITECTURE, (architecture)) | \\
     DRF_NUM(_PMC, _BOOT_42, _IMPLEMENTATION, (implementation)))

_Static_assert(sizeof(((OBJHALMGR *)0)->pHalList) / sizeof(((OBJHALMGR *)0)->pHalList[0])
               == HAL_IMPL_MAXIMUM, "generated enum and manager slots diverged");
_Static_assert(sizeof(chipID) / sizeof(chipID[0]) == HAL_IMPL_MAXIMUM,
               "generated enum and chip table diverged");

int main(void)
{{
    OBJHALMGR manager = {{0}};
    NvU32 selected = 0xa55aa55aU;
    NV_STATUS status;

    active_manager = &manager;
    status = REGISTER_ALL_HALS();
    assert(status == NV_OK);
    assert(registration_calls == {len(registration_symbols)}U);
    assert(manager.pHalList[HAL_IMPL_GV100] == NULL);
    assert(chipID[HAL_IMPL_GV100].arch == 0U);
    assert(chipID[HAL_IMPL_GV100].impl == 0U);

    status = halmgrGetHalForGpu_IMPL(
        &manager, 0U,
        PMC_BOOT42(NV_PMC_BOOT_42_ARCHITECTURE_GV100,
                   NV_PMC_BOOT_42_IMPLEMENTATION_0),
        &selected);
    assert(status == NV_ERR_NOT_SUPPORTED);
    assert(selected == 0xa55aa55aU);

    selected = 0U;
    status = halmgrGetHalForGpu_IMPL(
        &manager, 0U,
        PMC_BOOT42(NV_PMC_BOOT_42_ARCHITECTURE_TU100,
                   NV_PMC_BOOT_42_IMPLEMENTATION_2),
        &selected);
    assert(status == NV_OK && selected == HAL_IMPL_TU102);

    selected = 0U;
    status = halmgrGetHalForGpu_IMPL(
        &manager, 0U,
        PMC_BOOT42(NV_PMC_BOOT_42_ARCHITECTURE_GB200,
                   NV_PMC_BOOT_42_IMPLEMENTATION_2),
        &selected);
    assert(status == NV_OK && selected == HAL_IMPL_GB202);

    selected = 0U;
    status = halmgrGetHalForGpu_IMPL(
        &manager, 0U,
        PMC_BOOT42(NV_PMC_BOOT_42_ARCHITECTURE_GB200,
                   NV_PMC_BOOT_42_IMPLEMENTATION_3),
        &selected);
    assert(status == NV_OK && selected == HAL_IMPL_GB203);

    manager.pHalList[HAL_IMPL_TU102] = NULL;
    selected = 0x13579bdfU;
    status = halmgrGetHalForGpu_IMPL(
        &manager, 0U,
        PMC_BOOT42(NV_PMC_BOOT_42_ARCHITECTURE_TU100,
                   NV_PMC_BOOT_42_IMPLEMENTATION_2),
        &selected);
    assert(status == NV_ERR_NOT_SUPPORTED);
    assert(selected == 0x13579bdfU);

    printf("PASS: OpenRM {version}; REGISTER_ALL_HALS invoked %u stubs; "
           "GV100 unsupported; TU102/GB202/GB203 matched; null slot rejected\\n",
           registration_calls);
    return 0;
}}
'''
    return source, len(registration_symbols)


def run_release(input_item):
    """Compile and execute one exact release; return report-ready evidence."""
    version, filename, prefix, expected_sha256 = input_item
    with tempfile.TemporaryDirectory(prefix=f"openrm-hal-lookup-{version}-") as directory:
        root = Path(directory)
        release = _archive_sources(
            version, filename, prefix, expected_sha256, root / "include-root"
        )
        translation_unit, registration_count = _prepare_translation_unit(
            release["texts"], version
        )
        c_file = root / "legacy_hal_lookup.c"
        executable = root / "legacy_hal_lookup"
        c_file.write_text(translation_unit)
        include_root = root / "include-root"
        include = include_root / "src/common/sdk/nvidia/inc"
        published = include_root / "src/common/inc/swref/published"
        compile_command = [
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-Wno-old-style-declaration", "-Wno-unused-parameter",
            "-DNVTYPES_USE_STDINT=1", f"-I{include}", f"-I{published}",
            str(c_file), "-o", str(executable),
        ]
        compile_result = subprocess.run(
            compile_command, capture_output=True, text=True, timeout=60
        )
        if compile_result.returncode != 0:
            raise RuntimeError(
                f"{version} compile failed:\n{compile_result.stdout}{compile_result.stderr}"
            )
        executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
        run_result = subprocess.run(
            [str(executable)], capture_output=True, text=True, timeout=30
        )
        if run_result.returncode != 0:
            raise RuntimeError(
                f"{version} execution failed:\n{run_result.stdout}{run_result.stderr}"
            )
        if f"OpenRM {version};" not in run_result.stdout:
            raise RuntimeError(f"{version} executable output does not identify its profile")
        if f"invoked {registration_count} stubs" not in run_result.stdout:
            raise RuntimeError(f"{version} executable reported the wrong registration count")
        return {
            "version": version,
            "repository_tag": release["repository_tag"],
            "repository_commit": release["repository_commit"],
            "archive": release["archive"],
            "archive_sha256": release["archive_sha256"],
            "source_sha256": release["source_sha256"],
            "include_file_count": release["include_file_count"],
            "registration_stubs": registration_count,
            "compile_command": "cc -std=c11 -Wall -Wextra -Werror -Wno-old-style-declaration -Wno-unused-parameter -DNVTYPES_USE_STDINT=1",
            "translation_unit_sha256": hashlib.sha256(translation_unit.encode("utf-8")).hexdigest(),
            "executable_sha256": executable_sha256,
            "result_stdout": run_result.stdout.strip(),
            "result": "pass",
            "observable_checks": [
                "REGISTER_ALL_HALS invoked every generated registration stub",
                "GV100 lookup returned NV_ERR_NOT_SUPPORTED and preserved output",
                "TU102, GB202, and GB203 resolved to stock generated HAL enum slots",
                "a registered-but-null TU102 slot was rejected without changing output",
            ],
        }


class OpenRmLegacyHalLookupTests(unittest.TestCase):
    def test_exact_registration_and_lookup_paths_for_all_pinned_releases(self):
        self.assertEqual(
            {item[0] for item in INPUTS},
            {"580.196.07", "580.178.04", "595.104.02", "595.112.07", "610.57.04",
             "615.71.10", "615.78.08"},
        )
        for version, filename, prefix, expected_sha256 in INPUTS:
            with self.subTest(release=version):
                result = run_release((version, filename, prefix, expected_sha256))
                self.assertEqual(result["version"], version)
                self.assertEqual(result["result"], "pass")


class ArchiveMemberPathTests(unittest.TestCase):
    def test_selected_member_path_rejects_traversal_and_absolute_names(self):
        for name in (
            "fixture-root/../escape.h",
            "fixture-root/src/common/../../escape.h",
            "/fixture-root/src/common/sdk/nvidia/inc/nvtypes.h",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                _safe_relative_member(name, "fixture-root")

    def test_member_outside_exact_archive_root_is_not_selected(self):
        self.assertIsNone(
            _safe_relative_member("other-root/src/common/inc/nv_ref.h", "fixture-root")
        )


if __name__ == "__main__":
    unittest.main()
