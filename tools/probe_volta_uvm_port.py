#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare/build an isolated R580 Volta UVM overlay against an R595 source tree.

The tool copies its target tree to a new scratch path and never installs or loads
modules. A failed module build is recorded as evidence and returned as status 2.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_R595_SOURCE = Path("/usr/src/nvidia-595.99.02")
R580_SOURCE_ROOT = "NVIDIA-kernel-module-source-580.178.04"
DEFAULT_EXPECTED_R580_ARCHIVE_SHA256 = (
    "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
)
VOLTA_FILES = (
    "uvm_volta.c",
    "uvm_volta_ce.c",
    "uvm_volta_fault_buffer.c",
    "uvm_volta_fault_buffer.h",
    "uvm_volta_host.c",
    "uvm_volta_mmu.c",
)
DEPENDENCY_FILES = (
    "clc3b5.h",
    "clc36f.h",
    "hwref/volta/gv100/dev_fault.h",
    "hwref/volta/gv100/dev_fb.h",
    "hwref/volta/gv100/dev_mmu.h",
)
PASCAL_MMU_FILE = "uvm_pascal_mmu.c"
PASCAL_MMU_DEPENDENCY_FILES = (
    "uvm_pascal_fault_buffer.h",
    "hwref/pascal/gp100/dev_fault.h",
    "hwref/pascal/gp100/dev_fb.h",
    "hwref/pascal/gp100/dev_mmu.h",
)
CALLBACK_ANCESTRY_FILES = (
    "uvm_maxwell.c",
    "uvm_maxwell_access_counter_buffer.c",
    "uvm_maxwell_ce.c",
    "uvm_maxwell_fault_buffer.c",
    "uvm_maxwell_host.c",
    "uvm_maxwell_mmu.c",
    "uvm_maxwell_sec2.c",
    "uvm_pascal.c",
    "uvm_pascal_ce.c",
    "uvm_pascal_host.c",
    "uvm_pascal_fault_buffer.c",
)
CALLBACK_ANCESTRY_DEPENDENCY_FILES = (
    "cla16f.h",
    "clb06f.h",
    "clb0b5.h",
    "clc0b5.h",
    "clc06f.h",
    "uvm_pascal_fault_buffer.h",
    "hwref/pascal/gp100/dev_fault.h",
    "hwref/pascal/gp100/dev_fb.h",
    "hwref/pascal/gp100/dev_mmu.h",
    "hwref/maxwell/gm107/dev_mmu.h",
)
RESTORABLE_HAL_DISPATCH_LINEAGES = {
    "ce_table": (
        "MAXWELL_DMA_COPY_A", "PASCAL_DMA_COPY_A",
        "PASCAL_DMA_COPY_B", "VOLTA_DMA_COPY_A",
    ),
    "host_table": (
        "KEPLER_CHANNEL_GPFIFO_B", "MAXWELL_CHANNEL_GPFIFO_A",
        "PASCAL_CHANNEL_GPFIFO_A", "VOLTA_CHANNEL_GPFIFO_A",
    ),
    "arch_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
    "fault_buffer_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
    "access_counter_buffer_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
    "sec2_table": (
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM200",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100",
        "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100",
    ),
}
ANCESTOR_ARCH_PROPERTIES = {
    "uvm_maxwell.c": "uvm_hal_maxwell_arch_init_properties",
    "uvm_pascal.c": "uvm_hal_pascal_arch_init_properties",
}
MAXWELL_MMU_CALLBACK_TABLES = {
    "unmapped_pte_maxwell": {
        "legacy_definition": (
            r"\bstatic\s+NvU64\s+unmapped_pte_maxwell\s*"
            r"\(\s*NvU64\s+page_size\s*\)\s*\{"
        ),
        "legacy_body_marker": "if (page_size == UVM_PAGE_SIZE_4K)",
        "legacy_assignment": ".unmapped_pte = unmapped_pte_maxwell,",
        "probe_assignment": ".unmapped_pte = unmapped_pte_maxwell_compile_probe_only,",
    },
    "poisoned_pte_maxwell": {
        "legacy_definition": (
            r"\bstatic\s+NvU64\s+poisoned_pte_maxwell\s*"
            r"\(\s*void\s*\)\s*\{"
        ),
        "legacy_body_marker": "make_pte_maxwell(UVM_APERTURE_VID",
        "legacy_assignment": ".poisoned_pte = poisoned_pte_maxwell,",
        "probe_assignment": ".poisoned_pte = poisoned_pte_maxwell_compile_probe_only,",
    },
}
MAXWELL_MMU_COMPILE_PROBE_WRAPPERS = """static NvU64 unmapped_pte_maxwell_compile_probe_only(void)
{
    UVM_ASSERT_MSG(0, "compile-probe-only: unsupported Maxwell MMU callback");
    return 0;
}

static NvU64 poisoned_pte_maxwell_compile_probe_only(uvm_page_tree_t *tree)
{
    (void)tree;
    UVM_ASSERT_MSG(0, "compile-probe-only: unsupported Maxwell MMU callback");
    return 0;
}
"""
MAXWELL_MMU_TABLE_ANCHOR = "static uvm_mmu_mode_hal_t maxwell_64_mmu_mode_hal"
HAL_DISPATCH_CLASS_ID_HEADERS = {
    "KEPLER_CHANNEL_GPFIFO_B": "cla16f.h",
    "MAXWELL_CHANNEL_GPFIFO_A": "clb06f.h",
    "MAXWELL_DMA_COPY_A": "clb0b5.h",
    "PASCAL_CHANNEL_GPFIFO_A": "clc06f.h",
    "PASCAL_DMA_COPY_A": "clc0b5.h",
    "PASCAL_DMA_COPY_B": "clc1b5.h",
    "VOLTA_CHANNEL_GPFIFO_A": "clc36f.h",
    "VOLTA_DMA_COPY_A": "clc3b5.h",
}
HAL_DISPATCH_ARCH_ID_HEADER = "ctrl2080mc.h"
HAL_DISPATCH_TABLE_UNIONS = {
    "ce_table": "ce_ops",
    "host_table": "host_ops",
    "arch_table": "arch_ops",
    "fault_buffer_table": "fault_buffer_ops",
    "access_counter_buffer_table": "access_counter_buffer_ops",
    "sec2_table": "sec2_ops",
}
ARCH_MMU_MODE_PROBE_ADAPTATIONS = {
    "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GM000": (
        "uvm_hal_mmu_mode_maxwell",
        "uvm_hal_mmu_mode_maxwell_compile_probe_only",
    ),
    "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100": (
        "uvm_hal_mmu_mode_pascal",
        "uvm_hal_mmu_mode_pascal_compile_probe_only",
    ),
    "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100": (
        "uvm_hal_mmu_mode_volta",
        "uvm_hal_mmu_mode_volta_compile_probe_only",
    ),
}
ARCH_MMU_MODE_PROBE_WRAPPERS = """/* Compile probe only: R615's MMU callback ABI has no page-size argument. */
static uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_maxwell_compile_probe_only(void)
{
    /* No Maxwell MMU backend is part of this Volta-only source overlay. */
    return NULL;
}

static uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_pascal_compile_probe_only(void)
{
    return uvm_hal_mmu_mode_pascal(UVM_PAGE_SIZE_64K);
}

static uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_volta_compile_probe_only(void)
{
    return uvm_hal_mmu_mode_volta(UVM_PAGE_SIZE_64K);
}
"""
R580_VOLTA_MMU_128K_REJECT_MARKER = (
    "if (big_page_size == UVM_PAGE_SIZE_128K)\n        return NULL;"
)
R615_INTERFACE_HEADER = Path("common/inc/nv_uvm_interface.h")
R615_REQUIRED_INTERFACE_DECLARATIONS = (
    "nvUvmInterfaceRegisterUvmEvents",
    "nvUvmInterfaceDeRegisterUvmEvents",
    "nvUvmInterfaceAccessBitsBufAlloc",
    "nvUvmInterfaceAccessBitsDump",
    "nvUvmInterfaceAccessBitsBufFree",
)
CALLBACK_ANCESTRY_OBJECT_SOURCES = tuple(
    name for name in CALLBACK_ANCESTRY_FILES if name.endswith(".c")
)
REMOVED_VOLTA_PROPERTY_ASSIGNMENTS = (
    "parent_gpu->tlb_batch.va_invalidate_supported = true;",
    "parent_gpu->tlb_batch.va_range_invalidate_supported = true;",
    "parent_gpu->can_map_sysmem_with_large_pages = true;",
    "parent_gpu->prefetch_fault_supported = true;",
    "parent_gpu->gpfifo_in_vidmem_supported = true;",
    "parent_gpu->replayable_faults_supported = true;",
    "parent_gpu->non_replayable_faults_supported = true;",
    "parent_gpu->fault_cancel_va_supported = true;",
    "parent_gpu->scoped_atomics_supported = true;",
    "parent_gpu->sparse_mappings_supported = true;",
    "parent_gpu->plc_supported = false;",
)
COMPILE_PROBE_SIGNATURE_ADAPTATIONS = (
    "unmapped_pte_pascal(NvU64 page_size) -> unmapped_pte_pascal(void)",
    "poisoned_pte_pascal(void) -> poisoned_pte_pascal(uvm_page_tree_t *tree)",
)
PASCAL_PREFETCH_MARKER = "static void mmu_set_prefetch_faults("
PASCAL_UNMAPPED_MARKER = "static NvU64 unmapped_pte_pascal(NvU64 page_size)"
PASCAL_MAKE_PTE_MARKER = "static NvU64 make_pte_pascal("
PASCAL_POISONED_MARKER = "static NvU64 poisoned_pte_pascal(void)"
PASCAL_HAL_TABLE_MARKER = "static uvm_mmu_mode_hal_t pascal_mmu_mode_hal"
VOLTA_OBJECT_SOURCES = tuple(
    name for name in VOLTA_FILES if name.endswith(".c")
)
SUBCHANNEL_MAPPINGS = (
    "#define UVM_SUBCHANNEL_C36F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_C3B5 UVM_SUBCHANNEL_CE",
    "#define UVM_SUBCHANNEL_A16F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_B06F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_B0B5 UVM_SUBCHANNEL_CE",
    "#define UVM_SUBCHANNEL_C06F UVM_SUBCHANNEL_HOST",
    "#define UVM_SUBCHANNEL_C0B5 UVM_SUBCHANNEL_CE",
)
PASCAL_FAULT_CLEAR_VALID_PROTOTYPE = (
    "void uvm_hal_pascal_fault_buffer_entry_clear_valid("
    "uvm_parent_gpu_t *parent_gpu, NvU32 index);"
)
PASCAL_FAULT_CLEAR_VALID_ANCHOR = (
    "void uvm_hal_turing_fault_buffer_entry_clear_valid("
    "uvm_parent_gpu_t *parent_gpu, NvU32 index);"
)
MAXWELL_LEGACY_CLEAR_NONE = "return UVM_ACCESS_COUNTER_CLEAR_OP_NONE;"
MAXWELL_COMPILE_ONLY_CLEAR_NONE = (
    "return (uvm_access_counter_clear_op_t)0; "
    "/* Compile-only: preserve the R580 NONE encoding; not an R615 semantic mapping. */"
)
CALLBACK_ANCESTOR_COMPILE_ADAPTATIONS = (
    "restore the R580 Pascal fault-buffer clear-valid prototype in the R615 HAL header;",
    "preserve the R580 unsupported-Maxwell clear-op NONE encoding as enum value 0 "
    "for compilation only; R615 interprets enum 0 as TARGETED, so runtime use is invalid",
)
ERROR_PATTERN = re.compile(
    r"(?P<file>(?:[^:\n]*/)?nvidia-uvm/[^:\n]+):(?P<line>\d+):(?P<column>\d+): "
    r"(?P<severity>fatal error|error): (?P<message>[^\n]+)"
)
MODULE_LINK_PATTERN = re.compile(
    r"^\s*(?:LD|LINK)\s+\[M\]\s+(?:\S*/)?nvidia-uvm\.ko(?:\s|$)"
)
MODULE_ACTION_PATTERN = re.compile(
    r"^\s*(?P<action>(?:CC|LD|LINK)\s+\[M\]\s+(?P<target>\S+))"
)
UVM_MODULE_ACTION_TARGETS = {
    "nvidia-uvm.o",
    "nvidia-uvm.mod.o",
    ".module-common.o",
    "nvidia-uvm.ko",
}
BUILD_DIAGNOSTIC_PATTERN = re.compile(
    r"(?i)(?:\bfatal error\b|\berror:|undefined reference|undefined symbol|"
    r"multiple definition|no rule to make target|cannot find|"
    r"make(?:\[\d+\])?: \*\*\*|\berror\s+\d+\b)"
)
NVIDIA_CONFTEST_SECTION_MARKER = "# Register the conftests needed by nvidia.ko"
NVIDIA_CONFTEST_ASSIGNMENT_PATTERN = re.compile(
    r"NV_CONFTEST_(?P<kind>FUNCTION|GENERIC|MACRO|SYMBOL|TYPE)_COMPILE_TESTS"
    r"\s*\+=\s*(?P<name>[A-Za-z0-9_]+)\s*$"
)
NVIDIA_CONFTEST_DEPENDENCY_PATTERN = re.compile(
    r"NV_OBJECTS_DEPEND_ON_CONFTEST\s*\+=\s*\$\(NVIDIA_OBJECTS\)\s*$"
)
NVIDIA_CONFTEST_REQUIRED = {
    "FUNCTION": {"ktime_get_raw_ts64", "vm_flags_set"},
    "TYPE": {"mm_has_mmap_lock"},
}
KBUILD_MODULE_INCLUDE_BLOCK = (
    "$(foreach _module, $(NV_KERNEL_MODULES), \\\n"
    " $(eval include $(src)/$(_module)/$(_module).Kbuild))"
)
NVIDIA_CONFTEST_INCLUDE_BLOCK = (
    "ifneq ($(strip $(NV_KERNEL_EXTRA_CONFTEST_KBUILD)),)\n"
    "include $(NV_KERNEL_EXTRA_CONFTEST_KBUILD)\n"
    "endif"
)
R595_BUILD_ARTIFACT_EXCLUSION_POLICY = (
    "exclude generated conftest and .tmp_versions directories",
    "exclude Module.symvers and modules.order",
    "exclude generated .o, .ko, .mod, .mod.c, and .mod.o files",
    "exclude hidden Kbuild .cmd and .d dependency files",
    "preserve source inputs including nv-kernel.o_binary",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ignore_r595_kernel_build_outputs(directory: str, names: list[str]) -> set[str]:
    """Exclude generated kernel build state while preserving NVIDIA source inputs."""
    ignored = set()
    for name in names:
        if name in {"conftest", ".tmp_versions", "Module.symvers", "modules.order"}:
            ignored.add(name)
            continue
        if name.endswith((".o", ".ko", ".mod", ".mod.c", ".mod.o")):
            ignored.add(name)
            continue
        if name.startswith(".") and name.endswith((".cmd", ".d", ".o.d")):
            ignored.add(name)
    return ignored


def stage_frontend_conftest_fragment(scratch: Path) -> dict:
    """Reuse only R595 frontend conftest declarations while linking UVM alone."""
    scratch = Path(scratch)
    source = scratch / "nvidia/nvidia.Kbuild"
    kbuild = scratch / "Kbuild"
    fragment = scratch / "nvidia-conftest-only.Kbuild"
    if source.is_symlink() or not source.is_file():
        raise ValueError("R595 NVIDIA Kbuild source is missing or is not a regular file")
    if kbuild.is_symlink() or not kbuild.is_file():
        raise ValueError("R595 root Kbuild is missing or is not a regular file")

    source_text = source.read_text(encoding="utf-8", errors="strict")
    if source_text.count(NVIDIA_CONFTEST_SECTION_MARKER) != 1:
        raise ValueError("R595 NVIDIA conftest section marker must occur exactly once")
    section = source_text.split(NVIDIA_CONFTEST_SECTION_MARKER, 1)[1]
    declarations = []
    names_by_kind: dict[str, set[str]] = {}
    counts_by_kind: dict[str, int] = {}
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if NVIDIA_CONFTEST_DEPENDENCY_PATTERN.fullmatch(stripped):
            continue
        match = NVIDIA_CONFTEST_ASSIGNMENT_PATTERN.fullmatch(stripped)
        if match is None:
            raise ValueError(
                "unsupported nvidia conftest declaration in pinned R595 Kbuild: "
                + stripped
            )
        kind = match.group("kind")
        test_name = match.group("name")
        declarations.append(stripped)
        names_by_kind.setdefault(kind, set()).add(test_name)
        counts_by_kind[kind] = counts_by_kind.get(kind, 0) + 1

    missing = {
        kind: sorted(names - names_by_kind.get(kind, set()))
        for kind, names in NVIDIA_CONFTEST_REQUIRED.items()
        if names - names_by_kind.get(kind, set())
    }
    if missing:
        raise ValueError(
            "R595 NVIDIA Kbuild lacks required frontend conftests: "
            + ", ".join(
                f"{kind}:{name}" for kind, names in sorted(missing.items()) for name in names
            )
        )
    if not declarations:
        raise ValueError("R595 NVIDIA Kbuild has no supported conftest declarations")

    fragment_text = "\n".join(declarations) + "\n"
    fragment_bytes = fragment_text.encode("utf-8")
    if fragment.is_symlink():
        raise ValueError("staged NVIDIA conftest fragment is not a regular file")
    if fragment.exists():
        if not fragment.is_file():
            raise ValueError("staged NVIDIA conftest fragment is not a regular file")
        if fragment.read_bytes() != fragment_bytes:
            raise ValueError("staged NVIDIA conftest fragment differs from current R595 source")
    else:
        fragment.write_bytes(fragment_bytes)

    kbuild_text = kbuild.read_text(encoding="utf-8", errors="strict")
    include_count = kbuild_text.count(NVIDIA_CONFTEST_INCLUDE_BLOCK)
    if include_count == 0:
        if kbuild_text.count(KBUILD_MODULE_INCLUDE_BLOCK) != 1:
            raise ValueError("R595 root Kbuild module include anchor must occur exactly once")
        kbuild_text = kbuild_text.replace(
            KBUILD_MODULE_INCLUDE_BLOCK,
            KBUILD_MODULE_INCLUDE_BLOCK + "\n\n" + NVIDIA_CONFTEST_INCLUDE_BLOCK,
            1,
        )
        kbuild.write_text(kbuild_text, encoding="utf-8")
        include_count = kbuild_text.count(NVIDIA_CONFTEST_INCLUDE_BLOCK)
    if include_count != 1:
        raise ValueError("R595 root Kbuild conftest include must occur exactly once")

    return {
        "source_path": str(source),
        "source_sha256": sha256_file(source),
        "source_section_sha256": sha256_bytes(
            (NVIDIA_CONFTEST_SECTION_MARKER + section).encode("utf-8")
        ),
        "fragment_path": str(fragment),
        "fragment_sha256": sha256_file(fragment),
        "test_count": len(declarations),
        "test_counts_by_kind": {
            kind.lower(): count for kind, count in sorted(counts_by_kind.items())
        },
        "required_tests_present": {
            kind.lower(): sorted(names)
            for kind, names in sorted(NVIDIA_CONFTEST_REQUIRED.items())
        },
        "root_kbuild_path": str(kbuild),
        "root_kbuild_sha256": sha256_file(kbuild),
        "kbuild_include_injected": True,
        "compile_modules_selected": ["nvidia-uvm"],
        "nvidia_object_declarations_copied": False,
    }


def normalize_sha256(value: str) -> str:
    value = value.lower()
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("expected R580 archive SHA-256 must contain exactly 64 hex digits")
    return value


def module_file_signature(path: Path) -> tuple | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return (stat.st_dev, stat.st_ino, stat.st_size,
            stat.st_mtime_ns, stat.st_ctime_ns)


def is_elf64_relocatable_module(path: Path) -> bool:
    """Check the kernel module's ELF64 ET_REL header and section table bounds."""
    try:
        file_size = path.stat().st_size
        with path.open("rb") as stream:
            header = stream.read(64)
    except OSError:
        return False
    if len(header) != 64 or header[:4] != b"\x7fELF":
        return False
    if header[4] != 2 or header[5] not in (1, 2) or header[6] != 1:
        return False

    byte_order = "<" if header[5] == 1 else ">"
    try:
        fields = struct.unpack(byte_order + "HHIQQQIHHHHHH", header[16:])
    except struct.error:
        return False
    (elf_type, machine, version, _entry, _phoff, section_offset, _flags,
     header_size, _phentsize, _phnum, section_entry_size, section_count,
     _string_table_index) = fields
    return (
        elf_type == 1  # ET_REL
        and machine != 0
        and version == 1
        and header_size == 64
        and section_entry_size == 64
        and section_count > 0
        and section_offset >= header_size
        and section_offset + section_entry_size * section_count <= file_size
    )


def source_archive_root(archive: tarfile.TarFile,
                        expected_root: str = R580_SOURCE_ROOT) -> str:
    suffix = "/kernel-open/nvidia-uvm/uvm_volta.c"
    matches = [member.name[:-len(suffix)] for member in archive.getmembers()
               if member.name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError("archive must contain exactly one R580 kernel-open Volta UVM tree")
    if matches[0] != expected_root:
        raise ValueError(
            f"unexpected source root {matches[0]!r}; expected {expected_root!r}"
        )
    return matches[0]


def read_member(archive: tarfile.TarFile, name: str) -> bytes:
    try:
        member = archive.getmember(name)
    except KeyError as error:
        raise ValueError(f"required R580 source is absent: {name}") from error
    if not member.isfile():
        raise ValueError(f"required R580 source is not a regular file: {name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"unable to read R580 source: {name}")
    return stream.read()


def _mask_c_comments(source: str) -> str:
    """Blank C comments without changing offsets, while preserving literals."""
    output = list(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block"
                continue
            if char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line"
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
        elif state == "block":
            if char != "\n":
                output[index] = " "
            if char == "*" and following == "/":
                output[index + 1] = " "
                index += 2
                state = "code"
                continue
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state in {"string", "char"}:
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        index += 1
    if state == "block":
        raise ValueError("unterminated C block comment in HAL source")
    return "".join(output)


def _matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    raise ValueError("unbalanced HAL table initializer")


def _matching_paren(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "(":
            depth += 1
        elif source[index] == ")":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                break
    raise ValueError("unbalanced HAL callback prototype")


def extract_hal_table_rows(source: str) -> dict[str, list[dict[str, str | None]]]:
    """Return source-preserving rows and parent IDs from UVM HAL class tables."""
    masked = _mask_c_comments(source)
    declaration = re.compile(
        r"static\s+uvm_hal_class_ops_t\s+(\w+_table)\s*\[\s*\]\s*=\s*\{"
    )
    tables: dict[str, list[dict[str, str | None]]] = {}
    for match in declaration.finditer(masked):
        name = match.group(1)
        if name in tables:
            raise ValueError(f"duplicate HAL table declaration: {name}")
        outer_open = match.end() - 1
        outer_close = _matching_brace(masked, outer_open)
        rows = []
        depth = 0
        row_start = None
        for index in range(outer_open, outer_close + 1):
            char = masked[index]
            if char == "{":
                depth += 1
                if depth == 2:
                    row_start = index
            elif char == "}":
                if depth == 2 and row_start is not None:
                    row_masked = masked[row_start:index + 1]
                    row_id = re.search(r"\.id\s*=\s*([^,]+)", row_masked)
                    parent = re.search(r"\.parent_id\s*=\s*([^,]+)", row_masked)
                    union = re.search(r"\.u\.(\w+)\s*=", row_masked)
                    if row_id is None:
                        raise ValueError(f"HAL table {name} contains a row without .id")
                    source_end = index + 1
                    while source_end < outer_close and masked[source_end].isspace():
                        source_end += 1
                    if source_end < outer_close and masked[source_end] == ",":
                        source_end += 1
                    rows.append({
                        "id": row_id.group(1).strip(),
                        "parent_id": parent.group(1).strip() if parent else None,
                        "union": union.group(1) if union else None,
                        "source": source[row_start:source_end],
                    })
                    row_start = None
                depth -= 1
        ids = [row["id"] for row in rows]
        if len(ids) != len(set(ids)):
            raise ValueError(f"HAL table {name} has duplicate row IDs")
        if not rows:
            raise ValueError(f"HAL table {name} has no initializer rows")
        tables[name] = rows
    if not tables:
        raise ValueError("no static uvm_hal_class_ops_t tables found")
    return tables


def _macro_value(source: str, macro: str) -> int:
    source = _mask_c_comments(source)
    matches = re.findall(
        rf"^\s*#\s*define\s+{re.escape(macro)}\s+\(?\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*\)?\s*$",
        source,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError(
            f"pinned R580 header must define {macro} exactly once as an integer literal"
        )
    return int(matches[0], 0)


def _dispatch_id_values(archive: tarfile.TarFile, root: str) -> dict[str, int]:
    macros = dict(HAL_DISPATCH_CLASS_ID_HEADERS)
    for macro in RESTORABLE_HAL_DISPATCH_LINEAGES["arch_table"]:
        macros[macro] = HAL_DISPATCH_ARCH_ID_HEADER
    values = {}
    for macro, header in macros.items():
        member = root + "/kernel-open/nvidia-uvm/" + header
        header_text = read_member(archive, member).decode("utf-8", "strict")
        values[macro] = _macro_value(header_text, macro)
    return values


def _extract_function_prototype(header: str, symbol: str) -> str:
    """Extract one declaration from a pinned header, excluding comments."""
    masked = _mask_c_comments(header)
    matches = list(re.finditer(rf"\b{re.escape(symbol)}\s*\(", masked))
    if len(matches) != 1:
        raise ValueError(
            f"pinned R580 UVM HAL header must declare {symbol} exactly once"
        )
    match = matches[0]
    opening = masked.find("(", match.start())
    closing = _matching_paren(masked, opening)
    semicolon = masked.find(";", closing + 1)
    brace = masked.find("{", closing + 1)
    if semicolon < 0 or (brace >= 0 and brace < semicolon):
        raise ValueError(f"pinned R580 HAL symbol is not a function prototype: {symbol}")
    start = masked.rfind(";", 0, match.start()) + 1
    prototype = re.sub(r"\s+", " ", masked[start:semicolon + 1]).strip()
    if not prototype.endswith(";") or symbol not in prototype:
        raise ValueError(f"unable to isolate pinned R580 prototype for {symbol}")
    return prototype


def _verify_r580_volta_mmu_64k_contract(source: str) -> None:
    """Require the pinned Volta callback to reject 128 KiB and derive from Pascal."""
    masked = _mask_c_comments(source)
    definition = re.search(
        r"uvm_mmu_mode_hal_t\s*\*\s*uvm_hal_mmu_mode_volta\s*"
        r"\(\s*NvU64\s+big_page_size\s*\)\s*\{",
        masked,
    )
    if definition is None:
        raise ValueError("pinned R580 Volta MMU callback definition changed")
    opening = masked.find("{", definition.start())
    closing = _matching_brace(masked, opening)
    body = masked[opening + 1:closing]
    if not re.search(
        r"UVM_ASSERT\s*\(\s*big_page_size\s*==\s*UVM_PAGE_SIZE_64K\s*\|\|\s*"
        r"big_page_size\s*==\s*UVM_PAGE_SIZE_128K\s*\)\s*;",
        body,
    ):
        raise ValueError("pinned R580 Volta MMU page-size assertion changed")
    if len(re.findall(re.escape(R580_VOLTA_MMU_128K_REJECT_MARKER), body)) != 1:
        raise ValueError("pinned R580 Volta MMU no longer rejects 128 KiB pages as expected")
    if re.search(r"uvm_hal_mmu_mode_pascal\s*\(\s*big_page_size\s*\)", body) is None:
        raise ValueError("pinned R580 Volta MMU no longer derives its mode from Pascal")


def restore_dispatch_ancestor_rows(target_hal: str,
                                   r580_hal: str,
                                   r580_hal_header: str,
                                   target_hal_header: str,
                                   id_values: dict[str, int],
                                   r580_volta_mmu: str) -> tuple[str, dict, dict, dict, dict, dict]:
    """Insert pinned R580 Volta ancestry before modern UVM dispatch rows.

    The result is deliberately only a compile probe: table compatibility does
    not validate callback semantics, object-selection behavior, or GPU runtime.
    """
    old_tables = extract_hal_table_rows(r580_hal)
    new_tables = extract_hal_table_rows(target_hal)
    _verify_r580_volta_mmu_64k_contract(r580_volta_mmu)
    restored_rows = {}
    source_row_hashes = {}
    compiled_row_hashes = {}
    callback_symbols = set()
    arch_mmu_mode_row_adaptations = {}
    for table, lineage in RESTORABLE_HAL_DISPATCH_LINEAGES.items():
        if table not in old_tables or table not in new_tables:
            raise ValueError(f"R580/R615 HAL dispatch table missing: {table}")
        old_by_id = {row["id"]: row for row in old_tables[table]}
        new_ids = {row["id"] for row in new_tables[table]}
        absent = [class_id for class_id in lineage if class_id not in old_by_id]
        if absent:
            raise ValueError(
                f"pinned R580 {table} lacks required dispatch IDs: {', '.join(absent)}"
            )
        present = [class_id for class_id in lineage if class_id in new_ids]
        if present:
            raise ValueError(
                f"R615 {table} already contains legacy dispatch rows: {', '.join(present)}"
            )
        rows = [dict(old_by_id[class_id]) for class_id in lineage]
        for index, row in enumerate(rows):
            original_row_source = row["source"]
            expected_parent = lineage[index - 1] if index else None
            if row["parent_id"] != expected_parent:
                raise ValueError(
                    f"pinned R580 {table} has unexpected parent for {row['id']}: "
                    f"{row['parent_id']!r}; expected {expected_parent!r}"
                )
            if row["union"] != HAL_DISPATCH_TABLE_UNIONS[table]:
                raise ValueError(
                    f"pinned R580 {table} row {row['id']} uses unexpected union "
                    f"{row['union']!r}"
                )
            row_masked = _mask_c_comments(row["source"])
            union_match = re.search(
                rf"\.u\.{re.escape(HAL_DISPATCH_TABLE_UNIONS[table])}\s*=\s*\{{",
                row_masked,
            )
            if union_match is None:
                raise ValueError(f"pinned R580 {table} row {row['id']} lacks its union")
            if table == "arch_table" and row["id"] in ARCH_MMU_MODE_PROBE_ADAPTATIONS:
                legacy_symbol, probe_symbol = ARCH_MMU_MODE_PROBE_ADAPTATIONS[row["id"]]
                assignment = re.compile(
                    rf"(\.mmu_mode_hal\s*=\s*){re.escape(legacy_symbol)}(\s*,)"
                )
                if len(assignment.findall(row["source"])) != 1:
                    raise ValueError(
                        "pinned R580 architecture MMU assignment changed for " + row["id"]
                    )
                row["source"] = assignment.sub(
                    rf"\g<1>{probe_symbol}\g<2>", row["source"], count=1
                )
                arch_mmu_mode_row_adaptations[row["id"]] = {
                    "legacy_symbol": legacy_symbol,
                    "compile_probe_symbol": probe_symbol,
                }
            row_masked = _mask_c_comments(row["source"])
            union_open = row_masked.find("{", union_match.start())
            union_close = _matching_brace(row_masked, union_open)
            callback_symbols.update(re.findall(
                r"\.\w+\s*=\s*([A-Za-z_]\w*)",
                row_masked[union_open + 1:union_close],
            ))
            source_row_hashes.setdefault(table, []).append(
                sha256_bytes(original_row_source.encode("utf-8"))
            )
            compiled_row_hashes.setdefault(table, []).append(
                sha256_bytes(row["source"].encode("utf-8"))
            )
        declaration = re.compile(
            rf"static\s+uvm_hal_class_ops_t\s+{re.escape(table)}\s*\[\s*\]\s*=\s*\{{"
        )
        match = declaration.search(target_hal)
        if match is None or len(declaration.findall(target_hal)) != 1:
            raise ValueError(f"R615 must contain one {table} insertion point")
        insert_at = match.end()
        insertion = "\n" + "\n".join(row["source"] for row in rows) + "\n"
        target_hal = target_hal[:insert_at] + insertion + target_hal[insert_at:]
        restored_rows[table] = list(lineage)

    first_table = re.search(
        r"static\s+uvm_hal_class_ops_t\s+ce_table\s*\[\s*\]\s*=\s*\{",
        target_hal,
    )
    if first_table is None:
        raise ValueError("R615 ce_table lacks the class-ID compatibility insertion point")
    macro_guard_lines = [
        "/* R580.178.04 class IDs, inserted only for the isolated dispatch compile probe. */"
    ]
    for macro, value in sorted(id_values.items()):
        macro_guard_lines.extend((
            f"#ifndef {macro}",
            f"#define {macro} 0x{value:08X}",
            f"#elif {macro} != 0x{value:08X}",
            f'#error "R580/R615 class ID mismatch: {macro}"',
            "#endif",
        ))
    macro_block = "\n".join(macro_guard_lines) + "\n\n"
    callback_symbols.discard("NULL")
    callback_symbols.update((
        "uvm_hal_mmu_mode_pascal",
        "uvm_hal_mmu_mode_volta",
    ))
    internal_wrapper_symbols = {
        probe_symbol for _, probe_symbol in ARCH_MMU_MODE_PROBE_ADAPTATIONS.values()
    }
    declared_in_target = {
        symbol for symbol in callback_symbols
        if (symbol in internal_wrapper_symbols or
            re.search(rf"\b{re.escape(symbol)}\s*\(", target_hal_header) is not None)
    }
    prototype_map = {}
    for symbol in sorted(callback_symbols - declared_in_target):
        prototype_map[symbol] = _extract_function_prototype(r580_hal_header, symbol)
    prototype_block = (
        "/* R580.178.04 callbacks absent from R615 declarations; compile probe only. */\n" +
        "\n".join(prototype_map.values()) + "\n\n"
        if prototype_map else ""
    )
    wrapper_block = ARCH_MMU_MODE_PROBE_WRAPPERS + "\n"
    macro_block = prototype_block + wrapper_block + macro_block
    insertion_point = first_table.start()
    target_hal = target_hal[:insertion_point] + macro_block + target_hal[insertion_point:]
    return target_hal, restored_rows, source_row_hashes, compiled_row_hashes, {
        "added_symbols": sorted(prototype_map),
        "prototype_sha256": {
            symbol: sha256_bytes(prototype.encode("utf-8"))
            for symbol, prototype in sorted(prototype_map.items())
        },
        "compile_probe_only": True,
    }, {
        "compile_probe_only": True,
        "row_adaptations": arch_mmu_mode_row_adaptations,
        "maxwell": "unsupported callback returns NULL",
        "pascal": "legacy callback fixed to UVM_PAGE_SIZE_64K",
        "volta": "legacy callback fixed to UVM_PAGE_SIZE_64K",
        "volta_128k_supported": False,
        "volta_128k_rejection_source_verified": True,
    }


def replace_source_region(source: str,
                          start_marker: str,
                          end_marker: str,
                          replacement: str,
                          label: str) -> str:
    if source.count(start_marker) != 1 or source.count(end_marker) != 1:
        raise ValueError(f"R580 Pascal MMU source has unexpected {label} boundaries")
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    if end <= start:
        raise ValueError(f"R580 Pascal MMU source has reversed {label} boundaries")
    return source[:start] + replacement + "\n\n" + source[end:]


def _matching_c_brace(source: str, opening: int) -> int:
    """Find a C closing brace while skipping comments and quoted literals."""
    depth = 0
    index = opening
    state = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "*":
                state = "block"
                index += 2
                continue
            if char == "/" and next_char == "/":
                state = "line"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
                if depth < 0:
                    break
        elif state == "block":
            if char == "*" and next_char == "/":
                state = "code"
                index += 2
                continue
        elif state == "line":
            if char == "\n":
                state = "code"
        elif state in {"string", "char"}:
            if char == "\\":
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        index += 1
    raise ValueError("unbalanced C function body in pinned R580 source")


def replace_compile_probe_ancestor_callback(source: str, symbol: str) -> tuple[str, str]:
    """Trap an architecture callback whose R580 capability ABI was removed in R615."""
    pattern = re.compile(
        rf"\bvoid\s+{re.escape(symbol)}\s*\(\s*uvm_parent_gpu_t\s*\*\s*parent_gpu\s*\)\s*\{{"
    )
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise ValueError(f"pinned R580 callback definition changed: {symbol}")
    match = matches[0]
    opening = match.end() - 1
    closing = _matching_c_brace(source, opening)
    original_body = source[opening + 1:closing]
    legacy_fields = sorted(set(re.findall(r"parent_gpu->([A-Za-z_][A-Za-z0-9_.]*)", original_body)))
    if not legacy_fields:
        raise ValueError(f"pinned R580 callback has no expected legacy properties: {symbol}")
    replacement_body = (
        "\n    (void)parent_gpu;\n"
        "    UVM_ASSERT_MSG(0, \"compile-probe-only: unsupported R580 ancestor callback\");\n"
    )
    adapted = source[:opening + 1] + replacement_body + source[closing:]
    return adapted, "\n".join(legacy_fields)


def adapt_maxwell_mmu_callback_tables(source: str) -> tuple[str, list[dict]]:
    """Redirect Maxwell MMU table slots to fail-fast R615 ABI compile wrappers.

    The original R580 functions and their internal calls remain unchanged. Only
    the function pointers in the two Maxwell mode tables are redirected. These
    Maxwell modes are not a supported runtime path in this Volta-only probe.
    """
    adapted = source
    adaptations = []
    for symbol, spec in MAXWELL_MMU_CALLBACK_TABLES.items():
        definitions = list(re.finditer(spec["legacy_definition"], adapted))
        if len(definitions) != 1:
            raise ValueError(f"pinned R580 Maxwell MMU definition changed: {symbol}")
        match = definitions[0]
        closing = _matching_c_brace(adapted, match.end() - 1)
        original_definition = adapted[match.start():closing + 1]
        body = adapted[match.end():closing]
        if body.count(spec["legacy_body_marker"]) != 1:
            raise ValueError(f"pinned R580 Maxwell MMU body changed: {symbol}")
        if adapted.count(spec["legacy_assignment"]) != 2:
            raise ValueError(
                f"pinned R580 Maxwell MMU table must contain exactly two {symbol} assignments"
            )
        adapted = adapted.replace(
            spec["legacy_assignment"], spec["probe_assignment"]
        )
        adaptations.append({
            "symbol": symbol,
            "original_definition_sha256": sha256_bytes(
                original_definition.encode("utf-8")
            ),
            "probe_wrapper_sha256": sha256_bytes(
                MAXWELL_MMU_COMPILE_PROBE_WRAPPERS.encode("utf-8")
            ),
            "redirected_table_slots": 2,
            "legacy_definition_preserved": True,
            "compile_probe_only": True,
        })
    if adapted.count(MAXWELL_MMU_TABLE_ANCHOR) != 1:
        raise ValueError("pinned R580 Maxwell MMU table insertion point changed")
    adapted = adapted.replace(
        MAXWELL_MMU_TABLE_ANCHOR,
        MAXWELL_MMU_COMPILE_PROBE_WRAPPERS + "\n" + MAXWELL_MMU_TABLE_ANCHOR,
        1,
    )
    return adapted, adaptations


def prepare_overlay(archive_path: Path,
                    r595_source: Path,
                    scratch: Path,
                    *,
                    expected_archive_sha256: str,
                    expected_source_root: str = R580_SOURCE_ROOT,
                    compile_probe_adapter: bool = False,
                    restore_callback_ancestors: bool = False,
                    restore_dispatch_ancestors: bool = False) -> dict:
    archive_path = Path(archive_path).resolve(strict=True)
    r595_source = Path(r595_source).resolve(strict=True)
    scratch = Path(scratch).resolve()
    if not archive_path.is_file():
        raise ValueError(f"R580 source archive is not a regular file: {archive_path}")
    expected_archive_sha256 = normalize_sha256(expected_archive_sha256)
    archive_sha256 = sha256_file(archive_path)
    if archive_sha256 != expected_archive_sha256:
        raise ValueError(
            "R580 source archive SHA-256 mismatch: "
            f"got {archive_sha256}, expected {expected_archive_sha256}"
        )
    if not r595_source.is_dir():
        raise ValueError(f"R595 source root is not a directory: {r595_source}")
    if restore_callback_ancestors and not compile_probe_adapter:
        raise ValueError("restoring callback ancestors requires the compile-probe adapter")
    if restore_dispatch_ancestors and not restore_callback_ancestors:
        raise ValueError(
            "restoring dispatch ancestors requires the callback ancestors and compile-probe adapter"
        )
    if scratch.exists():
        raise FileExistsError(f"refusing to overwrite existing scratch tree: {scratch}")

    source_list = r595_source / "nvidia-uvm/nvidia-uvm-sources.Kbuild"
    push_macros = r595_source / "nvidia-uvm/uvm_push_macros.h"
    if not source_list.is_file() or not push_macros.is_file():
        raise ValueError("R595 source root is missing expected nvidia-uvm build files")
    preserved_target_interfaces = []
    if restore_callback_ancestors:
        target_interface = r595_source / R615_INTERFACE_HEADER
        if not target_interface.is_file():
            raise ValueError(
                f"R615 source tree is missing {R615_INTERFACE_HEADER.as_posix()}"
            )
        interface_text = target_interface.read_text(encoding="utf-8", errors="replace")
        missing_declarations = [
            name for name in R615_REQUIRED_INTERFACE_DECLARATIONS
            if re.search(rf"\b{re.escape(name)}\s*\(", interface_text) is None
        ]
        if missing_declarations:
            raise ValueError(
                "R615 UVM interface header is missing required declarations: "
                + ", ".join(missing_declarations)
            )
        preserved_target_interfaces.append({
            "path": R615_INTERFACE_HEADER.as_posix(),
            "sha256": sha256_file(target_interface),
            "required_declarations": list(R615_REQUIRED_INTERFACE_DECLARATIONS),
        })

    with tarfile.open(archive_path, "r:*") as archive:
        root = source_archive_root(archive, expected_source_root)
        license_text = read_member(archive, root + "/COPYING").decode("utf-8", "replace")
        license_text_detected = "licensed as MIT" in license_text
        if not license_text_detected:
            raise ValueError("R580 archive COPYING is missing the expected MIT license text marker")
        r580_push_macros = read_member(
            archive, root + "/kernel-open/nvidia-uvm/uvm_push_macros.h"
        ).decode("utf-8", "replace")
        for mapping in SUBCHANNEL_MAPPINGS:
            if r580_push_macros.count(mapping) != 1:
                raise ValueError(f"R580 source does not contain expected mapping: {mapping}")

        overlay_files = {}
        required_files = VOLTA_FILES + DEPENDENCY_FILES
        if compile_probe_adapter:
            required_files += (PASCAL_MMU_FILE,) + PASCAL_MMU_DEPENDENCY_FILES
        if restore_callback_ancestors:
            required_files += CALLBACK_ANCESTRY_FILES + CALLBACK_ANCESTRY_DEPENDENCY_FILES
        required_files = tuple(dict.fromkeys(required_files))
        for relative in required_files:
            archive_relative = "kernel-open/nvidia-uvm/" + relative
            member_name = root + "/" + archive_relative
            overlay_files[relative] = read_member(archive, member_name)
        r580_hal_source = None
        r580_hal_header = None
        dispatch_id_values = None
        if restore_dispatch_ancestors:
            r580_hal_source = read_member(
                archive, root + "/kernel-open/nvidia-uvm/uvm_hal.c"
            ).decode("utf-8", "strict")
            r580_hal_header = read_member(
                archive, root + "/kernel-open/nvidia-uvm/uvm_hal.h"
            ).decode("utf-8", "strict")
            dispatch_id_values = _dispatch_id_values(archive, root)

    compatibility_pruned_assignments = []
    legacy_prefetch_assertion_removed = False
    callback_ancestor_compile_adaptations = []
    stubbed_callback_parent_properties = []
    stubbed_maxwell_mmu_callbacks = []
    restored_dispatch_rows = {}
    restored_dispatch_row_hashes = {}
    restored_dispatch_compile_row_hashes = {}
    dispatch_callback_prototypes = {}
    dispatch_arch_mmu_mode_adaptations = {}
    if compile_probe_adapter:
        pascal_source = overlay_files[PASCAL_MMU_FILE].decode("utf-8")
        if pascal_source.count(PASCAL_PREFETCH_MARKER) != 1:
            raise ValueError("R580 Pascal MMU source has an unexpected prefetch section")
        if restore_callback_ancestors:
            legacy_assertion = "UVM_ASSERT(parent_gpu->prefetch_fault_supported);"
            if pascal_source.count(legacy_assertion) != 1:
                raise ValueError("R580 Pascal MMU prefetch capability assertion changed")
            pascal_source = pascal_source.replace(
                legacy_assertion,
                "/* Compile-only adapter: R615 has no legacy capability field. */",
                1,
            )
            legacy_prefetch_assertion_removed = True
        else:
            # The basic probe uses only the MMU mode HAL. Excluding the later
            # Pascal prefetch implementation avoids an unrelated removed field.
            pascal_source = pascal_source.split(PASCAL_PREFETCH_MARKER, 1)[0].rstrip() + "\n"
        pascal_source = replace_source_region(
            pascal_source,
            PASCAL_UNMAPPED_MARKER,
            PASCAL_MAKE_PTE_MARKER,
            """static NvU64 unmapped_pte_pascal(void)
{
    // Compile-probe shim copied from the modern MMU HAL contract. It is not a
    // validated GV100 choice for all Volta page sizes.
    return HWCONST64(_MMU_VER2, PTE, VALID, FALSE) |
           HWCONST64(_MMU_VER2, PTE, VOL, FALSE) |
           HWCONST64(_MMU_VER2, PTE, PRIVILEGE, TRUE);
}""",
            "unmapped PTE callback",
        )
        pascal_source = replace_source_region(
            pascal_source,
            PASCAL_POISONED_MARKER,
            PASCAL_HAL_TABLE_MARKER,
            """static NvU64 poisoned_pte_pascal(uvm_page_tree_t *tree)
{
    NvU64 phys_addr = 0x1bad000000ULL;
    NvU64 pte_bits = tree->hal->make_pte(UVM_APERTURE_VID,
                                         phys_addr,
                                         UVM_PROT_READ_ONLY,
                                         UVM_MMU_PTE_FLAGS_NONE);
    return WRITE_HWCONST64(pte_bits, _MMU_VER2, PTE, PRIVILEGE, TRUE);
}""",
            "poisoned PTE callback",
        )
        overlay_files[PASCAL_MMU_FILE] = pascal_source.encode("utf-8")
        volta_text = overlay_files["uvm_volta.c"].decode("utf-8")
        for assignment in REMOVED_VOLTA_PROPERTY_ASSIGNMENTS:
            if volta_text.count(assignment) != 1:
                raise ValueError(
                    "expected exactly one obsolete Volta property assignment: " + assignment
                )
            volta_text = volta_text.replace(assignment, "", 1)
            compatibility_pruned_assignments.append(assignment)
        overlay_files["uvm_volta.c"] = volta_text.encode("utf-8")
        if restore_callback_ancestors:
            maxwell_host = overlay_files["uvm_maxwell_host.c"].decode("utf-8")
            if maxwell_host.count(MAXWELL_LEGACY_CLEAR_NONE) != 1:
                raise ValueError(
                    "R580 Maxwell host source has an unexpected legacy NONE return"
                )
            maxwell_host = maxwell_host.replace(
                MAXWELL_LEGACY_CLEAR_NONE, MAXWELL_COMPILE_ONLY_CLEAR_NONE, 1
            )
            overlay_files["uvm_maxwell_host.c"] = maxwell_host.encode("utf-8")
            for relative, symbol in ANCESTOR_ARCH_PROPERTIES.items():
                original = overlay_files[relative].decode("utf-8", "strict")
                adapted, legacy_fields = replace_compile_probe_ancestor_callback(
                    original, symbol
                )
                overlay_files[relative] = adapted.encode("utf-8")
                stubbed_callback_parent_properties.append({
                    "source": relative,
                    "symbol": symbol,
                    "original_source_sha256": sha256_bytes(original.encode("utf-8")),
                    "adapted_source_sha256": sha256_bytes(adapted.encode("utf-8")),
                    "legacy_property_members": legacy_fields.splitlines(),
                    "adaptation": "fail-fast assertion; R615 removed the R580 property ABI",
                    "compile_probe_only": True,
                })
            maxwell_mmu_original = overlay_files["uvm_maxwell_mmu.c"].decode(
                "utf-8", "strict"
            )
            maxwell_mmu, stubbed_maxwell_mmu_callbacks = (
                adapt_maxwell_mmu_callback_tables(maxwell_mmu_original)
            )
            for record in stubbed_maxwell_mmu_callbacks:
                record.update({
                    "source": "uvm_maxwell_mmu.c",
                    "original_source_sha256": sha256_bytes(
                        maxwell_mmu_original.encode("utf-8")
                    ),
                    "adapted_source_sha256": sha256_bytes(
                        maxwell_mmu.encode("utf-8")
                    ),
                    "adaptation": "redirect R615-incompatible table slots to fail-fast wrappers; retain original R580 functions and internal calls",
                })
            overlay_files["uvm_maxwell_mmu.c"] = maxwell_mmu.encode("utf-8")
            callback_ancestor_compile_adaptations.extend(
                CALLBACK_ANCESTOR_COMPILE_ADAPTATIONS
            )
            callback_ancestor_compile_adaptations.append(
                "replace Maxwell/Pascal architecture-property callbacks with fail-fast compile-only stubs; the GV100 row overrides the inherited callback"
            )
            callback_ancestor_compile_adaptations.append(
                "redirect only Maxwell MMU table slots to fail-fast R615-signature wrappers; preserve the original page-size-aware R580 functions"
            )

    shutil.copytree(r595_source, scratch, ignore=ignore_r595_kernel_build_outputs)
    try:
        target_sources = scratch / "nvidia-uvm/nvidia-uvm-sources.Kbuild"
        source_text = target_sources.read_text()
        source_anchor = "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n"
        if source_text.count(source_anchor) != 1:
            raise ValueError("R595 UVM source-list anchor must occur exactly once")
        if any(f"NVIDIA_UVM_SOURCES += nvidia-uvm/{name}" in source_text
               for name in VOLTA_OBJECT_SOURCES):
            raise ValueError("R595 source list already contains one or more Volta sources")
        callback_ancestor_sources = (
            CALLBACK_ANCESTRY_OBJECT_SOURCES if restore_callback_ancestors else ()
        )
        if any(f"NVIDIA_UVM_SOURCES += nvidia-uvm/{name}" in source_text
               for name in callback_ancestor_sources):
            raise ValueError("R595 source list already contains one or more callback ancestors")
        source_entries = "".join(
            f"NVIDIA_UVM_SOURCES += nvidia-uvm/{name}\n"
            for name in VOLTA_OBJECT_SOURCES + callback_ancestor_sources
        )
        if compile_probe_adapter:
            pascal_entry = f"NVIDIA_UVM_SOURCES += nvidia-uvm/{PASCAL_MMU_FILE}\n"
            if pascal_entry in source_text:
                raise ValueError("R595 source list already contains the Pascal MMU source")
            source_entries += pascal_entry
        target_sources.write_text(source_text.replace(
            source_anchor, source_anchor + source_entries
        ))

        target_macros = scratch / "nvidia-uvm/uvm_push_macros.h"
        macro_text = target_macros.read_text()
        macro_anchor = "#define UVM_SUBCHANNEL_SEC2 NVA06F_SUBCHANNEL_COMPUTE\n"
        if macro_text.count(macro_anchor) != 1:
            raise ValueError("R595 UVM subchannel anchor must occur exactly once")
        if any(mapping.split()[1] in macro_text for mapping in SUBCHANNEL_MAPPINGS):
            raise ValueError("R595 source already contains one or more Volta subchannel maps")
        target_macros.write_text(macro_text.replace(
            macro_anchor, macro_anchor + "\n".join(SUBCHANNEL_MAPPINGS) + "\n"
        ))

        if compile_probe_adapter:
            hal_header = scratch / "nvidia-uvm/uvm_hal.h"
            hal_text = hal_header.read_text()
            hal_anchor = "uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_turing(void);\n"
            if hal_text.count(hal_anchor) != 1:
                raise ValueError("R595 UVM HAL header lacks its Turing MMU declaration anchor")
            pascal_prototype = "uvm_mmu_mode_hal_t *uvm_hal_mmu_mode_pascal(NvU64 big_page_size);\n"
            if pascal_prototype in hal_text:
                raise ValueError("R595 UVM HAL header already declares the Pascal MMU helper")
            hal_header.write_text(hal_text.replace(
                hal_anchor, pascal_prototype + hal_anchor
            ))

            if restore_callback_ancestors:
                hal_text = hal_header.read_text()
                if PASCAL_FAULT_CLEAR_VALID_PROTOTYPE in hal_text:
                    raise ValueError(
                        "R615 HAL header already declares the legacy Pascal helper"
                    )
                if hal_text.count(PASCAL_FAULT_CLEAR_VALID_ANCHOR) != 1:
                    raise ValueError(
                        "R615 HAL header lacks the Turing fault-clear prototype anchor"
                    )
                hal_header.write_text(hal_text.replace(
                    PASCAL_FAULT_CLEAR_VALID_ANCHOR,
                    PASCAL_FAULT_CLEAR_VALID_PROTOTYPE + "\n" +
                    PASCAL_FAULT_CLEAR_VALID_ANCHOR,
                ))

        copied = {}
        for relative, data in overlay_files.items():
            destination = scratch / "nvidia-uvm" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            copied[relative] = sha256_bytes(data)
        if restore_dispatch_ancestors:
            if (r580_hal_source is None or r580_hal_header is None or
                    dispatch_id_values is None):
                raise ValueError("pinned R580 HAL dispatch source or class IDs are unavailable")
            target_hal_path = scratch / "nvidia-uvm/uvm_hal.c"
            target_hal_text = target_hal_path.read_text(encoding="utf-8", errors="strict")
            target_hal_header_path = scratch / "nvidia-uvm/uvm_hal.h"
            (target_hal_text, restored_dispatch_rows, restored_dispatch_row_hashes,
             restored_dispatch_compile_row_hashes, dispatch_callback_prototypes,
             dispatch_arch_mmu_mode_adaptations) = (
                restore_dispatch_ancestor_rows(
                    target_hal_text,
                    r580_hal_source,
                    r580_hal_header,
                    target_hal_header_path.read_text(encoding="utf-8", errors="strict"),
                    dispatch_id_values,
                    overlay_files["uvm_volta_mmu.c"].decode("utf-8", "strict"),
                )
            )
            target_hal_path.write_text(target_hal_text)
    except Exception:
        # A failed preparation is kept for diagnosis; no existing path is removed.
        raise

    return {
        "r580_source_root": root,
        "r580_source_archive": str(archive_path),
        "r580_archive_sha256": archive_sha256,
        "expected_r580_archive_sha256": expected_archive_sha256,
        "archive_sha256_matches_expected": True,
        "r595_source": str(r595_source),
        "scratch": str(scratch),
        "build_artifact_exclusion_policy": list(R595_BUILD_ARTIFACT_EXCLUSION_POLICY),
        "license_text_detected": license_text_detected,
        "copied_volta_source_count": len(VOLTA_FILES),
        "copied_files_sha256": copied,
        "added_source_list_entries": list(VOLTA_OBJECT_SOURCES) + (
            [PASCAL_MMU_FILE] if compile_probe_adapter else []
        ) + list(CALLBACK_ANCESTRY_OBJECT_SOURCES if restore_callback_ancestors else ()),
        "added_callback_ancestor_sources": list(
            CALLBACK_ANCESTRY_OBJECT_SOURCES if restore_callback_ancestors else ()
        ),
        "copied_callback_ancestor_dependencies": list(
            CALLBACK_ANCESTRY_DEPENDENCY_FILES if restore_callback_ancestors else ()
        ),
        "preserved_target_interface_headers": preserved_target_interfaces,
        "callback_ancestry_compile_probe_only": restore_callback_ancestors,
        "legacy_prefetch_capability_assertion_removed": legacy_prefetch_assertion_removed,
        "added_subchannel_mappings": list(SUBCHANNEL_MAPPINGS),
        "callback_ancestor_compile_adaptations": callback_ancestor_compile_adaptations,
        "stubbed_callback_parent_properties": stubbed_callback_parent_properties,
        "stubbed_maxwell_mmu_callbacks": stubbed_maxwell_mmu_callbacks,
        "restored_dispatch_ancestor_rows": restored_dispatch_rows,
        "restored_dispatch_ancestor_row_sha256": restored_dispatch_row_hashes,
        "restored_dispatch_ancestor_compile_row_sha256": restored_dispatch_compile_row_hashes,
        "restored_dispatch_class_id_values": (
            {macro: f"0x{value:08X}" for macro, value in sorted(dispatch_id_values.items())}
            if dispatch_id_values is not None else {}
        ),
        "restored_dispatch_callback_prototypes": dispatch_callback_prototypes,
        "dispatch_arch_mmu_mode_adaptations": dispatch_arch_mmu_mode_adaptations,
        "dispatch_ancestors_compile_probe_only": restore_dispatch_ancestors,
        "compile_probe_adapter": compile_probe_adapter,
        "compatibility_pruned_assignments": compatibility_pruned_assignments,
        "compile_probe_signature_adaptations": (
            list(COMPILE_PROBE_SIGNATURE_ADAPTATIONS) if compile_probe_adapter else []
        ),
        "compile_probe_only": compile_probe_adapter,
        "runtime_semantics_validated": False,
        "loaded_or_installed": False,
    }


def resolve_frontend_module_symvers(path: Path | None,
                                    expected_sha256: str | None):
    if (path is None) != (expected_sha256 is None):
        raise ValueError(
            "frontend Module.symvers path and expected SHA-256 must be supplied together")
    if path is None:
        return None, None, None
    path = Path(path)
    if path.is_symlink():
        raise ValueError("frontend Module.symvers must not be a symlink")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError("frontend Module.symvers must be a regular file")
    if re.fullmatch(r"[0-9a-fA-F]{64}", str(expected_sha256)) is None:
        raise ValueError("expected frontend Module.symvers SHA-256 must contain 64 hex digits")
    expected_sha256 = str(expected_sha256).lower()
    actual_sha256 = sha256_file(path)
    if actual_sha256 != expected_sha256:
        raise ValueError(
            "frontend Module.symvers SHA-256 mismatch: "
            f"got {actual_sha256}, expected {expected_sha256}")
    return path, expected_sha256, actual_sha256


def build_overlay(scratch: Path, jobs: int, *, compile_probe_adapter: bool = False,
                  callback_ancestor_sources: tuple[str, ...] = (),
                  frontend_module_symvers: Path | None = None,
                  expected_frontend_symvers_sha256: str | None = None,
                  kernel_uname: str | None = None,
                  kernel_source: Path | None = None,
                  kernel_compiler: Path | None = None) -> dict:
    frontend_module_symvers, expected_frontend_symvers_sha256, symvers_before = (
        resolve_frontend_module_symvers(
            frontend_module_symvers, expected_frontend_symvers_sha256))
    log_path = scratch / "uvm-port-build.log"
    kernel_modules = "nvidia-uvm" if frontend_module_symvers else "nvidia nvidia-uvm"
    if kernel_uname is not None and re.fullmatch(r"[A-Za-z0-9._+-]+", kernel_uname) is None:
        raise ValueError("kernel release must contain only letters, digits, dot, underscore, plus, or hyphen")
    if (kernel_source is None) != (kernel_uname is None):
        raise ValueError("kernel source and release must be supplied together")
    resolved_kernel_source = None
    if kernel_source is not None:
        resolved_kernel_source = Path(kernel_source).resolve(strict=True)
        if not resolved_kernel_source.is_dir():
            raise ValueError("kernel source must resolve to a directory")
    resolved_kernel_compiler = None
    if kernel_compiler is not None:
        # Preserve a user-selected compiler symlink: Kbuild compares the
        # compiler's reported identity with CONFIG_CC_VERSION_TEXT, and
        # resolving /usr/bin/x86_64-linux-gnu-gcc to gcc-15 changes that
        # identity even though both paths invoke the same binary.
        resolved_kernel_compiler = Path(os.path.abspath(os.path.expanduser(
            os.fspath(kernel_compiler))))
        if not resolved_kernel_compiler.is_file() or not os.access(resolved_kernel_compiler, os.X_OK):
            raise ValueError("kernel compiler must name an executable file")

    command = ["make", "-C", str(scratch)]
    if kernel_uname is not None:
        command.extend((f"KERNEL_UNAME={kernel_uname}", f"SYSSRC={resolved_kernel_source}"))
    if resolved_kernel_compiler is not None:
        command.append(f"CC={resolved_kernel_compiler}")
    command.append(f"NV_KERNEL_MODULES={kernel_modules}")
    supplemental_frontend_conftests = None
    if frontend_module_symvers:
        supplemental_frontend_conftests = stage_frontend_conftest_fragment(scratch)
        command.append(f"KBUILD_EXTRA_SYMBOLS={frontend_module_symvers}")
        command.append(
            "NV_KERNEL_EXTRA_CONFTEST_KBUILD="
            + supplemental_frontend_conftests["fragment_path"]
        )
    command.extend(("modules", f"-j{jobs}"))
    module_path = scratch / "nvidia-uvm.ko"
    module_before = module_file_signature(module_path)
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    log_path.write_text(result.stdout)
    log_path.chmod(0o600)
    symvers_after = (sha256_file(frontend_module_symvers)
                     if frontend_module_symvers else None)
    frontend_symvers_record = None
    frontend_symvers_unchanged = True
    if frontend_module_symvers:
        frontend_symvers_unchanged = symvers_after == symvers_before
        frontend_symvers_record = {
            "path": str(frontend_module_symvers),
            "expected_sha256": expected_frontend_symvers_sha256,
            "sha256_before": symvers_before,
            "sha256_after": symvers_after,
            "unchanged": frontend_symvers_unchanged,
        }
    errors = [match.groupdict() for match in ERROR_PATTERN.finditer(result.stdout)]
    build_diagnostics = [
        line.strip() for line in result.stdout.splitlines()
        if BUILD_DIAGNOSTIC_PATTERN.search(line)
    ]
    build_diagnostics = list(dict.fromkeys(build_diagnostics))[:200]
    build_warnings = [
        line.strip() for line in result.stdout.splitlines()
        if re.search(r"\bwarning:", line, re.IGNORECASE)
    ]
    expected_objects = set(VOLTA_OBJECT_SOURCES)
    if compile_probe_adapter:
        expected_objects.add(PASCAL_MMU_FILE)
    expected_objects.update(callback_ancestor_sources)
    selected_object_names = {Path(name).stem for name in expected_objects}
    compiled_volta = sorted(set(re.findall(
        r"CC \[M\]\s+(?:\S*/)?(nvidia-uvm/uvm_volta(?:_[^\s]+)?\.o)", result.stdout
    )))
    compiled_port = sorted({
        object_path for object_path in re.findall(
            r"CC \[M\]\s+(?:\S*/)?(nvidia-uvm/[A-Za-z0-9_]+\.o)", result.stdout
        )
        if Path(object_path).stem in selected_object_names
    })
    compiled_objects = {
        Path(object_path).name[:-2] + ".c" for object_path in compiled_port
    }
    expected_objects_compiled = expected_objects <= compiled_objects
    linkage_trace_lines = [
        line.strip() for line in result.stdout.splitlines()
        if MODULE_LINK_PATTERN.match(line)
    ]
    unexpected_module_actions = []
    if frontend_module_symvers:
        for line in result.stdout.splitlines():
            match = MODULE_ACTION_PATTERN.match(line)
            if match is None:
                continue
            target = match.group("target")
            target_basename = Path(target).name
            target_is_uvm_source = bool(re.search(r"(?:^|/)nvidia-uvm/[^/]+$", target))
            if not (
                target_is_uvm_source
                or target_basename in UVM_MODULE_ACTION_TARGETS
            ):
                unexpected_module_actions.append(match.group("action"))
    module_exists = module_path.is_file()
    module_after = module_file_signature(module_path) if module_exists else None
    module_changed_by_build = module_after is not None and module_after != module_before
    module_elf_valid = module_exists and is_elf64_relocatable_module(module_path)
    build_command_succeeded = result.returncode == 0
    module_linked_this_run = (
        build_command_succeeded
        and bool(linkage_trace_lines)
        and module_changed_by_build
        and module_elf_valid
        and expected_objects_compiled
        and frontend_symvers_unchanged
        and not unexpected_module_actions
    )
    return {
        "command": command,
        "kernel_target": {
            "release": kernel_uname,
            "source": str(resolved_kernel_source) if resolved_kernel_source else None,
            "compiler": str(resolved_kernel_compiler) if resolved_kernel_compiler else None,
        },
        "build_exit_code": result.returncode,
        "build_command_succeeded": build_command_succeeded,
        "build_log": str(log_path),
        "build_log_sha256": sha256_file(log_path),
        "build_log_size_bytes": log_path.stat().st_size,
        "compiled_volta_objects": compiled_volta,
        "compiled_port_objects": compiled_port,
        "expected_volta_sources_compiled": sorted(expected_objects),
        "expected_port_sources_compiled": sorted(expected_objects),
        "expected_volta_sources_compiled_this_run": expected_objects_compiled,
        "expected_port_sources_compiled_this_run": expected_objects_compiled,
        "linkage_trace_found": bool(linkage_trace_lines),
        "linkage_trace_lines": linkage_trace_lines,
        "unexpected_module_actions": unexpected_module_actions,
        "module_exists": module_exists,
        "module_changed_by_build": module_changed_by_build,
        "module_elf_valid": module_elf_valid,
        "module_linked_this_run": module_linked_this_run,
        # Compatibility alias; true now has the same strict meaning.
        "module_linked": module_linked_this_run,
        "module_sha256": (
            sha256_file(module_path) if module_exists else None
        ),
        "frontend_module_symvers": frontend_symvers_record,
        "supplemental_frontend_conftests": supplemental_frontend_conftests,
        "errors": errors,
        "build_diagnostics": build_diagnostics,
        "build_warnings": build_warnings,
        "build_warning_count": len(build_warnings),
        "loaded_or_installed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", required=True, type=Path,
                        help="R580.178.04 module-source tarball")
    parser.add_argument(
        "--expected-r580-sha256",
        type=normalize_sha256,
        default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
        help="expected archive SHA-256 (defaults to the pinned R580.178.04 digest)",
    )
    parser.add_argument("--r595-source", type=Path, default=DEFAULT_R595_SOURCE,
                        help=f"R595 kernel-module source tree (default: {DEFAULT_R595_SOURCE})")
    parser.add_argument("--scratch", required=True, type=Path,
                        help="new path for a copied source tree; existing paths are refused")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--kernel-uname",
                        help="explicit target Linux release (paired with --kernel-source)")
    parser.add_argument("--kernel-source", type=Path,
                        help="explicit Linux kernel source/output tree")
    parser.add_argument("--kernel-compiler", type=Path,
                        help="explicit compiler executable for the target kernel")
    parser.add_argument("--prepare-only", action="store_true",
                        help="prepare the overlay without invoking make")
    parser.add_argument("--compile-probe-adapter", action="store_true",
                        help="also restore the Pascal MMU base and prune removed Volta capability assignments; diagnostic build only, not a semantic port")
    parser.add_argument("--restore-callback-ancestors", action="store_true",
                        help="add R580 Maxwell/Pascal HAL source ancestors to the compile-only probe; requires --compile-probe-adapter")
    parser.add_argument("--restore-dispatch-ancestors", action="store_true",
                        help="insert pinned R580 HAL inheritance rows and ID guards into R615 uvm_hal.c; compile probe only, and requires --restore-callback-ancestors")
    parser.add_argument(
        "--frontend-module-symvers", type=Path,
        help="build only nvidia-uvm against this exact frontend Module.symvers",
    )
    parser.add_argument(
        "--expected-frontend-symvers-sha256",
        help="required SHA-256 pin for --frontend-module-symvers",
    )
    parser.add_argument("--report", type=Path,
                        help="JSON report path (default: <scratch>.report.json)")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if (args.kernel_uname is None) != (args.kernel_source is None):
        parser.error("--kernel-uname and --kernel-source must be supplied together")
    if args.restore_callback_ancestors and not args.compile_probe_adapter:
        parser.error("--restore-callback-ancestors requires --compile-probe-adapter")
    if args.restore_dispatch_ancestors and not args.restore_callback_ancestors:
        parser.error("--restore-dispatch-ancestors requires --restore-callback-ancestors")
    if (args.frontend_module_symvers is None) != (
            args.expected_frontend_symvers_sha256 is None):
        parser.error(
            "--frontend-module-symvers and --expected-frontend-symvers-sha256 "
            "must be supplied together")

    try:
        report = prepare_overlay(
            args.r580_archive,
            args.r595_source,
            args.scratch,
            expected_archive_sha256=args.expected_r580_sha256,
            compile_probe_adapter=args.compile_probe_adapter,
            restore_callback_ancestors=args.restore_callback_ancestors,
            restore_dispatch_ancestors=args.restore_dispatch_ancestors,
        )
        if not args.prepare_only:
            report.update(build_overlay(
                args.scratch.resolve(), args.jobs,
                compile_probe_adapter=args.compile_probe_adapter,
                callback_ancestor_sources=(
                    CALLBACK_ANCESTRY_OBJECT_SOURCES
                    if args.restore_callback_ancestors else ()
                ),
                frontend_module_symvers=args.frontend_module_symvers,
                expected_frontend_symvers_sha256=(
                    args.expected_frontend_symvers_sha256
                ),
                kernel_uname=args.kernel_uname,
                kernel_source=args.kernel_source,
                kernel_compiler=args.kernel_compiler,
            ))
        else:
            report["build_status"] = "not-run"
        report_path = args.report or args.scratch.resolve().with_suffix(".report.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        report_path.chmod(0o600)
        print(json.dumps(report, indent=2, sort_keys=True))
        if report.get("build_command_succeeded") is False:
            return 2
        if report.get("module_linked_this_run") is False:
            return 3
        return 0
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"UVM overlay preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
