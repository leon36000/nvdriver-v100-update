#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and report the pinned R580/R595 Linux UVM payload ABI differences."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_R580 = ROOT / "build/experiments/r580-private-proprietary-build-v2-20261023/nvidia-580.178.04"
DEFAULT_R595 = ROOT / "build/experiments/r595-r580-open-fullbuild-v3-20261023/source/kernel-open"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compile_and_run(source, include_dir, compiler, define=None):
    with tempfile.TemporaryDirectory(prefix="hybrid-uvm-abi-") as directory:
        binary = Path(directory) / "probe"
        command = [*compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                   "-fsanitize=undefined", "-fno-sanitize-recover=all",
                   "-I", str(include_dir), str(source), "-o", str(binary)]
        if define:
            command.insert(len(compiler), f"-D{define}")
        build = subprocess.run(command, capture_output=True, text=True,
                               timeout=60, check=False)
        if build.returncode:
            raise RuntimeError("C ABI probe failed to compile:\n" +
                               build.stdout + build.stderr)
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             timeout=10, check=False)
        if run.returncode:
            raise RuntimeError("C ABI probe failed to run:\n" +
                               run.stdout + run.stderr)
        return run.stdout.strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def gpu_platform_info_declaration(header_path):
    header = Path(header_path).read_text()
    match = re.search(
        r"typedef\s+struct\s*\{.*?\}\s*UvmGpuPlatformInfo\s*;",
        header, re.DOTALL)
    require(match is not None,
            f"could not extract UvmGpuPlatformInfo from {header_path}")
    declaration = re.sub(r"/\*.*?\*/|//[^\n]*", "", match.group(),
                         flags=re.DOTALL)
    declaration = re.sub(r"\s+", " ", declaration).strip()
    fields = re.findall(
        r"\b(?:struct\s+pci_dev\s*\*|NvU64)\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
        declaration)
    return declaration, fields


def gpu_fb_info_signature(header_path):
    header = Path(header_path).read_text()
    match = re.search(
        r"NV_STATUS\s+nvUvmInterfaceGetFbInfo\s*\([^;]*\);",
        header, re.DOTALL)
    require(match is not None,
            f"could not extract nvUvmInterfaceGetFbInfo from {header_path}")
    signature = re.sub(r"/\*.*?\*/|//[^\n]*", "", match.group(),
                       flags=re.DOTALL)
    return re.sub(r"\s+", " ", signature).strip()


def gpu_fb_info_reads(source_path):
    source = Path(source_path).read_text()
    return sorted(set(re.findall(r"\bfb_info\.([A-Za-z_][A-Za-z0-9_]*)",
                                 source)))


def pma_allocation_signature(header_path):
    header = Path(header_path).read_text()
    match = re.search(
        r"NV_STATUS\s+nvUvmInterfacePmaAllocPages\s*\([^;]*\);",
        header, re.DOTALL)
    require(match is not None,
            f"could not extract nvUvmInterfacePmaAllocPages from {header_path}")
    signature = re.sub(r"/\*.*?\*/|//[^\n]*", "", match.group(),
                       flags=re.DOTALL)
    return re.sub(r"\s+", " ", signature).strip()


def pma_allocation_option_accesses(source_path):
    source = Path(source_path).read_text()
    return sorted(set(re.findall(r"\boptions\.([A-Za-z_][A-Za-z0-9_]*)",
                                 source)))


FAULT_API_NAMES = (
    "nvUvmInterfaceOwnPageFaultIntr",
    "nvUvmInterfaceInitFaultInfo",
    "nvUvmInterfaceDestroyFaultInfo",
    "nvUvmInterfaceHasPendingNonReplayableFaults",
    "nvUvmInterfaceGetNonReplayableFaults",
    "nvUvmInterfaceFlushReplayableFaultBuffer",
    "nvUvmInterfaceTogglePrefetchFaults",
    "nvUvmInterfaceReportNonReplayableFault",
)


def fault_api_signatures(header_path):
    header = Path(header_path).read_text()
    signatures = {}
    for name in FAULT_API_NAMES:
        match = re.search(
            r"NV_STATUS\s+" + re.escape(name) + r"\s*\([^;]*\);",
            header, re.DOTALL)
        require(match is not None,
                f"could not extract {name} from {header_path}")
        signature = re.sub(r"/\*.*?\*/|//[^\n]*", "", match.group(),
                           flags=re.DOTALL)
        signatures[name] = re.sub(r"\s+", " ", signature).strip()
    return signatures


def fault_info_source_accesses(uvm_root):
    """Return field references through UvmGpuFaultInfo and their C inputs."""
    pattern = re.compile(
        r"\b(?:rm_info|pFaultInfo|faultInfo)(?:->|\.)"
        r"(replayable|nonReplayable)\.([A-Za-z_][A-Za-z0-9_]*)")
    fields = set()
    sources = []
    for path in sorted(Path(uvm_root).rglob("*.c")):
        source = path.read_text(errors="strict")
        found = pattern.findall(source)
        if found:
            sources.append(path)
            fields.update(f"{group}.{field}" for group, field in found)
    return sorted(fields), sources


FAULT_HAL_OPERATIONS = (
    "enable_replayable_faults", "disable_replayable_faults",
    "clear_replayable_faults", "read_put", "read_get", "write_get",
    "get_ve_id", "get_mmu_engine_type", "parse_replayable_entry",
    "entry_is_valid", "entry_clear_valid", "entry_size",
    "parse_non_replayable_entry", "get_fault_type",
)


def parse_fault_hal_table(source_path):
    source = Path(source_path).read_text()
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)
    declaration = re.search(
        r"static\s+uvm_hal_class_ops_t\s+fault_buffer_table\s*\[\s*\]\s*=",
        source)
    require(declaration is not None,
            f"fault_buffer_table missing from {source_path}")
    open_brace = source.find("{", declaration.end())
    require(open_brace >= 0, f"fault_buffer_table initializer missing in {source_path}")
    depth = 0
    row_start = None
    row_texts = []
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
            if depth == 2:
                row_start = index
        elif char == "}":
            if depth == 2 and row_start is not None:
                row_texts.append(source[row_start:index + 1])
                row_start = None
            depth -= 1
            if depth == 0:
                break
    require(depth == 0 and row_texts,
            f"fault_buffer_table braces are malformed in {source_path}")

    rows = []
    for row in row_texts:
        arch = re.search(r"\.id\s*=\s*([^,]+)", row)
        require(arch is not None, f"fault HAL row has no .id in {source_path}")
        parent = re.search(r"\.parent_id\s*=\s*([^,]+)", row)
        assignments = dict(re.findall(r"\.(\w+)\s*=\s*(\w+)\s*,", row))
        callbacks = {name: assignments[name] for name in FAULT_HAL_OPERATIONS
                     if name in assignments}
        rows.append({
            "id": arch.group(1).strip(),
            "parent_id": parent.group(1).strip() if parent else None,
            "callbacks": callbacks,
        })

    row_by_id = {}
    resolved_by_id = {}
    for row in rows:
        arch = row["id"]
        require(arch not in row_by_id, f"duplicate fault HAL architecture {arch}")
        parent = row["parent_id"]
        if parent is not None:
            require(parent in resolved_by_id,
                    f"fault HAL parent {parent} for {arch} is missing or appears later")
            callbacks = resolved_by_id[parent].copy()
        else:
            callbacks = {}
        callbacks.update(row["callbacks"])
        require(set(callbacks) == set(FAULT_HAL_OPERATIONS),
                f"fault HAL row {arch} does not resolve all callback slots")
        row_by_id[arch] = row
        resolved_by_id[arch] = callbacks

    return row_by_id, resolved_by_id, source


def uvm_macro_value(header_path, name):
    header = Path(header_path).read_text()
    match = re.search(r"^\s*#\s*define\s+" + re.escape(name) + r"\s+(\d+)\b",
                      header, re.MULTILINE)
    require(match is not None, f"could not read {name} from {header_path}")
    return int(match.group(1))


def fault_entry_size_symbol(source_path, function_name):
    source = Path(source_path).read_text()
    match = re.search(
        r"\b" + re.escape(function_name) + r"\s*\([^)]*\)\s*\{[^}]*?"
        r"\breturn\s+(\w+)\s*;", source, re.DOTALL)
    require(match is not None,
            f"could not read the returned entry-size symbol for {function_name}")
    return match.group(1)


def c_function_definition(source_path, function_name):
    """Extract one C definition with brace balancing, masking comments first."""
    source = Path(source_path).read_text()
    # Preserve offsets while making braces and semicolons in comments inert.
    masked = list(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and following == "*":
                masked[index] = masked[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == "/" and following == "/":
                masked[index] = masked[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
        elif state == "block_comment":
            if char == "*" and following == "/":
                masked[index] = masked[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                masked[index] = " "
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
        elif state in ("string", "char"):
            if char == "\\":
                if char != "\n":
                    masked[index] = " "
                if index + 1 < len(source) and source[index + 1] != "\n":
                    masked[index + 1] = " "
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
            if char != "\n":
                masked[index] = " "
        index += 1

    masked = "".join(masked)
    declaration = re.search(
        r"\b" + re.escape(function_name) + r"\s*\([^;{}]*?\)\s*\{",
        masked, re.DOTALL)
    require(declaration is not None,
            f"could not extract definition of {function_name} from {source_path}")
    open_brace = masked.find("{", declaration.start(), declaration.end())
    depth = 0
    for end in range(open_brace, len(masked)):
        if masked[end] == "{":
            depth += 1
        elif masked[end] == "}":
            depth -= 1
            if depth == 0:
                definition = source[declaration.start():end + 1]
                definition = re.sub(r"/\*.*?\*/|//[^\n]*", "", definition,
                                    flags=re.DOTALL)
                return re.sub(r"\s+", " ", definition).strip()
    raise RuntimeError(f"unterminated definition of {function_name} in {source_path}")


def normalized_function_signature(source_path, function_name, canonical_name):
    definition = c_function_definition(source_path, function_name)
    return re.sub(r"\b" + re.escape(function_name) + r"\b",
                  canonical_name, definition, count=1)


def function_body_has_host_limit_and_bar1_guard(source_path, function_name):
    definition = c_function_definition(source_path, function_name)
    host_limit = re.search(
        r"mmu_engine_id\s*<=\s*(NV_PFAULT_MMU_ENG_ID_HOST\d+)", definition)
    require(host_limit is not None,
            f"could not extract the host-engine limit in {function_name}")
    return host_limit.group(1), bool(re.search(
        r"mmu_engine_id\s*<\s*NV_PFAULT_MMU_ENG_ID_BAR1", definition))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580", type=Path, default=DEFAULT_R580,
                        help="pinned R580 provider source root")
    parser.add_argument("--r595", type=Path, default=DEFAULT_R595,
                        help="pinned R595 Open source root")
    parser.add_argument("--report", type=Path, required=True,
                        help="new JSON report path")
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"),
                        help="C compiler (default: CC or cc)")
    args = parser.parse_args()
    r580 = args.r580.resolve(strict=True)
    r595 = args.r595.resolve(strict=True)
    r580_inc = r580 / "common/inc"
    r595_inc = r595 / "common/inc"
    r580_uvm = r580 / "nvidia-uvm"
    r595_uvm = r595 / "nvidia-uvm"
    for path in (r580_inc / "nv_uvm_types.h", r595_inc / "nv_uvm_types.h",
                 r580_uvm / "uvm_ampere_host.c", r595_uvm / "uvm_pmm_gpu.c"):
        require(path.is_file(), f"required pinned source is missing: {path}")

    compiler = shlex.split(args.cc)
    layout_probe = ROOT / "tests/fixtures/uvm_branch_layout_probe.c"
    r580_layout = json.loads(compile_and_run(layout_probe, r580_inc, compiler))
    r595_layout = json.loads(compile_and_run(
        layout_probe, r595_inc, compiler, "HYBRID_BRANCH_R595"))
    r580_platform_decl, r580_platform_fields = gpu_platform_info_declaration(
        r580_inc / "nv_uvm_interface.h")
    r595_platform_decl, r595_platform_fields = gpu_platform_info_declaration(
        r595_inc / "nv_uvm_interface.h")
    r580_fb_signature = gpu_fb_info_signature(r580_inc / "nv_uvm_interface.h")
    r595_fb_signature = gpu_fb_info_signature(r595_inc / "nv_uvm_interface.h")
    r580_fb_reads = gpu_fb_info_reads(r580_uvm / "uvm_gpu.c")
    r595_fb_reads = gpu_fb_info_reads(r595_uvm / "uvm_gpu.c")
    r580_pma_signature = pma_allocation_signature(r580_inc / "nv_uvm_interface.h")
    r595_pma_signature = pma_allocation_signature(r595_inc / "nv_uvm_interface.h")
    r580_pma_accesses = pma_allocation_option_accesses(r580_uvm / "uvm_pmm_gpu.c")
    r595_pma_accesses = pma_allocation_option_accesses(r595_uvm / "uvm_pmm_gpu.c")
    r580_fault_signatures = fault_api_signatures(r580_inc / "nv_uvm_interface.h")
    r595_fault_signatures = fault_api_signatures(r595_inc / "nv_uvm_interface.h")
    r580_fault_fields, r580_fault_sources = fault_info_source_accesses(r580_uvm)
    r595_fault_fields, r595_fault_sources = fault_info_source_accesses(r595_uvm)
    r580_fault_rows, r580_fault_resolved, r580_hal_source = parse_fault_hal_table(
        r580_uvm / "uvm_hal.c")
    r595_fault_rows, r595_fault_resolved, r595_hal_source = parse_fault_hal_table(
        r595_uvm / "uvm_hal.c")
    gv100_arch = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100"
    gb100_arch = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GB100"
    tu100_arch = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100"
    gp100_arch = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GP100"
    gh100_arch = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GH100"
    require(gv100_arch in r580_fault_rows and gv100_arch not in r595_fault_rows,
            "pinned R580/R595 Volta fault-HAL table membership changed")
    require(r580_fault_rows[gv100_arch]["parent_id"] == gp100_arch and
            r595_fault_rows[tu100_arch]["parent_id"] is None and
            r580_fault_rows[gb100_arch]["parent_id"] == gh100_arch and
            r595_fault_rows[gb100_arch]["parent_id"] == gh100_arch,
            "pinned Volta/Turing/Blackwell fault-HAL parent edges changed")
    r580_hal_init = r580_hal_source[
        r580_hal_source.index("static inline NV_STATUS ops_init_from_table"):]
    r595_hal_init = r595_hal_source[
        r595_hal_source.index("static inline NV_STATUS ops_init_from_table"):]
    for branch, source in (("R580", r580_hal_init), ("R595", r595_hal_init)):
        require(re.search(
            r"if\s*\(\s*op_is_null\(dest_table\s*\+\s*i,\s*j,\s*op_offset\)\s*\)\s*"
            r"op_copy\(dest_table\s*\+\s*i,\s*parent,\s*j,\s*op_offset\)", source),
            f"{branch} fault HAL parent-copy behavior changed")
        require("ops_init_from_parent(fault_buffer_table" in source and
                re.search(r"ops_find_by_id\s*\(\s*fault_buffer_table\s*,\s*"
                          r"ARRAY_SIZE\(fault_buffer_table\)\s*,\s*gpu_info->gpuArch\s*\)",
                          source),
                f"{branch} fault HAL table initialization or architecture lookup changed")
    r580_volta_fault_source = r580_uvm / "uvm_volta_fault_buffer.c"
    r595_turing_fault_source = r595_uvm / "uvm_turing_fault_buffer.c"
    for branch, source in (("R580", r580_volta_fault_source),
                           ("R595", r595_turing_fault_source)):
        require(re.search(r"NvU8\s+bufferEntry\s*\[\s*NVC369_BUF_SIZE\s*\]", source.read_text()),
                f"{branch} C369 fault entry storage declaration changed")
    r580_volta_fault_header = r580_uvm / "hwref/volta/gv100/dev_fault.h"
    r595_turing_fault_header = r595_uvm / "hwref/turing/tu102/dev_fault.h"
    common_fault_parser = {
        "r580": c_function_definition(
            r580_volta_fault_source, "parse_fault_entry_common"),
        "r595": c_function_definition(
            r595_turing_fault_source, "parse_fault_entry_common"),
    }
    fault_type_decoder = {
        "r580": normalized_function_signature(
            r580_volta_fault_source,
            "uvm_hal_volta_fault_buffer_get_fault_type",
            "uvm_hal_arch_fault_buffer_get_fault_type"),
        "r595": normalized_function_signature(
            r595_turing_fault_source,
            "uvm_hal_turing_fault_buffer_get_fault_type",
            "uvm_hal_arch_fault_buffer_get_fault_type"),
    }
    r580_mmu_limit, r580_mmu_bar1_guard = function_body_has_host_limit_and_bar1_guard(
        r580_volta_fault_source, "uvm_hal_volta_fault_buffer_get_mmu_engine_type")
    r595_mmu_limit, r595_mmu_bar1_guard = function_body_has_host_limit_and_bar1_guard(
        r595_turing_fault_source, "uvm_hal_turing_fault_buffer_get_mmu_engine_type")
    r580_host_limit = uvm_macro_value(r580_volta_fault_header, r580_mmu_limit)
    r595_host_limit = uvm_macro_value(r595_turing_fault_header, r595_mmu_limit)
    r580_bar1_engine = uvm_macro_value(
        r580_volta_fault_header, "NV_PFAULT_MMU_ENG_ID_BAR1")
    r595_bar1_engine = uvm_macro_value(
        r595_turing_fault_header, "NV_PFAULT_MMU_ENG_ID_BAR1")
    require(common_fault_parser["r580"] == common_fault_parser["r595"] and
            fault_type_decoder["r580"] == fault_type_decoder["r595"],
            "pinned Volta/Turing common fault parser or fault-type decoder changed")
    require((r580_mmu_limit, r580_host_limit, r580_bar1_engine,
             r580_mmu_bar1_guard) ==
            ("NV_PFAULT_MMU_ENG_ID_HOST13", 45, 4, False) and
            (r595_mmu_limit, r595_host_limit, r595_bar1_engine,
             r595_mmu_bar1_guard) ==
            ("NV_PFAULT_MMU_ENG_ID_HOST14", 46, 128, True),
            "pinned Volta/Turing MMU-engine classification source contract changed")
    fault_hal_callback_delta = {
        "classification": "pinned-UVM-callback-source-and-hardware-constant-census",
        "common_c369_fault_parser": {
            "normalized_definition_identical": True,
            "r580_sha256": hashlib.sha256(
                common_fault_parser["r580"].encode()).hexdigest(),
            "r595_sha256": hashlib.sha256(
                common_fault_parser["r595"].encode()).hexdigest(),
        },
        "fault_type_decoder": {
            "normalized_definition_identical": True,
            "r580_sha256": hashlib.sha256(
                fault_type_decoder["r580"].encode()).hexdigest(),
            "r595_sha256": hashlib.sha256(
                fault_type_decoder["r595"].encode()).hexdigest(),
        },
        "mmu_engine_classification": {
            "r580_host_engine_limit_symbol": r580_mmu_limit,
            "r580_host_engine_limit_value": r580_host_limit,
            "r595_host_engine_limit_symbol": r595_mmu_limit,
            "r595_host_engine_limit_value": r595_host_limit,
            "r580_bar1_engine_enum_value": r580_bar1_engine,
            "r595_bar1_engine_enum_value": r595_bar1_engine,
            "r580_graphics_guard_has_bar1_upper_bound": r580_mmu_bar1_guard,
            "r595_graphics_guard_has_bar1_upper_bound": r595_mmu_bar1_guard,
        },
        "hardware_validated": False,
    }
    r580_pascal_entry_size_source = r580_uvm / "uvm_pascal_fault_buffer.c"
    r580_blackwell_fault_source = r580_uvm / "uvm_blackwell_fault_buffer.c"
    r595_blackwell_fault_source = r595_uvm / "uvm_blackwell_fault_buffer.c"
    r580_fault_entry_size_symbol = fault_entry_size_symbol(
        r580_pascal_entry_size_source, "uvm_hal_pascal_fault_buffer_entry_size")
    r595_fault_entry_size_symbol = fault_entry_size_symbol(
        r595_turing_fault_source, "uvm_hal_turing_fault_buffer_entry_size")
    r580_nvb069_size = uvm_macro_value(r580_uvm / "clb069.h", "NVB069_FAULT_BUF_SIZE")
    r580_nvc369_size = uvm_macro_value(r580_uvm / "clc369.h", "NVC369_BUF_SIZE")
    r595_nvc369_size = uvm_macro_value(r595_uvm / "clc369.h", "NVC369_BUF_SIZE")
    require(r580_fault_entry_size_symbol == "NVB069_FAULT_BUF_SIZE" and
            r595_fault_entry_size_symbol == "NVC369_BUF_SIZE" and
            r580_nvb069_size == r580_nvc369_size == r595_nvc369_size == 32,
            "pinned Volta/Blackwell fault entry size relationship changed")
    adapter_output = compile_and_run(
        ROOT / "tests/fixtures/hybrid580_uvm_abi_compat_test.c",
        r595_inc, compiler, "HYBRID_BRANCH_R595")
    event_adapter_output = compile_and_run(
        ROOT / "tests/fixtures/hybrid580_uvm_event_compat_test.c",
        r595_inc, compiler)

    pmm_source = (r595_uvm / "uvm_pmm_gpu.c").read_text()
    pma_fields_read = sorted(set(re.findall(r"pma_stats->([A-Za-z0-9_]+)",
                                            pmm_source)))
    old_host_source = (r580_uvm / "uvm_ampere_host.c").read_text()
    old_doorbell_header = (r580_uvm / "hwref/ampere/ga100/dev_runlist.h").read_text()
    old_doorbell_offset = re.search(
        r"#define\s+NV_RUNLIST_INTERNAL_DOORBELL\s+(0x[0-9a-fA-F]+)",
        old_doorbell_header)
    old_chid_field = re.search(
        r"#define\s+NV_RUNLIST_INTERNAL_DOORBELL_CHID\s+(\d+:\d+)",
        old_doorbell_header)
    require(old_doorbell_offset and old_chid_field,
            "could not extract the R580 runlist doorbell offset/CHID field")
    require("runlist_pri_base_register + NV_RUNLIST_INTERNAL_DOORBELL" in old_host_source,
            "R580 channel doorbell address derivation changed")
    require("HWVALUE(_RUNLIST, INTERNAL_DOORBELL, CHID, user_channel->hw_channel_id)" in old_host_source,
            "R580 channel doorbell token derivation changed")

    expected_layout = {
        "R580": {"p2p_size": 64, "copy_caps_size": 8, "copy_mask_offset": 4,
                 "channel_size": 1120, "channel_divergence_offset": 1104,
                 "pma_size": 48, "event_table_size": 56,
                 "event_suspend_offset": 0, "event_resume_offset": 8,
                 "event_start_device_offset": 16, "event_stop_device_offset": 24,
                 "event_isr_top_half_offset": 32,
                 "event_drain_p2p_offset": 40,
                 "event_resume_p2p_offset": 48},
        "R595": {"p2p_size": 72, "copy_caps_size": 8, "copy_mask_offset": 4,
                 "channel_size": 1128, "channel_divergence_offset": 1104,
                 "pma_size": 96, "event_table_size": 40,
                 "event_isr_top_half_offset": 0, "event_suspend_offset": 8,
                 "event_resume_offset": 16, "event_drain_p2p_offset": 24,
                 "event_resume_p2p_offset": 32},
    }
    for branch, observed in (("R580", r580_layout), ("R595", r595_layout)):
        for field, expected in expected_layout[branch].items():
            require(observed.get(field) == expected,
                    f"{branch} {field}: observed {observed.get(field)}, expected {expected}")
    require(r580_layout["link_nvlink1"] == 2 and r595_layout["link_nvlink1"] == 3,
            "pinned link enum shift changed; review the explicit P2P translation")
    require(r580_layout["channel_resource_size"] == r595_layout["channel_resource_size"],
            "channel resource nested layout differs between pinned releases")
    gpu_info_fields = set(r580_layout["gpu_info_offsets"])
    require(len(gpu_info_fields) == 35 and
            gpu_info_fields == set(r595_layout["gpu_info_offsets"]),
            "pinned UvmGpuInfo field inventory changed; re-audit registration ABI")
    require(r580_layout["gpu_info_size"] == r595_layout["gpu_info_size"] and
            r580_layout["gpu_info_offsets"] == r595_layout["gpu_info_offsets"],
            "pinned UvmGpuInfo compiler layouts differ")
    expected_platform_decl = (
        "typedef struct { struct pci_dev *pci_dev; "
        "NvU64 dma_addressable_start; NvU64 dma_addressable_limit; "
        "} UvmGpuPlatformInfo;")
    expected_platform_fields = [
        "pci_dev", "dma_addressable_start", "dma_addressable_limit"]
    require(r580_platform_decl == expected_platform_decl and
            r595_platform_decl == expected_platform_decl and
            r580_platform_fields == expected_platform_fields and
            r595_platform_fields == expected_platform_fields,
            "pinned UvmGpuPlatformInfo declaration/order changed; re-audit registration ABI")
    expected_fb_fields = {
        "maxAllocatableAddress", "heapSize", "reservedHeapSize", "bZeroFb",
        "maxVidmemPageSize", "bStaticBar1Enabled", "bStaticBar1WriteCombined",
        "staticBar1StartOffset", "staticBar1Size", "heapStart",
    }
    expected_fb_reads = sorted(expected_fb_fields - {"bStaticBar1Enabled"})
    expected_fb_signature = (
        "NV_STATUS nvUvmInterfaceGetFbInfo(uvmGpuDeviceHandle device, "
        "UvmGpuFbInfo * fbInfo);")
    require(set(r580_layout["fb_info_offsets"]) == expected_fb_fields and
            set(r595_layout["fb_info_offsets"]) == expected_fb_fields,
            "pinned UvmGpuFbInfo field inventory changed; re-audit memory ABI")
    require(r580_layout["fb_info_size"] == r595_layout["fb_info_size"] and
            r580_layout["fb_info_offsets"] == r595_layout["fb_info_offsets"],
            "pinned UvmGpuFbInfo compiler layouts differ")
    require(r580_fb_signature == expected_fb_signature and
            r595_fb_signature == expected_fb_signature,
            "pinned GetFbInfo API signature changed; re-audit memory ABI")
    require(r580_fb_reads == expected_fb_reads and r595_fb_reads == expected_fb_reads,
            "pinned UVM GetFbInfo consumer field access changed; re-audit memory semantics")
    expected_pma_fields = {
        "flags", "minimumSpeed", "physBegin", "physEnd", "regionId",
        "alignment", "numPagesAllocated", "resultFlags",
    }
    expected_pma_accesses = [
        "flags", "numPagesAllocated", "physBegin", "physEnd", "resultFlags"]
    expected_pma_signature = (
        "NV_STATUS nvUvmInterfacePmaAllocPages(void *pPma, NvLength pageCount, "
        "NvU64 pageSize, UvmPmaAllocationOptions *pPmaAllocOptions, "
        "NvU64 *pPages);")
    expected_pma_flags = {
        "ALLOCATE_ALLOW_PARTIAL": 4096,
        "ALLOCATE_CONTIGUOUS": 64,
        "ALLOCATE_DONT_EVICT": 1,
        "ALLOCATE_NO_ZERO": 1024,
        "ALLOCATE_PINNED": 2,
        "ALLOCATE_PROTECTED_REGION": 256,
        "ALLOCATE_RESULT_IS_ZERO": 1,
        "ALLOCATE_SPECIFY_ADDRESS_RANGE": 8,
    }
    require(set(r580_layout["pma_options_offsets"]) == expected_pma_fields and
            set(r595_layout["pma_options_offsets"]) == expected_pma_fields,
            "pinned UvmPmaAllocationOptions field inventory changed")
    require(r580_layout["pma_options_size"] == 56 and
            r595_layout["pma_options_size"] == 56 and
            r580_layout["pma_options_offsets"] == r595_layout["pma_options_offsets"],
            "pinned UvmPmaAllocationOptions compiler layouts differ")
    require(r580_pma_signature == expected_pma_signature and
            r595_pma_signature == expected_pma_signature,
            "pinned PmaAllocPages API signature changed")
    require(r580_pma_accesses == expected_pma_accesses and
            r595_pma_accesses == expected_pma_accesses,
            "pinned PMA UVM option field access changed")
    require(r580_layout["pma_allocation_flags"] == expected_pma_flags and
            r595_layout["pma_allocation_flags"] == expected_pma_flags,
            "pinned UVM-used PMA allocation flag values changed")
    expected_fault_top_offsets = {
        "replayable": 0, "nonReplayable": 104,
        "faultBufferHandle": 168, "pDevice": 176,
    }
    expected_fault_replayable_offsets = {
        "pFaultBufferGet": 0, "pFaultBufferPut": 8,
        "pFaultBufferInfo": 16, "pPmcIntr": 24,
        "pPmcIntrEnSet": 32, "pPmcIntrEnClear": 40,
        "pPrefetchCtrl": 48, "replayableFaultMask": 56,
        "bufferAddress": 64, "bufferSize": 72,
        "bufferMetadata": 80, "cslCtx": 88,
    }
    expected_fault_nonreplayable_offsets = {
        "shadowBufferAddress": 0, "shadowBufferContext": 8,
        "bufferSize": 16, "isr_sp": 24, "isr_bh_sp": 32,
        "pFaultBufferPut": 40, "shadowBufferGet": 48,
        "shadowBufferMetadata": 56,
    }
    expected_fault_api_signatures = {
        "nvUvmInterfaceOwnPageFaultIntr":
            "NV_STATUS nvUvmInterfaceOwnPageFaultIntr(uvmGpuDeviceHandle device, NvBool bOwnInterrupts);",
        "nvUvmInterfaceInitFaultInfo":
            "NV_STATUS nvUvmInterfaceInitFaultInfo(uvmGpuDeviceHandle device, UvmGpuFaultInfo *pFaultInfo);",
        "nvUvmInterfaceDestroyFaultInfo":
            "NV_STATUS nvUvmInterfaceDestroyFaultInfo(uvmGpuDeviceHandle device, UvmGpuFaultInfo *pFaultInfo);",
        "nvUvmInterfaceHasPendingNonReplayableFaults":
            "NV_STATUS nvUvmInterfaceHasPendingNonReplayableFaults(UvmGpuFaultInfo *pFaultInfo, NvBool *hasPendingFaults);",
        "nvUvmInterfaceGetNonReplayableFaults":
            "NV_STATUS nvUvmInterfaceGetNonReplayableFaults(UvmGpuFaultInfo *pFaultInfo, void *pFaultBuffer, NvU32 *numFaults);",
        "nvUvmInterfaceFlushReplayableFaultBuffer":
            "NV_STATUS nvUvmInterfaceFlushReplayableFaultBuffer(UvmGpuFaultInfo *pFaultInfo, NvBool bCopyAndFlush);",
        "nvUvmInterfaceTogglePrefetchFaults":
            "NV_STATUS nvUvmInterfaceTogglePrefetchFaults(UvmGpuFaultInfo *pFaultInfo, NvBool bEnable);",
        "nvUvmInterfaceReportNonReplayableFault":
            "NV_STATUS nvUvmInterfaceReportNonReplayableFault(uvmGpuDeviceHandle device, const void *pFaultPacket);",
    }
    expected_fault_accesses = [
        "nonReplayable.bufferSize", "replayable.bufferAddress",
        "replayable.bufferMetadata", "replayable.bufferSize",
        "replayable.cslCtx", "replayable.pFaultBufferGet",
        "replayable.pFaultBufferPut", "replayable.pPmcIntr",
        "replayable.pPmcIntrEnClear", "replayable.pPmcIntrEnSet",
        "replayable.pPrefetchCtrl", "replayable.replayableFaultMask",
    ]
    for branch, observed in (("R580", r580_layout), ("R595", r595_layout)):
        require(observed["fault_info_size"] == 184 and
                observed["fault_info_top_offsets"] == expected_fault_top_offsets,
                f"{branch} UvmGpuFaultInfo top-level layout changed")
        require(observed["fault_info_replayable_size"] == 104 and
                observed["fault_info_replayable_offsets"] == expected_fault_replayable_offsets,
                f"{branch} UvmGpuFaultInfo replayable layout changed")
        require(observed["fault_info_nonreplayable_size"] == 64 and
                observed["fault_info_nonreplayable_offsets"] == expected_fault_nonreplayable_offsets,
                f"{branch} UvmGpuFaultInfo non-replayable layout changed")
        require(observed["fault_metadata_size"] == 32 and
                observed["fault_metadata_offsets"] == {"authTag": 0, "valid": 16},
                f"{branch} UvmFaultMetadataPacket layout changed")
        require(observed["csl_context_size"] == 16 and
                observed["csl_context_offsets"] == {"ctx": 0, "nvidia_stack": 8},
                f"{branch} UvmCslContext layout changed")
    require(r580_fault_signatures == expected_fault_api_signatures and
            r595_fault_signatures == expected_fault_api_signatures,
            "pinned fault-related UVM API declarations changed")
    require(r580_fault_fields == expected_fault_accesses and
            r595_fault_fields == expected_fault_accesses,
            "pinned UVM UvmGpuFaultInfo source field-access set changed")
    require(r580_layout["pma_free64k_offset"] == r595_layout["pma_free64k_offset"] == 8 and
            r580_layout["pma_free2m_offset"] == r595_layout["pma_free2m_offset"] == 16,
            "PMA counters consumed by R595 no longer share the R580 prefix")
    require(pma_fields_read == ["numFreePages2m", "numFreePages64k"],
            f"pinned R595 runtime PMA reads changed: {pma_fields_read}")
    require(old_doorbell_offset.group(1).lower() == "0x090" and
            old_chid_field.group(1) == "11:0",
            "R580 runlist doorbell constants changed; re-audit the mapping")
    require("passed" in adapter_output,
            "compiled R580-to-R595 payload conversion tests did not pass")
    require("passed" in event_adapter_output,
            "compiled R595-to-R580 event-table conversion tests did not pass")

    source_files = {
        "r580_types": r580_inc / "nv_uvm_types.h",
        "r580_user_types": r580_inc / "nv_uvm_user_types.h",
        "r580_uvm_interface": r580_inc / "nv_uvm_interface.h",
        "r580_channel_host": r580_uvm / "uvm_ampere_host.c",
        "r580_gpu_consumer": r580_uvm / "uvm_gpu.c",
        "r580_pmm_consumer": r580_uvm / "uvm_pmm_gpu.c",
        "r580_runlist_header": r580_uvm / "hwref/ampere/ga100/dev_runlist.h",
        "r595_types": r595_inc / "nv_uvm_types.h",
        "r595_user_types": r595_inc / "nv_uvm_user_types.h",
        "r595_uvm_interface": r595_inc / "nv_uvm_interface.h",
        "r595_pmm_runtime": r595_uvm / "uvm_pmm_gpu.c",
        "r595_gpu_consumer": r595_uvm / "uvm_gpu.c",
        "r595_pmm_consumer": r595_uvm / "uvm_pmm_gpu.c",
        "r580_fault_hal_table": r580_uvm / "uvm_hal.c",
        "r580_volta_fault_hal": r580_volta_fault_source,
        "r580_volta_fault_hardware_header": r580_volta_fault_header,
        "r580_pascal_fault_entry_size": r580_pascal_entry_size_source,
        "r580_blackwell_fault_overrides": r580_blackwell_fault_source,
        "r580_c369_fault_packet_header": r580_uvm / "clc369.h",
        "r580_b069_fault_packet_header": r580_uvm / "clb069.h",
        "r595_fault_hal_table": r595_uvm / "uvm_hal.c",
        "r595_turing_fault_hal": r595_turing_fault_source,
        "r595_turing_fault_hardware_header": r595_turing_fault_header,
        "r595_blackwell_fault_overrides": r595_blackwell_fault_source,
        "r595_c369_fault_packet_header": r595_uvm / "clc369.h",
        "adapter_header": ROOT / "src/hybrid580_uvm_abi_compat.h",
        "adapter_fixture": ROOT / "tests/fixtures/hybrid580_uvm_abi_compat_test.c",
        "event_adapter_header": ROOT / "src/hybrid580_uvm_event_compat.h",
        "event_adapter_fixture": ROOT / "tests/fixtures/hybrid580_uvm_event_compat_test.c",
        "layout_probe": layout_probe,
    }
    for branch, paths in (("r580", r580_fault_sources), ("r595", r595_fault_sources)):
        for path in paths:
            key = f"{branch}_fault_access_{path.stem}"
            source_files[key] = path
    report = {
        "schema": "hybrid-uvm-branch-abi-audit-v8",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "classification": "compiled-static-header-and-CPU-adapter-contract",
        "source_roots": {"r580": str(r580), "r595": str(r595)},
        "compiler": compiler,
        "layout": {"r580": r580_layout, "r595": r595_layout},
        "gpu_registration_abi": {
            "classification": "pinned-header-and-host-compiler-layout",
            "gpu_info": {
                "field_count": len(gpu_info_fields),
                "r580_size": r580_layout["gpu_info_size"],
                "r595_size": r595_layout["gpu_info_size"],
                "size_and_offsets_equal": True,
            },
            "gpu_platform_info": {
                "declaration_identical": True,
                "fields": r580_platform_fields,
                "normalized_declaration": r580_platform_decl,
            },
            "hardware_validated": False,
        },
        "gpu_memory_abi": {
            "classification": "pinned-layout-and-UVM-field-access-census",
            "fb_info": {
                "field_count": len(expected_fb_fields),
                "r580_size": r580_layout["fb_info_size"],
                "r595_size": r595_layout["fb_info_size"],
                "size_and_offsets_equal": True,
                "api_signature_identical": True,
                "normalized_api_signature": r580_fb_signature,
                "fields_read_by_r580_and_r595": r580_fb_reads,
                "fields_not_read_by_either_uvm_source": sorted(
                    expected_fb_fields - set(r580_fb_reads)),
            },
            "pma_allocation": {
                "field_count": len(expected_pma_fields),
                "r580_size": r580_layout["pma_options_size"],
                "r595_size": r595_layout["pma_options_size"],
                "size_and_offsets_equal": True,
                "api_signature_identical": True,
                "normalized_api_signature": r580_pma_signature,
                "fields_accessed_by_r580_and_r595_uvm": r580_pma_accesses,
                "fields_not_explicitly_accessed_by_either_uvm_source": sorted(
                    expected_pma_fields - set(r580_pma_accesses)),
                "allocation_flag_values": r580_layout["pma_allocation_flags"],
            },
            "hardware_validated": False,
        },
        "faults_abi": {
            "classification": "pinned-header-host-compiler-layout-and-UVM-source-access-census",
            "gpu_fault_info": {
                "r580_size": r580_layout["fault_info_size"],
                "r595_size": r595_layout["fault_info_size"],
                "size_and_offsets_equal": True,
                "top_level_offsets": r580_layout["fault_info_top_offsets"],
                "replayable_size": r580_layout["fault_info_replayable_size"],
                "replayable_offsets": r580_layout["fault_info_replayable_offsets"],
                "nonreplayable_size": r580_layout["fault_info_nonreplayable_size"],
                "nonreplayable_offsets": r580_layout["fault_info_nonreplayable_offsets"],
            },
            "metadata_packet": {
                "size": r580_layout["fault_metadata_size"],
                "offsets": r580_layout["fault_metadata_offsets"],
                "size_and_offsets_equal": True,
            },
            "csl_context": {
                "size": r580_layout["csl_context_size"],
                "offsets": r580_layout["csl_context_offsets"],
                "size_and_offsets_equal": True,
            },
            "fault_api_count": len(FAULT_API_NAMES),
            "fault_api_signatures_identical": True,
            "fault_api_signatures": r580_fault_signatures,
            "uvm_field_access_sets": {
                "r580": r580_fault_fields,
                "r595": r595_fault_fields,
                "identical": r580_fault_fields == r595_fault_fields,
            },
            "uvm_access_source_paths": {
                "r580": [str(path.relative_to(r580_uvm)) for path in r580_fault_sources],
                "r595": [str(path.relative_to(r595_uvm)) for path in r595_fault_sources],
            },
            "hardware_validated": False,
        },
        "fault_hal_abi": {
            "classification": "pinned-UVM-HAL-table-and-static-parent-resolution",
            "parent_resolution_algorithm_verified": True,
            "r580": {
                "table_rows": len(r580_fault_rows),
                "gv100_present": gv100_arch in r580_fault_rows,
                "gv100_parent": r580_fault_rows[gv100_arch]["parent_id"],
                "resolved_gv100": r580_fault_resolved[gv100_arch],
                "gb100_parent": r580_fault_rows[gb100_arch]["parent_id"],
                "resolved_gb100": r580_fault_resolved[gb100_arch],
            },
            "r595": {
                "table_rows": len(r595_fault_rows),
                "gv100_present": gv100_arch in r595_fault_rows,
                "tu100_present": tu100_arch in r595_fault_rows,
                "gb100_parent": r595_fault_rows[gb100_arch]["parent_id"],
                "resolved_gb100": r595_fault_resolved[gb100_arch],
            },
            "entry_size_constants": {
                "r580_nvb069_fault_buf_size": r580_nvb069_size,
                "r580_nvc369_buf_size": r580_nvc369_size,
                "r595_nvc369_buf_size": r595_nvc369_size,
                "resolved_r580_gv100_entry_size_symbol": r580_fault_entry_size_symbol,
                "resolved_r595_gb100_entry_size_symbol": r595_fault_entry_size_symbol,
                "numerical_sizes_equal": r580_nvb069_size == r580_nvc369_size == r595_nvc369_size,
            },
            "hardware_validated": False,
        },
        "fault_hal_callback_delta": fault_hal_callback_delta,
        "adapters": {
            "p2p": "passed: translates R580/R595 link enum, BAR1 classification, stable fields; PCIe atomics default false",
            "copy_engines": "passed: copies the R580 capability prefix and explicitly defaults R595 scrub=false",
            "retained_channel": "passed: translates the old runlist base to base+0x90 and CHID[11:0] token",
            "pma_statistics": "passed: preserves the live R580 pointer; pinned R595 runtime reads only shared prefix counters at offsets 8 and 16",
            "event_callbacks": "passed: adapts the exact R595 5-slot Linux table into the R580 7-slot table, in legacy field order, with startDevice/stopDevice NULL",
        },
        "pma_runtime_fields_read": pma_fields_read,
        "r580_doorbell": {
            "offset": old_doorbell_offset.group(1),
            "chid_field": old_chid_field.group(1),
            "source_mapping_found": True,
        },
        "adapter_fixture_output": adapter_output,
        "event_adapter_fixture_output": event_adapter_output,
        "inputs": {name: {"path": str(path), "sha256": sha256(path)}
                   for name, path in source_files.items()},
        "limitations": [
            "No NVIDIA RM function or proprietary R580 binary was executed by this audit.",
            "No kernel module was loaded and no GPU was accessed.",
            "The event fixture validates callback-pointer mapping but does not invoke the callbacks or prove their runtime lifetime behavior.",
            "R580/R595 UvmGpuInfo layouts and UvmGpuPlatformInfo declarations match statically; no registration call, proprietary RM path, GPU initialization, or Volta HAL was exercised.",
            "R580/R595 UvmGpuFbInfo layout and source-level GetFbInfo field reads match; no RM-returned memory values or FB/BAR1 mapping was exercised.",
            "R580/R595 PMA option layout, PmaAllocPages prototype, selected UVM field accesses, and selected allocation-bit values match statically; no proprietary PMA allocator or allocation was executed.",
            "R580/R595 UvmGpuFaultInfo, metadata-packet, CSL-context layouts, selected fault API prototypes, and direct UVM field-access sets match in the pinned host-compiler/source audit; no RM fault-buffer provider, hardware fault, interrupt, decryption, or fault packet lifecycle was executed.",
            "The R580/R595 HAL table comparison is static: R580 has a GV100 entry with Volta callbacks and R595 has no GV100 entry; the modeled callback maps follow the source parent-copy routine. Matching 32-byte entry-size macros and common C369 parser storage do not prove hardware packet semantics or Volta compatibility with the R595 RM.",
            "The Volta/Turing common parser and normalized fault-type decoder match in the pinned source audit. The MMU-engine decoder source differs in its HOST13/HOST14 limit and BAR1 enum/graphics guard; those source/header facts do not establish the runtime meaning of fault IDs or justify copying a callback across RM branches.",
            "This proves pinned source layout and CPU conversion contracts only; hardware runtime remains unvalidated.",
        ],
    }
    output = args.report.resolve()
    require(not output.exists(), f"report path already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    temporary.replace(output)
    print(json.dumps({"status": report["status"], "report": str(output),
                      "layout": report["layout"],
                      "adapter_fixture_output": adapter_output,
                      "event_adapter_fixture_output": event_adapter_output}, indent=2))


if __name__ == "__main__":
    main()
