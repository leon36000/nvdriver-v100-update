#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage and compile a complete, source-derived GV100 fault HAL row in R595.

This is an isolated compile probe. It never installs or loads a module and it
does not add GV100 to R595's architecture, host, MMU, CE, or RM tables. A
successful UVM link therefore proves callback type/link closure only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_hybrid_uvm_abi import (  # noqa: E402
    FAULT_HAL_OPERATIONS,
    c_function_definition,
    parse_fault_hal_table,
    sha256,
)
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    DEFAULT_R595_SOURCE,
    R580_SOURCE_ROOT,
    build_overlay,
    prepare_overlay,
    read_member,
    source_archive_root,
)

DEFAULT_R580_ARCHIVE = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
GV100_ARCH = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100"
TU100_ARCH = "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_TU100"
PASCAL_PREFIX = "uvm_hal_pascal_"
VOLTA_PREFIX = "uvm_hal_volta_"
PASCAL_COMPAT_HEADER = "uvm_pascal_compat_clb069.h"
PASCALE_FAULT_FILES = (
    "uvm_pascal_fault_buffer.c",
    "uvm_pascal_fault_buffer.h",
    "hwref/pascal/gp100/dev_fault.h",
    "clb069.h",
)
PROTOTYPE_RETURN_TYPES = (
    "NV_STATUS", "NvU32", "NvU8", "bool", "void",
    "uvm_fault_type_t", "uvm_mmu_engine_type_t",
)
FAULT_CALLBACKS = {
    "enable_replayable_faults": "uvm_hal_pascal_enable_replayable_faults",
    "disable_replayable_faults": "uvm_hal_pascal_disable_replayable_faults",
    "clear_replayable_faults": "uvm_hal_pascal_clear_replayable_faults",
    "read_put": "uvm_hal_volta_fault_buffer_read_put",
    "read_get": "uvm_hal_volta_fault_buffer_read_get",
    "write_get": "uvm_hal_volta_fault_buffer_write_get",
    "get_ve_id": "uvm_hal_volta_fault_buffer_get_ve_id",
    "get_mmu_engine_type": "uvm_hal_volta_fault_buffer_get_mmu_engine_type",
    "parse_replayable_entry": "uvm_hal_volta_fault_buffer_parse_replayable_entry",
    "entry_is_valid": "uvm_hal_pascal_fault_buffer_entry_is_valid",
    "entry_clear_valid": "uvm_hal_pascal_fault_buffer_entry_clear_valid",
    "entry_size": "uvm_hal_pascal_fault_buffer_entry_size",
    "parse_non_replayable_entry": "uvm_hal_volta_fault_buffer_parse_non_replayable_entry",
    "get_fault_type": "uvm_hal_volta_fault_buffer_get_fault_type",
}


def extract_archived_r580_uvm(archive_path: Path, destination: Path,
                              expected_root: str = R580_SOURCE_ROOT) -> Path:
    """Extract only the audited UVM inputs; reject paths outside the archive root."""
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:*") as archive:
        root = source_archive_root(archive, expected_root)
        uvm_root = destination / "nvidia-uvm"
        uvm_root.mkdir()
        required = (
            "uvm_hal.c", "uvm_hal.h", "uvm_volta_fault_buffer.c",
            *PASCALE_FAULT_FILES,
        )
        for relative in required:
            data = read_member(archive, root + "/kernel-open/nvidia-uvm/" + relative)
            output = uvm_root / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
    return uvm_root


def extract_prototype(header: Path, symbol: str) -> str:
    text = header.read_text()
    return_type = "|".join(map(re.escape, PROTOTYPE_RETURN_TYPES))
    matches = re.findall(
        r"\b(?:" + return_type + r")\s+" + re.escape(symbol) +
        r"\s*\([^;]*?\)\s*;", text, re.DOTALL)
    if len(matches) != 1:
        raise ValueError(
            f"expected one R580 prototype for {symbol}; found {len(matches)}"
        )
    prototype = re.sub(r"/\*.*?\*/|//[^\n]*", "", matches[0], flags=re.DOTALL)
    return re.sub(r"\s+", " ", prototype).strip()


def _callback_source(symbol: str) -> str:
    if symbol.startswith(PASCAL_PREFIX):
        return "uvm_pascal_fault_buffer.c"
    if symbol.startswith(VOLTA_PREFIX):
        return "uvm_volta_fault_buffer.c"
    raise ValueError(f"callback is outside the audited Volta/Pascal source set: {symbol}")


def _candidate_row(callbacks: dict[str, str]) -> str:
    assignments = "\n".join(
        f"            .{operation} = {callbacks[operation]},"
        for operation in FAULT_HAL_OPERATIONS
    )
    return (
        "    {\n"
        f"        .id = {GV100_ARCH},\n"
        "        .u.fault_buffer_ops = {\n"
        f"{assignments}\n"
        "        }\n"
        "    },\n"
    )


def callback_symbol_audit(nm_output: str, callbacks: dict[str, str]) -> dict:
    """Check that every candidate callback is a defined global ELF symbol."""
    defined = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol_type, symbol_name = fields[-2], fields[-1]
        # nm uses U/u and lowercase w/v for unresolved symbols. The production
        # invocation also passes --defined-only; filtering here makes the
        # parser fail closed when fixtures or tool behavior include undefineds.
        if symbol_type not in {"U", "u", "w", "v"}:
            defined.add(symbol_name)
    expected = set(callbacks.values())
    matched = sorted(expected & defined)
    missing = sorted(expected - defined)
    return {
        "expected_count": len(expected),
        "defined_callbacks": matched,
        "missing_callbacks": missing,
        "verified": len(expected) == 14 and not missing,
    }
def stage_fault_hal_candidate(r580_uvm: Path,
                              r595_uvm: Path,
                              callbacks: dict[str, str]) -> dict:
    """Copy real R580 implementations and add one complete no-parent R595 row."""
    r580_uvm = Path(r580_uvm).resolve(strict=True)
    r595_uvm = Path(r595_uvm).resolve(strict=True)
    if set(callbacks) != set(FAULT_HAL_OPERATIONS) or len(callbacks) != 14:
        raise ValueError("candidate requires exactly 14 fault HAL operations")
    if len(set(callbacks.values())) != 14:
        raise ValueError("candidate callback symbols must be unique")
    if callbacks != FAULT_CALLBACKS:
        raise ValueError("candidate callback map differs from pinned R580 GV100 resolution")

    source_for_symbol = {}
    for symbol in callbacks.values():
        source_name = _callback_source(symbol)
        source = r580_uvm / source_name
        try:
            c_function_definition(source, symbol)
        except RuntimeError as exc:
            raise ValueError(f"missing callback implementation: {symbol}") from exc
        source_for_symbol[symbol] = source_name

    prototypes = [extract_prototype(r580_uvm / "uvm_hal.h", symbol)
                  for symbol in callbacks.values()]
    source_list_path = r595_uvm / "nvidia-uvm-sources.Kbuild"
    source_list = source_list_path.read_text()
    source_anchor = "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_tracker.c\n"
    if source_list.count(source_anchor) != 1:
        raise ValueError("R595 UVM Kbuild source-list anchor is not unique")
    pascal_entry = "NVIDIA_UVM_SOURCES += nvidia-uvm/uvm_pascal_fault_buffer.c\n"
    if pascal_entry in source_list:
        raise ValueError("R595 source list already contains the Pascal fault implementation")

    header_path = r595_uvm / "uvm_hal.h"
    header = header_path.read_text()
    hal_struct_anchor = "struct uvm_fault_buffer_hal_struct\n{"
    if header.count(hal_struct_anchor) != 1:
        raise ValueError("R595 fault HAL struct declaration anchor is not unique")
    if any(re.search(r"\b" + re.escape(symbol) + r"\s*\(", header)
           for symbol in callbacks.values()):
        raise ValueError("R595 HAL header already declares a candidate callback symbol")

    hal_path = r595_uvm / "uvm_hal.c"
    hal_source = hal_path.read_text()
    table_match = re.search(
        r"static\s+uvm_hal_class_ops_t\s+fault_buffer_table\s*\[\s*\]\s*=\s*\{",
        hal_source)
    if table_match is None:
        raise ValueError("R595 fault_buffer_table declaration is missing")
    table_open = hal_source.find("{", table_match.start(), table_match.end())
    depth = 0
    table_end = None
    for index in range(table_open, len(hal_source)):
        if hal_source[index] == "{":
            depth += 1
        elif hal_source[index] == "}":
            depth -= 1
            if depth == 0:
                table_end = index + 1
                break
    if table_end is None:
        raise ValueError("R595 fault_buffer_table braces are unbalanced")
    table_source = hal_source[table_match.start():table_end]
    if GV100_ARCH in table_source:
        raise ValueError("R595 fault_buffer_table already contains GV100")
    tu_row = re.search(
        r"(?m)^\s*\{\s*\n\s*\.id\s*=\s*" + re.escape(TU100_ARCH) + r"\s*,",
        table_source)
    if tu_row is None:
        raise ValueError("R595 Turing fault HAL row anchor is missing")

    pascal_source = (r580_uvm / "uvm_pascal_fault_buffer.c").read_text()
    clb069_include = '#include "clb069.h"'
    if pascal_source.count(clb069_include) != 1:
        raise ValueError("R580 Pascal fault source does not have one exact clb069 include")

    # Preflight the complete copy set before the first destination write.
    copy_plan = []
    copied_hashes = {}
    for relative in PASCALE_FAULT_FILES:
        source = r580_uvm / relative
        destination = (r595_uvm / PASCAL_COMPAT_HEADER if relative == "clb069.h"
                      else r595_uvm / relative)
        data = source.read_bytes()
        if relative == "uvm_pascal_fault_buffer.c":
            data = data.replace(
                clb069_include.encode(),
                f'#include "{PASCAL_COMPAT_HEADER}"'.encode(),
            )
        if destination.exists():
            if relative not in ("uvm_pascal_fault_buffer.h",
                                "hwref/pascal/gp100/dev_fault.h") or \
                    destination.read_bytes() != data:
                raise FileExistsError(f"refusing to overwrite non-identical R595 input: {destination}")
            copied_hashes[str(destination.relative_to(r595_uvm))] = hashlib.sha256(data).hexdigest()
            continue
        copy_plan.append((relative, destination, data))

    for relative, destination, data in copy_plan:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        copied_hashes[str(destination.relative_to(r595_uvm))] = hashlib.sha256(data).hexdigest()

    source_list_path.write_text(source_list.replace(
        source_anchor, source_anchor + pascal_entry, 1))
    header_path.write_text(header.replace(
        hal_struct_anchor,
        "\n".join(prototypes) + "\n\n" + hal_struct_anchor,
        1,
    ))
    candidate_row = _candidate_row(callbacks)
    insertion = table_match.start() + tu_row.start()
    hal_path.write_text(hal_source[:insertion] + candidate_row + hal_source[insertion:])

    modern_arch_table = re.search(
        r"static\s+uvm_hal_class_ops_t\s+arch_table\s*\[\s*\]\s*=\s*\{",
        hal_source)
    if modern_arch_table is None:
        raise ValueError("R595 arch_table declaration is missing")
    arch_open = hal_source.find("{", modern_arch_table.start(), modern_arch_table.end())
    arch_depth = 0
    arch_end = None
    for index in range(arch_open, len(hal_source)):
        if hal_source[index] == "{":
            arch_depth += 1
        elif hal_source[index] == "}":
            arch_depth -= 1
            if arch_depth == 0:
                arch_end = index + 1
                break
    if arch_end is None:
        raise ValueError("R595 arch_table braces are unbalanced")
    arch_has_gv100 = GV100_ARCH in hal_source[modern_arch_table.start():arch_end]

    return {
        "callback_count": len(callbacks),
        "callbacks": callbacks,
        "parent_id": None,
        "copied_source_hashes": copied_hashes,
        "callback_implementation_sources": source_for_symbol,
        "architecture_table_has_gv100": arch_has_gv100,
        "hardware_validated": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r580-archive", type=Path, default=DEFAULT_R580_ARCHIVE)
    parser.add_argument("--r595-source", type=Path, default=DEFAULT_R595_SOURCE)
    parser.add_argument("--scratch", type=Path, required=True,
                        help="new isolated source build directory; must not exist")
    parser.add_argument("--report", type=Path, required=True,
                        help="new mode-0600 JSON evidence path")
    parser.add_argument("--log", type=Path, required=True,
                        help="new mode-0600 full build-log path")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--expected-r580-sha256",
                        default=DEFAULT_EXPECTED_R580_ARCHIVE_SHA256)
    args = parser.parse_args()
    archive = args.r580_archive.resolve(strict=True)
    r595 = args.r595_source.resolve(strict=True)
    scratch = args.scratch.resolve()
    report_path = args.report.resolve()
    log_path = args.log.resolve()
    if report_path.exists() or log_path.exists():
        parser.error("refusing to overwrite an existing report or build log")

    stage_result = None
    preparation = None
    build_result = None
    error = None
    with tempfile.TemporaryDirectory(prefix="r580-gv100-fault-hal-input-") as temporary:
        r580_uvm = extract_archived_r580_uvm(archive, Path(temporary) / "r580")
        _, resolved, _ = parse_fault_hal_table(r580_uvm / "uvm_hal.c")
        callbacks = resolved.get(GV100_ARCH)
        if callbacks is None:
            raise RuntimeError("official R580 source has no resolved GV100 fault HAL")
        if callbacks != FAULT_CALLBACKS:
            raise RuntimeError("official R580 GV100 callbacks differ from pinned candidate map")

        try:
            preparation = prepare_overlay(
                archive, r595, scratch,
                expected_archive_sha256=args.expected_r580_sha256,
                compile_probe_adapter=True,
            )
            stage_result = stage_fault_hal_candidate(
                r580_uvm, scratch / "nvidia-uvm", callbacks)
            build_result = build_overlay(
                scratch, args.jobs, compile_probe_adapter=True)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            scratch_log = scratch / "uvm-port-build.log"
            if scratch_log.is_file():
                build_result = {"build_log": str(scratch_log),
                                "build_log_sha256": sha256(scratch_log),
                                "build_command_succeeded": False,
                                "module_linked_this_run": False,
                                "exception": error}

    compiled_sources = []
    if build_result and Path(build_result["build_log"]).is_file():
        compiled_sources = re.findall(
            r"^\s*CC \[M\]\s+(nvidia-uvm/[^\s]+\.o)",
            Path(build_result["build_log"]).read_text(errors="replace"), re.M)
    required_link_evidence = {
        "nvidia-uvm/uvm_hal.o",
        "nvidia-uvm/uvm_volta_fault_buffer.o",
        "nvidia-uvm/uvm_pascal_fault_buffer.o",
    }
    object_linked = bool(build_result and build_result.get("module_linked_this_run") and
                  required_link_evidence <= set(compiled_sources))
    callback_audit = None
    if object_linked and stage_result:
        module = scratch / "nvidia-uvm.ko"
        nm = subprocess.run(
            ["nm", "-g", "--defined-only", str(module)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False,
        )
        callback_audit = callback_symbol_audit(nm.stdout, stage_result["callbacks"])
        callback_audit["command"] = ["nm", "-g", "--defined-only", str(module)]
        callback_audit["exit_code"] = nm.returncode
        if nm.returncode != 0:
            callback_audit["verified"] = False
            callback_audit["error"] = nm.stdout[-4000:]
    linked = bool(object_linked and callback_audit and
                  callback_audit.get("verified") and callback_audit.get("exit_code") == 0)
    if build_result is None and error is None:
        error = "candidate staging did not produce a build result"

    copied_log_sha = None
    if build_result and Path(build_result["build_log"]).is_file():
        log_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(build_result["build_log"], log_path)
        os.chmod(log_path, 0o600)
        copied_log_sha = sha256(log_path)

    report = {
        "schema": "r595-gv100-fault-hal-candidate-v2",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed" if linked else "failed",
        "classification": "isolated-R595-UVM-compile-link-probe-only",
        "r580_archive": str(archive),
        "r580_archive_sha256": sha256(archive),
        "expected_r580_archive_sha256": args.expected_r580_sha256,
        "r580_archive_hash_matches": sha256(archive) == args.expected_r580_sha256,
        "r595_source": str(r595),
        "r595_hal_source_sha256": sha256(r595 / "nvidia-uvm/uvm_hal.c"),
        "r595_hal_header_sha256": sha256(r595 / "nvidia-uvm/uvm_hal.h"),
        "scratch": str(scratch),
        "preparation": preparation,
        "candidate": stage_result,
        "build": build_result,
        "required_objects_compiled": sorted(required_link_evidence & set(compiled_sources)),
        "callback_symbol_audit": callback_audit,
        "module_linked_with_candidate_objects": linked,
        "module_loaded": False,
        "module_installed": False,
        "hardware_validated": False,
        "architecture_table_has_gv100": (
            stage_result["architecture_table_has_gv100"] if stage_result else None),
        "uvm_fault_hal_candidate_is_runtime_selectable": False,
        "error": error,
        "build_log_copy": str(log_path),
        "build_log_sha256": copied_log_sha,
        "limitations": [
            "The candidate adds only a fault_buffer_table row; R595 arch_table still has no GV100 row, so this probe is not a selectable or usable GV100 UVM port.",
            "A successful link proves only compile/type/symbol closure for the pinned source inputs; no callback was invoked and no GPU, RM, interrupt, fault packet, or module runtime was exercised.",
            "The UVM port still has other Volta architecture, host, MMU, CE, channel, capability, and RM registration dependencies.",
        ],
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({
        "status": report["status"],
        "report": str(report_path),
        "report_sha256": sha256(report_path),
        "log": str(log_path),
        "log_sha256": copied_log_sha,
        "module_linked_with_candidate_objects": linked,
        "required_objects_compiled": report["required_objects_compiled"],
        "candidate_callbacks_defined": bool(callback_audit and callback_audit.get("verified")),
        "error": error,
    }, indent=2))
    return 0 if linked else 2


if __name__ == "__main__":
    raise SystemExit(main())
