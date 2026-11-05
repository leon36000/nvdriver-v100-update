#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed source audit for R595 SYS_NON_COHERENT BAR1 consumers.

The audit checks the path from BAR1 peer-aperture selection through peer
address detection, Volta MMU/CE callbacks, and the internal-memory locations
that must remain coherent SYS or VID. It is static evidence only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_volta_uvm_port import (  # noqa: E402
    _mask_c_comments,
    _matching_c_brace,
)


DEFAULT_R595 = Path("/usr/src/nvidia-595.99.02/nvidia-uvm")
DEFAULT_R580 = ROOT / "build/experiments/r580-uvm-standard-module-private-frontend-v1-20261027T220300Z/NVIDIA-kernel-module-source-580.178.04/kernel-open/nvidia-uvm"
DEFAULT_CANDIDATE = ROOT / "build/experiments/r595-gv100-hal-standard-nvidia-frontend-v11-20261027T233405Z/nvidia-uvm"
P2P_ABI_ADAPTER = ROOT / "src/hybrid580_uvm_abi_compat.h"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read(root: Path, name: str) -> str:
    path = (root / name).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"expected source file: {path}")
    return path.read_text(encoding="utf-8")


def extract_function(source: str, symbol: str) -> tuple[str, int]:
    """Return one function body and its source line; reject ambiguity."""
    masked = _mask_c_comments(source)
    pattern = re.compile(rf"\b{re.escape(symbol)}\s*\([^;{{}}]*\)\s*\{{")
    matches = list(pattern.finditer(masked))
    if len(matches) != 1:
        raise ValueError(f"expected one definition of {symbol}, found {len(matches)}")
    match = matches[0]
    opening = match.end() - 1
    closing = _matching_c_brace(source, opening)
    line = masked.count("\n", 0, match.start()) + 1
    return source[opening + 1:closing], line


def extract_table(source: str, table_name: str) -> str:
    masked = _mask_c_comments(source)
    pattern = re.compile(rf"\b{re.escape(table_name)}\s*\[\s*\]\s*=\s*\{{")
    matches = list(pattern.finditer(masked))
    if len(matches) != 1:
        raise ValueError(f"expected one table {table_name}, found {len(matches)}")
    opening = matches[0].end() - 1
    closing = _matching_c_brace(source, opening)
    return source[opening + 1:closing]


def extract_ops_row(table: str, class_id: str, ops_field: str) -> str:
    masked = _mask_c_comments(table)
    class_match = re.search(rf"\.id\s*=\s*{re.escape(class_id)}\b", masked)
    if class_match is None:
        raise ValueError(f"missing {class_id} row")
    initializer = re.search(rf"\.u\.{re.escape(ops_field)}\s*=\s*\{{", masked[class_match.end():])
    if initializer is None:
        raise ValueError(f"missing {ops_field} initializer for {class_id}")
    opening = class_match.end() + initializer.end() - 1
    closing = _matching_c_brace(table, opening)
    return table[opening + 1:closing]


def require_tokens(body: str, label: str, tokens: tuple[str, ...]) -> dict:
    missing = [token for token in tokens if token not in body]
    if missing:
        raise ValueError(f"source contract failed: {label}; missing {missing}")
    return {"status": "passed", "required_tokens": list(tokens)}


def _assert_source_identity(source_root: Path, candidate_root: Path, names: tuple[str, ...], label: str) -> dict:
    rows = {}
    for name in names:
        source_path = source_root / name
        candidate_path = candidate_root / name
        source_hash = sha256_file(source_path)
        candidate_hash = sha256_file(candidate_path)
        if source_hash != candidate_hash:
            raise ValueError(f"source contract failed: {label} drift for {name}")
        rows[name] = {"sha256": source_hash, "matches_candidate": True}
    return rows


def _count_open_rm_p2p_definitions(kernel_open_root: Path) -> tuple[int, int]:
    """Count definitions of the RM P2P producer in pinned open C sources."""
    definition = re.compile(
        r"\brm_gpu_ops_get_p2p_caps\s*\([^;{}]*\)\s*\{", re.DOTALL
    )
    files_scanned = 0
    definitions = 0
    for path in sorted(kernel_open_root.rglob("*.c")):
        if path.is_symlink():
            continue
        files_scanned += 1
        source = path.read_text(encoding="utf-8", errors="replace")
        definitions += len(definition.findall(_mask_c_comments(source)))
    return files_scanned, definitions


def audit(r595_root: Path, r580_root: Path, candidate_root: Path) -> dict:
    r595_root = r595_root.resolve(strict=True)
    r580_root = r580_root.resolve(strict=True)
    candidate_root = candidate_root.resolve(strict=True)
    r595_open_root = r595_root.parent
    r595_interface_path = r595_open_root / "nvidia/nv_uvm_interface.c"
    r595_rm_ops_path = r595_open_root / "common/inc/rm-gpu-ops.h"
    candidate_open_root = candidate_root.parent
    candidate_interface_path = candidate_open_root / "nvidia/nv_uvm_interface.c"
    candidate_rm_ops_path = candidate_open_root / "common/inc/rm-gpu-ops.h"
    for path in (r595_interface_path, r595_rm_ops_path,
                 candidate_interface_path, candidate_rm_ops_path,
                 P2P_ABI_ADAPTER):
        if not path.is_file():
            raise ValueError(f"expected P2P source boundary file: {path}")

    r595_unmodified = (
        "uvm_gpu.c",
        "uvm_mmu.c",
        "uvm_pte_batch.c",
        "uvm_hal_types.h",
        "uvm_get_rm_ptes_test.c",
    )
    r580_legacy = ("uvm_volta_fault_buffer.c",)
    source_identity = {
        "R595.99.02": _assert_source_identity(r595_root, candidate_root, r595_unmodified, "R595 consumer source"),
        "R580.178.04": _assert_source_identity(r580_root, candidate_root, r580_legacy, "R580 Volta legacy source"),
    }

    gpu = _read(candidate_root, "uvm_gpu.c")
    mmu = _read(candidate_root, "uvm_mmu.c")
    pte_batch = _read(candidate_root, "uvm_pte_batch.c")
    hal_types = _read(candidate_root, "uvm_hal_types.h")
    hal = _read(candidate_root, "uvm_hal.c")
    rm_ptes_test = _read(candidate_root, "uvm_get_rm_ptes_test.c")
    volta_fault = _read(candidate_root, "uvm_volta_fault_buffer.c")
    volta_mmu = _read(candidate_root, "uvm_volta_mmu.c")
    volta_ce = _read(candidate_root, "uvm_volta_ce.c")
    maxwell_ce = _read(candidate_root, "uvm_maxwell_ce.c")
    r595_interface = r595_interface_path.read_text(encoding="utf-8")
    r595_rm_ops = r595_rm_ops_path.read_text(encoding="utf-8")
    candidate_interface = candidate_interface_path.read_text(encoding="utf-8")
    candidate_rm_ops = candidate_rm_ops_path.read_text(encoding="utf-8")
    p2p_adapter = P2P_ABI_ADAPTER.read_text(encoding="utf-8")

    checks = {}
    body, line = extract_function(gpu, "parent_gpu_peer_aperture")
    checks["bar1_aperture_selection"] = require_tokens(body, "parent_gpu_peer_aperture", (
        "parent_peer_caps->link_type == UVM_GPU_LINK_PCIE_BAR1",
        "bar1_p2p_pcie_atomics_enabled[peer_index]",
        "return enable_atomics ? UVM_APERTURE_SYS : UVM_APERTURE_SYS_NON_COHERENT",
    ))
    checks["bar1_aperture_selection"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(gpu, "uvm_gpu_peer_phys_address")
    checks["bar1_physical_address"] = require_tokens(body, "uvm_gpu_peer_phys_address", (
        "else if (uvm_aperture_is_sys(aperture))",
        "UVM_GPU_LINK_PCIE_BAR1",
        "bar1_p2p_dma_base_address[peer_index]",
        "return uvm_gpu_phys_address(aperture, address)",
    ))
    checks["bar1_physical_address"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(gpu, "gpu_phys_address_is_bar1p2p_peer")
    checks["bar1_peer_range_detection"] = require_tokens(body, "gpu_phys_address_is_bar1p2p_peer", (
        "uvm_aperture_is_sys(address.aperture)",
        "UVM_GPU_LINK_PCIE_BAR1",
        "bar1_p2p_dma_base_address[peer_index]",
        "bar1_p2p_dma_size[peer_index]",
    ))
    checks["bar1_peer_range_detection"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(gpu, "uvm_gpu_address_is_peer")
    checks["peer_classification_accepts_sys_apertures"] = require_tokens(body, "uvm_gpu_address_is_peer", (
        "uvm_aperture_is_sys(address.aperture)",
        "gpu_address_is_coherent_peer(gpu, phys_addr)",
        "gpu_phys_address_is_bar1p2p_peer(gpu, phys_addr)",
    ))
    checks["peer_classification_accepts_sys_apertures"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(hal_types, "uvm_aperture_is_sys")
    checks["system_aperture_predicate"] = require_tokens(body, "uvm_aperture_is_sys", (
        "aperture == UVM_APERTURE_SYS",
        "aperture == UVM_APERTURE_SYS_NON_COHERENT",
    ))
    checks["system_aperture_predicate"]["source"] = f"uvm_hal_types.h:{line}"

    body, line = extract_function(mmu, "mmu_biggest_page_size")
    checks["bar1_mapping_page_size"] = require_tokens(mmu, "mmu_biggest_page_size BAR1 contract", (
        "UVM_APERTURE_SYS_NON_COHERENT       biggest page size on BAR1 mappings",
    ))
    checks["bar1_mapping_page_size"]["source"] = f"uvm_mmu.c:{line}"

    body, line = extract_function(mmu, "phys_mem_allocate")
    checks["page_table_storage_aperture"] = require_tokens(body, "phys_mem_allocate", (
        "location == UVM_APERTURE_VID",
        "location == UVM_APERTURE_SYS",
        "UVM_ASSERT",
    ))
    checks["page_table_storage_aperture"]["source"] = f"uvm_mmu.c:{line}"

    for symbol in ("uvm_pte_batch_write_ptes", "uvm_pte_batch_write_pte", "uvm_pte_batch_clear_ptes"):
        body, line = extract_function(pte_batch, symbol)
        checks[f"{symbol}_rejects_noncoherent_storage"] = require_tokens(body, symbol, (
            "UVM_APERTURE_SYS_NON_COHERENT",
            "UVM_ASSERT",
        ))
        checks[f"{symbol}_rejects_noncoherent_storage"]["source"] = f"uvm_pte_batch.c:{line}"

    body, line = extract_function(gpu, "instance_ptr_to_key")
    checks["channel_instance_aperture"] = require_tokens(body, "instance_ptr_to_key", (
        "instance_ptr.aperture == UVM_APERTURE_SYS",
        "instance_ptr.aperture == UVM_APERTURE_VID || instance_ptr.aperture == UVM_APERTURE_SYS",
        "UVM_ASSERT",
    ))
    checks["channel_instance_aperture"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(volta_fault, "get_fault_inst_aperture")
    checks["fault_instance_noncoherent_normalization"] = require_tokens(body, "get_fault_inst_aperture", (
        "NVC369_BUF_ENTRY_INST_APERTURE_SYS_MEM_NONCOHERENT",
        "NVC369_BUF_ENTRY_INST_APERTURE_SYS_MEM_COHERENT",
        "return UVM_APERTURE_SYS",
    ))
    checks["fault_instance_noncoherent_normalization"]["source"] = f"uvm_volta_fault_buffer.c:{line}"

    body, line = extract_function(volta_mmu, "make_pte_volta")
    checks["volta_pte_noncoherent_encoding"] = require_tokens(body, "make_pte_volta", (
        "UVM_APERTURE_SYS_NON_COHERENT",
        "NV_MMU_VER2_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY",
        "ADDRESS_SYS",
    ))
    checks["volta_pte_noncoherent_encoding"]["source"] = f"uvm_volta_mmu.c:{line}"

    volta_ce_aperture, line = extract_function(volta_ce, "ce_aperture")
    checks["volta_c3b5_memset_aperture"] = require_tokens(volta_ce_aperture, "Volta C3B5 ce_aperture", (
        "C3B5",
        "aperture == UVM_APERTURE_SYS_NON_COHERENT",
        "NONCOHERENT_SYSMEM",
    ))
    checks["volta_c3b5_memset_aperture"]["source"] = f"uvm_volta_ce.c:{line}"

    maxwell_ce_aperture, line = extract_function(maxwell_ce, "ce_aperture")
    checks["maxwell_b0b5_memcopy_aperture"] = require_tokens(maxwell_ce_aperture, "Maxwell B0B5 ce_aperture", (
        "B0B5",
        "aperture == UVM_APERTURE_SYS_NON_COHERENT",
        "NONCOHERENT_SYSMEM",
    ))
    checks["maxwell_b0b5_memcopy_aperture"]["source"] = f"uvm_maxwell_ce.c:{line}"

    ce_table = extract_table(hal, "ce_table")
    volta_ce_row = extract_ops_row(ce_table, "VOLTA_DMA_COPY_A", "ce_ops")
    checks["volta_memcopy_uses_shared_maxwell_phys_mode"] = require_tokens(volta_ce_row, "VOLTA_DMA_COPY_A ce_ops", (
        ".phys_mode = uvm_hal_maxwell_ce_phys_mode",
        ".memcopy = uvm_hal_volta_ce_memcopy",
    ))

    access_table = extract_table(hal, "access_counter_buffer_table")
    volta_access_row = extract_ops_row(access_table, "NV2080_CTRL_MC_ARCH_INFO_ARCHITECTURE_GV100", "access_counter_buffer_ops")
    checks["volta_access_counter_callbacks_fail_closed"] = require_tokens(volta_access_row, "GV100 access counter HAL row", (
        "uvm_hal_maxwell_enable_access_counter_notifications_unsupported",
        "uvm_hal_maxwell_access_counter_buffer_parse_entry_unsupported",
        "uvm_hal_maxwell_access_counter_buffer_entry_size_unsupported",
    ))

    body, line = extract_function(rm_ptes_test, "get_aperture")
    checks["system_noncoherent_test_fixture"] = require_tokens(body, "get_aperture test fixture", (
        "UVM_APERTURE_SYS_NON_COHERENT",
        "UVM_APERTURE_SYS",
    ))
    checks["system_noncoherent_test_fixture"]["source"] = f"uvm_get_rm_ptes_test.c:{line}"

    body, line = extract_function(gpu, "get_parent_p2p_caps")
    checks["p2p_caps_query_orders_handles_and_clears_output"] = require_tokens(
        body, "get_parent_p2p_caps", (
            "uvm_parent_id_value(parent_gpu0->id) < uvm_parent_id_value(parent_gpu1->id)",
            "memset(p2p_caps_params, 0, sizeof(*p2p_caps_params))",
            "uvm_rm_locked_call(nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, p2p_caps_params))",
            "if (status != NV_OK)",
        ))
    checks["p2p_caps_query_orders_handles_and_clears_output"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(gpu, "parent_peers_init")
    checks["p2p_caps_consumer_copies_directional_bar1_and_atomics"] = require_tokens(
        body, "parent_peers_init", (
            "create_parent_p2p_object(parent_gpu0, parent_gpu1, &p2p_handle)",
            "get_parent_p2p_caps(parent_gpu0, parent_gpu1, &p2p_caps_params)",
            "parent_peer_caps->bar1_p2p_dma_base_address[0] = p2p_caps_params.bar1DmaAddress[0]",
            "parent_peer_caps->bar1_p2p_dma_base_address[1] = p2p_caps_params.bar1DmaAddress[1]",
            "parent_peer_caps->bar1_p2p_dma_size[0] = p2p_caps_params.bar1DmaSize[0]",
            "parent_peer_caps->bar1_p2p_dma_size[1] = p2p_caps_params.bar1DmaSize[1]",
            "parent_peer_caps->bar1_p2p_pcie_atomics_enabled[0] = p2p_caps_params.bar1PcieAtomics[0]",
            "parent_peer_caps->bar1_p2p_pcie_atomics_enabled[1] = p2p_caps_params.bar1PcieAtomics[1]",
            "UVM_ASSERT(link_type == UVM_GPU_LINK_PCIE_BAR1)",
        ))
    checks["p2p_caps_consumer_copies_directional_bar1_and_atomics"]["source"] = f"uvm_gpu.c:{line}"

    body, line = extract_function(r595_interface, "nvUvmInterfaceGetP2PCaps")
    checks["p2p_caps_interface_reaches_rm_provider"] = require_tokens(
        body, "nvUvmInterfaceGetP2PCaps", (
            "nv_kmem_cache_alloc_stack(&sp)",
            "rm_gpu_ops_get_p2p_caps(sp,",
            "(gpuDeviceHandle)device1",
            "(gpuDeviceHandle)device2",
            "p2pCapsParams",
            "nv_kmem_cache_free_stack(sp)",
        ))
    if "EXPORT_SYMBOL(nvUvmInterfaceGetP2PCaps);" not in r595_interface:
        raise ValueError("source contract failed: nvUvmInterfaceGetP2PCaps export")
    checks["p2p_caps_interface_reaches_rm_provider"]["source"] = f"nvidia/nv_uvm_interface.c:{line}"

    rm_prototype = re.compile(
        r"\bNV_STATUS\s+NV_API_CALL\s+rm_gpu_ops_get_p2p_caps\s*\([^;{}]*\)\s*;"
    )
    rm_declarations = len(rm_prototype.findall(_mask_c_comments(r595_rm_ops)))
    provider_files_scanned, provider_definitions = _count_open_rm_p2p_definitions(r595_open_root)
    if rm_declarations != 1 or provider_definitions != 0:
        raise ValueError(
            "source contract failed: expected one open RM P2P declaration and no open C definition "
            f"(declarations={rm_declarations}, definitions={provider_definitions})"
        )
    checks["p2p_rm_core_is_proprietary_boundary"] = {
        "status": "passed",
        "declaration_count": rm_declarations,
        "open_c_definitions": provider_definitions,
        "open_c_files_scanned": provider_files_scanned,
        "source": "common/inc/rm-gpu-ops.h",
    }

    body, line = extract_function(p2p_adapter, "hybrid580_uvm_r580_link_type_to_r595")
    legacy_link_check = require_tokens(
        body, "hybrid580_uvm_r580_link_type_to_r595", (
            "if (has_bar1_dma)",
            "r580_link_type != HYBRID580_R580_LINK_TYPE_PCIE",
            "*r595_link_type = UVM_LINK_TYPE_PCIE_BAR1",
            "HYBRID580_R580_LINK_TYPE_NVLINK_1",
            "UVM_LINK_TYPE_NVLINK_1",
            "HYBRID580_R580_LINK_TYPE_C2C",
            "UVM_LINK_TYPE_C2C",
        ))
    body, line = extract_function(p2p_adapter, "hybrid580_uvm_p2p_caps_from_r580")
    legacy_fields_check = require_tokens(
        body, "hybrid580_uvm_p2p_caps_from_r580", (
            "r595->bar1DmaAddress[0] = r580->bar1DmaAddress[0]",
            "r595->bar1DmaAddress[1] = r580->bar1DmaAddress[1]",
            "r595->bar1DmaSize[0] = r580->bar1DmaSize[0]",
            "r595->bar1DmaSize[1] = r580->bar1DmaSize[1]",
            "r595->bar1PcieAtomics[0] = NV_FALSE",
            "r595->bar1PcieAtomics[1] = NV_FALSE",
        ))
    checks["r580_p2p_adapter_maps_bar1_and_disables_unknown_atomics"] = {
        "status": "passed",
        "link_type_mapping": legacy_link_check["required_tokens"],
        "capability_field_mapping": legacy_fields_check["required_tokens"],
        "source": f"hybrid580_uvm_abi_compat.h:{line}",
    }

    if r595_interface != candidate_interface or r595_rm_ops != candidate_rm_ops:
        raise ValueError("source identity failed: candidate P2P interface differs from pinned R595")

    tracked = sorted(set(r595_unmodified + r580_legacy + (
        "uvm_volta_mmu.c", "uvm_volta_ce.c", "uvm_maxwell_ce.c",
    )))
    input_hashes = {
        f"candidate/{name}": sha256_file(candidate_root / name)
        for name in tracked
    }
    input_hashes["R595.99.02/uvm_gpu.c"] = sha256_file(r595_root / "uvm_gpu.c")
    input_hashes["R580.178.04/uvm_volta_fault_buffer.c"] = sha256_file(r580_root / "uvm_volta_fault_buffer.c")
    input_hashes["R595.99.02/nvidia/nv_uvm_interface.c"] = sha256_file(r595_interface_path)
    input_hashes["R595.99.02/common/inc/rm-gpu-ops.h"] = sha256_file(r595_rm_ops_path)
    input_hashes["candidate/nvidia/nv_uvm_interface.c"] = sha256_file(candidate_interface_path)
    input_hashes["candidate/common/inc/rm-gpu-ops.h"] = sha256_file(candidate_rm_ops_path)
    input_hashes["project/src/hybrid580_uvm_abi_compat.h"] = sha256_file(P2P_ABI_ADAPTER)

    return {
        "schema": "r595-noncoherent-bar1-consumer-audit-v3",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "scope": "pinned R595 UVM source consumers and R580 Volta callbacks staged in the v11 candidate",
        "qualification": "static-source-only",
        "runtime_or_hardware_validated": False,
        "module_loaded_or_installed": False,
        "roots": {
            "r595": str(r595_root),
            "r580": str(r580_root),
            "candidate": str(candidate_root),
        },
        "source_identity": source_identity,
        "source_hashes": input_hashes,
        "p2p_rm_boundary": {
            "api": "nvUvmInterfaceGetP2PCaps -> rm_gpu_ops_get_p2p_caps",
            "open_implementation_found": provider_definitions != 0,
            "open_c_files_scanned": provider_files_scanned,
            "interpretation": "R595 open UVM marshals the request; the P2P capability producer is not implemented in the pinned open C source set.",
            "gv100_return_values": "unknown; requires runtime observation through an initialized R595 RM peer pair",
        },
        "checks": checks,
        "conclusion": [
            "R595 selects SYS_NON_COHERENT for PCIe BAR1 peer addresses when the consolidated peer atomic capability is disabled.",
            "The Volta candidate carries this aperture through P2P recognition, its GV100 PTE encoder, and both dispatched CE physical-mode helpers.",
            "PTE/page-table storage and channel instance pointers retain SYS/VID-only invariants; Volta fault-buffer instance apertures normalize hardware SYS_NONCOHERENT to UVM_APERTURE_SYS.",
            "GV100 access-counter callbacks remain explicitly unsupported, so the Turing access-counter noncoherent parser is not inherited by Volta.",
            "R595 UVM orders the RM device handles, clears the output packet, and copies per-direction BAR1 windows and PCIe atomics from RM; the open source stops at the rm_gpu_ops_get_p2p_caps declaration/call.",
            "The R580 bridge maps legacy PCIe plus a nonempty BAR1 window to R595 PCIE_BAR1 and keeps both unreported PCIe-atomics bits false; actual Volta capability values are not inferred.",
        ],
        "limits": [
            "No Resource Manager mapping, PCIe BAR1 transaction, CE command, PTE installation, UVM migration, or GPU execution was tested.",
            "Static source compatibility does not establish R595 RM support for GV100 or same-process V100 plus Blackwell CUDA.",
            "The host peer harness exercises exact open UVM address/range functions with synthetic capability records; it does not produce those records through RM or test PCIe transactions.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r595-root", type=Path, default=DEFAULT_R595)
    parser.add_argument("--r580-root", type=Path, default=DEFAULT_R580)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATE)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        report = audit(args.r595_root, args.r580_root, args.candidate_root)
    except (OSError, ValueError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 2

    args.report.parent.mkdir(parents=True, exist_ok=True)
    previous_umask = os.umask(0o077)
    try:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        args.report.chmod(0o600)
    finally:
        os.umask(previous_umask)

    print(f"{report['schema']}: {len(report['checks'])} source-contract checks passed")
    print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
