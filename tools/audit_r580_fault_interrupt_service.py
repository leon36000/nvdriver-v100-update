#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the source-visible R580 RM interrupt-service path for UVM faults."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from audit_uvm_pm_lifecycle import function_body, strip_c_comments


SOURCE_FILES = (
    "kernel-open/common/inc/nv_uvm_types.h",
    "kernel-open/common/inc/nv_uvm_interface.h",
    "kernel-open/nvidia/nv_uvm_interface.c",
    "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080mc.h",
    "src/nvidia/arch/nvalloc/unix/src/rm-gpu-ops.c",
    "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c",
    "src/nvidia/src/kernel/gpu/intr/intr.c",
    "src/nvidia/src/kernel/gpu/intr/arch/pascal/intr_gp100.c",
    "src/nvidia/src/kernel/gpu/mmu/kern_gmmu.c",
    "src/nvidia/generated/g_subdevice_nvoc.c",
    "kernel-open/nvidia/nv.c",
    "kernel-open/nvidia/nv-procfs.c",
    "src/nvidia/arch/nvalloc/unix/src/unix_intr.c",
    "src/nvidia/generated/g_kern_gmmu_nvoc.c",
    "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c",
    "kernel-open/nvidia-uvm/uvm_gpu_isr.c",
    "kernel-open/nvidia-uvm/uvm_global.c",
    "kernel-open/nvidia/nv-msi.c",
    "src/nvidia/arch/nvalloc/unix/src/dynamic-power.c",
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _body(sources: dict[str, str], path: str, function: str) -> tuple[str, int]:
    body, line = function_body(sources[path], function)
    if isinstance(sources, _SourceMap):
        line = sources.raw_line(path, function, line)
    return body, line


class _SourceMap(dict):
    """Comment-stripped C text with offsets back to the original source bytes."""

    def __init__(self, code: dict[str, str], raw: dict[str, str],
                 source_offsets: dict[str, list[int]]):
        super().__init__(code)
        self.raw = raw
        self.source_offsets = source_offsets

    def raw_line(self, path: str, function: str, normalized_line: int) -> int:
        code = self[path]
        for match in re.finditer(rf"\b{re.escape(function)}\s*\(", code):
            if code.count("\n", 0, match.start()) + 1 != normalized_line:
                continue
            raw_position = self.source_offsets[path][match.start()]
            raw_prefix = self.raw[path][:raw_position]
            return len(re.findall(r"\r\n|\r|\n", raw_prefix)) + 1
        raise ValueError(f"source line map failed for function {function}")


def _has_call(body: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\s*\(", body) is not None


def _compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).lower()


def _normalize_setter_body(value: str) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    value = re.sub(r"\s*([(){};,])\s*", r"\1", value)
    return re.sub(r"\s*(==|<=|=|->)\s*", r"\1", value)


def _brace_depth_at(value: str, position: int) -> int:
    depth = 0
    quote = None
    escaped = False
    for character in value[:position]:
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in ("'", '"'):
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
    return depth


def _splice_c_lines(value: str) -> str:
    """Apply C translation phase 2 before comment/directive inspection."""
    return _splice_c_lines_with_offsets(value)[0]


_C_TRIGRAPHS = {
    "=": "#",
    "/": "\\",
    "'": "^",
    "(": "[",
    ")": "]",
    "!": "|",
    "<": "{",
    ">": "}",
    "-": "~",
}


def _translate_c_trigraphs_with_offsets(value: str) -> tuple[str, list[int]]:
    """Normalize physical line endings and translate C trigraphs with offsets."""
    output = []
    offsets = []
    position = 0
    while position < len(value):
        if value.startswith("\r\n", position):
            output.append("\n")
            offsets.append(position)
            position += 2
            continue
        if value[position] == "\r":
            # GCC accepts bare-CR source files as physical lines too. Treat
            # that implementation-supported form like a normalized newline.
            output.append("\n")
            offsets.append(position)
            position += 1
            continue
        replacement = None
        if value.startswith("??", position) and position + 2 < len(value):
            replacement = _C_TRIGRAPHS.get(value[position + 2])
        if replacement is not None:
            output.append(replacement)
            offsets.append(position)
            position += 3
        else:
            output.append(value[position])
            offsets.append(position)
            position += 1
    return "".join(output), offsets


def _splice_c_lines_with_offsets(value: str) -> tuple[str, list[int]]:
    # C translation phase 1 converts trigraphs before phase 2 removes escaped
    # newlines. A ``??/`` at the end of a line is therefore a line splice in
    # C90-C17 translation modes that retain trigraph support.
    value, phase1_offsets = _translate_c_trigraphs_with_offsets(value)
    output = []
    offsets = []
    position = 0
    while position < len(value):
        if value[position] == "\\" and position + 1 < len(value):
            if value.startswith("\r\n", position + 1):
                position += 3
                continue
            if value[position + 1] in "\r\n":
                position += 2
                continue
        output.append(value[position])
        offsets.append(phase1_offsets[position])
        position += 1
    return "".join(output), offsets


def _has_unconditional_control_exit_before(value: str, position: int) -> bool:
    exits = re.finditer(r"\b(?:return\b[^;]*;|goto\s+[A-Za-z_]\w*\s*;)",
                        value[:position])
    return any(_brace_depth_at(value, match.start()) == 0 for match in exits)


def _contains_preprocessor_directive(value: str) -> bool:
    # The audit inspects function bodies without the build's exact preprocessor
    # environment. Reject every directive (including macro definitions), and
    # recognize line-spliced directives and the C digraph/trigraph spellings
    # of '#'. Translation phase 2 removes backslash-newline before directives.
    value = _splice_c_lines(value)
    return re.search(
        r"(?m)^[ \t\f\v]*(?:#|%:|\?\?=)[ \t\f\v]*[A-Za-z_]\w*\b",
        value) is not None


def _comment_text(value: str) -> str:
    return _compact(re.sub(r"//|/\*|\*/|(?m:^\s*\*\s?)", " ", value))


def _matching_delimiter(value: str, opening: int, left: str, right: str) -> int:
    _require(opening < len(value) and value[opening] == left,
             f"expected {left!r} at offset {opening}")
    depth = 0
    for position in range(opening, len(value)):
        if value[position] == left:
            depth += 1
        elif value[position] == right:
            depth -= 1
            if depth == 0:
                return position
    raise ValueError(f"unclosed {left!r} delimiter")


def _extract_if_else(value: str, start: int = 0) -> tuple[str, str, str, int]:
    match = re.search(r"\bif\s*\(", value[start:])
    _require(match is not None, "generated HAL conditional is missing an if block")
    if_pos = start + match.start()
    cond_open = value.find("(", if_pos)
    cond_close = _matching_delimiter(value, cond_open, "(", ")")
    body_open = cond_close + 1
    while body_open < len(value) and value[body_open].isspace():
        body_open += 1
    _require(body_open < len(value) and value[body_open] == "{",
             "generated HAL if body is not braced")
    body_close = _matching_delimiter(value, body_open, "{", "}")
    else_pos = body_close + 1
    while else_pos < len(value) and value[else_pos].isspace():
        else_pos += 1
    _require(value.startswith("else", else_pos),
             "generated HAL if block is missing its else branch")
    else_open = else_pos + len("else")
    while else_open < len(value) and value[else_open].isspace():
        else_open += 1
    _require(else_open < len(value) and value[else_open] == "{",
             "generated HAL else body is not braced")
    else_close = _matching_delimiter(value, else_open, "{", "}")
    return (value[cond_open + 1:cond_close], value[body_open + 1:body_close],
            value[else_open + 1:else_close], else_close + 1)


def _extract_if_body(value: str, pattern: str) -> tuple[str, int, int] | None:
    match = re.search(pattern, value)
    if match is None:
        return None
    brace_open = value.find("{", match.start())
    if brace_open < 0:
        return None
    brace_close = _matching_delimiter(value, brace_open, "{", "}")
    return value[brace_open + 1:brace_close], match.start(), brace_close + 1


def audit_tree(source_root: Path) -> dict:
    source_root = source_root.resolve(strict=True)
    paths = {relative: source_root / relative for relative in SOURCE_FILES}
    missing = [relative for relative, path in paths.items() if not path.is_file()]
    _require(not missing, f"missing R580 source files: {', '.join(missing)}")
    source_bytes = {relative: path.read_bytes() for relative, path in paths.items()}
    sources = {relative: source_bytes[relative].decode("utf-8", errors="strict")
               for relative in paths}
    # Normalize physical line endings and apply C phase-1 trigraph translation
    # before phase-2 line splicing and comment removal. This is essential for
    # rejecting directives exposed by split comment delimiters or trigraph
    # splices. Retain offsets so report lines refer to raw source; hashes always
    # use the original bytes.
    spliced_sources = {}
    source_offsets = {}
    for relative, text in sources.items():
        spliced_sources[relative], source_offsets[relative] = (
            _splice_c_lines_with_offsets(text))
    code = _SourceMap(
        {relative: strip_c_comments(spliced_sources[relative])
         for relative in sources}, sources, source_offsets)

    type_comments = _comment_text(sources["kernel-open/common/inc/nv_uvm_types.h"])
    interface_comments = _comment_text(sources["kernel-open/common/inc/nv_uvm_interface.h"])
    # Use the unique documented function names as anchors while allowing comment
    # formatting changes between the same-version Open and proprietary wrappers.
    pending_doc_start = interface_comments.find("nvuvminterfacehaspendingnonreplayablefaults")
    get_doc_start = interface_comments.find("nvuvminterfacegetnonreplayablefaults")
    _require(pending_doc_start >= 0 and get_doc_start > pending_doc_start,
             "missing documented non-replayable client-queue APIs")
    pending_doc = interface_comments[pending_doc_start:get_doc_start]
    get_doc = interface_comments[get_doc_start:]
    client_queue_doc = "client shadow fault buffer" in pending_doc
    pending_is_client_queue = client_queue_doc and "ready to be consumed" in pending_doc
    get_consumes_client_queue = (
        "consumes all" in get_doc and "client shadow fault buffer" in get_doc and
        "circular queue" in get_doc
    )
    client_queue_apis_avoid_locks = (
        "does not acquire the rm api or gpu locks" in pending_doc and
        "does not acquire the rm api or gpu locks" in get_doc
    )
    rm_populates_queue = (
        "shadow buffer for non-replayable faults on cpu memory" in type_comments and
        "resman copies here the non-replayable faults that need to be handled by uvm"
        in type_comments and "shadowbufferaddress" in type_comments
    )

    interface_service, interface_service_line = _body(
        code, "kernel-open/nvidia/nv_uvm_interface.c",
        "nvUvmInterfaceServiceDeviceInterruptsRM")
    wrapper_delegates = _has_call(interface_service, "rm_gpu_ops_service_device_interrupts_rm")
    pending_wrapper, pending_wrapper_line = _body(
        code, "kernel-open/nvidia/nv_uvm_interface.c",
        "nvUvmInterfaceHasPendingNonReplayableFaults")
    get_wrapper, get_wrapper_line = _body(
        code, "kernel-open/nvidia/nv_uvm_interface.c",
        "nvUvmInterfaceGetNonReplayableFaults")
    pending_stack_isr = "pFaultInfo->nonReplayable.isr_sp" in pending_wrapper
    get_stack_bottom_half = "pFaultInfo->nonReplayable.isr_bh_sp" in get_wrapper

    ctrl_header = code["src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080mc.h"]
    ctrl_id_match = re.search(
        r"#\s*define\s+NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS\s+\(\s*(0x[0-9a-fA-F]+)\s*\)",
        ctrl_header)
    _require(ctrl_id_match is not None and int(ctrl_id_match.group(1), 16) == 0x20801702,
             "unexpected MC service-interrupt control ID")
    control_doc = _comment_text(sources[
        "src/common/sdk/nvidia/inc/ctrl/ctrl2080/ctrl2080mc.h"])
    control_is_service_interrupts = (
        "this command instructs the rm to service interrupts for the specified engine(s)"
        in control_doc and
        "typedef struct nv2080_ctrl_mc_service_interrupts_params" in control_doc and
        "nvu32 engines" in control_doc
    )
    registered = _compact(code["src/nvidia/generated/g_subdevice_nvoc.c"])
    control_method_registered = (
        "subdevicectrlcmdmcserviceinterrupts_impl" in registered and
        "0x20801702u" in registered
    )

    rm_wrapper, rm_wrapper_line = _body(
        code, "src/nvidia/arch/nvalloc/unix/src/rm-gpu-ops.c",
        "rm_gpu_ops_service_device_interrupts_rm")
    rm_core, rm_core_line = _body(
        code, "src/nvidia/src/kernel/rmapi/nv_gpu_ops.c",
        "nvGpuOpsServiceDeviceInterruptsRM")
    rm_sets_all_engines = re.search(
        r"params\.engines\s*=\s*NV2080_CTRL_MC_ENGINE_ID_ALL\s*;", rm_core) is not None
    rm_uses_control = _has_call(rm_core, "Control") and "NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS" in rm_core
    rm_wrapper_delegates_to_core = _has_call(rm_wrapper, "nvGpuOpsServiceDeviceInterruptsRM")

    method, method_line = _body(
        code, "src/nvidia/src/kernel/gpu/intr/intr.c",
        "subdeviceCtrlCmdMcServiceInterrupts_IMPL")
    method_all_engine_set = (
        "pServiceInterruptParams->engines == NV2080_CTRL_MC_ENGINE_ID_ALL" in method and
        _has_call(method, "bitVectorSetAll")
    )
    method_calls_stall_loop = re.search(
        r"intrServiceStallList_HAL\s*\([^;]*\bNV_TRUE\s*\)", method, re.S) is not None
    method_returns_success_after_void_dispatch = (
        method.find("intrServiceStallList_HAL") >= 0 and
        method.find("return NV_OK", method.find("intrServiceStallList_HAL")) >= 0
    )

    stall_loop, stall_loop_line = _body(
        code, "src/nvidia/src/kernel/gpu/intr/intr.c", "intrServiceStallList_IMPL")
    repeats_pending_stall_service = (
        _has_call(stall_loop, "intrGetPendingStall_HAL") and
        _has_call(stall_loop, "_intrServiceStallExactList") and
        re.search(r"while\s*\(\s*bPending\s*&&\s*bLoop\s*\)", stall_loop) is not None
    )
    stuck_exit, stuck_exit_line = _body(
        code, "src/nvidia/src/kernel/gpu/intr/intr.c", "_intrServiceStallExactList")
    service_loop_can_stop_stuck = (
        "bIntrStuck" in stuck_exit and "NV_ASSERT(0)" in stuck_exit and
        "return NV_FALSE" in stuck_exit
    )
    control_success_does_not_prove_stuck_drained = (
        method_returns_success_after_void_dispatch and service_loop_can_stop_stuck
    )

    gp100_pending, gp100_pending_line = _body(
        code, "src/nvidia/src/kernel/gpu/intr/arch/pascal/intr_gp100.c",
        "intrGetAuxiliaryPendingStall_GP100")
    gp100_enumerates_gmmu = (
        "MC_ENGINE_IDX_GMMU" in gp100_pending and _has_call(gp100_pending, "intrGetGmmuInterrupts")
    )
    get_gmmu, get_gmmu_line = _body(
        code, "src/nvidia/src/kernel/gpu/intr/intr.c", "intrGetGmmuInterrupts_IMPL")
    gmmu_pending_uses_fault_state = (
        _has_call(get_gmmu, "kgmmuGetFatalFaultIntrPendingState") and
        "MC_ENGINE_IDX_GMMU" in get_gmmu
    )

    kgmmu_registration, kgmmu_registration_line = _body(
        code, "src/nvidia/src/kernel/gpu/mmu/kern_gmmu.c",
        "kgmmuRegisterIntrService_IMPL")
    non_gsp_registers_non_replayable = (
        "MC_ENGINE_IDX_NON_REPLAYABLE_FAULT" in kgmmu_registration and
        "!IS_GSP_CLIENT(pGpu)" in kgmmu_registration
    )
    kgmmu_service, kgmmu_service_line = _body(
        code, "src/nvidia/src/kernel/gpu/mmu/kern_gmmu.c",
        "kgmmuServiceInterrupt_IMPL")
    kgmmu_service_comments = _comment_text(sources[
        "src/nvidia/src/kernel/gpu/mmu/kern_gmmu.c"])
    non_replayable_service_after_top_half = (
        "MC_ENGINE_IDX_NON_REPLAYABLE_FAULT" in kgmmu_service and
        _has_call(kgmmu_service, "kgmmuServiceNonReplayableFault_HAL") and
        "copy from hw fault buffer always happens in the top half" in kgmmu_service_comments and
        "this servicing is merely copying from the sw fault buffer" in kgmmu_service_comments
    )

    linux_isr, linux_isr_line = _body(code, "kernel-open/nvidia/nv.c", "nvidia_isr")
    rm_copy_in_isr = linux_isr.find("rm_gpu_handle_mmu_faults(")
    uvm_callback_in_isr = linux_isr.find("nv_uvm_event_interrupt(")
    linux_isr_copies_before_uvm_callback = (
        rm_copy_in_isr >= 0 and uvm_callback_in_isr > rm_copy_in_isr
    )

    rm_handle, rm_handle_line = _body(
        code, "src/nvidia/arch/nvalloc/unix/src/unix_intr.c",
        "rm_gpu_handle_mmu_faults")
    non_gsp_copy_branch = re.search(
        r"if\s*\(\s*IS_GSP_CLIENT\s*\([^)]*\)\s*\)\s*\{[^}]*\}\s*else\s*\{"
        r"[^}]*_rm_gpu_copy_mmu_faults_unlocked\s*\(", rm_handle, re.S)
    rm_copy_helper, rm_copy_helper_line = _body(
        code, "src/nvidia/arch/nvalloc/unix/src/unix_intr.c",
        "_rm_gpu_copy_mmu_faults_unlocked")
    non_gsp_fault_handler_invokes_shadow_copy = (
        non_gsp_copy_branch is not None and
        _has_call(rm_copy_helper, "kgmmuCopyMmuFaults_HAL") and
        "NON_REPLAYABLE_FAULT_BUFFER" in rm_copy_helper
    )

    hal_relative = "src/nvidia/generated/g_kern_gmmu_nvoc.c"
    hal_raw = sources[hal_relative]
    hal_begin = hal_raw.find("// kgmmuCopyMmuFaults -- halified")
    hal_end = hal_raw.find("// kgmmuParseFaultPacket -- halified", hal_begin + 1)
    _require(hal_begin >= 0 and hal_end > hal_begin,
             "generated GV100 fault-copy HAL block is missing or unbounded")
    hal_block = strip_c_comments(hal_raw[hal_begin:hal_end])
    vf_condition, vf_body, non_vf_body, _ = _extract_if_else(hal_block)
    chip_condition, tegra_body, non_tegra_body, _ = _extract_if_else(vf_body)
    rm_variant_is_vf = (
        "rmVariantHal_HalVarIdx" in vf_condition and
        "0x00000001UL" in vf_condition and
        "RmVariantHal: VF" in hal_raw[hal_begin:hal_end]
    )
    chip_variant_is_t234d_or_t264d = (
        "chipHal_HalVarIdx" in chip_condition and
        "0x00005000UL" in chip_condition and
        "ChipHal: T234D | T264D" in hal_raw[hal_begin:hal_end]
    )
    expected_tegra_copy = re.search(
        r"__kgmmuCopyMmuFaults__\s*=\s*&kgmmuCopyMmuFaults_56cd7a\s*;",
        tegra_body) is not None
    expected_non_tegra_copy = re.search(
        r"__kgmmuCopyMmuFaults__\s*=\s*&kgmmuCopyMmuFaults_GV100\s*;",
        non_tegra_body) is not None
    expected_non_vf_copy = re.search(
        r"__kgmmuCopyMmuFaults__\s*=\s*&kgmmuCopyMmuFaults_92bfc3\s*;",
        non_vf_body) is not None
    gv100_hal_copy_bound = (
        rm_variant_is_vf and chip_variant_is_t234d_or_t264d and
        expected_tegra_copy and expected_non_tegra_copy and expected_non_vf_copy
    )
    gv100_hal_match = re.search(
        r"__kgmmuCopyMmuFaults__\s*=\s*&kgmmuCopyMmuFaults_GV100",
        hal_block)
    gv100_hal_binding_line = (
        hal_raw.count("\n", 0, hal_begin) +
        hal_block.count("\n", 0, gv100_hal_match.start()) + 1
        if gv100_hal_match is not None else None
    )

    gv100 = "src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c"
    queue_routing, queue_routing_line = _body(
        code, gv100, "_kgmmuCopyFaultPktInShadowBuf_GV100")
    client_copy, client_copy_line = _body(
        code, gv100, "kgmmuCopyFaultPacketToClientShadowBuffer_GV100")
    rm_and_client_routes = (
        re.search(r"if\s*\(\s*bRmServiceable\s*\).*?queuePush\s*\(\s*pRmShadowFaultBuf",
                  queue_routing, re.S) is not None and
        "kgmmuCopyFaultPacketToClientShadowBuffer_HAL" in queue_routing and
        "queuePushNonManaged" in client_copy
    )
    client_put_pos = queue_routing.find("kgmmuWriteClientShadowBufPutIndex_HAL(")
    client_fence_pos = queue_routing.find("portAtomicMemoryFenceStore(")
    client_queue_publish_fenced = (
        "!bRmServiceable" in queue_routing and client_fence_pos >= 0 and
        client_put_pos > client_fence_pos
    )

    gv100_copy, gv100_copy_line = _body(code, gv100, "kgmmuCopyMmuFaults_GV100")
    empty_path = _extract_if_body(
        gv100_copy, r"if\s*\(\s*totalCount\s*==\s*0\s*\)")
    empty_path_body = empty_path[0] if empty_path is not None else ""
    empty_path_source_match = re.search(
        r"if\s*\(\s*totalCount\s*==\s*0\s*\)", sources[gv100])
    empty_path_line = (
        sources[gv100].count("\n", 0, empty_path_source_match.start()) + 1
        if empty_path_source_match is not None else None
    )
    empty_path_rewrites_get_without_publication = (
        _has_call(empty_path_body, "kgmmuWriteFaultBufferGetPtr_HAL") and
        "pHwFaultBuffer->cachedGetIndex" in empty_path_body and
        re.search(r"\bgoto\s+done\s*;", empty_path_body) is not None and
        not _has_call(empty_path_body, "_kgmmuCopyFaultPktInShadowBuf_GV100")
    )
    shadow_copy_pos = (
        gv100_copy.find("_kgmmuCopyFaultPktInShadowBuf_GV100(", empty_path[2])
        if empty_path is not None else -1
    )
    clear_pos = gv100_copy.find("kgmmuFaultBufferClearPackets_HAL(")
    first_fence_pos = gv100_copy.find("portAtomicMemoryFenceStore(")
    pending_state_pos = gv100_copy.find("portAtomicSetS32(")
    second_fence_pos = gv100_copy.find("portAtomicMemoryFenceStore(", first_fence_pos + 1)
    hw_get_pos = gv100_copy.rfind("kgmmuWriteFaultBufferGetPtr_HAL(")
    nonempty_copy_advances_get_after_shadow_publication = (
        empty_path is not None and shadow_copy_pos >= empty_path[2] and
        shadow_copy_pos >= 0 and clear_pos > shadow_copy_pos and
        first_fence_pos > clear_pos and pending_state_pos > first_fence_pos and
        second_fence_pos > pending_state_pos and hw_get_pos > second_fence_pos and
        "fatalFaultIntrPending" in gv100_copy
    )

    gv100_rm_queue_service, gv100_rm_service_line = _body(
        code, gv100, "kgmmuServiceNonReplayableFault_GV100")
    service_consumes_rm_shadow_queue = (
        "pRmShadowFaultBuffer" in gv100_rm_queue_service and
        _has_call(gv100_rm_queue_service, "queueIsEmpty") and
        _has_call(gv100_rm_queue_service, "queuePopAndCopy") and
        _has_call(gv100_rm_queue_service, "kgmmuHandleNonReplayableFaultPacket_HAL") and
        _has_call(gv100_rm_queue_service, "kgmmuNotifyNonReplayableFault_HAL")
    )

    uvm_top_half, uvm_top_half_line = _body(
        code, "kernel-open/nvidia-uvm/uvm_gpu_isr.c", "uvm_isr_top_half")
    uvm_suspend_setter, uvm_suspend_setter_line = _body(
        code, "kernel-open/nvidia-uvm/uvm_global.c",
        "uvm_parent_gpu_set_isr_suspended")
    isr_lock = "parent_gpu->isr.interrupts_lock"
    uvm_top_half_lock_serialized = (
        isr_lock in uvm_top_half and _has_call(uvm_top_half, "uvm_spin_lock_irqsave") and
        _has_call(uvm_top_half, "uvm_spin_unlock_irqrestore")
    )
    suspend_setter_lock_serialized = (
        isr_lock in uvm_suspend_setter and
        _has_call(uvm_suspend_setter, "uvm_spin_lock_irqsave") and
        _has_call(uvm_suspend_setter, "uvm_spin_unlock_irqrestore") and
        "parent_gpu->isr.is_suspended =" in uvm_suspend_setter
    )
    uvm_suspend_and_top_half_share_isr_lock = (
        uvm_top_half_lock_serialized and suspend_setter_lock_serialized
    )

    nvidia_driver = "kernel-open/nvidia/nv.c"
    system_suspend, system_suspend_line = _body(
        code, nvidia_driver, "nv_suspend_devices")
    device_suspend, device_suspend_line = _body(
        code, nvidia_driver, "nvidia_suspend")
    power_management, power_management_line = _body(
        code, nvidia_driver, "nv_power_management")
    rm_power, rm_power_line = _body(
        code, "src/nvidia/arch/nvalloc/unix/src/dynamic-power.c",
        "rm_power_management")
    rm_power_transition, rm_power_transition_line = _body(
        code, "src/nvidia/arch/nvalloc/unix/src/dynamic-power.c",
        "RmPowerManagement")
    intr_setter, intr_setter_line = _body(
        code, "src/nvidia/src/kernel/gpu/intr/intr.c", "intrSetIntrEn_IMPL")
    msix_isr, msix_isr_line = _body(code, nvidia_driver, "nvidia_isr_msix")
    msix_registration, msix_registration_line = _body(
        code, "kernel-open/nvidia/nv-msi.c", "nv_request_msix_irq")
    linux_dpm_suspend, linux_dpm_suspend_line = _body(
        code, nvidia_driver, "nv_pmops_suspend")
    procfs_driver = "kernel-open/nvidia/nv-procfs.c"
    procfs_depth_writer, procfs_depth_writer_line = _body(
        code, procfs_driver, "nv_procfs_write_suspend_depth")
    procfs_suspend_writer, procfs_suspend_writer_line = _body(
        code, procfs_driver, "nv_procfs_write_suspend")
    normal_irq_registers_direct_isr = re.search(
        r"request_threaded_irq\s*\(\s*nv->interrupt_line\s*,\s*"
        r"nvidia_isr\s*,", code[nvidia_driver]) is not None
    msix_irq_registers_serialized_wrapper = re.search(
        r"request_threaded_irq\s*\(\s*[^,]+\s*,\s*nvidia_isr_msix\s*,",
        msix_registration) is not None
    gv100_intr_check = re.search(
        r"if\s*\(\s*\(\s*pIntr\s*==\s*NULL\s*\)\s*\|\|\s*"
        r"\(\s*intrGetIntrEn\s*\(\s*pIntr\s*\)\s*==\s*"
        r"INTERRUPT_TYPE_DISABLED\s*\).*?return\s+NV_OK\s*;",
        gv100_copy, re.S)
    _require(gv100_intr_check is not None,
             "GV100 fault copier lost its disabled-interrupt early return")

    modeset_early_return = re.search(
        r"if\s*\(\s*pm_action_depth\s*==\s*NV_PM_ACTION_DEPTH_MODESET\s*\)\s*"
        r"\{\s*return\s+NV_OK\s*;\s*\}", system_suspend, re.S)
    modeset_suspend_position = system_suspend.find("nvidia_modeset_suspend(")
    first_preempt_position = system_suspend.find("nv_preempt_user_channels(")
    first_uvm_suspend_position = system_suspend.find("nv_uvm_suspend(")
    modeset_depth_returns_before_work = (
        modeset_early_return is not None and modeset_suspend_position >= 0 and
        modeset_suspend_position < modeset_early_return.start() and
        modeset_early_return.end() < first_preempt_position and
        modeset_early_return.end() < first_uvm_suspend_position
    )
    uvm_early_return = re.search(
        r"if\s*\(\s*pm_action_depth\s*==\s*NV_PM_ACTION_DEPTH_UVM\s*\)\s*"
        r"\{\s*return\s+NV_OK\s*;\s*\}", system_suspend, re.S)
    full_depth_device_suspend_position = system_suspend.find("nvidia_suspend(")
    uvm_depth_returns_after_uvm = (
        uvm_early_return is not None and first_uvm_suspend_position >= 0 and
        first_uvm_suspend_position < uvm_early_return.start() and
        uvm_early_return.end() < full_depth_device_suspend_position
    )
    ordered_full_depth_stages = (
        uvm_early_return is not None and first_preempt_position >= 0 and
        first_preempt_position < first_uvm_suspend_position <
        uvm_early_return.start() < full_depth_device_suspend_position
    )
    full_depth_procfs_pm_order = (
        modeset_depth_returns_before_work and uvm_depth_returns_after_uvm and
        ordered_full_depth_stages
    )
    linux_dpm_calls_per_device_suspend = _has_call(
        linux_dpm_suspend, "nvidia_suspend")
    linux_dpm_calls_global_uvm_suspend = _has_call(
        linux_dpm_suspend, "nv_uvm_suspend")
    procfs_depth_writer_is_preprocessor_plain = not _contains_preprocessor_directive(
        procfs_depth_writer)
    procfs_suspend_writer_is_preprocessor_plain = not _contains_preprocessor_directive(
        procfs_suspend_writer)
    procfs_control_functions_are_preprocessor_plain = (
        procfs_depth_writer_is_preprocessor_plain and
        procfs_suspend_writer_is_preprocessor_plain
    )
    procfs_depth_chain = re.search(
        r"if\s*\(\s*strcasecmp\s*\(\s*kbuf\s*,\s*\"uvm\"\s*\)\s*==\s*0\s*\)"
        r"\s*\{\s*nv_pm_action_depth\s*=\s*NV_PM_ACTION_DEPTH_UVM\s*;\s*\}"
        r"\s*else\s*if\s*\(\s*strcasecmp\s*\(\s*kbuf\s*,\s*\"modeset\"\s*\)"
        r"\s*==\s*0\s*\)\s*\{\s*nv_pm_action_depth\s*=\s*"
        r"NV_PM_ACTION_DEPTH_MODESET\s*;\s*\}\s*else\s*if\s*\(\s*"
        r"strcasecmp\s*\(\s*kbuf\s*,\s*\"default\"\s*\)\s*==\s*0\s*\)"
        r"\s*\{\s*nv_pm_action_depth\s*=\s*NV_PM_ACTION_DEPTH_DEFAULT\s*;\s*\}"
        r"\s*else\s*\{\s*return\s+-EINVAL\s*;\s*\}",
        procfs_depth_writer, re.S)
    procfs_depth_tail = (
        procfs_depth_writer[procfs_depth_chain.end():]
        if procfs_depth_chain is not None else "")
    # Keep this deliberately narrow: the exact pinned routine ends with one
    # unconditional success return. Do not approximate reachability through
    # arbitrary unbraced C statements.
    procfs_depth_returns_success_after_selection = re.fullmatch(
        r"\s*return\s+count\s*;\s*", procfs_depth_tail) is not None
    procfs_depth_writer_accepts_all_levels = (
        procfs_depth_chain is not None and
        procfs_depth_returns_success_after_selection and
        procfs_depth_writer_is_preprocessor_plain and
        _brace_depth_at(procfs_depth_writer, procfs_depth_chain.start()) == 0 and
        not _has_unconditional_control_exit_before(
            procfs_depth_writer, procfs_depth_chain.start())
    )
    procfs_suspend_call = re.search(
        r"nv_set_system_power_state\s*\(\s*power_state\s*,\s*"
        r"nv_pm_action_depth\s*\)", procfs_suspend_writer)
    procfs_suspend_uses_selected_depth = (
        procfs_suspend_call is not None and
        len(re.findall(r"\bnv_set_system_power_state\s*\(", procfs_suspend_writer)) == 1 and
        procfs_suspend_writer_is_preprocessor_plain and
        _brace_depth_at(procfs_suspend_writer, procfs_suspend_call.start()) == 0 and
        not _has_unconditional_control_exit_before(
            procfs_suspend_writer, procfs_suspend_call.start())
    )

    rm_intr_disabled_before_power_transition = True
    for action, sleep_call in (
            ("NV_PM_ACTION_HIBERNATE", "gpuEnterHibernate("),
            ("NV_PM_ACTION_STANDBY", "gpuEnterStandby(")):
        branch = re.search(
            rf"case\s+{action}\s*:(.*?)(?:\bbreak\s*;|\bcase\b)",
            rm_power_transition, re.S)
        if branch is None:
            rm_intr_disabled_before_power_transition = False
            break
        branch_body = branch.group(1)
        disable_pos = branch_body.find(
            "intrSetIntrEn(pIntr, INTERRUPT_TYPE_DISABLED)")
        sleep_pos = branch_body.find(sleep_call)
        if disable_pos < 0 or sleep_pos < 0 or disable_pos > sleep_pos:
            rm_intr_disabled_before_power_transition = False
            break
    setter_without_strings = re.sub(r'"(?:\\.|[^"\\])*"', '""', intr_setter)
    expected_software_only_setter = """
        if (pIntr->halIntrEnabled == NV_FALSE) {
            NV_PRINTF(LEVEL_INFO, "");
            return;
        }
        NV_ASSERT(intrEn0 <= INTERRUPT_TYPE_MAX);
        pIntr->intrEn0 = intrEn0;
    """
    intr_setter_is_software_only = (
        _normalize_setter_body(setter_without_strings) ==
        _normalize_setter_body(expected_software_only_setter)
    )
    msix_wrapper_serializes_isr = (
        msix_isr.find("NV_SPIN_LOCK(&nvl->msix_isr_lock)") >= 0 and
        msix_isr.find("nvidia_isr(irq, arg)") >
        msix_isr.find("NV_SPIN_LOCK(&nvl->msix_isr_lock)") and
        msix_isr.find("NV_SPIN_UNLOCK(&nvl->msix_isr_lock)") >
        msix_isr.find("nvidia_isr(irq, arg)")
    )
    pm_wrapper_bodies = (system_suspend, linux_dpm_suspend, device_suspend,
                         power_management, rm_power, rm_power_transition)
    linux_irq_wait_calls = [
        name for name in ("synchronize_irq", "disable_irq", "free_irq")
        if any(_has_call(body, name) for body in pm_wrapper_bodies)
    ]
    shutdown_adapter, shutdown_adapter_line = _body(
        code, nvidia_driver, "nv_shutdown_adapter")
    irq_free_on_adapter_shutdown = _has_call(shutdown_adapter, "free_irq")
    gv100_fault_copy_checks_intr_state = gv100_intr_check is not None

    facts = {
        "rm_populates_uvm_cpu_client_queue": rm_populates_queue,
        "pending_api_checks_client_queue": pending_is_client_queue,
        "get_api_consumes_client_queue": get_consumes_client_queue,
        "client_queue_apis_do_not_acquire_rm_gpu_locks": client_queue_apis_avoid_locks,
        "service_interrupts_api_delegates_to_rm": wrapper_delegates,
        "pending_api_uses_isr_stack": pending_stack_isr,
        "get_api_uses_bottom_half_stack": get_stack_bottom_half,
        "mc_service_control_is_documented_and_registered": (
            control_is_service_interrupts and control_method_registered
        ),
        "uvm_rm_method_services_all_engine_interrupts": (
            rm_sets_all_engines and rm_uses_control and rm_wrapper_delegates_to_core and
            method_all_engine_set and method_calls_stall_loop
        ),
        "stall_service_loops_over_pending_engines": repeats_pending_stall_service,
        "gp100_pending_enumeration_includes_gmmu": gp100_enumerates_gmmu,
        "gmmu_pending_checks_fault_service_state": gmmu_pending_uses_fault_state,
        "non_gsp_rm_registers_non_replayable_fault_service": non_gsp_registers_non_replayable,
        "non_replayable_service_runs_after_hw_top_half": non_replayable_service_after_top_half,
        "control_success_does_not_prove_stuck_interrupt_drained":
            control_success_does_not_prove_stuck_drained,
        "linux_isr_copies_faults_before_uvm_callback": linux_isr_copies_before_uvm_callback,
        "non_gsp_fault_handler_invokes_rm_shadow_copy":
            non_gsp_fault_handler_invokes_shadow_copy,
        "generated_hal_routes_vf_non_t234d_t264d_to_gv100_fault_copy":
            gv100_hal_copy_bound,
        "gv100_copy_routes_rm_and_client_faults": rm_and_client_routes,
        "client_queue_publish_is_fenced_before_put": client_queue_publish_fenced,
        "gv100_empty_copy_rewrites_hw_get_without_shadow_publication":
            empty_path_rewrites_get_without_publication,
        "gv100_nonempty_copy_advances_hw_get_after_shadow_publication":
            nonempty_copy_advances_get_after_shadow_publication,
        "rm_interrupt_service_consumes_rm_queue_and_notifies":
            service_consumes_rm_shadow_queue,
        "uvm_suspend_and_top_half_share_isr_lock":
            uvm_suspend_and_top_half_share_isr_lock,
        "procfs_modeset_depth_returns_before_preempt_or_uvm":
            modeset_depth_returns_before_work,
        "procfs_uvm_depth_returns_after_uvm_before_gpu_suspend":
            uvm_depth_returns_after_uvm,
        "procfs_full_depth_orders_preempt_uvm_gpu_suspend":
            full_depth_procfs_pm_order,
        "linux_pci_dpm_suspend_calls_per_device_suspend":
            linux_dpm_calls_per_device_suspend,
        "linux_pci_dpm_suspend_bypasses_global_uvm_suspend":
            not linux_dpm_calls_global_uvm_suspend,
        "procfs_depth_writer_accepts_uvm_modeset_default":
            procfs_depth_writer_accepts_all_levels,
        "procfs_suspend_writer_uses_selected_depth":
            procfs_suspend_uses_selected_depth,
        "procfs_control_functions_have_no_preprocessor_directives":
            procfs_control_functions_are_preprocessor_plain,
        "rm_disables_intr_state_before_gpu_power_transition":
            rm_intr_disabled_before_power_transition,
        "intr_setter_only_changes_rm_software_state": intr_setter_is_software_only,
        "gv100_fault_copy_checks_rm_intr_state": gv100_fault_copy_checks_intr_state,
        "msix_wrapper_serializes_isr_calls": msix_wrapper_serializes_isr,
        "normal_irq_registered_directly_to_fault_copy_isr":
            normal_irq_registers_direct_isr,
        "msix_irq_registered_to_serializing_wrapper":
            msix_irq_registers_serialized_wrapper,
        "adapter_shutdown_frees_linux_irq": irq_free_on_adapter_shutdown,
    }
    for name, fact in facts.items():
        _require(fact, f"R580 source contract not established: {name}")

    return {
        "schema": "r580-fault-interrupt-service-audit-v9",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audit_tool": {
            "path": Path(__file__).name,
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "source_root": str(source_root),
        "source_files": {
            relative: {"sha256": hashlib.sha256(source_bytes[relative]).hexdigest()}
            for relative in SOURCE_FILES
        },
        "facts": facts,
        "source_lines": {
            "service_interrupts_interface": interface_service_line,
            "pending_fault_wrapper": pending_wrapper_line,
            "get_fault_wrapper": get_wrapper_line,
            "rm_service_wrapper": rm_wrapper_line,
            "rm_service_core": rm_core_line,
            "mc_service_control": method_line,
            "stall_service_loop": stall_loop_line,
            "stuck_interrupt_exit": stuck_exit_line,
            "gp100_pending": gp100_pending_line,
            "gmmu_pending": get_gmmu_line,
            "kgmmu_registration": kgmmu_registration_line,
            "kgmmu_service": kgmmu_service_line,
            "linux_isr": linux_isr_line,
            "rm_fault_handler": rm_handle_line,
            "rm_fault_copy_helper": rm_copy_helper_line,
            "gv100_fault_copy_hal_binding": gv100_hal_binding_line,
            "gv100_empty_hw_buffer_path": empty_path_line,
            "gv100_queue_routing": queue_routing_line,
            "gv100_client_queue_copy": client_copy_line,
            "gv100_hardware_fault_copy": gv100_copy_line,
            "gv100_rm_queue_service": gv100_rm_service_line,
            "uvm_isr_top_half": uvm_top_half_line,
            "uvm_isr_suspend_setter": uvm_suspend_setter_line,
            "system_suspend": system_suspend_line,
            "device_suspend": device_suspend_line,
            "power_management": power_management_line,
            "rm_power_management": rm_power_line,
            "rm_power_transition": rm_power_transition_line,
            "intr_enable_setter": intr_setter_line,
            "msix_isr_wrapper": msix_isr_line,
            "msix_irq_registration": msix_registration_line,
            "linux_pci_dpm_suspend_callback": linux_dpm_suspend_line,
            "procfs_depth_writer": procfs_depth_writer_line,
            "procfs_suspend_writer": procfs_suspend_writer_line,
            "adapter_shutdown": shutdown_adapter_line,
        },
        "control": {
            "name": "NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS",
            "id": f"0x{int(ctrl_id_match.group(1), 16):08x}",
            "scope": "NV2080_CTRL_MC_ENGINE_ID_ALL",
        },
        "qualification": "static-source-contract-only",
        "limitations": [
            "The RM service loop may exit on a stuck interrupt after a void dispatch; the returned NV_OK is not proof that every pending engine drained.",
            "The Linux ISR invokes RM fault-buffer handling before the UVM top-half callback. The UVM suspend flag and UVM top-half use interrupts_lock, but these source paths do not establish that suspend waits for an in-flight Linux RM interrupt handler.",
            "The procfs PM ordering applies only to its full-depth successful path: MODESET returns before channel preemption or UVM suspend, UVM depth returns after UVM and before per-device GPU suspend, and the Linux PCI suspend callback invokes nvidia_suspend directly. The audit does not cover generic Linux noirq IRQ suspension.",
            "The procfs depth-selection and suspend-dispatch predicates fail closed if either inspected function contains a preprocessor directive; no build-specific preprocessor branches are inferred.",
            "The RM interrupt service path consumes RM software-shadow faults and notifies clients after the hardware-buffer copy step; source inspection does not prove its runtime completion or PM safety.",
            "The GV100 generated-HAL result is conditional: the source assigns the GV100 copier for the VF RM variant when the chip-HAL mask for T234D/T264D does not match. This source branch alone does not establish the runtime HAL selection for a particular physical GPU.",
            "The GET-pointer publication-order fact applies only to the nonempty-copy path. When totalCount is zero, GV100 rewrites the cached GET pointer and exits without a shadow-buffer publication.",
            "No RM call, GPU operation, module load, suspend, concurrent ISR/PM test, or fault-injection test was run.",
        ],
        "ordering_assessment": {
            "source_observation": "nvidia_isr calls rm_gpu_handle_mmu_faults before nv_uvm_event_interrupt; the physical non-GSP helper dispatches kgmmuCopyMmuFaults_HAL. In the generated HAL block, the VF RM variant uses the GV100 copier on the else branch of the T234D/T264D chip-HAL mask test; other branches assign different copiers.",
            "generated_hal_condition": "RmVariantHal VF branch AND chipHal T234D/T264D mask condition false assigns kgmmuCopyMmuFaults_GV100; this is source-conditional and not a physical-device selection result.",
            "hardware_fault_buffer_paths": {
                "empty_total_count": "rewrites cached GET and exits without shadow publication",
                "nonempty_total_count": "copies to shadow queue, clears packets, fences, sets fatalFaultIntrPending, fences, then advances GET",
            },
            "inference": "A UVM suspend racing an already-running Linux ISR is not ruled out by the UVM interrupts_lock alone because the RM fault-copy call precedes UVM top-half entry. Whether another Linux/RM PM barrier excludes that interleaving is unknown.",
            "decision": "Do not add an RM service call to the candidate suspend path until the in-flight Linux ISR ordering and RM control runtime/error semantics are independently closed.",
            "pm_irq_quiescence": {
            "source_observation": "On the procfs full-depth success path, nv_suspend_devices preempts user channels, invokes UVM suspend, then calls per-device nvidia_suspend. MODESET depth returns before preemption/UVM; UVM depth returns after UVM and before per-device suspend. The Linux PCI callback calls nvidia_suspend directly. Its RM wrapper stores INTERRUPT_TYPE_DISABLED before gpuEnterStandby/Hibernate. intrSetIntrEn_IMPL assigns the RM software field; the GV100 fault copier returns early when that field reads disabled.",
                "linux_irq_wait_calls_in_inspected_pm_wrappers": linux_irq_wait_calls,
                "adapter_shutdown_uses_free_irq": irq_free_on_adapter_shutdown,
                "procfs_modeset_depth_returns_before_preempt_or_uvm":
                    modeset_depth_returns_before_work,
                "procfs_uvm_depth_returns_after_uvm_before_gpu_suspend":
                    uvm_depth_returns_after_uvm,
                "procfs_full_depth_orders_preempt_uvm_gpu_suspend":
                    full_depth_procfs_pm_order,
                "linux_pci_dpm_suspend_calls_per_device_suspend":
                    linux_dpm_calls_per_device_suspend,
                "linux_pci_dpm_suspend_calls_global_uvm_suspend":
                    linux_dpm_calls_global_uvm_suspend,
                "procfs_depth_writer_accepts_uvm_modeset_default":
                    procfs_depth_writer_accepts_all_levels,
                "procfs_suspend_writer_uses_selected_depth":
                    procfs_suspend_uses_selected_depth,
                "procfs_control_functions_have_no_preprocessor_directives":
                    procfs_control_functions_are_preprocessor_plain,
                "rm_disables_intr_state_before_gpu_power_transition":
                    rm_intr_disabled_before_power_transition,
                "intr_setter_only_changes_rm_software_state": intr_setter_is_software_only,
                "gv100_fault_copy_checks_rm_intr_state": gv100_fault_copy_checks_intr_state,
                "msix_wrapper_serializes_isr_calls": msix_wrapper_serializes_isr,
                "normal_irq_registered_directly_to_fault_copy_isr":
                    normal_irq_registers_direct_isr,
                "msix_irq_registered_to_serializing_wrapper":
                    msix_irq_registers_serialized_wrapper,
                "pm_wrapper_contains_linux_irq_wait": bool(linux_irq_wait_calls),
                "in_flight_rm_fault_copy_completion_proven": False,
                "inference": "The RM interrupt gate is not itself an explicit Linux synchronize_irq/free_irq join. Because nvidia_isr copies RM faults before entering the UVM top half, a handler that already passed the GV100 interrupt-state check is not proven complete by the source-visible PM wrapper sequence. The UVM interrupts_lock protects UVM top-half state, not that earlier RM copy.",
                "decision": "Keep the UVM non-replayable drain patch as an unqualified candidate; do not claim producer quiescence or merge/install it until the in-flight ISR ordering is resolved and tested.",
            },
        },
    }


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True,
                        help="R580 source package root containing kernel-open/ and src/")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = audit_tree(Path(args.source_root))
    write_report(args.output, report)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"output": str(args.output), "sha256": digest,
                      "qualification": report["qualification"],
                      "control": report["control"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"audit_r580_fault_interrupt_service: {exc}", file=sys.stderr)
        raise SystemExit(2)
