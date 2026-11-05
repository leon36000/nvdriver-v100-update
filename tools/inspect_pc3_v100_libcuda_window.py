#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect one hash-pinned, bounded x86 instruction window from PC3's V100 guest.

The proprietary library is inspected in place. Only instruction addresses,
mnemonics, and operands for the requested window are retained; raw bytes,
pseudocode, and the library itself are not copied into the project.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_HOST = "pc3"
EXPECTED_HOST_KERNEL = "7.0.0-38-generic"
EXPECTED_GUEST = "pc3-v100"
EXPECTED_GUEST_KERNEL = "6.8.0-147-generic"
EXPECTED_GPU_UUID = "GPU-42d06a85-027a-75ea-7857-a8de27ad465e"
EXPECTED_GPU_PCI = "0000:00:05.0"
EXPECTED_DRIVER = "580.178.04"
EXPECTED_LIBCUDA = "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04"
EXPECTED_LIBCUDA_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
EXPECTED_LIBCUDA_BYTES = 96_284_520
GHIDRA_IMAGE_BASE = 0x100000
EXPECTED_ELF_LOAD_BASE = 0x0
CALL_RVA = 0x495AC7
RETURN_RVA = 0x495ACC
CALLEE_RVA = 0x48BC40
WINDOW_START_RVA = 0x495AA0
WINDOW_STOP_RVA = 0x495B20
HANDOFF_RVA = 0x49551A
HANDOFF_STOP_RVA = 0x49559A
SUCCESS_RVA = 0x4958E8
SUCCESS_STOP_RVA = 0x495968
IOCTL_CALL_RVA = 0x48BC83
IOCTL_RETURN_RVA = 0x48BC88
IOCTL_TARGET_RVA = 0x166160
PRECALL_START_RVA = 0x495900
PRECALL_STOP_RVA = 0x495AD4
CALLER_SCAN_START_RVA = 0x494F60
CALLER_SCAN_STOP_RVA = CALL_RVA
PARENT_CALL_START_RVA = 0x4600D0
PARENT_CALL_STOP_RVA = 0x460110
PARENT_CALL_RVA = 0x4600F7
PARENT_RETURN_RVA = 0x4600FC
PARENT_CALLEE_RVA = 0x494F60
FEATURE_DISPATCH_FOLLOWUP_START_RVA = 0x495B00
FEATURE_DISPATCH_FOLLOWUP_STOP_RVA = 0x495B90
GENERAL_COMMAND_TARGET_START_RVA = 0x496850
GENERAL_COMMAND_TARGET_STOP_RVA = 0x4968D0
NONZERO_HELPER_PATH_START_RVA = 0x495DC0
NONZERO_HELPER_PATH_STOP_RVA = 0x496040
FEATURE_FLAG_CALLER_START_RVA = 0x49D460
FEATURE_FLAG_CALLER_STOP_RVA = 0x49D550
GPU_NAME_CALLER_TRACE_PATH = (
    "evidence/pc3-v100-gpu-name-caller-stage-trace-v4-20261028T102004Z.json")
GPU_NAME_CALLER_TRACE_SHA256 = (
    "6cc2f9d20de78235af97fe3889f24e044e40d449cc9de1ac0d5d2aa3f0d6c774")
GPU_NAME_CALLER_RETURN_RVAS = (
    RETURN_RVA, 0x477209, 0x46311c, 0x3248f0, 0x47d265, 0xf5712d,
    0x2d251e, 0x331c32, 0x3279b0, 0x332226, 0x327cb0,
)
RIP_RELATIVE_CALL_RETURNS = {
    0x3279AA: 0x3279B0,
    0x327A6A: 0x327A70,
    0x327B2A: 0x327B30,
    0x327BEA: 0x327BF0,
    0x327CAA: 0x327CB0,
    0x32866A: 0x328670,
    0x32872A: 0x328730,
    0x37828A: 0x378290,
    0xF57127: 0xF5712D,
}
RIP_RELATIVE_CALL_SLOT_VAS = {
    0x3279AA: 0x5BCF9E8,
    0x327A6A: 0x5BCF9F0,
    0x327B2A: 0x5BCF9F8,
    0x327BEA: 0x5BCFA00,
    0x327CAA: 0x5BCFA08,
    0x32866A: 0x5BCFA20,
    0x32872A: 0x5BCFA10,
    0x37828A: 0x5BCFA18,
    0xF57127: 0x5BD7A50,
}
RIP_SLOT_CONTEXT_WINDOW_SPECS = (
    (0x3F1B00, 0x3F1C00),
    (0x3EB469, 0x3EB509),
)
RIP_SLOT_CONTEXT_WRITE_TARGETS = {
    0x3F1B65: 0x5BCFA08,
    0x3F1BD5: 0x5BCF9E8,
    0x3F1B49: 0x5BCFA10,
    0x3F1B2D: 0x5BCFA18,
    0x3F1B11: 0x5BCFA20,
    0x3F1B81: 0x5BCFA00,
    0x3F1B9D: 0x5BCF9F8,
    0x3F1BB9: 0x5BCF9F0,
}
RIP_SLOT_CONTEXT_READ_TARGETS = {
    0x3F1B55: 0x5BCFA08,
    0x3F1BC5: 0x5BCF9E8,
    0x3F1B39: 0x5BCFA10,
    0x3F1B1D: 0x5BCFA18,
    0x3F1B01: 0x5BCFA20,
    0x3F1B71: 0x5BCFA00,
    0x3F1B8D: 0x5BCF9F8,
    0x3F1BA9: 0x5BCF9F0,
}
RIP_SLOT_CONTEXT_VAS = {
    0x5BCF9E8, 0x5BCF9F0, 0x5BCF9F8, 0x5BCFA00, 0x5BCFA08,
    0x5BCFA10, 0x5BCFA18, 0x5BCFA20,
}
RIP_RELATIVE_TARGET_CODE_START_RVA = 0x332190
RIP_RELATIVE_TARGET_CODE_STOP_RVA = 0x332240
RIP_SLOT_BRANCH_XREF_TARGET_RVAS = {
    0x3F1B01, 0x3F1B11, 0x3F1B1D, 0x3F1B39, 0x3F1B40, 0x3F1B50, 0x3F1B55,
    0x3F1B6C, 0x3F1B71, 0x3F1B88, 0x3F1B8D, 0x3F1BA4, 0x3F1BA9, 0x3F1BC0,
    0x3F1BC5, 0x3F1BDC,
}
RIP_SLOT_BRANCH_XREF_EXACT_TARGETS = {0x3EB469}
GPU_NAME_CALLER_WINDOW_SPECS = tuple(
    (return_rva - 0x40, return_rva + 0x10)
    for return_rva in GPU_NAME_CALLER_RETURN_RVAS
    if return_rva != RETURN_RVA)
BASE_WINDOW_SPECS = (
    (WINDOW_START_RVA, WINDOW_STOP_RVA), (HANDOFF_RVA, HANDOFF_STOP_RVA),
    (SUCCESS_RVA, SUCCESS_STOP_RVA), (CALLEE_RVA, 0x48BD43),
    (PRECALL_START_RVA, PRECALL_STOP_RVA),
    (PARENT_CALL_START_RVA, PARENT_CALL_STOP_RVA),
    (FEATURE_DISPATCH_FOLLOWUP_START_RVA, FEATURE_DISPATCH_FOLLOWUP_STOP_RVA),
    (GENERAL_COMMAND_TARGET_START_RVA, GENERAL_COMMAND_TARGET_STOP_RVA),
    (NONZERO_HELPER_PATH_START_RVA, NONZERO_HELPER_PATH_STOP_RVA),
    (FEATURE_FLAG_CALLER_START_RVA, FEATURE_FLAG_CALLER_STOP_RVA),
)
WINDOW_SPECS = BASE_WINDOW_SPECS + GPU_NAME_CALLER_WINDOW_SPECS
MAX_WINDOW_BYTES = 0x1000
MAX_INSTRUCTIONS = 512
MAX_TEXT_BYTES = 32 * 1024
OUTPUT_PREFIX = "PC3_DISASSEMBLY_RESULT:"
INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]{1,16}):\s+([A-Za-z][A-Za-z0-9_.]*)"
    r"(?:\s+(.*?))?\s*$"
)
RAW_BYTE_PREFIX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}\s+){2,}")
ANNOTATION_RE = re.compile(r"\s+<[^<>\n]{1,256}>\s*$")
MNEMONIC_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,23}$")
OPERAND_RE = re.compile(r"^[A-Za-z0-9_.,:+*%$ \[\](){}-]{0,192}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
DIRECT_BRANCH_MNEMONICS = frozenset({
    "call", "callq", "jmp", "jmpq", "ja", "jae", "jb", "jbe", "jc", "jcxz",
    "je", "jecxz", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe",
    "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz",
    "jo", "jp", "jpe", "jpo", "jrcxz", "js", "jz",
})


def _load_transport_helper():
    path = ROOT / "tools/run_pc3_v100_guest_reference.py"
    spec = importlib.util.spec_from_file_location("pc3_v100_guest_reference_transport", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("pinned PC3 V100 guest transport helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse_address(value: object, field: str) -> int:
    if not isinstance(value, str) or ADDRESS_RE.fullmatch(value) is None:
        raise ValueError(f"invalid {field}")
    return int(value, 16)


def parse_instruction_window(
    text: str,
    *,
    image_base: int,
    start_rva: int,
    stop_rva: int,
) -> list[dict[str, str]]:
    """Parse a small objdump window, discarding bytes, symbols, and all other text."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError("disassembly text exceeds its fixed bound")
    if (type(image_base) is not int or type(start_rva) is not int or
            type(stop_rva) is not int or image_base < 0 or start_rva < 0 or
            stop_rva <= start_rva or stop_rva - start_rva > MAX_WINDOW_BYTES):
        raise ValueError("window exceeds its fixed bound or has invalid addresses")

    records: list[dict[str, str]] = []
    seen_addresses: set[int] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        prefix, body = line.split(":", 1)
        if not prefix.strip() or re.fullmatch(r"\s*[0-9a-fA-F]{1,16}\s*", prefix) is None:
            continue
        body = body.strip()
        if not body:
            continue
        if RAW_BYTE_PREFIX_RE.match(body):
            raise ValueError("raw instruction bytes were returned")
        if body.startswith("(bad)") or re.match(r"^\.byte\b", body):
            continue
        match = INSTRUCTION_RE.fullmatch(line)
        if match is None:
            raise ValueError("objdump instruction line is malformed")
        address = int(match.group(1), 16)
        rva = address - image_base
        if not start_rva <= rva < stop_rva:
            raise ValueError("instruction is outside the requested window")
        if address in seen_addresses:
            raise ValueError("duplicate instruction address")
        seen_addresses.add(address)
        mnemonic = match.group(2).lower()
        operands = (match.group(3) or "").strip()
        operands = operands.split("#", 1)[0].strip()
        operands = ANNOTATION_RE.sub("", operands).strip()
        if not MNEMONIC_RE.fullmatch(mnemonic) or not OPERAND_RE.fullmatch(operands):
            raise ValueError("instruction metadata contains unsupported characters")
        records.append({"rva": f"0x{rva:x}", "mnemonic": mnemonic, "operands": operands})
        if len(records) > MAX_INSTRUCTIONS:
            raise ValueError("instruction count exceeds its fixed bound")

    records.sort(key=lambda item: int(item["rva"], 16))
    if not records:
        raise ValueError("objdump returned no instructions in the requested window")
    return records


def parse_direct_branch_target(mnemonic: str, operands: str) -> int | None:
    """Return a direct call/jump target, excluding register and memory transfers."""
    if (not isinstance(mnemonic, str) or MNEMONIC_RE.fullmatch(mnemonic) is None or
            not isinstance(operands, str) or len(operands) > 512 or not operands.isascii()):
        return None
    normalized_mnemonic = mnemonic.lower()
    if normalized_mnemonic not in DIRECT_BRANCH_MNEMONICS:
        return None
    match = re.fullmatch(
        r"\s*(?:0x)?([0-9a-fA-F]{1,16})(?:\s+<[^<>\n]{1,256}>)?\s*", operands)
    if match is None:
        return None
    return int(match.group(1), 16)


def summarize_direct_branch_xrefs(
    raw_references: object,
    *,
    decoded_target_rvas: object,
    text_start_rva: int,
    text_end_rva: int,
) -> dict[str, Any]:
    """Validate direct branches into the pinned dispatch blocks and their common target."""
    if (type(text_start_rva) is not int or type(text_end_rva) is not int or
            text_start_rva < 0 or text_end_rva <= text_start_rva or
            text_end_rva - text_start_rva > 0x40000000):
        raise ValueError("direct-branch scan has invalid .text bounds")
    if not isinstance(raw_references, list) or len(raw_references) > 256:
        raise ValueError("direct-branch xref list is missing or exceeds its bound")
    if not isinstance(decoded_target_rvas, list) or len(decoded_target_rvas) > 256:
        raise ValueError("decoded branch-target instruction starts are missing or exceed their bound")

    decoded_targets: set[int] = set()
    for value in decoded_target_rvas:
        address = _parse_address(value, "decoded branch-target RVA")
        in_scope = (address in RIP_SLOT_BRANCH_XREF_TARGET_RVAS or
                    address in RIP_SLOT_BRANCH_XREF_EXACT_TARGETS)
        if not in_scope or address in decoded_targets:
            raise ValueError("decoded branch-target instruction start is out of scope or duplicated")
        decoded_targets.add(address)

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    referenced_targets: set[int] = set()
    for raw in raw_references:
        if not isinstance(raw, dict):
            raise ValueError("direct-branch xref record is malformed")
        source = _parse_address(raw.get("source_rva"), "direct-branch source RVA")
        target = _parse_address(raw.get("target_rva"), "direct-branch target RVA")
        length = raw.get("source_length_bytes")
        mnemonic = raw.get("mnemonic")
        if (type(length) is not int or not 1 <= length <= 15 or
                not isinstance(mnemonic, str) or MNEMONIC_RE.fullmatch(mnemonic) is None):
            raise ValueError("direct-branch xref instruction metadata is malformed")
        mnemonic = mnemonic.lower()
        if mnemonic not in DIRECT_BRANCH_MNEMONICS:
            raise ValueError("direct-branch xref contains a non-branch instruction")
        if not text_start_rva <= source < source + length <= text_end_rva:
            raise ValueError("direct-branch xref source is outside the scanned .text")
        source_in_context = any(
            start <= source < stop for start, stop in RIP_SLOT_CONTEXT_WINDOW_SPECS)
        if target in RIP_SLOT_BRANCH_XREF_EXACT_TARGETS and not source_in_context:
            raise ValueError("common sink xref source is outside the bounded source context")
        target_in_scope = (target in RIP_SLOT_BRANCH_XREF_TARGET_RVAS or
                           target in RIP_SLOT_BRANCH_XREF_EXACT_TARGETS)
        if not target_in_scope:
            raise ValueError("direct-branch xref target is outside the pinned target scope")
        identity = (source, target)
        if identity in seen:
            raise ValueError("direct-branch xref source/target pair is duplicated")
        seen.add(identity)
        referenced_targets.add(target)
        normalized.append({
            "source_rva": hex(source),
            "source_length_bytes": length,
            "mnemonic": mnemonic,
            "target_rva": hex(target),
            "target_instruction_start_verified": target in decoded_targets,
        })

    missing_targets = referenced_targets - decoded_targets
    if missing_targets:
        raise ValueError(
            "direct-branch xref target is not a decoded instruction start: " +
            ", ".join(hex(value) for value in sorted(missing_targets)))
    normalized.sort(key=lambda item: (int(item["target_rva"], 16),
                                     int(item["source_rva"], 16)))
    return {
        "reference_count": len(normalized),
        "references": normalized,
        "verified_target_instruction_starts": [hex(value) for value in sorted(decoded_targets)],
        "interpretation_limit": (
            "Direct call/jump xrefs and target starts come from a complete linear .text scan. "
            "This verifies decoded boundary candidates only; it does not establish a complete "
            "CFG, reachability, register definitions, function boundaries, or runtime execution."),
    }


def summarize_window(
    instructions: list[dict[str, str]],
    *,
    call_rva: int,
    return_rva: int,
    expected_callee_rva: int,
    image_base: int,
) -> dict[str, Any]:
    """Cross-check the known static call and summarize adjacent control-flow clues."""
    call = next((item for item in instructions
                 if int(item["rva"], 16) == call_rva and item["mnemonic"] == "call"), None)
    target_va: int | None = None
    if call is not None:
        target_match = re.match(r"^(0x)?([0-9a-fA-F]{1,16})(?:\s|$)", call["operands"])
        if target_match is not None:
            target_va = int(target_match.group(2), 16)
    call_target_rva = target_va - image_base if target_va is not None else None
    after = [item for item in instructions if int(item["rva"], 16) >= return_rva]
    branches = [f"{item['rva']}:{item['mnemonic']}" for item in after
                if ((item["mnemonic"].startswith("j") and item["mnemonic"] not in ("jmp", "jmpq"))
                    or item["mnemonic"].startswith("loop"))]
    memory_operands = sum("[" in item["operands"] and "]" in item["operands"]
                          for item in after)
    return {
        "call_instruction_rva": f"0x{call_rva:x}" if call is not None else None,
        "call_target_rva": f"0x{call_target_rva:x}" if call_target_rva is not None else None,
        "expected_callee_rva": f"0x{expected_callee_rva:x}",
        "call_target_matches_expected": call_target_rva == expected_callee_rva,
        "call_return_address_rva": f"0x{return_rva:x}",
        "known_call_length_bytes": return_rva - call_rva,
        "call_return_address_matches": call is not None and return_rva - call_rva == 5,
        "conditional_branch_rvas_in_bounded_window": branches,
        "memory_operand_count_after_return_in_bounded_window": memory_operands,
        "immediately_following_instructions": after[:2],
        "interpretation_limit": (
            "Bounded instruction adjacency can show branches and memory operands, "
            "but does not by itself prove ioctl-status or feature-mask dataflow."
        ),
    }


def summarize_call_handoff(
    instructions: list[dict[str, str]],
    handoff_instructions: list[dict[str, str]],
    success_instructions: list[dict[str, str]],
    *,
    elf_base: int,
) -> dict[str, Any]:
    """Verify the returned status capture and the two basic-block edges it takes."""
    result_capture = next((item for item in instructions if item["rva"] == hex(RETURN_RVA)), None)
    caller_local_arg = next((item for item in instructions
                             if item["rva"] == "0x495aae" and item["mnemonic"] == "lea"), None)
    fifth_arg_forward = next((item for item in instructions
                              if item["rva"] == "0x495ab5" and item["mnemonic"] == "mov"), None)
    handoff = next((item for item in instructions
                    if item["rva"] == hex(RETURN_RVA + 3) and item["mnemonic"] == "jmp"), None)
    target_match = (re.match(r"^(0x)?([0-9a-fA-F]{1,16})(?:\s|$)", handoff["operands"])
                    if handoff is not None else None)
    target_rva = int(target_match.group(2), 16) - elf_base if target_match is not None else None
    status_test = next((item for item in handoff_instructions
                        if item["rva"] == hex(HANDOFF_RVA) and item["mnemonic"] == "test"), None)
    success_branch = next((item for item in handoff_instructions
                           if item["rva"] == hex(HANDOFF_RVA + 3) and item["mnemonic"] == "je"), None)
    success_match = (re.match(r"^(0x)?([0-9a-fA-F]{1,16})(?:\s|$)", success_branch["operands"])
                     if success_branch is not None else None)
    success_target_rva = (int(success_match.group(2), 16) - elf_base
                          if success_match is not None else None)
    success_local_read = success_instructions[0] if success_instructions else None
    if (result_capture is None or result_capture["mnemonic"] != "mov" or
            result_capture["operands"] != "r13d,eax" or handoff is None or
            caller_local_arg is None or caller_local_arg["operands"] != "r9,[rbp-0x1114]" or
            fifth_arg_forward is None or fifth_arg_forward["operands"] != "r8,r10" or
            status_test is None or status_test["operands"] != "r13d,r13d" or
            target_rva != HANDOFF_RVA or not handoff_instructions or
            int(handoff_instructions[0]["rva"], 16) != HANDOFF_RVA or
            success_target_rva != SUCCESS_RVA or not success_instructions or
            int(success_instructions[0]["rva"], 16) != SUCCESS_RVA or
            success_local_read is None or success_local_read["mnemonic"] != "mov" or
            success_local_read["operands"] != "r8d,DWORD PTR [rbp-0x1114]"):
        raise ValueError("call-return capture or bounded control-flow handoff did not match")
    return {
        "call_return_capture": result_capture,
        "sixth_argument_local_operand": "[rbp-0x1114]",
        "fifth_argument_forwarding": fifth_arg_forward,
        "status_zero_test": status_test,
        "unconditional_handoff": handoff,
        "handoff_target_rva": hex(target_rva),
        "target_block_window_start_rva": hex(HANDOFF_RVA),
        "target_window_begins_at_handoff": True,
        "zero_status_branch": success_branch,
        "zero_status_target_rva": hex(success_target_rva),
        "zero_status_block_window_start_rva": hex(SUCCESS_RVA),
        "zero_status_window_begins_at_target": True,
        "success_path_local_read": success_local_read,
    }


def summarize_ioctl_wrapper(instructions: list[dict[str, str]], *, elf_base: int) -> dict[str, Any]:
    """Verify that the wrapper tests the ioctl return register before returning."""
    call_edge = summarize_window(instructions, call_rva=IOCTL_CALL_RVA,
                                 return_rva=IOCTL_RETURN_RVA,
                                 expected_callee_rva=IOCTL_TARGET_RVA, image_base=elf_base)
    status_test = next((item for item in instructions
                        if item["rva"] == hex(IOCTL_RETURN_RVA)), None)
    status_branch = next((item for item in instructions
                          if item["rva"] == hex(IOCTL_RETURN_RVA + 2) and item["mnemonic"] == "jns"), None)
    target_match = (re.match(r"^(0x)?([0-9a-fA-F]{1,16})(?:\s|$)", status_branch["operands"])
                    if status_branch is not None else None)
    target_rva = int(target_match.group(2), 16) - elf_base if target_match is not None else None
    r9_capture = next((item for item in instructions
                       if item["rva"] == "0x48bc48" and item["mnemonic"] == "mov"), None)
    r9_compare = next((item for item in instructions
                       if item["rva"] == "0x48bcb8" and item["mnemonic"] == "cmp"), None)
    compare_match = (re.fullmatch(r"DWORD PTR \[r14\],(0x[0-9a-f]+)",
                                  r9_compare["operands"], re.IGNORECASE)
                     if r9_compare is not None else None)
    if (not call_edge["call_target_matches_expected"] or not call_edge["call_return_address_matches"] or
            status_test is None or status_test["mnemonic"] != "test" or
            status_test["operands"] != "eax,eax" or status_branch is None or target_rva != 0x48BCB8 or
            r9_capture is None or r9_capture["operands"] != "r14,r9" or
            r9_compare is None or compare_match is None or int(compare_match.group(1), 16) != 3):
        raise ValueError("bounded ioctl wrapper status test/branch did not match")
    return {"ioctl_call_edge": call_edge,
            "ioctl_return_test": status_test,
            "nonnegative_status_branch": status_branch,
            "nonnegative_status_branch_target_rva": hex(target_rva),
            "r9_dword_compare": {
                "r9_capture_instruction": r9_capture,
                "r9_captured_in_r14": True,
                "compare_instruction": r9_compare,
                "compare_is_success_branch_target": int(r9_compare["rva"], 16) == target_rva,
                "compare_immediate": f"0x{int(compare_match.group(1), 16):x}",
                "interpretation_limit": (
                    "The wrapper dereferences a 32-bit value through the saved r9 pointer "
                    "after a nonnegative ioctl result and compares it with 3. This does not "
                    "identify that value's semantic field or featuresMask."
                ),
            },
            "interpretation_limit": "This proves status testing in the wrapper, not feature-mask dataflow."}


def summarize_r10_references(instructions: list[dict[str, str]]) -> dict[str, Any]:
    """List r10 mentions and candidate destination writes without claiming CFG dataflow."""
    register_pattern = re.compile(r"\br10(?:d|w|b)?\b", re.IGNORECASE)
    references = [item for item in instructions if register_pattern.search(item["operands"])]
    candidate_writes = []
    for item in references:
        destination = item["operands"].split(",", 1)[0].strip().lower()
        if destination in ("r10", "r10d", "r10w", "r10b") and item["mnemonic"] not in ("cmp", "test"):
            candidate_writes.append(item)
    return {
        "register_reference_count": len(references),
        "register_references": references,
        "candidate_destination_instructions": candidate_writes,
        "interpretation_limit": (
            "These are lexical references within the function prefix; candidate destinations "
            "do not prove control-flow reachability, dominance, or pointer/dataflow semantics."
        ),
    }


def summarize_r12_references(instructions: list[dict[str, str]]) -> dict[str, Any]:
    """List payload-pointer register mentions and lexical definitions only."""
    register_pattern = re.compile(r"\br12(?:d|w|b)?\b", re.IGNORECASE)
    references = [item for item in instructions if register_pattern.search(item["operands"])]
    candidate_writes = []
    for item in references:
        destination = item["operands"].split(",", 1)[0].strip().lower()
        if (destination in ("r12", "r12d", "r12w", "r12b") and
                item["mnemonic"] not in ("cmp", "test", "push")):
            candidate_writes.append(item)
    return {
        "register_reference_count": len(references),
        "register_references": references,
        "candidate_destination_instructions": candidate_writes,
        "interpretation_limit": (
            "These are lexical references within the caller prefix; they do not prove "
            "control-flow reachability, dominance, or that r12 is the SYSTEM_GET_FEATURES payload."
        ),
    }


def summarize_feature_query_ioctl_dataflow(
    instructions: list[dict[str, str]],
    *,
    callsite_instructions: list[dict[str, str]],
    parent_call_arguments: dict[str, Any],
) -> dict[str, Any]:
    """Match the pinned command-dispatch and frame construction, without claiming a full CFG.

    The caller scan is intentionally sparse.  This routine therefore checks a small,
    version-specific set of observed branch decisions and frame stores.  It does not
    reconstruct omitted basic blocks or the contents of the command callback table.
    """
    by_rva: dict[int, dict[str, str]] = {}
    duplicate_addresses: set[int] = set()
    for item in instructions:
        try:
            address = int(item["rva"], 16)
        except (KeyError, TypeError, ValueError):
            continue
        if address in by_rva:
            duplicate_addresses.add(address)
        by_rva[address] = item

    def exact(address: int, mnemonic: str, operands: str) -> dict[str, str] | None:
        item = by_rva.get(address)
        if (address in duplicate_addresses or item is None or
                item.get("mnemonic") != mnemonic or
                re.sub(r"\s+", "", item.get("operands", "")).lower() !=
                re.sub(r"\s+", "", operands).lower()):
            return None
        return item

    def target(item: dict[str, str] | None) -> int | None:
        if item is None:
            return None
        match = re.fullmatch(r"(?:0x)?([0-9a-f]+)", item["operands"].strip(), re.IGNORECASE)
        return int(match.group(1), 16) if match is not None else None

    command = parent_call_arguments.get("edx_command_candidate")
    size = parent_call_arguments.get("r8d_size_candidate")
    payload = parent_call_arguments.get("rcx_pointer_candidate")
    parent_args_match = (command == "0x1f0" and size == "0x4" and
                         isinstance(payload, str) and
                         re.fullmatch(r"\[rbp-0x[0-9a-f]+\]", payload, re.IGNORECASE) is not None)

    # Each tuple is (compare RVA, register, immediate, branch RVA, branch,
    # target, condition that must hold for command 0x1f0).
    branch_specs = (
        (0x494FCE, "edx", "0x27a", 0x494FD4, "jne", 0x495780, True),
        (0x495780, "edx", "0x278", 0x495786, "jne", 0x4957C0, True),
        (0x4957C0, "edx", "0x3d05", 0x4957C6, "jne", 0x495B15, True),
        (0x495B15, "ebx", "0x3d0a", 0x495B1B, "jne", 0x495424, True),
        (0x49542B, "ebx", "0x3d0b", 0x495431, "je", 0x495675, False),
        (0x495437, "ebx", "0x3d09", 0x49543D, "je", 0x495E62, False),
        (0x495443, "ebx", "0xfd0104", 0x495449, "je", 0x495B81, False),
        (0x49544F, "ebx", "0xe00101", 0x495455, "jne", 0x49582F, True),
        (0x49582F, "ebx", "0xd08", 0x495835, "jne", 0x496861, True),
    )
    branch_route: list[dict[str, Any]] = []
    branch_route_matched = bool(parent_args_match)
    for compare_rva, register, immediate, branch_rva, mnemonic, expected_target, taken in branch_specs:
        compare = exact(compare_rva, "cmp", f"{register},{immediate}")
        branch = by_rva.get(branch_rva)
        branch_valid = (branch_rva not in duplicate_addresses and branch is not None and
                        branch.get("mnemonic") == mnemonic and target(branch) == expected_target)
        branch_route_matched = branch_route_matched and compare is not None and branch_valid
        branch_route.append({
            "compare_rva": f"0x{compare_rva:x}",
            "compare_instruction": compare,
            "branch_rva": f"0x{branch_rva:x}",
            "branch_instruction": branch,
            "expected_taken_for_command_0x1f0": taken,
            "target_rva": f"0x{expected_target:x}" if branch_valid else None,
            "decision_basis": "command 0x1f0 compared with the pinned immediate",
        })

    dispatch_jump = by_rva.get(0x496868)
    frame_jump = by_rva.get(0x4957BA)
    dispatch_jump_matched = (0x496868 not in duplicate_addresses and
                             dispatch_jump is not None and
                             dispatch_jump.get("mnemonic") == "jmp" and
                             target(dispatch_jump) == 0x4957B7)
    frame_jump_matched = (0x4957BA not in duplicate_addresses and
                          frame_jump is not None and frame_jump.get("mnemonic") == "jmp" and
                          target(frame_jump) == 0x495497)
    branch_route_matched = branch_route_matched and dispatch_jump_matched and frame_jump_matched
    branch_route.extend((
        {"branch_rva": "0x496868", "branch_instruction": dispatch_jump,
         "target_rva": "0x4957b7" if dispatch_jump_matched else None,
         "decision_basis": "observed unconditional transfer"},
        {"branch_rva": "0x4957ba", "branch_instruction": frame_jump,
         "target_rva": "0x495497" if frame_jump_matched else None,
         "decision_basis": "observed unconditional transfer"},
    ))

    entry_command = exact(0x494F76, "mov", "ebx,edx")
    entry_payload = exact(0x494F72, "mov", "r12,rcx")
    entry_size = exact(0x494F7F, "mov", "DWORD PTR [rbp-0x1158],r8d")
    # The first taken dispatch branch and the later unconditional target jump
    # skip all other lexical r12 destinations in this image. A new destination
    # or moved block invalidates this narrow proof.
    r12_flow = summarize_r12_references(instructions)
    r12_destination_rvas = [int(item["rva"], 16)
                             for item in r12_flow["candidate_destination_instructions"]]
    expected_r12_destination_rvas = [
        0x494F72, 0x49505E, 0x4950B8, 0x495729, 0x496890, 0x496893,
    ]
    initial_branch_bypasses = all(0x494FD4 < address < 0x495780
                                  for address in (0x49505E, 0x4950B8, 0x495729))
    target_jump_bypasses = all(0x496868 < address < 0x4968D0
                               for address in (0x496890, 0x496893))
    pointer_register_matched = (
        entry_payload is not None and entry_command is not None and entry_size is not None and
        sorted(r12_destination_rvas) == sorted(expected_r12_destination_rvas) and
        initial_branch_bypasses and target_jump_bypasses and
        branch_route_matched
    )

    base = exact(0x496861, "lea", "r10,[rbp-0x1130]")
    r10_flow = summarize_r10_references(instructions)
    r10_destination_rvas = [int(item["rva"], 16)
                            for item in r10_flow["candidate_destination_instructions"]]
    expected_r10_destination_rvas = [
        0x495490, 0x49567D, 0x4956AC, 0x4957A6, 0x49580D, 0x495B75, 0x496861,
    ]
    r10_alternates_bypassed = (0x495786 < 0x4957A6 < 0x4957C0 and
                               all(0x495455 < address < 0x49582F
                                   for address in (0x495490, 0x49567D,
                                                   0x4956AC, 0x49580D)) and
                               0x495B1B < 0x495B75 and
                               target(by_rva.get(0x495B1B)) == 0x495424)
    r10_route_matched = (base is not None and
                         sorted(r10_destination_rvas) == sorted(expected_r10_destination_rvas) and
                         r10_alternates_bypassed and branch_route_matched)
    to_dispatch = dispatch_jump
    clear_scratch = exact(0x4957B7, "xor", "r15d,r15d")
    to_frame = frame_jump
    saved_size_read = exact(0x4954A2, "mov", "eax,DWORD PTR [rbp-0x1158]")
    command_store = exact(0x4954BF, "mov", "DWORD PTR [rbp-0x1128],ebx")
    params_store = exact(0x4954D0, "mov", "QWORD PTR [rbp-0x1120],r12")
    size_store = exact(0x4954D7, "mov", "DWORD PTR [rbp-0x1118],eax")
    generic_guard = exact(0x4954F9, "test", "eax,eax")
    generic_branch = by_rva.get(0x4954FB)
    frame_route_matched = (
        base is not None and target(to_dispatch) == 0x4957B7 and
        clear_scratch is not None and target(to_frame) == 0x495497 and
        saved_size_read is not None and command_store is not None and
        params_store is not None and size_store is not None and
        generic_guard is not None and generic_branch is not None and
        generic_branch.get("mnemonic") == "je" and target(generic_branch) == 0x495AA8
    )

    callsite_by_rva = {}
    duplicate_callsites: set[int] = set()
    for item in callsite_instructions:
        try:
            address = int(item["rva"], 16)
        except (KeyError, TypeError, ValueError):
            continue
        if address in callsite_by_rva:
            duplicate_callsites.add(address)
        callsite_by_rva[address] = item
    def call_exact(address: int, mnemonic: str, operands: str) -> dict[str, str] | None:
        item = callsite_by_rva.get(address)
        if (address in duplicate_callsites or item is None or item.get("mnemonic") != mnemonic or
                re.sub(r"\s+", "", item.get("operands", "")).lower() !=
                re.sub(r"\s+", "", operands).lower()):
            return None
        return item

    status_address = call_exact(0x495AAE, "lea", "r9,[rbp-0x1114]")
    struct_pointer = call_exact(0x495AB5, "mov", "r8,r10")
    request = call_exact(0x495AB8, "mov", "ecx,0xc020462a")
    ioctl_size = call_exact(0x495ABD, "mov", "edx,0x20")
    file_descriptor = call_exact(0x495AC2, "mov", "esi,0x2a")
    wrapper_call = call_exact(0x495AC7, "call", "48bc40")
    callsite_matched = all((status_address, struct_pointer, request, ioctl_size,
                            file_descriptor, wrapper_call))
    matched = bool(parent_args_match and pointer_register_matched and r10_route_matched and
                   frame_route_matched and callsite_matched)
    return {
        "path_specific_dataflow_matched": matched,
        "complete_cfg": False,
        "parent_command": command,
        "parent_payload_pointer": payload,
        "parent_payload_size": size,
        "branch_route": branch_route,
        "branch_route_matched": branch_route_matched,
        "r12_entry_transfer": entry_payload,
        "r12_alternate_destinations_bypassed_by_observed_transfers": [
            {"instruction_rva": f"0x{address:x}",
             "bypassed_by_transfer_rva": "0x494fd4" if address < 0x495780 else "0x496868"}
            for address in sorted(set(r12_destination_rvas) - {0x494F72})
        ],
        "r10_frame_base_transfer": base,
        "r10_route_matched": r10_route_matched,
        "r10_alternate_destinations_bypassed_by_observed_transfers": [
            {"instruction_rva": f"0x{address:x}",
             "bypassed_by_transfer_rva": {
                 0x495490: "0x495455", 0x49567D: "0x495455",
                 0x4956AC: "0x495455", 0x4957A6: "0x495786",
                 0x49580D: "0x495455", 0x495B75: "0x495b1b",
             }.get(address, None)}
            for address in sorted(set(r10_destination_rvas) - {0x496861})
        ],
        "frame_base": base,
        "frame_route_matched": frame_route_matched,
        "generic_dispatch_branch": {
            "test": generic_guard,
            "branch": generic_branch,
            "target_rva": "0x495aa8" if target(generic_branch) == 0x495AA8 else None,
            "table_sentinel_value_known": False,
        },
        "nvos54_fields": {
            "command": {"frame_offset": "0x8", "source": "ebx", "value": command,
                        "store": command_store},
            "params": {"frame_offset": "0x10", "source": "r12",
                       "source_is_parent_payload": bool(payload and entry_payload and matched),
                       "pointer": payload, "store": params_store},
            "params_size": {"frame_offset": "0x18", "source": "eax",
                            "value": size, "store": size_store,
                            "loaded_from_saved_r8d": saved_size_read is not None},
            "status": {"frame_offset": "0x1c", "expression": "rbp-0x1114",
                       "pointer_setup": status_address},
        },
        "wrapper_call_setup": {
            "request_code": "0xc020462a" if request is not None else None,
            "encoded_struct_size_bytes": 32 if ioctl_size is not None else None,
            "file_descriptor_candidate": "0x2a" if file_descriptor is not None else None,
            "struct_pointer_register": "r8" if struct_pointer is not None else None,
            "wrapper_target_rva": "0x48bc40" if wrapper_call is not None else None,
            "all_expected_setup_instructions_present": bool(callsite_matched),
        },
        "interpretation_limit": (
            "This matches the pinned R580 command-0x1f0 dispatch comparisons, the observed "
            "register/frame stores, and the wrapper-call setup in a filtered static scan. "
            "The scan is not a complete CFG, the callback-table contents and generic-path "
            "sentinel are unknown, and no machine-level dataflow proof spans omitted instructions. "
            "The separate runtime return-address correlation supports that this callsite was "
            "executed during the observed cuInit path; this does not establish general API, "
            "hybrid-driver, UVM, P2P, or same-Linux multi-GPU behavior."
        ),
    }


def summarize_filtered_control_flow(instructions: list[dict[str, str]]) -> dict[str, Any]:
    """Separate branch/predicate/call references from the sparse dataflow scan."""
    branches = [item for item in instructions
                if item["mnemonic"].startswith(("j", "loop"))]
    predicates = [item for item in instructions if item["mnemonic"] in ("cmp", "test")]
    calls = [item for item in instructions if item["mnemonic"].startswith("call")]
    returns = [item for item in instructions
               if item["mnemonic"].startswith(("ret", "iret"))]
    return {
        "branch_instructions": branches,
        "predicate_candidate_instructions": predicates,
        "call_instructions": calls,
        "return_instructions": returns,
        "complete_cfg": False,
        "interpretation_limit": (
            "This scan retains selected references, not every instruction. Branch targets are "
            "visible, but fallthrough instruction addresses and omitted basic-block contents "
            "are incomplete, so it is not a complete CFG or reaching-definition proof."
        ),
    }


def summarize_parent_call_arguments(
    instructions: list[dict[str, str]], *, call_rva: int,
) -> dict[str, Any]:
    """Report only last visible register/local writes in a branch-free prefix."""
    call_index = next((index for index, item in enumerate(instructions)
                       if int(item["rva"], 16) == call_rva and item["mnemonic"] == "call"), None)
    prefix = instructions[:call_index] if call_index is not None else instructions
    transfers = [item for item in prefix
                 if item["mnemonic"].startswith(("j", "loop")) or
                 item["mnemonic"] in ("call", "ret", "retq", "iret", "iretq")]
    single_block = call_index is not None and not transfers
    if not single_block:
        return {
            "call_instruction_rva": f"0x{call_rva:x}" if call_index is not None else None,
            "single_linear_pre_call_block": False,
            "pre_call_control_transfer_candidates": transfers,
            "rcx_pointer_candidate": None,
            "edx_command_candidate": None,
            "r8d_size_candidate": None,
            "zeroed_dword_candidate": None,
            "interpretation_limit": (
                "A branch/call/return before the site prevents this bounded linear window from "
                "identifying a unique argument state at the call. No arguments are inferred."
            ),
        }

    last_rcx: dict[str, str] | None = None
    last_edx: dict[str, str] | None = None
    last_r8d: dict[str, str] | None = None
    zeroed_dword: dict[str, str] | None = None
    for item in prefix:
        operands = item["operands"]
        if item["mnemonic"] == "lea":
            match = re.fullmatch(r"rcx,(.+)", operands, re.IGNORECASE)
            if match is not None:
                last_rcx = {"instruction": item["rva"], "value": match.group(1)}
        if item["mnemonic"] == "mov":
            for register, target in (("edx", "last_edx"), ("r8d", "last_r8d")):
                match = re.fullmatch(rf"{register},(0x[0-9a-f]+|[0-9]+)",
                                     operands, re.IGNORECASE)
                if match is not None:
                    value = f"0x{int(match.group(1), 0):x}"
                    if target == "last_edx":
                        last_edx = {"instruction": item["rva"], "value": value}
                    else:
                        last_r8d = {"instruction": item["rva"], "value": value}
            match = re.fullmatch(
                r"DWORD PTR (\[rbp-0x[0-9a-f]+\]),(?:0x0|0)", operands, re.IGNORECASE)
            if match is not None:
                zeroed_dword = {"instruction": item["rva"], "value": match.group(1)}

    pointer_value = last_rcx["value"] if last_rcx is not None else None
    zeroed_value = zeroed_dword["value"] if zeroed_dword is not None else None
    zeroed_matches_pointer = pointer_value == zeroed_value
    return {
        "call_instruction_rva": f"0x{call_rva:x}",
        "single_linear_pre_call_block": True,
        "pre_call_control_transfer_candidates": [],
        "rcx_pointer_candidate": pointer_value,
        "rcx_pointer_definition": last_rcx,
        "edx_command_candidate": last_edx["value"] if last_edx is not None else None,
        "edx_definition": last_edx,
        "r8d_size_candidate": last_r8d["value"] if last_r8d is not None else None,
        "r8d_definition": last_r8d,
        "zeroed_dword_candidate": zeroed_value,
        "zeroed_dword_definition": zeroed_dword,
        "zeroed_dword_matches_rcx_pointer": zeroed_matches_pointer,
        "interpretation_limit": (
            "These are last visible writes in the branch-free prefix beginning at the bounded "
            "function-entry window. They support the call-site register/local values, but do "
            "not by themselves establish a source-level prototype or the callee's later ioctl dataflow."
        ),
    }


def summarize_parent_feature_bit_consumer(
    instructions: list[dict[str, str]], *, call_rva: int,
    payload_pointer: str | None,
) -> dict[str, Any]:
    """Match the observed call-status gate, payload-bit test, and output-flag store."""
    call_index = next((index for index, item in enumerate(instructions)
                       if int(item["rva"], 16) == call_rva and item["mnemonic"] == "call"), None)
    by_rva = {int(item["rva"], 16): item for item in instructions}
    call_return_rva = call_rva + 5
    result_test = by_rva.get(call_return_rva)
    status_branch = by_rva.get(call_return_rva + 2)
    mask_test = by_rva.get(call_return_rva + 4)
    bit_branch = by_rva.get(call_return_rva + 8)
    flag_store = by_rva.get(call_return_rva + 10)
    test_match = (mask_test is not None and mask_test["mnemonic"] == "test" and
                  (test_fields := re.fullmatch(
                      r"BYTE PTR (\[[^]]+\]),(0x[0-9a-f]+|[0-9]+)",
                      mask_test["operands"], re.IGNORECASE)) is not None)
    bit_value = (int(test_fields.group(2), 0) if test_match else None)
    target_value = "460109"
    pattern = (
        call_index is not None and result_test is not None and
        result_test["mnemonic"] == "test" and result_test["operands"] == "eax,eax" and
        status_branch is not None and status_branch["mnemonic"] == "jne" and
        status_branch["operands"].lower() == target_value and
        test_match and test_fields.group(1).lower() == (payload_pointer or "").lower() and
        bit_value is not None and bit_value > 0 and bit_value & (bit_value - 1) == 0 and
        bit_branch is not None and bit_branch["mnemonic"] == "je" and
        bit_branch["operands"].lower() == target_value and
        flag_store is not None and flag_store["mnemonic"] == "mov" and
        flag_store["operands"].lower() == "byte ptr [rbx],0x1"
    )
    return {
        "pattern_matched": bool(pattern),
        "call_result_test": result_test,
        "nonzero_result_skip_branch": status_branch,
        "payload_bit_test": mask_test,
        "tested_payload": test_fields.group(1) if test_match else None,
        "tested_bit_value": f"0x{bit_value:x}" if bit_value is not None else None,
        "tested_bit_index": bit_value.bit_length() - 1 if bit_value is not None else None,
        "zero_bit_skip_branch": bit_branch,
        "conditional_output_flag_store": flag_store,
        "requires_zero_call_result": bool(
            result_test is not None and result_test["mnemonic"] == "test" and
            result_test["operands"] == "eax,eax" and status_branch is not None and
            status_branch["mnemonic"] == "jne" and status_branch["operands"].lower() == target_value
        ),
        "output_flag_set_only_when_bit_is_set": bool(
            test_match and bit_branch is not None and bit_branch["mnemonic"] == "je" and
            bit_branch["operands"].lower() == target_value and flag_store is not None and
            flag_store["mnemonic"] == "mov" and
            flag_store["operands"].lower() == "byte ptr [rbx],0x1"
        ),
        "interpretation_limit": (
            "This matches one bounded caller sequence. The source header identifies command "
            "0x1f0 and bit 3, but this static sequence alone does not prove broader API behavior "
            "or the callee's payload-pointer reaching definition at the ioctl."
        ),
    }


def summarize_ioctl_frame_layout(
    instructions: list[dict[str, str]],
    *,
    callsite_instructions: list[dict[str, str]] = (),
) -> dict[str, Any]:
    """Report frame-relative address arithmetic without inferring pointer reachability."""
    slot_pattern = re.compile(r"\[rbp-0x([0-9a-f]+)\]", re.IGNORECASE)
    base_sites: list[dict[str, str]] = []
    r9_sites: list[dict[str, str]] = []
    stack_accesses: list[dict[str, str]] = []
    request_codes: set[int] = set()
    for item in instructions:
        operands = item["operands"]
        if item["mnemonic"] == "lea" and re.fullmatch(
                r"r10,\[rbp-0x[0-9a-f]+\]", operands, re.IGNORECASE):
            base_sites.append(item)
        if item["mnemonic"] == "lea" and re.fullmatch(
                r"r9,\[rbp-0x[0-9a-f]+\]", operands, re.IGNORECASE):
            r9_sites.append(item)
        offsets = [int(value, 16) for value in slot_pattern.findall(operands)]
        if offsets:
            stack_accesses.append(item)
    for item in callsite_instructions:
        if item["mnemonic"] == "mov":
            match = re.fullmatch(r"ecx,(0x[0-9a-f]+)", item["operands"], re.IGNORECASE)
            if match is not None:
                request_codes.add(int(match.group(1), 16))

    base_expressions = {
        int(match.group(1), 16)
        for item in base_sites
        if (match := re.search(r"\[rbp-0x([0-9a-f]+)\]", item["operands"], re.IGNORECASE))
    }
    r9_expressions = {
        int(match.group(1), 16)
        for item in r9_sites
        if (match := re.search(r"\[rbp-0x([0-9a-f]+)\]", item["operands"], re.IGNORECASE))
    }
    deltas = {base - slot for base in base_expressions for slot in r9_expressions}
    delta = next(iter(deltas)) if len(deltas) == 1 else None
    request_code = next(iter(request_codes)) if len(request_codes) == 1 else None
    encoded_size = ((request_code >> 16) & 0x3FFF) if request_code is not None else None
    ends_at_boundary = (delta is not None and encoded_size is not None and
                        delta >= 0 and delta + 4 == encoded_size)
    return {
        "r10_frame_base_candidate_sites": base_sites,
        "r9_frame_pointer_candidate_sites": r9_sites,
        "candidate_base_expression": (
            f"rbp-0x{next(iter(base_expressions)):x}" if len(base_expressions) == 1 else None
        ),
        "r9_expression": (
            f"rbp-0x{next(iter(r9_expressions)):x}" if len(r9_expressions) == 1 else None
        ),
        "r9_offset_from_candidate_base": f"0x{delta:x}" if delta is not None else None,
        "stack_frame_access_instructions": stack_accesses,
        "request_code": f"0x{request_code:x}" if request_code is not None else None,
        "request_encoded_size_bytes": encoded_size,
        "four_byte_local_ends_at_encoded_span_boundary": ends_at_boundary,
        "candidate_base_reaches_ioctl_proven": False,
        "interpretation_limit": (
            "The offset is conditional on a candidate r10 base reaching the ioctl call. "
            "Lexical definitions do not prove that path; the encoded request size and "
            "frame-local offset do not identify the payload semantics or featuresMask."
        ),
    }


def _remote_root_script() -> str:
    helper = _load_transport_helper()
    hostkey_helper = inspect.getsource(helper.verify_guest_host_key)
    script = r"""import csv,hashlib,json,os,re,shlex,stat,subprocess,sys,tempfile
from pathlib import Path

EXPECTED_HOST="pc3"
EXPECTED_HOST_KERNEL="7.0.0-38-generic"
EXPECTED_GUEST="pc3-v100"
EXPECTED_GUEST_KERNEL="6.8.0-147-generic"
EXPECTED_GPU_UUID="GPU-42d06a85-027a-75ea-7857-a8de27ad465e"
EXPECTED_GPU_PCI="0000:00:05.0"
EXPECTED_DRIVER="580.178.04"
EXPECTED_LIBCUDA="/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04"
EXPECTED_LIBCUDA_SHA256="dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"
EXPECTED_LIBCUDA_BYTES=96284520
GUEST_KEY="/var/lib/pc3-v100-vm/id_ed25519"
GUEST_KNOWN_HOSTS="/tmp/codex-pc3-vm-known_hosts"
GUEST_FINGERPRINT="SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts"
GHIDRA_IMAGE_BASE=0x100000
CALLER_RETURN_RVAS=(0x495acc,0x477209,0x46311c,0x3248f0,0x47d265,0xf5712d,0x2d251e,0x331c32,0x3279b0,0x332226,0x327cb0)
RIP_RELATIVE_CALL_RETURNS={0x3279aa:0x3279b0,0x327a6a:0x327a70,0x327b2a:0x327b30,0x327bea:0x327bf0,0x327caa:0x327cb0,0x32866a:0x328670,0x32872a:0x328730,0x37828a:0x378290,0xf57127:0xf5712d}
RIP_RELATIVE_SLOT_VAS={0x5bcf9e8,0x5bcf9f0,0x5bcf9f8,0x5bcfa00,0x5bcfa08,0x5bcfa10,0x5bcfa18,0x5bcfa20,0x5bd7a50}
RIP_SLOT_CONTEXT_WINDOW_SPECS=((0x3f1b00,0x3f1c00),(0x3eb469,0x3eb509))
BRANCH_XREF_TARGET_RVAS={0x3f1b01,0x3f1b11,0x3f1b1d,0x3f1b39,0x3f1b40,0x3f1b50,0x3f1b55,0x3f1b6c,0x3f1b71,0x3f1b88,0x3f1b8d,0x3f1ba4,0x3f1ba9,0x3f1bc0,0x3f1bc5,0x3f1bdc}
BRANCH_XREF_EXACT_TARGETS={0x3eb469}
DIRECT_BRANCH_MNEMONICS={"call","callq","jmp","jmpq","ja","jae","jb","jbe","jc","jcxz","je","jecxz","jg","jge","jl","jle","jna","jnae","jnb","jnbe","jnc","jne","jng","jnge","jnl","jnle","jno","jnp","jns","jnz","jo","jp","jpe","jpo","jrcxz","js","jz"}
TARGET_CODE_START_RVA=0x332190; TARGET_CODE_STOP_RVA=0x332240
WINDOW_SPECS=((0x495aa0,0x495b20),(0x49551a,0x49559a),(0x4958e8,0x495968),(0x48bc40,0x48bd43),(0x495900,0x495ad4),(0x4600d0,0x460110),(0x495b00,0x495b90),(0x496850,0x4968d0),(0x495dc0,0x496040),(0x49d460,0x49d550))+tuple((r-0x40,r+0x10) for r in CALLER_RETURN_RVAS if r!=0x495acc)
TARGET_CALL_RVA=0x495ac7
TARGET_RETURN_RVA=0x495acc
HANDOFF_RVA=0x49551a
MAX_OUTPUT=131072

def call(argv,timeout=15):
    env={k:v for k,v in os.environ.items() if not k.startswith(("LD_","CUDA_","NVIDIA_","PYTHON"))}
    env.update({"PATH":"/usr/bin:/bin","LC_ALL":"C"})
    return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=timeout,check=False,env=env)

def guest_base():
    return ["ssh","-F","/dev/null","-T","-oBatchMode=yes","-oIdentitiesOnly=yes",
            "-oStrictHostKeyChecking=yes","-oUserKnownHostsFile="+GUEST_KNOWN_HOSTS,
            "-oConnectTimeout=8","-oConnectionAttempts=1","-i",GUEST_KEY,
            "-p","22223","ubuntu@127.0.0.1"]

def guest_json(code,timeout=30):
    cmd=" ".join(shlex.quote(x) for x in ("python3","-c",code))
    result=call(guest_base()+[cmd],timeout=timeout)
    if result.returncode or len(result.stdout)>MAX_OUTPUT or result.stderr:
        diagnostic=result.stderr.decode("utf-8","replace").replace("\\n"," ").replace("\\r"," ")[:240]
        raise RuntimeError(f"bounded guest inspection failed (ssh_exit={result.returncode}, stdout_bytes={len(result.stdout)}, stderr={diagnostic!r})")
    try: return json.loads(result.stdout.decode("utf-8","strict"))
    except (UnicodeDecodeError,ValueError): raise RuntimeError("guest inspection returned invalid JSON") from None

def main():
    if os.uname().nodename.split(".")[0]!=EXPECTED_HOST or os.uname().release!=EXPECTED_HOST_KERNEL:
        raise RuntimeError("PC3 host identity or kernel changed")
    for pci,vendor_device,driver in (("0000:02:00.0","0x10de 0x2c02","nvidia"),
                                    ("0000:81:00.0","0x10de 0x1db1","vfio-pci")):
        dev=Path("/sys/bus/pci/devices")/pci
        if (not dev.is_dir() or (dev/"vendor").read_text().strip()!="0x10de" or
                (dev/"device").read_text().strip()!=vendor_device.split()[1] or
                (dev/"driver").resolve().name!=driver):
            raise RuntimeError("PC3 PCI ownership differs from the pinned canary inventory")
    version=Path("/sys/module/nvidia/version").read_text().strip()
    if version!="595.99.02": raise RuntimeError("PC3 host NVIDIA module version changed")
    key=Path(GUEST_KEY); known=Path(GUEST_KNOWN_HOSTS)
    st=key.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600:
        raise RuntimeError("pinned guest SSH key ownership or mode is unsafe")
    verify_guest_host_key(known,GUEST_FINGERPRINT,0,call)
    guest_code=r'''import csv,hashlib,json,os,re,select,shutil,subprocess,sys,time
from pathlib import Path
CALLER_RETURN_RVAS=(0x495acc,0x477209,0x46311c,0x3248f0,0x47d265,0xf5712d,0x2d251e,0x331c32,0x3279b0,0x332226,0x327cb0)
RIP_RELATIVE_CALL_RETURNS={0x3279aa:0x3279b0,0x327a6a:0x327a70,0x327b2a:0x327b30,0x327bea:0x327bf0,0x327caa:0x327cb0,0x32866a:0x328670,0x32872a:0x328730,0x37828a:0x378290,0xf57127:0xf5712d}
RIP_RELATIVE_SLOT_VAS={0x5bcf9e8,0x5bcf9f0,0x5bcf9f8,0x5bcfa00,0x5bcfa08,0x5bcfa10,0x5bcfa18,0x5bcfa20,0x5bd7a50}
RIP_SLOT_CONTEXT_WINDOW_SPECS=((0x3f1b00,0x3f1c00),(0x3eb469,0x3eb509))
BRANCH_XREF_TARGET_RVAS={0x3f1b01,0x3f1b11,0x3f1b1d,0x3f1b39,0x3f1b40,0x3f1b50,0x3f1b55,0x3f1b6c,0x3f1b71,0x3f1b88,0x3f1b8d,0x3f1ba4,0x3f1ba9,0x3f1bc0,0x3f1bc5,0x3f1bdc}
BRANCH_XREF_EXACT_TARGETS={0x3eb469}
DIRECT_BRANCH_MNEMONICS={"call","callq","jmp","jmpq","ja","jae","jb","jbe","jc","jcxz","je","jecxz","jg","jge","jl","jle","jna","jnae","jnb","jnbe","jnc","jne","jng","jnge","jnl","jnle","jno","jnp","jns","jnz","jo","jp","jpe","jpo","jrcxz","js","jz"}
TARGET_CODE_START_RVA=0x332190; TARGET_CODE_STOP_RVA=0x332240
WINDOW_SPECS=((0x495aa0,0x495b20),(0x49551a,0x49559a),(0x4958e8,0x495968),(0x48bc40,0x48bd43),(0x495900,0x495ad4),(0x4600d0,0x460110),(0x495b00,0x495b90),(0x496850,0x4968d0),(0x495dc0,0x496040),(0x49d460,0x49d550))+tuple((r-0x40,r+0x10) for r in CALLER_RETURN_RVAS if r!=0x495acc)
def run(argv,timeout=20):
 r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                  text=True,timeout=timeout,check=False,env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
 return r
gpu=run(["nvidia-smi","--query-gpu=name,uuid,pci.bus_id,driver_version","--format=csv,noheader,nounits"])
rows=[r for r in csv.reader(gpu.stdout.splitlines(),skipinitialspace=True)]
if gpu.returncode or len(rows)!=1 or len(rows[0])!=4: raise SystemExit(10)
name,uuid,pci,driver=[x.strip() for x in rows[0]]
if os.uname().nodename.split(".")[0]!="pc3-v100" or os.uname().release!="6.8.0-147-generic": raise SystemExit(11)
pci_match=re.fullmatch(r"(0000|00000000):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])",pci)
if pci_match is None: raise SystemExit(12)
pci=f"{int(pci_match.group(1),16)&0xffff:04x}:{int(pci_match.group(2),16):02x}:{int(pci_match.group(3),16):02x}.{int(pci_match.group(4),16)}"
if uuid!="GPU-42d06a85-027a-75ea-7857-a8de27ad465e" or pci!="0000:00:05.0" or driver!="580.178.04" or not name.startswith("Tesla V100"): raise SystemExit(12)
path=Path("/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04")
st=path.stat(); digest=hashlib.sha256(path.read_bytes()).hexdigest()
if st.st_size!=96284520 or digest!="dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9": raise SystemExit(13)
ph=run(["readelf","-lW",str(path)])
if ph.returncode: raise SystemExit(14)
loads=[]
for line in ph.stdout.splitlines():
 f=line.split()
 if len(f)>2 and f[0]=="LOAD":
  try: loads.append(int(f[2],16))
  except ValueError: raise SystemExit(15)
if not loads: raise SystemExit(16)
elf_base=min(loads)
obj=shutil.which("objdump")
if not obj: raise SystemExit(17)
windows=[]
for start_rva,stop_rva in WINDOW_SPECS:
 start=elf_base+start_rva; stop=elf_base+stop_rva
 dis=run([obj,"-d","-M","intel","--no-show-raw-insn",f"--start-address={start:#x}",f"--stop-address={stop:#x}",str(path)])
 if dis.returncode or len(dis.stdout.encode())>16384: raise SystemExit(18)
 windows.append({"start_rva":hex(start_rva),"stop_rva_exclusive":hex(stop_rva),
                 "window_va_start":hex(start),"window_va_stop_exclusive":hex(stop),
                 "disassembly":dis.stdout})
section_table=run(["readelf","-SW",str(path)],timeout=20)
if section_table.returncode or len(section_table.stdout.encode())>4194304: raise SystemExit(38)
section_bytes=len(section_table.stdout.encode()); section_lines=0
section_records=[]
section_pattern_full=re.compile(r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]{1,16})\s+[0-9a-fA-F]{1,16}\s+([0-9a-fA-F]{1,16})\s+[0-9a-fA-F]{1,16}\s+(\S+)")
for line in section_table.stdout.splitlines():
 section_lines+=1
 if section_lines>4096: raise SystemExit(39)
 section_match=section_pattern_full.match(line)
 if section_match is None: continue
 section_name,section_type,section_start,section_size,section_flags=section_match.group(1,2,3,4,5)
 section_records.append({"section_name":section_name,"section_type":section_type,
  "section_start_va":int(section_start,16),"section_size_bytes":int(section_size,16),
  "section_flags":section_flags})
 if len(section_records)>256: raise SystemExit(42)
text_sections=[item for item in section_records if item["section_name"]==".text"]
if len(text_sections)!=1 or text_sections[0]["section_type"]!="PROGBITS" or "X" not in text_sections[0]["section_flags"] or text_sections[0]["section_size_bytes"]<=0: raise SystemExit(43)
text_section=text_sections[0]; text_start_va=text_section["section_start_va"]
text_end_va=text_start_va+text_section["section_size_bytes"]
target_rvas={elf_base+rva:rva for rva in CALLER_RETURN_RVAS}
boundary_candidates={address:[] for address in target_rvas}
rip_slot_candidates={rva:[] for rva in RIP_RELATIVE_CALL_RETURNS}
target_code_records=[]
slot_reference_candidates=[]
branch_reference_candidates=[]
decoded_branch_target_rvas=[]
slot_context_lines={start:[] for start,stop in RIP_SLOT_CONTEXT_WINDOW_SPECS}
boundary_proc=subprocess.Popen([obj,"-D","-w","-M","intel","-j",".text",str(path)],
 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={"PATH":"/usr/bin:/bin","LC_ALL":"C"},bufsize=0)
if boundary_proc.stdout is None: raise SystemExit(21)
boundary_fd=boundary_proc.stdout.fileno(); pending=bytearray(); scanned=0; lines=0
deadline=time.monotonic()+180; completed_to_section_end=False; first_instruction_va=None
last_instruction_va=None; last_instruction_length=0; previous_instruction_end=None
contiguous_byte_coverage=True
def consume_boundary_line(raw_line):
 global lines,first_instruction_va,last_instruction_va,last_instruction_length
 global previous_instruction_end,contiguous_byte_coverage
 lines+=1
 if lines>8000000: raise SystemExit(22)
 match=re.match(rb"^\s*([0-9a-fA-F]{1,16}):\s*(.*)$",raw_line)
 if match is None: return
 address=int(match.group(1),16)
 fields=match.group(2).split()
 length=0
 while fields and re.fullmatch(rb"[0-9a-fA-F]{2}",fields[0]):
  length+=1; fields.pop(0)
 if not fields or not 1<=length<=15: return
 mnemonic=fields[0].decode("ascii","ignore").lower()
 instruction_rva=address-elf_base
 if address<text_start_va or address>=text_end_va: raise SystemExit(44)
 if instruction_rva in BRANCH_XREF_TARGET_RVAS or instruction_rva in BRANCH_XREF_EXACT_TARGETS:
  decoded_branch_target_rvas.append(hex(instruction_rva))
  if len(decoded_branch_target_rvas)>256: raise SystemExit(47)
 if first_instruction_va is None: first_instruction_va=address
 if previous_instruction_end is not None and address!=previous_instruction_end:
  contiguous_byte_coverage=False
 last_instruction_va=address
 last_instruction_length=length; previous_instruction_end=address+length
 operands_bytes=b" ".join(fields[1:])
 operands_bytes=operands_bytes.split(b"#",1)[0].rstrip()
 for context_start,context_stop in RIP_SLOT_CONTEXT_WINDOW_SPECS:
  if context_start<=instruction_rva<context_stop:
   context_line=f"  {instruction_rva:x}:\t{mnemonic}"
   if operands_bytes: context_line+=" "+operands_bytes.decode("ascii","ignore")
   slot_context_lines[context_start].append(context_line)
   if len(slot_context_lines[context_start])>256: raise SystemExit(46)
 if mnemonic in DIRECT_BRANCH_MNEMONICS:
  direct_target_match=re.fullmatch(
   rb"(?:0x)?([0-9a-fA-F]{1,16})(?:[ \t]+<[^<>\r\n]{1,256}>)?",operands_bytes)
  if direct_target_match is not None:
   target_va=int(direct_target_match.group(1),16)
   target_rva=target_va-elf_base
   in_local_context=any(start<=instruction_rva<stop for start,stop in RIP_SLOT_CONTEXT_WINDOW_SPECS)
   if (target_rva in BRANCH_XREF_TARGET_RVAS or
       (target_rva in BRANCH_XREF_EXACT_TARGETS and in_local_context)):
    branch_reference_candidates.append({"source_rva":hex(instruction_rva),
     "source_length_bytes":length,"mnemonic":mnemonic,"target_rva":hex(target_rva)})
    if len(branch_reference_candidates)>256: raise SystemExit(48)
 for rip_match in re.finditer(rb"\[rip([+-])0x([0-9a-fA-F]+)\]",operands_bytes,re.I):
  operand_start=operands_bytes.rfind(b",",0,rip_match.start())+1
  if re.search(rb"\b(?:fs|gs):",operands_bytes[operand_start:rip_match.start()],re.I): continue
  displacement=int(rip_match.group(2),16)*(1 if rip_match.group(1)==b"+" else -1)
  target_va=address+length+displacement
  if target_va in RIP_RELATIVE_SLOT_VAS:
   slot_reference_candidates.append({"instruction_rva":hex(instruction_rva),
    "length_bytes":length,"mnemonic":mnemonic,
    "operand_index":operands_bytes[:rip_match.start()].count(b","),
    "operands":operands_bytes.decode("ascii","ignore"),"slot_va":hex(target_va)})
   if len(slot_reference_candidates)>64: raise SystemExit(40)
 if TARGET_CODE_START_RVA<=instruction_rva<TARGET_CODE_STOP_RVA:
  operands=b" ".join(fields[1:]).decode("ascii","ignore")
  target_code_records.append({"rva":hex(instruction_rva),"length_bytes":length,
   "mnemonic":mnemonic,"operands":operands})
  if len(target_code_records)>64: raise SystemExit(37)
 if instruction_rva in RIP_RELATIVE_CALL_RETURNS:
  if mnemonic not in ("call","callq") or address+length!=elf_base+RIP_RELATIVE_CALL_RETURNS[instruction_rva]: raise SystemExit(29)
  operands=operands_bytes.decode("ascii","ignore")
  displacement_match=re.search(r"\[rip([+-])0x([0-9a-f]+)\]",operands,re.I)
  if displacement_match is None: raise SystemExit(30)
  displacement=int(displacement_match.group(2),16)*(1 if displacement_match.group(1)=="+" else -1)
  slot_va=address+length+displacement
  rip_slot_candidates[instruction_rva].append({"call_rva":hex(instruction_rva),
   "observed_return_rva":hex(RIP_RELATIVE_CALL_RETURNS[instruction_rva]),
   "call_length_bytes":length,"slot_va":hex(slot_va),"slot_rva":hex(slot_va-elf_base),
   "call_instruction":{"rva":hex(instruction_rva),"length_bytes":length,
    "mnemonic":mnemonic,"operands":operands}})
 return_rva=target_rvas.get(address+length)
 if return_rva is not None and mnemonic in ("call","callq"):
  boundary_candidates[address+length].append({"instruction_rva":hex(address-elf_base),
   "length_bytes":length,"mnemonic":mnemonic})
try:
 while True:
  remaining=deadline-time.monotonic()
  if remaining<=0: raise SystemExit(23)
  ready,_,_=select.select([boundary_fd],[],[],remaining)
  if not ready: raise SystemExit(23)
  chunk=os.read(boundary_fd,65536)
  if not chunk: break
  scanned+=len(chunk)
  if scanned>536870912: raise SystemExit(24)
  pending.extend(chunk)
  if len(pending)>1048576 and b"\n" not in pending: raise SystemExit(25)
  while b"\n" in pending:
   raw_line,_,tail=pending.partition(b"\n"); pending=bytearray(tail)
   consume_boundary_line(raw_line)
 if pending: consume_boundary_line(bytes(pending))
 boundary_proc.wait(timeout=3)
 if boundary_proc.returncode!=0: raise SystemExit(28)
 completed_to_section_end=True
finally:
 if boundary_proc.poll() is None:
  boundary_proc.kill(); boundary_proc.wait()
if (not completed_to_section_end or first_instruction_va!=text_start_va or
    last_instruction_va is None or last_instruction_va<max(target_rvas) or
    last_instruction_va+last_instruction_length!=text_end_va or
    not contiguous_byte_coverage): raise SystemExit(41)
slot_reference_contexts=[]
for start_rva,stop_rva in RIP_SLOT_CONTEXT_WINDOW_SPECS:
 start=elf_base+start_rva; stop=elf_base+stop_rva
 disassembly="\n".join(slot_context_lines[start_rva])
 if not slot_context_lines[start_rva] or len(disassembly.encode())>8192: raise SystemExit(45)
 slot_reference_contexts.append({"start_rva":hex(start_rva),"stop_rva_exclusive":hex(stop_rva),
                 "window_va_start":hex(start),"window_va_stop_exclusive":hex(stop),
                 "disassembly":disassembly})
boundary_records=[]
for return_va,rva in sorted(target_rvas.items()):
 candidates=boundary_candidates[return_va]
 if len(candidates)!=1: raise SystemExit(26)
 item=candidates[0]
 if int(item["instruction_rva"],16)+item["length_bytes"]!=rva: raise SystemExit(27)
 boundary_records.append({"observed_return_rva":hex(rva),**item,"ends_at_return":True})
rip_slot_records=[]
for call_rva,return_rva in sorted(RIP_RELATIVE_CALL_RETURNS.items()):
 candidates=rip_slot_candidates[call_rva]
 if len(candidates)!=1: raise SystemExit(31)
 rip_slot_records.append(candidates[0])
target_slots={int(item["slot_va"],16) for item in rip_slot_records}
relocations=run(["readelf","-rW",str(path)],timeout=30)
if relocations.returncode or len(relocations.stdout.encode())>67108864: raise SystemExit(32)
relocation_bytes=len(relocations.stdout.encode()); relocation_lines=0
relocations_by_slot={slot:[] for slot in target_slots}
for line in relocations.stdout.splitlines():
 relocation_lines+=1
 if relocation_lines>1000000: raise SystemExit(33)
 fields=line.split()
 if len(fields)<3 or re.fullmatch(r"[0-9a-fA-F]{1,16}",fields[0]) is None: continue
 slot=int(fields[0],16)
 if slot not in relocations_by_slot: continue
 relocation_type=fields[2]
 if re.fullmatch(r"R_X86_64_[A-Z0-9_]+",relocation_type) is None: raise SystemExit(34)
 addend=None
 if relocation_type=="R_X86_64_RELATIVE":
  if len(fields)<4 or re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}",fields[-1]) is None: raise SystemExit(35)
  addend=hex(int(fields[-1],16))
 relocations_by_slot[slot].append({"relocation_type":relocation_type,"addend":addend})
if any(len(entries)>8 for entries in relocations_by_slot.values()): raise SystemExit(36)
for item in rip_slot_records:
 item["relocations"]=relocations_by_slot[int(item["slot_va"],16)]
sections_by_slot={slot:[] for slot in target_slots}
for section in section_records:
 section_name=section["section_name"]; section_type=section["section_type"]
 section_start=section["section_start_va"]; section_size=section["section_size_bytes"]
 if section_size==0: continue
 for slot in sections_by_slot:
  if section_start<=slot<section_start+section_size:
   sections_by_slot[slot].append({"section_name":section_name,"section_type":section_type,
    "section_start_va":hex(section_start),"section_size_bytes":section_size})
for item in rip_slot_records:
 item["sections"]=sections_by_slot[int(item["slot_va"],16)]
readelf_version=run(["readelf","--version"]).stdout.splitlines()[0]
scan_start_rva=0x494f60; scan_stop_rva=0x495ac7
scan_start=elf_base+scan_start_rva; scan_stop=elf_base+scan_stop_rva
scan=run([obj,"-d","-M","intel","--no-show-raw-insn",f"--start-address={scan_start:#x}",f"--stop-address={scan_stop:#x}",str(path)])
if scan.returncode or len(scan.stdout.encode())>131072: raise SystemExit(19)
decoded=[]
for line in scan.stdout.splitlines():
 m=re.match(r"^\s*([0-9a-fA-F]{1,16}):\s+(.+)$",line)
 if m is not None:
  decoded.append((int(m.group(1),16),m.group(2).strip(),line))
selected_by_address={}
flag_producers={"cmp","test","dec","sub","add","and","or","xor","inc","neg","bt","bts","btr","shr","shl","sar","imul"}
for index,(address,body,line) in enumerate(decoded):
 mnemonic=body.split(None,1)[0].lower()
 offsets=[int(value,16) for value in re.findall(r"\[rbp-0x([0-9a-f]+)\]",body,re.I)]
 frame_access=any(0x1000<=offset<=0x11ff for offset in offsets)
 control=mnemonic.startswith(("j","loop","call","ret","iret"))
 tracked_register=re.search(r"\b(?:r10|r12|edx|rdx)(?:d|w|b)?\b",body,re.I)
 predicate=mnemonic in ("cmp","test") and (tracked_register or frame_access)
 if tracked_register or frame_access or control or predicate:
  selected_by_address[address]=line
 if mnemonic.startswith(("j","loop")) and index>0:
  previous_address,previous_body,previous_line=decoded[index-1]
  previous_mnemonic=previous_body.split(None,1)[0].lower()
  if previous_mnemonic in flag_producers:
   selected_by_address[previous_address]=previous_line
selected=[selected_by_address[address] for address in sorted(selected_by_address)]
selected_bytes=len("\n".join(selected).encode())
if not selected or len(selected)>512 or selected_bytes>24576:
 print(f"bounded flow scan exceeded its fixed cap (records={len(selected)}, bytes={selected_bytes})",file=sys.stderr)
 raise SystemExit(20)
print(json.dumps({"hostname":os.uname().nodename.split(".")[0],"kernel_release":os.uname().release,
 "gpu":{"name":name,"uuid":uuid,"pci":pci,"driver_version":driver},
 "libcuda":{"path":str(path),"bytes":st.st_size,"sha256":digest},
 "elf_load_base":hex(elf_base),"ghidra_image_base":"0x100000",
 "objdump_version":run([obj,"--version"]).stdout.splitlines()[0],"windows":windows,
 "slot_reference_contexts":slot_reference_contexts,
 "caller_instruction_boundaries":boundary_records,
 "rip_relative_call_slots":rip_slot_records,
 "relocation_target_code_window":{"start_rva":hex(TARGET_CODE_START_RVA),
  "stop_rva_exclusive":hex(TARGET_CODE_STOP_RVA),"instructions":target_code_records},
 "relocation_scan":{"readelf_version":readelf_version,"scanned_output_bytes":relocation_bytes,
                     "parsed_line_count":relocation_lines,"symbol_names_transmitted":False,
                     "section_table_bytes":section_bytes,"section_table_lines":section_lines},
 "text_section":{"name":".text","type":text_section["section_type"],
                 "flags":text_section["section_flags"],"start_va":hex(text_start_va),
                 "size_bytes":text_section["section_size_bytes"],"end_va":hex(text_end_va)},
 "executable_sections":[{"name":item["section_name"],"type":item["section_type"],
                         "start_va":hex(item["section_start_va"]),
                         "size_bytes":item["section_size_bytes"],"scanned":item["section_name"]==".text"}
                        for item in section_records if "X" in item["section_flags"]],
 "boundary_scan":{"section":".text","scanned_output_bytes":scanned,
                   "parsed_line_count":lines,"stopped_after_last_return_rva":False,
                   "completed_to_section_end":completed_to_section_end,
                   "first_decoded_rva":hex(first_instruction_va-elf_base),
                   "last_decoded_rva":hex(last_instruction_va-elf_base),
                   "last_instruction_length_bytes":last_instruction_length,
                   "contiguous_byte_coverage":contiguous_byte_coverage,
                   "section_start_va":hex(text_start_va),"section_end_va":hex(text_end_va),
                   "covers_all_target_rvas":True,
                   "raw_instruction_bytes_transmitted":False},
 "slot_reference_scan":{"section":".text","scanned_output_bytes":scanned,
                   "parsed_line_count":lines,"completed_to_section_end":completed_to_section_end,
                   "section_start_va":hex(text_start_va),"section_end_va":hex(text_end_va),
                   "raw_instruction_bytes_transmitted":False,
                   "references":slot_reference_candidates},
 "branch_xref_scan":{"section":".text","scanned_output_bytes":scanned,
                   "parsed_line_count":lines,"completed_to_section_end":completed_to_section_end,
                   "section_start_va":hex(text_start_va),"section_end_va":hex(text_end_va),
                   "raw_instruction_bytes_transmitted":False,
                   "decoded_target_instruction_start_rvas":decoded_branch_target_rvas,
                   "references":branch_reference_candidates},
 "register_scan":{"start_rva":hex(scan_start_rva),"stop_rva_exclusive":hex(scan_stop_rva),
                  "window_va_start":hex(scan_start),"window_va_stop_exclusive":hex(scan_stop),
                  "disassembly":"\n".join(selected)}},separators=(",",":")))
'''
    result=guest_json(guest_code,timeout=240)
    print("PC3_DISASSEMBLY_RESULT:"+json.dumps({"schema":"nvidia-hybrid-pc3-v100-libcuda-window-transport-v2",
      "host_kernel":os.uname().release,"host_nvidia_module_version":version,
      "host_pci_ownership":{"0000:02:00.0":"nvidia","0000:81:00.0":"vfio-pci"},
      "guest":result},sort_keys=True,separators=(",",":")))

"""
    script += hostkey_helper
    script += "\nif __name__ == '__main__':\n    try:\n        main()\n    except Exception as error:\n        print(str(error)[:500], file=sys.stderr)\n        raise SystemExit(1)\n"
    return script


def _parse_remote_payload(text: str) -> dict[str, Any]:
    records = [line.split("PC3_DISASSEMBLY_RESULT:", 1)[1] for line in text.splitlines()
               if "PC3_DISASSEMBLY_RESULT:" in line]
    if len(records) != 1:
        raise ValueError("expected one bounded PC3 disassembly result")
    value = json.loads(records[0])
    if not isinstance(value, dict) or value.get("schema") != "nvidia-hybrid-pc3-v100-libcuda-window-transport-v2":
        raise ValueError("unsupported PC3 disassembly transport result")
    return value


def collect_remote_window() -> dict[str, Any]:
    helper = _load_transport_helper()
    secret = helper.fetch_pc3_sudo_secret(helper.DEFAULT_CREDENTIAL_HOST,
                                          helper.DEFAULT_CREDENTIAL_FILE)
    script = _remote_root_script()
    remote = "sudo -S -p '' python3 -c " + shlex.quote(script)
    try:
        completed = subprocess.run(
            helper.pc3_ssh_base(helper.DEFAULT_PC3_TARGET, helper.DEFAULT_HOST_KEY_ALIAS) + [remote],
            input=helper.sudo_auth_stdin(secret), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=300, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("read-only PC3 disassembly transport failed or timed out") from None
    if completed.returncode != 0 or len(completed.stdout) > 131072:
        safe_stderr = helper.redact_secret(completed.stderr.decode("utf-8", "replace"), secret)
        raise RuntimeError(
            f"read-only PC3 disassembly command failed (ssh_exit={completed.returncode}, "
            f"stdout_bytes={len(completed.stdout)}, stderr={safe_stderr[:350]!r})"
        )
    try:
        return _parse_remote_payload(completed.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("PC3 did not return one valid bounded disassembly record") from None


def validate_remote_payload(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("remote disassembly report is not an object")
    if (value.get("schema") != "nvidia-hybrid-pc3-v100-libcuda-window-transport-v2" or
            value.get("host_kernel") != EXPECTED_HOST_KERNEL or
            value.get("host_nvidia_module_version") != "595.99.02" or
            value.get("host_pci_ownership") != {"0000:02:00.0": "nvidia", "0000:81:00.0": "vfio-pci"}):
        raise ValueError("PC3 host identity or non-invasive PCI ownership check failed")
    guest = value.get("guest")
    if not isinstance(guest, dict) or guest.get("hostname") != EXPECTED_GUEST or guest.get("kernel_release") != EXPECTED_GUEST_KERNEL:
        raise ValueError("pinned V100 guest identity changed")
    gpu = guest.get("gpu")
    if (not isinstance(gpu, dict) or gpu.get("uuid") != EXPECTED_GPU_UUID or
            gpu.get("pci") != EXPECTED_GPU_PCI or gpu.get("driver_version") != EXPECTED_DRIVER or
            not isinstance(gpu.get("name"), str) or not gpu["name"].startswith("Tesla V100")):
        raise ValueError("pinned V100 guest GPU identity changed")
    library = guest.get("libcuda")
    if (not isinstance(library, dict) or library.get("path") != EXPECTED_LIBCUDA or
            library.get("bytes") != EXPECTED_LIBCUDA_BYTES or
            library.get("sha256") != EXPECTED_LIBCUDA_SHA256):
        raise ValueError("pinned R580 libcuda identity changed")
    elf_base_value = guest.get("elf_load_base")
    if not isinstance(elf_base_value, str) or re.fullmatch(r"0x[0-9a-f]+", elf_base_value) is None:
        raise ValueError("ELF load base is missing or malformed")
    elf_base = int(elf_base_value, 16)
    if (elf_base != EXPECTED_ELF_LOAD_BASE or
            guest.get("ghidra_image_base") != hex(GHIDRA_IMAGE_BASE)):
        raise ValueError("ELF-to-Ghidra address mapping differs from the pinned mapping")
    objdump_version = guest.get("objdump_version")
    raw_windows = guest.get("windows")
    expected_specs = BASE_WINDOW_SPECS + GPU_NAME_CALLER_WINDOW_SPECS
    if not isinstance(objdump_version, str) or len(objdump_version) > 120 or not isinstance(raw_windows, list) or len(raw_windows) != len(expected_specs):
        raise ValueError("bounded objdump window metadata is missing")
    windows: list[dict[str, Any]] = []
    for raw_window, (start_rva, stop_rva) in zip(raw_windows, expected_specs):
        if (not isinstance(raw_window, dict) or raw_window.get("start_rva") != hex(start_rva) or
                raw_window.get("stop_rva_exclusive") != hex(stop_rva) or
                raw_window.get("window_va_start") != hex(elf_base + start_rva) or
                raw_window.get("window_va_stop_exclusive") != hex(elf_base + stop_rva) or
                not isinstance(raw_window.get("disassembly"), str)):
            raise ValueError("bounded disassembly window does not match its requested addresses")
        instructions = parse_instruction_window(
            raw_window["disassembly"], image_base=elf_base,
            start_rva=start_rva, stop_rva=stop_rva)
        windows.append({"start_rva": hex(start_rva), "stop_rva_exclusive": hex(stop_rva),
                        "instructions": instructions})
    raw_boundaries = guest.get("caller_instruction_boundaries")
    raw_boundary_scan = guest.get("boundary_scan")
    if (not isinstance(raw_boundaries, list) or
            not isinstance(raw_boundary_scan, dict) or
            raw_boundary_scan.get("section") != ".text" or
            type(raw_boundary_scan.get("scanned_output_bytes")) is not int or
            not 0 <= raw_boundary_scan["scanned_output_bytes"] <= 536870912 or
            type(raw_boundary_scan.get("parsed_line_count")) is not int or
            not 0 <= raw_boundary_scan["parsed_line_count"] <= 8000000 or
            type(raw_boundary_scan.get("stopped_after_last_return_rva")) is not bool or
            type(raw_boundary_scan.get("completed_to_section_end")) is not bool or
            raw_boundary_scan["stopped_after_last_return_rva"] is not False or
            raw_boundary_scan["completed_to_section_end"] is not True or
            raw_boundary_scan.get("covers_all_target_rvas") is not True or
            raw_boundary_scan.get("contiguous_byte_coverage") is not True or
            raw_boundary_scan.get("raw_instruction_bytes_transmitted") is not False):
        raise ValueError("complete bounded raw-byte-discarding caller boundary scan is missing or malformed")
    raw_text_section = guest.get("text_section")
    if (not isinstance(raw_text_section, dict) or raw_text_section.get("name") != ".text" or
            raw_text_section.get("type") != "PROGBITS" or
            not isinstance(raw_text_section.get("flags"), str) or
            "X" not in raw_text_section["flags"] or
            re.fullmatch(r"[A-Z]{1,8}", raw_text_section["flags"]) is None or
            type(raw_text_section.get("size_bytes")) is not int or
            not 1 <= raw_text_section["size_bytes"] <= 0x40000000):
        raise ValueError("pinned executable .text section bounds are missing or malformed")
    text_start_va = _parse_address(raw_text_section.get("start_va"), ".text start VA")
    text_end_va = _parse_address(raw_text_section.get("end_va"), ".text end VA")
    if text_end_va != text_start_va + raw_text_section["size_bytes"]:
        raise ValueError(".text section size does not match its reported address bounds")
    text_start_rva = text_start_va - elf_base
    text_end_rva = text_end_va - elf_base
    if (raw_boundary_scan.get("section_start_va") != hex(text_start_va) or
            raw_boundary_scan.get("section_end_va") != hex(text_end_va)):
        raise ValueError("caller disassembly coverage does not match the ELF .text bounds")
    first_decoded_rva = _parse_address(
        raw_boundary_scan.get("first_decoded_rva"), "first decoded text RVA")
    last_decoded_rva = _parse_address(
        raw_boundary_scan.get("last_decoded_rva"), "last decoded text RVA")
    last_instruction_length = raw_boundary_scan.get("last_instruction_length_bytes")
    if (first_decoded_rva != text_start_rva or
            last_decoded_rva < max(GPU_NAME_CALLER_RETURN_RVAS) or
            type(last_instruction_length) is not int or not 1 <= last_instruction_length <= 15 or
            last_decoded_rva + last_instruction_length != text_end_rva):
        raise ValueError("complete text scan did not cover the pinned section interval and caller returns")
    raw_executable_sections = guest.get("executable_sections")
    if not isinstance(raw_executable_sections, list) or len(raw_executable_sections) > 128:
        raise ValueError("bounded executable-section inventory is missing or malformed")
    executable_section_names = []
    scanned_text_sections = 0
    for section in raw_executable_sections:
        if not isinstance(section, dict):
            raise ValueError("executable-section inventory record is malformed")
        name, section_type = section.get("name"), section.get("type")
        start_va = _parse_address(section.get("start_va"), "executable section start VA")
        size_bytes = section.get("size_bytes")
        scanned = section.get("scanned")
        if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.$-]{1,120}", name) is None or
                not isinstance(section_type, str) or re.fullmatch(r"[A-Z0-9_]{1,32}", section_type) is None or
                type(size_bytes) is not int or not 1 <= size_bytes <= 0x40000000 or
                type(scanned) is not bool or scanned != (name == ".text")):
            raise ValueError("executable-section inventory record is malformed or mislabels scan scope")
        executable_section_names.append(name)
        scanned_text_sections += int(scanned)
    if scanned_text_sections != 1 or len(set(executable_section_names)) != len(executable_section_names):
        raise ValueError("executable-section inventory has a duplicate or missing .text scan")
    if len(raw_boundaries) != len(GPU_NAME_CALLER_RETURN_RVAS):
        raise ValueError("caller instruction-boundary count differs from the runtime trace")
    boundaries_by_return: dict[int, dict[str, Any]] = {}
    for item in raw_boundaries:
        if not isinstance(item, dict):
            raise ValueError("caller instruction-boundary record is malformed")
        return_rva = _parse_address(item.get("observed_return_rva"), "caller return RVA")
        instruction_rva = _parse_address(item.get("instruction_rva"), "caller instruction RVA")
        length_bytes = item.get("length_bytes")
        mnemonic = item.get("mnemonic")
        if (return_rva not in GPU_NAME_CALLER_RETURN_RVAS or
                return_rva in boundaries_by_return or type(length_bytes) is not int or
                not 1 <= length_bytes <= 15 or mnemonic not in ("call", "callq") or
                item.get("ends_at_return") is not True or
                instruction_rva + length_bytes != return_rva):
            raise ValueError("caller instruction boundary does not end at the observed return address")
        boundaries_by_return[return_rva] = {
            "instruction_rva": hex(instruction_rva),
            "length_bytes": length_bytes,
            "mnemonic": mnemonic,
        }
    if set(boundaries_by_return) != set(GPU_NAME_CALLER_RETURN_RVAS):
        raise ValueError("caller instruction-boundary set differs from the runtime trace")
    caller_windows = {RETURN_RVA: windows[0]}
    caller_windows.update({
        return_rva: window for return_rva, window in zip(
            (rva for rva in GPU_NAME_CALLER_RETURN_RVAS if rva != RETURN_RVA),
            windows[len(BASE_WINDOW_SPECS):])})
    caller_return_site_windows = []
    for return_rva in GPU_NAME_CALLER_RETURN_RVAS:
        window = caller_windows[return_rva]
        return_text = hex(return_rva)
        return_index = next((index for index, instruction in enumerate(window["instructions"])
                             if instruction["rva"] == return_text), None)
        previous = (window["instructions"][return_index - 1]
                    if return_index is not None and return_index > 0 else None)
        previous_is_call = previous is not None and previous["mnemonic"] in ("call", "callq")
        boundary = boundaries_by_return[return_rva]
        boundary_verified = (
            previous_is_call and previous["rva"] == boundary["instruction_rva"] and
            previous["mnemonic"] == boundary["mnemonic"])
        if not boundary_verified:
            raise ValueError("decoded call predecessor disagrees with the exact instruction boundary")
        previous_call_kind = (
            "indirect" if previous_is_call and "[" in previous["operands"] else
            "direct" if previous_is_call else None)
        caller_return_site_windows.append({
            "observed_return_rva": return_text,
            "window_start_rva": window["start_rva"],
            "window_stop_rva_exclusive": window["stop_rva_exclusive"],
            "previous_decoded_instruction": previous,
            "previous_instruction_is_call": previous_is_call,
            "previous_instruction_boundary_verified": boundary_verified,
            "previous_instruction_length_bytes": boundary["length_bytes"],
            "previous_call_kind": previous_call_kind,
            "instruction_at_return": (
                window["instructions"][return_index]
                if return_index is not None else None),
            "instructions": window["instructions"],
        })
    raw_slots = guest.get("rip_relative_call_slots")
    raw_relocation_scan = guest.get("relocation_scan")
    if (not isinstance(raw_slots, list) or
            not isinstance(raw_relocation_scan, dict) or
            not isinstance(raw_relocation_scan.get("readelf_version"), str) or
            len(raw_relocation_scan["readelf_version"]) > 120 or
            type(raw_relocation_scan.get("scanned_output_bytes")) is not int or
            not 0 <= raw_relocation_scan["scanned_output_bytes"] <= 67108864 or
            type(raw_relocation_scan.get("parsed_line_count")) is not int or
            not 0 <= raw_relocation_scan["parsed_line_count"] <= 1000000 or
            type(raw_relocation_scan.get("section_table_bytes")) is not int or
            not 0 <= raw_relocation_scan["section_table_bytes"] <= 4194304 or
            type(raw_relocation_scan.get("section_table_lines")) is not int or
            not 0 <= raw_relocation_scan["section_table_lines"] <= 4096 or
            raw_relocation_scan.get("symbol_names_transmitted") is not False or
            len(raw_slots) != len(RIP_RELATIVE_CALL_RETURNS)):
        raise ValueError("bounded selected-slot relocation scan is missing or malformed")
    return_site_by_rva = {
        int(item["observed_return_rva"], 16): item
        for item in caller_return_site_windows
    }
    slots_by_call: dict[int, dict[str, Any]] = {}
    for raw_slot in raw_slots:
        if not isinstance(raw_slot, dict):
            raise ValueError("RIP-relative call slot record is malformed")
        call_rva = _parse_address(raw_slot.get("call_rva"), "RIP-relative call RVA")
        return_rva = _parse_address(raw_slot.get("observed_return_rva"), "RIP-relative return RVA")
        slot_va = _parse_address(raw_slot.get("slot_va"), "relocation slot VA")
        slot_rva = _parse_address(raw_slot.get("slot_rva"), "relocation slot RVA")
        call_instruction = raw_slot.get("call_instruction")
        if not isinstance(call_instruction, dict):
            raise ValueError("RIP-relative call instruction record is missing")
        instruction_rva = _parse_address(call_instruction.get("rva"),
                                         "RIP-relative call instruction RVA")
        instruction_length = call_instruction.get("length_bytes")
        mnemonic = call_instruction.get("mnemonic")
        operands = call_instruction.get("operands")
        if (call_rva not in RIP_RELATIVE_CALL_RETURNS or
                RIP_RELATIVE_CALL_RETURNS[call_rva] != return_rva or
                call_rva in slots_by_call or slot_va != elf_base + slot_rva or
                raw_slot.get("call_length_bytes") != 6 or
                instruction_rva != call_rva or instruction_length != 6 or
                raw_slot.get("call_length_bytes") != instruction_length or
                mnemonic not in ("call", "callq") or
                not isinstance(operands, str) or len(operands) > 512):
            raise ValueError("RIP-relative call slot identity or length changed")
        return_site = return_site_by_rva.get(return_rva)
        if return_site is not None:
            previous = return_site["previous_decoded_instruction"]
            if previous is None or previous["rva"] != hex(call_rva):
                raise ValueError("RIP-relative slot disagrees with its traced predecessor call")
        displacement_match = re.search(
            r"\[rip([+-])0x([0-9a-f]+)\]", operands, re.IGNORECASE)
        if displacement_match is None:
            raise ValueError("RIP-relative call operand is not parseable")
        if not re.fullmatch(r"(?:QWORD PTR )?\[rip[+-]0x[0-9a-f]+\]",
                            operands, re.IGNORECASE):
            raise ValueError("RIP-relative indirect call operand changed")
        displacement = int(displacement_match.group(2), 16)
        if displacement_match.group(1) == "-":
            displacement = -displacement
        computed_slot_rva = call_rva + instruction_length + displacement
        if slot_rva != computed_slot_rva:
            raise ValueError("relocation slot does not match the observed RIP-relative operand")
        raw_relocations = raw_slot.get("relocations")
        if not isinstance(raw_relocations, list) or len(raw_relocations) > 8:
            raise ValueError("selected slot relocation entries exceed their bound")
        relocations_for_slot = []
        for relocation in raw_relocations:
            if not isinstance(relocation, dict):
                raise ValueError("selected relocation record is malformed")
            relocation_type = relocation.get("relocation_type")
            addend_value = relocation.get("addend")
            if (not isinstance(relocation_type, str) or
                    re.fullmatch(r"R_X86_64_[A-Z0-9_]+", relocation_type) is None or
                    (addend_value is not None and
                     (not isinstance(addend_value, str) or
                      re.fullmatch(r"0x[0-9a-f]+", addend_value) is None))):
                raise ValueError("selected relocation type or addend is malformed")
            relocations_for_slot.append({"relocation_type": relocation_type,
                                         "addend": addend_value})
        raw_sections = raw_slot.get("sections")
        if not isinstance(raw_sections, list) or len(raw_sections) > 4:
            raise ValueError("selected slot section records exceed their bound")
        sections_for_slot = []
        for section in raw_sections:
            if not isinstance(section, dict):
                raise ValueError("selected slot section record is malformed")
            section_name = section.get("section_name")
            section_type = section.get("section_type")
            section_start_va = _parse_address(section.get("section_start_va"), "section start VA")
            section_size_bytes = section.get("section_size_bytes")
            if (not isinstance(section_name, str) or
                    re.fullmatch(r"[A-Za-z0-9_.$-]{1,120}", section_name) is None or
                    not isinstance(section_type, str) or
                    re.fullmatch(r"[A-Z0-9_]{1,32}", section_type) is None or
                    type(section_size_bytes) is not int or
                    not 1 <= section_size_bytes <= 0x100000000 or
                    not section_start_va <= slot_va < section_start_va + section_size_bytes):
                raise ValueError("selected slot does not lie within its reported ELF section")
            sections_for_slot.append({
                "section_name": section_name, "section_type": section_type,
                "section_start_va": hex(section_start_va),
                "section_size_bytes": section_size_bytes,
            })
        if call_rva == 0x3279AA and not any(
                item["relocation_type"] == "R_X86_64_RELATIVE" and
                item["addend"] == "0x331bc0" for item in relocations_for_slot):
            raise ValueError("known Ghidra relocation control did not resolve to 0x331bc0")
        slots_by_call[call_rva] = {
            "call_rva": hex(call_rva), "observed_return_rva": hex(return_rva),
            "call_length_bytes": raw_slot["call_length_bytes"],
            "call_instruction": {"rva": hex(instruction_rva),
                                  "length_bytes": instruction_length,
                                  "mnemonic": mnemonic, "operands": operands},
            "slot_va": hex(slot_va), "slot_rva": hex(slot_rva),
            "relocations": relocations_for_slot, "sections": sections_for_slot,
        }
    if set(slots_by_call) != set(RIP_RELATIVE_CALL_RETURNS):
        raise ValueError("RIP-relative relocation slot set differs from the pinned callsites")
    if any(int(slots_by_call[call_rva]["slot_va"], 16) != expected_slot_va
           for call_rva, expected_slot_va in RIP_RELATIVE_CALL_SLOT_VAS.items()):
        raise ValueError("RIP-relative callsite resolved to a slot outside the pinned ELF addresses")
    rip_relative_slot_report = {
        "readelf_version": raw_relocation_scan["readelf_version"],
        "scanned_output_bytes": raw_relocation_scan["scanned_output_bytes"],
        "parsed_line_count": raw_relocation_scan["parsed_line_count"],
        "section_table_bytes": raw_relocation_scan["section_table_bytes"],
        "section_table_lines": raw_relocation_scan["section_table_lines"],
        "symbol_names_transmitted": False,
        "slots": [slots_by_call[rva] for rva in sorted(slots_by_call)],
        "interpretation_limit": (
            "ELF relocation addends identify static initial pointer values for these slots; "
            "they do not prove the pointer remains unchanged after library initialization."),
    }
    raw_reference_scan = guest.get("slot_reference_scan")
    if (not isinstance(raw_reference_scan, dict) or
            raw_reference_scan.get("section") != ".text" or
            type(raw_reference_scan.get("scanned_output_bytes")) is not int or
            raw_reference_scan["scanned_output_bytes"] != raw_boundary_scan["scanned_output_bytes"] or
            type(raw_reference_scan.get("parsed_line_count")) is not int or
            raw_reference_scan["parsed_line_count"] != raw_boundary_scan["parsed_line_count"] or
            raw_reference_scan.get("section_start_va") != hex(text_start_va) or
            raw_reference_scan.get("section_end_va") != hex(text_end_va) or
            raw_reference_scan.get("completed_to_section_end") is not True or
            raw_reference_scan.get("raw_instruction_bytes_transmitted") is not False or
            not isinstance(raw_reference_scan.get("references"), list) or
            len(raw_reference_scan["references"]) > 64):
        raise ValueError("bounded complete text scan for RIP-relative slot references is missing or malformed")
    raw_branch_scan = guest.get("branch_xref_scan")
    if (not isinstance(raw_branch_scan, dict) or
            raw_branch_scan.get("section") != ".text" or
            raw_branch_scan.get("scanned_output_bytes") != raw_boundary_scan["scanned_output_bytes"] or
            raw_branch_scan.get("parsed_line_count") != raw_boundary_scan["parsed_line_count"] or
            raw_branch_scan.get("section_start_va") != hex(text_start_va) or
            raw_branch_scan.get("section_end_va") != hex(text_end_va) or
            raw_branch_scan.get("completed_to_section_end") is not True or
            raw_branch_scan.get("raw_instruction_bytes_transmitted") is not False or
            not isinstance(raw_branch_scan.get("references"), list) or
            not isinstance(raw_branch_scan.get("decoded_target_instruction_start_rvas"), list)):
        raise ValueError("bounded complete text scan for direct branch xrefs is missing or malformed")
    direct_branch_xref_report = summarize_direct_branch_xrefs(
        raw_branch_scan["references"],
        decoded_target_rvas=raw_branch_scan["decoded_target_instruction_start_rvas"],
        text_start_rva=text_start_va - elf_base,
        text_end_rva=text_end_va - elf_base)
    known_slot_vas = ({int(item["slot_va"], 16) for item in slots_by_call.values()} |
                      RIP_SLOT_CONTEXT_VAS)
    normalized_references = []
    seen_references = set()
    for raw_reference in raw_reference_scan["references"]:
        if not isinstance(raw_reference, dict):
            raise ValueError("RIP-relative slot reference record is malformed")
        instruction_rva = _parse_address(raw_reference.get("instruction_rva"),
                                         "slot-reference instruction RVA")
        length_bytes = raw_reference.get("length_bytes")
        mnemonic = raw_reference.get("mnemonic")
        operand_index = raw_reference.get("operand_index")
        operands = raw_reference.get("operands")
        slot_va = _parse_address(raw_reference.get("slot_va"), "RIP-relative slot reference VA")
        if (type(length_bytes) is not int or not 1 <= length_bytes <= 15 or
                not isinstance(mnemonic, str) or MNEMONIC_RE.fullmatch(mnemonic) is None or
                type(operand_index) is not int or not 0 <= operand_index <= 5 or
                not isinstance(operands, str) or not operands.isascii() or len(operands) > 192 or
                slot_va not in known_slot_vas):
            raise ValueError("RIP-relative slot reference exceeds its bound or targets an unknown slot")
        operand_parts = [part.strip() for part in operands.split(",")]
        if operand_index >= len(operand_parts):
            raise ValueError("RIP-relative slot reference operand index is outside its instruction")
        displacement_match = re.search(
            r"\[rip([+-])0x([0-9a-f]+)\]", operand_parts[operand_index], re.IGNORECASE)
        if displacement_match is None:
            raise ValueError("RIP-relative slot reference operand is not parseable")
        displacement = int(displacement_match.group(2), 16)
        if displacement_match.group(1) == "-":
            displacement = -displacement
        if not -(1 << 31) <= displacement < (1 << 31):
            raise ValueError("RIP-relative slot reference displacement is outside signed disp32")
        if re.search(r"\b(?:fs|gs):", operand_parts[operand_index], re.IGNORECASE):
            raise ValueError("segmented RIP-relative operands are outside the direct slot scan")
        instruction_va = elf_base + instruction_rva
        if not text_start_va <= instruction_va < instruction_va + length_bytes <= text_end_va:
            raise ValueError("RIP-relative slot reference instruction is outside the scanned .text")
        computed_va = elf_base + instruction_rva + length_bytes + displacement
        identity = (instruction_rva, length_bytes, mnemonic, operand_index, operands, slot_va)
        if computed_va != slot_va or identity in seen_references:
            raise ValueError("RIP-relative slot reference does not resolve to its reported slot")
        seen_references.add(identity)
        if operand_index == 0 and mnemonic in ("mov", "movabs", "pop"):
            access_class = "direct-write"
        elif mnemonic in ("xchg", "xchgq"):
            access_class = "read-write"
        elif mnemonic.startswith(("call", "jmp")):
            access_class = "indirect-control-read"
        elif mnemonic == "lea":
            access_class = "address-only"
        elif (operand_index == 0 and
              (mnemonic in ("add", "or", "and", "xor", "sub", "inc", "dec", "neg", "not",
                            "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr",
                            "bts", "btr", "btc", "cmpxchg", "xadd") or
               mnemonic.startswith("set"))):
            access_class = "read-write" if not mnemonic.startswith("set") else "direct-write"
        elif mnemonic in ("cmp", "test", "bt", "push"):
            access_class = "read"
        elif mnemonic.startswith("prefetch"):
            access_class = "prefetch"
        elif mnemonic in ("clflush", "clflushopt", "clwb"):
            access_class = "cache-maintenance"
        elif operand_index > 0:
            access_class = "read"
        else:
            access_class = "unknown"
        normalized_references.append({
            "instruction_rva": hex(instruction_rva), "length_bytes": length_bytes,
            "mnemonic": mnemonic, "operand_index": operand_index,
            "operands": operands, "slot_va": hex(slot_va),
            "static_access_class": access_class,
        })
    raw_contexts = guest.get("slot_reference_contexts")
    if not isinstance(raw_contexts, list) or len(raw_contexts) != len(RIP_SLOT_CONTEXT_WINDOW_SPECS):
        raise ValueError("bounded RIP-relative store-context window is missing or malformed")
    context_windows = []
    context_instructions: dict[int, dict[str, str]] = {}
    for raw_context, (start_rva, stop_rva) in zip(
            raw_contexts, RIP_SLOT_CONTEXT_WINDOW_SPECS):
        if (not isinstance(raw_context, dict) or
                raw_context.get("start_rva") != hex(start_rva) or
                raw_context.get("stop_rva_exclusive") != hex(stop_rva) or
                raw_context.get("window_va_start") != hex(elf_base + start_rva) or
                raw_context.get("window_va_stop_exclusive") != hex(elf_base + stop_rva) or
                not isinstance(raw_context.get("disassembly"), str)):
            raise ValueError("RIP-relative store-context window does not match its pinned range")
        decoded_context = parse_instruction_window(
            raw_context["disassembly"], image_base=elf_base,
            start_rva=start_rva, stop_rva=stop_rva)
        if start_rva == 0x3EB469 and (
                not decoded_context or decoded_context[0]["rva"] != hex(start_rva)):
            raise ValueError("common sink context does not begin at its verified target instruction")
        for instruction in decoded_context:
            instruction_rva = int(instruction["rva"], 16)
            if instruction_rva in context_instructions:
                raise ValueError("RIP-relative store-context windows contain duplicate instructions")
            context_instructions[instruction_rva] = instruction
        context_windows.append({"start_rva": hex(start_rva),
                                "stop_rva_exclusive": hex(stop_rva),
                                "instructions": decoded_context})
    for reference in normalized_references:
        instruction_rva = int(reference["instruction_rva"], 16)
        if not any(start <= instruction_rva < stop
                   for start, stop in RIP_SLOT_CONTEXT_WINDOW_SPECS):
            continue
        instruction = context_instructions.get(instruction_rva)
        if (instruction is None or instruction["mnemonic"] != reference["mnemonic"] or
                instruction["operands"] != reference["operands"]):
            raise ValueError(
                "bounded slot-reference instruction disagrees with its disassembly context "
                f"(rva={instruction_rva:#x}, reference={reference!r}, context={instruction!r})")
    references_by_instruction = {
        int(item["instruction_rva"], 16): item for item in normalized_references
    }
    store_contexts = []
    for write_rva, expected_slot_va in RIP_SLOT_CONTEXT_WRITE_TARGETS.items():
        write_instruction = context_instructions.get(write_rva)
        write_reference = references_by_instruction.get(write_rva)
        if (write_instruction is None or write_reference is None or
                write_reference["slot_va"] != hex(expected_slot_va) or
                write_reference["static_access_class"] != "direct-write" or
                write_instruction["mnemonic"] != write_reference["mnemonic"] or
                write_instruction["operands"] != write_reference["operands"]):
            raise ValueError(
                "pinned direct-store candidate disagrees with its bounded code context "
                f"(rva={write_rva:#x}, instruction={write_instruction!r}, "
                f"reference={write_reference!r})")
        read_rva = next((rva for rva, slot_va in RIP_SLOT_CONTEXT_READ_TARGETS.items()
                         if slot_va == expected_slot_va), None)
        read_instruction = context_instructions.get(read_rva) if read_rva is not None else None
        read_reference = references_by_instruction.get(read_rva) if read_rva is not None else None
        if (read_instruction is None or read_reference is None or
                read_reference["slot_va"] != hex(expected_slot_va) or
                read_reference["static_access_class"] != "read" or
                read_instruction["mnemonic"] != read_reference["mnemonic"] or
                read_instruction["operands"] != read_reference["operands"] or
                read_rva >= write_rva):
            raise ValueError("pinned same-slot load candidate is absent from the bounded code context")
        between = [instruction for instruction in context_windows[0]["instructions"]
                   if read_rva < int(instruction["rva"], 16) < write_rva]
        store_contexts.append({
            "read_instruction": read_instruction,
            "store_instruction": write_instruction,
            "intervening_instructions": between,
            "source_register_reaching_definition": "not established",
            "interpretation_limit": (
                "Nearby decoded instructions preserve a static context only; this report does "
                "not infer control-flow reachability, register value propagation, or runtime writes."),
        })
    branch_references_by_pair = {
        (int(item["source_rva"], 16), int(item["target_rva"], 16))
        for item in direct_branch_xref_report["references"]
    }
    for raw_reference in direct_branch_xref_report["references"]:
        source_rva = int(raw_reference["source_rva"], 16)
        if not any(start <= source_rva < stop
                   for start, stop in RIP_SLOT_CONTEXT_WINDOW_SPECS):
            continue
        source_instruction = context_instructions.get(source_rva)
        direct_target = (parse_direct_branch_target(
            source_instruction["mnemonic"], source_instruction["operands"])
            if source_instruction is not None else None)
        expected_target_rva = int(raw_reference["target_rva"], 16)
        if direct_target is None or direct_target - elf_base != expected_target_rva:
            raise ValueError("direct-branch xref disagrees with its bounded source context")
    for source_rva, source_instruction in context_instructions.items():
        direct_target = parse_direct_branch_target(
            source_instruction["mnemonic"], source_instruction["operands"])
        if direct_target is None:
            continue
        target_rva = direct_target - elf_base
        target_in_scope = (target_rva in RIP_SLOT_BRANCH_XREF_TARGET_RVAS or
                           target_rva in RIP_SLOT_BRANCH_XREF_EXACT_TARGETS)
        if target_in_scope and (source_rva, target_rva) not in branch_references_by_pair:
            raise ValueError("bounded direct-branch source is absent from the complete xref scan")
    rip_relative_slot_report["direct_rip_reference_scan"] = {
        "section": ".text",
        "scanned_output_bytes": raw_reference_scan["scanned_output_bytes"],
        "parsed_line_count": raw_reference_scan["parsed_line_count"],
        "completed_to_section_end": True,
        "raw_instruction_bytes_transmitted": False,
        "scanned_section_start_va": hex(text_start_va),
        "scanned_section_end_va": hex(text_end_va),
        "unscanned_executable_sections": [
            item for item in executable_section_names if item != ".text"],
        "references": normalized_references,
        "direct_branch_xref_scan": direct_branch_xref_report,
        "write_context_windows": context_windows,
        "same_slot_read_store_contexts": store_contexts,
        "interpretation_limit": (
            "This lists direct unsegmented RIP-relative operands from .text only; linear "
            "disassembly can include unreachable/data bytes and classifies syntax, not execution. "
            "Other executable sections and writes through register aliases, computed pointers, "
            "generic memory routines or runtime-generated code are outside this scan."),
    }
    raw_target_code = guest.get("relocation_target_code_window")
    if (not isinstance(raw_target_code, dict) or
            raw_target_code.get("start_rva") != hex(RIP_RELATIVE_TARGET_CODE_START_RVA) or
            raw_target_code.get("stop_rva_exclusive") != hex(RIP_RELATIVE_TARGET_CODE_STOP_RVA) or
            not isinstance(raw_target_code.get("instructions"), list) or
            len(raw_target_code["instructions"]) > 64):
        raise ValueError("bounded relocation-target code window is missing or malformed")
    target_lines = []
    for instruction in raw_target_code["instructions"]:
        if not isinstance(instruction, dict):
            raise ValueError("relocation-target instruction record is malformed")
        rva = _parse_address(instruction.get("rva"), "relocation-target instruction RVA")
        length_bytes = instruction.get("length_bytes")
        mnemonic = instruction.get("mnemonic")
        operands = instruction.get("operands")
        if (not RIP_RELATIVE_TARGET_CODE_START_RVA <= rva < RIP_RELATIVE_TARGET_CODE_STOP_RVA or
                type(length_bytes) is not int or not 1 <= length_bytes <= 15 or
                not isinstance(mnemonic, str) or MNEMONIC_RE.fullmatch(mnemonic) is None or
                not isinstance(operands, str) or len(operands.encode("utf-8")) > 192):
            raise ValueError("relocation-target instruction exceeds its bound or operand filter")
        target_lines.append(f"{rva:x}: {mnemonic} {operands}".rstrip())
    if not target_lines:
        raise ValueError("relocation-target code window contains no decoded instructions")
    target_code_instructions = parse_instruction_window(
        "\n".join(target_lines), image_base=0,
        start_rva=RIP_RELATIVE_TARGET_CODE_START_RVA,
        stop_rva=RIP_RELATIVE_TARGET_CODE_STOP_RVA)
    target_address_instruction = next((item for item in target_code_instructions
                                       if item["rva"] == "0x332190"), None)
    observed_target_return_call = next((item for item in target_code_instructions
                                        if item["rva"] == "0x332220" and
                                        item["mnemonic"] in ("call", "callq")), None)
    rip_relative_slot_report["relocation_target_code"] = {
        "candidate_target_rva": "0x332190",
        "instruction_at_candidate_target": target_address_instruction,
        "observed_frame_return_rva": "0x332226",
        "call_before_observed_frame_return": observed_target_return_call,
        "candidate_and_frame_return_share_bounded_code_window": (
            target_address_instruction is not None and observed_target_return_call is not None),
        "interpretation_limit": (
            "The relocated pointer addend is a candidate code address and the same linear "
            "text scan decoded the observed frame's predecessor call. This does not prove "
            "a function boundary, execution target at runtime, or API semantics."),
    }
    raw_scan = guest.get("register_scan")
    if (not isinstance(raw_scan, dict) or
            raw_scan.get("start_rva") != hex(CALLER_SCAN_START_RVA) or
            raw_scan.get("stop_rva_exclusive") != hex(CALLER_SCAN_STOP_RVA) or
            raw_scan.get("window_va_start") != hex(elf_base + CALLER_SCAN_START_RVA) or
            raw_scan.get("window_va_stop_exclusive") != hex(elf_base + CALLER_SCAN_STOP_RVA) or
            not isinstance(raw_scan.get("disassembly"), str)):
        raise ValueError("bounded caller register-reference scan is missing or malformed")
    register_scan = parse_instruction_window(
        raw_scan["disassembly"], image_base=elf_base,
        start_rva=CALLER_SCAN_START_RVA, stop_rva=CALLER_SCAN_STOP_RVA)
    r10_flow = summarize_r10_references(register_scan)
    if not r10_flow["register_references"]:
        raise ValueError("caller-prefix scan found no r10 references")
    r12_flow = summarize_r12_references(register_scan)
    if not r12_flow["register_references"]:
        raise ValueError("caller-prefix scan found no r12 references")
    filtered_control_flow = summarize_filtered_control_flow(register_scan)
    if (not filtered_control_flow["branch_instructions"] or
            not filtered_control_flow["call_instructions"]):
        raise ValueError("caller-prefix scan lacks the bounded branch/call overlay")
    instructions = windows[0]["instructions"]
    frame_layout = summarize_ioctl_frame_layout(
        register_scan, callsite_instructions=instructions)
    summary = summarize_window(instructions, call_rva=CALL_RVA, return_rva=RETURN_RVA,
                               expected_callee_rva=CALLEE_RVA, image_base=elf_base)
    if not summary["call_target_matches_expected"] or not summary["call_return_address_matches"]:
        raise ValueError("instruction window does not reproduce the pinned static call edge")
    follow_instructions = windows[1]["instructions"]
    success_instructions = windows[2]["instructions"]
    control_flow = summarize_call_handoff(instructions, follow_instructions,
                                          success_instructions, elf_base=elf_base)
    ioctl_summary = summarize_ioctl_wrapper(windows[3]["instructions"], elf_base=elf_base)
    parent_call_instructions = windows[5]["instructions"]
    parent_call_edge = summarize_window(
        parent_call_instructions, call_rva=PARENT_CALL_RVA,
        return_rva=PARENT_RETURN_RVA, expected_callee_rva=PARENT_CALLEE_RVA,
        image_base=elf_base)
    if (not parent_call_edge["call_target_matches_expected"] or
            not parent_call_edge["call_return_address_matches"]):
        raise ValueError("instruction window does not reproduce the pinned parent call edge")
    parent_argument_candidates = [
        item for item in parent_call_instructions
        if int(item["rva"], 16) < PARENT_CALL_RVA and
        item["mnemonic"] in ("mov", "lea", "movabs") and
        re.match(r"^(?:e?cx|rcx),", item["operands"], re.IGNORECASE)
    ]
    parent_call_arguments = summarize_parent_call_arguments(
        parent_call_instructions, call_rva=PARENT_CALL_RVA)
    if (not parent_call_arguments["single_linear_pre_call_block"] or
            parent_call_arguments["edx_command_candidate"] != "0x1f0" or
            parent_call_arguments["r8d_size_candidate"] != "0x4" or
            parent_call_arguments["rcx_pointer_candidate"] is None or
            parent_call_arguments["zeroed_dword_candidate"] is None or
            not parent_call_arguments["zeroed_dword_matches_rcx_pointer"]):
        raise ValueError("bounded parent call no longer matches the pinned feature-query argument pattern")
    parent_bit_consumer = summarize_parent_feature_bit_consumer(
        parent_call_instructions, call_rva=PARENT_CALL_RVA,
        payload_pointer=parent_call_arguments["rcx_pointer_candidate"])
    if not parent_bit_consumer["pattern_matched"]:
        raise ValueError("bounded parent call no longer matches the pinned feature-bit consumer pattern")
    feature_query_dataflow = summarize_feature_query_ioctl_dataflow(
        [*register_scan, *windows[6]["instructions"], *windows[7]["instructions"]],
        callsite_instructions=instructions,
        parent_call_arguments=parent_call_arguments)
    if not feature_query_dataflow["path_specific_dataflow_matched"]:
        raise ValueError("bounded SYSTEM_GET_FEATURES command/payload/frame path no longer matches the pinned R580 pattern")
    return {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-bounded-window-v1",
        "qualification": "read-only-static-instruction-window",
        "status": "observed",
        "host": {"name": EXPECTED_HOST, "kernel_release": EXPECTED_HOST_KERNEL,
                 "nvidia_module_version": "595.99.02",
                 "pci_ownership": {"0000:02:00.0": "nvidia", "0000:81:00.0": "vfio-pci"}},
        "guest": {"name": EXPECTED_GUEST, "kernel_release": EXPECTED_GUEST_KERNEL,
                  "gpu": gpu, "libcuda": library},
        "address_mapping": {"ghidra_image_base": hex(GHIDRA_IMAGE_BASE),
                             "elf_load_base": hex(elf_base),
                             "mapping_basis": "RVA is added to the minimum PT_LOAD p_vaddr; the Ghidra analysis base is separately pinned",
                             "windows": [{"rva_start": item["start_rva"],
                                          "rva_stop_exclusive": item["stop_rva_exclusive"],
                                          "va_start": hex(elf_base + int(item["start_rva"], 16)),
                                          "va_stop_exclusive": hex(elf_base + int(item["stop_rva_exclusive"], 16))}
                                         for item in windows]},
        "objdump_version": objdump_version,
        "instructions": instructions,
        "runtime_caller_trace": {
            "path": GPU_NAME_CALLER_TRACE_PATH,
            "sha256": GPU_NAME_CALLER_TRACE_SHA256,
            "return_site_windows": caller_return_site_windows,
            "static_predecessor_summary": {
                "return_sites_with_decoded_instruction": sum(
                    item["instruction_at_return"] is not None
                    for item in caller_return_site_windows),
                "return_sites_preceded_by_call": sum(
                    item["previous_instruction_is_call"]
                    for item in caller_return_site_windows),
                "direct_predecessor_calls": sum(
                    item["previous_call_kind"] == "direct"
                    for item in caller_return_site_windows),
                "indirect_predecessor_calls": sum(
                    item["previous_call_kind"] == "indirect"
                    for item in caller_return_site_windows),
                "call_instruction_boundaries_verified": sum(
                    item["previous_instruction_boundary_verified"]
                    for item in caller_return_site_windows),
            },
            "instruction_boundary_scan": {
                "section": ".text",
                "scanned_output_bytes": raw_boundary_scan["scanned_output_bytes"],
                "parsed_line_count": raw_boundary_scan["parsed_line_count"],
                "stopped_after_last_return_rva": raw_boundary_scan["stopped_after_last_return_rva"],
                "completed_to_section_end": raw_boundary_scan["completed_to_section_end"],
                "covers_all_target_rvas": True,
                "raw_instruction_bytes_transmitted": False,
                "interpretation_limit": (
                    "Instruction lengths were parsed from a bounded in-guest objdump stream; "
                    "only addresses, mnemonics and lengths were returned. This corroborates "
                    "byte-boundary adjacency, not runtime execution or API semantics."),
            },
            "rip_relative_dispatch_slots": rip_relative_slot_report,
            "interpretation_limit": (
                "These static instruction windows are keyed to RVAs observed in the stock "
                "R580 runtime trace; they do not establish API semantics or prove that every "
                "instruction was executed in that trace."),
        },
        "precall_instructions": windows[4]["instructions"],
        "parent_call_instructions": parent_call_instructions,
        "parent_call_edge": parent_call_edge,
        "parent_call_arguments": parent_call_arguments,
        "parent_feature_bit_consumer": parent_bit_consumer,
        "feature_query_ioctl_dataflow": feature_query_dataflow,
        "feature_dispatch_followup_instructions": windows[6]["instructions"],
        "general_command_target_instructions": windows[7]["instructions"],
        "nonzero_helper_path_instructions": windows[8]["instructions"],
        "feature_flag_parent_call_instructions": windows[9]["instructions"],
        "parent_call_rcx_argument_candidates": parent_argument_candidates,
        "handoff_instructions": follow_instructions,
        "zero_status_path_instructions": success_instructions,
        "ioctl_wrapper_instructions": windows[3]["instructions"],
        "caller_register_scan": register_scan,
        "r10_register_flow": r10_flow,
        "r12_register_flow": r12_flow,
        "filtered_control_flow": filtered_control_flow,
        "ioctl_frame_layout": frame_layout,
        "control_flow": control_flow,
        "call_edge": summary,
        "ioctl_wrapper": ioctl_summary,
        "static_reference": {
            "call_rva": hex(CALL_RVA), "return_rva": hex(RETURN_RVA),
            "callee_rva": hex(CALLEE_RVA),
            "correlation_report_sha256": "3e1d39b64cc64742ec3fcafac57fbf7fe7f6efa915d6f3a2d6ef2fb0ed4990c8",
        },
        "limitations": [
            "This is a static, bounded instruction window from the hash-pinned R580 libcuda.",
            "No raw instruction bytes, binary, pseudocode, or symbol annotations are retained.",
            "The command-specific filtered branch/frame match is not a complete CFG or a formal reaching-definition proof; callback-table contents and the generic-path sentinel value remain unknown.",
            "The parent caller's rcx argument remains a static call-site candidate; the separate runtime return-address correlation supports execution of the same call path during cuInit, but does not expose runtime argument values.",
            "The status/output-bit pattern and NVOS54 frame match do not establish broader API behavior, a hybrid-driver path, or shared device/context semantics.",
            "No kernel, driver module, VM state, PCI binding, or GPU state was changed by this inspection.",
        ],
    }


def write_private_exclusive(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.evidence.exists():
        parser.error("evidence output already exists")
    try:
        remote = collect_remote_window()
        report = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                  "transport": {"target": "pc3@pc3", "guest_host_key_fingerprint_verified": True,
                                "credential_value_logged": False, "credential_value_persisted": False},
                  **validate_remote_payload(remote)}
        write_private_exclusive(args.evidence, report)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "qualification": report["qualification"],
                      "evidence": str(args.evidence)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
