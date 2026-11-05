#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit pinned R580 lookup edges and optional V100 callsite evidence.

The static-only mode maps all five direct edges and their argument setup. The
combined mode also evaluates a separately pinned callsite capture. Neither
mode proves the loaded module embeds this exact relocatable RM object.
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


EXPECTED_OBJECT_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
EXPECTED_CALLSITE_REPORT_SHA256 = "431005c103640170fc48fb9c7ffc38a76377a881cf1f7ddc7b339ec45d847b36"
EXPECTED_MODULE_IDENTITY_SHA256 = "96d40d456fd62fe4f025b204c5c1521d85dc1a45e64066902758edf3cb262013"
BASE = Path(__file__).resolve().parents[1]
DEFAULT_OBJECT = BASE / (
    "build/experiments/proprietary580-wrapper-baseline-v1/"
    "nvidia-580.178.04/nvidia/nv-kernel.o_binary"
)
DEFAULT_CALLSITE_REPORT = BASE / "evidence/pc3-r580-callsite-active-v1-20261022.json"
DEFAULT_MODULE_IDENTITY_REPORT = BASE / "evidence/pc3-v100-loaded-module-identity-v2-20261022.json"
DEFAULT_REPORT = BASE / "evidence/rea-r580-lookup-branch-canary-v3-20261022.json"
DEFAULT_LOG = BASE / "evidence/logs/rea-r580-lookup-branch-canary-v3-20261022.log"

FUNCTION_BASE = 0x3C100
LOOKUP_JOIN_PREDECESSORS = (
    (0x31F, 0x31D, "xor", "edx,edx"),
    (0x9C3, 0x9C1, "xor", "edx,edx"),
    (0xA97, 0xA94, "mov", "dword ptr [rbp+0x8],eax"),
    (0xAAD, 0xAAA, "mov", "dword ptr [rbp+0x8],eax"),
    (0xDAD, 0xDAA, "mov", "dword ptr [rbp+0x8],eax"),
)
_INSTRUCTION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)([a-z][a-z0-9]*)\s*(.*?)\s*$"
)
_RELOCATION = re.compile(
    r"^\s*([0-9a-fA-F]+):\s*(R_X86_64_[A-Z0-9_]+)\s+"
    r"([A-Za-z0-9_.$]+?)(?:([+-])0x([0-9a-fA-F]+))?\s*$"
)
_OBSERVATION = re.compile(
    r"([0-9a-fA-F]{16}) (unavailable|[0-9a-fA-F]{8} [0-9a-fA-F]{8} [0-9a-fA-F]{8})"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_instructions(text: str) -> tuple[dict[int, tuple[str, str]], list[tuple[int, str, str, int]]]:
    instructions: dict[int, tuple[str, str]] = {}
    relocations: list[tuple[int, str, str, int]] = []
    for line in text.splitlines():
        match = _INSTRUCTION.match(line)
        if match:
            address = int(match.group(1), 16)
            if address in instructions:
                raise ValueError(f"duplicate disassembly address {address:#x}")
            instructions[address] = (match.group(3).lower(), " ".join(match.group(4).split()).lower())
            continue
        relocation = _RELOCATION.match(line)
        if relocation:
            sign, magnitude = relocation.group(4), relocation.group(5)
            addend = int(magnitude, 16) if magnitude else 0
            if sign == "-":
                addend = -addend
            relocations.append((int(relocation.group(1), 16), relocation.group(2),
                                relocation.group(3), addend))
    return instructions, relocations


def _expect_instruction(
    instructions: dict[int, tuple[str, str]], offset: int, mnemonic: str, operands_prefix: str
) -> None:
    address = FUNCTION_BASE + offset
    actual = instructions.get(address)
    if actual is None or actual[0] != mnemonic or not actual[1].startswith(operands_prefix.lower()):
        raise ValueError(
            f"unexpected instruction at function+{offset:#x}: {actual!r}; "
            f"expected {mnemonic} {operands_prefix}"
        )


def validate_lookup_branch_disassembly(text: str) -> dict[str, object]:
    """Verify a helper-return value can flow to arg0 while one branch zeros arg1."""
    instructions, relocations = _parse_instructions(text)
    anchors = (
        (0xA0A, "call", "3cb0f"),
        (0xA1A, "mov", "r14d,eax"),
        (0xA75, "mov", "eax,r14d"),
        (0xA78, "shr", "eax,0x18"),
        (0xA7B, "and", "eax,0x3f"),
        (0xA7E, "cmp", "eax,0x15"),
        (0xA81, "jbe", "3ce7e"),
        (0xD90, "xor", "r15d,r15d"),
        (0xDAD, "jmp", "3c18c"),
        (0x08C, "mov", "esi,r15d"),
        (0x08F, "mov", "edi,r14d"),
        (0x092, "call", "3c197"),
    )
    for offset, mnemonic, operands in anchors:
        _expect_instruction(instructions, offset, mnemonic, operands)

    # Pin the local branch gates and register definitions for every direct
    # edge into the common lookup call. These are candidate static paths; the
    # report deliberately does not assign semantic names to private fields.
    route_anchors = (
        (0x2E0, "cmp", "byte ptr [rbx+0x60],0x0"),
        (0x2E4, "je", "3cad0"),
        (0x2EA, "mov", "r15d,dword ptr [rbx+0xf70]"),
        (0x2F1, "cmp", "byte ptr [rbx+0xf78],0x0"),
        (0x2FC, "je", "3cc17"),
        (0x30E, "xor", "r14d,r14d"),
        (0x316, "mov", "dword ptr [rbp+0x8],0x3"),
        (0x9A0, "cmp", "byte ptr [rbx+0xf78],0x0"),
        (0x9A7, "mov", "r15d,dword ptr [rbx+0x12c8]"),
        (0x9B1, "jne", "3c402"),
        (0x9B7, "mov", "dword ptr [rbp+0x8],0x3"),
        (0x9BE, "xor", "r14d,r14d"),
        (0xA65, "xor", "edx,edx"),
        (0xA67, "test", "esi,esi"),
        (0xA69, "setne", "dl"),
        (0xA6C, "cmp", "byte ptr [rbx+0xf78],0x0"),
        (0xA73, "je", "3cb9c"),
        (0xA87, "movzx", "ecx,cl"),
        (0xA8A, "mov", "eax,0x2"),
        (0xA8F, "xor", "r15d,r15d"),
        (0xA92, "sub", "eax,ecx"),
        (0xA9C, "xor", "r15d,r15d"),
        (0xA9F, "cmp", "cl,0x1"),
        (0xAA2, "sbb", "eax,eax"),
        (0xAA4, "and", "eax,0x2"),
        (0xAA7, "add", "eax,0x1"),
        (0xD80, "mov", "esi,0x56b0000"),
        (0xD85, "mov", "edi,0xe3bb2f1"),
        (0xD8A, "mov", "dword ptr [rbp+0x10],edx"),
        (0xD8D, "mov", "byte ptr [rbp+0x8],cl"),
        (0xD9C, "mov", "edx,dword ptr [rbp+0x10]"),
        (0xD9F, "cmp", "cl,0x1"),
        (0xDA2, "sbb", "eax,eax"),
        (0xDA4, "and", "eax,0x2"),
        (0xDA7, "add", "eax,0x1"),
        (0x08C, "mov", "esi,r15d"),
        (0x08F, "mov", "edi,r14d"),
    )
    for offset, mnemonic, operands in route_anchors:
        _expect_instruction(instructions, offset, mnemonic, operands)

    branch_helper_relocations = [
        item for item in relocations if item[0] == FUNCTION_BASE + 0xD94
    ]
    if branch_helper_relocations != [
        (FUNCTION_BASE + 0xD94, "R_X86_64_PC32", "_nv047869rm", -4)
    ]:
        raise ValueError("dispatch-branch helper relocation does not match the pinned route")

    helper_relocations = [item for item in relocations if item[0] == FUNCTION_BASE + 0xA0B]
    if helper_relocations != [(FUNCTION_BASE + 0xA0B, "R_X86_64_PC32", "_nv049612rm", -4)]:
        raise ValueError("helper-return call relocation does not match the pinned _nv049612rm route")
    lookup_relocations = [item for item in relocations if item[0] == FUNCTION_BASE + 0x093]
    if lookup_relocations != [(FUNCTION_BASE + 0x093, "R_X86_64_PC32", "_nv031399rm", -4)]:
        raise ValueError("final call relocation does not target _nv031399rm")

    branch_references = []
    for address, (mnemonic, operands) in instructions.items():
        if mnemonic.startswith("j"):
            target = re.match(r"([0-9a-f]+)\b", operands)
            if target and int(target.group(1), 16) == FUNCTION_BASE + 0xD7E:
                branch_references.append((address, mnemonic))
    if branch_references != [(FUNCTION_BASE + 0xA81, "jbe")]:
        raise ValueError("branch target is not uniquely reached by the pinned jbe")

    lookup_join_edges = [
        address - FUNCTION_BASE
        for address, (mnemonic, operands) in sorted(instructions.items())
        if mnemonic == "jmp" and re.match(r"3c18c\b", operands)
    ]
    expected_jump_offsets = [entry[0] for entry in LOOKUP_JOIN_PREDECESSORS]
    if lookup_join_edges != expected_jump_offsets:
        raise ValueError(
            "lookup-join predecessor edges do not match the pinned R580 route"
        )
    lookup_join_predecessors = []
    for jump_offset, probe_offset, mnemonic, operands_prefix in LOOKUP_JOIN_PREDECESSORS:
        _expect_instruction(instructions, jump_offset, "jmp", "3c18c")
        _expect_instruction(instructions, probe_offset, mnemonic, operands_prefix)
        if mnemonic.startswith("j") or mnemonic in ("call", "ret"):
            raise ValueError("lookup-join probe instruction is not a safe fixed site")
        lookup_join_predecessors.append({
            "jump_offset": jump_offset,
            "probe_offset": probe_offset,
            "probe_instruction": mnemonic,
        })

    lookup_join_routes = [
        {
            "join_offset": 0x31F,
            "conditions": ["rbx+0x60!=0", "rbx+0xf78!=0"],
            "edi_source": "zeroed_r14d",
            "esi_source": "rbx+0xf70",
            "edx_source": "zero",
            "frame_local_source": "constant_3",
        },
        {
            "join_offset": 0x9C3,
            "conditions": ["rbx+0xf78==0"],
            "edi_source": "zeroed_r14d",
            "esi_source": "rbx+0x12c8",
            "edx_source": "zero",
            "frame_local_source": "constant_3",
        },
        {
            "join_offset": 0xA97,
            "conditions": ["rbx+0xf78!=0", "((r14d>>24)&0x3f)>0x15"],
            "edi_source": "helper_return_in_r14d",
            "esi_source": "zeroed_r15d",
            "edx_source": "boolean_of_preceding_esi_nonzero",
            "frame_local_source": "2-zero_extend8_cl",
        },
        {
            "join_offset": 0xAAD,
            "conditions": ["rbx+0xf78==0"],
            "edi_source": "helper_return_in_r14d",
            "esi_source": "zeroed_r15d",
            "edx_source": "boolean_of_preceding_esi_nonzero",
            "frame_local_source": "3_if_cl_zero_else_1",
        },
        {
            "join_offset": 0xDAD,
            "conditions": ["rbx+0xf78!=0", "((r14d>>24)&0x3f)<=0x15"],
            "edi_source": "helper_return_in_r14d",
            "esi_source": "zeroed_r15d",
            "edx_source": "saved_and_restored_prebranch_edx",
            "frame_local_source": "3_if_cl_zero_else_1",
        },
    ]

    # The target block's only R15D write is the zeroing operation, and its
    # direct jump reaches the argument setup before the lookup call.
    path_instructions = [
        (address, mnemonic, operands)
        for address, (mnemonic, operands) in instructions.items()
        if FUNCTION_BASE + 0xD7E <= address <= FUNCTION_BASE + 0xDAD
    ]
    r15_writes = [
        item for item in path_instructions
        if re.search(r"\br15d\s*,", item[2])
    ]
    if r15_writes != [(FUNCTION_BASE + 0xD90, "xor", "r15d,r15d")]:
        raise ValueError("candidate branch does not uniquely clear the second argument")

    return {
        "helper_call_offset": 0xA0A,
        "argument_zero_definition_offset": 0xA1A,
        "dispatch_branch_offset": 0xA75,
        "dispatch_branch_target_offset": 0xD7E,
        "zero_selector_offset": 0xD90,
        "lookup_call_offset": 0x92,
        "lookup_join_target_offset": 0x8C,
        "lookup_join_predecessors": lookup_join_predecessors,
        "lookup_join_routes": lookup_join_routes,
        "helper_return_flows_to_first_lookup_argument": True,
        "branch_clears_second_lookup_argument": True,
        "branch_target_unique_in_function": True,
    }


def build_static_join_report(object_sha256: str,
                             static_route: dict[str, object]) -> dict[str, object]:
    """Build a report whose claims are limited to the pinned object disassembly."""
    if object_sha256 != EXPECTED_OBJECT_SHA256:
        raise ValueError("static route report requires the pinned R580 RM object")
    routes = static_route.get("lookup_join_routes")
    expected_offsets = [entry[0] for entry in LOOKUP_JOIN_PREDECESSORS]
    if (not isinstance(routes, list) or
            any(not isinstance(route, dict) for route in routes) or
            [route.get("join_offset") for route in routes] != expected_offsets):
        raise ValueError("static route report requires all five validated join paths")
    return {
        "schema": "rea-r580-lookup-join-inputs-v1",
        "status": "static_join_routes_mapped",
        "qualification": "analyzed_statically",
        "inputs": {
            "rm_object_sha256": object_sha256,
            "runtime_capture_used": False,
            "loaded_module_identity_checked": False,
        },
        "static_route": static_route,
        "interpretation": (
            "The exact pinned R580 object contains five statically mapped direct "
            "edges into the common _nv031399rm call. The listed path gates and "
            "argument-register sources are disassembly-derived; private field "
            "semantics remain unknown. This report does not establish that any "
            "edge ran on hardware, identify a live call's predecessor, link the "
            "object byte-for-byte to a loaded module, or validate CUDA behavior."
        ),
    }


def classify_callsite_arguments(arg0: int, arg1: int, arg2: int) -> dict[str, object]:
    """Return only predicates needed to assess the candidate branch."""
    high_six = (arg0 >> 24) & 0x3F
    within_limit = high_six <= 0x15
    arg0_nonzero = arg0 != 0
    arg1_zero = arg1 == 0
    arg2_zero = arg2 == 0
    return {
        "first_argument_nonzero": arg0_nonzero,
        "second_argument_zero": arg1_zero,
        "third_argument_zero": arg2_zero,
        "high_six_bits_within_dispatch_limit": within_limit,
        "compatible_with_candidate_branch": (
            arg0_nonzero and arg1_zero and arg2_zero and within_limit
        ),
        "raw_tuple_recorded": False,
    }


def classify_capture_report(report: dict[str, object]) -> dict[str, object]:
    """Validate one paired private callsite/lookup capture and omit its scalars."""
    remote = report.get("remote")
    if (not isinstance(remote, dict) or
            remote.get("schema") != "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v7"):
        raise ValueError("unexpected remote callsite report schema")
    if report.get("status") != "active_lookup_callsite_capture_passed":
        raise ValueError("callsite capture report is not a passing active v7 run")
    if remote.get("status") != "active_lookup_callsite_capture_passed":
        raise ValueError("remote callsite capture status is not passing")
    active = remote.get("active_registration") if isinstance(remote, dict) else None
    if not isinstance(active, dict) or active.get("passed") is not True:
        raise ValueError("active callsite registration did not pass")
    if active.get("lookup_callsite_capture_passed") is not True:
        raise ValueError("callsite-to-lookup paired capture did not pass")
    if active.get("lookup_hits_delta") != 1:
        raise ValueError("expected exactly one lookup entry in the capture window")
    if active.get("lookup_callsite_dropped_before") != 0 or active.get(
        "lookup_callsite_dropped_after_trigger"
    ) != 0:
        raise ValueError("callsite capture reported dropped samples")

    before = active.get("lookup_callsite_observation_before")
    after = active.get("lookup_callsite_observation_after_trigger")
    if not isinstance(before, str) or not isinstance(after, str):
        raise ValueError("paired callsite observations are missing")
    before_match, after_match = _OBSERVATION.fullmatch(before), _OBSERVATION.fullmatch(after)
    if before_match is None or after_match is None:
        raise ValueError("paired callsite observation format is invalid")
    before_count = int(before_match.group(1), 16)
    after_count = int(after_match.group(1), 16)
    if before_match.group(2) != "unavailable" or after_count - before_count != 1:
        raise ValueError("expected one complete callsite tuple after an empty baseline")
    arguments = tuple(int(part, 16) for part in after_match.group(2).split())
    predicates = classify_callsite_arguments(*arguments)
    return {
        "capture_count_delta": 1,
        "lookup_count_delta": 1,
        "dropped_capture_count": 0,
        **predicates,
    }


def _read_pinned_json(path: Path, expected_sha256: str, label: str) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"{label} not found: {path}")
    digest = sha256_file(path)
    if digest != expected_sha256:
        raise ValueError(f"{label} SHA-256 mismatch")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return data


def _write_private_exclusive(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def run_static_join_audit(object_path: Path, report_path: Path,
                          log_path: Path) -> dict[str, object]:
    """Reproducibly audit the five static join paths without runtime inputs."""
    object_path = object_path.resolve()
    if not object_path.is_file() or sha256_file(object_path) != EXPECTED_OBJECT_SHA256:
        raise ValueError("input is not the pinned R580 nv-kernel.o_binary")
    objdump = shutil.which("objdump")
    if not objdump:
        raise RuntimeError("objdump is unavailable")
    command = [objdump, "-dr", "-M", "intel", "--disassemble=_nv031364rm", str(object_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(f"objdump failed with status {result.returncode}")
    _write_private_exclusive(log_path, result.stdout + result.stderr)
    static_route = validate_lookup_branch_disassembly(result.stdout)
    report = build_static_join_report(EXPECTED_OBJECT_SHA256, static_route)
    report["generated_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report["tool"] = {
        "path": objdump,
        "arguments": command[1:-1],
        "auditor_sha256": sha256_file(Path(__file__).resolve()),
        "log_path": str(log_path),
        "log_sha256": sha256_file(log_path),
    }
    _write_private_exclusive(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def run(object_path: Path, callsite_path: Path, identity_path: Path,
        report_path: Path, log_path: Path) -> dict[str, object]:
    object_path = object_path.resolve()
    if not object_path.is_file() or sha256_file(object_path) != EXPECTED_OBJECT_SHA256:
        raise ValueError("input is not the pinned R580 nv-kernel.o_binary")
    callsite_report = _read_pinned_json(
        callsite_path, EXPECTED_CALLSITE_REPORT_SHA256, "callsite report"
    )
    identity_report = _read_pinned_json(
        identity_path, EXPECTED_MODULE_IDENTITY_SHA256, "loaded-module identity report"
    )
    guest = identity_report.get("remote", {}).get("guest", {})
    if (identity_report.get("status") != "observed" or
            guest.get("build_id_match") is not True or
            guest.get("gpu", {}).get("name") != "Tesla V100-SXM2-16GB" or
            guest.get("gpu", {}).get("driver_version") != "580.178.04"):
        raise ValueError("loaded-module report does not identify the pinned V100/R580 build")

    objdump = shutil.which("objdump")
    if not objdump:
        raise RuntimeError("objdump is unavailable")
    command = [objdump, "-dr", "-M", "intel", "--disassemble=_nv031364rm", str(object_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(f"objdump failed with status {result.returncode}")
    _write_private_exclusive(log_path, result.stdout + result.stderr)
    static_route = validate_lookup_branch_disassembly(result.stdout)
    runtime_predicates = classify_capture_report(callsite_report)

    report: dict[str, object] = {
        "schema": "rea-r580-lookup-branch-canary-v1",
        "status": "static_candidate_path_matches_runtime_arguments"
        if runtime_predicates["compatible_with_candidate_branch"]
        else "static_candidate_path_does_not_match_runtime_arguments",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "inputs": {
            "rm_object_sha256": EXPECTED_OBJECT_SHA256,
            "callsite_report_sha256": EXPECTED_CALLSITE_REPORT_SHA256,
            "loaded_module_identity_report_sha256": EXPECTED_MODULE_IDENTITY_SHA256,
            "loaded_module_build_id_matches_installed_file": True,
            "loaded_embedded_rm_object_identity": "unverified",
        },
        "static_route": static_route,
        "runtime_predicates": runtime_predicates,
        "interpretation": (
            "The pinned object contains one candidate path in which a value returned "
            "by _nv049612rm is forwarded as lookup argument 0; for a bounded value "
            "range, the branch clears argument 1 and reaches _nv031399rm. The private "
            "V100 callsite capture has matching argument predicates and one paired "
            "lookup. This is path compatibility, not proof that the conditional branch "
            "was taken or that the loaded module embeds this exact object. No selector "
            "hardware meaning, cache hit/miss, CUDA behavior, or performance is inferred."
        ),
        "tool": {
            "path": objdump,
            "arguments": command[1:-1],
            "log_path": str(log_path),
            "log_sha256": sha256_file(log_path),
        },
    }
    _write_private_exclusive(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--object", type=Path, default=DEFAULT_OBJECT)
    parser.add_argument("--callsite-report", type=Path, default=DEFAULT_CALLSITE_REPORT)
    parser.add_argument("--module-identity-report", type=Path, default=DEFAULT_MODULE_IDENTITY_REPORT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument(
        "--static-only", action="store_true",
        help="audit only the pinned object and emit a static-only report",
    )
    args = parser.parse_args(argv)
    try:
        if args.static_only:
            report = run_static_join_audit(args.object, args.report, args.log)
        else:
            report = run(args.object, args.callsite_report, args.module_identity_report,
                         args.report, args.log)
    except (FileNotFoundError, OSError, RuntimeError, ValueError,
            subprocess.TimeoutExpired) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 1
    summary = {
        "status": report["status"],
        "branch_target_unique": report["static_route"]["branch_target_unique_in_function"],
        "report": str(args.report),
        "log": str(args.log),
    }
    if args.static_only:
        summary["mapped_join_routes"] = len(report["static_route"]["lookup_join_routes"])
        print(json.dumps(summary, sort_keys=True))
        return 0
    summary["compatible_with_candidate_branch"] = report["runtime_predicates"][
        "compatible_with_candidate_branch"
    ]
    print(json.dumps(summary, sort_keys=True))
    return 0 if report["runtime_predicates"]["compatible_with_candidate_branch"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
