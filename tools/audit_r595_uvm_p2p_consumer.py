#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate one hash-pinned REA/Ghidra analysis of the R595 UVM P2P consumer.

The tool records only a compact receipt. Ghidra pseudocode and full objdump
output remain outside the receipt because they are analysis representations,
not original NVIDIA source.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE_SHA256 = "b467e051c4af84011d512859751c20d0ef042e5c24d3281fbfb248173c18f4f2"
UPSTREAM_COMMIT = "d8257d95ae5fed364163e4df51db66df8b1ee0d2"
UPSTREAM_SOURCE_SHA256 = "66881c4ae46461314d41342b2a27df9119d68d68f90d181e3a32670dcc19f590"
EXCERPT_SHA256 = "33913c7fffc5c5307969a1fd15ebdb735259705edc0e4923c3ae9897099a2af2"
PROCEDURE = "get_parent_p2p_caps"
CALLEE = "nvUvmInterfaceGetP2PCaps"


class AuditError(RuntimeError):
    """Raised when a source, report, or compiled artifact misses its contract."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AuditError(f"input must be a regular, non-symlink file: {path.name}")
    return path.read_bytes()


def path_from_root(path: Path) -> str:
    try:
        return path.resolve(strict=True).relative_to(ROOT.resolve()).as_posix()
    except (OSError, ValueError) as exc:
        raise AuditError("receipt inputs must be inside the project root") from exc


def validate_source_excerpt(data: bytes) -> dict[str, str]:
    if sha256_bytes(data) != EXCERPT_SHA256:
        raise AuditError("R595.112.07 UVM consumer excerpt hash mismatch")
    text = data.decode("utf-8")
    required = (
        UPSTREAM_COMMIT,
        UPSTREAM_SOURCE_SHA256,
        "uvm_parent_id_value(parent_gpu0->id) < uvm_parent_id_value(parent_gpu1->id)",
        "memset(p2p_caps_params, 0, sizeof(*p2p_caps_params))",
        "uvm_rm_locked_call(nvUvmInterfaceGetP2PCaps(rm_device0, rm_device1, p2p_caps_params))",
        "link_type == UVM_GPU_LINK_INVALID || link_type == UVM_GPU_LINK_C2C",
    )
    missing = [needle for needle in required if needle not in text]
    if missing:
        raise AuditError("pinned UVM consumer source contract is incomplete")
    return {
        "repository": "NVIDIA/open-gpu-kernel-modules",
        "release": "595.112.07",
        "commit": UPSTREAM_COMMIT,
        "full_source_sha256": UPSTREAM_SOURCE_SHA256,
        "excerpt_sha256": EXCERPT_SHA256,
    }


def validate_rea_report(report: dict[str, Any], module_sha256: str) -> dict[str, Any]:
    if report.get("operation") != "procedure_pseudo_code":
        raise AuditError("REA did not return procedure pseudocode")
    provider = report.get("provider") or {}
    if provider.get("id") != "ghidra" or provider.get("version") != "12.1.4":
        raise AuditError("REA report is not from the pinned Ghidra 12.1.4 provider")
    if (report.get("parameters") or {}).get("procedure") != PROCEDURE:
        raise AuditError(f"REA report does not target {PROCEDURE}")
    observed_hash = (((report.get("subject") or {}).get("digest") or {}).get("sha256"))
    if observed_hash != module_sha256 or module_sha256 != MODULE_SHA256:
        raise AuditError("REA report and pinned module bytes do not match")
    body = report.get("normalized_result")
    if not isinstance(body, str) or not re.search(
        rf"\b{re.escape(PROCEDURE)}\s*\(", body
    ) or not re.search(rf"\b{re.escape(CALLEE)}\s*\(", body):
        raise AuditError("Ghidra output did not identify the expected P2P call")

    return {
        "evidence_id": report.get("evidence_id"),
        "provider": {"id": provider["id"], "version": provider["version"]},
        "procedure": PROCEDURE,
        "named_call": CALLEE,
        "call_signature_reconstructed": False,
        "pseudocode_retained": False,
        "interpretation": (
            "Ghidra identifies the external call but omits its output-pointer argument; "
            "the source declaration and object-code register flow are recorded separately."
        ),
    }


def _instruction(line: str) -> str:
    return line.split("\t")[-1].strip()


def validate_objdump(text: str) -> dict[str, Any]:
    if f"<{PROCEDURE}>:" not in text:
        raise AuditError(f"objdump output does not contain {PROCEDURE}")
    lines = text.splitlines()
    call_indices = [
        index for index, line in enumerate(lines)
        if "R_X86_64_PLT32" in line and re.search(rf"\b{re.escape(CALLEE)}(?:-|\b)", line)
    ]
    if len(call_indices) != 1:
        raise AuditError("expected exactly one relocated P2P-capability call")
    call_index = call_indices[0]
    instruction_lines = [
        (index, _instruction(line)) for index, line in enumerate(lines)
        if re.match(r"\s*[0-9a-fA-F]+:", line)
    ]
    handoff = [
        index for index, instruction in instruction_lines
        if re.search(r"\bmov\s+%rdx,%rdi$", instruction)
    ]
    clear_count = [
        index for index, instruction in instruction_lines
        if re.search(r"\bmov\s+\$0x9,%ecx$", instruction)
    ]
    clear_zero = [
        index for index, instruction in instruction_lines
        if re.search(r"\bxor\s+%eax,%eax$", instruction)
    ]
    clear_loop = [
        index for index, instruction in instruction_lines
        if re.search(r"\brep\s+stos\s+%rax,\(%rdi\)$", instruction)
    ]
    if not (len(handoff) == len(clear_count) == len(clear_zero) == len(clear_loop) == 1):
        raise AuditError("object code does not show the expected output initialization")
    handoff_index = handoff[0]
    clear_count_index = clear_count[0]
    clear_zero_index = clear_zero[0]
    clear_loop_index = clear_loop[0]
    if not (handoff_index < clear_zero_index < clear_loop_index < call_index):
        raise AuditError("output-pointer handoff, zero-fill, and P2P call order changed")
    if not (clear_count_index < clear_loop_index):
        raise AuditError("object code no longer initializes nine qwords")

    handoff_line = instruction_lines[handoff_index][0]
    call_line = call_index
    between = [
        _instruction(line) for line in lines[handoff_line + 1:call_line]
        if re.match(r"\s*[0-9a-fA-F]+:", line)
    ]
    if any(re.search(r"%(?:r|e)?dx\b|%dl\b", instruction) for instruction in between):
        raise AuditError("the incoming output pointer register changes before the P2P call")
    address_match = re.match(r"\s*([0-9a-fA-F]+):", lines[call_index])
    if address_match is None:
        raise AuditError("could not resolve the P2P call instruction address")
    return {
        "call_relocation": CALLEE,
        "call_address": "0x" + address_match.group(1).lower(),
        "output_pointer_register": "rdx",
        "output_pointer_preserved_through_call": True,
        "zero_fill_qwords": 9,
        "zero_fill_bytes": 72,
        "analysis_kind": "static x86_64 disassembly",
    }


def run_command(argv: list[str]) -> str:
    try:
        result = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError(f"could not complete {Path(argv[0]).name}") from exc
    if result.returncode:
        raise AuditError(f"{Path(argv[0]).name} exited with status {result.returncode}")
    return result.stdout.strip()


def modinfo(module: Path, field: str) -> str:
    return run_command(["modinfo", "-F", field, str(module)])


def build_receipt(
    module: Path,
    report_path: Path,
    source_excerpt: Path,
    rea_cli: Path,
) -> dict[str, Any]:
    module_data = read_regular(module)
    module_hash = sha256_bytes(module_data)
    if module_hash != MODULE_SHA256:
        raise AuditError("module hash differs from the pinned R595.112.07 build")
    report_data = read_regular(report_path)
    try:
        report = json.loads(report_data)
    except json.JSONDecodeError as exc:
        raise AuditError("REA report is not valid JSON") from exc
    if not isinstance(report, dict):
        raise AuditError("REA report must be a JSON object")
    excerpt_data = read_regular(source_excerpt)
    source = validate_source_excerpt(excerpt_data)
    ghidra = validate_rea_report(report, module_hash)
    objdump = validate_objdump(
        run_command(["objdump", "-drwC", f"--disassemble={PROCEDURE}", str(module)])
    )
    rea_version = run_command([str(rea_cli), "--version"]).splitlines()[0]
    if rea_version != "6.8.0":
        raise AuditError("expected the pinned REA 6.8.0 CLI")

    license_value = modinfo(module, "license")
    if license_value != "Dual MIT/GPL":
        raise AuditError("module license metadata changed")
    vermagic = modinfo(module, "vermagic")
    srcversion = modinfo(module, "srcversion")
    try:
        relative_report = path_from_root(report_path)
    except AuditError:
        relative_report = None

    return {
        "schema": "nvidia-hybrid.r595-uvm-p2p-consumer-ghidra.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ANALYZED_STATICALLY",
        "hardware_execution_validated": False,
        "module": {
            "path": path_from_root(module),
            "sha256": module_hash,
            "license_metadata": license_value,
            "srcversion": srcversion,
            "vermagic": vermagic,
        },
        "source": source,
        "tools": {
            "rea": rea_version,
            "ghidra": ghidra["provider"]["version"],
        },
        "analysis": {
            "ghidra": ghidra,
            "objdump": objdump,
            "raw_rea_report": {
                "path": relative_report or report_path.name,
                "sha256": sha256_bytes(report_data),
                "bytes": len(report_data),
                "pseudocode_retained_in_receipt": False,
            },
            "source_observations": [
                "The R595 consumer orders the RM handles by ascending UVM parent-GPU ID.",
                "It zeroes the 72-byte P2P-capability output before the RM query.",
                "The three-argument nvUvmInterfaceGetP2PCaps call is made inside uvm_rm_locked_call.",
                "The caller returns the RM status and rejects INVALID or C2C link types during peer initialization.",
            ],
        },
        "limitations": [
            "Ghidra pseudocode is analysis output, not NVIDIA source; its external call signature is incomplete here.",
            "The register-flow finding is static x86_64 object-code evidence, cross-checked against the pinned source signature.",
            "No module insertion, GPU access, RM response, CUDA execution, or P2P transfer occurred.",
            "This does not establish whether PCIe P2P or atomics are supported by any particular topology.",
        ],
    }


def write_new_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--rea-report", type=Path, required=True)
    parser.add_argument("--source-excerpt", type=Path, default=ROOT / (
        "tests/fixtures/upstream/nvidia-r595-uvm-p2p/595.112.07/"
        "uvm_gpu_p2p_consumer_excerpt.c"))
    parser.add_argument("--rea-cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / (
        "evidence/r595112-uvm-p2p-consumer-static-v1-20261102.json"))
    args = parser.parse_args(argv)
    try:
        receipt = build_receipt(
            args.module, args.rea_report, args.source_excerpt, args.rea_cli
        )
        output = args.output.resolve()
        if output != ROOT.resolve() and ROOT.resolve() not in output.parents:
            raise AuditError("receipt output must remain inside the project root")
        write_new_json(output, receipt)
    except (AuditError, OSError, ValueError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "receipt": output.relative_to(ROOT.resolve()).as_posix(),
        "schema": receipt["schema"],
        "status": receipt["status"],
        "module_sha256": receipt["module"]["sha256"],
        "raw_report_sha256": receipt["analysis"]["raw_rea_report"]["sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
