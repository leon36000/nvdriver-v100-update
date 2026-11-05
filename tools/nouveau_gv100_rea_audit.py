#!/usr/bin/env python3
"""Create a sanitized, static REA/Ghidra receipt for an open-source Nouveau module."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


class AuditError(RuntimeError):
    """Raised when an input does not satisfy the audit contract."""


def module_license_is_gpl(value: str) -> bool:
    return value.strip().upper().startswith("GPL")


def summarize_gv100_firmware(lines: Sequence[str]) -> dict[str, Any]:
    paths = [line.strip() for line in lines if line.strip()]
    gv100_acr = [p for p in paths if p.startswith("nvidia/gv100/acr/")]
    gv100_gsp = [p for p in paths if p.startswith("nvidia/gv100/gsp/")]
    other_gsp = [p for p in paths if "/gsp/" in p and p not in gv100_gsp]
    return {
        "declared_firmware_count": len(paths),
        "gv100_acr_count": len(gv100_acr),
        "gv100_acr_examples": gv100_acr[:8],
        "gv100_gsp_count": len(gv100_gsp),
        "gv100_gsp_examples": gv100_gsp[:8],
        "other_gsp_count": len(other_gsp),
        "other_gsp_examples": other_gsp[:8],
    }


def parse_chipset_relocations(nm_output: str, reloc_output: str) -> list[dict[str, str]]:
    table = None
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3] == "nv140_chipset":
            try:
                table = (int(fields[0], 16), int(fields[1], 16))
            except ValueError as exc:
                raise AuditError("nm returned an invalid nv140_chipset range") from exc
            break
    if table is None:
        raise AuditError("the module has no sized nv140_chipset symbol")

    start, size = table
    end = start + size
    found = []
    for line in reloc_output.splitlines():
        fields = line.split()
        if len(fields) < 3 or not re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            continue
        try:
            address = int(fields[0], 16)
        except ValueError:
            continue
        symbol = fields[2].split("+", 1)[0]
        if start <= address < end and symbol in {"gv100_acr_new", "gv100_gsp_new"}:
            found.append({"offset": hex(address), "symbol": symbol})

    found.sort(key=lambda row: (int(row["offset"], 16), row["symbol"]))
    symbols = {row["symbol"] for row in found}
    missing = {"gv100_acr_new", "gv100_gsp_new"} - symbols
    if missing:
        raise AuditError(
            "nv140_chipset relocations do not include: " + ", ".join(sorted(missing))
        )
    return found


def validate_rea_decompile(
    report: dict[str, Any],
    procedure: str,
    dispatch: str,
    interface_table: str,
) -> str:
    if report.get("operation") != "procedure_pseudo_code":
        raise AuditError(f"REA did not return pseudocode for {procedure}")
    if (report.get("provider") or {}).get("id") != "ghidra":
        raise AuditError(f"REA did not use Ghidra for {procedure}")
    subject_hash = ((report.get("subject") or {}).get("digest") or {}).get("sha256")
    if not isinstance(subject_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", subject_hash):
        raise AuditError(f"REA did not identify the analyzed bytes for {procedure}")
    body = report.get("normalized_result")
    if not isinstance(body, str):
        raise AuditError(f"REA returned no decompiler text for {procedure}")
    expected = re.compile(
        rf"\b{re.escape(procedure)}\s*\([\s\S]*?"
        rf"\b{re.escape(dispatch)}\s*\(\s*(?P<address>&?)\s*"
        rf"{re.escape(interface_table)}\b",
        re.MULTILINE,
    )
    match = expected.search(body)
    if not match:
        raise AuditError(f"REA did not show the expected dispatch in {procedure}")
    return f"{dispatch}({match.group('address')}{interface_table})"


def validate_rea_call(report: dict[str, Any], procedure: str, callee: str) -> str:
    """Keep only a hash-pinned named-call fact from a Ghidra result."""
    if report.get("operation") != "procedure_pseudo_code":
        raise AuditError(f"REA did not return pseudocode for {procedure}")
    if (report.get("provider") or {}).get("id") != "ghidra":
        raise AuditError(f"REA did not use Ghidra for {procedure}")
    subject_hash = ((report.get("subject") or {}).get("digest") or {}).get("sha256")
    if not isinstance(subject_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", subject_hash):
        raise AuditError(f"REA did not identify the analyzed bytes for {procedure}")
    body = report.get("normalized_result")
    if not isinstance(body, str):
        raise AuditError(f"REA returned no decompiler text for {procedure}")
    procedure_body = extract_procedure_body(body, procedure)
    if not re.search(rf"\b{re.escape(callee)}\s*\(", procedure_body):
        raise AuditError(f"REA did not show the expected call in {procedure}")
    return callee


def extract_procedure_body(text: str, procedure: str) -> str:
    """Return one C-like procedure body with comments and literals masked."""
    masked = mask_c_comments_and_literals(text)
    candidate = re.compile(rf"\b{re.escape(procedure)}\s*\(")
    control_words = re.compile(r"\b(?:do|if|for|while|switch|return|case)\b")
    for match in candidate.finditer(masked):
        line_start = masked.rfind("\n", 0, match.start()) + 1
        prefix = masked[line_start:match.start()].strip()
        if any(char in prefix for char in "()=") or control_words.search(prefix):
            continue
        if not prefix:
            previous_end = line_start
            while previous_end and masked[previous_end - 1].isspace():
                previous_end -= 1
            previous_start = masked.rfind("\n", 0, previous_end) + 1
            prefix = masked[previous_start:previous_end].strip()
            if (not prefix or any(char in prefix for char in "()=;{}")
                    or control_words.search(prefix)):
                continue

        open_paren = match.end() - 1
        depth = 0
        close_paren = None
        for index in range(open_paren, len(masked)):
            if masked[index] == "(":
                depth += 1
            elif masked[index] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = index
                    break
        if close_paren is None:
            continue

        # Kernel definitions may place balanced annotations such as
        # __releases(...) and __acquires(...) between the parameter list and
        # the opening brace. Stop at a declaration semicolon instead of
        # accidentally treating its following function as this body.
        body_start = close_paren + 1
        annotation_depth = 0
        while body_start < len(masked):
            char = masked[body_start]
            if char == "(":
                annotation_depth += 1
            elif char == ")":
                annotation_depth -= 1
            elif char == ";" and annotation_depth == 0:
                break
            elif char == "{" and annotation_depth == 0:
                break
            body_start += 1
        if body_start >= len(masked) or masked[body_start] != "{":
            continue

        depth = 0
        for index in range(body_start, len(masked)):
            if masked[index] == "{":
                depth += 1
            elif masked[index] == "}":
                depth -= 1
                if depth == 0:
                    return masked[body_start + 1:index]
    raise AuditError(f"REA did not identify a bounded body for {procedure}")


def mask_c_comments_and_literals(text: str) -> str:
    """Replace comment and string contents with spaces while preserving lines."""
    result = list(text)
    index = 0
    state = "code"
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""

        if state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block_comment":
            if current == "*" and following == "/":
                result[index] = result[index + 1] = " "
                index += 1
                state = "code"
            elif current != "\n":
                result[index] = " "
        elif state in ("string", "character"):
            quote = '"' if state == "string" else "'"
            if current == "\\":
                result[index] = " "
                if index + 1 < len(text):
                    if text[index + 1] != "\n":
                        result[index + 1] = " "
                    index += 1
            elif current == quote:
                result[index] = " "
                state = "code"
            elif current != "\n":
                result[index] = " "
        elif current == "/" and following == "/":
            result[index] = result[index + 1] = " "
            index += 1
            state = "line_comment"
        elif current == "/" and following == "*":
            result[index] = result[index + 1] = " "
            index += 1
            state = "block_comment"
        elif current == '"':
            result[index] = " "
            state = "string"
        elif current == "'":
            result[index] = " "
            state = "character"
        index += 1
    return "".join(result)


def summarize_rea_call(
    report: dict[str, Any], expected_module_sha256: str, procedure: str, callee: str
) -> dict[str, Any]:
    """Retain one named call only after binding it to the exact module bytes."""
    call = validate_rea_call(report, procedure, callee)
    observed_hash = ((report.get("subject") or {}).get("digest") or {}).get("sha256")
    if observed_hash != expected_module_sha256:
        raise AuditError(f"REA analyzed different bytes for {procedure}")
    provider = report["provider"]
    version = provider.get("version")
    if not isinstance(version, str) or not version:
        raise AuditError(f"REA did not identify the Ghidra version for {procedure}")
    return {
        "provider": {"id": "ghidra", "version": version},
        "procedure": procedure,
        "related_calls": [call],
        "pseudocode_retained": False,
    }


def run_command(
    argv: Sequence[str], env: dict[str, str], *, timeout: int = 1200
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(argv), capture_output=True, text=True, env=env, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError(f"could not complete {Path(argv[0]).name}") from exc
    if result.returncode:
        raise AuditError(
            f"{Path(argv[0]).name} failed with exit status {result.returncode}"
        )
    return result


def command_text(argv: Sequence[str], env: dict[str, str]) -> str:
    return run_command(argv, env).stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_json_output(output: str, command: str) -> dict[str, Any]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AuditError(f"{command} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AuditError(f"{command} returned a non-object JSON value")
    return value


def ghidra_version(doctor: dict[str, Any]) -> str:
    for check in doctor.get("scope_checks", []):
        if check.get("name") == "ghidra-version" and check.get("ok"):
            return str(check.get("detail"))
    raise AuditError("REA doctor did not verify the Ghidra version")


def run_audit(
    module: Path,
    rea_bin: Path,
    ghidra_dir: Path,
    java_home: Path,
    node_bin: Path | None = None,
) -> dict[str, Any]:
    module = module.resolve(strict=True)
    rea_bin = rea_bin.resolve(strict=True)
    ghidra_dir = ghidra_dir.resolve(strict=True)
    java_home = java_home.resolve(strict=True)
    if module.name.endswith(".zst"):
        raise AuditError("pass an uncompressed .ko file so hashes match the Ghidra input")
    if not (module.is_file() and rea_bin.is_file()):
        raise AuditError("module and REA paths must be regular files")
    if not (ghidra_dir / "support" / "analyzeHeadless").is_file():
        raise AuditError("Ghidra analyzeHeadless is missing")
    if not (java_home / "bin" / "java").is_file() or not (java_home / "bin" / "javac").is_file():
        raise AuditError("JAVA_HOME must point to a full JDK")

    env = os.environ.copy()
    env["GHIDRA_INSTALL_DIR"] = str(ghidra_dir)
    env["JAVA_HOME"] = str(java_home)
    if node_bin is not None:
        node_bin = node_bin.resolve(strict=True)
        env["PATH"] = str(node_bin) + os.pathsep + env.get("PATH", "")
    if shutil.which("node", path=env.get("PATH")) is None:
        raise AuditError("Node.js must be on PATH for the installed REA CLI")

    license_value = command_text(["modinfo", "-F", "license", str(module)], env)
    if not module_license_is_gpl(license_value):
        raise AuditError("refusing binary analysis without GPL module license metadata")
    vermagic = command_text(["modinfo", "-F", "vermagic", str(module)], env)
    srcversion = command_text(["modinfo", "-F", "srcversion", str(module)], env)
    firmware_lines = command_text(["modinfo", "-F", "firmware", str(module)], env).splitlines()
    firmware = summarize_gv100_firmware(firmware_lines)
    if firmware["gv100_acr_count"] == 0:
        raise AuditError("the module does not declare GV100 ACR firmware")

    nm_output = command_text(["nm", "-S", "--defined-only", str(module)], env)
    reloc_output = command_text(["objdump", "-r", str(module)], env)
    relocations = parse_chipset_relocations(nm_output, reloc_output)

    doctor = parse_json_output(
        command_text([str(rea_bin), "doctor", "--provider", "ghidra", "--json"], env),
        "REA doctor",
    )
    if doctor.get("healthy") is not True:
        raise AuditError("REA doctor did not qualify the Ghidra provider")
    rea_version = command_text([str(rea_bin), "--version"], env).splitlines()[0]
    java_text = run_command([str(java_home / "bin" / "java"), "-version"], env).stderr
    java_match = re.search(r'version\s+"([^"]+)"', java_text)
    if not java_match:
        raise AuditError("could not read the JDK version")

    decompiled = {}
    for procedure, dispatch, table in (
        ("gv100_acr_new", "nvkm_acr_new_", "gv100_acr_fwif"),
        ("gv100_gsp_new", "nvkm_gsp_new_", "gv100_gsps"),
    ):
        report = parse_json_output(
            command_text(
                [
                    str(rea_bin),
                    "decompile",
                    str(module),
                    "--procedure",
                    procedure,
                    "--provider",
                    "ghidra",
                    "--format",
                    "json",
                ],
                env,
            ),
            f"REA decompile {procedure}",
        )
        expected_call = validate_rea_decompile(report, procedure, dispatch, table)
        if report["subject"]["digest"]["sha256"] != sha256_file(module):
            raise AuditError(f"REA analyzed different bytes for {procedure}")
        decompiled[procedure] = {
            "provider": report["provider"],
            "call_summary": expected_call,
            "pseudocode_retained": False,
        }

    procedure = "gv100_gr_oneinit_sm_id"
    report = parse_json_output(
        command_text(
            [
                str(rea_bin), "decompile", str(module), "--procedure", procedure,
                "--provider", "ghidra", "--format", "json",
            ],
            env,
        ),
        f"REA decompile {procedure}",
    )
    related_call = validate_rea_call(report, procedure, "gv100_gr_scg_estimate_perf")
    if report["subject"]["digest"]["sha256"] != sha256_file(module):
        raise AuditError(f"REA analyzed different bytes for {procedure}")
    decompiled_gr_sm_id = {
        "provider": report["provider"],
        "procedure": procedure,
        "related_calls": [related_call],
        "pseudocode_retained": False,
    }

    procedure = "gv100_vmm_new"
    report = parse_json_output(
        command_text(
            [
                str(rea_bin), "decompile", str(module), "--procedure", procedure,
                "--provider", "ghidra", "--format", "json",
            ],
            env,
        ),
        f"REA decompile {procedure}",
    )
    vmm_call = validate_rea_decompile(
        report, procedure, "gp100_vmm_new_", "gv100_vmm"
    )
    if report["subject"]["digest"]["sha256"] != sha256_file(module):
        raise AuditError(f"REA analyzed different bytes for {procedure}")
    decompiled_vmm = {
        "provider": report["provider"],
        "call_summary": vmm_call,
        "pseudocode_retained": False,
    }

    procedure = "gv100_vmm_join"
    report = parse_json_output(
        command_text(
            [
                str(rea_bin), "decompile", str(module), "--procedure", procedure,
                "--provider", "ghidra", "--format", "json",
            ],
            env,
        ),
        f"REA decompile {procedure}",
    )
    vmm_join_call = validate_rea_call(report, procedure, "gp100_vmm_join")
    if report["subject"]["digest"]["sha256"] != sha256_file(module):
        raise AuditError(f"REA analyzed different bytes for {procedure}")
    decompiled_vmm_join = {
        "provider": report["provider"],
        "procedure": procedure,
        "related_calls": [vmm_join_call],
        "pseudocode_retained": False,
    }

    procedure = "gp100_vmm_new_"
    report = parse_json_output(
        command_text(
            [
                str(rea_bin), "decompile", str(module), "--procedure", procedure,
                "--provider", "ghidra", "--format", "json",
            ],
            env,
        ),
        f"REA decompile {procedure}",
    )
    common_vmm_call = validate_rea_call(report, procedure, "nvkm_vmm_new_")
    if report["subject"]["digest"]["sha256"] != sha256_file(module):
        raise AuditError(f"REA analyzed different bytes for {procedure}")
    decompiled_gp100_vmm = {
        "provider": report["provider"],
        "procedure": procedure,
        "related_calls": [common_vmm_call],
        "pseudocode_retained": False,
    }

    procedure = "gv100_fault_buffer_process"
    report = parse_json_output(
        command_text(
            [
                str(rea_bin), "decompile", str(module), "--procedure", procedure,
                "--provider", "ghidra", "--format", "json",
            ],
            env,
        ),
        f"REA decompile {procedure}",
    )
    decompiled_fault_buffer = summarize_rea_call(
        report, sha256_file(module), procedure, "nvkm_fifo_fault"
    )

    return {
        "schema": "nvidia-hybrid.nouveau-gv100-rea-audit.v6",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ANALYZED_STATICALLY",
        "hardware_execution_validated": False,
        "module": {
            "basename": module.name,
            "sha256": sha256_file(module),
            "license_metadata": license_value,
            "license_gate": "GPL-prefixed modinfo value",
            "srcversion": srcversion,
            "vermagic": vermagic,
            "kernel_release": vermagic.split()[0] if vermagic else None,
        },
        "tools": {
            "rea": rea_version,
            "ghidra": ghidra_version(doctor),
            "jdk": java_match.group(1),
        },
        "observations": {
            "gv100_firmware_declarations": firmware,
            "nv140_chipset_relocations": relocations,
            "decompiled_factory_summaries": decompiled,
            "decompiled_gr_sm_id": decompiled_gr_sm_id,
            "decompiled_vmm": decompiled_vmm,
            "decompiled_vmm_join": decompiled_vmm_join,
            "decompiled_gp100_vmm": decompiled_gp100_vmm,
            "decompiled_fault_buffer_worker": decompiled_fault_buffer,
            "xrefs": "not used for ET_REL data-table proof; objdump relocations are recorded",
            "pseudocode_retained": False,
            "module_loaded": False,
            "gpu_accessed": False,
        },
    }


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AuditError(f"refusing to overwrite existing receipt: {path}") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise AuditError("could not write the new audit receipt") from exc


def default_path(root: Path, relative: str) -> Path:
    return root / relative


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True, help="uncompressed GPL Nouveau .ko")
    parser.add_argument("--output", type=Path, required=True, help="new receipt path; existing files are never overwritten")
    parser.add_argument(
        "--rea-bin",
        type=Path,
        default=default_path(root, "build/tools/rea-6.8.0/node_modules/.bin/rea"),
    )
    parser.add_argument(
        "--ghidra-dir",
        type=Path,
        default=default_path(root, "build/tools/ghidra_12.1.4_PUBLIC"),
    )
    parser.add_argument(
        "--java-home",
        type=Path,
        default=default_path(root, "build/tools/jdk21/usr/lib/jvm/java-21-openjdk-amd64"),
    )
    parser.add_argument("--node-bin", type=Path, help="directory containing node when it is not already on PATH")
    args = parser.parse_args(argv)
    try:
        report = run_audit(
            args.module, args.rea_bin, args.ghidra_dir, args.java_home, args.node_bin
        )
        write_new_json(args.output, report)
    except AuditError as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
