#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correlate one Ghidra RET instruction with exact objtool warning evidence.

The sanitized receipt contains identities and instruction facts only. It never
copies Ghidra pseudocode, full disassembly, or local paths from its inputs.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


WARNING = re.compile(
    r"^(?P<unit>.+?): warning: objtool: (?P<symbol>.+?)\+0x"
    r"(?P<offset>[0-9a-fA-F]+): 'naked' return found in MITIGATION_RETHUNK build$"
)
ASSEMBLY = re.compile(r"^(0x[0-9a-fA-F]+):\s+([A-Z][A-Z0-9_]*)(?:\s+(.*))?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AuditError(ValueError):
    """Raised when the supplied evidence cannot be correlated safely."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"{label} is unreadable or invalid JSON") from error
    if not isinstance(value, dict):
        raise AuditError(f"{label} must contain a JSON object")
    return value


def _warning_rows(log_path: Path) -> list[dict[str, str]]:
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise AuditError("objtool log is unreadable") from error
    return [match.groupdict() for line in lines if (match := WARNING.fullmatch(line))]


def _symbol_definition_count(object_path: Path, symbol: str, nm_command: str) -> int:
    result = subprocess.run(
        [nm_command, "-A", "--defined-only", str(object_path)],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise AuditError("opaque-object symbol-table extraction failed")
    return sum(1 for line in result.stdout.splitlines()
               if len(line.split()) >= 3 and line.split()[-1] == symbol)


def summarize(log_path: Path, object_path: Path, rea_path: Path,
              provenance_path: Path, *, nm_command: str = "nm") -> dict:
    log_path = log_path.resolve(strict=True)
    object_path = object_path.resolve(strict=True)
    rea_path = rea_path.resolve(strict=True)
    provenance_path = provenance_path.resolve(strict=True)
    log_sha256 = _sha256(log_path)
    object_sha256 = _sha256(object_path)
    provenance_sha256 = _sha256(provenance_path)

    rea = _read_json(rea_path, "REA function evidence")
    provenance = _read_json(provenance_path, "warning provenance report")
    subject = rea.get("subject", {})
    provider = rea.get("provider", {})
    profile = rea.get("analysis_profile", {})
    profile_parameters = profile.get("parameters", {})
    result = rea.get("normalized_result", {})
    procedure = result.get("procedure", {}) if isinstance(result, dict) else {}
    body = procedure.get("body", {}) if isinstance(procedure, dict) else {}

    if rea.get("operation") != "analyze_function":
        raise AuditError("REA evidence is not an analyze_function result")
    if provider.get("id") != "ghidra" or not provider.get("version"):
        raise AuditError("REA evidence does not identify a versioned Ghidra provider")
    if subject.get("format") != "elf" or subject.get("architecture") != "x86_64":
        raise AuditError("REA evidence target must be an ELF x86_64 object")
    if subject.get("name") != object_path.name:
        raise AuditError("REA evidence does not name the supplied opaque object")
    if Path(subject.get("local_path", "")).resolve(strict=True) != object_path:
        raise AuditError("REA evidence target path does not match the supplied object")
    if subject.get("digest", {}).get("sha256") != object_sha256:
        raise AuditError("REA evidence target digest does not match the supplied object")
    if profile_parameters.get("import_mode") != "ephemeral-source-immutable":
        raise AuditError("REA evidence does not declare immutable-source import")
    if not isinstance(procedure, dict) or not isinstance(body, dict) \
            or body.get("available") is not True:
        raise AuditError("REA evidence lacks a function body")
    if not SHA256.fullmatch(str(profile.get("digest", ""))):
        raise AuditError("REA analysis profile digest is invalid")

    symbol = procedure.get("name")
    entry_text = procedure.get("address")
    if not isinstance(symbol, str) or not symbol or not isinstance(entry_text, str):
        raise AuditError("REA evidence lacks an exact function symbol and entry address")
    try:
        entry = int(entry_text, 16)
    except ValueError as error:
        raise AuditError("REA function entry address is invalid") from error
    ranges = body.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        raise AuditError("REA function body lacks address ranges")
    try:
        parsed_ranges = [(int(item["start"], 16), int(item["end"], 16))
                         for item in ranges]
    except (KeyError, TypeError, ValueError) as error:
        raise AuditError("REA function body address ranges are invalid") from error
    if not any(start <= entry <= end for start, end in parsed_ranges):
        raise AuditError("REA function body ranges do not contain its entry")

    instruction_rows = []
    for line in result.get("assembly", []):
        match = ASSEMBLY.fullmatch(line) if isinstance(line, str) else None
        if not match:
            raise AuditError("REA assembly contains an unsupported instruction row")
        address = int(match.group(1), 16)
        if address < entry:
            raise AuditError("REA instruction precedes its function entry")
        if not any(start <= address <= end for start, end in parsed_ranges):
            raise AuditError("REA instruction falls outside the recorded function body")
        instruction_rows.append({
            "offset": address - entry,
            "mnemonic": match.group(2),
            "operands": match.group(3) or "",
        })
    if not instruction_rows:
        raise AuditError("REA evidence contains no assembly observations")

    rows = _warning_rows(log_path)
    if not rows:
        raise AuditError("objtool log contains no exact RETHUNK warnings")
    matching_rows = [row for row in rows if row["symbol"] == symbol]
    if not matching_rows:
        raise AuditError("selected Ghidra function has no matching objtool warning")
    warning_offsets = Counter(int(row["offset"], 16) for row in matching_rows)
    ret_rows = [row for row in instruction_rows if row["mnemonic"] == "RET"]
    matches = [(ret, warning_offsets[ret["offset"]]) for ret in ret_rows
               if warning_offsets[ret["offset"]] > 0]
    if not matches:
        raise AuditError("Ghidra RET address does not match a warning offset for this symbol")
    if len(matches) != 1:
        raise AuditError("selected function has multiple RET instructions matching warnings")
    ret, matching_warning_count = matches[0]

    if provenance.get("schema") != "nvidia-hybrid.rethunk-warning-provenance.v1":
        raise AuditError("warning provenance report has an unsupported schema")
    provenance_inputs = provenance.get("inputs", {})
    if provenance_inputs.get("objtool_log_sha256") != log_sha256:
        raise AuditError("provenance report does not identify the supplied objtool log")
    if provenance_inputs.get("opaque_object_sha256") != object_sha256:
        raise AuditError("provenance report does not identify the supplied opaque object")
    classification = provenance.get("classification", {})
    if classification.get("warning_rows") != len(rows):
        raise AuditError("provenance report warning count does not match the supplied log")
    if classification.get("opaque_only_rows", 0) + classification.get("source_only_rows", 0) \
            + classification.get("opaque_and_source_rows", 0) \
            + classification.get("unmatched_rows", 0) != len(rows):
        raise AuditError("provenance classification does not cover all warning rows")
    if classification.get("match_basis") != "defined-symbol-name-only":
        raise AuditError("provenance report uses an unsupported match basis")
    if provenance.get("status") != "ANALYZED_STATICALLY" \
            or classification.get("opaque_only_rows") != len(rows) \
            or classification.get("source_only_rows") != 0 \
            or classification.get("opaque_and_source_rows") != 0 \
            or classification.get("unmatched_rows") != 0:
        raise AuditError("provenance report does not classify every warning as opaque-only")

    definitions = _symbol_definition_count(object_path, symbol, nm_command)
    if definitions == 0:
        raise AuditError("selected warning symbol is not defined in the supplied opaque object")
    warning_units = sorted({Path(row["unit"]).name for row in matching_rows})
    if not warning_units:
        raise AuditError("matching warning rows lack an object-unit identity")

    return {
        "schema": "nvidia-hybrid.rethunk-ghidra-sample.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "ANALYZED_STATICALLY",
        "inputs": {
            "objtool_log_sha256": log_sha256,
            "opaque_object_sha256": object_sha256,
            "warning_provenance_report_sha256": provenance_sha256,
            "opaque_object_size_bytes": object_path.stat().st_size,
        },
        "analysis": {
            "rea_version": "rea-agents@6.8.0",
            "ghidra_version": provider["version"],
            "analysis_profile_sha256": profile.get("digest"),
            "function_symbol": symbol,
            "opaque_object_symbol_definitions": definitions,
            "objtool_output_units": warning_units,
            "objtool_warning_rows_for_symbol": len(matching_rows),
            "objtool_warning_offsets_for_symbol": {
                f"0x{offset:x}": count for offset, count in sorted(warning_offsets.items())
            },
            "ghidra_entry_address": entry_text.lower(),
            "ghidra_body_size_bytes": body.get("total_bytes"),
            "ghidra_instructions": [
                {"offset": f"0x{row['offset']:x}",
                 "mnemonic": row["mnemonic"],
                 "operands": row["operands"]}
                for row in instruction_rows
            ],
            "ghidra_ret_instruction_offset": f"0x{ret['offset']:x}",
            "warning_rows_at_ghidra_ret_offset": matching_warning_count,
            "provenance_classification": classification,
        },
        "interpretation": (
            "Ghidra observes a RET in the supplied opaque ELF at an offset reported "
            "by objtool for the same symbol in the linked module object."
        ),
        "limits": [
            "Symbol-name and relative-offset correlation does not identify each linked duplicate body.",
            "One selected function instance does not prove every duplicate instance is byte-identical.",
            "The source-provenance aggregate is symbol-name-based and is not section-level linker provenance.",
            "Pseudocode is not retained; no source is reconstructed or claimed.",
            "Static analysis establishes neither exploitability nor kernel/module safety; no module was loaded.",
        ],
    }


def write_receipt(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise AuditError("refusing to overwrite an existing receipt") from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--opaque-object", type=Path, required=True)
    parser.add_argument("--rea-evidence", type=Path, required=True)
    parser.add_argument("--provenance-report", type=Path, required=True)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        document = summarize(args.log, args.opaque_object, args.rea_evidence,
                             args.provenance_report, nm_command=args.nm)
        if args.output:
            write_receipt(args.output, document)
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (AuditError, OSError, subprocess.SubprocessError) as error:
        print(f"Ghidra RETHUNK sample audit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
