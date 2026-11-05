#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only ELF inventory; global symbols are not treated as kernel exports."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run_readelf(readelf: str, *args: str) -> str:
    completed = subprocess.run([readelf, *args], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "readelf failed")
    return completed.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_header(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*(Class|Data|OS/ABI|Type|Machine|Entry point address):\s*(.*?)\s*$", line)
        if match:
            fields[match.group(1).lower().replace(" ", "_").replace("/", "_")] = match.group(2)
    return fields


def parse_sections(text: str) -> list[dict[str, str]]:
    sections = []
    for line in text.splitlines():
        match = re.match(r"\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)", line)
        if match:
            sections.append({"index": match.group(1), "name": match.group(2),
                             "type": match.group(3)})
    return sections


def parse_symbols(text: str) -> dict[str, list[str]]:
    result = {"global_defined": [], "weak_defined": [], "undefined": []}
    for line in text.splitlines():
        columns = line.strip().split(None, 7)
        if len(columns) != 8 or not columns[0].endswith(":"):
            continue
        bind, index, name = columns[4], columns[6], columns[7]
        if not name or bind not in {"GLOBAL", "WEAK"}:
            continue
        if index == "UND":
            result["undefined"].append(name)
        elif bind == "GLOBAL":
            result["global_defined"].append(name)
        else:
            result["weak_defined"].append(name)
    for names in result.values():
        names.sort()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--readelf", default=shutil.which("readelf") or "readelf")
    parser.add_argument("--output", type=Path,
                        help="write JSON here; stdout remains unused when set")
    args = parser.parse_args()
    path = args.elf.resolve(strict=True)
    if not path.is_file():
        parser.error(f"not a regular file: {path}")

    try:
        header_text = run_readelf(args.readelf, "-hW", str(path))
        section_text = run_readelf(args.readelf, "-SW", str(path))
        symbol_text = run_readelf(args.readelf, "-Ws", str(path))
    except (OSError, RuntimeError) as error:
        print(f"ELF audit failed: {error}", file=sys.stderr)
        return 2

    sections = parse_sections(section_text)
    symbols = parse_symbols(symbol_text)
    ksymtab_sections = sorted(
        section["name"] for section in sections
        if "ksymtab" in section["name"]
    )
    ksymtab_symbols = sorted(
        name for name in symbols["global_defined"] + symbols["weak_defined"]
        if name.startswith("__ksymtab_") or name.startswith("___ksymtab+")
    )
    exported_names = []
    for name in ksymtab_symbols:
        if name.startswith("__ksymtab_"):
            exported_names.append(name[len("__ksymtab_"):])
        elif name.startswith("___ksymtab+"):
            exported_names.append(name[len("___ksymtab+"):])

    report = {
        "schema": "nvidia-hybrid-elf-audit-v1",
        "path": str(path),
        "sha256": sha256(path),
        "header": parse_header(header_text),
        "sections": sections,
        "symbols": symbols,
        "symbol_counts": {key: len(value) for key, value in symbols.items()},
        "linux_module_export_evidence": {
            "ksymtab_sections": ksymtab_sections,
            "ksymtab_symbols": ksymtab_symbols,
            "verified_symbol_names_from_ksymtab_markers": sorted(set(exported_names)),
            "interpretation": (
                "No __ksymtab evidence found; global ELF symbol bindings alone do not prove "
                "Linux kernel exports."
                if not ksymtab_sections and not ksymtab_symbols else
                "Names are derived only from explicit __ksymtab section/symbol markers. "
                "Relocation and final-module linkage context still requires review."
            ),
        },
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.resolve().write_text(encoded)
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
