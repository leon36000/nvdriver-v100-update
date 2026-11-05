#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare ELF loadable sections while reporting build-ID/debug-only deltas."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any


ELF_MAGIC = b"\x7fELF"
SHF_ALLOC = 0x2
SHT_NOBITS = 8
BUILD_ID_SECTION = ".note.gnu.build-id"


class ElfFormatError(ValueError):
    """Raised when an ELF file is truncated or malformed for section analysis."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_elf_sections(data: bytes) -> dict[str, dict[str, Any]]:
    """Return section metadata keyed by name, rejecting ambiguous ELF layouts."""
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ElfFormatError("input is not an ELF file")

    elf_class, elf_data, ident_version = data[4], data[5], data[6]
    if elf_class not in (1, 2) or elf_data not in (1, 2) or ident_version != 1:
        raise ElfFormatError("unsupported ELF class, byte order, or identification version")
    endian = "<" if elf_data == 1 else ">"

    if elf_class == 2:
        if len(data) < 64:
            raise ElfFormatError("truncated ELF64 header")
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
        shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
        shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
        section_format = endian + "IIQQQQIIQQ"
    else:
        if len(data) < 52:
            raise ElfFormatError("truncated ELF32 header")
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
        shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
        shstrndx = struct.unpack_from(endian + "H", data, 0x32)[0]
        section_format = endian + "IIIIIIIIII"

    minimum_entry_size = struct.calcsize(section_format)
    if shoff == 0:
        if shnum == 0 and shstrndx == 0:
            return {}
        raise ElfFormatError("section table offset is zero")
    if shentsize < minimum_entry_size or shoff + shentsize > len(data):
        raise ElfFormatError("invalid or truncated section table")

    first = struct.unpack_from(section_format, data, shoff)
    if shnum == 0:
        shnum = first[5]
    if shstrndx == 0xFFFF:
        shstrndx = first[6]
    if shnum <= 0 or shstrndx >= shnum:
        raise ElfFormatError("invalid section count or section-name table index")
    if shoff + shentsize * shnum > len(data):
        raise ElfFormatError("section table extends past end of file")

    raw_sections = [
        struct.unpack_from(section_format, data, shoff + i * shentsize)
        for i in range(shnum)
    ]
    string_section = raw_sections[shstrndx]
    string_offset, string_size = string_section[4], string_section[5]
    if string_offset + string_size > len(data):
        raise ElfFormatError("section-name string table extends past end of file")
    name_table = data[string_offset:string_offset + string_size]

    sections: dict[str, dict[str, Any]] = {}
    for section in raw_sections:
        name_offset, section_type, flags = section[0], section[1], section[2]
        offset, size = section[4], section[5]
        if name_offset >= len(name_table):
            raise ElfFormatError("section name offset is outside the string table")
        name_end = name_table.find(b"\0", name_offset)
        if name_end < 0:
            raise ElfFormatError("unterminated section name")
        name = name_table[name_offset:name_end].decode("utf-8", "replace")
        if not name:
            continue
        if name in sections:
            raise ElfFormatError(f"duplicate section name: {name}")
        if section_type == SHT_NOBITS:
            section_digest = sha256_bytes(b"")
        else:
            if offset + size > len(data):
                raise ElfFormatError(f"section {name} extends past end of file")
            section_digest = sha256_bytes(data[offset:offset + size])
        sections[name] = {
            "flags": flags,
            "size": size,
            "sha256": section_digest,
            "type": section_type,
        }
    return sections


def compare_elf_sections(baseline: bytes, candidate: bytes) -> dict[str, Any]:
    left = parse_elf_sections(baseline)
    right = parse_elf_sections(candidate)
    changed = []
    for name in sorted(set(left) | set(right)):
        if left.get(name) != right.get(name):
            changed.append({
                "name": name,
                "baseline": left.get(name),
                "candidate": right.get(name),
            })

    loadable = sorted(
        name for name in set(left) | set(right)
        if ((left.get(name) or right.get(name) or {}).get("flags", 0) & SHF_ALLOC)
        and name != BUILD_ID_SECTION
    )
    loadable_equal = all(left.get(name) == right.get(name) for name in loadable)
    whole_file_equal = baseline == candidate
    if whole_file_equal:
        qualification = "byte-for-byte-identical"
    elif loadable_equal:
        qualification = "repeat-build-loadable-elf-sections-match-except-build-id-note"
    else:
        qualification = "loadable-elf-section-mismatch"
    return {
        "schema": "nvidia-hybrid-elf-loadable-section-comparison-v1",
        "baseline_sha256": sha256_bytes(baseline),
        "candidate_sha256": sha256_bytes(candidate),
        "whole_file_identical": whole_file_equal,
        "baseline_section_count": len(left),
        "candidate_section_count": len(right),
        "loadable_section_count_excluding_build_id": len(loadable),
        "all_loadable_sections_except_build_id_identical": loadable_equal,
        "qualification": qualification,
        "excluded_section": BUILD_ID_SECTION,
        "changed_sections": changed,
        "scope": "Static ELF comparison only; it does not validate module loading or runtime behavior.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path, help="write JSON to this path")
    args = parser.parse_args()
    try:
        baseline = args.baseline.read_bytes()
        candidate = args.candidate.read_bytes()
        report = compare_elf_sections(baseline, candidate)
    except (OSError, ElfFormatError) as error:
        print(f"ELF comparison failed: {error}", file=sys.stderr)
        return 2

    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0 if report["all_loadable_sections_except_build_id_identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
