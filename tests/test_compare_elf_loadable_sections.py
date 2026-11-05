# SPDX-License-Identifier: MIT
from __future__ import annotations

import struct
import unittest

from tools.compare_elf_loadable_sections import (
    ElfFormatError,
    compare_elf_sections,
    parse_elf_sections,
)


def make_elf64(sections: list[tuple[str, int, bytes]]) -> bytes:
    """Build a small little-endian ELF64 object with named sections."""
    names = bytearray(b"\0")
    name_offsets = {}
    for name, _flags, _payload in sections:
        name_offsets[name] = len(names)
        names.extend(name.encode() + b"\0")
    name_offsets[".shstrtab"] = len(names)
    names.extend(b".shstrtab\0")

    data = bytearray(b"\0" * 64)
    raw = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, flags, payload in sections:
        offset = len(data)
        data.extend(payload)
        raw.append((name_offsets[name], 1, flags, 0, offset, len(payload), 0, 0, 1, 0))
    names_offset = len(data)
    data.extend(names)
    raw.append((name_offsets[".shstrtab"], 3, 0, 0, names_offset, len(names), 0, 0, 1, 0))
    section_offset = len(data)
    for section in raw:
        data.extend(struct.pack("<IIQQQQIIQQ", *section))

    data[:16] = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    struct.pack_into("<HHI", data, 16, 1, 62, 1)
    struct.pack_into("<Q", data, 0x28, section_offset)
    struct.pack_into("<H", data, 0x3A, 64)
    struct.pack_into("<H", data, 0x3C, len(raw))
    struct.pack_into("<H", data, 0x3E, len(raw) - 1)
    return bytes(data)


class CompareElfLoadableSectionsTests(unittest.TestCase):
    def test_byte_identical_inputs_receive_exact_reproducibility_qualification(self):
        artifact = make_elf64([(".text", 0x6, b"code")])
        report = compare_elf_sections(artifact, artifact)
        self.assertTrue(report["whole_file_identical"])
        self.assertEqual(report["qualification"], "byte-for-byte-identical")

    def test_debug_and_build_id_changes_do_not_hide_loadable_code_parity(self):
        baseline = make_elf64([
            (".text", 0x6, b"code"),
            (".note.gnu.build-id", 0x2, b"id-1"),
            (".debug_info", 0, b"debug-a"),
        ])
        candidate = make_elf64([
            (".text", 0x6, b"code"),
            (".note.gnu.build-id", 0x2, b"id-2"),
            (".debug_info", 0, b"debug-b"),
        ])
        report = compare_elf_sections(baseline, candidate)
        self.assertFalse(report["whole_file_identical"])
        self.assertTrue(report["all_loadable_sections_except_build_id_identical"])
        self.assertEqual(
            [section["name"] for section in report["changed_sections"]],
            [".debug_info", ".note.gnu.build-id"],
        )

    def test_loadable_code_change_fails_comparison(self):
        baseline = make_elf64([(".text", 0x6, b"code")])
        candidate = make_elf64([(".text", 0x6, b"c0de")])
        report = compare_elf_sections(baseline, candidate)
        self.assertFalse(report["all_loadable_sections_except_build_id_identical"])
        self.assertEqual(report["qualification"], "loadable-elf-section-mismatch")

    def test_parse_reports_section_metadata_and_hashes(self):
        blob = make_elf64([(".text", 0x6, b"code")])
        sections = parse_elf_sections(blob)
        self.assertEqual(sections[".text"]["flags"], 0x6)
        self.assertEqual(sections[".text"]["size"], 4)
        self.assertEqual(len(sections[".text"]["sha256"]), 64)

    def test_rejects_non_elf_and_truncated_section_data(self):
        with self.assertRaises(ElfFormatError):
            parse_elf_sections(b"not ELF")
        blob = make_elf64([(".text", 0x6, b"code")])
        with self.assertRaises(ElfFormatError):
            parse_elf_sections(blob[:80])


if __name__ == "__main__":
    unittest.main()
