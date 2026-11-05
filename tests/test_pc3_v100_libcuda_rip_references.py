# SPDX-License-Identifier: MIT
"""CPU contract tests for bounded x86-64 RIP-relative reference scanning."""
from __future__ import annotations

import importlib.util
import copy
import os
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/pc3_v100_libcuda_rip_references.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_v100_libcuda_rip_references", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("RIP reference scanner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Pc3V100LibcudaRipReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def test_finds_address_materialization_without_retaining_bytes_or_symbols(self):
        lines = [
            "Disassembly of section .text:",
            "000000000049d4b5 <FUN_0059d4b5>:",
            "  49d4b5: 48 8d 35 50 f2 73 05 lea rsi,[rip+0x573f250] # 5bdc70c <hidden>",
            "  49d4bc: ff 92 d8 04 00 00 call QWORD PTR [rdx+0x4d8]",
        ]
        result = self.tool.scan_rip_references(
            lines, target_va=0x5BDC70C, elf_load_base=0, max_matches=8)
        self.assertEqual(result["instruction_count"], 2)
        self.assertEqual(result["rip_relative_reference_count"], 1)
        self.assertEqual(result["match_count"], 1)
        self.assertFalse(result["truncated"])
        match = result["matches"][0]
        self.assertEqual(match["source_va"], "0x49d4b5")
        self.assertEqual(match["source_rva"], "0x49d4b5")
        self.assertEqual(match["preceding_symbol_anchor_va"], "0x49d4b5")
        self.assertEqual(match["section"], ".text")
        self.assertEqual(match["mnemonic"], "lea")
        self.assertEqual(match["reference_kind"], "address_materialization")
        self.assertNotIn("bytes", str(result))
        self.assertNotIn("hidden", str(result))
        self.assertNotIn("operands", match)

    def test_collects_only_capped_instruction_context_when_requested(self):
        lines = [
            "Disassembly of section .text:",
            "  1000: 48 89 c8 mov rax,rcx",
            "0000000000100003 <symbol_must_not_escape>:",
            "  1003: 48 8d 05 f6 ff ff ff lea rax,[rip-0xa] # 0x1000 <symbol_must_not_escape>",
            "  100a: 48 85 c0 test rax,rax",
            "  100d: 74 02 je 0x1011",
        ]
        result = self.tool.scan_rip_references(
            lines, target_va=0x1000, elf_load_base=0, max_matches=8,
            context_before=1, context_after=2)
        context = result["matches"][0]["linear_instruction_context"]
        self.assertEqual([row["source_rva"] for row in context],
                         ["0x1000", "0x1003", "0x100a", "0x100d"])
        self.assertEqual(context[1]["operands"], "rax,[rip-0xa]")
        self.assertNotIn("symbol_must_not_escape", str(result))
        self.assertNotIn("48 8d 05", str(result))
        with self.assertRaises(ValueError):
            self.tool.scan_rip_references(
                lines, target_va=0x1000, elf_load_base=0, context_before=17)

    def test_classifies_direct_memory_read_and_write_candidates(self):
        lines = [
            "Disassembly of section .text:",
            "  49d4c2: f6 05 63 a3 73 05 04 test BYTE PTR [rip+0x573a363],0x4",
            "  49d4d0: c6 05 34 12 00 00 01 mov BYTE PTR [rip+0x1234],0x1",
        ]
        read = self.tool.scan_rip_references(
            lines, target_va=0x5BD782C, elf_load_base=0, max_matches=8)
        self.assertEqual(read["match_count"], 1)
        self.assertEqual(read["matches"][0]["source_va"], "0x49d4c2")
        self.assertEqual(read["matches"][0]["reference_kind"], "read_or_compare")
        write = self.tool.scan_rip_references(
            lines, target_va=0x49E70B, elf_load_base=0, max_matches=8)
        self.assertEqual(write["match_count"], 1)
        self.assertEqual(write["matches"][0]["source_va"], "0x49d4d0")
        self.assertEqual(write["matches"][0]["reference_kind"], "write_candidate")

    def test_honors_signed_displacements_and_filters_other_targets(self):
        lines = [
            "Disassembly of section .text:",
            "  1000: 48 8d 05 f9 ff ff ff lea rax,[rip-0x7]",
            "  1007: 48 8b 05 00 00 00 00 mov rax,QWORD PTR [rip+0x0]",
        ]
        result = self.tool.scan_rip_references(
            lines, target_va=0x1000, elf_load_base=0, max_matches=8)
        self.assertEqual(result["rip_relative_reference_count"], 2)
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["matches"][0]["source_va"], "0x1000")

    def test_caps_retained_matches_but_counts_all_hits(self):
        lines = [
            "Disassembly of section .text:",
            "  1000: 48 8d 05 f9 ff ff ff lea rax,[rip-0x7]",
            "  1007: 48 8d 05 f2 ff ff ff lea rax,[rip-0xe]",
            "  100e: 48 8d 05 eb ff ff ff lea rax,[rip-0x15]",
        ]
        result = self.tool.scan_rip_references(
            lines, target_va=0x1000, elf_load_base=0, max_matches=2)
        self.assertEqual(result["match_count"], 3)
        self.assertEqual(len(result["matches"]), 2)
        self.assertTrue(result["truncated"])

    def test_skips_bad_decode_rows_but_records_the_coverage_limit(self):
        result = self.tool.scan_rip_references(
            ["Disassembly of section .text:", "  1000: 0f (bad)"],
            target_va=0x1000, elf_load_base=0, max_matches=2)
        self.assertEqual(result["malformed_decode_count"], 1)
        self.assertEqual(result["instruction_count"], 0)
        self.assertEqual(result["match_count"], 0)

    def test_rejects_unbounded_or_invalid_scan_parameters(self):
        for kwargs in (
            {"target_va": -1, "elf_load_base": 0, "max_matches": 8},
            {"target_va": 0x1000, "elf_load_base": -1, "max_matches": 8},
            {"target_va": 0x1000, "elf_load_base": 0, "max_matches": 0},
            {"target_va": 0x1000, "elf_load_base": 0, "max_matches": 129},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.tool.scan_rip_references([], **kwargs)

    def test_canonicalizes_nvidia_smi_full_domain_pci_identity(self):
        self.assertEqual(self.tool.canonical_pci("00000000:00:05.0"), "0000:00:05.0")
        with self.assertRaises(ValueError):
            self.tool.canonical_pci("0000:20:20.0")

    def _remote_report(self):
        context = {"source_va": "0x1000", "source_rva": "0x1000", "section": ".text",
                   "mnemonic": "lea", "operands": "rax,[rip+0x0]"}
        match = {"source_va": "0x1000", "source_rva": "0x1000",
                 "preceding_symbol_anchor_va": None, "preceding_symbol_anchor_rva": None,
                 "section": ".text", "mnemonic": "lea",
                 "reference_kind": "address_materialization",
                 "linear_instruction_context": [context]}
        guest = {
            "schema": "nvidia-hybrid-pc3-v100-libcuda-rip-scan-v1",
            "guest": {"hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
                      "gpu": {"name": "Tesla V100-SXM2-16GB", "uuid": self.tool.EXPECTED_V100_UUID,
                              "pci": "0000:00:05.0", "driver_version": "580.178.04"}},
            "library": {"basename": "libcuda.so.580.178.04", "bytes": self.tool.EXPECTED_LIBCUDA_BYTES,
                        "sha256": self.tool.EXPECTED_LIBCUDA_SHA256},
            "address_mapping": {"target_elf_vma": "0x5bdc70c", "target_rva": "0x5bdc70c",
                                "target_ghidra_address": "0x5cdc70c"},
            "scan": {"target_va": "0x5bdc70c", "target_rva": "0x5bdc70c",
                     "elf_load_base": "0x0", "line_count": 1, "instruction_count": 1,
                     "rip_relative_reference_count": 1, "malformed_decode_count": 0,
                     "undecoded_byte_directive_count": 0, "match_count": 1,
                     "matches": [match], "truncated": False, "decode_scan_complete": True},
            "scope": {key: False for key in ("binary_copied", "binary_retained",
                      "raw_disassembly_retained", "symbols_retained", "pseudocode_retained",
                      "gpu_workload_run", "driver_or_vm_changed")},
        }
        return {"host": {"hostname": "pc3", "kernel_release": "7.0.0-38-generic",
                         "pci_ownership": {"0000:02:00.0": "nvidia", "0000:81:00.0": "vfio-pci"},
                         "nvidia_smi_gpu": {"name": "NVIDIA GeForce RTX 5080",
                             "uuid": self.tool.EXPECTED_RTX_UUID, "pci": "00000000:02:00.0",
                             "driver_version": "595.99.02"}},
                "guest_hostkey_fingerprint": "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts",
                "guest": guest}

    def test_remote_result_contract_accepts_exact_pinned_static_scan(self):
        result = self.tool._validate_remote_result(self._remote_report())
        self.assertEqual(result["guest"]["scan"]["match_count"], 1)

    def test_remote_result_contract_rejects_binary_copy_and_unexpected_payloads(self):
        copied = self._remote_report()
        copied["guest"]["scope"]["binary_copied"] = True
        with self.assertRaisesRegex(ValueError, "exceeded"):
            self.tool._validate_remote_result(copied)
        extra = self._remote_report()
        extra["guest"]["scan"]["matches"][0]["symbol_name"] = "must_not_escape"
        with self.assertRaisesRegex(ValueError, "unexpected field"):
            self.tool._validate_remote_result(extra)

    def test_private_report_is_exclusive_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            self.tool._write_report(path, {"status": "ok"})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.tool._write_report(path, {"status": "replacement"})


if __name__ == "__main__":
    unittest.main()
