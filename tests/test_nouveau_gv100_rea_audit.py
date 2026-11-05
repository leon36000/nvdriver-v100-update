import tempfile
import unittest
from pathlib import Path

from tools.nouveau_gv100_rea_audit import (
    AuditError,
    module_license_is_gpl,
    parse_chipset_relocations,
    summarize_gv100_firmware,
    summarize_rea_call,
    validate_rea_call,
    validate_rea_decompile,
    write_new_json,
)


class NouveauGv100ReaAuditTests(unittest.TestCase):
    def test_license_gate_accepts_gpl_module_metadata(self):
        self.assertTrue(module_license_is_gpl("GPL and additional rights"))
        self.assertFalse(module_license_is_gpl("NVIDIA"))
        self.assertFalse(module_license_is_gpl("Dual MIT/GPL"))

    def test_firmware_summary_keeps_gv100_acr_and_gsp_separate(self):
        report = summarize_gv100_firmware(
            [
                "nvidia/gv100/acr/ucode_load.bin",
                "nvidia/gv100/acr/bl.bin",
                "nvidia/tu102/gsp/gsp-570.144.bin",
            ]
        )
        self.assertEqual(report["gv100_acr_count"], 2)
        self.assertEqual(report["gv100_gsp_count"], 0)
        self.assertEqual(report["other_gsp_count"], 1)

    def test_chipset_relocations_are_limited_to_nv140_table(self):
        nm = "00000000000159c0 0000000000000348 r nv140_chipset\n"
        relocations = """\
00000000000159e0 R_X86_64_64 gv100_gsp_new
0000000000015b20 R_X86_64_64 gv100_acr_new
00000000000161e0 R_X86_64_64 gp108_acr_new
"""
        found = parse_chipset_relocations(nm, relocations)
        self.assertEqual(
            [(row["symbol"], row["offset"]) for row in found],
            [("gv100_gsp_new", "0x159e0"), ("gv100_acr_new", "0x15b20")],
        )

    def test_missing_chipset_symbol_fails_closed(self):
        with self.assertRaises(AuditError):
            parse_chipset_relocations("0000 0010 r another_table\n", "")

    def test_rea_summary_extracts_only_expected_dispatch(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "a" * 64}},
            "normalized_result": (
                "void gv100_acr_new() {\n"
                "  nvkm_acr_new_(gv100_acr_fwif, a, b, c, d);\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_decompile(
                report, "gv100_acr_new", "nvkm_acr_new_", "gv100_acr_fwif"
            ),
            "nvkm_acr_new_(gv100_acr_fwif)",
        )

    def test_rea_summary_preserves_pointer_to_vmm_descriptor(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "d" * 64}},
            "normalized_result": (
                "int gv100_vmm_new() {\n"
                "  return gp100_vmm_new_(&gv100_vmm, mmu, managed);\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_decompile(
                report, "gv100_vmm_new", "gp100_vmm_new_", "gv100_vmm"
            ),
            "gp100_vmm_new_(&gv100_vmm)",
        )

    def test_rea_summary_rejects_wrong_vmm_descriptor(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "e" * 64}},
            "normalized_result": (
                "int gv100_vmm_new() {\n"
                "  return gp100_vmm_new_(&gp100_vmm, mmu, managed);\n"
                "}\n"
            ),
        }
        with self.assertRaises(AuditError):
            validate_rea_decompile(
                report, "gv100_vmm_new", "gp100_vmm_new_", "gv100_vmm"
            )

    def test_rea_summary_rejects_wrong_target_and_does_not_keep_pseudocode(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "a" * 64}},
            "normalized_result": "void other() { nvkm_gsp_new_(gv100_gsps); }",
        }
        with self.assertRaises(AuditError):
            validate_rea_decompile(
                report, "gv100_gsp_new", "nvkm_gsp_new_", "gv100_gsps"
            )

    def test_rea_sm_id_summary_keeps_only_hash_pinned_call_fact(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "b" * 64}},
            "normalized_result": (
                "int gv100_gr_oneinit_sm_id(struct gf100_gr *gr) {\n"
                "  ret = gv100_gr_scg_estimate_perf(gr, mask, gpc, tpc, &perf);\n"
                "  return ret;\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_call(report, "gv100_gr_oneinit_sm_id",
                              "gv100_gr_scg_estimate_perf"),
            "gv100_gr_scg_estimate_perf",
        )

    def test_rea_vmm_join_summary_keeps_only_hash_pinned_call_fact(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "f" * 64}},
            "normalized_result": (
                "int gv100_vmm_join(struct nvkm_vmm *vmm) {\n"
                "  int ret = gp100_vmm_join(vmm, inst);\n"
                "  return ret;\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_call(report, "gv100_vmm_join", "gp100_vmm_join"),
            "gp100_vmm_join",
        )

    def test_rea_vmm_join_summary_rejects_missing_generic_join(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "1" * 64}},
            "normalized_result": (
                "int gv100_vmm_join(struct nvkm_vmm *vmm) {\n"
                "  return gf100_vmm_join(vmm, inst);\n"
                "}\n"
            ),
        }
        with self.assertRaises(AuditError):
            validate_rea_call(report, "gv100_vmm_join", "gp100_vmm_join")

    def test_rea_gp100_vmm_summary_keeps_only_common_vmm_call(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "2" * 64}},
            "normalized_result": (
                "int gp100_vmm_new_(struct nvkm_vmm **vmm) {\n"
                "  int ret = nvkm_vmm_new_(mmu, vmm);\n"
                "  return ret;\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_call(report, "gp100_vmm_new_", "nvkm_vmm_new_"),
            "nvkm_vmm_new_",
        )

    def test_rea_gp100_vmm_summary_rejects_wrong_generic_vmm_call(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "3" * 64}},
            "normalized_result": (
                "int gp100_vmm_new_(struct nvkm_vmm **vmm) {\n"
                "  return nv50_vmm_new_(mmu, vmm);\n"
                "}\n"
            ),
        }
        with self.assertRaises(AuditError):
            validate_rea_call(report, "gp100_vmm_new_", "nvkm_vmm_new_")

    def test_rea_fault_buffer_worker_summary_keeps_only_hash_pinned_fifo_call(self):
        module_hash = "4" * 64
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {
                "id": "ghidra",
                "version": "12.1.4",
                "local_path": "/must/not/enter/receipt",
            },
            "subject": {"digest": {"sha256": module_hash}},
            "normalized_result": (
                "void gv100_fault_buffer_process(long work) {\n"
                "  nvkm_fifo_fault(device->fifo, &info);\n"
                "}\n"
            ),
        }
        self.assertEqual(
            summarize_rea_call(
                report, module_hash, "gv100_fault_buffer_process", "nvkm_fifo_fault"
            ),
            {
                "provider": {"id": "ghidra", "version": "12.1.4"},
                "procedure": "gv100_fault_buffer_process",
                "related_calls": ["nvkm_fifo_fault"],
                "pseudocode_retained": False,
            },
        )

    def test_rea_call_summary_is_bounded_to_named_procedure_body(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "7" * 64}},
            "normalized_result": (
                "void gv100_fault_buffer_process(long work) {\n"
                "  if (ready) { drain(); }\n"
                "}\n"
                "void sibling(long work) {\n"
                "  nvkm_fifo_fault(device->fifo, &info);\n"
                "}\n"
            ),
        }
        with self.assertRaisesRegex(AuditError, "expected call"):
            summarize_rea_call(
                report, "7" * 64, "gv100_fault_buffer_process", "nvkm_fifo_fault"
            )

    def test_rea_call_summary_accepts_split_ghidra_function_header(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "9" * 64}},
            "normalized_result": (
                "undefined1 [16]\n"
                "gp100_vmm_new_(undefined8 arg1, undefined8 arg2)\n"
                "{\n"
                "  nvkm_vmm_new_(arg1);\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_call(report, "gp100_vmm_new_", "nvkm_vmm_new_"),
            "nvkm_vmm_new_",
        )

    def test_rea_call_summary_accepts_kernel_lock_annotations_before_body(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "a" * 64}},
            "normalized_result": (
                "static void process_one_work(struct worker *worker, struct work_struct *work)\n"
                "__releases(&pool->lock)\n"
                "__acquires(&pool->lock)\n"
                "{\n"
                "  worker->current_func(work);\n"
                "}\n"
            ),
        }
        self.assertEqual(
            validate_rea_call(report, "process_one_work", "current_func"),
            "current_func",
        )

    def test_rea_call_summary_ignores_comments_and_string_literals(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "8" * 64}},
            "normalized_result": (
                "void gv100_fault_buffer_process(long work) {\n"
                "  /* nvkm_fifo_fault(device->fifo, &info); */\n"
                "  const char *text = \"} nvkm_fifo_fault(\";\n"
                "}\n"
            ),
        }
        with self.assertRaisesRegex(AuditError, "expected call"):
            summarize_rea_call(
                report, "8" * 64, "gv100_fault_buffer_process", "nvkm_fifo_fault"
            )

    def test_rea_fault_buffer_worker_summary_rejects_different_module_hash(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "ghidra", "version": "12.1.4"},
            "subject": {"digest": {"sha256": "5" * 64}},
            "normalized_result": (
                "void gv100_fault_buffer_process(long work) {\n"
                "  nvkm_fifo_fault(device->fifo, &info);\n"
                "}\n"
            ),
        }
        with self.assertRaisesRegex(AuditError, "different bytes"):
            summarize_rea_call(
                report, "6" * 64, "gv100_fault_buffer_process", "nvkm_fifo_fault"
            )

    def test_rea_sm_id_summary_rejects_wrong_procedure_or_provider(self):
        report = {
            "operation": "procedure_pseudo_code",
            "provider": {"id": "other", "version": "1"},
            "subject": {"digest": {"sha256": "c" * 64}},
            "normalized_result": "int other() { gv100_gr_scg_estimate_perf(); }",
        }
        with self.assertRaises(AuditError):
            validate_rea_call(report, "gv100_gr_oneinit_sm_id",
                              "gv100_gr_scg_estimate_perf")
        report["provider"] = {"id": "ghidra"}
        with self.assertRaises(AuditError):
            validate_rea_call(report, "gv100_gr_oneinit_sm_id",
                              "gv100_gr_scg_estimate_perf")

    def test_receipt_is_private_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            write_new_json(path, {"status": "ANALYZED_STATICALLY"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            with self.assertRaises(AuditError):
                write_new_json(path, {"status": "REPLACED"})
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
