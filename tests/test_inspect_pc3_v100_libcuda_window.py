# SPDX-License-Identifier: MIT
"""CPU contract tests for bounded PC3 V100 libcuda disassembly metadata."""
from __future__ import annotations

import ast
import importlib.util
import copy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/inspect_pc3_v100_libcuda_window.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("inspect_pc3_v100_libcuda_window", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("bounded libcuda disassembly tool could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Pc3V100LibcudaWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def test_generated_remote_and_guest_inspection_sources_compile(self):
        remote_source = self.tool._remote_root_script()
        compile(remote_source, "<generated-pc3-root-inspector>", "exec")
        tree = ast.parse(remote_source)
        guest_assignments = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == "guest_code"
                for target in node.targets)
        ]
        self.assertEqual(len(guest_assignments), 1)
        guest_source = ast.literal_eval(guest_assignments[0].value)
        compile(guest_source, "<generated-pc3-guest-inspector>", "exec")
        self.assertIn("RIP_RELATIVE_CALL_RETURNS", guest_source)
        self.assertIn("RIP_RELATIVE_CALL_RETURNS={0x3279aa:0x3279b0,0x327a6a:0x327a70,0x327b2a:0x327b30,0x327bea:0x327bf0,0x327caa:0x327cb0,0x32866a:0x328670,0x32872a:0x328730,0x37828a:0x378290,0xf57127:0xf5712d}", guest_source)
        self.assertIn("RIP_RELATIVE_SLOT_VAS", guest_source)
        self.assertIn("RIP_SLOT_CONTEXT_WINDOW_SPECS", guest_source)
        self.assertIn("RIP_SLOT_CONTEXT_WINDOW_SPECS=((0x3f1b00,0x3f1c00),(0x3eb469,0x3eb509))", guest_source)
        self.assertIn("{0x5bcf9e8,0x5bcf9f0,0x5bcf9f8,0x5bcfa00,0x5bcfa08,0x5bcfa10,0x5bcfa18,0x5bcfa20,0x5bd7a50}", guest_source)
        self.assertIn("branch_xref_scan", guest_source)
        self.assertIn("BRANCH_XREF_TARGET_RVAS", guest_source)
        self.assertIn("slot_context_lines", guest_source)
        self.assertIn("{0x3f1b01,0x3f1b11,0x3f1b1d,0x3f1b39,0x3f1b40,0x3f1b50,0x3f1b55,0x3f1b6c,0x3f1b71,0x3f1b88,0x3f1b8d,0x3f1ba4,0x3f1ba9,0x3f1bc0,0x3f1bc5,0x3f1bdc}", guest_source)
        self.assertIn("in_local_context", guest_source)

    def test_parses_only_instruction_metadata_and_maps_va_to_rva(self):
        output = """\
Disassembly of section .text:

0000000000595ac0 <FUN_00594f60+0xb60>:
  595aa0:\t(bad)
  595ac0:\ttest   eax,eax
  595ac2:\tjne    0x595ae0
  595ac7:\tcall   58bc40 <FUN_0058bc40>
  595acc:\ttest   eax,eax
  595ace:\tjne    0x595b08
  595ad4:\tmov    eax,DWORD PTR [rbp-0x24] # 0x1 <unwanted annotation>
  595ad8:\t.byte 0x90
"""
        records = self.tool.parse_instruction_window(
            output, image_base=0x100000, start_rva=0x495AA0, stop_rva=0x495B20)
        self.assertEqual([item["rva"] for item in records],
                         ["0x495ac0", "0x495ac2", "0x495ac7", "0x495acc", "0x495ace", "0x495ad4"])
        self.assertEqual(records[2]["mnemonic"], "call")
        self.assertEqual(records[2]["operands"], "58bc40")
        self.assertNotIn("encoding", records[2])
        self.assertNotIn("FUN_0058bc40", str(records))

    def test_accepts_braced_x86_encoding_annotation_without_raw_bytes(self):
        records = self.tool.parse_instruction_window(
            "  3321e6:\tdata16 {vex}\n", image_base=0x0,
            start_rva=0x3321e0, stop_rva=0x332200)
        self.assertEqual(records, [{"rva": "0x3321e6", "mnemonic": "data16",
                                    "operands": "{vex}"}])

    def test_rejects_raw_bytes_and_out_of_window_instructions(self):
        with self.assertRaisesRegex(ValueError, "raw instruction bytes"):
            self.tool.parse_instruction_window(
                "  595ac7: e8 74 01 ff ff call 0x58bc40\n",
                image_base=0x100000, start_rva=0x495AA0, stop_rva=0x495B20)
        with self.assertRaisesRegex(ValueError, "outside the requested window"):
            self.tool.parse_instruction_window(
                "  595b20:\tret\n", image_base=0x100000,
                start_rva=0x495AA0, stop_rva=0x495B20)

    def test_rejects_duplicate_addresses_and_unbounded_windows(self):
        repeated = "  595ac7:\tcall 0x58bc40\n  595ac7:\tret\n"
        with self.assertRaisesRegex(ValueError, "duplicate instruction address"):
            self.tool.parse_instruction_window(
                repeated, image_base=0x100000, start_rva=0x495AA0, stop_rva=0x495B20)
        with self.assertRaisesRegex(ValueError, "window exceeds"):
            self.tool.parse_instruction_window(
                "", image_base=0x100000, start_rva=0, stop_rva=0x1001)

    def test_direct_branch_target_parser_ignores_indirect_control_operands(self):
        parse_target = self.tool.parse_direct_branch_target
        self.assertEqual(parse_target("jmp", "3eb469"), 0x3EB469)
        self.assertEqual(parse_target("jne", "0x3f1b40 <candidate>"), 0x3F1B40)
        self.assertIsNone(parse_target("call", "QWORD PTR [rip+0x1234]"))
        self.assertIsNone(parse_target("jmp", "rax"))
        self.assertIsNone(parse_target("junk", "3eb469"))
        self.assertIsNone(parse_target("mov", "3eb469"))

    def test_direct_branch_xrefs_require_scanned_instruction_boundaries(self):
        records = [
            {"source_rva": "0x3f1b6a", "source_length_bytes": 5,
             "mnemonic": "jmp", "target_rva": "0x3eb469"},
            {"source_rva": "0x3f1b25", "source_length_bytes": 5,
             "mnemonic": "jmp", "target_rva": "0x3eb469"},
            {"source_rva": "0x3f2000", "source_length_bytes": 6,
             "mnemonic": "jne", "target_rva": "0x3f1b40"},
            {"source_rva": "0x3f2010", "source_length_bytes": 5,
             "mnemonic": "call", "target_rva": "0x3f1b50"},
            {"source_rva": "0x3f2020", "source_length_bytes": 5,
             "mnemonic": "jmp", "target_rva": "0x3f1b39"},
            {"source_rva": "0x3f2030", "source_length_bytes": 5,
             "mnemonic": "jne", "target_rva": "0x3f1b1d"},
            {"source_rva": "0x3f2040", "source_length_bytes": 5,
             "mnemonic": "je", "target_rva": "0x3f1b11"},
        ]
        report = self.tool.summarize_direct_branch_xrefs(
            records, decoded_target_rvas=["0x3eb469", "0x3f1b11", "0x3f1b1d", "0x3f1b39", "0x3f1b40", "0x3f1b50"],
            text_start_rva=0x166F00, text_end_rva=0x10E94E4)
        self.assertEqual(report["reference_count"], 7)
        self.assertEqual(report["verified_target_instruction_starts"],
                         ["0x3eb469", "0x3f1b11", "0x3f1b1d", "0x3f1b39", "0x3f1b40", "0x3f1b50"])
        self.assertTrue(all(item["target_instruction_start_verified"]
                            for item in report["references"]))
        with self.assertRaisesRegex(ValueError, "decoded instruction start"):
            self.tool.summarize_direct_branch_xrefs(
                records, decoded_target_rvas=["0x3eb469"],
                text_start_rva=0x166F00, text_end_rva=0x10E94E4)
        out_of_scope = [dict(records[0], target_rva="0x3f2000")]
        with self.assertRaisesRegex(ValueError, "pinned target scope"):
            self.tool.summarize_direct_branch_xrefs(
                out_of_scope, decoded_target_rvas=[],
                text_start_rva=0x166F00, text_end_rva=0x10E94E4)
        invalid_opcode = [dict(records[0], mnemonic="junk")]
        with self.assertRaisesRegex(ValueError, "non-branch"):
            self.tool.summarize_direct_branch_xrefs(
                invalid_opcode, decoded_target_rvas=["0x3eb469"],
                text_start_rva=0x166F00, text_end_rva=0x10E94E4)

    def test_branch_xref_scope_is_copy_entry_and_six_jump_sites_not_the_whole_window(self):
        expected = {0x3F1B01, 0x3F1B11, 0x3F1B1D, 0x3F1B39, 0x3F1B40, 0x3F1B50, 0x3F1B55, 0x3F1B6C, 0x3F1B71, 0x3F1B88, 0x3F1B8D, 0x3F1BA4, 0x3F1BA9, 0x3F1BC0, 0x3F1BC5, 0x3F1BDC}
        self.assertEqual(self.tool.RIP_SLOT_BRANCH_XREF_TARGET_RVAS, expected)
        self.assertEqual(self.tool.RIP_SLOT_BRANCH_XREF_EXACT_TARGETS, {0x3EB469})
        self.assertEqual(self.tool.RIP_SLOT_CONTEXT_WINDOW_SPECS,
                         ((0x3F1B00, 0x3F1C00), (0x3EB469, 0x3EB509)))
        with self.assertRaisesRegex(ValueError, "decoded branch-target instruction start"):
            self.tool.summarize_direct_branch_xrefs(
                [{"source_rva": "0x3f2000", "source_length_bytes": 5,
                  "mnemonic": "jmp", "target_rva": "0x3f1b45"}],
                decoded_target_rvas=["0x3f1b45"],
                text_start_rva=0x166F00, text_end_rva=0x10E94E4)

    def test_common_sink_xrefs_are_collected_only_from_the_bounded_copy_block(self):
        with self.assertRaisesRegex(ValueError, "bounded source context"):
            self.tool.summarize_direct_branch_xrefs(
                [{"source_rva": "0x400000", "source_length_bytes": 5,
                  "mnemonic": "jmp", "target_rva": "0x3eb469"}],
                decoded_target_rvas=["0x3eb469"],
                text_start_rva=0x166F00, text_end_rva=0x10E94E4)

    def test_remote_collection_bounds_output_for_twenty_windows(self):
        script = self.tool._remote_root_script()
        self.assertIn("MAX_OUTPUT=131072", script)
        self.assertIn("(0x4600d0,0x460110)", script)
        self.assertIn("(0x495b00,0x495b90)", script)
        self.assertIn("(0x496850,0x4968d0)", script)
        self.assertIn("(0x495dc0,0x496040)", script)
        self.assertIn("(0x49d460,0x49d550)", script)
        self.assertIn("RIP_SLOT_CONTEXT_WINDOW_SPECS=((0x3f1b00,0x3f1c00),(0x3eb469,0x3eb509))", script)
        self.assertIn('"slot_reference_contexts":slot_reference_contexts', script)
        self.assertIn("CALLER_RETURN_RVAS=(0x495acc,0x477209,0x46311c,0x3248f0,0x47d265,0xf5712d,0x2d251e,0x331c32,0x3279b0,0x332226,0x327cb0)", script)
        self.assertEqual(len(self.tool.WINDOW_SPECS), 20)
        self.assertIn('control=mnemonic.startswith(("j","loop","call","ret","iret"))', script)
        self.assertIn('predicate=mnemonic in ("cmp","test") and (tracked_register or frame_access)', script)
        self.assertIn("len(selected)>512", script)
        self.assertIn("selected_bytes>24576", script)

    def test_runtime_caller_window_set_matches_pinned_v4_trace(self):
        trace_path = ROOT / self.tool.GPU_NAME_CALLER_TRACE_PATH
        self.assertEqual(
            __import__("hashlib").sha256(trace_path.read_bytes()).hexdigest(),
            self.tool.GPU_NAME_CALLER_TRACE_SHA256)
        import json
        trace = json.loads(trace_path.read_text())
        observed = set()
        for run in trace["runs"]:
            for record in run["gpu_name_string_records"]:
                observed.update(int(value, 16)
                                for value in record["caller_chain_offsets"])
        self.assertTrue(set(self.tool.GPU_NAME_CALLER_RETURN_RVAS) <= observed)

    def test_reports_the_call_and_bounded_post_call_control_flow(self):
        records = [
            {"rva": "0x495ac7", "mnemonic": "call", "operands": "0x58bc40"},
            {"rva": "0x495acc", "mnemonic": "test", "operands": "eax,eax"},
            {"rva": "0x495ace", "mnemonic": "jne", "operands": "0x1595b08"},
            {"rva": "0x495ad4", "mnemonic": "mov", "operands": "eax,DWORD PTR [rbp-0x24]"},
        ]
        result = self.tool.summarize_window(records, call_rva=0x495AC7,
                                            return_rva=0x495ACC, expected_callee_rva=0x48BC40,
                                            image_base=0x100000)
        self.assertTrue(result["call_return_address_matches"])
        self.assertEqual(result["conditional_branch_rvas_in_bounded_window"], ["0x495ace:jne"])
        self.assertNotIn("mask_dataflow_proven", result)

    def test_summarizes_parent_call_arguments_only_for_an_uninterrupted_pre_call_block(self):
        records = [
            {"rva": "0x4600d1", "mnemonic": "mov", "operands": "r8d,0x4"},
            {"rva": "0x4600d7", "mnemonic": "mov", "operands": "edx,0x1f0"},
            {"rva": "0x4600e3", "mnemonic": "lea", "operands": "rcx,[rbp-0x14]"},
            {"rva": "0x4600f0", "mnemonic": "mov", "operands": "DWORD PTR [rbp-0x14],0x0"},
            {"rva": "0x4600f7", "mnemonic": "call", "operands": "494f60"},
        ]
        result = self.tool.summarize_parent_call_arguments(records, call_rva=0x4600F7)
        self.assertTrue(result["single_linear_pre_call_block"])
        self.assertEqual(result["rcx_pointer_candidate"], "[rbp-0x14]")
        self.assertEqual(result["edx_command_candidate"], "0x1f0")
        self.assertEqual(result["r8d_size_candidate"], "0x4")
        self.assertEqual(result["zeroed_dword_candidate"], "[rbp-0x14]")
        branched = records[:2] + [
            {"rva": "0x4600e0", "mnemonic": "jne", "operands": "4600f7"},
            *records[2:],
        ]
        result = self.tool.summarize_parent_call_arguments(branched, call_rva=0x4600F7)
        self.assertFalse(result["single_linear_pre_call_block"])
        self.assertIsNone(result["rcx_pointer_candidate"])

    def test_traces_the_parent_feature_bit_test_only_after_successful_call(self):
        records = [
            {"rva": "0x4600f7", "mnemonic": "call", "operands": "494f60"},
            {"rva": "0x4600fc", "mnemonic": "test", "operands": "eax,eax"},
            {"rva": "0x4600fe", "mnemonic": "jne", "operands": "460109"},
            {"rva": "0x460100", "mnemonic": "test", "operands": "BYTE PTR [rbp-0x14],0x8"},
            {"rva": "0x460104", "mnemonic": "je", "operands": "460109"},
            {"rva": "0x460106", "mnemonic": "mov", "operands": "BYTE PTR [rbx],0x1"},
        ]
        result = self.tool.summarize_parent_feature_bit_consumer(
            records, call_rva=0x4600F7, payload_pointer="[rbp-0x14]")
        self.assertTrue(result["pattern_matched"])
        self.assertEqual(result["tested_payload"], "[rbp-0x14]")
        self.assertEqual(result["tested_bit_value"], "0x8")
        self.assertEqual(result["tested_bit_index"], 3)
        self.assertTrue(result["output_flag_set_only_when_bit_is_set"])
        self.assertTrue(result["requires_zero_call_result"])
        wrong_payload = [*records]
        wrong_payload[3] = {**records[3], "operands": "BYTE PTR [rbp-0x18],0x8"}
        result = self.tool.summarize_parent_feature_bit_consumer(
            wrong_payload, call_rva=0x4600F7, payload_pointer="[rbp-0x14]")
        self.assertFalse(result["pattern_matched"])

    def test_summary_does_not_claim_a_mask_read_from_one_memory_operand(self):
        records = [
            {"rva": "0x495ac7", "mnemonic": "call", "operands": "0x58bc40"},
            {"rva": "0x495acc", "mnemonic": "mov", "operands": "eax,DWORD PTR [rbp-0x24]"},
        ]
        result = self.tool.summarize_window(records, call_rva=0x495AC7,
                                            return_rva=0x495ACC, expected_callee_rva=0x48BC40,
                                            image_base=0x100000)
        self.assertEqual(result["memory_operand_count_after_return_in_bounded_window"], 1)
        self.assertNotIn("feature_mask_consumed", result)

    def test_verifies_the_ioctl_return_capture_and_indirect_basic_block_handoff(self):
        primary = [
            {"rva": "0x495aae", "mnemonic": "lea", "operands": "r9,[rbp-0x1114]"},
            {"rva": "0x495ab5", "mnemonic": "mov", "operands": "r8,r10"},
            {"rva": "0x495ac7", "mnemonic": "call", "operands": "48bc40"},
            {"rva": "0x495acc", "mnemonic": "mov", "operands": "r13d,eax"},
            {"rva": "0x495acf", "mnemonic": "jmp", "operands": "49551a"},
        ]
        following = [
            {"rva": "0x49551a", "mnemonic": "test", "operands": "r13d,r13d"},
            {"rva": "0x49551d", "mnemonic": "je", "operands": "4958e8"},
            {"rva": "0x495523", "mnemonic": "mov", "operands": "DWORD PTR [rbp-0x1114],r13d"},
        ]
        success = [
            {"rva": "0x4958e8", "mnemonic": "mov", "operands": "r8d,DWORD PTR [rbp-0x1114]"},
            {"rva": "0x4958ef", "mnemonic": "test", "operands": "r8d,r8d"},
        ]
        result = self.tool.summarize_call_handoff(primary, following, success, elf_base=0)
        self.assertEqual(result["handoff_target_rva"], "0x49551a")
        self.assertEqual(result["call_return_capture"]["operands"], "r13d,eax")
        self.assertTrue(result["target_window_begins_at_handoff"])
        self.assertEqual(result["zero_status_target_rva"], "0x4958e8")
        self.assertTrue(result["zero_status_window_begins_at_target"])
        self.assertEqual(result["sixth_argument_local_operand"], "[rbp-0x1114]")
        self.assertEqual(result["success_path_local_read"]["operands"], "r8d,DWORD PTR [rbp-0x1114]")
        with self.assertRaisesRegex(ValueError, "handoff did not match"):
            self.tool.summarize_call_handoff(primary, following[1:], success, elf_base=0)

    def test_traces_ioctl_return_test_without_treating_it_as_mask_consumption(self):
        instructions = [
            {"rva": "0x48bc48", "mnemonic": "mov", "operands": "r14,r9"},
            {"rva": "0x48bc83", "mnemonic": "call", "operands": "166160"},
            {"rva": "0x48bc88", "mnemonic": "test", "operands": "eax,eax"},
            {"rva": "0x48bc8a", "mnemonic": "jns", "operands": "48bcb8"},
            {"rva": "0x48bcb8", "mnemonic": "cmp", "operands": "DWORD PTR [r14],0x3"},
        ]
        result = self.tool.summarize_ioctl_wrapper(instructions, elf_base=0)
        self.assertEqual(result["ioctl_return_test"]["operands"], "eax,eax")
        self.assertEqual(result["nonnegative_status_branch_target_rva"], "0x48bcb8")
        self.assertTrue(result["r9_dword_compare"]["r9_captured_in_r14"])
        self.assertTrue(result["r9_dword_compare"]["compare_is_success_branch_target"])
        self.assertEqual(result["r9_dword_compare"]["compare_immediate"], "0x3")
        self.assertIn("does not identify", result["r9_dword_compare"]["interpretation_limit"])
        self.assertNotIn("feature_mask_consumed", result)

    def test_r10_reference_summary_labels_writes_as_candidates_only(self):
        records = [
            {"rva": "0x495100", "mnemonic": "mov", "operands": "r10,rax"},
            {"rva": "0x495110", "mnemonic": "test", "operands": "r10,r10"},
            {"rva": "0x495120", "mnemonic": "mov", "operands": "r8,r10"},
        ]
        summary = self.tool.summarize_r10_references(records)
        self.assertEqual(summary["candidate_destination_instructions"], [records[0]])
        self.assertEqual(summary["register_reference_count"], 3)
        self.assertIn("do not prove", summary["interpretation_limit"])

    def test_r12_reference_summary_exposes_payload_pointer_candidates_without_cfg_claims(self):
        records = [
            {"rva": "0x495100", "mnemonic": "mov", "operands": "r12,rdi"},
            {"rva": "0x495108", "mnemonic": "push", "operands": "r12"},
            {"rva": "0x495110", "mnemonic": "pop", "operands": "r12"},
            {"rva": "0x495118", "mnemonic": "mov", "operands": "QWORD PTR [rbp-0x1120],r12"},
            {"rva": "0x495120", "mnemonic": "mov", "operands": "r8,r12"},
        ]
        summary = self.tool.summarize_r12_references(records)
        self.assertEqual(summary["register_reference_count"], 5)
        self.assertEqual(summary["candidate_destination_instructions"], [records[0], records[2]])
        self.assertIn("do not prove", summary["interpretation_limit"])

    def test_summarizes_filtered_branch_and_predicate_references_without_claiming_full_cfg(self):
        records = [
            {"rva": "0x495490", "mnemonic": "lea", "operands": "r10,[rbp-0x1130]"},
            {"rva": "0x4954a0", "mnemonic": "cmp", "operands": "edx,0x1f0"},
            {"rva": "0x4954a4", "mnemonic": "jne", "operands": "495520"},
            {"rva": "0x4954a6", "mnemonic": "call", "operands": "48bc40"},
        ]
        summary = self.tool.summarize_filtered_control_flow(records)
        self.assertEqual(summary["branch_instructions"], [records[2]])
        self.assertEqual(summary["predicate_candidate_instructions"], [records[1]])
        self.assertEqual(summary["call_instructions"], [records[3]])
        self.assertFalse(summary["complete_cfg"])
        self.assertIn("fallthrough", summary["interpretation_limit"])

    def test_correlates_feature_query_pointer_into_nvos54_params_on_the_observed_command_path(self):
        def ins(rva, mnemonic, operands):
            return {"rva": hex(rva), "mnemonic": mnemonic, "operands": operands}

        scan = [
            ins(0x494F72, "mov", "r12,rcx"), ins(0x494F76, "mov", "ebx,edx"),
            ins(0x494F7F, "mov", "DWORD PTR [rbp-0x1158],r8d"),
            ins(0x494F86, "cmp", "edx,0x3d02"), ins(0x494F8C, "je", "4953c0"),
            ins(0x494F92, "cmp", "edx,0x2080012e"), ins(0x494F98, "je", "495350"),
            ins(0x494F9E, "cmp", "edx,0x20803a01"), ins(0x494FA4, "je", "4950c8"),
            ins(0x494FAA, "cmp", "edx,0x3d07"), ins(0x494FB0, "je", "495600"),
            ins(0x494FB6, "cmp", "edx,0x290"), ins(0x494FBC, "je", "495588"),
            ins(0x494FC2, "cmp", "edx,0x3d04"), ins(0x494FC8, "je", "4956c8"),
            ins(0x494FCE, "cmp", "edx,0x27a"), ins(0x494FD4, "jne", "495780"),
            ins(0x49505E, "mov", "r12d,eax"), ins(0x4950B8, "pop", "r12"),
            ins(0x495729, "mov", "r12d,0xc00846da"),
            ins(0x495780, "cmp", "edx,0x278"), ins(0x495786, "jne", "4957c0"),
            ins(0x4957C0, "cmp", "edx,0x3d05"), ins(0x4957C6, "jne", "495b15"),
            ins(0x495B15, "cmp", "ebx,0x3d0a"), ins(0x495B1B, "jne", "495424"),
            ins(0x495B75, "lea", "r10,[rbp-0x1130]"),
            ins(0x49542B, "cmp", "ebx,0x3d0b"), ins(0x495431, "je", "495675"),
            ins(0x495437, "cmp", "ebx,0x3d09"), ins(0x49543D, "je", "495e62"),
            ins(0x495443, "cmp", "ebx,0xfd0104"), ins(0x495449, "je", "495b81"),
            ins(0x49544F, "cmp", "ebx,0xe00101"), ins(0x495455, "jne", "49582f"),
            ins(0x495490, "lea", "r10,[rbp-0x1130]"),
            ins(0x49567D, "lea", "r10,[rbp-0x1130]"),
            ins(0x4956AC, "mov", "r10,QWORD PTR [rbp-0x1160]"),
            ins(0x4957A6, "lea", "r10,[rbp-0x1130]"),
            ins(0x49580D, "lea", "r10,[rbp-0x1130]"),
            ins(0x49582F, "cmp", "ebx,0xd08"), ins(0x495835, "jne", "496861"),
            ins(0x496861, "lea", "r10,[rbp-0x1130]"), ins(0x496868, "jmp", "4957b7"),
            ins(0x496890, "mov", "r12d,ebx"), ins(0x496893, "and", "r12d,0xff"),
            ins(0x4957B7, "xor", "r15d,r15d"), ins(0x4957BA, "jmp", "495497"),
            ins(0x4954A2, "mov", "eax,DWORD PTR [rbp-0x1158]"),
            ins(0x4954BF, "mov", "DWORD PTR [rbp-0x1128],ebx"),
            ins(0x4954D0, "mov", "QWORD PTR [rbp-0x1120],r12"),
            ins(0x4954D7, "mov", "DWORD PTR [rbp-0x1118],eax"),
            ins(0x4954F9, "test", "eax,eax"), ins(0x4954FB, "je", "495aa8"),
        ]
        callsite = [
            ins(0x495AAE, "lea", "r9,[rbp-0x1114]"),
            ins(0x495AB5, "mov", "r8,r10"),
            ins(0x495AB8, "mov", "ecx,0xc020462a"),
            ins(0x495ABD, "mov", "edx,0x20"),
            ins(0x495AC2, "mov", "esi,0x2a"),
            ins(0x495AC7, "call", "48bc40"),
        ]
        parent = {"edx_command_candidate": "0x1f0", "r8d_size_candidate": "0x4",
                  "rcx_pointer_candidate": "[rbp-0x14]"}
        result = self.tool.summarize_feature_query_ioctl_dataflow(
            scan, callsite_instructions=callsite, parent_call_arguments=parent)
        self.assertTrue(result["path_specific_dataflow_matched"])
        self.assertEqual(result["parent_payload_pointer"], "[rbp-0x14]")
        self.assertEqual(result["nvos54_fields"]["command"]["frame_offset"], "0x8")
        self.assertTrue(result["nvos54_fields"]["params"]["source_is_parent_payload"])
        self.assertEqual(result["nvos54_fields"]["params"]["frame_offset"], "0x10")
        self.assertEqual(result["nvos54_fields"]["params_size"]["value"], "0x4")
        self.assertEqual(result["nvos54_fields"]["status"]["frame_offset"], "0x1c")
        self.assertTrue(result["r10_route_matched"])
        self.assertEqual(len(result["r10_alternate_destinations_bypassed_by_observed_transfers"]), 6)
        self.assertEqual(result["branch_route"][-1]["target_rva"], "0x495497")
        self.assertFalse(result["complete_cfg"])
        wrong_source = [*scan]
        wrong_source = [
            {**item, "operands": "QWORD PTR [rbp-0x1120],r15"}
            if item["rva"] == "0x4954d0" else item for item in wrong_source
        ]
        result = self.tool.summarize_feature_query_ioctl_dataflow(
            wrong_source, callsite_instructions=callsite, parent_call_arguments=parent)
        self.assertFalse(result["path_specific_dataflow_matched"])
        wrong_branch = [
            {**item, "operands": "4957c1"}
            if item["rva"] == "0x495786" else item for item in scan
        ]
        result = self.tool.summarize_feature_query_ioctl_dataflow(
            wrong_branch, callsite_instructions=callsite, parent_call_arguments=parent)
        self.assertFalse(result["path_specific_dataflow_matched"])
        wrong_frame_pointer = [
            {**item, "operands": "r8,r11"}
            if item["rva"] == "0x495ab5" else item for item in callsite
        ]
        result = self.tool.summarize_feature_query_ioctl_dataflow(
            scan, callsite_instructions=wrong_frame_pointer, parent_call_arguments=parent)
        self.assertFalse(result["path_specific_dataflow_matched"])

    def test_reports_candidate_ioctl_frame_offset_without_proving_reaching_pointer(self):
        records = [
            {"rva": "0x49567d", "mnemonic": "lea", "operands": "r10,[rbp-0x1130]"},
            {"rva": "0x495695", "mnemonic": "mov", "operands": "QWORD PTR [rbp-0x1160],r10"},
            {"rva": "0x495aae", "mnemonic": "lea", "operands": "r9,[rbp-0x1114]"},
            {"rva": "0x495ac7", "mnemonic": "call", "operands": "48bc40"},
        ]
        summary = self.tool.summarize_ioctl_frame_layout(
            records, callsite_instructions=[
                {"rva": "0x495ab8", "mnemonic": "mov", "operands": "ecx,0xc020462a"},
            ])
        self.assertEqual(summary["candidate_base_expression"], "rbp-0x1130")
        self.assertEqual(summary["r9_expression"], "rbp-0x1114")
        self.assertEqual(summary["r9_offset_from_candidate_base"], "0x1c")
        self.assertEqual(summary["request_code"], "0xc020462a")
        self.assertEqual(summary["request_encoded_size_bytes"], 0x20)
        self.assertTrue(summary["four_byte_local_ends_at_encoded_span_boundary"])
        self.assertFalse(summary["candidate_base_reaches_ioctl_proven"])
        self.assertIn("do not prove", summary["interpretation_limit"])

    def test_frame_layout_stays_unknown_when_either_pointer_candidate_is_absent(self):
        records = [
            {"rva": "0x495aae", "mnemonic": "lea", "operands": "r9,[rbp-0x1114]"},
        ]
        summary = self.tool.summarize_ioctl_frame_layout(records)
        self.assertIsNone(summary["r9_offset_from_candidate_base"])
        self.assertFalse(summary["four_byte_local_ends_at_encoded_span_boundary"])

    def test_validates_and_normalizes_a_pinned_remote_report(self):
        specs = (
            (0x495AA0, 0x495B20,
             "  495aae:\tlea r9,[rbp-0x1114]\n"
             "  495ab5:\tmov r8,r10\n"
             "  495ab8:\tmov ecx,0xc020462a\n"
             "  495abd:\tmov edx,0x20\n"
             "  495ac2:\tmov esi,0x2a\n"
             "  495ac7:\tcall 48bc40 <FUN_0058bc40>\n"
             "  495acc:\tmov r13d,eax\n"
             "  495acf:\tjmp 49551a\n"),
            (0x49551A, 0x49559A,
             "  49551a:\ttest r13d,r13d\n  49551d:\tje 4958e8\n"),
            (0x4958E8, 0x495968,
             "  4958e8:\tmov r8d,DWORD PTR [rbp-0x1114]\n"),
            (0x48BC40, 0x48BD43,
             "  48bc48:\tmov r14,r9\n"
             "  48bc83:\tcall 166160 <ioctl@plt>\n"
             "  48bc88:\ttest eax,eax\n  48bc8a:\tjns 48bcb8\n"
             "  48bcb8:\tcmp DWORD PTR [r14],0x3\n"),
            (0x495900, 0x495AD4,
             "  495922:\tmov eax,r13d\n"),
            (0x4600D0, 0x460110,
             "  4600d1:\tmov r8d,0x4\n"
             "  4600d7:\tmov edx,0x1f0\n"
             "  4600e3:\tlea rcx,[rbp-0x14]\n"
             "  4600f0:\tmov DWORD PTR [rbp-0x14],0x0\n"
             "  4600f7:\tcall 494f60 <FUN_00594f60>\n"
             "  4600fc:\ttest eax,eax\n"
             "  4600fe:\tjne 460109\n"
             "  460100:\ttest BYTE PTR [rbp-0x14],0x8\n"
             "  460104:\tje 460109\n"
             "  460106:\tmov BYTE PTR [rbx],0x1\n"),
            (0x495B00, 0x495B90,
             "  495b15:\tcmp ebx,0x3d0a\n"
             "  495b1b:\tjne 495424\n"
             "  495b75:\tlea r10,[rbp-0x1130]\n"),
            (0x496850, 0x4968D0,
             "  496861:\tlea r10,[rbp-0x1130]\n"
             "  496868:\tjmp 4957b7\n"
             "  496890:\tmov r12d,ebx\n"
             "  496893:\tand r12d,0xff\n"),
            (0x495DC0, 0x496040,
             "  495dd7:\tcall 48bc40\n"
             "  495ddc:\tret\n"
             "  495fb4:\ttest eax,eax\n"),
            (0x49D460, 0x49D550,
             "  49d4bd:\tcall 4600d0\n"
             "  49d4c2:\ttest eax,eax\n"),
        )
        caller_calls = {
            0x495ACC: (0x495AC7, 5, "48bc40"),
            0x477209: (0x477204, 5, "494f60"),
            0x46311C: (0x463115, 7, "QWORD PTR [r8+0x2b0]"),
            0x3248F0: (0x3248EA, 6, "QWORD PTR [rax+0x6d60]"),
            0x47D265: (0x47D260, 5, "3213b0"),
            0xF5712D: (0xF57127, 6, "QWORD PTR [rip+0x4c80923]"),
            0x2D251E: (0x2D2519, 5, "f57030"),
            0x331C32: (0x331C2D, 5, "2d1e00"),
            0x3279B0: (0x3279AA, 6, "QWORD PTR [rip+0x58a8038]"),
            0x327A70: (0x327A6A, 6, "QWORD PTR [rip+0x58a7f80]"),
            0x327B30: (0x327B2A, 6, "QWORD PTR [rip+0x58a7ec8]"),
            0x327BF0: (0x327BEA, 6, "QWORD PTR [rip+0x58a7e10]"),
            0x332226: (0x332220, 6, "QWORD PTR [rax+0x6d60]"),
            0x327CB0: (0x327CAA, 6, "QWORD PTR [rip+0x58a7d58]"),
            0x328670: (0x32866A, 6, "QWORD PTR [rip+0x58a73b0]"),
            0x328730: (0x32872A, 6, "QWORD PTR [rip+0x58a72e0]"),
            0x378290: (0x37828A, 6, "QWORD PTR [rip+0x5857788]"),
        }
        specs = (*specs, *[
            (return_rva - 0x40, return_rva + 0x10,
             f"  {caller_calls[return_rva][0]:x}:\tcall {caller_calls[return_rva][2]}\n"
             f"  {return_rva:x}:\ttest eax,eax\n")
            for return_rva in self.tool.GPU_NAME_CALLER_RETURN_RVAS
            if return_rva != self.tool.RETURN_RVA
        ])
        windows = [{"start_rva": hex(start), "stop_rva_exclusive": hex(stop),
                    "window_va_start": hex(start), "window_va_stop_exclusive": hex(stop),
                    "disassembly": text}
                   for start, stop, text in specs]
        remote = {
            "schema": "nvidia-hybrid-pc3-v100-libcuda-window-transport-v2",
            "host_kernel": "7.0.0-38-generic",
            "host_nvidia_module_version": "595.99.02",
            "host_pci_ownership": {"0000:02:00.0": "nvidia", "0000:81:00.0": "vfio-pci"},
            "guest": {
                "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
                "gpu": {"name": "Tesla V100-SXM2-16GB", "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e",
                        "pci": "0000:00:05.0", "driver_version": "580.178.04"},
                "libcuda": {"path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
                            "bytes": 96284520,
                            "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"},
                "elf_load_base": "0x0", "ghidra_image_base": "0x100000",
                "objdump_version": "GNU objdump 2.42", "windows": windows,
                "text_section": {"name": ".text", "type": "PROGBITS", "flags": "AX",
                                 "start_va": "0x1000", "size_bytes": 0xf56200,
                                 "end_va": "0xf57200"},
                "executable_sections": [
                    {"name": ".text", "type": "PROGBITS", "start_va": "0x1000",
                     "size_bytes": 0xf56200, "scanned": True},
                    {"name": ".init", "type": "PROGBITS", "start_va": "0x800",
                     "size_bytes": 0x100, "scanned": False},
                    {"name": ".plt", "type": "PROGBITS", "start_va": "0x200000",
                     "size_bytes": 0x100, "scanned": False},
                    {"name": ".plt.got", "type": "PROGBITS", "start_va": "0x200100",
                     "size_bytes": 0x100, "scanned": False},
                    {"name": ".fini", "type": "PROGBITS", "start_va": "0x200200",
                     "size_bytes": 0x100, "scanned": False},
                ],
                "caller_instruction_boundaries": [
                    {"observed_return_rva": hex(return_rva),
                     "instruction_rva": hex(caller_calls[return_rva][0]),
                     "length_bytes": caller_calls[return_rva][1],
                     "mnemonic": "call", "ends_at_return": True}
                    for return_rva in self.tool.GPU_NAME_CALLER_RETURN_RVAS
                ],
                "boundary_scan": {"section": ".text", "scanned_output_bytes": 1048576,
                                  "parsed_line_count": 200000,
                                  "stopped_after_last_return_rva": False,
                                  "completed_to_section_end": True,
                                  "first_decoded_rva": "0x1000",
                                  "last_decoded_rva": "0xf571ff",
                                  "last_instruction_length_bytes": 1,
                                  "contiguous_byte_coverage": True,
                                  "section_start_va": "0x1000",
                                  "section_end_va": "0xf57200",
                                  "covers_all_target_rvas": True,
                                  "raw_instruction_bytes_transmitted": False},
                "slot_reference_scan": {
                    "section": ".text", "scanned_output_bytes": 1048576,
                    "parsed_line_count": 200000,
                    "completed_to_section_end": True,
                    "section_start_va": "0x1000", "section_end_va": "0xf57200",
                    "raw_instruction_bytes_transmitted": False,
                    "references": [
                        {"instruction_rva": "0x2bb6c6", "length_bytes": 7,
                         "mnemonic": "lea", "operand_index": 1,
                         "operands": "r8,[rip+0x591431b]", "slot_va": "0x5bcf9e8"},
                        {"instruction_rva": "0x3279aa", "length_bytes": 6,
                         "mnemonic": "call", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x58a8038]", "slot_va": "0x5bcf9e8"},
                        {"instruction_rva": "0x327caa", "length_bytes": 6,
                         "mnemonic": "call", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x58a7d58]", "slot_va": "0x5bcfa08"},
                        {"instruction_rva": "0x3eb40a", "length_bytes": 7,
                         "mnemonic": "lea", "operand_index": 1,
                         "operands": "r8,[rip+0x57e45d7]", "slot_va": "0x5bcf9e8"},
                        {"instruction_rva": "0x3f1b01", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57ddf18]", "slot_va": "0x5bcfa20"},
                        {"instruction_rva": "0x3f1b11", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57ddf08],rdx", "slot_va": "0x5bcfa20"},
                        {"instruction_rva": "0x3f1b1d", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57ddef4]", "slot_va": "0x5bcfa18"},
                        {"instruction_rva": "0x3f1b2d", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57ddee4],rdx", "slot_va": "0x5bcfa18"},
                        {"instruction_rva": "0x3f1b39", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57dded0]", "slot_va": "0x5bcfa10"},
                        {"instruction_rva": "0x3f1b49", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57ddec0],rdx", "slot_va": "0x5bcfa10"},
                        {"instruction_rva": "0x3f1b55", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57ddeac]", "slot_va": "0x5bcfa08"},
                        {"instruction_rva": "0x3f1b65", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57dde9c],rdx", "slot_va": "0x5bcfa08"},
                        {"instruction_rva": "0x3f1b71", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57dde88]", "slot_va": "0x5bcfa00"},
                        {"instruction_rva": "0x3f1b81", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57dde78],rdx", "slot_va": "0x5bcfa00"},
                        {"instruction_rva": "0x3f1b8d", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57dde64]", "slot_va": "0x5bcf9f8"},
                        {"instruction_rva": "0x3f1b9d", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57dde54],rdx", "slot_va": "0x5bcf9f8"},
                        {"instruction_rva": "0x3f1ba9", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57dde40]", "slot_va": "0x5bcf9f0"},
                        {"instruction_rva": "0x3f1bb9", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57dde30],rdx", "slot_va": "0x5bcf9f0"},
                        {"instruction_rva": "0x3f1bc5", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 1,
                         "operands": "rdx,QWORD PTR [rip+0x57dde1c]", "slot_va": "0x5bcf9e8"},
                        {"instruction_rva": "0x3f1bd5", "length_bytes": 7,
                         "mnemonic": "mov", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x57dde0c],rdx", "slot_va": "0x5bcf9e8"},
                        {"instruction_rva": "0xf57127", "length_bytes": 6,
                         "mnemonic": "call", "operand_index": 0,
                         "operands": "QWORD PTR [rip+0x4c80923]", "slot_va": "0x5bd7a50"},
                    ],
                },
                "branch_xref_scan": {
                    "section": ".text", "scanned_output_bytes": 1048576,
                    "parsed_line_count": 200000, "completed_to_section_end": True,
                    "section_start_va": "0x1000", "section_end_va": "0xf57200",
                    "raw_instruction_bytes_transmitted": False,
                    "decoded_target_instruction_start_rvas": [
                        "0x3eb469", "0x3f1b01", "0x3f1b11", "0x3f1b1d", "0x3f1b39", "0x3f1b40",
                        "0x3f1b50", "0x3f1b55", "0x3f1b6c", "0x3f1b71", "0x3f1b88", "0x3f1b8d",
                        "0x3f1ba4", "0x3f1ba9", "0x3f1bc0", "0x3f1bc5", "0x3f1bdc",
                    ],
                    "references": [
                        {"source_rva": "0x3f1b18", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1b34", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1b50", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1b6c", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1b88", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1ba4", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1bc0", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                        {"source_rva": "0x3f1bdc", "source_length_bytes": 5,
                         "mnemonic": "jmp", "target_rva": "0x3eb469"},
                    ],
                },
                "slot_reference_contexts": [{
                    "start_rva": "0x3f1b00", "stop_rva_exclusive": "0x3f1c00",
                    "window_va_start": "0x3f1b00", "window_va_stop_exclusive": "0x3f1c00",
                    "disassembly": (
                        "  3f1b01:\tmov rdx,QWORD PTR [rip+0x57ddf18]\n"
                        "  3f1b08:\tmov QWORD PTR [r12+0x40],rdx\n"
                        "  3f1b0d:\tmov rdx,QWORD PTR [rbx+0x40]\n"
                        "  3f1b11:\tmov QWORD PTR [rip+0x57ddf08],rdx\n"
                        "  3f1b18:\tjmp 3eb469\n"
                        "  3f1b1d:\tmov rdx,QWORD PTR [rip+0x57ddef4]\n"
                        "  3f1b20:\thlt\n"
                        "  3f1b21:\tfidivr WORD PTR [rbp+0x5]\n"
                        "  3f1b24:\tmov QWORD PTR [r12+0x38],rdx\n"
                        "  3f1b29:\tmov rdx,QWORD PTR [rbx+0x38]\n"
                        "  3f1b2d:\tmov QWORD PTR [rip+0x57ddee4],rdx\n"
                        "  3f1b34:\tjmp 3eb469\n"
                        "  3f1b39:\tmov rdx,QWORD PTR [rip+0x57dded0]\n"
                        "  3f1b40:\tmov QWORD PTR [r12+0x30],rdx\n"
                        "  3f1b45:\tmov rdx,QWORD PTR [rbx+0x30]\n"
                        "  3f1b49:\tmov QWORD PTR [rip+0x57ddec0],rdx\n"
                        "  3f1b50:\tjmp 3eb469\n"
                        "  3f1b55:\tmov rdx,QWORD PTR [rip+0x57ddeac]\n"
                        "  3f1b5c:\tmov QWORD PTR [r12+0x28],rdx\n"
                        "  3f1b61:\tmov rdx,QWORD PTR [rbx+0x28]\n"
                        "  3f1b65:\tmov QWORD PTR [rip+0x57dde9c],rdx\n"
                        "  3f1b6c:\tjmp 3eb469\n"
                        "  3f1b71:\tmov rdx,QWORD PTR [rip+0x57dde88]\n"
                        "  3f1b78:\tmov QWORD PTR [r12+0x20],rdx\n"
                        "  3f1b7d:\tmov rdx,QWORD PTR [rbx+0x20]\n"
                        "  3f1b81:\tmov QWORD PTR [rip+0x57dde78],rdx\n"
                        "  3f1b88:\tjmp 3eb469\n"
                        "  3f1b8d:\tmov rdx,QWORD PTR [rip+0x57dde64]\n"
                        "  3f1b94:\tmov QWORD PTR [r12+0x18],rdx\n"
                        "  3f1b99:\tmov rdx,QWORD PTR [rbx+0x18]\n"
                        "  3f1b9d:\tmov QWORD PTR [rip+0x57dde54],rdx\n"
                        "  3f1ba4:\tjmp 3eb469\n"
                        "  3f1ba9:\tmov rdx,QWORD PTR [rip+0x57dde40]\n"
                        "  3f1bb0:\tmov QWORD PTR [r12+0x10],rdx\n"
                        "  3f1bb5:\tmov rdx,QWORD PTR [rbx+0x10]\n"
                        "  3f1bb9:\tmov QWORD PTR [rip+0x57dde30],rdx\n"
                        "  3f1bc0:\tjmp 3eb469\n"
                        "  3f1bc5:\tmov rdx,QWORD PTR [rip+0x57dde1c]\n"
                        "  3f1bcc:\tmov QWORD PTR [r12+0x8],rdx\n"
                        "  3f1bd1:\tmov rdx,QWORD PTR [rbx+0x8]\n"
                        "  3f1bd5:\tmov QWORD PTR [rip+0x57dde0c],rdx\n"
                        "  3f1bdc:\tjmp 3eb469\n")
                }, {
                    "start_rva": "0x3eb469", "stop_rva_exclusive": "0x3eb509",
                    "window_va_start": "0x3eb469", "window_va_stop_exclusive": "0x3eb509",
                    "disassembly": "  3eb469:\tret\n",
                }],
                "rip_relative_call_slots": [
                    {"call_rva": hex(call_rva), "observed_return_rva": hex(return_rva),
                     "call_length_bytes": caller_calls[return_rva][1],
                     "call_instruction": {"rva": hex(call_rva),
                                           "length_bytes": caller_calls[return_rva][1],
                                           "mnemonic": "call",
                                           "operands": caller_calls[return_rva][2]},
                     "slot_va": hex(slot_rva), "slot_rva": hex(slot_rva),
                     "sections": ([{"section_name": ".data.rel.ro",
                                   "section_type": "PROGBITS",
                                   "section_start_va": "0x5bcf000",
                                   "section_size_bytes": 0x2000}]
                                  if call_rva != 0xF57127 else
                                  [{"section_name": ".bss", "section_type": "NOBITS",
                                    "section_start_va": "0x5bd7000",
                                    "section_size_bytes": 0x1000}]),
                     "relocations": ([{"relocation_type": "R_X86_64_RELATIVE",
                                       "addend": "0x331bc0"}]
                                     if call_rva == 0x3279AA else [])}
                    for call_rva, return_rva, slot_rva in (
                        (0x3279AA, 0x3279B0, 0x5BCF9E8),
                        (0x327A6A, 0x327A70, 0x5BCF9F0),
                        (0x327B2A, 0x327B30, 0x5BCF9F8),
                        (0x327BEA, 0x327BF0, 0x5BCFA00),
                        (0x327CAA, 0x327CB0, 0x5BCFA08),
                        (0x32866A, 0x328670, 0x5BCFA20),
                        (0x32872A, 0x328730, 0x5BCFA10),
                        (0x37828A, 0x378290, 0x5BCFA18),
                        (0xF57127, 0xF5712D, 0x5BD7A50),
                    )
                ],
                "relocation_scan": {"readelf_version": "GNU readelf 2.42",
                                    "scanned_output_bytes": 1048576,
                                    "parsed_line_count": 12000,
                                    "section_table_bytes": 2048,
                                    "section_table_lines": 48,
                                    "symbol_names_transmitted": False},
                "relocation_target_code_window": {
                    "start_rva": "0x332190", "stop_rva_exclusive": "0x332240",
                    "instructions": [
                        {"rva": "0x332190", "length_bytes": 1,
                         "mnemonic": "push", "operands": "rbp"},
                        {"rva": "0x332191", "length_bytes": 3,
                         "mnemonic": "mov", "operands": "rbp,rsp"},
                        {"rva": "0x332220", "length_bytes": 6,
                         "mnemonic": "call", "operands": "QWORD PTR [rax+0x6d60]"},
                        {"rva": "0x332226", "length_bytes": 3,
                         "mnemonic": "test", "operands": "eax,eax"},
                    ],
                },
                "register_scan": {"start_rva": "0x494f60", "stop_rva_exclusive": "0x495ac7",
                                  "window_va_start": "0x494f60", "window_va_stop_exclusive": "0x495ac7",
                                  "disassembly": (
                                      "  494f72:\tmov r12,rcx\n"
                                      "  494f76:\tmov ebx,edx\n"
                                      "  494f7f:\tmov DWORD PTR [rbp-0x1158],r8d\n"
                                      "  494fce:\tcmp edx,0x27a\n"
                                      "  494fd4:\tjne 495780\n"
                                      "  49505e:\tmov r12d,eax\n"
                                      "  4950b8:\tpop r12\n"
                                      "  495729:\tmov r12d,0xc00846da\n"
                                      "  49542b:\tcmp ebx,0x3d0b\n"
                                      "  495431:\tje 495675\n"
                                      "  495437:\tcmp ebx,0x3d09\n"
                                      "  49543d:\tje 495e62\n"
                                      "  495443:\tcmp ebx,0xfd0104\n"
                                      "  495449:\tje 495b81\n"
                                      "  49544f:\tcmp ebx,0xe00101\n"
                                      "  495455:\tjne 49582f\n"
                                      "  495780:\tcmp edx,0x278\n"
                                      "  495786:\tjne 4957c0\n"
                                      "  4957c0:\tcmp edx,0x3d05\n"
                                      "  4957c6:\tjne 495b15\n"
                                      "  49582f:\tcmp ebx,0xd08\n"
                                      "  495835:\tjne 496861\n"
                                      "  4957b7:\txor r15d,r15d\n"
                                      "  4957ba:\tjmp 495497\n"
                                      "  4954a2:\tmov eax,DWORD PTR [rbp-0x1158]\n"
                                      "  4954bf:\tmov DWORD PTR [rbp-0x1128],ebx\n"
                                      "  4954d0:\tmov QWORD PTR [rbp-0x1120],r12\n"
                                      "  4954d7:\tmov DWORD PTR [rbp-0x1118],eax\n"
                                      "  4954f9:\ttest eax,eax\n"
                                      "  4954fb:\tje 495aa8\n"
                                      "  495513:\tcall rax\n"
                                      "  495490:\tlea r10,[rbp-0x1130]\n"
                                      "  49567d:\tlea r10,[rbp-0x1130]\n"
                                      "  4956ac:\tmov r10,QWORD PTR [rbp-0x1160]\n"
                                      "  4957a6:\tlea r10,[rbp-0x1130]\n"
                                      "  49580d:\tlea r10,[rbp-0x1130]\n"
                                      "  495aae:\tlea r9,[rbp-0x1114]\n"
                                      "  495ab5:\tmov r8,r10\n")},
            },
        }
        report = self.tool.validate_remote_payload(remote)
        caller_sites = report["runtime_caller_trace"]["return_site_windows"]
        self.assertEqual(len(caller_sites), len(self.tool.GPU_NAME_CALLER_RETURN_RVAS))
        self.assertEqual([int(item["observed_return_rva"], 16) for item in caller_sites],
                         list(self.tool.GPU_NAME_CALLER_RETURN_RVAS))
        self.assertTrue(all(item["instruction_at_return"] is not None
                            for item in caller_sites))
        self.assertTrue(all(item["previous_instruction_is_call"]
                            for item in caller_sites))
        self.assertTrue(all(item["previous_instruction_boundary_verified"]
                            for item in caller_sites))
        self.assertEqual([item["previous_instruction_length_bytes"] for item in caller_sites],
                         [caller_calls[rva][1]
                          for rva in self.tool.GPU_NAME_CALLER_RETURN_RVAS])
        self.assertEqual(report["runtime_caller_trace"]["static_predecessor_summary"], {
            "return_sites_with_decoded_instruction": 11,
            "return_sites_preceded_by_call": 11,
            "direct_predecessor_calls": 5,
            "indirect_predecessor_calls": 6,
            "call_instruction_boundaries_verified": 11,
        })
        self.assertFalse(report["runtime_caller_trace"]["instruction_boundary_scan"][
            "raw_instruction_bytes_transmitted"])
        slot_report = report["runtime_caller_trace"]["rip_relative_dispatch_slots"]
        self.assertEqual([item["slot_rva"] for item in slot_report["slots"]],
                         ["0x5bcf9e8", "0x5bcf9f0", "0x5bcf9f8", "0x5bcfa00",
                          "0x5bcfa08", "0x5bcfa20", "0x5bcfa10", "0x5bcfa18", "0x5bd7a50"])
        self.assertEqual([item["call_rva"] for item in slot_report["slots"]],
                         ["0x3279aa", "0x327a6a", "0x327b2a", "0x327bea",
                          "0x327caa", "0x32866a", "0x32872a", "0x37828a", "0xf57127"])
        self.assertTrue(all(item["call_instruction"]["mnemonic"] == "call" and
                            item["call_instruction"]["operands"].startswith("QWORD PTR [rip+")
                            for item in slot_report["slots"]))
        self.assertEqual(slot_report["slots"][0]["relocations"],
                         [{"relocation_type": "R_X86_64_RELATIVE", "addend": "0x331bc0"}])
        self.assertEqual(slot_report["slots"][8]["sections"][0]["section_type"], "NOBITS")
        self.assertTrue(slot_report["direct_rip_reference_scan"]["completed_to_section_end"])
        self.assertEqual(slot_report["direct_rip_reference_scan"]["unscanned_executable_sections"],
                         [".init", ".plt", ".plt.got", ".fini"])
        references = slot_report["direct_rip_reference_scan"]["references"]
        stores = [item for item in references if item["static_access_class"] == "direct-write"]
        self.assertEqual([(item["instruction_rva"], item["slot_va"]) for item in stores],
                         [("0x3f1b11", "0x5bcfa20"), ("0x3f1b2d", "0x5bcfa18"),
                          ("0x3f1b49", "0x5bcfa10"), ("0x3f1b65", "0x5bcfa08"),
                          ("0x3f1b81", "0x5bcfa00"), ("0x3f1b9d", "0x5bcf9f8"),
                          ("0x3f1bb9", "0x5bcf9f0"), ("0x3f1bd5", "0x5bcf9e8")])
        contexts = slot_report["direct_rip_reference_scan"]["write_context_windows"]
        self.assertEqual(len(contexts), 2)
        self.assertEqual(contexts[1]["instructions"][0]["rva"], "0x3eb469")
        self.assertEqual([item["rva"] for item in contexts[0]["instructions"]
                          if item["rva"] in ("0x3f1b01", "0x3f1b08", "0x3f1b0d", "0x3f1b11",
                                             "0x3f1b1d", "0x3f1b2d", "0x3f1b39", "0x3f1b49",
                                             "0x3f1b55", "0x3f1b65", "0x3f1b71", "0x3f1b81",
                                             "0x3f1b8d", "0x3f1b9d", "0x3f1ba9", "0x3f1bb9",
                                             "0x3f1bc5", "0x3f1bd5")],
                         ["0x3f1b01", "0x3f1b08", "0x3f1b0d", "0x3f1b11", "0x3f1b1d",
                          "0x3f1b2d", "0x3f1b39", "0x3f1b49", "0x3f1b55", "0x3f1b65",
                          "0x3f1b71", "0x3f1b81", "0x3f1b8d", "0x3f1b9d", "0x3f1ba9",
                          "0x3f1bb9", "0x3f1bc5", "0x3f1bd5"])
        self.assertEqual([item["rva"] for item in
                          slot_report["direct_rip_reference_scan"]["same_slot_read_store_contexts"][0][
                              "intervening_instructions"]], ["0x3f1b5c", "0x3f1b61"])
        self.assertEqual(slot_report["direct_rip_reference_scan"]["same_slot_read_store_contexts"][0][
            "source_register_reaching_definition"], "not established")
        same_slot = slot_report["direct_rip_reference_scan"]["same_slot_read_store_contexts"]
        slot10_pair = next(item for item in same_slot
                           if item["store_instruction"]["rva"] == "0x3f1b49")
        self.assertEqual(slot10_pair["read_instruction"]["rva"], "0x3f1b39")
        slot18_pair = next(item for item in same_slot
                           if item["store_instruction"]["rva"] == "0x3f1b11")
        self.assertEqual(slot18_pair["read_instruction"]["rva"], "0x3f1b01")
        slot00_pair = next(item for item in same_slot
                           if item["store_instruction"]["rva"] == "0x3f1b81")
        self.assertEqual(slot00_pair["read_instruction"]["rva"], "0x3f1b71")
        slotf8_pair = next(item for item in same_slot
                           if item["store_instruction"]["rva"] == "0x3f1b9d")
        self.assertEqual(slotf8_pair["read_instruction"]["rva"], "0x3f1b8d")
        slotf0_pair = next(item for item in same_slot
                           if item["store_instruction"]["rva"] == "0x3f1bb9")
        self.assertEqual(slotf0_pair["read_instruction"]["rva"], "0x3f1ba9")
        branch_report = slot_report["direct_rip_reference_scan"]["direct_branch_xref_scan"]
        self.assertEqual(branch_report["reference_count"], 8)
        self.assertEqual([item["source_rva"] for item in branch_report["references"]],
                         ["0x3f1b18", "0x3f1b34", "0x3f1b50", "0x3f1b6c", "0x3f1b88", "0x3f1ba4",
                          "0x3f1bc0", "0x3f1bdc"])
        self.assertTrue(all(item["target_rva"] == "0x3eb469" and
                            item["target_instruction_start_verified"]
                            for item in branch_report["references"]))
        self.assertNotIn("0x3f1b39", [item["target_rva"] for item in branch_report["references"]])
        self.assertNotIn("0x3f1b11", [item["target_rva"] for item in branch_report["references"]])
        self.assertNotIn("0x3f1b40", [item["target_rva"] for item in branch_report["references"]])
        self.assertTrue(all(entry not in [item["target_rva"] for item in branch_report["references"]]
                            for entry in ("0x3f1b01", "0x3f1b1d", "0x3f1b39", "0x3f1b55",
                                          "0x3f1b71", "0x3f1b8d", "0x3f1ba9", "0x3f1bc5")))
        bad_branch_guest = dict(remote["guest"])
        bad_branch_guest["branch_xref_scan"] = {
            **remote["guest"]["branch_xref_scan"],
            "references": [dict(remote["guest"]["branch_xref_scan"]["references"][0],
                                target_rva="0x3f2000")],
            "decoded_target_instruction_start_rvas": [],
        }
        with self.assertRaisesRegex(ValueError, "target scope"):
            self.tool.validate_remote_payload(dict(remote, guest=bad_branch_guest))
        bad_guest = dict(remote["guest"])
        bad_scan = dict(bad_guest["slot_reference_scan"])
        bad_scan["references"] = [dict(bad_scan["references"][0], slot_va="0x5bd7a58")]
        bad_guest["slot_reference_scan"] = bad_scan
        bad_remote = dict(remote, guest=bad_guest)
        with self.assertRaisesRegex(ValueError, "RIP-relative slot reference"):
            self.tool.validate_remote_payload(bad_remote)
        bad_context_guest = dict(remote["guest"])
        bad_context_guest["slot_reference_contexts"] = [{
            **remote["guest"]["slot_reference_contexts"][0],
            "disassembly": (
                "  3f1b55:\tmov rdx,QWORD PTR [rip+0x57ddeac]\n"
                "  3f1b5c:\tmov QWORD PTR [r12+0x28],rdx\n"
                "  3f1b61:\tmov rdx,QWORD PTR [rbx+0x28]\n"
                "  3f1b65:\tmov QWORD PTR [rip+0x57dde94],rdx\n"
                "  3f1bc5:\tmov rdx,QWORD PTR [rip+0x57dde1c]\n"
                "  3f1bcc:\tmov QWORD PTR [r12+0x8],rdx\n"
                "  3f1bd1:\tmov rdx,QWORD PTR [rbx+0x8]\n"
                "  3f1bd5:\tmov QWORD PTR [rip+0x57dde0c],rdx\n")
        }, remote["guest"]["slot_reference_contexts"][1]]
        with self.assertRaisesRegex(ValueError, "bounded slot-reference instruction"):
            self.tool.validate_remote_payload(dict(remote, guest=bad_context_guest))
        reference_context_guest = dict(remote["guest"])
        reference_context_guest["slot_reference_contexts"] = [{
            **remote["guest"]["slot_reference_contexts"][0],
            "disassembly": remote["guest"]["slot_reference_contexts"][0]["disassembly"].replace(
                "0x57ddee4", "0x57ddee3", 1),
        }, remote["guest"]["slot_reference_contexts"][1]]
        with self.assertRaisesRegex(ValueError, "bounded slot-reference instruction"):
            self.tool.validate_remote_payload(dict(remote, guest=reference_context_guest))
        self.assertEqual(slot_report["relocation_target_code"]["instruction_at_candidate_target"],
                         {"rva": "0x332190", "mnemonic": "push", "operands": "rbp"})
        self.assertTrue(slot_report["relocation_target_code"][
            "candidate_and_frame_return_share_bounded_code_window"])
        self.assertEqual(report["runtime_caller_trace"]["sha256"],
                         self.tool.GPU_NAME_CALLER_TRACE_SHA256)
        self.assertEqual(report["control_flow"]["handoff_target_rva"], "0x49551a")
        self.assertEqual(report["ioctl_wrapper"]["nonnegative_status_branch_target_rva"], "0x48bcb8")
        self.assertTrue(report["parent_call_edge"]["call_target_matches_expected"])
        self.assertEqual(report["parent_call_edge"]["call_target_rva"], "0x494f60")
        self.assertTrue(report["parent_call_arguments"]["single_linear_pre_call_block"])
        self.assertEqual(report["parent_call_arguments"]["edx_command_candidate"], "0x1f0")
        self.assertEqual(report["parent_call_arguments"]["rcx_pointer_candidate"], "[rbp-0x14]")
        self.assertTrue(report["parent_call_arguments"]["zeroed_dword_matches_rcx_pointer"])
        self.assertTrue(report["parent_feature_bit_consumer"]["pattern_matched"])
        self.assertEqual(report["parent_feature_bit_consumer"]["tested_bit_value"], "0x8")
        self.assertTrue(report["parent_feature_bit_consumer"]["requires_zero_call_result"])
        self.assertEqual(report["r10_register_flow"]["register_reference_count"], 6)
        self.assertGreaterEqual(report["r12_register_flow"]["register_reference_count"], 4)
        self.assertIn("0x494f72", [item["rva"] for item in
                                    report["r12_register_flow"]["candidate_destination_instructions"]])
        self.assertEqual(report["filtered_control_flow"]["branch_instructions"][0]["rva"], "0x494fd4")
        self.assertEqual(report["filtered_control_flow"]["call_instructions"][0]["rva"], "0x495513")
        self.assertFalse(report["filtered_control_flow"]["complete_cfg"])
        self.assertEqual(report["feature_dispatch_followup_instructions"][0]["rva"], "0x495b15")
        self.assertEqual(report["general_command_target_instructions"][0]["rva"], "0x496861")
        self.assertEqual(report["nonzero_helper_path_instructions"][0]["rva"], "0x495dd7")
        self.assertEqual(report["feature_flag_parent_call_instructions"][0]["rva"], "0x49d4bd")
        self.assertEqual(report["ioctl_frame_layout"]["r9_offset_from_candidate_base"], "0x1c")
        self.assertEqual(report["ioctl_frame_layout"]["request_encoded_size_bytes"], 0x20)
        self.assertTrue(report["ioctl_frame_layout"]["four_byte_local_ends_at_encoded_span_boundary"])
        self.assertFalse(report["ioctl_frame_layout"]["candidate_base_reaches_ioctl_proven"])
        self.assertTrue(report["feature_query_ioctl_dataflow"]["path_specific_dataflow_matched"])
        self.assertEqual(report["feature_query_ioctl_dataflow"]["nvos54_fields"]["params"]["frame_offset"], "0x10")
        self.assertTrue(report["feature_query_ioctl_dataflow"]["r10_route_matched"])
        self.assertNotIn("FUN_0058bc40", str(report))
        self.assertNotIn("pseudocode", report)
        gapped_boundary = copy.deepcopy(remote)
        gapped_boundary["guest"]["caller_instruction_boundaries"][0]["length_bytes"] = 4
        with self.assertRaisesRegex(ValueError, "does not end at the observed return"):
            self.tool.validate_remote_payload(gapped_boundary)
        misidentified_call = copy.deepcopy(remote)
        misidentified_call["guest"]["caller_instruction_boundaries"][0].update(
            {"instruction_rva": "0x495ac6", "length_bytes": 6})
        with self.assertRaisesRegex(ValueError, "decoded call predecessor disagrees"):
            self.tool.validate_remote_payload(misidentified_call)
        wrong_slot = copy.deepcopy(remote)
        wrong_slot["guest"]["rip_relative_call_slots"][0].update(
            {"slot_va": "0x5bcf9e9", "slot_rva": "0x5bcf9e9"})
        with self.assertRaisesRegex(ValueError, "does not match the observed RIP-relative operand"):
            self.tool.validate_remote_payload(wrong_slot)
        wrong_call_instruction = copy.deepcopy(remote)
        wrong_call_instruction["guest"]["rip_relative_call_slots"][0][
            "call_instruction"]["operands"] = "QWORD PTR [rip+0x58a8039]"
        with self.assertRaisesRegex(ValueError, "does not match the observed RIP-relative operand"):
            self.tool.validate_remote_payload(wrong_call_instruction)
        non_indirect_call = copy.deepcopy(remote)
        non_indirect_call["guest"]["rip_relative_call_slots"][0][
            "call_instruction"]["mnemonic"] = "jmp"
        with self.assertRaisesRegex(ValueError, "identity or length changed"):
            self.tool.validate_remote_payload(non_indirect_call)
        wrong_control = copy.deepcopy(remote)
        wrong_control["guest"]["rip_relative_call_slots"][0]["relocations"][0]["addend"] = "0x331bd0"
        with self.assertRaisesRegex(ValueError, "known Ghidra relocation control"):
            self.tool.validate_remote_payload(wrong_control)
        wrong_section = copy.deepcopy(remote)
        wrong_section["guest"]["rip_relative_call_slots"][8]["sections"][0][
            "section_start_va"] = "0x5bd8000"
        with self.assertRaisesRegex(ValueError, "does not lie within its reported ELF section"):
            self.tool.validate_remote_payload(wrong_section)
        changed_call = copy.deepcopy(remote)
        changed_call["guest"]["windows"][5]["disassembly"] = (
            "  4600d1:\tmov r8d,0x4\n"
            "  4600d7:\tmov edx,0x1f1\n"
            "  4600e3:\tlea rcx,[rbp-0x14]\n"
            "  4600f0:\tmov DWORD PTR [rbp-0x14],0x0\n"
            "  4600f7:\tcall 494f60\n")
        with self.assertRaisesRegex(ValueError, "feature-query argument pattern"):
            self.tool.validate_remote_payload(changed_call)
        remote["host_nvidia_module_version"] = "unverified"
        with self.assertRaisesRegex(ValueError, "host identity"):
            self.tool.validate_remote_payload(remote)


if __name__ == "__main__":
    unittest.main()
