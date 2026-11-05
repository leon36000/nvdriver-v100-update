# SPDX-License-Identifier: MIT
import unittest

try:
    import tools.audit_r580_lookup_branch as lookup_branch_audit
    from tools.audit_r580_lookup_branch import (
        classify_callsite_arguments,
        classify_capture_report,
        validate_lookup_branch_disassembly,
    )
except ModuleNotFoundError:
    lookup_branch_audit = None
    classify_callsite_arguments = None
    validate_lookup_branch_disassembly = None


DISASSEMBLY = """\
000000000003c100 <_nv031364rm>:
   3cb0a: e8 00 00 00 00       call   3cb0f <_nv031364rm+0xa0f>
                        3cb0b: R_X86_64_PC32 _nv049612rm-0x4
   3cb1a: 41 89 c6             mov    r14d,eax
   3cb75: 44 89 f0             mov    eax,r14d
   3cb78: c1 e8 18             shr    eax,0x18
   3cb7b: 83 e0 3f             and    eax,0x3f
   3cb7e: 83 f8 15             cmp    eax,0x15
   3cb81: 0f 86 f7 02 00 00    jbe    3ce7e <_nv031364rm+0xd7e>
   3ce7e: 31 c0                xor    eax,eax
   3ce80: be 00 00 6b 05       mov    esi,0x56b0000
   3ce85: bf f1 b2 3b 0e       mov    edi,0xe3bb2f1
   3ce90: 45 31 ff             xor    r15d,r15d
   3ce93: e8 00 00 00 00       call   3ce98 <_nv031364rm+0xd98>
                        3ce94: R_X86_64_PC32 _nv047869rm-0x4
   3cead: e9 da f2 ff ff       jmp    3c18c <_nv031364rm+0x8c>
   3c18c: 44 89 fe             mov    esi,r15d
   3c18f: 44 89 f7             mov    edi,r14d
   3c192: e8 00 00 00 00       call   3c197 <_nv031364rm+0x97>
                        3c193: R_X86_64_PC32 _nv031399rm-0x4
   3c41d: 31 d2                xor    edx,edx
   3c41f: e9 68 fd ff ff       jmp    3c18c <_nv031364rm+0x8c>
   3cac1: 31 d2                xor    edx,edx
   3cac3: e9 c4 f6 ff ff       jmp    3c18c <_nv031364rm+0x8c>
   3cb92: 29 c8                sub    eax,ecx
   3cb94: 89 45 08             mov    DWORD PTR [rbp+0x8],eax
   3cb97: e9 f0 f5 ff ff       jmp    3c18c <_nv031364rm+0x8c>
   3cbaa: 89 45 08             mov    DWORD PTR [rbp+0x8],eax
   3cbad: e9 da f5 ff ff       jmp    3c18c <_nv031364rm+0x8c>
   3ceaa: 89 45 08             mov    DWORD PTR [rbp+0x8],eax
"""

DISASSEMBLY += """\
   3c3e0: 80 7b 60 00          cmp    BYTE PTR [rbx+0x60],0x0
   3c3e4: 0f 84 e6 06 00 00    je     3cad0 <_nv031364rm+0x9d0>
   3c3ea: 44 8b bb 70 0f 00 00 mov    r15d,DWORD PTR [rbx+0xf70]
   3c3f1: 80 bb 78 0f 00 00 00 cmp    BYTE PTR [rbx+0xf78],0x0
   3c3fc: 0f 84 15 08 00 00    je     3cc17 <_nv031364rm+0xb17>
   3c402: be 00 00 6b 05       mov    esi,0x56b0000
   3c407: bf f1 b2 3b 0e       mov    edi,0xe3bb2f1
   3c40c: 31 c0                xor    eax,eax
   3c40e: 45 31 f6             xor    r14d,r14d
   3c411: e8 00 00 00 00       call   3c416 <_nv031364rm+0x316>
   3c416: c7 45 08 03 00 00 00 mov    DWORD PTR [rbp+0x8],0x3
   3caa0: 80 bb 78 0f 00 00 00 cmp    BYTE PTR [rbx+0xf78],0x0
   3caa7: 44 8b bb c8 12 00 00 mov    r15d,DWORD PTR [rbx+0x12c8]
   3cab1: 0f 85 4b f9 ff ff    jne    3c402 <_nv031364rm+0x302>
   3cab7: c7 45 08 03 00 00 00 mov    DWORD PTR [rbp+0x8],0x3
   3cabe: 45 31 f6             xor    r14d,r14d
   3cb65: 31 d2                xor    edx,edx
   3cb67: 85 f6                test   esi,esi
   3cb69: 0f 95 c2             setne  dl
   3cb6c: 80 bb 78 0f 00 00 00 cmp    BYTE PTR [rbx+0xf78],0x0
   3cb73: 74 27                je     3cb9c <_nv031364rm+0xa9c>
   3cb87: 0f b6 c9             movzx  ecx,cl
   3cb8a: b8 02 00 00 00       mov    eax,0x2
   3cb8f: 45 31 ff             xor    r15d,r15d
   3cb9c: 45 31 ff             xor    r15d,r15d
   3cb9f: 80 f9 01             cmp    cl,0x1
   3cba2: 19 c0                sbb    eax,eax
   3cba4: 83 e0 02             and    eax,0x2
   3cba7: 83 c0 01             add    eax,0x1
   3ce8a: 89 55 10             mov    DWORD PTR [rbp+0x10],edx
   3ce8d: 88 4d 08             mov    BYTE PTR [rbp+0x8],cl
   3ce98: 0f b6 4d 08          movzx  ecx,BYTE PTR [rbp+0x8]
   3ce9c: 8b 55 10             mov    edx,DWORD PTR [rbp+0x10]
   3ce9f: 80 f9 01             cmp    cl,0x1
   3cea2: 19 c0                sbb    eax,eax
   3cea4: 83 e0 02             and    eax,0x2
   3cea7: 83 c0 01             add    eax,0x1
"""


class R580LookupBranchAuditTests(unittest.TestCase):
    def test_reads_v7_schema_from_transport_payload_and_omits_raw_arguments(self):
        report = {
            "schema": "nvidia-hybrid-pc3-r580-direct-kprobe-canary-transport-v1",
            "status": "active_lookup_callsite_capture_passed",
            "remote": {
                "schema": "nvidia-hybrid-pc3-r580-direct-kprobe-canary-v7",
                "status": "active_lookup_callsite_capture_passed",
                "active_registration": {
                    "passed": True,
                    "lookup_callsite_capture_passed": True,
                    "lookup_hits_delta": 1,
                    "lookup_callsite_dropped_before": 0,
                    "lookup_callsite_dropped_after_trigger": 0,
                    "lookup_callsite_observation_before": "0000000000000000 unavailable",
                    "lookup_callsite_observation_after_trigger": "0000000000000001 14000000 00000000 00000000",
                },
            },
        }
        result = classify_capture_report(report)
        self.assertTrue(result["compatible_with_candidate_branch"])
        self.assertNotIn("first_argument", result)
        self.assertNotIn("raw", result)

    def test_proves_candidate_helper_to_lookup_route_and_zero_selector(self):
        self.assertTrue(callable(validate_lookup_branch_disassembly),
                        "lookup-branch auditor has not been implemented")
        result = validate_lookup_branch_disassembly(DISASSEMBLY)
        self.assertEqual(result["helper_call_offset"], 0xA0A)
        self.assertEqual(result["argument_zero_definition_offset"], 0xA1A)
        self.assertEqual(result["dispatch_branch_offset"], 0xA75)
        self.assertEqual(result["dispatch_branch_target_offset"], 0xD7E)
        self.assertEqual(result["zero_selector_offset"], 0xD90)
        self.assertEqual(result["lookup_call_offset"], 0x92)
        self.assertEqual(
            [(entry["jump_offset"], entry["probe_offset"])
             for entry in result["lookup_join_predecessors"]],
            [(0x31F, 0x31D), (0x9C3, 0x9C1), (0xA97, 0xA94),
             (0xAAD, 0xAAA), (0xDAD, 0xDAA)],
        )
        self.assertTrue(result["helper_return_flows_to_first_lookup_argument"])
        self.assertTrue(result["branch_clears_second_lookup_argument"])
        self.assertNotIn("raw", result)

    def test_reports_all_five_join_route_arguments_and_gates(self):
        result = validate_lookup_branch_disassembly(DISASSEMBLY)
        self.assertEqual(result["lookup_join_routes"], [
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
        ])
        self.assertNotIn("raw", result)

    def test_static_join_report_cannot_claim_runtime_or_hardware_validation(self):
        self.assertTrue(callable(getattr(lookup_branch_audit,
                                         "build_static_join_report", None)))
        static_route = validate_lookup_branch_disassembly(DISASSEMBLY)
        report = lookup_branch_audit.build_static_join_report(
            lookup_branch_audit.EXPECTED_OBJECT_SHA256, static_route
        )
        self.assertEqual(report["schema"], "rea-r580-lookup-join-inputs-v1")
        self.assertEqual(report["status"], "static_join_routes_mapped")
        self.assertEqual(report["inputs"]["rm_object_sha256"],
                         lookup_branch_audit.EXPECTED_OBJECT_SHA256)
        self.assertEqual(len(report["static_route"]["lookup_join_routes"]), 5)
        self.assertNotIn("runtime_predicates", report)
        self.assertEqual(report["qualification"], "analyzed_statically")

    def test_static_report_rejects_malformed_route_entries(self):
        with self.assertRaisesRegex(ValueError, "all five validated join paths"):
            lookup_branch_audit.build_static_join_report(
                lookup_branch_audit.EXPECTED_OBJECT_SHA256,
                {"lookup_join_routes": ["not-a-route"]},
            )

    def test_rejects_changed_join_route_gate_or_argument_source(self):
        changed_gate = DISASSEMBLY.replace(
            "3cb73: 74 27                je     3cb9c <_nv031364rm+0xa9c>",
            "3cb73: 75 27                jne    3cb9c <_nv031364rm+0xa9c>",
        )
        with self.assertRaisesRegex(ValueError, "unexpected instruction"):
            validate_lookup_branch_disassembly(changed_gate)

        changed_source = DISASSEMBLY.replace(
            "3c3ea: 44 8b bb 70 0f 00 00 mov    r15d,DWORD PTR [rbx+0xf70]",
            "3c3ea: 44 8b bb 78 0f 00 00 mov    r15d,DWORD PTR [rbx+0xf78]",
        )
        with self.assertRaisesRegex(ValueError, "unexpected instruction"):
            validate_lookup_branch_disassembly(changed_source)

    def test_rejects_wrong_branch_destination(self):
        changed = DISASSEMBLY.replace("jbe    3ce7e", "jbe    3ce80")
        with self.assertRaisesRegex(ValueError, "unexpected instruction"):
            validate_lookup_branch_disassembly(changed)

    def test_rejects_nonzeroed_selector_path(self):
        changed = DISASSEMBLY.replace("xor    r15d,r15d", "mov    r15d,eax")
        with self.assertRaisesRegex(ValueError, "unexpected instruction"):
            validate_lookup_branch_disassembly(changed)

    def test_rejects_a_wrong_lookup_join_edge_or_probe_instruction(self):
        changed_edge = DISASSEMBLY.replace(
            "3cead: e9 da f2 ff ff       jmp    3c18c <_nv031364rm+0x8c>",
            "3cead: e9 de f2 ff ff       jmp    3c190 <_nv031364rm+0x90>", 1,
        )
        with self.assertRaisesRegex(ValueError, "unexpected instruction"):
            validate_lookup_branch_disassembly(changed_edge)
        changed_probe = DISASSEMBLY.replace(
            "3cb94: 89 45 08             mov    DWORD PTR [rbp+0x8],eax",
            "3cb94: 89 45 08             nop",
        )
        with self.assertRaisesRegex(ValueError, "unexpected instruction"):
            validate_lookup_branch_disassembly(changed_probe)

    def test_classifies_only_a_nonzero_helper_value_with_zero_selector(self):
        result = classify_callsite_arguments(0x140A1000, 0, 0)
        self.assertTrue(result["first_argument_nonzero"])
        self.assertTrue(result["second_argument_zero"])
        self.assertTrue(result["high_six_bits_within_dispatch_limit"])
        self.assertTrue(result["compatible_with_candidate_branch"])
        self.assertNotIn("first_argument", result)
        self.assertNotIn("raw", result)

    def test_rejects_values_that_do_not_fit_the_candidate_branch(self):
        result = classify_callsite_arguments(0x160A1000, 0, 0)
        self.assertFalse(result["high_six_bits_within_dispatch_limit"])
        self.assertFalse(result["compatible_with_candidate_branch"])
        self.assertFalse(classify_callsite_arguments(0, 0, 0)["compatible_with_candidate_branch"])
        self.assertFalse(classify_callsite_arguments(0x140A1000, 1, 0)["compatible_with_candidate_branch"])


if __name__ == "__main__":
    unittest.main()
