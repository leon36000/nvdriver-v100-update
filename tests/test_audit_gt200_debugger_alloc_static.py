# SPDX-License-Identifier: MIT
"""Regression checks for the pinned GT200_DEBUGGER static allocation audit."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "gt200_debugger_static_audit", ROOT / "tools/audit_gt200_debugger_alloc_static.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class Gt200DebuggerStaticAuditTests(unittest.TestCase):
    def test_pinned_binaries_source_and_capture_correlate_without_runtime_claim(self):
        report = AUDIT.audit()
        self.assertEqual(report["schema"], "gt200-debugger-allocation-static-audit-v7")
        self.assertEqual(report["qualification"],
                         "static-binary-and-open-source-correlation-only")
        self.assertEqual(set(report["libraries"]), {"580.178.04", "595.99.02"})
        self.assertEqual(set(report["source_branches"]),
                         {"580.178.04", "580.196.07", "595.99.02", "615.71.10"})
        route = report["debugger_control_route"]
        self.assertEqual(route["qualification"], "static-open-source-control-flow-only")
        self.assertEqual(set(route["branches"]), set(report["source_branches"]))
        self.assertIn("NV01_NULL_OBJECT (zero)", route["interpretation"]["conditional_route"])
        self.assertIn("does not show", route["interpretation"]["not_established"])
        self.assertIn("byte-identical", route["interpretation"]["portability"])
        for branch in route["branches"].values():
            self.assertTrue(branch["debugger_forward_uses_null_object_handle"])
            self.assertTrue(branch["gpu_fast_path_requires_internal_client_and_subdevice_pair"])
            self.assertTrue(branch["fallback_preserves_requested_client_and_object_handles"])
            self.assertTrue(branch["resource_server_looks_up_hObject_in_client_map"])
            self.assertTrue(branch["zero_handle_rejected_for_standard_resource_allocation"])
        self.assertFalse(route["runtime_or_hardware_validated"])
        self.assertFalse(route["gpu_accessed_by_this_audit"])
        self.assertEqual(set(report["trace_observations"]), {"v100", "rtx5080"})
        self.assertEqual(set(report["channel_ancestry"]), set(report["source_branches"]))
        self.assertEqual(set(report["build_gates"]), set(report["source_branches"]))
        expected_gates = {
            "RMCFG_CHIP_GV100": 0,
            "RMCFG_CLASS_VOLTA_CHANNEL_GPFIFO_A": 1,
            "RMCFG_CLASS_VOLTA_USERMODE_A": 1,
            "RMCFG_CLASS_VOLTA_COMPUTE_A": 0,
            "RMCFG_CLASS_BLACKWELL_COMPUTE_B": 1,
        }
        for gates in report["build_gates"].values():
            self.assertEqual(gates["macros"], expected_gates)
        for branch in report["channel_ancestry"].values():
            self.assertEqual(branch["VOLTA_CHANNEL_GPFIFO_A"]["class_id"], "0xc36f")
            self.assertEqual(branch["BLACKWELL_CHANNEL_GPFIFO_A"]["class_id"], "0xc96f")
            self.assertEqual(branch["BLACKWELL_COMPUTE_B"]["class_id"], "0xcec0")
            self.assertEqual(branch["BLACKWELL_COMPUTE_B"]["internal_class"],
                             "KernelGraphicsObject")
            self.assertEqual(branch["BLACKWELL_COMPUTE_B"]["parents"], ["KernelChannel"])
            self.assertTrue(branch["BLACKWELL_CHANNEL_GPFIFO_A"][
                "required_channel_alloc_params"])
        expected_resource_entry = "59c50239f2437ae512846c8a03ebbcfde7f7d3dfdf9b7cd3a2b0810b50aac537"
        for branch in report["source_branches"].values():
            self.assertEqual(branch["gt200_debugger_resource_entry_sha256"],
                             expected_resource_entry)
            self.assertEqual(branch["class_registration"], {
                "internal_class": "KernelSMDebuggerSession",
                "multi_instance": True,
                "parent_external_class": "NV01_DEVICE_0",
                "allocation_parameters": "NV83DE_ALLOC_PARAMETERS",
                "dual_client_lock": True,
            })
            constructor = branch["debugger_constructor"]
            self.assertTrue(constructor["debuggee_object_resolved_within_app_client"])
            self.assertTrue(constructor["debuggee_must_be_kernel_graphics_object"])
            self.assertEqual(constructor["permission_paths"],
                             ["matching-security-token", "RS_ACCESS_DEBUG"])
            self.assertTrue(constructor["debugger_and_debuggee_gpu_equality_checked"])
            self.assertTrue(constructor["debugger_session_registered_to_debuggee_graphics_context"])
        cleanup_by_version = {
            version: branch["debugger_constructor"]["constructor_failure_cleanup"]
            for version, branch in report["source_branches"].items()
        }
        self.assertEqual(cleanup_by_version, {
            "580.178.04": False,
            "580.196.07": True,
            "595.99.02": False,
            "615.71.10": False,
        })
        for role in report["trace_observations"].values():
            self.assertEqual(role["class_id"], "0x83de")
            self.assertEqual(role["parent_class_id"], "0x80")
            self.assertFalse(role["nested_payload_observed"])
        expected_outer_offsets = {
            "hRoot": 0, "hObjectParent": 4, "hObjectNew": 8, "hClass": 12,
            "pAllocParms": 16, "pRightsRequested": 24, "paramsSize": 32,
            "flags": 36, "status": 40,
        }
        for library in report["libraries"].values():
            packet = library["nvos64_packet_layout"]
            self.assertEqual(packet["packet_size"], 48)
            self.assertEqual({name: item["offset"] for name, item in
                              packet["fields"].items()}, expected_outer_offsets)
        nested = report["interpretation"]["payload_layout_static"]["NV83DE_ALLOC_PARAMETERS"]
        self.assertEqual(nested["size_bytes"], 12)
        self.assertEqual({name: item["offset"] for name, item in
                          nested["fields"].items()}, {
                              "hDebuggerClient_Obsolete": 0,
                              "hAppClient": 4,
                              "hClass3dObject": 8,
                          })
        self.assertFalse(report["runtime_or_hardware_validated"])
        self.assertFalse(report["driver_installed_or_loaded"])
        self.assertFalse(report["gpu_accessed_by_this_audit"])

    def test_disassembly_contract_rejects_a_changed_handle_assignment(self):
        with self.assertRaisesRegex(ValueError, "disassembly mismatch at 0x10"):
            AUDIT.validate_instruction_map({0x10: "mov DWORD PTR [rbp-0x50],ecx"},
                                           {0x10: "mov DWORD PTR [rbp-0x50],0x0"})

    def test_c_function_extractor_ignores_nested_braces_and_call_sites(self):
        text = '''
int target(int x)
{
    const char *s = "}";
    /* { ignored } */
    if (x) { return x + 1; }
    return 0;
}
int caller(void) { return target(2); }
'''
        body = AUDIT.extract_c_function(text, "target")
        self.assertTrue(body.startswith("{"))
        self.assertTrue(body.endswith("}"))
        self.assertIn("if (x) { return x + 1; }", body)


if __name__ == "__main__":
    unittest.main()
