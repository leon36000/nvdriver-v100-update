# SPDX-License-Identifier: MIT
"""Pinned source/ABI checks for the opaque NV2081 BINAPI control boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_binapi_control_boundary.py"
SPEC = importlib.util.spec_from_file_location("binapi_control_boundary", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class BinapiControlBoundaryTests(unittest.TestCase):
    def test_pinned_r580_r595_fixed_abi_and_dispatch_evidence(self):
        result = AUDIT.audit_sources("cc")
        self.assertTrue(result["source_comparison"]["binary_api_c_byte_identical"])
        self.assertEqual(result["source_comparison"]["releases"],
                         {"R580": "580.178.04", "R595": "595.99.02"})
        for release in ("R580", "R595"):
            measurement = result["fixed_header_abi"][release]
            self.assertEqual(measurement["finn_rm_api_size_bytes"], 32)
            self.assertEqual(measurement["finn_rm_api_offsets"], {
                "version": 0, "payloadSize": 8, "interface": 16, "message": 24})
            self.assertEqual(measurement["nv2081_alloc_params_size_bytes"], 4)
            facts = result["source_comparison"]["dispatch_facts"][release]
            self.assertTrue(facts["null_command_returns_ok"])
            self.assertTrue(facts["virtual_gpu_routes_to_rpc"])
            self.assertTrue(facts["firmware_client_routes_to_physical_rm"])
            self.assertTrue(facts["ordinary_physical_default_is_ok_without_rm_call"])
            finn = result["source_comparison"]["finn_serialization_facts"][release]
            self.assertFalse(finn["nv2081_interface_is_listed_in_generated_serializer"])
            self.assertTrue(finn["generated_serializer_rejects_unlisted_interface"])
            self.assertTrue(finn["serialized_size_returns_zero_on_serializer_error"])
            self.assertTrue(finn["unserialized_control_keeps_original_params_when_size_is_zero"])
            self.assertTrue(finn["finn_serialized_flag_set_only_after_successful_serialization"])
            schema = result["source_comparison"]["binapi_schema_facts"][release]
            self.assertTrue(schema["interface_declared"])
            self.assertTrue(schema["interface_aliases_generic_finn_header"])
            self.assertFalse(schema["cl2081_finn_input_source_present"])
            self.assertEqual(schema["class_structs_in_cl2081_header"],
                             ["NV2081_ALLOC_PARAMETERS"])
            self.assertEqual(schema["message_id_definitions_in_binapi_sdk_headers"], [])
            self.assertFalse(schema["observed_command_literal_in_binapi_sdk_headers"])
            resource = schema["resource_registration"]
            self.assertEqual(resource["internal_class"], "BinaryApi")
            self.assertEqual(resource["parent_class"], "Subdevice")
            self.assertTrue(resource["optional_alloc_parameters"])
            self.assertTrue(resource["alloc_rpc_to_physical_rm"])
            self.assertTrue(resource["alloc_rpc_to_vgpu_host"])
            self.assertTrue(resource["alloc_gsp_plugin_for_vgpu_gsp"])
        command = result["observed_command_decode"]
        self.assertEqual(command, {"command": 0x20810108,
                                   "interface_id": 0x208101,
                                   "message_id": 0x08,
                                   "matches_r580_binapi_interface": True,
                                   "matches_r595_binapi_interface": True})

    def test_hardware_inputs_are_class_correlated_but_payload_remains_unresolved(self):
        r580 = AUDIT.load_correlation(
            ROOT / "evidence/binapi-v100-object-correlation-v2-20261021.json")
        r595 = AUDIT.load_correlation(
            ROOT / "evidence/binapi-rtx5080-object-correlation-v2-20261021.json")
        observations = AUDIT.validate_correlations([r580, r595])
        self.assertEqual([row["case"] for row in observations], ["v100", "rtx5080"])
        for row in observations:
            self.assertEqual(row["params_size"], 992)
            self.assertEqual(row["flags"], 0)
            self.assertFalse(row["outer_finn_serialized_flag_set"])
            self.assertTrue(row["object_is_nv2081_binapi"])
            self.assertTrue(row["transport_success"])
        boundary = AUDIT.audit_sources("cc")["payload_boundary"]
        self.assertFalse(boundary["generated_serializer_lists_observed_interface"])
        self.assertTrue(boundary["open_source_serializer_rejects_unlisted_interface"])
        self.assertTrue(boundary["open_source_unserialized_control_keeps_original_params"])

    def test_cli_persists_a_private_sanitized_boundary_report_exclusively(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "boundary.json"
            result = subprocess.run([
                sys.executable, str(TOOL), "--output", str(output),
                "--correlation", str(ROOT / "evidence/binapi-v100-object-correlation-v2-20261021.json"),
                "--correlation", str(ROOT / "evidence/binapi-rtx5080-object-correlation-v2-20261021.json"),
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            report = json.loads(output.read_text())
            self.assertEqual(report["qualification"], "opaque-control-payload-unresolved")
            self.assertEqual(len(report["hardware_observations"]), 2)
            self.assertFalse(report["nested_payload_read"])
            text = output.read_text()
            for secret in ('"hClient"', '"hObject"', '"params_address"', '"pAllocParms"'):
                self.assertNotIn(secret, text)
            again = subprocess.run([
                sys.executable, str(TOOL), "--output", str(output),
                "--correlation", str(ROOT / "evidence/binapi-v100-object-correlation-v2-20261021.json"),
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(again.returncode, 2)


if __name__ == "__main__":
    unittest.main()
