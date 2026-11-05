# SPDX-License-Identifier: MIT
"""Source-contract tests for the R580 UVM provider ownership audit."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_uvm_interface_ownership.py"
SPEC = importlib.util.spec_from_file_location("uvm_ownership_audit", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


class UvmInterfaceOwnershipAuditTests(unittest.TestCase):
    def test_comments_are_removed_without_counting_documentation_examples(self):
        header = (ROOT / "tests/fixtures/uvm_interface_ownership.h").read_text()
        declarations = AUDIT.parse_prototypes(header)
        self.assertEqual(len(declarations), 12)
        self.assertNotIn("nvUvmInterfaceFake", {item["name"] for item in declarations})

    def test_route_classes_distinguish_uuid_session_pairs_and_callbacks(self):
        header = (ROOT / "tests/fixtures/uvm_interface_ownership.h").read_text()
        declarations = {item["name"]: item for item in AUDIT.parse_prototypes(header)}
        self.assertEqual(declarations["nvUvmInterfaceSessionCreate"]["route_class"],
                         "global_factory")
        self.assertEqual(declarations["nvUvmInterfaceDeviceCreate"]["route_class"],
                         "session_plus_uuid")
        self.assertEqual(declarations["nvUvmInterfaceGetP2PCaps"]["route_class"],
                         "paired_device_handles")
        self.assertEqual(declarations["nvUvmInterfaceQueryCaps"]["route_class"],
                         "single_opaque_handle")
        self.assertEqual(declarations["nvUvmInterfaceRegisterGpu"]["route_class"],
                         "uuid")
        self.assertEqual(declarations["nvUvmInterfaceRegisterUvmCallbacks"]["route_class"],
                         "global_callback")
        self.assertEqual(declarations["nvUvmInterfaceGetPmaObject"]["route_class"],
                         "handle_plus_opaque_pointer")
        self.assertEqual(declarations["nvUvmInterfacePmaAllocPages"]["route_class"],
                         "provider_opaque_pointer")
        self.assertEqual(declarations["nvUvmInterfacePmaRegisterEvictionCallbacks"]["route_class"],
                         "provider_opaque_pointer")
        self.assertEqual(declarations["nvUvmInterfaceFlushReplayableFaultBuffer"]["route_class"],
                         "embedded_gpu_state")
        self.assertEqual(declarations["nvUvmInterfaceCslInitContext"]["route_class"],
                         "context_plus_handle")
        self.assertEqual(declarations["nvUvmInterfaceCslEncrypt"]["route_class"],
                         "provider_context")

    def test_export_and_callsite_sets_are_source_pinned(self):
        fixture = ROOT / "tests/fixtures"
        audit = AUDIT.audit_sources(
            fixture / "uvm_interface_ownership.h",
            fixture / "uvm_interface_ownership.c",
            [fixture / "uvm_interface_ownership_calls.c"],
            source_root=fixture,
            expected_count=12,
            source_version="fixture",
        )
        self.assertTrue(audit["interface"]["declaration_export_sets_match"])
        self.assertEqual(audit["interface"]["declared_exported_count"], 12)
        self.assertEqual(audit["routing_inventory"]["by_route_class"]["global_factory"], 1)
        api = {row["name"]: row for row in audit["apis"]}
        self.assertEqual(api["nvUvmInterfaceSessionCreate"]["uvm_callsite_count"], 1)
        self.assertEqual(api["nvUvmInterfaceQueryCaps"]["uvm_callsite_count"], 0)

    def test_export_set_drift_is_rejected(self):
        header = (ROOT / "tests/fixtures/uvm_interface_ownership.h").read_text()
        bad_source = "EXPORT_SYMBOL(nvUvmInterfaceMissing);"
        with self.assertRaisesRegex(ValueError, "declaration/export set mismatch"):
            AUDIT.audit_texts(header, bad_source, [], expected_count=12)

    def test_owner_structs_expose_rm_private_device_and_context_pointers(self):
        types_text = (ROOT / "tests/fixtures/uvm_interface_ownership_types.h").read_text()
        facts = AUDIT.type_observations(types_text)
        self.assertTrue(facts["available"])
        self.assertTrue(facts["items"]["UvmGpuFaultInfo"]["contains_device_pointer"])
        self.assertTrue(facts["items"]["UvmCslContext"]["contains_rm_context_pointer"])
        self.assertTrue(facts["items"]["UvmCslContext"]["contains_backend_stack_pointer"])
        self.assertTrue(facts["items"]["UvmGpuPagingChannel"]["contains_gpu_device_pointer"])

    def test_report_is_private_and_refuses_overwrite(self):
        fixture = ROOT / "tests/fixtures"
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            AUDIT.write_report(output, {"schema": "test"})
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text()), {"schema": "test"})
            with self.assertRaises(FileExistsError):
                AUDIT.write_report(output, {"schema": "replacement"})
            self.assertEqual(json.loads(output.read_text()), {"schema": "test"})


if __name__ == "__main__":
    unittest.main()
