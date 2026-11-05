# SPDX-License-Identifier: MIT
"""Contracts for the non-loading R580 dual-backend preflight."""
import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "tools/audit_r580_backend_pair.py"
SPEC = (importlib.util.spec_from_file_location("audit_r580_backend_pair", AUDIT_PATH)
        if AUDIT_PATH.is_file() else None)
AUDIT = importlib.util.module_from_spec(SPEC) if SPEC else None
if SPEC:
    SPEC.loader.exec_module(AUDIT)


def module_record(name, license_name):
    return {
        "path": f"/fixture/{name}.ko",
        "name": name,
        "version": "580.178.04",
        "license": license_name,
        "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions",
        "alias": "",
        "parmtype": "hybrid_gpu_pci:charp",
        "imports": {
            "alloc_chrdev_region", "unregister_chrdev_region", "cdev_add",
            "cdev_del", "proc_create_data", "proc_remove",
        },
        "strings": {
            name, f"driver/{name}", f"{name}-caps", f"{name}-nvlink",
            f"{name}-nvswitch", f"{name}-caps-imex-channels",
            f"driver/{name}-caps", f"driver/{name}-nvlink",
            f"driver/{name}-nvswitch", f"{name}_exported_helper",
        },
        "sha256": "a" * 64,
        "bytes": 4096,
    }


class R580BackendPairAuditTests(unittest.TestCase):
    def setUp(self):
        if AUDIT is None and self._testMethodName != "test_preflight_accepts_private_same_version_backends":
            self.skipTest("implementation is not present yet")

    def test_preflight_accepts_private_same_version_backends(self):
        self.assertIsNotNone(AUDIT, "dual-backend static preflight tool is missing")
        result = AUDIT.audit_pair(
            module_record("hybrid580_open", "Dual MIT/GPL"),
            module_record("hybrid580_legacy", "NVIDIA"),
            {"open_export"}, {"legacy_export"}, "7.0.0-38-generic",
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["exports"]["collisions"], [])
        self.assertFalse(result["runtime_validated"])
        self.assertFalse(result["loaded_or_installed"])
        self.assertFalse(result["gpu_accessed"])
        open_report = result["modules"]["open"]
        self.assertEqual(open_report["autoload_aliases"], [])
        self.assertTrue(open_report["pci_selector_parameter_present"])
        self.assertNotIn("hybrid580_open_exported_helper",
                         open_report["private_resource_name_markers"])

    def test_report_records_symvers_provenance(self):
        inputs = {
            "open": {"path": "/fixture/open/Module.symvers", "sha256": "a" * 64,
                     "bytes": 17},
            "legacy": {"path": "/fixture/legacy/Module.symvers", "sha256": "b" * 64,
                       "bytes": 18},
        }
        result = AUDIT.audit_pair(
            module_record("hybrid580_open", "Dual MIT/GPL"),
            module_record("hybrid580_legacy", "NVIDIA"),
            {"open_export"}, {"legacy_export"}, "7.0.0-38-generic", inputs,
        )
        self.assertEqual(result["symvers_inputs"], inputs)

    def test_inspect_symvers_hashes_regular_input(self):
        raw = b"0x00000001 api_open hybrid580_open EXPORT_SYMBOL\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "Module.symvers"
            path.write_bytes(raw)
            symbols, identity = AUDIT.inspect_symvers(path)
            self.assertEqual(symbols, {"api_open"})
            self.assertEqual(identity["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(identity["bytes"], len(raw))

    def test_preflight_rejects_a_shared_module_export_owner(self):
        with self.assertRaisesRegex(ValueError, "export collision"):
            AUDIT.audit_pair(
                module_record("hybrid580_open", "Dual MIT/GPL"),
                module_record("hybrid580_legacy", "NVIDIA"),
                {"shared_api"}, {"shared_api"}, "7.0.0-38-generic",
            )

    def test_preflight_rejects_stock_nvlink_resource_names(self):
        legacy = module_record("hybrid580_legacy", "NVIDIA")
        legacy["strings"].add("driver/nvidia-nvlink")
        with self.assertRaisesRegex(ValueError, "un-namespaced resource"):
            AUDIT.audit_pair(
                module_record("hybrid580_open", "Dual MIT/GPL"), legacy,
                {"open_export"}, {"legacy_export"}, "7.0.0-38-generic",
            )

    def test_preflight_reports_legacy_nv_switch_diagnostic_string_as_ambiguous(self):
        opened = module_record("hybrid580_open", "Dual MIT/GPL")
        opened["strings"].add("nvidia-nvswitch")
        result = AUDIT.audit_pair(
            opened, module_record("hybrid580_legacy", "NVIDIA"),
            {"open_export"}, {"legacy_export"}, "7.0.0-38-generic",
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            result["modules"]["open"]["ambiguous_legacy_literals"],
            ["nvidia-nvswitch"],
        )

    def test_preflight_rejects_a_missing_dynamic_character_device_allocator(self):
        opened = module_record("hybrid580_open", "Dual MIT/GPL")
        opened["imports"].remove("alloc_chrdev_region")
        with self.assertRaisesRegex(ValueError, "alloc_chrdev_region"):
            AUDIT.audit_pair(
                opened, module_record("hybrid580_legacy", "NVIDIA"),
                {"open_export"}, {"legacy_export"}, "7.0.0-38-generic",
            )

    def test_preflight_rejects_kernel_abi_mismatch(self):
        legacy = module_record("hybrid580_legacy", "NVIDIA")
        legacy["vermagic"] = "6.8.0-147-generic SMP modversions"
        with self.assertRaisesRegex(ValueError, "kernel release mismatch"):
            AUDIT.audit_pair(
                module_record("hybrid580_open", "Dual MIT/GPL"), legacy,
                {"open_export"}, {"legacy_export"}, "7.0.0-38-generic",
            )

    def test_symvers_parser_rejects_duplicate_export_names(self):
        text = (
            "0x00000001 api_open hybrid580_open EXPORT_SYMBOL\n"
            "0x00000002 api_open hybrid580_legacy EXPORT_SYMBOL\n"
        )
        with self.assertRaisesRegex(ValueError, "duplicate Module.symvers export"):
            AUDIT.parse_symvers(text)


if __name__ == "__main__":
    unittest.main()
