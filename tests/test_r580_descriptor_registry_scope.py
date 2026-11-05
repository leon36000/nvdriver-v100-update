# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_descriptor_registry_scope.py"
RM_OBJECT = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-kernel.o_binary"
NV_SOURCE = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv.c"
PCI_SOURCE = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-pci.c"


class R580DescriptorRegistryScopeTests(unittest.TestCase):
    def run_audit(self, directory: Path, *, rm_object=RM_OBJECT, nv_source=NV_SOURCE, pci_source=PCI_SOURCE):
        report_path = directory / "registry-scope.json"
        log_path = directory / "registry-scope.log"
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--rm-object",
                str(rm_object),
                "--nv-source",
                str(nv_source),
                "--pci-source",
                str(pci_source),
                "--output",
                str(report_path),
                "--raw-log",
                str(log_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return result, report_path, log_path

    def test_module_manager_registry_and_per_adapter_callers_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, report_path, log_path = self.run_audit(Path(temporary))
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
            report_mode = os.stat(report_path).st_mode & 0o777 if report_path.exists() else None
            log_mode = os.stat(log_path).st_mode & 0o777 if log_path.exists() else None
            log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["schema"], "rea-r580-descriptor-registry-scope-v1")
        self.assertEqual(report["root_pointer"]["symbol"], "_nv029075rm")
        self.assertEqual(report["root_pointer"]["size_bytes"], 8)
        self.assertEqual(report["root_pointer"]["storage_section"], ".bss")
        self.assertEqual(report["root_pointer"]["text_reference_count"], 878)
        self.assertEqual(
            [
                {key: item[key] for key in ("offset", "owner", "operation")}
                for item in report["root_pointer"]["write_sites"]
            ],
            [
                {"offset": "0xa665", "owner": "_nv058760rm", "operation": "store_object_pointer"},
                {"offset": "0xa7c1", "owner": "_nv058760rm", "operation": "clear_on_initialization_failure"},
                {"offset": "0xab02", "owner": "_nv058761rm", "operation": "clear_on_manager_teardown"},
            ],
        )
        self.assertEqual(report["cache_registry"]["manager_pointer_field_offset"], "0x1e0")
        self.assertEqual(report["cache_registry"]["lock_offset_from_registry"], "0x950")
        self.assertEqual(report["cache_registry"]["list_head_offset_from_registry"], "0x38")
        self.assertEqual(report["cache_registry"]["descriptor_key_offsets"], ["0x88", "0x8c", "0x90", "0x94"])
        self.assertEqual(
            report["constructor_destructor_direct_reference_counts"],
            {"_nv000796rm": 1, "_nv021662rm": 1, "_nv058760rm": 1, "_nv058761rm": 1},
        )
        self.assertEqual(report["binary_shutdown_dispatch"]["indirect_destructor_slot"]["target"], "_nv005103rm")
        self.assertEqual(report["binary_shutdown_dispatch"]["indirect_destructor_slot"]["next_call"], "_nv005103rm -> _nv058761rm")
        self.assertEqual(report["scope_assessment"]["status"], "static_inference")
        self.assertIn("module-lifetime", report["scope_assessment"]["conclusion"])
        self.assertFalse(report["hardware_validation_performed"])
        self.assertEqual(report_mode, 0o600)
        self.assertEqual(log_mode, 0o600)
        self.assertIn("_nv031399rm", log)
        self.assertIn("rm_init_adapter", log)

    def test_unpinned_rm_object_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bad_object = directory / "wrong.o"
            bad_object.write_bytes(b"not the pinned proprietary object")
            result, report_path, _ = self.run_audit(directory, rm_object=bad_object)

        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned input hash mismatch", result.stderr)
        self.assertFalse(report_path.exists())

    def test_unpinned_wrapper_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            bad_source = directory / "nv.c"
            bad_source.write_text("/* altered source */\n", encoding="utf-8")
            result, report_path, _ = self.run_audit(directory, nv_source=bad_source)

        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned input hash mismatch", result.stderr)
        self.assertFalse(report_path.exists())


if __name__ == "__main__":
    unittest.main()
