# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_same_device_selector_reuse.py"
RM_OBJECT = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-kernel.o_binary"


class R580SameDeviceSelectorReuseTests(unittest.TestCase):
    def test_same_device_selector_route_is_reported_conditionally(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "selector-reuse.json"
            log_path = Path(temp_dir) / "selector-reuse.log"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--rm-object",
                    str(RM_OBJECT),
                    "--output",
                    str(report_path),
                    "--raw-log",
                    str(log_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
            report_mode = os.stat(report_path).st_mode & 0o777 if report_path.exists() else None
            log_mode = os.stat(log_path).st_mode & 0o777 if log_path.exists() else None

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["schema"], "rea-r580-same-device-selector-reuse-v1")
        self.assertEqual(report["selector_fields"]["private_state"], "nv_state+0x274")
        self.assertEqual(report["selector_fields"]["adapter_init"], "nv_state+0x274 -> record+0x12c8")
        self.assertTrue(report["same_per_device_nv_state_object_established_by_wrapper_source"])
        self.assertTrue(report["same_key_function_and_normalization"])
        self.assertEqual(report["selector_fields"]["private_state_gate"], "flags bit 0x10 set")
        self.assertEqual(report["selector_fields"]["adapter_init_gate"], "flags bit 0x8 at nv_state+0x11 clear")
        self.assertEqual(report["cache_seed_conclusion"], "possible_if_selector_and_registry_entry_remain_unchanged")
        self.assertEqual(report["runtime_selector_equality"], "unknown")
        self.assertEqual(report["runtime_cache_hit"], "unknown")
        platform = report["possible_intervening_field_store"]["platform_probe_store"]
        self.assertLess(platform["private_state_init"]["line"], platform["field_store"]["line"])
        self.assertIn(
            "calls rm_init_private_state before reading this property",
            report["possible_intervening_field_store"]["interpretation"],
        )
        self.assertEqual(report_mode, 0o600)
        self.assertEqual(log_mode, 0o600)

    def test_modified_wrapper_source_is_rejected(self):
        source = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv.c"
        with tempfile.TemporaryDirectory() as temp_dir:
            changed = Path(temp_dir) / "nv.c"
            output = Path(temp_dir) / "report.json"
            changed.write_bytes(source.read_bytes() + b"\n/* mutation */\n")
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--nv-c",
                    str(changed),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            output_exists = output.exists()

        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned input hash mismatch", result.stderr)
        self.assertFalse(output_exists)


if __name__ == "__main__":
    unittest.main()
