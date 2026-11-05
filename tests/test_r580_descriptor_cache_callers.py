# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_descriptor_cache_callers.py"
RM_OBJECT = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-kernel.o_binary"


class R580DescriptorCacheCallerTests(unittest.TestCase):
    def test_all_direct_lookup_callers_and_routes_are_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "cache-callers.json"
            log_path = Path(temp_dir) / "cache-callers.log"
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
            log_bytes = log_path.read_bytes() if log_path.exists() else b""
            log_mode = os.stat(log_path).st_mode & 0o777 if log_path.exists() else None

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["schema"], "rea-r580-descriptor-cache-callers-v1")
        self.assertEqual(
            report["direct_references_to_nv031399rm"],
            [
                {
                    "relocation_offset": "0x3c193",
                    "caller": "_nv031364rm",
                    "first_key_argument": "0",
                    "selector_argument": "record+0x12c8",
                    "third_key_argument": "0",
                },
                {
                    "relocation_offset": "0xd6d3cd",
                    "caller": "_nv000794rm",
                    "first_key_argument": "0",
                    "selector_argument": "nv_state+0x274",
                    "third_key_argument": "0",
                },
            ],
        )
        self.assertEqual(report["caller_routes"]["_nv031364rm"], "_nv000790rm")
        self.assertEqual(report["caller_routes"]["_nv000794rm"], "rm_init_private_state")
        self.assertEqual(report["caller_routes"]["_nv000790rm"], "rm_init_adapter (when flags bit 3 is clear)")
        self.assertTrue(report["cache_hit_before_private_state_cannot_be_excluded"])
        self.assertEqual(report["runtime_cache_contents"], "unknown")
        self.assertEqual(report_mode, 0o600)
        self.assertEqual(log_mode, 0o600)
        self.assertTrue(log_bytes)

    def test_unpinned_object_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            object_path = Path(temp_dir) / "wrong.o"
            report_path = Path(temp_dir) / "report.json"
            object_path.write_bytes(b"not the pinned R580 object")
            result = subprocess.run(
                [sys.executable, str(TOOL), "--rm-object", str(object_path), "--output", str(report_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            report_exists = report_path.exists()

        self.assertEqual(result.returncode, 2)
        self.assertIn("pinned input hash mismatch", result.stderr)
        self.assertFalse(report_exists)


if __name__ == "__main__":
    unittest.main()
