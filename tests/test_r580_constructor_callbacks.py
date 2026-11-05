# SPDX-License-Identifier: MIT
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r580_constructor_callbacks.py"
RM_OBJECT = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04/nvidia/nv-kernel.o_binary"


class R580ConstructorCallbackTests(unittest.TestCase):
    def test_pinned_object_resolves_zero_class_constructor_callbacks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "callback-audit.json"
            log_path = Path(temp_dir) / "callback-audit.log"
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
            report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else "{}"
            report_mode = os.stat(report_path).st_mode & 0o777 if report_path.exists() else None
            log_bytes = log_path.read_bytes() if log_path.exists() else b""
            log_mode = os.stat(log_path).st_mode & 0o777 if log_path.exists() else None

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(report_text)
        self.assertEqual(report["schema"], "rea-r580-constructor-callback-closure-v1")
        self.assertEqual(report_mode, 0o600)
        self.assertEqual(
            report["input"]["sha256"],
            "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b",
        )
        self.assertEqual(report["constructor_miss"]["condition"], "flags & 0x10 set; descriptor cache miss; constructor allocation succeeds")
        self.assertEqual(report["constructor_miss"]["_nv031399rm_arguments"], {"rdi": "0", "rsi": "nv_state+0x274", "rdx": "0"})
        case = report["constructor_miss"]["class_code_zero"]
        self.assertEqual(
            case["callback_targets"],
            {
                "0x68": "_nv031304rm",
                "0x70": "_nv031301rm",
                "0x78": "_nv031308rm",
                "0x80": "_nv031310rm",
            },
        )
        self.assertEqual(case["callback_returns"], {"0x68": "0x34", "0x70": "0", "0x78": "0", "0x80": "0"})
        self.assertEqual(case["nv_set_dma_address_size_argument"], "0x34")
        self.assertFalse(case["slots_0x78_0x80_invoked_on_flags_0x10_branch"])
        self.assertFalse(report["runtime_field_value_observed"])
        self.assertEqual(report["cache_hit_callback_targets"], "unknown")
        self.assertTrue(log_bytes)
        self.assertEqual(log_mode, 0o600)
        self.assertEqual(
            report["verification"]["raw_disassembly_log"]["sha256"],
            hashlib.sha256(log_bytes).hexdigest(),
        )

    def test_unpinned_input_is_rejected_before_emitting_a_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_object = Path(temp_dir) / "not-the-pinned-object"
            report_path = Path(temp_dir) / "must-not-exist.json"
            bad_object.write_bytes(b"not NVIDIA R580 object code")
            result = subprocess.run(
                [sys.executable, str(TOOL), "--rm-object", str(bad_object), "--output", str(report_path)],
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
