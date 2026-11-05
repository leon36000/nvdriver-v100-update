# SPDX-License-Identifier: MIT
"""Tests for the installed NVIDIA system-sleep hook inventory."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "nvidia_sleep_hook_audit", ROOT / "tools/audit_nvidia_sleep_hook.py")
AUDIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AUDIT)


class NvidiaSleepHookAuditTests(unittest.TestCase):
    def test_records_canonical_path_and_systemd_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "nvidia-sleep.sh"
            unit = root / "nvidia-suspend.service"
            hook = root / "nvidia"
            script.write_text(
                'if [ ! -f /proc/driver/nvidia/suspend ]; then exit 0; fi\n'
                'echo "$1" > /proc/driver/nvidia/suspend\n')
            unit.write_text("ExecStart=/usr/bin/nvidia-sleep.sh suspend\n")
            hook.write_text("/usr/bin/nvidia-sleep.sh resume\n")
            report = AUDIT.audit_config(script, [unit], [hook], "fixture")
            self.assertEqual(report["sleep_script"]["suspend_files"],
                             ["/proc/driver/nvidia/suspend"])
            self.assertTrue(report["sleep_script"]["canonical_path_guard_present"])
            self.assertTrue(report["systemd_units"][0]["invokes_nvidia_sleep_script"])
            self.assertTrue(report["system_sleep_hooks"][0]["invokes_nvidia_sleep_script"])

    def test_does_not_treat_private_backend_paths_as_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "private-sleep.sh"
            script.write_text(
                'echo suspend > /proc/driver/hybrid580_open/suspend\n'
                'echo suspend > /proc/driver/hybrid580_legacy/suspend\n')
            report = AUDIT.audit_config(script, [], [], "private")
            self.assertEqual(report["sleep_script"]["suspend_files"], [
                "/proc/driver/hybrid580_legacy/suspend",
                "/proc/driver/hybrid580_open/suspend",
            ])
            self.assertFalse(report["sleep_script"]["canonical_path_guard_present"])


if __name__ == "__main__":
    unittest.main()
