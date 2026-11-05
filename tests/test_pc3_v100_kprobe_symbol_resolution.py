# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/probe_pc3_v100_kprobe_symbol_resolution.py"
SPEC = importlib.util.spec_from_file_location("pc3_v100_kprobe_symbol_resolution", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


def valid_report():
    return {
        "schema": "nvidia-hybrid-pc3-v100-kprobe-symbol-resolution-v1",
        "status": "completed",
        "hostname": "pc3-v100",
        "kernel_release": "6.8.0-147-generic",
        "effective_uid": 0,
        "event_group": TOOL.GROUP,
        "stock_driver_changed": False,
        "pci_binding_changed": False,
        "kprobe_attached": False,
        "control_probe": {
            "target": "do_sys_openat2", "resolution": "resolved_by_kernel",
            "definition_added": True, "event_enabled": False,
            "definition_removed": True, "cleanup_verified": True,
        },
        "nvidia_target_probe": {
            "target": "nvidia:rm_init_adapter", "resolution": "failed",
            "error_errno": 22, "definition_added": False,
            "event_enabled": False, "definition_removed": False,
            "cleanup_verified": True,
        },
        "gpus": [{
            "name": "Tesla V100-SXM2-16GB",
            "pci": "0000:00:05.0",
            "driver_version": "580.178.04",
        }],
    }


class PC3V100KprobeSymbolResolutionTests(unittest.TestCase):
    def test_temporary_probe_definition_is_unique_never_enabled_and_cleaned(self):
        code = TOOL.guest_probe_script()
        self.assertRegex(TOOL.GROUP, r"^codex_v100_resolve_[0-9a-f]{12}$")
        self.assertIn('("control", "do_sys_openat2")', code)
        self.assertIn('("nvidia_target", "nvidia:rm_init_adapter")', code)
        self.assertIn('Path("/sys/kernel/tracing/error_log")', code)
        self.assertIn('needle = GROUP + "/nvidia_target"', code)
        self.assertIn('append_command("p:" + GROUP + "/" + event + " " + target)', code)
        self.assertIn('append_command("-:" + GROUP + "/" + event)', code)
        self.assertIn('enable_value.strip() != "0"', code)
        self.assertNotIn('ENABLE.write_text("1")', code)
        self.assertIn('"definition_added":False', code)
        self.assertIn('"stock_driver_changed":False', code)
        self.assertIn('"pci_binding_changed":False', code)
        compile(code, "<pc3-v100-kprobe-resolver>", "exec")

    def test_accepts_only_resolved_disabled_event_with_verified_cleanup(self):
        result = TOOL.validate_report(valid_report())
        self.assertEqual(result["control_probe"]["resolution"], "resolved_by_kernel")
        self.assertFalse(result["nvidia_target_probe"]["event_enabled"])
        self.assertTrue(result["nvidia_target_probe"]["cleanup_verified"])

    def test_rejects_enabled_or_uncleaned_event(self):
        enabled = valid_report()
        enabled["nvidia_target_probe"]["event_enabled"] = True
        with self.assertRaisesRegex(ValueError, "cleanup"):
            TOOL.validate_report(enabled)
        uncleaned = valid_report()
        uncleaned["nvidia_target_probe"]["cleanup_verified"] = False
        with self.assertRaisesRegex(ValueError, "cleanup"):
            TOOL.validate_report(uncleaned)

    def test_rejects_wrong_guest_driver_or_symbol(self):
        for field, value in (
            ("hostname", "other-vm"),
        ):
            report = valid_report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                TOOL.validate_report(report)
        wrong_driver = valid_report()
        wrong_driver["gpus"][0]["driver_version"] = "595.99.02"
        with self.assertRaisesRegex(ValueError, "stock R580"):
            TOOL.validate_report(wrong_driver)
        wrong_symbol = valid_report()
        wrong_symbol["nvidia_target_probe"]["target"] = "nvidia:_nv000794rm"
        with self.assertRaisesRegex(ValueError, "cleanup"):
            TOOL.validate_report(wrong_symbol)

    def test_remote_wrapper_records_the_tracefs_write_attempt_as_mutating(self):
        audit = TOOL.load_audit_tool()
        wrapper = audit.remote_root_script(
            TOOL.guest_probe_script(),
            "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts",
            "/var/lib/pc3-v100-vm/id_ed25519",
            "/tmp/codex-pc3-vm-known_hosts",
            read_only=False,
            trace_event_definition_write_attempted=True,
        )
        compile(wrapper, "<pc3-v100-temporary-kprobe-definition>", "exec")
        self.assertIn('"read_only":False', wrapper)
        self.assertIn('"trace_event_definition_write_attempted":True', wrapper)
        self.assertIn("StrictHostKeyChecking=yes", wrapper)


if __name__ == "__main__":
    unittest.main()
