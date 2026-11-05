# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/correct_pc3_v100_kprobe_semantics.py"
SPEC = importlib.util.spec_from_file_location("pc3_v100_kprobe_semantics_correction", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


def source_report():
    def probe(name, added, resolution):
        return {
            "event_name":name,
            "definition_added":added,
            "event_enabled":False,
            "definition_removed":added,
            "cleanup_verified":True,
            "resolution":resolution,
            "error_errno":None if added else 22,
        }

    return {
        "schema":"nvidia-hybrid-pc3-v100-elf-kprobe-address-transport-v1",
        "status":"observed",
        "probe_source_sha256":"9" * 64,
        "remote":{
            "guest":{
                "schema":"nvidia-hybrid-pc3-v100-elf-kprobe-address-v1",
                "kprobe_attached":False,
                "kernel_release":"6.8.0-147-generic",
                "kernel_probe_config":{
                    "config_dynamic_ftrace":"y",
                    "config_kprobe_events_on_notrace":"n",
                },
                "control_probe":probe("control", True, "resolved_by_kernel"),
                "control_absolute_probe":probe("control_absolute", True, "resolved_by_kernel"),
                "nvidia_named_probe":probe("nvidia_named", False, "failed"),
                "nvidia_absolute_probe":probe("nvidia_absolute", False, "failed"),
            }
        },
    }


class PC3V100KprobeSemanticsCorrectionTests(unittest.TestCase):
    def test_successful_controls_are_classified_registered_disabled_then_removed(self):
        result = TOOL.build_correction(source_report(), TOOL.INPUT_SHA256)
        self.assertEqual(result["registered_disabled_events"], ["control", "control_absolute"])
        self.assertEqual(result["corrected_lifecycle"]["nvidia_named"]["registration_interpretation"],
                         "not_registered")
        self.assertFalse(result["handlers_enabled_by_runner"])
        self.assertFalse(result["kernel_source_basis"]["guest_distribution_source_verified"])

    def test_wrong_source_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "pinned v4 evidence"):
            TOOL.build_correction(source_report(), "0" * 64)

    def test_enabled_control_or_unremoved_definition_is_rejected(self):
        report = source_report()
        report["remote"]["guest"]["control_probe"]["event_enabled"] = True
        with self.assertRaisesRegex(ValueError, "probe states"):
            TOOL.build_correction(report, TOOL.INPUT_SHA256)
        report = source_report()
        report["remote"]["guest"]["control_probe"]["cleanup_verified"] = False
        with self.assertRaisesRegex(ValueError, "probe states"):
            TOOL.build_correction(report, TOOL.INPUT_SHA256)


if __name__ == "__main__":
    unittest.main()
