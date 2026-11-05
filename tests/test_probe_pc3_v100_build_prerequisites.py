#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for the read-only PC3 V100 build-prerequisite probe."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/probe_pc3_v100_build_prerequisites.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("probe_pc3_v100_build_prerequisites", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_report():
    tools = {
        name: {"path": f"/usr/bin/{name}", "version": f"{name} 1.0"}
        for name in ("gcc", "make", "ld", "as", "nm", "objcopy", "strip", "readelf", "patch", "tar", "xz", "python3",
                     "bc", "perl", "flex", "bison", "modinfo", "depmod", "zstd", "rsync")
    }
    return {
        "schema": "nvidia-hybrid-pc3-v100-build-prerequisites-v1",
        "observed_at_utc": "2026-10-28T22:30:00+00:00",
        "hostname": "pc3-v100",
        "architecture": "x86_64",
        "kernel_release": "6.8.0-147-generic",
        "tools": tools,
        "temporary_filesystem": {"path": "/tmp", "available_bytes": 10000000000,
                                 "available_inodes": 100000},
        "kernel_build": {
            "build_link": "/lib/modules/6.8.0-147-generic/build",
            "resolved_build_path": "/usr/src/linux-headers-6.8.0-147-generic",
            "ready": True,
            "module_symvers_bytes": 2214587,
            "module_symvers_sha256": "a" * 64,
            "makefile_exists": True,
            "generated_autoconf_exists": True,
            "scripts_modpost_exists": True,
            "scripts_fixdep_exists": True,
            "required_inputs": {
                relative: {"entry_exists": True, "is_symlink": False, "target_exists": True,
                           "regular_file": True,
                           "resolved_path": "/usr/src/linux-headers-6.8.0-147-generic/" + relative}
                for relative in (
                    "Makefile", "Module.symvers", "include/config/auto.conf",
                    "include/generated/autoconf.h", "include/generated/utsrelease.h",
                    "scripts/Makefile.build", "scripts/Makefile.modpost", "scripts/mod/modpost",
                    "scripts/basic/fixdep")
            },
        },
        "build_prerequisites_ready": True,
        "read_only_guest_query": True,
        "mutation_performed": False,
    }


class BuildPrerequisiteProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def validate(self, report):
        return self.tool.validate_guest_report(json.dumps(report).encode("utf-8"))

    def test_tool_exists(self):
        self.assertTrue(TOOL_PATH.is_file())

    def test_accepts_complete_read_only_build_inventory(self):
        report = self.validate(valid_report())
        self.assertTrue(report["build_prerequisites_ready"])
        self.assertEqual(report["kernel_build"]["module_symvers_bytes"], 2214587)

    def test_rejects_module_symvers_for_another_kernel(self):
        report = valid_report()
        report["kernel_build"]["build_link"] = "/lib/modules/6.8.0-146-generic/build"
        with self.assertRaisesRegex(ValueError, "running kernel"):
            self.validate(report)

    def test_rejects_space_values_that_are_not_nonnegative_integers(self):
        report = valid_report()
        report["temporary_filesystem"]["available_bytes"] = -1
        with self.assertRaisesRegex(ValueError, "available bytes"):
            self.validate(report)

    def test_rejects_missing_compiler_while_claiming_ready(self):
        report = valid_report()
        report["tools"]["gcc"]["path"] = None
        report["tools"]["gcc"]["version"] = None
        with self.assertRaisesRegex(ValueError, "readiness"):
            self.validate(report)

    def test_accepts_optional_tool_with_unavailable_version_flag(self):
        report = valid_report()
        report["tools"]["modinfo"]["version"] = None
        self.assertTrue(self.validate(report)["build_prerequisites_ready"])

    def test_version_matched_common_header_symlink_is_ready_when_pinned(self):
        report = valid_report()
        report["kernel_build"]["required_inputs"]["scripts/Makefile.build"]["is_symlink"] = True
        report["kernel_build"]["required_inputs"]["scripts/Makefile.build"]["resolved_path"] = \
            "/usr/src/linux-headers-6.8.0-147/scripts/Makefile.build"
        self.assertTrue(self.validate(report)["build_prerequisites_ready"])

    def test_wrong_version_common_header_symlink_is_not_claimed_ready(self):
        report = valid_report()
        report["kernel_build"]["required_inputs"]["scripts/Makefile.build"]["is_symlink"] = True
        report["kernel_build"]["required_inputs"]["scripts/Makefile.build"]["resolved_path"] = \
            "/usr/src/linux-headers-6.8.0-999/scripts/Makefile.build"
        with self.assertRaisesRegex(ValueError, "readiness disagrees"):
            self.validate(report)

    def test_probe_can_record_missing_required_kbuild_input_as_not_ready(self):
        report = valid_report()
        report["kernel_build"]["required_inputs"]["scripts/Makefile.build"] = {
            "entry_exists": False, "is_symlink": False, "target_exists": False,
            "regular_file": False, "resolved_path": None}
        report["kernel_build"]["ready"] = False
        report["build_prerequisites_ready"] = False
        accepted = self.validate(report)
        self.assertFalse(accepted["kernel_build"]["ready"])
        self.assertFalse(accepted["build_prerequisites_ready"])

    def test_rejects_false_mutation_flags(self):
        report = valid_report()
        report["mutation_performed"] = True
        with self.assertRaisesRegex(ValueError, "read-only"):
            self.validate(report)

    def test_rejects_unbounded_tool_version(self):
        report = valid_report()
        report["tools"]["gcc"]["version"] = "g" * 1025
        with self.assertRaisesRegex(ValueError, "version"):
            self.validate(report)


if __name__ == "__main__":
    unittest.main()
