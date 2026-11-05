#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for the temporary PC3 V100 guest Kbuild smoke test."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/run_pc3_v100_kbuild_smoke.py"


def load_tool():
    if not TOOL_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("run_pc3_v100_kbuild_smoke", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_smoke():
    kernel_input_hashes = {
        "Makefile": "a" * 64,
        "Module.symvers": "b" * 64,
        "include/config/auto.conf": "c" * 64,
        "include/generated/autoconf.h": "d" * 64,
        "include/generated/utsrelease.h": "e" * 64,
        "scripts/Makefile.build": "f" * 64,
        "scripts/Makefile.modpost": "1" * 64,
        "scripts/mod/modpost": "2" * 64,
        "scripts/basic/fixdep": "3" * 64,
    }
    return {
        "schema": "nvidia-hybrid-pc3-v100-kbuild-smoke-result-v2",
        "status": "passed",
        "hostname": "pc3-v100",
        "kernel_release": "6.8.0-147-generic",
        "build_path": "/usr/src/linux-headers-6.8.0-147-generic",
        "make_exit_code": 0,
        "make_stdout_bytes": 4096,
        "make_stderr_bytes": 0,
        "make_output_complete": True,
        "make_stdout_sha256": "4" * 64,
        "make_stderr_sha256": "5" * 64,
        "temporary_directory_created": True,
        "temporary_directory_removed": True,
        "kernel_inputs_before_sha256": kernel_input_hashes,
        "kernel_inputs_after_sha256": kernel_input_hashes.copy(),
        "module": {
            "filename": "codex_kbuild_smoke.ko",
            "bytes": 4096,
            "sha256": "6" * 64,
            "elf_class_bits": 64,
            "elf_machine": 62,
            "vermagic_matches": True,
        },
        "module_installed": False,
        "module_loaded": False,
        "gpu_execution_tested": False,
    }


class ToolAvailability(unittest.TestCase):
    def test_temporary_guest_kbuild_tool_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "temporary guest Kbuild smoke tool is missing")


@unittest.skipUnless(TOOL_PATH.is_file(), "temporary guest Kbuild smoke tool is missing")
class GuestSmokeValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def validate(self, report):
        return self.tool.validate_guest_smoke(json.dumps(report).encode("utf-8"))

    def test_accepts_build_only_module_for_the_pinned_guest_kernel(self):
        result = self.validate(valid_smoke())
        self.assertEqual(result["kernel_release"], "6.8.0-147-generic")
        self.assertTrue(result["temporary_directory_removed"])
        self.assertFalse(result["module_loaded"])
        self.assertFalse(result["module_installed"])

    def test_rejects_wrong_guest_kernel(self):
        report = valid_smoke()
        report["kernel_release"] = "7.0.0-38-generic"
        with self.assertRaisesRegex(ValueError, "pinned V100 guest kernel"):
            self.validate(report)

    def test_rejects_module_load_or_install_claims(self):
        for field in ("module_loaded", "module_installed"):
            with self.subTest(field=field):
                report = valid_smoke()
                report[field] = True
                with self.assertRaisesRegex(ValueError, "module execution boundary"):
                    self.validate(report)

    def test_rejects_temporary_directory_leak(self):
        report = valid_smoke()
        report["temporary_directory_removed"] = False
        with self.assertRaisesRegex(ValueError, "temporary directory"):
            self.validate(report)

    def test_rejects_success_claim_when_make_failed(self):
        report = valid_smoke()
        report["make_exit_code"] = 2
        with self.assertRaisesRegex(ValueError, "build result"):
            self.validate(report)

    def test_rejects_success_claim_when_make_output_was_incomplete(self):
        report = valid_smoke()
        report["make_output_complete"] = False
        with self.assertRaisesRegex(ValueError, "build result"):
            self.validate(report)

    def test_rejects_kernel_header_changes(self):
        report = valid_smoke()
        report["kernel_inputs_after_sha256"]["Module.symvers"] = "7" * 64
        with self.assertRaisesRegex(ValueError, "kernel inputs changed"):
            self.validate(report)

    def test_rejects_invalid_module_identity(self):
        report = valid_smoke()
        report["module"]["elf_machine"] = 183
        with self.assertRaisesRegex(ValueError, "ELF machine"):
            self.validate(report)

    def test_guest_script_only_builds_and_never_installs_or_loads(self):
        module = load_tool()
        script = module.GUEST_KBUILD_SCRIPT
        self.assertIn("make", script)
        self.assertIn('"modules"', script)
        self.assertNotIn("modules_install", script)
        self.assertNotIn("modprobe", script)
        self.assertNotIn("insmod", script)


if __name__ == "__main__":
    unittest.main()
