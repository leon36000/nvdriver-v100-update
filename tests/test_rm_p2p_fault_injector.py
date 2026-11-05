# SPDX-License-Identifier: MIT
"""Process-local, exact-request P2P fault injection used by the V100 A/B probe."""
from pathlib import Path
import os
import importlib.util
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BUILD_SPEC = importlib.util.spec_from_file_location(
    "build_rm_p2p_fault_injector", ROOT / "tools/build_rm_p2p_fault_injector.py")
BUILDER = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(BUILDER)
SOURCE_ROOT = BUILDER.SOURCE_ROOT
SDK = BUILDER.SDK
INCLUDE_DIRS = BUILDER.INCLUDE_DIRS


class RmP2pFaultInjectorTests(unittest.TestCase):
    def test_source_root_selection_skips_missing_primary_and_uses_pinned_fallback(self):
        fallback = BUILDER.SOURCE_ROOT
        self.assertIsNotNone(fallback)
        missing_primary = ROOT / "build/experiments/intentionally-missing-source-root"
        with patch.object(BUILDER, "SOURCE_ROOT_CANDIDATES",
                          (missing_primary, fallback)):
            self.assertEqual(BUILDER._select_source_root(), fallback)

    def test_source_root_selection_fails_closed_when_all_pin_hashes_mismatch(self):
        mismatched_pins = {name: "0" * 64 for name in BUILDER.PINNED_HEADERS}
        with patch.object(BUILDER, "PINNED_HEADERS", mismatched_pins), \
                patch.object(BUILDER, "SOURCE_ROOT_CANDIDATES",
                             (BUILDER.SOURCE_ROOT,)):
            self.assertIsNone(BUILDER._select_source_root())

    def test_cold_ioctl_forwarding_fails_closed_with_enosys_when_next_is_missing(self):
        source = ROOT / "src/rm_p2p_fault_injector.c"
        assembly = ROOT / "src/rm_p2p_fault_injector.S"
        resolver = ROOT / "tests/fixtures/rm_p2p_dlsym_fail.c"
        fixture = ROOT / "tests/fixtures/rm_p2p_ioctl_enosys_test.c"
        with tempfile.TemporaryDirectory(prefix="rm-p2p-fault-enosys-") as directory:
            root = Path(directory)
            shim = root / "libp2p_fault.so"
            failing_resolver = root / "libfailing_dlsym.so"
            binary = root / "ioctl_enosys_test"
            includes = ["-I" + str(path) for path in INCLUDE_DIRS]
            common = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                      "-DNVRM=1", *includes]
            for command in (
                [*common, "-fPIC", "-shared", str(source), str(assembly),
                 "-ldl", "-pthread", "-o", str(shim)],
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fPIC", "-shared", str(resolver), "-ldl", "-o",
                 str(failing_resolver)],
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 str(fixture), "-o", str(binary)],
            ):
                result = subprocess.run(command, capture_output=True, text=True,
                                        timeout=30, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)

            env = {**os.environ, "LD_PRELOAD":
                   str(shim) + ":" + str(failing_resolver)}
            result = subprocess.run([str(binary)], env=env, capture_output=True,
                                    text=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertIn("failed closed with ENOSYS", result.stdout)

    def test_cold_unrelated_ioctl_resolution_preserves_raw_register_abi(self):
        source = (ROOT / "src/rm_p2p_fault_injector.c").read_text()
        assembly = (ROOT / "src/rm_p2p_fault_injector.S").read_text()
        cold_path = assembly.split(".Lhybrid_rm_resolve_forward:", 1)[1].split(
            ".Lhybrid_rm_target:", 1)[0]

        self.assertIn("uintptr_t hybrid_rm_resolve_next_ioctl(void)", source)
        self.assertNotIn("hybrid_rm_forward_ioctl_dispatch", source + assembly)
        self.assertNotIn("next_ioctl(fd, request, raw_argument)", source)
        self.assertIn("call    hybrid_rm_resolve_next_ioctl", cold_path)
        self.assertIn("jmp     *%r11", cold_path)
        self.assertEqual(
            [line.strip() for line in cold_path.splitlines()
             if line.strip().startswith("pushq")],
            ["pushq   %rax", "pushq   %r9", "pushq   %r8", "pushq   %rcx",
             "pushq   %rdx", "pushq   %rsi", "pushq   %rdi"])
        self.assertEqual(
            [line.strip() for line in cold_path.splitlines()
             if line.strip().startswith("popq")],
            ["popq    %rdi", "popq    %rsi", "popq    %rdx", "popq    %rcx",
             "popq    %r8", "popq    %r9", "popq    %rax"])

    def test_reproducible_builder_pins_sdk_and_records_compile_only_boundary(self):
        with tempfile.TemporaryDirectory(prefix="rm-p2p-fault-builder-") as directory:
            output = Path(directory) / "libhybrid_rm_p2p_fault.so"
            report_path = Path(directory) / "build.json"
            report = BUILDER.build(output, report_path)
            self.assertEqual(report["schema"],
                             "nvidia-hybrid-rm-p2p-fault-injector-build-v3")
            self.assertEqual(report["artifact"]["sha256"], BUILDER.sha256(output))
            self.assertEqual(report["artifact"]["bytes"], output.stat().st_size)
            self.assertFalse(report["hardware_execution_validated"])
            self.assertIn("separate software-validation receipt",
                          report["evidence_state"])
            self.assertEqual(report["assembly_source"]["path"],
                             "src/rm_p2p_fault_injector.S")
            self.assertEqual(report["pinned_headers"], BUILDER.PINNED_HEADERS)
            self.assertEqual(report["source_root"]["path"],
                             BUILDER.SOURCE_ROOT.relative_to(BUILDER.ROOT).as_posix())
            self.assertEqual(report["source_root"]["headers"],
                             BUILDER.PINNED_HEADERS)

    def test_only_selected_p2p_request_is_denied_and_other_ioctls_are_forwarded(self):
        source = ROOT / "src/rm_p2p_fault_injector.c"
        assembly = ROOT / "src/rm_p2p_fault_injector.S"
        fixture = ROOT / "tests/fixtures/rm_p2p_fault_injector_test.c"
        fake = ROOT / "tests/fixtures/rm_p2p_fake_ioctl.c"
        self.assertTrue(source.is_file(), "missing process-local P2P fault injector")
        self.assertTrue(assembly.is_file(), "missing ABI-preserving ioctl trampoline")
        self.assertTrue(fixture.is_file(), "missing synthetic ioctl fixture")
        self.assertTrue(fake.is_file(), "missing synthetic downstream ioctl")
        self.assertTrue(all(path.is_dir() for path in INCLUDE_DIRS),
                        "pinned R580.196.07 SDK include tree is incomplete")

        with tempfile.TemporaryDirectory(prefix="rm-p2p-fault-test-") as directory:
            root = Path(directory)
            shared = root / "libp2p_fault.so"
            synthetic_shared = root / "libp2p_fault_synthetic.so"
            fake_shared = root / "libfake_ioctl.so"
            binary = root / "fault_test"
            includes = ["-I" + str(path) for path in INCLUDE_DIRS]
            common = ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                      "-fsanitize=undefined", "-fno-sanitize-recover=all",
                      "-DNVRM=1", *includes]
            built_shim = subprocess.run(
                [*common, "-fPIC", "-shared", str(source), str(assembly),
                 "-ldl", "-pthread",
                 "-o", str(shared)], capture_output=True, text=True,
                timeout=30, check=False)
            self.assertEqual(built_shim.returncode, 0,
                             built_shim.stdout + built_shim.stderr)
            built_synthetic_shim = subprocess.run(
                [*common, '-DNV_RM_CONTROL_DEVICE="/dev/null"', "-fPIC",
                 "-shared", str(source), str(assembly), "-ldl", "-pthread", "-o",
                 str(synthetic_shared)], capture_output=True, text=True,
                timeout=30, check=False)
            self.assertEqual(built_synthetic_shim.returncode, 0,
                             built_synthetic_shim.stdout +
                             built_synthetic_shim.stderr)
            built_fake = subprocess.run(
                [*common, "-fPIC", "-shared", str(fake), "-o", str(fake_shared)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(built_fake.returncode, 0,
                             built_fake.stdout + built_fake.stderr)
            built_fixture = subprocess.run(
                [*common, str(fixture), "-ldl", "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(built_fixture.returncode, 0,
                             built_fixture.stdout + built_fixture.stderr)

            for mode, expected in (("alloc", "alloc-denied"),
                                   ("register-va", "control-denied"),
                                   ("register-vidmem", "control-denied"),
                                   ("unregister-vidmem", "control-denied")):
                env = {**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                       "LD_PRELOAD": str(synthetic_shared),
                       "HYBRID_RM_P2P_FAULT": mode}
                env["LD_PRELOAD"] = str(synthetic_shared) + ":" + str(fake_shared)
                result = subprocess.run([str(binary), mode], env=env,
                                        capture_output=True, text=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertIn("HYBRID_RM_P2P_FAULT denied=" + mode,
                              result.stderr)

            env = {**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                   "LD_PRELOAD": str(shared),
                   "HYBRID_RM_P2P_FAULT": "alloc"}
            env["LD_PRELOAD"] = str(shared) + ":" + str(fake_shared)
            result = subprocess.run([str(binary), "non-nvidia-fd"], env=env,
                                    capture_output=True, text=True,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertIn("non-NVIDIA descriptor forwarded", result.stdout)
            self.assertNotIn("HYBRID_RM_P2P_FAULT", result.stderr)

            env = {**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                   "LD_PRELOAD": str(synthetic_shared) + ":" + str(fake_shared),
                   "HYBRID_RM_P2P_FAULT": "alloc"}
            result = subprocess.run([str(binary), "control-fd-mismatch"], env=env,
                                    capture_output=True, text=True,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertIn("non-NVIDIA descriptor forwarded", result.stdout)
            self.assertNotIn("HYBRID_RM_P2P_FAULT", result.stderr)

            for mode, expected in (
                    ("abi-forwarding", "no-argument and scalar ioctls forwarded"),
                    ("abi-forwarding-scalar-cold",
                     "cold scalar and no-argument ioctls forwarded")):
                result = subprocess.run([str(binary), mode], env=env,
                                        capture_output=True, text=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertNotIn("HYBRID_RM_P2P_FAULT", result.stderr)

            env = {**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                   "LD_PRELOAD": str(synthetic_shared),
                   "HYBRID_RM_P2P_FAULT": "register-va"}
            env["LD_PRELOAD"] = str(synthetic_shared) + ":" + str(fake_shared)
            result = subprocess.run([str(binary), "tracking-overflow"], env=env,
                                    capture_output=True, text=True,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertIn("overflow object was not faulted", result.stdout)
            self.assertIn("HYBRID_RM_P2P_FAULT tracking-overflow", result.stderr)

            env = {**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                   "LD_PRELOAD": str(synthetic_shared),
                   "HYBRID_RM_P2P_FAULT": "alloc"}
            env["LD_PRELOAD"] = str(synthetic_shared) + ":" + str(fake_shared)
            result = subprocess.run([str(binary), "unrelated"], env=env,
                                    capture_output=True, text=True,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("forwarded", result.stdout)

            for invalid_mode in ("all", "register-pid", "ALLOC", ""):
                env = {**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                       "LD_PRELOAD": str(synthetic_shared),
                       "HYBRID_RM_P2P_FAULT": invalid_mode}
                env["LD_PRELOAD"] = str(synthetic_shared) + ":" + str(fake_shared)
                result = subprocess.run([str(binary), "unrelated"], env=env,
                                        capture_output=True, text=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertIn("forwarded", result.stdout)


if __name__ == "__main__":
    unittest.main()
