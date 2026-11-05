#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU tests for the test-only process-local feature-mask interposer."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/system_features_mask_override.c"
FIXTURE = ROOT / "tests/fixtures/system_features_mask_override_contract.c"
RUNTIME_FIXTURE = ROOT / "tests/fixtures/system_features_mask_override_runtime.c"
FAKE_IOCTL = ROOT / "tests/fixtures/system_features_mask_fake_ioctl.c"
UPSTREAM = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04"
INCLUDE_PARTS = (
    "src/common/sdk/nvidia/inc",
    "src/common/inc",
    "src/nvidia/arch/nvalloc/unix/include",
    "kernel-open/common/inc",
)


class SystemFeaturesMaskOverrideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not SOURCE.is_file():
            cls.binary = None
            return
        if not all(path.is_file() for path in (FIXTURE, RUNTIME_FIXTURE, FAKE_IOCTL)) or not UPSTREAM.is_dir():
            raise AssertionError("pinned test fixture or R580 SDK headers are missing")
        cls._temporary = tempfile.TemporaryDirectory(prefix="system-features-override-test-")
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.build_dir = Path(cls._temporary.name)
        include_dirs = [UPSTREAM / part for part in INCLUDE_PARTS]
        includes = ["-I" + str(path) for path in include_dirs]
        commands = (
            ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
             *includes, str(SOURCE), str(FIXTURE), "-ldl", "-o",
             str(cls.build_dir / "contract")],
            ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
             "-fPIC", "-shared", *includes, str(SOURCE), "-ldl", "-o",
             str(cls.build_dir / "system_features_override.so")],
            ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
             "-fPIC", "-shared", *includes, str(FAKE_IOCTL), "-o",
             str(cls.build_dir / "fake_ioctl.so")],
            ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-DNVRM=1",
             *includes, str(RUNTIME_FIXTURE), "-o", str(cls.build_dir / "runtime")],
        )
        for command in commands:
            built = subprocess.run(command, capture_output=True, text=True,
                                   timeout=45, check=False)
            if built.returncode != 0:
                raise AssertionError("strict CPU contract build failed:\n" + built.stderr)
        cls.result = subprocess.run([str(cls.build_dir / "contract")],
                                    capture_output=True, text=True,
                                    timeout=10, check=False)
        cls.binary = True

    def test_direct_root_answer_is_replaced_only_after_success(self) -> None:
        self.assertIsNotNone(self.binary,
                             "the process-local feature-mask override implementation is missing")
        self.assertEqual(self.result.returncode, 0, self.result.stderr)
        self.assertEqual(self.result.stdout.strip(),
                         "system features mask override contract: OK")

    def test_preload_overrides_direct_ioctl_and_records_both_masks(self) -> None:
        self.run_preload_case("direct")

    def test_preload_overrides_xfer_ioctl_and_records_transport(self) -> None:
        self.run_preload_case("xfer")

    def test_optional_call_chain_capture_records_only_bounded_relative_offsets(self) -> None:
        self.run_preload_case("nested-direct", capture_call_chain=True)

    def test_gpu_name_callsite_trace_records_redacted_direct_and_xfer_headers(self) -> None:
        for transport in ("direct", "xfer"):
            with self.subTest(transport=transport):
                self.run_preload_case(transport, capture_gpu_name_caller=True)

    def run_preload_case(self, transport: str, *, capture_call_chain: bool = False,
                         capture_gpu_name_caller: bool = False) -> None:
        self.assertIsNotNone(self.binary,
                             "the process-local feature-mask override implementation is missing")
        trace = self.build_dir / (transport + ".jsonl")
        trace.write_text("")
        trace.chmod(0o600)
        name_trace = self.build_dir / (transport + "-gpu-name.jsonl")
        if capture_gpu_name_caller:
            name_trace.write_text("")
            name_trace.chmod(0o600)
        env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LD_PRELOAD": (str(self.build_dir / "system_features_override.so") + ":" +
                           str(self.build_dir / "fake_ioctl.so")),
            "HYBRID_FEATURES_MASK_OVERRIDE": "0x8",
            "HYBRID_FEATURES_TRACE_PATH": str(trace),
        }
        if capture_gpu_name_caller:
            env["HYBRID_GPU_NAME_CALLER_TRACE_PATH"] = str(name_trace)
        if capture_call_chain:
            env["HYBRID_FEATURES_CAPTURE_CALL_CHAIN"] = "1"
        result = subprocess.run([str(self.build_dir / "runtime"), transport],
                                capture_output=True, text=True, env=env,
                                timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "runtime feature-mask override: OK")
        rows = [__import__("json").loads(line) for line in trace.read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        expected_transport = "direct" if transport == "nested-direct" else transport
        self.assertEqual({key: rows[0][key] for key in
                          ("transport", "kernel_mask", "exposed_mask")},
                         {"transport": expected_transport, "kernel_mask": 9,
                          "exposed_mask": 8})
        self.assertEqual(rows[0]["caller_image"], "runtime")
        self.assertRegex(rows[0]["caller_offset"], r"^0x[0-9a-f]+$")
        if capture_call_chain:
            offsets = rows[0].get("caller_chain_offsets")
            self.assertIsInstance(offsets, list)
            self.assertGreaterEqual(len(offsets), 1)
            self.assertLessEqual(len(offsets), 24)
            self.assertTrue(all(isinstance(value, str) and
                                __import__("re").fullmatch(r"0x[0-9a-f]+", value)
                                for value in offsets))
            self.assertIs(rows[0].get("caller_chain_anchor_found"), True)
            self.assertIs(type(rows[0].get("caller_chain_truncated")), bool)
        if capture_gpu_name_caller:
            name_rows = [__import__("json").loads(line)
                         for line in name_trace.read_text().splitlines()]
            self.assertEqual(len(name_rows), 1)
            name_row = name_rows[0]
            self.assertEqual(
                {key: name_row.get(key) for key in (
                    "command", "transport", "flags", "params_size",
                    "ioctl_result", "embedded_status")},
                {"command": "0x20800110", "transport": transport, "flags": 0,
                 "params_size": 132, "ioctl_result": 0, "embedded_status": 0})
            self.assertEqual(name_row.get("caller_image"), "runtime")
            self.assertRegex(name_row.get("caller_offset", ""), r"^0x[0-9a-f]+$")
            self.assertIs(name_row.get("caller_chain_anchor_found"), True)
            offsets = name_row.get("caller_chain_offsets")
            self.assertIsInstance(offsets, list)
            self.assertGreaterEqual(len(offsets), 1)
            self.assertLessEqual(len(offsets), 24)
            self.assertTrue(all(isinstance(value, str) and
                                __import__("re").fullmatch(r"0x[0-9a-f]+", value)
                                for value in offsets))
            self.assertIs(type(name_row.get("caller_chain_truncated")), bool)


if __name__ == "__main__":
    unittest.main()
