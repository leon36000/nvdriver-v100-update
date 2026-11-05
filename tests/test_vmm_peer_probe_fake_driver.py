# SPDX-License-Identifier: MIT
"""Exercise the VMM probe state machine against an explicitly fake CPU driver."""

from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest

from tools.run_vmm_peer_probe import load_build_manifest
from tools.vmm_peer_probe_contract import validate_vmm_peer_report


ROOT = Path(__file__).resolve().parents[1]
PROBE_DIR = ROOT / "build/vmm-peer-probe-v3-20261031"
PROBE = PROBE_DIR / "hybrid_cuda_vmm_peer_probe"
MODULE = ROOT / "build/probe-peer-transfer-v3-20261031/hybrid_probe.sm70-sm120.fatbin"
FAKE_SOURCE = ROOT / "tests/fixtures/vmm_fake_libcuda.cpp"


class VmmFakeDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_build_manifest(PROBE, MODULE)
        cuda_header = Path(cls.manifest["cuda_header"]["path"])
        cls.compiler = Path(cls.manifest["compiler"]["path"])
        cls.temp = tempfile.TemporaryDirectory(prefix="vmm-fake-libcuda-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.fake_dir = Path(cls.temp.name)
        library = cls.fake_dir / "libcuda.so.1"
        command = [
            str(cls.compiler), "-std=c++17", "-shared", "-fPIC",
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
            "-I", str(cuda_header.parent), str(FAKE_SOURCE), "-o", str(library),
        ]
        built = subprocess.run(command, capture_output=True, text=True,
                               check=False, timeout=30)
        if built.returncode:
            raise RuntimeError("fake CUDA driver build failed: " + built.stderr[-4000:])
        cls.fake_library = library
        cls.module_path = MODULE.resolve(strict=True)

    def run_probe(self, mode="success"):
        env = {key: value for key, value in os.environ.items()
               if key not in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH")}
        env["LD_LIBRARY_PATH"] = str(self.fake_dir)
        env["FAKE_CUDA_MODE"] = mode
        result = subprocess.run(
            [str(PROBE), "--module", str(self.module_path),
             "--expected-device", "70=0000:01:00.0",
             "--expected-device", "120=0000:02:00.0", "--count", "37"],
            capture_output=True, text=True, check=False, timeout=10, env=env,
        )
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"fake-driver probe emitted invalid JSON: {error}: {result.stdout!r}")
        validate_vmm_peer_report(report, {70: "0000:01:00.0", 120: "0000:02:00.0"})
        return result, report

    def test_bidirectional_kernel_reads_pass_even_without_classic_peer_capability(self):
        result, report = self.run_probe("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["status"], "vmm-peer-memory-verified")
        self.assertFalse(report["direct_dma_attested"])
        self.assertEqual([direction["peer_capability"] for direction in report["directions"]],
                         [False, False])
        self.assertEqual([direction["kernel_passed"] for direction in report["directions"]],
                         [True, True])

    def test_one_directional_permission_failure_is_reported_as_one_way(self):
        result, report = self.run_probe("one_way")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["status"], "one-way-vmm-peer-memory-verified")
        self.assertFalse(report["passed"])
        self.assertEqual([direction["kernel_attempted"] for direction in report["directions"]],
                         [False, True])
        self.assertEqual([direction["kernel_passed"] for direction in report["directions"]],
                         [False, True])

    def test_kernel_launch_failure_is_not_misreported_as_success(self):
        result, report = self.run_probe("launch_fail")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["status"], "vmm-peer-memory-failed")
        self.assertTrue(all(direction["kernel_attempted"] for direction in report["directions"]))
        self.assertFalse(any(direction["kernel_passed"] for direction in report["directions"]))

    def test_unmap_errors_fail_cleanup_even_when_numeric_kernel_passes(self):
        result, report = self.run_probe("unmap_fail")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["status"], "vmm-peer-memory-failed")
        self.assertFalse(report["cleanup_passed"])
        self.assertEqual(len(report["directions"]), 1)
        self.assertIn("reverse VMM direction skipped after prior direction cleanup failure",
                      report["error"])
        self.assertTrue(all(direction["kernel_passed"] for direction in report["directions"]))
        self.assertTrue(all(not direction["cleanup_passed"] and direction["cleanup_errors"]
                            for direction in report["directions"]))
        for direction in report["directions"]:
            errors = "\n".join(direction["cleanup_errors"])
            self.assertTrue(any(error.startswith("cuMemUnmap:") for error in direction["cleanup_errors"]))
            self.assertIn("cuMemRelease skipped: cuMemUnmap failed", errors)
            self.assertIn("cuMemAddressFree skipped: cuMemUnmap failed", errors)
            self.assertNotIn("cuMemRelease:", errors)
            self.assertNotIn("cuMemAddressFree:", errors)


if __name__ == "__main__":
    unittest.main()
