#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the real probe against a CPU-only synthetic CUDA Driver API.

These tests validate probe control flow and cleanup reporting. The fake driver
does not execute CUDA or establish functionality on any physical GPU.
"""

from __future__ import annotations

import json
import copy
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tools.cuda_probe_contract import validate_performance_benchmark_report
from tests.run_hybrid_acceptance import validate_probe_report


ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HYBRID_CUDA_PROBE", ROOT / "build/hybrid_cuda_probe"))
FAKE_DRIVER_SOURCE = Path(__file__).parent / "fixtures/fake_cuda_driver.cpp"


class FakeCudaDriverProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PROBE.is_file():
            raise RuntimeError(f"expected existing probe binary is missing: {PROBE}")
        if not FAKE_DRIVER_SOURCE.is_file():
            raise RuntimeError(f"fake CUDA Driver API source is missing: {FAKE_DRIVER_SOURCE}")
        cls.build_root = tempfile.TemporaryDirectory(prefix="hybrid-fake-cuda-build-")
        cls.fake_driver_dir = Path(cls.build_root.name)
        cls.fake_driver = cls.fake_driver_dir / "libcuda.so.1"
        cls.legacy_driver_dir = cls.fake_driver_dir / "legacy"
        cls.legacy_driver_dir.mkdir()
        cls.graphless_driver_dir = cls.fake_driver_dir / "graphless"
        cls.graphless_driver_dir.mkdir()
        cls.partial_graph_driver_dir = cls.fake_driver_dir / "partial-graphs"
        cls.partial_graph_driver_dir.mkdir()
        cls.no_peer_driver_dir = cls.fake_driver_dir / "no-peer-api"
        cls.no_peer_driver_dir.mkdir()
        command = [
            *shlex.split(os.environ.get("CXX", "c++")),
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-shared", "-fPIC", str(FAKE_DRIVER_SOURCE), "-o", str(cls.fake_driver),
        ]
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        if completed.returncode:
            raise RuntimeError(
                "failed to compile CPU-only fake CUDA Driver API:\n"
                + completed.stdout + completed.stderr
            )
        legacy_command = [
            *shlex.split(os.environ.get("CXX", "c++")),
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-DFAKE_CUDA_NO_PREFETCH_V2", "-shared", "-fPIC", str(FAKE_DRIVER_SOURCE),
            "-o", str(cls.legacy_driver_dir / "libcuda.so.1"),
        ]
        completed = subprocess.run(legacy_command, text=True, capture_output=True, check=False)
        if completed.returncode:
            raise RuntimeError(
                "failed to compile CPU-only legacy CUDA Driver API double:\n"
                + completed.stdout + completed.stderr
            )
        graphless_command = [
            *shlex.split(os.environ.get("CXX", "c++")),
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-DFAKE_CUDA_NO_PREFETCH_V2", "-DFAKE_CUDA_NO_GRAPHS",
            "-shared", "-fPIC", str(FAKE_DRIVER_SOURCE),
            "-o", str(cls.graphless_driver_dir / "libcuda.so.1"),
        ]
        completed = subprocess.run(graphless_command, text=True, capture_output=True,
                                   check=False)
        if completed.returncode:
            raise RuntimeError(
                "failed to compile CPU-only CUDA Driver API without Graph symbols:\n"
                + completed.stdout + completed.stderr
            )
        partial_graph_command = [
            *shlex.split(os.environ.get("CXX", "c++")),
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-DFAKE_CUDA_NO_GRAPH_EXEC_DESTROY", "-shared", "-fPIC",
            str(FAKE_DRIVER_SOURCE), "-o",
            str(cls.partial_graph_driver_dir / "libcuda.so.1"),
        ]
        completed = subprocess.run(partial_graph_command, text=True, capture_output=True,
                                   check=False)
        if completed.returncode:
            raise RuntimeError(
                "failed to compile CPU-only CUDA Driver API with a partial Graph API:\n"
                + completed.stdout + completed.stderr
            )
        no_peer_command = [
            *shlex.split(os.environ.get("CXX", "c++")),
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-DFAKE_CUDA_NO_PEER_API", "-shared", "-fPIC",
            str(FAKE_DRIVER_SOURCE), "-o",
            str(cls.no_peer_driver_dir / "libcuda.so.1"),
        ]
        completed = subprocess.run(no_peer_command, text=True, capture_output=True,
                                   check=False)
        if completed.returncode:
            raise RuntimeError(
                "failed to compile CPU-only CUDA Driver API without peer symbols:\n"
                + completed.stdout + completed.stderr
            )

    @classmethod
    def tearDownClass(cls):
        cls.build_root.cleanup()

    def setUp(self):
        self.test_root = tempfile.TemporaryDirectory(prefix="hybrid-fake-cuda-run-")
        self.addCleanup(self.test_root.cleanup)
        self.run_root = Path(self.test_root.name)
        self.module = self.run_root / "synthetic-sm70-sm120.fatbin"
        # cuModuleLoad is intentionally simulated; the probe only needs a readable path.
        self.module.write_bytes(b"FAKE CPU DRIVER TEST INPUT; NOT A CUDA FATBIN\n")
        self.trace = self.run_root / "fake-driver.trace"

    def run_probe(self, extra_arguments=(), require_report=True, driver_directory=None,
                  timeout=20, **extra_environment):
        environment = os.environ.copy()
        prior_library_path = environment.get("LD_LIBRARY_PATH", "")
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(
            part for part in (str(driver_directory or self.fake_driver_dir), prior_library_path) if part
        )
        environment.pop("LD_PRELOAD", None)
        environment["FAKE_CUDA_TRACE_PATH"] = str(self.trace)
        environment.update({key: str(value) for key, value in extra_environment.items()})
        arguments = [str(PROBE.resolve()), "--module", str(self.module), "--require-sm", "70,120"]
        if ("--phase" not in extra_arguments and "--benchmark" not in extra_arguments and
                "--expected-pci" not in extra_arguments and
                "--expected-device" not in extra_arguments):
            arguments += ["--expected-device", "70=0000:01:00.0",
                          "--expected-device", "120=0000:02:00.0"]
        arguments.extend(extra_arguments)
        completed = subprocess.run(
            arguments,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=timeout,
            check=False,
        )
        if not require_report:
            return completed, None, self.trace.read_text() if self.trace.exists() else ""
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(
                f"probe did not emit JSON ({error}); rc={completed.returncode}; "
                f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
            )
        return completed, report, self.trace.read_text()

    def test_two_synthetic_architectures_keep_contexts_resident_and_release_resources(self):
        completed, report, trace = self.run_probe()

        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["schema"], "nvidia-hybrid-probe-v2")
        self.assertEqual(report["status"], "hybrid-validated")
        self.assertTrue(report["hybrid_validated"])
        self.assertTrue(report["context_coexistence_passed"])
        self.assertEqual(report["execution_mode"], "resident-contexts-sequential-kernels")
        self.assertFalse(report["concurrent_kernel_execution_validated"])
        self.assertEqual(report["driver_library_path"], str(self.fake_driver.resolve()))
        self.assertEqual(report["expected_device_pci_by_sm"],
                         {"70": "00000000:01:00.0", "120": "00000000:02:00.0"})
        self.assertEqual({device["sm"] for device in report["devices"]}, {70, 120})
        self.assertTrue(all("FAKE CPU" in device["name"] for device in report["devices"]))
        for device in report["devices"]:
            self.assertTrue(device["architecture_kernel_passed"])
            self.assertTrue(device["synchronous_passed"])
            self.assertTrue(device["asynchronous_passed"])
            self.assertTrue(device["cleanup_passed"])
            self.assertEqual(device["synchronous_sizes"], [1, 31, 256, 4096, 65537])
            self.assertEqual(device["asynchronous_sizes"], [1, 31, 256, 4096, 65537])

        lines = trace.splitlines()
        create_indexes = [i for i, line in enumerate(lines) if line.startswith("ctx_create ")]
        launch_indexes = [i for i, line in enumerate(lines) if line.startswith("launch ")]
        destroy_indexes = [i for i, line in enumerate(lines) if line.startswith("ctx_destroy ")]
        round_trips = [line for line in lines if line.startswith("ctx_get_device ")]
        launches = [lines[i] for i in launch_indexes]
        self.assertEqual(len(create_indexes), 2)
        self.assertEqual(len(round_trips), 2)
        self.assertTrue(launches)
        self.assertLess(max(create_indexes), min(launch_indexes))
        self.assertLess(max(launch_indexes), min(destroy_indexes))
        self.assertTrue(all("live_contexts=2" in line for line in launches), launches)
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0"
        ), lines[-1])

    def test_explicit_libcuda_path_selects_exact_driver_library(self):
        selected = self.legacy_driver_dir / "libcuda.so.1"
        completed, report, _ = self.run_probe(extra_arguments=("--libcuda", str(selected)))
        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["driver_library_path"], str(selected.resolve()))

    def test_explicit_libcuda_path_must_exist_before_cuda_initialization(self):
        missing = self.run_root / "missing-libcuda.so.1"
        completed, _, trace = self.run_probe(
            extra_arguments=("--libcuda", str(missing)), require_report=False)
        self.assertEqual(completed.returncode, 64, completed.stderr)
        self.assertIn("libcuda", completed.stderr)
        self.assertFalse(any(line.startswith("cuInit ") for line in trace.splitlines()))

    def test_explicit_libcuda_path_rejects_fifo_without_blocking(self):
        fifo = self.run_root / "libcuda-fifo"
        os.mkfifo(fifo)
        completed, _, trace = self.run_probe(
            extra_arguments=("--libcuda", str(fifo)), require_report=False, timeout=2)
        self.assertEqual(completed.returncode, 64, completed.stderr)
        self.assertIn("regular file", completed.stderr)
        self.assertFalse(any(line.startswith("cuInit ") for line in trace.splitlines()))

    def test_concurrent_dispatch_checks_both_numeric_results_and_cleans_resources(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--concurrent-kernels",), require_report=False)

        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        report = json.loads(completed.stdout)
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_concurrent_dispatch=True)
        self.assertTrue(report["concurrent_kernel_test_requested"])
        self.assertTrue(report["concurrent_kernel_dispatch_passed"])
        self.assertFalse(report["concurrent_kernel_execution_validated"])
        self.assertEqual(report["execution_mode"],
                         "resident-contexts-sequential-kernels")
        dispatch = report["concurrent_kernel_dispatch"]
        self.assertEqual(dispatch["qualification"],
                         "host-dispatch-window-overlap-profiler-timeline-required")
        self.assertFalse(dispatch["gpu_timeline_overlap_validated"])
        self.assertEqual({device["sm"] for device in dispatch["devices"]}, {70, 120})
        windows = {}
        for device in dispatch["devices"]:
            self.assertTrue(device["numeric_result_passed"])
            self.assertGreater(device["host_window_end_ns"],
                               device["host_window_start_ns"])
            windows[device["sm"]] = (device["host_window_start_ns"],
                                     device["host_window_end_ns"])
        self.assertLess(max(windows[70][0], windows[120][0]),
                        min(windows[70][1], windows[120][1]))
        source = (ROOT / "src/hybrid_cuda_probe.cpp").read_text()
        self.assertLess(source.index("dispatchGate.arriveAndWait()"),
                        source.index("deviceReport.hostWindowStartNs = steadyClockNanoseconds();"))
        lines = trace.splitlines()
        self.assertEqual(sum(line.startswith("concurrent_launch ") for line in lines), 2)
        self.assertTrue(all("live_contexts=2" in line for line in lines
                            if line.startswith("concurrent_launch ")))
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0"
        ), lines[-1])

    def test_peer_transfer_checks_both_directions_and_releases_peer_access(self):
        completed, report, trace = self.run_probe(extra_arguments=("--peer-transfer",))
        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        peer = report["peer_transfer"]
        self.assertTrue(report["peer_transfer_requested"])
        self.assertEqual(peer["status"], "peer-memory-verified")
        self.assertTrue(peer["passed"])
        self.assertTrue(peer["direct_peer_access_enabled"])
        self.assertFalse(peer["direct_dma_attested"])
        self.assertTrue(peer["host_staged_fallback_passed"])
        self.assertEqual(peer["host_staged_fallback_status"], "host-staged-verified")
        self.assertEqual(peer["bytes_per_direction"], 4096)
        self.assertEqual({(row["source_sm"], row["destination_sm"])
                          for row in peer["directions"]}, {(70, 120), (120, 70)})
        self.assertTrue(all(row["direct_access_enabled"] and
                            row["direct_kernel_attempted"] and
                            row["direct_kernel_passed"] and
                            row["sync_copy_passed"] and row["async_copy_passed"] and
                            row["data_integrity_passed"] and
                            row["host_staged_sync_copy_passed"] and
                            row["host_staged_async_copy_passed"] and
                            row["host_staged_data_integrity_passed"]
                            for row in peer["directions"]))
        self.assertEqual(sum(line.startswith("peer_copy_sync ")
                             for line in trace.splitlines()), 2)
        self.assertEqual(sum(line.startswith("peer_copy_async ")
                             for line in trace.splitlines()), 2)
        self.assertEqual(sum(line.startswith("peer_kernel_read ")
                             for line in trace.splitlines()), 2)
        self.assertEqual(sum(line.startswith("peer_enable ")
                             for line in trace.splitlines()), 2)
        self.assertEqual(sum(line.startswith("peer_disable ")
                             for line in trace.splitlines()), 2)
        self.assertTrue(trace.splitlines()[-1].endswith("peer_accesses=0"),
                        trace.splitlines()[-1])
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)
        corrupted = copy.deepcopy(report)
        corrupted["peer_transfer"]["host_staged_fallback_passed"] = False
        with self.assertRaisesRegex(ValueError, "host-staged fallback flag"):
            validate_probe_report(
                corrupted, completed.returncode,
                expected_device_pci_by_sm={70: "00000000:01:00.0",
                                           120: "00000000:02:00.0"},
                expected_peer_transfer=True)

    def test_peer_copy_api_is_tested_even_when_direct_access_is_unavailable(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",), FAKE_CUDA_PEER_UNSUPPORTED=1)
        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        peer = report["peer_transfer"]
        self.assertEqual(peer["status"], "copy-only-verified")
        self.assertTrue(peer["passed"])
        self.assertFalse(peer["direct_peer_access_enabled"])
        self.assertFalse(peer["sm70_can_access_sm120"])
        self.assertFalse(peer["sm120_can_access_sm70"])
        self.assertEqual(sum(line.startswith("peer_enable ")
                             for line in trace.splitlines()), 0)
        self.assertFalse(any(line.startswith("peer_kernel_read ")
                             for line in trace.splitlines()))
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)

    def test_one_way_direct_capability_is_reported_without_claiming_bidirectional_access(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",), FAKE_CUDA_PEER_ONE_WAY=1)
        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        peer = report["peer_transfer"]
        self.assertEqual(peer["status"], "one-way-peer-memory-verified")
        self.assertTrue(peer["passed"])
        self.assertTrue(peer["sm70_can_access_sm120"])
        self.assertFalse(peer["sm120_can_access_sm70"])
        self.assertFalse(peer["direct_peer_access_enabled"])
        self.assertEqual(sum(line.startswith("peer_enable ")
                             for line in trace.splitlines()), 1)
        self.assertEqual(sum(line.startswith("peer_disable ")
                             for line in trace.splitlines()), 1)
        rows = {row["source_sm"]: row for row in peer["directions"]}
        self.assertFalse(rows[70]["direct_kernel_attempted"])
        self.assertTrue(rows[120]["direct_access_enabled"])
        self.assertTrue(rows[120]["direct_kernel_attempted"])
        self.assertTrue(rows[120]["direct_kernel_passed"])

    def test_peer_memory_kernel_failure_is_fatal_and_releases_peer_access(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",), FAKE_CUDA_PEER_KERNEL_FAIL=1)
        self.assertEqual(completed.returncode, 2,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["status"], "failed")
        peer = report["peer_transfer"]
        self.assertEqual(peer["status"], "peer-kernel-failed")
        self.assertFalse(peer["passed"])
        self.assertTrue(all(row["direct_kernel_attempted"] and
                            not row["direct_kernel_passed"]
                            for row in peer["directions"]))
        self.assertEqual(sum(line == "peer_kernel_injected_error"
                             for line in trace.splitlines()), 2)
        self.assertTrue(trace.splitlines()[-1].endswith("peer_accesses=0"),
                        trace.splitlines()[-1])
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)

    def test_peer_transfer_rejects_missing_exact_device_pair_before_cuda_init(self):
        completed, _, trace = self.run_probe(
            extra_arguments=("--peer-transfer", "--expected-device",
                             "70=0000:01:00.0"), require_report=False)
        self.assertEqual(completed.returncode, 64, completed.stderr)
        self.assertIn("exact pinned SM70 and SM120", completed.stderr)
        self.assertFalse(any(line.startswith("fake_cpu_driver_initialized")
                             for line in trace.splitlines()))

    def test_peer_copy_failure_is_fatal_when_both_directions_advertise_direct_access(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",), FAKE_CUDA_PEER_COPY_FAIL=1)
        self.assertEqual(completed.returncode, 2,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["status"], "failed")
        peer = report["peer_transfer"]
        self.assertEqual(peer["status"], "copy-failed")
        self.assertFalse(peer["passed"])
        self.assertTrue(peer["direct_peer_access_enabled"])
        self.assertTrue(all(row["direct_kernel_attempted"] and
                            row["direct_kernel_passed"] for row in peer["directions"]))
        self.assertEqual(sum(line.startswith("peer_kernel_read ")
                             for line in trace.splitlines()), 2)
        self.assertTrue(trace.splitlines()[-1].endswith("peer_accesses=0"),
                        trace.splitlines()[-1])
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)

    def test_peer_access_cleanup_failure_cannot_be_reported_as_pass(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",),
            FAKE_CUDA_PEER_DISABLE_FAIL=1)
        self.assertEqual(completed.returncode, 2,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["status"], "failed")
        peer = report["peer_transfer"]
        self.assertEqual(peer["status"], "cleanup-failed")
        self.assertFalse(peer["passed"])
        self.assertFalse(peer["cleanup_passed"])
        self.assertTrue(all(row["data_integrity_passed"]
                            for row in peer["directions"]))
        self.assertEqual(sum(line == "peer_disable_injected_error"
                             for line in trace.splitlines()), 2)
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)

    def test_missing_peer_api_is_reported_without_promoting_or_failing_core_cuda(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",),
            driver_directory=self.no_peer_driver_dir)
        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["status"], "hybrid-validated")
        peer = report["peer_transfer"]
        self.assertEqual(peer["status"], "api-unavailable")
        self.assertFalse(peer["passed"])
        self.assertTrue(peer["host_staged_fallback_passed"])
        self.assertEqual(peer["host_staged_fallback_status"], "host-staged-verified")
        self.assertEqual({(row["source_sm"], row["destination_sm"])
                          for row in peer["directions"]}, {(70, 120), (120, 70)})
        self.assertTrue(all(row["host_staged_data_integrity_passed"]
                            for row in peer["directions"]))
        self.assertFalse(any(line.startswith(("peer_capability ", "peer_copy_",
                                              "peer_enable ", "peer_kernel_read "))
                             for line in trace.splitlines()))
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)

    def test_host_staging_data_corruption_fails_the_fallback_gate(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--peer-transfer",),
            FAKE_CUDA_HOST_STAGE_CORRUPT=1)
        self.assertEqual(completed.returncode, 2,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["status"], "failed")
        peer = report["peer_transfer"]
        self.assertEqual(peer["host_staged_fallback_status"], "copy-failed")
        self.assertFalse(peer["host_staged_fallback_passed"])
        self.assertTrue(any(line == "host_stage_corrupt"
                            for line in trace.splitlines()))
        self.assertTrue(all(not row["host_staged_data_integrity_passed"]
                            for row in peer["directions"]))
        self.assertEqual(peer["status"], "peer-memory-verified")
        validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_peer_transfer=True)

    def test_acceptance_runner_pins_and_archives_opt_in_peer_transfer(self):
        evidence_dir = self.run_root / "acceptance-evidence"
        environment = os.environ.copy()
        prior_library_path = environment.get("LD_LIBRARY_PATH", "")
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(
            part for part in (str(self.fake_driver_dir), prior_library_path) if part)
        environment.pop("LD_PRELOAD", None)
        environment["FAKE_CUDA_TRACE_PATH"] = str(self.trace)
        runner = ROOT / "tests/run_hybrid_acceptance_fixture_cli.py"
        command = [
            "python3", "-B", str(runner), "--probe", str(PROBE.resolve()),
            "--module", str(self.module), "--peer-transfer",
            "--expected-device", "70=0000:01:00.0",
            "--expected-device", "120=0000:02:00.0",
            "--evidence-dir", str(evidence_dir),
        ]
        completed = subprocess.run(command, text=True, capture_output=True,
                                   env=environment, timeout=30, check=False)
        self.assertEqual(completed.returncode, 2,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        evidence = json.loads(completed.stdout)
        self.assertEqual(evidence["report_contract_qualification"], "report-contract-valid")
        self.assertEqual(evidence["qualification"], "untrusted-probe-artifact")
        self.assertEqual(evidence["probe_build_trust"]["status"], "untrusted")
        self.assertTrue(evidence["peer_transfer_requested"])
        self.assertEqual(evidence["probe"]["peer_transfer"]["status"],
                         "peer-memory-verified")
        self.assertFalse(evidence["probe"]["peer_transfer"]["direct_dma_attested"])
        self.assertEqual(evidence["artifacts"]["probe"]["sha256"],
                         hashlib.sha256(PROBE.read_bytes()).hexdigest())

    def test_concurrent_worker_failure_cancels_dispatch_and_releases_resources(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--concurrent-kernels",),
            FAKE_CUDA_FAIL_CONCURRENT_SM70=1)

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(validate_probe_report(
            report, completed.returncode,
            expected_device_pci_by_sm={70: "00000000:01:00.0",
                                       120: "00000000:02:00.0"},
            expected_concurrent_dispatch=True), "failed")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["hybrid_validated"])
        self.assertTrue(report["concurrent_kernel_test_requested"])
        self.assertFalse(report["concurrent_kernel_dispatch_passed"])
        self.assertIsNone(report["concurrent_kernel_dispatch"])
        self.assertTrue(all(device["cleanup_passed"] for device in report["devices"]))
        self.assertTrue(any("cuLaunchKernel(hybrid_concurrent_work)" in device["error"]
                            for device in report["devices"]))
        lines = trace.splitlines()
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0"
        ), lines[-1])

    def test_unified_memory_capabilities_are_reported_per_device(self):
        completed, report, _ = self.run_probe()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [(device["concurrent_managed_access"],
              device["pageable_memory_access"],
              device["pageable_memory_access_uses_host_page_tables"])
             for device in report["devices"]],
            [(True, False, False), (True, True, False)],
        )

    def test_system_pageable_memory_phase_uses_malloc_and_mmap_without_cuda_copies(self):
        completed, report, trace = self.run_probe(extra_arguments=(
            "--phase", "system-pageable-memory", "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120="1", FAKE_CUDA_SYSTEM_PAGEABLE_MEMORY="1")

        self.assertEqual(completed.returncode, 0,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["schema"], "nvidia-cuda-system-pageable-memory-v1")
        self.assertEqual(report["status"], "validated")
        self.assertEqual(report["phase"], "system-pageable-memory")
        self.assertEqual(report["selected_device"]["pci_bus_id"], "0000:02:00.0")
        self.assertTrue(report["selected_device"]["pageable_memory_access"])
        self.assertTrue(report["selected_device"]["unified_addressing"])
        self.assertEqual(report["allocators"], {
            "malloc": {"tested": True, "passed": True,
                       "execution_mode": "context-synchronized",
                       "sizes": [1, 31, 256, 4096, 65537]},
            "mmap": {"tested": True, "passed": True,
                     "execution_mode": "stream-synchronized",
                     "sizes": [1, 31, 256, 4096, 65537]},
        })
        self.assertTrue(report["cleanup_passed"])
        self.assertEqual(report["error"], "")
        self.assertEqual(sum(line.startswith("launch kind=add")
                             for line in trace.splitlines()), 10)
        self.assertEqual(sum(line.startswith("pageable_pointer_launch")
                             for line in trace.splitlines()), 10)
        self.assertFalse(any(line.startswith((
            "device_alloc ", "managed_alloc ", "host_alloc ", "copy_htod",
            "copy_dtoh", "host_register")) for line in trace.splitlines()))

    def test_system_pageable_memory_phase_skips_before_context_when_attribute_is_false(self):
        completed, report, trace = self.run_probe(extra_arguments=(
            "--phase", "system-pageable-memory", "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120="1", FAKE_CUDA_PAGEABLE_MEMORY_UNSUPPORTED="1")

        self.assertEqual(completed.returncode, 77,
                         f"stdout={completed.stdout!r}; stderr={completed.stderr!r}")
        self.assertEqual(report["schema"], "nvidia-cuda-system-pageable-memory-v1")
        self.assertEqual(report["status"], "unsupported")
        self.assertFalse(report["selected_device"]["pageable_memory_access"])
        self.assertEqual(report["allocators"], {"malloc": None, "mmap": None})
        self.assertFalse(any(line.startswith(("ctx_create", "launch "))
                             for line in trace.splitlines()))

    def test_opt_in_cuda_graphs_replay_kernel_twice_and_release_graph_resources(self):
        completed, report, trace = self.run_probe(extra_arguments=("--cuda-graphs",))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["schema"], "nvidia-hybrid-probe-v2")
        self.assertTrue(report["cuda_graphs_requested"])
        self.assertEqual(report["cuda_graph_api"], "cuGraphInstantiateWithFlags")
        self.assertEqual(report["status"], "hybrid-validated")
        for device in report["devices"]:
            self.assertTrue(device["cuda_graphs_passed"])
            self.assertEqual(device["cuda_graph_launches"], 2)
            self.assertTrue(device["cleanup_passed"])

        lines = trace.splitlines()
        self.assertEqual(sum(line.startswith("graph_create ") for line in lines), 2)
        self.assertEqual(sum(line.startswith("graph_add_kernel_node ") for line in lines), 2)
        self.assertEqual(sum(line.startswith("graph_instantiate ") for line in lines), 2)
        self.assertEqual(sum(line.startswith("graph_launch ") for line in lines), 4)
        self.assertEqual(sum(line.startswith("graph_exec_destroy ") for line in lines), 2)
        self.assertEqual(sum(line.startswith("graph_destroy ") for line in lines), 2)
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0"
        ), lines[-1])

    def test_cuda_graph_launch_failure_fails_probe_and_still_destroys_graphs(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--cuda-graphs",),
            FAKE_CUDA_GRAPH_LAUNCH_FAIL_ONCE=1,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["hybrid_validated"])
        first = report["devices"][0]
        self.assertFalse(first["cuda_graphs_passed"])
        self.assertEqual(first["cuda_graph_launches"], 0)
        self.assertIn("cuGraphLaunch", first["error"])
        self.assertTrue(first["cleanup_passed"])
        self.assertEqual(sum(line.startswith("graph_exec_destroy ") for line in trace.splitlines()), 2)
        self.assertEqual(sum(line.startswith("graph_destroy ") for line in trace.splitlines()), 2)
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0"
        ), trace.splitlines()[-1])

    def test_performance_benchmark_requires_an_exact_pci_guard(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--benchmark",), require_report=False,
            FAKE_CUDA_ONLY_SM120=1)

        self.assertEqual(completed.returncode, 64)
        self.assertIn("--benchmark requires --expected-pci", completed.stderr)
        self.assertIsNone(report)
        self.assertFalse(any(line.startswith(("ctx_create", "device_alloc", "host_alloc"))
                             for line in trace.splitlines()))

    def test_performance_benchmark_reports_device_and_transfer_samples_and_cleans_resources(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--benchmark", "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1)

        self.assertEqual(completed.returncode, 77, completed.stderr)
        self.assertEqual(report["schema"], "nvidia-hybrid-probe-v2")
        self.assertFalse(report["hybrid_validated"])
        self.assertTrue(report["performance_benchmark_requested"])
        device = report["devices"][0]
        self.assertEqual(device["pci_bus_id"], "0000:02:00.0")
        benchmark = device["performance_benchmark"]
        validate_performance_benchmark_report(report, True)
        self.assertEqual(benchmark["schema"], "nvidia-cuda-performance-benchmark-v2")
        self.assertEqual(benchmark["kernel_launch"]["kernel"], "hybrid_empty")
        self.assertEqual(benchmark["kernel_launch"]["samples"], 9)
        self.assertTrue(all(value > 0 for value in
                            benchmark["kernel_launch"]["host_api_us_samples"]))
        self.assertTrue(all(value > 0 for value in
                            benchmark["kernel_launch"]["device_elapsed_us_samples"]))
        self.assertEqual(benchmark["cuda_graph_launch"]["host_api_us"]["samples"], 9)
        self.assertGreater(benchmark["cuda_graph_launch"]["host_api_us"]["p95"], 0)
        self.assertEqual([row["bytes"] for row in benchmark["transfers"]],
                         [4096, 65536, 1048576, 16777216, 67108864])
        self.assertEqual([row["iterations_per_sample"] for row in benchmark["transfers"]],
                         [2048, 128, 8, 1, 1])
        for row in benchmark["transfers"]:
            self.assertEqual(len(row["h_to_d"]["gb_per_second_samples"]), 7)
            self.assertEqual(len(row["d_to_h"]["gb_per_second_samples"]), 7)
            self.assertEqual(len(row["h_to_d"]["device_elapsed_us_per_copy_samples"]), 7)
            self.assertEqual(len(row["d_to_h"]["device_elapsed_us_per_copy_samples"]), 7)
            self.assertTrue(all(value > 0 for value in row["h_to_d"]["gb_per_second_samples"]))
            self.assertTrue(all(value > 0 for value in row["d_to_h"]["gb_per_second_samples"]))
            self.assertTrue(row["data_integrity_passed"])
        expected_copy_elapsed_us = [4.04, 4.64, 14.24, 167.84, 659.36]
        for row, expected in zip(benchmark["transfers"], expected_copy_elapsed_us):
            for direction in ("h_to_d", "d_to_h"):
                for elapsed in row[direction]["device_elapsed_us_per_copy_samples"]:
                    self.assertAlmostEqual(elapsed, expected, delta=0.001)
        self.assertTrue(device["cleanup_passed"])
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0 events=0 peer_accesses=0"
        ), trace.splitlines()[-1])

        corrupted = copy.deepcopy(report)
        corrupted["devices"][0]["performance_benchmark"]["kernel_launch"]["host_api_us_samples"][0] = -1
        with self.assertRaisesRegex(ValueError, "launch host API sample"):
            validate_performance_benchmark_report(corrupted, True)

    def test_performance_benchmark_sample_count_is_configurable_and_consistent(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--benchmark", "--benchmark-samples", "21",
                             "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1)

        self.assertEqual(completed.returncode, 77, completed.stderr)
        device = report["devices"][0]
        benchmark = device["performance_benchmark"]
        validate_performance_benchmark_report(report, True, expected_samples=21)
        self.assertEqual(benchmark["samples"], 21)
        self.assertEqual(benchmark["kernel_launch"]["samples"], 21)
        self.assertEqual(len(benchmark["kernel_launch"]["device_elapsed_us_samples"]), 21)
        self.assertEqual(benchmark["cuda_graph_launch"]["device_elapsed_us"]["samples"], 21)
        self.assertTrue(all(row["samples"] == 21 for row in benchmark["transfers"]))
        self.assertTrue(device["cleanup_passed"])
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0"))

    def test_performance_benchmark_sample_count_is_bounded_and_requires_benchmark(self):
        cases = (
            (("--benchmark-samples", "8"), "integer from 9 through 1001"),
            (("--benchmark-samples", "21"), "requires --benchmark"),
            (("--benchmark", "--benchmark-samples", "1002",
              "--expected-pci", "0000:02:00.0"), "integer from 9 through 1001"),
            (("--benchmark", "--benchmark-samples", "9x",
              "--expected-pci", "0000:02:00.0"), "integer from 9 through 1001"),
            (("--benchmark", "--benchmark-samples", "21", "--benchmark-samples", "31",
              "--expected-pci", "0000:02:00.0"), "may be supplied only once"),
        )
        for arguments, expected_error in cases:
            with self.subTest(arguments=arguments):
                completed, _, _ = self.run_probe(extra_arguments=arguments,
                                                  require_report=False)
                self.assertEqual(completed.returncode, 64)
                self.assertIn(expected_error, completed.stderr)

    def test_performance_benchmark_rejects_transfer_iteration_protocol_drift(self):
        _completed, report, _trace = self.run_probe(
            extra_arguments=("--benchmark", "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1)

        corrupted = copy.deepcopy(report)
        corrupted["devices"][0]["performance_benchmark"]["transfers"][0][
            "iterations_per_sample"] = 1
        with self.assertRaisesRegex(ValueError, "unexpected pinned-transfer iteration count"):
            validate_performance_benchmark_report(corrupted, True)

    def test_performance_benchmark_event_record_and_sync_failures_clean_up(self):
        for variable, error_text in (
                ("FAKE_CUDA_EVENT_RECORD_FAIL_ONCE", "cuEventRecord(start)"),
                ("FAKE_CUDA_EVENT_SYNC_FAIL_ONCE", "cuEventSynchronize")):
            with self.subTest(variable=variable):
                completed, report, trace = self.run_probe(
                    extra_arguments=("--benchmark", "--expected-pci", "0000:02:00.0"),
                    FAKE_CUDA_ONLY_SM120=1, **{variable: "1"})

                self.assertEqual(completed.returncode, 2)
                self.assertEqual(report["status"], "failed")
                device = report["devices"][0]
                self.assertFalse(device["performance_benchmark_passed"])
                self.assertIsNone(device["performance_benchmark"])
                self.assertIn(error_text, device["error"])
                self.assertTrue(device["cleanup_passed"])
                self.assertTrue(trace.splitlines()[-1].endswith("events=0 peer_accesses=0"), trace)

    def test_performance_benchmark_event_failure_fails_closed_and_cleans_up(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--benchmark", "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1, FAKE_CUDA_EVENT_ELAPSED_FAIL_ONCE=1)

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["hybrid_validated"])
        self.assertTrue(report["performance_benchmark_requested"])
        device = report["devices"][0]
        self.assertFalse(device["performance_benchmark_passed"])
        self.assertIsNone(device["performance_benchmark"])
        self.assertIn("cuEventElapsedTime", device["error"])
        self.assertTrue(device["cleanup_passed"])
        self.assertTrue(trace.splitlines()[-1].endswith("events=0 peer_accesses=0"), trace.splitlines()[-1])

    def test_cuda_graphs_validate_each_replay_before_submitting_the_next(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--cuda-graphs",),
            FAKE_CUDA_GRAPH_CORRUPT_FIRST_ONCE=1,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["status"], "failed")
        first = report["devices"][0]
        self.assertFalse(first["cuda_graphs_passed"])
        self.assertEqual(first["cuda_graph_launches"], 1)
        self.assertIn("CUDA Graph numeric result mismatch", first["error"])
        self.assertTrue(first["cleanup_passed"])
        graph_launches = [line for line in trace.splitlines()
                          if line.startswith("graph_launch ")]
        self.assertEqual(len(graph_launches), 3, graph_launches)
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0"
        ), trace.splitlines()[-1])

    def test_cuda_graphs_follow_managed_prefetch_stream_ordering(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--managed-memory", "--managed-prefetch", "--cuda-graphs"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["memory_mode"], "managed")
        self.assertTrue(report["managed_prefetch_requested"])
        self.assertTrue(report["cuda_graphs_requested"])
        for device in report["devices"]:
            self.assertTrue(device["managed_prefetch_passed"])
            self.assertTrue(device["cuda_graphs_passed"])
            self.assertEqual(device["cuda_graph_launches"], 2)
        prefetches = [line for line in trace.splitlines()
                      if line.startswith("managed_prefetch ")]
        self.assertEqual(len(prefetches), 96, prefetches)
        self.assertEqual(sum(line.startswith("graph_launch ") for line in trace.splitlines()), 4)
        lines = trace.splitlines()
        graph_create_indexes = [i for i, line in enumerate(lines)
                                if line.startswith("graph_create ")]
        self.assertEqual(len(graph_create_indexes), 2)
        for ordinal, graph_index in enumerate(graph_create_indexes):
            graph_events = [line for line in lines[graph_index + 1:]
                            if line.startswith(("managed_prefetch ", "graph_launch ",
                                                "stream_synchronize"))]
            expected_events = []
            for _replay in range(2):
                expected_events.extend((
                    f"managed_prefetch destination={ordinal} bytes=1024 stream=nondefault",
                    f"graph_launch ordinal={ordinal} count=256",
                    "stream_synchronize",
                    "managed_prefetch destination=-1 bytes=1024 stream=nondefault",
                    "stream_synchronize",
                ))
            self.assertEqual(graph_events[:10], expected_events, graph_events[:10])
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0"
        ), trace.splitlines()[-1])

    def test_cuda_graph_api_is_required_only_when_opted_in(self):
        completed, report, _trace = self.run_probe(driver_directory=self.graphless_driver_dir)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(report["cuda_graphs_requested"])
        self.assertEqual(report["cuda_graph_api"], "not-requested")

        completed, report, _trace = self.run_probe(
            extra_arguments=("--cuda-graphs",), driver_directory=self.graphless_driver_dir)
        self.assertEqual(completed.returncode, 2)
        self.assertTrue(report["cuda_graphs_requested"])
        self.assertEqual(report["cuda_graph_api"], "unavailable")
        self.assertFalse(report["devices"][0]["cuda_graphs_passed"])
        self.assertIn("cuGraphCreate", report["devices"][0]["error"])

    def test_partial_cuda_graph_api_is_reported_unavailable_without_crashing(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--cuda-graphs",), driver_directory=self.partial_graph_driver_dir)

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertTrue(report["cuda_graphs_requested"])
        self.assertEqual(report["cuda_graph_api"], "unavailable")
        self.assertFalse(report["devices"][0]["cuda_graphs_passed"])
        self.assertIn("cuGraphExecDestroy", report["devices"][0]["error"])
        self.assertTrue(report["devices"][0]["cleanup_passed"])
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0"
        ), trace.splitlines()[-1])

    def test_phase_probes_stop_at_the_requested_driver_api_boundary(self):
        phases = {
            "initialize": ("ctx_create ", "device_alloc", "module_load", "launch "),
            "enumerate": ("ctx_create ", "device_alloc", "module_load", "launch "),
            "context": ("device_alloc", "module_load", "launch "),
            "allocation": ("module_load", "launch "),
            "module": ("device_alloc", "launch "),
            "kernel": (),
        }
        for phase, forbidden_prefixes in phases.items():
            with self.subTest(phase=phase):
                completed, report, trace = self.run_probe(
                    extra_arguments=("--phase", phase, "--expected-pci", "0000:02:00.0"),
                    FAKE_CUDA_ONLY_SM120=1)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(report["schema"], "nvidia-cuda-driver-phase-v1")
                self.assertEqual(report["status"], "phase-passed")
                self.assertEqual(report["phase"], phase)
                self.assertFalse(report.get("hybrid_validated", False))
                self.assertTrue(report["cleanup_passed"])
                lines = trace.splitlines()
                self.assertFalse(any(line.startswith(forbidden) for line in lines
                                     for forbidden in forbidden_prefixes), lines)
                if phase == "initialize":
                    self.assertIsNone(report["selected_device"])
                else:
                    self.assertEqual(report["selected_device"]["pci_bus_id"], "0000:02:00.0")
                if phase in ("context", "allocation", "module", "kernel"):
                    self.assertTrue(lines[-1].startswith(
                        "resource_snapshot contexts=0 modules=0 functions=0 "
                        "device_allocations=0 host_allocations=0 streams=0"), lines[-1])
                if phase == "kernel":
                    self.assertTrue(report["numeric_result_passed"])
                    self.assertEqual(report["result_value"], 1200)

    def test_phase_probe_reports_cleanup_failure_instead_of_pass(self):
        completed, report, _trace = self.run_probe(
            extra_arguments=("--phase", "allocation", "--expected-pci", "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1,
            FAKE_CUDA_FAIL_MEMFREE_ONCE=1)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report["schema"], "nvidia-cuda-driver-phase-v1")
        self.assertEqual(report["status"], "phase-failed")
        self.assertFalse(report["cleanup_passed"])
        self.assertTrue(report["cleanup_errors"])

    def test_managed_accessed_by_phase_sets_and_unsets_device_advice(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--phase", "managed-accessed-by", "--expected-pci",
                             "0000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["status"], "phase-passed")
        self.assertEqual(report["phase"], "managed-accessed-by")
        self.assertEqual(report["completed_operations"][-3:], [
            "cuMemAllocManaged", "cuMemAdvise(SET_ACCESSED_BY)",
            "cuMemAdvise(UNSET_ACCESSED_BY)"])
        self.assertFalse(report["numeric_result_passed"])
        self.assertTrue(report["cleanup_passed"])
        lines = trace.splitlines()
        self.assertTrue(any(line.startswith(
            "mem_advise advice=5 type=1 id=1 bytes=4096") for line in lines), lines)
        self.assertTrue(any(line.startswith(
            "mem_advise advice=6 type=1 id=1 bytes=4096") for line in lines), lines)
        self.assertIn("managed_free", lines)
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0"), lines[-1])

    def test_managed_accessed_by_phase_fails_closed_and_frees_on_advice_errors(self):
        for injection in ("FAKE_CUDA_MEM_ADVISE_FAIL_SET_ONCE",
                          "FAKE_CUDA_MEM_ADVISE_FAIL_UNSET_ONCE"):
            with self.subTest(injection=injection):
                completed, report, trace = self.run_probe(
                    extra_arguments=("--phase", "managed-accessed-by", "--expected-pci",
                                     "0000:02:00.0"),
                    FAKE_CUDA_ONLY_SM120=1, **{injection: 1})
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(report["status"], "phase-failed")
                self.assertFalse(report["numeric_result_passed"])
                self.assertTrue(report["cleanup_passed"], report["cleanup_errors"])
                self.assertIn("managed_free", trace.splitlines())
                self.assertTrue(trace.splitlines()[-1].startswith(
                    "resource_snapshot contexts=0 modules=0 functions=0 "
                    "device_allocations=0 host_allocations=0 streams=0"), trace)

    def test_managed_memory_mode_runs_numeric_kernels_through_cpu_visible_allocations(self):
        completed, report, trace = self.run_probe(extra_arguments=("--managed-memory",))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["memory_mode"], "managed")
        self.assertEqual(len(report["devices"]), 2)
        for device in report["devices"]:
            self.assertTrue(device["managed_memory_passed"])
            self.assertEqual(device["synchronous_sizes"], [1, 31, 256, 4096, 65537])
            self.assertEqual(device["asynchronous_sizes"], [1, 31, 256, 4096, 65537])
            self.assertTrue(device["cleanup_passed"])

        lines = trace.splitlines()
        self.assertEqual(sum(line.startswith("managed_alloc ") for line in lines), 6)
        self.assertEqual(sum(line == "managed_free" for line in lines), 6)
        self.assertFalse(any(line.startswith(("device_alloc", "host_alloc", "copy_htod", "copy_dtoh"))
                             for line in lines), lines)
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0"
        ), lines[-1])

    def test_managed_prefetch_moves_test_ranges_to_gpu_and_back_before_cpu_reads(self):
        completed, report, trace = self.run_probe(extra_arguments=("--managed-memory", "--managed-prefetch"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["memory_mode"], "managed")
        self.assertTrue(report["managed_prefetch_requested"])
        self.assertEqual(report["managed_prefetch_api"], "cuMemPrefetchAsync_v2")
        self.assertEqual(len(report["devices"]), 2)
        for device in report["devices"]:
            self.assertTrue(device["managed_memory_passed"])
            self.assertTrue(device["managed_prefetch_passed"])
        lines = trace.splitlines()
        prefetches = [line for line in lines if line.startswith("managed_prefetch ")]
        self.assertEqual(len(prefetches), 84, lines)
        self.assertTrue(any("destination=-1" in line for line in prefetches), prefetches)
        self.assertTrue(any("destination=0" in line for line in prefetches), prefetches)
        self.assertTrue(any("stream=default" in line for line in prefetches), prefetches)
        self.assertTrue(any("stream=nondefault" in line for line in prefetches), prefetches)
        self.assertFalse(any(line.startswith(("device_alloc", "host_alloc", "copy_htod", "copy_dtoh"))
                             for line in lines), lines)
        self.assertTrue(lines[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0"
        ), lines[-1])

    def test_managed_prefetch_failure_prevents_success_and_reports_cleanup(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--managed-memory", "--managed-prefetch"),
            FAKE_CUDA_MANAGED_PREFETCH_FAIL_ONCE=1,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertTrue(report["managed_prefetch_requested"])
        self.assertFalse(report["devices"][0]["managed_prefetch_passed"])
        self.assertIn("cuMemPrefetchAsync", report["devices"][0]["error"])
        self.assertTrue(report["devices"][0]["cleanup_passed"])
        self.assertTrue(trace.splitlines()[-1].startswith("resource_snapshot contexts=0"))

    def test_managed_prefetch_falls_back_to_legacy_driver_symbol(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--managed-memory", "--managed-prefetch"),
            driver_directory=self.legacy_driver_dir,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report["managed_prefetch_api"], "cuMemPrefetchAsync")
        self.assertTrue(all(device["managed_prefetch_passed"] for device in report["devices"]))
        self.assertEqual(sum(line.startswith("managed_prefetch ") for line in trace.splitlines()), 84)

    def test_synchronous_size_31_failure_keeps_partial_sizes_and_fails_phase(self):
        completed, report, _trace = self.run_probe(FAKE_CUDA_FAIL_SYNC_SIZE=31)

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["hybrid_validated"])
        for device in report["devices"]:
            self.assertFalse(device["synchronous_passed"])
            self.assertEqual(device["synchronous_sizes"], [1])
            self.assertFalse(device["asynchronous_passed"])
            self.assertEqual(device["asynchronous_sizes"], [])
            self.assertIn("cuCtxSynchronize(synchronous kernel)", device["error"])
            self.assertTrue(device["cleanup_passed"])

    def test_cuda_cleanup_api_errors_prevent_success(self):
        cases = (
            ("FAKE_CUDA_FAIL_MEMFREE_ONCE", "cuMemFree_v2"),
            ("FAKE_CUDA_FAIL_CTXDESTROY_ONCE", "cuCtxDestroy_v2"),
        )
        for variable, expected_operation in cases:
            with self.subTest(failure=variable):
                completed, report, _trace = self.run_probe(**{variable: 1})

                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertEqual(report["status"], "failed")
                self.assertFalse(report["hybrid_validated"])
                failed_cleanup = [
                    device for device in report["devices"]
                    if not device["cleanup_passed"]
                ]
                self.assertTrue(failed_cleanup)
                self.assertTrue(any(
                    expected_operation in error
                    for device in failed_cleanup
                    for error in device["cleanup_errors"]
                ))

    def test_second_context_creation_invalidation_is_detected(self):
        completed, report, trace = self.run_probe(
            FAKE_CUDA_INVALIDATE_FIRST_ON_SECOND_CONTEXT=1
        )

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["hybrid_validated"])
        self.assertFalse(report["context_coexistence_passed"])
        self.assertIn("ctx_invalidate first=", trace)
        first_device = next(device for device in report["devices"] if device["sm"] == 70)
        self.assertIn("cuCtxSetCurrent(residency)", first_device["error"])
        self.assertFalse(first_device["cleanup_passed"])

    def test_expected_pci_guard_refuses_extra_or_wrong_visible_gpu_before_contexts(self):
        for address in ("0000:02:00.0", "0000:09:00.0"):
            with self.subTest(address=address):
                completed, _, trace = self.run_probe(
                    extra_arguments=("--expected-pci", address), require_report=False)
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn("selected GPU guard", completed.stderr)
                self.assertNotIn("ctx_create ", trace)
                self.assertNotIn("launch ", trace)

    def test_selected_blackwell_passes_without_certifying_the_missing_volta(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--expected-pci", "00000000:02:00.0"),
            FAKE_CUDA_ONLY_SM120=1)
        self.assertEqual(completed.returncode, 77, completed.stderr)
        self.assertEqual(report["missing_sm"], [70])
        self.assertFalse(report["hybrid_validated"])
        self.assertEqual(len(report["devices"]), 1)
        self.assertEqual(report["devices"][0]["sm"], 120)
        self.assertTrue(report["devices"][0]["cleanup_passed"])
        self.assertEqual(sum(line.startswith("ctx_create ") for line in trace.splitlines()), 1)

    def test_expected_pci_guard_rejects_wrong_single_visible_gpu(self):
        completed, _, trace = self.run_probe(
            extra_arguments=("--expected-pci", "0000:09:00.0"), require_report=False,
            FAKE_CUDA_ONLY_SM120=1)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("selected GPU guard", completed.stderr)
        self.assertNotIn("ctx_create ", trace)

    def test_expected_device_map_rejects_compute_capability_mismatch_before_contexts(self):
        completed, _, trace = self.run_probe(
            extra_arguments=("--expected-device", "70=0000:02:00.0",
                             "--expected-device", "120=0000:01:00.0"),
            require_report=False)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("unexpected compute capability", completed.stderr)
        self.assertNotIn("ctx_create ", trace)
        self.assertNotIn("launch ", trace)

    def test_expected_device_map_requires_unique_complete_pairs_before_cuda_init(self):
        invalid_mappings = (
            ("--expected-device", "70=0000:01:00.0"),
            ("--expected-device", "70=0000:01:00.0",
             "--expected-device", "70=0000:02:00.0"),
            ("--expected-device", "70=0000:01:00.0",
             "--expected-device", "120=0000:01:00.0"),
        )
        for mapping in invalid_mappings:
            with self.subTest(mapping=mapping):
                completed, _, trace = self.run_probe(extra_arguments=mapping,
                                                      require_report=False)
                self.assertEqual(completed.returncode, 64)
                self.assertIn("--expected-device", completed.stderr)
                self.assertNotIn("fake_cpu_driver_initialized", trace)
                self.assertNotIn("ctx_create ", trace)

    def test_unmatched_expected_volta_pci_is_reported_incomplete_without_testing_other_volta(self):
        completed, report, trace = self.run_probe(
            extra_arguments=("--expected-device", "70=0000:09:00.0",
                             "--expected-device", "120=0000:02:00.0"))
        self.assertEqual(completed.returncode, 77, completed.stderr)
        self.assertEqual(report["missing_sm"], [70])
        self.assertFalse(report["hybrid_validated"])
        self.assertEqual([device["sm"] for device in report["devices"] if device["targeted"]],
                         [120])
        self.assertEqual(sum(line.startswith("ctx_create ") for line in trace.splitlines()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
