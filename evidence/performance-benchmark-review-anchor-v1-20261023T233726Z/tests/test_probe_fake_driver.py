#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the real probe against a CPU-only synthetic CUDA Driver API.

These tests validate probe control flow and cleanup reporting. The fake driver
does not execute CUDA or establish functionality on any physical GPU.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


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
                  **extra_environment):
        environment = os.environ.copy()
        prior_library_path = environment.get("LD_LIBRARY_PATH", "")
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(
            part for part in (str(driver_directory or self.fake_driver_dir), prior_library_path) if part
        )
        environment.pop("LD_PRELOAD", None)
        environment["FAKE_CUDA_TRACE_PATH"] = str(self.trace)
        environment.update({key: str(value) for key, value in extra_environment.items()})
        completed = subprocess.run(
            [str(PROBE.resolve()), "--module", str(self.module), "--require-sm", "70,120", *extra_arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=20,
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
        self.assertEqual(benchmark["schema"], "nvidia-cuda-performance-benchmark-v1")
        self.assertEqual(benchmark["kernel_launch"]["kernel"], "hybrid_empty")
        self.assertEqual(benchmark["kernel_launch"]["samples"], 9)
        self.assertTrue(all(value > 0 for value in
                            benchmark["kernel_launch"]["host_api_us_samples"]))
        self.assertTrue(all(value > 0 for value in
                            benchmark["kernel_launch"]["device_elapsed_us_samples"]))
        self.assertEqual([row["bytes"] for row in benchmark["transfers"]],
                         [4096, 65536, 1048576, 16777216, 67108864])
        for row in benchmark["transfers"]:
            self.assertEqual(len(row["h_to_d"]["gb_per_second_samples"]), 7)
            self.assertEqual(len(row["d_to_h"]["gb_per_second_samples"]), 7)
            self.assertTrue(all(value > 0 for value in row["h_to_d"]["gb_per_second_samples"]))
            self.assertTrue(all(value > 0 for value in row["d_to_h"]["gb_per_second_samples"]))
            self.assertTrue(row["data_integrity_passed"])
        self.assertTrue(device["cleanup_passed"])
        self.assertTrue(trace.splitlines()[-1].startswith(
            "resource_snapshot contexts=0 modules=0 functions=0 "
            "device_allocations=0 host_allocations=0 streams=0 graphs=0 graph_execs=0"
        ), trace.splitlines()[-1])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
