from __future__ import annotations

import hashlib
import mmap
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import tools.run_llama_backend_ops as runner
from tools.run_llama_backend_ops import (
    capture_mapped_library_identities,
    load_pinned_backend_source,
    require_authorized_test_host,
)
from tools.llama_backend_ops_contract import all_backend_runs_passed


_SOURCE_MAPPING = "\n".join((
    "info.devices[id].physical_device = id % info.physical_device_count;",
    "dev_ctx->name = GGML_CUDA_NAME + std::to_string(i);",
    "const int physical_id = info.devices[i].physical_device;",
    "CUDA_CHECK(cudaDeviceGetPCIBusId(pci_bus_id, sizeof(pci_bus_id), physical_id));",
))


class RunLlamaBackendOpsTests(unittest.TestCase):
    def test_gpu_runner_is_restricted_to_the_authorized_pc3_hostname(self):
        require_authorized_test_host("pc3")
        with self.assertRaisesRegex(ValueError, "only on PC3"):
            require_authorized_test_host("pc1")

    def test_preflight_resolves_repository_as_directory_then_checks_source_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_root = root / "llama"
            source_file = source_root / "ggml/src/ggml-cuda/ggml-cuda.cu"
            source_file.parent.mkdir(parents=True)
            source_file.write_text(_SOURCE_MAPPING, encoding="utf-8")

            actual_root, actual_file = load_pinned_backend_source(root, "llama")

        self.assertEqual(actual_root, source_root.resolve())
        self.assertEqual(actual_file, source_file.resolve())

    @unittest.skipUnless(Path("/proc/self/maps").is_file(), "Linux /proc maps is required")
    def test_mapped_library_hash_is_bound_to_live_map_device_and_inode(self):
        payload = b"CUDA-runtime-fixture" * 1024
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libcudart.so.12.9.79"
            path.write_bytes(payload)
            with path.open("rb") as stream:
                mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    observations, errors = capture_mapped_library_identities(
                        os.getpid(), {"runtime": "libcudart.so"}, {})
                    rows = [row for row in observations["runtime"] if row["path"] == str(path)]
                    self.assertEqual(errors, [])
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["sha256"], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(rows[0]["inode"], path.stat().st_ino)
                finally:
                    mapped.close()

    @unittest.skipUnless(Path("/proc/self/maps").is_file(), "Linux /proc maps is required")
    def test_replaced_mapped_path_fails_closed_instead_of_hashing_replacement(self):
        original = b"original-mapped-object" * 512
        replacement = b"replacement-path-object" * 512
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libcudart.so.12.9.79"
            path.write_bytes(original)
            with path.open("rb") as stream:
                mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    path.unlink()
                    path.write_bytes(replacement)
                    observations, errors = capture_mapped_library_identities(
                        os.getpid(), {"runtime": "libcudart.so"}, {})
                    self.assertEqual(observations["runtime"], [])
                    self.assertTrue(errors)
                    self.assertNotIn(hashlib.sha256(replacement).hexdigest(),
                                     [row["sha256"] for row in observations["runtime"]])
                finally:
                    mapped.close()

    @unittest.skipUnless(Path("/proc/self/maps").is_file(), "Linux /proc maps is required")
    def test_in_place_mapped_file_change_invalidates_cached_identity(self):
        payload = b"CUDA-runtime-fixture" * 1024
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libcudart.so.12.9.79"
            path.write_bytes(payload)
            with path.open("r+b") as stream:
                mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    cache = {}
                    first, first_errors = capture_mapped_library_identities(
                        os.getpid(), {"runtime": "libcudart.so"}, cache)
                    self.assertEqual(first_errors, [])
                    self.assertEqual(len(first["runtime"]), 1)
                    stream.seek(0)
                    stream.write(b"X" * len(payload))
                    stream.flush()
                    os.fsync(stream.fileno())
                    second, second_errors = capture_mapped_library_identities(
                        os.getpid(), {"runtime": "libcudart.so"}, cache)
                    self.assertEqual(second["runtime"], [])
                    self.assertTrue(any("changed after identity capture" in error
                                        for error in second_errors))
                finally:
                    mapped.close()

    @unittest.skipUnless(Path("/proc/self/maps").is_file(), "Linux /proc maps is required")
    def test_in_place_change_during_hash_fails_closed(self):
        payload = b"A" * (2 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libcudart.so.12.9.79"
            path.write_bytes(payload)
            with path.open("r+b") as stream:
                mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    real_read = os.read
                    changed = False

                    def mutate_after_chunk(descriptor: int, size: int) -> bytes:
                        nonlocal changed
                        chunk = real_read(descriptor, size)
                        if not changed and os.fstat(descriptor).st_ino == path.stat().st_ino:
                            stream.seek(len(payload) // 2)
                            stream.write(b"B" * (len(payload) // 2))
                            stream.flush()
                            os.fsync(stream.fileno())
                            changed = True
                        return chunk

                    with mock.patch.object(runner.os, "read", side_effect=mutate_after_chunk):
                        observations, errors = capture_mapped_library_identities(
                            os.getpid(), {"runtime": "libcudart.so"}, {})
                    self.assertTrue(changed)
                    self.assertEqual(observations["runtime"], [])
                    self.assertTrue(any("changed while being hashed" in error for error in errors))
                finally:
                    mapped.close()

    @unittest.skipUnless(Path("/proc/self/maps").is_file(), "Linux /proc maps is required")
    def test_final_cache_recheck_catches_change_after_process_maps_disappear(self):
        payload = b"CUDA-runtime-fixture" * 1024
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "libcudart.so.12.9.79"
            path.write_bytes(payload)
            with path.open("rb") as stream:
                mapped = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    cache = {}
                    first, first_errors = capture_mapped_library_identities(
                        os.getpid(), {"runtime": "libcudart.so"}, cache)
                    self.assertEqual(first_errors, [])
                    self.assertEqual(len(first["runtime"]), 1)
                    path.write_bytes(b"Z" * len(payload))
                    final, final_errors = capture_mapped_library_identities(-1, {"runtime": "libcudart.so"}, cache)
                    self.assertEqual(final["runtime"], [])
                    self.assertTrue(any("changed for " in error for error in final_errors))
                finally:
                    mapped.close()

    @staticmethod
    def _passing_backend_result(sm: int) -> dict:
        return {"sm": sm, "exit_code": 0, "timed_out": False,
                "test_summary": {"tests_passed": 24, "tests_total": 24}}

    def test_aggregate_rejects_acceptance_expired_before_first_backend(self):
        rows = [
            {"sm": sm, "not_run": True, "validation_error": "expired",
             "validation_errors": ["expired"]}
            for sm in (70, 120)
        ]
        self.assertFalse(all_backend_runs_passed(rows))

    def test_aggregate_rejects_acceptance_expired_between_backend_runs(self):
        expired = {"sm": 120, "not_run": True, "validation_error": "expired",
                   "validation_errors": ["expired"]}
        self.assertFalse(all_backend_runs_passed([
            self._passing_backend_result(70), expired]))

    def test_aggregate_requires_exactly_one_completed_result_for_both_architectures(self):
        rows = [self._passing_backend_result(70), self._passing_backend_result(120)]
        self.assertTrue(all_backend_runs_passed(rows))
        self.assertFalse(all_backend_runs_passed(rows[:1]))
        self.assertFalse(all_backend_runs_passed([rows[0], rows[0]]))
        self.assertFalse(all_backend_runs_passed([
            {**rows[0], "validation_error": "mapping failed"}, rows[1]]))

    def test_aggregate_rejects_boolean_values_masquerading_as_integer_success(self):
        rows = [self._passing_backend_result(70), self._passing_backend_result(120)]
        bad_exit = [{**rows[0], "exit_code": False}, rows[1]]
        self.assertFalse(all_backend_runs_passed(bad_exit))

        bad_count = [{**rows[0], "test_summary": {
            "tests_passed": True, "tests_total": 1}}, rows[1]]
        self.assertFalse(all_backend_runs_passed(bad_count))

    @staticmethod
    def _fake_backend(root: Path, body: str) -> Path:
        executable = root / "test-backend-ops"
        executable.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return executable

    @staticmethod
    def _successful_report() -> str:
        return """Testing 3 devices
Backend 1/3: CUDA1
  Device description: NVIDIA Tesla V100
24/24 tests passed
fa_vec (Q,NE) slice: 8 cases run, 0 failed
Backend CUDA1: OK
Backend 2/3: CUDA0
  Skipping CUDA0
Backend 3/3: CPU
  Skipping CPU backend
2/3 backends passed
OK
"""

    def test_runner_accepts_complete_stubbed_report_without_gpu_access(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = self._fake_backend(
                root, "print(" + repr(self._successful_report()) + ")\n")
            log_path = root / "evidence/backend-ops.log"
            log_path.parent.mkdir()
            runtime = {
                "libcudart.so.12": {
                    "path": "/cuda/lib/libcudart.so.12.9.79",
                    "bytes": 123,
                    "sha256": "a" * 64,
                    "device_major": 259,
                    "device_minor": 2,
                    "inode": 987,
                },
            }
            observations = {
                "driver": [{
                    "path": "/driver/libcuda.so.1",
                    "bytes": 456,
                    "sha256": "b" * 64,
                    "device_major": 259,
                    "device_minor": 2,
                    "inode": 654,
                }],
                "libcudart.so.12": [runtime["libcudart.so.12"]],
            }
            with mock.patch.object(runner, "ROOT", root), mock.patch.object(
                    runner, "capture_mapped_library_identities",
                    return_value=(observations, [])):
                result = runner.run_backend(
                    binary, "CUDA1", root, log_path, 3, 1, {}, runtime,
                    "Tesla V100")
            log_mode = stat.S_IMODE(log_path.stat().st_mode)

        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["test_summary"]["tests_passed"], 24)
        self.assertNotIn("validation_errors", result)
        self.assertEqual(log_mode, 0o600)

    def test_runner_timeout_is_recorded_and_all_validation_errors_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = self._fake_backend(root, "import time\ntime.sleep(10)\n")
            log_path = root / "evidence/backend-timeout.log"
            log_path.parent.mkdir()
            runtime = {"libcudart.so.12": {
                "path": "/cuda/lib/libcudart.so.12.9.79",
                "bytes": 123,
                "sha256": "a" * 64,
                "device_major": 259,
                "device_minor": 2,
                "inode": 987,
            }}
            empty = {"driver": [], "libcudart.so.12": []}
            with mock.patch.object(runner, "ROOT", root), mock.patch.object(
                    runner, "capture_mapped_library_identities",
                    return_value=(empty, [])):
                result = runner.run_backend(
                    binary, "CUDA1", root, log_path, 1, 1, {}, runtime,
                    "Tesla V100")

        self.assertTrue(result["timed_out"])
        self.assertNotEqual(result["exit_code"], 0)
        self.assertGreaterEqual(len(result["validation_errors"]), 3)


if __name__ == "__main__":
    unittest.main()
