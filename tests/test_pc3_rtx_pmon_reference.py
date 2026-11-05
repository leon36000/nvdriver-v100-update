import copy
import unittest

from tools.run_pc3_rtx_pmon_reference import (
    PMON_COUNT,
    WitnessError,
    _parse_pmon_rows,
    validate_witness,
    summarize_probe_reported_benchmark,
    CONTRACT_SHA256,
    FATBIN_SHA256,
    PROBE_SHA256,
    ROOT,
    RUNNER_SHA256,
)


HEADER = [
    "# gpu         pid   type     sm    mem    enc    dec    jpg    ofa    command",
    "# Idx           #    C/G      %      %      %      %      %      %    name",
]


def pmon_line(index, *, pid=None, sm=None, command=None):
    if pid is None:
        return f"0 {index:8d} - - - - - - - -"
    return f"0 {pid:8d} C {sm:3d} 0 - - - - {command}"


def witness(events=None):
    if events is None:
        events = [{"monotonic_ns": 90, "line": HEADER[0]},
                  {"monotonic_ns": 91, "line": HEADER[1]}]
        for index in range(PMON_COUNT):
            if 6 <= index <= 12:
                line = pmon_line(index, pid=129849, sm=62 + index, command="probe")
            else:
                line = "0          -     -      -      -      -      -      -      -    -"
            events.append({"monotonic_ns": 100 + index * 2, "line": line})
    return {
        "schema": "nvidia-hybrid-pc3-rtx-pmon-runtime-witness-v1",
        "target": "pc3@pc3",
        "host_key_alias": "pc3",
        "gpu_uuid": "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77",
        "pci": "0000:02:00.0",
        "ssh_argv": ["ssh", "-l", "pc3", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                     "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=pc3", "--", "pc3",
                     "nvidia-smi", "pmon", "-i", "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77",
                     "-s", "u", "-d", "1", "-c", "20"],
        "ssh_exit_code": 0,
        "pmon_exit_code": 0,
        "sample_interval_seconds": 1,
        "sample_count_requested": PMON_COUNT,
        "monitor_started_monotonic_ns": 10,
        "monitor_ready_monotonic_ns": 95,
        "benchmark_started_monotonic_ns": 99,
        "benchmark_finished_monotonic_ns": 140,
        "monitor_finished_monotonic_ns": 200,
        "benchmark_runner_exit_code": 77,
        "capture_sha256": "a" * 64,
        "events": events,
    }


class PmonArtifactPinTests(unittest.TestCase):
    def test_monitor_witness_uses_the_current_pinned_v3_acceptance_artifacts(self):
        from tools.run_remote_selected_gpu import (
            PINNED_ACCEPTANCE_ARTIFACTS, PINNED_MODULE_SHA256, PINNED_PROBE_SHA256,
        )
        runner_sha = next(digest for name, _, digest in PINNED_ACCEPTANCE_ARTIFACTS
                          if name == "runner")
        contract_sha = next(digest for name, _, digest in PINNED_ACCEPTANCE_ARTIFACTS
                            if name == "cuda_probe_contract.py")
        self.assertEqual(PROBE_SHA256, PINNED_PROBE_SHA256)
        self.assertEqual(FATBIN_SHA256, PINNED_MODULE_SHA256)
        self.assertEqual(RUNNER_SHA256, runner_sha)
        self.assertEqual(CONTRACT_SHA256, contract_sha)
        source = (ROOT / "tools/run_pc3_rtx_pmon_reference.py").read_text()
        self.assertIn(
            "build/probe-cuda129-sm70v-sm120a-v3-host-staged/hybrid_cuda_probe",
            source,
        )
        self.assertIn(
            "build/probe-cuda129-sm70v-sm120a-v3-host-staged/"
            "hybrid_probe.sm70-ptx_sm120a-cubin.fatbin",
            source,
        )


class PmonRowsTests(unittest.TestCase):
    def test_accepts_single_probe_with_repeated_nonzero_sm_samples(self):
        parsed = _parse_pmon_rows(witness()["events"], count=PMON_COUNT)
        active = [row for row in parsed if row["pid"] is not None]
        self.assertEqual(len(parsed), PMON_COUNT)
        self.assertEqual({row["pid"] for row in active}, {129849})
        self.assertTrue(all(row["command"] == "probe" for row in active))

    def test_rejects_wrong_header_and_row_width(self):
        bad_header = copy.deepcopy(witness()["events"])
        bad_header[0]["line"] = "# gpu pid sm"
        with self.assertRaises(WitnessError):
            _parse_pmon_rows(bad_header, count=PMON_COUNT)
        bad_width = copy.deepcopy(witness()["events"])
        bad_width[2]["line"] = "0 129849 C 62 0 probe"
        with self.assertRaises(WitnessError):
            _parse_pmon_rows(bad_width, count=PMON_COUNT)

    def test_rejects_invalid_idle_process_fields_and_unavailable_utilization(self):
        bad = copy.deepcopy(witness()["events"])
        bad[2]["line"] = "0 129849 C 62 0 - - - - -"
        with self.assertRaises(WitnessError):
            _parse_pmon_rows(bad, count=PMON_COUNT)
        bad = copy.deepcopy(witness()["events"])
        bad[8]["line"] = "0 129849 C - 0 - - - - probe"
        with self.assertRaises(WitnessError):
            _parse_pmon_rows(bad, count=PMON_COUNT)

    def test_rejects_wrong_sample_count_and_gpu_index(self):
        with self.assertRaises(WitnessError):
            _parse_pmon_rows(witness()["events"][:-1], count=PMON_COUNT)
        bad = copy.deepcopy(witness()["events"])
        bad[3]["line"] = bad[3]["line"].replace("0", "1", 1)
        with self.assertRaises(WitnessError):
            _parse_pmon_rows(bad, count=PMON_COUNT)


class PmonWitnessTests(unittest.TestCase):
    def test_accepts_fixed_gpu_strict_ssh_and_overlapping_window(self):
        result = validate_witness(witness(), capture_sha256="a" * 64)
        self.assertEqual(result["nonzero_sm_samples_during_benchmark"], 7)
        self.assertEqual(result["peak_sm_utilization_percent"], 74)
        self.assertEqual(result["observed_process_name"], "probe")

    def test_rejects_wrong_gpu_route_or_unpinned_ssh(self):
        bad = witness()
        bad["gpu_uuid"] = "GPU-other"
        with self.assertRaises(WitnessError):
            validate_witness(bad, capture_sha256="a" * 64)
        bad = witness()
        bad["ssh_argv"][bad["ssh_argv"].index("StrictHostKeyChecking=yes")] = "StrictHostKeyChecking=no"
        with self.assertRaises(WitnessError):
            validate_witness(bad, capture_sha256="a" * 64)

    def test_rejects_wrong_capture_and_exit_status(self):
        with self.assertRaises(WitnessError):
            validate_witness(witness(), capture_sha256="b" * 64)
        bad = witness()
        bad["benchmark_runner_exit_code"] = 0
        with self.assertRaises(WitnessError):
            validate_witness(bad, capture_sha256="a" * 64)

    def test_rejects_no_sm_activity_or_competing_process(self):
        bad = witness()
        for event in bad["events"]:
            if " C " in event["line"]:
                event["line"] = event["line"].replace(" C ", " C ").rsplit(" ", 1)[0]
                fields = event["line"].split()
                fields[3] = "0"
                event["line"] = " ".join(fields)
        with self.assertRaises(WitnessError):
            validate_witness(bad, capture_sha256="a" * 64)
        bad = witness()
        bad["events"][4]["line"] = pmon_line(4, pid=98765, sm=40, command="other")
        with self.assertRaises(WitnessError):
            validate_witness(bad, capture_sha256="a" * 64)

    def test_rejects_samples_outside_the_benchmark_window(self):
        bad = witness()
        bad["benchmark_started_monotonic_ns"] = 180
        with self.assertRaises(WitnessError):
            validate_witness(bad, capture_sha256="a" * 64)


class PmonBenchmarkSummaryTests(unittest.TestCase):
    @staticmethod
    def benchmark():
        transfers = []
        for size in (4096, 65536, 1048576, 16777216, 67108864):
            transfer = {"bytes": size, "samples": 1001,
                        "iterations_per_sample": 1, "data_integrity_passed": True}
            for name in ("h_to_d", "d_to_h"):
                transfer[name] = {
                    "device_elapsed_us_per_copy_median": 1.0,
                    "device_elapsed_us_per_copy_p95": 1.2,
                    "host_api_us_per_copy_median": 1.1,
                    "host_api_us_per_copy_p95": 1.3,
                    "gb_per_second_median": 3.0,
                    "gb_per_second_p95": 3.2,
                    "data_integrity_passed": True,
                }
            transfers.append(transfer)
        return {
            "samples": 1001,
            "transfer_samples": 1001,
            "timing_sources": {"device": "CUDA events (cuEventElapsedTime)",
                               "host": "std::chrono::steady_clock"},
            "kernel_launch": {"kernel": "hybrid_empty", "samples": 1001,
                              "device_elapsed_us_median": 1.18,
                              "device_elapsed_us_p95": 1.21,
                              "host_api_us_median": 1.19,
                              "host_api_us_p95": 1.22},
            "transfers": transfers,
        }

    def test_keeps_probe_reported_aggregates_without_validating_performance(self):
        summary = summarize_probe_reported_benchmark(self.benchmark())
        self.assertEqual(summary["qualification"], "probe-reported-unqualified-single-run")
        self.assertEqual(summary["kernel_launch"]["device_event_us"],
                         {"median": 1.18, "p95": 1.21})
        self.assertEqual(len(summary["transfers"]), 5)
        self.assertEqual(summary["transfers"][-1]["bytes"], 67108864)
        self.assertEqual(summary["transfers"][-1]["host_to_device"]["gb_per_second"],
                         {"median": 3.0, "p95": 3.2})
        self.assertNotIn("device_elapsed_us_per_copy_samples", str(summary))

    def test_rejects_bad_sample_count_or_failed_transfer_integrity(self):
        bad_samples = self.benchmark()
        bad_samples["samples"] = 1000
        with self.assertRaises(WitnessError):
            summarize_probe_reported_benchmark(bad_samples)
        bad_integrity = self.benchmark()
        bad_integrity["transfers"][0]["h_to_d"]["data_integrity_passed"] = False
        with self.assertRaises(WitnessError):
            summarize_probe_reported_benchmark(bad_integrity)


if __name__ == "__main__":
    unittest.main()
