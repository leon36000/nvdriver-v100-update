# SPDX-License-Identifier: MIT
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "analyze_v100_uvm_context_sequence",
    ROOT / "tools/analyze_v100_uvm_context_sequence.py",
)
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


class V100UvmContextSequenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ioctl_header = self.root / "uvm_ioctl.h"
        self.linux_header = self.root / "uvm_linux_ioctl.h"
        self.ioctl_header.write_text(
            "#define UVM_REGISTER_GPU UVM_IOCTL_BASE(37)\n"
            "#define UVM_REGISTER_GPU_VASPACE UVM_IOCTL_BASE(25)\n"
            "#define UVM_UNREGISTER_GPU_VASPACE UVM_IOCTL_BASE(26)\n"
            "#define UVM_CREATE_RANGE_GROUP UVM_IOCTL_BASE(23)\n"
        )
        self.linux_header.write_text("#define UVM_INITIALIZE 0x30000001\n")

    def make_capture(self, name, requests, *, complete=True, guest_uuid="GPU-test"):
        events = [
            {"node": "nvidia-uvm", "operation": "ioctl", "request": request,
             "syscall_return": 0, "tid": 517, "fd": 9, "file_id": 42,
             "argument": "0xfeedface"}
            for request in requests
        ]
        summary = {
            "qualification": "complete-node-open-trace" if complete else "partial-node-open-trace",
            "trace_complete": complete,
            "events": events,
            "unparsed_lines": [],
            "relative_path_open_count": 0,
            "ioctl_counts_by_node": {"nvidia-uvm": len(events)},
            "descriptor_lifecycle_scope":
                "selected node descriptors only; ioctl payloads and syscall arguments omitted",
        }
        report = {
            "schema": "nvidia-hybrid-pc3-v100-reference-transport-v1",
            "observed_at_utc": "2026-10-28T00:00:00+00:00",
            "qualification": "v100-cuda-phase-report-contract-valid",
            "phase": "context",
            "remote": {
                "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
                "qualification": "v100-cuda-phase-report-contract-valid",
                "phase": "context",
                "guest_cleanup_passed": True,
                "payload_file_cleanup_passed": True,
                "compute_process_count_prelaunch": 0,
                "compute_process_count_after": 0,
                "guest": {
                    "hostname": "pc3-v100", "driver_version": "580.178.04",
                    "kernel_release": "6.8.0-test", "name": "Tesla V100-SXM2-16GB",
                    "pci": "0000:00:05.0", "uuid": guest_uuid,
                },
                "probe": {"phase": "context", "status": "phase-passed"},
                "ioctl_trace": {
                    "trace": {
                        "trace_complete": complete,
                        "size_limit_exceeded": False,
                        "summary": summary,
                    },
                },
            },
        }
        path = self.root / name
        path.write_text(json.dumps(report))
        return path

    def test_compares_repeated_stock_context_traces_and_redacts_transient_ids(self):
        first = self.make_capture("first.json", ["0x30000001", "0x25", "0x19", "0x1a"])
        second = self.make_capture("second.json", ["0x30000001", "0x25", "0x19", "0x1a"])
        result = ANALYZER.analyze_reports(
            [first, second], self.ioctl_header, self.linux_header
        )
        self.assertEqual(result["schema"], "nvidia-hybrid-pc3-v100-context-uvm-sequence-v1")
        self.assertEqual(result["qualification"], "repeated-stock-driver-context-ioctl-metadata-only")
        self.assertTrue(result["comparison"]["request_counts_identical"])
        self.assertTrue(result["comparison"]["first_seen_order_identical"])
        self.assertEqual(result["captures"][0]["uvm_ioctl_count"], 4)
        rows = result["captures"][0]["requests"]
        self.assertEqual([row["name"] for row in rows], [
            "UVM_INITIALIZE", "UVM_REGISTER_GPU", "UVM_REGISTER_GPU_VASPACE",
            "UVM_UNREGISTER_GPU_VASPACE",
        ])
        encoded = json.dumps(result)
        for private_value in ("517", "\"fd\"", "file_id", "feedface", "GPU-test"):
            self.assertNotIn(private_value, encoded)

    def test_rejects_incomplete_trace(self):
        first = self.make_capture("first.json", ["0x19"], complete=False)
        second = self.make_capture("second.json", ["0x19"])
        with self.assertRaisesRegex(ValueError, "complete"):
            ANALYZER.analyze_reports([first, second], self.ioctl_header, self.linux_header)

    def test_rejects_different_guest_identity(self):
        first = self.make_capture("first.json", ["0x19"])
        second = self.make_capture("second.json", ["0x19"], guest_uuid="GPU-other")
        with self.assertRaisesRegex(ValueError, "same V100 guest"):
            ANALYZER.analyze_reports([first, second], self.ioctl_header, self.linux_header)

    def test_rejects_unknown_request_instead_of_guessing_name(self):
        first = self.make_capture("first.json", ["0x7ffff"])
        second = self.make_capture("second.json", ["0x7ffff"])
        with self.assertRaisesRegex(ValueError, "not present in pinned headers"):
            ANALYZER.analyze_reports([first, second], self.ioctl_header, self.linux_header)

    def test_rejects_mismatch_between_event_stream_and_summary_count(self):
        first = self.make_capture("first.json", ["0x19"])
        second = self.make_capture("second.json", ["0x19"])
        value = json.loads(first.read_text())
        value["remote"]["ioctl_trace"]["trace"]["summary"]["ioctl_counts_by_node"]["nvidia-uvm"] = 7
        first.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "event count"):
            ANALYZER.analyze_reports([first, second], self.ioctl_header, self.linux_header)

    def test_rejects_duplicate_request_definitions(self):
        self.ioctl_header.write_text(
            "#define UVM_REGISTER_GPU UVM_IOCTL_BASE(37)\n"
            "#define UVM_OTHER_ALIAS UVM_IOCTL_BASE(37)\n"
        )
        with self.assertRaisesRegex(ValueError, "duplicate UVM request value"):
            ANALYZER.load_request_names(self.ioctl_header, self.linux_header)

    def test_cli_output_is_created_exclusively_with_private_mode(self):
        first = self.make_capture("first.json", ["0x19"])
        second = self.make_capture("second.json", ["0x19"])
        output = self.root / "analysis.json"
        result = ANALYZER.analyze_reports([first, second], self.ioctl_header, self.linux_header)
        ANALYZER.write_report(output, result)
        self.assertEqual(json.loads(output.read_text()), result)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            ANALYZER.write_report(output, result)


if __name__ == "__main__":
    unittest.main()
