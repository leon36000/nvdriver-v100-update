"""Contract tests for the source-backed UVM ioctl surface audit."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_uvm_ioctl_surface.py"


def write_profile(root: Path, *, populate_pageable: bool = False) -> None:
    root.mkdir(parents=True)
    commands = [
        "#define UVM_CREATE_RANGE_GROUP UVM_IOCTL_BASE(23)",
        "#define UVM_MIGRATE UVM_IOCTL_BASE(51)",
        "#define UVM_INITIALIZE 0x30000001",
        "#define UVM_DEINITIALIZE 0x30000002",
    ]
    routes = [
        "case UVM_DEINITIALIZE: return 0;",
        "UVM_ROUTE_CMD_STACK_NO_INIT_CHECK(UVM_INITIALIZE, uvm_api_initialize);",
        "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_CREATE_RANGE_GROUP, uvm_api_create_range_group);",
        "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_MIGRATE, uvm_api_migrate);",
    ]
    if populate_pageable:
        commands.append("#define UVM_POPULATE_PAGEABLE UVM_IOCTL_BASE(71)")
        routes.append(
            "UVM_ROUTE_CMD_STACK_INIT_CHECK(UVM_POPULATE_PAGEABLE, uvm_api_populate_pageable);"
        )
    (root / "uvm_ioctl.h").write_text(
        "#define UVM_IOCTL_BASE(i) i\n" + "\n".join(commands) + "\n"
    )
    (root / "uvm_linux_ioctl.h").write_text(
        "#define UVM_INITIALIZE 0x30000001\n"
        "#define UVM_DEINITIALIZE 0x30000002\n"
    )
    (root / "uvm.c").write_text("static long uvm_ioctl(void) {\n" + "\n".join(routes) + "\n}\n")


def write_trace(path: Path) -> None:
    path.write_text(json.dumps({
        "schema": "test-uvm-trace-comparison-v1",
        "inputs": {
            "rtx5080": {
                "driver": "595.99.02",
                "uvm_workload_validated": False,
                "request_counts": [
                    {"node": "/dev/nvidia-uvm", "request": "0x17", "count": 2},
                    {"node": "/dev/nvidia-uvm", "request": "0x30000001", "count": 1},
                    {"node": "/dev/nvidia-uvm", "request": "0xee", "count": 3},
                    {"node": "/dev/nvidiactl", "request": "0x17", "count": 900},
                ],
            },
            "v100": {
                "driver": "580.178.04",
                "uvm_workload_validated": False,
                "request_counts": [
                    {"node": "/dev/nvidia-uvm", "request": "0x33", "count": 4},
                ],
            },
        },
    }))


def write_node_lifecycle_comparison(path: Path) -> None:
    path.write_text(json.dumps({
        "schema": "nvidia-hybrid-cuda-node-open-lifecycle-comparison-v3",
        "comparison": {
            "hybrid_runtime_validated": False,
            "scope": "one isolated cuInit/device-enumeration process per stock-driver environment",
        },
        "devices": {
            "rtx5080": {
                "driver": {"version": "595.99.02", "driver_api": 13020},
                "trace": {"ioctl_requests_by_node": {
                    "nvidia-uvm": {"0x17": 2, "0x30000001": 1, "0xee": 3},
                    "nvidiactl": {"0x17": 900},
                }},
            },
            "v100": {
                "driver": {"version": "580.178.04", "driver_api": 13000},
                "trace": {"ioctl_requests_by_node": {
                    "nvidia-uvm": {"0x33": 4},
                    "nvidia0": {"0x17": 700},
                }},
            },
        },
    }))


class UvmIoctlSurfaceTests(unittest.TestCase):
    def test_maps_observed_commands_and_reports_branch_surface_without_payloads(self):
        with tempfile.TemporaryDirectory(prefix="uvm-ioctl-surface-") as temporary:
            root = Path(temporary)
            write_profile(root / "r580-prop")
            write_profile(root / "r580-open")
            write_profile(root / "r595-open", populate_pageable=True)
            trace = root / "trace.json"
            report = root / "report.json"
            write_trace(trace)

            result = subprocess.run(
                [sys.executable, str(TOOL),
                 "--r580-proprietary", str(root / "r580-prop"),
                 "--r580-open", str(root / "r580-open"),
                 "--r595-open", str(root / "r595-open"),
                 "--trace", str(trace), "--report", str(report)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(report.read_text())
            self.assertEqual(data["qualification"], "source-and-command-number-audit-only")
            self.assertFalse(data["scope"]["ioctl_arguments_read"])
            self.assertFalse(data["scope"]["payloads_read"])
            self.assertFalse(data["scope"]["uvm_workload_executed"])
            self.assertTrue(data["comparisons"]["r580_flavors"]["command_ids_equal"])
            self.assertTrue(data["comparisons"]["r580_flavors"]["dispatch_equal"])
            self.assertIn("UVM_POPULATE_PAGEABLE",
                          data["comparisons"]["r580_to_r595_open"]["right_only_names"])

            observed = data["observations"][0]["inputs"]
            rtx = observed["rtx5080"]
            by_value = {item["value_hex"]: item for item in rtx["commands"]}
            self.assertEqual(by_value["0x17"]["names_by_source"]["r580_open"],
                             ["UVM_CREATE_RANGE_GROUP"])
            self.assertEqual(by_value["0x30000001"]["names_by_source"]["r580_proprietary"],
                             ["UVM_INITIALIZE"])
            self.assertEqual(by_value["0x17"]["count"], 2)
            self.assertEqual(rtx["unmapped_requests"], [{"value_hex": "0xee", "count": 3}])
            self.assertEqual(rtx["observed_call_count"], 6)
            self.assertFalse(rtx["input_claims_uvm_workload_validated"])

    def test_refuses_to_overwrite_an_existing_report(self):
        with tempfile.TemporaryDirectory(prefix="uvm-ioctl-surface-") as temporary:
            root = Path(temporary)
            write_profile(root / "r580-prop")
            write_profile(root / "r580-open")
            write_profile(root / "r595-open")
            trace = root / "trace.json"
            report = root / "report.json"
            write_trace(trace)
            report.write_text("keep-me\n")

            result = subprocess.run(
                [sys.executable, str(TOOL),
                 "--r580-proprietary", str(root / "r580-prop"),
                 "--r580-open", str(root / "r580-open"),
                 "--r595-open", str(root / "r595-open"),
                 "--trace", str(trace), "--report", str(report)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertEqual(report.read_text(), "keep-me\n")

    def test_maps_redacted_node_lifecycle_comparison_without_reading_sidecars(self):
        with tempfile.TemporaryDirectory(prefix="uvm-ioctl-lifecycle-") as temporary:
            root = Path(temporary)
            write_profile(root / "r580-prop")
            write_profile(root / "r580-open")
            write_profile(root / "r595-open", populate_pageable=True)
            trace = root / "node-lifecycle.json"
            report = root / "report.json"
            write_node_lifecycle_comparison(trace)

            result = subprocess.run(
                [sys.executable, str(TOOL),
                 "--r580-proprietary", str(root / "r580-prop"),
                 "--r580-open", str(root / "r580-open"),
                 "--r595-open", str(root / "r595-open"),
                 "--trace", str(trace), "--report", str(report)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(report.read_text())
            self.assertEqual(data["observations"][0]["schema"],
                             "nvidia-hybrid-cuda-node-open-lifecycle-comparison-v3")
            self.assertEqual(data["observations"][0]["inputs"]["rtx5080"]["driver"],
                             "595.99.02")
            self.assertEqual(data["observations"][0]["inputs"]["v100"]["driver"],
                             "580.178.04")
            rtx = data["observations"][0]["inputs"]["rtx5080"]
            by_value = {item["value_hex"]: item for item in rtx["commands"]}
            self.assertEqual(by_value["0x17"]["count"], 2)
            self.assertEqual(by_value["0x17"]["names_by_source"]["r580_open"],
                             ["UVM_CREATE_RANGE_GROUP"])
            self.assertEqual(rtx["unmapped_requests"], [{"value_hex": "0xee", "count": 3}])
            self.assertFalse(rtx["input_claims_uvm_workload_validated"])
            self.assertFalse(data["scope"]["strace_sidecars_read"])
            self.assertFalse(data["scope"]["hardware_compatibility_established"])


if __name__ == "__main__":
    unittest.main()
