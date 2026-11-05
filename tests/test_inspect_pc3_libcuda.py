# SPDX-License-Identifier: MIT
"""Safety and provenance tests for the read-only PC3 libcuda inspection."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/inspect_pc3_libcuda.py"
SPEC = importlib.util.spec_from_file_location("inspect_pc3_libcuda", TOOL)
INSPECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECT)


def snapshot():
    return {
        "hostname": "pc3",
        "kernel": "7.0.0-38-generic",
        "nvidia_smi": [
            {"name": "NVIDIA GeForce RTX 5080",
             "uuid": "GPU-819a4547-5ff3-130b-ea3b-1d1a837b1c77",
             "pci_bus_id": "00000000:02:00.0", "driver_version": "595.99.02"}
        ],
        "libraries": [{
            "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02",
            "links": ["/usr/lib/x86_64-linux-gnu/libcuda.so"],
            "bytes": 91505672,
            "sha256": "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d",
            "build_id": "0123456789abcdef",
            "static_symbol_table": False,
            "dynamic_export_count": 1600,
            "dynamic_symbol_marker_matches": [],
            "string_marker_counts": {"BINAPI": 0, "FINN": 0,
                                      "20810108": 0, "NV2081": 0}
        }]
    }


class InspectPc3LibcudaTests(unittest.TestCase):
    def test_snapshot_accepts_only_expected_pc3_rtx5080_identity(self):
        result = INSPECT.validate_snapshot(snapshot())
        self.assertEqual(result["nvidia_smi"][0]["driver_version"], "595.99.02")
        self.assertEqual(result["nvidia_smi"][0]["pci_bus_id"], "0000:02:00.0")
        self.assertEqual(result["libraries"][0]["sha256"],
                         "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d")
        self.assertFalse(result["libraries"][0]["static_symbol_table"])

    def test_snapshot_rejects_wrong_host_or_unexpected_gpu(self):
        wrong_host = snapshot()
        wrong_host["hostname"] = "other"
        with self.assertRaises(ValueError):
            INSPECT.validate_snapshot(wrong_host)
        wrong_gpu = snapshot()
        wrong_gpu["nvidia_smi"][0]["uuid"] = "GPU-wrong"
        with self.assertRaises(ValueError):
            INSPECT.validate_snapshot(wrong_gpu)

    def test_cli_writes_private_report_and_refuses_overwrite(self):
        output = Path(tempfile.gettempdir()) / ("pc3-libcuda-test-" + str(id(self)) + ".json")
        try:
            fake = subprocess.CompletedProcess([], 0, json.dumps(snapshot()).encode(), b"")
            with mock.patch.object(INSPECT.subprocess, "run", return_value=fake) as run:
                self.assertEqual(INSPECT.main(["--output", str(output)]), 0)
                run.assert_called_once()
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            report = json.loads(output.read_text())
            self.assertEqual(report["qualification"], "read-only-static-inspection")
            self.assertFalse(report["gpu_workload_run"])
            self.assertFalse(report["library_contents_copied"])
            self.assertEqual(INSPECT.main(["--output", str(output)]), 2)
            run.assert_called_once()
        finally:
            output.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
