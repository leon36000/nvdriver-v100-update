# SPDX-License-Identifier: MIT
"""Sanitized RM handle-to-class correlation tests."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/correlate_rm_object_classes.py"
SPEC = importlib.util.spec_from_file_location("rm_object_correlation", TOOL)
CORRELATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORRELATOR)


def allocation(root, handle, klass, *, parent=0, index=1, status=0,
               syscall_return=0, root_class=False):
    return {
        "operation": "alloc", "syscall_return": syscall_return,
        "entry": {"hRoot": root, "hObjectParent": parent,
                  "root_class": root_class},
        "exit": {"hObjectNew": handle, "hClass": klass, "status": status},
    }


def free(root, handle, *, status=0, syscall_return=0):
    return {
        "operation": "free", "syscall_return": syscall_return,
        "entry": {"hRoot": root, "hObjectOld": handle},
        "exit": {"status": status},
    }


def control(client, obj, *, command=0x20810108, size=992,
            syscall_return=0, entry_status=0, exit_status=0):
    entry = {"command": command, "params_size": size, "hClient": client,
             "hObject": obj, "flags": 0}
    exit = {**entry, "status": exit_status}
    entry["status"] = entry_status
    return {"operation": "rm_control_header", "syscall_return": syscall_return,
            "entry": entry, "exit": exit}


def observer(records, *, complete=True, nested=False):
    return {
        "schema": "nvidia-hybrid-rm-ioctl-observer-v5",
        "trace_complete": complete,
        "nested_pointers_read": nested,
        "payload_scope": "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted",
        "errors": [], "records": records,
    }


class RmObjectCorrelationTests(unittest.TestCase):
    def test_correlates_successful_live_binapi_object_without_emitting_handles(self):
        report = observer([
            allocation(0, 100, 0x41, root_class=True),
            allocation(100, 200, 0x2080, parent=100),
            allocation(100, 300, 0x2081, parent=200),
            control(100, 300),
        ])
        result = CORRELATOR.correlate(report, "a" * 64, case_name="v100")
        self.assertEqual(result["qualification"], "nv2081-control-object-correlated")
        self.assertEqual(result["controls"], [{
            "record_index": 3, "command": 0x20810108, "params_size": 992,
            "flags": 0, "outer_finn_serialized_flag_set": False,
            "transport_success": True, "entry_status": 0, "exit_status": 0,
            "header_stable": True, "client_root_class_id": 0x41,
            "object_class_id": 0x2081, "client_root_is_nv01_root_client": True,
            "object_is_nv2081_binapi": True,
        }])
        serialized = json.dumps(result)
        def values(value):
            if isinstance(value, dict):
                for nested in value.values():
                    yield from values(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from values(nested)
            else:
                yield value
        for raw in (100, 200, 300):
            self.assertNotIn(raw, values(result))
        for forbidden in ("hClient", "hObject", "params_address", "pAllocParms"):
            self.assertNotIn(forbidden, serialized)

    def test_wrong_root_wrong_class_and_handle_equal_client_do_not_match(self):
        report = observer([
            allocation(0, 100, 0x41, root_class=True),
            allocation(100, 300, 0x2081, parent=200),
            control(100, 301),
            allocation(0, 101, 0x41, root_class=True),
            control(101, 101),
            allocation(100, 302, 0x2080, parent=100),
            control(100, 302),
        ])
        result = CORRELATOR.correlate(report, "b" * 64, case_name="mixed")
        self.assertEqual([row["object_class_id"] for row in result["controls"]],
                         [None, 0x41, 0x2080])
        self.assertFalse(any(row["object_is_nv2081_binapi"]
                             for row in result["controls"]))
        self.assertEqual(result["qualification"], "nv2081-control-object-unresolved")

    def test_reports_only_the_documented_outer_finn_flag(self):
        root = allocation(0, 100, 0x41, root_class=True)
        item = control(100, 100)
        item["entry"]["flags"] = 0x4
        item["exit"]["flags"] = 0x4
        result = CORRELATOR.correlate(observer([root, item]), "f" * 64,
                                      case_name="flag")
        self.assertEqual(result["controls"][0]["flags"], 0x4)
        self.assertTrue(result["controls"][0]["outer_finn_serialized_flag_set"])

    def test_free_removes_live_class_before_control_and_failed_free_keeps_it(self):
        records = [allocation(0, 100, 0x41, root_class=True),
                   allocation(100, 300, 0x2081, parent=200),
                   free(100, 300, status=1), control(100, 300),
                   free(100, 300), control(100, 300)]
        result = CORRELATOR.correlate(observer(records), "c" * 64,
                                      case_name="lifetime")
        self.assertEqual(result["controls"][0]["object_class_id"], 0x2081)
        self.assertIsNone(result["controls"][1]["object_class_id"])

    def test_failed_allocations_are_not_correlated(self):
        report = observer([allocation(0, 100, 0x41, root_class=True),
                           allocation(100, 300, 0x2081, parent=200,
                                      status=1), control(100, 300)])
        result = CORRELATOR.correlate(report, "d" * 64, case_name="failed-alloc")
        self.assertIsNone(result["controls"][0]["object_class_id"])

    def test_rejects_partial_or_payload_decoding_reports(self):
        with self.assertRaisesRegex(ValueError, "complete"):
            CORRELATOR.correlate(observer([], complete=False), "e" * 64,
                                 case_name="partial")
        with self.assertRaisesRegex(ValueError, "nested payload"):
            CORRELATOR.correlate(observer([], nested=True), "e" * 64,
                                 case_name="nested")

    def test_finds_unique_wrapped_report_and_rejects_ambiguous_wrappers(self):
        report = observer([allocation(0, 100, 0x41, root_class=True),
                           allocation(100, 300, 0x2081), control(100, 300)])
        wrapped = {"remote": {"ioctl_observation": report}}
        self.assertIs(CORRELATOR.find_observer_report(wrapped), report)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            CORRELATOR.find_observer_report({"a": report, "b": report})

    def test_cli_writes_private_sanitized_report_exclusively(self):
        report = observer([allocation(0, 100, 0x41, root_class=True),
                           allocation(100, 300, 0x2081), control(100, 300)])
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            output = Path(temporary) / "safe.json"
            source.write_text(json.dumps({"remote": {"ioctl_observation": report}}))
            result = subprocess.run([sys.executable, str(TOOL), "--input", str(source),
                                     "--output", str(output), "--case", "v100"],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            emitted = output.read_text()
            self.assertNotIn('"hClient"', emitted)
            self.assertNotIn('"hObject"', emitted)
            self.assertIn('"object_class_id": 8321', emitted)
            again = subprocess.run([sys.executable, str(TOOL), "--input", str(source),
                                     "--output", str(output), "--case", "v100"],
                                   capture_output=True, text=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)


if __name__ == "__main__":
    unittest.main()
