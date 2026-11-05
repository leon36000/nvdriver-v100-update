# SPDX-License-Identifier: MIT
"""Adversarial tests for the path-free R595 UVM call-edge receipt."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.summarize_r595_uvm_add_gpu_ghidra_receipt import (  # noqa: E402
    EXPECTED_GHIDRA_VERSION,
    EXPECTED_MODULE_LICENSE,
    EXPECTED_MODULE_SHA256,
    EXPECTED_MODULE_VERSION,
    EXPECTED_REA_VERSION,
    EXPECTED_VERMAGIC,
    PROCEDURE_EXPECTATIONS,
    _read_private_regular,
    receipt_from_reports,
    write_new_receipt,
)


MODULE_METADATA = {
    "version": EXPECTED_MODULE_VERSION,
    "license": EXPECTED_MODULE_LICENSE,
    "vermagic": EXPECTED_VERMAGIC,
}


def sample_report(key):
    expected = PROCEDURE_EXPECTATIONS[key]
    return {
        "records": [{
            "operation": "analyze_function",
            "provider": {
                "id": "ghidra",
                "name": "Ghidra",
                "version": EXPECTED_GHIDRA_VERSION,
            },
            "subject": {
                "local_path": "/private/build/nvidia-uvm.ko",
                "digest": {"sha256": EXPECTED_MODULE_SHA256},
            },
            "confidence": "observed",
            "authority": "shipped-artifact",
            "relationship_coverage": {"status": "complete"},
            "normalized_result": {
                "procedure": {"name": expected["procedure"], "address": "0x123456"},
                "callees": [{"name": expected["required_callee"]}],
                "callers": [{"name": expected["required_caller"]}],
            },
        }],
    }


def sample_pair():
    return (
        json.dumps(sample_report("global_init")).encode("utf-8"),
        json.dumps(sample_report("per_gpu_add")).encode("utf-8"),
    )


class R595UvmAddGpuGhidraReceiptTests(unittest.TestCase):
    def test_receipt_binds_both_functions_and_contains_only_sanitized_facts(self):
        global_raw, per_gpu_raw = sample_pair()
        receipt = receipt_from_reports(
            global_raw, per_gpu_raw, EXPECTED_MODULE_SHA256, MODULE_METADATA
        )

        self.assertEqual(receipt["rea_version"], EXPECTED_REA_VERSION)
        self.assertEqual(receipt["ghidra_version"], EXPECTED_GHIDRA_VERSION)
        self.assertEqual(receipt["module"]["sha256"], EXPECTED_MODULE_SHA256)
        self.assertTrue(receipt["procedures"]["global_init"]["required_direct_callee_observed"])
        self.assertTrue(receipt["procedures"]["per_gpu_add"]["required_direct_callee_observed"])
        self.assertEqual(
            receipt["procedures"]["per_gpu_add"]["procedure"], "add_gpu"
        )
        encoded = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("/private", encoded)
        self.assertNotIn("parent_gpu", encoded)
        self.assertNotIn("NV_STATUS __stdcall", encoded)
        self.assertNotIn("return 0;", encoded)
        self.assertFalse(receipt["pseudocode_retained"])
        self.assertFalse(receipt["runtime_or_hardware_validated"])

    def test_rejects_changed_identity_operation_coverage_and_module(self):
        global_raw, per_gpu_raw = sample_pair()
        mutations = (
            ("operation", "procedure_info", "not analyze_function"),
            ("confidence", "inferred", "not an observed artifact analysis"),
            ("authority", "documentation", "not an observed artifact analysis"),
        )
        for field, value, message in mutations:
            changed = sample_report("global_init")
            changed["records"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                receipt_from_reports(
                    json.dumps(changed).encode(), per_gpu_raw,
                    EXPECTED_MODULE_SHA256, MODULE_METADATA,
                )

        changed = sample_report("per_gpu_add")
        changed["records"][0]["relationship_coverage"]["status"] = "partial"
        with self.assertRaisesRegex(ValueError, "coverage is incomplete"):
            receipt_from_reports(
                global_raw, json.dumps(changed).encode(),
                EXPECTED_MODULE_SHA256, MODULE_METADATA,
            )
        with self.assertRaisesRegex(ValueError, "module bytes do not match"):
            receipt_from_reports(global_raw, per_gpu_raw, "0" * 64, MODULE_METADATA)
        with self.assertRaisesRegex(ValueError, "metadata"):
            receipt_from_reports(
                global_raw, per_gpu_raw, EXPECTED_MODULE_SHA256,
                {**MODULE_METADATA, "license": "Proprietary"},
            )

    def test_rejects_wrong_procedure_missing_or_ambiguous_edges(self):
        global_raw, per_gpu_raw = sample_pair()
        cases = (
            ("procedure", {"name": "uvm_ioctl", "address": "0x123456"}, "different procedure"),
            ("callees", [], "required direct callee is absent or ambiguous"),
            ("callers", [], "required direct caller is absent or ambiguous"),
        )
        for field, value, message in cases:
            changed = sample_report("per_gpu_add")
            changed["records"][0]["normalized_result"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                receipt_from_reports(
                    global_raw, json.dumps(changed).encode(),
                    EXPECTED_MODULE_SHA256, MODULE_METADATA,
                )

        changed = sample_report("per_gpu_add")
        edge = PROCEDURE_EXPECTATIONS["per_gpu_add"]["required_callee"]
        changed["records"][0]["normalized_result"]["callees"].append({"name": edge})
        with self.assertRaisesRegex(ValueError, "absent or ambiguous"):
            receipt_from_reports(
                global_raw, json.dumps(changed).encode(),
                EXPECTED_MODULE_SHA256, MODULE_METADATA,
            )

    def test_rejects_malformed_or_multiple_records(self):
        global_raw, per_gpu_raw = sample_pair()
        for raw, message in ((b"{broken", "not UTF-8 JSON"),
                             (b'{"records":[]}', "exactly one")):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, message):
                receipt_from_reports(
                    raw, per_gpu_raw, EXPECTED_MODULE_SHA256, MODULE_METADATA
                )
        changed = sample_report("global_init")
        changed["records"].append(changed["records"][0])
        with self.assertRaisesRegex(ValueError, "exactly one"):
            receipt_from_reports(
                json.dumps(changed).encode(), per_gpu_raw,
                EXPECTED_MODULE_SHA256, MODULE_METADATA,
            )

    def test_private_reader_requires_regular_mode_0600_nonsymlink_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_bytes(b"{}")
            report.chmod(0o600)
            self.assertEqual(_read_private_regular(report), b"{}")
            report.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                _read_private_regular(report)
            link = root / "report-link.json"
            link.symlink_to(report)
            with self.assertRaises(OSError):
                _read_private_regular(link)

    def test_writer_sets_transfer_safe_mode_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            write_new_receipt(output, b'{"safe":true}\n')
            self.assertEqual(output.read_bytes(), b'{"safe":true}\n')
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                write_new_receipt(output, b"replacement\n")


if __name__ == "__main__":
    unittest.main()
