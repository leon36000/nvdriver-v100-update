# SPDX-License-Identifier: MIT
"""Tests for the path-free REA/Ghidra summary of the open R595 UVM module."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.summarize_r595_uvm_ghidra_receipt import (  # noqa: E402
    EXPECTED_GHIDRA_VERSION,
    EXPECTED_MODULE_LICENSE,
    EXPECTED_MODULE_SHA256,
    EXPECTED_MODULE_VERSION,
    EXPECTED_PROCEDURE,
    EXPECTED_REA_VERSION,
    EXPECTED_VERMAGIC,
    EXPECTED_JAVA_VERSION,
    receipt_from_report,
    write_new_receipt,
)


MODULE_METADATA = {
    "version": EXPECTED_MODULE_VERSION,
    "license": EXPECTED_MODULE_LICENSE,
    "vermagic": EXPECTED_VERMAGIC,
}


def sample_report():
    return {
        "operation": "procedure_pseudo_code",
        "provider": {"id": "ghidra", "version": EXPECTED_GHIDRA_VERSION},
        "parameters": {"procedure": EXPECTED_PROCEDURE},
        "subject": {
            "local_path": "/private/build/nvidia-uvm.ko",
            "digest": {"sha256": EXPECTED_MODULE_SHA256},
        },
        "confidence": "observed",
        "authority": "shipped-artifact",
        "normalized_result": (
            "int uvm_hal_init_gpu(void) {\n"
            "  parent_gpu->rm_info.gpuArch = 0;\n"
            "  parent_gpu->rm_info.hostClass = 0;\n"
            "  parent_gpu->rm_info.ceClass = 0;\n"
            "  return 0;\n"
            "}\n"
        ),
    }


class R595UvmGhidraReceiptTests(unittest.TestCase):
    def test_receipt_binds_exact_open_module_and_does_not_retain_pseudocode(self):
        raw = json.dumps(sample_report()).encode("utf-8")
        receipt = receipt_from_report(raw, EXPECTED_MODULE_SHA256, MODULE_METADATA)

        self.assertEqual(receipt["rea_version"], EXPECTED_REA_VERSION)
        self.assertEqual(receipt["ghidra_version"], EXPECTED_GHIDRA_VERSION)
        self.assertEqual(receipt["java_version"], EXPECTED_JAVA_VERSION)
        self.assertEqual(receipt["rea_report_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt["module"]["sha256"], EXPECTED_MODULE_SHA256)
        self.assertFalse(receipt["pseudocode_retained"])
        self.assertFalse(receipt["runtime_or_hardware_validated"])
        self.assertNotIn("/private", json.dumps(receipt))
        self.assertNotIn("parent_gpu", json.dumps(receipt))

    def test_rejects_changed_module_provider_and_procedure(self):
        report = json.dumps(sample_report()).encode()
        with self.assertRaisesRegex(ValueError, "different procedure"):
            changed = sample_report()
            changed["parameters"]["procedure"] = "uvm_ioctl"
            receipt_from_report(json.dumps(changed).encode(), EXPECTED_MODULE_SHA256, MODULE_METADATA)
        with self.assertRaisesRegex(ValueError, "module bytes do not match"):
            receipt_from_report(report, "0" * 64, MODULE_METADATA)
        with self.assertRaisesRegex(ValueError, "did not use Ghidra"):
            changed = sample_report()
            changed["provider"]["id"] = "ida"
            receipt_from_report(json.dumps(changed).encode(), EXPECTED_MODULE_SHA256, MODULE_METADATA)

    def test_rejects_missing_selector_and_comment_only_false_positive(self):
        changed = sample_report()
        changed["normalized_result"] = (
            "int uvm_hal_init_gpu(void) {\n"
            "  parent_gpu->rm_info.gpuArch = 0;\n"
            "  parent_gpu->rm_info.hostClass = 0;\n"
            "  /* ceClass */ return 0;\n"
            "}\n"
        )
        with self.assertRaisesRegex(ValueError, "does not expose all three"):
            receipt_from_report(json.dumps(changed).encode(), EXPECTED_MODULE_SHA256, MODULE_METADATA)

    def test_rejects_changed_module_metadata_and_missing_decomp(self):
        with self.assertRaisesRegex(ValueError, "metadata"):
            receipt_from_report(
                json.dumps(sample_report()).encode(), EXPECTED_MODULE_SHA256,
                {**MODULE_METADATA, "license": "Proprietary"},
            )
        changed = sample_report()
        changed["operation"] = "procedure_info"
        with self.assertRaisesRegex(ValueError, "did not return procedure pseudocode"):
            receipt_from_report(json.dumps(changed).encode(), EXPECTED_MODULE_SHA256, MODULE_METADATA)

    def test_rejects_malformed_report_metadata_without_attribute_errors(self):
        for field, value, message in (
            ("provider", [], "no provider metadata"),
            ("parameters", None, "no procedure metadata"),
            ("subject", {"digest": []}, "no subject digest"),
        ):
            changed = sample_report()
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                receipt_from_report(json.dumps(changed).encode(), EXPECTED_MODULE_SHA256, MODULE_METADATA)

    def test_writer_sets_mode_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            write_new_receipt(output, b"{}\n")
            self.assertEqual(output.read_bytes(), b"{}\n")
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                write_new_receipt(output, b"other\n")


if __name__ == "__main__":
    unittest.main()
