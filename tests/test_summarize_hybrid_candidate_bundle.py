#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for sanitizing static four-module hybrid-bundle evidence."""

import unittest
import hashlib
import json
from pathlib import Path
import tempfile

from tools.summarize_hybrid_candidate_bundle import (
    _read_private_report,
    build_receipt,
)


def clean_closure(count=1):
    return {"import_count": count, "matched_by_provider": {"kernel": count},
            "crc_mismatches": [], "ambiguous_matches": []}


def fixture_report():
    modules = {
        "frontend": ("nvidia", ["hybrid580_legacy", "hybrid580_open"], "", "Dual MIT/GPL"),
        "legacy": ("hybrid580_legacy", [], "580.196.07", "NVIDIA"),
        "open": ("hybrid580_open", [], "595.99.02", "Dual MIT/GPL"),
        "uvm": ("nvidia_uvm", ["nvidia"], "595.112.07", "Dual MIT/GPL"),
    }
    report_modules = {}
    for index, (role, row) in enumerate(modules.items()):
        name, depends, version, license_name = row
        report_modules[role] = {
            "name": name, "depends": depends, "version": version,
            "license": license_name, "sha256": f"{index + 1:064x}",
            "vermagic": "7.0.0-38-generic SMP preempt modversions",
            "path": f"/private/build/{name}.ko",
        }
    empty_exports = {
        role: {"actual_export_count": 3, "expected_export_count": 3,
               "missing_exports": [], "unexpected_exports": [], "crc_mismatches": []}
        for role in ("frontend", "open", "legacy")
    }
    return {
        "schema": "hybrid-module-bundle-static-audit-v1",
        "status": "passed", "qualification": "static-module-bundle-closure",
        "kernel_release": "7.0.0-38-generic", "issues": [],
        "module_loaded": False, "module_installed": False,
        "runtime_or_hardware_validated": False, "modules": report_modules,
        "symbol_closure": {
            "frontend_imports": clean_closure(3),
            "uvm_imports": clean_closure(4),
            "frontend_private_import_count": 2,
            "provider_imports": {"open": clean_closure(1), "legacy": clean_closure(2)},
            "module_exports": empty_exports,
            "standard_uvm_interface_import_count": 2,
            "standard_uvm_interface_export_count": 3,
            "standard_uvm_interface_closure": {
                "missing_exports": [], "unexpected_exports": [],
                "missing_frontend_extensions": [], "crc_mismatches": [],
                "frontend_only_extensions": ["declared-extension"],
            },
        },
    }


class HybridCandidateBundleSummaryTests(unittest.TestCase):
    def test_receipt_is_path_free_and_preserves_module_identity_and_scope(self):
        receipt = build_receipt(fixture_report(), "a" * 64)
        serialized = str(receipt)
        self.assertEqual(receipt["modules"]["uvm"]["version"], "595.112.07")
        self.assertEqual(receipt["modules"]["uvm"]["sha256"], f"{4:064x}")
        self.assertEqual(receipt["symbol_closure"]["frontend_import_count"], 3)
        self.assertFalse(receipt["runtime"]["runtime_or_hardware_validated"])
        self.assertNotIn("/private/build", serialized)
        self.assertNotIn("path", serialized)

    def test_receipt_rejects_any_runtime_or_load_claim(self):
        report = fixture_report()
        report["module_loaded"] = True
        with self.assertRaisesRegex(ValueError, "no-load"):
            build_receipt(report, "a" * 64)

    def test_receipt_rejects_crc_or_dependency_closure_drift(self):
        report = fixture_report()
        report["symbol_closure"]["uvm_imports"]["crc_mismatches"] = ["symbol"]
        with self.assertRaisesRegex(ValueError, "crc_mismatches"):
            build_receipt(report, "a" * 64)
        report = fixture_report()
        report["modules"]["uvm"]["depends"] = []
        with self.assertRaisesRegex(ValueError, "dependency set"):
            build_receipt(report, "a" * 64)

    def test_private_report_reader_pins_mode_hash_and_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "private.json"
            data = json.dumps(fixture_report()).encode()
            raw.write_bytes(data)
            raw.chmod(0o600)
            digest = hashlib.sha256(data).hexdigest()
            parsed, actual = _read_private_report(raw, digest)
            self.assertEqual(actual, digest)
            self.assertEqual(parsed["status"], "passed")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                _read_private_report(raw, "f" * 64)
            raw.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                _read_private_report(raw, digest)

            link = Path(directory) / "link.json"
            link.symlink_to(raw)
            with self.assertRaises(OSError):
                _read_private_report(link, digest)


if __name__ == "__main__":
    unittest.main()
