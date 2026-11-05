# SPDX-License-Identifier: MIT
"""Tests for path-free R580/R595 static-source audit receipts."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.summarize_volta_uvm_candidate_paths import (  # noqa: E402
    EXPECTED_BRANCH,
    EXPECTED_CAPABILITY_FIELDS,
    EXPECTED_CANDIDATE_HAL_SHA256,
    EXPECTED_R580_ARCHIVE_SHA256,
    EXPECTED_R580_INITIALIZER_SHA256,
    EXPECTED_REPORT_SCHEMA,
    receipt_from_report,
    write_sanitized_receipt,
)


def sample_report():
    return {
        "schema": EXPECTED_REPORT_SCHEMA,
        "created_utc": "2026-11-03T04:10:51.252305+00:00",
        "classification": "pinned-static-source-callpath-audit",
        "candidate_branch": EXPECTED_BRANCH,
        "candidate_tree_is_experimental": True,
        "candidate_legacy_identifiers_absent_count": 11,
        "candidate_source": {
            "root": "/private/candidate",
            "hal_source_sha256": EXPECTED_CANDIDATE_HAL_SHA256,
            "uvm_source_file_count": 242,
            "uvm_source_manifest_sha256": "c0fbbd9549fd8347da11b3b53f10d2be514f90f9a33d03a123416a3c34bc5ccb",
        },
        "r580_source": {
            "archive": "/private/r580.tar.xz",
            "archive_sha256": EXPECTED_R580_ARCHIVE_SHA256,
            "volta_initializer_sha256": EXPECTED_R580_INITIALIZER_SHA256,
        },
        "capabilities": [
            {
                "field": field,
                "candidate_disposition": "static-candidate-path",
                "candidate_interpretation": "Source callback path selected.",
                "validation_needed": "Hardware validation remains required.",
                "runtime_or_hardware_validated": False,
                "candidate_source_anchors": [{"path": "uvm_hal.c", "line": 1}],
            }
            for field in sorted(EXPECTED_CAPABILITY_FIELDS)
        ],
        "p2p_direction_mapping": {
            "classification": "static-r595-uvm-p2p-direction-consumer-audit",
            "consumer_direction_contract": {
                "capability_query_handle_order": "ascending UVM parent GPU ID",
                "index_copy_behavior": "UVM copies indices 0 and 1 without swapping",
                "bar1PcieAtomics_index_0": "lower-ID local GPU accessing higher-ID peer",
                "bar1PcieAtomics_index_1": "higher-ID local GPU accessing lower-ID peer",
            },
            "rm_capability_values_observed": False,
            "runtime_or_hardware_validated": False,
            "source_scan": {
                "c_header_file_count": 625,
                "qualification": "no-definition-found-in-scanned-candidate-C-H-source",
                "rm_gpu_ops_get_p2p_caps_definition_count": 0,
            },
            "validation_needed": "Validate both directions on a canary.",
            "candidate_source_anchors": [{"path": "uvm_gpu.c"}],
        },
        "prefetch_callback_comparison": {
            "candidate_callback_selection": "GV100 selects Turing MMU callbacks",
            "control_helper": {
                "identical_after_comments_literals_and_whitespace_masked": True,
                "operation": "Toggle prefetch faults through the mapped control.",
                "candidate": {"path": "uvm_turing_mmu.c"},
                "r580": {"path": "uvm_pascal_mmu.c"},
            },
            "enable_wrapper_guard": {
                "candidate_prefetch_fault_supported_assertion": False,
                "r580_prefetch_fault_supported_assertion": True,
                "interpretation": "Modern candidate replaces the old guard with runtime state.",
            },
            "runtime_or_hardware_validated": False,
            "validation_needed": "Validate prefetch delivery on GV100.",
        },
        "noncoherent_aperture_comparison": {
            "candidate": {
                "checks": {
                    "bar1_p2p_selects_noncoherent_when_pcie_atomics_unavailable": True,
                    "pte_sets_noncoherent_aperture_value": True,
                    "pte_uses_system_address_for_noncoherent_aperture": True,
                    "volta_ce_maps_noncoherent_sysmem": True,
                },
                "pte_source": {"path": "uvm_volta_mmu.c"},
            },
            "interpretation": "Static candidate encodes and maps noncoherent aperture.",
            "runtime_or_hardware_validated": False,
            "validation_needed": "Validate RM P2P and BAR1 transfers on GV100.",
        },
        "limitations": [
            "Static source paths do not prove RM acceptance or hardware behavior.",
            "No module or GPU runtime validation was performed.",
        ],
    }


class SanitizeVoltaUvmCandidatePathsTests(unittest.TestCase):
    def test_receipt_is_path_free_and_binds_exact_raw_input(self):
        raw = json.dumps(sample_report()).encode("utf-8")
        receipt = receipt_from_report(raw)
        encoded = json.dumps(receipt, sort_keys=True)

        self.assertEqual(receipt["source_report_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(receipt["qualification"], "ANALYZED_STATICALLY")
        self.assertEqual(receipt["capability_count"], 11)
        self.assertFalse(receipt["runtime_or_hardware_validated"])
        self.assertNotIn("/private", encoded)
        self.assertNotIn("candidate_source_anchors", encoded)
        self.assertNotIn("r580_source", receipt)

    def test_rejects_missing_or_duplicate_capability(self):
        report = sample_report()
        report["capabilities"].pop()
        with self.assertRaisesRegex(ValueError, "exactly eleven"):
            receipt_from_report(json.dumps(report).encode())

        report = sample_report()
        report["capabilities"][-1]["field"] = report["capabilities"][0]["field"]
        with self.assertRaisesRegex(ValueError, "field set is incomplete"):
            receipt_from_report(json.dumps(report).encode())

    def test_rejects_changed_pins_and_runtime_claims(self):
        report = sample_report()
        report["candidate_source"]["hal_source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "not the pinned overlay"):
            receipt_from_report(json.dumps(report).encode())

        report = sample_report()
        report["capabilities"][0]["runtime_or_hardware_validated"] = True
        with self.assertRaisesRegex(ValueError, "runtime validation cannot be inferred"):
            receipt_from_report(json.dumps(report).encode())

    def test_rejects_absolute_paths_in_copied_text(self):
        report = sample_report()
        report["capabilities"][0]["candidate_interpretation"] = (
            "leaked /home/pc1/private/source.c")
        with self.assertRaisesRegex(ValueError, "absolute local path"):
            receipt_from_report(json.dumps(report).encode())

    def test_sanitized_writer_sets_mode_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt.json"
            write_sanitized_receipt(output, b"{}\n")
            self.assertEqual(output.read_bytes(), b"{}\n")
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                write_sanitized_receipt(output, b"changed\n")
            self.assertEqual(output.read_bytes(), b"{}\n")


if __name__ == "__main__":
    unittest.main()
