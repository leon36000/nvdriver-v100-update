# SPDX-License-Identifier: MIT
"""Adversarial tests for sanitizing private full-suite output."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.run_software_test_suite import (  # noqa: E402
    PINNED_PROBE_FATBIN_SHA256,
    PINNED_PROBE_SHA256,
)
from tools.summarize_private_software_suite import (  # noqa: E402
    read_private_regular,
    receipt_from_private_inputs,
    write_new_receipt,
)


def valid_inputs():
    log = b"test_one (test_x.TestX.test_one) ... ok\n\nRan 1 test in 0.001s\n\nOK\n"
    digest = "1" * 64
    report = {
        "schema": "software-verification-openrm-hal-matrix-v1",
        "status": "pass",
        "process_exit_code": 0,
        "qualification": "software-suite-only",
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "test_source_changes": [],
        "implementation_source_changes": [],
        "test_source_sha256": {"tests/test_x.py": digest},
        "test_source_sha256_after": {"tests/test_x.py": digest},
        "implementation_sha256": {"tools/x.py": digest},
        "implementation_sha256_after": {"tools/x.py": digest},
        "probe": {
            "sha256": PINNED_PROBE_SHA256,
            "build_manifest": {"sha256": "2" * 64},
        },
        "log_sha256": hashlib.sha256(log).hexdigest(),
        "tests_run": 1,
        "reported_seconds": 0.001,
        "command": ["python", "/private/path"],
        "evidence_root": "/private/worktree",
    }
    return json.dumps(report).encode(), log


class PrivateSoftwareSuiteSanitizerTests(unittest.TestCase):
    def test_valid_report_becomes_path_free_software_only_receipt(self):
        report, log = valid_inputs()
        receipt = receipt_from_private_inputs(report, log)
        encoded = json.dumps(receipt, sort_keys=True)
        self.assertEqual(receipt["tests_run"], 1)
        self.assertEqual(receipt["pinned_probe_sha256"], PINNED_PROBE_SHA256)
        self.assertEqual(receipt["pinned_probe_fatbin_sha256"], PINNED_PROBE_FATBIN_SHA256)
        self.assertEqual(receipt["private_log_sha256"], hashlib.sha256(log).hexdigest())
        self.assertNotIn("/private", encoded)
        self.assertNotIn("command", receipt)
        self.assertFalse(receipt["runtime_or_hardware_validated"])
        self.assertFalse(receipt["loaded_or_installed"])

    def test_rejects_failure_or_overstated_qualification(self):
        for field, value in (
            ("status", "fail"),
            ("runtime_or_hardware_validated", True),
            ("loaded_or_installed", True),
        ):
            report, log = valid_inputs()
            changed = json.loads(report)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                receipt_from_private_inputs(json.dumps(changed).encode(), log)

    def test_rejects_changed_source_maps_or_changes_during_run(self):
        for field, mutation in (
            ("test_source_sha256_after", {"tests/test_x.py": "3" * 64}),
            ("test_source_changes", ["tests/test_x.py"]),
            ("implementation_source_changes", ["tools/x.py"]),
        ):
            report, log = valid_inputs()
            changed = json.loads(report)
            changed[field] = mutation
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "changed"):
                receipt_from_private_inputs(json.dumps(changed).encode(), log)

    def test_rejects_mismatched_digest_probe_and_terminal_summary(self):
        report, log = valid_inputs()
        changed = json.loads(report)
        changed["log_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "does not match"):
            receipt_from_private_inputs(json.dumps(changed).encode(), log)
        changed = json.loads(report)
        changed["probe"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned CUDA probe"):
            receipt_from_private_inputs(json.dumps(changed).encode(), log)
        changed = json.loads(report)
        failed_log = b"FAILED (failures=1)\n"
        changed["log_sha256"] = hashlib.sha256(failed_log).hexdigest()
        with self.assertRaisesRegex(ValueError, "terminal summary"):
            receipt_from_private_inputs(json.dumps(changed).encode(), failed_log)

    def test_rejects_count_duration_and_invalid_hash_map(self):
        report, log = valid_inputs()
        for field, value, message in (
            ("tests_run", 2, "test count disagrees"),
            ("reported_seconds", 9.0, "duration disagrees"),
            ("test_source_sha256", {"tests/x.py": "not-a-hash"}, "invalid entry"),
        ):
            changed = json.loads(report)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                receipt_from_private_inputs(json.dumps(changed).encode(), log)

    def test_private_reader_requires_mode_0600_and_nofollow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "private.json"
            report.write_bytes(b"{}")
            report.chmod(0o600)
            self.assertEqual(read_private_regular(report), b"{}")
            report.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                read_private_regular(report)
            link = root / "link.json"
            link.symlink_to(report)
            with self.assertRaises(OSError):
                read_private_regular(link)

    def test_receipt_writer_is_0644_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "receipt.json"
            write_new_receipt(output, b'{"status":"pass"}\n')
            self.assertEqual(output.read_bytes(), b'{"status":"pass"}\n')
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                write_new_receipt(output, b"replace\n")


if __name__ == "__main__":
    unittest.main()
