# SPDX-License-Identifier: MIT
"""CPU-only schema fixtures for the Nsight Systems timeline auditor."""

import sqlite3
import tempfile
from pathlib import Path
import unittest

from tools.audit_nsys_concurrent_overlap import audit_nsys_sqlite


def create_trace(path: Path, *, overlap=True, wrong_bdf=False, wrong_kernel=False,
                 invalid_interval=False):
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE TARGET_INFO_GPU (
            id INTEGER NOT NULL, name TEXT, busLocation TEXT
        );
        CREATE TABLE StringIds (id INTEGER NOT NULL PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE CUPTI_ACTIVITY_KIND_KERNEL (
            start INTEGER NOT NULL, end INTEGER NOT NULL, deviceId INTEGER NOT NULL,
            demangledName INTEGER NOT NULL, shortName INTEGER NOT NULL
        );
        INSERT INTO TARGET_INFO_GPU VALUES (3, 'V100 fixture', '0000:01:00.0');
        INSERT INTO TARGET_INFO_GPU VALUES (9, 'RTX 5080 fixture', '0000:02:00.0');
        INSERT INTO StringIds VALUES (41, 'hybrid_concurrent_work');
        INSERT INTO StringIds VALUES (42, 'other_kernel');
    """)
    second_start = 1001 if not overlap else 800
    name_id = 42 if wrong_kernel else 41
    connection.execute("INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES (?, ?, ?, ?, ?)",
                       (100, 900 if not invalid_interval else 50, 3, name_id, name_id))
    connection.execute("INSERT INTO CUPTI_ACTIVITY_KIND_KERNEL VALUES (?, ?, ?, ?, ?)",
                       (second_start, 1300, 9, name_id, name_id))
    if wrong_bdf:
        connection.execute("UPDATE TARGET_INFO_GPU SET busLocation='0000:03:00.0' WHERE id=9")
    connection.commit()
    connection.close()


class NsightConcurrentOverlapAuditTests(unittest.TestCase):
    def test_validates_same_trace_kernel_intervals_on_the_exact_sm70_sm120_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.sqlite"
            create_trace(trace)
            report = audit_nsys_sqlite(trace, {
                70: "0000:01:00.0", 120: "0000:02:00.0"})
            self.assertEqual(report["status"], "validated-gpu-timeline-overlap")
            self.assertTrue(report["gpu_timeline_overlap_validated"])
            self.assertEqual(report["kernel_name"], "hybrid_concurrent_work")
            self.assertEqual(set(report["device_intervals"]), {"70", "120"})

    def test_host_overlap_or_unrelated_kernel_rows_cannot_substitute_for_gpu_overlap(self):
        for options in ({"overlap": False}, {"wrong_kernel": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                trace = Path(directory) / "trace.sqlite"
                create_trace(trace, **options)
                with self.assertRaises(ValueError):
                    audit_nsys_sqlite(trace, {
                        70: "0000:01:00.0", 120: "0000:02:00.0"})

    def test_wrong_gpu_mapping_and_invalid_timestamps_fail_closed(self):
        for options in ({"wrong_bdf": True}, {"invalid_interval": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                trace = Path(directory) / "trace.sqlite"
                create_trace(trace, **options)
                with self.assertRaises(ValueError):
                    audit_nsys_sqlite(trace, {
                        70: "0000:01:00.0", 120: "0000:02:00.0"})

    def test_unrecognized_or_incomplete_sqlite_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "empty.sqlite"
            connection = sqlite3.connect(trace)
            connection.execute("CREATE TABLE TARGET_INFO_GPU (id INTEGER)")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(ValueError, "schema"):
                audit_nsys_sqlite(trace, {
                    70: "0000:01:00.0", 120: "0000:02:00.0"})


if __name__ == "__main__":
    unittest.main()
