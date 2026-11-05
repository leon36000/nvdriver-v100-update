import json
import tempfile
import unittest
from pathlib import Path

from tools import run_volta_fault_decode_host_harness as harness


class VoltaFaultDecodeHostHarnessTest(unittest.TestCase):
    def test_replayable_and_nonreplayable_vectors_match_pinned_r580_and_r595(self):
        with tempfile.TemporaryDirectory(prefix="volta-fault-decode-test-") as directory:
            root = Path(directory)
            report_path = root / "report.json"
            log_path = root / "build.log"

            result = harness.run(
                harness.DEFAULT_R580_UVM,
                harness.DEFAULT_R595_UVM,
                report_path,
                log_path,
            )

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("passed", result["status"])
            self.assertEqual(2, report["implementations_executed"])
            self.assertEqual(148, report["vectors_per_implementation"])
            self.assertEqual(146, report["parser_vectors_per_implementation"])
            self.assertEqual(2, report["confidential_callback_cases_per_implementation"])
            self.assertEqual(6448, report["checks_passed"])
            self.assertEqual(4, len(report["assertion_guards_per_implementation"]))
            self.assertIn("--probe-out-of-range-index",
                          report["assertion_guards_per_implementation"])
            self.assertEqual(64, len(report["runner"]["sha256"]))
            for source in ("r580", "r595"):
                callbacks = report["source_pair"][source]["gv100_fault_buffer_callbacks"]
                self.assertEqual("uvm_hal_pascal_fault_buffer_entry_is_valid",
                                 callbacks["entry_is_valid"])
                self.assertEqual("uvm_hal_pascal_fault_buffer_entry_clear_valid",
                                 callbacks["entry_clear_valid"])
                self.assertEqual("uvm_hal_volta_fault_buffer_parse_replayable_entry",
                                 callbacks["parse_replayable_entry"])
                self.assertEqual("uvm_hal_volta_fault_buffer_parse_non_replayable_entry",
                                 callbacks["parse_non_replayable_entry"])
                self.assertEqual("uvm_hal_volta_fault_buffer_read_put", callbacks["read_put"])
                self.assertEqual("uvm_hal_volta_fault_buffer_read_get", callbacks["read_get"])
                self.assertEqual("uvm_hal_volta_fault_buffer_write_get", callbacks["write_get"])
                self.assertEqual(
                    "GP100" if source == "r580" else "GV100",
                    report["source_pair"][source]["gv100_fault_buffer_callback_origins"]["entry_is_valid"],
                )
                callback_hashes = report["source_pair"][source]["pascal_callback_body_sha256"]
                self.assertEqual({
                    "uvm_hal_pascal_fault_buffer_entry_is_valid":
                        "902c765da722f21acd27b65eacab76a5234c79763c60100f756a9d2bbe893d58",
                    "uvm_hal_pascal_fault_buffer_entry_clear_valid":
                        "b17827bbac3afed78e09b46f2d0059760a26de75efdac99de0535f4f45d315af",
                }, callback_hashes)
                layout = report["source_pair"][source]["pascal_c369_packet_contract"]
                self.assertEqual(layout["c369_packet_size_bytes"], layout["b069_packet_size_bytes"])
                self.assertEqual(layout["c369_valid_field"], layout["b069_valid_field"])
            self.assertEqual(
                report["source_pair"]["r580"]["pascal_callback_body_sha256"],
                report["source_pair"]["r595"]["pascal_callback_body_sha256"],
            )
            self.assertFalse(report["hardware_validated"])
            self.assertFalse(report["same_process_cuda_validated"])
            self.assertTrue(log_path.is_file())


if __name__ == "__main__":
    unittest.main()
