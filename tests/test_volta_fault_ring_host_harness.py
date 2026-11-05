import json
import tempfile
import unittest
from pathlib import Path

from tools import run_volta_fault_ring_host_harness as harness


class VoltaFaultRingHostHarnessTest(unittest.TestCase):
    def test_get_register_field_contract_rejects_a_changed_pointer_layout(self):
        with tempfile.TemporaryDirectory(prefix="volta-get-register-contract-") as directory:
            header = Path(directory) / "dev_fb.h"
            changed = dict(harness.VOLTA_GET_REGISTER_FIELDS)
            changed["NV_PFB_PRI_MMU_FAULT_BUFFER_GET_PTR"] = "18:0"
            header.write_text("".join(
                f"#define {name} {value} /* pinned fixture */\n"
                for name, value in changed.items()
            ), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "GET register field contract differs"):
                harness._read_get_register_contract(header)

    def test_exact_volta_put_get_callbacks_and_overflow_write_order(self):
        with tempfile.TemporaryDirectory(prefix="volta-fault-ring-test-") as directory:
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
            self.assertEqual(19, report["vectors_per_implementation"])
            self.assertEqual(11, report["ring_callback_vectors_per_implementation"])
            self.assertEqual(8, report["fault_buffer_flush_locked_cases_per_implementation"])
            self.assertEqual(244, report["checks_passed"])
            self.assertEqual("codex.volta-fault-ring-host-harness.v5", report["schema"])
            self.assertEqual(8, report["expected_guard_count"])
            self.assertEqual(4, len(report["assertion_guards_per_implementation"]))
            self.assertEqual(
                [
                    "--probe-put-getptr-corrupted",
                    "--probe-get-out-of-range",
                    "--probe-get-overflow-status",
                    "--probe-write-get-out-of-range",
                ],
                report["assertion_guards_per_implementation"],
            )
            self.assertEqual(1, report["release_status_probes_per_implementation"])
            self.assertEqual(2, report["release_status_probes_passed"])
            self.assertIn("test-only host model", report["release_assert_model"])
            self.assertEqual(
                report["source_pair"]["r580"]["function_body_sha256"],
                report["source_pair"]["r595"]["function_body_sha256"],
            )
            self.assertEqual(
                report["source_pair"]["r580"]["drain_service_body_sha256"],
                report["source_pair"]["r595"]["drain_service_body_sha256"],
            )
            self.assertEqual(
                "2bccc613de4d63a923f5fb07dbad7bda8c3bde0952ddb466b133c5eb2edab81a",
                report["source_pair"]["r580"]["fault_buffer_flush_locked_body_sha256"],
            )
            self.assertEqual(
                "84bd10cc2b37265fb93c1b8e289928a785f481736c575684eb49f9aae13c6260",
                report["source_pair"]["r595"]["fault_buffer_flush_locked_body_sha256"],
            )
            self.assertTrue(report["source_pair"]["r580"]["replayable_support_assert_present"])
            self.assertFalse(report["source_pair"]["r595"]["replayable_support_assert_present"])
            self.assertEqual(
                report["source_pair"]["r580"]["fault_buffer_flush_locked_body_without_support_assert_sha256"],
                report["source_pair"]["r595"]["fault_buffer_flush_locked_body_without_support_assert_sha256"],
            )
            for source in ("r580", "r595"):
                callbacks = report["source_pair"][source]["gv100_fault_buffer_callbacks"]
                self.assertEqual("uvm_hal_volta_fault_buffer_read_put", callbacks["read_put"])
                self.assertEqual("uvm_hal_volta_fault_buffer_read_get", callbacks["read_get"])
                self.assertEqual("uvm_hal_volta_fault_buffer_write_get", callbacks["write_get"])
                self.assertEqual("GV100", report["source_pair"][source]["gv100_callback_origins"]["write_get"])
                self.assertEqual("0600", report["report"]["mode"])
                self.assertEqual(
                    harness.VOLTA_GET_REGISTER_FIELDS,
                    report["source_pair"][source]["fault_buffer_get_register_fields"],
                )
            self.assertEqual(
                "0666a8f60e034f8461b06b208b1ebe8b8425ff91149fa956533c0a6bda3914d6",
                report["source_pair"]["r580"]["uvm_common_header_sha256"],
            )
            self.assertEqual(
                "c93140e96f0dc70b6ae94a80aca1015f95464161f2af2d719dde849c80c8f977",
                report["source_pair"]["r595"]["uvm_common_header_sha256"],
            )
            self.assertFalse(report["hardware_validated"])
            self.assertFalse(report["dma_ordering_validated"])
            self.assertTrue(log_path.is_file())


if __name__ == "__main__":
    unittest.main()
