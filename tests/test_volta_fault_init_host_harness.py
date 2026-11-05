import importlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_NAME = "tools.run_volta_fault_init_host_harness"


class VoltaFaultInitHostHarnessTest(unittest.TestCase):
    def test_exact_replayable_fault_buffer_init_contract(self):
        spec = importlib.util.find_spec(MODULE_NAME)
        self.assertIsNotNone(spec, "exact-source fault-buffer init harness has not been added")
        harness = importlib.import_module(MODULE_NAME)

        with tempfile.TemporaryDirectory(prefix="volta-fault-init-test-") as directory:
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
            self.assertEqual("codex.volta-fault-init-host-harness.v4", report["schema"])
            self.assertEqual(2, report["implementations_executed"])
            self.assertEqual(15, report["vectors_per_implementation"])
            self.assertGreater(report["checks_per_implementation"], 67)
            self.assertEqual(2 * report["checks_per_implementation"], report["checks_passed"])
            self.assertEqual(6, report["expected_guard_count"])
            self.assertFalse(report["hardware_validated"])
            self.assertFalse(report["module_loaded"])
            self.assertEqual("host-cpu-execution-of-pinned-volta-fault-buffer-lifecycle-v5",
                             report["classification"])
            self.assertEqual(
                "v4 used synthetic non-replayable callbacks; v5 executes the exact pinned R580/R595 helpers through parent init, unwind, and teardown",
                report["supersedes"]["reason"],
            )
            self.assertEqual(
                "8af117f2c38f592c1e1facf2c7c913d3d5f715233759a0f29b9d1d48c2cfe0a5",
                report["source_pair"]["r580"]["fault_buffer_deinit_body_sha256"],
            )
            self.assertEqual(
                "0dce92b4c39fb4db283cb1d60aef691f5856e2b8daaea2010f7b7cc90be11372",
                report["source_pair"]["r595"]["fault_buffer_deinit_body_sha256"],
            )
            self.assertTrue(report["source_pair"]["r580"]["deinit_prefetch_capability_read_present"])
            self.assertFalse(report["source_pair"]["r595"]["deinit_prefetch_capability_read_present"])
            self.assertEqual(
                report["source_pair"]["r580"]["deinit_body_without_prefetch_expression_sha256"],
                report["source_pair"]["r595"]["deinit_body_without_prefetch_expression_sha256"],
            )
            self.assertEqual(4, report["partial_cleanup_vectors_per_implementation"])
            self.assertEqual(4, report["deinit_prefetch_vectors_per_implementation"])
            self.assertEqual(2, report["reinit_vectors_per_implementation"])
            self.assertEqual(5, report["outer_caller_vectors_per_implementation"])
            self.assertEqual(3, report["non_replayable_init_attempts_per_implementation"])
            self.assertEqual(5, report["non_replayable_deinit_calls_per_implementation"])
            self.assertEqual(
                "fb754753dcdcb2e85c33e0169d13aa267fb910964ffed87be0b49e65e0c25702",
                report["source_pair"]["r580"]["non_replayable_init_body_sha256"],
            )
            self.assertEqual(
                "9bfd56443847d2b34c7c9f268ef757fdf98138d8d0c16efb484920b6e69f4759",
                report["source_pair"]["r595"]["non_replayable_init_body_sha256"],
            )
            self.assertEqual(
                "46be8c999dca2c53f460f5ad03025243b48703bae62d75093dcc1aeb0b171946",
                report["source_pair"]["r580"]["non_replayable_deinit_body_sha256"],
            )
            self.assertEqual(
                report["source_pair"]["r580"]["non_replayable_deinit_body_sha256"],
                report["source_pair"]["r595"]["non_replayable_deinit_body_sha256"],
            )
            self.assertTrue(report["source_pair"]["r580"]["non_replayable_init_capability_assert_present"])
            self.assertFalse(report["source_pair"]["r595"]["non_replayable_init_capability_assert_present"])
            self.assertEqual(
                "5443ab1ea632d7c95f4f9e7df4964cf3fa93088c652d0678de6d71a746653a41",
                report["source_pair"]["r580"]["parent_fault_buffer_init_body_sha256"],
            )
            self.assertEqual(
                "d8ac4d8690ddf35245ac30c83bde7b5bd31ae5a78dacd1ec67aebd592ae536b1",
                report["source_pair"]["r595"]["parent_fault_buffer_init_body_sha256"],
            )
            self.assertTrue(report["source_pair"]["r580"]["replayable_capability_assert_in_parent_init"])
            self.assertFalse(report["source_pair"]["r595"]["replayable_capability_assert_in_parent_init"])
            self.assertTrue(report["source_pair"]["r580"]["replayable_capability_assert_in_parent_resume"])
            self.assertFalse(report["source_pair"]["r595"]["replayable_capability_assert_in_parent_resume"])
            self.assertTrue(report["source_pair"]["r580"]["nonreplayable_init_is_conditional"])
            self.assertFalse(report["source_pair"]["r595"]["nonreplayable_init_is_conditional"])
            self.assertTrue(report["source_pair"]["r580"]["nonreplayable_deinit_is_conditional"])
            self.assertFalse(report["source_pair"]["r595"]["nonreplayable_deinit_is_conditional"])
            self.assertEqual(
                "e8bbf1ac850e2483e25e64357366d5d52cc7390897499a11579565fb8cd93035",
                report["source_pair"]["r580"]["parent_resume_body_sha256"],
            )
            self.assertEqual(
                "7623abe672f950a6d89b452965c09cbdb2d42779ce6e9dec1dfa8aa703679f3b",
                report["source_pair"]["r595"]["parent_resume_body_sha256"],
            )
            self.assertEqual(
                "968290b9ae9e285fe9786479f4c19bcdef0d335ab2a7305b7985b727acc3587c",
                report["source_pair"]["r580"]["parent_deinit_body_sha256"],
            )
            self.assertEqual(
                "0d3c9ab13c084c3f55efad35658e9d1c58916cd7b89ff1f891d7016d7bd7d048",
                report["source_pair"]["r595"]["parent_deinit_body_sha256"],
            )
            self.assertEqual(
                ["uvm_parent_gpu_fault_buffer_init", "uvm_parent_gpu_fault_buffer_resume",
                 "uvm_parent_gpu_fault_buffer_deinit"],
                report["outer_caller_contract"]["executed_functions"],
            )
            self.assertEqual(5, len(report["outer_caller_contract"]["failure_paths"]))
            self.assertEqual(16, report["non_replayable_helper_contract"]["synthetic_inputs"]["test_cache_entry_size_bytes"])
            self.assertEqual(48, report["non_replayable_helper_contract"]["synthetic_inputs"]["test_fault_cache_allocation_bytes"])
            self.assertEqual(
                "reenable only when RM faultBufferHandle exists, prefetch is disabled, and prefetch_fault_supported is true",
                report["deinit_prefetch_contract"]["r580"],
            )
            self.assertEqual(
                "reenable when RM faultBufferHandle exists and prefetch is disabled",
                report["deinit_prefetch_contract"]["r595"],
            )

            r580 = report["source_pair"]["r580"]
            r595 = report["source_pair"]["r595"]
            self.assertEqual(
                "9fab37556fa02c9b7efd4c7ad59a5d6d92a3b6a2963800b5102a7ad566f8b473",
                r580["fault_buffer_init_body_sha256"],
            )
            self.assertEqual(
                "675c94f2d66a0614991f4042bf75c0006517ffbe38b42e46fc69ba3920935f2f",
                r595["fault_buffer_init_body_sha256"],
            )
            self.assertTrue(r580["prefetch_capability_read_present"])
            self.assertFalse(r595["prefetch_capability_read_present"])
            self.assertEqual(
                {"prefetch_fault_supported": True, "replayable_faults_supported": True,
                 "non_replayable_faults_supported": True},
                r580["capability_fields_present"],
            )
            self.assertEqual(
                {"prefetch_fault_supported": False, "replayable_faults_supported": False,
                 "non_replayable_faults_supported": False},
                r595["capability_fields_present"],
            )
            self.assertEqual(
                {"prefetch_fault_supported_true": True, "replayable_faults_supported_true": True,
                 "non_replayable_faults_supported_true": True},
                r580["volta_capability_initialization"],
            )
            self.assertEqual(
                {"prefetch_fault_supported_true": False, "replayable_faults_supported_true": False,
                 "non_replayable_faults_supported_true": False},
                r595["volta_capability_initialization"],
            )
            self.assertEqual(
                r580["fault_buffer_reinit_body_sha256"],
                r595["fault_buffer_reinit_body_sha256"],
            )
            self.assertEqual(
                r580["init_body_without_prefetch_expression_sha256"],
                r595["init_body_without_prefetch_expression_sha256"],
            )
            self.assertEqual(
                "enabled=false; callback=disable_prefetch_faults",
                report["prefetch_false_counterfactual"]["r580"],
            )
            self.assertEqual(
                "enabled=true; callback=enable_prefetch_faults",
                report["prefetch_false_counterfactual"]["r595"],
            )
            self.assertEqual("0600", report["report"]["mode"])
            self.assertEqual("0600", report["log"]["mode"])
            self.assertTrue(log_path.is_file())


if __name__ == "__main__":
    unittest.main()
