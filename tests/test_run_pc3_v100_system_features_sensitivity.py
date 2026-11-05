#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU contract tests for the isolated V100 feature-mask sensitivity runner."""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_pc3_v100_system_features_sensitivity.py"


def load_tool():
    if not TOOL.is_file():
        return None
    spec = importlib.util.spec_from_file_location("v100_system_features_sensitivity", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("sensitivity runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guest_report():
    masks = (9, 8, 1, 0)
    return {
        "schema": "nvidia-hybrid-v100-system-features-sensitivity-guest-v1",
        "hostname": "pc3-v100",
        "kernel_release": "6.8.0-147-generic",
        "gpu": {
            "name": "Tesla V100-SXM2-16GB",
            "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e",
            "pci": "0000:00:05.0",
            "driver_version": "580.178.04",
        },
        "libcuda": {
            "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
            "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
            "driver_api": 13000,
        },
        "gpu_compute_processes_before": [],
        "gpu_compute_processes_after": [],
        "caller_chain_capture_requested": False,
        "runs": [
            {
                "requested_mask": mask,
                "ioctl_records": [
                    {"transport": "direct", "kernel_mask": 9, "exposed_mask": mask,
                     "caller_image": "libcuda.so.580.178.04", "caller_offset": "0x1a2b"}
                ],
                "cuda": {
                    "cu_init": 0,
                    "device_count_status": 0,
                    "device_count": 1,
                    "driver_api": 13000,
                    "device": {
                        "name": "Tesla V100-SXM2-16GB",
                        "pci": "0000:00:05.0",
                        "compute_capability": [7, 0],
                        "attributes": {"concurrent_managed_access": 1,
                                       "pageable_memory_access": 0,
                                       "pageable_memory_access_uses_host_page_tables": 0},
                    },
                },
            }
            for mask in masks
        ],
        "cleanup_passed": True,
        "driver_or_module_changed": False,
        "gpu_reset_requested": False,
    }


def gpu_name_caller_record(offset="0x123456", chain=None):
    return {
        "command": "0x20800110",
        "transport": "direct",
        "flags": 0,
        "params_size": 132,
        "ioctl_result": 0,
        "embedded_status": 0,
        "caller_image": "libcuda.so.580.178.04",
        "caller_offset": offset,
        "caller_chain_offsets": ["0x123400"] if chain is None else chain,
        "caller_chain_anchor_found": True,
        "caller_chain_truncated": False,
    }


def gpu_name_stage_counts(record_count):
    stages = ("before_libcuda_load", "after_libcuda_load", "after_cu_init",
              "after_cu_driver_get_version", "after_cu_device_get_count",
              "after_cu_device_get", "after_cu_device_get_name")
    return [{"stage": stage, "records": record_count if index == len(stages) - 1 else 0}
            for index, stage in enumerate(stages)]


def kernel_phase_result():
    return {
        "schema": "nvidia-hybrid-v100-sm70-driver-api-kernel-v1",
        "status": "phase-passed",
        "phase": "kernel",
        "expected_pci": "0000:00:05.0",
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
        "driver_api": 13000,
        "device": {
            "name": "Tesla V100-SXM2-16GB",
            "pci_bus_id": "0000:00:05.0",
            "sm": 70,
            "compute_capability": "7.0",
        },
        "cubin_sha256": "8e175174646caaabd3590d13f6bc0d3269708a9c07246c409e62e5d7c967ad50",
        "cubin_digest_passed": True,
        "completed_operations": [
            "cuInit", "cuDriverGetVersion", "cuDeviceGetCount", "cuDeviceGet",
            "cuCtxCreate_v2", "cuModuleLoadData", "cuMemAlloc_v2", "cuLaunchKernel",
            "cuCtxSynchronize", "cuMemcpyDtoH_v2", "cuMemFree_v2", "cuModuleUnload",
            "cuCtxDestroy_v2",
        ],
        "numeric_result_passed": True,
        "result_value": 700,
        "expected_result": 700,
        "cleanup_passed": True,
        "cleanup_errors": [],
        "error": "",
    }


def guest_kernel_report():
    report = guest_report()
    report["schema"] = "nvidia-hybrid-v100-system-features-kernel-sensitivity-guest-v1"
    report["workload"] = "sm70-kernel"
    report["status"] = "observed"
    report["temporary_payload_remaining"] = False
    report["execution_scope"] = {
        "read_only": True,
        "experimental_module_loaded": False,
        "stock_driver_changed": False,
        "pci_binding_changed": False,
        "vm_management_issued": False,
        "gpu_reset_requested": False,
    }
    report["kernel_artifacts"] = {
        "probe_source_sha256": "d90f6cce9f46031d4f1c42c23cb6e21c57689633b1a88bc63edfd220d066b596",
        "sm70_cubin_sha256": "8e175174646caaabd3590d13f6bc0d3269708a9c07246c409e62e5d7c967ad50",
    }
    controls = []
    for mode in ("stock", "preload_passthrough"):
        controls.append({"mode": mode, "probe_exit_code": 0,
                         "cuda": kernel_phase_result()})
    report["controls"] = controls
    for run in report["runs"]:
        run["probe_exit_code"] = 0
        run["cuda"] = kernel_phase_result()
    return report


class Pc3V100SystemFeaturesSensitivityTests(unittest.TestCase):
    def test_current_pinned_transport_helper_loads(self):
        self.assertIsNotNone(self.tool)
        audit = self.tool.load_pinned_script(
            "pc3_v100_trace_capability_helper_test",
            self.tool.TRACE_AUDIT_TOOL,
            self.tool.TRACE_AUDIT_TOOL_SHA256,
        )
        self.assertTrue(callable(audit.remote_root_script))
        reference = self.tool.load_pinned_script(
            "pc3_v100_reference_transport_test",
            self.tool.REFERENCE_TOOL,
            self.tool.REFERENCE_TOOL_SHA256,
        )
        self.assertTrue(callable(reference.fetch_pc3_sudo_secret))
        self.assertTrue(callable(reference.pc3_ssh_base))

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def test_exact_masks_and_cuda_enumeration_are_accepted(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        result = self.tool.validate_guest_sensitivity(guest_report())
        self.assertEqual([run["requested_mask"] for run in result["runs"]], [9, 8, 1, 0])
        self.assertTrue(result["api_outcomes_equal"])

    def test_report_rejects_a_mask_not_exposed_to_userland(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        report["runs"][1]["ioctl_records"][0]["exposed_mask"] = 9
        with self.assertRaisesRegex(ValueError, "override mask"):
            self.tool.validate_guest_sensitivity(report)

    def test_report_requires_a_redacted_ioctl_caller_location(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        del report["runs"][0]["ioctl_records"][0]["caller_offset"]
        with self.assertRaisesRegex(ValueError, "caller location"):
            self.tool.validate_guest_sensitivity(report)

    def test_report_rejects_a_raw_caller_path(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        report["runs"][0]["ioctl_records"][0]["caller_image"] = (
            "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04")
        with self.assertRaisesRegex(ValueError, "caller location"):
            self.tool.validate_guest_sensitivity(report)

    def test_report_rejects_gpu_state_or_driver_changes(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        report["driver_or_module_changed"] = True
        with self.assertRaisesRegex(ValueError, "execution scope"):
            self.tool.validate_guest_sensitivity(report)

    def test_cuda_attribute_change_is_reported_as_sensitivity(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        report["runs"][3]["cuda"]["device"]["attributes"]["concurrent_managed_access"] = 0
        result = self.tool.validate_guest_sensitivity(report)
        self.assertFalse(result["api_outcomes_equal"])
        self.assertTrue(result["complete"])

    def test_absent_ioctl_is_retained_as_an_incomplete_mask_run(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        report["runs"][2]["ioctl_records"] = []
        result = self.tool.validate_guest_sensitivity(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["runs"][2]["override_observed"])

    def test_preload_passthrough_must_match_stock_cuda_control(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        stock = report["runs"][0]["cuda"]
        changed = guest_report()["runs"][0]["cuda"]
        changed["cu_init"] = 1
        report["controls"] = [
            {"mode": "stock", "probe_exit_code": 0, "cuda": stock},
            {"mode": "preload_passthrough", "probe_exit_code": 0, "cuda": changed},
        ]
        result = self.tool.validate_guest_sensitivity(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["control_outcomes_equal"])

    def test_gpu_name_caller_trace_requires_successful_redacted_r580_records(self):
        report = guest_report()
        report["gpu_name_caller_trace_requested"] = True
        signatures = [gpu_name_caller_record()]
        for run in report["runs"]:
            run["gpu_name_string_records"] = signatures
            run["cuda"]["gpu_name_trace_stage_counts"] = gpu_name_stage_counts(1)
        control_cuda = report["runs"][0]["cuda"]
        stock_cuda = {key: value for key, value in control_cuda.items()
                      if key != "gpu_name_trace_stage_counts"}
        report["controls"] = [
            {"mode": "stock", "probe_exit_code": 0, "cuda": stock_cuda},
            {"mode": "preload_passthrough", "probe_exit_code": 0,
             "cuda": control_cuda, "gpu_name_string_records": signatures},
        ]
        result = self.tool.validate_guest_sensitivity(report)
        self.assertTrue(result["complete"])
        self.assertTrue(result["control_outcomes_equal"])
        self.assertTrue(result["gpu_name_caller_trace_complete"])
        self.assertEqual(result["gpu_name_trace_stage_deltas"][-1],
                         {"after_stage": "after_cu_device_get_name", "new_records": 1})
        self.assertEqual(result["runs"][0]["gpu_name_string_records"], signatures)

    def test_gpu_name_caller_trace_rejects_wrong_abi_and_pointer_offsets(self):
        for field, value in (("params_size", 68),
                             ("caller_offset", "0x7fff12345678")):
            with self.subTest(field=field):
                report = guest_report()
                report["gpu_name_caller_trace_requested"] = True
                record = gpu_name_caller_record()
                record[field] = value
                for run in report["runs"]:
                    run["gpu_name_string_records"] = [record]
                    run["cuda"]["gpu_name_trace_stage_counts"] = gpu_name_stage_counts(1)
                control_cuda = report["runs"][0]["cuda"]
                report["controls"] = [
                    {"mode": "stock", "probe_exit_code": 0, "cuda": control_cuda},
                    {"mode": "preload_passthrough", "probe_exit_code": 0,
                     "cuda": control_cuda, "gpu_name_string_records": [record]},
                ]
                with self.assertRaisesRegex(ValueError, "GPU name"):
                    self.tool.validate_guest_sensitivity(report)

    def test_gpu_name_caller_trace_marks_nonmatching_sites_incomplete(self):
        report = guest_report()
        report["gpu_name_caller_trace_requested"] = True
        for run in report["runs"]:
            run["gpu_name_string_records"] = [gpu_name_caller_record("0x123456")]
            run["cuda"]["gpu_name_trace_stage_counts"] = gpu_name_stage_counts(1)
        control_cuda = report["runs"][0]["cuda"]
        report["controls"] = [
            {"mode": "stock", "probe_exit_code": 0, "cuda": control_cuda},
            {"mode": "preload_passthrough", "probe_exit_code": 0,
             "cuda": control_cuda,
             "gpu_name_string_records": [gpu_name_caller_record("0x123457")]},
        ]
        result = self.tool.validate_guest_sensitivity(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["gpu_name_caller_trace_complete"])

    def test_requested_caller_chain_must_be_present_and_redacted(self):
        self.assertIsNotNone(self.tool,
                             "the V100 feature-mask sensitivity runner is missing")
        report = guest_report()
        report["caller_chain_capture_requested"] = True
        with self.assertRaisesRegex(ValueError, "caller chain"):
            self.tool.validate_guest_sensitivity(report)

    def test_requested_caller_chain_accepts_bounded_relative_offsets(self):
        report = guest_report()
        report["caller_chain_capture_requested"] = True
        chain = [f"0x{0x48bd02 + index * 4:x}" for index in range(24)]
        for run in report["runs"]:
            run["ioctl_records"][0].update({
                "caller_chain_offsets": chain,
                "caller_chain_anchor_found": True,
                "caller_chain_truncated": False,
            })
        result = self.tool.validate_guest_sensitivity(report)
        self.assertTrue(result["complete"])
        self.assertTrue(result["caller_chain_capture_requested"])

    def test_requested_caller_chain_rejects_more_than_capture_bound(self):
        report = guest_report()
        report["caller_chain_capture_requested"] = True
        chain = [f"0x{0x48bd02 + index * 4:x}" for index in range(25)]
        for run in report["runs"]:
            run["ioctl_records"][0].update({
                "caller_chain_offsets": chain,
                "caller_chain_anchor_found": True,
                "caller_chain_truncated": False,
            })
        with self.assertRaisesRegex(ValueError, "caller chain"):
            self.tool.validate_guest_sensitivity(report)

    def test_unresolved_caller_chain_is_incomplete_but_preserved(self):
        report = guest_report()
        report["caller_chain_capture_requested"] = True
        for run in report["runs"]:
            run["ioctl_records"][0].update({
                "caller_chain_offsets": [],
                "caller_chain_anchor_found": False,
                "caller_chain_truncated": False,
            })
        result = self.tool.validate_guest_sensitivity(report)
        self.assertFalse(result["complete"])
        self.assertEqual(result["runs"][0]["ioctl_records"][0]["caller_chain_offsets"], [])

    def test_caller_chain_rejects_pointer_like_offsets(self):
        report = guest_report()
        report["caller_chain_capture_requested"] = True
        for run in report["runs"]:
            run["ioctl_records"][0].update({
                "caller_chain_offsets": ["0x7fff12345678"],
                "caller_chain_anchor_found": True,
                "caller_chain_truncated": False,
            })
        with self.assertRaisesRegex(ValueError, "caller chain"):
            self.tool.validate_guest_sensitivity(report)

    def test_generated_guest_code_is_valid_for_both_capture_modes(self):
        with tempfile.TemporaryDirectory(prefix="guest-code-contract-") as directory:
            shim = Path(directory) / "shim.so"
            shim.write_bytes(b"test-only shim payload")
            for capture in (False, True):
                code = self.tool.make_guest_code(shim, capture)
                ast.parse(code)
                self.assertIn(f"CAPTURE_CALLER_CHAIN = {capture}", code)
                self.assertIn('outcome = execute_probe(', code)
                if capture:
                    self.assertIn('env["HYBRID_FEATURES_CAPTURE_CALL_CHAIN"] = "1"', code)

    def test_generated_guest_code_enables_gpu_name_caller_trace_only_when_requested(self):
        with tempfile.TemporaryDirectory(prefix="guest-name-caller-code-contract-") as directory:
            shim = Path(directory) / "shim.so"
            shim.write_bytes(b"test-only shim payload")
            code = self.tool.make_guest_code(shim, capture_gpu_name_callers=True)
            tree = ast.parse(code)
            self.assertIn("CAPTURE_GPU_NAME_CALLERS = True", code)
            self.assertIn('env["HYBRID_GPU_NAME_CALLER_TRACE_PATH"]', code)
            self.assertIn('"gpu_name_string_records"', code)
            probe_b64 = next(node.value.value for node in tree.body
                             if isinstance(node, ast.Assign) and
                             any(isinstance(target, ast.Name) and target.id == "PROBE_B64"
                                 for target in node.targets))
            probe_source = base64.b64decode(probe_b64).decode("utf-8")
            ast.parse(probe_source)
            self.assertIn('sample_name_trace("after_cu_init")', probe_source)
            self.assertIn('sample_name_trace("after_cu_device_get_name")', probe_source)
            with self.assertRaisesRegex(ValueError, "only to enumeration"):
                self.tool.make_guest_code(shim, workload="sm70-kernel",
                                          capture_gpu_name_callers=True)

    def test_sm70_kernel_sensitivity_requires_exact_phase_and_numeric_result(self):
        report = guest_kernel_report()
        result = self.tool.validate_guest_kernel_sensitivity(report)
        self.assertTrue(result["complete"])
        self.assertTrue(result["api_outcomes_equal"])
        self.assertEqual(result["runs"][0]["cuda"]["result_value"], 700)

    def test_kernel_mask_failure_is_preserved_as_incomplete_evidence(self):
        report = guest_kernel_report()
        phase = report["runs"][2]["cuda"]
        phase["status"] = "phase-failed"
        phase["numeric_result_passed"] = False
        phase["result_value"] = None
        phase["expected_result"] = None
        phase["error"] = "architecture kernel failed"
        report["runs"][2]["probe_exit_code"] = 2
        result = self.tool.validate_guest_kernel_sensitivity(report)
        self.assertFalse(result["complete"])
        self.assertEqual(result["runs"][2]["cuda"]["error"],
                         "architecture kernel failed")

    def test_kernel_sensitivity_rejects_wrong_pci_or_unpinned_artifacts(self):
        report = guest_kernel_report()
        report["runs"][0]["cuda"]["device"]["pci_bus_id"] = "0000:00:06.0"
        with self.assertRaisesRegex(ValueError, "kernel phase identity"):
            self.tool.validate_guest_kernel_sensitivity(report)
        report = guest_kernel_report()
        report["runs"][0]["cuda"]["cubin_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "kernel phase identity"):
            self.tool.validate_guest_kernel_sensitivity(report)

    def test_kernel_guest_template_stages_pinned_probe_and_sm70_image(self):
        with tempfile.TemporaryDirectory(prefix="guest-kernel-code-contract-") as directory:
            shim = Path(directory) / "shim.so"
            shim.write_bytes(b"test-only shim payload")
            code = self.tool.make_guest_code(shim, workload="sm70-kernel")
            tree = ast.parse(code)
            self.assertIn('WORKLOAD = "sm70-kernel"', code)
            probe_b64 = next(node.value.value for node in tree.body
                             if isinstance(node, ast.Assign) and
                             any(isinstance(target, ast.Name) and target.id == "PROBE_B64"
                                 for target in node.targets))
            probe_source = base64.b64decode(probe_b64).decode("utf-8")
            ast.parse(probe_source)
            self.assertIn("cuLaunchKernel", probe_source)
            self.assertIn(self.tool.KERNEL_PROBE_SOURCE_SHA256, code)
            self.assertIn(self.tool.KERNEL_SM70_CUBIN_SHA256, probe_source)

    def test_sm70_probe_driver_api_sequence_and_cleanup_against_cpu_fake(self):
        with tempfile.TemporaryDirectory(prefix="fake-cuda-sm70-") as directory:
            root = Path(directory)
            library = root / "libcuda-test.so"
            fixture = ROOT / "tests/fixtures/fake_cuda_driver_sm70_kernel.c"
            built = subprocess.run(
                ["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                 str(fixture), "-o", str(library)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=15, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            cubin = b"synthetic SM70 image used only by the CPU ABI fixture"
            source = self.tool.KERNEL_PROBE_SOURCE.read_text(encoding="utf-8")
            source = source.replace("__LIBCUDA_PATH__", str(library))
            source = source.replace("__CUBIN_B64__", base64.b64encode(cubin).decode("ascii"))
            source = source.replace("__CUBIN_SHA256__", hashlib.sha256(cubin).hexdigest())
            env = os.environ.copy()
            env.pop("LD_PRELOAD", None)
            env.pop("HYBRID_FEATURES_MASK_OVERRIDE", None)
            passed = subprocess.run(
                [sys.executable, "-B", "-c", source], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=10, check=False, env=env)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            result = json.loads(passed.stdout)
            self.assertEqual(result["status"], "phase-passed")
            self.assertEqual(result["result_value"], 700)
            self.assertTrue(result["cleanup_passed"])
            self.assertIn("cuLaunchKernel", result["completed_operations"])
            self.assertIn("cuCtxDestroy_v2", result["completed_operations"])

            failed_env = dict(env, FAKE_CUDA_FAIL_KERNEL="1")
            failed = subprocess.run(
                [sys.executable, "-B", "-c", source], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=10, check=False, env=failed_env)
            self.assertEqual(failed.returncode, 2, failed.stderr)
            failure = json.loads(failed.stdout)
            self.assertEqual(failure["status"], "phase-failed")
            self.assertIn("cuLaunchKernel=123", failure["error"])
            self.assertTrue(failure["cleanup_passed"])
            self.assertIn("cuMemFree_v2", failure["completed_operations"])


if __name__ == "__main__":
    unittest.main()
