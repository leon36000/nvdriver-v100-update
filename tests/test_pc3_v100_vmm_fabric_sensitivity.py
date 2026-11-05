from __future__ import annotations

import ast
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/run_pc3_v100_system_features_sensitivity.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("v100_vmm_fabric_runner", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("V100 VMM/FABRIC runner could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def endpoint(tool, phase: str, fabric_supported: int = 1, passed: bool = True,
             kind: str = "fabric"):
    importer = phase.endswith("importer")
    handle_type = 8 if kind == "fabric" else 1
    handle_bytes = 64 if kind == "fabric" else 4
    fabric_support = {"status": 0, "value": fabric_supported}
    posix_support = {"status": 0, "value": 1}
    support = fabric_support if kind == "fabric" else posix_support
    device = {
        "name": "Tesla V100-SXM2-16GB", "pci_bus_id": "0000:00:05.0",
        "sm": 70, "compute_capability": "7.0", "unified_addressing": 1,
        "fabric_handle_support": fabric_support,
        "posix_fd_handle_support": posix_support,
    }
    common = {
        "schema": "nvidia-hybrid-driver-api-vmm-share-v1",
        "phase": phase,
        "shareable_handle_kind": kind,
        "shareable_handle_type": handle_type,
        "shareable_handle_bytes": handle_bytes,
        "status": "phase-passed" if passed else "phase-failed",
        "expected_pci": "0000:00:05.0",
        "driver_library_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
        "driver_api": 13000,
        "device": device,
        "imex_preflight": {
            "driver_registered": True, "directory_present": True,
            "channel_nodes_seen": 1, "character_nodes_seen": 1,
            "read_write_accessible_nodes": 1, "effective_uid": 0,
        },
        "allocation_bytes": 65536,
        "attribute_support": support,
        "posix_shareable_fd_opened": kind == "posix_fd" and passed,
        "posix_shareable_fd_closed": True,
        "observation_valid": True,
        "completed_operations": [],
        "failure_operation": None if passed else "cuMemCreate",
        "failure_code": None if passed else 801,
        "failure_name": None if passed else "CUDA_ERROR_NOT_SUPPORTED",
        "error_class": None,
        "cleanup_passed": True,
        "cleanup_errors": [],
    }
    if importer:
        common.update({
            "import_attempted": True,
            "import_succeeded": passed,
            "initial_values_match": True if passed else None,
            "numerical_phase_passed": passed,
        })
        if passed:
            common["completed_operations"] = [
                "cuInit", "cuCtxCreate_v2", "cuMemImportFromShareableHandle",
                "cuMemAddressReserve", "cuMemMap", "cuMemSetAccess", "cuMemcpyDtoH_v2",
                "cuMemcpyHtoD_v2", "cuCtxSynchronize", "cuMemUnmap", "cuMemAddressFree",
                "cuMemRelease", "cuCtxDestroy_v2",
            ]
            if kind == "posix_fd":
                common["completed_operations"].append("close_posix_shareable_fd")
    else:
        common.update({
            "allocation_created": passed,
            "export_attempted": passed,
            "export_succeeded": passed,
            "import_attempted": passed,
            "import_succeeded": passed,
            "initial_values_match": True if passed else None,
            "numerical_phase_passed": passed,
            "child_writeback_match": passed,
            "child_writeback_sha256": "a" * 64 if passed else None,
            "parent_readback_sha256": "a" * 64 if passed else None,
            "child": endpoint(tool, f"vmm-{kind}-importer", fabric_supported, passed, kind)
            if passed else None,
        })
        if passed:
            common["completed_operations"] = [
                "cuInit", "cuCtxCreate_v2", "cuMemGetAllocationGranularity", "cuMemCreate",
                "cuMemAddressReserve", "cuMemMap", "cuMemSetAccess", "cuMemcpyHtoD_v2",
                "cuCtxSynchronize", "cuMemExportToShareableHandle", "cuMemcpyDtoH_v2",
                "cuMemUnmap", "cuMemAddressFree", "cuMemRelease", "cuCtxDestroy_v2",
            ]
            if kind == "posix_fd":
                common["completed_operations"].append("close_posix_shareable_fd")
    return common


def guest_report(tool, failed_mask: int | None = None, kind: str = "fabric"):
    workload = "vmm-fabric-share" if kind == "fabric" else "vmm-posix-share"
    schema = ("nvidia-hybrid-v100-system-features-vmm-fabric-sensitivity-guest-v1"
              if kind == "fabric" else
              "nvidia-hybrid-v100-system-features-vmm-posix-sensitivity-guest-v1")
    base = {
        "schema": schema,
        "workload": workload, "status": "observed",
        "hostname": "pc3-v100", "kernel_release": "6.8.0-147-generic",
        "gpu": {"name": "Tesla V100-SXM2-16GB",
                "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e",
                "pci": "0000:00:05.0", "driver_version": "580.178.04"},
        "libcuda": {"path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
                    "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
                    "driver_api": 13000},
        "gpu_compute_processes_before": [], "gpu_compute_processes_after": [],
        "cleanup_passed": True, "driver_or_module_changed": False,
        "gpu_reset_requested": False, "temporary_payload_remaining": False,
        "execution_scope": {"read_only": True, "experimental_module_loaded": False,
                            "stock_driver_changed": False, "pci_binding_changed": False,
                            "vm_management_issued": False, "gpu_reset_requested": False},
        ("vmm_fabric_artifacts" if kind == "fabric" else "vmm_posix_artifacts"):
            {"probe_source_sha256": tool.VMM_FABRIC_PROBE_SOURCE_SHA256},
    }
    base["controls"] = [
        {"mode": mode, "probe_exit_code": 0,
         "cuda": endpoint(tool, f"vmm-{kind}-share", 1, True, kind)}
        for mode in ("stock", "preload_passthrough")
    ]
    records = lambda mask: [{"transport": "direct", "kernel_mask": 9,
                             "exposed_mask": mask, "caller_image": "libcuda.so.580.178.04",
                             "caller_offset": "0x1a2b"}]
    base["runs"] = []
    for mask in (9, 8, 1, 0):
        supported = 1 if mask in (9, 8) else 0
        passed = mask != failed_mask
        base["runs"].append({
            "requested_mask": mask, "ioctl_records": records(mask), "probe_exit_code": 0,
            "cuda": endpoint(tool, f"vmm-{kind}-share", supported, passed, kind),
        })
    return base


class Pc3V100VmmFabricSensitivityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def validator(self):
        validator = getattr(self.tool, "validate_guest_vmm_fabric_sensitivity", None)
        self.assertTrue(callable(validator), "VMM/FABRIC report validator is missing")
        return validator

    def test_numeric_vmm_fabric_exchange_is_accepted_and_capability_is_separate(self):
        result = self.validator()(guest_report(self.tool))
        self.assertTrue(result["complete"])
        self.assertTrue(result["vmm_fabric_succeeded_for_all_masks"])
        self.assertTrue(result["vmm_fabric_transfer_outcomes_equal"])
        self.assertFalse(result["vmm_fabric_capability_outcomes_equal"])
        self.assertFalse(result["mask_9_vs_1_fabric_capability_equal"])
        self.assertTrue(result["all_process_capability_pairs_equal"])
        self.assertEqual(result["api_outcomes_equal"], result["vmm_fabric_transfer_outcomes_equal"])

    def test_driver_api_rejection_is_a_valid_complete_observation(self):
        result = self.validator()(guest_report(self.tool, failed_mask=1))
        self.assertTrue(result["complete"])
        self.assertFalse(result["vmm_fabric_succeeded_for_all_masks"])
        self.assertFalse(result["vmm_fabric_transfer_outcomes_equal"])

    def test_posix_fd_vmm_exchange_uses_a_distinct_capability_and_handle_contract(self):
        result = self.validator()(guest_report(self.tool, kind="posix_fd"))
        self.assertTrue(result["complete"])
        self.assertEqual(result["vmm_share_kind"], "posix_fd")
        self.assertTrue(result["vmm_share_succeeded_for_all_masks"])
        self.assertTrue(result["vmm_share_transfer_outcomes_equal"])
        self.assertTrue(result["vmm_share_capability_outcomes_equal"])
        self.assertTrue(result["all_process_capability_pairs_equal"])

    def test_failed_capability_query_makes_report_incomplete(self):
        report = guest_report(self.tool)
        failed_query = {"status": 999, "value": None}
        report["runs"][0]["cuda"]["device"]["fabric_handle_support"] = failed_query
        report["runs"][0]["cuda"]["attribute_support"] = failed_query
        result = self.validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["capability_queries_complete"])

    def test_exporter_importer_capability_mismatch_makes_report_incomplete(self):
        report = guest_report(self.tool)
        child = report["runs"][0]["cuda"]["child"]
        child["device"]["fabric_handle_support"]["value"] = 0
        child["attribute_support"] = child["device"]["fabric_handle_support"]
        result = self.validator()(report)
        self.assertFalse(result["complete"])
        self.assertFalse(result["all_process_capability_pairs_equal"])

    def test_success_claim_requires_child_mapping_and_numeric_verification(self):
        report = guest_report(self.tool)
        report["runs"][0]["cuda"]["child"]["initial_values_match"] = False
        with self.assertRaisesRegex(ValueError, "successful VMM/FABRIC importer"):
            self.validator()(report)

    def test_guest_generator_embeds_hash_pinned_vmm_probe(self):
        with tempfile.TemporaryDirectory(prefix="v100-vmm-guest-code-") as directory:
            shim = Path(directory) / "shim.so"
            shim.write_bytes(b"test interposer")
            code = self.tool.make_guest_code(shim, workload="vmm-fabric-share")
        ast.parse(code)
        self.assertIn("vmm-fabric-share", code)
        self.assertIn(self.tool.VMM_FABRIC_PROBE_SOURCE_SHA256, code)

    def test_guest_generator_builds_hash_pinned_posix_vmm_workload(self):
        with tempfile.TemporaryDirectory(prefix="v100-vmm-posix-guest-code-") as directory:
            shim = Path(directory) / "shim.so"
            shim.write_bytes(b"test interposer")
            code = self.tool.make_guest_code(shim, workload="vmm-posix-share")
        ast.parse(code)
        self.assertIn("vmm-posix-share", code)
        self.assertIn("NVIDIA_HYBRID_VMM_SHARE_KIND", code)
        self.assertIn('VMM_EXPECTED_PCI = "0000:00:05.0"', code)
        self.assertIn('probe_env["NVIDIA_HYBRID_VMM_EXPECTED_PCI"] = VMM_EXPECTED_PCI', code)
        self.assertIn('probe_env["NVIDIA_HYBRID_VMM_EXPECTED_DEVICE_NAME_PREFIX"] = "Tesla V100"', code)
        self.assertIn('probe_env["NVIDIA_HYBRID_VMM_EXPECTED_DRIVER_API"] = "13000"', code)
        self.assertIn(self.tool.VMM_FABRIC_PROBE_SOURCE_SHA256, code)


if __name__ == "__main__":
    unittest.main()
