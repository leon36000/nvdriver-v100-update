import importlib.util
import ast
from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/run_pc3_r580_userland_probe.py"
SPEC = importlib.util.spec_from_file_location("pc3_r580_userland_probe", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def passing_probe():
    return {
        "schema": "nvidia-hybrid-probe-v2",
        "status": "incomplete",
        "hybrid_validated": False,
        "required_set_passed": False,
        "context_coexistence_passed": False,
        "driver_library_path": "/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/libcuda.so.580.196.07",
        "driver_api": 12080,
        "required_sm": [70, 120],
        "missing_sm": [70],
        "memory_mode": "managed",
        "managed_prefetch_requested": True,
        "managed_prefetch_api": "cuMemPrefetchAsync_v2",
        "cuda_graphs_requested": True,
        "cuda_graph_api": "cuGraphInstantiateWithFlags",
        "devices": [{
            "ordinal": 0,
            "name": "NVIDIA GeForce RTX 5080",
            "pci_bus_id": "0000:02:00.0",
            "compute_capability": "12.0",
            "sm": 120,
            "targeted": True,
            "tested": True,
            "architecture_kernel_passed": True,
            "synchronous_passed": True,
            "synchronous_sizes": [1, 31, 256, 4096, 65537],
            "asynchronous_passed": True,
            "asynchronous_sizes": [1, 31, 256, 4096, 65537],
            "managed_memory_passed": True,
            "managed_prefetch_passed": True,
            "cuda_graphs_passed": True,
            "cuda_graph_launches": 2,
            "cleanup_passed": True,
            "cleanup_errors": [],
            "error": "",
        }],
    }


class Pc3R580UserlandProbeTests(unittest.TestCase):
    def test_probe_artifacts_track_the_current_hybrid_acceptance_build(self):
        current = ROOT / "build/probe-pc3-rtx5080-event-close-v2-20261028"
        self.assertEqual(TOOL.PROBE_PATH, current / "hybrid_cuda_probe")
        self.assertEqual(TOOL.PROBE_SHA256,
                         "df4ab2558a7315680eb55d91cfacd807926d0adf15d9835424e256a5eb43b71d")
        self.assertEqual(TOOL.MODULE_PATH, current / "hybrid_probe.sm70-sm120.fatbin")
        self.assertEqual(TOOL.MODULE_SHA256,
                         "74cd97aabd47ab1abe720493bf54012a494472d9047b249d049300cda57e1741")

    def test_remote_payload_matches_the_worker_exact_field_allowlist(self):
        source = ast.parse(TOOL_PATH.read_text(encoding="utf-8"))
        main = next(node for node in source.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        payload_assignment = next(node for node in ast.walk(main)
                                  if isinstance(node, ast.Assign) and
                                  any(isinstance(target, ast.Name) and target.id == "payload"
                                      for target in node.targets) and
                                  isinstance(node.value, ast.Dict))
        local_fields = {key.value for key in payload_assignment.value.keys
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)}
        worker_match = re.search(r"if set\(payload\)!=\{([^}]+)\}", TOOL.REMOTE_SCRIPT)
        self.assertIsNotNone(worker_match)
        worker_fields = ast.literal_eval("{" + worker_match.group(1) + "}")
        self.assertEqual(local_fields, worker_fields)

    def test_pinned_stage_report_is_identity_checked_before_remote_probe(self):
        report = TOOL.validate_stage_report(
            TOOL.DEFAULT_REMOTE_STAGE_REPORT,
            "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33",
        )
        self.assertEqual(report["schema"], TOOL.SIMULATION_SCHEMA)
        self.assertEqual(report["stage_report_sha256"], TOOL.STAGE_REPORT_SHA256)
        self.assertEqual(report["install_count"], 18)
        self.assertEqual(report["remove_count"], 18)

    def test_stage_report_mutation_is_rejected_before_remote_access(self):
        raw = TOOL.DEFAULT_REMOTE_STAGE_REPORT.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stage-report.json"
            path.write_bytes(raw + b" ")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "pinned SHA-256"):
                TOOL.validate_stage_report(
                    path, "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33")

    def test_stage_report_rejects_wrong_stage_directory(self):
        with self.assertRaisesRegex(ValueError, "stage directory"):
            TOOL.validate_stage_report(
                TOOL.DEFAULT_REMOTE_STAGE_REPORT,
                "/var/tmp/codex-r580-canary-20261023T095544Z-deadbeef",
            )

    def test_stage_report_must_be_private_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stage-report.json"
            path.write_bytes(TOOL.DEFAULT_REMOTE_STAGE_REPORT.read_bytes())
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private regular file"):
                TOOL.validate_stage_report(
                    path, "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33")

    def test_stage_report_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stage-report.json"
            path.symlink_to(TOOL.DEFAULT_REMOTE_STAGE_REPORT)
            with self.assertRaisesRegex(ValueError, "safely open"):
                TOOL.validate_stage_report(
                    path, "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33")

    def test_accepts_blackwell_device_pass_without_calling_it_hybrid_success(self):
        result = TOOL.validate_probe_result(
            passing_probe(), 77,
            expected_pci="0000:02:00.0",
            expected_library_prefix="/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/",
        )
        self.assertEqual(result["qualification"], "rtx5080-r580-userland-only-hybrid-incomplete")
        self.assertFalse(result["hybrid_validated"])
        self.assertTrue(result["rtx5080_kernel_passed"])

    def test_classifies_exact_system_driver_mismatch_as_a_valid_negative_result(self):
        remote = {
            "status": "compatibility-rejected",
            "compatibility_outcome": "r580-userland-r595-kernel-system-driver-mismatch",
            "inventory_probe": {
                "exit_code": 2,
                "stdout": "",
                "stderr": "fatal: cuInit failed with CUresult=803 (CUDA_ERROR_SYSTEM_DRIVER_MISMATCH): system has unsupported display driver / cuda driver combination\\n",
                "timed_out": False,
            },
            "cuda_probe": None,
            "gpu_before": {"kernel_driver": "595.99.02", "uuid": TOOL.EXPECTED_UUID},
            "gpu_after": {"same_as_before": True},
            "user_library": {"path": "/tmp/pc3-r580-userland-test/libcuda.so.580.196.07",
                             "sha256": "a" * 64},
            "cleanup": {"attempted": True, "passed": True},
        }
        result = TOOL.validate_mismatch_rejection(remote)
        self.assertFalse(result["rtx5080_kernel_passed"])
        self.assertFalse(result["hybrid_validated"])
        self.assertIn("cannot pair", result["finding"])

    def test_does_not_accept_timeout_or_unrelated_initialization_errors_as_abi_proof(self):
        remote = {
            "status": "compatibility-rejected",
            "compatibility_outcome": "r580-userland-r595-kernel-system-driver-mismatch",
            "inventory_probe": {"exit_code": 124, "stdout": "", "stderr": "timeout", "timed_out": True},
            "cuda_probe": None,
            "gpu_before": {"kernel_driver": "595.99.02", "uuid": TOOL.EXPECTED_UUID},
            "gpu_after": {"same_as_before": True},
            "user_library": {"path": "/tmp/pc3-r580-userland-test/libcuda.so.580.196.07",
                             "sha256": "a" * 64},
            "cleanup": {"attempted": True, "passed": True},
        }
        with self.assertRaisesRegex(ValueError, "CUresult=803"):
            TOOL.validate_mismatch_rejection(remote)

    def test_rejects_wrong_cuda_library_branch(self):
        report = passing_probe()
        report["driver_library_path"] = "/usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02"
        with self.assertRaisesRegex(ValueError, "R580 libcuda"):
            TOOL.validate_probe_result(report, 77, "0000:02:00.0", "/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/")

    def test_rejects_false_hybrid_claim(self):
        report = passing_probe()
        report["hybrid_validated"] = True
        with self.assertRaisesRegex(ValueError, "hybrid"):
            TOOL.validate_probe_result(report, 77, "0000:02:00.0", "/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/")

    def test_rejects_missing_numeric_or_managed_memory_checks(self):
        report = passing_probe()
        report["devices"][0]["asynchronous_sizes"] = [1, 31]
        with self.assertRaisesRegex(ValueError, "asynchronous"):
            TOOL.validate_probe_result(report, 77, "0000:02:00.0", "/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/")

    def test_rejects_cleanup_failure_and_noncanonical_pci(self):
        report = passing_probe()
        report["devices"][0]["cleanup_passed"] = False
        with self.assertRaisesRegex(ValueError, "cleanup"):
            TOOL.validate_probe_result(report, 77, "0000:02:00.0", "/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/")
        report = passing_probe()
        report["devices"][0]["pci_bus_id"] = "0000:03:00.0"
        with self.assertRaisesRegex(ValueError, "PCI"):
            TOOL.validate_probe_result(report, 77, "0000:02:00.0", "/tmp/pc3-r580-userland-test/usr/lib/x86_64-linux-gnu/")

    def test_remote_package_directory_must_be_a_private_stage_path(self):
        self.assertEqual(
            TOOL.validate_remote_stage_dir("/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33"),
            "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33",
        )
        for value in ("/tmp/anything", "/var/tmp/codex-r580-canary-../../etc",
                      "/var/tmp/codex-r580-canary-20261023T095544Z-ab7b7b33/../x",
                      "relative"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                TOOL.validate_remote_stage_dir(value)

    def test_remote_script_never_invokes_package_install_or_module_operations(self):
        source = TOOL.REMOTE_SCRIPT
        for forbidden in ("apt-get install", "dpkg -i", "modprobe", "insmod", "rmmod",
                          "nvidia-smi --gpu-reset", "virsh", "systemctl stop"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
