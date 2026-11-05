import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_pc3_v100_guest_r580_stack.py"


class Pc3V100GuestR580StackAuditTests(unittest.TestCase):
    def _load_audit(self):
        self.assertTrue(TOOL.is_file(), "PC3 R580 guest-stack auditor is missing")
        spec = importlib.util.spec_from_file_location("pc3_guest_r580_stack_audit", TOOL)
        audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit)
        return audit

    def test_capture_artifact_is_hash_pinned_and_confined(self):
        audit = self._load_audit()
        with tempfile.TemporaryDirectory(prefix="pc3-r580-stack-audit-") as temp:
            root = Path(temp)
            artifact = root / "build/experiments/run/nvidia.ko"
            artifact.parent.mkdir(parents=True)
            payload = b"compile-only test module"
            artifact.write_bytes(payload)
            capture = {"retrieved_artifacts": [{
                "path": "build/experiments/run/nvidia.ko",
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }]}

            selected = audit.resolve_captured_artifact(
                capture, root, prefix="build/experiments/", suffix="/nvidia.ko")

            self.assertEqual(selected, artifact)

    def test_capture_artifact_rejects_hash_mismatch_and_ambiguous_matches(self):
        audit = self._load_audit()
        with tempfile.TemporaryDirectory(prefix="pc3-r580-stack-audit-") as temp:
            root = Path(temp)
            artifact = root / "build/experiments/run/nvidia.ko"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"actual bytes")
            capture = {"retrieved_artifacts": [{
                "path": "build/experiments/run/nvidia.ko",
                "bytes": len(b"claimed bytes"),
                "sha256": hashlib.sha256(b"claimed bytes").hexdigest(),
            }]}
            with self.assertRaisesRegex(ValueError, "differs from its capture manifest"):
                audit.resolve_captured_artifact(
                    capture, root, prefix="build/experiments/", suffix="/nvidia.ko")

    def test_capture_validation_keeps_compile_only_identity_strict(self):
        audit = self._load_audit()
        capture = {
            "schema": "nvidia-hybrid-pc3-v100-hybrid-frontend-build-capture-v1",
            "status": "compiled",
            "target": "pc3@pc3",
            "guest_hostname": "pc3-v100",
            "guest_kernel_release": "6.8.0-147-generic",
            "qualification": "compiled-bdf-selected-gpu-file-frontend-kernel-module",
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "builder_report": {"schema": "nvidia-hybrid-gpu-file-frontend-v1",
                               "kernel_release": "6.8.0-147-generic"},
        }
        audit.validate_capture(capture, "frontend")
        capture["gpu_accessed"] = True
        with self.assertRaisesRegex(ValueError, "crossed the compile-only boundary"):
            audit.validate_capture(capture, "frontend")

            for name in ("run-two",):
                duplicate = root / f"build/experiments/{name}/nvidia.ko"
                duplicate.parent.mkdir(parents=True)
                duplicate.write_bytes(b"actual bytes")
                capture["retrieved_artifacts"].append({
                    "path": f"build/experiments/{name}/nvidia.ko",
                    "bytes": len(b"actual bytes"),
                    "sha256": hashlib.sha256(b"actual bytes").hexdigest(),
                })
            capture["retrieved_artifacts"][0] = capture["retrieved_artifacts"][1]
            with self.assertRaisesRegex(ValueError, "exactly one captured artifact"):
                audit.resolve_captured_artifact(
                    capture, root, prefix="build/experiments/", suffix="/nvidia.ko")


if __name__ == "__main__":
    unittest.main()
