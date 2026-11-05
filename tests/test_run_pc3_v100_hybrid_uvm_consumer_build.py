import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pc3_v100_hybrid_uvm_consumer_build",
    ROOT / "tools/run_pc3_v100_hybrid_uvm_consumer_build.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class Pc3V100HybridUvmConsumerBuildContracts(unittest.TestCase):
    def _frontend_receipt(self, parent: Path):
        directory = parent / "build/experiments/frontend"
        directory.mkdir(parents=True)
        symvers = directory / "Module.symvers"
        symvers.write_text("0x1234abcd\tnvUvmInterfaceTest\tnvidia\tEXPORT_SYMBOL\n")
        module = directory / "nvidia.ko"
        module.write_bytes(b"ELF frontend fixture")
        digest = RUNNER._file_sha256
        receipt = {
            "schema": RUNNER.FRONTEND_REPORT_SCHEMA,
            "status": "build-failed",
            "target": RUNNER.PINNED_PC3,
            "guest_hostname": RUNNER.PINNED_GUEST,
            "guest_kernel_release": RUNNER.PINNED_KERNEL,
            "builder_report": {"module_name": "nvidia",
                               "built_module_identity": {"matches": True}},
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "retrieved_artifacts": [
                {"path": symvers.relative_to(ROOT).as_posix(), "bytes": symvers.stat().st_size,
                 "sha256": digest(symvers)},
                {"path": module.relative_to(ROOT).as_posix(), "bytes": module.stat().st_size,
                 "sha256": digest(module)},
            ],
        }
        report = parent / "evidence/frontend.json"
        report.parent.mkdir()
        report.write_text(json.dumps(receipt))
        return report, symvers, module, receipt

    def test_frontend_artifacts_are_bound_to_receipt_hashes_and_target(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/experiments") as temp:
            base = Path(temp)
            report, symvers, _, receipt = self._frontend_receipt(base)
            selected, digest, report_hash = RUNNER.load_frontend_module_symvers(report, symvers)
            self.assertEqual(selected, symvers.resolve())
            self.assertEqual(digest, RUNNER._file_sha256(symvers))
            self.assertEqual(report_hash, RUNNER._file_sha256(report))

            receipt["guest_kernel_release"] = "7.0.0-38-generic"
            report.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "pinned V100 guest"):
                RUNNER.load_frontend_module_symvers(report, symvers)

    def test_frontend_artifact_digest_and_pairing_are_enforced(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/experiments") as temp:
            base = Path(temp)
            report, symvers, module, receipt = self._frontend_receipt(base)
            receipt["retrieved_artifacts"][0]["sha256"] = "0" * 64
            report.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "Module.symvers differs"):
                RUNNER.load_frontend_module_symvers(report, symvers)

            receipt["retrieved_artifacts"][0]["sha256"] = RUNNER._file_sha256(symvers)
            receipt["retrieved_artifacts"] = receipt["retrieved_artifacts"][:1]
            report.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "paired nvidia.ko"):
                RUNNER.load_frontend_module_symvers(report, symvers)

    def test_bundle_contains_pinned_r580_consumer_inputs_and_guest_frontend_abi(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/experiments") as temp:
            base = Path(temp)
            report, symvers, _, _ = self._frontend_receipt(base)
            paths = RUNNER.input_bundle_paths(symvers)
            bundle, manifest = RUNNER.build_input_archive(paths, symvers)
            names = {item["path"] for item in manifest}
            self.assertIn("tools/probe_r580_uvm_isolated_execution.py", names)
            self.assertIn("tools/audit_uvm_owner_isolation_architecture.py", names)
            self.assertIn(".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz", names)
            self.assertIn("build/experiments/pc3-v100-uvm-consumer-input/frontend-Module.symvers", names)
            self.assertTrue(any(name.endswith("0002-hybrid-isolated-gpu-execution.patch") for name in names))
            self.assertLess(len(bundle), RUNNER.MAX_BUNDLE)
            with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as archive:
                symvers_member = archive.extractfile(
                    "build/experiments/pc3-v100-uvm-consumer-input/frontend-Module.symvers").read()
                source_member = archive.extractfile(
                    ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz").read()
            self.assertEqual(symvers_member, symvers.read_bytes())
            self.assertEqual(hashlib.sha256(source_member).hexdigest(),
                             "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8")

    def test_guest_script_is_pinned_and_stays_compile_only(self):
        compile(RUNNER.GUEST_BUILD_SCRIPT, "<guest-uvm-build-script>", "exec")
        script = RUNNER.GUEST_BUILD_SCRIPT
        self.assertIn('EXPECTED_HOST="pc3-v100"', script)
        self.assertIn('EXPECTED_KERNEL="6.8.0-147-generic"', script)
        self.assertIn('"--source-version","580.178.04"', script)
        self.assertIn('"--frontend-module-name","nvidia"', script)
        self.assertIn('"module_installed":False', script)
        self.assertIn('"module_loaded":False', script)
        self.assertIn('"gpu_accessed":False', script)
        self.assertNotIn("insmod", script)
        self.assertNotIn("modprobe", script)
        self.assertNotIn("nvidia-smi", script)

    def _valid_guest_result(self):
        run_id = "a" * 32
        bundle_sha = "b" * 64
        artifact = b"compiled uvm module fixture"
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w:gz") as archive:
            info = tarfile.TarInfo("build/experiments/test/nvidia-uvm.ko")
            info.size = len(artifact)
            archive.addfile(info, io.BytesIO(artifact))
        packed_bytes = packed.getvalue()
        digest = lambda data: hashlib.sha256(data).hexdigest()
        result = {
            "schema": RUNNER.RESULT_SCHEMA,
            "status": "completed",
            "run_id": run_id,
            "bundle_sha256": bundle_sha,
            "hostname": RUNNER.PINNED_GUEST,
            "kernel_release": RUNNER.PINNED_KERNEL,
            "builder_exit_code": 0,
            "builder_stdout_sha256": digest(b"stdout"),
            "builder_stderr_sha256": digest(b""),
            "builder_output_bytes": 6,
            "builder_report": {
                "schema": "r580-uvm-isolated-gpu-execution-build-v5",
                "build": {"kernel_release": RUNNER.PINNED_KERNEL},
            },
            "builder_report_sha256": digest(b"report"),
            "kernel_build_config": {"readable": True, "selected_options": {}},
            "artifacts": [{"path": "build/experiments/test/nvidia-uvm.ko",
                           "bytes": len(artifact), "sha256": digest(artifact)}],
            "artifact_archive_bytes": len(packed_bytes),
            "artifact_archive_sha256": digest(packed_bytes),
            "artifact_archive_base64": base64.b64encode(packed_bytes).decode(),
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "scratch_removed": True,
            "staged_bundle_removed": True,
        }
        return result, run_id, bundle_sha

    def test_guest_result_requires_exact_identity_scope_and_hashed_artifact(self):
        result, run_id, bundle_sha = self._valid_guest_result()
        checked = RUNNER.validate_guest_result(json.dumps(result).encode(), run_id, bundle_sha)
        self.assertIsInstance(checked["_packed_artifacts"], bytes)
        for mutation in (
                {"hostname": "pc3"}, {"kernel_release": "7.0.0-38-generic"},
                {"gpu_accessed": True}, {"module_loaded": True}, {"scratch_removed": False},
                {"bundle_sha256": "c" * 64}):
            changed = dict(result)
            changed.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                RUNNER.validate_guest_result(json.dumps(changed).encode(), run_id, bundle_sha)

    def test_guest_result_rejects_archive_tampering_and_path_escape(self):
        result, run_id, bundle_sha = self._valid_guest_result()
        changed = json.loads(json.dumps(result))
        changed["artifacts"][0]["path"] = "build/../../etc/passwd"
        with self.assertRaises(ValueError):
            RUNNER.validate_guest_result(json.dumps(changed).encode(), run_id, bundle_sha)
        changed = dict(result)
        changed["artifact_archive_base64"] = base64.b64encode(b"tampered").decode()
        with self.assertRaises(ValueError):
            RUNNER.validate_guest_result(json.dumps(changed).encode(), run_id, bundle_sha)


if __name__ == "__main__":
    unittest.main()
