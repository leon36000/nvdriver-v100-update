import base64
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pc3_v100_hybrid_frontend_build",
    ROOT / "tools/run_pc3_v100_hybrid_frontend_build.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class Pc3V100HybridFrontendBuildContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.paths = RUNNER.input_bundle_paths()

    def test_bundle_contains_exact_r580_provider_abi_inputs_and_frontend_sources(self):
        names = {path.relative_to(ROOT).as_posix() for path in self.paths}
        required = {
            "tools/build_hybrid_frontend.py",
            "src/hybrid_frontend.c",
            "src/hybrid580_uvm_callback_bridge.c",
            "src/hybrid580_uvm_typed_child_route.h",
            "tests/test_build_hybrid_frontend.py",
            "build/experiments/r58019607-sync-boost-open-build-v1/private/"
            "NVIDIA-kernel-module-source-580.196.07/kernel-open/Module.symvers",
            "build/experiments/r58019607-debugger-bridge-provider-build-v3-20261101/source/Module.symvers",
            "build/experiments/r58019607-sync-boost-open-build-v1/private/"
            "NVIDIA-kernel-module-source-580.196.07/kernel-open/common/inc/nv_uvm_interface.h",
            "build/experiments/r58019607-debugger-bridge-provider-build-v3-20261101/source/common/inc/nv_uvm_interface.h",
        }
        self.assertTrue(required <= names)
        archive, manifest = RUNNER.build_input_archive(self.paths)
        self.assertLess(len(archive), RUNNER.MAX_BUNDLE)
        self.assertEqual(len(manifest), len(names))
        self.assertEqual(len({item["path"] for item in manifest}), len(manifest))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest))

    def test_guest_script_is_pinned_to_compile_only_r580_frontend_build(self):
        compile(RUNNER.GUEST_BUILD_SCRIPT, "<guest-build-script>", "exec")
        script = RUNNER.GUEST_BUILD_SCRIPT
        self.assertIn('EXPECTED_HOST="pc3-v100"', script)
        self.assertIn('EXPECTED_KERNEL="6.8.0-147-generic"', script)
        self.assertIn('"--uvm-abi","r580","--module-name","nvidia"', script)
        self.assertNotIn('"insmod"', script)
        self.assertNotIn('"modprobe"', script)
        self.assertNotIn('"cuda"', script.lower())
        self.assertIn('"module_loaded":False', script)
        self.assertIn('"module_installed":False', script)
        self.assertIn('"gpu_accessed":False', script)
        self.assertIn('CONFIG_STACK_VALIDATION=', script)
        self.assertIn('name.endswith(".cmd")', script)

    def test_guest_script_captures_the_exact_kernel_module_symvers(self):
        script = RUNNER.GUEST_BUILD_SCRIPT
        self.assertIn('kernel_symvers_path="/lib/modules/"+EXPECTED_KERNEL+"/build/Module.symvers"', script)
        self.assertIn('"kernel-inputs","Module.symvers"', script)
        self.assertIn('os.path.isfile(kernel_symvers_path)', script)

    def test_guest_result_requires_the_exact_kernel_module_symvers_artifact(self):
        result, run_id, bundle_sha = self._valid_result()
        result["artifacts"] = [item for item in result["artifacts"]
                               if not item["path"].endswith("kernel-inputs/Module.symvers")]
        with self.assertRaisesRegex(ValueError, "kernel Module.symvers artifact"):
            RUNNER.validate_guest_result(json.dumps(result).encode(), run_id, bundle_sha)

    def _valid_result(self):
        run_id = "a" * 32
        bundle_sha = "b" * 64
        artifact = b"compile-only module bytes"
        kernel_symvers = b"exact pinned guest kernel Module.symvers\n"
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w:gz") as archive:
            for name, content in (
                ("build/experiments/test/nvidia.ko", artifact),
                (f"build/experiments/pc3-v100-hybrid-frontend-{run_id}/"
                 "kernel-inputs/Module.symvers", kernel_symvers),
            ):
                item = tarfile.TarInfo(name)
                item.size = len(content)
                archive.addfile(item, io.BytesIO(content))
        packed_bytes = packed.getvalue()
        import hashlib
        digest = lambda data: hashlib.sha256(data).hexdigest()
        result = {
            "schema": "nvidia-hybrid-pc3-v100-hybrid-frontend-build-result-v1",
            "status": "completed",
            "run_id": run_id,
            "bundle_sha256": bundle_sha,
            "hostname": RUNNER.PINNED_GUEST,
            "kernel_release": RUNNER.PINNED_KERNEL,
            "builder_exit_code": 0,
            "builder_stdout_sha256": digest(b"stdout"),
            "builder_stderr_sha256": digest(b""),
            "builder_output_bytes": 6,
            "builder_report": {"kernel_release": RUNNER.PINNED_KERNEL},
            "builder_report_sha256": digest(b"report"),
            "kernel_build_config": {"path": "/lib/modules/test/auto.conf",
                                    "sha256": digest(b"config"),
                                    "selected_options": {"CONFIG_MODULES": "y"},
                                    "readable": True},
            "artifacts": [
                {"path": "build/experiments/test/nvidia.ko",
                 "bytes": len(artifact), "sha256": digest(artifact)},
                {"path": f"build/experiments/pc3-v100-hybrid-frontend-{run_id}/"
                         "kernel-inputs/Module.symvers",
                 "bytes": len(kernel_symvers), "sha256": digest(kernel_symvers)},
            ],
            "artifact_archive_bytes": len(packed_bytes),
            "artifact_archive_sha256": digest(packed_bytes),
            "artifact_archive_base64": base64.b64encode(packed_bytes).decode("ascii"),
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "scratch_removed": True,
            "staged_bundle_removed": True,
        }
        return result, run_id, bundle_sha

    def test_guest_result_validates_identity_cleanup_and_artifact_hashes(self):
        result, run_id, bundle_sha = self._valid_result()
        checked = RUNNER.validate_guest_result(
            json.dumps(result).encode(), run_id, bundle_sha)
        self.assertEqual(checked["builder_exit_code"], 0)
        self.assertIsInstance(checked["_packed_artifacts"], bytes)
        for mutation in (
            {"hostname": "pc3"},
            {"kernel_release": "7.0.0-38-generic"},
            {"module_loaded": True},
            {"scratch_removed": False},
            {"bundle_sha256": "c" * 64},
        ):
            changed = dict(result)
            changed.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                RUNNER.validate_guest_result(json.dumps(changed).encode(), run_id, bundle_sha)

    def test_guest_result_preserves_build_failure_report_and_artifacts(self):
        result, run_id, bundle_sha = self._valid_result()
        result["builder_exit_code"] = 1
        result["error"] = "frontend ABI validation failed"
        checked = RUNNER.validate_guest_result(
            json.dumps(result).encode(), run_id, bundle_sha)
        self.assertEqual(checked["error"], "frontend ABI validation failed")
        self.assertEqual(checked["builder_exit_code"], 1)

    def test_guest_result_rejects_path_escape_and_archive_tampering(self):
        result, run_id, bundle_sha = self._valid_result()
        changed = json.loads(json.dumps(result))
        changed["artifacts"][0]["path"] = "build/../../etc/passwd"
        with self.assertRaises(ValueError):
            RUNNER.validate_guest_result(json.dumps(changed).encode(), run_id, bundle_sha)
        changed = dict(result)
        changed["artifact_archive_base64"] = base64.b64encode(b"tampered").decode()
        with self.assertRaises(ValueError):
            RUNNER.validate_guest_result(json.dumps(changed).encode(), run_id, bundle_sha)

    def test_target_open_build_conftest_is_hash_pinned_and_mapped_to_expected_input(self):
        with tempfile.TemporaryDirectory(prefix="pc3-v100-private-open580-test-",
                                         dir=ROOT / "build/experiments") as temp:
            base = Path(temp)
            source = (base / "private/NVIDIA-kernel-module-source-580.178.04/"
                      "kernel-open/conftest/headers.h")
            source.parent.mkdir(parents=True)
            contents = b'#define UTS_RELEASE "6.8.0-147-generic"\n'
            source.write_bytes(contents)
            open_symvers = source.parents[1] / "Module.symvers"
            open_symvers.write_text("0x12345678\thybrid580_open_test\thybrid580_open\tEXPORT_SYMBOL\n")
            relative = source.relative_to(ROOT).as_posix()
            open_symvers_relative = open_symvers.relative_to(ROOT).as_posix()
            import hashlib
            digest = hashlib.sha256(contents).hexdigest()
            open_symvers_digest = hashlib.sha256(open_symvers.read_bytes()).hexdigest()
            report = {
                "schema": "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1",
                "status": "collected",
                "guest_hostname": RUNNER.PINNED_GUEST,
                "guest_kernel_release": RUNNER.PINNED_KERNEL,
                "builder_qualification": "compiled-native-private-open580-provider-only",
                "builder_report": {"kernel_release": RUNNER.PINNED_KERNEL},
                "module_installed": False,
                "module_loaded": False,
                "gpu_accessed": False,
                "cuda_execution_tested": False,
                "retrieved_artifacts": [
                    {"path": relative, "bytes": len(contents), "sha256": digest},
                    {"path": open_symvers_relative, "bytes": open_symvers.stat().st_size,
                     "sha256": open_symvers_digest},
                ],
            }
            report_path = base / "capture.json"
            report_path.write_text(json.dumps(report))
            selected, report_sha = RUNNER.load_target_conftest(report_path)
            selected_open_symvers, open_report_sha = RUNNER.load_target_symvers(report_path, "open")
            self.assertEqual(set(selected), {"headers.h"})
            self.assertEqual(selected["headers.h"], source)
            self.assertEqual(len(report_sha), 64)
            self.assertEqual(selected_open_symvers, open_symvers)
            self.assertEqual(len(open_report_sha), 64)

            with tempfile.TemporaryDirectory(prefix="pc3-v100-private-proprietary580-test-",
                                             dir=ROOT / "build/experiments") as legacy_temp:
                legacy_base = Path(legacy_temp)
                legacy_symvers = legacy_base / "nvidia-580.178.04/Module.symvers"
                legacy_symvers.parent.mkdir(parents=True)
                legacy_symvers.write_text(
                    "0x87654321\thybrid580_legacy_test\thybrid580_legacy\tEXPORT_SYMBOL\n")
                legacy_symvers_bytes = legacy_symvers.read_bytes()
                legacy_relative = legacy_symvers.relative_to(ROOT).as_posix()
                legacy_raw = legacy_symvers_bytes
                legacy_report = {
                    "schema": "nvidia-hybrid-pc3-v100-private-legacy580-build-capture-v1",
                    "status": "collected",
                    "guest_hostname": RUNNER.PINNED_GUEST,
                    "guest_kernel_release": RUNNER.PINNED_KERNEL,
                    "builder_qualification": (
                        "compiled-module-and-CPU-model-only-with-inherited-vendor-objtool-warnings"),
                    "builder_report": {},
                    "module_installed": False,
                    "module_loaded": False,
                    "gpu_accessed": False,
                    "cuda_execution_tested": False,
                    "retrieved_artifacts": [{
                        "path": legacy_relative,
                        "bytes": len(legacy_raw),
                        "sha256": hashlib.sha256(legacy_raw).hexdigest(),
                    }],
                }
                legacy_report_path = legacy_base / "capture.json"
                legacy_report_path.write_text(json.dumps(legacy_report))
                selected_legacy_symvers, legacy_report_sha = RUNNER.load_target_symvers(
                    legacy_report_path, "legacy")
                self.assertEqual(selected_legacy_symvers, legacy_symvers)
                self.assertEqual(len(legacy_report_sha), 64)

                paths = RUNNER.input_bundle_paths(
                    selected, selected_open_symvers, selected_legacy_symvers)
                bundle, manifest = RUNNER.build_input_archive(
                    paths, selected, selected_open_symvers, selected_legacy_symvers)
            frontend = RUNNER._load_module(RUNNER.BUILD_TOOL, "front_end_expected_tree")
            open_tree, legacy_tree = frontend.default_provider_trees("r580")
            canonical_paths = (
                (open_tree / "kernel-open/conftest/headers.h").relative_to(ROOT).as_posix(),
                (open_tree / "kernel-open/Module.symvers").relative_to(ROOT).as_posix(),
                (legacy_tree / "Module.symvers").relative_to(ROOT).as_posix(),
            )
            with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as archive:
                self.assertEqual(archive.extractfile(canonical_paths[0]).read(), contents)
                self.assertEqual(archive.extractfile(canonical_paths[1]).read(), open_symvers.read_bytes())
                self.assertEqual(archive.extractfile(canonical_paths[2]).read(), legacy_symvers_bytes)
            for canonical, source_path in zip(
                    canonical_paths, (relative, open_symvers_relative, legacy_relative)):
                record = next(item for item in manifest if item["path"] == canonical)
                self.assertEqual(record["source_path"], source_path)

            report["retrieved_artifacts"][0]["sha256"] = "0" * 64
            report_path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "differs from its manifest"):
                RUNNER.load_target_conftest(report_path)


if __name__ == "__main__":
    unittest.main()
