from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    from tools.create_r595_uvm_isolation_manifest import build_manifest, write_report
except ModuleNotFoundError:
    build_manifest = None
    write_report = None


class R595UvmIsolationManifestTests(unittest.TestCase):
    def _fixture(self, root: Path):
        (root / "evidence").mkdir()
        (root / "build").mkdir()
        (root / "tools").mkdir()
        (root / "tests").mkdir()
        audit_tool = root / "tools/audit_hybrid_candidate_bundle.py"
        audit_tool.write_bytes(
            (Path(__file__).resolve().parents[1] /
             "tools/audit_hybrid_candidate_bundle.py").read_bytes()
        )
        manifest_tool = root / "tools/create_r595_uvm_isolation_manifest.py"
        manifest_tool.write_bytes(
            (Path(__file__).resolve().parents[1] /
             "tools/create_r595_uvm_isolation_manifest.py").read_bytes()
        )
        test_source = root / "tests/test_create_r595_uvm_isolation_manifest.py"
        test_source.write_bytes(Path(__file__).read_bytes())
        module = root / "build/nvidia-uvm.ko"
        module_bytes = b"exact candidate UVM module bytes"
        module.write_bytes(module_bytes)
        module_sha = hashlib.sha256(module_bytes).hexdigest()
        r580_archive = root / "sources/NVIDIA-kernel-module-source-580.196.07.tar.xz"
        r580_archive.parent.mkdir()
        r580_archive.write_bytes(b"pinned R580.196.07 source archive")
        archive_sha = hashlib.sha256(r580_archive.read_bytes()).hexdigest()

        config = root / "packaging/modprobe.d/hybrid595-standard-uvm.conf"
        config.parent.mkdir(parents=True)
        config.write_text(
            "# Candidate-only; do not install with stock UVM.\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n",
            encoding="utf-8",
        )
        build = {
            "schema": "r595-gv100-complete-hal-probe-v10",
            "status": "passed",
            "module_loaded": False,
            "module_installed": False,
            "hardware_validated": False,
            "candidate_module": {
                "linked_this_run": True,
                "path": "build/nvidia-uvm.ko",
                "sha256": module_sha,
            },
            "r580_archive": str(r580_archive),
            "r580_archive_sha256": archive_sha,
            "expected_r580_archive_sha256": archive_sha,
        }
        build_path = root / "evidence/uvm-build.json"
        build_path.write_text(json.dumps(build), encoding="utf-8")
        build_sha = hashlib.sha256(build_path.read_bytes()).hexdigest()

        audit = {
            "schema": "hybrid-module-bundle-static-audit-v1",
            "status": "passed",
            "qualification": "static-module-bundle-closure",
            "kernel_release": "7.0.0-38-generic",
            "issues": [],
            "module_loaded": False,
            "module_installed": False,
            "runtime_or_hardware_validated": False,
            "implementation_sha256": {
                "tools/audit_hybrid_candidate_bundle.py": hashlib.sha256(
                    audit_tool.read_bytes()
                ).hexdigest(),
            },
            "reports": {"uvm": {"path": "evidence/uvm-build.json", "sha256": build_sha}},
            "modules": {
                "uvm": {
                    "name": "nvidia_uvm",
                    "path": "build/nvidia-uvm.ko",
                    "sha256": module_sha,
                    "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions",
                    "version": "595.99.02",
                    "depends": ["nvidia"],
                    "parameters": {"uvm_hybrid_isolated_gpu_execution": {"type": "bool"}},
                }
            },
        }
        audit_path = root / "evidence/bundle-audit.json"
        audit_path.write_text(json.dumps(audit), encoding="utf-8")
        audit_sha = hashlib.sha256(audit_path.read_bytes()).hexdigest()
        depmod = {
            "schema": "hybrid-module-bundle-depmod-static-v1",
            "status": "passed",
            "qualification": "isolated-dependency-map-only",
            "kernel_release": "7.0.0-38-generic",
            "loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
            "audit_report": "evidence/bundle-audit.json",
            "audit_report_sha256": audit_sha,
            "modules": {"uvm": {"name": "nvidia_uvm", "sha256": module_sha}},
            "resolution": {
                "nvidia_uvm": {
                    "ordered_modules": [
                        "hybrid580_open.ko",
                        "hybrid580_legacy.ko",
                        "nvidia.ko",
                        "nvidia_uvm.ko",
                    ]
                }
            },
        }
        depmod_path = root / "evidence/bundle-depmod.json"
        depmod_path.write_text(json.dumps(depmod), encoding="utf-8")
        preflight = {
            "schema": "nvidia-hybrid-canary-preflight-v6",
            "host": "pc3",
            "status": "blocked",
            "canary_ready": False,
            "runtime_validated": False,
            "tool_loaded_modules": False,
            "tool_installed_modules": False,
            "candidate_modules": {"uvm": {"sha256": module_sha}},
            "preflight_inputs": {
                "candidate_bundle_audit": {
                    "path": str(audit_path),
                    "sha256": audit_sha,
                },
                "candidate_depmod_report": {
                    "path": str(depmod_path),
                    "sha256": hashlib.sha256(depmod_path.read_bytes()).hexdigest(),
                },
            },
            "blockers": [{"code": "loaded_module_name_conflict"}],
        }
        preflight_path = root / "evidence/pc3-preflight.json"
        preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
        suite = {
            "schema": "software-verification-openrm-hal-matrix-v1",
            "status": "pass",
            "process_exit_code": 0,
            "tests_run": 2100,
            "qualification": "software-suite-only",
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
            "implementation_sha256": {
                "tools/audit_hybrid_candidate_bundle.py": hashlib.sha256(
                    audit_tool.read_bytes()
                ).hexdigest(),
                "tools/create_r595_uvm_isolation_manifest.py": hashlib.sha256(
                    manifest_tool.read_bytes()
                ).hexdigest(),
            },
            "test_source_sha256": {
                "tests/test_create_r595_uvm_isolation_manifest.py": hashlib.sha256(
                    test_source.read_bytes()
                ).hexdigest(),
            },
        }
        suite_path = root / "evidence/software-suite.json"
        suite_path.write_text(json.dumps(suite), encoding="utf-8")
        return {
            "build_report": build_path,
            "bundle_audit": audit_path,
            "depmod_report": depmod_path,
            "preflight_report": preflight_path,
            "software_suite_report": suite_path,
            "uvm_module": module,
            "modprobe_config": config,
        }, {"build": build, "audit": audit, "depmod": depmod, "module_sha": module_sha}

    def test_manifest_builder_api_exists(self):
        self.assertIsNotNone(build_manifest, "R595 UVM isolation manifest generator is absent")

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_binds_isolation_option_to_exact_module_and_passed_build_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, fixture = self._fixture(root)
            manifest = build_manifest(inputs, project_root=root)
        self.assertEqual(manifest["schema"], "nvidia-hybrid-r595-uvm-isolation-manifest-v2")
        self.assertEqual(manifest["module"]["sha256"], fixture["module_sha"])
        self.assertEqual(manifest["configuration"]["bound_module_sha256"], fixture["module_sha"])
        self.assertEqual(manifest["configuration"]["options"],
                         ["uvm_hybrid_isolated_gpu_execution=1"])
        self.assertEqual(manifest["qualification"], "static-build-and-config-closure")
        self.assertFalse(manifest["activation_performed"])
        self.assertFalse(manifest["runtime_or_hardware_validated"])

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_manifest_binds_suite_that_pinned_generator_auditor_and_test_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self._fixture(root)
            manifest = build_manifest(inputs, project_root=root)
        self.assertEqual(manifest["schema"], "nvidia-hybrid-r595-uvm-isolation-manifest-v2")
        self.assertEqual(manifest["evidence"]["software_suite"]["schema"],
                         "software-verification-openrm-hal-matrix-v1")

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_suite_that_does_not_pin_current_manifest_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self._fixture(root)
            suite = json.loads(inputs["software_suite_report"].read_text())
            suite["implementation_sha256"][
                "tools/create_r595_uvm_isolation_manifest.py"
            ] = "f" * 64
            inputs["software_suite_report"].write_text(json.dumps(suite), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "suite report does not pin the current manifest"):
                build_manifest(inputs, project_root=root)

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_disabled_or_ambiguous_modprobe_option(self):
        for contents in (
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=0\n",
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=0\n",
            "options nvidia uvm_hybrid_isolated_gpu_execution=1\n",
        ):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                inputs, _ = self._fixture(root)
                inputs["modprobe_config"].write_text(contents, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "exact candidate UVM option"):
                    build_manifest(inputs, project_root=root)

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_missing_bool_parameter_even_when_other_audits_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, fixture = self._fixture(root)
            fixture["audit"]["modules"]["uvm"]["parameters"] = {}
            inputs["bundle_audit"].write_text(json.dumps(fixture["audit"]), encoding="utf-8")
            depmod = fixture["depmod"]
            depmod["audit_report_sha256"] = hashlib.sha256(
                inputs["bundle_audit"].read_bytes()
            ).hexdigest()
            inputs["depmod_report"].write_text(json.dumps(depmod), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bool isolation parameter"):
                build_manifest(inputs, project_root=root)

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_module_drift_after_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, _ = self._fixture(root)
            inputs["uvm_module"].write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "UVM module hash differs"):
                build_manifest(inputs, project_root=root)

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_depmod_receipt_for_other_bundle_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, fixture = self._fixture(root)
            fixture["depmod"]["audit_report_sha256"] = "f" * 64
            inputs["depmod_report"].write_text(json.dumps(fixture["depmod"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not pin the exact bundle audit"):
                build_manifest(inputs, project_root=root)

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_bundle_audit_from_different_auditor_implementation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, fixture = self._fixture(root)
            fixture["audit"]["implementation_sha256"][
                "tools/audit_hybrid_candidate_bundle.py"
            ] = "f" * 64
            audit_bytes = json.dumps(fixture["audit"]).encode()
            inputs["bundle_audit"].write_bytes(audit_bytes)
            audit_sha = hashlib.sha256(audit_bytes).hexdigest()
            fixture["depmod"]["audit_report_sha256"] = audit_sha
            inputs["depmod_report"].write_text(json.dumps(fixture["depmod"]), encoding="utf-8")
            preflight = json.loads(inputs["preflight_report"].read_text())
            preflight["preflight_inputs"]["candidate_bundle_audit"]["sha256"] = audit_sha
            preflight["preflight_inputs"]["candidate_depmod_report"]["sha256"] = hashlib.sha256(
                inputs["depmod_report"].read_bytes()
            ).hexdigest()
            inputs["preflight_report"].write_text(json.dumps(preflight), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "auditor source hash differs"):
                build_manifest(inputs, project_root=root)

    @unittest.skipIf(build_manifest is None, "generator API not implemented yet")
    def test_rejects_report_path_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, fixture = self._fixture(root)
            fixture["audit"]["modules"]["uvm"]["path"] = "/etc/passwd"
            inputs["bundle_audit"].write_text(json.dumps(fixture["audit"]), encoding="utf-8")
            depmod = fixture["depmod"]
            depmod["audit_report_sha256"] = hashlib.sha256(
                inputs["bundle_audit"].read_bytes()
            ).hexdigest()
            inputs["depmod_report"].write_text(json.dumps(depmod), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes the project root"):
                build_manifest(inputs, project_root=root)

    @unittest.skipIf(write_report is None, "generator API not implemented yet")
    def test_report_writer_is_private_atomic_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            write_report(path, {"schema": "test"}, project_root=Path(temporary))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_report(path, {"schema": "replaced"}, project_root=Path(temporary))
            self.assertEqual(json.loads(path.read_text()), {"schema": "test"})


if __name__ == "__main__":
    unittest.main()
