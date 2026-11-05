"""Tests for private R595 staging and read-only kmod dependency resolution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.stage_r595_uvm_isolated_bundle import stage_candidate


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class R595IsolatedBundleStageTests(unittest.TestCase):
    def _fixture(self, root: Path):
        release = "7.0.0-stage-test"
        module_dir = root / "build/artifacts"
        module_dir.mkdir(parents=True)
        contents = {
            "open": ("hybrid580_open", "hybrid580_open.ko", b"open"),
            "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko", b"legacy"),
            "frontend": ("nvidia", "nvidia.ko", b"frontend"),
            "uvm": ("nvidia_uvm", "nvidia_uvm.ko", b"uvm"),
        }
        dependencies = {
            "open": [], "legacy": [], "frontend": ["hybrid580_legacy", "hybrid580_open"],
            "uvm": ["nvidia"],
        }
        modules = {}
        for role, (name, filename, raw) in contents.items():
            path = module_dir / filename
            path.write_bytes(raw)
            modules[role] = {
                "name": name,
                "path": path.relative_to(root).as_posix(),
                "sha256": _sha(raw),
                "depends": dependencies[role],
                "vermagic": release + " SMP modversions",
                "bytes": len(raw),
                "parameters": ({"uvm_hybrid_isolated_gpu_execution": {"type": "bool"}}
                               if role == "uvm" else {}),
            }

        evidence = root / "evidence"
        evidence.mkdir()
        audit_path = evidence / "audit.json"
        audit_path.write_text(json.dumps({
            "schema": "hybrid-module-bundle-static-audit-v1",
            "status": "passed",
            "qualification": "static-module-bundle-closure",
            "kernel_release": release,
            "modules": modules,
            "issues": [],
            "module_loaded": False,
            "module_installed": False,
            "runtime_or_hardware_validated": False,
        }), encoding="utf-8")
        config_path = root / "packaging/modprobe.d/hybrid595-standard-uvm.conf"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            "# private candidate option\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n", encoding="utf-8")
        manifest = {
            "schema": "nvidia-hybrid-r595-uvm-isolation-manifest-v2",
            "created_at_utc": "2026-10-29T10:16:33+00:00",
            "qualification": "static-build-and-config-closure",
            "kernel_release": release,
            "module": {"name": "nvidia_uvm", **modules["uvm"]},
            "configuration": {
                "path": config_path.relative_to(root).as_posix(),
                "sha256": _sha(config_path.read_bytes()),
                "bytes": config_path.stat().st_size,
                "module": "nvidia_uvm",
                "options": ["uvm_hybrid_isolated_gpu_execution=1"],
                "isolated_execution_required": True,
                "activation_performed": False,
                "bound_module_sha256": modules["uvm"]["sha256"],
            },
            "source_hal": {"release": "580.196.07"},
            "dependency_load_order": [
                "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko", "nvidia_uvm.ko"],
            "pc3_preflight": {"status": "blocked", "canary_ready": False},
            "evidence": {
                "bundle_audit": {
                    "path": audit_path.relative_to(root).as_posix(),
                    "sha256": _sha(audit_path.read_bytes()),
                },
                "depmod": {"path": "evidence/depmod.json", "sha256": "d" * 64},
                "uvm_build": {"path": "evidence/build.json", "sha256": "b" * 64},
                "pc3_preflight": {"path": "evidence/preflight.json", "sha256": "p" * 64},
                "software_suite": {"path": "evidence/suite.json", "sha256": "s" * 64},
            },
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
            "activation_performed": False,
        }
        manifest_path = evidence / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, manifest, modules

    @staticmethod
    def _runner(argv, **kwargs):
        if argv[0] == "depmod":
            stage = Path(argv[argv.index("-b") + 1])
            release = argv[-1]
            (stage / "lib/modules" / release / "modules.dep").write_text(
                "updates/extra/hybrid580_open.ko:\n"
                "updates/extra/hybrid580_legacy.ko:\n"
                "updates/extra/nvidia.ko: updates/extra/hybrid580_legacy.ko "
                "updates/extra/hybrid580_open.ko\n"
                "updates/extra/nvidia_uvm.ko: updates/extra/nvidia.ko\n",
                encoding="utf-8")
            return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        assert argv[0] == "modprobe"
        assert "--show-depends" in argv
        assert argv[-1] == "nvidia_uvm"
        stage = Path(argv[argv.index("-d") + 1])
        release = argv[argv.index("--set-version") + 1]
        names = ("hybrid580_open", "hybrid580_legacy", "nvidia", "nvidia_uvm")
        lines = [
            f"insmod {stage}/lib/modules/{release}/updates/extra/{name}.ko"
            + (" uvm_hybrid_isolated_gpu_execution=1" if name == "nvidia_uvm" else "")
            for name in names
        ]
        return type("Result", (), {
            "returncode": 0, "stdout": "\n".join(lines) + "\n", "stderr": "",
        })()

    def test_stages_exact_manifest_bound_modules_and_dry_run_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, modules = self._fixture(root)
            manifest_hash = _sha(manifest_path.read_bytes())
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=manifest), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run",
                          side_effect=self._runner) as run:
                destination, report = stage_candidate(
                    manifest_path, manifest_hash, project_root=root)

            self.assertTrue(destination.is_relative_to(root / "build/staging"))
            self.assertEqual(report["qualification"],
                             "isolated-module-tree-staged-and-dry-run-resolved")
            self.assertEqual(report["dry_run"]["insert_order"], [
                "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko", "nvidia_uvm.ko"])
            self.assertFalse(report["activation_performed"])
            self.assertFalse(report["module_loaded_or_installed"])
            self.assertFalse(report["runtime_or_hardware_validated"])
            self.assertEqual(run.call_count, 2)
            for role, record in modules.items():
                staged = destination / "lib/modules" / manifest["kernel_release"] / "updates/extra" / record["path"].split("/")[-1]
                self.assertEqual(_sha(staged.read_bytes()), record["sha256"], role)
            self.assertEqual(
                (destination / "etc/modprobe.d/hybrid595-standard-uvm.conf").read_bytes(),
                (root / manifest["configuration"]["path"]).read_bytes())
            self.assertTrue((destination / "staging-report.json").is_file())

    def test_refuses_wrong_expected_manifest_hash_before_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, _ = self._fixture(root)
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=manifest), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "manifest SHA-256 mismatch"):
                    stage_candidate(manifest_path, "0" * 64, project_root=root)
            run.assert_not_called()
            self.assertFalse((root / "build/staging").exists())

    def test_refuses_manifest_that_no_longer_rebuilds_from_pinned_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, _ = self._fixture(root)
            changed = dict(manifest)
            changed["kernel_release"] = "7.0.0-foreign"
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=changed), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "no longer matches"):
                    stage_candidate(manifest_path, _sha(manifest_path.read_bytes()), project_root=root)
            run.assert_not_called()
            self.assertFalse((root / "build/staging").exists())

    def test_refuses_module_bytes_changed_after_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, modules = self._fixture(root)
            (root / modules["frontend"]["path"]).write_bytes(b"tampered frontend")
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=manifest), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "audited module identity or bytes differ"):
                    stage_candidate(manifest_path, _sha(manifest_path.read_bytes()), project_root=root)
            run.assert_not_called()
            self.assertFalse((root / "build/staging").exists())

    def test_depmod_failure_cleans_temporary_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, _ = self._fixture(root)
            failure = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "bad image"})()
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=manifest), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run", return_value=failure):
                with self.assertRaisesRegex(ValueError, "private depmod failed"):
                    stage_candidate(manifest_path, _sha(manifest_path.read_bytes()), project_root=root)
            self.assertEqual(list((root / "build/staging").iterdir()), [])

    def test_removes_partial_private_stage_when_kmod_rejects_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, _ = self._fixture(root)
            def bad_runner(argv, **kwargs):
                if argv[0] == "depmod":
                    stage = Path(argv[argv.index("-b") + 1])
                    release = argv[-1]
                    (stage / "lib/modules" / release / "modules.dep").write_text("", encoding="utf-8")
                    return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
                stage = Path(argv[argv.index("-d") + 1])
                release = argv[argv.index("--set-version") + 1]
                line = f"insmod {stage}/lib/modules/{release}/updates/extra/nvidia_uvm.ko uvm_hybrid_isolated_gpu_execution=1\n"
                return type("Result", (), {"returncode": 0, "stdout": line, "stderr": ""})()
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=manifest), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run", side_effect=bad_runner):
                with self.assertRaisesRegex(ValueError, "dependency order"):
                    stage_candidate(manifest_path, _sha(manifest_path.read_bytes()), project_root=root)
            self.assertEqual(list((root / "build/staging").iterdir()), [])

    def test_refuses_overwrite_of_manifest_derived_stage_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, _ = self._fixture(root)
            digest = _sha(manifest_path.read_bytes())
            target = root / "build/staging" / f"r595-uvm-isolated-{digest[:16]}"
            target.mkdir(parents=True)
            sentinel = target / "preserve"
            sentinel.write_text("preserved", encoding="utf-8")
            with patch("tools.stage_r595_uvm_isolated_bundle.build_manifest", return_value=manifest), \
                    patch("tools.stage_r595_uvm_isolated_bundle.subprocess.run") as run:
                with self.assertRaises(FileExistsError):
                    stage_candidate(manifest_path, digest, project_root=root)
            run.assert_not_called()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserved")


if __name__ == "__main__":
    unittest.main()
