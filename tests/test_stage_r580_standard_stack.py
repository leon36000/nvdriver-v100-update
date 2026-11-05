"""Tests for the reversible, non-installing R580 module staging tool."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.stage_r580_standard_stack import stage_candidate


class R580StandardStackStagingTests(unittest.TestCase):
    def _fixture(self, root: Path):
        release = "7.0.0-test"
        tree = root / "build" / "graph" / "lib" / "modules" / release
        update_dir = tree / "updates"
        update_dir.mkdir(parents=True)
        crypto_dir = tree / "kernel" / "crypto"
        crypto_dir.mkdir(parents=True)
        (crypto_dir / "ecdsa_generic.ko.zst").write_bytes(b"ecdsa-module")
        module_bytes = {
            "hybrid580_open": b"open-module",
            "hybrid580_legacy": b"legacy-module",
            "nvidia": b"frontend-module",
            "nvidia-uvm": b"uvm-module",
        }
        roles = {
            "hybrid580_open": "open",
            "hybrid580_legacy": "legacy",
            "nvidia": "frontend",
            "nvidia-uvm": "uvm",
        }
        graph_records = {}
        manifest_modules = {}
        for name, content in module_bytes.items():
            module_path = update_dir / f"{name}.ko"
            module_path.write_bytes(content)
            module_name = name.replace("-", "_")
            digest = hashlib.sha256(content).hexdigest()
            depends = {
                "hybrid580_open": [],
                "hybrid580_legacy": [],
                "nvidia": ["hybrid580_legacy", "hybrid580_open"],
                "nvidia-uvm": ["nvidia"],
            }[name]
            graph_records[module_name] = {
                "path": module_path.relative_to(root).as_posix(),
                "sha256": digest,
                "bytes": len(content),
                "depends": depends,
            }
            manifest_modules[roles[name]] = {
                "module_name": module_name,
                "filename": module_path.name,
                "path": module_path.relative_to(root).as_posix(),
                "sha256": digest,
                "bytes": len(content),
                "depends": depends,
            }
        (tree / "modules.dep").write_text(
            "updates/hybrid580_open.ko:\n"
            "updates/hybrid580_legacy.ko:\n"
            "updates/nvidia.ko: updates/hybrid580_legacy.ko updates/hybrid580_open.ko\n"
            "updates/nvidia-uvm.ko: updates/nvidia.ko\n",
            encoding="utf-8",
        )
        # Exercise copying and preserving non-module dependency metadata too.
        (tree / "modules.softdep").write_text(
            "softdep hybrid580_open pre: ecdh_generic ecdsa_generic\n", encoding="utf-8")
        config = root / "packaging/modprobe.d/hybrid580-standard-uvm.conf"
        config.parent.mkdir(parents=True)
        config.write_text(
            "# Candidate-only.\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n",
            encoding="utf-8",
        )
        manifest_path = root / "evidence/candidate-manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest = {
            "schema": "nvidia-r580-hybrid-candidate-module-manifest-v2",
            "qualification": "compiled-abi-closed-and-isolated-dependency-resolved",
            "candidate": {"kernel_release": release, "uvm_module_name": "nvidia_uvm"},
            "modules": manifest_modules,
            "runtime_configuration": {
                "module": "nvidia_uvm",
                "options": ["uvm_hybrid_isolated_gpu_execution=1"],
                "isolated_mode_required": True,
                "modprobe_config": {
                    "path": "packaging/modprobe.d/hybrid580-standard-uvm.conf",
                    "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                },
                "candidate_module": {"sha256": manifest_modules["uvm"]["sha256"]},
            },
            "abi_closure": {
                "dependency_load_order": ["ecdsa_generic", "hybrid580_open",
                                          "hybrid580_legacy", "nvidia", "nvidia_uvm"]
            },
            "pc3_preflight": {"status": "blocked", "canary_ready": False},
            "runtime_or_hardware_validated": False,
            "module_loaded_or_installed": False,
            "activation_authorized": False,
            "evidence": {},
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        graph_path = root / "evidence/dependency-graph.json"
        graph_path.write_text(json.dumps({
            "schema": "nvidia-r580-hybrid-module-dependency-graph-v5",
            "qualification": "isolated-depmod-and-modprobe-resolution",
            "candidate_base": "build/graph",
            "kernel_release": release,
            "frontend_module_name": "nvidia",
            "uvm_module_name": "nvidia_uvm",
            "modules": graph_records,
            "depmod": {"warning_lines": []},
            "modprobe_show_depends": {
                "insert_order": ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                                 "nvidia", "nvidia_uvm"]
            },
            "module_load_attempted": False,
            "runtime_or_hardware_validated": False,
        }), encoding="utf-8")
        graph_bytes = graph_path.read_bytes()
        manifest["evidence"] = {"dependency_graph": {
            "path": graph_path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(graph_bytes).hexdigest(),
        }}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, manifest, tree

    @staticmethod
    def _modprobe_result(argv, **kwargs):
        # Safe query shape and no insertion command; emulate kmod's read-only output.
        assert "--show-depends" in argv
        assert "--show-depends" in argv
        assert argv[-1] == "nvidia_uvm"
        stage_root = Path(argv[argv.index("-d") + 1])
        release = argv[argv.index("-S") + 1]
        lines = ["builtin ecdh_generic"]
        lines.append(
            f"insmod {stage_root}/lib/modules/{release}/kernel/crypto/ecdsa_generic.ko.zst ")
        for name in ("hybrid580_open", "hybrid580_legacy", "nvidia", "nvidia-uvm"):
            option = " uvm_hybrid_isolated_gpu_execution=1" if name == "nvidia-uvm" else ""
            lines.append(
                f"insmod {stage_root}/lib/modules/{release}/updates/{name}.ko{option} ")
        return type("Result", (), {"returncode": 0, "stdout": "\n".join(lines), "stderr": ""})()

    def test_stages_hash_closed_tree_and_records_read_only_dependency_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, manifest, source_tree = self._fixture(root)
            with patch("tools.stage_r580_standard_stack.subprocess.run",
                       side_effect=self._modprobe_result) as run:
                destination, report = stage_candidate(manifest_path, project_root=root)

            self.assertTrue(destination.is_relative_to(root / "build/staging"))
            self.assertEqual(report["qualification"], "isolated-module-tree-staged-and-dry-run-resolved")
            self.assertFalse(report["activation_performed"])
            self.assertFalse(report["runtime_or_hardware_validated"])
            self.assertEqual(report["modules"]["uvm"]["sha256"],
                             manifest["modules"]["uvm"]["sha256"])
            tree_files = {item["relative_path"]: item for item in report["module_tree_files"]}
            self.assertIn("kernel/crypto/ecdsa_generic.ko.zst", tree_files)
            self.assertEqual((destination / "lib/modules/7.0.0-test/modules.softdep").read_bytes(),
                             (source_tree / "modules.softdep").read_bytes())
            self.assertEqual((destination / "etc/modprobe.d/hybrid580-standard-uvm.conf").read_text(),
                             (root / "packaging/modprobe.d/hybrid580-standard-uvm.conf").read_text())
            self.assertEqual(run.call_count, 1)
            self.assertTrue((destination / "staging-report.json").is_file())
            self.assertTrue((destination / "candidate-manifest.json").is_file())

    def test_refuses_config_hash_mismatch_before_creating_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _, _ = self._fixture(root)
            (root / "packaging/modprobe.d/hybrid580-standard-uvm.conf").write_text(
                "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=0\n", encoding="utf-8")
            with patch("tools.stage_r580_standard_stack.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "configuration hash"):
                    stage_candidate(manifest_path, project_root=root)
            run.assert_not_called()
            self.assertFalse((root / "build/staging").exists())

    def test_refuses_nonzero_or_unexpected_modprobe_plan_and_removes_partial_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _, _ = self._fixture(root)
            bad_result = type("Result", (), {
                "returncode": 1, "stdout": "", "stderr": "unknown option"
            })()
            with patch("tools.stage_r580_standard_stack.subprocess.run", return_value=bad_result):
                with self.assertRaisesRegex(ValueError, "dry-run dependency resolution"):
                    stage_candidate(manifest_path, project_root=root)
            stages = list((root / "build/staging").glob("*"))
            self.assertEqual(stages, [])

    def test_refuses_existing_destination_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path, _, _ = self._fixture(root)
            manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()[:16]
            destination = root / "build/staging" / f"r580-standard-stack-{manifest_digest}"
            destination.mkdir(parents=True)
            sentinel = destination / "keep"
            sentinel.write_text("preserve", encoding="utf-8")
            with patch("tools.stage_r580_standard_stack.subprocess.run"):
                with self.assertRaises(FileExistsError):
                    stage_candidate(manifest_path, project_root=root)
            self.assertEqual(sentinel.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
