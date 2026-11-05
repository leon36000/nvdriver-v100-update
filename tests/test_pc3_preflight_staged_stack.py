# SPDX-License-Identifier: MIT
"""Tests binding PC3 static preflight inputs to the isolated R580 stage."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_pc3_canary_preflight import host_state, load_preflight


class Pc3PreflightStagedStackTests(unittest.TestCase):
    @staticmethod
    def _tree_records(module_tree: Path):
        records = []
        files = sorted((item for item in module_tree.rglob("*") if item.is_file()),
                       key=lambda item: item.relative_to(module_tree).as_posix())
        for path in files:
            raw = path.read_bytes()
            records.append({
                "relative_path": path.relative_to(module_tree).as_posix(),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        return records

    @staticmethod
    def _modprobe_result(argv, **_kwargs):
        stage = Path(argv[argv.index("-d") + 1])
        release = argv[argv.index("-S") + 1]
        paths = [
            f"{stage}/lib/modules/{release}/kernel/crypto/ecdsa_generic.ko.zst",
            f"{stage}/lib/modules/{release}/updates/hybrid580_open.ko",
            f"{stage}/lib/modules/{release}/updates/hybrid580_legacy.ko",
            f"{stage}/lib/modules/{release}/updates/nvidia.ko",
            f"{stage}/lib/modules/{release}/updates/nvidia-uvm.ko",
        ]
        lines = ["builtin ecdh_generic"]
        lines.extend("insmod " + path + (" uvm_hybrid_isolated_gpu_execution=1"
                                         if path.endswith("nvidia-uvm.ko") else "")
                     for path in paths)
        return mock.Mock(returncode=0, stdout="\n".join(lines) + "\n", stderr="")

    def _stage(self, root: Path):
        stage = root / "r580-stage"
        release = "7.0.0-test"
        tree = stage / "lib/modules" / release
        module_dir = tree / "updates"
        module_dir.mkdir(parents=True)
        filenames = {
            "open": ("hybrid580_open", "hybrid580_open.ko", b"open"),
            "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko", b"legacy"),
            "frontend": ("nvidia", "nvidia.ko", b"frontend"),
            "uvm": ("nvidia_uvm", "nvidia-uvm.ko", b"uvm"),
        }
        manifest_modules = {}
        stage_modules = {}
        module_metadata = {}
        for role, (name, filename, content) in filenames.items():
            path = module_dir / filename
            path.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            manifest_modules[role] = {
                "module_name": name,
                "filename": filename,
                "sha256": digest,
                "bytes": len(content),
            }
            relative = f"lib/modules/{release}/updates/{filename}"
            stage_modules[role] = {
                "relative_path": relative,
                "sha256": digest,
                "bytes": len(content),
            }
            module_metadata[role] = {
                "name": name,
                "path": str(path),
                "sha256": digest,
                "bytes": len(content),
            }
        crypto = tree / "kernel/crypto"
        crypto.mkdir(parents=True)
        (crypto / "ecdsa_generic.ko.zst").write_bytes(b"ecdsa")
        (tree / "modules.dep").write_text(
            "kernel/crypto/ecdsa_generic.ko.zst:\n"
            "updates/hybrid580_open.ko:\n"
            "updates/hybrid580_legacy.ko:\n"
            "updates/nvidia.ko: updates/hybrid580_legacy.ko updates/hybrid580_open.ko\n"
            "updates/nvidia-uvm.ko: updates/nvidia.ko\n",
            encoding="utf-8",
        )
        config = stage / "etc/modprobe.d/hybrid580-standard-uvm.conf"
        config.parent.mkdir(parents=True)
        config.write_text(
            "# Candidate-only.\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n",
            encoding="utf-8",
        )
        config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
        uvm_hash = manifest_modules["uvm"]["sha256"]
        manifest = {
            "schema": "nvidia-r580-hybrid-candidate-module-manifest-v2",
            "candidate": {"kernel_release": release},
            "modules": manifest_modules,
            "runtime_configuration": {
                "module": "nvidia_uvm",
                "options": ["uvm_hybrid_isolated_gpu_execution=1"],
                "isolated_mode_required": True,
                "modprobe_config": {
                    "path": "packaging/modprobe.d/hybrid580-standard-uvm.conf",
                    "sha256": config_hash,
                },
                "candidate_module": {"sha256": uvm_hash},
            },
            "pc3_preflight": {"status": "blocked", "canary_ready": False},
            "activation_authorized": False,
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        }
        manifest_path = stage / "candidate-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        staging_report = {
            "schema": "nvidia-r580-standard-stack-staging-v1",
            "qualification": "isolated-module-tree-staged-and-dry-run-resolved",
            "manifest": {"relative_path": "candidate-manifest.json", "sha256": manifest_hash},
            "kernel_release": release,
            "configuration": {
                "relative_path": "etc/modprobe.d/hybrid580-standard-uvm.conf",
                "sha256": config_hash,
                "module": "nvidia_uvm",
                "options": ["uvm_hybrid_isolated_gpu_execution=1"],
                "bound_module_sha256": uvm_hash,
            },
            "modules": stage_modules,
            "module_tree_files": self._tree_records(tree),
            "dry_run": {
                "exit_code": 0,
                "stderr_empty": True,
                "insert_order": ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                                 "nvidia", "nvidia_uvm"],
                "module_load_attempted": False,
            },
            "pc3_preflight_status": "blocked",
            "activation_performed": False,
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        }
        (stage / "staging-report.json").write_text(json.dumps(staging_report), encoding="utf-8")
        return stage, manifest, module_metadata

    def test_validates_staged_config_and_exact_uvm_module_hash_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, manifest, modules = self._stage(Path(temporary))
            tool = load_preflight()
            with mock.patch.object(tool.subprocess, "run",
                                   side_effect=self._modprobe_result) as run:
                result = tool.validate_staged_stack(stage, modules)

        self.assertEqual(result["configuration"]["options"],
                         ["uvm_hybrid_isolated_gpu_execution=1"])
        self.assertEqual(result["configuration"]["bound_module_sha256"],
                         manifest["modules"]["uvm"]["sha256"])
        self.assertEqual(result["dry_run"]["insert_order"],
                         ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                          "nvidia", "nvidia_uvm"])
        self.assertTrue(result["dry_run"]["independently_reexecuted"])
        self.assertEqual(run.call_count, 1)
        self.assertIn("--show-depends", run.call_args.args[0])
        self.assertIs(run.call_args.kwargs["stdin"], tool.subprocess.DEVNULL)
        self.assertFalse(result["activation_performed"])

    def test_rejects_config_or_module_hash_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, _, modules = self._stage(Path(temporary))
            config = stage / "etc/modprobe.d/hybrid580-standard-uvm.conf"
            config.write_text("options nvidia_uvm uvm_hybrid_isolated_gpu_execution=0\n",
                              encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "configuration hash"):
                load_preflight().validate_staged_stack(stage, modules)
            second_stage, _, second_modules = self._stage(Path(temporary) / "second")
            changed = dict(second_modules)
            changed["uvm"] = dict(second_modules["uvm"], sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "UVM module hash"):
                load_preflight().validate_staged_stack(second_stage, changed)

    def test_rejects_a_preflight_module_path_outside_the_validated_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, _, modules = self._stage(Path(temporary))
            modules["uvm"]["path"] = str(Path(temporary) / "outside/nvidia-uvm.ko")
            with self.assertRaisesRegex(ValueError, "module path is outside"):
                load_preflight().validate_staged_stack(stage, modules)

    def test_rehashes_every_module_tree_file_before_modprobe(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, _, modules = self._stage(Path(temporary))
            dependency_file = stage / "lib/modules/7.0.0-test/modules.dep"
            dependency_file.write_text(dependency_file.read_text(encoding="utf-8") + "# drift\n",
                                      encoding="utf-8")
            tool = load_preflight()
            with mock.patch.object(tool.subprocess, "run",
                                   side_effect=self._modprobe_result) as run:
                with self.assertRaisesRegex(ValueError, "module-tree bytes differ"):
                    tool.validate_staged_stack(stage, modules)
            run.assert_not_called()

    def test_rejects_malformed_or_duplicate_reported_tree_records(self):
        for mutation, message in (
                (lambda report: report["module_tree_files"].append(
                    dict(report["module_tree_files"][0])), "module-tree bytes differ"),
                (lambda report: report["module_tree_files"].__setitem__(0, {
                    "relative_path": 17, "bytes": 1, "sha256": "0" * 64}),
                 "invalid module-tree record")):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                stage, _, modules = self._stage(Path(temporary))
                report_path = stage / "staging-report.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                mutation(report)
                report_path.write_text(json.dumps(report), encoding="utf-8")
                tool = load_preflight()
                with mock.patch.object(tool.subprocess, "run",
                                       side_effect=self._modprobe_result) as run:
                    with self.assertRaisesRegex(ValueError, message):
                        tool.validate_staged_stack(stage, modules)
                run.assert_not_called()

    def test_rejects_symlink_in_module_tree_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage, _, modules = self._stage(root)
            tree = stage / "lib/modules/7.0.0-test"
            outside = root / "outside.modules.dep"
            outside.write_text("outside\n", encoding="utf-8")
            (tree / "modules.dep").unlink()
            (tree / "modules.dep").symlink_to(outside)
            tool = load_preflight()
            with mock.patch.object(tool.subprocess, "run",
                                   side_effect=self._modprobe_result) as run:
                with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                    tool.validate_staged_stack(stage, modules)
            run.assert_not_called()

    def test_rejects_symlinked_module_tree_ancestor_inside_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, _, modules = self._stage(Path(temporary))
            lib_path = stage / "lib"
            moved_path = stage / "module-tree-alias-target"
            lib_path.rename(moved_path)
            lib_path.symlink_to(moved_path, target_is_directory=True)
            tool = load_preflight()
            with mock.patch.object(tool.subprocess, "run",
                                   side_effect=self._modprobe_result) as run:
                with self.assertRaisesRegex(ValueError, "symlink component"):
                    tool.validate_staged_stack(stage, modules)
            run.assert_not_called()

    def test_rejects_module_tree_redirect_persisting_across_independent_dry_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, _, modules = self._stage(Path(temporary))
            tool = load_preflight()

            def redirect_tree_after_kmod(_stage, _config, _release):
                lib_path = stage / "lib"
                moved_path = stage / "module-tree-alias-target"
                lib_path.rename(moved_path)
                lib_path.symlink_to(moved_path, target_is_directory=True)
                return ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                        "nvidia", "nvidia_uvm"]

            with mock.patch.object(tool, "_independent_staged_modprobe_dry_run",
                                   side_effect=redirect_tree_after_kmod) as run:
                with self.assertRaisesRegex(ValueError, "module tree path contains"):
                    tool.validate_staged_stack(stage, modules)
            run.assert_called_once()

    def test_independently_rejects_changed_modprobe_plan_even_if_report_claims_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage, _, modules = self._stage(Path(temporary))
            tool = load_preflight()
            unexpected = mock.Mock(returncode=0, stdout="builtin ecdh_generic\n", stderr="")
            with mock.patch.object(tool.subprocess, "run", return_value=unexpected) as run:
                with self.assertRaisesRegex(ValueError, "unexpected insertion plan"):
                    tool.validate_staged_stack(stage, modules)
            run.assert_called_once()

    def test_cli_attaches_stage_validation_to_blocked_read_only_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage, _, staged_metadata = self._stage(root)
            state_path = root / "host-state.json"
            state_path.write_text(json.dumps(host_state()), encoding="utf-8")
            header_path = root / "nv-chardev-numbers.h"
            header_path.write_text(
                "#define NV_MAJOR_DEVICE_NUMBER 195\n"
                "#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 247\n"
                "#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255\n",
                encoding="utf-8")
            source_path = root / "hybrid580-standard-node-devices.c"
            source_path.write_text(
                "register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, 0), "
                "NV_MINOR_DEVICE_NUMBER_REGULAR_MAX + 1U, GPU_NAME);\n"
                "register_chrdev_region(MKDEV(NV_MAJOR_DEVICE_NUMBER, "
                "NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE), 1, CTL_NAME);\n",
                encoding="utf-8")
            enriched = {}
            dependencies = {
                "open": "", "legacy": "", "frontend": "hybrid580_legacy,hybrid580_open",
                "uvm": "nvidia",
            }
            for role, record in staged_metadata.items():
                enriched[role] = {
                    **record,
                    "version": "" if role == "frontend" else "580.178.04",
                    "vermagic": "7.0.0-test SMP preempt mod_unload modversions",
                    "signer": "",
                    "sig_key": "",
                    "depends": dependencies[role],
                }
            args = [
                "--host-state", str(state_path),
                "--open", enriched["open"]["path"],
                "--legacy", enriched["legacy"]["path"],
                "--frontend", enriched["frontend"]["path"],
                "--uvm", enriched["uvm"]["path"],
                "--frontend-module-name", "nvidia",
                "--uvm-module-name", "nvidia_uvm",
                "--node-header", str(header_path),
                "--frontend-source", str(source_path),
                "--staged-stack", str(stage),
            ]
            stdout = io.StringIO()
            tool = load_preflight()
            with mock.patch.object(tool, "_module_metadata",
                                   side_effect=lambda role, _path: enriched[role]), \
                    mock.patch.object(tool.subprocess, "run",
                                     side_effect=self._modprobe_result), \
                    mock.patch.object(tool.sys, "stdout", stdout):
                exit_code = tool.main(args)

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["schema"], "nvidia-hybrid-canary-preflight-v5")
        self.assertEqual(report["staged_stack_validation"]["configuration"]["bound_module_sha256"],
                         report["candidate_modules"]["uvm"]["sha256"])
        self.assertTrue(report["staged_stack_validation"]["dry_run"]["independently_reexecuted"])
        self.assertFalse(report["staged_stack_validation"]["activation_performed"])
        self.assertFalse(report["tool_loaded_modules"])
        self.assertIn("staged_stack", report["preflight_inputs"])


if __name__ == "__main__":
    unittest.main()
