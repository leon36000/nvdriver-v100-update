"""Tests for hash-closed R580 module manifest construction."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.create_r580_candidate_module_manifest import build_manifest, write_report


class R580CandidateModuleManifestTests(unittest.TestCase):
    def _fixture(self, root: Path):
        artifact_root = root / "build"
        artifact_root.mkdir()
        module_names = {
            "open": "hybrid580_open",
            "legacy": "hybrid580_legacy",
            "frontend": "nvidia",
            "uvm": "nvidia_uvm",
        }
        dependencies = {
            "hybrid580_open": [],
            "hybrid580_legacy": [],
            "nvidia": ["hybrid580_legacy", "hybrid580_open"],
            "nvidia_uvm": ["nvidia"],
        }
        artifacts = {}
        graph_modules = {}
        for role, name in module_names.items():
            filename = name.replace("_", "-") + ".ko"
            path = artifact_root / filename
            data = ("test module " + name).encode()
            path.write_bytes(data)
            record = {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "version": "" if name == "nvidia" else "580.178.04",
                "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions",
                "depends": dependencies[name],
            }
            artifacts[role] = record
            graph_modules[name] = record
        symvers_path = artifact_root / "Module.symvers"
        symvers_bytes = b"0x00000001 nvUvmInterfaceTest nvidia EXPORT_SYMBOL\n"
        symvers_path.write_bytes(symvers_bytes)
        symvers_digest = hashlib.sha256(symvers_bytes).hexdigest()

        modprobe_config_rel = "packaging/modprobe.d/hybrid580-standard-uvm.conf"
        modprobe_config = root / modprobe_config_rel
        modprobe_config.parent.mkdir(parents=True, exist_ok=True)
        modprobe_config.write_text(
            "# Candidate-only: requires the exact isolated R580 nvidia_uvm module.\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n",
            encoding="utf-8")
        isolated_patch_rel = (
            "patches/r580.178.04/uvm/0007-reject-cross-gpu-tracker-dependencies.patch")
        isolated_patch = root / isolated_patch_rel
        isolated_patch.parent.mkdir(parents=True, exist_ok=True)
        isolated_patch.write_bytes(
            (Path(__file__).resolve().parents[1] / isolated_patch_rel).read_bytes())
        isolated_patch_digest = hashlib.sha256(isolated_patch.read_bytes()).hexdigest()

        reports = {
            "backend_pair": {
                "schema": "nvidia-hybrid-r580-backend-pair-audit-v2",
                "status": "passed",
                "qualification": "static-only-no-load",
                "modules": {role: artifacts[role] for role in ("open", "legacy")},
            },
            "frontend_build": {
                "schema": "nvidia-hybrid-gpu-file-frontend-v1",
                "qualification": "compiled-bdf-selected-gpu-file-frontend-kernel-module",
                "module": artifacts["frontend"],
                "built_module_identity": {"matches": True, "observed": "nvidia"},
                "backend_import_crc_validation": {"verified": True, "mismatches": []},
                "inputs_unchanged": True,
                "unresolved_imports": [],
                "duplicate_import_providers": {},
                "generated_outputs_sha256": {str(symvers_path.resolve()): symvers_digest},
            },
            "uvm_build": {
                "schema": "r580-uvm-isolated-gpu-execution-build-v5",
                "qualification": {
                    "level": "compiled-frontend-bound-uvm",
                    "module_loaded_or_installed": False,
                    "runtime_or_hardware_validated": False,
                },
                "build": {
                    "modules": {"nvidia-uvm.ko": artifacts["uvm"]},
                    "frontend_consumer_binding": {
                        "passed": True,
                        "frontend_module_name": "nvidia",
                        "uvm_interface_import_count": 77,
                        "matching_frontend_crc_count": 77,
                        "symvers_unchanged_after_build": True,
                    },
                },
                "inputs": {
                    "patches": [{
                        "path": isolated_patch_rel,
                        "sha256": isolated_patch_digest,
                    }],
                },
            },
            "uvm_abi": {
                "schema": "nvidia-r580-uvm-consumer-frontend-abi-v2",
                "qualification": "compiled-and-consumer-modversion-crcs-validated",
                "module": {**artifacts["uvm"], "depends": "nvidia"},
                "frontend_symvers": {
                    "provider": "nvidia",
                    "path": symvers_path.relative_to(root).as_posix(),
                    "sha256": symvers_digest,
                },
                "uvm_interface": {
                    "all_crcs_match": True,
                    "consumer_import_count": 77,
                    "provider_only_symbols": ["nvUvmInterfaceUnused"],
                },
            },
            "dependency_graph": {
                "schema": "nvidia-r580-hybrid-module-dependency-graph-v5",
                "qualification": "isolated-depmod-and-modprobe-resolution",
                "kernel_release": "7.0.0-38-generic",
                "frontend_module_name": "nvidia",
                "uvm_module_name": "nvidia_uvm",
                "modules": graph_modules,
                "depmod": {"warning_lines": []},
                "modprobe_show_depends": {
                    "insert_order": ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                                     "nvidia", "nvidia_uvm"],
                },
                "module_load_attempted": False,
                "runtime_or_hardware_validated": False,
            },
            "pc3_preflight": {
                "schema": "nvidia-hybrid-canary-preflight-v4",
                "host": "pc3",
                "status": "blocked",
                "canary_ready": False,
                "expected_module_names": module_names,
                "candidate_modules": {
                    role: {"sha256": artifacts[role]["sha256"], "signer": "", "sig_key": ""}
                    for role in module_names
                },
                "blockers": [{"code": "loaded_module_name_conflict"}],
                "tool_loaded_modules": False,
                "tool_installed_modules": False,
                "runtime_validated": False,
            },
        }
        paths = {}
        for role, report in reports.items():
            path = root / "evidence" / f"{role}.json"
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps(report), encoding="utf-8")
            paths[role] = path
        return paths, reports, artifacts

    def test_builds_manifest_only_when_all_artifact_and_abi_hashes_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _, artifacts = self._fixture(root)
            manifest = build_manifest(paths, project_root=root)

        self.assertEqual(manifest["qualification"],
                         "compiled-abi-closed-and-isolated-dependency-resolved")
        self.assertEqual(manifest["abi_closure"]["uvm_import_count"], 77)
        self.assertEqual(manifest["modules"]["frontend"]["module_name"], "nvidia")
        self.assertEqual(manifest["modules"]["uvm"]["depends"], ["nvidia"])
        self.assertEqual(manifest["schema"], "nvidia-r580-hybrid-candidate-module-manifest-v2")
        self.assertEqual(manifest["runtime_configuration"]["module"], "nvidia_uvm")
        self.assertEqual(manifest["runtime_configuration"]["options"],
                         ["uvm_hybrid_isolated_gpu_execution=1"])
        self.assertEqual(manifest["runtime_configuration"]["candidate_module"]["sha256"],
                         artifacts["uvm"]["sha256"])
        self.assertEqual(manifest["pc3_preflight"]["status"], "blocked")
        self.assertFalse(manifest["runtime_or_hardware_validated"])
        self.assertFalse(manifest["activation_authorized"])

    def test_rejects_crc_or_provider_regression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, reports, _ = self._fixture(root)
            reports["uvm_abi"]["uvm_interface"]["all_crcs_match"] = False
            paths["uvm_abi"].write_text(json.dumps(reports["uvm_abi"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "all 77 standard imports"):
                build_manifest(paths, project_root=root)

    def test_accepts_staged_stack_preflight_schema_v5(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, reports, _ = self._fixture(root)
            reports["pc3_preflight"]["schema"] = "nvidia-hybrid-canary-preflight-v5"
            staged_manifest = "d" * 64
            staged_report = "c" * 64
            uvm_hash = reports["pc3_preflight"]["candidate_modules"]["uvm"]["sha256"]
            reports["pc3_preflight"]["staged_stack_validation"] = {
                "qualification": "staged-manifest-config-module-hash-verified",
                "staging_report_sha256": staged_report,
                "candidate_manifest_sha256": staged_manifest,
                "module_count": 4,
                "activation_performed": False,
                "configuration": {
                    "module": "nvidia_uvm",
                    "options": ["uvm_hybrid_isolated_gpu_execution=1"],
                    "bound_module_sha256": uvm_hash,
                },
            }
            reports["pc3_preflight"]["preflight_inputs"] = {"staged_stack": {
                "staging_report_sha256": staged_report,
                "candidate_manifest_sha256": staged_manifest,
            }}
            paths["pc3_preflight"].write_text(
                json.dumps(reports["pc3_preflight"]), encoding="utf-8")
            manifest = build_manifest(paths, project_root=root)
        self.assertEqual(manifest["pc3_preflight"]["status"], "blocked")

    def test_rejects_preflight_v5_without_staged_uvm_hash_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, reports, _ = self._fixture(root)
            reports["pc3_preflight"]["schema"] = "nvidia-hybrid-canary-preflight-v5"
            paths["pc3_preflight"].write_text(
                json.dumps(reports["pc3_preflight"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "staged UVM option/module hash pair"):
                build_manifest(paths, project_root=root)

    def test_rejects_artifact_tampering_after_build_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _, artifacts = self._fixture(root)
            (root / artifacts["open"]["path"]).write_bytes(b"tampered module")
            with self.assertRaisesRegex(ValueError, "artifact hash differs"):
                build_manifest(paths, project_root=root)

    def test_rejects_isolated_mode_patch_not_used_by_candidate_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, reports, _ = self._fixture(root)
            reports["uvm_build"]["inputs"]["patches"] = []
            paths["uvm_build"].write_text(json.dumps(reports["uvm_build"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "isolated-mode patch"):
                build_manifest(paths, project_root=root)

    def test_rejects_isolated_modprobe_config_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths, _, _ = self._fixture(root)
            config = root / "packaging/modprobe.d/hybrid580-standard-uvm.conf"
            config.write_text("options nvidia_uvm uvm_hybrid_isolated_gpu_execution=0\n",
                              encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "isolated UVM module option"):
                build_manifest(paths, project_root=root)

    def test_report_writer_never_overwrites_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            write_report(path, {"schema": "test"})
            with self.assertRaises(FileExistsError):
                write_report(path, {"schema": "replacement"})
            self.assertEqual(json.loads(path.read_text()), {"schema": "test"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
