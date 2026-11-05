#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for isolated PC3 R580 dependency staging."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/stage_pc3_v100_r580_depmod.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_r580_depmod_stage", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(name: str, path: str, payload: bytes, *, kind: str, depends=None):
    value = {
        "name": name,
        "path": path,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "kind": kind,
    }
    if depends is not None:
        value["depends"] = depends
    return value


class PC3V100R580DepmodStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tool = load_tool()
        release = self.tool.KERNEL_RELEASE
        self.capture_root = self.root / "build/experiments/captured"
        module_root = self.capture_root / "lib/modules" / release
        crypto = module_root / "kernel/crypto"
        crypto.mkdir(parents=True)
        contents = {
            "ecc": ("kernel/crypto/ecc.ko.zst", b"ecc", []),
            "ecdh_generic": ("kernel/crypto/ecdh_generic.ko.zst", b"ecdh", ["ecc"]),
            "ecdsa_generic": ("kernel/crypto/ecdsa_generic.ko.zst", b"ecdsa", ["ecc"]),
        }
        for relative, payload, _ in contents.values():
            (module_root / relative).write_bytes(payload)
        module_order = (
            "kernel/crypto/ecdsa_generic.ko\n"
            "kernel/crypto/ecc.ko\n"
            "kernel/crypto/ecdh_generic.ko\n"
        ).encode()
        metadata = {
            "modules.builtin": b"# builtins\n",
            "modules.builtin.modinfo": b"# builtin metadata\n",
            "modules.dep": b"kernel/crypto/ecc.ko.zst:\n",
            "modules.order": module_order,
            "modules.softdep": b"# no stock softdeps\n",
        }
        files = []
        for name, (relative, payload, depends) in contents.items():
            item = record(
                name,
                f"{self.capture_root.relative_to(self.root).as_posix()}/lib/modules/{release}/{relative}",
                payload, kind="module", depends=depends)
            item["guest_path"] = relative
            files.append(item)
        for name, payload in metadata.items():
            (module_root / name).write_bytes(payload)
            item = record(
                name,
                f"{self.capture_root.relative_to(self.root).as_posix()}/lib/modules/{release}/{name}",
                payload, kind="metadata")
            item["guest_path"] = name
            files.append(item)
        self.capture_path = self.root / "evidence/dependency-capture.json"
        self.capture_path.parent.mkdir(parents=True)
        self.capture_path.write_text(json.dumps({
            "schema": "pc3-v100-kernel-dependency-capture-v1",
            "status": "captured",
            "qualification": "read-only-exact-kernel-support-module-capture",
            "target": "pc3@pc3",
            "guest_hostname": "pc3-v100",
            "kernel_release": release,
            "stage_root": self.capture_root.relative_to(self.root).as_posix(),
            "files": files,
            "guest_mutation_performed": False,
            "module_installed": False,
            "module_loaded": False,
            "runtime_or_hardware_validated": False,
        }), encoding="utf-8")

        self.artifacts = {}
        module_records = {}
        roles = {
            "open": ("hybrid580_open", "hybrid580_open.ko", b"open", ["ecc"]),
            "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko", b"legacy", []),
            "frontend": ("nvidia", "nvidia.ko", b"frontend", ["hybrid580_legacy", "hybrid580_open"]),
            "uvm": ("nvidia_uvm", "nvidia-uvm.ko", b"uvm", ["nvidia"]),
        }
        for role, (name, filename, payload, depends) in roles.items():
            source = self.root / "build/experiments/source" / filename
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(payload)
            item = record(name, str(source), payload, kind="module", depends=depends)
            module_records[role] = item
            self.artifacts[name] = {"path": str(source), "sha256": item["sha256"], "bytes": item["bytes"]}
        self.bundle_path = self.root / "evidence/static-bundle-audit.json"
        self.bundle_path.write_text(json.dumps({
            "schema": "nvidia-pc3-v100-r580-hybrid-static-stack-audit-v1",
            "status": "passed",
            "qualification": "static-module-bundle-closure",
            "target": "pc3@pc3",
            "guest_hostname": "pc3-v100",
            "kernel_release": release,
            "gpu_accessed": False,
            "module_installed": False,
            "module_loaded": False,
            "cuda_execution_tested": False,
            "runtime_or_hardware_validated": False,
            "verified_artifacts": {role: self.artifacts[values[0]]
                                   for role, values in roles.items()},
            "static_audit": {
                "schema": "hybrid-module-bundle-static-audit-v1",
                "status": "passed",
                "qualification": "static-module-bundle-closure",
                "kernel_release": release,
                "modules": module_records,
                "module_loaded": False,
                "runtime_or_hardware_validated": False,
                "issues": [],
            },
        }), encoding="utf-8")
        self.stage_root = self.root / "build/experiments/staged"

    def tearDown(self):
        self.temporary.cleanup()

    def _runner(self, argv, **kwargs):
        if argv[:2] == ["modprobe", "--version"] or argv[-1:] == ["--version"]:
            return _result(0, "kmod version 34.2\n+ZSTD +XZ\n", "")
        if argv[0] == "modinfo":
            field = argv[argv.index("-F") + 1]
            path = Path(argv[-1])
            name_by_file = {
                "hybrid580_open.ko": "hybrid580_open",
                "hybrid580_legacy.ko": "hybrid580_legacy",
                "nvidia.ko": "nvidia",
                "nvidia_uvm.ko": "nvidia_uvm",
            }
            name = name_by_file[path.name]
            values = {
                "name": name,
                "depends": {
                    "hybrid580_open": "ecc",
                    "hybrid580_legacy": "",
                    "nvidia": "hybrid580_legacy,hybrid580_open",
                    "nvidia_uvm": "nvidia",
                }[name],
                "vermagic": self.tool.KERNEL_RELEASE + " SMP preempt mod_unload modversions",
                "version": "" if name == "nvidia" else "580.178.04",
            }
            return _result(0, values[field] + "\n", "")
        if argv[0] == "depmod":
            module_root = Path(argv[argv.index("-b") + 1]) / "lib/modules" / argv[-1]
            (module_root / "modules.dep").write_text(
                "kernel/crypto/ecc.ko.zst:\n"
                "kernel/crypto/ecdh_generic.ko.zst: kernel/crypto/ecc.ko.zst\n"
                "kernel/crypto/ecdsa_generic.ko.zst: kernel/crypto/ecc.ko.zst\n"
                "updates/extra/hybrid580_open.ko: kernel/crypto/ecc.ko.zst\n"
                "updates/extra/hybrid580_legacy.ko:\n"
                "updates/extra/nvidia.ko: updates/extra/hybrid580_legacy.ko updates/extra/hybrid580_open.ko kernel/crypto/ecc.ko.zst\n"
                "updates/extra/nvidia_uvm.ko: updates/extra/nvidia.ko updates/extra/hybrid580_legacy.ko updates/extra/hybrid580_open.ko kernel/crypto/ecc.ko.zst\n",
                encoding="utf-8",
            )
            (module_root / "modules.softdep").write_text(
                "# Soft dependencies extracted from modules themselves.\n"
                "softdep hybrid580_open pre: ecdh_generic ecdsa_generic\n",
                encoding="utf-8",
            )
            return _result(0, "", "")
        if argv[0] == "modprobe" and "--show-depends" in argv:
            base = Path(argv[argv.index("-d") + 1])
            root = base / "lib/modules" / self.tool.KERNEL_RELEASE
            lines = [
                root / "kernel/crypto/ecc.ko.zst",
                root / "kernel/crypto/ecc.ko.zst",
                root / "kernel/crypto/ecdh_generic.ko.zst",
                root / "kernel/crypto/ecc.ko.zst",
                root / "kernel/crypto/ecdsa_generic.ko.zst",
                root / "updates/extra/hybrid580_open.ko",
                root / "updates/extra/hybrid580_legacy.ko",
                root / "updates/extra/nvidia.ko",
                root / "updates/extra/nvidia_uvm.ko",
            ]
            return _result(0, "".join(f"insmod {path} \n" for path in lines), "")
        if argv[0] == "modprobe" and "--dry-run" in argv:
            base = Path(argv[argv.index("-d") + 1])
            root = base / "lib/modules" / self.tool.KERNEL_RELEASE
            names = [
                ("ecc", "kernel/crypto/ecc.ko.zst"),
                ("ecdh_generic", "kernel/crypto/ecdh_generic.ko.zst"),
                ("ecdsa_generic", "kernel/crypto/ecdsa_generic.ko.zst"),
                ("hybrid580_open", "updates/extra/hybrid580_open.ko"),
                ("hybrid580_legacy", "updates/extra/hybrid580_legacy.ko"),
                ("nvidia", "updates/extra/nvidia.ko"),
                ("nvidia_uvm", "updates/extra/nvidia_uvm.ko"),
            ]
            return _result(0, "".join(f"insmod {root / path} \n" for _, path in names), "")
        raise AssertionError("unexpected external command: " + " ".join(argv))

    def test_stages_exact_artifacts_and_validates_kernel_dependency_walk(self):
        sysfs = self.root / "sys/module"
        (sysfs / "nvidia").mkdir(parents=True)
        (sysfs / "nvidia_uvm").mkdir()
        with patch.object(self.tool.subprocess, "run", side_effect=self._runner) as run:
            report = self.tool.stage_bundle(
                self.bundle_path, self.capture_path, self.stage_root,
                project_root=self.root, sysfs_module_root=sysfs,
            )

        self.assertEqual(report["qualification"], "isolated-depmod-and-dependency-walk-validated")
        self.assertEqual(report["implementation"]["path"], "tools/stage_pc3_v100_r580_depmod.py")
        self.assertEqual(report["implementation"]["sha256"],
                         hashlib.sha256(TOOL.read_bytes()).hexdigest())
        self.assertEqual(report["kmod"]["version"], "34.2")
        self.assertEqual(report["depmod"]["warning_lines"], [])
        self.assertEqual(report["resolved_dependency_walk"]["first_occurrence_module_names"], [
            "ecc", "ecdh_generic", "ecdsa_generic", "hybrid580_open",
            "hybrid580_legacy", "nvidia", "nvidia_uvm",
        ])
        self.assertEqual(report["resolved_dependency_walk"]["repeated_module_names"], {"ecc": 3})
        self.assertFalse(report["resolved_dependency_walk"]["is_insert_order_proof"])
        self.assertFalse(report["dry_run"]["executed"])
        self.assertEqual(report["dry_run"]["loaded_name_collisions"], ["nvidia", "nvidia_uvm"])
        self.assertIn("active kernel", report["dry_run"]["skipped_reason"])
        self.assertFalse(report["module_load_attempted"])
        self.assertFalse(report["runtime_or_hardware_validated"])
        self.assertEqual(run.call_count, 4 * 4 + 4)
        self.assertTrue((self.stage_root / "lib/modules/6.8.0-147-generic/updates/extra/nvidia.ko").is_file())
        self.assertTrue((self.stage_root / "lib/modules/6.8.0-147-generic/kernel/crypto/ecc.ko.zst").is_file())
        tree_files = {item["relative_path"]: item for item in report["staging"]["tree_files"]}
        self.assertIn("lib/modules/6.8.0-147-generic/modules.dep", tree_files)
        self.assertTrue(all(len(item["sha256"]) == 64 for item in tree_files.values()))

    def test_rejects_modified_capture_file_before_running_tools(self):
        module = self.capture_root / "lib/modules" / self.tool.KERNEL_RELEASE / "kernel/crypto/ecc.ko.zst"
        module.write_bytes(b"tampered")
        with patch.object(self.tool.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "capture hash"):
                self.tool.stage_bundle(
                    self.bundle_path, self.capture_path, self.stage_root,
                    project_root=self.root, sysfs_module_root=self.root / "empty-sys-module",
                )
        run.assert_not_called()
        self.assertFalse(self.stage_root.exists())

    def test_uses_dry_run_only_when_candidate_names_are_absent_from_runner(self):
        with patch.object(self.tool.subprocess, "run", side_effect=self._runner) as run:
            report = self.tool.stage_bundle(
                self.bundle_path, self.capture_path, self.stage_root,
                project_root=self.root, sysfs_module_root=self.root / "empty-sys-module",
            )
        self.assertTrue(report["dry_run"]["executed"])
        self.assertEqual(report["dry_run"]["insertion_order"], [
            "ecc", "ecdh_generic", "ecdsa_generic", "hybrid580_open",
            "hybrid580_legacy", "nvidia", "nvidia_uvm",
        ])
        self.assertTrue(any("--dry-run" in call.args[0] for call in run.call_args_list))

    def test_rejects_artifact_hash_mismatch_before_staging(self):
        audit = json.loads(self.bundle_path.read_text())
        audit["static_audit"]["modules"]["open"]["sha256"] = "0" * 64
        audit["verified_artifacts"]["open"]["sha256"] = "0" * 64
        self.bundle_path.write_text(json.dumps(audit))
        with patch.object(self.tool.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "artifact hash"):
                self.tool.stage_bundle(
                    self.bundle_path, self.capture_path, self.stage_root,
                    project_root=self.root, sysfs_module_root=self.root / "empty-sys-module",
                )
        run.assert_not_called()
        self.assertFalse(self.stage_root.exists())

    def test_rejects_unexpected_shared_dependency_duplicate(self):
        original = self._runner

        def runner(argv, **kwargs):
            if argv[0] == "modprobe" and "--show-depends" in argv:
                result = original(argv, **kwargs)
                lines = result.stdout.splitlines()
                lines.append(lines[-1])
                return _result(0, "\n".join(lines) + "\n", "")
            return original(argv, **kwargs)

        with patch.object(self.tool.subprocess, "run", side_effect=runner):
            with self.assertRaisesRegex(ValueError, "unexpected repeated dependency"):
                self.tool.stage_bundle(
                    self.bundle_path, self.capture_path, self.stage_root,
                    project_root=self.root, sysfs_module_root=self.root / "empty-sys-module",
                )


def _result(code, stdout, stderr):
    return type("Completed", (), {"returncode": code, "stdout": stdout, "stderr": stderr})()


if __name__ == "__main__":
    unittest.main()
