#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for the exact-target R595/Linux 6.8 private kmod stage."""

import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.verify_r595_linux68_hybrid_depmod import (  # noqa: E402
    stage_r595_linux68_hybrid_bundle,
)


KERNEL = "6.8.0-147-generic"
MODULES = {
    "open": ("hybrid580_open", "hybrid580_open.ko", ["ecc"]),
    "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko", []),
    "frontend": ("nvidia", "nvidia.ko", ["hybrid580_legacy", "hybrid580_open"]),
    "uvm": ("nvidia_uvm", "nvidia-uvm.ko", ["nvidia"]),
}
SUPPORT = {
    "ecc": ("kernel/crypto/ecc.ko.zst", []),
    "ecdh_generic": ("kernel/crypto/ecdh_generic.ko.zst", ["ecc"]),
    "ecdsa_generic": ("kernel/crypto/ecdsa_generic.ko.zst", ["ecc"]),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class R595Linux68DepmodTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.project = base / "project"
        self.project.mkdir()
        self.inputs = self.project / "input"
        self.inputs.mkdir()
        self.stage_parent = base / "private-stages"
        self.stage_parent.mkdir(mode=0o700)
        self.evidence = self.project / "evidence"
        self.evidence.mkdir()
        config_path = self.project / "packaging/modprobe.d/hybrid595-standard-uvm.conf"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            "# candidate-only\n"
            "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n",
            encoding="utf-8",
        )

        module_records = {}
        for role, (name, filename, depends) in MODULES.items():
            path = self.inputs / filename
            path.write_bytes(f"module-fixture:{role}".encode())
            module_records[role] = {
                "name": name,
                "version": {"open": "595.99.02", "legacy": "580.196.07",
                            "frontend": "", "uvm": "595.99.02"}[role],
                "depends": depends,
                "vermagic": f"{KERNEL} SMP preempt mod_unload modversions",
                "path": str(path),
                "sha256": digest(path),
            }
        self.audit = self.project / "audit.json"
        self.audit.write_text(json.dumps({
            "schema": "hybrid-module-bundle-static-audit-v1",
            "status": "passed",
            "qualification": "static-module-bundle-closure",
            "kernel_release": KERNEL,
            "modules": module_records,
            "issues": [],
            "module_loaded": False,
            "module_installed": False,
            "runtime_or_hardware_validated": False,
        }))
        self.audit_hash = digest(self.audit)

        capture_root = self.project / "capture"
        module_root = capture_root / "lib/modules" / KERNEL
        support_records = []
        for name, (guest_path, depends) in SUPPORT.items():
            path = module_root / guest_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"support-fixture:{name}".encode())
            support_records.append({
                "kind": "module", "name": name, "guest_path": guest_path,
                "path": path.relative_to(self.project).as_posix(),
                "bytes": path.stat().st_size, "sha256": digest(path), "depends": depends,
            })
        order = module_root / "modules.order"
        order.write_text("".join(f"{path.removesuffix('.zst')}\n" for path, _ in SUPPORT.values()))
        support_records.append({
            "kind": "metadata", "name": "modules.order", "guest_path": "modules.order",
            "path": order.relative_to(self.project).as_posix(),
            "bytes": order.stat().st_size, "sha256": digest(order),
        })
        for name in ("modules.builtin", "modules.builtin.modinfo"):
            path = module_root / name
            path.write_text("")
            support_records.append({
                "kind": "metadata", "name": name, "guest_path": name,
                "path": path.relative_to(self.project).as_posix(),
                "bytes": path.stat().st_size, "sha256": digest(path),
            })
        self.capture = self.project / "capture.json"
        self.capture.write_text(json.dumps({
            "schema": "pc3-v100-kernel-dependency-capture-v1",
            "status": "captured",
            "qualification": "read-only-exact-kernel-support-module-capture",
            "target": "pc3@pc3",
            "guest_hostname": "pc3-v100",
            "kernel_release": KERNEL,
            "guest_mutation_performed": False,
            "module_installed": False,
            "module_loaded": False,
            "runtime_or_hardware_validated": False,
            "files": support_records,
        }))
        self.capture_hash = digest(self.capture)

    def _runner(self, commands, *, bad_softdep=False, outside_stage=False,
                omit_uvm_option=False, wrong_uvm_option=False):
        def run(command, **kwargs):
            commands.append(command)
            if command[0] in ("depmod", "modprobe") and "--version" in command:
                return mock.Mock(returncode=0, stdout="kmod version 34.2\n", stderr="")
            if command[0] in ("depmod",):
                stage = Path(command[command.index("-b") + 1])
                base = stage / "lib/modules" / KERNEL
                (base / "modules.dep").write_text(
                    "kernel/crypto/ecc.ko.zst:\n"
                    "kernel/crypto/ecdh_generic.ko.zst: kernel/crypto/ecc.ko.zst\n"
                    "kernel/crypto/ecdsa_generic.ko.zst: kernel/crypto/ecc.ko.zst\n"
                    "updates/extra/hybrid580_open.ko: kernel/crypto/ecc.ko.zst\n"
                    "updates/extra/hybrid580_legacy.ko:\n"
                    "updates/extra/nvidia.ko: updates/extra/hybrid580_open.ko "
                    "updates/extra/hybrid580_legacy.ko kernel/crypto/ecc.ko.zst\n"
                    "updates/extra/nvidia-uvm.ko: updates/extra/nvidia.ko "
                    "updates/extra/hybrid580_open.ko updates/extra/hybrid580_legacy.ko "
                    "kernel/crypto/ecc.ko.zst\n"
                )
                softdep = "softdep hybrid580_open pre: ecdh_generic ecdsa_generic\n"
                if bad_softdep:
                    softdep = "softdep hybrid580_open pre: ecdh_generic,ecdsa_generic\n"
                (base / "modules.softdep").write_text(softdep)
                return mock.Mock(returncode=0, stdout="", stderr="")
            if command[-1] == "--version":
                return mock.Mock(returncode=0, stdout="kmod version 34.2\n", stderr="")
            target = command[-1]
            stage = Path(command[command.index("-d") + 1])
            module_root = stage / "lib/modules" / KERNEL
            ordered = [
                "kernel/crypto/ecc.ko.zst",
                "kernel/crypto/ecdh_generic.ko.zst",
                "kernel/crypto/ecdsa_generic.ko.zst",
                "updates/extra/hybrid580_open.ko",
                "updates/extra/hybrid580_legacy.ko",
                "updates/extra/nvidia.ko",
            ]
            if target == "nvidia_uvm":
                ordered.append("updates/extra/nvidia-uvm.ko")
            prefix = Path("/outside") if outside_stage else module_root
            rows = []
            for name in ordered:
                option = ""
                if target == "nvidia_uvm" and name.endswith("nvidia-uvm.ko"):
                    if wrong_uvm_option:
                        option = " uvm_hybrid_isolated_gpu_execution=0"
                    elif not omit_uvm_option:
                        option = " uvm_hybrid_isolated_gpu_execution=1"
                rows.append(f"insmod {prefix / name}{option}\n")
            output = "".join(rows)
            return mock.Mock(returncode=0, stdout=output, stderr="")
        return run

    def _run_stage(self, runner, report_path=None):
        return stage_r595_linux68_hybrid_bundle(
            audit_report=self.audit,
            expected_audit_sha256=self.audit_hash,
            support_capture=self.capture,
            expected_support_capture_sha256=self.capture_hash,
            kernel_release=KERNEL,
            stage_parent=self.stage_parent,
            report_path=report_path or self.evidence / "stage.json",
            project_root=self.project,
            command_runner=runner,
        )

    def test_stages_external_ecc_and_softdeps_and_reports_modprobe_order(self):
        commands = []
        report_path = self.evidence / "stage.json"
        report = self._run_stage(self._runner(commands), report_path)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["qualification"], "private-static-depmod-and-modprobe-plan")
        self.assertEqual(report["hard_dependency_graph"]["hybrid580_open"], ["ecc"])
        self.assertEqual(report["softdep_lines"], ["softdep hybrid580_open pre: ecdh_generic ecdsa_generic"])
        self.assertEqual(
            report["resolution"]["nvidia"]["first_occurrences"],
            ["ecc", "ecdh_generic", "ecdsa_generic", "hybrid580_open", "hybrid580_legacy", "nvidia"],
        )
        self.assertEqual(report["resolution"]["nvidia_uvm"]["first_occurrences"][-1], "nvidia_uvm")
        self.assertFalse(report["module_loaded"])
        self.assertFalse(report["module_installed"])
        self.assertFalse(report["runtime_or_hardware_validated"])
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
        stage_root = Path(report["stage_root"])
        self.assertTrue((stage_root / "lib/modules" / KERNEL / "modules.dep").is_file())
        staged_config = stage_root / "etc/modprobe.d/hybrid595-standard-uvm.conf"
        self.assertEqual(staged_config.read_text(),
                         "# candidate-only\n"
                         "options nvidia_uvm uvm_hybrid_isolated_gpu_execution=1\n")
        self.assertEqual(report["candidate_uvm_config"]["staged_sha256"], digest(staged_config))
        self.assertEqual(
            report["resolution"]["nvidia_uvm"]["command"][2], str(staged_config))
        stage_manifest_path = stage_root / "candidate-stage-manifest.json"
        stage_manifest = json.loads(stage_manifest_path.read_text())
        self.assertEqual(stage_manifest["schema"],
                         "nvidia-r595-linux68-hybrid-candidate-stage-v1")
        self.assertEqual(stage_manifest["implementation"]["sha256"],
                         report["implementation_sha256"])
        self.assertEqual(stage_manifest["staged_configuration"]["sha256"],
                         report["candidate_uvm_config"]["staged_sha256"])
        self.assertFalse(stage_manifest["activation_performed"])
        self.assertFalse(stage_manifest["runtime_or_hardware_validated"])
        self.assertEqual(stat.S_IMODE(stage_manifest_path.stat().st_mode), 0o600)
        self.assertEqual(
            [command[-1] for command in commands if command[0] == "modprobe" and "--show-depends" in command],
            ["nvidia", "nvidia_uvm"],
        )

    def test_persists_complete_private_stage_under_project_build_staging(self):
        commands = []
        (self.project / "build").mkdir()
        report = stage_r595_linux68_hybrid_bundle(
            audit_report=self.audit,
            expected_audit_sha256=self.audit_hash,
            support_capture=self.capture,
            expected_support_capture_sha256=self.capture_hash,
            kernel_release=KERNEL,
            stage_parent=self.project / "build/staging",
            report_path=self.evidence / "persistent-stage.json",
            project_root=self.project,
            command_runner=self._runner(commands),
        )
        self.assertTrue(Path(report["stage_root"]).is_relative_to(self.project / "build/staging"))
        self.assertEqual(report["candidate_stage_manifest"]["path"],
                         "candidate-stage-manifest.json")
        self.assertTrue((Path(report["stage_root"]) / "candidate-stage-manifest.json").is_file())

    def test_isolation_option_is_required_and_cannot_be_changed_in_dry_run(self):
        for kwargs in ({"omit_uvm_option": True}, {"wrong_uvm_option": True}):
            with self.subTest(kwargs=kwargs):
                commands = []
                with self.assertRaisesRegex(ValueError, "unexpected options"):
                    self._run_stage(self._runner(commands, **kwargs))
                self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_audit_hash_mismatch_fails_before_stage_or_commands(self):
        commands = []
        with self.assertRaisesRegex(ValueError, "audit report SHA-256 mismatch"):
            stage_r595_linux68_hybrid_bundle(
                audit_report=self.audit, expected_audit_sha256="0" * 64,
                support_capture=self.capture, expected_support_capture_sha256=self.capture_hash,
                kernel_release=KERNEL, stage_parent=self.stage_parent,
                report_path=self.evidence / "bad.json", project_root=self.project,
                command_runner=self._runner(commands),
            )
        self.assertEqual(commands, [])
        self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_capture_hash_mismatch_fails_before_stage_or_commands(self):
        commands = []
        with self.assertRaisesRegex(ValueError, "support capture SHA-256 mismatch"):
            stage_r595_linux68_hybrid_bundle(
                audit_report=self.audit, expected_audit_sha256=self.audit_hash,
                support_capture=self.capture, expected_support_capture_sha256="f" * 64,
                kernel_release=KERNEL, stage_parent=self.stage_parent,
                report_path=self.evidence / "bad.json", project_root=self.project,
                command_runner=self._runner(commands),
            )
        self.assertEqual(commands, [])
        self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_comma_softdep_is_rejected_and_failed_stage_is_removed(self):
        commands = []
        with self.assertRaisesRegex(ValueError, "soft dependency"):
            self._run_stage(self._runner(commands, bad_softdep=True))
        self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_modprobe_path_outside_stage_is_rejected(self):
        commands = []
        with self.assertRaisesRegex(ValueError, "outside the private stage"):
            self._run_stage(self._runner(commands, outside_stage=True))
        self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_open_ecc_dependency_is_required_by_audit_contract(self):
        audit = json.loads(self.audit.read_text())
        audit["modules"]["open"]["depends"] = []
        self.audit.write_text(json.dumps(audit))
        self.audit_hash = digest(self.audit)
        commands = []
        with self.assertRaisesRegex(ValueError, "dependencies differ for open"):
            self._run_stage(self._runner(commands))
        self.assertEqual(commands, [])
        self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_wrong_provider_version_fails_before_commands(self):
        audit = json.loads(self.audit.read_text())
        audit["modules"]["open"]["version"] = "595.112.07"
        self.audit.write_text(json.dumps(audit))
        self.audit_hash = digest(self.audit)
        commands = []
        with self.assertRaisesRegex(ValueError, "module version differs for open"):
            self._run_stage(self._runner(commands))
        self.assertEqual(commands, [])
        self.assertEqual(list(self.stage_parent.iterdir()), [])

    def test_symlinked_evidence_root_is_rejected_before_commands(self):
        real_evidence = self.project / "evidence-real"
        self.evidence.rename(real_evidence)
        self.evidence.symlink_to(real_evidence, target_is_directory=True)
        commands = []
        with self.assertRaisesRegex(ValueError, "evidence directory must not be a symlink"):
            self._run_stage(self._runner(commands))
        self.assertEqual(commands, [])
        self.assertEqual(list(self.stage_parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
