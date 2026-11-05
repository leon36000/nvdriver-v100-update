# SPDX-License-Identifier: MIT
"""Contracts for the bounded read-only PC3 package-state query."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_pc3_package_dependency_state.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_package_dependency_state", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("package-state audit tool is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_snapshot():
    return {
        "schema": "nvidia-hybrid-canary-host-state-v2",
        "host": "pc3",
        "observed_at_utc": "2026-10-29T01:37:21.410664Z",
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
    }


def sample_remote():
    return {
        "schema": "pc3-package-manager-state-remote-v1",
        "host": "pc3",
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
        "packages": {
            "nvidia-driver-595-open": {"status": "ii ", "version": "595.99.02-0ubuntu0.26.04.1",
                                       "query_exit_code": 0, "stdout_sha256": "1" * 64,
                                       "stderr_sha256": "2" * 64},
            "xserver-xorg-video-nvidia-595": {"status": "un ", "version": "<none>",
                                              "query_exit_code": 1, "stdout_sha256": "3" * 64,
                                              "stderr_sha256": "4" * 64},
        },
        "dpkg_audit": {"exit_code": 0, "stdout_sha256": "a" * 64,
                        "stderr_sha256": "b" * 64, "stdout_nonempty": False},
        "apt_simulation": {"invoked": True, "exit_code": 0, "stdout_sha256": "c" * 64,
                            "stderr_sha256": "d" * 64,
                            "actions": [{"operation": "Inst",
                                         "package": "xserver-xorg-video-nvidia-595"}]},
        "apt_network_or_package_state_changed": False,
    }


class PC3PackageDependencyStateTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_remote_script_is_syntax_valid_and_apt_invocation_is_simulation_only(self):
        compile(self.tool.REMOTE_AUDIT_SCRIPT, "<pc3-package-audit>", "exec")
        script = self.tool.REMOTE_AUDIT_SCRIPT
        self.assertIn("--simulate", script)
        self.assertIn("--no-download", script)
        self.assertIn("Debug::NoLocking=1", script)
        for forbidden in ("dpkg --install", "dpkg -i", "apt-get update", "apt-get upgrade",
                          "apt-get dist-upgrade", "modprobe", "insmod", "rmmod",
                          "mokutil --import", "reboot", "systemctl stop"):
            self.assertNotIn(forbidden, script)

    def test_report_validator_binds_query_to_the_captured_pc3_identity(self):
        result = self.tool.validate_remote_report(sample_remote(), sample_snapshot())
        self.assertEqual(result["status"], "package-state-observed")
        self.assertEqual(result["host"], "pc3")
        self.assertEqual(result["kernel_release"], "7.0.0-38-generic")
        self.assertEqual(result["loaded_nvidia_module_version"], "595.99.02")
        self.assertEqual(result["apt_simulation"]["actions"], [
            {"operation": "Inst", "package": "xserver-xorg-video-nvidia-595"}])
        self.assertEqual(result["packages"]["xserver-xorg-video-nvidia-595"]["query_exit_code"], 1)
        self.assertFalse(result["state_changes"]["packages_installed"])
        self.assertFalse(result["state_changes"]["package_database_modified"])
        self.assertFalse(result["state_changes"]["apt_downloaded_packages"])

    def test_rejects_host_kernel_or_driver_drift(self):
        for field, value in (("host", "pc4"), ("kernel_release", "6.8.0-147-generic"),
                             ("loaded_nvidia_module_version", "580.178.04")):
            remote = sample_remote()
            remote[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.tool.validate_remote_report(remote, sample_snapshot())

    def test_rejects_unexpected_packages_actions_and_state_change_claims(self):
        cases = []
        remote = sample_remote(); remote["packages"]["unrelated"] = {"status": "ii ", "version": "1"}; cases.append(remote)
        remote = sample_remote(); remote["apt_simulation"]["actions"].append({"operation": "Remv", "package": "x"}); cases.append(remote)
        remote = sample_remote(); remote["apt_network_or_package_state_changed"] = True; cases.append(remote)
        remote = sample_remote(); remote["packages"]["nvidia-driver-595-open"]["query_exit_code"] = 1; cases.append(remote)
        remote = sample_remote(); del remote["packages"]["nvidia-driver-595-open"]["stdout_sha256"]; cases.append(remote)
        remote = sample_remote(); remote["apt_simulation"]["invoked"] = False; cases.append(remote)
        for remote in cases:
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                self.tool.validate_remote_report(remote, sample_snapshot())

    def test_snapshot_input_requires_exact_sha_and_supported_pc3_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "host.json"
            raw = json.dumps(sample_snapshot(), sort_keys=True).encode()
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(self.tool.load_host_snapshot(path, digest)["kernel_release"],
                             "7.0.0-38-generic")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.tool.load_host_snapshot(path, "0" * 64)
            invalid = sample_snapshot(); invalid["host"] = "pc2"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "PC3"):
                self.tool.load_host_snapshot(path, hashlib.sha256(path.read_bytes()).hexdigest())
            link = Path(directory) / "host-link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                self.tool.load_host_snapshot(link, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_report_writer_is_private_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            path = evidence / "audit.json"
            report = {"schema": self.tool.REPORT_SCHEMA, "status": "package-state-observed"}
            self.tool.write_report(path, report, evidence_root=evidence)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_report(path, report, evidence_root=evidence)
            with self.assertRaisesRegex(ValueError, "inside the evidence tree"):
                self.tool.write_report(root / "outside.json", report, evidence_root=evidence)


if __name__ == "__main__":
    unittest.main()
