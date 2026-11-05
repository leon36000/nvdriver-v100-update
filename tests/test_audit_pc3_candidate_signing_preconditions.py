# SPDX-License-Identifier: MIT
"""Contracts for the read-only signed-canary prerequisite audit."""
from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_pc3_candidate_signing_preconditions.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_signing_preconditions", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("signing precondition audit tool is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_snapshot():
    return {
        "schema": "nvidia-hybrid-canary-host-state-v2",
        "host": "pc3",
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
        "secure_boot_enabled": True,
        "module_sig_enforce": True,
        "lockdown": "integrity",
        "local_module_signing_key_metadata": {
            "certificate_present": True,
            "certificate_enrolled": False,
            "mok_test_result": "not_enrolled",
        },
    }


def sample_remote():
    return {
        "schema": "pc3-candidate-signing-preconditions-remote-v2",
        "host": "pc3",
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
        "module_sig_enforce": True,
        "module_sig_enforce_raw": "Y",
        "lockdown": "integrity",
        "sign_file": {"available": True, "path": "/usr/src/linux-headers-7.0.0-38-generic/scripts/sign-file",
                      "sha256": "a" * 64, "executable": True},
        "mok_certificate": {"present": True,
                            "sha256": "27a69d9988202e45bf8d5d0ae48fb1d0047545c81c3cf90e19a9c55eac021ee3",
                            "mokutil_exit_code": 0, "enrollment_state": "not_enrolled",
                            "stdout_sha256": "c" * 64,
                            "stderr_sha256": "d" * 64},
        "mok_private_key_metadata": {"present": True, "regular": True, "symlink": False,
                                     "mode": 384, "uid": 0, "gid": 0, "size_bytes": 1704},
        "kernel_keyring_subject_scan": {"keyctl_available": False,
                                         "proc_keys_present": True,
                                         "proc_keys_readable": True,
                                         "entry_count": 567,
                                         "certificate_subject": "CN=pc3 Secure Boot Module Signature key",
                                         "matching_subject_entries": 0,
                                         "matching_entries_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                         "trust_verified": False},
        "private_key_contents_read": False,
        "network_or_system_state_changed": False,
    }


class SigningPreconditionsTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_remote_script_is_syntax_valid_and_only_inspects_signing_inputs(self):
        compile(self.tool.REMOTE_SIGNING_AUDIT_SCRIPT, "<pc3-signing-audit>", "exec")
        script = self.tool.REMOTE_SIGNING_AUDIT_SCRIPT
        for required in ("mokutil", "--test-key", "scripts/sign-file", "MOK.der",
                         "MOK.priv", "module_sig_enforce", "private_key_contents_read"):
            self.assertIn(required, script)
        self.assertIn('/sys/module/module/parameters/sig_enforce', script)
        self.assertNotIn('/proc/sys/kernel/module_sig_enforce', script)
        self.assertIn('/proc/keys', script)
        self.assertIn('openssl', script)
        self.assertIn('keyctl', script)
        self.assertLess(script.index('if re.search(r"not\\s+enrolled'),
                        script.index('elif mok_exit==0'))
        for forbidden in ("mokutil --import", "apt-get install", "dpkg -i",
                          "modprobe", "insmod", "rmmod", "reboot", "systemctl stop",
                          "sign-file sha"):
            self.assertNotIn(forbidden, script)

    def test_report_binds_readiness_to_the_captured_pc3_identity(self):
        result = self.tool.validate_remote_report(sample_remote(), sample_snapshot())
        self.assertEqual(result["status"], "signing-preconditions-observed")
        self.assertTrue(result["sign_file"]["available"])
        self.assertTrue(result["mok_private_key_metadata"]["present"])
        self.assertFalse(result["mok_certificate"]["enrolled"])
        self.assertFalse(result["signature_trust_verified"])
        self.assertFalse(result["canary_ready"])
        self.assertFalse(result["state_changes"]["driver_or_key_state_changed"])

    def test_kernel_keyring_scan_never_promotes_subject_match_to_trust_proof(self):
        result = self.tool.validate_kernel_keyring_scan(
            sample_remote()["kernel_keyring_subject_scan"])
        self.assertFalse(result["keyctl_available"])
        self.assertEqual(result["entry_count"], 567)
        self.assertEqual(result["matching_subject_entries"], 0)
        self.assertFalse(result["trust_verified"])
        for changed in ({"trust_verified": True}, {"matching_subject_entries": -1},
                        {"certificate_subject": ""}):
            scan = sample_remote()["kernel_keyring_subject_scan"] | changed
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.tool.validate_kernel_keyring_scan(scan)

    def test_rejects_host_kernel_driver_and_policy_drift(self):
        for field, value in (("host", "pc4"), ("kernel_release", "6.8.0-147-generic"),
                             ("loaded_nvidia_module_version", "580.178.04"),
                             ("module_sig_enforce", False)):
            remote = sample_remote()
            remote[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.tool.validate_remote_report(remote, sample_snapshot())

    def test_rejects_malformed_host_and_unexpected_sign_file_path(self):
        remote = sample_remote()
        remote["host"] = None
        with self.assertRaises(ValueError):
            self.tool.validate_remote_report(remote, sample_snapshot())
        remote = sample_remote()
        remote["sign_file"]["path"] = "/tmp/sign-file"
        with self.assertRaises(ValueError):
            self.tool.validate_remote_report(remote, sample_snapshot())
        remote = sample_remote()
        remote["mok_certificate"]["enrollment_state"] = "unknown"
        with self.assertRaises(ValueError):
            self.tool.validate_remote_report(remote, sample_snapshot())

    def test_candidate_module_name_must_match_the_pinned_preflight(self):
        module_names = {"open": "hybrid580_open", "legacy": "hybrid580_legacy",
                        "frontend": "nvidia", "uvm": "nvidia_uvm"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.ko"
            path.write_bytes(b"candidate-module-fixture")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            modules = {role: {"name": name, "path": str(path), "sha256": digest,
                              "signer": "", "sig_key": "", "sig_hashalgo": ""}
                       for role, name in module_names.items()}
            preflight = {"schema": self.tool.PREFLIGHT_SCHEMA, "host": "pc3",
                         "kernel_release": "7.0.0-38-generic", "canary_ready": False,
                         "candidate_modules": modules}

            def fake_modinfo(argv, **_kwargs):
                field = argv[2]
                values = {"name": "wrong_module", "signer": "", "sig_key": "",
                          "sig_hashalgo": "", "vermagic": "7.0.0-38-generic SMP"}
                return SimpleNamespace(returncode=0,
                                       stdout=(values[field] + "\n").encode(), stderr=b"")

            with patch.object(self.tool.subprocess, "run", side_effect=fake_modinfo):
                with self.assertRaisesRegex(ValueError, "module name differs"):
                    self.tool.validate_candidate_bundle(preflight, sample_snapshot())

    def test_rejects_inconsistent_key_metadata_or_state_change_claims(self):
        cases = []
        remote = sample_remote(); remote["mok_certificate"]["enrollment_state"] = "unknown"; cases.append(remote)
        remote = sample_remote(); remote["mok_private_key_metadata"]["symlink"] = True; cases.append(remote)
        remote = sample_remote(); remote["private_key_contents_read"] = True; cases.append(remote)
        remote = sample_remote(); remote["network_or_system_state_changed"] = True; cases.append(remote)
        for remote in cases:
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                self.tool.validate_remote_report(remote, sample_snapshot())

    def test_report_writer_is_private_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            path = evidence / "report.json"
            report = {"schema": self.tool.REPORT_SCHEMA}
            self.tool.write_report(path, report, evidence_root=evidence)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_report(path, report, evidence_root=evidence)
            with self.assertRaisesRegex(ValueError, "inside the evidence tree"):
                self.tool.write_report(root / "outside.json", report, evidence_root=evidence)


if __name__ == "__main__":
    unittest.main()
