from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_r595_uvm_candidate_preflight.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("r595_uvm_candidate_preflight", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("R595 UVM preflight tool is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_host():
    return {
        "schema": "nvidia-hybrid-canary-host-state-v2",
        "host": "pc3",
        "observed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
        "loaded_nvidia_modules": ["nvidia", "nvidia_uvm", "nvidia_modeset", "nvidia_drm"],
        "active_char_devices": [
            {"major": 511, "minor": 0, "path": "/dev/nvidia-uvm"},
            {"major": 511, "minor": 1, "path": "/dev/nvidia-uvm-tools"},
        ],
        "char_device_major_names": [{"major": 511, "name": "nvidia-uvm"}],
        "secure_boot_enabled": True,
        "module_sig_enforce": True,
        "lockdown": "integrity",
        "local_module_signing_key_metadata": {
            "certificate_present": True,
            "certificate_enrolled": False,
            "mok_test_result": "not_enrolled",
        },
        "gpu_ownership": [
            {"pci": "0000:02:00.0", "model": "RTX 5080", "driver": "nvidia"},
            {"pci": "0000:81:00.0", "model": "Tesla V100", "driver": "vfio-pci"},
        ],
        "driver_recovery_inventory": {
            "module_files_on_disk": [
                {"name": "nvidia_uvm", "sha256": "b" * 64,
                 "version": "595.99.02", "vermagic": "7.0.0-38-generic SMP"}
            ]
        },
    }


def sample_candidate():
    return {
        "path": "/tmp/candidate/nvidia-uvm.ko",
        "sha256": "a" * 64,
        "size_bytes": 62116984,
        "name": "nvidia_uvm",
        "version": "595.99.02",
        "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions",
        "depends": "nvidia",
        "signer": "",
        "sig_key": "",
        "sig_hashalgo": "",
    }


def sample_recovery(snapshot_sha256):
    return {
        "schema": "pc3-r595-recovery-archive-audit-v1",
        "status": "all-archives-match-signed-ubuntu-indexes",
        "archive_count": 20,
        "captured_snapshot_exact_version_matches": 20,
        "operational_recovery_proven": False,
        "host_snapshot": {
            "host": "pc3",
            "kernel_release": "7.0.0-38-generic",
            "loaded_nvidia_module_version": "595.99.02",
            "sha256": snapshot_sha256,
        },
    }


def sample_gpu_process_inventory(observed_at_utc=None):
    return {
        "schema": "pc3-gpu-process-inventory-v1",
        "observed_at_utc": observed_at_utc or (
            datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "proc_scan_complete": True,
        "proc_processes_scanned": 412,
        "proc_fd_entries_scanned": 3560,
        "proc_scan_incomplete_reasons": {},
        "device_fd_owners": [],
        "compute_query_complete": True,
        "compute_pids": [],
    }


class R595UvmCandidatePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()
        self.snapshot_sha256 = "c" * 64

    def test_live_pc3_candidate_is_blocked_for_each_observed_canary_conflict(self):
        report = self.tool.evaluate_preflight(
            sample_host(), self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        codes = {item["code"] for item in report["blockers"]}
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["canary_ready"])
        self.assertTrue({
            "active-uvm-module-conflict",
            "active-uvm-device-conflict",
            "unsigned-under-enforced-signature-policy",
            "mok-certificate-not-enrolled",
            "signature-trust-unverified",
            "operational-recovery-unproven",
            "gpu-process-state-not-captured",
            "host-gpu-owned-by-nvidia",
        }.issubset(codes))
        self.assertEqual(report["state_changes"], {
            "module_loaded": False, "module_installed": False,
            "module_signed": False, "pc3_contacted": False,
        })

    def test_rejects_module_built_for_another_kernel_or_driver(self):
        for changes in ({"vermagic": "6.8.0-147-generic SMP"},
                        {"version": "580.178.04"},
                        {"depends": "other_provider"},
                        {"name": "nvidia"}):
            candidate = sample_candidate() | changes
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.tool.evaluate_preflight(
                    sample_host(), self.snapshot_sha256, candidate,
                    sample_recovery(self.snapshot_sha256), "d" * 64,
                )

    def test_rejects_recovery_report_bound_to_a_different_host_snapshot(self):
        with self.assertRaisesRegex(ValueError, "host snapshot"):
            self.tool.evaluate_preflight(
                sample_host(), self.snapshot_sha256, sample_candidate(),
                sample_recovery("e" * 64), "d" * 64,
            )

    def test_rejects_malformed_host_identity_and_recovery_inventory(self):
        host = sample_host()
        host["host"] = None
        with self.assertRaisesRegex(ValueError, "PC3 inventory"):
            self.tool.evaluate_preflight(
                host, self.snapshot_sha256, sample_candidate(),
                sample_recovery(self.snapshot_sha256), "d" * 64,
            )

        host = sample_host()
        host["driver_recovery_inventory"] = None
        with self.assertRaisesRegex(ValueError, "recovery module inventory"):
            self.tool.evaluate_preflight(
                host, self.snapshot_sha256, sample_candidate(),
                sample_recovery(self.snapshot_sha256), "d" * 64,
            )

    def test_rejects_recovery_archive_identity_as_operational_rollback_proof(self):
        recovery = sample_recovery(self.snapshot_sha256)
        recovery["operational_recovery_proven"] = True
        with self.assertRaisesRegex(ValueError, "cannot promote"):
            self.tool.evaluate_preflight(
                sample_host(), self.snapshot_sha256, sample_candidate(), recovery, "d" * 64,
            )

    def test_archive_only_recovery_evidence_never_marks_candidate_canary_ready(self):
        host = sample_host()
        host["loaded_nvidia_modules"] = ["nvidia"]
        host["active_char_devices"] = []
        host["module_sig_enforce"] = False
        host["gpu_ownership"] = [{"pci": "0000:81:00.0", "driver": "vfio-pci"}]
        host["gpu_process_inventory"] = sample_gpu_process_inventory()
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["canary_ready"])
        self.assertEqual([row["code"] for row in report["blockers"]],
                         ["operational-recovery-unproven"])

    def test_complete_empty_gpu_process_inventory_clears_only_the_process_unknown(self):
        host = sample_host()
        host["gpu_process_inventory"] = sample_gpu_process_inventory()
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        codes = {row["code"] for row in report["blockers"]}
        self.assertNotIn("gpu-process-state-not-captured", codes)
        self.assertNotIn("gpu-process-inventory-incomplete", codes)
        self.assertNotIn("gpu-processes-active", codes)

    def test_incomplete_or_active_gpu_process_inventory_fails_closed(self):
        for inventory, expected in (
                (sample_gpu_process_inventory() | {"proc_scan_complete": False,
                 "proc_scan_incomplete_reasons": {"fd-stat-vanished": 1}},
                 "gpu-process-inventory-incomplete"),
                (sample_gpu_process_inventory() | {"compute_query_complete": False},
                 "gpu-process-inventory-incomplete"),
                (sample_gpu_process_inventory() | {"proc_scan_complete": False,
                 "proc_processes_scanned": 0,
                 "proc_scan_incomplete_reasons": {"no-processes-observed": 1}},
                 "gpu-process-inventory-incomplete"),
                (sample_gpu_process_inventory() | {"compute_pids": [4421]},
                 "gpu-processes-active"),
                (sample_gpu_process_inventory() | {"device_fd_owners": [
                    {"pid": 4421, "comm": "cuda-worker", "fd_count": 2,
                     "nodes": ["nvidia0", "nvidiactl"]}]}, "gpu-processes-active")):
            host = sample_host()
            host["gpu_process_inventory"] = inventory
            report = self.tool.evaluate_preflight(
                host, self.snapshot_sha256, sample_candidate(),
                sample_recovery(self.snapshot_sha256), "d" * 64,
            )
            with self.subTest(expected=expected, inventory=inventory):
                self.assertIn(expected, {row["code"] for row in report["blockers"]})

    def test_unknown_nvidia_minor_label_is_accepted_as_a_bounded_device_name(self):
        host = sample_host()
        host["gpu_process_inventory"] = sample_gpu_process_inventory() | {
            "device_fd_owners": [{
                "pid": 4421, "comm": "cuda-worker", "fd_count": 1,
                "nodes": ["nvidia-major-195-minor-77"],
            }],
        }
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        self.assertIn("gpu-processes-active", {row["code"] for row in report["blockers"]})

    def test_incomplete_process_scan_reason_is_visible_in_preflight(self):
        host = sample_host()
        host["gpu_process_inventory"] = sample_gpu_process_inventory() | {
            "proc_scan_complete": False,
            "proc_scan_incomplete_reasons": {"fd-stat-vanished": 1},
        }
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        blocker = next(row for row in report["blockers"]
                       if row["code"] == "gpu-process-inventory-incomplete")
        self.assertIn("fd-stat-vanished=1", blocker["detail"])

    def test_stale_process_inventory_is_reported_as_a_blocker(self):
        host = sample_host()
        stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        host["observed_at_utc"] = stale
        host["gpu_process_inventory"] = sample_gpu_process_inventory(stale)
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        self.assertIn("gpu-process-inventory-stale",
                      {row["code"] for row in report["blockers"]})

    def test_process_scan_must_predate_the_bound_host_snapshot(self):
        host = sample_host()
        future = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
        host["gpu_process_inventory"] = sample_gpu_process_inventory(future)
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        self.assertIn("gpu-process-inventory-stale",
                      {row["code"] for row in report["blockers"]})

    def test_malformed_gpu_process_inventory_timestamp_is_rejected(self):
        host = sample_host()
        host["gpu_process_inventory"] = sample_gpu_process_inventory() | {
            "observed_at_utc": "yesterday"
        }
        with self.assertRaisesRegex(ValueError, "process inventory"):
            self.tool.evaluate_preflight(
                host, self.snapshot_sha256, sample_candidate(),
                sample_recovery(self.snapshot_sha256), "d" * 64,
            )

    def test_gpu_process_inventory_owner_counts_and_node_lists_are_bounded(self):
        for owner in (
                {"pid": 4421, "comm": "worker", "fd_count": 250001, "nodes": ["nvidia0"]},
                {"pid": 4421, "comm": "worker", "fd_count": 65,
                 "nodes": sorted(f"nvidia{index}" for index in range(65))}):
            host = sample_host()
            host["gpu_process_inventory"] = sample_gpu_process_inventory() | {
                "device_fd_owners": [owner]
            }
            with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, "process inventory"):
                self.tool.evaluate_preflight(
                    host, self.snapshot_sha256, sample_candidate(),
                    sample_recovery(self.snapshot_sha256), "d" * 64,
                )

    def test_known_direct_nvidia_caps_imex_node_is_accepted(self):
        host = sample_host()
        host["gpu_process_inventory"] = sample_gpu_process_inventory() | {
            "device_fd_owners": [{"pid": 4421, "comm": "worker", "fd_count": 1,
                                  "nodes": ["nvidia-caps-imex-channels"]}]
        }
        report = self.tool.evaluate_preflight(
            host, self.snapshot_sha256, sample_candidate(),
            sample_recovery(self.snapshot_sha256), "d" * 64,
        )
        self.assertIn("gpu-processes-active", {row["code"] for row in report["blockers"]})

    def test_pinned_json_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text('{"host":"pc3"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.tool.load_pinned_json(path, "f" * 64)

    def test_candidate_inspection_hashes_exact_bytes_and_reads_module_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nvidia-uvm.ko"
            payload = b"bounded candidate fixture"
            path.write_bytes(payload)
            fields = {"name": "nvidia_uvm", "version": "595.99.02",
                      "vermagic": "7.0.0-38-generic SMP", "depends": "nvidia",
                      "signer": "", "sig_key": "", "sig_hashalgo": ""}

            def fake_modinfo(argv, **_kwargs):
                return SimpleNamespace(returncode=0,
                                       stdout=(fields[argv[2]] + "\n").encode(), stderr=b"")

            facts = self.tool.inspect_candidate(path, fake_modinfo)
            self.assertEqual(facts["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(facts["size_bytes"], len(payload))
            self.assertEqual(facts["name"], "nvidia_uvm")

    def test_candidate_inspection_rejects_symlink_even_when_target_is_regular(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.ko"
            target.write_bytes(b"candidate")
            link = root / "candidate.ko"
            link.symlink_to(target)
            fields = {"name": "nvidia_uvm", "version": "595.99.02",
                      "vermagic": "7.0.0-38-generic SMP", "depends": "nvidia",
                      "signer": "", "sig_key": "", "sig_hashalgo": ""}

            def fake_modinfo(argv, **_kwargs):
                return SimpleNamespace(returncode=0,
                                       stdout=(fields[argv[2]] + "\n").encode(), stderr=b"")

            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                self.tool.inspect_candidate(link, fake_modinfo)

    def test_candidate_metadata_is_read_from_the_hashed_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "nvidia-uvm.ko"
            backup = root / "candidate.saved"
            payload_a = b"candidate A"
            payload_b = b"candidate B"
            path.write_bytes(payload_a)
            calls = []
            fields_a = {"name": "nvidia_uvm", "version": "595.99.02",
                        "vermagic": "7.0.0-38-generic SMP", "depends": "nvidia",
                        "signer": "A", "sig_key": "key-A", "sig_hashalgo": "sha256"}
            fields_b = fields_a | {"signer": "B", "sig_key": "key-B"}

            def fake_modinfo(argv, **_kwargs):
                if not calls:
                    path.rename(backup)
                    path.write_bytes(payload_b)
                observed = Path(argv[3]).read_bytes()
                calls.append(observed)
                if backup.exists():
                    path.unlink()
                    backup.rename(path)
                fields = fields_a if observed == payload_a else fields_b
                return SimpleNamespace(returncode=0,
                                       stdout=(fields[argv[2]] + "\n").encode(), stderr=b"")

            facts = self.tool.inspect_candidate(path, fake_modinfo)
            self.assertEqual(facts["sha256"], hashlib.sha256(payload_a).hexdigest())
            self.assertEqual(facts["signer"], "A")
            self.assertEqual(facts["sig_key"], "key-A")
            self.assertEqual(set(calls), {payload_a})

    def test_report_writer_is_private_exclusive_and_evidence_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            path = evidence / "report.json"
            self.tool.write_report(path, {"schema": self.tool.REPORT_SCHEMA}, evidence)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_report(path, {"schema": self.tool.REPORT_SCHEMA}, evidence)
            with self.assertRaisesRegex(ValueError, "inside the evidence tree"):
                self.tool.write_report(root / "outside.json", {}, evidence)

    def test_report_writer_does_not_follow_parent_symlink_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            outside = root / "outside"
            outside.mkdir()
            output = evidence / "report.json"
            original_open = self.tool.os.open
            swapped = False

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if path == output.name and kwargs.get("dir_fd") is not None and not swapped:
                    evidence.rename(root / "evidence-held")
                    evidence.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(self.tool.os, "open", side_effect=swap_then_open):
                with self.assertRaisesRegex(ValueError, "changed during report creation"):
                    self.tool.write_report(output, {"schema": self.tool.REPORT_SCHEMA}, evidence)
            self.assertFalse((outside / "report.json").exists())
            self.assertFalse((root / "evidence-held" / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
