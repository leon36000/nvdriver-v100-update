# SPDX-License-Identifier: MIT
"""Contracts for the read-only PC3 VM/IOMMU assignment audit."""
from __future__ import annotations

import importlib.util
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/audit_pc3_vm_gpu_assignment.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_vm_gpu_assignment", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("PC3 VM assignment auditor is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_snapshot():
    return {
        "schema": "nvidia-hybrid-canary-host-state-v2",
        "host": "pc3",
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
        "gpu_ownership": [
            {"pci": "0000:02:00.0", "vendor_id": "10de", "device_id": "2c02",
             "class": "030000", "driver": "nvidia", "pci_topology":
             {"iommu_group": 13, "iommu_group_device_count": 2,
              "nvidia_gpu_bdfs_in_group": ["0000:02:00.0"]}},
            {"pci": "0000:81:00.0", "vendor_id": "10de", "device_id": "1db1",
             "class": "030200", "driver": "vfio-pci", "pci_topology":
             {"iommu_group": 23, "iommu_group_device_count": 1,
              "nvidia_gpu_bdfs_in_group": ["0000:81:00.0"]}},
        ],
    }


def sample_remote():
    return {
        "schema": "pc3-vm-gpu-recovery-control-remote-v4",
        "host": "pc3",
        "kernel_release": "7.0.0-38-generic",
        "loaded_nvidia_module_version": "595.99.02",
        "rtx5080_bdf": "0000:02:00.0",
        "rtx5080_iommu_group": {"group_id": 13, "members": [
            {"pci": "0000:02:00.0", "vendor_id": "0x10de", "device_id": "0x2c02",
             "class": "0x030000", "driver": "nvidia"},
            {"pci": "0000:02:00.1", "vendor_id": "0x10de", "device_id": "0x22e9",
             "class": "0x040300", "driver": "snd_hda_intel"},
        ]},
        "hypervisor": {"virsh_available": False, "qm_available": False,
                       "qemu_binary_available": True, "qemu_process_count": 1,
                       "instances": [{"hostdev_bdfs": ["0000:81:00.0"],
                                      "cmdline_sha256": "a" * 64,
                                      "recovery_channels": {
                                          "monitor_transports": [], "qmp_transports": [],
                                          "serial_transports": [],
                                          "monitor_unix_socket_fd_match": False,
                                          "qmp_unix_socket_fd_match": False,
                                          "open_pty_fd_count": 0, "fd_scan_complete": True,
                                          "systemd_managed": True, "no_reboot_flag": False,
                                          "systemd_owner": {"unit_name": "pc3-v100-qemu.service",
                                              "query_complete": True, "active_state": "active",
                                              "sub_state": "running", "restart_policy": "no",
                                              "restart_delay": "100ms", "kill_mode": "control-group"},
                                          "no_shutdown_flag": False}}]},
        "system_state_changed": False,
    }


def direct_snapshot_fixture(collector):
    pinned_path = collector.ROOT / "evidence" / (
        "pc3-canary-host-state-signing-preflight-v17-20261029T0155Z.json")
    snapshot = json.loads(pinned_path.read_text(encoding="utf-8"))
    metadata = snapshot["collector_metadata"]
    metadata.update({
        "schema": collector.COLLECTOR_SCHEMA,
        "local_collector_sha256": hashlib.sha256(
            Path(collector.__file__).read_bytes()).hexdigest(),
        "remote_script_sha256": hashlib.sha256(
            collector.REMOTE_HOST_STATE_SCRIPT.encode("utf-8")).hexdigest(),
        "transport": {"mode": collector.DIRECT_TRANSPORT_MODE,
                      "target": collector.DEFAULT_TARGET, "ssh_gateway_alias": None,
                      "host_key_alias": collector.DEFAULT_HOST_KEY_ALIAS,
                      "sudo_value_logged": False, "sudo_value_persisted": False},
    })
    return snapshot


class Pc3VmGpuAssignmentTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_direct_remote_collection_uses_only_pc3_key_and_sudo_n(self):
        transport = self.tool.transport
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(sample_remote()).encode(), stderr=b"")
        with (patch.object(transport, "pc3_direct_ssh_base",
                           return_value=["ssh", "--", "pc3@pc3"]) as direct,
              patch.object(transport, "pc3_ssh_base") as legacy,
              patch.object(transport, "fetch_pc3_sudo_secret") as fetch,
              patch.object(self.tool.subprocess, "run", return_value=completed) as remote):
            result = self.tool.collect_remote("0000:02:00.0")
        self.assertEqual(result, sample_remote())
        direct.assert_called_once_with("pc3@pc3", "pc3")
        legacy.assert_not_called()
        fetch.assert_not_called()
        argv = remote.call_args.args[0]
        self.assertEqual(argv[:3], ["ssh", "--", "pc3@pc3"])
        self.assertTrue(argv[-1].startswith("sudo -n python3 -c "))
        self.assertTrue(argv[-1].endswith(" 0000:02:00.0"))
        self.assertNotIn("gx10-e526", repr(argv))
        self.assertIs(remote.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_remote_script_is_bounded_read_only_and_does_not_emit_raw_arguments(self):
        compile(self.tool.REMOTE_AUDIT_SCRIPT, "<pc3-vm-assignment>", "exec")
        script = self.tool.REMOTE_AUDIT_SCRIPT
        self.assertIn("/sys/bus/pci/devices", script)
        self.assertIn("iommu_group", script)
        self.assertNotIn("/sys/kernel/iommu_groups/13", script)
        self.assertIn("/proc", script)
        self.assertIn("hostdev_bdfs", script)
        for forbidden in ("modprobe", "insmod", "rmmod", "virsh attach-device",
                          "qm set", "bind", "unbind", "os.reboot", "systemctl stop"):
            self.assertNotIn(forbidden, script)
        self.assertNotIn('"cmdline": raw', script)
        self.assertNotIn('"argv":', script)
        self.assertIn('"cmdline_sha256"', script)

    def test_remote_script_resolves_the_requested_live_iommu_group_dynamically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sysroot = root / "sys"
            procroot = root / "proc"
            group_id = "47"
            group = sysroot / "kernel/iommu_groups" / group_id
            group_devices = group / "devices"
            group_devices.mkdir(parents=True)
            drivers = sysroot / "bus/pci/drivers"
            for name in ("nvidia", "snd_hda_intel"):
                (drivers / name).mkdir(parents=True, exist_ok=True)
            devices_root = sysroot / "bus/pci/devices"
            device_records = (
                ("0000:04:00.0", "0x10de", "0x2c02", "0x030000", "nvidia"),
                ("0000:04:00.1", "0x10de", "0x22e9", "0x040300", "snd_hda_intel"),
            )
            for bdf, vendor, device, pci_class, driver in device_records:
                pci_device = devices_root / bdf
                pci_device.mkdir(parents=True)
                (pci_device / "vendor").write_text(vendor, encoding="ascii")
                (pci_device / "device").write_text(device, encoding="ascii")
                (pci_device / "class").write_text(pci_class, encoding="ascii")
                (pci_device / "driver").symlink_to(drivers / driver)
                (pci_device / "iommu_group").symlink_to(group)
                (group_devices / bdf).symlink_to(pci_device)
            module_version = sysroot / "module/nvidia/version"
            module_version.parent.mkdir(parents=True)
            module_version.write_text("595.99.02", encoding="ascii")
            qemu = procroot / "1234"
            (qemu / "fd").mkdir(parents=True)
            (qemu / "comm").write_text("qemu-system-x86_64", encoding="ascii")
            (qemu / "cmdline").write_bytes(
                b"qemu-system-x86_64\0-device\0vfio-pci,host=0000:81:00.0\0")
            (qemu / "cgroup").write_text("0::/", encoding="ascii")
            (procroot / "net").mkdir(parents=True)
            (procroot / "net/unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n",
                                                encoding="ascii")
            script = self.tool.REMOTE_AUDIT_SCRIPT
            for original, replacement in (
                ('Path("/sys/bus/pci/devices")', f'Path({json.dumps(str(devices_root))})'),
                ('Path("/sys/kernel/iommu_groups")',
                 f'Path({json.dumps(str(sysroot / "kernel/iommu_groups") )})'),
                ('Path("/sys/module/nvidia/version")',
                 f'Path({json.dumps(str(module_version))})'),
                ('Path("/proc/net/unix")', f'Path({json.dumps(str(procroot / "net/unix"))})'),
                ('Path("/proc")', f'Path({json.dumps(str(procroot))})'),
            ):
                self.assertIn(original, script)
                script = script.replace(original, replacement)
            completed = subprocess.run(
                [self.tool.sys.executable, "-c", script, "0000:04:00.0"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
            report = json.loads(completed.stdout.decode("utf-8", "strict"))
            self.assertEqual(report["rtx5080_bdf"], "0000:04:00.0")
            self.assertEqual(report["rtx5080_iommu_group"]["group_id"], 47)
            self.assertEqual([item["pci"] for item in report["rtx5080_iommu_group"]["members"]],
                             ["0000:04:00.0", "0000:04:00.1"])
            self.assertEqual(report["hypervisor"]["instances"][0]["hostdev_bdfs"],
                             ["0000:81:00.0"])

    def test_report_binds_host_group_to_existing_v100_only_qemu_assignment(self):
        result = self.tool.validate_remote_report(sample_remote(), sample_snapshot())
        self.assertEqual(result["status"], "vm-assignment-observed")
        self.assertEqual(result["rtx5080_iommu_group"]["members"][-1]["driver"],
                         "snd_hda_intel")
        self.assertEqual(result["hypervisor"]["qemu_process_count"], 1)
        self.assertEqual(result["hypervisor"]["instances"][0]["hostdev_bdfs"],
                         ["0000:81:00.0"])
        self.assertFalse(result["rtx5080_currently_assigned_to_vm"])
        self.assertTrue(result["vm_route_requires_rtx_and_audio_rebind"])
        self.assertFalse(result["candidate_tested"])
        self.assertFalse(result["host_control_channel_observed"])
        self.assertFalse(result["vm_reset_recovery_verified"])
        self.assertEqual(result["qemu_unit_recovery_policy_observed"], "no")
        self.assertFalse(result["state_changes"]["system_or_vm_state_changed"])

    def test_dynamic_rtx_bdf_group_and_vfio_gpu_addresses_are_honored(self):
        snapshot = sample_snapshot()
        snapshot["gpu_ownership"][0]["pci"] = "0000:04:00.0"
        snapshot["gpu_ownership"][0]["pci_topology"].update(
            iommu_group=7, nvidia_gpu_bdfs_in_group=["0000:04:00.0"])
        snapshot["gpu_ownership"][1]["pci"] = "0000:91:00.0"
        snapshot["gpu_ownership"][1]["pci_topology"]["nvidia_gpu_bdfs_in_group"] = [
            "0000:91:00.0"]
        remote = sample_remote()
        remote["rtx5080_bdf"] = "0000:04:00.0"
        remote["rtx5080_iommu_group"].update(group_id=7, members=[
            {"pci": "0000:04:00.0", "vendor_id": "0x10de", "device_id": "0x2c02",
             "class": "0x030000", "driver": "nvidia"},
            {"pci": "0000:04:00.1", "vendor_id": "0x10de", "device_id": "0x22e9",
             "class": "0x040300", "driver": "snd_hda_intel"},
        ])
        remote["hypervisor"]["instances"][0]["hostdev_bdfs"] = ["0000:91:00.0"]
        result = self.tool.validate_remote_report(remote, snapshot)
        self.assertEqual(result["rtx5080_bdf"], "0000:04:00.0")
        self.assertEqual(result["rtx5080_iommu_group"]["group_id"], 7)
        self.assertEqual(result["hypervisor"]["instances"][0]["hostdev_bdfs"],
                         ["0000:91:00.0"])

    def test_rejects_nvidia_iommu_member_not_present_in_fresh_gpu_inventory(self):
        remote = sample_remote()
        remote["rtx5080_iommu_group"]["members"][1].update({
            "vendor_id": "0x10de", "device_id": "0x2c02",
            "class": "0x030000", "driver": "nvidia"})
        with self.assertRaisesRegex(ValueError, "NVIDIA devices differ"):
            self.tool.validate_remote_report(remote, sample_snapshot())

    def test_current_snapshot_reader_requires_private_evidence_and_direct_provenance(self):
        collector = self.tool.host_state_collector
        snapshot = direct_snapshot_fixture(collector)
        with tempfile.TemporaryDirectory(dir=collector.ROOT / "evidence") as directory:
            path = Path(directory) / "host.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            path.chmod(0o600)
            value, digest, relative = self.tool._read_current_host_snapshot(path)
            self.assertEqual(value["host"], "pc3")
            self.assertEqual(len(digest), 64)
            self.assertEqual(relative, str(path.relative_to(collector.ROOT)))
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private regular file"):
                self.tool._read_current_host_snapshot(path)
            path.chmod(0o600)
            link = Path(directory) / "host-link.json"
            link.symlink_to(path.name)
            with self.assertRaises(OSError):
                self.tool._read_current_host_snapshot(link)
        with self.assertRaisesRegex(ValueError, "inside the private evidence tree"):
            self.tool._read_current_host_snapshot(Path(tempfile.gettempdir()) / "outside.json")

    def test_cli_writes_a_private_direct_v4_report_from_snapshot_bound_addresses(self):
        collector = self.tool.host_state_collector
        snapshot = direct_snapshot_fixture(collector)
        with tempfile.TemporaryDirectory(dir=collector.ROOT / "evidence") as directory:
            snapshot_path = Path(directory) / "host.json"
            snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
            snapshot_path.chmod(0o600)
            output_path = Path(directory) / "audit.json"
            with (patch.object(self.tool, "collect_remote", return_value=sample_remote()) as remote,
                  patch("sys.stdout", new_callable=io.StringIO)):
                result = self.tool.main([
                    "--direct-pc3", "--host-snapshot", str(snapshot_path),
                    "--output", str(output_path)])
            self.assertEqual(result, 0)
            remote.assert_called_once_with("0000:02:00.0")
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "pc3-vm-gpu-recovery-control-audit-v4")
            self.assertEqual(report["audit_provenance"]["transport"]["mode"],
                             "pc3-direct-key-sudo-n")
            self.assertEqual(report["inputs"]["host_snapshot"]["sha256"],
                             hashlib.sha256(snapshot_path.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)

    def test_cli_refuses_gateway_or_stale_snapshot_routes_before_remote_access(self):
        for args, expected in (
            (["--output", "evidence/never.json", "--host-snapshot", "evidence/snapshot.json"],
             "PC3-direct-only"),
            (["--output", "evidence/never.json", "--direct-pc3"], "fresh --host-snapshot"),
        ):
            with patch.object(self.tool, "collect_remote") as remote:
                with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    result = self.tool.main(args)
            self.assertEqual(result, 2)
            self.assertIn(expected, stderr.getvalue())
            remote.assert_not_called()

    def test_rejects_incomplete_iommu_group_and_changed_driver_ownership(self):
        for mutate in (
            lambda remote: remote["rtx5080_iommu_group"].update(members=remote["rtx5080_iommu_group"]["members"][:1]),
            lambda remote: remote["rtx5080_iommu_group"]["members"][0].update(driver="vfio-pci"),
            lambda remote: remote["hypervisor"]["instances"][0].update(hostdev_bdfs=["0000:02:00.0"]),
        ):
            remote = sample_remote()
            mutate(remote)
            with self.assertRaises(ValueError):
                self.tool.validate_remote_report(remote, sample_snapshot())

    def test_rejects_raw_command_line_fields_and_system_state_changes(self):
        remote = sample_remote()
        remote["hypervisor"]["instances"][0]["argv"] = ["secret"]
        with self.assertRaises(ValueError):
            self.tool.validate_remote_report(remote, sample_snapshot())
        remote = sample_remote()
        remote["system_state_changed"] = True
        with self.assertRaises(ValueError):
            self.tool.validate_remote_report(remote, sample_snapshot())

    def test_reports_detected_qmp_as_channel_evidence_without_claiming_recovery(self):
        remote = sample_remote()
        remote["hypervisor"]["instances"][0]["recovery_channels"].update(
            qmp_transports=["unix"], qmp_unix_socket_fd_match=True)
        result = self.tool.validate_remote_report(remote, sample_snapshot())
        self.assertTrue(result["host_control_channel_observed"])
        self.assertFalse(result["vm_reset_recovery_verified"])
        self.assertFalse(result["canary_ready"])

    def test_systemd_restart_policy_alone_never_proves_vm_reset_recovery(self):
        remote = sample_remote()
        channels = remote["hypervisor"]["instances"][0]["recovery_channels"]
        channels["systemd_owner"]["restart_policy"] = "on-failure"
        result = self.tool.validate_remote_report(remote, sample_snapshot())
        self.assertEqual(result["qemu_unit_recovery_policy_observed"], "on-failure")
        self.assertFalse(result["vm_reset_recovery_verified"])
        self.assertFalse(result["canary_ready"])

    def test_rejects_incomplete_qemu_fd_scan_and_unknown_transport(self):
        for update in (
            {"fd_scan_complete": False},
            {"qmp_transports": ["undocumented-control-channel"]},
            {"open_pty_fd_count": True},
        ):
            remote = sample_remote()
            remote["hypervisor"]["instances"][0]["recovery_channels"].update(update)
            with self.assertRaises(ValueError):
                self.tool.validate_remote_report(remote, sample_snapshot())

    def test_writer_is_exclusive_private_and_evidence_root_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            report_path = evidence / "report.json"
            self.tool.write_report(report_path, {"schema": self.tool.REPORT_SCHEMA}, evidence)
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_report(report_path, {}, evidence)
            with self.assertRaisesRegex(ValueError, "inside the evidence tree"):
                self.tool.write_report(root / "outside.json", {}, evidence)


if __name__ == "__main__":
    unittest.main()
