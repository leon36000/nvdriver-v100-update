"""Contracts for the read-only PC3 canary host-state collector."""
from __future__ import annotations

import importlib.util
import ast
from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/collect_pc3_canary_host_state.py"


def load_module():
    if not MODULE_PATH.is_file():
        raise AssertionError("read-only PC3 host-state collector is missing")
    spec = importlib.util.spec_from_file_location("collect_pc3_canary_host_state", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot import PC3 host-state collector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_state():
    return {
        "schema": "nvidia-hybrid-canary-host-state-v2",
        "host": "pc3",
        "observed_at_utc": "2026-10-24T00:00:00Z",
        "boot_id": "9fc973f8-6a29-4d2c-b3fd-58ac27ef20b1",
        "kernel_release": "7.0.0-38-generic",
        "kernel_vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions",
        "secure_boot_enabled": True,
        "module_sig_enforce": True,
        "lockdown": "integrity",
        "active_char_devices": [{"path": "/dev/nvidia0", "major": 195, "minor": 0}],
        "active_modules_scope": "all",
        "active_modules": [
            {"name": "drm"},
            {"name": "hybrid580_open"},
            {"name": "nvidia", "version": "595.99.02", "signer": "Canonical Ltd."},
            {"name": "nvidia_uvm"},
        ],
        "loaded_nvidia_modules": ["nvidia", "nvidia_uvm"],
        "char_device_major_names": [
            {"major": 195, "name": "nvidia"},
            {"major": 5, "name": "/dev/tty"},
            {"major": 5, "name": "/dev/console"},
            {"major": 202, "name": "cpu/msr"},
        ],
        "gpu_ownership": [{"pci": "0000:02:00.0", "vendor_id": "10de", "device_id": "2c02", "driver": "nvidia"}],
        "installed_nvidia_module": {"version": "595.99.02", "signer": "Canonical Ltd.",
                                     "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions"},
        "loaded_nvidia_module_version": "595.99.02",
        "local_module_signing_key_metadata": {
            "certificate_present": True,
            "certificate_enrolled": False,
            "mok_test_result": "not_enrolled",
        },
        "gpu_process_inventory": {
            "schema": "pc3-gpu-process-inventory-v1",
            "observed_at_utc": "2026-10-24T00:00:00Z",
            "proc_scan_complete": True,
            "proc_processes_scanned": 412,
            "proc_fd_entries_scanned": 3560,
            "proc_scan_incomplete_reasons": {},
            "device_fd_owners": [],
            "compute_query_complete": True,
            "compute_pids": [],
        },
        "driver_recovery_inventory": {
            "schema": "pc3-driver-recovery-inventory-v1",
            "package_query_complete": True,
            "packages": [
                {"name": "linux-image-7.0.0-38-generic", "version": "7.0.0-38.38",
                 "status": "ii"},
                {"name": "nvidia-driver-595", "version": "595.99.02-0ubuntu1",
                 "status": "ii"},
                {"name": "xserver-xorg-video-nvidia-595", "version": "595.99.02-0ubuntu1",
                 "status": "ii"},
            ],
            "module_file_hash_scope": "installed_file_on_disk_not_loaded_memory",
            "module_files_on_disk": [
                {"name": "nvidia", "path": "/lib/modules/7.0.0-38-generic/updates/dkms/nvidia.ko.zst",
                 "exists": True, "size_bytes": 1000, "sha256": "a" * 64,
                 "version": "595.99.02", "signer": "Canonical Ltd.",
                 "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions"},
                {"name": "nvidia_uvm", "path": "/lib/modules/7.0.0-38-generic/updates/dkms/nvidia-uvm.ko.zst",
                 "exists": True, "size_bytes": 2000, "sha256": "b" * 64,
                 "version": "595.99.02", "signer": "Canonical Ltd.",
                 "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions"},
            ],
            "nvidia_module_by_kernel": [
                {"kernel_release": "7.0.0-34-generic", "module_present": False,
                 "path": None, "size_bytes": None, "sha256": None,
                 "version": None, "signer": None, "vermagic": None},
                {"kernel_release": "7.0.0-38-generic", "module_present": True,
                 "path": "/lib/modules/7.0.0-38-generic/kernel/nvidia-595-open/nvidia.ko",
                 "size_bytes": 1000, "sha256": "c" * 64, "version": "595.99.02",
                 "signer": "Canonical Ltd.",
                 "vermagic": "7.0.0-38-generic SMP preempt mod_unload modversions"},
            ],
            "boot_artifacts": [
                {"name": "initrd.img-7.0.0-34-generic", "path": "/boot/initrd.img-7.0.0-34-generic",
                 "kind": "initramfs", "exists": True, "size_bytes": 94000000},
                {"name": "initrd.img-7.0.0-38-generic", "path": "/boot/initrd.img-7.0.0-38-generic",
                 "kind": "initramfs", "exists": True, "size_bytes": 95000000},
                {"name": "initrd.img.old", "path": "/boot/initrd.img.old",
                 "kind": "initramfs", "exists": True, "size_bytes": 94000000},
                {"name": "vmlinuz-7.0.0-34-generic", "path": "/boot/vmlinuz-7.0.0-34-generic",
                 "kind": "kernel", "exists": True, "size_bytes": 11900000},
                {"name": "vmlinuz-7.0.0-38-generic", "path": "/boot/vmlinuz-7.0.0-38-generic",
                 "kind": "kernel", "exists": True, "size_bytes": 12000000},
                {"name": "vmlinuz.old", "path": "/boot/vmlinuz.old",
                 "kind": "kernel", "exists": True, "size_bytes": 11900000},
            ],
            "grub_environment": {"available": True, "saved_entry": "Ubuntu",
                                 "next_entry": None},
        },
    }


class HostStateSchemaTests(unittest.TestCase):
    def test_accepts_complete_read_only_snapshot(self):
        module = load_module()
        state = sample_state()
        self.assertEqual(module.validate_host_state(state), state)

    def test_fails_closed_when_security_policy_is_unknown(self):
        module = load_module()
        for key, value in (("secure_boot_enabled", None), ("module_sig_enforce", "Y"),
                           ("lockdown", "unknown")):
            state = sample_state()
            state[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.validate_host_state(state)

    def test_rejects_inconsistent_public_mok_enrollment_metadata(self):
        module = load_module()
        invalid = (
            (True, "not_enrolled"),
            (False, "enrolled"),
            (None, "enrolled"),
            (None, "not_enrolled"),
        )
        for enrolled, result in invalid:
            state = sample_state()
            state["local_module_signing_key_metadata"]["certificate_enrolled"] = enrolled
            state["local_module_signing_key_metadata"]["mok_test_result"] = result
            with self.subTest(enrolled=enrolled, result=result), self.assertRaisesRegex(
                    ValueError, "MOK"):
                module.validate_host_state(state)

    def test_absent_public_mok_certificate_must_have_unknown_enrollment(self):
        module = load_module()
        state = sample_state()
        state["local_module_signing_key_metadata"].update({
            "certificate_present": False,
            "certificate_enrolled": False,
            "mok_test_result": "not_enrolled",
        })
        with self.assertRaisesRegex(ValueError, "MOK"):
            module.validate_host_state(state)

    def test_rejects_snapshots_containing_credentials_or_private_key_material(self):
        module = load_module()
        for key in ("password", "sudo_credential", "private_key_contents", "mok_private_key_pem"):
            state = sample_state()
            state[key] = "must-not-be-recorded"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "sensitive"):
                module.validate_host_state(state)

    def test_rejects_duplicate_json_fields(self):
        module = load_module()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            module.parse_remote_json(b'{"schema":"x","schema":"y"}')

    def test_remote_probe_is_syntactically_valid_and_has_no_mutating_commands(self):
        module = load_module()
        compile(module.REMOTE_HOST_STATE_SCRIPT, "<pc3-host-state-collector>", "exec")
        self.assertIn("--test-key", module.REMOTE_HOST_STATE_SCRIPT)
        for forbidden in ("modprobe", "insmod", "rmmod", "mokutil --import", "sign-file",
                          "update-initramfs", "apt-get", "dpkg", "reboot", "systemctl stop"):
            self.assertIsNone(re.search(r"(?<![A-Za-z0-9_-])" + re.escape(forbidden) +
                                        r"(?![A-Za-z0-9_-])", module.REMOTE_HOST_STATE_SCRIPT))

    def test_remote_probe_records_every_loaded_module_before_nvidia_subset(self):
        module = load_module()
        expected = (
            'for line in read_text("/proc/modules").splitlines():\n'
            '    fields = line.split()\n'
            '    if fields:\n'
            '        active_modules.append({"name": fields[0]})\n'
            '        if fields[0].startswith("nvidia"):\n'
            '            loaded_modules.append(fields[0])'
        )
        self.assertIn(expected, module.REMOTE_HOST_STATE_SCRIPT)
        self.assertIn('"active_modules_scope": "all"', module.REMOTE_HOST_STATE_SCRIPT)
        self.assertIn('boot_id = read_text("/proc/sys/kernel/random/boot_id")',
                      module.REMOTE_HOST_STATE_SCRIPT)
        self.assertIn('"boot_id": boot_id', module.REMOTE_HOST_STATE_SCRIPT)

    def test_remote_probe_collects_pci_ancestry_link_and_iommu_group(self):
        module = load_module()
        for token in ("pci_ancestors", "current_link_speed", "current_link_width",
                      "max_link_speed", "max_link_width", "iommu_group_device_count",
                      "nvidia_gpu_bdfs_in_group", '"-vv", "-s"', "ACS(?:Cap|Ctl):"):
            self.assertIn(token, module.REMOTE_HOST_STATE_SCRIPT)

    def test_gpu_process_inventory_is_validated_and_fail_closed(self):
        module = load_module()
        state = sample_state()
        self.assertEqual(module.validate_host_state(state), state)
        for bad_inventory in (
                {"schema": "pc3-gpu-process-inventory-v1", "proc_scan_complete": "yes"},
                sample_state()["gpu_process_inventory"] | {"compute_pids": [0]},
                sample_state()["gpu_process_inventory"] | {"proc_processes_scanned": 0},
                sample_state()["gpu_process_inventory"] | {
                    "proc_scan_complete": False,
                    "proc_scan_incomplete_reasons": {"unknown-reason": 1}},
                sample_state()["gpu_process_inventory"] | {"proc_fd_entries_scanned": 250001},
                sample_state()["gpu_process_inventory"] | {"device_fd_owners": [
                    {"pid": 7, "comm": "worker", "fd_count": 1,
                     "nodes": ["../../etc/passwd"]}]},
                sample_state()["gpu_process_inventory"] | {"device_fd_owners": [
                    {"pid": 7, "comm": "worker", "fd_count": 0,
                     "nodes": ["nvidia0"]}]},
                sample_state()["gpu_process_inventory"] | {"device_fd_owners": [
                    {"pid": 7, "comm": "worker", "fd_count": 65,
                     "nodes": sorted(f"nvidia{index}" for index in range(65))}]},
        ):
            bad_state = sample_state()
            bad_state["gpu_process_inventory"] = bad_inventory
            with self.subTest(inventory=bad_inventory), self.assertRaisesRegex(
                ValueError, "GPU process inventory"):
                module.validate_host_state(bad_state)

    def test_proc_scan_incomplete_reason_is_retained_as_bounded_evidence(self):
        module = load_module()
        state = sample_state()
        state["gpu_process_inventory"].update({
            "proc_scan_complete": False,
            "proc_scan_incomplete_reasons": {"fd-stat-vanished": 3},
        })
        self.assertEqual(module.validate_host_state(state), state)

    def test_direct_nvidia_caps_imex_node_is_validated(self):
        module = load_module()
        state = sample_state()
        state["gpu_process_inventory"]["device_fd_owners"] = [{
            "pid": 7, "comm": "worker", "fd_count": 1,
            "nodes": ["nvidia-caps-imex-channels"],
        }]
        self.assertEqual(module.validate_host_state(state), state)

    def test_unknown_nvidia_minor_label_is_validated(self):
        module = load_module()
        tree = ast.parse(module.REMOTE_HOST_STATE_SCRIPT)
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "gpu_node_label")
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<remote-helper>", "exec"),
             namespace)
        label = namespace["gpu_node_label"](195, 77, {})
        self.assertEqual(label, "nvidia-major-195-minor-77")
        state = sample_state()
        state["gpu_process_inventory"]["device_fd_owners"] = [{
            "pid": 7, "comm": "worker", "fd_count": 1,
            "nodes": [label],
        }]
        self.assertEqual(module.validate_host_state(state), state)

    def test_gpu_device_node_limit_does_not_insert_the_overflow_node(self):
        module = load_module()
        tree = ast.parse(module.REMOTE_HOST_STATE_SCRIPT)
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "add_gpu_device_node")
        namespace = {"MAX_GPU_DEVICE_NODES_PER_OWNER": 64}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<remote-helper>", "exec"),
             namespace)
        nodes = {f"nvidia{index}": 1 for index in range(64)}
        reasons = {}

        def incomplete(reason):
            reasons[reason] = reasons.get(reason, 0) + 1

        self.assertFalse(namespace["add_gpu_device_node"](nodes, "nvidia64", incomplete))
        self.assertEqual(len(nodes), 64)
        self.assertNotIn("nvidia64", nodes)
        self.assertEqual(reasons, {"gpu-device-node-limit": 1})

    def test_generic_remote_command_output_has_an_aggregate_byte_cap(self):
        module = load_module()
        tree = ast.parse(module.REMOTE_HOST_STATE_SCRIPT)
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "run")
        namespace = {"subprocess": subprocess, "os": os, "time": time,
                     "selectors": selectors, "MAX_COMMAND_OUTPUT_BYTES": 128}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<remote-helper>", "exec"),
             namespace)
        script = "import sys; sys.stdout.write('x' * 80); sys.stderr.write('y' * 80)"
        with self.assertRaisesRegex(RuntimeError, "output exceeded limit"):
            namespace["run"](["python3", "-c", script], max_bytes=128)

    def test_remote_probe_scans_device_fds_and_nvidia_smi_compute_pids_read_only(self):
        module = load_module()
        for token in ("gpu_process_inventory", "/proc", "/dev/", "uvm(?:-tools)?",
                      "nvidia-smi", "--query-compute-apps=pid", "proc_scan_complete",
                      "compute_query_complete", "device_fd_owners", "st_rdev",
                      "char_device_major_names", "MAX_TOTAL_FD_ENTRIES",
                      "MAX_QUERY_OUTPUT_BYTES", "errno.ENOENT",
                      "fd-stat-vanished", "fd-stat-permission", "fd-stat-other"):
            self.assertIn(token, module.REMOTE_HOST_STATE_SCRIPT)

    def test_optional_pci_topology_is_validated_and_legacy_snapshot_still_passes(self):
        module = load_module()
        legacy = sample_state()
        legacy.pop("driver_recovery_inventory")
        self.assertEqual(module.validate_host_state(legacy), legacy)

        state = sample_state()
        state["gpu_ownership"][0]["pci_topology"] = {
            "pci_ancestors": [
                {"pci": "0000:00:01.0", "vendor_id": "8086",
                 "device_id": "7a34", "class": "060400", "driver": "pcieport",
                 "acs": ["ACSCap: SrcValid+ ReqRedir+", "ACSCtl: SrcValid+ ReqRedir+"]},
            ],
            "link": {"current_link_speed": "16.0 GT/s PCIe",
                     "current_link_width": "x16", "max_link_speed": "16.0 GT/s PCIe",
                     "max_link_width": "x16"},
            "iommu_group": 17,
            "iommu_group_device_count": 2,
            "nvidia_gpu_bdfs_in_group": ["0000:02:00.0"],
        }
        self.assertEqual(module.validate_host_state(state), state)

        state["gpu_ownership"][0]["pci_topology"]["iommu_group"] = "17"
        with self.assertRaisesRegex(ValueError, "PCI topology"):
            module.validate_host_state(state)

    def test_driver_recovery_inventory_validates_packages_modules_and_boot_artifacts(self):
        module = load_module()
        state = sample_state()
        self.assertEqual(module.validate_host_state(state), state)

        invalid_cases = (
            ("package_query_complete", False),
            ("module_file_hash_scope", "loaded_module_memory"),
        )
        for field, value in invalid_cases:
            invalid = sample_state()
            invalid["driver_recovery_inventory"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "recovery inventory"):
                module.validate_host_state(invalid)

        invalid = sample_state()
        invalid["driver_recovery_inventory"]["module_files_on_disk"][0]["sha256"] = "xyz"
        with self.assertRaisesRegex(ValueError, "recovery inventory"):
            module.validate_host_state(invalid)

        invalid = sample_state()
        invalid["driver_recovery_inventory"]["module_files_on_disk"].pop()
        with self.assertRaisesRegex(ValueError, "recovery inventory"):
            module.validate_host_state(invalid)

        invalid = sample_state()
        invalid["driver_recovery_inventory"]["nvidia_module_by_kernel"][1]["sha256"] = "bad"
        with self.assertRaisesRegex(ValueError, "recovery inventory"):
            module.validate_host_state(invalid)

        invalid = sample_state()
        invalid["driver_recovery_inventory"]["packages"].append(
            {"name": "unrelated-package", "version": "1", "status": "ii"})
        with self.assertRaisesRegex(ValueError, "recovery inventory"):
            module.validate_host_state(invalid)

    def test_remote_probe_collects_read_only_driver_recovery_facts(self):
        module = load_module()
        compile(module.REMOTE_HOST_STATE_SCRIPT, "<pc3-host-state-collector>", "exec")
        for token in ("dpkg-query", "module_files_on_disk", "nvidia_module_by_kernel",
                      "boot_artifacts", "grub-editenv", "module_file_hash_scope", "/boot",
                      "xserver-xorg-video-nvidia-"):
            self.assertIn(token, module.REMOTE_HOST_STATE_SCRIPT)
        for forbidden in ("apt-get", "dpkg -i", "dpkg --install", "modprobe", "insmod",
                          "rmmod", "mokutil --import", "sign-file", "update-initramfs",
                          "reboot", "systemctl stop"):
            self.assertIsNone(re.search(r"(?<![A-Za-z0-9_-])" + re.escape(forbidden) +
                                        r"(?![A-Za-z0-9_-])", module.REMOTE_HOST_STATE_SCRIPT))

    def test_active_module_inventory_requires_all_scope_and_exact_nvidia_subset(self):
        module = load_module()
        state = sample_state()
        self.assertEqual(module.validate_host_state(state), state)

        state["loaded_nvidia_modules"].remove("nvidia_uvm")
        with self.assertRaisesRegex(ValueError, "loaded NVIDIA module inventory differs"):
            module.validate_host_state(state)

        state = sample_state()
        state["active_modules_scope"] = "nvidia-only"
        with self.assertRaisesRegex(ValueError, "complete active-module inventory"):
            module.validate_host_state(state)

    def test_active_module_names_reject_malformed_kernel_names(self):
        module = load_module()
        for malformed in ("hybrid580_open\n", "nvidia/uvm", "nvidia\0uvm", "nvidia."):
            state = sample_state()
            state["active_modules"].append({"name": malformed})
            with self.subTest(name=malformed), self.assertRaisesRegex(
                    ValueError, "active module record"):
                module.validate_host_state(state)

    def test_character_major_inventory_accepts_proc_devices_path_labels(self):
        module = load_module()
        state = sample_state()
        self.assertEqual(module.validate_host_state(state), state)

    def test_collector_report_round_trips_through_report_validator(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", "gx10-e526")
        self.assertEqual(module.validate_collection_report(report), report)
        self.assertEqual(report["collector_metadata"]["transport"]["ssh_gateway_alias"],
                         "gx10-e526")
        self.assertNotIn("credential_host", json.dumps(report))

        legacy_state = sample_state()
        legacy_state.pop("driver_recovery_inventory")
        legacy_report = module.make_report(legacy_state, "pc3@pc3", "gx10-e526")
        self.assertEqual(module.validate_collection_report(legacy_report), legacy_report)

    def test_direct_report_proves_pc3_only_key_and_noninteractive_sudo_route(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", None, "pc3",
                                    transport_mode=module.DIRECT_TRANSPORT_MODE)
        self.assertEqual(module.validate_collection_report(report), report)
        transport = report["collector_metadata"]["transport"]
        self.assertEqual(transport["mode"], "pc3-ssh-key-sudo-n")
        self.assertIsNone(transport["ssh_gateway_alias"])
        self.assertEqual(transport["target"], "pc3@pc3")

    def test_direct_report_rejects_any_non_pc3_route_or_credential_gateway(self):
        module = load_module()
        with self.assertRaisesRegex(ValueError, "pinned PC3 SSH route"):
            module.make_report(sample_state(), "pc1@pc1", None, "pc3",
                               transport_mode=module.DIRECT_TRANSPORT_MODE)
        with self.assertRaisesRegex(ValueError, "pinned PC3 SSH route"):
            module.make_report(sample_state(), "pc3@pc3", "gx10-e526", "pc3",
                               transport_mode=module.DIRECT_TRANSPORT_MODE)
        report = module.make_report(sample_state(), "pc3@pc3", None, "pc3",
                                    transport_mode=module.DIRECT_TRANSPORT_MODE)
        report["collector_metadata"]["transport"]["ssh_gateway_alias"] = "gx10-e526"
        with self.assertRaisesRegex(ValueError, "transport provenance"):
            module.validate_collection_report(report)

    def test_report_validator_rejects_tampered_provenance_and_wrong_host(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", "gx10-e526")
        report["collector_metadata"]["remote_script_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "collector provenance"):
            module.validate_collection_report(report)

        report = module.make_report(sample_state(), "pc3@pc3", "gx10-e526")
        report["host"] = "pc6"
        with self.assertRaisesRegex(ValueError, "expected PC3"):
            module.validate_collection_report(report)

    def test_report_creation_is_exclusive_and_mode_0600(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", "gx10-e526")
        with tempfile.TemporaryDirectory(dir=ROOT / "evidence") as temporary:
            path = Path(temporary) / "snapshot.json"
            module.write_report(path, report)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), report)
            with self.assertRaises(FileExistsError):
                module.write_report(path, report)

    def test_report_writer_refuses_destinations_outside_private_evidence_tree(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", "gx10-e526")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "snapshot.json"
            with self.assertRaisesRegex(ValueError, "private evidence tree"):
                module.write_report(path, report)
            self.assertFalse(path.exists())

    def test_report_does_not_contain_credential_source_or_secret(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", "gx10-e526")
        encoded = json.dumps(report)
        self.assertNotIn("password", encoded.lower())
        self.assertNotIn("private_key_contents", encoded.lower())
        self.assertNotIn("ACCES-BANC-GPU.env", encoded)

    def test_collector_rejects_a_snapshot_from_the_wrong_host(self):
        module = load_module()
        state = sample_state()
        state["host"] = "another-host"
        with self.assertRaisesRegex(ValueError, "expected PC3"):
            module.make_report(state, "pc3@pc3", "gx10-e526")

    def test_collector_uses_strict_ssh_and_keeps_the_sudo_value_out_of_argv(self):
        module = load_module()
        secret = "test-only-sudo-value"
        payload = json.dumps(sample_state()).encode()
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr=b"")
        with (patch.object(module.pc3, "fetch_pc3_sudo_secret", return_value=secret) as fetch,
              patch.object(module.pc3, "pc3_ssh_base", return_value=["ssh", "--", "pc3@pc3"]) as ssh,
              patch.object(module.subprocess, "run", return_value=completed) as remote):
            state = module.collect_host_state()

        self.assertEqual(state, sample_state())
        fetch.assert_called_once()
        ssh.assert_called_once_with("pc3@pc3", "pc3")
        argv = remote.call_args.args[0]
        self.assertNotIn(secret, repr(argv))
        self.assertEqual(remote.call_args.kwargs["input"], (secret + "\n").encode())
        self.assertIs(remote.call_args.kwargs["check"], False)
        self.assertEqual(remote.call_args.kwargs["timeout"], 90)

    def test_direct_collector_uses_only_pinned_pc3_key_and_sudo_n(self):
        module = load_module()
        payload = json.dumps(sample_state()).encode()
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=payload, stderr=b"")
        with (patch.object(module.pc3, "fetch_pc3_sudo_secret") as fetch,
              patch.object(module, "direct_pc3_ssh_base",
                           return_value=["ssh", "--", "pc3@pc3"]) as ssh,
              patch.object(module.subprocess, "run", return_value=completed) as remote):
            state = module.collect_host_state_direct()

        self.assertEqual(state, sample_state())
        fetch.assert_not_called()
        ssh.assert_called_once_with("pc3@pc3", "pc3", None)
        argv = remote.call_args.args[0]
        self.assertEqual(argv[:3], ["ssh", "--", "pc3@pc3"])
        self.assertTrue(argv[-1].startswith("sudo -n python3 -c "))
        self.assertNotIn("gx10-e526", repr(argv))
        self.assertIs(remote.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(remote.call_args.kwargs["timeout"], 90)

    def test_direct_ssh_builder_enforces_pinned_alias_and_key_only_auth(self):
        module = load_module()
        argv = module.direct_pc3_ssh_base()
        encoded = " ".join(argv)
        self.assertEqual(argv[-1], "pc3@pc3")
        self.assertIn("-oPreferredAuthentications=publickey", encoded)
        self.assertIn("-oPasswordAuthentication=no", encoded)
        self.assertIn("-oStrictHostKeyChecking=yes", encoded)
        self.assertIn("-oHostKeyAlias=pc3", encoded)
        with self.assertRaisesRegex(ValueError, "pinned PC3 SSH route"):
            module.direct_pc3_ssh_base("pc1@pc1", "pc1")

    def test_direct_ssh_identity_is_private_and_scoped_to_users_ssh_directory(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            key = ssh_dir / "pc3-key"
            key.write_bytes(b"test key placeholder")
            key.chmod(0o600)
            with patch.object(module.Path, "home", return_value=root):
                argv = module.direct_pc3_ssh_base(identity_file=key)
                self.assertIn("-i", argv)
                self.assertIn(str(key), argv)
                self.assertIn("-oIdentitiesOnly=yes", argv)
                self.assertEqual(argv[-1], "pc3@pc3")
                self.assertEqual(module.validate_direct_identity_file(key), key)

                key.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "private regular file"):
                    module.validate_direct_identity_file(key)

    def test_direct_ssh_identity_rejects_symlink_and_non_pc3_paths(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            key = ssh_dir / "pc3-key"
            key.write_bytes(b"test key placeholder")
            key.chmod(0o600)
            link = ssh_dir / "key-link"
            link.symlink_to(key)
            outside = root / "outside-key"
            outside.write_bytes(b"test key placeholder")
            outside.chmod(0o600)
            with patch.object(module.Path, "home", return_value=root):
                with self.assertRaisesRegex(ValueError, "private regular file"):
                    module.validate_direct_identity_file(link)
                with self.assertRaisesRegex(ValueError, "private regular file"):
                    module.validate_direct_identity_file(outside)
                with self.assertRaisesRegex(ValueError, "absolute"):
                    module.validate_direct_identity_file(Path("relative-key"))

    def test_direct_ssh_identity_provenance_records_only_basename(self):
        module = load_module()
        report = module.make_report(sample_state(), "pc3@pc3", None,
                                    transport_mode=module.DIRECT_TRANSPORT_MODE,
                                    identity_file_basename="gitspace_pc3_20261009")
        transport = report["collector_metadata"]["transport"]
        self.assertEqual(transport["identity_file_basename"], "gitspace_pc3_20261009")
        self.assertNotIn("/home/", json.dumps(transport))
        self.assertEqual(module.validate_collection_report(report), report)

    def test_direct_cli_refuses_legacy_credential_route_options(self):
        module = load_module()
        with tempfile.TemporaryDirectory(dir=ROOT / "evidence") as temporary:
            output = Path(temporary) / "must-not-exist.json"
            stderr = io.StringIO()
            with (patch.object(module, "collect_host_state_direct") as collect,
                  redirect_stderr(stderr)):
                status = module.main(["--direct-pc3", "--credential-host", "gx10-e526",
                                      "--output", str(output)])
            self.assertEqual(status, 2)
            collect.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIn("cannot be combined", stderr.getvalue())

    def test_full_suite_evidence_pins_pc3_state_and_signing_tools(self):
        runner = (ROOT / "tools/run_software_test_suite.py").read_text(encoding="utf-8")
        self.assertIn('"tools/collect_pc3_canary_host_state.py"', runner)
        self.assertIn('"tools/audit_r595_uvm_candidate_preflight.py"', runner)
        self.assertIn('"tools/audit_pc3_candidate_signing_preconditions.py"', runner)
        self.assertIn('"tools/audit_pc3_vm_gpu_assignment.py"', runner)

    def test_full_suite_evidence_pins_the_hybrid_bundle_audit_and_builders(self):
        runner = (ROOT / "tools/run_software_test_suite.py").read_text(encoding="utf-8")
        for source in (
            "tools/audit_hybrid_candidate_bundle.py",
            "tools/audit_pc3_r595_recovery_stage.py",
            "tools/probe_volta_uvm_port.py",
            "tools/probe_r595_gv100_complete_hal.py",
            "tools/audit_r595_uvm_symbol_closure.py",
            "tools/build_hybrid_frontend.py",
            "tools/compare_uvm_ioctl_routes.py",
            "tools/build_private_open580_wrapper.py",
            "tools/replay_r580_open_patches_on_r595.py",
            "tools/verify_hybrid_bundle_depmod.py",
            "tools/run_pc3_v100_private_proprietary580_build.py",
            "tools/run_pc3_v100_private_open580_build.py",
            "tools/build_private_proprietary580.py",
            "tools/build_proprietary580_wrapper_baseline.py",
        ):
            with self.subTest(source=source):
                self.assertIn(f'"{source}"', runner)

    def test_full_suite_pins_the_current_acceptance_probe_bundle(self):
        runner = (ROOT / "tools/run_software_test_suite.py").read_text(encoding="utf-8")
        bundle = "build/probe-cuda129-sm70v-sm120a-v3-host-staged"
        self.assertIn(bundle + "/hybrid_cuda_probe", runner)
        self.assertIn(bundle + "/build-manifest.json", runner)
        self.assertIn("c2c0aa30d26fe2fb7e61a5ef732bc1f659faa39eb4626e1d46689f2aa85e1422", runner)
        self.assertIn("source_inputs_sha256", runner)
        self.assertIn("build_tool_sha256", runner)
        self.assertIn('builder_sha256 = manifest.get("build_tool_sha256")', runner)
        self.assertIn('ROOT / "tools/build_probe_cuda129.py"', runner)
        self.assertIn("eb08482739ac2f601bb1954ac8a88035e7752b91e8188aaba6730b952c48c22a", runner)


if __name__ == "__main__":
    unittest.main()
