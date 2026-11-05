# SPDX-License-Identifier: MIT
"""Offline safety and evidence-contract tests for the PC3 user inventory."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/probe_pc3_user_gpu_inventory.py"
SPEC = importlib.util.spec_from_file_location("probe_pc3_user_gpu_inventory", TOOL)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def payload(hostname="pc3"):
    return {
        "schema": "pc3-user-gpu-inventory-payload-v1",
        "hostname": hostname,
        "uid": 1000,
        "username": "pc3",
        "kernel_release": "6.8-test",
        "os_release": "NAME=Linux\n",
        "loaded_nvidia_modules": ["nvidia"],
        "commands": {"gpu_list": {"exit_code": 0, "stdout": "GPU 0: RTX 5080"}},
    }


class Pc3UserInventoryTests(unittest.TestCase):
    def test_remote_probe_is_python_syntax_and_contains_only_bounded_read_calls(self):
        compile(PROBE.REMOTE_SCRIPT, "pc3-remote-probe", "exec")
        self.assertIn("nvidia-smi", PROBE.REMOTE_SCRIPT)
        self.assertIn('"pci_topology":run(["lspci","-Dtv"])', PROBE.REMOTE_SCRIPT)
        self.assertIn('"pci_rtx_upstream_port":run(["lspci","-D","-s","0000:00:06.0","-vv"])', PROBE.REMOTE_SCRIPT)
        self.assertIn('"pci_v100_upstream_port":run(["lspci","-D","-s","0000:80:1b.0","-vv"])', PROBE.REMOTE_SCRIPT)
        self.assertIn('"/sys/kernel/iommu_groups"', PROBE.REMOTE_SCRIPT)
        for bdf in ("0000:02:00.0", "0000:02:00.1", "0000:81:00.0"):
            self.assertIn(bdf, PROBE.REMOTE_SCRIPT)
        self.assertIn("/proc/modules", PROBE.REMOTE_SCRIPT)
        self.assertNotIn("sudo ", PROBE.REMOTE_SCRIPT)
        for forbidden in ("modprobe", "insmod", "rmmod", "apt-get", "systemctl restart",
                          "os.system", "shell=True", "virsh attach-device", "Path.write_text",
                          "Path.unlink", "os.unlink"):
            self.assertNotIn(forbidden, PROBE.REMOTE_SCRIPT)

    def test_collection_is_pinned_to_pc3_and_records_scoped_identity(self):
        identity = Path("/home/pc1/.ssh/pc3-test-key")
        completed = subprocess.CompletedProcess([], 0,
            stdout=json.dumps(payload()).encode(), stderr=b"")
        with (patch.object(PROBE.host_state, "validate_direct_identity_file", return_value=identity),
              patch.object(PROBE.pc3_transport, "verify_pc3_host_key") as verify_key,
              patch.object(PROBE.host_state, "direct_pc3_ssh_base",
                           return_value=["ssh", "--", "pc3@pc3"]) as ssh,
              patch.object(PROBE.subprocess, "run", return_value=completed) as remote):
            report = PROBE.collect(identity)
        verify_key.assert_called_once_with()
        ssh.assert_called_once_with(identity_file=identity)
        argv = remote.call_args.args[0]
        self.assertEqual(argv[:3], ["ssh", "--", "pc3@pc3"])
        self.assertEqual(argv[-2], "pc3@pc3")
        self.assertTrue(argv[-1].startswith("python3 -c "))
        self.assertEqual(report["host"]["hostname"], "pc3")
        self.assertEqual(report["transport"]["identity_file_basename"], "pc3-test-key")
        self.assertTrue(report["transport"]["host_key_verified_against_pinned_known_hosts"])
        self.assertFalse(report["scope"]["runtime_or_hardware_workload_tested"])
        self.assertFalse(report["scope"]["driver_installed_or_loaded"])
        self.assertNotIn("/home/pc1", json.dumps(report["transport"]))

    def test_collection_rejects_wrong_host_and_nonzero_ssh_status(self):
        identity = Path("/home/pc1/.ssh/pc3-test-key")
        with (patch.object(PROBE.host_state, "validate_direct_identity_file", return_value=identity),
              patch.object(PROBE.pc3_transport, "verify_pc3_host_key"),
              patch.object(PROBE.host_state, "direct_pc3_ssh_base", return_value=["ssh"]),
              patch.object(PROBE.subprocess, "run", return_value=subprocess.CompletedProcess(
                  [], 0, stdout=json.dumps(payload("pc6")).encode(), stderr=b""))):
            with self.assertRaisesRegex(RuntimeError, "identity or schema"):
                PROBE.collect(identity)
        with (patch.object(PROBE.host_state, "validate_direct_identity_file", return_value=identity),
              patch.object(PROBE.pc3_transport, "verify_pc3_host_key"),
              patch.object(PROBE.host_state, "direct_pc3_ssh_base", return_value=["ssh"]),
              patch.object(PROBE.subprocess, "run", return_value=subprocess.CompletedProcess(
                  [], 255, stdout=b"", stderr=b"denied"))):
            with self.assertRaisesRegex(RuntimeError, "command failed"):
                PROBE.collect(identity)

    def test_report_is_private_exclusive_and_inside_evidence(self):
        report = {"schema": "fixture"}
        with tempfile.TemporaryDirectory(dir=ROOT / "evidence") as tmp:
            target = Path(tmp) / "inventory.json"
            PROBE.write_report(target, report)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                PROBE.write_report(target, report)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "inside evidence"):
                PROBE.write_report(Path(tmp) / "outside.json", report)


if __name__ == "__main__":
    unittest.main()
