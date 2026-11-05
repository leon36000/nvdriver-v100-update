# SPDX-License-Identifier: MIT
"""Contracts for the bounded PC3 V100 VM recovery watchdog."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shlex
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/manage_pc3_v100_canary_watchdog.py"
CANARY_ID = "0123456789abcdef0123456789abcdef"


def load_tool():
    spec = importlib.util.spec_from_file_location("pc3_v100_canary_watchdog", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("PC3 V100 watchdog tool is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Pc3V100CanaryWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_remote_programs_are_valid_python(self):
        compile(self.tool.REMOTE_PROGRAM, "<pc3-v100-watchdog-control>", "exec")
        compile(self.tool.WATCHDOG_SERVICE_PROGRAM, "<pc3-v100-watchdog-service>", "exec")

    def test_restart_is_guarded_by_timeout_cancel_marker_and_shared_lock(self):
        control = self.tool.REMOTE_PROGRAM
        service = self.tool.WATCHDOG_SERVICE_PROGRAM
        self.assertIn("--on-active=", control)
        self.assertIn("fcntl.LOCK_EX", control)
        self.assertIn("fcntl.LOCK_SH", service)
        self.assertIn("cancel_path.exists()", service)
        self.assertIn('["/usr/bin/systemctl","restart",SERVICE]', service)
        self.assertIn('"pc3-v100-qemu.service"', service)
        self.assertNotIn("shell=True", control + service)
        self.assertNotIn('"argv":', control + service)
        self.assertNotIn('"command_line":', control + service)

    def test_qemu_watchdog_arm_is_fixed_host_unit_and_requires_active_v100_assignment(self):
        script = self.tool.REMOTE_PROGRAM
        self.assertIn('EXPECTED_HOST="pc3"', script)
        self.assertIn('SERVICE="pc3-v100-qemu.service"', script)
        self.assertIn("has_v100", script)
        self.assertIn('props.get("Restart")!="on-failure"', script)
        self.assertIn('props.get("KillMode")!="control-group"', script)
        self.assertIn("not 120<=SECONDS<=900", script)

    def test_remote_command_rejects_unbounded_timeout_and_injection_values(self):
        with self.assertRaisesRegex(ValueError, "hex token"):
            self.tool.remote_script("arm", "bad;systemctl", 300)
        with self.assertRaisesRegex(ValueError, "120 and 900"):
            self.tool.remote_script("arm", CANARY_ID, 30)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.tool.remote_script("restart", CANARY_ID, 300)
        command = self.tool.remote_script("arm", CANARY_ID, 300)
        self.assertEqual(shlex.split(command)[-4:-1], ["arm", CANARY_ID, "300"])
        self.assertIn("systemctl-restart", self.tool.WATCHDOG_SERVICE_PROGRAM)

    def test_harmless_self_test_only_schedules_usr_bin_true(self):
        script = self.tool.REMOTE_PROGRAM
        block = script.split('if ACTION=="self-test":', 1)[1].split('if ACTION=="arm":', 1)[0]
        self.assertIn('"--on-active=90s"', block)
        self.assertIn('"/usr/bin/true"', block)
        self.assertNotIn('["/usr/bin/systemctl","restart",SERVICE]', block)

    def test_inspection_requires_successful_restart_receipt_and_active_qemu(self):
        script = self.tool.REMOTE_PROGRAM
        self.assertIn('ACTION not in ("arm","cancel","self-test","inspect")', script)
        block = script.split('elif ACTION=="inspect":', 1)[1].split('elif ACTION=="arm":', 1)[0]
        self.assertIn('status_path.lstat()', block)
        self.assertIn('"event":"restart_finished"', block)
        self.assertIn('"returncode":0', block)
        self.assertIn('status_data.get("action") not in (None,"systemctl-restart")', block)
        self.assertIn('props.get("ActiveState")=="active"', block)
        self.assertNotIn('["/usr/bin/systemctl","restart",SERVICE]', block)
        self.assertIn('"action":"systemctl-restart"', self.tool.WATCHDOG_SERVICE_PROGRAM)

    def test_inspection_is_read_only_at_evidence_contract(self):
        command = self.tool.remote_script("inspect", CANARY_ID, 300)
        self.assertIn(" inspect ", " " + command + " ")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.tool.remote_script("status", CANARY_ID, 300)

    def test_inspect_collect_requires_success_receipt_and_live_v100_qemu(self):
        class Transport:
            DEFAULT_CREDENTIAL_HOST = "credential-host"
            DEFAULT_CREDENTIAL_FILE = "/secure/credential.ini"
            DEFAULT_PC3_TARGET = "pc3@pc3"
            DEFAULT_HOST_KEY_ALIAS = "pc3"

            @staticmethod
            def fetch_pc3_sudo_secret(*_args):
                return "secret"

            @staticmethod
            def sudo_auth_stdin(_secret):
                return b"secret\n"

            @staticmethod
            def pc3_ssh_base(*_args):
                return ["ssh", "pc3"]

        receipt = {
            "schema": "pc3-v100-canary-watchdog-remote-v1",
            "host": "pc3",
            "action": "inspect",
            "canary_id": CANARY_ID,
            "target_service": "pc3-v100-qemu.service",
            "system_state_changed": False,
            "status": "restart-finished",
            "restart_event": "restart_finished",
            "restart_returncode": 0,
            "qemu_service_active": True,
            "qemu_process_count": 1,
            "qemu_command_digest": "a" * 64,
        }
        with patch.object(self.tool, "load_transport", return_value=Transport), \
                patch.object(self.tool.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=__import__("json").dumps(receipt).encode(), stderr=b"")):
            self.assertEqual(self.tool.collect("inspect", CANARY_ID, 300), receipt)

        bad_receipt = dict(receipt, qemu_process_count=0, qemu_command_digest=None)
        with patch.object(self.tool, "load_transport", return_value=Transport), \
                patch.object(self.tool.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=__import__("json").dumps(bad_receipt).encode(), stderr=b"")):
            with self.assertRaisesRegex(RuntimeError, "successful V100 QEMU service restart"):
                self.tool.collect("inspect", CANARY_ID, 300)

    def test_evidence_writer_is_private_exclusive_and_root_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            report = evidence / "watchdog.json"
            self.tool.ROOT = root
            self.assertEqual(self.tool.write_evidence(report, {"status": "armed"}),
                             __import__("hashlib").sha256(report.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.tool.write_evidence(report, {})
            with self.assertRaisesRegex(ValueError, "evidence directory"):
                self.tool.write_evidence(root / "outside.json", {})


if __name__ == "__main__":
    unittest.main()
