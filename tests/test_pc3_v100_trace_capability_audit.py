# SPDX-License-Identifier: MIT
import importlib.util
import json
from unittest import mock
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/inspect_pc3_v100_trace_capabilities.py"
SPEC = importlib.util.spec_from_file_location("pc3_v100_trace_capability_audit", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(TOOL)


def valid_report():
    return {
        "schema": "nvidia-hybrid-pc3-v100-trace-capability-v3",
        "status": "observed",
        "host": {"hostname": "pc3", "sudo_identity_verified": True, "guest_host_key_verified": True},
        "guest": {
            "hostname": "pc3-v100",
            "kernel_release": "6.8.0-147-generic",
            "effective_uid": 1000,
            "gpus": [{
                "name": "Tesla V100-SXM2-16GB",
                "pci": "0000:00:05.0",
                "driver_version": "580.178.04",
            }],
            "trace_interfaces": {
                "tracefs_kprobe_events": {"present": True, "readable": False,
                                          "mode": "0o600", "error": "permission_denied"},
            },
            "kernel_probe_config": {
                "tracefs_mounted": True,
                "tracefs_mountpoints": ["/sys/kernel/tracing"],
                "guest_sudo_root_nopasswd": False,
                "config_bpf_syscall":"y",
                "config_bpf_events":"y",
                "config_fprobe":"y",
            },
            "bpf_attachment_capabilities": {
                "tools_available":{"bpftrace":True, "bpftool":True, "clang":True},
                "vmlinux_btf":{"present":True, "readable":True, "mode":"0o444", "error":None},
                "bpffs":{"present":True, "readable":True, "mode":"0o700", "error":None},
                "unprivileged_bpf_disabled":"2", "lockdown_state":None,
                "effective_capabilities":{"cap_bpf":True, "cap_perfmon":True,
                    "cap_sys_admin":True, "readable":True},
            },
            "target_symbols": {"_nv000794rm": {"module_symbol_table": True}},
        },
        "read_only": True,
        "experimental_module_loaded": False,
        "stock_driver_changed": False,
        "pci_binding_changed": False,
        "vm_management_issued": False,
        "kprobe_attached": False,
    }


class PC3V100TraceCapabilityAuditTests(unittest.TestCase):
    def test_current_pinned_transport_helper_loads(self):
        reference = TOOL.load_reference_tool()
        self.assertTrue(callable(reference.fetch_pc3_sudo_secret))
        self.assertTrue(callable(reference.pc3_ssh_base))

    def test_pc3_ssh_environment_preserves_only_agent_access_from_caller(self):
        env = TOOL.pc3_ssh_environment({
            "PATH": "/unsafe/path",
            "LC_ALL": "fr_CA.UTF-8",
            "SSH_AUTH_SOCK": "/run/user/1000/ssh-agent.sock",
            "SSH_AGENT_PID": "9876",
            "CUDA_VISIBLE_DEVICES": "0",
            "LD_PRELOAD": "/tmp/evil.so",
            "AWS_SECRET_ACCESS_KEY": "must-not-pass",
        })
        self.assertEqual(env, {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "SSH_AUTH_SOCK": "/run/user/1000/ssh-agent.sock",
            "SSH_AGENT_PID": "9876",
        })

    def test_classifies_empty_ssh_255_as_pc3_transport_failure(self):
        self.assertEqual(TOOL.classify_transport_failure(255, b""), "pc3_ssh_transport")

    def test_distinguishes_remote_failure_from_transport_and_json_validation(self):
        self.assertEqual(TOOL.classify_transport_failure(1, b""), "pc3_remote_execution")
        self.assertIsNone(TOOL.classify_transport_failure(0, b""))
        self.assertIsNone(TOOL.classify_transport_failure(255, b"partial output"))

    def test_remote_failure_summary_keeps_only_allowlisted_diagnostics(self):
        remote = {
            "schema": "nvidia-hybrid-pc3-v100-trace-capability-v3",
            "status": "guest_query_failed",
            "host": {
                "hostname": "pc3",
                "kernel_release": "6.8.0-147-generic",
                "sudo_identity_verified": True,
                "guest_host_key_verified": True,
                "private_key": "must-not-be-retained",
            },
            "guest_transport": {
                "returncode": 255,
                "stdout_bytes": 0,
                "stdout_sha256": "a" * 64,
                "stderr_sha256": "b" * 64,
                "stderr": "must-not-be-retained",
            },
            "guest": {
                "hostname": "pc3-v100",
                "kernel_release": "6.8.0-147-generic",
                "effective_uid": 1000,
                "gpus": [{
                    "name": "Tesla V100-SXM2-16GB",
                    "pci": "0000:00:05.0",
                    "driver_version": "580.178.04",
                    "uuid": "must-not-be-retained",
                }],
                "stock_module": {
                    "version": "580.178.04",
                    "file": {"basename": "nvidia.ko.zst", "bytes": 123},
                    "module_symbol_table_readable": True,
                    "symbol_source": "zstd_memfd",
                    "decompressor_returncode": 0,
                    "target_symbol_offsets": {"_nv000794rm": "0000000000000000"},
                    "target_symbol_types": {"_nv000794rm": "T"},
                    "secret": "must-not-be-retained",
                },
                "trace_interfaces": {
                    "proc_kallsyms_target_names": ["_nv000794rm"],
                    "tracefs_root": {"present": True, "readable": False,
                                     "mode": "0o550", "error": "permission_denied"},
                },
                "kernel_kprobe_control_candidates": {
                    "proc_kallsyms": ["do_sys_openat2"],
                },
                "kernel_probe_config": {
                    "tracefs_mounted": True,
                    "tracefs_mountpoints": ["/sys/kernel/tracing"],
                    "guest_sudo_root_nopasswd": False,
                    "config_bpf_syscall":"y", "config_bpf_events":"y", "config_fprobe":"y",
                },
                "bpf_attachment_capabilities": {
                    "tools_available":{"bpftrace":True, "bpftool":False, "clang":True},
                    "vmlinux_btf":{"present":True, "readable":True, "mode":"0o444", "error":None},
                    "bpffs":{"present":True, "readable":True, "mode":"0o700", "error":None},
                    "unprivileged_bpf_disabled":"2", "lockdown_state":None,
                    "effective_capabilities":{"cap_bpf":True, "cap_perfmon":False,
                        "cap_sys_admin":True, "readable":True},
                },
                "raw_output": "must-not-be-retained",
            },
            "token": "must-not-be-retained",
        }
        summary = TOOL.remote_failure_summary(remote)
        self.assertEqual(summary["status"], "guest_query_failed")
        self.assertTrue(summary["host"]["guest_host_key_verified"])
        self.assertEqual(summary["guest_transport"]["returncode"], 255)
        self.assertNotIn("private_key", summary["host"])
        self.assertNotIn("stderr", summary["guest_transport"])
        self.assertEqual(summary["guest"]["gpus"][0]["pci"], "0000:00:05.0")
        self.assertNotIn("uuid", summary["guest"]["gpus"][0])
        self.assertEqual(summary["guest"]["stock_module"]["symbol_source"], "zstd_memfd")
        self.assertEqual(summary["guest"]["effective_uid"], 1000)
        self.assertEqual(summary["guest"]["trace_interfaces"]["tracefs_root"]["error"], "permission_denied")
        self.assertEqual(summary["guest"]["kernel_kprobe_control_candidates"]["proc_kallsyms"], ["do_sys_openat2"])
        self.assertEqual(summary["guest"]["kernel_probe_config"]["tracefs_mountpoints"], ["/sys/kernel/tracing"])
        self.assertTrue(summary["guest"]["bpf_attachment_capabilities"]["effective_capabilities"]["cap_bpf"])
        self.assertNotIn("secret", summary["guest"]["bpf_attachment_capabilities"])
        self.assertNotIn("secret", summary["guest"]["stock_module"])
        self.assertNotIn("raw_output", summary["guest"])
        self.assertNotIn("token", summary)

    def test_accepts_private_read_only_inventory_for_expected_guest(self):
        result = TOOL.validate_report(valid_report())
        self.assertEqual(result["guest"]["hostname"], "pc3-v100")
        self.assertEqual(result["guest"]["gpus"][0]["pci"], "0000:00:05.0")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["kprobe_attached"])

    def test_validates_v100_identity_without_assuming_vm_bdf_or_r580_patch(self):
        report = valid_report()
        report["guest"]["gpus"][0]["pci"] = "0000:01:00.0"
        report["guest"]["gpus"][0]["driver_version"] = "580.193.02"
        result = TOOL.validate_report(report)
        self.assertEqual(result["guest"]["gpus"][0]["pci"], "0000:01:00.0")

        wrong_branch = valid_report()
        wrong_branch["guest"]["gpus"][0]["driver_version"] = "610.12.00"
        with self.assertRaisesRegex(ValueError, "R580"):
            TOOL.validate_report(wrong_branch)

    def test_generated_probe_uses_literal_dot_in_pci_bus_pattern(self):
        code = TOOL.guest_probe_script()
        self.assertIn(r"{2})\.([0-7])", code)
        self.assertNotIn(r"{2})\\.([0-7])", code)

    def test_rejects_wrong_guest_or_any_mutating_action(self):
        wrong_guest = valid_report()
        wrong_guest["guest"]["hostname"] = "other"
        with self.assertRaisesRegex(ValueError, "wrong V100 guest"):
            TOOL.validate_report(wrong_guest)

        changed = valid_report()
        changed["experimental_module_loaded"] = True
        with self.assertRaisesRegex(ValueError, "read-only scope"):
            TOOL.validate_report(changed)

    def test_generated_probe_only_reads_trace_and_module_metadata(self):
        code = TOOL.guest_probe_script()
        self.assertIn("/proc/kallsyms", code)
        self.assertIn("available_filter_functions", code)
        self.assertIn("kprobe_events", code)
        self.assertIn("nm", code)
        for forbidden in ("modprobe ", "insmod ", "rmmod ", "systemctl ", "kprobe_events'\n"):
            self.assertNotIn(forbidden, code)
        self.assertIn('"kprobe_attached":False', code)
        self.assertIn("memfd_create", code)
        self.assertIn("zstd", code)
        self.assertIn("pass_fds", code)
        self.assertNotIn("query-gpu=name,uuid", code)
        self.assertIn('"KALLSYMS_ALL"', code)
        self.assertIn('"FTRACE"', code)
        self.assertIn("tracefs_mounted", code)
        self.assertIn("debugfs_mounted", code)
        self.assertIn('"effective_uid":os.geteuid()', code)
        self.assertIn('"guest_sudo_root_nopasswd"', code)
        self.assertIn('"bpf_attachment_capabilities"', code)
        self.assertIn('"config_bpf_syscall"', code)
        self.assertIn('"config_bpf_events"', code)
        self.assertIn('"config_fprobe"', code)
        self.assertIn('"vmlinux_btf"', code)
        self.assertIn('"cap_perfmon"', code)
        self.assertNotIn("BPF_PROG_LOAD", code)
        self.assertNotIn("bpftrace -e", code)
        self.assertIn('"do_sys_openat2"', code)
        self.assertIn('"permission_denied"', code)
        compile(code, "<pc3-v100-read-only-probe>", "exec")

    def test_generated_interface_probe_distinguishes_missing_from_permission_denied(self):
        code = TOOL.guest_probe_script().removesuffix("\nmain()\n")
        namespace = {"__name__": "pc3_v100_probe_test"}
        exec(compile(code, "<pc3-v100-interface>", "exec"), namespace)
        with mock.patch.object(namespace["os"], "stat", side_effect=FileNotFoundError):
            self.assertEqual(namespace["interface"]("/not-present"), {
                "present": False, "readable": False, "mode": None, "error": "not_found"
            })
        with mock.patch.object(namespace["os"], "stat", side_effect=PermissionError):
            self.assertEqual(namespace["interface"]("/permission-denied"), {
                "present": None, "readable": False, "mode": None, "error": "permission_denied"
            })
        directory = namespace["interface"](str(ROOT))
        self.assertTrue(directory["present"])
        self.assertTrue(directory["readable"])

    def test_guest_config_parser_distinguishes_disabled_bpf_from_unavailable_config(self):
        code = TOOL.guest_probe_script().removesuffix("\nmain()\n")
        namespace = {"__name__":"pc3_v100_config_test"}
        exec(compile(code, "<pc3-v100-config>", "exec"), namespace)
        self.assertEqual(namespace["config_value"](["CONFIG_BPF_SYSCALL=y"], "BPF_SYSCALL"), "y")
        self.assertEqual(namespace["config_value"](["# CONFIG_BPF_EVENTS is not set"], "BPF_EVENTS"), "n")
        self.assertEqual(namespace["config_value"]([], "DEBUG_INFO_BTF"), "unknown")

    def test_remote_wrapper_compiles_and_keeps_strict_guest_identity_checks(self):
        code = TOOL.remote_root_script(
            TOOL.guest_probe_script(),
            "SHA256:wqpBfvwVW7iYhOk7LWB8y438NOQHSgfcUgnOGaRK6ts",
            "/var/lib/pc3-v100-vm/id_ed25519",
            "/tmp/codex-pc3-vm-known_hosts",
        )
        compile(code, "<pc3-v100-root-audit>", "exec")
        self.assertIn("StrictHostKeyChecking=yes", code)
        self.assertIn("EXPECTED_HOST = \"pc3\"", code)
        self.assertIn("kprobe_attached", code)
        source = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn('remote = "sudo -n python3 -c "', source)


if __name__ == "__main__":
    unittest.main()
