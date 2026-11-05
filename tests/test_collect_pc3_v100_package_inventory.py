#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU-only contracts for the read-only V100 guest package inventory."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/collect_pc3_v100_package_inventory.py"


def load_tool():
    if not TOOL_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("collect_pc3_v100_package_inventory", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_inventory():
    return {
        "schema": "nvidia-hybrid-pc3-v100-package-inventory-v6",
        "observed_at_utc": "2026-10-28T15:00:00+00:00",
        "hostname": "v100-guest",
        "kernel_release": "6.8.0-147-generic",
        "packages": [{
            "name": "libnvidia-compute-580:amd64",
            "version": "580.178.04-0ubuntu0.26.04.1",
            "architecture": "amd64",
            "status": "install ok installed",
        }],
        "kernel_header_packages": [{
            "name": "linux-headers-6.8.0-147",
            "version": "6.8.0-147.1",
            "architecture": "all",
            "status": "install ok installed",
        }, {
            "name": "linux-headers-6.8.0-147-generic",
            "version": "6.8.0-147.1",
            "architecture": "amd64",
            "status": "install ok installed",
        }],
        "libraries": [{
            "package": "libnvidia-compute-580:amd64",
            "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
            "resolved_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
            "is_symlink": False,
            "bytes": 96284520,
            "sha256": "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9",
        }],
        "pinned_libcuda_path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
        "kernel_build": {
            "modules_directory": "/lib/modules/6.8.0-147-generic",
            "modules_directory_exists": True,
            "build_link_exists": True,
            "build_link_is_symlink": True,
            "build_link_target": "/usr/src/linux-headers-6.8.0-147-generic",
            "resolved_build_path": "/usr/src/linux-headers-6.8.0-147-generic",
            "resolved_build_directory_exists": True,
            "makefile_exists": True,
            "auto_config_exists": True,
            "generated_autoconf_exists": True,
            "generated_utsrelease_exists": True,
            "scripts_makefile_build_exists": True,
            "scripts_makefile_modpost_exists": True,
            "scripts_modpost_exists": True,
            "scripts_fixdep_exists": True,
            "module_symvers_exists": True,
            "module_symvers_bytes": 123456,
            "module_symvers_sha256": "a" * 64,
            "source_link_exists": True,
            "source_link_is_symlink": True,
            "source_link_target": "/usr/src/linux-headers-6.8.0-147-generic",
            "resolved_source_path": "/usr/src/linux-headers-6.8.0-147-generic",
            "resolved_source_directory_exists": True,
            "kernel_build_ready": True,
        },
        "module_state": {
            "loaded_nvidia_modules": ["nvidia", "nvidia_uvm"],
            "loaded_nvidia_module_version": "580.178.04",
            "loaded_nvidia_module_srcversion": "ABCDEF0123456789ABCDEF01",
            "loaded_nvidia_module_pre_capture": {
                "modules": ["nvidia", "nvidia_uvm"],
                "version": "580.178.04",
                "srcversion": "ABCDEF0123456789ABCDEF01",
            },
            "loaded_nvidia_module_matches_installed_source_identity": True,
            "signature_enforcement": "N",
            "lockdown_state": "none",
            "secure_boot_state": "disabled",
            "installed_modules": [
                {"name": "nvidia", "exists": True,
                 "path": "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia.ko.zst",
                 "bytes": 123456, "sha256": "b" * 64,
                 "version": "580.178.04",
                 "srcversion": "ABCDEF0123456789ABCDEF01",
                 "license": "NVIDIA",
                 "vermagic": "6.8.0-147-generic SMP preempt mod_unload modversions",
                 "signer": "Canonical Ltd."},
                {"name": "nvidia_drm", "exists": True,
                 "path": "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia-drm.ko.zst",
                 "bytes": 123456, "sha256": "c" * 64,
                 "version": "580.178.04",
                 "srcversion": "BCDEF0123456789ABCDEF012",
                 "license": "NVIDIA",
                 "vermagic": "6.8.0-147-generic SMP preempt mod_unload modversions",
                 "signer": "Canonical Ltd."},
                {"name": "nvidia_modeset", "exists": True,
                 "path": "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia-modeset.ko.zst",
                 "bytes": 123456, "sha256": "d" * 64,
                 "version": "580.178.04",
                 "srcversion": "CDEF0123456789ABCDEF0123",
                 "license": "NVIDIA",
                 "vermagic": "6.8.0-147-generic SMP preempt mod_unload modversions",
                 "signer": "Canonical Ltd."},
                {"name": "nvidia_uvm", "exists": True,
                 "path": "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia-uvm.ko.zst",
                 "bytes": 123456, "sha256": "e" * 64,
                 "version": "580.178.04",
                 "srcversion": "DEF0123456789ABCDEF01234",
                 "license": "NVIDIA",
                 "vermagic": "6.8.0-147-generic SMP preempt mod_unload modversions",
                 "signer": "Canonical Ltd."},
            ],
        },
    }


def guest_module_file_function(fake_os, run):
    """Load the embedded guest helper alone so its file checks stay testable."""
    tool = load_tool()
    tree = ast.parse(tool.GUEST_INVENTORY_SCRIPT)
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "module_file")
    namespace = {"hashlib": hashlib, "os": fake_os, "release": "6.8.0-147-generic",
                 "run": run, "stat": stat, "tempfile": tempfile}
    module = ast.Module(body=[function], type_ignores=[])
    exec(compile(module, "<guest-module-file>", "exec"), namespace)
    return namespace["module_file"]


def fake_guest_module_os(module_path, resolved):
    def mapped_path(path):
        return module_path if path == resolved else Path(path)

    class PathShim:
        isabs = staticmethod(os.path.isabs)

        @staticmethod
        def realpath(path):
            return resolved if path == str(module_path) else os.path.realpath(path)

        @staticmethod
        def isfile(path):
            return os.path.isfile(mapped_path(path))

    return SimpleNamespace(
        path=PathShim,
        stat=lambda path, **kwargs: os.stat(mapped_path(path), **kwargs),
        open=lambda path, flags, **kwargs: os.open(mapped_path(path), flags, **kwargs),
        symlink=os.symlink,
        fstat=os.fstat,
        fdopen=os.fdopen,
        close=os.close,
        O_RDONLY=os.O_RDONLY,
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
    )


class ToolAvailability(unittest.TestCase):
    def test_read_only_package_inventory_tool_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "V100 guest package inventory collector is missing")


@unittest.skipUnless(TOOL_PATH.is_file(), "V100 guest package inventory collector is missing")
class GuestInventoryValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def validate(self, inventory):
        return self.tool.validate_guest_inventory(json.dumps(inventory).encode("utf-8"))

    def test_accepts_installed_driver_package_and_pinned_libcuda_hash(self):
        result = self.validate(valid_inventory())
        self.assertEqual(result["packages"][0]["version"], "580.178.04-0ubuntu0.26.04.1")
        self.assertEqual(result["libraries"][0]["sha256"],
                         "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9")
        self.assertTrue(result["kernel_build"]["kernel_build_ready"])

    def test_rejects_build_directory_for_a_different_kernel(self):
        report = valid_inventory()
        report["kernel_build"]["modules_directory"] = "/lib/modules/6.8.0-146-generic"
        with self.assertRaisesRegex(ValueError, "kernel build directory"):
            self.validate(report)

    def test_rejects_kernel_header_package_for_a_different_kernel(self):
        report = valid_inventory()
        report["kernel_header_packages"][0]["name"] = "linux-headers-6.8.0-146"
        with self.assertRaisesRegex(ValueError, "does not match the running kernel"):
            self.validate(report)

    def test_rejects_module_symvers_hash_when_symvers_is_missing(self):
        report = valid_inventory()
        report["kernel_build"]["module_symvers_exists"] = False
        with self.assertRaisesRegex(ValueError, "Module.symvers"):
            self.validate(report)

    def test_rejects_readiness_claim_when_required_kbuild_input_is_missing(self):
        report = valid_inventory()
        report["kernel_build"]["makefile_exists"] = False
        with self.assertRaisesRegex(ValueError, "kernel build readiness"):
            self.validate(report)

    def test_rejects_build_target_without_an_existing_build_link(self):
        report = valid_inventory()
        report["kernel_build"]["build_link_exists"] = False
        with self.assertRaisesRegex(ValueError, "build link"):
            self.validate(report)

    def test_rejects_resolved_build_path_outside_system_kernel_source_locations(self):
        report = valid_inventory()
        report["kernel_build"]["resolved_build_path"] = "/tmp/kernel-build"
        with self.assertRaisesRegex(ValueError, "resolved build path"):
            self.validate(report)

    def test_rejects_wrong_schema(self):
        report = valid_inventory()
        report["schema"] = "other"
        with self.assertRaisesRegex(ValueError, "schema"):
            self.validate(report)

    def test_rejects_older_inventory_schemas_without_current_provenance(self):
        for schema in ("nvidia-hybrid-pc3-v100-package-inventory-v4",
                       "nvidia-hybrid-pc3-v100-package-inventory-v5"):
            with self.subTest(schema=schema):
                report = valid_inventory()
                report["schema"] = schema
                with self.assertRaisesRegex(ValueError, "schema"):
                    self.validate(report)

    def test_rejects_uninstalled_or_non_driver_package(self):
        report = valid_inventory()
        report["packages"][0]["status"] = "deinstall ok config-files"
        with self.assertRaisesRegex(ValueError, "installed"):
            self.validate(report)

    def test_rejects_unrelated_packages_with_cuda_looking_prefixes(self):
        for name in ("libcups2t64:amd64", "libcurl4t64:amd64", "libnvme1t64"):
            with self.subTest(name=name):
                report = valid_inventory()
                report["packages"][0]["name"] = name
                report["libraries"][0]["package"] = name
                with self.assertRaisesRegex(ValueError, "outside the NVIDIA/CUDA inventory scope"):
                    self.validate(report)

    def test_rejects_missing_pinned_libcuda(self):
        report = valid_inventory()
        report["libraries"] = []
        with self.assertRaisesRegex(ValueError, "pinned libcuda"):
            self.validate(report)

    def test_rejects_path_escape_even_when_hash_is_well_formed(self):
        report = valid_inventory()
        report["libraries"][0]["resolved_path"] = "/tmp/libcuda.so.580.178.04"
        with self.assertRaisesRegex(ValueError, "library path"):
            self.validate(report)

    def test_rejects_malformed_library_digest(self):
        report = valid_inventory()
        report["libraries"][0]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.validate(report)

    def test_guest_module_state_pins_security_policy_and_stock_rollback_files(self):
        result = self.validate(valid_inventory())
        module_state = result["module_state"]
        self.assertEqual(module_state["loaded_nvidia_module_version"], "580.178.04")
        self.assertTrue(module_state["loaded_nvidia_module_matches_installed_source_identity"])
        self.assertEqual(module_state["installed_modules"][0]["license"], "NVIDIA")
        self.assertEqual(module_state["installed_modules"][0]["srcversion"],
                         "ABCDEF0123456789ABCDEF01")
        self.assertEqual(len(module_state["installed_modules"]), 4)
        self.assertTrue(all(item["exists"] for item in module_state["installed_modules"]))

    def test_guest_module_state_records_a_source_identity_mismatch(self):
        report = valid_inventory()
        report["module_state"]["loaded_nvidia_module_srcversion"] = "0123456789ABCDEF01234567"
        report["module_state"]["loaded_nvidia_module_pre_capture"]["srcversion"] = "0123456789ABCDEF01234567"
        report["module_state"]["loaded_nvidia_module_matches_installed_source_identity"] = False
        result = self.validate(report)
        self.assertFalse(result["module_state"]["loaded_nvidia_module_matches_installed_source_identity"])

    def test_guest_module_state_leaves_source_identity_unresolved_without_srcversion(self):
        report = valid_inventory()
        report["module_state"]["loaded_nvidia_module_srcversion"] = None
        report["module_state"]["loaded_nvidia_module_pre_capture"]["srcversion"] = None
        report["module_state"]["loaded_nvidia_module_matches_installed_source_identity"] = None
        result = self.validate(report)
        self.assertIsNone(result["module_state"]["loaded_nvidia_module_matches_installed_source_identity"])

    def test_guest_module_state_rejects_a_false_loaded_source_identity_match(self):
        report = valid_inventory()
        report["module_state"]["loaded_nvidia_module_srcversion"] = "0123456789ABCDEF01234567"
        report["module_state"]["loaded_nvidia_module_pre_capture"]["srcversion"] = "0123456789ABCDEF01234567"
        with self.assertRaisesRegex(ValueError, "source identity"):
            self.validate(report)

    def test_loaded_module_change_during_capture_leaves_identity_unresolved(self):
        report = valid_inventory()
        report["module_state"]["loaded_nvidia_module_pre_capture"]["version"] = "580.170.02"
        report["module_state"]["loaded_nvidia_module_matches_installed_source_identity"] = None
        result = self.validate(report)
        self.assertIsNone(result["module_state"]["loaded_nvidia_module_matches_installed_source_identity"])

    def test_loaded_module_change_rejects_a_forged_source_identity_match(self):
        report = valid_inventory()
        report["module_state"]["loaded_nvidia_module_pre_capture"]["version"] = "580.170.02"
        report["module_state"]["loaded_nvidia_module_matches_installed_source_identity"] = True
        with self.assertRaisesRegex(ValueError, "source identity"):
            self.validate(report)

    def test_guest_module_state_rejects_unknown_security_states_and_wrong_vermagic(self):
        cases = (
            lambda state: state.update(signature_enforcement="maybe"),
            lambda state: state.update(secure_boot_state="probably"),
            lambda state: state["installed_modules"][0].update(vermagic="6.8.0-146-generic SMP"),
            lambda state: state["installed_modules"][0].update(path="/tmp/nvidia.ko"),
            lambda state: state["installed_modules"][0].update(sha256="bad"),
            lambda state: state["installed_modules"][0].update(license="NVIDIA\nforged"),
            lambda state: state["installed_modules"][0].update(srcversion="not-a-srcversion"),
        )
        for mutate in cases:
            report = valid_inventory()
            mutate(report["module_state"])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "module state"):
                self.validate(report)

    def test_guest_module_state_is_complete_even_when_a_stock_module_is_missing(self):
        report = valid_inventory()
        report["module_state"]["installed_modules"][1].update({
            "exists": False, "path": None, "bytes": None, "sha256": None,
            "version": None, "srcversion": None, "license": None,
            "vermagic": None, "signer": None,
        })
        result = self.validate(report)
        self.assertFalse(result["module_state"]["installed_modules"][1]["exists"])

    def test_remote_module_probe_is_bounded_and_read_only(self):
        module = self.tool
        compile(module.GUEST_INVENTORY_SCRIPT, "<v100-guest-inventory>", "exec")
        for required in ("/proc/modules", "sig_enforce", "mokutil", "modinfo", "srcversion", "license",
                         "installed_modules", "loaded_nvidia_modules",
                         "loaded_nvidia_module_pre_capture"):
            self.assertIn(required, module.GUEST_INVENTORY_SCRIPT)
        for forbidden in ("modprobe", "insmod", "rmmod", "update-initramfs", "reboot",
                          "systemctl stop", "apt-get install"):
            self.assertIsNone(re.search(r"(?<![A-Za-z0-9_-])" + re.escape(forbidden) +
                                        r"(?![A-Za-z0-9_-])", module.GUEST_INVENTORY_SCRIPT))

    def test_module_metadata_is_queried_from_the_selected_file(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / "nvidia.ko.zst"
            module_path.write_bytes(b"pinned-module-bytes")
            resolved = "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia.ko.zst"
            calls = []

            fake_os = fake_guest_module_os(module_path, resolved)

            def run(args, pass_fds=()):
                calls.append((args, pass_fds))
                if "-n" in args:
                    return str(module_path).encode()
                field = args[args.index("-F") + 1]
                metadata_path = Path(args[-1])
                self.assertTrue(metadata_path.is_symlink())
                descriptor = int(metadata_path.readlink().name)
                self.assertIn(descriptor, pass_fds)
                self.assertEqual(os.pread(descriptor, len(b"pinned-module-bytes"), 0),
                                 b"pinned-module-bytes")
                return {"version": b"580.178.04", "srcversion": b"ABCDEF0123456789",
                        "license": b"NVIDIA", "vermagic": b"6.8.0-147-generic SMP",
                        "signer": b""}[field]

            result = guest_module_file_function(fake_os, run)("nvidia")
            metadata_calls = [call for call in calls if "-F" in call[0]]
            self.assertEqual(len(metadata_calls), 5)
            self.assertTrue(all(call[0][-1].endswith("/nvidia.ko.zst") for call in metadata_calls))
            self.assertTrue(all(len(call[1]) == 1 for call in metadata_calls))
            self.assertEqual(result["sha256"], hashlib.sha256(b"pinned-module-bytes").hexdigest())

    def test_module_capture_rejects_file_replaced_during_metadata_query(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / "nvidia.ko.zst"
            module_path.write_bytes(b"original-module-bytes")
            resolved = "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia.ko.zst"
            changed = False

            fake_os = fake_guest_module_os(module_path, resolved)

            def run(args, pass_fds=()):
                nonlocal changed
                if "-n" in args:
                    return str(module_path).encode()
                if not changed:
                    replacement = module_path.with_suffix(".replacement")
                    replacement.write_bytes(b"replacement-module-bytes")
                    os.replace(replacement, module_path)
                    changed = True
                field = args[args.index("-F") + 1]
                return {"version": b"580.178.04", "srcversion": b"ABCDEF0123456789",
                        "license": b"NVIDIA", "vermagic": b"6.8.0-147-generic SMP",
                        "signer": b""}[field]

            with self.assertRaisesRegex(RuntimeError, "module changed during collection"):
                guest_module_file_function(fake_os, run)("nvidia")

    def test_module_capture_fails_closed_when_required_metadata_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / "nvidia.ko.zst"
            module_path.write_bytes(b"pinned-module-bytes")
            resolved = "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia.ko.zst"
            fake_os = fake_guest_module_os(module_path, resolved)

            def run(args, pass_fds=()):
                if "-n" in args:
                    return str(module_path).encode()
                field = args[args.index("-F") + 1]
                if field == "license":
                    return b""
                return {"version": b"580.178.04", "srcversion": b"ABCDEF0123456789",
                        "vermagic": b"6.8.0-147-generic SMP", "signer": b""}[field]

            with self.assertRaisesRegex(RuntimeError, "required license metadata"):
                guest_module_file_function(fake_os, run)("nvidia")

    def test_module_metadata_command_failure_is_not_converted_to_empty_value(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / "nvidia.ko.zst"
            module_path.write_bytes(b"pinned-module-bytes")
            resolved = "/lib/modules/6.8.0-147-generic/updates/dkms/nvidia.ko.zst"
            fake_os = fake_guest_module_os(module_path, resolved)

            def run(args, pass_fds=()):
                if "-n" in args:
                    return str(module_path).encode()
                raise RuntimeError("modinfo query failed")

            with self.assertRaisesRegex(RuntimeError, "modinfo query failed"):
                guest_module_file_function(fake_os, run)("nvidia")


class DirectPc3PackageTransportTests(unittest.TestCase):
    def test_direct_inventory_uses_only_pc3_and_sudo_n(self):
        tool = load_tool()
        transport = tool.load_transport()
        inventory = {"libraries": [{"path": tool.PINNED_LIBCUDA_PATH,
                                     "bytes": 123, "sha256": "a" * 64}]}
        guest_payload = tool.base64.b64encode(b"{}").decode("ascii")
        envelope = {"schema": "nvidia-hybrid-pc3-v100-package-transport-v1",
                    "guest_ssh_exit_code": 0, "guest_stdout_b64": guest_payload,
                    "guest_stderr_sha256": "b" * 64,
                    "hostkey_fingerprint": tool.GUEST_HOSTKEY_FINGERPRINT}
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(envelope).encode(), stderr=b"")
        with (patch.object(transport, "pc3_direct_ssh_base",
                           return_value=["ssh", "--", "pc3@pc3"]) as direct,
              patch.object(transport, "pc3_ssh_base") as legacy,
              patch.object(transport, "fetch_pc3_sudo_secret") as fetch,
              patch.object(tool, "validate_guest_inventory", return_value=inventory),
              patch.object(tool.subprocess, "run", return_value=completed) as remote):
            report = tool.collect(transport, "pc3@pc3", "pc3", direct_pc3=True)
        self.assertEqual(report["transport_mode"], "pc3-direct-key-sudo-n")
        self.assertTrue(report["read_only_guest_query"])
        self.assertFalse(report["host_or_guest_mutation_performed"])
        direct.assert_called_once_with("pc3@pc3", "pc3")
        legacy.assert_not_called()
        fetch.assert_not_called()
        self.assertEqual(remote.call_args.args[0][:3], ["ssh", "--", "pc3@pc3"])
        self.assertTrue(remote.call_args.args[0][-1].startswith("sudo -n python3 -c "))
        self.assertNotIn("gx10-e526", repr(remote.call_args.args[0]))

    def test_direct_inventory_rejects_non_pc3_target(self):
        tool = load_tool()
        with self.assertRaisesRegex(ValueError, "pinned PC3 SSH route"):
            tool.collect(tool.load_transport(), "pc1@pc1", "pc1", direct_pc3=True)


if __name__ == "__main__":
    unittest.main()
