# SPDX-License-Identifier: MIT
"""Contracts for the path-free isolated kmod resolution receipt."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.summarize_hybrid_bundle_depmod import build_receipt  # noqa: E402


KERNEL = "7.0.0-38-generic"
STAGE = "/tmp/hybrid-bundle-depmod-fixture"
AUDIT_HASH = "a" * 64
MODULE_HASHES = {
    "frontend": "1" * 64,
    "legacy": "2" * 64,
    "open": "3" * 64,
    "uvm": "4" * 64,
}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def output_for(names):
    rows = []
    for name in names:
        if name == "ecdsa_generic.ko.zst":
            rel = "kernel/crypto/ecdsa_generic.ko.zst"
        else:
            rel = "updates/extra/" + name
        rows.append(f"insmod {STAGE}/lib/modules/{KERNEL}/{rel} ")
    return "\n".join(rows) + "\n"


def module_record(name, filename, sha256, size):
    return {"name": name, "staged_name": filename,
            "sha256": sha256, "size_bytes": size}


def raw_report(include_softdep=False, include_builtin=False):
    hard = ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"]
    nvidia = (["ecdsa_generic.ko.zst"] + hard) if include_softdep else hard
    uvm = nvidia + ["nvidia_uvm.ko"]
    builtin_modules = ["ecdh_generic"] if include_builtin else []

    def show_output(names):
        prefix = "builtin ecdh_generic\n" if include_builtin else ""
        return prefix + output_for(names)
    modules_dep = (
        "updates/extra/hybrid580_open.ko:\n"
        "updates/extra/hybrid580_legacy.ko:\n"
        "updates/extra/nvidia.ko: updates/extra/hybrid580_legacy.ko "
        "updates/extra/hybrid580_open.ko\n"
        "updates/extra/nvidia_uvm.ko: updates/extra/nvidia.ko "
        "updates/extra/hybrid580_legacy.ko updates/extra/hybrid580_open.ko\n"
        "kernel/crypto/ecdsa_generic.ko.zst:\n"
    )
    modules_softdep = (
        "# Soft dependencies extracted from modules themselves.\n"
        "softdep hybrid580_open pre: ecdh_generic,ecdsa_generic\n"
    )
    ecdsa_hash = "e" * 64
    return {
        "schema": "hybrid-module-bundle-depmod-static-v1",
        "status": "passed",
        "qualification": "isolated-dependency-map-only",
        "kernel_release": KERNEL,
        "stage_root": STAGE,
        "audit_report_status": "passed",
        "audit_report_sha256": AUDIT_HASH,
        "loaded_or_installed": False,
        "runtime_or_hardware_validated": False,
        "modules": {
            "frontend": module_record("nvidia", "nvidia.ko", MODULE_HASHES["frontend"], 100),
            "legacy": module_record("hybrid580_legacy", "hybrid580_legacy.ko",
                                     MODULE_HASHES["legacy"], 200),
            "open": module_record("hybrid580_open", "hybrid580_open.ko",
                                  MODULE_HASHES["open"], 300),
            "uvm": module_record("nvidia_uvm", "nvidia_uvm.ko",
                                 MODULE_HASHES["uvm"], 400),
        },
        "depmod": {
            "command": ["depmod", "-b", STAGE, KERNEL],
            "exit_code": 0,
            "modules_dep": modules_dep,
            "modules_dep_sha256": digest(modules_dep),
            "modules_softdep": modules_softdep,
            "modules_softdep_sha256": digest(modules_softdep),
            "stdout": "",
            "stderr": "",
        },
        "resolution": {
            "nvidia": {
                "command": ["modprobe", "-C", "/dev/null", "-d", STAGE,
                            "--set-version", KERNEL, "--show-depends", "nvidia"],
                "ordered_modules": nvidia,
                "builtin_modules": builtin_modules,
                "stdout": show_output(nvidia),
                "stderr": "",
            },
            "nvidia_uvm": {
                "command": ["modprobe", "-C", "/dev/null", "-d", STAGE,
                            "--set-version", KERNEL, "--show-depends", "nvidia_uvm"],
                "ordered_modules": uvm,
                "builtin_modules": builtin_modules,
                "stdout": show_output(uvm),
                "stderr": "",
            },
        },
        "soft_dependency_resolution": {
            "owners": {"hybrid580_open": {
                "pre": ["ecdh_generic", "ecdsa_generic"], "post": []}},
            "expected_modules_softdep_lines": {
                "hybrid580_open":
                    "softdep hybrid580_open pre: ecdh_generic,ecdsa_generic"},
            "builtins": {"ecdh_generic": "kernel/crypto/ecdh_generic.ko"},
            "support_modules": {"ecdsa_generic": {
                "relative_path": "kernel/crypto/ecdsa_generic.ko.zst",
                "sha256": ecdsa_hash, "size_bytes": 7}},
            "resolved_targets": {
                "ecdh_generic": {
                    "kind": "kernel-builtin", "relative_path":
                        "kernel/crypto/ecdh_generic.ko", "resolved": True},
                "ecdsa_generic": {
                    "kind": "loadable-module", "relative_path":
                        "kernel/crypto/ecdsa_generic.ko.zst",
                    "sha256": ecdsa_hash,
                    "command": ["modprobe", "-C", "/dev/null", "-d", STAGE,
                                "--set-version", KERNEL, "--show-depends",
                                "ecdsa_generic"],
                    "ordered_modules": ["ecdsa_generic.ko.zst"],
                    "stdout": output_for(["ecdsa_generic.ko.zst"]),
                    "stderr": "",
                },
            },
        },
    }


class HybridBundleDepmodReceiptTests(unittest.TestCase):
    def test_cli_entrypoint_loads_and_documents_its_options(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/summarize_hybrid_bundle_depmod.py"),
             "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--expected-raw-report-sha256", result.stdout)

    def test_builds_path_free_receipt_for_observed_hard_graph_and_softdeps(self):
        report = raw_report()
        receipt = build_receipt(report, "f" * 64, AUDIT_HASH)
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertNotIn(STAGE, serialized)
        self.assertEqual(receipt["schema"],
                         "hybrid-module-bundle-depmod-sanitized-v1")
        self.assertEqual(set(receipt["implementation_sha256"]), {
            "tools/verify_hybrid_bundle_depmod.py",
            "tools/summarize_hybrid_bundle_depmod.py",
        })
        self.assertTrue(all(len(value) == 64
                            for value in receipt["implementation_sha256"].values()))
        self.assertEqual(receipt["dependency_resolution"]["nvidia"],
                         ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"])
        self.assertEqual(
            receipt["dependency_resolution"]["verified_pre_softdeps"]["kernel_builtin"],
            ["ecdh_generic"],
        )
        self.assertEqual(
            receipt["dependency_resolution"]["show_depends_included_verified_pre_softdep"],
            {"nvidia": False, "nvidia_uvm": False},
        )
        self.assertFalse(receipt["runtime_or_hardware_validated"])

    def test_accepts_hash_verified_pre_softdep_when_kmod_prints_it(self):
        receipt = build_receipt(
            raw_report(include_softdep=True, include_builtin=True),
            "f" * 64, AUDIT_HASH)
        self.assertEqual(
            receipt["dependency_resolution"]["show_depends_included_verified_pre_softdep"],
            {"nvidia": True, "nvidia_uvm": True},
        )

    def test_accepts_independently_verified_kernel_builtin_output(self):
        receipt = build_receipt(raw_report(include_builtin=True), "f" * 64, AUDIT_HASH)
        self.assertEqual(
            receipt["dependency_resolution"]["verified_pre_softdeps"]["kernel_builtin"],
            ["ecdh_generic"],
        )

    def test_rejects_kernel_builtin_output_missing_from_parsed_record(self):
        report = raw_report()
        report["resolution"]["nvidia"]["stdout"] = (
            "builtin ecdh_generic\n" + report["resolution"]["nvidia"]["stdout"])
        with self.assertRaisesRegex(ValueError, "builtin output mismatch"):
            build_receipt(report, "f" * 64, AUDIT_HASH)

    def test_rejects_unrecognized_kernel_builtin_output(self):
        report = raw_report(include_builtin=True)
        report["resolution"]["nvidia"]["stdout"] = report["resolution"]["nvidia"][
            "stdout"].replace("builtin ecdh_generic", "builtin unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected kmod output"):
            build_receipt(report, "f" * 64, AUDIT_HASH)

    def test_accepts_whitespace_formatted_depmod_softdep_list(self):
        report = raw_report()
        text = report["depmod"]["modules_softdep"].replace(
            "ecdh_generic,ecdsa_generic", "ecdh_generic ecdsa_generic")
        report["depmod"]["modules_softdep"] = text
        report["depmod"]["modules_softdep_sha256"] = digest(text)
        receipt = build_receipt(report, "f" * 64, AUDIT_HASH)
        self.assertEqual(
            receipt["dependency_resolution"]["verified_pre_softdeps"]["loadable_module"][0]["name"],
            "ecdsa_generic",
        )

    def test_rejects_audit_hash_mismatch(self):
        with self.assertRaisesRegex(ValueError, "static audit binding"):
            build_receipt(raw_report(), "f" * 64, "0" * 64)

    def test_rejects_loaded_or_runtime_claims(self):
        report = raw_report()
        report["loaded_or_installed"] = True
        with self.assertRaisesRegex(ValueError, "no-load qualification"):
            build_receipt(report, "f" * 64, AUDIT_HASH)

    def test_rejects_module_output_outside_private_stage(self):
        report = raw_report()
        report["resolution"]["nvidia"]["stdout"] = output_for([
            "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"]
        ).replace(STAGE, "/tmp/other-stage")
        with self.assertRaisesRegex(ValueError, "escapes isolated stage"):
            build_receipt(report, "f" * 64, AUDIT_HASH)

    def test_rejects_unverified_kmod_module(self):
        report = raw_report()
        report["resolution"]["nvidia"]["ordered_modules"].insert(0, "other.ko")
        with self.assertRaisesRegex(ValueError, "dependency order"):
            build_receipt(report, "f" * 64, AUDIT_HASH)

    def test_rejects_softdep_without_independent_query(self):
        report = raw_report()
        report["soft_dependency_resolution"]["resolved_targets"].pop("ecdsa_generic")
        with self.assertRaisesRegex(ValueError, "loadable softdep resolution"):
            build_receipt(report, "f" * 64, AUDIT_HASH)

    def test_rejects_modified_depmod_graph_even_with_updated_digest(self):
        report = raw_report()
        report["depmod"]["modules_dep"] += "updates/extra/other.ko:\n"
        report["depmod"]["modules_dep_sha256"] = digest(report["depmod"]["modules_dep"])
        with self.assertRaisesRegex(ValueError, "modules.dep dependency graph"):
            build_receipt(report, "f" * 64, AUDIT_HASH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
