#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for binding mixed-branch bundles into the read-only PC3 gate."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.audit_pc3_canary_preflight import (  # noqa: E402
    validate_candidate_bundle_evidence,
)


KERNEL = "7.0.0-38-generic"
MODULE_SPEC = {
    "open": ("hybrid580_open", "hybrid580_open.ko", "595.99.02", ""),
    "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko", "580.178.04", ""),
    "frontend": ("nvidia", "nvidia.ko", "", "hybrid580_legacy,hybrid580_open"),
    "uvm": ("nvidia_uvm", "nvidia_uvm.ko", "595.99.02", "nvidia"),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class HybridBundlePreflightEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module_records = {}
        self.modules = {}
        for role, (name, filename, version, depends) in MODULE_SPEC.items():
            path = self.root / filename
            path.write_bytes(f"candidate:{role}".encode())
            module_hash = digest(path)
            dependency_list = [item for item in depends.split(",") if item]
            self.module_records[role] = {
                "name": name,
                "version": version,
                "depends": dependency_list,
                "vermagic": f"{KERNEL} SMP preempt mod_unload modversions",
                "path": str(path),
                "sha256": module_hash,
                "bytes": path.stat().st_size,
            }
            self.modules[role] = {
                "role": role,
                "name": name,
                "version": version,
                "depends": depends,
                "vermagic": f"{KERNEL} SMP preempt mod_unload modversions",
                "path": str(path.resolve()),
                "sha256": module_hash,
                "bytes": path.stat().st_size,
            }
        self.audit_path = self.root / "bundle-audit.json"
        self.audit_path.write_text(json.dumps({
            "schema": "hybrid-module-bundle-static-audit-v1",
            "status": "passed",
            "qualification": "static-module-bundle-closure",
            "runtime_or_hardware_validated": False,
            "modules": self.module_records,
        }))
        self.audit_hash = digest(self.audit_path)
        self.depmod_path = self.root / "depmod-audit.json"
        self.depmod_path.write_text(json.dumps({
            "schema": "hybrid-module-bundle-depmod-static-v1",
            "status": "passed",
            "qualification": "isolated-dependency-map-only",
            "kernel_release": KERNEL,
            "audit_report_sha256": self.audit_hash,
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
            "modules": {
                role: {
                    "name": row["name"],
                    "staged_name": row["filename"],
                    "sha256": self.module_records[role]["sha256"],
                    "size_bytes": self.module_records[role]["bytes"],
                }
                for role, row in {
                    role: {"name": item[0], "filename": item[1]}
                    for role, item in MODULE_SPEC.items()
                }.items()
            },
            "resolution": {
                "nvidia": {"ordered_modules": [
                    "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"]},
                "nvidia_uvm": {"ordered_modules": [
                    "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko",
                    "nvidia_uvm.ko"]},
            },
        }))
        self.depmod_hash = digest(self.depmod_path)

    def validate(self, **overrides):
        args = {
            "audit_report_path": self.audit_path,
            "expected_audit_sha256": self.audit_hash,
            "depmod_report_path": self.depmod_path,
            "expected_depmod_sha256": self.depmod_hash,
            "modules": self.modules,
            "kernel_release": KERNEL,
        }
        args.update(overrides)
        return validate_candidate_bundle_evidence(**args)

    def test_validates_mixed_r595_r580_versions_and_binds_both_reports(self):
        result = self.validate()

        self.assertEqual(result["qualification"], "static-bundle-and-kmod-order-validated")
        self.assertEqual(result["module_count"], 4)
        self.assertEqual(result["versions"]["open"], "595.99.02")
        self.assertEqual(result["versions"]["legacy"], "580.178.04")
        self.assertEqual(result["dependency_order"]["nvidia_uvm"][-1], "nvidia_uvm.ko")
        self.assertEqual(result["audit_report"]["sha256"], self.audit_hash)
        self.assertEqual(result["depmod_report"]["sha256"], self.depmod_hash)

    def test_rejects_report_hash_mismatch_before_accepting_the_bundle(self):
        with self.assertRaisesRegex(ValueError, "bundle audit SHA-256 mismatch"):
            self.validate(expected_audit_sha256="0" * 64)

    def test_rejects_dependency_report_bound_to_a_different_audit(self):
        depmod = json.loads(self.depmod_path.read_text())
        depmod["audit_report_sha256"] = "f" * 64
        self.depmod_path.write_text(json.dumps(depmod))
        self.depmod_hash = digest(self.depmod_path)

        with self.assertRaisesRegex(ValueError, "does not bind the exact bundle audit"):
            self.validate()

    def test_rejects_candidate_module_hash_or_path_drift(self):
        self.modules["uvm"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "differ from the bundle audit"):
            self.validate()

    def test_rejects_kmod_order_drift_and_runtime_claims(self):
        depmod = json.loads(self.depmod_path.read_text())
        depmod["resolution"]["nvidia_uvm"]["ordered_modules"] = ["nvidia_uvm.ko"]
        self.depmod_path.write_text(json.dumps(depmod))
        self.depmod_hash = digest(self.depmod_path)
        with self.assertRaisesRegex(ValueError, "dependency resolution order"):
            self.validate()

        depmod["resolution"]["nvidia_uvm"]["ordered_modules"] = [
            "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko", "nvidia_uvm.ko"]
        depmod["runtime_or_hardware_validated"] = True
        self.depmod_path.write_text(json.dumps(depmod))
        self.depmod_hash = digest(self.depmod_path)
        with self.assertRaisesRegex(ValueError, "runtime or installation claim"):
            self.validate()


if __name__ == "__main__":
    unittest.main(verbosity=2)
