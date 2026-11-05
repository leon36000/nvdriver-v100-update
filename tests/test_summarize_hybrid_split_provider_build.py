# SPDX-License-Identifier: MIT
"""Mutation tests for the path-free split-provider build receipt."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.summarize_hybrid_split_provider_build import build_summary  # noqa: E402


KERNEL = "7.0.0-38-generic"
MODULES = {
    "frontend": ("nvidia", "frontend", ["hybrid580_legacy", "hybrid580_open"]),
    "legacy": ("hybrid580_legacy", "legacy", []),
    "open": ("hybrid580_open", "open", []),
    "uvm": ("nvidia_uvm", "uvm", ["nvidia"]),
}


def report_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class SplitProviderBuildReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="split-provider-receipt-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        logs = self.root / "logs"
        logs.mkdir()

        def write_log(name, warning_lines):
            path = logs / name
            path.write_text("\n".join(warning_lines) + "\n")
            return str(path), hashlib.sha256(path.read_bytes()).hexdigest()

        legacy_log, _ = write_log("legacy.log", [
            "hybrid580_legacy.o: warning: objtool: fn_a+0x1: frame pointer found",
            "hybrid580_legacy.o: warning: objtool: fn_b+0x1: frame pointer found",
            "hybrid580_legacy.o: warning: objtool: fn_c+0x1: 'naked' return found",
            "hybrid580_legacy.o: warning: objtool: fn_d+0x1: 'naked' return found",
            "hybrid580_legacy.o: warning: objtool: fn_e+0x1: 'naked' return found",
            "warning: fixture legacy provider",
        ])
        open_log, open_log_sha = write_log("open.log", [
            "warning: pahole version differs from the target kernel",
            "hybrid580_open.o: warning: objtool: fn_a+0x1: 'naked' return found",
            "driver.c:4:1: warning: fixture [-Wexpansion-to-defined]",
            "driver.c:5:1: warning: fixture [-Wmissing-prototypes]",
            "warning: fixture open provider",
        ])
        uvm_log, uvm_log_sha = write_log("uvm.log", [
            "warning: pahole version differs from the target kernel",
            "warning: fixture UVM provider",
        ])
        artifacts = {}
        for role, (name, version, depends) in MODULES.items():
            path = self.root / "modules" / (name + ".ko")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("artifact:" + role).encode())
            artifacts[role] = {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
                "name": name,
                "version": version,
                "depends": depends,
                "vermagic": KERNEL + " SMP modversions",
                "license": "NVIDIA" if role == "legacy" else "Dual MIT/GPL",
            }

        symvers = self.root / "modules" / "Module.symvers"
        symvers.write_text("fixture symbols\n")
        symvers_hash = hashlib.sha256(symvers.read_bytes()).hexdigest()
        self.reports = {
            "frontend": {
                "schema": "nvidia-hybrid-gpu-file-frontend-v1",
                "qualification": "compiled-bdf-selected-gpu-file-frontend-kernel-module",
                "kernel_release": KERNEL,
                "module_name": "nvidia",
                "module": {key: artifacts["frontend"][key]
                           for key in ("path", "sha256", "bytes")},
                "loaded_or_installed": False,
                "real_rm_executed": False,
                "gpu_accessed": False,
                "cuda_compatibility_established": False,
                "objtool_active": True,
                "inputs_unchanged": True,
                "unresolved_imports": [],
                "duplicate_import_providers": [],
                "hybrid_uvm_api_contract_failures": [],
                "backend_import_crc_validation": {"verified": True, "mismatches": []},
                "build_warnings": [
                    "warning: pahole version differs from the one used to build the kernel",
                ],
                "public_uvm_consumer_binding": {
                    "enabled": True, "verified": True, "api_count": 79,
                    "matched_count": 79, "missing": [], "mismatches": [],
                },
                "generated_outputs_sha256": {str(symvers): symvers_hash},
            },
            "open": {
                "schema": "replayed-r595-private-open-debugger-bridge-build-v1",
                "qualification": "compiled-replayed-r595-private-open-debugger-provider",
                "kernel_release": KERNEL,
                "source_version": "595.99.02",
                "module_loaded": False,
                "module_installed": False,
                "runtime_or_hardware_validated": False,
                "module": {key: artifacts["open"][key]
                           for key in ("path", "sha256", "bytes", "name", "license")},
                "build": {"log": {"path": open_log, "sha256": open_log_sha}},
            },
            "legacy": {
                "schema": "r58019607-proprietary-port-build-v1",
                "qualification": "compiled-module-with-retained-build-warnings",
                "kernel_release": KERNEL,
                "loaded_or_installed": False,
                "runtime_or_hardware_validated": False,
                "log": legacy_log,
                "build_warnings": {
                    "objtool_frame_pointer": 2,
                    "objtool_naked_return": 3,
                    "other_warning": 1,
                    "total_warning_lines": 6,
                },
                "module": {
                    "path": artifacts["legacy"]["path"],
                    "sha256": artifacts["legacy"]["sha256"],
                    "bytes": artifacts["legacy"]["bytes"],
                    "metadata": {key: artifacts["legacy"][key]
                                 for key in ("name", "version", "depends",
                                             "vermagic", "license")},
                },
            },
            "uvm": {
                "schema": "nvidia-r595-hybrid-uvm-target-build-v1",
                "qualification": "compiled-hybrid-r595-uvm-target-kernel-module-and-public-abi",
                "kernel_release": KERNEL,
                "status": "passed",
                "module_loaded": False,
                "module_installed": False,
                "gpu_accessed": False,
                "cuda_execution_validated": False,
                "source_copy_matches_input": True,
                "module": {
                    "path": artifacts["uvm"]["path"],
                    "sha256": artifacts["uvm"]["sha256"],
                    "bytes": artifacts["uvm"]["bytes"],
                    "identity": {key: artifacts["uvm"][key]
                                 for key in ("name", "version", "depends",
                                             "vermagic", "license")},
                },
                "frontend_public_uvm_binding": {
                    "verified": True,
                    "declared_public_api_count": 79,
                    "direct_public_import_count": 78,
                    "missing_public_imports": ["nvUvmInterfaceDupAddressSpace"],
                    "address_space_dispatch": {
                        "matches": True,
                        "replaces_public_call": "nvUvmInterfaceDupAddressSpace",
                        "symbol": "nvUvmInterfaceDupAddressSpaceWithControlFd",
                    },
                },
                "build": {
                    "argv": ["make", "KBUILD_EXTRA_SYMBOLS=" + str(symvers)],
                    "log_path": uvm_log,
                    "log_sha256": uvm_log_sha,
                },
            },
        }
        self.hashes = {role: report_hash(value)
                       for role, value in self.reports.items()}
        self.reports["bundle"] = {
            "schema": "hybrid-module-bundle-static-audit-v1",
            "qualification": "static-module-bundle-closure",
            "kernel_release": KERNEL,
            "status": "passed",
            "issues": [],
            "module_loaded": False,
            "module_installed": False,
            "runtime_or_hardware_validated": False,
            "reports": {role: {"sha256": self.hashes[role]}
                        for role in ("frontend", "open", "legacy", "uvm")},
            "modules": {
                role: {key: artifacts[role][key] for key in (
                    "path", "sha256", "name", "version", "depends", "vermagic", "license")}
                for role in MODULES
            },
            "symbol_closure": {
                "frontend_imports": {"import_count": 311,
                                     "crc_mismatches": [], "ambiguous_matches": []},
                "provider_imports": {
                    "legacy": {"import_count": 305,
                               "crc_mismatches": [], "ambiguous_matches": []},
                    "open": {"import_count": 461,
                             "crc_mismatches": [], "ambiguous_matches": []},
                },
                "uvm_imports": {"import_count": 331,
                                 "matched_by_provider": {"frontend": 81, "kernel": 250},
                                 "crc_mismatches": [], "ambiguous_matches": []},
                "standard_uvm_interface_closure": {
                    "crc_mismatches": [], "missing_exports": [], "unexpected_exports": [],
                },
            },
        }
        self.hashes["bundle"] = report_hash(self.reports["bundle"])
        self.reports["depmod"] = {
            "schema": "hybrid-module-bundle-depmod-static-v1",
            "qualification": "isolated-dependency-map-only",
            "kernel_release": KERNEL,
            "status": "passed",
            "loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
            "audit_report_sha256": self.hashes["bundle"],
            "modules": {role: {"sha256": artifacts[role]["sha256"]}
                        for role in MODULES},
            "resolution": {
                "nvidia": {
                    "ordered_modules": ["hybrid580_open.ko", "hybrid580_legacy.ko",
                                        "nvidia.ko"],
                    "builtin_modules": [],
                },
                "nvidia_uvm": {
                    "ordered_modules": ["hybrid580_open.ko", "hybrid580_legacy.ko",
                                        "nvidia.ko", "nvidia_uvm.ko"],
                    "builtin_modules": [],
                },
            },
            "soft_dependency_resolution": {
                "owners": {
                    "hybrid580_open": {
                        "pre": ["ecdh_generic", "ecdsa_generic"],
                        "post": [],
                    },
                },
                "support_modules": {"ecdsa_generic": {"sha256": "d" * 64}},
                "resolved_targets": {
                    "ecdh_generic": {
                        "kind": "kernel-builtin",
                        "relative_path": "kernel/crypto/ecdh_generic.ko",
                        "resolved": True,
                    },
                    "ecdsa_generic": {
                        "kind": "loadable-module",
                        "relative_path": "kernel/crypto/ecdsa_generic.ko.zst",
                        "sha256": "d" * 64,
                        "ordered_modules": ["ecdsa_generic.ko.zst"],
                    },
                },
            },
        }
        self.hashes["depmod"] = report_hash(self.reports["depmod"])

    def test_validates_sanitized_four_module_closure_without_local_paths(self):
        summary = build_summary(self.reports, self.hashes, root=self.root)
        serialized = json.dumps(summary, sort_keys=True)
        self.assertNotIn(str(self.root), serialized)
        self.assertEqual(
            summary["schema"], "hybrid-r580-r595-split-provider-build-sanitized-v4")
        self.assertEqual(summary["symbol_closure"]["frontend_imports"], 311)
        self.assertEqual(summary["abi"]["stock_r595_uvm_public_apis_matched"], 79)
        self.assertEqual(summary["modules"]["legacy"]["version"], "legacy")
        self.assertFalse(summary["runtime_or_hardware_validated"])
        self.assertEqual(
            summary["dependency_resolution"]["nvidia"],
            ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"],
        )
        self.assertEqual(
            summary["dependency_resolution"]["nvidia_uvm"],
            ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko", "nvidia_uvm.ko"],
        )
        warnings = summary["build_warning_inventory"]
        self.assertEqual(warnings["reported_total_lines"], 14)
        self.assertEqual(warnings["components"]["legacy_provider"][
            "reported_warning_lines"], 6)
        self.assertEqual(warnings["components"]["open_provider"][
            "reported_warning_lines"], 5)
        self.assertEqual(warnings["components"]["open_provider"][
            "categories"], {
                "compiler:-Wexpansion-to-defined": 1,
                "compiler:-Wmissing-prototypes": 1,
                "objtool_naked_return": 1,
                "pahole_version_mismatch": 1,
                "unclassified": 1,
            })
        self.assertEqual(warnings["components"]["open_provider"][
            "unclassified_warning_lines"], 1)
        self.assertEqual(warnings["components"]["legacy_provider"][
            "categories"]["objtool_naked_return"], 3)
        self.assertEqual(warnings["components"]["legacy_provider"][
            "categories"]["objtool_frame_pointer"], 2)
        self.assertEqual(warnings["components"]["uvm"][
            "unclassified_warning_lines"], 1)
        self.assertEqual(warnings["unclassified_warning_lines"], 3)
        self.assertFalse(warnings["message_classification_complete"])

    def test_normalizes_verified_softdeps_if_kmod_includes_them_in_show_depends(self):
        reports = copy.deepcopy(self.reports)
        reports["depmod"]["resolution"]["nvidia"]["ordered_modules"].insert(
            0, "ecdsa_generic.ko.zst")
        reports["depmod"]["resolution"]["nvidia_uvm"]["ordered_modules"].insert(
            0, "ecdsa_generic.ko.zst")
        hashes = dict(self.hashes)
        hashes["depmod"] = report_hash(reports["depmod"])
        summary = build_summary(reports, hashes, root=self.root)
        self.assertEqual(
            summary["dependency_resolution"]["nvidia"],
            ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"],
        )

    def test_rejects_softdep_target_that_is_not_independently_resolved(self):
        reports = copy.deepcopy(self.reports)
        reports["depmod"]["soft_dependency_resolution"]["resolved_targets"].pop(
            "ecdsa_generic")
        hashes = dict(self.hashes)
        hashes["depmod"] = report_hash(reports["depmod"])
        with self.assertRaisesRegex(ValueError, "loadable softdep resolution"):
            build_summary(reports, hashes, root=self.root)

    def test_rejects_inconsistent_legacy_warning_aggregate(self):
        reports = copy.deepcopy(self.reports)
        reports["legacy"]["build_warnings"]["other_warning"] += 1
        with self.assertRaisesRegex(ValueError, "R580 warning totals"):
            build_summary(reports, self.hashes, root=self.root)

    def test_rejects_legacy_warning_log_count_drift(self):
        path = Path(self.reports["legacy"]["log"])
        path.write_text(path.read_text() + "warning: extra line\n")
        with self.assertRaisesRegex(ValueError, "R580 build log warning count"):
            build_summary(self.reports, self.hashes, root=self.root)

    def test_rejects_open_provider_log_hash_drift(self):
        path = Path(self.reports["open"]["build"]["log"]["path"])
        path.write_text(path.read_text() + "warning: extra line\n")
        with self.assertRaisesRegex(ValueError, "build log hash"):
            build_summary(self.reports, self.hashes, root=self.root)

    def test_rejects_uvm_log_hash_drift(self):
        path = Path(self.reports["uvm"]["build"]["log_path"])
        path.write_text(path.read_text() + "warning: extra line\n")
        with self.assertRaisesRegex(ValueError, "build log hash"):
            build_summary(self.reports, self.hashes, root=self.root)

    def test_rejects_bundle_report_hash_drift(self):
        reports = copy.deepcopy(self.reports)
        reports["bundle"]["reports"]["frontend"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "bundle input report hash"):
            build_summary(reports, self.hashes, root=self.root)

    def test_rejects_unverified_backend_crc(self):
        reports = copy.deepcopy(self.reports)
        reports["frontend"]["backend_import_crc_validation"]["verified"] = False
        with self.assertRaisesRegex(ValueError, "backend import CRCs"):
            build_summary(reports, self.hashes, root=self.root)

    def test_rejects_control_fd_dispatch_mismatch(self):
        reports = copy.deepcopy(self.reports)
        reports["uvm"]["frontend_public_uvm_binding"]["address_space_dispatch"][
            "symbol"] = "nvUvmInterfaceDupAddressSpace"
        with self.assertRaisesRegex(ValueError, "control-fd dispatch CRC"):
            build_summary(reports, self.hashes, root=self.root)

    def test_rejects_module_bytes_changed_after_build(self):
        path = Path(self.reports["open"]["module"]["path"])
        path.write_bytes(b"changed module bytes")
        with self.assertRaisesRegex(ValueError, "module artifact hash differs"):
            build_summary(self.reports, self.hashes, root=self.root)

    def test_rejects_software_report_that_claims_hardware_validation(self):
        reports = copy.deepcopy(self.reports)
        reports["bundle"]["module_loaded"] = True
        with self.assertRaisesRegex(ValueError, "activation boundary"):
            build_summary(reports, self.hashes, root=self.root)

    def test_rejects_dependency_order_drift(self):
        reports = copy.deepcopy(self.reports)
        reports["depmod"]["resolution"]["nvidia"]["ordered_modules"].reverse()
        with self.assertRaisesRegex(ValueError, "kmod dependency order"):
            build_summary(reports, self.hashes, root=self.root)


if __name__ == "__main__":
    unittest.main()
