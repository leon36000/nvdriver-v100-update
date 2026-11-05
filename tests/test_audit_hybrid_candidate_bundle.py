#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for static hybrid frontend/provider/UVM bundle auditing."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tools.audit_hybrid_candidate_bundle as AUDITOR  # noqa: E402
from tools.audit_hybrid_candidate_bundle import (  # noqa: E402
    _normalize_uvm_report,
    _normalize_open_report,
    _legacy_report_vermagic,
    _frontend_provider_symvers_equivalent,
    _report_name,
    _provider_symvers_reference,
    _require_frontend_generated_symvers,
    _require_not_loaded,
    audit_export_closure,
    audit_import_closure,
    audit_standard_uvm_api,
    implementation_sha256,
    parse_modinfo_parameters,
    uvm_hybrid_isolation_parameter_issue,
    validate_module_topology,
)


class HybridCandidateBundleAuditTests(unittest.TestCase):
    @staticmethod
    def _r595_uvm_receipt():
        crc = "0x12345678"
        checks = {
            f"nvUvmInterfaceSynthetic{index}": {
                "matches": True,
                "consumer_import_crc": crc,
                "frontend_export_crc": crc,
            }
            for index in range(78)
        }
        return {
            "schema": "nvidia-r595-hybrid-uvm-target-build-v1",
            "status": "passed",
            "qualification": (
                "compiled-hybrid-r595-uvm-target-kernel-module-and-public-abi"
            ),
            "kernel_release": "7.0.0-38-generic",
            "source_copy_matches_input": True,
            "module_loaded": False,
            "module_installed": False,
            "gpu_accessed": False,
            "cuda_execution_validated": False,
            "module": {
                "path": "/tmp/nvidia-uvm.ko",
                "sha256": "a" * 64,
                "identity": {
                    "name": "nvidia_uvm", "depends": "nvidia",
                },
            },
            "inputs_sha256": {"frontend_module_symvers": "b" * 64},
            "build": {
                "exit_code": 0,
                "argv": [
                    "make", "KBUILD_EXTRA_SYMBOLS=/tmp/frontend/Module.symvers",
                ],
            },
            "frontend_public_uvm_binding": {
                "verified": True,
                "declared_public_api_count": 79,
                "direct_public_import_count": 78,
                "missing_public_imports": ["nvUvmInterfaceDupAddressSpace"],
                "unexpected_public_imports": [],
                "direct_binding": {"api_count": 78, "checks": checks},
                "address_space_dispatch": {
                    "matches": True,
                    "symbol": "nvUvmInterfaceDupAddressSpaceWithControlFd",
                    "replaces_public_call": "nvUvmInterfaceDupAddressSpace",
                    "frontend_owner": "nvidia",
                    "frontend_export": "EXPORT_SYMBOL",
                    "consumer_crc": crc,
                    "frontend_crc": crc,
                },
            },
        }

    def test_legacy_metadata_accepts_old_and_r580_196_report_shapes(self):
        old_report = {
            "module_metadata": {
                "name": ["hybrid580_legacy"],
                "vermagic": ["7.0.0-38-generic SMP preempt modversions"],
            },
        }
        new_report = {
            "module": {"metadata": {
                "name": "hybrid580_legacy",
                "vermagic": "7.0.0-38-generic SMP preempt modversions",
            }},
        }

        self.assertEqual(_legacy_report_vermagic(old_report),
                         "7.0.0-38-generic SMP preempt modversions")
        self.assertEqual(_legacy_report_vermagic(new_report),
                         "7.0.0-38-generic SMP preempt modversions")
        self.assertEqual(_report_name(new_report, "legacy"), "hybrid580_legacy")

    def test_legacy_metadata_rejects_missing_or_empty_vermagic(self):
        for report in ({}, {"module_metadata": {"vermagic": [""]}},
                       {"module": {"metadata": {"vermagic": 17}}}):
            with self.subTest(report=report):
                self.assertEqual(_legacy_report_vermagic(report), "")

    def test_require_not_loaded_accepts_explicit_combined_status(self):
        _require_not_loaded(
            {"loaded_or_installed": False},
            ("module_loaded", "module_installed"),
            "R580 Open backend",
        )

    def test_require_not_loaded_rejects_missing_or_true_combined_status(self):
        for report in (
            {},
            {"loaded_or_installed": True},
            {"module_loaded": True, "loaded_or_installed": False},
        ):
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, "does not prove"):
                    _require_not_loaded(
                        report,
                        ("module_loaded", "module_installed"),
                        "R580 Open backend",
                    )

    @staticmethod
    def _r595112_source_core_open_report():
        return {
            "schema": "nvidia-hybrid.r595112-open-provider-source-core-build.v1",
            "status": "BUILD_PASS",
            "qualification": {
                "compiled": True,
                "cuda_runtime_validated": False,
                "hardware_tested": False,
                "installed_or_loaded": False,
            },
            "build": {
                "commands_exit_codes": [0, 0],
                "error_lines": 0,
                "kernel_release": "7.0.0-38-generic",
                "module_path": "build/experiments/open/hybrid580_open.ko",
                "module_sha256": "a" * 64,
                "module_selection": ["nvidia"],
            },
        }

    def test_normalize_r595112_source_core_open_report_requires_compile_only_proof(self):
        normalized = _normalize_open_report(self._r595112_source_core_open_report())
        self.assertEqual(normalized["kernel_release"], "7.0.0-38-generic")
        self.assertFalse(normalized["module_loaded"])
        self.assertFalse(normalized["module_installed"])
        self.assertEqual(normalized["module"]["name"], "hybrid580_open")
        self.assertEqual(normalized["module"]["sha256"], "a" * 64)

        invalid_reports = []
        report = self._r595112_source_core_open_report()
        report["qualification"]["installed_or_loaded"] = True
        invalid_reports.append(report)
        report = self._r595112_source_core_open_report()
        report["qualification"]["hardware_tested"] = True
        invalid_reports.append(report)
        report = self._r595112_source_core_open_report()
        report["build"]["commands_exit_codes"] = [0, 1]
        invalid_reports.append(report)
        for report in invalid_reports:
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, "compile-only"):
                    _normalize_open_report(report)

    def test_source_core_open_symvers_must_match_pinned_frontend_input(self):
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "source" / "hybrid580_open.ko"
            module.parent.mkdir()
            module.write_bytes(b"module")
            symvers = module.parent / "Module.symvers"
            symvers.write_text("0x00112233 alpha hybrid580_open EXPORT_SYMBOL\n")
            digest = hashlib.sha256(symvers.read_bytes()).hexdigest()
            report = self._r595112_source_core_open_report()
            path, actual_digest = _provider_symvers_reference(
                report, "open", module,
                {"inputs_sha256": {str(symvers): digest}},
            )
            self.assertEqual(path, symvers)
            self.assertEqual(actual_digest, digest)

            with self.assertRaisesRegex(ValueError, "does not pin Module.symvers"):
                _provider_symvers_reference(
                    report, "open", module, {"inputs_sha256": {}})

    def test_normalize_r580_uvm_build_requires_exact_frontend_binding(self):
        frontend_sha = "b" * 64
        report = {
            "schema": "r580-uvm-isolated-gpu-execution-build-v5",
            "build": {
                "exit_code": 0,
                "kernel_release": "7.0.0-38-generic",
                "modules": {"nvidia-uvm.ko": {
                    "path": "/tmp/nvidia-uvm.ko", "sha256": "a" * 64,
                }},
                "module_identity": {
                    "actual_module_name": "nvidia_uvm",
                    "expected_module_name": "nvidia_uvm",
                    "module_name_matches": True,
                },
                "frontend_consumer_binding": {
                    "passed": True,
                    "frontend_is_only_provider_dependency": True,
                    "frontend_module_name": "nvidia",
                    "module_dependencies": ["nvidia"],
                    "matching_frontend_crc_count": 77,
                    "uvm_interface_import_count": 77,
                    "mismatched_symbols": {},
                    "symvers_unchanged_after_build": True,
                },
                "frontend_symvers_unchanged_after_build": True,
            },
            "inputs": {
                "frontend_module_name": "nvidia",
                "frontend_module_symvers": {
                    "path": "/tmp/Module.symvers", "sha256": frontend_sha,
                },
                "expected_frontend_module_symvers_sha256": frontend_sha,
            },
            "qualification": {
                "level": "compiled-frontend-bound-uvm",
                "module_loaded_or_installed": False,
                "runtime_or_hardware_validated": False,
            },
        }

        normalized = _normalize_uvm_report(report)

        self.assertEqual(normalized["candidate_module"], {
            "path": "/tmp/nvidia-uvm.ko", "sha256": "a" * 64,
            "name": "nvidia_uvm", "linked_this_run": True,
        })
        self.assertEqual(normalized["build"]["frontend_module_symvers"], {
            "path": "/tmp/Module.symvers", "expected_sha256": frontend_sha,
            "sha256_before": frontend_sha, "sha256_after": frontend_sha,
            "unchanged": True,
        })

        report["build"]["frontend_consumer_binding"]["matching_frontend_crc_count"] = 76
        with self.assertRaisesRegex(ValueError, "frontend UVM binding"):
            _normalize_uvm_report(report)
        report["build"]["frontend_consumer_binding"]["matching_frontend_crc_count"] = None
        report["build"]["frontend_consumer_binding"]["uvm_interface_import_count"] = None
        with self.assertRaisesRegex(ValueError, "frontend UVM binding"):
            _normalize_uvm_report(report)

    def test_normalize_r595_uvm_receipt_accepts_verified_control_fd_dispatch(self):
        normalized = _normalize_uvm_report(self._r595_uvm_receipt())

        self.assertEqual(normalized["candidate_module"], {
            "path": "/tmp/nvidia-uvm.ko", "sha256": "a" * 64,
            "name": "nvidia_uvm", "linked_this_run": True,
        })
        self.assertEqual(normalized["build"]["frontend_module_symvers"], {
            "path": "/tmp/frontend/Module.symvers",
            "expected_sha256": "b" * 64,
            "sha256_before": "b" * 64, "sha256_after": "b" * 64,
            "unchanged": True,
        })

    def test_normalize_r595_uvm_receipt_rejects_binding_or_safety_drift(self):
        invalid_receipts = []
        receipt = self._r595_uvm_receipt()
        receipt["frontend_public_uvm_binding"]["address_space_dispatch"][
            "frontend_crc"] = "0x87654321"
        invalid_receipts.append(receipt)

        receipt = self._r595_uvm_receipt()
        receipt["frontend_public_uvm_binding"]["missing_public_imports"] = []
        invalid_receipts.append(receipt)

        receipt = self._r595_uvm_receipt()
        receipt["module_installed"] = True
        invalid_receipts.append(receipt)

        receipt = self._r595_uvm_receipt()
        receipt["frontend_public_uvm_binding"]["direct_binding"][
            "checks"]["nvUvmInterfaceSynthetic0"]["matches"] = False
        invalid_receipts.append(receipt)

        for receipt in invalid_receipts:
            with self.subTest(receipt=receipt):
                with self.assertRaisesRegex(ValueError, "compile-only"):
                    _normalize_uvm_report(receipt)

    def test_provider_symvers_reference_uses_report_or_pinned_frontend_input(self):
        with tempfile.TemporaryDirectory() as directory:
            module_path = Path(directory) / "hybrid580_open.ko"
            module_path.write_bytes(b"module")
            symvers_path = Path(directory) / "Module.symvers"
            symvers_path.write_text("crc symbol module export\n")
            frontend_report = {
                "inputs_sha256": {
                    str(symvers_path): "d" * 64,
                },
            }

            path, digest = _provider_symvers_reference(
                {"inputs_unchanged": True}, "open", module_path, frontend_report)

            self.assertEqual(path, symvers_path)
            self.assertEqual(digest, "d" * 64)
            with self.assertRaisesRegex(ValueError, "unchanged"):
                _provider_symvers_reference(
                    {}, "open", module_path, frontend_report)

            legacy = {
                "compatibility_with_v2": {
                    "symvers": str(symvers_path), "symvers_sha256": "e" * 64,
                },
            }
            legacy_path, legacy_digest = _provider_symvers_reference(
                legacy, "legacy", module_path, frontend_report)
            self.assertEqual(legacy_path, symvers_path)
            self.assertEqual(legacy_digest, "e" * 64)

            legacy["compatibility_with_v2"]["symvers_sha256"] = None
            with self.assertRaisesRegex(ValueError, "legacy provider report"):
                _provider_symvers_reference(legacy, "legacy", module_path,
                                            frontend_report)

    def test_frontend_generated_symvers_matches_consumer_by_content_hash(self):
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frontend_symvers = root / "frontend" / "Module.symvers"
            consumer_symvers = root / "consumer" / "Module.symvers"
            frontend_symvers.parent.mkdir()
            consumer_symvers.parent.mkdir()
            content = "0x12345678 symbol nvidia EXPORT_SYMBOL\n"
            frontend_symvers.write_text(content)
            consumer_symvers.write_text(content)
            digest = hashlib.sha256(content.encode()).hexdigest()
            frontend_report = {
                "generated_outputs_sha256": {str(frontend_symvers): digest},
            }

            path, actual = _require_frontend_generated_symvers(
                frontend_report, hashlib.sha256(consumer_symvers.read_bytes()).hexdigest())
            self.assertEqual(Path(path), frontend_symvers.resolve())
            self.assertEqual(actual, digest)
            with self.assertRaisesRegex(ValueError, "differs from consumer"):
                _require_frontend_generated_symvers(frontend_report, "f" * 64)

    def test_legacy_symvers_without_report_digest_must_match_pinned_frontend_abi(self):
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provider = root / "rebuilt" / "hybrid580_legacy.ko"
            provider.parent.mkdir()
            provider.write_bytes(b"module")
            rebuilt_symvers = provider.parent / "Module.symvers"
            rebuilt_symvers.write_text(
                "0x00112233 legacy_export /tmp/rebuilt/hybrid580_legacy EXPORT_SYMBOL\n"
            )
            pinned_symvers = root / "frontend-input" / "Module.symvers"
            pinned_symvers.parent.mkdir()
            pinned_symvers.write_text(
                "0x00112233 legacy_export /tmp/frontend/hybrid580_legacy EXPORT_SYMBOL\n"
            )
            digest = hashlib.sha256(pinned_symvers.read_bytes()).hexdigest()
            frontend_report = {"inputs_sha256": {str(pinned_symvers): digest}}

            path, actual_digest = _provider_symvers_reference(
                {}, "legacy", provider, frontend_report)

            self.assertEqual(path, pinned_symvers)
            self.assertEqual(actual_digest, digest)
            rebuilt_symvers.write_text(
                "0x00112234 legacy_export /tmp/rebuilt/hybrid580_legacy EXPORT_SYMBOL\n"
            )
            with self.assertRaisesRegex(ValueError, "exactly one pinned Module.symvers"):
                _provider_symvers_reference({}, "legacy", provider, frontend_report)

    def test_frontend_provider_symvers_accepts_only_semantically_identical_export_abi(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frontend_input = root / "frontend-build" / "Module.symvers"
            rebuilt_provider = root / "full-replay" / "Module.symvers"
            frontend_input.parent.mkdir()
            rebuilt_provider.parent.mkdir()
            frontend_input.write_text(
                "0x00112233 alpha /tmp/old-build/hybrid580_open EXPORT_SYMBOL\n"
                "0x44556677 beta /tmp/old-build/hybrid580_open EXPORT_SYMBOL_GPL\n"
            )
            rebuilt_provider.write_text(
                "0x44556677 beta /tmp/new-build/hybrid580_open EXPORT_SYMBOL_GPL\n"
                "0x00112233 alpha /tmp/new-build/hybrid580_open EXPORT_SYMBOL\n"
            )
            import hashlib
            frontend_hash = hashlib.sha256(frontend_input.read_bytes()).hexdigest()
            binding = _frontend_provider_symvers_equivalent(
                {"inputs_sha256": {str(frontend_input): frontend_hash}},
                rebuilt_provider,
                "hybrid580_open",
            )
            self.assertEqual(binding["path"], str(frontend_input.resolve()))
            self.assertEqual(binding["sha256"], frontend_hash)
            self.assertEqual(binding["export_count"], 2)
            self.assertEqual(len(binding["semantic_abi_sha256"]), 64)

            rebuilt_provider.write_text(
                "0x00112234 alpha /tmp/new-build/hybrid580_open EXPORT_SYMBOL\n"
                "0x44556677 beta /tmp/new-build/hybrid580_open EXPORT_SYMBOL_GPL\n"
            )
            with self.assertRaisesRegex(ValueError, "exactly one pinned Module.symvers"):
                _frontend_provider_symvers_equivalent(
                    {"inputs_sha256": {str(frontend_input): frontend_hash}},
                    rebuilt_provider,
                    "hybrid580_open",
                )

    def test_frontend_provider_symvers_rejects_mutated_recorded_input(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "Module.symvers"
            input_path.write_text(
                "0x00112233 alpha /tmp/old-build/hybrid580_open EXPORT_SYMBOL\n"
            )
            provider = Path(directory) / "provider.symvers"
            provider.write_text(
                "0x00112233 alpha /tmp/new-build/hybrid580_open EXPORT_SYMBOL\n"
            )
            with self.assertRaisesRegex(ValueError, "input hash changed"):
                _frontend_provider_symvers_equivalent(
                    {"inputs_sha256": {str(input_path): "0" * 64}},
                    provider,
                    "hybrid580_open",
                )

    def test_audit_evidence_pins_its_implementation_chain(self):
        hashes = implementation_sha256()

        self.assertEqual(set(hashes), {
            "tools/audit_hybrid_candidate_bundle.py",
            "tools/audit_r595_uvm_symbol_closure.py",
            "tools/build_hybrid_frontend.py",
            "tools/probe_r595_gv100_complete_hal.py",
            "tools/probe_volta_uvm_port.py",
        })
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_modinfo_parameter_parser_requires_exact_bool_isolation_contract(self):
        output = (
            "uvm_hybrid_isolated_gpu_execution:Reject cross-provider UVM "
            "dependencies in hybrid mode (bool)\n"
            "uvm_debug_prints:Enable UVM debug output (bool)\n"
        )
        parameters = parse_modinfo_parameters(output)
        self.assertEqual(parameters["uvm_hybrid_isolated_gpu_execution"]["type"], "bool")
        self.assertNotIn("uvm_hybrid_isolated_gpu_execution_extra", parameters)
        self.assertNotIn(
            "uvm_hybrid_isolated_gpu_execution",
            parse_modinfo_parameters("uvm_other_option: unrelated option (bool)\n"),
        )

    def test_modinfo_parameter_parser_rejects_duplicate_names(self):
        with self.assertRaisesRegex(ValueError, "duplicate module parameter"):
            parse_modinfo_parameters(
                "uvm_hybrid_isolated_gpu_execution:first (bool)\n"
                "uvm_hybrid_isolated_gpu_execution:second (bool)\n")

    def test_bundle_requires_hybrid_isolation_parameter_as_bool(self):
        issue = uvm_hybrid_isolation_parameter_issue({})
        self.assertEqual(issue["check"], "uvm-hybrid-isolation-parameter")
        self.assertIsNone(uvm_hybrid_isolation_parameter_issue({
            "uvm_hybrid_isolated_gpu_execution": {
                "description": "Reject cross-provider UVM dependencies (bool)",
                "type": "bool",
            },
        }))
        self.assertIsNotNone(uvm_hybrid_isolation_parameter_issue({
            "uvm_hybrid_isolated_gpu_execution": {
                "description": "wrong type",
                "type": "uint",
            },
        }))

    def test_import_crc_closure_counts_unique_provider_matches(self):
        providers = {
            "kernel": {
                "memcpy": {"crc": "0x00000001", "module": "vmlinux"},
            },
            "frontend": {
                "nvUvmInterfaceAlloc": {"crc": "0x00000002", "module": "nvidia"},
            },
        }

        result = audit_import_closure(
            {"memcpy": "0x00000001", "nvUvmInterfaceAlloc": "0x00000002"},
            providers,
        )

        self.assertEqual(result["import_count"], 2)
        self.assertEqual(result["matched_by_provider"], {"frontend": 1, "kernel": 1})
        self.assertEqual(result["crc_mismatches"], [])
        self.assertEqual(result["ambiguous_matches"], [])

    def test_import_crc_closure_rejects_missing_and_mismatched_exports(self):
        result = audit_import_closure(
            {"missing_symbol": "0x00000010", "wrong_crc": "0x00000020"},
            {
                "kernel": {
                    "wrong_crc": {"crc": "0x00000021", "module": "vmlinux"},
                },
            },
        )

        self.assertEqual(result["matched_by_provider"], {})
        self.assertEqual(
            [entry["symbol"] for entry in result["crc_mismatches"]],
            ["missing_symbol", "wrong_crc"],
        )

    def test_import_crc_closure_rejects_duplicate_matching_providers(self):
        result = audit_import_closure(
            {"shared": "0x00000030"},
            {
                "kernel": {"shared": {"crc": "0x00000030", "module": "vmlinux"}},
                "backend": {"shared": {"crc": "0x00000030", "module": "backend"}},
            },
        )

        self.assertEqual(result["crc_mismatches"], [])
        self.assertEqual(result["ambiguous_matches"], [{
            "symbol": "shared", "providers": ["backend", "kernel"],
        }])

    def test_r580_backend_imports_must_close_against_kernel_symvers(self):
        self.assertTrue(hasattr(AUDITOR, "audit_provider_import_closures"),
                        "backend kernel-import closure is missing")
        kernel = {
            "kernel_api": {"crc": "0x00000070", "module": "vmlinux"},
        }
        result = AUDITOR.audit_provider_import_closures(
            {"kernel_api": "0x00000070"},
            {"missing_api": "0x00000071"},
            kernel,
        )
        self.assertEqual(result["open"]["crc_mismatches"], [])
        self.assertEqual(result["legacy"]["crc_mismatches"], [{
            "symbol": "missing_api", "import_crc": "0x00000071",
            "candidate_exports": [],
        }])

    def test_export_crc_audit_checks_module_owner_and_full_symbol_set(self):
        result = audit_export_closure(
            {"owned": "0x00000040", "extra": "0x00000041"},
            {
                "owned": {"crc": "0x00000040", "module": "nvidia"},
                "missing": {"crc": "0x00000042", "module": "nvidia"},
                "other_owner": {"crc": "0x00000041", "module": "backend"},
            },
            "nvidia",
        )

        self.assertEqual(result["actual_export_count"], 2)
        self.assertEqual(result["expected_export_count"], 2)
        self.assertEqual(result["missing_exports"], ["missing"])
        self.assertEqual(result["unexpected_exports"], ["extra"])
        self.assertEqual(result["crc_mismatches"], [])

    def test_export_crc_audit_accepts_path_qualified_symvers_owner(self):
        result = audit_export_closure(
            {"frontend_api": "0x00000040"},
            {
                "frontend_api": {
                    "crc": "0x00000040",
                    "module": "/tmp/build/pc3/nvidia",
                },
                "different_module": {
                    "crc": "0x00000041",
                    "module": "/tmp/build/pc3/nvidia_uvm",
                },
            },
            "nvidia",
        )

        self.assertEqual(result["expected_export_count"], 1)
        self.assertEqual(result["missing_exports"], [])
        self.assertEqual(result["unexpected_exports"], [])
        self.assertEqual(result["crc_mismatches"], [])

    def test_export_crc_audit_accepts_module_filename_owner(self):
        result = audit_export_closure(
            {"provider_api": "0x00000040"},
            {"provider_api": {"crc": "0x00000040", "module": "/tmp/build/hybrid580_open.ko"}},
            "hybrid580_open",
        )

        self.assertEqual(result["expected_export_count"], 1)
        self.assertEqual(result["missing_exports"], [])
        self.assertEqual(result["unexpected_exports"], [])

    def test_standard_uvm_api_accepts_only_declared_frontend_owned_extensions(self):
        result = audit_standard_uvm_api(
            {"nvUvmInterfaceAlloc": "0x00000050"},
            {
                "nvUvmInterfaceAlloc": "0x00000050",
                "nvUvmInterfaceDupWithControlFd": "0x00000051",
            },
            {"nvUvmInterfaceDupWithControlFd"},
        )

        self.assertEqual(result["crc_mismatches"], [])
        self.assertEqual(result["missing_exports"], [])
        self.assertEqual(result["unexpected_exports"], [])
        self.assertEqual(result["frontend_only_extensions"], [
            "nvUvmInterfaceDupWithControlFd",
        ])

    def test_standard_uvm_api_rejects_unlisted_exports_and_crc_drift(self):
        result = audit_standard_uvm_api(
            {"nvUvmInterfaceAlloc": "0x00000052"},
            {
                "nvUvmInterfaceAlloc": "0x00000050",
                "unlisted": "0x00000053",
            },
            set(),
        )

        self.assertEqual(result["crc_mismatches"], ["nvUvmInterfaceAlloc"])
        self.assertEqual(result["unexpected_exports"], ["unlisted"])

    def test_standard_uvm_api_accepts_declared_control_fd_replacement_only_when_imported(self):
        result = audit_standard_uvm_api(
            {
                "nvUvmInterfaceAlloc": "0x00000050",
                "nvUvmInterfaceDupAddressSpaceWithControlFd": "0x00000052",
            },
            {
                "nvUvmInterfaceAlloc": "0x00000050",
                "nvUvmInterfaceDupAddressSpace": "0x00000051",
                "nvUvmInterfaceDupAddressSpaceWithControlFd": "0x00000052",
            },
            {"nvUvmInterfaceDupAddressSpaceWithControlFd"},
        )
        self.assertEqual(result["crc_mismatches"], [])
        self.assertEqual(result["missing_exports"], [])
        self.assertEqual(result["unexpected_exports"], [])

        legacy_only = audit_standard_uvm_api(
            {"nvUvmInterfaceAlloc": "0x00000050"},
            {
                "nvUvmInterfaceAlloc": "0x00000050",
                "nvUvmInterfaceDupAddressSpace": "0x00000051",
            },
            set(),
        )
        self.assertEqual(legacy_only["unexpected_exports"], [
            "nvUvmInterfaceDupAddressSpace",
        ])

    def test_standard_module_names_dependencies_and_vermagic_are_enforced(self):
        modules = {
            "frontend": {"name": "nvidia", "vermagic": "6.8.0-147-generic SMP modversions",
                         "depends": ["hybrid580_legacy", "hybrid580_open"]},
            "open": {"name": "hybrid580_open", "vermagic": "6.8.0-147-generic SMP modversions",
                     "depends": ["ecc"]},
            "legacy": {"name": "hybrid580_legacy", "vermagic": "6.8.0-147-generic SMP modversions",
                       "depends": []},
            "uvm": {"name": "nvidia_uvm", "vermagic": "6.8.0-147-generic SMP modversions",
                    "depends": ["nvidia"]},
        }

        self.assertEqual(validate_module_topology(modules, "6.8.0-147-generic"), [])

        modules["uvm"]["depends"] = ["hybrid580_open"]
        modules["legacy"]["vermagic"] = "6.8.0-40-generic SMP modversions"
        issues = validate_module_topology(modules, "6.8.0-147-generic")
        self.assertEqual({issue["check"] for issue in issues}, {
            "module-dependencies", "module-kernel-release",
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
