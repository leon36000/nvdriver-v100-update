"""Tests for the isolated R580 module dependency-graph audit."""
from __future__ import annotations

import unittest

from tools.audit_r580_module_dependency_graph import (
    normalize_module_name,
    module_name_from_filename,
    parse_modules_dep,
    parse_dry_run,
    parse_show_depends,
    validate_full_load_order,
    validate_softdep,
    module_contracts,
)


class R580ModuleDependencyGraphTests(unittest.TestCase):
    def test_normalizes_modinfo_module_name(self):
        self.assertEqual(normalize_module_name("nvidia-uvm"), "nvidia_uvm")

    def test_captures_expected_provider_softdep(self):
        self.assertEqual(
            validate_softdep("hybrid580_open", " pre:  ecdh_generic ecdsa_generic\n"),
            "pre: ecdh_generic ecdsa_generic",
        )
        self.assertEqual(validate_softdep("nvidia_uvm", ""), "")
        self.assertEqual(
            validate_softdep("hybrid580_uvm", "", uvm_module_name="hybrid580_uvm"), ""
        )

    def test_rejects_missing_or_changed_provider_softdep(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_softdep("hybrid580_open", "")
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_softdep("hybrid580_open", "pre: ecdh_generic,ecdsa_generic")

    def test_rejects_unexpected_module_softdep(self):
        with self.assertRaisesRegex(ValueError, "unexpected module"):
            validate_softdep("other_module", "post: unrelated")

    def test_parses_modprobe_order(self):
        output = (
            "insmod /tmp/updates/hybrid580_open.ko \n"
            "insmod /tmp/updates/hybrid580_legacy.ko \n"
            "insmod /tmp/updates/hybrid580_frontend.ko \n"
            "insmod /tmp/updates/nvidia-uvm.ko \n"
        )
        self.assertEqual(
            parse_show_depends(output),
            ["hybrid580_open", "hybrid580_legacy", "hybrid580_frontend", "nvidia_uvm"],
        )
        custom_output = output.replace("nvidia-uvm.ko", "hybrid580-uvm.ko")
        self.assertEqual(
            parse_show_depends(custom_output),
            ["hybrid580_open", "hybrid580_legacy", "hybrid580_frontend", "hybrid580_uvm"],
        )

    def test_validates_full_plan_with_unloaded_crypto_softdep(self):
        order = ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                 "hybrid580_frontend", "nvidia_uvm"]
        validate_full_load_order(order, ecdsa_expected=True)

    def test_validates_full_plan_when_crypto_softdep_is_resident(self):
        order = ["hybrid580_open", "hybrid580_legacy", "hybrid580_frontend", "nvidia_uvm"]
        validate_full_load_order(order, ecdsa_expected=False)

    def test_validates_full_plan_with_custom_hybrid_uvm_identity(self):
        order = ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy",
                 "hybrid580_frontend", "hybrid580_uvm"]
        validate_full_load_order(
            order, ecdsa_expected=True, uvm_module_name="hybrid580_uvm"
        )
        with self.assertRaisesRegex(ValueError, "load set differs"):
            validate_full_load_order(
                ["hybrid580_open", "hybrid580_legacy", "hybrid580_frontend", "nvidia_uvm"],
                ecdsa_expected=False, uvm_module_name="hybrid580_uvm"
            )

    def test_validates_standard_nvidia_frontend_and_uvm_identity(self):
        modules, dependencies, _ = module_contracts("nvidia_uvm", "nvidia")
        self.assertEqual(
            modules,
            {"hybrid580_open", "hybrid580_legacy", "nvidia", "nvidia_uvm"},
        )
        self.assertEqual(dependencies["nvidia"], {"hybrid580_open", "hybrid580_legacy"})
        self.assertEqual(dependencies["nvidia_uvm"], {"nvidia"})
        order = ["ecdsa_generic", "hybrid580_open", "hybrid580_legacy", "nvidia", "nvidia_uvm"]
        validate_full_load_order(
            order,
            ecdsa_expected=True,
            uvm_module_name="nvidia_uvm",
            frontend_module_name="nvidia",
        )
        with self.assertRaisesRegex(ValueError, "before the frontend"):
            validate_full_load_order(
                ["hybrid580_open", "hybrid580_legacy", "nvidia_uvm", "nvidia"],
                ecdsa_expected=False,
                uvm_module_name="nvidia_uvm",
                frontend_module_name="nvidia",
            )

    def test_rejects_incomplete_or_misordered_full_plan(self):
        with self.assertRaisesRegex(ValueError, "load set differs"):
            validate_full_load_order(
                ["hybrid580_open", "hybrid580_legacy", "hybrid580_frontend", "nvidia_uvm"],
                ecdsa_expected=True,
            )
        with self.assertRaisesRegex(ValueError, "after hybrid580_open"):
            validate_full_load_order(
                ["hybrid580_open", "ecdsa_generic", "hybrid580_legacy",
                 "hybrid580_frontend", "nvidia_uvm"],
                ecdsa_expected=True,
            )
        with self.assertRaisesRegex(ValueError, "load set differs"):
            validate_full_load_order(
                ["ecdsa_generic", "hybrid580_open", "unrelated", "hybrid580_legacy",
                 "hybrid580_frontend", "nvidia_uvm"],
                ecdsa_expected=True,
            )

    def test_parses_compressed_kernel_module_filename(self):
        self.assertEqual(module_name_from_filename("ecdsa-generic.ko.zst"), "ecdsa_generic")
        self.assertEqual(
            parse_dry_run(
                "insmod /lib/modules/test/kernel/crypto/ecdsa_generic.ko.zst\n"
                "insmod /lib/modules/test/updates/hybrid580_open.ko\n"
            ),
            ["ecdsa_generic", "hybrid580_open"],
        )

    def test_rejects_bad_or_duplicate_dry_run_insertions(self):
        with self.assertRaisesRegex(ValueError, "unexpected module filename"):
            module_name_from_filename("ecdsa_generic.bin")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_dry_run(
                "insmod /a/hybrid580_open.ko\ninsmod /b/hybrid580_open.ko\n"
            )
    def test_rejects_empty_or_duplicate_modprobe_plans(self):
        with self.assertRaisesRegex(ValueError, "no module insertions"):
            parse_show_depends("builtin ecdh_generic\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_show_depends("insmod /a/hybrid580_open.ko\ninsmod /b/hybrid580_open.ko\n")

    def test_parses_depmod_transitive_dependencies(self):
        graph = parse_modules_dep(
            "updates/hybrid580_open.ko:\n"
            "updates/hybrid580_legacy.ko:\n"
            "updates/hybrid580_frontend.ko: updates/hybrid580_open.ko updates/hybrid580_legacy.ko\n"
            "updates/nvidia-uvm.ko: updates/hybrid580_frontend.ko updates/hybrid580_open.ko\n"
            "kernel/crypto/ecdsa_generic.ko.zst:\n"
        )
        self.assertEqual(
            graph["nvidia_uvm"], {"hybrid580_frontend", "hybrid580_open"}
        )
        self.assertIn("ecdsa_generic", graph)

    def test_rejects_malformed_or_conflicting_depmod_rows(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse_modules_dep("not-a-dependency-row\n")
        with self.assertRaisesRegex(ValueError, "conflicting"):
            parse_modules_dep(
                "updates/a.ko: updates/b.ko\n"
                "other/a.ko: updates/c.ko\n"
            )


if __name__ == "__main__":
    unittest.main()
