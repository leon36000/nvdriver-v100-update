#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Safety contracts for explicit-target R595 hybrid UVM builds."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.build_r595_hybrid_uvm_target import (  # noqa: E402
    safe_new_path,
    tree_manifest,
    validate_kernel,
    debug_prefix_map_flags,
    wire_supplemental_conftests,
    audit_uvm_import_bindings,
)


class R595HybridUvmTargetBuildTests(unittest.TestCase):
    def test_debug_prefix_map_normalizes_per_build_source_copy_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            flags = debug_prefix_map_flags(source, "/usr/src/nvidia-hybrid-driver")
        self.assertEqual(flags, [
            f"-ffile-prefix-map={source}=/usr/src/nvidia-hybrid-driver",
            f"-fdebug-prefix-map={source}=/usr/src/nvidia-hybrid-driver",
        ])

    def test_debug_prefix_map_rejects_unrepresentable_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            with self.assertRaisesRegex(ValueError, "must be absolute"):
                debug_prefix_map_flags(source, "relative/path")
        with tempfile.TemporaryDirectory(prefix="path with space") as temp:
            source = Path(temp) / "source"
            source.mkdir()
            with self.assertRaisesRegex(ValueError, "cannot contain whitespace"):
                debug_prefix_map_flags(source, "/usr/src/nvidia-hybrid-driver")

    def test_kernel_headers_must_match_explicit_release(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "headers"
            (root / "include/config").mkdir(parents=True)
            (root / "include/generated").mkdir(parents=True)
            for name in (".config", "Module.symvers", "Makefile",
                         "include/generated/autoconf.h"):
                (root / name).write_text("test\n")
            (root / "include/config/kernel.release").write_text("6.8.0-test\n")
            with self.assertRaisesRegex(ValueError, "kernel release mismatch"):
                validate_kernel("7.0.0-test", root)

    def test_kernel_headers_require_a_complete_module_build_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "lacks .config"):
                validate_kernel("7.0.0-test", root)

    def test_source_fingerprint_is_stable_and_tracks_content_and_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            item = root / "nvidia-uvm" / "source.c"
            item.parent.mkdir()
            item.write_text("source\n")
            first = tree_manifest(root)
            self.assertEqual(tree_manifest(root), first)
            item.write_text("changed\n")
            self.assertNotEqual(tree_manifest(root), first)

    def test_source_fingerprint_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").write_text("source\n")
            (root / "alias").symlink_to(root / "source")
            with self.assertRaisesRegex(ValueError, "contains a symlink"):
                tree_manifest(root)

    def test_output_paths_must_be_new_and_inside_the_allowed_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            allowed = root / "allowed"
            allowed.mkdir()
            self.assertEqual(safe_new_path(allowed / "new", allowed, "work"),
                             allowed / "new")
            with self.assertRaisesRegex(ValueError, "must be below"):
                safe_new_path(root / "outside", allowed, "work")
            existing = allowed / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                safe_new_path(existing, allowed, "work")

    def test_supplemental_conftests_are_inserted_at_the_unique_kbuild_anchor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            kbuild = source / "Kbuild"
            kbuild.write_text(
                "$(foreach _module, $(NV_KERNEL_MODULES), \\\n"
                " $(eval include $(src)/$(_module)/$(_module).Kbuild))\n"
                "ccflags-y += -I$(src)/common/inc\n"
            )
            fragment = root / "extra.Kbuild"
            fragment.write_text("NV_CONFTEST_TYPE_COMPILE_TESTS += mm_has_mmap_lock\n")
            receipt = wire_supplemental_conftests(source, fragment)
            text = kbuild.read_text()
            self.assertTrue(receipt["applied"])
            self.assertEqual(text.count("NV_KERNEL_EXTRA_CONFTEST_KBUILD"), 2)
            self.assertLess(text.index("_module).Kbuild"),
                            text.index("include $(NV_KERNEL_EXTRA_CONFTEST_KBUILD)"))

    def test_supplemental_conftests_refuse_ambiguous_or_missing_anchors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "Kbuild").write_text("ccflags-y += -I$(src)/common/inc\n")
            fragment = root / "extra.Kbuild"
            fragment.write_text("NV_CONFTEST_TYPE_COMPILE_TESTS += mm_has_mmap_lock\n")
            with self.assertRaisesRegex(ValueError, "one exact module-include anchor"):
                wire_supplemental_conftests(source, fragment)

    def test_address_space_public_import_uses_the_control_fd_dispatcher(self):
        api = ["nvUvmInterfaceAddressSpaceCreate", "nvUvmInterfaceDupAddressSpace"]
        exports = {
            "nvUvmInterfaceAddressSpaceCreate": {
                "crc": "0x01020304", "module": "nvidia", "export": "EXPORT_SYMBOL"},
            "nvUvmInterfaceDupAddressSpaceWithControlFd": {
                "crc": "0xaabbccdd", "module": "nvidia", "export": "EXPORT_SYMBOL"},
        }
        imports = {
            "nvUvmInterfaceAddressSpaceCreate": "0x01020304",
            "nvUvmInterfaceDupAddressSpaceWithControlFd": "0xaabbccdd",
        }
        result = audit_uvm_import_bindings(exports, imports, api)
        self.assertTrue(result["verified"])
        self.assertEqual(result["direct_binding"]["matched_count"], 1)
        self.assertEqual(result["missing_public_imports"], ["nvUvmInterfaceDupAddressSpace"])
        self.assertTrue(result["address_space_dispatch"]["matches"])

    def test_address_space_dispatch_crc_mismatch_fails_closed(self):
        api = ["nvUvmInterfaceAddressSpaceCreate", "nvUvmInterfaceDupAddressSpace"]
        exports = {
            "nvUvmInterfaceAddressSpaceCreate": {
                "crc": "0x01020304", "module": "nvidia", "export": "EXPORT_SYMBOL"},
            "nvUvmInterfaceDupAddressSpaceWithControlFd": {
                "crc": "0xaabbccdd", "module": "nvidia", "export": "EXPORT_SYMBOL"},
        }
        imports = {
            "nvUvmInterfaceAddressSpaceCreate": "0x01020304",
            "nvUvmInterfaceDupAddressSpaceWithControlFd": "0xdeadbeef",
        }
        self.assertFalse(audit_uvm_import_bindings(exports, imports, api)["verified"])


if __name__ == "__main__":
    unittest.main()
