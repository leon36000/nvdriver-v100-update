# SPDX-License-Identifier: MIT
"""Regression tests for complete, stable software-suite input manifests."""

import ast
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import run_software_test_suite as suite


class SoftwareSuiteSourceManifestTests(unittest.TestCase):
    def test_every_local_tool_module_imported_by_tests_is_manifested(self):
        imported_tools = set()
        for test_path in sorted(suite.TEST_ROOT.rglob("*.py")):
            tree = ast.parse(test_path.read_text(encoding="utf-8"),
                             filename=str(test_path))
            for node in ast.walk(tree):
                module_names = []
                if isinstance(node, ast.Import):
                    module_names.extend(alias.name for alias in node.names
                                        if alias.name.startswith("tools."))
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    if node.module == "tools":
                        module_names.extend(
                            f"tools.{alias.name}" for alias in node.names
                            if alias.name != "*"
                        )
                    elif node.module and node.module.startswith("tools."):
                        module_names.append(node.module)
                    elif node.module:
                        module_names.append(f"tools.{node.module}")
                for module_name in module_names:
                    source = suite.ROOT / Path(*module_name.split(".")).with_suffix(".py")
                    if source.is_file():
                        imported_tools.add(source.relative_to(suite.ROOT).as_posix())

        missing = sorted(imported_tools - set(suite.IMPLEMENTATION_INPUTS))
        self.assertTrue(imported_tools, "expected to discover local tool imports")
        self.assertEqual([], missing,
                         f"test-imported tool modules missing from implementation manifest: {missing}")

    def test_hashes_regular_nested_inputs_and_skips_caches_and_specials(self):
        with tempfile.TemporaryDirectory(prefix="software-suite-manifest-") as temp:
            root = Path(temp)
            (root / "fixtures").mkdir()
            (root / "__pycache__").mkdir()
            python_input = root / "test_contract.py"
            c_input = root / "fixtures" / "contract.c"
            pyc_input = root / "__pycache__" / "test_contract.pyc"
            external = root / "outside.txt"
            python_input.write_text("# source\n", encoding="utf-8")
            c_input.write_text("int fixture(void) { return 1; }\n", encoding="utf-8")
            pyc_input.write_bytes(b"cache")
            external.write_text("external\n", encoding="utf-8")
            fifo = root / "fixtures" / "fixture.fifo"
            os.mkfifo(fifo)

            hashes = suite._source_hashes(root)

            self.assertEqual(hashes, {
                "test-inputs/fixtures/contract.c": hashlib.sha256(
                    c_input.read_bytes()).hexdigest(),
                "test-inputs/outside.txt": hashlib.sha256(
                    external.read_bytes()).hexdigest(),
                "test-inputs/test_contract.py": hashlib.sha256(
                    python_input.read_bytes()).hexdigest(),
            })

    def test_rejects_file_and_directory_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="software-suite-symlink-") as temp:
            root = Path(temp)
            target = root / "target.py"
            target.write_text("# external source\n", encoding="utf-8")
            (root / "linked.py").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlink"):
                suite._source_hashes(root)

        with tempfile.TemporaryDirectory(prefix="software-suite-symlink-dir-") as temp:
            root = Path(temp)
            target_dir = root / "real"
            target_dir.mkdir()
            (root / "linked-dir").symlink_to(target_dir, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink directory"):
                suite._source_hashes(root)

    def test_fails_closed_when_a_test_input_directory_cannot_be_traversed(self):
        with tempfile.TemporaryDirectory(prefix="software-suite-walk-error-") as temp:
            root = Path(temp)
            inaccessible = root / "fixtures"

            def failed_walk(path, topdown=True, onerror=None, followlinks=False):
                self.assertEqual(Path(path), root)
                self.assertTrue(callable(onerror))
                self.assertFalse(followlinks)
                onerror(PermissionError(13, "permission denied", str(inaccessible)))
                return iter(())

            with patch.object(suite.os, "walk", side_effect=failed_walk):
                with self.assertRaisesRegex(OSError, "cannot traverse test input directory"):
                    suite._source_hashes(root)

    def test_change_detector_reports_added_removed_and_modified_inputs(self):
        before = {"tests/a.c": "a", "tests/b.py": "b"}
        after = {"tests/a.c": "changed", "tests/c.h": "c"}
        self.assertEqual(suite._changed_source_hashes(before, after),
                         ["tests/a.c", "tests/b.py", "tests/c.h"])
        self.assertEqual(suite._changed_source_hashes(before, dict(before)), [])

    def test_default_manifest_covers_compiled_p2p_fixture_and_test(self):
        hashes = suite._source_hashes()
        fixture = "tests/fixtures/hybrid580_uvm_p2p_bridge_contract_test.c"
        test = "tests/test_hybrid580_uvm_p2p_bridge_contract.py"
        self.assertEqual(hashes[fixture], hashlib.sha256(
            (suite.ROOT / fixture).read_bytes()).hexdigest())
        self.assertEqual(hashes[test], hashlib.sha256(
            (suite.ROOT / test).read_bytes()).hexdigest())

    def test_implementation_manifest_covers_driver_probe_and_patch_inputs(self):
        hashes = suite._implementation_hashes()
        self.assertEqual(len(hashes), len(suite.IMPLEMENTATION_INPUTS))
        self.assertEqual(len(hashes), len(set(suite.IMPLEMENTATION_INPUTS)))
        for name in (
                "tools/run_software_test_suite.py",
                "tools/run_volta_fault_decode_host_harness.py",
                "tools/run_volta_fault_ring_host_harness.py",
                "tools/run_pc3_rtx_pmon_reference.py",
                "tools/compare_elf_loadable_sections.py",
                "tools/build_r595_hybrid_uvm_target.py",
                "src/hybrid_frontend.c",
                "kernels/hybrid_probe.cu",
                "patches/r580.178.04/0048-private-open-sync-boost-groups.patch",
                "patches/r580.178.04/0050-private-open-debugger-bridge.patch",
                "patches/r580.178.04/proprietary/0046-private-legacy-sync-boost-groups.patch",
                "patches/r580.178.04/proprietary/0048-private-legacy-debugger-bridge.patch"):
            self.assertEqual(hashes[name], hashlib.sha256(
                (suite.ROOT / name).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
