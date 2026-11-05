import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE_PATH = ROOT / "tools/probe_r580_proprietary_source_port.py"


def load_probe():
    spec = importlib.util.spec_from_file_location("r580_proprietary_source_port_probe", PROBE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_patch(before: str, after: str, *, path: str = "nvidia/backend.c") -> str:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    return (
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,{len(before_lines)} +1,{len(after_lines)} @@\n"
        + "".join("-" + line for line in before_lines)
        + "".join("+" + line for line in after_lines)
    )


class R580ProprietarySourcePortProbeTests(unittest.TestCase):
    def test_applies_zero_fuzz_patch_without_mutating_vendor_input_or_core(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source_file = source / "nvidia/backend.c"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("int backend(void)\n{\n    return 1;\n}\n")
            core = source / "nvidia/nv-kernel.o_binary"
            core.write_bytes(b"unmodified vendor core")
            patch_file = base / "0001.patch"
            patch_file.write_text(make_patch(
                "int backend(void)\n{\n    return 1;\n}\n",
                "int backend(void)\n{\n    return 2;\n}\n"))

            result = probe.apply_patch_series(
                source, base / "scratch", [patch_file], core_relative="nvidia/nv-kernel.o_binary")

            self.assertTrue(result["all_patches_applied"])
            self.assertEqual(result["fuzz_notices"], [])
            self.assertTrue(result["source_tree_unchanged"])
            self.assertTrue(result["proprietary_core_unchanged"])
            self.assertFalse(result["build_performed"])
            self.assertEqual((base / "scratch/nvidia/backend.c").read_text(),
                             "int backend(void)\n{\n    return 2;\n}\n")

    def test_rejects_patch_paths_that_escape_the_source_tree(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "nvidia").mkdir()
            (source / "nvidia/nv-kernel.o_binary").write_bytes(b"unmodified core")
            patch_file = base / "escape.patch"
            patch_file.write_text(make_patch("old\n", "new\n", path="../outside.c"))

            with self.assertRaisesRegex(ValueError, "unsafe patch path"):
                probe.apply_patch_series(
                    source, base / "scratch", [patch_file], core_relative="nvidia/nv-kernel.o_binary")

            self.assertFalse((base / "scratch").exists())

    def test_rejects_proprietary_core_path_outside_source_tree(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            (source / "nvidia").mkdir(parents=True)
            (source / "nvidia/nv-kernel.o_binary").write_bytes(b"core")
            (base / "external-core").write_bytes(b"outside")
            patch_file = base / "empty.patch"
            patch_file.write_text("--- a/nvidia/input.c\n+++ b/nvidia/input.c\n@@ -1 +1 @@\n-a\n+b\n")

            with self.assertRaisesRegex(ValueError, "unsafe proprietary core path"):
                probe.apply_patch_series(
                    source, base / "scratch", [patch_file], core_relative="../external-core")

    def test_fuzz_zero_rejects_nonmatching_context_and_preserves_source(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source_file = source / "nvidia/backend.c"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("int backend(void) { return 7; }\n")
            (source / "nvidia/nv-kernel.o_binary").write_bytes(b"vendor core")
            patch_file = base / "bad-context.patch"
            patch_file.write_text(make_patch("int backend(void) { return 1; }\n",
                                             "int backend(void) { return 2; }\n"))

            result = probe.apply_patch_series(
                source, base / "scratch", [patch_file], core_relative="nvidia/nv-kernel.o_binary")

            self.assertFalse(result["all_patches_applied"])
            self.assertEqual(result["failed_patch"], "bad-context.patch")
            self.assertEqual(result["fuzz_notices"], [])
            self.assertTrue(result["source_tree_unchanged"])
            self.assertTrue(result["proprietary_core_unchanged"])
            self.assertEqual(source_file.read_text(), "int backend(void) { return 7; }\n")

    def test_refuses_symlinked_vendor_inputs_and_existing_scratch(self):
        probe = load_probe()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            external = base / "external"
            external.write_text("do not patch\n")
            (source / "linked.c").symlink_to(external)
            patch_file = base / "patch.patch"
            patch_file.write_text(make_patch("before\n", "after\n", path="linked.c"))

            with self.assertRaisesRegex(ValueError, "symlinked source"):
                probe.apply_patch_series(
                    source, base / "scratch", [patch_file], core_relative="nvidia/nv-kernel.o_binary")

            scratch = base / "existing"
            scratch.mkdir()
            with self.assertRaisesRegex(ValueError, "scratch path already exists"):
                probe.apply_patch_series(
                    source, scratch, [], core_relative="nvidia/nv-kernel.o_binary")

    def test_full_software_suite_pins_the_probe_implementation(self):
        runner = (ROOT / "tools/run_software_test_suite.py").read_text(encoding="utf-8")
        self.assertIn('"tools/probe_r580_proprietary_source_port.py"', runner)

    def test_repository_patch_series_matches_its_pin(self):
        probe = load_probe()
        self.assertEqual(len(probe.PATCHES), 48)
        manifest = probe.patch_manifest_sha256(probe.PATCHES)
        self.assertEqual(manifest, "fe87e5bffc0bcd91b382ef72ef9194416d6f82ac436d113a23d27ba7c2e716fd")
        self.assertEqual(manifest, probe.PATCH_MANIFEST_SHA256)
        self.assertNotIn(probe.EXPERIMENTAL_DEBUGGER_MASK_GUARD, probe.PATCHES)


if __name__ == "__main__":
    unittest.main()
