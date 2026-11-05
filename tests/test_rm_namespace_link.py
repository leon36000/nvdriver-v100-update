# SPDX-License-Identifier: MIT
"""Relocatable-object tests only; no CUDA or NVIDIA hardware is exercised."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RmNamespaceLinkTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "rm_namespace_probe", ROOT / "tools/probe_rm_namespace_link.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def object(self, name, source):
        c = self.root / (name + ".c")
        output = self.root / (name + ".o")
        c.write_text(source)
        subprocess.run(["cc", "-c", str(c), "-o", str(output)], check=True,
                       capture_output=True)
        return output

    def test_only_open_collisions_are_renamed_and_host_callback_stays_undefined(self):
        legacy = self.object("legacy", "extern int host_callback(void);\n"
                             "int rm_ioctl(void) { return host_callback()+1; }\n")
        modern = self.object("modern", "extern int host_callback(void);\n"
                             "int rm_ioctl(void) { return host_callback()+2; }\n"
                             "int open_only(void) { return rm_ioctl(); }\n")
        originals = legacy.read_bytes(), modern.read_bytes()
        report = self.module.probe(legacy, modern, self.root / "probe", "hybrid595_")
        self.assertEqual(report["qualification"], "linked-objects-only", report)
        self.assertEqual(report["renamed_symbol_count"], 1)
        self.assertEqual((legacy.read_bytes(), modern.read_bytes()), originals)
        symbols = subprocess.run(["nm", str(Path(report["combined_object"]["path"]))],
                                 capture_output=True, text=True, check=True).stdout
        self.assertIn(" T rm_ioctl", symbols)
        self.assertIn(" T hybrid595_rm_ioctl", symbols)
        self.assertIn(" T open_only", symbols)
        self.assertIn(" U host_callback", symbols)
        self.assertTrue(report["inputs_unchanged"])
        self.assertFalse(report["kernel_exports_or_abi_validated"])
        self.assertFalse(report["loaded_or_installed"])
        # Execute only our tiny C fixtures: internal references from the Open
        # fixture must call its renamed function, while the legacy call stays
        # bound to the legacy definition. No NVIDIA object is executed here.
        main = self.root / "main.c"
        main.write_text("int rm_ioctl(void); int hybrid595_rm_ioctl(void);\n"
                        "int open_only(void); int host_callback(void) { return 100; }\n"
                        "int main(void) { return !(rm_ioctl()==101 && "
                        "hybrid595_rm_ioctl()==102 && open_only()==102); }\n")
        executable = self.root / "fixture"
        subprocess.run(["cc", str(main), report["combined_object"]["path"],
                        "-o", str(executable)], check=True, capture_output=True)
        result = subprocess.run([str(executable)], check=False, capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_existing_destination_symbol_prevents_ambiguous_renaming(self):
        legacy = self.object("legacy", "int rm_ioctl(void) { return 1; }\n")
        modern = self.object("modern", "int rm_ioctl(void) { return 2; }\n"
                             "int hybrid595_rm_ioctl(void) { return 3; }\n")
        report = self.module.probe(legacy, modern, self.root / "probe", "hybrid595_")
        self.assertEqual(report["qualification"], "failed")
        self.assertIn("already exists", report["error"])
        self.assertTrue(report["inputs_unchanged"])

    def test_existing_work_tree_is_not_overwritten(self):
        legacy = self.object("legacy", "int a;\n")
        modern = self.object("modern", "int b;\n")
        with self.assertRaises(FileExistsError):
            self.module.probe(legacy, modern, self.root, "hybrid595_")

    def test_implicit_cross_backend_resolution_is_refused_in_both_directions(self):
        a = self.object("a", "extern int foreign(void); int entry(void) { return foreign(); }\n")
        b = self.object("b", "int foreign(void) { return 7; }\n")
        for index, (legacy, modern) in enumerate(((a, b), (b, a))):
            with self.subTest(direction=index):
                report = self.module.probe(legacy, modern, self.root / f"probe-{index}", "hybrid595_")
                self.assertEqual(report["qualification"], "failed")
                self.assertIn("cross-backend", report["error"])
                self.assertTrue(report["inputs_unchanged"])

    def test_weak_definitions_are_outside_the_strong_symbol_probe_scope(self):
        legacy = self.object("legacy", "__attribute__((weak)) int rm_ioctl(void) { return 1; }\n")
        modern = self.object("modern", "int rm_ioctl(void) { return 2; }\n")
        report = self.module.probe(legacy, modern, self.root / "probe", "hybrid595_")
        self.assertEqual(report["qualification"], "failed")
        self.assertIn("unsupported external definition", report["error"])


if __name__ == "__main__":
    unittest.main()
