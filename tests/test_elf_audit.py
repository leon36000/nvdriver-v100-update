#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify symbol classification and export caution on a tiny ELF fixture."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ElfAuditTests(unittest.TestCase):
    def test_global_weak_undefined_and_export_markers_are_distinct(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "a C compiler is required for the fixture")
        with tempfile.TemporaryDirectory(prefix="hybrid-elf-audit-") as temporary:
            directory = Path(temporary)
            source = directory / "fixture.c"
            object_file = directory / "fixture.o"
            source.write_text(
                "extern int audit_imported(void);\n"
                "int audit_global(void) { return audit_imported(); }\n"
                "__attribute__((weak)) int audit_weak(void) { return 7; }\n"
            )
            subprocess.run([compiler, "-c", str(source), "-o", str(object_file)],
                           check=True)
            result = subprocess.run(
                ["python3", str(ROOT / "tools/elf_audit.py"), str(object_file)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            symbols = report["symbols"]
            self.assertIn("audit_global", symbols["global_defined"])
            self.assertIn("audit_weak", symbols["weak_defined"])
            self.assertIn("audit_imported", symbols["undefined"])
            self.assertEqual(
                report["linux_module_export_evidence"][
                    "verified_symbol_names_from_ksymtab_markers"
                ],
                [],
            )
            self.assertIn("do not prove Linux kernel exports",
                          report["linux_module_export_evidence"]["interpretation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
