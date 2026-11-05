# SPDX-License-Identifier: MIT
"""Run the production name-string owner resolver with CPU backend stubs."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "src/hybrid_frontend.c"
FIXTURE = ROOT / "tests/fixtures/hybrid_front_gpu_name_string_test.c"


class HybridFrontendGpuNameStringTests(unittest.TestCase):
    def test_exact_production_resolver_routes_only_to_tracked_owner(self):
        source = FRONTEND.read_text()
        start_marker = "static long hybrid_front_gpu_name_string("
        end_marker = "\n}\n#endif\n\n/* The observed V100 controls refer to frontend objects."
        self.assertEqual(source.count(start_marker), 1)
        self.assertEqual(source.count(end_marker), 1)
        start = source.index(start_marker)
        end = source.index(end_marker, start) + len("\n}")
        resolver = source[start:end]

        fixture = FIXTURE.read_text()
        insertion = "/* INSERT_EXACT_PRODUCTION_RESOLVER */"
        self.assertEqual(fixture.count(insertion), 1)
        generated = fixture.replace(insertion, resolver)

        with tempfile.TemporaryDirectory() as directory:
            c_source = Path(directory) / "gpu_name_string_test.c"
            binary = Path(directory) / "gpu_name_string_test"
            c_source.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 str(c_source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
