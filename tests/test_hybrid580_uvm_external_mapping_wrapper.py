# SPDX-License-Identifier: MIT
"""Compile and execute exact public external-mapping wrappers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmExternalMappingWrapperTests(unittest.TestCase):
    def test_public_mapping_wrappers_route_by_both_native_owners(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        signatures = (
            "static NV_STATUS hybrid580_uvm_external_mapping_status_to_nv(",
            "NV_STATUS nvUvmInterfaceGetExternalAllocPtes(",
            "NV_STATUS nvUvmInterfaceGetExternalAllocPhysAddrs(",
        )
        for signature in signatures:
            self.assertEqual(text.count(signature), 1, signature)
        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_external_mapping_wrapper_test.c").read_text()
        marker = "/* INSERT_EXACT_EXTERNAL_MAPPING_STATUS_AND_WRAPPERS */"
        self.assertEqual(fixture.count(marker), 1)
        extracted = []
        for signature in signatures:
            function = _extract_function(bridge, signature)
            extracted.append("".join(lines[
                function["start_line"] - 1:function["end_line"]]))
        generated = fixture.replace(marker, "\n\n".join(extracted))

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-map-owner-") as directory:
            source = Path(directory) / "external_mapping_wrapper_test.c"
            binary = Path(directory) / "external_mapping_wrapper_test"
            source.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(ROOT), str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("exact UVM external mapping wrappers", run.stdout)


if __name__ == "__main__":
    unittest.main()
