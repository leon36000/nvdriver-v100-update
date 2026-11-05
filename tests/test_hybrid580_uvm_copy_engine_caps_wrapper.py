# SPDX-License-Identifier: MIT
"""Compile and exercise the exact public UVM copy-engine capability route."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
R595_FIXTURES = ROOT / (
    "tests/fixtures/upstream/nvidia-r595-p2p/595.112.07/include")

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmCopyEngineCapsWrapperTests(unittest.TestCase):
    def test_public_caps_route_translates_only_the_legacy_owner(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        signatures = (
            "static uint32_t hybrid580_open_QueryCopyEnginesCaps(",
            "static uint32_t hybrid580_legacy_QueryCopyEnginesCaps(",
            "static NV_STATUS hybrid580_uvm_device_call(",
            "NV_STATUS nvUvmInterfaceQueryCopyEnginesCaps(",
        )
        for signature in signatures:
            self.assertEqual(text.count(signature), 1, signature)

        def exact_function(path, signature):
            source_lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            result = _extract_function(path, signature)
            return "".join(source_lines[result["start_line"] - 1:
                                      result["end_line"]])

        exact = [exact_function(bridge, signature) for signature in signatures]
        abi_header = ROOT / "src/hybrid580_uvm_abi_compat.h"
        copy_translation = exact_function(
            abi_header, "static inline void hybrid580_uvm_copy_caps_from_r580(")

        def exact_struct(name):
            signature = f"struct {name} {{"
            self.assertEqual(abi_header.read_text(encoding="utf-8").count(signature), 1,
                             signature)
            header = abi_header.read_text(encoding="utf-8")
            start = header.index(signature)
            end = header.index("};", start) + len("};")
            return header[start:end]

        legacy_types = "\n\n".join(exact_struct(name) for name in (
            "hybrid580_r580_UvmGpuCopyEngineCaps",
            "hybrid580_r580_UvmGpuCopyEnginesCaps",
        ))

        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_copy_engine_caps_wrapper_test.c").read_text()
        markers = (
            "/* INSERT_EXACT_R580_COPY_CAPS_TYPES */",
            "/* INSERT_EXACT_COPY_CAPS_TRANSLATION */",
            "/* INSERT_EXACT_COPY_CAPS_ADAPTERS */",
            "/* INSERT_EXACT_DEVICE_CALL_HELPER */",
            "/* INSERT_EXACT_COPY_CAPS_PUBLIC_WRAPPER */",
        )
        for marker in markers:
            self.assertEqual(fixture.count(marker), 1, marker)
        generated = fixture.replace(markers[0], legacy_types).replace(
            markers[1], copy_translation).replace(markers[2],
            "\n\n".join(exact[:2])).replace(markers[3], exact[2]).replace(
            markers[4], exact[3])

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-copy-caps-") as directory:
            source = Path(directory) / "copy_caps_wrapper_test.c"
            binary = Path(directory) / "copy_caps_wrapper_test"
            source.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(R595_FIXTURES), "-I", str(ROOT / "src"), "-I", str(ROOT),
                 str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("exact UVM copy-engine capability wrapper", run.stdout)


if __name__ == "__main__":
    unittest.main()
