# SPDX-License-Identifier: MIT
"""Compile and run exact UVM memory allocation and CPU-map wrappers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmMemoryWrapperTests(unittest.TestCase):
    def test_public_memory_wrappers_execute_exact_bridge_and_provider_adapters(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        bridge_text = bridge.read_text(encoding="utf-8")
        bridge_lines = bridge_text.splitlines(keepends=True)
        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_memory_wrapper_test.c").read_text()
        signatures = (
            "static NV_STATUS hybrid580_uvm_address_space_call(",
            "static uint32_t hybrid580_open_memory_alloc_fb(",
            "static uint32_t hybrid580_legacy_memory_alloc_fb(",
            "static uint32_t hybrid580_open_memory_alloc_sys(",
            "static uint32_t hybrid580_legacy_memory_alloc_sys(",
            "static uint32_t hybrid580_open_memory_free(",
            "static uint32_t hybrid580_legacy_memory_free(",
            "static uint32_t hybrid580_open_memory_cpu_map(",
            "static uint32_t hybrid580_legacy_memory_cpu_map(",
            "static uint32_t hybrid580_open_memory_cpu_unmap(",
            "static uint32_t hybrid580_legacy_memory_cpu_unmap(",
            "static NV_STATUS hybrid580_uvm_memory_alloc(",
            "NV_STATUS nvUvmInterfaceMemoryAllocFB(",
            "NV_STATUS nvUvmInterfaceMemoryAllocSys(",
            "void nvUvmInterfaceMemoryFree(",
            "NV_STATUS nvUvmInterfaceMemoryCpuMap(",
            "void nvUvmInterfaceMemoryCpuUnMap(",
        )
        for signature in signatures:
            self.assertEqual(bridge_text.count(signature), 1, signature)

        def exact_function(signature):
            extracted = _extract_function(bridge, signature)
            return "".join(bridge_lines[
                extracted["start_line"] - 1:extracted["end_line"]])

        def exact_struct(name):
            signature = f"struct {name} {{"
            self.assertEqual(bridge_text.count(signature), 1, signature)
            start = bridge_text.index(signature)
            end = bridge_text.index("};", start) + len("};")
            return bridge_text[start:end]

        macro_start = bridge_text.index(
            "#define HYBRID580_UVM_MEMORY_OPS(name)")
        macro_end = bridge_text.index(
            "#undef HYBRID580_UVM_MEMORY_OPS", macro_start)
        exact_ops_macro = bridge_text[macro_start:macro_end]
        types_marker = "/* INSERT_EXACT_MEMORY_PARAM_TYPES */"
        helpers_marker = "/* INSERT_EXACT_MEMORY_HELPERS_AND_ADAPTERS */"
        ops_marker = "/* INSERT_EXACT_MEMORY_PROVIDER_OPS */"
        wrappers_marker = "/* INSERT_EXACT_MEMORY_PUBLIC_WRAPPERS */"
        for marker in (types_marker, helpers_marker, ops_marker, wrappers_marker):
            self.assertEqual(fixture.count(marker), 1, marker)

        helper_and_adapters = "\n\n".join(
            exact_function(signature) for signature in signatures[:12])
        param_types = "\n\n".join(exact_struct(name) for name in (
            "hybrid580_uvm_memory_alloc_params",
            "hybrid580_uvm_memory_free_params",
            "hybrid580_uvm_memory_cpu_map_params",
            "hybrid580_uvm_memory_cpu_unmap_params",
        ))
        wrappers = "\n\n".join(
            exact_function(signature) for signature in signatures[12:])
        generated = fixture.replace(types_marker, param_types).replace(
            helpers_marker, helper_and_adapters).replace(
            ops_marker, exact_ops_macro).replace(wrappers_marker, wrappers)

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-memory-") as directory:
            source = Path(directory) / "memory_wrapper_test.c"
            binary = Path(directory) / "memory_wrapper_test"
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
        self.assertIn("exact UVM memory allocation and CPU mapping wrappers", run.stdout)


if __name__ == "__main__":
    unittest.main()
