# SPDX-License-Identifier: MIT
"""Compile and execute same-provider UVM duplicate-allocation routing."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmDupAllocationRouteTests(unittest.TestCase):
    def test_same_provider_routes_and_cross_provider_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_uvm_dup_allocation_route_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined",
                 str(ROOT / "tests/fixtures/hybrid580_uvm_dup_allocation_route_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)

    def test_public_dup_allocation_executes_exact_bridge_adapters_and_ops(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        bridge_text = bridge.read_text(encoding="utf-8")
        bridge_lines = bridge_text.splitlines(keepends=True)
        source = (ROOT / "tests/fixtures/hybrid580_uvm_dup_allocation_wrapper_test.c").read_text()
        function_signatures = (
            "static uint32_t hybrid580_open_address_space_dup_allocation(",
            "static uint32_t hybrid580_legacy_address_space_dup_allocation(",
            "NV_STATUS nvUvmInterfaceDupAllocation(",
        )
        for signature in function_signatures:
            self.assertEqual(bridge_text.count(signature), 1, signature)

        def exact_function(signature):
            extracted = _extract_function(bridge, signature)
            return "".join(bridge_lines[
                extracted["start_line"] - 1:extracted["end_line"]])

        def exact_declaration(signature):
            self.assertEqual(bridge_text.count(signature), 1, signature)
            start = bridge_text.index(signature)
            end = bridge_text.index("};", start) + len("};")
            return bridge_text[start:end]

        adapters_marker = "/* INSERT_EXACT_DUP_ALLOCATION_BACKEND_ADAPTERS */"
        ops_marker = "/* INSERT_EXACT_DUP_ALLOCATION_PROVIDER_OPS */"
        wrapper_marker = "/* INSERT_EXACT_DUP_ALLOCATION_PUBLIC_WRAPPER */"
        for marker in (adapters_marker, ops_marker, wrapper_marker):
            self.assertEqual(source.count(marker), 1, marker)
        adapters = "\n\n".join(exact_function(signature)
                                for signature in function_signatures[:2])
        ops = "\n\n".join(exact_declaration(signature) for signature in (
            "static const struct hybrid580_uvm_address_space_dup_allocation_backend_ops\n"
            "hybrid580_open_address_space_dup_allocation_ops = {",
            "static const struct hybrid580_uvm_address_space_dup_allocation_backend_ops\n"
            "hybrid580_legacy_address_space_dup_allocation_ops = {",
        ))
        wrapper = exact_function(function_signatures[-1])
        generated = source.replace(adapters_marker, adapters).replace(
            ops_marker, ops).replace(wrapper_marker, wrapper)

        with tempfile.TemporaryDirectory(prefix="hybrid580-dup-allocation-public-") as directory:
            source_path = Path(directory) / "dup_allocation_public_test.c"
            binary = Path(directory) / "dup_allocation_public_test"
            source_path.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(ROOT), str(source_path), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("exact UVM DupAllocation wrapper", run.stdout)


if __name__ == "__main__":
    unittest.main()
