# SPDX-License-Identifier: MIT
"""Compile and execute dynamic UVM address-space owner/lifetime routing."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmAddressSpaceRouteTests(unittest.TestCase):
    def test_address_space_create_destroy_owner_parent_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hybrid580_uvm_address_space_route_test"
            build = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                 str(ROOT / "tests/fixtures/hybrid580_uvm_address_space_route_test.c"),
                 "-o", str(binary)],
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("passed", run.stdout)

    def test_public_address_space_create_destroy_execute_exact_bridge_adapters(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        bridge_text = bridge.read_text(encoding="utf-8")
        bridge_lines = bridge_text.splitlines(keepends=True)
        source = (ROOT / "tests/fixtures/hybrid580_uvm_address_space_wrapper_test.c").read_text()
        function_signatures = (
            "static uint32_t hybrid580_open_address_space_create(",
            "static uint32_t hybrid580_legacy_address_space_create(",
            "static void hybrid580_open_address_space_destroy(",
            "static void hybrid580_legacy_address_space_destroy(",
            "NV_STATUS nvUvmInterfaceAddressSpaceCreate(",
            "void nvUvmInterfaceAddressSpaceDestroy(",
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

        adapter_marker = "/* INSERT_EXACT_ADDRESS_SPACE_BACKEND_ADAPTERS */"
        ops_marker = "/* INSERT_EXACT_ADDRESS_SPACE_PROVIDER_OPS */"
        wrappers_marker = "/* INSERT_EXACT_ADDRESS_SPACE_PUBLIC_WRAPPERS */"
        self.assertEqual(source.count(adapter_marker), 1)
        self.assertEqual(source.count(ops_marker), 1)
        self.assertEqual(source.count(wrappers_marker), 1)

        adapters = "\n\n".join(exact_function(signature)
                                for signature in function_signatures[:4])
        ops = "\n\n".join(exact_declaration(signature) for signature in (
            "static const struct hybrid580_uvm_address_space_backend_ops\n"
            "hybrid580_open_address_space_ops = {",
            "static const struct hybrid580_uvm_address_space_backend_ops\n"
            "hybrid580_legacy_address_space_ops = {",
        ))
        wrappers = "\n\n".join(exact_function(signature)
                               for signature in function_signatures[4:])
        generated = source.replace(adapter_marker, adapters).replace(
            ops_marker, ops).replace(wrappers_marker, wrappers)

        with tempfile.TemporaryDirectory(prefix="hybrid580-address-space-public-") as directory:
            source_path = Path(directory) / "address_space_public_test.c"
            binary = Path(directory) / "address_space_public_test"
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
        self.assertIn("exact UVM address-space create/destroy wrappers", run.stdout)


if __name__ == "__main__":
    unittest.main()
