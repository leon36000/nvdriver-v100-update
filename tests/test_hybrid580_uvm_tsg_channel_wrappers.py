# SPDX-License-Identifier: MIT
"""Compile and execute exact public TSG/channel ownership wrappers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmTsgChannelWrapperTests(unittest.TestCase):
    def test_public_tsg_channel_wrappers_enforce_provider_and_parent_lifetimes(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        signatures = (
            "static uint32_t hybrid580_open_tsg_allocate(",
            "static uint32_t hybrid580_legacy_tsg_allocate(",
            "static void hybrid580_open_tsg_destroy(",
            "static void hybrid580_legacy_tsg_destroy(",
            "static uint32_t hybrid580_open_channel_allocate(",
            "static uint32_t hybrid580_legacy_channel_allocate(",
            "static void hybrid580_open_channel_destroy(",
            "static void hybrid580_legacy_channel_destroy(",
            "NV_STATUS nvUvmInterfaceTsgAllocate(",
            "void nvUvmInterfaceTsgDestroy(",
            "NV_STATUS nvUvmInterfaceChannelAllocate(",
            "void nvUvmInterfaceChannelDestroy(",
        )
        for signature in signatures:
            self.assertEqual(text.count(signature), 1, signature)

        def exact_function(signature):
            result = _extract_function(bridge, signature)
            return "".join(lines[result["start_line"] - 1:result["end_line"]])

        def exact_struct(name):
            signature = f"struct {name} {{"
            self.assertEqual(text.count(signature), 1, signature)
            start = text.index(signature)
            end = text.index("};", start) + len("};")
            return text[start:end]

        def exact_declaration(signature):
            self.assertEqual(text.count(signature), 1, signature)
            start = text.index(signature)
            end = text.index("};", start) + len("};")
            return text[start:end]

        structs = "\n\n".join(exact_struct(name) for name in (
            "hybrid580_uvm_tsg_allocate_params",
            "hybrid580_uvm_channel_allocate_params",
        ))
        adapter_block = "\n\n".join(exact_function(signature)
                                        for signature in signatures[:8])
        wrapper_block = "\n\n".join(exact_function(signature)
                                        for signature in signatures[8:])
        ops = "\n\n".join(exact_declaration(signature) for signature in (
            "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
            "hybrid580_open_tsg_allocate_ops = {",
            "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
            "hybrid580_legacy_tsg_allocate_ops = {",
            "static const struct hybrid580_uvm_typed_child_call_backend_ops\n"
            "hybrid580_open_channel_allocate_ops = {",
            "static const struct hybrid580_uvm_typed_child_call_backend_ops\n"
            "hybrid580_legacy_channel_allocate_ops = {",
            "static const struct hybrid580_uvm_typed_child_destroy_backend_ops\n"
            "hybrid580_open_tsg_destroy_ops = {",
            "static const struct hybrid580_uvm_typed_child_destroy_backend_ops\n"
            "hybrid580_legacy_tsg_destroy_ops = {",
            "static const struct hybrid580_uvm_typed_child_destroy_backend_ops\n"
            "hybrid580_open_channel_destroy_ops = {",
            "static const struct hybrid580_uvm_typed_child_destroy_backend_ops\n"
            "hybrid580_legacy_channel_destroy_ops = {",
        ))
        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_tsg_channel_wrapper_test.c").read_text()
        markers = (
            "/* INSERT_EXACT_TSG_CHANNEL_TYPES */",
            "/* INSERT_EXACT_TSG_CHANNEL_ADAPTERS */",
            "/* INSERT_EXACT_TSG_CHANNEL_OPS */",
            "/* INSERT_EXACT_TSG_CHANNEL_PUBLIC_WRAPPERS */",
        )
        for marker in markers:
            self.assertEqual(fixture.count(marker), 1, marker)
        generated = fixture.replace(markers[0], structs).replace(
            markers[1], adapter_block).replace(markers[2], ops).replace(
            markers[3], wrapper_block)

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-tsg-channel-") as directory:
            source = Path(directory) / "tsg_channel_wrapper_test.c"
            binary = Path(directory) / "tsg_channel_wrapper_test"
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
        self.assertIn("exact UVM TSG/channel wrappers", run.stdout)


if __name__ == "__main__":
    unittest.main()
