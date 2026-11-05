# SPDX-License-Identifier: MIT
"""Compile and execute the exact public channel resource-PTE wrapper."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmChannelResourcePteWrapperTests(unittest.TestCase):
    def test_public_resource_pte_wrapper_routes_and_copies_payload(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        signatures = (
            "static uint32_t hybrid580_open_get_channel_resource_ptes(",
            "static uint32_t hybrid580_legacy_get_channel_resource_ptes(",
            "static NV_STATUS hybrid580_uvm_address_space_call(",
            "NV_STATUS nvUvmInterfaceGetChannelResourcePtes(",
        )
        page_directory_signatures = (
            "static uint32_t hybrid580_open_set_page_directory(",
            "static uint32_t hybrid580_legacy_set_page_directory(",
            "static uint32_t hybrid580_open_unset_page_directory(",
            "static uint32_t hybrid580_legacy_unset_page_directory(",
            "NV_STATUS nvUvmInterfaceSetPageDirectory(",
            "NV_STATUS nvUvmInterfaceUnsetPageDirectory(",
        )
        for signature in signatures + page_directory_signatures:
            self.assertEqual(text.count(signature), 1, signature)

        def exact_function(signature):
            extracted = _extract_function(bridge, signature)
            return "".join(lines[extracted["start_line"] - 1:
                                extracted["end_line"]])

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

        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_channel_resource_pte_wrapper_test.c").read_text()
        markers = (
            "/* INSERT_EXACT_RESOURCE_PTE_TYPES */",
            "/* INSERT_EXACT_RESOURCE_PTE_ADAPTERS */",
            "/* INSERT_EXACT_RESOURCE_PTE_OPS */",
            "/* INSERT_EXACT_PAGE_DIRECTORY_TYPES */",
            "/* INSERT_EXACT_PAGE_DIRECTORY_ADAPTERS */",
            "/* INSERT_EXACT_PAGE_DIRECTORY_OPS */",
            "/* INSERT_EXACT_ADDRESS_SPACE_CALL_HELPER */",
            "/* INSERT_EXACT_RESOURCE_PTE_PUBLIC_WRAPPER */",
            "/* INSERT_EXACT_PAGE_DIRECTORY_PUBLIC_WRAPPERS */",
        )
        for marker in markers:
            self.assertEqual(fixture.count(marker), 1, marker)
        generated = fixture.replace(
            markers[0], exact_struct("hybrid580_uvm_channel_resource_ptes_params")).replace(
            markers[1], "\n\n".join(exact_function(signature)
                                     for signature in signatures[:2])).replace(
            markers[2], "\n\n".join(exact_declaration(signature) for signature in (
                "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
                "hybrid580_open_get_channel_resource_ptes_ops = {",
                "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
                "hybrid580_legacy_get_channel_resource_ptes_ops = {",
            ))).replace(
                markers[3], exact_struct("hybrid580_uvm_set_page_directory_params")).replace(
                markers[4], "\n\n".join(exact_function(signature)
                                         for signature in page_directory_signatures[:4])).replace(
                markers[5], "\n\n".join(exact_declaration(signature) for signature in (
                    "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
                    "hybrid580_open_set_page_directory_ops = {",
                    "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
                    "hybrid580_legacy_set_page_directory_ops = {",
                    "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
                    "hybrid580_open_unset_page_directory_ops = {",
                    "static const struct hybrid580_uvm_address_space_call_backend_ops\n"
                    "hybrid580_legacy_unset_page_directory_ops = {",
                ))).replace(markers[6], exact_function(signatures[2])).replace(
                    markers[7], exact_function(signatures[3])).replace(
                    markers[8], "\n\n".join(exact_function(signature)
                                             for signature in page_directory_signatures[4:]))

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-channel-ptes-") as directory:
            source = Path(directory) / "channel_resource_pte_wrapper_test.c"
            binary = Path(directory) / "channel_resource_pte_wrapper_test"
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
        self.assertIn("exact channel resource-PTE wrapper", run.stdout)


if __name__ == "__main__":
    unittest.main()
