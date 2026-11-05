#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and exercise the exact CSL multi-context key-rotation wrapper."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmCslRotateKeyTests(unittest.TestCase):
    def test_exact_key_rotation_enforces_single_owner_and_pins_contexts(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        signatures = (
            "static const struct hybrid580_uvm_csl_backend_ops *\n"
            "hybrid580_uvm_csl_backend(",
            "static NV_STATUS hybrid580_uvm_info_status_to_nv(",
            "static NV_STATUS hybrid580_uvm_csl_pin(\n",
            "static NV_STATUS hybrid580_uvm_csl_unpin(\n",
            "NV_STATUS nvUvmInterfaceCslRotateKey(",
            "NV_STATUS nvUvmInterfaceCslRotateIv(",
        )
        for signature in signatures:
            self.assertEqual(text.count(signature), 1, signature)

        def exact_function(signature):
            extracted = _extract_function(bridge, signature)
            return "".join(lines[extracted["start_line"] - 1:
                                  extracted["end_line"]])

        signature = "struct hybrid580_uvm_csl_backend_ops {"
        self.assertEqual(text.count(signature), 1, signature)
        start = text.index(signature)
        end = text.index("\n};", start) + len("\n};")
        ops_type = text[start:end]

        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_csl_rotate_key_test.c").read_text()
        markers = (
            "/* INSERT_EXACT_CSL_OPS_TYPE */",
            "/* INSERT_EXACT_CSL_BACKEND_TABLES */",
            "/* INSERT_EXACT_CSL_HELPERS */",
            "/* INSERT_EXACT_CSL_PUBLIC_WRAPPERS */",
        )
        for marker in markers:
            self.assertEqual(fixture.count(marker), 1, marker)

        exact = [exact_function(item) for item in signatures]
        backend_tables = """
static const struct hybrid580_uvm_csl_backend_ops hybrid580_open_csl_ops = {
    .provider = HYBRID580_UVM_PROVIDER_OPEN,
    .rotate_key = fake_open_rotate_key,
    .rotate_iv = fake_open_rotate_iv,
};
static const struct hybrid580_uvm_csl_backend_ops hybrid580_legacy_csl_ops = {
    .provider = HYBRID580_UVM_PROVIDER_LEGACY,
    .rotate_key = fake_legacy_rotate_key,
    .rotate_iv = fake_legacy_rotate_iv,
};
"""
        helpers = "\n\n".join(exact[:4])
        wrappers = "\n\n".join(exact[4:])
        generated = fixture.replace(markers[0], ops_type).replace(
            markers[1], backend_tables).replace(markers[2], helpers).replace(
            markers[3], wrappers)

        def compile_and_run(directory, source_text, name):
            source = Path(directory) / f"{name}.c"
            binary = Path(directory) / name
            source.write_text(source_text)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(ROOT / "src"), "-I", str(ROOT),
                 str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            return subprocess.run([str(binary)], capture_output=True, text=True,
                                  timeout=5, check=False)

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-csl-key-") as directory:
            run = compile_and_run(directory, generated, "csl_rotate_key")
            wrong_backend = "return &hybrid580_legacy_csl_ops;"
            self.assertEqual(generated.count(wrong_backend), 1)
            mutated = generated.replace(
                wrong_backend, "return &hybrid580_open_csl_ops;")
            mutation_run = compile_and_run(
                directory, mutated, "csl_rotate_key_wrong_backend")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("exact CSL key-rotation ownership and lifetime", run.stdout)
        self.assertNotEqual(
            mutation_run.returncode, 0,
            "fixture must reject routing legacy CSL context to Open RM")


if __name__ == "__main__":
    unittest.main()
