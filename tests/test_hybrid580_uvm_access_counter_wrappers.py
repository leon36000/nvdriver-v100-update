# SPDX-License-Identifier: MIT
"""Compile exact UVM access-counter wrappers with production owner lifetimes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmAccessCounterWrapperTests(unittest.TestCase):
    def test_exact_access_counter_wrappers_pin_owner_and_block_retirement(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        signatures = (
            "static NV_STATUS hybrid580_uvm_info_status_to_nv(",
            "static const struct hybrid580_uvm_access_cntr_backend_ops *\nhybrid580_uvm_access_cntr_backend(",
            "static NV_STATUS hybrid580_uvm_info_device_owner_locked(",
            "static NV_STATUS hybrid580_uvm_info_reserve_locked(",
            "static NV_STATUS hybrid580_uvm_info_finish_init(",
            "static NV_STATUS hybrid580_uvm_info_begin_retire_locked(",
            "static NV_STATUS hybrid580_uvm_info_finish_retire(",
            "NV_STATUS nvUvmInterfaceInitAccessCntrInfo(",
            "NV_STATUS nvUvmInterfaceDestroyAccessCntrInfo(",
            "NV_STATUS nvUvmInterfaceEnableAccessCntr(",
            "NV_STATUS nvUvmInterfaceDisableAccessCntr(",
        )
        for signature in signatures:
            self.assertEqual(text.count(signature), 1, signature)

        def exact_function(signature):
            extracted = _extract_function(bridge, signature)
            return "".join(lines[extracted["start_line"] - 1:
                                  extracted["end_line"]])

        def exact_block(signature):
            self.assertEqual(text.count(signature), 1, signature)
            start = text.index(signature)
            end = text.index("\n};", start) + len("\n};")
            return text[start:end]

        exact_functions = [exact_function(signature) for signature in signatures]
        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_access_counter_wrappers_test.c").read_text()
        markers = (
            "/* INSERT_EXACT_ACCESS_COUNTER_OPS_TYPE */",
            "/* INSERT_EXACT_ACCESS_COUNTER_BACKEND_OPS */",
            "/* INSERT_EXACT_ACCESS_COUNTER_HELPERS */",
            "/* INSERT_EXACT_ACCESS_COUNTER_PUBLIC_WRAPPERS */",
        )
        for marker in markers:
            self.assertEqual(fixture.count(marker), 1, marker)

        ops_type = exact_block("struct hybrid580_uvm_access_cntr_backend_ops {")
        backend_ops = "\n\n".join(exact_block(signature) for signature in (
            "static const struct hybrid580_uvm_access_cntr_backend_ops\nhybrid580_open_access_cntr_ops = {",
            "static const struct hybrid580_uvm_access_cntr_backend_ops\nhybrid580_legacy_access_cntr_ops = {",
        ))
        helpers = "\n\n".join(exact_functions[:7])
        wrappers = "\n\n".join(exact_functions[7:])
        generated = fixture.replace(markers[0], ops_type).replace(
            markers[1], backend_ops).replace(markers[2], helpers).replace(
            markers[3], wrappers)

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-access-counter-") as directory:
            source = Path(directory) / "access_counter_wrappers.c"
            binary = Path(directory) / "access_counter_wrappers"
            source.write_text(generated)
            build = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=undefined", "-fno-sanitize-recover=all",
                 "-I", str(ROOT / "src"), "-I", str(ROOT),
                 str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True,
                                 timeout=5, check=False)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("exact UVM access-counter owner and lifetime wrappers",
                      run.stdout)


if __name__ == "__main__":
    unittest.main()
