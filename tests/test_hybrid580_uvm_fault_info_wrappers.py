# SPDX-License-Identifier: MIT
"""Compile and exercise the exact public UVM fault-info bridge wrappers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

from tools.audit_volta_uvm_candidate_paths import _extract_function  # noqa: E402


class Hybrid580UvmFaultInfoWrapperTests(unittest.TestCase):
    def test_exact_fault_info_lifecycle_and_queries_route_by_owner(self):
        bridge = ROOT / "src/hybrid580_uvm_callback_bridge.c"
        text = bridge.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)

        function_signatures = (
            "static NV_STATUS hybrid580_uvm_info_status_to_nv(",
            "static const struct hybrid580_uvm_fault_info_backend_ops *\nhybrid580_uvm_fault_info_backend(",
            "static NV_STATUS hybrid580_uvm_info_device_owner_locked(",
            "static NV_STATUS hybrid580_uvm_info_reserve_fault_pair_locked(",
            "static NV_STATUS hybrid580_uvm_info_finish_fault_pair_init(",
            "static NV_STATUS hybrid580_uvm_info_begin_fault_retire_locked(",
            "static NV_STATUS hybrid580_uvm_info_finish_fault_pair_destroy(",
            "static NV_STATUS hybrid580_uvm_device_call(",
            "static uint32_t hybrid580_open_report_non_replayable_fault(",
            "static uint32_t hybrid580_legacy_report_non_replayable_fault(",
            "static uint32_t hybrid580_open_own_page_fault_intr(",
            "static uint32_t hybrid580_legacy_own_page_fault_intr(",
            "static uint32_t hybrid580_open_service_device_interrupts(",
            "static uint32_t hybrid580_legacy_service_device_interrupts(",
            "NV_STATUS nvUvmInterfaceInitFaultInfo(",
            "NV_STATUS nvUvmInterfaceDestroyFaultInfo(",
            "NV_STATUS nvUvmInterfaceHasPendingNonReplayableFaults(",
            "NV_STATUS nvUvmInterfaceGetNonReplayableFaults(",
            "NV_STATUS nvUvmInterfaceFlushReplayableFaultBuffer(",
            "NV_STATUS nvUvmInterfaceTogglePrefetchFaults(",
            "NV_STATUS nvUvmInterfaceReportNonReplayableFault(",
            "NV_STATUS nvUvmInterfaceOwnPageFaultIntr(",
            "NV_STATUS nvUvmInterfaceServiceDeviceInterruptsRM(",
        )
        for signature in function_signatures:
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

        exact_functions = [exact_function(signature)
                           for signature in function_signatures]
        fixture = (ROOT / "tests/fixtures/hybrid580_uvm_fault_info_wrappers_test.c").read_text()
        markers = (
            "/* INSERT_EXACT_FAULT_INFO_OPS_TYPE */",
            "/* INSERT_EXACT_FAULT_INFO_BACKEND_OPS */",
            "/* INSERT_EXACT_NON_REPLAYABLE_FAULT_CALL_STRUCT */",
            "/* INSERT_EXACT_DEVICE_CALL_AND_REPORT_ADAPTERS */",
            "/* INSERT_EXACT_FAULT_INFO_HELPERS */",
            "/* INSERT_EXACT_FAULT_INFO_PUBLIC_WRAPPERS */",
        )
        for marker in markers:
            self.assertEqual(fixture.count(marker), 1, marker)

        ops_type = exact_block(
            "struct hybrid580_uvm_fault_info_backend_ops {")
        backend_ops = "\n\n".join(exact_block(signature) for signature in (
            "static const struct hybrid580_uvm_fault_info_backend_ops\nhybrid580_open_fault_info_ops = {",
            "static const struct hybrid580_uvm_fault_info_backend_ops\nhybrid580_legacy_fault_info_ops = {",
        ))
        helpers = "\n\n".join(exact_functions[:7])
        fault_call_struct = exact_block(
            "struct hybrid580_uvm_non_replayable_fault_call {")
        fault_interrupt_routes = "\n\n".join(exact_functions[7:14])
        wrappers = "\n\n".join(exact_functions[14:])
        generated = fixture.replace(markers[0], ops_type).replace(
            markers[1], backend_ops).replace(markers[2], fault_call_struct).replace(
            markers[3], fault_interrupt_routes).replace(markers[4], helpers).replace(
            markers[5], wrappers)

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

        with tempfile.TemporaryDirectory(prefix="hybrid580-uvm-fault-info-") as directory:
            run = compile_and_run(directory, generated, "fault_info_wrappers")
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("exact UVM fault and interrupt routes",
                          run.stdout)

            wrong_identity = (
                "csl_identity = (uintptr_t)&pFaultInfo->replayable.cslCtx;")
            self.assertEqual(generated.count(wrong_identity), 1)
            mutated = generated.replace(
                wrong_identity,
                "csl_identity = (uintptr_t)&pFaultInfo->pDevice;")
            mutation_run = compile_and_run(
                directory, mutated, "fault_info_wrong_csl_identity")
            self.assertNotEqual(mutation_run.returncode, 0,
                                "fixture must reject a misrouted embedded CSL identity")


if __name__ == "__main__":
    unittest.main()
