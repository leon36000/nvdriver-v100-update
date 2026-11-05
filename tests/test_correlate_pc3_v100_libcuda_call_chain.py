#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the bounded runtime-to-Ghidra libcuda call-chain correlation."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/correlate_pc3_v100_libcuda_call_chain.py"
LIBCUDA_SHA256 = "dcdf334aeb177c95b3385b797c9b871d03a287895713c6d107f79096b0985aa9"


def load_tool():
    if not TOOL.is_file():
        return None
    spec = importlib.util.spec_from_file_location("pc3_v100_call_chain_correlation", TOOL)
    if spec is None or spec.loader is None:
        raise AssertionError("call-chain correlation tool could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sensitivity_report():
    chain = ["0x495acc", "0x4600fc", "0x49d4c2", "0x2ba6e9",
             "0x2d2340", "0x331c32", "0x3279b0"]
    return {
        "schema": "nvidia-hybrid-v100-system-features-sensitivity-v1",
        "status": "complete",
        "complete": True,
        "api_outcomes_equal": True,
        "control_outcomes_equal": True,
        "caller_chain_capture_requested": True,
        "guest": {
            "hostname": "pc3-v100",
            "kernel_release": "6.8.0-147-generic",
            "gpu": {
                "name": "Tesla V100-SXM2-16GB",
                "uuid": "GPU-42d06a85-027a-75ea-7857-a8de27ad465e",
                "pci": "0000:00:05.0",
                "driver_version": "580.178.04",
            },
            "libcuda": {
                "path": "/usr/lib/x86_64-linux-gnu/libcuda.so.580.178.04",
                "sha256": LIBCUDA_SHA256,
                "driver_api": 13000,
            },
        },
        "runs": [
            {
                "requested_mask": mask,
                "probe_exit_code": 0,
                "cuda": {"cu_init": 0, "device_count": 1, "driver_api": 13000},
                "ioctl_records": [{
                    "transport": "direct",
                    "kernel_mask": 9,
                    "exposed_mask": mask,
                    "caller_image": "libcuda.so.580.178.04",
                    "caller_offset": "0x48bc88",
                    "caller_chain_offsets": chain.copy(),
                    "caller_chain_anchor_found": True,
                    "caller_chain_truncated": False,
                }],
            }
            for mask in (9, 8, 1, 0)
        ],
    }


def ghidra_report():
    return {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-ghidra-function-v2",
        "status": "static_analysis_passed",
        "input": {"sha256": LIBCUDA_SHA256},
        "finding": {
            "target_rva": "0x48bc88",
            "function_name": "FUN_0058bc40",
            "function_entry_rva": "0x48bc40",
            "function_end_rva_exclusive": "0x48bd43",
            "incoming_callers_truncated": True,
            "incoming_callers": [{
                "source_rva": "0x495ac7",
                "reference_type": "UNCONDITIONAL_CALL",
                "source_function_name": "FUN_00594f60",
                "source_function_entry_rva": "0x494f60",
            }],
        },
    }


def multi_ghidra_report():
    frames = [
        (0x48BC88, "FUN_0058bc40", 0x48BC40, False, []),
        (0x495ACC, "FUN_00594f60", 0x494F60, True,
         [{"source_rva": "0x495ac7", "target_rva": "0x48bc40",
           "target_name": "FUN_0058bc40", "target_external": False,
           "reference_type": "UNCONDITIONAL_CALL"}]),
        (0x4600FC, "FUN_005600d0", 0x4600D0, False,
         [{"source_rva": "0x4600f7", "target_rva": "0x494f60",
           "target_name": "FUN_00594f60", "target_external": False,
           "reference_type": "UNCONDITIONAL_CALL"}]),
        (0x49D4C2, "FUN_0059d360", 0x49D360, False, []),
        (0x2BA6E9, "FUN_003ba4b0", 0x2BA4B0, False,
         [{"source_rva": "0x2ba6e3", "target_rva": "0x2b23f0",
           "target_name": "LAB_003b23ec+4", "target_external": False,
           "reference_type": "COMPUTED_CALL"}]),
        (0x2D2340, "FUN_003d1e00", 0x2D1E00, True,
         [{"source_rva": "0x2d233b", "target_rva": "0x2ba4b0",
           "target_name": "FUN_003ba4b0", "target_external": False,
           "reference_type": "UNCONDITIONAL_CALL"}]),
        (0x331C32, "FUN_00431bc0", 0x331BC0, False,
         [{"source_rva": "0x331c2d", "target_rva": "0x2d1e00",
           "target_name": "FUN_003d1e00", "target_external": False,
           "reference_type": "UNCONDITIONAL_CALL"}]),
        (0x3279B0, "cuInit", 0x327990, False,
         [{"source_rva": "0x3279aa", "target_rva": "0x331bc0",
           "target_name": "FUN_00431bc0", "target_external": False,
           "reference_type": "COMPUTED_CALL"}]),
    ]
    return {
        "schema": "nvidia-hybrid-pc3-v100-libcuda-ghidra-multi-function-v1",
        "status": "static_analysis_passed",
        "input": {"sha256": LIBCUDA_SHA256},
        "findings": [
            {
                "target_rva": f"0x{target:x}",
                "function_name": name,
                "function_entry_rva": f"0x{entry:x}",
                "function_end_rva_exclusive": f"0x{target + 0x40:x}",
                "instruction_count": 10,
                "incoming_callers": ([{
                    "source_rva": "0x495ac7",
                    "source_function_name": "FUN_00594f60",
                    "source_function_entry_rva": "0x494f60",
                    "reference_type": "UNCONDITIONAL_CALL",
                }] if target == 0x48BC88 else []),
                "incoming_callers_truncated": False,
                "outgoing_calls": outgoing,
                "outgoing_calls_truncated": truncated,
            }
            for target, name, entry, truncated, outgoing in frames
        ],
    }


class Pc3V100LibcudaCallChainCorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def test_runtime_return_matches_static_call_reference(self):
        self.assertIsNotNone(self.tool, "the call-chain correlation tool is missing")
        result = self.tool.correlate_reports(sensitivity_report(), ghidra_report())
        self.assertEqual(result["observation"]["runtime_first_caller_return_rva"], "0x495acc")
        reference = result["observation"]["static_call_reference"]
        self.assertEqual(reference["source_rva"], "0x495ac7")
        self.assertEqual(reference["function_name"], "FUN_00594f60")
        self.assertTrue(result["observation"]["same_chain_across_masks"])

    def test_rejects_a_runtime_chain_that_does_not_match_static_references(self):
        self.assertIsNotNone(self.tool, "the call-chain correlation tool is missing")
        static = ghidra_report()
        static["finding"]["incoming_callers"][0]["source_rva"] = "0x495ac6"
        with self.assertRaisesRegex(ValueError, "no static caller reference"):
            self.tool.correlate_reports(sensitivity_report(), static)

    def test_rejects_different_runtime_chains_between_masks(self):
        self.assertIsNotNone(self.tool, "the call-chain correlation tool is missing")
        observed = sensitivity_report()
        observed["runs"][1]["ioctl_records"][0]["caller_chain_offsets"][0] = "0x495bd0"
        with self.assertRaisesRegex(ValueError, "not stable across mask runs"):
            self.tool.correlate_reports(observed, ghidra_report())

    def test_maps_runtime_stack_to_functions_and_preserves_unresolved_edges(self):
        result = self.tool.correlate_stack_reports(sensitivity_report(), multi_ghidra_report())
        self.assertEqual(result["status"], "partial_stack_static_correlation")
        self.assertEqual(result["runtime_frames"][-1]["function_name"], "cuInit")
        self.assertEqual(result["static_edges_resolved"], 5)
        self.assertEqual(result["static_edges_total"], 7)
        self.assertEqual(result["call_edges"][3]["status"],
                         "nearby_reference_target_unresolved")
        self.assertEqual(result["call_edges"][2]["status"],
                         "no_matching_static_call_reference")


if __name__ == "__main__":
    unittest.main()
