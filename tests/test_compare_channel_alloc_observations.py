#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Contracts for the sanitized installed-driver channel comparison."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/compare_channel_alloc_observations.py"


class ComparatorAvailability(unittest.TestCase):
    def test_comparator_exists(self):
        self.assertTrue(TOOL_PATH.is_file(), "channel-allocation comparator is missing")


if TOOL_PATH.is_file():
    spec = importlib.util.spec_from_file_location("compare_channel_alloc", TOOL_PATH)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)

    def observation(class_id, flags=0, allocations=1, child_exit=0, schema="v8",
                    userd_class=None):
        channels = []
        for _ in range(allocations):
            channel = {
                "classPayloadBytes": 368,
                "hObjectErrorPresent": True,
                "hObjectBufferPresent": True,
                "gpFifoOffsetNonzero": True,
                "gpFifoEntries": 1024,
                "flags": flags,
                "hContextSharePresent": True,
                "hVASpacePresent": False,
                "hUserdMemoryPresentCount": 1,
                "userdOffsetNonzeroCount": 1,
                "engineType": 0,
                "subDeviceId": 0,
                "cidPresent": False,
                "hObjectEccErrorPresent": False,
                "memoryDescriptors": {
                    name: {"basePresent": False, "size": 0,
                           "addressSpace": 0, "cacheAttrib": 0}
                    for name in ("instanceMem", "userdMem", "ramfcMem", "mthdbufMem")
                },
                "reservedFields": {
                    "hPhysChannelGroupPresent": False,
                    "internalFlagsZero": True,
                    "errorNotifierMemZero": True,
                    "eccErrorNotifierMemZero": True,
                    "processIdZero": True,
                    "subProcessIdZero": True,
                    "encryptIvZero": True,
                    "decryptIvZero": True,
                    "hmacNonceZero": True,
                    "tpcConfigIdZero": True,
                },
            }
            if schema == "v9":
                absent = {"resolution": "absent", "classId": None}
                userd = [absent.copy() for _ in range(8)]
                if userd_class is not None:
                    userd[0] = {"resolution": "resolved", "classId": userd_class}
                channel["objectClasses"] = {
                    "parent": {"resolution": "resolved", "classId": 0xa06c},
                    "hObjectError": {"resolution": "resolved", "classId": 0x3e},
                    "hObjectBuffer": absent.copy(),
                    "hContextShare": {"resolution": "resolved", "classId": 0x9067},
                    "hVASpace": absent.copy(),
                    "hObjectEccError": absent.copy(),
                    "hPhysChannelGroup": absent.copy(),
                    "hUserdMemory": userd,
                }
            packet = {
                "layout": "NVOS64", "hClass": class_id, "paramsSize": 0,
                "flags": 0, "status": 0, "hRootPresent": True,
                "hObjectParentPresent": True, "hObjectNewPresent": True,
                "pAllocParmsPresent": True, "pRightsRequestedPresent": False,
                "channelPayloadState": "r580-r595-class-layout-parsed",
                "channel": channel,
            }
            channels.append({
                "operation": "channel_alloc", "packet_size": 48,
                "request": 0xc030462b, "syscall_return": 0,
                **({"fd_role": "control"} if schema == "v9" else {}),
                "fd": 7, "tid": 1234, "entry": packet, "exit": packet,
            })
        return {
            "schema": f"nvidia-hybrid-rm-ioctl-observer-{schema}",
            "trace_complete": True, "child_exit_code": child_exit,
            "control_path": "/dev/nvidiactl", "architecture": "x86_64",
            "pointer_bits": 64, "nested_pointers_read": True,
            **({"gpu_path": "/dev/nvidia0",
                "object_class_resolution_scope":
                "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed"}
               if schema == "v9" else {}),
            "nested_pointer_scope": tool.CHANNEL_SCOPE,
            "channel_payload_snapshots_read": allocations * 2,
            "fd_identity_tracking": False, "errors": [], "records": channels,
        }

    def branch_report(branch, capture):
        if branch == "blackwell":
            capture["child_exit_code"] = 77
        probe_device = {
            "name": "Tesla V100-SXM2-16GB" if branch == "v100" else "NVIDIA GeForce RTX 5080",
            "sm": 70 if branch == "v100" else 120,
            "targeted": True, "tested": True,
            "architecture_kernel_passed": True,
            "synchronous_passed": True, "asynchronous_passed": True,
            "cleanup_passed": True,
        }
        probe = {
            "schema": "nvidia-hybrid-probe-v2",
            "status": "control-passed" if branch == "v100" else "incomplete",
            "required_sm": [70] if branch == "v100" else [70, 120],
            "missing_sm": [] if branch == "v100" else [70],
            "hybrid_validated": False, "devices": [probe_device],
        }
        if branch == "v100":
            return {"remote": {
                "schema": "nvidia-hybrid-pc3-v100-guest-reference-v1",
                "qualification": "v100-reference-report-contract-valid",
                "guest": {"name": probe_device["name"], "driver_version": "580.178.04"},
                "probe_exit_code": 0, "probe": probe, "ioctl_observation": capture,
            }}
        return {"remote": {
            "qualification": "rtx5080-report-contract-valid-hybrid-incomplete",
            "selected_nvidia_smi": {"name": probe_device["name"], "driver": "595.99.02"},
            "hardware_acceptance": {
                "exit_code": 77, "stdout": json.dumps(probe),
                "ioctl_observation": {"report": capture},
            },
        }}

    def abi_build_report():
        return {
            "schema": "nvidia-hybrid-rm-ioctl-observer-build-v2",
            "qualification": "repeatable-build-only-no-driver-execution",
            "channel_payload_abi": {
                "byte_identical": True,
                "class_payload_size_bytes": 368,
                "r580_version": "580.178.04",
                "r595_version": "595.99.02",
                "r580_header_sha256": tool.CHANNEL_HEADER_SHA256,
                "r595_header_sha256": tool.CHANNEL_HEADER_SHA256,
                "required_classes": {
                    "R580:BLACKWELL_CHANNEL_GPFIFO_A": True,
                    "R580:VOLTA_CHANNEL_GPFIFO_A": True,
                    "R595:BLACKWELL_CHANNEL_GPFIFO_A": True,
                    "R595:VOLTA_CHANNEL_GPFIFO_A": True,
                },
            },
        }

    class ChannelComparison(unittest.TestCase):
        def test_reports_common_layout_and_observed_flag_difference(self):
            result = tool.compare_reports(
                branch_report("v100", observation(0xc36f)),
                branch_report("blackwell", observation(0xc96f, flags=16)))
            self.assertTrue(result["same_class_payload_size"])
            self.assertEqual(result["v100"]["class_id_histogram"], {"0xc36f": 1})
            self.assertEqual(result["blackwell"]["class_id_histogram"], {"0xc96f": 1})
            differences = {(item["phase"], item["field"])
                           for item in result["differences"]}
            self.assertIn(("entry", "flags"), differences)
            self.assertIn(("exit", "flags"), differences)
            self.assertFalse(result["hybrid_compatibility_validated"])

        def test_rejects_bad_snapshot_count_and_syscall_failure(self):
            v100 = branch_report("v100", observation(0xc36f))
            blackwell = branch_report("blackwell", observation(0xc96f))
            blackwell["remote"]["hardware_acceptance"]["ioctl_observation"][
                "report"]["channel_payload_snapshots_read"] = 1
            with self.assertRaisesRegex(ValueError, "snapshot count"):
                tool.compare_reports(v100, blackwell)

            blackwell = branch_report("blackwell", observation(0xc96f))
            blackwell["remote"]["hardware_acceptance"]["ioctl_observation"][
                "report"]["records"][0]["syscall_return"] = -1
            with self.assertRaisesRegex(ValueError, "allocation syscall"):
                tool.compare_reports(v100, blackwell)

        def test_rejects_unredacted_handle_or_address_fields(self):
            v100 = branch_report("v100", observation(0xc36f))
            v100["remote"]["ioctl_observation"]["records"][0]["entry"][
                "channel"]["rawHandle"] = 0xdeadbeef
            blackwell = branch_report("blackwell", observation(0xc96f))
            with self.assertRaisesRegex(ValueError, "unexpected channel fields"):
                tool.compare_reports(v100, blackwell)

        def test_rejects_branch_identity_mismatch(self):
            v100 = branch_report("v100", observation(0xc96f))
            blackwell = branch_report("blackwell", observation(0xc96f))
            with self.assertRaisesRegex(ValueError, "Volta class"):
                tool.compare_reports(v100, blackwell)

        def test_v9_compares_redacted_live_object_classes(self):
            v100 = branch_report("v100", observation(
                0xc36f, schema="v9", userd_class=0x3e))
            blackwell = branch_report("blackwell", observation(
                0xc96f, flags=16, schema="v9", userd_class=0x40))
            result = tool.compare_reports(v100, blackwell)
            self.assertTrue(result["object_class_resolution_compared"])
            differences = {(item["phase"], item["field"])
                           for item in result["differences"]}
            self.assertIn(("entry", "objectClasses"), differences)
            self.assertEqual(len(result["v100"]["phases"]["entry"]["objectClasses"]), 1)

        def test_v9_rejects_handle_values_in_object_class_evidence(self):
            v100 = branch_report("v100", observation(0xc36f, schema="v9"))
            v100["remote"]["ioctl_observation"]["records"][0]["entry"]["channel"][
                "objectClasses"]["hContextShare"]["handle"] = 1234
            blackwell = branch_report("blackwell", observation(0xc96f, schema="v9"))
            with self.assertRaisesRegex(ValueError, "handle class resolution"):
                tool.compare_reports(v100, blackwell)

        def test_cli_writes_new_private_evidence_without_overwrite(self):
            with tempfile.TemporaryDirectory(prefix="channel-compare-") as directory:
                root = Path(directory)
                v100_path, blackwell_path, output = (root / "v100.json", root / "blackwell.json",
                                                     root / "summary.json")
                abi_path = root / "abi.json"
                v100_path.write_text(json.dumps(branch_report("v100", observation(0xc36f))))
                blackwell_path.write_text(json.dumps(branch_report(
                    "blackwell", observation(0xc96f, flags=16))))
                abi_path.write_text(json.dumps(abi_build_report()))
                result = tool.run(v100_path, blackwell_path, abi_path, output)
                self.assertEqual(result["schema"], "nvidia-hybrid-channel-alloc-comparison-v2")
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(set(result["inputs"]), {"v100", "blackwell", "channel_abi_build"})
                self.assertRegex(result["tool"]["sha256"], r"^[0-9a-f]{64}$")
                with self.assertRaisesRegex(ValueError, "overwrite"):
                    tool.run(v100_path, blackwell_path, abi_path, output)

        def test_cli_requires_matching_pinned_abi_build(self):
            with tempfile.TemporaryDirectory(prefix="channel-compare-abi-") as directory:
                root = Path(directory)
                v100_path = root / "v100.json"
                blackwell_path = root / "blackwell.json"
                abi_path = root / "abi.json"
                output = root / "summary.json"
                v100_path.write_text(json.dumps(branch_report("v100", observation(0xc36f))))
                blackwell_path.write_text(json.dumps(branch_report("blackwell", observation(0xc96f))))
                abi = abi_build_report()
                abi["channel_payload_abi"]["byte_identical"] = False
                abi_path.write_text(json.dumps(abi))
                with self.assertRaisesRegex(ValueError, "ABI evidence"):
                    tool.run(v100_path, blackwell_path, abi_path, output)


if __name__ == "__main__":
    unittest.main()
