"""Tests for the exact-header UVM ioctl payload layout comparison."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/compare_uvm_payload_abi.py"
SPEC = importlib.util.spec_from_file_location("compare_uvm_payload_abi", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load UVM payload ABI comparator")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def sample_probe(*, r580_profile: bool = True) -> dict[str, object]:
    layouts = {
        "UVM_INITIALIZE_PARAMS": {"size": 16, "fields": [
            {"name": "flags", "offset": 0, "size": 8},
            {"name": "rmStatus", "offset": 8, "size": 4}]},
        "UVM_CREATE_RANGE_GROUP_PARAMS": {"size": 16, "fields": [
            {"name": "rangeGroupId", "offset": 0, "size": 8},
            {"name": "rmStatus", "offset": 8, "size": 4}]},
        "UVM_REGISTER_GPU_PARAMS": {"size": 40, "fields": [
            {"name": "gpu_uuid", "offset": 0, "size": 16},
            {"name": "numaEnabled", "offset": 16, "size": 1},
            {"name": "numaNodeId", "offset": 20, "size": 4},
            {"name": "rmCtrlFd", "offset": 24, "size": 4},
            {"name": "hClient", "offset": 28, "size": 4},
            {"name": "hSmcPartRef", "offset": 32, "size": 4},
            {"name": "rmStatus", "offset": 36, "size": 4}]},
        "UVM_REGISTER_GPU_VASPACE_PARAMS": {"size": 32, "fields": [
            {"name": "gpuUuid", "offset": 0, "size": 16},
            {"name": "rmCtrlFd", "offset": 16, "size": 4},
            {"name": "hClient", "offset": 20, "size": 4},
            {"name": "hVaSpace", "offset": 24, "size": 4},
            {"name": "rmStatus", "offset": 28, "size": 4}]},
        "UVM_PAGEABLE_MEM_ACCESS_PARAMS": {"size": 8, "fields": [
            {"name": "pageableMemAccess", "offset": 0, "size": 1},
            {"name": "rmStatus", "offset": 4, "size": 4}]},
        "UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS": {"size": 24, "fields": [
            {"name": "gpu_uuid", "offset": 0, "size": 16},
            {"name": "pageableMemAccess", "offset": 16, "size": 1},
            {"name": "rmStatus", "offset": 20, "size": 4}]},
        "UVM_MM_INITIALIZE_PARAMS": {"size": 8, "fields": [
            {"name": "uvmFd", "offset": 0, "size": 4},
            {"name": "rmStatus", "offset": 4, "size": 4}]},
        "UVM_EVENT_CTRL_PARAMS": (
            {"size": 20, "fields": [
                {"name": "sessionIndex", "offset": 0, "size": 4},
                {"name": "eventQueueIndex", "offset": 4, "size": 4},
                {"name": "eventType", "offset": 8, "size": 4},
                {"name": "enable", "offset": 12, "size": 4},
                {"name": "rmStatus", "offset": 16, "size": 4}]}
            if r580_profile else
            {"size": 16, "fields": [
                {"name": "eventQueueIndex", "offset": 0, "size": 4},
                {"name": "eventType", "offset": 4, "size": 4},
                {"name": "enable", "offset": 8, "size": 4},
                {"name": "rmStatus", "offset": 12, "size": 4}]}
        ),
        "UVM_CREATE_EXTERNAL_RANGE_PARAMS": {"size": 24, "fields": [
            {"name": "base", "offset": 0, "size": 8},
            {"name": "length", "offset": 8, "size": 8},
            {"name": "rmStatus", "offset": 16, "size": 4}]},
        "UVM_REGISTER_CHANNEL_PARAMS": {"size": 56, "fields": [
            {"name": "gpuUuid", "offset": 0, "size": 16},
            {"name": "rmCtrlFd", "offset": 16, "size": 4},
            {"name": "hClient", "offset": 20, "size": 4},
            {"name": "hChannel", "offset": 24, "size": 4},
            {"name": "base", "offset": 32, "size": 8},
            {"name": "length", "offset": 40, "size": 8},
            {"name": "rmStatus", "offset": 48, "size": 4}]},
        "UVM_UNREGISTER_CHANNEL_PARAMS": (
            {"size": 28, "fields": [
                {"name": "gpuUuid", "offset": 0, "size": 16},
                {"name": "hClient", "offset": 16, "size": 4},
                {"name": "hChannel", "offset": 20, "size": 4},
                {"name": "rmStatus", "offset": 24, "size": 4}]}
            if r580_profile else
            {"size": 12, "fields": [
                {"name": "hClient", "offset": 0, "size": 4},
                {"name": "hChannel", "offset": 4, "size": 4},
                {"name": "rmStatus", "offset": 8, "size": 4}]}
        ),
        "UVM_ALLOC_SEMAPHORE_POOL_PARAMS": {"size": 9248, "fields": [
            {"name": "base", "offset": 0, "size": 8},
            {"name": "length", "offset": 8, "size": 8},
            {"name": "perGpuAttributes", "offset": 16, "size": 9216},
            {"name": "gpuAttributesCount", "offset": 9232, "size": 8},
            {"name": "rmStatus", "offset": 9240, "size": 4}]},
        "UVM_VALIDATE_VA_RANGE_PARAMS": {"size": 24, "fields": [
            {"name": "base", "offset": 0, "size": 8},
            {"name": "length", "offset": 8, "size": 8},
            {"name": "rmStatus", "offset": 16, "size": 4}]},
        "UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS": {"size": 40, "fields": [
            {"name": "base", "offset": 0, "size": 8},
            {"name": "length", "offset": 8, "size": 8},
            {"name": "gpuUuid", "offset": 16, "size": 16},
            {"name": "rmStatus", "offset": 32, "size": 4}]},
        "UVM_FREE_PARAMS": (
            {"size": 24, "fields": [
                {"name": "base", "offset": 0, "size": 8},
                {"name": "length", "offset": 8, "size": 8},
                {"name": "rmStatus", "offset": 16, "size": 4}]}
            if r580_profile else
            {"size": 16, "fields": [
                {"name": "base", "offset": 0, "size": 8},
                {"name": "rmStatus", "offset": 8, "size": 4}]}
        ),
        "UVM_DESTROY_RANGE_GROUP_PARAMS": {"size": 16, "fields": [
            {"name": "rangeGroupId", "offset": 0, "size": 8},
            {"name": "rmStatus", "offset": 8, "size": 4}]},
        "UVM_UNREGISTER_GPU_VASPACE_PARAMS": {"size": 20, "fields": [
            {"name": "gpuUuid", "offset": 0, "size": 16},
            {"name": "rmStatus", "offset": 16, "size": 4}]},
        "UVM_MAP_EXTERNAL_ALLOCATION_PARAMS": {"size": 9264, "fields": [
            {"name": "base", "offset": 0, "size": 8},
            {"name": "length", "offset": 8, "size": 8},
            {"name": "offset", "offset": 16, "size": 8},
            {"name": "perGpuAttributes", "offset": 24, "size": 9216},
            {"name": "gpuAttributesCount", "offset": 9240, "size": 8},
            {"name": "rmCtrlFd", "offset": 9248, "size": 4},
            {"name": "hClient", "offset": 9252, "size": 4},
            {"name": "hMemory", "offset": 9256, "size": 4},
            {"name": "rmStatus", "offset": 9260, "size": 4}]},
    }
    return {
        "schema": AUDIT.PROBE_SCHEMA,
        "pointer_bytes": 8,
        "r580_abi_profile": r580_profile,
        "event_ctrl_has_session_index": r580_profile,
        "commands": {
            **AUDIT.EXPECTED_COMMANDS,
            "UVM_CREATE_EXTERNAL_RANGE": 0x49,
            "UVM_REGISTER_CHANNEL": 0x1B,
            "UVM_UNREGISTER_CHANNEL": 0x1C,
            "UVM_ALLOC_SEMAPHORE_POOL": 0x44,
            "UVM_VALIDATE_VA_RANGE": 0x48,
            "UVM_MAP_DYNAMIC_PARALLELISM_REGION": 0x41,
            "UVM_FREE": 0x22,
            "UVM_DESTROY_RANGE_GROUP": 0x18,
            "UVM_UNREGISTER_GPU_VASPACE": 0x1A,
            "UVM_EVENT_CTRL": 0x11,
        },
        "layouts": layouts,
    }


def sample_sequence_report() -> dict[str, object]:
    names = [
        "UVM_INITIALIZE", "UVM_MM_INITIALIZE", "UVM_PAGEABLE_MEM_ACCESS",
        "UVM_REGISTER_GPU", "UVM_CREATE_RANGE_GROUP", "UVM_REGISTER_GPU_VASPACE",
        "UVM_CREATE_EXTERNAL_RANGE", "UVM_MAP_EXTERNAL_ALLOCATION",
        "UVM_REGISTER_CHANNEL", "UVM_ALLOC_SEMAPHORE_POOL", "UVM_VALIDATE_VA_RANGE",
        "UVM_MAP_DYNAMIC_PARALLELISM_REGION", "UVM_FREE", "UVM_DESTROY_RANGE_GROUP",
        "UVM_UNREGISTER_CHANNEL", "UVM_UNREGISTER_GPU_VASPACE",
    ]
    names_to_hex = {
        "UVM_INITIALIZE": "0x30000001", "UVM_MM_INITIALIZE": "0x4b",
        "UVM_PAGEABLE_MEM_ACCESS": "0x27", "UVM_REGISTER_GPU": "0x25",
        "UVM_CREATE_RANGE_GROUP": "0x17", "UVM_REGISTER_GPU_VASPACE": "0x19",
        "UVM_CREATE_EXTERNAL_RANGE": "0x49", "UVM_MAP_EXTERNAL_ALLOCATION": "0x21",
        "UVM_REGISTER_CHANNEL": "0x1b", "UVM_ALLOC_SEMAPHORE_POOL": "0x44",
        "UVM_VALIDATE_VA_RANGE": "0x48", "UVM_MAP_DYNAMIC_PARALLELISM_REGION": "0x41",
        "UVM_FREE": "0x22", "UVM_DESTROY_RANGE_GROUP": "0x18",
        "UVM_UNREGISTER_CHANNEL": "0x1c", "UVM_UNREGISTER_GPU_VASPACE": "0x1a",
    }
    names_to_count = {
        "UVM_INITIALIZE": 1, "UVM_MM_INITIALIZE": 1,
        "UVM_PAGEABLE_MEM_ACCESS": 1, "UVM_REGISTER_GPU": 1,
        "UVM_CREATE_RANGE_GROUP": 8, "UVM_REGISTER_GPU_VASPACE": 1,
        "UVM_CREATE_EXTERNAL_RANGE": 26, "UVM_MAP_EXTERNAL_ALLOCATION": 26,
        "UVM_REGISTER_CHANNEL": 16, "UVM_ALLOC_SEMAPHORE_POOL": 1,
        "UVM_VALIDATE_VA_RANGE": 1, "UVM_MAP_DYNAMIC_PARALLELISM_REGION": 1,
        "UVM_FREE": 28, "UVM_DESTROY_RANGE_GROUP": 7,
        "UVM_UNREGISTER_CHANNEL": 16, "UVM_UNREGISTER_GPU_VASPACE": 1,
    }
    captures = []
    for index in range(2):
        captures.append({
            "capture": f"capture-{index}.json", "capture_sha256": f"{index + 1:064x}",
            "driver_version": "580.178.04", "kernel_release": "6.8.0-test",
            "guest_name": "Tesla V100-SXM2-16GB", "gpu_pci": "0000:00:05.0",
            "uvm_ioctl_count": 136, "trace_sha256": f"{index + 3:064x}",
            "first_seen_request_order": names,
            "requests": [
                {"name": name, "request": names_to_hex[name], "count": names_to_count[name]}
                for name in names
            ],
        })
    return {
        "schema": "nvidia-hybrid-pc3-v100-context-uvm-sequence-v1",
        "qualification": "repeated-stock-driver-context-ioctl-metadata-only",
        "uvm_payloads_observed": False,
        "scope": "UVM ioctl request metadata only; no payload observed",
        "captures": captures,
    }
class CompareUvmPayloadAbiTests(unittest.TestCase):
    def test_branch_layout_profile_is_checked_against_named_header_structs(self):
        r580_header = """
        typedef struct { NvU32 sessionIndex; NvU32 rmStatus; } UVM_EVENT_CTRL_PARAMS;
        typedef struct { NvU64 base; NvU64 length; NV_STATUS rmStatus; } UVM_FREE_PARAMS;
        typedef struct { NvProcessorUuid gpuUuid; NvHandle hClient; } UVM_UNREGISTER_CHANNEL_PARAMS;
        """
        r595_header = """
        typedef struct { NvU32 sessionIndex; } UNRELATED_PARAMS;
        typedef struct { NvU32 eventQueueIndex; NvU32 rmStatus; } UVM_EVENT_CTRL_PARAMS;
        typedef struct { NvU64 base; NV_STATUS rmStatus; } UVM_FREE_PARAMS;
        typedef struct { NvHandle hClient; } UVM_UNREGISTER_CHANNEL_PARAMS;
        """
        AUDIT.validate_branch_profile_header_text(r580_header, r580_abi_profile=True)
        AUDIT.validate_branch_profile_header_text(r595_header, r580_abi_profile=False)
        with self.assertRaisesRegex(ValueError, "branch-specific member"):
            AUDIT.validate_branch_profile_header_text(r580_header, r580_abi_profile=False)

    def test_loads_repeated_v100_sequence_and_pins_request_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sequence.json"
            path.write_text(json.dumps(sample_sequence_report()), encoding="utf-8")

            observed = AUDIT.load_sequence_report(path)

        self.assertEqual(observed["capture_count"], 2)
        self.assertTrue(observed["repeated_order_consistent"])
        self.assertEqual(observed["request_numbers"]["UVM_UNREGISTER_CHANNEL"], 0x1C)
        self.assertIn("UVM_EVENT_CTRL", observed["additional_probe_requests_not_in_trace"])
        self.assertIn(
            "UVM_PAGEABLE_MEM_ACCESS_ON_GPU",
            observed["additional_probe_requests_not_in_trace"],
        )

    def test_rejects_sequence_request_number_or_order_drift(self):
        for mutate in ("request", "order"):
            sequence = sample_sequence_report()
            capture = sequence["captures"][1]
            if mutate == "request":
                capture["requests"][0]["request"] = "0xdead"
            else:
                capture["first_seen_request_order"][0], capture["first_seen_request_order"][1] = (
                    capture["first_seen_request_order"][1], capture["first_seen_request_order"][0]
                )
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "sequence.json"
                path.write_text(json.dumps(sequence), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "sequence"):
                    AUDIT.load_sequence_report(path)

    def test_rejects_sequence_if_payloads_were_observed(self):
        sequence = sample_sequence_report()
        sequence["uvm_payloads_observed"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sequence.json"
            path.write_text(json.dumps(sequence), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "payload boundary"):
                AUDIT.load_sequence_report(path)

    def test_parses_exact_probe_shape_and_layout(self):
        parsed = AUDIT.parse_probe_output(json.dumps(sample_probe()))

        self.assertEqual(parsed["pointer_bytes"], 8)
        self.assertEqual(parsed["commands"], AUDIT.EXPECTED_COMMANDS)
        self.assertEqual(
            set(parsed["layouts"]),
            set(AUDIT.EXPECTED_LAYOUT_FIELDS) | set(AUDIT.BRANCH_LAYOUT_FIELDS),
        )
        self.assertEqual(parsed["layouts"]["UVM_REGISTER_GPU_PARAMS"]["fields"][0], {
            "name": "gpu_uuid", "offset": 0, "size": 16,
        })
        vaspace = parsed["layouts"]["UVM_REGISTER_GPU_VASPACE_PARAMS"]
        self.assertEqual(vaspace["size"], 32)
        self.assertEqual(vaspace["fields"][1], {
            "name": "rmCtrlFd", "offset": 16, "size": 4,
        })
        external_map = parsed["layouts"]["UVM_MAP_EXTERNAL_ALLOCATION_PARAMS"]
        self.assertEqual(external_map["size"], 9264)
        self.assertEqual(external_map["fields"][5], {
            "name": "rmCtrlFd", "offset": 9248, "size": 4,
        })
        self.assertEqual(parsed["commands"]["UVM_MAP_EXTERNAL_ALLOCATION"], 33)
        self.assertEqual(parsed["commands"]["UVM_REGISTER_GPU_VASPACE"], 0x19)
        self.assertEqual(parsed["commands"]["UVM_EVENT_CTRL"], 0x11)
        event = parsed["layouts"]["UVM_EVENT_CTRL_PARAMS"]
        self.assertEqual(event["size"], 20)
        self.assertEqual(event["fields"][0], {
            "name": "sessionIndex", "offset": 0, "size": 4,
        })

    def test_rejects_malformed_or_incomplete_layout_output(self):
        probe = sample_probe()
        del probe["layouts"]["UVM_MM_INITIALIZE_PARAMS"]
        with self.assertRaisesRegex(ValueError, "layout set"):
            AUDIT.parse_probe_output(json.dumps(probe))

        probe = sample_probe()
        probe["layouts"]["UVM_INITIALIZE_PARAMS"]["fields"][0]["offset"] = -1
        with self.assertRaisesRegex(ValueError, "field layout"):
            AUDIT.parse_probe_output(json.dumps(probe))

        probe = sample_probe(r580_profile=False)
        probe["layouts"]["UVM_EVENT_CTRL_PARAMS"]["fields"].insert(0, {
            "name": "sessionIndex", "offset": 0, "size": 4,
        })
        with self.assertRaisesRegex(ValueError, "field layout"):
            AUDIT.parse_probe_output(json.dumps(probe))

    def test_compares_command_numbers_and_field_offsets(self):
        left = AUDIT.parse_probe_output(json.dumps(sample_probe()))
        right = AUDIT.parse_probe_output(json.dumps(sample_probe()))
        self.assertTrue(AUDIT.compare_layouts(left, right)["identical"])

        right["layouts"]["UVM_REGISTER_GPU_PARAMS"]["fields"][3]["offset"] += 4
        comparison = AUDIT.compare_layouts(left, right)
        self.assertFalse(comparison["identical"])
        self.assertIn("UVM_REGISTER_GPU_PARAMS", comparison["layout_deltas"])

    def test_detects_event_ctrl_layout_delta_with_stable_command_number(self):
        r580 = AUDIT.parse_probe_output(json.dumps(sample_probe()))
        r595 = AUDIT.parse_probe_output(json.dumps(
            sample_probe(r580_profile=False)
        ))

        comparison = AUDIT.compare_layouts(r580, r595)

        self.assertEqual(r580["commands"]["UVM_EVENT_CTRL"], 0x11)
        self.assertEqual(r595["commands"]["UVM_EVENT_CTRL"], 0x11)
        self.assertFalse(comparison["identical"])
        self.assertIn("UVM_EVENT_CTRL_PARAMS", comparison["layout_deltas"])
        self.assertEqual(comparison["layout_deltas"]["UVM_EVENT_CTRL_PARAMS"]["left"]["size"], 20)
        self.assertEqual(comparison["layout_deltas"]["UVM_EVENT_CTRL_PARAMS"]["right"]["size"], 16)

    def test_compares_the_observed_v100_sequence_and_finds_branch_payload_deltas(self):
        r580 = AUDIT.parse_probe_output(json.dumps(sample_probe(r580_profile=True)))
        r595 = AUDIT.parse_probe_output(json.dumps(sample_probe(r580_profile=False)))

        comparison = AUDIT.compare_layouts(r580, r595)

        self.assertEqual(r580["commands"], r595["commands"])
        self.assertEqual(comparison["command_deltas"], {})
        self.assertEqual(
            set(comparison["layout_deltas"]),
            {"UVM_EVENT_CTRL_PARAMS", "UVM_FREE_PARAMS", "UVM_UNREGISTER_CHANNEL_PARAMS"},
        )
        self.assertEqual(comparison["layout_deltas"]["UVM_FREE_PARAMS"]["left"]["size"], 24)
        self.assertEqual(comparison["layout_deltas"]["UVM_FREE_PARAMS"]["right"]["size"], 16)
        self.assertEqual(
            comparison["layout_deltas"]["UVM_UNREGISTER_CHANNEL_PARAMS"]["left"]["size"], 28
        )
        self.assertEqual(
            comparison["layout_deltas"]["UVM_UNREGISTER_CHANNEL_PARAMS"]["right"]["size"], 12
        )


if __name__ == "__main__":
    unittest.main()
