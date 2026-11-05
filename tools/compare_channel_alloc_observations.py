#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate and compare sanitized V100/R580 and RTX5080/R595 channel captures."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


CHANNEL_SCOPE = (
    "VOLTA_CHANNEL_GPFIFO_A and BLACKWELL_CHANNEL_GPFIFO_A class payloads parsed "
    "using the byte-identical pinned R580.178.04/R595.99.02 "
    "NV_CHANNEL_ALLOC_PARAMS layout; raw addresses and handles omitted")
CHANNEL_HEADER_SHA256 = "f0211fbc8bf3f80841f699bf4ccb776d32517308782dfb3c8e99c7652986b5ab"
CHANNEL_FIELDS = {
    "classPayloadBytes", "hObjectErrorPresent", "hObjectBufferPresent",
    "gpFifoOffsetNonzero", "gpFifoEntries", "flags", "hContextSharePresent",
    "hVASpacePresent", "hUserdMemoryPresentCount", "userdOffsetNonzeroCount",
    "engineType", "subDeviceId", "cidPresent", "hObjectEccErrorPresent",
    "memoryDescriptors", "reservedFields",
}
CHANNEL_FIELDS_V9 = CHANNEL_FIELDS | {"objectClasses"}
OBJECT_CLASS_KEYS = {
    "parent", "hObjectError", "hObjectBuffer", "hContextShare", "hVASpace",
    "hObjectEccError", "hPhysChannelGroup", "hUserdMemory",
}
OBJECT_REF_FIELDS = {"resolution", "classId"}
OBJECT_RESOLUTIONS = {
    "absent", "resolved", "not-observed-live-object", "invalid-root", "ambiguous",
}
MEMORY_FIELDS = {"instanceMem", "userdMem", "ramfcMem", "mthdbufMem"}
MEMORY_DESC_FIELDS = {"basePresent", "size", "addressSpace", "cacheAttrib"}
RESERVED_FIELDS = {
    "hPhysChannelGroupPresent", "internalFlagsZero", "errorNotifierMemZero",
    "eccErrorNotifierMemZero", "processIdZero", "subProcessIdZero",
    "encryptIvZero", "decryptIvZero", "hmacNonceZero", "tpcConfigIdZero",
}
PACKET_FIELDS = {
    "layout", "hClass", "paramsSize", "flags", "status", "hRootPresent",
    "hObjectParentPresent", "hObjectNewPresent", "pAllocParmsPresent",
    "pRightsRequestedPresent", "channelPayloadState", "channel",
}
RECORD_FIELDS = {"operation", "packet_size", "request", "syscall_return", "fd", "tid", "entry", "exit"}
RECORD_FIELDS_V9 = RECORD_FIELDS | {"fd_role"}
PROFILE_FIELDS = (
    "paramsSize", "classPayloadBytes", "hObjectErrorPresent", "hObjectBufferPresent",
    "gpFifoOffsetNonzero", "gpFifoEntries", "flags", "hContextSharePresent",
    "hVASpacePresent", "hUserdMemoryPresentCount", "userdOffsetNonzeroCount",
    "engineType", "subDeviceId", "cidPresent", "hObjectEccErrorPresent",
    "memoryDescriptors", "reservedFields",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _branch_capture(report: object, branch: str) -> tuple[dict[str, object], dict[str, object]]:
    require(isinstance(report, dict) and isinstance(report.get("remote"), dict),
            f"{branch} report has no remote result")
    remote = report["remote"]
    if branch == "v100":
        require(remote.get("schema") == "nvidia-hybrid-pc3-v100-guest-reference-v1" and
                remote.get("qualification") == "v100-reference-report-contract-valid",
                "V100 report is not a qualified installed-driver reference")
        identity = remote.get("guest")
        probe = remote.get("probe")
        capture = remote.get("ioctl_observation")
        require(isinstance(identity, dict) and identity.get("name", "").startswith("Tesla V100") and
                identity.get("driver_version") == "580.178.04",
                "report does not identify Tesla V100 under R580.178.04")
        require(isinstance(probe, dict) and remote.get("probe_exit_code") == 0 and
                probe.get("status") == "control-passed" and probe.get("required_sm") == [70] and
                probe.get("missing_sm") == [] and probe.get("hybrid_validated") is False,
                "V100 SM70 installed-driver reference did not pass")
        devices = probe.get("devices")
        require(isinstance(devices, list) and len(devices) == 1,
                "V100 probe must contain exactly one selected device")
        device = devices[0]
        require(isinstance(device, dict) and device.get("sm") == 70 and
                device.get("targeted") is True and device.get("tested") is True and
                device.get("architecture_kernel_passed") is True and
                device.get("synchronous_passed") is True and
                device.get("asynchronous_passed") is True and
                device.get("cleanup_passed") is True,
                "V100 evidence lacks a successful SM70 numerical run")
        identity_result = {"gpu": identity["name"], "driver": identity["driver_version"],
                           "sm": 70, "pci": identity.get("pci")}
        expected_class, expected_exit = 0xc36f, 0
    else:
        require(remote.get("qualification") ==
                "rtx5080-report-contract-valid-hybrid-incomplete",
                "RTX5080 report is not an installed-driver reference")
        identity = remote.get("selected_nvidia_smi")
        hardware = remote.get("hardware_acceptance")
        require(isinstance(identity, dict) and
                identity.get("name") == "NVIDIA GeForce RTX 5080" and
                identity.get("driver") == "595.99.02",
                "report does not identify RTX5080 under R595.99.02")
        require(isinstance(hardware, dict), "RTX5080 hardware result is missing")
        try:
            probe = json.loads(hardware.get("stdout", ""))
        except (TypeError, ValueError):
            raise ValueError("RTX5080 probe result is not valid JSON") from None
        require(hardware.get("exit_code") == 77 and isinstance(probe, dict) and
                probe.get("status") == "incomplete" and probe.get("required_sm") == [70, 120] and
                probe.get("missing_sm") == [70] and probe.get("hybrid_validated") is False,
                "RTX5080 evidence must retain the explicit missing-SM70 result")
        devices = probe.get("devices")
        require(isinstance(devices, list) and len(devices) == 1,
                "RTX5080 probe must contain one selected device")
        device = devices[0]
        require(isinstance(device, dict) and device.get("sm") == 120 and
                device.get("targeted") is True and device.get("tested") is True and
                device.get("architecture_kernel_passed") is True and
                device.get("synchronous_passed") is True and
                device.get("asynchronous_passed") is True and
                device.get("cleanup_passed") is True,
                "RTX5080 evidence lacks a successful SM120 numerical run")
        observation = hardware.get("ioctl_observation")
        capture = observation.get("report") if isinstance(observation, dict) else None
        identity_result = {"gpu": identity["name"], "driver": identity["driver"],
                           "sm": 120, "pci": identity.get("pci")}
        expected_class, expected_exit = 0xc96f, 77

    require(isinstance(capture, dict), f"{branch} channel observer report is missing")
    schema = capture.get("schema")
    require(schema in ("nvidia-hybrid-rm-ioctl-observer-v8",
                       "nvidia-hybrid-rm-ioctl-observer-v9") and
            capture.get("trace_complete") is True and capture.get("errors") == [] and
            capture.get("control_path") == "/dev/nvidiactl" and
            capture.get("architecture") == "x86_64" and capture.get("pointer_bits") == 64 and
            capture.get("child_exit_code") == expected_exit and
            capture.get("nested_pointers_read") is True and
            capture.get("fd_identity_tracking") is False and
            capture.get("nested_pointer_scope") == CHANNEL_SCOPE,
            f"{branch} observer is incomplete or outside the pinned channel-payload scope")
    if schema == "nvidia-hybrid-rm-ioctl-observer-v9":
        require(capture.get("gpu_path") == "/dev/nvidia0" and
                capture.get("object_class_resolution_scope") ==
                "successful prior RM_ALLOC and RM_FREE packets observed on the explicitly selected control and GPU paths; keyed by root and handle; unresolved means no unique live object was observed",
                f"{branch} observer did not capture the explicit GPU descriptor path")
    records = capture.get("records")
    require(isinstance(records, list), f"{branch} observer records are malformed")
    channel_records = [row for row in records
                      if isinstance(row, dict) and row.get("operation") == "channel_alloc"]
    require(bool(channel_records), f"{branch} report has no channel allocation records")
    require(capture.get("channel_payload_snapshots_read") == 2 * len(channel_records),
            f"{branch} channel payload snapshot count is inconsistent")
    for row in channel_records:
        expected_record_fields = RECORD_FIELDS_V9 if schema.endswith("v9") else RECORD_FIELDS
        require(set(row) == expected_record_fields,
                f"{branch} channel record has unexpected fields (possible unredacted data)")
        if schema.endswith("v9"):
            require(row.get("fd_role") in ("control", "gpu"),
                    f"{branch} channel record has no selected descriptor role")
        require(row.get("request") == 0xc030462b and row.get("packet_size") == 48 and
                row.get("syscall_return") == 0,
                f"{branch} allocation syscall did not succeed")
        for phase in ("entry", "exit"):
            packet = row.get(phase)
            generation = "Volta" if branch == "v100" else "Blackwell"
            require(isinstance(packet, dict) and set(packet) == PACKET_FIELDS and
                    packet.get("layout") == "NVOS64" and
                    packet.get("hClass") == expected_class and
                    packet.get("pAllocParmsPresent") is True and
                    packet.get("channelPayloadState") == "r580-r595-class-layout-parsed",
                    f"{branch} channel packet has the wrong {generation} class or layout")
            channel = packet.get("channel")
            expected_channel_fields = CHANNEL_FIELDS_V9 if schema.endswith("v9") else CHANNEL_FIELDS
            require(isinstance(channel, dict) and set(channel) == expected_channel_fields and
                    channel.get("classPayloadBytes") == 368,
                    f"{branch} channel payload has unexpected channel fields or size")
            descriptors = channel.get("memoryDescriptors")
            require(isinstance(descriptors, dict) and set(descriptors) == MEMORY_FIELDS and
                    all(isinstance(value, dict) and set(value) == MEMORY_DESC_FIELDS
                        for value in descriptors.values()),
                    f"{branch} channel payload has unexpected memory descriptor fields")
            reserved = channel.get("reservedFields")
            require(isinstance(reserved, dict) and set(reserved) == RESERVED_FIELDS,
                    f"{branch} channel payload has unexpected reserved fields")
            if schema.endswith("v9"):
                refs = channel.get("objectClasses")
                require(isinstance(refs, dict) and set(refs) == OBJECT_CLASS_KEYS,
                        f"{branch} channel object-class evidence has unexpected fields")
                for name, ref in refs.items():
                    values = ref if name == "hUserdMemory" else [ref]
                    require(isinstance(values, list),
                            f"{branch} UserD class evidence is malformed")
                    if name == "hUserdMemory":
                        require(0 < len(values) <= 32,
                                f"{branch} UserD class evidence has invalid cardinality")
                    for value in values:
                        require(isinstance(value, dict) and
                                set(value) == OBJECT_REF_FIELDS and
                                value.get("resolution") in OBJECT_RESOLUTIONS and
                                ((value.get("resolution") == "resolved" and
                                  type(value.get("classId")) is int and
                                  0 <= value["classId"] <= 0xffffffff) or
                                 (value.get("resolution") != "resolved" and
                                  value.get("classId") is None)),
                                f"{branch} handle class resolution is malformed")
    return {"identity": identity_result, "capture": capture,
            "records": channel_records}


def _histogram(values: list[object]) -> dict[str, int]:
    encoded = [json.dumps(value, sort_keys=True, separators=(",", ":")) for value in values]
    return dict(sorted(Counter(encoded).items()))


def _profile(item: dict[str, object]) -> dict[str, object]:
    capture = item["capture"]
    records = item["records"]
    assert isinstance(capture, dict) and isinstance(records, list)
    result: dict[str, object] = {
        "identity": item["identity"], "allocation_records": len(records),
        "payload_snapshots": capture["channel_payload_snapshots_read"],
        "class_id_histogram": {}, "phases": {},
        "object_class_resolution_compared":
            capture.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v9",
        "successful_syscalls": sum(row.get("syscall_return") == 0 for row in records),
    }
    class_ids = [f"0x{row['entry']['hClass']:04x}" for row in records]
    result["class_id_histogram"] = dict(sorted(Counter(class_ids).items()))
    phases: dict[str, object] = {}
    for phase in ("entry", "exit"):
        packets = [row[phase] for row in records]
        fields: dict[str, object] = {}
        profile_fields = (PROFILE_FIELDS + ("objectClasses",)
                          if capture.get("schema") == "nvidia-hybrid-rm-ioctl-observer-v9"
                          else PROFILE_FIELDS)
        for name in profile_fields:
            values = []
            for packet in packets:
                value = (packet[name] if name == "paramsSize" else
                         packet["channel"][name])
                values.append(value)
            fields[name] = _histogram(values)
        phases[phase] = fields
    result["phases"] = phases
    return result


def compare_reports(v100_report: object, blackwell_report: object) -> dict[str, object]:
    v100 = _branch_capture(v100_report, "v100")
    blackwell = _branch_capture(blackwell_report, "blackwell")
    v100_profile = _profile(v100)
    blackwell_profile = _profile(blackwell)
    differences = []
    comparable_fields = list(PROFILE_FIELDS)
    compare_object_classes = (
        v100["capture"].get("schema") == "nvidia-hybrid-rm-ioctl-observer-v9" and
        blackwell["capture"].get("schema") == "nvidia-hybrid-rm-ioctl-observer-v9")
    if compare_object_classes:
        comparable_fields.append("objectClasses")
    for phase in ("entry", "exit"):
        v100_fields = v100_profile["phases"][phase]
        blackwell_fields = blackwell_profile["phases"][phase]
        for field in comparable_fields:
            if v100_fields[field] != blackwell_fields[field]:
                differences.append({"phase": phase, "field": field,
                                    "v100": v100_fields[field],
                                    "blackwell": blackwell_fields[field]})
    return {
        "schema": "nvidia-hybrid-channel-alloc-comparison-v2",
        "qualification": "separate-installed-driver-channel-observation",
        "same_class_payload_size": True,
        "class_payload_size_bytes": 368,
        "v100": v100_profile,
        "blackwell": blackwell_profile,
        "differences": differences,
        "hybrid_compatibility_validated": False,
        "object_class_resolution_compared": compare_object_classes,
        "limitations": [
            "The V100/R580 and RTX5080/R595 captures ran in separate Linux kernels.",
            "Observed input packets are not a cross-driver allocation experiment.",
            "Matching structure layout does not prove matching handle ownership or RM behavior.",
            "This capture does not validate the experimental frontend, CUDA coexistence, UVM, P2P, or performance.",
        ],
    }


def _read_report(path: Path) -> tuple[object, dict[str, object]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), "input evidence must be a regular file")
        require(0 < metadata.st_size <= 50 * 1024 * 1024,
                "input evidence size is outside the accepted bound")
        raw = stream.read(50 * 1024 * 1024 + 1)
    require(0 < len(raw) <= 50 * 1024 * 1024 and len(raw) == metadata.st_size,
            "input evidence changed or exceeded the accepted bound")
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("input evidence is not valid UTF-8 JSON") from None
    return report, {"path": str(path.resolve()), "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest()}


def run(v100_path: Path, blackwell_path: Path, abi_path: Path,
        output_path: Path) -> dict[str, object]:
    require(not output_path.exists(), "refusing to overwrite existing comparison evidence")
    v100_report, v100_identity = _read_report(v100_path)
    blackwell_report, blackwell_identity = _read_report(blackwell_path)
    abi_report, abi_identity = _read_report(abi_path)
    require(isinstance(abi_report, dict) and
            abi_report.get("schema") in ("nvidia-hybrid-rm-ioctl-observer-build-v2",
                                          "nvidia-hybrid-rm-ioctl-observer-build-v3") and
            abi_report.get("qualification") == "repeatable-build-only-no-driver-execution",
            "pinned channel observer build report is missing")
    abi = abi_report.get("channel_payload_abi")
    require(isinstance(abi, dict) and abi.get("byte_identical") is True and
            abi.get("r580_version") == "580.178.04" and
            abi.get("r595_version") == "595.99.02" and
            abi.get("class_payload_size_bytes") == 368 and
            abi.get("r580_header_sha256") == CHANNEL_HEADER_SHA256 and
            abi.get("r595_header_sha256") == CHANNEL_HEADER_SHA256 and
            isinstance(abi.get("required_classes"), dict) and
            abi["required_classes"] == {
                "R580:BLACKWELL_CHANNEL_GPFIFO_A": True,
                "R580:VOLTA_CHANNEL_GPFIFO_A": True,
                "R595:BLACKWELL_CHANNEL_GPFIFO_A": True,
                "R595:VOLTA_CHANNEL_GPFIFO_A": True},
            "R580/R595 channel ABI evidence does not match this comparison")
    result = compare_reports(v100_report, blackwell_report)
    result["inputs"] = {"v100": v100_identity, "blackwell": blackwell_identity,
                        "channel_abi_build": abi_identity}
    tool_path = Path(__file__).resolve()
    result["tool"] = {"path": str(tool_path), "sha256": hashlib.sha256(
        tool_path.read_bytes()).hexdigest()}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v100", type=Path, required=True)
    parser.add_argument("--blackwell", type=Path, required=True)
    parser.add_argument("--abi-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run(args.v100, args.blackwell, args.abi_report, args.output)
    except (OSError, ValueError) as error:
        print(json.dumps({"qualification": "failed", "error": str(error)[:500]}))
        return 2
    print(json.dumps({"report": str(args.output), "qualification": report["qualification"],
                      "different_fields": [f"{row['phase']}.{row['field']}"
                                           for row in report["differences"]],
                      "hybrid_compatibility_validated": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
