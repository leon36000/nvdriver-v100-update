# SPDX-License-Identifier: MIT
"""Fail-closed validation for the experimental CUDA VMM peer-read report."""

from __future__ import annotations

import re


TOP_REQUIRED = {
    "schema", "status", "passed", "direct_dma_attested", "directions", "error",
}
DIRECTION_REQUIRED = {
    "source_sm", "destination_sm", "source_pci_bus_id", "destination_pci_bus_id",
    "peer_capability", "allocation_granularity_bytes", "allocation_bytes",
    "allocation_created", "mapping_created", "access_configured",
    "source_access_verified", "destination_readonly_access_verified",
    "kernel_attempted", "kernel_passed", "cleanup_passed", "cleanup_errors", "error",
}
VALID_STATUSES = {
    "preflight-failed", "setup-failed", "vmm-peer-memory-failed",
    "one-way-vmm-peer-memory-verified", "vmm-peer-memory-verified",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _boolean(value: object, message: str) -> None:
    _require(type(value) is bool, message)


def _pci(value: object, message: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(
        r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value) is not None,
        message)
    return value.lower()


def validate_vmm_peer_report(report: object,
                             expected_pci_by_sm: dict[int, str] | None = None) -> None:
    _require(isinstance(report, dict), "VMM peer report must be an object")
    _require(TOP_REQUIRED.issubset(report), "VMM peer report is missing required fields")
    _require(report.get("schema") == "nvidia-hybrid-vmm-peer-probe-v1",
             "unsupported VMM peer report schema")
    status = report.get("status")
    _require(status in VALID_STATUSES, "unknown VMM peer status")
    _boolean(report.get("passed"), "VMM peer passed must be boolean")
    _boolean(report.get("direct_dma_attested"),
             "VMM peer DMA attestation flag must be boolean")
    _require(report.get("direct_dma_attested") is False,
             "VMM peer kernel result cannot attest physical DMA routing")
    _require(isinstance(report.get("error"), str), "VMM peer error must be text")
    directions = report.get("directions")
    _require(isinstance(directions, list) and len(directions) <= 2,
             "VMM peer directions must be a list of at most two entries")
    if status not in {"preflight-failed"}:
        _require(report.get("cuda_vmm_mode") ==
                 "explicit-vmm-access-no-cuCtxEnablePeerAccess",
                 "VMM peer report used an unexpected CUDA access mode")
        _require(type(report.get("driver_version")) is int and report["driver_version"] > 0,
                 "VMM peer report is missing the CUDA Driver API version")
        _require(isinstance(report.get("libcuda_path"), str) and report["libcuda_path"],
                 "VMM peer report is missing the loaded libcuda path")
        _require(isinstance(report.get("module_path"), str) and report["module_path"],
                 "VMM peer report is missing the loaded kernel module path")
        for sm in (70, 120):
            name = report.get(f"sm{sm}_name")
            _require(isinstance(name, str) and name,
                     f"VMM peer report is missing the SM{sm} device name")
            expected_model = "v100" if sm == 70 else "rtx 5080"
            _require(expected_model in name.lower(),
                     f"SM{sm} PCI device is not identified as the expected {expected_model.upper()} model")
            _require(_pci(report.get(f"sm{sm}_pci_bus_id"),
                          f"invalid top-level SM{sm} PCI identity"),
                     f"invalid top-level SM{sm} PCI identity")
        if expected_pci_by_sm is not None:
            _require(_pci(report["sm70_pci_bus_id"], "invalid SM70 PCI identity") ==
                     _pci(expected_pci_by_sm[70], "invalid expected SM70 PCI identity") and
                     _pci(report["sm120_pci_bus_id"], "invalid SM120 PCI identity") ==
                     _pci(expected_pci_by_sm[120], "invalid expected SM120 PCI identity"),
                     "top-level VMM peer identities differ from pinned GPU identities")

    seen: set[tuple[int, int]] = set()
    passed_directions = 0
    for direction in directions:
        _require(isinstance(direction, dict) and DIRECTION_REQUIRED == set(direction),
                 "VMM peer direction has unexpected or missing fields")
        source, destination = direction.get("source_sm"), direction.get("destination_sm")
        _require((source, destination) in {(70, 120), (120, 70)},
                 "VMM peer direction is not the pinned SM70/SM120 pair")
        _require((source, destination) not in seen, "duplicate VMM peer direction")
        seen.add((source, destination))
        for key in (
            "peer_capability", "allocation_created", "mapping_created", "access_configured",
            "source_access_verified", "destination_readonly_access_verified",
            "kernel_attempted", "kernel_passed", "cleanup_passed",
        ):
            _boolean(direction.get(key), f"VMM peer {key} must be boolean")
        for key in ("allocation_granularity_bytes", "allocation_bytes"):
            value = direction.get(key)
            _require(type(value) is int and value >= 0,
                     f"VMM peer {key} must be a non-negative integer")
        _require(isinstance(direction.get("cleanup_errors"), list) and
                 all(isinstance(item, str) for item in direction["cleanup_errors"]),
                 "VMM peer cleanup_errors must be a string list")
        _require(isinstance(direction.get("error"), str), "VMM peer direction error must be text")
        _pci(direction.get("source_pci_bus_id"), "invalid VMM source PCI identity")
        _pci(direction.get("destination_pci_bus_id"), "invalid VMM destination PCI identity")
        if expected_pci_by_sm is not None:
            _require(_pci(direction["source_pci_bus_id"], "invalid source PCI identity") ==
                     _pci(expected_pci_by_sm[source], "invalid expected PCI identity") and
                     _pci(direction["destination_pci_bus_id"], "invalid destination PCI identity") ==
                     _pci(expected_pci_by_sm[destination], "invalid expected PCI identity"),
                     "VMM peer direction differs from pinned GPU identities")
        if direction["kernel_passed"]:
            _require(direction["kernel_attempted"] and direction["allocation_created"] and
                     direction["mapping_created"] and direction["access_configured"] and
                     direction["source_access_verified"] and
                     direction["destination_readonly_access_verified"],
                     "VMM peer kernel success lacks allocation or permission proof")
            _require(direction["allocation_granularity_bytes"] > 0 and
                     direction["allocation_bytes"] >= direction["allocation_granularity_bytes"],
                     "VMM peer success has invalid allocation sizing")
            passed_directions += 1
        if direction["kernel_attempted"]:
            _require(direction["access_configured"] and
                     direction["source_access_verified"] and
                     direction["destination_readonly_access_verified"],
                     "VMM peer kernel attempt lacks verified VMM access permissions")
        if direction["cleanup_passed"]:
            _require(not direction["cleanup_errors"],
                     "VMM peer cleanup claims success while listing cleanup errors")
        else:
            _require(bool(direction["cleanup_errors"]),
                     "VMM peer cleanup failure lacks cleanup error evidence")

    _require(report["passed"] == (status == "vmm-peer-memory-verified"),
             "VMM peer pass flag disagrees with status")
    if status == "vmm-peer-memory-verified":
        _require(len(directions) == 2 and passed_directions == 2 and
                 {(70, 120), (120, 70)} == seen and report["cleanup_passed"] is True,
                 "bidirectional VMM success lacks both verified directions and clean teardown")
    if status == "one-way-vmm-peer-memory-verified":
        _require(len(directions) == 2 and passed_directions == 1,
                 "one-way VMM status requires exactly one successful direction")
    if status in {"setup-failed", "preflight-failed"}:
        _require(not report["passed"], "failed setup cannot pass")
    if "cleanup_passed" in report:
        _boolean(report["cleanup_passed"], "overall VMM cleanup_passed must be boolean")
        _require(report["cleanup_passed"] == all(d["cleanup_passed"] for d in directions),
                 "overall cleanup flag disagrees with directional results")
