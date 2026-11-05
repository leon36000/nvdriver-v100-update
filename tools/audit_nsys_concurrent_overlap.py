#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit real cross-GPU kernel overlap in an Nsight Systems SQLite export."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import quote


REQUIRED_SMS = {70, 120}
EXPECTED_KERNEL = "hybrid_concurrent_work"


def canonical_pci(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", value):
        raise ValueError("invalid expected PCI ID")
    domain, bus, slot_function = value.lower().split(":")
    if int(slot_function[:2], 16) > 31:
        raise ValueError("invalid expected PCI slot")
    return domain.zfill(8) + ":" + bus + ":" + slot_function


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    escaped = table.replace('"', '""')
    return {row[1] for row in connection.execute(f'PRAGMA table_info("{escaped}")')}


def _require_columns(connection: sqlite3.Connection, table: str,
                     required: set[str]) -> None:
    present = _columns(connection, table)
    if not required.issubset(present):
        raise ValueError(f"unsupported Nsight SQLite schema: {table} is missing required columns")


def audit_nsys_sqlite(trace_path: str | Path,
                      expected_device_pci_by_sm: dict[int, str]) -> dict:
    """Prove that the named GPU kernel intervals overlap in one Nsight trace DB.

    This only qualifies Nsight's GPU activity timeline. It is intentionally
    independent of host dispatch windows and does not certify CUDA correctness.
    """
    path = Path(trace_path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("Nsight SQLite trace must be a regular file")
    if not isinstance(expected_device_pci_by_sm, dict) or set(expected_device_pci_by_sm) != REQUIRED_SMS:
        raise ValueError("expected device map must pin exactly SM70 and SM120")
    normalized = {}
    for sm, bdf in expected_device_pci_by_sm.items():
        if type(sm) is not int or sm not in REQUIRED_SMS:
            raise ValueError("expected device map contains an invalid SM")
        normalized[sm] = canonical_pci(bdf)
    if len(set(normalized.values())) != 2:
        raise ValueError("expected device map reuses a PCI ID")

    before_hash = sha256(path)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as error:
        raise ValueError("Nsight SQLite trace cannot be opened read-only") from error
    try:
        connection.execute("PRAGMA query_only=ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",):
            raise ValueError("Nsight SQLite integrity check failed")
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"TARGET_INFO_GPU", "CUPTI_ACTIVITY_KIND_KERNEL", "StringIds"}.issubset(tables):
            raise ValueError("unsupported Nsight SQLite schema: required GPU/kernel tables are absent")
        _require_columns(connection, "TARGET_INFO_GPU", {"id", "busLocation", "name"})
        _require_columns(connection, "CUPTI_ACTIVITY_KIND_KERNEL",
                         {"start", "end", "deviceId", "shortName"})
        _require_columns(connection, "StringIds", {"id", "value"})

        gpu_rows = connection.execute(
            "SELECT id, busLocation, name FROM TARGET_INFO_GPU WHERE busLocation IS NOT NULL"
        ).fetchall()
        if not gpu_rows:
            raise ValueError("Nsight trace contains no PCI-addressed GPU metadata")
        gpu_by_pci: dict[str, list[tuple[int, str]]] = {}
        for gpu_id, bus_location, name in gpu_rows:
            if type(gpu_id) is not int or not isinstance(bus_location, str):
                raise ValueError("Nsight GPU identity row is malformed")
            try:
                bdf = canonical_pci(bus_location)
            except ValueError as error:
                raise ValueError("Nsight GPU metadata contains an invalid PCI address") from error
            gpu_by_pci.setdefault(bdf, []).append((gpu_id, name or ""))

        device_ids: dict[int, int] = {}
        device_names: dict[int, str] = {}
        for sm, bdf in normalized.items():
            matches = gpu_by_pci.get(bdf, [])
            if len(matches) != 1:
                raise ValueError(f"Nsight trace does not identify exactly one GPU at the pinned SM{sm} BDF")
            gpu_id, name = matches[0]
            if gpu_id in device_ids.values():
                raise ValueError("Nsight maps both required architectures to one GPU activity ID")
            device_ids[sm] = gpu_id
            device_names[sm] = name

        kernel_columns = _columns(connection, "CUPTI_ACTIVITY_KIND_KERNEL")
        has_demangled = "demangledName" in kernel_columns
        name_join = ("LEFT JOIN StringIds AS demangled ON demangled.id = k.demangledName"
                     if has_demangled else "")
        demangled_select = "demangled.value" if has_demangled else "NULL"
        event_rows = connection.execute(
            "SELECT k.start, k.end, k.deviceId, short.value, " + demangled_select +
            " FROM CUPTI_ACTIVITY_KIND_KERNEL AS k "
            "JOIN StringIds AS short ON short.id = k.shortName " + name_join +
            " WHERE k.deviceId IN (?, ?) ORDER BY k.start, k.end",
            (device_ids[70], device_ids[120])).fetchall()
        matching: dict[int, list[tuple[int, int]]] = {70: [], 120: []}
        for start, end, gpu_id, short_name, demangled_name in event_rows:
            if EXPECTED_KERNEL not in (short_name, demangled_name):
                continue
            if (type(start) is not int or type(end) is not int or
                    type(gpu_id) is not int or start < 0 or end <= start):
                raise ValueError("Nsight kernel activity has an invalid interval or device ID")
            sm = next((candidate for candidate, value in device_ids.items()
                       if value == gpu_id), None)
            if sm is None:
                raise ValueError("target kernel row has an unknown GPU activity ID")
            matching[sm].append((start, end))
        for sm in REQUIRED_SMS:
            if len(matching[sm]) != 1:
                raise ValueError(f"Nsight trace must contain exactly one {EXPECTED_KERNEL} interval for SM{sm}")

        interval70 = matching[70][0]
        interval120 = matching[120][0]
        overlap_start = max(interval70[0], interval120[0])
        overlap_end = min(interval70[1], interval120[1])
        if overlap_start >= overlap_end:
            raise ValueError("Nsight GPU kernel intervals do not overlap")
        export_version = None
        if "META_DATA_EXPORT" in tables and {"name", "value"}.issubset(
                _columns(connection, "META_DATA_EXPORT")):
            row = connection.execute(
                "SELECT value FROM META_DATA_EXPORT WHERE name='EXPORT_PRODUCT_VERSION'"
            ).fetchone()
            export_version = row[0] if row else None
    except sqlite3.Error as error:
        raise ValueError("Nsight SQLite query failed") from error
    finally:
        connection.close()

    after_hash = sha256(path)
    if before_hash != after_hash:
        raise ValueError("Nsight SQLite trace changed during the audit")
    return {
        "schema": "nvidia-hybrid-nsys-overlap-v1",
        "status": "validated-gpu-timeline-overlap",
        "trace_sha256": before_hash,
        "nsight_export_version": export_version,
        "timeline_source": "CUPTI_ACTIVITY_KIND_KERNEL.start/end (nanoseconds, same exported trace)",
        "kernel_name": EXPECTED_KERNEL,
        "gpu_timeline_overlap_validated": True,
        "host_dispatch_overlap_is_sufficient": False,
        "device_intervals": {
            "70": {"pci_bus_id": expected_device_pci_by_sm[70],
                   "gpu_name": device_names[70], "start_ns": interval70[0],
                   "end_ns": interval70[1]},
            "120": {"pci_bus_id": expected_device_pci_by_sm[120],
                    "gpu_name": device_names[120], "start_ns": interval120[0],
                    "end_ns": interval120[1]},
        },
        "overlap": {"start_ns": overlap_start, "end_ns": overlap_end,
                    "duration_ns": overlap_end - overlap_start},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-sqlite", type=Path, required=True,
                        help="Nsight Systems SQLite export; opened read-only")
    parser.add_argument("--expected-device", action="append", required=True,
                        metavar="SM=PCI", help="pin each of SM70 and SM120 by PCI BDF")
    args = parser.parse_args()
    expected = {}
    for value in args.expected_device:
        sm_text, separator, pci = value.partition("=")
        if not separator or not sm_text.isdigit():
            parser.error("--expected-device must use SM=PCI")
        sm = int(sm_text)
        try:
            normalized = canonical_pci(pci)
        except ValueError as error:
            parser.error(str(error))
        if sm not in REQUIRED_SMS or sm in expected:
            parser.error("--expected-device must uniquely pin SM70 and SM120")
        expected[sm] = pci
    if set(expected) != REQUIRED_SMS:
        parser.error("--expected-device must pin both SM70 and SM120")
    try:
        report = audit_nsys_sqlite(args.trace_sqlite, expected)
    except (OSError, ValueError) as error:
        print(json.dumps({"schema": "nvidia-hybrid-nsys-overlap-v1",
                          "status": "audit-failed", "error": str(error)},
                         sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
