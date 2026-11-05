#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Correlate RM_CONTROL objects to prior live allocations without exporting handles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 8192
OBSERVER_SCHEMA = "nvidia-hybrid-rm-ioctl-observer-v5"
HEADER_SCOPE = "fixed NVOS54 RM_CONTROL headers only; nested parameter payloads omitted"
NV01_ROOT_CLIENT = 0x41
NV2081_BINAPI = 0x2081
NV2081_CONTROL = 0x20810108
NVOS54_FLAGS_FINN_SERIALIZED = 0x00000004


def find_observer_report(value: Any) -> dict[str, Any]:
    """Return the single v5 observer object embedded in a direct or wrapped report."""
    found: list[dict[str, Any]] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            if (item.get("schema") == OBSERVER_SCHEMA and
                    isinstance(item.get("records"), list)):
                found.append(item)
                return
            for nested in item.values():
                visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    if len(found) != 1:
        raise ValueError("input must contain exactly one R580/R595 observer-v5 report")
    return found[0]


def _uint(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _successful_syscall(record: dict[str, Any]) -> bool:
    return _uint(record.get("syscall_return")) == 0


def correlate(observer: dict[str, Any], source_sha256: str, *,
              case_name: str) -> dict[str, Any]:
    """Replay successful alloc/free headers and emit class-only control evidence."""
    if not re.fullmatch(r"[a-f0-9]{64}", source_sha256):
        raise ValueError("source digest must be a lowercase SHA-256")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", case_name):
        raise ValueError("case name must be a short lowercase token")
    if observer.get("schema") != OBSERVER_SCHEMA:
        raise ValueError("only the pinned fixed-header observer-v5 schema is accepted")
    if observer.get("trace_complete") is not True:
        raise ValueError("observer trace must be complete")
    if observer.get("nested_pointers_read") is not False:
        raise ValueError("observer report must not include nested payload reads")
    if observer.get("payload_scope") != HEADER_SCOPE:
        raise ValueError("observer report is outside fixed RM_CONTROL header scope")
    if observer.get("errors") != []:
        raise ValueError("observer report contains errors")
    records = observer.get("records")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("observer record list is invalid or exceeds its bound")

    # Values stay process-local. Only the typed class IDs and structural booleans
    # leave this function, never RM handles or user-space addresses.
    live: dict[tuple[int, int], int | None] = {}
    controls: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("observer record is malformed")
        entry = record.get("entry")
        exit_packet = record.get("exit")
        if not isinstance(entry, dict):
            entry = {}
        if not isinstance(exit_packet, dict):
            exit_packet = {}

        if (record.get("operation") == "alloc" and _successful_syscall(record) and
                _uint(exit_packet.get("status")) == 0):
            obj = _uint(exit_packet.get("hObjectNew"))
            root = _uint(entry.get("hRoot"))
            if entry.get("root_class") is True and root == 0:
                root = obj
            klass = _uint(exit_packet.get("hClass"))
            if root and obj and klass is not None:
                key = (root, obj)
                if key in live:
                    # A duplicate live identity is ambiguous; preserve that fact
                    # rather than assigning whichever class happened to arrive last.
                    live[key] = None
                else:
                    live[key] = klass
            continue

        if (record.get("operation") == "free" and _successful_syscall(record) and
                _uint(exit_packet.get("status")) == 0):
            root = _uint(entry.get("hRoot"))
            obj = _uint(entry.get("hObjectOld"))
            if root and obj == root:
                live = {key: klass for key, klass in live.items() if key[0] != root}
            elif root and obj:
                live.pop((root, obj), None)
            continue

        if (record.get("operation") != "rm_control_header" or
                _uint(entry.get("command")) != NV2081_CONTROL):
            continue

        client = _uint(entry.get("hClient"))
        obj = _uint(entry.get("hObject"))
        client_class = live.get((client, client)) if client else None
        object_class = live.get((client, obj)) if client and obj else None
        stable_fields = ("command", "flags", "params_size", "hClient", "hObject")
        flags = _uint(entry.get("flags"))
        controls.append({
            "record_index": index,
            "command": NV2081_CONTROL,
            "params_size": _uint(entry.get("params_size")),
            "flags": flags,
            "outer_finn_serialized_flag_set": (flags is not None and
                                                bool(flags & NVOS54_FLAGS_FINN_SERIALIZED)),
            "transport_success": _successful_syscall(record),
            "entry_status": _uint(entry.get("status")),
            "exit_status": _uint(exit_packet.get("status")),
            "header_stable": all(entry.get(key) == exit_packet.get(key)
                                  for key in stable_fields),
            "client_root_class_id": client_class,
            "object_class_id": object_class,
            "client_root_is_nv01_root_client": client_class == NV01_ROOT_CLIENT,
            "object_is_nv2081_binapi": object_class == NV2081_BINAPI,
        })

    correlated = bool(controls) and all(
        control["client_root_is_nv01_root_client"] and
        control["object_is_nv2081_binapi"] and control["header_stable"]
        for control in controls)
    return {
        "schema": "nvidia-hybrid-rm-object-correlation-v1",
        "qualification": ("nv2081-control-object-correlated" if correlated else
                          "nv2081-control-object-unresolved" if controls else
                          "no-target-control-observed"),
        "case": case_name,
        "source_sha256": source_sha256,
        "observer_schema": OBSERVER_SCHEMA,
        "trace_complete": True,
        "nested_pointers_read": False,
        "scope": "ordered successful RM_ALLOC/RM_FREE headers joined to NV2081 RM_CONTROL headers; handles and addresses omitted",
        "control_count": len(controls),
        "controls": controls,
    }


def read_input(path: Path) -> tuple[bytes, dict[str, Any]]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
        raise ValueError("input must be a regular JSON file within the 64 MiB bound")
    data = path.read_bytes()
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the 64 MiB bound")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("input is not valid UTF-8 JSON") from exc
    if not isinstance(value, (dict, list)):
        raise ValueError("input JSON must be an object or list")
    return data, value


def write_private_exclusive(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise FileNotFoundError("output directory does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="observer-v5 report or wrapper containing exactly one")
    parser.add_argument("--output", required=True, type=Path,
                        help="new, private sanitized JSON report")
    parser.add_argument("--case", required=True,
                        help="short label such as v100 or rtx5080")
    args = parser.parse_args(argv)
    try:
        raw, wrapper = read_input(args.input)
        observer = find_observer_report(wrapper)
        result = correlate(observer, hashlib.sha256(raw).hexdigest(),
                          case_name=args.case)
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_private_exclusive(args.output, encoded)
    except (OSError, ValueError) as exc:
        print(f"correlation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"case": result["case"],
                      "qualification": result["qualification"],
                      "control_count": result["control_count"],
                      "output_mode": "0600"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
