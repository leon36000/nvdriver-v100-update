# SPDX-License-Identifier: MIT
"""Local compatibility check for the CUDA probe report protocol."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Callable


CONTRACT_SCHEMA = "nvidia-hybrid-probe-contract-v1"
REPORT_SCHEMA = "nvidia-hybrid-probe-v2"
REQUIRED_REPORT_FIELDS = {
    "memory_mode",
    "managed_prefetch_requested",
    "managed_prefetch_api",
    "devices",
    "cuda_graphs_requested",
    "cuda_graph_api",
}
REQUIRED_DEVICE_FIELDS = {
    "managed_memory_passed",
    "managed_prefetch_passed",
    "cuda_graphs_passed",
    "cuda_graph_launches",
}


def validate_probe_contract(
    probe_path: str | Path,
    expected_sha256: str | None = None,
    invoke: Callable = subprocess.run,
) -> dict[str, object]:
    """Require the probe build that reports the fields its runner validates.

    ``--contract`` is a no-CUDA command. Hash checks bind its response to the
    exact probe bytes prepared for upload and catch a local replacement race.
    """
    path = Path(probe_path).resolve(strict=True)
    try:
        before = path.read_bytes()
    except OSError:
        raise ValueError("CUDA probe artifact cannot be read") from None
    digest = hashlib.sha256(before).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("CUDA probe artifact changed before contract check")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("CUDA probe artifact is not an executable regular file")

    try:
        result = invoke(
            [str(path), "--contract"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("CUDA probe report contract could not be read") from None
    if result.returncode != 0:
        raise ValueError(
            "CUDA probe report contract is missing; rebuild the probe with tools/build_probe.py"
        )
    try:
        contract = json.loads(result.stdout)
    except (TypeError, ValueError):
        raise ValueError("CUDA probe report contract is malformed") from None
    if not isinstance(contract, dict):
        raise ValueError("CUDA probe report contract is malformed")
    version = contract.get("contract_version")
    probe_fields = contract.get("probe_report_fields")
    device_fields = contract.get("device_report_fields")
    if (contract.get("schema") != CONTRACT_SCHEMA or
            type(version) is not int or version < 1 or
            contract.get("probe_report_schema") != REPORT_SCHEMA or
            not isinstance(probe_fields, list) or
            any(type(field) is not str for field in probe_fields) or
            not REQUIRED_REPORT_FIELDS.issubset(probe_fields) or
            not isinstance(device_fields, list) or
            any(type(field) is not str for field in device_fields) or
            not REQUIRED_DEVICE_FIELDS.issubset(device_fields)):
        raise ValueError("CUDA probe report contract is incompatible")

    try:
        after_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise ValueError("CUDA probe artifact changed during contract check") from None
    if after_digest != digest:
        raise ValueError("CUDA probe artifact changed during contract check")
    return {
        "schema": CONTRACT_SCHEMA,
        "contract_version": version,
        "probe_report_schema": REPORT_SCHEMA,
        "probe_sha256": digest,
    }
