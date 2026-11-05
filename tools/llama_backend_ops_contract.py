# SPDX-License-Identifier: MIT
"""Strict report checks for llama.cpp's test-backend-ops console output.

llama.cpp's upstream test-backend-ops returns success when a requested backend
is absent because it counts skipped backends as successful. Its CSV output also
omits the per-operation `passed` field. These checks require evidence that the
requested CUDA backend actually ran non-empty numerical comparisons.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_BACKEND_INIT = re.compile(r"^Backend (\d+)/(\d+): (.+)$")
_TEST_SUMMARY = re.compile(r"^\s*(\d+)/(\d+) tests passed\s*$")
_FA_VEC_SUMMARY = re.compile(r"^\s*fa_vec \(Q,NE\) slice: (\d+) cases run, (\d+) failed\s*$")


def canonical_pci(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]",
            value):
        raise ValueError("invalid PCI bus ID")
    domain, bus, slot_function = value.lower().split(":")
    if int(slot_function[:2], 16) > 31:
        raise ValueError("invalid PCI slot")
    return domain.zfill(8) + ":" + bus + ":" + slot_function


def target_cuda_ordinals(probe: object, expected_device_pci_by_sm: dict[int, str]) -> dict[int, int]:
    """Bind the two required architectures to ordinals from a passed probe."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(isinstance(probe, dict), "hybrid probe report must be an object")
    require(probe.get("schema") == "nvidia-hybrid-probe-v2" and
            probe.get("status") == "hybrid-validated" and
            probe.get("hybrid_validated") is True and
            probe.get("required_set_passed") is True and
            probe.get("context_coexistence_passed") is True,
            "same-process hybrid kernel acceptance has not passed")
    require(set(expected_device_pci_by_sm) == {70, 120},
            "both SM70 and SM120 PCI identities are required")
    expected = {sm: canonical_pci(pci) for sm, pci in expected_device_pci_by_sm.items()}
    require(len(set(expected.values())) == 2, "expected PCI identities must be unique")

    rows = probe.get("devices")
    require(isinstance(rows, list), "hybrid probe has no device inventory")
    ordinals: dict[int, int] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("targeted") is not True:
            continue
        sm = row.get("sm")
        require(type(sm) is int and sm in expected and sm not in ordinals,
                "hybrid probe has an unexpected or duplicate targeted architecture")
        require(canonical_pci(row.get("pci_bus_id")) == expected[sm],
                "targeted probe device does not match the pinned PCI identity")
        ordinal = row.get("ordinal")
        require(type(ordinal) is int and ordinal >= 0,
                "targeted probe device has an invalid CUDA ordinal")
        require(row.get("tested") is True and row.get("architecture_kernel_passed") is True and
                row.get("synchronous_passed") is True and row.get("asynchronous_passed") is True and
                row.get("cleanup_passed") is True and row.get("error") == "",
                "targeted hybrid probe device did not pass its numerical kernel checks")
        ordinals[sm] = ordinal
    require(set(ordinals) == {70, 120},
            "hybrid probe did not validate both pinned architectures")
    require(len(set(ordinals.values())) == 2,
            "hybrid probe assigned both devices the same CUDA ordinal")
    return ordinals


def validate_runtime_library_identities(actual: dict[str, list[dict[str, Any]]],
                                         expected: dict[str, dict[str, Any]]) -> None:
    """Require one exact hash-locked runtime library mapping per dependency."""
    if set(actual) != set(expected):
        raise ValueError("mapped CUDA runtime dependency set differs from the profile lock")
    for name, identity in expected.items():
        rows = actual[name]
        if len(rows) != 1:
            raise ValueError(f"expected exactly one mapped instance of {name}")
        observed = rows[0]
        if any(observed.get(key) != identity.get(key)
               for key in ("path", "bytes", "sha256", "device_major",
                           "device_minor", "inode")):
            raise ValueError(f"mapped CUDA runtime dependency identity differs for {name}")


def validate_backend_source_mapping(source: str) -> None:
    """Check pinned ggml CUDA source keeps backend ordinals aligned to CUDA IDs."""
    required = (
        "info.devices[id].physical_device = id % info.physical_device_count;",
        "dev_ctx->name = GGML_CUDA_NAME + std::to_string(i);",
        "const int physical_id = info.devices[i].physical_device;",
        "CUDA_CHECK(cudaDeviceGetPCIBusId(pci_bus_id, sizeof(pci_bus_id), physical_id));",
    )
    if not isinstance(source, str) or any(fragment not in source for fragment in required):
        raise ValueError("pinned ggml CUDA source no longer proves ordinal-to-PCI mapping")


def validate_acceptance_freshness(timestamp: object,
                                  now: datetime | None = None) -> int:
    """Require a timezone-aware hardware acceptance result no older than 15 minutes."""
    if not isinstance(timestamp, str):
        raise ValueError("hybrid acceptance receipt has no observation timestamp")
    try:
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("hybrid acceptance timestamp is malformed") from error
    if observed.tzinfo is None:
        raise ValueError("hybrid acceptance timestamp has no timezone")
    current = now or datetime.now(timezone.utc)
    age = (current.astimezone(timezone.utc) - observed.astimezone(timezone.utc)).total_seconds()
    if age < -60 or age > 900:
        raise ValueError("hybrid acceptance receipt is future-dated or older than 15 minutes")
    return max(0, int(age))


def all_backend_runs_passed(results: object) -> bool:
    """Require one fully validated, executed backend result for each GPU."""
    if not isinstance(results, list) or len(results) != 2:
        return False
    by_sm: dict[int, dict[str, Any]] = {}
    for row in results:
        if not isinstance(row, dict):
            return False
        sm = row.get("sm")
        if type(sm) is not int or sm in by_sm:
            return False
        summary = row.get("test_summary")
        if (row.get("not_run") is True or row.get("timed_out") is True or
                row.get("validation_error") or row.get("validation_errors") or
                type(row.get("exit_code")) is not int or row["exit_code"] != 0 or
                not isinstance(summary, dict) or
                type(summary.get("tests_total")) is not int or summary["tests_total"] <= 0 or
                type(summary.get("tests_passed")) is not int or
                summary.get("tests_passed") != summary.get("tests_total")):
            return False
        by_sm[sm] = row
    return set(by_sm) == {70, 120}


def validate_backend_ops_output(output: str, exit_code: int,
                                backend_name: str,
                                expected_description_fragment: str) -> dict[str, Any]:
    """Reject skipped/missing backends and empty or failed operation suites."""
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise ValueError(message)

    require(type(exit_code) is int, "test-backend-ops exit status must be an integer")
    require(isinstance(output, str), "test-backend-ops output must be text")
    require(isinstance(backend_name, str) and re.fullmatch(r"CUDA\d+", backend_name),
            "expected backend must be a CUDA ordinal name")
    require(isinstance(expected_description_fragment, str) and expected_description_fragment.strip(),
            "expected CUDA device description fragment is required")
    text = _ANSI.sub("", output).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.splitlines()
    require(exit_code == 0, "test-backend-ops exited unsuccessfully")

    device_counts = [int(match.group(1)) for line in lines
                     if (match := re.fullmatch(r"Testing (\d+) devices", line.strip()))]
    require(len(device_counts) == 1 and device_counts[0] > 0,
            "test-backend-ops did not report a non-empty backend inventory")

    starts = [(index, match) for index, line in enumerate(lines)
              if (match := _BACKEND_INIT.fullmatch(line.strip()))]
    target_starts = [(index, match) for index, match in starts
                     if match.group(3) == backend_name]
    require(len(target_starts) == 1,
            "requested CUDA backend was not enumerated exactly once")
    start_index, start_match = target_starts[0]
    backend_index, backend_count = int(start_match.group(1)), int(start_match.group(2))
    require(backend_count == device_counts[0] and 1 <= backend_index <= backend_count,
            "backend enumeration indices contradict the reported device count")
    next_start = next((index for index, _ in starts if index > start_index), len(lines))
    target_block = lines[start_index:next_start]
    init_block = target_block[1:]
    require(not any("skipping" in line.casefold() for line in init_block),
            "requested CUDA backend was enumerated but skipped")
    descriptions = [line.partition(":")[2].strip() for line in init_block
                    if line.strip().startswith("Device description:")]
    require(len(descriptions) == 1 and
            expected_description_fragment.casefold() in descriptions[0].casefold(),
            "requested CUDA ordinal description does not match the accepted GPU architecture")

    statuses = [line.strip() for line in target_block
                if re.fullmatch(rf"\s*Backend {re.escape(backend_name)}: (?:OK|FAIL)\s*", line)]
    require(statuses == [f"Backend {backend_name}: OK"],
            "requested CUDA backend did not report one successful execution")

    summaries = [tuple(map(int, match.groups())) for line in target_block
                 if (match := _TEST_SUMMARY.fullmatch(line))]
    require(len(summaries) == 1,
            "test-backend-ops did not emit exactly one operation-test summary")
    passed, total = summaries[0]
    require(total > 0 and passed == total,
            "operation tests were empty or at least one numerical comparison failed")

    fa_summaries = [tuple(map(int, match.groups())) for line in target_block
                    if (match := _FA_VEC_SUMMARY.fullmatch(line))]
    fa_vec_cases_run = fa_vec_failures = None
    if fa_summaries:
        require(len(fa_summaries) == 1,
                "FA vector slice summary was reported more than once")
        fa_vec_cases_run, fa_vec_failures = fa_summaries[0]
        require(fa_vec_cases_run > 0 and fa_vec_failures == 0,
                "FA vector slice summary is empty or reports a failure")
    return {
        "backend_name": backend_name,
        "backend_index_one_based": backend_index,
        "enumerated_backend_count": backend_count,
        "device_description": descriptions[0],
        "tests_passed": passed,
        "tests_total": total,
        "fa_vec_cases_run": fa_vec_cases_run,
        "fa_vec_failures": fa_vec_failures,
    }
