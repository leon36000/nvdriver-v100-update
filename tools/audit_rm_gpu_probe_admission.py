#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Trace pinned NVIDIA OpenRM PCI admission through GV100 HAL selection.

This is a bounded source-text audit of exact local release archives. It does
not build, load, or execute a driver and cannot establish hardware behavior.
The PCI predicate check accepts only the audited straight-line if/return
subset; it is not a general C parser or proof of arbitrary C control flow.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.compare_openrm_gv100 import (  # noqa: E402
    FILES as GENERATED_FILES,
    INPUTS as RELEASE_INPUTS,
    SOURCE_COMMITS,
    _read_regular_snapshot,
    parse_generated_sources,
)
from tools.probe_r615_gv100_dispatch import (  # noqa: E402
    write_private_evidence_report,
)

AUDITED_VERSIONS = (
    "580.196.07", "580.178.04", "595.104.02", "595.112.07",
    "610.57.04", "615.71.10", "615.78.08",
)
SOURCE_FILES = (
    "kernel-open/nvidia/nv-pci-table.c",
    "kernel-open/nvidia/nv-pci.c",
    "src/nvidia/arch/nvalloc/unix/src/osapi.c",
    "src/nvidia/src/kernel/core/hal_mgr.c",
    *GENERATED_FILES,
)
DEFAULT_REPORT = ROOT / "evidence/rm-pci-to-hal-admission-v7-20261023.json"


def _skip_space_and_comments(source: str, offset: int) -> int:
    """Skip C whitespace/comments from offset; return first code character."""
    while offset < len(source):
        if source[offset].isspace():
            offset += 1
        elif source.startswith("//", offset):
            newline = source.find("\n", offset + 2)
            if newline < 0:
                return len(source)
            offset = newline + 1
        elif source.startswith("/*", offset):
            end = source.find("*/", offset + 2)
            if end < 0:
                raise ValueError("unterminated C block comment")
            offset = end + 2
        else:
            return offset
    return offset


def _code_only(source: str) -> str:
    """Blank C comments and literals while preserving offsets and newlines."""
    output = list(source)
    state = "code"
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block-comment":
            if char == "*" and following == "/":
                output[index] = output[index + 1] = " "
                state = "code"
                index += 1
            elif char != "\n":
                output[index] = " "
        elif state in ("string", "character"):
            if char != "\n":
                output[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "character" and char == "'"
            ):
                state = "code"
        elif char == "/" and following == "/":
            output[index] = output[index + 1] = " "
            state = "line-comment"
            index += 1
        elif char == "/" and following == "*":
            output[index] = output[index + 1] = " "
            state = "block-comment"
            index += 1
        elif char == '"':
            output[index] = " "
            state = "string"
        elif char == "'":
            output[index] = " "
            state = "character"
        index += 1
    if state == "block-comment":
        raise ValueError("unterminated C block comment")
    if state in ("string", "character"):
        raise ValueError("unterminated C literal")
    return "".join(output)


def _return_expressions(source: str) -> list[str]:
    """Extract active return expressions from a C statement fragment."""
    code = _code_only(source)
    return [re.sub(r"\s+", " ", match.group(1)).strip()
            for match in re.finditer(r"\breturn\s+([^;]+);", code)]


def _if_branches(source: str) -> list[tuple[str, str, bool, bool]]:
    """Return un-nested if conditions, bodies, and else-branch presence.

    This deliberately recognizes only direct guards in a function body. Nested
    conditions are omitted so a dead or conditional block cannot satisfy an
    admission predicate accidentally.
    """
    code = _code_only(source)
    branches = []
    for match in re.finditer(r"\bif\s*\(", code):
        depth = code[:match.start()].count("{") - code[:match.start()].count("}")
        if depth != 0:
            continue
        condition_open = code.find("(", match.start(), match.end())
        condition_end = _matching_delimiter(code, condition_open, "(", ")")
        body_start = _skip_space_and_comments(code, condition_end + 1)
        if body_start >= len(code):
            raise ValueError("if condition is missing its body")
        braced_body = code[body_start] == "{"
        if braced_body:
            body_end = _matching_delimiter(code, body_start, "{", "}")
            body = code[body_start + 1:body_end]
        else:
            body_end = code.find(";", body_start)
            if body_end < 0:
                raise ValueError("if statement is missing its terminating semicolon")
            body = code[body_start:body_end + 1]
        after_body = _skip_space_and_comments(code, body_end + 1)
        has_else = re.match(r"\belse\b", code[after_body:]) is not None
        branches.append((code[condition_open + 1:condition_end], body,
                         has_else, braced_body))
    return branches


def _validate_simple_guard_flow(source: str,
                                branches: list[tuple[str, str, bool, bool]],
                                context: str) -> None:
    """Fail closed unless a PCI predicate uses only direct if/return guards.

    These audited bodies contain no labels, jumps, loops, switch statements,
    conditional expressions, preprocessor directives, nested ifs, or extra
    blocks. This deliberately recognizes a small C subset.
    """
    code = _code_only(source)
    unsupported = re.search(
        r"\b(?:goto|switch|case|while|for|do|break|continue|else)\b|[:#]",
        code,
    )
    total_if_statements = len(re.findall(r"\bif\s*\(", code))
    braced_guard_count = sum(braced for _condition, _body, _else, braced in branches)
    if (unsupported is not None or total_if_statements != len(branches) or
            code.count("{") != braced_guard_count or
            code.count("}") != braced_guard_count):
        raise ValueError(f"{context} contains unsupported control flow")


def _has_if_rejecting_call(source: str, call_name: str, *, negated: bool) -> bool:
    """Check a complete, direct call condition with only a false return body."""
    expected_call = re.escape(call_name) + r"\([^()]*\)"
    expected_condition = (r"!\s*" if negated else "") + expected_call
    for condition, body, has_else, _braced in _if_branches(source):
        if (re.fullmatch(expected_condition, condition.strip()) and not has_else and
                _normalized_expression(_code_only(body)) == "returnNV_FALSE;"):
            return True
    return False


def _normalized_expression(expression: str) -> str:
    return re.sub(r"\s+", "", expression)


def _matching_delimiter(source: str, start: int, opening: str, closing: str) -> int:
    """Return a balanced C delimiter, ignoring quoted text and comments."""
    if start >= len(source) or source[start] != opening:
        raise ValueError(f"expected {opening!r} delimiter")
    depth = 0
    index = start
    state = "code"
    escaped = False
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("string", "character"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "character" and char == "'"
            ):
                state = "code"
        elif char == "/" and following == "/":
            state = "line-comment"
            index += 1
        elif char == "/" and following == "*":
            state = "block-comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "character"
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                raise ValueError("unbalanced C delimiters")
        index += 1
    raise ValueError(f"unterminated C {opening}{closing} block")


def extract_function_body(source: str, name: str) -> str:
    """Extract one C function definition, rejecting missing/ambiguous names."""
    source = _code_only(source)
    definitions = []
    for match in re.finditer(r"\b" + re.escape(name) + r"\s*\(", source):
        open_paren = source.find("(", match.start(), match.end())
        close_paren = _matching_delimiter(source, open_paren, "(", ")")
        body_start = _skip_space_and_comments(source, close_paren + 1)
        if body_start < len(source) and source[body_start] == "{":
            body_end = _matching_delimiter(source, body_start, "{", "}")
            definitions.append(source[body_start + 1:body_end])
    if len(definitions) != 1:
        raise ValueError(f"expected one C definition of {name}, found {len(definitions)}")
    return definitions[0]


def _source_line(source: str, symbol: str) -> int:
    code = _code_only(source)
    for match in re.finditer(r"\b" + re.escape(symbol) + r"\s*\(", code):
        open_paren = code.find("(", match.start(), match.end())
        close_paren = _matching_delimiter(code, open_paren, "(", ")")
        body_start = _skip_space_and_comments(code, close_paren + 1)
        if body_start < len(code) and code[body_start] == "{":
            return source.count("\n", 0, match.start()) + 1
    raise ValueError(f"could not locate source definition {symbol}")


def _table_body(source: str) -> str:
    source = _code_only(source)
    matches = list(re.finditer(
        r"struct\s+pci_device_id\s+nv_pci_table\s*\[\s*\]\s*=\s*\{",
        source,
    ))
    if len(matches) != 1:
        raise ValueError(f"expected one nv_pci_table definition, found {len(matches)}")
    start = source.find("{", matches[0].start(), matches[0].end())
    end = _matching_delimiter(source, start, "{", "}")
    return source[start + 1:end]


def _check_pci_table(source: str) -> dict:
    body = _table_body(source)
    devices = [value.strip() for value in re.findall(r"\.device\s*=\s*([^,}]+)", body)]
    vendors = [value.strip() for value in re.findall(r"\.vendor\s*=\s*([^,}]+)", body)]
    classes = re.findall(r"\.class\s*=\s*\(\s*(PCI_CLASS_DISPLAY_(?:VGA|3D))\s*<<\s*8\s*\)", body)
    if len(devices) != 2 or any(value != "PCI_ANY_ID" for value in devices):
        raise ValueError("nv_pci_table is no longer the expected generation-agnostic display table")
    if len(vendors) != 2 or any(value != "PCI_VENDOR_ID_NVIDIA" for value in vendors):
        raise ValueError("nv_pci_table vendor filter changed")
    if set(classes) != {"PCI_CLASS_DISPLAY_VGA", "PCI_CLASS_DISPLAY_3D"}:
        raise ValueError("nv_pci_table display class rows changed")
    if body.count("PCI_ANY_ID") < 6 or len(re.findall(r"\.class_mask\s*=\s*~0", body)) != 2:
        raise ValueError("nv_pci_table wildcard match fields changed")
    return {
        "generation_agnostic": True,
        "device_id_entries": devices,
        "vendor_entries": vendors,
        "display_classes": sorted(set(classes)),
        "matches_specific_generation_id": False,
    }


def _check_gpu_class_filter(osapi: str) -> dict:
    wrapper = extract_function_body(osapi, "rm_is_supported_pci_device")
    try:
        classifier = extract_function_body(osapi, "rm_is_nvidia_gpu_device")
        classifier_form = "shared-helper"
    except ValueError as error:
        if "found 0" not in str(error):
            raise
        # R580 and R595 keep the same generic class checks inline in the PCI
        # predicate; R615 factors them into rm_is_nvidia_gpu_device().
        classifier = wrapper
        classifier_form = "inline-in-pci-predicate"
    legacy_device = extract_function_body(osapi, "rm_is_legacy_device")
    classifier_code = _code_only(classifier)
    wrapper_code = _code_only(wrapper)
    constants = {
        name: re.search(
            r"\b" + re.escape(name) + r"\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)",
            classifier_code,
        )
        for name in (
            "nv_pci_vendor_id", "nv_pci_id_riva_tnt", "nv_pci_class_display",
            "nv_pci_subclass_display_vga", "nv_pci_subclass_display_3d",
        )
    }
    if any(match is None for match in constants.values()):
        raise ValueError("generic NVIDIA PCI class filter constants changed")
    values = {name: int(match.group(1), 0) for name, match in constants.items()}
    expected = {
        "nv_pci_vendor_id": 0x10DE,
        "nv_pci_id_riva_tnt": 0x20,
        "nv_pci_class_display": 0x03,
        "nv_pci_subclass_display_vga": 0x00,
        "nv_pci_subclass_display_3d": 0x02,
    }
    if values != expected:
        raise ValueError("generic NVIDIA PCI class filter values changed")
    branches = _if_branches(classifier_code)
    _validate_simple_guard_flow(classifier_code, branches, "generic PCI classifier")
    expected_conditions = [
        "pci_class!=nv_pci_class_display",
        "(pci_subclass!=nv_pci_subclass_display_vga)&&(pci_subclass!=nv_pci_subclass_display_3d)",
        "vendor!=nv_pci_vendor_id",
        "device<nv_pci_id_riva_tnt",
    ]
    if classifier_form == "inline-in-pci-predicate":
        expected_conditions.append(
            "rm_is_legacy_device(device,subsystem_vendor,subsystem_device,print_legacy_warning)"
        )
    conditions = [_normalized_expression(condition)
                  for condition, _body, _else, _braced in branches]
    if (conditions != list(expected_conditions) or
            any(has_else or _normalized_expression(_code_only(body)) != "returnNV_FALSE;"
                for _condition, body, has_else, _braced in branches) or
            _return_expressions(classifier_code) !=
            ["NV_FALSE"] * len(expected_conditions) + ["NV_TRUE"]):
        raise ValueError("generic NVIDIA PCI class checks changed")
    wrapper_branches = _if_branches(wrapper_code)
    _validate_simple_guard_flow(wrapper_code, wrapper_branches,
                                "generic PCI filter wrapper")
    if classifier_form == "shared-helper":
        wrapper_conditions = [
            _normalized_expression(condition)
            for condition, _body, _else, _braced in wrapper_branches
        ]
        if (len(wrapper_branches) != 2 or
                re.fullmatch(r"!rm_is_nvidia_gpu_device\([^()]*\)",
                             wrapper_conditions[0] if wrapper_conditions else "") is None or
                re.fullmatch(r"rm_is_legacy_device\([^()]*\)",
                             wrapper_conditions[1] if len(wrapper_conditions) > 1 else "") is None or
                any(has_else or _normalized_expression(_code_only(body)) != "returnNV_FALSE;"
                    for _condition, body, has_else, _braced in wrapper_branches)):
            raise ValueError("generic PCI filter wrapper control flow changed")
    if not _has_if_rejecting_call(wrapper_code, "rm_is_legacy_device", negated=False):
        raise ValueError("generic PCI filter no longer rejects legacy-device matches")
    if "halmgrGetHalForGpu" in wrapper_code:
        raise ValueError("generic PCI filter is not generic")
    if classifier_form == "shared-helper" and not _has_if_rejecting_call(
        wrapper_code, "rm_is_nvidia_gpu_device", negated=True
    ):
        raise ValueError("generic PCI filter no longer rejects classifier failures")
    expected_wrapper_returns = (
        ["NV_FALSE"] * 2 + ["NV_TRUE"]
        if classifier_form == "shared-helper"
        else ["NV_FALSE"] * 5 + ["NV_TRUE"]
    )
    if _return_expressions(wrapper_code) != expected_wrapper_returns:
        raise ValueError("generic PCI filter has an ambiguous return path")
    legacy_returns = _return_expressions(legacy_device)
    if not legacy_returns or any(value != "NV_FALSE" for value in legacy_returns):
        raise ValueError("legacy device policy is not statically false")
    return {
        "generic_pci_filter_has_no_hal_lookup": True,
        "vendor_id": values["nv_pci_vendor_id"],
        "display_class": values["nv_pci_class_display"],
        "display_subclasses": [0x00, 0x02],
        "minimum_device_id": values["nv_pci_id_riva_tnt"],
        "legacy_device_filter_returns_false": True,
        "classifier_form": classifier_form,
    }


def _check_hal_error_path(osapi: str, hal_manager: str) -> dict:
    legacy_arch = extract_function_body(osapi, "rm_is_legacy_arch")
    legacy_arch_compact = _normalized_expression(_code_only(legacy_arch))
    legacy_arch_false = legacy_arch_compact in (
        "returnNV_FALSE;",
        "NvBoollegacy=NV_FALSE;returnlegacy;",
    )
    supported = extract_function_body(osapi, "rm_is_supported_device")
    supported_code = _code_only(supported)
    hal_call = re.search(r"\brmStatus\s*=\s*halmgrGetHalForGpu\s*\(", supported_code)
    if hal_call is None:
        raise ValueError("supported-device gate no longer selects a HAL")
    hal_failure = re.search(r"if\s*\(\s*rmStatus\s*!=\s*NV_OK\s*\)", supported_code[hal_call.end():])
    if hal_failure is None:
        raise ValueError("HAL error condition changed")
    condition_start = hal_call.end() + hal_failure.start()
    condition_open = condition_start + hal_failure.group(0).find("(")
    condition_end = _matching_delimiter(supported_code, condition_open, "(", ")")
    failure_start = _skip_space_and_comments(supported_code, condition_end + 1)
    if failure_start >= len(supported_code) or supported_code[failure_start] != "{":
        raise ValueError("HAL error branch lost its explicit body")
    failure_end = _matching_delimiter(supported_code, failure_start, "{", "}")
    error_branch = supported_code[failure_start + 1:failure_end]
    label = re.search(r"\bprint_unsupported\s*:", supported_code[failure_end + 1:])
    teardown = re.search(r"\bthreadfree\s*:", supported_code[failure_end + 1:])
    if label is None or teardown is None:
        raise ValueError("firmware-capability fallback labels changed")
    label_start = failure_end + 1 + label.end()
    teardown_start = failure_end + 1 + teardown.start()
    print_path = supported_code[label_start:teardown_start]
    final_return = re.search(r"\breturn\s+rmStatus\s*;", supported_code[teardown_start:])
    firmware_fallback = (
        "gpumgrIsDeviceRmFirmwareCapable" in error_branch
        and re.search(r"goto\s+print_unsupported\s*;", error_branch) is not None
        and re.search(r"goto\s+threadfree\s*;", error_branch) is not None
        and re.search(r"\brmStatus\s*=", error_branch) is None
        and re.search(r"\brmStatus\s*=", print_path) is None
        and final_return is not None
    )
    hal_body = extract_function_body(hal_manager, "halmgrGetHalForGpu_IMPL")
    hal_body_code = _code_only(hal_body)
    null_hal_skip = bool(re.search(
        r"\bpHal\s*=\s*pHalMgr->pHalList\s*\[[^]]+\]\s*;\s*"
        r"if\s*\(\s*pHal\s*==\s*NULL\s*\)\s*continue\s*;",
        hal_body_code,
    ))
    if not legacy_arch_false:
        raise ValueError("legacy architecture gate is not statically disabled")
    if not null_hal_skip or "NV_ERR_NOT_SUPPORTED" not in _return_expressions(hal_body_code):
        raise ValueError("HAL manager no longer skips NULL entries and rejects no match")
    if not firmware_fallback:
        raise ValueError("firmware-capability fallback may bypass the HAL error")
    return {
        "rm_is_legacy_arch_returns_false": True,
        "rm_is_supported_device_calls_hal_selector": True,
        "hal_manager_skips_null_hal_entries": True,
        "hal_manager_no_match_status": "NV_ERR_NOT_SUPPORTED",
        "firmware_capability_does_not_accept_missing_hal": True,
    }


def parse_gpu_probe_admission(version: str, texts: dict[str, str]) -> dict:
    """Analyze the source-level PCI -> RM -> generated HAL admission chain."""
    required = set(SOURCE_FILES)
    missing = sorted(required - set(texts))
    if missing:
        raise ValueError(f"missing source for {version}: {', '.join(missing)}")
    pci = texts["kernel-open/nvidia/nv-pci-table.c"]
    pci_probe = texts["kernel-open/nvidia/nv-pci.c"]
    osapi = texts["src/nvidia/arch/nvalloc/unix/src/osapi.c"]
    hal_manager = texts["src/nvidia/src/kernel/core/hal_mgr.c"]
    table = _check_pci_table(pci)
    pci_filter = _check_gpu_class_filter(osapi)
    hal_gate = _check_hal_error_path(osapi, hal_manager)
    try:
        probe_name = "nv_pci_probe_body"
        probe = extract_function_body(pci_probe, probe_name)
    except ValueError as error:
        if "found 0" not in str(error):
            raise
        # Earlier releases keep probe logic in nv_pci_probe; newer releases
        # split the deferred wrapper from nv_pci_probe_body.
        probe_name = "nv_pci_probe"
        probe = extract_function_body(pci_probe, probe_name)
    gate_calls = (
        "rm_is_supported_pci_device(",
        "pci_enable_device(",
        "rm_is_supported_device(",
        "rm_init_private_state(",
    )
    probe_code = _code_only(probe)
    positions = [probe_code.find(call) for call in gate_calls]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise ValueError("probe gate order changed")
    generated_texts = {path: texts[path] for path in GENERATED_FILES}
    generated = parse_generated_sources(version, generated_texts)
    if generated["source_profile"] != "gv100-disabled-in-generated-profile":
        raise ValueError(f"{version} GV100 generated profile is not proven disabled")
    table_digest = hashlib.sha256(pci.encode("utf-8")).hexdigest()
    return {
        "version": version,
        "pci_table_sha256": table_digest,
        "pci_table_is_generation_agnostic": table["generation_agnostic"],
        "pci_table": table,
        "generic_pci_filter_has_no_hal_lookup": pci_filter["generic_pci_filter_has_no_hal_lookup"],
        "generic_pci_filter": pci_filter,
        "probe_gate_precedes_private_rm_init": True,
        "probe_gate_order": list(gate_calls),
        "source_locations": {
            probe_name: _source_line(pci_probe, probe_name),
            "rm_is_supported_device": _source_line(osapi, "rm_is_supported_device"),
            "rm_is_supported_pci_device": _source_line(osapi, "rm_is_supported_pci_device"),
            "halmgrGetHalForGpu_IMPL": _source_line(hal_manager, "halmgrGetHalForGpu_IMPL"),
        },
        **hal_gate,
        "generated_profile_disables_gv100": True,
        "generated_profile": generated,
        "rm_support_gate_requires_registered_hal": True,
        "source_conclusion": "generic-pci-match-no-gv100-admission-established-in-audited-generated-openrm-profile",
    }


def _inspect_archive(cache: Path, version: str, filename: str, prefix: str,
                     expected_digest: str) -> dict:
    path = cache / filename
    snapshot = _read_regular_snapshot(path)
    digest = hashlib.sha256(snapshot).hexdigest()
    if digest != expected_digest:
        raise ValueError(f"{version} source archive digest differs from pinned input")
    wanted = {prefix + "/" + relative for relative in SOURCE_FILES}
    found: dict[str, list[tarfile.TarInfo]] = {}
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:*") as archive:
        for member in archive.getmembers():
            if member.name in wanted:
                found.setdefault(member.name, []).append(member)
        texts, file_hashes = {}, {}
        for relative in SOURCE_FILES:
            member_name = prefix + "/" + relative
            matches = found.get(member_name, [])
            if len(matches) != 1 or not matches[0].isfile():
                raise ValueError(f"expected one regular source member: {member_name}")
            payload_file = archive.extractfile(matches[0])
            if payload_file is None:
                raise ValueError(f"unable to read source member: {member_name}")
            payload = payload_file.read()
            try:
                texts[relative] = payload.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ValueError(f"source member is not UTF-8: {member_name}") from error
            file_hashes[relative] = {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
    return {
        "archive": str(path.resolve()),
        "archive_sha256": digest,
        "repository_tag": version,
        "repository_commit": SOURCE_COMMITS.get(version),
        "source_files": file_hashes,
        **parse_gpu_probe_admission(version, texts),
    }


def _fingerprints() -> dict[str, str]:
    paths = (
        Path(__file__).resolve(strict=True),
        ROOT / "tests/test_audit_rm_gpu_probe_admission.py",
        ROOT / "tools/compare_openrm_gv100.py",
        ROOT / "tools/probe_r615_gv100_dispatch.py",
    )
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".cache/upstream")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT,
                        help="new JSON path under evidence/; overwrite refused")
    args = parser.parse_args()
    try:
        by_version = {entry[0]: entry for entry in RELEASE_INPUTS}
        if set(AUDITED_VERSIONS) - set(by_version):
            raise ValueError("pinned release input list is missing an audited version")
        results = [
            _inspect_archive(args.cache, *by_version[version])
            for version in AUDITED_VERSIONS
        ]
        table_hashes = {result["pci_table_sha256"] for result in results}
        if len(table_hashes) != 1:
            raise ValueError("generation-agnostic PCI table source differs across releases")
        report = {
            "schema": "rm-pci-to-hal-admission-v4",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "implementation_sha256": _fingerprints(),
            "inputs": results,
            "common_pci_table_sha256": next(iter(table_hashes)),
            "source_conclusion": "generic-pci-match-no-gv100-admission-established-in-audited-generated-openrm-profile",
            "qualification": "analyzed-statically",
            "hardware_validated": False,
            "runtime_or_hybrid_cuda_validated": False,
            "driver_installed_or_loaded": False,
            "limits": [
                "Source audit covers pinned NVIDIA OpenRM source only; R580.178.04 open-source profile is not the proprietary stock backend used by the V100 reference.",
                "The conclusion is limited to the audited generated OpenRM admission profile; GV100-suffixed methods may remain in source or linked objects without proving catalog registration or runtime admission.",
                "Generated profile, selector source, and error-path analysis do not prove the complete physical HAL is absent from every linked object.",
                "No physical RM initialization, CUDA API, kernel execution, UVM, P2P, stability, or performance was tested by this audit.",
            ],
            "decision": {
                "architecture_a": "no GV100 admission path is established in the audited generated OpenRM profiles; restoring PCI IDs alone is insufficient",
                "architecture_c": "preferred next integration experiment because it retains the already working stock Volta backend, but same-process cross-backend CUDA remains unproven",
                "next_discriminator": "exercise exact stock RM control initialization through the existing frontend with both backend descriptors in a CPU harness, then run the least invasive canary only after ABI and rollback gates pass",
            },
        }
        report_path = write_private_evidence_report(args.report, report)
        print(json.dumps(report, indent=2))
        print(f"report_path={report_path}")
        return 0
    except (OSError, ValueError, KeyError, UnicodeError, tarfile.TarError) as error:
        parser.exit(2, f"admission audit failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
