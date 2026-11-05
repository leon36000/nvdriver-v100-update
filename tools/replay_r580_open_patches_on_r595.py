#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the R580 private Open integration onto the pinned R595 source.

The first module-namespace patch is translated with explicit R595 anchors;
the remaining R580 GPU-session/backend patches are replayed unchanged with no
fuzz or offsets. This is a source-compatibility experiment, not a build/load.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "build/research/open-gpu-kernel-modules-595.99.02/source/"
          "open-gpu-kernel-modules-595.99.02")
SOURCE_TREE_SHA256 = "6d4ae86fb03f3afac63007c3c13422b114c93f5ab6a271ccb3dde5fb2440c066"
SOURCE_FILE_COUNT = 3810
BASELINE_SYMVERS = (ROOT / "build/experiments/r595-private-open-wrapper-v1-20261023/"
                    "baseline/source/kernel-open/Module.symvers")
BASELINE_SYMVERS_SHA256 = "1afbdc5d864d0d8f7ae7c57b6def32b82a0d99da73772fafc85f5da07baaa918"


class SourceProfile(NamedTuple):
    version: str
    source_path: Path
    source_sha256: str
    source_file_count: int
    baseline_symvers_path: Path
    baseline_symvers_sha256: str


SOURCE_PROFILES = {
    "595.99.02": SourceProfile(
        version="595.99.02",
        source_path=SOURCE,
        source_sha256=SOURCE_TREE_SHA256,
        source_file_count=SOURCE_FILE_COUNT,
        baseline_symvers_path=BASELINE_SYMVERS,
        baseline_symvers_sha256=BASELINE_SYMVERS_SHA256,
    ),
    "595.112.07": SourceProfile(
        version="595.112.07",
        source_path=(ROOT / "build/research/open-gpu-kernel-modules-595.112.07/source/"
                     "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2"),
        source_sha256="8e29bef1a16a00952024fbe0224d90ce115a72b393e89d5cff337fe5f908d2d1",
        source_file_count=3810,
        baseline_symvers_path=(ROOT / "build/experiments/"
                              "r595112-hybrid-stack-build-v1-20261029T1122Z/inputs/"
                              "r595112-open-provider-Module.symvers"),
        baseline_symvers_sha256=BASELINE_SYMVERS_SHA256,
    ),
}


def source_profile(version: str) -> SourceProfile:
    try:
        return SOURCE_PROFILES[version]
    except KeyError as error:
        raise ValueError(f"unsupported pinned source version: {version}") from error
PATCH_ROOT = ROOT / "patches/r580.178.04"
BUILD_VERSION_HEADER = ROOT / "src/hybrid580-open-build-version.h"
PM_PROVIDER_HEADERS = (
    (ROOT / "src/hybrid580_pm_provider_kernel.h",
     "hybrid580-pm-provider-kernel.h"),
    (ROOT / "src/hybrid580_pm_provider_recovery.h",
     "hybrid580-pm-provider-recovery.h"),
    (ROOT / "src/hybrid580_pm_shared_uvm.h",
     "hybrid580-pm-shared-uvm.h"),
)
ADAPTED_PATCHES = (
    "0002-private-open-module.patch",
    "0003-private-open-pci-guard.patch",
    "0004-private-open-chardev.patch",
    "0005-private-open-procfs-path.patch",
    "0007-private-open-pci-only-lifecycle.patch",
)
PATCH_ORDER = (
    "0006-private-open-resource-names.patch",
    "0008-private-open-file-projection.patch",
    "0009-private-open-control-session.patch",
    "0010-private-open-gpu-session.patch",
    "0011-private-open-gpu-session-bdf-lookup.patch",
    "0012-private-open-gpu-inventory.patch",
    "0014-private-control-attach-after-gpu.patch",
    "0015-private-open-card-info.patch",
    "0016-private-open-gpu-id-info.patch",
    "0017-private-open-attached-ids.patch",
    "0018-private-open-probed-ids.patch",
    "0019-private-open-device-ids.patch",
    "0020-private-open-device-object.patch",
    "0021-private-open-memory-object.patch",
    "0022-private-open-vaspace-object.patch",
    "0023-private-open-channel-group-object.patch",
    "0024-private-open-context-share-object.patch",
    "0025-private-open-channel-object.patch",
    "0026-private-open-subdevice-and-tpc-mask.patch",
    "0027-private-open-binapi-object.patch",
    "0028-private-open-usermode-object.patch",
    "0029-private-open-map-memory.patch",
    "0041-private-open-update-device-mapping-info.patch",
    "0030-private-open-rusd-object.patch",
    "0039-private-open-gpu-register-control.patch",
    "0040-private-open-engine-object.patch",
    "0037-private-open-sys-params.patch",
    "0038-private-open-build-version-v1.patch",
    "0044-private-open-system-features.patch",
    "0045-private-open-fabric-status.patch",
    "0047-private-open-client-share-policy.patch",
    "0048-private-open-sync-boost-groups.patch",
    "0049-private-open-control-export-prototypes.patch",
    "0001-private-open-pm-channel-depth-enum.patch",
    "0031-private-open-pm-channel-depth.patch",
    "0033-private-open-pm-vma-access-guard.patch",
    "0034-private-open-vma-free-list-lock.patch",
    "0035-private-open-pm-recovery-provider.patch",
    "0036-private-open-pm-channel-dpm-modeset.patch",
    "0050-private-open-debugger-bridge.patch",
)
PATCH_COUNT = len(ADAPTED_PATCHES) + len(PATCH_ORDER)
ASSERT = importlib.util.spec_from_file_location(
    "private_open595_wrapper", ROOT / "tools/build_private_open595_wrapper.py")
if ASSERT is None or ASSERT.loader is None:
    raise RuntimeError("R595 wrapper helper could not be imported")
HELPER = importlib.util.module_from_spec(ASSERT)
ASSERT.loader.exec_module(HELPER)


def sha256(path: Path) -> str:
    return HELPER.sha256(path)


def source_tree_digest(path: Path) -> tuple[str, int]:
    return HELPER.source_tree_digest(path)


def validate_pinned_tree(digest: str, file_count: int,
                         source_version: str = "595.99.02") -> None:
    profile = source_profile(source_version)
    if (digest, file_count) != (profile.source_sha256, profile.source_file_count):
        raise ValueError(f"R595 {source_version} source snapshot differs from pinned content manifest")


def apply_patch_exact(patch_file: Path, cwd: Path) -> tuple[int, str]:
    result = subprocess.run(
        ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch_file)],
        cwd=cwd, capture_output=True, text=True)
    output = result.stdout + result.stderr
    if result.returncode or re.search(r"\b(?:fuzz|offset)\b|\bFAILED\b", output,
                                     flags=re.IGNORECASE):
        raise RuntimeError(output.strip() or f"patch returned {result.returncode}")
    return result.returncode, output


def rebase_resource_names_patch_r595(patch_text: str,
                                      nv_caps_source: str) -> str:
    """Retarget the nv-caps hunk by its unique allocation call, preserving its body."""
    lines = patch_text.splitlines(keepends=True)
    old_header = "@@ -823,7 +823,7 @@\n"
    marker = "    rc = alloc_chrdev_region(&g_nv_cap_drv.devno,\n"
    if lines.count(old_header) != 1:
        raise ValueError("resource-names nv-caps hunk header changed or is ambiguous")
    expected_context = (
        marker +
        "                             0,\n"
        "                             NV_CAP_DRV_MINOR_COUNT,\n"
        "                             \"nvidia-caps\");\n"
    )
    patch_context = "".join(
        line[1:] for line in lines[lines.index(old_header) + 1:]
        if line.startswith(" ") or line.startswith("-"))
    if expected_context not in patch_context:
        raise ValueError("resource-names nv-caps patch context changed")
    if nv_caps_source.count(expected_context) != 1:
        raise ValueError("R595 nv-caps allocation anchor is missing or ambiguous")
    line_number = nv_caps_source[:nv_caps_source.index(marker)].count("\n") + 1
    new_header = f"@@ -{line_number},7 +{line_number},7 @@\n"
    rebased = lines.copy()
    rebased[rebased.index(old_header)] = new_header
    if [line for line in rebased if line.startswith("+") and not line.startswith("+++")] != [
            line for line in lines if line.startswith("+") and not line.startswith("+++")]:
        raise ValueError("R595 resource-names adaptation changed added C lines")
    return "".join(rebased)


def rebase_system_features_patch_r595(patch_text: str,
                                      source_version: str = "595.99.02") -> str:
    """Rebase only line/context anchors; preserve every added C line verbatim."""
    lines = patch_text.splitlines(keepends=True)
    old_header = "@@ -4723,6 +4723,103 @@\n"
    feature_line = {"595.99.02": 5957, "595.112.07": 5969}.get(source_version)
    if feature_line is None:
        raise ValueError(f"unsupported pinned source version: {source_version}")
    new_header = f"@@ -{feature_line},6 +{feature_line},103 @@\n"
    if len(lines) < 10 or lines[2] != old_header:
        raise ValueError("SYSTEM_GET_FEATURES patch hunk changed")
    body = lines[3:]
    first_add = next((i for i, line in enumerate(body) if line.startswith("+")), None)
    last_add = next((i for i in range(len(body) - 1, -1, -1)
                     if body[i].startswith("+")), None)
    if first_add is None or last_add is None:
        raise ValueError("SYSTEM_GET_FEATURES patch has no added provider implementation")
    prefix, additions, suffix = body[:first_add], body[first_add:last_add + 1], body[last_add + 1:]
    expected_prefix = [
        " }\n",
        " EXPORT_SYMBOL(hybrid580_open_control_session_update_device_mapping_info_v1);\n",
        " \n",
    ]
    expected_suffix = [
        " \n", " static void hybrid580_control_session_release(struct kref *refs)\n", " {\n",
    ]
    if prefix != expected_prefix or suffix != expected_suffix or len(additions) != 97:
        raise ValueError("SYSTEM_GET_FEATURES patch context or C implementation changed")
    r595_suffix = [
        " NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(\n",
        "     struct hybrid580_control_session *session, NvHandle h_root,\n",
        "     NvHandle h_subdevice, NvHandle h_rusd,\n",
    ]
    rebased = lines[:2] + [new_header] + prefix + additions + r595_suffix
    if [line for line in rebased if line.startswith("+")] != [
            line for line in lines if line.startswith("+")]:
        raise ValueError("R595 SYSTEM_GET_FEATURES adaptation changed added C lines")
    return "".join(rebased)


def rebase_fabric_status_patch_r595(patch_text: str,
                                    source_version: str = "595.99.02") -> str:
    """Preserve the provider C and adapt only R595's exact adjacent source anchor."""
    lines = patch_text.splitlines(keepends=True)
    old_header = "@@ -4819,6 +4819,102 @@\n"
    fabric_line = {"595.99.02": 6053, "595.112.07": 6065}.get(source_version)
    if fabric_line is None:
        raise ValueError(f"unsupported pinned source version: {source_version}")
    new_header = f"@@ -{fabric_line},6 +{fabric_line},102 @@\n"
    if len(lines) < 10 or lines[2] != old_header:
        raise ValueError("SYSTEM_GET_FABRIC_STATUS patch hunk changed")
    body = lines[3:]
    first_add = next((i for i, line in enumerate(body) if line.startswith("+")), None)
    last_add = next((i for i in range(len(body) - 1, -1, -1)
                     if body[i].startswith("+")), None)
    if first_add is None or last_add is None:
        raise ValueError("SYSTEM_GET_FABRIC_STATUS patch has no provider implementation")
    prefix, additions, suffix = body[:first_add], body[first_add:last_add + 1], body[last_add + 1:]
    expected_prefix = [
        " }\n",
        " EXPORT_SYMBOL(hybrid580_open_control_session_system_features_v1);\n",
        " \n",
    ]
    expected_suffix = [
        " \n", " \n", " static void hybrid580_control_session_release(struct kref *refs)\n",
    ]
    r595_suffix = [
        " \n",
        " NV_STATUS hybrid580_open_control_session_rusd_alloc_v1(\n",
        "     struct hybrid580_control_session *session, NvHandle h_root,\n",
        "     NvHandle h_subdevice, NvHandle h_rusd,\n",
    ]
    if prefix != expected_prefix or suffix != expected_suffix or len(additions) != 96:
        raise ValueError("SYSTEM_GET_FABRIC_STATUS patch context or C implementation changed")
    rebased = lines[:2] + [new_header] + prefix + additions + r595_suffix
    if [line for line in rebased if line.startswith("+")] != [
            line for line in lines if line.startswith("+")]:
        raise ValueError("R595 SYSTEM_GET_FABRIC_STATUS adaptation changed added C lines")
    return "".join(rebased)


def rebase_client_share_policy_patch_r595(patch_text: str,
                                           source_text: str) -> str:
    """Move the unchanged provider body to R595's unique fabric-export site."""
    lines = patch_text.splitlines(keepends=True)
    old_header = "@@ -5008,6 +5008,101 @@\n"
    anchor = " EXPORT_SYMBOL(hybrid580_open_control_session_fabric_status_v1);\n"
    if len(lines) != 104 or lines[:2] != [
            "--- a/kernel-open/nvidia/nv.c\n",
            "+++ b/kernel-open/nvidia/nv.c\n"] or lines[2] != old_header:
        raise ValueError("CLIENT_SET_INHERITED_SHARE_POLICY patch shape changed")
    body = lines[3:]
    first_add = next((i for i, line in enumerate(body) if line.startswith("+")), None)
    last_add = next((i for i in range(len(body) - 1, -1, -1)
                     if body[i].startswith("+")), None)
    if first_add is None or last_add is None:
        raise ValueError("CLIENT_SET_INHERITED_SHARE_POLICY provider body is missing")
    prefix, additions, suffix = body[:first_add], body[first_add:last_add + 1], body[last_add + 1:]
    if prefix != [
            " EXPORT_SYMBOL(hybrid580_open_control_session_gpu_name_string_v1);\n",
            " \n", " \n"] or suffix != [
            " static void hybrid580_control_session_release(struct kref *refs)\n",
            " {\n", "     struct hybrid580_control_session *session =\n"]:
        raise ValueError("CLIENT_SET_INHERITED_SHARE_POLICY patch context changed")
    if len(additions) != 95 or additions[-1] != "+\n":
        raise ValueError("CLIENT_SET_INHERITED_SHARE_POLICY provider body changed")
    source_lines = source_text.splitlines(keepends=True)
    anchor_text = anchor[1:]
    if source_text.count(anchor_text) != 1:
        raise ValueError("R595 fabric export anchor is missing or ambiguous")
    anchor_index = next(i for i, line in enumerate(source_lines) if line == anchor_text)
    insertion_line = anchor_index + 1
    r595_suffix = source_lines[anchor_index + 1:anchor_index + 3]
    if not r595_suffix or any(not line.endswith("\n") for line in r595_suffix):
        raise ValueError("R595 fabric-export successor context is incomplete")
    old_count = 1 + len(r595_suffix)
    new_count = old_count + len(additions)
    new_header = f"@@ -{insertion_line},{old_count} +{insertion_line},{new_count} @@\n"
    rebased = (lines[:2] + [new_header, anchor] + additions +
               [" " + line for line in r595_suffix])
    if [line for line in rebased if line.startswith("+")] != [
            line for line in lines if line.startswith("+")]:
        raise ValueError("R595 client share-policy adaptation changed provider lines")
    return "".join(rebased)


def rebase_sync_boost_groups_patch_r595(patch_text: str, source_text: str) -> str:
    """Insert the count-only provider after the exact R595 client-share export."""
    lines = patch_text.splitlines(keepends=True)
    anchor_text = "EXPORT_SYMBOL(hybrid580_open_control_session_client_share_policy_v1);\n"
    anchor = " " + anchor_text
    if (len(lines) < 8 or lines[:2] != [
            "--- a/kernel-open/nvidia/nv.c\n",
            "+++ b/kernel-open/nvidia/nv.c\n"] or
            re.fullmatch(r"@@ -\d+,\d+ \+\d+,\d+ @@\n", lines[2]) is None):
        raise ValueError("sync-boost-groups patch shape changed")
    body = lines[3:]
    context = [line for line in body if line.startswith(" ")]
    additions = [line for line in body if line.startswith("+")]
    if context != [" }\n", anchor, " \n", " \n",
                   " static void hybrid580_control_session_release(struct kref *refs)\n",
                   " {\n"]:
        raise ValueError("sync-boost-groups patch anchor context changed")
    if len(additions) != 107 or any(not line.startswith("+") for line in additions):
        raise ValueError("sync-boost-groups provider body is missing or has context")
    source_lines = source_text.splitlines(keepends=True)
    if source_text.count(anchor_text) != 1:
        raise ValueError("R595 client-share export anchor is missing or ambiguous")
    anchor_index = next(i for i, line in enumerate(source_lines)
                        if line == anchor_text)
    # Keep exact successor context in the unified diff. A one-line context-only
    # hunk with additions at EOF-like position is rejected by GNU patch on this
    # source, even though the anchor is present. The pinned R595 source has a
    # blank line immediately after the export; requiring and retaining it makes
    # the insertion location unambiguous and applies with --fuzz=0.
    successor = source_lines[anchor_index + 1:anchor_index + 2]
    if successor != ["\n"]:
        raise ValueError("R595 client-share export successor context changed")
    insertion_line = anchor_index + 1
    old_count = 1 + len(successor)
    new_count = old_count + len(additions)
    new_header = (f"@@ -{insertion_line},{old_count} "
                  f"+{insertion_line},{new_count} @@\n")
    rebased = (lines[:2] + [new_header, anchor] + additions +
               [" " + line for line in successor])
    if [line for line in rebased if line.startswith("+")] != [
            line for line in lines if line.startswith("+")]:
        raise ValueError("R595 sync-boost-groups adaptation changed provider lines")
    return "".join(rebased)


DEBUGGER_BRIDGE_PATCH_SHA256 = (
    "31103e6d37963290f819835426697d8cafebc6b791af2ef2a311b7aec82dfcf2")


def rebase_debugger_bridge_patch_r595(patch_text: str, source_text: str,
                                      header_text: str) -> str:
    """Rebase the provider and retain earlier R595 share/boost prototypes."""
    if hashlib.sha256(patch_text.encode("utf-8")).hexdigest() != \
            DEBUGGER_BRIDGE_PATCH_SHA256:
        raise ValueError("debugger-bridge patch differs from the pinned provider")
    lines = patch_text.splitlines(keepends=True)
    expected_paths = [
        "--- a/kernel-open/nvidia/nv.c\n",
        "--- a/kernel-open/nvidia/hybrid580-control-session.h\n",
    ]
    expected_hunks = [
        "@@ -6563,6 +6563,181 @@\n",
        "@@ -35,6 +35,8 @@\n",
        "@@ -179,15 +181,15 @@\n",
    ]
    patch_paths = [line for line in lines if line.startswith("--- a/")]
    hunk_headers = [line for line in lines if line.startswith("@@")]
    if patch_paths != expected_paths or hunk_headers != expected_hunks:
        raise ValueError("debugger-bridge patch file or hunk shape changed")

    old_header = expected_hunks[0]
    hunk_index = lines.index(old_header)
    next_file_index = lines.index(expected_paths[1])
    nv_hunk = lines[hunk_index + 1:next_file_index]
    expected_context = [
        "    return status;\n",
        "}\n",
        "EXPORT_SYMBOL(hybrid580_open_control_session_engine_alloc_v1);\n",
        "\n",
        "int hybrid580_open_control_session_sys_params_v1(\n",
        "    struct hybrid580_control_session *session, NvU64 memblock_size)\n",
    ]
    context = [line[1:] for line in nv_hunk if line.startswith(" ")]
    additions = [line for line in nv_hunk if line.startswith("+")]
    deletions = [line for line in nv_hunk if line.startswith("-")]
    if context != expected_context or len(additions) != 175 or deletions:
        raise ValueError("debugger-bridge provider body or exact context changed")
    added_text = "".join(additions)
    for symbol in (
            "hybrid580_open_control_session_debugger_alloc_v1",
            "hybrid580_open_control_session_debugger_exception_mask_v1"):
        if added_text.count(symbol) != 2:
            raise ValueError(f"debugger-bridge provider symbol shape changed: {symbol}")

    context_text = "".join(expected_context)
    if source_text.count(context_text) != 1:
        raise ValueError("R595 debugger export anchor is missing or ambiguous")
    for symbol in (
            "hybrid580_open_control_session_debugger_alloc_v1",
            "hybrid580_open_control_session_debugger_exception_mask_v1"):
        if symbol in source_text:
            raise ValueError(f"R595 debugger provider is already present: {symbol}")
    header_index = lines.index(expected_hunks[2])
    header_hunk = lines[header_index + 1:]
    expected_removed_prototypes = [
        "/* Fixed, input-only root-client share policy bridge. */\n",
        "NV_STATUS hybrid580_open_control_session_client_share_policy_v1(\n",
        "    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,\n",
        "    NvU32 flags, RS_SHARE_POLICY *policy, NvU32 *control_status);\n",
        "/* Return only the provider-local count; provider-owned IDs stay local. */\n",
        "NV_STATUS hybrid580_open_control_session_sync_boost_groups_v1(\n",
        "    struct hybrid580_control_session *, NvHandle h_client, NvHandle h_object,\n",
        "    NvU32 flags, NvU32 *group_count, NvU32 *control_status);\n",
    ]
    removed_prototypes = [line[1:] for line in header_hunk if line.startswith("-")]
    if removed_prototypes != expected_removed_prototypes:
        raise ValueError("debugger-bridge patch no longer removes the exact R580 prototypes")
    old_header_context = "".join(
        line[1:] for line in header_hunk
        if line.startswith(" ") or line.startswith("-"))
    if header_text.count(old_header_context) != 1:
        raise ValueError("R595 debugger header anchor is missing or ambiguous")
    header_old_line = header_text[:header_text.index(old_header_context)].count("\n") + 1
    first_header_index = lines.index(expected_hunks[1])
    first_header_hunk = lines[first_header_index + 1:header_index]
    header_delta = sum(line.startswith("+") for line in first_header_hunk) - sum(
        line.startswith("-") for line in first_header_hunk)
    header_new_line = header_old_line + header_delta
    header_old_count = sum(line.startswith(" ") or line.startswith("-")
                           for line in header_hunk)
    header_new_count = header_old_count + sum(
        line.startswith("+") for line in header_hunk)
    line_number = source_text[:source_text.index(context_text)].count("\n") + 1
    rebased = lines.copy()
    rebased[hunk_index] = f"@@ -{line_number},6 +{line_number},181 @@\n"
    rebased[header_index] = (f"@@ -{header_old_line},{header_old_count} "
                             f"+{header_new_line},{header_new_count} @@\n")
    expected_rebased = lines.copy()
    expected_rebased[hunk_index] = rebased[hunk_index]
    expected_rebased[header_index] = rebased[header_index]
    for offset, line in enumerate(header_hunk, header_index + 1):
        if line.startswith("-"):
            rebased[offset] = " " + line[1:]
            expected_rebased[offset] = rebased[offset]
    if rebased != expected_rebased:
        raise ValueError("debugger-bridge adaptation changed provider code")
    if [line for line in rebased if line.startswith("+")] != [
            line for line in lines if line.startswith("+")]:
        raise ValueError("R595 debugger adaptation changed added provider declarations")
    return "".join(rebased)


def add_sync_boost_group_header_r595(header_text: str) -> str:
    """Include the fixed SDK packet type used by the sync-boost provider."""
    anchor = "#include <ctrl/ctrl0000/ctrl0000gpu.h>\n"
    include = "#include <ctrl/ctrl0000/ctrl0000syncgpuboost.h>\n"
    if include in header_text:
        raise ValueError("R595 sync-boost SDK header is already present")
    if header_text.count(anchor) != 1:
        raise ValueError("R595 root GPU control-header anchor is missing or ambiguous")
    return header_text.replace(anchor, anchor + include, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source-version", choices=tuple(SOURCE_PROFILES),
                        default="595.99.02")
    args = parser.parse_args()
    profile = source_profile(args.source_version)
    source = profile.source_path
    baseline_symvers = profile.baseline_symvers_path
    work = args.work_dir.resolve()
    report_path = args.report.resolve()
    if work.exists() or report_path.exists():
        parser.error("unused work and report paths are required")
    if not work.is_relative_to(ROOT / "build/experiments"):
        parser.error("work directory must remain under build/experiments")
    if not report_path.is_relative_to(ROOT / "evidence"):
        parser.error("report must remain under evidence")
    if len(PATCH_ORDER) != 40 or any(
            not (PATCH_ROOT / name).is_file() for name in (*ADAPTED_PATCHES, *PATCH_ORDER)):
        parser.error("the exact R580 GPU-session patch chain is unavailable")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = ROOT / "evidence/logs" / f"r595-r580-patch-port-v1-{stamp}.log"
    report: dict = {
        "schema": "r595-r580-private-open-patch-port-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "not-started",
        "source": str(source),
        "source_version": profile.version,
        "source_manifest_expected_sha256": profile.source_sha256,
        "baseline_symvers": str(baseline_symvers),
        "work_dir": str(work),
        "bootstrap": "R595-specific exact-anchor adaptation of R580 module-namespace patch",
        "patch_count": PATCH_COUNT,
        "patches_attempted": 0,
        "patch_records": [],
        "r595_source_modified": False,
        "module_compiled": False,
        "module_loaded": False,
        "hardware_tested": False,
    }
    source_before: tuple[str, int] | None = None
    symvers_before: str | None = None
    build_version_header_before: str | None = None
    pm_provider_headers_before: dict[str, str] = {}
    patch_hashes = {name: sha256(PATCH_ROOT / name)
                    for name in (*ADAPTED_PATCHES, *PATCH_ORDER)}
    try:
        source_before = source_tree_digest(source)
        validate_pinned_tree(*source_before, source_version=profile.version)
        if not baseline_symvers.is_file():
            raise FileNotFoundError(
                f"pinned R595 {profile.version} baseline Module.symvers is missing")
        symvers_before = sha256(baseline_symvers)
        if symvers_before != profile.baseline_symvers_sha256:
            raise ValueError(
                f"R595 {profile.version} baseline Module.symvers digest mismatch")
        if not BUILD_VERSION_HEADER.is_file():
            raise FileNotFoundError("project build-version API header is missing")
        build_version_header_before = sha256(BUILD_VERSION_HEADER)
        for header_source, _ in PM_PROVIDER_HEADERS:
            if not header_source.is_file():
                raise FileNotFoundError(f"PM provider API header is missing: {header_source}")
            pm_provider_headers_before[str(header_source.relative_to(ROOT))] = sha256(header_source)
        report.update(source_manifest_sha256=source_before[0],
                      source_file_count=source_before[1],
                      baseline_symvers_sha256=symvers_before,
                      build_version_api_header=str(BUILD_VERSION_HEADER),
                      build_version_api_header_sha256=build_version_header_before,
                      pm_provider_api_header_hashes=pm_provider_headers_before,
                      patch_input_hashes=patch_hashes)
        work.mkdir(parents=True)
        shutil.copytree(source, work / "source", symlinks=True)
        tree = work / "source"
        kbuild = tree / "kernel-open/nvidia/nvidia.Kbuild"
        linux_header = tree / "kernel-open/common/inc/nv-linux.h"
        pci_source = tree / "kernel-open/nvidia/nv-pci.c"
        nv_source = tree / "kernel-open/nvidia/nv.c"
        procfs_source = tree / "kernel-open/nvidia/nv-procfs.c"
        sdk_rs_access = tree / "src/common/sdk/nvidia/inc/rs_access.h"
        kernel_rs_access = tree / "kernel-open/common/inc/rs_access.h"
        kbuild.write_text(HELPER.transform_kbuild(kbuild.read_text()))
        linux_header.write_text(HELPER.transform_module_name(linux_header.read_text()))
        pci_source.write_text(HELPER.transform_nv_pci_selection(pci_source.read_text()))
        nv_source.write_text(HELPER.transform_private_chardev(nv_source.read_text()))
        procfs_source.write_text(HELPER.transform_procfs_path(procfs_source.read_text()))
        sdk_rs_access.write_text(HELPER.transform_sdk_rs_access_header_r595(
            sdk_rs_access.read_text(), kernel_rs_access.read_text()))
        exports = HELPER.parse_symvers(baseline_symvers.read_text())
        export_header = tree / "kernel-open/nvidia/hybrid580-open-exports.h"
        if export_header.exists():
            raise ValueError("private namespace header already exists in pinned R595")
        export_header.write_text(HELPER.private_export_header(exports))
        report["adapted_bootstrap_files"] = [
            {"path": str(path.relative_to(tree)), "sha256": sha256(path)}
            for path in (kbuild, linux_header, pci_source, nv_source, procfs_source,
                         export_header, sdk_rs_access)]
        report["patch_records"].extend([
            {"index": 1, "patch": ADAPTED_PATCHES[0],
             "sha256": patch_hashes[ADAPTED_PATCHES[0]], "exit_code": 0,
             "adaptation": "exact R595 Kbuild and MODULE_NAME anchors",
             "offset_or_fuzz": False},
            {"index": 2, "patch": ADAPTED_PATCHES[1],
             "sha256": patch_hashes[ADAPTED_PATCHES[1]], "exit_code": 0,
             "adaptation": "exact R595 PCI selector, probe and enumeration anchors",
             "offset_or_fuzz": False},
            {"index": 3, "patch": ADAPTED_PATCHES[2],
             "sha256": patch_hashes[ADAPTED_PATCHES[2]], "exit_code": 0,
             "adaptation": "exact R595 dynamic character-device lifecycle anchors",
             "offset_or_fuzz": False},
            {"index": 4, "patch": ADAPTED_PATCHES[3],
             "sha256": patch_hashes[ADAPTED_PATCHES[3]], "exit_code": 0,
             "adaptation": "exact R595 private procfs name buffer anchor",
             "offset_or_fuzz": False},
        ])
        report["patches_attempted"] = 4
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("x", encoding="utf-8") as output:
            os.chmod(log, 0o600)
            record_index = 4
            for name in PATCH_ORDER:
                patch_file = PATCH_ROOT / name
                start = time.monotonic()
                try:
                    adaptation = None
                    adaptation_artifacts: list[Path] = []
                    if name == "0006-private-open-resource-names.patch":
                        overlay_dir = tree / ".hybrid-local-overlays"
                        overlay_dir.mkdir(exist_ok=True, mode=0o700)
                        overlay = overlay_dir / name
                        nv_caps = tree / "kernel-open/nvidia/nv-caps.c"
                        patch_overlay = rebase_resource_names_patch_r595(
                            patch_file.read_text(), nv_caps.read_text())
                        with overlay.open("x", encoding="utf-8") as stream:
                            stream.write(patch_overlay)
                        code, text = apply_patch_exact(overlay, tree)
                        adaptation_artifacts = [nv_caps, overlay]
                        resource_header = re.search(
                            r"@@ -(\d+),7 \+\d+,7 @@\n"
                            r"     rc = alloc_chrdev_region\(&g_nv_cap_drv\.devno,\n",
                            patch_overlay)
                        if resource_header is None:
                            raise ValueError("rebased resource-name patch lost its exact line header")
                        resource_line = int(resource_header.group(1))
                        text = ("R595 exact-anchor resource-name rebase targets the unique "
                                f"nv-caps allocation call at line {resource_line}; "
                                "no fuzz or offset.\n")
                        adaptation = "R595 nv-caps allocation call line selected from pinned source"
                    elif name == "0008-private-open-file-projection.patch":
                        projection_patch = patch_file.read_text()
                        projection_header = tree / "kernel-open/nvidia/hybrid580-file-projection.h"
                        if projection_header.exists():
                            raise ValueError("R595 projection ABI header already exists")
                        nv_source.write_text(HELPER.transform_file_projection_r595(
                            nv_source.read_text(), projection_patch))
                        projection_header.write_text(
                            HELPER.extract_projection_api_header(projection_patch))
                        adaptation_artifacts = [nv_source, projection_header]
                        code = 0
                        text = ("R595 semantic adaptation: bitmap occupancy plus per-file minor/state "
                                "identity; removed-device rejection; sleep-free iterate_fd matcher; "
                                "shared projection ABI header extracted from the pinned R580 patch.\n")
                        adaptation = "R595 bitmap, control-state and hot-remove semantics"
                    elif name == "0009-private-open-control-session.patch":
                        control_patch = patch_file.read_text()
                        nv_text, kbuild_text = HELPER.transform_control_session_r595(
                            nv_source.read_text(), kbuild.read_text(), control_patch)
                        nv_source.write_text(nv_text)
                        kbuild.write_text(kbuild_text)
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        endpoint_header = tree / "kernel-open/nvidia/rm_session_endpoint.h"
                        endpoint_source = ROOT / "src/rm_session_endpoint.h"
                        if control_header.exists() or endpoint_header.exists():
                            raise ValueError("R595 control-session ABI header already exists")
                        if not endpoint_source.is_file():
                            raise FileNotFoundError("shared RM endpoint header is unavailable")
                        control_header.write_text(
                            HELPER.extract_control_session_api_header(control_patch))
                        shutil.copy2(endpoint_source, endpoint_header)
                        adaptation_artifacts = [nv_source, kbuild, control_header,
                                                endpoint_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: control-session implementation, "
                                "pseudo-file close guard, SDK include paths and shared endpoint ABI.\n")
                        adaptation = "R595 control-session source layout and exported API"
                    elif name == "0010-private-open-gpu-session.patch":
                        gpu_patch = patch_file.read_text()
                        nv_source.write_text(HELPER.transform_gpu_session_r595(
                            nv_source.read_text(), gpu_patch))
                        gpu_header = tree / "kernel-open/nvidia/hybrid580-gpu-session.h"
                        if gpu_header.exists():
                            raise ValueError("R595 GPU-session ABI header already exists")
                        gpu_header.write_text(
                            HELPER.extract_gpu_session_api_header(gpu_patch))
                        adaptation_artifacts = [nv_source, gpu_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: GPU-session implementation inserted "
                                "before nv_get_file_private; ABI header extracted from pinned R580.\n")
                        adaptation = "R595 GPU-session function anchor and shared API header"
                    elif name == "0011-private-open-gpu-session-bdf-lookup.patch":
                        bdf_patch = patch_file.read_text()
                        gpu_header = tree / "kernel-open/nvidia/hybrid580-gpu-session.h"
                        if not gpu_header.is_file():
                            raise FileNotFoundError("R595 GPU-session API header is unavailable")
                        nv_text, header_text = HELPER.transform_gpu_session_bdf_lookup_r595(
                            nv_source.read_text(), gpu_header.read_text(), bdf_patch)
                        nv_source.write_text(nv_text)
                        gpu_header.write_text(header_text)
                        adaptation_artifacts = [nv_source, gpu_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: BDF lookup inserted after the GPU "
                                "session factory and declared in its shared API header.\n")
                        adaptation = "R595 GPU-session BDF lookup and header anchors"
                    elif name == "0012-private-open-gpu-inventory.patch":
                        inventory_patch = patch_file.read_text()
                        gpu_header = tree / "kernel-open/nvidia/hybrid580-gpu-session.h"
                        catalog_source = ROOT / "src/hybrid580-gpu-catalog.h"
                        catalog_header = tree / "kernel-open/nvidia/hybrid580-gpu-catalog.h"
                        if not gpu_header.is_file() or not catalog_source.is_file():
                            raise FileNotFoundError("R595 GPU inventory ABI inputs are unavailable")
                        if catalog_header.exists():
                            raise ValueError("R595 GPU catalog header already exists")
                        nv_text, gpu_header_text = HELPER.transform_gpu_inventory_r595(
                            nv_source.read_text(), gpu_header.read_text(),
                            catalog_source.read_text(), inventory_patch)
                        nv_source.write_text(nv_text)
                        gpu_header.write_text(gpu_header_text)
                        shutil.copy2(catalog_source, catalog_header)
                        adaptation_artifacts = [nv_source, gpu_header, catalog_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: GPU inventory uses the locked device "
                                "list and the pinned shared catalog record ABI.\n")
                        adaptation = "R595 GPU inventory source anchor and shared catalog header"
                    elif name == "0014-private-control-attach-after-gpu.patch":
                        attach_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text = HELPER.transform_control_attach_r595(
                            nv_source.read_text(), control_header.read_text(), attach_patch)
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: attach ioctl uses a shared helper, "
                                "and GPU reference pin/rollback preserves reset_aware=false.\n")
                        adaptation = "R595 reset-aware attach API and control-session header"
                    elif name == "0015-private-open-card-info.patch":
                        card_info_patch = patch_file.read_text()
                        gpu_header = tree / "kernel-open/nvidia/hybrid580-gpu-session.h"
                        if not gpu_header.is_file():
                            raise FileNotFoundError("R595 GPU-session ABI header is unavailable")
                        nv_text, gpu_header_text = HELPER.transform_gpu_card_info_r595(
                            nv_source.read_text(), gpu_header.read_text(), card_info_patch)
                        nv_source.write_text(nv_text)
                        gpu_header.write_text(gpu_header_text)
                        adaptation_artifacts = [nv_source, gpu_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: card-info export follows the "
                                "pinned nvidia_read_card_info() implementation and shared header.\n")
                        adaptation = "R595 card-info source and GPU-session ABI anchors"
                    elif name == "0016-private-open-gpu-id-info.patch":
                        id_info_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text = HELPER.transform_gpu_id_info_r595(
                            nv_source.read_text(), control_header.read_text(), id_info_patch)
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: GPU-ID control bridge uses the "
                                "pinned kernel RMAPI operation interface and command header.\n")
                        adaptation = "R595 kernel RMAPI bridge and control-session API header"
                    elif name in (
                            "0017-private-open-attached-ids.patch",
                            "0018-private-open-probed-ids.patch",
                            "0019-private-open-device-ids.patch"):
                        query_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_name = (
                            HELPER.transform_control_query_r595(
                                nv_source.read_text(), control_header.read_text(), query_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: fixed-size " + api_name +
                                " bridge uses the kernel RMAPI path; only source offsets differ.\n")
                        adaptation = "R595 fixed-size control-query insertion and API header"
                    elif name == "0020-private-open-device-object.patch":
                        device_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text = HELPER.transform_device_object_r595(
                            nv_source.read_text(), control_header.read_text(), device_patch)
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: typed NV01_DEVICE_0 allocate/free "
                                "operations use the pinned kernel RMAPI ABI.\n")
                        adaptation = "R595 device-object lifecycle bridge and typed header"
                    elif name in (
                            "0021-private-open-memory-object.patch",
                            "0022-private-open-vaspace-object.patch",
                            "0023-private-open-channel-group-object.patch",
                            "0026-private-open-subdevice-and-tpc-mask.patch",
                            "0027-private-open-binapi-object.patch",
                            "0028-private-open-usermode-object.patch"):
                        memory_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_control_session_additions_r595(
                                nv_source.read_text(), control_header.read_text(), memory_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor adaptation: typed RM allocation methods " +
                                ", ".join(api_names) + " use the kernel RMAPI ABI.\n")
                        adaptation = "R595 typed RM allocation methods and shared header"
                    elif name == "0024-private-open-context-share-object.patch":
                        context_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_context_share_r595(
                                nv_source.read_text(), control_header.read_text(), context_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 context-share parameters preserve null/default VASpace "
                                "and output subcontext-ID semantics.\n")
                        adaptation = "R595 context-share input/output contract and shared header"
                    elif name == "0025-private-open-channel-object.patch":
                        channel_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_channel_allocation_r595(
                                nv_source.read_text(), control_header.read_text(), channel_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor channel allocation permits only its Volta "
                                "and Blackwell A/B physical GPFIFO classes.\n")
                        adaptation = "R595 Volta plus Blackwell A/B channel-class whitelist"
                    elif name == "0029-private-open-map-memory.patch":
                        map_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_map_memory_r595(
                                nv_source.read_text(), control_header.read_text(), map_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor NVOS33/NVOS34 map/unmap methods use the "
                                "native rm_ioctl path and current-process fd wrapper.\n")
                        adaptation = "R595 fixed-packet RM map/unmap bridge"
                    elif name == "0041-private-open-update-device-mapping-info.patch":
                        mapping_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_update_device_mapping_info_r595(
                                nv_source.read_text(), control_header.read_text(), mapping_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor NVOS56 bridge uses native synchronous RM ioctl; "
                                "address keys and embedded status remain unchanged.\n")
                        adaptation = "R595 caller-process NVOS56 mapping update bridge"
                    elif name == "0030-private-open-rusd-object.patch":
                        rusd_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_rusd_allocation_r595(
                                nv_source.read_text(), control_header.read_text(), rusd_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor RM_USER_SHARED_DATA allocation method "
                                "adds the class payload type and shared API declaration.\n")
                        adaptation = "R595 typed RUSD allocation bridge and class dependency"
                    elif name == "0039-private-open-gpu-register-control.patch":
                        register_patch = patch_file.read_text()
                        gpu_header = tree / "kernel-open/nvidia/hybrid580-gpu-session.h"
                        if not gpu_header.is_file():
                            raise FileNotFoundError("R595 GPU-session ABI header is unavailable")
                        nv_text, gpu_header_text = HELPER.transform_gpu_register_control_r595(
                            nv_source.read_text(), gpu_header.read_text(), register_patch)
                        nv_source.write_text(nv_text)
                        gpu_header.write_text(gpu_header_text)
                        adaptation_artifacts = [nv_source, gpu_header]
                        code = 0
                        text = ("R595 exact-anchor REGISTER_FD bridge retains the pinned "
                                "control-file ownership and atomic publication contract.\n")
                        adaptation = "R595 REGISTER_FD bridge and GPU-session API"
                    elif name == "0040-private-open-engine-object.patch":
                        engine_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_engine_allocation_r595(
                                nv_source.read_text(), control_header.read_text(), engine_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor Blackwell B compute/DMA engine allocation "
                                "uses the fixed zero-payload RM allocation ABI.\n")
                        adaptation = "R595 Blackwell B engine allocation bridge"
                    elif name == "0037-private-open-sys-params.patch":
                        sys_params_patch = patch_file.read_text()
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError("R595 control-session ABI header is unavailable")
                        nv_text, control_header_text, api_names = (
                            HELPER.transform_sys_params_r595(
                                nv_source.read_text(), control_header.read_text(),
                                sys_params_patch))
                        nv_source.write_text(nv_text)
                        control_header.write_text(control_header_text)
                        adaptation_artifacts = [nv_source, control_header]
                        code = 0
                        text = ("R595 exact-anchor SYS_PARAMS bridge shares the native "
                                "set-once state update under one mutex.\n")
                        adaptation = "R595 serialized NV_ESC_SYS_PARAMS bridge"
                    elif name == "0038-private-open-build-version-v1.patch":
                        build_version_patch = patch_file.read_text()
                        build_version_header = tree / "kernel-open/nvidia/hybrid580-open-build-version.h"
                        if build_version_header.exists():
                            raise ValueError("R595 Open build-version API header already exists")
                        nv_source.write_text(HELPER.transform_build_version_r595(
                            nv_source.read_text(), build_version_patch,
                            BUILD_VERSION_HEADER.read_text()))
                        shutil.copy2(BUILD_VERSION_HEADER, build_version_header)
                        if sha256(build_version_header) != build_version_header_before:
                            raise ValueError("R595 Open build-version API header copy differs from project input")
                        adaptation_artifacts = [nv_source, build_version_header]
                        code = 0
                        text = ("R595 exact-anchor build-version bridge uses the existing "
                                "pointer-free V2 RM command and pinned project API header.\n")
                        adaptation = "R595 pointer-free system build-version control bridge"
                    elif name == "0044-private-open-system-features.patch":
                        overlay_dir = tree / ".hybrid-local-overlays"
                        overlay_dir.mkdir(exist_ok=True, mode=0o700)
                        overlay = overlay_dir / name
                        patch_overlay = rebase_system_features_patch_r595(
                            patch_file.read_text(), profile.version)
                        old_context = "".join(
                            line[1:] for line in patch_overlay.splitlines(keepends=True)[3:]
                            if line.startswith(" "))
                        if not old_context or nv_source.read_text().count(old_context) != 1:
                            raise ValueError("R595 SYSTEM_GET_FEATURES context is missing or ambiguous")
                        with overlay.open("x", encoding="utf-8") as stream:
                            stream.write(patch_overlay)
                        code, text = apply_patch_exact(overlay, tree)
                        adaptation_artifacts = [nv_source, overlay]
                        text = ("R595 exact-line adaptation places the unchanged fixed-buffer "
                                "SYSTEM_GET_FEATURES provider after the pinned mapping-info "
                                "export; unique literal context, no fuzz or offset.\n")
                        adaptation = "R595 SYSTEM_GET_FEATURES insertion anchor"
                    elif name == "0045-private-open-fabric-status.patch":
                        overlay_dir = tree / ".hybrid-local-overlays"
                        overlay_dir.mkdir(exist_ok=True, mode=0o700)
                        overlay = overlay_dir / name
                        patch_overlay = rebase_fabric_status_patch_r595(
                            patch_file.read_text(), profile.version)
                        old_context = "".join(
                            line[1:] for line in patch_overlay.splitlines(keepends=True)[3:]
                            if line.startswith(" "))
                        if not old_context or nv_source.read_text().count(old_context) != 1:
                            raise ValueError(
                                "R595 SYSTEM_GET_FABRIC_STATUS context is missing or ambiguous")
                        with overlay.open("x", encoding="utf-8") as stream:
                            stream.write(patch_overlay)
                        code, text = apply_patch_exact(overlay, tree)
                        adaptation_artifacts = [nv_source, overlay]
                        text = ("R595 exact-line adaptation places the unchanged fixed-buffer "
                                "SYSTEM_GET_FABRIC_STATUS provider after the root feature "
                                "provider; unique literal context, no fuzz or offset.\n")
                        adaptation = "R595 SYSTEM_GET_FABRIC_STATUS insertion anchor"
                    elif name == "0047-private-open-client-share-policy.patch":
                        if "hybrid580_open_control_session_client_share_policy_v1(" in nv_source.read_text():
                            raise ValueError("R595 client share-policy provider is already present")
                        overlay_dir = tree / ".hybrid-local-overlays"
                        overlay_dir.mkdir(exist_ok=True, mode=0o700)
                        overlay = overlay_dir / name
                        patch_overlay = rebase_client_share_policy_patch_r595(
                            patch_file.read_text(), nv_source.read_text())
                        with overlay.open("x", encoding="utf-8") as stream:
                            stream.write(patch_overlay)
                        code, text = apply_patch_exact(overlay, tree)
                        adaptation_artifacts = [nv_source, overlay]
                        text = ("R595 exact-line adaptation inserts the fixed 12-byte "
                                "CLIENT_SET_INHERITED_SHARE_POLICY provider after the unique "
                                "Fabric status export; the provider body is unchanged.\n")
                        adaptation = "R595 dual-backend client share-policy bridge"
                    elif name == "0048-private-open-sync-boost-groups.patch":
                        if "hybrid580_open_control_session_sync_boost_groups_v1(" in nv_source.read_text():
                            raise ValueError("R595 sync-boost-groups provider is already present")
                        overlay_dir = tree / ".hybrid-local-overlays"
                        overlay_dir.mkdir(exist_ok=True, mode=0o700)
                        overlay = overlay_dir / name
                        patch_overlay = rebase_sync_boost_groups_patch_r595(
                            patch_file.read_text(), nv_source.read_text())
                        with overlay.open("x", encoding="utf-8") as stream:
                            stream.write(patch_overlay)
                        code, text = apply_patch_exact(overlay, tree)
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError(
                                "R595 control-session API header is unavailable")
                        control_header.write_text(add_sync_boost_group_header_r595(
                            control_header.read_text()))
                        adaptation_artifacts = [nv_source, overlay, control_header]
                        text = ("R595 exact-line adaptation inserts the count-only "
                                "SYNC_GPU_BOOST_GROUP_INFO provider after the unique "
                                "client-share export and adds its exact SDK packet header; "
                                "the provider body is unchanged.\n")
                        adaptation = "R595 dual-provider sync-boost count bridge"
                    elif name == "0049-private-open-control-export-prototypes.patch":
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError(
                                "R595 control-session API header is unavailable")
                        code, text = apply_patch_exact(patch_file, tree)
                        adaptation_artifacts = [control_header]
                        text = ("R595 control-session API now declares the exact exported "
                                "client-share and sync-boost signatures consumed by the "
                                "frontend; zero-offset, zero-fuzz header patch.\n")
                        adaptation = "R595 private control API prototype closure"
                    elif name == "0050-private-open-debugger-bridge.patch":
                        control_header = tree / "kernel-open/nvidia/hybrid580-control-session.h"
                        if not control_header.is_file():
                            raise FileNotFoundError(
                                "R595 control-session API header is unavailable")
                        overlay_dir = tree / ".hybrid-local-overlays"
                        overlay_dir.mkdir(exist_ok=True, mode=0o700)
                        overlay = overlay_dir / name
                        patch_overlay = rebase_debugger_bridge_patch_r595(
                            patch_file.read_text(), nv_source.read_text(),
                            control_header.read_text())
                        with overlay.open("x", encoding="utf-8") as stream:
                            stream.write(patch_overlay)
                        code, text = apply_patch_exact(overlay, tree)
                        adapted_hunk = re.search(
                            r"(?m)^@@ -(\d+),6 \+\d+,181 @@$", patch_overlay)
                        if adapted_hunk is None:
                            raise ValueError(
                                "R595 debugger bridge lost its exact line header")
                        adaptation_artifacts = [nv_source, control_header, overlay]
                        text = ("R595 debugger allocation and exception-mask provider "
                                "reuses the exact R580 body after the unique engine export "
                                f"at line {adapted_hunk.group(1)}; only the diff line number "
                                "changed, with zero offset/fuzz.\n")
                        adaptation = "R595 GT200_DEBUGGER bridge exact-anchor rebase"
                    elif name == "0001-private-open-pm-channel-depth-enum.patch":
                        pm_patch = patch_file.read_text()
                        pm_header = tree / "kernel-open/common/inc/nv.h"
                        nv_text = HELPER.transform_pm_channel_depth_enum_r595(
                            pm_header.read_text(), pm_patch)
                        pm_header.write_text(nv_text)
                        adaptation_artifacts = [pm_header]
                        code = 0
                        text = ("R595 exact enum anchor adds the private channel PM depth "
                                "without accepting patch offsets.\n")
                        adaptation = "R595 channel PM depth enum exact-anchor adaptation"
                    elif name == "0031-private-open-pm-channel-depth.patch":
                        pm_patch = patch_file.read_text()
                        procfs_source = tree / "kernel-open/nvidia/nv-procfs.c"
                        nv_text, procfs_text = HELPER.transform_pm_channel_depth_r595(
                            nv_source.read_text(), procfs_source.read_text(), pm_patch)
                        nv_source.write_text(nv_text)
                        procfs_source.write_text(procfs_text)
                        adaptation_artifacts = [nv_source, procfs_source]
                        code = 0
                        text = ("R595 exact-anchor control-file/mmap PM guards and channel-only "
                                "suspend/resume policy; procfs accepts and reports channels.\n")
                        adaptation = "R595 PM channel-depth lifecycle adaptation"
                    elif name == "0033-private-open-pm-vma-access-guard.patch":
                        access_patch = patch_file.read_text()
                        mmap_source = tree / "kernel-open/nvidia/nv-mmap.c"
                        mmap_text = HELPER.transform_pm_vma_access_r595(
                            mmap_source.read_text(), access_patch)
                        mmap_source.write_text(mmap_text)
                        adaptation_artifacts = [mmap_source]
                        code = 0
                        text = ("R595 VMA access delegates through an exact wrapper that holds "
                                "the provider PM read lock for the complete memory access.\n")
                        adaptation = "R595 PM-guarded VMA access wrapper"
                    elif name == "0034-private-open-vma-free-list-lock.patch":
                        release_patch = patch_file.read_text()
                        linux_header = tree / "kernel-open/common/inc/nv-linux.h"
                        header_text = HELPER.transform_pm_free_list_lock_r595(
                            linux_header.read_text(), release_patch)
                        linux_header.write_text(header_text)
                        adaptation_artifacts = [linux_header]
                        code = 0
                        text = ("R595 nv_alloc_release serializes the last-reference check and "
                                "free-list publication with the per-file IRQ-safe spinlock.\n")
                        adaptation = "R595 per-file allocation free-list lock"
                    elif name == "0035-private-open-pm-recovery-provider.patch":
                        recovery_patch = patch_file.read_text()
                        uvm_source = tree / "kernel-open/nvidia/nv_uvm_interface.c"
                        nv_text, uvm_text = HELPER.transform_pm_recovery_provider_r595(
                            nv_source.read_text(), uvm_source.read_text(), recovery_patch)
                        nv_source.write_text(nv_text)
                        uvm_source.write_text(uvm_text)
                        adaptation_artifacts = [nv_source, uvm_source]
                        for header_source, header_name in PM_PROVIDER_HEADERS:
                            header_target = tree / "kernel-open/nvidia" / header_name
                            if header_target.exists():
                                raise ValueError(
                                    f"R595 PM provider API header already exists: {header_name}")
                            if header_name == "hybrid580-pm-provider-kernel.h":
                                header_target.write_text(
                                    HELPER.transform_pm_provider_kernel_r595(
                                        header_source.read_text()))
                            else:
                                shutil.copy2(header_source, header_target)
                            if (header_name != "hybrid580-pm-provider-kernel.h" and
                                    sha256(header_target) != pm_provider_headers_before[
                                        str(header_source.relative_to(ROOT))]):
                                raise ValueError(
                                    f"R595 PM provider header copy differs from input: {header_name}")
                            adaptation_artifacts.append(header_target)
                        code = 0
                        text = ("R595 exact-anchor PM recovery callbacks plus registered-UVM "
                                "dispatch under the native event lock; no-callback paths return "
                                "NV_ERR_NOT_SUPPORTED. Provider ownership adapts to R595's "
                                "device list; shared headers are copied.\n")
                        adaptation = "R595 PM recovery and registered-UVM bridge"
                    elif name == "0036-private-open-pm-channel-dpm-modeset.patch":
                        modeset_patch = patch_file.read_text()
                        nv_source.write_text(
                            HELPER.transform_pm_channel_dpm_modeset_r595(
                                nv_source.read_text(), modeset_patch))
                        adaptation_artifacts = [nv_source]
                        code = 0
                        text = ("R595 exact function-scoped anchors skip aggregate NVKMS "
                                "suspend/resume during channels-only PCI DPM, including the "
                                "rollback path; default, UVM and modeset depths retain calls.\n")
                        adaptation = "R595 channels-only DPM/NVKMS de-duplication"
                    else:
                        code, text = apply_patch_exact(patch_file, tree)
                    record_index += 1
                    output.write(f"PATCH {record_index:02d} {name} exit={code}\n{text}")
                    output.flush()
                    patch_record = {
                        "index": record_index, "patch": name,
                        "sha256": patch_hashes[name], "exit_code": code,
                        "offset_or_fuzz": False,
                        "duration_seconds": round(time.monotonic() - start, 3),
                        "output": text.strip()}
                    if adaptation is not None:
                        patch_record["adaptation"] = adaptation
                    if adaptation_artifacts:
                        patch_record["adapted_artifacts"] = [
                            {"path": str(path.relative_to(tree)), "sha256": sha256(path)}
                            for path in adaptation_artifacts]
                    report["patch_records"].append(patch_record)
                    report["patches_attempted"] += 1
                    if name == "0006-private-open-resource-names.patch":
                        pci_table_source = tree / "kernel-open/nvidia/nv-pci-table.c"
                        platform_source = tree / "kernel-open/nvidia/nv-platform.c"
                        nv_text, pci_table_text, platform_text = HELPER.transform_pci_only_lifecycle(
                            nv_source.read_text(), pci_table_source.read_text(),
                            platform_source.read_text())
                        nv_source.write_text(nv_text)
                        pci_table_source.write_text(pci_table_text)
                        platform_source.write_text(platform_text)
                        record_index += 1
                        report["patch_records"].append({
                            "index": record_index, "patch": ADAPTED_PATCHES[-1],
                            "sha256": patch_hashes[ADAPTED_PATCHES[-1]],
                            "exit_code": 0,
                            "adaptation": "exact R595 NVSwitch, platform and autoload anchors",
                            "offset_or_fuzz": False})
                        report["patches_attempted"] += 1
                except (RuntimeError, ValueError) as error:
                    text = str(error)
                    record_index += 1
                    output.write(f"PATCH {record_index:02d} {name} exit=1\n{text}\n")
                    output.flush()
                    record = {"index": record_index, "patch": name,
                              "sha256": patch_hashes[name], "exit_code": 1,
                              "offset_or_fuzz": bool(re.search(
                                  r"\b(?:fuzz|offset)\b", text, flags=re.IGNORECASE)),
                              "duration_seconds": round(time.monotonic() - start, 3),
                              "output": text}
                    report["patch_records"].append(record)
                    report["patches_attempted"] += 1
                    report["first_failure"] = record
                    break
        report["log"] = {"path": str(log.relative_to(ROOT)),
                          "sha256": sha256(log), "mode": "0600"}
        if "first_failure" in report:
            report["qualification"] = "replay-stopped"
        elif report["patches_attempted"] == report["patch_count"]:
            report["qualification"] = "all-r580-open-patches-apply-to-r595-source"
    except Exception as error:
        report.update(qualification="failed", error=f"{type(error).__name__}: {error}")
    try:
        report["source_tree_unchanged"] = source_before is None or source_tree_digest(source) == source_before
        report["baseline_symvers_unchanged"] = symvers_before is None or sha256(baseline_symvers) == symvers_before
        report["patch_inputs_unchanged"] = all(
            sha256(PATCH_ROOT / name) == digest for name, digest in patch_hashes.items())
        report["build_version_api_header_unchanged"] = (
            build_version_header_before is not None and
            BUILD_VERSION_HEADER.is_file() and
            sha256(BUILD_VERSION_HEADER) == build_version_header_before)
        report["pm_provider_api_headers_unchanged"] = (
            len(pm_provider_headers_before) == len(PM_PROVIDER_HEADERS) and
            all((ROOT / path).is_file() and sha256(ROOT / path) == digest
                for path, digest in pm_provider_headers_before.items()))
        report["inputs_unchanged"] = all((report["source_tree_unchanged"],
                                         report["baseline_symvers_unchanged"],
                                         report["patch_inputs_unchanged"],
                                         report["build_version_api_header_unchanged"],
                                         report["pm_provider_api_headers_unchanged"]))
        if not report["inputs_unchanged"]:
            report["qualification"] = "failed"
            report.setdefault("error", "a pinned replay input changed during experiment")
    except OSError as error:
        report.update(qualification="failed", inputs_unchanged=False,
                      error=f"input verification failed: {type(error).__name__}: {error}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    os.chmod(report_path, 0o600)
    print(json.dumps({"qualification": report["qualification"],
                      "patches_attempted": report["patches_attempted"],
                      "first_failure": report.get("first_failure"),
                      "report": str(report_path)}, sort_keys=True))
    return 0 if report["qualification"] == "all-r580-open-patches-apply-to-r595-source" else 1


if __name__ == "__main__":
    raise SystemExit(main())
