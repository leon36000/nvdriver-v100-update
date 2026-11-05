#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check whether Ubuntu's pinned kernel patch changes the kprobe notrace guard."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re

TARGET_PATH = "kernel/trace/trace_kprobe.c"
EXPECTED_UBUNTU_VERSION = "6.8.0-147.147"
EXPECTED_DSC_SHA256 = "c546485ca6c4bd45143817f44c7c12498b64e9c911f434fd14147ecb9ebb981f"
EXPECTED_DIFF_SHA256 = "370fa76631a470323e92a0b25dca6012287c4ada448c7f2e4954f45a628e936c"
EXPECTED_UPSTREAM_SOURCE_SHA256 = "3d5130b1c160d3f3dadf482f94337488f8105b9dd07f9b33256bcdd52094cd9b"
UPSTREAM_SOURCE_URL = "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/trace/trace_kprobe.c"
UBUNTU_DSC_URL = "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_6.8.0-147.147.dsc"
UBUNTU_DIFF_URL = "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_6.8.0-147.147.diff.gz"
UBUNTU_PACKAGE_PAGE_URL = "https://packages.ubuntu.com/noble-updates/linux-headers-6.8.0-147"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_dsc_metadata(text: str) -> dict:
    scalar = {}
    for key in ("Source", "Version"):
        match = re.search(r"^" + key + r":\s*(\S+)\s*$", text, re.MULTILINE)
        if not match:
            raise ValueError("source descriptor lacks " + key)
        scalar[key.lower()] = match.group(1)
    checksums = {"sha256":{}, "md5":{}}
    current_section = None
    for line in text.splitlines():
        if line.startswith("Checksums-Sha256:"):
            current_section = "sha256"
            continue
        if line.startswith("Files:"):
            current_section = "md5"
            continue
        if line.startswith("Checksums-Sha1:") or line.startswith("-----BEGIN PGP"):
            current_section = None
        if current_section == "sha256":
            match = re.match(r"^\s*([0-9a-f]{64})\s+\d+\s+(\S+)\s*$", line)
            if match:
                checksums["sha256"][match.group(2)] = match.group(1)
        if current_section == "md5":
            match = re.match(r"^\s*([0-9a-f]{32})\s+\d+\s+(\S+)\s*$", line)
            if match:
                checksums["md5"][match.group(2)] = match.group(1)
    if not checksums["sha256"] or not checksums["md5"]:
        raise ValueError("source descriptor contains no SHA-256 file list")
    return {**scalar, "checksums_sha256":checksums}


def diff_hunks(diff_path: Path, target_path: str = TARGET_PATH) -> list[dict]:
    result = []
    in_target = False
    with gzip.open(diff_path, "rt", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if line.startswith("--- "):
                in_target = line.rstrip("\n") == "--- linux-6.8.0.orig/" + target_path
                continue
            if not in_target or not line.startswith("@@"):
                continue
            match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("unrecognized unified-diff hunk header")
            old_start, old_count, new_start, new_count = match.groups()
            result.append({"old_start":int(old_start), "old_count":int(old_count or "1"),
                           "new_start":int(new_start), "new_count":int(new_count or "1")})
    if not result:
        raise ValueError("pinned Ubuntu diff contains no target-file hunks")
    return result


def source_contract_ranges(source_path: Path) -> list[dict]:
    lines = source_path.read_text(encoding="utf-8", errors="strict").splitlines()
    start = next((i for i, line in enumerate(lines, 1)
                  if line.strip() == "#if defined(CONFIG_DYNAMIC_FTRACE) && \\"), None)
    if start is None or start >= len(lines):
        raise ValueError("dynamic-ftrace notrace guard not found")
    end = next((i for i in range(start + 1, len(lines) + 1)
                if lines[i - 1].strip() == "#endif"), None)
    if end is None:
        raise ValueError("dynamic-ftrace notrace guard is unterminated")
    registration = next((i for i, line in enumerate(lines, 1)
                         if line.startswith("static int __register_trace_kprobe(")), None)
    unregister = next((i for i, line in enumerate(lines, 1)
                       if line.startswith("static void __unregister_trace_kprobe(")), None)
    if registration is None or unregister is None or unregister <= registration:
        raise ValueError("trace-kprobe registration function boundaries not found")
    return [
        {"name":"dynamic-ftrace notrace guard", "start":start, "end":end},
        {"name":"trace-kprobe registration", "start":registration, "end":unregister - 1},
    ]


def hunk_overlaps_contract(hunk: dict, contract: dict) -> bool:
    start, count = hunk["old_start"], hunk["old_count"]
    if count == 0:
        return contract["start"] <= start <= contract["end"]
    end = start + count - 1
    return start <= contract["end"] and contract["start"] <= end


def validate_guest_report(report: object, version: str) -> dict:
    if not isinstance(report, dict) or report.get("status") != "observed":
        raise ValueError("PC3 guest report is not a successful observation")
    remote = report.get("remote")
    guest = remote.get("guest") if isinstance(remote, dict) else None
    if not isinstance(guest, dict) or guest.get("hostname") != "pc3-v100":
        raise ValueError("PC3 V100 guest identity is missing")
    os_release = guest.get("os_release", {})
    packages = guest.get("installed_kernel_packages", [])
    image_versions = {item.get("version") for item in packages
                      if item.get("package") == "linux-image-" + guest.get("kernel_release", "")}
    config = guest.get("kernel_config", {})
    if (os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04" or
            guest.get("kernel_release") != "6.8.0-147-generic" or image_versions != {version} or
            config.get("config_dynamic_ftrace") != "y" or
            config.get("config_kprobe_events_on_notrace") != "n"):
        raise ValueError("guest package/config does not match the audited Ubuntu source")
    return guest


def build_report(dsc_path: Path, diff_path: Path, upstream_source_path: Path,
                 guest_report_path: Path) -> dict:
    dsc = dsc_path.read_text(encoding="utf-8", errors="strict")
    metadata = source_dsc_metadata(dsc)
    if metadata["source"] != "linux" or metadata["version"] != EXPECTED_UBUNTU_VERSION:
        raise ValueError("Ubuntu source package identity differs from the PC3 kernel")
    if sha256_file(dsc_path) != EXPECTED_DSC_SHA256:
        raise ValueError("source descriptor differs from the downloaded Ubuntu package descriptor")
    diff_sha = sha256_file(diff_path)
    diff_name = "linux_6.8.0-147.147.diff.gz"
    expected_sha = metadata["checksums_sha256"]["sha256"].get(diff_name)
    expected_md5 = metadata["checksums_sha256"]["md5"].get(diff_name)
    actual_md5 = hashlib.md5(diff_path.read_bytes()).hexdigest()
    if expected_sha != diff_sha or diff_sha != EXPECTED_DIFF_SHA256:
        raise ValueError("Ubuntu source diff does not match the descriptor's SHA-256 list")
    if not expected_md5 or expected_md5 != actual_md5:
        raise ValueError("Ubuntu source diff does not match the descriptor's MD5 file list")
    guest_report = json.loads(guest_report_path.read_text(encoding="utf-8"))
    guest = validate_guest_report(guest_report, metadata["version"])
    upstream_sha = sha256_file(upstream_source_path)
    if upstream_sha != EXPECTED_UPSTREAM_SOURCE_SHA256:
        raise ValueError("upstream v6.8 trace_kprobe.c differs from the pinned source")
    contracts = source_contract_ranges(upstream_source_path)
    source_lines = upstream_source_path.read_text(encoding="utf-8", errors="strict").splitlines()
    for contract in contracts:
        block = "\n".join(source_lines[contract["start"] - 1:contract["end"]])
        if contract["name"] == "dynamic-ftrace notrace guard" and (
                "ftrace_location_range" not in block or "CONFIG_KPROBE_EVENTS_ON_NOTRACE" not in block):
            raise ValueError("pinned notrace source contract is missing expected guard expressions")
        if contract["name"] == "trace-kprobe registration" and (
                "return -EINVAL" not in block or "KPROBE_FLAG_DISABLED" not in block or
                "register_kprobe(&tk->rp.kp)" not in block):
            raise ValueError("pinned trace-kprobe registration path is incomplete")
    hunks = diff_hunks(diff_path)
    overlaps = [{"hunk":hunk, "contract":contract["name"]}
                for hunk in hunks for contract in contracts if hunk_overlaps_contract(hunk, contract)]
    if overlaps:
        raise ValueError("Ubuntu source patch changes a kprobe registration contract")
    target_functions = guest["target_fentry_inspection"]
    expected_targets = {"_nv000794rm", "_nv000790rm", "_nv031399rm",
                        "rm_init_private_state", "rm_init_adapter"}
    if not isinstance(target_functions, dict) or set(target_functions) != expected_targets:
        raise ValueError("guest report does not cover the pinned NVIDIA target set")
    if any(item.get("fentry_reference") is not False or item.get("mcount_reference") is not False
           or item.get("symbol_header_found") is not True or item.get("instruction_line_count", 0) < 1
           for item in target_functions.values()):
        raise ValueError("guest module disassembly does not establish the target instrumentation boundary")
    if guest["available_filter_function_targets"]:
        raise ValueError("one or more target functions unexpectedly appear in available_filter_functions")
    return {
        "schema":"nvidia-hybrid-ubuntu-kprobe-source-patch-audit-v1",
        "status":"audited",
        "created_utc":datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_package":{"name":metadata["source"], "version":metadata["version"],
            "dsc_url":UBUNTU_DSC_URL, "diff_url":UBUNTU_DIFF_URL,
            "dsc_sha256":sha256_file(dsc_path), "diff_sha256":diff_sha,
            "diff_sha256_in_dsc":expected_sha, "diff_md5":actual_md5,
            "package_source_page_url":UBUNTU_PACKAGE_PAGE_URL,
            "upstream_source_url":UPSTREAM_SOURCE_URL,
            "upstream_source_sha256":upstream_sha,
            "dsc_signature_verification":"not_verified_public_key_unavailable"},
        "input_evidence":{"guest_module_report_sha256":sha256_file(guest_report_path)},
        "guest":{"hostname":guest["hostname"], "os_release":guest["os_release"],
            "kernel_release":guest["kernel_release"], "installed_kernel_packages":guest["installed_kernel_packages"],
            "kernel_config":guest["kernel_config"], "kernel_config_sha256":guest["kernel_config_sha256"],
            "stock_module_sha256":guest["module_elf"]["decompressed_sha256"],
            "target_fentry_inspection":guest["target_fentry_inspection"],
            "available_filter_function_targets":guest["available_filter_function_targets"]},
        "source_ranges":contracts,
        "ubuntu_trace_kprobe_hunks":hunks,
        "contract_hunk_overlaps":overlaps,
        "conclusion":{"notrace_guard_unchanged_by_ubuntu_diff":True,
            "disabled_registration_path_unchanged_by_ubuntu_diff":True,
            "errno_einval_is_consistent_with_upstream_guard":True,
            "exact_runtime_errno_cause_proven":False,
            "notes":"The observed module functions have no fentry/mcount references and are absent from available_filter_functions. With the guest's dynamic-ftrace/notrace config, the unchanged upstream guard is consistent with the observed EINVAL. The generic error log does not prove this was the exact runtime return path."},
    }


def write_private_new(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsc", type=Path, required=True)
    parser.add_argument("--diff", type=Path, required=True)
    parser.add_argument("--upstream-source", type=Path, required=True)
    parser.add_argument("--guest-report", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.evidence.exists():
        parser.error("evidence destination already exists")
    report = build_report(args.dsc, args.diff, args.upstream_source, args.guest_report)
    write_private_new(args.evidence, report)
    print(json.dumps({"status":report["status"], "evidence":str(args.evidence),
                      "diff_sha256":report["source_package"]["diff_sha256"],
                      "hunks":len(report["ubuntu_trace_kprobe_hunks"]),
                      "contract_overlaps":len(report["contract_hunk_overlaps"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
