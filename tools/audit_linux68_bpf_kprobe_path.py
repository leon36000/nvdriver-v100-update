#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit BPF kprobe routes against PC3's exact Ubuntu 6.8 source inputs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

EXPECTED_DIFF_SHA256 = "370fa76631a470323e92a0b25dca6012287c4ada448c7f2e4954f45a628e936c"
EXPECTED_SOURCE_SHA256 = {
    "trace_event_perf.c": "698c296df9f60325827e7e170db03ed0d1d1792f86d04eaf45af7445c8448a9c",
    "trace_kprobe.c": "3d5130b1c160d3f3dadf482f94337488f8105b9dd07f9b33256bcdd52094cd9b",
    "bpf_trace.c": "f5537c7e6c8e5e8d1faf73e5e9ef93e776db8b7a8cc0182b154021f362e0dfe2",
    "fprobe.c": "6c5a9f0d532bc9b7d9b4d8e7db5578cba9997136dd6055cafbc60d8b6761e893",
}
PATCHED_PATHS = {
    "kernel/trace/trace_event_perf.c",
    "kernel/trace/trace_kprobe.c",
    "kernel/trace/bpf_trace.c",
}
EXPECTED_RM_TARGETS = {
    "_nv000790rm", "_nv000794rm", "_nv031399rm",
    "rm_init_adapter", "rm_init_private_state",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mask_c_comments_and_literals(source: str) -> str:
    pattern = re.compile(
        r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )
    return pattern.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), source)


def function_body(source: str, signature: str) -> str:
    """Return one C function body, ignoring braces in comments and literals."""
    masked = _mask_c_comments_and_literals(source)
    start = masked.find(signature)
    if start < 0:
        raise ValueError(f"missing function signature: {signature}")
    opening = masked.find("{", start + len(signature))
    semicolon = masked.find(";", start + len(signature))
    if opening < 0 or (semicolon >= 0 and semicolon < opening):
        raise ValueError(f"function body not found: {signature}")
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening:index + 1]
    raise ValueError(f"unterminated function body: {signature}")


def audit_source_paths(sources: dict[str, str]) -> dict[str, object]:
    """Check the perf-event and fprobe BPF paths and their registration APIs."""
    required = {"perf", "trace_kprobe", "bpf_trace", "fprobe"}
    if set(sources) != required:
        raise ValueError("source set must contain perf, trace_kprobe, bpf_trace and fprobe")

    perf_init = function_body(sources["perf"], "int perf_kprobe_init(")
    local_probe = function_body(sources["trace_kprobe"], "create_local_trace_kprobe(")
    trace_register = function_body(sources["trace_kprobe"], "static int __register_trace_kprobe(")
    multi_attach = function_body(sources["bpf_trace"], "int bpf_kprobe_multi_link_attach(")
    fprobe_register = function_body(sources["fprobe"], "int register_fprobe_ips(")

    if "create_local_trace_kprobe(" not in perf_init:
        raise ValueError("perf kprobe route no longer uses create_local_trace_kprobe")
    if "__register_trace_kprobe(tk)" not in local_probe:
        raise ValueError("local perf kprobe route no longer uses trace-kprobe registration")
    if ("within_notrace_func(tk)" not in trace_register or
            "return -EINVAL" not in trace_register or "register_kprobe(" not in trace_register):
        raise ValueError("trace-kprobe notrace guard or direct registration path is absent")
    guard_start = sources["trace_kprobe"].find("#if defined(CONFIG_DYNAMIC_FTRACE) &&")
    guard_else = sources["trace_kprobe"].find("#else", guard_start)
    guard_end = guard_else if guard_else >= 0 else sources["trace_kprobe"].find("#endif", guard_start)
    guard_text = sources["trace_kprobe"][guard_start:guard_end] if guard_start >= 0 and guard_end >= 0 else ""
    if ("!defined(CONFIG_KPROBE_EVENTS_ON_NOTRACE)" not in guard_text or
            "within_notrace_func" not in guard_text):
        raise ValueError("notrace guard compile-time conditions are absent")
    if ("ftrace_lookup_symbols(" not in multi_attach or
            "register_fprobe_ips(" not in multi_attach or "register_kprobe(" in multi_attach):
        raise ValueError("BPF kprobe-multi no longer resolves ftrace IPs and registers an fprobe")
    if ("ftrace_set_filter_ips(" not in fprobe_register or
            "register_ftrace_function(" not in fprobe_register):
        raise ValueError("fprobe IP registration no longer uses the ftrace function API")

    return {
        "perf_event_kprobe_uses_notrace_guard": True,
        "perf_event_route": [
            "perf_kprobe_init",
            "create_local_trace_kprobe",
            "__register_trace_kprobe",
            "within_notrace_func -> -EINVAL",
        ],
        "kprobe_multi_uses_ftrace_fprobe": True,
        "kprobe_multi_route": [
            "bpf_kprobe_multi_link_attach",
            "ftrace_lookup_symbols",
            "register_fprobe_ips",
            "ftrace_set_filter_ips",
            "register_ftrace_function",
        ],
        "direct_kprobe_registration_in_kprobe_multi": False,
    }


def selected_diff_blocks(diff_text: str, selected_paths: set[str]) -> str:
    """Select unified-diff file blocks using their original source paths."""
    blocks: list[str] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("--- linux-6.8.0.orig/"):
            if current_path in selected_paths:
                blocks.extend(current_lines)
            current_path = line.split("orig/", 1)[1].strip()
            current_lines = [line]
        elif current_path is not None:
            current_lines.append(line)
    if current_path in selected_paths:
        blocks.extend(current_lines)
    if not blocks:
        raise ValueError("Ubuntu diff has no selected source-file blocks")
    return "".join(blocks)


def diff_file_paths(diff_text: str) -> set[str]:
    return {
        line.split("orig/", 1)[1].strip()
        for line in diff_text.splitlines()
        if line.startswith("--- linux-6.8.0.orig/")
    }


def selected_gzip_diff(diff_path: Path) -> str:
    with gzip.open(diff_path, "rt", encoding="utf-8", errors="strict") as stream:
        return stream.read()


def apply_selected_patch(diff_text: str, source_paths: dict[str, Path]) -> tuple[dict[str, str], str]:
    if set(source_paths) != PATCHED_PATHS:
        raise ValueError("exactly the three pinned trace source files are required")
    patch_binary = shutil.which("patch")
    if not patch_binary:
        raise RuntimeError("patch utility is unavailable")
    selected = selected_diff_blocks(diff_text, PATCHED_PATHS)
    with tempfile.TemporaryDirectory(prefix="linux68-bpf-kprobe-audit-") as tmp_name:
        root = Path(tmp_name)
        for relative, source in source_paths.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        patch_file = root / "selected-ubuntu.patch"
        patch_file.write_text(selected, encoding="utf-8")
        result = subprocess.run(
            [patch_binary, "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_file)],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0 or "fuzz" in output.lower() or "offset" in output.lower():
            raise RuntimeError("Ubuntu source patch did not apply cleanly: " + output[:400])
        for relative in source_paths:
            if f"patching file {relative}" not in output:
                raise RuntimeError("Ubuntu source patch skipped a required file: " + relative)
        patched = {
            key: (root / key).read_text(encoding="utf-8", errors="strict")
            for key in source_paths
        }
        return patched, output


def validate_pc3_evidence(capability: object, module: object) -> dict[str, object]:
    if (not isinstance(capability, dict) or capability.get("status") != "observed" or
            capability.get("schema") != "nvidia-hybrid-pc3-v100-trace-capability-transport-v2"):
        raise ValueError("PC3 capability evidence is incomplete")
    guest = capability.get("remote", {}).get("guest", {}) if isinstance(capability.get("remote"), dict) else {}
    config = guest.get("kernel_probe_config", {}) if isinstance(guest, dict) else {}
    bpf = guest.get("bpf_attachment_capabilities", {}) if isinstance(guest, dict) else {}
    if (guest.get("hostname") != "pc3-v100" or guest.get("kernel_release") != "6.8.0-147-generic" or
            len(guest.get("gpus", [])) != 1 or "Tesla V100" not in guest["gpus"][0].get("name", "") or
            guest["gpus"][0].get("driver_version") != "580.178.04"):
        raise ValueError("capability evidence is not the pinned PC3 V100/R580 guest")
    expected_config = {
        "config_dynamic_ftrace": "y",
        "config_kprobe_events_on_notrace": "n",
        "config_bpf_syscall": "y",
        "config_bpf_events": "y",
        "config_fprobe": "y",
    }
    for key, value in expected_config.items():
        if config.get(key) != value:
            raise ValueError("PC3 kernel config does not satisfy the expected BPF/ftrace boundary: " + key)
    if (not isinstance(bpf, dict) or not isinstance(bpf.get("effective_capabilities"), dict) or
            not isinstance(bpf.get("tools_available"), dict)):
        raise ValueError("PC3 BPF capability inventory is absent")
    capabilities = bpf["effective_capabilities"]
    if not all(capabilities.get(key) is True for key in ("cap_bpf", "cap_perfmon", "cap_sys_admin")):
        raise ValueError("PC3 guest lacks the recorded privileged BPF capabilities")

    if (not isinstance(module, dict) or module.get("status") != "observed" or
            module.get("schema") != "nvidia-hybrid-pc3-v100-module-ftrace-transport-v4"):
        raise ValueError("PC3 module ftrace evidence is incomplete")
    module_guest = module.get("remote", {}).get("guest", {}) if isinstance(module.get("remote"), dict) else {}
    if (module_guest.get("hostname") != "pc3-v100" or
            module_guest.get("available_filter_function_targets") != []):
        raise ValueError("module ftrace evidence does not establish zero target callsites")
    targets = module_guest.get("module_elf", {}).get("target_symbols", {})
    inspections = module_guest.get("target_fentry_inspection", {})
    if (set(targets) != EXPECTED_RM_TARGETS or set(inspections) != EXPECTED_RM_TARGETS or any(
        not isinstance(item, dict) or item.get("fentry_reference") is not False or
        item.get("mcount_reference") is not False
        for item in inspections.values()
    )):
        raise ValueError("module ftrace evidence does not show all target functions without callsites")
    if any(not item.get("objdump_succeeded") or not item.get("symbol_found")
           for item in inspections.values()):
        raise ValueError("module ftrace evidence does not contain complete disassembly for each target")
    return {
        "guest": "pc3-v100",
        "kernel_release": "6.8.0-147-generic",
        "gpu": guest["gpus"][0],
        "driver": "580.178.04",
        "config": {key: config[key] for key in expected_config},
        "bpf_tools_available": bpf["tools_available"],
        "effective_capabilities": {key: capabilities[key] for key in ("cap_bpf", "cap_perfmon", "cap_sys_admin")},
        "target_filter_functions": module_guest["available_filter_function_targets"],
        "target_fentry_mcount_references": False,
    }


def write_private_new(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diff", type=Path, required=True)
    parser.add_argument("--perf-source", type=Path, required=True)
    parser.add_argument("--trace-kprobe-source", type=Path, required=True)
    parser.add_argument("--bpf-trace-source", type=Path, required=True)
    parser.add_argument("--fprobe-source", type=Path, required=True)
    parser.add_argument("--capability-evidence", type=Path, required=True)
    parser.add_argument("--module-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output destination already exists")

    inputs = {
        "diff": args.diff,
        "trace_event_perf.c": args.perf_source,
        "trace_kprobe.c": args.trace_kprobe_source,
        "bpf_trace.c": args.bpf_trace_source,
        "fprobe.c": args.fprobe_source,
        "capability_evidence": args.capability_evidence,
        "module_evidence": args.module_evidence,
    }
    expected = {"diff": EXPECTED_DIFF_SHA256, **{
        key: EXPECTED_SOURCE_SHA256[key] for key in EXPECTED_SOURCE_SHA256
    }}
    for key, digest in expected.items():
        if sha256_file(inputs[key]) != digest:
            raise ValueError("hash mismatch for pinned source input: " + key)

    capability = json.loads(args.capability_evidence.read_text(encoding="utf-8"))
    module = json.loads(args.module_evidence.read_text(encoding="utf-8"))
    guest_evidence = validate_pc3_evidence(capability, module)
    source_paths = {
        "kernel/trace/trace_event_perf.c": args.perf_source,
        "kernel/trace/trace_kprobe.c": args.trace_kprobe_source,
        "kernel/trace/bpf_trace.c": args.bpf_trace_source,
    }
    diff_text = selected_gzip_diff(args.diff)
    changed_paths = diff_file_paths(diff_text)
    if "kernel/trace/fprobe.c" in changed_paths:
        raise ValueError("Ubuntu diff changes fprobe core; its source patch must be included")
    patched, patch_output = apply_selected_patch(diff_text, source_paths)
    route = audit_source_paths({
        "perf": patched["kernel/trace/trace_event_perf.c"],
        "trace_kprobe": patched["kernel/trace/trace_kprobe.c"],
        "bpf_trace": patched["kernel/trace/bpf_trace.c"],
        "fprobe": args.fprobe_source.read_text(encoding="utf-8", errors="strict"),
    })
    report = {
        "schema": "nvidia-hybrid-ubuntu-6.8-bpf-kprobe-path-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "static_path_audit_passed",
        "source_package": "linux 6.8.0-147.147; Ubuntu 24.04.5 kernel 6.8.0-147-generic",
        "source_refs": {
            "ubuntu_diff": "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_6.8.0-147.147.diff.gz",
            "trace_event_perf.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/trace/trace_event_perf.c",
            "trace_kprobe.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/trace/trace_kprobe.c",
            "bpf_trace.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/trace/bpf_trace.c",
            "fprobe.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/trace/fprobe.c",
        },
        "inputs": {key: {"path": str(path), "sha256": sha256_file(path)} for key, path in inputs.items()},
        "patch_application": {
            "status": "clean",
            "fuzz": 0,
            "output": patch_output,
            "selected_paths": sorted(PATCHED_PATHS),
            "fprobe_core_patched": "kernel/trace/fprobe.c" in changed_paths,
            "trace_fprobe_frontend_patched": "kernel/trace/trace_fprobe.c" in changed_paths,
        },
        "audit_tool": {"path": str(Path(__file__).resolve()), "sha256": sha256_file(Path(__file__).resolve())},
        "guest_evidence": guest_evidence,
        "routes": route,
        "conclusion": {
            "bpf_perfevent_kprobe_bypasses_notrace": False,
            "bpf_kprobe_multi_can_target_these_rm_functions": False,
            "reason": "The perf-event path reaches the notrace rejection in trace-kprobe registration. The Ubuntu kprobe-multi path resolves ftrace IPs and registers an fprobe; the exact guest has no target ftrace callsites.",
            "runtime_attach_attempted": False,
            "driver_or_gpu_changed": False,
            "limitations": "This closes these BPF attachment routes only. It does not prove the exact errno from the earlier tracefs attempt or rule out a separately reviewed direct register_kprobe diagnostic module.",
        },
    }
    write_private_new(args.output, json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output),
                      "output_sha256": sha256_file(args.output),
                      "routes": route["perf_event_route"],
                      "kprobe_multi_route": route["kprobe_multi_route"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
