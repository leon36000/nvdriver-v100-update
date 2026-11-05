#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit direct register_kprobe feasibility against PC3's exact Linux 6.8 sources."""
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
    "arch/x86/kernel/kprobes/core.c": "efb80a526428179345d10ff12c008f5e6e59bf18ef885c78b6a6a6e116752a18",
    "include/linux/kprobes.h": "2fdf253122f970e33c43fa10a6bb0d54a8b29a2636428a95ac20251a3b3b7fa6",
    "kernel/kallsyms.c": "231cbbe10420d8b1652145da3af908d63e03775c11f3ce052f85720bbeccb9dc",
    "kernel/kprobes.c": "8044adfbc5198aaddefd882fba4eb2c95a3b341b7194eea5fe4d5c899d1c9438",
    "kernel/module/kallsyms.c": "010bdb7ceffbe02f51cfdf0353a4762c2f0aaa3abdc1d73632a812d4244d690b",
    "kernel/trace/trace_kprobe.c": "3d5130b1c160d3f3dadf482f94337488f8105b9dd07f9b33256bcdd52094cd9b",
}
PATCHED_PATHS = set(EXPECTED_SOURCE_SHA256)
TARGETS = {
    "_nv000790rm", "_nv000794rm", "_nv031399rm",
    "rm_init_adapter", "rm_init_private_state",
}
SOURCE_URLS = {
    "ubuntu_diff": "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_6.8.0-147.147.diff.gz",
    "kernel/kprobes.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/kprobes.c",
    "include/linux/kprobes.h": "https://raw.githubusercontent.com/torvalds/linux/v6.8/include/linux/kprobes.h",
    "kernel/kallsyms.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/kallsyms.c",
    "kernel/module/kallsyms.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/module/kallsyms.c",
    "arch/x86/kernel/kprobes/core.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/kernel/kprobes/core.c",
    "kernel/trace/trace_kprobe.c": "https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/trace/trace_kprobe.c",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mask_comments_literals(source: str) -> str:
    pattern = re.compile(
        r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )
    return pattern.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), source)


def function_body(source: str, signature: str) -> str:
    """Extract one C function body while ignoring braces in comments/literals."""
    masked = _mask_comments_literals(source)
    start = masked.find(signature)
    if start < 0:
        raise ValueError("missing function signature: " + signature)
    opening = masked.find("{", start + len(signature))
    semicolon = masked.find(";", start + len(signature))
    if opening < 0 or (semicolon >= 0 and semicolon < opening):
        raise ValueError("function body not found: " + signature)
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening:index + 1]
    raise ValueError("unterminated function: " + signature)


def selected_diff_blocks(diff_text: str, selected_paths: set[str]) -> str:
    blocks: list[str] = []
    current_path: str | None = None
    current: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("--- linux-6.8.0.orig/"):
            if current_path in selected_paths:
                blocks.extend(current)
            current_path = line.split("orig/", 1)[1].strip()
            current = [line]
        elif current_path is not None:
            current.append(line)
    if current_path in selected_paths:
        blocks.extend(current)
    if not blocks:
        raise ValueError("Ubuntu diff has no selected Linux source blocks")
    found = {
        line.split("orig/", 1)[1].strip()
        for line in diff_text.splitlines()
        if line.startswith("--- linux-6.8.0.orig/")
    }
    if found.intersection(selected_paths) != selected_paths:
        missing = sorted(selected_paths - found)
        raise ValueError("Ubuntu diff lacks pinned paths: " + ", ".join(missing))
    return "".join(blocks)


def apply_selected_patch(diff_text: str, source_paths: dict[str, Path]) -> tuple[dict[str, str], str]:
    if set(source_paths) != PATCHED_PATHS:
        raise ValueError("exactly the six pinned Linux 6.8 source files are required")
    patch_binary = shutil.which("patch")
    if not patch_binary:
        raise RuntimeError("patch utility is unavailable")
    selected = selected_diff_blocks(diff_text, PATCHED_PATHS)
    with tempfile.TemporaryDirectory(prefix="linux68-direct-kprobe-audit-") as tmp_name:
        root = Path(tmp_name)
        for relative, source in source_paths.items():
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        patch_file = root / "selected-ubuntu.patch"
        patch_file.write_text(selected, encoding="utf-8")
        result = subprocess.run(
            [patch_binary, "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_file)],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            check=False, timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode != 0 or "fuzz" in output.lower() or "offset" in output.lower():
            raise RuntimeError("Ubuntu source patch did not apply exactly: " + output[:500])
        for relative in source_paths:
            if f"patching file {relative}" not in output:
                raise RuntimeError("Ubuntu source patch skipped a required file: " + relative)
        patched = {
            key: (root / key).read_text(encoding="utf-8", errors="strict")
            for key in source_paths
        }
        return patched, output


def audit_direct_route(sources: dict[str, str]) -> dict[str, object]:
    required = PATCHED_PATHS
    if set(sources) != required:
        raise ValueError("source set must contain exactly the pinned patched source paths")
    core = sources["kernel/kprobes.c"]
    resolver = function_body(core, "_kprobe_addr(kprobe_opcode_t *addr")
    ftrace_check = function_body(core, "static int check_ftrace_location(")
    safety = function_body(core, "static int check_kprobe_address_safe(")
    register = function_body(core, "int register_kprobe(struct kprobe *p)")
    arm = function_body(core, "static int arm_kprobe(struct kprobe *kp)")
    unregister_many = function_body(core, "void unregister_kprobes(struct kprobe **kps, int num)")
    module_lifecycle = function_body(core, "static int kprobes_module_callback(")
    kill = function_body(core, "static void kill_kprobe(struct kprobe *p)")
    module_resolver = function_body(
        sources["kernel/module/kallsyms.c"],
        "static unsigned long __module_kallsyms_lookup_name(const char *name)",
    )
    trace_register = function_body(
        sources["kernel/trace/trace_kprobe.c"], "static int __register_trace_kprobe("
    )
    x86_entry = function_body(
        sources["arch/x86/kernel/kprobes/core.c"], "kprobe_opcode_t *arch_adjust_kprobe_addr("
    )
    header = sources["include/linux/kprobes.h"]

    if "kprobe_lookup_name(symbol_name, offset)" not in resolver:
        raise ValueError("direct kprobe address path no longer resolves symbol_name in the kernel")
    weak_lookup = function_body(core, "kprobe_opcode_t * __weak kprobe_lookup_name(")
    if "kallsyms_lookup_name(name)" not in weak_lookup:
        raise ValueError("default kprobe symbol resolution no longer uses kallsyms_lookup_name")
    if ("strnchr(name, MODULE_NAME_LEN, ':')" not in module_resolver or
            "find_module_all(name" not in module_resolver or
            "__find_kallsyms_symbol_value(mod, colon + 1)" not in module_resolver):
        raise ValueError("module-qualified kallsyms lookup is absent")
    if ("check_kprobe_address_safe(p, &probed_mod)" not in register or
            "prepare_kprobe(p)" not in register or "arm_kprobe(p)" not in register or
            "module_put(probed_mod)" not in register or
            "EXPORT_SYMBOL_GPL(register_kprobe)" not in core):
        raise ValueError("direct register_kprobe module path is incomplete or not GPL-exported")
    if "within_notrace_func" in register or "within_notrace_func" in safety:
        raise ValueError("direct register_kprobe path unexpectedly invokes trace notrace guard")
    if ("ftrace_location(addr) == addr" not in ftrace_check or
            "p->flags |= KPROBE_FLAG_FTRACE" not in ftrace_check or
            "return 0" not in ftrace_check):
        raise ValueError("direct kprobe ftrace selection has changed")
    if ("kprobe_ftrace(kp)" not in arm or "__arm_kprobe(kp)" not in arm or
            "mutex_lock(&text_mutex)" not in arm):
        raise ValueError("non-ftrace direct kprobes no longer use the architecture breakpoint path")
    if ("__module_text_address" not in safety or "try_module_get(*probed_mod)" not in safety or
            "within_module_init" not in safety or "within_kprobe_blacklist" not in safety):
        raise ValueError("target-module lifetime, init-text, or blacklist checks are absent")
    if ("synchronize_rcu()" not in unregister_many or
            "__unregister_kprobe_bottom" not in unregister_many):
        raise ValueError("unregister path does not synchronize handler lifetime")
    if ("MODULE_STATE_GOING" not in module_lifecycle or
            "within_module_core" not in module_lifecycle or "kill_kprobe(p)" not in module_lifecycle or
            "KPROBE_FLAG_GONE" not in kill):
        raise ValueError("target module-unload probe invalidation path is absent")
    if "register_kprobe" not in header or "unregister_kprobe" not in header:
        raise ValueError("kprobe APIs are not declared in the Linux header")
    if "copy_from_kernel_nofault(&insn" not in x86_entry or "is_endbr(insn)" not in x86_entry:
        raise ValueError("Ubuntu x86 kprobe entry adjustment no longer uses nofault instruction read")
    if "within_notrace_func(tk)" not in trace_register:
        raise ValueError("trace-event route no longer exposes the distinct notrace guard")

    return {
        "direct_register_kprobe_module_api": True,
        "module_qualified_symbol_resolution": True,
        "register_kprobe_gpl_export": True,
        "direct_path_notrace_guard": False,
        "non_ftrace_target_uses_arch_breakpoint": True,
        "module_text_ref_held_during_patch": True,
        "unregister_waits_for_rcu_handlers": True,
        "target_module_unload_invalidates_probes": True,
        "ubuntu_x86_entry_nofault_read": True,
        "contrasting_trace_event_path_has_notrace_guard": True,
        "sequence": [
            "kprobe.symbol_name (module:symbol)",
            "_kprobe_addr -> kprobe_lookup_name -> kallsyms_lookup_name",
            "check_kprobe_address_safe",
            "prepare_kprobe",
            "arm_kprobe -> __arm_kprobe (no ftrace callsite)",
            "unregister_kprobes -> synchronize_rcu -> free probe state",
        ],
    }


def validate_pc3_evidence(capability: object, module: object) -> dict[str, object]:
    if not isinstance(capability, dict) or capability.get("status") != "observed":
        raise ValueError("PC3 capability evidence is incomplete")
    guest = capability.get("remote", {}).get("guest", {}) if isinstance(capability.get("remote"), dict) else {}
    config = guest.get("kernel_probe_config", {}) if isinstance(guest, dict) else {}
    if (guest.get("hostname") != "pc3-v100" or guest.get("kernel_release") != "6.8.0-147-generic" or
            len(guest.get("gpus", [])) != 1 or "Tesla V100" not in guest["gpus"][0].get("name", "") or
            guest["gpus"][0].get("driver_version") != "580.178.04"):
        raise ValueError("capability report is not the exact PC3 V100/R580 guest")
    expected_config = {
        "config_kprobes": "y", "config_modules": "y", "config_module_unload": "y",
        "config_kallsyms": "y", "config_kallsyms_all": "y",
    }
    for key, value in expected_config.items():
        if config.get(key) != value:
            raise ValueError("PC3 lacks a required kprobe/module/symbol config: " + key)
    if not isinstance(module, dict) or module.get("status") != "observed":
        raise ValueError("PC3 module ftrace evidence is incomplete")
    module_guest = module.get("remote", {}).get("guest", {}) if isinstance(module.get("remote"), dict) else {}
    if module_guest.get("hostname") != "pc3-v100" or module_guest.get("available_filter_function_targets") != []:
        raise ValueError("module report does not establish target ftrace absence")
    targets = module_guest.get("module_elf", {}).get("target_symbols", {})
    inspections = module_guest.get("target_fentry_inspection", {})
    if set(targets) != TARGETS or set(inspections) != TARGETS:
        raise ValueError("module evidence must cover the five pinned RM target functions")
    if any(not isinstance(item, dict) or item.get("fentry_reference") is not False or
           item.get("mcount_reference") is not False or item.get("objdump_succeeded") is not True or
           item.get("symbol_found") is not True
           for item in inspections.values()):
        raise ValueError("target ELF evidence does not verify all function bodies lack ftrace calls")
    if any(not isinstance(item, dict) or item.get("section") != ".text" or
           item.get("type") != "FUNC" or not isinstance(item.get("size"), int) or item["size"] <= 0
           for item in targets.values()):
        raise ValueError("target symbols are not all verified non-empty module .text functions")
    return {
        "guest": "pc3-v100", "kernel_release": "6.8.0-147-generic",
        "gpu": guest["gpus"][0], "driver": "580.178.04",
        "config": {key: config[key] for key in expected_config},
        "target_symbols": sorted(TARGETS), "target_filter_functions": [],
        "target_fentry_mcount_references": False,
        "target_functions_in_module_text": True,
    }


def write_private_new(path: Path, report: dict[str, object]) -> None:
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
    parser.add_argument("--diff", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True,
                        help="directory containing the pinned upstream v6.8 source paths")
    parser.add_argument("--capability-evidence", type=Path, required=True)
    parser.add_argument("--module-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output destination already exists")

    source_paths = {rel: args.source_root / rel for rel in EXPECTED_SOURCE_SHA256}
    inputs = {"ubuntu_diff": args.diff, **source_paths,
              "pc3_capability_report": args.capability_evidence,
              "pc3_module_ftrace_report": args.module_evidence}
    if sha256_file(args.diff) != EXPECTED_DIFF_SHA256:
        raise ValueError("Ubuntu source diff hash mismatch")
    for rel, path in source_paths.items():
        if sha256_file(path) != EXPECTED_SOURCE_SHA256[rel]:
            raise ValueError("upstream source hash mismatch: " + rel)
    capability = json.loads(args.capability_evidence.read_text(encoding="utf-8"))
    module = json.loads(args.module_evidence.read_text(encoding="utf-8"))
    guest = validate_pc3_evidence(capability, module)
    with gzip.open(args.diff, "rt", encoding="utf-8", errors="strict") as stream:
        diff_text = stream.read()
    patched, patch_output = apply_selected_patch(diff_text, source_paths)
    route = audit_direct_route(patched)
    report = {
        "schema": "nvidia-hybrid-ubuntu-6.8-direct-kprobe-path-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": "static_path_audit_passed",
        "source_package": "linux 6.8.0-147.147; Ubuntu 24.04.5 kernel 6.8.0-147-generic",
        "source_refs": SOURCE_URLS,
        "inputs": {key: {"path": str(path), "sha256": sha256_file(path)} for key, path in inputs.items()},
        "patch_application": {"status": "clean", "fuzz": 0, "output": patch_output,
                              "selected_paths": sorted(PATCHED_PATHS)},
        "audit_tool": {"path": str(Path(__file__).resolve()),
                       "sha256": sha256_file(Path(__file__).resolve())},
        "guest_evidence": guest,
        "route": route,
        "conclusion": {
            "direct_register_kprobe_source_route_exists": True,
            "direct_route_bypasses_trace_event_notrace_guard": True,
            "runtime_attach_tested": False,
            "driver_or_gpu_changed": False,
            "next_step": "Build a one-target GPL diagnostic module with a no-sleep/no-allocation handler, run its attach/capture/unregister test on the PC3 V100 canary, and retain an immediate cleanup path.",
            "limitations": "Static source/config feasibility only. It does not establish module-signing policy, target symbol uniqueness at runtime, successful breakpoint preparation on the installed NVIDIA binary, observed function arguments, or GPU behavior.",
        },
    }
    write_private_new(args.output, report)
    print(json.dumps({"status": report["status"], "output": str(args.output),
                      "output_sha256": sha256_file(args.output),
                      "direct_route": route["sequence"],
                      "runtime_attach_tested": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
