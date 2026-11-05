#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join the pinned R580 selector dataflow to its per-device wrapper lifetime.

This static audit asks whether the PCI private-state lookup and first-open
adapter lookup can address one descriptor key for the same nv_state object.
It does not observe a live selector value or cache hit.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04"
DEFAULT_OBJECT = BASE / "nvidia/nv-kernel.o_binary"
DEFAULT_NV_C = BASE / "nvidia/nv.c"
DEFAULT_NV_PCI_C = BASE / "nvidia/nv-pci.c"
DEFAULT_NV_PLATFORM_C = BASE / "nvidia/nv-platform.c"
DEFAULT_NV_H = BASE / "common/inc/nv.h"
DEFAULT_NV_LINUX_H = BASE / "common/inc/nv-linux.h"

PINNED = {
    "rm_object": "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b",
    "nv_c": "359a50f7dc840c0d7adc40388313391cfcaa55598982a4745622887e9423e005",
    "nv_pci_c": "7ac1926cb26ee6495c7af5b50c073ec6dfc351e2a7654268bebc9bde61862681",
    "nv_platform_c": "9fcce137af66b1ca7e304fc18a62b5654c7bf4fc4814ba10dcc541b1db5d6c96",
    "nv_h": "bc5802ef5a0e47be045cac9b74e61a0092f0bb96fc1ede05e2361d164e3b7787",
    "nv_linux_h": "16b7612d2a0f70708b1400e569a1b5d4b726c0218657d13de34e10c710f9169c",
}


class AuditError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def private_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AuditError(f"could not run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        raise AuditError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr.strip()}")
    return result.stdout


def require(text: str, fragment: str, source_name: str) -> None:
    if fragment not in text:
        raise AuditError(f"expected pinned source/disassembly anchor missing in {source_name}: {fragment}")


def source_anchor(path: Path, source: str, fragment: str, line_offset: int = 0) -> dict[str, object]:
    matches = [index for index, line in enumerate(source.splitlines(), 1) if fragment in line]
    if len(matches) != 1:
        raise AuditError(f"expected exactly one source anchor {fragment!r} in {path}, got lines {matches}")
    return {
        "path": str(path.resolve()),
        "line": line_offset + matches[0],
        "text": source.splitlines()[matches[0] - 1].strip(),
    }


def function_body(source: str, signature: str) -> tuple[str, int]:
    start = source.find(signature)
    if start < 0:
        raise AuditError(f"pinned wrapper source is missing function signature {signature!r}")
    opening = source.find("{", start)
    if opening < 0:
        raise AuditError(f"pinned wrapper source has no body for {signature!r}")

    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if current == "\n":
                state = "code"
        elif state == "block_comment":
            if current == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("string", "character"):
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif (state == "string" and current == '"') or (state == "character" and current == "'"):
                state = "code"
        elif current == "/" and following == "/":
            state = "line_comment"
            index += 1
        elif current == "/" and following == "*":
            state = "block_comment"
            index += 1
        elif current == '"':
            state = "string"
        elif current == "'":
            state = "character"
        elif current == "{":
            depth += 1
        elif current == "}":
            depth -= 1
            if depth == 0:
                body = source[opening : index + 1]
                start_line = source.count("\n", 0, opening) + 1
                return body, start_line - 1
        index += 1
    raise AuditError(f"unclosed function body for {signature!r}")


def audit(
    rm_object: Path,
    nv_c_path: Path,
    nv_pci_c_path: Path,
    nv_platform_c_path: Path,
    nv_h_path: Path,
    nv_linux_h_path: Path,
) -> tuple[dict[str, object], str]:
    inputs = {
        "rm_object": rm_object,
        "nv_c": nv_c_path,
        "nv_pci_c": nv_pci_c_path,
        "nv_platform_c": nv_platform_c_path,
        "nv_h": nv_h_path,
        "nv_linux_h": nv_linux_h_path,
    }
    source_text: dict[str, str] = {}
    for name, path in inputs.items():
        actual = sha256(path)
        if actual != PINNED[name]:
            raise AuditError(f"pinned input hash mismatch for {name}: got {actual}, expected {PINNED[name]}")
        if name != "rm_object":
            source_text[name] = path.read_text(encoding="utf-8")

    nv_c = source_text["nv_c"]
    nv_pci = source_text["nv_pci_c"]
    nv_platform = source_text["nv_platform_c"]
    nv_h = source_text["nv_h"]
    nv_linux_h = source_text["nv_linux_h"]

    # The PCI probe allocates one state container, derives nv_state from it,
    # initializes private state, and only then publishes the device for opens.
    pci_probe, pci_probe_line_offset = function_body(nv_pci, "nv_pci_probe\n(")
    probe_anchors = {
        "per_gpu_state_allocation": source_anchor(nv_pci_c_path, pci_probe, "NV_KZALLOC(nvl, sizeof(nv_linux_state_t));", pci_probe_line_offset),
        "nv_state_is_member_of_that_container": source_anchor(nv_pci_c_path, pci_probe, "nv  = NV_STATE_PTR(nvl);", pci_probe_line_offset),
        "private_state_init_on_pci_probe": source_anchor(nv_pci_c_path, pci_probe, "if (!rm_init_private_state(sp, nv))", pci_probe_line_offset),
        "device_published_after_private_state": source_anchor(nv_pci_c_path, pci_probe, "if (nv_linux_add_device_locked(nvl) != 0)", pci_probe_line_offset),
    }
    # The first open resolves the same per-device container through the minor
    # table and passes its member through nv_open_device -> nv_start_device.
    open_fn, open_line_offset = function_body(nv_c, "int\nnvidia_open(")
    device_open_fn, device_open_line_offset = function_body(nv_c, "static int nv_open_device(")
    start_fn, start_line_offset = function_body(nv_c, "static int nv_start_device(")
    open_anchors = {
        "open_resolves_existing_minor_entry": source_anchor(nv_c_path, open_fn, "nvl = find_minor_locked(NV_DEVICE_MINOR_NUMBER(inode));", open_line_offset),
        "open_recovers_nv_state_member": source_anchor(nv_c_path, open_fn, "nv = NV_STATE_PTR(nvl);", open_line_offset),
        "open_enters_device_open_path": source_anchor(nv_c_path, open_fn, "rc = nv_open_device_for_nvlfp(nv, nvlfp->sp, nvlfp);", open_line_offset),
        "first_open_starts_device": source_anchor(nv_c_path, device_open_fn, "rc = nv_start_device(nv, sp);", device_open_line_offset),
        "start_calls_adapter_init": source_anchor(nv_c_path, start_fn, "if (!rm_init_adapter(sp, nv))", start_line_offset),
    }
    header_anchors = {
        "nv_state_pointer_macro": source_anchor(nv_linux_h_path, nv_linux_h, "#define NV_STATE_PTR(nvl)"),
        "selector_member_name": source_anchor(nv_h_path, nv_h, "NvU32 disp_sw_soc_chip_id;"),
        "zero_initialized_container_macro": source_anchor(nv_linux_h_path, nv_linux_h, "(ptr) = kzalloc(size, NV_GFP_KERNEL);"),
    }
    platform_probe, platform_probe_line_offset = function_body(
        nv_platform, "static int nv_platform_device_display_probe("
    )
    platform_setter = {
        "private_state_init": source_anchor(
            nv_platform_c_path,
            platform_probe,
            "if (!rm_init_private_state(sp, nv))",
            platform_probe_line_offset,
        ),
        "field_store": source_anchor(
            nv_platform_c_path,
            platform_probe,
            "&nv->disp_sw_soc_chip_id);",
            platform_probe_line_offset,
        ),
        "property_name": source_anchor(
            nv_platform_c_path,
            platform_probe,
            '"nvidia,disp-sw-soc-chip-id",',
            platform_probe_line_offset,
        ),
        "order": "platform display probe calls rm_init_private_state before reading this property",
    }

    disassemblies = {
        name: run(["objdump", "-dr", "-M", "intel", f"--disassemble={name}", str(rm_object)])
        for name in ("rm_init_private_state", "rm_init_adapter", "_nv000794rm", "_nv000790rm", "_nv031364rm")
    }
    private_fn = disassemblies["_nv000794rm"]
    for fragment in (
        "test   BYTE PTR [rdi+0x10],0x10",
        "mov    r13d,DWORD PTR [rdi+0x274]",
        "mov    esi,r13d",
        "xor    edx,edx",
        "_nv031399rm-0x4",
    ):
        require(private_fn, fragment, "_nv000794rm")

    adapter_fn = disassemblies["_nv000790rm"]
    for fragment in (
        "mov    eax,DWORD PTR [r12+0x274]",
        "mov    DWORD PTR [r9+0x12c8],eax",
        "_nv031364rm-0x4",
    ):
        require(adapter_fn, fragment, "_nv000790rm")
    enumerate_fn = disassemblies["_nv031364rm"]
    for fragment in (
        "mov    eax,DWORD PTR [rbx+0x12c8]",
        "_nv031399rm-0x4",
    ):
        require(enumerate_fn, fragment, "_nv031364rm")
    adapter_wrapper = disassemblies["rm_init_adapter"]
    require(adapter_wrapper, "test   BYTE PTR [r12+0x11],0x8", "rm_init_adapter branch")
    require(adapter_wrapper, "_nv000790rm-0x4", "rm_init_adapter normal branch")

    # Re-run the established direct-caller/key-argument census as a dependency,
    # keeping its exact assertions in one implementation.
    caller_tool_path = ROOT / "tools/audit_r580_descriptor_cache_callers.py"
    spec = importlib.util.spec_from_file_location("r580_descriptor_cache_callers", caller_tool_path)
    if spec is None or spec.loader is None:
        raise AuditError("could not load the pinned direct-caller audit")
    caller_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = caller_module
    spec.loader.exec_module(caller_module)
    caller_report, caller_log = caller_module.audit(rm_object)

    report: dict[str, object] = {
        "schema": "rea-r580-same-device-selector-reuse-v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "qualification": "analysed_statically",
        "inputs": {
            name: {"path": str(path.resolve()), "sha256": sha256(path)}
            for name, path in inputs.items()
        },
        "wrapper_lifetime": {
            "pci_probe": probe_anchors,
            "first_open": open_anchors,
            "headers": header_anchors,
            "interpretation": "The source connects the PCI probe's nv_state member to a later first-open lookup by resolving the published per-device nvl and applying the same NV_STATE_PTR macro.",
        },
        "selector_fields": {
            "private_state": "nv_state+0x274",
            "adapter_init": "nv_state+0x274 -> record+0x12c8",
            "private_state_gate": "flags bit 0x10 set",
            "adapter_init_gate": "flags bit 0x8 at nv_state+0x11 clear",
            "lookup": "both paths call _nv031399rm with first and third key words zero",
            "normalization": "same _nv031399rm transformation documented by rea-r580-normalized-descriptor-selector-v1",
        },
        "same_per_device_nv_state_object_established_by_wrapper_source": True,
        "same_key_function_and_normalization": True,
        "cache_seed_conclusion": "possible_if_selector_and_registry_entry_remain_unchanged",
        "runtime_selector_equality": "unknown",
        "runtime_cache_hit": "unknown",
        "possible_intervening_field_store": {
            "platform_probe_store": platform_setter,
            "interpretation": "The pinned platform display probe calls rm_init_private_state before reading this property, so this route can change the field after private-state initialization. The audit does not establish that this probe applies to a PCI V100 or that its later adapter init sees this same state object.",
        },
        "direct_caller_audit": {
            "schema": caller_report["schema"],
            "direct_references_to_nv031399rm": caller_report["direct_references_to_nv031399rm"],
            "caller_routes": caller_report["caller_routes"],
        },
        "limitations": [
            "Static wrapper sources tie the per-device nv_state member across PCI probe and first open; they do not observe a runtime pointer or selector value.",
            "The first lookup is gated by flags bit 0x10 and the later lookup by a separate backend flag condition; neither gate's value on a live V100 is established.",
            "Identical selector loads imply the same four-word key only if the field value is unchanged; field aliases and indirect writes are not ruled out.",
            "A shared locked registry makes reuse possible but does not prove that the first path inserts an entry, that it remains present, or that the second path hits it.",
            "No GPU, driver module, VM, PCI binding, firmware, or boot state was changed.",
        ],
        "verification": {
            "direct_caller_report_schema": caller_report["schema"],
            "audit_tool_sha256": sha256(Path(__file__).resolve()),
        },
    }
    raw_log = "\n".join(f"===== {name} =====\n{body}" for name, body in disassemblies.items())
    raw_log += "\n===== direct cache-caller census =====\n" + caller_log
    return report, raw_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rm-object", type=Path, default=DEFAULT_OBJECT)
    parser.add_argument("--nv-c", type=Path, default=DEFAULT_NV_C)
    parser.add_argument("--nv-pci-c", type=Path, default=DEFAULT_NV_PCI_C)
    parser.add_argument("--nv-platform-c", type=Path, default=DEFAULT_NV_PLATFORM_C)
    parser.add_argument("--nv-h", type=Path, default=DEFAULT_NV_H)
    parser.add_argument("--nv-linux-h", type=Path, default=DEFAULT_NV_LINUX_H)
    parser.add_argument("--output", type=Path, help="write a private JSON report instead of stdout")
    parser.add_argument("--raw-log", type=Path, help="also save selected disassembly as a private log")
    args = parser.parse_args(argv)
    try:
        report, raw_log = audit(args.rm_object, args.nv_c, args.nv_pci_c, args.nv_platform_c, args.nv_h, args.nv_linux_h)
        if args.raw_log:
            private_write(args.raw_log, raw_log)
            report["verification"]["raw_disassembly_log"] = {
                "path": str(args.raw_log.resolve()),
                "sha256": hashlib.sha256(raw_log.encode("utf-8")).hexdigest(),
                "mode": "0600",
            }
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            private_write(args.output, encoded)
        else:
            sys.stdout.write(encoded)
        return 0
    except (AuditError, OSError, UnicodeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
