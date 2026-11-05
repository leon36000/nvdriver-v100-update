#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a built R580 UVM module against the hybrid frontend's exported ABI.

This reads module metadata, the actual module modversion table, the frontend
Module.symvers, and the Kbuild log. It never installs or loads a module.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_TAG = "580.178.04"
DEFAULT_PROVIDER = "hybrid580_frontend"
SUPPORTED_PROVIDERS = {DEFAULT_PROVIDER, "nvidia"}
FATAL_BUILD_RE = re.compile(
    r"(?i)(?:\berror:\s|\bfatal error\b|undefined reference|undefined symbol|"
    r"multiple definition|no rule to make target|make(?:\[\d+\])?:\s*\*\*\*|"
    r"\bError\s+[1-9][0-9]*\b)"
)
CRC_RE = re.compile(r"0[xX]([0-9a-fA-F]+)")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def parse_frontend_symvers(text: str, *, provider: str = DEFAULT_PROVIDER) -> dict[str, str]:
    """Return uniquely owned frontend nvUvmInterface exports and CRCs."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"unsupported frontend provider {provider!r}")
    exports: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) < 4:
            continue
        crc, name, module, export_type = fields[:4]
        if module != provider or not name.startswith("nvUvmInterface"):
            continue
        if not export_type.startswith("EXPORT_SYMBOL"):
            continue
        match = CRC_RE.fullmatch(crc)
        if match is None:
            raise ValueError(f"malformed CRC on frontend Module.symvers line {line_number}")
        normalized = f"0x{match.group(1).lower().zfill(8)}"
        previous = exports.get(name)
        if previous is not None and previous != normalized:
            raise ValueError(f"conflicting frontend CRC rows for {name}")
        exports[name] = normalized
    if not exports:
        raise ValueError(f"no nvUvmInterface exports found for {provider}")
    return exports


def parse_dump_modversions(text: str) -> dict[str, str]:
    """Parse kmod's `modprobe --dump-modversions` output."""
    imports: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if len(fields) < 2 or not fields[1].startswith("nvUvmInterface"):
            continue
        match = CRC_RE.fullmatch(fields[0])
        if match is None:
            raise ValueError(f"malformed modversion CRC on output line {line_number}")
        normalized = f"0x{match.group(1).lower().zfill(8)}"
        name = fields[1]
        previous = imports.get(name)
        if previous is not None and previous != normalized:
            raise ValueError(f"conflicting consumer CRC rows for {name}")
        imports[name] = normalized
    if not imports:
        raise ValueError("module contains no nvUvmInterface modversion entries")
    return imports


def compare_crc_tables(imports: dict[str, str], exports: dict[str, str]) -> dict[str, Any]:
    missing = sorted(set(imports) - set(exports))
    provider_only = sorted(set(exports) - set(imports))
    mismatches = [
        {"symbol": name, "consumer_crc": imports[name], "provider_crc": exports[name]}
        for name in sorted(set(imports) & set(exports))
        if imports[name] != exports[name]
    ]
    return {
        "consumer_import_count": len(imports),
        "provider_export_count": len(exports),
        "exact_symbol_set_match": not missing and not provider_only,
        "all_crcs_match": not missing and not mismatches,
        "missing_provider_symbols": missing,
        "provider_only_symbols": provider_only,
        "crc_mismatches": mismatches,
    }


def validate_consumer_provider_abi(imports: dict[str, str],
                                   exports: dict[str, str]) -> dict[str, Any]:
    """Require every consumer import to exist with the exact provider CRC.

    A provider may export additional symbols that this consumer does not use;
    that is normal for Linux module dependencies and is recorded in the result
    without being treated as an ABI failure.
    """
    comparison = compare_crc_tables(imports, exports)
    if comparison["missing_provider_symbols"]:
        raise ValueError("UVM imports without provider exports")
    if comparison["crc_mismatches"]:
        raise ValueError("UVM consumer/provider CRC mismatch")
    return comparison


def run_text(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cannot run {argv[0]}: {exc}") from None
    if result.returncode != 0:
        raise ValueError(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()[:500]}")
    return result.stdout


def summarize_build_log(text: str,
                        *,
                        expected_module: str = "nvidia-uvm.ko") -> dict[str, Any]:
    if Path(expected_module).name != expected_module or not re.fullmatch(
            r"[A-Za-z0-9_-]+\.ko", expected_module):
        raise ValueError("expected UVM module filename is invalid")
    lines = text.splitlines()
    errors = [line.strip() for line in lines if FATAL_BUILD_RE.search(line)]
    if errors:
        raise ValueError("build log contains errors: " + " | ".join(errors[:4]))
    modpost_count = sum("MODPOST Module.symvers" in line for line in lines)
    module_linked = any(
        re.search(r"\bLD\s+\[M\]\s+" + re.escape(expected_module) + r"\s*$", line)
        for line in lines
    )
    if modpost_count == 0 or not module_linked:
        raise ValueError("build log lacks successful UVM MODPOST/link steps")
    return {
        "modpost_count": modpost_count,
        "nvidia_uvm_linked": module_linked,
        "warning_line_count": sum("warning:" in line.lower() for line in lines),
        "error_lines": [],
    }


def module_field(module: Path, field: str) -> str:
    return run_text(["modinfo", "-F", field, str(module)]).strip()


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    module = args.module.resolve(strict=True)
    symvers = args.frontend_symvers.resolve(strict=True)
    log = args.build_log.resolve(strict=True)
    for path in (module, symvers, log):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required input is absent or not a regular file: {path}")

    version = module_field(module, "version")
    depends = module_field(module, "depends")
    vermagic = module_field(module, "vermagic")
    provider = args.frontend_module_name
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"unsupported frontend provider {provider!r}")
    if version != SOURCE_TAG:
        raise ValueError(f"module version {version!r} does not match R580 {SOURCE_TAG}")
    if provider not in {item for item in depends.split(",") if item}:
        raise ValueError(f"module dependencies do not include {provider}")
    kernel_tokens = vermagic.split()
    if not kernel_tokens or kernel_tokens[0] != args.kernel_release:
        raise ValueError("module vermagic does not match the requested kernel release")

    imports = parse_dump_modversions(run_text(["modprobe", "--dump-modversions", str(module)]))
    exports = parse_frontend_symvers(
        symvers.read_text(encoding="utf-8", errors="strict"), provider=provider
    )
    comparison = validate_consumer_provider_abi(imports, exports)

    log_summary = summarize_build_log(
        log.read_text(encoding="utf-8", errors="strict"),
        expected_module=module.name,
    )
    return {
        "schema": "nvidia-r580-uvm-consumer-frontend-abi-v2",
        "qualification": "compiled-and-consumer-modversion-crcs-validated",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_version": version,
        "kernel_release": args.kernel_release,
        "module": {
            "path": project_path(module),
            "bytes": module.stat().st_size,
            "sha256": sha256_file(module),
            "version": version,
            "depends": depends,
            "vermagic": vermagic,
        },
        "frontend_symvers": {
            "path": project_path(symvers),
            "sha256": sha256_file(symvers),
            "provider": provider,
        },
        "build_log": {
            "path": project_path(log),
            "sha256": sha256_file(log),
            **log_summary,
        },
        "uvm_interface": comparison,
        "runtime_or_hardware_validated": False,
        "loaded_or_installed": False,
        "notes": [
            "Kbuild MODPOST and the actual .ko modversion table agree with the frontend Module.symvers.",
            "Provider-only nvUvmInterface exports are reported but are valid; every consumer import must resolve with an exact CRC.",
            "This does not validate callback payload semantics, module coexistence at runtime, RM initialization, CUDA, or GPU behavior.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--frontend-symvers", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument(
        "--frontend-module-name", choices=sorted(SUPPORTED_PROVIDERS),
        default=DEFAULT_PROVIDER,
        help="exact provider module recorded in Module.symvers and UVM depends metadata",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build_report(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.output.chmod(0o600)
        print(json.dumps({
            "report": project_path(args.output),
            "qualification": report["qualification"],
            "consumer_import_count": report["uvm_interface"]["consumer_import_count"],
            "all_crcs_match": report["uvm_interface"]["all_crcs_match"],
        }, sort_keys=True))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
