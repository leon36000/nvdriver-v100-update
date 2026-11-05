#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Statically compare the CUDA probe's dlsym API surface with staged libcuda.

This reads source, ELF symbol metadata, and pinned staging receipts only. It
does not load libcuda, call CUDA, access a GPU, or change the installed driver.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hybrid_cuda_probe.cpp"
SOURCE_SHA256 = "59b6b057e7b122b4e3d9882c4304e9818660ec4dd2f8a13d268958fb97a26384"
PROBE = ROOT / "build/probe-peer-transfer-v3-20261031/hybrid_cuda_probe"
PROBE_SHA256 = "d7cdbd528cbf4665a1ffe2ca0d5792e8e70de98cb88fd368f4a1e496abdcac13"
STAGE_REPORT = ROOT / "evidence/r595.99.02-compute-userland-stage-v1-20261031.json"
STAGE_REPORT_SHA256 = "492f8bdc48bf2d4b2d0afb3e5498ef069834f891b043ecd7b27c6f58e6c36312"
STAGED_LIBCUDA = ROOT / (
    "build/staging/r595.99.02-compute-userland-v1-20261031/"
    "usr/lib/x86_64-linux-gnu/libcuda.so.595.99.02"
)
STAGED_LIBCUDA_SHA256 = "192d4eedb1b39f0568f2b5423d35227d13b32b9025599e1968a9081982da207d"
DEFAULT_REPORT = ROOT / "evidence/r595.99.02-libcuda-probe-symbol-audit-v1-20261031.json"
CORE_LOAD = re.compile(r'\bLOAD\s*\(\s*\w+\s*,\s*"(cu[A-Za-z0-9_]+)"\s*\)')
TYPED_LOOKUP = re.compile(r'\bsymbol\s*<[^\n]*?>\s*\(\s*"(cu[A-Za-z0-9_]+)"\s*\)')
DIRECT_DLSYM = re.compile(r'\bdlsym\s*\(\s*library\s*,\s*"(cu[A-Za-z0-9_]+)"\s*\)')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_pinned_file(path: Path, expected_sha256: str, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError(f"{label} hash differs from the pin")
    return raw


def extract_probe_symbols(source: str) -> dict[str, list[str]]:
    """Collect mandatory constructor LOADs and conditional/fallback lookups."""
    core = set(CORE_LOAD.findall(source))
    conditional = set(TYPED_LOOKUP.findall(source)) | set(DIRECT_DLSYM.findall(source))
    if not core:
        raise ValueError("probe source contains no recognizable mandatory CUDA lookups")
    conditional -= core
    return {"core": sorted(core), "conditional": sorted(conditional),
            "all": sorted(core | conditional)}


def parse_nm_exports(output: str) -> set[str]:
    """Parse GNU nm defined-symbol output, dropping ELF symbol versions."""
    exports = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        symbol_type = fields[-2]
        if len(symbol_type) != 1 or symbol_type.upper() == "U":
            continue
        name = fields[-1].split("@", 1)[0]
        if name.startswith("cu"):
            exports.add(name)
    return exports


def _validate_stage_receipt(raw: bytes) -> dict[str, Any]:
    try:
        receipt = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError):
        raise ValueError("pinned R595 userland stage receipt is malformed") from None
    if (receipt.get("schema") != "r595.99.02-compute-userland-stage-v1" or
            receipt.get("qualification") != "pinned-r595-compute-userland-staged; no runtime test" or
            receipt.get("stage", {}).get("path") != str(STAGED_LIBCUDA.parents[3]) or
            receipt.get("stage", {}).get("libraries", {}).get("libcuda", {}).get("sha256") !=
            STAGED_LIBCUDA_SHA256 or
            receipt.get("actions", {}).get("cuda_api_called") is not False or
            receipt.get("actions", {}).get("gpu_accessed") is not False):
        raise ValueError("R595 userland receipt does not match the staged libcuda input")
    return receipt


def _validate_inputs() -> dict[str, Any]:
    source_bytes = _read_pinned_file(SOURCE, SOURCE_SHA256, "probe source")
    probe_bytes = _read_pinned_file(PROBE, PROBE_SHA256, "probe binary")
    stage_bytes = _read_pinned_file(STAGE_REPORT, STAGE_REPORT_SHA256, "stage receipt")
    libcuda = _read_pinned_file(STAGED_LIBCUDA, STAGED_LIBCUDA_SHA256, "staged libcuda")
    receipt = _validate_stage_receipt(stage_bytes)
    if receipt["stage"]["libraries"]["libcuda"].get("bytes") != len(libcuda):
        raise ValueError("staged libcuda size differs from its receipt")
    if not probe_bytes.startswith(b"\x7fELF") or not libcuda.startswith(b"\x7fELF"):
        raise ValueError("probe or staged libcuda is not an ELF file")
    return {
        "source": {"path": str(SOURCE.relative_to(ROOT)), "sha256": SOURCE_SHA256},
        "probe": {"path": str(PROBE.relative_to(ROOT)), "sha256": PROBE_SHA256},
        "stage_receipt": {"path": str(STAGE_REPORT.relative_to(ROOT)),
                          "sha256": STAGE_REPORT_SHA256},
        "staged_libcuda": {"path": str(STAGED_LIBCUDA.relative_to(ROOT)),
                            "sha256": STAGED_LIBCUDA_SHA256, "bytes": len(libcuda)},
    }


def audit(*, runner=subprocess.run) -> dict[str, Any]:
    input_identities = _validate_inputs()
    source = SOURCE.read_text(encoding="utf-8")
    symbol_sets = extract_probe_symbols(source)
    result = runner(["nm", "-D", "--defined-only", str(STAGED_LIBCUDA)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("nm could not read the staged libcuda dynamic symbol table")
    exports = parse_nm_exports(result.stdout)
    missing = sorted(set(symbol_sets["all"]) - exports)
    if missing:
        raise ValueError("staged libcuda does not export probe symbols: " + ", ".join(missing))
    return {
        "schema": "r595.99.02-libcuda-probe-symbol-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "all-probe-cuda-symbols-exported-static",
        "qualification": "analyzed-statically; no library load or CUDA execution",
        "inputs": input_identities,
        "symbol_counts": {
            "core_constructor_lookups": len(symbol_sets["core"]),
            "conditional_and_fallback_lookups": len(symbol_sets["conditional"]),
            "distinct_probe_lookups": len(symbol_sets["all"]),
            "exported_cuda_symbols": len(exports),
            "missing": 0,
        },
        "symbols": {
            "core": symbol_sets["core"],
            "conditional_and_fallback": symbol_sets["conditional"],
            "checked_exports": symbol_sets["all"],
        },
        "actions": {
            "libcuda_loaded": False,
            "cuda_api_called": False,
            "gpu_accessed": False,
            "package_installed": False,
            "module_loaded_or_installed": False,
        },
        "tool_sha256": sha256_file(Path(__file__).resolve(strict=True)),
    }


def _write_private_exclusive(path: Path, report: dict[str, Any]) -> None:
    if path.is_symlink() or path.exists():
        raise FileExistsError("audit report already exists or is a symlink")
    try:
        path.parent.resolve(strict=True).relative_to((ROOT / "evidence").resolve(strict=True))
    except (OSError, ValueError):
        raise ValueError("audit report must remain below the project evidence directory") from None
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)
    try:
        result = audit()
        _write_private_exclusive(args.report, result)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"R595 libcuda symbol audit failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "symbols": result["symbol_counts"],
                      "report": str(args.report)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
