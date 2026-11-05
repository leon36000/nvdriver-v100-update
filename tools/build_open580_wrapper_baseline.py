#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the official Open R580 Linux nvidia.ko wrapper in a fresh tree.

This bounded experiment compiles only the nvidia kernel module wrapper and
links it with a pinned, already-built Open R580 RM object. It never installs,
loads, signs, or patches a kernel module. The resulting symbol report is a
linkage observation, not a hardware qualification.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_DEFAULT = ROOT / ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz"
ARCHIVE_SHA256 = "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"
SOURCE_TOP = "NVIDIA-kernel-module-source-580.178.04"
RM_OBJECT = ROOT / "build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04/src/nvidia/_out/Linux_x86_64/nv-kernel.o"
RM_OBJECT_SHA256 = "5e9219a4a263315d20757159852b35be61dfd2ce75dcd2ca90b1cd1764d6bb8a"
PAIR_EVIDENCE = ROOT / "evidence/same-branch-rm-link-v2-20261018.json"
PAIR_UNDEFINED_EVIDENCE = ROOT / "evidence/r580-external-dependencies-20261018.json"
DEFAULT_WORK = ROOT / "build/experiments/open580-wrapper-baseline-v1"
REPORT_PATH = ROOT / "evidence/open580-wrapper-baseline-20261018.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_logged(name: str, command: list[str], cwd: Path, log: Path,
               timeout: int = 900) -> dict:
    start = time.monotonic()
    with log.open("x", encoding="utf-8") as output:
        output.write("$ " + " ".join(command) + "\n")
        output.write(f"cwd: {cwd}\n\n")
        output.flush()
        try:
            result = subprocess.run(command, cwd=cwd, stdout=output,
                                    stderr=subprocess.STDOUT, check=False,
                                    timeout=timeout, text=True)
            code = result.returncode
        except subprocess.TimeoutExpired:
            output.write(f"\nTIMEOUT after {timeout}s\n")
            code = 124
    return {"name": name, "argv": command, "cwd": str(cwd),
            "exit_code": code, "duration_seconds": round(time.monotonic() - start, 3),
            "log": str(log), "log_sha256": sha256(log), "log_bytes": log.stat().st_size}


def capture(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                          check=False, timeout=120)


def parse_nm_defined(text: str) -> list[dict]:
    """Parse GNU nm -A --format=posix output into exact object definitions."""
    out = []
    for line in text.splitlines():
        # POSIX format: file: symbol type value size (filename may contain colons).
        match = re.match(r"^(.*):\s+(\S+)\s+([A-Za-z?])\s+([0-9A-Fa-f]+)\s+(\S+)\s*$", line)
        if not match:
            continue
        path, name, typ, value, size = match.groups()
        if typ.upper() in {"U", "W", "V"}:
            continue
        out.append({"object": path, "name": name, "type": typ,
                    "value": value, "size": size,
                    "strong_global": typ in "TDBRGS"})
    return out


def parse_nm_undefined(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-2] in {"U", "w", "v"}:
            names.add(fields[-1])
    return names


def parse_readelf_undefined(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[6] == "UND":
            name = fields[7].split("@", 1)[0]
            if name:
                names.add(name)
    return names


def parse_readelf_defined_global(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[4] == "GLOBAL" and fields[6] not in {"UND", "ABS"}:
            name = fields[7].split("@", 1)[0]
            if name:
                names.add(name)
    return names


def load_pair_symbols() -> tuple[list[str], dict[str, dict]]:
    pair = json.loads(PAIR_EVIDENCE.read_text())
    audit = json.loads(PAIR_UNDEFINED_EVIDENCE.read_text())
    if pair.get("combined_undefined_symbol_count") != 411:
        raise ValueError("same-branch RM pair evidence is not the expected 411-UND result")
    rows = audit.get("symbols")
    if not isinstance(rows, list):
        raise ValueError("external-dependency evidence has no symbols array")
    names = [row["name"] for row in rows]
    if len(names) != 411 or len(set(names)) != 411:
        raise ValueError(f"expected 411 unique dependency names, got {len(names)}")
    return names, {row["name"]: row for row in rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", type=Path, default=ARCHIVE_DEFAULT)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK,
                        help="new scratch directory; existing directories are refused")
    parser.add_argument("--kernel-release", default=os.uname().release)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log_dir = ROOT / "evidence/logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_PATH
    report = {
        "schema": "nvidia-open580-wrapper-baseline-v1",
        "source_tag": "580.178.04",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "not-started",
        "scope": "official-open-R580-nvidia-wrapper-only",
        "loaded_or_installed": False,
        "module_license_changed": False,
        "hardware_validated": False,
        "steps": [],
        "pair_undefined_count": None,
        "provider_counts": None,
    }

    def step(name: str, argv: list[str], cwd: Path, timeout: int = 900) -> dict:
        log = log_dir / f"open580-wrapper-{name}-{stamp}.log"
        item = run_logged(name, argv, cwd, log, timeout)
        report["steps"].append(item)
        return item

    try:
        archive = args.source_archive.resolve(strict=True)
        if sha256(archive) != ARCHIVE_SHA256:
            raise ValueError("R580 Open source archive does not match pinned SHA-256")
        rm_object = RM_OBJECT.resolve(strict=True)
        if sha256(rm_object) != RM_OBJECT_SHA256:
            raise ValueError("prebuilt Open R580 RM object does not match pinned SHA-256")
        work = args.work_dir.resolve()
        if work.exists():
            raise FileExistsError(f"refusing to overwrite existing scratch tree: {work}")
        if report_path.exists():
            raise FileExistsError(f"refusing to overwrite existing report: {report_path}")

        pair_names, pair_rows = load_pair_symbols()
        report.update(
            source_archive=str(archive), archive_sha256=ARCHIVE_SHA256,
            source_archive_bytes=archive.stat().st_size,
            rm_object=str(rm_object), rm_object_sha256=RM_OBJECT_SHA256,
            pair_evidence=str(PAIR_EVIDENCE), pair_evidence_sha256=sha256(PAIR_EVIDENCE),
            dependency_evidence=str(PAIR_UNDEFINED_EVIDENCE),
            dependency_evidence_sha256=sha256(PAIR_UNDEFINED_EVIDENCE),
            pair_undefined_count=len(pair_names), kernel_release=args.kernel_release,
            jobs=args.jobs, work_dir=str(work),
        )

        with tarfile.open(archive, "r:xz") as tar:
            members = tar.getmembers()
            roots = {member.name.split("/", 1)[0] for member in members if member.name}
            if roots != {SOURCE_TOP}:
                raise ValueError(f"unexpected source archive roots: {sorted(roots)}")
            work.mkdir(parents=True, exist_ok=False)
            tar.extractall(work, members=members, filter="data")

        source = work / SOURCE_TOP
        binary_dest = source / "kernel-open/nvidia/nv-kernel.o_binary"
        if not source.is_dir() or not (source / "kernel-open/Makefile").is_file():
            raise RuntimeError("extracted R580 tree is missing the official kernel-open Makefile")
        archived_core = None
        if binary_dest.exists():
            if binary_dest.is_symlink() or not binary_dest.is_file():
                raise RuntimeError("archive core-object destination is not a regular file")
            archived_core = {"sha256": sha256(binary_dest), "bytes": binary_dest.stat().st_size}
        shutil.copy2(rm_object, binary_dest)
        if sha256(binary_dest) != RM_OBJECT_SHA256:
            raise RuntimeError("copied Open R580 RM object failed its SHA-256 check")
        report.update(source=str(source), archived_core_replaced=archived_core,
                      copied_rm_object={"path": str(binary_dest), "sha256": sha256(binary_dest),
                                        "bytes": binary_dest.stat().st_size})

        headers = Path(f"/lib/modules/{args.kernel_release}/build").resolve(strict=True)
        report["kernel_headers"] = str(headers)
        report["kernel_symvers_present"] = (headers / "Module.symvers").is_file()
        command = ["make", "-C", str(source / "kernel-open"),
                   f"KERNEL_UNAME={args.kernel_release}", "NV_KERNEL_MODULES=nvidia",
                   f"-j{args.jobs}", "modules"]
        result = step("nvidia-module-build", command, ROOT, timeout=1200)
        module_path = source / "kernel-open/nvidia.ko"
        report["build_exit_code"] = result["exit_code"]
        if result["exit_code"] != 0:
            report.update(status="wrapper-build-failed", qualification="build-failed",
                          failure_log_tail=tail_text(Path(result["log"]), 160))
            raise BuildFailure("kernel wrapper build failed; exact log preserved")
        if not module_path.is_file() or module_path.stat().st_size == 0:
            raise RuntimeError("make returned success but kernel-open/nvidia.ko is missing or empty")

        elf_log = log_dir / f"open580-wrapper-module-elf-{stamp}.log"
        elf_result = run_logged("module-elf-header", ["readelf", "-h", str(module_path)],
                                ROOT, elf_log)
        report["steps"].append(elf_result)
        if elf_result["exit_code"] != 0:
            raise RuntimeError("readelf rejected produced nvidia.ko")
        elf_text = elf_log.read_text(errors="replace")
        if "Type:" not in elf_text or "REL (Relocatable file)" not in elf_text:
            raise RuntimeError("produced nvidia.ko is not an ELF relocatable object")

        objects = sorted((source / "kernel-open/nvidia").glob("*.o"))
        if not objects:
            raise RuntimeError("wrapper build produced no module constituent objects")
        nm_objects_log = log_dir / f"open580-wrapper-objects-nm-{stamp}.log"
        nm_obj = run_logged("wrapper-object-symbols",
                            ["nm", "-A", "-g", "--defined-only", "--format=posix",
                             *map(str, objects)], ROOT, nm_objects_log)
        report["steps"].append(nm_obj)
        if nm_obj["exit_code"] != 0:
            raise RuntimeError("nm failed on compiled wrapper objects")
        definitions = parse_nm_defined(nm_objects_log.read_text(errors="replace"))

        nm_mod_log = log_dir / f"open580-wrapper-module-nm-{stamp}.log"
        nm_module = run_logged("module-symbols",
                               ["nm", "-g", str(module_path)], ROOT,
                               nm_mod_log)
        report["steps"].append(nm_module)
        if nm_module["exit_code"] != 0:
            raise RuntimeError("nm failed on produced nvidia.ko")
        module_nm = nm_mod_log.read_text(errors="replace")
        module_undefined = parse_nm_undefined(module_nm)

        readelf_log = log_dir / f"open580-wrapper-module-readelf-symbols-{stamp}.log"
        readelf_result = run_logged("module-readelf-symbols",
                                    ["readelf", "-W", "-s", str(module_path)], ROOT,
                                    readelf_log)
        report["steps"].append(readelf_result)
        if readelf_result["exit_code"] != 0:
            raise RuntimeError("readelf failed on produced nvidia.ko symbol table")
        readelf_undefined = parse_readelf_undefined(readelf_log.read_text(errors="replace"))
        if module_undefined != readelf_undefined:
            report["nm_readelf_undefined_set_mismatch"] = {
                "nm_only": sorted(module_undefined - readelf_undefined),
                "readelf_only": sorted(readelf_undefined - module_undefined),
            }
        # Use ELF symbol table as the authoritative final-module UND set.
        module_undefined = readelf_undefined
        module_defined = parse_readelf_defined_global(readelf_log.read_text(errors="replace"))

        by_name: dict[str, list[dict]] = {}
        for item in definitions:
            by_name.setdefault(item["name"], []).append(item)
        outcomes = []
        for name in pair_names:
            strong = [item for item in by_name.get(name, []) if item["strong_global"]]
            weak = [item for item in by_name.get(name, []) if not item["strong_global"]]
            final_providers = [item for item in strong if Path(item["object"]).name != "nv-interface.o"]
            if name in module_defined and final_providers:
                state = "provided-by-compiled-wrapper-or-open-rm-object"
            elif name in module_undefined:
                state = "retained-undefined-import-in-final-module"
            elif final_providers:
                state = "object-definition-not-retained-in-final-module"
            else:
                state = "no-strong-provider-found-in-compiled-wrapper-objects"
            outcomes.append({
                "name": name,
                "prior_category": pair_rows[name].get("category"),
                "state": state,
                "strong_providers": final_providers,
                "weak_or_special_definitions": weak,
                "present_defined_in_final_module": name in module_defined,
                "present_undefined_in_final_module": name in module_undefined,
            })

        counts = {}
        for row in outcomes:
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        module_imports = sorted(module_undefined)
        module_record = {"path": str(module_path), "bytes": module_path.stat().st_size,
                         "sha256": sha256(module_path), "elf_type": "ET_REL",
                         "undefined_symbol_count": len(module_imports),
                         "undefined_symbol_names": module_imports}
        report.update(
            status="compiled-wrapper-symbols-classified",
            qualification="compiled-kernel-module-linkage-only",
            module_artifact=module_record,
            compiled_wrapper_objects=[{"path": str(path), "sha256": sha256(path),
                                       "bytes": path.stat().st_size} for path in objects],
            wrapper_object_count=len(objects),
            pair_symbol_outcomes=outcomes,
            provider_counts=counts,
            unresolved_pair_names_in_final_module=sorted(
                row["name"] for row in outcomes if row["present_undefined_in_final_module"]),
            kernel_imports_from_final_module_are_not_hardware_validation=True,
            output_module_license_metadata="left unchanged from archive sources",
            next_qualification="module load and hardware initialization require a separate authorized canary step",
        )
        code = 0
    except BuildFailure as error:
        report["error"] = str(error)
        code = 2
    except (OSError, ValueError, RuntimeError, tarfile.TarError, json.JSONDecodeError) as error:
        report.update(status="failed", qualification=report.get("qualification", "setup-failed"),
                      error=f"{type(error).__name__}: {error}")
        code = 2

    report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
    report["tool_path"] = str(Path(__file__).resolve())
    report["tool_sha256"] = sha256(Path(__file__).resolve())
    report["report_path"] = str(report_path)
    with report_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"report": str(report_path), "status": report.get("status"),
                      "qualification": report.get("qualification"),
                      "error": report.get("error"),
                      "provider_counts": report.get("provider_counts")}, indent=2))
    return code


class BuildFailure(RuntimeError):
    pass


def tail_text(path: Path, lines: int) -> list[str]:
    try:
        return path.read_text(errors="replace").splitlines()[-lines:]
    except OSError:
        return []


if __name__ == "__main__":
    raise SystemExit(main())
