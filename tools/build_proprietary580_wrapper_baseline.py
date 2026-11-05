#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the extracted proprietary R580 nvidia wrapper in a fresh copy.

This experiment uses the package's original nv-kernel.o_binary and the
unmodified MODULE_LICENSE("NVIDIA") declaration. It compiles only nvidia.ko;
it never installs, loads, signs, or patches a kernel module.
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
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
ACQUISITION = ROOT / "evidence/r580-proprietary-reference-acquisition-20261018.json"
PACKAGE_DEB = ROOT / ".cache/vendor-proprietary/nvidia-kernel-source-580_580.178.04-0ubuntu0.26.04.1_amd64.deb"
PACKAGE_DEB_SHA256 = "31666b2940d0375d9ca984bd78a195c2da8d353998f92f745e0831e5c7bd2a5c"
SOURCE_ROOT = ROOT / ".cache/vendor-proprietary/r580.178.04-ubuntu/usr/src/nvidia-580.178.04"
CORE_OBJECT = SOURCE_ROOT / "nvidia/nv-kernel.o_binary"
CORE_OBJECT_SHA256 = "5269a23ffba19a17fe16f076463e7ad4151254659441d1711bee6c6221ff6f4b"
PAIR_EVIDENCE = ROOT / "evidence/r580-external-dependencies-20261018.json"
OPEN_BASELINE = ROOT / "evidence/open580-wrapper-baseline-20261018.json"
DEFAULT_WORK = ROOT / "build/experiments/proprietary580-wrapper-baseline-v1"
DEFAULT_REPORT = ROOT / "evidence/proprietary580-wrapper-baseline-20261018.json"


class BuildFailure(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_fingerprint(root: Path) -> dict:
    digest = hashlib.sha256()
    files = symlinks = total_bytes = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            row = f"L\0{rel}\0{target}\n".encode()
            symlinks += 1
        elif path.is_file():
            size = path.stat().st_size
            file_hash = sha256(path)
            row = f"F\0{rel}\0{size}\0{file_hash}\n".encode()
            files += 1
            total_bytes += size
        elif path.is_dir():
            row = f"D\0{rel}\n".encode()
        else:
            row = f"O\0{rel}\n".encode()
        digest.update(row)
    return {"sha256": digest.hexdigest(), "regular_file_count": files,
            "symlink_count": symlinks, "regular_file_bytes": total_bytes}


def run_logged(name: str, argv: list[str], cwd: Path, log: Path,
               timeout: int = 1200) -> dict:
    start = time.monotonic()
    with log.open("x", encoding="utf-8") as stream:
        stream.write("$ " + " ".join(argv) + "\n")
        stream.write(f"cwd: {cwd}\n\n")
        stream.flush()
        try:
            result = subprocess.run(argv, cwd=cwd, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False,
                                    timeout=timeout, text=True)
            code = result.returncode
        except subprocess.TimeoutExpired:
            stream.write(f"\nTIMEOUT after {timeout}s\n")
            code = 124
    return {"name": name, "argv": argv, "cwd": str(cwd), "exit_code": code,
            "duration_seconds": round(time.monotonic() - start, 3),
            "log": str(log.resolve()), "log_sha256": sha256(log),
            "log_bytes": log.stat().st_size}


def parse_nm_defined(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        match = re.match(r"^(.*):\s+(\S+)\s+([A-Za-z?])\s+([0-9A-Fa-f]+)\s+(\S+)\s*$", line)
        if not match:
            continue
        obj, name, typ, value, size = match.groups()
        if typ.upper() in {"U", "W", "V"}:
            continue
        out.append({"object": obj, "name": name, "type": typ,
                    "value": value, "size": size,
                    "strong_global": typ in "TDBRGS"})
    return out


def readelf_symbols(path: Path, log_dir: Path, stamp: str, name: str,
                    report_steps: list) -> tuple[set[str], set[str]]:
    log = log_dir / f"proprietary580-wrapper-{name}-{stamp}.log"
    step = run_logged(name, ["readelf", "-W", "-s", str(path)], ROOT, log)
    report_steps.append(step)
    if step["exit_code"]:
        return set(), set()
    defined, undefined = set(), set()
    for line in log.read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        symbol = fields[7].split("@", 1)[0]
        if not symbol:
            continue
        if fields[6] == "UND":
            undefined.add(symbol)
        elif fields[4] == "GLOBAL" and fields[6] != "ABS":
            defined.add(symbol)
    return defined, undefined


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--package-deb", type=Path, default=PACKAGE_DEB)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK,
                        help="new scratch directory; existing paths are refused")
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT,
                        help="new report path under evidence/")
    parser.add_argument("--kernel-release", default="7.0.0-38-generic")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log_dir = ROOT / "evidence/logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.report_path.resolve()
    source_root = args.package_root.resolve()
    work = args.work_dir.resolve()
    copy_root = work / "nvidia-580.178.04"
    report = {
        "schema": "nvidia-proprietary580-wrapper-baseline-v1",
        "source_package_version": "580.178.04-0ubuntu0.26.04.1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "unmodified-proprietary-R580-nvidia-wrapper-only",
        "qualification": "not-started",
        "loaded_or_installed": False,
        "module_license_source_modified": False,
        "hardware_validated": False,
        "steps": [],
    }
    code = 2
    source_before = None

    try:
        if source_root != SOURCE_ROOT.resolve():
            raise ValueError("--package-root must be the pinned extracted package tree")
        if not report_path.is_relative_to((ROOT / "evidence").resolve()):
            raise ValueError("--report-path must be inside the repository evidence/ directory")
        if not work.is_relative_to((ROOT / "build/experiments").resolve()):
            raise ValueError("--work-dir must be inside build/experiments/")
        if work.exists():
            raise FileExistsError(f"refusing to overwrite scratch tree: {work}")
        if report_path.exists():
            raise FileExistsError(f"refusing to overwrite report: {report_path}")

        deb = args.package_deb.resolve(strict=True)
        if sha256(deb) != PACKAGE_DEB_SHA256:
            raise ValueError("source package .deb does not match its pinned SHA-256")
        if not ACQUISITION.is_file():
            raise FileNotFoundError(f"missing package acquisition evidence: {ACQUISITION}")
        acquisition = json.loads(ACQUISITION.read_text())
        if acquisition.get("package_sha256") != PACKAGE_DEB_SHA256:
            raise ValueError("acquisition evidence package hash does not match pinned .deb")
        if not source_root.is_dir():
            raise FileNotFoundError(f"missing extracted proprietary package root: {source_root}")
        core = source_root / "nvidia/nv-kernel.o_binary"
        if not core.is_file() or sha256(core) != CORE_OBJECT_SHA256:
            raise ValueError("proprietary nvidia/nv-kernel.o_binary does not match pinned SHA-256")
        license_source = source_root / "nvidia/nv.c"
        license_text = license_source.read_text(errors="replace")
        license_matches = re.findall(r'MODULE_LICENSE\s*\(\s*"([^"]+)"\s*\)', license_text)
        if license_matches != ["NVIDIA"]:
            raise ValueError(f"expected exactly MODULE_LICENSE(\"NVIDIA\"), got {license_matches}")

        source_before = tree_fingerprint(source_root)
        report.update(
            package_deb=str(deb), package_deb_sha256=PACKAGE_DEB_SHA256,
            package_deb_bytes=deb.stat().st_size,
            acquisition_evidence=str(ACQUISITION),
            acquisition_evidence_sha256=sha256(ACQUISITION),
            package_root=str(source_root), package_tree_before=source_before,
            core_object={"path": str(core), "sha256": CORE_OBJECT_SHA256,
                         "bytes": core.stat().st_size},
            module_license_source={"path": str(license_source),
                                   "sha256": sha256(license_source),
                                   "declaration": 'MODULE_LICENSE("NVIDIA")'},
            kernel_release=args.kernel_release, jobs=args.jobs,
            work_dir=str(work), scratch_source_root=str(copy_root),
            open_baseline_evidence=str(OPEN_BASELINE),
            open_baseline_evidence_sha256=sha256(OPEN_BASELINE),
        )

        work.mkdir(parents=True, exist_ok=False)
        shutil.copytree(source_root, copy_root, symlinks=True, copy_function=shutil.copy2)
        copy_before = tree_fingerprint(copy_root)
        report["scratch_tree_before_build"] = copy_before
        if copy_before["sha256"] != source_before["sha256"]:
            raise RuntimeError("scratch copy does not exactly match extracted source tree")

        nvidia_dir = copy_root / "nvidia"
        stale_candidates = [copy_root / "nvidia.ko", copy_root / "nvidia.o"]
        stale_candidates += list(nvidia_dir.glob("*.o"))
        stale = [str(path) for path in stale_candidates if path.exists()]
        report["preexisting_build_outputs"] = stale
        if stale:
            raise RuntimeError("copied package tree has preexisting nvidia build outputs; refusing stale artifacts")

        headers = Path(f"/lib/modules/{args.kernel_release}/build").resolve(strict=True)
        symvers = headers / "Module.symvers"
        report["kernel_headers"] = str(headers)
        report["kernel_symvers"] = {"path": str(symvers), "present": symvers.is_file(),
                                    "sha256": sha256(symvers) if symvers.is_file() else None}

        command = ["make", "-C", str(copy_root), f"KERNEL_UNAME={args.kernel_release}",
                   "NV_KERNEL_MODULES=nvidia", f"-j{args.jobs}", "modules"]
        build_log = log_dir / f"proprietary580-wrapper-build-{stamp}.log"
        build_step = run_logged("nvidia-wrapper-build", command, ROOT, build_log)
        report["steps"].append(build_step)
        report["build_exit_code"] = build_step["exit_code"]
        report["build_log_tail"] = build_log.read_text(errors="replace").splitlines()[-120:]

        gpl_error_lines = [line for line in build_log.read_text(errors="replace").splitlines()
                           if "GPL-incompatible" in line or "GPL-only symbol" in line]
        report["modpost_gpl_error_lines"] = gpl_error_lines[:250]
        report["modpost_gpl_error_line_count"] = len(gpl_error_lines)
        report["modpost_gpl_symbol_names"] = sorted({
            match.group(1) for line in gpl_error_lines
            for match in re.finditer(r"GPL-only symbol ['\"]([^'\"]+)['\"]", line)
        })

        module = copy_root / "nvidia.ko"
        composite = copy_root / "nvidia.o"
        report["module_artifact_present"] = module.is_file()
        report["composite_object_present"] = composite.is_file()
        if module.is_file():
            report["module_artifact"] = {"path": str(module), "bytes": module.stat().st_size,
                                         "sha256": sha256(module)}
            elf_log = log_dir / f"proprietary580-wrapper-module-elf-{stamp}.log"
            elf_step = run_logged("module-elf-header", ["readelf", "-h", str(module)], ROOT, elf_log)
            report["steps"].append(elf_step)
            if elf_step["exit_code"] == 0:
                elf_text = elf_log.read_text(errors="replace")
                report["module_artifact"]["elf_type"] = "ET_REL" if "REL (Relocatable file)" in elf_text else "other"
            info = subprocess.run(["modinfo", "-F", "license", str(module)], capture_output=True,
                                  text=True, check=False, timeout=60)
            vermagic = subprocess.run(["modinfo", "-F", "vermagic", str(module)], capture_output=True,
                                      text=True, check=False, timeout=60)
            report["module_modinfo"] = {"license": info.stdout.strip(), "license_exit_code": info.returncode,
                                        "vermagic": vermagic.stdout.strip(),
                                        "vermagic_exit_code": vermagic.returncode}

        pair_rows = json.loads(PAIR_EVIDENCE.read_text())["symbols"]
        pair_names = [row["name"] for row in pair_rows]
        report["pair_undefined_count"] = len(pair_names)
        if len(pair_names) != 411 or len(set(pair_names)) != 411:
            raise ValueError("R580 RM pair evidence does not contain exactly 411 unique names")
        report["pair_evidence"] = str(PAIR_EVIDENCE)
        report["pair_evidence_sha256"] = sha256(PAIR_EVIDENCE)

        objects = sorted(path for path in nvidia_dir.glob("*.o") if path.name != "nv-interface.o")
        report["compiled_wrapper_object_count"] = len(objects)
        report["compiled_wrapper_objects"] = [
            {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in objects if path.is_file()
        ]
        if objects:
            nm_log = log_dir / f"proprietary580-wrapper-objects-nm-{stamp}.log"
            nm_step = run_logged("wrapper-object-symbols",
                                 ["nm", "-A", "-g", "--defined-only", "--format=posix",
                                  *map(str, objects)], ROOT, nm_log)
            report["steps"].append(nm_step)
            definitions = parse_nm_defined(nm_log.read_text(errors="replace")) if nm_step["exit_code"] == 0 else []
        else:
            definitions = []
        by_name: dict[str, list[dict]] = {}
        for definition in definitions:
            by_name.setdefault(definition["name"], []).append(definition)
        pair_providers = []
        for row in pair_rows:
            providers = [item for item in by_name.get(row["name"], []) if item["strong_global"]]
            pair_providers.append({"name": row["name"], "category": row.get("category"),
                                   "provider_count": len(providers), "strong_providers": providers})
        report["pair_wrapper_provider_counts"] = {
            "unique_pair_names": len(pair_names),
            "with_strong_wrapper_object_provider": sum(bool(r["strong_providers"]) for r in pair_providers),
            "without_strong_wrapper_object_provider": sum(not r["strong_providers"] for r in pair_providers),
            "multiple_strong_wrapper_object_providers": sum(r["provider_count"] > 1 for r in pair_providers),
        }
        report["pair_wrapper_providers"] = pair_providers

        effective_elf = module if module.is_file() else (composite if composite.is_file() else None)
        if effective_elf:
            defined, undefined = readelf_symbols(effective_elf, log_dir, stamp,
                                                  "module-symbols" if module.is_file() else "composite-symbols",
                                                  report["steps"])
            pair_undefined = sorted(set(pair_names) & undefined)
            report["effective_link_artifact"] = str(effective_elf)
            report["effective_undefined_symbol_count"] = len(undefined)
            report["pair_names_still_undefined_in_effective_link"] = pair_undefined
            report["pair_names_defined_in_effective_link_count"] = len(set(pair_names) & defined)
        else:
            report["effective_link_artifact"] = None
            report["effective_undefined_symbol_count"] = None
            report["pair_names_still_undefined_in_effective_link"] = None
            report["pair_names_defined_in_effective_link_count"] = None

        if symvers.is_file() and effective_elf:
            _, effective_undefined = readelf_symbols(effective_elf, log_dir, stamp,
                                                      "module-symbols-for-export-classification",
                                                      report["steps"])
            export_rows = {}
            for line in symvers.read_text(errors="replace").splitlines():
                fields = line.split("\t")
                if len(fields) >= 4:
                    export_rows[fields[1]] = {"name": fields[1], "module": fields[2],
                                              "export_type": fields[3], "symvers_line": line}
            gpl_imports = [export_rows[name] for name in sorted(effective_undefined)
                           if name in export_rows and export_rows[name]["export_type"] == "EXPORT_SYMBOL_GPL"]
            report["effective_link_gpl_only_imports"] = gpl_imports
            report["effective_link_gpl_only_import_count"] = len(gpl_imports)
            report["symvers_unmatched_effective_import_count"] = sum(
                name not in export_rows for name in effective_undefined)
        else:
            report["effective_link_gpl_only_imports"] = []
            report["effective_link_gpl_only_import_count"] = None
            report["symvers_unmatched_effective_import_count"] = None

        after = tree_fingerprint(source_root)
        report["package_tree_after"] = after
        report["package_source_tree_unchanged"] = after["sha256"] == source_before["sha256"]
        if build_step["exit_code"] == 0 and module.is_file():
            report["status"] = "compiled-proprietary-wrapper"
            report["qualification"] = "compiled-module-linkage-only"
            code = 0
        else:
            report["status"] = "wrapper-build-failed" if build_step["exit_code"] else "module-artifact-missing"
            report["qualification"] = "modpost-or-build-failed"
            code = 2
        if not report["package_source_tree_unchanged"]:
            report["status"] = "input-source-tree-changed"
            report["qualification"] = "invalidated-by-input-mutation"
            code = 2
        report["scratch_tree_after_build"] = tree_fingerprint(copy_root)
        report["scratch_outputs_are_canary_only"] = True
    except (OSError, ValueError, RuntimeError, tarfile.TarError, json.JSONDecodeError,
            subprocess.SubprocessError) as error:
        report.update(status="failed", qualification="setup-or-analysis-failed",
                      error=f"{type(error).__name__}: {error}")
        if source_before is not None and source_root.is_dir():
            after = tree_fingerprint(source_root)
            report["package_tree_after"] = after
            report["package_source_tree_unchanged"] = after["sha256"] == source_before["sha256"]
        code = 2

    report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
    report["tool_path"] = str(Path(__file__).resolve())
    report["tool_sha256"] = sha256(Path(__file__).resolve())
    report["report_path"] = str(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"report": str(report_path), "status": report.get("status"),
                      "qualification": report.get("qualification"),
                      "build_exit_code": report.get("build_exit_code"),
                      "module_artifact_present": report.get("module_artifact_present"),
                      "modpost_gpl_symbol_names": report.get("modpost_gpl_symbol_names"),
                      "pair_wrapper_provider_counts": report.get("pair_wrapper_provider_counts")}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
