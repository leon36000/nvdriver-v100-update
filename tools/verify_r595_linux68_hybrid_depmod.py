#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the exact R595/Linux 6.8 hybrid set privately and verify kmod planning.

This tool copies hash-pinned module artifacts, the exact candidate-only UVM
option, and captured target-kernel support modules into a private tree. It runs
depmod there and asks modprobe to print its proposed insertion plans. It never
loads, installs, signs, or binds a module.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
KERNEL_RELEASE = "6.8.0-147-generic"
TARGET = "pc3@pc3"
GUEST_HOSTNAME = "pc3-v100"
AUDIT_SCHEMA = "hybrid-module-bundle-static-audit-v1"
CAPTURE_SCHEMA = "pc3-v100-kernel-dependency-capture-v1"
ROLES = {
    "open": {"name": "hybrid580_open", "filename": "hybrid580_open.ko",
             "depends": ["ecc"], "version": "595.99.02"},
    "legacy": {"name": "hybrid580_legacy", "filename": "hybrid580_legacy.ko",
               "depends": [], "version": "580.196.07"},
    "frontend": {
        "name": "nvidia", "filename": "nvidia.ko",
        "depends": ["hybrid580_legacy", "hybrid580_open"], "version": "",
    },
    "uvm": {"name": "nvidia_uvm", "filename": "nvidia-uvm.ko",
            "depends": ["nvidia"], "version": "595.99.02"},
}
SUPPORT = {
    "ecc": {"guest_path": "kernel/crypto/ecc.ko.zst", "depends": []},
    "ecdh_generic": {
        "guest_path": "kernel/crypto/ecdh_generic.ko.zst", "depends": ["ecc"],
    },
    "ecdsa_generic": {
        "guest_path": "kernel/crypto/ecdsa_generic.ko.zst", "depends": ["ecc"],
    },
}
CAPTURE_METADATA = {"modules.order", "modules.builtin", "modules.builtin.modinfo"}
EXPECTED_GRAPH = {
    "ecc": set(),
    "ecdh_generic": {"ecc"},
    "ecdsa_generic": {"ecc"},
    "hybrid580_open": {"ecc"},
    "hybrid580_legacy": set(),
    "nvidia": {"ecc", "hybrid580_open", "hybrid580_legacy"},
    "nvidia_uvm": {"ecc", "hybrid580_open", "hybrid580_legacy", "nvidia"},
}
FRONTEND_PLAN = [
    "ecc", "ecdh_generic", "ecdsa_generic", "hybrid580_open", "hybrid580_legacy", "nvidia",
]
UVM_PLAN = FRONTEND_PLAN + ["nvidia_uvm"]
SOFTDEP = "softdep hybrid580_open pre: ecdh_generic ecdsa_generic"
CONFIG_RELATIVE_PATH = PurePosixPath("packaging/modprobe.d/hybrid595-standard-uvm.conf")
CONFIG_NAME = CONFIG_RELATIVE_PATH.name
ISOLATED_UVM_OPTION = "uvm_hybrid_isolated_gpu_execution=1"
EXPECTED_CONFIG_LINE = "options nvidia_uvm " + ISOLATED_UVM_OPTION
MODULE_SUFFIXES = (".ko.zst", ".ko.xz", ".ko.gz", ".ko")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    return path.resolve(strict=True)


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"invalid relative path for {label}")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in ("", ".", "..") for part in result.parts):
        raise ValueError(f"unsafe relative path for {label}")
    return result


def _inside_project(root: Path, value: Any, label: str) -> Path:
    relative = _safe_relative(value, label)
    source = root / Path(relative.as_posix())
    resolved = _regular_file(source, label)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError:
        raise ValueError(f"{label} escapes the project root") from None
    return resolved


def _safe_evidence_path(path: Path, project_root: Path) -> Path:
    root = project_root.resolve(strict=True)
    raw = path if path.is_absolute() else root / path
    candidate = Path(os.path.abspath(raw))
    allowed = root / "evidence"
    if allowed.is_symlink():
        raise ValueError("evidence directory must not be a symlink")
    try:
        relative = candidate.relative_to(allowed)
    except ValueError:
        raise ValueError(f"report must stay inside {allowed}") from None
    current = allowed
    for component in relative.parts:
        current = current / component
        if current.exists() and current.is_symlink():
            raise ValueError(f"report path contains a symlink: {current}")
    try:
        candidate.resolve(strict=False).relative_to(allowed.resolve(strict=False))
    except ValueError:
        raise ValueError("report path resolves outside evidence") from None
    return candidate


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {label}: {error}") from None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _pinned_report(path: Path, expected_hash: str, label: str) -> tuple[dict[str, Any], str]:
    path = _regular_file(path, label)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash or ""):
        raise ValueError(f"expected {label} SHA-256 must be 64 hexadecimal characters")
    actual = _sha256_file(path)
    if actual != expected_hash.lower():
        raise ValueError(f"{label} SHA-256 mismatch: got {actual}, expected {expected_hash.lower()}")
    return _load_json(path, label), actual


def _load_bundle(path: Path, expected_hash: str, kernel_release: str,
                 project_root: Path) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]]]:
    report, report_hash = _pinned_report(path, expected_hash, "audit report")
    if (report.get("schema") != AUDIT_SCHEMA or report.get("status") != "passed"
            or report.get("qualification") != "static-module-bundle-closure"
            or report.get("kernel_release") != kernel_release
            or report.get("runtime_or_hardware_validated") is not False
            or report.get("module_loaded") is not False
            or report.get("module_installed") is not False
            or report.get("issues") != []):
        raise ValueError("audit report is not a clean, unloaded exact-target static bundle")
    records = report.get("modules")
    if not isinstance(records, dict) or set(records) != set(ROLES):
        raise ValueError("audit report must identify exactly the four hybrid module roles")
    verified = {}
    for role, expected in ROLES.items():
        record = records[role]
        if not isinstance(record, dict) or record.get("name") != expected["name"]:
            raise ValueError(f"unexpected module identity for {role}")
        if sorted(record.get("depends", [])) != sorted(expected["depends"]):
            raise ValueError(f"static module dependencies differ for {role}")
        if record.get("vermagic", "").split(maxsplit=1)[:1] != [kernel_release]:
            raise ValueError(f"module vermagic differs from target for {role}")
        if record.get("version", "") != expected["version"]:
            raise ValueError(f"module version differs for {role}")
        source = Path(record.get("path", ""))
        source = _regular_file(source, f"{role} module")
        digest = record.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError(f"audit report lacks a valid module digest for {role}")
        actual = _sha256_file(source)
        if actual != digest.lower():
            raise ValueError(f"module SHA-256 mismatch for {role}")
        if source.name != expected["filename"]:
            raise ValueError(f"module artifact filename differs for {role}")
        verified[role] = {**expected, "source": source, "sha256": actual, "bytes": source.stat().st_size}
    return report, report_hash, verified


def _load_support_capture(path: Path, expected_hash: str, kernel_release: str,
                          project_root: Path) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]]]:
    capture, capture_hash = _pinned_report(path, expected_hash, "support capture")
    if (capture.get("schema") != CAPTURE_SCHEMA or capture.get("status") != "captured"
            or capture.get("qualification") != "read-only-exact-kernel-support-module-capture"
            or capture.get("target") != TARGET or capture.get("guest_hostname") != GUEST_HOSTNAME
            or capture.get("kernel_release") != kernel_release
            or capture.get("guest_mutation_performed") is not False
            or capture.get("module_installed") is not False or capture.get("module_loaded") is not False
            or capture.get("runtime_or_hardware_validated") is not False):
        raise ValueError("support capture is not a read-only exact PC3 Linux 6.8 capture")
    rows = capture.get("files")
    if not isinstance(rows, list):
        raise ValueError("support capture has no file list")
    by_name = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ValueError("support capture contains an invalid file record")
        name = row["name"]
        if name in by_name:
            raise ValueError(f"support capture contains duplicate {name} records")
        by_name[name] = row
    expected_names = set(SUPPORT) | CAPTURE_METADATA
    if not expected_names.issubset(by_name):
        raise ValueError("support capture omits required crypto modules or metadata")
    verified = {}
    for name, expected in SUPPORT.items():
        row = by_name[name]
        if (row.get("kind") != "module" or row.get("guest_path") != expected["guest_path"]
                or row.get("depends") != expected["depends"]):
            raise ValueError(f"captured support module contract differs for {name}")
        source = _inside_project(project_root, row.get("path"), f"captured {name} module")
        expected_bytes, expected_digest = row.get("bytes"), row.get("sha256")
        if type(expected_bytes) is not int or expected_bytes < 1 or source.stat().st_size != expected_bytes:
            raise ValueError(f"captured support module size differs for {name}")
        if not isinstance(expected_digest, str) or _sha256_file(source) != expected_digest:
            raise ValueError(f"captured support module hash differs for {name}")
        verified[name] = {**expected, "source": source, "sha256": expected_digest, "bytes": expected_bytes}
    metadata = {}
    for name in CAPTURE_METADATA:
        row = by_name[name]
        if row.get("kind") != "metadata" or row.get("guest_path") != name:
            raise ValueError(f"captured metadata contract differs for {name}")
        source = _inside_project(project_root, row.get("path"), f"captured {name}")
        if type(row.get("bytes")) is not int or source.stat().st_size != row["bytes"]:
            raise ValueError(f"captured metadata size differs for {name}")
        if not isinstance(row.get("sha256"), str) or _sha256_file(source) != row["sha256"]:
            raise ValueError(f"captured metadata hash differs for {name}")
        metadata[name] = {"source": source, "sha256": row["sha256"], "bytes": row["bytes"]}
    return capture, capture_hash, {"modules": verified, "metadata": metadata}


def _filter_order(order_path: Path, support: dict[str, dict[str, Any]]) -> list[str]:
    expected = {}
    for name, record in support.items():
        guest_path = record["guest_path"]
        expected[guest_path] = name
        # The exact PC3 modules.order records the logical .ko path even though
        # the captured installed files use .ko.zst.
        for compression in (".zst", ".xz", ".gz"):
            if guest_path.endswith(compression):
                expected[guest_path[:-len(compression)]] = name
                break
    selected = []
    for number, raw in enumerate(order_path.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
        value = raw.strip()
        if not value:
            continue
        relative = _safe_relative(value, f"modules.order line {number}").as_posix()
        name = expected.get(relative)
        if name:
            if name in selected:
                raise ValueError("captured modules.order repeats a required support module")
            selected.append(name)
    if set(selected) != set(SUPPORT):
        raise ValueError("captured modules.order does not list all three required crypto modules")
    return [support[name]["guest_path"] for name in selected]


def _module_name(path: str) -> str:
    name = PurePosixPath(path).name
    for suffix in MODULE_SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)].replace("-", "_")
    raise ValueError(f"unexpected module filename: {name}")


def _parse_modules_dep(path: Path) -> dict[str, set[str]]:
    result = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
        target, separator, dependencies = line.partition(":")
        if not separator:
            raise ValueError(f"malformed depmod output line {line_number}")
        target = _safe_relative(target.strip(), "modules.dep target").as_posix()
        name = _module_name(target)
        if name in result:
            raise ValueError(f"duplicate modules.dep record for {name}")
        result[name] = {_module_name(_safe_relative(item, "modules.dep dependency").as_posix())
                        for item in dependencies.split()}
    return result


def _parse_plan(stdout: str, stage_root: Path, requested: str,
                expected_first: list[str]) -> tuple[list[str], list[str], dict[str, int]]:
    raw_names = []
    stage = stage_root.resolve(strict=True)
    for number, line in enumerate(stdout.splitlines(), 1):
        if not line.strip():
            continue
        fields = shlex.split(line)
        if len(fields) < 2 or fields[0] != "insmod":
            raise ValueError(f"unexpected modprobe dependency plan line {number}")
        raw_module_path = Path(fields[1])
        if raw_module_path.is_symlink():
            raise ValueError("modprobe plan points through a symlink")
        module_path = raw_module_path.resolve(strict=False)
        try:
            relative = module_path.relative_to(stage).as_posix()
        except ValueError:
            raise ValueError("modprobe resolved a module outside the private stage") from None
        if not module_path.is_file() or module_path.is_symlink():
            raise ValueError("modprobe plan points to a missing or non-regular staged module")
        name = _module_name(relative)
        options = fields[2:]
        expected_options = [ISOLATED_UVM_OPTION] if name == "nvidia_uvm" else []
        if options != expected_options:
            raise ValueError(f"modprobe attached unexpected options to {name}")
        raw_names.append(name)
    counts = Counter(raw_names)
    if not raw_names or set(counts) != set(expected_first):
        raise ValueError(f"modprobe dependency module set differs for {requested}")
    repeated = {name: count for name, count in counts.items() if count > 1}
    if set(repeated) - {"ecc"}:
        raise ValueError("modprobe repeats a module other than the shared ecc dependency")
    first = list(dict.fromkeys(raw_names))
    if first != expected_first or raw_names[-1] != requested:
        raise ValueError(f"modprobe ordering differs for {requested}")
    return raw_names, first, repeated


def _run(runner: Callable[..., Any], argv: list[str]) -> Any:
    try:
        return runner(argv, check=False, capture_output=True, text=True,
                      timeout=120, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot run {argv[0]}: {error}") from None


def _checked(runner: Callable[..., Any], argv: list[str], label: str) -> Any:
    result = _run(runner, argv)
    if result.returncode:
        raise RuntimeError(f"{label} failed ({result.returncode}): {result.stderr.strip()[:1000]}")
    return result


def _version(runner: Callable[..., Any], command: str) -> str:
    result = _checked(runner, [command, "--version"], f"{command} version query")
    if result.stderr.strip():
        raise ValueError(f"{command} version query emitted stderr")
    match = re.search(r"kmod version ([0-9]+(?:\.[0-9]+)+)", result.stdout)
    if not match:
        raise ValueError(f"cannot identify {command} version")
    return match.group(1)


def _copy_verified(source: Path, destination: Path, expected_hash: str,
                   expected_bytes: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"refusing to overwrite staged file: {destination}")
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)
    if destination.stat().st_size != expected_bytes or _sha256_file(destination) != expected_hash:
        raise ValueError(f"staged copy failed hash/size verification: {destination.name}")


def stage_r595_linux68_hybrid_bundle(*, audit_report: Path, expected_audit_sha256: str,
                                     support_capture: Path, expected_support_capture_sha256: str,
                                     kernel_release: str, stage_parent: Path, report_path: Path,
                                     project_root: Path = ROOT,
                                     command_runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Create a private external stage and verify exact R595 Linux 6.8 kmod plans."""
    if kernel_release != KERNEL_RELEASE:
        raise ValueError(f"this verifier is pinned to {KERNEL_RELEASE}")
    root = project_root.resolve(strict=True)
    report_path = _safe_evidence_path(report_path, root)
    if report_path.exists() or report_path.is_symlink():
        raise ValueError(f"refusing to overwrite report: {report_path}")
    stage_parent = Path(stage_parent)
    if not stage_parent.is_absolute():
        stage_parent = root / stage_parent
    if stage_parent.is_symlink():
        raise ValueError("stage parent must not be a symlink")
    project_stage = root / "build/staging"
    if not stage_parent.exists() and stage_parent == project_stage:
        build_parent = root / "build"
        if build_parent.is_symlink() or not build_parent.is_dir():
            raise ValueError("project build directory must be an existing non-symlink directory")
        stage_parent.mkdir(mode=0o700)
    if not stage_parent.is_dir():
        raise ValueError("stage parent must be a directory")
    stage_parent = stage_parent.resolve(strict=True)
    try:
        stage_parent.relative_to(root)
    except ValueError:
        pass
    else:
        if stage_parent != project_stage.resolve(strict=True):
            raise ValueError("in-project staging is restricted to build/staging")

    bundle, audit_hash, modules = _load_bundle(
        audit_report, expected_audit_sha256, kernel_release, root)
    capture, capture_hash, support = _load_support_capture(
        support_capture, expected_support_capture_sha256, kernel_release, root)
    support_order = _filter_order(
        support["metadata"]["modules.order"]["source"], support["modules"])

    config_source = _inside_project(root, CONFIG_RELATIVE_PATH.as_posix(), "candidate UVM config")
    config_raw = config_source.read_bytes()
    active_config = [line.strip() for line in config_raw.decode("utf-8", errors="strict").splitlines()
                     if line.strip() and not line.lstrip().startswith("#")]
    if active_config != [EXPECTED_CONFIG_LINE]:
        raise ValueError("candidate UVM config must contain only the exact isolation option")
    config_hash = _sha256_file(config_source)
    implementation_path = Path(__file__).resolve(strict=True)
    implementation_hash = _sha256_file(implementation_path)
    stage_key = hashlib.sha256(
        f"{audit_hash}:{capture_hash}:{config_hash}:{implementation_hash}".encode("ascii")
    ).hexdigest()[:16]
    stage_root = stage_parent / f"r595-linux68-hybrid-{stage_key}"
    if stage_root.exists() or stage_root.is_symlink():
        raise FileExistsError(f"refusing to overwrite private stage: {stage_root}")

    stage_root.mkdir(mode=0o700)
    success = False
    try:
        module_root = stage_root / "lib/modules" / kernel_release
        candidate_root = module_root / "updates/extra"
        staged_support = {}
        for name, record in support["modules"].items():
            destination = module_root / record["guest_path"]
            _copy_verified(record["source"], destination, record["sha256"], record["bytes"])
            staged_support[name] = {
                "guest_path": record["guest_path"], "bytes": record["bytes"],
                "sha256": record["sha256"], "depends": record["depends"],
            }
        metadata_hashes = {}
        for name in ("modules.builtin", "modules.builtin.modinfo"):
            record = support["metadata"][name]
            destination = module_root / name
            _copy_verified(record["source"], destination, record["sha256"], record["bytes"])
            metadata_hashes[name] = record["sha256"]

        staged_modules = {}
        order_rows = list(support_order)
        for role in ("open", "legacy", "frontend", "uvm"):
            record = modules[role]
            destination = candidate_root / record["filename"]
            _copy_verified(record["source"], destination, record["sha256"], record["bytes"])
            relative = destination.relative_to(module_root).as_posix()
            order_rows.append(relative)
            staged_modules[role] = {
                "name": record["name"], "relative_path": relative,
                "bytes": record["bytes"], "sha256": record["sha256"],
                "depends": record["depends"],
            }
        order_path = module_root / "modules.order"
        if order_path.exists():
            raise ValueError("modules.order was unexpectedly staged before generation")
        order_path.write_text("".join(f"{item}\n" for item in order_rows), encoding="utf-8")
        os.chmod(order_path, 0o600)

        config_target = stage_root / "etc/modprobe.d" / CONFIG_NAME
        _copy_verified(config_source, config_target, config_hash, len(config_raw))

        depmod_command = ["depmod", "-b", str(stage_root), kernel_release]
        depmod = _checked(command_runner, depmod_command, "private depmod")
        if depmod.stderr.strip():
            raise ValueError("private depmod emitted warnings: " + depmod.stderr.strip()[:1000])
        modules_dep_path = module_root / "modules.dep"
        if not modules_dep_path.is_file() or modules_dep_path.is_symlink():
            raise ValueError("private depmod did not create modules.dep")
        graph = _parse_modules_dep(modules_dep_path)
        if graph != EXPECTED_GRAPH:
            raise ValueError("private depmod hard-dependency graph differs: " + repr(
                {name: sorted(edges) for name, edges in graph.items()}))
        softdep_path = module_root / "modules.softdep"
        if not softdep_path.is_file() or softdep_path.is_symlink():
            raise ValueError("private depmod did not create modules.softdep")
        softdep_lines = [line.strip() for line in softdep_path.read_text(encoding="utf-8", errors="strict").splitlines()
                         if line.strip() and not line.lstrip().startswith("#")]
        if softdep_lines != [SOFTDEP]:
            raise ValueError("private depmod soft dependency differs from the whitespace-separated contract")

        resolution = {}
        for target, expected_first in (("nvidia", FRONTEND_PLAN), ("nvidia_uvm", UVM_PLAN)):
            modprobe_config = str(config_target) if target == "nvidia_uvm" else "/dev/null"
            command = ["modprobe", "-C", modprobe_config, "-d", str(stage_root),
                       "--set-version", kernel_release, "--show-depends", target]
            result = _checked(command_runner, command, f"private modprobe plan for {target}")
            if result.stderr.strip():
                raise ValueError(f"private modprobe plan for {target} emitted stderr")
            raw, first, repeated = _parse_plan(result.stdout, stage_root, target, expected_first)
            resolution[target] = {
                "command": command, "stdout": result.stdout, "stderr": result.stderr,
                "raw_module_names": raw, "first_occurrences": first,
                "repeated_dependencies": repeated,
            }

        depmod_version = _version(command_runner, "depmod")
        modprobe_version = _version(command_runner, "modprobe")
        if depmod_version != modprobe_version:
            raise ValueError("depmod and modprobe kmod versions differ")
        stage_manifest = {
            "schema": "nvidia-r595-linux68-hybrid-candidate-stage-v1",
            "qualification": "private-static-candidate-tree",
            "kernel_release": kernel_release,
            "inputs": {
                "static_bundle_audit": {
                    "path": Path(audit_report).resolve().relative_to(root).as_posix(),
                    "sha256": audit_hash,
                },
                "kernel_support_capture": {
                    "path": Path(support_capture).resolve().relative_to(root).as_posix(),
                    "sha256": capture_hash,
                },
                "candidate_uvm_config": {
                    "path": config_source.relative_to(root).as_posix(),
                    "sha256": config_hash,
                },
            },
            "implementation": {
                "path": implementation_path.relative_to(ROOT).as_posix(),
                "sha256": implementation_hash,
            },
            "staged_modules": staged_modules,
            "staged_support_modules": staged_support,
            "captured_metadata_sha256": metadata_hashes,
            "staged_configuration": {
                "relative_path": config_target.relative_to(stage_root).as_posix(),
                "sha256": _sha256_file(config_target),
                "option": ISOLATED_UVM_OPTION,
            },
            "modules_order": order_rows,
            "hard_dependency_graph": {name: sorted(edges) for name, edges in sorted(graph.items())},
            "softdep_lines": softdep_lines,
            "modprobe_plans": {
                target: resolution[target]["first_occurrences"] for target in resolution
            },
            "activation_performed": False,
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "runtime_or_hardware_validated": False,
        }
        stage_manifest_path = stage_root / "candidate-stage-manifest.json"
        with stage_manifest_path.open("x", encoding="utf-8") as stream:
            json.dump(stage_manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(stage_manifest_path, 0o600)

        result = {
            "schema": "nvidia-r595-linux68-static-depmod-plan-v3",
            "status": "passed",
            "qualification": "private-static-depmod-and-modprobe-plan",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "target": TARGET,
            "guest_hostname": GUEST_HOSTNAME,
            "kernel_release": kernel_release,
            "kmod_version": modprobe_version,
            "static_bundle_audit": {"path": str(Path(audit_report).resolve()), "sha256": audit_hash},
            "kernel_support_capture": {"path": str(Path(support_capture).resolve()), "sha256": capture_hash,
                                       "guest_mutation_performed": False},
            "candidate_uvm_config": {
                "path": str(config_source), "sha256": config_hash,
                "staged_path": str(config_target.relative_to(stage_root)),
                "staged_sha256": _sha256_file(config_target),
                "option": ISOLATED_UVM_OPTION,
            },
            "implementation_sha256": implementation_hash,
            "staged_modules": staged_modules,
            "staged_support_modules": staged_support,
            "captured_metadata_sha256": metadata_hashes,
            "staged_configuration": {
                "relative_path": config_target.relative_to(stage_root).as_posix(),
                "sha256": _sha256_file(config_target),
                "option": ISOLATED_UVM_OPTION,
            },
            "modules_order": order_rows,
            "hard_dependency_graph": {name: sorted(edges) for name, edges in sorted(graph.items())},
            "softdep_lines": softdep_lines,
            "resolution": resolution,
            "candidate_stage_manifest": {
                "path": str(stage_manifest_path.relative_to(stage_root)),
                "sha256": _sha256_file(stage_manifest_path),
            },
            "commands": {
                "depmod": {"argv": depmod_command, "exit_code": depmod.returncode,
                           "stdout": depmod.stdout, "stderr": depmod.stderr},
            },
            "stage_root": str(stage_root.resolve(strict=True)),
            "module_installed": False,
            "module_loaded": False,
            "gpu_accessed": False,
            "cuda_execution_tested": False,
            "runtime_or_hardware_validated": False,
            "limitations": [
                "depmod and modprobe only build and print a proposed dependency plan; no module was loaded.",
                "this does not validate module init, RM/GPU initialization, CUDA, UVM runtime, P2P, performance, or endurance.",
            ],
        }
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(report_path, 0o600)
        result["report_path"] = str(report_path.resolve(strict=True))
        result["report_sha256"] = _sha256_file(report_path)
        success = True
        return result
    finally:
        if not success:
            shutil.rmtree(stage_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-report", type=Path, required=True)
    parser.add_argument("--expected-audit-sha256", required=True)
    parser.add_argument("--support-capture", type=Path, required=True)
    parser.add_argument("--expected-support-capture-sha256", required=True)
    parser.add_argument("--kernel-release", default=KERNEL_RELEASE)
    parser.add_argument("--stage-parent", type=Path, default=ROOT / "build/staging")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = stage_r595_linux68_hybrid_bundle(
            audit_report=args.audit_report,
            expected_audit_sha256=args.expected_audit_sha256,
            support_capture=args.support_capture,
            expected_support_capture_sha256=args.expected_support_capture_sha256,
            kernel_release=args.kernel_release,
            stage_parent=args.stage_parent,
            report_path=args.report,
            project_root=ROOT,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"verify_r595_linux68_hybrid_depmod: error: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": result["status"],
        "qualification": result["qualification"],
        "report": result["report_path"],
        "report_sha256": result["report_sha256"],
        "stage_root": result["stage_root"],
        "frontend_plan": result["resolution"]["nvidia"]["first_occurrences"],
        "uvm_plan": result["resolution"]["nvidia_uvm"]["first_occurrences"],
        "module_loaded": False,
        "module_installed": False,
        "runtime_or_hardware_validated": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
