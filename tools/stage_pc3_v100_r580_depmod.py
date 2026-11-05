#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the exact PC3 R580 bundle and check its isolated Linux 6.8 module graph.

This tool consumes the hash-verified static bundle audit and read-only PC3
kernel dependency capture. It copies those exact inputs to a new scratch tree,
runs depmod there, and asks modprobe to enumerate dependencies. It never
installs, signs, or inserts modules. A modprobe dependency walk is not treated
as an insertion-order or runtime proof.
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
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
KERNEL_RELEASE = "6.8.0-147-generic"
TARGET = "pc3@pc3"
GUEST_HOSTNAME = "pc3-v100"
CAPTURE_SCHEMA = "pc3-v100-kernel-dependency-capture-v1"
BUNDLE_SCHEMA = "nvidia-pc3-v100-r580-hybrid-static-stack-audit-v1"
ROLES = {
    "open": ("hybrid580_open", "hybrid580_open.ko", ["ecc"]),
    "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko", []),
    "frontend": ("nvidia", "nvidia.ko", ["hybrid580_legacy", "hybrid580_open"]),
    "uvm": ("nvidia_uvm", "nvidia_uvm.ko", ["nvidia"]),
}
SUPPORT_MODULES = {
    "ecc": ("kernel/crypto/ecc.ko.zst", []),
    "ecdh_generic": ("kernel/crypto/ecdh_generic.ko.zst", ["ecc"]),
    "ecdsa_generic": ("kernel/crypto/ecdsa_generic.ko.zst", ["ecc"]),
}
METADATA_FILES = (
    "modules.builtin", "modules.builtin.modinfo", "modules.dep",
    "modules.order", "modules.softdep",
)
EXPECTED_WALK_FIRST_OCCURRENCES = [
    "ecc", "ecdh_generic", "ecdsa_generic", "hybrid580_open",
    "hybrid580_legacy", "nvidia", "nvidia_uvm",
]
MODULE_SUFFIXES = (".ko.zst", ".ko.xz", ".ko.gz", ".ko")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON evidence {path.name}: {error}") from None
    if not isinstance(value, dict):
        raise ValueError(f"evidence is not a JSON object: {path.name}")
    return value, raw


def _inside(path: Path, root: Path) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError:
        raise ValueError("evidence path escapes the project root") from None
    if path.is_symlink() or not resolved.is_file():
        raise ValueError("evidence artifact is not a regular file")
    return resolved


def _relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"invalid relative path for {label}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe relative path for {label}")
    return path


def _module_name(path: str) -> str:
    leaf = PurePosixPath(path).name
    for suffix in MODULE_SUFFIXES:
        if leaf.endswith(suffix):
            return leaf[:-len(suffix)].replace("-", "_")
    raise ValueError(f"unexpected module filename: {leaf}")


def _copy_private(source: Path, destination: Path, expected_hash: str, expected_bytes: int) -> None:
    raw = source.read_bytes()
    if len(raw) != expected_bytes or _sha256(raw) != expected_hash:
        raise ValueError(f"capture hash or length differs for {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with destination.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(destination, 0o600)


def _tree_records(base: Path) -> list[dict[str, Any]]:
    records = []
    for current, dirs, files in os.walk(base, followlinks=False):
        directory = Path(current)
        for name in dirs:
            item = directory / name
            if item.is_symlink() or not item.is_dir():
                raise ValueError("isolated module stage contains a non-directory entry")
        for name in sorted(files):
            item = directory / name
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("isolated module stage contains a non-regular file")
            raw = item.read_bytes()
            records.append({
                "relative_path": item.relative_to(base).as_posix(),
                "bytes": len(raw),
                "sha256": _sha256(raw),
            })
    return sorted(records, key=lambda item: item["relative_path"])


def _run(runner: Callable[..., Any], argv: list[str]) -> Any:
    try:
        return runner(argv, check=False, capture_output=True, text=True,
                      timeout=120, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"cannot run {argv[0]}: {error}") from None


def _check_result(result: Any, operation: str) -> tuple[str, str]:
    if result.returncode != 0:
        raise ValueError(f"{operation} failed ({result.returncode}): {result.stderr.strip()[:1000]}")
    return result.stdout, result.stderr


def _validate_inputs(bundle_path: Path, capture_path: Path, root: Path):
    bundle_path = _inside(bundle_path, root)
    capture_path = _inside(capture_path, root)
    bundle, bundle_raw = _read_json(bundle_path)
    capture, capture_raw = _read_json(capture_path)
    if (bundle.get("schema") != BUNDLE_SCHEMA or bundle.get("status") != "passed" or
            bundle.get("qualification") != "static-module-bundle-closure" or
            bundle.get("target") != TARGET or bundle.get("guest_hostname") != GUEST_HOSTNAME or
            bundle.get("kernel_release") != KERNEL_RELEASE or
            bundle.get("gpu_accessed") is not False or bundle.get("module_installed") is not False or
            bundle.get("module_loaded") is not False or bundle.get("cuda_execution_tested") is not False or
            bundle.get("runtime_or_hardware_validated") is not False):
        raise ValueError("static bundle audit identity or qualification differs")
    static = bundle.get("static_audit")
    if (not isinstance(static, dict) or static.get("schema") != "hybrid-module-bundle-static-audit-v1" or
            static.get("status") != "passed" or static.get("kernel_release") != KERNEL_RELEASE or
            static.get("runtime_or_hardware_validated") is not False or static.get("issues") != []):
        raise ValueError("static bundle closure is not a clean Linux 6.8 audit")
    module_records = static.get("modules")
    if not isinstance(module_records, dict) or set(module_records) != set(ROLES):
        raise ValueError("static bundle module role set differs")
    verified = bundle.get("verified_artifacts")
    if not isinstance(verified, dict):
        raise ValueError("static bundle verified-artifact records are absent")

    modules = {}
    for role, (expected_name, filename, expected_depends) in ROLES.items():
        record = module_records[role]
        if (not isinstance(record, dict) or record.get("name") != expected_name or
                record.get("depends") != expected_depends):
            raise ValueError(f"static bundle module contract differs for {role}")
        artifact = verified.get(role)
        if (not isinstance(artifact, dict) or artifact.get("sha256") != record.get("sha256") or
                artifact.get("path") != record.get("path")):
            raise ValueError(f"verified artifact record differs for {role}")
        try:
            candidate_path = Path(record["path"])
            if not candidate_path.is_absolute():
                candidate_path = root / candidate_path
            candidate_path = _inside(candidate_path, root)
        except (KeyError, OSError, ValueError):
            raise ValueError(f"artifact path is invalid for {role}") from None
        raw = candidate_path.read_bytes()
        expected_size = record.get("bytes")
        if ((expected_size is not None and
             (not isinstance(expected_size, int) or isinstance(expected_size, bool) or
              len(raw) != expected_size)) or _sha256(raw) != record.get("sha256")):
            raise ValueError(f"artifact hash or length differs for {role}")
        modules[role] = {
            "name": expected_name,
            "filename": filename,
            "depends": expected_depends,
            "source": candidate_path,
            "bytes": len(raw),
            "sha256": _sha256(raw),
        }

    if (capture.get("schema") != CAPTURE_SCHEMA or capture.get("status") != "captured" or
            capture.get("qualification") != "read-only-exact-kernel-support-module-capture" or
            capture.get("target") != TARGET or capture.get("guest_hostname") != GUEST_HOSTNAME or
            capture.get("kernel_release") != KERNEL_RELEASE or
            capture.get("guest_mutation_performed") is not False or
            capture.get("module_installed") is not False or capture.get("module_loaded") is not False or
            capture.get("runtime_or_hardware_validated") is not False):
        raise ValueError("read-only PC3 capture identity or qualification differs")
    stage_rel = _relative_path(capture.get("stage_root"), "capture stage root")
    capture_root = root / Path(stage_rel.as_posix())
    try:
        capture_root.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError):
        raise ValueError("captured dependency stage is unavailable or escapes the project") from None
    captured_modules = {}
    captured_metadata = {}
    seen_names: set[tuple[str, str]] = set()
    for item in capture.get("files", []):
        if not isinstance(item, dict):
            raise ValueError("malformed capture file record")
        kind = item.get("kind")
        name = item.get("name")
        path = _relative_path(item.get("path"), "captured file")
        if (kind, name) in seen_names:
            raise ValueError("duplicate capture file identity")
        seen_names.add((kind, name))
        if kind == "module":
            expected = SUPPORT_MODULES.get(name)
            if expected is None or item.get("guest_path") != expected[0] or item.get("depends") != expected[1]:
                raise ValueError("captured kernel module set or dependency graph differs")
            if path != stage_rel / "lib" / "modules" / KERNEL_RELEASE / expected[0]:
                raise ValueError("captured module path differs")
            captured_modules[name] = item
        elif kind == "metadata":
            if name not in METADATA_FILES or item.get("guest_path") != name:
                raise ValueError("captured kernel metadata set differs")
            if path != stage_rel / "lib" / "modules" / KERNEL_RELEASE / name:
                raise ValueError("captured metadata path differs")
            captured_metadata[name] = item
        else:
            raise ValueError("unknown capture file kind")
        source = _inside(root / Path(path.as_posix()), root)
        raw = source.read_bytes()
        if (len(raw) != item.get("bytes") or _sha256(raw) != item.get("sha256") or
                not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256")))):
            raise ValueError(f"capture hash or length differs for {name}")
    if set(captured_modules) != set(SUPPORT_MODULES) or set(captured_metadata) != set(METADATA_FILES):
        raise ValueError("capture module or metadata set is incomplete")
    return {
        "bundle": bundle,
        "bundle_sha256": _sha256(bundle_raw),
        "capture": capture,
        "capture_sha256": _sha256(capture_raw),
        "modules": modules,
        "support_modules": captured_modules,
        "metadata": captured_metadata,
        "capture_root": capture_root,
    }


def _filter_modules_order(raw: bytes, support: dict[str, dict[str, Any]]) -> list[str]:
    text = raw.decode("utf-8", "strict")
    normalized_to_name = {}
    for name, record in support.items():
        guest_path = record["guest_path"]
        if not guest_path.endswith(".ko.zst"):
            raise ValueError("captured support module compression differs")
        normalized_to_name[guest_path[:-4]] = name
    selected = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if not value:
            continue
        path = _relative_path(value, f"modules.order line {line_number}").as_posix()
        name = normalized_to_name.get(path)
        if name is not None:
            if name in selected:
                raise ValueError("modules.order contains a duplicate captured provider")
            selected.append(name)
    if set(selected) != set(SUPPORT_MODULES):
        raise ValueError("target modules.order does not contain the three captured dependencies")
    return [support[name]["guest_path"] for name in selected]


def _parse_modules_dep(path: Path) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
        target, separator, dependency_text = line.partition(":")
        if not separator:
            raise ValueError(f"depmod emitted malformed modules.dep line {number}")
        target = _relative_path(target.strip(), "modules.dep target").as_posix()
        name = _module_name(target)
        if name in result:
            raise ValueError(f"depmod emitted duplicate modules.dep rows for {name}")
        dependencies = set()
        for entry in dependency_text.split():
            rel = _relative_path(entry, "modules.dep dependency").as_posix()
            dependencies.add(_module_name(rel))
        result[name] = dependencies
    return result


def _parse_modprobe_walk(stdout: str, stage: Path) -> tuple[list[str], list[str], dict[str, int]]:
    raw_names = []
    seen_paths: dict[str, str] = {}
    for number, line in enumerate(stdout.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if fields[0] != "insmod" or len(fields) < 2:
            raise ValueError(f"unexpected modprobe dependency-walk output line {number}")
        path = Path(fields[1])
        try:
            relative = path.resolve(strict=True).relative_to(stage.resolve(strict=True)).as_posix()
        except (OSError, ValueError):
            raise ValueError("modprobe dependency walk escaped the isolated stage") from None
        name = _module_name(relative)
        if name not in set(SUPPORT_MODULES) | {item[0] for item in ROLES.values()}:
            raise ValueError(f"modprobe dependency walk returned unexpected module {name}")
        previous = seen_paths.get(name)
        if previous is not None and previous != relative:
            raise ValueError(f"ambiguous providers for repeated dependency {name}")
        seen_paths[name] = relative
        raw_names.append(name)
    counts = Counter(raw_names)
    expected = set(SUPPORT_MODULES) | {item[0] for item in ROLES.values()}
    if set(counts) != expected:
        raise ValueError(f"modprobe dependency walk module set differs: {sorted(counts)}")
    repeated = {name: count for name, count in counts.items() if count > 1}
    if set(repeated) - {"ecc"}:
        raise ValueError("unexpected repeated dependency in modprobe dependency walk")
    first_occurrences = list(dict.fromkeys(raw_names))
    if first_occurrences != EXPECTED_WALK_FIRST_OCCURRENCES:
        raise ValueError("modprobe dependency walk first-occurrence order differs")
    return raw_names, first_occurrences, repeated


def _validate_dry_run(stdout: str, stage: Path) -> list[str]:
    names = []
    for number, line in enumerate(stdout.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if fields[0] != "insmod" or len(fields) < 2:
            raise ValueError(f"unexpected modprobe dry-run output line {number}")
        path = Path(fields[1])
        try:
            relative = path.resolve(strict=True).relative_to(stage.resolve(strict=True)).as_posix()
        except (OSError, ValueError):
            raise ValueError("modprobe dry-run escaped the isolated stage") from None
        names.append(_module_name(relative))
    expected = set(SUPPORT_MODULES) | {item[0] for item in ROLES.values()}
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError("modprobe dry-run does not show one insertion for each staged provider")
    positions = {name: index for index, name in enumerate(names)}
    if not (positions["ecc"] < positions["ecdh_generic"] < positions["ecdsa_generic"] <
            positions["hybrid580_open"] < positions["nvidia"] < positions["nvidia_uvm"]):
        raise ValueError("modprobe dry-run dependency order differs")
    if positions["hybrid580_legacy"] > positions["nvidia"]:
        raise ValueError("modprobe dry-run places legacy provider after frontend")
    return names


def stage_bundle(bundle_path: Path, capture_path: Path, stage_root: Path, *,
                 project_root: Path = ROOT, sysfs_module_root: Path = Path("/sys/module"),
                 runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    root = Path(project_root).resolve(strict=True)
    bundle_path = Path(bundle_path)
    capture_path = Path(capture_path)
    if not bundle_path.is_absolute():
        bundle_path = root / bundle_path
    if not capture_path.is_absolute():
        capture_path = root / capture_path
    validated = _validate_inputs(bundle_path, capture_path, root)
    stage_root = Path(stage_root)
    if not stage_root.is_absolute():
        stage_root = root / stage_root
    stage_root = Path(os.path.abspath(stage_root))
    try:
        stage_root.relative_to(root / "build/experiments")
    except ValueError:
        raise ValueError("stage destination must remain under build/experiments") from None
    parent = stage_root.parent
    cursor = root
    for component in parent.relative_to(root).parts:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("stage destination contains a symlink or non-directory")
    parent.mkdir(parents=True, exist_ok=True)
    if stage_root.exists() or stage_root.is_symlink():
        raise FileExistsError(f"refusing to overwrite staging tree: {stage_root}")
    runner = runner or subprocess.run
    temporary = Path(tempfile.mkdtemp(prefix=".pc3-v100-r580-depmod-", dir=parent))
    try:
        os.chmod(temporary, 0o700)
        module_root = temporary / "lib/modules" / KERNEL_RELEASE
        support_root = module_root / "kernel/crypto"
        candidate_root = module_root / "updates/extra"
        support_paths = {}
        for name, (relative, _) in SUPPORT_MODULES.items():
            record = validated["support_modules"][name]
            destination = module_root / relative
            _copy_private(root / record["path"], destination, record["sha256"], record["bytes"])
            support_paths[name] = destination
        metadata_hashes = {}
        for name in ("modules.builtin", "modules.builtin.modinfo"):
            record = validated["metadata"][name]
            destination = module_root / name
            _copy_private(root / record["path"], destination, record["sha256"], record["bytes"])
            metadata_hashes[name] = record["sha256"]

        selected_order = _filter_modules_order(
            (root / validated["metadata"]["modules.order"]["path"]).read_bytes(),
            validated["support_modules"],
        )
        module_order = list(selected_order)
        module_order.extend(f"updates/extra/{ROLES[role][1]}" for role in ("open", "legacy", "frontend", "uvm"))
        (module_root / "modules.order").write_text("".join(f"{path}\n" for path in module_order), encoding="utf-8")
        os.chmod(module_root / "modules.order", 0o600)

        staged_modules = {}
        for role, (name, filename, depends) in ROLES.items():
            item = validated["modules"][role]
            destination = candidate_root / filename
            _copy_private(item["source"], destination, item["sha256"], item["bytes"])
            identity = {}
            for field in ("name", "depends", "vermagic", "version"):
                output, error = _check_result(
                    _run(runner, ["modinfo", "-F", field, str(destination)]),
                    f"modinfo {field} for {name}",
                )
                if error.strip():
                    raise ValueError(f"modinfo {field} emitted stderr for {name}")
                identity[field] = output.strip()
            if identity["name"].replace("-", "_") != name:
                raise ValueError(f"staged module internal identity differs for {name}")
            actual_depends = {x.replace("-", "_") for x in identity["depends"].split(",") if x}
            if actual_depends != set(depends):
                raise ValueError(f"staged module dependency metadata differs for {name}")
            if not identity["vermagic"].split() or identity["vermagic"].split()[0] != KERNEL_RELEASE:
                raise ValueError(f"staged module vermagic differs for {name}")
            expected_version = "" if name == "nvidia" else "580.178.04"
            if identity["version"] != expected_version:
                raise ValueError(f"staged module version differs for {name}")
            staged_modules[name] = {
                "relative_path": destination.relative_to(temporary).as_posix(),
                "bytes": item["bytes"],
                "sha256": item["sha256"],
                "depends": depends,
                "identity": identity,
            }

        depmod_stdout, depmod_stderr = _check_result(
            _run(runner, ["depmod", "-b", str(temporary), KERNEL_RELEASE]), "isolated depmod"
        )
        warning_lines = [line for line in depmod_stderr.splitlines() if line.strip()]
        if warning_lines:
            raise ValueError("isolated depmod emitted warnings: " + " | ".join(warning_lines[:5]))
        modules_dep_path = module_root / "modules.dep"
        if not modules_dep_path.is_file() or modules_dep_path.is_symlink():
            raise ValueError("isolated depmod did not create a regular modules.dep")
        graph = _parse_modules_dep(modules_dep_path)
        expected_edges = {
            "ecc": set(), "ecdh_generic": {"ecc"}, "ecdsa_generic": {"ecc"},
            "hybrid580_open": {"ecc"}, "hybrid580_legacy": set(),
            "nvidia": {"hybrid580_open", "hybrid580_legacy", "ecc"},
            "nvidia_uvm": {"nvidia", "hybrid580_open", "hybrid580_legacy", "ecc"},
        }
        for name, dependencies in expected_edges.items():
            if graph.get(name) != dependencies:
                raise ValueError(f"depmod hard-dependency closure differs for {name}: {sorted(graph.get(name, set()))}")
        softdep_path = module_root / "modules.softdep"
        softdep_lines = [line.strip() for line in softdep_path.read_text(encoding="utf-8", errors="strict").splitlines()
                         if line.strip() and not line.lstrip().startswith("#")]
        if softdep_lines != ["softdep hybrid580_open pre: ecdh_generic ecdsa_generic"]:
            raise ValueError("depmod soft-dependency projection differs")

        stdout, show_stderr = _check_result(_run(runner, [
            "modprobe", "-C", "/dev/null", "-d", str(temporary), "--set-version",
            KERNEL_RELEASE, "--show-depends", "nvidia_uvm",
        ]), "isolated modprobe --show-depends")
        if show_stderr.strip():
            raise ValueError("modprobe --show-depends emitted stderr")
        raw_names, unique_names, repeated = _parse_modprobe_walk(stdout, temporary)

        version_output, version_error = _check_result(
            _run(runner, ["modprobe", "--version"]), "modprobe version query")
        if version_error.strip():
            raise ValueError("modprobe --version emitted stderr")
        match = re.search(r"kmod version ([0-9]+(?:\.[0-9]+)+)", version_output)
        if not match:
            raise ValueError("could not identify kmod version")
        kmod_version = match.group(1)
        depmod_version_output, depmod_version_error = _check_result(
            _run(runner, ["depmod", "--version"]), "depmod version query")
        if depmod_version_error.strip():
            raise ValueError("depmod --version emitted stderr")
        depmod_match = re.search(r"kmod version ([0-9]+(?:\.[0-9]+)+)", depmod_version_output)
        if not depmod_match or depmod_match.group(1) != kmod_version:
            raise ValueError("depmod and modprobe versions differ")

        loaded_collisions = sorted(name for name in set(SUPPORT_MODULES) | {x[0] for x in ROLES.values()}
                                   if (Path(sysfs_module_root) / name).exists())
        dry_run = {
            "executed": False,
            "exit_code": None,
            "insertion_order": [],
            "stderr_empty": None,
            "loaded_name_collisions": loaded_collisions,
            "skipped_reason": None,
        }
        if loaded_collisions:
            dry_run["skipped_reason"] = (
                "one or more module names needed by the candidate already exist in the runner's active kernel; "
                "a dry-run would omit those candidates and cannot represent this target-kernel insertion plan"
            )
        else:
            dry_stdout, dry_stderr = _check_result(_run(runner, [
                "modprobe", "-C", "/dev/null", "-d", str(temporary), "--set-version",
                KERNEL_RELEASE, "--dry-run", "--verbose", "nvidia_uvm",
            ]), "isolated modprobe dry-run")
            dry_order = _validate_dry_run(dry_stdout, temporary)
            if dry_stderr.strip():
                raise ValueError("modprobe dry-run emitted stderr")
            dry_run.update({"executed": True, "exit_code": 0,
                            "insertion_order": dry_order, "stderr_empty": True})

        report = {
            "schema": "nvidia-pc3-v100-r580-depmod-stage-v1",
            "status": "passed",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "implementation": {
                "path": Path(__file__).resolve().relative_to(ROOT).as_posix(),
                "sha256": _sha256(Path(__file__).read_bytes()),
            },
            "qualification": "isolated-depmod-and-dependency-walk-validated",
            "target": TARGET,
            "guest_hostname": GUEST_HOSTNAME,
            "kernel_release": KERNEL_RELEASE,
            "input_evidence": {
                "bundle_audit": {"path": bundle_path.relative_to(root).as_posix(),
                                 "sha256": validated["bundle_sha256"]},
                "kernel_dependency_capture": {"path": capture_path.relative_to(root).as_posix(),
                                              "sha256": validated["capture_sha256"]},
            },
            "staging": {
                "stage_root": stage_root.relative_to(root).as_posix(),
                "source_kernel_modules_order_sha256": validated["metadata"]["modules.order"]["sha256"],
                "selected_kernel_order": selected_order,
                "candidate_module_order_entries": module_order[len(selected_order):],
                "copied_kernel_metadata": metadata_hashes,
                "modules": staged_modules,
                "tree_files": _tree_records(temporary),
            },
            "kmod": {"version": kmod_version, "depmod_version": depmod_match.group(1)},
            "depmod": {
                "exit_code": 0,
                "warning_lines": warning_lines,
                "stdout_lines": depmod_stdout.splitlines(),
                "modules_dep_sha256": _sha256(modules_dep_path.read_bytes()),
                "hard_dependency_graph": {name: sorted(values) for name, values in graph.items()},
                "softdep_lines": softdep_lines,
            },
            "resolved_dependency_walk": {
                "exit_code": 0,
                "raw_module_names": raw_names,
                "first_occurrence_module_names": unique_names,
                "repeated_module_names": repeated,
                "stderr_empty": True,
                "is_insert_order_proof": False,
                "semantics": "kmod --show-depends flat dependency listing; repeated ecc paths reflect shared transitive dependencies",
            },
            "kmod_probe_list_source_inspection": {
                "source_url": "https://github.com/kmod-project/kmod/blob/v34.2/libkmod/libkmod-module.c#L3604-L3721",
                "observation": "the v34.2 insertion probe-list traversal marks a module visited before walking dependencies and returns on revisits",
                "qualification": "upstream-code-inspection-only; no candidate insertion attempted",
            },
            "dry_run": dry_run,
            "module_load_attempted": False,
            "module_installed": False,
            "module_loaded": False,
            "cuda_execution_tested": False,
            "runtime_or_hardware_validated": False,
        }
        os.rename(temporary, stage_root)
        if _tree_records(stage_root) != report["staging"]["tree_files"]:
            shutil.rmtree(stage_root, ignore_errors=True)
            temporary = None
            raise ValueError("final staged tree differs from its recorded file hashes")
        temporary = None
        return report
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def _write_private_json(path: Path, value: dict[str, Any]) -> str:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return _sha256(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-audit", type=Path, required=True)
    parser.add_argument("--dependency-capture", type=Path, required=True)
    parser.add_argument("--stage-root", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stage_root = args.stage_root or Path("build/experiments") / f"pc3-v100-r580-depmod-{stamp}-{uuid.uuid4().hex[:8]}"
    report_path = args.report or Path("evidence") / f"pc3-v100-r580-depmod-{stamp}.json"
    try:
        report_path = report_path if report_path.is_absolute() else ROOT / report_path
        report_path = Path(os.path.abspath(report_path))
        try:
            report_path.relative_to(ROOT / "evidence")
        except ValueError:
            raise ValueError("report path must remain under evidence/") from None
        if report_path.exists() or report_path.is_symlink():
            raise FileExistsError(f"refusing to overwrite report: {report_path}")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report = stage_bundle(args.bundle_audit, args.dependency_capture, stage_root)
        digest = _write_private_json(report_path, report)
        print(json.dumps({"status": report["status"], "report": report_path.relative_to(ROOT).as_posix(),
                          "sha256": digest, "stage_root": report["staging"]["stage_root"],
                          "qualification": report["qualification"]}, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
