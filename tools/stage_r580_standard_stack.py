#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage an evidence-pinned R580 module tree without installing or loading it.

The output is an isolated directory under build/staging. The tool verifies the
candidate manifest and dependency-graph evidence, copies the exact module tree
and isolated-UVM modprobe option, then asks kmod to print the insertion plan
with --show-depends. It never invokes modprobe insertion, depmod on the host,
signing, or any system configuration operation.
"""
from __future__ import annotations

import argparse
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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.create_r580_candidate_module_manifest import (
    ISOLATED_UVM_CONFIG,
    ISOLATED_UVM_OPTION,
    MODULES,
    _project_file,
    sha256_bytes,
)


EXPECTED_ORDER = [
    "ecdsa_generic", "hybrid580_open", "hybrid580_legacy", "nvidia", "nvidia_uvm"
]
MODULE_DEPENDENCIES = {
    "hybrid580_open": [],
    "hybrid580_legacy": [],
    "nvidia": ["hybrid580_legacy", "hybrid580_open"],
    "nvidia_uvm": ["nvidia"],
}
MODULE_FILENAMES = {
    "hybrid580_open": "hybrid580_open.ko",
    "hybrid580_legacy": "hybrid580_legacy.ko",
    "nvidia": "nvidia.ko",
    "nvidia_uvm": "nvidia-uvm.ko",
}
MANIFEST_SCHEMA = "nvidia-r580-hybrid-candidate-module-manifest-v2"
GRAPH_SCHEMA = "nvidia-r580-hybrid-module-dependency-graph-v5"


def _read_json(path: Path, root: Path) -> tuple[dict[str, Any], bytes]:
    resolved = _project_file(str(path), root)
    raw = resolved.read_bytes()

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON evidence {resolved.name}: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError(f"evidence is not a JSON object: {resolved.name}")
    return value, raw


def _safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError(f"invalid relative path for {label}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe relative path for {label}")
    return path


def _require_regular_tree(path: Path) -> None:
    if not path.is_dir() or path.is_symlink():
        raise ValueError("candidate module tree is not a regular directory")
    for current, dirs, files in os.walk(path, followlinks=False):
        base = Path(current)
        for name in dirs:
            item = base / name
            if item.is_symlink() or not item.is_dir():
                raise ValueError(f"candidate module tree contains a non-directory: {item}")
        for name in files:
            item = base / name
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"candidate module tree contains a non-regular file: {item}")


def _project_directory(relative: PurePosixPath, root: Path) -> Path:
    path = root / relative.as_posix()
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ValueError("candidate module tree escapes the project root") from None
    if path.is_symlink() or not resolved.is_dir():
        raise ValueError("candidate module tree is not a regular non-symlink directory")
    return resolved


def _tree_file_records(path: Path) -> list[dict[str, Any]]:
    records = []
    for current, dirs, files in os.walk(path, followlinks=False):
        base = Path(current)
        dirs.sort()
        for name in sorted(files):
            item = base / name
            info = item.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"module tree contains a non-regular file: {item}")
            raw = item.read_bytes()
            records.append({
                "relative_path": item.relative_to(path).as_posix(),
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
            })
    return records


def _validate_inputs(manifest_path: Path, root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any], Path, Path]:
    manifest, manifest_bytes = _read_json(manifest_path, root)
    if (manifest.get("schema") != MANIFEST_SCHEMA or
            manifest.get("qualification") != "compiled-abi-closed-and-isolated-dependency-resolved"):
        raise ValueError("candidate manifest is not the pinned R580 v2 artifact closure")
    if (manifest.get("runtime_or_hardware_validated") is not False or
            manifest.get("module_loaded_or_installed") is not False or
            manifest.get("activation_authorized") is not False):
        raise ValueError("candidate manifest has an unexpected runtime or activation state")
    if manifest.get("pc3_preflight", {}).get("status") != "blocked":
        raise ValueError("staging requires the recorded PC3 canary preflight to remain blocked")

    release = manifest.get("candidate", {}).get("kernel_release")
    if not isinstance(release, str) or not re.fullmatch(r"[A-Za-z0-9._+-]+", release):
        raise ValueError("candidate kernel release is invalid")
    if manifest.get("candidate", {}).get("uvm_module_name") != "nvidia_uvm":
        raise ValueError("candidate UVM module identity differs")
    runtime = manifest.get("runtime_configuration", {})
    if (runtime.get("module") != "nvidia_uvm" or
            runtime.get("options") != [ISOLATED_UVM_OPTION] or
            runtime.get("isolated_mode_required") is not True):
        raise ValueError("candidate does not require the isolated UVM execution option")
    config_record = runtime.get("modprobe_config", {})
    config_rel = _safe_relative(config_record.get("path"), "modprobe config")
    if config_rel.as_posix() != ISOLATED_UVM_CONFIG:
        raise ValueError("candidate modprobe config path is not the isolated-UVM file")
    config_path = _project_file(config_rel.as_posix(), root)
    config_bytes = config_path.read_bytes()
    if sha256_bytes(config_bytes) != config_record.get("sha256"):
        raise ValueError("candidate modprobe configuration hash differs from manifest")
    active_lines = [line.strip() for line in config_bytes.decode("utf-8", errors="strict").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    if active_lines != [f"options nvidia_uvm {ISOLATED_UVM_OPTION}"]:
        raise ValueError("candidate modprobe configuration is not the exact isolated option")

    module_records = manifest.get("modules", {})
    if set(module_records) != set(MODULES):
        raise ValueError("candidate manifest module set is not the exact four-module stack")
    evidence = manifest.get("evidence", {}).get("dependency_graph", {})
    graph_path = _project_file(evidence.get("path"), root)
    graph_bytes = graph_path.read_bytes()
    if sha256_bytes(graph_bytes) != evidence.get("sha256"):
        raise ValueError("dependency-graph evidence hash differs from candidate manifest")
    graph, _ = _read_json(graph_path, root)
    if (graph.get("schema") != GRAPH_SCHEMA or
            graph.get("qualification") != "isolated-depmod-and-modprobe-resolution" or
            graph.get("kernel_release") != release or
            graph.get("frontend_module_name") != "nvidia" or
            graph.get("uvm_module_name") != "nvidia_uvm" or
            graph.get("module_load_attempted") is not False or
            graph.get("runtime_or_hardware_validated") is not False or
            graph.get("depmod", {}).get("warning_lines") != [] or
            graph.get("modprobe_show_depends", {}).get("insert_order") != EXPECTED_ORDER or
            manifest.get("abi_closure", {}).get("dependency_load_order") != EXPECTED_ORDER):
        raise ValueError("dependency graph does not prove the exact isolated standard-name plan")

    candidate_base = _safe_relative(graph.get("candidate_base"), "dependency graph candidate base")
    module_tree_rel = candidate_base / "lib" / "modules" / release
    module_tree = _project_directory(module_tree_rel, root)
    _require_regular_tree(module_tree)
    graph_modules = graph.get("modules", {})
    role_for_name = {module_name: role for role, module_name in MODULES.items()}
    for module_name, expected_depends in MODULE_DEPENDENCIES.items():
        graph_record = graph_modules.get(module_name)
        manifest_record = module_records.get(role_for_name[module_name])
        if not isinstance(graph_record, dict) or not isinstance(manifest_record, dict):
            raise ValueError(f"missing pinned artifact record for {module_name}")
        relative_path = _safe_relative(graph_record.get("path"), f"{module_name} module")
        expected_path = module_tree_rel / "updates" / MODULE_FILENAMES[module_name]
        if relative_path != expected_path:
            raise ValueError(f"module path differs from the standard staged path for {module_name}")
        if (manifest_record.get("path") != relative_path.as_posix() or
                manifest_record.get("filename") != relative_path.name or
                manifest_record.get("module_name") != module_name or
                manifest_record.get("depends") != expected_depends or
                graph_record.get("depends") != expected_depends or
                manifest_record.get("sha256") != graph_record.get("sha256") or
                manifest_record.get("bytes") != graph_record.get("bytes")):
            raise ValueError(f"manifest and dependency graph disagree for {module_name}")
        artifact = _project_file(relative_path.as_posix(), root)
        raw = artifact.read_bytes()
        if len(raw) != graph_record.get("bytes") or sha256_bytes(raw) != graph_record.get("sha256"):
            raise ValueError(f"module bytes differ from evidence for {module_name}")
    if (runtime.get("candidate_module", {}).get("sha256") !=
            module_records["uvm"].get("sha256")):
        raise ValueError("isolated UVM option is not bound to the exact candidate module")
    return manifest, manifest_bytes, graph, module_tree, config_path


def _validate_show_depends(stdout: str, stage_root: Path, release: str) -> list[str]:
    lines = [line for line in stdout.splitlines() if line]
    if not lines or lines[0] != "builtin ecdh_generic":
        raise ValueError("dry-run dependency resolution has an unexpected builtin prelude")
    insmod_lines = [line for line in lines if line.startswith("insmod ")]
    if lines != [lines[0], *insmod_lines] or len(insmod_lines) != len(EXPECTED_ORDER):
        raise ValueError("dry-run dependency resolution returned an unexpected insertion count")
    resolved_order = []
    for line, expected_name in zip(insmod_lines, EXPECTED_ORDER, strict=True):
        fields = line.split()
        if len(fields) < 2:
            raise ValueError("dry-run dependency resolution returned malformed insmod output")
        module_path = Path(fields[1])
        try:
            relative = module_path.resolve(strict=True).relative_to(stage_root.resolve(strict=True))
        except (OSError, ValueError):
            raise ValueError("dry-run dependency resolution escaped the staged root") from None
        if expected_name == "ecdsa_generic":
            expected_rel = Path("lib/modules") / release / "kernel/crypto/ecdsa_generic.ko.zst"
        else:
            expected_rel = (Path("lib/modules") / release / "updates" /
                            MODULE_FILENAMES[expected_name])
        if relative != expected_rel:
            raise ValueError("dry-run dependency resolution points at an unexpected module")
        actual_name = (module_path.name.removesuffix(".ko.zst").removesuffix(".ko")
                       .replace("-", "_"))
        if actual_name != expected_name:
            raise ValueError("dry-run dependency resolution changed module insertion order")
        options = fields[2:]
        if expected_name == "nvidia_uvm":
            if options != [ISOLATED_UVM_OPTION]:
                raise ValueError("dry-run does not bind isolated mode to the exact UVM module")
        elif options:
            raise ValueError(f"unexpected modprobe options are set for {expected_name}")
        resolved_order.append(actual_name)
    return resolved_order


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def stage_candidate(manifest_path: Path, *, project_root: Path = ROOT) -> tuple[Path, dict[str, Any]]:
    root = Path(project_root).resolve(strict=True)
    manifest_path = Path(manifest_path)
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    manifest, manifest_bytes, graph, source_tree, config_path = _validate_inputs(manifest_path, root)
    release = manifest["candidate"]["kernel_release"]
    manifest_digest = sha256_bytes(manifest_bytes)
    staging_parent = root / "build" / "staging"
    try:
        staging_parent.resolve(strict=True).relative_to(root)
    except FileNotFoundError:
        # Create only after all source validation has succeeded.
        pass
    if staging_parent.exists() and (staging_parent.is_symlink() or not staging_parent.is_dir()):
        raise ValueError("staging parent must be a non-symlink directory")
    staging_parent.mkdir(parents=True, exist_ok=True)
    if staging_parent.resolve(strict=True).parent != (root / "build").resolve(strict=True):
        raise ValueError("staging parent resolves outside the project build directory")
    destination = staging_parent / f"r580-standard-stack-{manifest_digest[:16]}"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing staging tree: {destination}")

    temporary = Path(tempfile.mkdtemp(prefix=".r580-standard-stack-", dir=staging_parent))
    try:
        module_tree_target = temporary / "lib" / "modules" / release
        module_tree_target.parent.mkdir(parents=True)
        shutil.copytree(source_tree, module_tree_target, symlinks=False)
        source_tree_records = _tree_file_records(source_tree)
        staged_tree_records = _tree_file_records(module_tree_target)
        if staged_tree_records != source_tree_records:
            raise ValueError("staged module tree differs from the evidence-pinned source tree")
        config_target = temporary / "etc" / "modprobe.d" / Path(ISOLATED_UVM_CONFIG).name
        config_target.parent.mkdir(parents=True)
        shutil.copyfile(config_path, config_target, follow_symlinks=False)
        os.chmod(config_target, 0o644)
        _write_private(temporary / "candidate-manifest.json", manifest_bytes)

        argv = [
            "modprobe", "-C", str(config_target), "-d", str(temporary), "-S", release,
            "--show-depends", "nvidia_uvm",
        ]
        result = subprocess.run(argv, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise ValueError(f"dry-run dependency resolution failed: {result.stderr.strip()}")
        resolved_order = _validate_show_depends(result.stdout, temporary, release)
        if result.stderr.strip():
            raise ValueError("dry-run dependency resolution emitted stderr")

        modules_report = {}
        for role, record in manifest["modules"].items():
            relative = _safe_relative(record["path"], f"{role} manifest path")
            staged_file = temporary / "lib" / "modules" / release / "updates" / relative.name
            raw = staged_file.read_bytes()
            if sha256_bytes(raw) != record["sha256"] or len(raw) != record["bytes"]:
                raise ValueError(f"staged module verification failed for {role}")
            modules_report[role] = {
                "relative_path": f"lib/modules/{release}/updates/{relative.name}",
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
            }
        report = {
            "schema": "nvidia-r580-standard-stack-staging-v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "qualification": "isolated-module-tree-staged-and-dry-run-resolved",
            "manifest": {
                "relative_path": "candidate-manifest.json",
                "sha256": manifest_digest,
            },
            "dependency_graph": {
                "path": manifest["evidence"]["dependency_graph"]["path"],
                "sha256": manifest["evidence"]["dependency_graph"]["sha256"],
            },
            "kernel_release": release,
            "configuration": {
                "relative_path": f"etc/modprobe.d/{Path(ISOLATED_UVM_CONFIG).name}",
                "sha256": sha256_bytes(config_target.read_bytes()),
                "module": "nvidia_uvm",
                "options": [ISOLATED_UVM_OPTION],
                "bound_module_sha256": manifest["modules"]["uvm"]["sha256"],
            },
            "modules": modules_report,
            "module_tree_files": source_tree_records,
            "dry_run": {
                "command": ["modprobe", "-C", "<stage>/etc/modprobe.d/"
                            + Path(ISOLATED_UVM_CONFIG).name, "-d", "<stage>", "-S", release,
                            "--show-depends", "nvidia_uvm"],
                "exit_code": 0,
                "insert_order": resolved_order,
                "stderr_empty": True,
                "module_load_attempted": False,
            },
            "pc3_preflight_status": manifest["pc3_preflight"]["status"],
            "activation_performed": False,
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        }
        report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        _write_private(temporary / "staging-report.json", report_bytes)
        os.rename(temporary, destination)
        return destination, report
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        destination, report = stage_candidate(args.manifest)
        print(json.dumps({
            "staging_directory": str(destination),
            "qualification": report["qualification"],
            "module_count": len(report["modules"]),
            "insert_order": report["dry_run"]["insert_order"],
            "activation_performed": report["activation_performed"],
        }, sort_keys=True))
    except (FileExistsError, OSError, TypeError, ValueError, KeyError) as exc:
        print(f"R580 candidate staging failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
