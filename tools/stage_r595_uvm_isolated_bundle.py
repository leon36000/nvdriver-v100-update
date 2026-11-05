#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage a pinned R595/R580-GV100 candidate privately and query kmod only.

This tool copies four audited modules and the candidate-only UVM option into a
new directory below build/staging, runs depmod against that private root, then
uses modprobe --show-depends to inspect the proposed insertion order. It never
installs, signs, inserts, or loads a module and never writes host module or
modprobe configuration.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.create_r595_uvm_isolation_manifest import (  # noqa: E402
    CONFIG_RELATIVE_PATH,
    EXPECTED_CONFIG_LINE,
    build_manifest,
    _project_file,
)

EXPECTED_SCHEMA = "nvidia-hybrid-r595-uvm-isolation-manifest-v2"
EXPECTED_ORDER = [
    "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko", "nvidia_uvm.ko",
]
MODULES = {
    "open": {"name": "hybrid580_open", "filename": "hybrid580_open.ko", "depends": []},
    "legacy": {"name": "hybrid580_legacy", "filename": "hybrid580_legacy.ko", "depends": []},
    "frontend": {
        "name": "nvidia", "filename": "nvidia.ko",
        "depends": ["hybrid580_legacy", "hybrid580_open"],
    },
    "uvm": {"name": "nvidia_uvm", "filename": "nvidia_uvm.ko", "depends": ["nvidia"]},
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"expected regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()

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
        raise ValueError(f"invalid JSON evidence {path.name}: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError(f"evidence is not a JSON object: {path.name}")
    return value, raw


def _stable_manifest(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("created_at_utc", None)
    return result


def _manifest_inputs(manifest: dict[str, Any]) -> dict[str, str]:
    evidence = manifest.get("evidence", {})
    references = {
        "build_report": evidence.get("uvm_build", {}).get("path"),
        "bundle_audit": evidence.get("bundle_audit", {}).get("path"),
        "depmod_report": evidence.get("depmod", {}).get("path"),
        "preflight_report": evidence.get("pc3_preflight", {}).get("path"),
        "software_suite_report": evidence.get("software_suite", {}).get("path"),
        "uvm_module": manifest.get("module", {}).get("path"),
        "modprobe_config": manifest.get("configuration", {}).get("path"),
    }
    if any(not isinstance(value, str) or not value for value in references.values()):
        raise ValueError("manifest omits one or more source evidence paths")
    return references


def _validate_manifest(manifest_path: Path, expected_sha256: str,
                       root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    path = _project_file(manifest_path, root)
    raw = path.read_bytes()
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256 or "") is None:
        raise ValueError("expected manifest SHA-256 must contain 64 hexadecimal characters")
    digest = _sha256_bytes(raw)
    if digest != expected_sha256.lower():
        raise ValueError(f"manifest SHA-256 mismatch: got {digest}")
    manifest, _ = _read_json(path)
    if manifest.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("candidate manifest is not the pinned R595 isolation-manifest v2")
    if (manifest.get("module_loaded_or_installed") is not False or
            manifest.get("runtime_or_hardware_validated") is not False or
            manifest.get("activation_performed") is not False):
        raise ValueError("candidate manifest contains unexpected activation or runtime claims")
    if (manifest.get("pc3_preflight", {}).get("status") != "blocked" or
            manifest.get("pc3_preflight", {}).get("canary_ready") is not False):
        raise ValueError("staging requires the current blocked PC3 preflight receipt")

    rebuilt = build_manifest(_manifest_inputs(manifest), project_root=root)
    if json.dumps(_stable_manifest(rebuilt), sort_keys=True, separators=(",", ":")) != \
            json.dumps(_stable_manifest(manifest), sort_keys=True, separators=(",", ":")):
        raise ValueError("manifest no longer matches its source evidence and current validator")

    release = manifest.get("kernel_release")
    if not isinstance(release, str) or re.fullmatch(r"[A-Za-z0-9._+-]+", release) is None:
        raise ValueError("candidate kernel release is invalid")
    if manifest.get("dependency_load_order") != EXPECTED_ORDER:
        raise ValueError("manifest does not bind the expected four-module dependency order")
    configuration = manifest.get("configuration", {})
    if (configuration.get("path") != CONFIG_RELATIVE_PATH.as_posix() or
            configuration.get("module") != "nvidia_uvm" or
            configuration.get("options") != ["uvm_hybrid_isolated_gpu_execution=1"] or
            configuration.get("isolated_execution_required") is not True or
            configuration.get("activation_performed") is not False or
            configuration.get("bound_module_sha256") != manifest.get("module", {}).get("sha256")):
        raise ValueError("manifest does not bind the exact candidate-only UVM isolation option")
    config_path = _project_file(configuration["path"], root)
    config_raw = config_path.read_bytes()
    active_lines = [line.strip() for line in config_raw.decode("utf-8", errors="strict").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    if (_sha256_bytes(config_raw) != configuration.get("sha256") or
            len(config_raw) != configuration.get("bytes") or
            active_lines != [EXPECTED_CONFIG_LINE]):
        raise ValueError("candidate UVM modprobe configuration is stale or not isolated")

    audit_ref = manifest["evidence"]["bundle_audit"]
    audit_path = _project_file(audit_ref["path"], root)
    audit, audit_raw = _read_json(audit_path)
    if (_sha256_bytes(audit_raw) != audit_ref.get("sha256") or
            audit.get("schema") != "hybrid-module-bundle-static-audit-v1" or
            audit.get("status") != "passed" or
            audit.get("qualification") != "static-module-bundle-closure" or
            audit.get("kernel_release") != release or audit.get("issues") != [] or
            audit.get("module_loaded") is not False or
            audit.get("module_installed") is not False or
            audit.get("runtime_or_hardware_validated") is not False):
        raise ValueError("bundle audit is stale or has a non-static qualification")
    audited_modules = audit.get("modules", {})
    if set(audited_modules) != set(MODULES):
        raise ValueError("bundle audit does not identify exactly the four candidate modules")
    manifest_module = manifest.get("module", {})
    staged = {}
    for role, expected in MODULES.items():
        record = audited_modules[role]
        source = _project_file(record.get("path", ""), root)
        digest = _sha256_file(source)
        if (record.get("name") != expected["name"] or
                record.get("depends") != expected["depends"] or
                not str(record.get("vermagic", "")).startswith(release) or
                digest != record.get("sha256")):
            raise ValueError(f"audited module identity or bytes differ for {role}")
        if role == "uvm" and (source != _project_file(manifest_module["path"], root) or
                               digest != manifest_module.get("sha256") or
                               record.get("parameters", {}).get(
                                   "uvm_hybrid_isolated_gpu_execution", {}).get("type") != "bool"):
            raise ValueError("audited UVM differs from the isolation manifest")
        staged[role] = {"source": source, "sha256": digest, "bytes": source.stat().st_size,
                        **expected}
    return manifest, raw, staged


def _validate_modprobe_plan(stdout: str, stage_root: Path, release: str) -> list[str]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != len(EXPECTED_ORDER):
        raise ValueError("kmod returned an unexpected dependency order")
    actual = []
    stage = stage_root.resolve(strict=True)
    for line, expected_file in zip(lines, EXPECTED_ORDER, strict=True):
        fields = shlex.split(line)
        if len(fields) < 2 or fields[0] != "insmod":
            raise ValueError("kmod returned a non-module insertion instruction")
        module_path = Path(fields[1]).resolve(strict=True)
        try:
            relative = module_path.relative_to(stage)
        except ValueError:
            raise ValueError("kmod resolved a module outside the private staged root") from None
        expected_path = Path("lib/modules") / release / "updates/extra" / expected_file
        if relative != expected_path or module_path.name != expected_file:
            raise ValueError("kmod dependency order or staged module path differs")
        options = fields[2:]
        expected_options = (["uvm_hybrid_isolated_gpu_execution=1"]
                            if expected_file == "nvidia_uvm.ko" else [])
        if options != expected_options:
            raise ValueError("kmod did not attach the exact isolated option only to candidate UVM")
        actual.append(expected_file)
    return actual


def _write_private(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _staging_parent(root: Path) -> Path:
    build = root / "build"
    if build.exists() and (build.is_symlink() or not build.is_dir()):
        raise ValueError("project build directory must be a regular directory")
    staging = build / "staging"
    if staging.exists() and (staging.is_symlink() or not staging.is_dir()):
        raise ValueError("private staging parent must be a non-symlink directory")
    staging.mkdir(parents=True, exist_ok=True)
    if staging.resolve(strict=True).parent != build.resolve(strict=True):
        raise ValueError("private staging parent escapes the project build directory")
    return staging


def stage_candidate(manifest_path: Path, expected_manifest_sha256: str, *,
                    project_root: Path = ROOT, command_runner=None
                    ) -> tuple[Path, dict[str, Any]]:
    """Stage exact manifest-bound bytes and ask kmod for a non-inserting plan."""
    root = Path(project_root).resolve(strict=True)
    if command_runner is None:
        command_runner = subprocess.run
    manifest, manifest_raw, module_records = _validate_manifest(
        Path(manifest_path), expected_manifest_sha256, root)
    release = manifest["kernel_release"]
    manifest_digest = _sha256_bytes(manifest_raw)
    staging_parent = _staging_parent(root)
    destination = staging_parent / f"r595-uvm-isolated-{manifest_digest[:16]}"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite private stage: {destination}")
    temporary = Path(tempfile.mkdtemp(prefix=".r595-uvm-isolated-", dir=staging_parent))
    try:
        module_dir = temporary / "lib/modules" / release / "updates/extra"
        module_dir.mkdir(parents=True)
        base = temporary / "lib/modules" / release
        staged_modules = {}
        for role, record in module_records.items():
            target = module_dir / record["filename"]
            shutil.copyfile(record["source"], target, follow_symlinks=False)
            os.chmod(target, 0o600)
            digest = _sha256_file(target)
            if digest != record["sha256"] or target.stat().st_size != record["bytes"]:
                raise ValueError(f"staged module bytes differ from evidence for {role}")
            staged_modules[role] = {
                "name": record["name"], "relative_path": target.relative_to(temporary).as_posix(),
                "bytes": target.stat().st_size, "sha256": digest,
            }

        (base / "modules.order").write_text("".join(
            f"updates/extra/{MODULES[role]['filename']}\n"
            for role in ("open", "legacy", "frontend", "uvm")), encoding="utf-8")
        for metadata in ("modules.order", "modules.builtin", "modules.builtin.modinfo"):
            path = base / metadata
            if metadata != "modules.order":
                path.write_bytes(b"")
            os.chmod(path, 0o600)

        config_target = temporary / "etc/modprobe.d" / CONFIG_RELATIVE_PATH.name
        config_target.parent.mkdir(parents=True)
        config_source = _project_file(manifest["configuration"]["path"], root)
        shutil.copyfile(config_source, config_target, follow_symlinks=False)
        os.chmod(config_target, 0o600)
        _write_private(temporary / "candidate-manifest.json", manifest_raw)

        depmod_argv = ["depmod", "-b", str(temporary), release]
        depmod = command_runner(depmod_argv, capture_output=True, text=True, check=False)
        if depmod.returncode != 0:
            raise ValueError(f"private depmod failed: {depmod.stderr.strip()}")
        if depmod.stderr.strip():
            raise ValueError("private depmod emitted warnings for this staged bundle")
        modules_dep = base / "modules.dep"
        if not modules_dep.is_file() or modules_dep.is_symlink():
            raise ValueError("private depmod did not produce a regular modules.dep")

        modprobe_argv = [
            "modprobe", "-C", str(config_target), "-d", str(temporary),
            "--set-version", release, "--show-depends", "nvidia_uvm",
        ]
        plan = command_runner(modprobe_argv, capture_output=True, text=True, check=False)
        if plan.returncode != 0:
            raise ValueError(f"private modprobe dependency query failed: {plan.stderr.strip()}")
        if plan.stderr.strip():
            raise ValueError("private modprobe dependency query emitted stderr")
        insertion_order = _validate_modprobe_plan(plan.stdout, temporary, release)

        report = {
            "schema": "nvidia-hybrid-r595-private-staging-v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "qualification": "isolated-module-tree-staged-and-dry-run-resolved",
            "manifest": {"relative_path": "candidate-manifest.json", "sha256": manifest_digest},
            "kernel_release": release,
            "source_hal_release": manifest["source_hal"]["release"],
            "modules": staged_modules,
            "configuration": {
                "relative_path": config_target.relative_to(temporary).as_posix(),
                "sha256": _sha256_file(config_target),
                "module": "nvidia_uvm",
                "options": ["uvm_hybrid_isolated_gpu_execution=1"],
                "bound_module_sha256": manifest["module"]["sha256"],
            },
            "private_depmod": {
                "command": ["depmod", "-b", "<stage>", release],
                "exit_code": depmod.returncode,
                "stderr_empty": True,
                "modules_dep_sha256": _sha256_file(modules_dep),
                "module_load_attempted": False,
            },
            "dry_run": {
                "command": ["modprobe", "-C", "<stage>/etc/modprobe.d/"
                            + CONFIG_RELATIVE_PATH.name, "-d", "<stage>", "--set-version",
                            release, "--show-depends", "nvidia_uvm"],
                "exit_code": plan.returncode,
                "insert_order": insertion_order,
                "stderr_empty": True,
                "module_load_attempted": False,
            },
            "pc3_preflight_status": manifest["pc3_preflight"]["status"],
            "canary_ready": False,
            "activation_performed": False,
            "module_loaded_or_installed": False,
            "runtime_or_hardware_validated": False,
        }
        report_raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        _write_private(temporary / "staging-report.json", report_raw)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"refusing to overwrite private stage: {destination}")
        os.rename(temporary, destination)
        return destination, report
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        destination, report = stage_candidate(args.manifest, args.expected_manifest_sha256)
        print(json.dumps({
            "staging_directory": str(destination),
            "qualification": report["qualification"],
            "module_count": len(report["modules"]),
            "insert_order": report["dry_run"]["insert_order"],
            "activation_performed": False,
        }, sort_keys=True))
    except (FileExistsError, OSError, TypeError, ValueError, KeyError,
            subprocess.SubprocessError) as exc:
        print(f"R595 private candidate staging failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
