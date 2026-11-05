#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve an isolated R580 hybrid module stack with depmod/modprobe only."""
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
DEFAULT_UVM_MODULE = "nvidia_uvm"
SUPPORTED_UVM_MODULES = {DEFAULT_UVM_MODULE, "hybrid580_uvm"}
DEFAULT_FRONTEND_MODULE = "hybrid580_frontend"
SUPPORTED_FRONTEND_MODULES = {DEFAULT_FRONTEND_MODULE, "nvidia"}
EXPECTED_VERSION = "580.178.04"
OPEN_SOFTDEP = "pre: ecdh_generic ecdsa_generic"
MODULE_SUFFIXES = (".ko.zst", ".ko.xz", ".ko.gz", ".ko")


def module_contracts(
    uvm_module_name: str,
    frontend_module_name: str = DEFAULT_FRONTEND_MODULE,
) -> tuple[set[str], dict[str, set[str]], dict[str, str]]:
    if uvm_module_name not in SUPPORTED_UVM_MODULES:
        raise ValueError("unsupported UVM module identity")
    if frontend_module_name not in SUPPORTED_FRONTEND_MODULES:
        raise ValueError("unsupported frontend module identity")
    modules = {"hybrid580_open", "hybrid580_legacy", frontend_module_name, uvm_module_name}
    dependencies = {
        frontend_module_name: {"hybrid580_open", "hybrid580_legacy"},
        "hybrid580_open": set(),
        "hybrid580_legacy": set(),
        uvm_module_name: {frontend_module_name},
    }
    softdeps = {name: "" for name in modules}
    softdeps["hybrid580_open"] = OPEN_SOFTDEP
    return modules, dependencies, softdeps


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_module_name(name: str) -> str:
    """Normalize filenames to modinfo's underscore spelling."""
    return name.replace("-", "_")


def module_name_from_filename(filename: str) -> str:
    for suffix in MODULE_SUFFIXES:
        if filename.endswith(suffix):
            return normalize_module_name(filename[:-len(suffix)])
    raise ValueError(f"unexpected module filename: {filename}")


def module_name_from_filename_if_known(filename: str) -> str | None:
    try:
        return module_name_from_filename(filename)
    except ValueError:
        return None


def validate_softdep(name: str, value: str,
                     *, uvm_module_name: str = DEFAULT_UVM_MODULE,
                     frontend_module_name: str = DEFAULT_FRONTEND_MODULE) -> str:
    """Return normalized softdep metadata, rejecting unexpected changes."""
    _, _, expected_softdeps = module_contracts(uvm_module_name, frontend_module_name)
    if name not in expected_softdeps:
        raise ValueError(f"unexpected module in softdep audit: {name}")
    normalized = " ".join(value.split())
    expected = expected_softdeps[name]
    if normalized != expected:
        raise ValueError(f"{name} softdep {normalized!r} does not match {expected!r}")
    return normalized


def project_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def parse_show_depends(text: str) -> list[str]:
    """Return module names in the order modprobe would insert them."""
    order: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if not fields:
            continue
        if fields[0] != "insmod":
            continue
        if len(fields) < 2:
            raise ValueError(f"malformed insmod line {line_number}")
        name = Path(fields[1]).name
        order.append(module_name_from_filename(name))
    if not order:
        raise ValueError("modprobe reported no module insertions")
    if len(order) != len(set(order)):
        raise ValueError("modprobe plan contains duplicate module insertions")
    return order


def validate_full_load_order(order: list[str], *, ecdsa_expected: bool,
                             uvm_module_name: str = DEFAULT_UVM_MODULE,
                             frontend_module_name: str = DEFAULT_FRONTEND_MODULE) -> None:
    """Check the complete UVM insertion plan, including an unloaded softdep."""
    expected_modules, _, _ = module_contracts(uvm_module_name, frontend_module_name)
    expected = expected_modules | ({"ecdsa_generic"} if ecdsa_expected else set())
    if set(order) != expected:
        raise ValueError(f"resolved load set differs: {order}")
    positions = {name: order.index(name) for name in order}
    if ecdsa_expected and positions["ecdsa_generic"] > positions["hybrid580_open"]:
        raise ValueError("resolved load plan places ecdsa_generic after hybrid580_open")
    if not all(positions[provider] < positions[frontend_module_name]
               for provider in ("hybrid580_open", "hybrid580_legacy")):
        raise ValueError("modprobe plan places an R580 provider after the frontend")
    if positions[frontend_module_name] > positions[uvm_module_name]:
        raise ValueError("modprobe plan places the UVM consumer before the frontend")


def parse_modules_dep(text: str) -> dict[str, set[str]]:
    """Parse depmod's module dependency closure, keyed by module basename."""
    result: dict[str, set[str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        target, separator, dependencies = line.partition(":")
        if not separator:
            raise ValueError(f"malformed modules.dep line {line_number}")
        name = Path(target.strip()).name
        key = module_name_from_filename(name)
        values = {
            module_name_from_filename(Path(item).name)
            for item in dependencies.split()
            if any(item.endswith(suffix) for suffix in MODULE_SUFFIXES)
        }
        if key in result and result[key] != values:
            raise ValueError(f"conflicting modules.dep rows for {key}")
        result[key] = values
    return result


def parse_dry_run(text: str) -> list[str]:
    """Return staged module insertions in libkmod dry-run output order."""
    order: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if not fields or fields[0] != "insmod":
            continue
        if len(fields) < 2:
            raise ValueError(f"malformed dry-run insmod line {line_number}")
        order.append(module_name_from_filename(Path(fields[1]).name))
    if len(order) != len(set(order)):
        raise ValueError("modprobe dry-run contains duplicate module insertions")
    return order


def parse_builtin_modules(path: Path) -> set[str]:
    result: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="strict").splitlines(), start=1):
        value = line.strip()
        if not value:
            continue
        try:
            result.add(module_name_from_filename(Path(value).name))
        except ValueError as exc:
            raise ValueError(f"malformed modules.builtin line {line_number}: {exc}") from None
    return result


def run_text(argv: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cannot run {argv[0]}: {exc}") from None
    return result.returncode, result.stdout, result.stderr


def module_field(path: Path, field: str) -> str:
    status, out, err = run_text(["modinfo", "-F", field, str(path)])
    if status != 0:
        raise ValueError(f"modinfo failed for {path.name}: {err.strip()[:500]}")
    return out.strip()


def build_report(base: Path, kernel_release: str,
                 uvm_module_name: str = DEFAULT_UVM_MODULE,
                 frontend_module_name: str = DEFAULT_FRONTEND_MODULE) -> dict[str, Any]:
    expected_modules, expected_dependencies, _ = module_contracts(
        uvm_module_name, frontend_module_name
    )
    base = base.resolve(strict=True)
    module_root = base / "lib/modules" / kernel_release
    # The stage may also include compressed kernel modules required by the
    # Open provider's softdeps. Audit only the four candidate modules in
    # updates/, leaving system modules as resolver inputs.
    updates = module_root / "updates"
    modules = sorted(path for path in updates.rglob("*.ko") if path.is_file())
    by_name: dict[str, Path] = {}
    for path in modules:
        name = normalize_module_name(module_field(path, "name"))
        if name in by_name:
            raise ValueError(f"multiple candidate files provide module {name}")
        by_name[name] = path
    if set(by_name) != expected_modules:
        raise ValueError(
            f"candidate module set differs: missing={sorted(expected_modules - set(by_name))}, "
            f"extra={sorted(set(by_name) - expected_modules)}"
        )

    module_records: dict[str, dict[str, Any]] = {}
    for name, path in sorted(by_name.items()):
        depends = {item for item in module_field(path, "depends").split(",") if item}
        softdep = validate_softdep(
            name, module_field(path, "softdep"),
            uvm_module_name=uvm_module_name,
            frontend_module_name=frontend_module_name,
        )
        vermagic = module_field(path, "vermagic")
        version = module_field(path, "version")
        tokens = vermagic.split()
        if not tokens or tokens[0] != kernel_release:
            raise ValueError(f"{name} vermagic does not match {kernel_release}")
        if name != frontend_module_name and version != EXPECTED_VERSION:
            raise ValueError(f"{name} version {version!r} does not match {EXPECTED_VERSION}")
        if name == frontend_module_name and version not in {"", EXPECTED_VERSION}:
            raise ValueError(f"frontend version {version!r} is unexpected")
        if depends != expected_dependencies[name]:
            raise ValueError(f"{name} dependency metadata differs: {sorted(depends)}")
        module_records[name] = {
            "path": project_path(path),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "version": version,
            "depends": sorted(depends),
            "softdep": softdep,
            "vermagic": vermagic,
        }

    depmod_code, depmod_stdout, depmod_stderr = run_text(["depmod", "-b", str(base), kernel_release])
    if depmod_code != 0:
        raise ValueError(f"depmod failed ({depmod_code}): {depmod_stderr.strip()[:1000]}")
    modules_dep_path = module_root / "modules.dep"
    if not modules_dep_path.is_file():
        raise ValueError("depmod did not create modules.dep")
    dep_graph = parse_modules_dep(modules_dep_path.read_text(encoding="utf-8", errors="strict"))
    uvm_row = dep_graph.get(uvm_module_name)
    if uvm_row is None or not expected_modules - {uvm_module_name} <= uvm_row:
        raise ValueError("depmod's UVM row does not contain the frontend and both providers")

    modprobe_code, modprobe_stdout, modprobe_stderr = run_text([
        "modprobe", "-d", str(base), "-S", kernel_release, "--show-depends", uvm_module_name
    ])
    if modprobe_code != 0:
        raise ValueError(f"modprobe dependency resolution failed ({modprobe_code}): "
                         f"{modprobe_stderr.strip()[:1000]}")
    order = parse_show_depends(modprobe_stdout)

    builtin_path = module_root / "modules.builtin"
    if not builtin_path.is_file():
        raise ValueError("complete staged metadata is required: modules.builtin is absent")
    builtin_names = parse_builtin_modules(builtin_path)
    if "ecdh_generic" not in builtin_names:
        raise ValueError("expected ecdh_generic to be recorded as a built-in module")
    ecdsa_paths = [path for path in module_root.rglob("*")
                   if path.is_file() and module_name_from_filename_if_known(path.name) == "ecdsa_generic"]
    if len(ecdsa_paths) != 1:
        raise ValueError(f"expected one staged ecdsa_generic provider, found {len(ecdsa_paths)}")
    ecdsa_loaded = Path("/sys/module/ecdsa_generic").exists()
    open_loaded = Path("/sys/module/hybrid580_open").exists()
    if open_loaded:
        raise ValueError("hybrid580_open is already loaded; dry-run cannot validate its insertion plan")
    validate_full_load_order(order, ecdsa_expected=not ecdsa_loaded,
                             uvm_module_name=uvm_module_name,
                             frontend_module_name=frontend_module_name)
    dryrun_code, dryrun_stdout, dryrun_stderr = run_text([
        "modprobe", "--dry-run", "--verbose", "-d", str(base), "-S", kernel_release, "hybrid580_open"
    ])
    if dryrun_code != 0:
        raise ValueError(f"modprobe dry-run failed ({dryrun_code}): {dryrun_stderr.strip()[:1000]}")
    dryrun_order = parse_dry_run(dryrun_stdout)
    if "hybrid580_open" not in dryrun_order:
        raise ValueError("modprobe dry-run did not plan the Open provider insertion")
    if not ecdsa_loaded and "ecdsa_generic" not in dryrun_order:
        raise ValueError("modprobe dry-run omitted unloaded ecdsa_generic soft dependency")
    if "ecdsa_generic" in dryrun_order and dryrun_order.index("ecdsa_generic") > dryrun_order.index("hybrid580_open"):
        raise ValueError("modprobe dry-run places ecdsa_generic after the Open provider")

    return {
        "schema": "nvidia-r580-hybrid-module-dependency-graph-v5",
        "qualification": "isolated-depmod-and-modprobe-resolution",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "kernel_release": kernel_release,
        "candidate_base": project_path(base),
        "uvm_module_name": uvm_module_name,
        "frontend_module_name": frontend_module_name,
        "modules": module_records,
        "modinfo_dependency_graph": {name: sorted(values) for name, values in expected_dependencies.items()},
        "depmod": {
            "exit_code": depmod_code,
            "warning_lines": [line for line in depmod_stderr.splitlines() if line.strip()],
            "modules_dep_path": project_path(modules_dep_path),
            "modules_dep_sha256": sha256_file(modules_dep_path),
            "uvm_transitive_dependencies": sorted(uvm_row),
        },
        "softdep_resolution": {
            "module_metadata": {name: record["softdep"] for name, record in module_records.items()},
            "depmod_file_path": project_path(module_root / "modules.softdep"),
            "depmod_file_sha256": sha256_file(module_root / "modules.softdep")
            if (module_root / "modules.softdep").is_file() else None,
            "modules_builtin_path": project_path(builtin_path),
            "modules_builtin_sha256": sha256_file(builtin_path),
            "builtin_dependencies": sorted(builtin_names & {"ecdh_generic"}),
            "staged_ecdsa_module": project_path(ecdsa_paths[0]),
            "ecdsa_generic_resident_before_probe": ecdsa_loaded,
            "dry_run": {
                "exit_code": dryrun_code,
                "insert_order": dryrun_order,
                "stdout": dryrun_stdout.splitlines(),
                "stderr": dryrun_stderr.splitlines(),
            },
            "show_depends_exposes_softdep_order": (
                "ecdsa_generic" in order and
                order.index("ecdsa_generic") < order.index("hybrid580_open")
            ),
        },
        "modprobe_show_depends": {
            "exit_code": modprobe_code,
            "insert_order": order,
            "stdout": modprobe_stdout.splitlines(),
            "stderr": modprobe_stderr.splitlines(),
        },
        "module_load_attempted": False,
        "runtime_or_hardware_validated": False,
        "notes": [
            "depmod and modprobe resolved the staged module graph without inserting a module.",
            "The UVM and frontend module identities were checked against the explicitly selected names; this supports standard nvidia/nvidia_uvm and isolated hybrid580_frontend/hybrid580_uvm candidates.",
            "The isolated stage includes the target kernel's modules.order/modules.builtin metadata and compressed ecdsa_generic provider, so the dependency resolution uses the actual target-kernel inputs.",
            "The Open provider softdep uses kmod-compatible space-separated module names. The dry-run verifies ecdsa_generic precedes the provider when it is not already resident; ecdh_generic is identified as built in and therefore has no insmod line.",
            "The module's comma-separated softdep from the pinned source was omitted by kmod 34.2 dry-run despite being visible in modinfo/modules.softdep; an explicit space-separated rule resolved correctly. The private build overlay normalizes the delimiter without changing crypto code.",
            "This does not test symbol relocation at load time, provider callbacks, RM, CUDA, or GPU initialization.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True,
                        help="temporary root containing lib/modules/<release>/*.ko")
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--uvm-module-name", choices=sorted(SUPPORTED_UVM_MODULES),
                        default=DEFAULT_UVM_MODULE,
                        help="exact UVM module identity in the candidate set")
    parser.add_argument("--frontend-module-name", choices=sorted(SUPPORTED_FRONTEND_MODULES),
                        default=DEFAULT_FRONTEND_MODULE,
                        help="exact frontend module identity in the candidate set")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build_report(
            args.base, args.kernel_release, args.uvm_module_name, args.frontend_module_name
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        args.output.chmod(0o600)
        print(json.dumps({
            "report": project_path(args.output),
            "qualification": report["qualification"],
            "insert_order": report["modprobe_show_depends"]["insert_order"],
            "module_load_attempted": False,
        }, sort_keys=True))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
