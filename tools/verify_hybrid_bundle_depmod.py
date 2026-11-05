#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage a hash-pinned module bundle privately and query kmod's load order."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULES = {
    "open": {"name": "hybrid580_open", "filename": "hybrid580_open.ko", "depends": []},
    "legacy": {"name": "hybrid580_legacy", "filename": "hybrid580_legacy.ko", "depends": []},
    "frontend": {
        "name": "nvidia", "filename": "nvidia.ko",
        "depends": ["hybrid580_legacy", "hybrid580_open"],
    },
    "uvm": {"name": "nvidia_uvm", "filename": "nvidia_uvm.ko", "depends": ["nvidia"]},
}
EXPECTED_AUDIT_SCHEMA = "hybrid-module-bundle-static-audit-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    return path.resolve(strict=True)


def _safe_project_destination(path: Path, project_root: Path, subdirectory: str,
                             label: str) -> Path:
    """Keep generated state inside one named project subtree, rejecting symlinks."""
    root = Path(project_root).resolve(strict=True)
    raw = Path(path)
    candidate = raw if raw.is_absolute() else root / raw
    candidate = Path(os.path.abspath(candidate))
    allowed_root = root / subdirectory
    try:
        relative = candidate.relative_to(allowed_root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay inside {allowed_root}: {candidate}") from exc
    current = allowed_root
    if current.exists() and current.is_symlink():
        raise ValueError(f"{label} path contains a symlink: {current}")
    for component in relative.parts:
        current = current / component
        if current.exists() and current.is_symlink():
            raise ValueError(f"{label} path contains a symlink: {current}")
    try:
        candidate.resolve(strict=False).relative_to(allowed_root.resolve(strict=False))
    except ValueError as exc:
        raise ValueError(f"{label} resolves outside {allowed_root}: {candidate}") from exc
    return candidate


def _load_pinned_bundle(audit_report: Path, expected_audit_sha256: str,
                        kernel_release: str) -> tuple[dict, str, dict]:
    report_path = _regular_file(Path(audit_report), "audit report")
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected_audit_sha256 or "") is None:
        raise ValueError("expected audit report SHA-256 must be 64 hexadecimal characters")
    actual_report_hash = sha256_file(report_path)
    if actual_report_hash != expected_audit_sha256.lower():
        raise ValueError(
            f"audit report SHA-256 mismatch: got {actual_report_hash}, "
            f"expected {expected_audit_sha256.lower()}")
    report = json.loads(report_path.read_text())
    if not isinstance(report, dict):
        raise ValueError("audit report must contain a JSON object")
    if report.get("schema") != EXPECTED_AUDIT_SCHEMA or report.get("status") != "passed":
        raise ValueError("audit report must be a passed static module-bundle audit")
    if report.get("runtime_or_hardware_validated") is not False:
        raise ValueError("audit report must preserve its non-runtime qualification")
    modules = report.get("modules")
    if not isinstance(modules, dict) or set(modules) != set(EXPECTED_MODULES):
        raise ValueError("audit report must identify exactly the four expected module roles")

    verified = {}
    for role, expected in EXPECTED_MODULES.items():
        record = modules[role]
        if not isinstance(record, dict):
            raise ValueError(f"audit report module record is invalid: {role}")
        if record.get("name") != expected["name"]:
            raise ValueError(f"unexpected module identity for {role}: {record.get('name')}")
        if sorted(record.get("depends", [])) != sorted(expected["depends"]):
            raise ValueError(f"unexpected module dependencies for {role}")
        if record.get("vermagic", "").split(maxsplit=1)[:1] != [kernel_release]:
            raise ValueError(f"module vermagic does not match {kernel_release}: {role}")
        source = _regular_file(Path(record.get("path", "")), f"{role} module")
        expected_hash = record.get("sha256")
        if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash) is None:
            raise ValueError(f"audit report has no valid module SHA-256: {role}")
        actual_hash = sha256_file(source)
        if actual_hash != expected_hash.lower():
            raise ValueError(
                f"{role} module SHA-256 mismatch: got {actual_hash}, expected {expected_hash.lower()}")
        verified[role] = {
            "source": source,
            "sha256": actual_hash,
            "filename": expected["filename"],
            "name": expected["name"],
        }
    return report, actual_report_hash, verified


def _kmod_name(module_path: str) -> str:
    name = Path(module_path).name
    match = re.fullmatch(r"(.+)\.ko(?:\.(?:zst|xz|gz))?", name)
    if match is None:
        raise ValueError(f"unrecognized kernel module path: {module_path}")
    return match.group(1).replace("-", "_")


def _parse_softdep(value: str) -> dict[str, list[str]]:
    result = {"pre": [], "post": []}
    if not value:
        return result
    current = None
    for token in value.split():
        if token in ("pre:", "post:"):
            current = token[:-1]
            continue
        if current is None:
            raise ValueError(f"malformed module softdep metadata: {value}")
        result[current].extend(item.replace("-", "_")
                               for item in token.split(",") if item)
    if any(len(values) != len(set(values)) for values in result.values()):
        raise ValueError(f"duplicate module in softdep metadata: {value}")
    return result


def _parse_depmod_softdep_metadata(value: str) -> dict[str, dict[str, list[str]]]:
    """Parse depmod output independent of comma or whitespace list formatting."""
    result = {}
    for line in value.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) < 2 or fields[0] != "softdep":
            raise ValueError(f"malformed depmod softdep record: {line}")
        owner = fields[1].replace("-", "_")
        if owner in result:
            raise ValueError(f"duplicate depmod softdep owner: {owner}")
        result[owner] = _parse_softdep(" ".join(fields[2:]))
    return result


def _load_softdep_plan(audit_report: dict, kernel_modules_root: Path,
                       kernel_release: str) -> dict:
    """Resolve module-declared softdeps against one exact kernel module tree."""
    root = Path(kernel_modules_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"kernel modules root must be a real directory: {root}")
    root = root.resolve(strict=True)
    if root.name != kernel_release:
        raise ValueError(
            f"kernel modules root release mismatch: {root.name} != {kernel_release}")
    dep_path = root / "modules.dep"
    builtin_path = root / "modules.builtin"
    for path, label in ((dep_path, "modules.dep"), (builtin_path, "modules.builtin")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"kernel module tree has no safe {label}: {path}")

    modules = {}
    for line_number, line in enumerate(dep_path.read_text().splitlines(), 1):
        relative, separator, raw_dependencies = line.partition(":")
        relative = relative.strip()
        if not separator or not relative:
            raise ValueError(f"malformed kernel modules.dep row {line_number}")
        rel_path = Path(relative)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise ValueError(f"unsafe kernel module path in modules.dep: {relative}")
        name = _kmod_name(relative)
        dependencies = [_kmod_name(item) for item in raw_dependencies.split()]
        record = {"relative_path": rel_path.as_posix(),
                  "dependencies": dependencies}
        if name in modules and modules[name] != record:
            raise ValueError(f"ambiguous kernel module entries for {name}")
        modules[name] = record

    builtins = {}
    for line_number, line in enumerate(builtin_path.read_text().splitlines(), 1):
        relative = line.strip()
        if not relative:
            continue
        rel_path = Path(relative)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise ValueError(f"unsafe kernel built-in path at line {line_number}")
        name = _kmod_name(relative)
        if name in builtins and builtins[name] != rel_path.as_posix():
            raise ValueError(f"ambiguous built-in kernel module entries for {name}")
        builtins[name] = rel_path.as_posix()

    owners = {}
    all_names = set()
    for record in audit_report["modules"].values():
        softdeps = _parse_softdep(record.get("softdep", ""))
        flattened = softdeps["pre"] + softdeps["post"]
        if set(softdeps["pre"]) & set(softdeps["post"]):
            raise ValueError(f"module softdep repeats targets in pre and post: {record['name']}")
        if flattened:
            owners[record["name"]] = softdeps
            all_names.update(flattened)

    support_modules = {}
    selected_builtins = {}
    visited = set()

    def visit(name: str, active: set[str]) -> None:
        if name in active:
            raise ValueError(f"cyclic softdep support-module dependency at {name}")
        if name in visited:
            return
        builtin = builtins.get(name)
        module = modules.get(name)
        if builtin is not None and module is not None:
            raise ValueError(f"softdep support module is both built-in and loadable: {name}")
        if builtin is not None:
            selected_builtins[name] = builtin
            visited.add(name)
            return
        if module is None:
            raise ValueError(f"softdep target is unavailable in {root}: {name}")
        support_modules[name] = module
        active.add(name)
        for dependency in module["dependencies"]:
            visit(dependency, active)
        active.remove(name)
        visited.add(name)

    for name in sorted(all_names):
        visit(name, set())

    return {
        "kernel_modules_root": root,
        "owners": owners,
        "support_modules": support_modules,
        "builtins": selected_builtins,
    }


def _parse_show_depends(stdout: str, stage_root: Path, expected: set[str], label: str,
                        target_filename: str | None = None,
                        known_builtins: set[str] | None = None,
                        optional_modules: set[str] | None = None) -> dict[str, list[str]]:
    actual = []
    actual_builtins = []
    known_builtins = known_builtins or set()
    stage = stage_root.resolve(strict=True)
    for raw_line in stdout.splitlines():
        if not raw_line.strip():
            continue
        fields = shlex.split(raw_line)
        if fields and fields[0] == "builtin":
            if len(fields) != 2:
                raise ValueError(
                    f"unexpected builtin record in modprobe --show-depends for {label}: {raw_line}")
            name = fields[1].replace("-", "_")
            if re.fullmatch(r"[A-Za-z0-9_]+", name) is None or name not in known_builtins:
                raise ValueError(
                    f"modprobe resolved an unverified builtin for {label}: {raw_line}")
            actual_builtins.append(name)
            continue
        if len(fields) < 2 or fields[0] != "insmod":
            raise ValueError(f"unexpected modprobe --show-depends output for {label}: {raw_line}")
        module_path = Path(fields[1]).resolve(strict=True)
        try:
            module_path.relative_to(stage)
        except ValueError as exc:
            raise ValueError(f"modprobe resolved outside isolated stage: {module_path}") from exc
        if re.search(r"\.ko(?:\.(?:zst|xz|gz))?$", module_path.name) is None:
            raise ValueError(f"unexpected module path in kmod output: {module_path}")
        actual.append(module_path.name)
    actual_set = set(actual)
    missing = expected - actual_set
    allowed = expected | (optional_modules or set())
    unexpected = actual_set - allowed
    if (len(actual) != len(actual_set)
            or len(actual_builtins) != len(set(actual_builtins))
            or missing or unexpected):
        raise ValueError(
            f"kmod dependency set mismatch for {label}: got modules={actual}, "
            f"builtins={actual_builtins}, missing modules={sorted(missing)}, "
            f"unexpected modules={sorted(unexpected)}")
    if not actual or actual[-1] != target_filename:
        raise ValueError(f"kmod placed the requested module before its providers for {label}: {actual}")
    return {"modules": actual, "builtins": actual_builtins}


def stage_hybrid_bundle(*, audit_report: Path, expected_audit_sha256: str,
                        kernel_release: str, output_parent: Path,
                        report_path: Path, project_root: Path = ROOT,
                        kernel_modules_root: Path | None = None,
                        command_runner=subprocess.run) -> dict:
    """Stage the bundle and its declared softdep closure without loading modules."""
    pinned_report, audit_hash, modules = _load_pinned_bundle(
        audit_report, expected_audit_sha256, kernel_release)
    if kernel_modules_root is None:
        kernel_modules_root = Path("/lib/modules") / kernel_release
    softdep_plan = _load_softdep_plan(
        pinned_report, kernel_modules_root, kernel_release)
    output_parent = _safe_project_destination(
        output_parent, project_root, "build/experiments", "stage directory")
    report_path = _safe_project_destination(
        report_path, project_root, "evidence", "report path")
    if report_path.exists() or report_path.is_symlink():
        raise ValueError(f"refusing to overwrite report: {report_path}")

    output_parent.mkdir(parents=True, exist_ok=True)
    stage_root = Path(tempfile.mkdtemp(prefix="hybrid-bundle-depmod-", dir=output_parent))
    module_dir = stage_root / "lib/modules" / kernel_release / "updates/extra"
    module_dir.mkdir(parents=True)
    base = stage_root / "lib/modules" / kernel_release

    staged_modules = {}
    for role, record in modules.items():
        destination = module_dir / record["filename"]
        destination.write_bytes(record["source"].read_bytes())
        os.chmod(destination, 0o600)
        staged_hash = sha256_file(destination)
        if staged_hash != record["sha256"]:
            raise ValueError(f"staged module hash changed while copying: {role}")
        staged_modules[role] = {
            "name": record["name"],
            "staged_name": record["filename"],
            "sha256": staged_hash,
            "size_bytes": destination.stat().st_size,
        }

    staged_support_modules = {}
    for name, record in sorted(softdep_plan["support_modules"].items()):
        relative = Path(record["relative_path"])
        source = softdep_plan["kernel_modules_root"] / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"softdep source must be a regular non-symlink file: {source}")
        current = softdep_plan["kernel_modules_root"]
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError(f"softdep source path contains a symlink: {current}")
        destination = base / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        staged_support_modules[name] = {
            "relative_path": relative.as_posix(),
            "sha256": sha256_file(destination),
            "size_bytes": destination.stat().st_size,
        }

    # Supplying the normal metadata files keeps depmod warnings about a partial,
    # intentionally isolated module tree out of the result.
    ordered_paths = [
        f"updates/extra/{modules[role]['filename']}\n"
        for role in ("open", "legacy", "frontend", "uvm")]
    ordered_paths.extend(
        f"{record['relative_path']}\n"
        for _, record in sorted(softdep_plan["support_modules"].items()))
    (base / "modules.order").write_text("".join(ordered_paths))
    (base / "modules.builtin").write_text("".join(
        f"{relative}\n" for _, relative in sorted(softdep_plan["builtins"].items())))
    (base / "modules.builtin.modinfo").write_text("")
    for metadata in (base / "modules.order", base / "modules.builtin", base / "modules.builtin.modinfo"):
        os.chmod(metadata, 0o600)

    depmod_command = ["depmod", "-b", str(stage_root), kernel_release]
    depmod = command_runner(depmod_command, capture_output=True, text=True, check=False)
    if depmod.returncode:
        raise RuntimeError(f"isolated depmod failed ({depmod.returncode}): {depmod.stderr.strip()}")
    modules_dep = base / "modules.dep"
    if not modules_dep.is_file():
        raise RuntimeError("isolated depmod did not produce modules.dep")

    modules_softdep = base / "modules.softdep"
    if not modules_softdep.is_file():
        raise RuntimeError("isolated depmod did not produce modules.softdep")
    softdep_text = modules_softdep.read_text()
    actual_softdep_records = _parse_depmod_softdep_metadata(softdep_text)
    expected_softdep_lines = {}
    for owner, softdeps in softdep_plan["owners"].items():
        actual = actual_softdep_records.pop(owner, None)
        if actual != softdeps:
            raise RuntimeError(f"depmod softdep metadata differs for {owner}: {actual!r}")
        fields = ["softdep", owner]
        for relation in ("pre", "post"):
            if softdeps[relation]:
                fields.extend((f"{relation}:", ",".join(softdeps[relation])))
        expected_line = " ".join(fields)
        expected_softdep_lines[owner] = expected_line
    if actual_softdep_records:
        raise RuntimeError(
            "depmod produced unexpected softdep owners: "
            + ", ".join(sorted(actual_softdep_records)))

    staged_module_names = set()
    for line in modules_dep.read_text().splitlines():
        relative = line.partition(":")[0].strip()
        if relative:
            staged_module_names.add(_kmod_name(relative))
    staged_builtin_names = {
        _kmod_name(line.strip()) for line in (base / "modules.builtin").read_text().splitlines()
        if line.strip()
    }
    for softdeps in softdep_plan["owners"].values():
        for name in softdeps["pre"] + softdeps["post"]:
            if name not in staged_module_names and name not in staged_builtin_names:
                raise RuntimeError(f"depmod could not resolve softdep target: {name}")

    resolution = {}
    # The selected kmod's --show-depends output contains only the hard graph,
    # even though modules.softdep names a loadable pre-softdep. Permit that
    # verified closure if another kmod release includes it, and validate every
    # softdep target with its own query below.
    expected_frontend_order = {
        "hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko",
    }
    expected_orders = {
        "nvidia": expected_frontend_order,
        "nvidia_uvm": expected_frontend_order | {"nvidia_uvm.ko"},
    }

    def add_support_closure(name: str, expected: set[str], visited: set[str]) -> None:
        if name in visited or name in softdep_plan["builtins"]:
            return
        visited.add(name)
        record = softdep_plan["support_modules"].get(name)
        if record is None:
            return
        expected.add(Path(record["relative_path"]).name)
        for dependency in record["dependencies"]:
            add_support_closure(dependency, expected, visited)

    for target, expected in expected_orders.items():
        expected = set(expected)
        expected_owners = {Path(filename).stem.replace("-", "_")
                           for filename in expected}
        optional_modules = set()
        visited_softdeps = set()
        for owner, softdeps in softdep_plan["owners"].items():
            if owner in expected_owners:
                for name in softdeps["pre"]:
                    add_support_closure(name, optional_modules, visited_softdeps)
        command = [
            "modprobe", "-C", "/dev/null", "-d", str(stage_root),
            "--set-version", kernel_release, "--show-depends", target,
        ]
        result = command_runner(command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise RuntimeError(
                f"isolated modprobe dependency query failed for {target} "
                f"({result.returncode}): {result.stderr.strip()}")
        parsed = _parse_show_depends(
            result.stdout, stage_root, expected, target,
            "nvidia.ko" if target == "nvidia" else "nvidia_uvm.ko",
            known_builtins=staged_builtin_names,
            optional_modules=optional_modules)
        resolution[target] = {
            "command": command,
            "ordered_modules": parsed["modules"],
            "builtin_modules": parsed["builtins"],
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    support_resolution = {}
    for owner, softdeps in softdep_plan["owners"].items():
        for relation in ("pre", "post"):
            for name in softdeps[relation]:
                if name in softdep_plan["builtins"]:
                    support_resolution[name] = {
                        "kind": "kernel-builtin",
                        "relative_path": softdep_plan["builtins"][name],
                        "resolved": True,
                    }
                    continue
                record = softdep_plan["support_modules"][name]
                command = [
                    "modprobe", "-C", "/dev/null", "-d", str(stage_root),
                    "--set-version", kernel_release, "--show-depends", name,
                ]
                result = command_runner(command, capture_output=True, text=True, check=False)
                if result.returncode:
                    raise RuntimeError(
                        f"isolated modprobe softdep query failed for {name} "
                        f"({result.returncode}): {result.stderr.strip()}")
                expected_support = set()

                def add_independent_support_closure(current: str) -> None:
                    item = softdep_plan["support_modules"][current]
                    expected_support.add(Path(item["relative_path"]).name)
                    for dependency in item["dependencies"]:
                        if dependency in softdep_plan["support_modules"]:
                            add_independent_support_closure(dependency)

                add_independent_support_closure(name)
                parsed_support = _parse_show_depends(
                    result.stdout, stage_root, expected_support,
                    f"softdep:{name}", Path(record["relative_path"]).name,
                    known_builtins=staged_builtin_names)
                support_resolution[name] = {
                    "kind": "loadable-module",
                    "relative_path": record["relative_path"],
                    "sha256": staged_support_modules[name]["sha256"],
                    "command": command,
                    "ordered_modules": parsed_support["modules"],
                    "builtin_modules": parsed_support["builtins"],
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

    result = {
        "schema": "hybrid-module-bundle-depmod-static-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "qualification": "isolated-dependency-map-only",
        "kernel_release": kernel_release,
        "audit_report": str(Path(audit_report).resolve(strict=True)),
        "audit_report_sha256": audit_hash,
        "audit_report_status": pinned_report["status"],
        "stage_root": str(stage_root.resolve(strict=True)),
        "stage_parent": str(output_parent.resolve(strict=True)),
        "depmod": {
            "command": depmod_command,
            "exit_code": depmod.returncode,
            "stdout": depmod.stdout,
            "stderr": depmod.stderr,
            "modules_dep_sha256": sha256_file(modules_dep),
            "modules_dep": modules_dep.read_text(),
            "modules_softdep_sha256": sha256_file(modules_softdep),
            "modules_softdep": softdep_text,
        },
        "modules": staged_modules,
        "soft_dependency_resolution": {
            "kernel_modules_root": str(softdep_plan["kernel_modules_root"]),
            "owners": softdep_plan["owners"],
            "expected_modules_softdep_lines": expected_softdep_lines,
            "builtins": softdep_plan["builtins"],
            "support_modules": staged_support_modules,
            "resolved_targets": support_resolution,
        },
        "resolution": resolution,
        "loaded_or_installed": False,
        "runtime_or_hardware_validated": False,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    os.chmod(report_path, 0o600)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-report", type=Path, required=True)
    parser.add_argument("--expected-audit-sha256", required=True)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--kernel-modules-root", type=Path)
    parser.add_argument("--output-parent", type=Path, default=ROOT / "build/experiments")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = stage_hybrid_bundle(
            audit_report=args.audit_report,
            expected_audit_sha256=args.expected_audit_sha256,
            kernel_release=args.kernel_release,
            output_parent=args.output_parent,
            report_path=args.report,
            kernel_modules_root=args.kernel_modules_root,
            project_root=ROOT,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"verify_hybrid_bundle_depmod: error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": result["status"],
        "qualification": result["qualification"],
        "stage_root": result["stage_root"],
        "report": str(args.report),
        "resolution": {
            target: entry["ordered_modules"]
            for target, entry in result["resolution"].items()
        },
        "soft_dependency_targets": {
            name: record["kind"]
            for name, record in result["soft_dependency_resolution"][
                "resolved_targets"].items()
        },
        "loaded_or_installed": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
