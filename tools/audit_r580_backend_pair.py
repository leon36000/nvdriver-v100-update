#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Statically audit a matched private R580 Open/proprietary backend pair.

This tool reads module ELF metadata, import tables, strings, and Module.symvers
files. It never inserts, removes, or installs a module and never accesses a GPU.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

PINNED_VERSION = "580.178.04"
MODULE_CONTRACT = {
    "open": ("hybrid580_open", "Dual MIT/GPL"),
    "legacy": ("hybrid580_legacy", "NVIDIA"),
}
REQUIRED_IMPORTS = {
    "alloc_chrdev_region",
    "unregister_chrdev_region",
    "cdev_add",
    "cdev_del",
    "proc_create_data",
    "proc_remove",
}
PUBLIC_RESOURCE_LITERALS = {
    "driver/nvidia-nvlink",
    "driver/nvidia-caps",
    "driver/nvidia-nvswitch",
    "driver/nvidia-caps-imex-channels",
}
AMBIGUOUS_LEGACY_LITERALS = {
    "nvidia-nvlink",
    "nvidia-caps",
    "nvidia-nvswitch",
    "nvidia-caps-imex-channels",
}


def _query(argv):
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except FileNotFoundError as exc:
        raise ValueError(f"required inspection tool is unavailable: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"inspection command timed out: {argv[0]}") from exc
    if result.returncode:
        raise ValueError(f"inspection command failed: {argv[0]}: {result.stderr.strip()}")
    return result.stdout


def _open_regular(path):
    path = Path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ValueError(f"cannot safely read regular input: {path}") from exc
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"regular file required: {path}")
    return descriptor


def _descriptor_identity(descriptor, path, require_elf=False):
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"regular file required: {path}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    prefix = os.read(descriptor, 4)
    if require_elf and prefix != b"\x7fELF":
        raise ValueError(f"ELF module required: {path}")
    digest = hashlib.sha256()
    size = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
        size += len(block)
    after = os.fstat(descriptor)
    before_signature = (
        before.st_dev, before.st_ino, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns,
    )
    after_signature = (
        after.st_dev, after.st_ino, after.st_size,
        after.st_mtime_ns, after.st_ctime_ns,
    )
    if size != before.st_size or before_signature != after_signature:
        raise ValueError(f"input changed while reading: {path}")
    return {
        "path": os.path.abspath(path),
        "sha256": digest.hexdigest(),
        "bytes": size,
    }


def inspect_module(path):
    """Inspect a private snapshot bound to the hash of the opened input."""
    source_descriptor = _open_regular(path)
    try:
        identity = _descriptor_identity(source_descriptor, path, require_elf=True)
        with tempfile.TemporaryDirectory(prefix="hybrid-r580-pair-audit-") as temp_dir:
            snapshot_path = Path(temp_dir) / "module.ko"
            snapshot_descriptor = os.open(
                snapshot_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            digest = hashlib.sha256()
            size = 0
            try:
                os.lseek(source_descriptor, 0, os.SEEK_SET)
                while block := os.read(source_descriptor, 1024 * 1024):
                    digest.update(block)
                    size += len(block)
                    view = memoryview(block)
                    while view:
                        written = os.write(snapshot_descriptor, view)
                        view = view[written:]
                os.fsync(snapshot_descriptor)
            finally:
                os.close(snapshot_descriptor)
            copied_identity = {
                "sha256": digest.hexdigest(),
                "bytes": size,
            }
            if copied_identity != {
                "sha256": identity["sha256"],
                "bytes": identity["bytes"],
            } or _descriptor_identity(
                source_descriptor, path, require_elf=True
            ) != identity:
                raise ValueError(f"module changed while snapshotting: {path}")

            snapshot_fd = _open_regular(snapshot_path)
            try:
                snapshot_identity = _descriptor_identity(
                    snapshot_fd, snapshot_path, require_elf=True
                )
                if snapshot_identity["sha256"] != identity["sha256"]:
                    raise ValueError(f"module snapshot hash mismatch: {path}")
                fields = {
                    key: _query(["modinfo", "-F", key, str(snapshot_path)]).strip()
                    for key in (
                        "name", "version", "license", "vermagic", "alias", "parmtype"
                    )
                }
                imports = {
                    line.split()[-1]
                    for line in _query(["nm", "-u", str(snapshot_path)]).splitlines()
                    if line.split()
                }
                strings = {
                    line
                    for line in _query(["strings", "-a", str(snapshot_path)]).splitlines()
                    if line
                }
                if _descriptor_identity(
                    snapshot_fd, snapshot_path, require_elf=True
                ) != snapshot_identity:
                    raise ValueError(f"module snapshot changed during inspection: {path}")
            finally:
                os.close(snapshot_fd)
        return {**identity, **fields, "imports": imports, "strings": strings}
    finally:
        os.close(source_descriptor)


def inspect_symvers(path):
    """Read and hash a Module.symvers file through one no-follow descriptor."""
    descriptor = _open_regular(path)
    try:
        before = os.fstat(descriptor)
        chunks = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        raw = b"".join(chunks)
        if len(raw) != before.st_size or (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        ):
            raise ValueError(f"Module.symvers changed while reading: {path}")
        symbols = parse_symvers(raw.decode("utf-8"))
        identity = {
            "path": os.path.abspath(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        return symbols, identity
    except UnicodeDecodeError as exc:
        raise ValueError(f"Module.symvers is not UTF-8: {path}") from exc
    finally:
        os.close(descriptor)


def parse_symvers(text):
    """Return unique exported symbol names from a Linux Module.symvers file."""
    symbols = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 4 or not re.fullmatch(r"0x[0-9a-fA-F]+", fields[0]):
            raise ValueError(f"malformed Module.symvers record at line {line_number}")
        name = fields[1]
        if name in symbols:
            raise ValueError(f"duplicate Module.symvers export: {name}")
        symbols.add(name)
    if not symbols:
        raise ValueError("Module.symvers contains no exports")
    return symbols


def _module_report(record):
    name = record["name"]
    private_resources = {
        name,
        f"driver/{name}",
        f"{name}-caps",
        f"{name}-nvlink",
        f"{name}-nvswitch",
        f"{name}-caps-imex-channels",
        f"driver/{name}-caps",
        f"driver/{name}-nvlink",
        f"driver/{name}-nvswitch",
    }
    parmtype = set(record["parmtype"].splitlines())
    return {
        key: record[key]
        for key in ("path", "sha256", "bytes", "name", "version", "license", "vermagic")
    } | {
        "autoload_aliases": [item for item in record["alias"].splitlines() if item],
        "pci_selector_parameter_present": "hybrid_gpu_pci:charp" in parmtype,
        "imports_checked": sorted(REQUIRED_IMPORTS & record["imports"]),
        "private_resource_name_markers": sorted(private_resources & record["strings"]),
        "public_conflicting_resource_literals": sorted(
            PUBLIC_RESOURCE_LITERALS & record["strings"]
        ),
        "ambiguous_legacy_literals": sorted(
            AMBIGUOUS_LEGACY_LITERALS & record["strings"]
        ),
    }


def _validate_module(role, record, kernel_release):
    expected_name, expected_license = MODULE_CONTRACT[role]
    if record.get("name") != expected_name:
        raise ValueError(f"{role} module name mismatch: expected {expected_name}")
    if record.get("version") != PINNED_VERSION:
        raise ValueError(f"{role} driver version mismatch: expected {PINNED_VERSION}")
    if record.get("license") != expected_license:
        raise ValueError(f"{role} module license mismatch")
    if record.get("vermagic", "").split()[0:1] != [kernel_release]:
        raise ValueError(f"kernel release mismatch for {role} backend")
    if record.get("alias", "").strip():
        raise ValueError(f"unexpected hardware autoload alias in {role} backend")
    if "hybrid_gpu_pci:charp" not in record.get("parmtype", "").splitlines():
        raise ValueError(f"{role} BDF selector parameter is absent")

    missing_imports = REQUIRED_IMPORTS - record["imports"]
    if missing_imports:
        raise ValueError(
            f"{role} backend lacks required character-device/procfs imports: "
            + ", ".join(sorted(missing_imports))
        )

    name = record["name"]
    required_resources = {
        name,
        f"driver/{name}",
        f"{name}-caps",
        f"{name}-nvlink",
        f"{name}-nvswitch",
        f"{name}-caps-imex-channels",
        f"driver/{name}-caps",
        f"driver/{name}-nvlink",
        f"driver/{name}-nvswitch",
    }
    missing_resources = required_resources - record["strings"]
    if missing_resources:
        raise ValueError(
            f"{role} backend lacks private resource names: "
            + ", ".join(sorted(missing_resources))
        )
    public_resources = PUBLIC_RESOURCE_LITERALS & record["strings"]
    if public_resources:
        raise ValueError(
            f"un-namespaced resource in {role} backend: "
            + ", ".join(sorted(public_resources))
        )


def audit_pair(
    open_module,
    legacy_module,
    open_exports,
    legacy_exports,
    kernel_release,
    symvers_inputs=None,
):
    """Enforce the matched-pair static contract without claiming runtime safety."""
    _validate_module("open", open_module, kernel_release)
    _validate_module("legacy", legacy_module, kernel_release)
    if open_module["name"] == legacy_module["name"]:
        raise ValueError("backend module names are not distinct")
    collisions = sorted(set(open_exports) & set(legacy_exports))
    if collisions:
        raise ValueError("Module.symvers export collision: " + ", ".join(collisions))

    return {
        "schema": "nvidia-hybrid-r580-backend-pair-audit-v2",
        "status": "passed",
        "qualification": "static-only-no-load",
        "kernel_release": kernel_release,
        "driver_version": PINNED_VERSION,
        "modules": {
            "open": _module_report(open_module),
            "legacy": _module_report(legacy_module),
        },
        "exports": {
            "open_count": len(open_exports),
            "legacy_count": len(legacy_exports),
            "collisions": collisions,
        },
        "symvers_inputs": symvers_inputs or {},
        "runtime_validated": False,
        "loaded_or_installed": False,
        "gpu_accessed": False,
        "limitations": [
            "Static metadata and ELF markers only; no kernel insertion or VFS registration was attempted.",
            "Unscoped legacy device-name strings are reported as ambiguous and are not treated as proof of active registration.",
            "Does not prove independent RM/NVLink library semantics, GPU initialization, UVM, or CUDA.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open-module", required=True, type=Path)
    parser.add_argument("--legacy-module", required=True, type=Path)
    parser.add_argument("--open-symvers", required=True, type=Path)
    parser.add_argument("--legacy-symvers", required=True, type=Path)
    parser.add_argument("--kernel-release", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)

    try:
        open_exports, open_symvers = inspect_symvers(args.open_symvers)
        legacy_exports, legacy_symvers = inspect_symvers(args.legacy_symvers)
        report = audit_pair(
            inspect_module(args.open_module),
            inspect_module(args.legacy_module),
            open_exports,
            legacy_exports,
            args.kernel_release,
            {"open": open_symvers, "legacy": legacy_symvers},
        )
        report["observed_at_utc"] = datetime.now(timezone.utc).isoformat()
        serialized = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if args.report:
            descriptor = os.open(
                args.report,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            sys.stdout.write(serialized)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"audit failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
