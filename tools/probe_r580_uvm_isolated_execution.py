#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the opt-in R580 UVM prototype from a clean, pinned source archive.

The probe never installs or loads a module. It securely extracts the pinned
R580 source archive, verifies the UVM inputs, applies the patches without fuzz,
and builds either the normal nvidia+nvidia-uvm pair or a UVM-only consumer
bound to a supplied hybrid frontend. Optional additional patches are applied
after the pinned baseline overlays and recorded in the build report.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import subprocess
import sys
import stat
import tarfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.audit_uvm_owner_isolation_architecture import (  # noqa: E402
    EXPECTED_ARCHIVE_SHA256,
    EXPECTED_SOURCE_SHA256,
    SOURCE_ARCHIVE,
    SOURCE_TAG,
    sha256_file,
)
from tools.build_hybrid_frontend import (  # noqa: E402
    extract_extended_modversions,
    extract_kernel_modversions_section,
)

PATCHES = (
    ROOT / "patches/r580.178.04/uvm/0002-hybrid-isolated-gpu-execution.patch",
    ROOT / "patches/r580.178.04/uvm/0003-pass-control-fd-to-dup-memory.patch",
    ROOT / "patches/r580.178.04/uvm/0004-share-linux-conftests-with-uvm-consumer.patch",
    ROOT / "patches/r580.178.04/uvm/0005-pass-control-fd-to-dup-address-space.patch",
    ROOT / "patches/r580.178.04/uvm/0006-pin-control-file-before-va-space-registration.patch",
    ROOT / "patches/r580.178.04/uvm/0007-reject-cross-gpu-tracker-dependencies.patch",
    ROOT / "patches/r580.178.04/uvm/0008-pmm-allocation-outside-va-block-lock.patch",
    ROOT / "patches/r580.178.04/uvm/0009-reject-hmm-gpu-migration-in-isolated-mode.patch",
    ROOT / "patches/r580.178.04/uvm/0010-reject-unsupported-isolated-staged-migrations.patch",
    ROOT / "patches/r580.178.04/uvm/0011-preflight-unsupported-staging-before-unmap.patch",
    ROOT / "patches/r580.178.04/uvm/0012-exact-isolated-staged-page-mask.patch",
    ROOT / "patches/r580.178.04/uvm/0013-reject-foreign-pmm-trackers-in-isolated-mode.patch",
    ROOT / "patches/r580.178.04/uvm/0014-reject-foreign-pmm-trackers-before-eviction.patch",
)
# Compatibility alias for callers that inspect the original isolation patch.
PATCH = PATCHES[0]
SUPPORTED_FRONTEND_MODULES = {"hybrid580_frontend", "nvidia"}
FRONTEND_ONLY_PATCH_NAMES = frozenset({
    "0005-pass-control-fd-to-dup-address-space.patch",
    "0006-pin-control-file-before-va-space-registration.patch",
})
OWNER_NAMESPACE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
CHARDEV_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
PROBE_SOURCE_SHA256 = dict(EXPECTED_SOURCE_SHA256)
# The audit's separately patched private-provider tree has a local R580 edit
# in this source file. The source archive used by the clean UVM build probe is
# pinned independently and contains the upstream bytes below.
PROBE_SOURCE_SHA256["nv_uvm_interface.c"] = (
    "b41c704d29363dd52dd0ea669ee253a37185f5826c7db56a07dec21c3d24eddc"
)
PROBE_SOURCE_SHA256["nvidia.Kbuild"] = (
    "adee2cdb65f387611e2816d91beb4c3ce3a45f648831d8b1e79a2564b160f406"
)


def kernel_extended_modversions_enabled(config_path: Path) -> bool:
    """Select the ELF modversion representation from the target kernel config."""
    config = Path(config_path).read_text(errors="strict")
    if re.search(r"^CONFIG_EXTENDED_MODVERSIONS=y$", config, re.MULTILINE):
        return True
    if (re.search(r"^# CONFIG_EXTENDED_MODVERSIONS is not set$", config, re.MULTILINE)
            or re.search(r"^CONFIG_EXTENDED_MODVERSIONS=n$", config, re.MULTILINE)):
        return False
    # Kernels predating CONFIG_EXTENDED_MODVERSIONS use compact __versions.
    return False
SOURCE_LABELS = {
    "common/inc/nv_uvm_interface.h": "nv_uvm_interface.h",
    "nvidia/nvidia.Kbuild": "nvidia.Kbuild",
    "nvidia-uvm/nvidia-uvm.Kbuild": "nvidia-uvm.Kbuild",
    "nvidia/nv_uvm_interface.c": "nv_uvm_interface.c",
    "nvidia-uvm/uvm_gpu.c": "uvm_gpu.c",
    "nvidia-uvm/uvm_gpu_semaphore.c": "uvm_gpu_semaphore.c",
    "nvidia-uvm/uvm_push.c": "uvm_push.c",
    "nvidia-uvm/uvm_migrate_pageable.c": "uvm_migrate_pageable.c",
    "nvidia-uvm/uvm_channel_test.c": "uvm_channel_test.c",
    "nvidia-uvm/uvm_map_external.c": "uvm_map_external.c",
}

R580_196_SOURCE_SHA256 = {
    "nv_uvm_interface.h": "68b6cae62ad0bdf6940d48a34084d789cd1f87a06b84310195cd2adc4b9e50f8",
    "nvidia.Kbuild": "b1bc451a2fd2b1abd68608fa7156e86472f5ec414764d712727ed0463feaea5e",
    "nvidia-uvm.Kbuild": "0e8d3d96e00d6ca8b6b564e4668dd70447d8b6bca9200845180ce7c66902328b",
    "nv_uvm_interface.c": "b41c704d29363dd52dd0ea669ee253a37185f5826c7db56a07dec21c3d24eddc",
    "uvm_gpu.c": "b43bb94bbc465bbb4fb243e6f722cb450d6402f3071971843d61f1f7678bf700",
    "uvm_gpu_semaphore.c": "1472d3bdcd91b35095fb7ae6aa1f66a075ea495c08d106ed7da497176a3d629f",
    "uvm_push.c": "9628ada0b4007eff5af16525d0d71788045832e5ca268699e2ae82a5dc14b85e",
    "uvm_migrate_pageable.c": "e7178513d684596aadbe24c1f699eb9e7b13b7f39c19805fe213bbef090898da",
    "uvm_channel_test.c": "f846b5e2925258bb1643e389bee4016743a73a6f396571e0621aac109bb94e87",
    "uvm_map_external.c": "4115e9f2de1fc9ad460a61168e78e68ede19c57ac6216740dc57475b29d07511",
}
R580_196_SOURCE_ARCHIVE = (
    ROOT / "build/experiments/private-open580-native-19607-v1-20261024"
    / "inputs/open580-580.196.07.tar.xz"
)
R580_196_SOURCE_ARCHIVE_SHA256 = (
    "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"
)
R580_196_KBUILD_PATCH = (
    ROOT / "patches/r580.196.07/uvm/"
    "0001-share-linux-conftests-with-uvm-consumer.patch"
)
SOURCE_PROFILES = {
    "580.178.04": {
        "archive": SOURCE_ARCHIVE,
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "source_hashes": PROBE_SOURCE_SHA256,
        "kbuild_patch": PATCHES[2],
    },
    "580.196.07": {
        "archive": R580_196_SOURCE_ARCHIVE,
        "archive_sha256": R580_196_SOURCE_ARCHIVE_SHA256,
        "source_hashes": R580_196_SOURCE_SHA256,
        "kbuild_patch": R580_196_KBUILD_PATCH,
    },
}


def _patches_for_build(
    frontend_module_symvers: Path | None,
    source_version: str = SOURCE_TAG,
) -> tuple[Path, ...]:
    """Choose overlays whose imported dispatch APIs have a matching provider."""
    if source_version not in SOURCE_PROFILES:
        raise ValueError(f"unsupported R580 source profile: {source_version}")
    profile = SOURCE_PROFILES[source_version]
    patches = list(PATCHES)
    patches[2] = profile["kbuild_patch"]
    if frontend_module_symvers is not None:
        return tuple(patches)
    return tuple(path for path in patches if path.name not in FRONTEND_ONLY_PATCH_NAMES)


def project_path(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def _write_new_private(path: Path, payload: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)


def _write_json_new(path: Path, report: dict[str, Any]) -> None:
    _write_new_private(
        path,
        (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def apply_owner_namespace(
    source_root: Path,
    owner_namespace: str,
    *,
    chardev_name: str | None = None,
) -> dict[str, str]:
    """Give one R580 UVM build a private owner and selectable chardev label.

    The chardev label is passed to alloc_chrdev_region; it is not a node path.
    Keeping it as nvidia-uvm lets the matching NVIDIA userspace discover the
    expected UVM major when this provider is the sole owner of that label.
    """
    if (not isinstance(owner_namespace, str) or
            not OWNER_NAMESPACE_PATTERN.fullmatch(owner_namespace) or
            owner_namespace == "nvidia"):
        raise ValueError("invalid UVM owner namespace")
    if chardev_name is not None and (
            not isinstance(chardev_name, str) or
            not CHARDEV_NAME_PATTERN.fullmatch(chardev_name)):
        raise ValueError("invalid character-device name")

    source_root = Path(source_root)
    module_stem = f"{owner_namespace}-uvm"
    device_name = chardev_name or module_stem
    log_name = module_stem
    procfs_path = f"driver/{module_stem}"
    replacements = {
        source_root / "nvidia-uvm/nvidia-uvm.Kbuild": (
            ("obj-m += nvidia-uvm.o", f"obj-m += {module_stem}.o"),
            ("nvidia-uvm-y := $(NVIDIA_UVM_OBJECTS)",
             f"{module_stem}-y := $(NVIDIA_UVM_OBJECTS)"),
            ("NVIDIA_UVM_KO = nvidia-uvm/nvidia-uvm.ko",
             f"NVIDIA_UVM_KO = nvidia-uvm/{module_stem}.ko"),
        ),
        source_root / "nvidia-uvm/uvm.c": (
            ('#define NVIDIA_UVM_DEVICE_NAME          "nvidia-uvm"',
             f'#define NVIDIA_UVM_DEVICE_NAME          "{device_name}"'),
        ),
        source_root / "nvidia-uvm/uvm_procfs.c": (
            ('#define UVM_PROC_DIR_NAME "driver/nvidia-uvm"',
             f'#define UVM_PROC_DIR_NAME "{procfs_path}"'),
        ),
        source_root / "nvidia-uvm/uvm_linux.h": (
            ('#define NVIDIA_UVM_PRETTY_PRINTING_PREFIX "nvidia-uvm: "',
             f'#define NVIDIA_UVM_PRETTY_PRINTING_PREFIX "{log_name}: "'),
        ),
    }
    rewritten = {}
    for path, edits in replacements.items():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"owner namespace source is not a regular file: {path.name}")
        text = path.read_text(encoding="utf-8")
        for old, new in edits:
            if text.count(old) != 1:
                raise ValueError(f"owner namespace source contract must occur exactly once: {path.name}")
            text = text.replace(old, new, 1)
        rewritten[path] = text
    for path, text in rewritten.items():
        path.write_text(text, encoding="utf-8")

    return {
        "module_filename": f"{module_stem}.ko",
        "module_name": module_stem.replace("-", "_"),
        "device_name": device_name,
        "chardev_registration_name": device_name,
        "log_prefix": f"{log_name}: ",
        "procfs_path": procfs_path,
    }


def _ensure_no_escaping_symlinks(root: Path) -> None:
    root = root.resolve(strict=True)
    for path in root.rglob("*"):
        if not path.is_symlink():
            continue
        target = path.resolve(strict=True)
        try:
            target.relative_to(root)
        except ValueError:
            raise ValueError(f"source package symlink escapes its root: {path}") from None


def _validated_archive_members(
    archive: tarfile.TarFile,
    source_tag: str = SOURCE_TAG,
) -> list[tarfile.TarInfo]:
    """Accept only unique regular files and directories below the pinned root."""
    package_name = f"NVIDIA-kernel-module-source-{source_tag}"
    members = archive.getmembers()
    if not members:
        raise ValueError("the pinned R580 source archive is empty")

    seen: set[str] = set()
    files: set[str] = set()
    for member in members:
        name = member.name
        path = PurePosixPath(name)
        parts = path.parts
        if (path.is_absolute() or len(parts) < 2 or parts[0] != package_name or
                any(part in ("", ".", "..") for part in parts) or "\\" in name):
            raise ValueError(f"unsafe archive path: {name!r}")
        normalized = path.as_posix()
        if normalized != name.rstrip("/"):
            raise ValueError(f"unsafe archive path: {name!r}")
        if normalized in seen:
            raise ValueError(f"duplicate archive path: {name!r}")
        if not (member.isfile() or member.isdir()):
            raise ValueError(f"non-regular archive member: {name!r}")
        if member.size < 0 or (member.isdir() and member.size != 0):
            raise ValueError(f"invalid archive member size: {name!r}")

        parents = [PurePosixPath(*parts[:index]).as_posix()
                   for index in range(1, len(parts))]
        if any(parent in files for parent in parents):
            raise ValueError(f"archive member is below a regular file: {name!r}")
        if member.isfile() and any(existing.startswith(normalized + "/") for existing in seen):
            raise ValueError(f"regular archive member shadows a directory: {name!r}")
        seen.add(normalized)
        if member.isfile():
            files.add(normalized)

    return members


def extract_source_archive(
    archive_path: Path,
    destination: Path,
    expected_sha256: str | None = None,
    source_tag: str = SOURCE_TAG,
) -> Path:
    """Extract the exact hashed archive snapshot without following links."""
    archive_path = Path(archive_path)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"fresh extraction destination already exists: {destination}")

    archive_fd = os.open(
        archive_path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    with os.fdopen(archive_fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("pinned source archive is not a regular file")
        archive_bytes = stream.read()
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    if expected_sha256 is not None and archive_sha256 != expected_sha256:
        raise ValueError(f"archive SHA-256 mismatch: {archive_sha256}")

    package_root = destination / f"NVIDIA-kernel-module-source-{source_tag}"
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
        members = _validated_archive_members(archive, source_tag=source_tag)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)
        package_root.mkdir(mode=0o700)
        for member in members:
            relative_parts = PurePosixPath(member.name).parts[1:]
            target = package_root.joinpath(*relative_parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue

            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, member.mode & 0o777)
            source = archive.extractfile(member)
            if source is None:
                os.close(fd)
                raise ValueError(f"cannot read regular archive member: {member.name!r}")
            copied = 0
            with source, os.fdopen(fd, "wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
                    copied += len(chunk)
            if copied != member.size:
                raise ValueError(f"truncated archive member: {member.name!r}")
            os.chmod(target, member.mode & 0o777)

    return package_root


def _verified_source_hashes(
    kernel_open_root: Path,
    expected_hashes: dict[str, str] | None = None,
) -> dict[str, str]:
    expected_hashes = PROBE_SOURCE_SHA256 if expected_hashes is None else expected_hashes
    hashes: dict[str, str] = {}
    for relative, label in SOURCE_LABELS.items():
        path = Path(kernel_open_root) / relative
        actual = sha256_file(path)
        if actual != expected_hashes[label]:
            raise ValueError(f"pinned UVM source changed: {relative} ({actual})")
        hashes[relative] = actual
    return hashes


def _read_regular_file_snapshot(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(Path(path), flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"expected regular file: {path}")
        payload = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            payload.extend(chunk)
        after = os.fstat(descriptor)
        before_state = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        )
        after_state = (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        )
        if before_state != after_state or len(payload) != after.st_size:
            raise ValueError(f"file changed while being read: {path}")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _build_command(
    source_package: Path,
    kernel_release: str,
    jobs: int,
    frontend_module_symvers: Path | None = None,
) -> list[str]:
    command = [
        "make",
        "-C", str(source_package),
        f"KERNEL_UNAME={kernel_release}",
        "NV_KERNEL_MODULES=nvidia-uvm" if frontend_module_symvers else
        "NV_KERNEL_MODULES=nvidia nvidia-uvm",
        "NV_VERBOSE=1",
    ]
    if frontend_module_symvers is not None:
        command.append(f"KBUILD_EXTRA_SYMBOLS={Path(frontend_module_symvers).resolve()}")
    command.extend(("modules", "-j", str(jobs)))
    return command


def _verify_frontend_consumer_binding(
    module_versions: dict[str, str],
    symvers_text: str,
    depends_text: str,
    *,
    frontend_module_name: str = "hybrid580_frontend",
    module_version_source: str = "ELF __versions compact-record parser",
) -> dict[str, Any]:
    if frontend_module_name not in SUPPORTED_FRONTEND_MODULES:
        raise ValueError("unsupported frontend module identity")
    exports = {}
    for line in symvers_text.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            exports[fields[1]] = {
                "crc": fields[0].lower(), "module": fields[2], "export": fields[3]
            }
    imports = {
        name: crc.lower()
        for name, crc in module_versions.items()
        if name.startswith("nvUvmInterface")
    }
    def owner_matches(owner: str) -> bool:
        if owner == frontend_module_name:
            return True
        # External Kbuild's Module.symvers records the target object path
        # (e.g. /tmp/build/nvidia), while modinfo records the normalized module
        # identity. Accept that path only when its final component is exact.
        pure = PurePosixPath(owner)
        return (pure.name == frontend_module_name and
                all(part not in (".", "..") for part in pure.parts if part != "/"))

    mismatches = {
        name: {"import_crc": crc, "frontend_export": exports.get(name)}
        for name, crc in imports.items()
        if (name not in exports or exports[name]["crc"] != crc or
                exports[name]["export"] != "EXPORT_SYMBOL" or
                not owner_matches(exports[name]["module"]))
    }
    dependencies = sorted({name for name in depends_text.strip().split(",") if name})
    frontend_is_only_provider_dependency = dependencies == [frontend_module_name]
    return {
        "frontend_module_name": frontend_module_name,
        "module_dependencies": dependencies,
        "uvm_interface_import_count": len(imports),
        "matching_frontend_crc_count": len(imports) - len(mismatches),
        "mismatched_symbols": mismatches,
        "module_version_source": module_version_source,
        "frontend_is_only_provider_dependency": frontend_is_only_provider_dependency,
        "passed": bool(imports) and not mismatches and frontend_is_only_provider_dependency,
    }


def _apply_patch_overlays(source_root: Path, patches: tuple[Path, ...]) -> list[dict[str, Any]]:
    """Apply ordered patch overlays without fuzz and return reproducible evidence."""
    artifacts = []
    for patch_path in patches:
        patch_path = Path(patch_path)
        if patch_path.is_symlink():
            raise ValueError(f"patch must not be a symlink: {patch_path}")
        if not patch_path.is_file():
            raise ValueError(f"patch must be a regular file: {patch_path}")
        patch_path = patch_path.resolve(strict=True)
        patch_command = [
            "patch", "--batch", "--fuzz=0", "--forward", "-p1",
            "-i", str(patch_path),
        ]
        applied = subprocess.run(
            patch_command,
            cwd=source_root,
            text=True,
            capture_output=True,
            check=False,
        )
        if applied.returncode != 0:
            raise RuntimeError(
                f"patch did not apply cleanly ({patch_path.name}): " +
                applied.stdout + applied.stderr
            )
        artifacts.append({
            "path": project_path(patch_path),
            "sha256": sha256_file(patch_path),
            "apply_command": patch_command,
            "apply_output": applied.stdout,
        })
    return artifacts


def build_probe(
    scratch: Path,
    report_path: Path,
    log_path: Path,
    kernel_release: str,
    jobs: int,
    frontend_module_symvers: Path | None = None,
    expected_frontend_symvers_sha256: str | None = None,
    owner_namespace: str | None = None,
    chardev_name: str | None = None,
    extra_patches: tuple[Path, ...] = (),
    frontend_module_name: str = "hybrid580_frontend",
    source_version: str = SOURCE_TAG,
) -> dict[str, Any]:
    scratch = Path(scratch)
    report_path = Path(report_path)
    log_path = Path(log_path)
    if chardev_name is not None and owner_namespace is None:
        raise ValueError("--chardev-name requires --owner-namespace")
    if frontend_module_name not in SUPPORTED_FRONTEND_MODULES:
        raise ValueError("unsupported frontend module identity")
    if source_version not in SOURCE_PROFILES:
        raise ValueError(f"unsupported R580 source profile: {source_version}")
    source_profile = SOURCE_PROFILES[source_version]
    source_archive = Path(source_profile["archive"])
    source_archive_sha256 = str(source_profile["archive_sha256"])
    source_hashes_expected = dict(source_profile["source_hashes"])
    all_patches = (
        *_patches_for_build(frontend_module_symvers, source_version),
        *tuple(extra_patches),
    )
    for path, label in [*((patch, "patch") for patch in all_patches),
                        (source_archive, "source archive")]:
        if path.is_symlink():
            raise ValueError(f"{label} must not be a symlink")
    if any(not patch.is_file() for patch in all_patches):
        raise ValueError("an isolated-execution/control-fd/Kbuild/additional UVM patch is missing")
    if jobs < 1 or not kernel_release:
        raise ValueError("jobs and kernel release must be valid")
    kernel_config = Path("/lib/modules", kernel_release, "build", ".config").resolve(strict=True)
    if not kernel_config.is_file():
        raise ValueError("target kernel config is not a regular file")
    kernel_config_sha256 = sha256_file(kernel_config)
    if (frontend_module_symvers is None) != (expected_frontend_symvers_sha256 is None):
        raise ValueError("frontend Module.symvers path and expected SHA-256 must be supplied together")
    frontend_symvers_bytes = None
    frontend_symvers_record = None
    if frontend_module_symvers is not None:
        frontend_module_symvers = Path(frontend_module_symvers)
        if frontend_module_symvers.is_symlink():
            raise ValueError("frontend Module.symvers must not be a symlink")
        frontend_symvers_bytes = _read_regular_file_snapshot(frontend_module_symvers)
        frontend_symvers_sha256 = hashlib.sha256(frontend_symvers_bytes).hexdigest()
        if frontend_symvers_sha256 != expected_frontend_symvers_sha256:
            raise ValueError("frontend Module.symvers differs from the pinned input")
        frontend_symvers_record = {
            "path": str(frontend_module_symvers.resolve()),
            "sha256": frontend_symvers_sha256,
        }
    if scratch.exists() or scratch.is_symlink():
        raise FileExistsError(f"scratch destination already exists: {scratch}")
    if report_path.exists() or report_path.is_symlink():
        raise FileExistsError(f"report destination already exists: {report_path}")
    if log_path.exists() or log_path.is_symlink():
        raise FileExistsError(f"log destination already exists: {log_path}")
    scratch = scratch.resolve()
    report_path = report_path.resolve()
    log_path = log_path.resolve()

    copied_root = extract_source_archive(
        source_archive,
        scratch,
        expected_sha256=source_archive_sha256,
        source_tag=source_version,
    )
    _ensure_no_escaping_symlinks(copied_root)
    source_hashes = _verified_source_hashes(
        copied_root / "kernel-open", expected_hashes=source_hashes_expected
    )

    patch_artifacts = _apply_patch_overlays(copied_root, all_patches)

    owner_identity = None
    if owner_namespace is not None:
        owner_identity = apply_owner_namespace(
            copied_root / "kernel-open",
            owner_namespace,
            chardev_name=chardev_name,
        )
        owner_identity["source_sha256"] = {
            relative: sha256_file(copied_root / "kernel-open" / relative)
            for relative in (
                "nvidia-uvm/nvidia-uvm.Kbuild",
                "nvidia-uvm/uvm.c",
                "nvidia-uvm/uvm_procfs.c",
                "nvidia-uvm/uvm_linux.h",
            )
        }

    command = _build_command(copied_root, kernel_release, jobs, frontend_module_symvers)
    start_utc = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(
        os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600),
        "w",
        encoding="utf-8",
    ) as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        result = subprocess.run(
            command,
            cwd=copied_root,
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    elapsed = time.monotonic() - start
    frontend_symvers_unchanged_after_build = None
    if frontend_module_symvers is not None and frontend_symvers_bytes is not None:
        after_build = _read_regular_file_snapshot(frontend_module_symvers)
        frontend_symvers_unchanged_after_build = (
            hashlib.sha256(after_build).hexdigest()
            == hashlib.sha256(frontend_symvers_bytes).hexdigest()
        )
    uvm_filename = owner_identity["module_filename"] if owner_identity else "nvidia-uvm.ko"
    module_names = (uvm_filename,) if frontend_module_symvers else ("nvidia.ko", uvm_filename)
    module_artifacts = {}
    for module_name in module_names:
        module_path = copied_root / "kernel-open" / module_name
        if module_path.is_file():
            module_artifacts[module_name] = {
                "path": str(module_path),
                "bytes": module_path.stat().st_size,
                "sha256": sha256_file(module_path),
            }
    symvers_path = copied_root / "kernel-open/Module.symvers"
    symvers_artifact = ({
        "path": str(symvers_path),
        "bytes": symvers_path.stat().st_size,
        "sha256": sha256_file(symvers_path),
    } if symvers_path.is_file() else None)
    build_succeeded = result.returncode == 0 and all(name in module_artifacts for name in module_names)
    frontend_consumer_binding = None
    if build_succeeded and frontend_module_symvers is not None:
        uvm_module = copied_root / "kernel-open" / uvm_filename
        depends = subprocess.run(
            ["modinfo", "-F", "depends", str(uvm_module)],
            text=True, capture_output=True, check=False,
        )
        if depends.returncode == 0 and frontend_symvers_bytes is not None:
            try:
                if kernel_extended_modversions_enabled(kernel_config):
                    module_versions = extract_extended_modversions(
                        uvm_module, Path(log_path).parent)
                    version_source = "ELF __version_ext_names/__version_ext_crcs parser"
                else:
                    module_versions = extract_kernel_modversions_section(
                        uvm_module, Path(log_path).parent)
                    version_source = "ELF __versions compact-record parser"
                frontend_consumer_binding = _verify_frontend_consumer_binding(
                    module_versions,
                    frontend_symvers_bytes.decode("utf-8"),
                    depends.stdout,
                    frontend_module_name=frontend_module_name,
                    module_version_source=version_source,
                )
                frontend_consumer_binding["symvers_unchanged_after_build"] = (
                    frontend_symvers_unchanged_after_build
                )
                kernel_config_unchanged_after_build = (
                    sha256_file(kernel_config) == kernel_config_sha256
                )
                frontend_consumer_binding["kernel_config_unchanged_after_build"] = (
                    kernel_config_unchanged_after_build
                )
                frontend_consumer_binding["passed"] &= (
                    frontend_symvers_unchanged_after_build and
                    kernel_config_unchanged_after_build
                )
            except (OSError, RuntimeError, ValueError) as error:
                frontend_consumer_binding = {
                    "passed": False,
                    "error": f"could not parse compiled UVM ELF modversions: {error}",
                    "modinfo_exit_code": depends.returncode,
                }
        else:
            frontend_consumer_binding = {
                "passed": False,
                "error": "could not inspect compiled UVM module dependency metadata",
                "modinfo_exit_code": depends.returncode,
            }
    uvm_module = copied_root / "kernel-open" / uvm_filename
    expected_module_name = (
        owner_identity["module_name"] if owner_identity else "nvidia_uvm"
    )
    if build_succeeded:
        name_result = subprocess.run(
            ["modinfo", "-F", "name", str(uvm_module)],
            text=True, capture_output=True, check=False,
        )
        module_identity = {
            "expected_module_name": expected_module_name,
            "actual_module_name": name_result.stdout.strip(),
            "modinfo_exit_code": name_result.returncode,
            "module_name_matches": (
                name_result.returncode == 0 and
                name_result.stdout.strip() == expected_module_name
            ),
        }
    else:
        module_identity = {
            "expected_module_name": expected_module_name,
            "actual_module_name": None,
            "modinfo_exit_code": None,
            "module_name_matches": False,
        }
    frontend_bound = bool(
        frontend_consumer_binding and frontend_consumer_binding.get("passed")
    )
    if owner_identity and frontend_bound and module_identity["module_name_matches"]:
        level = "compiled-private-owner-uvm"
    elif owner_identity and build_succeeded:
        level = "compiled-but-private-owner-unverified"
    elif frontend_module_symvers is None:
        level = "compiled" if build_succeeded else "build-failed"
    elif frontend_bound:
        level = "compiled-frontend-bound-uvm"
    elif build_succeeded:
        level = "compiled-but-frontend-binding-unproven"
    else:
        level = "build-failed"
    nvidia_module_built = (copied_root / "kernel-open/nvidia.ko").is_file()
    if frontend_module_symvers:
        scope = "clean pinned R580 UVM-only consumer build against the supplied hybrid frontend; "
        if owner_identity:
            scope += (
                "private module/procfs identity with alloc_chrdev_region label "
                f"{owner_identity['device_name']}; "
            )
        else:
            scope += "stock module/device/procfs identity retained; "
        scope += "no install, module insertion, GPU access, VM change, or reboot"
    else:
        scope = (
            "clean pinned R580 nvidia+nvidia-uvm build; "
            "no install, module insertion, GPU access, VM change, or reboot"
        )

    report = {
        "schema": "r580-uvm-isolated-gpu-execution-build-v5",
        "started_at_utc": start_utc,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": {
            "level": level,
            "runtime_or_hardware_validated": False,
            "module_loaded_or_installed": False,
        },
        "inputs": {
            "implementation_sha256": {
                "tools/probe_r580_uvm_isolated_execution.py": sha256_file(Path(__file__)),
                "tools/build_hybrid_frontend.py": sha256_file(
                    ROOT / "tools/build_hybrid_frontend.py"),
            },
            "source_version": source_version,
            "kernel_config": {
                "path": str(kernel_config),
                "sha256": kernel_config_sha256,
            },
            "source_archive": {
                "path": project_path(source_archive),
                "sha256": source_archive_sha256,
            },
            "source_package": str(copied_root),
            "source_files": source_hashes,
            "patches": patch_artifacts,
            "owner_namespace": owner_identity,
            "frontend_module_symvers": frontend_symvers_record,
            "frontend_module_name": frontend_module_name,
            "expected_frontend_module_symvers_sha256": expected_frontend_symvers_sha256,
        },
        "build": {
            "kernel_release": kernel_release,
            "command": command,
            "scratch_package": str(copied_root),
            "exit_code": result.returncode,
            "elapsed_seconds": round(elapsed, 3),
            "modules": module_artifacts,
            "module_symvers": symvers_artifact,
            "frontend_consumer_binding": frontend_consumer_binding,
            "module_identity": module_identity,
            "frontend_symvers_unchanged_after_build": frontend_symvers_unchanged_after_build,
            "nvidia_kernel_module_built": nvidia_module_built,
            "log": project_path(log_path),
            "log_sha256": sha256_file(log_path),
        },
        "scope": scope,
    }
    _write_json_new(report_path, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--kernel-release", default="7.0.0-38-generic")
    parser.add_argument(
        "--source-version",
        choices=sorted(SOURCE_PROFILES),
        default=SOURCE_TAG,
        help="select the exact pinned R580 source profile and matching Kbuild overlay",
    )
    parser.add_argument("--jobs", type=int, default=max(1, min(os.cpu_count() or 1, 8)))
    parser.add_argument("--frontend-module-symvers", type=Path)
    parser.add_argument("--expected-frontend-symvers-sha256")
    parser.add_argument(
        "--frontend-module-name", choices=sorted(SUPPORTED_FRONTEND_MODULES),
        default="hybrid580_frontend",
        help="exact provider name recorded in the frontend Module.symvers",
    )
    parser.add_argument(
        "--owner-namespace",
        help="build R580 UVM with a private module/procfs identity (compile-only)",
    )
    parser.add_argument(
        "--chardev-name",
        help="override the alloc_chrdev_region label, e.g. nvidia-uvm for matching NVIDIA userspace",
    )
    parser.add_argument(
        "--additional-patch",
        type=Path,
        action="append",
        default=[],
        help="apply an extra patch after the pinned R580 isolation patches (repeatable)",
    )
    args = parser.parse_args(argv)
    if args.chardev_name is not None and args.owner_namespace is None:
        parser.error("--chardev-name requires --owner-namespace")
    try:
        report = build_probe(
            args.scratch, args.report, args.log,
            args.kernel_release, args.jobs,
            args.frontend_module_symvers, args.expected_frontend_symvers_sha256,
            args.owner_namespace, args.chardev_name, tuple(args.additional_patch),
            args.frontend_module_name, args.source_version,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["qualification"]["level"] in (
            "compiled", "compiled-frontend-bound-uvm", "compiled-private-owner-uvm"
        ) else 1
    except (FileExistsError, OSError, RuntimeError, ValueError, tarfile.TarError) as exc:
        print(f"isolated UVM build probe failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
