#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare UVM dispatch/ioctl surfaces directly from pinned NVIDIA source archives."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.compare_uvm_ioctl_routes import (  # noqa: E402
    compare_uvm_sources,
    parse_uvm_source,
)
from tools.audit_r595_uvm_hal_table_closure import (  # noqa: E402
    REQUIRED_GV100_TABLE_TARGETS,
    checked_source_archive_root,
)
from tools.audit_volta_uvm_hal_dispatch import (  # noqa: E402
    DEFAULT_R580_ARCHIVE,
    audit_volta_uvm_dispatch,
)
from tools.probe_r615_gv100_dispatch import write_private_evidence_report  # noqa: E402
from tools.probe_volta_uvm_port import (  # noqa: E402
    DEFAULT_EXPECTED_R580_ARCHIVE_SHA256,
    R580_SOURCE_ROOT,
    read_member,
)

RELEASES = {
    "R595.112.07": {
        "tag": "595.112.07",
        "commit": "d8257d95ae5fed364163e4df51db66df8b1ee0d2",
        "archive": ".cache/upstream/open-gpu-kernel-modules-595.112.07-d8257d95.tar.gz",
        "sha256": "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4",
    },
    "R615.78.08": {
        "tag": "615.78.08",
        "commit": "1a82fbfda8f321b056eb3568850f9316c5e465c5",
        "archive": ".cache/upstream/open-gpu-kernel-modules-1a82fbfda8f321b056eb3568850f9316c5e465c5.tar.gz",
        "sha256": "590ee6a5a780f946322edd17f9d235c6664eb7e6839073ac0d68c0f263e7184f",
    },
}
UVM_MEMBER_SUFFIXES = {
    "uvm.c": ("kernel-open", "nvidia-uvm", "uvm.c"),
    "uvm_hal.c": ("kernel-open", "nvidia-uvm", "uvm_hal.c"),
    "uvm_ioctl.h": ("kernel-open", "nvidia-uvm", "uvm_ioctl.h"),
    "uvm_linux_ioctl.h": ("kernel-open", "nvidia-uvm", "uvm_linux_ioctl.h"),
    "uvm_api.h": ("kernel-open", "nvidia-uvm", "uvm_api.h"),
    "uvm_policy.c": ("kernel-open", "nvidia-uvm", "uvm_policy.c"),
}
LEGACY_SYSTEM_WIDE_ATOMICS = {
    "UVM_ENABLE_SYSTEM_WIDE_ATOMICS": "uvm_api_enable_system_wide_atomics",
    "UVM_DISABLE_SYSTEM_WIDE_ATOMICS": "uvm_api_disable_system_wide_atomics",
}
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def extract_uvm_archive_sources(
        archive_path: Path, *, expected_sha256: str | None = None
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Read only allowlisted regular UVM files; never extract arbitrary tar members."""
    archive_path = Path(archive_path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to verify source archives")
    descriptor = os.open(archive_path, flags | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"source archive must be a regular file: {archive_path}")
            if before.st_size < 1 or before.st_size > MAX_ARCHIVE_BYTES:
                raise ValueError(f"source archive has an invalid size: {archive_path}")
            with tempfile.TemporaryFile(mode="w+b") as verified_copy:
                digest = hashlib.sha256()
                total_bytes = 0
                while chunk := source.read(1024 * 1024):
                    total_bytes += len(chunk)
                    if total_bytes > MAX_ARCHIVE_BYTES:
                        raise ValueError(f"source archive exceeds size limit: {archive_path}")
                    digest.update(chunk)
                    verified_copy.write(chunk)
                after = os.fstat(source.fileno())
                if (total_bytes != before.st_size or
                        (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise ValueError(f"source archive changed while it was being read: {archive_path}")
                archive_sha256 = digest.hexdigest()
                if expected_sha256 is not None and archive_sha256 != expected_sha256:
                    raise ValueError(
                        f"source archive SHA-256 does not match its pin: {archive_path}"
                    )
                verified_copy.seek(0)
                sources: dict[str, bytes] = {}
                names: dict[str, str] = {}
                try:
                    with tarfile.open(fileobj=verified_copy, mode="r:gz") as archive:
                        for member in archive:
                            name = PurePosixPath(member.name)
                            if name.is_absolute() or any(
                                    part in ("", ".", "..") for part in name.parts):
                                raise ValueError(
                                    f"unsafe path in source archive: {member.name!r}"
                                )
                            matching = [
                                filename for filename, suffix in UVM_MEMBER_SUFFIXES.items()
                                if tuple(name.parts[-len(suffix):]) == suffix
                            ]
                            if not matching:
                                continue
                            filename = matching[0]
                            if filename in sources:
                                raise ValueError(f"duplicate {filename} member in source archive")
                            if not member.isfile():
                                raise ValueError(
                                    f"UVM source member is not a regular file: {member.name}"
                                )
                            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                                raise ValueError(
                                    f"UVM source member has an invalid size: {member.name}"
                                )
                            stream = archive.extractfile(member)
                            if stream is None:
                                raise ValueError(
                                    f"cannot read UVM source member: {member.name}"
                                )
                            with stream:
                                data = stream.read(MAX_MEMBER_BYTES + 1)
                            if len(data) != member.size or len(data) > MAX_MEMBER_BYTES:
                                raise ValueError(
                                    f"UVM source member size mismatch: {member.name}"
                                )
                            sources[filename] = data
                            names[filename] = member.name
                except (tarfile.TarError, OSError) as error:
                    raise ValueError(
                        f"cannot read source archive {archive_path}: {error}"
                    ) from error
    except OSError as error:
        raise ValueError(f"cannot open source archive {archive_path}: {error}") from error
    missing = sorted(set(UVM_MEMBER_SUFFIXES) - sources.keys())
    if missing:
        raise ValueError(f"source archive lacks required UVM files: {missing}")
    return sources, {"archive_sha256": archive_sha256, **{
        f"{name}_member": names[name] for name in sorted(names)
    }}


def _pinned_archive(release: str) -> tuple[Path, dict[str, str]]:
    metadata = RELEASES.get(release)
    if metadata is None:
        raise ValueError(f"unsupported pinned source release: {release}")
    path = ROOT / metadata["archive"]
    cursor = ROOT
    for part in Path(metadata["archive"]).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"source archive path contains a symlink: {cursor}")
    return path, metadata


def _read_release(release: str) -> tuple[dict[str, Any], dict[str, str]]:
    archive_path, metadata = _pinned_archive(release)
    sources, members = extract_uvm_archive_sources(
        archive_path, expected_sha256=metadata["sha256"]
    )
    return sources, {
        "release": release,
        "tag": metadata["tag"],
        "repository_commit": metadata["commit"],
        "archive": metadata["archive"],
        **members,
    }


def _read_pinned_r580_uvm_sources() -> tuple[dict[str, bytes], dict[str, str]]:
    """Read the allowlisted R580 UVM comparison files from the pinned archive."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to verify the R580 source archive")
    descriptor = os.open(DEFAULT_R580_ARCHIVE, flags | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("R580 source archive is not a bounded regular file")
        digest = hashlib.sha256()
        total_bytes = 0
        while chunk := stream.read(1024 * 1024):
            total_bytes += len(chunk)
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (total_bytes != before.st_size or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("R580 source archive changed while it was being read")
        archive_sha256 = digest.hexdigest()
        if archive_sha256 != DEFAULT_EXPECTED_R580_ARCHIVE_SHA256:
            raise ValueError("R580 source archive SHA-256 differs from its immutable pin")
        stream.seek(0)
        try:
            with tarfile.open(fileobj=stream, mode="r:xz") as archive:
                source_root = checked_source_archive_root(archive, R580_SOURCE_ROOT)
                prefix = source_root + "/kernel-open/nvidia-uvm/"
                members = {name: prefix + name for name in UVM_MEMBER_SUFFIXES}
                sources = {
                    name: read_member(archive, member)
                    for name, member in members.items()
                }
        except (OSError, tarfile.TarError) as error:
                raise ValueError(f"cannot read pinned R580 UVM sources: {error}") from error
    return sources, {
        "release": "R580.178.04",
        "archive": ".cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz",
        "archive_sha256": archive_sha256,
        "source_root": R580_SOURCE_ROOT,
        "selected_uvm_members": members,
        "uvm_hal_sha256": hashlib.sha256(sources["uvm_hal.c"]).hexdigest(),
    }


def audit_legacy_system_wide_atomics_api(
        r580_sources: dict[str, bytes],
        r580_surface: dict[str, Any],
        modern_sources: dict[str, dict[str, bytes]],
        modern_surfaces: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Prove the legacy UVM opt-in ioctl routes are absent from modern source."""
    required_r580_policy_tokens = {
        "uvm_api.h": (
            "uvm_api_enable_system_wide_atomics",
            "uvm_api_disable_system_wide_atomics",
        ),
        "uvm_policy.c": ("system_wide_atomics_set", "scoped_atomics_supported"),
    }
    for relative_path, tokens in required_r580_policy_tokens.items():
        source = r580_sources.get(relative_path)
        if source is None:
            raise ValueError(f"R580 source is missing for legacy atomic API audit: {relative_path}")
        for token in tokens:
            if token.encode("ascii") not in source:
                raise ValueError(f"R580 legacy atomic API token is missing: {relative_path}: {token}")

    operations = {}
    for ioctl_name, handler in LEGACY_SYSTEM_WIDE_ATOMICS.items():
        r580_route = r580_surface["routes"].get(ioctl_name)
        if (ioctl_name not in r580_surface["ioctl_definitions"]
                or r580_route != handler
                or handler.encode("ascii") not in r580_sources["uvm_api.h"]
                or handler.encode("ascii") not in r580_sources["uvm_policy.c"]):
            raise ValueError(f"R580 legacy atomic ioctl is not closed: {ioctl_name}")
        modern = {}
        for release, sources in modern_sources.items():
            surface = modern_surfaces[release]
            if ioctl_name in surface["ioctl_definitions"] or ioctl_name in surface["routes"]:
                raise ValueError(f"legacy system-wide-atomics ioctl survived in {release}: {ioctl_name}")
            tokens = {
                ioctl_name,
                handler,
                "system_wide_atomics_set",
                "scoped_atomics_supported",
            }
            occurrences = []
            for relative_path, source in sorted(sources.items()):
                text = source.decode("utf-8", errors="strict")
                for token in sorted(tokens):
                    if token in text:
                        occurrences.append({"path": relative_path, "token": token})
            if occurrences:
                raise ValueError(
                    f"legacy system-wide-atomics policy code survived in {release}: {occurrences}"
                )
            modern[release] = {
                "ioctl_definition_present": False,
                "dispatch_route_present": False,
                "handler_or_policy_tokens_present": False,
                "checked_source_files": sorted(sources),
            }
        operations[ioctl_name] = {
            "r580_ioctl_definition_present": True,
            "r580_dispatch_handler": handler,
            "r580_handler_declared_and_implemented": True,
            "modern_branches": modern,
        }

    return {
        "disposition": "legacy-system-wide-atomics-uapi-removed",
        "baseline": {
            "release": "R580.178.04",
            "scoped_atomics_guard_present": True,
            "operations": operations,
        },
        "interpretation": (
            "R580 exposes enable/disable UVM ioctls and rejects the policy when "
            "scoped_atomics_supported is true. Both ioctl definitions, dispatch "
            "routes, handler names, and the policy helper are absent from the pinned "
            "R595.112.07 and R615.78.08 UVM source files. The removed field is not "
            "evidence about CUDA C++ atomic scopes or hardware correctness."
        ),
        "limitations": [
            "Static source comparison only; no proprietary libcuda call path was inspected.",
            "No old-user-mode/new-kernel ABI compatibility or GV100 atomic execution was tested.",
        ],
    }


def compare_pinned_archives(baseline_release: str = "R595.112.07",
                            candidate_release: str = "R615.78.08") -> dict[str, Any]:
    baseline_sources, baseline_provenance = _read_release(baseline_release)
    candidate_sources, candidate_provenance = _read_release(candidate_release)
    r580_sources, r580_provenance = _read_pinned_r580_uvm_sources()
    with tempfile.TemporaryDirectory(prefix="uvm-route-archive-audit-") as temporary:
        sources_by_release = {
            "R580.178.04": r580_sources,
            baseline_release: baseline_sources,
            candidate_release: candidate_sources,
        }
        roots = {}
        for label, sources in sources_by_release.items():
            root = Path(temporary) / label / "nvidia-uvm"
            root.mkdir(parents=True)
            for name, data in sources.items():
                (root / name).write_bytes(data)
            roots[label] = root
        comparison = compare_uvm_sources(
            roots[baseline_release], roots[candidate_release],
            baseline_release, candidate_release,
        )
        surfaces = {
            label: parse_uvm_source(root, label)
            for label, root in roots.items()
        }
        legacy_atomic_api = audit_legacy_system_wide_atomics_api(
            r580_sources,
            surfaces["R580.178.04"],
            {baseline_release: baseline_sources, candidate_release: candidate_sources},
            {baseline_release: surfaces[baseline_release],
             candidate_release: surfaces[candidate_release]},
        )

    volta_hal_comparisons = {}
    for release, sources in ((baseline_release, baseline_sources),
                             (candidate_release, candidate_sources)):
        volta_hal_comparisons[release] = audit_volta_uvm_dispatch(
            r580_sources["uvm_hal.c"].decode("utf-8", errors="strict"),
            sources["uvm_hal.c"].decode("utf-8", errors="strict"),
            modern_branch=release,
        )
    r580_provenance["uvm_hal_member"] = r580_provenance["selected_uvm_members"]["uvm_hal.c"]

    for role, provenance in (("baseline", baseline_provenance),
                             ("candidate", candidate_provenance)):
        source = comparison[role]["source"]
        for filename in UVM_MEMBER_SUFFIXES:
            if filename not in source:
                continue
            source[filename]["path"] = (
                provenance["archive"] + "::" + provenance[f"{filename}_member"]
            )
    return {
        "schema": "nvidia-uvm-archive-compatibility-audit-v2",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "qualification": "analyzed-statically",
        "runtime_compatibility_proven": False,
        "hardware_tested": False,
        "baseline_provenance": baseline_provenance,
        "candidate_provenance": candidate_provenance,
        "comparison": comparison,
        "r580_volta_reference": r580_provenance,
        "volta_hal_dispatch_comparisons": volta_hal_comparisons,
        "legacy_system_wide_atomics_api": legacy_atomic_api,
        "scope": (
            "UVM dispatch/ioctl surfaces and GV100 HAL class-table dispatch from "
            "complete SHA-256-pinned NVIDIA source archives; no compilation, loading, "
            "or hardware execution"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", choices=sorted(RELEASES), default="R595.112.07")
    parser.add_argument("--candidate", choices=sorted(RELEASES), default="R615.78.08")
    parser.add_argument("--report", type=Path,
                        help="new evidence path (defaults to a unique UTC timestamp)")
    args = parser.parse_args(argv)
    report = compare_pinned_archives(args.baseline, args.candidate)
    report_path = args.report or Path("evidence") / (
        "uvm-archive-compatibility-audit-v2-" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"
    )
    report_path = write_private_evidence_report(
        report_path, report, repository_root=ROOT
    )
    diff = report["comparison"]
    print(json.dumps({
        "schema": report["schema"],
        "report": str(report_path.resolve()),
        "qualification": report["qualification"],
        "baseline_route_count": diff["baseline"]["route_count"],
        "baseline_all_route_count": diff["baseline"]["all_route_count"],
        "baseline_uvm_ioctl_definition_count": diff["baseline"]["ioctl_definition_count"],
        "baseline_total_ioctl_definition_count": diff["baseline"]["all_ioctl_definition_count"],
        "candidate_route_count": diff["candidate"]["route_count"],
        "candidate_all_route_count": diff["candidate"]["all_route_count"],
        "candidate_uvm_ioctl_definition_count": diff["candidate"]["ioctl_definition_count"],
        "candidate_total_ioctl_definition_count": diff["candidate"]["all_ioctl_definition_count"],
        "baseline_volta_hal_targets_missing": sorted(
            report["volta_hal_dispatch_comparisons"][args.baseline]["modern_missing_targets"]
        ),
        "candidate_volta_hal_targets_missing": sorted(
            report["volta_hal_dispatch_comparisons"][args.candidate]["modern_missing_targets"]
        ),
        "removed_dispatch_routes": diff["removed_dispatch_routes"],
        "added_dispatch_routes": diff["added_dispatch_routes"],
        "runtime_compatibility_proven": False,
        "hardware_tested": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
