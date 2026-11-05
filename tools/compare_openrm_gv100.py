#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare pinned Open R580/R595/R610/R615 generated GV100 profiles.

This inventories the shipping Open profiles, not proprietary R580 behavior or
complete physical HAL availability. It reads an immutable archive snapshot,
does not extract source, and does not modify modules.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.probe_r615_gv100_dispatch import (  # noqa: E402
    write_private_evidence_report,
)

INPUTS = (
    ("580.196.07", "NVIDIA-kernel-module-source-580.196.07.tar.xz",
     "NVIDIA-kernel-module-source-580.196.07",
     "21914a460f17190c43cffb75f0c35aef957e267bfefea267bc18638beae17084"),
    ("580.178.04", "NVIDIA-kernel-module-source-580.178.04.tar.xz",
     "NVIDIA-kernel-module-source-580.178.04",
     "060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8"),
    ("595.104.02", "open-gpu-kernel-modules-ac24e02fc090c3e05c1fc03384b317ac2cc301b5.tar.gz",
     "open-gpu-kernel-modules-ac24e02fc090c3e05c1fc03384b317ac2cc301b5",
     "da4e454d493818027998fc9d7ef95fd5dd291d3d37119f1f81d12db85fc33190"),
    ("595.112.07", "open-gpu-kernel-modules-595.112.07-d8257d95.tar.gz",
     "open-gpu-kernel-modules-d8257d95ae5fed364163e4df51db66df8b1ee0d2",
     "567d4ba082a54ef733e7ce87c87401da488a3aabe29837c92feb19011c8250c4"),
    ("610.57.04", "open-gpu-kernel-modules-610.57.04-e4a5faa.tar.gz",
     "open-gpu-kernel-modules-610.57.04",
     "619d7b5ce1f79c3211afdbf87d02b2174d268b10d005c5b8f994be22299be681"),
    ("615.71.10", "open-gpu-kernel-modules-615.71.10-6f3be8c9.tar.gz",
     "open-gpu-kernel-modules-6f3be8c9c3fb4ed6ffc607a0d32d31ce4db7fba5",
     "c01605048cab3d988b1b3028fbee0646ba0937407949dc43514b3e4694f40f6c"),
    ("615.78.08", "open-gpu-kernel-modules-1a82fbfda8f321b056eb3568850f9316c5e465c5.tar.gz",
     "open-gpu-kernel-modules-1a82fbfda8f321b056eb3568850f9316c5e465c5",
     "590ee6a5a780f946322edd17f9d235c6664eb7e6839073ac0d68c0f263e7184f"),
)
SOURCE_COMMITS = {
    "580.196.07": "02e64bf229e77873c9df22ebcfed6a3e0b813206",
    "580.178.04": "c8e699821c23e4335bf23330a54a23d15cfb95e9",
    "595.104.02": "ac24e02fc090c3e05c1fc03384b317ac2cc301b5",
    "595.112.07": "d8257d95ae5fed364163e4df51db66df8b1ee0d2",
    "610.57.04": "e4a5faa2567f28c8eabe0ebb6422b6d0abcf37eb",
    "615.71.10": "6f3be8c9c3fb4ed6ffc607a0d32d31ce4db7fba5",
    "615.78.08": "1a82fbfda8f321b056eb3568850f9316c5e465c5",
}
FILES = (
    "src/nvidia/generated/rmconfig.h",
    "src/nvidia/generated/g_chips2halspec_nvoc.c",
    "src/nvidia/generated/g_hal_register.h",
    "src/nvidia/generated/g_hal_archimpl.h",
    "src/nvidia/src/kernel/core/hal_mgr.c",
)

DEFAULT_REPORT = ROOT / "evidence/openrm-gv100-generated-release-matrix-v8-20261023.json"


def _read_regular_snapshot(path: Path) -> bytes:
    """Read one regular archive through a no-follow descriptor into a snapshot."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to read pinned source archives")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"source archive is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            snapshot = stream.read()
        after = os.fstat(descriptor)
        if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ValueError(f"source archive changed while being read: {path}")
        if len(snapshot) != metadata.st_size:
            raise ValueError(f"short read of source archive: {path}")
        return snapshot
    finally:
        os.close(descriptor)


def _implementation_fingerprints() -> dict[str, str]:
    paths = (
        Path(__file__).resolve(strict=True),
        ROOT / "tests/test_compare_openrm_gv100.py",
        ROOT / "tools/probe_r615_gv100_dispatch.py",
    )
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def parse_generated_sources(version: str, texts: dict[str, str]) -> dict:
    """Summarize exact generated gates without treating a row as runtime support."""
    required = set(FILES)
    missing = sorted(required - set(texts))
    if missing:
        raise ValueError(f"missing generated source for {version}: {', '.join(missing)}")
    rmconfig = texts["src/nvidia/generated/rmconfig.h"]
    flags = {}
    for name in ("GV10X", "GV100", "VOLTA_CLASSIC_GPUS"):
        matches = re.findall(
            r"^#define\s+RMCFG_CHIP_" + name + r"\s+([01])\s*$",
            rmconfig, re.M,
        )
        if len(matches) != 1:
            raise ValueError(f"ambiguous {version} chip flag {name}")
        flags[name] = int(matches[0])

    rows = [
        line.strip() for line in texts["src/nvidia/generated/g_hal_archimpl.h"].splitlines()
        if re.search(r"//\s*GV100\b", line)
    ]
    if len(rows) != 1:
        raise ValueError(f"ambiguous {version} GV100 chipID row")
    row_code = rows[0].split("//", 1)[0]
    row_values = re.findall(r"0[xX][0-9a-fA-F]+", row_code)
    if not row_values:
        raise ValueError(f"unparseable {version} GV100 chipID row")
    row_nonzero = any(int(value, 16) != 0 for value in row_values)
    chiphal_label = bool(re.search(
        r"//\s*GV100\b", texts["src/nvidia/generated/g_chips2halspec_nvoc.c"]
    ))
    legacy_registration = bool(re.search(
        r"\bregisterHalModule_GV100\s*\(",
        texts["src/nvidia/generated/g_hal_register.h"],
    ))
    if (
        not flags["GV100"]
        and not flags["VOLTA_CLASSIC_GPUS"]
        and not row_nonzero
        and not chiphal_label
        and not legacy_registration
    ):
        profile = "gv100-disabled-in-generated-profile"
    else:
        profile = "not-proven-disabled-or-enabled"
    return {
        "version": version,
        "files": {},
        "chip_flags": flags,
        "gv100_chip_id_row": rows[0],
        "gv100_chip_row_nonzero": row_nonzero,
        "chiphal_gv100_label_present": chiphal_label,
        "gv100_legacy_registration_symbol_present": legacy_registration,
        "source_profile": profile,
    }


def inspect_archive(cache, version, filename, prefix, expected):
    path = cache / filename
    snapshot = _read_regular_snapshot(path)
    actual = hashlib.sha256(snapshot).hexdigest()
    if actual != expected:
        raise ValueError(f"{version} source archive digest differs from pinned input")
    texts, identities = {}, {}
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode="r:*") as archive:
        members_by_name: dict[str, list[tarfile.TarInfo]] = {}
        wanted_names = {prefix + "/" + relative for relative in FILES}
        for item in archive.getmembers():
            if item.name in wanted_names:
                members_by_name.setdefault(item.name, []).append(item)
        for relative in FILES:
            member_name = prefix + "/" + relative
            matches = members_by_name.get(member_name, [])
            if len(matches) != 1:
                raise ValueError(f"expected one source member, found {len(matches)}: {member_name}")
            member = matches[0]
            if not member.isfile():
                raise ValueError(f"not a regular source file: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"could not read source member: {member.name}")
            data = source.read()
            texts[relative] = data.decode("utf-8", errors="strict")
            identities[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    summary = parse_generated_sources(version, texts)
    return {
        "version": version, "archive": str(path.resolve()), "archive_sha256": actual,
        "repository_tag": version,
        "repository_commit": SOURCE_COMMITS.get(version),
        **summary,
        "files": identities,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".cache/upstream")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT,
                        help="new JSON path under evidence/; overwrite refused")
    args = parser.parse_args()
    try:
        results = [inspect_archive(args.cache, *item) for item in INPUTS]
        key = "src/nvidia/src/kernel/core/hal_mgr.c"
        report = {
            "schema": "openrm-gv100-generated-release-matrix-v8",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "implementation_sha256": _implementation_fingerprints(),
            "inputs": results,
            "legacy_hal_manager_source_identical_pairs": {
                f"{left['version']}-{right['version']}":
                    left["files"][key] == right["files"][key]
                for index, left in enumerate(results)
                for right in results[index + 1:]
            },
            "qualification": "analyzed-statically",
            "physical_hal_completeness": "not-established",
            "proprietary_r580_behavior_compared": False,
            "runtime_or_hardware_validated": False,
            "loaded_or_installed": False,
            "limitations": [
                "Generated source flags and table rows do not establish physical HAL completeness, RM object creation or GPU initialization.",
                "R580 is the public Open source profile; it is not the proprietary R580 implementation used by the Volta reference driver.",
            ],
        }
        report_path = write_private_evidence_report(args.report, report)
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(2, f"comparison failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
