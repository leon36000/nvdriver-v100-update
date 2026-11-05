#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate and sanitize an isolated hybrid-bundle kmod resolution report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_hybrid_bundle_depmod import _parse_depmod_softdep_metadata

MODULES = {
    "frontend": ("nvidia", "nvidia.ko"),
    "legacy": ("hybrid580_legacy", "hybrid580_legacy.ko"),
    "open": ("hybrid580_open", "hybrid580_open.ko"),
    "uvm": ("nvidia_uvm", "nvidia_uvm.ko"),
}
HARD_ORDER = ["hybrid580_open.ko", "hybrid580_legacy.ko", "nvidia.ko"]
SOFTDEP_LINE = "softdep hybrid580_open pre: ecdh_generic,ecdsa_generic"
SHA256 = re.compile(r"[0-9a-f]{64}")


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError("invalid hybrid-bundle depmod evidence: " + label)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("receipt implementation must be a regular project file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_sha256(value) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _validate_command(command, expected: list[str], label: str) -> None:
    _require(isinstance(command, list) and command == expected, label + " command")


def _validate_show_output(stdout: str, stage_root: str, kernel: str,
                          expected_names: list[str], target: str,
                          expected_builtin_modules: list[str] | None = None) -> None:
    _require(isinstance(stdout, str), target + " output type")
    if expected_builtin_modules is None:
        expected_builtin_modules = []
    _require(expected_builtin_modules in ([], ["ecdh_generic"]),
             target + " builtin output")
    modules = []
    builtin_modules = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        fields = shlex.split(line)
        if fields and fields[0] == "builtin":
            _require(fields == ["builtin", "ecdh_generic"],
                     target + " unexpected kmod output")
            builtin_modules.append(fields[1])
            continue
        _require(len(fields) == 2 and fields[0] == "insmod",
                 target + " unexpected kmod output")
        module_path = Path(fields[1])
        _require(module_path.is_absolute(), target + " non-absolute module path")
        _require(".." not in module_path.parts and "." not in module_path.parts,
                 target + " unsafe module path")
        try:
            relative = module_path.relative_to(
                Path(stage_root) / "lib/modules" / kernel)
        except ValueError:
            raise ValueError("invalid hybrid-bundle depmod evidence: "
                             + target + " module path escapes isolated stage") from None
        name = module_path.name
        if name == "ecdsa_generic.ko.zst":
            _require(relative == Path("kernel/crypto/ecdsa_generic.ko.zst"),
                     target + " softdep module path")
        else:
            _require(relative == Path("updates/extra") / name,
                     target + " bundle module path")
        modules.append(name)
    _require(builtin_modules == expected_builtin_modules,
             target + " builtin output mismatch")
    _require(modules == expected_names, target + " output/order mismatch")


def _validate_modules_dep(text: str, digest: str) -> None:
    _require(isinstance(text, str) and _sha256(text.encode()) == digest,
             "modules.dep digest")
    expected = {
        "updates/extra/hybrid580_open.ko": set(),
        "updates/extra/hybrid580_legacy.ko": set(),
        "updates/extra/nvidia.ko": {
            "updates/extra/hybrid580_open.ko",
            "updates/extra/hybrid580_legacy.ko",
        },
        "updates/extra/nvidia_uvm.ko": {
            "updates/extra/nvidia.ko",
            "updates/extra/hybrid580_open.ko",
            "updates/extra/hybrid580_legacy.ko",
        },
        "kernel/crypto/ecdsa_generic.ko.zst": set(),
    }
    actual = {}
    for line in text.splitlines():
        left, separator, right = line.partition(":")
        _require(bool(separator) and left and left not in actual,
                 "malformed modules.dep")
        dependencies = right.split()
        _require(len(dependencies) == len(set(dependencies)),
                 "duplicate modules.dep dependency")
        actual[left] = set(dependencies)
    _require(actual == expected, "modules.dep dependency graph")


def _validate_softdep_metadata(depmod: dict, softdep: dict) -> None:
    text = depmod.get("modules_softdep")
    digest = depmod.get("modules_softdep_sha256")
    _require(isinstance(text, str) and _sha256(text.encode()) == digest,
             "modules.softdep digest")
    parsed = _parse_depmod_softdep_metadata(text)
    _require(parsed == {
        "hybrid580_open": {"pre": ["ecdh_generic", "ecdsa_generic"], "post": []},
    }, "modules.softdep declaration")
    _require(softdep.get("expected_modules_softdep_lines") == {
        "hybrid580_open": SOFTDEP_LINE,
    }, "expected modules.softdep declaration")
    _require(softdep.get("owners") == {
        "hybrid580_open": {"pre": ["ecdh_generic", "ecdsa_generic"], "post": []},
    }, "source softdep declaration")


def build_receipt(report: dict, raw_report_sha256: str,
                  expected_audit_sha256: str) -> dict:
    """Validate raw evidence and return a path-free, normalized receipt."""
    _require(isinstance(report, dict), "report object")
    _require(_is_sha256(raw_report_sha256),
             "raw report digest")
    _require(_is_sha256(expected_audit_sha256),
             "audit report digest")
    _require(report.get("schema") == "hybrid-module-bundle-depmod-static-v1" and
             report.get("status") == "passed" and
             report.get("qualification") == "isolated-dependency-map-only",
             "report status/schema/qualification")
    _require(report.get("audit_report_status") == "passed" and
             report.get("audit_report_sha256") == expected_audit_sha256,
             "static audit binding")
    _require(report.get("loaded_or_installed") is False and
             report.get("runtime_or_hardware_validated") is False,
             "no-load qualification")

    kernel = report.get("kernel_release")
    _require(isinstance(kernel, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+", kernel),
             "kernel release")
    stage_root = report.get("stage_root")
    _require(isinstance(stage_root, str) and Path(stage_root).is_absolute() and
             ".." not in Path(stage_root).parts and
             Path(stage_root).name.startswith("hybrid-bundle-depmod-"),
             "isolated stage identity")

    module_records = report.get("modules")
    _require(isinstance(module_records, dict) and set(module_records) == set(MODULES),
             "four module roles")
    modules = {}
    for role, (name, filename) in MODULES.items():
        record = module_records[role]
        _require(isinstance(record, dict) and record.get("name") == name and
                 record.get("staged_name") == filename and
                 _is_sha256(record.get("sha256")) and
                 isinstance(record.get("size_bytes"), int) and
                 record["size_bytes"] > 0,
                 role + " module identity/hash/size")
        modules[role] = {
            "name": name,
            "filename": filename,
            "sha256": record["sha256"],
            "size_bytes": record["size_bytes"],
        }

    depmod = report.get("depmod", {})
    _require(isinstance(depmod, dict) and depmod.get("exit_code") == 0,
             "depmod exit status")
    depmod_command = ["depmod", "-b", stage_root, kernel]
    _validate_command(depmod.get("command"), depmod_command, "depmod")
    for key in ("modules_dep_sha256", "modules_softdep_sha256"):
        _require(_is_sha256(depmod.get(key)),
                 key + " format")
    _validate_modules_dep(depmod.get("modules_dep", ""),
                          depmod["modules_dep_sha256"])

    softdep = report.get("soft_dependency_resolution", {})
    _require(isinstance(softdep, dict), "softdep resolution object")
    _validate_softdep_metadata(depmod, softdep)
    _require(softdep.get("builtins") == {
        "ecdh_generic": "kernel/crypto/ecdh_generic.ko",
    }, "kernel builtin inventory")
    resolved = softdep.get("resolved_targets", {})
    _require(isinstance(resolved, dict), "resolved softdep targets")
    builtin = resolved.get("ecdh_generic", {})
    _require(isinstance(builtin, dict), "kernel builtin target record")
    _require(builtin.get("kind") == "kernel-builtin" and
             builtin.get("resolved") is True and
             builtin.get("relative_path") == "kernel/crypto/ecdh_generic.ko",
             "kernel builtin softdep resolution")
    support_modules = softdep.get("support_modules", {})
    _require(isinstance(support_modules, dict), "softdep support module inventory")
    support = support_modules.get("ecdsa_generic", {})
    target = resolved.get("ecdsa_generic", {})
    _require(isinstance(support, dict) and isinstance(target, dict),
             "loadable softdep records")
    _require(target.get("kind") == "loadable-module" and
             target.get("relative_path") == "kernel/crypto/ecdsa_generic.ko.zst" and
             target.get("ordered_modules") == ["ecdsa_generic.ko.zst"] and
             _is_sha256(target.get("sha256")) and
             target.get("sha256") == support.get("sha256") and
             support.get("relative_path") == target.get("relative_path"),
             "loadable softdep resolution")
    _validate_command(target.get("command"), [
        "modprobe", "-C", "/dev/null", "-d", stage_root,
        "--set-version", kernel, "--show-depends", "ecdsa_generic",
    ], "softdep modprobe")
    _validate_show_output(
        target.get("stdout", ""), stage_root, kernel,
        ["ecdsa_generic.ko.zst"], "ecdsa_generic", [])

    resolution = report.get("resolution", {})
    _require(isinstance(resolution, dict), "resolution object")
    reported_softdeps = {}
    for name, hard_order, target_filename in (
        ("nvidia", HARD_ORDER, "nvidia.ko"),
        ("nvidia_uvm", HARD_ORDER + ["nvidia_uvm.ko"], "nvidia_uvm.ko"),
    ):
        record = resolution.get(name, {})
        _require(isinstance(record, dict), name + " resolution")
        builtin_modules = record.get("builtin_modules")
        _require(builtin_modules in ([], ["ecdh_generic"]),
                 name + " builtin output")
        with_softdep = ["ecdsa_generic.ko.zst"] + hard_order
        order = record.get("ordered_modules")
        _require(order in (hard_order, with_softdep) and order[-1] == target_filename,
                 name + " dependency order")
        reported_softdeps[name] = order == with_softdep
        _validate_command(record.get("command"), [
            "modprobe", "-C", "/dev/null", "-d", stage_root,
            "--set-version", kernel, "--show-depends", name,
        ], name + " modprobe")
        _validate_show_output(record.get("stdout", ""), stage_root, kernel,
                              order, name, builtin_modules)

    return {
        "schema": "hybrid-module-bundle-depmod-sanitized-v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "raw_report_sha256": raw_report_sha256,
        "audit_report_sha256": expected_audit_sha256,
        "implementation_sha256": {
            "tools/verify_hybrid_bundle_depmod.py": _sha256_file(
                ROOT / "tools/verify_hybrid_bundle_depmod.py"),
            "tools/summarize_hybrid_bundle_depmod.py": _sha256_file(
                Path(__file__).resolve()),
        },
        "audit_report_status": "passed",
        "kernel_release": kernel,
        "qualification": "isolated-dependency-map-only",
        "modules": modules,
        "dependency_resolution": {
            "nvidia": HARD_ORDER,
            "nvidia_uvm": HARD_ORDER + ["nvidia_uvm.ko"],
            "show_depends_included_verified_pre_softdep": reported_softdeps,
            "verified_pre_softdeps": {
                "kernel_builtin": ["ecdh_generic"],
                "loadable_module": [{
                    "name": "ecdsa_generic",
                    "filename": "ecdsa_generic.ko.zst",
                    "sha256": target["sha256"],
                }],
            },
        },
        "depmod_metadata_sha256": {
            "modules_dep": depmod["modules_dep_sha256"],
            "modules_softdep": depmod["modules_softdep_sha256"],
        },
        "loaded_or_installed": False,
        "runtime_or_hardware_validated": False,
        "cuda_execution_validated": False,
    }


def _read_report(path: Path) -> tuple[dict, str]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("raw report must not be a symlink")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT / "evidence")
    except ValueError:
        raise ValueError("raw report must stay inside project evidence") from None
    fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("raw report must be a regular file")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key in raw report")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique_object), _sha256(data)


def _write_receipt(path: Path, receipt: dict) -> None:
    path = Path(path)
    if path.is_absolute():
        candidate = path
    else:
        candidate = ROOT / path
    candidate = Path(os.path.abspath(candidate))
    allowed = ROOT / "evidence"
    try:
        candidate.relative_to(allowed)
    except ValueError:
        raise ValueError("sanitized receipt must stay inside project evidence") from None
    current = allowed
    for component in candidate.relative_to(allowed).parts:
        current = current / component
        if current.exists() and current.is_symlink():
            raise ValueError("sanitized receipt path must not contain symlinks")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(candidate, flags, 0o600)
    try:
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.chmod(candidate, 0o600)
    except BaseException:
        try:
            candidate.unlink()
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-report", type=Path, required=True)
    parser.add_argument("--expected-raw-report-sha256", required=True)
    parser.add_argument("--expected-audit-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report, raw_hash = _read_report(args.raw_report)
        _require(raw_hash == args.expected_raw_report_sha256.lower(),
                 "raw report digest mismatch")
        receipt = build_receipt(
            report, raw_hash, args.expected_audit_sha256.lower())
        _write_receipt(args.output, receipt)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"summarize_hybrid_bundle_depmod: error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "passed",
        "schema": receipt["schema"],
        "output": str(args.output),
        "modules": {role: entry["sha256"] for role, entry in receipt["modules"].items()},
        "runtime_or_hardware_validated": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
