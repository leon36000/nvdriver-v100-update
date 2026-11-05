#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the captured PC3 guest builds as one static R580 module stack.

The wrapper reports contain paths from a disposable guest build directory.
This tool rebinds those claims only to locally retrieved, hash-verified build
artifacts, then delegates symbol and module topology checks to the existing
hybrid bundle auditor. It never loads or installs a module or accesses a GPU.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import uuid
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.audit_hybrid_candidate_bundle import audit_bundle  # noqa: E402


GUEST = "pc3-v100"
KERNEL = "6.8.0-147-generic"
CAPTURES = {
    "frontend": {
        "schema": "nvidia-hybrid-pc3-v100-hybrid-frontend-build-capture-v1",
        "status": "compiled",
        "builder_schema": "nvidia-hybrid-gpu-file-frontend-v1",
        "qualification": "compiled-bdf-selected-gpu-file-frontend-kernel-module",
        "prefix": "build/experiments/pc3-v100-hybrid-frontend-",
        "module_suffix": "/nvidia.ko",
    },
    "open": {
        "schema": "nvidia-hybrid-pc3-v100-private-open580-build-capture-v1",
        "status": "collected",
        "builder_schema": "private-open580-native-wrapper-v2",
        "builder_qualification": "compiled-native-private-open580-provider-only",
        "prefix": "build/experiments/pc3-v100-private-open580-",
        "module_suffix": "/private/NVIDIA-kernel-module-source-580.178.04/"
                         "kernel-open/hybrid580_open.ko",
    },
    "legacy": {
        "schema": "nvidia-hybrid-pc3-v100-private-legacy580-build-capture-v1",
        "status": "collected",
        "builder_schema": "private-proprietary580-v1",
        "builder_qualification": "compiled-module-and-CPU-model-only-with-inherited-vendor-objtool-warnings",
        "prefix": "build/experiments/pc3-v100-private-proprietary580-",
        "module_suffix": "/nvidia-580.178.04/hybrid580_legacy.ko",
    },
    "uvm": {
        "schema": "nvidia-hybrid-pc3-v100-uvm-consumer-build-capture-v1",
        "status": "compiled-frontend-bound-uvm",
        "builder_schema": "r580-uvm-isolated-gpu-execution-build-v5",
        "qualification": "compiled-frontend-bound-uvm",
        "prefix": "build/experiments/pc3-v100-uvm-consumer-",
        "module_suffix": "/scratch/NVIDIA-kernel-module-source-580.178.04/"
                         "kernel-open/nvidia-uvm.ko",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_captured_artifact(capture: dict[str, Any], root: Path, *,
                              prefix: str, suffix: str, exact: bool = False) -> Path:
    """Resolve one captured artifact only after checking its manifest hash."""
    entries = capture.get("retrieved_artifacts")
    if not isinstance(entries, list):
        raise ValueError("capture does not contain a retrieved artifact manifest")
    matches = []
    for record in entries:
        if not isinstance(record, dict):
            raise ValueError("captured artifact manifest is malformed")
        relative = record.get("path")
        pure = PurePosixPath(relative) if isinstance(relative, str) else None
        if (pure is None or pure.is_absolute() or ".." in pure.parts or
                (relative != prefix if exact else
                 not relative.startswith(prefix) or not relative.endswith(suffix))):
            continue
        matches.append((record, pure))
    if len(matches) != 1:
        raise ValueError("expected exactly one captured artifact matching the pinned role")
    record, pure = matches[0]
    root = Path(root).resolve(strict=True)
    candidate = root.joinpath(*pure.parts)
    cursor = root
    for part in pure.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("captured artifact path contains a symlink")
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("captured artifact is missing or not a regular file")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("captured artifact escaped the canonical project")
    if (type(record.get("bytes")) is not int or
            record["bytes"] != resolved.stat().st_size or
            not isinstance(record.get("sha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None or
            sha256_file(resolved) != record["sha256"]):
        raise ValueError("captured artifact differs from its capture manifest")
    return resolved


def validate_capture(capture: dict[str, Any], role: str) -> None:
    """Require one exact PC3/Linux6.8 compile-only receipt for each role."""
    contract = CAPTURES.get(role)
    if contract is None:
        raise ValueError(f"unsupported guest stack role: {role}")
    if (capture.get("schema") != contract["schema"] or
            capture.get("status") != contract["status"] or
            capture.get("target") != "pc3@pc3" or
            capture.get("guest_hostname") != GUEST or
            capture.get("guest_kernel_release") != KERNEL):
        raise ValueError(f"{role} capture identity or qualification differs from PC3 guest contract")
    for field in ("module_installed", "module_loaded", "gpu_accessed", "cuda_execution_tested"):
        if capture.get(field) is not False:
            raise ValueError(f"{role} capture crossed the compile-only boundary: {field}")
    builder = capture.get("builder_report")
    if not isinstance(builder, dict) or builder.get("schema") != contract["builder_schema"]:
        raise ValueError(f"{role} capture lacks its pinned builder report")
    if role in ("frontend", "uvm"):
        if capture.get("qualification") != contract["qualification"]:
            raise ValueError(f"{role} capture qualification is not the expected compile-only result")
    elif capture.get("builder_qualification") != contract["builder_qualification"]:
        raise ValueError(f"{role} provider capture qualification is not the expected build")
    if role == "frontend" and builder.get("kernel_release") != KERNEL:
        raise ValueError("frontend builder report targets a different guest kernel")
    if role == "uvm":
        qualification = builder.get("qualification", {})
        if (qualification.get("level") != "compiled-frontend-bound-uvm" or
                qualification.get("module_loaded_or_installed") is not False or
                qualification.get("runtime_or_hardware_validated") is not False):
            raise ValueError("UVM builder report crosses its compile-only qualification boundary")


def _capture_file(path: Path, root: Path) -> tuple[dict[str, Any], str, Path]:
    candidate = Path(path).absolute()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"capture report is missing or not a regular file: {candidate}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("capture report is outside the canonical project")
    raw = resolved.read_bytes()
    value = json.loads(raw.decode("utf-8", "strict"))
    if not isinstance(value, dict):
        raise ValueError(f"capture report is not a JSON object: {resolved}")
    return value, hashlib.sha256(raw).hexdigest(), resolved


def _module_record(record: dict[str, Any], path: Path, role: str) -> None:
    if (not isinstance(record, dict) or
            record.get("sha256") != sha256_file(path) or
            ("bytes" in record and (type(record["bytes"]) is not int or
                                    record["bytes"] != path.stat().st_size))):
        raise ValueError(f"{role} builder module identity does not match its retrieved artifact")
    record["path"] = str(path)


def _sibling_symvers(capture: dict[str, Any], module: Path, root: Path) -> Path:
    relative_parent = module.relative_to(root).parent.as_posix()
    return resolve_captured_artifact(
        capture, root, prefix=relative_parent + "/Module.symvers", suffix="", exact=True)


def normalize_guest_reports(captures: dict[str, dict[str, Any]], root: Path = ROOT
                            ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    """Rebind four remote build reports to verified local PC3 artifacts."""
    root = Path(root).resolve(strict=True)
    for role in CAPTURES:
        if role not in captures or not isinstance(captures[role], dict):
            raise ValueError(f"missing {role} capture")
        validate_capture(captures[role], role)

    modules = {}
    for role, contract in CAPTURES.items():
        modules[role] = resolve_captured_artifact(
            captures[role], root, prefix=contract["prefix"], suffix=contract["module_suffix"])

    frontend_symvers = _sibling_symvers(captures["frontend"], modules["frontend"], root)
    kernel_symvers = resolve_captured_artifact(
        captures["frontend"], root,
        prefix=modules["frontend"].relative_to(root).parent.as_posix() +
        "/kernel-inputs/Module.symvers", suffix="", exact=True)
    open_symvers = _sibling_symvers(captures["open"], modules["open"], root)
    legacy_symvers = _sibling_symvers(captures["legacy"], modules["legacy"], root)
    symvers_by_hash = {}
    for label, path in (("kernel", kernel_symvers), ("open", open_symvers),
                        ("legacy", legacy_symvers)):
        digest = sha256_file(path)
        if digest in symvers_by_hash:
            raise ValueError("provider and kernel Module.symvers digests are ambiguous")
        symvers_by_hash[digest] = (label, path)

    reports = {role: copy.deepcopy(captures[role]["builder_report"]) for role in CAPTURES}
    _module_record(reports["frontend"].get("module"), modules["frontend"], "frontend")
    _module_record(reports["open"].get("module"), modules["open"], "Open provider")
    _module_record(reports["legacy"].get("module"), modules["legacy"], "legacy provider")
    _module_record(reports["uvm"]["build"]["modules"].get("nvidia-uvm.ko"),
                   modules["uvm"], "UVM")

    front = reports["frontend"]
    original_inputs = front.get("inputs_sha256")
    if not isinstance(original_inputs, dict):
        raise ValueError("frontend report lacks its pinned input hashes")
    normalized_inputs = {}
    for original, digest in original_inputs.items():
        if PurePosixPath(original).name != "Module.symvers":
            normalized_inputs[original] = digest
            continue
        selected = symvers_by_hash.get(str(digest).lower())
        if selected is None:
            raise ValueError("frontend Module.symvers input is not one of the captured exact providers")
        _, path = selected
        normalized_inputs[str(path)] = digest
    if len([path for path in normalized_inputs if Path(path).name == "Module.symvers"]) != 3:
        raise ValueError("frontend must pin exactly kernel, Open, and proprietary Module.symvers inputs")
    front["inputs_sha256"] = normalized_inputs

    generated = front.get("generated_outputs_sha256")
    if not isinstance(generated, dict):
        raise ValueError("frontend report lacks its generated output hashes")
    generated_symvers = [(name, digest) for name, digest in generated.items()
                         if PurePosixPath(name).name == "Module.symvers"]
    if len(generated_symvers) != 1 or generated_symvers[0][1] != sha256_file(frontend_symvers):
        raise ValueError("frontend generated Module.symvers differs from its retrieved artifact")
    front["generated_outputs_sha256"] = {
        (str(frontend_symvers) if PurePosixPath(name).name == "Module.symvers" else name): digest
        for name, digest in generated.items()
    }

    legacy_binding = reports["legacy"].get("compatibility_with_v2", {})
    if (legacy_binding.get("symvers_sha256") != sha256_file(legacy_symvers)):
        raise ValueError("legacy provider symvers does not match its captured compatibility pin")
    legacy_binding["symvers"] = str(legacy_symvers)

    uvm = reports["uvm"]
    symvers_input = uvm.get("inputs", {}).get("frontend_module_symvers", {})
    if symvers_input.get("sha256") != sha256_file(frontend_symvers):
        raise ValueError("UVM build was not bound to this exact frontend Module.symvers")
    symvers_input["path"] = str(frontend_symvers)

    artifact_hashes = {
        role: {"path": str(path), "sha256": sha256_file(path)}
        for role, path in modules.items()
    }
    artifact_hashes.update({
        "frontend_symvers": {"path": str(frontend_symvers), "sha256": sha256_file(frontend_symvers)},
        "kernel_symvers": {"path": str(kernel_symvers), "sha256": sha256_file(kernel_symvers)},
        "open_symvers": {"path": str(open_symvers), "sha256": sha256_file(open_symvers)},
        "legacy_symvers": {"path": str(legacy_symvers), "sha256": sha256_file(legacy_symvers)},
    })
    return reports, artifact_hashes


def write_private_json(path: Path, value: dict[str, Any]) -> str:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(payload).hexdigest()


def _project_file(value: str, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.absolute()
    if candidate.is_symlink() or not candidate.resolve(strict=True).is_relative_to(ROOT):
        raise ValueError(f"{label} is outside the canonical project or is a symlink")
    return candidate.resolve(strict=True)


def run(frontend_path: Path, open_path: Path, legacy_path: Path, uvm_path: Path,
        report_path: Path) -> dict[str, Any]:
    capture_paths = {"frontend": frontend_path, "open": open_path,
                     "legacy": legacy_path, "uvm": uvm_path}
    captures = {}
    sources = {}
    for role, value in capture_paths.items():
        source_path = _project_file(str(value), f"{role} capture report")
        capture, digest, path = _capture_file(source_path, ROOT)
        validate_capture(capture, role)
        captures[role] = capture
        sources[role] = {"path": str(path.relative_to(ROOT)), "sha256": digest}
    reports, artifacts = normalize_guest_reports(captures, ROOT)

    report_path = _project_file(str(report_path), "audit report destination") if report_path.exists() else Path(report_path)
    if not report_path.is_absolute():
        report_path = ROOT / report_path
    report_path = report_path.absolute()
    if not report_path.is_relative_to(ROOT) or not report_path.is_relative_to(ROOT / "evidence"):
        raise ValueError("audit report destination must be under evidence/")
    if report_path.exists() or report_path.is_symlink():
        raise FileExistsError(f"refusing to overwrite audit report: {report_path}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    normalized_dir = ROOT / "build/experiments" / f"pc3-v100-r580-stack-audit-{run_id}"
    normalized_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    normalized = {}
    normalized_paths = {}
    for role, value in reports.items():
        path = normalized_dir / f"{role}.json"
        digest = write_private_json(path, value)
        normalized_paths[role] = path
        normalized[role] = {"path": str(path.relative_to(ROOT)), "sha256": digest}

    try:
        static_audit = audit_bundle(
            normalized_paths["frontend"], normalized_paths["open"],
            normalized_paths["legacy"], normalized_paths["uvm"])
    finally:
        changed = [role for role, record in artifacts.items()
                   if sha256_file(Path(record["path"])) != record["sha256"]]
        if changed:
            raise ValueError("static audit modified captured artifacts: " + ", ".join(changed))
    return {
        "schema": "nvidia-pc3-v100-r580-hybrid-static-stack-audit-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": static_audit["status"],
        "qualification": "static-module-bundle-closure" if static_audit["status"] == "passed" else "failed",
        "target": "pc3@pc3",
        "guest_hostname": GUEST,
        "kernel_release": KERNEL,
        "source_captures": sources,
        "normalized_reports": normalized,
        "verified_artifacts": artifacts,
        "audit_wrapper_sha256": sha256_file(Path(__file__).resolve()),
        "static_audit": static_audit,
        "module_installed": False,
        "module_loaded": False,
        "gpu_accessed": False,
        "cuda_execution_tested": False,
        "runtime_or_hardware_validated": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-capture", required=True)
    parser.add_argument("--open-capture", required=True)
    parser.add_argument("--legacy-capture", required=True)
    parser.add_argument("--uvm-capture", required=True)
    parser.add_argument("--report", required=True, help="new report path under evidence/")
    args = parser.parse_args(argv)
    try:
        report_path = Path(args.report)
        if not report_path.is_absolute():
            report_path = ROOT / report_path
        report = run(Path(args.frontend_capture), Path(args.open_capture),
                     Path(args.legacy_capture), Path(args.uvm_capture), report_path)
        digest = write_private_json(report_path, report)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        parser.error(f"static PC3 R580 stack audit failed closed: {error}")
    print(json.dumps({"status": report["status"], "qualification": report["qualification"],
                      "report": str(report_path), "sha256": digest,
                      "issues": report["static_audit"]["issues"]}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
