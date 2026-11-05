#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the pinned VMM peer-read probe on an idle, exact SM70/SM120 GPU pair."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

try:
    from .vmm_peer_probe_contract import validate_vmm_peer_report
except ImportError:
    from vmm_peer_probe_contract import validate_vmm_peer_report


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROBE = ROOT / "build/vmm-peer-probe-v3-20261031/hybrid_cuda_vmm_peer_probe"
DEFAULT_MODULE = ROOT / "build/probe-peer-transfer-v3-20261031/hybrid_probe.sm70-sm120.fatbin"
PROBE_SHA256 = "3ebe23609679621035c14f2eec895e4df5df0cbe9bd8e00cddde23e8b9cd92e0"
BUILD_MANIFEST_SHA256 = "52daa929819bc3b82407a6f3fa16824dc9083a45ac8cd81510ded7b87f8e2e5d"
FATBIN_SHA256 = "9b6c772590c0e7ce6a95e36fb637b769eceef69856979761d739028d8b45675f"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required to hash pinned CUDA inputs")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"expected a regular file while hashing: {path}")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def decode_captured_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def clean_probe_environment(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"):
        env.pop(key, None)
    return env


def normalize_pci(value: str) -> str:
    value = value.strip().lower()
    if len(value) == 7:
        value = "0000:" + value
    if len(value) == 16 and value[:8] == "00000000":
        value = "0000" + value[8:]
    if re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", value) is None:
        raise ValueError(f"invalid PCI bus id: {value}")
    return value


def parse_expected(specs: list[str]) -> dict[int, str]:
    expected: dict[int, str] = {}
    for spec in specs:
        if "=" not in spec:
            raise ValueError("expected-device format is SM=PCI")
        sm_text, pci_text = spec.split("=", 1)
        sm = int(sm_text)
        if sm not in (70, 120) or sm in expected:
            raise ValueError("pass one exact PCI identity for each of SM70 and SM120")
        expected[sm] = normalize_pci(pci_text)
    if set(expected) != {70, 120} or expected[70] == expected[120]:
        raise ValueError("one distinct PCI identity for SM70 and SM120 is required")
    return expected


def query_idle_pair(expected: dict[int, str]) -> tuple[list[dict[str, str]], list[str]]:
    gpu_result = subprocess.run(
        ["nvidia-smi", "--query-gpu=pci.bus_id,uuid,name,memory.used,memory.total",
         "--format=csv,noheader,nounits"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=10)
    if gpu_result.returncode:
        raise RuntimeError("nvidia-smi GPU inventory failed: " + gpu_result.stderr.strip())
    inventory: list[dict[str, str]] = []
    for row in csv.reader(io.StringIO(gpu_result.stdout), skipinitialspace=True):
        if len(row) != 5:
            raise RuntimeError("nvidia-smi returned an unparseable GPU inventory row")
        inventory.append({"pci_bus_id": normalize_pci(row[0]), "uuid": row[1].strip(),
                          "name": row[2].strip(), "memory_used_mib": row[3].strip(),
                          "memory_total_mib": row[4].strip()})
    by_pci = {row["pci_bus_id"]: row for row in inventory}
    expected_pcis = set(expected.values())
    if not expected_pcis.issubset(by_pci):
        raise RuntimeError("nvidia-smi does not show both expected PCI devices")
    expected_models = {70: "v100", 120: "rtx 5080"}
    for sm, pci in expected.items():
        if expected_models[sm] not in by_pci[pci]["name"].lower():
            raise RuntimeError(f"PCI device for SM{sm} is not identified as "
                               f"the expected {expected_models[sm].upper()} model")

    app_result = subprocess.run(
        ["nvidia-smi", "--query-compute-apps=gpu_uuid,pid",
         "--format=csv,noheader,nounits"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=10)
    if app_result.returncode:
        raise RuntimeError("nvidia-smi compute-process query failed: " + app_result.stderr.strip())
    target_uuids = {by_pci[pci]["uuid"] for pci in expected_pcis}
    active: list[str] = []
    for row in csv.reader(io.StringIO(app_result.stdout), skipinitialspace=True):
        if len(row) != 2:
            if row and "no running processes" in ",".join(row).lower():
                continue
            raise RuntimeError("nvidia-smi returned an unparseable compute-process row")
        if row[0].strip() in target_uuids:
            active.append(row[1].strip())
    if active:
        raise RuntimeError("refusing to run while a compute process is active on a target GPU")
    return inventory, []


def load_build_manifest(probe: Path, module: Path) -> dict:
    manifest_path = probe.parent / "build-manifest.json"
    if sha256(probe) != PROBE_SHA256:
        raise RuntimeError("probe binary differs from its pinned SHA-256")
    if sha256(manifest_path) != BUILD_MANIFEST_SHA256:
        raise RuntimeError("probe build manifest differs from its pinned SHA-256")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "nvidia-hybrid-vmm-peer-probe-build-v1":
        raise RuntimeError("probe build manifest schema is not the pinned VMM probe build")
    if manifest.get("mode") != "explicit-vmm-access-no-cuCtxEnablePeerAccess":
        raise RuntimeError("probe build manifest does not pin the explicit CUDA VMM access mode")
    if Path(manifest["binary"]["path"]).resolve() != probe.resolve() or \
            manifest["binary"]["sha256"] != PROBE_SHA256:
        raise RuntimeError("probe binary does not match its build manifest")
    if module.resolve() != Path(manifest["fatbin"]["path"]).resolve() or \
            sha256(module) != FATBIN_SHA256 or \
            manifest["fatbin"]["sha256"] != FATBIN_SHA256:
        raise RuntimeError("kernel module is not the pinned SM70/SM120 fatbin")
    if manifest.get("links_libcuda_directly") is not False:
        raise RuntimeError("probe build must resolve libcuda dynamically")
    return manifest


def write_exclusive(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, default=DEFAULT_PROBE)
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--expected-device", action="append", required=True)
    parser.add_argument("--count", type=int, default=1024)
    parser.add_argument("--evidence", type=Path, required=True,
                        help="fresh evidence JSON path; existing files are never overwritten")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    evidence_path = args.evidence.absolute()
    if evidence_path.exists() or evidence_path.is_symlink():
        raise SystemExit(f"evidence path already exists: {evidence_path}")

    record: dict = {
        "schema": "nvidia-hybrid-vmm-peer-runner-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": os.uname().nodename,
        "kernel": os.uname().release,
        "qualification": "preflight-failed",
        "expected_devices": {},
        "gpu_inventory": [],
        "probe": {},
        "module": {},
        "runner": {"path": str(Path(__file__).resolve()),
                   "sha256": sha256(Path(__file__).resolve())},
        "report_contract": {
            "path": str(Path(__file__).with_name("vmm_peer_probe_contract.py").resolve()),
            "sha256": sha256(Path(__file__).with_name("vmm_peer_probe_contract.py").resolve()),
        },
        "libcuda": None,
        "probe_report": None,
        "probe_exit_code": None,
        "error": "",
    }
    exit_code = 2
    try:
        expected = parse_expected(args.expected_device)
        record["expected_devices"] = {str(sm): pci for sm, pci in expected.items()}
        probe = args.probe.resolve(strict=True)
        module = args.module.resolve(strict=True)
        if args.count < 1 or args.count > (1 << 20):
            raise ValueError("count must be in 1..1048576")
        if args.timeout < 1 or args.timeout > 3600:
            raise ValueError("timeout must be in 1..3600 seconds")
        manifest = load_build_manifest(probe, module)
        record["build_manifest_sha256"] = sha256(probe.parent / "build-manifest.json")
        record["probe"] = {"path": str(probe), "sha256": sha256(probe),
                           "build_manifest_sha256": manifest["binary"]["sha256"]}
        record["module"] = {"path": str(module), "sha256": sha256(module)}
        inventory, _ = query_idle_pair(expected)
        record["gpu_inventory"] = inventory

        command = [str(probe), "--module", str(module), "--count", str(args.count)]
        for sm in (70, 120):
            command.extend(["--expected-device", f"{sm}={expected[sm]}"])
        env = clean_probe_environment()
        started = time.monotonic()
        try:
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False, timeout=args.timeout,
                                    env=env)
        except subprocess.TimeoutExpired as error:
            record["qualification"] = "hardware-test-timeout"
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
            record["error"] = f"probe exceeded {args.timeout} second timeout"
            record["stderr"] = decode_captured_output(error.stderr)[:16000]
            write_exclusive(evidence_path, record)
            print(f"probe timed out; evidence: {evidence_path}", file=sys.stderr)
            return 2

        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        record["probe_exit_code"] = result.returncode
        record["stderr"] = result.stderr[:16000]
        try:
            probe_report = json.loads(result.stdout)
            validate_vmm_peer_report(probe_report, expected)
        except (json.JSONDecodeError, ValueError, KeyError, TypeError) as error:
            record["qualification"] = "invalid-probe-report"
            record["error"] = str(error)
            record["stdout"] = result.stdout[:16000]
            write_exclusive(evidence_path, record)
            print(f"probe report failed validation; evidence: {evidence_path}", file=sys.stderr)
            return 2
        record["probe_report"] = probe_report
        libcuda_path = probe_report.get("libcuda_path")
        if libcuda_path:
            library = Path(libcuda_path).resolve(strict=True)
            if "/stubs/" in str(library):
                record["qualification"] = "wrong-libcuda-loaded"
                record["error"] = "CUDA toolkit stub library was loaded instead of a driver library"
                write_exclusive(evidence_path, record)
                print(f"wrong libcuda path; evidence: {evidence_path}", file=sys.stderr)
                return 2
            record["libcuda"] = {"path": str(library), "sha256": sha256(library)}
        else:
            record["qualification"] = "probe-did-not-report-libcuda"
            record["error"] = "loaded libcuda identity is missing"
            write_exclusive(evidence_path, record)
            print(f"libcuda identity missing; evidence: {evidence_path}", file=sys.stderr)
            return 2

        if probe_report["passed"] and result.returncode == 0:
            record["qualification"] = "hardware-bidirectional-vmm-peer-read-validated"
            exit_code = 0
        elif any(d.get("kernel_attempted") for d in probe_report["directions"]):
            record["qualification"] = "hardware-vmm-peer-test-failed"
        else:
            record["qualification"] = "hardware-preflight-failed"
        if result.returncode == 0 and not probe_report["passed"]:
            record["error"] = "probe exit code contradicts its report"
        write_exclusive(evidence_path, record)
        print(f"qualification={record['qualification']} evidence={evidence_path}")
        return exit_code
    except Exception as error:
        record["error"] = str(error)
        write_exclusive(evidence_path, record)
        print(f"preflight failed; evidence: {evidence_path}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
