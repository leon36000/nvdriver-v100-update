#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run pinned llama.cpp backend operation comparisons on accepted GPUs.

The runner requires a same-host, same-kernel, same-device-selection hybrid
acceptance receipt first. It then runs the upstream `test-backend-ops` target
separately on each exact CUDA ordinal and refuses upstream's skipped-backend
false-success case. It accesses GPUs and is intended only for the authorized
PC3 test host; it does not install or load a driver module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "configs/inference/llama.cpp-cuda129-sm70v-sm120a.json"
sys.path.insert(0, str(ROOT))
from tools.llama_backend_ops_contract import (  # noqa: E402
    canonical_pci, target_cuda_ordinals, validate_backend_ops_output,
    validate_acceptance_freshness, validate_backend_source_mapping,
    validate_runtime_library_identities, all_backend_runs_passed,
)
from tools.verify_llama_cuda_artifacts import (  # noqa: E402
    VerificationError, _resolve, _resolve_dir, build_receipt, parse_cmake_cache,
    sha256_file, write_new_json,
)


def parse_expected_devices(values: list[str]) -> dict[int, str]:
    expected: dict[int, str] = {}
    for value in values:
        sm_text, separator, pci = value.partition("=")
        if not separator or not sm_text.isdecimal():
            raise ValueError("expected device must use SM=PCI format")
        sm = int(sm_text)
        if sm not in (70, 120) or sm in expected:
            raise ValueError("exactly one mapping for SM70 and SM120 is required")
        expected[sm] = canonical_pci(pci)
    if set(expected) != {70, 120} or len(set(expected.values())) != 2:
        raise ValueError("two distinct PCI identities for SM70 and SM120 are required")
    return expected


def require_authorized_test_host(hostname: str) -> None:
    """Keep this GPU workload confined to the user-authorized PC3 host."""
    if hostname != "pc3":
        raise ValueError(f"GPU workload is authorized only on PC3; current host is {hostname!r}")


def load_hybrid_acceptance(path: Path, expected: dict[int, str]) -> tuple[dict, dict[int, int], dict, int]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read hybrid acceptance receipt: {error}") from error
    if (not isinstance(receipt, dict) or
            receipt.get("schema") != "nvidia-hybrid-hardware-acceptance-v2" or
            receipt.get("qualification") != "report-contract-valid" or
            receipt.get("exit_code") != 0):
        raise ValueError("input is not a passing hardware-acceptance receipt")
    age_seconds = validate_acceptance_freshness(receipt.get("observed_at_utc"))
    if receipt.get("host") != socket.gethostname() or receipt.get("kernel_release") != os.uname().release:
        raise ValueError("hybrid acceptance receipt belongs to another host or kernel")
    selection = receipt.get("device_selection")
    if not isinstance(selection, dict):
        raise ValueError("hybrid acceptance receipt has no device-selection environment")
    for key, variable in (("cuda_visible_devices", "CUDA_VISIBLE_DEVICES"),
                          ("cuda_device_order", "CUDA_DEVICE_ORDER")):
        if key not in selection:
            raise ValueError(f"hybrid receipt predates required {variable} selection metadata")
        if selection[key] != os.environ.get(variable):
            raise ValueError(f"{variable} differs from the accepted CUDA enumeration")

    probe = receipt.get("probe")
    option_fields = {
        "managed_prefetch_requested": receipt.get("managed_prefetch_requested"),
        "cuda_graphs_requested": receipt.get("cuda_graphs_requested"),
        "performance_benchmark_requested": receipt.get("performance_benchmark_requested"),
        "peer_transfer_requested": receipt.get("peer_transfer_requested"),
    }
    if any(type(value) is not bool for value in option_fields.values()):
        raise ValueError("hybrid acceptance receipt has incomplete probe-option metadata")
    memory_mode = receipt.get("memory_mode")
    concurrent_requested = probe.get("concurrent_kernel_test_requested") if isinstance(probe, dict) else None
    if memory_mode not in ("device", "managed") or type(concurrent_requested) is not bool:
        raise ValueError("hybrid acceptance receipt has invalid memory or concurrency metadata")
    benchmark_samples = benchmark_transfer_samples = None
    if option_fields["performance_benchmark_requested"] and isinstance(probe, dict):
        targeted_rows = [row for row in probe.get("devices", [])
                         if isinstance(row, dict) and row.get("targeted") is True]
        launch_counts, transfer_counts = set(), set()
        for row in targeted_rows:
            benchmark = row.get("performance_benchmark")
            if isinstance(benchmark, dict):
                launch_counts.add(benchmark.get("samples"))
                transfer_counts.add(benchmark.get("transfer_samples"))
        if len(launch_counts) == len(transfer_counts) == 1:
            benchmark_samples = launch_counts.pop()
            benchmark_transfer_samples = transfer_counts.pop()
    validator = runpy.run_path(str(ROOT / "tests/run_hybrid_acceptance.py"))["validate_probe_report"]
    qualification = validator(
        probe, 0,
        expected_memory_mode=memory_mode,
        expected_managed_prefetch=option_fields["managed_prefetch_requested"],
        expected_cuda_graphs=option_fields["cuda_graphs_requested"],
        expected_performance_benchmark=option_fields["performance_benchmark_requested"],
        expected_device_pci_by_sm=expected,
        expected_concurrent_dispatch=concurrent_requested,
        expected_peer_transfer=option_fields["peer_transfer_requested"],
        expected_benchmark_samples=benchmark_samples,
        expected_benchmark_transfer_samples=benchmark_transfer_samples,
    )
    if qualification != "report-contract-valid":
        raise ValueError("hybrid probe did not pass the strict acceptance contract")
    ordinals = target_cuda_ordinals(probe, expected)

    artifacts = receipt.get("artifacts")
    driver_identity = artifacts.get("driver_library_observed_after_run") if isinstance(artifacts, dict) else None
    if not isinstance(driver_identity, dict) or set(driver_identity) != {"path", "bytes", "sha256"}:
        raise ValueError("hybrid receipt lacks the observed CUDA driver-library identity")
    if (probe.get("driver_library_path") != driver_identity.get("path") or
            type(driver_identity.get("bytes")) is not int or driver_identity["bytes"] <= 0 or
            not isinstance(driver_identity.get("sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", driver_identity["sha256"])):
        raise ValueError("hybrid CUDA driver-library identity is inconsistent")
    return receipt, ordinals, driver_identity, age_seconds


def load_pinned_backend_source(root: Path, relative_path: str) -> tuple[Path, Path]:
    """Resolve and validate the pinned llama.cpp CUDA ordinal-to-PCI source."""
    source_root = _resolve_dir(root, relative_path)
    source_file = _resolve(root, relative_path + "/ggml/src/ggml-cuda/ggml-cuda.cu")
    try:
        source_file.relative_to(source_root)
    except ValueError as error:
        raise ValueError("pinned CUDA backend source escapes its repository") from error
    validate_backend_source_mapping(source_file.read_text(encoding="utf-8"))
    return source_root, source_file


def verify_cached_mapped_library_objects(
        cache: dict[tuple[str, int, int, int], dict[str, Any]]) -> list[str]:
    """Recheck every captured mapping after its process exits or maps vanish."""
    errors: list[str] = []
    for key, identity in cache.items():
        mapped_path, device_major, device_minor, inode = key
        descriptor = -1
        try:
            descriptor = os.open(mapped_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            current = os.fstat(descriptor)
            if (not stat.S_ISREG(current.st_mode) or
                    os.major(current.st_dev) != device_major or
                    os.minor(current.st_dev) != device_minor or current.st_ino != inode or
                    identity.get("bytes") != current.st_size or
                    identity.get("mtime_ns") != current.st_mtime_ns or
                    identity.get("ctime_ns") != current.st_ctime_ns):
                raise ValueError("mapped library path or metadata changed after capture")
        except (OSError, ValueError) as error:
            errors.append(f"cached mapped library identity changed for {mapped_path}: {error}")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return sorted(errors)


def capture_mapped_library_identities(
        pid: int, prefixes: dict[str, str],
        cache: dict[tuple[str, int, int, int], dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Hash files through descriptors matched to the live /proc maps inode."""
    observations: dict[str, dict[tuple[str, int, int, int], dict[str, Any]]] = {
        label: {} for label in prefixes
    }
    errors: set[str] = set()
    try:
        lines = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return ({label: [] for label in prefixes},
                verify_cached_mapped_library_objects(cache))
    except OSError as error:
        return {label: [] for label in prefixes}, [f"cannot read process mappings: {error}"]

    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) < 6:
            continue
        mapped_text = fields[5]
        deleted = mapped_text.endswith(" (deleted)")
        mapped_path = mapped_text.removesuffix(" (deleted)")
        if not mapped_path.startswith("/"):
            continue
        matching = [label for label, prefix in prefixes.items()
                    if Path(mapped_path).name.startswith(prefix)]
        if not matching:
            continue
        if deleted:
            errors.update(f"{label}: mapped library was deleted before identity capture" for label in matching)
            continue
        try:
            major_text, minor_text = fields[3].split(":", 1)
            device_major, device_minor = int(major_text, 16), int(minor_text, 16)
            inode = int(fields[4], 10)
            address = fields[0]
            if inode <= 0 or not re.fullmatch(r"[0-9a-fA-F]+-[0-9a-fA-F]+", address):
                raise ValueError("mapping has invalid device, inode, or address fields")
        except ValueError as error:
            errors.update(f"{label}: invalid process mapping identity ({error})" for label in matching)
            continue
        key = (mapped_path, device_major, device_minor, inode)
        descriptor = -1
        try:
            descriptor = os.open(mapped_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or
                    os.major(before.st_dev) != device_major or
                    os.minor(before.st_dev) != device_minor or before.st_ino != inode):
                raise ValueError("opened pathname no longer identifies the mapped file object")
            identity = cache.get(key)
            if identity is not None:
                if any(identity.get(field) != getattr(before, stat_field) for field, stat_field in (
                        ("bytes", "st_size"), ("mtime_ns", "st_mtime_ns"),
                        ("ctime_ns", "st_ctime_ns"))):
                    raise ValueError("mapped file changed after identity capture")
            else:
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                after = os.fstat(descriptor)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
                    raise ValueError("mapped file object changed while being hashed")
                identity = {
                    "path": mapped_path,
                    "bytes": before.st_size,
                    "sha256": digest.hexdigest(),
                    "device_major": device_major,
                    "device_minor": device_minor,
                    "inode": inode,
                    "mtime_ns": before.st_mtime_ns,
                    "ctime_ns": before.st_ctime_ns,
                }
                cache[key] = identity
        except (OSError, ValueError) as error:
            errors.update(f"{label}: mapped object identity verification failed ({error})"
                          for label in matching)
            continue
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        for label in matching:
            observations[label][key] = identity
    return {label: list(rows.values()) for label, rows in observations.items()}, sorted(errors)


def run_backend(binary: Path, backend_name: str, library_dir: Path,
                log_path: Path, timeout_seconds: int, jobs: int,
                base_environment: dict[str, str],
                expected_runtime: dict[str, dict[str, Any]],
                expected_description: str) -> dict[str, Any]:
    command = [str(binary), "test", "-b", backend_name, "-j", str(jobs)]
    environment = base_environment.copy()
    for variable in ("LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT",
                     "LD_ORIGIN_PATH", "LD_PROFILE", "LD_PROFILE_OUTPUT",
                     "GGML_BACKEND_PATH"):
        environment.pop(variable, None)
    environment["LD_LIBRARY_PATH"] = str(library_dir)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("O_NOFOLLOW is required to create private backend-test logs")
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                 getattr(os, "O_CLOEXEC", 0), 0o600)
    start = time.monotonic()
    prefixes = {"driver": "libcuda.so"}
    prefixes.update({name: name.rsplit(".so", 1)[0] + ".so" for name in expected_runtime})
    identity_cache: dict[tuple[str, int, int, int], dict[str, Any]] = {}
    mapped_identities: dict[str, dict[tuple[str, int, int, int], dict[str, Any]]] = {
        label: {} for label in prefixes
    }
    identity_errors: set[str] = set()

    def add_validation_error(message: str) -> None:
        errors = record.setdefault("validation_errors", [])
        if message not in errors:
            errors.append(message)
        record.setdefault("validation_error", message)

    def capture_mapped_identities(pid: int) -> None:
        observed, errors = capture_mapped_library_identities(pid, prefixes, identity_cache)
        identity_errors.update(errors)
        for label, identities in observed.items():
            for identity in identities:
                key = (identity["path"], identity["device_major"],
                       identity["device_minor"], identity["inode"])
                mapped_identities[label][key] = identity

    timed_out = False
    with os.fdopen(fd, "wb") as stream:
        process = subprocess.Popen(command, cwd=ROOT, env=environment,
                                   stdout=stream, stderr=subprocess.STDOUT,
                                   close_fds=True, start_new_session=True)
        deadline = start + timeout_seconds
        while process.poll() is None:
            capture_mapped_identities(process.pid)
            if time.monotonic() >= deadline:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                break
            time.sleep(0.01)
        return_code = process.wait()
        capture_mapped_identities(process.pid)
        stream.flush()
        os.fsync(stream.fileno())

    output = log_path.read_text(encoding="utf-8", errors="replace")
    record: dict[str, Any] = {
        "command": command,
        "exit_code": return_code,
        "timed_out": timed_out,
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "log_relative_path": str(log_path.relative_to(ROOT)),
        "log_bytes": log_path.stat().st_size,
        "log_sha256": sha256_file(log_path),
        "mapped_libcuda_paths": sorted(identity["path"] for identity in mapped_identities["driver"].values()),
    }
    try:
        record["test_summary"] = validate_backend_ops_output(
            output, return_code, backend_name, expected_description)
    except ValueError as error:
        add_validation_error(str(error))
    identities = sorted(mapped_identities["driver"].values(), key=lambda identity: identity["path"])
    record["mapped_libcuda_identities"] = identities
    if len(identities) != 1:
        add_validation_error("expected exactly one verified mapped CUDA driver library")
    observed_runtime: dict[str, list[dict[str, Any]]] = {}
    for name, expected in expected_runtime.items():
        observed_runtime[name] = sorted(mapped_identities[name].values(), key=lambda identity: identity["path"])
    record["mapped_runtime_library_identities"] = observed_runtime
    try:
        validate_runtime_library_identities(observed_runtime, expected_runtime)
    except ValueError as error:
        add_validation_error(str(error))
    if identity_errors:
        record["mapping_identity_errors"] = sorted(identity_errors)
        add_validation_error("one or more mapped library identities could not be proven")
    return record


def safe_evidence_directory(root: Path, value: Path) -> Path:
    project_root = root.resolve(strict=True)
    evidence_root = (root / "evidence").resolve(strict=True)
    try:
        evidence_root.relative_to(project_root)
    except ValueError as error:
        raise ValueError("project evidence/ directory resolves outside the project") from error
    candidate = value if value.is_absolute() else root / value
    if candidate.exists() or candidate.is_symlink():
        raise ValueError("evidence output directory already exists")
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(evidence_root)
    except ValueError as error:
        raise ValueError("evidence output directory must be below project evidence/") from error
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance-receipt", type=Path, required=True)
    parser.add_argument("--expected-device", action="append", default=[], metavar="SM=PCI")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--evidence-dir", type=Path, required=True,
                        help="new output directory below evidence/; existing paths are refused")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.timeout <= 21600 or not 1 <= args.jobs <= 32:
            raise ValueError("timeout must be 1..21600 seconds and jobs must be 1..32")
        if "GGML_CUDA_DEVICES" in os.environ:
            raise ValueError("unset GGML_CUDA_DEVICES so backend ordinals match physical CUDA ordinals")
        require_authorized_test_host(socket.gethostname())
        expected = parse_expected_devices(args.expected_device)
        acceptance_path = args.acceptance_receipt.resolve(strict=True)
        acceptance, ordinals, driver_identity, acceptance_age = load_hybrid_acceptance(
            acceptance_path, expected)
        config_path = args.config if args.config.is_absolute() else ROOT / args.config
        config_path = config_path.resolve(strict=True)
        try:
            config_path.relative_to(ROOT.resolve(strict=True))
        except ValueError as error:
            raise ValueError("profile config must remain within the project") from error
        profile = json.loads(config_path.read_text(encoding="utf-8"))
        verification = build_receipt(ROOT, config_path)
        source_root, source_file = load_pinned_backend_source(
            ROOT, profile["source"]["relative_path"])
        binary_spec = [row for row in profile["build"]["artifacts"]
                       if row.get("name") == "test-backend-ops"]
        if len(binary_spec) != 1:
            raise ValueError("profile must pin exactly one test-backend-ops executable")
        binary = _resolve(ROOT, binary_spec[0]["relative_path"])
        if not os.access(binary, os.X_OK):
            raise ValueError("test-backend-ops is not executable")
        cache = parse_cmake_cache(_resolve(ROOT, profile["build"]["relative_path"] + "/CMakeCache.txt"))
        if cache.get("GGML_BACKEND_DL") != "OFF" or cache.get("LLAMA_BUILD_TESTS") != "ON":
            raise ValueError("profile does not pin statically linked CUDA backends and test targets")
        toolkit_root = Path(cache["CUDAToolkit_ROOT"]).resolve(strict=True)
        toolkit_root.relative_to(ROOT.resolve(strict=True))
        library_dir = (toolkit_root / "lib").resolve(strict=True)
        if not (library_dir / "libcudart.so.12").is_file() or not (library_dir / "libcublas.so.12").is_file():
            raise ValueError("profile CUDA runtime libraries are missing")
        expected_runtime = {
            dependency["name"]: {
                "path": dependency["resolved_path"],
                "bytes": dependency["size_bytes"],
                "sha256": dependency["sha256"],
                "device_major": dependency["device_major"],
                "device_minor": dependency["device_minor"],
                "inode": dependency["inode"],
            }
            for dependency in verification["build"]["runtime_dependencies"]
        }
        if not expected_runtime:
            raise ValueError("profile does not pin CUDA runtime dependencies")
        output_dir = safe_evidence_directory(ROOT, args.evidence_dir)
        output_dir.mkdir(parents=True, mode=0o700)
        os.chmod(output_dir, 0o700)
    except (OSError, KeyError, json.JSONDecodeError, VerificationError, ValueError) as error:
        print(f"llama backend-ops preflight failed: {error}", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    environment_selection = acceptance["device_selection"]
    base_environment = os.environ.copy()
    for variable, field in (("CUDA_VISIBLE_DEVICES", "cuda_visible_devices"),
                            ("CUDA_DEVICE_ORDER", "cuda_device_order")):
        value = environment_selection[field]
        if value is None:
            base_environment.pop(variable, None)
        else:
            base_environment[variable] = value

    results = []
    description_fragments = {70: "Tesla V100", 120: "GeForce RTX 5080"}
    for sm in (70, 120):
        try:
            current_acceptance_age = validate_acceptance_freshness(
                acceptance.get("observed_at_utc"))
        except ValueError as error:
            message = f"acceptance expired before SM{sm} run: {error}"
            results.append({"sm": sm, "not_run": True,
                            "validation_error": message,
                            "validation_errors": [message]})
            continue
        backend_name = f"CUDA{ordinals[sm]}"
        log_path = output_dir / f"backend-ops-sm{sm}-{now}.log"
        result = run_backend(binary, backend_name, library_dir, log_path,
                             args.timeout, args.jobs, base_environment, expected_runtime,
                             description_fragments[sm])
        result["sm"] = sm
        result["pci_bus_id"] = expected[sm]
        result["cuda_ordinal"] = ordinals[sm]
        result["acceptance_age_seconds_at_start"] = current_acceptance_age
        mapped = result.get("mapped_libcuda_identities", [])
        if (len(mapped) != 1 or
                any(mapped[0].get(key) != driver_identity.get(key)
                    for key in ("path", "bytes", "sha256"))):
            error = "application process loaded a different CUDA driver library than the accepted probe"
            result.setdefault("validation_errors", []).append(error)
            result.setdefault("validation_error", error)
        if sha256_file(binary) != binary_spec[0]["sha256"]:
            error = "test-backend-ops executable changed during execution"
            result.setdefault("validation_errors", []).append(error)
            result.setdefault("validation_error", error)
        results.append(result)

    passed = all_backend_runs_passed(results)
    receipt = {
        "schema": "nvidia-hybrid-llama-backend-ops-v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "qualification": "per-device-backend-ops-passed" if passed else "failed",
        "proof_level": "GPU_RUNTIME_TESTED_PER_DEVICE_AFTER_SAME_PROCESS_HYBRID_KERNEL_ACCEPTANCE" if passed else "GPU_RUNTIME_TEST_FAILED_OR_INCOMPLETE",
        "host": socket.gethostname(),
        "kernel_release": os.uname().release,
        "hybrid_acceptance_receipt": {
            "path": str(acceptance_path),
            "sha256": sha256_file(acceptance_path),
            "qualification": acceptance["qualification"],
            "age_seconds_at_start": acceptance_age,
        },
        "llama_cpp": {
            "source_commit": verification["source"]["commit"],
            "profile_id": verification["profile_id"],
            "test_backend_ops": {
                "path": binary_spec[0]["relative_path"],
                "sha256": sha256_file(binary),
            },
            "cuda_toolkit_root": str(toolkit_root),
            "runtime_library_directory": str(library_dir),
            "runtime_dependencies": expected_runtime,
            "backend_ordinal_mapping": {
                "source_path": str(source_file.relative_to(ROOT)),
                "source_sha256": sha256_file(source_file),
                "source_root": str(source_root.relative_to(ROOT)),
                "source_contract": "ggml CUDA index i names CUDAi and derives PCI ID from the mapped physical CUDA ordinal",
                "GGML_CUDA_DEVICES": "unset; virtual backend duplication is prohibited",
            },
            "p2p_enabled": False,
        },
        "cuda_selection_environment": {
            "CUDA_VISIBLE_DEVICES": environment_selection["cuda_visible_devices"],
            "CUDA_DEVICE_ORDER": environment_selection["cuda_device_order"],
        },
        "cuda_driver_library": driver_identity,
        "devices": results,
        "same_process_llama_inference_validated": False,
        "hybrid_driver_validated": False,
        "limitations": [
            "test-backend-ops runs separately on each CUDA backend; it is not mixed-GPU inference.",
            "The test emits a GPU model description but not a PCI bus ID; PCI identity binding is inherited from the accepted probe and pinned ggml source mapping.",
            "The required same-process driver probe is a prerequisite but this app test does not install or load a driver module.",
            "P2P was compiled out by the pinned build profile and is not evaluated by this receipt.",
        ],
    }
    receipt_path = output_dir / f"llama-backend-ops-{now}.json"
    try:
        write_new_json(receipt_path, receipt)
    except OSError as error:
        print(f"could not write llama backend-ops receipt: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"status": receipt["qualification"],
                      "receipt": str(receipt_path.relative_to(ROOT)),
                      "devices": len(results)}, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
