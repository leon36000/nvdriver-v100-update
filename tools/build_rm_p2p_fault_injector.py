#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a hash-pinned, process-local R580 P2P fault-injection shim."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/rm_p2p_fault_injector.c"
ASSEMBLY_SOURCE = ROOT / "src/rm_p2p_fault_injector.S"
SOURCE_ROOT_CANDIDATES = (
    ROOT / "build/experiments/local-rm90e6-master-route-v3-20261030"
    / "private-provider-v2/source",
    ROOT / "build/experiments/r58019607-proprietary-module-build-v4-20261029"
    / "source",
)
PINNED_HEADERS = {
    "common/inc/nvtypes.h": "e3901c0991b3a3dc77fffc2269fee84661bdda8a5bc43c0fe70a620af05edd5b",
    "common/inc/nvos.h": "07f9f453afbf080750663abc9e04e2d3b55500887303ba03bd6855916d2405bd",
    "hybrid-sdk/nvidia/arch/nvalloc/unix/include/nv_escape.h": "12850ee7368dbfeba1e2392f9ff7fb44563d88ed12cbf478d0c0f61a03763570",
    "common/inc/nv-ioctl-numbers.h": "7f449a019521f2f858a2d485eed1ee0fa4a8ffc82c9aecd484be5d3f6821f87d",
    "hybrid-sdk/common/sdk/nvidia/inc/class/cl503c.h": "58db3118f0cd03b42c927043354e6471be75b6e4a2bba3c28927941d1b1c3428",
    "hybrid-sdk/common/sdk/nvidia/inc/ctrl/ctrl503c.h": "78ac9e168e017203611f5a1b5e43d0a46c5e57f5033c58c62b7d3eec5257017b",
}
FLAGS = ("-std=gnu11", "-O2", "-fPIC", "-fstack-protector-strong",
         "-D_FORTIFY_SOURCE=2", "-Wall", "-Wextra", "-Wformat=2", "-Werror")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select_source_root() -> Path | None:
    for candidate in SOURCE_ROOT_CANDIDATES:
        sdk = candidate / "hybrid-sdk"
        include_dirs = (
            candidate / "common/inc",
            sdk / "common/inc",
            sdk / "common/sdk/nvidia/inc",
            sdk / "nvidia/arch/nvalloc/unix/include",
        )
        if not all(path.is_dir() for path in include_dirs):
            continue
        try:
            if all(sha256(candidate / name) == expected
                   for name, expected in PINNED_HEADERS.items()):
                return candidate
        except OSError:
            continue

    return None


SOURCE_ROOT = _select_source_root()
SDK = SOURCE_ROOT / "hybrid-sdk" if SOURCE_ROOT is not None else None
INCLUDE_DIRS = (() if SOURCE_ROOT is None or SDK is None else (
    SOURCE_ROOT / "common/inc",
    SDK / "common/inc",
    SDK / "common/sdk/nvidia/inc",
    SDK / "nvidia/arch/nvalloc/unix/include",
))


def persist_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def dependency_paths(depfile: Path) -> list[Path]:
    text = depfile.read_text(encoding="utf-8").replace("\\\n", " ")
    if ":" not in text:
        raise ValueError("compiler dependency output is malformed")
    paths = {Path(name).resolve(strict=True)
             for name in shlex.split(text.split(":", 1)[1])}
    if not paths or any(not path.is_relative_to(ROOT) for path in paths):
        raise ValueError("compiler dependency closure escapes the project")
    return sorted(paths)


def build(output: Path, report_path: Path, cc: str = "cc") -> dict[str, object]:
    if os.path.lexists(output) or os.path.lexists(report_path):
        raise ValueError("output or report already exists")
    if (SOURCE_ROOT is None or SDK is None or
            not SOURCE.is_file() or not ASSEMBLY_SOURCE.is_file() or
            not all(path.is_dir() for path in INCLUDE_DIRS)):
        raise ValueError("pinned R580.196.07 source or SDK include tree is incomplete")
    header_hashes = {name: sha256(SOURCE_ROOT / name) for name in PINNED_HEADERS}
    if header_hashes != PINNED_HEADERS:
        raise ValueError("pinned R580.196.07 SDK header hashes differ")
    compiler = shutil.which(cc)
    if compiler is None:
        raise ValueError("C compiler is unavailable")

    output.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    created_output = False
    try:
        with tempfile.TemporaryDirectory(prefix="rm-p2p-fault-build-",
                                         dir=output.parent) as directory:
            staged = Path(directory) / "libhybrid_rm_p2p_fault.so"
            depfile = Path(directory) / "dependencies.d"
            preflight = [compiler, *FLAGS, "-DNVRM=1",
                         *["-I" + str(path) for path in INCLUDE_DIRS]]
            dependency_result = subprocess.run(
                [*preflight, "-MM", "-MF", str(depfile), str(SOURCE)],
                cwd=ROOT, capture_output=True, text=True,
                timeout=30, check=False)
            if dependency_result.returncode != 0 or not depfile.is_file():
                raise RuntimeError("fault injector dependency scan failed: " +
                                   (dependency_result.stderr[-2000:] or
                                    dependency_result.stdout[-2000:]))
            dependencies = sorted(set(dependency_paths(depfile) +
                                      [ASSEMBLY_SOURCE.resolve(strict=True)]))
            dependency_hashes_before = {str(path.relative_to(ROOT)): sha256(path)
                                        for path in dependencies}
            expected_header_paths = {
                str((SOURCE_ROOT / name).relative_to(ROOT)): digest
                for name, digest in PINNED_HEADERS.items()}
            if (str(SOURCE.relative_to(ROOT)) not in dependency_hashes_before or
                    str(ASSEMBLY_SOURCE.relative_to(ROOT)) not in dependency_hashes_before or
                    any(dependency_hashes_before.get(path) != digest
                        for path, digest in expected_header_paths.items())):
                raise ValueError("compiler dependency closure does not match pinned source headers")
            command = [*preflight,
                       "-shared", "-Wl,-z,relro,-z,now", "-Wl,--no-undefined",
                       str(SOURCE), str(ASSEMBLY_SOURCE), "-ldl", "-pthread",
                       "-o", str(staged)]
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
            result = subprocess.run(command, cwd=ROOT, env=environment,
                                    capture_output=True, text=True,
                                    timeout=60, check=False)
            if result.returncode != 0 or not staged.is_file():
                raise RuntimeError("fault injector compilation failed: " +
                                   (result.stderr[-2000:] or result.stdout[-2000:]))
            artifact_hash = sha256(staged)
            artifact_bytes = staged.stat().st_size
            if artifact_bytes < 4096 or staged.read_bytes()[:6] != b"\x7fELF\x02\x01":
                raise RuntimeError("compiler output is not an ELF64 shared object")
            if int.from_bytes(staged.read_bytes()[16:18], "little") != 3 or \
                    int.from_bytes(staged.read_bytes()[18:20], "little") != 62:
                raise RuntimeError("compiler output is not an x86_64 ELF shared object")
            dependency_hashes_after = {str(path.relative_to(ROOT)): sha256(path)
                                       for path in dependencies}
            if dependency_hashes_after != dependency_hashes_before:
                raise RuntimeError("source or SDK headers changed during compilation")
            report: dict[str, object] = {
                "schema": "nvidia-hybrid-rm-p2p-fault-injector-build-v3",
                "built_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "driver_source_version": "R580.196.07 SDK headers verified against fixed SHA-256 pins",
                "source_root": {
                    "path": str(SOURCE_ROOT.relative_to(ROOT)),
                    "headers": header_hashes,
                },
                "source": {"path": str(SOURCE), "sha256": sha256(SOURCE)},
                "assembly_source": {
                    "path": str(ASSEMBLY_SOURCE.relative_to(ROOT)),
                    "sha256": sha256(ASSEMBLY_SOURCE)},
                "pinned_headers": header_hashes,
                "dependency_sha256": dependency_hashes_before,
                "compiler": {"path": compiler,
                             "version": subprocess.run([compiler, "--version"],
                                                        capture_output=True, text=True,
                                                        timeout=10, check=False).stdout.splitlines()[0]},
                "compile_flags": list(FLAGS),
                "artifact": {"path": str(output.resolve()), "bytes": artifact_bytes,
                             "sha256": artifact_hash},
                "evidence_state": "compiled; synthetic fixture results belong to the separate software-validation receipt; no GPU or kernel module tested",
                "hardware_execution_validated": False,
            }
            report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
            os.link(staged, output)
            created_output = True
            persist_exclusive(report_path, report_bytes)
            return report
    except Exception:
        if created_output:
            try:
                output.unlink()
            except OSError:
                pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    try:
        report = build(args.output, args.report, args.cc)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
