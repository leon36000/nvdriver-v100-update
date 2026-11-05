#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Record whether the R580 isolated-tracker patch applies to pinned R595 UVM."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import replay_r580_open_patches_on_r595 as r595


PATCH = r595.PATCH_ROOT / "uvm/0007-reject-cross-gpu-tracker-dependencies.patch"
EXPECTED_CONFLICTS = {
    "kernel-open/nvidia-uvm/uvm_push.c": 1,
    "kernel-open/nvidia-uvm/uvm_gpu.c": 1,
    "kernel-open/nvidia-uvm/uvm_gpu_semaphore.c": 1,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _patch_inputs() -> tuple[str, ...]:
    paths = tuple(dict.fromkeys(re.findall(r"^\+\+\+ b/([^\n]+)$", PATCH.read_text(), re.M)))
    if not paths or any(not path.startswith("kernel-open/nvidia-uvm/") for path in paths):
        raise ValueError("unexpected source scope in the pinned R580 tracker patch")
    return paths


def probe() -> dict:
    digest, count = r595.source_tree_digest(r595.SOURCE)
    if (digest, count) != (r595.SOURCE_TREE_SHA256, r595.SOURCE_FILE_COUNT):
        raise ValueError("pinned R595.99.02 source tree changed")

    inputs = _patch_inputs()
    input_hashes = {}
    with tempfile.TemporaryDirectory(prefix="r580-tracker-r595-compat-") as temporary:
        root = Path(temporary)
        for relative in inputs:
            source = r595.SOURCE / relative
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"pinned R595 UVM input is not a regular file: {relative}")
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            input_hashes[relative] = sha256(source)

        result = subprocess.run(
            ["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(PATCH)],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        output = result.stdout + result.stderr
        rejected = {}
        for relative in inputs:
            reject = root / f"{relative}.rej"
            if reject.exists():
                rejected[relative] = reject.read_text(errors="replace")

        observed_conflicts = {
            relative: len(re.findall(r"^@@ .* @@", content, re.M))
            for relative, content in rejected.items()
        }
        expected_status = (
            result.returncode == 1
            and observed_conflicts == EXPECTED_CONFLICTS
            and not re.search(r"\bfuzz\b", output, re.I)
        )
        return {
            "schema": "r580-tracker-patch-r595-compatibility-probe-v1",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": {
                "version": "595.99.02",
                "root": str(r595.SOURCE),
                "tree_sha256": digest,
                "file_count": count,
                "files_used": input_hashes,
            },
            "patch": {
                "path": str(PATCH.relative_to(ROOT)),
                "sha256": sha256(PATCH),
                "application": "patch --batch --forward --fuzz=0 -p1",
            },
            "result": {
                "expected_r580_to_r595_conflict_observed": expected_status,
                "exit_code": result.returncode,
                "rejected_hunks_by_file": observed_conflicts,
                "rejected_hunk_text": rejected,
                "output": output,
                "scope": "temporary source projection only; no build, module, device, or host changes",
            },
        }


def write_private(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    report = probe()
    report_bytes = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    log_bytes = report["result"]["output"].encode()
    write_private(args.report, report_bytes)
    write_private(args.log, log_bytes)
    print(json.dumps({
        "status": "expected incompatibility recorded" if report["result"]["expected_r580_to_r595_conflict_observed"] else "unexpected patch behavior",
        "report": str(args.report),
        "log": str(args.log),
        "rejected_hunks_by_file": report["result"]["rejected_hunks_by_file"],
    }, indent=2, sort_keys=True))
    return 0 if report["result"]["expected_r580_to_r595_conflict_observed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
