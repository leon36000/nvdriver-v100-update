#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build and hash the bounded RM root-ID probe against pinned R580 headers."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/rm_root_id_probe.c'
UPSTREAM = ROOT / 'build/experiments/openrm580-baseline-v1/NVIDIA-kernel-module-source-580.178.04'
INCLUDE_PARTS = (
    'kernel-open/common/inc',
    'src/common/sdk/nvidia/inc',
    'src/common/inc',
    'src/common/inc/swref',
    'src/nvidia/arch/nvalloc/unix/include',
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build(output: Path, report_path: Path, cc: str = 'cc') -> dict[str, object]:
    output = output.resolve()
    report_path = report_path.resolve()
    report: dict[str, object] = {
        'schema': 'nvidia-hybrid-rm-root-id-probe-build-v1',
        'qualification': 'failed',
        'source': str(SOURCE),
        'source_sha256': sha256(SOURCE),
        'header_root': str(UPSTREAM),
        'binary': str(output),
        'report': str(report_path),
        'inputs': [],
        'command': [],
        'compiler_version': '',
        'diagnostics': '',
    }
    if report_path.exists():
        report['diagnostics'] = 'refusing to overwrite an existing output or report'
        return report

    def persist() -> dict[str, object]:
        try:
            fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            report['qualification'] = 'failed'
            report['diagnostics'] = 'report appeared during build; refusing to overwrite it'
            return report
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        return report

    if output.exists():
        report['diagnostics'] = 'refusing to overwrite an existing output or report'
        return persist()
    include_dirs = [UPSTREAM / part for part in INCLUDE_PARTS]
    if not SOURCE.is_file() or not all(path.is_dir() for path in include_dirs):
        report['diagnostics'] = 'source or pinned R580 include directory is missing'
        return persist()
    compiler = shutil.which(cc)
    if not compiler:
        report['diagnostics'] = 'C compiler not found'
        return persist()
    version = subprocess.run([compiler, '--version'], capture_output=True, text=True, timeout=10)
    report['compiler_version'] = (version.stdout or version.stderr).splitlines()[0] if version.returncode == 0 else 'unavailable'
    output.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.rm-root-id-build-', dir=output.parent) as temp_dir:
        temporary = Path(temp_dir) / 'probe'
        depfile = Path(temp_dir) / 'probe.d'
        command = [compiler, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-DNVRM=1',
                   '-MMD', '-MF', str(depfile), '-Isrc',
                   *[f'-I{path}' for path in include_dirs], str(SOURCE), '-o', str(temporary)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
        report['command'] = ['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-DNVRM=1',
                             '-MMD', '-MF', '<temporary>/probe.d', '-Isrc',
                             *[f'-I{path.relative_to(ROOT)}' for path in include_dirs],
                             str(SOURCE.relative_to(ROOT)), '-o', '<temporary>/probe']
        report['diagnostics'] = (result.stderr or result.stdout)[-12000:]
        if result.returncode != 0 or not temporary.is_file():
            return persist()
        dependencies = depfile.read_text().replace('\\\n', ' ').split(':', 1)[1].split()
        inputs = []
        for item in sorted({Path(value).resolve() for value in dependencies}):
            if item.is_file():
                inputs.append({'path': str(item), 'sha256': sha256(item)})
        report['inputs'] = inputs
        try:
            os.link(temporary, output)
        except FileExistsError:
            report['diagnostics'] = 'output appeared during build; refusing to overwrite it'
            return persist()
        report['binary_bytes'] = output.stat().st_size
        report['binary_sha256'] = sha256(output)
        report['qualification'] = 'compiled-only-no-driver-execution'
        report['diagnostics'] = result.stderr[-12000:]
    return persist()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args(argv)
    report = build(args.output, args.report, args.cc)
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get('qualification') == 'compiled-only-no-driver-execution' else 2


if __name__ == '__main__':
    raise SystemExit(main())
