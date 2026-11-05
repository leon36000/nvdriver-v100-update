#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acquire exact R580 firmware as local data; never install or execute it.

Uses existing configured APT indexes, apt-get download, dpkg-deb --field and
--extract only. No apt update, package installation, maintainer scripts, system
firmware writes, driver loading, GPU, SSH, VM or firmware flash operation.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'nvidia-firmware-580-580.178.04'
VERSION = '580.178.04-0ubuntu0.26.04.1'
SOURCE_PACKAGE = 'nvidia-graphics-drivers-580'
PACKAGE_SHA256 = 'e79b39a7e395ffc02696de453f302cdaae31d193b5d81c0b9562a3af2dd94636'
PACKAGE_BYTES = 76005520
REQUESTS = ('nvidia/580.178.04/gsp_tu10x.bin', 'nvidia/580.178.04/gsp_ga10x.bin')
CACHE = ROOT / '.cache/canary-firmware580'


def paragraphs(text):
    records, record, previous = [], {}, None
    for line in text.splitlines() + ['']:
        if not line.strip():
            if record:
                records.append(record)
                record, previous = {}, None
        elif line[:1].isspace():
            if previous is None:
                raise ValueError('APT/control continuation without a field')
            record[previous] += '\n' + line.strip()
        else:
            key, separator, value = line.partition(':')
            if not separator or key in record:
                raise ValueError('malformed or duplicate APT/control field')
            record[key], previous = value.strip(), key
    return records


def select_metadata(text):
    records = paragraphs(text)
    if len(records) != 1:
        raise ValueError('exactly one APT record for the pinned package/version is required')
    item = records[0]
    required = {'Package': PACKAGE, 'Version': VERSION, 'Architecture': 'amd64', 'Source': SOURCE_PACKAGE}
    if any(item.get(key) != value for key, value in required.items()):
        raise ValueError('APT record is not the exact R580 firmware package/version/source/architecture')
    filename = PurePosixPath(item.get('Filename', ''))
    if (not item.get('Filename') or filename.is_absolute() or '..' in filename.parts or
            not str(filename).endswith('.deb')):
        raise ValueError('unsafe or absent APT package filename')
    if not re.fullmatch(r'[0-9a-f]{64}', item.get('SHA256', '')):
        raise ValueError('missing or malformed APT SHA256')
    if not item.get('Size', '').isdigit() or int(item['Size']) <= 0:
        raise ValueError('missing or malformed APT package size')
    return item


def verify_file(path, size=None, sha256=None):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('refusing symlink artifact: ' + str(path))
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError('artifact is not a regular file: ' + str(path))
    with resolved.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    count = resolved.stat().st_size
    if size is not None and count != size:
        raise ValueError('artifact size differs from pinned metadata: ' + str(path))
    if sha256 is not None and digest != sha256:
        raise ValueError('artifact SHA256 differs from pinned metadata: ' + str(path))
    return {'path': str(resolved), 'bytes': count, 'sha256': digest}


def inventory_extracted(tree):
    tree = Path(tree).resolve(strict=True)
    blobs = []
    for request in REQUESTS:
        candidates = [tree / prefix / request for prefix in ('usr/lib/firmware', 'lib/firmware')]
        matches = [path for path in candidates if path.exists() or path.is_symlink()]
        if not matches:
            raise FileNotFoundError('missing exact firmware request: ' + request)
        if len(matches) != 1 or not matches[0].resolve(strict=True).is_relative_to(tree):
            raise ValueError('ambiguous or escaping firmware path: ' + request)
        blobs.append({'request': request, **verify_file(matches[0])})
    copyright_path = tree / 'usr/share/doc' / PACKAGE / 'copyright'
    if not copyright_path.resolve(strict=True).is_relative_to(tree):
        raise ValueError('copyright file escapes extracted package')
    licenses = [verify_file(copyright_path)]
    return blobs, licenses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'evidence/canary-firmware580-20261019.json')
    parser.add_argument('--deb', type=Path, help='reuse this local exact .deb after index/hash checks')
    args = parser.parse_args()
    report_path = args.report.resolve()
    if report_path.exists() or not report_path.is_relative_to(ROOT / 'evidence'):
        parser.error('a new report path under evidence/ is required')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report = {'schema': 'nvidia-hybrid-canary-firmware-v1', 'observed_at_utc': stamp,
        'status': 'not-started', 'qualification': 'not-acquired', 'steps': [],
        'scope': 'exact same-branch original firmware data snapshot for local canary packaging',
        'loaded_or_installed': False, 'hardware_validated': False, 'blob_executed': False,
        'system_firmware_modified': False, 'maintainer_scripts_executed': False,
        'apt_update_executed': False, 'gpu_accessed': False, 'ssh_or_vm_operation': False,
        'firmware_blobs': [], 'license_files': [],
        'trust_basis': 'existing configured APT index metadata plus pinned package SHA256/size; no index refresh'}
    def command(name, argv, cwd=ROOT, timeout=300):
        start = time.monotonic()
        log = ROOT / 'evidence/logs' / ('canary-firmware580-' + name + '-' + stamp + '.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=timeout, check=False)
            output, error, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            output, error, code = '', 'command timed out', 124
        log.write_text(output + '\n--- stderr ---\n' + error)
        report['steps'].append({'name': name, 'argv': argv, 'cwd': str(cwd), 'exit_code': code,
            'duration_seconds': round(time.monotonic()-start, 3), **verify_file(log)})
        if code:
            raise RuntimeError(name + ' failed; see ' + str(log))
        return output
    try:
        raw = command('apt-index', ['apt-cache', 'show', PACKAGE + '=' + VERSION])
        metadata = select_metadata(raw)
        report['apt_index_metadata'] = metadata
        if metadata['SHA256'] != PACKAGE_SHA256 or int(metadata['Size']) != PACKAGE_BYTES:
            raise ValueError('APT index differs from the recorded exact-version package digest/size')
        CACHE.mkdir(parents=True, exist_ok=True)
        candidates = [args.deb] if args.deb is not None else (
            sorted((ROOT / '.cache').rglob('nvidia-firmware*580*.deb')) +
            sorted(Path('/var/cache/apt/archives').glob('nvidia-firmware*580*.deb')))
        deb = None
        report['rejected_local_candidates'] = []
        for candidate in candidates:
            try:
                verify_file(candidate, PACKAGE_BYTES, PACKAGE_SHA256)
                deb = candidate.resolve(strict=True)
                report['package_reused'] = True
                break
            except (OSError, ValueError) as error:
                report['rejected_local_candidates'].append({'path': str(candidate), 'error': str(error)})
                if args.deb is not None:
                    raise
        if deb is None:
            download = Path(tempfile.mkdtemp(prefix='download-', dir=CACHE))
            command('download-only', ['apt-get', 'download', PACKAGE + '=' + VERSION], download)
            downloads = list(download.glob('*.deb'))
            if len(downloads) != 1:
                raise ValueError('exact download did not produce one .deb')
            deb = downloads[0]
            verify_file(deb, PACKAGE_BYTES, PACKAGE_SHA256)
            report['package_reused'] = False
        control = paragraphs(command('package-control', ['dpkg-deb', '--field', str(deb)]))
        if len(control) != 1 or any(control[0].get(key) != metadata[key] for key in
                                  ('Package', 'Version', 'Architecture', 'Source')):
            raise ValueError('downloaded package control identity differs from exact APT record')
        report['package'] = {'name': PACKAGE, 'version': VERSION, 'architecture': 'amd64',
            'source': SOURCE_PACKAGE, **verify_file(deb, PACKAGE_BYTES, PACKAGE_SHA256)}
        report['package_control'] = control[0]
        extracted = CACHE / ('extracted-' + stamp)
        if extracted.exists():
            raise ValueError('refusing to overwrite extracted firmware snapshot')
        command('extract-data-only', ['dpkg-deb', '--extract', str(deb), str(extracted)])
        report['extracted_root'] = str(extracted)
        report['firmware_blobs'], report['license_files'] = inventory_extracted(extracted)
        report['provenance_files'] = [verify_file(path) for path in sorted(
            (extracted / 'usr/share/doc' / PACKAGE).glob('*')) if path.is_file() and path.name != 'copyright']
        report['qualification'] = 'downloaded-extracted-hash-verified-never-loaded'
        report['status'] = 'acquired-original-firmware-data-only'
        code = 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(status='blocked-exact-firmware-not-acquired', error=str(error))
        code = 2
    report['tool'] = verify_file(Path(__file__))
    report['test_source'] = verify_file(ROOT / 'tests/test_canary_firmware.py')
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open('x') as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'report': str(report_path), 'status': report['status'],
        'error': report.get('error'), 'firmware_files': len(report['firmware_blobs'])}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
