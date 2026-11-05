#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the fully replayed R595 private Open provider without installing it."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REPLAY_REPORT = ROOT / 'evidence/r595-debugger-bridge-replay-v3-20261101.json'
REPLAY_REPORT_SHA256 = 'd35a1b8435913763ccf27739157523321ce67223fd0e781eb8fa695cb7fb9fbb'
R595_UPSTREAM_SOURCE = (ROOT / 'build/research/open-gpu-kernel-modules-595.99.02/source/'
                        'open-gpu-kernel-modules-595.99.02')
R595_CORE = Path('/usr/src/nvidia-595.99.02/nvidia/nv-kernel.o_binary')
R595_CORE_SHA256 = 'c19870e43606b4358d9274c4d3dec2adb1822d65ce1203520a8184cf043cafe8'
R595_FRONTEND_SYMVERS = ROOT / 'build/experiments/r595-syncboost-nvidia-frontend-v1/Module.symvers'
R595_FRONTEND_SYMVERS_SHA256 = 'dbcf0cc653a970395534635d7ef533c3626112a41b12f8b5cbaf6504bb903e08'
KMOD_SOFTDEP_PATCH = ROOT / 'patches/r595.99.02/0014-open-kmod-softdep-space-separators.patch'
KMOD_SOFTDEP_PATCH_SHA256 = '6384b2ec99b5768a751cc71edda3bdda4c326fe9f60f80a7b76dd8afc4bfaeaf'
KMOD_SOFTDEP_SOURCE_SHA256 = '9dc820124a9f568d38d35c324bac8e845ddbc7158959ac94ed0000248749fb61'
KMOD_SOFTDEP_PATCHED_SOURCE_SHA256 = 'ffb79501c6725ade872304e5b826973011097002f122fed11f7f201c47f965ac'
KMOD_SOFTDEP_VALUE = 'pre: ecdh_generic ecdsa_generic'
KERNEL_RELEASE = '7.0.0-38-generic'
SHARE_POLICY_EXPORT = 'hybrid580_open_control_session_client_share_policy_v1'
SYNC_BOOST_EXPORT = 'hybrid580_open_control_session_sync_boost_groups_v1'
DEBUGGER_ALLOC_EXPORT = 'hybrid580_open_control_session_debugger_alloc_v1'
DEBUGGER_MASK_EXPORT = 'hybrid580_open_control_session_debugger_exception_mask_v1'
BUILD_QUALIFICATION = 'compiled-replayed-r595-private-open-debugger-provider'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_replay_report(report: dict) -> None:
    required = {
        'qualification': 'all-r580-open-patches-apply-to-r595-source',
        'source_version': '595.99.02',
        'patch_count': 45,
        'patches_attempted': 45,
        'source_tree_unchanged': True,
        'inputs_unchanged': True,
        'patch_inputs_unchanged': True,
        'baseline_symvers_unchanged': True,
        'build_version_api_header_unchanged': True,
        'pm_provider_api_headers_unchanged': True,
        'r595_source_modified': False,
        'module_compiled': False,
        'module_loaded': False,
        'hardware_tested': False,
    }
    for key, expected in required.items():
        if report.get(key) != expected:
            raise ValueError(f'R595 patch-replay report gate failed: {key}')
    records = report.get('patch_records')
    if not isinstance(records, list) or len(records) != 45:
        raise ValueError('R595 patch-replay record count mismatch')
    for patch_name in ('0047-private-open-client-share-policy.patch',
                       '0048-private-open-sync-boost-groups.patch',
                       '0049-private-open-control-export-prototypes.patch',
                       '0050-private-open-debugger-bridge.patch'):
        matching = [item for item in records if item.get('patch') == patch_name]
        if len(matching) != 1 or matching[0].get('exit_code') != 0 or \
                matching[0].get('offset_or_fuzz') is not False:
            raise ValueError(f'R595 {patch_name} was not applied exactly')


def build_command(source: Path, jobs: int) -> list[str]:
    if type(jobs) is not int or jobs < 1:
        raise ValueError('jobs must be a positive integer')
    return ['make', '-C', str(Path(source) / 'kernel-open'),
            'KERNEL_UNAME=' + KERNEL_RELEASE,
            'NV_KERNEL_MODULES=nvidia nvidia-uvm',
            'KBUILD_EXTRA_SYMBOLS=' + str(R595_FRONTEND_SYMVERS),
            '-j' + str(jobs), 'modules']


def source_from_replay_report(report: dict) -> Path:
    work = Path(report.get('work_dir', '')).absolute()
    upstream = Path(report.get('source', '')).absolute()
    if upstream != R595_UPSTREAM_SOURCE or \
            upstream.name != 'open-gpu-kernel-modules-595.99.02':
        raise ValueError('replay source path does not match its report')
    return work / 'source'


def validate_share_policy_export(symvers_text: str) -> None:
    matches = []
    for line in symvers_text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == SHARE_POLICY_EXPORT:
            matches.append(fields)
    if len(matches) != 1 or matches[0][2] != 'hybrid580_open' or \
            matches[0][3] != 'EXPORT_SYMBOL':
        raise ValueError('R595 candidate lacks the exact namespaced share-policy export')


def validate_sync_boost_export(symvers_text: str) -> None:
    matches = []
    for line in symvers_text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == SYNC_BOOST_EXPORT:
            matches.append(fields)
    if len(matches) != 1 or matches[0][2] != 'hybrid580_open' or \
            matches[0][3] != 'EXPORT_SYMBOL':
        raise ValueError('R595 candidate lacks the exact namespaced sync-boost export')


def validate_debugger_bridge_exports(symvers_text: str) -> None:
    for symbol in (DEBUGGER_ALLOC_EXPORT, DEBUGGER_MASK_EXPORT):
        matches = []
        for line in symvers_text.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[1] == symbol:
                matches.append(fields)
        if len(matches) != 1 or matches[0][2] != 'hybrid580_open' or \
                matches[0][3] != 'EXPORT_SYMBOL':
            raise ValueError('R595 candidate lacks the exact namespaced debugger export: ' + symbol)


def validate_output_paths(work: Path, report: Path, *, check_exists: bool = True) -> None:
    for path, allowed in ((Path(work).absolute(), ROOT / 'build/experiments'),
                          (Path(report).absolute(), ROOT / 'evidence')):
        if not path.is_relative_to(allowed) or any(
                parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError('output must stay below a canonical project output root')
        if check_exists and path.exists():
            raise ValueError('refusing to overwrite existing output: ' + str(path))


def replay_artifacts(report: dict) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for item in report.get('adapted_bootstrap_files', []):
        artifacts[item['path']] = item['sha256']
    for record in report.get('patch_records', []):
        for item in record.get('adapted_artifacts', []):
            artifacts[item['path']] = item['sha256']
    if not artifacts:
        raise ValueError('replay report has no source artifact hashes')
    return artifacts


def validate_replayed_source(source: Path, report: dict) -> dict[str, str]:
    source = Path(source)
    verified = {}
    for relative, expected in replay_artifacts(report).items():
        rel = Path(relative)
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('unsafe source artifact path in replay report')
        path = source / rel
        if path.is_symlink() or not path.is_file() or sha256(path) != expected:
            raise ValueError('replayed source artifact hash mismatch: ' + relative)
        verified[relative] = expected
    nv_source = source / 'kernel-open/nvidia/nv.c'
    kbuild = source / 'kernel-open/nvidia/nvidia.Kbuild'
    source_text = nv_source.read_text() if nv_source.is_file() else ''
    if not nv_source.is_file() or SHARE_POLICY_EXPORT not in source_text or \
            SYNC_BOOST_EXPORT not in source_text or \
            DEBUGGER_ALLOC_EXPORT not in source_text or \
            DEBUGGER_MASK_EXPORT not in source_text:
        raise ValueError('R595 replayed source lacks a root-control provider')
    if not kbuild.is_file() or 'obj-m += hybrid580_open.o' not in kbuild.read_text():
        raise ValueError('R595 replayed source is not namespaced as hybrid580_open')
    return verified


def apply_kmod_softdep_overlay(source: Path) -> dict:
    """Normalize the R595 softdep list delimiter for kmod's modules.softdep grammar."""
    source = Path(source)
    target = source / 'kernel-open/nvidia/libspdm_ecc.c'
    if not KMOD_SOFTDEP_PATCH.is_file() or KMOD_SOFTDEP_PATCH.is_symlink() or \
            sha256(KMOD_SOFTDEP_PATCH) != KMOD_SOFTDEP_PATCH_SHA256:
        raise ValueError('R595 kmod softdep overlay hash mismatch')
    if target.is_symlink() or not target.is_file() or \
            sha256(target) != KMOD_SOFTDEP_SOURCE_SHA256:
        raise ValueError('R595 libspdm_ecc.c preimage hash mismatch')
    argv = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(KMOD_SOFTDEP_PATCH)]
    dry = subprocess.run(argv + ['--dry-run'], cwd=source, capture_output=True,
                         text=True, timeout=60, check=False)
    if dry.returncode != 0 or re.search(r'(?im)\b(?:fuzz|offset)\b', dry.stdout + dry.stderr):
        raise ValueError('R595 kmod softdep overlay did not dry-run cleanly')
    applied = subprocess.run(argv, cwd=source, capture_output=True, text=True,
                             timeout=60, check=False)
    if applied.returncode != 0 or \
            re.search(r'(?im)\b(?:fuzz|offset)\b', applied.stdout + applied.stderr):
        raise ValueError('R595 kmod softdep overlay application failed or used offset/fuzz')
    digest = sha256(target)
    text = target.read_text()
    if digest != KMOD_SOFTDEP_PATCHED_SOURCE_SHA256 or \
            text.count('MODULE_SOFTDEP("' + KMOD_SOFTDEP_VALUE + '");') != 1 or \
            'MODULE_SOFTDEP("pre: ecdh_generic,ecdsa_generic");' in text:
        raise ValueError('R595 kmod softdep overlay output differs from the pinned source')
    return {
        'patch': str(KMOD_SOFTDEP_PATCH),
        'patch_sha256': KMOD_SOFTDEP_PATCH_SHA256,
        'preimage_sha256': KMOD_SOFTDEP_SOURCE_SHA256,
        'postimage_sha256': digest,
        'value': KMOD_SOFTDEP_VALUE,
        'dry_run_exit_code': dry.returncode,
        'apply_exit_code': applied.returncode,
        'fuzz_used': False,
        'offset_used': False,
    }


def run_build(work: Path, report_path: Path, jobs: int) -> dict:
    validate_output_paths(work, report_path)
    work = Path(work).absolute()
    report_path = Path(report_path).absolute()
    report = {
        'schema': 'replayed-r595-private-open-debugger-bridge-build-v1',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'qualification': 'failed',
        'source_version': '595.99.02',
        'kernel_release': KERNEL_RELEASE,
        'module_loaded': False,
        'module_installed': False,
        'hardware_tested': False,
        'runtime_or_hardware_validated': False,
        'activation_performed': False,
        'scope': 'compile/link the exact 45-patch R595 replay plus the separately pinned kmod softdep delimiter overlay, with provider and UVM conftests in one Kbuild invocation; no install, load, RM, or GPU access',
    }
    work.mkdir(parents=True, mode=0o700)
    (work / 'logs').mkdir(mode=0o700)
    log_path = work / 'logs/r595-open-module-build.log'
    try:
        if sha256(REPLAY_REPORT) != REPLAY_REPORT_SHA256:
            raise ValueError('pinned R595 replay report hash mismatch')
        replay = json.loads(REPLAY_REPORT.read_text())
        validate_replay_report(replay)
        replay_source = source_from_replay_report(replay)
        if not replay_source.is_dir():
            raise ValueError('reported R595 replay source is missing')
        original_artifacts = validate_replayed_source(replay_source, replay)
        if not R595_CORE.is_file() or R595_CORE.is_symlink() or \
                sha256(R595_CORE) != R595_CORE_SHA256:
            raise ValueError('installed R595 core binary does not match its pinned hash')
        if not R595_FRONTEND_SYMVERS.is_file() or R595_FRONTEND_SYMVERS.is_symlink() or \
                sha256(R595_FRONTEND_SYMVERS) != R595_FRONTEND_SYMVERS_SHA256:
            raise ValueError('R595 frontend Module.symvers does not match its pinned hash')
        candidate_source = work / 'source'
        shutil.copytree(replay_source, candidate_source, symlinks=True)
        copied_artifacts = validate_replayed_source(candidate_source, replay)
        if copied_artifacts != original_artifacts:
            raise ValueError('candidate source copy differs from replayed source evidence')
        softdep_overlay = apply_kmod_softdep_overlay(candidate_source)
        core_target = candidate_source / 'kernel-open/nvidia/nv-kernel.o_binary'
        if core_target.exists() or core_target.is_symlink():
            raise ValueError('candidate source already contains an unexpected RM core')
        shutil.copy2(R595_CORE, core_target)
        if sha256(core_target) != R595_CORE_SHA256:
            raise ValueError('private copy of pinned R595 core failed hash verification')
        report['inputs'] = {
            'replay_report': {'path': str(REPLAY_REPORT), 'sha256': REPLAY_REPORT_SHA256},
            'core': {'path': str(R595_CORE), 'sha256': R595_CORE_SHA256,
                     'private_copy_sha256': sha256(core_target)},
            'frontend_symvers': {'path': str(R595_FRONTEND_SYMVERS),
                                 'sha256': R595_FRONTEND_SYMVERS_SHA256},
            'replayed_source_artifacts': original_artifacts,
            'kmod_softdep_overlay': softdep_overlay,
            'builder_sha256': sha256(Path(__file__)),
        }
        argv = build_command(candidate_source, jobs)
        env = os.environ.copy()
        cleared = []
        for name in ('CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'EXTRA_CFLAGS',
                     'MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES', 'CC', 'CXX', 'LD',
                     'OBJCOPY', 'TARGET_ARCH', 'NV_VERBOSE', 'NV_SPECTRE_V2'):
            if name in env:
                cleared.append(name)
                del env[name]
        env['LC_ALL'] = 'C'
        started = time.monotonic()
        with log_path.open('x') as log:
            os.chmod(log_path, 0o600)
            log.write('$ ' + shlex.join(argv) + '\ncwd: ' + str(candidate_source) + '\n')
            log.flush()
            try:
                completed = subprocess.run(argv, cwd=ROOT, env=env, stdout=log,
                                           stderr=subprocess.STDOUT, timeout=1800,
                                           check=False)
                exit_code = completed.returncode
            except subprocess.TimeoutExpired:
                exit_code = 124
                log.write('\nTIMEOUT after 1800 seconds\n')
        report['build'] = {
            'argv': argv, 'exit_code': exit_code,
            'duration_seconds': round(time.monotonic() - started, 3),
            'environment_names_cleared': cleared,
            'log': {'path': str(log_path), 'sha256': sha256(log_path), 'mode': '0600'},
        }
        if exit_code != 0:
            raise RuntimeError('R595 candidate module build failed; see the private build log')
        module = candidate_source / 'kernel-open/hybrid580_open.ko'
        symvers = candidate_source / 'kernel-open/Module.symvers'
        uvm_conftest_module = candidate_source / 'kernel-open/nvidia-uvm.ko'
        types_header = candidate_source / 'kernel-open/conftest/types.h'
        if not module.is_file() or not symvers.is_file() or \
                not uvm_conftest_module.is_file() or not types_header.is_file():
            raise ValueError('R595 Kbuild did not produce the provider, UVM conftest target, and shared config')
        types_text = types_header.read_text()
        if not re.search(r'^#define\s+NV_MEMORY_DEVICE_COHERENT_PRESENT(?:\s|$)',
                         types_text, re.MULTILINE):
            raise ValueError('shared provider/UVM conftest did not enable coherent device pages')
        symvers_text = symvers.read_text()
        validate_share_policy_export(symvers_text)
        validate_sync_boost_export(symvers_text)
        validate_debugger_bridge_exports(symvers_text)
        modinfo = subprocess.run(['modinfo', '-F', 'name', str(module)],
                                 capture_output=True, text=True, check=True).stdout.strip()
        license_name = subprocess.run(['modinfo', '-F', 'license', str(module)],
                                      capture_output=True, text=True, check=True).stdout.strip()
        if modinfo != 'hybrid580_open' or license_name != 'Dual MIT/GPL':
            raise ValueError('R595 candidate module identity or license metadata mismatch')
        softdep = subprocess.run(['modinfo', '-F', 'softdep', str(module)],
                                 capture_output=True, text=True, check=True).stdout.strip()
        if softdep != KMOD_SOFTDEP_VALUE:
            raise ValueError('R595 candidate softdep metadata does not use kmod whitespace separators')
        readelf = subprocess.run(['readelf', '-p', '__ksymtab_strings', str(module)],
                                 capture_output=True, text=True, check=True).stdout
        if SHARE_POLICY_EXPORT not in readelf:
            raise ValueError('R595 candidate ELF lacks the share-policy export string')
        if SYNC_BOOST_EXPORT not in readelf:
            raise ValueError('R595 candidate ELF lacks the sync-boost export string')
        if DEBUGGER_ALLOC_EXPORT not in readelf or DEBUGGER_MASK_EXPORT not in readelf:
            raise ValueError('R595 candidate ELF lacks a debugger bridge export string')
        if validate_replayed_source(candidate_source, replay) != original_artifacts:
            raise ValueError('candidate build modified a replayed source artifact')
        report.update(
            qualification=BUILD_QUALIFICATION,
            module={'path': str(module), 'sha256': sha256(module),
                    'bytes': module.stat().st_size, 'name': modinfo,
                    'license': license_name, 'softdep': softdep},
            exports=[
                {'name': SHARE_POLICY_EXPORT, 'flavor': 'EXPORT_SYMBOL',
                 'present_in_symvers': True, 'present_in_elf': True},
                {'name': SYNC_BOOST_EXPORT, 'flavor': 'EXPORT_SYMBOL',
                 'present_in_symvers': True, 'present_in_elf': True},
                {'name': DEBUGGER_ALLOC_EXPORT, 'flavor': 'EXPORT_SYMBOL',
                 'present_in_symvers': True, 'present_in_elf': True},
                {'name': DEBUGGER_MASK_EXPORT, 'flavor': 'EXPORT_SYMBOL',
                 'present_in_symvers': True, 'present_in_elf': True},
            ],
            export_count=sum(1 for line in symvers.read_text().splitlines()
                             if len(line.split()) >= 4 and
                             line.split()[3].startswith('EXPORT_SYMBOL')),
            symvers_sha256=sha256(symvers),
            shared_conftest={
                'modules': ['nvidia', 'nvidia-uvm'],
                'types_header': {'path': str(types_header), 'sha256': sha256(types_header)},
                'NV_MEMORY_DEVICE_COHERENT_PRESENT': True,
                'uvm_conftest_sidecar': {
                    'path': str(uvm_conftest_module),
                    'sha256': sha256(uvm_conftest_module),
                    'included_in_hybrid_bundle': False,
                },
            },
            replayed_source_artifacts_unchanged=True,
            source_tree_original_unchanged=replay['source_tree_unchanged'],
            build_input_source=replay['source'],
        )
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}')
    report_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'report': str(report_path),
                      'qualification': report['qualification'],
                      'error': report.get('error'),
                      'module': report.get('module')}, indent=2))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    try:
        report = run_build(args.work_dir, args.report, args.jobs)
    except ValueError as exc:
        parser.error(str(exc))
    return 0 if report['qualification'] == BUILD_QUALIFICATION else 1


if __name__ == '__main__':
    raise SystemExit(main())
