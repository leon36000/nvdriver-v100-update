#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build a private R580 proprietary backend without touching its core/license.

No install, load, sign, device access, SSH, firmware or VM operation. The real
kernel modpost and explicit import classification both enforce non-GPL imports.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proprietary_baseline',
                                             ROOT / 'tools/build_proprietary580_wrapper_baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
ARCHIVE = ROOT / '.cache/upstream/NVIDIA-kernel-module-source-580.178.04.tar.xz'
ARCHIVE_SHA = '060749a0df733af2d0bc863fff4581faca398048d17dbc691d039141ead391d8'
PATCH_DIR = ROOT / 'patches/r580.178.04/proprietary'
NOTICE_PATCH = PATCH_DIR / '0010-local-modification-notices.patch'
# Apply authored code patches before the comment-only notice patch so source
# hunk offsets stay tied to vendor files rather than notice-comment line count.
PATCHES = [patch for patch in sorted(PATCH_DIR.glob('*.patch'))
           if patch != NOTICE_PATCH] + [NOTICE_PATCH]
BASE = ROOT / 'build/experiments/proprietary580-wrapper-baseline-v1/nvidia-580.178.04'
BASE_SHA = '6687ca7503c4fef5b44186fba1209d579631ba4a96998625001299dda0eecff4'
SDK_DIRS = ('common/sdk/nvidia/inc', 'common/inc', 'nvidia/arch/nvalloc/unix/include')
PREVIOUS_REPORT = ROOT / 'evidence/private-proprietary-session-v2-20261019.json'
PREVIOUS_REPORT_SHA = '26b18c6e0b32ad8d73be38f60644116f9552c48869ab56602f709ead107a1b13'
PREVIOUS_SOURCE = ROOT / 'build/experiments/private-proprietary-session-v2/nvidia-580.178.04'
PREVIOUS_SYMVERS_SHA = '897065a1a1a9ec4bf1d1cef4f1495fa782498f4ba397560361e32b420b1a66fc'
PREVIOUS_CONTROL_HEADER = PREVIOUS_SOURCE / 'nvidia/hybrid580-control-session.h'
PREVIOUS_CONTROL_HEADER_SHA = 'b836278f6c81b6e10109ab9954e80a633bb569d54fa2814e1519c62d793dc8c6'
CHANNEL_OBJECT_PATCH = PATCH_DIR / '0023-private-legacy-channel-object.patch'
SUBDEVICE_TPC_MASK_PATCH = PATCH_DIR / '0024-private-legacy-subdevice-and-tpc-mask.patch'
BINAPI_OBJECT_PATCH = PATCH_DIR / '0025-private-legacy-binapi-object.patch'
USERMODE_OBJECT_PATCH = PATCH_DIR / '0026-private-legacy-usermode-object.patch'
MAP_MEMORY_PATCH = PATCH_DIR / '0027-private-legacy-map-memory.patch'
P2P_OBJECT_PATCH = PATCH_DIR / '0028-private-legacy-p2p-object.patch'
PM_CHANNEL_DEPTH_ENUM_PATCH = PATCH_DIR / '0001-private-legacy-pm-channel-depth-enum.patch'
PM_CHANNEL_DEPTH_PATCH = PATCH_DIR / '0031-private-legacy-pm-channel-depth.patch'
PM_CHANNEL_DEPTH_PROCFS_PATCH = PATCH_DIR / '0032-private-legacy-pm-procfs-channel-depth.patch'
PM_VMA_ACCESS_PATCH = PATCH_DIR / '0033-private-legacy-pm-vma-access-guard.patch'
PM_VMA_FREE_LIST_PATCH = PATCH_DIR / '0034-private-legacy-vma-free-list-lock.patch'
PM_RECOVERY_PROVIDER_PATCH = PATCH_DIR / '0035-private-legacy-pm-recovery-provider.patch'
PM_CHANNEL_DPM_MODESET_PATCH = PATCH_DIR / '0036-private-legacy-pm-channel-dpm-modeset.patch'
SYS_PARAMS_PATCH = PATCH_DIR / '0037-private-legacy-sys-params.patch'
GPU_REGISTER_CONTROL_PATCH = PATCH_DIR / '0038-private-legacy-gpu-register-control.patch'
PM_CHANNEL_DEPTH_TEST = ROOT / 'tests/test_hybrid_pm_channel_depth.py'
PM_RECOVERY_TEST = ROOT / 'tests/test_hybrid580_pm_provider_recovery.py'
PM_RECOVERY_PROVIDER_TEST = ROOT / 'tests/test_private_pm_recovery_provider.py'
GPU_SESSION_PATCHES = [
    ROOT / 'patches/r580.178.04/proprietary/0009-private-legacy-gpu-session.patch',
    ROOT / 'patches/r580.178.04/proprietary/0009z-private-legacy-gpu-bdf-lookup.patch',
    ROOT / 'patches/r580.178.04/proprietary/0011-private-legacy-gpu-inventory.patch']
CONTROL_ATTACH_PATCH = ROOT / 'patches/r580.178.04/proprietary/0012-private-legacy-control-attach.patch'
CARD_INFO_PATCH = ROOT / 'patches/r580.178.04/proprietary/0013-private-legacy-card-info.patch'
GPU_ID_INFO_PATCH = ROOT / 'patches/r580.178.04/proprietary/0014-private-legacy-gpu-id-info.patch'
ATTACHED_IDS_PATCH = ROOT / 'patches/r580.178.04/proprietary/0015-private-legacy-attached-ids.patch'
DEVICE_OBJECT_PATCH = ROOT / 'patches/r580.178.04/proprietary/0018-private-legacy-device-object.patch'
MEMORY_OBJECT_PATCH = ROOT / 'patches/r580.178.04/proprietary/0019-private-legacy-memory-object.patch'
GPU_SESSION_HEADER = ROOT / 'src/hybrid580-gpu-session.h'
CONTROL_SESSION_HEADER = ROOT / 'src/hybrid580-control-session.h'
GPU_CATALOG_HEADER = ROOT / 'src/hybrid580-gpu-catalog.h'
NOTICE_ID = 'LOCAL MODIFICATION NOTICE - NVIDIA Hybrid Driver Lab, 2026-10-19.'
PM_CHANNEL_DEPTH_PREDECESSOR_PATCHES = [
    *GPU_SESSION_PATCHES,
    CONTROL_ATTACH_PATCH, CARD_INFO_PATCH, GPU_ID_INFO_PATCH, ATTACHED_IDS_PATCH,
    PATCH_DIR / '0016-private-legacy-probed-ids.patch',
    PATCH_DIR / '0017-private-legacy-device-ids.patch',
    DEVICE_OBJECT_PATCH, MEMORY_OBJECT_PATCH,
    PATCH_DIR / '0020-private-legacy-vaspace-object.patch',
    PATCH_DIR / '0021-private-legacy-channel-group-object.patch',
    PATCH_DIR / '0022-private-legacy-context-share-object.patch',
    CHANNEL_OBJECT_PATCH, SUBDEVICE_TPC_MASK_PATCH, BINAPI_OBJECT_PATCH,
    USERMODE_OBJECT_PATCH, MAP_MEMORY_PATCH, P2P_OBJECT_PATCH,
    PATCH_DIR / '0029-private-legacy-p2p-controls.patch',
    PATCH_DIR / '0030-private-legacy-rusd-object.patch',
]


def split_local_notice(text, relative):
    """Recognize the prominent comment without treating code as a notice."""
    if relative.endswith('.Kbuild'):
        prefix, separator, remainder = text.partition('\n\n')
        if not separator or not prefix.startswith('# ' + NOTICE_ID + '\n') or not all(
                line.startswith('#') for line in prefix.splitlines()):
            raise ValueError('missing prominent Kbuild modification notice: ' + relative)
    else:
        prefix, separator, remainder = text.partition(' */\n')
        if not separator or not prefix.startswith('/*\n * ' + NOTICE_ID + '\n'):
            raise ValueError('missing prominent C modification notice: ' + relative)
    return prefix + separator, remainder


def exports(text):
    return {row[1]: row[3] for line in text.splitlines() if len(row := line.split()) >= 4}


def symvers_rows(path):
    return {row[1]: (row[0], row[3]) for line in Path(path).read_text().splitlines()
            if len(row := line.split()) >= 4}


def expected_exports(original):
    if len(original) != 94 or 'nv_vma_start_write' not in original:
        raise ValueError('expected the exact 94-export proprietary baseline')
    result = {'hybrid580_legacy_' + name: flavor for name, flavor in original.items()}
    for operation in ('register', 'unregister'):
        result['hybrid580_legacy_' + operation + '_file_projection_v1'] = 'EXPORT_SYMBOL'
    for operation in ('create', 'get', 'put', 'file', 'attach'):
        result['hybrid580_legacy_control_session_' + operation + '_v1'] = 'EXPORT_SYMBOL'
    for operation in ('create', 'create_by_bdf', 'get', 'put', 'file', 'ioctl',
                      'register_control'):
        result['hybrid580_legacy_gpu_session_' + operation + '_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_gpu_inventory_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_gpu_card_info_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_gpu_id_info_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_attached_ids_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_probed_ids_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_device_ids_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_device_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_device_free_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_memory_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_object_free_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_vaspace_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_channel_group_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_context_share_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_channel_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_engine_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_subdevice_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_gr_tpc_mask_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_binapi_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_rusd_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_usermode_alloc_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_map_memory_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_unmap_memory_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_update_device_mapping_info_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_sys_params_v1'] = 'EXPORT_SYMBOL'
    result['hybrid580_legacy_control_session_p2p_alloc_v1'] = 'EXPORT_SYMBOL'
    for operation in ('register_va_space', 'unregister_va_space',
                      'register_vidmem', 'unregister_vidmem'):
        result['hybrid580_legacy_control_session_p2p_' + operation + '_v1'] = 'EXPORT_SYMBOL'
    for operation in ('begin', 'recover', 'end'):
        result['hybrid580_legacy_pm_recovery_' + operation + '_v1'] = 'EXPORT_SYMBOL'
    for operation in ('suspend', 'resume'):
        result['hybrid580_legacy_pm_channels_' + operation + '_v1'] = 'EXPORT_SYMBOL'
    return result


def apply_patches_to_text(text, patch_paths, relative_path, extra_files=(),
                          target_filter=None):
    """Apply pinned incremental patches with their exact companion headers."""
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp)
        target = tree / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        for relative, source in extra_files:
            companion = tree / relative
            companion.parent.mkdir(parents=True, exist_ok=True)
            companion.write_bytes(Path(source).read_bytes())
        for index, patch_path in enumerate(patch_paths):
            input_patch = patch_path
            if target_filter is not None:
                sections = re.split(r'(?=^--- a/)', patch_path.read_text(), flags=re.M)
                selected = []
                for section in sections:
                    match = re.match(r'--- a/([^\n]+)\n\+\+\+ b/([^\n]+)', section)
                    if match and match.group(1) in target_filter:
                        selected.append(section)
                if not selected:
                    raise ValueError('target-filtered patch has no requested file: ' + str(patch_path))
                input_patch = tree / ('filtered-' + str(index) + '.patch')
                input_patch.write_text(''.join(selected))
            result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(input_patch)],
                                    cwd=tree, capture_output=True, text=True)
            if result.returncode or re.search(r'\b(?:fuzz|offset)\b', result.stdout + result.stderr):
                raise ValueError('incremental source patch failed: ' + result.stdout + result.stderr)
        return target.read_text()


def symbols(path):
    output = subprocess.check_output(['readelf', '-W', '-s', str(path)], text=True)
    defined, undefined = set(), set()
    for line in output.splitlines():
        f = line.split()
        if len(f) < 8 or not f[0].endswith(':'):
            continue
        if f[6] == 'UND':
            undefined.add(f[7])
        elif f[4] == 'GLOBAL' and f[6] != 'ABS':
            defined.add(f[7])
    return defined, undefined


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path,
                        default=ROOT / 'build/experiments/private-proprietary-session-v1')
    parser.add_argument('--report', type=Path,
                        default=ROOT / 'evidence/private-proprietary-session-v1-20261019.json')
    parser.add_argument('--kernel-release', default='7.0.0-38-generic')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    work, report_path = args.work_dir.resolve(), args.report.resolve()
    if args.jobs < 1 or work.exists() or report_path.exists():
        parser.error('positive jobs and unused scratch/report paths required')
    if not work.is_relative_to(ROOT / 'build/experiments') or not report_path.is_relative_to(ROOT / 'evidence'):
        parser.error('scratch/report must remain under build/experiments and evidence')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report = {'schema': 'private-proprietary580-v1', 'observed_at_utc': stamp,
              'qualification': 'not-started', 'loaded_or_installed': False,
              'hardware_validated': False, 'runtime_isolation_validated': False,
              'module_license': 'NVIDIA', 'module_license_changed': False,
              'core_modified': False, 'steps': [], 'work_dir': str(work),
              'remaining_boundaries': ['No frontend/provider registered or real broker invocation',
                 'No VFS/LSM/deferred-fput/unload runtime validation',
                 'Private UVM/modeset consumer routing is not integrated',
                 'Module-wide RM/NVLink/caps initialization precedes BDF GPU gate',
                 'Original proprietary core retains its objtool return/frame warnings',
                 'No GPU or CUDA execution; no performance claim']}
    source_before = None
    def step(name, argv, cwd=ROOT, timeout=1200):
        log = ROOT / 'evidence/logs' / ('private-proprietary-' + name + '-' + stamp + '.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        item = baseline.run_logged(name, argv, cwd, log, timeout)
        report['steps'].append(item)
        if item['exit_code']:
            raise RuntimeError(name + ' failed: ' + str(log))
        return log.read_text(errors='replace')
    try:
        kernel = Path('/lib/modules', args.kernel_release, 'build').resolve(strict=True)
        pins = ((baseline.PACKAGE_DEB, baseline.PACKAGE_DEB_SHA256),
                (baseline.CORE_OBJECT, baseline.CORE_OBJECT_SHA256),
                (ARCHIVE, ARCHIVE_SHA), (BASE / 'nvidia.ko', BASE_SHA),
                (PREVIOUS_REPORT, PREVIOUS_REPORT_SHA),
                (PREVIOUS_SOURCE / 'Module.symvers', PREVIOUS_SYMVERS_SHA),
                (PREVIOUS_CONTROL_HEADER, PREVIOUS_CONTROL_HEADER_SHA))
        for path, digest in pins:
            if baseline.sha256(path) != digest:
                raise ValueError('pinned input changed: ' + str(path))
        inputs = [path for path, _ in pins] + PATCHES + [Path(__file__),
            ROOT / 'src/rm_session_endpoint.h', ROOT / 'tests/test_private_proprietary580.py',
            PM_CHANNEL_DEPTH_TEST,
            PM_RECOVERY_TEST, PM_RECOVERY_PROVIDER_TEST,
            ROOT / 'tests/test_usermode_object.py',
            GPU_SESSION_HEADER, CONTROL_SESSION_HEADER,
            ROOT / 'src/hybrid580_pm_provider_recovery.h',
            ROOT / 'src/hybrid580_pm_provider_kernel.h',
            ROOT / 'tests/test_private_backend_control_session.py',
            ROOT / 'tests/test_private_backend_gpu_session.py',
            ROOT / 'tests/test_private_backend_file_projection.py',
            ROOT / 'tests/test_private_backend_pci.py',
            ROOT / 'tools/build_proprietary580_wrapper_baseline.py',
            BASE / 'Module.symvers', kernel / 'Module.symvers', kernel / '.config']
        report['inputs'] = [{'path': str(path), 'sha256': baseline.sha256(path)} for path in inputs]
        step('cpu-contracts', ['python3', '-B', '-m', 'unittest', 'discover', '-v',
                               '-s', 'tests', '-p', 'test_private_proprietary580.py'])
        step('pm-channel-depth-contracts', ['python3', '-B', '-m', 'unittest', '-v',
                                            'tests.test_hybrid_pm_channel_depth'])
        step('pm-provider-recovery-contracts', ['python3', '-B', '-m', 'unittest', '-v',
            'tests.test_hybrid580_pm_provider_recovery',
            'tests.test_private_pm_recovery_provider'])
        source_before = baseline.tree_fingerprint(baseline.SOURCE_ROOT)
        report['source_tree_before'] = source_before
        work.mkdir(parents=True)
        source = work / 'nvidia-580.178.04'
        shutil.copytree(baseline.SOURCE_ROOT, source, symlinks=True, copy_function=shutil.copy2)
        if baseline.tree_fingerprint(source) != source_before:
            raise ValueError('scratch copy differs from source')
        for patch in PATCHES:
            patch_output = step(patch.stem,
                ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], source)
            if patch == SYS_PARAMS_PATCH and re.search(
                    r'(?im)^Hunk #\d+ succeeded[^\n]*(?:offset|fuzz)', patch_output):
                raise ValueError('source patch used fuzz or an offset: ' + patch.name)
        sdk = source / 'hybrid-sdk'
        # Preserve the original SDK file bytes and all notices. Extract only
        # headers needed to compile the typed kernel-only session API.
        with tarfile.open(ARCHIVE, 'r:xz') as archive:
            top = 'NVIDIA-kernel-module-source-580.178.04/src/'
            for member in archive.getmembers():
                if not member.name.startswith(top) or not member.isfile():
                    continue
                suffix = member.name[len(top):]
                if not any(suffix.startswith(part + '/') for part in SDK_DIRS):
                    continue
                target = sdk / suffix
                if not target.resolve().is_relative_to(sdk.resolve()):
                    raise ValueError('unsafe SDK archive path')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        shutil.copy2(ROOT / 'src/rm_session_endpoint.h', source / 'nvidia/rm_session_endpoint.h')
        shutil.copy2(GPU_CATALOG_HEADER, source / 'nvidia/hybrid580-gpu-catalog.h')
        expected_control_header = CONTROL_SESSION_HEADER.read_bytes().replace(
            b'hybrid580_open', b'hybrid580_legacy')
        (source / 'nvidia/hybrid580-control-session.h').write_bytes(expected_control_header)
        shutil.copy2(ROOT / 'src/hybrid580_pm_provider_recovery.h',
                     source / 'nvidia/hybrid580-pm-provider-recovery.h')
        shutil.copy2(ROOT / 'src/hybrid580_pm_provider_kernel.h',
                     source / 'nvidia/hybrid580-pm-provider-kernel.h')
        gpu_header = source / 'nvidia/hybrid580-gpu-session.h'
        expected_gpu_header = GPU_SESSION_HEADER.read_bytes().replace(b'hybrid580_open', b'hybrid580_legacy')
        if not gpu_header.is_file() or gpu_header.read_bytes() != expected_gpu_header:
            raise ValueError('proprietary GPU session header differs from the namespaced project API')
        sdk_nvos = sdk / 'common/sdk/nvidia/inc/nvos.h'
        overlay = source / 'common/inc/nvos.h'
        shutil.copy2(sdk_nvos, overlay)
        report['sdk_tree'] = {'path': str(sdk), **baseline.tree_fingerprint(sdk)}
        report['sdk_overlay'] = {'source': str(sdk_nvos), 'path': str(overlay),
                                 'sha256': baseline.sha256(sdk_nvos),
                                 'verbatim': sdk_nvos.read_bytes() == overlay.read_bytes()}
        previous = json.loads(PREVIOUS_REPORT.read_text())
        prior_changes = {item['path']: item['sha256'] for item in previous['source_changes']}
        declared_targets = set()
        for patch in PATCHES:
            if patch.name.startswith('000') or patch in (
                    PM_VMA_ACCESS_PATCH, PM_VMA_FREE_LIST_PATCH,
                    PM_RECOVERY_PROVIDER_PATCH, PM_CHANNEL_DPM_MODESET_PATCH):
                declared_targets.update(re.findall(r'^--- a/([^\n]+)$', patch.read_text(), re.M))
        vendor_targets = {relative for relative in declared_targets
                          if (baseline.SOURCE_ROOT / relative).is_file()}
        authored_targets = declared_targets - vendor_targets
        if authored_targets != {'nvidia/hybrid580-gpu-session.h'}:
            raise ValueError('unexpected non-vendor patch targets: ' + ','.join(sorted(authored_targets)))
        # Discover changes by comparing actual original files, independently of
        # patch target declarations. New project/SDK headers are not vendor edits.
        vendor_changes = {str(path.relative_to(source)) for path in source.rglob('*')
            if path.is_file() and (baseline.SOURCE_ROOT / path.relative_to(source)).is_file()
            and path.read_bytes() != (baseline.SOURCE_ROOT / path.relative_to(source)).read_bytes()}
        if vendor_changes != vendor_targets:
            raise ValueError('actual modified vendor files differ from original patch targets')
        notice_targets = set(re.findall(r'^\+\+\+ b/([^\n]+)$',
            (ROOT / 'patches/r580.178.04/proprietary/0010-local-modification-notices.patch').read_text(), re.M))
        if notice_targets != vendor_targets:
            raise ValueError('notice patch does not cover exactly the modified vendor files')
        modifications = []
        for relative in sorted(vendor_changes):
            path, prior = source / relative, PREVIOUS_SOURCE / relative
            baseline_path = baseline.SOURCE_ROOT / relative
            expected_prior_sha = prior_changes.get(str(prior), baseline.sha256(baseline_path))
            if baseline.sha256(prior) != expected_prior_sha:
                raise ValueError('pre-notice source differs from v2 evidence: ' + relative)
            notice, remainder = split_local_notice(path.read_text(), relative)
            prior_text = prior.read_text()
            prior_notice, prior_separator, prior_body = prior_text.partition(' */\n')
            if prior_text.startswith('/*\n * ' + NOTICE_ID + '\n'):
                expected_remainder = prior_body
            else:
                expected_remainder = prior_text
            if relative == 'nvidia/nv.c':
                expected_remainder = apply_patches_to_text(
                    expected_remainder,
                    PM_CHANNEL_DEPTH_PREDECESSOR_PATCHES +
                    [PM_CHANNEL_DEPTH_PATCH, PM_RECOVERY_PROVIDER_PATCH,
                     PM_CHANNEL_DPM_MODESET_PATCH, SYS_PARAMS_PATCH], relative,
                    extra_files=(('nvidia/hybrid580-control-session.h', PREVIOUS_CONTROL_HEADER),
                                 ('nvidia/nv-procfs.c', PREVIOUS_SOURCE / 'nvidia/nv-procfs.c')))
                expected_remainder = apply_patches_to_text(
                    expected_remainder, [GPU_REGISTER_CONTROL_PATCH], relative,
                    target_filter={relative})
                expected_remainder = apply_patches_to_text(
                    expected_remainder,
                    [PATCH_DIR / '0039-private-legacy-engine-object.patch'],
                    relative, target_filter={relative})
                expected_remainder = apply_patches_to_text(
                    expected_remainder,
                    [PATCH_DIR / '0040-private-legacy-update-device-mapping-info.patch'],
                    relative, target_filter={relative})
            elif relative == 'nvidia/nv-procfs.c':
                expected_remainder = apply_patches_to_text(
                    expected_remainder, [PM_CHANNEL_DEPTH_PROCFS_PATCH], relative)
            elif relative == 'common/inc/nv.h':
                expected_remainder = apply_patches_to_text(
                    expected_remainder, [PM_CHANNEL_DEPTH_ENUM_PATCH], relative)
            elif relative == 'nvidia/nv-mmap.c':
                expected_remainder = apply_patches_to_text(
                    expected_remainder, [PM_VMA_ACCESS_PATCH], relative)
            elif relative == 'common/inc/nv-linux.h':
                expected_remainder = apply_patches_to_text(
                    expected_remainder, [PM_VMA_FREE_LIST_PATCH], relative)
            if remainder != expected_remainder:
                raise ValueError('notice patch changes more than its comment: ' + relative)
            original = (baseline.SOURCE_ROOT / relative).read_text()
            if original.startswith('/*') and not remainder.startswith(original[:original.index('*/') + 2]):
                raise ValueError('original copyright/license comment changed: ' + relative)
            modifications.append({'relative_path': relative, 'path': str(path),
                'sha256': baseline.sha256(path), 'original_path': str(baseline.SOURCE_ROOT / relative),
                'original_sha256': baseline.sha256(baseline.SOURCE_ROOT / relative),
                'pre_notice_path': str(prior), 'pre_notice_sha256': baseline.sha256(prior),
                'incremental_source_matches_gpu_patch': relative == 'nvidia/nv.c',
                'original_notice_preserved': True})
        authored_headers = []
        for name in ('hybrid580-legacy-exports.h', 'hybrid580-file-projection.h',
                     'hybrid580-control-session.h', 'hybrid580-gpu-session.h',
                     'hybrid580-gpu-catalog.h',
                     'hybrid580-pm-provider-recovery.h',
                     'hybrid580-pm-provider-kernel.h'):
            path = source / 'nvidia' / name
            if NOTICE_ID in path.read_text():
                raise ValueError('authored API header mislabeled as vendor: ' + name)
            if name == 'hybrid580-gpu-session.h':
                if path.read_bytes() != expected_gpu_header:
                    raise ValueError('authored GPU API header differs after backend prefix substitution')
            elif name == 'hybrid580-control-session.h':
                expected_control_header = CONTROL_SESSION_HEADER.read_bytes().replace(
                    b'hybrid580_open', b'hybrid580_legacy')
                if path.read_bytes() != expected_control_header:
                    raise ValueError('authored control API header differs after backend prefix substitution')
            elif name == 'hybrid580-gpu-catalog.h':
                if path.read_bytes() != GPU_CATALOG_HEADER.read_bytes():
                    raise ValueError('authored catalog header differs from project API')
            elif name == 'hybrid580-pm-provider-recovery.h':
                if path.read_bytes() != (ROOT / 'src/hybrid580_pm_provider_recovery.h').read_bytes():
                    raise ValueError('provider recovery contract header differs from project API')
            elif name == 'hybrid580-pm-provider-kernel.h':
                if path.read_bytes() != (ROOT / 'src/hybrid580_pm_provider_kernel.h').read_bytes():
                    raise ValueError('provider recovery kernel header differs from project API')
            else:
                prior = PREVIOUS_SOURCE / 'nvidia' / name
                if path.read_bytes() != prior.read_bytes():
                    raise ValueError('existing authored API header changed: ' + name)
            authored_headers.append({'path': str(path), 'sha256': baseline.sha256(path),
                                    'matches_project_api': name in ('hybrid580-gpu-session.h',
                                                                     'hybrid580-control-session.h',
                                                                     'hybrid580-pm-provider-recovery.h',
                                                                     'hybrid580-pm-provider-kernel.h'),
                                    'unchanged_vs_v2': name not in ('hybrid580-gpu-session.h',
                                                                     'hybrid580-control-session.h',
                                                                     'hybrid580-pm-provider-recovery.h',
                                                                     'hybrid580-pm-provider-kernel.h')})
        report['vendor_modification_notices'] = modifications
        report['authored_headers'] = authored_headers
        # A local source provenance artifact, not a redistribution permission.
        modifications_path = work / 'MODIFICATIONS.md'
        rows = ['# Local proprietary-wrapper source modifications', '',
            'Experimental local source changes by NVIDIA Hybrid Driver Lab, 2026-10-19.',
            'Incremental private API patches modify the files below; patch 0010 adds prominent comment notices.',
            'Original vendor notices and proprietary core bytes remain intact. This record grants no redistribution rights.',
            '', '| Vendor source | Original SHA-256 | Modified SHA-256 |', '|---|---|---|']
        rows.extend('| ' + item['relative_path'] + ' | ' + item['original_sha256'] + ' | ' +
                    item['sha256'] + ' |' for item in modifications)
        modifications_path.write_text('\n'.join(rows) + '\n')
        report['local_modifications_document'] = {'path': str(modifications_path),
                                                  'sha256': baseline.sha256(modifications_path)}
        before_license = (baseline.SOURCE_ROOT / 'nvidia/nv.c').read_text()
        after_license = (source / 'nvidia/nv.c').read_text()
        _, unmarked = split_local_notice(after_license, 'nvidia/nv.c')
        if before_license.split('#include', 1)[0] != unmarked.split('#include', 1)[0]:
            raise ValueError('original wrapper notices changed')
        if re.findall(r'MODULE_LICENSE\("([^\"]+)"\)', after_license) != ['NVIDIA']:
            raise ValueError('proprietary module license altered')
        output = step('module-build', ['make', '-C', str(source),
            'KERNEL_UNAME=' + args.kernel_release, 'NV_KERNEL_MODULES=nvidia',
            '-j' + str(args.jobs), 'modules'])
        module = source / 'hybrid580_legacy.ko'
        report['module'] = {'path': str(module), 'sha256': baseline.sha256(module),
                            'bytes': module.stat().st_size}
        actual = exports((source / 'Module.symvers').read_text())
        wanted = expected_exports(exports((BASE / 'Module.symvers').read_text()))
        if actual != wanted:
            raise ValueError('private export names/flavors differ from original ABI')
        report['exports'] = actual
        strings = step('export-strings', ['readelf', '-p', '__ksymtab_strings', str(module)])
        actual_strings = {line.split(']', 1)[1].strip() for line in strings.splitlines() if ']' in line}
        if actual_strings != set(wanted):
            raise ValueError('ELF export strings differ from private ABI')
        info = step('modinfo', ['modinfo', str(module)])
        metadata = {}
        for line in info.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                metadata.setdefault(key, []).append(value.strip())
        if metadata.get('license') != ['NVIDIA'] or metadata.get('name') != ['hybrid580_legacy']:
            raise ValueError('module name/license metadata mismatch')
        if metadata.get('alias') or not metadata.get('vermagic', [''])[0].startswith(args.kernel_release + ' '):
            raise ValueError('public hardware aliases or wrong kernel target')
        report['module_metadata'] = metadata
        parameters = subprocess.check_output(['modinfo', '-F', 'parmtype', str(module)], text=True).splitlines()
        if 'hybrid_gpu_pci:charp' not in parameters:
            raise ValueError('read-only PCI selector parameter absent')
        report['parameter_types'] = parameters
        defined, undefined = symbols(module)
        kernel_exports = exports((kernel / 'Module.symvers').read_text())
        if undefined - kernel_exports.keys():
            raise ValueError('unresolved kernel imports')
        gpl = {name: kernel_exports[name] for name in sorted(undefined) if 'GPL' in kernel_exports[name]}
        if gpl:
            raise ValueError('NVIDIA module requires GPL-only imports: ' + ','.join(gpl))
        _, baseline_imports = symbols(BASE / 'nvidia.ko')
        report['imports'] = {name: kernel_exports[name] for name in sorted(undefined)}
        report['added_imports'] = {name: kernel_exports[name] for name in sorted(undefined - baseline_imports)}
        report['removed_imports'] = sorted(baseline_imports - undefined)
        report['gpl_only_imports'] = gpl
        report['compatibility_with_v2'] = {
            'reference_report': str(PREVIOUS_REPORT), 'reference_report_sha256': PREVIOUS_REPORT_SHA,
            'symvers': str(source / 'Module.symvers'),
            'symvers_sha256': baseline.sha256(source / 'Module.symvers'),
            'reference_symvers_sha256': PREVIOUS_SYMVERS_SHA,
            'prior_export_crcs_and_flavors_unchanged': all(
                symvers_rows(source / 'Module.symvers').get(name) == row
                for name, row in symvers_rows(PREVIOUS_SOURCE / 'Module.symvers').items()),
            'new_gpu_exports_exact': {name for name in actual if name.startswith('hybrid580_legacy_gpu_session_')} ==
                {'hybrid580_legacy_gpu_session_' + operation + '_v1'
                 for operation in ('create', 'create_by_bdf', 'get', 'put', 'file', 'ioctl',
                                   'register_control')} and
                'hybrid580_legacy_gpu_inventory_v1' in actual and
                actual.get('hybrid580_legacy_gpu_card_info_v1') == 'EXPORT_SYMBOL' and
                actual.get('hybrid580_legacy_control_session_gpu_id_info_v1') == 'EXPORT_SYMBOL' and
                actual.get('hybrid580_legacy_control_session_attached_ids_v1') == 'EXPORT_SYMBOL' and
                actual.get('hybrid580_legacy_control_session_probed_ids_v1') == 'EXPORT_SYMBOL',
            'new_control_attach_export_exact': actual.get('hybrid580_legacy_control_session_attach_v1') == 'EXPORT_SYMBOL',
            'new_device_object_exports_exact': all(actual.get(
                'hybrid580_legacy_control_session_' + operation + '_v1') == 'EXPORT_SYMBOL'
                for operation in ('device_ids', 'device_alloc', 'device_free',
                                  'memory_alloc', 'object_free')),
            'new_vaspace_export_exact': actual.get(
                'hybrid580_legacy_control_session_vaspace_alloc_v1') == 'EXPORT_SYMBOL',
            'new_channel_group_export_exact': actual.get(
                'hybrid580_legacy_control_session_channel_group_alloc_v1') == 'EXPORT_SYMBOL',
            'new_context_share_export_exact': actual.get(
                'hybrid580_legacy_control_session_context_share_alloc_v1') == 'EXPORT_SYMBOL',
            'new_channel_alloc_export_exact': actual.get(
                'hybrid580_legacy_control_session_channel_alloc_v1') == 'EXPORT_SYMBOL',
            'new_engine_alloc_export_exact': actual.get(
                'hybrid580_legacy_control_session_engine_alloc_v1') == 'EXPORT_SYMBOL',
            'new_subdevice_tpc_mask_exports_exact': all(actual.get(
                'hybrid580_legacy_control_session_' + operation + '_v1') == 'EXPORT_SYMBOL'
                for operation in ('subdevice_alloc', 'gr_tpc_mask')),
            'new_binapi_export_exact': actual.get(
                'hybrid580_legacy_control_session_binapi_alloc_v1') == 'EXPORT_SYMBOL',
            'new_rusd_alloc_export_exact': actual.get(
                'hybrid580_legacy_control_session_rusd_alloc_v1') == 'EXPORT_SYMBOL',
            'new_usermode_export_exact': actual.get(
                'hybrid580_legacy_control_session_usermode_alloc_v1') == 'EXPORT_SYMBOL',
            'new_map_memory_exports_exact': all(actual.get(
                'hybrid580_legacy_control_session_' + operation + '_v1') == 'EXPORT_SYMBOL'
                for operation in ('map_memory', 'unmap_memory')),
            'new_device_mapping_update_export_exact': actual.get(
                'hybrid580_legacy_control_session_update_device_mapping_info_v1') == 'EXPORT_SYMBOL',
            'new_sys_params_export_exact': actual.get(
                'hybrid580_legacy_control_session_sys_params_v1') == 'EXPORT_SYMBOL',
            'new_p2p_alloc_export_exact': actual.get(
                'hybrid580_legacy_control_session_p2p_alloc_v1') == 'EXPORT_SYMBOL',
            'new_p2p_control_exports_exact': all(actual.get(
                'hybrid580_legacy_control_session_p2p_' + operation + '_v1') == 'EXPORT_SYMBOL'
                for operation in ('register_va_space', 'unregister_va_space',
                                  'register_vidmem', 'unregister_vidmem')),
            'new_pm_recovery_exports_exact': {
                name for name in actual if name.startswith('hybrid580_legacy_pm_recovery_')
            } == {
                'hybrid580_legacy_pm_recovery_' + operation + '_v1'
                for operation in ('begin', 'recover', 'end')
            } and all(actual.get('hybrid580_legacy_pm_recovery_' + operation + '_v1') ==
                      'EXPORT_SYMBOL' for operation in ('begin', 'recover', 'end')),
            'new_pm_channels_exports_exact': {
                name for name in actual if name.startswith('hybrid580_legacy_pm_channels_')
            } == {
                'hybrid580_legacy_pm_channels_' + operation + '_v1'
                for operation in ('suspend', 'resume')
            } and all(actual.get('hybrid580_legacy_pm_channels_' + operation + '_v1') ==
                      'EXPORT_SYMBOL' for operation in ('suspend', 'resume')),
            'kernel_imports_and_flavors_unchanged': report['imports'] == previous['imports']}
        if (len(actual) != 142 or len(undefined) != 303 or
            not report['compatibility_with_v2']['prior_export_crcs_and_flavors_unchanged'] or
            not report['compatibility_with_v2']['new_gpu_exports_exact'] or
            not report['compatibility_with_v2']['new_control_attach_export_exact'] or
            not report['compatibility_with_v2']['new_device_object_exports_exact'] or
            not report['compatibility_with_v2']['new_vaspace_export_exact'] or
            not report['compatibility_with_v2']['new_channel_group_export_exact'] or
            not report['compatibility_with_v2']['new_context_share_export_exact'] or
            not report['compatibility_with_v2']['new_channel_alloc_export_exact'] or
            not report['compatibility_with_v2']['new_engine_alloc_export_exact'] or
            not report['compatibility_with_v2']['new_subdevice_tpc_mask_exports_exact'] or
            not report['compatibility_with_v2']['new_binapi_export_exact'] or
            not report['compatibility_with_v2']['new_rusd_alloc_export_exact'] or
            not report['compatibility_with_v2']['new_usermode_export_exact'] or
            not report['compatibility_with_v2']['new_map_memory_exports_exact'] or
            not report['compatibility_with_v2']['new_device_mapping_update_export_exact'] or
            not report['compatibility_with_v2']['new_sys_params_export_exact'] or
            not report['compatibility_with_v2']['new_p2p_alloc_export_exact'] or
            not report['compatibility_with_v2']['new_p2p_control_exports_exact'] or
            not report['compatibility_with_v2']['new_pm_recovery_exports_exact'] or
            not report['compatibility_with_v2']['new_pm_channels_exports_exact'] or
            not report['compatibility_with_v2']['kernel_imports_and_flavors_unchanged']):
            raise ValueError('typed child-object bridges change prior exports or kernel import contract')
        old_exports = exports((BASE / 'Module.symvers').read_text())
        if old_exports.keys() & defined:
            raise ValueError('unprefixed public export definition retained')
        core = source / 'nvidia/nv-kernel.o_binary'
        if baseline.sha256(core) != baseline.CORE_OBJECT_SHA256:
            raise ValueError('core was modified')
        report['core'] = {'path': str(core), 'sha256': baseline.sha256(core)}
        report['shared_endpoint'] = {'path': str(source / 'nvidia/rm_session_endpoint.h'),
            'sha256': baseline.sha256(source / 'nvidia/rm_session_endpoint.h'),
            'verbatim': (source / 'nvidia/rm_session_endpoint.h').read_bytes() ==
                        (ROOT / 'src/rm_session_endpoint.h').read_bytes()}
        if not report['shared_endpoint']['verbatim'] or overlay.read_bytes() != sdk_nvos.read_bytes():
            raise ValueError('shared endpoint or SDK overlay bytes changed')
        report['gpu_session_header'] = {'path': str(gpu_header),
            'sha256': baseline.sha256(gpu_header),
            'matches_project_api_after_backend_prefix_substitution':
                gpu_header.read_bytes() == expected_gpu_header}
        composite_command = source / '.hybrid580_legacy.o.cmd'
        command_text = composite_command.read_text()
        required_flags = ('--retpoline', '--rethunk', '--sls', '--stackval')
        if 'objtool' not in command_text or not all(flag in command_text for flag in required_flags):
            raise ValueError('expected objtool checks were not invoked')
        report['objtool_command'] = {'path': str(composite_command),
             'sha256': baseline.sha256(composite_command), 'required_flags_present': list(required_flags)}
        report['source_changes'] = [{'path': str(path), 'sha256': baseline.sha256(path)}
            for path in sorted(source.rglob('*')) if path.is_file() and
            (path.suffix in {'.c', '.h', '.Kbuild'} or path.name.endswith('.Kbuild')) and
            'hybrid-sdk' not in path.parts and (not (baseline.SOURCE_ROOT / path.relative_to(source)).is_file()
                or baseline.sha256(path) != baseline.sha256(baseline.SOURCE_ROOT / path.relative_to(source)))]
        report['build_warnings'] = {'total': len(re.findall(r'(?i)warning:', output)),
             'objtool': len(re.findall(r'(?i)warning:.*objtool', output)),
             'naked_return': len(re.findall(r"warning:.*naked.*return", output)),
             'frame_pointer': len(re.findall(r"warning:.*frame pointer", output)),
             'note': 'Proprietary binary remains unchanged; no warning suppression added.'}
        report['inputs_unchanged'] = all(baseline.sha256(Path(item['path'])) == item['sha256']
                                         for item in report['inputs'])
        if not report['inputs_unchanged']:
            raise ValueError('an input changed during the build')
        report['qualification'] = 'compiled-module-and-CPU-model-only'
        report['status'] = 'compiled-private-proprietary-backend'
        code = 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, tarfile.TarError) as error:
        report.update(status='failed', qualification='build-or-analysis-failed', error=str(error))
        code = 2
    if source_before is not None:
        report['source_tree_after'] = baseline.tree_fingerprint(baseline.SOURCE_ROOT)
        report['source_tree_unchanged'] = report['source_tree_after'] == source_before
        if not report['source_tree_unchanged']:
            report['qualification'] = 'invalidated-source-mutation'
            code = 2
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'report': str(report_path), 'status': report.get('status'),
          'error': report.get('error'), 'exports': len(report.get('exports', {})),
          'imports': len(report.get('imports', {})),
          'gpl_only_imports': report.get('gpl_only_imports')}, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
