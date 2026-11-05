#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit static R595 UVM import closure against a hybrid frontend build.

This is a read-only ELF/module-version audit. It does not load or install any
module and does not exercise a GPU, RM, or UVM runtime path.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BUILDER_SPEC = importlib.util.spec_from_file_location(
    'build_hybrid_frontend', ROOT / 'tools/build_hybrid_frontend.py')
BUILDER = importlib.util.module_from_spec(BUILDER_SPEC)
BUILDER_SPEC.loader.exec_module(BUILDER)
DEFAULT_HEADER = (ROOT / 'build/experiments/r595-r580-open-fullbuild-v3-20261023'
                  / 'source/kernel-open/common/inc/nv_uvm_interface.h')
DEFAULT_UVM = Path('/lib/modules/7.0.0-38-generic/updates/dkms/nvidia-uvm.ko.zst')
DEFAULT_REFERENCE_SYMVERS = Path(
    '/var/lib/dkms/nvidia/595.99.02/7.0.0-38-generic/x86_64/module/Module.symvers')
DEFAULT_FRONTEND_DIR = ROOT / 'build/experiments/hybrid-frontend-r595-r580-v11-20261023'
DEFAULT_OPEN_SYMVERS = (ROOT / 'build/experiments/r595-r580-open-fullbuild-v3-20261023'
                        / 'source/kernel-open/Module.symvers')
DEFAULT_LEGACY_SYMVERS = (ROOT / 'build/experiments/r580-private-proprietary-build-v2-20261023'
                          / 'nvidia-580.178.04/Module.symvers')

OPEN_ONLY = frozenset({
    'nvUvmInterfaceAccessBitsBufAlloc',
    'nvUvmInterfaceAccessBitsBufFree',
    'nvUvmInterfaceAccessBitsDump',
})
FAIL_CLOSED = frozenset({
    'nvUvmInterfacePagingChannelAllocate',
    'nvUvmInterfacePagingChannelDestroy',
    'nvUvmInterfacePagingChannelsMap',
    'nvUvmInterfacePagingChannelsUnmap',
    'nvUvmInterfacePagingChannelPushStream',
})
LEGACY_RENAMES = {
    'nvUvmInterfaceRegisterUvmEvents':
        'hybrid580_legacy_nvUvmInterfaceRegisterUvmCallbacks',
    'nvUvmInterfaceDeRegisterUvmEvents':
        'hybrid580_legacy_nvUvmInterfaceDeRegisterUvmOps',
}
HYBRID_EXTENSION_APIS = frozenset({
    'nvUvmInterfaceDupAddressSpaceWithControlFd',
    'nvUvmInterfaceDupMemoryWithControlFd',
    'nvUvmInterfaceGetGpuProvider',
})
HYBRID_REPLACED_APIS = {
    'nvUvmInterfaceDupAddressSpace': 'nvUvmInterfaceDupAddressSpaceWithControlFd',
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def parse_header_api_names(path):
    text = Path(path).read_text()
    names = re.findall(r'^(?:NV_STATUS|void)\s+(nvUvmInterface\w+)\s*\(',
                       text, re.MULTILINE)
    if not names or len(names) != len(set(names)):
        raise ValueError(f'empty or duplicate standard UVM declarations in {path}')
    return tuple(names)


def parse_symvers(path):
    result = {}
    for line_number, line in enumerate(Path(path).read_text().splitlines(), 1):
        fields = line.split()
        if len(fields) < 4:
            continue
        name = fields[1]
        entry = {'crc': fields[0].lower(), 'module': fields[2], 'export': fields[3]}
        if name in result and result[name] != entry:
            raise ValueError(f'conflicting symvers entry for {name} at {path}:{line_number}')
        result[name] = entry
    return result


def parse_modversions(text):
    result = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 2 or not re.fullmatch(r'0x[0-9a-fA-F]+', fields[0]):
            raise ValueError(f'malformed modversion output at line {line_number}: {line!r}')
        name, crc = fields[1], fields[0].lower()
        if name in result and result[name] != crc:
            raise ValueError(f'conflicting module import CRCs for {name}')
        result[name] = crc
    return result


def _extended_module_versions(module, work):
    """Read Linux extended names when present; accept kernels using only __versions."""
    readelf = shutil.which('readelf')
    if not readelf:
        raise ValueError('readelf is unavailable for extended modversion section detection')
    sections = subprocess.run([readelf, '-W', '-S', str(module)],
                              capture_output=True, text=True, check=False)
    if sections.returncode:
        raise ValueError(f'readelf could not inspect module sections: {sections.stderr.strip()}')
    names = set(re.findall(r'\[\s*\d+\]\s+(\S+)', sections.stdout))
    extended = {'__version_ext_names', '__version_ext_crcs'}
    present = names & extended
    if not present:
        return {}
    if present != extended:
        raise ValueError('module contains only one Linux extended modversion section')
    return BUILDER.extract_extended_modversions(module, work)


def dump_modversions(module, modprobe=None, include_extended=False):
    modprobe = modprobe or shutil.which('modprobe')
    if not modprobe:
        raise ValueError('modprobe is unavailable; cannot inspect module imports')
    module = Path(module)
    if module.is_symlink() or not module.is_file():
        raise ValueError(f'module must be a regular non-symlink file: {module}')
    with tempfile.TemporaryDirectory(prefix='r595-uvm-modversions-') as temp_dir:
        temp_dir = Path(temp_dir)
        staged = temp_dir / module.name

        # kmod and binutils receive only a disposable copy. Some combinations
        # of target module format and host tool may rewrite their input even
        # when the operation fails; the captured artifact remains untouched.
        shutil.copyfile(module, staged)
        result = subprocess.run([modprobe, '--dump-modversions', str(staged)],
                                capture_output=True, text=True, check=False)
        if result.returncode:
            try:
                shutil.copyfile(module, staged)
                versions = BUILDER.extract_kernel_modversions_section(staged, temp_dir)
                if include_extended:
                    shutil.copyfile(module, staged)
                    extended = _extended_module_versions(staged, temp_dir)
                    versions = BUILDER.merge_module_modversions(versions, extended)
                return versions
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                raise ValueError(
                    f'modprobe --dump-modversions failed for {module}: '
                    f'{result.stderr.strip()}; ELF fallback failed: {error}') from error
        versions = parse_modversions(result.stdout)
        if include_extended:
            shutil.copyfile(module, staged)
            extended = _extended_module_versions(staged, temp_dir)
            versions = BUILDER.merge_module_modversions(versions, extended)
        return versions


def module_version(module, modinfo=None):
    modinfo = modinfo or shutil.which('modinfo')
    if not modinfo:
        raise ValueError('modinfo is unavailable; cannot identify the UVM module release')
    result = subprocess.run([modinfo, '-F', 'version', str(module)],
                            capture_output=True, text=True, check=False)
    version = result.stdout.strip()
    if result.returncode or not version:
        raise ValueError(f'modinfo could not identify {module}: {result.stderr.strip()}')
    return version


def private_provider_names(api):
    if api in FAIL_CLOSED:
        return None, None
    open_name = 'hybrid580_open_' + api
    if api in OPEN_ONLY:
        return open_name, None
    return open_name, LEGACY_RENAMES.get(api, 'hybrid580_legacy_' + api)


def crc_matches(import_crc, symvers_entry):
    return bool(import_crc and symvers_entry and
                import_crc.lower() == symvers_entry['crc'].lower())


def audit_closure(api_names, installed_imports, frontend_imports,
                  frontend_symvers, reference_symvers, open_symvers,
                  legacy_symvers):
    issues = []
    api_set = set(api_names)
    installed_api_imports = {name: crc for name, crc in installed_imports.items()
                             if name.startswith('nvUvmInterface')}
    hybrid_mode = bool(set(installed_api_imports) & HYBRID_EXTENSION_APIS)
    hybrid_mode |= any(api in api_set and api not in installed_api_imports
                       for api in HYBRID_REPLACED_APIS)
    expected_standard_imports = (api_set - set(HYBRID_REPLACED_APIS)
                                 if hybrid_mode else api_set)
    expected_extension_imports = HYBRID_EXTENSION_APIS if hybrid_mode else frozenset()
    expected_interface_imports = expected_standard_imports | set(expected_extension_imports)
    private_imports = {name: crc for name, crc in frontend_imports.items()
                        if name.startswith(('hybrid580_open_nvUvmInterface',
                                            'hybrid580_legacy_nvUvmInterface'))}
    if set(installed_api_imports) != expected_interface_imports:
        issues.append({
            'check': 'installed-module-interface-set',
            'missing': sorted(expected_interface_imports - set(installed_api_imports)),
            'unexpected': sorted(set(installed_api_imports) - expected_interface_imports),
        })
    expected_private = set()
    api_checks = {}
    for api in api_names:
        stock_crc = installed_api_imports.get(api)
        reference = reference_symvers.get(api)
        frontend_export = frontend_symvers.get(api)
        if hybrid_mode and api in HYBRID_REPLACED_APIS:
            replacement = HYBRID_REPLACED_APIS[api]
            check = {
                'installed_uvm_import_crc': None,
                'r595_reference_export_crc': reference['crc'] if reference else None,
                'frontend_export_crc': frontend_export['crc'] if frontend_export else None,
                'stock_crc_matches_reference': None,
                'stock_crc_matches_frontend_export': None,
                'hybrid_replaced_by': replacement,
                'classification': 'replaced-by-fd-aware-hybrid-extension',
            }
            if replacement not in expected_extension_imports:
                issues.append({'check': 'invalid-hybrid-api-replacement', 'api': api})
        else:
            check = {
                'installed_uvm_import_crc': stock_crc,
                'r595_reference_export_crc': reference['crc'] if reference else None,
                'frontend_export_crc': frontend_export['crc'] if frontend_export else None,
                'stock_crc_matches_reference': crc_matches(stock_crc, reference),
                'stock_crc_matches_frontend_export': crc_matches(stock_crc, frontend_export),
            }
            if not check['stock_crc_matches_reference']:
                issues.append({'check': 'stock-import-vs-r595-reference', 'api': api})
            if not check['stock_crc_matches_frontend_export']:
                issues.append({'check': 'stock-import-vs-frontend-export', 'api': api})

        open_name, legacy_name = private_provider_names(api)
        check['open_private_provider'] = open_name
        check['legacy_private_provider'] = legacy_name
        if 'classification' not in check:
            check['classification'] = ('fail-closed-no-backend-call' if api in FAIL_CLOSED else
                                       'open-only-r595-native-payload' if api in OPEN_ONLY else
                                       'dual-provider-or-adapted')
        for provider_name, symvers, provider in (
                (open_name, open_symvers, 'R595 Open'),
                (legacy_name, legacy_symvers, 'R580 legacy')):
            if provider_name is None:
                continue
            expected_private.add(provider_name)
            imported_crc = frontend_imports.get(provider_name)
            provider_entry = symvers.get(provider_name)
            matched = crc_matches(imported_crc, provider_entry)
            check[provider + '_private_import_crc'] = imported_crc
            check[provider + '_export_crc'] = provider_entry['crc'] if provider_entry else None
            check[provider + '_private_import_matches_export'] = matched
            if not matched:
                issues.append({'check': 'private-import-vs-provider-export',
                               'api': api, 'provider': provider,
                               'symbol': provider_name})
        api_checks[api] = check

    extension_checks = {}
    for extension in sorted(expected_extension_imports):
        imported_crc = installed_api_imports.get(extension)
        frontend_entry = frontend_symvers.get(extension)
        matched = crc_matches(imported_crc, frontend_entry)
        extension_checks[extension] = {
            'uvm_import_crc': imported_crc,
            'frontend_export_crc': frontend_entry['crc'] if frontend_entry else None,
            'matches': matched,
        }
        if not matched:
            issues.append({'check': 'hybrid-extension-import-vs-frontend-export',
                           'api': extension})

    actual_private = set(private_imports)
    if actual_private != expected_private:
        issues.append({
            'check': 'frontend-private-import-set',
            'missing': sorted(expected_private - actual_private),
            'unexpected': sorted(actual_private - expected_private),
        })
    return {
        'installed_uvm_interface_import_count': len(installed_api_imports),
        'installed_r595_api_import_count': len(set(installed_api_imports) & api_set),
        'hybrid_extension_import_count': len(set(installed_api_imports) & HYBRID_EXTENSION_APIS),
        'module_interface_mode': 'hybrid-extended' if hybrid_mode else 'stock-r595',
        'frontend_interface_export_count': sum(
            1 for api in api_names if api in frontend_symvers),
        'expected_private_interface_import_count': len(expected_private),
        'actual_private_interface_import_count': len(actual_private),
        'api_checks': api_checks,
        'hybrid_extension_checks': extension_checks,
        'issues': issues,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed-uvm', type=Path, default=DEFAULT_UVM)
    parser.add_argument('--r595-reference-symvers', type=Path,
                        default=DEFAULT_REFERENCE_SYMVERS)
    parser.add_argument('--r595-header', type=Path, default=DEFAULT_HEADER)
    parser.add_argument('--frontend-module', type=Path,
                        default=DEFAULT_FRONTEND_DIR / 'hybrid580_frontend.ko')
    parser.add_argument('--frontend-symvers', type=Path,
                        default=DEFAULT_FRONTEND_DIR / 'Module.symvers')
    parser.add_argument('--open-symvers', type=Path, default=DEFAULT_OPEN_SYMVERS)
    parser.add_argument('--legacy-symvers', type=Path, default=DEFAULT_LEGACY_SYMVERS)
    parser.add_argument('--report', type=Path,
                        default=ROOT / 'evidence/r595-uvm-symbol-closure-v1-20261023.json')
    args = parser.parse_args()

    inputs = {
        'installed_uvm_module': args.installed_uvm,
        'r595_reference_symvers': args.r595_reference_symvers,
        'r595_interface_header': args.r595_header,
        'frontend_module': args.frontend_module,
        'frontend_symvers': args.frontend_symvers,
        'r595_open_symvers': args.open_symvers,
        'r580_legacy_symvers': args.legacy_symvers,
    }
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if missing:
        parser.error('missing audit input: ' + ', '.join(missing))

    try:
        api_names = parse_header_api_names(args.r595_header)
        installed_module_version = module_version(args.installed_uvm)
        installed_imports = dump_modversions(args.installed_uvm)
        # The kernel is built with CONFIG_EXTENDED_MODVERSIONS. kmod's dump
        # omits long private names from the compact table, so merge the ELF
        # name/CRC sections just as the frontend build audit does.
        frontend_imports = dump_modversions(args.frontend_module,
                                            include_extended=True)
        result = audit_closure(
            api_names, installed_imports, frontend_imports,
            parse_symvers(args.frontend_symvers),
            parse_symvers(args.r595_reference_symvers),
            parse_symvers(args.open_symvers),
            parse_symvers(args.legacy_symvers))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))

    expected_standard_imports = (len(api_names) - len(HYBRID_REPLACED_APIS)
                                 if result['module_interface_mode'] == 'hybrid-extended'
                                 else len(api_names))
    expected_extensions = (len(HYBRID_EXTENSION_APIS)
                           if result['module_interface_mode'] == 'hybrid-extended' else 0)
    report = {
        'schema': 'r595-uvm-static-symbol-closure-v2',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'qualification': ('static-r595-uvm-symbol-closure' if not result['issues']
                          and result['installed_r595_api_import_count'] == expected_standard_imports
                          and result['hybrid_extension_import_count'] == expected_extensions
                          and result['frontend_interface_export_count'] == len(api_names)
                          else 'failed'),
        'scope': ('Static module import/export CRC closure only. No module was loaded or '
                  'installed; no NVIDIA RM, UVM runtime path, or GPU was exercised.'),
        'installed_module_version': installed_module_version,
        'uvm_module_under_test': str(args.installed_uvm),
        'api_count_from_pinned_header': len(api_names),
        'input_sha256': {name: sha256(path) for name, path in inputs.items()},
        **result,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    args.report.chmod(0o600)
    print(json.dumps({
        'qualification': report['qualification'],
        'api_count': report['api_count_from_pinned_header'],
        'installed_imports': result['installed_uvm_interface_import_count'],
        'module_interface_mode': result['module_interface_mode'],
        'hybrid_extensions': result['hybrid_extension_import_count'],
        'frontend_exports': result['frontend_interface_export_count'],
        'private_imports': result['actual_private_interface_import_count'],
        'issue_count': len(result['issues']),
        'report': str(args.report),
        'report_sha256': sha256(args.report),
    }, indent=2))
    return 0 if report['qualification'] == 'static-r595-uvm-symbol-closure' else 1


if __name__ == '__main__':
    sys.exit(main())
