#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only static gate for an experimental R580 module canary.

This tool never inserts, removes, signs, installs or executes a kernel module.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import collect_pc3_canary_host_state as host_collector  # noqa: E402

HOST_SCHEMA = host_collector.STATE_SCHEMA
REPORT_SCHEMA = 'nvidia-hybrid-canary-preflight-v5'
STAGED_STACK_SCHEMA = 'nvidia-r580-standard-stack-staging-v1'
STAGED_MANIFEST_SCHEMA = 'nvidia-r580-hybrid-candidate-module-manifest-v2'
STAGED_UVM_OPTION = 'uvm_hybrid_isolated_gpu_execution=1'
STAGED_STANDARD_MODULE_NAMES = {
    'open': 'hybrid580_open',
    'legacy': 'hybrid580_legacy',
    'frontend': 'nvidia',
    'uvm': 'nvidia_uvm',
}
STANDARD_BUNDLE_MODULES = {
    'open': {'name': 'hybrid580_open', 'depends': []},
    'legacy': {'name': 'hybrid580_legacy', 'depends': []},
    'frontend': {'name': 'nvidia', 'depends': ['hybrid580_legacy', 'hybrid580_open']},
    'uvm': {'name': 'nvidia_uvm', 'depends': ['nvidia']},
}
ROLE_NAMES = {
    'open': 'hybrid580_open',
    'legacy': 'hybrid580_legacy',
    'frontend': 'hybrid580_frontend',
    'uvm': 'nvidia_uvm',
}
SUPPORTED_FRONTEND_MODULE_NAMES = {ROLE_NAMES['frontend'], 'nvidia'}
REQUIRED_ROLES = tuple(ROLE_NAMES)
EXPECTED_R580_VERSION = '580.178.04'
VALID_LOCKDOWN_MODES = {'none', 'integrity', 'confidentiality'}
LINUX_DEV_T_MAJOR_MAX = (1 << 12) - 1
LINUX_DEV_T_MINOR_MAX = (1 << 20) - 1
EXPECTED_STANDARD_NODE_LAYOUT = {
    'major': 195, 'gpu_minor_first': 0,
    'gpu_minor_last': 247, 'control_minor': 255,
}
SIGNATURE_TRUST_SCHEMA = 'nvidia-module-signature-trust-v1'
MAX_HOST_SNAPSHOT_AGE = timedelta(minutes=5)
MAX_HOST_SNAPSHOT_CLOCK_SKEW = timedelta(seconds=30)


def _validate_standard_node_layout(layout):
    if layout['major'] > LINUX_DEV_T_MAJOR_MAX:
        raise ValueError('character-device major exceeds Linux dev_t range')
    for field in ('gpu_minor_first', 'gpu_minor_last', 'control_minor'):
        if layout[field] > LINUX_DEV_T_MINOR_MAX:
            raise ValueError(field + ' exceeds Linux dev_t minor range')
    if layout != EXPECTED_STANDARD_NODE_LAYOUT:
        raise ValueError('standard-node layout differs from the audited R580.178.04 mapping')


def _required_int(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(name + ' must be an integer >= ' + str(minimum))
    return value


def _validate_inputs(host, modules, layout):
    if not isinstance(host, dict):
        raise ValueError('host state must be an object')
    if host.get('schema') != HOST_SCHEMA:
        raise ValueError('unsupported host-state schema')
    if not isinstance(host.get('host'), str) or host['host'].lower() != 'pc3':
        raise ValueError('expected PC3 host identity')
    if not isinstance(host.get('observed_at_utc'), str):
        raise ValueError('observation timestamp must be UTC RFC3339')
    if host.get('active_modules_scope') != 'all':
        raise ValueError('complete active-module inventory is required')
    if not isinstance(host.get('boot_id'), str):
        raise ValueError('boot ID is invalid')
    if not isinstance(host.get('kernel_release'), str) or not host['kernel_release']:
        raise ValueError('host kernel release is required')
    if not isinstance(host.get('kernel_vermagic'), str) or not host['kernel_vermagic'].strip():
        raise ValueError('host kernel vermagic is required')
    for key in ('secure_boot_enabled', 'module_sig_enforce'):
        if type(host.get(key)) is not bool:
            raise ValueError(key + ' must be boolean')
    if (not isinstance(host.get('lockdown'), str) or
            host['lockdown'].strip().lower() not in VALID_LOCKDOWN_MODES):
        raise ValueError('unsupported lockdown mode')
    devices = host.get('active_char_devices')
    if not isinstance(devices, list):
        raise ValueError('active_char_devices must be a list')
    for device in devices:
        if not isinstance(device, dict):
            raise ValueError('active character-device entries must be objects')
        device_major = _required_int(device.get('major'), 'device major', 1)
        device_minor = _required_int(device.get('minor'), 'device minor')
        if device_major > LINUX_DEV_T_MAJOR_MAX or device_minor > LINUX_DEV_T_MINOR_MAX:
            raise ValueError('active character-device number exceeds Linux dev_t range')
    active_modules = host.get('active_modules')
    if not isinstance(active_modules, list):
        raise ValueError('active_modules must be a list')
    active_module_names = []
    for active_module in active_modules:
        if (not isinstance(active_module, dict) or
                not isinstance(active_module.get('name'), str) or
                not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', active_module['name'])):
            raise ValueError('active module record is invalid')
        active_module_names.append(active_module['name'])
    if len(active_module_names) != len(set(active_module_names)):
        raise ValueError('active module inventory contains duplicate names')
    char_device_major_names = host.get('char_device_major_names')
    if not isinstance(char_device_major_names, list):
        raise ValueError('char_device_major_names must be a list')
    for item in char_device_major_names:
        if (not isinstance(item, dict) or
                type(item.get('major')) is not int or
                not 1 <= item['major'] <= LINUX_DEV_T_MAJOR_MAX or
                not isinstance(item.get('name'), str) or
                not re.fullmatch(r'[A-Za-z0-9_./+-]{1,255}', item['name'])):
            raise ValueError('character-device major record is invalid')
    major_name_pairs = [(item['major'], item['name']) for item in char_device_major_names]
    if len(major_name_pairs) != len(set(major_name_pairs)):
        raise ValueError('character-device major inventory contains duplicates')
    loaded_nvidia_modules = host.get('loaded_nvidia_modules')
    if not isinstance(loaded_nvidia_modules, list):
        raise ValueError('loaded_nvidia_modules must be a list')
    if loaded_nvidia_modules != [name for name in active_module_names if name.startswith('nvidia')]:
        raise ValueError('loaded NVIDIA module inventory differs from complete active-module inventory')

    if not isinstance(modules, dict) or set(modules) != set(REQUIRED_ROLES):
        raise ValueError('candidate modules must contain exactly: ' + ', '.join(REQUIRED_ROLES))
    for role in REQUIRED_ROLES:
        module = modules[role]
        if not isinstance(module, dict):
            raise ValueError(role + ' module metadata must be an object')
        for key in ('name', 'version', 'vermagic', 'signer', 'depends'):
            if not isinstance(module.get(key), str):
                raise ValueError(role + '.' + key + ' must be a string')
        for key in ('sig_key', 'sha256'):
            if key in module and not isinstance(module[key], str):
                raise ValueError(role + '.' + key + ' must be a string')

    if not isinstance(layout, dict):
        raise ValueError('standard node layout must be an object')
    _required_int(layout.get('major'), 'node major', 1)
    _required_int(layout.get('gpu_minor_first'), 'first GPU minor')
    _required_int(layout.get('gpu_minor_last'), 'last GPU minor')
    _required_int(layout.get('control_minor'), 'control minor')
    if layout['gpu_minor_first'] > layout['gpu_minor_last']:
        raise ValueError('GPU minor range is reversed')
    _validate_standard_node_layout(layout)
    return devices


def _candidate_signature_trust_matches(host, modules):
    evidence = host.get('module_signature_trust')
    if not isinstance(evidence, dict):
        return False
    kernel = host['kernel_release']
    boot_id = host.get('boot_id')
    keyring_digest = evidence.get('target_keyring_sha256')
    evidence_digest = evidence.get('evidence_sha256')
    roles = evidence.get('roles')
    digest_pattern = re.compile(r'^[0-9a-f]{64}$')
    if (evidence.get('schema') != SIGNATURE_TRUST_SCHEMA or
            evidence.get('kernel_release') != kernel or
            not isinstance(boot_id, str) or not boot_id or
            evidence.get('boot_id') != boot_id or
            not isinstance(keyring_digest, str) or
            not digest_pattern.fullmatch(keyring_digest) or
            not isinstance(evidence_digest, str) or
            not digest_pattern.fullmatch(evidence_digest) or
            not isinstance(roles, dict) or set(roles) != set(REQUIRED_ROLES)):
        return False

    for role, module in modules.items():
        record = roles.get(role)
        module_digest = module.get('sha256')
        signer = module['signer'].strip()
        sig_key = module.get('sig_key', '').strip()
        if (not isinstance(record, dict) or
                not isinstance(module_digest, str) or
                not digest_pattern.fullmatch(module_digest) or not signer or not sig_key or
                record.get('module_sha256') != module_digest or
                record.get('signer') != signer or
                record.get('sig_key') != sig_key or
                record.get('kernel_release') != kernel or
                record.get('boot_id') != boot_id or
                record.get('target_keyring_sha256') != keyring_digest or
                record.get('signature_valid') is not True or
                record.get('key_trusted') is not True):
            return False
    return True


def evaluate_preflight(
        host, modules, layout, now_utc=None,
        expected_frontend_module_name=ROLE_NAMES['frontend'],
        expected_uvm_module_name=ROLE_NAMES['uvm'],
        expected_uvm_chardev_name='nvidia-uvm',
        audited_candidate_versions=None):
    if (not isinstance(expected_frontend_module_name, str) or
            expected_frontend_module_name not in SUPPORTED_FRONTEND_MODULE_NAMES):
        raise ValueError('expected frontend module name is unsupported')
    """Evaluate static compatibility gates without implying runtime readiness."""
    if (not isinstance(expected_uvm_module_name, str) or
            not re.fullmatch(r'[A-Za-z0-9_]{1,63}', expected_uvm_module_name)):
        raise ValueError('expected UVM module name is invalid')
    if (not isinstance(expected_uvm_chardev_name, str) or
            not re.fullmatch(r'[A-Za-z0-9_./+-]{1,255}', expected_uvm_chardev_name)):
        raise ValueError('expected UVM character-device name is invalid')
    expected_module_names = dict(ROLE_NAMES)
    expected_module_names['frontend'] = expected_frontend_module_name
    expected_module_names['uvm'] = expected_uvm_module_name
    if len(set(expected_module_names.values())) != len(expected_module_names):
        raise ValueError('expected UVM module name must be unique')
    devices = _validate_inputs(host, modules, layout)
    host_collector.validate_collection_report(host)
    try:
        observed_at = datetime.fromisoformat(host['observed_at_utc'][:-1] + '+00:00')
    except (TypeError, ValueError) as error:
        raise ValueError('observation timestamp must be UTC RFC3339') from error
    if observed_at.tzinfo != timezone.utc:
        raise ValueError('observation timestamp must be UTC RFC3339')
    now_utc = datetime.now(timezone.utc) if now_utc is None else now_utc
    if not isinstance(now_utc, datetime) or now_utc.tzinfo is None:
        raise ValueError('preflight clock must be timezone-aware')
    now_utc = now_utc.astimezone(timezone.utc)
    age = now_utc - observed_at
    if age > MAX_HOST_SNAPSHOT_AGE:
        raise ValueError('host-state snapshot is stale')
    if age < -MAX_HOST_SNAPSHOT_CLOCK_SKEW:
        raise ValueError('observation timestamp is in the future')
    blockers = []

    def block(code, detail):
        blockers.append({'code': code, 'detail': detail})

    kernel = host['kernel_release']
    all_active_module_names = {
        record['name'].replace('-', '_') for record in host['active_modules']
    }
    active_module_names = all_active_module_names
    active_nvidia_module_names = {
        name for name in all_active_module_names if name.startswith('nvidia')
    }
    module_name_conflicts = []
    for role, module in modules.items():
        name = module['name'].replace('-', '_')
        if name in active_module_names:
            conflict = {'role': role, 'name': name}
            module_name_conflicts.append(conflict)
            block('loaded_module_name_conflict',
                  'candidate ' + role + ' module name ' + name +
                  ' is already loaded on the target host')

    kernel_vermagic = host['kernel_vermagic'].strip()
    for role, module in modules.items():
        if module['name'] != expected_module_names[role]:
            block('module_identity_mismatch', role + ' is named ' + module['name'])
        module_kernel = module['vermagic'].split()[0] if module['vermagic'].split() else ''
        if module_kernel != kernel:
            block('kernel_release_mismatch',
                  role + ' vermagic targets ' + (module_kernel or '<missing>') +
                  ', host runs ' + kernel)
        if module['vermagic'].strip() != kernel_vermagic:
            block('kernel_vermagic_mismatch',
                  role + ' vermagic differs from the target kernel vermagic')

    versions = {role: modules[role]['version'] for role in ('open', 'legacy', 'uvm')}
    if audited_candidate_versions is None:
        unsupported = [role for role, version in versions.items()
                       if version != EXPECTED_R580_VERSION]
        if unsupported:
            block('unsupported_candidate_version',
                  'only audited R580 ' + EXPECTED_R580_VERSION + ' candidates are accepted; '
                  'mismatched roles: ' + ', '.join(unsupported))
        if not versions['open'] or len(set(versions.values())) != 1:
            block('backend_version_mismatch',
                  'Open, proprietary and UVM modules must share one R580 version')
    else:
        if (not isinstance(audited_candidate_versions, dict) or
                set(audited_candidate_versions) != {'open', 'legacy', 'uvm'}):
            raise ValueError('audited candidate version map is invalid')
        mismatched = [role for role in versions
                      if versions[role] != audited_candidate_versions[role]]
        if mismatched:
            block('candidate_bundle_version_mismatch',
                  'module versions differ from the pinned static bundle audit: ' +
                  ', '.join(mismatched))

    expected_dependencies = {
        'open': (),
        'legacy': (),
        'frontend': (ROLE_NAMES['open'], ROLE_NAMES['legacy']),
        'uvm': (expected_frontend_module_name,),
    }
    for role, expected in expected_dependencies.items():
        actual = tuple(sorted(part.strip() for part in
                              modules[role]['depends'].split(',') if part.strip()))
        if actual != tuple(sorted(expected)):
            block(role + '_dependency_mismatch',
                  role + ' module dependencies differ from the audited graph')

    lockdown_active = host['lockdown'].strip().lower() != 'none'
    signature_required = (host['module_sig_enforce'] or host['secure_boot_enabled'] or
                          lockdown_active)
    unsigned_roles = [role for role, module in modules.items() if not module['signer'].strip()]
    if signature_required and unsigned_roles:
        block('unsigned_modules_rejected_by_policy',
              'kernel policy requires signatures; unsigned roles: ' + ', '.join(unsigned_roles))
    signature_trust_verified = _candidate_signature_trust_matches(host, modules)
    if signature_required and not signature_trust_verified:
        block('signature_trust_unverified',
              'signature policy is active, but trust for the exact candidate signatures '
              'has not been verified against the target kernel keyrings')

    first = layout['gpu_minor_first']
    last = layout['gpu_minor_last']
    control = layout['control_minor']
    occupied = []
    for device in devices:
        minor = device['minor']
        overlaps = (device['major'] == layout['major'] and
                    (first <= minor <= last or minor == control))
        if overlaps:
            occupied.append({'path': device.get('path', ''),
                             'major': device['major'], 'minor': minor})
    if occupied:
        block('standard_device_numbers_in_use',
              'candidate reserves major ' + str(layout['major']) +
              ' minors ' + str(first) + '-' + str(last) + ' and ' + str(control) +
              '; active nodes overlap: ' + ', '.join(
                  str(item['major']) + ':' + str(item['minor']) for item in occupied))

    major_owners = [item for item in host['char_device_major_names']
                    if item['major'] == layout['major']]
    if major_owners:
        block('standard_device_major_in_use',
              'candidate reserves character-device major ' + str(layout['major']) +
              '; /proc/devices assigns it to: ' + ', '.join(
                  item['name'] for item in major_owners))

    uvm_chardev_name_conflicts = [
        {'name': expected_uvm_chardev_name, 'major': item['major']}
        for item in host['char_device_major_names']
        if item['name'] == expected_uvm_chardev_name
    ]
    if uvm_chardev_name_conflicts:
        block('character_device_name_in_use',
              'candidate UVM registration label ' + expected_uvm_chardev_name +
              ' is already present in the target /proc/devices inventory; its major '
              'would be ambiguous to name-based userspace discovery')

    return {
        'schema': REPORT_SCHEMA,
        'host': host['host'],
        'observed_at_utc': host.get('observed_at_utc'),
        'kernel_release': kernel,
        'status': 'blocked' if blockers else 'static-preflight-clear',
        'qualification': 'static-preflight-only',
        'blockers': blockers,
        'active_nvidia_modules': sorted(active_nvidia_module_names),
        'active_module_inventory_scope': host['active_modules_scope'],
        'active_module_count': len(host['active_modules']),
        'candidate_module_name_conflicts': module_name_conflicts,
        'candidate_chardev_name_conflicts': uvm_chardev_name_conflicts,
        'expected_module_names': expected_module_names,
        'expected_uvm_chardev_name': expected_uvm_chardev_name,
        'expected_frontend_module_name': expected_frontend_module_name,
        'candidate_versions': versions,
        'standard_node_layout': {
            'major': layout['major'], 'gpu_minor_first': first,
            'gpu_minor_last': last, 'control_minor': control,
        },
        'signature_policy_requires_signature': signature_required,
        'signature_trust_verified': signature_trust_verified,
        'tool_loaded_modules': False,
        'tool_installed_modules': False,
        'runtime_validated': False,
        'canary_ready': False,
    }


def _read_stable_regular_file(path, label):
    path = Path(path)
    before_path = path.lstat()
    if not stat.S_ISREG(before_path.st_mode):
        raise ValueError(label + ' must be a regular non-symlink file: ' + str(path))
    if not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('O_NOFOLLOW is required to read ' + label)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                 row.st_mtime_ns, row.st_ctime_ns)
        if identity(before_path) != identity(before):
            raise ValueError(label + ' changed before read: ' + str(path))
        data = stream.read()
        after = os.fstat(stream.fileno())
        if identity(before) != identity(after) or len(data) != after.st_size:
            raise ValueError(label + ' changed during read: ' + str(path))
    return data


def _strip_comments_and_literals(text):
    def replace(match):
        token = match.group(0)
        line_breaks = token.count('\n')
        # C replaces comments with whitespace; removing an empty comment
        # outright can fuse directive tokens and hide a macro override.
        return (' ' if not line_breaks else '') + ('\n' * line_breaks)

    return re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        replace, text, flags=re.DOTALL)


def _parse_standard_node_layout(header, source):
    # The target toolchain accepts CR-only files; normalize all standard C
    # line endings before checking directive boundaries or line splices.
    header = header.replace('\r\n', '\n').replace('\r', '\n')
    source = source.replace('\r\n', '\n').replace('\r', '\n')
    if re.search(r'\\[ \t\f\v]+\n', header) or re.search(
            r'\\[ \t\f\v]+\n', source):
        raise ValueError('node-layout inputs contain a GCC spaced line continuation')
    trigraphs = ('??=', '??/', "??'", '??(', '??)', '??!', '??<', '??>', '??-')
    if any(token in header or token in source for token in trigraphs):
        raise ValueError('node-layout inputs contain an unsupported C trigraph')
    # C translation phase 2 joins backslash-newline pairs before directives
    # are parsed. Normalize first so a continued #define cannot bypass the
    # source override guard below.
    header = _strip_comments_and_literals(
        header.replace('\\\r\n', '').replace('\\\n', ''))
    source = _strip_comments_and_literals(
        source.replace('\\\r\n', '').replace('\\\n', ''))
    audited_node_macros = (
        'NV_MAJOR_DEVICE_NUMBER',
        'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX',
        'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE',
    )
    override = re.compile(
        r'^\s*(?:#|%:)\s*(?:define|undef)\s+(?:' +
        '|'.join(map(re.escape, audited_node_macros)) + r')\b', re.MULTILINE)
    if override.search(source):
        raise ValueError('frontend source overrides audited standard-node macros')
    undefinition = re.compile(
        r'^\s*(?:#|%:)\s*undef\s+(?:' +
        '|'.join(map(re.escape, audited_node_macros)) + r')\b', re.MULTILINE)
    if undefinition.search(header):
        raise ValueError('node header undefines an audited standard-node macro')

    def macro(name):
        definitions = []
        directive = re.compile(r'^\s*(?:#|%:)\s*define\s+' +
                               re.escape(name) + r'\b(.*)$')
        for line in header.splitlines():
            match = directive.fullmatch(line)
            if match:
                definitions.append(match.group(1).strip())
        if len(definitions) != 1:
            raise ValueError(name + ' must have exactly one definition')
        value = definitions[0]
        integer = re.fullmatch(
            r'(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)'
            r'(?:[uU](?:ll|LL|l|L)?|(?:ll|LL|l|L)[uU]?)?', value)
        if not integer:
            raise ValueError(name + ' must be a single integer literal')
        digits = integer.group(1)
        base = (16 if digits.lower().startswith('0x') else
                8 if len(digits) > 1 and digits.startswith('0') else 10)
        return int(digits, base)
    registration = r'(?<![A-Za-z0-9_])register_chrdev_region\s*\('
    gpu_region = re.search(
        registration + r'\s*MKDEV\(\s*NV_MAJOR_DEVICE_NUMBER\s*,\s*0\s*\)\s*,\s*'
        r'NV_MINOR_DEVICE_NUMBER_REGULAR_MAX\s*\+\s*1U\s*,\s*[^,)]+\s*\)', source)
    control_region = re.search(
        registration + r'\s*MKDEV\(\s*NV_MAJOR_DEVICE_NUMBER\s*,\s*'
        r'NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE\s*\)\s*,\s*1\s*,\s*[^,)]+\s*\)', source)
    if not gpu_region or not control_region:
        raise ValueError('frontend source does not contain the expected standard-node reservations')
    layout = {
        'major': macro('NV_MAJOR_DEVICE_NUMBER'),
        'gpu_minor_first': 0,
        'gpu_minor_last': macro('NV_MINOR_DEVICE_NUMBER_REGULAR_MAX'),
        'control_minor': macro('NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE'),
    }
    _validate_standard_node_layout(layout)
    return layout


def parse_standard_node_layout(header_path, source_path):
    header = _read_stable_regular_file(header_path, 'node header').decode('utf-8')
    source = _read_stable_regular_file(source_path, 'frontend source').decode('utf-8')
    return _parse_standard_node_layout(header, source)


def _module_metadata(role, path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('candidate module must be a regular non-symlink file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if (info.st_dev, info.st_ino, info.st_size) != (
                before.st_dev, before.st_ino, before.st_size):
            raise ValueError('candidate module changed before snapshot: ' + str(path))
        digest = hashlib.sha256()
        with tempfile.TemporaryDirectory(prefix='pc3-canary-preflight-') as temp_dir:
            snapshot = Path(temp_dir) / 'module.ko'
            with snapshot.open('xb') as target:
                while data := source.read(1024 * 1024):
                    digest.update(data)
                    target.write(data)
            after = os.fstat(source.fileno())
            identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                     row.st_mtime_ns, row.st_ctime_ns)
            if identity(before) != identity(after) or after.st_size != snapshot.stat().st_size:
                raise ValueError('candidate module changed during snapshot: ' + str(path))
            try:
                result = subprocess.run(['modinfo', str(snapshot)], check=True,
                                        capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as error:
                raise ValueError('modinfo failed for ' + str(path) + ': ' + str(error)) from error
            fields = {}
            for line in result.stdout.splitlines():
                key, separator, value = line.partition(':')
                if separator and key in ('name', 'version', 'vermagic', 'signer',
                                         'sig_key', 'depends'):
                    fields.setdefault(key.strip(), value.strip())
            for key in ('name', 'version', 'vermagic', 'signer', 'sig_key', 'depends'):
                fields.setdefault(key, '')
    fields['role'] = role
    fields['path'] = str(path.resolve())
    fields['sha256'] = digest.hexdigest()
    fields['bytes'] = info.st_size
    return fields


def validate_candidate_bundle_evidence(
        *, audit_report_path, expected_audit_sha256, depmod_report_path,
        expected_depmod_sha256, modules, kernel_release):
    """Bind exact CLI module bytes to a static bundle audit and kmod receipt."""
    def read_pinned(path_value, expected_hash, label):
        raw = _read_stable_regular_file(path_value, label)
        actual_hash = hashlib.sha256(raw).hexdigest()
        if (not isinstance(expected_hash, str) or
                not re.fullmatch(r'[0-9a-fA-F]{64}', expected_hash) or
                actual_hash != expected_hash.lower()):
            raise ValueError(label + ' SHA-256 mismatch')
        value = _parse_json_bytes(raw)
        if not isinstance(value, dict):
            raise ValueError(label + ' must contain a JSON object')
        return value, Path(path_value).resolve(strict=True), actual_hash

    audit, audit_path, audit_hash = read_pinned(
        audit_report_path, expected_audit_sha256, 'candidate bundle audit')
    depmod, depmod_path, depmod_hash = read_pinned(
        depmod_report_path, expected_depmod_sha256, 'candidate depmod report')
    if (audit.get('schema') != 'hybrid-module-bundle-static-audit-v1' or
            audit.get('status') != 'passed' or
            audit.get('qualification') != 'static-module-bundle-closure' or
            audit.get('runtime_or_hardware_validated') is not False):
        raise ValueError('candidate bundle audit is not a passed static-only report')
    if (depmod.get('schema') != 'hybrid-module-bundle-depmod-static-v1' or
            depmod.get('status') != 'passed' or
            depmod.get('qualification') != 'isolated-dependency-map-only' or
            depmod.get('runtime_or_hardware_validated') is not False or
            depmod.get('loaded_or_installed') is not False):
        raise ValueError('candidate depmod report contains an unexpected runtime or installation claim')
    if (depmod.get('kernel_release') != kernel_release or
            depmod.get('audit_report_sha256') != audit_hash):
        raise ValueError('candidate depmod report does not bind the exact bundle audit or kernel')

    expected = STANDARD_BUNDLE_MODULES
    bundle_modules = audit.get('modules')
    if not isinstance(bundle_modules, dict) or set(bundle_modules) != set(expected):
        raise ValueError('candidate bundle audit does not identify the exact four module roles')
    if not isinstance(modules, dict) or set(modules) != set(expected):
        raise ValueError('candidate module inputs do not identify the exact four roles')
    depmod_modules = depmod.get('modules')
    if not isinstance(depmod_modules, dict) or set(depmod_modules) != set(expected):
        raise ValueError('candidate depmod report does not identify the exact four module roles')

    versions = {}
    for role, contract in expected.items():
        audited = bundle_modules[role]
        actual = modules[role]
        staged = depmod_modules[role]
        if (audited.get('name') != contract['name'] or
                actual.get('name') != contract['name'] or
                sorted(audited.get('depends', [])) != sorted(contract['depends'])):
            raise ValueError('candidate bundle module identity or dependency graph differs for ' + role)
        if (actual.get('depends', '') != ','.join(sorted(contract['depends'])) and
                sorted(item for item in actual.get('depends', '').split(',') if item) !=
                sorted(contract['depends'])):
            raise ValueError('candidate module dependency metadata differs for ' + role)
        if (audited.get('vermagic', '').split(maxsplit=1)[:1] != [kernel_release] or
                actual.get('vermagic', '').split(maxsplit=1)[:1] != [kernel_release]):
            raise ValueError('candidate bundle module vermagic differs for ' + role)
        module_path = Path(audited.get('path', ''))
        try:
            same_path = module_path.resolve(strict=True) == Path(actual.get('path', '')).resolve(strict=True)
        except OSError:
            same_path = False
        if (not same_path or audited.get('sha256') != actual.get('sha256') or
                audited.get('sha256') != staged.get('sha256') or
                staged.get('size_bytes') != actual.get('bytes') or
                staged.get('name') != contract['name'] or
                staged.get('staged_name') != {
                    'open': 'hybrid580_open.ko', 'legacy': 'hybrid580_legacy.ko',
                    'frontend': 'nvidia.ko', 'uvm': 'nvidia_uvm.ko',
                }[role]):
            raise ValueError('candidate module bytes or path differ from the bundle audit for ' + role)
        versions[role] = actual.get('version', '')

    expected_order = {
        'nvidia': {'hybrid580_open.ko', 'hybrid580_legacy.ko', 'nvidia.ko'},
        'nvidia_uvm': {
            'hybrid580_open.ko', 'hybrid580_legacy.ko', 'nvidia.ko', 'nvidia_uvm.ko',
        },
    }
    resolution = depmod.get('resolution')
    if not isinstance(resolution, dict) or set(resolution) != set(expected_order):
        raise ValueError('candidate depmod report has an incomplete dependency resolution order')
    dependency_order = {}
    for target, expected_files in expected_order.items():
        ordered = resolution[target].get('ordered_modules')
        if (not isinstance(ordered, list) or len(ordered) != len(expected_files) or
                set(ordered) != expected_files or
                not ordered or ordered[-1] != ('nvidia.ko' if target == 'nvidia' else 'nvidia_uvm.ko')):
            raise ValueError('candidate depmod report has an invalid dependency resolution order for ' + target)
        dependency_order[target] = ordered

    return {
        'qualification': 'static-bundle-and-kmod-order-validated',
        'module_count': len(expected),
        'audit_report': {'path': str(audit_path), 'sha256': audit_hash},
        'depmod_report': {'path': str(depmod_path), 'sha256': depmod_hash},
        'versions': versions,
        'dependency_order': dependency_order,
        'runtime_or_hardware_validated': False,
        'loaded_or_installed': False,
    }


def _parse_json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique)


def _staged_module_tree_records(stage_root, release):
    """Hash the stage's module tree independently of its producer report."""
    module_tree = stage_root
    for part in ('lib', 'modules', release):
        module_tree = module_tree / part
        try:
            info = module_tree.lstat()
        except OSError:
            raise ValueError('staged module tree is missing a directory component') from None
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('staged module tree path contains a non-directory or symlink')
    records = []
    for current, directories, filenames in os.walk(module_tree, topdown=True, followlinks=False):
        base = Path(current)
        directories.sort()
        filenames.sort()
        for name in directories:
            entry = base / name
            info = entry.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('staged module tree contains a non-directory: ' + str(entry))
        for name in filenames:
            entry = base / name
            raw = _read_stable_regular_file(entry, 'staged module-tree file')
            records.append({
                'relative_path': entry.relative_to(module_tree).as_posix(),
                'bytes': len(raw),
                'sha256': hashlib.sha256(raw).hexdigest(),
            })
    if not records:
        raise ValueError('staged module tree is empty')
    return sorted(records, key=lambda record: record['relative_path'])


def _independent_staged_modprobe_dry_run(stage_root, config_path, release):
    """Repeat and validate the staged-only kmod resolution without insertion."""
    executable = shutil.which('modprobe', path='/usr/sbin:/usr/bin:/sbin:/bin')
    if not executable:
        raise ValueError('modprobe is unavailable for independent staged dry-run')
    argv = [executable, '-C', str(config_path), '-d', str(stage_root), '-S', release,
            '--show-depends', 'nvidia_uvm']
    try:
        result = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=30,
            stdin=subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('independent staged modprobe dry-run failed: ' + str(error)) from error
    if result.returncode != 0:
        raise ValueError('independent staged modprobe dry-run exited ' + str(result.returncode))
    if result.stderr:
        raise ValueError('independent staged modprobe dry-run emitted stderr')

    lines = result.stdout.splitlines()
    if not lines or lines[0] != 'builtin ecdh_generic':
        raise ValueError('independent staged dry-run has an unexpected builtin prelude')
    insmod_lines = [line for line in lines if line.startswith('insmod ')]
    if lines != [lines[0], *insmod_lines] or len(insmod_lines) != 5:
        raise ValueError('independent staged dry-run returned an unexpected insertion plan')
    expected_order = ['ecdsa_generic', 'hybrid580_open', 'hybrid580_legacy', 'nvidia',
                      'nvidia_uvm']
    module_filenames = {
        'hybrid580_open': 'hybrid580_open.ko',
        'hybrid580_legacy': 'hybrid580_legacy.ko',
        'nvidia': 'nvidia.ko',
        'nvidia_uvm': 'nvidia-uvm.ko',
    }
    observed_order = []
    for line, expected_name in zip(insmod_lines, expected_order, strict=True):
        fields = line.split()
        if len(fields) < 2:
            raise ValueError('independent staged dry-run returned malformed insmod output')
        module_path = Path(fields[1])
        try:
            resolved = module_path.resolve(strict=True)
            relative = resolved.relative_to(stage_root)
        except (OSError, ValueError):
            raise ValueError('independent staged dry-run escaped the staged root') from None
        if expected_name == 'ecdsa_generic':
            expected_relative = (Path('lib/modules') / release / 'kernel/crypto' /
                                 'ecdsa_generic.ko.zst')
        else:
            expected_relative = (Path('lib/modules') / release / 'updates' /
                                 module_filenames[expected_name])
        if relative != expected_relative or module_path.is_symlink():
            raise ValueError('independent staged dry-run resolved an unexpected module path')
        actual_name = (module_path.name.removesuffix('.ko.zst').removesuffix('.ko')
                       .replace('-', '_'))
        if actual_name != expected_name:
            raise ValueError('independent staged dry-run changed module insertion order')
        options = fields[2:]
        expected_options = [STAGED_UVM_OPTION] if expected_name == 'nvidia_uvm' else []
        if options != expected_options:
            raise ValueError('independent staged dry-run has unexpected module options')
        observed_order.append(actual_name)
    return observed_order


def validate_staged_stack(stage_root, modules):
    """Bind the standard-name preflight modules to a staged manifest/config pair."""
    stage_root = Path(stage_root)
    if stage_root.is_symlink() or not stage_root.is_dir():
        raise ValueError('staged stack must be a non-symlink directory')
    stage_root = stage_root.resolve(strict=True)

    def safe_stage_file(relative, label):
        if not isinstance(relative, str) or not relative or '\\' in relative or '\x00' in relative:
            raise ValueError(label + ' path is invalid')
        rel = PurePosixPath(relative)
        if rel.is_absolute() or any(part in ('', '.', '..') for part in rel.parts):
            raise ValueError(label + ' path is unsafe')
        path = stage_root.joinpath(*rel.parts)
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(stage_root)
        except (OSError, ValueError):
            raise ValueError(label + ' path escapes or is missing from staged stack') from None
        current = stage_root
        for index, part in enumerate(rel.parts):
            current = current / part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(label + ' path contains a symlink component')
            final_component = index == len(rel.parts) - 1
            if final_component:
                valid_type = stat.S_ISREG(info.st_mode)
            else:
                valid_type = stat.S_ISDIR(info.st_mode)
            if not valid_type:
                raise ValueError(label + ' path contains a non-directory or non-regular component')
        if not resolved.is_file():
            raise ValueError(label + ' must be a regular non-symlink file')
        return resolved

    manifest_path = safe_stage_file('candidate-manifest.json', 'candidate manifest')
    staging_report_path = safe_stage_file('staging-report.json', 'staging report')
    manifest_raw = _read_stable_regular_file(manifest_path, 'staged candidate manifest')
    report_raw = _read_stable_regular_file(staging_report_path, 'staged stack report')
    manifest = _parse_json_bytes(manifest_raw)
    report = _parse_json_bytes(report_raw)
    if not isinstance(manifest, dict) or manifest.get('schema') != STAGED_MANIFEST_SCHEMA:
        raise ValueError('staged candidate manifest schema is unsupported')
    if (manifest.get('module_loaded_or_installed') is not False or
            manifest.get('runtime_or_hardware_validated') is not False or
            manifest.get('activation_authorized') is not False or
            manifest.get('pc3_preflight', {}).get('status') != 'blocked'):
        raise ValueError('staged candidate manifest has unsafe activation or qualification state')
    if (report.get('schema') != STAGED_STACK_SCHEMA or
            report.get('qualification') != 'isolated-module-tree-staged-and-dry-run-resolved' or
            report.get('activation_performed') is not False or
            report.get('module_loaded_or_installed') is not False or
            report.get('runtime_or_hardware_validated') is not False or
            report.get('pc3_preflight_status') != 'blocked'):
        raise ValueError('staging report is not a non-activated isolated stage')
    if (report.get('manifest') != {
            'relative_path': 'candidate-manifest.json',
            'sha256': hashlib.sha256(manifest_raw).hexdigest()}):
        raise ValueError('staging report does not authenticate the staged manifest')

    release = manifest.get('candidate', {}).get('kernel_release')
    if not isinstance(release, str) or not re.fullmatch(r'[A-Za-z0-9._+-]+', release):
        raise ValueError('staged candidate kernel release is invalid')
    if report.get('kernel_release') != release:
        raise ValueError('staging report kernel release differs from manifest')
    expected_order = ['ecdsa_generic', 'hybrid580_open', 'hybrid580_legacy', 'nvidia', 'nvidia_uvm']

    runtime = manifest.get('runtime_configuration', {})
    config_record = runtime.get('modprobe_config', {})
    if (runtime.get('module') != 'nvidia_uvm' or
            runtime.get('options') != [STAGED_UVM_OPTION] or
            runtime.get('isolated_mode_required') is not True):
        raise ValueError('manifest does not require the exact isolated UVM option')
    config_rel = 'etc/modprobe.d/hybrid580-standard-uvm.conf'
    config_path = safe_stage_file(config_rel, 'staged modprobe configuration')
    config_raw = _read_stable_regular_file(config_path, 'staged modprobe configuration')
    config_hash = hashlib.sha256(config_raw).hexdigest()
    active_lines = [line.strip() for line in config_raw.decode('utf-8').splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
    if (config_record.get('path') != 'packaging/modprobe.d/hybrid580-standard-uvm.conf' or
            config_record.get('sha256') != config_hash or
            active_lines != ['options nvidia_uvm ' + STAGED_UVM_OPTION]):
        raise ValueError('staged modprobe configuration hash or isolated option differs')
    report_config = report.get('configuration', {})
    if (report_config.get('relative_path') != config_rel or
            report_config.get('sha256') != config_hash or
            report_config.get('module') != 'nvidia_uvm' or
            report_config.get('options') != [STAGED_UVM_OPTION]):
        raise ValueError('staging report configuration hash or option differs')

    manifest_modules = manifest.get('modules', {})
    report_modules = report.get('modules', {})
    if (set(manifest_modules) != set(REQUIRED_ROLES) or
            set(report_modules) != set(REQUIRED_ROLES) or
            set(modules) != set(REQUIRED_ROLES)):
        raise ValueError('staged stack requires the exact four standard module roles')
    filenames = {
        'open': 'hybrid580_open.ko',
        'legacy': 'hybrid580_legacy.ko',
        'frontend': 'nvidia.ko',
        'uvm': 'nvidia-uvm.ko',
    }
    for role, expected_name in STAGED_STANDARD_MODULE_NAMES.items():
        rel = f'lib/modules/{release}/updates/{filenames[role]}'
        path = safe_stage_file(rel, role + ' module')
        candidate = manifest_modules[role]
        staged = report_modules[role]
        observed = modules[role]
        if (candidate.get('module_name') != expected_name or
                candidate.get('filename') != filenames[role] or
                staged.get('relative_path') != rel or
                candidate.get('sha256') != staged.get('sha256') or
                candidate.get('bytes') != staged.get('bytes')):
            raise ValueError('staged manifest and report disagree for ' + role)
        if (observed.get('name') != expected_name or
                observed.get('sha256') != candidate.get('sha256') or
                observed.get('bytes') != candidate.get('bytes')):
            label = 'UVM module hash' if role == 'uvm' else role + ' module hash'
            raise ValueError(label + ' differs from staged manifest')
        try:
            observed_path = Path(observed['path']).resolve(strict=True)
            observed_path.relative_to(stage_root)
        except (KeyError, OSError, ValueError):
            raise ValueError(role + ' module path is outside the validated staged stack') from None
        if observed_path != path:
            raise ValueError(role + ' module path is outside the validated staged stack')
        module_raw = _read_stable_regular_file(path, role + ' staged module')
        if (hashlib.sha256(module_raw).hexdigest() != candidate.get('sha256') or
                len(module_raw) != candidate.get('bytes')):
            raise ValueError(role + ' module bytes differ from staged manifest')

    if (report_config.get('bound_module_sha256') != manifest_modules['uvm'].get('sha256') or
            runtime.get('candidate_module', {}).get('sha256') != manifest_modules['uvm'].get('sha256')):
        raise ValueError('isolated UVM option is not paired with the exact staged UVM module hash')

    reported_tree = report.get('module_tree_files')
    actual_tree = _staged_module_tree_records(stage_root, release)
    if not isinstance(reported_tree, list):
        raise ValueError('staging report module-tree records are invalid')
    for record in reported_tree:
        if (not isinstance(record, dict) or
                set(record) != {'relative_path', 'bytes', 'sha256'} or
                not isinstance(record.get('relative_path'), str) or
                type(record.get('bytes')) is not int or record['bytes'] < 0 or
                not isinstance(record.get('sha256'), str) or
                not re.fullmatch(r'[0-9a-f]{64}', record['sha256'])):
            raise ValueError('staging report contains an invalid module-tree record')
    if sorted(reported_tree, key=lambda record: record['relative_path']) != actual_tree:
        raise ValueError('staged module-tree bytes differ from staging report')
    observed_order = _independent_staged_modprobe_dry_run(stage_root, config_path, release)
    # Re-hash after kmod has inspected the tree so a concurrent replacement cannot
    # silently turn the independently checked dry-run into unrelated evidence.
    if _staged_module_tree_records(stage_root, release) != actual_tree:
        raise ValueError('staged module tree changed during independent dry-run')
    repeated_config_path = safe_stage_file(config_rel, 'staged modprobe configuration')
    if (repeated_config_path != config_path or
            _read_stable_regular_file(repeated_config_path,
                                      'staged modprobe configuration') != config_raw):
        raise ValueError('staged modprobe configuration changed during independent dry-run')
    dry_run = report.get('dry_run', {})
    if (not isinstance(dry_run, dict) or dry_run.get('exit_code') != 0 or
            dry_run.get('stderr_empty') is not True or
            dry_run.get('module_load_attempted') is not False or
            dry_run.get('insert_order') != observed_order or observed_order != expected_order):
        raise ValueError('staging report dry-run differs from independent read-only resolution')
    return {
        'qualification': 'staged-manifest-config-tree-and-dry-run-independently-verified',
        'path': str(stage_root),
        'staging_report_sha256': hashlib.sha256(report_raw).hexdigest(),
        'candidate_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
        'configuration': {
            'relative_path': config_rel,
            'sha256': config_hash,
            'module': 'nvidia_uvm',
            'options': [STAGED_UVM_OPTION],
            'bound_module_sha256': manifest_modules['uvm']['sha256'],
        },
        'dry_run': {
            'insert_order': observed_order,
            'independently_reexecuted': True,
            'module_load_attempted': False,
        },
        'module_count': len(manifest_modules),
        'activation_performed': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-state', required=True, type=Path,
                        help='read-only host snapshot JSON')
    parser.add_argument('--open', required=True, type=Path, dest='open_module')
    parser.add_argument('--legacy', required=True, type=Path)
    parser.add_argument('--frontend', required=True, type=Path)
    parser.add_argument('--uvm', required=True, type=Path)
    parser.add_argument('--uvm-module-name', default=ROLE_NAMES['uvm'],
                        help='expected module identity; use only for an audited private UVM owner')
    parser.add_argument('--frontend-module-name',
                        choices=sorted(SUPPORTED_FRONTEND_MODULE_NAMES),
                        default=ROLE_NAMES['frontend'],
                        help='exact frontend identity; nvidia selects the standard NVIDIA module name')
    parser.add_argument('--uvm-chardev-name', default='nvidia-uvm',
                        help='expected alloc_chrdev_region label used for UVM discovery')
    parser.add_argument('--staged-stack', type=Path,
                        help='verify the standard R580 staging manifest/config/module hash pair')
    parser.add_argument('--candidate-bundle-audit', type=Path,
                        help='static audit report for a hash-pinned mixed-branch four-module bundle')
    parser.add_argument('--candidate-bundle-audit-sha256',
                        help='required SHA-256 pin for --candidate-bundle-audit')
    parser.add_argument('--candidate-depmod-report', type=Path,
                        help='isolated depmod/modprobe --show-depends report for that bundle')
    parser.add_argument('--candidate-depmod-report-sha256',
                        help='required SHA-256 pin for --candidate-depmod-report')
    parser.add_argument('--node-header', required=True, type=Path)
    parser.add_argument('--frontend-source', required=True, type=Path)
    parser.add_argument('--output', type=Path,
                        help='create a new mode-0600 JSON report; never overwrite')
    args = parser.parse_args(argv)
    try:
        host_raw = _read_stable_regular_file(args.host_state, 'host-state snapshot')
        host = _parse_json_bytes(host_raw)
        header_raw = _read_stable_regular_file(args.node_header, 'node header')
        source_raw = _read_stable_regular_file(args.frontend_source, 'frontend source')
        module_paths = {'open': args.open_module, 'legacy': args.legacy,
                        'frontend': args.frontend, 'uvm': args.uvm}
        modules = {role: _module_metadata(role, path)
                   for role, path in module_paths.items()}
        standard_names = (args.frontend_module_name == 'nvidia' and
                          args.uvm_module_name == 'nvidia_uvm')
        bundle_inputs = (args.candidate_bundle_audit,
                         args.candidate_bundle_audit_sha256,
                         args.candidate_depmod_report,
                         args.candidate_depmod_report_sha256)
        has_bundle_inputs = any(item is not None for item in bundle_inputs)
        if has_bundle_inputs and any(item is None for item in bundle_inputs):
            raise ValueError('candidate bundle audit and depmod report each require an exact SHA-256 pin')
        if standard_names and args.staged_stack is None and not has_bundle_inputs:
            raise ValueError('standard-name preflight requires --staged-stack or a pinned candidate bundle audit and depmod report')
        if args.staged_stack is not None and has_bundle_inputs:
            raise ValueError('choose either --staged-stack or the pinned candidate bundle evidence')
        if has_bundle_inputs and not standard_names:
            raise ValueError('candidate bundle evidence is valid only for the standard nvidia/nvidia_uvm names')
        staged_stack = None
        if args.staged_stack is not None:
            if not standard_names:
                raise ValueError('--staged-stack is valid only for the standard nvidia/nvidia_uvm pair')
            staged_stack = validate_staged_stack(args.staged_stack, modules)
        candidate_bundle = None
        audited_candidate_versions = None
        if has_bundle_inputs:
            candidate_bundle = validate_candidate_bundle_evidence(
                audit_report_path=args.candidate_bundle_audit,
                expected_audit_sha256=args.candidate_bundle_audit_sha256,
                depmod_report_path=args.candidate_depmod_report,
                expected_depmod_sha256=args.candidate_depmod_report_sha256,
                modules=modules,
                kernel_release=host.get('kernel_release', ''),
            )
            audited_candidate_versions = {
                role: candidate_bundle['versions'][role]
                for role in ('open', 'legacy', 'uvm')
            }
        layout = _parse_standard_node_layout(
            header_raw.decode('utf-8'), source_raw.decode('utf-8'))
        result = evaluate_preflight(
            host, modules, layout,
            expected_frontend_module_name=args.frontend_module_name,
            expected_uvm_module_name=args.uvm_module_name,
            expected_uvm_chardev_name=args.uvm_chardev_name,
            audited_candidate_versions=audited_candidate_versions)
        result['candidate_modules'] = modules
        result['evidence_refs'] = host.get('evidence_refs', [])
        result['preflight_inputs'] = {
            'expected_frontend_module_name': args.frontend_module_name,
            'expected_uvm_module_name': args.uvm_module_name,
            'expected_uvm_chardev_name': args.uvm_chardev_name,
            'host_state': {
                'path': str(args.host_state.resolve()),
                'sha256': hashlib.sha256(host_raw).hexdigest(),
                'bytes': len(host_raw),
            },
            'node_header': {
                'path': str(args.node_header.resolve()),
                'sha256': hashlib.sha256(header_raw).hexdigest(),
                'bytes': len(header_raw),
            },
            'frontend_source': {
                'path': str(args.frontend_source.resolve()),
                'sha256': hashlib.sha256(source_raw).hexdigest(),
                'bytes': len(source_raw),
            },
            'tool': {
                'path': str(Path(__file__).resolve()),
                'sha256': hashlib.sha256(_read_stable_regular_file(
                    __file__, 'preflight tool')).hexdigest(),
            },
        }
        if staged_stack is not None:
            result['staged_stack_validation'] = staged_stack
            result['preflight_inputs']['staged_stack'] = {
                'path': staged_stack['path'],
                'staging_report_sha256': staged_stack['staging_report_sha256'],
                'candidate_manifest_sha256': staged_stack['candidate_manifest_sha256'],
            }
        if candidate_bundle is not None:
            result['candidate_bundle_validation'] = candidate_bundle
            result['preflight_inputs']['candidate_bundle_audit'] = candidate_bundle['audit_report']
            result['preflight_inputs']['candidate_depmod_report'] = candidate_bundle['depmod_report']
        payload = json.dumps(result, sort_keys=True, indent=2) + '\n'
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(payload)
        else:
            sys.stdout.write(payload)
        return 0 if result['status'] == 'static-preflight-clear' else 1
    except (OSError, ValueError, json.JSONDecodeError) as error:
        sys.stderr.write('canary preflight failed: ' + str(error) + '\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
