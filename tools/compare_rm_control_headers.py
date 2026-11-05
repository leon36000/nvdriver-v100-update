#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare fixed NVOS54 headers from archived installed-driver references only.

The observer never reads RM_CONTROL parameter pointers. This utility deliberately
reports command IDs, declared sizes, transport returns, and embedded statuses;
it cannot establish command semantics or backend compatibility.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


RTX_SCHEMA = 'nvidia-hybrid-remote-selected-gpu-transport-v1'
V100_SCHEMA = 'nvidia-hybrid-pc3-v100-reference-transport-v1'
OBSERVER_SCHEMA = 'nvidia-hybrid-rm-ioctl-observer-v6'
OBSERVER_SCHEMA_V23 = 'nvidia-hybrid-rm-ioctl-observer-v23'
RM_CONTROL_IOCTL = 0xC020462A
HEADER_KEYS = {
    'command', 'flags', 'hClient', 'hObject', 'params_size', 'status',
    'client_object_equal', 'object_matches_prior_root_allocation',
    'client_matches_prior_root_allocation',
}
ROW_KEYS = {'operation', 'request', 'packet_size', 'syscall_return', 'fd', 'tid', 'entry', 'exit'}
HEADER_STABLE_FIELDS = ('command', 'flags', 'hClient', 'hObject', 'params_size')
V23_HEADER_KEYS = {
    'command', 'flags', 'params_size', 'status', 'hClientPresent', 'hObjectPresent',
    'client_object_equal', 'client_matches_prior_root_allocation',
    'object_matches_prior_root_allocation',
}
V23_ROW_KEYS = {'operation', 'request', 'packet_size', 'syscall_return', 'fd', 'tid',
                'fd_role', 'entry', 'exit'}


def _observer_from_transport(role: str, source: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(source, dict):
        raise ValueError('transport report must be a JSON object')
    remote = source.get('remote')
    if not isinstance(remote, dict):
        raise ValueError('transport report is missing remote result')

    if (source.get('rm_control_headers_capture_requested') is True or
            remote.get('rm_control_headers_capture_requested') is True):
        if (source.get('rm_control_headers_capture_requested') is not True or
                remote.get('rm_control_headers_capture_requested') is not True or
                source.get('rm_control_headers_records_seen') not in (None, True) or
                remote.get('rm_control_headers_records_seen') is not True):
            raise ValueError('redacted RM_CONTROL header capture was not verified at both runner layers')
        if role == 'rtx5080':
            phase = remote.get('phase_report')
            acceptance = remote.get('hardware_acceptance')
            cleanup = remote.get('remote_work_cleanup')
            if (source.get('schema') != RTX_SCHEMA or source.get('phase') != 'enumerate' or
                    source.get('exit_code') != 0 or remote.get('phase') != 'enumerate' or
                    remote.get('qualification') != 'rtx5080-cuda-phase-report-contract-valid' or
                    remote.get('exit_code') != 0 or not isinstance(cleanup, dict) or
                    cleanup.get('passed') is not True or cleanup.get('removed') is not True or
                    not isinstance(acceptance, dict) or
                    acceptance.get('schema') != 'nvidia-hybrid-hardware-acceptance-v2' or
                    acceptance.get('qualification') != 'phase-report-contract-pass' or
                    acceptance.get('exit_code') != 0 or
                    acceptance.get('validation_errors') != []):
                raise ValueError('RTX input is not a successful installed-driver enumeration reference')
            observation_wrapper = acceptance.get('ioctl_observation')
            if not isinstance(observation_wrapper, dict):
                raise ValueError('RTX reference is missing the observer result')
            observation = observation_wrapper.get('report')
        elif role == 'v100':
            phase = remote.get('probe')
            if (source.get('schema') != V100_SCHEMA or source.get('phase') != 'enumerate' or
                    source.get('qualification') != 'v100-cuda-phase-report-contract-valid' or
                    source.get('exit_code') != 0 or remote.get('phase') != 'enumerate' or
                    remote.get('qualification') != 'v100-cuda-phase-report-contract-valid' or
                    remote.get('exit_code') not in (None, 0) or
                    remote.get('probe_exit_code') != 0 or
                    remote.get('observer_exit_code') != 0 or
                    remote.get('guest_cleanup_passed') is not True or
                    remote.get('payload_file_cleanup_passed') is not True):
                raise ValueError('V100 input is not a successful installed-driver enumeration reference')
            observation = remote.get('ioctl_observation')
        else:
            raise ValueError('role must be rtx5080 or v100')

        selected = phase.get('selected_device') if isinstance(phase, dict) else None
        expected_sm = 120 if role == 'rtx5080' else 70
        required_operations = {
            'cuInit', 'cuDriverGetVersion', 'cuDeviceGetCount', 'cuDeviceGet',
            'cuDeviceGetName', 'cuDeviceGetPCIBusId',
            'cuDeviceGetAttribute.major', 'cuDeviceGetAttribute.minor',
        }
        completed_operations = phase.get('completed_operations') if isinstance(phase, dict) else None
        if (not isinstance(phase, dict) or phase.get('schema') != 'nvidia-cuda-driver-phase-v1' or
                phase.get('status') != 'phase-passed' or phase.get('phase') != 'enumerate' or
                type(phase.get('driver_api')) is not int or phase['driver_api'] <= 0 or
                phase.get('cleanup_passed') is not True or phase.get('cleanup_errors') != [] or
                phase.get('error') != '' or not isinstance(completed_operations, list) or
                not required_operations.issubset(completed_operations) or
                any(op in completed_operations for op in ('cuCtxCreate_v2', 'cuLaunchKernel(hybrid_arch)')) or
                not isinstance(selected, dict) or selected.get('sm') != expected_sm or
                not isinstance(selected.get('name'), str) or
                not isinstance(selected.get('pci_bus_id'), str) or
                not isinstance(selected.get('compute_capability'), str)):
            raise ValueError(f'{role}: CUDA enumeration did not select the expected SM70/SM120 GPU generation')
        if (not isinstance(observation, dict) or observation.get('schema') != OBSERVER_SCHEMA_V23 or
                observation.get('trace_complete') is not True or observation.get('errors') != [] or
                observation.get('control_path') != '/dev/nvidiactl' or
                observation.get('architecture') != 'x86_64' or
                observation.get('pointer_bits') != 64 or
                observation.get('child_exit_code') != 0 or
                observation.get('nested_pointers_read') is not False or
                observation.get('fd_identity_tracking') is not False or
                observation.get('payload_scope') !=
                    'fixed NVOS54 RM_CONTROL headers only; handles redacted; nested parameter payloads omitted'):
            raise ValueError('typed v23 observer report is incomplete or outside the redacted header scope')
        records = observation.get('records')
        expected_count = remote.get('rm_control_headers_record_count')
        if (not isinstance(records, list) or not records or
                type(expected_count) is not int or len(records) != expected_count):
            raise ValueError('v23 observer record count differs from the runner summary')
        return observation

    if source.get('rm_control_capture_requested') is not True or \
            remote.get('rm_control_capture_requested') is not True:
        raise ValueError('RM_CONTROL capture was not requested at both runner layers')
    if remote.get('rm_control_records_seen') is not True:
        raise ValueError('runner did not verify RM_CONTROL records')

    if role == 'rtx5080':
        if (source.get('schema') != RTX_SCHEMA or
                remote.get('qualification') != 'rtx5080-report-contract-valid-hybrid-incomplete'):
            raise ValueError('RTX input is not a validated installed-driver reference')
        acceptance = remote.get('hardware_acceptance')
        if (not isinstance(acceptance, dict) or
                acceptance.get('qualification') != 'incomplete-hardware-missing' or
                acceptance.get('exit_code') != 77 or acceptance.get('validation_errors') != []):
            raise ValueError('RTX reference did not pass its selected-device acceptance')
        probe = acceptance.get('probe')
        capture = acceptance.get('ioctl_observation')
        if (not isinstance(probe, dict) or probe.get('missing_sm') != [70] or
                probe.get('hybrid_validated') is not False or not isinstance(capture, dict)):
            raise ValueError('RTX record does not establish the expected single-generation scope')
        observation = capture.get('report')
    elif role == 'v100':
        if (source.get('schema') != V100_SCHEMA or
                source.get('qualification') != 'v100-reference-report-contract-valid' or
                remote.get('qualification') != 'v100-reference-report-contract-valid' or
                source.get('exit_code') != 0 or remote.get('probe_exit_code') != 0 or
                remote.get('observer_exit_code') != 0 or
                remote.get('guest_cleanup_passed') is not True or
                remote.get('payload_file_cleanup_passed') is not True):
            raise ValueError('V100 input is not a successful installed-driver reference')
        observation = remote.get('ioctl_observation')
    else:
        raise ValueError('role must be rtx5080 or v100')

    if (not isinstance(observation, dict) or observation.get('schema') != OBSERVER_SCHEMA or
            observation.get('trace_complete') is not True or observation.get('errors') != [] or
            observation.get('control_path') != '/dev/nvidiactl' or
            observation.get('pointer_bits') != 64 or
            'RM_CONTROL headers' not in observation.get('payload_scope', '') or
            'other nested parameters omitted' not in observation.get('payload_scope', '') or
            'addresses omitted' not in observation.get('nested_pointer_scope', '')):
        raise ValueError('typed observer report is incomplete or outside the fixed-header scope')
    return observation


def _u32(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def _validate_row(row: Any, index: int, observer_schema: str) -> dict[str, Any]:
    prefix = f'RM_CONTROL record {index}'
    if observer_schema == OBSERVER_SCHEMA_V23:
        if not isinstance(row, dict) or set(row) != V23_ROW_KEYS:
            raise ValueError(prefix + ': unexpected pointer-bearing field or row schema')
        if (row.get('operation') != 'rm_control_header' or
                row.get('request') != RM_CONTROL_IOCTL or row.get('packet_size') != 32 or
                type(row.get('syscall_return')) is not int or
                not -(1 << 31) <= row['syscall_return'] < (1 << 31) or
                type(row.get('fd')) is not int or row['fd'] < 0 or
                type(row.get('tid')) is not int or row['tid'] <= 0 or
                row.get('fd_role') != 'control'):
            raise ValueError(prefix + ': invalid redacted RM_CONTROL ioctl envelope')
        for phase in ('entry', 'exit'):
            header = row.get(phase)
            if not isinstance(header, dict) or set(header) != V23_HEADER_KEYS:
                raise ValueError(prefix + ': fixed header is incomplete or has unexpected fields')
            for name in ('command', 'flags', 'params_size', 'status'):
                if not _u32(header.get(name)):
                    raise ValueError(prefix + ': invalid fixed-header integer')
            for name in ('hClientPresent', 'hObjectPresent', 'client_object_equal',
                         'client_matches_prior_root_allocation',
                         'object_matches_prior_root_allocation'):
                if type(header.get(name)) is not bool:
                    raise ValueError(prefix + ': invalid redacted header boolean')
        return row

    if not isinstance(row, dict) or set(row) != ROW_KEYS:
        raise ValueError(prefix + ': unexpected pointer-bearing field or row schema')
    if (row.get('operation') != 'rm_control_header' or
            row.get('request') != RM_CONTROL_IOCTL or row.get('packet_size') != 32):
        raise ValueError(prefix + ': invalid RM_CONTROL ioctl envelope')
    syscall_return = row.get('syscall_return')
    if type(syscall_return) is not int or not -(1 << 31) <= syscall_return < (1 << 31):
        raise ValueError(prefix + ': invalid syscall return')
    if type(row.get('fd')) is not int or row['fd'] < 0 or type(row.get('tid')) is not int or row['tid'] < 0:
        raise ValueError(prefix + ': invalid local process metadata')
    for phase in ('entry', 'exit'):
        header = row.get(phase)
        if not isinstance(header, dict) or set(header) != HEADER_KEYS:
            raise ValueError(prefix + ': typed fixed header is incomplete or has unexpected fields')
        for name in ('command', 'flags', 'hClient', 'hObject', 'status'):
            if not _u32(header.get(name)):
                raise ValueError(prefix + ': invalid fixed-header integer')
        size = header.get('params_size')
        if type(size) is not int or not 0 <= size <= 16 * 1024 * 1024:
            raise ValueError(prefix + ': invalid parameter size')
        for name in ('client_object_equal', 'object_matches_prior_root_allocation',
                     'client_matches_prior_root_allocation'):
            if type(header.get(name)) is not bool:
                raise ValueError(prefix + ': invalid observer correlation metadata')
    return row


def summarize_transport(role: str, source: dict[str, Any]) -> dict[str, Any]:
    observation = _observer_from_transport(role, source)
    observer_schema = observation.get('schema')
    records = observation.get('records')
    if not isinstance(records, list):
        raise ValueError('observer record list is missing')
    if observer_schema == OBSERVER_SCHEMA_V23 and any(
            not isinstance(row, dict) or row.get('operation') != 'rm_control_header'
            for row in records):
        raise ValueError('v23 fixed-header observer returned an unexpected non-header record')
    rows = [_validate_row(row, index, observer_schema) for index, row in enumerate(records)
            if observer_schema == OBSERVER_SCHEMA_V23 or
            (isinstance(row, dict) and row.get('operation') == 'rm_control_header')]
    if not rows:
        raise ValueError('complete observer trace contains no RM_CONTROL headers')

    groups: dict[tuple[int, int], dict[str, Any]] = {}
    syscall_failures = 0
    header_mutations: Counter[str] = Counter()
    root_matches = 0
    client_object_equal = 0
    header_fields = (('command', 'flags', 'params_size', 'status', 'hClientPresent',
                      'hObjectPresent', 'client_object_equal',
                      'client_matches_prior_root_allocation',
                      'object_matches_prior_root_allocation')
                     if observer_schema == OBSERVER_SCHEMA_V23 else HEADER_STABLE_FIELDS)
    client_present = 0
    object_present = 0
    zero_sized = 0
    for row in rows:
        entry, output = row['entry'], row['exit']
        key = (output['command'], output['params_size'])
        summary = groups.setdefault(key, {
            'calls': 0, 'syscall_failures': 0, 'embedded_statuses': Counter(),
        })
        summary['calls'] += 1
        summary['embedded_statuses'][output['status']] += 1
        if row['syscall_return'] != 0:
            summary['syscall_failures'] += 1
            syscall_failures += 1
        for name in header_fields:
            if entry[name] != output[name]:
                header_mutations[name] += 1
        if observer_schema == OBSERVER_SCHEMA_V23:
            client_present += int(output['hClientPresent'])
            object_present += int(output['hObjectPresent'])
            zero_sized += int(output['params_size'] == 0)
        root_matches += int(output['object_matches_prior_root_allocation'])
        client_object_equal += int(output['client_object_equal'])

    commands = []
    for (command, size), summary in sorted(groups.items()):
        commands.append({
            'command': f'0x{command:08x}',
            'params_size': size,
            'calls': summary['calls'],
            'syscall_failures': summary['syscall_failures'],
            'embedded_statuses': [
                {'status': f'0x{status:08x}', 'count': count}
                for status, count in sorted(summary['embedded_statuses'].items())
            ],
        })
    report_meta = source.get('remote', {})
    if role == 'rtx5080':
        qualification = report_meta['qualification']
    else:
        qualification = source['qualification']
    report = {
        'role': role,
        'report_schema': source.get('schema'),
        'observer_schema': observer_schema,
        'qualification': qualification,
        'observer_record_count': len(records),
        'rm_control_records': len(rows),
        'syscall_failures': syscall_failures,
        'embedded_nonzero_statuses': sum(
            item['count'] for item in commands
            for item in item['embedded_statuses'] if item['status'] != '0x00000000'),
        'header_mutations': dict(sorted(header_mutations.items())),
        'same_root_client_object_correlations': client_object_equal,
        'object_matches_prior_root_allocation_correlations': root_matches,
        'commands': commands,
        'rm_control_nested_parameters_read': False,
        'payload_addresses_recorded': False,
        'report_contract_validated': True,
        'cuda_execution_validated': False,
        'evidence_scope': 'validated JSON and redacted observer report contracts; probe execution provenance is not attested',
    }
    if observer_schema == OBSERVER_SCHEMA_V23:
        if role == 'rtx5080':
            phase = report_meta['phase_report']
            kernel_release = report_meta.get('kernel_release')
        else:
            phase = report_meta['probe']
            kernel_release = report_meta.get('guest', {}).get('kernel_release')
        selected = phase['selected_device']
        library_path = phase.get('driver_library_path', '')
        library_name = Path(library_path).name if isinstance(library_path, str) else ''
        version_match = re.search(r'libcuda\.so\.(\d+(?:\.\d+)+)$', library_name)
        report.update({
            'device': {key: selected[key] for key in
                       ('name', 'pci_bus_id', 'sm', 'compute_capability')},
            'driver': {
                'api': phase['driver_api'],
                'library': library_name,
                'version_from_library_name': version_match.group(1) if version_match else None,
                'kernel_release': kernel_release,
            },
            'params_size_zero_records': zero_sized,
            'client_handle_present_records': client_present,
            'object_handle_present_records': object_present,
        })
    return report


def compare_observations(rtx: tuple[str, dict[str, Any]],
                         v100: tuple[str, dict[str, Any]]) -> dict[str, Any]:
    summaries = [summarize_transport(*rtx), summarize_transport(*v100)]
    by_role = {summary['role']: summary for summary in summaries}
    if set(by_role) != {'rtx5080', 'v100'}:
        raise ValueError('one rtx5080 and one v100 observation are required')
    if by_role['rtx5080']['observer_schema'] != by_role['v100']['observer_schema']:
        raise ValueError('both inputs must use the same observer schema family')
    observer_schema = by_role['rtx5080']['observer_schema']
    is_redacted_v23 = observer_schema == OBSERVER_SCHEMA_V23
    if is_redacted_v23:
        for role, source in (rtx, v100):
            artifact_map = (source.get('local_artifacts') if role == 'rtx5080'
                            else source)
            if not isinstance(artifact_map, dict):
                raise ValueError(f'{role}: local probe and CUDA fatbin identities are missing')
            identities = {}
            for name, output_key in (('probe', 'probe_sha256'),
                                     ('module', 'cuda_fatbin_sha256')):
                artifact = artifact_map.get(name)
                if (not isinstance(artifact, dict) or
                        type(artifact.get('bytes')) is not int or artifact['bytes'] <= 0 or
                        not isinstance(artifact.get('sha256'), str) or
                        re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']) is None):
                    raise ValueError(f'{role}: {name} artifact identity is malformed or missing')
                identities[output_key] = {
                    'bytes': artifact['bytes'], 'sha256': artifact['sha256']}
            by_role[role].update({key: value['sha256'] for key, value in identities.items()})
            by_role[role]['probe_bytes'] = identities['probe_sha256']['bytes']
            by_role[role]['cuda_fatbin_bytes'] = identities['cuda_fatbin_sha256']['bytes']
        for digest_key, byte_key, label in (
                ('probe_sha256', 'probe_bytes', 'CUDA probe binary'),
                ('cuda_fatbin_sha256', 'cuda_fatbin_bytes', 'CUDA fatbin')):
            if (by_role['rtx5080'][digest_key] != by_role['v100'][digest_key] or
                    by_role['rtx5080'][byte_key] != by_role['v100'][byte_key]):
                raise ValueError(f'paired enumeration captures must use the same {label}')
    distributions: dict[str, dict[int, Counter[int]]] = {}
    status_distributions: dict[str, dict[int, dict[int, Counter[int]]]] = {}
    for role, summary in by_role.items():
        current: dict[int, Counter[int]] = {}
        statuses: dict[int, dict[int, Counter[int]]] = {}
        for item in summary['commands']:
            command = int(item['command'], 16)
            size = item['params_size']
            current.setdefault(command, Counter())[size] += item['calls']
            distribution = statuses.setdefault(command, {}).setdefault(size, Counter())
            for status in item['embedded_statuses']:
                distribution[int(status['status'], 16)] += status['count']
        distributions[role] = current
        status_distributions[role] = statuses

    rtx_ids, v100_ids = set(distributions['rtx5080']), set(distributions['v100'])
    common = rtx_ids & v100_ids
    size_drift = []
    call_count_drift = []
    status_drift = []
    for command in sorted(common):
        left = distributions['rtx5080'][command]
        right = distributions['v100'][command]
        if set(left) != set(right):
            size_drift.append({
                'command': f'0x{command:08x}',
                'rtx5080': [{'bytes': size, 'count': count} for size, count in sorted(left.items())],
                'v100': [{'bytes': size, 'count': count} for size, count in sorted(right.items())],
            })
        elif left != right:
            call_count_drift.append({
                'command': f'0x{command:08x}',
                'params_size': sorted(left),
                'rtx5080_calls': sum(left.values()),
                'v100_calls': sum(right.values()),
            })
        for size in sorted(set(left) & set(right)):
            rtx_statuses = status_distributions['rtx5080'][command][size]
            v100_statuses = status_distributions['v100'][command][size]
            if set(rtx_statuses) != set(v100_statuses):
                status_drift.append({
                    'command': f'0x{command:08x}',
                    'params_size': size,
                    'rtx5080_status_codes': [f'0x{status:08x}'
                                             for status in sorted(rtx_statuses)],
                    'v100_status_codes': [f'0x{status:08x}'
                                          for status in sorted(v100_statuses)],
                })
    schema = ('nvidia-hybrid-rm-control-header-comparison-v3'
              if is_redacted_v23 else 'nvidia-hybrid-rm-control-header-comparison-v1')
    scope = (
        'Fixed NVOS54 command/flags/size/status headers with handle-presence and relational '
        'booleans only; raw handles and nested parameter bytes omitted; two separate installed-driver references.'
        if is_redacted_v23 else
        'Fixed NVOS54 command/flags/handle/size/status headers from two separate installed-driver references; '
        'no nested RM parameter bytes.'
    )
    comparison = {
        'observer_schema': observer_schema,
        'common_command_ids': len(common),
        'rtx5080_only_command_ids': [f'0x{x:08x}' for x in sorted(rtx_ids - v100_ids)],
        'v100_only_command_ids': [f'0x{x:08x}' for x in sorted(v100_ids - rtx_ids)],
        'shared_command_size_drift': size_drift,
        'shared_command_call_count_drift': call_count_drift,
        'shared_command_status_code_drift': status_drift,
        'rm_control_payloads_read': False,
        'payload_addresses_recorded': False,
        'hybrid_runtime_validated': False,
        'scope': scope,
    }
    if is_redacted_v23:
        comparison.update(same_probe_binary=True, same_cuda_fatbin=True)
    return {
        'schema': schema,
        'reports': [by_role['rtx5080'], by_role['v100']],
        'comparison': comparison,
        'not_proven': [
            'same-Linux or same-process Volta plus Blackwell execution',
            'identity or lifetime of Linux struct file objects',
            'RM command payload layouts beyond the declared byte count',
            'cross-version command compatibility or frontend forwarding safety',
            'CUDA contexts, UVM, P2P, concurrency, stability, or performance',
        ],
    }


def write_private_report(path: Path, report: dict[str, Any]) -> None:
    encoded = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.close(fd)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(fd)


def _load_input(path: Path, role: str) -> tuple[dict[str, Any], str]:
    source_path = path.resolve(strict=True)
    mode = stat.S_IMODE(source_path.stat().st_mode)
    if mode & 0o077:
        raise ValueError(f'{role}: source evidence must not be group/world accessible')
    raw = source_path.read_bytes()
    source = json.loads(raw)
    if not isinstance(source, dict):
        raise ValueError(f'{role}: source report must be a JSON object')
    return source, hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rtx-report', type=Path, required=True)
    parser.add_argument('--v100-report', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('report already exists')
    try:
        rtx, rtx_hash = _load_input(args.rtx_report, 'rtx5080')
        v100, v100_hash = _load_input(args.v100_report, 'v100')
        result = compare_observations(('rtx5080', rtx), ('v100', v100))
        for summary, source_path, digest in zip(result['reports'],
                (args.rtx_report, args.v100_report), (rtx_hash, v100_hash)):
            summary['source_report'] = {'name': source_path.name, 'sha256': digest}
        result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        write_private_report(args.report, result)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({
        'report': str(args.report),
        'schema': result['schema'],
        'rtx5080_rm_control_records': result['reports'][0]['rm_control_records'],
        'v100_rm_control_records': result['reports'][1]['rm_control_records'],
        'shared_command_size_drift': len(result['comparison']['shared_command_size_drift']),
        'shared_command_status_code_drift': len(
            result['comparison']['shared_command_status_code_drift']),
        'hybrid_runtime_validated': False,
    }))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
