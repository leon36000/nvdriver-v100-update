#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize fixed NVOS64 RM_ALLOC headers without exposing handles or pointers."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_rm_control_headers import (  # noqa: E402
    _observer_from_transport,
    write_private_report,
)


RM_ALLOC_IOCTL = 0xC030462B
ROW_KEYS = {'operation', 'request', 'packet_size', 'syscall_return', 'fd', 'tid', 'entry', 'exit'}
ALLOC_HEADER_KEYS = {
    'layout', 'hRoot', 'hObjectParent', 'hObjectNew', 'hClass', 'root_class',
    'pAllocParms', 'paramsSize', 'pRightsRequested', 'flags', 'status',
}
U32_KEYS = {
    'hRoot', 'hObjectParent', 'hObjectNew', 'hClass', 'paramsSize',
    'pRightsRequested', 'flags', 'status',
}


def _load_input(path: Path, role: str) -> tuple[dict[str, Any], str]:
    source_path = path.resolve(strict=True)
    if stat.S_IMODE(source_path.stat().st_mode) & 0o077:
        raise ValueError(f'{role}: source evidence must not be group/world accessible')
    raw = source_path.read_bytes()
    source = json.loads(raw)
    if not isinstance(source, dict):
        raise ValueError(f'{role}: source report must be a JSON object')
    return source, hashlib.sha256(raw).hexdigest()


def _observer_for_role(role: str, source: dict[str, Any]) -> dict[str, Any]:
    if role == 'rtx5080':
        return _observer_from_transport(role, source)
    if role == 'v100':
        return _observer_from_transport(role, source)
    raise ValueError('role must be rtx5080 or v100')


def _validate_alloc_row(row: Any, index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    prefix = f'RM_ALLOC record {index}'
    if not isinstance(row, dict) or set(row) != ROW_KEYS:
        raise ValueError(prefix + ': unexpected row schema')
    if (row.get('operation') != 'alloc' or row.get('request') != RM_ALLOC_IOCTL or
            row.get('packet_size') != 48):
        raise ValueError(prefix + ': expected NVOS64 RM_ALLOC with a 48-byte envelope')
    if type(row.get('syscall_return')) is not int or type(row.get('fd')) is not int or \
            type(row.get('tid')) is not int or row['fd'] < 0 or row['tid'] < 0:
        raise ValueError(prefix + ': invalid syscall metadata')
    entry, output = row.get('entry'), row.get('exit')
    if not isinstance(entry, dict) or not isinstance(output, dict) or \
            set(entry) != ALLOC_HEADER_KEYS or set(output) != ALLOC_HEADER_KEYS:
        raise ValueError(prefix + ': fixed allocation header schema is incomplete')
    for header in (entry, output):
        if header.get('layout') != 'NVOS64' or type(header.get('root_class')) is not bool:
            raise ValueError(prefix + ': invalid packet layout metadata')
        for key in U32_KEYS:
            value = header.get(key)
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(prefix + f': invalid {key}')
        pointer = header.get('pAllocParms')
        if type(pointer) is not int or not 0 <= pointer < (1 << 64):
            raise ValueError(prefix + ': invalid pointer metadata')
    for key in ('layout', 'hRoot', 'hObjectParent', 'pAllocParms', 'paramsSize',
                'pRightsRequested', 'flags', 'root_class'):
        if entry[key] != output[key]:
            raise ValueError(prefix + f': fixed {key} mutated across RM_ALLOC')
    return entry, output


def summarize_allocations(role: str, source: dict[str, Any]) -> dict[str, Any]:
    observer = _observer_for_role(role, source)
    records = observer.get('records')
    if not isinstance(records, list):
        raise ValueError('observer record list is missing')

    classes: dict[int, dict[str, Any]] = {}
    edges: Counter[tuple[int | None, int]] = Counter()
    objects: dict[tuple[int, int], int] = {}
    syscall_failures = 0
    alloc_count = 0
    unknown_parent_count = 0
    for index, row in enumerate(records):
        if not isinstance(row, dict) or row.get('operation') != 'alloc':
            continue
        entry, output = _validate_alloc_row(row, index)
        alloc_count += 1
        requested_class = entry['hClass']
        current = classes.setdefault(requested_class, {
            'alloc_records': 0,
            'parameter_size_counts': Counter(),
            'null_alloc_parameter_pointer_count': 0,
            'non_null_alloc_parameter_pointer_count': 0,
            'syscall_failures': 0,
            'embedded_statuses': Counter(),
            'root_class_record_count': 0,
        })
        current['alloc_records'] += 1
        current['parameter_size_counts'][entry['paramsSize']] += 1
        if entry['pAllocParms'] == 0:
            current['null_alloc_parameter_pointer_count'] += 1
        else:
            current['non_null_alloc_parameter_pointer_count'] += 1
        status = output['status']
        current['embedded_statuses'][status] += 1
        current['root_class_record_count'] += int(entry['root_class'])
        if row['syscall_return'] != 0:
            current['syscall_failures'] += 1
            syscall_failures += 1
            continue
        if status != 0 or output['hObjectNew'] == 0:
            continue

        if entry['root_class']:
            client_handle = output['hObjectNew']
            parent_class: int | None = None
            object_key = (client_handle, client_handle)
        else:
            root = entry['hRoot']
            parent = entry['hObjectParent']
            parent_class = objects.get((root, parent)) if parent != 0 else None
            if parent != 0 and parent_class is None:
                unknown_parent_count += 1
            if parent != 0:
                edges[(parent_class, requested_class)] += 1
            object_key = (root, output['hObjectNew'])

        # Root-client allocations report class 0 at entry and class 65 at exit.
        # For a child object, the class reported by the RM is its effective class.
        effective_class = output['hClass']
        previous = objects.get(object_key)
        if previous is None:
            objects[object_key] = effective_class
        elif previous != effective_class:
            raise ValueError(prefix + ': successful object handle reused with a different class')

    if alloc_count == 0:
        raise ValueError('complete observer trace contains no RM_ALLOC records')

    class_rows = []
    for class_id, item in sorted(classes.items()):
        class_rows.append({
            'class_id': f'0x{class_id:08x}',
            'alloc_records': item['alloc_records'],
            'parameter_size_counts': [
                {'bytes': size, 'count': count}
                for size, count in sorted(item['parameter_size_counts'].items())
            ],
            'null_alloc_parameter_pointer_count': item['null_alloc_parameter_pointer_count'],
            'non_null_alloc_parameter_pointer_count': item['non_null_alloc_parameter_pointer_count'],
            'syscall_failures': item['syscall_failures'],
            'embedded_statuses': [
                {'status': f'0x{status:08x}', 'count': count}
                for status, count in sorted(item['embedded_statuses'].items())
            ],
            'root_class_record_count': item['root_class_record_count'],
        })
    edge_rows = [
        {'parent_class': 'unknown' if parent is None else f'0x{parent:08x}',
         'child_class': f'0x{child:08x}', 'count': count}
        for (parent, child), count in sorted(
            edges.items(), key=lambda item: (-1 if item[0][0] is None else item[0][0], item[0][1]))
    ]
    return {
        'role': role,
        'qualification': ('rtx5080-report-contract-valid-hybrid-incomplete'
                          if role == 'rtx5080' else 'v100-reference-report-contract-valid'),
        'observer_record_count': len(records),
        'alloc_records': alloc_count,
        'syscall_failures': syscall_failures,
        'unknown_parent_class_count': unknown_parent_count,
        'classes': class_rows,
        'parent_class_edges': edge_rows,
        'fixed_nvOS64_alloc_headers_only': True,
        'nested_alloc_parameters_read': False,
        'alloc_parameter_pointer_addresses_recorded': False,
        'object_handles_recorded': False,
    }


def compare_allocations(rtx: dict[str, Any], v100: dict[str, Any]) -> dict[str, Any]:
    rtx_ids = {row['class_id'] for row in rtx['classes']}
    v100_ids = {row['class_id'] for row in v100['classes']}
    return {
        'common_class_ids': sorted(rtx_ids & v100_ids),
        'rtx5080_only_class_ids': sorted(rtx_ids - v100_ids),
        'v100_only_class_ids': sorted(v100_ids - rtx_ids),
        'rtx5080_alloc_records': rtx['alloc_records'],
        'v100_alloc_records': v100['alloc_records'],
        'allocation_payloads_read': False,
        'object_handles_compared': False,
    }


def build_report(rtx_path: Path, v100_path: Path) -> dict[str, Any]:
    rtx_source, rtx_hash = _load_input(rtx_path, 'rtx5080')
    v100_source, v100_hash = _load_input(v100_path, 'v100')
    rtx = summarize_allocations('rtx5080', rtx_source)
    v100 = summarize_allocations('v100', v100_source)
    return {
        'schema': 'nvidia-hybrid-rm-alloc-header-summary-v1',
        'sources': [
            {'role': 'rtx5080', 'name': rtx_path.name, 'sha256': rtx_hash},
            {'role': 'v100', 'name': v100_path.name, 'sha256': v100_hash},
        ],
        'reports': [rtx, v100],
        'comparison': compare_allocations(rtx, v100),
        'scope': {
            'classification': 'hardware-observed fixed NVOS64 RM_ALLOC headers',
            'same_linux_hybrid_validated': False,
            'experimental_module_loaded': False,
        },
        'not_proven': [
            'class-specific allocation parameter semantics',
            'same-Linux execution or CUDA object creation through experimental backends',
            'arbitrary RM_ALLOC/RM_CONTROL forwarding safety',
            'VFS file identity, UVM, P2P, concurrency, or performance',
        ],
        'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rtx-report', type=Path, required=True)
    parser.add_argument('--v100-report', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_report(args.rtx_report, args.v100_report)
        write_private_report(args.report, result)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        'report': str(args.report),
        'schema': result['schema'],
        'rtx5080_alloc_records': result['reports'][0]['alloc_records'],
        'v100_alloc_records': result['reports'][1]['alloc_records'],
        'shared_classes': len(result['comparison']['common_class_ids']),
        'nested_parameters_read': False,
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
