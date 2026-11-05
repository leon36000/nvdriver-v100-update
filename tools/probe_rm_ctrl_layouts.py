#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile a small ABI probe against pinned NVIDIA SDK header trees."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


EXPECTED_VERSIONS = {'r580': '580.178.04', 'r595': '595.99.02'}
FIXTURE = Path(__file__).resolve().parents[1] / 'tests/fixtures/rm_ctrl_layout_probe.c'
INCLUDE_DIR = Path('src/common/sdk/nvidia/inc')
HEADER_PATHS = (
    INCLUDE_DIR / 'class/cl0080.h',
    INCLUDE_DIR / 'ctrl/ctrl0000/ctrl0000gpu.h',
    INCLUDE_DIR / 'ctrl/ctrl2080/ctrl2080gpu.h',
    INCLUDE_DIR / 'ctrl/ctrl2080/ctrl2080nvlink.h',
    INCLUDE_DIR / 'ctrl/ctrl2080/ctrl2080nvlink_common.h',
)
PROBE_KEYS = {
    'gpu_get_name_string_cmd', 'gpu_get_name_string_size',
    'gpu_get_name_string_buffer_offset', 'gpu_get_name_string_buffer_size',
    'gpu_query_ecc_status_cmd', 'gpu_query_ecc_status_size', 'gpu_ecc_unit_count',
    'nvlink_get_status_cmd', 'nvlink_max_array_size',
    'nvlink_link_status_info_size', 'nvlink_get_status_size',
    'nvlink_link_info_offset', 'nv01_device_class_id',
    'nv0080_alloc_params_size', 'nv0080_device_id_offset',
    'nv0080_flags_offset', 'nv0080_va_space_size_offset',
    'nv0080_va_mode_offset', 'gpu_get_device_ids_cmd',
    'gpu_get_device_ids_size', 'gpu_get_device_ids_value_offset',
}
COMMAND_KEYS = (
    'gpu_get_name_string_cmd', 'gpu_query_ecc_status_cmd', 'nvlink_get_status_cmd',
    'gpu_get_device_ids_cmd',
)
PARAMETER_SIZE_KEYS = (
    ('gpu_get_name_string_cmd', 'gpu_get_name_string_size'),
    ('gpu_query_ecc_status_cmd', 'gpu_query_ecc_status_size'),
    ('nvlink_get_status_cmd', 'nvlink_get_status_size'),
)
LAYOUT_FIELDS = (
    'gpu_get_name_string_buffer_offset', 'gpu_get_name_string_buffer_size',
    'gpu_ecc_unit_count', 'nvlink_max_array_size',
    'nvlink_link_status_info_size', 'nvlink_link_info_offset',
    'nv01_device_class_id', 'nv0080_alloc_params_size',
    'nv0080_device_id_offset', 'nv0080_flags_offset',
    'nv0080_va_space_size_offset', 'nv0080_va_mode_offset',
    'gpu_get_device_ids_size', 'gpu_get_device_ids_value_offset',
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_source_version(source_root: Path, expected: str | None = None) -> str:
    version_file = source_root / 'version.mk'
    try:
        content = version_file.read_text(encoding='utf-8')
    except OSError as exc:
        raise ValueError(f'cannot read source version file: {version_file.name}') from exc
    values = re.findall(r'^NVIDIA_VERSION\s*=\s*([^\s#]+)', content, re.MULTILINE)
    if len(values) != 1:
        raise ValueError('version.mk must contain exactly one NVIDIA_VERSION')
    version = values[0]
    if expected is not None and version != expected:
        raise ValueError(f'expected NVIDIA source version {expected}, found {version}')
    return version


def parse_probe_output(output: str) -> dict[str, int]:
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError('C probe did not emit valid JSON') from exc
    if not isinstance(result, dict) or set(result) != PROBE_KEYS:
        raise ValueError('C probe output does not match the exact layout schema')
    for key, value in result.items():
        if type(value) is not int or value < 0:
            raise ValueError(f'{key} must be a non-negative integer')
    for key in COMMAND_KEYS:
        if result[key] > 0xFFFFFFFF:
            raise ValueError(f'{key} is outside the unsigned 32-bit command range')
    return result


def compare_layouts(r580: dict[str, int], r595: dict[str, int]) -> dict[str, Any]:
    if set(r580) != PROBE_KEYS or set(r595) != PROBE_KEYS:
        raise ValueError('both compiled layouts must match the exact probe schema')
    if any(type(value) is not int or value < 0
           for layout in (r580, r595) for value in layout.values()):
        raise ValueError('layout values must be non-negative integers')
    for key in COMMAND_KEYS:
        if r580[key] != r595[key]:
            raise ValueError(f'command IDs differ for {key}; compare layouts by command IDs first')
    if r580['nv01_device_class_id'] != r595['nv01_device_class_id']:
        raise ValueError('NV01_DEVICE_0 class IDs differ; compare allocation layouts first')

    changed_sizes = []
    for command_key, size_key in PARAMETER_SIZE_KEYS:
        if r580[size_key] != r595[size_key]:
            changed_sizes.append({
                'command': f'0x{r580[command_key]:08x}',
                'r580_bytes': r580[size_key],
                'r595_bytes': r595[size_key],
            })
    changed_fields = [
        {'field': key, 'r580': r580[key], 'r595': r595[key]}
        for key in LAYOUT_FIELDS if r580[key] != r595[key]
    ]
    unchanged = {
        key: r580[key] == r595[key]
        for key in (*COMMAND_KEYS, 'nv01_device_class_id',
                    'nvlink_max_array_size', 'nvlink_link_info_offset')
    }
    typed_allocations = {
        'nv01_device_0': {
            'class_id': r580['nv01_device_class_id'],
            'parameters_size_bytes': {
                'r580': r580['nv0080_alloc_params_size'],
                'r595': r595['nv0080_alloc_params_size'],
            },
            'field_offsets_bytes': {
                'deviceId': {
                    'r580': r580['nv0080_device_id_offset'],
                    'r595': r595['nv0080_device_id_offset'],
                },
                'flags': {
                    'r580': r580['nv0080_flags_offset'],
                    'r595': r595['nv0080_flags_offset'],
                },
                'vaSpaceSize': {
                    'r580': r580['nv0080_va_space_size_offset'],
                    'r595': r595['nv0080_va_space_size_offset'],
                },
                'vaMode': {
                    'r580': r580['nv0080_va_mode_offset'],
                    'r595': r595['nv0080_va_mode_offset'],
                },
            },
            'identical_layout': all(
                r580[key] == r595[key]
                for key in ('nv0080_alloc_params_size', 'nv0080_device_id_offset',
                            'nv0080_flags_offset', 'nv0080_va_space_size_offset',
                            'nv0080_va_mode_offset')
            ),
        },
        'gpu_get_device_ids': {
            'command': {
                'r580': r580['gpu_get_device_ids_cmd'],
                'r595': r595['gpu_get_device_ids_cmd'],
            },
            'parameters_size_bytes': {
                'r580': r580['gpu_get_device_ids_size'],
                'r595': r595['gpu_get_device_ids_size'],
            },
            'deviceIds_offset_bytes': {
                'r580': r580['gpu_get_device_ids_value_offset'],
                'r595': r595['gpu_get_device_ids_value_offset'],
            },
            'identical_layout': all(
                r580[key] == r595[key]
                for key in ('gpu_get_device_ids_cmd', 'gpu_get_device_ids_size',
                            'gpu_get_device_ids_value_offset')
            ),
        },
    }
    return {
        'changed_parameter_sizes': changed_sizes,
        'changed_layout_fields': changed_fields,
        'unchanged': unchanged,
        'typed_allocation_contracts': typed_allocations,
    }


def _source_metadata(role: str, source_root: Path, compiler: str,
                     compiler_version: str) -> dict[str, Any]:
    expected = EXPECTED_VERSIONS[role]
    version = read_source_version(source_root, expected=expected)
    include_root = source_root / INCLUDE_DIR
    if not include_root.is_dir():
        raise ValueError(f'{role} source tree is missing the SDK include directory')
    headers: dict[str, str] = {}
    for relative in HEADER_PATHS:
        header = source_root / relative
        if not header.is_file():
            raise ValueError(f'{role} source tree is missing {relative.as_posix()}')
        headers[relative.name] = sha256_file(header)
    return {
        'role': role,
        'version': version,
        'source_directory_name': source_root.name,
        'version_mk_sha256': sha256_file(source_root / 'version.mk'),
        'sdk_header_sha256': headers,
        'layout': compile_layout(source_root, compiler),
        'compiler': Path(compiler).name,
        'compiler_version': compiler_version,
    }


def compile_layout(source_root: Path, compiler: str) -> dict[str, int]:
    include_root = source_root / INCLUDE_DIR
    with tempfile.TemporaryDirectory(prefix='rm-ctrl-layout-') as temporary:
        binary = Path(temporary) / 'rm_ctrl_layout_probe'
        command = [
            compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-I', str(include_root), str(FIXTURE), '-o', str(binary),
        ]
        built = subprocess.run(command, check=False, capture_output=True, text=True)
        if built.returncode != 0:
            detail = (built.stderr or built.stdout).strip()[-4000:]
            raise RuntimeError(f'SDK layout probe compilation failed ({built.returncode}): {detail}')
        executed = subprocess.run([str(binary)], check=False, capture_output=True, text=True)
        if executed.returncode != 0:
            detail = (executed.stderr or executed.stdout).strip()[-4000:]
            raise RuntimeError(f'SDK layout probe execution failed ({executed.returncode}): {detail}')
        return parse_probe_output(executed.stdout)


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


def _archive_hash(path: Path | None) -> dict[str, str] | None:
    if path is None:
        return None
    if not path.is_file():
        raise ValueError(f'source archive is not a regular file: {path.name}')
    return {'file_name': path.name, 'sha256': sha256_file(path)}


def build_report(r580_root: Path, r595_root: Path, compiler_arg: str,
                 r580_archive: Path | None = None,
                 r595_archive: Path | None = None) -> dict[str, Any]:
    compiler = shutil.which(compiler_arg)
    if compiler is None:
        raise ValueError(f'compiler not found: {compiler_arg}')
    version_run = subprocess.run([compiler, '--version'], check=False,
                                 capture_output=True, text=True)
    if version_run.returncode != 0:
        raise RuntimeError('compiler --version failed')
    compiler_version = (version_run.stdout or version_run.stderr).splitlines()[0]
    r580 = _source_metadata('r580', r580_root, compiler, compiler_version)
    r595 = _source_metadata('r595', r595_root, compiler, compiler_version)
    return {
        'schema': 'nvidia-hybrid-rm-control-sdk-layout-probe-v3',
        'fixture': {
            'file': 'tests/fixtures/rm_ctrl_layout_probe.c',
            'sha256': sha256_file(FIXTURE),
            'compiler_flags': ['-std=c11', '-Wall', '-Wextra', '-Werror'],
        },
        'sources': [r580, r595],
        'source_archives': {
            'r580': _archive_hash(r580_archive),
            'r595': _archive_hash(r595_archive),
        },
        'comparison': compare_layouts(r580['layout'], r595['layout']),
        'scope': {
            'classification': 'compiled SDK header layout evidence',
            'hardware_executed': False,
            'kernel_module_loaded': False,
            'nested_rm_control_payloads_read': False,
            'nested_alloc_parameters_read': False,
            'same_linux_hybrid_validated': False,
        },
        'not_proven': [
            'compatibility of arbitrary cross-branch RM_CONTROL payloads',
            'backend-local device-instance translation or child-handle ownership',
            'that observed hardware requests use each queried structure',
            'same-Linux V100 plus Blackwell initialization or CUDA execution',
            'performance, UVM, P2P, recovery, or long-duration stability',
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--r580-source', required=True, type=Path)
    parser.add_argument('--r595-source', required=True, type=Path)
    parser.add_argument('--r580-archive', type=Path)
    parser.add_argument('--r595-archive', type=Path)
    parser.add_argument('--cc', default='cc', help='C compiler executable (default: cc)')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.r580_source, args.r595_source, args.cc,
                              args.r580_archive, args.r595_archive)
        report['tool_sha256'] = sha256_file(Path(__file__).resolve())
        write_private_report(args.report, report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        'report': str(args.report),
        'schema': report['schema'],
        'versions': [source['version'] for source in report['sources']],
        'size_drift_count': len(report['comparison']['changed_parameter_sizes']),
        'typed_alloc_layouts_identical': all(
            item['identical_layout']
            for item in report['comparison']['typed_allocation_contracts'].values()
        ),
        'hardware_validated': False,
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
