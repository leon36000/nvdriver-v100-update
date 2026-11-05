#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce a bounded R580/Blackwell ROOT ioctl-shape comparison.

The tool consumes archived transport reports and their typed summaries. It
does not open a device, execute an ioctl, inspect nested pointers, or imply
that the two backends can coexist.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re


SUMMARY_TOOL = Path(__file__).with_name('summarize_rm_payloads.py')
SUMMARY_SPEC = importlib.util.spec_from_file_location('rm_payload_summary', SUMMARY_TOOL)
SUMMARY = importlib.util.module_from_spec(SUMMARY_SPEC)
SUMMARY_SPEC.loader.exec_module(SUMMARY)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def normalize_pci(value):
    """Normalize accepted full-domain PCI BDF spellings to dddd:bb:dd.f."""
    if not isinstance(value, str):
        raise ValueError('PCI identity must be a string')
    match = re.fullmatch(r'(?:(?P<domain>[0-9a-fA-F]{4}|[0-9a-fA-F]{8}):)?'
                         r'(?P<bus>[0-9a-fA-F]{2}):(?P<device>[0-9a-fA-F]{2})\.'
                         r'(?P<function>[0-7])', value)
    if not match:
        raise ValueError('invalid PCI BDF: ' + value)
    domain = int(match.group('domain') or '0', 16)
    bus = int(match.group('bus'), 16)
    device = int(match.group('device'), 16)
    if domain > 0xffff or device > 0x1f:
        raise ValueError('PCI BDF component outside conventional range: ' + value)
    return f'{domain:04x}:{bus:02x}:{device:02x}.{match.group("function")}'


def _load_json(path):
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f'invalid JSON in {path}: {error}') from error
    if not isinstance(value, dict):
        raise ValueError(f'JSON root must be an object: {path}')
    return value, raw


def _probe_for_role(role, source):
    remote = source.get('remote')
    if not isinstance(remote, dict):
        raise ValueError(role + ' transport report has no remote result')
    if role == 'volta':
        if (source.get('schema') != 'nvidia-hybrid-pc3-v100-reference-transport-v1' or
            remote.get('schema') != 'nvidia-hybrid-pc3-v100-guest-reference-v1'):
            raise ValueError('unexpected V100 guest transport schema')
        guest = remote.get('guest')
        probe = remote.get('probe')
        if (source.get('exit_code') != 0 or source.get('pc3_ssh_exit_code') != 0 or
            remote.get('probe_exit_code') != 0 or remote.get('observer_exit_code') != 0 or
            remote.get('guest_cleanup_passed') is not True or
            remote.get('payload_file_cleanup_passed') is not True or
            remote.get('qualification') != 'v100-reference-report-contract-valid' or
            not isinstance(guest, dict) or not isinstance(probe, dict) or
            probe.get('status') != 'control-passed' or probe.get('required_set_passed') is not True or
            probe.get('missing_sm') != []):
            raise ValueError('V100 reference did not pass its guarded guest contract')
        identity = {
            'gpu': guest.get('name'), 'uuid': guest.get('uuid'),
            'pci': normalize_pci(guest.get('pci')),
            'kernel': guest.get('kernel_release'), 'driver': guest.get('driver_version'),
            'driver_api': probe.get('driver_api'), 'host': 'PC3 VM pc3-v100',
            'observer_records': None,
            'probe_exit_code': remote.get('probe_exit_code'),
            'overall_probe_status': probe.get('status'),
            'required_set_passed': probe.get('required_set_passed'),
            'missing_sm': probe.get('missing_sm'),
        }
        target_sm, expected_gpu = 70, 'Tesla V100'
    else:
        if (source.get('schema') != 'nvidia-hybrid-remote-selected-gpu-transport-v1' or
            remote.get('schema') != 'nvidia-hybrid-remote-selected-gpu-v1'):
            raise ValueError('unexpected RTX5080 transport schema')
        acceptance = remote.get('hardware_acceptance')
        if not isinstance(acceptance, dict):
            raise ValueError('RTX 5080 report has no guarded hardware acceptance record')
        probe = acceptance.get('probe')
        selection = acceptance.get('device_selection')
        if (source.get('exit_code') != 77 or source.get('ssh_exit_code') != 77 or
            acceptance.get('exit_code') != 77 or
            acceptance.get('qualification') != 'incomplete-hardware-missing' or
            remote.get('qualification') != 'rtx5080-report-contract-valid-hybrid-incomplete' or
            not isinstance(probe, dict) or not isinstance(selection, dict) or
            acceptance.get('schema') != 'nvidia-hybrid-hardware-acceptance-v2' or
            acceptance.get('validation_errors') != [] or
            probe.get('status') != 'incomplete' or probe.get('required_set_passed') is not False or
            70 not in probe.get('missing_sm', [])):
            raise ValueError('RTX5080 run must preserve its truthful missing-Volta result')
        selected_uuid = selection.get('cuda_visible_devices')
        selected_pci = normalize_pci(selection.get('expected_pci_bus_id'))
        if not isinstance(selected_uuid, str) or not selected_uuid:
            raise ValueError('RTX 5080 report is missing the selected UUID')
        identity = {
            'gpu': 'NVIDIA GeForce RTX 5080', 'uuid': selected_uuid,
            'pci': selected_pci,
            'kernel': acceptance.get('kernel_release'),
            'driver_api': probe.get('driver_api'), 'host': acceptance.get('host'),
            'driver': remote.get('selected_nvidia_smi', {}).get('driver')
                if isinstance(remote.get('selected_nvidia_smi'), dict) else None,
            'observer_records': None,
            'probe_exit_code': acceptance.get('exit_code'),
            'overall_probe_status': probe.get('status'),
            'required_set_passed': probe.get('required_set_passed'),
            'missing_sm': probe.get('missing_sm'),
        }
        target_sm, expected_gpu = 120, 'RTX 5080'
    if not isinstance(probe.get('devices'), list):
        raise ValueError(role + ' probe has no device result list')
    devices = [device for device in probe['devices']
               if isinstance(device, dict) and device.get('sm') == target_sm]
    if len(devices) != 1:
        raise ValueError(role + ' probe must contain exactly one target architecture')
    device = devices[0]
    pci = normalize_pci(device.get('pci_bus_id'))
    if pci != identity['pci'] or device.get('targeted') is not True:
        raise ValueError(role + ' probe device identity or target guard does not match')
    if role == 'blackwell' and device.get('uuid', identity['uuid']) != identity['uuid']:
        raise ValueError('RTX 5080 probe UUID does not match selected UUID')
    if not isinstance(device.get('name'), str) or expected_gpu.lower() not in device['name'].lower():
        raise ValueError(role + ' probe GPU name does not match the expected architecture')
    required_device_checks = ('tested', 'architecture_kernel_passed', 'synchronous_passed',
                              'asynchronous_passed', 'cleanup_passed')
    if (any(device.get(key) is not True for key in required_device_checks) or
        device.get('cleanup_errors') != [] or
        device.get('synchronous_sizes') != [1, 31, 256, 4096, 65537] or
        device.get('asynchronous_sizes') != [1, 31, 256, 4096, 65537]):
        raise ValueError(('RTX 5080' if role == 'blackwell' else 'V100') +
                         ' device-level kernel reference did not pass')
    identity['gpu'] = device['name']
    identity['selected_device_kernel_passed'] = True
    identity['sync_sizes'] = device['synchronous_sizes']
    identity['async_sizes'] = device['asynchronous_sizes']
    identity['sm'] = target_sm
    return probe, identity


def _observer_for_role(role, source):
    try:
        observer = SUMMARY.extract_observation(source)
    except ValueError as error:
        raise ValueError(role + ' transport is missing its typed observer trace') from error
    if (observer.get('schema') != 'nvidia-hybrid-rm-ioctl-observer-v1' or
        observer.get('trace_complete') is not True or observer.get('errors') != [] or
        observer.get('control_path') != '/dev/nvidiactl' or
        observer.get('architecture') != 'x86_64' or observer.get('pointer_bits') != 64 or
        observer.get('nested_pointers_read') is not False or
        observer.get('fd_identity_tracking') is not False or
        not isinstance(observer.get('records'), list) or not observer['records']):
        raise ValueError(role + ' observer scope/completeness contract failed')
    return observer


def _validated_summary(role, summary_path, summary, report_raw, observer):
    if not isinstance(summary, dict):
        raise ValueError(role + ' summary must be a JSON object')
    expected_hash = _sha256(report_raw)
    trace = summary.get('trace')
    if not isinstance(trace, dict) or trace.get('sha256') != expected_hash:
        raise ValueError(role + ' summary does not pin exact source report')
    if summary.get('tool_sha256') != _sha256(SUMMARY_TOOL.read_bytes()):
        raise ValueError(role + ' summary was produced by a different payload summarizer')
    expected = SUMMARY.summarize(observer)
    for key, value in expected.items():
        if summary.get(key) != value:
            raise ValueError(role + ' summary content differs from archived observer: ' + key)
    return {
        'path': str(summary_path), 'sha256': _sha256(summary_path.read_bytes()),
        'source_report_sha256': expected_hash,
        'payload_summarizer_sha256': summary['tool_sha256'],
    }, expected


def _allocation_shapes(summary):
    fields = ('layout', 'hRoot', 'hObjectParent', 'hObjectNew', 'hClass',
              'pAllocParms', 'paramsSize', 'pRightsRequested', 'flags', 'status')
    shapes = []
    for sample in summary['root_samples']:
        entry = sample['entry']
        shapes.append({'layout': entry['layout'],
            **{field: entry[field] for field in fields if field != 'layout'},
            'packet_size': sample['packet_size']})
    return sorted(shapes, key=lambda item: json.dumps(item, sort_keys=True))


def _root_free_shapes(observer):
    shapes = []
    for row in observer['records']:
        if row.get('operation') != 'free':
            continue
        entry, output = row.get('entry'), row.get('exit')
        if not isinstance(entry, dict) or not isinstance(output, dict):
            continue
        confirmed = (row.get('syscall_return') == 0 and output.get('status') == 0 and
                     entry.get('hRoot', 0) != 0 and
                     entry.get('hObjectOld') == entry.get('hRoot'))
        if confirmed:
            shapes.append({'layout': entry.get('layout'),
                'packet_size': row.get('packet_size'),
                'hRoot_nonzero': True,
                'hObjectOld_equals_hRoot': True,
                'hObjectParent_equals_hRoot': entry.get('hObjectParent') == entry.get('hRoot'),
                'syscall_success': True, 'payload_status_success': True})
    return sorted(shapes, key=lambda item: json.dumps(item, sort_keys=True))


def _load_side(role, report_path, summary_path):
    source, source_raw = _load_json(report_path)
    probe, identity = _probe_for_role(role, source)
    observer = _observer_for_role(role, source)
    if observer.get('child_exit_code') != identity['probe_exit_code']:
        raise ValueError(role + ' observer child exit does not match probe exit')
    if role == 'volta':
        remote = source['remote']
        if remote.get('probe_exit_code') != observer['child_exit_code']:
            raise ValueError('V100 observer child exit mismatch')
    else:
        acceptance = source['remote']['hardware_acceptance']
        if acceptance.get('exit_code') != observer['child_exit_code']:
            raise ValueError('RTX5080 observer child exit mismatch')
    summary, _ = _load_json(summary_path)
    summary_meta, recomputed = _validated_summary(role, summary_path,
        summary, source_raw, observer)
    identity['observer_records'] = len(observer['records'])
    return {
        'identity': identity,
        'source_report': {'path': str(report_path), 'sha256': _sha256(source_raw)},
        'summary': summary_meta,
        'observer': observer,
        'root_summary': recomputed,
    }


def compare_reports(volta_report, volta_summary, blackwell_report, blackwell_summary):
    volta = _load_side('volta', Path(volta_report), Path(volta_summary))
    blackwell = _load_side('blackwell', Path(blackwell_report), Path(blackwell_summary))
    volta_alloc = _allocation_shapes(volta['root_summary'])
    blackwell_alloc = _allocation_shapes(blackwell['root_summary'])
    volta_free = _root_free_shapes(volta['observer'])
    blackwell_free = _root_free_shapes(blackwell['observer'])
    if (volta['root_summary']['root_allocations'] == 0 or
        blackwell['root_summary']['root_allocations'] == 0 or
        not volta_free or not blackwell_free):
        raise ValueError('both reports must contain confirmed ROOT allocation and free observations')
    return {
        'schema': 'nvidia-hybrid-rm-root-protocol-comparison-v2',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'tool': {'path': str(Path(__file__).resolve()),
                 'sha256': _sha256(Path(__file__).read_bytes())},
        'comparison': {
            'root_allocation_inputs_equal': volta_alloc == blackwell_alloc,
            'root_free_shape_equal': volta_free == blackwell_free,
            'all_observed_root_inputs_fit_bounded_broker_validation': (
                volta['root_summary']['broker_compatible_root_inputs'] ==
                    volta['root_summary']['root_allocations'] and
                blackwell['root_summary']['broker_compatible_root_inputs'] ==
                    blackwell['root_summary']['root_allocations'] and
                not volta['root_summary']['unsupported_root_inputs'] and
                not blackwell['root_summary']['unsupported_root_inputs']),
            'same_linux_instance': False,
            'same_cuda_process': False,
            'experimental_backend_loaded': False,
        },
        'devices': [
            {'role': 'Volta', **volta['identity'],
             'source_report': volta['source_report'], 'summary': volta['summary'],
             'root_allocations': volta['root_summary']['root_allocations'],
             'confirmed_root_allocations': volta['root_summary']['confirmed_root_allocations'],
             'broker_compatible_root_inputs': volta['root_summary']['broker_compatible_root_inputs'],
             'unsupported_root_inputs': volta['root_summary']['unsupported_root_inputs'],
             'confirmed_root_frees': volta['root_summary']['confirmed_root_frees']},
            {'role': 'Blackwell', **blackwell['identity'],
             'source_report': blackwell['source_report'], 'summary': blackwell['summary'],
             'root_allocations': blackwell['root_summary']['root_allocations'],
             'confirmed_root_allocations': blackwell['root_summary']['confirmed_root_allocations'],
             'broker_compatible_root_inputs': blackwell['root_summary']['broker_compatible_root_inputs'],
             'unsupported_root_inputs': blackwell['root_summary']['unsupported_root_inputs'],
             'confirmed_root_frees': blackwell['root_summary']['confirmed_root_frees']},
        ],
        'root_allocation_input_shapes': {'volta': volta_alloc, 'blackwell': blackwell_alloc},
        'root_free_shapes': {'volta': volta_free, 'blackwell': blackwell_free},
        'interpretation': _interpret(volta_alloc == blackwell_alloc,
            volta_free == blackwell_free,
            (volta['root_summary']['broker_compatible_root_inputs'] == volta['root_summary']['root_allocations'] and
             blackwell['root_summary']['broker_compatible_root_inputs'] == blackwell['root_summary']['root_allocations'] and
             not volta['root_summary']['unsupported_root_inputs'] and
             not blackwell['root_summary']['unsupported_root_inputs'])),
        'not_proven': [
            'same-process or same-Linux coexistence',
            'the prototype nonzero-hRoot second-backend request; both hardware traces contain only hRoot=0 root inputs',
            'mirrored client-ID acceptance across separate RM server/global-state domains',
            'general NVOS/RM ABI coverage',
            'GPU-file/control/event/mmap/UVM routing',
            'hybrid CUDA execution or performance',
        ],
        'method_limits': [
            'observer traces only the explicitly launched process and its threads',
            'no nested pointers are read',
            'fd identity is not tracked',
            'these are ordinary root requests from separate probes, not an observation of the broker mirror packet',
            'the V100 and RTX5080 runs use separate Linux instances and installed driver branches',
            'the RTX5080 combined acceptance exits 77 because no SM70 device is visible',
        ],
    }


def _interpret(alloc_equal, free_equal, broker_compatible):
    allocation = ('matching observed NVOS64 ROOT allocation input shapes' if alloc_equal else
                  'different observed NVOS64 ROOT allocation input shapes')
    frees = ('matching ROOT FREE alias shapes' if free_equal else
             'different ROOT FREE alias shapes')
    fit = ('both fit the broker current null-parameter/null-rights/flags-zero slice' if broker_compatible else
           'at least one observed ROOT input exceeds the broker current bounded slice')
    return ('The V100 R580 guest and RTX5080 R595 host references show ' +
            allocation + ' and ' + frees + '; ' + fit + '. The RTX5080 probe '
            'successfully tested its own SM120 device, while the overall '
            'dual-architecture acceptance correctly returned incomplete because '
            'SM70 was absent from that Linux instance. Both traces contain only '
            'ordinary hRoot=0 ROOT inputs; the prototype nonzero-hRoot mirrored '
            'request has not been observed on either backend.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volta-report', type=Path, required=True)
    parser.add_argument('--volta-summary', type=Path, required=True)
    parser.add_argument('--blackwell-report', type=Path, required=True)
    parser.add_argument('--blackwell-summary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists')
    report = compare_reports(args.volta_report, args.volta_summary,
                             args.blackwell_report, args.blackwell_summary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['comparison'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
