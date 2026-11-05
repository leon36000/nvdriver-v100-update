#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare observed ROOT packet inputs against the broker's bounded input slice.

This reads archived observations only; no ioctl or nested-pointer dereference.
A compatible input is not evidence that a second backend can execute it.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def extract_observation(source):
    if isinstance(source, dict) and source.get('schema') == 'nvidia-hybrid-rm-ioctl-observer-v1':
        return source
    if not isinstance(source, dict):
        raise ValueError('observer source must be a JSON object')
    remote = source.get('remote')
    if not isinstance(remote, dict):
        raise ValueError('transport report has no remote result')
    observation = remote.get('ioctl_observation')
    if isinstance(observation, dict):
        return observation
    acceptance = remote.get('hardware_acceptance')
    if isinstance(acceptance, dict):
        wrapped = acceptance.get('ioctl_observation')
        if isinstance(wrapped, dict) and isinstance(wrapped.get('report'), dict):
            return wrapped['report']
    raise ValueError('transport report has no typed RM ioctl observation')


def summarize(report):
    if (report.get('schema') != 'nvidia-hybrid-rm-ioctl-observer-v1' or
        report.get('trace_complete') is not True or report.get('errors') != [] or
        report.get('control_path') != '/dev/nvidiactl' or
        not isinstance(report.get('records'), list)):
        raise ValueError('incomplete or out-of-scope typed observation')
    result = {'schema': 'nvidia-hybrid-rm-root-payload-summary-v1',
              'root_allocations': 0, 'confirmed_root_allocations': 0,
              'broker_compatible_root_inputs': 0, 'unsupported_root_inputs': [],
              'confirmed_root_frees': 0, 'alloc_packet_sizes': [],
              'root_samples': [], 'nested_parameter_contents_observed': False,
              'hybrid_runtime_validated': False,
              'scope': 'observed single-process packet inputs/statuses; not dual-backend execution'}
    sizes = Counter()
    for index, row in enumerate(report['records']):
        operation, size = row.get('operation'), row.get('packet_size')
        expected_size = (32, 48) if operation == 'alloc' else (16,) if operation == 'free' else ()
        expected_number = 0x2b if operation == 'alloc' else 0x29
        request = row.get('request')
        if (size not in expected_size or type(request) is not int or
            (request & 0xff) != expected_number or ((request >> 8) & 255) != ord('F') or
            ((request >> 16) & 16383) != size or ((request >> 30) & 3) != 3 or
            type(row.get('syscall_return')) is not int):
            raise ValueError('invalid packet metadata at record ' + str(index))
        fields = ['hRoot', 'hObjectParent', 'status']
        if operation == 'alloc':
            fields += ['hObjectNew', 'hClass', 'pAllocParms', 'paramsSize']
            if size == 48:fields += ['pRightsRequested', 'flags']
        else: fields += ['hObjectOld']
        for phase in ('entry', 'exit'):
            packet = row.get(phase)
            if (not isinstance(packet, dict) or any(type(packet.get(k)) is not int or packet[k] < 0
                or packet[k] >= (1 << (64 if k in ('pAllocParms','pRightsRequested') else 32)) for k in fields)):
                raise ValueError('missing/invalid typed fields at record ' + str(index) + ' ' + phase)
        entry, output = row['entry'], row['exit']
        successful = row['syscall_return'] == 0 and output['status'] == 0
        if operation == 'free':
            # R580 _nv01FreeWithSecInfo ignores hObjectParent. The real
            # RTX5080 ROOT free uses parent==root, rather than parent==0.
            if (successful and entry['hRoot'] != 0 and
                entry['hObjectOld'] == entry['hRoot']):
                result['confirmed_root_frees'] += 1
            continue
        sizes[size] += 1
        if entry['hClass'] not in (0, 0x41) or entry['hObjectParent'] != 0:
            continue
        result['root_allocations'] += 1
        result['confirmed_root_allocations'] += int(successful and output['hObjectNew'] != 0)
        reasons = []
        if entry['hRoot'] != 0: reasons.append('requested-root')
        if entry['hObjectNew'] != 0: reasons.append('requested-object')
        if entry['pAllocParms'] != 0 or entry['paramsSize'] != 0: reasons.append('parameters')
        if size == 48 and entry['pRightsRequested'] != 0: reasons.append('rights')
        if size == 48 and entry['flags'] != 0: reasons.append('flags')
        sample = {'record_index': index, 'packet_size': size, 'entry': entry, 'exit': output,
                  'syscall_return': row['syscall_return'], 'broker_input_rejection_reasons': reasons}
        result['root_samples'].append(sample)
        if reasons:
            result['unsupported_root_inputs'].append({'record_index': index, 'reasons': reasons})
        else:
            result['broker_compatible_root_inputs'] += 1
    result['alloc_packet_sizes'] = [{'bytes': size, 'count': count} for size, count in sorted(sizes.items())]
    result['qualification'] = ('no-root-allocation-observed' if not result['root_allocations'] else
        'observed-root-inputs-exceed-current-broker' if result['unsupported_root_inputs'] else
        'observed-root-inputs-fit-current-broker-slice')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace',type=Path)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists():parser.error('report already exists')
    raw=args.trace.read_bytes(); source=json.loads(raw)
    # Accept a raw trace or either guarded transport report shape.
    source=extract_observation(source)
    result=summarize(source)
    result['trace']={'path':str(args.trace.resolve()),'sha256':hashlib.sha256(raw).hexdigest()}
    result['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.report.open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('qualification','root_allocations','confirmed_root_allocations',
                                          'broker_compatible_root_inputs','confirmed_root_frees')}))
    return 0


if __name__=='__main__':raise SystemExit(main())
